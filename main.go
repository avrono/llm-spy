// Copyright (c) 2026 llm-spy contributors
// SPDX-License-Identifier: MIT

package main

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target amd64 probe bpf/probe.c -- -I./bpf/headers

import (
	"bytes"
	"encoding/binary"
	"errors"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/perf"
	"github.com/cilium/ebpf/rlimit"

	"llm-spy/pkg/http2"
	"llm-spy/pkg/jsonutil"
	"llm-spy/pkg/llm"
	"llm-spy/pkg/sse"

	"net"
	//"net/http"
	//"net/http/httputil"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
)

// Command-line flags
var (
	llmOnly       = flag.Bool("llm-only", false, "Only show LLM API traffic")
	showAll       = flag.Bool("all", false, "Show all SSL traffic (not just LLM)")
	rawOutput     = flag.Bool("raw", false, "Show raw output without parsing")
	processFilter = flag.String("process", "", "Filter by process name (e.g., 'node', 'python3')")
	debug         = flag.Bool("debug", false, "Show debug information")
	proxyMode     = flag.Bool("proxy", false, "Enable transparent proxy for Chrome/Electron")
	proxyPort     = flag.Int("port", 8080, "Port for the transparent proxy")
	outputFile    = flag.String("output", "", "File path to log outgoing request data (append mode)")
)

// match the struct in probe.c
type probeData struct {
	Pid    uint32
	Type   uint32 // 0=SEND, 1=RECV
	Length uint32
	Comm   [16]byte // Process name
	Data   [4096]byte
}

// ConnectionBuffer tracks reassembly state for a connection
type ConnectionBuffer struct {
	buffer     bytes.Buffer
	lastUpdate time.Time
	provider   llm.Provider
}

// Global buffer manager
type BufferManager struct {
	buffers map[string]*ConnectionBuffer
	mu      sync.Mutex
}

func NewBufferManager() *BufferManager {
	return &BufferManager{
		buffers: make(map[string]*ConnectionBuffer),
	}
}

func (bm *BufferManager) getBuffer(key string) *ConnectionBuffer {
	bm.mu.Lock()
	defer bm.mu.Unlock()

	buf, exists := bm.buffers[key]
	if !exists {
		buf = &ConnectionBuffer{
			lastUpdate: time.Now(),
		}
		bm.buffers[key] = buf
	}
	return buf
}

func (bm *BufferManager) cleanup() {
	bm.mu.Lock()
	defer bm.mu.Unlock()

	now := time.Now()
	for key, buf := range bm.buffers {
		if now.Sub(buf.lastUpdate) > 5*time.Second {
			delete(bm.buffers, key)
		}
	}
}

func main() {
	flag.Parse()

	// Allow the current process to lock memory for eBPF resources.
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatalf("failed to remove mem lockdown: %v", err)
	}

	// Load pre-compiled programs and maps into the kernel.
	objs := probeObjects{}
	if err := loadProbeObjects(&objs, nil); err != nil {
		log.Fatalf("loading objects: %v", err)
	}
	defer objs.Close()

	// ---------------------------------------------------------
	// PROXY MODE (Transparent MITM)
	// ---------------------------------------------------------
	if *proxyMode {
		log.Printf("🚀 Starting Transparent Proxy on port %d...", *proxyPort)

		// 1. Attach Cgroup Connect4 Redirect
		// Note: We need to attach to a cgroup. The root cgroup is typical for "system-wide"
		// but requires cgroup v2 unified hierarchy at /sys/fs/cgroup
		cgroupPath := "/sys/fs/cgroup"

		// Helper to find a valid cgroup if root fails?
		// For now, assume standard systemd setup

		cg, err := link.AttachCgroup(link.CgroupOptions{
			Path:    cgroupPath,
			Attach:  ebpf.AttachCGroupInet4Connect,
			Program: objs.Connect4Redirect,
		})
		if err != nil {
			log.Printf("⚠️  Failed to attach connect4 redirect to %s: %v", cgroupPath, err)
			log.Printf("    Make sure you are running as root and cgroup v2 is mounted at /sys/fs/cgroup")
			log.Fatalf("Critical error in proxy mode")
		}

		// 1b. Attach Cgroup Connect6 Redirect (IPv6)
		cg6, err := link.AttachCgroup(link.CgroupOptions{
			Path:    cgroupPath,
			Attach:  ebpf.AttachCGroupInet6Connect,
			Program: objs.Connect6Redirect,
		})
		if err != nil {
			log.Printf("⚠️  Failed to attach connect6 redirect to %s: %v", cgroupPath, err)
			log.Printf("    IPv6 traffic will NOT be redirected.")
		} else {
			log.Printf("✓ Attached Connect6 Redirect (IPv6 Traffic -> [::1]:%d)", *proxyPort)
		}

		// Ensure cleanup happens even on panic or error
		var cleanupOnce sync.Once
		cleanup := func() {
			cleanupOnce.Do(func() {
				log.Println("🧹 Cleaning up eBPF programs...")
				cg.Close()
				if cg6 != nil {
					cg6.Close()
				}
				log.Println("✓ eBPF programs detached")
			})
		}
		defer cleanup()

		log.Printf("✓ Attached Connect4 Redirect (Traffic -> 127.0.0.1:%d)", *proxyPort)

		// 1.5 Update Config Map with our PID
		// This prevents the proxy itself from being redirected (infinite loop)
		pid := uint32(os.Getpid())
		key := uint32(0)
		if err := objs.ConfigMap.Update(key, pid, ebpf.UpdateAny); err != nil {
			log.Fatalf("Failed to update config map with PID: %v", err)
		}
		log.Printf("✓ Whitelisted Proxy PID: %d", pid)

		// 2. Start Go Proxy Server
		// Need buffers for proxy too
		bufMgr := NewBufferManager()
		sseAggregators := make(map[string]*sse.StreamAggregator)
		var sseMu sync.Mutex

		// Use a WaitGroup to manage goroutines
		var wg sync.WaitGroup
		wg.Add(1)

		go func() {
			defer wg.Done()
			defer func() {
				if r := recover(); r != nil {
					log.Printf("⚠️  Recovered from panic in proxy server: %v", r)
				}
			}()
			startProxyServer(*proxyPort, bufMgr, sseAggregators, &sseMu)
		}()

		// Wait for SIGINT
		stopper := make(chan os.Signal, 1)
		signal.Notify(stopper, os.Interrupt, syscall.SIGTERM)

		// Block until signal received
		sig := <-stopper
		log.Printf("\n👋 Received signal: %v. Exiting...", sig)

		// Explicitly call cleanup (defer will also call it, but cleanupOnce ensures single execution)
		cleanup()
		return
	}

	// Locate the library
	const libPath = "/lib/x86_64-linux-gnu/libssl.so.3"

	// 1. Attach SSL_write (uprobe) to capture SENT data
	sslWriteLink, err := link.OpenExecutable(libPath)
	if err != nil {
		log.Fatalf("opening executable: %v", err)
	}

	upWrite, err := sslWriteLink.Uprobe("SSL_write", objs.ProbeSslWrite, nil)
	if err != nil {
		log.Fatalf("attaching SSL_write: %v", err)
	}
	defer upWrite.Close()
	log.Printf("✓ Attached SSL_write")

	// 2. Attach SSL_read (uprobe + uretprobe) to capture RECEIVED data
	upReadEnter, err := sslWriteLink.Uprobe("SSL_read", objs.ProbeSslReadEnter, nil)
	if err != nil {
		log.Fatalf("attaching SSL_read entry: %v", err)
	}
	defer upReadEnter.Close()

	upReadExit, err := sslWriteLink.Uretprobe("SSL_read", objs.ProbeSslReadExit, nil)
	if err != nil {
		log.Fatalf("attaching SSL_read exit: %v", err)
	}
	defer upReadExit.Close()
	log.Printf("✓ Attached SSL_read")

	// 2b. Attach SSL_write_ex (OpenSSL 3.x API)
	upWriteEx, err := sslWriteLink.Uprobe("SSL_write_ex", objs.ProbeSslWriteEx, nil)
	if err != nil {
		log.Printf("Warning: could not attach SSL_write_ex: %v", err)
	} else {
		defer upWriteEx.Close()
		log.Printf("✓ Attached SSL_write_ex (OpenSSL 3.x)")
	}

	// 2c. Attach SSL_read_ex (OpenSSL 3.x API)
	upReadExEnter, err := sslWriteLink.Uprobe("SSL_read_ex", objs.ProbeSslReadExEnter, nil)
	if err != nil {
		log.Printf("Warning: could not attach SSL_read_ex entry: %v", err)
	} else {
		defer upReadExEnter.Close()

		upReadExExit, err := sslWriteLink.Uretprobe("SSL_read_ex", objs.ProbeSslReadExExit, nil)
		if err != nil {
			log.Printf("Warning: could not attach SSL_read_ex exit: %v", err)
		} else {
			defer upReadExExit.Close()
			log.Printf("✓ Attached SSL_read_ex (OpenSSL 3.x)")
		}
	}

	// 3. Open a perf event reader from user space on the PERF_EVENT_ARRAY map.
	rd, err := perf.NewReader(objs.Events, 4096*64) // Larger buffer for 4KB chunks
	if err != nil {
		log.Fatalf("creating perf event reader: %v", err)
	}
	defer rd.Close()

	log.Println("\n🔍 LLM Traffic Monitor Active")
	log.Printf("Mode: %s\n", getMode())
	log.Println(strings.Repeat("=", 80))

	// Buffer manager
	bufMgr := NewBufferManager()

	// Cleanup goroutine
	go func() {
		ticker := time.NewTicker(5 * time.Second)
		defer ticker.Stop()
		for range ticker.C {
			bufMgr.cleanup()
		}
	}()

	// SSE aggregators per connection
	sseAggregators := make(map[string]*sse.StreamAggregator)
	var sseMu sync.Mutex

	// CTRL+C handler
	stopper := make(chan os.Signal, 1)
	signal.Notify(stopper, os.Interrupt, syscall.SIGTERM)

	go func() {
		for {
			record, err := rd.Read()
			if err != nil {
				if errors.Is(err, perf.ErrClosed) {
					return
				}
				log.Printf("reading from perf event reader: %v", err)
				continue
			}

			if record.LostSamples > 0 {
				log.Printf("⚠️  Dropped %d samples (increase buffer size)", record.LostSamples)
				continue
			}

			// Parse the event
			var event probeData
			if err := binary.Read(bytes.NewReader(record.RawSample), binary.LittleEndian, &event); err != nil {
				log.Printf("parsing perf event: %v", err)
				continue
			}

			processEvent(&event, bufMgr, sseAggregators, &sseMu)
		}
	}()

	<-stopper
	log.Println("\n👋 Exiting...")
}

func processEvent(event *probeData, bufMgr *BufferManager, sseAggregators map[string]*sse.StreamAggregator, sseMu *sync.Mutex) {
	// Extract process name
	processName := string(bytes.TrimRight(event.Comm[:], "\x00"))
	direction := "SEND"
	if event.Type == 1 {
		direction = "RECV"
	}

	// Debug mode: show ALL events
	if *debug {
		log.Printf("[DEBUG] Event: PID=%d Proc=%s Dir=%s Len=%d", event.Pid, processName, direction, event.Length)
	}

	// Apply process filter if specified
	if *processFilter != "" && !strings.Contains(strings.ToLower(processName), strings.ToLower(*processFilter)) {
		if *debug {
			log.Printf("[DEBUG] Filtered out by process name: %s", processName)
		}
		return
	}

	// Get payload
	payload := event.Data[:event.Length]
	payloadStr := string(payload)

	// Buffer key
	bufKey := fmt.Sprintf("%d-%d", event.Pid, event.Type)
	buf := bufMgr.getBuffer(bufKey)
	buf.buffer.Write(payload)
	buf.lastUpdate = time.Now()

	// Get current buffer content
	currentData := buf.buffer.Bytes()

	// Check if this is LLM traffic or HTTP/2
	provider := llm.DetectProvider(string(currentData))
	isLLM := provider != llm.ProviderUnknown
	isHTTP2 := http2.IsHTTP2(currentData)

	// Skip non-LLM traffic if --llm-only is set
	if *llmOnly && !isLLM {
		if *debug {
			log.Printf("[DEBUG] Filtered: Not LLM traffic (llm-only mode)")
		}
		return
	}

	// Skip traffic if --all is NOT set (default behavior)
	// But allow: LLM traffic, HTTP/2, HTTP/JSON patterns
	if !*showAll && !isLLM && !isHTTP2 {
		// Still show if it looks like HTTP/JSON in plaintext
		if !llm.IsRequest(payloadStr) && !llm.IsResponse(payloadStr) {
			if *debug {
				log.Printf("[DEBUG] Filtered: Not LLM/HTTP2/HTTP/JSON (default mode)")
			}
			return
		}
	}

	// Raw output mode
	if *rawOutput {
		log.Printf("\n[%d:%s] %s (len=%d)\n%q\n", event.Pid, processName, direction, event.Length, payloadStr)
		return
	}

	if *debug {
		log.Printf("[DEBUG] Passed filter - processing HTTP/2 and JSON")
	}

	// Try HTTP/2 parsing
	if isHTTP2 {
		if *debug {
			log.Printf("[DEBUG] Detected as HTTP/2, extracting frames")
		}
		dataFrames := http2.ExtractDataFrames(currentData)
		if len(dataFrames) > 0 {
			if *debug {
				log.Printf("[DEBUG] Extracted %d HTTP/2 DATA frames", len(dataFrames))
			}
			// Concatenate all data frames
			var combined bytes.Buffer
			for _, frame := range dataFrames {
				combined.Write(frame)
			}
			currentData = combined.Bytes()
			payloadStr = string(currentData)
		} else if *debug {
			log.Printf("[DEBUG] No DATA frames found in HTTP/2")
		}
	}

	// File logging moved to after JSON extraction for formatted output

	// Check for streaming response (SSE)
	if llm.IsStreaming(payloadStr) {
		sseMu.Lock()
		agg, exists := sseAggregators[bufKey]
		if !exists {
			agg = &sse.StreamAggregator{}
			sseAggregators[bufKey] = agg
		}
		sseMu.Unlock()

		events, _ := sse.ParseEvents(currentData)
		for _, evt := range events {
			chunk, err := sse.ParseStreamingChunk(evt.Data)
			if err == nil {
				agg.AddChunk(chunk)
				if chunk.Delta != "" {
					fmt.Print(chunk.Delta) // Live streaming output
				}
				if chunk.FinishReason == "done" || chunk.FinishReason == "stop" {
					fmt.Println("\n" + strings.Repeat("-", 60))
					log.Printf("✅ Streaming Complete: %s\n", agg.GetFullResponse())
					sseMu.Lock()
					delete(sseAggregators, bufKey)
					sseMu.Unlock()
					buf.buffer.Reset()
				}
			}
		}
		return
	}

	// Try JSON extraction
	jsonObjects, _ := jsonutil.ExtractJSON(currentData)
	if len(jsonObjects) > 0 {
		log.Printf("[DEBUG-JSON] Found %d JSON objects, direction=%s, outputFile=%s", len(jsonObjects), direction, *outputFile)
		for _, obj := range jsonObjects {
			// Determine if request or response
			if llm.IsRequest(payloadStr) {
				log.Printf("[DEBUG-JSON] Detected as LLM Request")
				output := jsonutil.FormatLLMRequest(obj)
				log.Println("\n" + output)
				logToFile(*outputFile, output)
			} else if llm.IsResponse(payloadStr) {
				log.Printf("[DEBUG-JSON] Detected as LLM Response")
				output := jsonutil.FormatLLMResponse(obj)
				log.Println("\n" + output)
				logToFile(*outputFile, output)
			} else {
				// Generic JSON
				log.Printf("[DEBUG-JSON] Generic JSON, direction=%s", direction)
				pretty, _ := jsonutil.PrettyPrint(obj)
				log.Printf("\n[%d:%s] %s JSON (%s)\n%s\n", event.Pid, processName, direction, provider, pretty)
				logToFile(*outputFile, fmt.Sprintf("[%d:%s] %s JSON (%s)\n%s", event.Pid, processName, direction, provider, pretty))
			}
		}
		buf.buffer.Reset() // Clear buffer after successful JSON parse
		return
	}

	// Fallback logging for non-JSON but interesting traffic
	if *outputFile != "" && direction == "SEND" {
		// Log all SEND traffic to help debug what's being captured
		log.Printf("[DEBUG-FILE] Attempting to log SEND traffic: PID=%d, Proc=%s, Len=%d", event.Pid, processName, len(payloadStr))
		logToFile(*outputFile, fmt.Sprintf("[RAW] [%d:%s]\n%s", event.Pid, processName, truncate(payloadStr, 2000)))
		log.Printf("[DEBUG-FILE] Successfully called logToFile")
	}

	// Fallback: show if it contains interesting patterns or is HTTP/2
	// If --all is set, show everything that wasn't already processed as JSON/SSE
	if *showAll || isLLM || isHTTP2 || llm.IsRequest(payloadStr) || llm.IsResponse(payloadStr) {
		if *debug {
			log.Printf("[DEBUG] Fallback display triggered (showAll=%v)", *showAll)
		}
		log.Printf("\n[%d:%s] %s %s (len=%d)\n%s\n",
			event.Pid, processName, direction, provider, len(currentData), truncate(payloadStr, 1000))
	} else if *debug {
		log.Printf("[DEBUG] No display condition met - event silently dropped")
	}
}

func getMode() string {
	if *showAll {
		return "All SSL Traffic"
	}
	if *llmOnly {
		return "LLM Traffic Only"
	}
	return "Smart (LLM + HTTP)"
}

func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "\n... (truncated)"
}

// logToFile writes formatted content to the output file with timestamp
func logToFile(filename, content string) {
	if filename == "" {
		return
	}
	f, err := os.OpenFile(filename, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		log.Printf("Error opening log file: %v", err)
		return
	}
	defer f.Close()

	timestamp := time.Now().Format("2006-01-02 15:04:05.000")
	fmt.Fprintf(f, "\n[%s]\n%s\n%s\n", timestamp, strings.Repeat("-", 60), content)
}

// --------------------------------------------------------------------------------
// TRANSPARENT PROXY SERVER IMPLEMENTATION
// --------------------------------------------------------------------------------

func startProxyServer(port int, bufMgr *BufferManager, sseAggregators map[string]*sse.StreamAggregator, sseMu *sync.Mutex) {
	// Load CA certificate and key
	cert, err := tls.LoadX509KeyPair("certs/ca.crt", "certs/ca.key")
	if err != nil {
		log.Fatalf("❌ Failed to load CA certs (run ./gen_ca.sh first): %v", err)
	}

	// Parse CA leaf explicitly to ensure it's available for signing
	if cert.Leaf == nil {
		cert.Leaf, err = x509.ParseCertificate(cert.Certificate[0])
		if err != nil {
			log.Fatalf("❌ Failed to parse CA certificate: %v", err)
		}
	}

	tlsConfig := &tls.Config{
		GetCertificate: func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
			return generateCert(hello.ServerName, &cert)
		},
	}

	listener, err := tls.Listen("tcp", fmt.Sprintf(":%d", port), tlsConfig)
	if err != nil {
		log.Fatalf("❌ Failed to bind proxy port: %v", err)
	}

	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Printf("Proxy accept error: %v", err)
			continue
		}
		go handleProxyConnection(conn, bufMgr, sseAggregators, sseMu)
	}
}

// Simple in-memory cache for generated certs
var certCache = make(map[string]*tls.Certificate)
var certMu sync.Mutex

func generateCert(hostname string, ca *tls.Certificate) (*tls.Certificate, error) {
	certMu.Lock()
	defer certMu.Unlock()

	if cert, ok := certCache[hostname]; ok {
		return cert, nil
	}

	if hostname == "" {
		hostname = "unknown"
	}

	cert, err := generateSelfSignedCert(hostname, ca)
	if err != nil {
		return nil, err
	}
	certCache[hostname] = cert
	return cert, nil
}

func handleProxyConnection(clientConn net.Conn, bufMgr *BufferManager, sseAggregators map[string]*sse.StreamAggregator, sseMu *sync.Mutex) {
	defer clientConn.Close()

	tlsConn, ok := clientConn.(*tls.Conn)
	if !ok {
		return
	}

	// Force handshake to get SNI
	if err := tlsConn.Handshake(); err != nil {
		if *debug {
			// Try to read a bit of data to see if it's not TLS (e.g. plain HTTP)
			log.Printf("TLS Handshake failed from %s: %v", clientConn.RemoteAddr(), err)
		}
		return
	}

	state := tlsConn.ConnectionState()
	serverName := state.ServerName

	if *debug {
		log.Printf("Handshake success. SNI: %s", serverName)
	}

	if serverName == "" {
		if *debug {
			log.Println("No SNI found, cannot proxy")
		}
		return
	}

	// Dial upstream
	upstreamConn, err := tls.Dial("tcp", serverName+":443", &tls.Config{
		InsecureSkipVerify: true, // We are inspecting, not validating upstream security strictly here
	})
	if err != nil {
		log.Printf("Failed to dial upstream %s: %v", serverName, err)
		return
	}
	defer upstreamConn.Close()

	if *debug {
		log.Printf("Successfully connected to upstream: %s", serverName)
	}

	// Bidirectional copy with logging
	var wg sync.WaitGroup
	wg.Add(2)

	// Client -> Server (Request)
	go func() {
		defer wg.Done()
		buf := make([]byte, 4096)
		for {
			n, err := tlsConn.Read(buf)
			if n > 0 {
				// Fake a probeData event for analysis
				evt := &probeData{
					Pid:    0,
					Type:   0, // SEND
					Length: uint32(n),
				}
				copy(evt.Comm[:], "ChromeProxy")
				copy(evt.Data[:], buf[:n])
				processEvent(evt, bufMgr, sseAggregators, sseMu)

				upstreamConn.Write(buf[:n])
			}
			if err != nil {
				break
			}
		}
	}()

	// Server -> Client (Response)
	go func() {
		defer wg.Done()
		buf := make([]byte, 4096)
		for {
			n, err := upstreamConn.Read(buf)
			if n > 0 {
				evt := &probeData{
					Pid:    0,
					Type:   1, // RECV
					Length: uint32(n),
				}
				copy(evt.Comm[:], "ChromeProxy")
				copy(evt.Data[:], buf[:n])
				processEvent(evt, bufMgr, sseAggregators, sseMu)

				tlsConn.Write(buf[:n])
			}
			if err != nil {
				break
			}
		}
	}()

	wg.Wait()
}

// Helper to generate dynamic certs
func generateSelfSignedCert(hostname string, ca *tls.Certificate) (*tls.Certificate, error) {
	// Generate a new key for the leaf cert
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}

	// Create certificate template
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return nil, err
	}

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"LLM-Spy Proxy"},
			CommonName:   hostname,
		},
		NotBefore: time.Now().Add(-1 * time.Hour), // Backdate slightly to avoid sync issues
		NotAfter:  time.Now().Add(24 * time.Hour),

		KeyUsage:    x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},

		BasicConstraintsValid: true,
		IsCA:                  false, // Explicitly NOT a CA

		DNSNames: []string{hostname},
		// No SubjectKeyId/AuthorityKeyId here as we are doing simple on-the-fly signing,
		// but IsCA=false is critical.
	}

	// Sign the new cert with the CA key
	derBytes, err := x509.CreateCertificate(rand.Reader, &template, ca.Leaf, &key.PublicKey, ca.PrivateKey)
	if err != nil {
		return nil, fmt.Errorf("creating cert: %v", err)
	}

	return &tls.Certificate{
		Certificate: [][]byte{derBytes},
		PrivateKey:  key,
	}, nil
}
