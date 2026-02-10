package main

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target amd64 probe bpf/tcp_probe.c -- -I./bpf/headers

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/perf"
	"github.com/cilium/ebpf/rlimit"
)

type event struct {
	Pid    uint32
	Type   uint32 // 0=CONNECT, 1=ACCEPT
	Family uint16 // 2=AF_INET, 10=AF_INET6
	Comm   [16]byte
	_      [2]byte   // Padding to match C struct alignment (26 -> 28)
	Saddr  [4]uint32 // 16 bytes for IPv6
	Daddr  [4]uint32
	Sport  uint16
	Dport  uint16
}

// Cache for Process Names
var procCache = make(map[uint32]string)
var procCacheMu sync.RWMutex

// Cache for DNS Lookups
var dnsCache = make(map[string]string)
var dnsCacheMu sync.RWMutex

func main() {
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

	// Attach tcp_connect (Outgoing)
	kpConnect, err := link.Kprobe("tcp_connect", objs.KprobeTcpConnect, nil)
	if err != nil {
		log.Fatalf("opening kprobe tcp_connect: %v", err)
	}
	defer kpConnect.Close()

	// Attach inet_csk_accept (Incoming)
	kpAccept, err := link.Kretprobe("inet_csk_accept", objs.KretprobeInetCskAccept, nil)
	if err != nil {
		log.Fatalf("opening kretprobe inet_csk_accept: %v", err)
	}
	defer kpAccept.Close()

	// Open perf event reader
	rd, err := perf.NewReader(objs.Events, os.Getpagesize())
	if err != nil {
		log.Fatalf("creating perf event reader: %v", err)
	}
	defer rd.Close()

	log.Println("Listening for TCP connections (IPv4/IPv6)... (Ctrl+C to exit)")

	// Handle signals
	stopper := make(chan os.Signal, 1)
	signal.Notify(stopper, os.Interrupt, syscall.SIGTERM)

	go func() {
		<-stopper
		rd.Close()
	}()

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
			log.Printf("perf event ring buffer full, dropped %d samples", record.LostSamples)
			continue
		}

		// Parse event
		var evt event
		if err := binary.Read(bytes.NewReader(record.RawSample), binary.LittleEndian, &evt); err != nil {
			log.Printf("parsing perf event: %v", err)
			continue
		}

		// Use goroutine for display to not block reader on DNS lookup
		go handleEvent(evt)
	}
}

func handleEvent(evt event) {
	// Format output
	shortComm := string(bytes.TrimRight(evt.Comm[:], "\x00"))
	fullComm := getFullProcessName(evt.Pid, shortComm)
	
	direction := "OUT"
	if evt.Type == 1 {
		direction = "IN "
	}

	srcIP := parseIntToIP(evt.Family, evt.Saddr)
	dstIP := parseIntToIP(evt.Family, evt.Daddr)
	
	sport := evt.Sport
	dport := htons(evt.Dport) 

	// Resolve DNS for Destination IP if OUT, or Source IP if IN (usually interesting part is remote)
	remoteIP := dstIP
	if direction == "IN " {
		remoteIP = srcIP
	}
	
	dnsName := lookupDNS(remoteIP.String())
	if dnsName != "" {
		dnsName = fmt.Sprintf(" (%s)", dnsName)
	}

	familyTag := ""
	if evt.Family == 10 { // AF_INET6
		familyTag = "[v6] "
	}

	fmt.Printf("[%s] %sPID: %-6d Comm: %-20s %s:%d -> %s:%d%s\n", 
		direction, familyTag, evt.Pid, truncate(fullComm, 20), srcIP, sport, dstIP, dport, dnsName)
}

func truncate(s string, n int) string {
	if len(s) > n {
		return s[:n] + "..."
	}
	return s
}

func parseIntToIP(family uint16, addr [4]uint32) net.IP {
	if family == 2 { // AF_INET
		ip := make(net.IP, 4)
		binary.LittleEndian.PutUint32(ip, addr[0])
		return ip
	} else { // AF_INET6
		ip := make(net.IP, 16)
		for i := 0; i < 4; i++ {
			binary.LittleEndian.PutUint32(ip[i*4:], addr[i])
		}
		return ip
	}
}

func htons(v uint16) uint16 {
	return (v << 8) | (v >> 8)
}

// getFullProcessName tries to read /proc/<pid>/cmdline. Caches result.
func getFullProcessName(pid uint32, shortComm string) string {
	procCacheMu.RLock()
	name, exists := procCache[pid]
	procCacheMu.RUnlock()
	
	if exists {
		return name
	}

	// Read from /proc
	cmdLineBytes, err := os.ReadFile(fmt.Sprintf("/proc/%d/cmdline", pid))
	if err == nil && len(cmdLineBytes) > 0 {
		// cmdline arguments are separated by null bytes. Take the first one (the command)
		// or join them with space? Let's take the first arg (binary path/name)
		parts := bytes.Split(cmdLineBytes, []byte{0})
		if len(parts) > 0 {
			name = string(parts[0])
			// If it's a full path, maybe just take the base name? 
			// User asked for "name of process", let's give the base name of binary
			// but if it's "python3 script.py", we might want "script.py"?
			// Let's stick to base binary name for now to fit in UI.
			// Actually, let's clean it up.
			
			// Just the binary name
			if idx := strings.LastIndex(name, "/"); idx >= 0 {
				name = name[idx+1:]
			}
		}
	}

	if name == "" {
		name = shortComm
	}

	procCacheMu.Lock()
	procCache[pid] = name
	procCacheMu.Unlock()
	
	return name
}

// lookupDNS performs a reverse lookup. Caches result.
func lookupDNS(ip string) string {
	// Skip local IPs to save time
	if strings.HasPrefix(ip, "127.") || strings.HasPrefix(ip, "10.") || strings.HasPrefix(ip, "192.168.") || ip == "::1" {
		return ""
	}

	dnsCacheMu.RLock()
	name, exists := dnsCache[ip]
	dnsCacheMu.RUnlock()

	if exists {
		return name
	}

	// Async lookup not to block?
	// Note: We are already in a goroutine per event, so blocking here blocks only this event's print.
	// But valid to not cache failed lookups forever?
	
	names, err := net.LookupAddr(ip)
	if err == nil && len(names) > 0 {
		name = strings.TrimSuffix(names[0], ".") // Remove trailing dot
	} else {
		name = "" // Cache empty string for failure to avoid retrying immediately?
	}

	dnsCacheMu.Lock()
	dnsCache[ip] = name
	dnsCacheMu.Unlock()

	return name
}
