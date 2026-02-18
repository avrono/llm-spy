# 🔍 llm-spy

**Zero-configuration LLM traffic monitoring using eBPF**

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Go Version](https://img.shields.io/badge/Go-1.25-blue.svg)](https://golang.org/)
[![eBPF](https://img.shields.io/badge/eBPF-Powered-green.svg)](https://ebpf.io/)

> Intercept and monitor LLM API traffic (OpenAI, Anthropic, Google, Cohere) in real-time without proxies, configuration changes, or breaking SSL certificate pinning.
> 
> **Note**: Currently supports applications using OpenSSL 3.x. Many coding agents use BoringSSL and are not yet supported - [we need your help!](#-current-limitations)

## 🎯 Overview

`llm-spy` is an innovative observability tool that uses eBPF (extended Berkeley Packet Filter) to monitor Large Language Model API traffic on Linux systems. Unlike traditional approaches that require proxy configuration or certificate manipulation, llm-spy operates at the SSL/TLS library level, making it completely transparent to applications.

### Why llm-spy?

**The Problem**: Modern applications communicate with LLM providers over HTTPS, making it impossible to inspect traffic with traditional tools like tcpdump or Wireshark. Setting up MITM proxies requires:
- Application configuration changes
- Certificate trust modifications
- Breaks with certificate pinning
- Complex setup for each application

**The Solution**: llm-spy uses eBPF uprobes to hook into OpenSSL functions (`SSL_write`, `SSL_read`) *before encryption* and *after decryption*, capturing plaintext data without any application awareness.

> [!IMPORTANT]
> **Current Scope**: llm-spy currently works with applications using **OpenSSL 3.x** (`libssl.so.3`). This includes Python, Node.js, Ruby, and many other applications. However, **most modern coding agents** (Cursor, Windsurf, Cody, etc.) use BoringSSL or embedded SSL libraries and are **not yet supported**. See [Current Limitations](#-current-limitations) for details and how you can help!
## Alternate Implementation

The `ebpf` approach does not always yield results for analysing `tokens` sent. 

Have been trying an alternate approach using `tshark` and parsing `protobuf` with `protoc`

````bash
# Ensure your SSL keylog is active (usually set via export SSLKEYLOGFILE=/tmp/sslkeys.log)
# Run the capture script and pipe it into the python decoder

cd llm_proxy/
sudo ./capture_prompts.sh | python3 decode_prompts.py | tee decode_test.out
````

You need `tshark` and `protoc` installed for this to work.

## ✨ Key Features

- 🚫 **Zero Configuration**: No proxy setup, no environment variables, no certificate installation
- 🔓 **Bypass Certificate Pinning**: Works even with pinned certificates (Chrome, Electron apps)
- 🎯 **Smart Filtering**: Automatically detects and highlights LLM API calls
- 📊 **HTTP/2 Support**: Parses HTTP/2 frames and reassembles fragmented messages
- 🌊 **Streaming Support**: Real-time display of streaming LLM responses (SSE)
- 🤖 **Multi-Provider**: Detects OpenAI, Anthropic, Google Gemini, and Cohere APIs
- 💾 **Large Buffer Handling**: Captures up to 4KB per SSL call using per-CPU BPF maps
- 📝 **JSON Formatting**: Pretty-prints and extracts key fields from LLM requests/responses

## 🛠️ How It Works

```
┌─────────────────┐
│  Application    │  (Python, Node.js, Chrome, etc.)
│  (any process)  │
└────────┬────────┘
         │ HTTPS (encrypted)
         ▼
┌─────────────────┐
│  libssl.so.3    │ ◄── llm-spy hooks here with eBPF uprobes
│  (OpenSSL)      │     • SSL_write / SSL_write_ex (before encryption)
└────────┬────────┘     • SSL_read / SSL_read_ex (after decryption)
         │
         ▼
    Internet/LLM API
```

### Technical Architecture

1. **eBPF Probes** (`bpf/probe.c`): Kernel-space programs that attach to OpenSSL functions
   - Captures plaintext buffers before encryption (writes) and after decryption (reads)
   - Uses per-CPU maps to handle large payloads (4KB) without stack limitations
   - Sends events to userspace via perf ring buffer

2. **Userspace Controller** (`main.go`): Go program that processes captured data
   - Reassembles fragmented SSL records
   - Parses HTTP/2 frames and extracts DATA payloads
   - Detects LLM providers and formats JSON output
   - Handles streaming responses (Server-Sent Events)

3. **Parser Packages** (`pkg/`):
   - `http2/`: HTTP/2 frame parsing and DATA extraction
   - `llm/`: Provider detection (OpenAI, Anthropic, Google, Cohere)
   - `jsonutil/`: JSON extraction and pretty-printing
   - `sse/`: Server-Sent Events parsing for streaming responses

## 📦 Installation

### Prerequisites

- **Linux kernel** 5.8+ (with eBPF support)
- **Go** 1.25+
- **libssl.so.3** (OpenSSL 3.x)
- **Root privileges** (required for eBPF)
- **Kernel headers** (for BPF compilation)
- **libbpf headers** (required for BPF compilation)

### Build from Source

```bash
# Install dependencies (Debian/Ubuntu)
sudo apt update
sudo apt install -y build-essential libbpf-dev linux-headers-$(uname -r)

# Clone the repository
git clone https://github.com/avrono/llm-spy.git
cd llm-spy

# Generate BPF code
go generate

# Build the binary
go build -o llm-spy

# Verify installation
sudo ./llm-spy --help
```

### Quick Build Script

```bash
#!/bin/bash
go generate && go build -o llm-spy
```

## 🚀 Quick Start

### Basic Usage

```bash
# Monitor all LLM traffic (default smart mode)
sudo ./llm-spy

# Only show LLM API calls (filter out other HTTPS)
sudo ./llm-spy --llm-only

# Show ALL SSL traffic (very verbose)
sudo ./llm-spy --all

# Raw mode without parsing
sudo ./llm-spy --raw
```

### Advanced Options

```bash
# Filter by process name
sudo ./llm-spy --process python3

# Save output to file
sudo ./llm-spy --output llm_traffic.log

# Enable debug logging
sudo ./llm-spy --debug

# Transparent proxy mode (for Chrome/Electron)
sudo ./llm-spy --proxy --port 8080
```

## 🔒 Certificate Setup for Proxy Mode

When using proxy mode (`--proxy`) to intercept traffic from browsers or Electron apps (like Antigravity or Factory Droid), you need to trust the local CA.

### 1. Generate Local CA
```bash
./gen_ca.sh
```

### 2. Import into Chrome/Chromium
1.  Settings -> **Privacy and security** -> **Security** -> **Manage certificates**.
2.  Select **Authorities** tab -> **Import**.
3.  Choose `certs/ca.crt` and check **"Trust this certificate for identifying websites"**.

### Example Output

**LLM Request Capture:**
```
🤖 LLM API REQUEST
============================================================
Provider: OpenAI
Model: gpt-4
Messages: 2
  [1] system: You are a helpful assistant.
  [2] user: What is eBPF?
Temperature: 0.70
Max Tokens: 1000
```

**LLM Response Capture:**
```
💬 LLM API RESPONSE
============================================================
Provider: OpenAI
ID: chatcmpl-abc123
Model: gpt-4

Choice 1:
  Content: eBPF (extended Berkeley Packet Filter) is a revolutionary
           technology that allows running sandboxed programs in the
           Linux kernel without changing kernel source code...
  Finish Reason: stop

Token Usage:
  prompt_tokens: 25
  completion_tokens: 150
  total_tokens: 175
```

**Streaming Response:**
```
eBPF is a revolutionary technology... (live output as it streams)
------------------------------------------------------------
✅ Streaming Complete: Model: gpt-4, Chunks: 42, Finish Reason: stop
```

## 🎯 Supported LLM Providers

> [!NOTE]
> **Current Status**: llm-spy currently works with applications using **OpenSSL 3.x** (`libssl.so.3`). Many modern coding agents and AI tools use embedded SSL libraries like BoringSSL, which are not yet supported. See [Current Limitations](#-current-limitations) below.

| Provider | Detection | Streaming | Notes |
|----------|-----------|-----------|-------|
| **OpenAI** | ✅ | ✅ | ChatGPT, GPT-4, GPT-3.5 |
| **Anthropic** | ✅ | ✅ | Claude models |
| **Google** | ✅ | ✅ | Gemini API |
| **Cohere** | ✅ | ✅ | Generate, Chat APIs |

## ⚠️ Current Limitations

### What Works Now

✅ **Applications using OpenSSL 3.x** (`libssl.so.3`):
- Python applications (requests, urllib3, httpx)
- Node.js applications using system OpenSSL
- Ruby, PHP, and other languages using system SSL
- Some Electron apps (depending on build configuration)

### What Doesn't Work Yet

❌ **Applications with embedded SSL libraries**:
- **Coding Agents** (Cursor, Windsurf, Cody, etc.) - Most use BoringSSL or statically linked SSL
- **Go Applications** - Use `crypto/tls` (static, not a shared library)
- **Rust Applications** - Often use `rustls` or statically linked OpenSSL
- **Chrome/Chromium** - Uses BoringSSL (Google's OpenSSL fork)
- **Modern Electron Apps** - Many bundle BoringSSL instead of using system OpenSSL

### The BoringSSL Challenge

Many modern coding agents (the primary target for LLM monitoring) use **BoringSSL**, Google's fork of OpenSSL. Unlike OpenSSL which is a shared library (`libssl.so`), BoringSSL is typically:
- **Statically linked** into the application binary
- **Not exposed as a shared library** with stable symbols
- **Lacks consistent function names** across builds
- **Embedded directly** in Chromium/Electron frameworks

This means our current uprobes on `libssl.so.3` functions don't work for these applications.

### Potential Solutions (Help Wanted!)

1. **BoringSSL Symbol Detection**: Dynamically find BoringSSL symbols in binaries
2. **Kernel-Level Interception**: Hook at the socket layer instead of SSL layer
3. **Go crypto/tls Support**: Add uprobes for Go's TLS implementation
4. **Proxy Mode Enhancement**: Improve transparent proxy to handle more protocols
5. **Binary Patching**: Runtime modification of application binaries (advanced)

**We need community help to solve this!** See [Contributing](#-contributing) below.

## 🔧 Operating Modes

| Mode | Flag | Description |
|------|------|-------------|
| **Smart** | *(default)* | Shows LLM + HTTP/JSON traffic |
| **LLM-Only** | `--llm-only` | Only displays detected LLM API calls |
| **All** | `--all` | Shows ALL SSL traffic (very verbose) |
| **Raw** | `--raw` | Raw output without parsing |
| **Proxy** | `--proxy` | Transparent MITM proxy for Chrome/Electron |

## 💡 Use Cases

- **Cost Monitoring**: Track token usage across all applications
- **Debugging**: Inspect prompts and responses in development
- **Security Auditing**: Monitor what data is sent to LLM providers
- **Performance Analysis**: Measure API latency and response times
- **Research**: Study LLM API usage patterns
- **Compliance**: Verify data handling in production systems

## 🧩 Technical Challenges Solved

### 1. **SSL/TLS Encryption**
**Challenge**: HTTPS traffic is encrypted end-to-end  
**Solution**: Hook OpenSSL functions at the library level before encryption/after decryption using eBPF uprobes

### 2. **Certificate Pinning**
**Challenge**: Modern apps (Chrome, Electron) use certificate pinning, breaking traditional MITM proxies  
**Solution**: Operate below the TLS layer, making certificate validation irrelevant

### 3. **Large Payloads**
**Challenge**: BPF stack is limited to 512 bytes, but LLM requests can be several KB  
**Solution**: Use BPF per-CPU array maps to store 4KB buffers outside the stack

### 4. **HTTP/2 Complexity**
**Challenge**: LLM APIs use HTTP/2 with binary framing and stream multiplexing  
**Solution**: Custom HTTP/2 parser that extracts and reassembles DATA frames

### 5. **Fragmented Messages**
**Challenge**: Large JSON payloads are split across multiple SSL_read/write calls  
**Solution**: Connection-based buffering with automatic reassembly and timeout-based flushing

### 6. **Streaming Responses**
**Challenge**: LLM streaming uses Server-Sent Events (SSE) with chunked delivery  
**Solution**: SSE parser with state aggregation for complete response reconstruction

### 7. **Zero Configuration**
**Challenge**: Traditional monitoring requires proxy setup and certificate trust  
**Solution**: eBPF operates transparently without any application or system configuration

## 🏗️ Architecture Deep Dive

For detailed architecture information, see [architecture.md](architecture.md).

### Component Overview

```
┌─────────────────────────────────────────────────────────┐
│                    User Space (Go)                      │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐ │
│  │ HTTP/2 Parser│  │ LLM Detector │  │ JSON Formatter│ │
│  └──────────────┘  └──────────────┘  └──────────────┘ │
│  ┌──────────────────────────────────────────────────┐  │
│  │         Connection Buffer Manager                │  │
│  │    (Reassembly + Streaming Aggregation)          │  │
│  └──────────────────────────────────────────────────┘  │
└───────────────────────┬─────────────────────────────────┘
                        │ Perf Ring Buffer
┌───────────────────────┴─────────────────────────────────┐
│                  Kernel Space (eBPF)                    │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐ │
│  │ SSL_write    │  │ SSL_read     │  │ Per-CPU Maps │ │
│  │ uprobes      │  │ uprobes      │  │ (4KB buffers)│ │
│  └──────────────┘  └──────────────┘  └──────────────┘ │
└─────────────────────────────────────────────────────────┘
```

## 🐛 Troubleshooting

### No output from Python applications?

Python uses `SSL_write_ex` (OpenSSL 3.x API). This is now supported! Try:
- Restart the Python script while `llm-spy` is running
- Use `--debug` to see if events are being captured

### Dropped samples warning?

Increase the perf buffer size in `main.go`:
```go
rd, err := perf.NewReader(objs.Events, 4096*128) // Increase from 64 to 128
```

### Partial JSON output?

Traffic might be fragmented. The buffer automatically reassembles, but you can:
- Wait a moment for complete reassembly
- Increase buffer timeout in the code

### Permission denied errors?

eBPF requires root privileges:
```bash
sudo ./llm-spy
```

## 🤝 Contributing

Contributions are welcome! Here are the **most impactful** areas where we need help:

### 🔥 High Priority: SSL Library Support

**The biggest challenge**: Most coding agents use BoringSSL or embedded SSL libraries, making them invisible to llm-spy.

- **BoringSSL Detection**: Develop methods to hook BoringSSL functions in Chromium/Electron apps
- **Go crypto/tls Support**: Add uprobes for Go's native TLS implementation
- **Rust TLS Support**: Hook rustls or statically linked OpenSSL in Rust binaries
- **Symbol Discovery**: Automatically find SSL functions in arbitrary binaries
- **Kernel-Level Hooks**: Intercept at socket layer (before SSL) as fallback

### Other Improvements

- **Additional Providers**: Add detection for more LLM APIs (Mistral, Together, etc.)
- **Cost Estimation**: Calculate costs based on token usage and provider pricing
- **Process Filtering**: Enhanced filtering by PID, cgroup, or container
- **Export Formats**: JSON, CSV, or database export options
- **Real-time Dashboard**: Web UI for live monitoring
- **Performance**: Optimize buffer management and parsing

### Development Setup

```bash
# Install dependencies
go mod download

# Generate BPF code
go generate

# Run tests
go test ./pkg/...

# Build
go build -o llm-spy
```

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

The BPF code (`bpf/probe.c`) is dual-licensed under BSD/GPL for kernel compatibility.

## 🙏 Acknowledgments

- [Cilium eBPF Library](https://github.com/cilium/ebpf) - Modern eBPF library for Go
- [eBPF.io](https://ebpf.io/) - eBPF documentation and community
- [BCC Project](https://github.com/iovisor/bcc) - Inspiration for SSL tracing techniques
- The Linux kernel eBPF community

## 📚 Additional Resources

- [eBPF Documentation](https://ebpf.io/what-is-ebpf/)
- [OpenSSL API Reference](https://www.openssl.org/docs/)
- [HTTP/2 Specification](https://httpwg.org/specs/rfc7540.html)
- [Server-Sent Events](https://html.spec.whatwg.org/multipage/server-sent-events.html)

---

**Note**: This tool is intended for debugging, monitoring, and research purposes on systems you own or have permission to monitor. Always respect privacy and comply with applicable laws and regulations.
