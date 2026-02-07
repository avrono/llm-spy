# LLM Traffic Monitor - Architecture Suggestions

## Goal
To monitor outgoing and incoming data to LLM agents running on a Linux machine. The primary challenge is that communication with LLM providers (OpenAI, Anthropic, etc.) is encrypted via HTTPS (TLS), preventing simple network packet sniffing (like tcpdump/wireshark) from seeing the payload (prompts/responses).

## Strategy 1: Explicit MITM Proxy (Non-eBPF)
The traditional approach. You run a local HTTP/HTTPS proxy server and configure your LLM Agents to route traffic through it.

*   **Mechanism**: The proxy intercepts the connection, presents its own SSL certificate to the client (Agent), and establishes a separate connection to the upstream server (LLM Provider).
*   **Requirements**:
    *   Agents must support proxy configuration (e.g., `HTTPS_PROXY` environment variable).
    *   Agents must trust the Proxy's Certificate Authority (CA), or SSL verification must be disabled.
*   **Pros**: Relies on standard networking protocols; easiest to implement basic filtering/modification.
*   **Cons**: Invasive configuration; "Pinned" certificates in agents will break this; not "invisible".

## Strategy 2: Transparent Proxy + eBPF Redirection
A hybrid approach. You use eBPF to transparently capture traffic and redirect it to a local proxy, without configuring the application.

*   **Mechanism**:
    *   **eBPF/Sockmap**: Attach BPF programs to socket hooks (`connect`, `sendmsg`, `recvmsg`).
    *   **Redirection**: Recognize traffic destined for port 443 (or specific IPs) and redirect the socket to a local listener (MITM Proxy).
    *   **Proxy**: The local proxy handles the TLS termination.
*   **Pros**: Application doesn't need proxy configuration.
*   **Cons**: Still faces the TLS Encryption problem. The application will see an invalid certificate (from the proxy) unless the system-wide trust store is updated, or the application checks are disabled.

## Strategy 3: eBPF uProbes / kProbes (Recommended for "Monitoring")
The "Observability" approach. Instead of sitting *on the network*, we sit *inside the process*. We attach eBPF probes to the functions responsible for encryption *before* the data is encrypted (for sending) or *after* it is decrypted (for receiving).

*   **Mechanism**:
    *   **Dynamic Libraries (OpenSSL/GnuTLS)**: Use `uprobes` (User Probes) to hook functions like `SSL_write` and `SSL_read`. The arguments to these functions contain the cleartext buffer.
    *   **Static Binaries (Go/Rust)**: Many modern agents are written in Go, which uses a static `crypto/tls` library. We must attach `uprobes` to the specific symbols in the binary (e.g., `crypto/tls.(*Conn).Write`).
*   **Architecture**:
    1.  **Kernel Space (eBPF)**: 
        *   Probe fires on `SSL_write(ssl, buf, len)`.
        *   Capture `pid`, `comm` (process name), and the data in `buf`.
        *   Send event to User Space via `perf_buffer` or `ring_buffer`.
    2.  **User Space (Controller)**:
        *   Load specific BPF programs based on target application type (Python app vs Go Binary).
        *   Parse events and reconstruction streams (HTTP requests).
        *   Log specific LLM JSON bodies.
*   **Pros**:
    *   **Zero Configuration**: No proxy settings, no cert stuffing, no breaking SSL pinning.
    *   **Invisible**: The agent is unaware it is being watched.
*   **Cons**:
    *   **Fragile**: Depends on internal function signatures (API) of libraries (OpenSSL versioning) or languages (Go ABI).
    *   **Complexity**: Requires handling multiple TLS implementations (OpenSSL, Go `crypto/tls`, BoringSSL).

---

## Recommended Solution: eBPF uProbe Monitor
Given your folder is `/ebpf_exp` (eBPF experiments), the **Strategy 3** (Interception via uProbes) is the most educational and powerful approach for a local monitor. It allows you to "trace" the LLM calls without setting up complex networking proxies.

### Recommended Stack

#### Language: **Go (Golang)** or **Python**
*   **Go** is preferred for the "Agent" side (the monitor itself) because of excellent eBPF library support and distribution (single binary).
*   **Python** is great for rapid prototyping using the BCC (BPF Compiler Collection) framework.

#### Frameworks & Libraries
1.  **Go + `cilium/ebpf`**:
    *   The modern standard for eBPF in Go. Use `rlimit` to manage memory, generating BPF skeletons from C code.
    *   *Why*: Type-safe, high performance, clean distinct kernel (C) vs user (Go) separation.
2.  **Python + `bcc`**:
    *   Classic toolkit. Allows writing C BPF code inside Python string.
    *   *Why*: Easiest "Hello World". Good for "SSL Sniffing" examples which are abundant in the BCC repo.

### Implementation Blueprint (Python/BCC Start)

1.  **Identify Target**: Is the LLM agent Python (using `requests` -> `urllib3` -> `ssl` -> `openssl`) or Go (static)?
    *   *Python Apps*: Hook `libssl.so` symbols `SSL_write` / `SSL_read`.
    *   *Go Apps*: Identify binary path, finding offsets for `crypto/tls.(*Conn).Write`.
2.  **eBPF Code (C)**:
    ```c
    int probe_ssl_write(struct pt_regs *ctx, void *ssl, void *buf, int num) {
        // Read cleartext 'buf'
        // Push to perf buffer
    }
    ```
3.  **User Space (Python)**:
    *   Attach to `/usr/lib/x86_64-linux-gnu/libssl.so.3`.
    *   Poll perf buffer.
    *   Decode byte stream.
    *   Heuristic parsing: Look for `POST /v1/chat/completions`, JSON bodies.

### Implementation Blueprint (Go/Cilium)

For a robust tool, verify using **Go**. It can handle the high throughput of buffers better and compile into a standalone `llm-spy` binary.

1.  Write `bpf/probes.c` defining `SEC("uprobe/SSL_write")`.
2.  Use `bpf2go` to generate Go structs.
3.  Load the program and attach to discovered libraries or PIDs.
