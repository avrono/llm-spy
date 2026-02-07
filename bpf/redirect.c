//go:build ignore
#include "headers/vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";

// Map to store original destination for the proxy to lookup
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 65535);
    __type(key, struct bpf_sock_tuple); // source IP/Port -> dest IP/Port
    __type(value, struct sockaddr_in); // Original destination
} proxy_map SEC(".maps");

// Define PROXY_PORT (will be replaced by loader or compile flag if needed, hardcoded for now)
#define PROXY_PORT 8080

// Helper to check if IP is loopback (127.0.0.1)
static __always_inline bool is_loopback(u32 ip) {
    return (ip & 0xFF) == 127;
}

SEC("cgroup/connect4")
int connect4_redirect(struct bpf_sock_addr *ctx) {
    // 1. Filter: Only redirect TCP traffic
    if (ctx->type != SOCK_STREAM) return 1;

    // 2. Filter: Target Port 443 (HTTPS)
    u32 dest_port = bpf_ntohs(ctx->user_port);
    if (dest_port != 443) return 1;

    // 3. Filter: Ignore loopback traffic (avoid redirecting the proxy itself!)
    // ctx->user_ip4 is network byte order
    u32 dest_ip = ctx->user_ip4;
    // 127.0.0.1 in network byte order is usually 0x0100007F (little endian view of bytes)
    // Checking first byte (low address in LE)
    if ((dest_ip & 0xFF) == 127) return 1;

    // 4. Save original destination
    u64 cookie = bpf_get_socket_cookie(ctx);
    // Note: We need a way to look this up later.
    // For transparent proxying with SO_ORIGINAL_DST, we usually don't need a map
    // if we are just rewriting user_ip4/port. The kernel tracks the original dst.
    // However, to support 'getsockopt' looking up the original destination if not using TPROXY,
    // we might need to store it.
    //
    // BUT: standard Linux "redirect" behavior in cgroup/connect4 actually changes the destination
    // transparently. The application thinks it's connecting to 1.2.3.4:443, but packets go to localhost:8080.
    // The Proxy receiving the connection needs to know the ORIGINAL destination.
    //
    // For this simple implementation, we will use a naive approach:
    // Just rewrite destination to 127.0.0.1:PROXY_PORT.
    // The Go proxy will need to use 'SO_ORIGINAL_DST' (if supported by netfilter/iptables logic) OR
    // we use a BPF map keyed by (SourceIP, SourcePort) -> (OriginalDestIP, OriginalDestPort).
    //
    // Challenge: At 'connect4', we might not know the Source Port yet if it's ephemeral (0).
    //
    // Alternative: Just proxy everything to a generic "Forward Proxy" if the client supports it?
    // No, we want transparent.
    //
    // Let's stick to simple redirection for now and see if we can infer destination from the SNI in the TLS ClientHello
    // which the Go proxy will see! This is much more robust for HTTP/HTTPS.

    bpf_printk("Redirecting connect to %pI4:443 -> 127.0.0.1:%d\n", &dest_ip, PROXY_PORT);

    // Redirect to localhost
    ctx->user_ip4 = bpf_htonl(0x7F000001); // 127.0.0.1
    ctx->user_port = bpf_htons(PROXY_PORT);

    return 1;
}

SEC("cgroup/connect6")
int connect6_redirect(struct bpf_sock_addr *ctx) {
    // 1. Filter: Only redirect TCP traffic
    if (ctx->type != SOCK_STREAM) return 1;

    // 2. Filter: Target Port 443 (HTTPS)
    u32 dest_port = bpf_ntohs(ctx->user_port);
    if (dest_port != 443) return 1;

    // 3. Filter: Ignore loopback traffic (avoid redirecting the proxy itself!)
    // Check if dest is ::1
    // user_ip6 is __u32[4]
    u32 *ip6 = ctx->user_ip6;
    if (ip6[0] == 0 && ip6[1] == 0 && ip6[2] == 0 && ip6[3] == bpf_htonl(1)) {
        return 1; 
    }

    bpf_printk("Redirecting connect6 to port 443 -> [::1]:%d\n", PROXY_PORT);

    // Redirect to ::1 (IPv6 Loopback)
    ctx->user_ip6[0] = 0;
    ctx->user_ip6[1] = 0;
    ctx->user_ip6[2] = 0;
    ctx->user_ip6[3] = bpf_htonl(1);
    
    ctx->user_port = bpf_htons(PROXY_PORT);

    return 1;
}
