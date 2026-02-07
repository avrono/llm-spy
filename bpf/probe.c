// Copyright (c) 2026 llm-spy contributors
// SPDX-License-Identifier: MIT
// BPF License: Dual BSD/GPL (required for kernel compatibility)

//go:build ignore
#include "headers/vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";

// Data shared with userspace for uprobes
struct probe_data_t {
    u32 pid;
    u32 type;   // 0=SEND, 1=RECV
    u32 length;
    char comm[16]; // Process name
    u8 data[4096];
};

static __always_inline void opt_barrier(u32 va) {
    asm volatile("" : "+r"(va));
}

// Events map for uprobes
struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(u32));
    __uint(value_size, sizeof(u32));
} events SEC(".maps");

// State map for taking SSL_read arguments across function entry/exit
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, u64);
    __type(value, u64);
} active_reads SEC(".maps");

// Per-CPU array to store large data structures (avoid stack limit)
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, struct probe_data_t);
} data_buffer SEC(".maps");

// Config map to store Proxy PID
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, u32);
} config_map SEC(".maps");

// Helper to get buffer from per-CPU map
static __always_inline struct probe_data_t* get_data_buffer() {
    u32 key = 0;
    return bpf_map_lookup_elem(&data_buffer, &key);
}

// --------------------------------------------------------
// UPROBES (Original functionality for Python/etc)
// --------------------------------------------------------

SEC("uprobe/SSL_write")
int probe_ssl_write(struct pt_regs *ctx) {
    void *buf = (void *)PT_REGS_PARM2(ctx);
    u32 len = (u32)PT_REGS_PARM3(ctx);

    struct probe_data_t *data = get_data_buffer();
    if (!data) return 0;
    
    data->pid = bpf_get_current_pid_tgid() >> 32;
    data->type = 0;
    bpf_get_current_comm(&data->comm, sizeof(data->comm));

    if (len > 4096) len = 4096;
    data->length = len;
    bpf_probe_read_user(&data->data, 4096, buf);
    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, data, sizeof(*data));
    return 0;
}

SEC("uprobe/SSL_write_ex")
int probe_ssl_write_ex(struct pt_regs *ctx) {
    void *buf = (void *)PT_REGS_PARM2(ctx);
    u64 num = (u64)PT_REGS_PARM3(ctx);

    struct probe_data_t *data = get_data_buffer();
    if (!data) return 0;
    
    data->pid = bpf_get_current_pid_tgid() >> 32;
    data->type = 0;
    bpf_get_current_comm(&data->comm, sizeof(data->comm));

    u32 len = (u32)num;
    if (len > 4096) len = 4096;
    data->length = len;
    bpf_probe_read_user(&data->data, 4096, buf);
    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, data, sizeof(*data));
    return 0;
}

SEC("uprobe/SSL_read")
int probe_ssl_read_enter(struct pt_regs *ctx) {
    u64 id = bpf_get_current_pid_tgid();
    void *buf = (void *)PT_REGS_PARM2(ctx);
    bpf_map_update_elem(&active_reads, &id, &buf, BPF_ANY);
    return 0;
}

SEC("uretprobe/SSL_read")
int probe_ssl_read_exit(struct pt_regs *ctx) {
    u64 id = bpf_get_current_pid_tgid();
    void **buf_ptr = bpf_map_lookup_elem(&active_reads, &id);
    if (!buf_ptr) return 0;
    
    u64 ret = PT_REGS_RC(ctx);
    if (ret > 0x7FFFFFFF || ret == 0) {
        bpf_map_delete_elem(&active_reads, &id);
        return 0;
    }
    
    struct probe_data_t *data = get_data_buffer();
    if (!data) {
        bpf_map_delete_elem(&active_reads, &id);
        return 0;
    }
    
    data->pid = id >> 32;
    data->type = 1;
    bpf_get_current_comm(&data->comm, sizeof(data->comm));
    u32 len = (u32)ret;
    if (len > 4096) len = 4096;

    data->length = len;
    bpf_probe_read_user(&data->data, 4096, *buf_ptr);
    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, data, sizeof(*data));

    bpf_map_delete_elem(&active_reads, &id);
    return 0;
}

SEC("uprobe/SSL_read_ex")
int probe_ssl_read_ex_enter(struct pt_regs *ctx) {
    u64 id = bpf_get_current_pid_tgid();
    void *buf = (void *)PT_REGS_PARM2(ctx);
    bpf_map_update_elem(&active_reads, &id, &buf, BPF_ANY);
    return 0;
}

SEC("uretprobe/SSL_read_ex")
int probe_ssl_read_ex_exit(struct pt_regs *ctx) {
    u64 id = bpf_get_current_pid_tgid();
    void **buf_ptr = bpf_map_lookup_elem(&active_reads, &id);
    if (!buf_ptr) return 0;
    
    u64 ret = PT_REGS_RC(ctx);
    if (ret != 1) { // 1 means success in SSL_read_ex
        bpf_map_delete_elem(&active_reads, &id);
        return 0;
    }

    struct probe_data_t *data = get_data_buffer();
    if (!data) {
        bpf_map_delete_elem(&active_reads, &id);
        return 0;
    }
    
    data->pid = id >> 32;
    data->type = 1;
    bpf_get_current_comm(&data->comm, sizeof(data->comm));
    
    // We don't know exact length easily here without reading *read_bytes
    // For simplicity, we assume full buffer read or rely on userspace to parse valid TLS
    // Actually, *read_bytes is the 4th arg to SSL_read_ex, but we can't access it easily in uretprobe
    // unless we saved the pointer to it in entry probe.
    // For now, let's grab the buffer content up to MAX_DATA_LEN
    data->length = 4096;
    bpf_probe_read_user(&data->data, 4096, *buf_ptr);
    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, data, sizeof(*data));

    bpf_map_delete_elem(&active_reads, &id);
    return 0;
}

// --------------------------------------------------------
// CONNECT4 REDIRECT (For Chrome/Electron)
// --------------------------------------------------------

#define PROXY_PORT 8080

SEC("cgroup/connect4")
int connect4_redirect(struct bpf_sock_addr *ctx) {
    // 1. Filter: Only redirect TCP traffic
    if (ctx->type != SOCK_STREAM) return 1;

    // 2. Filter: Target Port 443 (HTTPS)
    u32 dest_port = bpf_ntohs(ctx->user_port);
    if (dest_port != 443) return 1;

    // 3. Filter: Ignore loopback traffic
    u32 dest_ip = ctx->user_ip4;
    // 127.0.0.1 in network byte order is usually 0x0100007F (little endian view of bytes)
    // Checking first byte (low address in LE)
    // 127 = 0x7F
    // bpf_htonl(0x7F000001) -> 0x0100007F (on LE system)
    // Let's just use 127 check for first octet in host order if we converted?
    // user_ip4 is Network Byte Order (Big Endian)
    // 127.0.0.1 -> 0x7F 0x00 0x00 0x01
    // If we read as u32, on LE machine it is 0x0100007F
    
    // Simplest check:
    // If (dest_ip & 0x000000FF) == 0x7F (if dest_ip is treated as little endian u32 but holds BE data?)
    // NO. bpf_ntohl(dest_ip) >> 24 == 127
    
    // Debug loopback filter
    // bpf_printk("IP: %x, Host: %x, Top: %x\n", dest_ip, bpf_ntohl(dest_ip), bpf_ntohl(dest_ip) >> 24);
    
    if ((bpf_ntohl(dest_ip) >> 24) == 127) return 1;

    bpf_printk("Redirecting connect to %pI4:443 -> 127.0.0.1:%d\n", &dest_ip, PROXY_PORT);

    // Redirect to localhost
    // ctx->user_ip4 = bpf_htonl(0x7F000001); // 127.0.0.1
    // Using simple constant for 127.0.0.1
    // Network Byte Order for 127.0.0.1 is 0x7F000001? 
    // Wait, ip "1.2.3.4" -> 0x01020304 in BE.
    // 127.0.0.1 -> 0x7F000001 in BE.
    // So we assign 0x0100007F (integer) converted to network (htonl) -> 0x7F000001.
    // Yes.
    
    // IMPORTANT: When redirecting, we MUST ensure the application can actually connect.
    // If we redirect to 127.0.0.1, we are bypassing the original route.
    // The issue might be infinite loops if the PROXY itself is also being redirected!
    // The proxy connects to upstream (port 443).
    // If the proxy runs on the SAME cgroup (root), its connect calls are ALSO intercepted.
    // And redirected to itself.
    // Infinite loop!
    
    // Fix: We need to filter out the Proxy's PID or use a magic mark.
    // But we don't know the Proxy PID easily here (it changes).
    
    // Workaround: The proxy connects to IPs, not localhost.
    // But our filter catches ALL port 443 traffic.
    // The proxy dials "upstreamIP:443". This triggers the hook.
    // The hook redirects it back to localhost:8080.
    // Proxy accepts it, sees SNI, dials upstream again... LOOP.
    
    // Solution 1: Use a specific cgroup for the proxy and exclude it.
    // Solution 2: Filter by PID (if we can pass it from userspace).
    // Solution 3: Check if we are already in a loop? Hard.
    
    // Let's rely on a PID map.
    // Userspace should update a map with its own PID.
    
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    // u32 *proxy_pid = bpf_map_lookup_elem(&proxy_pid_map, &pid); // wait we need a map key 0 -> pid
    
    // Or simpler: Just a single element map storing the proxy PID.
    u32 key = 0;
    u32 *p_pid = bpf_map_lookup_elem(&config_map, &key);
    if (p_pid && *p_pid == pid) {
         // This is the proxy itself! Let it pass.
         bpf_printk("Ignoring proxy traffic PID %d\n", pid);
         return 1;
    }

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

    // 3. Filter: Proxy PID (Avoid infinite loop)
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u32 key = 0;
    u32 *p_pid = bpf_map_lookup_elem(&config_map, &key);
    if (p_pid && *p_pid == pid) {
         bpf_printk("Ignoring proxy traffic (IPv6) PID %d\n", pid);
         return 1;
    }

    // 4. Filter: Ignore loopback traffic (::1)
    if (ctx->user_ip6[0] == 0 && ctx->user_ip6[1] == 0 && ctx->user_ip6[2] == 0 && ctx->user_ip6[3] == bpf_htonl(1)) {
        return 1; 
    }

    bpf_printk("Redirecting connect6 to port 443 -> [::1]:%d\n", PROXY_PORT);

    // Redirect to ::1 (IPv6 Loopback)
    // ::1 is 0,0,0,1 in network order (if interpreted as 4 u32s? No, just bytes)
    // 00..00 00..01
    ctx->user_ip6[0] = 0;
    ctx->user_ip6[1] = 0;
    ctx->user_ip6[2] = 0;
    ctx->user_ip6[3] = bpf_htonl(1);
    
    ctx->user_port = bpf_htons(PROXY_PORT);

    return 1;
}
