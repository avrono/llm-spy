//go:build ignore
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#define AF_INET   2
#define AF_INET6 10

char __license[] SEC("license") = "Dual MIT/GPL";

struct event {
	u32 pid;
	u32 type; // 0=CONNECT (OUT), 1=ACCEPT (IN)
	u16 family; // AF_INET (2) or AF_INET6 (10)
	u8  comm[16];
	u32 saddr[4]; // IPv4 uses index 0, IPv6 uses all 4
	u32 daddr[4];
	u16 sport;
	u16 dport;
};

struct {
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
} events SEC(".maps");

// capture outgoing IPv4/IPv6 connections
// We use tcp_connect instead of tcp_v4_connect because at this point
// the socket (sk) is usually fully populated with source/dest info.
SEC("kprobe/tcp_connect")
int kprobe_tcp_connect(struct pt_regs *ctx) {
	struct sock *sk = (struct sock *)PT_REGS_PARM1(ctx);
	struct event evt = {};

	evt.pid = bpf_get_current_pid_tgid() >> 32;
	evt.type = 0; // CONNECT
	bpf_get_current_comm(&evt.comm, sizeof(evt.comm));

	// Read Family
	evt.family = BPF_CORE_READ(sk, __sk_common.skc_family);

	// Read Ports
	evt.sport = BPF_CORE_READ(sk, __sk_common.skc_num);
	evt.dport = BPF_CORE_READ(sk, __sk_common.skc_dport);

	if (evt.family == AF_INET) {
		// IPv4
		u32 saddr = BPF_CORE_READ(sk, __sk_common.skc_rcv_saddr);
		u32 daddr = BPF_CORE_READ(sk, __sk_common.skc_daddr);
		evt.saddr[0] = saddr;
		evt.daddr[0] = daddr;
		
		// Filter 0.0.0.0
		if (daddr == 0) return 0;
	} else if (evt.family == AF_INET6) {
		// IPv6
		BPF_CORE_READ_INTO(&evt.saddr, sk, __sk_common.skc_v6_rcv_saddr.in6_u.u6_addr32);
		BPF_CORE_READ_INTO(&evt.daddr, sk, __sk_common.skc_v6_daddr.in6_u.u6_addr32);
	} else {
		// Unknown family, ignore
		return 0;
	}

	bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &evt, sizeof(evt));
	return 0;
}

// capture incoming IPv4/IPv6 connections (accepted)
// inet_csk_accept returns the new socket on success
SEC("kretprobe/inet_csk_accept")
int kretprobe_inet_csk_accept(struct pt_regs *ctx) {
	struct sock *newsk = (struct sock *)PT_REGS_RC(ctx);
	
	if (newsk == NULL) return 0;

	struct event evt = {};
	evt.pid = bpf_get_current_pid_tgid() >> 32;
	evt.type = 1; // ACCEPT
	bpf_get_current_comm(&evt.comm, sizeof(evt.comm));

	evt.family = BPF_CORE_READ(newsk, __sk_common.skc_family);
	evt.sport = BPF_CORE_READ(newsk, __sk_common.skc_num);        // local port
	evt.dport = BPF_CORE_READ(newsk, __sk_common.skc_dport);      // remote port

	if (evt.family == AF_INET) {
		evt.saddr[0] = BPF_CORE_READ(newsk, __sk_common.skc_rcv_saddr); // local IP
		evt.daddr[0] = BPF_CORE_READ(newsk, __sk_common.skc_daddr);     // remote IP
	} else if (evt.family == AF_INET6) {
		BPF_CORE_READ_INTO(&evt.saddr, newsk, __sk_common.skc_v6_rcv_saddr.in6_u.u6_addr32);
		BPF_CORE_READ_INTO(&evt.daddr, newsk, __sk_common.skc_v6_daddr.in6_u.u6_addr32);
	} else {
		return 0;
	}

	bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &evt, sizeof(evt));
	return 0;
}
