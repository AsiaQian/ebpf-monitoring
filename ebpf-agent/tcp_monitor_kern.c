// ebpf_tcp_accept_tracer.c

#include <uapi/linux/ptrace.h>
#include <net/sock.h>
#include <bcc/proto.h> // For ntohs
#include <linux/tcp.h> // For IPPROTO_TCP constant
#include <linux/in.h>  // For AF_INET
#include <linux/in6.h> // For AF_INET6, in6_addr

// TASK_COMM_LEN is typically 16 bytes for process name
#ifndef TASK_COMM_LEN
#define TASK_COMM_LEN 16
#endif

// Data structure to send event from kernel to userspace
// MUST match the Python struct exactly.
// We make saddr/daddr flexible to handle both IPv4 and IPv6.
// For IPv4, the address will be stored in the first 4 bytes of the u8[16] array.
struct accept_event_t {
    u32 pid;
    u8 ip_version; // 4 for IPv4, 6 for IPv6
    u8 saddr[16];  // Source IP (IPv4 stored in first 4 bytes, IPv6 in full 16)
    u8 daddr[16];  // Destination IP (IPv4 stored in first 4 bytes, IPv6 in full 16)
    u16 sport;     // Source Port (local port for server)
    u16 dport;     // Destination Port (remote port for server, client's source port)
    char comm[TASK_COMM_LEN]; // Process command name
};

// Define BPF_PERF_OUTPUT map to send events to userspace
BPF_PERF_OUTPUT(events);

// kretprobe for inet_csk_accept()
// This function is called when a new TCP connection is accepted.
// It returns a pointer to the new socket (struct sock *).
int kretprobe__inet_csk_accept(struct pt_regs *ctx) {
    struct sock *newsk = (struct sock *)PT_REGS_RC(ctx);
    u32 pid = bpf_get_current_pid_tgid() >> 32; // Get PID

    // Get connection details
    u16 family = newsk->__sk_common.skc_family; // AF_INET or AF_INET6
    u16 lport = newsk->__sk_common.skc_num;      // Local port (server's listening port)
    u16 dport = newsk->__sk_common.skc_dport;    // Remote port (client's source port, network byte order)
    dport = ntohs(dport);                         // Convert to host byte order

    // Initialize event data
    struct accept_event_t data = {}; // Initialize to zero
    data.pid = pid;
    data.sport = lport; // Server's listening port
    data.dport = dport; // Client's source port
    bpf_get_current_comm(&data.comm, sizeof(data.comm));

    if (family == AF_INET) {
        data.ip_version = 4;
        // For IPv4, copy saddr/daddr to the first 4 bytes of the u8[16] arrays
        // newsk->__sk_common.skc_rcv_saddr is the server's local IP (destination for client)
        // newsk->__sk_common.skc_daddr is the client's remote IP (source for client)
        bpf_probe_read_kernel(&data.saddr, 4, &newsk->__sk_common.skc_daddr); // Client's remote IP
        bpf_probe_read_kernel(&data.daddr, 4, &newsk->__sk_common.skc_rcv_saddr); // Server's local IP
    } else if (family == AF_INET6) {
        data.ip_version = 6;
        // For IPv6, copy full 16 bytes.
        // The address struct is a union, so we access u6_addr32 which is u32[4] (16 bytes).
        bpf_probe_read_kernel(&data.saddr, 16, &newsk->__sk_common.skc_v6_daddr.in6_u.u6_addr32); // Client's remote IP
        bpf_probe_read_kernel(&data.daddr, 16, &newsk->__sk_common.skc_v6_rcv_saddr.in6_u.u6_addr32); // Server's local IP
    } else {
        // Not AF_INET or AF_INET6, ignore this connection type
        return 0;
    }

    // Filter out invalid IPs (like 0.0.0.0 or :: for initial states)
    // This check ensures that both source and destination IPs are non-zero.
    // Loopback addresses (127.0.0.1, ::1) will pass this filter.
    bool saddr_is_zero = true;
    int addr_len = (data.ip_version == 4) ? 4 : 16;
    for (int i = 0; i < addr_len; i++) {
        if (data.saddr[i] != 0) {
            saddr_is_zero = false;
            break;
        }
    }
    bool daddr_is_zero = true;
    for (int i = 0; i < addr_len; i++) {
        if (data.daddr[i] != 0) {
            daddr_is_zero = false;
            break;
        }
    }

    if (saddr_is_zero || daddr_is_zero) {
        return 0;
    }

    // Submit the event to userspace
    events.perf_submit(ctx, &data, sizeof(data));

    return 0;
}