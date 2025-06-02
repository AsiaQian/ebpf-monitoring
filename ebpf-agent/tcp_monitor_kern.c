#include <uapi/linux/ptrace.h>
#include <linux/skbuff.h>
#include <linux/net.h>
#include <linux/tcp.h>
#include <net/sock.h>
#include <net/tcp.h>
#include <bcc/proto.h> // for IPV4 and IPV6 definitions

// Define a structure to hold event data
struct event {
    u64 timestamp_ns;
    u32 pid;
    u32 tgid; // Thread Group ID, usually process ID
    int af;   // Address Family (AF_INET/AF_INET6)
    u16 lport;
    u16 dport;
    u32 saddr_v4;
    u32 daddr_v4;
    unsigned __int128 saddr_v6;
    unsigned __int128 daddr_v6;
    char comm[TASK_COMM_LEN];
    int type; // 0: accept, 1: connect, 2: read, 3: write
    size_t data_len; // for read/write events
};

// Define a perf event map to send data to userspace
BPF_PERF_OUTPUT(events);

// Map to store active connections (pid -> sock*)
BPF_HASH(active_socks, u62, struct sock *);

// Kprobe for tcp_v{4,6}_connect
int kprobe__tcp_v4_connect(struct pt_regs *ctx, struct sock *sk) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;
    u32 tgid = pid_tgid;

    struct event ev = {};
    ev.timestamp_ns = bpf_ktime_get_ns();
    ev.pid = pid;
    ev.tgid = tgid;
    bpf_get_current_comm(&ev.comm, sizeof(ev.comm));
    ev.type = 1; // Connect event

    // Get connection info
    if (sk->__sk_common.skc_family == AF_INET) {
        ev.af = AF_INET;
        ev.lport = sk->__sk_common.skc_num;
        ev.dport = sk->__sk_common.skc_dport;
        ev.saddr_v4 = sk->__sk_common.skc_rcv_saddr;
        ev.daddr_v4 = sk->__sk_common.skc_daddr;
    } else if (sk->__sk_common.skc_family == AF_INET6) {
        ev.af = AF_INET6;
        ev.lport = sk->__sk_common.skc_num;
        ev.dport = sk->__sk_common.skc_dport;
        bpf_probe_read_kernel(&ev.saddr_v6, sizeof(ev.saddr_v6), &sk->__sk_common.skc_v6_rcv_saddr);
        bpf_probe_read_kernel(&ev.daddr_v6, sizeof(ev.daddr_v6), &sk->__sk_common.skc_v6_daddr);
    } else {
        // Not interested in other families
        return 0;
    }

    events.perf_submit(ctx, &ev, sizeof(ev));
    active_socks.update(&pid_tgid, &sk); // Store socket for later use with read/write
    return 0;
}

int kretprobe__tcp_v4_connect(struct pt_regs *ctx) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    active_socks.delete(&pid_tgid); // Clean up
    return 0;
}

int kprobe__tcp_v6_connect(struct pt_regs *ctx, struct sock *sk) {
    return kprobe__tcp_v4_connect(ctx, sk); // Reuse logic
}

int kretprobe__tcp_v6_connect(struct pt_regs *ctx) {
    return kretprobe__tcp_v4_connect(ctx); // Reuse logic
}

// Kprobe for tcp_accept and tcp_listen_accept
// This is trickier as it depends on kernel version. We will use a more generic approach if possible.
// For demonstration, we'll try to hook into a common accept path.
// Note: This might require adjustment based on specific kernel versions.
// A more robust approach might involve `sock_accept` or `inet_csk_accept`.
int kprobe__inet_csk_accept(struct pt_regs *ctx, struct sock *sk) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;
    u32 tgid = pid_tgid;

    struct event ev = {};
    ev.timestamp_ns = bpf_ktime_get_ns();
    ev.pid = pid;
    ev.tgid = tgid;
    bpf_get_current_comm(&ev.comm, sizeof(ev.comm));
    ev.type = 0; // Accept event

    // Get connection info (this is the listening socket, not the accepted one yet)
    // We need to capture the *returned* socket from inet_csk_accept.
    // This requires kretprobe.
    return 0;
}

int kretprobe__inet_csk_accept(struct pt_regs *ctx) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;
    u32 tgid = pid_tgid;
    struct sock *new_sk = (struct sock *)PT_REGS_RC(ctx); // The accepted socket

    if (new_sk == NULL) {
        return 0;
    }

    struct event ev = {};
    ev.timestamp_ns = bpf_ktime_get_ns();
    ev.pid = pid;
    ev.tgid = tgid;
    bpf_get_current_comm(&ev.comm, sizeof(ev.comm));
    ev.type = 0; // Accept event

    if (new_sk->__sk_common.skc_family == AF_INET) {
        ev.af = AF_INET;
        ev.lport = new_sk->__sk_common.skc_num;
        ev.dport = new_sk->__sk_common.skc_dport;
        ev.saddr_v4 = new_sk->__sk_common.skc_rcv_saddr;
        ev.daddr_v4 = new_sk->__sk_common.skc_daddr;
    } else if (new_sk->__sk_common.skc_family == AF_INET6) {
        ev.af = AF_INET6;
        ev.lport = new_sk->__sk_common.skc_num;
        ev.dport = new_sk->__sk_common.skc_dport;
        bpf_probe_read_kernel(&ev.saddr_v6, sizeof(ev.saddr_v6), &new_sk->__sk_common.skc_v6_rcv_saddr);
        bpf_probe_read_kernel(&ev.daddr_v6, sizeof(ev.daddr_v6), &new_sk->__sk_common.skc_v6_daddr);
    } else {
        return 0;
    }

    events.perf_submit(ctx, &ev, sizeof(ev));
    return 0;
}


// Syscall tracepoints for read and write
// This will capture all read/write, need to filter for network sockets in userspace
TRACEPOINT_PROBE(syscalls, sys_enter_read) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;
    u32 tgid = pid_tgid;

    struct event ev = {};
    ev.timestamp_ns = bpf_ktime_get_ns();
    ev.pid = pid;
    ev.tgid = tgid;
    bpf_get_current_comm(&ev.comm, sizeof(ev.comm));
    ev.type = 2; // Read event
    ev.data_len = args->count; // bytes to read

    // We can't easily get socket info from tracepoints without iterating fds.
    // This is a limitation. For network traffic, kprobes on `tcp_recvmsg` and `tcp_sendmsg`
    // would be more specific, but `read` and `write` are more general.
    // For this demo, we'll just report the read/write length.
    events.perf_submit(args, &ev, sizeof(ev));
    return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_write) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;
    u32 tgid = pid_tgid;

    struct event ev = {};
    ev.timestamp_ns = bpf_ktime_get_ns();
    ev.pid = pid;
    ev.tgid = tgid;
    bpf_get_current_comm(&ev.comm, sizeof(ev.comm));
    ev.type = 3; // Write event
    ev.data_len = args->count; // bytes to write

    events.perf_submit(args, &ev, sizeof(ev));
    return 0;
}