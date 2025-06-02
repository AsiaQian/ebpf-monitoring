#include <uapi/linux/ptrace.h>
#include <linux/skbuff.h>
#include <linux/net.h>
#include <linux/tcp.h>
#include <net/sock.h>
#include <net/tcp.h>
#include <bcc/proto.h> // for IPV4 and IPV6 definitions

// === 修正：将结构体和 BPF map 定义移动到顶部 ===

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
    int type; // 0: accept, 1: connect, 2: read, 3: write (read/write types will not be generated with this code)
    size_t data_len; // for read/write events (will be 0 with this code)
};

// Define a perf event map to send data to userspace
BPF_PERF_OUTPUT(events);

// Map to store active connections (pid -> sock*)
BPF_HASH(active_socks, u64, struct sock *);

// === 辅助函数和探针定义在结构体和 map 定义之后 ===

// Helper function to handle common connect logic for IPv4 and IPv6
static __always_inline int handle_connect(struct pt_regs *ctx, struct sock *sk) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;
    u32 tgid = pid_tgid;

    struct event ev = {}; // 现在 struct event 已经完整定义
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

    events.perf_submit(ctx, &ev, sizeof(ev)); // 现在 events 已经声明
    active_socks.update(&pid_tgid, &sk); // 现在 active_socks 已经声明
    return 0;
}

// Helper function to handle common disconnect logic
static __always_inline int handle_disconnect(struct pt_regs *ctx) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    active_socks.delete(&pid_tgid); // 现在 active_socks 已经声明
    return 0;
}


// Kprobe for tcp_v{4,6}_connect
int kprobe__tcp_v4_connect(struct pt_regs *ctx, struct sock *sk) {
    return handle_connect(ctx, sk); // 调用通用连接逻辑
}

int kretprobe__tcp_v4_connect(struct pt_regs *ctx) {
    return handle_disconnect(ctx); // 调用通用断开连接逻辑
}

int kprobe__tcp_v6_connect(struct pt_regs *ctx, struct sock *sk) {
    return handle_connect(ctx, sk); // 调用通用连接逻辑
}

int kretprobe__tcp_v6_connect(struct pt_regs *ctx) {
    return handle_disconnect(ctx); // 调用通用断开连接逻辑
}

// Kprobe for inet_csk_accept
int kprobe__inet_csk_accept(struct pt_regs *ctx, struct sock *sk) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;
    u32 tgid = pid_tgid;

    struct event ev = {}; // 现在 struct event 已经完整定义
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

    struct event ev = {}; // 现在 struct event 已经完整定义
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

    events.perf_submit(ctx, &ev, sizeof(ev)); // 现在 events 已经声明
    return 0;
}