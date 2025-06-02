#include <uapi/linux/ptrace.h>
#include <linux/skbuff.h>
#include <linux/net.h>
#include <linux/tcp.h>
#include <net/sock.h>
#include <net/tcp.h>
#include <bcc/proto.h>
#include <linux/in6.h> // 确保包含此头文件以获取 in6_addr 定义

// Event data structure with explicit padding for precise alignment
// This is the most robust way to ensure C and Python agree on memory layout.
struct event {
    // Total size: 8 + 8 + 8 + 8 + 4 + 4 + 4 + 4 + 2 + 2 + 2 + 4 + 16 = 70 bytes.
    // 70 is not a multiple of 8. We need to pad to 72 or 80.
    // Let's ensure fields start on 8-byte boundaries where possible and end on 8-byte boundary.

    // Grouping 64-bit fields first for natural alignment
    u64 saddr_v6_h;             // Offset 0, size 8
    u64 saddr_v6_l;             // Offset 8, size 8
    u64 daddr_v6_h;             // Offset 16, size 8
    u64 daddr_v6_l;             // Offset 24, size 8

    // Grouping 32-bit fields
    u32 saddr_v4;               // Offset 32, size 4
    u32 daddr_v4;               // Offset 36, size 4
    u32 pid;                    // Offset 40, size 4
    u32 tgid;                   // Offset 44, size 4

    // Grouping 16-bit fields
    u16 lport;                  // Offset 48, size 2
    u16 dport;                  // Offset 50, size 2
    u16 family;                 // Offset 52, size 2
    // Current total: 54 bytes. Next field 'type' (4 bytes) would start at 54.
    // If we want 'type' to align on 4-byte boundary, we need 2 bytes padding here.
    char __pad0[2];             // Offset 54, size 2 bytes padding (to align type to 56)

    int type;                   // Offset 56, size 4 bytes (0: accept, 1: connect)

    // Current total: 56 + 4 = 60 bytes. Next field 'comm' (16 bytes) would start at 60.
    // Total is 60 + 16 = 76 bytes. Not a multiple of 8. We need 4 bytes padding at the end.
    char comm[16];              // Offset 60, size 16 bytes (TASK_COMM_LEN)

    // Current total: 76 bytes. Pad to nearest multiple of 8 (which is 80)
    char __pad1[4];             // Offset 76, size 4 bytes padding (to make total size 80)
} __attribute__((packed)); // Keep packed to ensure *our* padding works as intended

// Perf event map to send data to userspace
BPF_PERF_OUTPUT(events); // This defines a map named 'events'

// Common connect logic (remains the same)
static __always_inline int handle_connect(struct pt_regs *ctx, struct sock *sk) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;
    u32 tgid = pid_tgid;

    struct event ev = {}; // Initializes all fields to 0, including padding
    ev.pid = pid;
    ev.tgid = tgid;
    bpf_get_current_comm(&ev.comm, sizeof(ev.comm));
    ev.type = 1; // Connect event

    // Initialize family to 0 (unknown) - already done by ev={}

    if (sk->__sk_common.skc_family == AF_INET) {
        ev.family = AF_INET; // Set family
        ev.lport = sk->__sk_common.skc_num;
        ev.dport = sk->__sk_common.skc_dport;
        ev.saddr_v4 = sk->__sk_common.skc_rcv_saddr; // These are in network byte order
        ev.daddr_v4 = sk->__sk_common.skc_daddr;     // These are in network byte order
    } else if (sk->__sk_common.skc_family == AF_INET6) {
        ev.family = AF_INET6; // Set family
        ev.lport = sk->__sk_common.skc_num;
        ev.dport = sk->__sk_common.skc_dport;

        // **改进：更安全的 IPv6 地址读取方式**
        // struct in6_addr 通常由 s6_addr32[4] (4个u32) 组成。
        // 读取前两个u32作为saddr_v6_h，后两个u32作为saddr_v6_l。
        // 注意：这里读取的是 u32，然后存入 u64。由于 BPF 读取是按字节的，
        // 且通常 s6_addr32 内部已经是网络字节序，这样读取是安全的。
        // Python 端会将其合并成 128 位并以大端序解释。
        // bpf_probe_read_kernel expects a pointer to the source and a size.
        // We are reading 8 bytes (sizeof(u64)) at a time.
        // For saddr_v6_h, read from s6_addr32[0] (first two u32s).
        // For saddr_v6_l, read from s6_addr32[2] (last two u32s).
        bpf_probe_read_kernel(&ev.saddr_v6_h, sizeof(ev.saddr_v6_h), &sk->__sk_common.skc_v6_rcv_saddr.s6_addr32[0]);
        bpf_probe_read_kernel(&ev.saddr_v6_l, sizeof(ev.saddr_v6_l), &sk->__sk_common.skc_v6_rcv_saddr.s6_addr32[2]);
        bpf_probe_read_kernel(&ev.daddr_v6_h, sizeof(ev.daddr_v6_h), &sk->__sk_common.skc_v6_daddr.s6_addr32[0]);
        bpf_probe_read_kernel(&ev.daddr_v6_l, sizeof(ev.daddr_v6_l), &sk->__sk_common.skc_v6_daddr.s6_addr32[2]);
    } else {
        return 0; // Not interested in other families
    }

    events.perf_submit(ctx, &ev, sizeof(ev));
    return 0;
}

// Common accept logic (remains the same)
static __always_inline int handle_accept(struct pt_regs *ctx, struct sock *new_sk) {
    if (new_sk == NULL) {
        return 0;
    }

    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;
    u32 tgid = pid_tgid;

    struct event ev = {}; // Initializes all fields to 0
    ev.pid = pid;
    ev.tgid = tgid;
    bpf_get_current_comm(&ev.comm, sizeof(ev.comm));
    ev.type = 0; // Accept event

    if (new_sk->__sk_common.skc_family == AF_INET) {
        ev.family = AF_INET; // Set family
        ev.lport = new_sk->__sk_common.skc_num;
        ev.dport = new_sk->__sk_common.skc_dport;
        ev.saddr_v4 = new_sk->__sk_common.skc_rcv_saddr;
        ev.daddr_v4 = new_sk->__sk_common.skc_daddr;
    } else if (new_sk->__sk_common.skc_family == AF_INET6) {
        ev.family = AF_INET6; // Set family
        ev.lport = new_sk->__sk_common.skc_num;
        ev.dport = new_sk->__sk_common.skc_dport;

        bpf_probe_read_kernel(&ev.saddr_v6_h, sizeof(ev.saddr_v6_h), &new_sk->__sk_common.skc_v6_rcv_saddr.s6_addr32[0]);
        bpf_probe_read_kernel(&ev.saddr_v6_l, sizeof(ev.saddr_v6_l), &new_sk->__sk_common.skc_v6_rcv_saddr.s6_addr32[2]);
        bpf_probe_read_kernel(&ev.daddr_v6_h, sizeof(ev.daddr_v6_h), &new_sk->__sk_common.skc_v6_daddr.s6_addr32[0]);
        bpf_probe_read_kernel(&ev.daddr_v6_l, sizeof(ev.daddr_v6_l), &new_sk->__sk_common.skc_v6_daddr.s6_addr32[2]);
    } else {
        return 0;
    }

    events.perf_submit(ctx, &ev, sizeof(ev));
    return 0;
}

// Kprobe for tcp_v4_connect
int kprobe__tcp_v4_connect(struct pt_regs *ctx, struct sock *sk) {
    return handle_connect(ctx, sk);
}

// Kprobe for tcp_v6_connect
int kprobe__tcp_v6_connect(struct pt_regs *ctx, struct sock *sk) {
    return handle_connect(ctx, sk);
}

// Kretprobe for inet_csk_accept
int kretprobe__inet_csk_accept(struct pt_regs *ctx) {
    struct sock *new_sk = (struct sock *)PT_REGS_RC(ctx); // The accepted socket
    return handle_accept(ctx, new_sk);
}