from bcc import BPF
import ctypes as ct
import socket
import struct
import time
import json
import requests
from prometheus_client import Counter, start_http_server # 引入 prometheus_client

# eBPF C code filename
EBPF_KERN_FILE = "tcp_monitor_kern.c"

# Event structure matching the C code
class Event(ct.Structure):
    _fields_ = [
        ("timestamp_ns", ct.c_ulonglong),
        ("pid", ct.c_uint),
        ("tgid", ct.c_uint),
        ("af", ct.c_int),
        ("lport", ct.c_ushort),
        ("dport", ct.c_ushort),
        ("saddr_v4", ct.c_uint),
        ("daddr_v4", ct.c_uint),
        ("saddr_v6", ct.c_ubyte * 16),
        ("daddr_v6", ct.c_ubyte * 16),
        ("comm", ct.c_char * 16), # TASK_COMM_LEN is 16
        ("type", ct.c_int),
        ("data_len", ct.c_ulonglong), # This will always be 0 now as read/write tracepoints are removed
    ]

# --- Prometheus Metrics ---
# 1. 定义 Prometheus Counter
# 'app_call_count' 是指标名称
# 'Total number of application calls.' 是帮助信息
# ['source_app', 'dest_app', 'call_type'] 是标签列表
APP_CALL_COUNT = Counter('app_call_count', 'Total number of application calls.',
                         ['source_app', 'dest_app', 'call_type'])

# 如果将来需要字节传输量，可以这样定义：
# APP_BYTES_TRANSFERRED = Counter('app_bytes_transferred', 'Total bytes transferred during application calls.',
#                                 ['source_app', 'dest_app', 'call_type'])
# 注意：您的 eBPF 程序目前没有传输 data_len，所以这个指标暂时不会增加。

# `metrics_store`, `update_metrics`, `get_metrics_prometheus_format`, `PrometheusMetricsHandler`, `start_metrics_server` 这些函数和变量
# 在使用 prometheus_client 后都可以被移除或大幅简化，因为库已经提供了这些功能。
# 为了保持代码的最小改动并展示新方法，我将只移除直接相关的部分并替换为 prometheus_client 的调用。
# 因此，旧的 `metrics_store`, `update_metrics`, `get_metrics_prometheus_format` 将不再需要。

def print_event(cpu, data, size):
    event = ct.cast(data, ct.POINTER(Event)).contents

    comm = event.comm.decode('utf-8', 'ignore')
    timestamp_ms = event.timestamp_ns / 1_000_000

    saddr = ""
    daddr = ""
    if event.af == socket.AF_INET:
        saddr = socket.inet_ntop(socket.AF_INET, struct.pack("I", event.saddr_v4))
        daddr = socket.inet_ntop(socket.AF_INET, struct.pack("I", event.daddr_v4))
    elif event.af == socket.AF_INET6:
        saddr = socket.inet_ntop(socket.AF_INET6, bytes(event.saddr_v6))
        daddr = socket.inet_ntop(socket.AF_INET6, bytes(event.daddr_v6))

    event_type_str = ""

    source_app = comm # Default source for client processes
    dest_app = "unknown" # Default dest
    call_type = "unknown"

    if event.type == 0: # ACCEPT event
        event_type_str = "ACCEPT"
        if event.dport == 3306:
            dest_app = "mysql"
            call_type = "java-to-mysql"
        else:
            dest_app = "java_app_listener"
            call_type = "java-to-java"
        source_app = 'client_app' # For accepted connections, the initiator is a "client_app"
        # 2. 直接更新 Prometheus Counter
        APP_CALL_COUNT.labels(source_app=source_app, dest_app=dest_app, call_type=call_type).inc()

    elif event.type == 1: # CONNECT event
        event_type_str = "CONNECT"
        if event.dport == 3306:
            dest_app = "mysql"
            call_type = "java-to-mysql"
        else:
            dest_app = "java_app_target"
            call_type = "java-to-java"
        # 2. 直接更新 Prometheus Counter
        APP_CALL_COUNT.labels(source_app=source_app, dest_app=dest_app, call_type=call_type).inc()

    print(f"{timestamp_ms:10.3f} {comm:16s} ({event.pid:6d}/{event.tgid:6d}) {event_type_str:7s} "
          f"{saddr}:{event.lport:<5d} -> {daddr}:{event.dport:<5d} "
          f"AF:{event.af}")

# Load the eBPF program
try:
    with open(EBPF_KERN_FILE, "r") as f:
        bpf_text = f.read()
    b = BPF(text=bpf_text)
except Exception as e:
    print(f"Error loading BPF program: {e}")
    exit(1)

# Attach kprobes and tracepoints
try:
    b.attach_kprobe(event="tcp_v4_connect", fn_name="kprobe__tcp_v4_connect")
    b.attach_kretprobe(event="tcp_v4_connect", fn_name="kretprobe__tcp_v4_connect")
    b.attach_kprobe(event="tcp_v6_connect", fn_name="kprobe__tcp_v6_connect")
    b.attach_kretprobe(event="tcp_v6_connect", fn_name="kretprobe__tcp_v6_connect")
    b.attach_kprobe(event="inet_csk_accept", fn_name="kprobe__inet_csk_accept")
    b.attach_kretprobe(event="inet_csk_accept", fn_name="kretprobe__inet_csk_accept")

except Exception as e:
    print(f"Error attaching BPF probes: {e}")
    exit(1)

print("eBPF TCP Monitor is running. (Read/Write syscalls no longer monitored)")
print("Press Ctrl+C to stop.")
print(f"{'Time':<10} {'Comm':<16} {'PID/TGID':<13} {'Event':<7} {'Source':<21} {'Dest':<21} {'AF':<4}")

# --- Start Prometheus HTTP server using prometheus_client ---
metrics_port = 8000
try:
    start_http_server(metrics_port)
    print(f"eBPF Exporter: Serving metrics on port {metrics_port}")
except Exception as e:
    print(f"Error starting Prometheus HTTP server: {e}")
    exit(1)

# Read events from the perf buffer
try:
    b["events"].open_perf_buffer(print_event)
    while True:
        b.perf_buffer_poll()
except KeyboardInterrupt:
    print("\nStopping eBPF TCP Monitor.")
except Exception as e:
    print(f"An error occurred: {e}")