from bcc import BPF
import ctypes as ct
import socket
import struct
import time
import json
import requests # For sending data to a Prometheus Pushgateway or custom exporter

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

# Prometheus Pushgateway URL (if used)
PROMETHEUS_PUSHGATEWAY_URL = "http://localhost:9091" # To be replaced with K8s service

# In-memory store for metrics (for a simple HTTP exporter)
metrics_store = {}

def update_metrics(key_dict, metric_type, value=1):
    """Updates a metric in the in-memory store.
    key_dict must be a dictionary that will be converted to a hashable tuple.
    """
    # === 关键修复点：将字典 key_dict 转换为可哈希的元组 ===
    # 排序是为了确保键值对顺序不同但内容相同的字典能生成相同的哈希值
    hashable_key = tuple(sorted(key_dict.items()))

    if hashable_key not in metrics_store:
        metrics_store[hashable_key] = {}
    if metric_type not in metrics_store[hashable_key]:
        metrics_store[hashable_key][metric_type] = 0
    metrics_store[hashable_key][metric_type] += value

def get_metrics_prometheus_format():
    """Generates Prometheus exposition format from metrics_store."""
    output = []
    for hashable_key, data in metrics_store.items():
        # 将可哈希的元组（hashable_key）转换回字典，以便访问其内容
        key_dict = dict(hashable_key)
        source_app = key_dict.get('source_app', 'unknown')
        dest_app = key_dict.get('dest_app', 'unknown')
        call_type = key_dict.get('call_type', 'unknown') # 'java-to-java', 'java-to-mysql'

        # Connection/Call Count
        if 'call_count' in data:
            output.append(f'# HELP app_call_count Total number of application calls.\n')
            output.append(f'# TYPE app_call_count counter\n')
            output.append(f'app_call_count{{source_app="{source_app}",dest_app="{dest_app}",call_type="{call_type}"}} {data["call_count"]}\n')

        # Bytes Transferred (will likely be 0 if read/write tracepoints are removed)
        if 'bytes_transferred' in data:
            output.append(f'# HELP app_bytes_transferred Total bytes transferred during application calls.\n')
            output.append(f'# TYPE app_bytes_transferred counter\n')
            output.append(f'app_bytes_transferred{{source_app="{source_app}",dest_app="{dest_app}",call_type="{call_type}"}} {data["bytes_transferred"]}\n')

    return "".join(output)

# Simple HTTP server to expose metrics
from http.server import BaseHTTPRequestHandler, HTTPServer
import threading

class PrometheusMetricsHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/metrics":
            self.send_response(200)
            self.send_header("Content-type", "text/plain")
            self.end_headers()
            self.wfile.write(get_metrics_prometheus_format().encode("utf-8"))
        else:
            self.send_response(404)
            self.end_headers()

def start_metrics_server(port):
    server_address = ('', port)
    httpd = HTTPServer(server_address, PrometheusMetricsHandler)
    print(f"eBPF Exporter: Serving metrics on port {port}")
    httpd.serve_forever()


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
    data_len_str = "" # Always 0 now

    source_app = comm # Default source for client processes
    dest_app = "unknown" # Default dest

    if event.type == 0:
        event_type_str = "ACCEPT"
        if event.dport == 3306:
            dest_app = "mysql"
            call_type = "java-to-mysql"
        else:
            dest_app = "java_app_listener"
            call_type = "java-to-java"

        # 这里传入的 key 依然是字典
        key = {'source_app': 'client_app', 'dest_app': dest_app, 'call_type': call_type}
        update_metrics(key, 'call_count')

    elif event.type == 1:
        event_type_str = "CONNECT"
        if event.dport == 3306:
            dest_app = "mysql"
            call_type = "java-to-mysql"
        else:
            dest_app = "java_app_target"
            call_type = "java-to-java"

        # 这里传入的 key 依然是字典
        key = {'source_app': comm, 'dest_app': dest_app, 'call_type': call_type}
        update_metrics(key, 'call_count')

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

# Start the Prometheus metrics server in a separate thread
metrics_port = 8000
metrics_thread = threading.Thread(target=start_metrics_server, args=(metrics_port,))
metrics_thread.daemon = True # Allow main program to exit even if thread is running
metrics_thread.start()

# Read events from the perf buffer
try:
    b["events"].open_perf_buffer(print_event)
    while True:
        b.perf_buffer_poll()
except KeyboardInterrupt:
    print("\nStopping eBPF TCP Monitor.")
except Exception as e:
    print(f"An error occurred: {e}")