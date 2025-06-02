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
        ("data_len", ct.c_ulonglong),
    ]

# Prometheus Pushgateway URL (if used)
PROMETHEUS_PUSHGATEWAY_URL = "http://localhost:9091" # To be replaced with K8s service

# In-memory store for metrics (for a simple HTTP exporter)
metrics_store = {}

def update_metrics(key, metric_type, value=1):
    """Updates a metric in the in-memory store."""
    if key not in metrics_store:
        metrics_store[key] = {}
    if metric_type not in metrics_store[key]:
        metrics_store[key][metric_type] = 0
    metrics_store[key][metric_type] += value

def get_metrics_prometheus_format():
    """Generates Prometheus exposition format from metrics_store."""
    output = []
    for key, data in metrics_store.items():
        source_app = key.get('source_app', 'unknown')
        dest_app = key.get('dest_app', 'unknown')
        call_type = key.get('call_type', 'unknown') # 'java-to-java', 'java-to-mysql'

        # Connection/Call Count
        if 'call_count' in data:
            output.append(f'# HELP app_call_count Total number of application calls.\n')
            output.append(f'# TYPE app_call_count counter\n')
            output.append(f'app_call_count{{source_app="{source_app}",dest_app="{dest_app}",call_type="{call_type}"}} {data["call_count"]}\n')

        # Bytes Transferred
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
    source_app = comm # Default source
    dest_app = "unknown" # Default dest

    if event.type == 0:
        event_type_str = "ACCEPT"
        # For ACCEPT, the process (comm) is the server
        # daddr and dport are the client's address and port
        # saddr and lport are the server's address and listening port
        # We assume the destination is the server that accepted the connection.
        # Need to map ports/IPs to service names later.
        # For simplicity, if dest port is MySQL (3306), it's java-to-mysql, otherwise java-to-java.
        # This is a simplification; a more robust solution would involve service discovery/mapping.
        if event.dport == 3306:
            dest_app = "mysql"
            call_type = "java-to-mysql"
        else:
            dest_app = "java_app_listener" # This needs to be resolved to actual service name
            call_type = "java-to-java"

        key = {'source_app': 'client_app', 'dest_app': dest_app, 'call_type': call_type} # Client app needs to be identified via connect
        update_metrics(key, 'call_count')

    elif event.type == 1:
        event_type_str = "CONNECT"
        # For CONNECT, the process (comm) is the client
        # saddr and lport are the client's address and port
        # daddr and dport are the server's address and port
        if event.dport == 3306:
            dest_app = "mysql"
            call_type = "java-to-mysql"
        else:
            dest_app = "java_app_target" # This needs to be resolved
            call_type = "java-to-java"

        key = {'source_app': comm, 'dest_app': dest_app, 'call_type': call_type}
        update_metrics(key, 'call_count')

    elif event.type == 2:
        event_type_str = "READ"
        # Here, `comm` is the process that performed the read
        key = {'source_app': comm, 'dest_app': 'unknown', 'call_type': 'read_bytes'}
        update_metrics(key, 'bytes_transferred', event.data_len)
    elif event.type == 3:
        event_type_str = "WRITE"
        # Here, `comm` is the process that performed the write
        key = {'source_app': comm, 'dest_app': 'unknown', 'call_type': 'write_bytes'}
        update_metrics(key, 'bytes_transferred', event.data_len)


    print(f"{timestamp_ms:10.3f} {comm:16s} ({event.pid:6d}/{event.tgid:6d}) {event_type_str:7s} "
          f"{saddr}:{event.lport:<5d} -> {daddr}:{event.dport:<5d} "
          f"AF:{event.af} Data Len: {event.data_len}")

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

    # Attach to syscall tracepoints for read/write.
    # Note: These are general read/write, not specific to sockets.
    # More refined approach would be kprobes on tcp_recvmsg/tcp_sendmsg
    b.attach_tracepoint(tp="syscalls:sys_enter_read", fn_name="syscalls_sys_enter_read")
    b.attach_tracepoint(tp="syscalls:sys_enter_write", fn_name="syscalls_sys_enter_write")

except Exception as e:
    print(f"Error attaching BPF probes: {e}")
    exit(1)

print("eBPF TCP Monitor is running. Press Ctrl+C to stop.")
print(f"{'Time':<10} {'Comm':<16} {'PID/TGID':<13} {'Event':<7} {'Source':<21} {'Dest':<21} {'AF':<4} {'Data Len':<10}")

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