#!/usr/bin/python3
from bcc import BPF
from prometheus_client import start_http_server, Counter
import time
import ctypes as ct
import socket
import struct
import os
import sys

# Prometheus metrics
connection_event_count = Counter(
    'ebpf_connection_event_total',
    'Total number of TCP connection acceptance events captured by eBPF.',
    ['source_comm', 'source_ip', 'dest_ip', 'dest_port', 'ip_version', 'server_listen_port'] # Added ip_version and server_listen_port
)

# Structs for BPF Map keys/values (must match C code -> accept_event_t)
class AcceptEvent(ct.Structure):
    _fields_ = [
        ("pid", ct.c_uint32),
        ("ip_version", ct.c_ubyte),  # u8 -> c_ubyte
        ("saddr", ct.c_ubyte * 16),
        ("daddr", ct.c_ubyte * 16),
        ("sport", ct.c_uint16),      # local port for server
        ("dport", ct.c_uint16),      # remote port for server (client's source port)
        ("comm", ct.c_char * 16),
    ]

def ip_to_str(ip_bytes_array, ip_version):
    """Converts a u8 array IP address to string format (IPv4 or IPv6)."""
    # ctypes.c_ubyte_Array needs to be converted to bytes for socket functions
    ip_bytes = bytes(bytearray(ip_bytes_array))
    if ip_version == 4:
        # For IPv4, ip_bytes contains the u32 in the first 4 bytes.
        # Ensure it's in network byte order for inet_ntoa
        return socket.inet_ntoa(ip_bytes[:4])
    elif ip_version == 6:
        # For IPv6, ip_bytes is already the 16-byte address in network byte order.
        return socket.inet_ntop(socket.AF_INET6, ip_bytes)
    else:
        return "UNKNOWN_IP"

# Callback function to process events from the perf buffer
def print_accept_event(cpu, data, size):
    event = ct.cast(data, ct.POINTER(AcceptEvent)).contents

    comm = event.comm.decode('utf-8').rstrip('\x00')
    source_ip = ip_to_str(event.saddr, event.ip_version) # Client's IP
    dest_ip = ip_to_str(event.daddr, event.ip_version) # Server's IP
    client_source_port = str(event.dport) # Client's ephemeral source port
    server_listen_port = str(event.sport) # Server's listening port

    labels = {
        'source_comm': comm,
        'source_ip': source_ip,
        # 'source_port': client_source_port, # Usually not needed as a label, can be high cardinality
        'dest_ip': dest_ip,
        'dest_port': server_listen_port, # This is the server's port being connected to
        'ip_version': str(event.ip_version),
        'server_listen_port': server_listen_port, # Redundant with dest_port, but explicit
    }

    # Increment the Prometheus counter for each received event
    connection_event_count.labels(**labels).inc()

    print(f"[{time.time():.2f}] PID: {event.pid}, COMM: {comm}, "
          f"IP_VER: {event.ip_version}, "
          f"CLIENT: {source_ip}:{client_source_port} -> "
          f"SERVER: {dest_ip}:{server_listen_port}")


def main():
    print("Starting eBPF Agent...")

    script_dir = os.path.dirname(__file__)
    c_code_path = os.path.join(script_dir, "tcp_monitor_kern.c")
    try:
        with open(c_code_path, "r") as f:
            bpf_c_code = f.read()
    except FileNotFoundError:
        print(f"Error: eBPF C code file not found at {c_code_path}")
        sys.exit(1)

    # Load BPF C code directly from the embedded string
    try:
        b = BPF(text=bpf_c_code)
    except Exception as e:
        print(f"Error loading BPF program: {e}")
        # Print detailed verifier errors for debugging
        if 'b' in locals(): # Check if b is defined before accessing it
            print(b.get_formatted_output())
        sys.exit(1)

    # Attach kretprobe to inet_csk_accept
    b.attach_kretprobe(event="inet_csk_accept", fn_name="kretprobe__inet_csk_accept")

    print("eBPF programs loaded and attached. Collecting metrics...")

    # Open the perf buffer for events
    b["events"].open_perf_buffer(print_accept_event)

    # Start Prometheus HTTP server on port 9090 (standard exporter port)
    print("Prometheus metrics server listening on :9090")
    start_http_server(8000)

    try:
        while True:
            # Poll the perf buffer for new events
            b.perf_buffer_poll()
            # Sleep for a short period to avoid busy-looping if no events
            time.sleep(0.1)

    except KeyboardInterrupt:
        print("Stopping eBPF Agent.")
    finally:
        if 'b' in locals() and b:
            print("eBPF probes detached (or will be on process exit).")

if __name__ == "__main__":
    main()