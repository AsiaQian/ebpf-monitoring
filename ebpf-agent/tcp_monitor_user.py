from bcc import BPF
import ctypes as ct
import socket
import struct
import time
import json
import requests
from prometheus_client import Counter, start_http_server
import threading
from kubernetes import client, config
import os

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
# 移除了 'call_type'，增加了 'source_comm' 和 'dest_comm'
APP_CALL_COUNT = Counter('app_call_count', 'Total number of application calls.',
                         ['source_workload', 'dest_workload', 'source_ip', 'dest_ip', 'dest_port',
                          'source_comm', 'dest_comm']) # 新增 comm 标签

# --- Kubernetes Workload Mapping ---
PID_TO_WORKLOAD_MAP = {}
IP_PORT_TO_WORKLOAD_MAP = {}
kube_v1 = None

def get_kubernetes_workload_info():
    """
    Queries Kubernetes API to build PID_TO_WORKLOAD_MAP and IP_PORT_TO_WORKLOAD_MAP.
    This function should be run periodically or at startup.
    """
    global PID_TO_WORKLOAD_MAP, IP_PORT_TO_WORKLOAD_MAP, kube_v1
    print("Fetching Kubernetes workload info...")
    try:
        config.load_kube_config()
        kube_v1 = client.CoreV1Api()
    except Exception as e:
        print(f"Error loading Kubernetes config or client: {e}")
        print("Please ensure KUBECONFIG is set or you are running in a K8s cluster.")
        return

    new_pid_map = {}
    new_ip_port_map = {}

    try:
        # 1. Map Service IPs/Ports to Workload Names
        services = kube_v1.list_service_for_all_namespaces()
        for svc in services.items:
            if svc.spec.cluster_ip and svc.spec.cluster_ip != "None":
                for port in svc.spec.ports:
                    svc_key = f"{svc.spec.cluster_ip}:{port.port}"
                    new_ip_port_map[svc_key] = svc.metadata.name
                    # print(f"Mapped Service {svc.metadata.name} to {svc_key}")
            if svc.spec.type == "NodePort" and svc.spec.cluster_ip:
                for port in svc.spec.ports:
                    minikube_ip = os.popen("minikube ip").read().strip()
                    if minikube_ip:
                        node_port_key = f"{minikube_ip}:{port.node_port}"
                        new_ip_port_map[node_port_key] = svc.metadata.name
                        # print(f"Mapped NodePort Service {svc.metadata.name} to {node_port_key}")

        # 2. Map Pod IPs to Workload Names
        pods = kube_v1.list_pod_for_all_namespaces()
        for pod in pods.items:
            if pod.status.phase == "Running" and pod.status.pod_ip:
                new_ip_port_map[f"{pod.status.pod_ip}"] = pod.metadata.name
                # print(f"Mapped Pod {pod.metadata.name} to {pod.status.pod_ip}")

    except client.ApiException as e:
        print(f"Error querying Kubernetes API: {e}")
    except Exception as e:
        print(f"Unexpected error in Kubernetes info fetching: {e}")

    PID_TO_WORKLOAD_MAP = new_pid_map
    IP_PORT_TO_WORKLOAD_MAP = new_ip_port_map
    print("Kubernetes workload info updated.")


def print_event(cpu, data, size):
    event = ct.cast(data, ct.POINTER(Event)).contents

    # Raw command name from eBPF event
    current_comm = event.comm.decode('utf-8', 'ignore')
    timestamp_ms = event.timestamp_ns / 1_000_000

    saddr_str = ""
    daddr_str = ""
    if event.af == socket.AF_INET:
        saddr_str = socket.inet_ntop(socket.AF_INET, struct.pack("I", event.saddr_v4))
        daddr_str = socket.inet_ntop(socket.AF_INET, struct.pack("I", event.daddr_v4))
    elif event.af == socket.AF_INET6:
        saddr_str = socket.inet_ntop(socket.AF_INET6, bytes(event.saddr_v6))
        daddr_str = socket.inet_ntop(socket.AF_INET6, bytes(event.daddr_v6))

    event_type_str = ""

    # --- Determine source and destination workload names and comms ---
    source_workload = "unknown"
    dest_workload = "unknown"
    source_comm = "unknown"
    dest_comm = "unknown"


    if event.type == 1: # CONNECT event (outbound connections initiated by `comm`)
        event_type_str = "CONNECT"

        # Source is the process initiating the connection
        source_workload = current_comm # Fallback to comm if no K8s mapping
        source_comm = current_comm

        # Determine destination workload
        dest_workload = IP_PORT_TO_WORKLOAD_MAP.get(f"{daddr_str}:{event.dport}", "unknown")
        if dest_workload == "unknown":
            dest_workload = IP_PORT_TO_WORKLOAD_MAP.get(daddr_str, "unknown")

        # For CONNECT, dest_comm is unknown from event itself, as we're initiating to a remote process
        # Can't directly get remote comm without further introspection (e.g., in-depth K8s knowledge or specific agent on dest)
        # So we leave dest_comm as "unknown" or infer based on workload/port if desired
        dest_comm = dest_workload # Best guess for dest_comm is its workload name or a generic "remote"

    elif event.type == 0: # ACCEPT event (inbound connections to `comm`)
        event_type_str = "ACCEPT"

        # Destination is the process accepting the connection
        dest_workload = current_comm # Fallback to comm if no K8s mapping
        dest_comm = current_comm

        # Source is the client initiating the connection.
        source_workload = IP_PORT_TO_WORKLOAD_MAP.get(f"{saddr_str}:{event.lport}", "unknown_client")
        if source_workload == "unknown_client":
            source_workload = IP_PORT_TO_WORKLOAD_MAP.get(saddr_str, "unknown_client")

        # For ACCEPT, source_comm is unknown from event itself (it's the remote client's comm)
        # Same as dest_comm for CONNECT, we'll use a placeholder or inferred name
        source_comm = source_workload # Best guess for source_comm is its workload name or a generic "remote"


    # Update Prometheus Counter with all labels
    APP_CALL_COUNT.labels(source_workload=source_workload,
                          dest_workload=dest_workload,
                          source_ip=saddr_str,
                          dest_ip=daddr_str,
                          dest_port=str(event.dport),
                          source_comm=source_comm, # 使用新的 source_comm 标签
                          dest_comm=dest_comm).inc() # 使用新的 dest_comm 标签

    print(f"{timestamp_ms:10.3f} {current_comm:16s} ({event.pid:6d}/{event.tgid:6d}) {event_type_str:7s} "
          f"{saddr_str}:{event.lport:<5d} -> {daddr_str}:{event.dport:<5d} "
          f"AF:{event.af} | SrcWL: {source_workload} ({source_comm}), DstWL: {dest_workload} ({dest_comm})")

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
print(f"{'Time':<10} {'Comm':<16} {'PID/TGID':<13} {'Event':<7} {'Source':<21} {'Dest':<21} {'AF':<4} | {'Workload Info':<50}")

# --- Start Prometheus HTTP server ---
metrics_port = 8000
try:
    start_http_server(metrics_port)
    print(f"eBPF Exporter: Serving metrics on port {metrics_port}")
except Exception as e:
    print(f"Error starting Prometheus HTTP server: {e}")
    exit(1)

# --- Start Kubernetes workload info fetching in a separate thread ---
kubernetes_info_thread = threading.Thread(target=get_kubernetes_workload_info)
kubernetes_info_thread.daemon = True
kubernetes_info_thread.start()

# Read events from the perf buffer
try:
    b["events"].open_perf_buffer(print_event)
    while True:
        b.perf_buffer_poll()
except KeyboardInterrupt:
    print("\nStopping eBPF TCP Monitor.")
except Exception as e:
    print(f"An error occurred: {e}")