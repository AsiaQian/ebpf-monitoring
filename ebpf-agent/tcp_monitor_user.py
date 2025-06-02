import os
import socket
import struct
from bcc import BPF
from prometheus_client import start_http_server, Counter
from kubernetes import client, config
from cachetools import LRUCache, cached
import time

# --- Configuration ---
PROMETHEUS_PORT = 8000
EBPF_C_CODE_PATH = "tcp_monitor_kern.c"

# --- Prometheus Metrics ---
network_calls_total = Counter(
    'k8s_network_calls_total',
    'Total number of network calls between Kubernetes workloads and to MySQL.',
    ['source_workload', 'destination_workload', 'destination_ip', 'destination_port', 'call_type', 'process_comm']
)

# --- Kubernetes Client Initialization ---
v1 = None
app_v1 = None
try:
    if os.getenv("KUBERNETES_IN_CLUSTER", "true").lower() == "true":
        config.load_incluster_config()
    else:
        config.load_kube_config()
    v1 = client.CoreV1Api()
    app_v1 = client.AppsV1Api()
    print("Kubernetes client initialized successfully.")
except Exception as e:
    print(f"Warning: Could not initialize Kubernetes client ({e}). Workload names will default to 'unknown'.")

# --- Caches for performance ---
ip_to_workload_cache = LRUCache(maxsize=5000)

# --- Helper Functions for Kubernetes Lookup ---

def _get_workload_name_from_pod_obj(pod):
    """Internal helper to get workload name from a Pod object's owner references."""
    if not pod or not pod.metadata or not pod.metadata.owner_references:
        return "unknown"

    for owner_ref in pod.metadata.owner_references:
        if owner_ref.kind == "ReplicaSet":
            try:
                if app_v1:
                    rs = app_v1.read_namespaced_replica_set(name=owner_ref.name, namespace=pod.metadata.namespace)
                    if rs and rs.metadata and rs.metadata.owner_references:
                        for rs_owner_ref in rs.metadata.owner_references:
                            if rs_owner_ref.kind == "Deployment":
                                return rs_owner_ref.name
            except client.ApiException:
                pass
        elif owner_ref.kind in ["StatefulSet", "DaemonSet"]:
            return owner_ref.name
    return "unknown"

@cached(cache=ip_to_workload_cache)
def get_workload_name_by_ip(ip_address):
    """
    Looks up the workload name associated with a given IP address.
    Currently only checks Pod IPs directly.
    """
    if not v1 or not ip_address:
        return "unknown"
    try:
        pods = v1.list_pod_for_all_namespaces(field_selector=f"status.podIP={ip_address}")
        if pods.items:
            return _get_workload_name_from_pod_obj(pods.items[0])
        return "unknown"
    except client.ApiException as e:
        # print(f"Kubernetes API error for IP {ip_address}: {e}") # Uncomment for deeper K8s debugging
        return "unknown"

def get_mysql_workload_name(destination_ip, destination_port):
    """Identifies MySQL based on default port."""
    if destination_port == 3306:
        return "mysql_server"
    return "unknown"

# --- Event Handling Function ---
def print_event(cpu, data, size):
    try:
        event = b["events"].event(data)
    except Exception as e:
        print(f"Error parsing event data from perf buffer: {e}. Raw data size: {size}. Skipping event.")
        # Debugging: Print raw data if parsing fails to understand format issues
        # print(f"Raw data (hex): {data.hex()}")
        return

    comm = event.comm.decode('utf-8', 'ignore').strip('\x00') # Remove null bytes
    lport = socket.ntohs(event.lport)
    dport = socket.ntohs(event.dport)

    saddr_str, daddr_str = "unknown", "unknown"
    try:
        if event.family == socket.AF_INET: # IPv4
            saddr_str = socket.inet_ntop(socket.AF_INET, struct.pack("I", event.saddr_v4))
            daddr_str = socket.inet_ntop(socket.AF_INET, struct.pack("I", event.daddr_v4))
        elif event.family == socket.AF_INET6: # IPv6
            # Reconstructed IPv6 address from two u64 parts
            saddr_v6_combined = (event.saddr_v6_h << 64) | event.saddr_v6_l
            daddr_v6_combined = (event.daddr_v6_h << 64) | event.daddr_v6_l

            saddr_str = socket.inet_ntop(socket.AF_INET6, saddr_v6_combined.to_bytes(16, 'big'))
            daddr_str = socket.inet_ntop(socket.AF_INET6, daddr_v6_combined.to_bytes(16, 'big'))
        else:
            print(f"DEBUG: Unknown address family: {event.family}. Event type: {event.type}. Comm: {comm}. Skipping IP conversion.")
            saddr_str = "invalid" # Mark as invalid to prevent K8s lookup
            daddr_str = "invalid"
    except (socket.error, struct.error, AttributeError, ValueError) as e:
        print(f"Error converting IP address or accessing event IP fields: {e}. Raw event data: {data}. Skipping IP conversion.")
        saddr_str = "invalid"
        daddr_str = "invalid"

    # Resolve source and destination workload names using Kubernetes API.
    # Only try to resolve if IP is not 'invalid'
    source_workload = get_workload_name_by_ip(saddr_str) if saddr_str != "invalid" else "unknown"
    destination_workload = get_workload_name_by_ip(daddr_str) if daddr_str != "invalid" else "unknown"

    call_type = "other_to_other"

    # Check for Java applications and specific ports
    is_java_process = "java" in comm.lower() or "openjdk" in comm.lower() # More robust check for Java comm

    if is_java_process:
        if dport == 3306:
            destination_workload = get_mysql_workload_name(daddr_str, dport)
            call_type = "java_to_mysql"
        elif dport == 8081: # Explicitly check for 8081 as requested
            call_type = "java_to_java_8081"
        elif destination_workload != "unknown":
            call_type = "java_to_workload"
        else:
            call_type = "java_to_external"
    elif dport == 3306:
        destination_workload = get_mysql_workload_name(daddr_str, dport)
        call_type = "other_to_mysql"
    elif source_workload != "unknown" and destination_workload != "unknown":
        call_type = "workload_to_workload"
    elif source_workload != "unknown" and destination_workload == "unknown":
        call_type = "workload_to_external"

    # Debugging output to see more details
    print(f"DEBUG_EVENT: pid={event.pid}, tgid={event.tgid}, comm='{comm}', type={event.type}, family={event.family}, "
          f"lport={lport}, dport={dport}, saddr_str='{saddr_str}', daddr_str='{daddr_str}'")
    print(f"FINAL_METRIC: source={source_workload} destWorkload={destination_workload} destIP={daddr_str} "
          f"destPort={dport} callType={call_type} comm={comm}")

    network_calls_total.labels(
        source_workload=source_workload,
        destination_workload=destination_workload,
        destination_ip=daddr_str,
        destination_port=dport,
        call_type=call_type,
        process_comm=comm # Add actual process command to labels for more insight
    ).inc()


# --- Main Execution ---
if __name__ == "__main__":
    print(f"Starting simplified eBPF network monitoring. Loading eBPF code from {EBPF_C_CODE_PATH}...")

    start_http_server(PROMETHEUS_PORT)
    print(f"Prometheus metrics exposed on port {PROMETHEUS_PORT}")

    try:
        with open(EBPF_C_CODE_PATH, 'r') as f:
            bpf_text = f.read()
    except FileNotFoundError:
        print(f"Error: eBPF C code file not found at {EBPF_C_CODE_PATH}. Please ensure it exists.")
        exit(1)
    except Exception as e:
        print(f"Error reading eBPF C code file: {e}")
        exit(1)

    try:
        # Keep debug for more verbose output, 0x1000 is for BPF_DEBUG_PREPROCESS
        # You can try 0xFFFF for max debug verbosity if needed
        b = BPF(text=bpf_text, debug=0x1000) # Remove debug=0x1000 after confirmed working
    except Exception as e:
        print(f"Failed to load BPF program: {e}")
        print("Please ensure BCC is installed, kernel headers are available, and the eBPF C code is valid.")
        exit(1)

    b["events"].open_perf_buffer(print_event)

    print("Monitoring network events... Press Ctrl+C to stop.")
    # Print BPF_DEBUG_PREPROCESS output (if debug flag is set)
    # print(b.dump_func("handle_connect"))
    # print(b.dump_func("kprobe__tcp_v4_connect"))
    # print(b.dump_func("kretprobe__inet_csk_accept"))

    while True:
        try:
            b.perf_buffer_poll()
            time.sleep(0.1)
        except KeyboardInterrupt:
            print("\nStopping monitoring.")
            break
        except Exception as e:
            print(f"Error polling perf buffer: {e}. Exiting.")
            break