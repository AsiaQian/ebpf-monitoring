import os
import socket
import struct
import re # 引入正则表达式模块
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
    ['source_workload', 'destination_workload', 'source_ip', 'destination_ip', 'destination_port', 'call_type', 'process_comm']
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
# 新增：PID到Pod/Workload的缓存
pid_to_workload_cache = LRUCache(maxsize=1000)

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
                pass # Suppress API errors for owner references, log if needed for debugging
        elif owner_ref.kind in ["StatefulSet", "DaemonSet"]:
            return owner_ref.name
        # Add other potential owners like Job if needed, though they usually own ReplicaSets/Pods
    return "unknown"

@cached(cache=ip_to_workload_cache)
def get_workload_name_by_ip(ip_address):
    """
    Looks up the workload name associated with a given IP address.
    Currently only checks Pod IPs directly.
    """
    if not v1 or not ip_address or ip_address in ["0.0.0.0", "::", "invalid", "127.0.0.1", "::1"]: # 避免无效IP和本地IP查询K8s
        return "unknown"
    try:
        pods = v1.list_pod_for_all_namespaces(field_selector=f"status.podIP={ip_address}")
        if pods.items:
            return _get_workload_name_from_pod_obj(pods.items[0])
        return "unknown"
    except client.ApiException as e:
        # print(f"Kubernetes API error for IP {ip_address}: {e}") # Uncomment for deeper K8s debugging
        return "unknown"
    except Exception as e:
        print(f"An unexpected error occurred during K8s IP lookup for {ip_address}: {e}")
        return "unknown"

@cached(cache=pid_to_workload_cache)
def get_pod_info_from_pid(pid):
    """
    Attempts to get Kubernetes Pod and Workload info from a process PID by reading cgroup.
    Returns (pod_name, workload_name, namespace) or (None, "unknown", None) if not found.
    This function should be run on the host where the process exists.
    """
    if not v1: # K8s client not initialized
        return (None, "unknown", None)

    try:
        cgroup_path = f"/proc/{pid}/cgroup"
        with open(cgroup_path, 'r') as f:
            cgroup_content = f.read()

        # Regex to find Kubernetes Pod UID in cgroup path
        # Common patterns:
        # /kubepods.slice/kubepods-besteffort.slice/kubepods-besteffort-pod<UID>.slice
        # /kubepods/burstable/pod<UID>/
        # /kubepods.slice/pod-<UID>.slice (cgroup v2 style)
        pod_uid = None
        # Pattern 1: UUID format (8-4-4-4-12 hex chars)
        match = re.search(r'/pod([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})/', cgroup_content)
        if match:
            pod_uid = match.group(1)
        else:
            # Pattern 2: 32 hex chars (older/different runtimes)
            match = re.search(r'pod([0-9a-f]{32})', cgroup_content)
            if match:
                pod_uid = match.group(1)
            else:
                # Pattern 3: cgroup v2 style '/pod-UID.slice'
                match = re.search(r'/pod-([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})\.slice', cgroup_content)
                if match:
                    pod_uid = match.group(1)

        if not pod_uid:
            return (None, "unknown", None)

        # List all pods and find by UID using field selector (most efficient)
        pods = v1.list_pod_for_all_namespaces(field_selector=f"metadata.uid={pod_uid}")

        if pods.items:
            pod_obj = pods.items[0]
            pod_name = pod_obj.metadata.name
            namespace = pod_obj.metadata.namespace
            workload_name = _get_workload_name_from_pod_obj(pod_obj)
            return (pod_name, workload_name, namespace)

        return (None, "unknown", None)

    except FileNotFoundError:
        # Process does not exist or cgroup info not accessible (e.g., non-containerized process)
        return (None, "unknown", None)
    except client.ApiException as e:
        # Kubernetes API error (e.g., permissions)
        print(f"Kubernetes API error during PID lookup for {pid}: {e}")
        return (None, "unknown", None)
    except Exception as e:
        # General error during cgroup parsing or other operations
        print(f"An unexpected error occurred during PID lookup for {pid}: {e}")
        return (None, "unknown", None)


def get_mysql_workload_name(destination_ip, destination_port):
    """Identifies MySQL based on default port."""
    if destination_port == 3306:
        # Consider a more sophisticated check if needed, e.g., if there are multiple MySQL instances
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
    lport = socket.ntohs(event.lport) # Convert from network byte order to host byte order
    dport = socket.ntohs(event.dport) # Convert from network byte order to host byte order

    saddr_str, daddr_str = "unknown", "unknown"
    try:
        if event.family == socket.AF_INET: # IPv4
            # 修正：使用 socket.htonl 将从 BPF 结构体中读取的 u32 (主机字节序) 转换为网络字节序，
            # 然后再打包成网络字节序的字节串。这样 socket.inet_ntop 就能正确解析。
            saddr_bytes = struct.pack("!I", socket.htonl(event.saddr_v4))
            daddr_bytes = struct.pack("!I", socket.htonl(event.daddr_v4))

            saddr_str = socket.inet_ntop(socket.AF_INET, saddr_bytes)
            daddr_str = socket.inet_ntop(socket.AF_INET, daddr_bytes)
        elif event.family == socket.AF_INET6: # IPv6
            # Reconstructed IPv6 address from two u64 parts (which are already network byte order from kernel)
            saddr_v6_combined = (event.saddr_v6_h << 64) | event.saddr_v6_l
            daddr_v6_combined = (event.daddr_v6_h << 64) | event.daddr_v6_l

            saddr_bytes = saddr_v6_combined.to_bytes(16, 'big')
            daddr_bytes = daddr_v6_combined.to_bytes(16, 'big')

            saddr_str = socket.inet_ntop(socket.AF_INET6, saddr_bytes)
            daddr_str = socket.inet_ntop(socket.AF_INET6, daddr_bytes)
        else:
            print(f"DEBUG: Unknown address family: {event.family}. Event type: {event.type}. Comm: {comm}. Skipping IP conversion.")
            saddr_str = "invalid" # Mark as invalid to prevent K8s lookup
            daddr_str = "invalid"
    except (socket.error, struct.error, AttributeError, ValueError) as e:
        print(f"Error converting IP address or accessing event IP fields: {e}. Raw event data: {data}. Skipping IP conversion.")
        saddr_str = "invalid"
        daddr_str = "invalid"

    # --- 工作负载解析逻辑 ---

    # 1. 优先通过 PID 查找源工作负载 (即使是 127.0.0.1 或 0.0.0.0 的情况也能解决)
    source_pod_name, source_workload, source_namespace = get_pod_info_from_pid(event.pid)

    # 2. 通过 IP 查找目的工作负载 (主要用于外部和跨 Pod IP 通信)
    destination_workload = get_workload_name_by_ip(daddr_str)

    # 3. 处理特殊 comm 的系统进程
    if "kube-apiserver" in comm:
        source_workload = "kube-apiserver"
        destination_workload = destination_workload if destination_workload != "unknown" else "external_or_system"
    elif "kubelet" in comm:
        source_workload = "kubelet"
        destination_workload = destination_workload if destination_workload != "unknown" else "external_or_system"
    elif "coredns" in comm:
        # CoreDNS 可能是 Pod，但如果 IP 是本地的，PID 查找会更准。这里作为补充。
        source_workload = "coredns-deployment" if source_workload == "unknown" else source_workload
        destination_workload = destination_workload if destination_workload != "unknown" else "external_or_system"
    elif "etcd" in comm:
        source_workload = "etcd"
        destination_workload = destination_workload if destination_workload != "unknown" else "external_or_system"


    # 4. 启发式判断：如果源和目的都是本地 IP，且源工作负载已知，则目的工作负载相同
    if saddr_str in ["127.0.0.1", "::1", "0.0.0.0", "::"] and \
            daddr_str in ["127.0.0.1", "::1", "0.0.0.0", "::"]:
        if source_workload != "unknown":
            destination_workload = source_workload # 它们是同一个 Pod 内部的通信

    # 5. 确保 source_workload 至少是 "unknown" 如果没有找到
    if source_workload is None: # get_pod_info_from_pid 返回 None 的情况
        source_workload = "unknown"


    # --- Call Type Determination (保持原有的 Java 相关逻辑) ---
    call_type = "other_to_other"
    is_java_process = "java" in comm.lower() or "openjdk" in comm.lower()

    if is_java_process:
        if dport == 3306:
            destination_workload = get_mysql_workload_name(daddr_str, dport) # 重新确认 MySQL
            call_type = "java_to_mysql"
        elif dport == 8081:
            call_type = "java_to_java_8081"
        elif destination_workload != "unknown":
            call_type = "java_to_workload"
        else: # 如果目的工作负载未知，但源是 Java，则可能是外部
            call_type = "java_to_external"
    elif dport == 3306:
        destination_workload = get_mysql_workload_name(daddr_str, dport) # 重新确认 MySQL
        call_type = "other_to_mysql"
    elif source_workload != "unknown" and destination_workload != "unknown":
        call_type = "workload_to_workload"
    elif source_workload != "unknown" and destination_workload == "unknown":
        call_type = "workload_to_external"
    elif source_workload == "unknown" and destination_workload != "unknown":
        call_type = "external_to_workload" # 适用于被动接受连接的情况 (accept)
    # else, default to "other_to_other" if both are unknown

    # Debugging output to see more details
    print(f"DEBUG_EVENT: pid={event.pid}, tgid={event.tgid}, comm='{comm}', type={event.type}, family={event.family}, "
          f"lport={lport}, dport={dport}, saddr_str='{saddr_str}', daddr_str='{daddr_str}'")
    print(f"FINAL_METRIC: source={source_workload} destWorkload={destination_workload} destIP={daddr_str} "
          f"destPort={dport} callType={call_type} comm={comm}")

    network_calls_total.labels(
        source_workload=source_workload,
        destination_workload=destination_workload,
        source_ip=saddr_str,
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