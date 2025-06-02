import os
import socket
import struct
import re
from bcc import BPF
from prometheus_client import start_http_server, Counter
from kubernetes import client, config
from cachetools import LRUCache, cached
import time
import threading

# --- Configuration ---
PROMETHEUS_PORT = 8000
EBPF_C_CODE_PATH = "tcp_monitor_kern.c"
K8S_CACHE_REFRESH_INTERVAL_SECONDS = 300 # Refresh K8s caches every 5 minutes

# --- Prometheus Metrics ---
network_calls_total = Counter(
    'k8s_network_calls_total',
    'Total number of network calls between Kubernetes workloads and to MySQL.',
    ['source_workload', 'destination_workload', 'source_ip', 'destination_ip', 'destination_port', 'call_type', 'process_comm', 'pid']
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
# IP -> WorkloadName (for external/known IPs)
ip_to_workload_cache = LRUCache(maxsize=5000)
# PID -> (pod_name, workload_name, namespace)
pid_to_workload_cache = LRUCache(maxsize=1000)
# NodePort -> TargetPort (from Service spec)
nodeport_to_targetport_cache = LRUCache(maxsize=100)
# PodIP -> (PodName, WorkloadName, {ContainerPort: ExposedPort}) - For direct Pod IP lookups and port mapping
pod_ip_to_pod_info_cache = LRUCache(maxsize=2000) # (pod_name, workload_name, {container_port: host_port/service_port})

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
    Checks Pod IPs directly.
    """
    # Exclude common loopback/unspecified/invalid IPs from direct K8s API lookup
    if not v1 or not ip_address or \
            ip_address in ["0.0.0.0", "::", "invalid", "127.0.0.1", "::1", "::100:7f:ffff:0"]:
        return "unknown"

    # Try fetching from pod_ip_to_pod_info_cache first
    if ip_address in pod_ip_to_pod_info_cache:
        pod_name, workload_name, _ = pod_ip_to_pod_info_cache[ip_address]
        return workload_name # return cached workload name

    try:
        pods = v1.list_pod_for_all_namespaces(field_selector=f"status.podIP={ip_address}")
        if pods.items:
            # Update pod_ip_to_pod_info_cache if found
            pod_obj = pods.items[0]
            pod_name = pod_obj.metadata.name
            workload_name = _get_workload_name_from_pod_obj(pod_obj)

            # Extract port mappings from Pod spec if available (e.g. for containerPorts)
            # This is a basic example; more complex logic might be needed for named ports or service ports
            port_mappings = {}
            if pod_obj.spec and pod_obj.spec.containers:
                for container in pod_obj.spec.containers:
                    if container.ports:
                        for p in container.ports:
                            if p.container_port:
                                port_mappings[p.container_port] = p.host_port if p.host_port else p.container_port # Assuming target port is container port

            pod_ip_to_pod_info_cache[ip_address] = (pod_name, workload_name, port_mappings)
            return workload_name
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
    print(f"find pid={pid}")
    if not v1: # K8s client not initialized
        print("K8s client not init")
        return (None, "unknown", None)

    try:
        # print("pid 1") # Debug print, can be removed
        cgroup_path = f"/proc/{pid}/cgroup"
        with open(cgroup_path, 'r') as f:
            cgroup_content = f.read()
        # print("pid 2") # Debug print, can be removed

        pod_uid = None
        # Pattern 1: UUID format (8-4-4-4-12 hex chars)
        match = re.search(r'/pod([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})/', cgroup_content)
        if match:
            # print("pid 3") # Debug print, can be removed
            pod_uid = match.group(1)
        else:
            # print("pid 4") # Debug print, can be removed
            # Pattern 2: 32 hex chars (older/different runtimes)
            match = re.search(r'pod([0-9a-f]{32})', cgroup_content)
            if match:
                pod_uid = match.group(1)
            else:
                # Pattern 3: cgroup v2 style '/pod-UID.slice'
                match = re.search(r'/pod-([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})\.slice', cgroup_content)
                if match:
                    pod_uid = match.group(1)

        print(f"cgroup_path={cgroup_path} content={cgroup_content} pod_uid={pod_uid}") # Debug print, can be removed

        if not pod_uid:
            return (None, "unknown", None)

        # --- MODIFIED PART START ---
        # Instead of field_selector, get all pods and filter in Python
        # Consider getting only necessary fields to reduce payload size if performance is critical
        # e.g., list_pod_for_all_namespaces(_preload_content=False) then parse manually,
        # but for simplicity, let's get full objects for now.
        all_pods = v1.list_pod_for_all_namespaces() # Get all pods
        target_pod_obj = None

        for pod_item in all_pods.items:
            if pod_item.metadata and pod_item.metadata.uid == pod_uid:
                target_pod_obj = pod_item
                print(f"Found pod, pod_item={pod_item.metadata.name}")
                break # Found the pod, no need to continue iterating

        if target_pod_obj:
            pod_obj = target_pod_obj
            pod_name = pod_obj.metadata.name
            namespace = pod_obj.metadata.namespace
            workload_name = _get_workload_name_from_pod_obj(pod_obj)

            # Also update pod_ip_to_pod_info_cache if this pod has an IP
            if pod_obj.status and pod_obj.status.pod_ip:
                port_mappings = {}
                if pod_obj.spec and pod_obj.spec.containers:
                    for container in pod_obj.spec.containers:
                        if container.ports:
                            for p in container.ports: # Corrected from p.games to p.ports if using default container ports
                                if p.container_port:
                                    port_mappings[p.container_port] = p.host_port if p.host_port else p.container_port

                pod_ip_to_pod_info_cache[pod_obj.status.pod_ip] = (pod_name, workload_name, port_mappings)
                print(f"found pod pid={pid} podName={pod_name} port_mappings={port_mappings}")

            return (pod_name, workload_name, namespace)
        # --- MODIFIED PART END ---

        return (None, "unknown", None) # If pod_uid was found but no matching pod_obj in list

    except FileNotFoundError as e :
        print(f"FileNotFoundError lookup for {pid}: {e}")
        pass # This means the process no longer exists on the host
    except client.ApiException as e:
        print(f"Kubernetes API error during PID lookup for {pid}: {e}")
    except Exception as e:
        print(f"An unexpected error occurred during PID lookup for {pid}: {e}")

    return (None, "unknown", None)

def refresh_k8s_caches():
    """
    Refreshes all Kubernetes-related caches: NodePort mappings and Pod IP info.
    This should be run periodically in a separate thread.
    """
    global nodeport_to_targetport_cache
    global pod_ip_to_pod_info_cache

    if not v1 or not app_v1:
        print("Kubernetes client not initialized, skipping cache refresh.")
        return

    print(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] Refreshing Kubernetes caches...")

    temp_nodeport_cache = {}
    temp_pod_info_cache = {}

    try:
        # Refresh Service NodePort mappings
        services = v1.list_service_for_all_namespaces()
        for svc in services.items:
            if svc.spec and svc.spec.ports:
                for port in svc.spec.ports:
                    if port.node_port:
                        # Store NodePort -> TargetPort
                        # Note: port.target_port can be a string (named port) or int
                        temp_nodeport_cache[port.node_port] = port.target_port
                        print(f"nodeport > targetport: {port.node_port} {port.target_port}")

        # Refresh Pod IP to Pod/Workload/Port info mappings
        # This will also populate ip_to_workload_cache via get_workload_name_by_ip calls
        pods = v1.list_pod_for_all_namespaces()
        for pod_obj in pods.items:
            if pod_obj.status and pod_obj.status.pod_ip:
                pod_ip = pod_obj.status.pod_ip
                pod_name = pod_obj.metadata.name
                workload_name = _get_workload_name_from_pod_obj(pod_obj)

                port_mappings = {}
                if pod_obj.spec and pod_obj.spec.containers:
                    for container in pod_obj.spec.containers:
                        if container.ports:
                            for p in container.ports:
                                if p.container_port:
                                    # This maps container's exposed port (e.g. 8080)
                                    port_mappings[p.container_port] = p.host_port if p.host_port else p.container_port # host_port usually for hostNetwork pods

                temp_pod_info_cache[pod_ip] = (pod_name, workload_name, port_mappings)
                # Also update the IP to workload cache for direct IP lookups
                ip_to_workload_cache[pod_ip] = workload_name

    except client.ApiException as e:
        print(f"Kubernetes API error during cache refresh: {e}")
    except Exception as e:
        print(f"An unexpected error occurred during K8s cache refresh: {e}")

    nodeport_to_targetport_cache = LRUCache(maxsize=100) # Reset cache
    nodeport_to_targetport_cache.update(temp_nodeport_cache)

    pod_ip_to_pod_info_cache = LRUCache(maxsize=2000) # Reset cache
    pod_ip_to_pod_info_cache.update(temp_pod_info_cache)

    print(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] Kubernetes caches refreshed successfully.")

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
    lport = socket.ntohs(event.lport) # Convert from network byte order to host byte order
    dport = socket.ntohs(event.dport) # Convert from network byte order to host byte order

    saddr_str, daddr_str = "unknown", "unknown"
    try:
        if event.family == socket.AF_INET: # IPv4
            # Correct: Convert host byte order u32 (from BPF) to network byte order bytes
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
        print(f"Error converting IP address or accessing event IP fields: {e}. Skipping IP conversion.")
        saddr_str = "invalid"
        daddr_str = "invalid"

    # --- Workload Resolution Logic ---

    # 1. Resolve source workload from PID (most reliable for the originating process)
    print("call get_pod_info_from_pid")
    source_pod_name, source_workload, source_namespace = get_pod_info_from_pid(event.pid)
    print(f"call get_pod_info_from_pid after: pid={event.pid} pod_name={source_pod_name}")

    # get_pod_info_from_pid(4405)
    if source_workload is None: # get_pod_info_from_pid might return None for workload_name if no pod found
        source_workload = "unknown"

    # 2. Initialize destination workload (will be refined)
    destination_workload = "unknown"
    adjusted_dport = dport # Default to raw dport from event

    # Define common loopback/unspecified IPs for easier checking
    loopback_ips = ["127.0.0.1", "::1", "0.0.0.0", "::", "::100:7f:ffff:0"]

    # 3. Handle 'accept' events with loopback destination IP (common for NodePort/internal traffic)
    if event.type == 0: # This is an 'accept' event
        if daddr_str in loopback_ips:
            # If destination IP is loopback and source workload is known (meaning this is *our* process accepting)
            if source_workload != "unknown":
                destination_workload = source_workload # It's internal communication within the same Pod

            # Now, attempt to correct the destination port based on known Java app behavior or K8s Service mapping
            # This is crucial for NodePort scenarios where the recorded dport is the NodePort
            if comm.lower().startswith("http-nio-"): # Assuming Java app, it listens on 8080
                # Try to find mapping from our NodePort cache
                target_port_from_cache = nodeport_to_targetport_cache.get(dport)
                print(f"found http-nio- target port: {target_port_from_cache}")
                if target_port_from_cache:
                    adjusted_dport = target_port_from_cache
                    print(f"DEBUG: NodePort {dport} for {comm} mapped to targetPort {adjusted_dport} via Service cache.")
                elif dport != 8080: # If it's a Java http-nio process, and not already 8080, assume 8080
                    # This is a strong heuristic for common Java web servers
                    print(f"DEBUG: Assuming {comm} on loopback IP means actual port is 8080, not {dport}.")
                    adjusted_dport = 8080
            # You can add more heuristics here for other well-known application ports (e.g., Nginx, Redis)

    # 4. For non-loopback destination IPs, try to resolve via IP lookup
    if daddr_str not in loopback_ips and daddr_str != "invalid":
        destination_workload = get_workload_name_by_ip(daddr_str)
        # Check if the dport is a NodePort that maps to a container port for this resolved destination_workload
        if destination_workload != "unknown" and dport in nodeport_to_targetport_cache:
            target_port_from_cache = nodeport_to_targetport_cache.get(dport)
            if target_port_from_cache:
                adjusted_dport = target_port_from_cache
                print(f"DEBUG: Destination IP {daddr_str} (workload {destination_workload}) and NodePort {dport} mapped to targetPort {adjusted_dport}.")


    # 5. Handle special 'comm' for system processes (fallback/override)
    if "kube-apiserver" in comm:
        source_workload = "kube-apiserver"
        destination_workload = destination_workload if destination_workload != "unknown" else "external_or_system"
    elif "kubelet" in comm:
        source_workload = "kubelet"
        destination_workload = destination_workload if destination_workload != "unknown" else "external_or_system"
    elif "coredns" in comm:
        source_workload = "coredns-deployment" if source_workload == "unknown" else source_workload
        destination_workload = destination_workload if destination_workload != "unknown" else "external_or_system"
    elif "etcd" in comm:
        source_workload = "etcd"
        destination_workload = destination_workload if destination_workload != "unknown" else "external_or_system"


    # --- Call Type Determination ---
    call_type = "other_to_other"
    is_java_process = "java" in comm.lower() or "openjdk" in comm.lower() or comm.lower().startswith("http-nio-")

    if is_java_process:
        if adjusted_dport == 3306:
            destination_workload = get_mysql_workload_name(daddr_str, adjusted_dport) # Re-confirm MySQL
            call_type = "java_to_mysql"
        elif adjusted_dport == 8081: # Example specific port
            call_type = "java_to_java_8081"
        elif destination_workload != "unknown":
            call_type = "java_to_workload"
        else:
            call_type = "java_to_external"
    elif adjusted_dport == 3306:
        destination_workload = get_mysql_workload_name(daddr_str, adjusted_dport) # Re-confirm MySQL
        call_type = "other_to_mysql"
    elif source_workload != "unknown" and destination_workload != "unknown":
        call_type = "workload_to_workload"
    elif source_workload != "unknown" and destination_workload == "unknown":
        call_type = "workload_to_external"
    elif source_workload == "unknown" and destination_workload != "unknown":
        call_type = "external_to_workload"
    # else, default to "other_to_other" if both are unknown

    # Debugging output
    print(f"DEBUG_EVENT: pid={event.pid}, tgid={event.tgid}, comm='{comm}', type={event.type}, family={event.family}, "
          f"lport={lport}, dport={dport} (raw), adjusted_dport={adjusted_dport}, saddr_str='{saddr_str}', daddr_str='{daddr_str}'")
    print(f"FINAL_METRIC: source={source_workload} destWorkload={destination_workload} destIP={daddr_str} "
          f"destPort={adjusted_dport} callType={call_type} process_comm={comm}")

    network_calls_total.labels(
        source_workload=source_workload,
        destination_workload=destination_workload,
        source_ip=saddr_str,
        pid=event.pid,
        destination_ip=daddr_str, # Use raw daddr_str as it represents the observed IP
        destination_port=adjusted_dport, # Use adjusted port for correct mapping
        call_type=call_type,
        process_comm=comm
    ).inc()

# --- Cache Refresh Thread ---
def k8s_cache_refresher():
    while True:
        refresh_k8s_caches()
        time.sleep(K8S_CACHE_REFRESH_INTERVAL_SECONDS)


# --- Main Execution ---
if __name__ == "__main__":
    print(f"Starting eBPF network monitoring. Loading eBPF code from {EBPF_C_CODE_PATH}...")

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
        b = BPF(text=bpf_text, debug=0x1000) # Remove debug=0x1000 after confirmed working
    except Exception as e:
        print(f"Failed to load BPF program: {e}")
        print("Please ensure BCC is installed, kernel headers are available, and the eBPF C code is valid.")
        exit(1)

    # Start K8s cache refreshing in a separate thread
    cache_thread = threading.Thread(target=k8s_cache_refresher, daemon=True)
    cache_thread.start()

    b["events"].open_perf_buffer(print_event)

    print("Monitoring network events... Press Ctrl+C to stop.")

    while True:
        try:
            b.perf_buffer_poll()
            time.sleep(0.1) # Small sleep to prevent busy-looping
        except KeyboardInterrupt:
            print("\nStopping monitoring.")
            break
        except Exception as e:
            print(f"Error polling perf buffer: {e}. Exiting.")
            break