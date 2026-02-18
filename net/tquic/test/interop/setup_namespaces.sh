#!/bin/bash
# SPDX-License-Identifier: GPL-2.0-only
#
# Network Namespace Setup for TQUIC Interoperability Testing
#
# Creates isolated network namespaces with configurable topology
# for testing QUIC connections, including multipath scenarios.

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Namespace names
CLIENT_NS="tquic_client"
SERVER_NS="tquic_server"

# Primary path (veth0/veth1)
PRIMARY_CLIENT_IP="10.0.1.1"
PRIMARY_SERVER_IP="10.0.1.2"
PRIMARY_SUBNET="10.0.1.0/24"

# Secondary path for multipath (veth2/veth3)
SECONDARY_CLIENT_IP="10.0.2.1"
SECONDARY_SERVER_IP="10.0.2.2"
SECONDARY_SUBNET="10.0.2.0/24"

# Tertiary path for advanced multipath testing (veth4/veth5)
TERTIARY_CLIENT_IP="10.0.3.1"
TERTIARY_SERVER_IP="10.0.3.2"
TERTIARY_SUBNET="10.0.3.0/24"

# MTU settings
MTU_SIZE=1500

log_info() {
    echo "[INFO] $*"
}

log_error() {
    echo "[ERROR] $*" >&2
}

#------------------------------------------------------------------------------
# Namespace Management
#------------------------------------------------------------------------------

create_namespace() {
    local ns_name="$1"

    if ip netns list | grep -q "^${ns_name}"; then
        log_info "Namespace ${ns_name} already exists, removing..."
        delete_namespace "${ns_name}"
    fi

    log_info "Creating namespace: ${ns_name}"
    ip netns add "${ns_name}"

    # Enable loopback
    ip netns exec "${ns_name}" ip link set lo up
}

delete_namespace() {
    local ns_name="$1"

    if ip netns list | grep -q "^${ns_name}"; then
        log_info "Deleting namespace: ${ns_name}"
        ip netns delete "${ns_name}"
    fi
}

#------------------------------------------------------------------------------
# Veth Pair Creation
#------------------------------------------------------------------------------

create_veth_pair() {
    local veth_client="$1"
    local veth_server="$2"
    local client_ip="$3"
    local server_ip="$4"
    local subnet_prefix="$5"

    log_info "Creating veth pair: ${veth_client} <-> ${veth_server}"

    # Create veth pair
    ip link add "${veth_client}" type veth peer name "${veth_server}"

    # Move to namespaces
    ip link set "${veth_client}" netns "${CLIENT_NS}"
    ip link set "${veth_server}" netns "${SERVER_NS}"

    # Configure client side
    ip netns exec "${CLIENT_NS}" ip addr add "${client_ip}/${subnet_prefix}" dev "${veth_client}"
    ip netns exec "${CLIENT_NS}" ip link set "${veth_client}" mtu "${MTU_SIZE}"
    ip netns exec "${CLIENT_NS}" ip link set "${veth_client}" up

    # Configure server side
    ip netns exec "${SERVER_NS}" ip addr add "${server_ip}/${subnet_prefix}" dev "${veth_server}"
    ip netns exec "${SERVER_NS}" ip link set "${veth_server}" mtu "${MTU_SIZE}"
    ip netns exec "${SERVER_NS}" ip link set "${veth_server}" up
}

#------------------------------------------------------------------------------
# Routing Configuration
#------------------------------------------------------------------------------

setup_routing() {
    log_info "Configuring routing tables..."

    # Client routing - default via primary path
    ip netns exec "${CLIENT_NS}" ip route add default via "${PRIMARY_SERVER_IP}" dev veth0 metric 100 2>/dev/null || true

    # Server routing - default via primary path
    ip netns exec "${SERVER_NS}" ip route add default via "${PRIMARY_CLIENT_IP}" dev veth1 metric 100 2>/dev/null || true

    # Enable IP forwarding in namespaces
    ip netns exec "${CLIENT_NS}" sysctl -w net.ipv4.ip_forward=1 >/dev/null
    ip netns exec "${SERVER_NS}" sysctl -w net.ipv4.ip_forward=1 >/dev/null

    # Configure for QUIC
    ip netns exec "${CLIENT_NS}" sysctl -w net.ipv4.udp_rmem_min=8192 >/dev/null
    ip netns exec "${CLIENT_NS}" sysctl -w net.ipv4.udp_wmem_min=8192 >/dev/null
    ip netns exec "${SERVER_NS}" sysctl -w net.ipv4.udp_rmem_min=8192 >/dev/null
    ip netns exec "${SERVER_NS}" sysctl -w net.ipv4.udp_wmem_min=8192 >/dev/null

    # Increase UDP buffer sizes
    ip netns exec "${CLIENT_NS}" sysctl -w net.core.rmem_max=26214400 >/dev/null
    ip netns exec "${CLIENT_NS}" sysctl -w net.core.wmem_max=26214400 >/dev/null
    ip netns exec "${SERVER_NS}" sysctl -w net.core.rmem_max=26214400 >/dev/null
    ip netns exec "${SERVER_NS}" sysctl -w net.core.wmem_max=26214400 >/dev/null
}

#------------------------------------------------------------------------------
# Multipath Routing Configuration
#------------------------------------------------------------------------------

setup_multipath_routing() {
    log_info "Configuring multipath routing..."

    # Add secondary routes
    ip netns exec "${CLIENT_NS}" ip route add "${SECONDARY_SUBNET}" dev veth2 metric 200 2>/dev/null || true
    ip netns exec "${SERVER_NS}" ip route add "${SECONDARY_SUBNET}" dev veth3 metric 200 2>/dev/null || true

    # Configure routing tables for multipath
    # Table 100 - primary path
    ip netns exec "${CLIENT_NS}" ip route add "${PRIMARY_SUBNET}" dev veth0 table 100 2>/dev/null || true
    ip netns exec "${CLIENT_NS}" ip rule add from "${PRIMARY_CLIENT_IP}" table 100 2>/dev/null || true

    # Table 200 - secondary path
    ip netns exec "${CLIENT_NS}" ip route add "${SECONDARY_SUBNET}" dev veth2 table 200 2>/dev/null || true
    ip netns exec "${CLIENT_NS}" ip rule add from "${SECONDARY_CLIENT_IP}" table 200 2>/dev/null || true

    # Server side multipath rules
    ip netns exec "${SERVER_NS}" ip route add "${PRIMARY_SUBNET}" dev veth1 table 100 2>/dev/null || true
    ip netns exec "${SERVER_NS}" ip rule add from "${PRIMARY_SERVER_IP}" table 100 2>/dev/null || true

    ip netns exec "${SERVER_NS}" ip route add "${SECONDARY_SUBNET}" dev veth3 table 200 2>/dev/null || true
    ip netns exec "${SERVER_NS}" ip rule add from "${SECONDARY_SERVER_IP}" table 200 2>/dev/null || true
}

#------------------------------------------------------------------------------
# Network Impairment (tc netem)
#------------------------------------------------------------------------------

apply_netem() {
    local namespace="$1"
    local interface="$2"
    local delay="${3:-0ms}"
    local loss="${4:-0%}"
    local bandwidth="${5:-}"

    log_info "Applying netem to ${namespace}/${interface}: delay=${delay} loss=${loss}"

    # Remove existing qdisc
    ip netns exec "${namespace}" tc qdisc del dev "${interface}" root 2>/dev/null || true

    # Add netem qdisc
    local netem_opts="delay ${delay}"
    if [[ "${loss}" != "0%" ]]; then
        netem_opts="${netem_opts} loss ${loss}"
    fi

    ip netns exec "${namespace}" tc qdisc add dev "${interface}" root netem ${netem_opts}

    # Add bandwidth limit if specified
    if [[ -n "${bandwidth}" ]]; then
        ip netns exec "${namespace}" tc qdisc add dev "${interface}" parent 1:1 handle 10: tbf rate "${bandwidth}" burst 32kbit latency 400ms
    fi
}

clear_netem() {
    local namespace="$1"
    local interface="$2"

    log_info "Clearing netem from ${namespace}/${interface}"
    ip netns exec "${namespace}" tc qdisc del dev "${interface}" root 2>/dev/null || true
}

#------------------------------------------------------------------------------
# Main Setup/Cleanup Functions
#------------------------------------------------------------------------------

setup() {
    log_info "Setting up TQUIC test network..."

    # Create namespaces
    create_namespace "${CLIENT_NS}"
    create_namespace "${SERVER_NS}"

    # Create primary path
    create_veth_pair "veth0" "veth1" "${PRIMARY_CLIENT_IP}" "${PRIMARY_SERVER_IP}" "24"

    # Create secondary path for multipath
    create_veth_pair "veth2" "veth3" "${SECONDARY_CLIENT_IP}" "${SECONDARY_SERVER_IP}" "24"

    # Create tertiary path for advanced testing
    create_veth_pair "veth4" "veth5" "${TERTIARY_CLIENT_IP}" "${TERTIARY_SERVER_IP}" "24"

    # Setup routing
    setup_routing
    setup_multipath_routing

    log_info "Network setup complete"
    log_info ""
    log_info "Topology:"
    log_info "  Client namespace: ${CLIENT_NS}"
    log_info "    veth0: ${PRIMARY_CLIENT_IP}/24"
    log_info "    veth2: ${SECONDARY_CLIENT_IP}/24"
    log_info "    veth4: ${TERTIARY_CLIENT_IP}/24"
    log_info ""
    log_info "  Server namespace: ${SERVER_NS}"
    log_info "    veth1: ${PRIMARY_SERVER_IP}/24"
    log_info "    veth3: ${SECONDARY_SERVER_IP}/24"
    log_info "    veth5: ${TERTIARY_SERVER_IP}/24"
    log_info ""
    log_info "Run commands in namespaces:"
    log_info "  ip netns exec ${CLIENT_NS} <command>"
    log_info "  ip netns exec ${SERVER_NS} <command>"
}

cleanup() {
    log_info "Cleaning up TQUIC test network..."

    # Kill any processes in namespaces
    for ns in "${CLIENT_NS}" "${SERVER_NS}"; do
        if ip netns list | grep -q "^${ns}"; then
            # Find and kill processes
            for pid in $(ip netns pids "${ns}" 2>/dev/null); do
                kill -9 "${pid}" 2>/dev/null || true
            done
        fi
    done

    # Delete namespaces
    delete_namespace "${CLIENT_NS}"
    delete_namespace "${SERVER_NS}"

    log_info "Cleanup complete"
}

status() {
    echo "TQUIC Test Network Status"
    echo "========================="
    echo ""

    for ns in "${CLIENT_NS}" "${SERVER_NS}"; do
        if ip netns list | grep -q "^${ns}"; then
            echo "Namespace: ${ns}"
            echo "  Interfaces:"
            ip netns exec "${ns}" ip -brief addr show
            echo "  Routes:"
            ip netns exec "${ns}" ip route show
            echo ""
        else
            echo "Namespace: ${ns} [NOT FOUND]"
            echo ""
        fi
    done
}

#------------------------------------------------------------------------------
# Entry Point
#------------------------------------------------------------------------------

case "${1:-}" in
    setup)
        setup
        ;;
    cleanup)
        cleanup
        ;;
    status)
        status
        ;;
    netem)
        # Usage: setup_namespaces.sh netem <namespace> <interface> <delay> [loss] [bandwidth]
        apply_netem "$2" "$3" "$4" "${5:-0%}" "${6:-}"
        ;;
    clear-netem)
        clear_netem "$2" "$3"
        ;;
    *)
        echo "Usage: $0 {setup|cleanup|status|netem|clear-netem}"
        echo ""
        echo "Commands:"
        echo "  setup       - Create network namespaces and interfaces"
        echo "  cleanup     - Remove all test network configuration"
        echo "  status      - Show current network status"
        echo "  netem       - Apply network emulation (delay, loss, etc.)"
        echo "  clear-netem - Remove network emulation"
        echo ""
        echo "Examples:"
        echo "  $0 setup"
        echo "  $0 netem tquic_client veth0 50ms 1% 100mbit"
        echo "  $0 cleanup"
        exit 1
        ;;
esac
