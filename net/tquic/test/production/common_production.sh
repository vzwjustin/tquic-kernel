#!/bin/bash
# SPDX-License-Identifier: GPL-2.0
#
# Common functions for TQUIC production tests
#
# CRITICAL: These tests use REAL WAN links, not network namespaces

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'  # No color

# Logging functions
log_test() {
    echo -e "${BLUE}[TEST]${NC} $*"
}

log_pass() {
    echo -e "${GREEN}[PASS]${NC} $*"
}

log_fail() {
    echo -e "${RED}[FAIL]${NC} $*"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $*"
}

# Check if running as root
require_root() {
    if [[ $EUID -ne 0 ]]; then
        log_fail "This test must be run as root (for network interface control)"
        exit 1
    fi
}

# Verify interface exists and is up
check_interface() {
    local iface=$1

    if ! ip link show ${iface} &> /dev/null; then
        log_fail "Interface ${iface} does not exist"
        return 1
    fi

    local state=$(ip link show ${iface} | grep -oP 'state \K\w+')
    if [[ "${state}" != "UP" ]]; then
        log_warn "Interface ${iface} is ${state}, not UP"
        return 1
    fi

    return 0
}

# Get interface IP address
get_interface_ip() {
    local iface=$1
    ip -4 addr show ${iface} | grep inet | awk '{print $2}' | cut -d/ -f1 | head -1
}

# Check if TQUIC module is loaded
check_tquic_module() {
    if ! lsmod | grep -q quic; then
        log_warn "TQUIC kernel module not loaded"
        return 1
    fi
    return 0
}

# Load TQUIC module
load_tquic_module() {
    if ! check_tquic_module; then
        log_test "Loading TQUIC kernel module..."
        if ! modprobe quic; then
            log_fail "Failed to load TQUIC module"
            return 1
        fi
        log_pass "TQUIC module loaded"
    fi
    return 0
}

# Verify server connectivity
check_server_reachable() {
    local server=$1
    local iface=$2
    local timeout=${3:-5}

    if ! ping -I ${iface} -c 3 -W ${timeout} ${server} > /dev/null 2>&1; then
        log_fail "Server ${server} not reachable via ${iface}"
        return 1
    fi

    return 0
}

# Measure RTT to server
measure_rtt() {
    local server=$1
    local iface=$2

    local rtt=$(ping -I ${iface} -c 5 ${server} 2>/dev/null | tail -1 | awk -F'/' '{print $5}')
    echo ${rtt}
}

# Check for required tools
check_required_tools() {
    local missing_tools=()

    for tool in tcpdump ip ping bc conntrack ifstat; do
        if ! command -v ${tool} &> /dev/null; then
            missing_tools+=("${tool}")
        fi
    done

    if [[ ${#missing_tools[@]} -gt 0 ]]; then
        log_fail "Missing required tools: ${missing_tools[*]}"
        log_fail "Install with: apt-get install iproute2 iputils-ping bc conntrack ifstat tcpdump"
        return 1
    fi

    return 0
}

# Save test environment info
save_environment_info() {
    local output_file=$1

    cat > ${output_file} <<EOF
Test Environment Information
Generated: $(date -Iseconds)

Kernel:
$(uname -a)

TQUIC Module:
$(lsmod | grep quic || echo "Not loaded")

Network Interfaces:
$(ip link show)

Routing Table:
$(ip route show)

TQUIC Sysctl:
$(sysctl -a 2>/dev/null | grep tquic || echo "No TQUIC sysctls found")

Memory:
$(free -h)

CPU:
$(lscpu | grep "Model name\|CPU(s)\|Thread(s)")
EOF
}

# Record test start
test_start() {
    local test_name=$1
    local work_dir=$2

    log_test "=========================================="
    log_test "Starting: ${test_name}"
    log_test "Time: $(date -Iseconds)"
    log_test "Working directory: ${work_dir}"
    log_test "=========================================="

    # Save environment
    save_environment_info "${work_dir}/environment.txt"
}

# Record test end
test_end() {
    local test_name=$1
    local result=$2
    local work_dir=$3

    log_test "=========================================="
    if [[ "${result}" == "PASS" ]]; then
        log_pass "Test completed: ${test_name}"
    else
        log_fail "Test failed: ${test_name}"
    fi
    log_test "End time: $(date -Iseconds)"
    log_test "Results: ${work_dir}"
    log_test "=========================================="
}

# Cleanup handler
cleanup_handler() {
    log_test "Cleanup triggered (Ctrl+C or error)"

    # Kill background processes
    jobs -p | xargs -r kill 2>/dev/null || true

    # Re-enable any disabled interfaces
    for iface in eth0 eth1 wwan0 wwan1; do
        if ip link show ${iface} 2>/dev/null | grep -q "state DOWN"; then
            log_test "Re-enabling ${iface}..."
            ip link set ${iface} up 2>/dev/null || true
        fi
    done
}

trap cleanup_handler EXIT INT TERM

# Export functions
export -f log_test log_pass log_fail log_warn
export -f require_root check_interface get_interface_ip
export -f check_tquic_module load_tquic_module
export -f check_server_reachable measure_rtt
export -f check_required_tools
export -f save_environment_info test_start test_end
