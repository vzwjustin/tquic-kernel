#!/bin/bash
# SPDX-License-Identifier: GPL-2.0-only
#
# Common functions for TQUIC interoperability tests

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Default timeout for operations
DEFAULT_TIMEOUT=30

# Test data
TEST_DATA_SIZE=1048576  # 1MB
TEST_REQUEST="GET /test HTTP/1.1\r\nHost: localhost\r\n\r\n"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

#------------------------------------------------------------------------------
# Logging
#------------------------------------------------------------------------------

log_test() {
    echo "[TEST] $*"
}

log_pass() {
    echo -e "${GREEN}[PASS]${NC} $*"
}

log_fail() {
    echo -e "${RED}[FAIL]${NC} $*"
}

log_skip() {
    echo -e "${YELLOW}[SKIP]${NC} $*"
}

log_debug() {
    if [[ "${TQUIC_INTEROP_VERBOSE:-0}" == "1" ]]; then
        echo "[DEBUG] $*"
    fi
}

#------------------------------------------------------------------------------
# Process Management
#------------------------------------------------------------------------------

# Start a process in a namespace and track its PID
start_in_namespace() {
    local namespace="$1"
    shift
    local pidfile="$1"
    shift

    ip netns exec "${namespace}" "$@" &
    local pid=$!
    echo "${pid}" > "${pidfile}"
    log_debug "Started PID ${pid} in ${namespace}: $*"
    return 0
}

# Wait for a process to be ready (listening on port)
wait_for_port() {
    local namespace="$1"
    local port="$2"
    local timeout="${3:-10}"

    log_debug "Waiting for port ${port} in ${namespace}..."

    local count=0
    while [[ ${count} -lt ${timeout} ]]; do
        if ip netns exec "${namespace}" ss -uln | grep -q ":${port}"; then
            log_debug "Port ${port} is ready"
            return 0
        fi
        sleep 1
        ((count++))
    done

    log_fail "Timeout waiting for port ${port}"
    return 1
}

# Kill process by PID file
kill_by_pidfile() {
    local pidfile="$1"

    if [[ -f "${pidfile}" ]]; then
        local pid=$(cat "${pidfile}")
        if kill -0 "${pid}" 2>/dev/null; then
            kill "${pid}" 2>/dev/null || true
            sleep 0.5
            kill -9 "${pid}" 2>/dev/null || true
        fi
        rm -f "${pidfile}"
    fi
}

# Clean up all test processes
cleanup_test_processes() {
    local test_dir="$1"

    for pidfile in "${test_dir}"/*.pid; do
        [[ -f "${pidfile}" ]] && kill_by_pidfile "${pidfile}"
    done
}

#------------------------------------------------------------------------------
# Test Data Generation
#------------------------------------------------------------------------------

# Generate test data file
generate_test_data() {
    local output_file="$1"
    local size="${2:-${TEST_DATA_SIZE}}"

    dd if=/dev/urandom of="${output_file}" bs=1024 count=$((size / 1024)) 2>/dev/null
    log_debug "Generated ${size} bytes of test data: ${output_file}"
}

# Calculate checksum
calc_checksum() {
    local file="$1"
    sha256sum "${file}" | cut -d' ' -f1
}

# Verify transferred data
verify_transfer() {
    local source_file="$1"
    local dest_file="$2"

    if [[ ! -f "${source_file}" ]] || [[ ! -f "${dest_file}" ]]; then
        log_fail "Missing file for verification"
        return 1
    fi

    local src_sum=$(calc_checksum "${source_file}")
    local dst_sum=$(calc_checksum "${dest_file}")

    if [[ "${src_sum}" == "${dst_sum}" ]]; then
        log_debug "Checksum verified: ${src_sum}"
        return 0
    else
        log_fail "Checksum mismatch: ${src_sum} != ${dst_sum}"
        return 1
    fi
}

#------------------------------------------------------------------------------
# TQUIC Kernel Module Interaction
#------------------------------------------------------------------------------

# Check if TQUIC module is loaded
check_tquic_loaded() {
    if lsmod | grep -q "^tquic"; then
        return 0
    fi
    return 1
}

# Get TQUIC statistics
get_tquic_stats() {
    if [[ -f "/proc/net/tquic/stats" ]]; then
        cat /proc/net/tquic/stats
    elif [[ -d "/sys/kernel/debug/tquic" ]]; then
        cat /sys/kernel/debug/tquic/stats 2>/dev/null || true
    fi
}

# Get connection info
get_tquic_connections() {
    if [[ -f "/proc/net/tquic/connections" ]]; then
        cat /proc/net/tquic/connections
    fi
}

#------------------------------------------------------------------------------
# Peer Management
#------------------------------------------------------------------------------

# Start peer server
start_peer_server() {
    local peer="$1"
    local namespace="$2"
    local addr="$3"
    local port="$4"
    local cert_dir="$5"
    local work_dir="$6"

    local peer_script="${SCRIPT_DIR}/peers/${peer}_peer.sh"
    if [[ ! -f "${peer_script}" ]]; then
        log_fail "Peer script not found: ${peer_script}"
        return 1
    fi

    source "${peer_script}"

    if type -t "start_${peer}_server" &>/dev/null; then
        "start_${peer}_server" "${namespace}" "${addr}" "${port}" "${cert_dir}" "${work_dir}"
        return $?
    fi

    log_fail "Server function not found for peer: ${peer}"
    return 1
}

# Start peer client
start_peer_client() {
    local peer="$1"
    local namespace="$2"
    local addr="$3"
    local port="$4"
    local cert_dir="$5"
    local work_dir="$6"

    local peer_script="${SCRIPT_DIR}/peers/${peer}_peer.sh"
    source "${peer_script}"

    if type -t "start_${peer}_client" &>/dev/null; then
        "start_${peer}_client" "${namespace}" "${addr}" "${port}" "${cert_dir}" "${work_dir}"
        return $?
    fi

    log_fail "Client function not found for peer: ${peer}"
    return 1
}

# Stop peer
stop_peer() {
    local peer="$1"
    local work_dir="$2"

    local peer_script="${SCRIPT_DIR}/peers/${peer}_peer.sh"
    if [[ -f "${peer_script}" ]]; then
        source "${peer_script}"
        if type -t "stop_${peer}" &>/dev/null; then
            "stop_${peer}" "${work_dir}"
        fi
    fi

    cleanup_test_processes "${work_dir}"
}

#------------------------------------------------------------------------------
# TQUIC Test Tools
#------------------------------------------------------------------------------

# Start TQUIC test server
start_tquic_server() {
    local namespace="$1"
    local addr="$2"
    local port="$3"
    local cert_dir="$4"
    local work_dir="$5"
    local extra_args="${6:-}"

    local server_bin="${SCRIPT_DIR}/tools/tquic_test_server"
    if [[ ! -x "${server_bin}" ]]; then
        log_fail "TQUIC test server not built: ${server_bin}"
        return 1
    fi

    start_in_namespace "${namespace}" "${work_dir}/tquic_server.pid" \
        "${server_bin}" \
        --addr "${addr}" \
        --port "${port}" \
        --cert "${cert_dir}/server.crt" \
        --key "${cert_dir}/server.key" \
        ${extra_args}

    wait_for_port "${namespace}" "${port}"
}

# Start TQUIC test client
start_tquic_client() {
    local namespace="$1"
    local addr="$2"
    local port="$3"
    local cert_dir="$4"
    local work_dir="$5"
    local extra_args="${6:-}"

    local client_bin="${SCRIPT_DIR}/tools/tquic_test_client"
    if [[ ! -x "${client_bin}" ]]; then
        log_fail "TQUIC test client not built: ${client_bin}"
        return 1
    fi

    ip netns exec "${namespace}" "${client_bin}" \
        --addr "${addr}" \
        --port "${port}" \
        --ca "${cert_dir}/ca.crt" \
        ${extra_args}

    return $?
}

#------------------------------------------------------------------------------
# Connection Verification
#------------------------------------------------------------------------------

# Check if connection was established
check_connection_established() {
    local log_file="$1"

    if grep -q "connection established\|handshake complete\|CONNECTED" "${log_file}"; then
        return 0
    fi
    return 1
}

# Check for 0-RTT success
check_zerortt_success() {
    local log_file="$1"

    if grep -q "0-RTT accepted\|early data accepted\|0RTT" "${log_file}"; then
        return 0
    fi
    return 1
}

# Check for migration success
check_migration_success() {
    local log_file="$1"

    if grep -q "path validated\|migration complete\|new path" "${log_file}"; then
        return 0
    fi
    return 1
}

# Check multipath status
check_multipath_active() {
    local log_file="$1"

    if grep -q "path added\|multipath enabled\|secondary path" "${log_file}"; then
        return 0
    fi
    return 1
}

#------------------------------------------------------------------------------
# Test Harness
#------------------------------------------------------------------------------

# Run a test function with setup/teardown
run_test() {
    local test_name="$1"
    local test_func="$2"
    shift 2

    local work_dir=$(mktemp -d)
    local result=0

    log_test "Starting test: ${test_name}"

    # Run test
    if "${test_func}" "${work_dir}" "$@"; then
        log_pass "${test_name}"
        result=0
    else
        log_fail "${test_name}"
        result=1
    fi

    # Cleanup
    cleanup_test_processes "${work_dir}"
    rm -rf "${work_dir}"

    return ${result}
}

# Assert function for tests
assert_true() {
    local condition="$1"
    local message="${2:-Assertion failed}"

    if ! eval "${condition}"; then
        log_fail "${message}"
        return 1
    fi
    return 0
}

assert_eq() {
    local expected="$1"
    local actual="$2"
    local message="${3:-Values not equal}"

    if [[ "${expected}" != "${actual}" ]]; then
        log_fail "${message}: expected '${expected}', got '${actual}'"
        return 1
    fi
    return 0
}

assert_file_exists() {
    local file="$1"
    local message="${2:-File does not exist}"

    if [[ ! -f "${file}" ]]; then
        log_fail "${message}: ${file}"
        return 1
    fi
    return 0
}

#------------------------------------------------------------------------------
# Metrics Collection
#------------------------------------------------------------------------------

# Collect timing metrics
start_timer() {
    echo $(date +%s%N)
}

stop_timer() {
    local start="$1"
    local end=$(date +%s%N)
    echo $(( (end - start) / 1000000 ))  # milliseconds
}

# Record metric
record_metric() {
    local name="$1"
    local value="$2"
    local unit="${3:-}"
    local metrics_file="${4:-/tmp/tquic_metrics.json}"

    echo "{\"name\": \"${name}\", \"value\": ${value}, \"unit\": \"${unit}\", \"timestamp\": $(date +%s)}" >> "${metrics_file}"
}
