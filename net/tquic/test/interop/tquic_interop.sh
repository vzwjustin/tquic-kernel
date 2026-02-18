#!/bin/bash
# SPDX-License-Identifier: GPL-2.0-only
#
# TQUIC Interoperability Test Runner
#
# Main test harness for testing TQUIC kernel implementation against
# various userspace QUIC implementations.
#
# Usage: ./tquic_interop.sh [options]

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/common.sh" 2>/dev/null || true

# Default configuration
TQUIC_INTEROP_PEERS="${TQUIC_INTEROP_PEERS:-/opt/quic-peers}"
TQUIC_INTEROP_CERTS="${TQUIC_INTEROP_CERTS:-${SCRIPT_DIR}/certs}"
TQUIC_INTEROP_TIMEOUT="${TQUIC_INTEROP_TIMEOUT:-30}"
TQUIC_INTEROP_VERBOSE="${TQUIC_INTEROP_VERBOSE:-0}"

# Supported peers
SUPPORTED_PEERS="quiche msquic ngtcp2 picoquic"

# Supported tests
SUPPORTED_TESTS="handshake zerortt migration multipath failover"

# Network configuration
CLIENT_NS="tquic_client"
SERVER_NS="tquic_server"
PRIMARY_CLIENT_IP="10.0.1.1"
PRIMARY_SERVER_IP="10.0.1.2"
SECONDARY_CLIENT_IP="10.0.2.1"
SECONDARY_SERVER_IP="10.0.2.2"
SERVER_PORT="4433"

# Network impairment defaults
LATENCY=""
BANDWIDTH=""
LOSS=""
JITTER=""
REORDER=""

# Test results
RESULTS_DIR="${SCRIPT_DIR}/results"
PASSED=0
FAILED=0
SKIPPED=0

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

#------------------------------------------------------------------------------
# Utility Functions
#------------------------------------------------------------------------------

log_info() {
    echo -e "${BLUE}[INFO]${NC} $*"
}

log_success() {
    echo -e "${GREEN}[PASS]${NC} $*"
}

log_error() {
    echo -e "${RED}[FAIL]${NC} $*"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $*"
}

log_debug() {
    if [[ "${TQUIC_INTEROP_VERBOSE}" == "1" ]]; then
        echo -e "[DEBUG] $*"
    fi
}

usage() {
    cat << EOF
TQUIC Interoperability Test Runner

Usage: $(basename "$0") [options]

Options:
    -h, --help              Show this help message
    -a, --all               Run all tests against all peers
    -p, --peer <name>       Test against specific peer (quiche|msquic|ngtcp2|picoquic)
    -t, --test <name>       Run specific test (handshake|zerortt|migration|multipath|failover)
    -l, --latency <ms>      Add latency (e.g., 50ms)
    -b, --bandwidth <rate>  Limit bandwidth (e.g., 100mbit)
    --loss <percent>        Add packet loss (e.g., 1%)
    --jitter <ms>           Add latency jitter (e.g., 10ms)
    --reorder <percent>     Add packet reordering (e.g., 1%)
    -c, --capture           Capture packets to PCAP
    -v, --verbose           Enable verbose output
    --list-peers            List available peers
    --list-tests            List available tests
    --setup-only            Only setup namespaces, don't run tests
    --cleanup               Clean up namespaces and exit

Examples:
    $(basename "$0") --all
    $(basename "$0") --peer quiche --test handshake
    $(basename "$0") --peer picoquic --test multipath --latency 50ms --bandwidth 100mbit
EOF
    exit 0
}

#------------------------------------------------------------------------------
# Peer Management
#------------------------------------------------------------------------------

check_peer_available() {
    local peer="$1"
    local peer_script="${SCRIPT_DIR}/peers/${peer}_peer.sh"

    if [[ ! -f "${peer_script}" ]]; then
        log_error "Peer script not found: ${peer_script}"
        return 1
    fi

    source "${peer_script}"

    if type -t "check_${peer}_installed" &>/dev/null; then
        "check_${peer}_installed"
        return $?
    fi

    return 0
}

list_peers() {
    echo "Supported QUIC peers:"
    echo ""
    for peer in ${SUPPORTED_PEERS}; do
        if check_peer_available "${peer}" 2>/dev/null; then
            echo "  ${peer} [available]"
        else
            echo "  ${peer} [not installed]"
        fi
    done
    echo ""
    echo "Install directory: ${TQUIC_INTEROP_PEERS}"
}

list_tests() {
    echo "Available test cases:"
    echo ""
    for test in ${SUPPORTED_TESTS}; do
        local test_script="${SCRIPT_DIR}/test_cases/${test}_test.sh"
        if [[ -f "${test_script}" ]]; then
            local desc=$(head -5 "${test_script}" | grep "^# Description:" | cut -d: -f2- || echo "No description")
            echo "  ${test}: ${desc}"
        else
            echo "  ${test}: [script not found]"
        fi
    done
}

#------------------------------------------------------------------------------
# Network Setup
#------------------------------------------------------------------------------

setup_network() {
    log_info "Setting up network namespaces..."

    "${SCRIPT_DIR}/setup_namespaces.sh" setup

    # Apply network impairment if specified
    apply_network_impairment
}

cleanup_network() {
    log_info "Cleaning up network namespaces..."
    "${SCRIPT_DIR}/setup_namespaces.sh" cleanup
}

apply_network_impairment() {
    local tc_opts=""

    if [[ -n "${LATENCY}" ]]; then
        tc_opts="delay ${LATENCY}"
        if [[ -n "${JITTER}" ]]; then
            tc_opts="${tc_opts} ${JITTER}"
        fi
    fi

    if [[ -n "${LOSS}" ]]; then
        if [[ -n "${tc_opts}" ]]; then
            tc_opts="${tc_opts} loss ${LOSS}"
        else
            tc_opts="loss ${LOSS}"
        fi
    fi

    if [[ -n "${REORDER}" ]]; then
        if [[ -n "${tc_opts}" ]]; then
            tc_opts="${tc_opts} reorder ${REORDER}"
        else
            tc_opts="reorder ${REORDER}"
        fi
    fi

    if [[ -n "${tc_opts}" ]]; then
        log_info "Applying network impairment: ${tc_opts}"

        # Apply to both directions on primary path
        ip netns exec "${CLIENT_NS}" tc qdisc add dev veth0 root netem ${tc_opts} 2>/dev/null || \
            ip netns exec "${CLIENT_NS}" tc qdisc change dev veth0 root netem ${tc_opts}

        ip netns exec "${SERVER_NS}" tc qdisc add dev veth1 root netem ${tc_opts} 2>/dev/null || \
            ip netns exec "${SERVER_NS}" tc qdisc change dev veth1 root netem ${tc_opts}
    fi

    if [[ -n "${BANDWIDTH}" ]]; then
        log_info "Applying bandwidth limit: ${BANDWIDTH}"

        # Use tbf for bandwidth limiting
        ip netns exec "${CLIENT_NS}" tc qdisc add dev veth0 root tbf rate ${BANDWIDTH} burst 32kbit latency 400ms 2>/dev/null || true
        ip netns exec "${SERVER_NS}" tc qdisc add dev veth1 root tbf rate ${BANDWIDTH} burst 32kbit latency 400ms 2>/dev/null || true
    fi
}

#------------------------------------------------------------------------------
# Certificate Management
#------------------------------------------------------------------------------

setup_certificates() {
    if [[ ! -d "${TQUIC_INTEROP_CERTS}" ]]; then
        log_info "Generating test certificates..."
        mkdir -p "${TQUIC_INTEROP_CERTS}"

        # Generate CA key and certificate
        openssl genrsa -out "${TQUIC_INTEROP_CERTS}/ca.key" 2048 2>/dev/null
        openssl req -x509 -new -nodes -key "${TQUIC_INTEROP_CERTS}/ca.key" \
            -sha256 -days 365 -out "${TQUIC_INTEROP_CERTS}/ca.crt" \
            -subj "/CN=TQUIC Test CA" 2>/dev/null

        # Generate server key and certificate
        openssl genrsa -out "${TQUIC_INTEROP_CERTS}/server.key" 2048 2>/dev/null
        openssl req -new -key "${TQUIC_INTEROP_CERTS}/server.key" \
            -out "${TQUIC_INTEROP_CERTS}/server.csr" \
            -subj "/CN=localhost" 2>/dev/null

        cat > "${TQUIC_INTEROP_CERTS}/server.ext" << EXTEOF
authorityKeyIdentifier=keyid,issuer
basicConstraints=CA:FALSE
keyUsage = digitalSignature, nonRepudiation, keyEncipherment, dataEncipherment
subjectAltName = @alt_names

[alt_names]
DNS.1 = localhost
IP.1 = 127.0.0.1
IP.2 = ${PRIMARY_SERVER_IP}
IP.3 = ${SECONDARY_SERVER_IP}
EXTEOF

        openssl x509 -req -in "${TQUIC_INTEROP_CERTS}/server.csr" \
            -CA "${TQUIC_INTEROP_CERTS}/ca.crt" \
            -CAkey "${TQUIC_INTEROP_CERTS}/ca.key" \
            -CAcreateserial -out "${TQUIC_INTEROP_CERTS}/server.crt" \
            -days 365 -sha256 -extfile "${TQUIC_INTEROP_CERTS}/server.ext" 2>/dev/null

        log_info "Certificates generated in ${TQUIC_INTEROP_CERTS}"
    fi
}

#------------------------------------------------------------------------------
# TQUIC Module Management
#------------------------------------------------------------------------------

load_tquic_module() {
    if ! lsmod | grep -q "^tquic"; then
        log_info "Loading TQUIC kernel module..."
        modprobe tquic 2>/dev/null || {
            # Try loading from local build
            local module_path="${SCRIPT_DIR}/../../tquic.ko"
            if [[ -f "${module_path}" ]]; then
                insmod "${module_path}"
            else
                log_error "TQUIC module not found. Build with: make -C /lib/modules/\$(uname -r)/build M=${SCRIPT_DIR}/../.."
                return 1
            fi
        }
    fi
    log_debug "TQUIC module loaded"
}

#------------------------------------------------------------------------------
# Test Execution
#------------------------------------------------------------------------------

run_test() {
    local test_name="$1"
    local peer="$2"
    local test_script="${SCRIPT_DIR}/test_cases/${test_name}_test.sh"

    if [[ ! -f "${test_script}" ]]; then
        log_error "Test script not found: ${test_script}"
        return 1
    fi

    # Check if test is compatible with peer
    if [[ "${test_name}" == "multipath" && "${peer}" != "picoquic" ]]; then
        log_warn "Skipping ${test_name} for ${peer} (no multipath support)"
        ((SKIPPED++))
        return 0
    fi

    log_info "Running test: ${test_name} against ${peer}"

    # Create results directory for this test
    local test_results="${RESULTS_DIR}/${test_name}_${peer}"
    mkdir -p "${test_results}"

    # Source peer setup
    source "${SCRIPT_DIR}/peers/${peer}_peer.sh"

    # Run test with timeout
    local start_time=$(date +%s)
    local test_log="${test_results}/test.log"

    if timeout "${TQUIC_INTEROP_TIMEOUT}" bash "${test_script}" \
        "${peer}" \
        "${CLIENT_NS}" \
        "${SERVER_NS}" \
        "${PRIMARY_SERVER_IP}" \
        "${SERVER_PORT}" \
        "${TQUIC_INTEROP_CERTS}" \
        > "${test_log}" 2>&1; then

        local end_time=$(date +%s)
        local duration=$((end_time - start_time))

        log_success "${test_name}/${peer} passed (${duration}s)"
        echo "PASSED" > "${test_results}/status"
        ((PASSED++))
        return 0
    else
        local exit_code=$?
        local end_time=$(date +%s)
        local duration=$((end_time - start_time))

        if [[ ${exit_code} -eq 124 ]]; then
            log_error "${test_name}/${peer} timed out after ${TQUIC_INTEROP_TIMEOUT}s"
            echo "TIMEOUT" > "${test_results}/status"
        else
            log_error "${test_name}/${peer} failed (exit code: ${exit_code}, ${duration}s)"
            echo "FAILED" > "${test_results}/status"
        fi

        # Show last few lines of log on failure
        if [[ "${TQUIC_INTEROP_VERBOSE}" == "1" ]]; then
            echo "--- Test Log (last 20 lines) ---"
            tail -20 "${test_log}"
            echo "--- End Log ---"
        fi

        ((FAILED++))
        return 1
    fi
}

run_all_tests() {
    log_info "Running all tests against all available peers..."

    for peer in ${SUPPORTED_PEERS}; do
        if ! check_peer_available "${peer}" 2>/dev/null; then
            log_warn "Skipping ${peer} (not available)"
            continue
        fi

        for test in ${SUPPORTED_TESTS}; do
            run_test "${test}" "${peer}" || true
        done
    done
}

run_peer_tests() {
    local peer="$1"

    if ! check_peer_available "${peer}"; then
        log_error "Peer ${peer} is not available"
        return 1
    fi

    log_info "Running all tests against ${peer}..."

    for test in ${SUPPORTED_TESTS}; do
        run_test "${test}" "${peer}" || true
    done
}

#------------------------------------------------------------------------------
# Packet Capture
#------------------------------------------------------------------------------

start_capture() {
    local test_name="$1"
    local peer="$2"
    local pcap_file="${RESULTS_DIR}/${test_name}_${peer}.pcap"

    log_info "Starting packet capture: ${pcap_file}"

    # Capture on both interfaces
    ip netns exec "${CLIENT_NS}" tcpdump -i veth0 -w "${pcap_file}.client" -U &
    CAPTURE_CLIENT_PID=$!

    ip netns exec "${SERVER_NS}" tcpdump -i veth1 -w "${pcap_file}.server" -U &
    CAPTURE_SERVER_PID=$!
}

stop_capture() {
    if [[ -n "${CAPTURE_CLIENT_PID}" ]]; then
        kill "${CAPTURE_CLIENT_PID}" 2>/dev/null || true
    fi
    if [[ -n "${CAPTURE_SERVER_PID}" ]]; then
        kill "${CAPTURE_SERVER_PID}" 2>/dev/null || true
    fi
}

#------------------------------------------------------------------------------
# Results Summary
#------------------------------------------------------------------------------

generate_summary() {
    local total=$((PASSED + FAILED + SKIPPED))

    echo ""
    echo "========================================"
    echo "       TQUIC Interop Test Results"
    echo "========================================"
    echo ""
    echo "  Passed:  ${PASSED}"
    echo "  Failed:  ${FAILED}"
    echo "  Skipped: ${SKIPPED}"
    echo "  Total:   ${total}"
    echo ""

    if [[ ${FAILED} -eq 0 ]]; then
        echo -e "  Status: ${GREEN}ALL TESTS PASSED${NC}"
    else
        echo -e "  Status: ${RED}SOME TESTS FAILED${NC}"
    fi

    echo ""
    echo "Results directory: ${RESULTS_DIR}"
    echo ""
}

generate_html_report() {
    local html_file="${RESULTS_DIR}/interop_matrix.html"

    cat > "${html_file}" << 'HTMLEOF'
<!DOCTYPE html>
<html>
<head>
    <title>TQUIC Interoperability Test Results</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        h1 { color: #333; }
        table { border-collapse: collapse; margin: 20px 0; }
        th, td { border: 1px solid #ddd; padding: 10px; text-align: center; }
        th { background-color: #4a90d9; color: white; }
        .pass { background-color: #90EE90; }
        .fail { background-color: #FFB6C1; }
        .skip { background-color: #FFFACD; }
        .timeout { background-color: #FFA500; }
    </style>
</head>
<body>
    <h1>TQUIC Interoperability Test Results</h1>
    <p>Generated: TIMESTAMP</p>
    <table>
        <tr>
            <th>Test</th>
HTMLEOF

    # Add peer headers
    for peer in ${SUPPORTED_PEERS}; do
        echo "            <th>${peer}</th>" >> "${html_file}"
    done
    echo "        </tr>" >> "${html_file}"

    # Add test rows
    for test in ${SUPPORTED_TESTS}; do
        echo "        <tr>" >> "${html_file}"
        echo "            <td><strong>${test}</strong></td>" >> "${html_file}"

        for peer in ${SUPPORTED_PEERS}; do
            local status_file="${RESULTS_DIR}/${test}_${peer}/status"
            local status="N/A"
            local class="skip"

            if [[ -f "${status_file}" ]]; then
                status=$(cat "${status_file}")
                case "${status}" in
                    PASSED) class="pass" ;;
                    FAILED) class="fail" ;;
                    TIMEOUT) class="timeout" ;;
                    *) class="skip" ;;
                esac
            fi

            echo "            <td class=\"${class}\">${status}</td>" >> "${html_file}"
        done

        echo "        </tr>" >> "${html_file}"
    done

    cat >> "${html_file}" << 'HTMLEOF'
    </table>
</body>
</html>
HTMLEOF

    # Replace timestamp
    sed -i "s/TIMESTAMP/$(date)/" "${html_file}" 2>/dev/null || \
        sed -i '' "s/TIMESTAMP/$(date)/" "${html_file}"

    log_info "HTML report generated: ${html_file}"
}

#------------------------------------------------------------------------------
# Main
#------------------------------------------------------------------------------

main() {
    local run_all=false
    local selected_peer=""
    local selected_test=""
    local capture=false
    local setup_only=false
    local cleanup_only=false

    # Parse arguments
    while [[ $# -gt 0 ]]; do
        case "$1" in
            -h|--help)
                usage
                ;;
            -a|--all)
                run_all=true
                shift
                ;;
            -p|--peer)
                selected_peer="$2"
                shift 2
                ;;
            -t|--test)
                selected_test="$2"
                shift 2
                ;;
            -l|--latency)
                LATENCY="$2"
                shift 2
                ;;
            -b|--bandwidth)
                BANDWIDTH="$2"
                shift 2
                ;;
            --loss)
                LOSS="$2"
                shift 2
                ;;
            --jitter)
                JITTER="$2"
                shift 2
                ;;
            --reorder)
                REORDER="$2"
                shift 2
                ;;
            -c|--capture)
                capture=true
                shift
                ;;
            -v|--verbose)
                TQUIC_INTEROP_VERBOSE=1
                shift
                ;;
            --list-peers)
                list_peers
                exit 0
                ;;
            --list-tests)
                list_tests
                exit 0
                ;;
            --setup-only)
                setup_only=true
                shift
                ;;
            --cleanup)
                cleanup_only=true
                shift
                ;;
            *)
                log_error "Unknown option: $1"
                usage
                ;;
        esac
    done

    # Check root privileges
    if [[ $EUID -ne 0 ]]; then
        log_error "This script must be run as root"
        exit 2
    fi

    # Cleanup only mode
    if [[ "${cleanup_only}" == "true" ]]; then
        cleanup_network
        exit 0
    fi

    # Create results directory
    mkdir -p "${RESULTS_DIR}"

    # Setup
    setup_certificates
    load_tquic_module || exit 2
    setup_network

    # Setup only mode
    if [[ "${setup_only}" == "true" ]]; then
        log_info "Network namespaces set up. Use --cleanup to remove."
        exit 0
    fi

    # Trap for cleanup
    trap cleanup_network EXIT

    # Run tests
    if [[ "${run_all}" == "true" ]]; then
        run_all_tests
    elif [[ -n "${selected_peer}" && -n "${selected_test}" ]]; then
        run_test "${selected_test}" "${selected_peer}"
    elif [[ -n "${selected_peer}" ]]; then
        run_peer_tests "${selected_peer}"
    elif [[ -n "${selected_test}" ]]; then
        for peer in ${SUPPORTED_PEERS}; do
            if check_peer_available "${peer}" 2>/dev/null; then
                run_test "${selected_test}" "${peer}" || true
            fi
        done
    else
        usage
    fi

    # Generate reports
    generate_summary
    generate_html_report

    # Exit with appropriate code
    if [[ ${FAILED} -gt 0 ]]; then
        exit 1
    fi
    exit 0
}

main "$@"
