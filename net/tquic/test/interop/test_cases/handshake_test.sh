#!/bin/bash
# SPDX-License-Identifier: GPL-2.0-only
#
# Description: Basic QUIC connection establishment test
#
# Tests:
# - Version negotiation
# - Cryptographic handshake (TLS 1.3)
# - Connection ID exchange
# - Transport parameter negotiation

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/../common.sh"

#------------------------------------------------------------------------------
# Test Parameters
#------------------------------------------------------------------------------

PEER="$1"
CLIENT_NS="$2"
SERVER_NS="$3"
SERVER_ADDR="$4"
SERVER_PORT="$5"
CERT_DIR="$6"

#------------------------------------------------------------------------------
# Test Implementation
#------------------------------------------------------------------------------

test_basic_handshake() {
    local work_dir="$1"

    log_test "Testing basic handshake with ${PEER}"

    # Start peer server
    start_peer_server "${PEER}" "${SERVER_NS}" "${SERVER_ADDR}" "${SERVER_PORT}" \
        "${CERT_DIR}" "${work_dir}"

    # Wait for server to be ready
    wait_for_port "${SERVER_NS}" "${SERVER_PORT}" 10 || {
        log_fail "Server failed to start"
        return 1
    }

    # Run TQUIC client to establish connection
    local client_log="${work_dir}/client.log"

    if start_tquic_client "${CLIENT_NS}" "${SERVER_ADDR}" "${SERVER_PORT}" \
        "${CERT_DIR}" "${work_dir}" "--test-mode handshake" > "${client_log}" 2>&1; then
        log_debug "Client completed"
    else
        log_fail "Client connection failed"
        cat "${client_log}"
        return 1
    fi

    # Verify handshake completed
    if check_connection_established "${client_log}"; then
        log_pass "Handshake completed successfully"
        return 0
    else
        log_fail "Handshake verification failed"
        cat "${client_log}"
        return 1
    fi
}

test_version_negotiation() {
    local work_dir="$1"

    log_test "Testing version negotiation with ${PEER}"

    # Start peer server
    start_peer_server "${PEER}" "${SERVER_NS}" "${SERVER_ADDR}" "${SERVER_PORT}" \
        "${CERT_DIR}" "${work_dir}"

    wait_for_port "${SERVER_NS}" "${SERVER_PORT}" 10 || return 1

    # Try connection with version negotiation
    local client_log="${work_dir}/client_vn.log"

    # Request version 1 (RFC 9000)
    start_tquic_client "${CLIENT_NS}" "${SERVER_ADDR}" "${SERVER_PORT}" \
        "${CERT_DIR}" "${work_dir}" "--quic-version 1" > "${client_log}" 2>&1 || true

    # Check for successful negotiation or fallback
    if grep -q "version.*1\|QUIC v1\|version negotiation" "${client_log}"; then
        log_pass "Version negotiation successful"
        return 0
    fi

    log_fail "Version negotiation failed"
    return 1
}

test_transport_parameters() {
    local work_dir="$1"

    log_test "Testing transport parameter exchange with ${PEER}"

    start_peer_server "${PEER}" "${SERVER_NS}" "${SERVER_ADDR}" "${SERVER_PORT}" \
        "${CERT_DIR}" "${work_dir}"

    wait_for_port "${SERVER_NS}" "${SERVER_PORT}" 10 || return 1

    local client_log="${work_dir}/client_tp.log"

    # Connect with specific transport parameters
    start_tquic_client "${CLIENT_NS}" "${SERVER_ADDR}" "${SERVER_PORT}" \
        "${CERT_DIR}" "${work_dir}" \
        "--max-stream-data 1048576 --max-data 16777216 --idle-timeout 30000" \
        > "${client_log}" 2>&1 || true

    if check_connection_established "${client_log}"; then
        log_pass "Transport parameters exchanged successfully"
        return 0
    fi

    log_fail "Transport parameter exchange failed"
    return 1
}

test_connection_close() {
    local work_dir="$1"

    log_test "Testing graceful connection close with ${PEER}"

    start_peer_server "${PEER}" "${SERVER_NS}" "${SERVER_ADDR}" "${SERVER_PORT}" \
        "${CERT_DIR}" "${work_dir}"

    wait_for_port "${SERVER_NS}" "${SERVER_PORT}" 10 || return 1

    local client_log="${work_dir}/client_close.log"

    # Connect and close gracefully
    start_tquic_client "${CLIENT_NS}" "${SERVER_ADDR}" "${SERVER_PORT}" \
        "${CERT_DIR}" "${work_dir}" "--test-mode close" > "${client_log}" 2>&1 || true

    if grep -q "connection closed\|CONNECTION_CLOSE\|closed gracefully" "${client_log}"; then
        log_pass "Graceful close successful"
        return 0
    fi

    log_fail "Graceful close failed"
    return 1
}

test_data_transfer() {
    local work_dir="$1"

    log_test "Testing basic data transfer with ${PEER}"

    # Generate test data
    local test_file="${work_dir}/test_data.bin"
    local received_file="${work_dir}/received_data.bin"
    generate_test_data "${test_file}" 65536  # 64KB

    start_peer_server "${PEER}" "${SERVER_NS}" "${SERVER_ADDR}" "${SERVER_PORT}" \
        "${CERT_DIR}" "${work_dir}" "--serve-dir ${work_dir}"

    wait_for_port "${SERVER_NS}" "${SERVER_PORT}" 10 || return 1

    local client_log="${work_dir}/client_data.log"

    # Request file transfer
    start_tquic_client "${CLIENT_NS}" "${SERVER_ADDR}" "${SERVER_PORT}" \
        "${CERT_DIR}" "${work_dir}" \
        "--download /test_data.bin --output ${received_file}" \
        > "${client_log}" 2>&1 || true

    # Verify data integrity
    if [[ -f "${received_file}" ]] && verify_transfer "${test_file}" "${received_file}"; then
        log_pass "Data transfer verified"
        return 0
    fi

    log_fail "Data transfer verification failed"
    return 1
}

#------------------------------------------------------------------------------
# Main Test Runner
#------------------------------------------------------------------------------

main() {
    local work_dir=$(mktemp -d)
    local result=0

    log_test "=========================================="
    log_test "Handshake Tests: TQUIC <-> ${PEER}"
    log_test "=========================================="

    # Run all handshake tests
    local tests=(
        "test_basic_handshake"
        "test_version_negotiation"
        "test_transport_parameters"
        "test_connection_close"
        "test_data_transfer"
    )

    for test in "${tests[@]}"; do
        # Create fresh work directory for each test
        local test_work="${work_dir}/${test}"
        mkdir -p "${test_work}"

        if "${test}" "${test_work}"; then
            log_pass "${test}"
        else
            log_fail "${test}"
            result=1
        fi

        # Cleanup between tests
        stop_peer "${PEER}" "${test_work}"
        sleep 1
    done

    # Final cleanup
    rm -rf "${work_dir}"

    return ${result}
}

main
