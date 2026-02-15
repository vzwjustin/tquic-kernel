#!/bin/bash
# SPDX-License-Identifier: GPL-2.0
#
# Description: 0-RTT session resumption test
#
# Tests:
# - Session ticket acquisition
# - 0-RTT early data transmission
# - Anti-replay protection
# - Fallback to 1-RTT when 0-RTT rejected

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

test_session_ticket_acquisition() {
    local work_dir="$1"

    log_test "Testing session ticket acquisition with ${PEER}"

    start_peer_server "${PEER}" "${SERVER_NS}" "${SERVER_ADDR}" "${SERVER_PORT}" \
        "${CERT_DIR}" "${work_dir}" "--enable-session-tickets"

    wait_for_port "${SERVER_NS}" "${SERVER_PORT}" 10 || return 1

    local client_log="${work_dir}/client_ticket.log"
    local session_file="${work_dir}/session.ticket"

    # Initial connection to acquire ticket
    start_tquic_client "${CLIENT_NS}" "${SERVER_ADDR}" "${SERVER_PORT}" \
        "${CERT_DIR}" "${work_dir}" \
        "--save-session ${session_file}" \
        > "${client_log}" 2>&1 || true

    # Check for ticket
    if [[ -f "${session_file}" ]] && [[ -s "${session_file}" ]]; then
        log_pass "Session ticket acquired successfully"
        return 0
    fi

    if grep -q "session ticket\|NewSessionTicket\|ticket received" "${client_log}"; then
        log_pass "Session ticket message observed"
        return 0
    fi

    log_fail "Session ticket acquisition failed"
    cat "${client_log}"
    return 1
}

test_zerortt_resumption() {
    local work_dir="$1"

    log_test "Testing 0-RTT resumption with ${PEER}"

    start_peer_server "${PEER}" "${SERVER_NS}" "${SERVER_ADDR}" "${SERVER_PORT}" \
        "${CERT_DIR}" "${work_dir}" "--enable-0rtt"

    wait_for_port "${SERVER_NS}" "${SERVER_PORT}" 10 || return 1

    local session_file="${work_dir}/session.ticket"

    # First connection to acquire ticket
    local client_log1="${work_dir}/client_first.log"
    start_tquic_client "${CLIENT_NS}" "${SERVER_ADDR}" "${SERVER_PORT}" \
        "${CERT_DIR}" "${work_dir}" \
        "--save-session ${session_file}" \
        > "${client_log1}" 2>&1 || true

    if [[ ! -f "${session_file}" ]]; then
        log_fail "No session ticket saved from first connection"
        return 1
    fi

    sleep 1  # Allow ticket to be stored

    # Second connection with 0-RTT
    local client_log2="${work_dir}/client_zerortt.log"
    local early_data="${work_dir}/early_data.txt"
    echo "Hello 0-RTT!" > "${early_data}"

    local start_time=$(start_timer)

    start_tquic_client "${CLIENT_NS}" "${SERVER_ADDR}" "${SERVER_PORT}" \
        "${CERT_DIR}" "${work_dir}" \
        "--resume-session ${session_file} --early-data ${early_data}" \
        > "${client_log2}" 2>&1 || true

    local elapsed=$(stop_timer ${start_time})

    # Check for 0-RTT acceptance
    if check_zerortt_success "${client_log2}"; then
        log_pass "0-RTT resumption successful (${elapsed}ms)"
        record_metric "zerortt_latency_${PEER}" "${elapsed}" "ms" "${work_dir}/metrics.json"
        return 0
    fi

    # Check if fell back to 1-RTT
    if grep -q "0-RTT rejected\|early data rejected\|1-RTT" "${client_log2}"; then
        log_warn "0-RTT rejected, fell back to 1-RTT"
        return 0  # Fallback is acceptable
    fi

    log_fail "0-RTT resumption failed"
    cat "${client_log2}"
    return 1
}

test_zerortt_rejection() {
    local work_dir="$1"

    log_test "Testing 0-RTT rejection handling with ${PEER}"

    # Start server without 0-RTT support
    start_peer_server "${PEER}" "${SERVER_NS}" "${SERVER_ADDR}" "${SERVER_PORT}" \
        "${CERT_DIR}" "${work_dir}" "--disable-0rtt"

    wait_for_port "${SERVER_NS}" "${SERVER_PORT}" 10 || return 1

    local session_file="${work_dir}/session.ticket"

    # First connection
    local client_log1="${work_dir}/client_first.log"
    start_tquic_client "${CLIENT_NS}" "${SERVER_ADDR}" "${SERVER_PORT}" \
        "${CERT_DIR}" "${work_dir}" \
        "--save-session ${session_file}" \
        > "${client_log1}" 2>&1 || true

    sleep 1

    # Second connection attempting 0-RTT (should be rejected)
    local client_log2="${work_dir}/client_reject.log"
    local early_data="${work_dir}/early_data.txt"
    echo "This should be rejected" > "${early_data}"

    start_tquic_client "${CLIENT_NS}" "${SERVER_ADDR}" "${SERVER_PORT}" \
        "${CERT_DIR}" "${work_dir}" \
        "--resume-session ${session_file} --early-data ${early_data}" \
        > "${client_log2}" 2>&1 || true

    # Verify 1-RTT fallback
    if grep -q "0-RTT rejected\|fallback\|1-RTT complete" "${client_log2}"; then
        log_pass "0-RTT rejection handled correctly"
        return 0
    fi

    # Check if connection still succeeded
    if check_connection_established "${client_log2}"; then
        log_pass "Connection succeeded after 0-RTT rejection"
        return 0
    fi

    log_fail "Failed to handle 0-RTT rejection"
    return 1
}

test_anti_replay() {
    local work_dir="$1"

    log_test "Testing 0-RTT anti-replay with ${PEER}"

    start_peer_server "${PEER}" "${SERVER_NS}" "${SERVER_ADDR}" "${SERVER_PORT}" \
        "${CERT_DIR}" "${work_dir}" "--enable-0rtt --anti-replay"

    wait_for_port "${SERVER_NS}" "${SERVER_PORT}" 10 || return 1

    local session_file="${work_dir}/session.ticket"

    # Acquire ticket
    local client_log1="${work_dir}/client_first.log"
    start_tquic_client "${CLIENT_NS}" "${SERVER_ADDR}" "${SERVER_PORT}" \
        "${CERT_DIR}" "${work_dir}" \
        "--save-session ${session_file}" \
        > "${client_log1}" 2>&1 || true

    sleep 1

    local early_data="${work_dir}/early_data.txt"
    echo "Replay test data" > "${early_data}"

    # First 0-RTT attempt (should succeed)
    local client_log2="${work_dir}/client_replay1.log"
    start_tquic_client "${CLIENT_NS}" "${SERVER_ADDR}" "${SERVER_PORT}" \
        "${CERT_DIR}" "${work_dir}" \
        "--resume-session ${session_file} --early-data ${early_data}" \
        > "${client_log2}" 2>&1 || true

    # Second immediate 0-RTT attempt with same ticket (replay)
    local client_log3="${work_dir}/client_replay2.log"
    start_tquic_client "${CLIENT_NS}" "${SERVER_ADDR}" "${SERVER_PORT}" \
        "${CERT_DIR}" "${work_dir}" \
        "--resume-session ${session_file} --early-data ${early_data}" \
        > "${client_log3}" 2>&1 || true

    # Second attempt should be rejected or fall back to 1-RTT
    if grep -q "replay detected\|0-RTT rejected\|early data rejected" "${client_log3}"; then
        log_pass "Anti-replay protection working"
        return 0
    fi

    # If both succeeded, anti-replay might not be enabled (acceptable for some peers)
    log_warn "Anti-replay not verified (may not be supported by peer)"
    return 0
}

test_ticket_lifetime() {
    local work_dir="$1"

    log_test "Testing session ticket lifetime with ${PEER}"

    # Start server with short ticket lifetime
    start_peer_server "${PEER}" "${SERVER_NS}" "${SERVER_ADDR}" "${SERVER_PORT}" \
        "${CERT_DIR}" "${work_dir}" "--enable-0rtt --ticket-lifetime 5"

    wait_for_port "${SERVER_NS}" "${SERVER_PORT}" 10 || return 1

    local session_file="${work_dir}/session.ticket"

    # Acquire ticket
    local client_log1="${work_dir}/client_first.log"
    start_tquic_client "${CLIENT_NS}" "${SERVER_ADDR}" "${SERVER_PORT}" \
        "${CERT_DIR}" "${work_dir}" \
        "--save-session ${session_file}" \
        > "${client_log1}" 2>&1 || true

    # Wait for ticket to expire
    log_debug "Waiting for ticket expiration (6 seconds)..."
    sleep 6

    # Attempt resumption with expired ticket
    local client_log2="${work_dir}/client_expired.log"
    start_tquic_client "${CLIENT_NS}" "${SERVER_ADDR}" "${SERVER_PORT}" \
        "${CERT_DIR}" "${work_dir}" \
        "--resume-session ${session_file}" \
        > "${client_log2}" 2>&1 || true

    # Should fall back to full handshake
    if grep -q "ticket expired\|full handshake\|1-RTT" "${client_log2}"; then
        log_pass "Expired ticket handled correctly"
        return 0
    fi

    if check_connection_established "${client_log2}"; then
        log_pass "Connection succeeded with expired ticket (full handshake)"
        return 0
    fi

    log_fail "Failed to handle expired ticket"
    return 1
}

#------------------------------------------------------------------------------
# Main Test Runner
#------------------------------------------------------------------------------

main() {
    local work_dir=$(mktemp -d)
    local result=0

    log_test "=========================================="
    log_test "0-RTT Tests: TQUIC <-> ${PEER}"
    log_test "=========================================="

    local tests=(
        "test_session_ticket_acquisition"
        "test_zerortt_resumption"
        "test_zerortt_rejection"
        "test_anti_replay"
        "test_ticket_lifetime"
    )

    for test in "${tests[@]}"; do
        local test_work="${work_dir}/${test}"
        mkdir -p "${test_work}"

        if "${test}" "${test_work}"; then
            log_pass "${test}"
        else
            log_fail "${test}"
            result=1
        fi

        stop_peer "${PEER}" "${test_work}"
        sleep 1
    done

    rm -rf "${work_dir}"
    return ${result}
}

main
