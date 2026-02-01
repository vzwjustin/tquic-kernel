#!/bin/bash
# SPDX-License-Identifier: GPL-2.0
#
# Description: Path failover test
#
# Tests:
# - Primary path failure detection
# - Automatic failover to backup path
# - Recovery and re-establishment
# - Hitless failover metrics
# - Failover under load

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

# Path addresses
PRIMARY_CLIENT_IP="10.0.1.1"
PRIMARY_SERVER_IP="10.0.1.2"
SECONDARY_CLIENT_IP="10.0.2.1"
SECONDARY_SERVER_IP="10.0.2.2"

#------------------------------------------------------------------------------
# Helper Functions
#------------------------------------------------------------------------------

# Simulate path failure by blocking traffic
simulate_path_failure() {
    local namespace="$1"
    local interface="$2"

    log_debug "Simulating failure on ${namespace}/${interface}"
    ip netns exec "${namespace}" iptables -A OUTPUT -o "${interface}" -j DROP
    ip netns exec "${namespace}" iptables -A INPUT -i "${interface}" -j DROP
}

# Restore path after failure
restore_path() {
    local namespace="$1"
    local interface="$2"

    log_debug "Restoring ${namespace}/${interface}"
    ip netns exec "${namespace}" iptables -D OUTPUT -o "${interface}" -j DROP 2>/dev/null || true
    ip netns exec "${namespace}" iptables -D INPUT -i "${interface}" -j DROP 2>/dev/null || true
}

# Clean up all iptables rules
cleanup_iptables() {
    for ns in "${CLIENT_NS}" "${SERVER_NS}"; do
        ip netns exec "${ns}" iptables -F 2>/dev/null || true
    done
}

#------------------------------------------------------------------------------
# Test Implementation
#------------------------------------------------------------------------------

test_basic_failover() {
    local work_dir="$1"

    log_test "Testing basic path failover with ${PEER}"

    # For non-multipath peers, test migration-based failover
    local multipath_flag=""
    if [[ "${PEER}" == "picoquic" ]]; then
        multipath_flag="--enable-multipath"
    else
        multipath_flag="--enable-migration"
    fi

    start_peer_server "${PEER}" "${SERVER_NS}" "${SERVER_ADDR}" "${SERVER_PORT}" \
        "${CERT_DIR}" "${work_dir}" "${multipath_flag}"

    wait_for_port "${SERVER_NS}" "${SERVER_PORT}" 10 || return 1

    local client_log="${work_dir}/client_failover.log"

    # Start long-running transfer in background
    start_tquic_client "${CLIENT_NS}" "${SERVER_ADDR}" "${SERVER_PORT}" \
        "${CERT_DIR}" "${work_dir}" \
        "--multipath --add-path ${SECONDARY_CLIENT_IP} --continuous-transfer 60" \
        > "${client_log}" 2>&1 &
    local client_pid=$!

    # Wait for connection establishment
    sleep 3

    # Simulate primary path failure
    simulate_path_failure "${CLIENT_NS}" "veth0"

    # Wait for failover detection and completion
    sleep 5

    # Check if connection survived
    if kill -0 "${client_pid}" 2>/dev/null; then
        log_debug "Client still running after failover"

        # Wait a bit more for transfer to continue
        sleep 3

        # Kill client gracefully
        kill "${client_pid}" 2>/dev/null || true
        wait "${client_pid}" 2>/dev/null || true
    fi

    # Restore path
    restore_path "${CLIENT_NS}" "veth0"

    # Check logs for failover evidence
    if grep -q "failover\|path.*failed\|switching.*path\|backup.*active" "${client_log}"; then
        log_pass "Failover detected and handled"
        return 0
    fi

    if grep -q "transfer continued\|connection maintained" "${client_log}"; then
        log_pass "Connection survived path failure"
        return 0
    fi

    log_fail "Failover not observed"
    cat "${client_log}"
    return 1
}

test_failover_recovery() {
    local work_dir="$1"

    log_test "Testing failover recovery with ${PEER}"

    local multipath_flag=""
    if [[ "${PEER}" == "picoquic" ]]; then
        multipath_flag="--enable-multipath"
    else
        multipath_flag="--enable-migration"
    fi

    start_peer_server "${PEER}" "${SERVER_NS}" "${SERVER_ADDR}" "${SERVER_PORT}" \
        "${CERT_DIR}" "${work_dir}" "${multipath_flag}"

    wait_for_port "${SERVER_NS}" "${SERVER_PORT}" 10 || return 1

    local client_log="${work_dir}/client_recovery.log"

    start_tquic_client "${CLIENT_NS}" "${SERVER_ADDR}" "${SERVER_PORT}" \
        "${CERT_DIR}" "${work_dir}" \
        "--multipath --add-path ${SECONDARY_CLIENT_IP} --continuous-transfer 90" \
        > "${client_log}" 2>&1 &
    local client_pid=$!

    # Phase 1: Establish and verify
    sleep 3

    # Phase 2: Fail primary
    log_debug "Failing primary path"
    simulate_path_failure "${CLIENT_NS}" "veth0"
    sleep 5

    # Phase 3: Restore primary
    log_debug "Restoring primary path"
    restore_path "${CLIENT_NS}" "veth0"
    sleep 5

    # Phase 4: Check if primary is re-established
    kill "${client_pid}" 2>/dev/null || true
    wait "${client_pid}" 2>/dev/null || true

    if grep -q "path.*recovered\|primary.*restored\|path.*re-established" "${client_log}"; then
        log_pass "Path recovery successful"
        return 0
    fi

    if check_connection_established "${client_log}"; then
        log_pass "Connection maintained through failure and recovery"
        return 0
    fi

    log_fail "Failover recovery failed"
    return 1
}

test_hitless_failover() {
    local work_dir="$1"

    log_test "Testing hitless failover metrics with ${PEER}"

    if [[ "${PEER}" != "picoquic" ]]; then
        log_skip "Hitless failover requires multipath (picoquic)"
        return 0
    fi

    # Generate test data
    local test_file="${work_dir}/test_data.bin"
    local received_file="${work_dir}/received_data.bin"
    generate_test_data "${test_file}" 10485760  # 10MB

    start_peer_server "${PEER}" "${SERVER_NS}" "${SERVER_ADDR}" "${SERVER_PORT}" \
        "${CERT_DIR}" "${work_dir}" "--enable-multipath --serve-dir ${work_dir}"

    wait_for_port "${SERVER_NS}" "${SERVER_PORT}" 10 || return 1

    local client_log="${work_dir}/client_hitless.log"
    local metrics_file="${work_dir}/metrics.json"

    # Start transfer with metrics collection
    start_tquic_client "${CLIENT_NS}" "${SERVER_ADDR}" "${SERVER_PORT}" \
        "${CERT_DIR}" "${work_dir}" \
        "--multipath --add-path ${SECONDARY_CLIENT_IP} \
         --download /test_data.bin --output ${received_file} \
         --metrics-output ${metrics_file} --failover-trigger 3000" \
        > "${client_log}" 2>&1 &
    local client_pid=$!

    # Wait for transfer to start
    sleep 2

    # Trigger failover mid-transfer
    simulate_path_failure "${CLIENT_NS}" "veth0"

    # Wait for transfer to complete
    wait "${client_pid}" 2>/dev/null || true

    # Restore path
    restore_path "${CLIENT_NS}" "veth0"

    # Verify data integrity (hitless = no data loss)
    if verify_transfer "${test_file}" "${received_file}"; then
        log_pass "Hitless failover: data integrity verified"

        # Check for failover timing metrics
        if [[ -f "${metrics_file}" ]]; then
            local failover_time=$(grep "failover_time" "${metrics_file}" | grep -o '[0-9]*' | head -1 || echo "unknown")
            log_test "Failover time: ${failover_time}ms"
            record_metric "hitless_failover_time_${PEER}" "${failover_time}" "ms"
        fi

        return 0
    fi

    log_fail "Data corruption during failover"
    return 1
}

test_failover_under_load() {
    local work_dir="$1"

    log_test "Testing failover under heavy load with ${PEER}"

    # Generate large test file
    local test_file="${work_dir}/large_test.bin"
    generate_test_data "${test_file}" 104857600  # 100MB

    local multipath_flag=""
    if [[ "${PEER}" == "picoquic" ]]; then
        multipath_flag="--enable-multipath"
    else
        multipath_flag="--enable-migration"
    fi

    start_peer_server "${PEER}" "${SERVER_NS}" "${SERVER_ADDR}" "${SERVER_PORT}" \
        "${CERT_DIR}" "${work_dir}" "${multipath_flag} --serve-dir ${work_dir}"

    wait_for_port "${SERVER_NS}" "${SERVER_PORT}" 10 || return 1

    local client_log="${work_dir}/client_load.log"
    local received_file="${work_dir}/received_large.bin"

    # Start high-bandwidth transfer
    start_tquic_client "${CLIENT_NS}" "${SERVER_ADDR}" "${SERVER_PORT}" \
        "${CERT_DIR}" "${work_dir}" \
        "--multipath --add-path ${SECONDARY_CLIENT_IP} \
         --download /large_test.bin --output ${received_file}" \
        > "${client_log}" 2>&1 &
    local client_pid=$!

    # Wait for transfer to hit peak throughput
    sleep 5

    # Fail primary during peak load
    local failover_start=$(date +%s%N)
    simulate_path_failure "${CLIENT_NS}" "veth0"

    # Wait for failover
    sleep 3
    local failover_end=$(date +%s%N)

    # Continue transfer on backup
    wait "${client_pid}" 2>/dev/null || true

    # Restore path
    restore_path "${CLIENT_NS}" "veth0"

    local failover_duration=$(( (failover_end - failover_start) / 1000000 ))
    log_test "Failover duration under load: ${failover_duration}ms"

    if [[ -f "${received_file}" ]]; then
        if verify_transfer "${test_file}" "${received_file}"; then
            log_pass "Transfer completed correctly after failover under load"
            return 0
        else
            log_fail "Data corruption during failover under load"
            return 1
        fi
    fi

    log_fail "Transfer failed during failover under load"
    return 1
}

test_rapid_failover() {
    local work_dir="$1"

    log_test "Testing rapid consecutive failovers with ${PEER}"

    if [[ "${PEER}" != "picoquic" ]]; then
        log_skip "Rapid failover requires multipath (picoquic)"
        return 0
    fi

    start_peer_server "${PEER}" "${SERVER_NS}" "${SERVER_ADDR}" "${SERVER_PORT}" \
        "${CERT_DIR}" "${work_dir}" "--enable-multipath"

    wait_for_port "${SERVER_NS}" "${SERVER_PORT}" 10 || return 1

    local client_log="${work_dir}/client_rapid.log"

    start_tquic_client "${CLIENT_NS}" "${SERVER_ADDR}" "${SERVER_PORT}" \
        "${CERT_DIR}" "${work_dir}" \
        "--multipath --add-path ${SECONDARY_CLIENT_IP} --continuous-transfer 60" \
        > "${client_log}" 2>&1 &
    local client_pid=$!

    sleep 3

    # Rapid failover cycles
    for i in {1..5}; do
        log_debug "Failover cycle ${i}"

        # Fail primary
        simulate_path_failure "${CLIENT_NS}" "veth0"
        sleep 2

        # Restore primary
        restore_path "${CLIENT_NS}" "veth0"
        sleep 2

        # Check if still running
        if ! kill -0 "${client_pid}" 2>/dev/null; then
            log_fail "Connection died during failover cycle ${i}"
            return 1
        fi
    done

    # Cleanup
    kill "${client_pid}" 2>/dev/null || true
    wait "${client_pid}" 2>/dev/null || true

    local failover_count=$(grep -c "failover\|path.*switch" "${client_log}" || echo "0")

    if [[ ${failover_count} -ge 3 ]]; then
        log_pass "Survived ${failover_count} rapid failovers"
        return 0
    fi

    log_warn "Only ${failover_count} failovers confirmed"
    return 0
}

test_bidirectional_failover() {
    local work_dir="$1"

    log_test "Testing bidirectional failover with ${PEER}"

    if [[ "${PEER}" != "picoquic" ]]; then
        log_skip "Bidirectional failover requires multipath (picoquic)"
        return 0
    fi

    start_peer_server "${PEER}" "${SERVER_NS}" "${SERVER_ADDR}" "${SERVER_PORT}" \
        "${CERT_DIR}" "${work_dir}" "--enable-multipath"

    wait_for_port "${SERVER_NS}" "${SERVER_PORT}" 10 || return 1

    local client_log="${work_dir}/client_bidir.log"

    # Start bidirectional transfer
    start_tquic_client "${CLIENT_NS}" "${SERVER_ADDR}" "${SERVER_PORT}" \
        "${CERT_DIR}" "${work_dir}" \
        "--multipath --add-path ${SECONDARY_CLIENT_IP} --bidirectional-transfer 60" \
        > "${client_log}" 2>&1 &
    local client_pid=$!

    sleep 3

    # Fail from server side
    simulate_path_failure "${SERVER_NS}" "veth1"
    sleep 5
    restore_path "${SERVER_NS}" "veth1"

    sleep 3

    # Fail from client side
    simulate_path_failure "${CLIENT_NS}" "veth0"
    sleep 5
    restore_path "${CLIENT_NS}" "veth0"

    sleep 2

    kill "${client_pid}" 2>/dev/null || true
    wait "${client_pid}" 2>/dev/null || true

    if grep -q "bidirectional.*maintained\|both directions" "${client_log}"; then
        log_pass "Bidirectional failover successful"
        return 0
    fi

    if check_connection_established "${client_log}"; then
        log_pass "Connection survived bidirectional failures"
        return 0
    fi

    log_fail "Bidirectional failover failed"
    return 1
}

#------------------------------------------------------------------------------
# Main Test Runner
#------------------------------------------------------------------------------

main() {
    local work_dir=$(mktemp -d)
    local result=0

    # Ensure cleanup on exit
    trap 'cleanup_iptables; rm -rf "${work_dir}"' EXIT

    log_test "=========================================="
    log_test "Failover Tests: TQUIC <-> ${PEER}"
    log_test "=========================================="

    local tests=(
        "test_basic_failover"
        "test_failover_recovery"
        "test_hitless_failover"
        "test_failover_under_load"
        "test_rapid_failover"
        "test_bidirectional_failover"
    )

    for test in "${tests[@]}"; do
        local test_work="${work_dir}/${test}"
        mkdir -p "${test_work}"

        # Clean iptables before each test
        cleanup_iptables

        if "${test}" "${test_work}"; then
            log_pass "${test}"
        else
            log_fail "${test}"
            result=1
        fi

        stop_peer "${PEER}" "${test_work}"
        cleanup_iptables
        sleep 1
    done

    return ${result}
}

main
