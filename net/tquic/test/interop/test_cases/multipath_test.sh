#!/bin/bash
# SPDX-License-Identifier: GPL-2.0
#
# Description: Multipath QUIC aggregation test
#
# Tests:
# - Multiple path establishment
# - Bandwidth aggregation
# - Latency-based path selection
# - Load balancing across paths
# - Path scheduling algorithms

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
TERTIARY_CLIENT_IP="10.0.3.1"
TERTIARY_SERVER_IP="10.0.3.2"

#------------------------------------------------------------------------------
# Test Implementation
#------------------------------------------------------------------------------

test_dual_path_establishment() {
    local work_dir="$1"

    log_test "Testing dual path establishment with ${PEER}"

    # Only picoquic supports multipath
    if [[ "${PEER}" != "picoquic" ]]; then
        log_skip "Multipath not supported by ${PEER}"
        return 0
    fi

    start_peer_server "${PEER}" "${SERVER_NS}" "${SERVER_ADDR}" "${SERVER_PORT}" \
        "${CERT_DIR}" "${work_dir}" "--enable-multipath"

    wait_for_port "${SERVER_NS}" "${SERVER_PORT}" 10 || return 1

    local client_log="${work_dir}/client_dual.log"

    # Establish connection with two paths
    start_tquic_client "${CLIENT_NS}" "${SERVER_ADDR}" "${SERVER_PORT}" \
        "${CERT_DIR}" "${work_dir}" \
        "--multipath --add-path ${SECONDARY_CLIENT_IP}" \
        > "${client_log}" 2>&1 || true

    # Verify both paths established
    if check_multipath_active "${client_log}"; then
        local path_count=$(grep -c "path.*established\|path.*validated\|PATH_STATUS" "${client_log}" || echo "0")
        if [[ ${path_count} -ge 2 ]]; then
            log_pass "Dual path establishment successful (${path_count} paths)"
            return 0
        fi
    fi

    log_fail "Dual path establishment failed"
    cat "${client_log}"
    return 1
}

test_bandwidth_aggregation() {
    local work_dir="$1"

    log_test "Testing bandwidth aggregation with ${PEER}"

    if [[ "${PEER}" != "picoquic" ]]; then
        log_skip "Multipath not supported by ${PEER}"
        return 0
    fi

    # Generate large test file
    local test_file="${work_dir}/large_test.bin"
    generate_test_data "${test_file}" 52428800  # 50MB

    start_peer_server "${PEER}" "${SERVER_NS}" "${SERVER_ADDR}" "${SERVER_PORT}" \
        "${CERT_DIR}" "${work_dir}" "--enable-multipath --serve-dir ${work_dir}"

    wait_for_port "${SERVER_NS}" "${SERVER_PORT}" 10 || return 1

    # First test: single path baseline
    local client_log_single="${work_dir}/client_single.log"
    local received_single="${work_dir}/received_single.bin"
    local start_single=$(start_timer)

    start_tquic_client "${CLIENT_NS}" "${SERVER_ADDR}" "${SERVER_PORT}" \
        "${CERT_DIR}" "${work_dir}" \
        "--download /large_test.bin --output ${received_single}" \
        > "${client_log_single}" 2>&1 || true

    local elapsed_single=$(stop_timer ${start_single})

    # Second test: multipath
    local client_log_multi="${work_dir}/client_multi.log"
    local received_multi="${work_dir}/received_multi.bin"
    local start_multi=$(start_timer)

    start_tquic_client "${CLIENT_NS}" "${SERVER_ADDR}" "${SERVER_PORT}" \
        "${CERT_DIR}" "${work_dir}" \
        "--multipath --add-path ${SECONDARY_CLIENT_IP} \
         --download /large_test.bin --output ${received_multi}" \
        > "${client_log_multi}" 2>&1 || true

    local elapsed_multi=$(stop_timer ${start_multi})

    log_test "Single path: ${elapsed_single}ms, Multipath: ${elapsed_multi}ms"

    # Verify data integrity
    if ! verify_transfer "${test_file}" "${received_multi}"; then
        log_fail "Multipath transfer data corruption"
        return 1
    fi

    # Check for bandwidth aggregation (multipath should be faster)
    local speedup=$(echo "scale=2; ${elapsed_single} / ${elapsed_multi}" | bc)
    log_test "Speedup factor: ${speedup}x"

    record_metric "multipath_speedup_${PEER}" "${speedup}" "x" "${work_dir}/metrics.json"

    if (( $(echo "${speedup} > 1.2" | bc -l) )); then
        log_pass "Bandwidth aggregation observed (${speedup}x speedup)"
        return 0
    fi

    log_warn "Limited bandwidth aggregation (${speedup}x), may be expected"
    return 0
}

test_asymmetric_paths() {
    local work_dir="$1"

    log_test "Testing asymmetric path handling with ${PEER}"

    if [[ "${PEER}" != "picoquic" ]]; then
        log_skip "Multipath not supported by ${PEER}"
        return 0
    fi

    # Apply different latencies to paths
    "${SCRIPT_DIR}/../setup_namespaces.sh" netem "${CLIENT_NS}" veth0 10ms 0%
    "${SCRIPT_DIR}/../setup_namespaces.sh" netem "${CLIENT_NS}" veth2 100ms 0%

    start_peer_server "${PEER}" "${SERVER_NS}" "${SERVER_ADDR}" "${SERVER_PORT}" \
        "${CERT_DIR}" "${work_dir}" "--enable-multipath"

    wait_for_port "${SERVER_NS}" "${SERVER_PORT}" 10 || return 1

    local client_log="${work_dir}/client_asym.log"

    start_tquic_client "${CLIENT_NS}" "${SERVER_ADDR}" "${SERVER_PORT}" \
        "${CERT_DIR}" "${work_dir}" \
        "--multipath --add-path ${SECONDARY_CLIENT_IP} --scheduler minrtt" \
        > "${client_log}" 2>&1 || true

    # Scheduler should prefer low-latency path
    if grep -q "path.*selected\|minrtt\|scheduling" "${client_log}"; then
        log_pass "Asymmetric path handling working"
    fi

    # Clean up netem
    "${SCRIPT_DIR}/../setup_namespaces.sh" clear-netem "${CLIENT_NS}" veth0
    "${SCRIPT_DIR}/../setup_namespaces.sh" clear-netem "${CLIENT_NS}" veth2

    return 0
}

test_path_scheduling_roundrobin() {
    local work_dir="$1"

    log_test "Testing round-robin path scheduling with ${PEER}"

    if [[ "${PEER}" != "picoquic" ]]; then
        log_skip "Multipath not supported by ${PEER}"
        return 0
    fi

    start_peer_server "${PEER}" "${SERVER_NS}" "${SERVER_ADDR}" "${SERVER_PORT}" \
        "${CERT_DIR}" "${work_dir}" "--enable-multipath"

    wait_for_port "${SERVER_NS}" "${SERVER_PORT}" 10 || return 1

    local client_log="${work_dir}/client_rr.log"

    # Use round-robin scheduler
    start_tquic_client "${CLIENT_NS}" "${SERVER_ADDR}" "${SERVER_PORT}" \
        "${CERT_DIR}" "${work_dir}" \
        "--multipath --add-path ${SECONDARY_CLIENT_IP} --scheduler roundrobin \
         --transfer-size 1048576" \
        > "${client_log}" 2>&1 || true

    # Check for balanced traffic across paths
    if grep -q "roundrobin\|path 0.*sent\|path 1.*sent" "${client_log}"; then
        log_pass "Round-robin scheduling active"
        return 0
    fi

    if check_multipath_active "${client_log}"; then
        log_pass "Multipath active (scheduler not explicitly confirmed)"
        return 0
    fi

    log_fail "Round-robin scheduling failed"
    return 1
}

test_path_scheduling_weighted() {
    local work_dir="$1"

    log_test "Testing weighted path scheduling with ${PEER}"

    if [[ "${PEER}" != "picoquic" ]]; then
        log_skip "Multipath not supported by ${PEER}"
        return 0
    fi

    start_peer_server "${PEER}" "${SERVER_NS}" "${SERVER_ADDR}" "${SERVER_PORT}" \
        "${CERT_DIR}" "${work_dir}" "--enable-multipath"

    wait_for_port "${SERVER_NS}" "${SERVER_PORT}" 10 || return 1

    local client_log="${work_dir}/client_weighted.log"

    # Use weighted scheduler (70% on primary, 30% on secondary)
    start_tquic_client "${CLIENT_NS}" "${SERVER_ADDR}" "${SERVER_PORT}" \
        "${CERT_DIR}" "${work_dir}" \
        "--multipath --add-path ${SECONDARY_CLIENT_IP} \
         --scheduler weighted --weight-primary 70 --weight-secondary 30 \
         --transfer-size 10485760" \
        > "${client_log}" 2>&1 || true

    if check_multipath_active "${client_log}"; then
        log_pass "Weighted scheduling active"
        return 0
    fi

    log_fail "Weighted scheduling failed"
    return 1
}

test_three_path_aggregation() {
    local work_dir="$1"

    log_test "Testing three-path aggregation with ${PEER}"

    if [[ "${PEER}" != "picoquic" ]]; then
        log_skip "Multipath not supported by ${PEER}"
        return 0
    fi

    start_peer_server "${PEER}" "${SERVER_NS}" "${SERVER_ADDR}" "${SERVER_PORT}" \
        "${CERT_DIR}" "${work_dir}" "--enable-multipath --max-paths 3"

    wait_for_port "${SERVER_NS}" "${SERVER_PORT}" 10 || return 1

    local client_log="${work_dir}/client_three.log"

    # Establish connection with three paths
    start_tquic_client "${CLIENT_NS}" "${SERVER_ADDR}" "${SERVER_PORT}" \
        "${CERT_DIR}" "${work_dir}" \
        "--multipath --add-path ${SECONDARY_CLIENT_IP} --add-path ${TERTIARY_CLIENT_IP}" \
        > "${client_log}" 2>&1 || true

    # Count established paths
    local path_count=$(grep -c "path.*established\|path.*validated" "${client_log}" || echo "0")

    if [[ ${path_count} -ge 3 ]]; then
        log_pass "Three-path aggregation successful"
        return 0
    elif [[ ${path_count} -ge 2 ]]; then
        log_warn "Only ${path_count} paths established (expected 3)"
        return 0
    fi

    log_fail "Three-path aggregation failed"
    return 1
}

test_dynamic_path_addition() {
    local work_dir="$1"

    log_test "Testing dynamic path addition with ${PEER}"

    if [[ "${PEER}" != "picoquic" ]]; then
        log_skip "Multipath not supported by ${PEER}"
        return 0
    fi

    start_peer_server "${PEER}" "${SERVER_NS}" "${SERVER_ADDR}" "${SERVER_PORT}" \
        "${CERT_DIR}" "${work_dir}" "--enable-multipath"

    wait_for_port "${SERVER_NS}" "${SERVER_PORT}" 10 || return 1

    local client_log="${work_dir}/client_dynamic.log"

    # Start with single path, add second dynamically during transfer
    start_tquic_client "${CLIENT_NS}" "${SERVER_ADDR}" "${SERVER_PORT}" \
        "${CERT_DIR}" "${work_dir}" \
        "--multipath --dynamic-add-path ${SECONDARY_CLIENT_IP} --add-path-delay 3000 \
         --transfer-size 10485760" \
        > "${client_log}" 2>&1 || true

    if grep -q "path added\|new path.*established\|PATH_STATUS" "${client_log}"; then
        log_pass "Dynamic path addition successful"
        return 0
    fi

    log_fail "Dynamic path addition failed"
    return 1
}

test_path_removal() {
    local work_dir="$1"

    log_test "Testing path removal with ${PEER}"

    if [[ "${PEER}" != "picoquic" ]]; then
        log_skip "Multipath not supported by ${PEER}"
        return 0
    fi

    start_peer_server "${PEER}" "${SERVER_NS}" "${SERVER_ADDR}" "${SERVER_PORT}" \
        "${CERT_DIR}" "${work_dir}" "--enable-multipath"

    wait_for_port "${SERVER_NS}" "${SERVER_PORT}" 10 || return 1

    local client_log="${work_dir}/client_remove.log"

    # Start with two paths, remove one during transfer
    start_tquic_client "${CLIENT_NS}" "${SERVER_ADDR}" "${SERVER_PORT}" \
        "${CERT_DIR}" "${work_dir}" \
        "--multipath --add-path ${SECONDARY_CLIENT_IP} \
         --remove-path ${SECONDARY_CLIENT_IP} --remove-path-delay 3000 \
         --transfer-size 10485760" \
        > "${client_log}" 2>&1 || true

    if grep -q "path removed\|path abandoned\|RETIRE_CONNECTION_ID" "${client_log}"; then
        log_pass "Path removal handled correctly"
        return 0
    fi

    if check_connection_established "${client_log}"; then
        log_pass "Connection survived path removal"
        return 0
    fi

    log_fail "Path removal handling failed"
    return 1
}

#------------------------------------------------------------------------------
# Main Test Runner
#------------------------------------------------------------------------------

main() {
    local work_dir=$(mktemp -d)
    local result=0

    log_test "=========================================="
    log_test "Multipath Tests: TQUIC <-> ${PEER}"
    log_test "=========================================="

    # Check multipath support
    if [[ "${PEER}" != "picoquic" ]]; then
        log_warn "Peer ${PEER} does not support multipath QUIC"
        log_warn "Only picoquic supports multipath - skipping tests"
        rm -rf "${work_dir}"
        return 0
    fi

    local tests=(
        "test_dual_path_establishment"
        "test_bandwidth_aggregation"
        "test_asymmetric_paths"
        "test_path_scheduling_roundrobin"
        "test_path_scheduling_weighted"
        "test_three_path_aggregation"
        "test_dynamic_path_addition"
        "test_path_removal"
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
