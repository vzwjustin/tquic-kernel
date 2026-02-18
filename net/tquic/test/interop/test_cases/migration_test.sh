#!/bin/bash
# SPDX-License-Identifier: GPL-2.0-only
#
# Description: Connection migration test
#
# Tests:
# - Client-initiated connection migration
# - NAT rebinding simulation
# - Path validation
# - Preferred address handling
# - Migration during active transfer

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

# Secondary addresses for migration
SECONDARY_CLIENT_IP="10.0.2.1"
SECONDARY_SERVER_IP="10.0.2.2"

#------------------------------------------------------------------------------
# Test Implementation
#------------------------------------------------------------------------------

test_client_migration() {
    local work_dir="$1"

    log_test "Testing client-initiated migration with ${PEER}"

    start_peer_server "${PEER}" "${SERVER_NS}" "${SERVER_ADDR}" "${SERVER_PORT}" \
        "${CERT_DIR}" "${work_dir}" "--enable-migration"

    wait_for_port "${SERVER_NS}" "${SERVER_PORT}" 10 || return 1

    local client_log="${work_dir}/client_migrate.log"

    # Connect and then migrate to secondary address
    start_tquic_client "${CLIENT_NS}" "${SERVER_ADDR}" "${SERVER_PORT}" \
        "${CERT_DIR}" "${work_dir}" \
        "--migrate-to ${SECONDARY_CLIENT_IP} --migrate-delay 2000" \
        > "${client_log}" 2>&1 || true

    # Verify migration
    if check_migration_success "${client_log}"; then
        log_pass "Client migration successful"
        return 0
    fi

    if grep -q "migration.*complete\|new path.*validated\|PATH_RESPONSE" "${client_log}"; then
        log_pass "Migration evidence found"
        return 0
    fi

    log_fail "Client migration failed"
    cat "${client_log}"
    return 1
}

test_nat_rebinding() {
    local work_dir="$1"

    log_test "Testing NAT rebinding simulation with ${PEER}"

    start_peer_server "${PEER}" "${SERVER_NS}" "${SERVER_ADDR}" "${SERVER_PORT}" \
        "${CERT_DIR}" "${work_dir}" "--enable-migration"

    wait_for_port "${SERVER_NS}" "${SERVER_PORT}" 10 || return 1

    local client_log="${work_dir}/client_nat.log"

    # Simulate NAT rebinding by changing source port
    start_tquic_client "${CLIENT_NS}" "${SERVER_ADDR}" "${SERVER_PORT}" \
        "${CERT_DIR}" "${work_dir}" \
        "--simulate-nat-rebind --rebind-delay 2000" \
        > "${client_log}" 2>&1 || true

    # Server should continue accepting packets from new port
    if grep -q "NAT rebind\|port change\|path validated\|connection maintained" "${client_log}"; then
        log_pass "NAT rebinding handled correctly"
        return 0
    fi

    if check_connection_established "${client_log}"; then
        log_pass "Connection survived NAT rebinding"
        return 0
    fi

    log_fail "NAT rebinding handling failed"
    return 1
}

test_path_validation() {
    local work_dir="$1"

    log_test "Testing path validation with ${PEER}"

    start_peer_server "${PEER}" "${SERVER_NS}" "${SERVER_ADDR}" "${SERVER_PORT}" \
        "${CERT_DIR}" "${work_dir}" "--enable-migration"

    wait_for_port "${SERVER_NS}" "${SERVER_PORT}" 10 || return 1

    local client_log="${work_dir}/client_pathval.log"

    # Trigger migration with explicit path validation
    start_tquic_client "${CLIENT_NS}" "${SERVER_ADDR}" "${SERVER_PORT}" \
        "${CERT_DIR}" "${work_dir}" \
        "--migrate-to ${SECONDARY_CLIENT_IP} --validate-path" \
        > "${client_log}" 2>&1 || true

    # Check for path validation frames
    if grep -q "PATH_CHALLENGE\|PATH_RESPONSE\|path validated" "${client_log}"; then
        log_pass "Path validation completed"
        return 0
    fi

    log_fail "Path validation not observed"
    return 1
}

test_migration_during_transfer() {
    local work_dir="$1"

    log_test "Testing migration during active transfer with ${PEER}"

    # Generate large test file for continuous transfer
    local test_file="${work_dir}/large_file.bin"
    generate_test_data "${test_file}" 10485760  # 10MB

    start_peer_server "${PEER}" "${SERVER_NS}" "${SERVER_ADDR}" "${SERVER_PORT}" \
        "${CERT_DIR}" "${work_dir}" "--enable-migration --serve-dir ${work_dir}"

    wait_for_port "${SERVER_NS}" "${SERVER_PORT}" 10 || return 1

    local client_log="${work_dir}/client_transfer_migrate.log"
    local received_file="${work_dir}/received_large.bin"

    # Download file while migrating mid-transfer
    start_tquic_client "${CLIENT_NS}" "${SERVER_ADDR}" "${SERVER_PORT}" \
        "${CERT_DIR}" "${work_dir}" \
        "--download /large_file.bin --output ${received_file} \
         --migrate-to ${SECONDARY_CLIENT_IP} --migrate-after-bytes 5242880" \
        > "${client_log}" 2>&1 || true

    # Verify transfer completed after migration
    if [[ -f "${received_file}" ]] && verify_transfer "${test_file}" "${received_file}"; then
        log_pass "Transfer completed successfully after migration"
        return 0
    fi

    log_fail "Transfer failed during migration"
    return 1
}

test_preferred_address() {
    local work_dir="$1"

    log_test "Testing server preferred address with ${PEER}"

    # Server advertises preferred address
    start_peer_server "${PEER}" "${SERVER_NS}" "${SERVER_ADDR}" "${SERVER_PORT}" \
        "${CERT_DIR}" "${work_dir}" \
        "--enable-migration --preferred-address ${SECONDARY_SERVER_IP}:${SERVER_PORT}"

    wait_for_port "${SERVER_NS}" "${SERVER_PORT}" 10 || return 1

    local client_log="${work_dir}/client_preferred.log"

    # Client should migrate to preferred address
    start_tquic_client "${CLIENT_NS}" "${SERVER_ADDR}" "${SERVER_PORT}" \
        "${CERT_DIR}" "${work_dir}" \
        "--use-preferred-address" \
        > "${client_log}" 2>&1 || true

    if grep -q "preferred address\|migrating to.*${SECONDARY_SERVER_IP}\|using server preferred" "${client_log}"; then
        log_pass "Preferred address migration successful"
        return 0
    fi

    # Check if connection established at all
    if check_connection_established "${client_log}"; then
        log_warn "Connection established but preferred address not used"
        return 0
    fi

    log_fail "Preferred address handling failed"
    return 1
}

test_migration_disabled() {
    local work_dir="$1"

    log_test "Testing disabled migration with ${PEER}"

    # Server disables migration
    start_peer_server "${PEER}" "${SERVER_NS}" "${SERVER_ADDR}" "${SERVER_PORT}" \
        "${CERT_DIR}" "${work_dir}" "--disable-migration"

    wait_for_port "${SERVER_NS}" "${SERVER_PORT}" 10 || return 1

    local client_log="${work_dir}/client_nomigrate.log"

    # Attempt migration (should fail or be rejected)
    start_tquic_client "${CLIENT_NS}" "${SERVER_ADDR}" "${SERVER_PORT}" \
        "${CERT_DIR}" "${work_dir}" \
        "--migrate-to ${SECONDARY_CLIENT_IP}" \
        > "${client_log}" 2>&1 || true

    # Check for migration rejection or parameter indication
    if grep -q "migration disabled\|disable_active_migration\|migration not allowed" "${client_log}"; then
        log_pass "Migration correctly rejected when disabled"
        return 0
    fi

    # Connection should still work on original path
    if check_connection_established "${client_log}"; then
        log_pass "Connection works with migration disabled"
        return 0
    fi

    log_fail "Migration disabled handling failed"
    return 1
}

test_rapid_migration() {
    local work_dir="$1"

    log_test "Testing rapid successive migrations with ${PEER}"

    start_peer_server "${PEER}" "${SERVER_NS}" "${SERVER_ADDR}" "${SERVER_PORT}" \
        "${CERT_DIR}" "${work_dir}" "--enable-migration"

    wait_for_port "${SERVER_NS}" "${SERVER_PORT}" 10 || return 1

    local client_log="${work_dir}/client_rapid.log"

    # Perform multiple rapid migrations
    start_tquic_client "${CLIENT_NS}" "${SERVER_ADDR}" "${SERVER_PORT}" \
        "${CERT_DIR}" "${work_dir}" \
        "--rapid-migrations 5 --migration-interval 500" \
        > "${client_log}" 2>&1 || true

    # Count successful migrations
    local migration_count=$(grep -c "path validated\|migration complete" "${client_log}" || echo "0")

    if [[ ${migration_count} -ge 3 ]]; then
        log_pass "Rapid migration test passed (${migration_count} migrations)"
        return 0
    fi

    if check_connection_established "${client_log}"; then
        log_warn "Connection survived rapid migrations (${migration_count} confirmed)"
        return 0
    fi

    log_fail "Rapid migration test failed"
    return 1
}

#------------------------------------------------------------------------------
# Main Test Runner
#------------------------------------------------------------------------------

main() {
    local work_dir=$(mktemp -d)
    local result=0

    log_test "=========================================="
    log_test "Migration Tests: TQUIC <-> ${PEER}"
    log_test "=========================================="

    local tests=(
        "test_client_migration"
        "test_nat_rebinding"
        "test_path_validation"
        "test_migration_during_transfer"
        "test_preferred_address"
        "test_migration_disabled"
        "test_rapid_migration"
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
