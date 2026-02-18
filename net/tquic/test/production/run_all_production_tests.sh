#!/bin/bash
# SPDX-License-Identifier: GPL-2.0-only
#
# TQUIC Production Test Suite - Master Runner
#
# Runs comprehensive real-world WAN bonding validation
#
# Usage: ./run_all_production_tests.sh --server <IP> [options]

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/common_production.sh"

# Default configuration
SERVER_ADDR=""
WAN1_IFACE="eth0"
WAN2_IFACE="eth1"
OUTPUT_DIR="./results/$(date +%Y%m%d_%H%M%S)"
RUN_SOAK_TEST=false
SOAK_HOURS=24

# Parse arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --server|-s)
            SERVER_ADDR="$2"
            shift 2
            ;;
        --wan1)
            WAN1_IFACE="$2"
            shift 2
            ;;
        --wan2)
            WAN2_IFACE="$2"
            shift 2
            ;;
        --output|-o)
            OUTPUT_DIR="$2"
            shift 2
            ;;
        --soak)
            RUN_SOAK_TEST=true
            shift
            ;;
        --soak-hours)
            SOAK_HOURS="$2"
            shift 2
            ;;
        --help|-h)
            echo "Usage: $0 --server <IP> [options]"
            echo ""
            echo "Required:"
            echo "  --server <IP>      Test server public IP address"
            echo ""
            echo "Optional:"
            echo "  --wan1 <iface>     WAN1 interface (default: eth0)"
            echo "  --wan2 <iface>     WAN2 interface (default: eth1)"
            echo "  --output <dir>     Output directory (default: ./results/TIMESTAMP)"
            echo "  --soak             Run 24-hour soak test (adds ${SOAK_HOURS} hours)"
            echo "  --soak-hours <N>   Soak test duration (default: 24)"
            echo ""
            echo "Example:"
            echo "  sudo $0 --server 203.0.113.100 --wan1 eth0 --wan2 wwan0"
            exit 0
            ;;
        *)
            echo "Unknown option: $1"
            echo "Use --help for usage information"
            exit 1
            ;;
    esac
done

# Validate required arguments
if [[ -z "${SERVER_ADDR}" ]]; then
    log_fail "Server address is required"
    echo "Usage: $0 --server <IP> [options]"
    exit 1
fi

# Pre-flight checks
log_test "=========================================="
log_test "TQUIC Production Test Suite"
log_test "=========================================="
log_test "Server: ${SERVER_ADDR}"
log_test "WAN1: ${WAN1_IFACE}"
log_test "WAN2: ${WAN2_IFACE}"
log_test "Output: ${OUTPUT_DIR}"
if [[ "${RUN_SOAK_TEST}" == "true" ]]; then
    log_warn "Soak test enabled (${SOAK_HOURS} hours) - total runtime will be long!"
fi
log_test "=========================================="

require_root
check_required_tools || exit 1

# Create output directory
mkdir -p "${OUTPUT_DIR}"
log_test "Results will be saved to: ${OUTPUT_DIR}"

# Verify interfaces
log_test "Verifying WAN interfaces..."
check_interface ${WAN1_IFACE} || exit 1
check_interface ${WAN2_IFACE} || exit 1
log_pass "Both WAN interfaces are UP"

# Verify TQUIC module
load_tquic_module || exit 1

# Verify server connectivity
log_test "Verifying server connectivity..."
check_server_reachable ${SERVER_ADDR} ${WAN1_IFACE} || exit 1
check_server_reachable ${SERVER_ADDR} ${WAN2_IFACE} || exit 1
log_pass "Server reachable from both WANs"

# Save environment info
save_environment_info "${OUTPUT_DIR}/environment.txt"

# Test suite
declare -A TESTS
TESTS=(
    ["wan_dual_path"]="Multi-WAN Path Establishment"
    ["nat_multi_wan"]="NAT Traversal"
    ["bandwidth_aggregation"]="Bandwidth Aggregation"
    ["failover_wan_disconnect"]="WAN Failover"
)

if [[ "${RUN_SOAK_TEST}" == "true" ]]; then
    TESTS["soak_24hour"]="24-Hour Soak Test"
fi

# Results tracking
PASSED_TESTS=()
FAILED_TESTS=()
TOTAL_TESTS=${#TESTS[@]}

log_test "=========================================="
log_test "Running ${TOTAL_TESTS} test categories"
log_test "=========================================="

# Run each test
for test_name in "${!TESTS[@]}"; do
    test_desc="${TESTS[${test_name}]}"

    log_test ""
    log_test "=========================================="
    log_test "Test: ${test_desc}"
    log_test "=========================================="

    test_script="${SCRIPT_DIR}/${test_name}_test.sh"

    if [[ ! -f "${test_script}" ]]; then
        log_fail "Test script not found: ${test_script}"
        FAILED_TESTS+=("${test_desc} (missing script)")
        continue
    fi

    # Create test-specific output directory
    test_output="${OUTPUT_DIR}/${test_name}"
    mkdir -p "${test_output}"

    # Run test with timeout (except soak test)
    if [[ "${test_name}" == "soak_24hour" ]]; then
        TIMEOUT=$((SOAK_HOURS * 3600 + 600))  # Add 10min buffer
    else
        TIMEOUT=900  # 15 minutes for other tests
    fi

    START_TIME=$(date +%s)

    if timeout ${TIMEOUT} bash "${test_script}" \
        "${SERVER_ADDR}" \
        "${WAN1_IFACE}" \
        "${WAN2_IFACE}" \
        > "${test_output}/stdout.log" 2>&1; then

        END_TIME=$(date +%s)
        DURATION=$((END_TIME - START_TIME))

        log_pass "${test_desc} - PASSED (${DURATION}s)"
        PASSED_TESTS+=("${test_desc}")

        # Move test artifacts to output dir
        if [[ -d /tmp/tquic_*_test.* ]]; then
            mv /tmp/tquic_*_test.* "${test_output}/" 2>/dev/null || true
        fi
    else
        END_TIME=$(date +%s)
        DURATION=$((END_TIME - START_TIME))
        EXIT_CODE=$?

        if [[ ${EXIT_CODE} -eq 124 ]]; then
            log_fail "${test_desc} - TIMEOUT after ${TIMEOUT}s"
            FAILED_TESTS+=("${test_desc} (timeout)")
        else
            log_fail "${test_desc} - FAILED (exit code ${EXIT_CODE}, ${DURATION}s)"
            FAILED_TESTS+=("${test_desc}")
        fi

        # Save failure logs
        cat "${test_output}/stdout.log" | tail -50 > "${test_output}/failure_summary.txt"
    fi

    # Brief pause between tests
    sleep 5
done

# Final Summary
log_test ""
log_test "=========================================="
log_test "PRODUCTION TEST SUITE SUMMARY"
log_test "=========================================="
log_test "Total tests: ${TOTAL_TESTS}"
log_test "Passed: ${#PASSED_TESTS[@]}"
log_test "Failed: ${#FAILED_TESTS[@]}"
log_test ""

if [[ ${#PASSED_TESTS[@]} -gt 0 ]]; then
    log_pass "Passed tests:"
    for test in "${PASSED_TESTS[@]}"; do
        log_pass "  ✓ ${test}"
    done
fi

if [[ ${#FAILED_TESTS[@]} -gt 0 ]]; then
    log_fail "Failed tests:"
    for test in "${FAILED_TESTS[@]}"; do
        log_fail "  ✗ ${test}"
    done
fi

# Generate summary JSON
SUMMARY_FILE="${OUTPUT_DIR}/summary.json"
cat > "${SUMMARY_FILE}" <<EOF
{
    "test_suite": "tquic_production_validation",
    "timestamp": "$(date -Iseconds)",
    "server": "${SERVER_ADDR}",
    "wan1_interface": "${WAN1_IFACE}",
    "wan2_interface": "${WAN2_IFACE}",
    "total_tests": ${TOTAL_TESTS},
    "passed": ${#PASSED_TESTS[@]},
    "failed": ${#FAILED_TESTS[@]},
    "pass_rate": $(echo "scale=2; ${#PASSED_TESTS[@]} * 100 / ${TOTAL_TESTS}" | bc),
    "soak_test_included": ${RUN_SOAK_TEST},
    "results_directory": "${OUTPUT_DIR}"
}
EOF

log_test ""
log_test "Summary saved to: ${SUMMARY_FILE}"
log_test "Full results in: ${OUTPUT_DIR}"
log_test "=========================================="

# Exit code based on results
if [[ ${#FAILED_TESTS[@]} -eq 0 ]]; then
    log_pass "ALL TESTS PASSED - TQUIC WAN BONDING VALIDATED! ✅"
    exit 0
else
    log_fail "SOME TESTS FAILED - SEE SUMMARY ABOVE ❌"
    exit 1
fi
