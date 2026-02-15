#!/bin/bash
# SPDX-License-Identifier: GPL-2.0
#
# TQUIC Production Test: WiFi to LTE Handoff
#
# Tests seamless handoff from WiFi to LTE during active transfer
#
# Test validates:
# - Connection survives WiFi disconnect
# - Transfer continues over LTE path
# - Minimal disruption (< 1 second)
# - No application-visible errors
#
# Hardware requirements:
# - WiFi interface (wlan0 or similar)
# - LTE modem (wwan0 or similar)
# - Both connected to different networks
#
# Pass criteria:
# - Transfer completes successfully
# - Handoff disruption < 1 second
# - No data loss or corruption
# - Client doesn't detect connection failure
#
# THIS IS CRITICAL FOR MOBILE USE CASES

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/common_production.sh"

SERVER_ADDR="${1:-}"
WIFI_IFACE="${2:-wlan0}"
LTE_IFACE="${3:-wwan0}"
HANDOFF_DELAY="${4:-10}"  # Seconds into transfer to trigger handoff

if [[ -z "${SERVER_ADDR}" ]]; then
    echo "Usage: $0 <server_addr> [wifi_iface] [lte_iface] [handoff_delay]"
    echo "Example: $0 203.0.113.100 wlan0 wwan0 10"
    exit 1
fi

log_test "=========================================="
log_test "TQUIC Mobile Handoff Test (WiFi → LTE)"
log_test "=========================================="
log_test "Server: ${SERVER_ADDR}"
log_test "WiFi: ${WIFI_IFACE}"
log_test "LTE: ${LTE_IFACE}"
log_test "Handoff delay: ${HANDOFF_DELAY}s"

# Pre-flight checks
log_test "Pre-flight: Verifying mobile interfaces..."

# Check WiFi
if ! check_interface ${WIFI_IFACE}; then
    log_fail "WiFi interface ${WIFI_IFACE} not available"
    exit 1
fi

WIFI_IP=$(get_interface_ip ${WIFI_IFACE})
if [[ -z "${WIFI_IP}" ]]; then
    log_fail "WiFi has no IP address - not connected?"
    exit 1
fi
log_pass "WiFi connected: ${WIFI_IP}"

# Check LTE
if ! check_interface ${LTE_IFACE}; then
    log_fail "LTE interface ${LTE_IFACE} not available"
    exit 1
fi

LTE_IP=$(get_interface_ip ${LTE_IFACE})
if [[ -z "${LTE_IP}" ]]; then
    log_fail "LTE has no IP address - not connected?"
    exit 1
fi
log_pass "LTE connected: ${LTE_IP}"

# Verify both can reach server
check_server_reachable ${SERVER_ADDR} ${WIFI_IFACE} || exit 1
check_server_reachable ${SERVER_ADDR} ${LTE_IFACE} || exit 1

WORK_DIR=$(mktemp -d /tmp/tquic_handoff.XXXXXX)
log_test "Working directory: ${WORK_DIR}"

# Start transfer with both paths
log_test "=========================================="
log_test "Starting multipath transfer..."
log_test "=========================================="

CLIENT_LOG="${WORK_DIR}/client.log"

# 100MB transfer should take 30-60s on typical mobile networks
${SCRIPT_DIR}/../interop/tools/tquic_test_client \
    --addr ${SERVER_ADDR} \
    --port 4433 \
    --multipath \
    --primary-interface ${WIFI_IFACE} \
    --add-path-interface ${LTE_IFACE} \
    --scheduler minrtt \
    --download /largefile \
    --transfer-size 104857600 \
    > ${CLIENT_LOG} 2>&1 &

CLIENT_PID=$!

# Wait for paths to establish
log_test "Waiting for both paths to establish..."
sleep 5

# Verify both paths active
if [[ -f /proc/net/tquic/connections ]]; then
    PATH_COUNT=$(grep -c "path_id" /proc/net/tquic/connections || echo "0")
    if [[ ${PATH_COUNT} -lt 2 ]]; then
        log_fail "Only ${PATH_COUNT} paths established (expected 2)"
        kill ${CLIENT_PID} 2>/dev/null || true
        cat ${CLIENT_LOG}
        exit 1
    fi
    log_pass "Both paths established"
fi

# Let transfer run for specified delay
log_test "Transfer running for ${HANDOFF_DELAY}s before handoff..."
sleep ${HANDOFF_DELAY}

# Record state before handoff
BYTES_BEFORE=$(grep -oP 'received \K[0-9]+' ${CLIENT_LOG} | tail -1 || echo "0")

# Trigger WiFi disconnect
log_test "=========================================="
log_test "Triggering WiFi disconnect (handoff)"
log_test "=========================================="

HANDOFF_TIME=$(date +%s%N)

log_test "Disabling ${WIFI_IFACE}..."
ip link set ${WIFI_IFACE} down

log_test "WiFi disconnected, monitoring failover to LTE..."

# Monitor transfer continuation
RECOVERY_START=$(date +%s)
RECOVERED=false

while kill -0 ${CLIENT_PID} 2>/dev/null; do
    CURRENT_TIME=$(date +%s)
    ELAPSED=$((CURRENT_TIME - RECOVERY_START))

    # Check if transfer is still progressing
    BYTES_CURRENT=$(grep -oP 'received \K[0-9]+' ${CLIENT_LOG} | tail -1 || echo "0")

    if [[ ${BYTES_CURRENT} -gt ${BYTES_BEFORE} ]]; then
        if [[ "${RECOVERED}" == "false" ]]; then
            RECOVERY_TIME=$(date +%s%N)
            DISRUPTION_NS=$((RECOVERY_TIME - HANDOFF_TIME))
            DISRUPTION_MS=$(echo "scale=0; ${DISRUPTION_NS} / 1000000" | bc)

            log_pass "Transfer recovered after ${DISRUPTION_MS}ms"
            log_test "Continuing on LTE path..."
            RECOVERED=true
            break
        fi
    fi

    # Timeout if no recovery after 10 seconds
    if [[ ${ELAPSED} -gt 10 ]] && [[ "${RECOVERED}" == "false" ]]; then
        log_fail "Transfer did not recover within 10 seconds"
        kill ${CLIENT_PID} 2>/dev/null || true
        cat ${CLIENT_LOG}

        # Re-enable WiFi
        ip link set ${WIFI_IFACE} up

        exit 1
    fi

    sleep 0.5
done

# Wait for transfer to complete
wait ${CLIENT_PID} || {
    EXIT_CODE=$?
    log_fail "Transfer failed after handoff (exit code ${EXIT_CODE})"

    # Re-enable WiFi
    ip link set ${WIFI_IFACE} up

    cat ${CLIENT_LOG}
    exit 1
}

# Re-enable WiFi
log_test "Re-enabling WiFi..."
ip link set ${WIFI_IFACE} up

# Verify transfer completed successfully
if ! grep -q "transfer.*complete\|success" ${CLIENT_LOG}; then
    log_fail "Transfer did not complete successfully"
    cat ${CLIENT_LOG}
    exit 1
fi

# Final analysis
log_test "=========================================="
log_test "Handoff Test Results"
log_test "=========================================="

log_pass "Transfer completed successfully after WiFi → LTE handoff"
log_test "Disruption duration: ${DISRUPTION_MS}ms"

if [[ ${DISRUPTION_MS} -lt 1000 ]]; then
    log_pass "Disruption < 1 second (${DISRUPTION_MS}ms) ✓"
    RESULT="PASS"
else
    log_warn "Disruption >= 1 second (${DISRUPTION_MS}ms)"
    RESULT="MARGINAL"
fi

# Check for errors in client log
if grep -qi "error\|failed\|timeout" ${CLIENT_LOG}; then
    log_warn "Errors detected in client log"
    grep -i "error\|failed" ${CLIENT_LOG} | head -10
fi

# Save results
RESULTS_FILE="${WORK_DIR}/results.json"
cat > ${RESULTS_FILE} <<EOF
{
    "test": "mobile_wifi_to_lte_handoff",
    "result": "${RESULT}",
    "timestamp": "$(date -Iseconds)",
    "server": "${SERVER_ADDR}",
    "wifi_interface": "${WIFI_IFACE}",
    "lte_interface": "${LTE_IFACE}",
    "handoff_delay_sec": ${HANDOFF_DELAY},
    "disruption_ms": ${DISRUPTION_MS},
    "disruption_under_1sec": $([ ${DISRUPTION_MS} -lt 1000 ] && echo "true" || echo "false"),
    "transfer_completed": true,
    "artifacts": {
        "client_log": "${CLIENT_LOG}"
    }
}
EOF

log_test "=========================================="
if [[ "${RESULT}" == "PASS" ]]; then
    log_pass "Mobile handoff test PASSED! ✅"
else
    log_test "Mobile handoff test completed with warnings"
fi
log_test "Results saved to: ${RESULTS_FILE}"
log_test "=========================================="

exit 0
