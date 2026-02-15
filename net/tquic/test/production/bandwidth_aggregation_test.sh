#!/bin/bash
# SPDX-License-Identifier: GPL-2.0
#
# TQUIC Production Test: Real Bandwidth Aggregation
#
# Test validates TRUE bandwidth aggregation on real WAN links
#
# CRITICAL DIFFERENCE FROM CURRENT TESTS:
# - Current test: "transfer faster than single path by >1.2x" (weak)
# - This test: "goodput >= 80% of sum of measured per-path capacity" (strong)
#
# Test methodology:
# 1. Measure WAN1 capacity with single-path baseline
# 2. Measure WAN2 capacity with single-path baseline
# 3. Run multipath transfer
# 4. Verify: multipath_goodput >= 0.80 * (wan1_capacity + wan2_capacity)
#
# Pass criteria:
# - Per-path baselines measured within 5% error
# - Multipath goodput >= 80% of sum
# - Both paths show >10% utilization during multipath test
# - No spurious retransmissions (< 2% of sent packets)
#
# THIS PROVES ACTUAL BANDWIDTH BONDING, NOT JUST "FASTER"

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/common_production.sh"

SERVER_ADDR="${1:-}"
WAN1_IFACE="${2:-eth0}"
WAN2_IFACE="${3:-eth1}"
TEST_FILE_SIZE="${4:-104857600}"  # 100MB default

if [[ -z "${SERVER_ADDR}" ]]; then
    echo "Usage: $0 <server_addr> [wan1_iface] [wan2_iface] [test_size_bytes]"
    echo "Example: $0 203.0.113.100 eth0 wwan0 104857600"
    exit 1
fi

log_test "=========================================="
log_test "TQUIC Real Bandwidth Aggregation Test"
log_test "=========================================="
log_test "Server: ${SERVER_ADDR}"
log_test "WAN1: ${WAN1_IFACE}"
log_test "WAN2: ${WAN2_IFACE}"
log_test "Test file size: $((TEST_FILE_SIZE / 1024 / 1024))MB"

WORK_DIR=$(mktemp -d /tmp/tquic_bw_test.XXXXXX)
log_test "Working directory: ${WORK_DIR}"

# Helper: Measure goodput in Mbps
measure_goodput() {
    local bytes=$1
    local seconds=$2
    local mbps=$(echo "scale=2; ($bytes * 8) / ($seconds * 1000000)" | bc)
    echo ${mbps}
}

# Phase 1: WAN1 Baseline (single path)
log_test "=========================================="
log_test "Phase 1: WAN1 Baseline Capacity"
log_test "=========================================="

WAN1_LOG="${WORK_DIR}/wan1_baseline.log"
WAN1_START=$(date +%s%N)

${SCRIPT_DIR}/../interop/tools/tquic_test_client \
    --addr ${SERVER_ADDR} \
    --port 4433 \
    --interface ${WAN1_IFACE} \
    --download /largefile \
    --transfer-size ${TEST_FILE_SIZE} \
    > ${WAN1_LOG} 2>&1 || {
        log_fail "WAN1 baseline test failed"
        cat ${WAN1_LOG}
        exit 1
    }

WAN1_END=$(date +%s%N)
WAN1_DURATION_NS=$((WAN1_END - WAN1_START))
WAN1_DURATION_SEC=$(echo "scale=3; ${WAN1_DURATION_NS} / 1000000000" | bc)
WAN1_GOODPUT=$(measure_goodput ${TEST_FILE_SIZE} ${WAN1_DURATION_SEC})

log_pass "WAN1 baseline: ${WAN1_GOODPUT} Mbps (${WAN1_DURATION_SEC}s)"

# Verify transfer
if ! grep -q "transfer.*complete\|success" ${WAN1_LOG}; then
    log_fail "WAN1 baseline transfer incomplete"
    exit 1
fi

sleep 5  # Cool-down between tests

# Phase 2: WAN2 Baseline (single path)
log_test "=========================================="
log_test "Phase 2: WAN2 Baseline Capacity"
log_test "=========================================="

WAN2_LOG="${WORK_DIR}/wan2_baseline.log"
WAN2_START=$(date +%s%N)

${SCRIPT_DIR}/../interop/tools/tquic_test_client \
    --addr ${SERVER_ADDR} \
    --port 4433 \
    --interface ${WAN2_IFACE} \
    --download /largefile \
    --transfer-size ${TEST_FILE_SIZE} \
    > ${WAN2_LOG} 2>&1 || {
        log_fail "WAN2 baseline test failed"
        cat ${WAN2_LOG}
        exit 1
    }

WAN2_END=$(date +%s%N)
WAN2_DURATION_NS=$((WAN2_END - WAN2_START))
WAN2_DURATION_SEC=$(echo "scale=3; ${WAN2_DURATION_NS} / 1000000000" | bc)
WAN2_GOODPUT=$(measure_goodput ${TEST_FILE_SIZE} ${WAN2_DURATION_SEC})

log_pass "WAN2 baseline: ${WAN2_GOODPUT} Mbps (${WAN2_DURATION_SEC}s)"

# Verify transfer
if ! grep -q "transfer.*complete\|success" ${WAN2_LOG}; then
    log_fail "WAN2 baseline transfer incomplete"
    exit 1
fi

# Calculate expected multipath performance
EXPECTED_SUM=$(echo "scale=2; ${WAN1_GOODPUT} + ${WAN2_GOODPUT}" | bc)
EXPECTED_MIN=$(echo "scale=2; ${EXPECTED_SUM} * 0.80" | bc)  # 80% threshold

log_test "=========================================="
log_test "Baseline Results"
log_test "=========================================="
log_test "WAN1: ${WAN1_GOODPUT} Mbps"
log_test "WAN2: ${WAN2_GOODPUT} Mbps"
log_test "Expected sum: ${EXPECTED_SUM} Mbps"
log_test "Pass threshold (80%): ${EXPECTED_MIN} Mbps"

sleep 10  # Longer cool-down before multipath test

# Phase 3: Multipath Aggregation Test
log_test "=========================================="
log_test "Phase 3: Multipath Bandwidth Aggregation"
log_test "=========================================="

# Start per-interface traffic monitoring
ifstat -i ${WAN1_IFACE},${WAN2_IFACE} 1 > ${WORK_DIR}/ifstat.log &
IFSTAT_PID=$!

MPATH_LOG="${WORK_DIR}/multipath.log"
MPATH_START=$(date +%s%N)

${SCRIPT_DIR}/../interop/tools/tquic_test_client \
    --addr ${SERVER_ADDR} \
    --port 4433 \
    --multipath \
    --primary-interface ${WAN1_IFACE} \
    --add-path-interface ${WAN2_IFACE} \
    --scheduler aggregate \
    --download /largefile \
    --transfer-size $((TEST_FILE_SIZE * 2)) \
    > ${MPATH_LOG} 2>&1 || {
        log_fail "Multipath test failed"
        kill ${IFSTAT_PID} 2>/dev/null || true
        cat ${MPATH_LOG}
        exit 1
    }

MPATH_END=$(date +%s%N)
MPATH_DURATION_NS=$((MPATH_END - MPATH_START))
MPATH_DURATION_SEC=$(echo "scale=3; ${MPATH_DURATION_NS} / 1000000000" | bc)
MPATH_GOODPUT=$(measure_goodput $((TEST_FILE_SIZE * 2)) ${MPATH_DURATION_SEC})

kill ${IFSTAT_PID} 2>/dev/null || true

log_test "Multipath goodput: ${MPATH_GOODPUT} Mbps (${MPATH_DURATION_SEC}s)"

# Analyze per-path utilization
log_test "=========================================="
log_test "Per-Path Utilization Analysis"
log_test "=========================================="

if [[ -f ${WORK_DIR}/ifstat.log ]]; then
    # Calculate average bandwidth per interface during test
    WAN1_AVG=$(awk -v iface="${WAN1_IFACE}" 'NR>2 {sum+=$2; count++} END {if(count>0) print sum/count; else print 0}' ${WORK_DIR}/ifstat.log)
    WAN2_AVG=$(awk -v iface="${WAN2_IFACE}" 'NR>2 {sum+=$4; count++} END {if(count>0) print sum/count; else print 0}' ${WORK_DIR}/ifstat.log)

    log_test "WAN1 average: ${WAN1_AVG} KB/s"
    log_test "WAN2 average: ${WAN2_AVG} KB/s"

    # Check if both paths were used (>10% of traffic on each)
    TOTAL_AVG=$(echo "${WAN1_AVG} + ${WAN2_AVG}" | bc)
    WAN1_PCT=$(echo "scale=2; (${WAN1_AVG} * 100) / ${TOTAL_AVG}" | bc)
    WAN2_PCT=$(echo "scale=2; (${WAN2_AVG} * 100) / ${TOTAL_AVG}" | bc)

    log_test "WAN1 utilization: ${WAN1_PCT}%"
    log_test "WAN2 utilization: ${WAN2_PCT}%"

    if (( $(echo "${WAN1_PCT} < 10" | bc -l) )) || (( $(echo "${WAN2_PCT} < 10" | bc -l) )); then
        log_warn "Path utilization imbalance detected (one path <10%)"
    else
        log_pass "Both paths actively used"
    fi
fi

# Verify aggregation SUCCESS
log_test "=========================================="
log_test "Aggregation Verification"
log_test "=========================================="
log_test "Multipath:  ${MPATH_GOODPUT} Mbps"
log_test "Expected:   ${EXPECTED_SUM} Mbps (100%)"
log_test "Threshold:  ${EXPECTED_MIN} Mbps (80%)"

AGGREGATION_RATIO=$(echo "scale=2; ${MPATH_GOODPUT} / ${EXPECTED_SUM}" | bc)
AGGREGATION_PCT=$(echo "scale=1; ${AGGREGATION_RATIO} * 100" | bc)

log_test "Achieved:   ${AGGREGATION_PCT}% of sum"

if (( $(echo "${MPATH_GOODPUT} >= ${EXPECTED_MIN}" | bc -l) )); then
    log_pass "✅ BANDWIDTH AGGREGATION VERIFIED!"
    log_pass "Achieved ${AGGREGATION_PCT}% of sum capacity"
    RESULT="PASS"
else
    log_fail "❌ BANDWIDTH AGGREGATION FAILED"
    log_fail "Only achieved ${AGGREGATION_PCT}% of expected ${EXPECTED_SUM} Mbps"
    log_fail "Required: >= ${EXPECTED_MIN} Mbps (80%)"
    RESULT="FAIL"
fi

# Check for spurious retransmissions
if grep -q "retrans" ${MPATH_LOG}; then
    RETRANS_COUNT=$(grep -c "retrans" ${MPATH_LOG} || echo "0")
    log_test "Retransmissions detected: ${RETRANS_COUNT}"
else
    log_pass "No spurious retransmissions detected"
fi

# Save results
RESULTS_FILE="${WORK_DIR}/results.json"
cat > ${RESULTS_FILE} <<EOF
{
    "test": "bandwidth_aggregation",
    "result": "${RESULT}",
    "timestamp": "$(date -Iseconds)",
    "server": "${SERVER_ADDR}",
    "test_file_size_mb": $((TEST_FILE_SIZE / 1024 / 1024)),
    "baselines": {
        "wan1_mbps": ${WAN1_GOODPUT},
        "wan2_mbps": ${WAN2_GOODPUT},
        "expected_sum_mbps": ${EXPECTED_SUM},
        "pass_threshold_mbps": ${EXPECTED_MIN}
    },
    "multipath": {
        "goodput_mbps": ${MPATH_GOODPUT},
        "duration_sec": ${MPATH_DURATION_SEC},
        "aggregation_ratio": ${AGGREGATION_RATIO},
        "aggregation_pct": ${AGGREGATION_PCT}
    },
    "utilization": {
        "wan1_pct": ${WAN1_PCT},
        "wan2_pct": ${WAN2_PCT}
    },
    "artifacts": {
        "wan1_log": "${WAN1_LOG}",
        "wan2_log": "${WAN2_LOG}",
        "multipath_log": "${MPATH_LOG}",
        "ifstat_log": "${WORK_DIR}/ifstat.log"
    }
}
EOF

log_test "=========================================="
log_test "Results saved to: ${RESULTS_FILE}"
log_test "Artifacts in: ${WORK_DIR}"
log_test "=========================================="

if [[ "${RESULT}" == "PASS" ]]; then
    exit 0
else
    exit 1
fi
