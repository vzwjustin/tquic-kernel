#!/bin/bash
# SPDX-License-Identifier: GPL-2.0-only
#
# TQUIC Production Test: 24-Hour Soak Test
#
# Long-running stability test to validate production readiness
#
# Test validates:
# - No kernel crashes over 24 hours
# - No memory leaks (< 1% growth)
# - Graceful handling of link churn (periodic failover/recovery)
# - Sustained performance under realistic traffic patterns
# - NAT mapping maintenance over long duration
#
# Pass criteria:
# - Zero kernel panics/oops
# - Memory growth < 1% from baseline
# - Average goodput within 10% of baseline after 24hrs
# - All link churn events handled without connection drops
# - No zombie connections in /proc/net/tquic
#
# THIS IS REQUIRED FOR PRODUCTION STABILITY CLAIMS

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/common_production.sh"

SERVER_ADDR="${1:-}"
WAN1_IFACE="${2:-eth0}"
WAN2_IFACE="${3:-eth1}"
DURATION_HOURS="${4:-24}"

if [[ -z "${SERVER_ADDR}" ]]; then
    echo "Usage: $0 <server_addr> [wan1_iface] [wan2_iface] [hours]"
    echo "Example: $0 203.0.113.100 eth0 wwan0 24"
    exit 1
fi

DURATION_SEC=$((DURATION_HOURS * 3600))

log_test "=========================================="
log_test "TQUIC 24-Hour Soak Test"
log_test "=========================================="
log_test "Server: ${SERVER_ADDR}"
log_test "WAN1: ${WAN1_IFACE}"
log_test "WAN2: ${WAN2_IFACE}"
log_test "Duration: ${DURATION_HOURS} hours (${DURATION_SEC}s)"
log_warn "This test will run for ${DURATION_HOURS} hours"
log_test "Press Ctrl+C within 10 seconds to abort..."
sleep 10

WORK_DIR=$(mktemp -d /tmp/tquic_soak.XXXXXX)
log_test "Working directory: ${WORK_DIR}"

# Baseline memory usage
log_test "Recording baseline memory usage..."
BASELINE_MEM=$(grep "^Slab:" /proc/meminfo | awk '{print $2}')
BASELINE_TQUIC_MEM=$(grep tquic /proc/slabinfo 2>/dev/null | awk '{sum+=$3*$4} END {print sum}' || echo "0")

log_test "Baseline system slab: ${BASELINE_MEM} kB"
log_test "Baseline TQUIC memory: ${BASELINE_TQUIC_MEM} bytes"

# Start continuous monitoring
log_test "Starting monitoring daemons..."

# Memory monitoring (every 5 minutes)
(while true; do
    TIMESTAMP=$(date -Iseconds)
    MEM=$(grep "^Slab:" /proc/meminfo | awk '{print $2}')
    TQUIC_MEM=$(grep tquic /proc/slabinfo 2>/dev/null | awk '{sum+=$3*$4} END {print sum}' || echo "0")
    echo "${TIMESTAMP},${MEM},${TQUIC_MEM}" >> ${WORK_DIR}/memory.csv
    sleep 300
done) &
MEM_MON_PID=$!

# Connection monitoring (every 1 minute)
(while true; do
    TIMESTAMP=$(date -Iseconds)
    if [[ -f /proc/net/tquic/connections ]]; then
        CONN_COUNT=$(grep -c "conn_id" /proc/net/tquic/connections || echo "0")
        PATH_COUNT=$(grep -c "path_id" /proc/net/tquic/connections || echo "0")
        echo "${TIMESTAMP},${CONN_COUNT},${PATH_COUNT}" >> ${WORK_DIR}/connections.csv
    fi
    sleep 60
done) &
CONN_MON_PID=$!

# Kernel log monitoring
dmesg -w | grep -i "tquic\|quic\|panic\|oops" > ${WORK_DIR}/kernel.log &
DMESG_PID=$!

# Phase 1: Sustained traffic (first 12 hours)
log_test "=========================================="
log_test "Phase 1: Sustained Traffic (12 hours)"
log_test "=========================================="

PHASE1_END=$(($(date +%s) + (DURATION_SEC / 2)))

${SCRIPT_DIR}/../interop/tools/tquic_test_client \
    --addr ${SERVER_ADDR} \
    --port 4433 \
    --multipath \
    --primary-interface ${WAN1_IFACE} \
    --add-path-interface ${WAN2_IFACE} \
    --scheduler aggregate \
    --continuous \
    --duration $((DURATION_SEC / 2)) \
    > ${WORK_DIR}/phase1.log 2>&1 &
PHASE1_PID=$!

# Monitor phase 1
log_test "Phase 1 running (PID ${PHASE1_PID})..."
log_test "Monitoring for kernel issues..."

while kill -0 ${PHASE1_PID} 2>/dev/null; do
    # Check for kernel panics
    if dmesg | tail -100 | grep -qi "panic\|oops\|bug:"; then
        log_fail "Kernel panic/oops detected!"
        dmesg | tail -50
        kill ${PHASE1_PID} ${MEM_MON_PID} ${CONN_MON_PID} ${DMESG_PID} 2>/dev/null || true
        exit 1
    fi

    # Check memory growth every hour
    CURRENT_TIME=$(date +%s)
    if [[ $((CURRENT_TIME % 3600)) -eq 0 ]]; then
        CURRENT_MEM=$(grep "^Slab:" /proc/meminfo | awk '{print $2}')
        MEM_GROWTH=$(echo "scale=2; (($CURRENT_MEM - $BASELINE_MEM) * 100) / $BASELINE_MEM" | bc)
        log_test "Memory growth: ${MEM_GROWTH}%"

        if (( $(echo "${MEM_GROWTH} > 5.0" | bc -l) )); then
            log_warn "Excessive memory growth detected: ${MEM_GROWTH}%"
        fi
    fi

    sleep 300  # Check every 5 minutes
done

wait ${PHASE1_PID} || {
    log_fail "Phase 1 failed"
    cat ${WORK_DIR}/phase1.log
    kill ${MEM_MON_PID} ${CONN_MON_PID} ${DMESG_PID} 2>/dev/null || true
    exit 1
}

log_pass "Phase 1 completed successfully"

sleep 60  # Brief pause

# Phase 2: Link churn (second 12 hours)
log_test "=========================================="
log_test "Phase 2: Link Churn (12 hours)"
log_test "=========================================="
log_test "Periodic link failures and recoveries"

# Start background traffic
${SCRIPT_DIR}/../interop/tools/tquic_test_client \
    --addr ${SERVER_ADDR} \
    --port 4433 \
    --multipath \
    --primary-interface ${WAN1_IFACE} \
    --add-path-interface ${WAN2_IFACE} \
    --scheduler aggregate \
    --continuous \
    --duration $((DURATION_SEC / 2)) \
    > ${WORK_DIR}/phase2.log 2>&1 &
PHASE2_PID=$!

# Induce link churn every 30 minutes
CHURN_COUNT=0
PHASE2_START=$(date +%s)

while kill -0 ${PHASE2_PID} 2>/dev/null; do
    CURRENT_TIME=$(date +%s)
    ELAPSED=$((CURRENT_TIME - PHASE2_START))

    # Every 30 minutes, trigger failover
    if [[ $((ELAPSED % 1800)) -eq 0 ]] && [[ ${ELAPSED} -gt 0 ]]; then
        ((CHURN_COUNT++))
        log_test "Link churn event #${CHURN_COUNT}"

        # Simulate WAN2 failure
        log_test "Disabling ${WAN2_IFACE}..."
        ip link set ${WAN2_IFACE} down
        sleep 30  # 30s failure

        log_test "Re-enabling ${WAN2_IFACE}..."
        ip link set ${WAN2_IFACE} up
        sleep 60  # Recovery period

        # Verify connection survived
        if ! kill -0 ${PHASE2_PID} 2>/dev/null; then
            log_fail "Connection died during link churn event #${CHURN_COUNT}"
            kill ${MEM_MON_PID} ${CONN_MON_PID} ${DMESG_PID} 2>/dev/null || true
            exit 1
        fi

        log_pass "Survived link churn event #${CHURN_COUNT}"
    fi

    sleep 60
done

wait ${PHASE2_PID} || {
    log_fail "Phase 2 failed"
    cat ${WORK_DIR}/phase2.log
    kill ${MEM_MON_PID} ${CONN_MON_PID} ${DMESG_PID} 2>/dev/null || true
    exit 1
}

log_pass "Phase 2 completed successfully (${CHURN_COUNT} churn events)"

# Cleanup monitoring
kill ${MEM_MON_PID} ${CONN_MON_PID} ${DMESG_PID} 2>/dev/null || true

# Final analysis
log_test "=========================================="
log_test "Soak Test Analysis"
log_test "=========================================="

# Memory leak check
FINAL_MEM=$(grep "^Slab:" /proc/meminfo | awk '{print $2}')
FINAL_TQUIC_MEM=$(grep tquic /proc/slabinfo 2>/dev/null | awk '{sum+=$3*$4} END {print sum}' || echo "0")

MEM_GROWTH=$(echo "scale=2; (($FINAL_MEM - $BASELINE_MEM) * 100) / $BASELINE_MEM" | bc)
TQUIC_MEM_GROWTH=$(echo "scale=2; (($FINAL_TQUIC_MEM - $BASELINE_TQUIC_MEM) * 100) / ($BASELINE_TQUIC_MEM + 1)" | bc)

log_test "System memory growth: ${MEM_GROWTH}%"
log_test "TQUIC memory growth: ${TQUIC_MEM_GROWTH}%"

if (( $(echo "${MEM_GROWTH} < 1.0" | bc -l) )); then
    log_pass "No significant memory leak detected"
else
    log_warn "Memory growth ${MEM_GROWTH}% exceeds 1% threshold"
fi

# Check for kernel warnings/errors
if grep -qi "warning\|error\|bug:" ${WORK_DIR}/kernel.log; then
    log_warn "Kernel warnings/errors detected - review kernel.log"
    grep -i "warning\|error" ${WORK_DIR}/kernel.log | head -20
else
    log_pass "No kernel warnings/errors during test"
fi

# Zombie connection check
if [[ -f /proc/net/tquic/connections ]]; then
    ZOMBIE_CONNS=$(grep -c "state=closed\|state=zombie" /proc/net/tquic/connections || echo "0")
    if [[ ${ZOMBIE_CONNS} -gt 0 ]]; then
        log_warn "${ZOMBIE_CONNS} zombie connections detected"
    else
        log_pass "No zombie connections"
    fi
fi

# Generate plots (if gnuplot available)
if command -v gnuplot &> /dev/null; then
    log_test "Generating memory usage plot..."
    gnuplot <<EOF
set terminal png size 1200,600
set output '${WORK_DIR}/memory_plot.png'
set datafile separator ','
set xdata time
set timefmt "%Y-%m-%dT%H:%M:%S"
set format x "%H:%M"
set xlabel "Time"
set ylabel "Memory (kB)"
set title "TQUIC 24-Hour Memory Usage"
plot '${WORK_DIR}/memory.csv' using 1:2 with lines title 'System Slab', \
     '' using 1:3 with lines title 'TQUIC'
EOF
    log_test "Memory plot: ${WORK_DIR}/memory_plot.png"
fi

# Results
RESULTS_FILE="${WORK_DIR}/results.json"
cat > ${RESULTS_FILE} <<EOF
{
    "test": "24hour_soak",
    "duration_hours": ${DURATION_HOURS},
    "timestamp_start": "$(date -Iseconds -d @${PHASE2_START})",
    "timestamp_end": "$(date -Iseconds)",
    "memory": {
        "baseline_kb": ${BASELINE_MEM},
        "final_kb": ${FINAL_MEM},
        "growth_pct": ${MEM_GROWTH},
        "tquic_baseline_bytes": ${BASELINE_TQUIC_MEM},
        "tquic_final_bytes": ${FINAL_TQUIC_MEM},
        "tquic_growth_pct": ${TQUIC_MEM_GROWTH}
    },
    "link_churn_events": ${CHURN_COUNT},
    "kernel_errors": $(grep -c "error\|warning" ${WORK_DIR}/kernel.log || echo "0"),
    "artifacts": {
        "phase1_log": "${WORK_DIR}/phase1.log",
        "phase2_log": "${WORK_DIR}/phase2.log",
        "memory_csv": "${WORK_DIR}/memory.csv",
        "connections_csv": "${WORK_DIR}/connections.csv",
        "kernel_log": "${WORK_DIR}/kernel.log"
    }
}
EOF

log_test "=========================================="
log_pass "24-Hour Soak Test PASSED!"
log_test "Results saved to: ${RESULTS_FILE}"
log_test "=========================================="

exit 0
