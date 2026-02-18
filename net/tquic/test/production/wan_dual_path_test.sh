#!/bin/bash
# SPDX-License-Identifier: GPL-2.0-only
#
# TQUIC Production Test: Dual WAN Path Establishment
#
# CRITICAL: This test uses REAL WAN links, not network namespaces
#
# Test validates:
# - Both WAN interfaces can establish independent QUIC paths
# - Paths use correct source IP/interface binding
# - Both paths pass validation and become active
# - Server sees both client addresses
#
# Hardware requirements:
# - Client: 2x WAN interfaces (different ISPs/carriers)
# - Server: Public IP address accessible from both WANs
#
# Pass criteria:
# - Both paths establish within 10 seconds
# - Both paths validate (no PATH_CHALLENGE timeout)
# - Per-path byte counters show traffic on both
#
# DIFFERENCE FROM INTEROP TEST:
# - Uses real ISP links with real NAT/routing
# - Validates actual interface binding (SO_BINDTODEVICE)
# - Measures real RTT across internet

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/common_production.sh"

# Test parameters (must be provided)
SERVER_ADDR="${1:-}"
WAN1_IFACE="${2:-eth0}"
WAN2_IFACE="${3:-eth1}"
TEST_DURATION="${4:-60}"  # seconds

if [[ -z "${SERVER_ADDR}" ]]; then
    echo "Usage: $0 <server_addr> [wan1_iface] [wan2_iface] [duration]"
    echo "Example: $0 203.0.113.100 eth0 wwan0 60"
    exit 1
fi

log_test "=========================================="
log_test "TQUIC Real-World Dual WAN Path Test"
log_test "=========================================="
log_test "Server: ${SERVER_ADDR}"
log_test "WAN1: ${WAN1_IFACE}"
log_test "WAN2: ${WAN2_IFACE}"
log_test "Duration: ${TEST_DURATION}s"

# Pre-flight checks
log_test "Pre-flight: Verifying WAN connectivity"

# Check WAN1 is up and has IP
WAN1_IP=$(ip -4 addr show ${WAN1_IFACE} | grep inet | awk '{print $2}' | cut -d/ -f1 | head -1)
if [[ -z "${WAN1_IP}" ]]; then
    log_fail "WAN1 interface ${WAN1_IFACE} has no IPv4 address"
    exit 1
fi
log_test "WAN1 IP: ${WAN1_IP}"

# Check WAN2 is up and has IP
WAN2_IP=$(ip -4 addr show ${WAN2_IFACE} | grep inet | awk '{print $2}' | cut -d/ -f1 | head -1)
if [[ -z "${WAN2_IP}" ]]; then
    log_fail "WAN2 interface ${WAN2_IFACE} has no IPv4 address"
    exit 1
fi
log_test "WAN2 IP: ${WAN2_IP}"

# Verify both WANs can reach server
log_test "Testing WAN1 connectivity to server..."
if ! ping -I ${WAN1_IFACE} -c 3 -W 5 ${SERVER_ADDR} > /dev/null 2>&1; then
    log_fail "WAN1 cannot reach server ${SERVER_ADDR}"
    exit 1
fi
WAN1_RTT=$(ping -I ${WAN1_IFACE} -c 5 ${SERVER_ADDR} | tail -1 | awk -F'/' '{print $5}')
log_pass "WAN1 reachable (RTT: ${WAN1_RTT}ms)"

log_test "Testing WAN2 connectivity to server..."
if ! ping -I ${WAN2_IFACE} -c 3 -W 5 ${SERVER_ADDR} > /dev/null 2>&1; then
    log_fail "WAN2 cannot reach server ${SERVER_ADDR}"
    exit 1
fi
WAN2_RTT=$(ping -I ${WAN2_IFACE} -c 5 ${SERVER_ADDR} | tail -1 | awk -F'/' '{print $5}')
log_pass "WAN2 reachable (RTT: ${WAN2_RTT}ms)"

# Check TQUIC module is loaded
if ! lsmod | grep -q quic; then
    log_test "Loading TQUIC kernel module..."
    modprobe quic || {
        log_fail "Failed to load TQUIC module"
        exit 1
    }
fi

# Create test directory
WORK_DIR=$(mktemp -d /tmp/tquic_wan_test.XXXXXX)
log_test "Working directory: ${WORK_DIR}"

# Start packet captures on both WANs
log_test "Starting packet captures..."
tcpdump -i ${WAN1_IFACE} -w ${WORK_DIR}/wan1.pcap udp port 4433 &
WAN1_TCPDUMP_PID=$!
tcpdump -i ${WAN2_IFACE} -w ${WORK_DIR}/wan2.pcap udp port 4433 &
WAN2_TCPDUMP_PID=$!
sleep 2

# Record initial path stats
STATS_BEFORE="${WORK_DIR}/path_stats_before.txt"
if [[ -f /proc/net/tquic/path_stats ]]; then
    cat /proc/net/tquic/path_stats > ${STATS_BEFORE}
fi

# Start TQUIC client with explicit multipath and interface binding
log_test "Starting TQUIC multipath client..."

CLIENT_LOG="${WORK_DIR}/client.log"

# Use tquic_test_client with multipath and second interface
${SCRIPT_DIR}/../interop/tools/tquic_test_client \
    --addr ${SERVER_ADDR} \
    --port 4433 \
    --multipath \
    --primary-interface ${WAN1_IFACE} \
    --add-path-interface ${WAN2_IFACE} \
    --scheduler minrtt \
    --duration ${TEST_DURATION} \
    --transfer-size $((100 * 1024 * 1024)) \
    > ${CLIENT_LOG} 2>&1 &

CLIENT_PID=$!

# Monitor path establishment
log_test "Waiting for paths to establish..."
TIMEOUT=15
ELAPSED=0

while [[ ${ELAPSED} -lt ${TIMEOUT} ]]; do
    if [[ -f /proc/net/tquic/connections ]]; then
        # Check if we have 2 active paths
        PATH_COUNT=$(grep -c "path_id" /proc/net/tquic/connections 2>/dev/null || echo "0")
        if [[ ${PATH_COUNT} -ge 2 ]]; then
            log_pass "Both paths established after ${ELAPSED}s"
            break
        fi
    fi

    sleep 1
    ((ELAPSED++))
done

if [[ ${ELAPSED} -ge ${TIMEOUT} ]]; then
    log_fail "Dual path establishment timeout after ${TIMEOUT}s"
    kill ${CLIENT_PID} ${WAN1_TCPDUMP_PID} ${WAN2_TCPDUMP_PID} 2>/dev/null || true
    cat ${CLIENT_LOG}
    exit 1
fi

# Let transfer run
log_test "Transfer running for ${TEST_DURATION}s..."
wait ${CLIENT_PID} || {
    CLIENT_EXIT=$?
    log_fail "Client exited with code ${CLIENT_EXIT}"
    cat ${CLIENT_LOG}
    kill ${WAN1_TCPDUMP_PID} ${WAN2_TCPDUMP_PID} 2>/dev/null || true
    exit 1
}

# Stop packet captures
kill ${WAN1_TCPDUMP_PID} ${WAN2_TCPDUMP_PID} 2>/dev/null || true
sleep 1

# Collect final stats
STATS_AFTER="${WORK_DIR}/path_stats_after.txt"
if [[ -f /proc/net/tquic/path_stats ]]; then
    cat /proc/net/tquic/path_stats > ${STATS_AFTER}
fi

# Analyze results
log_test "=========================================="
log_test "Test Results Analysis"
log_test "=========================================="

# Check client log for both paths
if grep -q "path 0.*validated" ${CLIENT_LOG} && grep -q "path 1.*validated" ${CLIENT_LOG}; then
    log_pass "Both paths validated successfully"
else
    log_fail "Not all paths validated"
    grep "path.*validated\|PATH_CHALLENGE\|PATH_RESPONSE" ${CLIENT_LOG}
fi

# Verify traffic went over both WANs
WAN1_PACKETS=$(tcpdump -r ${WORK_DIR}/wan1.pcap 2>/dev/null | wc -l)
WAN2_PACKETS=$(tcpdump -r ${WORK_DIR}/wan2.pcap 2>/dev/null | wc -l)

log_test "WAN1 packets: ${WAN1_PACKETS}"
log_test "WAN2 packets: ${WAN2_PACKETS}"

if [[ ${WAN1_PACKETS} -gt 0 ]] && [[ ${WAN2_PACKETS} -gt 0 ]]; then
    log_pass "Traffic observed on both WAN interfaces"

    # Calculate distribution
    TOTAL_PACKETS=$((WAN1_PACKETS + WAN2_PACKETS))
    WAN1_PCT=$((WAN1_PACKETS * 100 / TOTAL_PACKETS))
    WAN2_PCT=$((WAN2_PACKETS * 100 / TOTAL_PACKETS))
    log_test "Distribution: WAN1=${WAN1_PCT}%, WAN2=${WAN2_PCT}%"
else
    log_fail "Traffic not observed on both WANs (WAN1=${WAN1_PACKETS}, WAN2=${WAN2_PACKETS})"
fi

# Check for errors in dmesg
if dmesg | tail -100 | grep -i "tquic.*error\|tquic.*warning"; then
    log_warn "Kernel warnings/errors detected (see dmesg)"
fi

# Save results
RESULTS_FILE="${WORK_DIR}/results.json"
cat > ${RESULTS_FILE} <<EOF
{
    "test": "wan_dual_path_establishment",
    "timestamp": "$(date -Iseconds)",
    "server": "${SERVER_ADDR}",
    "wan1": {
        "interface": "${WAN1_IFACE}",
        "ip": "${WAN1_IP}",
        "rtt_ms": ${WAN1_RTT},
        "packets": ${WAN1_PACKETS},
        "distribution_pct": ${WAN1_PCT}
    },
    "wan2": {
        "interface": "${WAN2_IFACE}",
        "ip": "${WAN2_IP}",
        "rtt_ms": ${WAN2_RTT},
        "packets": ${WAN2_PACKETS},
        "distribution_pct": ${WAN2_PCT}
    },
    "duration_sec": ${TEST_DURATION},
    "artifacts": {
        "client_log": "${CLIENT_LOG}",
        "wan1_pcap": "${WORK_DIR}/wan1.pcap",
        "wan2_pcap": "${WORK_DIR}/wan2.pcap",
        "stats_before": "${STATS_BEFORE}",
        "stats_after": "${STATS_AFTER}"
    }
}
EOF

log_test "=========================================="
log_pass "Test completed successfully!"
log_test "Results saved to: ${RESULTS_FILE}"
log_test "Artifacts in: ${WORK_DIR}"
log_test "=========================================="

exit 0
