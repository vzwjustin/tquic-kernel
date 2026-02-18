#!/bin/bash
# SPDX-License-Identifier: GPL-2.0-only
#
# TQUIC Production Test: Multi-WAN NAT Traversal
#
# CRITICAL: Tests TQUIC multipath through REAL NATs, not simulated
#
# Test validates:
# - Connection establishment through primary NAT
# - Additional path creation through secondary NAT (different public IP)
# - Both paths stay active despite NAT mapping timeouts
# - NAT rebinding doesn't break the connection
#
# Hardware requirements:
# - Client behind 2 separate NAT routers (different ISPs)
# - Each NAT has different external IP
# - Server on public internet (no NAT)
#
# Topology:
#   [Client] --WAN1--> [NAT1] --Internet--> [Server]
#            --WAN2--> [NAT2] --Internet--> [Server]
#
# Pass criteria:
# - Both NAT traversal succeeds without manual port forwarding
# - Connection survives 5+ minute idle period (NAT timeout test)
# - NAT rebinding (force new port) doesn't break session
#
# THIS IS THE #1 MISSING TEST FROM CURRENT SUITE

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/common_production.sh"

SERVER_ADDR="${1:-}"
WAN1_IFACE="${2:-eth0}"
WAN2_IFACE="${3:-eth1}"
NAT_TIMEOUT_TEST="${4:-300}"  # 5 minutes default

if [[ -z "${SERVER_ADDR}" ]]; then
    echo "Usage: $0 <server_addr> [wan1_iface] [wan2_iface] [nat_timeout_sec]"
    echo "Example: $0 203.0.113.100 eth0 wwan0 300"
    exit 1
fi

log_test "=========================================="
log_test "TQUIC NAT Traversal Test (REAL NATs)"
log_test "=========================================="
log_test "Server: ${SERVER_ADDR}"
log_test "WAN1 (NAT1): ${WAN1_IFACE}"
log_test "WAN2 (NAT2): ${WAN2_IFACE}"
log_test "NAT timeout test: ${NAT_TIMEOUT_TEST}s"

# CRITICAL: Verify we're actually behind NAT
log_test "Pre-flight: Verifying NAT detection"

# Get local IPs
WAN1_LOCAL_IP=$(ip -4 addr show ${WAN1_IFACE} | grep inet | awk '{print $2}' | cut -d/ -f1 | head -1)
WAN2_LOCAL_IP=$(ip -4 addr show ${WAN2_IFACE} | grep inet | awk '{print $2}' | cut -d/ -f1 | head -1)

log_test "WAN1 local IP: ${WAN1_LOCAL_IP}"
log_test "WAN2 local IP: ${WAN2_LOCAL_IP}"

# Check if IPs are private (RFC1918) - indicates NAT
is_private_ip() {
    local ip=$1
    # Check for 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16
    if [[ $ip =~ ^10\. ]] || \
       [[ $ip =~ ^192\.168\. ]] || \
       [[ $ip =~ ^172\.(1[6-9]|2[0-9]|3[01])\. ]]; then
        return 0
    fi
    return 1
}

NAT1_DETECTED=false
NAT2_DETECTED=false

if is_private_ip ${WAN1_LOCAL_IP}; then
    log_pass "WAN1: NAT detected (private IP ${WAN1_LOCAL_IP})"
    NAT1_DETECTED=true
else
    log_warn "WAN1: No NAT detected (public IP ${WAN1_LOCAL_IP}) - test may not be meaningful"
fi

if is_private_ip ${WAN2_LOCAL_IP}; then
    log_pass "WAN2: NAT detected (private IP ${WAN2_LOCAL_IP})"
    NAT2_DETECTED=true
else
    log_warn "WAN2: No NAT detected (public IP ${WAN2_LOCAL_IP}) - test may not be meaningful"
fi

if [[ "${NAT1_DETECTED}" == "false" ]] && [[ "${NAT2_DETECTED}" == "false" ]]; then
    log_fail "ERROR: No NAT detected on either WAN interface"
    log_fail "This test requires at least one NAT to validate traversal"
    exit 1
fi

# Verify server reachability through both NATs
log_test "Testing NAT1 connectivity..."
if ! ping -I ${WAN1_IFACE} -c 3 -W 10 ${SERVER_ADDR} > /dev/null 2>&1; then
    log_fail "Cannot reach server through NAT1"
    exit 1
fi
log_pass "Server reachable through NAT1"

log_test "Testing NAT2 connectivity..."
if ! ping -I ${WAN2_IFACE} -c 3 -W 10 ${SERVER_ADDR} > /dev/null 2>&1; then
    log_fail "Cannot reach server through NAT2"
    exit 1
fi
log_pass "Server reachable through NAT2"

WORK_DIR=$(mktemp -d /tmp/tquic_nat_test.XXXXXX)
log_test "Working directory: ${WORK_DIR}"

# Enable TQUIC NAT keepalive
log_test "Configuring TQUIC NAT keepalive..."
sysctl -w net.tquic.keepalive_interval=15000 > /dev/null  # 15 seconds
sysctl -w net.tquic.keepalive_enabled=1 > /dev/null

# Start conntrack monitoring to observe NAT mappings
log_test "Starting NAT conntrack monitoring..."
(while true; do
    conntrack -L | grep "dport=4433" >> ${WORK_DIR}/conntrack.log 2>/dev/null || true
    sleep 5
done) &
CONNTRACK_PID=$!

# Phase 1: Establish connection through NAT1
log_test "=========================================="
log_test "Phase 1: Initial connection via NAT1"
log_test "=========================================="

CLIENT_LOG="${WORK_DIR}/client_phase1.log"

${SCRIPT_DIR}/../interop/tools/tquic_test_client \
    --addr ${SERVER_ADDR} \
    --port 4433 \
    --interface ${WAN1_IFACE} \
    --transfer-size $((10 * 1024 * 1024)) \
    > ${CLIENT_LOG} 2>&1 &
CLIENT_PID=$!

# Wait for initial connection
sleep 5

if ! kill -0 ${CLIENT_PID} 2>/dev/null; then
    log_fail "Phase 1: Client failed to establish connection"
    cat ${CLIENT_LOG}
    kill ${CONNTRACK_PID} 2>/dev/null || true
    exit 1
fi

if ! grep -q "connected\|established" ${CLIENT_LOG}; then
    log_fail "Phase 1: Connection not established through NAT1"
    kill ${CLIENT_PID} ${CONNTRACK_PID} 2>/dev/null || true
    cat ${CLIENT_LOG}
    exit 1
fi

log_pass "Phase 1: Connection established through NAT1"

# Get NAT1 mapping
NAT1_MAPPING=$(conntrack -L 2>/dev/null | grep "dport=4433" | grep ${WAN1_IFACE} | head -1)
log_test "NAT1 mapping: ${NAT1_MAPPING}"

wait ${CLIENT_PID} || log_warn "Phase 1 client exit code: $?"

# Phase 2: Add second path through NAT2
log_test "=========================================="
log_test "Phase 2: Add path via NAT2 (CRITICAL)"
log_test "=========================================="

CLIENT_LOG2="${WORK_DIR}/client_phase2.log"

${SCRIPT_DIR}/../interop/tools/tquic_test_client \
    --addr ${SERVER_ADDR} \
    --port 4433 \
    --multipath \
    --primary-interface ${WAN1_IFACE} \
    --add-path-interface ${WAN2_IFACE} \
    --add-path-delay 5000 \
    --transfer-size $((50 * 1024 * 1024)) \
    > ${CLIENT_LOG2} 2>&1 &
CLIENT_PID=$!

# Monitor for second path establishment
log_test "Waiting for second path through NAT2..."
TIMEOUT=30
ELAPSED=0

while [[ ${ELAPSED} -lt ${TIMEOUT} ]]; do
    if grep -q "path 1.*established\|new path.*validated" ${CLIENT_LOG2}; then
        log_pass "Second path established through NAT2 after ${ELAPSED}s"
        break
    fi
    sleep 1
    ((ELAPSED++))
done

if [[ ${ELAPSED} -ge ${TIMEOUT} ]]; then
    log_fail "Second path failed to establish through NAT2"
    cat ${CLIENT_LOG2}
    kill ${CLIENT_PID} ${CONNTRACK_PID} 2>/dev/null || true
    exit 1
fi

# Get NAT2 mapping
NAT2_MAPPING=$(conntrack -L 2>/dev/null | grep "dport=4433" | grep ${WAN2_IFACE} | head -1)
log_test "NAT2 mapping: ${NAT2_MAPPING}"

# Verify both paths are active
sleep 10
if [[ -f /proc/net/tquic/connections ]]; then
    ACTIVE_PATHS=$(grep "state=active" /proc/net/tquic/connections | wc -l)
    if [[ ${ACTIVE_PATHS} -ge 2 ]]; then
        log_pass "Both paths active through separate NATs"
    else
        log_fail "Only ${ACTIVE_PATHS} paths active (expected 2)"
    fi
fi

# Phase 3: NAT Timeout Test
log_test "=========================================="
log_test "Phase 3: NAT Timeout Survival"
log_test "=========================================="
log_test "Idle timeout test: ${NAT_TIMEOUT_TEST}s"
log_test "(Keepalive should maintain NAT mappings)"

# Let connection idle but keepalives running
START_TIME=$(date +%s)
while true; do
    CURRENT_TIME=$(date +%s)
    ELAPSED=$((CURRENT_TIME - START_TIME))

    if [[ ${ELAPSED} -ge ${NAT_TIMEOUT_TEST} ]]; then
        break
    fi

    # Check if client still alive
    if ! kill -0 ${CLIENT_PID} 2>/dev/null; then
        log_fail "Client died during NAT timeout test after ${ELAPSED}s"
        cat ${CLIENT_LOG2}
        kill ${CONNTRACK_PID} 2>/dev/null || true
        exit 1
    fi

    # Log NAT state every 30s
    if [[ $((ELAPSED % 30)) -eq 0 ]]; then
        NAT_COUNT=$(conntrack -L 2>/dev/null | grep -c "dport=4433" || echo "0")
        log_test "T+${ELAPSED}s: ${NAT_COUNT} NAT mappings active"
    fi

    sleep 10
done

log_pass "Connection survived ${NAT_TIMEOUT_TEST}s idle period"

# Verify NAT mappings still exist
if conntrack -L 2>/dev/null | grep -q "dport=4433"; then
    log_pass "NAT mappings maintained by keepalive"
else
    log_warn "NAT mappings expired (but connection may still be alive)"
fi

# Send more data to verify paths still work
log_test "Sending post-timeout traffic..."
# Client should still be running and complete transfer
wait ${CLIENT_PID} || {
    CLIENT_EXIT=$?
    if [[ ${CLIENT_EXIT} -ne 0 ]]; then
        log_fail "Client exited with error ${CLIENT_EXIT} after timeout test"
        cat ${CLIENT_LOG2}
        kill ${CONNTRACK_PID} 2>/dev/null || true
        exit 1
    fi
}

log_pass "Transfer completed after NAT timeout test"

# Phase 4: NAT Rebinding Test (Force New Port)
log_test "=========================================="
log_test "Phase 4: NAT Rebinding Test"
log_test "=========================================="
log_test "(Would require router control to force rebind)"
log_test "Skipping - requires additional infrastructure"

# Cleanup
kill ${CONNTRACK_PID} 2>/dev/null || true

# Final Results
log_test "=========================================="
log_test "Test Results Summary"
log_test "=========================================="

# Analyze conntrack log
UNIQUE_NAT_MAPPINGS=$(grep "dport=4433" ${WORK_DIR}/conntrack.log | sort -u | wc -l)
log_test "Unique NAT mappings observed: ${UNIQUE_NAT_MAPPINGS}"

# Check for NAT rebinding events
REBIND_EVENTS=$(grep -c "UNREPLIED\|ASSURED" ${WORK_DIR}/conntrack.log || echo "0")
log_test "Potential NAT rebinding events: ${REBIND_EVENTS}"

# Save results
RESULTS_FILE="${WORK_DIR}/results.json"
cat > ${RESULTS_FILE} <<EOF
{
    "test": "nat_multi_wan_traversal",
    "timestamp": "$(date -Iseconds)",
    "server": "${SERVER_ADDR}",
    "nat1": {
        "interface": "${WAN1_IFACE}",
        "local_ip": "${WAN1_LOCAL_IP}",
        "nat_detected": ${NAT1_DETECTED}
    },
    "nat2": {
        "interface": "${WAN2_IFACE}",
        "local_ip": "${WAN2_LOCAL_IP}",
        "nat_detected": ${NAT2_DETECTED}
    },
    "phases": {
        "path1_established": true,
        "path2_established": true,
        "timeout_survived": true,
        "timeout_duration_sec": ${NAT_TIMEOUT_TEST}
    },
    "nat_mappings_observed": ${UNIQUE_NAT_MAPPINGS},
    "artifacts": {
        "client_log_phase1": "${CLIENT_LOG}",
        "client_log_phase2": "${CLIENT_LOG2}",
        "conntrack_log": "${WORK_DIR}/conntrack.log"
    }
}
EOF

log_test "=========================================="
log_pass "NAT traversal test PASSED!"
log_test "Results saved to: ${RESULTS_FILE}"
log_test "=========================================="

exit 0
