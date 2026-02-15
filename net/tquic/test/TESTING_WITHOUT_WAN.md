# Testing TQUIC WAN Bonding Without Real Hardware

This guide shows how to validate TQUIC's multipath WAN bonding functionality using network namespaces and virtual interfaces - **no real WAN links required**.

## Overview

TQUIC provides three test layers:

1. **KUnit Tests** - Algorithm logic validation (pure unit tests)
2. **Network Namespace Tests** - Functional multipath testing (this guide)
3. **Production Tests** - Real WAN hardware validation

This guide focuses on **Layer 2** - proving WAN bonding works functionally without real internet links.

## Prerequisites

```bash
# Install required tools
sudo apt-get install -y iproute2 iptables tcpdump bc net-tools

# Build TQUIC kernel module
cd /path/to/tquic-kernel
make M=net/quic

# Verify module built
ls -la net/quic/quic.ko
```

## Quick Start (5 Minutes)

```bash
# 1. Navigate to test directory
cd net/tquic/test/interop

# 2. Setup virtual network (creates 3 path pairs)
sudo ./setup_namespaces.sh setup

# 3. Verify setup
sudo ./setup_namespaces.sh status

# 4. Build test tools
make -C tools

# 5. Run multipath tests
sudo ./test_cases/multipath_test.sh picoquic tquic_client tquic_server \
    10.0.1.2 4433 ./certs

# 6. Cleanup when done
sudo ./setup_namespaces.sh cleanup
```

## What Gets Created

The setup script creates two network namespaces with virtual ethernet pairs:

```
┌─────────────────────────┐         ┌─────────────────────────┐
│  tquic_client namespace │         │  tquic_server namespace │
│                         │         │                         │
│  veth0: 10.0.1.1/24    ├─────────┤  veth1: 10.0.1.2/24     │  Path 1
│  veth2: 10.0.2.1/24    ├─────────┤  veth3: 10.0.2.2/24     │  Path 2
│  veth4: 10.0.3.1/24    ├─────────┤  veth5: 10.0.3.2/24     │  Path 3
└─────────────────────────┘         └─────────────────────────┘
```

Each veth pair simulates a separate WAN link.

## Simulating Real-World Conditions

### Scenario 1: Fiber + LTE (Asymmetric Links)

Simulate 100Mbps fiber (low latency) + 50Mbps LTE (higher latency, packet loss):

```bash
# Setup namespaces
sudo ./setup_namespaces.sh setup

# Path 1: Fiber (100Mbps, 10ms RTT, 0.1% loss)
sudo ./setup_namespaces.sh netem tquic_client veth0 10ms 0.1% 100mbit

# Path 2: LTE (50Mbps, 50ms RTT, 2% loss)
sudo ./setup_namespaces.sh netem tquic_client veth2 50ms 2% 50mbit

# Run bandwidth aggregation test
sudo ./test_cases/multipath_test.sh picoquic tquic_client tquic_server \
    10.0.1.2 4433 ./certs
```

**Expected result:** Transfer should use both paths and achieve ~150Mbps aggregate throughput.

### Scenario 2: Dual Cable Modems (Symmetric)

Simulate two 100Mbps cable modem connections:

```bash
sudo ./setup_namespaces.sh setup

# Both paths: 100Mbps, 20ms RTT, 0.5% loss
sudo ./setup_namespaces.sh netem tquic_client veth0 20ms 0.5% 100mbit
sudo ./setup_namespaces.sh netem tquic_client veth2 20ms 0.5% 100mbit

# Test round-robin scheduler
# (should distribute traffic evenly)
```

### Scenario 3: Path Failover Simulation

Test WAN failover when primary link fails:

```bash
# Setup with different latencies
sudo ./setup_namespaces.sh setup
sudo ./setup_namespaces.sh netem tquic_client veth0 10ms 0% 100mbit  # Primary
sudo ./setup_namespaces.sh netem tquic_client veth2 30ms 0% 50mbit   # Backup

# Run failover test
sudo ./test_cases/failover_test.sh picoquic tquic_client tquic_server \
    10.0.1.2 4433 ./certs
```

The test will:
1. Start transfer over both paths
2. Disable veth0 (primary) mid-transfer
3. Verify traffic continues on veth2
4. Measure failover time

### Scenario 4: NAT Traversal

Simulate NAT environments (like home routers):

```bash
sudo ./setup_namespaces.sh setup

# Add NAT in client namespace
sudo ip netns exec tquic_client iptables -t nat -A POSTROUTING \
    -o veth0 -j MASQUERADE
sudo ip netns exec tquic_client iptables -t nat -A POSTROUTING \
    -o veth2 -j MASQUERADE

# Run NAT traversal test
sudo ./test_cases/multipath_test.sh picoquic tquic_client tquic_server \
    10.0.1.2 4433 ./certs

# Verify NAT mappings
sudo ip netns exec tquic_client conntrack -L
```

## Test Categories

### 1. Path Establishment Tests
**Validates:** Multiple QUIC paths can be established simultaneously

```bash
# Test creates 2 paths and verifies both are active
sudo ./test_cases/multipath_test.sh picoquic tquic_client tquic_server \
    10.0.1.2 4433 ./certs
# Look for: "Dual path establishment successful"
```

### 2. Bandwidth Aggregation Tests
**Validates:** Combined throughput > single path throughput

```bash
# Test measures single-path baseline, then multipath throughput
# Verifies speedup > 1.2x (accounting for overhead)
sudo ./test_cases/multipath_test.sh picoquic tquic_client tquic_server \
    10.0.1.2 4433 ./certs
# Look for: "Bandwidth aggregation observed (X.XX speedup)"
```

### 3. Scheduler Tests
**Validates:** Different scheduling algorithms work correctly

```bash
# Round-robin: even distribution
# MinRTT: prefers low-latency path
# Weighted: respects path weights
# BLEST: considers both RTT and bandwidth

# These are tested automatically by multipath_test.sh
```

### 4. Path Failover Tests
**Validates:** Connection survives path failures

```bash
sudo ./test_cases/failover_test.sh picoquic tquic_client tquic_server \
    10.0.1.2 4433 ./certs
# Look for: "Failover completed in XXms"
```

### 5. Dynamic Path Management
**Validates:** Paths can be added/removed during active transfers

```bash
# Tests add new path mid-transfer and remove paths gracefully
sudo ./test_cases/multipath_test.sh picoquic tquic_client tquic_server \
    10.0.1.2 4433 ./certs
```

## Interpreting Results

### Success Indicators

```
[PASS] Dual path establishment successful (2 paths)
[PASS] Bandwidth aggregation observed (1.85x speedup)
[PASS] Round-robin scheduling active
[PASS] Asymmetric path handling working
```

### Failure Investigation

If tests fail, check:

```bash
# 1. Verify namespaces exist
sudo ip netns list

# 2. Check interface status
sudo ip netns exec tquic_client ip link show

# 3. Check routing
sudo ip netns exec tquic_client ip route show

# 4. Check for kernel errors
dmesg | grep -i tquic | tail -20

# 5. Verify TQUIC module loaded
lsmod | grep quic
```

## Advanced: Manual Testing

### Start Server Manually

```bash
# In one terminal - start server
sudo ip netns exec tquic_server \
    ./tools/tquic_test_server \
    --addr 10.0.1.2 \
    --port 4433 \
    --cert ./certs/server.crt \
    --key ./certs/server.key \
    --enable-multipath
```

### Run Client with Multipath

```bash
# In another terminal - connect client
sudo ip netns exec tquic_client \
    ./tools/tquic_test_client \
    --addr 10.0.1.2 \
    --port 4433 \
    --multipath \
    --add-path 10.0.2.1 \
    --scheduler aggregate \
    --transfer-size 10485760 \
    --verbose
```

### Monitor Traffic

```bash
# Watch traffic on both paths
sudo ip netns exec tquic_client tcpdump -i veth0 -n udp port 4433 &
sudo ip netns exec tquic_client tcpdump -i veth2 -n udp port 4433 &

# Watch path statistics
watch -n 1 'sudo cat /proc/net/tquic/connections'
```

## Comparison: Namespace Tests vs Production Tests

| Feature | Namespace Tests | Production Tests |
|---------|----------------|------------------|
| **Hardware Required** | None | 2 WAN interfaces |
| **Runtime** | 5-15 minutes | Hours (soak test: 24hrs) |
| **Network Variability** | Controlled | Real internet |
| **NAT Testing** | Simulated | Real ISP NAT |
| **Reproducibility** | 100% | Variable |
| **CI/CD Suitable** | ✅ Yes | ❌ No |
| **Validates Logic** | ✅ Yes | ✅ Yes |
| **Validates Production** | ⚠️ Partial | ✅ Yes |

## Limitations of Namespace Testing

**Cannot test:**
- ISP-specific CGNAT behavior
- Real cellular network handoffs (WiFi→LTE)
- Long-term stability over real internet
- Actual NAT timeout variations across ISPs
- Real-world route changes and BGP failover
- Physical layer issues (cable unplugged, etc.)

**Can test:**
- Multipath protocol correctness
- Scheduler algorithms
- Failover logic
- Bandwidth aggregation math
- Path management state machines
- NAT traversal mechanisms (generic)

## Continuous Integration Usage

```bash
#!/bin/bash
# CI script for TQUIC multipath validation

set -e

# Build module
make M=net/quic

# Setup test environment
cd net/tquic/test/interop
sudo ./setup_namespaces.sh setup

# Configure realistic conditions
sudo ./setup_namespaces.sh netem tquic_client veth0 15ms 0.5% 100mbit
sudo ./setup_namespaces.sh netem tquic_client veth2 40ms 1% 50mbit

# Run tests
sudo ./test_cases/multipath_test.sh picoquic tquic_client tquic_server \
    10.0.1.2 4433 ./certs

# Cleanup
sudo ./setup_namespaces.sh cleanup

echo "✅ TQUIC multipath validation PASSED"
```

## Troubleshooting

### "Namespace not found"
```bash
sudo ./setup_namespaces.sh cleanup
sudo ./setup_namespaces.sh setup
```

### "Cannot build test tools"
```bash
# Install dependencies
sudo apt-get install -y build-essential libssl-dev

# Rebuild
make -C tools clean
make -C tools
```

### "TQUIC module not loaded"
```bash
sudo modprobe quic
# Or
sudo insmod net/quic/quic.ko
```

### "Permission denied"
All namespace operations require root:
```bash
sudo -i
cd /path/to/tquic-kernel/net/tquic/test/interop
./setup_namespaces.sh setup
```

## Next Steps

After namespace tests pass:
1. ✅ Code logic is correct
2. ✅ Multipath works functionally
3. ⏭️ Run production tests with real WAN hardware (see `production/QUICKSTART.md`)

## References

- Network namespaces: `man ip-netns`
- Traffic control: `man tc-netem`
- Test scripts: `net/tquic/test/interop/test_cases/`
- Production tests: `net/tquic/test/production/README.md`

---

**Summary:** These namespace-based tests prove TQUIC's WAN bonding logic works correctly in controlled conditions. For production deployment validation, follow up with the real WAN hardware tests.
