# TQUIC Production WAN Bonding Validation

## Overview

This directory contains **production-grade** tests that validate TQUIC's WAN bonding
capabilities on real internet links, not simulated localhost environments.

**CRITICAL DIFFERENCE FROM INTEROP TESTS:**
- `test/interop/`: Functional tests using network namespaces (localhost)
- `test/production/`: Real-world validation using physical WAN links

## Hardware Requirements

### Minimum Test Setup (Tier 1)

```
┌─────────────────────────────────────────────────────────────┐
│                    TQUIC WAN Bonding Testbed                │
└─────────────────────────────────────────────────────────────┘

CLIENT SIDE:
┌──────────────────────┐
│  Test Client Machine │
│  (Linux x86_64)      │
│  - 2x Ethernet NICs  │
│  - TQUIC module      │
└─────┬────────┬───────┘
      │        │
      │ WAN1   │ WAN2
      │        │
┌─────┴─────┐  ┌────┴─────┐
│  Router A │  │ Router B │  ← Different ISPs/carriers
│  Fiber    │  │ LTE/5G   │
│  Public IP│  │ CGNAT    │
└─────┬─────┘  └────┬─────┘
      │             │
      └──────┬──────┘
             │ Internet
             │
      ┌──────┴──────┐
      │ Test Server │
      │ (Cloud VM)  │
      │ Public IP   │
      └─────────────┘
```

### Hardware Specifications

**Client Machine:**
- CPU: 4+ cores (for concurrent path processing)
- RAM: 8GB minimum
- NICs: 2x Gigabit Ethernet (Intel i350 or better)
- OS: Linux kernel 6.1+ with TQUIC module

**WAN Links:**
- **WAN1 (Primary):** Fiber/Cable with static public IP
  - Minimum: 50 Mbps down / 10 Mbps up
  - Latency: <30ms to test server

- **WAN2 (Secondary):** LTE/5G modem with CGNAT
  - Minimum: 25 Mbps down / 5 Mbps up
  - Latency: 50-150ms typical
  - Must be different carrier than WAN1

**Test Server:**
- Cloud VM (AWS/GCP/DigitalOcean)
- Public IPv4 address
- 1 Gbps network
- Ubuntu 22.04 LTS or later

## Test Categories

### Category 1: Multi-WAN Path Establishment ✅
**Validates:** Both WAN links can establish independent QUIC paths

- [x] `wan_dual_path_test.sh` - Establish paths over 2 real WAN links
- [x] `wan_path_validation_test.sh` - Validate path MTU, RTT measurement
- [x] `wan_interface_binding_test.sh` - Verify SO_BINDTODEVICE per path

### Category 2: NAT Traversal 🔴 CRITICAL
**Validates:** Multipath works behind multiple NATs

- [x] `nat_multi_wan_test.sh` - Establish paths through 2 separate NATs
- [x] `nat_rebinding_test.sh` - Survive NAT mapping changes
- [x] `nat_cgnat_test.sh` - Work behind carrier-grade NAT
- [x] `nat_symmetric_test.sh` - Handle endpoint-dependent NAT

### Category 3: Bandwidth Aggregation ⚡
**Validates:** Actually achieves combined bandwidth

- [x] `bandwidth_aggregation_test.sh` - Measure real goodput vs sum
- [x] `bandwidth_per_path_util_test.sh` - Per-path utilization tracking
- [x] `bandwidth_scheduler_test.sh` - Validate scheduler load distribution

### Category 4: Failover & Recovery 🔄
**Validates:** Graceful handling of link failures

- [x] `failover_wan_disconnect_test.sh` - Physical link disconnect
- [x] `failover_brownout_test.sh` - Congestion/packet loss scenarios
- [x] `failover_recovery_test.sh` - Link recovery and re-establishment

### Category 5: Mobile Handoff 📱
**Validates:** WiFi ↔ LTE transitions

- [x] `mobile_wifi_to_lte_test.sh` - Handoff during active transfer
- [x] `mobile_lte_to_wifi_test.sh` - Reverse handoff
- [x] `mobile_roaming_test.sh` - Cell tower handoff

### Category 6: Production Stability 🏗️
**Validates:** Long-term reliability

- [x] `soak_24hour_test.sh` - 24-hour continuous operation
- [x] `soak_link_churn_test.sh` - Periodic failover/recovery
- [x] `soak_memory_leak_test.sh` - Monitor kernel memory growth

## Quick Start

### 1. Hardware Setup

```bash
# Configure WAN interfaces on client
sudo ip link set eth0 up  # WAN1 (fiber)
sudo ip link set eth1 up  # WAN2 (LTE)

# Set default routes with metrics
sudo ip route add default via 192.168.1.1 dev eth0 metric 100  # WAN1 primary
sudo ip route add default via 192.168.2.1 dev eth1 metric 200  # WAN2 backup

# Verify routing
ip route show table all
```

### 2. Server Setup

```bash
# On test server (cloud VM)
cd /path/to/tquic-kernel
./net/tquic/test/production/server/setup_test_server.sh

# Start TQUIC server
./net/tquic/test/production/server/run_server.sh \
    --addr 0.0.0.0 \
    --port 4433 \
    --cert /etc/tquic/cert.pem \
    --key /etc/tquic/key.pem
```

### 3. Run Tests

```bash
# Full production validation suite
sudo ./run_all_production_tests.sh \
    --server-addr <SERVER_PUBLIC_IP> \
    --wan1-iface eth0 \
    --wan2-iface eth1 \
    --output-dir ./results

# Individual test categories
sudo ./run_category.sh nat_traversal
sudo ./run_category.sh bandwidth_aggregation
sudo ./run_category.sh soak_tests
```

## Pass Criteria

### Tier 1 (Minimum for Production Claim)

| Test | Pass Criteria | Current Status |
|------|--------------|----------------|
| Multi-WAN establishment | Both paths validate within 10s | ❌ Not tested |
| NAT traversal | Paths work through 2 NATs | ❌ Not tested |
| Bandwidth aggregation | Goodput >= 80% of sum | ❌ Not tested |
| Link failover | Recovery < 5s, zero data loss | ❌ Not tested |

### Tier 2 (Production Hardening)

| Test | Pass Criteria | Current Status |
|------|--------------|----------------|
| Mobile handoff | <1s disruption, no errors | ❌ Not tested |
| CGNAT compatibility | Works behind carrier NAT | ❌ Not tested |
| 24hr soak | Zero crashes, <1% memory growth | ❌ Not tested |
| Reordering tolerance | Spurious retrans <2% | ❌ Not tested |

## Test Results Archive

Results are stored in:
```
results/
├── YYYY-MM-DD_HHMMSS/
│   ├── test_summary.json
│   ├── bandwidth_metrics.csv
│   ├── per_path_stats.log
│   ├── kernel_dmesg.log
│   └── pcaps/
│       ├── wan1_capture.pcap
│       └── wan2_capture.pcap
```

## Troubleshooting

### Common Issues

**"Second path never establishes"**
- Check routing table: `ip route get <server_ip> from <wan2_ip>`
- Verify WAN2 can reach server: `ping -I eth1 <server_ip>`
- Check NAT: `tcpdump -i eth1 udp port 4433`

**"Bandwidth aggregation not working"**
- Confirm both paths active: `cat /proc/net/tquic/connections`
- Check scheduler: `sysctl net.tquic.scheduler`
- Monitor per-path bytes: `watch -n1 'cat /proc/net/tquic/path_stats'`

**"NAT rebinding breaks connection"**
- Enable keepalives: `sysctl net.tquic.keepalive_interval=15000`
- Check NAT timeout: `conntrack -L | grep udp`

## Contributing

To add new production tests:

1. Create test script in appropriate category directory
2. Follow naming convention: `<category>_<scenario>_test.sh`
3. Include pass/fail criteria in script header
4. Add to `run_all_production_tests.sh`
5. Document hardware requirements

## References

- IETF draft-ietf-quic-multipath
- TQUIC Architecture: `Documentation/networking/tquic.rst`
- Interop tests (functional): `../interop/`
