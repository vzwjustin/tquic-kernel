# TQUIC Production Testing - Quick Start Guide

## 🚀 30-Second Setup

```bash
# 1. Have hardware ready:
#    - Client machine with 2 WAN connections (different ISPs)
#    - Server with public IP (cloud VM)

# 2. On client machine:
sudo modprobe quic  # Load TQUIC module

# 3. Run basic validation (15 minutes):
sudo ./run_all_production_tests.sh \
    --server <YOUR_SERVER_PUBLIC_IP> \
    --wan1 eth0 \
    --wan2 wwan0

# 4. For full validation including 24hr soak:
sudo ./run_all_production_tests.sh \
    --server <YOUR_SERVER_PUBLIC_IP> \
    --wan1 eth0 \
    --wan2 wwan0 \
    --soak
```

## 📋 Hardware Checklist

### Client Machine
- [ ] 2 network interfaces configured
- [ ] WAN1 has internet connectivity
- [ ] WAN2 has internet connectivity
- [ ] Both WANs can ping test server
- [ ] TQUIC kernel module compiled

### Test Server
- [ ] Public IP address
- [ ] UDP port 4433 open
- [ ] TQUIC server running
- [ ] Sufficient bandwidth for tests

## 🔧 Minimal Server Setup

```bash
# On your cloud VM (Ubuntu/Debian):
cd /path/to/tquic-kernel

# Build TQUIC module (if not done)
make M=net/quic

# Build test tools
make -C net/tquic/test/interop/tools

# Run TQUIC test server
sudo ./net/tquic/test/interop/tools/tquic_test_server \
    --addr 0.0.0.0 \
    --port 4433 \
    --cert /etc/ssl/test-cert.pem \
    --key /etc/ssl/test-key.pem \
    --serve-dir /tmp
```

## 📊 Understanding Results

### Success Indicators

✅ **All tests PASSED:**
```
[PASS] Multi-WAN Path Establishment - PASSED (45s)
[PASS] NAT Traversal - PASSED (120s)
[PASS] Bandwidth Aggregation - PASSED (180s)
[PASS] WAN Failover - PASSED (90s)
========================================
ALL TESTS PASSED - TQUIC WAN BONDING VALIDATED! ✅
```

**You can now claim:** "TQUIC achieves true WAN bonding on real internet links"

❌ **Tests FAILED:**
```
[FAIL] NAT Traversal - FAILED (exit code 1, 45s)
========================================
SOME TESTS FAILED - SEE SUMMARY ABOVE ❌
```

**Next steps:**
1. Check `results/TIMESTAMP/<test_name>/stdout.log`
2. Review failure_summary.txt
3. Verify hardware setup (both WANs working?)

### Key Metrics

After successful run, check `results/TIMESTAMP/summary.json`:

```json
{
    "total_tests": 4,
    "passed": 4,
    "failed": 0,
    "pass_rate": 100.00
}
```

## 🔍 Test-by-Test Guide

### Test 1: WAN Dual Path (5 minutes)

**What it validates:**
- Both WAN links can establish QUIC paths
- Traffic actually goes over both interfaces

**Common failures:**
- "WAN2 cannot reach server" → Check WAN2 routing
- "Only 1 path active" → Check multipath QUIC support

**Fix:**
```bash
# Verify both WANs have routes
ip route show

# Add default route for WAN2 if missing
sudo ip route add default via <WAN2_GATEWAY> dev eth1 metric 200
```

### Test 2: NAT Traversal (10 minutes) 🔴 CRITICAL

**What it validates:**
- Multipath works through 2 separate NATs
- NAT mappings survive 5-minute idle

**Common failures:**
- "No NAT detected" → You're not behind NAT (test less meaningful)
- "Second path timeout" → NAT may be blocking QUIC

**Fix:**
```bash
# Check if behind NAT
ip addr show eth0  # Should be private IP (10.x, 192.168.x)

# Verify NAT allows outbound UDP
sudo tcpdump -i eth1 udp port 4433
```

### Test 3: Bandwidth Aggregation (15 minutes)

**What it validates:**
- Actual bandwidth bonding (not just "faster")
- Goodput >= 80% of (WAN1 + WAN2)

**Common failures:**
- "Only achieved 65% of sum" → Scheduler issue or congestion
- "Only WAN1 utilized" → Check path selection

**Fix:**
```bash
# Check scheduler
sysctl net.tquic.scheduler

# Force aggregate scheduler
sudo sysctl -w net.tquic.scheduler=aggregate
```

### Test 4: 24-Hour Soak (24+ hours) ⏱️

**What it validates:**
- No kernel crashes over 24 hours
- Memory leak detection
- Link churn handling

**Common failures:**
- "Memory growth 3.2%" → Possible memory leak
- "Kernel panic detected" → Critical bug

**Fix:**
- Memory leaks → File bug report with logs
- Kernel panics → Provide dmesg to developers

## 🐛 Troubleshooting

### "Cannot load TQUIC module"

```bash
# Check module built
ls -la net/quic/quic.ko

# Build if missing
make M=net/quic

# Load manually
sudo insmod net/quic/quic.ko
```

### "Server unreachable from WAN2"

```bash
# Test connectivity
ping -I eth1 <SERVER_IP>

# Check routing
ip route get <SERVER_IP> from <WAN2_LOCAL_IP>

# May need policy routing
sudo ip rule add from <WAN2_LOCAL_IP> table 200
sudo ip route add default via <WAN2_GATEWAY> table 200
```

### "Permission denied" errors

```bash
# All tests must run as root
sudo -i
cd /path/to/tquic-kernel/net/tquic/test/production
./run_all_production_tests.sh --server <IP> ...
```

## 📈 Benchmark Your Results

Share your results with the community:

```bash
# After successful run:
cat results/*/summary.json

# Example tweet:
# "TQUIC WAN bonding validation ✅
#  - 2x WAN links (Fiber 100Mbps + LTE 50Mbps)
#  - Achieved 145Mbps aggregated (96% of sum)
#  - NAT traversal: PASS
#  - 24hr soak: PASS, <0.5% memory growth"
```

## 🎯 Next Steps After Validation

1. **Document your setup** in the results directory
2. **Run tests periodically** (weekly/monthly) for regression
3. **Test different scenarios:**
   - Different ISP combinations
   - Various LTE carriers
   - Different server locations
4. **Contribute improvements** to test suite

## 📞 Getting Help

- **Test failures:** Open issue with `results/` directory attached
- **Hardware questions:** Check `README.md` hardware requirements
- **TQUIC bugs:** If all tests fail, may be TQUIC bug not hardware

---

**Remember:** These are PRODUCTION tests using REAL internet links.
Results prove TQUIC actually works for WAN bonding, not just in theory.
