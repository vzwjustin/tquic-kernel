# Performance Testing Plan: Zero-Copy Transmission Optimization

**Optimization:** P-001 - Zero-copy transmission in tquic_output.c
**Expected Impact:** 50-70% throughput improvement, 50+ fewer allocations per send
**Date:** 2026-02-11

---

## 1. Key Performance Metrics

### Primary Metrics (Must Measure)

#### Throughput
- **Metric:** Megabits per second (Mbps) or Gigabits per second (Gbps)
- **Target:** 50-70% improvement over baseline
- **Measurement:** Application-layer goodput (QUIC stream data)
- **Tools:** iperf3, custom QUIC benchmark

#### Memory Allocations
- **Metric:** Allocations per send operation
- **Target:** Reduce from 50+ to near-zero
- **Measurement:** kmem_cache_alloc calls for tquic_frame_cache
- **Tools:** ftrace, perf, `/proc/slabinfo`

#### Memory Copies
- **Metric:** memcpy operations per packet
- **Target:** Reduce from 2 to 1
- **Measurement:** memcpy trace events in packet path
- **Tools:** ftrace function_graph, perf probe

### Secondary Metrics (Should Measure)

#### CPU Utilization
- **Metric:** CPU percentage per Gbps throughput
- **Target:** 20-30% reduction (fewer allocations = less CPU)
- **Measurement:** System CPU time, softirq time
- **Tools:** mpstat, perf top

#### Latency
- **Metric:** Round-trip time (RTT) for QUIC streams
- **Target:** No degradation (may see slight improvement)
- **Measurement:** Stream completion time, packet timestamps
- **Tools:** tcpdump + timestamping, qlog analysis

#### Memory Footprint
- **Metric:** Peak allocated memory for TQUIC
- **Target:** Significant reduction in transient allocations
- **Measurement:** slab cache usage, /proc/meminfo
- **Tools:** slabtop, /proc/slabinfo

---

## 2. Benchmark Commands and Tools

### A. Load Module and Verify

```bash
# Load TQUIC module
sudo insmod net/tquic/quic.ko

# Verify module loaded
lsmod | grep quic
dmesg | tail -20

# Check slab cache created
sudo cat /proc/slabinfo | grep tquic
```

### B. Baseline Measurement (Before Optimization)

```bash
# Get baseline allocations
sudo cat /proc/slabinfo | grep tquic_frame > baseline_slab.txt

# Run baseline throughput test (10 seconds)
iperf3 -c <server_ip> --quic -t 10 -P 4 > baseline_throughput.txt

# Capture baseline CPU usage
mpstat 1 10 > baseline_cpu.txt
```

### C. Performance Benchmarks

#### 1. iperf3 with QUIC (if supported)
```bash
# Server side
iperf3 -s --quic

# Client side - single stream
iperf3 -c <server_ip> --quic -t 30 -i 1

# Client side - parallel streams (stress test)
iperf3 -c <server_ip> --quic -t 30 -P 8 -i 1

# Client side - UDP mode for comparison
iperf3 -c <server_ip> -u -b 10G -t 30
```

#### 2. Custom QUIC Benchmark (if available in tools/)
```bash
# Look for existing benchmarks
ls tools/testing/selftests/net/quic/
ls net/tquic/bench/

# Run custom benchmark if available
./net/tquic/bench/tquic_bench --connections 10 --streams 4 --duration 30
```

#### 3. qperf for Latency Testing
```bash
# Server
qperf

# Client - measure UDP latency as baseline
qperf <server_ip> udp_lat udp_bw

# Then measure QUIC if supported
```

---

## 3. Test Scenarios

### Scenario 1: Single-Path Baseline
**Purpose:** Isolate zero-copy impact without multipath complexity

```bash
# Configuration
- Single network interface
- MTU: 1500 (default)
- Window size: Default
- Streams: 1, 4, 8

# Expected results
- Throughput: 50-70% higher than baseline
- Allocations: Near-zero per send
- CPU: 20-30% lower per Gbps
```

### Scenario 2: Multipath WAN Bonding
**Purpose:** Validate optimization under production multipath scenario

```bash
# Configuration
- 2-4 network paths (LTE + WiFi + Ethernet)
- Multipath scheduler: weighted or aggregate
- Streams: Multiple concurrent

# Expected results
- Aggregate throughput significantly higher
- Per-path allocations reduced
- Scheduler overhead reduced
```

### Scenario 3: Variable Packet Sizes
**Purpose:** Ensure optimization works across different MTUs

```bash
# Test with different MTUs
for mtu in 1200 1500 9000; do
    sudo ip link set dev eth0 mtu $mtu
    iperf3 -c <server> --quic -t 10 | tee throughput_mtu_${mtu}.txt
done

# Expected results
- Benefit scales with packet size
- Larger MTU = more allocations saved
- Jumbo frames (9000) show biggest improvement
```

### Scenario 4: High Connection Count
**Purpose:** Stress test with many concurrent connections

```bash
# Run 100 concurrent connections
for i in {1..100}; do
    iperf3 -c <server> --quic -t 60 &
done
wait

# Monitor slab fragmentation
watch -n 1 'sudo cat /proc/slabinfo | grep tquic'

# Expected results
- Memory pressure significantly reduced
- No slab fragmentation from allocations
- Sustained throughput under load
```

---

## 4. Profiling Tools and Validation

### A. Verify Allocation Reduction with ftrace

```bash
# Enable function tracing for kmem_cache_alloc
sudo su
cd /sys/kernel/debug/tracing
echo 0 > tracing_on
echo > trace

# Trace kmem_cache allocations
echo 'kmem_cache_alloc' > set_ftrace_filter
echo function > current_tracer
echo 1 > tracing_on

# Run short test
timeout 5 iperf3 -c <server> --quic

# Stop tracing and analyze
echo 0 > tracing_on
grep tquic_frame_cache trace | wc -l  # Should be near-zero

# Compare with baseline (expect 50+ allocations per send before optimization)
```

### B. Count memcpy Operations with perf

```bash
# Probe memcpy in tquic_output.c
sudo perf probe -x net/tquic/quic.ko --add 'tquic_output.c:370 memcpy_stream'
sudo perf probe -x net/tquic/quic.ko --add 'tquic_output.c:636 memcpy_coalesce'

# Record events during test
sudo perf record -e probe:memcpy_* -a -- sleep 10 &
iperf3 -c <server> --quic -t 10

# Analyze results
sudo perf report
sudo perf script | grep memcpy | wc -l

# Expected: Only memcpy_coalesce should fire (single copy)
```

### C. CPU Profiling with perf top

```bash
# Monitor CPU hotspots in real-time
sudo perf top -K

# Look for reduction in:
# - kmem_cache_alloc
# - __kmalloc
# - memcpy (should still appear, but only once per packet)

# Expected:
# - tquic_xmit should use less CPU
# - tquic_output_flush should use less CPU
# - No kmalloc in top functions
```

### D. Memory Allocation Tracking

```bash
# Monitor slab cache usage in real-time
watch -n 1 'sudo cat /proc/slabinfo | grep tquic_frame'

# Columns to watch:
# - active_objs: Should be low (only frames, not data allocations)
# - num_slabs: Should be stable (no growth from allocations)

# Compare before/after optimization
sudo slabtop -o | grep tquic
```

### E. Detailed Tracing with function_graph

```bash
# Trace complete packet path
sudo su
cd /sys/kernel/debug/tracing
echo function_graph > current_tracer
echo tquic_xmit > set_graph_function
echo 1 > tracing_on

# Run quick test
timeout 2 iperf3 -c <server> --quic

# Analyze call graph
echo 0 > tracing_on
less trace

# Expected in trace:
# - tquic_xmit calls tquic_assemble_packet (no kmalloc in between)
# - tquic_coalesce_frames has single memcpy
# - No kfree calls for frame->data (owns_data = false)
```

---

## 5. Validation Checklist

### Before Declaring Success

- [ ] **Throughput increased 50-70%** in single-path scenario
- [ ] **Allocations reduced to near-zero** per send (verified with ftrace)
- [ ] **memcpy count reduced by 50%** (verified with perf probe)
- [ ] **CPU usage reduced 20-30%** per Gbps (verified with mpstat/perf)
- [ ] **Latency not degraded** (verified with tcpdump timestamps)
- [ ] **Memory footprint reduced** (verified with slabinfo)
- [ ] **No memory leaks** after sustained testing (check slabinfo growth)
- [ ] **Multipath performance improved** proportionally
- [ ] **Works with all MTU sizes** (1200, 1500, 9000)
- [ ] **Stable under high connection count** (100+ concurrent)

### Regression Testing

- [ ] **All packet types work** (STREAM, CRYPTO, PATH_CHALLENGE)
- [ ] **Error paths don't leak** (simulate allocation failures)
- [ ] **Retransmissions work correctly**
- [ ] **Flow control still enforced**
- [ ] **Congestion control unaffected**

---

## 6. Performance Test Script Template

```bash
#!/bin/bash
# TQUIC Zero-Copy Performance Validation Script

set -e

RESULTS_DIR="zerocopy_perf_results_$(date +%Y%m%d_%H%M%S)"
mkdir -p "$RESULTS_DIR"

echo "=== TQUIC Zero-Copy Performance Test ==="
echo "Results will be saved to: $RESULTS_DIR"

# 1. Collect baseline system info
uname -a > "$RESULTS_DIR/system_info.txt"
cat /proc/cpuinfo | grep "model name" | head -1 >> "$RESULTS_DIR/system_info.txt"
free -h >> "$RESULTS_DIR/system_info.txt"

# 2. Load module and verify
sudo modprobe quic
lsmod | grep quic > "$RESULTS_DIR/module_loaded.txt"

# 3. Record initial slab state
sudo cat /proc/slabinfo | grep tquic > "$RESULTS_DIR/slabinfo_before.txt"

# 4. Run throughput benchmark
echo "Running throughput test..."
iperf3 -c SERVER_IP --quic -t 30 -P 4 -J > "$RESULTS_DIR/throughput.json"

# 5. Monitor allocations during test
echo "Monitoring allocations..."
sudo timeout 30 ftrace-trace kmem_cache_alloc > "$RESULTS_DIR/allocations.trace" &
sleep 1
iperf3 -c SERVER_IP --quic -t 20 > /dev/null
wait

# 6. Record final slab state
sudo cat /proc/slabinfo | grep tquic > "$RESULTS_DIR/slabinfo_after.txt"

# 7. Compare allocation counts
ALLOC_COUNT=$(grep tquic_frame_cache "$RESULTS_DIR/allocations.trace" | wc -l)
echo "Frame allocations during test: $ALLOC_COUNT" > "$RESULTS_DIR/summary.txt"

# 8. Calculate improvement
echo "Expected: < 100 allocations (vs 50+ per send in baseline)"
echo "Actual: $ALLOC_COUNT" >> "$RESULTS_DIR/summary.txt"

echo "=== Test Complete ==="
echo "Results saved to: $RESULTS_DIR"
```

---

## 7. Expected Results Summary

### Quantitative Targets

| Metric | Baseline | After Zero-Copy | Improvement |
|--------|----------|-----------------|-------------|
| Throughput | 1.0 Gbps | 1.5-1.7 Gbps | +50-70% |
| Allocations/send | 50+ | 0-2 | -96% to -100% |
| memcpy/packet | 2 | 1 | -50% |
| CPU per Gbps | 100% | 70-80% | -20% to -30% |
| Peak memory | 100 MB | 60-70 MB | -30% to -40% |

### Qualitative Indicators

- **Smooth throughput:** No jitter from allocation overhead
- **Linear scaling:** Performance scales with CPU cores
- **Low softirq:** Network interrupt processing more efficient
- **Stable memory:** No slab fragmentation or growth over time

---

## 8. Troubleshooting Performance Issues

### If throughput improvement < 50%:

1. Check that optimized code is actually running:
   ```bash
   sudo perf probe -L tquic_output.c:1896  # Should show data_ref assignment
   ```

2. Verify allocations actually reduced:
   ```bash
   sudo ftrace | grep kmalloc | grep tquic
   ```

3. Check for bottlenecks elsewhere:
   ```bash
   sudo perf top -K  # Look for new hotspots
   ```

### If allocations not reduced:

1. Check owns_data flag is false:
   ```bash
   sudo crash  # Use crash utility to inspect live frame structures
   ```

2. Verify code path is taken:
   ```bash
   sudo perf probe 'tquic_output.c:1900 frame->owns_data'
   sudo perf record -e probe:* -- iperf3 ...
   ```

### If memory leaks detected:

1. Monitor slab growth:
   ```bash
   watch -d 'sudo cat /proc/slabinfo | grep tquic'
   ```

2. Check for missing kfree on error paths:
   ```bash
   sudo ftrace function_graph on error paths
   ```

---

## 9. Integration with CI/CD

### Automated Performance Regression Test

```yaml
# .github/workflows/perf-test.yml
name: TQUIC Performance Test

on: [push, pull_request]

jobs:
  performance-test:
    runs-on: ubuntu-latest
    steps:
      - name: Build TQUIC
        run: make M=net/tquic

      - name: Run performance benchmark
        run: ./scripts/perf_test_zerocopy.sh

      - name: Check throughput threshold
        run: |
          THROUGHPUT=$(jq '.end.sum_received.bits_per_second' results/throughput.json)
          if [ $THROUGHPUT -lt 1500000000 ]; then
            echo "Performance regression detected!"
            exit 1
          fi

      - name: Upload results
        uses: actions/upload-artifact@v3
        with:
          name: perf-results
          path: zerocopy_perf_results_*
```

---

## 10. Documentation Updates

After successful validation, update:

- [ ] `README.md`: Add performance characteristics section
- [ ] `PERFORMANCE.md`: Document zero-copy optimization details
- [ ] `CHANGELOG.md`: Record 50-70% throughput improvement
- [ ] Code comments: Add perf test results as comments in tquic_output.c

---

**End of Performance Testing Plan**

*This document should be executed after module compilation and before production deployment to validate the zero-copy transmission optimization delivers the expected 50-70% throughput improvement.*
