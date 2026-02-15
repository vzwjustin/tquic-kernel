# TQUIC Kernel Module Performance Benchmarks

This directory contains comprehensive benchmarking tools for the TQUIC kernel module.

## Overview

The TQUIC benchmark suite measures performance across several dimensions:

| Benchmark | Description | Target Metric |
|-----------|-------------|---------------|
| Throughput | Data transfer rates | >9 Gbps @ 10G NIC |
| Multipath | Aggregated bandwidth | >95% of sum(path BWs) |
| Latency | RTT, jitter, percentiles | p99 < 2x p50 |
| Connections | Setup rate, capacity | <1 RTT (0-RTT support) |
| Failover | Recovery time | <100ms |
| Memory | Per-connection overhead | <64KB per connection |
| Scheduler | Algorithm comparison | Minimal overhead |

## Prerequisites

### Kernel Requirements
- Linux kernel 5.15+ with TQUIC module loaded
- Root privileges for kernel module access
- Test network interfaces configured

### Build Dependencies
```bash
# Ubuntu/Debian
sudo apt-get install build-essential libnuma-dev libpthread-stubs0-dev

# RHEL/CentOS
sudo yum install gcc make numactl-devel
```

## Building the Benchmarks

```bash
cd net/tquic/bench
make
```

Individual targets:
```bash
make tquic_bench_throughput
make tquic_bench_latency
make tquic_bench_connections
make tquic_bench_failover
make tquic_bench_scheduler
```

## Running Benchmarks

### Quick Start
```bash
sudo ./run_benchmarks.sh
```

### Individual Benchmarks

#### Throughput Benchmark
```bash
sudo ./tquic_bench_throughput \
    --interface eth0 \
    --duration 60 \
    --packet-sizes 64,512,1500,9000,65535 \
    --multipath eth0,eth1 \
    --report results/throughput.json
```

Options:
- `--interface`: Primary network interface
- `--duration`: Test duration in seconds
- `--packet-sizes`: Comma-separated list of packet sizes
- `--multipath`: Comma-separated list of interfaces for aggregation test
- `--report`: Output file path (JSON format)

#### Latency Benchmark
```bash
sudo ./tquic_bench_latency \
    --target 192.168.1.1 \
    --samples 10000 \
    --interval 1ms \
    --histogram \
    --report results/latency.json
```

Options:
- `--target`: Target IP address
- `--samples`: Number of RTT samples to collect
- `--interval`: Delay between samples
- `--histogram`: Enable histogram output
- `--report`: Output file path

#### Connection Benchmark
```bash
sudo ./tquic_bench_connections \
    --target 192.168.1.1 \
    --max-conns 100000 \
    --rate 10000 \
    --zero-rtt \
    --report results/connections.json
```

Options:
- `--target`: Target server address
- `--max-conns`: Maximum concurrent connections
- `--rate`: Connection attempts per second
- `--zero-rtt`: Enable 0-RTT connection resumption
- `--report`: Output file path

#### Failover Benchmark
```bash
sudo ./tquic_bench_failover \
    --primary eth0 \
    --backup eth1 \
    --iterations 100 \
    --report results/failover.json
```

Options:
- `--primary`: Primary network interface
- `--backup`: Backup/failover interface
- `--iterations`: Number of failover tests
- `--report`: Output file path

#### Scheduler Benchmark
```bash
sudo ./tquic_bench_scheduler \
    --algorithms minrtt,roundrobin,weighted,redundant \
    --duration 30 \
    --interfaces eth0,eth1,eth2 \
    --report results/scheduler.json
```

Options:
- `--algorithms`: Comma-separated list of scheduling algorithms
- `--duration`: Test duration per algorithm
- `--interfaces`: Available network paths
- `--report`: Output file path

## Generating Reports

After running benchmarks, generate an HTML report:
```bash
./generate_report.py results/20240101_120000/ > results/report.html
```

The report includes:
- Performance summary tables
- Throughput charts
- Latency distribution graphs
- Comparison with target metrics
- Regression detection (if historical data available)

## Interpreting Results

### Throughput Metrics
- **Gbps**: Gigabits per second of application data
- **PPS**: Packets per second
- **CPU%**: CPU utilization during test
- **Efficiency**: Gbps per CPU core

### Latency Metrics
- **RTT**: Round-trip time in microseconds
- **Jitter**: Variation in RTT
- **p50/p95/p99/p99.9**: Latency percentiles

### Connection Metrics
- **CPS**: Connections per second
- **0-RTT Rate**: Percentage of 0-RTT connections
- **Memory**: Per-connection memory usage

### Failover Metrics
- **Failover Time**: Time to detect and switch paths
- **Packet Loss**: Packets lost during failover
- **Recovery Time**: Time to restore full bandwidth

## CI/CD Integration

The benchmarks can be integrated into CI/CD pipelines:

```yaml
# Example GitHub Actions workflow
performance-test:
  runs-on: self-hosted
  steps:
    - name: Run benchmarks
      run: |
        cd net/tquic/bench
        sudo ./run_benchmarks.sh --ci

    - name: Check thresholds
      run: |
        ./check_thresholds.py results/latest/ --fail-on-regression
```

## Troubleshooting

### Common Issues

1. **Permission denied**: Run benchmarks with sudo
2. **Module not loaded**: `sudo modprobe tquic`
3. **Interface not found**: Check interface names with `ip link`
4. **Low performance**: Disable CPU frequency scaling:
   ```bash
   for cpu in /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor; do
       echo performance | sudo tee $cpu
   done
   ```

### Debug Mode
```bash
sudo ./tquic_bench_throughput --debug --verbose
```

## Contributing

When adding new benchmarks:
1. Follow existing code style
2. Add documentation to this README
3. Include target metrics
4. Ensure reproducibility

## License

GPL-2.0 (same as Linux kernel)
