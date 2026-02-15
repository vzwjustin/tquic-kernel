#!/bin/bash
# SPDX-License-Identifier: GPL-2.0
#
# TQUIC Full Benchmark Suite Runner
#
# Runs all TQUIC benchmarks and generates a comprehensive report.
#

set -e

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RESULTS_DIR="${SCRIPT_DIR}/results/$(date +%Y%m%d_%H%M%S)"
TARGET="${TARGET:-127.0.0.1}"
PORT="${PORT:-4433}"
DURATION="${DURATION:-60}"
SAMPLES="${SAMPLES:-10000}"
MAX_CONNS="${MAX_CONNS:-100000}"
ITERATIONS="${ITERATIONS:-10}"
CI_MODE="${CI_MODE:-0}"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Target metrics
TARGET_THROUGHPUT_GBPS=9.0
TARGET_MULTIPATH_EFFICIENCY=0.95
TARGET_FAILOVER_MS=100
TARGET_MEMORY_KB=64

# Parse command line arguments
usage() {
    echo "Usage: $0 [OPTIONS]"
    echo ""
    echo "Options:"
    echo "  -t, --target ADDR      Target address (default: $TARGET)"
    echo "  -p, --port PORT        Target port (default: $PORT)"
    echo "  -d, --duration SEC     Duration for throughput tests (default: $DURATION)"
    echo "  -s, --samples NUM      Samples for latency tests (default: $SAMPLES)"
    echo "  -c, --max-conns NUM    Max connections (default: $MAX_CONNS)"
    echo "  -i, --iterations NUM   Failover iterations (default: $ITERATIONS)"
    echo "  -o, --output DIR       Output directory (default: results/timestamp)"
    echo "  --ci                   CI mode (non-interactive, fail on threshold breach)"
    echo "  --quick                Quick mode (shorter tests)"
    echo "  --throughput-only      Run only throughput benchmarks"
    echo "  --latency-only         Run only latency benchmarks"
    echo "  --connections-only     Run only connection benchmarks"
    echo "  --failover-only        Run only failover benchmarks"
    echo "  --scheduler-only       Run only scheduler benchmarks"
    echo "  -h, --help             Show this help"
    echo ""
    echo "Environment variables:"
    echo "  PRIMARY_IF             Primary network interface"
    echo "  BACKUP_IF              Backup network interface"
    echo "  MULTIPATH_IFS          Comma-separated interfaces for multipath"
}

# Parse arguments
RUN_THROUGHPUT=1
RUN_LATENCY=1
RUN_CONNECTIONS=1
RUN_FAILOVER=1
RUN_SCHEDULER=1
QUICK_MODE=0

while [[ $# -gt 0 ]]; do
    case $1 in
        -t|--target)
            TARGET="$2"
            shift 2
            ;;
        -p|--port)
            PORT="$2"
            shift 2
            ;;
        -d|--duration)
            DURATION="$2"
            shift 2
            ;;
        -s|--samples)
            SAMPLES="$2"
            shift 2
            ;;
        -c|--max-conns)
            MAX_CONNS="$2"
            shift 2
            ;;
        -i|--iterations)
            ITERATIONS="$2"
            shift 2
            ;;
        -o|--output)
            RESULTS_DIR="$2"
            shift 2
            ;;
        --ci)
            CI_MODE=1
            shift
            ;;
        --quick)
            QUICK_MODE=1
            DURATION=10
            SAMPLES=1000
            MAX_CONNS=1000
            ITERATIONS=3
            shift
            ;;
        --throughput-only)
            RUN_THROUGHPUT=1
            RUN_LATENCY=0
            RUN_CONNECTIONS=0
            RUN_FAILOVER=0
            RUN_SCHEDULER=0
            shift
            ;;
        --latency-only)
            RUN_THROUGHPUT=0
            RUN_LATENCY=1
            RUN_CONNECTIONS=0
            RUN_FAILOVER=0
            RUN_SCHEDULER=0
            shift
            ;;
        --connections-only)
            RUN_THROUGHPUT=0
            RUN_LATENCY=0
            RUN_CONNECTIONS=1
            RUN_FAILOVER=0
            RUN_SCHEDULER=0
            shift
            ;;
        --failover-only)
            RUN_THROUGHPUT=0
            RUN_LATENCY=0
            RUN_CONNECTIONS=0
            RUN_FAILOVER=1
            RUN_SCHEDULER=0
            shift
            ;;
        --scheduler-only)
            RUN_THROUGHPUT=0
            RUN_LATENCY=0
            RUN_CONNECTIONS=0
            RUN_FAILOVER=0
            RUN_SCHEDULER=1
            shift
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            echo "Unknown option: $1"
            usage
            exit 1
            ;;
    esac
done

# Logging functions
log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[PASS]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[FAIL]${NC} $1"
}

log_header() {
    echo ""
    echo "================================================================"
    echo " $1"
    echo "================================================================"
}

# Check prerequisites
check_prerequisites() {
    log_header "Checking Prerequisites"

    # Check for root
    if [[ $EUID -ne 0 ]]; then
        log_warning "Not running as root - some tests may fail"
    fi

    # Check for benchmark binaries
    local missing=0
    for bin in tquic_bench_throughput tquic_bench_latency tquic_bench_connections \
               tquic_bench_failover tquic_bench_scheduler; do
        if [[ ! -x "${SCRIPT_DIR}/${bin}" ]]; then
            log_error "Missing binary: ${bin}"
            missing=1
        fi
    done

    if [[ $missing -eq 1 ]]; then
        log_info "Run 'make' to build the benchmarks first"
        exit 1
    fi

    # Check for TQUIC module
    if lsmod | grep -q "^tquic "; then
        log_success "TQUIC module is loaded"
    else
        log_warning "TQUIC module not loaded - using simulated mode"
    fi

    # Check target connectivity
    if ping -c 1 -W 1 "$TARGET" >/dev/null 2>&1; then
        log_success "Target $TARGET is reachable"
    else
        log_warning "Target $TARGET is not reachable - tests may fail"
    fi

    log_success "Prerequisites check complete"
}

# Create results directory
setup_results_dir() {
    mkdir -p "$RESULTS_DIR"
    log_info "Results will be saved to: $RESULTS_DIR"

    # Create symlink to latest
    ln -sfn "$(basename "$RESULTS_DIR")" "${SCRIPT_DIR}/results/latest"

    # Save test configuration
    cat > "${RESULTS_DIR}/config.json" << EOF
{
  "target": "$TARGET",
  "port": $PORT,
  "duration_sec": $DURATION,
  "samples": $SAMPLES,
  "max_connections": $MAX_CONNS,
  "failover_iterations": $ITERATIONS,
  "quick_mode": $QUICK_MODE,
  "ci_mode": $CI_MODE,
  "timestamp": "$(date -Iseconds)",
  "kernel": "$(uname -r)",
  "hostname": "$(hostname)"
}
EOF
}

# Run throughput benchmark
run_throughput_benchmark() {
    log_header "Running Throughput Benchmark"

    local extra_args=""
    if [[ -n "$MULTIPATH_IFS" ]]; then
        extra_args="-m $MULTIPATH_IFS"
    fi

    "${SCRIPT_DIR}/tquic_bench_throughput" \
        -t "$TARGET" \
        -p "$PORT" \
        -d "$DURATION" \
        -s "64,512,1500,9000" \
        $extra_args \
        -v \
        -r "${RESULTS_DIR}/throughput.json"

    if [[ $? -eq 0 ]]; then
        log_success "Throughput benchmark completed"
    else
        log_error "Throughput benchmark failed"
        return 1
    fi
}

# Run latency benchmark
run_latency_benchmark() {
    log_header "Running Latency Benchmark"

    "${SCRIPT_DIR}/tquic_bench_latency" \
        -t "$TARGET" \
        -p "$PORT" \
        -n "$SAMPLES" \
        -H \
        -v \
        -r "${RESULTS_DIR}/latency.json"

    if [[ $? -eq 0 ]]; then
        log_success "Latency benchmark completed"
    else
        log_error "Latency benchmark failed"
        return 1
    fi
}

# Run connection benchmark
run_connection_benchmark() {
    log_header "Running Connection Benchmark"

    "${SCRIPT_DIR}/tquic_bench_connections" \
        -t "$TARGET" \
        -p "$PORT" \
        -m "$MAX_CONNS" \
        -d "$DURATION" \
        -z \
        -M \
        -v \
        -r "${RESULTS_DIR}/connections.json"

    if [[ $? -eq 0 ]]; then
        log_success "Connection benchmark completed"
    else
        log_error "Connection benchmark failed"
        return 1
    fi
}

# Run failover benchmark
run_failover_benchmark() {
    log_header "Running Failover Benchmark"

    local primary_if="${PRIMARY_IF:-eth0}"
    local backup_if="${BACKUP_IF:-eth1}"

    "${SCRIPT_DIR}/tquic_bench_failover" \
        -P "$primary_if" \
        -B "$backup_if" \
        -t "$TARGET" \
        -p "$PORT" \
        -n "$ITERATIONS" \
        -v \
        -r "${RESULTS_DIR}/failover.json"

    if [[ $? -eq 0 ]]; then
        log_success "Failover benchmark completed"
    else
        log_error "Failover benchmark failed"
        return 1
    fi
}

# Run scheduler benchmark
run_scheduler_benchmark() {
    log_header "Running Scheduler Benchmark"

    local interfaces="${MULTIPATH_IFS:-lo,lo}"

    "${SCRIPT_DIR}/tquic_bench_scheduler" \
        -a "minrtt,roundrobin,weighted,blest,ecf" \
        -i "$interfaces" \
        -t "$TARGET" \
        -p "$PORT" \
        -d 30 \
        -O \
        -v \
        -r "${RESULTS_DIR}/scheduler.json"

    if [[ $? -eq 0 ]]; then
        log_success "Scheduler benchmark completed"
    else
        log_error "Scheduler benchmark failed"
        return 1
    fi
}

# Generate HTML report
generate_report() {
    log_header "Generating Report"

    if [[ -x "${SCRIPT_DIR}/generate_report.py" ]]; then
        "${SCRIPT_DIR}/generate_report.py" "$RESULTS_DIR" > "${RESULTS_DIR}/report.html"
        log_success "Report generated: ${RESULTS_DIR}/report.html"
    else
        log_warning "generate_report.py not found, skipping HTML report"
    fi
}

# Check results against thresholds
check_thresholds() {
    log_header "Checking Against Target Metrics"

    local failures=0

    # Check throughput
    if [[ -f "${RESULTS_DIR}/throughput.json" ]]; then
        local throughput=$(python3 -c "import json; d=json.load(open('${RESULTS_DIR}/throughput.json')); print(max([r['gbps'] for r in d.get('results', [])]))" 2>/dev/null || echo "0")
        if (( $(echo "$throughput >= $TARGET_THROUGHPUT_GBPS" | bc -l) )); then
            log_success "Throughput: ${throughput} Gbps >= ${TARGET_THROUGHPUT_GBPS} Gbps"
        else
            log_error "Throughput: ${throughput} Gbps < ${TARGET_THROUGHPUT_GBPS} Gbps"
            failures=$((failures + 1))
        fi
    fi

    # Check failover time
    if [[ -f "${RESULTS_DIR}/failover.json" ]]; then
        local failover_time=$(python3 -c "import json; d=json.load(open('${RESULTS_DIR}/failover.json')); print(d.get('failover', {}).get('failover_time_ms', 999))" 2>/dev/null || echo "999")
        if (( $(echo "$failover_time <= $TARGET_FAILOVER_MS" | bc -l) )); then
            log_success "Failover time: ${failover_time} ms <= ${TARGET_FAILOVER_MS} ms"
        else
            log_error "Failover time: ${failover_time} ms > ${TARGET_FAILOVER_MS} ms"
            failures=$((failures + 1))
        fi
    fi

    # Check memory per connection
    if [[ -f "${RESULTS_DIR}/connections.json" ]]; then
        local memory=$(python3 -c "import json; d=json.load(open('${RESULTS_DIR}/connections.json')); print(d.get('connections', {}).get('memory_per_conn_kb', 999))" 2>/dev/null || echo "999")
        if (( $(echo "$memory <= $TARGET_MEMORY_KB" | bc -l) )); then
            log_success "Memory per connection: ${memory} KB <= ${TARGET_MEMORY_KB} KB"
        else
            log_error "Memory per connection: ${memory} KB > ${TARGET_MEMORY_KB} KB"
            failures=$((failures + 1))
        fi
    fi

    echo ""
    if [[ $failures -eq 0 ]]; then
        log_success "All target metrics met!"
        return 0
    else
        log_error "$failures target metric(s) not met"
        return 1
    fi
}

# Print summary
print_summary() {
    log_header "Benchmark Summary"

    echo "Results directory: $RESULTS_DIR"
    echo ""
    echo "Generated files:"
    ls -la "$RESULTS_DIR"
    echo ""

    if [[ -f "${RESULTS_DIR}/report.html" ]]; then
        echo "View the report at: file://${RESULTS_DIR}/report.html"
    fi
}

# Main execution
main() {
    echo ""
    echo "╔════════════════════════════════════════════════════════════════╗"
    echo "║              TQUIC Performance Benchmark Suite                 ║"
    echo "╚════════════════════════════════════════════════════════════════╝"
    echo ""

    check_prerequisites
    setup_results_dir

    local exit_code=0

    # Run selected benchmarks
    [[ $RUN_THROUGHPUT -eq 1 ]] && run_throughput_benchmark || exit_code=1
    [[ $RUN_LATENCY -eq 1 ]] && run_latency_benchmark || exit_code=1
    [[ $RUN_CONNECTIONS -eq 1 ]] && run_connection_benchmark || exit_code=1
    [[ $RUN_FAILOVER -eq 1 ]] && run_failover_benchmark || exit_code=1
    [[ $RUN_SCHEDULER -eq 1 ]] && run_scheduler_benchmark || exit_code=1

    # Generate report
    generate_report

    # Check thresholds
    if [[ $CI_MODE -eq 1 ]]; then
        check_thresholds || exit_code=1
    else
        check_thresholds
    fi

    # Print summary
    print_summary

    echo ""
    if [[ $exit_code -eq 0 ]]; then
        log_success "Benchmark suite completed successfully"
    else
        log_error "Benchmark suite completed with failures"
    fi

    exit $exit_code
}

main "$@"
