# SPDX-License-Identifier: GPL-2.0-only
#
# Makefile for TQUIC benchmark tools
#

CC := gcc
CFLAGS := -Wall -Wextra -O3 -march=native -pthread
LDFLAGS := -lpthread -lm -lrt

# Add NUMA support if available
CFLAGS += $(shell pkg-config --cflags libnuma 2>/dev/null)
LDFLAGS += $(shell pkg-config --libs libnuma 2>/dev/null || echo "")

# Kernel headers
KERNEL_INCLUDE := -I/lib/modules/$(shell uname -r)/build/include
CFLAGS += $(KERNEL_INCLUDE)

# TQUIC module headers
TQUIC_INCLUDE := -I$(CURDIR)/..
CFLAGS += $(TQUIC_INCLUDE)

# Debug build
ifdef DEBUG
    CFLAGS += -g -DDEBUG -fsanitize=address
    LDFLAGS += -fsanitize=address
endif

# All benchmark targets
TARGETS := tquic_bench_throughput \
           tquic_bench_latency \
           tquic_bench_connections \
           tquic_bench_failover \
           tquic_bench_scheduler

# Common source files
COMMON_SRCS := bench_common.c
COMMON_OBJS := $(COMMON_SRCS:.c=.o)

.PHONY: all clean install check help

all: $(TARGETS)

# Individual benchmark builds
tquic_bench_throughput: tquic_bench_throughput.c $(COMMON_OBJS)
	$(CC) $(CFLAGS) -o $@ $< $(COMMON_OBJS) $(LDFLAGS)

tquic_bench_latency: tquic_bench_latency.c $(COMMON_OBJS)
	$(CC) $(CFLAGS) -o $@ $< $(COMMON_OBJS) $(LDFLAGS)

tquic_bench_connections: tquic_bench_connections.c $(COMMON_OBJS)
	$(CC) $(CFLAGS) -o $@ $< $(COMMON_OBJS) $(LDFLAGS)

tquic_bench_failover: tquic_bench_failover.c $(COMMON_OBJS)
	$(CC) $(CFLAGS) -o $@ $< $(COMMON_OBJS) $(LDFLAGS)

tquic_bench_scheduler: tquic_bench_scheduler.c $(COMMON_OBJS)
	$(CC) $(CFLAGS) -o $@ $< $(COMMON_OBJS) $(LDFLAGS)

# Common object files
%.o: %.c bench_common.h
	$(CC) $(CFLAGS) -c -o $@ $<

# Create results directory
results:
	mkdir -p results

# Run all benchmarks
run: all results
	./run_benchmarks.sh

# Quick smoke test
check: all
	@echo "Running smoke tests..."
	@./tquic_bench_throughput --help >/dev/null && echo "  throughput: OK"
	@./tquic_bench_latency --help >/dev/null && echo "  latency: OK"
	@./tquic_bench_connections --help >/dev/null && echo "  connections: OK"
	@./tquic_bench_failover --help >/dev/null && echo "  failover: OK"
	@./tquic_bench_scheduler --help >/dev/null && echo "  scheduler: OK"
	@echo "All smoke tests passed."

# Install to /usr/local/bin
install: all
	install -d $(DESTDIR)/usr/local/bin
	install -m 755 $(TARGETS) $(DESTDIR)/usr/local/bin/
	install -m 755 run_benchmarks.sh $(DESTDIR)/usr/local/bin/tquic_run_benchmarks
	install -m 755 generate_report.py $(DESTDIR)/usr/local/bin/tquic_generate_report

# Clean build artifacts
clean:
	rm -f $(TARGETS) $(COMMON_OBJS)
	rm -rf *.dSYM

# Clean everything including results
distclean: clean
	rm -rf results

# Help
help:
	@echo "TQUIC Benchmark Suite Makefile"
	@echo ""
	@echo "Targets:"
	@echo "  all        - Build all benchmark tools (default)"
	@echo "  check      - Run smoke tests"
	@echo "  run        - Run full benchmark suite"
	@echo "  install    - Install tools to /usr/local/bin"
	@echo "  clean      - Remove build artifacts"
	@echo "  distclean  - Remove build artifacts and results"
	@echo ""
	@echo "Variables:"
	@echo "  DEBUG=1    - Build with debug symbols and sanitizers"
	@echo ""
	@echo "Examples:"
	@echo "  make                    # Build all benchmarks"
	@echo "  make DEBUG=1            # Build with debug support"
	@echo "  make tquic_bench_throughput  # Build single benchmark"
	@echo "  sudo make run           # Run benchmarks (requires root)"
