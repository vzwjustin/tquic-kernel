# TQUIC Interoperability Test Framework

## Overview

This framework provides comprehensive interoperability testing for the TQUIC
kernel implementation against major QUIC implementations in userspace.

## Supported QUIC Implementations

| Implementation | Organization | Multipath Support | Notes |
|---------------|--------------|-------------------|-------|
| quiche        | Cloudflare   | No                | Rust-based, widely deployed |
| msquic        | Microsoft    | No                | C-based, Windows/Linux |
| ngtcp2        | nghttp2      | No                | C-based, reference impl |
| picoquic      | Private Octopus | Yes            | C-based, multipath pioneer |

## Directory Structure

```
test/interop/
├── README.md                 # This file
├── tquic_interop.sh         # Main test runner
├── setup_namespaces.sh      # Network namespace setup
├── test_cases/
│   ├── handshake_test.sh    # Basic connection establishment
│   ├── zerortt_test.sh      # 0-RTT session resumption
│   ├── migration_test.sh    # Connection migration
│   ├── multipath_test.sh    # Multipath aggregation
│   └── failover_test.sh     # Path failover testing
├── peers/
│   ├── quiche_peer.sh       # Cloudflare quiche setup
│   ├── msquic_peer.sh       # Microsoft msquic setup
│   ├── ngtcp2_peer.sh       # ngtcp2 setup
│   └── picoquic_peer.sh     # picoquic setup
└── tools/
    ├── tquic_test_server.c  # Minimal test server
    ├── tquic_test_client.c  # Minimal test client
    └── Makefile             # Build tools
```

## Requirements

### System Requirements
- Linux kernel 5.10+ with TQUIC module
- Root privileges (for network namespaces and tc)
- iproute2 with tc netem support

### Peer Implementations (install as needed)
```bash
# quiche (Rust)
git clone https://github.com/cloudflare/quiche
cd quiche && cargo build --examples

# msquic
git clone https://github.com/microsoft/msquic
cd msquic && mkdir build && cd build
cmake -G 'Unix Makefiles' .. && cmake --build .

# ngtcp2
git clone https://github.com/ngtcp2/ngtcp2
cd ngtcp2 && autoreconf -i
./configure && make

# picoquic
git clone https://github.com/private-octopus/picoquic
cd picoquic && cmake . && make
```

## Quick Start

### Run All Tests
```bash
sudo ./tquic_interop.sh --all
```

### Run Specific Test Against Specific Peer
```bash
sudo ./tquic_interop.sh --peer quiche --test handshake
```

### Run With Network Impairment
```bash
sudo ./tquic_interop.sh --peer picoquic --test multipath \
    --latency 50ms --bandwidth 100mbit --loss 1%
```

## Test Cases

### handshake_test.sh
Tests basic QUIC connection establishment:
- Version negotiation
- Cryptographic handshake (TLS 1.3)
- Connection ID exchange
- Transport parameter negotiation

### zerortt_test.sh
Tests 0-RTT session resumption:
- Session ticket storage/retrieval
- Early data transmission
- Anti-replay protection
- Fallback to 1-RTT

### migration_test.sh
Tests connection migration:
- Client-initiated migration
- NAT rebinding simulation
- Path validation
- Preferred address handling

### multipath_test.sh
Tests multipath QUIC (RFC 9000 extension):
- Path establishment
- Bandwidth aggregation
- Latency optimization
- Path scheduling algorithms

### failover_test.sh
Tests path failover:
- Primary path failure detection
- Automatic failover to backup
- Recovery and re-establishment
- Hitless failover metrics

## Network Topology

The test framework creates isolated network namespaces:

```
                    ┌─────────────────────────────────────────┐
                    │           Host Network                   │
                    │                                          │
  ┌─────────────────┼──────────────┐    ┌─────────────────────┼─────┐
  │  tquic_client   │              │    │                     │     │
  │  namespace      │              │    │  tquic_server       │     │
  │                 │              │    │  namespace          │     │
  │  10.0.1.1/24 ───┼── veth0 ─────┼────┼── veth1 ── 10.0.1.2/24   │
  │                 │              │    │                     │     │
  │  10.0.2.1/24 ───┼── veth2 ─────┼────┼── veth3 ── 10.0.2.2/24   │
  │  (multipath)    │              │    │  (multipath)        │     │
  └─────────────────┼──────────────┘    └─────────────────────┼─────┘
                    │                                          │
                    └─────────────────────────────────────────┘
```

## Configuration

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| TQUIC_INTEROP_PEERS | /opt/quic-peers | Peer installation directory |
| TQUIC_INTEROP_CERTS | ./certs | TLS certificate directory |
| TQUIC_INTEROP_TIMEOUT | 30 | Test timeout in seconds |
| TQUIC_INTEROP_VERBOSE | 0 | Enable verbose output |

### Network Impairment Options

```bash
--latency <delay>      # Add latency (e.g., 50ms, 100ms)
--bandwidth <rate>     # Limit bandwidth (e.g., 10mbit, 100mbit)
--loss <percent>       # Packet loss (e.g., 0.1%, 1%, 5%)
--jitter <variation>   # Latency jitter (e.g., 10ms)
--reorder <percent>    # Packet reordering (e.g., 1%)
```

## Output and Reporting

Test results are written to:
- Console: Summary and failures
- `results/`: Detailed logs per test
- `results/interop_matrix.html`: Visual compatibility matrix

### Exit Codes
- 0: All tests passed
- 1: One or more tests failed
- 2: Setup/configuration error
- 3: Peer not available

## Writing Custom Tests

Create a new test in `test_cases/`:

```bash
#!/bin/bash
# my_test.sh - Description of test

source "$(dirname "$0")/../common.sh"

test_my_feature() {
    local peer="$1"
    local client_ns="$2"
    local server_ns="$3"

    # Start server in server namespace
    start_peer_server "$peer" "$server_ns"

    # Run TQUIC client in client namespace
    run_tquic_client "$client_ns" "$SERVER_ADDR" "$SERVER_PORT"

    # Verify results
    check_connection_established
    check_data_transferred

    return $?
}

# Execute test
run_test "my_feature" test_my_feature "$@"
```

## Troubleshooting

### Common Issues

1. **Permission denied**: Run with sudo
2. **Module not loaded**: `modprobe tquic`
3. **Peer not found**: Check TQUIC_INTEROP_PEERS path
4. **Timeout**: Increase TQUIC_INTEROP_TIMEOUT

### Debug Mode
```bash
sudo TQUIC_INTEROP_VERBOSE=1 ./tquic_interop.sh --peer quiche --test handshake
```

### Capture Traffic
```bash
sudo ./tquic_interop.sh --peer quiche --test handshake --capture
# PCAP saved to results/handshake_quiche.pcap
```

## Contributing

When adding new tests:
1. Follow existing naming conventions
2. Document expected behavior
3. Handle cleanup on failure
4. Support all command-line options

## License

This test framework is part of the TQUIC kernel implementation and is
licensed under GPL-2.0.
