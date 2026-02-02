# TQUIC Kernel

**True QUIC** - A deep kernel-level QUIC implementation for True WAN Bonding (MPQUIC).

## Overview

TQUIC is a complete, production-ready kernel module implementing the QUIC protocol (RFC 9000, 9001, 9002) with multipath support for WAN bonding. Unlike userspace QUIC implementations, TQUIC operates directly in the Linux kernel for maximum performance and integration with the networking stack.

**171,000+ lines of C code** implementing the full QUIC/HTTP3 stack with advanced multipath, security, and performance features.

## Features

### Core QUIC Protocol (RFC 9000)
- **Connection Management**: Full connection lifecycle with states (IDLE, CONNECTING, HANDSHAKE, CONNECTED, CLOSING, DRAINING, CLOSED)
- **Packet Types**: Initial, Handshake, 0-RTT, 1-RTT, Version Negotiation, Retry
- **Stream Multiplexing**: Bidirectional and unidirectional streams with flow control
- **All 28+ Frame Types**: PADDING, PING, ACK, CRYPTO, STREAM, MAX_DATA, NEW_CONNECTION_ID, PATH_CHALLENGE/RESPONSE, DATAGRAM, and more
- **Connection IDs**: Multiple CID support with retirement and rotation
- **Variable-Length Integers**: Complete varint codec (1, 2, 4, 8 byte variants)

### TLS 1.3 & Cryptography (RFC 9001)
- **Kernel TLS Integration**: Native kernel TLS subsystem integration
- **AEAD Ciphers**: AES-128-GCM, AES-256-GCM, ChaCha20-Poly1305
- **Header Protection**: AES-ECB and ChaCha20-based HP
- **Key Update**: Per RFC 9001 §5.6 with configurable update intervals
- **0-RTT Support**: Early data with anti-replay protection
- **Session Resumption**: PSK-based resumption with session tickets
- **Certificate Validation**: Full chain verification with kernel keyring

### Loss Detection & Recovery (RFC 9002)
- **RTT Estimation**: EWMA-smoothed RTT tracking
- **Loss Detection**: Timeout (PTO) and reordering threshold
- **Persistent Congestion**: Detection and recovery
- **ACK Frequency**: Configurable ACK delay and MAX_ACK_DELAY

### HTTP/3 Protocol (RFC 9114)
- **Full HTTP/3 Semantics**: Request/response multiplexing over QUIC
- **Stream Priorities**: Weight-based and urgency/incremental (RFC 9218)
- **Extended CONNECT**: Protocol upgrade for WebTransport (RFC 9220)
- **Server Push**: Full server push support
- **Settings Negotiation**: QPACK table size, max field section size
- **Frame Types**: DATA, HEADERS, SETTINGS, GOAWAY, CANCEL_PUSH, PUSH_PROMISE

### QPACK Header Compression (RFC 9204)
- **Dynamic Table**: Configurable size with encoder/decoder streams
- **Static Table**: 61 standard header entries
- **Literal Encoding**: Name reference and dynamic index support
- **Table State Sync**: Encoder stream updates and decoder acknowledgments

### DATAGRAM Extension (RFC 9221)
- **Unreliable Datagrams**: For latency-sensitive data
- **Configurable Max Size**: Transport parameter negotiation
- **Flow Control Exemption**: Per RFC 9221 specification

### WebTransport (draft-ietf-webtrans-http3)
- **Extended CONNECT**: `:protocol=webtransport` activation
- **Session Management**: CONNECT stream ID binding
- **Stream Types**: Reliable and unreliable stream support
- **Session Flow Control**: WT_MAX_DATA capsules
- **Graceful Termination**: WT_CLOSE_SESSION capsule

### MASQUE Protocol
- **CONNECT-UDP (RFC 9298)**: UDP tunneling over HTTP/3
- **CONNECT-IP (RFC 9484)**: IP-level proxying over HTTP/3
- **HTTP Datagrams (RFC 9297)**: For tunneled traffic
- **Capsule Protocol**: Full encoding/decoding
- **QUIC-Aware Proxy**: Connection multiplexing support

### QUIC Version 2 (RFC 9369)
- **Version 2 Support**: Version constant `0x6b3343cf`
- **Version 2 Crypto**: Specific initial salt and HKDF labels
- **Compatible Negotiation**: RFC 9368 version information transport parameter
- **Version-Aware Encoding**: Automatic packet type handling

### GREASE Support (RFC 9287)
- **Random Reserved Bits**: In packet headers
- **GREASE Transport Parameters**: For forward compatibility
- **Greased Version Fields**: In version negotiation

### Multipath QUIC (draft-ietf-quic-multipath)
- **True WAN Bonding**: Aggregate bandwidth across multiple network paths
- **Per-Packet Scheduling**: NOT flow-pinning - true packet-level distribution
- **Path Management**: Dynamic path addition, removal, and failover
- **Path Validation**: PATH_CHALLENGE/PATH_RESPONSE per RFC 9000
- **Preferred Address**: Server-initiated migration support (RFC 9000 §9.6)
- **Multipath Frames**: MP_ACK, MP_NEW_CONNECTION_ID, MP_RETIRE_CONNECTION_ID, PATH_ABANDON, PATH_STATUS
- **Path ID in AEAD**: Cryptographic separation per path
- **Per-Path Packet Spaces**: Independent packet number spaces

### Packet Schedulers
- **Round-Robin**: Cycle through available paths
- **Minimum RTT**: Select lowest-latency path
- **Weighted**: Proportional to available bandwidth
- **BLEST**: Blocking Estimation-based scheduling
- **ECF**: Earliest Completion First
- **Deadline-Aware**: Real-time packet scheduling
- **BPF struct_ops**: Custom schedulers via eBPF (14 kfuncs available)

### Congestion Control
| Algorithm | Description |
|-----------|-------------|
| CUBIC | Default CC algorithm (RFC 8312) |
| BBRv1 | Google Bottleneck Bandwidth and RTT |
| BBRv2 | Next-generation BBR with improved loss recovery |
| BBRv3 | Latest BBR variant |
| Copa | Delay-based congestion control |
| Westwood+ | Rate-based CC for wireless links |
| Prague | L4S-compatible congestion control |
| OLIA | Opportunistic Linked Increases (multipath) |
| LIA | Linked Increases Algorithm (multipath) |
| BALIA | Balanced Linked Adaptation (multipath) |

### L4S / ECN Support
- **ECN Validation**: In ACK frames with per-path tracking
- **L4S Support**: ECT(1) marking for L4S-compatible flows
- **AccECN**: Accurate ECN feedback protocol
- **Prague CC**: L4S-optimized congestion control

### QUIC Load Balancing (draft-ietf-quic-load-balancers)
- **Server ID Encoding**: In connection IDs
- **Configuration Distribution**: Load balancer protocol
- **Retry Service**: Shared state support
- **Stateless Retry**: Validation support

### Forward Error Correction (FEC)
- **Reed-Solomon FEC**: For high-loss paths
- **XOR-Based FEC**: Reduced computational overhead
- **FEC Scheduler**: Selective packet protection
- **Configurable Redundancy**: Per-path FEC levels

### Performance Optimizations
- **GRO/GSO**: Generic Receive/Segmentation Offload
- **Zero-Copy I/O**: MSG_ZEROCOPY for TX, page pinning for RX
- **AF_XDP**: eXpress Data Path for ultra-high performance
- **io_uring**: Async I/O with SQPOLL mode and buffer rings
- **NAPI Polling**: Interrupt reduction via polling mode
- **SmartNIC Offload**: FPGA/NIC integration for header processing
- **Hardware Crypto**: AES-NI/VAES detection and utilization

### Security Features
- **Anti-Replay Protection**: 0-RTT replay filter with configurable window
- **QUIC-LEAK Defense** (CVE-2025-54939): Pre-handshake memory exhaustion protection
- **CID Stuffing Protection** (CVE-2024-22189): RETIRE_CONNECTION_ID flooding mitigation
- **Optimistic ACK Detection**: Detection of ACKs for never-sent packets
- **PATH_CHALLENGE Flooding**: Rate limiting with crypto-grade RNG
- **Anti-Amplification**: RFC 9000 amplification limit enforcement
- **Spin Bit Privacy**: Three-level policy (always, never, probabilistic)
- **Connection Rate Limiting**: Per-IP and global limits
- **Reliable Reset**: RESET_STREAM_AT (0x24) for guaranteed delivery

### Observability & Diagnostics
- **qlog Support**: QUIC Event Logging (RFC 9293-compatible, v2 format)
- **Kernel Tracepoints**: Connection state, frame events, errors
- **Path Metrics**: Per-path RTT, bandwidth, loss rate
- **sock_diag**: `ss` command visibility for QUIC sockets
- **Procfs Statistics**: `/proc/net/tquic/stats`, `/proc/net/tquic_errors`
- **Sysctl Tunables**: ~30 configurable parameters at `/proc/sys/net/tquic/`

### Kernel Integration
- **Netfilter Hooks**: Firewall integration
- **sock_diag Support**: `ss` command visibility
- **Sysctl Interface**: `/proc/sys/net/tquic/`
- **Netlink Interface**: Userspace control plane
- **Per-Namespace Isolation**: Full netns support

## Building

### Out-of-Tree Module (Recommended)

Build against your running kernel without recompiling the entire kernel:

```bash
# Clone the repository
git clone https://github.com/vzwjustin/tquic-kernel.git
cd tquic-kernel/net/tquic

# Build the module
make -j$(nproc)

# Load the module
sudo insmod tquic.ko

# Verify
lsmod | grep tquic
dmesg | tail -20
```

Supported kernels: **Linux 6.x** (tested on 6.12)

### In-Tree Build

For custom kernel builds:

```bash
# Use provided router config
cp configs/router_minimal.config .config
make olddefconfig

# Or configure manually
make menuconfig  # Enable TQUIC under Networking → TQUIC

# Build
make -j$(nproc)

# Install
sudo make modules_install
sudo make install
```

## Verification

After loading the module:

```bash
# Check module is loaded
lsmod | grep tquic

# View sysctl parameters
ls /proc/sys/net/tquic/

# Check protocol registration
cat /proc/net/protocols | grep QUIC

# View statistics
cat /proc/net/tquic/stats
```

## Configuration

Sysctl tunables available at `/proc/sys/net/tquic/`:

| Parameter | Description |
|-----------|-------------|
| `max_connections` | Maximum concurrent connections |
| `max_streams_bidi` | Max bidirectional streams per connection |
| `max_streams_uni` | Max unidirectional streams per connection |
| `idle_timeout` | Connection idle timeout (ms) |
| `max_udp_payload` | Maximum UDP payload size |
| `ack_delay_exponent` | ACK delay exponent for timestamps |
| `max_ack_delay` | Maximum ACK delay (ms) |
| `active_connection_id_limit` | Max active CIDs |
| `initial_rtt` | Initial RTT estimate (ms) |
| `congestion_control` | Default CC algorithm |
| `multipath_enabled` | Enable/disable multipath |
| `scheduler` | Default packet scheduler |

## Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│                         User Space                                   │
│  ┌─────────┐  ┌─────────┐  ┌─────────┐  ┌──────────────┐           │
│  │ quicly  │  │  ngtcp2 │  │  msquic │  │ WebTransport │           │
│  └────┬────┘  └────┬────┘  └────┬────┘  └──────┬───────┘           │
└───────┼────────────┼────────────┼──────────────┼────────────────────┘
        │            │            │              │
┌───────▼────────────▼────────────▼──────────────▼────────────────────┐
│                      TQUIC Socket Layer                              │
│  ┌────────────────────────────────────────────────────────────────┐ │
│  │                    HTTP/3 + QPACK Layer                         │ │
│  │  ┌──────────┐ ┌────────┐ ┌─────────────┐ ┌──────────────────┐  │ │
│  │  │  HTTP/3  │ │  QPACK │ │ WebTransport│ │      MASQUE      │  │ │
│  │  │  Frames  │ │ Codec  │ │   Sessions  │ │ CONNECT-UDP/IP   │  │ │
│  │  └──────────┘ └────────┘ └─────────────┘ └──────────────────┘  │ │
│  └────────────────────────────────────────────────────────────────┘ │
│  ┌────────────────────────────────────────────────────────────────┐ │
│  │                   Connection Manager                            │ │
│  │  ┌────────┐ ┌────────┐ ┌────────┐ ┌────────────┐ ┌──────────┐ │ │
│  │  │ Crypto │ │ Streams│ │  ACK   │ │ Flow Ctrl  │ │ Datagram │ │ │
│  │  │  TLS   │ │  Mux   │ │Handler │ │            │ │          │ │ │
│  │  └────────┘ └────────┘ └────────┘ └────────────┘ └──────────┘ │ │
│  └────────────────────────────────────────────────────────────────┘ │
│  ┌────────────────────────────────────────────────────────────────┐ │
│  │                Path Manager (MPQUIC)                            │ │
│  │  ┌─────────┐ ┌─────────┐ ┌──────────┐ ┌───────────┐ ┌───────┐ │ │
│  │  │Scheduler│ │  Cong   │ │   Path   │ │ Migration │ │  FEC  │ │ │
│  │  │ (6 alg) │ │ Control │ │ Validate │ │           │ │       │ │ │
│  │  └─────────┘ └─────────┘ └──────────┘ └───────────┘ └───────┘ │ │
│  └────────────────────────────────────────────────────────────────┘ │
│  ┌────────────────────────────────────────────────────────────────┐ │
│  │                    Performance Layer                            │ │
│  │  ┌────────┐ ┌────────┐ ┌──────────┐ ┌───────────┐ ┌─────────┐ │ │
│  │  │GRO/GSO │ │Zero-Cp │ │  AF_XDP  │ │  io_uring │ │SmartNIC │ │ │
│  │  └────────┘ └────────┘ └──────────┘ └───────────┘ └─────────┘ │ │
│  └────────────────────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────────────────┘
                              │
┌─────────────────────────────▼───────────────────────────────────────┐
│                         UDP Layer                                    │
│                    (Netfilter hooks here)                            │
└─────────────────────────────────────────────────────────────────────┘
                              │
┌─────────────────────────────▼───────────────────────────────────────┐
│                       IP Layer (v4/v6)                               │
└─────────────────────────────────────────────────────────────────────┘
```

## Testing Infrastructure

### KUnit Tests (33+ test suites)
Comprehensive unit tests covering all protocol components:
- Frame encoding/decoding
- Packet parsing/generation
- Transport parameter negotiation
- Flow control enforcement
- Scheduler algorithms
- Security mechanisms (42K lines)

### Interoperability Testing
Test framework against major QUIC implementations:
- **quiche** (Cloudflare)
- **msquic** (Microsoft)
- **ngtcp2** (nghttp2)
- **picoquic** (multipath pioneer)

Test cases: handshake, 0-RTT, migration, multipath, failover

### Network Simulation
- Namespace-based isolated topology
- `tc netem` support: latency, bandwidth, loss, jitter, reordering

### Benchmarking Suite
- **throughput_bench**: Target >9 Gbps @ 10G NIC
- **latency_bench**: Target p99 < 2x p50
- **connections_bench**: 0-RTT rate measurement
- **failover_bench**: Target <100ms recovery
- **scheduler_bench**: Algorithm comparison

## Protocol Compliance

### RFCs Implemented
| RFC | Title |
|-----|-------|
| RFC 9000 | QUIC: A UDP-Based Multiplexed and Secure Transport |
| RFC 9001 | Using TLS to Secure QUIC |
| RFC 9002 | QUIC Loss Detection and Congestion Control |
| RFC 9114 | HTTP/3 |
| RFC 9204 | QPACK: Field Compression for HTTP/3 |
| RFC 9218 | Extensible Prioritization Scheme for HTTP |
| RFC 9220 | Bootstrapping WebSockets with HTTP/3 |
| RFC 9221 | An Unreliable Datagram Extension to QUIC |
| RFC 9287 | Greasing the QUIC Bit |
| RFC 9293 | Debugging Logging for QUIC (qlog) |
| RFC 9297 | HTTP Datagrams and the Capsule Protocol |
| RFC 9298 | Proxying UDP in HTTP |
| RFC 9368 | Compatible Version Negotiation for QUIC |
| RFC 9369 | QUIC Version 2 |
| RFC 9484 | Proxying IP in HTTP |

### Drafts Implemented
| Draft | Description |
|-------|-------------|
| draft-ietf-quic-multipath-17 | Multipath Extension for QUIC |
| draft-ietf-quic-load-balancers-21 | QUIC-LB: Generating Routable QUIC Connection IDs |
| draft-ietf-webtrans-http3-14 | WebTransport over HTTP/3 |
| draft-ietf-quic-reliable-stream-reset | Reliable QUIC Stream Resets |
| draft-smith-quic-receive-ts-03 | QUIC Extension for Reporting Packet Receive Timestamps |

## Use Cases

- **WAN Bonding**: Aggregate LTE, 5G, and wired connections for increased bandwidth and reliability
- **Failover**: Seamless connection migration when primary path fails (<100ms)
- **Mobile Networks**: Maintain connections across network transitions
- **High-Performance Proxies**: Kernel-level QUIC/HTTP3 termination
- **SD-WAN**: Software-defined WAN with QUIC transport
- **WebTransport Applications**: Real-time gaming, live streaming, collaborative tools
- **MASQUE Proxying**: Privacy-preserving proxy infrastructure

## Implementation Status

| Component | Status |
|-----------|--------|
| QUIC Core (RFC 9000) | ✅ Complete |
| TLS 1.3 Integration (RFC 9001) | ✅ Complete |
| Loss Detection (RFC 9002) | ✅ Complete |
| HTTP/3 (RFC 9114) | ✅ Complete |
| QPACK (RFC 9204) | ✅ Complete |
| DATAGRAM Extension (RFC 9221) | ✅ Complete |
| QUIC Version 2 (RFC 9369) | ✅ Complete |
| WebTransport | ✅ Complete |
| MASQUE (CONNECT-UDP/IP) | ✅ Complete |
| Multipath QUIC | ✅ Complete |
| Load Balancing Support | ✅ Complete |
| Forward Error Correction | ✅ Complete |
| AF_XDP / io_uring | ✅ Complete |
| Security Hardening | ✅ Complete |
| KUnit Test Suite | ✅ Complete |
| Interop Testing | ✅ Complete |
| Benchmarking Suite | ✅ Complete |

## Author

**Justin Adams** ([@vzwjustin](https://github.com/vzwjustin))

Designed and built from the ground up as a true kernel-level QUIC implementation for real-world WAN bonding. This is not a port or wrapper—it's a native Linux kernel module engineered for production deployment.

## Acknowledgments

- **Claude AI** (Anthropic) - Code implementation assistance
- **IETF QUIC Working Group** - RFC 9000, 9001, 9002, 9114, 9204 specifications
- **Linux Kernel Community** - MPTCP reference implementation and kernel networking APIs
- **Google** - BBRv2/v3 congestion control algorithms

## License

GPL-2.0 (Linux kernel)

## Contributing

Contributions welcome. Please ensure:
- Code follows Linux kernel coding style
- No stubs or placeholder implementations
- Full RFC compliance for protocol changes
- Test on kernel 6.x before submitting
- Add KUnit tests for new features
