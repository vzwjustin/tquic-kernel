# TQUIC Kernel

**True QUIC** - A deep kernel-level QUIC implementation for True WAN Bonding (MPQUIC).

## Overview

TQUIC is a complete, production-ready kernel module implementing the QUIC protocol (RFC 9000, 9001, 9002) with multipath support for WAN bonding. Unlike userspace QUIC implementations, TQUIC operates directly in the Linux kernel for maximum performance and integration with the networking stack.

## Features

### Protocol Implementation (RFC 9000 Compliant)
- **Connection Management**: Full connection lifecycle, handshake, and termination
- **Packet Processing**: Initial, Handshake, 0-RTT, and 1-RTT packet types
- **Stream Multiplexing**: Bidirectional and unidirectional streams with flow control
- **Connection IDs**: Multiple CID support with retirement and rotation
- **Crypto**: TLS 1.3 integration via kernel TLS (RFC 9001)
- **Loss Detection & Recovery**: RFC 9002 compliant with PTO, RTT tracking

### Multipath QUIC (MPQUIC)
- **True WAN Bonding**: Aggregate bandwidth across multiple network paths
- **Path Management**: Dynamic path addition, removal, and failover
- **Preferred Address**: Server-initiated migration support (RFC 9000 Section 9.6)
- **Path Validation**: PATH_CHALLENGE/PATH_RESPONSE per RFC 9000

### Schedulers
- Round-robin
- Minimum RTT
- Weighted
- BLEST (Blocking Estimation)
- ECF (Earliest Completion First)
- BPF struct_ops for custom schedulers

### Congestion Control
- CUBIC
- BBRv2
- Prague (L4S/ECN)
- Westwood+
- Coupled algorithms: OLIA, BALIA

### Kernel Integration
- Netfilter hooks for firewall integration
- sock_diag support (`ss` command visibility)
- sysctl tunables at `/proc/sys/net/tquic/`
- Netlink interface for userspace control
- Per-namespace isolation

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

## Architecture

```
┌─────────────────────────────────────────────────────────┐
│                    User Space                            │
│  ┌─────────┐  ┌─────────┐  ┌─────────┐                  │
│  │ quicly  │  │  ngtcp2 │  │  msquic │  Applications    │
│  └────┬────┘  └────┬────┘  └────┬────┘                  │
└───────┼────────────┼────────────┼───────────────────────┘
        │            │            │
┌───────▼────────────▼────────────▼───────────────────────┐
│                  TQUIC Socket Layer                      │
│  ┌──────────────────────────────────────────────────┐   │
│  │              Connection Manager                    │   │
│  │  ┌────────┐ ┌────────┐ ┌────────┐ ┌────────────┐ │   │
│  │  │ Crypto │ │ Streams│ │  ACK   │ │  Flow Ctrl │ │   │
│  │  │  TLS   │ │  Mux   │ │ Handler│ │            │ │   │
│  │  └────────┘ └────────┘ └────────┘ └────────────┘ │   │
│  └──────────────────────────────────────────────────┘   │
│  ┌──────────────────────────────────────────────────┐   │
│  │              Path Manager (MPQUIC)                │   │
│  │  ┌────────┐ ┌────────┐ ┌────────┐ ┌────────────┐ │   │
│  │  │Scheduler│ │  Cong  │ │  Path  │ │  Migration │ │   │
│  │  │        │ │ Control│ │Validate│ │            │ │   │
│  │  └────────┘ └────────┘ └────────┘ └────────────┘ │   │
│  └──────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────┘
                            │
┌───────────────────────────▼─────────────────────────────┐
│                     UDP Layer                            │
│              (Netfilter hooks here)                      │
└─────────────────────────────────────────────────────────┘
                            │
┌───────────────────────────▼─────────────────────────────┐
│                   IP Layer (v4/v6)                       │
└─────────────────────────────────────────────────────────┘
```

## Implementation Status

| Component | Status |
|-----------|--------|
| Initial Packet Parsing | Complete |
| Handshake (IPv4/IPv6) | Complete |
| TLS 1.3 Integration | Complete |
| Stream TX/RX | Complete |
| Flow Control | Complete |
| ACK Processing | Complete |
| Loss Detection (RFC 9002) | Complete |
| Connection ID Management | Complete |
| CID Retirement | Complete |
| Path Validation | Complete |
| Preferred Address Migration | Complete |
| Multipath Scheduling | Complete |
| Congestion Control | Complete |
| Netlink Interface | Complete |
| Sysctl Interface | Complete |
| Namespace Support | Complete |

## Use Cases

- **WAN Bonding**: Aggregate LTE, 5G, and wired connections for increased bandwidth and reliability
- **Failover**: Seamless connection migration when primary path fails
- **Mobile Networks**: Maintain connections across network transitions
- **High-Performance Proxies**: Kernel-level QUIC termination
- **SD-WAN**: Software-defined WAN with QUIC transport

## Author

**Justin Adams** ([@vzwjustin](https://github.com/vzwjustin))

Designed and built from the ground up as a true kernel-level QUIC implementation for real-world WAN bonding. This is not a port or wrapper—it's a native Linux kernel module engineered for production deployment.

## Acknowledgments

- **Claude AI** (Anthropic) - Code implementation assistance
- **IETF QUIC Working Group** - RFC 9000, 9001, 9002 specifications
- **Linux Kernel Community** - MPTCP reference implementation and kernel networking APIs
- **Google** - BBRv2 congestion control algorithm

## License

GPL-2.0 (Linux kernel)

## Contributing

Contributions welcome. Please ensure:
- Code follows Linux kernel coding style
- No stubs or placeholder implementations
- Full RFC compliance for protocol changes
- Test on kernel 6.x before submitting
