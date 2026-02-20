# TQUIC Kernel

**True QUIC** - A kernel-level QUIC implementation for True WAN Bonding (MPQUIC).

> **Warning: Not production ready.** This project is experimental and under active development.

## Overview

TQUIC is a Linux kernel module implementing the QUIC protocol (RFC 9000/9001/9002) with multipath support for WAN bonding. Unlike userspace QUIC implementations, TQUIC operates directly in the kernel for maximum performance and tight integration with the networking stack.

**~642k lines of C** across `net/tquic/` implementing the full QUIC/HTTP3 stack with multipath, security, and performance features. Security audit completed February 2026 with all critical issues resolved across 11 rounds of fixes. Codebase quality sweep (2026-02-20) resolved GPL compliance across all 6 affected files (44 `EXPORT_SYMBOL` → `EXPORT_SYMBOL_GPL`), removed dead code confirmed by full call-graph audit (core/ack.c, 17 unreachable exports; 10 dead exports in quic_output.c; 7 dead functions in quic_connection.c), fixed BUG-4 (GSO fallback silent fall-through) and BUG-5 (orphaned function body at file scope — compile error), and eliminated the standalone Makefile duplicate-link overlap. **End-to-end data exchange verified**: TLS 1.3 handshake, bidirectional STREAM data, ACK generation, flow control (MAX_DATA/MAX_STREAM_DATA), and clean CONNECTION_CLOSE teardown — 1MB file transfer with MD5 integrity verification over loopback.

### Project Structure

The implementation is in `net/tquic/` with key subdirectories:
- `core/` - Protocol state machine, connections, streams
- `crypto/` - TLS 1.3 integration and cryptographic operations
- `http3/` - HTTP/3 and QPACK implementation
- `multipath/` - Path management and schedulers
- `cong/` - Congestion control algorithms
- `transport/` - Packet I/O, ACK processing, loss detection
- `test/` - KUnit test suites

## Features

**Protocol**
- QUIC v1 (RFC 9000) - all frame types 0x00-0x1e handled, connection lifecycle, packet coalescing
- TLS 1.3 inline handshake (no userspace TLS daemon) with X.509 certificate verification and RSA-PSS signatures
- AES-128-GCM encryption at Initial, Handshake, and Application levels with per-level AEAD key selection
- Bidirectional STREAM data exchange with ACK generation and flow control
- Connection-level (MAX_DATA) and stream-level (MAX_STREAM_DATA) flow control
- Clean CONNECTION_CLOSE exchange with graceful connection teardown
- HTTP/3 (RFC 9114) + QPACK header compression (RFC 9204)
- DATAGRAM extension (RFC 9221), GREASE, ACK_FREQUENCY
- Loss detection & recovery (RFC 9002) framework - PTO, persistent congestion, PRR

**Multipath & Bonding**
- True per-packet scheduling across multiple WAN paths (not flow-pinning)
- 7 schedulers: Aggregate, MinRTT, Weighted, BLEST, ECF, Deadline-Aware, BPF struct_ops
- 10 congestion control algorithms: CUBIC, BBRv1/v2/v3, Copa, Westwood+, Prague, OLIA, LIA, BALIA
- Dynamic path management with failover, PATH_ABANDON/STANDBY/AVAILABLE
- Forward Error Correction (Reed-Solomon, XOR)

**Performance**
- GRO/GSO offload, zero-copy I/O, AF_XDP, io_uring with SQPOLL
- Hardware crypto acceleration (AES-NI/VAES detection)
- SmartNIC offload support, NAPI polling

**Security**
- Comprehensive DoS prevention: QUIC-LEAK defense, rate limiting, anti-amplification
- Constant-time crypto, secure key cleanup, anti-replay protection
- Full security audit with 11 rounds of fixes (deadlocks, UAFs, races, overflows)

**Observability**
- qlog (RFC 9293), kernel tracepoints, sock_diag (`ss` integration)
- Procfs stats, ~30 sysctl tunables at `/proc/sys/net/tquic/`
- Netlink control plane with CAP_NET_ADMIN enforcement

## Architecture

Userspace QUIC implementations pay a heavy cost crossing the kernel boundary on every packet. TQUIC eliminates this entirely - crypto, congestion control, scheduling, and I/O all execute in kernel context with direct access to the networking stack.

```
  ┌─────────────────────────────────────────────────────────────────┐
  │                        User Space                               │
  │    Apps just open a socket - no QUIC library needed             │
  └───────┬────────────┬────────────┬──────────────┬────────────────┘
          │ socket()   │ send()     │ recv()       │ setsockopt()
  ════════╪════════════╪════════════╪══════════════╪════════════════════
          │     No userspace ↔ kernel copies per packet             │
  ┌───────▼────────────▼────────────▼──────────────▼────────────────┐
  │                    TQUIC (Kernel Space)                          │
  │                                                                  │
  │  ┌────────────────────────────────────────────────────────────┐  │
  │  │  HTTP/3 + QPACK + WebTransport + MASQUE                   │  │
  │  └────────────────────────────────────────────────────────────┘  │
  │  ┌────────────────────────────────────────────────────────────┐  │
  │  │  Connection Manager (Crypto, Streams, ACK, Flow Ctrl)      │  │
  │  │  ← TLS 1.3 with AES-NI/VAES hardware acceleration         │  │
  │  └────────────────────────────────────────────────────────────┘  │
  │  ┌────────────────────────────────────────────────────────────┐  │
  │  │  Path Manager & Multipath Scheduler                        │  │
  │  │  ← Per-packet decisions at wire speed, no syscall overhead │  │
  │  └────────────────────────────────────────────────────────────┘  │
  │  ┌────────────────────────────────────────────────────────────┐  │
  │  │  Performance (GRO/GSO, Zero-Copy, AF_XDP, io_uring)       │  │
  │  │  ← Direct NIC access, no socket buffer copies              │  │
  │  └────────────────────────────────────────────────────────────┘  │
  │                                                                  │
  │  Kernel advantages: NAPI polling, softirq scheduling,           │
  │  netfilter integration, per-CPU data, RCU-protected paths       │
  └──────────────────────────┬──────────────────────────────────────┘
  ┌──────────────────────────▼──────────────────────────────────────┐
  │                   UDP → IP Layer (v4/v6)                         │
  │  ← Direct stack integration, no raw socket overhead              │
  └─────────────────────────────────────────────────────────────────┘
```

## Development Status

| Milestone | Status |
|-----------|--------|
| Core QUIC framing & packet I/O | Done |
| Connection & stream management | Done |
| Inline TLS 1.3 handshake (client + server) | Done |
| X.509 certificate parsing & RSA-PSS verification | Done |
| Per-level AEAD encryption (Initial/Handshake/Application) | Done |
| Multi-record TLS processing in CRYPTO frames | Done |
| DCID negotiation (RFC 9000 Section 7.2) | Done |
| Multipath schedulers & congestion control | Done |
| Security audit (11 rounds) | Done |
| Post-handshake connection state transition | Done |
| Server accept queue (inline handshake path) | Done |
| PATH_CHALLENGE/RESPONSE validation | Done |
| HANDSHAKE_DONE frame (RFC 9000 Section 19.20) | Done |
| Bidirectional STREAM data exchange | Done |
| ACK generation for 1-RTT packets | Done |
| Flow control (MAX_DATA / MAX_STREAM_DATA) | Done |
| Stream FIN on connection close | Done |
| CONNECTION_CLOSE exchange & clean teardown | Done |
| All RFC 9000 frame types (0x00-0x1e) | Done |
| 1MB file transfer with integrity verification | Done |
| Loss detection & retransmission (RFC 9002) | Done |
| Delayed ACK timer (RFC 9000 Section 13.2.1) | Done |
| Live VPS functional test (18/18 checks) | Done |
| setsockopt string options (TQUIC_SCHEDULER/CONGESTION) | Fixed |
| SO_TQUIC_SCHEDULER mp-scheduler name lookup | Fixed |
| GPL compliance — 44 `EXPORT_SYMBOL` → `EXPORT_SYMBOL_GPL` (6 files) | Fixed |
| Build overlap fix — Makefile duplicate-link (pm/sched/crypto) | Fixed |
| Dead-code audit — orphan files, 29 test files wired, core/ack.c removed | Done |
| BUG-4: `tquic_output_gso_send` GSO fallback silent fall-through | Fixed |
| BUG-5: Orphaned function body at file scope in `quic_connection.c` | Fixed |
| Dead export sweep — 10 zero-caller exports in `quic_output.c` de-exported | Done |
| Dead function sweep — 7 dead functions removed from `quic_connection.c` | Done |
| Multi-megabyte transfers & throughput optimization | Planned |
| Interop testing (quiche, msquic, ngtcp2) | Planned |

## Quick Start

```bash
git clone https://github.com/vzwjustin/tquic-kernel.git
cd tquic-kernel

# Build the TQUIC module
make -C net/tquic -j$(nproc)

# Load the module
sudo insmod net/tquic/tquic.ko

# Verify
lsmod | grep tquic
dmesg | tail -20
```

Supported kernels: **Linux 6.x** (tested on 6.12). See [Quick Start Guide](docs/QUICKSTART_DIETPI.md) for full setup instructions.

## Use Cases

- **WAN Bonding** - Aggregate LTE, 5G, and wired connections
- **Failover** - Seamless path migration on failure (<100ms target)
- **Mobile Networks** - Maintain connections across network transitions
- **SD-WAN** - Software-defined WAN with QUIC transport
- **High-Performance Proxies** - Kernel-level QUIC/HTTP3 termination
- **WebTransport** - Real-time gaming, live streaming, collaborative tools
- **MASQUE Proxying** - Privacy-preserving proxy infrastructure

## Documentation

| Document | Description |
|----------|-------------|
| [Quick Start](docs/QUICKSTART_DIETPI.md) | Build, load, and verify the module |
| [Architecture](docs/ARCHITECTURE.md) | System design and component overview |
| [Configuration](docs/CONFIGURATION.md) | Sysctl tunables and netlink interface |
| [Troubleshooting](docs/TROUBLESHOOTING.md) | Common issues and debugging |
| [Roadmap](docs/ROADMAP.md) | Development plans |
| [Kernel Boot Guide](docs/KERNEL_BOOT_GUIDE.md) | Installing and booting a custom kernel |
| [Porting Guide](docs/PORTING_GUIDE.md) | Porting to different kernel versions |
| [CLAUDE.md](CLAUDE.md) | Development workflow and coding standards |

## Testing

78 KUnit test suites across 42 test files in `net/tquic/test/`, plus an interoperability test framework for validation against quiche, msquic, ngtcp2, and picoquic.

```bash
./tools/testing/kunit/kunit.py run --kunitconfig=net/tquic/test/.kunitconfig
```

### Live Functional Test Results (2026-02-19, kernel 6.19.0-tquic-d43af692)

Tested on a DigitalOcean VPS running the TQUIC kernel. Two bugs found and fixed during testing:
1. `TQUIC_SCHEDULER`/`TQUIC_CONGESTION` string options blocked by integer-only `sizeof(int)` optlen guard
2. `SO_TQUIC_SCHEDULER` rejected mp-scheduler names (e.g. "aggregate") not in the core stream-scheduler list

```
[Socket Creation]     PASS: AF_INET SOCK_STREAM IPPROTO_TQUIC
                      PASS: AF_INET6 SOCK_STREAM IPPROTO_TQUIC
[Bind + Listen]       PASS: bind(lo:14560)  PASS: listen(5)
[Socket Options]      PASS: getsockopt(TQUIC_SCHEDULER) = minrtt
                      PASS: setsockopt(TQUIC_SCHEDULER, minrtt/aggregate/weighted/blest/ecf)
                      PASS: getsockopt(TQUIC_CONGESTION)
[/proc Interfaces]    PASS: /proc/net/tquic, /proc/net/tquic_stat, /proc/net/tquic_errors
[sysctl]              PASS: scheduler=aggregate, max_paths=16, probe_interval_ms=1000
[Stress]              PASS: 64 concurrent TQUIC sockets

Result: 18 passed, 0 failed
```

## Author

**Justin Adams** ([@vzwjustin](https://github.com/vzwjustin))

Built from the ground up as a native Linux kernel module for real-world WAN bonding. Not a port or wrapper.

## Acknowledgments

- **Claude AI** (Anthropic) - Code implementation assistance
- **IETF QUIC Working Group** - Protocol specifications
- **Linux Kernel Community** - MPTCP reference and kernel networking APIs
- **Google** - BBR congestion control algorithms

## License

GPL-2.0

## Contributing

Contributions welcome. Code must follow Linux kernel style, include KUnit tests, maintain full RFC compliance, and contain no stubs or placeholders. Test on kernel 6.x before submitting.
