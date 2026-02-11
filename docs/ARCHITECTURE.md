# Architecture Overview

TQUIC is a kernel-level QUIC implementation with native multipath WAN bonding.
It integrates directly with the Linux networking stack and exposes control via
netlink and sysctls.

## Components

| Directory | Description |
|-----------|-------------|
| `net/tquic/core/` | Packet parsing, stream management, flow control, loss recovery, ACK processing |
| `net/tquic/crypto/` | TLS 1.3 integration, key derivation, header protection, 0-RTT |
| `net/tquic/http3/` | HTTP/3 frames, QPACK header compression, server push |
| `net/tquic/multipath/` | Per-path packet spaces, path lifecycle, multipath frames |
| `net/tquic/bond/` | Bonding state machine (SINGLE_PATH, BONDED, DEGRADED) |
| `net/tquic/sched/` | Packet schedulers (MinRTT, Weighted, BLEST, ECF, Deadline, BPF) |
| `net/tquic/pm/` | Path managers (kernel and userspace), netlink control plane |
| `net/tquic/masque/` | CONNECT-UDP/IP proxying, capsule protocol |
| `net/tquic/transport/` | UDP tunnel sockets, QUIC-over-TCP fallback |
| `net/tquic/fec/` | Forward Error Correction (Reed-Solomon, XOR) |
| `net/tquic/lb/` | QUIC-LB load balancing, server ID encoding |
| `net/tquic/security/` | QUIC-LEAK defense, rate limiting, DoS mitigation |
| `net/tquic/diag/` | sock_diag integration, path metrics |
| `net/tquic/offload/` | SmartNIC/hardware offload support |
| `net/tquic/test/` | 78 KUnit test suites across 35 files |

Top-level files in `net/tquic/`:
- `tquic_main.c` - Module init/exit
- `tquic_proto.c` - Protocol registration (IPPROTO_TQUIC = 253)
- `tquic_socket.c` - Socket operations
- `tquic_udp.c` - UDP tunnel layer
- `tquic_netlink.c` - Netlink interface
- `tquic_sysctl.c` - Sysctl tunables
- `tquic_timer.c` - Timer management
- `io_uring.c`, `napi.c`, `af_xdp.c` - Performance optimizations
- `bpf.c` - BPF struct_ops for pluggable schedulers

## Data Path

1. **UDP socket** receives packet
2. **QUIC parser** identifies connection + packet type
3. **Crypto** decrypts header/payload (AES-NI/VAES accelerated)
4. **Frames** dispatched to stream/connection handlers
5. **Scheduler** decides path for outbound packets (per-packet, not per-flow)
6. **UDP tunnel** transmits on selected path

## Control Plane

- **Netlink**: Path manager, multipath configuration, runtime queries (CAP_NET_ADMIN required)
- **Sysctl**: ~30 tunables at `/proc/sys/net/tquic/`
- **sock_diag**: `ss` command visibility for QUIC sockets
- **Tracepoints**: Connection state, frame events, errors

## WAN Bonding

Bonding aggregates multiple network paths by:

- Maintaining **per-path state** (RTT, loss, congestion window)
- Scheduling packets across paths based on scheduler policy
- Handling **path validation** and **path lifecycle** events (ABANDON, STANDBY, AVAILABLE)
- Supporting **multipath frames** (MP_ACK, MP_NEW_CONNECTION_ID) and **per-path packet spaces**
- Providing **FEC** for lossy paths (Reed-Solomon, XOR)
