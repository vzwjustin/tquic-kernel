# Architecture Overview

TQUIC is a kernel‑level QUIC implementation with native multipath WAN bonding.
It integrates directly with the Linux networking stack and exposes control via
netlink and sysctls.

## High‑Level Components

- **Core QUIC** (`net/tquic/core/`)
  - Packet parsing/assembly, stream management, flow control, loss recovery.
- **Crypto & TLS** (`net/tquic/crypto/`)
  - TLS 1.3 integration, key derivation, header protection, 0‑RTT.
- **Multipath + Bonding** (`net/tquic/multipath/`, `net/tquic/bond/`)
  - Path management, schedulers, per‑path packet spaces, bonding state machine.
- **Path Management (PM)** (`net/tquic/pm/`)
  - Kernel and userspace path managers; netlink control plane.
- **Transport & Tunneling** (`net/tquic/tquic_udp.c`, `net/tquic/transport/`)
  - UDP tunnel sockets and QUIC over UDP (optionally over TCP).
- **Netlink & Sysctl** (`net/tquic/tquic_netlink.c`, `net/tquic/tquic_sysctl.c`)
  - Userspace control and runtime configuration.

## Data Path (Simplified)

1. **UDP socket** receives packet
2. **QUIC parser** identifies connection + packet type
3. **Crypto** decrypts header/payload
4. **Frames** dispatched to stream/connection handlers
5. **Scheduler** decides path for outbound packets
6. **UDP tunnel** transmits on selected path

## Control Plane

- **Netlink**: path manager, multipath configuration, runtime queries
- **Sysctl**: tunables exposed in `/proc/sys/net/tquic/`

## WAN Bonding

Bonding aggregates multiple network paths by:

- Maintaining **per‑path state** (RTT, loss, congestion window)
- Scheduling packets across paths based on scheduler policy
- Handling **path validation** and **path lifecycle** events
- Supporting **multipath frames** and **per‑path packet spaces**
