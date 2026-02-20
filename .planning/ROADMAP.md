# Roadmap: TQUIC Kernel Integration

## Overview

TQUIC kernel integration delivers true WAN bandwidth aggregation at MPTCP-level kernel depth. The roadmap progresses from protocol foundation (IPPROTO_TQUIC registration) through diagnostics integration, path management, scheduling, congestion control, VPS aggregation endpoint, tooling, and upstream preparation. Each phase builds on prior work: protocol registration enables diagnostics, diagnostics enable debugging of path management, path management enables scheduling, and so forth. The 47 v1 requirements map across 10 phases delivering a complete, upstreamable kernel multi-path QUIC implementation.

## Phases

**Phase Numbering:**
- Integer phases (1, 2, 3): Planned milestone work
- Decimal phases (2.1, 2.2): Urgent insertions (marked with INSERTED)

Decimal phases appear between their surrounding integers in numeric order.

- [x] **Phase 1: Protocol Foundation** - IPPROTO_TQUIC registration and UAPI headers
- [x] **Phase 2: Socket API Completion** - Full socket operations with proper lifecycle
- [x] **Phase 3: Diagnostics Integration** - ss tool support via inet_diag and MIB statistics
- [x] **Phase 4: Path Manager Completion** - Kernel PM, userspace PM, and netlink interface
- [x] **Phase 5: Multi-Path Bonding Core** - True bandwidth aggregation with path validation
- [x] **Phase 6: Scheduler Framework** - Multiple schedulers with runtime selection
- [x] **Phase 7: Congestion Control** - Per-path and coupled congestion control algorithms
- [x] **Phase 8: VPS Aggregation Endpoint** - Server-side implementation for traffic aggregation
- [x] **Phase 9: Tooling Integration** - ss, ip, iproute2, and proc/sys interfaces
- [x] **Phase 10: Quality and Upstream** - checkpatch clean, KUnit tests, documentation

## Phase Details

### Phase 1: Protocol Foundation
**Goal**: TQUIC becomes a first-class kernel protocol with proper IPPROTO assignment and UAPI headers
**Depends on**: Nothing (first phase)
**Requirements**: PROTO-01, PROTO-02
**Plans**: 3 plans in 3 waves
**Success Criteria** (what must be TRUE):
  1. socket(AF_INET, SOCK_STREAM, IPPROTO_TQUIC) creates a valid socket
  2. socket(AF_INET6, SOCK_STREAM, IPPROTO_TQUIC) creates a valid socket
  3. UAPI headers installed to /usr/include/linux/tquic.h and tquic_pm.h
  4. Lock ordering hierarchy documented and enforced via lockdep annotations

Plans:
- [x] 01-01-PLAN.md - IPPROTO_TQUIC=263 registration in in.h and Kconfig verification
- [x] 01-02-PLAN.md - UAPI tquic_pm.h header and protocol.h with tquic_sock definition
- [x] 01-03-PLAN.md - Lockdep annotations and inline lock documentation

### Phase 2: Socket API Completion
**Goal**: Full BSD socket API for TQUIC with proper connection lifecycle and handshake
**Depends on**: Phase 1
**Requirements**: PROTO-03, PROTO-04, PROTO-05, PROTO-06
**Plans**: 4 plans in 2 waves
**Success Criteria** (what must be TRUE):
  1. connect() initiates QUIC handshake and establishes encrypted connection
  2. listen()/accept() allows server to accept incoming TQUIC connections
  3. sendmsg()/recvmsg() transmit and receive data on streams
  4. Multiple streams can be opened within a single connection
  5. Connection ID migration works when source address changes

Plans:
- [x] 02-01-PLAN.md - Connect and handshake with TLS 1.3 via net/handshake
- [x] 02-02-PLAN.md - Listen and accept for server mode with server handshake
- [x] 02-03-PLAN.md - Stream multiplexing via ioctl(TQUIC_NEW_STREAM) and sendmsg/recvmsg
- [x] 02-04-PLAN.md - Connection ID management and migration (auto + explicit)

### Phase 3: Diagnostics Integration
**Goal**: ss tool shows TQUIC connections and MIB statistics enable debugging
**Depends on**: Phase 2
**Requirements**: KINT-01, KINT-03
**Success Criteria** (what must be TRUE):
  1. `ss -t` shows TQUIC connections with state, addresses, and port
  2. `ss -ti` shows extended TQUIC info (streams, paths, RTT)
  3. /proc/net/tquic shows connection and path statistics
  4. MIB counters increment correctly for handshakes, packets, errors
**Plans**: 3 plans in 1 wave (2 original + 1 gap closure)

Plans:
- [x] 03-01-PLAN.md - inet_diag handler for ss integration with UAPI tquic_diag.h
- [x] 03-02-PLAN.md - MIB statistics, /proc/net/tquic, and error ring buffer
- [x] 03-03-PLAN.md - Gap closure: wire netns, MIB, diag init, proc iteration

### Phase 4: Path Manager Completion
**Goal**: Full path manager with kernel automatic mode and userspace daemon interface
**Depends on**: Phase 3
**Requirements**: BOND-03, BOND-04, BOND-05, BOND-06, KINT-06
**Success Criteria** (what must be TRUE):
  1. Kernel PM automatically discovers and adds paths when new interfaces come up
  2. Userspace PM daemon can add/remove paths via netlink commands
  3. PATH_CHALLENGE/PATH_RESPONSE validates paths before data transmission
  4. Paths can be added/removed dynamically without connection disruption
  5. Netlink events notify userspace of path state changes
**Plans**: 4 plans in 2 waves

Plans:
- [x] 04-01-PLAN.md - PM type framework and kernel automatic PM with netdevice notifier
- [x] 04-02-PLAN.md - Userspace PM and PM netlink interface with multicast events
- [x] 04-03-PLAN.md - PATH_CHALLENGE/PATH_RESPONSE validation with adaptive timeout
- [x] 04-04-PLAN.md - Dynamic path add/remove with state preservation and fast recovery

### Phase 5: Multi-Path Bonding Core
**Goal**: True bandwidth aggregation with reordering buffer for heterogeneous latencies
**Depends on**: Phase 4
**Requirements**: BOND-01, BOND-02, SCHED-09
**Success Criteria** (what must be TRUE):
  1. Two 1Gbps paths yield approximately 2Gbps aggregate throughput
  2. Packet loss on one path triggers seamless failover to remaining paths
  3. Reorder buffer handles 600ms latency difference (fiber + satellite)
  4. Connection survives complete path failure with zero application-visible packet loss
**Plans**: 3 plans in 2 waves

Plans:
- [x] 05-01-PLAN.md - Bonding state machine and capacity-proportional path weighting
- [x] 05-02-PLAN.md - RB-tree adaptive reorder buffer for latency differences
- [x] 05-03-PLAN.md - Seamless failover with retransmit queue priority

### Phase 6: Scheduler Framework
**Goal**: Multiple scheduling algorithms with runtime selection via sysctl/sockopt
**Depends on**: Phase 5
**Requirements**: SCHED-01, SCHED-02, SCHED-03, SCHED-04, SCHED-05, SCHED-06, SCHED-07
**Success Criteria** (what must be TRUE):
  1. Round-robin scheduler distributes packets evenly across paths
  2. MinRTT scheduler sends packets on lowest-latency path
  3. Weighted scheduler respects user-defined path priorities
  4. Aggregate scheduler maximizes combined throughput
  5. sysctl net.tquic.scheduler selects default algorithm
  6. SO_TQUIC_SCHEDULER sockopt changes algorithm per-socket
**Plans**: 5 plans in 2 waves

Plans:
- [x] 06-01-PLAN.md - Scheduler ops framework with per-netns defaults and connection locking
- [x] 06-02-PLAN.md - Round-robin and MinRTT schedulers with tolerance band
- [x] 06-03-PLAN.md - Weighted and aggregate (default) schedulers
- [x] 06-04-PLAN.md - BLEST and ECF schedulers from academic research
- [x] 06-05-PLAN.md - Runtime selection via sysctl and sockopt

### Phase 7: Congestion Control
**Goal**: Per-path and coupled congestion control with multiple algorithms
**Depends on**: Phase 6
**Requirements**: CONG-01, CONG-02, CONG-03, CONG-04, CONG-05, CONG-06, SCHED-08
**Success Criteria** (what must be TRUE):
  1. Each path has independent CWND, ssthresh, and pacing rate
  2. Cubic, BBR, COPA, and Westwood algorithms work per-path
  3. Coupled congestion control (OLIA/BALIA) coordinates CWND across paths
  4. Loss on one path reduces only that path's CWND
  5. Aggregate throughput doesn't exceed shared bottleneck capacity
**Plans**: 4 plans in 3 waves

Plans:
- [x] 07-01-PLAN.md - CC framework central registry and path lifecycle integration
- [x] 07-02-PLAN.md - Per-netns CC sysctl, SO_TQUIC_CONGESTION sockopt, BBR auto-selection
- [x] 07-03-PLAN.md - Coupled CC (OLIA/BALIA) integration and ECN support
- [x] 07-04-PLAN.md - Pacing integration (FQ qdisc) and path degradation on loss

### Phase 8: VPS Aggregation Endpoint
**Goal**: Server-side TQUIC implementation for VPS traffic aggregation
**Depends on**: Phase 7
**Requirements**: VPS-01, VPS-02, VPS-03, VPS-04, VPS-05, VPS-06
**Success Criteria** (what must be TRUE):
  1. VPS accepts multi-path TQUIC connections from home routers
  2. VPS forwards traffic to internet destinations transparently
  3. Real-time path monitoring shows per-path bandwidth/latency/loss
  4. VPS deploys on standard Ubuntu/Debian server via apt install
  5. Connection tracking maintains aggregated flow state
**Plans**: 4 plans in 3 waves

Plans:
- [x] 08-01-PLAN.md - Multi-tenant server PSK authentication and connection acceptance
- [x] 08-02-PLAN.md - TCP-over-QUIC tunnel termination with zero-copy splice forwarding
- [x] 08-03-PLAN.md - Userspace tquicd daemon with Prometheus metrics and dashboard
- [x] 08-04-PLAN.md - Debian package with systemd service and kernel tuning

### Phase 9: Tooling Integration
**Goal**: Full integration with Linux networking tools (ss, ip, iproute2, proc, sys)
**Depends on**: Phase 8
**Requirements**: TOOL-01, TOOL-02, TOOL-03, TOOL-04, TOOL-05, KINT-02, KINT-04, KINT-05, KINT-07
**Success Criteria** (what must be TRUE):
  1. `ss -t` shows TQUIC connections (fulfilled in Phase 3, extended here)
  2. `ip tquic` commands manage paths, scheduler, and bonding policy
  3. iproute2 package includes TQUIC support
  4. /proc/sys/net/tquic/* provides all tunable parameters
  5. Netfilter hooks enable TQUIC-aware firewalling
  6. Per-netns isolation works correctly for containers
**Plans**: 5 plans in 1 wave

Plans:
- [x] 09-01: Complete sysctl interface
- [x] 09-02: ip tquic command implementation
- [x] 09-03: Netfilter hooks
- [x] 09-04: Per-netns support
- [x] 09-05: Routing table integration

### Phase 10: Quality and Upstream
**Goal**: Upstream-quality code with full test coverage and documentation
**Depends on**: Phase 9
**Requirements**: QUAL-01, QUAL-02, QUAL-03, QUAL-04, QUAL-05, QUAL-06, QUAL-07, QUAL-08
**Success Criteria** (what must be TRUE):
  1. checkpatch.pl --strict reports zero errors, zero warnings
  2. All code follows Documentation/process/coding-style.rst
  3. KUnit tests cover protocol core, path manager, and scheduler
  4. Documentation/networking/tquic.rst exists and is complete
  5. Man pages exist for ip-tquic and tquic tunables
  6. MAINTAINERS file entry for net/tquic/
**Plans**: 6 plans in 2 waves

Plans:
- [x] 10-01: checkpatch cleanup
- [x] 10-02: KUnit test suite - protocol core
- [x] 10-03: KUnit test suite - path manager
- [x] 10-04: KUnit test suite - scheduler
- [x] 10-05: Kernel documentation
- [x] 10-06: Man pages and MAINTAINERS entry

## Progress

**Execution Order:**
Phases execute in numeric order: 1 -> 2 -> 3 -> ... -> 10

| Phase | Plans Complete | Status | Completed |
|-------|----------------|--------|-----------|
| 1. Protocol Foundation | 3/3 | Complete | 2026-01-31 |
| 2. Socket API Completion | 4/4 | Complete | 2026-01-31 |
| 3. Diagnostics Integration | 3/3 | Complete | 2026-01-31 |
| 4. Path Manager Completion | 4/4 | Complete | 2026-01-31 |
| 5. Multi-Path Bonding Core | 3/3 | Complete | 2026-01-31 |
| 6. Scheduler Framework | 5/5 | Complete | 2026-01-31 |
| 7. Congestion Control | 4/4 | Complete | 2026-02-01 |
| 8. VPS Aggregation Endpoint | 4/4 | Complete | 2026-02-19 |
| 9. Tooling Integration | 5/5 | Complete | 2026-02-19 |
| 10. Quality and Upstream | 6/6 | Complete | 2026-02-19 |

---
*Roadmap created: 2026-01-30*
*Phase 1 planned: 2026-01-30*
*Phase 1 complete: 2026-01-31*
*Phase 2 planned: 2026-01-31*
*Phase 2 complete: 2026-01-31*
*Phase 3 complete: 2026-01-31*
*Phase 4 complete: 2026-01-31*
*Phase 5 planned: 2026-01-31*
*Phase 5 complete: 2026-01-31*
*Phase 6 planned: 2026-01-31*
*Phase 6 complete: 2026-01-31*
*Phase 7 planned: 2026-01-31*
*Phase 7 complete: 2026-02-01*
*Phase 8 planned: 2026-01-31*
*Total plans: 41 (estimated)*
*Total requirements: 47 mapped*
