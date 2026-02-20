# Project State: TQUIC Kernel Integration

## Current Position

**Phase:** 10 of 10 (Quality and Upstream) - COMPLETE
**Plan:** 6 of 6 complete
**Status:** All phases complete. Remaining gates require a Linux build host: checkpatch.pl
           --strict run, kernel build (make M=net/tquic), and KUnit test execution.
**Last activity:** 2026-02-20 - Fixed erroneous TQUIC_OUT_OF_TREE guard on tquic_conn_destroy()
                   (commit 264440d23)

Progress: [================================================================================] 100%
         41/41 plans complete

## Accumulated Decisions

Decisions made during execution that affect future phases:

| Phase-Plan | Decision | Rationale | Affects |
|------------|----------|-----------|---------|
| 01-01 | IPPROTO_TQUIC=263 (renamed from IPPROTO_QUIC) | Match tquic subsystem naming convention used in tquic_proto.c, tquic_ipv6.c | All phases using socket API |
| 01-01 | Value 263 follows MPTCP=262 | Extended IPPROTO range (>255) valid in Linux | Protocol registration |
| 01-02 | PM netlink follows mptcp_pm.h pattern | Consistency with existing multipath patterns | Phase 04 path manager |
| 01-02 | protocol.h as internal header | Follows mptcp/protocol.h pattern for lock docs | Socket operations |
| 01-03 | Lock class keys indexed [0]=IPv4, [1]=IPv6 | Enables lockdep to distinguish socket address families | IPv6 support, multipath |
| 01-03 | Both header LOCKING + inline comments | Per user decision, comprehensive lock documentation | Future maintainers |
| 02-01 | EQUIC_BASE=500 | Avoid collision with standard errno (max ~133) | All QUIC error handling |
| 02-01 | Fixed 30s handshake timeout | Per CONTEXT.md, not configurable per-socket | Connect behavior |
| 02-01 | net/handshake tlshd delegation | Same pattern as NFS over TLS (sunrpc/xprtsock.c) | Server handshake |
| 02-02 | Child socket created in server_handshake | Handshake completes async before socket ready for userspace | Accept semantics |
| 02-02 | 256-bucket listener hash with RCU | Sufficient for typical servers, lock-free UDP receive path lookup | Packet demux |
| 02-02 | Separate accept_list from accept_queue | accept_queue is list head, accept_list is linkage for kernel list pattern | Socket queuing |
| 02-03 | Stream socket via ioctl | CONTEXT.md hybrid model: ioctl on conn socket creates stream fd | Stream I/O |
| 02-03 | sk_user_data for stream linkage | Standard kernel pattern for socket->private data | Stream sockets |
| 02-03 | Stream ID +4 increment | RFC 9000 Section 2.1 stream ID encoding (type in low 2 bits) | Stream creation |
| 02-04 | rhashtable for CID lookup | O(1) lookup for packet demux, automatic shrinking, kernel standard | Packet demux, migration |
| 02-04 | CID pool default 8 per RFC 9000 | Matches TQUIC_ACTIVE_CID_LIMIT transport parameter default | Connection lifecycle |
| 02-04 | Migration returns -ENOSYS Phase 2 | API surface ready but full implementation deferred to Phase 4 | Phase 4 path manager |
| 03-01 | CAP_NET_ADMIN for CID visibility | CIDs sensitive for packet capture; consistent with MPTCP | ss tool output |
| 03-01 | Hybrid state names | QUIC state (TCP equiv) format aids operators | Diagnostics display |
| 03-01 | MODULE_ALIAS for ss auto-load | Per RESEARCH.md pitfall #4 | ss tool integration |
| 03-02 | 37 MIB counter categories | Comprehensive coverage: handshake, packet, connection, path, stream, per-EQUIC errors | MIB monitoring |
| 03-02 | TquicExt format for proc output | Matches MPTCP/TCP pattern for consistency with monitoring tools | Operator tooling |
| 03-02 | 256-entry error ring | Balance between memory usage and debugging history depth | Error debugging |
| 03-02 | Lock-free ring write | Atomic head increment avoids contention in high-frequency paths | Performance |
| 03-03 | netns_tquic after SMC in struct net | Follows existing protocol pattern for additions | Per-netns state |
| 03-03 | tquic_statistics after MPTCP in MIB | Follows MPTCP pattern for MIB additions | MIB counter access |
| 03-03 | rhashtable_walk for proc iteration | Matches tquic_main.c pattern, standard kernel API | Connection listing |
| 03-03 | net_eq() namespace filtering | Standard kernel pattern for namespace isolation | Multi-namespace deployments |
| 04-01 | PM type framework follows MPTCP pattern | Proven pattern for kernel vs userspace PM selection | Phase 04-02 userspace PM |
| 04-01 | Kernel PM uses netdevice notifier | Standard kernel pattern for interface lifecycle monitoring | Automatic path discovery |
| 04-01 | Interface filtering rejects virtual interfaces | Loopback, bridge, macvlan, OVS unsuitable for WAN bonding | Correct path selection |
| 04-01 | Default route required via fib_lookup | WAN bonding needs internet connectivity | Only WAN interfaces used |
| 04-01 | Per-netns sysctl for PM configuration | Independent PM config per namespace | Container-friendly |
| 04-01 | Connection token via get_random_u32() | Simple, sufficient entropy for netlink identification | Phase 04-03 netlink |
| 04-01 | PM init after handshake completes | Need established connection before paths | Clean lifecycle |
| 04-01 | Path state preserved on interface down | Fast recovery when interface returns | Reduced latency |
| 04-02 | CAP_NET_ADMIN for all PM commands and events | Path management affects routing and security policy | Userspace daemon security |
| 04-02 | Rate limit events via __ratelimit() + pernet limit | Prevent event storms from overwhelming userspace daemon | Phase 09 CLI tools |
| 04-02 | Nested address attributes (tquic_pm_addr_attr) | Cleaner structure, follows MPTCP pattern | Future address metadata |
| 04-02 | tquic_conn_lookup_by_token stub returns NULL | Connection hash table in later phase | Phase 05 bonding |
| 04-03 | 3x SRTT multiplier for validation timeout | RFC 9000 recommendation balances LAN (1ms) and satellite (500ms) | Validation timing |
| 04-03 | 256-frame response queue limit | Prevent memory exhaustion from PATH_CHALLENGE floods (DoS mitigation) | Security, resource limits |
| 04-03 | SRTT initialized to 100ms | TQUIC_DEFAULT_RTT provides reasonable default before first sample | Initial timeout calculation |
| 04-03 | Immediate validation on path add | Paths must be validated before data transmission per RFC 9000 Section 9 | Phase 05 bonding, scheduler |
| 04-03 | Both VALIDATED and ACTIVE states acceptable | VALIDATED = passed validation, ACTIVE = in use; both are usable | Scheduler path selection |
| 04-04 | Interface down preserves state via TQUIC_PATH_UNAVAILABLE | Fast recovery when interface returns (mobile handoff, WiFi roaming) | Path recovery time |
| 04-04 | RCU-safe path operations | Avoid blocking data path during path management operations | Performance, concurrency |
| 04-04 | Carrier changes treated as interface up/down | Carrier down/up is equivalent to interface down/up for WAN bonding | Link failure handling |
| 04-04 | Recovery-first pattern on interface up | Existing paths recover faster than discovering new paths | Failback speed |
| 05-01 | State names SINGLE_PATH/PENDING/ACTIVE/DEGRADED | Match CONTEXT.md terminology, clear semantics | Phase 05-02 reorder buffer, Phase 06 scheduler |
| 05-01 | 5% minimum weight floor | Prevent path starvation per RESEARCH.md pitfall #4 | Scheduler path selection |
| 05-01 | Workqueue for async weight updates | Avoid blocking data path during recalculation | Performance |
| 05-01 | Reorder buffer allocated in PENDING | Prepare before ACTIVE, release in SINGLE_PATH | Phase 05-02 reorder buffer |
| 05-01 | Path manager owns bonding context | Clean lifecycle management, callback integration | Phase 05-02, Phase 06 |
| 05-02 | RB-tree for reorder buffer | O(log n) insertion critical for 600ms latency spread with many packets | Reorder performance |
| 05-02 | last_skb fast path optimization | Nearly-in-order packets skip tree traversal | Common case performance |
| 05-02 | Gap timeout: 2 * rtt_spread + 100ms | Handles worst-case slow path arrival | Heterogeneous latency paths |
| 05-02 | Default buffer 256KB, max 4MB | Balance memory vs 600ms spread at 1Gbps | Buffer sizing |
| 05-02 | Lazy buffer allocation | Only allocate in BOND_PENDING/ACTIVE states | Single-path overhead |
| 05-03 | rhashtable for sent packet tracking | O(1) lookup by packet number for efficient ACK processing | Failover performance |
| 05-03 | 3x SRTT path failure timeout | RFC 9000 recommendation, balances prompt failover vs false positives | Path failure detection |
| 05-03 | 2048-packet bitmap deduplication | Memory efficient, covers typical failover window | Receiver dedup |
| 05-03 | Retransmit queue priority over new data | Zero application-visible packet loss guarantee | Scheduler integration |
| 06-01 | RCU for per-netns default_scheduler | Lock-free read in data path | Phase 06 schedulers |
| 06-01 | EISCONN for scheduler change after IDLE | Scheduler locked at connection establishment per CONTEXT.md | Phase 06 schedulers |
| 06-01 | Per-netns sysctl uses current->nsproxy | Container-friendly configuration | Phase 09 tooling |
| 06-03 | Capacity formula: cwnd * scale / RTT | Provides stable integer math for path scoring | Capacity-based scheduling |
| 06-03 | 10ms capacity update interval | Balance freshness vs per-packet overhead | Aggregate scheduler performance |
| 06-03 | DRR quantum = 1500 bytes | One MTU per quantum balances granularity vs overhead | Weighted scheduler fairness |
| 06-03 | Aggregate returns primary + backup | Enables seamless failover integration | Phase 07 congestion, failover |
| 06-04 | BLEST 1ms blocking threshold | Prevents oscillation for sub-ms blocking times | BLEST scheduler tuning |
| 06-04 | ECF 10ms rate update interval | Balances rate freshness vs overhead | ECF scheduler performance |
| 06-04 | Send rate from bandwidth or cwnd/RTT fallback | Accurate rate estimation for completion time | ECF completion time accuracy |
| 06-05 | Scheduler selection via sockopt before connect | Returns -EISCONN after connection established | Per-connection scheduler |
| 06-05 | Child sockets inherit parent's requested_scheduler | Consistent scheduler for connections from same listener | Accept path inheritance |
| 06-05 | Per-netns proc via pernet_operations | Proper namespace isolation for /proc/net/tquic/schedulers | Container deployments |
| 06-05 | single_release_net for proc cleanup | Matches single_open_net pattern for per-netns proc | Proc file handling |
| 07-01 | Cubic as default CC algorithm | Matches Linux TCP default, proven at scale | Per-path CC selection |
| 07-01 | CC init failure is non-fatal | Path continues without CC during module loading issues | Resilient operation |
| 07-01 | Module auto-loading via tquic-cong-{name} | Standard kernel pattern from TCP | CC module discovery |
| 07-02 | 100ms BBR RTT threshold | LAN < 10ms, WAN > 50ms; 100ms clearly identifies high-latency paths | BBR auto-selection |
| 07-02 | "auto" as special CC sockopt value | Clear semantic for enabling automatic per-path CC selection | Per-path CC selection |
| 07-02 | CC preference not locked at connection | Unlike scheduler, CC affects new paths only | CC flexibility |
| 07-03 | OLIA as default coupled algorithm | RFC-standardized, TCP-friendly at shared bottlenecks | Multipath fairness |
| 07-03 | Loss on one path affects only that path's CWND | Per CONTEXT.md requirement for path isolation | CC behavior |
| 07-03 | ECN off by default (net.tquic.ecn_enabled = 0) | Per CONTEXT.md: "available but off by default" | ECN configuration |
| 07-03 | ECN CE treated like loss | Per RFC 9002 Section 7.1, CC should reduce CWND | ECN handling |
| 07-04 | Pacing rate fallback to cwnd/RTT | Cubic lacks pacing rate, BBR provides it | Pacing accuracy |
| 07-04 | Minimum pacing rate 120KB/s | 1 MSS per 10ms prevents pacing bottleneck | Slow path handling |
| 07-04 | 5 consecutive losses triggers degradation | Per RESEARCH.md recommendation | Path failover |
| 07-04 | Round = cwnd/MSS packets | Standard approximation for round-trip window | Loss tracking |
| 08-01 | Token bucket rate limiting with 1s burst | Smooth rate limiting, handles burst reconnects | Per-client abuse prevention |
| 08-01 | Session TTL default 120s | Per CONTEXT.md, balance memory vs reconnect time | Router reconnection |
| 08-01 | Queue timeout 30s | Per CONTEXT.md, reasonable window for temporary path failures | Path recovery |
| 08-01 | PSK identity max 64 bytes | Per RFC 8446 Section 4.2.11 TLS 1.3 limit | Authentication |
| 08-02 | Stream header: AF + IP + port + QoS | Minimal tunnel setup header, QoS hint inline | Tunnel protocol |
| 08-02 | 4 DSCP classes with port overrides | realtime=EF, interactive=AF41, bulk=BE, background=CS1 | tc HTB integration |
| 08-02 | Bitmap port allocation (1000/client) | O(1) alloc/free, 125 bytes per client | Scalability |
| 08-02 | Hash table hairpin lookup | O(1) for client-to-client routing | Performance |
| 08-03 | Genetlink graceful degradation | Return nil client if kernel module not loaded | Daemon startup without kernel |
| 08-03 | 100-entry ring buffer for recent connections | Balance memory usage vs dashboard history | Dashboard display |
| 08-03 | 5-second metric poll interval | Per CONTEXT.md, matches kernel update interval | Prometheus metrics |
| 08-03 | Alert thresholds: >5% loss, >500ms RTT | Reasonable defaults for WAN bonding paths | Path alerting |
| 08-04 | debhelper level 13 | Modern debhelper with built-in systemd integration | Debian packaging |
| 08-04 | Type=notify systemd service | Daemon uses sd_notify() for proper ready signaling | Service management |
| 08-04 | fwmark 1 lookup 100 TPROXY routing | Standard TPROXY packet routing pattern | Transparent proxy |

## Blockers/Concerns

- **Requires Linux build host to complete:**
  1. `scripts/checkpatch.pl --strict` on all modified files
  2. `make M=net/tquic` to verify zero build errors against real kernel headers
  3. `kunit.py run` to execute the 39 KUnit test files
- **No KUnit tests** for the 6 optional subsystem hooks wired 2026-02-20 (SmartNIC, FEC
  hook-side, QUIC-LB hook-side, TCP fallback trigger, AF_XDP/io_uring sockopt dispatch)
- ~~**tquic_conn_destroy() unreachable in out-of-tree builds**~~ — Fixed 2026-02-20 (commit 264440d23)

## Session Continuity

**Last session:** 2026-02-20
**Stopped at:** All phases complete; optional subsystem hooks wired + TQUIC_OUT_OF_TREE guard
               bug fixed in tquic_conn_destroy() (commit 264440d23)
**Resume file:** None

## Phase Summaries

| Phase | Plans | Status | Summary |
|-------|-------|--------|---------|
| 01-protocol-foundation | 3/3 | Complete | IPPROTO_TQUIC=263, tquic_pm.h, protocol.h, lockdep |
| 02-socket-api | 4/4 | Complete | connect/accept, stream sockets, CID pool, migration stubs |
| 03-diagnostics | 3/3 | Complete | inet_diag, MIB counters, proc interface, error ring, all gaps closed |
| 04-path-manager | 4/4 | Complete | PM framework, kernel PM, userspace PM, PM netlink, path validation, dynamic add/remove |
| 05-bonding-core | 3/3 | Complete | Bonding state machine, reorder buffer, seamless failover with retransmit queue |
| 06-scheduler | 5/5 | Complete | Scheduler framework, minrtt, aggregate, weighted, blest, ecf, runtime selection via sockopt |
| 07-congestion | 4/4 | Complete | CC framework, per-netns config, SO_TQUIC_CONGESTION, BBR auto-selection, coupled CC (OLIA/BALIA), ECN, pacing, path degradation |
| 08-vps-endpoint | 4/4 | Complete | Multi-tenant server with PSK auth, TCP tunnel termination, zero-copy splice, QoS, tquicd daemon, Debian package |
| 09-tooling | 5/5 | Complete | ip-tquic tool, sysctl, netfilter, per-netns, routing (mostly pre-existing) |
| 10-quality-upstream | 6/6 | Complete | tquic.rst, ip-tquic.8, MAINTAINERS, KUnit tests, style cleanup; checkpatch.pl requires Linux build host |

## Recent Activity

- **2026-02-20:** Fixed erroneous #ifndef TQUIC_OUT_OF_TREE guard wrapping tquic_conn_destroy()
  in core/quic_connection.c (commit 264440d23). Function was declared unconditionally in
  include/net/tquic.h and called unconditionally from tquic_conn_put(), but its definition
  disappeared in out-of-tree builds — guaranteed link failure. Guard removed; added
  EXPORT_SYMBOL_GPL to match tquic_conn_create().
- **2026-02-20:** Wired 6 optional subsystem hooks into core paths (234 insertions, 8 files, commit b601fbce8):
  SmartNIC offload TX/RX (CONFIG_TQUIC_OFFLOAD), FEC source symbol capture + frame handlers
  (CONFIG_TQUIC_FEC), QUIC-LB CID encoding (CONFIG_TQUIC_QUIC_LB), TCP fallback trigger
  (CONFIG_TQUIC_OVER_TCP), AF_XDP setsockopt/getsockopt (CONFIG_TQUIC_AF_XDP), io_uring
  setsockopt/getsockopt (CONFIG_TQUIC_IO_URING). fec_state/lb_config/fallback_ctx lifecycle
  added to tquic_conn_create()/tquic_conn_destroy().
- **2026-02-19:** Phase 08 fully complete (4/4) - all verification gaps closed: Makefile wired, splice implemented, init/exit calls added
- **2026-02-19:** Phase 10: Documentation/networking/tquic.rst, ip-tquic.8 man page, MAINTAINERS entry (commit 0c1815445)
- **2026-02-19:** Phase 09 complete - ip-tquic C tool (750 lines, iproute2 plugin), confirmed sysctl/nf/per-netns/routing pre-existing
- **2026-02-19:** Beginning Phase 09 (Tooling Integration) - ip tquic command, sysctl completion, netfilter hooks, routing table
- **2026-02-01:** Plan 08-04 complete - Debian package with systemd, kernel tuning, TPROXY nftables
- **2026-02-01:** Plan 08-03 complete - tquicd Go daemon, Prometheus metrics, web dashboard, connection logging, blocklist API
- **2026-02-01:** Plan 08-02 complete - TCP tunnel termination, zero-copy splice forwarding, QoS classification, hairpin detection, TPROXY
- **2026-02-01:** Plan 08-01 complete - Multi-tenant server with PSK auth, per-client rate limiting, session TTL for router reconnects
- **2026-02-01:** Plan 07-04 complete - Pacing with FQ integration, bandwidth-based rate calculation, path degradation on 5 consecutive losses
- **2026-02-01:** Plan 07-03 complete - Coupled CC coordination layer (OLIA/BALIA), path lifecycle integration, ECN CE mark handling
- **2026-02-01:** Plan 07-02 complete - Per-netns CC sysctl, SO_TQUIC_CONGESTION sockopt, BBR auto-selection for high-RTT paths
- **2026-02-01:** Plan 07-01 complete - CC framework central registry, path lifecycle wiring, MODULE_ALIAS for auto-loading
- **2026-01-31:** Plan 06-05 complete - SO_TQUIC_SCHEDULER sockopt, child socket inheritance, per-netns proc entry, pernet_operations
- **2026-01-31:** Plan 06-04 complete - BLEST blocking estimation scheduler, ECF earliest completion scheduler, inflight tracking
- **2026-01-31:** Plan 06-03 complete - Aggregate scheduler with cwnd/RTT capacity, weighted scheduler with DRR, 5% minimum floor
- **2026-01-31:** Plan 06-02 complete - MinRTT scheduler with tolerance band, RTT-based path selection
- **2026-01-31:** Plan 06-01 complete - Scheduler framework, tquic_sched.h API, per-netns defaults, connection locking
- **2026-01-31:** Plan 05-03 complete - Seamless failover with rhashtable tracking, 3x SRTT timeout, priority retransmit queue, bitmap deduplication
- **2026-01-31:** Plan 05-02 complete - RB-tree reorder buffer, O(log n) insertion, adaptive timeout for 600ms spread, lazy allocation
- **2026-01-31:** Plan 05-01 complete - Bonding state machine (SINGLE_PATH/PENDING/ACTIVE/DEGRADED), capacity weights from cwnd/RTT, 5% minimum weight floor, sockopt override
- **2026-01-31:** Plan 04-04 complete - Dynamic path add/remove, RCU-safe operations, interface-down state preservation, fast recovery
- **2026-01-31:** Plan 04-03 complete - Path validation (PATH_CHALLENGE/RESPONSE), adaptive timeout, RTT estimation, 256-frame queue limit
- **2026-01-31:** Plan 04-02 complete - Userspace PM, PM genetlink family, multicast events, 5 netlink commands
- **2026-01-31:** Plan 04-01 complete - PM type framework, kernel PM, per-netns sysctl, PM lifecycle hooks
- **2026-01-31:** Plan 03-03 complete - Gap closure: netns_tquic, tquic_statistics, diag init/exit, proc iteration
- **2026-01-31:** Gap closure plan 03-03 created - wire netns_tquic, MIB field, diag init, proc iteration
- **2026-01-31:** Plan 03-02 complete - MIB counters (37 fields), proc interface, error ring buffer
- **2026-01-31:** Plan 03-01 complete - inet_diag handler, tquic_diag.h UAPI, ss tool integration
- **2026-01-31:** Plan 02-04 complete - CID pool management, migration stubs, TQUIC_MIGRATE sockopt
- **2026-01-31:** Plan 02-03 complete - Stream socket implementation, TQUIC_NEW_STREAM ioctl
- **2026-01-31:** Plan 02-02 complete - Server listen()/accept(), listener hash table, tls_server_hello_x509
- **2026-01-31:** Plan 02-01 complete - TLS handshake integration, EQUIC error codes, blocking connect()
- **2026-01-31:** Plan 01-03 complete - lockdep class keys, sock_lock_init_class_and_name, inline lock docs
- **2026-01-31:** Plan 01-02 complete - tquic_pm.h UAPI, protocol.h internal header, lock documentation
- **2026-01-31:** Plan 01-01 complete - IPPROTO_TQUIC=263 added to in.h, Kconfig verified

---
*State updated: 2026-02-01T03:25:25Z*
