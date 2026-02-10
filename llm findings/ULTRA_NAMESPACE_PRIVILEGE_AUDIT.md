# ULTRA-DEEP CROSS-CUTTING AUDIT: Network Namespace Isolation and Privilege Checks in TQUIC

**Auditor:** Claude Opus 4.6 (Kernel Security Reviewer)
**Date:** 2026-02-09
**Codebase:** `/Users/justinadams/Downloads/tquic-kernel/net/tquic/`
**Scope:** Namespace isolation, privilege escalation, container escape vectors, LSM integration

---

## Executive Summary

The TQUIC codebase has **systemic namespace isolation failures** that constitute container escape vulnerabilities. At least **15 distinct locations** hardcode `&init_net` instead of using the connection's or socket's network namespace. This means containers, network namespaces, and unprivileged users can:

1. Create sockets and route traffic in the host (init) network namespace
2. Enumerate network devices across namespace boundaries
3. Pollute host-namespace MIB statistics
4. Bypass container network isolation entirely

Additionally, **no privilege checks exist** for security-sensitive socket options (bond mode, migration, tunnel creation), and **zero LSM/security_socket_* hooks** are invoked, meaning SELinux and AppArmor cannot control TQUIC connections.

**Severity: CRITICAL -- Multiple container escape vectors present.**

---

## SECTION 1: Namespace Isolation Failures (Container Escape)

### CRITICAL-01: Tunnel Socket Creation Uses init_net (Container Escape)

**File:** `/Users/justinadams/Downloads/tquic-kernel/net/tquic/tquic_tunnel.c`
**Line:** 332

```c
err = sock_create_kern(&init_net, family, SOCK_STREAM, IPPROTO_TCP,
                       &sock);
```

**Impact:** When a containerized process creates a TQUIC tunnel, the underlying TCP socket is created in the host network namespace. This allows the container to:
- Establish TCP connections using host routing tables
- Bypass container network policies (iptables, nftables, CNI)
- Reach hosts that are not reachable from within the container's namespace

**Fix:** Must use `sock_net(conn->sk)` or propagate the caller's namespace. The tunnel struct should store a `struct net *` reference obtained from the originating socket.

---

### CRITICAL-02: MASQUE CONNECT-UDP Proxy Creates Sockets in init_net (Container Escape)

**File:** `/Users/justinadams/Downloads/tquic-kernel/net/tquic/masque/connect_udp.c`
**Line:** 459

```c
ret = sock_create_kern(&init_net, family, SOCK_DGRAM, IPPROTO_UDP, &sock);
```

**Impact:** A MASQUE proxy running inside a container creates its forwarding UDP sockets in the host namespace. An attacker who can trigger CONNECT-UDP proxy functionality from within a container can send UDP packets from the host's network stack to arbitrary destinations, completely bypassing container isolation.

**Additionally:** No privilege check exists to determine whether the caller is authorized to create proxy tunnels.

**Fix:** The tunnel must inherit the network namespace from the QUIC connection's socket: `sock_net(tunnel->conn->sk)`.

---

### CRITICAL-03: QUIC-over-TCP Client and Server Sockets Use init_net (Container Escape)

**File:** `/Users/justinadams/Downloads/tquic-kernel/net/tquic/transport/quic_over_tcp.c`
**Lines:** 1225, 1446

```c
// Client socket (line 1225):
ret = sock_create_kern(&init_net, addr->sa_family, SOCK_STREAM,
                       IPPROTO_TCP, &conn->tcp_sk);

// Server listener (line 1446):
ret = sock_create_kern(&init_net, AF_INET6, SOCK_STREAM,
                       IPPROTO_TCP, &listener->tcp_sk);
```

**Impact:** Both QUIC-over-TCP client connections and server listeners operate entirely in the host namespace, regardless of the caller's namespace. A container can listen on TCP ports and accept connections in the host namespace.

**Fix:** Propagate `sock_net(quic_conn->sk)` to the TCP socket creation.

---

### CRITICAL-04: AF_XDP Socket and Device Lookup Use init_net (Container Escape)

**File:** `/Users/justinadams/Downloads/tquic-kernel/net/tquic/af_xdp.c`
**Lines:** 367, 1096, 1117

```c
// Socket creation (line 367):
err = sock_create_kern(&init_net, AF_XDP, SOCK_RAW, 0, &xsk->sock);

// Device lookup (line 1096 and 1117):
dev = dev_get_by_name(&init_net, ifname);
```

**Partial mitigation:** Line 300 correctly uses `current->nsproxy->net_ns` for the initial device lookup in `tquic_xsk_create()`, and the function does check `capable(CAP_NET_ADMIN)`. However, the actual XDP socket is then created in `&init_net` (line 367), and subsequent device lookups at lines 1096/1117 also hardcode `&init_net`. This means a process with `CAP_NET_ADMIN` inside a user namespace (common in rootless containers) could attach XDP programs to host interfaces.

**Fix:** Replace `&init_net` with `current->nsproxy->net_ns` consistently, and use `ns_capable()` instead of `capable()` to check capabilities relative to the correct namespace.

---

### CRITICAL-05: Netfilter Hooks Registered Only in init_net

**File:** `/Users/justinadams/Downloads/tquic-kernel/net/tquic/tquic_nf.c`
**Lines:** 800, 813, 839

```c
ret = nf_register_net_hooks(&init_net, tquic_nf_hooks,
                            ARRAY_SIZE(tquic_nf_hooks));

tquic_nf_proc_entry = proc_create("tquic_conntrack", 0444,
                                   init_net.proc_net, &tquic_nf_proc_ops);
```

**Impact:** TQUIC connection tracking only works in the init namespace. TQUIC connections within containers will not be tracked by the netfilter integration. This is a functional bug that also means:
- Container traffic may bypass TQUIC-specific firewall rules
- Connection tracking state is not isolated per namespace

**Fix:** Register hooks via `pernet_operations` so each namespace gets its own hooks, or verify this is intentionally init_net-only and document the limitation.

---

### CRITICAL-06: IPv4/IPv6 Address Discovery Enumerates Host Interfaces (Container Escape / Info Leak)

**File:** `/Users/justinadams/Downloads/tquic-kernel/net/tquic/pm/path_manager.c`
**Line:** 424

```c
for_each_netdev(&init_net, dev) {
```

**File:** `/Users/justinadams/Downloads/tquic-kernel/net/tquic/tquic_ipv6.c`
**Line:** 826

```c
for_each_netdev_rcu(&init_net, dev) {
```

**Impact:** When TQUIC discovers available network addresses for multipath, it enumerates **all devices in the host namespace**, regardless of the caller's container. This leaks host network topology information (interface names, IP addresses) to containerized processes. In multipath bonding mode, it could also cause the container to establish paths via host-only interfaces.

**Fix:** Use `sock_net(conn->sk)` to enumerate only devices visible in the connection's namespace.

---

### HIGH-07: ip_local_out Uses init_net for Packet Transmission

**File:** `/Users/justinadams/Downloads/tquic-kernel/net/tquic/tquic_output.c`
**Line:** 1730

```c
ret = ip_local_out(&init_net, NULL, skb);
```

**Impact:** Packets are transmitted via the host namespace's routing table and netfilter chains. Iptables rules and routing policies configured in a container's namespace will not apply. This directly circumvents container network isolation for outbound TQUIC traffic on this code path.

**Note:** Line 1681 has a partial fix using `net ?: &init_net` for route lookup, but when `net` is NULL, it still falls back to init_net. The `ip_local_out` call always uses init_net unconditionally.

**Fix:** Use `sock_net(conn->sk)` for `ip_local_out`. Remove the `&init_net` fallback from the route lookup.

---

### HIGH-08: Route Lookup Fallback to init_net

**File:** `/Users/justinadams/Downloads/tquic-kernel/net/tquic/tquic_output.c`
**Line:** 1681

```c
rt = ip_route_output_key(net ?: &init_net, &fl4);
```

**Impact:** If `net` is NULL (which can happen when `path->conn->sk` is NULL, as shown at line 1714), routing lookups silently fall to the host namespace. This is a subtle escape -- if a connection loses its socket reference temporarily, packets get routed via the host.

**Fix:** If `net` is NULL, the packet should be dropped, not routed via init_net.

---

### HIGH-09: BPM Path Manager Falls Back to init_net

**File:** `/Users/justinadams/Downloads/tquic-kernel/net/tquic/bond/tquic_bpm.c`
**Line:** 1005

```c
dev = dev_get_by_index_rcu(path->pm ? path->pm->net : &init_net, ifindex);
```

**Impact:** If `path->pm` is NULL, device lookup occurs in the host namespace instead of failing safely. This is a defense-in-depth issue -- the `path->pm` should never be NULL if called correctly, but the fallback to init_net is unsafe.

**Fix:** Return -EINVAL if `path->pm` is NULL rather than falling back to init_net.

---

### HIGH-10: Stateless Reset Falls Back to init_net

**File:** `/Users/justinadams/Downloads/tquic-kernel/net/tquic/tquic_stateless_reset.c`
**Line:** 370

```c
net = sk ? sock_net(sk) : &init_net;
```

**Impact:** If a stateless reset is sent without a socket context (which is plausible for stateless handling), the reset packet is sent from the host namespace.

**Fix:** Require a valid socket/namespace context or drop the reset.

---

### MEDIUM-11: Security Hardening MIB Stats Always Go to init_net

**File:** `/Users/justinadams/Downloads/tquic-kernel/net/tquic/security_hardening.c`
**Lines:** 848-860

```c
TQUIC_INC_STATS(&init_net, TQUIC_MIB_SEC_PRE_HS_LIMIT);
TQUIC_INC_STATS(&init_net, TQUIC_MIB_SEC_RETIRE_CID_FLOOD);
TQUIC_INC_STATS(&init_net, TQUIC_MIB_SEC_NEW_CID_RATE_LIMIT);
TQUIC_INC_STATS(&init_net, TQUIC_MIB_SEC_OPTIMISTIC_ACK);
TQUIC_INC_STATS(&init_net, TQUIC_MIB_SEC_INVALID_ACK);
```

**Impact:** Security event counters are always attributed to the host namespace, not the namespace where the attack occurred. This pollutes host statistics and prevents per-namespace security monitoring. A containerized attacker generating flood traffic will show up in the host's MIB counters but not in their own namespace's counters.

**Fix:** Pass the connection's `sock_net(conn->sk)` to the security event reporting function.

---

### MEDIUM-12: Sysctl and Proc Entries Registered in init_net Only

**File:** `/Users/justinadams/Downloads/tquic-kernel/net/tquic/tquic_sysctl.c`
**Line:** 2077

```c
tquic_sysctl_header = register_net_sysctl_sz(&init_net, "net/tquic", ...);
```

**File:** `/Users/justinadams/Downloads/tquic-kernel/net/tquic/cong/persistent_cong.c`
**Line:** 412

**File:** `/Users/justinadams/Downloads/tquic-kernel/net/tquic/tquic_ratelimit.c`
**Line:** 1231

**File:** `/Users/justinadams/Downloads/tquic-kernel/net/tquic/transport/tcp_fallback.c`
**Lines:** 863, 874

**Impact:** Multiple sysctl tables and proc entries are registered only in the init_net namespace. While `tquic_proto.c` does have per-netns sysctl registration via `pernet_operations` (correctly skipping init_net at line 843), several subsystems bypass this and register globally. Containers cannot see or configure their own TQUIC sysctls for these subsystems.

**Note:** `tquic_sysctl.c` uses `current->nsproxy->net_ns` in proc handlers (lines 272, 341, 405, etc.), which is correct for reading per-netns data. However, the sysctl *registration* at line 2077 means only init_net has the sysctl entries visible.

---

### MEDIUM-13: Proc Entries Hardcoded to init_net.proc_net

**File:** `/Users/justinadams/Downloads/tquic-kernel/net/tquic/napi.c`
**Line:** 1071

```c
pde = proc_create("tquic_napi", 0444, init_net.proc_net, ...);
```

**File:** `/Users/justinadams/Downloads/tquic-kernel/net/tquic/crypto/cert_verify.c`
**Line:** 2860

```c
tquic_cert_proc_dir = proc_mkdir("tquic_cert", init_net.proc_net);
```

**File:** `/Users/justinadams/Downloads/tquic-kernel/net/tquic/crypto/hw_offload.c`
**Line:** 1141

**Impact:** Diagnostic and certificate proc entries are only visible in the host namespace. Lower severity but indicates incomplete namespace awareness.

---

### MEDIUM-14: Diag/Tracepoints Initialize in init_net

**File:** `/Users/justinadams/Downloads/tquic-kernel/net/tquic/diag/tracepoints.c`
**Lines:** 707, 718

```c
ret = tquic_path_metrics_init(&init_net);
// ...
tquic_path_metrics_exit(&init_net);
```

**Impact:** Path metrics tracing is only initialized for the host namespace.

---

## SECTION 2: Privilege Check Failures

### CRITICAL-15: No Privilege Check for TQUIC Socket Creation

**File:** `/Users/justinadams/Downloads/tquic-kernel/net/tquic/tquic_proto.c`
**Lines:** 554-577 (proto_ops registration)

The TQUIC protocol family registers as a standard socket type. Any unprivileged user can `socket(AF_INET, SOCK_DGRAM, IPPROTO_QUIC)` (or equivalent) and create a TQUIC socket. While QUIC itself runs over UDP and inherits UDP's permission model, the TQUIC-specific features (bonding, tunneling, multipath, MASQUE proxy) grant significantly elevated capabilities without additional checks.

**Fix:** Consider requiring `CAP_NET_ADMIN` for bonding/multipath features, or at minimum for creating tunnels and MASQUE proxies.

---

### CRITICAL-16: No Privilege Checks for Security-Sensitive Socket Options

**File:** `/Users/justinadams/Downloads/tquic-kernel/net/tquic/tquic_socket.c`
**Lines:** 726-1300 (tquic_sock_setsockopt)

The following socket options have NO capability checks:

| Option | Impact | Should Require |
|--------|--------|----------------|
| `TQUIC_BOND_MODE` (line 771) | Changes bonding mode, affects all paths | `CAP_NET_ADMIN` |
| `TQUIC_BOND_PATH_WEIGHT` (line 780) | Sets path weights, affects traffic distribution | `CAP_NET_ADMIN` |
| `TQUIC_MIGRATE` (line 803) | Forces connection migration to new address | `CAP_NET_ADMIN` |
| `TQUIC_MIGRATION_ENABLED` (line 823) | Enables connection migration | `CAP_NET_ADMIN` |
| `TQUIC_SCHEDULER` (line 830) | Changes multipath scheduler | `CAP_NET_ADMIN` |
| `TQUIC_CONGESTION` (line 882) | Changes congestion control algorithm | Consider `CAP_NET_ADMIN` |

An unprivileged user can configure multipath bonding, change schedulers, and force connection migration. In a multi-tenant environment, this could be used to manipulate shared network resources.

**Fix:** Add `ns_capable(sock_net(sk)->user_ns, CAP_NET_ADMIN)` checks for privileged options.

---

### HIGH-17: MASQUE Proxy Has No Access Control

**File:** `/Users/justinadams/Downloads/tquic-kernel/net/tquic/masque/connect_udp.c` (entire file)

The MASQUE CONNECT-UDP proxy implementation has **no privilege checks whatsoever**. Any user who can create a QUIC socket can:
- Act as a MASQUE proxy, forwarding UDP traffic
- Proxy traffic to arbitrary destinations
- Combined with CRITICAL-02 (init_net), proxy traffic from the host namespace

This is equivalent to an open relay at the kernel level.

**Fix:** Require `CAP_NET_ADMIN` to enable MASQUE proxy functionality.

---

### HIGH-18: Load Balancer Has No Privilege Checks

**File:** `/Users/justinadams/Downloads/tquic-kernel/net/tquic/lb/quic_lb.c`

No `capable()` or `ns_capable()` calls found in the load balancer module. Load balancer configuration (server ID assignment, routing decisions) can potentially be modified by unprivileged users.

**Fix:** All LB configuration interfaces should require `CAP_NET_ADMIN`.

---

### HIGH-19: Tunnel Creation Has Insufficient Privilege Checks

**File:** `/Users/justinadams/Downloads/tquic-kernel/net/tquic/tquic_tunnel.c`
**Lines:** 373-378

```c
if (capable(CAP_NET_ADMIN)) {
    tquic_err("IP_TRANSPARENT failed despite CAP_NET_ADMIN: %d\n", err);
} else {
    tquic_info("IP_TRANSPARENT requires CAP_NET_ADMIN, using normal mode\n");
}
```

The tunnel creation function only checks `CAP_NET_ADMIN` for the `IP_TRANSPARENT` option and gracefully degrades if absent. **No overall privilege check gates tunnel creation itself.** An unprivileged user can create TCP tunnels (albeit without IP_TRANSPARENT). Combined with CRITICAL-01 (init_net), these tunnels operate in the host namespace.

Additionally, `capable()` is used instead of `ns_capable()`. In user namespaces (rootless containers), `capable(CAP_NET_ADMIN)` checks against the initial user namespace, which is correct for preventing privilege escalation. However, if the code *should* allow container-root to use IP_TRANSPARENT within their namespace, `ns_capable()` should be used instead.

**Fix:** Require `CAP_NET_ADMIN` to create tunnels. Use `ns_capable(sock_net(sk)->user_ns, CAP_NET_ADMIN)`.

---

### HIGH-20: Packet Forwarding Has No Privilege Checks

**File:** `/Users/justinadams/Downloads/tquic-kernel/net/tquic/tquic_forward.c`

The zero-copy splice forwarding implementation has no capability checks. Any user who can create a QUIC socket can set up forwarding between QUIC streams and TCP sockets.

**Fix:** Require `CAP_NET_ADMIN` to enable packet forwarding.

---

### MEDIUM-21: Sysctl Permissions Are Overly Permissive

**File:** `/Users/justinadams/Downloads/tquic-kernel/net/tquic/tquic_sysctl.c`
**Lines:** 842-938

All sysctls use mode `0644`, meaning any user can read them and root can write. The following sysctls should have more restrictive permissions:

| Sysctl | Current | Should Be | Reason |
|--------|---------|-----------|--------|
| `key_update_interval_packets` | 0644 | 0600 | Cryptographic parameter |
| `key_update_interval_seconds` | 0600 | 0600 | Already correct |
| `debug_level` | 0644 | 0600 | May enable verbose logging that leaks sensitive data |

Most other sysctls at 0644 are reasonable.

---

### MEDIUM-22: XDP Uses capable() Instead of ns_capable()

**File:** `/Users/justinadams/Downloads/tquic-kernel/net/tquic/af_xdp.c`
**Lines:** 296, 752, 950

```c
if (!capable(CAP_NET_ADMIN))
    return -EPERM;
```

Using `capable()` checks against the init user namespace, which is the conservative (safe) choice. However, this means XDP cannot be used from within any user namespace, even privileged containers. If the intention is to allow container-root to use XDP within their namespace, `ns_capable()` should be used. If the intention is to restrict to host-root only, this is correct but should be documented.

---

### LOW-23: Netlink Operations All Require GENL_ADMIN_PERM

**File:** `/Users/justinadams/Downloads/tquic-kernel/net/tquic/tquic_netlink.c`
**Lines:** 1571-1617

All netlink operations correctly require `GENL_ADMIN_PERM`:
```c
{ .cmd = TQUIC_NL_CMD_PATH_ADD,    .flags = GENL_ADMIN_PERM },
{ .cmd = TQUIC_NL_CMD_PATH_REMOVE, .flags = GENL_ADMIN_PERM },
{ .cmd = TQUIC_NL_CMD_PATH_SET,    .flags = GENL_ADMIN_PERM },
{ .cmd = TQUIC_NL_CMD_PATH_GET,    .flags = GENL_ADMIN_PERM },
{ .cmd = TQUIC_NL_CMD_PATH_LIST,   .flags = GENL_ADMIN_PERM },
{ .cmd = TQUIC_NL_CMD_SCHED_SET,   .flags = GENL_ADMIN_PERM },
{ .cmd = TQUIC_NL_CMD_SCHED_GET,   .flags = GENL_ADMIN_PERM },
{ .cmd = TQUIC_NL_CMD_STATS_GET,   .flags = GENL_ADMIN_PERM },
{ .cmd = TQUIC_NL_CMD_CONN_GET,    .flags = GENL_ADMIN_PERM },
```

The multicast group also correctly uses `GENL_MCAST_CAP_NET_ADMIN` (line 274). This is properly implemented.

**Positive finding:** Netlink interface is well-secured.

---

### LOW-24: Netlink Correctly Uses sock_net for Namespace Scoping

**File:** `/Users/justinadams/Downloads/tquic-kernel/net/tquic/tquic_netlink.c`
**Line:** 985

```c
struct net *net = sock_net(skb->sk);
```

The netlink path dump correctly scopes lookups to the caller's namespace. This is correct.

**Positive finding.**

---

## SECTION 3: LSM/Security Module Integration

### CRITICAL-25: No security_socket_* Hook Invocations

A grep for `security_socket` across the entire TQUIC codebase returns **zero results**.

**Impact:** SELinux, AppArmor, Smack, and other Linux Security Modules cannot control TQUIC connections. This means:

1. SELinux policies cannot restrict which processes use QUIC
2. AppArmor profiles cannot deny QUIC network access
3. Audit subsystem will not log TQUIC socket operations
4. seccomp-bpf can only block the initial `socket()` call, not TQUIC-specific operations

For context, the standard kernel TCP/UDP code paths invoke:
- `security_socket_create()` -- during socket creation
- `security_socket_bind()` -- during bind
- `security_socket_connect()` -- during connect
- `security_socket_sendmsg()` / `security_socket_recvmsg()` -- during data transfer

TQUIC appears to rely on the underlying UDP socket's security hooks, which may provide partial coverage for the data path. However, TQUIC-specific operations (tunnel creation, MASQUE proxy, multipath bonding) are completely invisible to LSMs.

**Fix:** Invoke appropriate `security_socket_*` hooks in TQUIC socket operations. At minimum:
- `security_socket_create()` in `tquic_sock_create()`
- `security_socket_connect()` in `tquic_connect_socket()`
- `security_socket_bind()` in `tquic_sock_bind()`

---

## SECTION 4: Correct Namespace Usage (Positive Findings)

The following areas correctly use `sock_net()` for namespace awareness:

1. **MIB statistics in data path** -- Most `TQUIC_INC_STATS` / `TQUIC_ADD_STATS` calls use `sock_net(conn->sk)` (e.g., `tquic_input.c`, `tquic_handshake.c`, `tquic_output.c`)
2. **Netlink dump operations** -- Correctly use `sock_net(skb->sk)` for namespace scoping
3. **UDP socket creation for data path** -- `tquic_udp.c` uses `sock_net(sk)` for creating UDP sockets
4. **Child socket allocation** -- `tquic_handshake.c:1690` correctly uses `sock_net(listener_sk)`
5. **Per-netns pernet_operations** -- `tquic_proto.c`, `tquic_netlink.c`, `tquic_ratelimit.c`, `tquic_ipv6.c`, `pm/pm_types.c`, `transport/tcp_fallback.c` all register pernet_operations for per-namespace state
6. **Proc/diag namespace filtering** -- `tquic_proc.c:327`, `tquic_diag.c:154` correctly filter by namespace
7. **Route lookups in core output** -- `core/quic_output.c:432` correctly uses `sock_net(conn->sk)`
8. **Stream socket creation** -- `tquic_stream.c:566` correctly uses `sock_net(parent_sk)`

This indicates the core data path is largely namespace-aware, but the tunnel/proxy/auxiliary subsystems were added without the same namespace discipline.

---

## SECTION 5: Summary of All Findings

### By Severity

| Severity | Count | Issue Range |
|----------|-------|-------------|
| CRITICAL | 7 | #01-06, #15-17, #25 |
| HIGH | 6 | #07-10, #18-20 |
| MEDIUM | 5 | #11-14, #21-22 |
| LOW | 2 | #23-24 (positive findings) |

### By Category

| Category | Issues |
|----------|--------|
| Container Escape (init_net) | #01, #02, #03, #04, #05, #06, #07, #08, #09, #10 |
| Missing Privilege Checks | #15, #16, #17, #18, #19, #20 |
| Information Disclosure | #06, #11 |
| LSM Bypass | #25 |
| Sysctl/Proc Visibility | #12, #13, #14, #21 |

### Complete init_net Usage Inventory

| File | Line | Context | Severity |
|------|------|---------|----------|
| `tquic_tunnel.c` | 332 | `sock_create_kern(&init_net, ...)` -- tunnel TCP socket | CRITICAL |
| `masque/connect_udp.c` | 459 | `sock_create_kern(&init_net, ...)` -- proxy UDP socket | CRITICAL |
| `transport/quic_over_tcp.c` | 1225 | `sock_create_kern(&init_net, ...)` -- TCP client | CRITICAL |
| `transport/quic_over_tcp.c` | 1446 | `sock_create_kern(&init_net, ...)` -- TCP listener | CRITICAL |
| `af_xdp.c` | 367 | `sock_create_kern(&init_net, ...)` -- XDP socket | CRITICAL |
| `af_xdp.c` | 1096, 1117 | `dev_get_by_name(&init_net, ...)` -- device lookup | HIGH |
| `tquic_nf.c` | 800 | `nf_register_net_hooks(&init_net, ...)` | CRITICAL |
| `tquic_nf.c` | 813 | `proc_create(..., init_net.proc_net, ...)` | MEDIUM |
| `tquic_ipv6.c` | 826 | `for_each_netdev_rcu(&init_net, ...)` -- addr discovery | CRITICAL |
| `pm/path_manager.c` | 424 | `for_each_netdev(&init_net, ...)` -- addr discovery | CRITICAL |
| `tquic_output.c` | 1681 | `ip_route_output_key(net ?: &init_net, ...)` -- route fallback | HIGH |
| `tquic_output.c` | 1730 | `ip_local_out(&init_net, ...)` -- packet send | HIGH |
| `tquic_stateless_reset.c` | 370 | `sk ? sock_net(sk) : &init_net` -- fallback | HIGH |
| `bond/tquic_bpm.c` | 1005 | `path->pm ? path->pm->net : &init_net` -- fallback | HIGH |
| `security_hardening.c` | 848-860 | `TQUIC_INC_STATS(&init_net, ...)` -- MIB counters | MEDIUM |
| `tquic_sysctl.c` | 2077 | `register_net_sysctl_sz(&init_net, ...)` | MEDIUM |
| `cong/persistent_cong.c` | 412 | `register_net_sysctl_sz(&init_net, ...)` | MEDIUM |
| `tquic_ratelimit.c` | 1231 | `register_net_sysctl_sz(&init_net, ...)` | MEDIUM |
| `transport/tcp_fallback.c` | 863, 874 | sysctl and proc in init_net | MEDIUM |
| `napi.c` | 1071 | `proc_create(..., init_net.proc_net, ...)` | MEDIUM |
| `crypto/cert_verify.c` | 2860 | `proc_mkdir(..., init_net.proc_net)` | MEDIUM |
| `crypto/hw_offload.c` | 1141 | `proc_create(..., init_net.proc_net, ...)` | MEDIUM |
| `diag/tracepoints.c` | 707, 718 | `tquic_path_metrics_init/exit(&init_net)` | MEDIUM |

---

## Recommended Remediation Priority

### Immediate (P0) -- Container Escape Vectors
1. Replace all `sock_create_kern(&init_net, ...)` with namespace-aware versions
2. Fix `ip_local_out(&init_net, ...)` to use connection's namespace
3. Fix address discovery to use connection's namespace
4. Remove all `&init_net` fallbacks in favor of dropping/failing

### Short-term (P1) -- Privilege Escalation
5. Add `CAP_NET_ADMIN` checks for bonding, migration, tunnel, MASQUE, and LB socket options
6. Add LSM hooks to TQUIC socket operations
7. Use `ns_capable()` instead of `capable()` where appropriate

### Medium-term (P2) -- Defense in Depth
8. Register NF hooks per-namespace via pernet_operations
9. Fix MIB counter namespace attribution
10. Audit and fix sysctl/proc namespace visibility

---

*End of audit report.*
