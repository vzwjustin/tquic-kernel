# Multi-AI Bonding Bug Fixes

**Date**: February 15, 2026
**Analysis Method**: Three-way AI verification (Opus 4.6, Gemini 3.0 Pro, Codex GPT 5.3)
**Bugs Discovered**: 2 critical production-blocking bugs
**Patches Created**: 2 patches fixing both bugs

---

## Executive Summary

Multi-AI analysis of TQUIC's multi-WAN bonding implementation revealed that while the **architecture is correct for true bandwidth aggregation**, there are **2 critical bugs** preventing it from working in production.

### Verdict Summary

| AI Model | Verdict | Key Finding |
|----------|---------|-------------|
| 🔵 **Opus 4.6** | TRUE bonding ✅ | Extended thinking verification |
| 🟡 **Gemini 3.0 Pro** | TRUE aggregation ✅ | Water-filling algorithm |
| 🔴 **Codex GPT 5.3** | Architecture ✅ / **Bugs found** ⚠️ | **2 critical bugs discovered** |

---

## Bug #1: RX Path Attribution Broken

### Discovery

**Discovered by**: Codex GPT-5.3 during exhaustive code audit
**Severity**: CRITICAL (blocks all multipath functionality)
**Location**: `net/tquic/tquic_udp.c`

### Problem

When `tquic_udp_sock_create4/6()` allocates ephemeral ports (when `path->local_addr` has port 0):
1. Port is allocated and stored in `us->local_port`
2. **Port is NEVER written back to `path->local_addr.sin_port`**
3. RX path attribution in `tquic_udp_encap_recv()` tries to match paths by comparing `us->local_port` against `p->local_addr.sin_port`
4. Since `path->local_addr.sin_port` remains 0, **match always fails**
5. Result: `path == NULL` passed to upper layers

### Impact

- ❌ Per-path RTT accounting broken
- ❌ Per-path loss detection broken
- ❌ Path validation decisions broken
- ❌ Multipath scheduler cannot function
- ❌ **WAN bonding completely non-functional**

### Evidence

```bash
$ rg "path->local_addr.*sin_port\\s*=" net/tquic
# NO RESULTS - port never written back!
```

### Fix

**Patch**: `0003-net-tquic-Fix-RX-path-attribution-write-ephemeral-port-back.patch`

Write allocated port back to `path->local_addr` in `tquic_udp_create_path_socket()`:

```c
/* Write allocated port back to path->local_addr */
if (path->local_addr.ss_family == AF_INET) {
    struct sockaddr_in *sin = (struct sockaddr_in *)&path->local_addr;
    sin->sin_port = us->local_port;
}
#if IS_ENABLED(CONFIG_IPV6)
else if (path->local_addr.ss_family == AF_INET6) {
    struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)&path->local_addr;
    sin6->sin6_port = us->local_port;
}
#endif
```

---

## Bug #2: No Hard Egress Interface Binding

### Discovery

**Discovered by**: Codex GPT-5.3 during multi-WAN routing analysis
**Severity**: HIGH (breaks bonding in complex routing scenarios)
**Location**: `net/tquic/tquic_udp.c:tquic_udp_xmit_skb4/6()`

### Problem

Current code routes packets with `fl4.flowi4_oif = 0`, relying on source IP to imply the correct route. This fails with:

- ❌ Policy routing rules
- ❌ Overlapping subnets on multiple interfaces
- ❌ VPN interfaces
- ❌ Multi-address NICs
- ❌ Any scenario where source IP != egress interface

### Evidence

```c
// net/tquic/tquic_udp.c:1457
fl4.flowi4_oif = 0;  // ← Should be path->ifindex!
```

### Impact

- Packets may egress on wrong WAN interface
- Multi-WAN bonding works only if "source IP implies route"
- **Fails in production with policy routing or complex network configs**

### Fix

**Patch**: `0004-net-tquic-Add-hard-egress-interface-binding-for-multi-WAN.patch`

1. **Set routing OIF to path's interface**:
```c
fl4.flowi4_oif = (us->path && us->path->ifindex > 0) ?
                 us->path->ifindex : 0;
```

2. **Bind socket to device at creation**:
```c
if (us->path && us->path->ifindex > 0) {
    us->sock->sk->sk_bound_dev_if = us->path->ifindex;
}
```

---

## Patch Application

Apply patches in order:

```bash
cd /Users/justinadams/Downloads/tquic-kernel

# Previous patches (already applied)
git apply 0001-net-tquic-Remove-broken-validation_work-mechanism.patch
git apply 0002-net-tquic-Fix-UAF-in-quic_tcp_close-missing-work-ca.patch

# New multi-WAN bonding fixes
git apply 0003-net-tquic-Fix-RX-path-attribution-write-ephemeral-port-back.patch
git apply 0004-net-tquic-Add-hard-egress-interface-binding-for-multi-WAN.patch
```

### Verify Patches

```bash
scripts/checkpatch.pl --strict 0003-*.patch
scripts/checkpatch.pl --strict 0004-*.patch
```

---

## Testing Recommendations

After applying these patches, test the following scenarios:

### 1. RX Path Attribution Test
```bash
# Start TQUIC with 2 WAN interfaces
# Monitor per-path statistics
cat /proc/net/tquic/paths

# Verify packets are correctly attributed to paths
# Look for non-zero rx_packets on both paths
```

### 2. Interface Binding Test
```bash
# Setup: 2 WAN interfaces with policy routing
ip rule add from 192.168.1.0/24 table 100
ip rule add from 192.168.2.0/24 table 200

# Verify packets egress on correct interface
tcpdump -i eth0 udp port 443 &
tcpdump -i eth1 udp port 443 &

# Start TQUIC connection
# Verify traffic appears on BOTH interfaces (not just one)
```

### 3. Multi-WAN Bonding Test
```bash
# 2 WAN connections: fiber (100Mbps) + LTE (20Mbps)
# Expected aggregate throughput: ~120Mbps
iperf3 -c <server> -t 60

# Verify scheduler distributes traffic proportionally:
# - Fiber should get ~5x more packets than LTE
# - Both paths should show active transmission
```

---

## Multi-AI Analysis Attribution

This bug discovery was made possible by three-way AI verification:

### 🔵 Claude Opus 4.6
- **Model**: `claude-opus-4-6`
- **Contribution**: Extended thinking verification of bonding architecture
- **Key Finding**: Reorder buffer is "smoking gun" for true bonding

### 🟡 Gemini 3.0 Pro
- **Model**: `gemini-3-pro-preview`
- **Contribution**: Water-filling algorithm analysis
- **Key Finding**: Unified bonding state with dynamic weight calculation

### 🔴 Codex GPT 5.3
- **Model**: `gpt-5.3-codex`
- **Contribution**: **Exhaustive implementation audit**
- **Key Finding**: **Discovered both critical bugs**
- **Tokens analyzed**: ~123,897

---

## Conclusion

**Design Verdict**: TQUIC implements TRUE multi-WAN bonding ✅

**Implementation Verdict**: CRITICAL BUGS FIXED with these patches ⚠️→✅

**Production Readiness**:
- Before patches: ❌ NOT READY (broken RX, no interface binding)
- After patches: ⚠️ NEEDS TESTING (bugs fixed, needs validation)

---

## Files Generated

1. `0003-net-tquic-Fix-RX-path-attribution-write-ephemeral-port-back.patch` - Fix RX path attribution
2. `0004-net-tquic-Add-hard-egress-interface-binding-for-multi-WAN.patch` - Add interface binding
3. `MULTI_AI_BONDING_BUG_FIXES.md` - This document

---

**Report Generated**: 2026-02-15
**Multi-AI Analysis**: Claude Opus 4.6 + Gemini 3.0 Pro + Codex GPT 5.3
**Bugs Fixed**: 2 critical production blockers
**Status**: Ready for testing
