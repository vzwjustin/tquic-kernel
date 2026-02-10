# TQUIC Ultra-Deep DoS and Resource Exhaustion Audit

**Auditor**: Kernel Security Reviewer (Claude Opus 4.6)
**Date**: 2026-02-09
**Codebase**: `/Users/justinadams/Downloads/tquic-kernel/net/quic/tquic/`
**Scope**: Every denial-of-service and resource exhaustion vector in TQUIC

---

## Executive Summary

The TQUIC codebase demonstrates a mature security posture with **defense-in-depth layering** across most DoS vectors. Multiple rate limiting subsystems (token bucket + cookie-based), pre-handshake memory budgets, anti-amplification enforcement, stream limits, and connection tracking limits are all present. However, the audit uncovered **12 medium-to-high severity issues** and **9 low-severity hardening opportunities** where an attacker could still achieve partial resource exhaustion or degraded service.

---

## Section 1: MEMORY EXHAUSTION VECTORS

### 1.1 Allocation Sites Audit

Total allocation sites identified: **~120** across `kmalloc`, `kzalloc`, `alloc_skb`, `kcalloc`, `kmalloc_array`, `kmem_cache_zalloc`.

#### CRITICAL: Attacker-Controlled Allocation Sizes

| File | Line | Allocation | Size Source | Bounded? |
|------|------|-----------|-------------|----------|
| `tquic_input.c` | 2589 | `kmalloc(payload_len, GFP_ATOMIC)` | Network packet payload | YES - capped at packet length |
| `tquic_input.c` | 944 | `alloc_skb(length, GFP_ATOMIC)` | STREAM frame length field | YES - capped at 65535 (line 909) |
| `tquic_input.c` | 1455 | `alloc_skb(length, GFP_ATOMIC)` | DATAGRAM frame length | YES - capped at ctx->len |
| `tquic_output.c` | 1819 | `kmalloc(chunk, GFP_ATOMIC)` | Stream data chunk | YES - bounded by MTU |
| `tquic_output.c` | 2508 | `kmalloc(path->mtu, GFP_ATOMIC)` | Path MTU | YES - capped at path MTU |
| `fec/fec_decoder.c` | 114 | `kmalloc(length, GFP_ATOMIC)` | FEC symbol length (u16) | PARTIAL - u16 max is 65535 |
| `tquic_cid.c` | 821 | `alloc_skb(frame_len + 32, GFP_ATOMIC)` | CID frame size | YES - bounded by CID len limit |
| `tquic_handshake.c` | 605 | `alloc_skb(ch_len, GFP_KERNEL)` | ClientHello length | NEEDS REVIEW |
| `tquic_handshake.c` | 1136 | `alloc_skb(resp_len, GFP_ATOMIC)` | Handshake response | NEEDS REVIEW |

**Finding MEM-1 (MEDIUM)**: `tquic_handshake.c` lines 605 and 1136 allocate skbs based on computed handshake message lengths (`ch_len`, `resp_len`). While these are internally computed (not directly from network), a malformed or oversized CRYPTO frame feeding into the TLS state machine could result in large allocation requests. The pre-handshake memory limit (`tquic_pre_hs_can_allocate`) guards the CRYPTO frame processing, but the handshake response generation path may not be covered by the same budget.

- **File**: `/Users/justinadams/Downloads/tquic-kernel/net/quic/tquic/tquic_handshake.c`
- **Lines**: 605, 1136
- **Impact**: Server could allocate large handshake response buffers if attacker sends carefully crafted CRYPTO data
- **Recommendation**: Enforce a hard cap on `ch_len` and `resp_len` (e.g., 16KB max for any single handshake message)

### 1.2 Queue Boundedness Analysis

| Queue | File | Bounded? | Mechanism |
|-------|------|----------|-----------|
| `stream->recv_buf` (skb_queue) | `tquic_input.c:971` | YES | Socket receive buffer (`sk_rcvbuf`) check at line 963 |
| `stream->send_buf` (skb_queue) | `tquic_stream.c` | YES | Socket write buffer accounting |
| `path->response.queue` (PATH_RESPONSE) | `pm/path_validation.c:277` | YES | `TQUIC_MAX_PENDING_RESPONSES` cap at line 259 |
| `conn->crypto_buffer[space]` | `tquic_handshake.c:615` | PARTIAL | Pre-HS memory limit, but no per-queue cap |
| `fec decoder active_blocks` | `fec/fec_decoder.c:277` | YES | `max_active_blocks` limit at line 266 |
| `pool->remote_cids` (list) | `tquic_cid.c:663` | YES | `active_connection_id_limit` check at line 656 |

**Finding MEM-2 (MEDIUM)**: The `crypto_buffer[space]` queue per connection is only bounded by the global pre-handshake memory budget, not by a per-connection limit. An attacker establishing many connections, each sending CRYPTO frames just below the per-IP budget, could collectively exhaust the global 64MB budget and starve legitimate connections.

- **File**: `/Users/justinadams/Downloads/tquic-kernel/net/quic/tquic/tquic_handshake.c`
- **Line**: 615
- **Impact**: Distributed attack from many IPs could exhaust crypto buffer memory
- **Recommendation**: Add per-connection crypto buffer limit (e.g., 256KB per connection per PN space)

### 1.3 Connection Limits

| Limit | Value | File | Line |
|-------|-------|------|------|
| NF connection tracking max | 65536 | `tquic_nf.c` | 69 |
| Pre-handshake connections per IP | 16 | `security_hardening.h` | 53 |
| Pre-handshake global memory | 64 MB | `security_hardening.h` | 43 |
| Pre-handshake per-IP memory | 1 MB | `security_hardening.h` | 48 |
| Global rate limit | 10000 conn/sec | `rate_limit.h` | 44 |
| Per-IP rate limit | 100 conn/sec | `rate_limit.h` | 46 |
| Per-client (PSK) rate limit | 10 conn/sec | `tquic_server.c` | 43 |

**Finding MEM-3 (LOW)**: The NF connection tracking limit (65536) has no per-source-IP limit at the netfilter layer. While the TQUIC protocol layer has per-IP limits, the NF `tquic_nf_conn_alloc` at line 497 only checks the global count, not per-IP. An attacker with many IPs could fill the NF tracking table and prevent new connection tracking for legitimate users.

- **File**: `/Users/justinadams/Downloads/tquic-kernel/net/quic/tquic/tquic_nf.c`
- **Lines**: 494-497
- **Impact**: NF tracking table exhaustion from distributed sources
- **Recommendation**: Add per-IP NF tracking limit (e.g., 256 entries per source IP)

### 1.4 Stream Limits

The stream creation path in `tquic_stream_open_incoming()` properly validates against `max_streams_bidi` and `max_streams_uni` (lines 634-648 of `tquic_main.c`). This is correctly enforced per RFC 9000 Section 4.6.

**Finding MEM-4 (LOW)**: While stream count is limited, each stream allocates both `send_buf` and `recv_buf` skb queues. An attacker opening `max_streams_bidi` streams and sending minimal data to each creates per-stream overhead. With default limits, this is bounded but should be monitored.

- **File**: `/Users/justinadams/Downloads/tquic-kernel/net/quic/tquic/tquic_main.c`
- **Lines**: 651-665
- **Impact**: Memory overhead of ~1KB per empty stream x max_streams
- **Recommendation**: Consider lazy initialization of stream buffers

---

## Section 2: CPU EXHAUSTION VECTORS

### 2.1 Loop Analysis

Total loop count: **870** `for`/`while`/`do` loops across 154 files.

#### Attacker-Controlled Loop Bounds

**Finding CPU-1 (MEDIUM)**: ACK range processing loop.

```c
// tquic_input.c:646
for (i = 0; i < ack_range_count; i++) {
    // varint decode for gap and range (2 varints per iteration)
}
```

The `ack_range_count` is capped at `TQUIC_MAX_ACK_RANGES = 256` (line 642). Each iteration does 2 varint decodes. This caps the loop at 256 iterations -- acceptable, but an attacker can force 256 * 2 = 512 varint decodes per ACK frame, and multiple ACK frames per packet. There is no per-packet limit on the number of ACK frames.

- **File**: `/Users/justinadams/Downloads/tquic-kernel/net/quic/tquic/tquic_input.c`
- **Lines**: 642-660
- **Impact**: Moderate CPU consumption from crafted ACK-heavy packets
- **Recommendation**: Limit ACK frames per packet to 1 (which RFC 9000 already expects)

**Finding CPU-2 (MEDIUM)**: FEC decoder block search is a linear list walk.

```c
// fec/fec_decoder.c:220
list_for_each_entry(block, &dec->active_blocks, list) {
    if (block->block_id == block_id)
        return block;
}
```

With `max_active_blocks = 16` (default), this is bounded. However, the per-block symbol duplicate check at line 285 is also a linear scan over source symbols. An attacker sending many symbols per block could make this O(n^2) within a block.

- **File**: `/Users/justinadams/Downloads/tquic-kernel/net/quic/tquic/fec/fec_decoder.c`
- **Lines**: 220-226, 285-289
- **Impact**: O(n^2) symbol dedup within FEC blocks
- **Recommendation**: Use a bitmap or hash set for symbol ID dedup within blocks

**Finding CPU-3 (LOW)**: CID pool active count enumeration.

```c
// tquic_cid.c:652
list_for_each_entry(iter, &pool->remote_cids, list) {
    if (iter->state == CID_STATE_ACTIVE)
        active_count++;
}
```

This traverses the entire CID list on every `NEW_CONNECTION_ID` frame. With CVE-2024-22189 rate limiting in place (line 617), this is mitigated, but the linear scan under `pool->lock` could contribute to lock contention.

- **File**: `/Users/justinadams/Downloads/tquic-kernel/net/quic/tquic/tquic_cid.c`
- **Lines**: 652-656
- **Impact**: Lock contention under CID flood
- **Recommendation**: Maintain running `active_count` counter to avoid list traversal

### 2.2 Crypto Operation Cost

**Finding CPU-4 (HIGH)**: Attacker can trigger expensive decrypt attempts cheaply.

The packet reception path at `tquic_input.c:2618` attempts decryption on every received packet. If decryption fails for short-header packets, the code at line 2631 attempts a second decryption with old keys (`tquic_try_decrypt_with_old_keys`). An attacker sending garbage short-header packets to a valid DCID forces TWO AEAD decrypt operations per packet, both of which fail.

AEAD decryption (AES-GCM or ChaCha20-Poly1305) is computationally expensive. An attacker knowing the DCID (observable from the wire) can flood garbage packets to exhaust server CPU.

- **File**: `/Users/justinadams/Downloads/tquic-kernel/net/quic/tquic/tquic_input.c`
- **Lines**: 2618-2644
- **Impact**: CPU exhaustion via garbage packet flood (each packet costs 2 AEAD operations)
- **Recommendation**: Track consecutive decryption failures per CID and temporarily blacklist CIDs with excessive failures. Also, the rate limiting at the UDP receive entry point should cover short-header packets, not just Initial packets.

### 2.3 Hash Table Collision Analysis

**Finding CPU-5 (HIGH)**: All hash tables use `jhash` with a **fixed seed of 0**.

```c
// tquic_nf.c:147
return jhash(cid->id, cid->len, 0);

// tquic_ratelimit.c:97
return jhash_1word(sin->sin_addr.s_addr, 0);

// security_hardening.c:73
return jhash(&sin->sin_addr, sizeof(sin->sin_addr), 0);

// tquic_forward.c:157
hash = jhash(&sin->sin_addr, sizeof(sin->sin_addr), 0);
```

Using seed 0 makes hash collisions deterministic and predictable. An attacker who knows the hash function (it is open source) can craft inputs that all hash to the same bucket, degrading hash table operations from O(1) to O(n). This affects:

1. **NF connection tracking** (`tquic_nf_cid_hash`, `tquic_nf_addr_hash`) - degraded connection lookup
2. **Rate limiting** (`tquic_ratelimit.c`) - degraded per-IP rate limit lookups
3. **Security hardening** IP tracking - degraded pre-HS defense
4. **Forwarding hairpin hash** - degraded hairpin route lookups
5. **PMTU cache** - degraded PMTU lookups

The `rate_limit.c` module uses `rhashtable` which has built-in rehashing, partially mitigating this. But `DEFINE_HASHTABLE` instances (nf, forward, PMTU) are static-size and fully vulnerable.

- **Files**: Multiple (see above)
- **Impact**: Hash collision attack can degrade multiple subsystems simultaneously
- **Recommendation**: Use `siphash` with a per-boot random key (from `net_get_random_once`) instead of `jhash` with seed 0. This is the standard kernel approach since Linux 4.1.

**Exception**: The `crypto/zero_rtt.c` replay detection at line 848 correctly uses random seeds (`replay_hash_seed1`, `replay_hash_seed2`). This is the right approach.

### 2.4 QPACK Decompression

QPACK dynamic table capacity is bounded:
- Default: 4096 bytes (`tquic_sysctl.c:100`)
- Maximum: 1048576 bytes / 1MB (`tquic_sysctl.c:691`)
- Blocked streams default: 100

**Finding CPU-6 (LOW)**: The QPACK decoder accepts a `max_table_capacity` parameter from the peer via SETTINGS. While the sysctl caps the local maximum at 1MB, the actual limit used should be `min(peer_requested, local_max)`. Verify that the SETTINGS parsing enforces this bound before passing to `qpack_decoder_init`.

- **File**: `/Users/justinadams/Downloads/tquic-kernel/net/quic/tquic/http3/qpack_decoder.c`
- **Line**: 41-63
- **Impact**: Peer could request oversized table
- **Recommendation**: Audit SETTINGS parsing to confirm capacity is clamped

---

## Section 3: AMPLIFICATION VECTORS

### 3.1 Anti-Amplification Enforcement

The anti-amplification limit is properly implemented:

```c
// tquic_migration.c:72
#define TQUIC_ANTI_AMPLIFICATION_LIMIT  3  /* Max 3x amplification */

// tquic_migration.c:85-106
bool tquic_path_anti_amplification_check(struct tquic_path *path, u64 bytes)
{
    received = atomic64_read(&path->anti_amplification.bytes_received);
    sent = atomic64_read(&path->anti_amplification.bytes_sent);
    return (sent + bytes <= received * TQUIC_ANTI_AMPLIFICATION_LIMIT);
}
```

**Enforcement points verified:**
- Path creation: `tquic_migration.c:440-442` -- sets active=true, counters to 0
- Connection migration: `tquic_migration.c:785-789` -- enables on new address
- Path validation start: `pm/path_validation.c:221-223` -- enables before challenge
- Path validation success: `pm/path_validation.c:394` -- disables
- Bonding path selection: `bond/bonding.c:498-499` -- checks before send
- Core path data send: `core/quic_path.c:831-843` -- checks 3x limit

**Finding AMP-1 (MEDIUM)**: The anti-amplification check uses `atomic64` operations for `bytes_received` and `bytes_sent`, but the check-then-add pattern is not atomic as a whole:

```c
// Check:
sent + bytes <= received * TQUIC_ANTI_AMPLIFICATION_LIMIT
// Then later:
atomic64_add(bytes, &path->anti_amplification.bytes_sent);
```

Under concurrent packet processing, two threads could both pass the check simultaneously and then both add, exceeding the 3x limit. This is a classic TOCTOU race.

- **File**: `/Users/justinadams/Downloads/tquic-kernel/net/quic/tquic/tquic_migration.c`
- **Lines**: 85-106, 113-117
- **Impact**: Marginal amplification limit bypass (could exceed 3x briefly under concurrency)
- **Recommendation**: Use `atomic64_add_return` to atomically check-and-add, or serialize under a spinlock

### 3.2 Stateless Reset Amplification

The stateless reset implementation correctly prevents amplification:

```c
// tquic_stateless_reset.c:211
// "than the packet it received to avoid being used for amplification."
```

The reset response is shorter than the triggering packet, and rate limited at line 271. Verified correct.

### 3.3 Version Negotiation Amplification

Version negotiation packets are only sent in response to valid-looking packets with unknown versions. The response is small (fixed size) and not larger than the triggering packet in practice. No issue found.

### 3.4 Retry Amplification

Retry packets are sent in response to Initial packets during rate limiting (cookie-required mode). Since Initial packets must be >= 1200 bytes (RFC 9000) and Retry packets are smaller, this is not an amplification vector. Verified correct.

### 3.5 PATH_CHALLENGE/RESPONSE Rate Limiting

```c
// pm/path_manager.c:169
TQUIC_MAX_CHALLENGE_RESPONSES_PER_RTT

// pm/path_validation.c:259
TQUIC_MAX_PENDING_RESPONSES
```

PATH_RESPONSE generation is rate-limited both per-RTT and by queue depth. However:

**Finding AMP-2 (MEDIUM)**: The `tquic_path_handle_challenge` function in `pm/path_validation.c:249` does not check anti-amplification limits before queuing the PATH_RESPONSE. Per RFC 9000 Section 8.1, data sent on unvalidated paths counts against the amplification limit. PATH_RESPONSE data should be charged to the anti-amplification budget.

- **File**: `/Users/justinadams/Downloads/tquic-kernel/net/quic/tquic/pm/path_validation.c`
- **Lines**: 249-314
- **Impact**: PATH_CHALLENGE flood could bypass amplification limits
- **Recommendation**: Check `tquic_path_anti_amplification_check` before queuing response; charge response bytes to `bytes_sent`

### 3.6 MASQUE Proxy Amplification

**Finding AMP-3 (MEDIUM)**: The MASQUE CONNECT-UDP tunnel implementation in `masque/connect_udp.c` creates UDP sockets to forward proxied traffic. There is **no visible limit on the number of tunnels per connection or per client**.

The `tunnel_alloc` function at line 374 allocates tunnel structures without checking any limit. If a MASQUE client can open unlimited tunnels (each with its own kernel UDP socket), this is a resource exhaustion vector consuming both memory (tunnel structs, socket buffers) and file descriptors.

- **File**: `/Users/justinadams/Downloads/tquic-kernel/net/quic/tquic/masque/connect_udp.c`
- **Lines**: 374-401
- **Impact**: Kernel socket and memory exhaustion through tunnel flooding
- **Recommendation**: Add per-connection and per-client tunnel limits (e.g., max 16 tunnels per connection)

---

## Section 4: TIMER AND STATE EXHAUSTION

### 4.1 Half-Open Connection Attack (QUIC SYN Flood Equivalent)

QUIC's equivalent of a SYN flood is sending many Initial packets to force server-side state allocation before address validation.

**Defense assessment:**
1. **Rate limiting**: Two layers -- token bucket (rate_limit.c) and advanced with cookie (tquic_ratelimit.c). The first layer is lightweight and runs before any state allocation.
2. **Pre-handshake memory**: Global 64MB limit, 1MB per-IP, 16 connections per-IP.
3. **Retry/cookie mechanism**: Under attack mode, cookie-required forces address validation.

**Finding STATE-1 (MEDIUM)**: The transition to "attack mode" (TQUIC_RL_COOKIE_REQUIRED) appears to be reactive -- it triggers when rate limits are exceeded. During the ramp-up period before attack mode activates, an attacker could establish many connections at just below the rate limit, consuming the full pre-handshake budget.

With 10,000 connections/sec global limit and 64MB pre-handshake budget, an attacker sending Initial packets at 9,999/sec from diverse IPs could sustain a connection flood below the detection threshold while steadily consuming memory.

- **Files**: `/Users/justinadams/Downloads/tquic-kernel/net/quic/tquic/rate_limit.c`, `/Users/justinadams/Downloads/tquic-kernel/net/quic/tquic/tquic_ratelimit.c`
- **Impact**: Slow-ramp attack can exhaust pre-handshake memory before defense escalation
- **Recommendation**: Consider proactive cookie validation when pre-handshake memory exceeds 50% of budget, independent of rate limit triggers

### 4.2 Slowloris Equivalent

A QUIC Slowloris attack would involve keeping connections alive with minimal data to hold server resources.

**Defense assessment:**
- Idle timeout: 30 seconds default (`tquic_sysctl.c:36`), range 1ms to 600s
- Handshake timeout: 10 seconds default (`core/quic_protocol.c:44`)
- Per-client connection count tracking (tquic_server.c)

**Finding STATE-2 (LOW)**: An attacker could open connections, complete the handshake (consuming 1 connection per client rate token), then keep them alive by sending a PING frame every 29 seconds. With default 100 conn/sec per-IP limit, an attacker with one IP could accumulate ~100 idle connections in 1 second, then sustain them indefinitely with minimal bandwidth (~100 PINGs every 29 seconds = ~3.4 packets/sec).

Each connection consumes kernel memory (connection struct, crypto state, timer state, etc.). The aggregate memory across many idle connections could be significant.

- **File**: `/Users/justinadams/Downloads/tquic-kernel/net/quic/tquic/tquic_sysctl.c`
- **Line**: 36
- **Impact**: Idle connection accumulation consuming memory
- **Recommendation**: Enforce a maximum concurrent connections per-IP limit (distinct from rate limit), e.g., 32 connections per source IP

### 4.3 Timer Resource Exhaustion

Each connection creates multiple timers (idle, loss detection, PTO, path validation). Each path also has a validation timer. With multipath enabled, a connection could have N paths * M timers.

**Finding STATE-3 (LOW)**: No visible limit on the number of paths per connection. If an attacker can trigger path creation (via connection migration or multipath signaling), each new path creates timers and state.

- **Impact**: Timer and path state accumulation
- **Recommendation**: Enforce max paths per connection limit

---

## Section 5: PROTOCOL-SPECIFIC DoS VECTORS

### 5.1 NEW_CONNECTION_ID Stuffing (CVE-2024-22189)

Defense is in place at `tquic_cid.c:617`:
```c
ret = tquic_cid_security_check_new_cid(&pool->security);
```
Rate limiting is applied before processing. Active CID count is also enforced at line 656. **Adequately defended.**

### 5.2 Retire CID Churn

An attacker could send NEW_CONNECTION_ID with high `retire_prior_to` values to force RETIRE_CONNECTION_ID frame generation. The rate limit at line 617 mitigates this, but:

**Finding PROTO-1 (LOW)**: The retire loop at `tquic_cid.c:667-674` iterates the entire remote CID list for each NEW_CONNECTION_ID frame, marking CIDs as retired. While bounded by `active_connection_id_limit`, repeated retire-and-reissue cycles could generate a storm of RETIRE_CONNECTION_ID frames in the outbound direction, consuming output queue space.

### 5.3 Stream ID Exhaustion

**Finding PROTO-2 (LOW)**: The `tquic_stream_open_incoming` function checks `stream_seq >= conn->max_streams_*` but the peer can send frames referencing stream IDs in any order. An attacker could send a STREAM frame for stream ID `max_streams * 4` to probe the limit, and separately send frames for non-existent lower stream IDs to force stream creation. The RB-tree insertion handles duplicates correctly (line 681), but creating streams out of order fills the tree with gaps.

### 5.4 Optimistic ACK Attack

The security hardening module references optimistic ACK defense via packet number skipping. The `bytes_acked` calculation at `tquic_input.c:737` uses an estimation:
```c
u64 bytes_acked = (first_ack_range + 1) * 1200;
```

**Finding PROTO-3 (MEDIUM)**: This estimation-based ACK processing means an attacker can send ACK frames claiming to acknowledge packets that were never sent, inflating the `bytes_acked` value and causing the congestion controller to increase the window incorrectly. The comment at line 733 says "Simplified: use first_ack_range * 1200 (MTU) as estimate." A proper implementation should track sent packets and only count actually-sent packets as acknowledged.

- **File**: `/Users/justinadams/Downloads/tquic-kernel/net/quic/tquic/tquic_input.c`
- **Lines**: 732-744
- **Impact**: Attacker can inflate congestion window via optimistic ACKs, potentially causing network congestion or self-DoS
- **Recommendation**: Implement proper sent-packet tracking to validate ACK ranges

---

## Section 6: INFORMATION DISCLOSURE VIA DoS RESPONSE

### 6.1 Error Message Information Leakage

**Finding INFO-1 (LOW)**: Several `pr_debug`/`tquic_dbg` calls include connection state information. While these are compile-time optional, in debug builds they could leak timing information about connection state to attackers via dmesg:

```c
// tquic_input.c:2664
tquic_warn("key phase change %u->%u failed: %d\n",
           current_phase, ctx.key_phase_bit, ku_ret);
```

This is low severity as it requires local dmesg access, but kernel log flooding is itself a minor DoS vector if many error messages are generated.

---

## Section 7: CROSS-CUTTING ISSUES

### 7.1 Hash Collision Attack Surface Summary

**Finding CROSS-1 (HIGH)**: The systematic use of `jhash` with seed 0 across 15+ call sites creates a coordinated attack vector. An attacker who can determine CID values and IP addresses can craft inputs that degrade:
1. Connection lookup
2. Rate limiting
3. Pre-handshake defense
4. PMTU cache
5. Hairpin detection

All simultaneously. This is the single most impactful finding in this audit because it undermines multiple defense layers at once.

See Section 2.3 for details and recommendation.

### 7.2 GFP_ATOMIC Allocation Pressure

Of the ~120 allocation sites, approximately 80% use `GFP_ATOMIC`. This is expected for packet processing paths, but `GFP_ATOMIC` allocations fail silently under memory pressure rather than blocking. An attacker causing sustained memory pressure through other means (e.g., connection flooding) could cause cascading allocation failures throughout the packet processing path.

**Finding CROSS-2 (LOW)**: Consider using the `tquic_rx_buf_cache` slab cache pattern (already used at `tquic_input.c:2586`) more broadly for hot-path allocations to reduce GFP_ATOMIC pressure.

---

## Severity Summary

| Severity | Count | IDs |
|----------|-------|-----|
| **HIGH** | 2 | CPU-4 (Decrypt CPU exhaustion), CPU-5/CROSS-1 (jhash seed 0) |
| **MEDIUM** | 6 | MEM-1, MEM-2, CPU-1, AMP-1, AMP-2, AMP-3, STATE-1, PROTO-3 |
| **LOW** | 9 | MEM-3, MEM-4, CPU-2, CPU-3, CPU-6, STATE-2, STATE-3, PROTO-1, PROTO-2, INFO-1, CROSS-2 |

---

## Prioritized Remediation Plan

### Immediate (HIGH priority)

1. **Replace jhash seed 0 with siphash + random per-boot key** across all hash tables. This is a systematic fix that hardens all subsystems at once.

2. **Rate limit decryption attempts per DCID** for short-header packets. Track consecutive failures and temporarily skip decryption for CIDs with > N recent failures (e.g., 10 failures in 1 second = 1 second cooldown).

### Short-term (MEDIUM priority)

3. Add per-connection crypto buffer size limit
4. Charge PATH_RESPONSE to anti-amplification budget
5. Fix TOCTOU in anti-amplification check (use atomic check-and-add)
6. Add tunnel count limits in MASQUE proxy
7. Switch to proactive cookie mode when pre-handshake memory > 50%
8. Cap handshake message allocation sizes
9. Implement proper sent-packet tracking for ACK validation

### Long-term (LOW priority)

10. Add per-IP NF connection tracking limits
11. Lazy stream buffer initialization
12. Use bitmap for FEC symbol dedup
13. Maintain running CID active count
14. Add max concurrent connections per-IP enforcement
15. Enforce max paths per connection

---

## Positive Findings (Defenses Working Correctly)

The following defenses were verified as correctly implemented:

1. **Pre-handshake memory budgets** (CVE-2025-54939 defense): Global and per-IP limits with proper atomic tracking
2. **NEW_CONNECTION_ID rate limiting** (CVE-2024-22189 defense): Rate check before CID processing
3. **Anti-amplification 3x limit**: Enforced on all new and migrated paths
4. **Stateless reset anti-amplification**: Response shorter than trigger, rate limited
5. **Stream count limits**: MAX_STREAMS properly enforced in stream creation
6. **Connection rate limiting**: Two-layer defense (token bucket + cookie-based)
7. **PATH_CHALLENGE queue depth limit**: Prevents response queue memory exhaustion
8. **CRYPTO frame pre-handshake check**: Memory budget enforced before processing
9. **ACK range count limit**: Capped at 256 to prevent loop exhaustion
10. **Constant-time comparisons**: `crypto_memneq` used for security-sensitive comparisons (stateless reset tokens, challenge verification, HMAC validation)
11. **FEC block count limit**: Active blocks capped at `max_active_blocks`
12. **Socket receive buffer enforcement**: Stream data charged against `sk_rcvbuf`
13. **Idle and handshake timeouts**: Properly configured with sane defaults
14. **Zero-RTT replay detection**: Uses random seeds for hash functions (unlike rest of codebase)

---

*End of audit report. All file paths are absolute, referencing the codebase at `/Users/justinadams/Downloads/tquic-kernel/net/quic/tquic/`.*
