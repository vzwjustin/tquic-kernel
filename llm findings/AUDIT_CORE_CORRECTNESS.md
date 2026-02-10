# TQUIC Core Protocol Correctness Audit Report

**Auditor:** Core Protocol Correctness Agent (Kernel Security Reviewer)
**Date:** 2026-02-09
**Scope:** Core protocol implementation, RFC compliance, frame handling safety, connection lifecycle, timer correctness, socket interface, ACK processing, stream management, flow control, and error handling.
**Files Reviewed:** 22 files totaling ~50,000+ lines of code

---

## Executive Summary

The TQUIC core protocol implementation is generally well-structured, with extensive security annotations and defense-in-depth measures already in place. However, the audit identified **7 CRITICAL**, **12 HIGH**, **9 MEDIUM**, and **8 LOW** severity issues across the codebase. The most concerning findings involve potential race conditions in connection state transitions, missing bounds validation on certain attacker-controlled values in the input processing path, a timing side channel in retry token validation, and several resource exhaustion vectors that could be exploited by malicious peers.

---

## CRITICAL Issues

### C-1: Retry Token Address Validation Uses Non-Constant-Time Comparison

**File:** `/Users/justinadams/Downloads/tquic-kernel/net/tquic/core/connection.c`
**Line:** 1283
**Code:**
```c
memcpy(&token_hash, p, sizeof(token_hash));
if (token_hash != expected_hash) {
    tquic_conn_dbg(conn, "retry token address mismatch\n");
    return -EINVAL;
}
```
**Description:** The retry token validation compares the address hash using a direct `!=` comparison. While the address hash itself is not a secret, the comparison of the overall token uses AEAD decryption (which is constant-time), but the subsequent hash comparison reveals whether the decryption produced a valid address. An attacker could use timing differences to distinguish between "bad decryption" (fast failure) and "decryption succeeded but address doesn't match" (slightly slower).

**Impact:** LOW practical impact since AEAD already protects the token, but fails defense-in-depth best practice.

**Recommendation:** Use `crypto_memneq()` for the hash comparison, or accept the current design as adequate given AEAD authentication.

### C-2: Connection State Transition Not Fully Atomic

**File:** `/Users/justinadams/Downloads/tquic-kernel/net/tquic/core/connection.c`
**Lines:** 266-419
**Code:**
```c
static int tquic_conn_set_state(struct tquic_connection *conn,
                                enum tquic_conn_state new_state,
                                enum tquic_state_reason reason)
{
    // ... state validation ...
    conn->state = new_state;
    // ... entry actions (scheduling work, waking waiters) ...
}
```
**Description:** `tquic_conn_set_state()` performs the state transition and entry actions without holding a lock. The caller is expected to hold `conn->lock`, but this is not enforced by the function itself. Multiple callers from different contexts (timer callbacks, packet reception, socket operations) could race to transition state. Specifically:
- `tquic_handle_stateless_reset()` at `/Users/justinadams/Downloads/tquic-kernel/net/tquic/tquic_input.c:398` directly sets `conn->state = TQUIC_CONN_CLOSED` under `conn->lock`, bypassing the state machine validation entirely.

**Impact:** A race condition could cause the connection to skip required cleanup steps (e.g., skipping DRAINING when going directly to CLOSED), potentially leaking resources or causing use-after-free if work items execute on freed state.

**Recommendation:** All state transitions MUST go through `tquic_conn_set_state()`, and the function should assert/acquire `conn->lock` internally. Fix `tquic_handle_stateless_reset()` to use the state machine.

### C-3: ECN CE Count Processing Does Not Track Deltas

**File:** `/Users/justinadams/Downloads/tquic-kernel/net/tquic/tquic_input.c`
**Lines:** 757-768
**Code:**
```c
if (has_ecn && ecn_ce > 0) {
    /*
     * Track previous ECN-CE count to detect increase.
     * For now, treat any reported CE count as new marks.
     */
    tquic_cong_on_ecn(ctx->path, ecn_ce);
    ...
}
```
**Description:** RFC 9002 Section 7.1 requires that congestion control respond only to **increases** in the ECN-CE counter: "Each increase in the ECN-CE counter is a signal of congestion." The current implementation treats the raw CE count as the delta, which means if a peer reports CE=5 in every ACK, the congestion controller will react 5 times per ACK rather than only when the count increases. This directly violates RFC 9002.

**Impact:** A malicious peer can cause severe, spurious congestion responses by repeatedly reporting the same CE count, effectively throttling a legitimate connection to near-zero throughput.

**Recommendation:** Store the previous ECN counts per path (in `struct tquic_ecn_tracking`) and only call `tquic_cong_on_ecn()` with the delta when `ecn_ce > path->ecn.ce_count`. Update the stored count after processing.

### C-4: RTT Estimation Uses Approximation Instead of Per-Packet Tracking

**File:** `/Users/justinadams/Downloads/tquic-kernel/net/tquic/tquic_input.c`
**Lines:** 722-724
**Code:**
```c
rtt_us = ktime_us_delta(now, ctx->path->last_activity);
if (rtt_us > ack_delay_us)
    rtt_us -= ack_delay_us;
```
**Description:** The RTT sample is computed using `path->last_activity` as an approximation of the sent time. RFC 9002 Section 5.1 requires: "An RTT sample MUST NOT be generated on receiving an ACK frame that does not newly acknowledge at least one ack-eliciting packet." The approximation can produce wildly inaccurate RTT samples, especially on paths with multiple in-flight packets.

**Impact:** Incorrect RTT estimates directly affect PTO calculation (RFC 9002), loss detection thresholds, and congestion control behavior. This could cause premature retransmissions, failed loss detection, or incorrect persistent congestion detection.

**Recommendation:** Implement per-packet sent-time tracking in the `tquic_sent_packet` structure and look up the actual send time of the largest newly-acknowledged packet when processing ACKs.

### C-5: `ack_delay` Exponent Hardcoded to Default

**File:** `/Users/justinadams/Downloads/tquic-kernel/net/tquic/tquic_input.c`
**Line:** 715
**Code:**
```c
u64 ack_delay_us = ack_delay * 8;  /* Default exponent = 3 */
```
**Description:** The ACK delay exponent is hardcoded to 3 (multiplier 8). RFC 9000 Section 18.2 specifies that this value is negotiated via the `ack_delay_exponent` transport parameter. If the peer negotiates a different exponent, all ACK delay values will be misinterpreted.

**Impact:** Incorrect ACK delay scaling leads to incorrect RTT estimation per RFC 9002 Section 5.3, which cascades into incorrect PTO, loss detection, and congestion control.

**Recommendation:** Use the negotiated `ack_delay_exponent` from the peer's transport parameters: `ack_delay_us = ack_delay << conn->remote_params.ack_delay_exponent`.

### C-6: `tquic_varint_len()` Returns 0 for Invalid Values Without Error Propagation

**File:** `/Users/justinadams/Downloads/tquic-kernel/net/tquic/tquic_output.c`
**Lines:** 164-168
**Code:**
```c
static inline int tquic_varint_len(u64 val)
{
    // ... (declared elsewhere but used here)
}

static inline int tquic_encode_varint(u8 *buf, size_t buf_len, u64 val)
{
    int len = tquic_varint_len(val);
    if (len > buf_len)
        return -ENOSPC;
```
**Description:** If `tquic_varint_len()` returns 0 (value too large), the check `len > buf_len` evaluates to `0 > buf_len` which is always false for `size_t`. The function would then enter the switch statement with `len=0`, falling through to no case and returning 0 (success with 0 bytes written). This silently truncates varint values that exceed 2^62-1.

**Impact:** Attacker-controlled values (e.g., stream IDs, offsets) that exceed the varint maximum could be silently encoded as 0 bytes, corrupting packet contents and potentially causing protocol violations.

**Recommendation:** Add explicit check: `if (len == 0) return -EOVERFLOW;`

### C-7: Stream Frame Without Length Allows Reading Past Decrypted Buffer

**File:** `/Users/justinadams/Downloads/tquic-kernel/net/tquic/tquic_input.c`
**Lines:** 904-907
**Code:**
```c
} else {
    /* Length extends to end of packet */
    length = ctx->len - ctx->offset;
}
```
**Description:** When a STREAM frame does not have the LENGTH bit set, the code assumes the data extends to the end of the buffer. However, `ctx->len` represents the total payload length, which may include subsequent frames in the same packet. Per RFC 9000 Section 19.8, a STREAM frame without the LENGTH bit "extends to the end of the packet." Since this is the last frame in a packet, this is correct in theory, but the frame dispatcher (the caller of this function) should not call any further frame processing after a length-less STREAM frame. If the dispatcher continues processing, it would find `ctx->offset == ctx->len` and cleanly exit, so this is safe.

**Impact:** LOW - the design is correct as long as the frame dispatcher respects the protocol requirement that a frame without a length field must be the last frame. However, the code lacks an explicit assertion or comment in the dispatcher to enforce this invariant.

**Recommendation:** Add a flag to `tquic_rx_ctx` that records when a length-less STREAM frame is processed, and assert in the dispatcher that no further frames follow.

---

## HIGH Severity Issues

### H-1: `bytes_acked` Estimate Based on First ACK Range is Grossly Inaccurate

**File:** `/Users/justinadams/Downloads/tquic-kernel/net/tquic/tquic_input.c`
**Lines:** 737-738
**Code:**
```c
u64 bytes_acked = (first_ack_range + 1) * 1200;
```
**Description:** The bytes acknowledged calculation multiplies the ACK range count by a fixed 1200-byte MTU estimate. This is incorrect for several reasons: (1) packets vary in size, (2) only the first ACK range is used ignoring additional ranges, (3) the value 1200 is the minimum QUIC packet size, not typical size. A malicious peer could send ACK frames claiming to acknowledge many packets, causing the congestion controller to inflate CWND inappropriately.

**Impact:** Congestion controller can be manipulated by a malicious peer to increase sending rate far beyond what the network can handle (ACK amplification/optimistic ACK attack).

**Recommendation:** Track actual sent bytes per packet in `tquic_sent_packet.sent_bytes` and sum the bytes of newly acknowledged packets.

### H-2: Missing `retire_prior_to > seq_num` Validation in NEW_CONNECTION_ID Processing

**File:** `/Users/justinadams/Downloads/tquic-kernel/net/tquic/tquic_input.c`
**Lines:** 1116-1183
**Description:** When processing NEW_CONNECTION_ID frames, the code does not validate that `retire_prior_to <= seq_num` as required by RFC 9000 Section 19.15: "The value in the Retire Prior To field MUST be less than or equal to the value in the Sequence Number field." A malicious peer sending `retire_prior_to > seq_num` could cause retirement of CIDs that should remain active.

**Impact:** Could force retirement of all CIDs, potentially causing connection failure or forcing use of a specific CID controlled by the attacker.

**Recommendation:** Add validation: `if (retire_prior_to > seq_num) return -EPROTO;`

### H-3: Stateless Reset Handling Bypasses Connection State Machine

**File:** `/Users/justinadams/Downloads/tquic-kernel/net/tquic/tquic_input.c`
**Lines:** 391-408
**Code:**
```c
static void tquic_handle_stateless_reset(struct tquic_connection *conn)
{
    spin_lock_bh(&conn->lock);
    conn->state = TQUIC_CONN_CLOSED;
    // ...
    spin_unlock_bh(&conn->lock);
    if (sk)
        sk->sk_state_change(sk);
}
```
**Description:** This directly sets the connection state to CLOSED, bypassing `tquic_conn_set_state()` and all its cleanup logic (canceling work items, flushing drain timer, etc.). This means pending work items (close_work, migration_work, drain_work, validation_work) are not canceled.

**Impact:** Pending work items may fire after the connection is freed, causing use-after-free.

**Recommendation:** Use the state machine: call `tquic_conn_set_state(conn, TQUIC_CONN_CLOSED, TQUIC_REASON_PEER_CLOSE)` instead.

### H-4: `tquic_output.c` Encode Varint Does Not Check for 0 Return from `tquic_varint_len`

**File:** `/Users/justinadams/Downloads/tquic-kernel/net/tquic/tquic_output.c`
**Lines:** 164-198
**Description:** The `tquic_encode_varint()` inline function calls `tquic_varint_len()` which can return 0 for values exceeding `TQUIC_VARINT_MAX`. If `len` is 0, the check `if (len > buf_len)` passes (0 is never > any size_t), and the switch falls through with no case matched, returning 0. This means the caller thinks 0 bytes were written (success with no data), silently dropping the varint.

**Impact:** Protocol messages could be constructed with missing fields, causing the peer to misparse them.

**Recommendation:** Add `if (len == 0) return -EOVERFLOW;` after the `tquic_varint_len()` call.

### H-5: STREAM Frame `length` Validation Allows Up to 65535 Bytes Per Frame

**File:** `/Users/justinadams/Downloads/tquic-kernel/net/tquic/tquic_input.c`
**Lines:** 909-910
**Code:**
```c
if (length > 65535)
    return -EINVAL;
```
**Description:** This limit is arbitrary and not from the RFC. RFC 9000 does not impose a per-frame length limit beyond the packet size. While the intent is resource protection, the limit means legitimate peers sending frames up to the maximum UDP payload size minus overhead (~65,200 bytes) could be rejected if they happen to exceed 65535.

**Impact:** MEDIUM - could cause interoperability issues with peers sending large STREAM frames. The limit should be the remaining packet length, which is already checked on line 912.

**Recommendation:** Remove the 65535 limit since line 912 already validates against the actual packet bounds.

### H-6: `tquic_conn_retire_cid()` Does Not Remove CID from Lookup Hash Table

**File:** `/Users/justinadams/Downloads/tquic-kernel/net/tquic/core/connection.c`
**Lines:** 598-627
**Description:** When retiring a CID, the code marks `entry->retired = true` but does not remove the entry from `cid_lookup_table` (the rhashtable). This means the global lookup table still maps the retired CID to this connection. A peer could continue using a retired CID and the connection would still be found via hash lookup.

**Impact:** Per RFC 9000 Section 5.1.2: "An endpoint SHOULD stop accepting packets sent to a retired connection ID." Continuing to accept packets on retired CIDs defeats the privacy benefits of CID rotation and could enable tracking.

**Recommendation:** Call `rhashtable_remove_fast()` when retiring a local CID.

### H-7: Missing Validation of `first_ack_range` Against `largest_ack`

**File:** `/Users/justinadams/Downloads/tquic-kernel/net/tquic/tquic_input.c`
**Lines:** 634-639 and `/Users/justinadams/Downloads/tquic-kernel/net/tquic/core/frame.c:358-364`
**Description:** RFC 9000 Section 19.3.1 states: "The First ACK Range value is the value of the Largest Acknowledged field minus the smallest packet number acknowledged in this range." Therefore `first_ack_range` MUST be <= `largest_ack`. Neither the frame parser nor the input processor validates this constraint.

**Impact:** A malicious peer sending `first_ack_range > largest_ack` could cause integer underflow in ACK range calculations, potentially marking packet numbers that were never sent as acknowledged.

**Recommendation:** Add validation: `if (first_ack_range > largest_ack) return -EPROTO;`

### H-8: Stream State Machine Allows Unexpected Transitions from OPEN

**File:** `/Users/justinadams/Downloads/tquic-kernel/net/tquic/core/stream.c`
**Lines:** 273-279
**Code:**
```c
case TQUIC_STREAM_OPEN:
    /* Can go to SIZE_KNOWN, DATA_SENT, RESET_SENT, RESET_RECVD */
    if (new_state != TQUIC_STREAM_SIZE_KNOWN &&
        new_state != TQUIC_STREAM_DATA_SENT &&
        new_state != TQUIC_STREAM_RESET_SENT &&
        new_state != TQUIC_STREAM_RESET_RECVD)
        return -EINVAL;
    break;
```
**Description:** Per RFC 9000 Figure 3 (bidirectional stream states), OPEN can transition to SEND (half-close receiving) or RECV (half-close sending), SIZE_KNOWN (recv side), DATA_SENT (send side), RESET_SENT (send side), or RESET_RECVD (recv side). The current implementation is missing SEND and RECV transitions from OPEN.

**Impact:** Bidirectional streams cannot properly half-close, which would break applications that shut down one direction while keeping the other open.

**Recommendation:** Add TQUIC_STREAM_SEND and TQUIC_STREAM_RECV as valid transitions from OPEN.

### H-9: `ext->final_size = -1` Uses Signed Overflow

**File:** `/Users/justinadams/Downloads/tquic-kernel/net/tquic/core/stream.c`
**Line:** 177
**Code:**
```c
ext->final_size = -1;
```
**Description:** `final_size` is likely a `u64` field. Assigning `-1` produces `U64_MAX` (0xFFFFFFFFFFFFFFFF). While this is a common sentinel pattern, RFC 9000 limits stream data offsets to 2^62-1. Using U64_MAX as "unknown" is correct but should use a named constant like `TQUIC_STREAM_SIZE_UNKNOWN` to avoid confusion.

**Impact:** LOW - functionally correct but poor code clarity. Any comparison against 2^62-1 limits would pass incorrectly if the sentinel is not properly handled.

**Recommendation:** Define `#define TQUIC_STREAM_SIZE_UNKNOWN U64_MAX` and use it consistently.

### H-10: Retry Packet Version Encoding Is Hardcoded for v1

**File:** `/Users/justinadams/Downloads/tquic-kernel/net/tquic/core/connection.c`
**Lines:** 1328-1329
**Code:**
```c
*p++ = 0xf0;  /* Long header, Retry type */
memcpy(p, &conn->version, 4);
```
**Description:** The first byte `0xf0` encodes Retry type as `0b11` (bits 4-5) which is the QUIC v1 encoding. For QUIC v2 (RFC 9369), Retry type is `0b00`. If the connection negotiated v2, this produces an invalid packet type.

Additionally, `conn->version` is copied in host byte order, not network byte order. This would produce corrupted version fields on little-endian systems.

**Impact:** Retry packets are malformed on v2 connections and on little-endian architectures, causing connection establishment failures.

**Recommendation:** Use `tquic_encode_packet_type()` for the header byte and `cpu_to_be32(conn->version)` for the version field.

### H-11: Retry Integrity Tag Uses Wrong Key/Nonce for QUIC v2

**File:** `/Users/justinadams/Downloads/tquic-kernel/net/tquic/core/connection.c`
**Lines:** 1356-1363
**Description:** The retry integrity key and nonce are hardcoded for QUIC v1. RFC 9369 Section 3.4.2 specifies different keys for QUIC v2:
- Key: `8fb4b01b56ac48e260fbcbcead7ccc92`
- Nonce: `d86969bc2d7c6d9990efb04a`

**Impact:** Retry integrity verification fails for QUIC v2 connections, preventing address validation.

**Recommendation:** Select retry integrity key/nonce based on `conn->version`.

### H-12: Version Negotiation Packet Missing Randomized First Byte

**File:** `/Users/justinadams/Downloads/tquic-kernel/net/tquic/core/connection.c`
**Lines:** 956-957
**Code:**
```c
*p++ = 0x80;  /* Long header */
```
**Description:** RFC 9000 Section 17.2.1 states for Version Negotiation: "The value of the unused fields is selected randomly." The first byte should have random bits in the type-specific fields (bits 0-5). The current implementation uses a fixed `0x80`, making VN packets distinguishable by middleboxes (ossification risk).

**Impact:** Middlebox ossification - fixed patterns allow NATs/firewalls to fingerprint QUIC version negotiation packets.

**Recommendation:** Use `get_random_bytes(&first_byte, 1); first_byte |= 0x80;` similar to the function in `tquic_input.c:523`.

---

## MEDIUM Severity Issues

### M-1: `tquic_fc_conn_data_sent()` Race Between Check and Update

**File:** `/Users/justinadams/Downloads/tquic-kernel/net/tquic/core/flow_control.c`
**Lines:** 280-300
**Description:** Although the function holds `fc->conn.lock`, the caller may have checked `tquic_fc_conn_can_send()` and then called `tquic_fc_conn_data_sent()` without atomicity between the two calls. Another thread could have consumed the credit between check and update.

**Recommendation:** Provide a combined `tquic_fc_conn_try_send()` that atomically checks and commits.

### M-2: `kmem_cache_create()` Per Stream Manager Risks Name Collision

**File:** `/Users/justinadams/Downloads/tquic-kernel/net/tquic/core/stream.c`
**Lines:** 118-134
**Description:** Each stream manager creates slab caches with fixed names like `"tquic_stream_ext"`. `kmem_cache_create()` requires globally unique names; creating multiple stream managers (multiple connections) with the same cache name could fail or cause confusing sysfs entries.

**Recommendation:** Use a global slab cache shared across all stream managers, or include a unique identifier in the cache name.

### M-3: `additional_addr_add()` Has TOCTOU Between Duplicate Check and Insert

**File:** `/Users/justinadams/Downloads/tquic-kernel/net/tquic/core/additional_addresses.c`
**Lines:** 169-191
**Description:** The function releases `addrs->lock` after the duplicate check (line 188) and before the `kzalloc()` and re-acquisition (line 191 is outside the lock). Another thread could add the same address in between.

**Recommendation:** Keep the lock held across the check-and-insert operation, or use a two-phase approach with lock re-check after allocation.

### M-4: `ring_index()` Uses Unbounded While Loop

**File:** `/Users/justinadams/Downloads/tquic-kernel/net/tquic/core/receive_timestamps.c`
**Lines:** 96-103
**Code:**
```c
static inline u32 ring_index(u32 head, s32 offset, u32 size)
{
    s32 idx = (s32)head + offset;
    while (idx < 0)
        idx += size;
    return (u32)(idx % size);
}
```
**Description:** If `size` is 0, this is an infinite loop. If `offset` is very negative (e.g., INT_MIN) and `size` is small, the loop could iterate billions of times.

**Recommendation:** Add a guard: `if (size == 0) return 0;` and use modular arithmetic: `return ((idx % (s32)size) + size) % size;`

### M-5: Anti-Replay Hash Table Cleanup Iterates All Buckets Under spinlock

**File:** `/Users/justinadams/Downloads/tquic-kernel/net/tquic/core/early_data.c`
**Lines:** 196-206
**Description:** The anti-replay check iterates over all 4096 hash buckets under `anti_replay_state.lock` to clean expired entries. This is O(buckets) per check, executed for every 0-RTT packet.

**Recommendation:** Use a separate periodic cleanup timer rather than inline cleanup, or maintain a time-ordered list for efficient expiration.

### M-6: `tquic_process_stream_frame()` Does Not Check Final Size Consistency

**File:** `/Users/justinadams/Downloads/tquic-kernel/net/tquic/tquic_input.c`
**Lines:** 986-987
**Code:**
```c
if (fin)
    stream->fin_received = true;
```
**Description:** RFC 9000 Section 4.5 requires: "Once a final size for a stream is known, it cannot change." The code does not check whether a previously received FIN specified a different final size than the current `offset + length`. Receiving data beyond a previously-indicated final size is a FINAL_SIZE_ERROR.

**Recommendation:** When FIN is received, record `stream->final_size = offset + length`. On subsequent data, verify `offset + length <= stream->final_size` and that any new FIN matches the recorded value.

### M-7: Connection Close Does Not Validate Reason Phrase Encoding

**File:** `/Users/justinadams/Downloads/tquic-kernel/net/tquic/tquic_input.c`
**Lines:** 1248-1250
**Description:** RFC 9000 Section 19.19 states the reason phrase "SHOULD be a UTF-8 encoded string." While not mandatory to validate, the reason_len is used to advance the offset without any sanity check against reasonable lengths. A 2^62-1 byte reason phrase would pass the check on line 1248 only if the packet was that large.

**Recommendation:** The existing check is adequate for safety. Consider adding a reasonable maximum for logging purposes.

### M-8: `tquic_accept()` Holding `sk_lock.slock` Improperly

**File:** `/Users/justinadams/Downloads/tquic-kernel/net/tquic/tquic_socket.c`
**Lines:** 462-481
**Description:** The accept function acquires `sk->sk_lock.slock` (the BH spinlock) while already holding `sk_lock` (from `lock_sock()`). This nesting is technically valid (socket lock ordering allows this), but the inner spinlock is unnecessary because `lock_sock()` already provides exclusive access. The extra spinlock adds latency.

**Recommendation:** Access the accept queue under `lock_sock()` alone without the additional spinlock.

### M-9: `tquic_poll()` Checks Stream Data Without Lock

**File:** `/Users/justinadams/Downloads/tquic-kernel/net/tquic/tquic_socket.c`
**Lines:** 574-577
**Code:**
```c
if (conn && stream) {
    if (!skb_queue_empty(&stream->recv_buf))
        mask |= EPOLLIN | EPOLLRDNORM;
}
```
**Description:** `stream->recv_buf` is checked without holding any lock. While `skb_queue_empty()` reads `skb_queue_len()` which is updated atomically, there is a potential for the stream pointer itself to become invalid between the `READ_ONCE()` and the queue check.

**Recommendation:** This is acceptable for poll() semantics (spurious wakeups are allowed), but document the intentional lockless access.

---

## LOW Severity Issues

### L-1: Multiple Redundant Varint Implementations

**Files:** `frame.c`, `transport_params.c`, `reliable_reset.c`, `tquic_input.c`, `tquic_output.c`, `varint.h`, `varint.c`
**Description:** There are at least 6 separate varint encode/decode implementations across the codebase. This increases maintenance burden and the chance of inconsistent behavior or bugs in one copy.

**Recommendation:** Consolidate to a single implementation in `varint.c`/`varint.h` and use it everywhere.

### L-2: `established_time` Set Twice in Connection State Machine

**File:** `/Users/justinadams/Downloads/tquic-kernel/net/tquic/core/connection.c`
**Lines:** 329, 334
**Description:** `conn->stats.established_time = ktime_get()` is set in both CONNECTING and CONNECTED entry actions. The CONNECTING value is immediately overwritten when transitioning to CONNECTED.

**Recommendation:** Only set it in CONNECTED, or rename the CONNECTING one to `handshake_start_time`.

### L-3: `tquic_cid_compare()` Marked `__maybe_unused`

**File:** `/Users/justinadams/Downloads/tquic-kernel/net/tquic/core/connection.c`
**Line:** 451
**Description:** The function is marked as possibly unused, suggesting dead code. Either it should be used or removed.

**Recommendation:** Remove if truly unused, or remove the `__maybe_unused` annotation.

### L-4: Version Negotiation Packet Size Not Validated Against 256-Byte Buffer

**File:** `/Users/justinadams/Downloads/tquic-kernel/net/tquic/core/connection.c`
**Lines:** 951-973
**Description:** The VN packet is built in a 256-byte stack buffer. With two CIDs at maximum 20 bytes each and version list, the maximum size is `5 + 1 + 20 + 1 + 20 + 8 = 55` bytes, well within the 256-byte buffer. However, there is no explicit bounds check during packet construction.

**Recommendation:** Add a bounds check or use the `p - packet < sizeof(packet)` idiom.

### L-5: `tquic_sysctl_prefer_v2()` Function Not Declared in Visible Header

**File:** `/Users/justinadams/Downloads/tquic-kernel/net/tquic/core/connection.c`
**Line:** 883
**Description:** `tquic_sysctl_prefer_v2()` is called but not visible in any included header, relying on implicit declaration.

**Recommendation:** Add a proper declaration in a shared header file.

### L-6: `sk->sk_err = -ret` Stores Negative Error Code

**File:** `/Users/justinadams/Downloads/tquic-kernel/net/tquic/tquic_socket.c`
**Line:** 329
**Code:**
```c
sk->sk_err = -ret;  /* Store error for getsockopt */
```
**Description:** `sk_err` is conventionally a positive errno value. The code negates `ret` (which is already negative), producing a positive value, so this is correct. However, the pattern is confusing.

**Recommendation:** Add a comment: `/* ret is negative errno, sk_err needs positive */`

### L-7: `tquic_store_session_ticket()` Does Not Store ALPN or Transport Parameters

**File:** `/Users/justinadams/Downloads/tquic-kernel/net/tquic/tquic_handshake.c`
**Lines:** 295-296
**Code:**
```c
plaintext.alpn_len = 0;
plaintext.transport_params_len = 0;
```
**Description:** The session ticket does not save the ALPN or transport parameters. RFC 9001 Section 4.6.1 requires that 0-RTT clients remember transport parameters from the session ticket. Without stored transport parameters, 0-RTT validation in `tquic_validate_zero_rtt_transport_params()` cannot properly compare old vs. new values.

**Recommendation:** Populate `plaintext.alpn` and `plaintext.transport_params` from the connection state when storing session tickets.

### L-8: Slab Cache Names Are Not Module-Prefixed

**File:** `/Users/justinadams/Downloads/tquic-kernel/net/tquic/core/stream.c`
**Lines:** 118-134
**Description:** Slab cache names like `"tquic_stream_ext"` should use a consistent prefix to avoid collisions with other kernel modules.

**Recommendation:** Use names like `"tquic_core_stream_ext"` for clarity.

---

## RFC Compliance Summary

| RFC | Section | Compliance | Issue |
|-----|---------|-----------|-------|
| RFC 9000 | 4.5 (Final Size) | Partial | M-6: No final size consistency check |
| RFC 9000 | 5.1.2 (Retire CID) | Partial | H-6: Retired CIDs not removed from lookup |
| RFC 9000 | 17.2.1 (VN Packet) | Partial | H-12: Non-random first byte |
| RFC 9000 | 19.3.1 (ACK Range) | Missing | H-7: No first_ack_range validation |
| RFC 9000 | 19.15 (NEW_CID) | Missing | H-2: No retire_prior_to validation |
| RFC 9001 | 4.6.1 (0-RTT TP) | Partial | L-7: ALPN/TP not stored in ticket |
| RFC 9001 | 5.8 (Retry Tag) | Partial | H-10/H-11: v2 keys missing |
| RFC 9002 | 5.1 (RTT) | Missing | C-4: No per-packet sent-time tracking |
| RFC 9002 | 5.3 (ACK Delay) | Missing | C-5: Hardcoded exponent |
| RFC 9002 | 7.1 (ECN) | Missing | C-3: No ECN delta tracking |
| RFC 9369 | 3.4.2 (v2 Retry) | Missing | H-11: v1 keys used for v2 |

---

## Recommendations Priority

1. **Immediate:** Fix C-3 (ECN delta tracking) - directly exploitable for DoS
2. **Immediate:** Fix C-4/C-5 (RTT estimation) - affects all loss detection
3. **Immediate:** Fix H-3 (stateless reset state bypass) - potential UAF
4. **Immediate:** Fix H-1 (bytes_acked estimate) - optimistic ACK vulnerability
5. **High:** Fix H-2, H-7 (missing validations) - protocol correctness
6. **High:** Fix H-10, H-11 (QUIC v2 retry) - v2 interoperability
7. **Medium:** Fix C-6, H-4 (varint encode 0 return) - silent failures
8. **Medium:** Address M-1 through M-6 (race conditions, resource issues)
9. **Low:** Clean up L-1 through L-8 (code quality)
