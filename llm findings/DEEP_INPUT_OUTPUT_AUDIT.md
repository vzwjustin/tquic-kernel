# EXTREME DEEP AUDIT: tquic_input.c and tquic_output.c

## Audit Metadata
- **Date**: 2026-02-09
- **Auditor**: Kernel Security Reviewer (Opus 4.6)
- **Files Audited**:
  - `/Users/justinadams/Downloads/tquic-kernel/net/tquic/tquic_input.c` (3195 lines)
  - `/Users/justinadams/Downloads/tquic-kernel/net/tquic/tquic_output.c` (2801 lines)
- **Focus**: Packet input/output paths processing untrusted network data
- **Severity Scale**: Critical / High / Medium / Low / Informational

---

## EXECUTIVE SUMMARY

The TQUIC input and output paths demonstrate generally competent security awareness -- varint bounds checking is consistent, CID lengths are validated, and overflow-safe arithmetic is used in several key areas. However, the deep line-by-line audit uncovered **6 Critical**, **8 High**, **5 Medium**, and **7 Low** severity issues. The most dangerous findings involve: (1) use-after-free risk in `tquic_find_path_by_addr()` where the returned path pointer has no refcount protection, (2) a stale skb->len read after `ip_local_out()` consumes the skb, (3) missing encryption level validation for certain multipath frames, (4) a potential infinite re-try loop in `tquic_recv_datagram()`, and (5) several integer truncation and state confusion vectors.

---

## CRITICAL ISSUES

### C-1: Use-After-Free in Path Lookup (tquic_input.c, lines 245-261)

**File**: `/Users/justinadams/Downloads/tquic-kernel/net/tquic/tquic_input.c`
**Lines**: 245-261

**Vulnerable Code**:
```c
static struct tquic_path *tquic_find_path_by_addr(struct tquic_connection *conn,
                                                  struct sockaddr_storage *addr)
{
    struct tquic_path *path;
    struct tquic_path *found = NULL;

    spin_lock_bh(&conn->paths_lock);
    list_for_each_entry(path, &conn->paths, list) {
        if (memcmp(&path->remote_addr, addr, sizeof(*addr)) == 0) {
            found = path;
            break;
        }
    }
    spin_unlock_bh(&conn->paths_lock);

    return found;  /* <-- returned WITHOUT refcount increment */
}
```

**Exploitation Scenario**: The function returns a raw pointer to a `tquic_path` after releasing `paths_lock`. Between the unlock and any use of the returned pointer (e.g., line 2562: `path = tquic_find_path_by_addr(conn, src_addr)`), a concurrent path removal on another CPU could free the path, causing use-after-free. This is particularly dangerous because multipath bonding actively adds/removes paths.

**Impact**: Kernel heap use-after-free leading to arbitrary code execution (privilege escalation), kernel crash (DoS).

**Recommendation**: Implement reference counting on `tquic_path` objects. The lookup function should atomically increment the refcount under `paths_lock` before returning. Callers must call `tquic_path_put()` when done.

---

### C-2: Stale skb->len Read After ip_local_out (tquic_output.c, lines 1730-1736)

**File**: `/Users/justinadams/Downloads/tquic-kernel/net/tquic/tquic_output.c`
**Lines**: 1730-1736

**Vulnerable Code**:
```c
    /* Send via IP */
    ret = ip_local_out(&init_net, NULL, skb);

    /* Update path statistics */
    if (ret >= 0) {
        path->stats.tx_packets++;
        path->stats.tx_bytes += skb->len;   /* <-- skb may be freed */
        path->last_activity = ktime_get();
```

**Exploitation Scenario**: `ip_local_out()` may consume and free the skb (the network stack takes ownership). Reading `skb->len` after the call is a use-after-free on the skb. Even if the skb is not immediately freed, the network stack may have cloned or modified it.

**Impact**: Reading freed memory. In the best case, corrupted statistics. In the worst case, the freed memory is reallocated and attacker-controlled data is read as `skb->len`, potentially corrupting `tx_bytes` (u64 stat counter).

**Recommendation**: Save `skb->len` in a local variable before calling `ip_local_out()`:
```c
u32 pkt_len = skb->len;
ret = ip_local_out(&init_net, NULL, skb);
if (ret >= 0) {
    path->stats.tx_bytes += pkt_len;
```

---

### C-3: Wrong Network Namespace in ip_local_out (tquic_output.c, line 1730)

**File**: `/Users/justinadams/Downloads/tquic-kernel/net/tquic/tquic_output.c`
**Line**: 1730

**Vulnerable Code**:
```c
    ret = ip_local_out(&init_net, NULL, skb);
```

**Exploitation Scenario**: The function always uses `&init_net` (the default network namespace) regardless of which namespace the connection's socket belongs to. This is a namespace escape: a QUIC connection in a container's network namespace will send packets through the host's network namespace, bypassing network isolation, firewall rules, and routing policies.

**Impact**: Network namespace escape. Containers can send traffic through the host network. This violates a fundamental Linux security boundary. Firewall rules in the container's namespace are bypassed.

**Recommendation**: Use `sock_net(conn->sk)` instead of `&init_net`. The correct network namespace was already computed at line 1681 in the `rt` lookup:
```c
ret = ip_local_out(net, conn->sk, skb);
```

---

### C-4: conn->sk Accessed Without Lock After Stateless Reset (tquic_input.c, lines 397-407)

**File**: `/Users/justinadams/Downloads/tquic-kernel/net/tquic/tquic_input.c`
**Lines**: 397-407

**Vulnerable Code**:
```c
static void tquic_handle_stateless_reset(struct tquic_connection *conn)
{
    struct sock *sk;

    spin_lock_bh(&conn->lock);
    conn->state = TQUIC_CONN_CLOSED;
    conn->error_code = EQUIC_NO_ERROR;

    /* Read sk under lock to prevent use-after-free */
    sk = READ_ONCE(conn->sk);
    spin_unlock_bh(&conn->lock);

    /* Notify upper layer */
    if (sk)
        sk->sk_state_change(sk);  /* <-- sk could be freed here */
}
```

**Exploitation Scenario**: While `conn->sk` is read under the lock, the socket could be released between the `spin_unlock_bh` and the `sk->sk_state_change(sk)` call. Another CPU running `tquic_release()` could set `conn->sk = NULL` and free the socket. The READ_ONCE only prevents compiler optimization, not concurrent freeing.

**Impact**: Use-after-free on the socket structure, leading to privilege escalation or kernel crash.

**Recommendation**: Hold a reference to the socket (`sock_hold(sk)`) under the lock, then call `sk_state_change`, then release the reference (`sock_put(sk)`).

---

### C-5: PADDING Frame Infinite Skip Without Bound on Encrypted Payload (tquic_input.c, lines 565-571)

**File**: `/Users/justinadams/Downloads/tquic-kernel/net/tquic/tquic_input.c`
**Lines**: 565-571

**Vulnerable Code**:
```c
static int tquic_process_padding_frame(struct tquic_rx_ctx *ctx)
{
    /* Just skip padding bytes */
    while (ctx->offset < ctx->len && ctx->data[ctx->offset] == 0)
        ctx->offset++;

    return 0;
}
```

**Analysis**: This function is called from the frame processing loop after decryption. The frame type byte (0x00 = PADDING) is NOT consumed before entering the `while` loop -- the caller does not increment `ctx->offset` for the PADDING case (line 1901 calls `tquic_process_padding_frame` which enters the while loop seeing `data[offset] == 0` which is the frame type itself).

However, note the anti-infinite-loop guard at line 2058:
```c
if (ctx.offset == prev_offset)
    return -EPROTO;
```

If `ctx->data[ctx->offset]` is NOT zero (i.e., padding byte is actually non-zero due to decryption producing a 0x00 frame type followed by non-zero), the function returns without advancing `ctx->offset` at all if `ctx->data[ctx->offset]` happens to be non-zero on the first check. Actually wait -- the caller enters at `frame_type == TQUIC_FRAME_PADDING` (line 1900), so `data[offset]` IS 0, so the while loop will advance at least one byte. This is actually OK -- the stuck-parsing guard will catch any zero-progress case.

**Re-assessment**: After closer analysis, this is actually handled correctly. The while loop always makes at least one iteration of progress since `data[offset] == 0` was already verified by the caller. **Downgrading to Informational -- not a real issue.**

**REPLACING C-5**:

### C-5 (Revised): tquic_process_packet Does Not Validate pkt_num_len Against Remaining Data (tquic_input.c, lines 2528-2529, 2572-2574)

**File**: `/Users/justinadams/Downloads/tquic-kernel/net/tquic/tquic_input.c`
**Lines**: 2528-2529, 2545, 2572-2574

**Vulnerable Code**:
```c
    /* Packet number length from first byte */
    pkt_num_len = (data[0] & 0x03) + 1;   /* line 2529 or 2545 */
    ...
    /* Decode packet number */
    pkt_num = tquic_decode_pkt_num(data + ctx.offset, pkt_num_len, 0); /* line 2573 */
    ctx.offset += pkt_num_len;  /* line 2574 */
```

**Exploitation Scenario**: The packet number length (1-4 bytes) is extracted from the first byte of the packet. However, this first byte has NOT yet had header protection removed (HP removal happens at line 2565, but `pkt_num_len` is read from the ORIGINAL first byte at line 2529/2545, BEFORE HP removal modifies the low bits). Moreover, there is NO bounds check that `ctx.offset + pkt_num_len <= len` before reading `pkt_num_len` bytes at `data + ctx.offset`.

For a short header packet with `ctx.offset` near `len`, if `pkt_num_len = 4` (attacker controls `data[0] & 0x03`), the `tquic_decode_pkt_num` call reads up to 4 bytes past the end of the packet buffer.

**Impact**: Out-of-bounds read of 1-4 bytes past the packet buffer. On a SLUB-allocated buffer, this reads from adjacent slab objects, potentially leaking sensitive data (heap information disclosure). If the packet data is in an skb's linear data area, this could read past `skb->tail`.

**Recommendation**: Add a bounds check before decoding the packet number:
```c
if (ctx.offset + pkt_num_len > len)
    return -EINVAL;
```

---

### C-6: Packet Number Length Extracted Before Header Unprotection (tquic_input.c, lines 2529, 2545 vs 2565)

**File**: `/Users/justinadams/Downloads/tquic-kernel/net/tquic/tquic_input.c`
**Lines**: 2529, 2545, 2565

**Vulnerable Code**:
```c
    // Long header path (line 2529):
    pkt_num_len = (data[0] & 0x03) + 1;

    // Short header path (line 2545):
    pkt_num_len = (data[0] & 0x03) + 1;

    // Header protection removal (line 2565):
    ret = tquic_remove_header_protection(conn, data, ctx.offset, ...);
```

**Exploitation Scenario**: Per RFC 9001 Section 5.4, the packet number length bits in the first byte are protected by header protection. They can only be read AFTER header protection is removed. The code reads them BEFORE HP removal, meaning:

1. The `pkt_num_len` value is based on encrypted/protected bits and is essentially random
2. After HP removal modifies `data[0]`, the actual pkt_num_len could differ
3. The wrong pkt_num_len causes the wrong number of bytes to be consumed as the packet number
4. This shifts the payload boundary, causing the decryption to fail or produce garbage
5. If decryption "succeeds" (e.g., when crypto is not yet established for Initial packets), garbage frames are processed

**Impact**: Protocol confusion leading to frame processing of attacker-controlled data at wrong offsets. Combined with C-5 (no bounds check), this is a high-impact logic error.

**Recommendation**: Move the `pkt_num_len` extraction to AFTER `tquic_remove_header_protection()`:
```c
ret = tquic_remove_header_protection(conn, data, ctx.offset, ...);
if (ret < 0) return ret;
pkt_num_len = (data[0] & 0x03) + 1;  // Now reads unprotected bits
if (ctx.offset + pkt_num_len > len) return -EINVAL;
```

---

## HIGH SEVERITY ISSUES

### H-1: GRO Coalesce Uses Hardcoded 8-byte CID Comparison (tquic_input.c, lines 2249-2253)

**File**: `/Users/justinadams/Downloads/tquic-kernel/net/tquic/tquic_input.c`
**Lines**: 2249-2253

**Vulnerable Code**:
```c
    /* For short headers, compare DCID */
    if (!(h1[0] & TQUIC_HEADER_FORM_LONG)) {
        /* Assume 8-byte CID for now */
        return memcmp(h1 + 1, h2 + 1, 8) == 0;
    }
```

**Exploitation Scenario**: The code blindly reads 8 bytes from both packets without checking if either packet is at least 9 bytes long. A packet shorter than 9 bytes (e.g., a 5-byte short header) causes an out-of-bounds read. Furthermore, CID lengths can vary (0-20 bytes per RFC 9000). Using a hardcoded 8-byte comparison can falsely coalesce packets from different connections if their first 8 bytes after the header happen to match, or fail to coalesce packets from the same connection using a different CID length.

**Impact**: Out-of-bounds read (heap info leak / crash). Incorrect coalescing could mix packets from different connections, causing frame processing confusion.

**Recommendation**: The GRO coalesce function needs to know the actual CID length. Pass it via skb metadata or look it up from connection state. Also add length checks:
```c
if (skb1->len < 1 + cid_len || skb2->len < 1 + cid_len)
    return false;
```

---

### H-2: tquic_process_stream_frame Allocates skb Based on Attacker-Controlled length (tquic_input.c, line 944)

**File**: `/Users/justinadams/Downloads/tquic-kernel/net/tquic/tquic_input.c`
**Lines**: 909-948

**Vulnerable Code**:
```c
    if (length > 65535)
        return -EINVAL;
    ...
    /* Copy data to stream receive buffer */
    data_skb = alloc_skb(length, GFP_ATOMIC);
```

**Exploitation Scenario**: The length is capped at 65535 bytes (line 909), which is reasonable for a single allocation. However, an attacker can send many STREAM frames in rapid succession, each with `length = 65535`. While the `sk_rmem_alloc_get` check at line 963 provides backpressure for connections with a socket, the allocation at line 944 happens BEFORE the rmem check. Under GFP_ATOMIC, the kernel memory allocator can OOM before the rmem check fires.

Additionally, there is no per-connection cap on the total number of open streams. The `tquic_stream_open_incoming()` call at line 938 should enforce MAX_STREAMS, but this is undocumented.

**Impact**: Memory exhaustion (kernel OOM) by flooding STREAM frames from multiple connections.

**Recommendation**: Move the `sk_rmem_alloc` check BEFORE the `alloc_skb()` call to avoid the allocation entirely when the buffer is full. Also consider a global receive buffer cap.

---

### H-3: ECN Counter Values Passed Directly to TQUIC_ADD_STATS Without Overflow Check (tquic_input.c, lines 702-707)

**File**: `/Users/justinadams/Downloads/tquic-kernel/net/tquic/tquic_input.c`
**Lines**: 702-707

**Vulnerable Code**:
```c
    if (ecn_ect0 > 0)
        TQUIC_ADD_STATS(net, TQUIC_MIB_ECNECT0RX, ecn_ect0);
    if (ecn_ect1 > 0)
        TQUIC_ADD_STATS(net, TQUIC_MIB_ECNECT1RX, ecn_ect1);
    if (ecn_ce > 0)
        TQUIC_ADD_STATS(net, TQUIC_MIB_ECNCEMARKSRX, ecn_ce);
```

**Exploitation Scenario**: `ecn_ect0`, `ecn_ect1`, and `ecn_ce` are u64 values decoded from varints. An attacker can craft an ACK_ECN frame with `ecn_ce = 2^62 - 1`. This enormous value is added to per-netns statistics counters. While stats counters are typically atomic64_t and won't overflow in a dangerous way, the tquic_cong_on_ecn call at line 764 receives this value and may interpret it as a massive congestion signal.

**Impact**: Congestion control manipulation. An attacker spoofing ACK_ECN frames can cause the sender to dramatically reduce its congestion window, effectively performing a denial of service by throttling legitimate traffic.

**Recommendation**: Validate that ECN counts are monotonically increasing from previous values. Store previous ECN counts per-path and only react to the *increase*, not the absolute value (as RFC 9002 Section 7.1 requires). The comment at line 759-763 acknowledges this is missing.

---

### H-4: Connection Close Reason Phrase Skipped Without Content Validation (tquic_input.c, lines 1248-1250)

**File**: `/Users/justinadams/Downloads/tquic-kernel/net/tquic/tquic_input.c`
**Lines**: 1248-1250

**Vulnerable Code**:
```c
    if (reason_len > ctx->len - ctx->offset)
        return -EINVAL;
    ctx->offset += (size_t)reason_len;
```

**Analysis**: The bounds check here is correct: `ctx->len - ctx->offset` is a safe subtraction since `ctx->offset < ctx->len` is guaranteed by the frame loop. The cast to `(size_t)` is safe because `reason_len` has already been validated as fitting within the remaining buffer. However, the `pr_info_ratelimited` at line 1252 prints `error_code` and `frame_type` which are attacker-controlled values -- this is acceptable since they are just integers, not strings.

**Re-assessment**: Actually this is correctly implemented. **Downgrading to Informational.**

**REPLACING H-4**:

### H-4 (Revised): tquic_pacing_work Accesses skb->len After tquic_output_packet (tquic_output.c, lines 1413-1418)

**File**: `/Users/justinadams/Downloads/tquic-kernel/net/tquic/tquic_output.c`
**Lines**: 1413-1418

**Vulnerable Code**:
```c
        skb = __skb_dequeue(&pacing->queue);
        spin_unlock_bh(&pacing->lock);

        /* Actually send the packet */
        tquic_output_packet(NULL, pacing->path, skb);

        spin_lock_bh(&pacing->lock);

        /* Update next send time */
        gap = tquic_pacing_calc_gap(pacing, skb->len);  /* <-- UAF */
```

**Exploitation Scenario**: Same pattern as C-2. `tquic_output_packet()` takes ownership of the skb and may free it. Reading `skb->len` afterward is use-after-free.

**Impact**: Reading freed memory for pacing calculation. Could result in incorrect pacing timing or kernel crash if slab is reallocated.

**Recommendation**: Save `skb->len` before calling `tquic_output_packet()`.

---

### H-5: Multipath Frame Processing Lacks Encryption Level Validation (tquic_input.c, lines 2027-2038)

**File**: `/Users/justinadams/Downloads/tquic-kernel/net/tquic/tquic_input.c`
**Lines**: 2027-2038

**Vulnerable Code**:
```c
#ifdef CONFIG_TQUIC_MULTIPATH
        } else if (frame_type == 0x40) {
            /* MP_NEW_CONNECTION_ID (RFC 9369) */
            ret = tquic_process_mp_new_connection_id_frame(&ctx);
        } else if (frame_type == 0x41) {
            /* MP_RETIRE_CONNECTION_ID (RFC 9369) */
            ret = tquic_process_mp_retire_connection_id_frame(&ctx);
        } else if (frame_type == 0x42 || frame_type == 0x43) {
            /* MP_ACK or MP_ACK_ECN (RFC 9369) */
            ret = tquic_process_mp_ack_frame(&ctx);
        } else if (tquic_is_mp_extended_frame(&ctx)) {
            /* Extended multipath frames (PATH_ABANDON, PATH_STATUS) */
            ret = tquic_process_mp_extended_frame(&ctx);
#endif
```

**Exploitation Scenario**: Unlike standard QUIC frames (where each type is checked against `is_initial`, `is_handshake`, `is_0rtt`, `is_1rtt`), the multipath frames (0x40-0x43, extended frames) have NO encryption level validation. An attacker could inject MP_NEW_CONNECTION_ID frames in Initial or Handshake packets where they are not permitted. Since Initial packets are only protected with Initial keys (derivable from the DCID), an on-path attacker could forge Initial packets containing multipath frames to manipulate connection state.

**Impact**: State manipulation via forged multipath frames in weakly-authenticated Initial/Handshake packets. Could cause path confusion, CID manipulation, or denial of service.

**Recommendation**: Add encryption level checks for all multipath frame types. They should only be accepted in 1-RTT packets (and possibly 0-RTT):
```c
} else if (frame_type == 0x40) {
    if (is_initial || is_handshake) {
        conn->error_code = EQUIC_FRAME_ENCODING;
        return -EPROTO;
    }
    ret = tquic_process_mp_new_connection_id_frame(&ctx);
```

---

### H-6: ACK Frame bytes_acked Calculation Can Overflow (tquic_input.c, lines 736-738)

**File**: `/Users/justinadams/Downloads/tquic-kernel/net/tquic/tquic_input.c`
**Lines**: 736-738

**Vulnerable Code**:
```c
    {
        u64 bytes_acked = (first_ack_range + 1) * 1200;

        /* Dispatch ACK event to congestion control */
        tquic_cong_on_ack(ctx->path, bytes_acked, rtt_us);
```

**Exploitation Scenario**: `first_ack_range` is a u64 varint value up to 2^62-1. `(first_ack_range + 1)` overflows if `first_ack_range == UINT64_MAX` (though varint max is 2^62-1, so +1 is safe from wrap). However, `(2^62) * 1200` = 5.5 * 10^21, which exceeds `UINT64_MAX` (1.8 * 10^19). This means the multiplication overflows u64 for any `first_ack_range > ~1.5 * 10^16`.

An attacker sending an ACK frame with `first_ack_range = 2^62 - 1` causes `bytes_acked` to wrap to a small value or to `0`, confusing the congestion control algorithm.

**Impact**: Congestion control manipulation. The sender may suddenly increase its sending rate based on bogus ACK data, potentially contributing to network congestion or enabling amplification.

**Recommendation**: Cap `first_ack_range` to a reasonable value (e.g., the maximum number of packets in flight) before the multiplication. Alternatively, cap `bytes_acked` to the actual bytes in flight.

---

### H-7: tquic_udp_recv Processes Stateless Reset Before Authenticating Packet (tquic_input.c, lines 2916-2932)

**File**: `/Users/justinadams/Downloads/tquic-kernel/net/tquic/tquic_input.c`
**Lines**: 2916-2932

**Vulnerable Code**:
```c
    /* Check for stateless reset (received from peer) */
    if (len < TQUIC_STATELESS_RESET_MIN_LEN)
        goto not_reset;

    if (data[0] & TQUIC_HEADER_FORM_LONG)
        goto not_reset;

    /* Try to find connection for reset check */
    if (len > 1) {
        u8 dcid_len = min_t(size_t, len - 1, TQUIC_MAX_CID_LEN);
        conn = tquic_lookup_by_dcid(data + 1, dcid_len);
    }

    if (conn && tquic_is_stateless_reset_internal(conn, data, len)) {
        tquic_handle_stateless_reset(conn);
        kfree_skb(skb);
        return 0;
    }
```

**Exploitation Scenario**: The code performs a connection lookup using a guessed DCID length (`min(len-1, 20)` bytes). If the attacker knows a valid DCID and the stateless reset token associated with it, they can forge a stateless reset to kill the connection. The RFC acknowledges this is inherent to the protocol. However, the code tries to match the DCID by taking the first `min(len-1, 20)` bytes, which may not match the actual CID length, causing false negatives and wasted lookup cycles.

More importantly, this stateless reset check runs for EVERY short-header packet before the normal decryption path. The `tquic_stateless_reset_detect_conn` function iterates over all stored reset tokens (O(n) per stored CID). An attacker sending a flood of short-header packets forces this O(n) check for every packet.

**Impact**: CPU exhaustion via stateless reset token scanning on every incoming short-header packet. In a multipath scenario with many CIDs, this becomes expensive.

**Recommendation**: Only check for stateless reset AFTER regular decryption fails (RFC 9000 Section 10.3.1 recommends this order). The check should be a last resort, not a first check.

---

### H-8: tquic_output_packet Passes NULL conn to ip_local_out (tquic_output.c, line 1413)

**File**: `/Users/justinadams/Downloads/tquic-kernel/net/tquic/tquic_output.c`
**Line**: 1413

**Vulnerable Code**:
```c
    /* Actually send the packet */
    tquic_output_packet(NULL, pacing->path, skb);
```

**Exploitation Scenario**: In `tquic_pacing_work`, the first argument to `tquic_output_packet` is `NULL`. Inside `tquic_output_packet`, `conn` is checked at lines 1662-1663 and 1713-1714 before dereferencing. However, at line 1730:
```c
ret = ip_local_out(&init_net, NULL, skb);
```
The `&init_net` fallback is always used (since `net` is NULL when `conn` is NULL), reinforcing the namespace escape issue from C-3.

Additionally, at line 1735, the `conn->stats.tx_packets++` line would crash if reached with `conn == NULL`, but it is guarded by `ret >= 0` and the conn check. However, the MIB counter update at line 1739 IS guarded by `if (conn && conn->sk)`. And line 1749 checks `if (conn && conn->crypto_state)`. So the NULL conn path is mostly safe but bypasses all statistics, MIB counters, and key update tracking.

**Impact**: Statistics and security state (key update tracking) are silently skipped for pacing-deferred packets. The namespace escape (C-3) is always triggered.

**Recommendation**: Store a reference to `conn` in `tquic_pacing_state` and pass it through.

---

## MEDIUM SEVERITY ISSUES

### M-1: ktime_get_ts64 Written to skb->cb May Exceed cb Size (tquic_input.c, line 1471)

**File**: `/Users/justinadams/Downloads/tquic-kernel/net/tquic/tquic_input.c`
**Line**: 1471

**Vulnerable Code**:
```c
    /* Store receive timestamp in SKB cb */
    ktime_get_ts64((struct timespec64 *)dgram_skb->cb);
```

**Analysis**: `skb->cb` is 48 bytes. `struct timespec64` is 16 bytes (on 64-bit kernels). This fits. However, the DATAGRAM receive path also stores the recv timestamp here, while the STREAM frame path stores a `u64 offset` in `skb->cb` (line 951: `*(u64 *)data_skb->cb = offset`). There is no type safety -- if code later processes a datagram skb expecting a `u64` offset, or a stream skb expecting a `timespec64`, data corruption occurs.

**Impact**: Logic confusion if skbs are mishandled between datagram and stream paths. Low exploitability but a correctness issue.

**Recommendation**: Use a typed union or dedicated struct for `skb->cb` usage, documented per frame type.

---

### M-2: tquic_recv_datagram Can Loop Forever Under Signal Pressure (tquic_output.c, lines 2706-2743)

**File**: `/Users/justinadams/Downloads/tquic-kernel/net/tquic/tquic_output.c`
**Lines**: 2706-2743

**Vulnerable Code**:
```c
retry:
    spin_lock_irqsave(&conn->datagram.lock, irqflags);
    skb = skb_peek(&conn->datagram.recv_queue);
    if (!skb) {
        spin_unlock_irqrestore(&conn->datagram.lock, irqflags);
        if (flags & MSG_DONTWAIT)
            return -EAGAIN;
        if (timeo == 0)
            return -EAGAIN;
        if (signal_pending(current))
            return sock_intr_errno(timeo);
        ret = tquic_datagram_wait_data(conn, &timeo);
        if (ret < 0) { ... return ... }
        if (conn->state != TQUIC_CONN_CONNECTED ...) return -ENOTCONN;
        goto retry;
    }
```

**Exploitation Scenario**: If `tquic_datagram_wait_data` returns 0 (success, data should be available) but a racing consumer on another thread dequeues the datagram between the wait return and the `retry:` label, the loop goes back to `retry`, finds no skb, calls `wait_data` again. If the peer keeps sending and another consumer keeps racing, this can loop indefinitely, holding `current` in the kernel.

More practically, `timeo` is updated by `wait_event_interruptible_timeout` to the remaining time. On each retry, `*timeo` decreases. When it reaches 0, the `timeo == 0` check returns `-EAGAIN`. So this is bounded by the timeout. However, with `MAX_SCHEDULE_TIMEOUT` (blocking socket, no SO_RCVTIMEO), the timeout is effectively infinite.

**Impact**: A blocking `tquic_recv_datagram` call without SO_RCVTIMEO can be held in a tight retry loop if a racing consumer steals datagrams, consuming CPU.

**Recommendation**: Add a retry counter to prevent excessive looping:
```c
int retries = 0;
...
retry:
    if (++retries > 3) return -EAGAIN;
```

---

### M-3: Version Negotiation Versions Logged Without Rate Limiting (tquic_input.c, lines 473-477)

**File**: `/Users/justinadams/Downloads/tquic-kernel/net/tquic/tquic_input.c`
**Lines**: 473-477

**Vulnerable Code**:
```c
    for (i = 0; i + 4 <= versions_len; i += 4) {
        u32 version = ...;
        tquic_dbg("  version 0x%08x\n", version);
```

**Exploitation Scenario**: An attacker sends a crafted Version Negotiation packet with the maximum possible `versions_len` (up to ~1400 bytes for a 1500-byte MTU), containing 350 version entries. Each triggers a `tquic_dbg` call. While `tquic_dbg` is likely a no-op in production builds, if dynamic debugging is enabled, this floods the kernel log buffer.

**Impact**: Log flooding (minor DoS of logging infrastructure).

**Recommendation**: Either remove the per-version debug line or cap the number of logged versions.

---

### M-4: tquic_gro_flush Drops and Re-acquires Lock Per Packet (tquic_input.c, lines 2303-2310)

**File**: `/Users/justinadams/Downloads/tquic-kernel/net/tquic/tquic_input.c`
**Lines**: 2303-2310

**Vulnerable Code**:
```c
    while ((skb = __skb_dequeue(&gro->hold_queue)) != NULL) {
        spin_unlock(&gro->lock);
        deliver(skb);
        flushed++;
        spin_lock(&gro->lock);
    }

    gro->held_count = 0;
```

**Exploitation Scenario**: While the lock is released during `deliver(skb)`, other code can add packets to the `hold_queue`. When the loop re-acquires the lock, it dequeues and delivers those packets too. After the loop, `held_count` is unconditionally set to 0. If packets were added during the flush, `held_count` becomes incorrect (should reflect newly added packets).

**Impact**: Incorrect `held_count` could cause GRO to hold more packets than intended, or to prematurely stop holding, affecting performance but not security directly.

**Recommendation**: After the loop, set `held_count = skb_queue_len(&gro->hold_queue)`.

---

### M-5: Coalesced Packet Processing Silently Truncates on Overflow (tquic_input.c, lines 3172-3173)

**File**: `/Users/justinadams/Downloads/tquic-kernel/net/tquic/tquic_input.c`
**Lines**: 3172-3173

**Vulnerable Code**:
```c
        if (offset + pkt_len > total_len)
            pkt_len = total_len - offset;
```

**Exploitation Scenario**: If the Length field in a long header packet claims a larger size than the remaining datagram, the code silently truncates `pkt_len` and processes a shorter-than-claimed packet. This packet will have its payload cut short, which means:
1. Decryption will fail (AEAD tag missing or truncated) -- this is the safe case
2. If decryption is not active (Initial before keys), truncated frame data is processed

**Impact**: Could cause frame parsing errors or incomplete CRYPTO frame data being fed to the TLS state machine, potentially triggering TLS parsing bugs.

**Recommendation**: Instead of silently truncating, reject the coalesced packet entirely when the claimed length exceeds remaining data:
```c
if (offset + pkt_len > total_len)
    break;  /* Malformed coalesced packet -- stop */
```

---

## LOW SEVERITY ISSUES

### L-1: tquic_encode_varint Does Not Validate val Range (tquic_output.c, lines 164-198)

**File**: `/Users/justinadams/Downloads/tquic-kernel/net/tquic/tquic_output.c`
**Lines**: 164-198

**Analysis**: The function calls `tquic_varint_len(val)` which should return -EINVAL or similar for values >= 2^62 (the QUIC varint maximum). If `tquic_varint_len` returns 8 for values in [2^62, 2^64-1], the encoding would produce incorrect output (the high 2 bits would be overwritten by the length prefix `0xc0`, silently truncating the value).

**Impact**: If any code path passes a value >= 2^62, the encoded varint would decode to a different (smaller) value. This is a correctness issue that could cause protocol violations.

**Recommendation**: Add validation: `if (val >= (1ULL << 62)) return -EINVAL;`

---

### L-2: tquic_build_short_header_internal Writes pkt_num to buf+64 Scratch Space (tquic_output.c, line 818)

**File**: `/Users/justinadams/Downloads/tquic-kernel/net/tquic/tquic_output.c`
**Line**: 818

**Vulnerable Code**:
```c
    pkt_num_len = tquic_encode_pkt_num(buf + 64, pkt_num, largest_acked);
```

**Analysis**: This writes the packet number encoding into `buf + 64` as scratch space. The function is called with `buf` pointing to stack buffers of size 64 (e.g., line 1915: `u8 header[64]`). Writing at `buf + 64` is a stack buffer overflow of up to 4 bytes past the 64-byte buffer.

In the `tquic_assemble_packet` path, `buf` is `header_buf[128]` (line 961), so `buf + 64` is within bounds. But in `tquic_send_ack` (line 1915) and `tquic_send_connection_close` (line 1982), `buf` is `u8 header[64]`, making `buf + 64` a 4-byte stack overflow.

**Impact**: Stack buffer overflow. The 4 bytes at `header[64..67]` overwrite whatever is next on the stack. Depending on stack layout, this could corrupt the return address or other local variables. However, the overwritten data is then never used (it's just scratch for determining `pkt_num_len`), so the written values don't matter as long as the stack frame can absorb 4 extra bytes.

In practice, the compiler's stack frame is likely larger than 64 bytes due to other local variables. But this is undefined behavior in C and could cause intermittent corruption depending on optimization level and stack layout.

**Recommendation**: Allocate a separate scratch buffer or use a function-local buffer:
```c
u8 pn_scratch[4];
pkt_num_len = tquic_encode_pkt_num(pn_scratch, pkt_num, largest_acked);
```

---

### L-3: tquic_gso_init Integer Overflow in Allocation Size (tquic_output.c, line 1489)

**File**: `/Users/justinadams/Downloads/tquic-kernel/net/tquic/tquic_output.c`
**Line**: 1489

**Vulnerable Code**:
```c
    gso->gso_skb = alloc_skb(gso->gso_size * max_segs + MAX_HEADER, GFP_ATOMIC);
```

**Analysis**: `gso->gso_size` is `path->mtu - 48` (u16), `max_segs` is u16. The multiplication `gso_size * max_segs` is performed in 32-bit (u16 * u16 promotes to int). Maximum value: 65535 * 65535 = 4,294,836,225 which overflows u32. However, `max_segs` is typically small (TQUIC_GSO_MAX_SEGS = 64), making the practical maximum 65535 * 64 = 4,194,240, which fits. But if `max_segs` is user-controllable or comes from an untrusted source, this could overflow.

**Impact**: Allocation of undersized buffer if overflow occurs, leading to heap buffer overflow when GSO segments are added.

**Recommendation**: Use `size_t` arithmetic with overflow checking:
```c
size_t alloc_size;
if (check_mul_overflow((size_t)gso->gso_size, (size_t)max_segs, &alloc_size))
    return -EINVAL;
```

---

### L-4: tquic_process_ack_frame Does Not Validate largest_ack vs first_ack_range (tquic_input.c, lines 601-660)

**File**: `/Users/justinadams/Downloads/tquic-kernel/net/tquic/tquic_input.c`
**Lines**: 601-660

**Analysis**: Per RFC 9000 Section 19.3.1: "The largest packet number in the first ACK Range is determined by subtracting the First ACK Range value from the Largest Acknowledged field." If `first_ack_range > largest_ack`, this subtraction underflows. The code does not validate this relationship.

Similarly, within the ACK ranges loop, each gap and range should be validated against the running smallest acknowledged value to ensure monotonically decreasing packet numbers.

**Impact**: Protocol confusion in the congestion control / loss detection subsystem. An attacker could cause the CC to mark incorrect packets as acknowledged.

**Recommendation**: Add: `if (first_ack_range > largest_ack) return -EINVAL;`

---

### L-5: tquic_process_coalesced Missing Infinite Loop Guard (tquic_input.c, lines 3079-3182)

**File**: `/Users/justinadams/Downloads/tquic-kernel/net/tquic/tquic_input.c`
**Lines**: 3079-3182

**Analysis**: The coalesced packet loop increments `offset` by `pkt_len` each iteration. For short header packets (line 3169), `pkt_len = total_len - offset`, which always terminates the loop. For long header packets, `pkt_len` is computed from the Length field. If `pkt_len` computes to 0 (e.g., `hdr_len + 0 = hdr_len`, but then `check_add_overflow(hdr_len, 0, &pkt_len)` gives `pkt_len = hdr_len`), the loop processes the same bytes repeatedly. However, `pkt_len` must be at least `hdr_len >= 7`, so `offset` always advances at least 7 bytes. This bounds the loop to `total_len / 7` iterations.

Actually, the pkt_len could be very small (just the header) but still positive, so the loop always terminates. Still, adding a `packets` counter limit would be a defense-in-depth improvement.

**Impact**: Bounded CPU consumption (at most ~214 iterations for a 1500-byte datagram).

**Recommendation**: Add `if (packets > 16) break;` to cap coalesced packets.

---

### L-6: spin_lock (Not spin_lock_bh) Used in tquic_process_max_data_frame (tquic_input.c, lines 1015-1017)

**File**: `/Users/justinadams/Downloads/tquic-kernel/net/tquic/tquic_input.c`
**Lines**: 1015-1017

**Vulnerable Code**:
```c
    spin_lock(&ctx->conn->lock);
    ctx->conn->max_data_remote = max(ctx->conn->max_data_remote, max_data);
    spin_unlock(&ctx->conn->lock);
```

**Analysis**: The input path runs in softirq context (UDP receive callback). Using `spin_lock` instead of `spin_lock_bh` means softirqs are NOT disabled. If another softirq on the same CPU also takes `conn->lock` (e.g., timer processing), deadlock occurs.

Other lock acquisitions in the same file correctly use `spin_lock_bh` (e.g., lines 251, 917).

**Impact**: Potential deadlock if `conn->lock` is acquired from both softirq and process context on the same CPU.

**Recommendation**: Change to `spin_lock_bh(&ctx->conn->lock)`.

---

### L-7: tquic_output_flush Holds conn->lock While Calling GFP_ATOMIC Allocation (tquic_output.c, lines 2071-2117)

**File**: `/Users/justinadams/Downloads/tquic-kernel/net/tquic/tquic_output.c`
**Lines**: 2071-2117

**Analysis**: The function acquires `conn->lock` at line 2071 and calls `kzalloc(sizeof(*frame), GFP_ATOMIC)` at line 2117, `kmalloc(chunk_size, GFP_ATOMIC)` at line 2132. GFP_ATOMIC is correct for atomic context, but holding a spinlock while allocating memory is a performance concern. The lock is released before `tquic_assemble_packet` (line 2148), which is good.

The real concern is that `spin_lock_bh` disables softirqs, and if `kzalloc(GFP_ATOMIC)` fails, the error handling at lines 2118-2121 and 2133-2136 correctly breaks out but the lock is still held. The cleanup after the loop at line 2216 releases the lock. This is correct but could hold the lock for a long time if many streams have data.

**Impact**: Potential latency spike from holding `conn->lock` through multiple iterations of the stream loop with GFP_ATOMIC allocations.

**Recommendation**: Consider pre-allocating frame structures outside the lock, or batching frame preparation.

---

## INFORMATIONAL NOTES

### I-1: ACK Frequency Frame Type Inconsistency

The ACK_FREQUENCY frame type is checked as a single-byte value `0xaf` at line 2022, but the `tquic_process_ack_frequency_frame` function (line 1514) re-decodes the frame type as a varint. `0xaf` encoded as a QUIC varint is the 2-byte sequence `0x40 0xaf`. The single-byte check `frame_type == 0xaf` at line 2022 will never match because 0xaf as a single byte has the high 2 bits = `10`, making it a 4-byte varint prefix. This means ACK_FREQUENCY frames may never be dispatched correctly from the main frame loop. (This depends on how `TQUIC_FRAME_ACK_FREQUENCY` is defined -- if it's `0xaf`, the single-byte read `ctx.data[ctx.offset]` would read `0xaf`, but this is not a valid 1-byte varint frame type since the top 2 bits indicate a 4-byte encoding.)

**Recommendation**: Verify the frame type dispatch logic handles multi-byte frame types correctly.

### I-2: IMMEDIATE_ACK Frame Type Similar Issue

Same potential issue as I-1 for `TQUIC_FRAME_IMMEDIATE_ACK` at line 2024.

### I-3: tquic_encap_recv Double UDP Header Strip

At line 3030-3032, `tquic_encap_recv` strips the UDP header with `__skb_pull(skb, sizeof(struct udphdr))` then calls `tquic_udp_recv`. If the UDP encapsulation layer already stripped the header before calling the encap callback, this double-strips and the packet data pointer is wrong. This depends on the kernel version's UDP tunnel semantics.

### I-4: send_skb Variable Used After Potential NULL

In `tquic_output_flush` at line 2182: `if (ret >= 0 && send_skb)` -- but `send_skb` was set at line 2151 and used at line 2162. If `send_skb` is NULL, `tquic_output_packet` is never called, so `ret` retains its previous value. The check at line 2182 is defensive and correct.

---

## SUMMARY TABLE

| ID  | Severity | Category | File | Line(s) | Brief Description |
|-----|----------|----------|------|---------|-------------------|
| C-1 | Critical | Use-After-Free | tquic_input.c | 245-261 | Path returned without refcount |
| C-2 | Critical | Use-After-Free | tquic_output.c | 1730-1736 | skb->len read after ip_local_out |
| C-3 | Critical | Namespace Escape | tquic_output.c | 1730 | Always uses init_net |
| C-4 | Critical | Use-After-Free | tquic_input.c | 397-407 | sk used after unlock without refcount |
| C-5 | Critical | OOB Read | tquic_input.c | 2528-2574 | pkt_num_len not bounds-checked |
| C-6 | Critical | Logic Error | tquic_input.c | 2529,2545,2565 | pkt_num_len read before HP removal |
| H-1 | High | OOB Read | tquic_input.c | 2249-2253 | GRO hardcoded 8-byte CID |
| H-2 | High | Resource Exhaustion | tquic_input.c | 944 | alloc_skb before rmem check |
| H-3 | High | Protocol Abuse | tquic_input.c | 702-707 | ECN counter manipulation |
| H-4 | High | Use-After-Free | tquic_output.c | 1413-1418 | skb->len after output in pacing |
| H-5 | High | Missing AuthZ | tquic_input.c | 2027-2038 | MP frames lack enc_level check |
| H-6 | High | Integer Overflow | tquic_input.c | 736-738 | bytes_acked overflow |
| H-7 | High | CPU Exhaustion | tquic_input.c | 2916-2932 | Stateless reset check on every pkt |
| H-8 | High | Namespace Escape | tquic_output.c | 1413 | NULL conn in pacing work |
| M-1 | Medium | Type Confusion | tquic_input.c | 1471 | skb->cb type safety |
| M-2 | Medium | CPU Exhaustion | tquic_output.c | 2706-2743 | recv_datagram retry loop |
| M-3 | Medium | Log Flood | tquic_input.c | 473-477 | Version neg debug logging |
| M-4 | Medium | Counter Bug | tquic_input.c | 2303-2310 | GRO held_count incorrect |
| M-5 | Medium | Truncation | tquic_input.c | 3172-3173 | Coalesced pkt silent truncate |
| L-1 | Low | Correctness | tquic_output.c | 164-198 | varint val >= 2^62 |
| L-2 | Low | Stack Overflow | tquic_output.c | 818 | Write past header[64] |
| L-3 | Low | Integer Overflow | tquic_output.c | 1489 | GSO alloc size overflow |
| L-4 | Low | Protocol | tquic_input.c | 601-660 | ACK range validation |
| L-5 | Low | DoS | tquic_input.c | 3079-3182 | Coalesced loop bound |
| L-6 | Low | Deadlock | tquic_input.c | 1015-1017 | spin_lock vs spin_lock_bh |
| L-7 | Low | Performance | tquic_output.c | 2071-2117 | Lock held during alloc |

---

## RECOMMENDED FIX PRIORITY

1. **Immediate** (before any deployment):
   - C-2, C-3, H-4: Use-after-free on skb->len and namespace escape -- straightforward fixes
   - C-5, C-6: Packet number length bounds check and HP ordering -- fundamental protocol correctness
   - L-2: Stack buffer overflow in short header building -- trivial fix, high risk

2. **Urgent** (within days):
   - C-1, C-4: Use-after-free on path and socket -- require refcounting infrastructure
   - H-5: Multipath frame encryption level checks -- simple addition
   - L-6: spin_lock_bh fix -- one-line change

3. **Important** (within weeks):
   - H-1: GRO CID length -- requires design change
   - H-2: Stream frame allocation ordering
   - H-3: ECN counter validation
   - H-6: ACK bytes_acked overflow
   - H-7: Stateless reset check ordering

4. **Scheduled** (next release):
   - All Medium and remaining Low issues

---

## APPENDIX: ATTACK SURFACE MAP

```
UDP Datagram from Network
    |
    v
tquic_encap_recv() [line 3027]
    |-- __skb_pull(skb, sizeof(struct udphdr))
    v
tquic_udp_recv(sk, skb) [line 2718]  <-- MAIN ENTRY POINT
    |
    |-- Rate limiting check [2785-2913]
    |   |-- tquic_decode_varint (token parsing) [2841]
    |   |-- tquic_ratelimit_check_initial [2862]
    |   |-- tquic_retry_send [2896]    <-- amplification vector
    |
    |-- Stateless reset check [2916-2932]  <-- H-7: expensive
    |   |-- tquic_lookup_by_dcid [2925]
    |   |-- tquic_is_stateless_reset_internal [2928]
    |
    |-- Version negotiation [2936-2961]
    |   |-- tquic_process_version_negotiation [2954]
    |
    v
tquic_process_packet() [line 2329]  <-- CORE PROCESSING
    |
    |-- Long header path:
    |   |-- tquic_parse_long_header_internal [2354]
    |   |-- Version negotiation [2361]
    |   |-- Retry processing [2380]
    |   |-- 0-RTT processing [2438]
    |   |-- Token parsing for Initial [2501]
    |   |-- Length field parsing [2519]
    |   |-- pkt_num_len extraction [2529]  <-- C-6: before HP
    |
    |-- Short header path:
    |   |-- tquic_parse_short_header_internal [2539]
    |   |-- pkt_num_len extraction [2545]  <-- C-6: before HP
    |
    |-- tquic_remove_header_protection [2565]
    |-- tquic_decode_pkt_num [2573]  <-- C-5: no bounds check
    |
    |-- Decryption:
    |   |-- kmem_cache_alloc / kmalloc [2586-2590]
    |   |-- tquic_zero_rtt_decrypt [2601] or tquic_decrypt_payload [2618]
    |
    |-- Key update detection [2656-2670]
    |
    v
tquic_process_frames() [line 1839]  <-- FRAME DEMUX
    |
    |-- PADDING [1900]
    |-- PING [1902]
    |-- ACK/ACK_ECN [1904]  <-- H-3, H-6, L-4
    |-- CRYPTO [1915]
    |-- NEW_TOKEN [1925]
    |-- STREAM [1935]  <-- H-2
    |-- MAX_DATA [1945]  <-- L-6
    |-- PATH_CHALLENGE/RESPONSE [1963,1972]
    |-- NEW_CONNECTION_ID [1981]
    |-- CONNECTION_CLOSE [1999]
    |-- HANDSHAKE_DONE [2003]
    |-- DATAGRAM [2013]
    |-- ACK_FREQUENCY [2022]  <-- I-1
    |-- MP frames [2027-2038]  <-- H-5
    |-- Unknown frame -> FRAME_ENCODING_ERROR [2040]
    |
    |-- Infinite loop guard [2058]
```

---

*End of audit report.*
