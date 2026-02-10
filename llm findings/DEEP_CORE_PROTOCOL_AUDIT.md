# DEEP CORE PROTOCOL SECURITY AUDIT

## Scope

Line-by-line analysis of three critical files:
- `/Users/justinadams/Downloads/tquic-kernel/net/tquic/core/connection.c` (2832 lines)
- `/Users/justinadams/Downloads/tquic-kernel/net/tquic/core/frame.c` (2823 lines)
- `/Users/justinadams/Downloads/tquic-kernel/net/tquic/core/packet.c` (1768 lines)

Audit Date: 2026-02-09

---

## Critical Issues

### CRIT-01: Server Accept CID Parsing Missing Bounds Checks -- Buffer Over-Read

**File:** `/Users/justinadams/Downloads/tquic-kernel/net/tquic/core/connection.c`
**Lines:** 2449-2515

**Code:**
```c
/* tquic_conn_server_accept */
offset = 5;
dcid_len = data[offset++];     // Line 2450: No check that offset < len
memcpy(dcid.id, data + offset, dcid_len);  // No check dcid_len <= TQUIC_MAX_CID_LEN
dcid.len = dcid_len;
offset += dcid_len;

scid_len = data[offset++];     // Line 2509: No check that offset < len
if (offset + scid_len > len)
    goto err_free;
```

**Vulnerability:** `dcid_len` is read from attacker-controlled data at line 2450 but is never validated against `TQUIC_MAX_CID_LEN` (20 bytes) before being used as the size argument to `memcpy` into `dcid.id[TQUIC_MAX_CID_LEN]`. If `dcid_len > 20`, this is a **stack buffer overflow** writing up to 255 bytes past the `dcid.id[20]` array. Additionally, the first CID length read at line 2450 has no bounds check against `len` at all -- `offset + dcid_len > len` is not checked before the `memcpy`.

**Exploitation:** A remote attacker sends a crafted Initial packet with `dcid_len = 255`. This overflows the stack-allocated `struct tquic_cid dcid` in `tquic_conn_server_accept`, corrupting the return address and potentially achieving kernel RCE.

**Severity:** CRITICAL -- Remote kernel stack buffer overflow, pre-authentication.

**Recommendation:** Add bounds validation:
```c
if (offset >= len) goto err_free;
dcid_len = data[offset++];
if (dcid_len > TQUIC_MAX_CID_LEN) goto err_free;
if (offset + dcid_len > len) goto err_free;
```

---

### CRIT-02: Version Negotiation Packet Overflow -- Unsanitized CID Lengths in tquic_send_version_negotiation

**File:** `/Users/justinadams/Downloads/tquic-kernel/net/tquic/core/connection.c`
**Lines:** 947-997

**Code:**
```c
int tquic_send_version_negotiation(struct tquic_connection *conn,
                                   const struct tquic_cid *dcid,
                                   const struct tquic_cid *scid)
{
    u8 packet[256];
    u8 *p = packet;

    *p++ = 0x80;
    *p++ = 0x00; *p++ = 0x00; *p++ = 0x00; *p++ = 0x00;

    *p++ = scid->len;
    memcpy(p, scid->id, scid->len);   // Line 961
    p += scid->len;

    *p++ = dcid->len;
    memcpy(p, dcid->id, dcid->len);   // Line 965
    p += dcid->len;

    for (i = 0; tquic_supported_versions[i] != 0; i++) {
        u32 ver = cpu_to_be32(tquic_supported_versions[i]);
        memcpy(p, &ver, 4);           // Line 971
        p += 4;
    }
```

**Vulnerability:** The `packet` buffer is 256 bytes. The CID data comes from `tquic_conn_server_accept` where `dcid` and `scid` are populated from attacker data. The CIDs flow from server_accept (CRIT-01) into this function. Even if CID lengths were validated to max 20 each, `5 + 1 + 20 + 1 + 20 + 8 = 55` bytes is safe. But there is no check that `p - packet` does not exceed 256 at any point. If called with corrupted CID structures (via CRIT-01), this overflows the stack buffer.

**Severity:** HIGH -- Stack buffer overflow cascading from CRIT-01.

**Recommendation:** Calculate required size upfront and validate against `sizeof(packet)`.

---

### CRIT-03: Handshake Packet Parsing with Unvalidated Offsets

**File:** `/Users/justinadams/Downloads/tquic-kernel/net/tquic/core/connection.c`
**Lines:** 1921-1971

**Code:**
```c
if (len > 20) {
    size_t hdr_offset;
    u8 dcid_len, scid_len;
    ...
    hdr_offset = 5;
    dcid_len = data[hdr_offset++];       // Line 1932
    hdr_offset += dcid_len;              // No bounds check
    scid_len = data[hdr_offset++];       // Line 1934: May be past buffer end
    hdr_offset += scid_len;              // No bounds check

    token_len = data[hdr_offset];        // Line 1938: May be past buffer end
    ...
    hdr_offset += token_len_size + token_len;  // Line 1947

    pkt_length = data[hdr_offset];       // Line 1950: May be past buffer end
    ...
    hdr_offset += length_size;
    hdr_offset += 4;                     // Line 1961

    payload_offset = hdr_offset;

    if (payload_offset < len &&
        data[payload_offset] == 0x06) {  // Line 1967
```

**Vulnerability:** This manual header parsing in `tquic_conn_process_handshake` has **zero bounds checking** between field reads. After `hdr_offset = 5`, `dcid_len` is read but never validated. If `dcid_len = 200` (attacker-controlled), `hdr_offset` jumps far past `len`. Subsequent reads at `data[hdr_offset]` are out-of-bounds reads from kernel memory.

Additionally, the varint parsing at lines 1938-1957 is completely ad-hoc and incorrect. A 2-byte varint only reads the first byte (`token_len = data[hdr_offset]`), masks the tag bits off, but never reads the second byte. This is both a logic bug and a security issue -- a malformed packet can cause `token_len` to be wrong, leading to further offset miscalculations.

**Exploitation:** A remote attacker sends a crafted Initial packet during handshake. The kernel reads arbitrary kernel memory past the skb buffer, potentially leaking sensitive data through timing side channels or triggering a page fault (kernel crash).

**Severity:** CRITICAL -- Remote kernel memory read (info disclosure / DoS), pre-authentication.

**Recommendation:** Replace the ad-hoc parsing with calls to the existing safe header parser `tquic_parse_long_header()`, or add proper bounds checks before every `data[hdr_offset]` access.

---

### CRIT-04: Retry Token Validation -- Plaintext Buffer Overread

**File:** `/Users/justinadams/Downloads/tquic-kernel/net/tquic/core/connection.c`
**Lines:** 1226-1282

**Code:**
```c
/* Copy ciphertext to plaintext buffer for in-place decryption */
memcpy(plaintext, token + TQUIC_RETRY_TOKEN_IV_LEN, ciphertext_len);
```

Where:
```c
u8 plaintext[128];
ciphertext_len = token_len - TQUIC_RETRY_TOKEN_IV_LEN;
```

**Vulnerability:** `token_len` is a `u32` parameter. The minimum check at line 1195 ensures:
```
token_len >= TQUIC_RETRY_TOKEN_IV_LEN + sizeof(ktime_t) + 1 + sizeof(u32) + TQUIC_RETRY_TOKEN_TAG_LEN
```
That is `12 + 8 + 1 + 4 + 16 = 41`. So `ciphertext_len >= 29`. But there is **no maximum check** on `ciphertext_len`. If `token_len = 300`, then `ciphertext_len = 288`, which overflows the `plaintext[128]` stack buffer in the `memcpy`.

The attacker controls `token_len` via the Initial packet's token field.

**Exploitation:** Send an Initial packet with a token of 300+ bytes. The `memcpy` writes 288 bytes into a 128-byte stack buffer -- a **160-byte stack overflow** allowing kernel RCE.

**Severity:** CRITICAL -- Remote kernel stack buffer overflow during retry token validation.

**Recommendation:** Add `if (ciphertext_len > sizeof(plaintext)) return -EINVAL;` before the memcpy.

---

## High Severity Issues

### HIGH-01: Retry Packet Stack Buffer Overflow

**File:** `/Users/justinadams/Downloads/tquic-kernel/net/tquic/core/connection.c`
**Lines:** 1303-1408

**Code:**
```c
int tquic_send_retry(...)
{
    u8 packet[512];
    u8 *p = packet;
    u8 token[TQUIC_RETRY_TOKEN_MAX_LEN];  // 256 bytes
    ...
    u8 pseudo_packet[512];
    u8 *pp = pseudo_packet;
    ...
    *pp++ = original_dcid->len;
    memcpy(pp, original_dcid->id, original_dcid->len);
    pp += original_dcid->len;

    pkt_len = p - packet;
    memcpy(pp, packet, pkt_len);     // Line 1379
    pp += pkt_len;
```

**Vulnerability:** The `pseudo_packet[512]` buffer receives: `1 + original_dcid->len + pkt_len`. The `pkt_len` includes `5 + 1 + conn->scid.len + 1 + new_scid.len + token_len`. With `token_len` up to 256 (from `tquic_generate_retry_token` output into `token[256]`), `pkt_len` could be `5 + 1 + 20 + 1 + 8 + 256 = 291`. Then `pseudo_len = 1 + 20 + 291 = 312`, which fits in 512. However, the `packet[512]` buffer receives all that plus the 16-byte integrity tag at line 1401: `p += 16`. The maximum `p - packet` could be `291 + 16 = 307`, which fits. But the **total stack usage** is `512 + 256 + 512 = 1280` bytes on the stack, which is excessive for kernel code and risks stack overflow on systems with small kernel stacks (4KB).

**Severity:** HIGH -- Excessive stack allocation may cause kernel stack overflow.

**Recommendation:** Allocate `packet`, `token`, and `pseudo_packet` on the heap using `kmalloc`.

---

### HIGH-02: Retry Token AEAD Key Set Under Non-IRQ-Safe Spinlock

**File:** `/Users/justinadams/Downloads/tquic-kernel/net/tquic/core/connection.c`
**Lines:** 1122-1148

**Code:**
```c
spin_lock(&tquic_retry_aead_lock);
ret = crypto_aead_setkey(tquic_retry_aead, tquic_retry_token_key, ...);
...
ret = crypto_aead_encrypt(req);
spin_unlock(&tquic_retry_aead_lock);
```

**Vulnerability:** `tquic_retry_aead_lock` is defined as `DEFINE_SPINLOCK` (not `_bh` or `_irqsave`). The `crypto_aead_encrypt` function can sleep if the underlying cipher requires async operations. Furthermore, `aead_request_alloc` is called with `GFP_ATOMIC` outside the lock, but `crypto_aead_encrypt/decrypt` may internally schedule work. Calling a potentially-sleeping function under a spinlock causes **sleeping in atomic context** (BUG).

Additionally, this spinlock is taken without `_bh`, so if the crypto operation is interrupted by a softirq that also calls retry token operations, a **deadlock** occurs.

**Severity:** HIGH -- Deadlock or sleeping-in-atomic-context BUG.

**Recommendation:** Use a mutex instead of a spinlock, or use `spin_lock_bh`. Better yet, allocate a per-connection AEAD instance to avoid global locking entirely.

---

### HIGH-03: Return Pointer to Stack/Lock-Protected Data in tquic_conn_get_active_cid

**File:** `/Users/justinadams/Downloads/tquic-kernel/net/tquic/core/connection.c`
**Lines:** 636-655

**Code:**
```c
struct tquic_cid *tquic_conn_get_active_cid(struct tquic_connection *conn)
{
    ...
    spin_lock_bh(&conn->lock);
    list_for_each_entry(entry, &cs->remote_cids, list) {
        if (!entry->retired) {
            result = &entry->cid;
            break;
        }
    }
    spin_unlock_bh(&conn->lock);

    return result;
}
```

**Vulnerability:** Returns a pointer to `entry->cid` which is inside a list entry that can be freed by concurrent CID retirement. After the lock is released, another thread could call `tquic_conn_retire_cid` or free the entry, causing the caller to dereference a **freed pointer** (use-after-free).

**Severity:** HIGH -- Use-after-free via race condition.

**Recommendation:** Copy the CID data into a caller-provided buffer while holding the lock, rather than returning a pointer to shared data.

---

### HIGH-04: Anti-Amplification Integer Overflow

**File:** `/Users/justinadams/Downloads/tquic-kernel/net/tquic/core/connection.c`
**Lines:** 2639-2645

**Code:**
```c
if (cs->is_server) {
    u64 limit = cs->bytes_received_unvalidated * cs->amplification_limit;
    if (cs->bytes_sent_unvalidated + bytes > limit) {
```

**Vulnerability:** `bytes_received_unvalidated * amplification_limit` can overflow `u64` if `bytes_received_unvalidated` is very large (attacker sending many packets before validation). While `amplification_limit` is 3, and `bytes_received_unvalidated` is bounded by actual received data, the `bytes_sent_unvalidated + bytes` addition on the next line can also overflow, wrapping to a small value that appears less than the limit. This would bypass anti-amplification protection.

**Severity:** HIGH -- Amplification attack bypass via integer overflow.

**Recommendation:** Use `check_add_overflow` and `check_mul_overflow` for safe arithmetic.

---

### HIGH-05: Coalesced Packet Splitting Assumes v1 Packet Type Encoding

**File:** `/Users/justinadams/Downloads/tquic-kernel/net/tquic/core/packet.c`
**Lines:** 1275-1276, 1320-1321

**Code:**
```c
/* Check for Initial packet (has token) */
if ((data[offset] & QUIC_LONG_HEADER_TYPE_MASK) ==
    (QUIC_PACKET_TYPE_INITIAL << QUIC_LONG_HEADER_TYPE_SHIFT)) {
```

and:
```c
if ((data[offset] & QUIC_LONG_HEADER_TYPE_MASK) ==
    (QUIC_PACKET_TYPE_RETRY << QUIC_LONG_HEADER_TYPE_SHIFT)) {
```

**Vulnerability:** These checks hardcode QUIC v1 packet type encodings. For QUIC v2 (RFC 9369), the type bits are different (Initial = 0x01, Retry = 0x00 in v2 vs Initial = 0x00, Retry = 0x03 in v1). The function never reads the version field to determine which encoding to use.

For a v2 coalesced packet, an Initial packet would be misidentified, so its token field would not be parsed. This causes the length field to be read from the wrong offset, potentially reading the token data as a length, which would cause completely incorrect packet splitting.

**Severity:** HIGH -- Coalesced QUIC v2 packets are parsed incorrectly, causing buffer over-reads and incorrect packet boundaries.

**Recommendation:** Read the version field (bytes 1-4) and use `tquic_decode_packet_type()` for version-aware type detection.

---

### HIGH-06: payload_len Subtraction Underflow in Long Header Parsing

**File:** `/Users/justinadams/Downloads/tquic-kernel/net/tquic/core/packet.c`
**Lines:** 618-619

**Code:**
```c
hdr->header_len = offset;
/* Adjust payload_len to not include packet number */
hdr->payload_len -= hdr->pn_len;
```

**Vulnerability:** `hdr->payload_len` was set from the decoded varint Length field, which specifies "the length of the remainder of the packet (that is, the Packet Number and Payload fields)" per RFC 9000. But if `hdr->payload_len < hdr->pn_len` (from a malformed packet where the Length field is very small, e.g., 0), this subtraction underflows. Since `payload_len` is `u64`, it wraps to a huge value.

The check at line 590-601 validates `offset + payload_len <= len` using the original payload_len (which includes pn_len). But the subtraction at line 619 is not checked.

**Severity:** HIGH -- Integer underflow leads to huge `payload_len` value, causing callers to read past buffer.

**Recommendation:** Add `if (hdr->payload_len < hdr->pn_len) return -EPROTO;` before the subtraction.

---

## Medium Severity Issues

### MED-01: Retry Token Address Validation Uses Weak Hash

**File:** `/Users/justinadams/Downloads/tquic-kernel/net/tquic/core/connection.c`
**Lines:** 1093-1104, 1270-1286

**Code:**
```c
u32 hash = jhash(&sin->sin_addr, sizeof(sin->sin_addr), sin->sin_port);
```

**Vulnerability:** `jhash` is a non-cryptographic hash. An attacker who observes one valid retry token and can predict the seed (port number) could potentially craft collisions. The token is encrypted with AES-GCM, so the hash itself is not directly visible, but using a cryptographic hash (e.g., SipHash) would be more robust.

**Severity:** MEDIUM

**Recommendation:** Use `siphash` instead of `jhash` for address validation hashing.

---

### MED-02: Token Hash Comparison Not Constant-Time

**File:** `/Users/justinadams/Downloads/tquic-kernel/net/tquic/core/connection.c`
**Lines:** 1283

**Code:**
```c
if (token_hash != expected_hash) {
```

**Vulnerability:** The address hash comparison uses a simple `!=` operator, which is not constant-time. While the hash is already within an AEAD-encrypted envelope (so an attacker cannot iterate), this is a defense-in-depth concern.

**Severity:** MEDIUM -- Timing oracle on address hash (mitigated by AEAD encryption).

**Recommendation:** Use `crypto_memneq` for the comparison.

---

### MED-03: CID Sequence Number Rollback on rhashtable Insert Failure

**File:** `/Users/justinadams/Downloads/tquic-kernel/net/tquic/core/connection.c`
**Lines:** 536

**Code:**
```c
cs->next_local_cid_seq--;
```

**Vulnerability:** The sequence number is decremented on error after `cs->next_local_cid_seq++` was already done at line 502 outside the lock. If two threads call `tquic_conn_add_local_cid` concurrently, both increment `next_local_cid_seq`, and if the second thread's rhashtable insert fails, it decrements, creating a sequence number that overlaps with the first thread's successful entry.

**Severity:** MEDIUM -- CID sequence number collision under concurrent access.

**Recommendation:** Perform the sequence number increment inside the spinlock, or use atomic operations.

---

### MED-04: Version Negotiation Packet Not Authenticated

**File:** `/Users/justinadams/Downloads/tquic-kernel/net/tquic/core/connection.c`
**Lines:** 1012-1048

**Code:**
```c
int tquic_handle_version_negotiation(...)
{
    ...
    if (cs->version_negotiation_done) {
        tquic_conn_warn(conn, "duplicate version negotiation\n");
        return -EPROTO;
    }
    new_version = tquic_version_select(versions, num_versions);
    ...
    conn->version = new_version;
```

**Vulnerability:** Version Negotiation packets are not authenticated in QUIC (by design -- they happen before crypto setup). However, this code does not implement the VN packet validation described in RFC 9368 (Compatible Version Negotiation). An on-path attacker could inject a VN packet to force a version downgrade or cause the connection to fail. The code checks for duplicate VN but does not verify the VN packet contains the originally attempted version.

Per RFC 9000 Section 6.2: "A client MUST discard a Version Negotiation packet that lists the QUIC version selected by the client."

**Severity:** MEDIUM -- Version downgrade attack possible.

**Recommendation:** Check that the VN version list does NOT contain the version the client originally tried.

---

### MED-05: Unbounded Pending Path Challenges

**File:** `/Users/justinadams/Downloads/tquic-kernel/net/tquic/core/connection.c`
**Lines:** 1440-1464

**Code:**
```c
int tquic_send_path_challenge(struct tquic_connection *conn, struct tquic_path *path)
{
    ...
    challenge = kzalloc(sizeof(*challenge), GFP_ATOMIC);
    ...
    list_add_tail(&challenge->list, &cs->pending_challenges);
```

**Vulnerability:** There is no limit on the number of pending path challenges. Each challenge allocates memory (`sizeof(struct tquic_path_challenge)` = ~40 bytes). A rapid caller could exhaust kernel memory. While the caller is typically internal, if migration or path creation is triggered by attacker actions (e.g., address changes), this could be abused.

**Severity:** MEDIUM -- Potential memory exhaustion via unbounded path challenges.

**Recommendation:** Limit pending challenges to a reasonable maximum (e.g., 10).

---

### MED-06: ACK Frame Range Count Uses u64 Loop Variable Against size_t max_ranges

**File:** `/Users/justinadams/Downloads/tquic-kernel/net/tquic/core/frame.c`
**Lines:** 355-356

**Code:**
```c
if (frame->ack.ack_range_count > max_ranges)
    return -EOVERFLOW;
```

**Vulnerability:** `ack_range_count` is `u64` and `max_ranges` is `size_t`. On 32-bit systems, `size_t` is 32 bits. If `ack_range_count = 0x1_0000_0001` and `max_ranges = 1`, the comparison `0x1_0000_0001 > 1` is true, so this is caught. This is actually safe because the comparison promotes `size_t` to `u64`. However, the loop at line 370 uses `u64 i` iterating up to `ack_range_count`, which on a 32-bit system could cause very long loops if `ack_range_count` is large but less than `max_ranges` (if max_ranges is also large).

**Severity:** LOW (properly mitigated by the range check).

---

### MED-07: Packet Number Decode Returns 0 on Invalid Input

**File:** `/Users/justinadams/Downloads/tquic-kernel/net/tquic/core/packet.c`
**Lines:** 335-336

**Code:**
```c
if (len < 1 || len > 4)
    return 0;
```

**Vulnerability:** Returning 0 for invalid input is ambiguous -- 0 is a valid packet number. Callers cannot distinguish between "packet number is 0" and "invalid input". This could cause packet number 0 to be processed incorrectly for malformed packets.

**Severity:** MEDIUM -- Ambiguous error return could cause mis-processing.

**Recommendation:** Return a sentinel value or use an error pointer pattern (pass pn by reference, return error code).

---

### MED-08: Connection State Not Checked in tquic_conn_handle_close

**File:** `/Users/justinadams/Downloads/tquic-kernel/net/tquic/core/connection.c`
**Lines:** 2138-2164

**Code:**
```c
int tquic_conn_handle_close(struct tquic_connection *conn,
                            u64 error_code, u64 frame_type,
                            const char *reason, bool is_app)
{
    ...
    /* Enter draining state */
    tquic_conn_enter_draining(conn);
```

**Vulnerability:** This function does not check the current connection state before calling `tquic_conn_enter_draining`. If the connection is already CLOSED, `tquic_conn_set_state` will reject the transition (CLOSED is terminal), but the function still modifies `cs->remote_close` fields. If the connection is already DRAINING, it would attempt a DRAINING->DRAINING transition, which is also rejected. The `kstrdup(reason)` allocation and `kfree(cs->remote_close.reason_phrase)` is performed regardless.

This means an attacker can repeatedly send CONNECTION_CLOSE frames to trigger repeated `kfree`/`kstrdup` cycles, causing memory churn.

**Severity:** MEDIUM -- Resource churn via repeated CONNECTION_CLOSE.

**Recommendation:** Check `conn->state` and early-return for DRAINING/CLOSED states.

---

## Low Severity Issues

### LOW-01: Retry Integrity Tag Computed with Potentially-Failing AEAD

**File:** `/Users/justinadams/Downloads/tquic-kernel/net/tquic/core/connection.c`
**Lines:** 1383-1407

**Code:**
```c
aead = crypto_alloc_aead("gcm(aes)", 0, 0);
if (!IS_ERR(aead)) {
    ...
    ret = crypto_aead_encrypt(req);
    if (ret == 0) {
        memcpy(p, tag, 16);
        p += 16;
    }
    ...
}
```

**Vulnerability:** If AEAD allocation or encryption fails, the Retry packet is sent **without the Retry Integrity Tag**. The client should reject this (per RFC 9001), but a non-compliant client might accept it. A Retry packet without a valid integrity tag defeats address validation.

**Severity:** LOW -- Graceful degradation issue; client-side should reject.

**Recommendation:** Return an error if the integrity tag cannot be computed rather than sending a tagless packet.

---

### LOW-02: close_work Repurposes drain_work for Retransmit Scheduling

**File:** `/Users/justinadams/Downloads/tquic-kernel/net/tquic/core/connection.c`
**Lines:** 2214-2216

**Code:**
```c
static void tquic_close_work_handler(struct work_struct *work)
{
    ...
    if (cs->close_retries < 3) {
        tquic_send_close_frame(conn);
        schedule_delayed_work(&cs->drain_work,
                              msecs_to_jiffies(1000));
    }
```

**Vulnerability:** The `close_work_handler` schedules `drain_work` for retransmission timing. But `drain_work` is also used for the drain timeout. If the connection transitions to DRAINING while close retries are pending, the `drain_work` callback (`tquic_drain_timeout`) will fire instead of the intended retransmit, potentially entering CLOSED prematurely.

**Severity:** LOW -- Logic confusion between close retransmit timer and drain timer.

**Recommendation:** Use a separate delayed_work for close retransmission.

---

### LOW-03: HMAC Output Not Zeroized on Fallback Path

**File:** `/Users/justinadams/Downloads/tquic-kernel/net/tquic/core/connection.c`
**Lines:** 730-733

**Code:**
```c
fallback:
    kfree(desc);
    crypto_free_shash(tfm);
    tquic_stateless_reset_generate_token(cid, static_key, token);
```

**Vulnerability:** On the success path, `hmac_out` is zeroized with `memzero_explicit`. On the fallback path, the stack buffer may still contain partial HMAC output that is not cleared.

**Severity:** LOW -- Residual key material on stack.

**Recommendation:** Add `memzero_explicit(hmac_out, sizeof(hmac_out));` before `goto fallback`.

---

### LOW-04: Version Negotiation First Byte Missing Fixed Bit Randomization

**File:** `/Users/justinadams/Downloads/tquic-kernel/net/tquic/core/connection.c`
**Line:** 956

**Code:**
```c
*p++ = 0x80;  /* Long header */
```

**Vulnerability:** The first byte of a VN packet should have random bits in the non-form bit positions per RFC 9000 Section 17.2.1 to prevent ossification. The code always sends `0x80`. Compare with `tquic_build_version_negotiation` in packet.c (line 807) which correctly randomizes: `buf[offset++] = QUIC_HEADER_FORM_LONG | (get_random_u8() & 0x7f);`

**Severity:** LOW -- Ossification concern; no direct security impact.

---

### LOW-05: Duplicate CID Not Checked in tquic_conn_add_remote_cid

**File:** `/Users/justinadams/Downloads/tquic-kernel/net/tquic/core/connection.c`
**Lines:** 559-587

**Code:**
```c
int tquic_conn_add_remote_cid(struct tquic_connection *conn,
                              const struct tquic_cid *cid, u64 seq, ...)
{
    ...
    entry = tquic_cid_entry_create(cid, seq);
    ...
    list_add_tail(&entry->list, &cs->remote_cids);
```

**Vulnerability:** The function does not check if a CID with the same sequence number already exists. A malicious peer could send duplicate NEW_CONNECTION_ID frames with the same seq but different CIDs, causing the list to grow unboundedly with duplicate sequence numbers.

**Severity:** LOW -- Memory waste via duplicate CID entries; also violates RFC 9000 which says peers MUST NOT reuse sequence numbers.

**Recommendation:** Check for existing seq before adding.

---

## Summary Table

| ID | Severity | File | Line(s) | Description |
|----|----------|------|---------|-------------|
| CRIT-01 | CRITICAL | connection.c | 2449-2515 | Server accept CID parsing: stack buffer overflow via unchecked dcid_len |
| CRIT-02 | HIGH | connection.c | 947-997 | VN packet: cascading overflow from CRIT-01 |
| CRIT-03 | CRITICAL | connection.c | 1921-1971 | Handshake parsing: zero bounds checks, kernel memory over-read |
| CRIT-04 | CRITICAL | connection.c | 1226-1227 | Retry token validation: stack buffer overflow via unbounded ciphertext |
| HIGH-01 | HIGH | connection.c | 1303-1408 | Excessive stack usage (~1280 bytes) in tquic_send_retry |
| HIGH-02 | HIGH | connection.c | 1122-1148 | Potentially-sleeping AEAD ops under spinlock |
| HIGH-03 | HIGH | connection.c | 636-655 | Use-after-free: returning pointer to lock-protected CID entry |
| HIGH-04 | HIGH | connection.c | 2639-2645 | Anti-amplification integer overflow bypasses rate limiting |
| HIGH-05 | HIGH | packet.c | 1275-1321 | Coalesced packet splitting hardcodes v1 type encoding, breaks v2 |
| HIGH-06 | HIGH | packet.c | 618-619 | payload_len underflow when payload_len < pn_len |
| MED-01 | MEDIUM | connection.c | 1093-1104 | Non-cryptographic jhash for address validation |
| MED-02 | MEDIUM | connection.c | 1283 | Non-constant-time hash comparison |
| MED-03 | MEDIUM | connection.c | 502,536 | CID sequence number race on concurrent add |
| MED-04 | MEDIUM | connection.c | 1012-1048 | VN packet missing RFC 9000 Sec 6.2 validation |
| MED-05 | MEDIUM | connection.c | 1440-1464 | Unbounded pending path challenges |
| MED-06 | LOW | frame.c | 355-356 | u64 vs size_t comparison (actually safe) |
| MED-07 | MEDIUM | packet.c | 335-336 | pn_decode returns 0 for invalid input (ambiguous) |
| MED-08 | MEDIUM | connection.c | 2138-2164 | handle_close does not check current state |
| LOW-01 | LOW | connection.c | 1383-1407 | Retry sent without integrity tag on AEAD failure |
| LOW-02 | LOW | connection.c | 2214-2216 | drain_work reused for close retransmit timer |
| LOW-03 | LOW | connection.c | 730-733 | HMAC output not zeroized on fallback |
| LOW-04 | LOW | connection.c | 956 | VN first byte not randomized |
| LOW-05 | LOW | connection.c | 559-587 | Duplicate remote CID seq not checked |

## Assessment of frame.c

The frame parsing code in `frame.c` is **well-written from a security perspective**. Key positive observations:

1. **FRAME_ADVANCE_SAFE macro** provides consistent underflow protection for all pointer arithmetic.
2. **Every varint decode** is followed by bounds checking before advancing.
3. **Data length fields** (crypto, stream, new_token, datagram, connection_close) are all validated against both `SIZE_MAX` (for 32-bit safety) and `remaining` before buffer access.
4. **Protocol limits** are enforced (MAX_STREAMS capped at 2^60, NEW_CONNECTION_ID CID length validated 1-20).
5. **The `tquic_parse_frame` dispatch** correctly rejects unknown frame types with `-EPROTONOSUPPORT`.
6. **No raw pointer arithmetic** -- all movement through the buffer uses the safe advance pattern.

The only minor issue found is MED-06 (u64 vs size_t comparison), which is actually safe due to implicit promotion.

## Assessment of packet.c Header Parsing

The `tquic_parse_long_header` and `tquic_parse_short_header` functions are **mostly well-defended**:

1. **CID lengths** are validated against `TQUIC_MAX_CID_LEN` before memcpy.
2. **Token lengths** use `check_add_overflow` to prevent integer wraparound.
3. **Payload length** uses both `SIZE_MAX` check and `check_add_overflow`.
4. The main issues are HIGH-05 (v2 coalesced packet) and HIGH-06 (payload_len underflow).

## Assessment of connection.c

The connection state machine has **the most security issues** of the three files, concentrated in:

1. **Manual header parsing** in `tquic_conn_process_handshake` (CRIT-03) that duplicates and badly reimplements what `tquic_parse_long_header` does safely.
2. **Server accept** (CRIT-01) missing CID length validation.
3. **Retry token handling** (CRIT-04) missing buffer size validation.
4. **Concurrency issues** (HIGH-02, HIGH-03, MED-03) around lock usage and shared data.

The state machine transitions themselves (lines 275-310) are correctly implemented with a whitelist approach that prevents invalid transitions.

## Recommendations Priority

1. **Immediate (before any deployment):** Fix CRIT-01, CRIT-03, CRIT-04 -- these are remotely exploitable pre-authentication.
2. **High priority:** Fix HIGH-02 through HIGH-06 -- these can cause crashes, UAF, or protocol failures.
3. **Medium priority:** Address MED-01 through MED-08 for defense-in-depth.
4. **Low priority:** LOW-01 through LOW-05 for code quality.
