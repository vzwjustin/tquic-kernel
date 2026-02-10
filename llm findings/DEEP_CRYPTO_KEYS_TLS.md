# TQUIC Deep Crypto Audit Part 2: Key Management, TLS, Header Protection

**Date:** 2026-02-09
**Auditor:** Claude Opus 4.6 (Kernel Security Reviewer)
**Scope:** Key lifecycle, key update races, AEAD nonce reuse, header protection,
HW offload, token encryption, crypto API error handling, hot-path allocations,
timing attacks

---

## Files Reviewed

| File | Lines | Description |
|------|-------|-------------|
| `/Users/justinadams/Downloads/tquic-kernel/net/tquic/crypto/key_update.c` | 1459 | Key update mechanism (RFC 9001 Section 6) |
| `/Users/justinadams/Downloads/tquic-kernel/net/tquic/crypto/key_update.h` | 419 | Key update state structures |
| `/Users/justinadams/Downloads/tquic-kernel/net/tquic/crypto/extended_key_update.c` | 1157 | Extended key update with PSK injection |
| `/Users/justinadams/Downloads/tquic-kernel/net/tquic/crypto/extended_key_update.h` | 524 | EKU state machine and API |
| `/Users/justinadams/Downloads/tquic-kernel/net/tquic/crypto/tls.c` | 1179 | TLS 1.3 crypto state, encrypt/decrypt |
| `/Users/justinadams/Downloads/tquic-kernel/net/tquic/crypto/header_protection.c` | 1227 | HP mask generation (AES-ECB, ChaCha20) |
| `/Users/justinadams/Downloads/tquic-kernel/net/tquic/crypto/hw_offload.c` | 1176 | HW crypto offload, batch operations |
| `/Users/justinadams/Downloads/tquic-kernel/net/tquic/crypto/hw_offload.h` | 426 | HW offload API and structures |
| `/Users/justinadams/Downloads/tquic-kernel/net/tquic/crypto/crypto_module.c` | 70 | Module init/exit |
| `/Users/justinadams/Downloads/tquic-kernel/net/tquic/core/quic_crypto.c` | 1815 | Core crypto context, HKDF, encrypt/decrypt |
| `/Users/justinadams/Downloads/tquic-kernel/net/tquic/tquic_token.c` | 908 | Address validation token generation |
| `/Users/justinadams/Downloads/tquic-kernel/net/tquic/crypto/zero_rtt.h` | 658 | 0-RTT state and anti-replay |
| `/Users/justinadams/Downloads/tquic-kernel/net/tquic/crypto/cert_verify.h` | ~100 | Certificate verification types |

---

## CRITICAL Findings

### C1. Hardcoded Struct Offset to Access Key Update State -- Memory Corruption Risk

**File:** `/Users/justinadams/Downloads/tquic-kernel/net/tquic/crypto/key_update.c`
**Lines:** 1143-1172

```c
struct tquic_crypto_state_ku_accessor {
    char _before_key_update[304];    /* Approximate offset */
    struct tquic_key_update_state *key_update;
} *accessor;

if (!crypto_state)
    return NULL;

if (header->cipher_suite == 0)
    return NULL;

accessor = crypto_state;
return accessor->key_update;
```

**Crypto Impact:** This function uses a hardcoded 304-byte offset to locate the
`key_update` pointer inside `tquic_crypto_state`. If the struct layout changes
(new fields, reordering, different compiler padding), this reads an arbitrary
8-byte value and interprets it as a pointer. The "safety check" on
`cipher_suite != 0` is insufficient -- most non-zero garbage values pass this
check.

**Severity:** CRITICAL

**Fix:** Export a proper accessor function from `tls.c` that has visibility into
the actual `tquic_crypto_state` definition:
```c
/* In tls.c, where tquic_crypto_state is fully defined: */
struct tquic_key_update_state *tquic_crypto_get_key_update_state(
    struct tquic_crypto_state *crypto)
{
    return crypto ? crypto->key_update : NULL;
}
```

---

### C2. Per-Packet crypto_aead_setkey on Shared AEAD Handle -- Race Condition

**File:** `/Users/justinadams/Downloads/tquic-kernel/net/tquic/crypto/tls.c`
**Lines:** 622, 679

```c
/* In tquic_encrypt_packet(), line 622: */
ret = crypto_aead_setkey(crypto->aead, keys->key, keys->key_len);

/* In tquic_decrypt_packet(), line 679: */
ret = crypto_aead_setkey(crypto->aead, keys->key, keys->key_len);
```

**Crypto Impact:** Both encrypt and decrypt paths call `crypto_aead_setkey()`
on the SAME `crypto->aead` transform handle on every packet. If TX and RX run
concurrently (which they will -- TX from sendmsg, RX from softirq), one path
can set the RX key while the other is mid-encryption with the TX key. This is
a data race on the internal key schedule of the AEAD transform.

The result: packets encrypted with the wrong key, authentication failures,
potential plaintext disclosure if a packet is encrypted with a key the attacker
knows (e.g., the read key for the attacker's own traffic).

**Severity:** CRITICAL

**Fix:** Use separate AEAD transform handles for TX and RX, each with the key
set once during key installation (not per-packet). The `quic_crypto.c` file
already does this correctly with `tx_aead` and `rx_aead` -- the `tls.c`
implementation should follow the same pattern.

---

### C3. Install Secrets Accesses State Without Lock After Unlock

**File:** `/Users/justinadams/Downloads/tquic-kernel/net/tquic/crypto/key_update.c`
**Lines:** 878-898

```c
spin_unlock_irqrestore(&state->lock, flags);    /* line 878 */

/* Derive keys from secrets -- NO LOCK HELD */
ret = tquic_ku_derive_keys(state, &state->current_read);   /* line 881 */
if (ret)
    return ret;

ret = tquic_ku_derive_keys(state, &state->current_write);  /* line 885 */
if (ret)
    return ret;

/* Pre-compute next generation keys -- NO LOCK HELD */
ret = tquic_ku_derive_next_generation(state, &state->current_read,
                                      &state->next_read);   /* line 890 */
```

**Crypto Impact:** After installing secrets into `state->current_read` and
`state->current_write` under the lock (lines 868-878), the lock is dropped and
then key derivation is performed directly on `state->current_read` and
`state->current_write` without any lock. If another thread initiates a key
update concurrently, it could modify these fields while derivation is reading
them, leading to corrupted key material or use of partially-updated secrets.

This function also passes `state` itself to `tquic_ku_derive_keys()`, which
accesses `state->hash_tfm` without locking -- a shared crypto transform handle.

**Severity:** CRITICAL

**Fix:** Copy the secrets into local variables under the lock, then derive from
the local copies (the pattern already used correctly in
`tquic_initiate_key_update` at lines 392-405). The results should be committed
back under the lock.

---

## HIGH Severity Findings

### H1. EKU Derives Keys Using KU hash_tfm Without KU Lock

**File:** `/Users/justinadams/Downloads/tquic-kernel/net/tquic/crypto/extended_key_update.c`
**Lines:** 829-834

```c
spin_unlock_irqrestore(&state->lock, flags);    /* line 821 */

/* Access ku_state->hash_tfm WITHOUT ku_state->lock */
if (ku_state->hash_tfm) {                       /* line 829 */
    ret = eku_hkdf_extract(ku_state->hash_tfm,  /* line 830 */
                           current_secret, secret_len,
                           state->injected_psk,
                           state->injected_psk_len,
                           mixed_secret, secret_len);
```

**Crypto Impact:** After releasing the EKU lock, the code reads
`ku_state->hash_tfm` and calls `eku_hkdf_extract()` with it, but the KU state
lock is never held. A concurrent key update could free/replace `hash_tfm`.
Additionally, `state->injected_psk` and `state->injected_psk_len` are accessed
after the EKU lock was released (line 821), so they could be modified by a
concurrent PSK injection.

**Severity:** HIGH

**Fix:** Either (a) hold the KU lock around `hash_tfm` access, or (b) copy
`hash_tfm` under the KU lock and use the copy (though crypto transforms are
not reference-counted, so this requires ensuring the transform outlives usage).
For the PSK, copy it under the EKU lock before releasing.

---

### H2. EKU Semantic Mismatch: get_current_keys Returns Key, Not Secret

**File:** `/Users/justinadams/Downloads/tquic-kernel/net/tquic/crypto/extended_key_update.c`
**Lines:** 808-815

```c
size_t secret_len = 32;  /* SHA-256 default */
u8 current_secret[48];
u32 key_len;

/* Get current secret from base key update state */
ret = tquic_key_update_get_current_keys(ku_state, 1,
                                        current_secret, &key_len,
                                        NULL, NULL);
```

**Crypto Impact:** The variable is named `current_secret` and later used as the
IKM (input key material) for HKDF-Extract. However,
`tquic_key_update_get_current_keys()` returns the derived AEAD key (16 or 32
bytes), NOT the traffic secret (32 or 48 bytes). Using the derived key instead
of the traffic secret as HKDF-Extract input is cryptographically incorrect --
the HKDF chain is broken, and the resulting key material will not match what the
peer derives.

Additionally, the hardcoded `secret_len = 32` ignores the cipher suite;
AES-256-GCM with SHA-384 uses 48-byte secrets.

**Severity:** HIGH

**Fix:** Add and use a function to retrieve the current traffic secret (not the
derived key) from `tquic_key_update_state`. Derive `secret_len` from the
cipher suite.

---

### H3. memset Instead of memzero_explicit for Old Key Material

**File:** `/Users/justinadams/Downloads/tquic-kernel/net/tquic/crypto/key_update.c`
**Lines:** 435, 627-628

```c
/* Line 435: After key rotation in tquic_initiate_key_update */
memset(&state->next_write, 0, sizeof(state->next_write));

/* Lines 627-628: After peer key phase change */
memset(&state->next_read, 0, sizeof(state->next_read));
memset(&state->next_write, 0, sizeof(state->next_write));
```

**Crypto Impact:** `memset` may be optimized away by the compiler since the
memory is not read afterward. This leaves old key material in memory, which can
be recovered via cold boot attacks, kernel memory dumps, or /proc/kcore. The
kernel provides `memzero_explicit()` specifically for this purpose and it is
used correctly elsewhere in the same file (e.g., line 404).

**Severity:** HIGH

**Fix:** Replace all `memset(..., 0, ...)` clearing key material with
`memzero_explicit()`.

---

## MEDIUM Severity Findings

### M1. Per-Call skcipher_request Allocation in HP Mask Hot Path

**File:** `/Users/justinadams/Downloads/tquic-kernel/net/tquic/crypto/header_protection.c`
**Lines:** 164, 211

```c
/* AES path, line 164: */
req = skcipher_request_alloc(hp_key->tfm, GFP_ATOMIC);
if (!req)
    return -ENOMEM;

/* ChaCha20 path, line 211: */
req = skcipher_request_alloc(hp_key->tfm, GFP_ATOMIC);
if (!req)
    return -ENOMEM;
```

**Crypto Impact:** Header protection is applied to EVERY packet (both TX and
RX). Allocating a `skcipher_request` per packet from atomic context adds
allocation pressure, memory fragmentation, and ENOMEM risk under load. Under
memory pressure (e.g., DDoS), the GFP_ATOMIC allocation fails, causing packet
drops even when the connection is otherwise healthy.

**Severity:** MEDIUM

**Fix:** Pre-allocate the `skcipher_request` in the `tquic_hp_key` structure
during key setup. Use a per-CPU or per-connection pre-allocated request to
avoid hot-path allocations.

---

### M2. Per-Packet kmalloc in Batch Encrypt/Decrypt

**File:** `/Users/justinadams/Downloads/tquic-kernel/net/tquic/crypto/hw_offload.c`
**Lines:** 708, 773

```c
/* Encrypt path, line 708: */
ct_buf = kmalloc(ct_buf_len, GFP_ATOMIC);
if (!ct_buf) {
    pkt->result = -ENOMEM;
    continue;
}
```

**Crypto Impact:** The entire point of batch encrypt/decrypt is performance, but
each packet in the batch gets a separate `kmalloc(GFP_ATOMIC)` for a temporary
ciphertext buffer. For a batch of 64 packets, this is 64 allocations + 64 frees.
Under memory pressure, partial batch failures leave some packets encrypted and
some not.

**Severity:** MEDIUM

**Fix:** Allocate a single buffer sized for the largest packet in the batch, or
use a pre-allocated per-CPU bounce buffer. Alternatively, encrypt in-place if
the caller guarantees sufficient tail room (the `data_buf_len` check at line
703 already validates this -- the temporary buffer is unnecessary).

---

### M3. Hardcoded 8-Byte CID in Short Header Unprotect

**File:** `/Users/justinadams/Downloads/tquic-kernel/net/tquic/core/quic_crypto.c`
**Line:** 1453

```c
/* Short header - DCID starts at byte 1 */
*pn_offset = 1 + 8;  /* Assume 8-byte connection ID */
```

**Crypto Impact:** QUIC connection IDs can be 0-20 bytes (RFC 9000 Section
17.2). Hardcoding 8 bytes means:
- Shorter CIDs: the PN offset is wrong, header unprotection fails or produces
  garbage, AEAD decryption fails.
- Longer CIDs: same failure mode.
This breaks interoperability with any peer using non-8-byte CIDs.

**Severity:** MEDIUM (protocol compliance, not a direct security vulnerability,
but could cause packets to be misinterpreted)

**Fix:** Pass the known local CID length to the unprotection function. The
receiver knows the length of its own CIDs.

---

### M4. HP Key Rotation Swaps Old Keys Without Zeroization

**File:** `/Users/justinadams/Downloads/tquic-kernel/net/tquic/crypto/header_protection.c`
**Lines:** 890-898

```c
/* Rotate read key */
tmp = ctx->read_keys[TQUIC_HP_LEVEL_APPLICATION];
ctx->read_keys[TQUIC_HP_LEVEL_APPLICATION] = ctx->next_read_key;
ctx->next_read_key = tmp;    /* Old key is now "next" -- not zeroized */

/* Rotate write key */
tmp = ctx->write_keys[TQUIC_HP_LEVEL_APPLICATION];
ctx->write_keys[TQUIC_HP_LEVEL_APPLICATION] = ctx->next_write_key;
ctx->next_write_key = tmp;   /* Old key is now "next" -- not zeroized */
```

**Crypto Impact:** After rotation, the old HP keys remain in the `next_read_key`
and `next_write_key` slots. They persist until the next key update overwrites
them. This extends the lifetime of old key material unnecessarily.

**Severity:** MEDIUM

**Fix:** After the swap, zeroize the key bytes in the now-"next" slots (which
hold old keys) using `memzero_explicit()` on the key material fields. The
`tfm` pointer should be freed separately if the old cipher context is no longer
needed.

---

### M5. Token Key Rotation Does Not Zeroize Old Key

**File:** `/Users/justinadams/Downloads/tquic-kernel/net/tquic/tquic_token.c`
**Lines:** 222-233

```c
int tquic_token_rotate_key(struct tquic_token_key *old_key,
                           struct tquic_token_key *new_key)
{
    if (!new_key)
        return -EINVAL;

    get_random_bytes(new_key->key, TQUIC_TOKEN_KEY_LEN);
    new_key->generation = old_key ? old_key->generation + 1 : 1;
    new_key->valid = true;

    return 0;
}
```

**Crypto Impact:** The old key is left intact after rotation. Caller is
presumably responsible for zeroizing it, but the API does not enforce this.
Old token keys allow forging address validation tokens, enabling an attacker
who obtains old key material to bypass address validation.

**Severity:** MEDIUM

**Fix:** Zeroize `old_key->key` with `memzero_explicit()` and set
`old_key->valid = false` inside this function, making the API self-cleaning.

---

### M6. No Token Replay Protection Beyond Timestamp

**File:** `/Users/justinadams/Downloads/tquic-kernel/net/tquic/tquic_token.c`

**Crypto Impact:** The token validation relies on embedded timestamps for
freshness, but there is no mechanism to prevent replay of a valid token within
its validity window. An attacker who captures a Retry token could reuse it from
a different source address within the token's lifetime. RFC 9000 Section 8.1.4
recommends servers maintain some state to detect and prevent such replays.

**Severity:** MEDIUM

**Fix:** Implement a token replay cache (e.g., a bloom filter or hash set of
recently seen token nonces) similar to the 0-RTT anti-replay mechanism already
defined in `zero_rtt.h`.

---

## LOW Severity Findings

### L1. Lock Drop/Re-acquire Pattern in Key Derivation

**File:** `/Users/justinadams/Downloads/tquic-kernel/net/tquic/crypto/key_update.c`
**Lines:** 397-412

```c
staged_cur_write = state->current_write;           /* Copy under lock */
memset(&staged_next, 0, sizeof(staged_next));
spin_unlock_irqrestore(&state->lock, flags);       /* Drop lock */

ret = tquic_ku_derive_next_generation(state,       /* Derive unlocked */
                                      &staged_cur_write,
                                      &staged_next);
memzero_explicit(&staged_cur_write, sizeof(staged_cur_write));
if (ret) {
    memzero_explicit(&staged_next, sizeof(staged_next));
    return ret;
}

spin_lock_irqsave(&state->lock, flags);            /* Re-acquire */

/* Re-check state for concurrent modification */
if (state->update_pending || state->next_write.valid) {
    memzero_explicit(&staged_next, sizeof(staged_next));
    ret = -EINPROGRESS;
    goto out_unlock;
}
```

**Crypto Impact:** This pattern is CORRECT -- it copies data under lock, derives
with copies, then re-checks state before committing. However,
`tquic_ku_derive_next_generation()` still receives `state` as a parameter and
may access `state->hash_tfm` or `state->aead_tfm` without locking. If a
concurrent thread frees these transforms, use-after-free results.

**Severity:** LOW (the pattern is mostly correct, the residual risk is in the
transform access)

**Fix:** Pass `hash_tfm` as a separate parameter copied under the lock, rather
than passing the entire state.

---

### L2. CRYPTO_TFM_REQ_MAY_BACKLOG in Atomic Context

**File:** `/Users/justinadams/Downloads/tquic-kernel/net/tquic/crypto/header_protection.c`
**Lines:** 172-173, 216-217

```c
skcipher_request_set_callback(req, CRYPTO_TFM_REQ_MAY_BACKLOG,
                              crypto_req_done, &wait);
```

**Crypto Impact:** `CRYPTO_TFM_REQ_MAY_BACKLOG` combined with
`crypto_wait_req()` can sleep if the crypto engine is backlogged. If
`tquic_hp_mask_aes()` or `tquic_hp_mask_chacha20()` is called from softirq or
with a spinlock held, this causes a BUG (sleeping in atomic context).

**Severity:** LOW (depends on calling context; the allocation is GFP_ATOMIC
suggesting callers are atomic)

**Fix:** Either (a) ensure callers never hold spinlocks when calling HP mask
generation, or (b) use `CRYPTO_TFM_REQ_MAY_SLEEP` only when in process context
and remove `MAY_BACKLOG` in atomic context, or (c) document the sleeping
requirement clearly.

---

### L3. crypto_wait_req May Sleep in Encrypt/Decrypt Hot Path

**File:** `/Users/justinadams/Downloads/tquic-kernel/net/tquic/crypto/tls.c`
**Lines:** 637, 694

```c
ret = crypto_wait_req(crypto_aead_encrypt(req), &wait);  /* line 637 */
ret = crypto_wait_req(crypto_aead_decrypt(req), &wait);  /* line 694 */
```

**Crypto Impact:** Same as L2 -- `crypto_wait_req` sleeps if the operation is
backlogged. If called from softirq context (packet RX path), this is a bug.

**Severity:** LOW

**Fix:** Ensure the encrypt/decrypt paths are only called from process context
(e.g., in a workqueue), or use async completion callbacks instead of
`crypto_wait_req`.

---

### L4. Multipath Nonce Construction -- Potential Nonce Reuse Across Paths

**File:** `/Users/justinadams/Downloads/tquic-kernel/net/tquic/crypto/tls.c`
**Lines:** 590-592

```c
/* XOR path_id into nonce bytes 4..7 for path separation */
for (i = 0; i < 4; i++)
    nonce[7 - i] ^= (path_id >> (i * 8)) & 0xff;
```

**Crypto Impact:** The nonce is constructed as `IV XOR pkt_num XOR (path_id <<
32)`. If two paths use the same packet number space (which they do in QUIC
multipath -- each path has its own PN space starting from 0), then different
path_ids produce different nonces. This is CORRECT. However, if path_id values
are reused (e.g., path torn down and re-established with the same path_id), and
the PN space resets, nonce reuse occurs with the same key. The code must ensure
path_id is never reused within a key generation.

**Severity:** LOW (depends on path_id allocation policy elsewhere)

**Fix:** Verify that path_id allocation is monotonically increasing per
connection and never reuses IDs within a key phase.

---

## Summary

| Severity | Count | Key Issues |
|----------|-------|------------|
| CRITICAL | 3 | Hardcoded struct offset (C1), shared AEAD handle race (C2), unlocked state access during key install (C3) |
| HIGH | 3 | EKU hash_tfm unlocked access (H1), semantic key/secret mismatch (H2), memset vs memzero_explicit (H3) |
| MEDIUM | 6 | Hot-path allocs (M1, M2), hardcoded CID length (M3), key material retention (M4, M5), no token replay cache (M6) |
| LOW | 4 | Lock pattern residual risk (L1), sleeping in atomic (L2, L3), nonce reuse risk (L4) |

**Total findings: 16**

---

## Positive Observations

1. **key_update.c lines 392-423**: The lock-drop-derive-recheck pattern in
   `tquic_initiate_key_update()` is a good example of correctly handling sleeping
   operations that need spinlock protection. It copies data under lock, derives
   with copies, and re-checks before committing.

2. **tls.c line 645**: `memzero_explicit(nonce, sizeof(nonce))` correctly
   zeroizes the nonce after use in the encrypt path.

3. **quic_crypto.c lines 966-983**: `tquic_crypto_ctx_destroy()` uses
   `memzero_explicit` on the entire context structure -- proper cleanup.

4. **quic_crypto.c lines 1307-1372**: Key update rate limiting (minimum 1-second
   interval) prevents attackers from forcing rapid key rotations to exhaust CPU.

5. **header_protection.c line 183**: `memzero_explicit(ecb_output, ...)` properly
   clears the AES-ECB output after extracting the mask.

6. **hw_offload.c line 703**: Validates `data_buf_len` before each batch
   operation to prevent buffer overflows.

7. **key_update.h**: Clean structure layout with fixed-size arrays (no
   variable-length members), preventing certain classes of overflow.

---

## Recommended Priority for Fixes

1. **Immediate (C1, C2, C3):** These are exploitable or can cause silent
   cryptographic failures. C2 is especially dangerous because the shared AEAD
   handle race can cause packets to be encrypted with the wrong key without
   any error being signaled.

2. **Next sprint (H1, H2, H3):** H2 is a correctness issue that breaks
   interoperability with peers implementing Extended Key Update correctly.
   H3 is a defense-in-depth fix with low effort.

3. **Backlog (M1-M6, L1-L4):** Performance and defense-in-depth improvements.
   M3 (hardcoded CID) should be prioritized if interoperability testing is
   planned.
