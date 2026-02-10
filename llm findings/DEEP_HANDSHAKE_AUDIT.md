# DEEP SECURITY AUDIT: net/tquic/crypto/handshake.c

**File:** `/Users/justinadams/Downloads/tquic-kernel/net/tquic/crypto/handshake.c`
**Lines:** 3373
**Auditor:** Kernel Security Reviewer (Claude Opus 4.6)
**Date:** 2026-02-09

---

## Executive Summary

This file implements the full TLS 1.3 handshake protocol for QUIC in-kernel, including
key schedule, ECDH key exchange, RSA-PSS/ECDSA signature verification, transport
parameter negotiation, and session resumption. It directly processes untrusted data
from network peers. The audit identified **7 Critical**, **9 High**, **8 Medium**, and
**6 Low** severity issues spanning buffer overflows, missing bounds checks, integer
overflows, secret material leaks, and logic errors.

---

## Critical Issues

### CRITICAL-1: Stack buffer overflow in `tquic_hs_build_ch_extensions` -- no bounds checking on output buffer

**File:** `/Users/justinadams/Downloads/tquic-kernel/net/tquic/crypto/handshake.c`
**Lines:** 1076-1253

**Vulnerable code:**
```c
static int tquic_hs_build_ch_extensions(struct tquic_handshake *hs,
                                        u8 *buf, u32 buf_len, u32 *out_len)
{
    u8 *p = buf;
    // ...
    /* Supported Versions extension */
    *p++ = (TLS_EXT_SUPPORTED_VERSIONS >> 8) & 0xff;
    *p++ = TLS_EXT_SUPPORTED_VERSIONS & 0xff;
    // ... ~170 bytes of direct writes ...
    memcpy(p, hs->key_share.public_key, 32);
    p += 32;
    // ... ALPN, SNI, transport params, PSK identities ...
```

**Description:** The function accepts `buf_len` but **never checks it**. The pointer `p`
is advanced with `*p++` and `memcpy()` calls throughout the entire function without a
single bounds check against `buf + buf_len`. The caller in `tquic_hs_generate_client_hello`
passes a 2048-byte buffer (`extensions = kzalloc(2048, GFP_KERNEL)`), but the actual
written size depends on attacker-influenced data: ALPN strings, SNI hostname, transport
parameters (up to 1024 bytes from a stack buffer), and PSK identities (whose
`identity_len` is user-controlled). A long SNI + many ALPN entries + large PSK identity
data can exceed 2048 bytes.

**Exploitation scenario:** A local user calls `tquic_hs_set_alpn()` with many long
protocol names and `tquic_hs_set_sni()` with a 255-byte hostname, then `tquic_hs_setup_psk()`
with a ticket containing a large identity. When `tquic_hs_generate_client_hello()` is
called, the extensions buffer overflows, corrupting heap memory (heap buffer overflow).

**Impact:** Heap corruption leading to arbitrary kernel code execution.

**Severity:** CRITICAL

**Recommendation:** Add bounds checking throughout `tquic_hs_build_ch_extensions`. Every
write to `p` must verify `p + N <= buf + buf_len` before writing. Use a macro similar to
`TP_CHECK_SPACE` from the transport params encoder.

---

### CRITICAL-2: Stack buffer overflow in `tquic_hs_hkdf_expand_label` -- unbounded label/context write to 512-byte stack buffer

**File:** `/Users/justinadams/Downloads/tquic-kernel/net/tquic/crypto/handshake.c`
**Lines:** 735-809

**Vulnerable code:**
```c
static int tquic_hs_hkdf_expand_label(struct tquic_handshake *hs,
                                      const u8 *secret, u32 secret_len,
                                      const char *label,
                                      const u8 *context, u32 context_len,
                                      u8 *out, u32 out_len)
{
    u8 hkdf_label[512];     // <-- stack buffer
    u8 *p = hkdf_label;
    u32 label_len = strlen(label);
    u32 total_label_len = 6 + label_len;
    // ...
    *p++ = (out_len >> 8) & 0xff;
    *p++ = out_len & 0xff;
    *p++ = total_label_len;
    memcpy(p, "tls13 ", 6);
    p += 6;
    memcpy(p, label, label_len);
    p += label_len;
    *p++ = context_len;        // <-- truncated to u8
    if (context_len > 0) {
        memcpy(p, context, context_len);   // <-- no bounds check
        p += context_len;
    }
```

**Description:** The `hkdf_label` stack buffer is 512 bytes. `context_len` is a `u32`
parameter. If `context_len` exceeds approximately 500 bytes, the `memcpy` at line 762
writes past the end of the stack buffer. Additionally, `context_len` is written as a
single byte (`*p++ = context_len`), which truncates values > 255, creating a mismatch
between the written length and the actual copied data.

While current internal callers pass small contexts (transcript hashes up to 48 bytes),
this is a library function and future callers or modified transcript handling could
trigger this. The function interface accepts arbitrary `u32` context_len with no
validation.

**Impact:** Stack buffer overflow, kernel stack smashing, potential RCE.

**Severity:** CRITICAL

**Recommendation:**
```c
/* Validate that hkdf_label fits in the stack buffer */
if (3 + 6 + label_len + 1 + context_len > sizeof(hkdf_label))
    return -EINVAL;
if (context_len > 255)
    return -EINVAL;  /* TLS context is at most 255 bytes */
```

---

### CRITICAL-3: No bounds checking on `buf` output in `tquic_hs_generate_client_hello`

**File:** `/Users/justinadams/Downloads/tquic-kernel/net/tquic/crypto/handshake.c`
**Lines:** 1258-1380

**Vulnerable code:**
```c
int tquic_hs_generate_client_hello(struct tquic_handshake *hs,
                                   u8 *buf, u32 buf_len, u32 *out_len)
{
    u8 *p = buf;
    // ...
    /* Handshake header */
    *p++ = TLS_HS_CLIENT_HELLO;
    msg_len_ptr = p;
    p += 3;
    *p++ = (TLS_LEGACY_VERSION >> 8) & 0xff;
    *p++ = TLS_LEGACY_VERSION & 0xff;
    memcpy(p, hs->client_random, TLS_RANDOM_LEN);  // 32 bytes
    p += TLS_RANDOM_LEN;
    // ... session ID (up to 32 bytes) ...
    // ... cipher suites (8 bytes) ...
    // ... compression (2 bytes) ...
    memcpy(p, extensions, ext_len);  // up to 2048 bytes
    p += ext_len;
```

**Description:** The function writes into `buf` without ever checking `buf_len`. The
minimum output is approximately 4 + 2 + 32 + 1 + 32 + 2 + 6 + 2 = 81 bytes plus
extensions. If the caller provides a small buffer, this overflows. This is an exported
symbol (`EXPORT_SYMBOL_GPL`) so any kernel module can call it with an arbitrary buffer.

**Impact:** Heap or stack buffer overflow depending on caller's buffer allocation.

**Severity:** CRITICAL

**Recommendation:** Check `buf_len` before each write block, or compute the total
required size first and validate it fits.

---

### CRITICAL-4: Integer overflow in `tquic_hs_build_ch_extensions` PSK identity length calculations

**File:** `/Users/justinadams/Downloads/tquic-kernel/net/tquic/crypto/handshake.c`
**Lines:** 1206-1244

**Vulnerable code:**
```c
if (hs->psk_count > 0) {
    u32 identities_len = 0;
    u32 binders_len = 0;
    u32 i;

    for (i = 0; i < hs->psk_count; i++) {
        identities_len += 2 + hs->psk_identities[i].identity_len + 4;
        binders_len += 1 + hs->hash_len;
    }

    *p++ = (TLS_EXT_PRE_SHARED_KEY >> 8) & 0xff;
    *p++ = TLS_EXT_PRE_SHARED_KEY & 0xff;
    *p++ = ((identities_len + binders_len + 4) >> 8) & 0xff;
    *p++ = (identities_len + binders_len + 4) & 0xff;
```

**Description:** `identities_len` accumulates `identity_len` values from each PSK
identity. The field `identity_len` is `u32`. With enough PSK identities or large
identity lengths, `identities_len` can overflow the `u32`, wrapping to a small value.
This small value is then used to write the extension length header, but the actual
data written (in the loop at lines 1224-1234) uses the real `identity_len` values.
This creates a mismatch between the declared extension length and the actual data
written, leading to buffer overwrite.

Additionally, `identities_len + binders_len + 4` is written into a 2-byte field
(lines 1217-1218), truncating values > 65535.

**Impact:** Buffer overflow from length mismatch, malformed TLS messages.

**Severity:** CRITICAL

**Recommendation:** Check for u32 overflow in the accumulation loop. Validate that
the total extension length fits in a u16.

---

### CRITICAL-5: `tquic_hs_process_certificate` -- integer underflow in `certs_len` tracking

**File:** `/Users/justinadams/Downloads/tquic-kernel/net/tquic/crypto/handshake.c`
**Lines:** 1769-1807

**Vulnerable code:**
```c
while (p < data + 4 + msg_len && certs_len > 0) {
    u32 cert_len;
    u16 ext_len;

    if (p + 3 > end)
        break;

    cert_len = (p[0] << 16) | (p[1] << 8) | p[2];
    p += 3;
    certs_len -= 3;              // <-- can underflow if certs_len < 3

    if (p + cert_len > end || cert_len > certs_len)
        return -EINVAL;
    // ...
    p += cert_len;
    certs_len -= cert_len;

    /* Certificate extensions */
    if (p + 2 > end)
        break;
    ext_len = (p[0] << 8) | p[1];
    p += 2;
    certs_len -= 2;              // <-- can underflow if certs_len < 2

    if (ext_len > certs_len)
        return -EINVAL;

    p += ext_len;
    certs_len -= ext_len;
}
```

**Description:** `certs_len` is a `u32`. The subtraction `certs_len -= 3` at line 1778
is performed **before** the check `cert_len > certs_len` at line 1780. If `certs_len`
is 1 or 2 at the loop entry, the subtraction wraps to a very large value (near
UINT32_MAX). The subsequent `cert_len > certs_len` check then passes for almost any
`cert_len`, leading to out-of-bounds reads. Similarly, `certs_len -= 2` at line 1800
can underflow.

**Exploitation scenario:** A malicious server sends a Certificate message with
`certs_len = 2`, causing the first `certs_len -= 3` to underflow. The attacker then
controls `cert_len` and `ext_len` parsing from beyond the message boundary.

**Impact:** Out-of-bounds read from attacker-controlled packet data, potential
information leak or crash.

**Severity:** CRITICAL

**Recommendation:** Check `certs_len >= 3` before `certs_len -= 3`, and
`certs_len >= 2` before `certs_len -= 2`. Alternatively, track position using
pointer arithmetic against `end` only.

---

### CRITICAL-6: `tquic_hs_process_new_session_ticket` -- nonce overflow into session ticket

**File:** `/Users/justinadams/Downloads/tquic-kernel/net/tquic/crypto/handshake.c`
**Lines:** 2583-2597

**Vulnerable code:**
```c
/* Ticket nonce */
nonce_len = *p++;
if (p + nonce_len > end)
    return -EINVAL;

/* ... allocate session_ticket ... */

hs->session_ticket->nonce_len = nonce_len;
memcpy(hs->session_ticket->nonce, p, nonce_len);
```

**Header definition (`handshake.h` line 76-77):**
```c
struct tquic_session_ticket {
    // ...
    u8 nonce[255];
    u8 nonce_len;
    // ...
};
```

**Description:** `nonce_len` is a `u8` (max 255), and the `nonce` buffer is 255 bytes,
so this specific copy is safe. However, `nonce_len` is read directly from untrusted
network data and the check only validates it against `end`. The RFC mandates that
the nonce MUST be at most 255 bytes but some implementations might send more in a
non-conformant way. The real issue is that the allocated `nonce[255]` exactly matches
the max u8 value -- if the struct ever changes to a smaller buffer, this becomes
an overflow without any additional validation.

While this specific case is technically safe due to type constraints, there is a
more serious issue below.

**Severity:** LOW (type-safe by coincidence)

---

### CRITICAL-6 (actual): `tquic_hs_process_server_hello` -- missing check before cipher suite read

**File:** `/Users/justinadams/Downloads/tquic-kernel/net/tquic/crypto/handshake.c`
**Lines:** 1457-1459

**Vulnerable code:**
```c
    p += session_id_len;

    /* Cipher suite */
    cipher_suite = (p[0] << 8) | p[1];
    p += 2;
```

**Description:** After advancing past the session ID, there is no check that
`p + 2 <= end` before reading the cipher suite. If the message is truncated right
after the session ID, this reads 2 bytes past the buffer.

**Impact:** Out-of-bounds read of 1-2 bytes. In kernel context, this reads from
adjacent slab memory, potentially leaking sensitive data.

**Severity:** CRITICAL

**Recommendation:** Add `if (p + 2 > end) return -EINVAL;` before the cipher suite read.

---

### CRITICAL-7: `tquic_hs_process_server_hello` -- missing bounds check before compression byte read

**File:** `/Users/justinadams/Downloads/tquic-kernel/net/tquic/crypto/handshake.c`
**Lines:** 1477-1481

**Vulnerable code:**
```c
    /* Compression (must be null) */
    compression = *p++;
    if (compression != 0) {
```

**Description:** No check that `p < end` before dereferencing `*p++`. If the message
is truncated after the cipher suite, this reads one byte out of bounds.

**Impact:** Out-of-bounds read.

**Severity:** CRITICAL (combined with CRITICAL-6 actual, both are in the same parsing path)

**Recommendation:** Add `if (p >= end) return -EINVAL;` before reading compression.

---

## High Severity Issues

### HIGH-1: `tquic_hs_hkdf_expand_label` -- `context_len` truncated to u8

**File:** `/Users/justinadams/Downloads/tquic-kernel/net/tquic/crypto/handshake.c`
**Line:** 760

**Vulnerable code:**
```c
    *p++ = context_len;     // context_len is u32, written as u8
```

**Description:** The HKDF label encodes the context length as a single byte per the TLS
spec (HkdfLabel.context is limited to 255 bytes). But the function parameter is `u32`.
If `context_len > 255`, the written byte is truncated, but `memcpy` at line 762 still
copies the full `context_len` bytes. This means the HKDF label header says the context
is (context_len % 256) bytes, but the actual data is context_len bytes.

This creates a cryptographically incorrect HKDF derivation -- the label structure is
malformed. An attacker who can influence the context data could use this to cause
key derivation errors or potentially create collisions.

**Impact:** Cryptographic weakness, potentially exploitable for key manipulation.

**Severity:** HIGH

**Recommendation:**
```c
if (context_len > 255)
    return -EINVAL;
```

---

### HIGH-2: `tquic_hs_generate_client_hello` -- output buffer `buf` not validated for minimum size

**File:** `/Users/justinadams/Downloads/tquic-kernel/net/tquic/crypto/handshake.c`
**Lines:** 1319-1357

**Description:** Even the fixed-size header portions (handshake type, version, random,
session ID, cipher suites, compression) require at least ~81 bytes. The function never
validates that `buf_len >= 81` (or any minimum). A caller passing `buf_len = 0` causes
immediate out-of-bounds write at line 1320 (`*p++ = TLS_HS_CLIENT_HELLO`).

**Severity:** HIGH

**Recommendation:** Validate `buf_len` against the minimum required size at function entry.

---

### HIGH-3: `tquic_hs_process_server_hello` -- session ID comparison not fully bounds-safe

**File:** `/Users/justinadams/Downloads/tquic-kernel/net/tquic/crypto/handshake.c`
**Lines:** 1443-1455

**Vulnerable code:**
```c
    session_id_len = *p++;
    if (session_id_len > TLS_SESSION_ID_MAX_LEN)
        return -EINVAL;
    if (p + session_id_len > end)
        return -EINVAL;
```

**Description:** Before reading `session_id_len` at `*p++`, there is no check that
`p < end`. The earlier check `p + TLS_RANDOM_LEN > end` at line 1423 ensures p is
valid through the random bytes, but after advancing p by TLS_RANDOM_LEN (line 1426),
if the message is exactly `4 + 2 + 32` bytes, `p` points to `end` and the `*p++`
read is out of bounds.

**Impact:** One-byte out-of-bounds read.

**Severity:** HIGH

**Recommendation:** Add `if (p >= end) return -EINVAL;` before `session_id_len = *p++;`.

---

### HIGH-4: Secrets not zeroized on error paths in key derivation functions

**File:** `/Users/justinadams/Downloads/tquic-kernel/net/tquic/crypto/handshake.c`
**Lines:** 935-990 (`tquic_hs_derive_handshake_secrets`)

**Vulnerable code:**
```c
static int tquic_hs_derive_handshake_secrets(struct tquic_handshake *hs)
{
    u8 derived[TLS_SECRET_MAX_LEN];
    u8 transcript_hash[TLS_SECRET_MAX_LEN];
    // ...
    ret = tquic_hs_derive_secret(hs, hs->early_secret, "derived",
                                 NULL, 0, derived, hash_len);
    if (ret)
        return ret;        // <-- derived[] left on stack with secret data
    // ...
}
```

**Description:** Stack-local secret buffers `derived[]` and `transcript_hash[]` are not
zeroized on error paths. When the function returns early due to an error, these secrets
remain on the kernel stack and could be leaked via stack reuse or information disclosure
vulnerabilities.

This pattern repeats in:
- `tquic_hs_derive_app_secrets` (lines 995-1045)
- `tquic_hs_derive_resumption_secret` (lines 1050-1071)
- `tquic_hs_derive_early_secrets` (lines 895-930)
- `tquic_hs_process_finished` (lines 2379-2462) -- `verify_data[]`, `transcript_hash[]`
- `tquic_hs_generate_finished` (lines 2467-2536) -- `verify_data[]`, `transcript_hash[]`

**Impact:** Kernel secret material persists on stack after error, potential information leak.

**Severity:** HIGH

**Recommendation:** Use `goto out_zeroize` pattern with `memzero_explicit()` on all
local secret buffers before returning, even on error paths.

---

### HIGH-5: `tquic_hs_setup_psk` -- integer overflow in ticket age calculation

**File:** `/Users/justinadams/Downloads/tquic-kernel/net/tquic/crypto/handshake.c`
**Lines:** 2688-2691

**Vulnerable code:**
```c
    age = (now - ticket->creation_time) * 1000;  /* Convert to ms */
    obfuscated_age = age + ticket->age_add;
    psk->obfuscated_ticket_age = obfuscated_age;
```

**Description:** `age` is `u32`. `now - ticket->creation_time` is a `u64` subtraction
but `age` is `u32`, so the result is truncated. Then `age * 1000` can overflow a `u32`
if the ticket is more than about 4.3 million seconds old (approx 50 days). This is
within the max ticket lifetime of 7 days (604800 seconds), where 604800 * 1000 =
604800000 which fits in u32. However, if `ticket->lifetime` validation is bypassed
or the ticket is from a misbehaving server with a very long lifetime, this overflows.

The `obfuscated_age = age + ticket->age_add` can also overflow, but that is expected
per the RFC (the addition is modular).

**Impact:** Incorrect ticket age sent to server, potentially causing ticket rejection
or replay issues.

**Severity:** HIGH

**Recommendation:** Use `u64` for `age` and validate the time difference before
multiplication. Also validate `lifetime` against RFC 8446 maximum of 604800 (7 days).

---

### HIGH-6: `tquic_hs_build_ch_extensions` -- ALPN extension length written as 2-byte but can overflow u16

**File:** `/Users/justinadams/Downloads/tquic-kernel/net/tquic/crypto/handshake.c`
**Lines:** 1144-1163

**Vulnerable code:**
```c
    if (hs->alpn_count > 0) {
        u32 alpn_total_len = 0;

        for (i = 0; i < hs->alpn_count; i++)
            alpn_total_len += 1 + strlen(hs->alpn_list[i]);

        *p++ = ((alpn_total_len + 2) >> 8) & 0xff;
        *p++ = (alpn_total_len + 2) & 0xff;
```

**Description:** `alpn_total_len` is `u32` but is written into 2-byte extension length
fields. If many ALPN protocols are registered (e.g., > 256 protocols of 255 bytes each),
`alpn_total_len + 2` exceeds 65535 and is silently truncated. The actual data written
below uses the full count, creating a length mismatch.

No validation exists on `hs->alpn_count` in `tquic_hs_set_alpn` -- any number of
protocols can be set.

**Impact:** Malformed TLS message, potential buffer overflow from length mismatch.

**Severity:** HIGH

**Recommendation:** Validate ALPN total length fits in u16 in `tquic_hs_set_alpn()`.
Add a reasonable cap on `alpn_count`.

---

### HIGH-7: `tquic_hs_process_encrypted_extensions` -- ALPN validation insufficient

**File:** `/Users/justinadams/Downloads/tquic-kernel/net/tquic/crypto/handshake.c`
**Lines:** 1671-1684

**Vulnerable code:**
```c
    case TLS_EXT_ALPN:
        if (ext_data_len >= 3) {
            u16 list_len = (p[0] << 8) | p[1];
            u8 proto_len = p[2];

            if (list_len >= proto_len + 1 && proto_len > 0) {
                kfree(hs->alpn_selected);
                hs->alpn_selected = kmalloc(proto_len + 1, GFP_KERNEL);
                if (hs->alpn_selected) {
                    memcpy(hs->alpn_selected, p + 3, proto_len);
```

**Description:** The check `list_len >= proto_len + 1` validates that `proto_len`
fits within `list_len`, but does not validate that `3 + proto_len <= ext_data_len`.
If `ext_data_len` is exactly 3, `proto_len` could be non-zero, and `memcpy(p + 3, proto_len)`
reads past `p + ext_data_len`. Additionally, `list_len` is not validated against
`ext_data_len - 2` (where the 2 bytes are for the list length field itself).

**Impact:** Out-of-bounds read from attacker-controlled ServerHello.

**Severity:** HIGH

**Recommendation:**
```c
if (ext_data_len >= 3 && proto_len > 0 && 3 + proto_len <= ext_data_len) {
```

---

### HIGH-8: `tquic_hs_cleanup` -- potential double-free of session ticket

**File:** `/Users/justinadams/Downloads/tquic-kernel/net/tquic/crypto/handshake.c`
**Lines:** 3284-3287 and 2701-2702

**Vulnerable code in cleanup:**
```c
    if (hs->session_ticket) {
        kfree(hs->session_ticket->ticket);
        kfree(hs->session_ticket);
    }
```

**Vulnerable code in `tquic_hs_setup_psk`:**
```c
    /* Store session ticket for early data */
    hs->session_ticket = ticket;
```

**Description:** `tquic_hs_setup_psk()` stores a **borrowed pointer** to the caller's
`ticket` in `hs->session_ticket`. When `tquic_hs_cleanup()` runs, it frees
`hs->session_ticket->ticket` and `hs->session_ticket`. If the caller also frees the
same ticket structure, this is a double-free. Conversely, if the caller expects the
handshake to take ownership, this is correct -- but the API is ambiguous and error-prone.

**Impact:** Double-free leading to use-after-free, heap corruption.

**Severity:** HIGH

**Recommendation:** Either document clearly that `tquic_hs_setup_psk` takes ownership
(and the caller must not free), or make `tquic_hs_setup_psk` copy the ticket data.

---

### HIGH-9: `tquic_hs_process_new_session_ticket` -- memory leak of old ticket data on re-entry

**File:** `/Users/justinadams/Downloads/tquic-kernel/net/tquic/crypto/handshake.c`
**Lines:** 2588-2612

**Vulnerable code:**
```c
    if (!hs->session_ticket) {
        hs->session_ticket = kzalloc(sizeof(*hs->session_ticket), GFP_KERNEL);
        if (!hs->session_ticket)
            return -ENOMEM;
    }
    // ... writes to hs->session_ticket fields ...

    kfree(hs->session_ticket->ticket);
    hs->session_ticket->ticket = kmalloc(ticket_len, GFP_KERNEL);
```

**Description:** If a second NewSessionTicket arrives, the function reuses the existing
`hs->session_ticket` but does not free the old nonce data or reset other fields. The
`kfree(hs->session_ticket->ticket)` on line 2609 handles the ticket data, but if the
first call failed after allocating the session_ticket but before setting ticket (e.g.,
`kmalloc` for ticket fails at line 2610), and then a second NewSessionTicket arrives,
the session ticket structure may contain stale state.

More importantly, if `tquic_hs_setup_psk` was called first (setting `hs->session_ticket`
to a borrowed pointer), and then a NewSessionTicket arrives, the `kfree()` on line 2609
frees memory that was not allocated by this code path.

**Impact:** Memory corruption from freeing a borrowed pointer.

**Severity:** HIGH

**Recommendation:** Track whether `hs->session_ticket` is owned or borrowed. Only free
owned tickets.

---

## Medium Severity Issues

### MEDIUM-1: `tquic_hs_generate_client_hello` -- `hkdf_label` stack buffer on sensitive crypto path

**File:** `/Users/justinadams/Downloads/tquic-kernel/net/tquic/crypto/handshake.c`
**Line:** 741

**Description:** The 512-byte `hkdf_label` stack buffer in `tquic_hs_hkdf_expand_label`
is not zeroed after use. It contains the HKDF label structure which includes the context
(transcript hash). While not directly a secret, it can assist an attacker in reconstructing
the key derivation inputs.

**Severity:** MEDIUM

**Recommendation:** Add `memzero_explicit(hkdf_label, sizeof(hkdf_label));` before return.

---

### MEDIUM-2: `hs_varint_encode` -- no bounds check on output buffer

**File:** `/Users/justinadams/Downloads/tquic-kernel/net/tquic/crypto/handshake.c`
**Lines:** 292-319

**Vulnerable code:**
```c
static int hs_varint_encode(u64 val, u8 *buf, u32 *len)
{
    if (val < 0x40) {
        buf[0] = val;
        *len = 1;
    } else if (val < 0x4000) {
        buf[0] = 0x40 | (val >> 8);
        buf[1] = val & 0xff;
```

**Description:** The function writes up to 8 bytes to `buf` but does not know or check
the buffer size. All callers use `u8 varint[8]` which is exactly the maximum, so this
is safe in current usage. But the function interface is unsafe by design.

**Severity:** MEDIUM (safe by convention, not by contract)

**Recommendation:** Add a `u32 buf_len` parameter or document the 8-byte minimum requirement.

---

### MEDIUM-3: `tquic_hs_process_server_hello` -- extension parsing loop bound mismatch

**File:** `/Users/justinadams/Downloads/tquic-kernel/net/tquic/crypto/handshake.c`
**Lines:** 1493

**Vulnerable code:**
```c
    while (p < data + 4 + msg_len) {
```

**Description:** The extension parsing loop uses `data + 4 + msg_len` as the bound, but
the extensions start at a specific offset within the message and have their own length
(`ext_len` at line 1486). The loop should be bounded by `p < ext_start + ext_len` where
ext_start is the position after the ext_len field. Using `msg_len` as the bound could
allow the loop to read past the declared extension block into subsequent data if
`ext_len` is less than the remaining message bytes.

The same pattern appears in `tquic_hs_process_encrypted_extensions` at line 1655.

**Severity:** MEDIUM

**Recommendation:** Use `const u8 *ext_end = p + ext_len;` and loop `while (p < ext_end)`.

---

### MEDIUM-4: `tquic_hs_process_certificate` -- unbounded certificate allocation

**File:** `/Users/justinadams/Downloads/tquic-kernel/net/tquic/crypto/handshake.c`
**Lines:** 1784-1789

**Vulnerable code:**
```c
    if (!hs->peer_cert && cert_len > 0) {
        hs->peer_cert = kmalloc(cert_len, GFP_KERNEL);
        if (!hs->peer_cert)
            return -ENOMEM;
        memcpy(hs->peer_cert, p, cert_len);
        hs->peer_cert_len = cert_len;
    }
```

**Description:** `cert_len` comes from network data and can be up to 16777215 (24-bit
field). The `TLS_CERT_MAX_LEN` constant (16384) is defined but never checked before
this allocation. A malicious server can force the client to allocate up to 16 MB for a
single certificate.

**Impact:** Remote denial of service via memory exhaustion.

**Severity:** MEDIUM

**Recommendation:**
```c
if (cert_len > TLS_CERT_MAX_LEN)
    return -EINVAL;
```

---

### MEDIUM-5: `tquic_hs_process_new_session_ticket` -- `ticket_len` is u16, can be up to 65535

**File:** `/Users/justinadams/Downloads/tquic-kernel/net/tquic/crypto/handshake.c`
**Lines:** 2601-2612

**Description:** `ticket_len` is parsed as a `u16` (max 65535 bytes). The function
allocates and copies this amount. While 65535 is not extremely large, TLS 1.3 RFC 8446
states that tickets are typically small. There is no upper bound validation. A malicious
server can repeatedly send NewSessionTicket messages with 64KB tickets, consuming memory.

**Severity:** MEDIUM

**Recommendation:** Add a reasonable upper limit (e.g., 8192 bytes) for ticket length.

---

### MEDIUM-6: `tquic_hs_derive_early_secrets` -- `memzero_explicit` called before error check

**File:** `/Users/justinadams/Downloads/tquic-kernel/net/tquic/crypto/handshake.c`
**Lines:** 923-927

**Vulnerable code:**
```c
        ret = tquic_hs_derive_secret(hs, hs->early_secret,
                                     "ext binder", NULL, 0,
                                     binder_key, hash_len);
        memzero_explicit(binder_key, sizeof(binder_key));
        if (ret)
            return ret;
```

**Description:** `memzero_explicit` is called before checking `ret`. This means if
`tquic_hs_derive_secret` succeeds, the binder key is immediately zeroed and cannot be
used. This is likely a bug where the intent was to zero on cleanup, but the order is
wrong.

**Impact:** Incorrect binder key derivation (always zeroed), PSK authentication failure.

**Severity:** MEDIUM (functional bug with security implications)

**Recommendation:** Move `memzero_explicit` after the binder key is no longer needed,
or into an error/cleanup path.

---

### MEDIUM-7: `tquic_hs_process_certificate_verify` -- `content[200]` stack buffer could overflow with large hash

**File:** `/Users/justinadams/Downloads/tquic-kernel/net/tquic/crypto/handshake.c`
**Lines:** 2180-2220

**Vulnerable code:**
```c
    u8 content[200];
    u8 *cp = content;
    // ...
    memset(cp, 0x20, 64);   // 64 bytes
    cp += 64;
    memcpy(cp, "TLS 1.3, server CertificateVerify", 33);  // 33 bytes
    cp += 33;
    *cp++ = 0x00;            // 1 byte = 98 total
    memcpy(cp, transcript_hash, hash_len);  // hash_len up to 48
    cp += hash_len;          // max = 98 + 48 = 146 bytes
```

**Description:** The maximum content is 64 + 33 + 1 + 48 (SHA-384) = 146 bytes, which
fits in 200 bytes. However, if a future cipher suite with a 64-byte hash (SHA-512) is
added to the key schedule, `hash_len` could be 64, making the total 162 -- still safe.
But the margin is only 38 bytes. If the context string changes or additional data is
added, this could overflow.

**Severity:** MEDIUM (safe now, fragile)

**Recommendation:** Compute the required size dynamically: `content_size = 64 + 33 + 1 + hash_len`
and validate it fits, or allocate dynamically.

---

### MEDIUM-8: `tquic_hs_process_server_hello` -- `static const` inside function body

**File:** `/Users/justinadams/Downloads/tquic-kernel/net/tquic/crypto/handshake.c`
**Lines:** 1430-1435

**Vulnerable code:**
```c
    static const u8 hrr_random[32] = {
        0xcf, 0x21, 0xad, 0x74, ...
    };
```

**Description:** A `static const` variable is declared inside a block scope within the
function. In C, this is valid but unusual in kernel code and can confuse code analysis
tools. Some versions of GCC/Clang may not warn about this, but it creates a data
section variable from within function scope.

This is a code quality issue rather than a security bug, but it could mask issues in
static analysis.

**Severity:** MEDIUM (code quality)

**Recommendation:** Move to file scope alongside the other static const arrays (like
`tls12_downgrade_sentinel`).

---

## Low Severity Issues

### LOW-1: `tquic_hs_cleanup` -- does not zeroize exporter_secret and resumption_secret

**File:** `/Users/justinadams/Downloads/tquic-kernel/net/tquic/crypto/handshake.c`
**Lines:** 3304-3314

**Vulnerable code:**
```c
    memzero_explicit(hs->early_secret, sizeof(hs->early_secret));
    memzero_explicit(hs->handshake_secret, sizeof(hs->handshake_secret));
    memzero_explicit(hs->master_secret, sizeof(hs->master_secret));
    // ... other secrets ...
    memzero_explicit(hs->shared_secret, sizeof(hs->shared_secret));
```

**Description:** The cleanup function zeroizes most secrets but misses:
- `hs->exporter_secret`
- `hs->resumption_secret`
- `hs->client_random`
- `hs->server_random`

**Severity:** LOW

**Recommendation:** Add `memzero_explicit` calls for all remaining sensitive fields.

---

### LOW-2: `tquic_hs_get_handshake_secrets` and `tquic_hs_get_app_secrets` -- no output buffer size validation

**File:** `/Users/justinadams/Downloads/tquic-kernel/net/tquic/crypto/handshake.c`
**Lines:** 3086-3131

**Description:** These functions copy `hs->hash_len` bytes (up to 48) into caller-provided
buffers but do not verify the buffers are large enough. The caller must ensure at least
`TLS_SECRET_MAX_LEN` (48) bytes are available.

**Severity:** LOW (kernel-internal API, callers are trusted)

**Recommendation:** Document the minimum buffer size requirement or add a `buf_len` parameter.

---

### LOW-3: `tquic_hs_set_alpn` -- missing `hs->alpn_count = 0` on cleanup

**File:** `/Users/justinadams/Downloads/tquic-kernel/net/tquic/crypto/handshake.c`
**Lines:** 2958-2962

**Vulnerable code:**
```c
    if (hs->alpn_list) {
        for (i = 0; i < hs->alpn_count; i++)
            kfree(hs->alpn_list[i]);
        kfree(hs->alpn_list);
    }
```

**Description:** When replacing the ALPN list, the old list is freed but `hs->alpn_count`
is not set to 0 before the new allocation. If the `kcalloc` on line 2964 fails, the
function returns `-ENOMEM` with `hs->alpn_list = NULL` but `hs->alpn_count` still has
the old value. A subsequent call to cleanup or extension building would iterate over
the stale count with a NULL list pointer.

**Severity:** LOW

**Recommendation:** Set `hs->alpn_count = 0` after freeing the old list.

---

### LOW-4: `tquic_hs_generate_client_hello` -- client random not checked for all-zero

**File:** `/Users/justinadams/Downloads/tquic-kernel/net/tquic/crypto/handshake.c`
**Line:** 1273

**Description:** `get_random_bytes()` in the kernel is reliable, but defense-in-depth
would suggest verifying the random is not all zeros (which would indicate a catastrophic
RNG failure).

**Severity:** LOW

---

### LOW-5: `tquic_hs_process_certificate_verify` hardcodes "server CertificateVerify" string

**File:** `/Users/justinadams/Downloads/tquic-kernel/net/tquic/crypto/handshake.c`
**Line:** 2203

**Description:** The context string is hardcoded as `"TLS 1.3, server CertificateVerify"`.
If this function is ever used on the server side to verify a client's CertificateVerify,
the string should be `"TLS 1.3, client CertificateVerify"`. The current code does not
check `hs->is_server` to select the correct string.

**Impact:** If used for client cert verification (not currently implemented), signature
verification would always fail, causing a denial of service against client authentication.

**Severity:** LOW (currently safe, future bug)

**Recommendation:** Use `hs->is_server ? "TLS 1.3, client CertificateVerify" : "TLS 1.3, server CertificateVerify"`.

---

### LOW-6: `tquic_hs_process_new_session_ticket` -- ignores extensions

**File:** `/Users/justinadams/Downloads/tquic-kernel/net/tquic/crypto/handshake.c`
**Lines:** 2624-2625

**Vulnerable code:**
```c
    /* Parse extensions (early_data max size, etc.) */
    /* Skip for now */
```

**Description:** The `early_data` extension in NewSessionTicket specifies the maximum
amount of 0-RTT data the server will accept. By ignoring this, the client may attempt
to send more 0-RTT data than the server allows, causing connection failures.

**Severity:** LOW (functional completeness issue)

---

## Summary Table

| ID | Severity | Category | Location | Description |
|----|----------|----------|----------|-------------|
| CRITICAL-1 | CRITICAL | Buffer overflow | Lines 1076-1253 | No bounds checking in extension builder |
| CRITICAL-2 | CRITICAL | Stack overflow | Lines 735-809 | Unbounded context write to 512-byte stack buffer |
| CRITICAL-3 | CRITICAL | Buffer overflow | Lines 1258-1380 | No buf_len validation in ClientHello generation |
| CRITICAL-4 | CRITICAL | Integer overflow | Lines 1206-1244 | PSK identity length overflow in u32/u16 |
| CRITICAL-5 | CRITICAL | Integer underflow | Lines 1769-1807 | certs_len underflow in certificate parsing |
| CRITICAL-6 | CRITICAL | OOB read | Lines 1457-1459 | Missing bounds check before cipher suite read |
| CRITICAL-7 | CRITICAL | OOB read | Lines 1477-1481 | Missing bounds check before compression read |
| HIGH-1 | HIGH | Crypto | Line 760 | context_len truncated to u8 in HKDF label |
| HIGH-2 | HIGH | Buffer overflow | Lines 1319-1357 | No minimum buf_len check in ClientHello |
| HIGH-3 | HIGH | OOB read | Lines 1443-1455 | Missing check before session_id_len read |
| HIGH-4 | HIGH | Info leak | Lines 935-990+ | Secrets not zeroized on error paths |
| HIGH-5 | HIGH | Integer overflow | Lines 2688-2691 | Ticket age overflow in u32 arithmetic |
| HIGH-6 | HIGH | Integer overflow | Lines 1144-1163 | ALPN extension length overflow |
| HIGH-7 | HIGH | OOB read | Lines 1671-1684 | ALPN validation insufficient in EncryptedExtensions |
| HIGH-8 | HIGH | Double-free | Lines 2701, 3284 | Ambiguous session ticket ownership |
| HIGH-9 | HIGH | Memory corruption | Lines 2588-2612 | Freeing borrowed session ticket pointer |
| MEDIUM-1 | MEDIUM | Info leak | Line 741 | HKDF label not zeroed after use |
| MEDIUM-2 | MEDIUM | API safety | Lines 292-319 | varint_encode has no buffer size param |
| MEDIUM-3 | MEDIUM | Logic | Lines 1493, 1655 | Extension parsing loop bound mismatch |
| MEDIUM-4 | MEDIUM | DoS | Lines 1784-1789 | Unbounded certificate allocation |
| MEDIUM-5 | MEDIUM | DoS | Lines 2601-2612 | No upper limit on ticket length |
| MEDIUM-6 | MEDIUM | Logic bug | Lines 923-927 | memzero_explicit before error check |
| MEDIUM-7 | MEDIUM | Fragile | Lines 2180-2220 | Stack buffer margin thin for content |
| MEDIUM-8 | MEDIUM | Code quality | Lines 1430-1435 | static const in function body |
| LOW-1 | LOW | Info leak | Lines 3304-3314 | Missing zeroization of some secrets |
| LOW-2 | LOW | API safety | Lines 3086-3131 | No output buffer size validation |
| LOW-3 | LOW | Logic | Lines 2958-2962 | alpn_count not reset on free |
| LOW-4 | LOW | Defense-in-depth | Line 1273 | Random not checked for zero |
| LOW-5 | LOW | Future bug | Line 2203 | Hardcoded server CertificateVerify string |
| LOW-6 | LOW | Completeness | Lines 2624-2625 | NewSessionTicket extensions ignored |

---

## Positive Security Observations

1. **Constant-time comparisons**: The code correctly uses `crypto_memneq()` for
   comparing secrets (session ID at line 1451, Finished verify at line 2437, downgrade
   sentinels at lines 1581-1584, PSS H vs H' at line 2016). This prevents timing
   side-channel attacks.

2. **Key zeroization on cleanup**: The `tquic_hs_cleanup()` function uses
   `memzero_explicit()` for most secret material and `kfree_sensitive()` for the
   private key. This is good practice.

3. **Transcript size limit**: The `TQUIC_MAX_TRANSCRIPT_SIZE` (128KB) limit in
   `tquic_hs_update_transcript` prevents unbounded memory growth.

4. **Overflow check in transcript update**: Line 842 checks for u32 wrap:
   `if (new_len < hs->transcript_len || new_len > TQUIC_MAX_TRANSCRIPT_SIZE)`.

5. **X25519 key clamping**: The private key is properly clamped (lines 1293-1295)
   per the X25519 specification.

6. **Transport parameter validation**: The decoder validates ranges (e.g.,
   `max_udp_payload_size >= 1200`, `ack_delay_exponent <= 20`, `max_ack_delay < 16384`,
   `active_conn_id_limit >= 2`).

---

## Overall Risk Assessment

**Overall Risk: HIGH**

The handshake code has several critical buffer overflow vulnerabilities in the
message construction path (`tquic_hs_build_ch_extensions`, `tquic_hs_generate_client_hello`)
where attacker-influenced data sizes are not validated against output buffer bounds.
The message parsing path (`tquic_hs_process_server_hello`, `tquic_hs_process_certificate`)
has multiple missing bounds checks that allow out-of-bounds reads from maliciously
crafted packets.

The most urgent fixes needed are:
1. Add comprehensive bounds checking in all message generation functions (CRITICAL-1, -2, -3)
2. Fix the certificate parsing underflow (CRITICAL-5)
3. Add missing bounds checks in ServerHello parsing (CRITICAL-6, -7)
4. Resolve session ticket ownership ambiguity (HIGH-8, -9)
5. Add `memzero_explicit` to all error paths in key derivation (HIGH-4)
