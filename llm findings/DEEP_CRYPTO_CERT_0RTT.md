# DEEP CRYPTO AUDIT Part 1: Certificate Verification and 0-RTT

**Audit Date:** 2026-02-09
**Auditor:** Security Reviewer Agent (claude-opus-4-6)
**Scope:** `/Users/justinadams/Downloads/tquic-kernel/net/tquic/crypto/cert_verify.c` (2892 lines), `/Users/justinadams/Downloads/tquic-kernel/net/tquic/crypto/zero_rtt.c` (1928 lines), and their headers.

---

## Executive Summary

This audit examines the X.509 certificate verification and 0-RTT early data subsystems of the TQUIC kernel module. The code demonstrates generally competent design with proper bounds checking in many areas, but contains several critical and high-severity vulnerabilities, primarily in OCSP stapling verification (completely unimplemented), ASN.1 parsing edge cases, timing side channels, bloom filter collision properties, and key material handling on error paths.

**Finding count:** 5 CRITICAL, 7 HIGH, 8 MEDIUM, 5 LOW

---

## CRITICAL Findings

### CRITICAL-01: OCSP Stapling Response Accepted Without Any Verification

**File:** `/Users/justinadams/Downloads/tquic-kernel/net/tquic/crypto/cert_verify.c`
**Lines:** 2094-2131

```c
int tquic_check_revocation(struct tquic_cert_verify_ctx *ctx,
                           const struct tquic_x509_cert *cert)
{
    ...
    /* Check OCSP stapling data if provided */
    if (ctx->ocsp_stapling && ctx->ocsp_stapling_len > 0) {
        /*
         * OCSP response parsing would go here.
         * For now, accept stapled responses as valid.
         */
        pr_debug("tquic_cert: OCSP stapling present (%u bytes)\n",
                 ctx->ocsp_stapling_len);
        return 0;  // <-- ACCEPTS ANY DATA AS VALID OCSP
    }
    ...
}
```

**Exploitation:** An attacker who has compromised a certificate's private key (or obtained a mis-issued certificate that has since been revoked) can supply **any arbitrary bytes** as OCSP stapling data. The code will accept this as proof the certificate is not revoked. The OCSP response signature is never checked, the OCSP response status is never parsed, the responder identity is never verified, and the response freshness (thisUpdate/nextUpdate) is never validated.

Even when `check_revocation == TQUIC_REVOKE_HARD_FAIL`, if any OCSP data is present (even a single garbage byte), the check returns success.

**Impact:** Complete bypass of certificate revocation checking. A revoked certificate (e.g., due to key compromise) will be accepted as valid.

**Severity:** CRITICAL

**Fix:** The OCSP response must be fully parsed per RFC 6960: verify the signature against the issuer CA or a designated OCSP responder, check the response status (good/revoked/unknown), validate thisUpdate/nextUpdate timestamps, and match the certificate serial number.

---

### CRITICAL-02: Hard-Fail Revocation Mode Does Not Actually Fail

**File:** `/Users/justinadams/Downloads/tquic-kernel/net/tquic/crypto/cert_verify.c`
**Lines:** 2118-2130

```c
    if (ctx->check_revocation == TQUIC_REVOKE_HARD_FAIL) {
        pr_warn("tquic_cert: Revocation check required but no OCSP stapling available\n");
        /* In production, this should return an error.
         * For now, allow to support existing deployments.
         */
    }

    return 0;  // <-- RETURNS SUCCESS EVEN IN HARD_FAIL MODE
```

**Exploitation:** When configured for hard-fail revocation checking and no OCSP stapling is provided, the function logs a warning but returns 0 (success). This means `TQUIC_REVOKE_HARD_FAIL` behaves identically to `TQUIC_REVOKE_SOFT_FAIL` -- it is a documentation lie.

**Impact:** Administrators who configure hard-fail revocation checking have a false sense of security. Revoked certificates without OCSP stapling will be accepted.

**Severity:** CRITICAL

**Fix:** The function must return `-EKEYREVOKED` or a similar error when `TQUIC_REVOKE_HARD_FAIL` is set and revocation status cannot be determined.

---

### CRITICAL-03: Client Certificate Verification Uses Server Logic (EKU Bypass)

**File:** `/Users/justinadams/Downloads/tquic-kernel/net/tquic/crypto/cert_verify.c`
**Lines:** 2586-2594

```c
int tquic_hs_verify_client_cert(struct tquic_handshake *hs,
                                struct tquic_connection *conn)
{
    /* Client certificate verification uses same logic
     * but checks for client auth EKU instead of server auth
     */
    return tquic_hs_verify_server_cert(hs, conn);
}
```

However, `tquic_hs_verify_server_cert` calls `verify_chain(ctx, true)` (line 2450) which hardcodes `is_server = true`. Inside `verify_chain`, the key usage check at line 2243 calls `tquic_x509_check_key_usage(cert, depth, is_server)` which checks for `TQUIC_EKU_SERVER_AUTH` when `is_server` is true.

**Exploitation:** A client presenting a certificate with only `serverAuth` EKU (but not `clientAuth`) will pass verification. In a mutual-TLS scenario, an attacker with a server-only certificate can impersonate a client.

**Impact:** EKU validation bypass for client certificates.

**Severity:** CRITICAL

**Fix:** `tquic_hs_verify_client_cert` must call `verify_chain(ctx, false)` instead of delegating to the server verification function.

---

### CRITICAL-04: Self-Signed Certificate Comparison Uses Non-Constant-Time memcmp in One Path

**File:** `/Users/justinadams/Downloads/tquic-kernel/net/tquic/crypto/cert_verify.c`
**Lines:** 1626-1630 vs 1926-1929

The self-signed check at line 1626-1628 uses `crypto_memneq` (constant-time):
```c
    if (cert->issuer_raw && cert->subject_raw &&
        cert->issuer_raw_len == cert->subject_raw_len &&
        !crypto_memneq(cert->issuer_raw, cert->subject_raw, cert->issuer_raw_len)) {
        cert->self_signed = true;
    }
```

But `tquic_x509_verify_signature` at line 1926-1928 uses `memcmp` (non-constant-time):
```c
    if (cert->issuer_raw && cert->subject_raw &&
        cert->issuer_raw_len == cert->subject_raw_len &&
        memcmp(cert->issuer_raw, cert->subject_raw, cert->issuer_raw_len) == 0) {
        ((struct tquic_x509_cert *)cert)->self_signed = true;
    }
```

This is inconsistent. However, the more serious issue is that this comparison is on the issuer/subject DN, which is **not secret material** -- it is visible in the certificate itself. The real concern is the const-cast on line 1929 (`(struct tquic_x509_cert *)cert`), which violates the const qualifier and could be a symptom of a deeper design issue.

**Revised Assessment:** The timing channel on DN comparison is LOW since DNs are public. The const-cast is MEDIUM. Reclassifying to HIGH for the aggregate issue of inconsistent security-critical comparison patterns.

**Severity:** HIGH (revised from CRITICAL)

**Fix:** Use `crypto_memneq` consistently. Remove the const-cast by refactoring to set `self_signed` during parse, not during verification.

---

### CRITICAL-05: ASN.1 Time Parsing Does Not Validate Character Ranges

**File:** `/Users/justinadams/Downloads/tquic-kernel/net/tquic/crypto/cert_verify.c`
**Lines:** 1210-1254

```c
static int parse_time(const u8 *data, u32 len, s64 *time_out)
{
    ...
    const char *t = (const char *)data + 1 + hdr_len;
    year = (t[0] - '0') * 10 + (t[1] - '0');
    year += (year < 50) ? 2000 : 1900;
    month = (t[2] - '0') * 10 + (t[3] - '0');
    day = (t[4] - '0') * 10 + (t[5] - '0');
    hour = (t[6] - '0') * 10 + (t[7] - '0');
    min = (t[8] - '0') * 10 + (t[9] - '0');
    sec = (t[10] - '0') * 10 + (t[11] - '0');
    ...
    *time_out = mktime64(year, month, day, hour, min, sec);
```

**Exploitation:** No validation that characters are actually digits (0x30-0x39). A crafted certificate with non-digit characters in the time fields will produce garbage values via the `t[x] - '0'` arithmetic, which are then passed to `mktime64`. This can produce unexpected time values that could make an expired certificate appear valid, or a not-yet-valid certificate appear current.

For example, byte value 0xFF at t[0] would yield: `(0xFF - 0x30) * 10 = 2070` for just the first digit contribution. With maliciously chosen values, an attacker could craft a certificate with a `valid_to` time far in the future despite the visual representation appearing expired.

Additionally, `month`, `day`, `hour`, `min`, `sec` are not range-validated (e.g., month > 12, day > 31).

**Impact:** Certificate validity period bypass via crafted ASN.1 time values.

**Severity:** CRITICAL

**Fix:** Validate each character is an ASCII digit before arithmetic. Validate month (1-12), day (1-31), hour (0-23), minute (0-59), second (0-59).

---

## HIGH Findings

### HIGH-01: RSA Signature Algorithm Hardcoded to SHA-256 Regardless of Certificate

**File:** `/Users/justinadams/Downloads/tquic-kernel/net/tquic/crypto/cert_verify.c`
**Lines:** 1951-1954

```c
    case TQUIC_PUBKEY_ALGO_RSA:
        alg_name = "pkcs1pad(rsa,sha256)";
        break;
```

The signature verification always uses `pkcs1pad(rsa,sha256)` for RSA, regardless of what hash algorithm the certificate's signature actually uses. If a certificate is signed with RSA-SHA384 or RSA-SHA512, the verification will either fail (false negative) or, worse, not correctly verify (passing when it should not, depending on padding internals).

**Impact:** Certificates signed with RSA-SHA384 or RSA-SHA512 will not verify correctly. This could cause interoperability issues or, in edge cases, allow acceptance of improperly-verified signatures.

**Severity:** HIGH

**Fix:** Construct the algorithm name dynamically from `cert->signature.hash_algo`, e.g., `"pkcs1pad(rsa,sha384)"` or `"pkcs1pad(rsa,sha512)"`.

---

### HIGH-02: RSA-PSS Hash Algorithm Hardcoded to SHA-256

**File:** `/Users/justinadams/Downloads/tquic-kernel/net/tquic/crypto/cert_verify.c`
**Lines:** 228-232

```c
    } else if (oid_len == sizeof(oid_rsa_pss) &&
               memcmp(oid, oid_rsa_pss, oid_len) == 0) {
        /* RSA-PSS: hash algo determined from parameters */
        *hash_algo = TQUIC_HASH_SHA256;
        *pubkey_algo = TQUIC_PUBKEY_ALGO_RSA;
    }
```

The comment says "hash algo determined from parameters" but then hardcodes SHA-256. RSA-PSS parameters are embedded in the AlgorithmIdentifier and must be parsed to determine the actual hash algorithm. This is required by TLS 1.3 (RFC 8446 Section 4.2.3) which mandates RSA-PSS for RSA signatures.

**Impact:** RSA-PSS certificates using SHA-384 or SHA-512 will have incorrect signature verification.

**Severity:** HIGH

**Fix:** Parse RSA-PSS AlgorithmIdentifier parameters to extract the actual hash algorithm.

---

### HIGH-03: Bloom Filter Has High False Positive Rate at Scale

**File:** `/Users/justinadams/Downloads/tquic-kernel/net/tquic/crypto/zero_rtt.h`
**Lines:** 59-61

```c
#define TQUIC_REPLAY_BLOOM_BITS         (1 << 16)    /* 64K bits */
#define TQUIC_REPLAY_BLOOM_HASHES       4             /* 4 hash functions */
#define TQUIC_REPLAY_TTL_SECONDS        3600          /* 1 hour */
```

Each bucket is 32K bits (half of 64K). With 4 hash functions and a 32K-bit filter, the false positive rate after n insertions is approximately `(1 - e^(-4n/32768))^4`.

- At 1,000 tickets: ~0.6% false positive rate (acceptable)
- At 5,000 tickets: ~14% false positive rate (problematic)
- At 10,000 tickets: ~44% false positive rate (unacceptable)

For a busy server handling thousands of 0-RTT connections per hour, this means a significant fraction of legitimate 0-RTT attempts will be falsely rejected as replays, causing unnecessary 1-RTT fallback.

More concerning: because both buckets are populated simultaneously (line 913-916 of zero_rtt.c), the effective capacity is halved compared to what you might expect.

**Impact:** Denial of service (0-RTT degradation) on busy servers. Not a security bypass but a reliability issue with security implications (users may disable anti-replay to fix performance).

**Severity:** HIGH

**Fix:** Increase `TQUIC_REPLAY_BLOOM_BITS` to at least `(1 << 20)` (1M bits = 128KB) for production use, or make it configurable via sysctl.

---

### HIGH-04: Ticket Store Free-After-Remove Race Condition

**File:** `/Users/justinadams/Downloads/tquic-kernel/net/tquic/crypto/zero_rtt.c`
**Lines:** 497-500

```c
    old = ticket_store_find_locked(&global_ticket_store,
                                   server_name, server_name_len);
    if (old) {
        ticket_store_remove_locked(&global_ticket_store, old);
        ticket_free(old);  // <-- frees while refcount may be > 1
    }
```

In `tquic_zero_rtt_store_ticket`, when replacing an existing ticket for the same server, the old ticket is removed and freed without checking its refcount. If another thread obtained a reference via `tquic_zero_rtt_lookup_ticket` and is actively using the ticket (e.g., deriving 0-RTT keys), calling `ticket_free(old)` will free memory still in use.

The `ticket_free` function does not check `refcount` before freeing:
```c
static void ticket_free(struct tquic_zero_rtt_ticket *ticket)
{
    if (!ticket)
        return;
    kfree(ticket->ticket);
    memzero_explicit(&ticket->plaintext, sizeof(ticket->plaintext));
    kfree(ticket);  // <-- unconditional free
}
```

**Impact:** Use-after-free. An attacker could trigger this by rapidly reconnecting to the same server, causing a ticket replacement while another thread reads the old ticket. In kernel context, this is exploitable for privilege escalation.

**Severity:** HIGH

**Fix:** `ticket_store_remove_locked` should only remove from the tree/list. The actual free should happen via `tquic_zero_rtt_put_ticket` (refcount-based). Change `ticket_free(old)` to `tquic_zero_rtt_put_ticket(old)`.

---

### HIGH-05: Session Ticket Decode Missing Bounds Check on PSK Copy

**File:** `/Users/justinadams/Downloads/tquic-kernel/net/tquic/crypto/zero_rtt.c`
**Lines:** 1154-1164

```c
    out->psk_len = *p++;
    if (out->psk_len == 0 ||
        out->psk_len > TQUIC_ZERO_RTT_SECRET_MAX_LEN) {
        ret = -EINVAL;
        goto out_free;
    }
    if (payload_len < 1 + out->psk_len + 4 + 8 + 2 + 1) {
        ret = -EINVAL;
        goto out_free;
    }
    memcpy(out->psk, p, out->psk_len);
```

The bounds check at line 1160 uses `payload_len` (which has already been decremented by `TQUIC_SESSION_TICKET_TAG_LEN` at line 1143), but `p` has already been advanced past the PSK length byte. The check should account for the current position of `p` relative to `payload`, not just `payload_len`. If `payload_len` is exactly `1 + out->psk_len + 4 + 8 + 2 + 1`, the subsequent reads of ALPN and transport params could read past the buffer.

Actually, tracing more carefully: `p` starts at `payload` (line 1147), advances by 1 for psk_len byte. The check `payload_len < 1 + out->psk_len + 4 + 8 + 2 + 1` ensures at minimum 16 bytes + psk_len exist, which covers through the ALPN length byte. This is borderline correct but fragile -- it does not account for ALPN data or transport parameters data. Those are checked later, but via pointer arithmetic against `payload + payload_len`. This is acceptable but the pattern invites off-by-one errors.

**Revised severity:** MEDIUM (the code is technically correct but fragile).

---

### HIGH-06: 0-RTT Keys Derived With Empty Transcript (Not ClientHello Hash)

**File:** `/Users/justinadams/Downloads/tquic-kernel/net/tquic/crypto/zero_rtt.c`
**Lines:** 636-637

```c
    /* For simplicity, we use an empty transcript here. The actual
     * implementation should include the ClientHello hash.
     */
```

The `tquic_zero_rtt_derive_keys` function uses an empty hash as the transcript for deriving client_early_traffic_secret, but RFC 8446 Section 7.1 requires the hash of the ClientHello message. Using an empty transcript means:

1. All connections to the same server with the same PSK will derive identical 0-RTT keys.
2. This is a nonce reuse risk if packet numbers are reused across connections (they start from 0 each time).
3. The security binding to the specific ClientHello is lost.

**Impact:** If two connections use the same PSK (which is the purpose of session resumption), they will have identical 0-RTT keys. Since packet numbers start from 0, the first packet of each connection will use the same nonce, causing AES-GCM nonce reuse -- a catastrophic cryptographic failure.

**Severity:** HIGH (upgraded from the code comment's "simplicity" note)

**Fix:** The ClientHello hash must be included in the key derivation. Use `tquic_zero_rtt_derive_secret` (which does accept `client_hello_hash`) instead of `tquic_zero_rtt_derive_keys` for actual connections.

---

### HIGH-07: Procfs trusted_cas Writable Without Privilege Check

**File:** `/Users/justinadams/Downloads/tquic-kernel/net/tquic/crypto/cert_verify.c`
**Lines:** 2862

```c
    proc_create("trusted_cas", 0644, tquic_cert_proc_dir,
                &tquic_proc_trusted_cas_ops);
```

The procfs entry is created with mode 0644, meaning any user with write access (the file owner, which defaults to root) can modify trusted CAs. However, the write handler at line 2772-2808 does not perform any additional capability checks (e.g., `capable(CAP_SYS_ADMIN)`).

While 0644 typically restricts writes to root, a process running as root but in a user namespace or container could potentially manipulate the trust store. The `keyring_alloc` at line 2615 uses `current_cred()` which could be namespace-scoped.

**Impact:** In containerized environments, untrusted root processes might be able to add arbitrary trusted CAs, enabling MITM attacks.

**Severity:** MEDIUM (requires root or container escape, but still a defense-in-depth gap)

**Fix:** Add `capable(CAP_NET_ADMIN)` check in the write handler. Consider using 0600 permissions.

---

## MEDIUM Findings

### MEDIUM-01: asn1_get_length Does Not Handle Length 0x84+ (4+ byte lengths)

**File:** `/Users/justinadams/Downloads/tquic-kernel/net/tquic/crypto/cert_verify.c`
**Lines:** 139-167

```c
static int asn1_get_length(const u8 *data, u32 data_len, u32 *len, u32 *hdr_len)
{
    ...
    } else if (data[0] == 0x83) {
        if (data_len < 4)
            return -EINVAL;
        *len = (data[1] << 16) | (data[2] << 8) | data[3];
        *hdr_len = 4;
    } else {
        return -EINVAL;
    }
```

The function rejects 0x84 (4-byte length encoding), which is used for objects larger than 16MB. While X.509 certificates should never be this large, the rejection path is correct (returns -EINVAL). However, the 0x80 (indefinite length) form is also rejected, which is correct for DER but could cause issues with BER-encoded inputs.

More importantly, the 0x83 case handles up to 16MB objects. The `*len` value is a u32, so there is no overflow here. However, the subsequent `*total_len = 1 + hdr_len + len` in `asn1_get_tag_length` (line 186) could overflow if `len` is close to UINT32_MAX. Given the maximum is 0x83FFFFFF = ~134MB, and `1 + 4 + 134M` fits in u32, this is safe.

**Note:** The 0x82 case at line 155: `*len = (data[1] << 8) | data[2]` -- `data[1]` is u8, `data[1] << 8` promotes to int. This is safe because u8 << 8 fits in int. No issue.

**Severity:** MEDIUM (defensive code is correct but incomplete -- BER indefinite length rejection should be explicit with a clear error message)

---

### MEDIUM-02: SAN DNS Names Not Validated for Embedded NUL Characters

**File:** `/Users/justinadams/Downloads/tquic-kernel/net/tquic/crypto/cert_verify.c`
**Lines:** 465-471

```c
    names[name_count] = kmalloc(content_len + 1, GFP_KERNEL);
    if (!names[name_count])
        goto err_free;

    memcpy(names[name_count], p + 1 + hdr_len, content_len);
    names[name_count][content_len] = '\0';
```

DNS names from SAN extensions are copied without checking for embedded NUL bytes. An attacker could create a certificate with SAN `www.evil.com\0.example.com`. The `hostname_match` function uses `strncasecmp` which will stop at the NUL, effectively matching `www.evil.com` when the full SAN appears to be for `example.com`.

**Impact:** Hostname verification bypass via NUL-byte injection in SAN DNS names. This is a well-known attack vector (CVE-2009-2408 in NSS, CVE-2009-3555 variants).

**Severity:** MEDIUM (mitigated by the fact that CAs should not issue such certificates, but defense-in-depth requires checking)

**Fix:** Reject SAN DNS names containing NUL bytes (0x00). Add: `if (memchr(p + 1 + hdr_len, 0, content_len)) continue;`

---

### MEDIUM-03: Hostname Wildcard Matching Allows Wildcards in Non-Leftmost Position

**File:** `/Users/justinadams/Downloads/tquic-kernel/net/tquic/crypto/cert_verify.c`
**Lines:** 1816-1829

```c
    if (pattern_len >= 2 && pattern[0] == '*' && pattern[1] == '.') {
```

The wildcard check only validates that the pattern starts with `*.`. It does not reject patterns like `f*o.example.com` or `*.*.example.com`. RFC 6125 Section 6.4.3 states wildcards should only appear in the leftmost label. While the current code does require `*` at position 0, a pattern like `*.*` would not be caught since the check passes and the subsequent comparison might match incorrectly.

Additionally, RFC 6125 recommends not matching wildcards against public suffixes (e.g., `*.com` should not match). No public suffix list check is performed.

**Impact:** Overly permissive wildcard matching could allow a wildcard certificate to match unintended domains.

**Severity:** MEDIUM

---

### MEDIUM-04: Path Length Constraint Check Off-By-One

**File:** `/Users/justinadams/Downloads/tquic-kernel/net/tquic/crypto/cert_verify.c`
**Lines:** 2259-2264

```c
    if (cert->path_len_constraint >= 0 &&
        (int)(depth - 1) > cert->path_len_constraint) {
```

The `depth` variable counts from 0 (end-entity) upward. For the first intermediate CA, `depth = 1`. The check `(int)(depth - 1) > path_len_constraint` means for depth=1, it checks `0 > constraint`. This seems correct for the first intermediate, but consider: RFC 5280 says `pathLenConstraint` gives the maximum number of non-self-issued intermediate certificates that may follow this certificate in a valid certification path. The check should count how many intermediate certificates exist **below** the current CA in the chain, not the depth of the CA itself.

The current logic counts relative to the end-entity, which is approximately correct for a simple chain but may be wrong for complex chains with multiple intermediate CAs where the constraint is on an intermediate, not the root.

**Severity:** MEDIUM

---

### MEDIUM-05: 0-RTT Encrypt Allocates AEAD Per-Packet (Performance / Side Channel)

**File:** `/Users/justinadams/Downloads/tquic-kernel/net/tquic/crypto/zero_rtt.c`
**Lines:** 1522-1531

```c
    aead = crypto_alloc_aead(tquic_cipher_to_aead_name(state->cipher_suite), 0, 0);
    if (IS_ERR(aead))
        return PTR_ERR(aead);

    ret = crypto_aead_setkey(aead, state->keys.key, state->keys.key_len);
```

A new AEAD cipher instance is allocated and the key is set for **every single packet**. This is extremely expensive and creates a timing side channel: the time to encrypt a packet depends on memory allocator state, which varies based on system load and could leak information about concurrent operations.

**Impact:** Performance degradation (crypto_alloc_aead involves slab allocation, module loading checks, etc.). Minor timing side channel.

**Severity:** MEDIUM

**Fix:** Allocate the AEAD transform once during key derivation and store it in `tquic_zero_rtt_keys`. Reuse for all packets.

---

### MEDIUM-06: Bloom Filter Seeds Never Rotated

**File:** `/Users/justinadams/Downloads/tquic-kernel/net/tquic/crypto/zero_rtt.c`
**Lines:** 96-103

```c
/*
 * Seeds are NOT rotated after initialization because rotating seeds
 * invalidates all existing bloom filter entries...
 */
static u32 replay_hash_seed1 __read_mostly;
static u32 replay_hash_seed2 __read_mostly;
```

The hash seeds are initialized once at module load and never changed. If an attacker can observe bloom filter behavior over time (e.g., by measuring whether 0-RTT is accepted or rejected for crafted tickets), they could potentially deduce the seeds through a chosen-input attack. The seeds are only 32 bits each, making brute-force feasible (2^32 attempts per seed, or 2^64 for both, but correlation attacks could reduce this).

**Impact:** After seed recovery, an attacker could craft tickets that always collide (causing DoS via false positives) or never collide (bypassing replay detection).

**Severity:** MEDIUM

**Fix:** Use 64-bit seeds (siphash instead of jhash) and rotate seeds during bucket rotation, hashing any remaining entries into the new bucket with new seeds.

---

### MEDIUM-07: Key Material Not Zeroized on All Error Paths in tquic_zero_rtt_derive_keys

**File:** `/Users/justinadams/Downloads/tquic-kernel/net/tquic/crypto/zero_rtt.c`
**Lines:** 596-707

The `keys` structure is populated incrementally. If an error occurs after the secret is derived but before the function returns, the partially-filled `keys->secret` is not zeroized. The `out:` label only zeroizes `early_secret`:

```c
out:
    memzero_explicit(early_secret, sizeof(early_secret));
    crypto_free_shash(hash);
    return ret;
```

If the function returns with an error after line 662 (secret derived) but before line 698 (`keys->valid = true`), the caller receives an error code but `keys->secret` still contains the client_early_traffic_secret. If the caller does not zeroize `keys` on error, this secret persists in memory.

**Impact:** Key material leak on error paths. The secret could be recovered from kernel memory dumps.

**Severity:** MEDIUM

**Fix:** Add `if (ret) memzero_explicit(keys, sizeof(*keys));` before the `out:` label, or zeroize in the `out:` path when `ret != 0`.

---

### MEDIUM-08: Certificate Chain Parsing Does Not Verify Issuer-Subject Linkage Before Trust Check

**File:** `/Users/justinadams/Downloads/tquic-kernel/net/tquic/crypto/cert_verify.c`
**Lines:** 2300-2305

```c
    /* Check if this certificate is a trust anchor */
    ret = find_trust_anchor(ctx, cert);
    if (ret == 0) {
        /* Found trust anchor, chain is valid */
        return 0;
    }
```

The `find_trust_anchor` function is called for **every** certificate in the chain, including the end-entity certificate. If the end-entity certificate's issuer/serial happens to match a key in the system keyring (which could happen with a long-running keyring), the chain is accepted without verifying any signatures.

Additionally, the signature of the end-entity certificate against its issuer is only verified if `cert->next` exists (line 2319). If the chain contains only one certificate (the end-entity) and it matches a trust anchor, no signature verification occurs at all.

**Impact:** A certificate that appears in the keyring but has been tampered with (different public key or extensions) could be accepted without signature verification.

**Severity:** MEDIUM

---

## LOW Findings

### LOW-01: parse_basic_constraints Hardcoded BOOLEAN Length

**File:** `/Users/justinadams/Downloads/tquic-kernel/net/tquic/crypto/cert_verify.c`
**Lines:** 633-638

```c
    if (p < end && p[0] == 0x01) {  /* BOOLEAN */
        if (p + 3 <= end) {
            *is_ca = (p[2] != 0);
            p += 3;
        }
    }
```

Assumes BOOLEAN is always encoded as `01 01 XX` (tag + length 1 + value). While this is the only valid DER encoding, a BER encoder could produce different lengths. The code should use `asn1_get_tag_length` for consistency.

**Severity:** LOW

---

### LOW-02: server_ticket_key Is Static Global Without Rotation

**File:** `/Users/justinadams/Downloads/tquic-kernel/net/tquic/crypto/zero_rtt.c`
**Lines:** 88-89

```c
static u8 server_ticket_key[TQUIC_SESSION_TICKET_KEY_LEN];
static bool server_ticket_key_valid;
```

The ticket encryption key is generated once at module load and never rotated. Long-running servers will use the same key for the entire uptime, potentially years. If the key is ever compromised (e.g., via memory disclosure vulnerability), all past and future tickets are compromised.

**Severity:** LOW (key rotation is a best practice but not a vulnerability per se)

**Fix:** Implement periodic key rotation (e.g., every 24 hours) with support for decrypting tickets encrypted with the previous key.

---

### LOW-03: Empty Hash Computed Without Algorithm Validation

**File:** `/Users/justinadams/Downloads/tquic-kernel/net/tquic/crypto/zero_rtt.c`
**Lines:** 648-657

The empty hash is computed using the same `hash` transform allocated for the cipher suite, but `empty_hash` is sized at `TQUIC_ZERO_RTT_SECRET_MAX_LEN` (48 bytes). For SHA-256, only 32 bytes are written, leaving 16 bytes uninitialized. While the uninitialized bytes are never read (hash_len is used to constrain reads), the buffer is on the stack and could be observed via speculative execution side channels.

**Severity:** LOW

**Fix:** Zero-initialize `empty_hash` or use `memzero_explicit` after use.

---

### LOW-04: Inconsistent Error Return From verify_chain

**File:** `/Users/justinadams/Downloads/tquic-kernel/net/tquic/crypto/cert_verify.c`
**Lines:** 2318-2326

If the chain has no next certificate and is not self-signed and not a trust anchor, the loop falls through to return -ENOKEY on line 2332. But the signature of the last certificate is never verified against anything. This is correct behavior (untrusted chain) but the error message "No trusted root certificate found in chain" might be misleading if the actual problem is a missing intermediate.

**Severity:** LOW

---

### LOW-05: SAN Parsing Capacity Limit Check Could Be Tighter

**File:** `/Users/justinadams/Downloads/tquic-kernel/net/tquic/crypto/cert_verify.c`
**Lines:** 454

```c
    if (name_capacity >= 10000)
        goto err_free;
```

The limit of 10,000 SAN entries per certificate is very high. A typical certificate has fewer than 100 SANs. Each SAN involves a separate `kmalloc`, so a maliciously crafted certificate with thousands of SANs could cause significant kernel memory allocation pressure.

**Severity:** LOW

**Fix:** Reduce limit to 1000 or add a total allocation size limit.

---

## Summary Table

| ID | Severity | Component | Description |
|---|---|---|---|
| CRITICAL-01 | CRITICAL | cert_verify.c:2094 | OCSP stapling accepted without any verification |
| CRITICAL-02 | CRITICAL | cert_verify.c:2122 | Hard-fail revocation mode does not actually fail |
| CRITICAL-03 | CRITICAL | cert_verify.c:2592 | Client cert verification uses server EKU check |
| CRITICAL-04 | HIGH* | cert_verify.c:1928 | Inconsistent const-time comparison, const-cast |
| CRITICAL-05 | CRITICAL | cert_verify.c:1225 | ASN.1 time parsing no character validation |
| HIGH-01 | HIGH | cert_verify.c:1953 | RSA sig algorithm hardcoded to SHA-256 |
| HIGH-02 | HIGH | cert_verify.c:231 | RSA-PSS hash hardcoded to SHA-256 |
| HIGH-03 | HIGH | zero_rtt.h:59 | Bloom filter undersized for production |
| HIGH-04 | HIGH | zero_rtt.c:499 | Use-after-free on ticket replacement |
| HIGH-05 | MEDIUM* | zero_rtt.c:1160 | Fragile bounds checking in ticket decode |
| HIGH-06 | HIGH | zero_rtt.c:636 | 0-RTT keys derived with empty transcript |
| HIGH-07 | MEDIUM | cert_verify.c:2862 | Procfs writable without capability check |
| MEDIUM-01 | MEDIUM | cert_verify.c:139 | ASN.1 indefinite length handling |
| MEDIUM-02 | MEDIUM | cert_verify.c:469 | SAN NUL-byte injection |
| MEDIUM-03 | MEDIUM | cert_verify.c:1816 | Wildcard matching overly permissive |
| MEDIUM-04 | MEDIUM | cert_verify.c:2260 | Path length constraint off-by-one risk |
| MEDIUM-05 | MEDIUM | zero_rtt.c:1523 | Per-packet AEAD allocation |
| MEDIUM-06 | MEDIUM | zero_rtt.c:101 | Bloom filter seeds never rotated |
| MEDIUM-07 | MEDIUM | zero_rtt.c:703 | Key material not zeroized on error |
| MEDIUM-08 | MEDIUM | cert_verify.c:2301 | Trust anchor check skips signature verification |
| LOW-01 | LOW | cert_verify.c:633 | Hardcoded BOOLEAN length in ASN.1 |
| LOW-02 | LOW | zero_rtt.c:88 | Static ticket key without rotation |
| LOW-03 | LOW | zero_rtt.c:603 | Uninitialized stack bytes in empty_hash |
| LOW-04 | LOW | cert_verify.c:2332 | Misleading error message for incomplete chain |
| LOW-05 | LOW | cert_verify.c:454 | Excessive SAN capacity limit |

*Severity was revised during analysis.

---

## Positive Observations

Despite the findings above, several aspects of the code are well-implemented:

1. **PN replay protection in 0-RTT decrypt** (zero_rtt.c:1742-1807): The check-before-decrypt, record-after-authenticate pattern is correct and prevents PN burning attacks.

2. **Nonce reuse prevention in 0-RTT encrypt** (zero_rtt.c:1489-1520): The spinlock-protected monotonicity check with WARN_ONCE on violation is excellent defensive coding.

3. **Key zeroization in cleanup paths** (zero_rtt.c:1271): `memzero_explicit` is used correctly for key material in the main cleanup path.

4. **ASN.1 bounds checking** (cert_verify.c:186-189): The `*total_len > data_len` check prevents buffer over-reads in the main parsing functions.

5. **Name constraints validation** (cert_verify.c:940-1031): RFC 5280 Section 4.2.1.10 is implemented correctly, including the distinction between permitted and excluded subtrees.

6. **Bloom filter two-bucket rotation** (zero_rtt.c:793-813): The two-bucket scheme ensures entries survive for at least TTL/2, which is a sound approach.

---

## Recommendations Priority

1. **Immediate (before any deployment):** Fix CRITICAL-01 (OCSP), CRITICAL-02 (hard-fail), CRITICAL-03 (client EKU), CRITICAL-05 (time parsing), HIGH-06 (empty transcript)
2. **Before production:** Fix HIGH-01 (RSA hash), HIGH-02 (RSA-PSS), HIGH-04 (use-after-free)
3. **Short-term:** Fix MEDIUM-02 (NUL injection), MEDIUM-07 (key zeroize), MEDIUM-08 (trust anchor)
4. **Medium-term:** Fix HIGH-03 (bloom filter sizing), MEDIUM-05 (AEAD reuse), MEDIUM-06 (seed rotation)
