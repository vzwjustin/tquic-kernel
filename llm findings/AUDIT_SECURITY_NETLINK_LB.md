# TQUIC Security Audit: Security Subsystem, Netlink, Load Balancer, and Tunnel

**Auditor**: Kernel Security Reviewer (Claude Opus 4.6)
**Date**: 2026-02-09
**Scope**: `net/tquic/security/`, `net/tquic/tquic_netlink.c`, `net/tquic/lb/`, `net/tquic/tquic_tunnel.c`

---

## CRITICAL Issues

### CRIT-01: Tunnel Uses init_net -- Namespace Escape

**File**: `/Users/justinadams/Downloads/tquic-kernel/net/tquic/tquic_tunnel.c`
**Line**: 332

```c
err = sock_create_kern(&init_net, family, SOCK_STREAM, IPPROTO_TCP,
                       &sock);
```

**Description**: The tunnel subsystem creates TCP sockets in `init_net` (the root network namespace) regardless of which namespace the calling QUIC connection belongs to. This is a namespace escape vulnerability. A user in a container or non-root network namespace who can open a QUIC tunnel will have TCP connections created in the host's root namespace, bypassing all network namespace isolation including firewall rules, routing policies, and network access controls.

**Impact**: Complete network namespace isolation bypass. Container escape for network traffic. Attacker in a restricted namespace can reach any host reachable from the root namespace.

**Fix**: Use the network namespace from the QUIC connection's socket (`sock_net(conn->sk)`) instead of `&init_net`. Pass the correct `struct net *` through the client and tunnel structures.

---

### CRIT-02: SSRF via IPv4-Mapped IPv6 Addresses Bypasses Address Filtering

**File**: `/Users/justinadams/Downloads/tquic-kernel/net/tquic/tquic_tunnel.c`
**Lines**: 196-206

```c
if (ipv6_addr_loopback(&addr6) ||
    ipv6_addr_is_multicast(&addr6) ||
    ipv6_addr_type(&addr6) & IPV6_ADDR_LINKLOCAL) {
    return -EACCES;
}
```

**Description**: The IPv6 address filter does not check for IPv4-mapped IPv6 addresses (`::ffff:127.0.0.1`), IPv4-compatible IPv6 addresses (`::127.0.0.1`), 6to4 addresses that embed private IPv4 ranges, or Teredo addresses. An attacker can use `::ffff:127.0.0.1` to connect to localhost, or `::ffff:10.0.0.1` to reach RFC 1918 private networks, completely bypassing the SSRF protections.

**Impact**: Full SSRF bypass. Attacker can connect to localhost services, cloud metadata endpoints (169.254.169.254), and internal networks via the tunnel.

**Fix**: Add checks for `ipv6_addr_v4mapped()`, `ipv6_addr_is_isatap()`, private RFC 1918 ranges within mapped addresses, and the unspecified address (`::` / `in6addr_any`). Also check for `::ffff:169.254.169.254` (cloud metadata).

---

### CRIT-03: Missing RFC 1918 / Private Network Filtering in IPv4 SSRF Checks

**File**: `/Users/justinadams/Downloads/tquic-kernel/net/tquic/tquic_tunnel.c`
**Lines**: 164-168

```c
if (ipv4_is_loopback(addr4) ||
    ipv4_is_multicast(addr4) ||
    ipv4_is_lbcast(addr4) ||
    ipv4_is_zeronet(addr4)) {
    return -EACCES;
}
```

**Description**: The IPv4 SSRF filter does not block RFC 1918 private addresses (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16), link-local (169.254.0.0/16 including the cloud metadata endpoint 169.254.169.254), or other reserved ranges. A remote attacker controlling QUIC stream data can instruct the VPS to connect to internal infrastructure services.

**Impact**: SSRF to internal networks, cloud metadata endpoints, and management interfaces.

**Fix**: Add checks for `ipv4_is_private_10()`, `ipv4_is_private_172()`, `ipv4_is_private_192()`, `ipv4_is_linklocal_169()`, and other reserved ranges per RFC 5737 (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24).

---

### CRIT-04: Load Balancer Plaintext Mode Exposes Server ID

**File**: `/Users/justinadams/Downloads/tquic-kernel/net/tquic/lb/quic_lb.c`
**Lines**: 88-90, 407-408

```c
case TQUIC_LB_MODE_PLAINTEXT:
    memcpy(cid->payload, plaintext, payload_len);
    break;
```

**Description**: In plaintext mode (`encryption_key == NULL`), the server ID is embedded directly in the connection ID without any obfuscation. Any network observer can extract the server ID by reading bytes from the CID. The draft-ietf-quic-load-balancers specification explicitly warns that plaintext mode is only for testing and MUST NOT be used in production. There is no runtime warning or compile-time guard against this.

**Impact**: Server ID disclosure to any on-path observer. Enables targeted attacks against specific backend servers, load balancer topology mapping, and connection tracking/correlation.

**Fix**: Log a `pr_warn_once()` when plaintext mode is selected. Consider requiring `CAP_NET_ADMIN` to create plaintext configs, or removing plaintext mode entirely. At minimum, add a prominent `IS THIS REALLY WHAT YOU WANT` style warning.

---

## HIGH Severity Issues

### HIGH-01: Function Pointer Stored in skb->cb Without Validation

**File**: `/Users/justinadams/Downloads/tquic-kernel/net/tquic/security/quic_exfil.c`
**Lines**: 71-75, 270-271, 484-487, 782, 1310

```c
/* Store send function in skb->cb */
*(unsigned long *)skb->cb = (unsigned long)send_fn;

/* Later, retrieve and call */
void (*send_fn)(struct sk_buff *) =
    (void (*)(struct sk_buff *))(*(unsigned long *)skb->cb);
send_fn(skb);
```

**Description**: Function pointers are stored in `skb->cb` (the control buffer) and later retrieved and called without validation. The `skb->cb` area is 48 bytes and is used by multiple layers; if any intermediate processing corrupts or overwrites `cb[0]`, an attacker could achieve code execution. The check `if (skb->cb[0])` at line 71 treats cb[0] as a boolean but the actual pointer starts at `*(unsigned long *)skb->cb` -- a nonzero cb[0] byte does not guarantee a valid function pointer. Furthermore, the decoy traffic code at line 533 writes `'D', 'E', 'C', 'O', 'Y'` into cb, which would be interpreted as a garbage function pointer if the SKB were accidentally passed through the send path.

**Impact**: If `skb->cb` is corrupted (by another network layer or a bug), calling the stored function pointer leads to arbitrary code execution in kernel context.

**Fix**: Do not store raw function pointers in `skb->cb`. Instead, use a dedicated structure with a magic number for validation, or use a callback registration mechanism that does not rely on `skb->cb`.

---

### HIGH-02: No CAP_NET_ADMIN Check for Tunnel Creation

**File**: `/Users/justinadams/Downloads/tquic-kernel/net/tquic/tquic_tunnel.c`
**Lines**: 496-546

```c
struct tquic_tunnel *tquic_tunnel_create(struct tquic_client *client,
                                         struct tquic_stream *stream,
                                         const u8 *header_data,
                                         size_t header_len)
```

**Description**: `tquic_tunnel_create()` and `tquic_tunnel_create_tproxy()` do not perform any capability checks. Any process that can open a QUIC stream can instruct the kernel to create outbound TCP connections to arbitrary destinations (subject to the incomplete SSRF filter). Tunnel creation should require `CAP_NET_ADMIN` or at minimum `CAP_NET_RAW`.

**Impact**: Unprivileged users can open arbitrary TCP connections via the tunnel mechanism, potentially circumventing local firewall rules and creating unauthorized network flows.

**Fix**: Add `capable(CAP_NET_ADMIN)` check at the entry point of tunnel creation, or ensure the calling path enforces this.

---

### HIGH-03: Load Balancer Encryption Key Not Zeroized on Destroy

**File**: `/Users/justinadams/Downloads/tquic-kernel/net/tquic/lb/quic_lb.c`
**Lines**: 107-116

```c
void tquic_lb_config_destroy(struct tquic_lb_config *cfg)
{
    if (!cfg)
        return;

    if (cfg->aes_tfm)
        crypto_free_sync_skcipher(cfg->aes_tfm);

    kmem_cache_free(lb_config_cache, cfg);
}
```

**Description**: The AES-128 encryption key stored in `cfg->encryption_key[16]` is not zeroized before the config structure is freed. The SLAB allocator may reuse this memory for other allocations, potentially exposing the key material through information disclosure vulnerabilities in other subsystems. The `server_id` is also not zeroized.

**Impact**: Encryption key material remains in freed memory, potentially recoverable via heap spraying or other memory disclosure techniques.

**Fix**: Add `memzero_explicit(cfg->encryption_key, sizeof(cfg->encryption_key))` and `memzero_explicit(cfg->server_id, sizeof(cfg->server_id))` before `kmem_cache_free()`.

---

### HIGH-04: Constant-Time CID Validation Has Branching on Lengths

**File**: `/Users/justinadams/Downloads/tquic-kernel/net/tquic/security/quic_exfil.c`
**Lines**: 379-405

```c
bool tquic_ct_validate_cid(const u8 *cid, size_t cid_len,
                           const u8 *expected, size_t expected_len)
{
    ...
    /* Compare lengths without branching */
    len_match = !(cid_len ^ expected_len);

    /* Use the larger length to ensure constant-time */
    max_len = cid_len > expected_len ? cid_len : expected_len;
    if (max_len > sizeof(dummy_buf))
        max_len = sizeof(dummy_buf);
    ...
}
```

**Description**: Despite the comment "without branching," the ternary `cid_len > expected_len ? cid_len : expected_len` is a branch on secret data. The comparison `max_len > sizeof(dummy_buf)` is also a branch. More critically, `tquic_ct_memcmp(cid, expected, max_len)` reads `max_len` bytes from both `cid` and `expected`, but if `cid_len < max_len`, this is an out-of-bounds read. The function assumes both buffers are at least `max_len` bytes, which is not guaranteed.

**Impact**: Potential out-of-bounds read if `cid_len != expected_len`. The timing variation from branches may leak length information.

**Fix**: Read exactly `min(cid_len, expected_len)` bytes with bounds checking, use `ct_select` for branchless max, and ensure both buffers are adequately sized or copy to fixed-size local buffers first.

---

### HIGH-05: Unbounded Connection Creation via Netlink

**File**: `/Users/justinadams/Downloads/tquic-kernel/net/tquic/tquic_netlink.c`
**Lines**: 668-674

```c
conn = tquic_conn_lookup(net, conn_id);
if (!conn) {
    conn = tquic_conn_info_create(net, conn_id);
    if (!conn)
        return -ENOMEM;
}
```

**Description**: In `tquic_nl_cmd_path_add()`, a new connection is automatically created if the specified `conn_id` does not exist. There is no limit on the number of connections that can be created per namespace. While paths per connection are limited to 256, an attacker with `CAP_NET_ADMIN` can create unlimited connection objects by varying `conn_id`, leading to kernel memory exhaustion.

**Impact**: Denial of service via kernel memory exhaustion by creating millions of connection info objects.

**Fix**: Add a per-namespace limit on the number of connections (e.g., via an `atomic_t conn_count` in `struct tquic_net`).

---

### HIGH-06: Timing Normalization Can Block in Packet Processing Path

**File**: `/Users/justinadams/Downloads/tquic-kernel/net/tquic/security/quic_exfil.c`
**Lines**: 218-228

```c
if (delay_us <= 10) {
    udelay(delay_us);
} else if (delay_us <= 1000) {
    usleep_range(delay_us, delay_us + 10);
} else {
    msleep(delay_us / 1000);
    ...
}
```

**Description**: `tquic_timing_normalize_process()` is called during incoming packet processing (`tquic_exfil_process_incoming`). The function uses `usleep_range()` and `msleep()` which sleep and can only be called from process context. If called from softirq/BH context (typical for incoming packet processing), this will cause a BUG or schedule-while-atomic panic. Even if called from process context, blocking for up to 2ms per packet at PARANOID level is a denial-of-service amplifier.

**Impact**: Kernel panic if called from softirq context. Denial of service via intentional latency injection (attacker sends many packets, each causing 2ms delay on the receiver).

**Fix**: Never sleep in packet processing paths. Use `udelay()` only for very short delays, or defer processing to a workqueue. Add a `might_sleep()` annotation and ensure callers are in sleepable context.

---

## MEDIUM Severity Issues

### MED-01: Decoy Packet Size Calculation Can Underflow

**File**: `/Users/justinadams/Downloads/tquic-kernel/net/tquic/security/quic_exfil.c`
**Line**: 519

```c
decoy_size = 64 + (rand_val % (shaper->mtu - 64 + 1));
```

**Description**: If `shaper->mtu` is set to a value less than 64 (e.g., via `tquic_traffic_shaper_set_mtu()` with no lower bound check), `shaper->mtu - 64 + 1` wraps around to a very large number due to unsigned arithmetic (both are `u32`). This would produce a decoy_size of up to ~4GB, and `alloc_skb()` with such a size would fail, but the modulo of a random u32 by a near-u32-max value could still produce very large sizes.

**Impact**: Potential large memory allocation attempt (though allocation will fail). If MTU is exactly 64, `rand_val % 1` = 0, so `decoy_size = 64`, which is correct. Values below 64 are the problem.

**Fix**: Add minimum MTU validation in `tquic_traffic_shaper_set_mtu()`:
```c
if (mtu < 64) mtu = 64;
```

---

### MED-02: Load Balancer Feistel Network Half-Length Overlap

**File**: `/Users/justinadams/Downloads/tquic-kernel/net/tquic/lb/quic_lb.c`
**Lines**: 269-275, 282

```c
half_len = (len + 1) / 2;
memcpy(left, plaintext, half_len);
memcpy(right, plaintext + half_len, len - half_len);
...
tmp[15] = round;  /* Include round number */
```

**Description**: When `len` is odd, `half_len > len - half_len`, so the left and right halves overlap by one byte in the middle of the plaintext. This is handled correctly for the Feistel network itself, but `tmp[15] = round` could overwrite meaningful data if `half_len > 15`. Given `TQUIC_LB_CID_PAYLOAD_MAX = 19`, `half_len` can be up to 10 (for len=19), so `tmp[15]` is always in the zero-padded area. However, if the function is called with `len > 30`, `half_len = 16` and `memcpy(tmp, right, half_len)` fills all 16 bytes, then `tmp[15] = round` overwrites the last byte of actual data.

**Impact**: For `len > 30` (which is rejected by the `len > 32` check), the round number would overwrite data, causing decryption to fail. With current bounds (`len <= 32`, `half_len <= 16`), the last byte of `right` at index 15 can be overwritten. For `len = 31`, `half_len = 16`, and `right` has 15 bytes with `right[15]` being zero-pad, so `tmp[15] = round` overwrites zero-pad -- but for `len = 32`, both halves are 16 bytes, and `tmp[15] = round` overwrites `right[15]`, a real data byte.

**Impact**: Encryption/decryption corruption when `len = 32` and `half_len = 16`.

**Fix**: Use a separate byte position for the round number that does not conflict with data, or XOR the round number rather than overwriting.

---

### MED-03: Sysctl Variables Lack Range Validation

**File**: `/Users/justinadams/Downloads/tquic-kernel/net/tquic/security/quic_exfil.c`
**Lines**: 40-46

```c
static int exfil_protection_level = TQUIC_EXFIL_LEVEL_MEDIUM;
static int exfil_timing_delay_us = TQUIC_EXFIL_DELAY_MEDIUM_MAX_US;
static int exfil_padding_strategy = TQUIC_PAD_RANDOM;
static int exfil_pad_probability = TQUIC_PAD_PROBABILITY_DEFAULT;
static int exfil_spin_mode = TQUIC_SPIN_RANDOM_PROB;
static int exfil_jitter_min_us = TQUIC_JITTER_DEFAULT_MIN_US;
static int exfil_jitter_max_us = TQUIC_JITTER_DEFAULT_MAX_US;
```

**Description**: These module parameters are exposed via sysctl but no sysctl table with `.extra1`/`.extra2` range validation is registered anywhere in the code. The sysctl accessor functions cast these raw `int` values to enum types without range checking. A root user could set `exfil_protection_level = 99`, and the switch statements in the set_level functions would fall through without setting any delay values, potentially leaving the normalizer in an inconsistent state.

**Impact**: Invalid configuration states. Not exploitable for code execution but can disable security protections or cause unexpected behavior.

**Fix**: Register a proper sysctl table with `proc_dointvec_minmax` handlers and range limits, or add range validation in the accessor functions.

---

### MED-04: Netlink Path Dump Reads conn_id on Every Iteration

**File**: `/Users/justinadams/Downloads/tquic-kernel/net/tquic/tquic_netlink.c`
**Lines**: 1006-1011

```c
if (!attrs[TQUIC_NL_ATTR_CONN_ID]) {
    NL_SET_ERR_MSG(cb->extack, "Connection ID required");
    return -EINVAL;
}

ctx->conn_id = nla_get_u64(attrs[TQUIC_NL_ATTR_CONN_ID]);
```

**Description**: In `tquic_nl_cmd_path_dump()`, the connection ID is re-read from attributes on every dump iteration (netlink dump callbacks are called repeatedly). The `ctx->conn_id` is overwritten each time. This is a correctness issue rather than a security issue, but if the attributes could theoretically change between calls (they cannot in current genetlink), it could cause confusion. More importantly, the `tquic_conn_lookup()` takes a reference on each call but only releases it once at the end, so if the dump callback is called N times for a large path list, N-1 reference increments are leaked.

Actually, examining more carefully: each dump call does `tquic_conn_lookup` (refcount_inc) and `tquic_nl_conn_put` (refcount_dec) in a single call, so the refcount is balanced per call. This is correct.

**Impact**: Low -- no actual reference leak, but redundant work on each iteration.

---

### MED-05: Load Balancer Nonce Counter Wraps Without Re-keying

**File**: `/Users/justinadams/Downloads/tquic-kernel/net/tquic/lb/quic_lb.c`
**Lines**: 136-138

```c
spin_lock(&cfg->lock);
counter = cfg->nonce_counter++;
spin_unlock(&cfg->lock);
```

**Description**: The nonce counter is a `u64` that increments monotonically. While a 64-bit counter will not wrap in practice for a single config lifetime, the counter is initialized with a random value (`get_random_bytes`), so depending on the starting value, it could wrap sooner than expected. More concerning: in AES-ECB single-pass mode, if the same nonce is reused (due to wrap or counter reset after module reload), the same server_id + nonce pair produces the same CID, breaking unlinkability.

**Impact**: After counter wrap or module reload, CID collisions could allow connection correlation by a passive observer.

**Fix**: Detect counter wrap and refuse to generate nonces, or use a larger state that combines counter with additional randomness.

---

### MED-06: Tunnel Port Allocation Unsigned Underflow

**File**: `/Users/justinadams/Downloads/tquic-kernel/net/tquic/tquic_tunnel.c`
**Lines**: 104-105

```c
bit = ntohs(port) - ntohs(client->port_range_start);
if (bit >= TQUIC_PORTS_PER_CLIENT)
    return;
```

**Description**: The variable `bit` is `unsigned long`. If `ntohs(port) < ntohs(client->port_range_start)`, the subtraction wraps to a very large positive value. The `>= TQUIC_PORTS_PER_CLIENT` check catches this case correctly (the wrapped value will be much larger than 1000), so the function returns safely. However, this relies on unsigned wrap behavior and would be clearer with an explicit check.

**Impact**: None (correctly handled by bounds check), but defense-in-depth could be improved.

---

### MED-07: Exfil Context set_level Destroys and Reinitializes Without Lock

**File**: `/Users/justinadams/Downloads/tquic-kernel/net/tquic/security/quic_exfil.c`
**Lines**: 1443-1465

```c
void tquic_exfil_ctx_set_level(struct tquic_exfil_ctx *ctx,
                               enum tquic_exfil_protection_level level)
{
    ...
    /* Reinitialize shaper and spin with new level */
    tquic_traffic_shaper_destroy(&ctx->shaper);
    tquic_traffic_shaper_init(&ctx->shaper, level);

    tquic_spin_randomizer_destroy(&ctx->spin_rand);
    tquic_spin_randomizer_init(&ctx->spin_rand, level);

    tquic_packet_jitter_destroy(&ctx->jitter);
    tquic_packet_jitter_init(&ctx->jitter, level);
}
```

**Description**: The context has a `spinlock_t lock` field, but `tquic_exfil_ctx_set_level()` does not acquire it. Destroying and reinitializing the shaper, spin randomizer, and jitter while other threads may be using them (via `tquic_exfil_process_outgoing`) creates a use-after-free / use-during-reinit race condition. The shaper's batch queue, hrtimer, and decoy work are destroyed and reinitialized without synchronization.

**Impact**: Use-after-free, double-free, or crash if the protection level is changed while packets are being processed.

**Fix**: Acquire `ctx->lock` around the destroy/init sequence, or use RCU to swap in a new configuration atomically.

---

## LOW Severity Issues

### LOW-01: Duplicate MODULE_DESCRIPTION/MODULE_LICENSE in quic_exfil.c

**File**: `/Users/justinadams/Downloads/tquic-kernel/net/tquic/security/quic_exfil.c`
**Lines**: 1684-1686, 1763-1765

```c
MODULE_DESCRIPTION("TQUIC QUIC-Exfil Mitigation (draft-iab-quic-exfil)");
MODULE_LICENSE("GPL");
MODULE_AUTHOR("Linux Foundation");
```

**Description**: The MODULE_DESCRIPTION, MODULE_LICENSE, and MODULE_AUTHOR macros are declared twice in the same file. This is a code quality issue that may cause build warnings.

**Impact**: None (build warning only).

---

### LOW-02: Netlink Events Do Not Include Timestamp

**File**: `/Users/justinadams/Downloads/tquic-kernel/net/tquic/tquic_netlink.c`
**Lines**: 1386-1430

**Description**: Netlink event notifications for path up/down/change/migration do not include a kernel timestamp. Userspace tools cannot determine the exact time of events, making debugging and correlation with other log sources difficult.

**Impact**: Reduced observability, no security impact.

---

### LOW-03: Volatile Qualifiers in Constant-Time Functions May Be Insufficient

**File**: `/Users/justinadams/Downloads/tquic-kernel/net/tquic/security/quic_exfil.c`
**Lines**: 306-317

```c
const volatile unsigned char *aa = a;
const volatile unsigned char *bb = b;
```

**Description**: The `volatile` qualifier prevents the compiler from optimizing away reads, but does not prevent speculative execution or microarchitectural side channels. Modern compilers and CPUs may still optimize the loop or execute it speculatively in ways that leak timing information. The kernel provides `crypto_memneq()` for this purpose, which uses architecture-specific barriers.

**Impact**: Timing side-channel may still be exploitable despite the `volatile` annotation, particularly on architectures with speculative execution.

**Fix**: Use `crypto_memneq()` from `<crypto/algapi.h>` instead of a custom implementation.

---

### LOW-04: Load Balancer Stack Buffers for Feistel Not Zeroized on Error

**File**: `/Users/justinadams/Downloads/tquic-kernel/net/tquic/lb/quic_lb.c`
**Lines**: 262-306

**Description**: The `left[16]`, `right[16]`, `tmp[16]`, and `round_out[16]` buffers in `tquic_lb_encrypt_four_pass()` and `tquic_lb_decrypt_four_pass()` are not zeroized on error return paths. While stack memory is less persistent than heap, in a kernel with KASAN or stack reuse, residual plaintext/key-derived data could be observable.

**Impact**: Minor information disclosure risk in specialized attack scenarios.

**Fix**: Add `memzero_explicit()` calls in error paths and at function exit.

---

### LOW-05: Netlink Family Exported as EXPORT_SYMBOL_GPL

**File**: `/Users/justinadams/Downloads/tquic-kernel/net/tquic/tquic_netlink.c`
**Line**: 1635

```c
EXPORT_SYMBOL_GPL(tquic_genl_family);
```

**Description**: Exporting the entire `genl_family` structure allows other modules to directly manipulate the netlink family or send events on its behalf. This is unusual; typically only specific helper functions are exported.

**Impact**: Other kernel modules could send spoofed TQUIC events to userspace listeners.

**Fix**: Export only the specific notification helper functions, not the family structure itself.

---

## Summary

| Severity | Count | Key Themes |
|----------|-------|------------|
| CRITICAL | 4 | Namespace escape, SSRF bypass (IPv4-mapped IPv6, missing private range checks), server ID disclosure |
| HIGH | 6 | Function pointer in skb->cb, missing CAP_NET_ADMIN, key material not zeroized, OOB read in CT validation, unbounded connections, sleeping in packet path |
| MEDIUM | 7 | Integer underflow in decoy size, Feistel data corruption at len=32, sysctl validation, nonce counter wrap, port allocation clarity, race in set_level |
| LOW | 5 | Duplicate module macros, missing timestamps, volatile insufficiency, stack buffer cleanup, over-exported symbol |

### Priority Remediation Order

1. **CRIT-01** (namespace escape) -- immediate fix required
2. **CRIT-02 + CRIT-03** (SSRF bypass) -- immediate fix required
3. **HIGH-02** (missing CAP_NET_ADMIN on tunnel creation) -- immediate fix required
4. **HIGH-06** (sleeping in packet path) -- kernel panic risk
5. **HIGH-01** (function pointer in skb->cb) -- design fix needed
6. **HIGH-03** (key zeroization) -- straightforward fix
7. **CRIT-04** (plaintext mode warning) -- configuration hardening
8. **HIGH-04** (OOB read in CT validation) -- bounds fix
9. **HIGH-05** (unbounded connections) -- add limit
10. **MED-07** (race in set_level) -- locking fix
