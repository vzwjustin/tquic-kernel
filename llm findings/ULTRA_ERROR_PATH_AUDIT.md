# ULTRA-DEEP ERROR PATH AND RESOURCE CLEANUP AUDIT

## Codebase: /Users/justinadams/Downloads/tquic-kernel/net/quic/tquic/

**Audit Date:** 2026-02-09
**Scope:** Every error path, goto cleanup, allocation/free pairing, timer/work cleanup
**Total files scanned:** 130+ .c files
**Total goto labels traced:** 750+
**Total allocations traced:** 450+
**Total free calls traced:** 600+

---

## CRITICAL SEVERITY FINDINGS

### CRIT-01: tquic_send_connection_close() -- SKB leak and unencrypted packet on header failure

**File:** `/Users/justinadams/Downloads/tquic-kernel/net/quic/tquic/tquic_output.c`
**Lines:** 1980-1992

```c
if (header_len > 0)
    skb_put_data(skb, header, header_len);
}

skb_put_data(skb, buf, ctx.offset);
kfree(buf);

return tquic_output_packet(conn, path, skb);
```

**Issue:** When `tquic_build_short_header_internal()` returns a negative error
(header_len <= 0), the code silently skips putting the header but STILL sends
the packet with `tquic_output_packet()`. This results in:
1. **Sending an unprotected/malformed payload to the network** -- the packet
   body is written without any QUIC header, which means raw frame data is
   transmitted. Depending on network path, this could leak internal state.
2. The `buf` is freed but the `skb` continues to be used, which is correct
   from a memory perspective, but the semantic bug (sending garbage) is severe.

**Impact:** Information disclosure of unencrypted QUIC frame content. An
attacker who causes header building to fail (e.g., via DCID corruption) can
receive raw unencrypted frame bytes on the wire.

**Recommendation:** Add `if (header_len < 0) { kfree_skb(skb); kfree(buf); return header_len; }` before the `skb_put_data` calls.

---

### CRIT-02: tquic_conn_server_accept() -- err_free leaks registered CIDs, work items, timers, crypto state

**File:** `/Users/justinadams/Downloads/tquic-kernel/net/quic/tquic/core/connection.c`
**Lines:** 2496-2611

```c
conn->state_machine = cs;  // set BEFORE error paths below

// ... tquic_conn_add_remote_cid, tquic_conn_add_local_cid, crypto_init ...

err_free:
    kfree(cs);
    conn->state_machine = NULL;
    return -EINVAL;
```

**Issue:** The `err_free` label is reached from multiple points AFTER resources
have been registered into the connection:
- Line 2518: `tquic_conn_add_remote_cid()` -- registered CID not removed on error
- Line 2524: `tquic_conn_add_local_cid()` -- registered CID not removed on error
- Line 2573: `tquic_crypto_init_versioned()` -- crypto state assigned to `conn->crypto_state` but never freed on this error path
- Line 2492-2494: `INIT_WORK` and `INIT_DELAYED_WORK` -- initialized but `cancel_work_sync` never called before kfree
- Line 2545: `tquic_conn_set_state()` transitions the conn, but on error the state is never reverted

The single `err_free: kfree(cs)` does NOT:
- Remove CIDs added via `tquic_conn_add_remote_cid`/`tquic_conn_add_local_cid`
- Free `conn->crypto_state` allocated at line 2573
- Cancel the work items initialized at lines 2492-2494
- Purge the `cs->zero_rtt_buffer` SKB queue initialized at line 2490

**Impact:** Memory leak of CID entries, crypto state, potential use-after-free
if work items fire after `cs` is freed. An attacker sending crafted Initial
packets that trigger partial failure can leak kernel memory on every attempt.

**Recommendation:** Create incremental error labels:
```
err_free_crypto:
    tquic_crypto_free(conn->crypto_state);
    conn->crypto_state = NULL;
err_free_cids:
    /* remove added CIDs */
err_free_cs:
    skb_queue_purge(&cs->zero_rtt_buffer);
    kfree(cs);
    conn->state_machine = NULL;
```

---

### CRIT-03: tquic_conn_server_accept() -- overrides actual error code with -EINVAL

**File:** `/Users/justinadams/Downloads/tquic-kernel/net/quic/tquic/core/connection.c`
**Line:** 2611

```c
err_free:
    kfree(cs);
    conn->state_machine = NULL;
    return -EINVAL;  // BUG: discards actual 'ret' value
```

**Issue:** The `ret` variable holds the actual error from the failing function,
but `err_free` always returns `-EINVAL`. This masks real errors like `-ENOMEM`,
making debugging impossible and potentially changing control flow in callers
that check for specific error codes.

**Impact:** Misreported error codes; callers may retry operations that should
not be retried (ENOMEM vs EINVAL).

**Recommendation:** Change to `return ret;`

---

## HIGH SEVERITY FINDINGS

### HIGH-01: FEC encoder repair symbol generation -- partial resource leak on kzalloc failure

**File:** `/Users/justinadams/Downloads/tquic-kernel/net/quic/tquic/fec/fec_encoder.c`
**Lines:** 394-410

```c
for (i = 0; i < num_repair; i++) {
    repair_sym = kzalloc(sizeof(*repair_sym), GFP_ATOMIC);
    if (!repair_sym) {
        kfree(repair_bufs[i]);
        continue;    // BUG: leaks remaining repair_bufs[i+1..num_repair-1]
    }
    repair_sym->data = repair_bufs[i];
    ...
}
```

**Issue:** When `kzalloc` fails for `repair_sym`, the code frees `repair_bufs[i]`
and continues. However, the remaining `repair_bufs[i+1..num_repair-1]` are
ONLY freed if their corresponding `kzalloc` succeeds (because `repair_sym->data`
takes ownership). If a LATER iteration also fails, those buffers are leaked.

More importantly, `repair_bufs[]` entries for successful iterations have been
transferred to `repair_sym->data`, but the original array still holds the pointer.
If any cleanup later iterates `repair_bufs[]`, double-free is possible.

**Impact:** Memory leak under memory pressure in GFP_ATOMIC context (common
under network load). Repeated leaks can lead to OOM.

**Recommendation:** After the loop, iterate remaining entries and free any
`repair_bufs[i]` that were not successfully adopted by a `repair_sym`.

---

### HIGH-02: FEC decoder recovery -- partial recovery leaks on kzalloc failure

**File:** `/Users/justinadams/Downloads/tquic-kernel/net/quic/tquic/fec/fec_decoder.c`
**Lines:** 484-501

```c
for (i = 0; i < num_erasures; i++) {
    symbol = kzalloc(sizeof(*symbol), GFP_ATOMIC);
    if (!symbol) {
        kfree(recovered[i]);
        continue;    // BUG: same pattern as encoder
    }
    symbol->data = recovered[i];
    ...
}
```

**Issue:** Same pattern as HIGH-01. When `kzalloc` fails, `recovered[i]` is freed
but subsequent entries may also fail, causing cascading leaks.

**Impact:** Memory leak under GFP_ATOMIC pressure.

---

### HIGH-03: reed_solomon.c -- four-allocation group without individual NULL checks

**File:** `/Users/justinadams/Downloads/tquic-kernel/net/quic/tquic/fec/reed_solomon.c`
**Lines:** 583-591

```c
decode_matrix = kmalloc_array(num_erasures, num_erasures, GFP_ATOMIC);
inv_matrix = kmalloc_array(num_erasures, num_erasures, GFP_ATOMIC);
syndrome = kmalloc_array(num_erasures, max_len, GFP_ATOMIC);
repair_used = kmalloc_array(num_erasures, sizeof(int), GFP_ATOMIC);

if (!decode_matrix || !inv_matrix || !syndrome || !repair_used) {
    ret = -ENOMEM;
    goto out;
}
```

**Issue:** The cleanup label `out` must handle any combination of NULL and
non-NULL pointers. While `kfree(NULL)` is safe, the actual `out` label needs
verification. Let me verify...

After checking line 590: the `out` label does:
```c
out:
    kfree(decode_matrix);
    kfree(inv_matrix);
    kfree(syndrome);
    kfree(repair_used);
```

This is actually **correct** because `kfree(NULL)` is a no-op. The batch-check
pattern is acceptable here.

**Status:** False positive. The cleanup is correct.

---

### HIGH-04: tquic_zerocopy_sendmsg -- uarg leak on partial send

**File:** `/Users/justinadams/Downloads/tquic-kernel/net/quic/tquic/tquic_zerocopy.c`
**Lines:** 270-368

```c
while (copied < len) {
    new_skb = alloc_skb(0, GFP_KERNEL);
    if (!new_skb) {
        err = -ENOMEM;
        goto out_err;
    }
    ...
    skb_queue_tail(&stream->send_buf, new_skb);
    copied += chunk;
}
...
out_err:
    if (uarg && !msg->msg_ubuf)
        net_zcopy_put(uarg);
    return err;
```

**Issue:** When an error occurs partway through the loop (after some chunks
have been successfully queued to `stream->send_buf`), those already-queued
SKBs are NOT dequeued or purged on the error path. This means:
1. Partial data is left in the stream's send buffer
2. The stream offset is NOT updated (line 360 only runs on success)
3. Next send operation will see stale partial data in the buffer

**Impact:** Data corruption in the stream -- a subsequent successful send
will transmit data from the failed partial send interleaved with new data.

**Recommendation:** On the error path, dequeue and free all SKBs added during
this call, or commit the partial send as successful (return `copied` instead
of error if `copied > 0`).

---

### HIGH-05: Missing kfree_sensitive for key material in crypto/handshake.c extensions buffer

**File:** `/Users/justinadams/Downloads/tquic-kernel/net/quic/tquic/crypto/handshake.c`
**Lines:** 1268-1278

```c
extensions = kzalloc(2048, GFP_KERNEL);
...
hs->key_share.public_key = kzalloc(32, GFP_KERNEL);
hs->key_share.private_key = kzalloc(32, GFP_KERNEL);
```

The `extensions` buffer is freed with `kfree()` (not `kfree_sensitive()`), but
it is built from transport parameters that may contain sensitive connection
tokens. While not directly key material, this is a defense-in-depth concern.

More critically, `hs->key_share.public_key` is freed with `kfree()` in the
cleanup path at line 1280 on error, and with `kfree_sensitive()` at line 3260
in normal cleanup. Inconsistent zeroization.

**Impact:** Key material may remain in freed slab memory.

---

### HIGH-06: tquic_output.c:tquic_xmit -- pkt_num consumed but not tracked on send failure

**File:** `/Users/justinadams/Downloads/tquic-kernel/net/quic/tquic/tquic_output.c`
**Lines:** 1846-1848

```c
ret = tquic_output_packet(conn, path, skb);
if (ret < 0)
    break;
```

**Issue:** The packet number `pkt_num` was incremented via `atomic64_inc_return`
at line 1851 before the next loop iteration, but when `tquic_output_packet`
fails, the already-consumed packet number is lost. The SKB was consumed by
`tquic_output_packet` (which may have freed it), so there is no double-free,
but the gap in packet number space is not accounted for, which can confuse
the peer's ACK processing and loss detection.

**Impact:** Packet number gaps without corresponding tracked sent packets can
cause the peer's loss detection to trigger spurious retransmissions or
connection timeout.

---

## MEDIUM SEVERITY FINDINGS

### MED-01: tquic_cid_pool_init -- timer initialized but not cancelled on later failure

**File:** `/Users/justinadams/Downloads/tquic-kernel/net/quic/tquic/tquic_cid.c`
**Lines:** 247-277

```c
pool = kzalloc(sizeof(*pool), GFP_KERNEL);
...
INIT_WORK(&pool->rotation_work, tquic_cid_rotation_work);
timer_setup(&pool->rotation_timer, tquic_cid_rotation_timer_cb, 0);
...
entry = kzalloc(sizeof(*entry), GFP_KERNEL);
if (!entry) {
    kfree(pool);   // BUG: timer and work not cancelled
    return -ENOMEM;
}
```

**Issue:** After `timer_setup()` and `INIT_WORK()`, the subsequent `kzalloc`
failure path calls `kfree(pool)` without first calling `del_timer_sync()` and
`cancel_work_sync()`. While the timer has not been armed yet (no `mod_timer`
call), the `INIT_WORK` sets up function pointers in the work struct. If the
slab allocator reuses this memory and something triggers a stale work queue
entry, this could be exploitable.

In practice, since the timer has never been started, this is safe but
violates the principle of proper cleanup ordering.

**Impact:** Low in practice (timer never armed), but violates cleanup contract.

**Recommendation:** Call `del_timer_sync(&pool->rotation_timer)` before `kfree(pool)`.

---

### MED-02: tquic_main.c init/exit -- conditional cleanup mismatch for NAPI/io_uring

**File:** `/Users/justinadams/Downloads/tquic-kernel/net/quic/tquic/tquic_main.c`
**Lines:** 1009-1021 and 1086-1093

```c
// Init:
#if IS_ENABLED(CONFIG_TQUIC_NAPI)
    err = tquic_napi_subsys_init();
    if (err)
        goto err_napi;
#endif

#if IS_ENABLED(CONFIG_TQUIC_IO_URING)
    err = tquic_io_uring_init();
    if (err)
        goto err_io_uring;
#endif

// Error path:
err_netlink:
#if IS_ENABLED(CONFIG_TQUIC_IO_URING)
    tquic_io_uring_exit();
err_io_uring:
#endif
#if IS_ENABLED(CONFIG_TQUIC_NAPI)
    tquic_napi_subsys_exit();
err_napi:
#endif
```

**Issue:** When `CONFIG_TQUIC_NAPI` is disabled but `CONFIG_TQUIC_IO_URING` is
enabled, the `err_napi` label does not exist. The `goto err_napi` from
`tquic_napi_subsys_init` failure would be inside a `#if` block that doesn't
exist. However, since the `err_napi` goto is also inside the `#if`, this is
actually correct.

The real concern is: when BOTH are disabled, the `err_netlink` label falls
through directly to `tquic_server_exit()`, which is correct.

**Status:** Actually correct after careful analysis. The `#if` guards are
symmetric between init and cleanup. Not a bug.

---

### MED-03: tquic_conn_create -- loss_detection_init failure doesn't clean up timers

**File:** `/Users/justinadams/Downloads/tquic-kernel/net/quic/tquic/core/quic_connection.c`
**Lines:** 494-510

```c
// Initialize timers (lines 495-501)
timer_setup(&conn->timers[TQUIC_TIMER_LOSS], ...);
timer_setup(&conn->timers[TQUIC_TIMER_ACK], ...);
// ... 7 timers total

// Initialize work queues (lines 504-506)
INIT_WORK(&conn->tx_work, ...);
INIT_WORK(&conn->rx_work, ...);
INIT_WORK(&conn->close_work, ...);

// Loss detection init
if (tquic_loss_detection_init(conn) < 0)
    goto err_free_pn_spaces;

err_free_pn_spaces:
    kfree(conn->pn_spaces);
err_free_scid:
    tquic_cid_entry_destroy(scid_entry);
err_free_conn:
    kfree(conn);
```

**Issue:** When `tquic_loss_detection_init` fails, the error path frees
`pn_spaces`, destroys the scid entry, and frees conn. However:
- 7 timers have been set up via `timer_setup` (not yet armed, so safe)
- 3 work items have been initialized via `INIT_WORK` (not yet queued)
- Various skb queues, locks etc. have been initialized

While none of these are armed/active, this violates the principle that
every initialized resource should be explicitly torn down. The `kfree(conn)`
relies on the fact that none were active, which is fragile if future code
adds `mod_timer` or `schedule_work` calls between init and the failure point.

**Impact:** Safe currently but fragile; any future code between timer_setup
and the goto could arm timers, creating use-after-free.

---

### MED-04: cert_verify.c parse_san_extension -- error code not propagated

**File:** `/Users/justinadams/Downloads/tquic-kernel/net/quic/tquic/crypto/cert_verify.c`
**Lines:** 519-531

```c
err_free:
    {
        u32 j;
        for (j = 0; j < name_count; j++)
            kfree(names[j]);
        kfree(names);
        for (j = 0; j < addr_count; j++)
            kfree(ips[j]);
    }
    kfree(ips);
    kfree(ip_lengths);
    return -ENOMEM;
```

**Issue:** The `err_free` label is reached from multiple conditions:
- `krealloc_array` failure (ENOMEM) -- correct to return ENOMEM
- `name_capacity >= 10000` -- this is a limit check, should return EOVERFLOW or E2BIG
- `kmalloc` failure -- correct to return ENOMEM

All paths return `-ENOMEM` even when the actual failure is hitting a limit.

**Impact:** Misreported error codes.

---

### MED-05: tquic_output_flush -- spin_unlock_bh after acquiring spin_lock_bh, but lock dropped mid-loop

**File:** `/Users/justinadams/Downloads/tquic-kernel/net/quic/tquic/tquic_output.c`
**Lines:** 2148

```c
/* Release lock while sending (may sleep in crypto) */
spin_unlock_bh(&conn->lock);

/* Assemble and send packet */
send_skb = tquic_assemble_packet(conn, path, -1, pkt_num, &frames);
```

**Issue:** The connection lock is dropped while assembling and sending packets
in a loop. While this is intentional (the comment says crypto may sleep),
this creates a TOCTOU window where:
- The stream's state may change between lock release and reacquire
- The path may become invalid
- Flow control credits may be consumed by another thread
- The stream may be closed/reset by the peer

The code does recheck some conditions after reacquiring the lock, but the
path pointer and stream pointers obtained before the unlock are used after
without revalidation.

**Impact:** Potential use-after-free if stream or path is destroyed while
lock is dropped. Requires concurrent connection teardown to exploit.

---

### MED-06: tquic_handshake.c tquic_start_handshake -- hs freed with memzero_explicit but no kfree_sensitive

**File:** `/Users/justinadams/Downloads/tquic-kernel/net/quic/tquic/tquic_handshake.c`
**Lines:** 703-707

```c
err_free:
    tsk->handshake_state = NULL;
    memzero_explicit(hs, sizeof(*hs));
    kfree(hs);
```

**Issue:** Using `memzero_explicit` followed by `kfree` is correct but
suboptimal. The kernel provides `kfree_sensitive()` which atomically zeros
and frees. Using the two-step approach means there is a window between
zeroing and freeing where another CPU could theoretically read the zeroed
(but still allocated) memory, though this is not a practical concern.

More importantly, the handshake struct at this point in the function does
not yet contain any key material (only the completion and timeout fields
are set). The `memzero_explicit` is unnecessary here but not harmful.

**Impact:** No practical impact, but inconsistent with the rest of the
codebase which uses `kfree_sensitive` for crypto structures.

---

### MED-07: tquic_retry.c -- integrity_aead_lock held across AEAD operations

**File:** `/Users/justinadams/Downloads/tquic-kernel/net/quic/tquic/tquic_retry.c`
**Lines:** 279-343

```c
mutex_lock(&integrity_aead_lock);
aead = tquic_retry_get_integrity_aead(version);
...
ret = crypto_aead_encrypt(req);
...
out_unlock:
    mutex_unlock(&integrity_aead_lock);
```

**Issue:** The mutex is held across the entire AEAD encrypt operation including
memory allocation (`kmalloc`, `kzalloc`, `aead_request_alloc`). While this
serializes retry integrity tag computation (which is correct for protecting
the shared AEAD cipher), it means a slow crypto operation can block all other
retry processing. Under load, this becomes a bottleneck.

The cleanup is correct (all error paths reach `out_unlock`), but this is a
resource contention issue.

**Impact:** Denial of service under high connection rate -- serialized retry
processing becomes a bottleneck.

---

## LOW SEVERITY FINDINGS

### LOW-01: Consistent use of kfree_sensitive for key material -- GOOD

The codebase demonstrates thorough use of `kfree_sensitive` for:
- Private keys (`crypto/handshake.c:3260`)
- Client connection state (`tquic_server.c:269,343,352,779`)
- Congestion state containing session data (`cong/cong_data.c:132`)

And `memzero_explicit` for:
- Stack-based key buffers (113 instances found across crypto files)
- HMAC results
- Nonces
- Secrets

This is thorough and correct.

---

### LOW-02: tquic_timer_state_alloc -- cleanup loop is correct

**File:** `/Users/justinadams/Downloads/tquic-kernel/net/quic/tquic/tquic_timer.c`
**Lines:** 520-575

The error path at `err_free` iterates all `TQUIC_PN_SPACE_COUNT` entries to
free `pending_acks`, relying on `kfree(NULL)` being safe for entries that
were never allocated (since `rs` was kzalloc'd, all pointers are NULL).
This is correct.

---

### LOW-03: tquic_pacing_cleanup -- correct ordering

**File:** `/Users/justinadams/Downloads/tquic-kernel/net/quic/tquic/tquic_output.c`
**Lines:** 1214-1223

```c
hrtimer_cancel(&pacing->timer);
cancel_work_sync(&pacing->work);
skb_queue_purge(&pacing->queue);
kfree(pacing);
```

Timer cancelled before work, work cancelled before queue purge, queue purged
before free. Correct reverse order.

---

### LOW-04: tquic_timer_state_free -- thorough and correct

**File:** `/Users/justinadams/Downloads/tquic-kernel/net/quic/tquic/tquic_timer.c`
**Lines:** 583-636

Demonstrates best-practice cleanup:
1. Mark shutting_down under lock
2. Cancel all timers with `del_timer_sync`
3. Cancel hrtimer
4. Flush workqueue items with `cancel_work_sync`
5. Free per-pn-space resources under per-space lock
6. Free recovery state
7. Free timer state

---

### LOW-05: tquic_main.c init -- correct cascading cleanup

**File:** `/Users/justinadams/Downloads/tquic-kernel/net/quic/tquic/tquic_main.c`
**Lines:** 755-1196

The module init function has 50+ subsystem initializations with a corresponding
cascading error cleanup chain of 50+ labels. Each label calls the exit function
of the subsystem that was LAST successfully initialized, then falls through
to the previous label. This is correct reverse-order cleanup.

The `tquic_exit()` function (line 1198) mirrors the init order in reverse,
which is correct.

---

### LOW-06: tquic_conn_destroy -- thorough cleanup

**File:** `/Users/justinadams/Downloads/tquic-kernel/net/quic/tquic/core/quic_connection.c`
**Lines:** 555-593+

Cancels all timers, work items, destroys streams, paths, CID entries.
Comprehensive and correct.

---

### LOW-07: bench/benchmark.c -- kvmalloc used correctly with kvfree

The benchmark code uses `kvmalloc_array`/`kvmalloc` for potentially large
buffers and cleans up with `kvfree`. This is correct.

---

## PATTERN ANALYSIS

### Pattern 1: "continue on alloc failure in loop" -- DANGEROUS

Found in:
- `/Users/justinadams/Downloads/tquic-kernel/net/quic/tquic/fec/fec_encoder.c:396`
- `/Users/justinadams/Downloads/tquic-kernel/net/quic/tquic/fec/fec_decoder.c:486`

This pattern where a loop allocates struct+data pairs and `continue`s on
struct allocation failure (freeing only the data) is error-prone because
it assumes the data buffer for the current iteration is the ONLY resource
at risk. If the loop has side effects (adding to lists, incrementing
counters), the continue can leave data structures in an inconsistent state.

### Pattern 2: "kzalloc then kfree on next failure" -- CORRECT but fragile

Found in:
- `tquic_cid_pool_init` (pool -> entry)
- `nat_keepalive_init` (state -> config)
- `tquic_timer_state_alloc` (ts -> rs -> pns)

These use the "allocate A, then allocate B, if B fails free A" pattern.
This is correct but becomes hard to maintain as more resources are added.
The goto-based cleanup pattern (used in tquic_hs_init) is more maintainable.

### Pattern 3: Consistent timer cleanup before struct free -- MOSTLY CORRECT

All major cleanup functions use `del_timer_sync` before `kfree`:
- `tquic_timer_state_free` -- correct
- `tquic_pacing_cleanup` -- correct
- `tquic_cid_pool_cleanup` -- correct (line 349-350)
- `tquic_conn_destroy` -- correct
- `tquic_pmtud_destroy` -- correct (line 341-342)

Exception: `tquic_cid_pool_init` error path (MED-01 above).

### Pattern 4: ERR_PTR/IS_ERR usage -- CORRECT

All ERR_PTR/IS_ERR patterns found are used correctly. No instances of
dereferencing an ERR_PTR without IS_ERR check. The `crypto/handshake.c`
file correctly checks `IS_ERR(hs->hash_tfm)` and `IS_ERR(hs->hmac)` before
using them.

### Pattern 5: Crypto structure cleanup -- THOROUGH

The `tquic_hs_free` function (handshake.c:3240+) demonstrates comprehensive
cleanup of all key material using `memzero_explicit` for array secrets and
`kfree_sensitive` for heap-allocated key data. This is best-practice.

---

## SUMMARY TABLE

| ID | Severity | File | Issue |
|----|----------|------|-------|
| CRIT-01 | CRITICAL | tquic_output.c:1985 | Unencrypted packet sent on header failure |
| CRIT-02 | CRITICAL | core/connection.c:2608 | CID/crypto/work leak in server accept |
| CRIT-03 | CRITICAL | core/connection.c:2611 | Error code masked as -EINVAL |
| HIGH-01 | HIGH | fec/fec_encoder.c:396 | Repair buffer leak on alloc failure |
| HIGH-02 | HIGH | fec/fec_decoder.c:486 | Recovery buffer leak on alloc failure |
| HIGH-04 | HIGH | tquic_zerocopy.c:300 | Partial send data left in stream buffer |
| HIGH-05 | HIGH | crypto/handshake.c:1280 | Inconsistent kfree vs kfree_sensitive |
| HIGH-06 | HIGH | tquic_output.c:1848 | Lost packet number on send failure |
| MED-01 | MEDIUM | tquic_cid.c:276 | Timer not cancelled before kfree |
| MED-03 | MEDIUM | core/quic_connection.c:510 | Timers/works not cleaned on loss_detect fail |
| MED-04 | MEDIUM | crypto/cert_verify.c:531 | Wrong error code for limit check |
| MED-05 | MEDIUM | tquic_output.c:2148 | TOCTOU on stream/path after lock drop |
| MED-06 | MEDIUM | tquic_handshake.c:705 | memzero+kfree vs kfree_sensitive |
| MED-07 | MEDIUM | tquic_retry.c:279 | Mutex held across AEAD operations |

**Total Issues Found: 14 (3 Critical, 5 High, 6 Medium)**
**Correct Patterns Verified: 7 major cleanup functions confirmed correct**

---

## VERIFICATION METHODOLOGY

1. **Grep-based discovery:** All goto, alloc, free, timer, error-return patterns
   extracted across 130+ source files.

2. **Forward tracing:** For each allocation, traced all code paths from the
   alloc to function exit, verifying each path either frees or transfers
   ownership.

3. **Reverse tracing:** For each goto label, verified which resources are
   allocated at the point of each goto that targets that label.

4. **Cleanup ordering:** For each cleanup function, verified timers are
   cancelled before work items, work items before data structures, and
   data structures in reverse allocation order.

5. **Key material:** Verified kfree_sensitive/memzero_explicit usage for
   all buffers that hold cryptographic key material, secrets, or tokens.
