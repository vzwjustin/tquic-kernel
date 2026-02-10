# TQUIC Ultra-Deep Locking Audit Report

**Date**: 2026-02-09
**Auditor**: Claude Opus 4.6 (Security Reviewer Agent)
**Scope**: Every locking pattern in `/Users/justinadams/Downloads/tquic-kernel/net/quic/tquic/`

---

## Executive Summary

The TQUIC codebase contains approximately 500+ lock acquisition/release sites across 40+ source files. The codebase defines a clear lock hierarchy in `protocol.h` (lines 12-58), which is mostly followed. However, the audit identified **4 Critical**, **6 High**, **5 Medium**, and **4 Low** severity issues.

---

## 1. Lock Inventory

### 1.1 Documented Lock Hierarchy (protocol.h:12-58)

```
1. sk->sk_lock.slock (socket lock - lock_sock/release_sock)
   |
   +-- 2. conn->lock (connection state lock - spin_lock_bh)
             |
             +-- 3. path->state_lock (per-path state)
                       |
                       +-- 4. cc->lock (congestion control)
                                 |
                                 +-- 5. stream->lock (per-stream)
```

### 1.2 All Locks Identified

| Lock | Type | Variant | Files Using |
|------|------|---------|-------------|
| `sk->sk_lock` | socket lock | lock_sock/release_sock | tquic_socket.c, quic_protocol.c, af_xdp.c, tquic_zerocopy.c, quic_over_tcp.c |
| `conn->lock` | spinlock | spin_lock_bh | tquic_input.c, tquic_main.c, tquic_stream.c, tquic_output.c, tquic_timer.c, tquic_cid.c, and ~40 more files |
| `conn->paths_lock` | spinlock | spin_lock_bh / spin_lock | tquic_input.c |
| `conn->streams_lock` | spinlock | spin_lock_bh | tquic_input.c |
| `conn->datagram.lock` | spinlock | spin_lock | tquic_input.c |
| `ts->lock` | spinlock | spin_lock_bh | tquic_timer.c |
| `pns->lock` | spinlock | spin_lock / spin_lock_bh | tquic_timer.c |
| `rs->lock` | spinlock | spin_lock / spin_lock_bh | tquic_timer.c |
| `path->state_lock` | spinlock | spin_lock_bh | bond/tquic_bpm.c |
| `path->cc_lock` | spinlock | spin_lock_bh | bond/tquic_bpm.c |
| `bc->state_lock` | spinlock | spin_lock_bh | bond/tquic_bonding.c |
| `ctx->lock` (coupled CC) | spinlock | spin_lock_bh | bond/cong_coupled.c |
| `enc->lock` / `block->lock` | spinlock | spin_lock_bh / spin_lock | fec/fec_encoder.c |
| `pool->lock` (CID pool) | spinlock | spin_lock_bh | tquic_cid.c |
| `rb->buffer_lock` | spinlock | spin_lock_bh | bond/tquic_reorder.c |
| `fc->sent_packets_lock` | spinlock | spin_lock_bh | bond/tquic_failover.c |
| `fc->retx_queue.lock` | spinlock | spin_lock_bh | bond/tquic_failover.c |
| `fc->dedup.lock` | spinlock | spin_lock_init only | bond/tquic_failover.c |
| `h3conn->lock` | spinlock | spin_lock | http3/http3_stream.c |
| `state->lock` (deadline sched) | spinlock | spin_lock_bh | sched/deadline_aware.c |
| `pm->lock` (BPM) | spinlock | spin_lock_bh | bond/tquic_bpm.c |
| `tquic_bpm_list_lock` | spinlock | spin_lock_bh | bond/tquic_bpm.c |
| `tquic_nf_lock` | spinlock | spin_lock_bh | tquic_nf.c |
| `tquic_udp_hash_lock` | spinlock | spin_lock_bh | tquic_udp.c |
| `tquic_listener_lock` | spinlock | spin_lock_bh | tquic_udp.c |
| `port_alloc.lock` | spinlock | spin_lock_bh | tquic_udp.c |
| `tquic_nic_lock` | spinlock | spin_lock | offload/smartnic.c |
| `tquic_sched_lock` | spinlock | spin_lock | sched/scheduler.c |
| `bucket->lock` (rate limit) | spinlock | spin_lock_irqsave | tquic_ratelimit.c |
| `ring->lock` (error ring) | spinlock | spin_lock | tquic_proc.c |
| `gro->lock` | spinlock | spin_lock | tquic_input.c |
| `cfg->lock` (LB) | spinlock | spin_lock | lb/quic_lb.c |
| `zc->lock` (zerocopy) | spinlock | spin_lock_bh | tquic_zerocopy.c |
| `tquic_client_mutex` | mutex | mutex_lock | tquic_server.c |
| `tquic_token_mutex` | mutex | mutex_lock | tquic_token.c |
| `integrity_aead_lock` | mutex | mutex_lock | tquic_retry.c |
| `tquic_retry_mutex` | mutex | mutex_lock | tquic_retry.c |
| `state->pool_locks[slot]` | mutex | mutex_lock | tquic_retry.c |
| `pm_ops_lock` | mutex | mutex_lock | pm/pm_types.c |
| `keyring_mutex` | mutex | mutex_lock | crypto/cert_verify.c |
| `tquic_cid_table_lock` | mutex | mutex_lock | core/cid.c |
| `fuzz_conn_lock` | mutex | mutex_lock | test/fuzz/fuzz_framework.c |

---

## 2. Critical Issues

### CRITICAL-1: List Iterator Invalidation in BPM Netdev Notifier (Drop-Relock Pattern)

**File**: `/Users/justinadams/Downloads/tquic-kernel/net/quic/tquic/bond/tquic_bpm.c`
**Lines**: 1850-1898

```c
rcu_read_lock();
list_for_each_entry_rcu(pm, &tquic_bpm_list, path_list) {
    spin_lock_bh(&pm->lock);
    list_for_each_entry(path, &pm->path_list, list) {
        if (path->ifindex == dev->ifindex &&
            path->state != TQUIC_BPM_PATH_FAILED) {
            spin_unlock_bh(&pm->lock);           // DROPPED
            tquic_bpm_path_set_state(path, ...);  // path may be freed here
            spin_lock_bh(&pm->lock);              // REACQUIRED
            pm->paths_failed++;                    // list iteration continues!
        }
    }
    spin_unlock_bh(&pm->lock);
}
rcu_read_unlock();
```

**Impact**: After dropping `pm->lock` and calling `tquic_bpm_path_set_state()`, another thread could remove or free `path` from the list. When the lock is reacquired, the `list_for_each_entry` macro continues using `path->list.next` which may point to freed memory. This is a **use-after-free** that can be triggered by concurrent netdev events.

The same pattern repeats for `NETDEV_CHANGE` at lines 1876-1898 with TWO separate unlock/relock windows inside the inner loop.

**Severity**: CRITICAL -- Remote attacker could trigger network interface state changes (e.g., via crafted ICMP or triggering PMTU changes) to race with this path, corrupting kernel memory.

**Recommendation**: Use `list_for_each_entry_safe()` is NOT sufficient here since the iteration continues after relock. Instead, collect paths to process into a separate list under the lock, then process them after releasing the lock.

---

### CRITICAL-2: TOCTOU Race in Failover Hysteresis (Atomic Read-Modify-Write)

**File**: `/Users/justinadams/Downloads/tquic-kernel/net/quic/tquic/bond/tquic_failover.c`
**Line**: 198

```c
WRITE_ONCE(pt->consec_failures, READ_ONCE(pt->consec_failures) + 1);
WRITE_ONCE(pt->consec_successes, 0);
```

**Impact**: `READ_ONCE + 1 + WRITE_ONCE` is NOT atomic. Two concurrent timeout callbacks (from different timer expirations) could both read the same value and write the same incremented value, losing an increment. While individual increments being lost is not catastrophic, the combined pattern at lines 198-229 uses the result to make failover decisions:

```c
switch (READ_ONCE(pt->hyst_state)) {        // Line 207
case TQUIC_PATH_HYST_DEGRADED:
    if (READ_ONCE(pt->consec_failures) >= TQUIC_HYST_FAIL_THRESHOLD)
        goto do_failover;                     // Line 230
```

Between the READ_ONCE of `hyst_state` and the READ_ONCE of `consec_failures`, another thread could change both values. This can cause missed failovers or spurious failovers.

Similarly at line 688:
```c
WRITE_ONCE(pt->consec_successes, READ_ONCE(pt->consec_successes) + 1);
```

**Severity**: CRITICAL -- This controls path failover timing. A race could prevent timely failover when a path truly fails (availability impact) or cause unnecessary failovers (performance impact). In a bonded WAN setup, this directly affects connection reliability.

**Recommendation**: Either protect these operations with a per-path spinlock, or use `atomic_inc_return()` / `atomic_set()` with `atomic_t` fields instead of plain integers + READ_ONCE/WRITE_ONCE.

---

### CRITICAL-3: Path Pointer Use After Lock Release

**File**: `/Users/justinadams/Downloads/tquic-kernel/net/quic/tquic/tquic_input.c`
**Lines**: 245-261

```c
static struct tquic_path *tquic_find_path_by_addr(struct tquic_connection *conn,
                                                   struct sockaddr_storage *addr)
{
    struct tquic_path *found = NULL;

    spin_lock_bh(&conn->paths_lock);
    list_for_each_entry(path, &conn->paths, list) {
        if (memcmp(&path->remote_addr, addr, sizeof(*addr)) == 0) {
            found = path;
            break;
        }
    }
    spin_unlock_bh(&conn->paths_lock);

    return found;  // Path can be freed after unlock!
}
```

The comment at line 242-243 says: "The returned path pointer is safe to use only while the caller ensures the connection remains valid." However, the path could be removed from the list and freed between the unlock and the caller's use of the returned pointer. The connection remaining valid does NOT prevent path removal.

The same pattern exists in `tquic_find_path_by_cid` (lines 268-285).

**Severity**: CRITICAL -- This is a classic use-after-free pattern. If a path is removed (e.g., during migration or failover) after the lock is released but before the caller uses the returned pointer, the caller dereferences freed memory.

**Recommendation**: Take a reference on the path before releasing the lock: `tquic_path_get(found)` and require callers to call `tquic_path_put()`.

---

### CRITICAL-4: Nested Lock Hierarchy Violation in Timer Code

**File**: `/Users/justinadams/Downloads/tquic-kernel/net/quic/tquic/tquic_timer.c`
**Lines**: 933-955

```c
// tquic_timer_pto_expired (timer callback, softirq context)
spin_lock_bh(&ts->lock);           // Lock #1: ts->lock
    spin_lock(&rs->lock);           // Lock #2: rs->lock (nested)
    rs->pto_count++;
    spin_unlock(&rs->lock);
spin_unlock_bh(&ts->lock);
```

And at lines 975-1029 (tquic_timer_update_pto):
```c
spin_lock_bh(&ts->lock);           // Lock #1: ts->lock
    for (i = 0; i < TQUIC_PN_SPACE_COUNT; i++) {
        spin_lock(&pns->lock);      // Lock #2: pns->lock (nested)
            spin_lock(&rs->lock);    // Lock #3: rs->lock (TRIPLE nested!)
            spin_unlock(&rs->lock);
        spin_unlock(&pns->lock);
    }
spin_unlock_bh(&ts->lock);
```

Compare with lines 820-870 (tquic_timer_detect_lost):
```c
spin_lock_bh(&pns->lock);           // Lock pns FIRST
    spin_lock(&rs->lock);            // Then rs
    spin_unlock(&rs->lock);
spin_unlock_bh(&pns->lock);
```

**Impact**: The lock ordering is `ts->lock -> pns->lock -> rs->lock` in `tquic_timer_update_pto`, but `pns->lock -> rs->lock` (without ts->lock) in `tquic_timer_detect_lost`. This is not a direct ordering violation, but the triple nesting combined with the fact that `tquic_timer_pto_expired` runs from timer softirq means that if any of these locks are also taken from process context with `_bh` disabled, a softirq deadlock can occur.

Additionally, at line 1628-1677:
```c
spin_lock_bh(&pns->lock);
    list_for_each_entry_safe(pkt, tmp, &pns->sent_list, list) {
        spin_lock(&rs->lock);        // Nested under pns->lock
        spin_unlock(&rs->lock);
    }
spin_unlock_bh(&pns->lock);
```

The same `rs->lock` is also taken as `spin_lock_bh(&rs->lock)` at lines 1782, 1811, and also as `spin_lock(&rs->lock)` at lines 842, 941, 1001, 1090. This mixed `_bh` / non-`_bh` usage of the SAME lock is dangerous -- if the lock is held without `_bh` in process context and a softirq tries to acquire it with `spin_lock_bh`, there is no deadlock. However, if `spin_lock_bh(&rs->lock)` is called at line 1589 from process context while `spin_lock(&rs->lock)` is being held at line 842 from softirq (which cannot happen since 842 is under pns->lock _bh), the overall correctness depends on consistently calling from the right context.

**Severity**: CRITICAL -- While the current code may work due to the softirq execution model, the inconsistent `_bh` usage on `rs->lock` and `pns->lock` is a latent deadlock. A future code change that takes `rs->lock` with `spin_lock(&rs->lock)` from process context would immediately create a softirq deadlock.

**Recommendation**: Standardize ALL uses of `rs->lock` and `pns->lock` to use `spin_lock_bh` / `spin_unlock_bh` consistently, since they are accessed from both timer/softirq context and process context.

---

## 3. High Severity Issues

### HIGH-1: Bonding State Machine Drop-Relock Without Re-validation

**File**: `/Users/justinadams/Downloads/tquic-kernel/net/quic/tquic/bond/tquic_bonding.c`
**Lines**: 456-483

```c
spin_lock_bh(&bc->state_lock);
    // ... state transition logic ...
    if (new_state == TQUIC_BOND_SINGLE_PATH && bc->reorder) {
        spin_unlock_bh(&bc->state_lock);     // DROP LOCK
        tquic_bonding_free_reorder(bc);       // Calls synchronize_rcu()!
        spin_lock_bh(&bc->state_lock);        // REACQUIRE

        // Re-evaluate after relock (good!)
        total_usable = bc->active_path_count;
        // ... re-checks state ...
    }
spin_unlock_bh(&bc->state_lock);
```

The code correctly re-evaluates state after relock, which is good. However, `tquic_bonding_free_reorder` calls `synchronize_rcu()` (line 174), which can sleep for an unbounded time. During this window, arbitrary state changes can occur. The re-evaluation only checks `active_path_count` and `failed_path_count`, but does not check whether `bc` itself is still valid or whether a concurrent destroy is in progress.

**Severity**: HIGH -- If `tquic_bonding_destroy()` runs concurrently while `synchronize_rcu()` blocks, `bc` could be freed.

**Recommendation**: Add a "destroying" flag to `bc` checked after relock, or use refcounting on `bc`.

---

### HIGH-2: GRO Flush Unlock-Relock Loop Without Re-validation

**File**: `/Users/justinadams/Downloads/tquic-kernel/net/quic/tquic/tquic_input.c`
**Lines**: 2303-2314

```c
spin_lock(&gro->lock);
while ((skb = __skb_dequeue(&gro->hold_queue)) != NULL) {
    spin_unlock(&gro->lock);
    deliver(skb);               // Arbitrary callback!
    flushed++;
    spin_lock(&gro->lock);     // New packets may have been added
}
gro->held_count = 0;           // Resets to 0, but new packets arrived!
spin_unlock(&gro->lock);
```

**Impact**: Between `spin_unlock` (line 2306) and `spin_lock` (line 2309), `tquic_gro_receive_internal()` could add new packets and increment `gro->held_count`. After the loop finishes, `gro->held_count = 0` blindly resets the count, losing track of any packets added during the unlock window. Those packets will sit in the queue without being properly tracked.

**Severity**: HIGH -- Can cause packet ordering violations or indefinitely held packets in the GRO queue.

**Recommendation**: After the loop, set `gro->held_count = skb_queue_len(&gro->hold_queue)` instead of hard-coding 0.

---

### HIGH-3: accept() Uses spin_lock_bh on sk_lock.slock While lock_sock() Is Held

**File**: `/Users/justinadams/Downloads/tquic-kernel/net/quic/tquic/tquic_socket.c`
**Lines**: 451-481

```c
lock_sock(sk);
// ...
for (;;) {
    spin_lock_bh(&sk->sk_lock.slock);    // Takes the backing spinlock!
    if (!list_empty(&tsk->accept_queue)) {
        // ...
        spin_unlock_bh(&sk->sk_lock.slock);
        goto out_unlock;
    }
    spin_unlock_bh(&sk->sk_lock.slock);
```

While this is technically not a deadlock (lock_sock releases the slock after setting owned=1), it is an anti-pattern. The accept queue is protected by the socket lock itself -- there is no need to separately take the backing spinlock. Furthermore, `spin_lock_bh` will disable softirqs, but `lock_sock` already provides the necessary serialization.

The real concern is that modifying `tsk->accept_queue` under `sk->sk_lock.slock` but reading it later (line 562: `tsk->accept_queue_len > 0` in poll) without any lock creates a data race on `accept_queue_len`.

**Severity**: HIGH -- Unnecessary inner locking that complicates the code and may mask actual synchronization bugs.

**Recommendation**: Remove the inner `spin_lock_bh(&sk->sk_lock.slock)` calls in `tquic_accept()`. The `lock_sock()` already provides sufficient serialization. If the accept queue needs to be accessed from softirq context, use a dedicated spinlock instead of the socket's backing slock.

---

### HIGH-4: smartnic.c Uses spin_lock Without _bh

**File**: `/Users/justinadams/Downloads/tquic-kernel/net/quic/tquic/offload/smartnic.c`
**Lines**: 193, 232, 251, 278, 737, 830 (and more)

All uses of `tquic_nic_lock` and `dev->lock` use plain `spin_lock()` without `_bh`. If any NIC registration/deregistration function is called from a softirq-enabled context AND the lock is also taken from softirq context (e.g., via a netdev callback), this creates a deadlock.

**Severity**: HIGH -- Potential deadlock if called from softirq context.

**Recommendation**: Audit all call sites. If any are reachable from softirq context, change to `spin_lock_bh`.

---

### HIGH-5: http3_stream.c Uses spin_lock Without _bh

**File**: `/Users/justinadams/Downloads/tquic-kernel/net/quic/tquic/http3/http3_stream.c`
**Lines**: 362, 435, 499, 555, 793, 888, 945, 985, 1024

All uses of `h3conn->lock` use `spin_lock()` without `_bh`. HTTP/3 stream processing is likely triggered from packet receive path (softirq context). If `h3conn->lock` is ever held from process context when a softirq tries to acquire it, deadlock.

**Severity**: HIGH -- Potential softirq deadlock.

**Recommendation**: Use `spin_lock_bh` consistently.

---

### HIGH-6: Security Hardening Pre-HS Atomic TOCTOU

**File**: `/Users/justinadams/Downloads/tquic-kernel/net/quic/tquic/security_hardening.c`
**Lines**: 255-289

```c
new_total = atomic64_add_return(size, &pre_hs_state.total_memory);
if (new_total > pre_hs_state.memory_limit) {
    atomic64_sub(size, &pre_hs_state.total_memory);
    return -ENOMEM;
}

entry = find_or_create_ip_entry(addr, true);
if (entry) {
    new_per_ip = atomic64_add_return(size, &entry->memory_used);
    if (new_per_ip > pre_hs_state.per_ip_budget) {
        atomic64_sub(size, &entry->memory_used);
        atomic64_sub(size, &pre_hs_state.total_memory);
        return -ENOMEM;
    }

    if (atomic_read(&entry->conn_count) >= TQUIC_PRE_HS_MAX_CONNS_PER_IP) {
        // ... rollback ...
        return -ENOMEM;
    }

    atomic_inc(&entry->conn_count);  // TOCTOU with the check above!
}
```

The check at line 280 (`atomic_read(&entry->conn_count) >= MAX`) and the increment at line 289 (`atomic_inc(&entry->conn_count)`) are not atomic together. Two concurrent connections from the same IP could both pass the check and both increment, exceeding the limit.

**Severity**: HIGH -- An attacker from a single IP can exceed the per-IP connection limit by racing multiple Initial packets. This undermines the QUIC-LEAK defense.

**Recommendation**: Use `atomic_inc_return()` and check the result instead of separate read + increment.

---

## 4. Medium Severity Issues

### MEDIUM-1: Error Ring Uses Atomics Under Spinlock Unnecessarily

**File**: `/Users/justinadams/Downloads/tquic-kernel/net/quic/tquic/tquic_proc.c`
**Lines**: 198-248

```c
spin_lock(&ring->lock);
idx = atomic_read(&ring->head) & (TQUIC_ERROR_RING_SIZE - 1);
atomic_inc(&ring->head);

if (atomic_read(&ring->count) < TQUIC_ERROR_RING_SIZE)
    atomic_set(&ring->count, ...);
// ...
spin_unlock(&ring->lock);
```

Using `atomic_t` operations while holding a spinlock is unnecessary overhead. The spinlock already provides mutual exclusion. The atomics add memory barriers that serve no purpose when the spinlock already provides ordering.

However, the REAL issue: if readers access `ring->head` and `ring->count` without taking the lock (likely, for proc output), they need atomics. But the reader at lines 572-589 DOES take the lock. So the atomics add no value.

**Severity**: MEDIUM -- Performance overhead, no correctness issue.

---

### MEDIUM-2: FEC Encoder Triple-Nested Locking

**File**: `/Users/justinadams/Downloads/tquic-kernel/net/quic/tquic/fec/fec_encoder.c`
**Lines**: 246-298, 434-486

```c
spin_lock_bh(&enc->lock);           // Outer lock
    spin_lock(&block->lock);         // Inner lock (nested)
    // ... operations ...
    spin_unlock(&block->lock);
spin_unlock_bh(&enc->lock);
```

The nesting `enc->lock -> block->lock` is consistent across the file. However, at line 576 there is a standalone `spin_lock(&block->lock)` acquisition WITHOUT holding `enc->lock`:

```c
spin_lock(&block->lock);   // Line 576 -- no enc->lock held!
```

This means `block->lock` can be acquired both with and without `enc->lock` held, which is fine for lock ordering but means the block can be concurrently modified while `enc->lock` is held by another thread.

**Severity**: MEDIUM -- The standalone block->lock acquisition is intentional for read-only operations but should be clearly documented.

---

### MEDIUM-3: poll() Accesses Connection/Stream Without Any Lock

**File**: `/Users/justinadams/Downloads/tquic-kernel/net/quic/tquic/tquic_socket.c`
**Lines**: 562-598

```c
if (sk->sk_state == TCP_LISTEN) {
    if (tsk->accept_queue_len > 0)      // No lock!
        mask |= EPOLLIN | EPOLLRDNORM;
} else if (sk->sk_state == TCP_ESTABLISHED) {
    conn = READ_ONCE(tsk->conn);
    stream = READ_ONCE(tsk->default_stream);

    if (conn && stream) {
        if (!skb_queue_empty(&stream->recv_buf))  // No lock on stream!
            mask |= EPOLLIN | EPOLLRDNORM;
    }
}
```

`tsk->accept_queue_len` is read without any lock, while it is modified under `spin_lock_bh(&sk->sk_lock.slock)` in accept(). The `skb_queue_empty` check on `stream->recv_buf` is similarly unprotected. While poll is inherently racy, the lack of `READ_ONCE` on `accept_queue_len` could cause compiler optimizations to cache a stale value.

**Severity**: MEDIUM -- Stale poll results, potential missed wakeups.

**Recommendation**: Use `READ_ONCE(tsk->accept_queue_len)`.

---

### MEDIUM-4: Coupled Congestion Control Division by Zero

**File**: `/Users/justinadams/Downloads/tquic-kernel/net/quic/tquic/bond/cong_coupled.c`
**Lines**: 941-943

```c
spin_lock_bh(&ctx->lock);
// ... ctx->total_cwnd checked != 0 at line 897 ...
increase = div64_u64(ctx->alpha * acked_bytes * mss,
                     ctx->total_cwnd * COUPLED_ALPHA_SCALE);
```

While `total_cwnd` is checked for zero at line 897, it is also modified at line 949 (`ctx->total_cwnd += increase`). In theory, between the check and the division, another path could decrement `total_cwnd` to zero. However, since the lock IS held, this cannot happen. The real risk is if `total_cwnd * COUPLED_ALPHA_SCALE` overflows u64. With `total_cwnd` being a window size (max ~2^32 bytes) and `COUPLED_ALPHA_SCALE` being a constant, overflow is unlikely but not guarded against.

**Severity**: MEDIUM.

---

### MEDIUM-5: rcu_dereference Outside Explicit RCU Section

**File**: `/Users/justinadams/Downloads/tquic-kernel/net/quic/tquic/tquic_udp.c`
**Line**: 1271

```c
static struct sk_buff *tquic_udp_gro_receive(struct sock *sk, ...)
{
    us = rcu_dereference_sk_user_data(sk);
```

And line 1303:
```c
us = rcu_dereference_sk_user_data(sk);
```

These are in GRO callbacks which run in NAPI/softirq context, providing implicit RCU read-side protection. This is correct but should be documented with a comment for maintainability.

**Severity**: MEDIUM -- Correct but fragile; a future refactoring could break the implicit RCU guarantee.

---

## 5. Low Severity Issues

### LOW-1: Inconsistent Lock Variant for conn->lock in tquic_input.c

**File**: `/Users/justinadams/Downloads/tquic-kernel/net/quic/tquic/tquic_input.c`
**Lines**: 1015, 1306, 1776

Uses `spin_lock(&ctx->conn->lock)` without `_bh`, while the documented convention (protocol.h:33) says to use `spin_lock_bh(&conn->lock)`.

This is actually CORRECT for tquic_input.c because packet processing runs in softirq context where bottom halves are already disabled. Using `_bh` would be redundant. However, the inconsistency with the documented convention could confuse future developers.

**Severity**: LOW -- No actual bug, but violates documented convention.

**Recommendation**: Add a comment explaining why `_bh` is not needed in the receive path.

---

### LOW-2: Scheduler Lock Uses spin_lock Without _bh

**File**: `/Users/justinadams/Downloads/tquic-kernel/net/quic/tquic/sched/scheduler.c`
**Lines**: 39, 54, 179

`tquic_sched_lock` uses plain `spin_lock()`. Scheduler registration/unregistration likely only happens during module init/exit (process context), so this is fine.

**Severity**: LOW.

---

### LOW-3: Redundant Lock in tquic_bonding_get_state

**File**: `/Users/justinadams/Downloads/tquic-kernel/net/quic/tquic/bond/tquic_bonding.c`
**Lines**: 526, 899, 932

```c
return READ_ONCE(bc->state);   // Line 526 -- lockless read
// ...
if (READ_ONCE(bc->state) == TQUIC_BOND_SINGLE_PATH)   // Line 899
```

The state is read with `READ_ONCE` (lockless) in some places but under `state_lock` in others. This is acceptable since individual reads do not need atomicity guarantees, but compound state checks (check state + do something based on state) need the lock.

**Severity**: LOW -- Correct usage pattern.

---

### LOW-4: Missing lockdep Annotations

The codebase does not use `lockdep_assert_held()` or lock class annotations (`lock_set_class()`, `lock_set_subclass()`). Adding these would catch lock ordering violations at runtime during testing.

**Severity**: LOW -- Defense-in-depth improvement.

**Recommendation**: Add `lockdep_assert_held(&conn->lock)` at the beginning of functions that require `conn->lock` to be held.

---

## 6. Lock Hierarchy Map

```
                          Global Locks
                          ============
tquic_nf_lock (bh)
tquic_udp_hash_lock (bh)
tquic_listener_lock (bh)
port_alloc.lock (bh)
tquic_nic_lock (plain)
tquic_sched_lock (plain)
tquic_bpm_list_lock (bh)

                          Mutex Locks (sleepable)
                          =======================
tquic_client_mutex
tquic_token_mutex
integrity_aead_lock
tquic_retry_mutex
state->pool_locks[slot]
keyring_mutex
pm_ops_lock
tquic_cid_table_lock

                          Per-Connection Hierarchy
                          ========================
sk->sk_lock (lock_sock)
  |
  +-- conn->lock (spin_lock_bh)
  |     |
  |     +-- conn->paths_lock (spin_lock_bh or spin_lock in softirq)
  |     |
  |     +-- conn->streams_lock (spin_lock_bh)
  |     |
  |     +-- conn->datagram.lock (spin_lock)
  |
  +-- ts->lock (timer state, spin_lock_bh)
        |
        +-- pns->lock (per PN-space, spin_lock_bh or spin_lock)
        |     |
        |     +-- rs->lock (recovery state, spin_lock_bh or spin_lock)
        |
        +-- rs->lock (can also be direct under ts->lock)

                          Per-Path Hierarchy
                          ==================
path->state_lock (spin_lock_bh)
  |
  +-- path->cc_lock (spin_lock_bh)

                          Bonding Hierarchy
                          =================
bc->state_lock (spin_lock_bh)

pm->lock (spin_lock_bh)
  |
  +-- path->state_lock (via drop-relock pattern -- UNSAFE)

fc->sent_packets_lock (spin_lock_bh)
  |
  +-- fc->retx_queue.lock (spin_lock_bh) -- taken separately, same level

                          FEC Hierarchy
                          =============
enc->lock (spin_lock_bh)
  |
  +-- block->lock (spin_lock)

                          Other Per-Object Locks
                          ======================
h3conn->lock (spin_lock)
h3s->lock (spin_lock_init only, never used?)
rb->buffer_lock (reorder, spin_lock_bh)
state->lock (deadline sched, spin_lock_bh)
ctx->lock (coupled CC, spin_lock_bh)
pool->lock (CID pool, spin_lock_bh)
bucket->lock (rate limit, spin_lock_irqsave)
ring->lock (error ring, spin_lock)
gro->lock (spin_lock)
cfg->lock (LB config, spin_lock)
zc->lock (zerocopy, spin_lock_bh)
```

### Observed Lock Nesting (Verified Correct)

1. `ts->lock -> pns->lock -> rs->lock` (tquic_timer.c)
2. `ts->lock -> rs->lock` (tquic_timer.c)
3. `enc->lock -> block->lock` (fec_encoder.c)
4. `lock_sock -> spin_lock_bh(sk->sk_lock.slock)` (tquic_socket.c -- questionable)
5. `rcu_read_lock -> pm->lock -> [drop/reacquire]` (tquic_bpm.c -- UNSAFE)

### Lock Ordering Violations Found

None of the identified nesting patterns create a direct ABBA deadlock. However, the mixed `_bh`/non-`_bh` usage on `rs->lock` and `pns->lock` is a latent violation.

---

## 7. Summary of Recommendations

| Priority | Count | Description |
|----------|-------|-------------|
| **Fix Immediately** | 4 | CRITICAL-1 through CRITICAL-4: UAF, TOCTOU, latent deadlock |
| **Fix Before Release** | 6 | HIGH-1 through HIGH-6: deadlock potential, race conditions |
| **Fix When Convenient** | 5 | MEDIUM-1 through MEDIUM-5: correctness improvements |
| **Track** | 4 | LOW-1 through LOW-4: documentation and defense-in-depth |

### Top 3 Actions

1. **Fix the BPM notifier drop-relock pattern** (CRITICAL-1) -- most likely to be triggered remotely
2. **Replace READ_ONCE/WRITE_ONCE increment patterns with proper atomics** (CRITICAL-2, HIGH-6) -- affects failover reliability and security
3. **Add refcounting to path lookup results** (CRITICAL-3) -- fundamental safety issue

---

*End of audit report.*
