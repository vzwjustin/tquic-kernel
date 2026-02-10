# TQUIC Multipath, Bonding, Scheduling, and Path Management Security Audit

**Auditor:** kernel-security-reviewer (multipath-auditor)
**Date:** 2026-02-09
**Scope:** net/tquic/multipath/, net/tquic/bond/, net/tquic/sched/, net/tquic/pm/, tquic_migration.c, tquic_cid.c

---

## Executive Summary

This audit covers the multipath scheduler, bonding state machine, failover logic, path management, connection migration, CID management, and NAT keepalive subsystems. The codebase shows generally good engineering practices with proper locking discipline, anti-amplification enforcement, and constant-time comparisons for challenge/response. However, several issues were identified ranging from critical resource exhaustion vulnerabilities to medium-severity logic bugs and low-severity defense-in-depth improvements.

**Findings by severity:**
- CRITICAL: 3
- HIGH: 8
- MEDIUM: 12
- LOW: 7

---

## Critical Issues

### C-1: Redundant Scheduler Deduplication Uses Only 8-bit Sequence Hash -- Trivial Collision

- **File:** `/Users/justinadams/Downloads/tquic-kernel/net/tquic/multipath/tquic_scheduler.c`
- **Lines:** 1308-1332
- **Code:**
```c
bool tquic_redundant_is_duplicate(struct tquic_connection *conn, u64 seq)
{
    seq_byte = (u8)(seq & 0xFF);
    for (i = 0; i < 256; i++) {
        if (rd->dedup_window[i] == seq_byte) {
            return true;  /* Duplicate found */
        }
    }
    rd->dedup_window[rd->dedup_head] = seq_byte;
    rd->dedup_head = (rd->dedup_head + 1) & 0xFF;
    return false;
}
```
- **Impact:** The deduplication mechanism truncates 64-bit QUIC packet numbers to 8 bits. After 256 unique packets, every single subsequent packet will be flagged as a duplicate since the 256-entry window is guaranteed to contain every possible byte value. This effectively makes the redundant scheduler non-functional after a few hundred packets, causing silent data loss by dropping legitimate non-duplicate packets.
- **Recommendation:** Use the full 64-bit packet number with a proper sliding window bitmap (similar to the `tquic_dedup_state` in `tquic_failover.h` which correctly uses a 2048-entry bitmap with 64-bit base tracking).

### C-2: Adaptive Scheduler CWND Underflow in Score Calculation

- **File:** `/Users/justinadams/Downloads/tquic-kernel/net/tquic/multipath/tquic_scheduler.c`
- **Lines:** 1473-1478
- **Code:**
```c
if (path->cc.cwnd == 0)
    cwnd_score = 0;
else {
    cwnd_avail = path->cc.cwnd - path->cc.bytes_in_flight;
    cwnd_score = (cwnd_avail * 1000) / path->cc.cwnd;
}
```
- **Impact:** Both `cwnd` and `bytes_in_flight` are `u32`. When `bytes_in_flight > cwnd` (which occurs transiently during congestion or loss recovery), the subtraction wraps around to a very large `u64` value. This corrupts the score calculation, potentially giving a failing path the highest score and routing all traffic to it -- exactly the wrong behavior during congestion.
- **Recommendation:** Add an explicit check: `cwnd_avail = (path->cc.cwnd > path->cc.bytes_in_flight) ? path->cc.cwnd - path->cc.bytes_in_flight : 0;`

### C-3: ACK Range Failover Can Iterate Over Unbounded Packet Number Range

- **File:** `/Users/justinadams/Downloads/tquic-kernel/net/tquic/bond/tquic_failover.c`
- **Lines:** 534-549
- **Code:**
```c
int tquic_failover_on_ack_range(struct tquic_failover_ctx *fc,
                                u64 first, u64 last)
{
    for (pkt_num = first; pkt_num <= last; pkt_num++) {
        if (tquic_failover_on_ack(fc, pkt_num) == 0)
            count++;
    }
    return count;
}
```
- **Impact:** An attacker sending a crafted ACK frame with `first=0` and `last=UINT64_MAX` would cause this loop to iterate up to 2^64 times, each iteration acquiring `sent_packets_lock`. This is a denial-of-service that would lock up a CPU core indefinitely in BH context, effectively freezing the kernel. Even moderate ranges (e.g., last-first = 10 million) would cause multi-second softlockups.
- **Recommendation:** Clamp the range: `if (last - first > TQUIC_FAILOVER_MAX_QUEUED) return -ERANGE;` before the loop. The maximum meaningful range is bounded by the number of packets actually tracked.

---

## High Severity Issues

### H-1: Path Validation Timeout Accesses Path State Without Lock After Unlock

- **File:** `/Users/justinadams/Downloads/tquic-kernel/net/tquic/pm/path_validation.c`
- **Lines:** 144-158
- **Code:**
```c
/* Retry validation */
path->validation.retries++;
spin_unlock_bh(&conn->paths_lock);

/* Resend PATH_CHALLENGE */
if (tquic_path_send_challenge(conn, path) == 0) {
    u32 timeout_us = tquic_validation_timeout_us(path);
    // ... accesses path->stats after lock release
```
- **Impact:** After unlocking `paths_lock`, the code accesses `path->validation.retries`, `path->stats.rtt_smoothed`, and `path->stats.rtt_variance` without protection. A concurrent `tquic_path_handle_response()` could complete validation and reset these fields, leading to corrupted timeout calculations or use-after-free if the path is freed.
- **Recommendation:** Either hold the lock across the entire operation, or cache the needed values (`retries`, timeout) before releasing the lock.

### H-2: Migration State Stores Raw Path Pointers Without Reference Counting

- **File:** `/Users/justinadams/Downloads/tquic-kernel/net/tquic/tquic_migration.c`
- **Lines:** 199-215, 858-870
- **Code:**
```c
struct tquic_migration_state {
    struct tquic_path *old_path;
    struct tquic_path *new_path;
    // ...
};
// ...
ms->old_path = conn->active_path;
ms->new_path = best_path;
```
- **Impact:** The migration state machine holds raw pointers to paths without incrementing any reference count. If the path is freed (e.g., via netlink `DEL_PATH` command or interface down event) while migration is in progress, the timer callback `tquic_migration_timeout()` and work handler `tquic_migration_work_handler()` will dereference a freed pointer, causing a use-after-free and potential kernel code execution.
- **Recommendation:** Use proper path reference counting. The `tquic_bpm_path` already has `refcount_t refcnt` -- ensure migration state increments it and releases on cleanup.

### H-3: Failover Retransmit Queue Can Exceed Memory Limits

- **File:** `/Users/justinadams/Downloads/tquic-kernel/net/tquic/bond/tquic_failover.c`
- **Lines:** 600-611
- **Code:**
```c
if (requeued >= TQUIC_FAILOVER_MAX_QUEUED) {
    pr_warn_ratelimited(...);
    break;
}
```
- **Impact:** The TQUIC_FAILOVER_MAX_QUEUED limit (1024 packets) is enforced per path failure event but not cumulatively. If multiple paths fail in sequence, each failure can add up to 1024 packets. With 8 paths, this allows 8192 packets in the retransmit queue. Furthermore, the `TQUIC_FAILOVER_MAX_QUEUE_BYTES` (4MB) limit defined in the header is never actually checked during requeue. Each packet holds a cloned SKB, so an attacker triggering repeated path failures could exhaust memory.
- **Recommendation:** Check `fc->retx_queue.count >= TQUIC_FAILOVER_MAX_QUEUED` and `fc->retx_queue.bytes >= TQUIC_FAILOVER_MAX_QUEUE_BYTES` at the start of the requeue loop, rejecting if already at limit.

### H-4: Hysteresis Counters Use Non-Atomic READ_ONCE/WRITE_ONCE Without Lock

- **File:** `/Users/justinadams/Downloads/tquic-kernel/net/tquic/bond/tquic_failover.c`
- **Lines:** 198-199, 688-689
- **Code:**
```c
WRITE_ONCE(pt->consec_failures, READ_ONCE(pt->consec_failures) + 1);
WRITE_ONCE(pt->consec_successes, 0);
// ... and in update_path_ack:
WRITE_ONCE(pt->consec_successes, READ_ONCE(pt->consec_successes) + 1);
WRITE_ONCE(pt->consec_failures, 0);
```
- **Impact:** The increment pattern `WRITE_ONCE(x, READ_ONCE(x) + 1)` is a read-modify-write that is NOT atomic. If `tquic_failover_timeout_work()` (running in workqueue) and `tquic_failover_update_path_ack()` (called from BH context on ACK receipt) run concurrently on different CPUs, the increment can be lost. This could cause the hysteresis thresholds to never be reached, preventing failover or recovery.
- **Recommendation:** Use `atomic_t` for `consec_failures` and `consec_successes`, or protect both with a spinlock.

### H-5: Path Manager Uses init_net Instead of Per-Connection Net Namespace

- **File:** `/Users/justinadams/Downloads/tquic-kernel/net/tquic/pm/path_manager.c`
- **Lines:** 424
- **Code:**
```c
for_each_netdev(&init_net, dev) {
```
- **Impact:** In a containerized environment, `tquic_pm_discover_addresses()` iterates over devices in the init namespace rather than the connection's network namespace. This leaks the host's network interface information to containers and could result in paths being created to addresses the container should not access, breaking network namespace isolation.
- **Recommendation:** Use `sock_net(conn->sk)` or pass the correct `struct net *` instead of `&init_net`.

### H-6: Bonding State Machine Missing Lock on State Transition Checks

- **File:** `/Users/justinadams/Downloads/tquic-kernel/net/tquic/bond/tquic_bonding.c`
- **Lines:** 221-247
- **Code:**
```c
static void tquic_bonding_set_state(struct tquic_bonding_ctx *bc,
                                    enum tquic_bonding_state new_state)
{
    enum tquic_bonding_state old_state = bc->state;
    // ... no lock acquisition ...
    bc->state = new_state;
```
- **Impact:** `tquic_bonding_set_state()` reads and writes `bc->state` without holding `bc->state_lock`. Multiple concurrent callers (e.g., path failure callback + path recovery callback) could race on the state transition, leading to invalid state combinations (e.g., transitioning from SINGLE_PATH to DEGRADED when the intermediate ACTIVE state was never entered).
- **Recommendation:** Document that callers must hold `bc->state_lock`, or acquire it within the function.

### H-7: CID Lookup Returns Connection Without Reference Count

- **File:** `/Users/justinadams/Downloads/tquic-kernel/net/tquic/tquic_cid.c`
- **Lines:** 530-542
- **Code:**
```c
struct tquic_connection *tquic_cid_lookup(const struct tquic_cid *cid)
{
    entry = rhashtable_lookup_fast(&tquic_cid_table, cid, cid_rht_params);
    if (entry && entry->state == CID_STATE_ACTIVE)
        return entry->conn;
    return NULL;
}
```
- **Impact:** Returns a raw pointer to a connection without incrementing any reference count. If the connection is concurrently destroyed (e.g., timeout, reset) after the lookup but before the caller uses the pointer, this is a use-after-free. This is the packet demux hot path -- every incoming packet calls this function.
- **Recommendation:** The caller should be in an RCU read-side section, and connections should be freed via `kfree_rcu()`. Alternatively, take a refcount on the connection before returning.

### H-8: Weighted Scheduler Index Assumption Breaks After Path Removal

- **File:** `/Users/justinadams/Downloads/tquic-kernel/net/tquic/multipath/tquic_scheduler.c`
- **Lines:** 820-855
- **Code:**
```c
list_for_each_entry_rcu(path, &conn->paths, list) {
    if (idx == path_idx) {
        pd = &wd->path_data[path_idx];
        pd->deficit += ...;
```
- **Impact:** The weighted scheduler uses a positional index into `path_data[]` array that is implicitly coupled to the order of paths in the linked list. When a path is removed from the middle of the list, subsequent paths shift position but the array data does not. This means path_data entries become misaligned: path N gets the deficit/weight state of path N-1. This corrupts scheduling fairness and may cause starvation of some paths.
- **Recommendation:** Index `path_data[]` by `path->path_id` (which is stable) rather than by list position. Add bounds checking for `path_id < TQUIC_MAX_PATHS`.

---

## Medium Severity Issues

### M-1: Path Creation Uses static atomic_t for path_id -- Not Per-Connection

- **File:** `/Users/justinadams/Downloads/tquic-kernel/net/tquic/tquic_migration.c`
- **Lines:** 394, 409
- **Code:**
```c
static atomic_t path_id_gen = ATOMIC_INIT(0);
path->path_id = atomic_inc_return(&path_id_gen);
```
- **Impact:** Path IDs are globally unique across all connections rather than per-connection. After many connections/migrations, the ID space wraps around, potentially causing collisions in data structures that assume unique path IDs per connection. RFC 9000 multipath draft specifies per-connection path IDs.
- **Recommendation:** Use per-connection path ID allocation (the BPM module already has `next_path_id` and a bitmap for this).

### M-2: Round-Robin Scheduler Iterates Path List Without Position Stability

- **File:** `/Users/justinadams/Downloads/tquic-kernel/net/tquic/multipath/tquic_scheduler.c`
- **Lines:** 655-725
- **Impact:** The round-robin scheduler finds its starting point by matching `path_id >= rr->next_path_id`. If the previously-selected path is removed and a new path is added with a lower ID, the iteration may skip paths or always select the same path. This violates the round-robin fairness guarantee.
- **Recommendation:** Track the position using a path pointer (saved via RCU) or the `list_head` position rather than path_id comparison.

### M-3: Anti-Amplification Check Has TOCTOU Race

- **File:** `/Users/justinadams/Downloads/tquic-kernel/net/tquic/tquic_migration.c`
- **Lines:** 85-105
- **Code:**
```c
received = atomic64_read(&path->anti_amplification.bytes_received);
sent = atomic64_read(&path->anti_amplification.bytes_sent);
limit = received * TQUIC_ANTI_AMPLIFICATION_LIMIT;
if (sent + bytes > limit) { return false; }
```
- **Impact:** The check reads `received` and `sent` atomically individually, but the comparison is not atomic as a whole. Between reading `sent` and the caller actually adding `bytes` via `tquic_path_anti_amplification_sent()`, another thread could also pass the check, allowing the 3x limit to be exceeded. Under concurrency, the limit could be violated by up to N*bytes where N is the number of concurrent senders.
- **Recommendation:** Use a combined atomic check-and-increment, or protect the entire check+send sequence with a spinlock.

### M-4: Path Manager discover_addresses Holds rtnl_lock While Accessing inet6_dev

- **File:** `/Users/justinadams/Downloads/tquic-kernel/net/tquic/pm/path_manager.c`
- **Lines:** 422-482
- **Impact:** The function holds `rtnl_lock()` for the entire iteration over all network devices and their addresses. It then also takes `idev->lock` (read_lock_bh) for IPv6. This has lock ordering implications: if any other code path takes these locks in a different order, it could deadlock.
- **Recommendation:** Collect device references under rtnl_lock, release it, then access addresses under RCU where possible.

### M-5: Coupled CC Alpha Calculation Has Precision Loss

- **File:** `/Users/justinadams/Downloads/tquic-kernel/net/tquic/bond/cong_coupled.c`
- **Lines:** 199-213
- **Impact:** When `sum_cwnd_rtt > 2^32`, the code shifts down before squaring. The shift_count calculation `(fls64(sum_cwnd_rtt) - 32 + 1) / 2 + 1` may over-shift in some cases, losing significant precision in the alpha calculation. This could cause suboptimal bandwidth distribution across paths.
- **Recommendation:** Use `mul_u64_u64_div()` or 128-bit intermediate calculations to avoid the need for pre-shifting.

### M-6: Scheduler Change Race Between State Check and Modification

- **File:** `/Users/justinadams/Downloads/tquic-kernel/net/tquic/multipath/tquic_scheduler.c`
- **Lines:** 554-607
- **Code:**
```c
if (conn->state != TQUIC_CONN_IDLE)
    return -EISCONN;
// ... RCU lookup, module_get ...
spin_lock_bh(&conn->lock);
old_sched = conn->sched;
```
- **Impact:** The connection state is checked before acquiring `conn->lock`. A concurrent connection establishment could change the state between the check and the lock acquisition, allowing the scheduler to be changed mid-connection. While unlikely, this violates the stated invariant ("Scheduler locked at connection establishment").
- **Recommendation:** Move the state check inside the spinlock-protected region.

### M-7: Missing Bounds Check on tquic_hyst_state_names Array Access

- **File:** `/Users/justinadams/Downloads/tquic-kernel/net/tquic/bond/tquic_failover.c`
- **Lines:** 155-159
- **Code:**
```c
pr_info("path %u hysteresis: %s -> %s ...\n",
    pt->path_id,
    tquic_hyst_state_names[old_state],
    tquic_hyst_state_names[new_state], ...);
```
- **Impact:** If `old_state` or `new_state` is out of bounds (e.g., due to memory corruption or a bug), this will cause an out-of-bounds read from the array, potentially leaking kernel memory through log messages.
- **Recommendation:** Use `ARRAY_SIZE(tquic_hyst_state_names)` bounds check before indexing.

### M-8: Netlink PM Commands Missing CAP_NET_ADMIN Checks

- **File:** `/Users/justinadams/Downloads/tquic-kernel/net/tquic/pm/pm_netlink.c`
- **Lines:** 226-341
- **Impact:** The `tquic_pm_nl_add_path()` and `tquic_pm_nl_del_path()` netlink command handlers do not appear to require `CAP_NET_ADMIN`. While the genl_ops definition may set `.flags = GENL_ADMIN_PERM`, this was not verified in the visible code. Without privilege checks, any user process could add or remove paths from QUIC connections, enabling path hijacking or denial-of-service.
- **Recommendation:** Ensure all PM netlink ops have `.flags = GENL_ADMIN_PERM` in the `genl_ops` array, or add explicit `capable(CAP_NET_ADMIN)` checks in each handler.

### M-9: Path Score Computation Can Overflow in Migration Target Selection

- **File:** `/Users/justinadams/Downloads/tquic-kernel/net/tquic/tquic_migration.c`
- **Lines:** 287-318
- **Code:**
```c
u64 score = 1000000;
score = score * 1000 / stats->rtt_smoothed;
score = (score * stats->bandwidth) >> 20;
score = score * (100 - min(loss_pct, 90ULL)) / 100;
score = score * (256 - path->priority) / 256;
score = score * path->weight;
```
- **Impact:** The score starts at 1000000 and is multiplied by 1000, bandwidth, (100-loss), (256-priority), and weight without overflow checks. For a path with high bandwidth (e.g., 10Gbps = 1250000000) and low RTT, the intermediate value `1000000 * 1000 / rtt * bandwidth` can overflow u64 (bandwidth * 1000000000 > 2^64).
- **Recommendation:** Reorder operations to divide before multiplying, or cap intermediate values.

### M-10: Path Manager netdev_event Shadows Variable 'i'

- **File:** `/Users/justinadams/Downloads/tquic-kernel/net/tquic/pm/path_manager.c`
- **Lines:** 325-327
- **Code:**
```c
int num_addrs, i;    // outer 'i'
// ...
for (i = 0; i < num_addrs; i++) {  // shadows outer 'i'
```
- **Impact:** The inner variable `i` shadows the outer `i` declared at function scope. While C allows this, it suggests a potential bug if the outer `i` was intended to be used later. This is a code quality issue that could mask real bugs.
- **Recommendation:** Rename the inner loop variable.

### M-11: BPM Path Manager Uses Workqueue Without Connection Lifetime Guard

- **File:** `/Users/justinadams/Downloads/tquic-kernel/net/tquic/bond/tquic_bpm.c`
- **Lines:** 307-311
- **Code:**
```c
struct work_struct discover_work;
struct work_struct failover_work;
struct delayed_work probe_work;
```
- **Impact:** The path manager schedules work items that reference the connection. If the connection is freed before the work runs, the work callback will dereference a freed `pm->conn` pointer. While `cancel_delayed_work_sync()` should be called during teardown, if any work items are missed (e.g., discover_work, failover_work), this is a use-after-free.
- **Recommendation:** Add a `struct tquic_connection *conn` reference with proper refcounting, and verify all work items are cancelled during teardown.

### M-12: NAT Keepalive Config Pointer Not Protected Against Concurrent Free

- **File:** `/Users/justinadams/Downloads/tquic-kernel/net/tquic/pm/nat_keepalive.c`
- **Lines:** 99-103, 155-158
- **Code:**
```c
if (!state || !state->initialized || state->suspended)
    return false;
if (!state->config || !state->config->enabled)
    return false;
// ...
config = state->config;
```
- **Impact:** `state->config` is read without holding `state->lock`. If the config is freed or replaced concurrently (e.g., via sysctl or sockopt), the pointer dereference at `state->config->enabled` would be a use-after-free.
- **Recommendation:** Access `state->config` under `state->lock`, or use `rcu_dereference()`/`rcu_assign_pointer()` for RCU-protected access.

---

## Low Severity Issues

### L-1: Defensive Check Missing for TQUIC_MAX_PATHS in Path Add

- **File:** `/Users/justinadams/Downloads/tquic-kernel/net/tquic/multipath/tquic_scheduler.c`
- **Lines:** 935-939
- **Code:**
```c
idx = conn->num_paths - 1;
if (idx >= 0 && idx < TQUIC_MAX_PATHS) {
```
- **Impact:** `idx` is computed as `num_paths - 1` but `num_paths` could be 0 if called at the wrong time. The `idx >= 0` check works because `idx` is `int`, but this is fragile.
- **Recommendation:** Check `conn->num_paths > 0` explicitly before the subtraction.

### L-2: Path Validation Timer del_timer vs del_timer_sync

- **File:** `/Users/justinadams/Downloads/tquic-kernel/net/tquic/pm/path_validation.c`
- **Lines:** 131, 397
- **Impact:** `del_timer()` is used inside spinlock-protected regions (appropriate since `del_timer_sync()` can sleep), but it means the timer callback could still be executing on another CPU when the state change takes effect.
- **Recommendation:** This is acceptable within the spinlock context, but document this clearly. Ensure `del_timer_sync()` is used in the teardown path.

### L-3: Scheduler get_info Callback Could Write Past Buffer

- **File:** `/Users/justinadams/Downloads/tquic-kernel/net/tquic/multipath/tquic_scheduler.c`
- **Lines:** 258-259
- **Code:**
```c
size_t (*get_info)(struct tquic_connection *conn, char *buf, size_t len);
```
- **Impact:** The get_info callback signature passes a buffer and length but there is no enforcement that scheduler implementations respect the length. A buggy scheduler could write past the buffer.
- **Recommendation:** Consider using `scnprintf()` style return values and validate in the caller.

### L-4: Failover Sent Packet Count Can Go Negative

- **File:** `/Users/justinadams/Downloads/tquic-kernel/net/tquic/bond/tquic_failover.c`
- **Lines:** 469, 503
- **Code:**
```c
fc->sent_count++;   // in track_sent
fc->sent_count--;   // in on_ack
```
- **Impact:** `sent_count` is a plain integer modified under `sent_packets_lock`. If a bug causes double-ack of the same packet (e.g., due to ACK range overlap), the count could go negative. This is defensive, not exploitable.
- **Recommendation:** Use unsigned and check for underflow before decrement.

### L-5: BPM Path Metrics min_rtt Initialized to UINT_MAX

- **File:** `/Users/justinadams/Downloads/tquic-kernel/net/tquic/bond/tquic_bpm.c`
- **Lines:** 536-537
- **Code:**
```c
m->min_rtt = UINT_MAX;
```
- **Impact:** Using `UINT_MAX` as sentinel is functional but could cause misleading path scores if min_rtt is used in calculations before the first RTT sample. A path with `UINT_MAX` min_rtt would score extremely poorly in RTT-based comparisons, which is actually the safe behavior.
- **Recommendation:** Document this sentinel value or use 0 with explicit "no sample yet" checks.

### L-6: Path Validation Response Queue Uses Two Tracking Mechanisms

- **File:** `/Users/justinadams/Downloads/tquic-kernel/net/tquic/pm/path_validation.c`
- **Lines:** 259, 278-279
- **Code:**
```c
if (atomic_read(&path->response.count) >= TQUIC_MAX_PENDING_RESPONSES) {
// ...
skb_queue_tail(&path->response.queue, skb);
atomic_inc(&path->response.count);
```
- **Impact:** The response queue uses both `skb_queue_*` (which has its own count via `skb_queue_len()`) and a separate `atomic_t count`. These could diverge if a dequeue path forgets to decrement the atomic. Dual tracking is error-prone.
- **Recommendation:** Use only one mechanism. `skb_queue_len()` is already atomic and thread-safe.

### L-7: Coupled CC Alpha Smoothing May Suppress Rapid Changes

- **File:** `/Users/justinadams/Downloads/tquic-kernel/net/tquic/bond/cong_coupled.c`
- **Lines:** 96-97
- **Impact:** `COUPLED_ALPHA_SMOOTHING = 8` means alpha changes by only 1/8 per update. When a path is suddenly added or removed, it takes many RTTs for alpha to converge, causing unfair bandwidth distribution during transitions. This is a design tradeoff, not a bug, but it could be improved.
- **Recommendation:** Consider faster convergence when path count changes.

---

## Positive Findings

The following security-relevant practices were correctly implemented:

1. **Constant-time PATH_RESPONSE comparison:** `crypto_memneq()` used in both `path_validation.c:352` and `path_manager.c:207` to prevent timing side-channels.

2. **Anti-amplification enforcement:** RFC 9000 Section 8.1 3x limit properly implemented in `tquic_migration.c:85-105` with atomic byte counters.

3. **CVE-2024-22189 defense:** CID management includes rate limiting for NEW_CONNECTION_ID processing (`tquic_cid.c:617`) and RETIRE_CONNECTION_ID queue limiting (`tquic_cid.c:917-936`).

4. **Hysteresis for path flap prevention:** The failover module implements a proper state machine (HEALTHY -> DEGRADED -> FAILED -> RECOVERING -> HEALTHY) with configurable thresholds to prevent rapid oscillation.

5. **Lock ordering discipline:** Path manager code carefully documents and maintains lock ordering between `paths_lock` and bond/scheduler locks, using temporary arrays to call callbacks outside locks.

6. **PATH_CHALLENGE rate limiting:** The path manager implements per-path rate limiting for PATH_RESPONSE generation (`path_manager.c:149-180`) to prevent response flooding.

7. **Reorder buffer for multipath:** Proper reorder buffer with RTT-spread-based timeout calculation handles out-of-order delivery across paths with different latencies.

---

## Summary of Recommendations

**Immediate fixes required (Critical/High):**
1. Replace 8-bit dedup hash with proper sliding window bitmap
2. Fix CWND underflow in adaptive scheduler score
3. Clamp ACK range iteration to prevent DoS
4. Add path reference counting in migration state machine
5. Fix namespace leak in address discovery
6. Use atomic operations for hysteresis counters
7. Add refcounting to CID lookup return values
8. Fix weighted scheduler index-by-position assumption

**Short-term improvements (Medium):**
1. Verify netlink ops have proper privilege checks
2. Fix anti-amplification TOCTOU with combined check-and-increment
3. Fix overflow in path score computation
4. Protect NAT keepalive config access with proper synchronization
5. Cancel all work items during path manager teardown

**Defense-in-depth (Low):**
1. Consolidate response queue tracking to single mechanism
2. Add bounds checks on state name array accesses
3. Use unsigned counters with underflow protection
