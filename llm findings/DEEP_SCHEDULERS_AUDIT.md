# TQUIC Multipath Scheduler -- Deep Security Audit

**Date:** 2026-02-09
**Auditor:** Kernel Security Reviewer (Automated)
**Scope:** All multipath scheduler implementations
**Status:** COMPLETE

**Files Audited:**
- `/Users/justinadams/Downloads/tquic-kernel/net/tquic/multipath/sched_minrtt.c` (MinRTT + Round-Robin)
- `/Users/justinadams/Downloads/tquic-kernel/net/tquic/multipath/sched_aggregate.c` (Aggregate)
- `/Users/justinadams/Downloads/tquic-kernel/net/tquic/multipath/sched_blest.c` (BLEST)
- `/Users/justinadams/Downloads/tquic-kernel/net/tquic/multipath/sched_ecf.c` (ECF)
- `/Users/justinadams/Downloads/tquic-kernel/net/tquic/multipath/sched_weighted.c` (Weighted DRR)
- `/Users/justinadams/Downloads/tquic-kernel/net/tquic/multipath/tquic_scheduler.c` (3065 lines, framework + 5 internal schedulers)
- `/Users/justinadams/Downloads/tquic-kernel/net/tquic/multipath/tquic_sched.h` (API header)
- `/Users/justinadams/Downloads/tquic-kernel/net/tquic/multipath/mp_sched_registry.c` (OOT registry)
- `/Users/justinadams/Downloads/tquic-kernel/net/tquic/sched/scheduler.c` (framework + 8 built-in schedulers)
- `/Users/justinadams/Downloads/tquic-kernel/net/tquic/sched/deadline_aware.c` (Deadline-aware scheduler)
- `/Users/justinadams/Downloads/tquic-kernel/net/tquic/sched/deadline_scheduler.c` (EDF scheduler)

---

## Summary

| Severity | Count |
|----------|-------|
| CRITICAL | 5 |
| HIGH | 10 |
| MEDIUM | 9 |
| LOW | 5 |

The most pervasive class of bugs is **missing lock protection** on scheduler-private state. The ECF scheduler declares a spinlock but never uses it. BLEST uses it inconsistently. The weighted scheduler has no lock at all. Combined with the fact that scheduler callbacks can be invoked from multiple contexts (send path, ACK processing, path management), these are serious data race conditions that will manifest under real multipath traffic loads.

The second major class is **use-after-free via stale RCU pointers** -- every scheduler returns path pointers that may become invalid after `rcu_read_unlock()`.

---

## Critical Issues

### CRIT-01: ECF Scheduler Declares Lock But Never Uses It

- **File:** `/Users/justinadams/Downloads/tquic-kernel/net/tquic/multipath/sched_ecf.c`
- **Lines:** 75 (lock declaration), 212-294 (ecf_get_path), 334-352 (ecf_path_added), 361-379 (ecf_path_removed), 390-409 (ecf_packet_sent), 419-441 (ecf_ack_received), 451-473 (ecf_loss_detected)
- **Description:** `ecf_sched_data` declares `spinlock_t lock` but no function ever calls `spin_lock_irqsave()`. Every function that reads or writes `sd->paths[]`, `sd->current_path_id`, and `sd->path_switches` does so without synchronization. The send path (`ecf_get_path`), ACK processing (`ecf_ack_received`), loss detection (`ecf_loss_detected`), packet sent notification (`ecf_packet_sent`), and path management (`ecf_path_added`, `ecf_path_removed`) all run concurrently.
- **Code:**
```c
// ecf_sched_data has spinlock_t lock -- never acquired
static int ecf_get_path(...) {
    // NO lock
    ps = ecf_find_path_state(sd, path->path_id);
    if (!ps) {
        ps = ecf_alloc_path_state(sd, path->path_id); // modifies sd->paths[]
    }
    // reads ps->inflight_bytes, ps->send_rate -- concurrently modified by ecf_ack_received
}

static void ecf_packet_sent(...) {
    // NO lock
    ps->inflight_bytes += sent_bytes; // races with ecf_ack_received
}

static void ecf_ack_received(...) {
    // NO lock
    ps->inflight_bytes -= acked_bytes; // races with ecf_packet_sent
}
```
- **Impact:** On 32-bit architectures, u64 `inflight_bytes` writes are non-atomic, producing torn values. On 64-bit, concurrent read-modify-write (`+=` and `-=`) without atomics causes lost updates. Path state corruption leads to wildly incorrect completion time estimates, causing traffic to be sent on the wrong path (potentially a congested or failed path).
- **Severity:** CRITICAL
- **Recommendation:** Wrap all accesses to `sd->paths[]` and `sd->current_path_id` in `spin_lock_irqsave(&sd->lock, flags)` / `spin_unlock_irqrestore(&sd->lock, flags)`.

---

### CRIT-02: BLEST Inconsistent Locking -- 3 of 6 Callbacks Lack Lock

- **File:** `/Users/justinadams/Downloads/tquic-kernel/net/tquic/multipath/sched_blest.c`
- **Lines:** 445-463 (blest_path_removed), 515-549 (blest_ack_received), 559-581 (blest_loss_detected)
- **Description:** BLEST's `blest_get_path()` and `blest_packet_sent()` correctly acquire `sd->lock`. However, `blest_path_removed()`, `blest_ack_received()`, and `blest_loss_detected()` modify the same shared state (`sd->paths[]`, `sd->current_path_id`) without holding the lock.
- **Code:**
```c
// blest_ack_received -- NO LOCK
static void blest_ack_received(...) {
    ps = blest_find_path_state(sd, path->path_id);  // reads sd->paths[]
    ps->inflight_bytes -= acked_bytes;               // modifies ps
    ps->rtt_us = path->cc.smoothed_rtt_us;           // modifies ps
    ps->send_rate = path->cc.bandwidth;              // modifies ps
}

// blest_path_removed -- NO LOCK
static void blest_path_removed(...) {
    ps = blest_find_path_state(sd, path->path_id);
    ps->valid = false;        // races with blest_get_path reading valid
    sd->current_path_id = TQUIC_INVALID_PATH_ID;
}
```
- **Impact:** `blest_ack_received()` modifies `inflight_bytes` and `send_rate` that `blest_get_path()` reads under lock. The locked reader sees inconsistent state (e.g., inflight updated but send_rate not yet). `blest_path_removed()` setting `valid=false` without lock means `blest_get_path()` could return a path whose state was just invalidated.
- **Severity:** CRITICAL
- **Recommendation:** Add `spin_lock_irqsave(&sd->lock, flags)` to `blest_path_removed()`, `blest_ack_received()`, and `blest_loss_detected()`.

---

### CRIT-03: Redundant Scheduler Dedup Uses Only 8 Bits of Sequence Number

- **File:** `/Users/justinadams/Downloads/tquic-kernel/net/tquic/multipath/tquic_scheduler.c`
- **Lines:** 1308-1332 (tquic_redundant_is_duplicate)
- **Description:** The deduplication window truncates the 64-bit QUIC sequence number to 8 bits: `seq_byte = (u8)(seq & 0xFF)`. It then searches a 256-byte window for a match. This means any two packets whose sequence numbers differ by a multiple of 256 will collide, causing legitimate unique packets to be falsely identified as duplicates and dropped.
- **Code:**
```c
seq_byte = (u8)(seq & 0xFF);

for (i = 0; i < 256; i++) {
    if (rd->dedup_window[i] == seq_byte)
        return true;  /* False positive: seq 0 and seq 256 both map to 0 */
}
```
- **Impact:** After sending 256 unique packets, the dedup window is full and every new packet has a 100% collision rate with an existing entry. This causes **all subsequent packets to be dropped as duplicates**, completely breaking the connection. Even before the window is full, there is a `filled_entries/256` probability of false positive per packet.
- **Severity:** CRITICAL
- **Recommendation:** Use a proper bitmap or hash table keyed on the full 64-bit sequence number, or at minimum use a larger hash with a rolling window.

---

### CRIT-04: Adaptive Scheduler cwnd_avail Underflow

- **File:** `/Users/justinadams/Downloads/tquic-kernel/net/tquic/multipath/tquic_scheduler.c`
- **Lines:** 1475-1478 (tquic_adaptive_calc_score)
- **Description:** The CWND availability score is computed as `cwnd_avail = path->cc.cwnd - path->cc.bytes_in_flight`. Both are `u32` fields. If `bytes_in_flight > cwnd` (which can happen during loss recovery when cwnd is reduced but inflight data hasn't been acknowledged), this is an unsigned underflow producing a very large value. The subsequent `cwnd_score = (cwnd_avail * 1000) / path->cc.cwnd` would then overflow.
- **Code:**
```c
if (path->cc.cwnd == 0)
    cwnd_score = 0;
else {
    cwnd_avail = path->cc.cwnd - path->cc.bytes_in_flight;  // u32 underflow!
    cwnd_score = (cwnd_avail * 1000) / path->cc.cwnd;        // garbage
}
```
- **Impact:** A congested path gets an artificially high CWND score, causing the adaptive scheduler to prefer sending traffic to the most congested path. This inverts the scheduling decision.
- **Severity:** CRITICAL
- **Recommendation:** Check `if (path->cc.bytes_in_flight >= path->cc.cwnd) cwnd_score = 0;` before the subtraction.

---

### CRIT-05: Adaptive Feedback Uses Path After list_for_each_entry Exit

- **File:** `/Users/justinadams/Downloads/tquic-kernel/net/tquic/multipath/tquic_scheduler.c`
- **Lines:** 1625-1634 (tquic_adaptive_feedback)
- **Description:** After `list_for_each_entry_rcu()` exits (either by finding the path or exhausting the list), the code checks `if (path->path_id != fb->path_id)`. However, when the list is exhausted, `path` points to the list head (cast to `struct tquic_path *`), not a valid path. Dereferencing `path->path_id` on the list head is an out-of-bounds read.
- **Code:**
```c
list_for_each_entry_rcu(path, &conn->paths, list) {
    if (path->path_id == fb->path_id)
        break;
    path_idx++;
}

if (path->path_id != fb->path_id) {  // path may be &conn->paths (list head)!
    rcu_read_unlock();
    return;
}
```
- **Impact:** Reading `path_id` from the list head reads from an arbitrary offset in `struct tquic_int_connection`, returning garbage. If the garbage happens to match `fb->path_id`, the function continues with a corrupt pointer, potentially writing to arbitrary memory via the subsequent `tquic_update_rtt()` and `path->cc.*` assignments.
- **Severity:** CRITICAL
- **Recommendation:** Use a separate flag variable to track whether the path was found, or use `list_for_each_entry_rcu()` with a found flag check.

---

## High Severity Issues

### HIGH-01: Weighted Scheduler Has No Lock Protection

- **File:** `/Users/justinadams/Downloads/tquic-kernel/net/tquic/multipath/sched_weighted.c`
- **Lines:** 51-54, 65-157
- **Description:** `weighted_sched_data` has no spinlock. `weighted_get_path()` reads and modifies `paths[].weight`, `paths[].deficit`, and `current_path_idx` without synchronization. Concurrent callers corrupt deficit counters.
- **Severity:** HIGH

---

### HIGH-02: TOCTOU in Round-Robin Path Count vs Selection

- **File:** `/Users/justinadams/Downloads/tquic-kernel/net/tquic/multipath/sched_minrtt.c`
- **Lines:** 427-461 (rr_get_path)
- **Description:** The RR scheduler traverses the path list twice: once to count active paths, once to select one. A path removal between traversals makes the count stale, causing the selection to miss.
- **Severity:** HIGH

---

### HIGH-03: TQUIC_MAX_PATHS Mismatch (16 vs 8)

- **File:** `/Users/justinadams/Downloads/tquic-kernel/net/tquic/multipath/tquic_sched.h` line 40 vs `/Users/justinadams/Downloads/tquic-kernel/net/tquic/multipath/tquic_scheduler.c` line 46
- **Description:** External schedulers allocate 16-element arrays; internal schedulers use 8-element arrays. `tquic_path_selection` struct at line 222 has `paths[TQUIC_MAX_PATHS]` which resolves to `paths[8]` in tquic_scheduler.c. If the redundant scheduler tries to select more than 8 paths (line 1243: `count < target && count < TQUIC_MAX_PATHS`), it writes past the array bounds.
- **Severity:** HIGH

---

### HIGH-04: Type Shadowing Creates Memory Corruption Risk

- **File:** `/Users/justinadams/Downloads/tquic-kernel/net/tquic/multipath/tquic_scheduler.c`
- **Lines:** 191-199, 2158-2164
- **Description:** `#define tquic_path tquic_int_path` causes all code in this file to use internal types. At line 2158-2164, the code explicitly casts through `void *` to call `tquic_mp_sched_notify_sent()` with an internal path pointer where the external API expects the global `tquic_path` type. These types have different layouts (different struct fields). The cast through `void *` silences the compiler but the scheduler callback will read wrong fields.
- **Code:**
```c
{
    void *c = conn;   // tquic_int_connection *, not tquic_connection *
    void *p = path;   // tquic_int_path *, not tquic_path *
    tquic_mp_sched_notify_sent(c, p, bytes);  // ABI mismatch!
}
```
- **Severity:** HIGH

---

### HIGH-05: Stale Path Pointer Returned After rcu_read_unlock (All Schedulers)

- **Files:** All scheduler `get_path`/`select_path` functions
- **Description:** Every scheduler stores a path pointer in `result->primary` or `result->backup` while holding `rcu_read_lock()`, then releases the lock before returning. The path could be freed by `synchronize_rcu()` in `tquic_path_remove()` before the caller uses the pointer.
- **Affected Locations:**
  - `sched_minrtt.c:233` (minrtt and rr)
  - `sched_aggregate.c:241`
  - `sched_ecf.c:293`
  - `sched_blest.c:366`
  - `sched_weighted.c:132`
  - `tquic_scheduler.c:723,880,1075,1274,1607` (all internal schedulers)
- **Severity:** HIGH (depends on caller's RCU discipline)

---

### HIGH-06: Aggregate Scheduler Unfair Minimum Weight Floor

- **File:** `/Users/justinadams/Downloads/tquic-kernel/net/tquic/multipath/sched_aggregate.c`
- **Lines:** 128-146 (update_capacities_locked, second pass)
- **Description:** The 5% minimum weight floor is computed as `(total * 50) / 1000`. As paths get boosted, `total` increases, making subsequent minimum weights higher. Paths later in the list get systematically higher floors than paths earlier in the list. This creates list-position-dependent bias.
- **Severity:** HIGH (algorithmic correctness)

---

### HIGH-07: Internal Round-Robin Scheduler Missing Bounds Check

- **File:** `/Users/justinadams/Downloads/tquic-kernel/net/tquic/multipath/tquic_scheduler.c`
- **Lines:** 822, 838
- **Description:** `tquic_weighted_select_path()` computes `start_idx = wd->current_path_idx % conn->num_paths`. If `conn->num_paths` is 0, this is a division by zero. The check on line 817 returns if `conn->num_paths == 0`, but `conn->num_paths` is read without lock and could change between the check and the modulo operation.
- **Code:**
```c
if (!wd || conn->num_paths == 0)
    return -ENOENT;
// ... conn->num_paths could become 0 here via concurrent path_remove ...
start_idx = wd->current_path_idx % conn->num_paths;  // div by zero
```
- **Severity:** HIGH (kernel panic on division by zero)

---

### HIGH-08: sched/scheduler.c rr_select TOCTOU on num_paths

- **File:** `/Users/justinadams/Downloads/tquic-kernel/net/tquic/sched/scheduler.c`
- **Lines:** 277-285 (rr_select)
- **Description:** `target = atomic_inc_return(&data->counter) % conn->num_paths`. If `conn->num_paths` is 0 or changes between reads, this produces a division-by-zero or out-of-range index. The function does not check for zero paths before the modulo.
- **Code:**
```c
target = atomic_inc_return(&data->counter) % conn->num_paths;
// num_paths could be 0 -> div by zero
```
- **Severity:** HIGH

---

### HIGH-09: sched/scheduler.c wrr_select Stale total_weight

- **File:** `/Users/justinadams/Downloads/tquic-kernel/net/tquic/sched/scheduler.c`
- **Lines:** 357-378 (wrr_select)
- **Description:** `total_weight` is computed once at init time and never updated. When paths are added or removed, `total_weight` becomes stale. The modulo `target = counter % data->total_weight` produces indices that no longer correspond to the current path set, causing packets to be sent on wrong paths or the fallback active_path.
- **Severity:** HIGH (algorithmic correctness)

---

## Medium Severity Issues

### MED-01: All MP Scheduler init() Functions Silently Fail on OOM

- **Files:** All `sched_*.c` init functions
- **Description:** `minrtt_init()`, `aggregate_init()`, `blest_init()`, `ecf_init()`, `weighted_init()`, `rr_init()` all have void return type. If `kzalloc()` fails, `conn->sched_priv` remains NULL. `get_path()` returns -EINVAL but no error is logged.
- **Severity:** MEDIUM

---

### MED-02: Weighted Scheduler Weight Not Validated

- **File:** `/Users/justinadams/Downloads/tquic-kernel/net/tquic/multipath/sched_weighted.c`
- **Lines:** 88-89, 121
- **Description:** `path->weight` from netlink is used directly. No upper bound. `TQUIC_DRR_QUANTUM * ps->weight` (1500 * huge_weight) overflows u32.
- **Severity:** MEDIUM

---

### MED-03: Duplicate ECF Path State Allocation Race

- **File:** `/Users/justinadams/Downloads/tquic-kernel/net/tquic/multipath/sched_ecf.c`
- **Lines:** 241-246
- **Description:** Without lock, two threads can allocate duplicate path states for the same path_id.
- **Severity:** MEDIUM

---

### MED-04: Adaptive Scheduler Score Manipulation via Crafted Loss

- **File:** `/Users/justinadams/Downloads/tquic-kernel/net/tquic/multipath/tquic_scheduler.c`
- **Lines:** 1677-1686
- **Description:** A remote peer can selectively drop packets to trigger `recent_loss_count >= 3`, activating the penalty mechanism (`in_penalty = true, score / 4`) for a specific path. By targeting the best path with crafted packet drops, an attacker can steer traffic to a worse path (potentially one they control for interception).
- **Severity:** MEDIUM (requires on-path attacker)

---

### MED-05: LIA Alpha Calculation Precision Loss

- **File:** `/Users/justinadams/Downloads/tquic-kernel/net/tquic/multipath/tquic_scheduler.c`
- **Lines:** 1530-1554 (tquic_adaptive_update_alpha)
- **Description:** `sum_rtt_cwnd += path->cc.cwnd / rtt` -- integer division truncates when cwnd < rtt. For a path with cwnd=1200 and rtt=100000, `1200/100000 = 0`, making this path's contribution to sum_rtt_cwnd zero. This causes alpha to be computed incorrectly, giving too little weight increase to slow-start paths.
- **Severity:** MEDIUM

---

### MED-06: Deadline Scheduler in_flight Underflow

- **File:** `/Users/justinadams/Downloads/tquic-kernel/net/tquic/sched/deadline_aware.c`
- **Lines:** 297-298 (deadline_estimate_delivery_time)
- **Description:** `in_flight = path->stats.tx_bytes - path->stats.acked_bytes` can underflow if ACK processing updates `acked_bytes` ahead of the tx accounting. The clamping to cwnd on line 299 limits the damage, but the underflowed value (near U64_MAX) will saturate to cwnd and overestimate queue delay.
- **Severity:** MEDIUM

---

### MED-07: sched/scheduler.c ECF Loss Rate Division by Zero

- **File:** `/Users/justinadams/Downloads/tquic-kernel/net/tquic/sched/scheduler.c`
- **Lines:** 604-610
- **Description:** `loss_rate_pct = (path->stats.lost_packets * 100) / path->stats.tx_packets`. If `lost_packets * 100` overflows u64, the division produces wrong results. More importantly, `completion_time * 100 / (100 - loss_rate_pct)` is a division by zero when `loss_rate_pct == 100` (100% loss rate). The check `loss_rate_pct < 50` prevents this, but `lost_packets` and `tx_packets` can be modified concurrently making the check unreliable.
- **Severity:** MEDIUM

---

### MED-08: sched/scheduler.c Debug Logging Leaks Kernel Pointers

- **File:** `/Users/justinadams/Downloads/tquic-kernel/net/tquic/sched/scheduler.c`
- **Lines:** 152-155, 198-220
- **Description:** `tquic_sched_default()` and `tquic_sched_init_conn()` use `pr_warn()` to print raw kernel pointers (`%px` format): `pr_warn("tquic_sched: default_scheduler='%s' owner=%px\n", ops->name, ops->owner)`. The `%px` format bypasses pointer hashing (`%p` hashes by default since Linux 4.15) and leaks raw kernel addresses.
- **Code:**
```c
pr_warn("tquic_sched: default_scheduler='%s' owner=%px\n",
        ops->name, ops->owner);
pr_warn("tquic_sched: init_conn called, ops=%px conn=%px\n", ops, conn);
```
- **Impact:** Information disclosure of kernel ASLR addresses. These addresses help attackers craft exploits for other vulnerabilities.
- **Severity:** MEDIUM
- **Recommendation:** Replace `%px` with `%p` or remove the debug logging entirely.

---

### MED-09: EDF Scheduler edf_select_path Called Without Lock

- **File:** `/Users/justinadams/Downloads/tquic-kernel/net/tquic/sched/deadline_scheduler.c`
- **Lines:** 590-591 (in tquic_edf_enqueue)
- **Description:** `edf_select_path()` is called at line 591 before the lock is acquired at line 594. The path selection reads `sched->conn->paths` without RCU or the scheduler lock. The tree insertion at line 595 holds the lock, but the entry's `selected_path` was set outside the lock.
- **Code:**
```c
entry->selected_path = edf_select_path(sched, entry);  // NO LOCK
spin_lock_bh(&sched->lock);
edf_tree_insert(&sched->edf_tree, entry);
```
- **Severity:** MEDIUM

---

## Low Severity Issues

### LOW-01: Diagnostic Counter Wraps (MinRTT, ECF)

- **Files:** `sched_minrtt.c:225`, `sched_ecf.c:286`
- **Description:** `switch_count` and `path_switches` are u32 diagnostics that wrap.
- **Severity:** LOW

### LOW-02: Aggregate Scheduler Long Spinlock Hold

- **File:** `/Users/justinadams/Downloads/tquic-kernel/net/tquic/multipath/sched_aggregate.c`
- **Lines:** 172-230
- **Description:** Spinlock held across entire capacity recalculation including `ktime_get()`.
- **Severity:** LOW

### LOW-03: Weighted DRR Iterates Over Empty Slots

- **File:** `/Users/justinadams/Downloads/tquic-kernel/net/tquic/multipath/sched_weighted.c`
- **Lines:** 101-138
- **Description:** The DRR loop iterates over all 16 `TQUIC_MAX_PATHS` slots even if only 2 paths exist. For each slot, it traverses the full path list to find the path at that index. This is O(TQUIC_MAX_PATHS * num_paths) per scheduling decision.
- **Severity:** LOW (performance only)

### LOW-04: Multiple Scheduler Registration Systems Coexist

- **Files:** `tquic_scheduler.c` (3 separate list/lock pairs), `sched/scheduler.c` (1 more)
- **Description:** There are at least 4 independent scheduler registration systems: (1) `tquic_sched_list` + `tquic_sched_list_lock` for internal schedulers, (2) `tquic_new_sched_list` + `tquic_new_sched_list_lock` for new-style schedulers, (3) `tquic_mp_sched_list` + `tquic_mp_sched_list_lock` for multipath schedulers, (4) `tquic_sched_list` + `tquic_sched_lock` in `sched/scheduler.c`. Duplicate names can be registered across systems without detection.
- **Severity:** LOW (maintenance hazard)

### LOW-05: timer_setup with NULL Callback

- **File:** `/Users/justinadams/Downloads/tquic-kernel/net/tquic/sched/deadline_aware.c`
- **Line:** 475
- **Description:** `timer_setup(&state->scheduler_timer, NULL, 0)` sets up a timer with a NULL callback. If this timer ever fires, it will call through a NULL function pointer, causing a kernel panic. Currently the timer is never armed, so this is not exploitable.
- **Severity:** LOW

---

## Architectural Observations

### OBS-01: Three Parallel Scheduler Frameworks

The codebase contains three independently developed scheduler frameworks:
1. **Internal schedulers** in `tquic_scheduler.c` (round-robin, weighted, lowlat, redundant, adaptive) using `tquic_sched_internal` ops
2. **Multipath schedulers** in `sched_*.c` (minrtt, aggregate, blest, ecf, weighted) using `tquic_mp_sched_ops`
3. **Simple schedulers** in `sched/scheduler.c` (roundrobin, minrtt, weighted, blest, redundant, ecf, owd, owd-ecf, edf) using `tquic_sched_ops`

Each has its own registration, lookup, and callback mechanism. This triplication means bugs in one framework do not get fixed in the others, and the same algorithm (e.g., ECF) is implemented three times with different quality levels.

### OBS-02: Inconsistent Congestion State Layouts

The internal schedulers use `tquic_int_path_cc` (line 102-117) while external schedulers use the global `tquic_path.cc`. The `sched/scheduler.c` schedulers use `path->stats.*` (a completely different struct). This means the same path has three different representations of RTT, cwnd, bandwidth, etc., and there is no guarantee they are synchronized.

---

## Recommendations Summary

1. **Immediate (CRITICAL):** Add proper locking to ECF, BLEST, and weighted schedulers. Fix the redundant scheduler dedup hash. Fix the adaptive scheduler cwnd underflow and list traversal bug.

2. **Short-term (HIGH):** Unify TQUIC_MAX_PATHS to a single definition. Remove or fix the type-shadowing macros. Add division-by-zero guards for num_paths. Ensure path pointers are used within RCU critical sections.

3. **Medium-term (MEDIUM):** Remove `%px` debug logging. Add weight validation. Fix LIA alpha precision. Add admission control for the scheduler registration systems.

4. **Long-term:** Consolidate the three scheduler frameworks into one. Eliminate type shadowing. Add KCSAN annotations for intentional lockless reads.
