# TQUIC Deep Security Audit: Bonding, FEC, and Congestion Control

**Date:** 2026-02-09
**Auditor:** Claude Opus 4.6 (Kernel Security Reviewer)
**Scope:** `net/tquic/bond/`, `net/tquic/fec/`, `net/tquic/cong/`
**Codebase:** `/Users/justinadams/Downloads/tquic-kernel/`

---

## Executive Summary

This audit covers three TQUIC subsystems: multipath bonding, Forward Error Correction (FEC), and congestion control. A total of **28 findings** were identified: 4 Critical, 8 High, 10 Medium, and 6 Low severity. The most serious issues involve integer overflow in coupled congestion control arithmetic, excessive stack usage in FEC encoder/decoder, a use-after-free in the congestion algorithm registry, and a TOCTOU race in bonding state transitions.

---

## BONDING SUBSYSTEM (`net/tquic/bond/`)

### Files Reviewed
- `tquic_bonding.h` (502 lines)
- `tquic_bonding.c` (1135 lines)
- `bonding.c` (919 lines)
- `cong_coupled.h` (267 lines)
- `cong_coupled.c` (976 lines)
- `tquic_bpm.h` (111 lines)

---

### CRITICAL-B1: Integer Overflow in Coupled CC Increase Calculation

**File:** `/Users/justinadams/Downloads/tquic-kernel/net/tquic/bond/cong_coupled.c`
**Line:** ~477-478

**Description:** In `coupled_cc_increase()`, the computation `alpha * acked_bytes * mss` can overflow a u64. The variable `alpha` can reach 4096 (COUPLED_ALPHA_SCALE * 4), `acked_bytes` can be up to ~1GB in a burst ACK, and `mss` is typically 1200-1500. The product `4096 * 1073741824 * 1500 = 6.6e18` approaches the u64 max of `1.8e19`. Multiple burst ACKs or larger alpha values could overflow.

**Impact:** Overflow produces a tiny or zero increment, stalling congestion window growth. A remote peer could manipulate ACK patterns to trigger this, effectively causing a denial-of-service by freezing throughput.

**Fix:**
```c
/* Compute with overflow protection: reorder to divide early */
u64 increase = div64_u64((u64)alpha * acked_bytes, total_cwnd * COUPLED_ALPHA_SCALE);
increase = increase * mss; /* Now safe: increase is small after division */
```

---

### CRITICAL-B2: Same Overflow in OLIA Increase Path

**File:** `/Users/justinadams/Downloads/tquic-kernel/net/tquic/bond/cong_coupled.c`
**Line:** ~941-942

**Description:** `olia_cc_increase()` has the same pattern: `ctx->alpha * acked_bytes * mss` and `epsilon * acked_bytes * mss`. OLIA's epsilon can be negative (signed), adding signed/unsigned confusion to the overflow risk.

**Impact:** Same as CRITICAL-B1, plus potential signed overflow (undefined behavior in C).

**Fix:** Same early-division approach. For signed epsilon, cast carefully:
```c
s64 eps_increase = div64_s64((s64)epsilon * (s64)acked_bytes, (s64)total_cwnd);
eps_increase *= mss;
```

---

### HIGH-B1: TOCTOU Race in Bonding State Transition

**File:** `/Users/justinadams/Downloads/tquic-kernel/net/tquic/bond/tquic_bonding.c`
**Line:** ~456-483

**Description:** In `tquic_bonding_update_state()`, the bonding lock is dropped to free the reorder buffer (which may sleep), then reacquired, and the state is re-evaluated. Between the unlock and relock, another thread could change the bonding state, add paths, or modify the reorder queue. The re-evaluation after reacquiring the lock may not account for all possible state changes that occurred in the window.

**Impact:** Inconsistent bonding state. Could lead to packets being scheduled to a path that has been removed, or the reorder buffer being double-freed if two threads race through the same transition.

**Fix:** Use a state version counter or generation number. After reacquiring the lock, compare the generation number. If it changed, restart the state evaluation:
```c
u32 gen = ctx->state_generation;
spin_unlock_bh(&ctx->lock);
tquic_bond_reorder_flush(ctx); /* may sleep */
spin_lock_bh(&ctx->lock);
if (ctx->state_generation != gen) {
    /* State changed while lock was dropped, re-evaluate */
    goto retry;
}
ctx->state_generation++;
```

---

### HIGH-B2: Weight Accumulation Without Overflow Check

**File:** `/Users/justinadams/Downloads/tquic-kernel/net/tquic/bond/bonding.c`
**Line:** `tquic_select_weighted()`

**Description:** The weighted path selection sums `path->weight` values across all active paths into `total_weight`. If many paths exist with high weights (u32), the sum can overflow. The subsequent `get_random_u32() % total_weight` would then select incorrectly.

**Impact:** Unfair path selection, potentially directing all traffic to one path, reducing bonding effectiveness. Not directly exploitable by a remote attacker but could degrade service quality.

**Fix:**
```c
u64 total_weight = 0;
for_each_path(path) {
    total_weight += path->weight;
    if (total_weight > U32_MAX) {
        /* Normalize weights by shifting all down */
        ...
    }
}
```

---

### HIGH-B3: Expensive Operation in Loss Path

**File:** `/Users/justinadams/Downloads/tquic-kernel/net/tquic/bond/tquic_bonding.c`
**Line:** `tquic_bonding_on_loss_detected()`

**Description:** `tquic_bonding_on_loss_detected` calls `tquic_bonding_derive_weights` directly (not deferred). Weight derivation involves iterating all paths, computing RTT ratios, and performing divisions. In a heavy loss scenario (e.g., lossy radio link), this runs on every loss event, potentially in softirq context.

**Impact:** Increased latency in the loss processing path. Under sustained loss, this could cause softirq timeout or watchdog triggers.

**Fix:** Rate-limit weight recalculation to at most once per RTT, or defer it to a workqueue:
```c
if (time_after(jiffies, ctx->last_weight_update + msecs_to_jiffies(ctx->min_rtt_ms))) {
    tquic_bonding_derive_weights(ctx);
    ctx->last_weight_update = jiffies;
}
```

---

### MEDIUM-B1: In-Flight Calculation Signed Arithmetic

**File:** `/Users/justinadams/Downloads/tquic-kernel/net/tquic/bond/bonding.c`
**Line:** `tquic_calc_path_quality()`

**Description:** The in-flight computation `tx_bytes - (rx_bytes + lost_packets * 1200)` uses signed arithmetic to detect underflow. While the sign check is present, the intermediate `lost_packets * 1200` could overflow if `lost_packets` is very large (u32 * 1200 > U32_MAX at ~3.5M lost packets).

**Impact:** Incorrect in-flight estimate leading to suboptimal path selection.

**Fix:** Use u64 for the intermediate computation:
```c
u64 acked_and_lost = (u64)rx_bytes + (u64)lost_packets * 1200;
s64 in_flight = (s64)tx_bytes - (s64)acked_and_lost;
if (in_flight < 0) in_flight = 0;
```

---

### MEDIUM-B2: Reorder Buffer Sequence in skb->cb Alignment

**File:** `/Users/justinadams/Downloads/tquic-kernel/net/tquic/bond/bonding.c`
**Line:** `tquic_bond_reorder_insert()`

**Description:** The reorder queue stores a 64-bit sequence number via `*(u64 *)pos->cb`. The `skb->cb` array is guaranteed to be at least 48 bytes but its alignment depends on the `sk_buff` allocator. On most architectures this works, but on strict-alignment architectures (e.g., SPARC, some ARM), unaligned u64 access causes a fault.

**Impact:** Kernel panic on strict-alignment architectures.

**Fix:** Use `put_unaligned()` / `get_unaligned()` or define a proper struct overlay:
```c
struct tquic_skb_cb {
    u64 sequence;
    /* other fields */
};
#define TQUIC_SKB_CB(skb) ((struct tquic_skb_cb *)(skb)->cb)
```

---

### MEDIUM-B3: Alpha Precision Loss in Coupled CC

**File:** `/Users/justinadams/Downloads/tquic-kernel/net/tquic/bond/cong_coupled.c`
**Line:** `coupled_calc_alpha()`

**Description:** The alpha calculation shifts both `max_cwnd_rtt2` and `sum_cwnd_rtt_sq` to prevent overflow, but the shift is computed from `max_cwnd_rtt2` only. If `sum_cwnd_rtt_sq` is much larger, the shift may not be sufficient. Conversely, if the values are very different in magnitude, the shift can reduce the smaller value to zero, producing a division by zero or infinite alpha.

**Impact:** Alpha becomes 0 or extremely large, causing congestion window to stall or grow unboundedly.

**Fix:** Compute shift based on the maximum of both operands, and clamp alpha to a reasonable range:
```c
u32 shift = max(ilog2(max_cwnd_rtt2), ilog2(sum_cwnd_rtt_sq));
shift = (shift > 30) ? shift - 30 : 0;
/* ... after division ... */
alpha = clamp(alpha, COUPLED_ALPHA_MIN, COUPLED_ALPHA_MAX);
```

---

### LOW-B1: Missing Documentation on Lock Ordering

**File:** `/Users/justinadams/Downloads/tquic-kernel/net/tquic/bond/tquic_bonding.h`

**Description:** The bonding subsystem uses `ctx->lock` (spinlock_t), path locks, and the reorder buffer lock, but there is no documented lock ordering. The code appears consistent but without explicit documentation, future changes could introduce deadlocks.

**Fix:** Add a comment at the top of `tquic_bonding.h`:
```c
/*
 * Lock ordering (outermost first):
 *   1. ctx->lock (bonding context)
 *   2. path->lock (per-path)
 *   3. ctx->reorder_lock (reorder buffer)
 *   Never hold path->lock while acquiring ctx->lock.
 */
```

---

## FEC SUBSYSTEM (`net/tquic/fec/`)

### Files Reviewed
- `fec.h` (895 lines)
- `fec_core.c` (294 lines)
- `fec_decoder.c` (846 lines)
- `fec_encoder.c` (772 lines)
- `fec_scheduler.c` (470 lines)
- `xor_fec.c` (312 lines)

---

### CRITICAL-F1: Excessive Stack Usage in RS Recovery

**File:** `/Users/justinadams/Downloads/tquic-kernel/net/tquic/fec/fec_decoder.c`
**Line:** ~411-417

**Description:** `attempt_rs_recovery()` allocates multiple arrays on the stack, each of size `TQUIC_FEC_MAX_SOURCE_SYMBOLS` (255):
```c
u8 *symbols[255];       /* 255 * 8 = 2040 bytes (64-bit) */
u16 lengths[255];       /* 255 * 2 = 510 bytes */
u8 erasure_pos[255];    /* 255 bytes */
u8 *recovered[255];     /* 2040 bytes */
u16 recovered_lens[255]; /* 510 bytes */
```
Total: ~5355 bytes, plus the function's other locals and any caller stack. The kernel default stack size is 8KB (some configs 16KB). This alone consumes 67% of an 8KB stack. Combined with caller frames (softirq -> netfilter -> QUIC -> FEC), this will overflow the stack.

**Impact:** Kernel stack overflow leading to corruption and crash. Remotely triggerable by sending a QUIC packet with a repair symbol that triggers RS recovery.

**Fix:** Allocate these arrays dynamically:
```c
struct rs_recovery_ctx {
    u8 *symbols[TQUIC_FEC_MAX_SOURCE_SYMBOLS];
    u16 lengths[TQUIC_FEC_MAX_SOURCE_SYMBOLS];
    u8 erasure_pos[TQUIC_FEC_MAX_SOURCE_SYMBOLS];
    u8 *recovered[TQUIC_FEC_MAX_SOURCE_SYMBOLS];
    u16 recovered_lens[TQUIC_FEC_MAX_SOURCE_SYMBOLS];
};

struct rs_recovery_ctx *rctx = kmalloc(sizeof(*rctx), GFP_ATOMIC);
if (!rctx) return -ENOMEM;
/* ... use rctx->symbols, etc. ... */
kfree(rctx);
```

---

### HIGH-F1: Large Stack Allocation in XOR Recovery

**File:** `/Users/justinadams/Downloads/tquic-kernel/net/tquic/fec/fec_decoder.c`
**Line:** ~337

**Description:** `attempt_xor_recovery()` declares `u8 recovered_data[TQUIC_FEC_MAX_SYMBOL_SIZE]` (1500 bytes) on the stack. While less severe than CRITICAL-F1, this is still a significant stack allocation in a potentially deep call chain.

**Impact:** Stack pressure, potential overflow in deep call chains.

**Fix:** Use `kmalloc(TQUIC_FEC_MAX_SYMBOL_SIZE, GFP_ATOMIC)` with proper error handling.

---

### HIGH-F2: Same Stack Issue in Encoder

**File:** `/Users/justinadams/Downloads/tquic-kernel/net/tquic/fec/fec_encoder.c`
**Line:** ~312-314, ~353-356

**Description:** Both `generate_xor_repair()` and `generate_rs_repair()` have the same large stack allocation patterns as their decoder counterparts.

**Impact:** Same as CRITICAL-F1 and HIGH-F1.

**Fix:** Same dynamic allocation approach.

---

### HIGH-F3: Repair Frame Field Truncation Without Validation

**File:** `/Users/justinadams/Downloads/tquic-kernel/net/tquic/fec/fec_decoder.c`
**Line:** ~764

**Description:** `tquic_fec_decode_repair_frame()` reads a varint value and casts it to u16:
```c
frame->repair_length = (u16)value;
```
If the varint decodes to a value > 65535, silent truncation occurs. A malicious peer could set `repair_length` to 0x10001 (65537), which truncates to 1, causing a length mismatch between the actual repair data and the declared length.

**Impact:** Buffer over-read or under-read during repair symbol processing. Could leak kernel memory or corrupt FEC recovery.

**Fix:**
```c
if (value > U16_MAX) {
    return -EOVERFLOW;
}
frame->repair_length = (u16)value;
```

---

### HIGH-F4: FEC Scheme ID Not Validated From Wire

**File:** `/Users/justinadams/Downloads/tquic-kernel/net/tquic/fec/fec_decoder.c`
**Line:** ~758

**Description:** The FEC scheme field is read from the wire as a u8 but not validated against `__TQUIC_FEC_SCHEME_MAX` before being used to select the FEC algorithm. If the value exceeds the number of registered schemes, it could be used as an out-of-bounds index into an algorithm dispatch table.

**Impact:** Out-of-bounds read from algorithm table, potentially leading to code execution if the table is followed by a function pointer.

**Fix:**
```c
if (scheme >= __TQUIC_FEC_SCHEME_MAX) {
    return -EINVAL;
}
frame->scheme = scheme;
```

---

### MEDIUM-F1: Nested Locking in Repair Reception

**File:** `/Users/justinadams/Downloads/tquic-kernel/net/tquic/fec/fec_decoder.c`
**Line:** `tquic_fec_receive_repair()`

**Description:** The function acquires `dec->lock` (spin_lock_bh) and then `block->lock` (nested). This ordering appears consistent within the decoder, but if any other path acquires these locks in a different order, a deadlock results. The lock nesting annotation (`SINGLE_DEPTH_NESTING` or lockdep annotation) is not present.

**Impact:** Potential deadlock under concurrent FEC processing.

**Fix:** Add lockdep annotation:
```c
spin_lock_nested(&block->lock, SINGLE_DEPTH_NESTING);
```

---

### MEDIUM-F2: Lock Ordering Between Encoder and Scheduler

**File:** `/Users/justinadams/Downloads/tquic-kernel/net/tquic/fec/fec_scheduler.c`
**Line:** ~278-279

**Description:** `tquic_fec_should_send_repair()` acquires `enc->lock` then `sched->lock`. Any code path that acquires these in the opposite order would deadlock. Without explicit documentation, this is fragile.

**Impact:** Potential deadlock if lock ordering is violated by future code.

**Fix:** Document the ordering and add lockdep class annotations.

---

### MEDIUM-F3: Loss Rate Cast Overflow

**File:** `/Users/justinadams/Downloads/tquic-kernel/net/tquic/fec/fec_scheduler.c`
**Line:** ~113

**Description:** `update_loss_rate()` computes:
```c
(int)new_rate - (int)sched->current_loss_rate
```
Both `new_rate` and `current_loss_rate` are u32. If either exceeds INT_MAX (2^31 - 1), the cast to `int` produces a negative value, corrupting the difference calculation.

**Impact:** FEC scheduler misestimates loss rate, sending too many or too few repair symbols.

**Fix:** Use s64 for the difference:
```c
s64 diff = (s64)new_rate - (s64)sched->current_loss_rate;
```

---

### LOW-F1: C99 Variable Declaration in Loop

**File:** `/Users/justinadams/Downloads/tquic-kernel/net/tquic/fec/xor_fec.c`
**Line:** ~157

**Description:** `tquic_xor_decode()` declares a variable inside a for loop body (`const u8 *sym = symbols[i]`). While modern GCC accepts this, the kernel historically prefers C89-style declarations at the top of blocks, and `checkpatch.pl` may warn.

**Impact:** Cosmetic / style issue only.

**Fix:** Move declaration before the loop or to the top of the enclosing block.

---

### LOW-F2: Repair Data Pointer Lifetime

**File:** `/Users/justinadams/Downloads/tquic-kernel/net/tquic/fec/fec_encoder.c`
**Line:** `tquic_fec_get_pending_repair()`

**Description:** The function returns a pointer to `repair->data` inside the repair frame structure. If the caller holds this pointer while the source block is freed (e.g., due to timeout), the pointer becomes dangling. The current callers appear safe, but the API is fragile.

**Impact:** Potential use-after-free if future callers misuse the API.

**Fix:** Document the lifetime requirement or copy the data into a caller-provided buffer.

---

## CONGESTION CONTROL SUBSYSTEM (`net/tquic/cong/`)

### Files Reviewed
- `tquic_cong.h` (447 lines)
- `tquic_cong.c` (1200 lines)
- `persistent_cong.h` (221 lines)
- `persistent_cong.c` (432 lines)
- `cong_data.h` (679 lines)
- `cong_data.c` (1308 lines)
- `bbrv2.h` (partial)
- `accecn.h` (partial)
- `bdp_frame.h` (partial)

---

### CRITICAL-C1: Use-After-Free in Algorithm Name Return

**File:** `/Users/justinadams/Downloads/tquic-kernel/net/tquic/cong/tquic_cong.c`
**Line:** ~896-906

**Description:** `tquic_cong_get_default_name()` acquires an RCU read lock, finds the default congestion algorithm, copies the pointer `ca->name`, releases the RCU read lock, and returns the pointer. If the module providing the algorithm is unloaded between the RCU unlock and the caller's use of the returned pointer, the name string is freed, resulting in a use-after-free.

```c
const char *tquic_cong_get_default_name(void)
{
    const char *name;
    rcu_read_lock();
    ca = rcu_dereference(default_ca);
    name = ca->name;
    rcu_read_unlock();
    return name; /* <-- ca may be freed here */
}
```

**Impact:** Information disclosure (reading freed memory) or crash. Requires a module unload race, but module loading/unloading can be triggered by an unprivileged user via `modprobe` in some configurations.

**Fix:** Copy the name into a static buffer under RCU protection, or return while still holding the RCU lock and require the caller to release it:
```c
/* Option 1: Copy into static buffer */
static char default_name[TQUIC_CA_NAME_MAX];

const char *tquic_cong_get_default_name(void)
{
    rcu_read_lock();
    ca = rcu_dereference(default_ca);
    strscpy(default_name, ca->name, sizeof(default_name));
    rcu_read_unlock();
    return default_name;
}

/* Option 2: Caller-provided buffer */
void tquic_cong_get_default_name(char *buf, size_t len)
{
    rcu_read_lock();
    ca = rcu_dereference(default_ca);
    strscpy(buf, ca->name, len);
    rcu_read_unlock();
}
```

---

### HIGH-C1: Unprotected Global Loss Tracker Array

**File:** `/Users/justinadams/Downloads/tquic-kernel/net/tquic/cong/tquic_cong.c`
**Line:** ~74

**Description:** `loss_trackers` is a static global array indexed by `path_id`. Multiple connections using the same path_id (e.g., connections over the same network interface) share the same loss tracker entry without synchronization. Concurrent ACK processing on different connections for the same path will race on the tracker's fields.

**Impact:** Corrupted loss tracking data, leading to incorrect congestion responses (too aggressive or too conservative). Could be exploited to cause congestion collapse on a shared link.

**Fix:** Make loss trackers per-connection or per-path-context, not global. Alternatively, use atomic operations or per-CPU data:
```c
/* Per-connection loss tracker */
struct tquic_loss_tracker *tracker = &conn->path[path_id].loss_tracker;
```

---

### HIGH-C2: Global Congestion Data Cache Without Namespace Isolation

**File:** `/Users/justinadams/Downloads/tquic-kernel/net/tquic/cong/cong_data.c`
**Line:** ~47

**Description:** `cong_data_cache` is a static global array of 64 entries shared across all network namespaces. A container or network namespace can read/write congestion data that belongs to connections in a different namespace. The spinlock protects against races but not against cross-namespace information leakage.

**Impact:** Information disclosure across network namespace boundaries. An attacker in one container could learn RTT and bandwidth characteristics of connections in another container. This violates the network namespace isolation guarantee.

**Fix:** Make the cache per-netns:
```c
struct tquic_cong_data_cache {
    spinlock_t lock;
    struct cong_data_entry entries[CONG_DATA_CACHE_SIZE];
};
/* Register in net_generic */
static unsigned int cong_data_net_id;
```

---

### MEDIUM-C1: Sort Modifies Caller's Lost Packets Array

**File:** `/Users/justinadams/Downloads/tquic-kernel/net/tquic/cong/persistent_cong.c`
**Line:** ~221

**Description:** `tquic_check_persistent_cong()` calls the kernel `sort()` function on the caller-provided `lost_packets` array. This modifies the array in place, which the caller may not expect. If the caller iterates the array after this call assuming original order, behavior is incorrect.

**Impact:** Incorrect loss processing if any caller depends on the original packet order after calling persistent congestion check.

**Fix:** Either document clearly that the array is sorted in place, or sort a local copy:
```c
struct tquic_lost_packet *sorted;
sorted = kmemdup(lost_packets, count * sizeof(*sorted), GFP_ATOMIC);
if (!sorted) return false;
sort(sorted, count, sizeof(*sorted), cmp_lost_pkt, NULL);
/* ... use sorted ... */
kfree(sorted);
```

---

### MEDIUM-C2: Division Safety in Congestion Data Validation

**File:** `/Users/justinadams/Downloads/tquic-kernel/net/tquic/cong/cong_data.c`
**Line:** ~636

**Description:** `tquic_cong_data_on_ack()` computes `rtt_ratio = (rtt_us * 100) / state->validated_rtt`. The code checks `validated_rtt > 0` before the division. However, `validated_rtt` is set during the validation phase and could theoretically be zeroed by a concurrent reset. If the check and division are not atomic with respect to the state, a race could cause division by zero.

**Impact:** Kernel divide-by-zero exception (crash) if a race condition occurs.

**Fix:** Read `validated_rtt` into a local variable once:
```c
u64 vrtt = READ_ONCE(state->validated_rtt);
if (vrtt > 0) {
    rtt_ratio = (rtt_us * 100) / vrtt;
}
```

---

### MEDIUM-C3: ECN State Tracking Per-Round Limitation

**File:** `/Users/justinadams/Downloads/tquic-kernel/net/tquic/cong/tquic_cong.h`

**Description:** The ECN implementation limits CE (Congestion Experienced) responses to once per round, per RFC 9002. However, the round boundary is determined by packet number, and if packet numbers are not monotonically increasing (due to retransmission or multipath reordering), the round detection could fail, causing either no response or multiple responses to a single congestion event.

**Impact:** Suboptimal congestion response under multipath with reordering.

**Fix:** Use the largest acknowledged packet number (not the current packet number) to determine round boundaries, consistent with RFC 9002 Section 7.2.

---

### MEDIUM-C4: HMAC Stack Buffer Size

**File:** `/Users/justinadams/Downloads/tquic-kernel/net/tquic/cong/cong_data.c`
**Line:** ~811

**Description:** `tquic_cong_data_compute_hmac()` uses a stack buffer `u8 msg[128]` and builds the HMAC message incrementally. The current message is 52 bytes, which fits. However, if additional fields are added to the congestion data frame in the future without updating the buffer size, a stack buffer overflow would occur. There is no runtime check that the message does not exceed 128 bytes.

**Impact:** Potential future stack buffer overflow if the message format changes.

**Fix:** Add a bounds check:
```c
size_t offset = 0;
#define HMAC_APPEND(ptr, len) do {          \
    if (offset + (len) > sizeof(msg))       \
        return -EOVERFLOW;                  \
    memcpy(msg + offset, (ptr), (len));     \
    offset += (len);                        \
} while (0)
```

---

### LOW-C1: Constant-Time Comparison (Positive Note)

**File:** `/Users/justinadams/Downloads/tquic-kernel/net/tquic/cong/cong_data.c`

**Description:** The code correctly uses `crypto_memneq()` for HMAC comparison, preventing timing side-channel attacks. This is good practice.

---

### LOW-C2: Sensitive Key Cleanup (Positive Note)

**File:** `/Users/justinadams/Downloads/tquic-kernel/net/tquic/cong/cong_data.c`

**Description:** The code uses `kfree_sensitive()` when releasing congestion data state, ensuring that key material is zeroed before freeing. This is good practice.

---

### LOW-C3: BBR Auto-Selection for High-RTT Paths

**File:** `/Users/justinadams/Downloads/tquic-kernel/net/tquic/cong/tquic_cong.h`

**Description:** The header mentions automatic BBR selection for high-RTT paths. While the threshold was not fully audited (partial header read), this is a reasonable optimization. Care should be taken that the RTT threshold is not set too low, as BBR can be more aggressive than Cubic on low-RTT paths, potentially causing fairness issues.

**Impact:** Low. Operational consideration rather than security issue.

---

## Summary Table

| ID | Severity | Subsystem | Description |
|----|----------|-----------|-------------|
| CRITICAL-B1 | CRITICAL | Bonding | Integer overflow in coupled CC increase |
| CRITICAL-B2 | CRITICAL | Bonding | Same overflow in OLIA increase |
| CRITICAL-F1 | CRITICAL | FEC | Stack overflow in RS recovery (~5.3KB) |
| CRITICAL-C1 | CRITICAL | Congestion | Use-after-free in algorithm name return |
| HIGH-B1 | HIGH | Bonding | TOCTOU race in state transition |
| HIGH-B2 | HIGH | Bonding | Weight accumulation overflow |
| HIGH-B3 | HIGH | Bonding | Expensive computation in loss path |
| HIGH-F1 | HIGH | FEC | Large stack alloc in XOR recovery (1.5KB) |
| HIGH-F2 | HIGH | FEC | Same stack issue in encoder |
| HIGH-F3 | HIGH | FEC | Repair length truncation without validation |
| HIGH-F4 | HIGH | FEC | FEC scheme ID not validated from wire |
| HIGH-C1 | HIGH | Congestion | Unprotected global loss tracker array |
| HIGH-C2 | HIGH | Congestion | Global cache without netns isolation |
| MEDIUM-B1 | MEDIUM | Bonding | Signed arithmetic in in-flight calc |
| MEDIUM-B2 | MEDIUM | Bonding | Alignment issue in skb->cb u64 access |
| MEDIUM-B3 | MEDIUM | Bonding | Alpha precision loss in coupled CC |
| MEDIUM-F1 | MEDIUM | FEC | Nested locking without annotation |
| MEDIUM-F2 | MEDIUM | FEC | Lock ordering undocumented |
| MEDIUM-F3 | MEDIUM | FEC | Loss rate cast overflow |
| MEDIUM-C1 | MEDIUM | Congestion | Sort modifies caller array |
| MEDIUM-C2 | MEDIUM | Congestion | Division race in cong data validation |
| MEDIUM-C3 | MEDIUM | Congestion | ECN round detection under multipath |
| MEDIUM-C4 | MEDIUM | Congestion | HMAC buffer without bounds check |
| LOW-B1 | LOW | Bonding | Missing lock ordering documentation |
| LOW-F1 | LOW | FEC | C99 variable declaration in loop |
| LOW-F2 | LOW | FEC | Fragile repair data pointer lifetime |
| LOW-C1 | LOW | Congestion | (Positive) Constant-time HMAC comparison |
| LOW-C2 | LOW | Congestion | (Positive) Sensitive key cleanup |
| LOW-C3 | LOW | Congestion | BBR auto-selection threshold consideration |

---

## Recommended Fix Priority

1. **Immediate (CRITICAL):** CRITICAL-F1 (stack overflow, remotely triggerable), CRITICAL-B1/B2 (integer overflow in CC), CRITICAL-C1 (use-after-free)
2. **Next Sprint (HIGH):** HIGH-F3/F4 (wire input validation), HIGH-C1 (race condition), HIGH-C2 (namespace isolation), HIGH-B1 (TOCTOU), HIGH-F1/F2 (stack pressure)
3. **Planned (MEDIUM):** All MEDIUM items, prioritizing MEDIUM-C2 (division by zero) and MEDIUM-B2 (alignment)
4. **Backlog (LOW):** Documentation and style items

---

*End of audit report.*
