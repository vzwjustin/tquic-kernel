# TQUIC Hot Path and I/O Subsystem Performance Audit

**Auditor:** Claude Opus 4.6 (kernel security reviewer)
**Date:** 2026-02-09
**Scope:** `net/tquic/tquic_input.c`, `net/tquic/tquic_output.c`, `net/tquic/tquic_zerocopy.c`, `net/tquic/napi.c`, `net/tquic/io_uring.c`, `net/tquic/core/packet.c`

---

## 1. Lock Contention

### CRITICAL: NAPI busy_poll per-skb lock/unlock cycle

- **File:** `/Users/justinadams/Downloads/tquic-kernel/net/tquic/napi.c:460-465`
- **Code:**
```c
while (work_done < budget) {
    spin_lock_irqsave(&tn->lock, flags);
    skb = __skb_dequeue(&tn->rx_queue);
    if (skb)
        atomic_dec(&tn->rx_queue_len);
    spin_unlock_irqrestore(&tn->lock, flags);
    ...
}
```
- **Description:** `tquic_busy_poll()` acquires and releases `tn->lock` once per packet in a tight loop. In contrast, `tquic_napi_poll()` at line 295 correctly uses `skb_queue_splice_init()` to batch-dequeue the entire queue under a single lock acquisition. The busy_poll path, which is specifically designed for latency-sensitive workloads, is performing far worse than the standard NAPI poll path due to this per-skb locking.
- **Impact:** Under high packet rates with busy polling enabled, this creates severe lock contention. Each lock/unlock pair includes IRQ save/restore overhead, multiplied by every packet processed.
- **Recommended fix:** Mirror the `tquic_napi_poll()` pattern -- use `skb_queue_splice_init()` to batch-dequeue into a local `sk_buff_head`, then process without holding the lock. Update `rx_queue_len` atomically by the batch count.

### HIGH: conn->lock released and reacquired during output flush stream iteration

- **File:** `/Users/justinadams/Downloads/tquic-kernel/net/tquic/tquic_output.c:2058-2072`
- **Code:**
```c
spin_lock_bh(&conn->lock);
if (conn->data_sent >= conn->max_data_remote) {
    spin_unlock_bh(&conn->lock);
    ...
}
conn_credit = conn->max_data_remote - conn->data_sent;
spin_unlock_bh(&conn->lock);

spin_lock_bh(&conn->lock);
for (node = rb_first(&conn->streams); node && packets_sent < 16;
     node = rb_next(node)) {
```
- **Description:** `tquic_output_flush()` takes `conn->lock`, checks flow control, releases it, then immediately re-takes it for stream iteration. This is a redundant lock release/acquire cycle that costs two atomic operations for no benefit. The flow control check and stream iteration could be done under a single lock hold.
- **Impact:** Two unnecessary atomic operations (cmpxchg or similar) per flush call. On systems with contended locks, this creates a window for preemption between the two acquisitions.
- **Recommended fix:** Merge the two critical sections into one: check flow control credit and begin stream iteration under the same `conn->lock` hold.

### HIGH: io_uring buffer ring spinlock per get/put operation

- **File:** `/Users/justinadams/Downloads/tquic-kernel/net/tquic/io_uring.c:804-838`
- **Code:**
```c
void *tquic_io_buf_ring_get(struct tquic_io_buf_ring *br, u16 *bid)
{
    spin_lock(&br->lock);
    ...
    spin_unlock(&br->lock);
}

void tquic_io_buf_ring_put(struct tquic_io_buf_ring *br, u16 bid)
{
    spin_lock(&br->lock);
    ...
    spin_unlock(&br->lock);
}
```
- **Description:** The buffer ring is a classic single-producer/single-consumer ring buffer, but uses a spinlock for every get and put operation. Since io_uring submission and completion typically run on the same thread (or with well-defined ordering), a lockless SPSC ring with `smp_store_release`/`smp_load_acquire` would eliminate all lock overhead.
- **Impact:** Every io_uring receive/send operation takes two spinlock acquisitions (get buffer, then put buffer). Under high I/O rates, this serializes all buffer ring operations.
- **Recommended fix:** If get/put are guaranteed to be called from different contexts (producer vs consumer), replace the spinlock with a lockless SPSC ring using `smp_store_release`/`smp_load_acquire` on head/tail. If multi-producer or multi-consumer, consider per-CPU rings or batch get/put APIs.

### MEDIUM: Multiple lock acquisitions in RX hot path

- **File:** `/Users/justinadams/Downloads/tquic-kernel/net/tquic/tquic_input.c` (throughout packet processing)
- **Description:** Processing a single incoming packet requires acquiring `conn->lock`, `conn->paths_lock`, `conn->streams_lock`, and potentially `conn->datagram.lock` at various points. Each lock acquisition/release pair adds cache line bouncing overhead.
- **Impact:** Moderate latency increase per packet, more significant under multipath where multiple paths may be processing concurrently.
- **Recommended fix:** Consider a hierarchical locking strategy where `conn->lock` covers paths and streams for the common case, with finer-grained locks only for specific concurrent access patterns. Alternatively, use RCU for read-mostly structures like the stream rb-tree.

---

## 2. Memory Allocation in Fast Path

### CRITICAL: Per-frame kzalloc + kmalloc in TX path

- **File:** `/Users/justinadams/Downloads/tquic-kernel/net/tquic/tquic_output.c:1806-1825`
- **Code:**
```c
/* Create pending frame */
frame = kzalloc(sizeof(*frame), GFP_ATOMIC);
if (unlikely(!frame)) {
    ret = -ENOMEM;
    break;
}

frame->type = TQUIC_FRAME_STREAM;
...
if (chunk > 0) {
    frame->data = kmalloc(chunk, GFP_ATOMIC);
    if (!frame->data) {
        kfree(frame);
        ret = -ENOMEM;
        break;
    }
    memcpy(frame->data, data + offset, chunk);
}
```
- **Description:** `tquic_xmit()` allocates two objects per STREAM frame: a `struct tquic_pending_frame` via `kzalloc` and a data buffer via `kmalloc`. For a typical 100KB transfer at 1200-byte chunks, this produces ~83 pairs of allocations (166 total `GFP_ATOMIC` allocations). `GFP_ATOMIC` allocations are more expensive than `GFP_KERNEL` and can fail under memory pressure.
- **Impact:** Significant CPU overhead from slab allocator calls in the TX hot path. Under memory pressure, `GFP_ATOMIC` failures will cause partial sends and retransmissions.
- **Recommended fix:** Create a dedicated `kmem_cache` for `struct tquic_pending_frame` (the RX path already uses `tquic_packet_cache` as a precedent). For frame data, consider embedding a small inline buffer (e.g., 128 bytes) in the frame struct for small frames, falling back to `kmalloc` only for larger chunks. Alternatively, use a per-connection slab or a free list of pre-allocated frames.

### HIGH: Per-STREAM-frame skb allocation in RX path

- **File:** `/Users/justinadams/Downloads/tquic-kernel/net/tquic/tquic_input.c:944-948`
- **Code:**
```c
data_skb = alloc_skb(length, GFP_ATOMIC);
if (!data_skb)
    return -ENOMEM;

skb_put_data(data_skb, ctx->data + ctx->offset, length);
```
- **Description:** Every incoming STREAM frame triggers a fresh `alloc_skb()` plus a full `memcpy` of the frame data. This is particularly wasteful because the data already exists in the decryption buffer (which itself came from a slab cache). The copy and allocation happen in softirq context with `GFP_ATOMIC`.
- **Impact:** One skb allocation and one memcpy per STREAM frame received, which can be thousands per second under load.
- **Recommended fix:** Use `skb_clone()` or page fragment references to avoid copying. If the decryption buffer is page-backed, create frags pointing to the original pages with appropriate reference counting, eliminating both the allocation and the copy.

### HIGH: kmalloc(path->mtu) per datagram send

- **File:** `/Users/justinadams/Downloads/tquic-kernel/net/tquic/tquic_output.c:2508`
- **Code:**
```c
buf = kmalloc(path->mtu, GFP_ATOMIC);
if (!buf)
    return -ENOMEM;
```
- **Description:** `tquic_send_datagram()` allocates a temporary buffer of `path->mtu` bytes (typically 1200-1500 bytes) for every datagram send, uses it to build the frame, then frees it. This is a classic pattern that should use a per-CPU or per-connection pre-allocated buffer.
- **Impact:** One `GFP_ATOMIC` allocation and free per datagram sent.
- **Recommended fix:** Use a per-connection pre-allocated scratch buffer (protected by `conn->lock` which is already held in the send path), or use a stack allocation since `path->mtu` is bounded and small (typically <= 1500 bytes; 1500 bytes on stack is acceptable in kernel context).

### MEDIUM: Per-chunk skb allocation in zerocopy path

- **File:** `/Users/justinadams/Downloads/tquic-kernel/net/tquic/tquic_zerocopy.c:297`
- **Code:**
```c
while (copied < len) {
    size_t chunk = min_t(size_t, len - copied, 1200);

    new_skb = alloc_skb(0, GFP_KERNEL);
    if (!new_skb) {
        err = -ENOMEM;
        goto out_err;
    }
```
- **Description:** The zerocopy send path allocates one skb per 1200-byte chunk. For a 1MB send, this is ~833 skb allocations. While `GFP_KERNEL` is used (allowing sleeping), the sheer volume of allocations is wasteful. The chunk size of 1200 is also suboptimal -- it should use the actual path MTU.
- **Impact:** Hundreds to thousands of skb allocations per large zerocopy send.
- **Recommended fix:** Batch skb allocation using `alloc_skb_with_frags()` or `napi_alloc_skb()` for bulk allocation. Use the path MTU instead of hardcoded 1200. Consider using GSO to coalesce multiple chunks into fewer skbs.

### MEDIUM: kzalloc per io_uring async request

- **File:** `/Users/justinadams/Downloads/tquic-kernel/net/tquic/io_uring.c:139`
- **Code:**
```c
data = kzalloc(sizeof(*data), GFP_KERNEL);
if (!data)
    return NULL;

req->async_data = data;
req->flags |= REQ_F_ASYNC_DATA;
```
- **Description:** Every io_uring TQUIC request allocates async data via `kzalloc`. io_uring has built-in mechanisms for async data that use the io_uring memory pool, avoiding the general-purpose allocator.
- **Impact:** One slab allocation per io_uring request, which under high-frequency I/O patterns can be thousands per second.
- **Recommended fix:** Use `io_alloc_async_data()` (io_uring's internal API) or the req's inline async data storage if the struct fits. This avoids the general allocator and leverages io_uring's pre-allocated memory pools.

---

## 3. Cache Line False Sharing

### HIGH: struct tquic_napi mixes hot and cold fields

- **File:** `/Users/justinadams/Downloads/tquic-kernel/net/tquic/napi.h`
- **Description:** The `struct tquic_napi` packs frequently-written fields (stats counters, `rx_queue_len` atomic, `state`) alongside rarely-changed configuration fields (coalesce parameters, `busy_poll_enabled`) and the NAPI struct itself. When the poll path increments `stats.poll_cycles`, it dirties the cache line that also contains `coalesce` configuration, causing unnecessary cache invalidations on other CPUs reading the coalesce config.
- **Impact:** Cache line bouncing between CPUs, particularly harmful in multi-queue NIC configurations where different CPUs poll different NAPI instances but may read each other's coalesce settings.
- **Recommended fix:** Reorganize the struct with `____cacheline_aligned_in_smp` annotations:
  1. Group read-mostly fields (config, coalesce, enabled flags) together
  2. Group write-heavy fields (stats, state, queue_len) together with explicit cache line alignment
  3. Place the lock on its own cache line

### MEDIUM: Global atomic64 stats counters shared across CPUs

- **File:** `/Users/justinadams/Downloads/tquic-kernel/net/tquic/napi.c:308,477`
- **Code:**
```c
atomic64_inc(&tquic_napi_global_stats.total_polls);     // line 308
atomic64_add(work_done, &tquic_napi_global_stats.busy_poll_packets); // line 477
```
- **Description:** Global `atomic64` counters are incremented on every NAPI poll cycle and every busy_poll cycle, in addition to per-CPU counters. The global atomics create a shared cache line that bounces between all CPUs doing NAPI processing.
- **Impact:** Cache line bouncing on the global stats structure for every poll/busy_poll invocation across all CPUs.
- **Recommended fix:** Remove the global atomic counters entirely. They are redundant with the per-CPU counters. Aggregate per-CPU stats on-demand when reading via procfs/sysfs (the `tquic_napi_aggregate_pcpu_stats()` function already exists for this purpose).

---

## 4. Unnecessary memcpy

### HIGH: Double copy in RX STREAM frame processing

- **File:** `/Users/justinadams/Downloads/tquic-kernel/net/tquic/tquic_input.c:944-948`
- **Code:**
```c
data_skb = alloc_skb(length, GFP_ATOMIC);
...
skb_put_data(data_skb, ctx->data + ctx->offset, length);
```
- **Description:** Data arriving from the network is first decrypted into a slab-allocated buffer (`ctx->data`), then copied again into a freshly allocated skb via `skb_put_data()`. This is a full copy of every byte of STREAM data received.
- **Impact:** For a 10 Gbps link with ~1200-byte frames, this is approximately 1M copies/sec, each touching both source and destination cache lines.
- **Recommended fix:** Avoid the second copy. Options:
  1. Decrypt directly into the skb's data area (requires pre-allocating the skb before decryption)
  2. Use page fragments: decrypt into page-backed buffers, then add page frags to skb via `skb_fill_page_desc()` with `get_page()` reference
  3. Use `skb_copy_bits()` with scatter-gather to reference the existing buffer

### MEDIUM: memcpy of TX frame data from userspace into frame, then into skb

- **File:** `/Users/justinadams/Downloads/tquic-kernel/net/tquic/tquic_output.c:1825`
- **Code:**
```c
memcpy(frame->data, data + offset, chunk);
```
- **Description:** In `tquic_xmit()`, data is copied from the source buffer into `frame->data` (a newly kmalloc'd buffer), then later when the packet is assembled, it gets copied again into the skb. This double-copy is inherent in the pending frame design.
- **Impact:** Every byte sent is copied twice through the TX path before reaching the NIC driver.
- **Recommended fix:** Consider a zero-copy frame design where the pending frame holds a reference (page frag or skb frag) to the original data rather than copying it. For the non-zerocopy path, at minimum use `copy_from_iter()` directly into the final skb to eliminate one copy.

---

## 5. Zero-Copy Correctness

### HIGH: Infinite retry loop on EMSGSIZE/EEXIST

- **File:** `/Users/justinadams/Downloads/tquic-kernel/net/tquic/tquic_zerocopy.c:315-318`
- **Code:**
```c
if (err == -EMSGSIZE || err == -EEXIST) {
    /* Try with a new skb */
    continue;
}
```
- **Description:** When `TQUIC_SKB_ZEROCOPY_ITER_STREAM()` returns `-EMSGSIZE` or `-EEXIST`, the loop frees the current skb and retries with a new one -- but `copied` is not advanced, so the same chunk is retried indefinitely. If the error condition is persistent (e.g., the chunk size always exceeds some limit), this becomes an infinite loop in kernel context.
- **Impact:** Potential kernel soft-lockup or hang in the sendmsg syscall path. This is exploitable by any local user with a TQUIC socket.
- **Recommended fix:** Add a retry counter (e.g., max 3 retries) and return an error after exhausting retries. Alternatively, adjust the chunk size downward on EMSGSIZE before retrying.

### MEDIUM: Hardcoded 1200-byte chunk size ignores path MTU

- **File:** `/Users/justinadams/Downloads/tquic-kernel/net/tquic/tquic_zerocopy.c:293`
- **Code:**
```c
size_t chunk = min_t(size_t, len - copied, 1200);
```
- **Description:** The zerocopy path hardcodes 1200 bytes as the chunk size (QUIC minimum MTU), ignoring the actual path MTU which could be 1452 or higher. This creates more skbs and more overhead than necessary on paths with larger MTUs.
- **Impact:** ~17% more skb allocations than necessary on a typical 1452-byte MTU path.
- **Recommended fix:** Use the connection's path MTU (minus overhead for QUIC headers) instead of the hardcoded 1200.

---

## 6. NAPI Polling Efficiency

### HIGH: Redundant triple-counting of statistics

- **File:** `/Users/justinadams/Downloads/tquic-kernel/net/tquic/napi.c:306-308`
- **Code:**
```c
tn->stats.poll_cycles++;
this_cpu_inc(tquic_napi_pcpu_stats.total_polls);
atomic64_inc(&tquic_napi_global_stats.total_polls);
```
- **Description:** Every NAPI poll cycle increments three separate counters: the per-NAPI instance stats, per-CPU stats, and global atomic stats. This is triply redundant. The per-CPU stats can be aggregated to produce global stats, and the per-NAPI stats are a subset of per-CPU stats.
- **Impact:** Three memory writes (one of which is an atomic RMW on a shared cache line) for every NAPI poll invocation. The atomic global counter is particularly harmful as it serializes across all CPUs.
- **Recommended fix:** Keep only per-CPU stats. Remove `tn->stats` (or make it derived) and remove global atomic counters. Aggregate on-demand via `tquic_napi_aggregate_pcpu_stats()` for reporting.

### MEDIUM: atomic_inc/dec for rx_queue_len on every enqueue/dequeue

- **File:** `/Users/justinadams/Downloads/tquic-kernel/net/tquic/napi.c:464,689`
- **Description:** `rx_queue_len` is maintained as an `atomic_t` and incremented on every enqueue, decremented on every dequeue. However, in the NAPI poll path the queue is drained via `skb_queue_splice_init()` which already knows the count (via `skb_queue_len()`), making the separate atomic counter redundant.
- **Impact:** One atomic RMW per packet enqueued and dequeued.
- **Recommended fix:** Remove `rx_queue_len` atomic. Use `skb_queue_len(&tn->rx_queue)` when the length is needed (it reads `qlen` from the queue head, which is maintained by `__skb_queue_tail`/`__skb_dequeue` already under the queue's lock).

---

## 7. io_uring Handling

### HIGH: Kernel address stored as u64 in buffer ring entries

- **File:** `/Users/justinadams/Downloads/tquic-kernel/net/tquic/io_uring.c:833`
- **Code:**
```c
br->br->bufs[tail].addr = (u64)(br->buf_base + bid * br->buf_size);
```
- **Description:** A kernel virtual address is cast to `u64` and stored in a buffer ring entry struct field named `addr`. If this struct is ever exposed to userspace (which is the normal io_uring buffer ring model), this leaks kernel ASLR. Even if the struct is kernel-only, this pattern is fragile and error-prone.
- **Impact:** Potential kernel address leak to userspace, defeating KASLR. This is a security concern in addition to a design concern.
- **Recommended fix:** Use buffer IDs (indices) rather than raw kernel addresses. Store the base address separately in a kernel-only structure and compute the buffer address from `base + bid * size` at use time, never exposing the kernel address in shared structures.

### MEDIUM: Missing batch API for buffer ring operations

- **File:** `/Users/justinadams/Downloads/tquic-kernel/net/tquic/io_uring.c:799-838`
- **Description:** `tquic_io_buf_ring_get()` and `tquic_io_buf_ring_put()` acquire and release the spinlock for every single buffer operation. When processing a batch of I/O completions, this means N lock/unlock pairs instead of one.
- **Impact:** Lock overhead scales linearly with batch size.
- **Recommended fix:** Add batch APIs: `tquic_io_buf_ring_get_batch(br, bufs, bids, count)` and `tquic_io_buf_ring_put_batch(br, bids, count)` that acquire the lock once for multiple operations.

---

## 8. Atomic Operation Hot Spots

### HIGH: atomic64_inc_return for packet number on every TX

- **File:** `/Users/justinadams/Downloads/tquic-kernel/net/tquic/tquic_output.c:1785`
- **Code:**
```c
pkt_num = atomic64_inc_return(&conn->pkt_num_tx) - 1;
```
- **Description:** Every packet sent uses `atomic64_inc_return()` to generate a packet number. This is a full memory barrier atomic RMW operation. However, the TX path is typically serialized by `conn->lock` (or should be, since packet numbers must be monotonic and gap-free within a packet number space). If `conn->lock` is already held, the atomic is unnecessary overhead.
- **Impact:** One atomic RMW (with implicit memory barrier) per TX packet.
- **Recommended fix:** If the TX path is always serialized by `conn->lock`, replace with a plain `u64` increment. If not always locked, document which paths require the atomic and consider whether a per-path packet number counter with a regular lock would be more appropriate.

### MEDIUM: Multiple atomic operations in NAPI enqueue path

- **File:** `/Users/justinadams/Downloads/tquic-kernel/net/tquic/napi.c:689` (and surrounding)
- **Description:** Enqueuing a single packet into the NAPI RX queue involves: `spin_lock_irqsave` (atomic CAS), `__skb_queue_tail` (increments qlen), `atomic_inc(&tn->rx_queue_len)`, `spin_unlock_irqrestore`. That is at least 3 atomic operations per packet in the hot enqueue path.
- **Impact:** Cumulative overhead on high-packet-rate workloads.
- **Recommended fix:** Remove the redundant `rx_queue_len` atomic (as noted above). This reduces to the minimum of one lock acquisition per enqueue.

---

## Summary Table

| # | Category | Severity | File | Line(s) |
|---|----------|----------|------|---------|
| 1 | Lock contention | CRITICAL | napi.c | 460-465 |
| 2 | Fast-path alloc | CRITICAL | tquic_output.c | 1806-1825 |
| 3 | Lock contention | HIGH | tquic_output.c | 2058-2072 |
| 4 | Lock contention | HIGH | io_uring.c | 804-838 |
| 5 | Memcpy | HIGH | tquic_input.c | 944-948 |
| 6 | Fast-path alloc | HIGH | tquic_input.c | 944 |
| 7 | Fast-path alloc | HIGH | tquic_output.c | 2508 |
| 8 | NAPI stats | HIGH | napi.c | 306-308 |
| 9 | Atomic hotspot | HIGH | tquic_output.c | 1785 |
| 10 | io_uring security | HIGH | io_uring.c | 833 |
| 11 | Zero-copy | HIGH | tquic_zerocopy.c | 315-318 |
| 12 | False sharing | HIGH | napi.h | struct tquic_napi |
| 13 | False sharing | MEDIUM | napi.c | 308, 477 |
| 14 | Lock contention | MEDIUM | tquic_input.c | multiple |
| 15 | Fast-path alloc | MEDIUM | tquic_zerocopy.c | 297 |
| 16 | Fast-path alloc | MEDIUM | io_uring.c | 139 |
| 17 | Memcpy | MEDIUM | tquic_output.c | 1825 |
| 18 | Zero-copy | MEDIUM | tquic_zerocopy.c | 293 |
| 19 | NAPI | MEDIUM | napi.c | 464, 689 |
| 20 | io_uring | MEDIUM | io_uring.c | 799-838 |
| 21 | Atomic hotspot | MEDIUM | napi.c | 689 |

**Total findings: 21**
- CRITICAL: 2
- HIGH: 10
- MEDIUM: 9

---

*Generated by kernel security reviewer agent, Claude Opus 4.6*
