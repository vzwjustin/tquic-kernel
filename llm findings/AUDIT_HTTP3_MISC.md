# Security Audit: HTTP/3, WebTransport, QPACK, Diagnostics, and Miscellaneous Subsystems

**Auditor:** security-reviewer agent
**Date:** 2026-02-09
**Scope:** `net/tquic/http3/`, `net/tquic/diag/`, `net/tquic/test/`, `net/tquic/bench/`, `net/tquic/tquic_stream.c`, `include/net/tquic*.h`, `include/uapi/linux/tquic*.h`

---

## Executive Summary

This audit covers the HTTP/3 implementation (frame parsing, stream management, request handling, settings), QPACK header compression (encoder, decoder, dynamic table, static table, Huffman coding), WebTransport, diagnostics (qlog, path metrics, tracepoints), UAPI headers, and the stream socket layer. A total of **25 security findings** were identified: 4 CRITICAL, 7 HIGH, 10 MEDIUM, and 4 LOW severity.

The most severe issues are use-after-free vulnerabilities in the QPACK dynamic table and HTTP/3 stream lookup, a sleeping-under-spinlock bug in connection teardown, and an unbounded memory allocation in the path metrics netlink handler.

---

## Critical Issues

### C1. QPACK Dynamic Table Duplicate: Use-After-Free via Lock Drop

- **File:** `/Users/justinadams/Downloads/tquic-kernel/net/tquic/http3/qpack_dynamic.c`
- **Lines:** ~345-356
- **Description:** `qpack_dynamic_table_duplicate()` looks up a source entry pointer under the table spinlock, then drops the lock to perform a `kmalloc(GFP_KERNEL)` allocation, then re-acquires the lock and uses the original source pointer. Between the lock drop and re-acquisition, another thread can evict the source entry from the dynamic table, freeing it. The subsequent `memcpy` from the stale pointer is a use-after-free.
- **Impact:** An attacker who can trigger concurrent QPACK encoder instruction processing (e.g., via multiple streams referencing the same dynamic table) can cause kernel memory corruption, leading to privilege escalation or denial of service.
- **Recommendation:** Either (a) increment the entry's refcount before dropping the lock, or (b) copy the name/value data into a local buffer before dropping the lock, or (c) use `GFP_ATOMIC` allocation under the lock (acceptable for small allocations).

### C2. HTTP/3 Stream Lookup: Use-After-Free (No Refcount)

- **File:** `/Users/justinadams/Downloads/tquic-kernel/net/tquic/http3/http3_stream.c`
- **Lines:** `h3_stream_lookup()` function
- **Description:** `h3_stream_lookup()` returns a raw pointer to an `h3_stream` without incrementing its reference count. Callers use this pointer outside the lock that protected the lookup. If another thread closes/destroys the stream concurrently, the caller dereferences freed memory.
- **Impact:** Remote attacker can trigger this by rapidly opening and closing streams while sending frames that reference those streams. Results in use-after-free, potential code execution.
- **Recommendation:** Add `refcount_inc(&stream->refcount)` in `h3_stream_lookup()` and require all callers to call a corresponding `h3_stream_put()` when done.

### C3. Connection Destroy Calls Sleeping Function Under Spinlock

- **File:** `/Users/justinadams/Downloads/tquic-kernel/net/tquic/http3/http3_stream.c`
- **Lines:** `h3_connection_destroy()` function
- **Description:** `h3_connection_destroy()` iterates over streams under a spinlock and calls `tquic_stream_close()` for each. `tquic_stream_close()` may invoke allocation paths with `GFP_KERNEL` (sleeping allocation) or other sleeping operations. Calling a potentially-sleeping function under a spinlock causes a BUG on kernels with `CONFIG_DEBUG_ATOMIC_SLEEP`.
- **Impact:** Kernel panic (BUG) during connection teardown, causing denial of service. Easily triggered by any connection close.
- **Recommendation:** Collect stream pointers into a local list under the spinlock, release the spinlock, then close each stream outside the lock.

### C4. Path Metrics Netlink: Unbounded Allocation from Attacker-Influenced Value

- **File:** `/Users/justinadams/Downloads/tquic-kernel/net/tquic/diag/path_metrics.c`
- **Lines:** ~469 (`tquic_nl_get_all_paths()`)
- **Description:** The function allocates `nlmsg_new(NLMSG_DEFAULT_SIZE * conn->num_paths, GFP_KERNEL)`. `conn->num_paths` is influenced by the number of paths on a connection (up to `TQUIC_MAX_PATHS` = 16, but the multiplication with `NLMSG_DEFAULT_SIZE` (typically 8192) can be up to 128KB). While `TQUIC_MAX_PATHS=16` provides some bound, if `num_paths` is ever corrupted or the limit is raised, this becomes an unbounded allocation. More importantly, any unprivileged user can trigger this allocation (see H1).
- **Impact:** Local denial of service via repeated large kernel allocations. If `num_paths` validation is ever bypassed, attacker-controlled allocation size.
- **Recommendation:** Cap the allocation at a fixed reasonable maximum (e.g., `min(conn->num_paths, TQUIC_MAX_PATHS) * NLMSG_DEFAULT_SIZE`), and add the CAP_NET_ADMIN check from H1.

---

## High Severity Issues

### H1. Path Metrics Netlink: Missing CAP_NET_ADMIN Permission Check

- **File:** `/Users/justinadams/Downloads/tquic-kernel/net/tquic/diag/path_metrics.c`
- **Lines:** All netlink handler functions
- **Description:** The genetlink operations for path metrics export (`tquic_nl_get_path_metrics`, `tquic_nl_get_all_paths`, `tquic_nl_subscribe_events`) do not require `CAP_NET_ADMIN`. Any unprivileged local user can query connection metrics, subscribe to events, and enumerate all TQUIC connections.
- **Impact:** Information disclosure of network connection metadata (RTT, bandwidth, loss rates, connection IDs, peer addresses) to unprivileged users. Subscription flooding can also cause kernel memory exhaustion.
- **Recommendation:** Add `.policy` with `GENL_ADMIN_PERM` flag or explicit `CAP_NET_ADMIN` check in each handler.

### H2. QPACK Decoder: Unbounded Blocked Stream Memory Exhaustion

- **File:** `/Users/justinadams/Downloads/tquic-kernel/net/tquic/http3/qpack_decoder.c`
- **Lines:** ~320
- **Description:** When a header block references a dynamic table entry that has not yet been received (insert count > known received count), the decoder stores the entire header block data via `kmemdup(data, len, GFP_ATOMIC)`. While there is a `max_blocked_streams` limit on the count of blocked streams, there is no limit on the total memory consumed by blocked stream data. An attacker can send large header blocks (up to the maximum allowed) on each blocked stream.
- **Impact:** Remote attacker can exhaust kernel memory by sending many large header blocks that all reference high insert counts. With `max_blocked_streams=100` and headers up to the frame size limit, this could consume hundreds of megabytes.
- **Recommendation:** Track total blocked stream memory and enforce a per-connection limit (e.g., 1MB total blocked stream data).

### H3. WebTransport Context Destroy: Lock Drop During Iteration

- **File:** `/Users/justinadams/Downloads/tquic-kernel/net/tquic/http3/webtransport.c`
- **Lines:** `context_destroy()` function
- **Description:** During WebTransport context destruction, the function iterates over sessions and drops/re-acquires the lock for cleanup operations. This creates a window where the session list can be modified by concurrent operations, potentially causing list corruption or use-after-free of the iteration cursor.
- **Impact:** Kernel memory corruption during WebTransport session teardown, triggerable by a remote peer closing sessions concurrently.
- **Recommendation:** Use a safe iteration pattern: move items to a local list under the lock, release the lock, then process the local list.

### H4. WebTransport: Unbounded Capsule Buffer Growth

- **File:** `/Users/justinadams/Downloads/tquic-kernel/net/tquic/http3/webtransport.c`
- **Lines:** Capsule buffer accumulation
- **Description:** The capsule parsing code accumulates incoming capsule data into `capsule_buf` without enforcing a maximum total size. A remote peer can send an arbitrarily large capsule (or many partial capsules) to exhaust kernel memory.
- **Impact:** Remote denial of service via kernel memory exhaustion.
- **Recommendation:** Enforce a maximum capsule buffer size (e.g., 64KB or configurable via socket option) and reject connections that exceed it with `H3_EXCESSIVE_LOAD`.

### H5. HTTP/3 Settings Frame Length Truncation

- **File:** `/Users/justinadams/Downloads/tquic-kernel/net/tquic/http3/http3_stream.c`
- **Lines:** ~1127 (`h3_connection_send_settings()`)
- **Description:** The settings frame length is cast to `u8`: `*len_pos = (u8)settings_len;`. If the total settings payload exceeds 255 bytes, the length field is silently truncated. The peer will parse an incomplete settings frame, potentially interpreting subsequent data as a new frame.
- **Impact:** Protocol confusion: the truncated length causes the peer to misparse the stream, potentially leading to security-relevant misinterpretation of subsequent frames. While 255 bytes is sufficient for typical settings, extensions or future settings could exceed this.
- **Recommendation:** Use proper QUIC variable-length integer encoding for the frame length, or validate that `settings_len <= 255` before the cast and return an error if exceeded.

### H6. QPACK Encoder: Insert Count Increment Overflow

- **File:** `/Users/justinadams/Downloads/tquic-kernel/net/tquic/http3/qpack_encoder.c`
- **Lines:** ~704
- **Description:** The Insert Count Increment instruction handler adds the received value to `known_received_count` without overflow checking: `known_received_count += value;`. An attacker can send a crafted increment value that wraps the counter, causing the encoder to believe the decoder has received entries that do not exist.
- **Impact:** The encoder may reference non-existent dynamic table entries, causing the decoder to fail or reference wrong entries. This could lead to header injection if the wrong entry is referenced.
- **Recommendation:** Validate that `known_received_count + value <= insert_count` (the total entries ever inserted) and that the addition does not overflow.

### H7. HTTP/3 Request: TOCTOU Between State Check and Send

- **File:** `/Users/justinadams/Downloads/tquic-kernel/net/tquic/http3/http3_request.c`
- **Lines:** ~156-173 (`h3_request_send_headers()`)
- **Description:** The function checks the stream state under a lock, releases the lock, then performs the actual send operation without the lock. Between the check and the send, another thread can change the stream state (e.g., close the stream), causing the send to operate on a stream in an invalid state.
- **Impact:** Protocol violation, potential data corruption or crash if send operates on a closed/reset stream.
- **Recommendation:** Either hold the lock during the entire send operation, or re-validate state after acquiring any needed resources.

---

## Medium Severity Issues

### M1. HTTP/3 Frame Parsing: 16MB Maximum Frame Payload

- **File:** `/Users/justinadams/Downloads/tquic-kernel/net/tquic/http3/http3_frame.c`
- **Lines:** `H3_MAX_FRAME_PAYLOAD_SIZE` definition
- **Description:** `H3_MAX_FRAME_PAYLOAD_SIZE` is set to 16MB. While this is a valid limit, it means a single frame can cause a 16MB kernel allocation. Under memory pressure, this is significant.
- **Impact:** A remote attacker can trigger large kernel allocations by sending frames with large payload lengths.
- **Recommendation:** Consider reducing the default limit to 1MB or making it configurable. Most HTTP/3 frames (HEADERS, SETTINGS, GOAWAY) should be much smaller.

### M2. QPACK Huffman Decoder: O(n*256) Complexity

- **File:** `/Users/justinadams/Downloads/tquic-kernel/net/tquic/http3/qpack.c`
- **Lines:** Huffman decode function
- **Description:** The Huffman decoder uses a brute-force O(n * 256) algorithm that iterates over all 256 possible symbols for each input byte. This is significantly slower than a proper lookup-table or tree-based decoder.
- **Impact:** CPU exhaustion: an attacker can send Huffman-encoded headers that maximize decoding time. With large headers, this becomes a practical slowloris-style attack.
- **Recommendation:** Replace with a 256-entry lookup table or state-machine-based decoder (standard approach for HPACK/QPACK Huffman).

### M3. QPACK Integer Decode: Shift Overflow

- **File:** `/Users/justinadams/Downloads/tquic-kernel/net/tquic/http3/qpack.c`
- **Lines:** QPACK integer decode function
- **Description:** The QPACK integer decode loop accumulates `value |= (byte & 0x7f) << shift` and increments `shift` by 7 each iteration. If the input contains many continuation bytes, `shift` can exceed 63, causing undefined behavior for the left shift on a `u64`.
- **Impact:** Undefined behavior (implementation-defined on most architectures) that could produce incorrect values, leading to buffer overflows or other memory safety issues.
- **Recommendation:** Add a check: `if (shift > 62) return -H3_ERR_QPACK_DECOMPRESSION_FAILED;`

### M4. QPACK Encoder/Decoder: Excessive Stack Usage

- **File:** `/Users/justinadams/Downloads/tquic-kernel/net/tquic/http3/qpack_encoder.c`, `qpack_decoder.c`
- **Lines:** Various encode/decode functions
- **Description:** Multiple functions allocate large buffers on the stack:
  - `qpack_decoder`: `name_buf[256]` + `value_buf[8192]` = 8448 bytes
  - `qpack_encoder_insert_name_ref()`: `buf[QPACK_MAX_HEADER_VALUE_LEN + 32]` = 8224 bytes
  - `qpack_encoder_insert_literal()`: `buf[8512]` = 8512 bytes

  Kernel stack is typically 8KB-16KB. These allocations consume most of the available stack, leaving very little for called functions.
- **Impact:** Stack overflow if these functions are called from a deep call chain (e.g., interrupt context -> softirq -> QUIC receive -> QPACK decode). Results in kernel panic.
- **Recommendation:** Allocate these buffers dynamically with `kmalloc(GFP_ATOMIC)` or use a pre-allocated per-connection buffer.

### M5. HTTP/3 Settings Parser: TOCTOU on Settings Count

- **File:** `/Users/justinadams/Downloads/tquic-kernel/net/tquic/http3/http3_frame.c`
- **Lines:** Settings parsing function
- **Description:** The settings parser checks the count/length of settings, then processes them in a separate pass. If the underlying data can change between the check and the processing (e.g., if the buffer is shared), this is a TOCTOU vulnerability. In practice, this depends on whether the input buffer is guaranteed to be stable.
- **Impact:** If the buffer is shared, settings could be double-processed or skipped, potentially leading to protocol confusion.
- **Recommendation:** Ensure the input buffer is exclusively owned during parsing, or perform length validation inline during the single-pass parse.

### M6. HTTP/3 Connection: O(n) Push Entry Counting

- **File:** `/Users/justinadams/Downloads/tquic-kernel/net/tquic/http3/http3_conn.c`
- **Lines:** Push stream management functions
- **Description:** The connection counts push entries by iterating the entire push list on each operation, resulting in O(n) complexity. An attacker can create many push promises to make subsequent operations slow.
- **Impact:** CPU exhaustion for servers processing many push promises from a malicious client (or vice versa).
- **Recommendation:** Maintain a running counter of push entries instead of counting on demand.

### M7. WebTransport: TOCTOU in Datagram Queue Push

- **File:** `/Users/justinadams/Downloads/tquic-kernel/net/tquic/http3/webtransport.c`
- **Lines:** Datagram queue management
- **Description:** The datagram queue checks its current size, then pushes a new element. If two threads push concurrently, both may see the queue as under-limit and both push, exceeding the intended limit.
- **Impact:** Queue size limit bypass, potentially leading to memory exhaustion if the limit is the only defense against unbounded growth.
- **Recommendation:** Perform the size check and push atomically under a lock, or use an atomic counter with compare-and-swap.

### M8. Qlog Ring Buffer: Not Truly Lock-Free

- **File:** `/Users/justinadams/Downloads/tquic-kernel/net/tquic/diag/qlog.c`
- **Lines:** Ring buffer implementation
- **Description:** The qlog ring buffer is documented as lock-free but actually uses a spinlock for write operations. Under high event rates, this creates contention on the hot path.
- **Impact:** Performance degradation under high qlog event rates. Not a security vulnerability per se, but the misleading documentation could lead to incorrect assumptions about safety in interrupt context.
- **Recommendation:** Either implement a true lock-free ring buffer (using `smp_store_release`/`smp_load_acquire` pairs) or document the locking requirement clearly.

### M9. Qlog: JSON Strings Not Escaped

- **File:** `/Users/justinadams/Downloads/tquic-kernel/net/tquic/diag/qlog.c`
- **Lines:** JSON emission functions
- **Description:** When emitting JSON-formatted qlog events, string values (such as reason phrases from CONNECTION_CLOSE frames) are included without JSON escaping. If a reason phrase contains characters like `"`, `\`, or control characters, the resulting JSON is malformed.
- **Impact:** Malformed JSON output that could cause parsing failures in qlog consumers. If a qlog consumer naively processes the JSON (e.g., injecting into a web dashboard), this could be an XSS vector.
- **Recommendation:** Implement JSON string escaping for all string values emitted in qlog JSON output.

### M10. Path Metrics Subscription: Timer/Connection Lifetime Race

- **File:** `/Users/justinadams/Downloads/tquic-kernel/net/tquic/diag/path_metrics.c`
- **Lines:** Subscription timer callback
- **Description:** A metrics subscription timer can fire after the associated connection has been freed, if `tquic_metrics_unsubscribe_conn()` races with the timer callback. The timer callback accesses the connection pointer without verifying it is still valid.
- **Impact:** Use-after-free when the timer fires on a freed connection, causing kernel memory corruption.
- **Recommendation:** Use `del_timer_sync()` in `tquic_metrics_unsubscribe_conn()` to ensure the timer callback has completed before freeing the connection, or hold a connection reference in the subscription.

---

## Low Severity Issues

### L1. Duplicate Static Functions: h3_varint_encode/decode

- **File:** `/Users/justinadams/Downloads/tquic-kernel/net/tquic/http3/http3_request.c`, `http3_stream.c`
- **Lines:** Static `h3_varint_encode()` and `h3_varint_decode()` functions
- **Description:** Both files contain independent static implementations of varint encode/decode functions. If one is fixed for a bug and the other is not, inconsistent behavior results.
- **Impact:** Maintenance risk; potential for divergent behavior if one copy is patched but not the other.
- **Recommendation:** Move to a shared helper (e.g., in `http3_frame.c` or a common header as inline functions).

### L2. HTTP/3 Priority: push_buckets Not Initialized

- **File:** `/Users/justinadams/Downloads/tquic-kernel/net/tquic/http3/http3_priority.c`
- **Lines:** `push_buckets[]` array
- **Description:** The `push_buckets[]` array used for server push scheduling is not explicitly initialized in the priority scheduler initialization path. It relies on the structure being zeroed by `kzalloc`, which is correct but fragile.
- **Impact:** If the allocation path changes to use `kmalloc` instead of `kzalloc`, the array would contain garbage, leading to incorrect scheduling or null pointer dereferences.
- **Recommendation:** Explicitly initialize `push_buckets[]` in the priority init function for defensive coding.

### L3. Qlog: Lock Drop Around copy_to_user

- **File:** `/Users/justinadams/Downloads/tquic-kernel/net/tquic/diag/qlog.c`
- **Lines:** Ring buffer read path
- **Description:** The qlog read path drops the ring buffer lock before calling `copy_to_user()` (which may sleep). This is correct behavior (you cannot hold a spinlock across `copy_to_user`), but the entry being copied could be overwritten by a new event between the lock drop and the copy completion.
- **Impact:** Userspace may receive a partially old/partially new event if the ring buffer wraps during the copy. This is a data integrity issue, not a security vulnerability.
- **Recommendation:** Copy the entry to a local kernel buffer under the lock, then `copy_to_user` from the local buffer.

### L4. Benchmark Code: Userspace, Not Kernel

- **File:** `/Users/justinadams/Downloads/tquic-kernel/net/tquic/bench/bench_common.c` and related files
- **Lines:** All benchmark files
- **Description:** The benchmark code in `net/tquic/bench/` is userspace code using libc functions (`printf`, `malloc`, `FILE *`, `math.h`). It does not run in kernel context and is not compiled as part of the kernel module.
- **Impact:** No kernel security impact. The code is a test harness only.
- **Recommendation:** Consider moving benchmark code to a `tools/` or `tests/` directory to avoid confusion about its execution context.

---

## Positive Findings

The following areas demonstrate good security practices:

1. **QPACK Static Table** (`qpack_static.c`): Proper bounds checking in `qpack_static_get()` with `index >= QPACK_STATIC_TABLE_SIZE` guard. Clean, read-only data.

2. **HTTP/3 Settings** (`http3_settings.c`): Proper duplicate detection via `seen_mask`, correct GREASE handling (skip unknown identifiers per RFC 9114), and good value validation for each setting.

3. **UAPI Headers** (`include/uapi/linux/tquic.h`, `tquic_diag.h`, `tquic_qlog.h`, `tquic_pm.h`): Well-structured with proper `__u8/__u16/__u32/__u64` types, reasonable limits, proper include guards, reserved fields for future extension, and versioning.

4. **Tracepoints** (`diag/tracepoints.h`): Proper use of `min_t()` for CID length bounds in `TP_fast_assign`, preventing buffer overflows in tracepoint data. NULL checks before `memcpy`.

5. **WebTransport Header** (`webtransport.h`): Proper use of `refcount_t` for session reference counting, reasonable limits (`WEBTRANSPORT_MAX_SESSIONS=256`, `WEBTRANSPORT_MAX_URL_LEN=8192`).

6. **HTTP/3 Module Init** (`http3_module.c`): Proper error cleanup in reverse initialization order.

7. **Stream Socket Layer** (`tquic_stream.c`): Good use of kernel memory accounting APIs (`sk_wmem_schedule`, `sk_mem_charge`, `skb_set_owner_w`).

8. **QPACK Dynamic Table Refcounting** (`qpack_dynamic.c`): Uses `refcount_t` with proper `refcount_set/refcount_inc/refcount_dec_and_test` patterns (except for the C1 issue noted above).

9. **Trace Helper** (`diag/trace.h`): Safe fallback to no-op macros for out-of-tree builds. `quic_trace_conn_id()` safely bounds CID length to 8 bytes.

10. **Test Infrastructure** (`test/http3_test.c`, `test/security_test.c`): Good coverage of boundary values and security regression tests for known P0/P1 issues.

---

## Summary by Component

| Component | Critical | High | Medium | Low | Total |
|-----------|----------|------|--------|-----|-------|
| QPACK (encoder/decoder/dynamic) | 1 | 2 | 2 | 0 | 5 |
| HTTP/3 Stream Management | 2 | 1 | 0 | 0 | 3 |
| HTTP/3 Frame Parsing | 0 | 0 | 2 | 0 | 2 |
| HTTP/3 Request | 0 | 1 | 0 | 1 | 2 |
| HTTP/3 Connection | 0 | 0 | 1 | 0 | 1 |
| HTTP/3 Priority | 0 | 0 | 0 | 1 | 1 |
| WebTransport | 0 | 2 | 1 | 0 | 3 |
| Diagnostics (qlog) | 0 | 0 | 2 | 1 | 3 |
| Diagnostics (path_metrics) | 1 | 1 | 1 | 0 | 3 |
| Benchmark | 0 | 0 | 0 | 1 | 1 |
| UAPI/Headers | 0 | 0 | 0 | 0 | 0 |
| Test Infrastructure | 0 | 0 | 0 | 0 | 0 |
| **TOTAL** | **4** | **7** | **10** | **4** | **25** |

---

## Recommended Priority for Fixes

**Immediate (before any deployment):**
1. C1 - QPACK dynamic table use-after-free
2. C2 - HTTP/3 stream lookup use-after-free
3. C3 - Sleeping under spinlock in connection destroy
4. C4 - Path metrics unbounded allocation

**High priority (next release):**
5. H1 - Missing CAP_NET_ADMIN checks
6. H2 - QPACK blocked stream memory exhaustion
7. H3 - WebTransport lock drop during iteration
8. H4 - WebTransport capsule buffer growth
9. H5 - Settings frame length truncation
10. H6 - QPACK insert count overflow
11. H7 - Request send TOCTOU

**Medium priority (tracked for fix):**
12-21. All Medium severity issues

**Low priority (defense in depth):**
22-25. All Low severity issues
