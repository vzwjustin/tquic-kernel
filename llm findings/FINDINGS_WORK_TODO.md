# TQUIC Kernel Findings -- Work TODO

> Generated from `JUDGED_FINDINGS.json` by the Skeptical Code Audit Judge.
> **645** consolidated findings judged. Work items below organized by
> verdict (certainty) then severity (impact), then category (fix-domain).

## How to Use This File

1. Work **top-down**: CERTIFIED S0 first, then CERTIFIED S1, etc.
2. For each finding: verify, fix, test, then check the box.
3. PLAUSIBLE items need evidence gaps filled before fixing.
4. SPECULATIVE items need investigation before any code change.
5. REJECTED items are listed for completeness -- skip unless new evidence appears.

## Summary

| Verdict | S0 | S1 | S2 | S3 | Total |
|---|---:|---:|---:|---:|---:|
| CERTIFIED | 40 | 55 | 41 | 19 | **155** |
| PLAUSIBLE | 72 | 96 | 122 | 74 | **364** |
| SPECULATIVE | 23 | 22 | 28 | 43 | **116** |
| REJECTED | 0 | 1 | 0 | 9 | **10** |

**Progress: 167 / 645 findings fixed.**

---

## Phase Plan

### Phase 1: CERTIFIED S0 -- Critical Confirmed Bugs (40 items)
Memory safety + security fixes first, then concurrency, then correctness.
These have strong evidence and multi-source agreement. Fix immediately.

### Phase 2: CERTIFIED S1 -- High Confirmed Bugs (55 items)
Same approach. High impact, strong evidence.

### Phase 3: PLAUSIBLE S0 -- Critical Likely Bugs (72 items)
Fill evidence gaps (get line ranges, snippets) then fix.

### Phase 4: PLAUSIBLE S1 -- High Likely Bugs (96 items)
Fill evidence gaps then fix.

### Phase 5: CERTIFIED S2/S3 -- Medium/Low Confirmed (60 items)
Lower urgency but confirmed. Schedule after critical work.

### Phase 6: Remaining PLAUSIBLE S2/S3 (196 items)
Backlog. Address as capacity allows.

### Phase 7: SPECULATIVE (116 items)
Investigate. Promote or discard based on evidence.

### Phase 8: REJECTED (10 items)
Parked. Only revisit if new evidence surfaces.

---

## Phase 1: CERTIFIED S0 -- Critical Confirmed (40 items)

#### Memory (10)

- [x] **CF-006** -- HTTP/3 Stream Lookup: Use-After-Free
  - Severity: S0 | Sources: A,B,C | Priority: 10.0
  - Evidence: file:1, sym:5
  - Missing: Exact line range(s) where the fault manifests; Code snippet proving the vulnerable pattern
  - Verify: `rg -n "free" "net/tquic/http3/http3_stream.c"`
  - Fix: Add `refcount_inc(&stream->refcount)` in `h3_stream_lookup()` and require all callers to call a corresponding `h3_stream_put()` when done. Risk: Fixes

- [x] **CF-009** -- QPACK Dynamic Table Duplicate: Use-After-Free via Lock Drop
  - Severity: S0 | Sources: A,B,C | Priority: 10.0
  - Evidence: file:1, sym:5
  - Missing: Exact line range(s) where the fault manifests; Code snippet proving the vulnerable pattern
  - Verify: `rg -n "either" "net/tquic/http3/qpack_dynamic.c"`
  - Fix: Either (a) increment the entry's refcount before dropping the lock, or (b) copy the name/value data into a local buffer before dropping the lock, or (

- [x] **CF-011** -- Stack Buffer Overflow in HKDF-Expand-Label
  - Severity: S0 | Sources: A,B,C | Priority: 10.0
  - Evidence: file:1, sym:3, lines:1
  - Missing: Code snippet proving the vulnerable pattern; Kernel log / stack trace / error output demonstrating the issue
  - Verify: `rg -n "label" "net/tquic/crypto/handshake.c"`
  - Fix: Add explicit bounds check: `if (label_len + context_len + 10 > sizeof(hkdf_label)) return -EINVAL;` before any writes to the buffer. Note: the zero_rt

- [x] **CF-015** -- `tquic_hs_process_new_session_ticket` -- nonce overflow into session ticket
  - Severity: S0 | Sources: B,C | Priority: 10.0
  - Evidence: file:1, sym:3, lines:1, snippet:3
  - Missing: Kernel log / stack trace / error output demonstrating the issue
  - Verify: `rg -n "tquic_session_ticket" "net/tquic/crypto/handshake.c"`
  - Fix: Add strict validation and bounds checks at parse boundaries, enforce lifetime/ownership rules, and fail closed on malformed input. Risk: Fixes in pars

- [x] **CF-030** -- Handshake Packet Parsing with Unvalidated Offsets
  - Severity: S0 | Sources: B,C | Priority: 10.0
  - Evidence: file:1, sym:1, lines:5, snippet:1
  - Missing: Kernel log / stack trace / error output demonstrating the issue
  - Verify: `rg -n "tquic_parse_long_header" "net/tquic/core/connection.c"`
  - Fix: Replace the ad-hoc parsing with calls to the existing safe header parser `tquic_parse_long_header()`, or add proper bounds checks before every `data[h

- [x] **CF-046** -- Per-frame kzalloc + kmalloc in TX path
  - Severity: S0 | Sources: A,B | Priority: 10.0
  - Evidence: file:5, sym:18, lines:5, snippet:4
  - Missing: Kernel log / stack trace / error output demonstrating the issue
  - Verify: `rg -n "cache" "net/tquic/tquic_output.c"`
  - Fix: 1. Use a slab cache (`kmem_cache`) for `tquic_pending_frame` structs (fixed size, high churn). 2. Eliminate the intermediate data copy entirely -- wri

- [x] **CF-053** -- Retry Token Validation -- Plaintext Buffer Overread
  - Severity: S0 | Sources: B,C | Priority: 10.0
  - Evidence: file:1, lines:1, snippet:3
  - Missing: Function/struct symbol name at the fault site; Kernel log / stack trace / error output demonstrating the issue
  - Verify: `sed -n '1195,1195p' net/tquic/core/connection.c`
  - Fix: Add `if (ciphertext_len > sizeof(plaintext)) return -EINVAL;` before the memcpy. Risk: Fixes in parser/crypto/lifetime code may alter packet acceptanc

- [x] **CF-054** -- Server Accept CID Parsing Missing Bounds Checks -- Buffer Over-Read
  - Severity: S0 | Sources: B,C | Priority: 10.0
  - Evidence: file:1, sym:1, lines:2, snippet:3
  - Missing: Kernel log / stack trace / error output demonstrating the issue
  - Verify: `rg -n "tquic_cid" "net/tquic/core/connection.c"`
  - Fix: Add bounds validation: ```c if (offset >= len) goto err_free; dcid_len = data[offset++]; if (dcid_len > TQUIC_MAX_CID_LEN) goto err_free; if (offset +

- [x] **CF-058** -- Stack buffer overflow in `tquic_hs_hkdf_expand_label` -- unbounded label/context write to 512-byte s
  - Severity: S0 | Sources: B,C | Priority: 10.0
  - Evidence: file:1, sym:8, lines:1, snippet:5
  - Missing: Kernel log / stack trace / error output demonstrating the issue
  - Verify: `rg -n "tquic_handshake" "net/tquic/crypto/handshake.c"`
  - Fix: Add bounds checking throughout `tquic_hs_build_ch_extensions`. Every write to `p` must verify `p + N <= buf + buf_len` before writing. Use a macro sim

- [x] **CF-068** -- Use-After-Free in Path Lookup
  - Severity: S0 | Sources: A,B | Priority: 10.0
  - Evidence: file:2, sym:8, lines:4, snippet:1
  - Missing: Kernel log / stack trace / error output demonstrating the issue
  - Verify: `rg -n "memcmp" "net/tquic/tquic_input.c"`
  - Fix: - Compare by `ss_family`, then compare only the relevant address+port fields for that family. Risk: Fixes in parser/crypto/lifetime code may alter pac

#### Security (6)

- [x] **CF-003** -- Client Certificate Verification Uses Server Logic
  - Severity: S0 | Sources: A,B,C | Priority: 10.0
  - Evidence: file:1, sym:5, lines:2, snippet:2
  - Missing: Kernel log / stack trace / error output demonstrating the issue
  - Verify: `rg -n "tquic_hs_verify_client_cert" "net/tquic/crypto/cert_verify.c"`
  - Fix: Add a `bool is_server` parameter to the internal `verify_chain()` call path, or refactor so that client cert verification passes `is_server=false`. Ri

- [x] **CF-005** -- Fragile Hardcoded Offset for Key Update State Access
  - Severity: S0 | Sources: A,B,C | Priority: 10.0
  - Evidence: file:1, sym:9, snippet:4
  - Missing: Exact line range(s) where the fault manifests; Kernel log / stack trace / error output demonstrating the issue
  - Verify: `rg -n "change" "net/tquic/crypto/key_update.c"`
  - Fix: Use a proper typed structure with a named field, or use `container_of()` macro. Never use raw byte offsets to access structure members. Define a prope

- [x] **CF-007** -- OCSP Stapling Response Accepted Without Any Verification
  - Severity: S0 | Sources: A,B,C | Priority: 10.0
  - Evidence: file:1, sym:6, snippet:2
  - Missing: Exact line range(s) where the fault manifests; Kernel log / stack trace / error output demonstrating the issue
  - Verify: `rg -n "pr_debug" "net/tquic/crypto/cert_verify.c"`
  - Fix: Either implement OCSP response verification or remove the early return so that the "no OCSP available" path is taken, which at least logs warnings in 

- [x] **CF-008** -- Path Metrics Netlink: Unbounded Allocation from Attacker-Influenced Value
  - Severity: S0 | Sources: A,B,C | Priority: 10.0
  - Evidence: file:1, sym:6
  - Missing: Exact line range(s) where the fault manifests; Code snippet proving the vulnerable pattern
  - Verify: `rg -n "allocation" "net/tquic/diag/path_metrics.c"`
  - Fix: Cap the allocation at a fixed reasonable maximum (e.g., `min(conn->num_paths, TQUIC_MAX_PATHS) * NLMSG_DEFAULT_SIZE`), and add the CAP_NET_ADMIN check

- [x] **CF-010** -- Self-Signed Certificate Comparison Uses Non-Constant-Time memcmp in One Path
  - Severity: S0 | Sources: A,B,C | Priority: 10.0
  - Evidence: file:1, sym:7, lines:4, snippet:2
  - Missing: Kernel log / stack trace / error output demonstrating the issue
  - Verify: `rg -n "comparison" "net/tquic/crypto/cert_verify.c"`
  - Fix: Use `crypto_memneq()` consistently for all comparisons, or use `memcmp()` consistently for non-secret data. The key point is to be consistent and use 

- [x] **CF-061** -- tquic_conn_server_accept() -- err_free leaks registered CIDs, work items, timers, crypto state
  - Severity: S0 | Sources: B,C | Priority: 10.0
  - Evidence: file:1, sym:6, lines:5, snippet:2
  - Missing: Kernel log / stack trace / error output demonstrating the issue
  - Verify: `rg -n "tquic_crypto_init_versioned" "net/quic/tquic/core/connection.c"`
  - Fix: Create incremental error labels: ``` err_free_crypto:     tquic_crypto_free(conn->crypto_state);     conn->crypto_state = NULL; err_free_cids:     /* 

#### Concurrency (12)

- [x] **CF-004** -- Connection Destroy Calls Sleeping Function Under Spinlock
  - Severity: S0 | Sources: A,B,C | Priority: 10.0
  - Evidence: file:1, sym:3
  - Missing: Exact line range(s) where the fault manifests; Code snippet proving the vulnerable pattern
  - Verify: `rg -n "h3_connection_destroy" "net/tquic/http3/http3_stream.c"`
  - Fix: Collect stream pointers into a local list under the spinlock, release the spinlock, then close each stream outside the lock. Risk: Locking/ordering ch

- [x] **CF-023** -- Busy-poll per-packet lock/unlock
  - Severity: S0 | Sources: A,B | Priority: 10.0
  - Evidence: file:2, sym:8, lines:3, snippet:1
  - Missing: Kernel log / stack trace / error output demonstrating the issue
  - Verify: `rg -n "__skb_dequeue" "net/tquic/napi.c"`
  - Fix: Use the same batch-splice pattern as `tquic_napi_poll()`: splice the queue to a local list under a single lock acquisition, then process without holdi

- [x] **CF-029** -- GSO SKB Allocation Multiplication Overflow
  - Severity: S0 | Sources: B,C | Priority: 10.0
  - Evidence: file:1, sym:2, lines:1, snippet:3
  - Missing: Kernel log / stack trace / error output demonstrating the issue
  - Verify: `rg -n "tquic_output" "net/quic/tquic/tquic_output.c"`
  - Fix: Use `check_mul_overflow` and `check_add_overflow`: ```c size_t alloc_size; if (check_mul_overflow((size_t)gso->gso_size, (size_t)max_segs, &alloc_size

- [x] **CF-033** -- Install Secrets Accesses State Without Lock After Unlock
  - Severity: S0 | Sources: B,C | Priority: 10.0
  - Evidence: file:1, sym:2, lines:5, snippet:1
  - Missing: Kernel log / stack trace / error output demonstrating the issue
  - Verify: `rg -n "tquic_ku_derive_keys" "net/tquic/crypto/key_update.c"`
  - Fix: Copy the secrets into local variables under the lock, then derive from the local copies (the pattern already used correctly in `tquic_initiate_key_upd

- [x] **CF-038** -- Nested Lock Hierarchy Violation in Timer Code
  - Severity: S0 | Sources: B,C | Priority: 10.0
  - Evidence: file:1, sym:4, lines:5, snippet:5
  - Missing: Kernel log / stack trace / error output demonstrating the issue
  - Verify: `rg -n "tquic_timer_update_pto" "net/quic/tquic/tquic_timer.c"`
  - Fix: Standardize ALL uses of `rs->lock` and `pns->lock` to use `spin_lock_bh` Risk: Locking/ordering changes can cause deadlocks or throughput regressions 

- [x] **CF-045** -- Path Pointer Use After Lock Release
  - Severity: S0 | Sources: B,C | Priority: 10.0
  - Evidence: file:1, sym:6, lines:2, snippet:1
  - Missing: Kernel log / stack trace / error output demonstrating the issue
  - Verify: `rg -n "sockaddr_storage" "net/quic/tquic/tquic_input.c"`
  - Fix: Take a reference on the path before releasing the lock: `tquic_path_get(found)` and require callers to call `tquic_path_put()`. Risk: Locking/ordering

- [x] **CF-047** -- Per-Packet crypto_aead_setkey on Shared AEAD Handle -- Race Condition
  - Severity: S0 | Sources: B,C | Priority: 10.0
  - Evidence: file:1, sym:4, lines:2, snippet:1
  - Missing: Kernel log / stack trace / error output demonstrating the issue
  - Verify: `rg -n "tquic_decrypt_packet" "net/tquic/crypto/tls.c"`
  - Fix: Use separate AEAD transform handles for TX and RX, each with the key set once during key installation (not per-packet). The `quic_crypto.c` file alrea

- [x] **CF-051** -- Race Condition Between `tquic_destroy_sock()` and Poll/Sendmsg/Recvmsg
  - Severity: S0 | Sources: B,C | Priority: 10.0
  - Evidence: file:1, sym:9, lines:1, snippet:3
  - Missing: Kernel log / stack trace / error output demonstrating the issue
  - Verify: `rg -n "read_once" "net/tquic/tquic_socket.c"`
  - Fix: This is acceptable for poll() semantics (spurious wakeups are allowed), but document the intentional lockless access. Risk: Locking/ordering changes c

- [x] **CF-055** -- Slab Cache Decryption Buffer May Be Too Small for Payload
  - Severity: S0 | Sources: B,C | Priority: 10.0
  - Evidence: file:1, sym:5, lines:10, snippet:2
  - Missing: Kernel log / stack trace / error output demonstrating the issue
  - Verify: `rg -n "tquic_process_stream_frame" "net/quic/tquic/tquic_input.c"`
  - Fix: Add a comment explaining why `_bh` is not needed in the receive path. Risk: Locking/ordering changes can cause deadlocks or throughput regressions if 

- [x] **CF-056** -- Sleep-in-Atomic Context
  - Severity: S0 | Sources: B,C | Priority: 10.0
  - Evidence: file:1, sym:7, lines:2, snippet:4
  - Missing: Kernel log / stack trace / error output demonstrating the issue
  - Verify: `rg -n "tquic_path" "net/tquic/tquic_migration.c"`
  - Fix: Establish one synchronization model for this code path and make all state transitions/lookup paths follow it consistently. Risk: Locking/ordering chan

- [x] **CF-059** -- Stateless Reset Bypasses State Machine
  - Severity: S0 | Sources: B,C | Priority: 10.0
  - Evidence: file:1, sym:7, lines:1, snippet:3
  - Missing: Kernel log / stack trace / error output demonstrating the issue
  - Verify: `rg -n "tquic_conn_set_state" "net/tquic/tquic_input.c"`
  - Fix: Use the state machine: call `tquic_conn_set_state(conn, TQUIC_CONN_CLOSED, TQUIC_REASON_PEER_CLOSE)` instead. Risk: Locking/ordering changes can cause

- [x] **CF-060** -- Stream Data Delivery Uses u64 Length with u32 alloc_skb
  - Severity: S0 | Sources: B,C | Priority: 10.0
  - Evidence: file:1, sym:2, lines:1, snippet:2
  - Missing: Kernel log / stack trace / error output demonstrating the issue
  - Verify: `rg -n "tquic_stream" "net/quic/tquic/core/quic_packet.c"`
  - Fix: Cap `len` to a reasonable maximum (e.g., 16384 or the connection's max_stream_data) before allocation.  --- Risk: Locking/ordering changes can cause d

#### Correctness (12)

- [x] **CF-001** -- Adaptive Scheduler cwnd_avail Underflow
  - Severity: S0 | Sources: A,B,C | Priority: 10.0
  - Evidence: file:1, sym:4, snippet:5
  - Missing: Exact line range(s) where the fault manifests; Kernel log / stack trace / error output demonstrating the issue
  - Verify: `rg -n "tquic_scheduler" "net/tquic/multipath/tquic_scheduler.c"`
  - Fix: Add an explicit check: `cwnd_avail = (path->cc.cwnd > path->cc.bytes_in_flight) ? path->cc.cwnd - path->cc.bytes_in_flight : 0;` Risk: Protocol correc

- [x] **CF-012** -- Stream Data Queued Before Validation Check
  - Severity: S0 | Sources: A,B,C | Priority: 10.0
  - Evidence: file:4, sym:20, lines:8, snippet:12
  - Missing: Kernel log / stack trace / error output demonstrating the issue
  - Verify: `rg -n "dispatcher" "net/tquic/tquic_input.c"`
  - Fix: Add a flag to `tquic_rx_ctx` that records when a length-less STREAM frame is processed, and assert in the dispatcher that no further frames follow. Ri

- [x] **CF-014** -- `tquic_hs_process_certificate` -- integer underflow in `certs_len` tracking
  - Severity: S0 | Sources: B,C | Priority: 10.0
  - Evidence: file:1, sym:1, lines:3, snippet:1
  - Missing: Kernel log / stack trace / error output demonstrating the issue
  - Verify: `rg -n "tquic_hs_process_certificate" "net/tquic/crypto/handshake.c"`
  - Fix: Check `certs_len >= 3` before `certs_len -= 3`, and `certs_len >= 2` before `certs_len -= 2`. Alternatively, track position using pointer arithmetic a

- [x] **CF-024** -- Capsule Buffer Size Addition Overflow
  - Severity: S0 | Sources: B,C | Priority: 10.0
  - Evidence: file:1, lines:2, snippet:2
  - Missing: Function/struct symbol name at the fault site; Kernel log / stack trace / error output demonstrating the issue
  - Verify: `sed -n '850,850p' net/quic/tquic/masque/capsule.c`
  - Fix: Add overflow check: ```c if (cap->length > SIZE_MAX - CAPSULE_MAX_HEADER_SIZE)     return -EOVERFLOW; ```  --- Risk: Protocol correctness fixes can sh

- [x] **CF-028** -- GSO Segment Accumulation Can Overflow SKB Tailroom
  - Severity: S0 | Sources: B,C | Priority: 10.0
  - Evidence: file:1, sym:2, lines:1, snippet:1
  - Missing: Kernel log / stack trace / error output demonstrating the issue
  - Verify: `rg -n "tquic_gso_ctx" "net/quic/tquic/tquic_output.c"`
  - Fix: Validate cumulative bytes written against SKB tailroom before each `skb_put_data`/`skb_put` call, or check `skb_tailroom(gso->gso_skb) >= len` before 

- [x] **CF-034** -- Integer overflow in `tquic_hs_build_ch_extensions` PSK identity length calculations
  - Severity: S0 | Sources: B,C | Priority: 10.0
  - Evidence: file:1, sym:1, lines:2, snippet:2
  - Missing: Kernel log / stack trace / error output demonstrating the issue
  - Verify: `rg -n "tquic_hs_build_ch_extensions" "net/tquic/crypto/handshake.c"`
  - Fix: Check for u32 overflow in the accumulation loop. Validate that the total extension length fits in a u16.  --- Risk: Protocol correctness fixes can shi

- [x] **CF-037** -- Missing SKB Tailroom Check in Coalesced Packet Output
  - Severity: S0 | Sources: B,C | Priority: 10.0
  - Evidence: file:1, sym:1, lines:2, snippet:4
  - Missing: Kernel log / stack trace / error output demonstrating the issue
  - Verify: `rg -n "tquic_output" "net/quic/tquic/tquic_output.c"`
  - Fix: Add `BUILD_BUG_ON(TQUIC_MAX_HEADER_SIZE > 64)` or use `min(header_len, 64)` as a defense.  --- Risk: Protocol correctness fixes can shift timing/state

- [x] **CF-044** -- PADDING Frame Infinite Skip Without Bound on Encrypted Payload
  - Severity: S0 | Sources: B,C | Priority: 10.0
  - Evidence: file:1, sym:3, lines:5, snippet:3
  - Missing: Kernel log / stack trace / error output demonstrating the issue
  - Verify: `rg -n "tquic_rx_ctx" "net/tquic/tquic_input.c"`
  - Fix: Add a bounds check before decoding the packet number: ```c if (ctx.offset + pkt_num_len > len)     return -EINVAL; ``` Risk: Protocol correctness fixe

- [x] **CF-048** -- Priority PRIORITY_UPDATE Parsing Off-by-Two in Loop Bound
  - Severity: S0 | Sources: B,C | Priority: 10.0
  - Evidence: file:1, lines:2, snippet:1
  - Missing: Function/struct symbol name at the fault site; Kernel log / stack trace / error output demonstrating the issue
  - Verify: `sed -n '633,633p' net/quic/tquic/core/priority.c`
  - Fix: Implement proper Structured Field Dictionary parsing per RFC 8941. Validate the priority field value format strictly. Risk: Protocol correctness fixes

- [x] **CF-050** -- quic_packet.c Stream Frame - Uncapped Stream Creation
  - Severity: S0 | Sources: B,C | Priority: 10.0
  - Evidence: file:1, sym:3, lines:3, snippet:3
  - Missing: Kernel log / stack trace / error output demonstrating the issue
  - Verify: `rg -n "quic_packet" "net/quic/tquic/core/quic_packet.c"`
  - Fix: Replace `tquic_stream_create_internal` with `tquic_stream_open_incoming` which validates peer's MAX_STREAMS limit.  --- Risk: Protocol correctness fix

- [x] **CF-065** -- Transcript Buffer Reallocation Doubling Overflow
  - Severity: S0 | Sources: B,C | Priority: 10.0
  - Evidence: file:1, lines:3, snippet:2
  - Missing: Function/struct symbol name at the fault site; Kernel log / stack trace / error output demonstrating the issue
  - Verify: `sed -n '842,842p' net/quic/tquic/crypto/handshake.c`
  - Fix: Use `check_mul_overflow` or cap `new_alloc` more conservatively: ```c u32 new_alloc; if (check_mul_overflow(new_len, 2U, &new_alloc))     new_alloc = 

- [x] **CF-069** -- Version Negotiation Packet Overflow -- Unsanitized CID Lengths in tquic_send_version_negotiation
  - Severity: S0 | Sources: B,C | Priority: 10.0
  - Evidence: file:1, sym:4, lines:4, snippet:2
  - Missing: Kernel log / stack trace / error output demonstrating the issue
  - Verify: `rg -n "tquic_cid" "net/tquic/core/connection.c"`
  - Fix: Calculate required size upfront and validate against `sizeof(packet)`.  --- Risk: Protocol correctness fixes can shift timing/state-machine behavior; 

---

## Phase 2: CERTIFIED S1 -- High Confirmed (55 items)

#### Memory (8)

- [x] **CF-137** -- Constant-Time CID Validation Has Branching on Lengths
  - Severity: S1 | Sources: A,B,C | Priority: 7.0
  - Evidence: file:1, sym:4, lines:1, snippet:4
  - Missing: Kernel log / stack trace / error output demonstrating the issue
  - Verify: `rg -n "tquic_ct_memcmp" "net/tquic/security/quic_exfil.c"`
  - Fix: Missing fix suggestion in source text. Risk: Fixes in parser/crypto/lifetime code may alter packet acceptance logic. Watch for interoperability regres

- [x] **CF-148** -- QPACK Encoder: Insert Count Increment Overflow
  - Severity: S1 | Sources: A,B,C | Priority: 7.0
  - Evidence: file:1, sym:1
  - Missing: Exact line range(s) where the fault manifests; Code snippet proving the vulnerable pattern
  - Verify: `rg -n "qpack_encoder" "net/tquic/http3/qpack_encoder.c"`
  - Fix: Validate that `known_received_count + value <= insert_count` (the total entries ever inserted) and that the addition does not overflow. Risk: Fixes in

- [x] **CF-155** -- WebTransport Context Destroy: Lock Drop During Iteration
  - Severity: S1 | Sources: A,B,C | Priority: 7.0
  - Evidence: file:1, sym:1
  - Missing: Exact line range(s) where the fault manifests; Code snippet proving the vulnerable pattern
  - Verify: `rg -n "context_destroy" "net/tquic/http3/webtransport.c"`
  - Fix: Use a safe iteration pattern: move items to a local list under the lock, release the lock, then process the local list. Risk: Fixes in parser/crypto/l

- [x] **CF-179** -- conn->paths_lock in RX path for every packet
  - Severity: S1 | Sources: A,B | Priority: 7.0
  - Evidence: file:2, sym:7, lines:1, snippet:1
  - Missing: Kernel log / stack trace / error output demonstrating the issue
  - Verify: `rg -n "first" "net/tquic/tquic_input.c"`
  - Fix: Use a hash table (rhashtable) for path-by-address lookup. For single-path connections, cache the last-used path and check it first (fast-path optimiza

- [x] **CF-220** -- Retry Packet Stack Buffer Overflow
  - Severity: S1 | Sources: B,C | Priority: 7.0
  - Evidence: file:1, lines:2, snippet:2
  - Missing: Function/struct symbol name at the fault site; Kernel log / stack trace / error output demonstrating the issue
  - Verify: `sed -n '1379,1379p' net/tquic/core/connection.c`
  - Fix: Allocate `packet`, `token`, and `pseudo_packet` on the heap using `kmalloc`.  --- Risk: Fixes in parser/crypto/lifetime code may alter packet acceptan

- [x] **CF-226** -- Session Ticket Decode Missing Bounds Check on PSK Copy
  - Severity: S1 | Sources: B,C | Priority: 7.0
  - Evidence: file:1, lines:3, snippet:2
  - Missing: Function/struct symbol name at the fault site; Kernel log / stack trace / error output demonstrating the issue
  - Verify: `sed -n '1160,1160p' net/tquic/crypto/zero_rtt.c`
  - Fix: Add strict validation and bounds checks at parse boundaries, enforce lifetime/ownership rules, and fail closed on malformed input. Risk: Fixes in pars

- [x] **CF-236** -- tquic_stream_socket_create Double-Free on fd Failure
  - Severity: S1 | Sources: B,C | Priority: 7.0
  - Evidence: file:1, sym:4, lines:4, snippet:1
  - Missing: Kernel log / stack trace / error output demonstrating the issue
  - Verify: `rg -n "tquic_stream_socket_create" "net/quic/tquic/tquic_stream.c"`
  - Fix: Set `sk_user_data` to NULL before calling `tquic_sock_map_fd`, or set it only after successful fd allocation. Fix the `sock_alloc_file` failure path t

- [x] **CF-240** -- Zero-RTT Session Ticket Deserialization Trusts Length Fields
  - Severity: S1 | Sources: B,C | Priority: 7.0
  - Evidence: file:1, lines:1, snippet:1
  - Missing: Function/struct symbol name at the fault site; Kernel log / stack trace / error output demonstrating the issue
  - Verify: `sed -n '1140,1160p' net/quic/tquic/crypto/zero_rtt.c`
  - Fix: Add strict validation and bounds checks at parse boundaries, enforce lifetime/ownership rules, and fail closed on malformed input. Risk: Fixes in pars

#### Security (20)

- [x] **CF-138** -- Custom ASN.1 Parser - High Attack Surface
  - Severity: S1 | Sources: A,B,C | Priority: 7.0
  - Evidence: file:1, sym:4
  - Missing: Exact line range(s) where the fault manifests; Code snippet proving the vulnerable pattern
  - Verify: `rg -n "decoder" "net/tquic/crypto/cert_verify.c"`
  - Fix: Consider using the kernel's built-in ASN.1 decoder (`lib/asn1_decoder.c`) and the x509 certificate parser (`crypto/asymmetric_keys/x509_cert_parser.c`

- [x] **CF-139** -- Function Pointer Stored in skb->cb Without Validation
  - Severity: S1 | Sources: A,B,C | Priority: 7.0
  - Evidence: file:1, sym:5, lines:2, snippet:3
  - Missing: Kernel log / stack trace / error output demonstrating the issue
  - Verify: `rg -n "corrupted" "net/tquic/security/quic_exfil.c"`
  - Fix: Missing fix suggestion in source text. Risk: Fixes in parser/crypto/lifetime code may alter packet acceptance logic. Watch for interoperability regres

- [x] **CF-141** -- HTTP/3 Settings Frame Length Truncation
  - Severity: S1 | Sources: A,B,C | Priority: 7.0
  - Evidence: file:1, sym:1
  - Missing: Exact line range(s) where the fault manifests; Code snippet proving the vulnerable pattern
  - Verify: `rg -n "h3_connection_send_settings" "net/tquic/http3/http3_stream.c"`
  - Fix: Use proper QUIC variable-length integer encoding for the frame length, or validate that `settings_len <= 255` before the cast and return an error if e

- [x] **CF-142** -- Load Balancer Encryption Key Not Zeroized on Destroy
  - Severity: S1 | Sources: A,B,C | Priority: 7.0
  - Evidence: file:1, sym:5, snippet:1
  - Missing: Exact line range(s) where the fault manifests; Kernel log / stack trace / error output demonstrating the issue
  - Verify: `rg -n "crypto_free_sync_skcipher" "net/tquic/lb/quic_lb.c"`
  - Fix: Missing fix suggestion in source text. Risk: Fixes in parser/crypto/lifetime code may alter packet acceptance logic. Watch for interoperability regres

- [x] **CF-143** -- No CAP_NET_ADMIN Check for Tunnel Creation
  - Severity: S1 | Sources: A,B,C | Priority: 7.0
  - Evidence: file:1, sym:8, snippet:1
  - Missing: Exact line range(s) where the fault manifests; Kernel log / stack trace / error output demonstrating the issue
  - Verify: `rg -n "capable" "net/tquic/tquic_tunnel.c"`
  - Fix: Missing fix suggestion in source text. Risk: Fixes in parser/crypto/lifetime code may alter packet acceptance logic. Watch for interoperability regres

- [x] **CF-144** -- Path Metrics Netlink: Missing CAP_NET_ADMIN Permission Check
  - Severity: S1 | Sources: A,B,C | Priority: 7.0
  - Evidence: file:1, sym:5
  - Missing: Exact line range(s) where the fault manifests; Code snippet proving the vulnerable pattern
  - Verify: `rg -n "export" "net/tquic/diag/path_metrics.c"`
  - Fix: Add `.policy` with `GENL_ADMIN_PERM` flag or explicit `CAP_NET_ADMIN` check in each handler. Risk: Fixes in parser/crypto/lifetime code may alter pack

- [x] **CF-145** -- Per-Call crypto_aead_setkey in Encrypt/Decrypt Hot Path
  - Severity: S1 | Sources: A,B,C | Priority: 7.0
  - Evidence: file:1, sym:4
  - Missing: Exact line range(s) where the fault manifests; Code snippet proving the vulnerable pattern
  - Verify: `rg -n "changes" "net/tquic/crypto/tls.c"`
  - Fix: Set the key once when it changes (at key installation time), not on every packet. Store the AEAD transform with the key pre-set in `tquic_key_generati

- [x] **CF-146** -- Per-Call crypto_alloc_aead in 0-RTT Encrypt/Decrypt
  - Severity: S1 | Sources: A,B,C | Priority: 7.0
  - Evidence: file:1, sym:6
  - Missing: Exact line range(s) where the fault manifests; Code snippet proving the vulnerable pattern
  - Verify: `rg -n "crypto_alloc_aead" "net/tquic/crypto/zero_rtt.c"`
  - Fix: Pre-allocate the AEAD transform during `tquic_zero_rtt_init()` or `tquic_zero_rtt_attempt()` and reuse it for the lifetime of the 0-RTT state. Risk: F

- [x] **CF-150** -- RSA-PSS Hash Algorithm Hardcoded to SHA-256
  - Severity: S1 | Sources: A,B,C | Priority: 7.0
  - Evidence: file:1, sym:1, snippet:1
  - Missing: Exact line range(s) where the fault manifests; Kernel log / stack trace / error output demonstrating the issue
  - Verify: `rg -n "verification" "net/tquic/crypto/cert_verify.c"`
  - Fix: Parse the RSA-PSS AlgorithmIdentifier parameters to extract the actual hash algorithm. Risk: Fixes in parser/crypto/lifetime code may alter packet acc

- [x] **CF-151** -- Secrets not zeroized on error paths in key derivation functions
  - Severity: S1 | Sources: A,B,C | Priority: 7.0
  - Evidence: file:1, sym:4, lines:5, snippet:2
  - Missing: Kernel log / stack trace / error output demonstrating the issue
  - Verify: `rg -n "consumed" "net/tquic/crypto/handshake.c"`
  - Fix: Zeroize these secrets using `memzero_explicit()` as soon as they have been consumed (after key derivation and ticket issuance). Risk: Fixes in parser/

- [x] **CF-154** -- Unbounded Connection Creation via Netlink
  - Severity: S1 | Sources: A,B,C | Priority: 7.0
  - Evidence: file:1, sym:5, snippet:1
  - Missing: Exact line range(s) where the fault manifests; Kernel log / stack trace / error output demonstrating the issue
  - Verify: `rg -n "connections" "net/tquic/tquic_netlink.c"`
  - Fix: Missing fix suggestion in source text. Risk: Fixes in parser/crypto/lifetime code may alter packet acceptance logic. Watch for interoperability regres

- [x] **CF-156** -- WebTransport: Unbounded Capsule Buffer Growth
  - Severity: S1 | Sources: A,B,C | Priority: 7.0
  - Evidence: file:1, sym:2
  - Missing: Exact line range(s) where the fault manifests; Code snippet proving the vulnerable pattern
  - Verify: `rg -n "capsule" "net/tquic/http3/webtransport.c"`
  - Fix: Enforce a maximum capsule buffer size (e.g., 64KB or configurable via socket option) and reject connections that exceed it with `H3_EXCESSIVE_LOAD`. R

- [x] **CF-160** -- `tquic_hs_build_ch_extensions` -- ALPN extension length written as 2-byte but can overflow u16
  - Severity: S1 | Sources: B,C | Priority: 7.0
  - Evidence: file:1, sym:2, lines:1, snippet:2
  - Missing: Kernel log / stack trace / error output demonstrating the issue
  - Verify: `rg -n "tquic_hs_set_alpn" "net/tquic/crypto/handshake.c"`
  - Fix: Validate ALPN total length fits in u16 in `tquic_hs_set_alpn()`. Add a reasonable cap on `alpn_count`.  --- Risk: Fixes in parser/crypto/lifetime code

- [x] **CF-163** -- `tquic_hs_hkdf_expand_label` -- `context_len` truncated to u8
  - Severity: S1 | Sources: B,C | Priority: 7.0
  - Evidence: file:1, sym:1, lines:1, snippet:2
  - Missing: Kernel log / stack trace / error output demonstrating the issue
  - Verify: `rg -n "tquic_hs_hkdf_expand_label" "net/tquic/crypto/handshake.c"`
  - Fix: ```c if (context_len > 255)     return -EINVAL; ```  --- Risk: Fixes in parser/crypto/lifetime code may alter packet acceptance logic. Watch for inter

- [x] **CF-165** -- `tquic_hs_process_new_session_ticket` -- memory leak of old ticket data on re-entry
  - Severity: S1 | Sources: B,C | Priority: 7.0
  - Evidence: file:1, sym:3, lines:2, snippet:2
  - Missing: Kernel log / stack trace / error output demonstrating the issue
  - Verify: `rg -n "tquic_hs_process_new_session_ticket" "net/tquic/crypto/handshake.c"`
  - Fix: Track whether `hs->session_ticket` is owned or borrowed. Only free owned tickets. Risk: Fixes in parser/crypto/lifetime code may alter packet acceptan

- [x] **CF-166** -- `tquic_hs_process_server_hello` -- session ID comparison not fully bounds-safe
  - Severity: S1 | Sources: B,C | Priority: 7.0
  - Evidence: file:1, sym:1, lines:4, snippet:2
  - Missing: Kernel log / stack trace / error output demonstrating the issue
  - Verify: `rg -n "tquic_hs_process_server_hello" "net/tquic/crypto/handshake.c"`
  - Fix: Add `if (p >= end) return -EINVAL;` before `session_id_len = *p++;`.  --- Risk: Fixes in parser/crypto/lifetime code may alter packet acceptance logic

- [x] **CF-173** -- Bloom Filter Has High False Positive Rate at Scale
  - Severity: S1 | Sources: B,C | Priority: 7.0
  - Evidence: file:1, lines:1, snippet:1
  - Missing: Function/struct symbol name at the fault site; Kernel log / stack trace / error output demonstrating the issue
  - Verify: `sed -n '913,916p' net/tquic/crypto/zero_rtt.h`
  - Fix: Increase `TQUIC_REPLAY_BLOOM_BITS` to at least `(1 << 20)` (1M bits = 128KB) for production use, or make it configurable via sysctl.  --- Risk: Fixes 

- [x] **CF-205** -- memset Instead of memzero_explicit for Old Key Material
  - Severity: S1 | Sources: B,C | Priority: 7.0
  - Evidence: file:1, sym:1, lines:3, snippet:1
  - Missing: Kernel log / stack trace / error output demonstrating the issue
  - Verify: `rg -n "memzero_explicit" "net/tquic/crypto/key_update.c"`
  - Fix: Replace all `memset(..., 0, ...)` clearing key material with `memzero_explicit()`. Risk: Fixes in parser/crypto/lifetime code may alter packet accepta

- [x] **CF-206** -- Missing kfree_sensitive for key material in crypto/handshake.c extensions buffer
  - Severity: S1 | Sources: B,C | Priority: 7.0
  - Evidence: file:1, sym:1, lines:2, snippet:1
  - Missing: Kernel log / stack trace / error output demonstrating the issue
  - Verify: `rg -n "kfree_sensitive" "net/quic/tquic/crypto/handshake.c"`
  - Fix: Add strict validation and bounds checks at parse boundaries, enforce lifetime/ownership rules, and fail closed on malformed input. Risk: Fixes in pars

- [x] **CF-213** -- Procfs trusted_cas Writable Without Privilege Check
  - Severity: S1 | Sources: B,C | Priority: 7.0
  - Evidence: file:1, sym:1, lines:2, snippet:1
  - Missing: Kernel log / stack trace / error output demonstrating the issue
  - Verify: `rg -n "current_cred" "net/tquic/crypto/cert_verify.c"`
  - Fix: Add `capable(CAP_NET_ADMIN)` check in the write handler. Consider using 0600 permissions. Risk: Fixes in parser/crypto/lifetime code may alter packet 

#### Concurrency (15)

- [x] **CF-140** -- HTTP/3 Request: TOCTOU Between State Check and Send
  - Severity: S1 | Sources: A,B,C | Priority: 7.0
  - Evidence: file:1, sym:2
  - Missing: Exact line range(s) where the fault manifests; Code snippet proving the vulnerable pattern
  - Verify: `rg -n "h3_request_send_headers" "net/tquic/http3/http3_request.c"`
  - Fix: Either hold the lock during the entire send operation, or re-validate state after acquiring any needed resources. Risk: Locking/ordering changes can c

- [x] **CF-147** -- QPACK Decoder: Unbounded Blocked Stream Memory Exhaustion
  - Severity: S1 | Sources: A,B,C | Priority: 7.0
  - Evidence: file:1, sym:5
  - Missing: Exact line range(s) where the fault manifests; Code snippet proving the vulnerable pattern
  - Verify: `rg -n "blocks" "net/tquic/http3/qpack_decoder.c"`
  - Fix: Track total blocked stream memory and enforce a per-connection limit (e.g., 1MB total blocked stream data). Risk: Locking/ordering changes can cause d

- [x] **CF-149** -- Race Condition in Key Update Secret Installation
  - Severity: S1 | Sources: A,B,C | Priority: 7.0
  - Evidence: file:1, sym:4
  - Missing: Exact line range(s) where the fault manifests; Code snippet proving the vulnerable pattern
  - Verify: `rg -n "derivation" "net/tquic/crypto/key_update.c"`
  - Fix: Use a state flag (e.g., `keys_installing`) that prevents concurrent use during the derivation window. Set the flag under the first lock acquisition, d

- [x] **CF-153** -- Timing Normalization Can Block in Packet Processing Path
  - Severity: S1 | Sources: A,B,C | Priority: 7.0
  - Evidence: file:1, sym:9, snippet:1
  - Missing: Exact line range(s) where the fault manifests; Kernel log / stack trace / error output demonstrating the issue
  - Verify: `rg -n "context" "net/tquic/security/quic_exfil.c"`
  - Fix: Missing fix suggestion in source text. Risk: Locking/ordering changes can cause deadlocks or throughput regressions if not validated under stress and 

- [x] **CF-169** -- accept() Uses spin_lock_bh on sk_lock.slock While lock_sock() Is Held
  - Severity: S1 | Sources: B,C | Priority: 7.0
  - Evidence: file:2, sym:5, lines:4, snippet:3
  - Missing: Kernel log / stack trace / error output demonstrating the issue
  - Verify: `rg -n "lock_sock" "net/quic/tquic/tquic_socket.c"`
  - Fix: Remove the inner `spin_lock_bh(&sk->sk_lock.slock)` calls in `tquic_accept()`. The `lock_sock()` already provides sufficient serialization. If the acc

- [x] **CF-174** -- Bonding State Machine Drop-Relock Without Re-validation
  - Severity: S1 | Sources: B,C | Priority: 7.0
  - Evidence: file:1, sym:3, lines:1, snippet:2
  - Missing: Kernel log / stack trace / error output demonstrating the issue
  - Verify: `rg -n "tquic_bonding_destroy" "net/quic/tquic/bond/tquic_bonding.c"`
  - Fix: Add a "destroying" flag to `bc` checked after relock, or use refcounting on `bc`. Risk: Locking/ordering changes can cause deadlocks or throughput reg

- [x] **CF-177** -- conn->lock held during path selection on every TX packet
  - Severity: S1 | Sources: A,B | Priority: 7.0
  - Evidence: file:2, sym:8, lines:1, snippet:1
  - Missing: Kernel log / stack trace / error output demonstrating the issue
  - Verify: `rg -n "read_once" "net/tquic/tquic_output.c"`
  - Fix: For the single-path fast path, use `READ_ONCE(conn->active_path)` without the lock. Only take the lock when a scheduler is configured. Consider RCU pr

- [x] **CF-178** -- conn->lock released and reacquired during output flush stream iteration
  - Severity: S1 | Sources: A,B | Priority: 7.0
  - Evidence: file:2, sym:7, lines:1, snippet:2
  - Missing: Kernel log / stack trace / error output demonstrating the issue
  - Verify: `rg -n "operations" "net/tquic/tquic_output.c"`
  - Fix: Merge the two critical sections into one: check flow control credit and begin stream iteration under the same `conn->lock` hold. Risk: Locking/orderin

- [x] **CF-184** -- EKU Derives Keys Using KU hash_tfm Without KU Lock
  - Severity: S1 | Sources: B,C | Priority: 7.0
  - Evidence: file:1, sym:1, lines:3, snippet:2
  - Missing: Kernel log / stack trace / error output demonstrating the issue
  - Verify: `rg -n "eku_hkdf_extract" "net/tquic/crypto/extended_key_update.c"`
  - Fix: Either (a) hold the KU lock around `hash_tfm` access, or (b) copy `hash_tfm` under the KU lock and use the copy (though crypto transforms are not refe

- [x] **CF-192** -- GRO Flush Unlock-Relock Loop Without Re-validation
  - Severity: S1 | Sources: B,C | Priority: 7.0
  - Evidence: file:1, sym:2, lines:2, snippet:2
  - Missing: Kernel log / stack trace / error output demonstrating the issue
  - Verify: `rg -n "tquic_gro_receive_internal" "net/quic/tquic/tquic_input.c"`
  - Fix: After the loop, set `gro->held_count = skb_queue_len(&gro->hold_queue)` instead of hard-coding 0. Risk: Locking/ordering changes can cause deadlocks o

- [x] **CF-200** -- Infinite retry loop on EMSGSIZE/EEXIST
  - Severity: S1 | Sources: A,B | Priority: 7.0
  - Evidence: file:2, sym:4, lines:1, snippet:1
  - Missing: Kernel log / stack trace / error output demonstrating the issue
  - Verify: `rg -n "tquic_skb_zerocopy_iter_stream" "net/tquic/tquic_zerocopy.c"`
  - Fix: Add a retry counter (e.g., max 3 retries) and return an error after exhausting retries. Alternatively, adjust the chunk size downward on EMSGSIZE befo

- [x] **CF-202** -- io_uring buffer ring spinlock per get/put operation
  - Severity: S1 | Sources: A,B | Priority: 7.0
  - Evidence: file:3, sym:8, lines:2, snippet:1
  - Missing: Kernel log / stack trace / error output demonstrating the issue
  - Verify: `rg -n "acquisitions" "net/tquic/io_uring.c"`
  - Fix: If get/put are guaranteed to be called from different contexts (producer vs consumer), replace the spinlock with a lockless SPSC ring using `smp_store

- [x] **CF-218** -- reed_solomon.c -- four-allocation group without individual NULL checks
  - Severity: S1 | Sources: B,C | Priority: 7.0
  - Evidence: file:1, lines:1, snippet:3
  - Missing: Function/struct symbol name at the fault site; Kernel log / stack trace / error output demonstrating the issue
  - Verify: `sed -n '590,590p' net/quic/tquic/fec/reed_solomon.c`
  - Fix: Establish one synchronization model for this code path and make all state transitions/lookup paths follow it consistently. Risk: Locking/ordering chan

- [x] **CF-225** -- Security Hardening Pre-HS Atomic TOCTOU
  - Severity: S1 | Sources: B,C | Priority: 7.0
  - Evidence: file:1, sym:1, lines:2, snippet:1
  - Missing: Kernel log / stack trace / error output demonstrating the issue
  - Verify: `rg -n "atomic_inc_return" "net/quic/tquic/security_hardening.c"`
  - Fix: Use `atomic_inc_return()` and check the result instead of separate read + increment. Risk: Locking/ordering changes can cause deadlocks or throughput 

- [x] **CF-231** -- tquic_process_stream_frame Allocates skb Based on Attacker-Controlled length
  - Severity: S1 | Sources: B,C | Priority: 7.0
  - Evidence: file:1, sym:4, lines:4, snippet:1
  - Missing: Kernel log / stack trace / error output demonstrating the issue
  - Verify: `rg -n "alloc_skb" "net/tquic/tquic_input.c"`
  - Fix: Move the `sk_rmem_alloc` check BEFORE the `alloc_skb()` call to avoid the allocation entirely when the buffer is full. Also consider a global receive 

#### Correctness (10)

- [x] **CF-136** -- `ext->final_size = -1` Uses Signed Overflow
  - Severity: S1 | Sources: A,B,C | Priority: 7.0
  - Evidence: file:1, snippet:1
  - Missing: Exact line range(s) where the fault manifests; Function/struct symbol name at the fault site
  - Verify: `make M=net/tquic W=1`
  - Fix: Define `#define TQUIC_STREAM_SIZE_UNKNOWN U64_MAX` and use it consistently. Risk: Protocol correctness fixes can shift timing/state-machine behavior; 

- [x] **CF-152** -- Stream State Machine Allows Unexpected Transitions from OPEN
  - Severity: S1 | Sources: A,B,C | Priority: 7.0
  - Evidence: file:1, sym:6, snippet:2
  - Missing: Exact line range(s) where the fault manifests; Kernel log / stack trace / error output demonstrating the issue
  - Verify: `rg -n "data_sent" "net/tquic/core/stream.c"`
  - Fix: Add TQUIC_STREAM_SEND and TQUIC_STREAM_RECV as valid transitions from OPEN. Risk: Protocol correctness fixes can shift timing/state-machine behavior; 

- [x] **CF-157** -- `quic_offload.c` Version Field Shift Without Cast
  - Severity: S1 | Sources: B,C | Priority: 7.0
  - Evidence: file:2, sym:1, lines:2, snippet:2
  - Missing: Kernel log / stack trace / error output demonstrating the issue
  - Verify: `rg -n "quic_offload" "net/quic/tquic/quic_offload.c"`
  - Fix: Cast to `u32` before shift: ```c version = ((u32)data[1] << 24) | ((u32)data[2] << 16) |           ((u32)data[3] << 8) | data[4]; ``` Risk: Protocol c

- [x] **CF-183** -- ECN Counter Values Passed Directly to TQUIC_ADD_STATS Without Overflow Check
  - Severity: S1 | Sources: B,C | Priority: 7.0
  - Evidence: file:1, sym:1, lines:3, snippet:1
  - Missing: Kernel log / stack trace / error output demonstrating the issue
  - Verify: `rg -n "tquic_input" "net/tquic/tquic_input.c"`
  - Fix: Validate that ECN counts are monotonically increasing from previous values. Store previous ECN counts per-path and only react to the *increase*, not t

- [x] **CF-190** -- getsockopt PSK Identity - Missing Length Validation
  - Severity: S1 | Sources: B,C | Priority: 7.0
  - Evidence: file:1, sym:1, lines:2, snippet:3
  - Missing: Kernel log / stack trace / error output demonstrating the issue
  - Verify: `rg -n "tquic_socket" "net/quic/tquic/tquic_socket.c"`
  - Fix: Add `if (identity_len > len) return -EINVAL;` before the copy_to_user call.  --- Risk: Protocol correctness fixes can shift timing/state-machine behav

- [x] **CF-191** -- GRO Coalesce Uses Hardcoded 8-byte CID Comparison
  - Severity: S1 | Sources: B,C | Priority: 7.0
  - Evidence: file:1, sym:1, lines:1, snippet:2
  - Missing: Kernel log / stack trace / error output demonstrating the issue
  - Verify: `rg -n "tquic_input" "net/tquic/tquic_input.c"`
  - Fix: The GRO coalesce function needs to know the actual CID length. Pass it via skb metadata or look it up from connection state. Also add length checks: `

- [x] **CF-195** -- HIGH: GRO stats use global atomic64 on every packet
  - Severity: S1 | Sources: A,B | Priority: 7.0
  - Evidence: file:4, sym:8, lines:3, snippet:3
  - Missing: Kernel log / stack trace / error output demonstrating the issue
  - Verify: `rg -n "atomic64_inc" "net/tquic/tquic_offload.c"`
  - Fix: Use per-CPU counters for GRO statistics, aggregate on read. Risk: Protocol correctness fixes can shift timing/state-machine behavior; verify against i

- [x] **CF-211** -- payload_len Subtraction Underflow in Long Header Parsing
  - Severity: S1 | Sources: B,C | Priority: 7.0
  - Evidence: file:1, lines:2, snippet:1
  - Missing: Function/struct symbol name at the fault site; Kernel log / stack trace / error output demonstrating the issue
  - Verify: `sed -n '590,601p' net/tquic/core/packet.c`
  - Fix: Add `if (hdr->payload_len < hdr->pn_len) return -EPROTO;` before the subtraction. Risk: Protocol correctness fixes can shift timing/state-machine beha

- [x] **CF-233** -- tquic_stream_recv_data Potential Integer Overflow in Flow Control Check
  - Severity: S1 | Sources: B,C | Priority: 7.0
  - Evidence: file:1, sym:1, lines:1, snippet:1
  - Missing: Kernel log / stack trace / error output demonstrating the issue
  - Verify: `rg -n "tquic_stream_recv_data" "net/quic/tquic/core/stream.c"`
  - Fix: Add overflow check before the addition: `if (skb->len > U64_MAX - offset) return -EOVERFLOW;`  --- Risk: Protocol correctness fixes can shift timing/s

- [x] **CF-237** -- tquic_zerocopy_sendmsg -- uarg leak on partial send
  - Severity: S1 | Sources: B,C | Priority: 7.0
  - Evidence: file:1, sym:2, lines:1, snippet:2
  - Missing: Kernel log / stack trace / error output demonstrating the issue
  - Verify: `rg -n "tquic_zerocopy_sendmsg" "net/quic/tquic/tquic_zerocopy.c"`
  - Fix: On the error path, dequeue and free all SKBs added during this call, or commit the partial send as successful (return `copied` instead of error if `co

#### Api (1)

- [x] **CF-217** -- Redundant triple-counting of statistics
  - Severity: S1 | Sources: A,B | Priority: 7.0
  - Evidence: file:4, sym:11, lines:7, snippet:4
  - Missing: Kernel log / stack trace / error output demonstrating the issue
  - Verify: `rg -n "atomic64_add" "net/tquic/napi.c"`
  - Fix: Remove the `tquic_napi_global_stats` atomic counters entirely. Use `tquic_napi_aggregate_pcpu_stats()` (already implemented at line 75) when global to

#### Perf (1)

- [x] **CF-180** -- CONNECTION_CLOSE uses kmalloc for small buffer
  - Severity: S1 | Sources: A,B | Priority: 7.0
  - Evidence: file:2, sym:3, lines:2, snippet:1
  - Missing: Kernel log / stack trace / error output demonstrating the issue
  - Verify: `rg -n "does" "net/tquic/tquic_output.c"`
  - Fix: Use a stack buffer like `tquic_send_ack()` does (line 1877: `u8 buf_stack[128]`). A 256-byte stack allocation is safe in kernel context. Risk: Protoco

---

## Phase 3: PLAUSIBLE S0 -- Critical Likely (72 items)

#### Memory (23)

- [x] **CF-002** -- Buffer Overflow in ClientHello Extension Building
  - Severity: S0 | Sources: A,B,C | Priority: 10.0
  - Evidence: file:1, sym:3
  - Missing: Exact line range(s) where the fault manifests; Code snippet proving the vulnerable pattern
  - Verify: `rg -n "enabled" "net/tquic/crypto/handshake.c"`
  - Fix: Add a running `offset` tracker and validate `offset + needed_bytes <= buf_len` before every write operation. Return `-ENOSPC` if insufficient space. R

- [x] **CF-016** -- `tquic_hs_process_server_hello` -- missing bounds check before compression byte read
  - Severity: S0 | Sources: B,C | Priority: 10.0
  - Evidence: file:1, sym:1, snippet:1
  - Missing: Exact line range(s) where the fault manifests; Kernel log / stack trace / error output demonstrating the issue
  - Verify: `rg -n "tquic_hs_process_server_hello" "net/tquic/crypto/handshake.c"`
  - Fix: Add `if (p >= end) return -EINVAL;` before reading compression. Risk: Fixes in parser/crypto/lifetime code may alter packet acceptance logic. Watch fo

- [x] **CF-019** -- Adaptive Feedback Uses Path After list_for_each_entry Exit
  - Severity: S0 | Sources: B,C | Priority: 10.0
  - Evidence: file:1, sym:7, snippet:1
  - Missing: Exact line range(s) where the fault manifests; Kernel log / stack trace / error output demonstrating the issue
  - Verify: `rg -n "tquic_path" "net/tquic/multipath/tquic_scheduler.c"`
  - Fix: Use a separate flag variable to track whether the path was found, or use `list_for_each_entry_rcu()` with a found flag check. Risk: Fixes in parser/cr

- [x] **CF-035** -- Load Balancer Plaintext Mode Exposes Server ID
  - Severity: S0 | Sources: B,C | Priority: 10.0
  - Evidence: file:1, sym:1, snippet:1
  - Missing: Exact line range(s) where the fault manifests; Kernel log / stack trace / error output demonstrating the issue
  - Verify: `rg -n "pr_warn_once" "net/tquic/lb/quic_lb.c"`
  - Fix: Log a `pr_warn_once()` when plaintext mode is selected. Consider requiring `CAP_NET_ADMIN` to create plaintext configs, or removing plaintext mode ent

- [x] **CF-049** -- QPACK Decoder Stack Buffer Overflow via Large Headers
  - Severity: S0 | Sources: B,C | Priority: 10.0
  - Evidence: file:1, sym:3, snippet:1
  - Missing: Exact line range(s) where the fault manifests; Kernel log / stack trace / error output demonstrating the issue
  - Verify: `rg -n "qpack_decoder" "net/quic/tquic/http3/qpack_decoder.c"`
  - Fix: Replace stack buffers with heap allocation (kmalloc with GFP_ATOMIC). The value_buf alone at 8192 bytes is dangerously large for kernel stack. Alterna

- [x] **CF-052** -- Retry Token Address Validation Uses Non-Constant-Time Comparison
  - Severity: S0 | Sources: B,C | Priority: 10.0
  - Evidence: file:1, sym:3, snippet:1
  - Missing: Exact line range(s) where the fault manifests; Kernel log / stack trace / error output demonstrating the issue
  - Verify: `rg -n "crypto_memneq" "net/tquic/core/connection.c"`
  - Fix: Use `crypto_memneq()` for the hash comparison, or accept the current design as adequate given AEAD authentication. Risk: Fixes in parser/crypto/lifeti

- [x] **CF-064** -- tquic_stream_sendmsg Writes to Stream Without Connection Refcount on Stream
  - Severity: S0 | Sources: B,C | Priority: 10.0
  - Evidence: file:1, sym:3
  - Missing: Exact line range(s) where the fault manifests; Code snippet proving the vulnerable pattern
  - Verify: `rg -n "tquic_stream_sendmsg" "net/quic/tquic/tquic_stream.c"`
  - Fix: Stream objects need reference counting. The stream_sock should hold a reference to the stream. Only when both the tree reference and the socket refere

- [x] **CF-070** -- WebTransport Close Capsule Large Stack Allocation
  - Severity: S0 | Sources: B,C | Priority: 10.0
  - Evidence: file:1, snippet:1
  - Missing: Exact line range(s) where the fault manifests; Function/struct symbol name at the fault site
  - Verify: `rg -n "kmalloc\|kzalloc\|alloc_skb\|memcpy" "net/quic/tquic/http3/webtransport.c"`
  - Fix: Use heap allocation (kmalloc/kzalloc) for this buffer.  --- Risk: Fixes in parser/crypto/lifetime code may alter packet acceptance logic. Watch for in

- [x] **CF-072** -- conn->sk Accessed Without Lock After Stateless Reset
  - Severity: S0 | Sources: B | Priority: 10.0
  - Evidence: file:1, sym:4, lines:1, snippet:1
  - Missing: Kernel log / stack trace / error output demonstrating the issue; Independent confirmation from a second audit source
  - Verify: `rg -n "tquic_connection" "net/tquic/tquic_input.c"`
  - Fix: Hold a reference to the socket (`sock_hold(sk)`) under the lock, then call `sk_state_change`, then release the reference (`sock_put(sk)`). Risk: Fixes

- [x] **CF-074** -- Missing Lock in `tquic_sock_bind()` -- Race with `tquic_connect()`
  - Severity: S0 | Sources: B | Priority: 10.0
  - Evidence: file:1, sym:11, lines:1, snippet:1
  - Missing: Kernel log / stack trace / error output demonstrating the issue; Independent confirmation from a second audit source
  - Verify: `rg -n "copies" "net/tquic/tquic_socket.c"`
  - Fix: Add strict validation and bounds checks at parse boundaries, enforce lifetime/ownership rules, and fail closed on malformed input. Risk: Fixes in pars

- [x] **CF-078** -- Refcount Underflow in Netlink Path Creation
  - Severity: S0 | Sources: B | Priority: 10.0
  - Evidence: file:1, sym:1, lines:5, snippet:1
  - Missing: Kernel log / stack trace / error output demonstrating the issue; Independent confirmation from a second audit source
  - Verify: `rg -n "tquic_netlink" "net/tquic/tquic_netlink.c"`
  - Fix: Add strict validation and bounds checks at parse boundaries, enforce lifetime/ownership rules, and fail closed on malformed input. Risk: Fixes in pars

- [x] **CF-081** -- Stream Lookup Returns Pointer Without Refcount -- Use-After-Free
  - Severity: S0 | Sources: B | Priority: 10.0
  - Evidence: file:4, sym:4, lines:4, snippet:1
  - Missing: Kernel log / stack trace / error output demonstrating the issue; Independent confirmation from a second audit source
  - Verify: `rg -n "tquic_stream" "net/quic/tquic/core/priority.c"`
  - Fix: Add strict validation and bounds checks at parse boundaries, enforce lifetime/ownership rules, and fail closed on malformed input. Risk: Fixes in pars

- [x] **CF-083** -- TQUIC_NEW_STREAM Missing Reserved Field Zeroing Check
  - Severity: S0 | Sources: B | Priority: 10.0
  - Evidence: file:1, sym:1, lines:1, snippet:1
  - Missing: Kernel log / stack trace / error output demonstrating the issue; Independent confirmation from a second audit source
  - Verify: `rg -n "tquic_conn_get" "net/quic/tquic/tquic_stream.c"`
  - Fix: Add strict validation and bounds checks at parse boundaries, enforce lifetime/ownership rules, and fail closed on malformed input. Risk: Fixes in pars

- [x] **CF-084** -- UAF-P1-01: - SmartNIC tquic_nic_find() returns pointer without reference
  - Severity: S0 | Sources: B | Priority: 10.0
  - Evidence: file:1, sym:7, lines:2, snippet:1
  - Missing: Kernel log / stack trace / error output demonstrating the issue; Independent confirmation from a second audit source
  - Verify: `rg -n "tquic_offload_key_install" "net/tquic/offload/smartnic.c"`
  - Fix: Add strict validation and bounds checks at parse boundaries, enforce lifetime/ownership rules, and fail closed on malformed input. Risk: Fixes in pars

- [x] **CF-085** -- Use-After-Free in Connect
  - Severity: S0 | Sources: B | Priority: 10.0
  - Evidence: file:1, sym:3, lines:5, snippet:2
  - Missing: Kernel log / stack trace / error output demonstrating the issue; Independent confirmation from a second audit source
  - Verify: `rg -n "sock" "net/tquic/tquic_socket.c"`
  - Fix: Add strict validation and bounds checks at parse boundaries, enforce lifetime/ownership rules, and fail closed on malformed input. Risk: Fixes in pars

- [x] **CF-119** -- Reference counting/RCU lifetime is not actually enforced; direct `tquic_conn_destroy()` calls can fr
  - Severity: S0 | Sources: A | Priority: 7.0
  - Evidence: file:4, sym:10, lines:4
  - Missing: Code snippet proving the vulnerable pattern; Kernel log / stack trace / error output demonstrating the issue
  - Verify: `rg -n "assertions" "Users/justinadams/Downloads/tquic-kernel/include/net/tquic.h"`
  - Fix: - Make `tquic_conn_destroy()` private/internal (not a general-purpose public API). Enforce that all external callers use `tquic_conn_put()` and that t

- [x] **CF-120** -- rhashtable/RCU lifetime issues (use-after-free risk) in CID tables
  - Severity: S0 | Sources: A | Priority: 7.0
  - Evidence: file:2, sym:6, lines:2
  - Missing: Code snippet proving the vulnerable pattern; Kernel log / stack trace / error output demonstrating the issue
  - Verify: `rg -n "call_rcu" "net/tquic/core/quic_connection.c"`
  - Fix: - Decide on a correct concurrency model:   - Option A: Use rhashtable in the intended RCU mode.     - Lookups under `rcu_read_lock()`.     - Deletions

- [x] **CF-127** -- UAF-P2-01: - SKB accessed after udp_tunnel_xmit_skb
  - Severity: S0 | Sources: B | Priority: 7.0
  - Evidence: file:1, sym:2, snippet:2
  - Missing: Exact line range(s) where the fault manifests; Kernel log / stack trace / error output demonstrating the issue
  - Verify: `rg -n "udp_tunnel_xmit_skb" "net/tquic/tquic_udp.c"`
  - Fix: Add strict validation and bounds checks at parse boundaries, enforce lifetime/ownership rules, and fail closed on malformed input. Risk: Fixes in pars

- [x] **CF-128** -- UAF-P3-01: - retransmit_work_fn accesses ts->conn without connection reference
  - Severity: S0 | Sources: B | Priority: 7.0
  - Evidence: file:1, sym:8, lines:2
  - Missing: Code snippet proving the vulnerable pattern; Kernel log / stack trace / error output demonstrating the issue
  - Verify: `rg -n "cancel_work_sync" "net/tquic/tquic_timer.c"`
  - Fix: Add strict validation and bounds checks at parse boundaries, enforce lifetime/ownership rules, and fail closed on malformed input. Risk: Fixes in pars

- [x] **CF-129** -- UAF-P3-02: - path_work_fn accesses ts->conn without reference
  - Severity: S0 | Sources: B | Priority: 7.0
  - Evidence: file:1, sym:3, snippet:1
  - Missing: Exact line range(s) where the fault manifests; Kernel log / stack trace / error output demonstrating the issue
  - Verify: `rg -n "tquic_timer_state" "net/tquic/tquic_timer.c"`
  - Fix: Add strict validation and bounds checks at parse boundaries, enforce lifetime/ownership rules, and fail closed on malformed input. Risk: Fixes in pars

- [x] **CF-131** -- Use-After-Free in `tquic_migrate_explicit()` -- Path Used Without Reference
  - Severity: S0 | Sources: B | Priority: 7.0
  - Evidence: file:1, sym:5, snippet:1
  - Missing: Exact line range(s) where the fault manifests; Kernel log / stack trace / error output demonstrating the issue
  - Verify: `rg -n "tquic_path_find_by_addr" "net/tquic/tquic_migration.c"`
  - Fix: Add strict validation and bounds checks at parse boundaries, enforce lifetime/ownership rules, and fail closed on malformed input. Risk: Fixes in pars

- [x] **CF-132** -- Use-After-Free in Algorithm Name Return
  - Severity: S0 | Sources: B | Priority: 7.0
  - Evidence: file:1, sym:4, snippet:1
  - Missing: Exact line range(s) where the fault manifests; Kernel log / stack trace / error output demonstrating the issue
  - Verify: `rg -n "tquic_cong_get_default_name" "net/tquic/cong/tquic_cong.c"`
  - Fix: Add strict validation and bounds checks at parse boundaries, enforce lifetime/ownership rules, and fail closed on malformed input. Risk: Fixes in pars

- [x] **CF-134** -- Widespread allocator mismatches (kmem_cache vs kzalloc/kfree) for core objects (conn/path/stream)
  - Severity: S0 | Sources: A | Priority: 7.0
  - Evidence: file:6, sym:18, lines:9
  - Missing: Code snippet proving the vulnerable pattern; Kernel log / stack trace / error output demonstrating the issue
  - Verify: `rg -n "evidence" "net/tquic/Makefile"`
  - Fix: - Pick exactly one allocator strategy per object type (`tquic_connection`, `tquic_path`, `tquic_stream`) and enforce it via dedicated wrappers:   - `t

#### Security (18)

- [x] **CF-020** -- ASN.1 Time Parsing Does Not Validate Character Ranges
  - Severity: S0 | Sources: B,C | Priority: 10.0
  - Evidence: file:1, snippet:1
  - Missing: Exact line range(s) where the fault manifests; Function/struct symbol name at the fault site
  - Verify: `make M=net/tquic W=1`
  - Fix: Validate each character is an ASCII digit before arithmetic. Validate month (1-12), day (1-31), hour (0-23), minute (0-59), second (0-59). Risk: Fixes

- [x] **CF-021** -- Authentication Bypass in QUIC-Aware Proxy
  - Severity: S0 | Sources: B,C | Priority: 10.0
  - Evidence: file:1, sym:2, snippet:1
  - Missing: Exact line range(s) where the fault manifests; Kernel log / stack trace / error output demonstrating the issue
  - Verify: `rg -n "tquic_quic_proxy_register_conn" "net/tquic/masque/quic_proxy.c"`
  - Fix: Set `require_auth = true` by default. Implement mandatory authentication (PSK, certificate, or token-based) in `tquic_quic_proxy_register_conn()` befo

- [x] **CF-025** -- Complete SSRF in CONNECT-UDP -- No Address Validation
  - Severity: S0 | Sources: B,C | Priority: 10.0
  - Evidence: file:1, sym:11, snippet:1
  - Missing: Exact line range(s) where the fault manifests; Kernel log / stack trace / error output demonstrating the issue
  - Verify: `rg -n "resolve_target" "net/tquic/masque/connect_udp.c"`
  - Fix: Add address validation after `in4_pton`/`in6_pton` succeeds. Block at minimum: `ipv4_is_loopback()`, `ipv4_is_multicast()`, `ipv4_is_lbcast()`, `ipv4_

- [x] **CF-031** -- Hard-Fail Revocation Mode Does Not Actually Fail
  - Severity: S0 | Sources: B,C | Priority: 10.0
  - Evidence: file:1, snippet:2
  - Missing: Exact line range(s) where the fault manifests; Function/struct symbol name at the fault site
  - Verify: `make M=net/tquic W=1`
  - Fix: The function must return `-EKEYREVOKED` or a similar error when `TQUIC_REVOKE_HARD_FAIL` is set and revocation status cannot be determined.  --- Risk:

- [x] **CF-039** -- Netfilter Hooks Registered Only in init_net
  - Severity: S0 | Sources: B,C | Priority: 10.0
  - Evidence: file:1, sym:1, snippet:1
  - Missing: Exact line range(s) where the fault manifests; Kernel log / stack trace / error output demonstrating the issue
  - Verify: `rg -n "tquic_nf" "net/tquic/tquic_nf.c"`
  - Fix: Register hooks via `pernet_operations` so each namespace gets its own hooks, or verify this is intentionally init_net-only and document the limitation

- [x] **CF-041** -- No Privilege Check for TQUIC Socket Creation
  - Severity: S0 | Sources: B,C | Priority: 10.0
  - Evidence: file:1, sym:1
  - Missing: Exact line range(s) where the fault manifests; Code snippet proving the vulnerable pattern
  - Verify: `rg -n "tquic_proto" "net/tquic/tquic_proto.c"`
  - Fix: Consider requiring `CAP_NET_ADMIN` for bonding/multipath features, or at minimum for creating tunnels and MASQUE proxies.  --- Risk: Fixes in parser/c

- [x] **CF-042** -- No Privilege Checks for Security-Sensitive Socket Options
  - Severity: S0 | Sources: B,C | Priority: 10.0
  - Evidence: file:1, sym:2, lines:5
  - Missing: Code snippet proving the vulnerable pattern; Kernel log / stack trace / error output demonstrating the issue
  - Verify: `rg -n "tquic_socket" "net/tquic/tquic_socket.c"`
  - Fix: Add `ns_capable(sock_net(sk)->user_ns, CAP_NET_ADMIN)` checks for privileged options.  --- Risk: Fixes in parser/crypto/lifetime code may alter packet

- [x] **CF-057** -- SSRF via IPv4-Mapped IPv6 Addresses Bypasses Address Filtering
  - Severity: S0 | Sources: B,C | Priority: 10.0
  - Evidence: file:1, sym:2, snippet:1
  - Missing: Exact line range(s) where the fault manifests; Kernel log / stack trace / error output demonstrating the issue
  - Verify: `rg -n "ipv6_addr_v4mapped" "net/tquic/tquic_tunnel.c"`
  - Fix: Add checks for `ipv6_addr_v4mapped()`, `ipv6_addr_is_isatap()`, private RFC 1918 ranges within mapped addresses, and the unspecified address (`::` Ris

- [x] **CF-066** -- Tunnel Uses init_net -- Namespace Escape
  - Severity: S0 | Sources: B,C | Priority: 10.0
  - Evidence: file:1, snippet:1
  - Missing: Exact line range(s) where the fault manifests; Function/struct symbol name at the fault site
  - Verify: `make M=net/tquic W=1`
  - Fix: Use the network namespace from the QUIC connection's socket (`sock_net(conn->sk)`) instead of `&init_net`. Pass the correct `struct net *` through the

- [x] **CF-071** -- AF_XDP Socket and Device Lookup Use init_net
  - Severity: S0 | Sources: B | Priority: 10.0
  - Evidence: file:1, sym:1, lines:3, snippet:1
  - Missing: Kernel log / stack trace / error output demonstrating the issue; Independent confirmation from a second audit source
  - Verify: `rg -n "tquic_xsk_create" "net/tquic/af_xdp.c"`
  - Fix: Add strict validation and bounds checks at parse boundaries, enforce lifetime/ownership rules, and fail closed on malformed input. Risk: Fixes in pars

- [x] **CF-077** -- QUIC-over-TCP Client and Server Sockets Use init_net
  - Severity: S0 | Sources: B | Priority: 10.0
  - Evidence: file:1, sym:1, lines:2, snippet:1
  - Missing: Kernel log / stack trace / error output demonstrating the issue; Independent confirmation from a second audit source
  - Verify: `rg -n "quic_over_tcp" "net/tquic/transport/quic_over_tcp.c"`
  - Fix: Add strict validation and bounds checks at parse boundaries, enforce lifetime/ownership rules, and fail closed on malformed input. Risk: Fixes in pars

- [x] **CF-086** -- Wrong Network Namespace in ip_local_out
  - Severity: S0 | Sources: B | Priority: 10.0
  - Evidence: file:1, lines:2, snippet:2
  - Missing: Function/struct symbol name at the fault site; Kernel log / stack trace / error output demonstrating the issue
  - Verify: `sed -n '1730,1730p' net/tquic/tquic_output.c`
  - Fix: Use `sock_net(conn->sk)` instead of `&init_net`. The correct network namespace was already computed at line 1681 in the `rt` lookup: ```c ret = ip_loc

- [ ] **CF-092** -- CID demux/lookup appears non-functional: the RX path uses one table, while connection creation popul
  - Severity: S0 | Sources: A | Priority: 7.0
  - Evidence: file:4, sym:6, lines:4
  - Missing: Code snippet proving the vulnerable pattern; Kernel log / stack trace / error output demonstrating the issue
  - Verify: `rg -n "tquic_cid_hash_add" "net/tquic/core/connection.c"`
  - Fix: - Pick exactly one authoritative CID demux table for RX and ensure connection creation inserts the SCID/DCIDs into it. - Delete or hard-disable the un

- [x] **CF-099** -- Header protection outputs are ignored; packet-number length + key phase are derived from protected h
  - Severity: S0 | Sources: A | Priority: 7.0
  - Evidence: file:1, sym:2, lines:3
  - Missing: Code snippet proving the vulnerable pattern; Kernel log / stack trace / error output demonstrating the issue
  - Verify: `rg -n "tquic_hp_unprotect" "net/tquic/tquic_input.c"`
  - Fix: - Treat `tquic_hp_unprotect()` as authoritative for `pn_len` and (short header) `key_phase`. - After HP removal, recompute any fields derived from the

- [x] **CF-100** -- Huffman Decoder O(n*256) Algorithmic Complexity DoS
  - Severity: S0 | Sources: B | Priority: 7.0
  - Evidence: file:1, snippet:1
  - Missing: Exact line range(s) where the fault manifests; Function/struct symbol name at the fault site
  - Verify: `make M=net/tquic W=1`
  - Fix: Add strict validation and bounds checks at parse boundaries, enforce lifetime/ownership rules, and fail closed on malformed input. Risk: Fixes in pars

- [x] **CF-102** -- IPv4/IPv6 Address Discovery Enumerates Host Interfaces
  - Severity: S0 | Sources: B | Priority: 7.0
  - Evidence: file:2, snippet:2
  - Missing: Exact line range(s) where the fault manifests; Function/struct symbol name at the fault site
  - Verify: `make M=net/tquic W=1`
  - Fix: Add strict validation and bounds checks at parse boundaries, enforce lifetime/ownership rules, and fail closed on malformed input. Risk: Fixes in pars

- [x] **CF-106** -- MASQUE CONNECT-UDP Proxy Creates Sockets in init_net
  - Severity: S0 | Sources: B | Priority: 7.0
  - Evidence: file:1, snippet:1
  - Missing: Exact line range(s) where the fault manifests; Function/struct symbol name at the fault site
  - Verify: `make M=net/tquic W=1`
  - Fix: Add strict validation and bounds checks at parse boundaries, enforce lifetime/ownership rules, and fail closed on malformed input. Risk: Fixes in pars

- [x] **CF-125** -- Tunnel Socket Creation Uses init_net
  - Severity: S0 | Sources: B | Priority: 7.0
  - Evidence: file:1, sym:3, snippet:1
  - Missing: Exact line range(s) where the fault manifests; Kernel log / stack trace / error output demonstrating the issue
  - Verify: `rg -n "should" "net/tquic/tquic_tunnel.c"`
  - Fix: Add strict validation and bounds checks at parse boundaries, enforce lifetime/ownership rules, and fail closed on malformed input. Risk: Fixes in pars

#### Concurrency (11)

- [x] **CF-013** -- `tquic_close()` Does Not Hold `lock_sock()` During Connection Teardown
  - Severity: S0 | Sources: B,C | Priority: 10.0
  - Evidence: file:1, sym:12, snippet:3
  - Missing: Exact line range(s) where the fault manifests; Kernel log / stack trace / error output demonstrating the issue
  - Verify: `rg -n "tquic_sock" "net/tquic/tquic_socket.c"`
  - Fix: Establish one synchronization model for this code path and make all state transitions/lookup paths follow it consistently. Risk: Locking/ordering chan

- [x] **CF-017** -- `tquic_shutdown()` Missing `lock_sock()` -- Race on Connection State
  - Severity: S0 | Sources: B,C | Priority: 10.0
  - Evidence: file:1, sym:9, snippet:2
  - Missing: Exact line range(s) where the fault manifests; Kernel log / stack trace / error output demonstrating the issue
  - Verify: `rg -n "tquic_shutdown" "net/tquic/tquic_socket.c"`
  - Fix: Establish one synchronization model for this code path and make all state transitions/lookup paths follow it consistently. Risk: Locking/ordering chan

- [x] **CF-022** -- BLEST Inconsistent Locking -- 3 of 6 Callbacks Lack Lock
  - Severity: S0 | Sources: B,C | Priority: 10.0
  - Evidence: file:1, sym:5, snippet:1
  - Missing: Exact line range(s) where the fault manifests; Kernel log / stack trace / error output demonstrating the issue
  - Verify: `rg -n "blest_get_path" "net/tquic/multipath/sched_blest.c"`
  - Fix: Add `spin_lock_irqsave(&sd->lock, flags)` to `blest_path_removed()`, `blest_ack_received()`, and `blest_loss_detected()`.  --- Risk: Locking/ordering 

- [x] **CF-026** -- ECF Scheduler Declares Lock But Never Uses It
  - Severity: S0 | Sources: B,C | Priority: 10.0
  - Evidence: file:1, sym:1, snippet:1
  - Missing: Exact line range(s) where the fault manifests; Kernel log / stack trace / error output demonstrating the issue
  - Verify: `rg -n "spin_lock_irqsave" "net/tquic/multipath/sched_ecf.c"`
  - Fix: Wrap all accesses to `sd->paths[]` and `sd->current_path_id` in `spin_lock_irqsave(&sd->lock, flags)` Risk: Locking/ordering changes can cause deadloc

- [x] **CF-036** -- Missing RFC 1918 / Private Network Filtering in IPv4 SSRF Checks
  - Severity: S0 | Sources: B,C | Priority: 10.0
  - Evidence: file:1, sym:5, snippet:1
  - Missing: Exact line range(s) where the fault manifests; Kernel log / stack trace / error output demonstrating the issue
  - Verify: `rg -n "ipv4_is_linklocal_169" "net/tquic/tquic_tunnel.c"`
  - Fix: Add checks for `ipv4_is_private_10()`, `ipv4_is_private_172()`, `ipv4_is_private_192()`, `ipv4_is_linklocal_169()`, and other reserved ranges per RFC 

- [x] **CF-082** -- TOCTOU Race in Failover Hysteresis
  - Severity: S0 | Sources: B | Priority: 10.0
  - Evidence: file:1, sym:3, lines:4, snippet:3
  - Missing: Kernel log / stack trace / error output demonstrating the issue; Independent confirmation from a second audit source
  - Verify: `rg -n "atomic_set" "net/quic/tquic/bond/tquic_failover.c"`
  - Fix: Either protect these operations with a per-path spinlock, or use `atomic_inc_return()` Risk: Locking/ordering changes can cause deadlocks or throughpu

- [x] **CF-095** -- Connection State Transition Not Fully Atomic
  - Severity: S0 | Sources: B | Priority: 7.0
  - Evidence: file:2, sym:5, snippet:1
  - Missing: Exact line range(s) where the fault manifests; Kernel log / stack trace / error output demonstrating the issue
  - Verify: `rg -n "tquic_conn_set_state" "net/tquic/core/connection.c"`
  - Fix: Establish one synchronization model for this code path and make all state transitions/lookup paths follow it consistently. Risk: Locking/ordering chan

- [x] **CF-104** -- List Iterator Invalidation in BPM Netdev Notifier
  - Severity: S0 | Sources: B | Priority: 7.0
  - Evidence: file:1, sym:5, lines:1
  - Missing: Code snippet proving the vulnerable pattern; Kernel log / stack trace / error output demonstrating the issue
  - Verify: `rg -n "rcu_read_unlock" "net/quic/tquic/bond/tquic_bpm.c"`
  - Fix: Use `list_for_each_entry_safe()` is NOT sufficient here since the iteration continues after relock. Instead, collect paths to process into a separate 

- [x] **CF-112** -- QPACK Dynamic Table Duplicate TOCTOU Race
  - Severity: S0 | Sources: B | Priority: 7.0
  - Evidence: file:1, sym:2, snippet:1
  - Missing: Exact line range(s) where the fault manifests; Kernel log / stack trace / error output demonstrating the issue
  - Verify: `rg -n "qpack_dynamic" "net/quic/tquic/http3/qpack_dynamic.c"`
  - Fix: Establish one synchronization model for this code path and make all state transitions/lookup paths follow it consistently. Risk: Locking/ordering chan

- [x] **CF-113** -- QUIC-Exfil mitigation code uses `skb->cb` as a function-pointer slot and gates on `skb->cb[0]`
  - Severity: S0 | Sources: A | Priority: 7.0
  - Evidence: file:1, lines:2
  - Missing: Code snippet proving the vulnerable pattern; Function/struct symbol name at the fault site
  - Verify: `sed -n '1090,1090p' net/tquic/security/quic_exfil.c`
  - Fix: - Never store function pointers in `skb->cb`. - Use a wrapper object (`struct { struct sk_buff *skb; void (*send_fn)(...); }`) in a dedicated queue, o

- [x] **CF-115** -- Rate Calculation Integer Overflow
  - Severity: S0 | Sources: B | Priority: 7.0
  - Evidence: file:2, snippet:2
  - Missing: Exact line range(s) where the fault manifests; Function/struct symbol name at the fault site
  - Verify: `make M=net/tquic W=1`
  - Fix: Establish one synchronization model for this code path and make all state transitions/lookup paths follow it consistently. Risk: Locking/ordering chan

#### Correctness (18)

- [x] **CF-018** -- `tquic_varint_len()` Returns 0 for Invalid Values Without Error Propagation
  - Severity: S0 | Sources: B,C | Priority: 10.0
  - Evidence: file:1, sym:3, snippet:1
  - Missing: Exact line range(s) where the fault manifests; Kernel log / stack trace / error output demonstrating the issue
  - Verify: `rg -n "tquic_varint_len" "net/tquic/tquic_output.c"`
  - Fix: Add explicit check: `if (len == 0) return -EOVERFLOW;` Risk: Protocol correctness fixes can shift timing/state-machine behavior; verify against intero

- [x] **CF-027** -- ECN CE Count Processing Does Not Track Deltas
  - Severity: S0 | Sources: B,C | Priority: 10.0
  - Evidence: file:1, sym:3, snippet:1
  - Missing: Exact line range(s) where the fault manifests; Kernel log / stack trace / error output demonstrating the issue
  - Verify: `rg -n "tquic_cong_on_ecn" "net/tquic/tquic_input.c"`
  - Fix: Store the previous ECN counts per path (in `struct tquic_ecn_tracking`) and only call `tquic_cong_on_ecn()` with the delta when `ecn_ce > path->ecn.ce

- [x] **CF-032** -- Hardcoded init_net Namespace Bypass in Socket Creation
  - Severity: S0 | Sources: B,C | Priority: 10.0
  - Evidence: file:2, sym:2, snippet:2
  - Missing: Exact line range(s) where the fault manifests; Kernel log / stack trace / error output demonstrating the issue
  - Verify: `rg -n "tquic_tunnel" "net/tquic/masque/connect_udp.c"`
  - Fix: Store a reference to the correct network namespace (`struct net *`) at connection establishment time (via `sock_net(sk)` from the original QUIC socket

- [x] **CF-040** -- No Address Validation in CONNECT-IP Packet Injection
  - Severity: S0 | Sources: B,C | Priority: 10.0
  - Evidence: file:1, sym:5, snippet:2
  - Missing: Exact line range(s) where the fault manifests; Kernel log / stack trace / error output demonstrating the issue
  - Verify: `rg -n "netif_rx" "net/tquic/masque/connect_ip.c"`
  - Fix: Add source and destination address validation in `connect_ip_validate_ip_header()` or a new function called before `netif_rx()`. Block loopback, multi

- [x] **CF-062** -- tquic_conn_server_accept() -- overrides actual error code with -EINVAL
  - Severity: S0 | Sources: B,C | Priority: 10.0
  - Evidence: file:1, sym:1, snippet:1
  - Missing: Exact line range(s) where the fault manifests; Kernel log / stack trace / error output demonstrating the issue
  - Verify: `rg -n "tquic_conn_server_accept" "net/quic/tquic/core/connection.c"`
  - Fix: Change to `return ret;` Risk: Protocol correctness fixes can shift timing/state-machine behavior; verify against interop traces and existing retransmi

- [x] **CF-073** -- Integer Overflow in bytes_acked Calculation
  - Severity: S0 | Sources: B | Priority: 10.0
  - Evidence: file:1, sym:3, lines:1, snippet:2
  - Missing: Kernel log / stack trace / error output demonstrating the issue; Independent confirmation from a second audit source
  - Verify: `rg -n "tquic_cong_on_ack" "net/quic/tquic/tquic_input.c"`
  - Fix: Fix the protocol logic per the relevant RFC section; add an interop regression test covering the corrected state transition.

- [x] **CF-075** -- Missing Upper Bound on Coalesced Packet Count
  - Severity: S0 | Sources: B | Priority: 10.0
  - Evidence: file:1, sym:7, lines:6, snippet:2
  - Missing: Kernel log / stack trace / error output demonstrating the issue; Independent confirmation from a second audit source
  - Verify: `rg -n "tquic_udp_recv" "net/quic/tquic/tquic_input.c"`
  - Fix: Fix the protocol logic per the relevant RFC section; add an interop regression test covering the corrected state transition.

- [x] **CF-076** -- Packet Number Length Extracted Before Header Unprotection
  - Severity: S0 | Sources: B | Priority: 10.0
  - Evidence: file:1, sym:1, lines:3, snippet:2
  - Missing: Kernel log / stack trace / error output demonstrating the issue; Independent confirmation from a second audit source
  - Verify: `rg -n "tquic_remove_header_protection" "net/tquic/tquic_input.c"`
  - Fix: Move the `pkt_num_len` extraction to AFTER `tquic_remove_header_protection()`: ```c ret = tquic_remove_header_protection(conn, data, ctx.offset, ...);

- [x] **CF-079** -- Stale skb->len Read After ip_local_out
  - Severity: S0 | Sources: B | Priority: 10.0
  - Evidence: file:1, sym:2, lines:1, snippet:2
  - Missing: Kernel log / stack trace / error output demonstrating the issue; Independent confirmation from a second audit source
  - Verify: `rg -n "ip_local_out" "net/tquic/tquic_output.c"`
  - Fix: Save `skb->len` in a local variable before calling `ip_local_out()`: ```c u32 pkt_len = skb->len; ret = ip_local_out(&init_net, NULL, skb); if (ret >=

- [x] **CF-080** -- State Machine Type Confusion via `conn->state_machine` Void Pointer
  - Severity: S0 | Sources: B | Priority: 10.0
  - Evidence: file:1, sym:11, lines:1, snippet:1
  - Missing: Kernel log / stack trace / error output demonstrating the issue; Independent confirmation from a second audit source
  - Verify: `rg -n "could" "net/tquic/tquic_migration.c"`
  - Fix: Fix the protocol logic per the relevant RFC section; add an interop regression test covering the corrected state transition.

- [x] **CF-089** -- ACK Range Failover Can Iterate Over Unbounded Packet Number Range
  - Severity: S0 | Sources: B | Priority: 7.0
  - Evidence: file:1, sym:4, snippet:1
  - Missing: Exact line range(s) where the fault manifests; Kernel log / stack trace / error output demonstrating the issue
  - Verify: `rg -n "tquic_failover_ctx" "net/tquic/bond/tquic_failover.c"`
  - Fix: Fix the protocol logic per the relevant RFC section; add an interop regression test covering the corrected state transition.

- [x] **CF-096** -- Connection State Transition Not Fully Atomic
  - Severity: S0 | Sources: C | Priority: 7.0
  - Evidence: file:1, sym:3, snippet:1
  - Missing: Exact line range(s) where the fault manifests; Kernel log / stack trace / error output demonstrating the issue
  - Verify: `rg -n "tquic_conn_set_state" "net/tquic/tquic_input.c"`
  - Fix: All state transitions MUST go through `tquic_conn_set_state()`, and the function should assert/acquire `conn->lock` internally. Fix `tquic_handle_stat

- [x] **CF-097** -- Excessive Stack Usage in RS Recovery
  - Severity: S0 | Sources: B | Priority: 7.0
  - Evidence: file:1, sym:2, snippet:2
  - Missing: Exact line range(s) where the fault manifests; Kernel log / stack trace / error output demonstrating the issue
  - Verify: `rg -n "attempt_rs_recovery" "net/tquic/fec/fec_decoder.c"`
  - Fix: Fix the protocol logic per the relevant RFC section; add an interop regression test covering the corrected state transition.

- [x] **CF-098** -- Global connection hashtable (`tquic_conn_table`) is initialized and removed-from, but never inserted
  - Severity: S0 | Sources: A | Priority: 7.0
  - Evidence: file:1, sym:4, lines:2
  - Missing: Code snippet proving the vulnerable pattern; Kernel log / stack trace / error output demonstrating the issue
  - Verify: `rg -n "hashtable" "net/tquic/tquic_main.c"`
  - Fix: - Either wire up insertion consistently at connection establishment, or delete `tquic_conn_table` and all iteration users in favor of the per-netns li

- [x] **CF-101** -- Integer Overflow in Coupled CC Increase Calculation
  - Severity: S0 | Sources: B | Priority: 7.0
  - Evidence: file:1, sym:1, snippet:1
  - Missing: Exact line range(s) where the fault manifests; Kernel log / stack trace / error output demonstrating the issue
  - Verify: `rg -n "coupled_cc_increase" "net/tquic/bond/cong_coupled.c"`
  - Fix: Fix the protocol logic per the relevant RFC section; add an interop regression test covering the corrected state transition.

- [x] **CF-110** -- Packet number reconstruction always uses `largest_pn = 0`
  - Severity: S0 | Sources: A | Priority: 7.0
  - Evidence: file:1, sym:1, lines:1
  - Missing: Code snippet proving the vulnerable pattern; Kernel log / stack trace / error output demonstrating the issue
  - Verify: `rg -n "tquic_decode_pkt_num" "net/tquic/tquic_input.c"`
  - Fix: - Track `largest_pn` per PN space (Initial/Handshake/Application) and pass it into `tquic_decode_pkt_num()`. Risk: Protocol correctness fixes can shif

- [x] **CF-118** -- Redundant Scheduler Deduplication Uses Only 8-bit Sequence Hash -- Trivial Collision
  - Severity: S0 | Sources: B | Priority: 7.0
  - Evidence: file:1, sym:3, snippet:2
  - Missing: Exact line range(s) where the fault manifests; Kernel log / stack trace / error output demonstrating the issue
  - Verify: `rg -n "tquic_connection" "net/tquic/multipath/tquic_scheduler.c"`
  - Fix: Fix the protocol logic per the relevant RFC section; add an interop regression test covering the corrected state transition.

- [x] **CF-122** -- Same Overflow in OLIA Increase Path
  - Severity: S0 | Sources: B | Priority: 7.0
  - Evidence: file:1, sym:1, snippet:1
  - Missing: Exact line range(s) where the fault manifests; Kernel log / stack trace / error output demonstrating the issue
  - Verify: `rg -n "olia_cc_increase" "net/tquic/bond/cong_coupled.c"`
  - Fix: Fix the protocol logic per the relevant RFC section; add an interop regression test covering the corrected state transition.

#### Perf (1)

- [x] **CF-067** -- Unbounded Memory Allocation from Attacker-Controlled Capsule Length
  - Severity: S0 | Sources: B,C | Priority: 10.0
  - Evidence: file:1, sym:2, snippet:3
  - Missing: Exact line range(s) where the fault manifests; Kernel log / stack trace / error output demonstrating the issue
  - Verify: `rg -n "capsule_alloc" "net/tquic/masque/capsule.c"`
  - Fix: Validate `parser->header.length <= CAPSULE_MAX_PAYLOAD_SIZE` immediately after header decode succeeds, before calling `capsule_alloc()`. Additionally,

#### Build (1)

- [x] **CF-063** -- tquic_send_connection_close() -- SKB leak and unencrypted packet on header failure
  - Severity: S0 | Sources: B,C | Priority: 10.0
  - Evidence: file:1, sym:4, snippet:1
  - Missing: Exact line range(s) where the fault manifests; Kernel log / stack trace / error output demonstrating the issue
  - Verify: `rg -n "tquic_send_connection_close" "net/quic/tquic/tquic_output.c"`
  - Fix: Add `if (header_len < 0) { kfree_skb(skb); kfree(buf); return header_len; }` before the `skb_put_data` calls.  --- Risk: Protocol correctness fixes ca

---

## Phase 4: PLAUSIBLE S1 -- High Likely (96 items)

#### Memory (24)

- [ ] **CF-161** -- `tquic_hs_cleanup` -- potential double-free of session ticket
  - Severity: S1 | Sources: B,C | Priority: 7.0
  - Evidence: file:1, sym:2, snippet:2
  - Missing: Exact line range(s) where the fault manifests; Kernel log / stack trace / error output demonstrating the issue
  - Verify: `rg -n "tquic_hs_setup_psk" "net/tquic/crypto/handshake.c"`
  - Fix: Either document clearly that `tquic_hs_setup_psk` takes ownership (and the caller must not free), or make `tquic_hs_setup_psk` copy the ticket data.  

- [ ] **CF-162** -- `tquic_hs_generate_client_hello` -- output buffer `buf` not validated for minimum size
  - Severity: S1 | Sources: B,C | Priority: 7.0
  - Evidence: file:1, sym:1, lines:1
  - Missing: Code snippet proving the vulnerable pattern; Kernel log / stack trace / error output demonstrating the issue
  - Verify: `rg -n "tquic_hs_generate_client_hello" "net/tquic/crypto/handshake.c"`
  - Fix: Validate `buf_len` against the minimum required size at function entry.  --- Risk: Fixes in parser/crypto/lifetime code may alter packet acceptance lo

- [ ] **CF-171** -- atomic_sub on sk_rmem_alloc Incompatible with refcount_t
  - Severity: S1 | Sources: B,C | Priority: 7.0
  - Evidence: file:1, sym:2, snippet:1
  - Missing: Exact line range(s) where the fault manifests; Kernel log / stack trace / error output demonstrating the issue
  - Verify: `rg -n "skb_set_owner_r" "net/quic/tquic/core/stream.c"`
  - Fix: Use `skb_set_owner_r()` for receive buffers and let the destructor handle accounting, consistent with the tquic_stream.c approach.  --- Risk: Fixes in

- [ ] **CF-175** -- CID Lookup Returns Connection Without Reference Count
  - Severity: S1 | Sources: B,C | Priority: 7.0
  - Evidence: file:1, sym:5, snippet:1
  - Missing: Exact line range(s) where the fault manifests; Kernel log / stack trace / error output demonstrating the issue
  - Verify: `rg -n "kfree_rcu" "net/tquic/tquic_cid.c"`
  - Fix: The caller should be in an RCU read-side section, and connections should be freed via `kfree_rcu()`. Alternatively, take a refcount on the connection 

- [ ] **CF-181** -- const-Correctness Violation in Proxy Packet Decode
  - Severity: S1 | Sources: B,C | Priority: 7.0
  - Evidence: file:1, sym:1, snippet:1
  - Missing: Exact line range(s) where the fault manifests; Kernel log / stack trace / error output demonstrating the issue
  - Verify: `rg -n "quic_proxy_capsules" "net/tquic/masque/quic_proxy_capsules.c"`
  - Fix: Either copy the packet data into a separately allocated buffer, or declare `capsule->packet` as `const u8 *` and ensure all consumers respect const co

- [ ] **CF-201** -- Integer Overflow in iovec Total Length Calculation
  - Severity: S1 | Sources: B,C | Priority: 7.0
  - Evidence: file:1, sym:2, snippet:2
  - Missing: Exact line range(s) where the fault manifests; Kernel log / stack trace / error output demonstrating the issue
  - Verify: `rg -n "check_add_overflow" "net/tquic/masque/connect_udp.c"`
  - Fix: Use `check_add_overflow()` or manually check for overflow: `if (total_len + iov[i].iov_len < total_len) return -EOVERFLOW;` within the accumulation lo

- [ ] **CF-209** -- Netfilter Short Header DCID Parsing Uses Arbitrary Length
  - Severity: S1 | Sources: B,C | Priority: 7.0
  - Evidence: file:1, sym:1, snippet:1
  - Missing: Exact line range(s) where the fault manifests; Kernel log / stack trace / error output demonstrating the issue
  - Verify: `rg -n "tquic_nf" "net/quic/tquic/tquic_nf.c"`
  - Fix: Add strict validation and bounds checks at parse boundaries, enforce lifetime/ownership rules, and fail closed on malformed input. Risk: Fixes in pars

- [ ] **CF-221** -- Retry Packet Version Encoding Is Hardcoded for v1
  - Severity: S1 | Sources: B,C | Priority: 7.0
  - Evidence: file:1, sym:1, snippet:1
  - Missing: Exact line range(s) where the fault manifests; Kernel log / stack trace / error output demonstrating the issue
  - Verify: `rg -n "tquic_encode_packet_type" "net/tquic/core/connection.c"`
  - Fix: Use `tquic_encode_packet_type()` for the header byte and `cpu_to_be32(conn->version)` for the version field. Risk: Fixes in parser/crypto/lifetime cod

- [ ] **CF-229** -- Ticket Store Free-After-Remove Race Condition
  - Severity: S1 | Sources: B,C | Priority: 7.0
  - Evidence: file:1, sym:2, snippet:2
  - Missing: Exact line range(s) where the fault manifests; Kernel log / stack trace / error output demonstrating the issue
  - Verify: `rg -n "tquic_zero_rtt_ticket" "net/tquic/crypto/zero_rtt.c"`
  - Fix: `ticket_store_remove_locked` should only remove from the tree/list. The actual free should happen via `tquic_zero_rtt_put_ticket` (refcount-based). Ch

- [ ] **CF-235** -- tquic_stream_sendfile Reads Only Into First Page
  - Severity: S1 | Sources: B,C | Priority: 7.0
  - Evidence: file:1, sym:1, snippet:1
  - Missing: Exact line range(s) where the fault manifests; Kernel log / stack trace / error output demonstrating the issue
  - Verify: `rg -n "tquic_stream_sendfile" "net/quic/tquic/core/stream.c"`
  - Fix: Read into each page individually, or allocate a contiguous buffer. The current code only works correctly when `chunk <= PAGE_SIZE`. Risk: Fixes in par

- [ ] **CF-244** -- Connection Close Reason Phrase Skipped Without Content Validation
  - Severity: S1 | Sources: B | Priority: 7.0
  - Evidence: file:2, sym:1, lines:3, snippet:2
  - Missing: Kernel log / stack trace / error output demonstrating the issue; Independent confirmation from a second audit source
  - Verify: `rg -n "tquic_output_packet" "net/tquic/tquic_output.c"`
  - Fix: Save `skb->len` before calling `tquic_output_packet()`. Risk: Fixes in parser/crypto/lifetime code may alter packet acceptance logic. Watch for intero

- [ ] **CF-245** -- Data Race in Server Migration Check
  - Severity: S1 | Sources: B | Priority: 7.0
  - Evidence: file:1, sym:1, lines:2, snippet:1
  - Missing: Kernel log / stack trace / error output demonstrating the issue; Independent confirmation from a second audit source
  - Verify: `rg -n "tquic_migration" "net/tquic/tquic_migration.c"`
  - Fix: Add strict validation and bounds checks at parse boundaries, enforce lifetime/ownership rules, and fail closed on malformed input. Risk: Fixes in pars

- [ ] **CF-246** -- Internal Round-Robin Scheduler Missing Bounds Check
  - Severity: S1 | Sources: B | Priority: 7.0
  - Evidence: file:1, sym:2, lines:1, snippet:1
  - Missing: Kernel log / stack trace / error output demonstrating the issue; Independent confirmation from a second audit source
  - Verify: `rg -n "tquic_weighted_select_path" "net/tquic/multipath/tquic_scheduler.c"`
  - Fix: Add strict validation and bounds checks at parse boundaries, enforce lifetime/ownership rules, and fail closed on malformed input. Risk: Fixes in pars

- [ ] **CF-253** -- UAF-P1-02: - tquic_diag.c accesses conn->sk without reference
  - Severity: S1 | Sources: B | Priority: 7.0
  - Evidence: file:1, sym:3, lines:2, snippet:1
  - Missing: Kernel log / stack trace / error output demonstrating the issue; Independent confirmation from a second audit source
  - Verify: `rg -n "tquic_net_close_connection" "net/tquic/tquic_diag.c"`
  - Fix: Add strict validation and bounds checks at parse boundaries, enforce lifetime/ownership rules, and fail closed on malformed input. Risk: Fixes in pars

- [ ] **CF-254** -- UAF-P3-03: - Tunnel close races with connect_work and forward_work
  - Severity: S1 | Sources: B | Priority: 7.0
  - Evidence: file:1, sym:4, lines:4, snippet:1
  - Missing: Kernel log / stack trace / error output demonstrating the issue; Independent confirmation from a second audit source
  - Verify: `rg -n "cancel_work_sync" "net/tquic/tquic_tunnel.c"`
  - Fix: Add strict validation and bounds checks at parse boundaries, enforce lifetime/ownership rules, and fail closed on malformed input. Risk: Fixes in pars

- [ ] **CF-255** -- UAF-P3-04: - Path validation timer callback accesses path after potential free
  - Severity: S1 | Sources: B | Priority: 7.0
  - Evidence: file:1, sym:8, lines:3, snippet:1
  - Missing: Kernel log / stack trace / error output demonstrating the issue; Independent confirmation from a second audit source
  - Verify: `rg -n "tquic_path" "net/tquic/tquic_timer.c"`
  - Fix: Add strict validation and bounds checks at parse boundaries, enforce lifetime/ownership rules, and fail closed on malformed input. Risk: Fixes in pars

- [ ] **CF-256** -- UAF-P6-01: - SmartNIC ops dereference after device could be freed
  - Severity: S1 | Sources: B | Priority: 7.0
  - Evidence: file:1, sym:1, lines:4, snippet:1
  - Missing: Kernel log / stack trace / error output demonstrating the issue; Independent confirmation from a second audit source
  - Verify: `rg -n "tquic_nic_unregister" "net/tquic/offload/smartnic.c"`
  - Fix: Add strict validation and bounds checks at parse boundaries, enforce lifetime/ownership rules, and fail closed on malformed input. Risk: Fixes in pars

- [ ] **CF-271** -- FEC Scheme ID Not Validated From Wire
  - Severity: S1 | Sources: B | Priority: 4.9
  - Evidence: file:1, snippet:1
  - Missing: Exact line range(s) where the fault manifests; Function/struct symbol name at the fault site
  - Verify: `rg -n "kmalloc\|kzalloc\|alloc_skb\|memcpy" "net/tquic/fec/fec_decoder.c"`
  - Fix: Add strict validation and bounds checks at parse boundaries, enforce lifetime/ownership rules, and fail closed on malformed input. Risk: Fixes in pars

- [ ] **CF-279** -- Migration State Stores Raw Path Pointers Without Reference Counting
  - Severity: S1 | Sources: B | Priority: 4.9
  - Evidence: file:1, sym:5, snippet:1
  - Missing: Exact line range(s) where the fault manifests; Kernel log / stack trace / error output demonstrating the issue
  - Verify: `rg -n "tquic_migration_state" "net/tquic/tquic_migration.c"`
  - Fix: Add strict validation and bounds checks at parse boundaries, enforce lifetime/ownership rules, and fail closed on malformed input. Risk: Fixes in pars

- [ ] **CF-280** -- Missing Address Family Validation in `tquic_path_create()`
  - Severity: S1 | Sources: B | Priority: 4.9
  - Evidence: file:1, sym:4, snippet:1
  - Missing: Exact line range(s) where the fault manifests; Kernel log / stack trace / error output demonstrating the issue
  - Verify: `rg -n "sockaddr_in6" "net/tquic/tquic_migration.c"`
  - Fix: Add strict validation and bounds checks at parse boundaries, enforce lifetime/ownership rules, and fail closed on malformed input. Risk: Fixes in pars

- [ ] **CF-301** -- UAF-P1-03: - conn->sk dereference in congestion control without locking
  - Severity: S1 | Sources: B | Priority: 4.9
  - Evidence: file:1, sym:2, snippet:1
  - Missing: Exact line range(s) where the fault manifests; Kernel log / stack trace / error output demonstrating the issue
  - Verify: `rg -n "sock_net" "net/tquic/cong/tquic_cong.c"`
  - Fix: Add strict validation and bounds checks at parse boundaries, enforce lifetime/ownership rules, and fail closed on malformed input. Risk: Fixes in pars

- [ ] **CF-302** -- UAF-P4-01: - tquic_zc_entry uses atomic_t instead of refcount_t
  - Severity: S1 | Sources: B | Priority: 4.9
  - Evidence: file:1, sym:5, snippet:1
  - Missing: Exact line range(s) where the fault manifests; Kernel log / stack trace / error output demonstrating the issue
  - Verify: `rg -n "refcount_set" "net/tquic/tquic_zerocopy.c"`
  - Fix: Add strict validation and bounds checks at parse boundaries, enforce lifetime/ownership rules, and fail closed on malformed input. Risk: Fixes in pars

- [ ] **CF-303** -- UAF-P4-02: - Paths lack reference counting entirely
  - Severity: S1 | Sources: B | Priority: 4.9
  - Evidence: file:1, sym:3, snippet:1
  - Missing: Exact line range(s) where the fault manifests; Kernel log / stack trace / error output demonstrating the issue
  - Verify: `rg -n "tquic_path" "net/tquic/tquic_migration.c"`
  - Fix: Add strict validation and bounds checks at parse boundaries, enforce lifetime/ownership rules, and fail closed on malformed input. Risk: Fixes in pars

- [ ] **CF-306** -- Unvalidated `addr_len` Passed to `memcpy` in `tquic_connect()`
  - Severity: S1 | Sources: B | Priority: 4.9
  - Evidence: file:1, sym:4, snippet:1
  - Missing: Exact line range(s) where the fault manifests; Kernel log / stack trace / error output demonstrating the issue
  - Verify: `rg -n "tquic_connect" "net/tquic/tquic_socket.c"`
  - Fix: Add strict validation and bounds checks at parse boundaries, enforce lifetime/ownership rules, and fail closed on malformed input. Risk: Fixes in pars

#### Security (15)

- [ ] **CF-164** -- `tquic_hs_process_encrypted_extensions` -- ALPN validation insufficient
  - Severity: S1 | Sources: B,C | Priority: 7.0
  - Evidence: file:1, sym:1, snippet:3
  - Missing: Exact line range(s) where the fault manifests; Kernel log / stack trace / error output demonstrating the issue
  - Verify: `rg -n "tquic_hs_process_encrypted_extensions" "net/tquic/crypto/handshake.c"`
  - Fix: ```c if (ext_data_len >= 3 && proto_len > 0 && 3 + proto_len <= ext_data_len) { ```  --- Risk: Fixes in parser/crypto/lifetime code may alter packet a

- [ ] **CF-185** -- EKU Semantic Mismatch: get_current_keys Returns Key, Not Secret
  - Severity: S1 | Sources: B,C | Priority: 7.0
  - Evidence: file:1, sym:2, snippet:2
  - Missing: Exact line range(s) where the fault manifests; Kernel log / stack trace / error output demonstrating the issue
  - Verify: `rg -n "tquic_key_update_get_current_keys" "net/tquic/crypto/extended_key_update.c"`
  - Fix: Add and use a function to retrieve the current traffic secret (not the derived key) from `tquic_key_update_state`. Derive `secret_len` from the cipher

- [ ] **CF-196** -- HIGH: Kernel address stored as u64 in buffer ring entries
  - Severity: S1 | Sources: A,B | Priority: 7.0
  - Evidence: file:2, sym:3, snippet:1
  - Missing: Exact line range(s) where the fault manifests; Kernel log / stack trace / error output demonstrating the issue
  - Verify: `rg -n "userspace" "net/tquic/io_uring.c"`
  - Fix: Use buffer IDs (indices) rather than raw kernel addresses. Store the base address separately in a kernel-only structure and compute the buffer address

- [ ] **CF-203** -- Load Balancer Has No Privilege Checks
  - Severity: S1 | Sources: B,C | Priority: 7.0
  - Evidence: file:1, sym:1
  - Missing: Exact line range(s) where the fault manifests; Code snippet proving the vulnerable pattern
  - Verify: `rg -n "quic_lb" "net/tquic/lb/quic_lb.c"`
  - Fix: All LB configuration interfaces should require `CAP_NET_ADMIN`.  --- Risk: Fixes in parser/crypto/lifetime code may alter packet acceptance logic. Wat

- [ ] **CF-210** -- Packet Forwarding Has No Privilege Checks
  - Severity: S1 | Sources: B,C | Priority: 7.0
  - Evidence: file:1, sym:1
  - Missing: Exact line range(s) where the fault manifests; Code snippet proving the vulnerable pattern
  - Verify: `rg -n "tquic_forward" "net/tquic/tquic_forward.c"`
  - Fix: Require `CAP_NET_ADMIN` to enable packet forwarding.  --- Risk: Fixes in parser/crypto/lifetime code may alter packet acceptance logic. Watch for inte

- [ ] **CF-224** -- RSA Signature Algorithm Hardcoded to SHA-256 Regardless of Certificate
  - Severity: S1 | Sources: B,C | Priority: 7.0
  - Evidence: file:1, snippet:1
  - Missing: Exact line range(s) where the fault manifests; Function/struct symbol name at the fault site
  - Verify: `make M=net/tquic W=1`
  - Fix: Construct the algorithm name dynamically from `cert->signature.hash_algo`, e.g., `"pkcs1pad(rsa,sha384)"` or `"pkcs1pad(rsa,sha512)"`.  --- Risk: Fixe

- [ ] **CF-230** -- TPROXY Capability Check Logic Inversion
  - Severity: S1 | Sources: B,C | Priority: 7.0
  - Evidence: file:1, sym:4, snippet:2
  - Missing: Exact line range(s) where the fault manifests; Kernel log / stack trace / error output demonstrating the issue
  - Verify: `rg -n "tquic_tunnel" "net/tquic/tquic_tunnel.c"`
  - Fix: Check `capable(CAP_NET_ADMIN)` first. If the caller lacks the capability, return `-EPERM` immediately rather than silently degrading. Risk: Fixes in p

- [ ] **CF-239** -- Weak CID Hash Function Enables Hash Flooding
  - Severity: S1 | Sources: B,C | Priority: 7.0
  - Evidence: file:1, sym:3, snippet:1
  - Missing: Exact line range(s) where the fault manifests; Kernel log / stack trace / error output demonstrating the issue
  - Verify: `rg -n "quic_proxy" "net/tquic/masque/quic_proxy.c"`
  - Fix: Use `jhash()` or `siphash()` with a per-proxy random key initialized at proxy creation time. SipHash is specifically designed to be resistant to hash-

- [ ] **CF-243** -- ACK Range Processing Without Semantic Validation
  - Severity: S1 | Sources: B | Priority: 7.0
  - Evidence: file:1, sym:4, lines:4, snippet:2
  - Missing: Kernel log / stack trace / error output demonstrating the issue; Independent confirmation from a second audit source
  - Verify: `rg -n "tquic_input" "net/quic/tquic/tquic_input.c"`
  - Fix: Limit ACK frames per packet to 1 (which RFC 9000 already expects) Risk: Fixes in parser/crypto/lifetime code may alter packet acceptance logic. Watch 

- [ ] **CF-247** -- Multipath Frame Processing Lacks Encryption Level Validation
  - Severity: S1 | Sources: B | Priority: 7.0
  - Evidence: file:1, sym:1, lines:1, snippet:1
  - Missing: Kernel log / stack trace / error output demonstrating the issue; Independent confirmation from a second audit source
  - Verify: `rg -n "tquic_process_mp_new_connection_id_frame" "net/tquic/tquic_input.c"`
  - Fix: Add encryption level checks for all multipath frame types. They should only be accepted in 1-RTT packets (and possibly 0-RTT): ```c } else if (frame_t

- [ ] **CF-250** -- Route Lookup Fallback to init_net
  - Severity: S1 | Sources: B | Priority: 7.0
  - Evidence: file:1, sym:1, lines:2, snippet:2
  - Missing: Kernel log / stack trace / error output demonstrating the issue; Independent confirmation from a second audit source
  - Verify: `rg -n "tquic_output" "net/tquic/tquic_output.c"`
  - Fix: Add strict validation and bounds checks at parse boundaries, enforce lifetime/ownership rules, and fail closed on malformed input. Risk: Fixes in pars

- [ ] **CF-266** -- BPM Path Manager Falls Back to init_net
  - Severity: S1 | Sources: B | Priority: 4.9
  - Evidence: file:1, sym:1, snippet:1
  - Missing: Exact line range(s) where the fault manifests; Kernel log / stack trace / error output demonstrating the issue
  - Verify: `rg -n "tquic_bpm" "net/tquic/bond/tquic_bpm.c"`
  - Fix: Add strict validation and bounds checks at parse boundaries, enforce lifetime/ownership rules, and fail closed on malformed input. Risk: Fixes in pars

- [ ] **CF-267** -- CPU-5: All hash tables use `jhash` with a **fixed seed of 0**.
  - Severity: S1 | Sources: B | Priority: 4.9
  - Evidence: sym:1, lines:1, snippet:1
  - Missing: Concrete source file path (e.g., net/tquic/...); Kernel log / stack trace / error output demonstrating the issue
  - Verify: `rg -rn "tquic_nf" net/tquic/`
  - Fix: Use `siphash` with a per-boot random key (from `net_get_random_once`) instead of `jhash` with seed 0. This is the standard kernel approach since Linux

- [ ] **CF-283** -- No ACK Frame Frequency Limit Per Packet
  - Severity: S1 | Sources: B | Priority: 4.9
  - Evidence: file:1, sym:3, lines:4
  - Missing: Code snippet proving the vulnerable pattern; Kernel log / stack trace / error output demonstrating the issue
  - Verify: `rg -n "tquic_process_frames" "net/quic/tquic/tquic_input.c"`
  - Fix: Add strict validation and bounds checks at parse boundaries, enforce lifetime/ownership rules, and fail closed on malformed input. Risk: Fixes in pars

- [ ] **CF-292** -- Stateless Reset Falls Back to init_net
  - Severity: S1 | Sources: B | Priority: 4.9
  - Evidence: file:1, sym:1, snippet:1
  - Missing: Exact line range(s) where the fault manifests; Kernel log / stack trace / error output demonstrating the issue
  - Verify: `rg -n "tquic_stateless_reset" "net/tquic/tquic_stateless_reset.c"`
  - Fix: Add strict validation and bounds checks at parse boundaries, enforce lifetime/ownership rules, and fail closed on malformed input. Risk: Fixes in pars

#### Concurrency (31)

- [ ] **CF-158** -- `tquic_cid_pool_destroy()` Removes from rhashtable Under BH spinlock
  - Severity: S1 | Sources: B,C | Priority: 7.0
  - Evidence: file:1, sym:7, snippet:2
  - Missing: Exact line range(s) where the fault manifests; Kernel log / stack trace / error output demonstrating the issue
  - Verify: `rg -n "kfree_rcu" "net/tquic/tquic_cid.c"`
  - Fix: Establish one synchronization model for this code path and make all state transitions/lookup paths follow it consistently. Risk: Locking/ordering chan

- [ ] **CF-168** -- `tquic_recvmsg()` Same Issue as HIGH-07
  - Severity: S1 | Sources: B,C | Priority: 7.0
  - Evidence: file:1, sym:2
  - Missing: Exact line range(s) where the fault manifests; Code snippet proving the vulnerable pattern
  - Verify: `rg -n "tquic_recvmsg" "net/tquic/tquic_socket.c"`
  - Fix: Establish one synchronization model for this code path and make all state transitions/lookup paths follow it consistently. Risk: Locking/ordering chan

- [ ] **CF-186** -- FEC decoder recovery -- partial recovery leaks on kzalloc failure
  - Severity: S1 | Sources: B,C | Priority: 7.0
  - Evidence: file:1, snippet:1
  - Missing: Exact line range(s) where the fault manifests; Function/struct symbol name at the fault site
  - Verify: `make M=net/tquic W=1`
  - Fix: Establish one synchronization model for this code path and make all state transitions/lookup paths follow it consistently. Risk: Locking/ordering chan

- [ ] **CF-187** -- FEC encoder repair symbol generation -- partial resource leak on kzalloc failure
  - Severity: S1 | Sources: B,C | Priority: 7.0
  - Evidence: file:1, snippet:1
  - Missing: Exact line range(s) where the fault manifests; Function/struct symbol name at the fault site
  - Verify: `make M=net/tquic W=1`
  - Fix: After the loop, iterate remaining entries and free any `repair_bufs[i]` that were not successfully adopted by a `repair_sym`.  --- Risk: Locking/order

- [ ] **CF-188** -- FEC Repair Count Computation: `block_size * target_fec_rate` Truncation
  - Severity: S1 | Sources: B,C | Priority: 7.0
  - Evidence: file:1, snippet:1
  - Missing: Exact line range(s) where the fault manifests; Function/struct symbol name at the fault site
  - Verify: `make M=net/tquic W=1`
  - Fix: Validate `target_fec_rate <= 100` before this calculation.  --- Risk: Locking/ordering changes can cause deadlocks or throughput regressions if not va

- [ ] **CF-194** -- HIGH: atomic64_inc_return for packet number on every TX
  - Severity: S1 | Sources: A,B | Priority: 7.0
  - Evidence: file:2, sym:3, snippet:1
  - Missing: Exact line range(s) where the fault manifests; Kernel log / stack trace / error output demonstrating the issue
  - Verify: `rg -n "atomic64_inc_return" "net/tquic/tquic_output.c"`
  - Fix: If the TX path is always serialized by `conn->lock`, replace with a plain `u64` increment. If not always locked, document which paths require the atom

- [ ] **CF-197** -- HIGH: kmalloc(path->mtu) per datagram send
  - Severity: S1 | Sources: A,B | Priority: 7.0
  - Evidence: file:2, sym:6, snippet:1
  - Missing: Exact line range(s) where the fault manifests; Kernel log / stack trace / error output demonstrating the issue
  - Verify: `rg -n "buffer" "net/tquic/tquic_output.c"`
  - Fix: Use a per-connection pre-allocated scratch buffer (protected by `conn->lock` which is already held in the send path), or use a stack allocation since 

- [ ] **CF-198** -- http3_stream.c Uses spin_lock Without _bh
  - Severity: S1 | Sources: B,C | Priority: 7.0
  - Evidence: file:1, sym:1
  - Missing: Exact line range(s) where the fault manifests; Code snippet proving the vulnerable pattern
  - Verify: `rg -n "spin_lock" "net/quic/tquic/http3/http3_stream.c"`
  - Fix: Use `spin_lock_bh` consistently. Risk: Locking/ordering changes can cause deadlocks or throughput regressions if not validated under stress and teardo

- [ ] **CF-199** -- Incomplete SSRF Protection in TCP-over-QUIC Tunnel
  - Severity: S1 | Sources: B,C | Priority: 7.0
  - Evidence: file:1, sym:6, snippet:1
  - Missing: Exact line range(s) where the fault manifests; Kernel log / stack trace / error output demonstrating the issue
  - Verify: `rg -n "ipv6_addr_v4mapped" "net/tquic/tquic_tunnel.c"`
  - Fix: Add checks for all private ranges. Use `ipv4_is_private_10()`, `ipv4_is_private_172()`, `ipv4_is_private_192()` (or the unified `ipv4_is_private()` if

- [ ] **CF-215** -- qlog TOCTOU Race Between Length Check and copy_to_user
  - Severity: S1 | Sources: B,C | Priority: 7.0
  - Evidence: file:1, snippet:1
  - Missing: Exact line range(s) where the fault manifests; Function/struct symbol name at the fault site
  - Verify: `make M=net/tquic W=1`
  - Fix: Establish one synchronization model for this code path and make all state transitions/lookup paths follow it consistently. Risk: Locking/ordering chan

- [ ] **CF-216** -- Race Condition in Idle Timer Connection Processing
  - Severity: S1 | Sources: B,C | Priority: 7.0
  - Evidence: file:1, sym:3, snippet:2
  - Missing: Exact line range(s) where the fault manifests; Kernel log / stack trace / error output demonstrating the issue
  - Verify: `rg -n "proxied_conn_put" "net/tquic/masque/quic_proxy.c"`
  - Fix: Hold a reference count on each connection while it is in the `to_remove` list (which appears to be partially done via `proxied_conn_put`). Ensure CID 

- [ ] **CF-222** -- Retry Token AEAD Key Set Under Non-IRQ-Safe Spinlock
  - Severity: S1 | Sources: B,C | Priority: 7.0
  - Evidence: file:1, snippet:1
  - Missing: Exact line range(s) where the fault manifests; Function/struct symbol name at the fault site
  - Verify: `make M=net/tquic W=1`
  - Fix: Use a mutex instead of a spinlock, or use `spin_lock_bh`. Better yet, allocate a per-connection AEAD instance to avoid global locking entirely.  --- R

- [ ] **CF-223** -- Return Pointer to Stack/Lock-Protected Data in tquic_conn_get_active_cid
  - Severity: S1 | Sources: B,C | Priority: 7.0
  - Evidence: file:1, sym:3, snippet:2
  - Missing: Exact line range(s) where the fault manifests; Kernel log / stack trace / error output demonstrating the issue
  - Verify: `rg -n "tquic_cid" "net/tquic/core/connection.c"`
  - Fix: Copy the CID data into a caller-provided buffer while holding the lock, rather than returning a pointer to shared data.  --- Risk: Locking/ordering ch

- [ ] **CF-227** -- smartnic.c Uses spin_lock Without _bh
  - Severity: S1 | Sources: B,C | Priority: 7.0
  - Evidence: file:1, sym:1
  - Missing: Exact line range(s) where the fault manifests; Code snippet proving the vulnerable pattern
  - Verify: `rg -n "spin_lock" "net/quic/tquic/offload/smartnic.c"`
  - Fix: Audit all call sites. If any are reachable from softirq context, change to `spin_lock_bh`. Risk: Locking/ordering changes can cause deadlocks or throu

- [ ] **CF-228** -- struct tquic_napi mixes hot and cold fields
  - Severity: S1 | Sources: A,B | Priority: 7.0
  - Evidence: file:2, sym:10, lines:1
  - Missing: Code snippet proving the vulnerable pattern; Kernel log / stack trace / error output demonstrating the issue
  - Verify: `rg -n "cpus" "net/tquic/napi.h"`
  - Fix: Add `____cacheline_aligned_in_smp` between the RX-side fields (`rx_queue`, `rx_queue_len`, `lock`) and the poll-side fields (`stats`, `coalesce`) to s

- [ ] **CF-232** -- tquic_stream_count_by_type O(n) Scan for Critical Stream Enforcement
  - Severity: S1 | Sources: B,C | Priority: 7.0
  - Evidence: file:1, sym:2
  - Missing: Exact line range(s) where the fault manifests; Code snippet proving the vulnerable pattern
  - Verify: `rg -n "tquic_stream_count_by_type" "net/quic/tquic/tquic_stream.c"`
  - Fix: Maintain per-type counters in the connection structure, incrementing/decrementing on stream creation/destruction. Risk: Locking/ordering changes can c

- [ ] **CF-234** -- tquic_stream_send_allowed Missing Underflow Check
  - Severity: S1 | Sources: B,C | Priority: 7.0
  - Evidence: file:1, sym:1, snippet:2
  - Missing: Exact line range(s) where the fault manifests; Kernel log / stack trace / error output demonstrating the issue
  - Verify: `rg -n "tquic_stream_send_allowed" "net/quic/tquic/core/stream.c"`
  - Fix: Add underflow guards: ```c if (stream->send_offset >= stream->max_send_data) { blocked; return 0; } stream_limit = stream->max_send_data - stream->sen

- [ ] **CF-248** -- Race Condition on path->last_activity
  - Severity: S1 | Sources: B | Priority: 7.0
  - Evidence: file:1, sym:3, lines:3, snippet:1
  - Missing: Kernel log / stack trace / error output demonstrating the issue; Independent confirmation from a second audit source
  - Verify: `rg -n "tquic_process_packet" "net/quic/tquic/tquic_input.c"`
  - Fix: Establish one synchronization model for this code path and make all state transitions/lookup paths follow it consistently. Risk: Locking/ordering chan

- [ ] **CF-257** -- Unlocked Connection Access in IOCTL
  - Severity: S1 | Sources: B | Priority: 7.0
  - Evidence: file:1, sym:4, lines:2, snippet:1
  - Missing: Kernel log / stack trace / error output demonstrating the issue; Independent confirmation from a second audit source
  - Verify: `rg -n "socket" "net/tquic/tquic_socket.c"`
  - Fix: Establish one synchronization model for this code path and make all state transitions/lookup paths follow it consistently. Risk: Locking/ordering chan

- [ ] **CF-262** -- `tquic_nl_cmd_path_remove()` Double Put on Path
  - Severity: S1 | Sources: B | Priority: 4.9
  - Evidence: file:1, sym:8, snippet:1
  - Missing: Exact line range(s) where the fault manifests; Kernel log / stack trace / error output demonstrating the issue
  - Verify: `rg -n "kfree_rcu" "net/tquic/tquic_netlink.c"`
  - Fix: Establish one synchronization model for this code path and make all state transitions/lookup paths follow it consistently. Risk: Locking/ordering chan

- [ ] **CF-265** -- Bonding State Machine Missing Lock on State Transition Checks
  - Severity: S1 | Sources: B | Priority: 4.9
  - Evidence: file:1, sym:4, snippet:1
  - Missing: Exact line range(s) where the fault manifests; Kernel log / stack trace / error output demonstrating the issue
  - Verify: `rg -n "tquic_bonding_ctx" "net/tquic/bond/tquic_bonding.c"`
  - Fix: Establish one synchronization model for this code path and make all state transitions/lookup paths follow it consistently. Risk: Locking/ordering chan

- [ ] **CF-268** -- Double `tquic_nl_path_put()` in `tquic_path_remove_and_free()` Assumes refcnt==2
  - Severity: S1 | Sources: B | Priority: 4.9
  - Evidence: file:1, sym:8, snippet:1
  - Missing: Exact line range(s) where the fault manifests; Kernel log / stack trace / error output demonstrating the issue
  - Verify: `rg -n "tquic_path_remove_and_free" "net/tquic/tquic_netlink.c"`
  - Fix: Establish one synchronization model for this code path and make all state transitions/lookup paths follow it consistently. Risk: Locking/ordering chan

- [ ] **CF-272** -- Global Congestion Data Cache Without Namespace Isolation
  - Severity: S1 | Sources: B | Priority: 4.9
  - Evidence: file:1, sym:2, snippet:1
  - Missing: Exact line range(s) where the fault manifests; Kernel log / stack trace / error output demonstrating the issue
  - Verify: `rg -n "tquic_cong_data_cache" "net/tquic/cong/cong_data.c"`
  - Fix: Establish one synchronization model for this code path and make all state transitions/lookup paths follow it consistently. Risk: Locking/ordering chan

- [ ] **CF-274** -- h3_stream_lookup_by_push_id Linear Scan Under Lock
  - Severity: S1 | Sources: B | Priority: 4.9
  - Evidence: file:1, sym:2, snippet:1
  - Missing: Exact line range(s) where the fault manifests; Kernel log / stack trace / error output demonstrating the issue
  - Verify: `rg -n "h3_stream" "net/quic/tquic/http3/http3_request.c"`
  - Fix: Establish one synchronization model for this code path and make all state transitions/lookup paths follow it consistently. Risk: Locking/ordering chan

- [ ] **CF-276** -- Hysteresis Counters Use Non-Atomic READ_ONCE/WRITE_ONCE Without Lock
  - Severity: S1 | Sources: B | Priority: 4.9
  - Evidence: file:1, sym:3, snippet:1
  - Missing: Exact line range(s) where the fault manifests; Kernel log / stack trace / error output demonstrating the issue
  - Verify: `rg -n "tquic_failover_timeout_work" "net/tquic/bond/tquic_failover.c"`
  - Fix: Establish one synchronization model for this code path and make all state transitions/lookup paths follow it consistently. Risk: Locking/ordering chan

- [ ] **CF-285** -- Path Validation Timeout Accesses Path State Without Lock After Unlock
  - Severity: S1 | Sources: B | Priority: 4.9
  - Evidence: file:1, sym:1, snippet:1
  - Missing: Exact line range(s) where the fault manifests; Kernel log / stack trace / error output demonstrating the issue
  - Verify: `rg -n "tquic_path_handle_response" "net/tquic/pm/path_validation.c"`
  - Fix: Establish one synchronization model for this code path and make all state transitions/lookup paths follow it consistently. Risk: Locking/ordering chan

- [ ] **CF-289** -- sched/scheduler.c rr_select TOCTOU on num_paths
  - Severity: S1 | Sources: B | Priority: 4.9
  - Evidence: file:1, snippet:1
  - Missing: Exact line range(s) where the fault manifests; Function/struct symbol name at the fault site
  - Verify: `make M=net/tquic W=1`
  - Fix: Establish one synchronization model for this code path and make all state transitions/lookup paths follow it consistently. Risk: Locking/ordering chan

- [ ] **CF-294** -- TOCTOU Race in Bonding State Transition
  - Severity: S1 | Sources: B | Priority: 4.9
  - Evidence: file:1, sym:2, snippet:1
  - Missing: Exact line range(s) where the fault manifests; Kernel log / stack trace / error output demonstrating the issue
  - Verify: `rg -n "tquic_bonding_update_state" "net/tquic/bond/tquic_bonding.c"`
  - Fix: Establish one synchronization model for this code path and make all state transitions/lookup paths follow it consistently. Risk: Locking/ordering chan

- [ ] **CF-297** -- tquic_stream_check_flow_control TOCTOU with sendmsg
  - Severity: S1 | Sources: B | Priority: 4.9
  - Evidence: file:1, sym:2, lines:2
  - Missing: Code snippet proving the vulnerable pattern; Kernel log / stack trace / error output demonstrating the issue
  - Verify: `rg -n "tquic_stream_check_flow_control" "net/quic/tquic/tquic_stream.c"`
  - Fix: Establish one synchronization model for this code path and make all state transitions/lookup paths follow it consistently. Risk: Locking/ordering chan

- [ ] **CF-298** -- tquic_stream_ext Uses GFP_ATOMIC for Large Allocation
  - Severity: S1 | Sources: B | Priority: 4.9
  - Evidence: file:1, sym:1, snippet:1
  - Missing: Exact line range(s) where the fault manifests; Kernel log / stack trace / error output demonstrating the issue
  - Verify: `rg -n "tquic_stream_ext" "net/quic/tquic/core/stream.c"`
  - Fix: Establish one synchronization model for this code path and make all state transitions/lookup paths follow it consistently. Risk: Locking/ordering chan

- [ ] **CF-305** -- Unprotected Global Loss Tracker Array
  - Severity: S1 | Sources: B | Priority: 4.9
  - Evidence: file:1, sym:2, snippet:1
  - Missing: Exact line range(s) where the fault manifests; Kernel log / stack trace / error output demonstrating the issue
  - Verify: `rg -n "tquic_loss_tracker" "net/tquic/cong/tquic_cong.c"`
  - Fix: Establish one synchronization model for this code path and make all state transitions/lookup paths follow it consistently. Risk: Locking/ordering chan

#### Correctness (23)

- [ ] **CF-159** -- `tquic_conn_retire_cid()` Does Not Remove CID from Lookup Hash Table
  - Severity: S1 | Sources: B,C | Priority: 7.0
  - Evidence: file:1, sym:2
  - Missing: Exact line range(s) where the fault manifests; Code snippet proving the vulnerable pattern
  - Verify: `rg -n "tquic_conn_retire_cid" "net/tquic/core/connection.c"`
  - Fix: Call `rhashtable_remove_fast()` when retiring a local CID. Risk: Protocol correctness fixes can shift timing/state-machine behavior; verify against in

- [ ] **CF-167** -- `tquic_hs_setup_psk` -- integer overflow in ticket age calculation
  - Severity: S1 | Sources: B,C | Priority: 7.0
  - Evidence: file:1, sym:1, snippet:1
  - Missing: Exact line range(s) where the fault manifests; Kernel log / stack trace / error output demonstrating the issue
  - Verify: `rg -n "tquic_hs_setup_psk" "net/tquic/crypto/handshake.c"`
  - Fix: Use `u64` for `age` and validate the time difference before multiplication. Also validate `lifetime` against RFC 8446 maximum of 604800 (7 days).  ---

- [ ] **CF-170** -- Anti-Amplification Integer Overflow
  - Severity: S1 | Sources: B,C | Priority: 7.0
  - Evidence: file:1, snippet:1
  - Missing: Exact line range(s) where the fault manifests; Function/struct symbol name at the fault site
  - Verify: `make M=net/tquic W=1`
  - Fix: Use `check_add_overflow` and `check_mul_overflow` for safe arithmetic.  --- Risk: Protocol correctness fixes can shift timing/state-machine behavior; 

- [ ] **CF-172** -- BBRv2 Inflight Calculation Truncation
  - Severity: S1 | Sources: B,C | Priority: 7.0
  - Evidence: file:1, snippet:2
  - Missing: Exact line range(s) where the fault manifests; Function/struct symbol name at the fault site
  - Verify: `make M=net/tquic W=1`
  - Fix: Return `u64` or `u32` with saturation: ```c return (u32)min_t(u64, inflight, U32_MAX); ```  --- Risk: Protocol correctness fixes can shift timing/stat

- [ ] **CF-176** -- Coalesced Packet Splitting Assumes v1 Packet Type Encoding
  - Severity: S1 | Sources: B,C | Priority: 7.0
  - Evidence: file:1, sym:1, snippet:2
  - Missing: Exact line range(s) where the fault manifests; Kernel log / stack trace / error output demonstrating the issue
  - Verify: `rg -n "tquic_decode_packet_type" "net/tquic/core/packet.c"`
  - Fix: Read the version field (bytes 1-4) and use `tquic_decode_packet_type()` for version-aware type detection.  --- Risk: Protocol correctness fixes can sh

- [ ] **CF-189** -- FEC Scheduler Loss Rate Overflow
  - Severity: S1 | Sources: B,C | Priority: 7.0
  - Evidence: file:1, snippet:2
  - Missing: Exact line range(s) where the fault manifests; Function/struct symbol name at the fault site
  - Verify: `make M=net/tquic W=1`
  - Fix: ```c new_rate = (u32)((u64)sched->loss_count * 1000 Risk: Protocol correctness fixes can shift timing/state-machine behavior; verify against interop t

- [ ] **CF-193** -- h3_control_recv_frame Does Not Parse Frame Payloads
  - Severity: S1 | Sources: B,C | Priority: 7.0
  - Evidence: file:1, sym:1, snippet:1
  - Missing: Exact line range(s) where the fault manifests; Kernel log / stack trace / error output demonstrating the issue
  - Verify: `rg -n "h3_control_recv_frame" "net/quic/tquic/http3/http3_request.c"`
  - Fix: Implement actual parsing and processing for each frame type in this handler.  --- Risk: Protocol correctness fixes can shift timing/state-machine beha

- [ ] **CF-207** -- Missing Validation of `first_ack_range` Against `largest_ack`
  - Severity: S1 | Sources: B,C | Priority: 7.0
  - Evidence: file:2, sym:1, lines:1
  - Missing: Code snippet proving the vulnerable pattern; Kernel log / stack trace / error output demonstrating the issue
  - Verify: `rg -n "tquic_input" "net/tquic/core/frame.c"`
  - Fix: Add validation: `if (first_ack_range > largest_ack) return -EPROTO;` Risk: Protocol correctness fixes can shift timing/state-machine behavior; verify 

- [ ] **CF-208** -- Missing Validation of `TQUIC_MIGRATE` sockopt Address
  - Severity: S1 | Sources: B,C | Priority: 7.0
  - Evidence: file:1, sym:5, snippet:2
  - Missing: Exact line range(s) where the fault manifests; Kernel log / stack trace / error output demonstrating the issue
  - Verify: `rg -n "tquic_path_find_by_addr" "net/tquic/tquic_socket.c"`
  - Fix: Fix the protocol logic per the relevant RFC section; add an interop regression test covering the corrected state transition.

- [ ] **CF-212** -- Prague Congestion Control: `ecn_ce_count * mss` Overflow
  - Severity: S1 | Sources: B,C | Priority: 7.0
  - Evidence: file:1, snippet:2
  - Missing: Exact line range(s) where the fault manifests; Function/struct symbol name at the fault site
  - Verify: `make M=net/tquic W=1`
  - Fix: Clamp `ecn_ce_count` to a reasonable maximum before multiplication: ```c ecn_ce_count = min_t(u64, ecn_ce_count, U32_MAX); ce_bytes = ecn_ce_count * m

- [ ] **CF-214** -- PTO Duration Exponential Shift Overflow
  - Severity: S1 | Sources: B,C | Priority: 7.0
  - Evidence: file:1, sym:1, snippet:2
  - Missing: Exact line range(s) where the fault manifests; Kernel log / stack trace / error output demonstrating the issue
  - Verify: `rg -n "tquic_timer" "net/quic/tquic/tquic_timer.c"`
  - Fix: ```c u32 shift = min_t(u32, rs->pto_count, 30); pto_duration *= (1ULL << shift); ```  --- Risk: Protocol correctness fixes can shift timing/state-mach

- [ ] **CF-238** -- Version Negotiation Packet Missing Randomized First Byte
  - Severity: S1 | Sources: B,C | Priority: 7.0
  - Evidence: file:1, sym:1
  - Missing: Exact line range(s) where the fault manifests; Code snippet proving the vulnerable pattern
  - Verify: `rg -n "tquic_input" "net/tquic/core/connection.c"`
  - Fix: Use `get_random_bytes(&first_byte, 1); first_byte |= 0x80;` similar to the function in `tquic_input.c:523`. Risk: Protocol correctness fixes can shift

- [ ] **CF-241** -- `tquic_connect()` Stores Error in `sk->sk_err` as Positive Value Wrongly
  - Severity: S1 | Sources: B | Priority: 7.0
  - Evidence: file:1, sym:2, lines:1, snippet:1
  - Missing: Kernel log / stack trace / error output demonstrating the issue; Independent confirmation from a second audit source
  - Verify: `rg -n "tquic_connect" "net/tquic/tquic_socket.c"`
  - Fix: Fix the protocol logic per the relevant RFC section; add an interop regression test covering the corrected state transition.

- [ ] **CF-242** -- ACK Frame bytes_acked Calculation Can Overflow
  - Severity: S1 | Sources: B | Priority: 7.0
  - Evidence: file:1, sym:1, lines:1, snippet:1
  - Missing: Kernel log / stack trace / error output demonstrating the issue; Independent confirmation from a second audit source
  - Verify: `rg -n "tquic_cong_on_ack" "net/tquic/tquic_input.c"`
  - Fix: Cap `first_ack_range` to a reasonable value (e.g., the maximum number of packets in flight) before the multiplication. Alternatively, cap `bytes_acked

- [ ] **CF-249** -- Retire Prior To Not Validated Against Sequence Number
  - Severity: S1 | Sources: B | Priority: 7.0
  - Evidence: file:1, sym:5, lines:7, snippet:1
  - Missing: Kernel log / stack trace / error output demonstrating the issue; Independent confirmation from a second audit source
  - Verify: `rg -n "tquic_process_retire_connection_id_frame" "net/quic/tquic/tquic_input.c"`
  - Fix: Fix the protocol logic per the relevant RFC section; add an interop regression test covering the corrected state transition.

- [ ] **CF-251** -- tquic_output_packet Passes NULL conn to ip_local_out
  - Severity: S1 | Sources: B | Priority: 7.0
  - Evidence: file:1, sym:2, lines:5, snippet:2
  - Missing: Kernel log / stack trace / error output demonstrating the issue; Independent confirmation from a second audit source
  - Verify: `rg -n "tquic_output_packet" "net/tquic/tquic_output.c"`
  - Fix: Store a reference to `conn` in `tquic_pacing_state` and pass it through. Risk: Protocol correctness fixes can shift timing/state-machine behavior; ver

- [ ] **CF-269** -- Expensive Operation in Loss Path
  - Severity: S1 | Sources: B | Priority: 4.9
  - Evidence: file:1, sym:2, snippet:1
  - Missing: Exact line range(s) where the fault manifests; Kernel log / stack trace / error output demonstrating the issue
  - Verify: `rg -n "tquic_bonding_on_loss_detected" "net/tquic/bond/tquic_bonding.c"`
  - Fix: Fix the protocol logic per the relevant RFC section; add an interop regression test covering the corrected state transition.

- [ ] **CF-270** -- Failover Retransmit Queue Can Exceed Memory Limits
  - Severity: S1 | Sources: B | Priority: 4.9
  - Evidence: file:1, sym:1, snippet:1
  - Missing: Exact line range(s) where the fault manifests; Kernel log / stack trace / error output demonstrating the issue
  - Verify: `rg -n "tquic_failover" "net/tquic/bond/tquic_failover.c"`
  - Fix: Fix the protocol logic per the relevant RFC section; add an interop regression test covering the corrected state transition.

- [ ] **CF-286** -- qpack_encoder known_received_count Overflow via Insert Count Increment
  - Severity: S1 | Sources: B | Priority: 4.9
  - Evidence: file:1, sym:1, snippet:1
  - Missing: Exact line range(s) where the fault manifests; Kernel log / stack trace / error output demonstrating the issue
  - Verify: `rg -n "qpack_encoder" "net/quic/tquic/http3/qpack_encoder.c"`
  - Fix: Fix the protocol logic per the relevant RFC section; add an interop regression test covering the corrected state transition.

- [ ] **CF-287** -- Repair Frame Field Truncation Without Validation
  - Severity: S1 | Sources: B | Priority: 4.9
  - Evidence: file:1, sym:1, snippet:2
  - Missing: Exact line range(s) where the fault manifests; Kernel log / stack trace / error output demonstrating the issue
  - Verify: `rg -n "tquic_fec_decode_repair_frame" "net/tquic/fec/fec_decoder.c"`
  - Fix: Fix the protocol logic per the relevant RFC section; add an interop regression test covering the corrected state transition.

- [ ] **CF-295** -- TQUIC_MAX_PATHS Mismatch
  - Severity: S1 | Sources: B | Priority: 4.9
  - Evidence: file:2, sym:2, lines:4
  - Missing: Code snippet proving the vulnerable pattern; Kernel log / stack trace / error output demonstrating the issue
  - Verify: `rg -n "tquic_sched" "net/tquic/multipath/tquic_scheduler.c"`
  - Fix: Fix the protocol logic per the relevant RFC section; add an interop regression test covering the corrected state transition.

- [ ] **CF-299** -- tquic_udp_recv Processes Stateless Reset Before Authenticating Packet
  - Severity: S1 | Sources: B | Priority: 4.9
  - Evidence: file:1, sym:1, lines:1
  - Missing: Code snippet proving the vulnerable pattern; Kernel log / stack trace / error output demonstrating the issue
  - Verify: `rg -n "tquic_udp_recv" "net/tquic/tquic_input.c"`
  - Fix: Only check for stateless reset AFTER regular decryption fails (RFC 9000 Section 10.3.1 recommends this order). The check should be a last resort, not 

- [ ] **CF-307** -- Weight Accumulation Without Overflow Check
  - Severity: S1 | Sources: B | Priority: 4.9
  - Evidence: file:1, sym:2, snippet:1
  - Missing: Exact line range(s) where the fault manifests; Kernel log / stack trace / error output demonstrating the issue
  - Verify: `rg -n "tquic_select_weighted" "net/tquic/bond/bonding.c"`
  - Fix: Fix the protocol logic per the relevant RFC section; add an interop regression test covering the corrected state transition.

#### Api (3)

- [ ] **CF-182** -- copy_from_user with User-Controlled Size in Socket Options
  - Severity: S1 | Sources: B,C | Priority: 7.0
  - Evidence: file:1, sym:1, snippet:1
  - Missing: Exact line range(s) where the fault manifests; Kernel log / stack trace / error output demonstrating the issue
  - Verify: `rg -n "tquic_socket" "net/quic/tquic/tquic_socket.c"`
  - Fix: Apply minimal targeted fix; add regression test; verify with make M=net/tquic W=1 C=1 and lockdep/KASAN enabled.

- [ ] **CF-252** -- Type Shadowing Creates Memory Corruption Risk
  - Severity: S1 | Sources: B | Priority: 7.0
  - Evidence: file:1, sym:5, lines:1, snippet:1
  - Missing: Kernel log / stack trace / error output demonstrating the issue; Independent confirmation from a second audit source
  - Verify: `rg -n "tquic_mp_sched_notify_sent" "net/tquic/multipath/tquic_scheduler.c"`
  - Fix: Apply minimal targeted fix; add regression test; verify with make M=net/tquic W=1 C=1 and lockdep/KASAN enabled.

- [ ] **CF-284** -- Path Manager Uses init_net Instead of Per-Connection Net Namespace
  - Severity: S1 | Sources: B | Priority: 4.9
  - Evidence: file:1, sym:2, snippet:1
  - Missing: Exact line range(s) where the fault manifests; Kernel log / stack trace / error output demonstrating the issue
  - Verify: `rg -n "tquic_pm_discover_addresses" "net/tquic/pm/path_manager.c"`
  - Fix: Apply minimal targeted fix; add regression test; verify with make M=net/tquic W=1 C=1 and lockdep/KASAN enabled.

---

## Phase 5: CERTIFIED S2/S3 -- Medium/Low Confirmed (60 items)

#### Memory (9)

- [ ] **CF-316** -- Missing Bounds Check on tbs Pointer in Signature Parse
  - S2 | A,B,C | Evidence: file:1, sym:4

- [ ] **CF-318** -- Path Score Computation Can Overflow in Migration Target Selection
  - S2 | A,B,C | Evidence: file:1, sym:4, snippet:1

- [ ] **CF-323** -- QPACK Encoder/Decoder: Excessive Stack Usage
  - S2 | A,B,C | Evidence: file:2, sym:5

- [ ] **CF-325** -- QPACK Integer Decode: Shift Overflow
  - S2 | A,B,C | Evidence: file:1, sym:1

- [ ] **CF-348** -- `tquic_proc.c` Buffer Overflow in Hex CID Formatting
  - S2 | B,C | Evidence: file:1, sym:2, lines:3, snippet:2

- [ ] **CF-352** -- `transport_params.c` Memcpy with `count * sizeof(u32)` Without Overflow Check
  - S2 | B,C | Evidence: file:1, lines:1, snippet:1

- [ ] **CF-372** -- FEC encoder allocates per-symbol in GFP_ATOMIC
  - S2 | A,B | Evidence: file:2, lines:1, snippet:1

- [ ] **CF-438** -- Zerocopy entry refcount uses atomic_t
  - S2 | A,B | Evidence: file:2, sym:4, lines:1, snippet:1

- [ ] **CF-510** -- Netlink Family Exported as EXPORT_SYMBOL_GPL
  - S3 | A,B,C | Evidence: file:1, sym:2, snippet:1

#### Security (24)

- [ ] **CF-309** -- Bloom Filter False Negatives Allow Replay
  - S2 | A,B,C | Evidence: file:1, sym:2

- [ ] **CF-310** -- Decoy Packet Size Calculation Can Underflow
  - S2 | A,B,C | Evidence: file:1, sym:4, snippet:2

- [ ] **CF-312** -- HP Key Rotation Swaps Old Keys Without Zeroization
  - S2 | A,B,C | Evidence: file:1, sym:2, snippet:2

- [ ] **CF-313** -- HTTP/3 Connection: O(n) Push Entry Counting
  - S2 | A,B,C | Evidence: file:1, sym:1

- [ ] **CF-314** -- HTTP/3 Frame Parsing: 16MB Maximum Frame Payload
  - S2 | A,B,C | Evidence: file:1, sym:1

- [ ] **CF-319** -- Per-Call crypto_alloc_shash in Stateless Reset Token Generation
  - S2 | A,B,C | Evidence: file:1, sym:2

- [ ] **CF-320** -- QAT Encrypt Sets Key on Every Call
  - S2 | A,B,C | Evidence: file:1, sym:2

- [ ] **CF-324** -- QPACK Huffman Decoder: O(n*256) Complexity
  - S2 | A,B,C | Evidence: file:1, sym:1

- [ ] **CF-326** -- Time Parsing Does Not Validate Digit Characters
  - S2 | A,B,C | Evidence: file:1, sym:3

- [ ] **CF-327** -- Transcript Buffer Not Zeroized Before Free
  - S2 | A,B,C | Evidence: file:1, sym:4

- [ ] **CF-361** -- Certificate Chain Parsing Does Not Verify Issuer-Subject Linkage Before Trust Check
  - S2 | B,C | Evidence: file:1, lines:1, snippet:1

- [ ] **CF-383** -- Key Material Not Zeroized on All Error Paths in tquic_zero_rtt_derive_keys
  - S2 | B,C | Evidence: file:1, sym:1, lines:2, snippet:1

- [ ] **CF-421** -- Sysctl and Proc Entries Registered in init_net Only
  - S2 | B,C | Evidence: file:4, sym:2, lines:3, snippet:1

- [ ] **CF-502** -- Certificate Chain Length Limit Checked Late
  - S3 | A,B,C | Evidence: file:17, sym:11

- [ ] **CF-503** -- Duplicate MODULE_DESCRIPTION in quic_exfil.c
  - S3 | A,B,C | Evidence: file:1, sym:6, lines:1, snippet:1

- [ ] **CF-507** -- Load Balancer Stack Buffers for Feistel Not Zeroized on Error
  - S3 | A,B,C | Evidence: file:1, sym:3

- [ ] **CF-508** -- Module Parameters Expose Security Configuration
  - S3 | A,B,C | Evidence: file:1, sym:3

- [ ] **CF-511** -- Per-CPU Stats Not Protected Against Torn Reads on 32-bit
  - S3 | A,B,C | Evidence: file:1, sym:2

- [ ] **CF-512** -- Procfs trusted_cas File Writable Without Capability Check
  - S3 | A,B,C | Evidence: file:1, sym:4

- [ ] **CF-514** -- Unused HKDF-Expand Output in Extended Key Update
  - S3 | A,B,C | Evidence: file:1, sym:1

- [ ] **CF-515** -- Volatile Qualifiers in Constant-Time Functions May Be Insufficient
  - S3 | A,B,C | Evidence: file:1, sym:1, snippet:1

- [ ] **CF-538** -- crypto_wait_req May Sleep in Encrypt/Decrypt Hot Path
  - S3 | B,C | Evidence: file:1, lines:2, snippet:1

- [ ] **CF-551** -- Multipath Nonce Construction -- Potential Nonce Reuse Across Paths
  - S3 | B,C | Evidence: file:1, sym:3, lines:5, snippet:1

- [ ] **CF-553** -- Netlink Operations All Require GENL_ADMIN_PERM
  - S3 | B,C | Evidence: file:1, sym:2, lines:1, snippet:2

#### Concurrency (17)

- [ ] **CF-311** -- EKU Request ID Increment Outside Lock
  - S2 | A,B,C | Evidence: file:1, sym:1, lines:2

- [ ] **CF-315** -- HTTP/3 Settings Parser: TOCTOU on Settings Count
  - S2 | A,B,C | Evidence: file:1, sym:1

- [ ] **CF-321** -- Qlog Ring Buffer: Not Truly Lock-Free
  - S2 | A,B,C | Evidence: file:1, sym:1

- [ ] **CF-362** -- CID Sequence Number Rollback on rhashtable Insert Failure
  - S2 | B,C | Evidence: file:1, lines:1, snippet:1

- [ ] **CF-363** -- conn->streams_lock for RB-tree walk on every STREAM frame
  - S2 | A,B | Evidence: file:2, sym:4, lines:1, snippet:1

- [ ] **CF-367** -- Coupled Congestion Control Division by Zero
  - S2 | B,C | Evidence: file:1, lines:2, snippet:1

- [ ] **CF-370** -- Error Ring Uses Atomics Under Spinlock Unnecessarily
  - S2 | B,C | Evidence: file:1, sym:1, lines:1, snippet:1

- [ ] **CF-373** -- FEC encoder double lock nesting
  - S2 | A,B | Evidence: file:2, sym:4, lines:1, snippet:1

- [ ] **CF-374** -- FEC Encoder Triple-Nested Locking
  - S2 | B,C | Evidence: file:1, lines:1, snippet:2

- [ ] **CF-400** -- Pacing work function drops and reacquires lock per packet
  - S2 | A,B | Evidence: file:2, sym:5, lines:1, snippet:1

- [ ] **CF-404** -- Per-Call skcipher_request Allocation in HP Mask Hot Path
  - S2 | B,C | Evidence: file:1, sym:1, lines:2, snippet:1

- [ ] **CF-405** -- Per-Packet kmalloc in Batch Encrypt/Decrypt
  - S2 | B,C | Evidence: file:1, lines:2, snippet:1

- [ ] **CF-410** -- rcu_dereference Outside Explicit RCU Section
  - S2 | B,C | Evidence: file:1, sym:3, lines:1, snippet:2

- [ ] **CF-417** -- SmartNIC offload takes dev->lock for every key operation
  - S2 | A,B | Evidence: file:2, sym:3, lines:1, snippet:1

- [ ] **CF-506** -- Key Update Timeout Revert Could Race With Concurrent Update
  - S3 | A,B,C | Evidence: file:1, sym:2

- [ ] **CF-513** -- Qlog: Lock Drop Around copy_to_user
  - S3 | A,B,C | Evidence: file:1, sym:2

- [ ] **CF-558** -- Redundant Lock in tquic_bonding_get_state
  - S3 | B,C | Evidence: file:1, sym:2, lines:2, snippet:1

#### Correctness (7)

- [ ] **CF-328** -- Tunnel Port Allocation Unsigned Underflow
  - S2 | A,B,C | Evidence: file:1, sym:3, snippet:1

- [ ] **CF-353** -- ACK Frame Range Count Uses u64 Loop Variable Against size_t max_ranges
  - S2 | B,C | Evidence: file:1, lines:1, snippet:1

- [ ] **CF-409** -- PSK Identity Logged with `tquic_dbg()` -- Sensitive Data in Kernel Logs
  - S2 | B,C | Evidence: file:1, sym:2, lines:1, snippet:2

- [ ] **CF-427** -- tquic_conn_create -- loss_detection_init failure doesn't clean up timers
  - S2 | B,C | Evidence: file:1, sym:2, lines:2, snippet:1

- [ ] **CF-504** -- Duplicate Static Functions: h3_varint_encode/decode
  - S3 | A,B,C | Evidence: file:2, sym:3

- [ ] **CF-564** -- Stream ID Right-Shift Comparison
  - S3 | B,C | Evidence: file:1, sym:1, lines:1, snippet:1

- [ ] **CF-566** -- tquic_ipv6.c MTU Info getsockopt
  - S3 | B,C | Evidence: file:1, sym:2, lines:5, snippet:1

#### Api (2)

- [ ] **CF-322** -- Qlog: JSON Strings Not Escaped
  - S2 | A,B,C | Evidence: file:1, sym:2

- [ ] **CF-351** -- `tquic_sock_setsockopt()` Reads `int` for Some Options But Accepts `optlen >= sizeof(int)` Without C
  - S2 | B,C | Evidence: file:1, sym:4, lines:5, snippet:2

#### Perf (1)

- [ ] **CF-501** -- Batch Crypto Allocates Per-Packet Temporary Buffer
  - S3 | A,B,C | Evidence: file:1, sym:1

---

## Phase 6: PLAUSIBLE S2/S3 -- Medium/Low Likely (196 items)

#### Memory (22)

- [ ] **CF-317** -- Path Metrics Subscription: Timer/Connection Lifetime Race
  - S2 | A,B,C | Evidence: file:1, sym:2

- [ ] **CF-332** -- `hs_varint_encode` -- no bounds check on output buffer
  - S2 | B,C | Evidence: file:1, snippet:1

- [ ] **CF-341** -- `tquic_hs_process_certificate_verify` -- `content[200]` stack buffer could overflow with large hash
  - S2 | B,C | Evidence: file:1, sym:1, snippet:2

- [ ] **CF-342** -- `tquic_hs_process_certificate` -- unbounded certificate allocation
  - S2 | B,C | Evidence: file:1, sym:1, snippet:2

- [ ] **CF-371** -- Exfil Context set_level Destroys and Reinitializes Without Lock
  - S2 | B,C | Evidence: file:1, sym:3, snippet:1

- [ ] **CF-385** -- Load Balancer Feistel Network Half-Length Overlap
  - S2 | B,C | Evidence: file:1, snippet:1

- [ ] **CF-392** -- Missing Bounds Check on tquic_hyst_state_names Array Access
  - S2 | B,C | Evidence: file:1, sym:3, snippet:1

- [ ] **CF-396** -- Netlink Path Dump Reads conn_id on Every Iteration
  - S2 | B,C | Evidence: file:1, sym:3, snippet:1

- [ ] **CF-413** -- SAN DNS Names Not Validated for Embedded NUL Characters
  - S2 | B,C | Evidence: file:1, snippet:1

- [ ] **CF-449** -- TQUIC_PSK_IDENTITY Off-by-One Potential
  - S2 | B | Evidence: file:1, lines:2, snippet:1

- [ ] **CF-452** -- UAF-P5-02: - Path list uses RCU but active_path does not
  - S2 | B | Evidence: file:1, sym:4, lines:1, snippet:1

- [ ] **CF-470** -- HMAC Stack Buffer Size
  - S2 | B | Evidence: file:1, sym:1, snippet:1

- [ ] **CF-491** -- UAF-ADD-01: - tquic_tunnel_close does not cancel forward_work for tproxy tunnels
  - S2 | B | Evidence: file:1, sym:3, lines:1

- [ ] **CF-492** -- UAF-P3-05: - GRO flush_timer can fire after kfree
  - S2 | B | Evidence: file:1, sym:3, snippet:1

- [ ] **CF-493** -- UAF-P4-03: - Double destruction path for connections
  - S2 | B | Evidence: file:2, sym:6, lines:3

- [ ] **CF-494** -- UAF-P5-01: - Correct RCU usage in tquic_nf.c
  - S2 | B | Evidence: file:1, sym:5, snippet:1

- [ ] **CF-495** -- UAF-P6-02: - tquic_zerocopy_complete callback chain
  - S2 | B | Evidence: file:1, sym:4, snippet:1

- [ ] **CF-531** -- Benchmark Code: Userspace, Not Kernel
  - S3 | A,B | Evidence: file:2, sym:12

- [ ] **CF-548** -- Minimal tracepoint overhead
  - S3 | A,B | Evidence: file:1, sym:7

- [ ] **CF-559** -- Retry Integrity Tag Computed with Potentially-Failing AEAD
  - S3 | B,C | Evidence: file:1, snippet:1

- [ ] **CF-576** -- Version Negotiation Response - dcid/scid_len Not Capped
  - S3 | B,C | Evidence: file:1, sym:1, snippet:1

- [ ] **CF-584** -- UAF-ADD-02: - CID pool rotation_work vs pool destruction race window
  - S3 | B | Evidence: file:1, sym:1, lines:5, snippet:1

#### Security (43)

- [ ] **CF-335** -- `ring_index()` Uses Unbounded While Loop
  - S2 | B,C | Evidence: file:1, sym:1, snippet:1

- [ ] **CF-339** -- `tquic_hs_derive_early_secrets` -- `memzero_explicit` called before error check
  - S2 | B,C | Evidence: file:1, sym:2, snippet:1

- [ ] **CF-340** -- `tquic_hs_generate_client_hello` -- `hkdf_label` stack buffer on sensitive crypto path
  - S2 | B,C | Evidence: file:1, sym:2

- [ ] **CF-357** -- Bloom Filter Seeds Never Rotated
  - S2 | B,C | Evidence: file:1, snippet:1

- [ ] **CF-360** -- cert_verify.c parse_san_extension -- error code not propagated
  - S2 | B,C | Evidence: file:1, snippet:1

- [ ] **CF-368** -- Decoy Traffic Uses Easily Fingerprinted All-Zero Padding
  - S2 | B,C | Evidence: file:1, sym:1

- [ ] **CF-369** -- Diag/Tracepoints Initialize in init_net
  - S2 | B,C | Evidence: file:1, snippet:1

- [ ] **CF-378** -- Hardcoded 8-Byte CID in Short Header Unprotect
  - S2 | B,C | Evidence: file:1, sym:1

- [ ] **CF-380** -- Hostname Wildcard Matching Allows Wildcards in Non-Leftmost Position
  - S2 | B,C | Evidence: file:1, snippet:1

- [ ] **CF-397** -- Netlink PM Commands Missing CAP_NET_ADMIN Checks
  - S2 | B,C | Evidence: file:1, sym:2

- [ ] **CF-398** -- No Flow Count Limit in HTTP Datagram Manager
  - S2 | B,C | Evidence: file:1, sym:1

- [ ] **CF-399** -- No Token Replay Protection Beyond Timestamp
  - S2 | B,C | Evidence: file:1, sym:1

- [ ] **CF-402** -- Path Length Constraint Check Off-By-One
  - S2 | B,C | Evidence: file:1, snippet:1

- [ ] **CF-408** -- Proc Entries Hardcoded to init_net.proc_net
  - S2 | B,C | Evidence: file:3, snippet:2

- [ ] **CF-412** -- Retry Token Address Validation Uses Weak Hash
  - S2 | B,C | Evidence: file:1, snippet:1

- [ ] **CF-415** -- Security Hardening MIB Stats Always Go to init_net
  - S2 | B,C | Evidence: file:1, snippet:1

- [ ] **CF-420** -- Stateless Reset Static Key Accessible via `tquic_stateless_reset_get_static_key()` Export
  - S2 | B,C | Evidence: file:1, sym:2, snippet:1

- [ ] **CF-422** -- Sysctl Permissions Are Overly Permissive
  - S2 | B,C | Evidence: file:1, sym:1

- [ ] **CF-424** -- Token Hash Comparison Not Constant-Time
  - S2 | B,C | Evidence: file:1, snippet:1

- [ ] **CF-425** -- Token Key Rotation Does Not Zeroize Old Key
  - S2 | B,C | Evidence: file:1, sym:3, snippet:2

- [ ] **CF-440** -- asn1_get_length Does Not Handle Length 0x84+
  - S2 | B | Evidence: file:1, lines:2, snippet:1

- [ ] **CF-455** -- 0-RTT Encrypt Allocates AEAD Per-Packet
  - S2 | B | Evidence: file:1, snippet:1

- [ ] **CF-460** -- AMP-3: The MASQUE CONNECT-UDP tunnel implementation in `masque/connect_udp.c` creates UDP sockets to
  - S2 | B | Evidence: file:1, lines:1

- [ ] **CF-475** -- MEM-1: `tquic_handshake.c` lines 605 and 1136 allocate skbs based on computed handshake message leng
  - S2 | B | Evidence: file:1, sym:1, lines:5

- [ ] **CF-499** -- XDP Uses capable
  - S2 | B | Evidence: file:1, snippet:1

- [ ] **CF-521** -- `tquic_hs_cleanup` -- does not zeroize exporter_secret and resumption_secret
  - S3 | B,C | Evidence: file:1, sym:1, snippet:1

- [ ] **CF-522** -- `tquic_hs_generate_client_hello` -- client random not checked for all-zero
  - S3 | B,C | Evidence: file:1, sym:2

- [ ] **CF-523** -- `tquic_hs_get_handshake_secrets` and `tquic_hs_get_app_secrets` -- no output buffer size validation
  - S3 | B,C | Evidence: file:1, sym:2

- [ ] **CF-524** -- `tquic_hs_process_certificate_verify` hardcodes "server CertificateVerify" string
  - S3 | B,C | Evidence: file:1, sym:1

- [ ] **CF-525** -- `tquic_hs_process_new_session_ticket` -- ignores extensions
  - S3 | B,C | Evidence: file:1, sym:5, lines:5

- [ ] **CF-535** -- Constant-Time Comparison Used for Integrity Tags
  - S3 | B,C | Evidence: file:1, sym:1, snippet:1

- [ ] **CF-541** -- HMAC Output Not Zeroized on Fallback Path
  - S3 | B,C | Evidence: file:1, snippet:1

- [ ] **CF-542** -- Inconsistent Error Return From verify_chain
  - S3 | B,C | Evidence: file:1, lines:1

- [ ] **CF-547** -- memzero_explicit Used Correctly for Key Material
  - S3 | B,C | Evidence: sym:2, lines:2

- [ ] **CF-555** -- parse_basic_constraints Hardcoded BOOLEAN Length
  - S3 | B,C | Evidence: file:1, snippet:1

- [ ] **CF-560** -- SAN Parsing Capacity Limit Check Could Be Tighter
  - S3 | B,C | Evidence: file:1, snippet:1

- [ ] **CF-562** -- server_ticket_key Is Static Global Without Rotation
  - S3 | B,C | Evidence: file:1, snippet:1

- [ ] **CF-590** -- `tquic_stateless_reset_detect()` Iterates All Tokens Non-Constant-Time
  - S3 | B | Evidence: file:1, sym:2, snippet:1

- [ ] **CF-598** -- CPU-6: The QPACK decoder accepts a `max_table_capacity` parameter from the peer via SETTINGS. While 
  - S3 | B | Evidence: file:1, sym:2, snippet:1

- [ ] **CF-603** -- MEM-3: The NF connection tracking limit (65536) has no per-source-IP limit at the netfilter layer. W
  - S3 | B | Evidence: file:1, sym:3, lines:2

- [ ] **CF-606** -- Multicast Group Only Requires CAP_NET_ADMIN
  - S3 | B | Evidence: sym:2, lines:5, snippet:1

- [ ] **CF-622** -- Stream Creation Not Bounded in Input Path
  - S3 | B | Evidence: sym:2, lines:2, snippet:1

- [ ] **CF-631** -- tquic_process_coalesced Missing Infinite Loop Guard
  - S3 | B | Evidence: file:1, sym:2, lines:2

#### Concurrency (45)

- [ ] **CF-330** -- `additional_addr_add()` Has TOCTOU Between Duplicate Check and Insert
  - S2 | B,C | Evidence: file:1, sym:2, lines:2

- [ ] **CF-336** -- `tquic_accept()` Holding `sk_lock.slock` Improperly
  - S2 | B,C | Evidence: file:1, sym:3

- [ ] **CF-338** -- `tquic_fc_conn_data_sent()` Race Between Check and Update
  - S2 | B,C | Evidence: file:1, sym:3

- [ ] **CF-343** -- `tquic_hs_process_server_hello` -- `static const` inside function body
  - S2 | B,C | Evidence: file:1, sym:1, snippet:1

- [ ] **CF-344** -- `tquic_migrate_validate_all_additional()` Lock Drop/Reacquire Pattern
  - S2 | B,C | Evidence: file:1, sym:2, snippet:2

- [ ] **CF-355** -- atomic_inc/dec for rx_queue_len on every enqueue/dequeue
  - S2 | A,B | Evidence: file:2, sym:4

- [ ] **CF-364** -- connect_ip.c Datagram Buffer Allocation from Attacker Data
  - S2 | B,C | Evidence: file:1, snippet:1

- [ ] **CF-379** -- HMAC Transform Allocated Per-Token in `tquic_stateless_reset_generate_token()`
  - S2 | B,C | Evidence: file:1, sym:4

- [ ] **CF-386** -- Load Balancer Nonce Counter Wraps Without Re-keying
  - S2 | B,C | Evidence: file:1, snippet:1

- [ ] **CF-394** -- Multiple atomic operations in NAPI enqueue path
  - S2 | A,B | Evidence: file:2, sym:4

- [ ] **CF-395** -- NAT Keepalive Config Pointer Not Protected Against Concurrent Free
  - S2 | B,C | Evidence: file:1, sym:2, snippet:1

- [ ] **CF-407** -- poll() Accesses Connection/Stream Without Any Lock
  - S2 | B,C | Evidence: file:1, sym:1, snippet:2

- [ ] **CF-414** -- Scheduler Change Race Between State Check and Modification
  - S2 | B,C | Evidence: file:1, sym:1, snippet:1

- [ ] **CF-418** -- smartnic.c - kmalloc_array with Attacker-Influenced Count
  - S2 | B,C | Evidence: file:1, snippet:1

- [ ] **CF-429** -- tquic_handshake.c tquic_start_handshake -- hs freed with memzero_explicit but no kfree_sensitive
  - S2 | B,C | Evidence: file:1, sym:3, snippet:1

- [ ] **CF-430** -- tquic_output_flush -- spin_unlock_bh after acquiring spin_lock_bh, but lock dropped mid-loop
  - S2 | B,C | Evidence: file:1, sym:2, snippet:1

- [ ] **CF-431** -- tquic_retry.c -- integrity_aead_lock held across AEAD operations
  - S2 | B,C | Evidence: file:1, sym:1, snippet:1

- [ ] **CF-434** -- tquic_stream_write Holds mgr->lock for Entire Copy Loop
  - S2 | B,C | Evidence: file:1, sym:1

- [ ] **CF-435** -- Unbounded Pending Path Challenges
  - S2 | B,C | Evidence: file:1, sym:3, snippet:1

- [ ] **CF-439** -- AMP-1: The anti-amplification check uses `atomic64` operations for `bytes_received` and `bytes_sent`
  - S2 | B | Evidence: file:1, lines:1, snippet:3

- [ ] **CF-442** -- conn->data_sent Underflow on Error Path
  - S2 | B | Evidence: file:1, lines:4, snippet:1

- [ ] **CF-443** -- CPU-2: FEC decoder block search is a linear list walk.
  - S2 | B | Evidence: file:1, lines:1, snippet:1

- [ ] **CF-444** -- EDF Scheduler edf_select_path Called Without Lock
  - S2 | B | Evidence: file:1, sym:2, lines:3, snippet:1

- [ ] **CF-450** -- tquic_recv_datagram Can Loop Forever Under Signal Pressure
  - S2 | B | Evidence: file:1, sym:1, lines:1, snippet:1

- [ ] **CF-451** -- TQUIC_SCHEDULER Race on tquic_sched_find
  - S2 | B | Evidence: file:1, sym:6, lines:4, snippet:1

- [ ] **CF-461** -- Anti-Amplification Check Has TOCTOU Race
  - S2 | B | Evidence: file:1, sym:2, snippet:1

- [ ] **CF-465** -- Division Safety in Congestion Data Validation
  - S2 | B | Evidence: file:1, sym:1, snippet:1

- [ ] **CF-476** -- Nested Locking in Repair Reception
  - S2 | B | Evidence: file:1, sym:1, snippet:1

- [ ] **CF-477** -- Path Creation Uses static atomic_t for path_id -- Not Per-Connection
  - S2 | B | Evidence: file:1, sym:1, snippet:1

- [ ] **CF-526** -- `tquic_server_check_path_recovery()` Uses `goto restart` Pattern
  - S3 | B,C | Evidence: file:1, sym:3

- [ ] **CF-529** -- AF_XDP frame pool uses spinlock for every frame alloc/free
  - S3 | A,B | Evidence: file:2, sym:1, lines:1

- [ ] **CF-532** -- CID Table Initialization Not Thread-Safe
  - S3 | B,C | Evidence: file:1, sym:1, snippet:1

- [ ] **CF-537** -- CRYPTO_TFM_REQ_MAY_BACKLOG in Atomic Context
  - S3 | B,C | Evidence: file:1, sym:3, snippet:1

- [ ] **CF-544** -- Lock Drop/Re-acquire Pattern in Key Derivation
  - S3 | B,C | Evidence: file:1, sym:1, snippet:1

- [ ] **CF-550** -- Missing lockdep Annotations
  - S3 | B,C | Evidence: sym:3, snippet:1

- [ ] **CF-556** -- Path Validation Response Queue Uses Two Tracking Mechanisms
  - S3 | B,C | Evidence: file:1, sym:1, snippet:1

- [ ] **CF-561** -- Scheduler Lock Uses spin_lock Without _bh
  - S3 | B,C | Evidence: file:1, sym:1

- [ ] **CF-568** -- tquic_output_flush Holds conn->lock While Calling GFP_ATOMIC Allocation
  - S3 | B,C | Evidence: file:1, sym:7, lines:5

- [ ] **CF-573** -- tquic_timer_state_free -- thorough and correct
  - S3 | B,C | Evidence: file:1, sym:2

- [ ] **CF-580** -- CPU-3: CID pool active count enumeration.
  - S3 | B | Evidence: file:1, sym:1, lines:1, snippet:1

- [ ] **CF-581** -- spin_lock
  - S3 | B | Evidence: file:1, lines:2, snippet:1

- [ ] **CF-583** -- tquic_gso_init Integer Overflow in Allocation Size
  - S3 | B | Evidence: file:1, sym:1, lines:1, snippet:2

- [ ] **CF-601** -- Failover Sent Packet Count Can Go Negative
  - S3 | B | Evidence: file:1, sym:1, snippet:1

- [ ] **CF-612** -- Priority Extension Allocation Race
  - S3 | B | Evidence: file:1, snippet:1

- [ ] **CF-636** -- tquic_stream_set_priority Missing Lock Protection
  - S3 | B | Evidence: file:1, sym:2, snippet:1

#### Correctness (77)

- [ ] **CF-331** -- `bbrv3.c` CE Ratio Potential Division by Zero
  - S2 | B,C | Evidence: file:1, snippet:1

- [ ] **CF-333** -- `http3_frame.c` Settings Frame Parser: No Bounds on `count`
  - S2 | B,C | Evidence: file:1, snippet:1

- [ ] **CF-334** -- `kmem_cache_create()` Per Stream Manager Risks Name Collision
  - S2 | B,C | Evidence: file:1, sym:2

- [ ] **CF-337** -- `tquic_cong.c` ECN Byte Calculation Overflow
  - S2 | B,C | Evidence: file:1, sym:1, snippet:1

- [ ] **CF-345** -- `tquic_nl_cmd_path_dump()` Incorrect Cast of `cb->ctx`
  - S2 | B,C | Evidence: file:1, sym:4, snippet:1

- [ ] **CF-346** -- `tquic_path_compute_score()` Integer Overflow in Score Calculation
  - S2 | B,C | Evidence: file:1, sym:2, snippet:1

- [ ] **CF-347** -- `tquic_path_is_degraded()` Division by Zero Possible
  - S2 | B,C | Evidence: file:1, sym:2, snippet:1

- [ ] **CF-349** -- `tquic_process_stream_frame()` Does Not Check Final Size Consistency
  - S2 | B,C | Evidence: file:1, sym:2, snippet:1

- [ ] **CF-350** -- `tquic_sendmsg_datagram()` Allocates Kernel Buffer Sized by User-Controlled `len`
  - S2 | B,C | Evidence: file:1, sym:2, snippet:1

- [ ] **CF-356** -- Benchmark write() Handler - Stack Buffer for User Input
  - S2 | B,C | Evidence: file:1, snippet:1

- [ ] **CF-358** -- BPM Path Manager Uses Workqueue Without Connection Lifetime Guard
  - S2 | B,C | Evidence: file:1, sym:5, snippet:1

- [ ] **CF-359** -- cert_verify.c - kmalloc(count + 1) Integer Overflow
  - S2 | B,C | Evidence: file:1, snippet:1

- [ ] **CF-365** -- connect_udp.c URL Encoding Can Exceed Buffer
  - S2 | B,C | Evidence: file:1, snippet:1

- [ ] **CF-366** -- Connection State Not Checked in tquic_conn_handle_close
  - S2 | B,C | Evidence: file:1, sym:2, snippet:1

- [ ] **CF-375** -- Gaussian Random Approximation Produces Biased Distribution
  - S2 | B,C | Evidence: file:1, sym:3

- [ ] **CF-376** -- h3_stream_recv_data frame_hdr Buffer Partial Read
  - S2 | B,C | Evidence: file:1, sym:3, snippet:1

- [ ] **CF-377** -- h3_stream_recv_headers Does Not Validate payload_len Against H3_MAX_FRAME_PAYLOAD_SIZE
  - S2 | B,C | Evidence: file:1, sym:1, snippet:1

- [ ] **CF-381** -- http3_priority.c snprintf Priority Field Truncation
  - S2 | B,C | Evidence: file:1, snippet:1

- [ ] **CF-384** -- kmem_cache Names Not Unique Per Connection
  - S2 | B,C | Evidence: file:1, snippet:1

- [ ] **CF-388** -- MEDIUM: kzalloc per io_uring async request
  - S2 | A,B | Evidence: file:2, sym:4, snippet:2

- [ ] **CF-401** -- Packet Number Decode Returns 0 on Invalid Input
  - S2 | B,C | Evidence: file:1, snippet:1

- [ ] **CF-403** -- Path Manager netdev_event Shadows Variable 'i'
  - S2 | B,C | Evidence: file:1, snippet:1

- [ ] **CF-411** -- Request ID Truncation from u64 to int
  - S2 | B,C | Evidence: file:1, sym:1, snippet:1

- [ ] **CF-416** -- Signed/Unsigned Mismatch in Scheduler Queue Delay
  - S2 | B,C | Evidence: file:1, snippet:1

- [ ] **CF-419** -- snprintf Return Value Not Checked in qlog.c
  - S2 | B,C | Evidence: file:1, snippet:1

- [ ] **CF-423** -- Sysctl Variables Lack Range Validation
  - S2 | B,C | Evidence: file:1, snippet:2

- [ ] **CF-426** -- tquic_cid_pool_init -- timer initialized but not cancelled on later failure
  - S2 | B,C | Evidence: file:1, sym:6, snippet:2

- [ ] **CF-428** -- tquic_fc_reserve_credit Does Not Actually Reserve
  - S2 | B,C | Evidence: file:1, sym:1, snippet:2

- [ ] **CF-432** -- tquic_stream_memory_pressure Frees Without ext Cleanup
  - S2 | B,C | Evidence: file:1, sym:2, snippet:1

- [ ] **CF-433** -- tquic_stream_trigger_output Inflight Underflow
  - S2 | B,C | Evidence: file:1, sym:2, snippet:1

- [ ] **CF-436** -- Version Negotiation Packet Not Authenticated
  - S2 | B,C | Evidence: file:1, snippet:1

- [ ] **CF-441** -- Coalesced Packet Processing Silently Truncates on Overflow
  - S2 | B | Evidence: file:1, lines:1, snippet:2

- [ ] **CF-445** -- ktime_get_ts64 Written to skb->cb May Exceed cb Size
  - S2 | B | Evidence: file:1, sym:2, lines:2, snippet:1

- [ ] **CF-446** -- MP Frame Type Range Check Too Broad
  - S2 | B | Evidence: file:1, lines:4, snippet:1

- [ ] **CF-447** -- tquic_fc_stream_can_send Missing Overflow Check
  - S2 | B | Evidence: file:1, sym:1, lines:1, snippet:2

- [ ] **CF-448** -- TQUIC_IDLE_TIMEOUT Missing Range Validation
  - S2 | B | Evidence: file:1, lines:1, snippet:1

- [ ] **CF-453** -- Version Negotiation Versions Logged Without Rate Limiting
  - S2 | B | Evidence: file:1, sym:1, lines:1, snippet:1

- [ ] **CF-458** -- Alpha Precision Loss in Coupled CC
  - S2 | B | Evidence: file:1, sym:2, snippet:1

- [ ] **CF-464** -- Deadline Scheduler in_flight Underflow
  - S2 | B | Evidence: file:1, lines:1

- [ ] **CF-468** -- h3_parse_settings_frame u64 to Pointer Cast
  - S2 | B | Evidence: file:1, sym:1, snippet:1

- [ ] **CF-471** -- In-Flight Calculation Signed Arithmetic
  - S2 | B | Evidence: file:1, sym:1, snippet:1

- [ ] **CF-474** -- Loss Rate Cast Overflow
  - S2 | B | Evidence: file:1, sym:1, snippet:2

- [ ] **CF-481** -- Reorder Buffer Sequence in skb->cb Alignment
  - S2 | B | Evidence: file:1, sym:5, snippet:1

- [ ] **CF-482** -- sched/scheduler.c Debug Logging Leaks Kernel Pointers
  - S2 | B | Evidence: file:1, sym:4, snippet:1

- [ ] **CF-484** -- Sort Modifies Caller's Lost Packets Array
  - S2 | B | Evidence: file:1, sym:2, snippet:1

- [ ] **CF-516** -- `established_time` Set Twice in Connection State Machine
  - S3 | B,C | Evidence: file:1, sym:1

- [ ] **CF-517** -- `sk->sk_err = -ret` Stores Negative Error Code
  - S3 | B,C | Evidence: file:1, sym:1, snippet:1

- [ ] **CF-518** -- `tquic_cid_compare()` Marked `__maybe_unused`
  - S3 | B,C | Evidence: file:1, sym:1

- [ ] **CF-519** -- `tquic_cid_retire()` Sends RETIRE_CONNECTION_ID After Retirement
  - S3 | B,C | Evidence: file:1, sym:11, lines:1

- [ ] **CF-520** -- `tquic_debug.c` CID Hex Loop Bound
  - S3 | B,C | Evidence: file:1, sym:1, snippet:1

- [ ] **CF-527** -- `tquic_store_session_ticket()` Does Not Store ALPN or Transport Parameters
  - S3 | B,C | Evidence: file:1, sym:3, snippet:1

- [ ] **CF-528** -- `tquic_sysctl_prefer_v2()` Function Not Declared in Visible Header
  - S3 | B,C | Evidence: file:1, sym:1

- [ ] **CF-530** -- bench/benchmark.c -- kvmalloc used correctly with kvfree
  - S3 | B,C | Evidence: file:2, sym:2, lines:2

- [ ] **CF-533** -- close_work Repurposes drain_work for Retransmit Scheduling
  - S3 | B,C | Evidence: file:1, sym:1, snippet:1

- [ ] **CF-536** -- Context Set Level Does Not Check init Return Values
  - S3 | B,C | Evidence: file:1, sym:7, snippet:1

- [ ] **CF-540** -- h3_varint_len Defined Multiple Times as Static
  - S3 | B,C | Evidence: file:1, sym:1

- [ ] **CF-545** -- LOW: pacing_calc_gap uses division
  - S3 | A,B | Evidence: file:2, sym:1, snippet:1

- [ ] **CF-546** -- LOW: Prague RTT scaling division on every ACK
  - S3 | A,B | Evidence: file:2, snippet:1

- [ ] **CF-554** -- nla_put Operations in Netlink Properly Handle Failure
  - S3 | B,C | Evidence: file:1, sym:1

- [ ] **CF-557** -- quic_exfil.c Decoy Packet Size Controlled by MTU
  - S3 | B,C | Evidence: file:1, sym:1, snippet:1

- [ ] **CF-563** -- Slab Cache Names Are Not Module-Prefixed
  - S3 | B,C | Evidence: file:1, sym:2

- [ ] **CF-565** -- tquic_conn_destroy -- thorough cleanup
  - S3 | B,C | Evidence: file:1, sym:2

- [ ] **CF-567** -- tquic_main.c init -- correct cascading cleanup
  - S3 | B,C | Evidence: file:1, sym:2, lines:1

- [ ] **CF-569** -- tquic_pacing_cleanup -- correct ordering
  - S3 | B,C | Evidence: file:1, sym:2, snippet:1

- [ ] **CF-570** -- tquic_retry_rate_limit Potential Token Bucket Underflow
  - S3 | B,C | Evidence: file:1, sym:2, snippet:1

- [ ] **CF-571** -- tquic_stream_manager_destroy Does Not Free Extended State for All Streams
  - S3 | B,C | Evidence: file:22, sym:4

- [ ] **CF-572** -- tquic_timer_state_alloc -- cleanup loop is correct
  - S3 | B,C | Evidence: file:1, sym:2

- [ ] **CF-574** -- Version Negotiation First Byte Missing Fixed Bit Randomization
  - S3 | B,C | Evidence: file:1, sym:1, lines:1

- [ ] **CF-577** -- Workqueue Not Validated Before Use
  - S3 | B,C | Evidence: file:1, sym:4

- [ ] **CF-589** -- `tquic_sock_listen()` Redundant `INIT_LIST_HEAD` Check
  - S3 | B | Evidence: file:1, sym:2, snippet:1

- [ ] **CF-593** -- BPM Path Metrics min_rtt Initialized to UINT_MAX
  - S3 | B | Evidence: file:1, sym:1, snippet:1

- [ ] **CF-608** -- Multiple Varint Implementations
  - S3 | B | Evidence: file:10, sym:2, lines:5

- [ ] **CF-609** -- Netlink Attribute Policy Does Not Use Strict Validation for Binary Addresses
  - S3 | B | Evidence: file:1, sym:6, snippet:1

- [ ] **CF-623** -- timer_setup with NULL Callback
  - S3 | B | Evidence: file:1, lines:1

- [ ] **CF-626** -- tquic_encode_varint Does Not Validate val Range
  - S3 | B | Evidence: file:1, sym:2, lines:1

- [ ] **CF-629** -- tquic_process_ack_frame Does Not Validate largest_ack vs first_ack_range
  - S3 | B | Evidence: file:1, sym:2, lines:1

- [ ] **CF-635** -- tquic_stream_release Missing Error Return
  - S3 | B | Evidence: file:1, sym:2, lines:1

#### Api (3)

- [ ] **CF-389** -- MEDIUM: Per-chunk skb allocation in zerocopy path
  - S2 | A,B | Evidence: file:2, sym:6, snippet:1

- [ ] **CF-393** -- Missing skb->dev Assignment in Packet Injection
  - S2 | B,C | Evidence: file:1, sym:2, snippet:1

- [ ] **CF-487** -- tquic_main.c init/exit -- conditional cleanup mismatch for NAPI/io_uring
  - S2 | B | Evidence: file:1, sym:6, snippet:1

#### Perf (4)

- [ ] **CF-387** -- MEDIUM: BBRv3 uses ktime_get_ns() for every bandwidth sample
  - S2 | A,B | Evidence: file:2, sym:3, snippet:1

- [ ] **CF-390** -- MEDIUM: Zerocopy sendmsg chunks at 1200 bytes
  - S2 | A,B | Evidence: file:2, sym:6, snippet:1

- [ ] **CF-391** -- MIB counter updates on every packet in RX/TX paths
  - S2 | A,B | Evidence: sym:8, lines:2, snippet:1

- [ ] **CF-579** -- `bench_latency.c` Allocation Without Overflow Check
  - S3 | B | Evidence: file:2, sym:1, lines:4, snippet:3

#### Build (1)

- [ ] **CF-582** -- tquic_build_short_header_internal Writes pkt_num to buf+64 Scratch Space
  - S3 | B | Evidence: file:1, sym:2, lines:4, snippet:2

#### Tests (1)

- [ ] **CF-585** -- `bench_common.c` Variance Calculation
  - S3 | B | Evidence: file:1, snippet:1

---

## Phase 7: SPECULATIVE -- Needs Investigation (116 items)

> These findings lack sufficient evidence. Investigate before making code changes.
> Promote to PLAUSIBLE/CERTIFIED if evidence found, or discard.

#### Memory (8)

- [ ] **CF-108** -- Missing Bounds Check Before Frame Type Read
  - S0 | B | Evidence: lines:2, snippet:1

- [ ] **CF-121** -- RX parsing/decryption assumes contiguous skb data (non-linear skb / GRO risk)
  - S0 | A | Evidence: file:1, sym:2

- [ ] **CF-130** -- Use-After-Free in `tquic_migrate_auto()` -- RCU-Protected Path Used After RCU Unlock
  - S0 | B | Evidence: file:1, sym:6

- [ ] **CF-437** -- WebTransport Session Refcount Not Checked After Accept
  - S2 | B,C | Evidence: file:1

- [ ] **CF-469** -- h3_parser_advance Missing Bounds Check
  - S2 | B | Evidence: file:1, sym:1

- [ ] **CF-575** -- Version Negotiation Packet Size Not Validated Against 256-Byte Buffer
  - S3 | B,C | Evidence: file:1

- [ ] **CF-614** -- Repair Data Pointer Lifetime
  - S3 | B | Evidence: file:2, sym:1

- [ ] **CF-633** -- tquic_sched_release Frees ext Under Lock but kfree Can Sleep
  - S3 | B | Evidence: file:1, sym:1

#### Security (21)

- [ ] **CF-093** -- Client Certificate Verification Uses Server Logic (EKU Bypass)
  - S0 | C | Evidence: sym:1, snippet:1

- [ ] **CF-204** -- MASQUE Proxy Has No Access Control
  - S1 | B,C | Evidence: file:1

- [ ] **CF-219** -- Retry Integrity Tag Uses Wrong Key/Nonce for QUIC v2
  - S1 | B,C | Evidence: file:1

- [ ] **CF-259** -- 0-RTT Keys Derived With Empty Transcript
  - S1 | B | Evidence: file:1

- [ ] **CF-260** -- 0-RTT Keys Derived With Empty Transcript (Not ClientHello Hash)
  - S1 | C | Evidence: sym:2

- [ ] **CF-278** -- Memory Exhaustion via Unbounded QPACK Header Lists
  - S1 | B | Evidence: file:1, sym:1

- [ ] **CF-456** -- 0-RTT Encrypt Allocates AEAD Per-Packet (Performance / Side Channel)
  - S2 | C | Evidence: sym:1, snippet:1

- [ ] **CF-459** -- AMP-2: The `tquic_path_handle_challenge` function in `pm/path_validation.c:249` does not check anti-
  - S2 | B | Evidence: file:1, sym:2

- [ ] **CF-462** -- asn1_get_length Does Not Handle Length 0x84+ (4+ byte lengths)
  - S2 | C | Evidence: snippet:1

- [ ] **CF-485** -- STATE-1: The transition to "attack mode" (TQUIC_RL_COOKIE_REQUIRED) appears to be reactive -- it tri
  - S2 | B | Evidence: file:2

- [ ] **CF-509** -- Netlink Events Do Not Include Timestamp
  - S3 | A,B,C | Evidence: file:1

- [ ] **CF-534** -- Consistent use of kfree_sensitive for key material -- GOOD
  - S3 | B,C | Evidence: sym:1

- [ ] **CF-539** -- Empty Hash Computed Without Algorithm Validation
  - S3 | B,C | Evidence: file:1

- [ ] **CF-595** -- Constant-Time Comparison
  - S3 | B | Evidence: file:1, sym:1

- [ ] **CF-602** -- INFO-1: Several `pr_debug`/`tquic_dbg` calls include connection state information. While these are c
  - S3 | B | Evidence: sym:3, snippet:1

- [ ] **CF-604** -- MEM-4: While stream count is limited, each stream allocates both `send_buf` and `recv_buf` skb queue
  - S3 | B | Evidence: file:1, sym:1

- [ ] **CF-613** -- PROTO-1: The retire loop at `tquic_cid.c:667-674` iterates the entire remote CID list for each NEW_C
  - S3 | B | Evidence: sym:1

- [ ] **CF-616** -- Sensitive Key Cleanup
  - S3 | B | Evidence: file:1, sym:1

- [ ] **CF-619** -- STATE-2: An attacker could open connections, complete the handshake (consuming 1 connection per clie
  - S3 | B | Evidence: file:1

- [ ] **CF-620** -- STATE-3: No visible limit on the number of paths per connection. If an attacker can trigger path cre
  - S3 | B | Evidence: lines:2, snippet:1

- [ ] **CF-621** -- Stateless Reset Token Comparison Timing
  - S3 | B | Evidence: sym:5, lines:1

#### Concurrency (26)

- [x] **CF-043** -- No security_socket_* Hook Invocations
  - S0 | B,C | Evidence: sym:10

- [ ] **CF-091** -- Attacker-Controlled Allocation Sizes
  - S0 | B | Evidence: lines:1

- [ ] **CF-105** -- List Iterator Invalidation in BPM Netdev Notifier (Drop-Relock Pattern)
  - S0 | C | Evidence: sym:2, snippet:1

- [ ] **CF-124** -- TOCTOU Race in Failover Hysteresis (Atomic Read-Modify-Write)
  - S0 | C | Evidence: sym:2, snippet:3

- [ ] **CF-264** -- Aggregate Scheduler Unfair Minimum Weight Floor
  - S1 | B | Evidence: file:1

- [ ] **CF-273** -- h3_request_send_headers State Check TOCTOU
  - S1 | B | Evidence: file:1, sym:1

- [ ] **CF-291** -- Stale Path Pointer Returned After rcu_read_unlock
  - S1 | B | Evidence: sym:4

- [ ] **CF-293** -- TOCTOU in Round-Robin Path Count vs Selection
  - S1 | B | Evidence: file:1

- [ ] **CF-304** -- Unit tests model packet-number length as readable from the first byte without HP removal
  - S1 | A | Evidence: file:1, sym:5

- [ ] **CF-308** -- Weighted Scheduler Has No Lock Protection
  - S1 | B | Evidence: file:1, sym:1

- [ ] **CF-329** -- WebTransport: TOCTOU in Datagram Queue Push
  - S2 | A,B,C | Evidence: file:1

- [ ] **CF-354** -- Anti-Replay Hash Table Cleanup Iterates All Buckets Under spinlock
  - S2 | B,C | Evidence: file:1

- [ ] **CF-466** -- Duplicate ECF Path State Allocation Race
  - S2 | B | Evidence: file:1

- [ ] **CF-473** -- Lock Ordering Between Encoder and Scheduler
  - S2 | B | Evidence: file:1, sym:1

- [ ] **CF-478** -- Path Manager discover_addresses Holds rtnl_lock While Accessing inet6_dev
  - S2 | B | Evidence: file:1, sym:1

- [ ] **CF-480** -- Push Entry Count O(n) Iteration
  - S2 | B | Evidence: file:1

- [ ] **CF-497** -- WebTransport Datagram Queue Double-Checked Locking Anti-Pattern
  - S2 | B | Evidence: file:1

- [ ] **CF-578** -- XOR FEC encoding is efficient
  - S3 | A,B | Evidence: sym:1

- [ ] **CF-588** -- `tquic_accept()` Nested Locking Pattern
  - S3 | B | Evidence: file:1, sym:2

- [ ] **CF-591** -- Aggregate Scheduler Long Spinlock Hold
  - S3 | B | Evidence: file:1, sym:1

- [ ] **CF-594** -- C99 Variable Declaration in Loop
  - S3 | B | Evidence: file:1, sym:1

- [ ] **CF-599** -- CROSS-2: Consider using the `tquic_rx_buf_cache` slab cache pattern (already used at `tquic_input.c:
  - S3 | B | Evidence: file:1, sym:2

- [ ] **CF-605** -- Missing Documentation on Lock Ordering
  - S3 | B | Evidence: file:2, sym:1

- [ ] **CF-607** -- Multiple Scheduler Registration Systems Coexist
  - S3 | B | Evidence: sym:4

- [ ] **CF-611** -- Path Validation Timer del_timer vs del_timer_sync
  - S3 | B | Evidence: file:1, sym:2

- [ ] **CF-634** -- tquic_stream_alloc Uses GFP_KERNEL in Potentially Atomic Context
  - S3 | B | Evidence: file:1, sym:2

#### Correctness (17)

- [ ] **CF-111** -- Potential Integer Overflow in CRYPTO Frame on 32-bit
  - S0 | B | Evidence: lines:1, snippet:1

- [ ] **CF-117** -- Reason Length Underflow on 32-bit
  - S0 | B | Evidence: lines:1, snippet:1

- [ ] **CF-277** -- Large Stack Allocation in XOR Recovery
  - S1 | B | Evidence: file:1, sym:1

- [ ] **CF-290** -- sched/scheduler.c wrr_select Stale total_weight
  - S1 | B | Evidence: file:1

- [ ] **CF-406** -- Per-path stats updated from both RX and TX
  - S2 | A,B | Evidence: sym:2

- [ ] **CF-457** -- All MP Scheduler init() Functions Silently Fail on OOM
  - S2 | B | Evidence: sym:8

- [ ] **CF-467** -- ECN State Tracking Per-Round Limitation
  - S2 | B | Evidence: file:1, sym:1

- [ ] **CF-483** -- sched/scheduler.c ECF Loss Rate Division by Zero
  - S2 | B | Evidence: file:1

- [ ] **CF-490** -- Triplicated Varint Encode/Decode Implementations
  - S2 | B | Evidence: file:3

- [ ] **CF-498** -- Weighted Scheduler Weight Not Validated
  - S2 | B | Evidence: file:1

- [ ] **CF-505** -- HTTP/3 Priority: push_buckets Not Initialized
  - S3 | A,B,C | Evidence: file:1

- [ ] **CF-543** -- io_uring.c getsockopt Same len Validation Pattern
  - S3 | B,C | Evidence: file:1

- [ ] **CF-549** -- Missing Error Check for init_net Reference
  - S3 | B,C | Evidence: sym:1

- [ ] **CF-552** -- Multiple Redundant Varint Implementations
  - S3 | B,C | Evidence: sym:2

- [ ] **CF-600** -- Debug Logging of Packet Contents
  - S3 | B | Evidence: sym:1

- [ ] **CF-610** -- No Per-Connection Frame Processing Budget
  - S3 | B | Evidence: sym:1

- [ ] **CF-617** -- settings seen_mask Limited to 64 Settings
  - S3 | B | Evidence: file:1

#### Api (3)

- [ ] **CF-261** -- `setsockopt(SOL_TQUIC, ...)` forces `optlen >= sizeof(int)` even for string/binary options
  - S1 | A | Evidence: file:1, sym:4

- [ ] **CF-479** -- Priority State No Limit on stream_count
  - S2 | B | Evidence: file:1

- [ ] **CF-596** -- Coupled CC Alpha Smoothing May Suppress Rapid Changes
  - S3 | B | Evidence: file:1, sym:1

#### Perf (4)

- [ ] **CF-275** -- HIGH: Multiple ktime_get() calls per packet
  - S1 | A | Evidence: file:3, sym:3

- [ ] **CF-282** -- Multiple ktime_get() calls per packet
  - S1 | B | Evidence: file:3, sym:3

- [ ] **CF-288** -- Same Stack Issue in Encoder
  - S1 | B | Evidence: file:1, sym:2

- [ ] **CF-637** -- Weighted DRR Iterates Over Empty Slots
  - S3 | B | Evidence: file:1

#### Tests (1)

- [ ] **CF-382** -- Interop Framework - Same Pattern
  - S2 | B,C | Evidence: file:1

#### Other (36)

- [ ] **CF-087** -- (actual): `tquic_hs_process_server_hello` -- missing check before cipher suite read
  - S0 | C | Evidence: sym:1, snippet:1

- [ ] **CF-088** -- (Revised): tquic_process_packet Does Not Validate pkt_num_len Against Remaining Data (tquic_input.c,
  - S0 | C | Evidence: sym:2, snippet:2

- [ ] **CF-090** -- AF_XDP Socket and Device Lookup Use init_net (Container Escape)
  - S0 | C | Evidence: sym:2, snippet:1

- [ ] **CF-094** -- conn->sk Accessed Without Lock After Stateless Reset (tquic_input.c, lines 397-407)
  - S0 | C | Evidence: sym:1, snippet:1

- [ ] **CF-103** -- IPv4/IPv6 Address Discovery Enumerates Host Interfaces (Container Escape / Info Leak)
  - S0 | C | Evidence: snippet:2

- [ ] **CF-107** -- MASQUE CONNECT-UDP Proxy Creates Sockets in init_net (Container Escape)
  - S0 | C | Evidence: snippet:1

- [ ] **CF-109** -- Packet Number Length Extracted Before Header Unprotection (tquic_input.c, lines 2529, 2545 vs 2565)
  - S0 | C | Evidence: sym:2, snippet:2

- [ ] **CF-114** -- QUIC-over-TCP Client and Server Sockets Use init_net (Container Escape)
  - S0 | C | Evidence: sym:1, snippet:1

- [ ] **CF-116** -- Rate Calculation Integer Overflow (`count * 1000`)
  - S0 | C | Evidence: snippet:2

- [ ] **CF-123** -- Stale skb->len Read After ip_local_out (tquic_output.c, lines 1730-1736)
  - S0 | C | Evidence: sym:2, snippet:2

- [ ] **CF-126** -- Tunnel Socket Creation Uses init_net (Container Escape)
  - S0 | C | Evidence: snippet:1

- [ ] **CF-133** -- Use-After-Free in Path Lookup (tquic_input.c, lines 245-261)
  - S0 | C | Evidence: sym:3, snippet:1

- [ ] **CF-135** -- Wrong Network Namespace in ip_local_out (tquic_output.c, line 1730)
  - S0 | C | Evidence: sym:1, snippet:2

- [ ] **CF-258** -- (Revised): tquic_pacing_work Accesses skb->len After tquic_output_packet (tquic_output.c, lines 1413
  - S1 | C | Evidence: sym:3, snippet:1

- [ ] **CF-263** -- ACK Frame bytes_acked Calculation Can Overflow (tquic_input.c, lines 736-738)
  - S1 | C | Evidence: sym:1, snippet:1

- [ ] **CF-281** -- Multipath Frame Processing Lacks Encryption Level Validation (tquic_input.c, lines 2027-2038)
  - S1 | C | Evidence: sym:2, snippet:2

- [ ] **CF-296** -- tquic_output_packet Passes NULL conn to ip_local_out (tquic_output.c, line 1413)
  - S1 | C | Evidence: sym:3, snippet:2

- [ ] **CF-300** -- tquic_udp_recv Processes Stateless Reset Before Authenticating Packet (tquic_input.c, lines 2916-293
  - S1 | C | Evidence: sym:2, snippet:1

- [ ] **CF-463** -- Coalesced Packet Processing Silently Truncates on Overflow (tquic_input.c, lines 3172-3173)
  - S2 | C | Evidence: sym:1, snippet:2

- [ ] **CF-472** -- ktime_get_ts64 Written to skb->cb May Exceed cb Size (tquic_input.c, line 1471)
  - S2 | C | Evidence: sym:1, snippet:1

- [ ] **CF-486** -- tquic_gro_flush Drops and Re-acquires Lock Per Packet (tquic_input.c, lines 2303-2310)
  - S2 | C | Evidence: sym:2, snippet:1

- [ ] **CF-488** -- tquic_main.c init/exit -- conditional cleanup mismatch for NAPI/io_uring
  - S2 | C | Evidence: sym:1, snippet:1

- [ ] **CF-489** -- tquic_recv_datagram Can Loop Forever Under Signal Pressure (tquic_output.c, lines 2706-2743)
  - S2 | C | Evidence: sym:2, snippet:2

- [ ] **CF-496** -- Version Negotiation Versions Logged Without Rate Limiting (tquic_input.c, lines 473-477)
  - S2 | C | Evidence: sym:1, snippet:1

- [ ] **CF-500** -- XDP Uses capable() Instead of ns_capable()
  - S2 | C | Evidence: snippet:1

- [ ] **CF-586** -- `bench_common.c` Variance Calculation (Userspace Code)
  - S3 | C | Evidence: snippet:1

- [ ] **CF-587** -- `bench_latency.c` Allocation Without Overflow Check (Userspace Code)
  - S3 | C | Evidence: snippet:4

- [ ] **CF-592** -- Benchmark Code: Userspace, Not Kernel
  - S3 | C | Evidence: file:1

- [ ] **CF-615** -- send_skb Variable Used After Potential NULL
  - S3 | C | Evidence: snippet:1

- [ ] **CF-618** -- spin_lock (Not spin_lock_bh) Used in tquic_process_max_data_frame (tquic_input.c, lines 1015-1017)
  - S3 | C | Evidence: sym:2, snippet:1

- [ ] **CF-624** -- tquic_build_short_header_internal Writes pkt_num to buf+64 Scratch Space (tquic_output.c, line 818)
  - S3 | C | Evidence: sym:6, snippet:2

- [ ] **CF-625** -- tquic_encap_recv Double UDP Header Strip
  - S3 | C | Evidence: sym:1

- [ ] **CF-627** -- tquic_encode_varint Does Not Validate val Range (tquic_output.c, lines 164-198)
  - S3 | C | Evidence: sym:3

- [ ] **CF-628** -- tquic_gso_init Integer Overflow in Allocation Size (tquic_output.c, line 1489)
  - S3 | C | Evidence: sym:2, snippet:2

- [ ] **CF-630** -- tquic_process_ack_frame Does Not Validate largest_ack vs first_ack_range (tquic_input.c, lines 601-6
  - S3 | C | Evidence: sym:2

- [ ] **CF-632** -- tquic_process_coalesced Missing Infinite Loop Guard (tquic_input.c, lines 3079-3182)
  - S3 | C | Evidence: sym:2

---

## Phase 8: REJECTED -- Parked (10 items)

> No actionable evidence. Skip unless new evidence appears.

- [ ] ~~**CF-454** -- CROSS-1: The systematic use of `jhash` with seed 0 across 15+ call sites creates a coordinated attac~~
  - S1 | B | Evidence: NONE

- [ ] ~~**CF-597** -- Coupled CC Alpha Smoothing May Suppress Rapid Changes~~
  - S3 | C | Evidence: NONE

- [ ] ~~**CF-638** -- ACK Frequency Frame Type Inconsistency~~
  - S3 | C | Evidence: NONE

- [ ] ~~**CF-639** -- copy_from_sockptr in setsockopt Always Uses sizeof(type)~~
  - S3 | C | Evidence: NONE

- [ ] ~~**CF-640** -- Diagnostic Counter Wraps~~
  - S3 | B | Evidence: NONE

- [ ] ~~**CF-641** -- Error Codes Leak Processing State~~
  - S3 | B | Evidence: NONE

- [ ] ~~**CF-642** -- IMMEDIATE_ACK Frame Type Similar Issue~~
  - S3 | C | Evidence: NONE

- [ ] ~~**CF-643** -- Inconsistent Congestion State Layouts~~
  - S3 | C | Evidence: NONE

- [ ] ~~**CF-644** -- Multiple Varint Implementations (Code Duplication Risk)~~
  - S3 | C | Evidence: NONE

- [ ] ~~**CF-645** -- Three Parallel Scheduler Frameworks~~
  - S3 | C | Evidence: NONE

---

*End of work TODO. 645 findings across 8 phases.*