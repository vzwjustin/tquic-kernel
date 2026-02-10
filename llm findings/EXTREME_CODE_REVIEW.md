# TQUIC Kernel Module — Verified Bug Report

**Date:** 2026-02-10  
**Methodology:** Extreme line-by-line audit (Opus pass), re-verification of all findings  
**Status:** Only line-verified bugs included. Every entry has been confirmed against source code.

---

## Bug Summary Table

| # | Severity | Bug Type | File | Lines | Function |
|---|----------|----------|------|-------|----------|
| 1 | **CRITICAL** | State Machine Bypass | `tquic_input.c` | 398 | `tquic_handle_stateless_reset` |
| 2 | **CRITICAL** | Use-After-Free Race | `tquic_socket.c` | 230–333 | `tquic_connect` |
| 3 | **CRITICAL** | Sleep-in-Atomic | `tquic_migration.c` | 503 | `tquic_path_free` (via timer) |
| 4 | **CRITICAL** | Refcount Underflow / UAF | `tquic_netlink.c` | 439–641 | `tquic_nl_path_create` / `tquic_path_remove_and_free` |
| 5 | **CRITICAL** | Data Leaked Before Validation | `tquic_input.c` | 971 vs 980 | `tquic_process_stream_frame` |
| 6 | **HIGH** | Unlocked Access / UAF | `tquic_socket.c` | 660 | `tquic_sock_ioctl` |
| 7 | **HIGH** | Data Race (Torn Read) | `tquic_migration.c` | 1261 | `tquic_handle_server_migration` |
| 8 | **MEDIUM** | State Machine Bypass | `tquic_input.c` | 1308 | `tquic_process_handshake_done_frame` |

---

## Detailed Findings

### Bug 1: Stateless Reset Bypasses State Machine

**Severity:** CRITICAL  
**Location:** `net/tquic/tquic_input.c:398`

```c
static void tquic_handle_stateless_reset(struct tquic_connection *conn)
{
    struct sock *sk;

    spin_lock_bh(&conn->lock);
    conn->state = TQUIC_CONN_CLOSED;  // ← DIRECT ASSIGNMENT
    conn->error_code = EQUIC_NO_ERROR;

    sk = READ_ONCE(conn->sk);
    spin_unlock_bh(&conn->lock);

    if (sk)
        sk->sk_state_change(sk);
}
```

**Bug:** Directly assigns `conn->state` instead of calling `tquic_conn_set_state()` or `tquic_conn_close_with_error()`.

**Impact:**
- Active timers (PTO, loss detection, idle timeout) are never canceled → fire on freed connection → UAF
- QUIC-specific waiters (handshake, stream credit) never woken → deadlock
- Connection reference counts not adjusted for state transition → refcount leak

**Fix:** `tquic_conn_close_with_error(conn, EQUIC_NO_ERROR, "stateless reset");`

---

### Bug 2: Use-After-Free in Connect (Race with Close)

**Severity:** CRITICAL  
**Location:** `net/tquic/tquic_socket.c:230–333`

```c
int tquic_connect(struct sock *sk, ...) {
    struct tquic_connection *conn = tsk->conn;  // line 230: cache pointer
    ...
    release_sock(sk);                           // line 285: drop lock
    ret = tquic_wait_for_handshake(...);        // line 291: SLEEP
    lock_sock(sk);                              // line 293: reacquire
    ...
    ret = tquic_pm_conn_init(conn);             // line 309: use stale pointer!
}
```

**Bug:** `conn` is cached at line 230. Between lines 285–293 (lock released, thread sleeps), a concurrent `close()` or `shutdown()` can destroy and free `tsk->conn`. Upon waking, the stale `conn` pointer is dereferenced at line 309.

**Impact:** Kernel panic, exploitable Use-After-Free.

**Fix:** After re-acquiring lock at line 293, add:
```c
conn = tsk->conn;
if (!conn) { ret = -ECONNABORTED; goto out_close; }
```

---

### Bug 3: Sleep-in-Atomic Context (synchronize_rcu from Timer)

**Severity:** CRITICAL  
**Location:** `net/tquic/tquic_migration.c:503`

**Call chain:**
```
tquic_session_ttl_expired()          ← timer callback (softirq context)
  → tquic_conn_close_with_error()    ← line 1395
    → (connection teardown)
      → tquic_path_free()            ← line 503
        → synchronize_rcu()          ← BLOCKING CALL IN ATOMIC CONTEXT
```

```c
void tquic_path_free(struct tquic_path *path) {
    ...
    synchronize_rcu();  // line 503: SLEEPS
    kfree(path);
}
```

**Bug:** `synchronize_rcu()` sleeps. Timer callbacks run in softirq (atomic) context.

**Impact:** Kernel panic: `BUG: scheduling while atomic`.

**Fix:** Replace with `call_rcu(&path->rcu_head, tquic_path_free_callback)`, or defer teardown to a workqueue.

---

### Bug 4: Refcount Underflow in Netlink Path Creation

**Severity:** CRITICAL  
**Location:** `net/tquic/tquic_netlink.c:439–641`

```c
// tquic_nl_path_create (line 427):
refcount_set(&path->refcnt, 1);       // line 439: refcount = 1
list_add_tail_rcu(&path->list, ...);   // line 445: list owns it (needs ref)
return path;                           // line 449: caller owns it (needs ref)
// TWO owners, ONE refcount

// tquic_path_remove_and_free (line 631):
tquic_nl_path_put(path);  // line 640: drop list ref (1 → 0, FREED)
tquic_nl_path_put(path);  // line 641: USE-AFTER-FREE
```

**Bug:** `tquic_nl_path_create` sets refcount to 1 but creates TWO owners (the list via `list_add_tail_rcu` and the returned pointer to caller). Error cleanup in `tquic_path_remove_and_free` correctly calls `put` twice, but since refcount is 1, the second `put` is a use-after-free.

**Impact:** Kernel panic (`refcount_t: underflow` BUG) or silent memory corruption.

**Fix:** Initialize refcount to 2 at line 439: `refcount_set(&path->refcnt, 2);`

---

### Bug 5: Stream Data Queued Before Validation Check

**Severity:** CRITICAL  
**Location:** `net/tquic/tquic_input.c:971 vs 980`

```c
skb_queue_tail(&stream->recv_buf, data_skb);  // line 971: DATA QUEUED

// ... then LATER ...

if (offset > ((1ULL << 62) - 1) - length) {   // line 980: VALIDATION
    return -EPROTO;                            // line 982: ERROR, but skb
}                                              //           already in recv_buf!
```

**Bug:** The skb containing stream data is queued into `stream->recv_buf` at line 971, but the critical validity check (offset overflow per RFC 9000 Section 4.5) doesn't occur until line 980. If the check fails and `-EPROTO` is returned, the corrupted/invalid skb remains in the receive buffer and will be delivered to userspace.

**Impact:** Corrupted data delivered to application. Connection error handling is incomplete — the connection is supposed to be closed on this error, but the bad data persists.

**Fix:** Move the offset validation check (lines 980–983) to BEFORE `skb_queue_tail` at line 971.

---

### Bug 6: Unlocked Connection Access in IOCTL

**Severity:** HIGH  
**Location:** `net/tquic/tquic_socket.c:660`

```c
int tquic_sock_ioctl(struct socket *sock, unsigned int cmd, unsigned long arg)
{
    struct tquic_sock *tsk = tquic_sk(sk);
    struct tquic_connection *conn = tsk->conn;  // line 660: NO LOCK

    switch (cmd) {
    case TQUIC_NEW_STREAM:
        if (!conn || conn->state != TQUIC_CONN_CONNECTED)  // line 672: RACE
            return -ENOTCONN;
```

**Bug:** `tsk->conn` is read at line 660 without holding `lock_sock(sk)`. The `ioctl()` path in the socket layer does not automatically hold the socket lock for the protocol handler. A concurrent `close()` can free `tsk->conn`.

**Impact:** Use-After-Free if `close()` races with `ioctl()`.

**Fix:** Add `lock_sock(sk)` / `release_sock(sk)` around the function body.

---

### Bug 7: Data Race in Server Migration Check

**Severity:** HIGH  
**Location:** `net/tquic/tquic_migration.c:1261`

```c
// line 1261: READ WITHOUT LOCK
if (!sockaddr_equal(&path->remote_addr, new_remote)) {
    ...
    // line 1270: LOCK ACQUIRED LATER
    spin_lock_bh(&conn->paths_lock);
    memcpy(&path->remote_addr, new_remote, sizeof(*new_remote));
```

**Bug:** `path->remote_addr` is read at line 1261 for comparison without holding `paths_lock`. The lock is not acquired until line 1270. A concurrent path update (from another migration, NAT rebind handler, or netlink) could be writing to `path->remote_addr` simultaneously, causing a torn read on the `sockaddr_storage` struct.

**Impact:** Incorrect migration decision (false positive or false negative on address comparison), potential inconsistent state.

**Fix:** Move `spin_lock_bh(&conn->paths_lock)` to before the `sockaddr_equal` check at line 1261.

---

### Bug 8: HANDSHAKE_DONE Bypasses State Machine

**Severity:** MEDIUM  
**Location:** `net/tquic/tquic_input.c:1308`

```c
static int tquic_process_handshake_done_frame(struct tquic_rx_ctx *ctx)
{
    ...
    spin_lock(&ctx->conn->lock);
    if (ctx->conn->state == TQUIC_CONN_CONNECTING) {
        ctx->conn->state = TQUIC_CONN_CONNECTED;  // line 1308: DIRECT
        ctx->conn->handshake_complete = true;
    }
    spin_unlock(&ctx->conn->lock);
```

**Bug:** Same class as Bug #1. Directly assigns `conn->state` instead of using `tquic_conn_set_state()`. While less dangerous than the stateless reset case (CONNECTING→CONNECTED is forward progress), it bypasses any state transition hooks that `tquic_conn_set_state()` might perform (e.g., updating metrics, notifying subsystems).

**Impact:** Missed state transition side effects. Lower severity because this is a forward transition and less likely to cause crashes, but violates the state machine invariant.

**Fix:** Use `tquic_conn_set_state(conn, TQUIC_CONN_CONNECTED)` to ensure consistent state transitions.

---

## Conclusion

| Category | Count |
|----------|-------|
| CRITICAL | 5 |
| HIGH | 2 |
| MEDIUM | 1 |
| **Total** | **8** |

**Top 3 Immediate Action Items:**
1. Fix the `tquic_connect` UAF race (Bug #2) — most easily exploitable
2. Fix `tquic_path_free` sleep-in-atomic (Bug #3) — deterministic kernel panic
3. Fix Netlink refcount underflow (Bug #4) — deterministic kernel panic on error path
