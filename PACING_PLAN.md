# Plan: Wire Up Packet Pacing

## Context

TQUIC's pacing infrastructure is fully built (hrtimer, CC pacing rates, timer functions, per-path pacing state) but two stub functions in `core/quic_output.c` bypass it all, causing uncontrolled packet bursts. RFC 9002 Section 7.7 requires: "A sender SHOULD pace sending of all in-flight packets based on input from the congestion controller." Additionally, the pacing queue drainer in `tquic_timer.c` is commented out.

The goal is to wire the existing infrastructure together with minimal new code.

## Files to Modify

1. `net/tquic/core/quic_output.c` - Replace 2 stubs + fix pacing queue function
2. `net/tquic/core/quic_connection.c` - Add pacing checks to tx_work loop
3. `net/tquic/tquic_timer.c` - Wire pacing timer bit handler to drain queue + re-trigger tx_work
4. `net/tquic/test/tx_work_test.c` - Add pacing-aware test cases
5. `net/tquic/Makefile` - No change needed (test already registered)

## Existing Functions to Reuse (DO NOT recreate)

| Function | File | Purpose |
|----------|------|---------|
| `tquic_cong_get_pacing_rate(path)` | `cong/tquic_cong.c:751` | Gets pacing rate (bytes/sec) from CC algo |
| `tquic_timer_can_send_paced(ts)` | `tquic_timer.c:1427` | Checks if hrtimer allows sending now |
| `tquic_timer_schedule_pacing(ts, bytes)` | `tquic_timer.c:1370` | Schedules next pacing time |
| `tquic_timer_set_pacing_rate(ts, rate)` | `tquic_timer.c:1409` | Updates timer's pacing rate |
| `tquic_net_get_pacing_enabled(net)` | `tquic_sysctl.c:1678` | Checks netns pacing sysctl |
| `conn->timer_state` | `include/net/tquic.h:1088` | Connection's timer state pointer |
| `conn->tsk->pacing_enabled` | `include/net/tquic.h:1555` | Per-socket pacing flag |
| `conn->pacing_queue` | `include/net/tquic.h:1366` | Pacing-delayed frame queue |
| `tquic_output(conn, skb)` | `core/quic_output.h:22` | Direct send (exported symbol) |

## Changes

### Change 1: `net/tquic/core/quic_output.c` - Replace Stubs

**1a. Add include** (after line 38):
```c
#include "../cong/tquic_cong.h"
```
Already used by `core/quic_loss.c:18` so the path works.

**1b. Replace `tquic_cc_pacing_delay()`** (lines 686-690):
```c
static u64 tquic_cc_pacing_delay(struct tquic_path *path, u32 bytes)
{
	u64 rate = tquic_cong_get_pacing_rate(path);

	if (rate == 0)
		return 0;

	/* delay_ns = bytes * NSEC_PER_SEC / pacing_rate */
	return div64_u64((u64)bytes * NSEC_PER_SEC, rate);
}
```

**1c. Replace `tquic_pacing_allow()`** (lines 821-825):
```c
static bool tquic_pacing_allow(struct tquic_connection *conn)
{
	/* Pacing disabled at socket level - allow immediately */
	if (!conn->tsk || !conn->tsk->pacing_enabled)
		return true;

	/* No timer state yet (early in connection) - allow */
	if (!conn->timer_state)
		return true;

	/* Check the hrtimer-based pacing gate */
	return tquic_timer_can_send_paced(conn->timer_state);
}
```
Safe for early connections: `tquic_timer_can_send_paced()` returns true when `pacing_rate == 0`.

**1d. Fix `tquic_pacing_queue_packet()`** (lines 833-846):
Change `conn->control_frames` to `conn->pacing_queue` (which is initialized at `quic_connection.c:772`). Add timer scheduling:
```c
static int tquic_pacing_queue_packet(struct tquic_connection *conn,
				     struct sk_buff *skb)
{
	/* Limit pacing queue to prevent memory exhaustion */
	if (skb_queue_len(&conn->pacing_queue) >= TQUIC_MAX_PENDING_FRAMES) {
		kfree_skb(skb);
		return -ENOBUFS;
	}

	/* Queue for pacing-delayed transmission */
	skb_queue_tail(&conn->pacing_queue, skb);

	/*
	 * Schedule the pacing timer to drain this queue.
	 * tquic_timer_schedule_pacing() calculates the appropriate
	 * delay based on the current pacing rate and packet size.
	 */
	if (conn->timer_state)
		tquic_timer_schedule_pacing(conn->timer_state, skb->len);

	return 0;
}
```

**1e. Remove `__maybe_unused` from `tquic_pacing_delay()`** (line 804):
It's now called indirectly through the non-stub `tquic_cc_pacing_delay()`.

### Change 2: `net/tquic/core/quic_connection.c` - Wire Pacing into tx_work

**2a. Add includes** (after line 26):
```c
#include "../cong/tquic_cong.h"
#include "../tquic_sysctl.h"
```

**2b. Modify `tquic_conn_tx_work()`** (lines 558-632):

Key changes inside the existing loop:

- Add `pacing_enabled` and `pacing_blocked` local variables
- Compute `pacing_enabled` once at function entry by checking `conn->timer_state`, `conn->tsk->pacing_enabled`, and `tquic_net_get_pacing_enabled(net)`
- Before building Application-level packets (`i == TQUIC_PN_SPACE_APPLICATION`), check `tquic_timer_can_send_paced(conn->timer_state)`. If blocked, set `pacing_blocked = true` and `continue` to skip Application space. **Initial/Handshake packets are never paced** per RFC 9002 Section 7.7.
- **CRITICAL**: Capture `skb->len` into `pkt_len` **before** `tquic_udp_send()` because send consumes the skb
- After successful Application-level send, call:
  - `tquic_timer_set_pacing_rate(conn->timer_state, tquic_cong_get_pacing_rate(path))`
  - `tquic_timer_schedule_pacing(conn->timer_state, pkt_len)`
- If `pacing_blocked`, force `more_work = false` to exit the outer loop. The pacing hrtimer will re-trigger tx_work when the send time arrives (via Change 3).

### Change 3: `net/tquic/tquic_timer.c` - Wire Pacing Bit Handler

Find the commented-out pacing handler in `tquic_timer_work_fn()` (around line 1638):
```c
/* Handle pacing - allow next packet send */
if (test_bit(TQUIC_TIMER_PACING_BIT, &pending)) {
	/* Would trigger packet transmission */
	/* tquic_transmit_pending(conn); */
}
```

Replace with:
```c
/* Handle pacing - drain pacing queue and re-trigger tx_work */
if (test_bit(TQUIC_TIMER_PACING_BIT, &pending)) {
	struct sk_buff *pacing_skb;

	/* Drain any packets queued by tquic_pacing_queue_packet() */
	while ((pacing_skb = skb_dequeue(&conn->pacing_queue)) != NULL)
		tquic_output(conn, pacing_skb);

	/*
	 * Re-schedule tx_work to build and send new packets.
	 * The pacing gate is now open since the hrtimer just fired.
	 */
	if (!work_pending(&conn->tx_work))
		schedule_work(&conn->tx_work);
}
```

Check if `tquic_output()` is accessible - it's declared in `core/quic_output.h` and exported via `EXPORT_SYMBOL`. Add `#include "core/quic_output.h"` if not already included.

### Change 4: KUnit Tests - `net/tquic/test/tx_work_test.c`

Add 2 new test cases to the existing suite:

**test_tx_pacing_delay_calculation**: Verify the pacing delay formula:
- 1200 bytes at 1,200,000 bytes/sec = 1,000,000 ns (1ms)
- 1200 bytes at 0 bytes/sec = 0 ns (no pacing)

**test_tx_pacing_blocks_when_rate_set**: Simulate pacing by tracking `next_send_time` in the future and verify the drain loop respects it (similar pattern to cwnd test).

## Verification

1. Run `scripts/checkpatch.pl --strict -f` on all modified files
2. Build check: `make M=net/tquic W=1` (on Linux build env)
3. KUnit: `./tools/testing/kunit/kunit.py run --kunitconfig=net/tquic/test/.kunitconfig`
4. Runtime: Load module, transfer 1MB file, observe paced packet spacing in `tcpdump` (packets should be evenly spaced rather than bursted)
5. Verify pacing can be disabled: `sysctl net.tquic.pacing_enabled=0` should revert to burst behavior

## Summary

This is a **wiring-only change** - all the pacing infrastructure is already built:
- Timer layer with hrtimer (nanosecond precision)
- CC algorithms computing pacing rates (BBR, BBRv2, BBRv3, CUBIC, etc.)
- Per-path pacing state with token bucket
- Sysctl and socket option enable/disable
- FQ qdisc integration

We're just connecting the dots by replacing 2 stub functions, fixing a queue target, wiring the timer handler, and adding pacing checks to tx_work.
