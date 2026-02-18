// SPDX-License-Identifier: GPL-2.0
/*
 * TQUIC Seamless Failover for WAN Bonding
 *
 * Copyright (c) 2026 Justin Adams <spotty118@gmail.com>
 * Kernel implementation by Justin Adams <spotty118@gmail.com>
 *
 * Implements seamless failover with zero application-visible packet loss.
 * When a path fails (3x SRTT without ACK), all unacknowledged packets are
 * moved to a priority retransmit queue for transmission on remaining paths.
 *
 * Key components:
 *   - rhashtable for O(1) sent packet lookup by packet number
 *   - Retransmit queue with priority over new data
 *   - 3x SRTT path timeout for failure detection
 *   - Hysteresis state machine to prevent path flapping
 *   - Bitmap-based receiver deduplication
 */

#define pr_fmt(fmt) "TQUIC-FAILOVER: " fmt

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/rhashtable.h>
#include <linux/workqueue.h>
#include <linux/bitmap.h>

#include "tquic_failover.h"
#include "tquic_bonding.h"
#include "../tquic_debug.h"

/*
 * ============================================================================
 * rhashtable configuration for sent packet tracking
 * ============================================================================
 */

static u32 tquic_sent_packet_hash(const void *data, u32 len, u32 seed)
{
	const struct tquic_sent_packet *sp = data;
	u32 hash;

	hash = jhash_2words((u32)sp->packet_number,
			    (u32)(sp->packet_number >> 32), seed);
	tquic_dbg("sent_packet_hash: pkt=%llu hash=%u\n",
		  sp->packet_number, hash);
	return hash;
}

static u32 tquic_sent_packet_obj_hash(const void *data, u32 len, u32 seed)
{
	return tquic_sent_packet_hash(data, len, seed);
}

static int tquic_sent_packet_cmp(struct rhashtable_compare_arg *arg,
				 const void *obj)
{
	const struct tquic_sent_packet *sp = obj;
	const u64 *pkt_num = arg->key;

	return sp->packet_number != *pkt_num;
}

const struct rhashtable_params tquic_sent_packet_params = {
	.head_offset = offsetof(struct tquic_sent_packet, hash_node),
	.key_offset = offsetof(struct tquic_sent_packet, packet_number),
	.key_len = sizeof(u64),
	.hashfn = tquic_sent_packet_obj_hash,
	.obj_hashfn = tquic_sent_packet_obj_hash,
	.obj_cmpfn = tquic_sent_packet_cmp,
	.automatic_shrinking = true,
};
EXPORT_SYMBOL_GPL(tquic_sent_packet_params);

/*
 * ============================================================================
 * Utility functions
 * ============================================================================
 */

static inline u64 tquic_get_time_us(void)
{
	return ktime_get_ns() / 1000;
}

static void tquic_sent_packet_free_rcu(struct rcu_head *rcu)
{
	struct tquic_sent_packet *sp =
		container_of(rcu, struct tquic_sent_packet, rcu);

	tquic_dbg("sent_packet_free_rcu: pkt=%llu path=%u\n",
		  sp->packet_number, sp->path_id);
	if (sp->skb)
		kfree_skb(sp->skb);
	kfree(sp);
}

static void tquic_sent_packet_free(struct tquic_sent_packet *sp)
{
	tquic_dbg("sent_packet_free: pkt=%llu path=%u\n",
		  sp->packet_number, sp->path_id);
	if (sp->skb)
		kfree_skb(sp->skb);
	kfree(sp);
}

/**
 * tquic_failover_put_packet - Release a packet obtained from tquic_failover_get_next
 * @sp: Packet to release
 *
 * After tquic_failover_get_next() returns an sp, the caller owns it.
 * tquic_failover_on_path_failed() already removed sp from sent_packets,
 * so no ACK or destroy path will free it automatically.  The caller
 * MUST call this function exactly once after it has finished with sp
 * (i.e. after a successful retransmit and tquic_failover_track_sent()
 * for the new packet number, or after giving up on retransmission).
 * Callers that re-enqueue via tquic_failover_requeue() must NOT call
 * this until the packet is finally dequeued and not re-enqueued again.
 */
void tquic_failover_put_packet(struct tquic_sent_packet *sp)
{
	if (!sp)
		return;
	tquic_sent_packet_free(sp);
}
EXPORT_SYMBOL_GPL(tquic_failover_put_packet);

/*
 * ============================================================================
 * Hysteresis helpers
 * ============================================================================
 *
 * Per-path spinlocks protect the consec_failures / consec_successes
 * counters and hyst_state from TOCTOU races between the timeout work
 * (failure path) and ACK updates (success path) running on different
 * CPUs.  The critical sections are very small (increment + threshold
 * check), so a single global array is acceptable.
 */
#define TQUIC_HYST_LOCK_COUNT 16 /* Must match max path count */
static spinlock_t tquic_hyst_locks[TQUIC_HYST_LOCK_COUNT] = {
	[0 ... 15] = __SPIN_LOCK_UNLOCKED(tquic_hyst_locks)
};

static const char *const tquic_hyst_state_names[] = {
	[TQUIC_PATH_HYST_HEALTHY] = "HEALTHY",
	[TQUIC_PATH_HYST_DEGRADED] = "DEGRADED",
	[TQUIC_PATH_HYST_FAILED] = "FAILED",
	[TQUIC_PATH_HYST_RECOVERING] = "RECOVERING",
};

/* CF-392: Bounds-safe accessor for state name */
static inline const char *tquic_hyst_state_name(unsigned int state)
{
	if (state >= ARRAY_SIZE(tquic_hyst_state_names) ||
	    !tquic_hyst_state_names[state])
		return "UNKNOWN";
	return tquic_hyst_state_names[state];
}

/**
 * tquic_hyst_stable_time_us - Calculate minimum stabilization time
 * @pt: Path timeout structure with current SRTT
 *
 * Returns the minimum time (in microseconds) a failed path must remain
 * stable (receiving consecutive ACKs) before it can be restored.
 * This is max(TQUIC_HYST_MIN_STABLE_MS, TQUIC_HYST_RTT_STABLE_MULT * SRTT),
 * capped at TQUIC_HYST_MAX_STABLE_MS.
 */
static u64 tquic_hyst_stable_time_us(struct tquic_path_timeout *pt)
{
	u64 rtt_based_us;
	u64 min_us;
	u64 result;

	min_us = (u64)TQUIC_HYST_MIN_STABLE_MS * 1000;
	rtt_based_us = pt->srtt_us * TQUIC_HYST_RTT_STABLE_MULT;

	result = max(min_us, rtt_based_us);
	result = min(result, (u64)TQUIC_HYST_MAX_STABLE_MS * 1000);
	tquic_dbg("hyst_stable_time_us: path=%u srtt=%llu result=%llu us\n",
		  pt->path_id, pt->srtt_us, result);
	return result;
}

/**
 * tquic_hyst_transition - Transition path hysteresis state
 * @pt: Path timeout structure
 * @new_state: Target hysteresis state
 *
 * Records the state change and resets the appropriate counters.
 * Caller must hold appropriate locks if needed.
 */
static void tquic_hyst_transition(struct tquic_path_timeout *pt,
				  enum tquic_path_hyst_state new_state)
{
	enum tquic_path_hyst_state old_state = READ_ONCE(pt->hyst_state);

	if (old_state == new_state)
		return;

	WRITE_ONCE(pt->hyst_state, new_state);
	pt->last_state_change_us = tquic_get_time_us();

	if (new_state == TQUIC_PATH_HYST_FAILED)
		pt->fail_time_us = pt->last_state_change_us;

	pr_info("path %u hysteresis: %s -> %s (failures=%u successes=%u)\n",
		pt->path_id, tquic_hyst_state_name(old_state),
		tquic_hyst_state_name(new_state), pt->consec_failures,
		pt->consec_successes);
}

/*
 * ============================================================================
 * Path Timeout Handling
 * ============================================================================
 */

static void tquic_failover_timeout_work(struct work_struct *work)
{
	struct tquic_path_timeout *pt = container_of(
		work, struct tquic_path_timeout, timeout_work.work);
	struct tquic_failover_ctx *fc = pt->fc;
	u64 now, elapsed_us;
	u8 path_id = pt->path_id;

	/*
	 * Check the destruction guard before doing anything.  A work item
	 * that re-queued itself (line below) before cancel_delayed_work_sync()
	 * could cancel the requeued item may arrive here after the rhashtable
	 * has been destroyed.  Exit immediately in that case.
	 */
	if (atomic_read(&fc->destroyed))
		return;

	now = tquic_get_time_us();
	elapsed_us = now - pt->last_ack_time;

	/* Check if timeout has actually elapsed */
	if (elapsed_us < (u64)pt->timeout_ms * 1000) {
		/* Reschedule for remaining time */
		u32 remaining_ms;

		remaining_ms = (pt->timeout_ms * 1000 - elapsed_us) / 1000;
		if (remaining_ms < 1)
			remaining_ms = 1;

		queue_delayed_work(fc->wq, &pt->timeout_work,
				   msecs_to_jiffies(remaining_ms));
		return;
	}

	/*
	 * Timeout has elapsed - apply hysteresis before declaring failure.
	 * Increment consecutive failure count and reset success counter.
	 * Only trigger actual failover after reaching the threshold.
	 *
	 * Hold the per-path hysteresis lock to make the increment-and-
	 * threshold-check atomic with respect to concurrent ACK updates
	 * in tquic_failover_update_path_ack().
	 */
	{
		bool trigger_failover = false;
		spinlock_t *hyst_lock;

		hyst_lock = &tquic_hyst_locks[path_id % TQUIC_HYST_LOCK_COUNT];
		spin_lock_bh(hyst_lock);

		pt->consec_failures++;
		pt->consec_successes = 0;

		pr_info("path %u timeout: %llu us since last ACK "
			"(timeout=%u ms, consec_failures=%u/%u, "
			"hyst_state=%s)\n",
			path_id, elapsed_us, pt->timeout_ms,
			pt->consec_failures, TQUIC_HYST_FAIL_THRESHOLD,
			tquic_hyst_state_name(pt->hyst_state));

		switch (pt->hyst_state) {
		case TQUIC_PATH_HYST_HEALTHY:
			/*
			 * First failure(s) on a healthy path - enter
			 * DEGRADED. Don't immediately fail; wait for
			 * sustained failures.
			 */
			tquic_hyst_transition(pt, TQUIC_PATH_HYST_DEGRADED);
			if (pt->consec_failures >= TQUIC_HYST_FAIL_THRESHOLD)
				trigger_failover = true;
			else
				pt->timeout_armed = false;
			break;

		case TQUIC_PATH_HYST_DEGRADED:
			/*
			 * Already degraded, check if we have enough
			 * consecutive failures to confirm truly failed.
			 */
			if (pt->consec_failures >= TQUIC_HYST_FAIL_THRESHOLD)
				trigger_failover = true;
			else
				pt->timeout_armed = false;
			break;

		case TQUIC_PATH_HYST_RECOVERING:
			/*
			 * Path was recovering but timed out again.
			 * Reset recovery progress and return to FAILED.
			 */
			pt->consec_successes = 0;
			tquic_hyst_transition(pt, TQUIC_PATH_HYST_FAILED);
			atomic64_inc(&fc->stats.flaps_suppressed);
			pt->timeout_armed = false;
			break;

		case TQUIC_PATH_HYST_FAILED:
			/*
			 * Already failed, nothing further to do.
			 */
			pt->timeout_armed = false;
			break;
		}

		if (trigger_failover) {
			tquic_hyst_transition(pt, TQUIC_PATH_HYST_FAILED);
			pt->timeout_armed = false;
		}

		spin_unlock_bh(hyst_lock);

		if (trigger_failover)
			tquic_failover_on_path_failed(fc, path_id);
	}
}

/*
 * ============================================================================
 * Lifecycle API
 * ============================================================================
 */

/**
 * tquic_failover_init - Initialize failover context
 */
struct tquic_failover_ctx *
tquic_failover_init(struct tquic_bonding_ctx *bonding,
		    struct workqueue_struct *wq, gfp_t gfp)
{
	struct tquic_failover_ctx *fc;
	int ret, i;

	fc = kzalloc(sizeof(*fc), gfp);
	if (!fc)
		return NULL;

	/* Initialize sent packet rhashtable */
	ret = rhashtable_init(&fc->sent_packets, &tquic_sent_packet_params);
	if (ret) {
		pr_err("failed to initialize sent_packets rhashtable: %d\n",
		       ret);
		kfree(fc);
		return NULL;
	}

	spin_lock_init(&fc->sent_packets_lock);
	fc->sent_count = 0;

	/* Initialize retransmit queue */
	INIT_LIST_HEAD(&fc->retx_queue.queue);
	spin_lock_init(&fc->retx_queue.lock);
	fc->retx_queue.count = 0;
	fc->retx_queue.bytes = 0;

	/* Initialize per-path timeout tracking with hysteresis */
	for (i = 0; i < TQUIC_MAX_PATHS; i++) {
		struct tquic_path_timeout *pt = &fc->path_timeouts[i];
		u64 now_us = tquic_get_time_us();

		pt->last_ack_time = now_us;
		pt->srtt_us = TQUIC_FAILOVER_DEFAULT_SRTT_US;
		pt->timeout_ms = TQUIC_FAILOVER_MIN_TIMEOUT_MS;
		pt->timeout_armed = false;
		pt->fc = fc;
		pt->path_id = i;
		INIT_DELAYED_WORK(&pt->timeout_work,
				  tquic_failover_timeout_work);

		/* Hysteresis state */
		pt->hyst_state = TQUIC_PATH_HYST_HEALTHY;
		pt->consec_failures = 0;
		pt->consec_successes = 0;
		pt->last_state_change_us = now_us;
		pt->fail_time_us = 0;
	}

	/* Initialize receiver deduplication */
	bitmap_zero(fc->dedup.bitmap, TQUIC_DEDUP_WINDOW_SIZE);
	fc->dedup.window_base = 0;
	fc->dedup.duplicates_detected = 0;
	spin_lock_init(&fc->dedup.lock);

	fc->wq = wq;
	fc->bonding = bonding;

	/* Initialize statistics */
	atomic64_set(&fc->stats.packets_tracked, 0);
	atomic64_set(&fc->stats.packets_acked, 0);
	atomic64_set(&fc->stats.packets_requeued, 0);
	atomic64_set(&fc->stats.packets_retransmitted, 0);
	atomic64_set(&fc->stats.path_failures, 0);
	atomic64_set(&fc->stats.failover_time_ns, 0);
	atomic64_set(&fc->stats.rhashtable_errors, 0);
	atomic64_set(&fc->stats.hash_insert_errors, 0);
	atomic64_set(&fc->stats.flaps_suppressed, 0);
	atomic64_set(&fc->stats.path_recoveries, 0);

	/* Destruction guard — cleared until tquic_failover_destroy() */
	atomic_set(&fc->destroyed, 0);

	pr_debug("failover context initialized\n");

	return fc;
}
EXPORT_SYMBOL_GPL(tquic_failover_init);

/**
 * tquic_failover_destroy - Destroy failover context
 */
void tquic_failover_destroy(struct tquic_failover_ctx *fc)
{
	struct tquic_sent_packet *sp, *tmp;
	struct rhashtable_iter iter;
	int i;

	if (!fc)
		return;

	/*
	 * Signal that the context is being destroyed.  Timeout work items
	 * that are already running check this flag at their entry point and
	 * bail out early, preventing them from re-queuing themselves or
	 * calling tquic_failover_on_path_failed() after the rhashtable is
	 * torn down below.  Set before cancel_delayed_work_sync() so that
	 * any concurrent work item that re-queued itself between the cancel
	 * call and the sync will also see the flag and exit.
	 */
	atomic_set(&fc->destroyed, 1);

	/* Cancel all path timeout work (safe to call even if never queued) */
	for (i = 0; i < TQUIC_MAX_PATHS; i++)
		cancel_delayed_work_sync(&fc->path_timeouts[i].timeout_work);

	/* Free all packets in retransmit queue */
	spin_lock_bh(&fc->retx_queue.lock);
	list_for_each_entry_safe(sp, tmp, &fc->retx_queue.queue, retx_list) {
		list_del_init(&sp->retx_list);
		tquic_sent_packet_free(sp);
	}
	spin_unlock_bh(&fc->retx_queue.lock);

	/* Free all tracked sent packets */
	rhashtable_walk_enter(&fc->sent_packets, &iter);
	rhashtable_walk_start(&iter);

	while ((sp = rhashtable_walk_next(&iter)) != NULL) {
		if (IS_ERR(sp)) {
			long err = PTR_ERR(sp);
			if (err != -EAGAIN) {
				pr_err_ratelimited(
					"rhashtable walk error: %ld during destroy\n",
					err);
				atomic64_inc(&fc->stats.rhashtable_errors);
			}
			continue;
		}

		rhashtable_remove_fast(&fc->sent_packets, &sp->hash_node,
				       tquic_sent_packet_params);
		tquic_sent_packet_free(sp);
	}

	rhashtable_walk_stop(&iter);
	rhashtable_walk_exit(&iter);

	rhashtable_destroy(&fc->sent_packets);

	pr_debug(
		"failover context destroyed (tracked=%lld acked=%lld requeued=%lld)\n",
		(long long)atomic64_read(&fc->stats.packets_tracked),
		(long long)atomic64_read(&fc->stats.packets_acked),
		(long long)atomic64_read(&fc->stats.packets_requeued));

	kfree(fc);
}
EXPORT_SYMBOL_GPL(tquic_failover_destroy);

/*
 * ============================================================================
 * Sent Packet Tracking API
 * ============================================================================
 */

/**
 * tquic_failover_track_sent - Track a sent packet for potential failover
 */
int tquic_failover_track_sent(struct tquic_failover_ctx *fc,
			      struct sk_buff *skb, u64 packet_number,
			      u8 path_id)
{
	struct tquic_sent_packet *sp;
	int ret;

	if (!fc || !skb)
		return -EINVAL;

	sp = kzalloc(sizeof(*sp), GFP_ATOMIC);
	if (!sp)
		return -ENOMEM;

	sp->packet_number = packet_number;
	sp->send_time = tquic_get_time_us();
	sp->path_id = path_id;
	sp->len = skb->len;
	sp->retx_count = 0;
	sp->in_retx_queue = false;
	INIT_LIST_HEAD(&sp->retx_list);

	/* Clone the skb for potential retransmission */
	sp->skb = skb_clone(skb, GFP_ATOMIC);
	if (!sp->skb) {
		kfree(sp);
		return -ENOMEM;
	}

	spin_lock_bh(&fc->sent_packets_lock);

	ret = rhashtable_insert_fast(&fc->sent_packets, &sp->hash_node,
				     tquic_sent_packet_params);
	if (ret) {
		spin_unlock_bh(&fc->sent_packets_lock);
		kfree_skb(sp->skb);
		kfree(sp);
		if (ret == -EEXIST) {
			pr_debug("packet %llu already tracked\n",
				 packet_number);
		} else {
			pr_err_ratelimited(
				"failed to track packet %llu: error %d\n",
				packet_number, ret);
			atomic64_inc(&fc->stats.hash_insert_errors);
		}
		return ret;
	}

	fc->sent_count++;
	atomic64_inc(&fc->stats.packets_tracked);

	spin_unlock_bh(&fc->sent_packets_lock);

	pr_debug("tracking packet %llu on path %u (len=%u)\n", packet_number,
		 path_id, sp->len);

	return 0;
}
EXPORT_SYMBOL_GPL(tquic_failover_track_sent);

/**
 * tquic_failover_on_ack - Handle ACK for a sent packet
 */
int tquic_failover_on_ack(struct tquic_failover_ctx *fc, u64 packet_number)
{
	struct tquic_sent_packet *sp;
	struct tquic_sent_packet *queued = NULL;

	if (!fc)
		return -EINVAL;

	spin_lock_bh(&fc->sent_packets_lock);

	sp = rhashtable_lookup_fast(&fc->sent_packets, &packet_number,
				    tquic_sent_packet_params);
	if (!sp) {
		spin_unlock_bh(&fc->sent_packets_lock);

		/*
		 * Packet might already have been transferred to retx_queue by
		 * failover. A late ACK should purge it from retransmission.
		 */
		spin_lock_bh(&fc->retx_queue.lock);
		list_for_each_entry(sp, &fc->retx_queue.queue, retx_list) {
			if (sp->packet_number != packet_number)
				continue;

			queued = sp;
			list_del_init(&queued->retx_list);
			queued->in_retx_queue = false;
			if (likely(fc->retx_queue.count > 0))
				fc->retx_queue.count--;
			else
				pr_warn_once("tquic: retx_queue.count underflow in late on_ack\n");
			if (fc->retx_queue.bytes >= queued->len)
				fc->retx_queue.bytes -= queued->len;
			else
				fc->retx_queue.bytes = 0;
			break;
		}
		spin_unlock_bh(&fc->retx_queue.lock);

		if (!queued)
			return -ENOENT;

		atomic64_inc(&fc->stats.packets_acked);
		pr_debug("acked packet %llu from retx_queue (retx_count=%u)\n",
			 packet_number, queued->retx_count);
		call_rcu(&queued->rcu, tquic_sent_packet_free_rcu);
		return 0;
	}

	/* Remove from tracking */
	rhashtable_remove_fast(&fc->sent_packets, &sp->hash_node,
			       tquic_sent_packet_params);
	if (fc->sent_count > 0)
		fc->sent_count--;
	atomic64_inc(&fc->stats.packets_acked);

	spin_unlock_bh(&fc->sent_packets_lock);

	/*
	 * Remove from retransmit queue if present.
	 * Use list_empty() as authoritative check under lock to avoid
	 * TOCTOU race with the in_retx_queue flag.
	 */
	spin_lock_bh(&fc->retx_queue.lock);
	if (!list_empty(&sp->retx_list)) {
		list_del_init(&sp->retx_list);
		if (likely(fc->retx_queue.count > 0))
			fc->retx_queue.count--;
		else
			pr_warn_once(
				"tquic: retx_queue.count underflow in on_ack\n");
		if (fc->retx_queue.bytes >= sp->len)
			fc->retx_queue.bytes -= sp->len;
		else
			fc->retx_queue.bytes = 0;
	}
	spin_unlock_bh(&fc->retx_queue.lock);

	pr_debug("acked packet %llu (retx_count=%u)\n", packet_number,
		 sp->retx_count);

	/* Free via RCU */
	call_rcu(&sp->rcu, tquic_sent_packet_free_rcu);

	return 0;
}
EXPORT_SYMBOL_GPL(tquic_failover_on_ack);

/**
 * tquic_failover_on_ack_range - Handle ACK range for multiple packets
 *
 * Bounds the iteration to TQUIC_FAILOVER_MAX_ACK_RANGE to prevent
 * a malicious or malformed ACK frame with an excessively large range
 * (e.g. [0, UINT64_MAX]) from causing a near-infinite loop.
 */
#define TQUIC_FAILOVER_MAX_ACK_RANGE 1000

int tquic_failover_on_ack_range(struct tquic_failover_ctx *fc, u64 first,
				u64 last)
{
	u64 pkt_num;
	int count = 0;
	u32 iterations = 0;

	if (!fc || first > last)
		return 0;

	for (pkt_num = first; pkt_num <= last; pkt_num++) {
		if (++iterations > TQUIC_FAILOVER_MAX_ACK_RANGE) {
			pr_warn_ratelimited(
				"ACK range [%llu, %llu] exceeds max "
				"iterations (%u), truncating\n",
				first, last, TQUIC_FAILOVER_MAX_ACK_RANGE);
			break;
		}
		if (tquic_failover_on_ack(fc, pkt_num) == 0)
			count++;
	}

	return count;
}
EXPORT_SYMBOL_GPL(tquic_failover_on_ack_range);

/*
 * ============================================================================
 * Path Failure API
 * ============================================================================
 */

/**
 * tquic_failover_on_path_failed - Handle path failure
 */
int tquic_failover_on_path_failed(struct tquic_failover_ctx *fc, u8 path_id)
{
	struct tquic_sent_packet *sp;
	struct tquic_sent_packet *tracked;
	u64 packet_number;
	struct rhashtable_iter iter;
	int requeued = 0;
	ktime_t start;
	int ret;

	if (!fc)
		return 0;

	start = ktime_get();

	pr_info("path %u failed, requeuing unacked packets\n", path_id);

	/*
	 * Walk the rhashtable and atomically transfer matching packets from
	 * sent_packets to retx_queue.
	 *
	 * SECURITY FIX (MEDIUM-4):
	 *   Hold sent_packets_lock and retx_queue.lock together while:
	 *   1) validating the walked object is still tracked
	 *   2) removing it from rhashtable
	 *   3) adding it to retx_queue
	 *
	 * This prevents an ACK thread from removing + call_rcu()'ing the same
	 * object in between walk pointer acquisition and queue insertion.
	 *
	 * Lock order is fixed as:
	 *   sent_packets_lock -> retx_queue.lock
	 * matching tquic_failover_on_ack() and avoiding ABBA deadlocks.
	 */
	rhashtable_walk_enter(&fc->sent_packets, &iter);
	rhashtable_walk_start(&iter);

	while ((sp = rhashtable_walk_next(&iter)) != NULL) {
		if (IS_ERR(sp)) {
			long err = PTR_ERR(sp);
			if (err != -EAGAIN) {
				pr_warn_ratelimited(
					"rhashtable walk error: %ld during path %u failover\n",
					err, path_id);
				atomic64_inc(&fc->stats.rhashtable_errors);
			}
			continue;
		}

			if (sp->path_id != path_id)
				continue;
			packet_number = sp->packet_number;

			/*
			 * Enforce a safety limit to prevent memory exhaustion
			 * during catastrophic path failure with large BDP.
		 */
		if (requeued >= TQUIC_FAILOVER_MAX_QUEUED) {
			pr_warn_ratelimited(
				"path %u: requeue limit reached (%d)\n",
				path_id, requeued);
			break;
		}

		/* Transfer ownership from sent_packets -> retx_queue atomically. */
		spin_lock_bh(&fc->sent_packets_lock);
		spin_lock_bh(&fc->retx_queue.lock);

			/*
			 * Validate that this object is still tracked by packet number
			 * and pointer identity. If ACK already removed/replaced it,
			 * skip safely.
			 */
			tracked = rhashtable_lookup_fast(&fc->sent_packets,
							 &packet_number,
							 tquic_sent_packet_params);
			if (tracked != sp) {
				spin_unlock_bh(&fc->retx_queue.lock);
				spin_unlock_bh(&fc->sent_packets_lock);
				continue;
		}

			if (tracked->in_retx_queue) {
				/* Already queued by concurrent requeue — skip */
				spin_unlock_bh(&fc->retx_queue.lock);
				spin_unlock_bh(&fc->sent_packets_lock);
				continue;
		}

		/* Check queue limits under lock */
		if (fc->retx_queue.count >= TQUIC_FAILOVER_MAX_QUEUED ||
		    fc->retx_queue.bytes >= TQUIC_FAILOVER_MAX_QUEUE_BYTES) {
			spin_unlock_bh(&fc->retx_queue.lock);
			spin_unlock_bh(&fc->sent_packets_lock);
			pr_warn_ratelimited(
				"path %u: retx_queue full during failover\n",
				path_id);
			break;
		}

			ret = rhashtable_remove_fast(&fc->sent_packets, &tracked->hash_node,
						     tquic_sent_packet_params);
			if (ret) {
				spin_unlock_bh(&fc->retx_queue.lock);
				spin_unlock_bh(&fc->sent_packets_lock);
				continue;
		}
		if (fc->sent_count > 0)
			fc->sent_count--;

			list_add_tail(&tracked->retx_list, &fc->retx_queue.queue);
			tracked->in_retx_queue = true;
			fc->retx_queue.count++;
			fc->retx_queue.bytes += tracked->len;
			requeued++;

		spin_unlock_bh(&fc->retx_queue.lock);
		spin_unlock_bh(&fc->sent_packets_lock);
	}

	rhashtable_walk_stop(&iter);
	rhashtable_walk_exit(&iter);

	if (requeued > 0)
		atomic64_add(requeued, &fc->stats.packets_requeued);

	atomic64_inc(&fc->stats.path_failures);
	atomic64_add(ktime_to_ns(ktime_sub(ktime_get(), start)),
		     &fc->stats.failover_time_ns);

	pr_info("path %u: requeued %d packets for retransmission\n", path_id,
		requeued);

	/* Notify bonding layer */
	if (fc->bonding) {
		/*
		 * The bonding layer's on_path_failed callback should already
		 * be called by the path manager. This is just for coordination.
		 */
		atomic64_inc(&fc->bonding->stats.failover_events);
	}

	return requeued;
}
EXPORT_SYMBOL_GPL(tquic_failover_on_path_failed);

/**
 * tquic_failover_update_path_ack - Update path ACK timestamp and hysteresis
 *
 * Each ACK reception counts as a consecutive success. When a path is in
 * FAILED or RECOVERING state, enough consecutive successes over a minimum
 * stabilization period will restore the path to HEALTHY.
 */
void tquic_failover_update_path_ack(struct tquic_failover_ctx *fc, u8 path_id,
				    u64 srtt_us)
{
	struct tquic_path_timeout *pt;
	u32 timeout_ms;
	u64 now_us;

	if (!fc || path_id >= TQUIC_MAX_PATHS)
		return;

	pt = &fc->path_timeouts[path_id];
	now_us = tquic_get_time_us();

	pt->last_ack_time = now_us;
	pt->srtt_us = srtt_us;

	/* Calculate timeout: 3x SRTT */
	timeout_ms = (srtt_us * TQUIC_FAILOVER_TIMEOUT_MULT) / 1000;
	timeout_ms = clamp(timeout_ms, (u32)TQUIC_FAILOVER_MIN_TIMEOUT_MS,
			   (u32)TQUIC_FAILOVER_MAX_TIMEOUT_MS);
	pt->timeout_ms = timeout_ms;

	/*
	 * Process hysteresis on ACK reception.
	 * Each ACK increments consecutive successes and resets failures.
	 *
	 * Hold the per-path hysteresis lock to make the increment-and-
	 * threshold-check atomic with respect to concurrent timeout
	 * work in tquic_failover_timeout_work().
	 */
	{
		spinlock_t *hyst_lock;

		hyst_lock = &tquic_hyst_locks[path_id % TQUIC_HYST_LOCK_COUNT];
		spin_lock_bh(hyst_lock);

		pt->consec_successes++;
		pt->consec_failures = 0;

		switch (pt->hyst_state) {
		case TQUIC_PATH_HYST_HEALTHY:
			/* Already healthy, nothing to do */
			break;

		case TQUIC_PATH_HYST_DEGRADED:
			/*
			 * Path was degraded but is now receiving ACKs.
			 * Require enough consecutive successes to
			 * confirm stability before returning to HEALTHY.
			 */
			if (pt->consec_successes >=
			    TQUIC_HYST_RECOVER_THRESHOLD) {
				tquic_hyst_transition(pt,
						      TQUIC_PATH_HYST_HEALTHY);
				pt->consec_successes = 0;
			}
			break;

		case TQUIC_PATH_HYST_FAILED:
			/*
			 * Path was failed and is now getting ACKs.
			 * Enter RECOVERING state to begin the
			 * stabilization period.
			 */
			tquic_hyst_transition(pt, TQUIC_PATH_HYST_RECOVERING);
			break;

		case TQUIC_PATH_HYST_RECOVERING:
			/*
			 * Check both consecutive success threshold AND
			 * minimum stabilization period.
			 */
			if (pt->consec_successes >=
			    TQUIC_HYST_RECOVER_THRESHOLD) {
				u64 stable_us;
				u64 since_fail_us;

				stable_us = tquic_hyst_stable_time_us(pt);
				since_fail_us = now_us - pt->fail_time_us;

				if (since_fail_us >= stable_us) {
					tquic_hyst_transition(
						pt, TQUIC_PATH_HYST_HEALTHY);
					pt->consec_successes = 0;
					atomic64_inc(
						&fc->stats.path_recoveries);
					pr_info("path %u: recovered "
						"after %llu ms\n",
						path_id, since_fail_us / 1000);
				}
			}
			break;
		}

		spin_unlock_bh(hyst_lock);
	}

	pr_debug("path %u: ACK received, SRTT=%llu us, timeout=%u ms, "
		 "hyst=%s consec_ok=%u\n",
		 path_id, srtt_us, timeout_ms,
		 tquic_hyst_state_name(READ_ONCE(pt->hyst_state)),
		 READ_ONCE(pt->consec_successes));
}
EXPORT_SYMBOL_GPL(tquic_failover_update_path_ack);

/**
 * tquic_failover_arm_timeout - Arm path failure timeout
 */
void tquic_failover_arm_timeout(struct tquic_failover_ctx *fc, u8 path_id)
{
	struct tquic_path_timeout *pt;

	if (!fc || !fc->wq || path_id >= TQUIC_MAX_PATHS)
		return;

	pt = &fc->path_timeouts[path_id];

	tquic_dbg("failover_arm_timeout: path=%u timeout=%u ms\n",
		  path_id, pt->timeout_ms);
	if (!xchg(&pt->timeout_armed, true)) {
		queue_delayed_work(fc->wq, &pt->timeout_work,
				   msecs_to_jiffies(pt->timeout_ms));
	}
}
EXPORT_SYMBOL_GPL(tquic_failover_arm_timeout);

/**
 * tquic_failover_path_hyst_state - Get hysteresis state name for a path
 */
const char *tquic_failover_path_hyst_state(struct tquic_failover_ctx *fc,
					   u8 path_id)
{
	if (!fc || path_id >= TQUIC_MAX_PATHS)
		return "UNKNOWN";

	return tquic_hyst_state_name(
		READ_ONCE(fc->path_timeouts[path_id].hyst_state));
}
EXPORT_SYMBOL_GPL(tquic_failover_path_hyst_state);

/**
 * tquic_failover_is_path_usable - Check if path is usable for sending
 *
 * A path is usable only if it is HEALTHY or DEGRADED. Paths in FAILED
 * or RECOVERING state must not be used until they have demonstrated
 * stability through consecutive ACKs over the stabilization period.
 */
bool tquic_failover_is_path_usable(struct tquic_failover_ctx *fc, u8 path_id)
{
	enum tquic_path_hyst_state state;
	bool usable;

	if (!fc || path_id >= TQUIC_MAX_PATHS)
		return false;

	state = READ_ONCE(fc->path_timeouts[path_id].hyst_state);

	usable = state == TQUIC_PATH_HYST_HEALTHY ||
		 state == TQUIC_PATH_HYST_DEGRADED;
	tquic_dbg("failover_is_path_usable: path=%u hyst_state=%s usable=%d\n",
		  path_id, tquic_hyst_state_name(state), usable);
	return usable;
}
EXPORT_SYMBOL_GPL(tquic_failover_is_path_usable);

/*
 * ============================================================================
 * Retransmit Queue API
 * ============================================================================
 */

/**
 * tquic_failover_requeue - Add packet to retransmit queue
 */
int tquic_failover_requeue(struct tquic_failover_ctx *fc,
			   struct tquic_sent_packet *sp)
{
	if (!fc || !sp)
		return -EINVAL;

	tquic_dbg("failover_requeue: pkt=%llu path=%u len=%u\n",
		  sp->packet_number, sp->path_id, sp->len);

	spin_lock_bh(&fc->retx_queue.lock);

	/* Check queue limits under lock to prevent TOCTOU race */
	if (!sp->in_retx_queue &&
	    (fc->retx_queue.count >= TQUIC_FAILOVER_MAX_QUEUED ||
	     fc->retx_queue.bytes >= TQUIC_FAILOVER_MAX_QUEUE_BYTES)) {
		spin_unlock_bh(&fc->retx_queue.lock);
		return -ENOBUFS;
	}

	if (sp->in_retx_queue) {
		/* Already queued, move to front */
		list_move(&sp->retx_list, &fc->retx_queue.queue);
	} else {
		/* Add to front (priority) */
		list_add(&sp->retx_list, &fc->retx_queue.queue);
		sp->in_retx_queue = true;
		fc->retx_queue.count++;
		fc->retx_queue.bytes += sp->len;
	}

	spin_unlock_bh(&fc->retx_queue.lock);

	return 0;
}
EXPORT_SYMBOL_GPL(tquic_failover_requeue);

/**
 * tquic_failover_has_pending - Check if retransmit queue has packets
 */
bool tquic_failover_has_pending(struct tquic_failover_ctx *fc)
{
	bool pending;

	if (!fc)
		return false;

	pending = READ_ONCE(fc->retx_queue.count) > 0;
	tquic_dbg("failover_has_pending: retx_count=%u pending=%d\n",
		  READ_ONCE(fc->retx_queue.count), pending);
	return pending;
}
EXPORT_SYMBOL_GPL(tquic_failover_has_pending);

/**
 * tquic_failover_get_next - Get next packet to retransmit
 */
struct tquic_sent_packet *tquic_failover_get_next(struct tquic_failover_ctx *fc)
{
	struct tquic_sent_packet *sp;

	if (!fc)
		return NULL;

	spin_lock_bh(&fc->retx_queue.lock);

	if (list_empty(&fc->retx_queue.queue)) {
		spin_unlock_bh(&fc->retx_queue.lock);
		return NULL;
	}

	sp = list_first_entry(&fc->retx_queue.queue, struct tquic_sent_packet,
			      retx_list);

	/* Remove from queue (entry already removed from sent_packets on failover). */
	list_del_init(&sp->retx_list);
	sp->in_retx_queue = false;
	if (likely(fc->retx_queue.count > 0))
		fc->retx_queue.count--;
	else
		pr_warn_once("tquic: retx_queue.count underflow in get_next\n");
	if (likely(fc->retx_queue.bytes >= sp->len))
		fc->retx_queue.bytes -= sp->len;
	else {
		pr_warn_once("tquic: retx_queue.bytes underflow in get_next\n");
		fc->retx_queue.bytes = 0;
	}

	sp->retx_count++;
	atomic64_inc(&fc->stats.packets_retransmitted);

	spin_unlock_bh(&fc->retx_queue.lock);

	pr_debug("dequeued packet %llu for retransmission (retx_count=%u)\n",
		 sp->packet_number, sp->retx_count);

	return sp;
}
EXPORT_SYMBOL_GPL(tquic_failover_get_next);

/*
 * ============================================================================
 * Receiver Deduplication API
 * ============================================================================
 */

/**
 * tquic_failover_dedup_check - Check if packet is duplicate
 */
bool tquic_failover_dedup_check(struct tquic_failover_ctx *fc,
				u64 packet_number)
{
	u64 offset;
	bool is_duplicate;

	if (!fc)
		return false;

	tquic_dbg("failover_dedup_check: pkt=%llu window_base=%llu\n",
		  packet_number, fc->dedup.window_base);

	spin_lock_bh(&fc->dedup.lock);

	/* Handle packet numbers before window (definitely duplicates) */
	if (packet_number < fc->dedup.window_base) {
		fc->dedup.duplicates_detected++;
		spin_unlock_bh(&fc->dedup.lock);
		return true;
	}

	/* Handle packet numbers beyond window (need to advance) */
	if (packet_number >= fc->dedup.window_base + TQUIC_DEDUP_WINDOW_SIZE) {
		/*
		 * Advance window to include this packet.
		 * Clear old bits as we advance.
		 */
		u64 advance = packet_number - fc->dedup.window_base -
			      TQUIC_DEDUP_WINDOW_SIZE + 1;

		if (advance >= TQUIC_DEDUP_WINDOW_SIZE) {
			/* Complete window reset */
			bitmap_zero(fc->dedup.bitmap, TQUIC_DEDUP_WINDOW_SIZE);
			fc->dedup.window_base = packet_number;
		} else {
			/* Partial advance with shift */
			bitmap_shift_left(fc->dedup.bitmap, fc->dedup.bitmap,
					  advance, TQUIC_DEDUP_WINDOW_SIZE);
			fc->dedup.window_base += advance;
		}
	}

	/* Calculate offset within window */
	offset = packet_number - fc->dedup.window_base;
	if (offset >= TQUIC_DEDUP_WINDOW_SIZE) {
		/* Should not happen after advance above */
		spin_unlock_bh(&fc->dedup.lock);
		return false;
	}

	/* Check and set bit */
	is_duplicate = test_and_set_bit(offset, fc->dedup.bitmap);

	if (is_duplicate)
		fc->dedup.duplicates_detected++;

	spin_unlock_bh(&fc->dedup.lock);

	return is_duplicate;
}
EXPORT_SYMBOL_GPL(tquic_failover_dedup_check);

/**
 * tquic_failover_dedup_advance - Advance deduplication window
 */
void tquic_failover_dedup_advance(struct tquic_failover_ctx *fc, u64 ack_number)
{
	u64 advance;

	if (!fc)
		return;

	spin_lock_bh(&fc->dedup.lock);

	/* Only advance if ACK is ahead of current base */
	if (ack_number <= fc->dedup.window_base) {
		spin_unlock_bh(&fc->dedup.lock);
		return;
	}

	advance = ack_number - fc->dedup.window_base;

	if (advance >= TQUIC_DEDUP_WINDOW_SIZE) {
		/* Complete reset */
		bitmap_zero(fc->dedup.bitmap, TQUIC_DEDUP_WINDOW_SIZE);
		fc->dedup.window_base = ack_number;
	} else {
		/* Shift and advance */
		bitmap_shift_left(fc->dedup.bitmap, fc->dedup.bitmap, advance,
				  TQUIC_DEDUP_WINDOW_SIZE);
		fc->dedup.window_base = ack_number;
	}

	spin_unlock_bh(&fc->dedup.lock);

	pr_debug("advanced dedup window to %llu\n", ack_number);
}
EXPORT_SYMBOL_GPL(tquic_failover_dedup_advance);

/*
 * ============================================================================
 * Statistics API
 * ============================================================================
 */

/**
 * tquic_failover_get_stats - Get failover statistics
 */
void tquic_failover_get_stats(struct tquic_failover_ctx *fc,
			      struct tquic_failover_stats *stats)
{
	tquic_dbg("failover_get_stats: retrieving failover statistics\n");

	if (!fc || !stats) {
		if (stats)
			memset(stats, 0, sizeof(*stats));
		return;
	}

	stats->packets_tracked = atomic64_read(&fc->stats.packets_tracked);
	stats->packets_acked = atomic64_read(&fc->stats.packets_acked);
	stats->packets_requeued = atomic64_read(&fc->stats.packets_requeued);
	stats->packets_retransmitted =
		atomic64_read(&fc->stats.packets_retransmitted);
	stats->path_failures = atomic64_read(&fc->stats.path_failures);
	stats->duplicates_detected = fc->dedup.duplicates_detected;
	stats->flaps_suppressed = atomic64_read(&fc->stats.flaps_suppressed);
	stats->path_recoveries = atomic64_read(&fc->stats.path_recoveries);
	stats->current_tracked = fc->sent_count;
	stats->current_retx_queue = READ_ONCE(fc->retx_queue.count);
}
EXPORT_SYMBOL_GPL(tquic_failover_get_stats);

MODULE_DESCRIPTION("TQUIC Seamless Failover for WAN Bonding");
MODULE_LICENSE("GPL");
MODULE_AUTHOR("Linux Foundation");
