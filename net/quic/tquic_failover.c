// SPDX-License-Identifier: GPL-2.0
/*
 * TQUIC Seamless Failover for WAN Bonding
 *
 * Copyright (c) 2024-2026 Linux Foundation
 *
 * Implements seamless failover with zero application-visible packet loss.
 * When a path fails (3x SRTT without ACK), all unacknowledged packets are
 * moved to a priority retransmit queue for transmission on remaining paths.
 *
 * Key components:
 *   - rhashtable for O(1) sent packet lookup by packet number
 *   - Retransmit queue with priority over new data
 *   - 3x SRTT path timeout for failure detection
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

/*
 * ============================================================================
 * rhashtable configuration for sent packet tracking
 * ============================================================================
 */

static u32 tquic_sent_packet_hash(const void *data, u32 len, u32 seed)
{
	const struct tquic_sent_packet *sp = data;

	return jhash_2words((u32)sp->packet_number,
			    (u32)(sp->packet_number >> 32), seed);
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
	struct tquic_sent_packet *sp = container_of(rcu, struct tquic_sent_packet, rcu);

	if (sp->skb)
		kfree_skb(sp->skb);
	kfree(sp);
}

static void tquic_sent_packet_free(struct tquic_sent_packet *sp)
{
	if (sp->skb)
		kfree_skb(sp->skb);
	kfree(sp);
}

/*
 * ============================================================================
 * Path Timeout Handling
 * ============================================================================
 */

static void tquic_failover_timeout_work(struct work_struct *work)
{
	struct tquic_path_timeout *pt = container_of(work,
					struct tquic_path_timeout, timeout_work.work);
	struct tquic_failover_ctx *fc;
	u64 now, elapsed_us;
	u8 path_id;

	/* Recover path_id from array position */
	fc = container_of(pt - (pt - &fc->path_timeouts[0]),
			  struct tquic_failover_ctx, path_timeouts[0]);

	/* Calculate path_id from offset */
	path_id = pt - fc->path_timeouts;

	now = tquic_get_time_us();
	elapsed_us = now - pt->last_ack_time;

	/* Check if timeout has actually elapsed */
	if (elapsed_us >= (u64)pt->timeout_ms * 1000) {
		pr_info("path %u timeout: %llu us since last ACK (timeout=%u ms)\n",
			path_id, elapsed_us, pt->timeout_ms);

		pt->timeout_armed = false;

		/* Trigger path failure */
		tquic_failover_on_path_failed(fc, path_id);
	} else {
		/* Reschedule for remaining time */
		u32 remaining_ms = (pt->timeout_ms * 1000 - elapsed_us) / 1000;

		if (remaining_ms < 1)
			remaining_ms = 1;

		queue_delayed_work(fc->wq, &pt->timeout_work,
				   msecs_to_jiffies(remaining_ms));
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
struct tquic_failover_ctx *tquic_failover_init(struct tquic_bonding_ctx *bonding,
					       struct workqueue_struct *wq,
					       gfp_t gfp)
{
	struct tquic_failover_ctx *fc;
	int ret, i;

	fc = kzalloc(sizeof(*fc), gfp);
	if (!fc)
		return NULL;

	/* Initialize sent packet rhashtable */
	ret = rhashtable_init(&fc->sent_packets, &tquic_sent_packet_params);
	if (ret) {
		pr_err("failed to initialize sent_packets rhashtable: %d\n", ret);
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

	/* Initialize per-path timeout tracking */
	for (i = 0; i < 8; i++) {
		struct tquic_path_timeout *pt = &fc->path_timeouts[i];

		pt->last_ack_time = tquic_get_time_us();
		pt->srtt_us = TQUIC_FAILOVER_DEFAULT_SRTT_US;
		pt->timeout_ms = TQUIC_FAILOVER_MIN_TIMEOUT_MS;
		pt->timeout_armed = false;
		INIT_DELAYED_WORK(&pt->timeout_work, tquic_failover_timeout_work);
	}

	/* Initialize receiver deduplication */
	bitmap_zero(fc->dedup.bitmap, TQUIC_DEDUP_WINDOW_SIZE);
	fc->dedup.window_base = 0;
	fc->dedup.duplicates_detected = 0;
	spin_lock_init(&fc->dedup.lock);

	fc->wq = wq;
	fc->bonding = bonding;

	/* Initialize statistics */
	memset(&fc->stats, 0, sizeof(fc->stats));

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

	/* Cancel all path timeout work */
	for (i = 0; i < 8; i++) {
		if (fc->path_timeouts[i].timeout_armed)
			cancel_delayed_work_sync(&fc->path_timeouts[i].timeout_work);
	}

	/* Free all packets in retransmit queue */
	spin_lock_bh(&fc->retx_queue.lock);
	list_for_each_entry_safe(sp, tmp, &fc->retx_queue.queue, retx_list) {
		list_del(&sp->retx_list);
		tquic_sent_packet_free(sp);
	}
	spin_unlock_bh(&fc->retx_queue.lock);

	/* Free all tracked sent packets */
	rhashtable_walk_enter(&fc->sent_packets, &iter);
	rhashtable_walk_start(&iter);

	while ((sp = rhashtable_walk_next(&iter)) != NULL) {
		if (IS_ERR(sp))
			continue;

		rhashtable_remove_fast(&fc->sent_packets, &sp->hash_node,
				       tquic_sent_packet_params);
		tquic_sent_packet_free(sp);
	}

	rhashtable_walk_stop(&iter);
	rhashtable_walk_exit(&iter);

	rhashtable_destroy(&fc->sent_packets);

	pr_debug("failover context destroyed (tracked=%llu acked=%llu requeued=%llu)\n",
		 fc->stats.packets_tracked, fc->stats.packets_acked,
		 fc->stats.packets_requeued);

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
		if (ret == -EEXIST)
			pr_debug("packet %llu already tracked\n", packet_number);
		return ret;
	}

	fc->sent_count++;
	fc->stats.packets_tracked++;

	spin_unlock_bh(&fc->sent_packets_lock);

	pr_debug("tracking packet %llu on path %u (len=%u)\n",
		 packet_number, path_id, sp->len);

	return 0;
}
EXPORT_SYMBOL_GPL(tquic_failover_track_sent);

/**
 * tquic_failover_on_ack - Handle ACK for a sent packet
 */
int tquic_failover_on_ack(struct tquic_failover_ctx *fc, u64 packet_number)
{
	struct tquic_sent_packet *sp;

	if (!fc)
		return -EINVAL;

	spin_lock_bh(&fc->sent_packets_lock);

	sp = rhashtable_lookup_fast(&fc->sent_packets, &packet_number,
				    tquic_sent_packet_params);
	if (!sp) {
		spin_unlock_bh(&fc->sent_packets_lock);
		return -ENOENT;
	}

	/* Remove from tracking */
	rhashtable_remove_fast(&fc->sent_packets, &sp->hash_node,
			       tquic_sent_packet_params);
	fc->sent_count--;
	fc->stats.packets_acked++;

	spin_unlock_bh(&fc->sent_packets_lock);

	/* If in retransmit queue, remove it */
	if (sp->in_retx_queue) {
		spin_lock_bh(&fc->retx_queue.lock);
		list_del(&sp->retx_list);
		fc->retx_queue.count--;
		fc->retx_queue.bytes -= sp->len;
		spin_unlock_bh(&fc->retx_queue.lock);
	}

	pr_debug("acked packet %llu (retx_count=%u)\n",
		 packet_number, sp->retx_count);

	/* Free via RCU */
	call_rcu(&sp->rcu, tquic_sent_packet_free_rcu);

	return 0;
}
EXPORT_SYMBOL_GPL(tquic_failover_on_ack);

/**
 * tquic_failover_on_ack_range - Handle ACK range for multiple packets
 */
int tquic_failover_on_ack_range(struct tquic_failover_ctx *fc,
				u64 first, u64 last)
{
	u64 pkt_num;
	int count = 0;

	if (!fc || first > last)
		return 0;

	for (pkt_num = first; pkt_num <= last; pkt_num++) {
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
	struct rhashtable_iter iter;
	struct list_head requeue_list;
	int requeued = 0;
	ktime_t start;

	if (!fc)
		return 0;

	start = ktime_get();
	INIT_LIST_HEAD(&requeue_list);

	pr_info("path %u failed, requeuing unacked packets\n", path_id);

	/*
	 * Walk the rhashtable and collect all packets sent on the failed path.
	 * We use a temporary list to avoid holding locks during requeue.
	 */
	rhashtable_walk_enter(&fc->sent_packets, &iter);
	rhashtable_walk_start(&iter);

	while ((sp = rhashtable_walk_next(&iter)) != NULL) {
		if (IS_ERR(sp))
			continue;

		if (sp->path_id == path_id && !sp->in_retx_queue) {
			/*
			 * Mark for requeue but don't remove from rhashtable.
			 * The packet stays tracked for duplicate ACK handling.
			 */
			sp->in_retx_queue = true;
			list_add_tail(&sp->retx_list, &requeue_list);
			requeued++;
		}
	}

	rhashtable_walk_stop(&iter);
	rhashtable_walk_exit(&iter);

	/* Add collected packets to retransmit queue */
	if (requeued > 0) {
		spin_lock_bh(&fc->retx_queue.lock);

		list_for_each_entry(sp, &requeue_list, retx_list) {
			/* Insert at tail to maintain packet order */
			list_move_tail(&sp->retx_list, &fc->retx_queue.queue);
			fc->retx_queue.count++;
			fc->retx_queue.bytes += sp->len;
		}

		spin_unlock_bh(&fc->retx_queue.lock);

		fc->stats.packets_requeued += requeued;
	}

	fc->stats.path_failures++;
	fc->stats.failover_time_ns += ktime_to_ns(ktime_sub(ktime_get(), start));

	pr_info("path %u: requeued %d packets for retransmission\n",
		path_id, requeued);

	/* Notify bonding layer */
	if (fc->bonding) {
		/*
		 * The bonding layer's on_path_failed callback should already
		 * be called by the path manager. This is just for coordination.
		 */
		fc->bonding->stats.failover_events++;
	}

	return requeued;
}
EXPORT_SYMBOL_GPL(tquic_failover_on_path_failed);

/**
 * tquic_failover_update_path_ack - Update path ACK timestamp
 */
void tquic_failover_update_path_ack(struct tquic_failover_ctx *fc,
				    u8 path_id, u64 srtt_us)
{
	struct tquic_path_timeout *pt;
	u32 timeout_ms;

	if (!fc || path_id >= 8)
		return;

	pt = &fc->path_timeouts[path_id];

	pt->last_ack_time = tquic_get_time_us();
	pt->srtt_us = srtt_us;

	/* Calculate timeout: 3x SRTT */
	timeout_ms = (srtt_us * TQUIC_FAILOVER_TIMEOUT_MULT) / 1000;
	timeout_ms = clamp(timeout_ms,
			   (u32)TQUIC_FAILOVER_MIN_TIMEOUT_MS,
			   (u32)TQUIC_FAILOVER_MAX_TIMEOUT_MS);

	pt->timeout_ms = timeout_ms;

	pr_debug("path %u: updated ACK time, SRTT=%llu us, timeout=%u ms\n",
		 path_id, srtt_us, timeout_ms);
}
EXPORT_SYMBOL_GPL(tquic_failover_update_path_ack);

/**
 * tquic_failover_arm_timeout - Arm path failure timeout
 */
void tquic_failover_arm_timeout(struct tquic_failover_ctx *fc, u8 path_id)
{
	struct tquic_path_timeout *pt;

	if (!fc || !fc->wq || path_id >= 8)
		return;

	pt = &fc->path_timeouts[path_id];

	if (!pt->timeout_armed) {
		pt->timeout_armed = true;
		queue_delayed_work(fc->wq, &pt->timeout_work,
				   msecs_to_jiffies(pt->timeout_ms));
	}
}
EXPORT_SYMBOL_GPL(tquic_failover_arm_timeout);

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

	/* Check queue limits */
	if (fc->retx_queue.count >= TQUIC_FAILOVER_MAX_QUEUED ||
	    fc->retx_queue.bytes >= TQUIC_FAILOVER_MAX_QUEUE_BYTES)
		return -ENOBUFS;

	spin_lock_bh(&fc->retx_queue.lock);

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
	if (!fc)
		return false;

	return READ_ONCE(fc->retx_queue.count) > 0;
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

	sp = list_first_entry(&fc->retx_queue.queue,
			      struct tquic_sent_packet, retx_list);

	/* Remove from queue (but keep in rhashtable for ACK handling) */
	list_del_init(&sp->retx_list);
	sp->in_retx_queue = false;
	fc->retx_queue.count--;
	fc->retx_queue.bytes -= sp->len;

	sp->retx_count++;
	fc->stats.packets_retransmitted++;

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
bool tquic_failover_dedup_check(struct tquic_failover_ctx *fc, u64 packet_number)
{
	u64 offset;
	bool is_duplicate;

	if (!fc)
		return false;

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
		bitmap_shift_left(fc->dedup.bitmap, fc->dedup.bitmap,
				  advance, TQUIC_DEDUP_WINDOW_SIZE);
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
	if (!fc || !stats) {
		if (stats)
			memset(stats, 0, sizeof(*stats));
		return;
	}

	stats->packets_tracked = fc->stats.packets_tracked;
	stats->packets_acked = fc->stats.packets_acked;
	stats->packets_requeued = fc->stats.packets_requeued;
	stats->packets_retransmitted = fc->stats.packets_retransmitted;
	stats->path_failures = fc->stats.path_failures;
	stats->duplicates_detected = fc->dedup.duplicates_detected;
	stats->current_tracked = fc->sent_count;
	stats->current_retx_queue = fc->retx_queue.count;
}
EXPORT_SYMBOL_GPL(tquic_failover_get_stats);

MODULE_DESCRIPTION("TQUIC Seamless Failover for WAN Bonding");
MODULE_LICENSE("GPL");
MODULE_AUTHOR("Linux Foundation");
