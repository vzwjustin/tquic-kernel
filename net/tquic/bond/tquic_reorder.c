// SPDX-License-Identifier: GPL-2.0
/*
 * TQUIC Adaptive Reorder Buffer for WAN Bonding
 *
 * Copyright (c) 2026 Justin Adams <spotty118@gmail.com>
 * Kernel implementation by Justin Adams <spotty118@gmail.com>
 *
 * RB-tree based out-of-order packet buffering for multi-path bandwidth
 * aggregation. Handles heterogeneous latency paths (fiber + satellite)
 * with adaptive sizing based on RTT spread.
 *
 * Based on MPTCP's out_of_order_queue pattern from net/mptcp/protocol.c.
 */

#define pr_fmt(fmt) "TQUIC-REORDER: " fmt

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/rbtree.h>
#include <linux/skbuff.h>
#include <linux/workqueue.h>
#include "tquic_reorder.h"
#include "../tquic_debug.h"

/* rb_to_skb is defined in linux/skbuff.h */

/*
 * Compare sequence numbers for RB-tree ordering
 * Returns negative if a < b, zero if equal, positive if a > b
 */
static inline int seq_compare(u64 a, u64 b)
{
	if (a < b)
		return -1;
	if (a > b)
		return 1;
	return 0;
}

/*
 * Gap timeout work handler - flushes stale packets from the reorder buffer
 * when gaps are not filled within the timeout period.
 */
static void tquic_reorder_timeout_handler(struct work_struct *work)
{
	struct tquic_reorder_buffer *rb =
		container_of(work, struct tquic_reorder_buffer,
			     timeout_work.work);

	if (rb->deliver_fn)
		tquic_reorder_flush_timeout(rb, rb->deliver_fn,
					    rb->deliver_ctx);
}

/*
 * ============================================================================
 * Lifecycle Functions
 * ============================================================================
 */

/**
 * tquic_reorder_alloc - Allocate a new reorder buffer
 * @gfp: Memory allocation flags
 *
 * Returns allocated buffer or NULL on failure.
 * Caller must call tquic_reorder_init() before use.
 */
struct tquic_reorder_buffer *tquic_reorder_alloc(gfp_t gfp)
{
	struct tquic_reorder_buffer *rb;

	rb = kzalloc(sizeof(*rb), gfp);
	if (!rb)
		return NULL;

	rb->queue = RB_ROOT;
	spin_lock_init(&rb->buffer_lock);

	return rb;
}
EXPORT_SYMBOL_GPL(tquic_reorder_alloc);

/**
 * tquic_reorder_init - Initialize reorder buffer
 * @rb: Reorder buffer to initialize
 * @max_bytes: Maximum buffer size in bytes (0 for default)
 * @wq: Workqueue for timeout handling (can be NULL)
 * @priv: Private context pointer for callbacks
 *
 * Returns 0 on success, negative error code on failure.
 */
int tquic_reorder_init(struct tquic_reorder_buffer *rb, size_t max_bytes,
		       struct workqueue_struct *wq, void *priv)
{
	if (!rb)
		return -EINVAL;

	rb->queue = RB_ROOT;
	rb->last_skb = NULL;
	rb->next_expected = 0;
	rb->max_buffered = 0;
	rb->buffer_bytes = 0;
	rb->packet_count = 0;

	/* Set buffer size limit */
	if (max_bytes == 0)
		max_bytes = TQUIC_REORDER_DEFAULT_BUFFER;
	rb->max_buffer_bytes = clamp(max_bytes,
				     (size_t)TQUIC_REORDER_MIN_BUFFER,
				     (size_t)TQUIC_REORDER_MAX_BUFFER);

	/* Gap timeout defaults */
	rb->gap_timeout_ms = TQUIC_REORDER_DEFAULT_TIMEOUT_MS;
	rb->timeout_scheduled = false;

	/* RTT tracking */
	rb->min_path_rtt = UINT_MAX;
	rb->max_path_rtt = 0;
	rb->rtt_spread = 0;

	rb->wq = wq;
	rb->priv = priv;
	rb->deliver_fn = NULL;
	rb->deliver_ctx = NULL;
	INIT_DELAYED_WORK(&rb->timeout_work, tquic_reorder_timeout_handler);

	memset(&rb->stats, 0, sizeof(rb->stats));

	pr_debug("initialized buffer: max_bytes=%zu timeout=%ums\n",
		 rb->max_buffer_bytes, rb->gap_timeout_ms);

	return 0;
}
EXPORT_SYMBOL_GPL(tquic_reorder_init);

/**
 * tquic_reorder_set_deliver - Register delivery callback for timeout flushes
 * @rb: Reorder buffer
 * @deliver: Callback to deliver each packet
 * @ctx: Context for callback
 */
void tquic_reorder_set_deliver(struct tquic_reorder_buffer *rb,
			       void (*deliver)(void *ctx, struct sk_buff *skb),
			       void *ctx)
{
	if (!rb)
		return;
	rb->deliver_fn = deliver;
	rb->deliver_ctx = ctx;
}
EXPORT_SYMBOL_GPL(tquic_reorder_set_deliver);

/**
 * tquic_reorder_destroy - Destroy reorder buffer and free all packets
 * @rb: Reorder buffer to destroy
 */
void tquic_reorder_destroy(struct tquic_reorder_buffer *rb)
{
	struct rb_node *node, *next;

	if (!rb)
		return;

	/* Cancel pending timeout work */
	if (rb->wq && rb->timeout_scheduled)
		cancel_delayed_work_sync(&rb->timeout_work);

	/* Free all buffered packets */
	spin_lock_bh(&rb->buffer_lock);

	for (node = rb_first(&rb->queue); node; node = next) {
		struct sk_buff *skb = rb_to_skb(node);

		next = rb_next(node);
		rb_erase(node, &rb->queue);
		kfree_skb(skb);
	}

	rb->queue = RB_ROOT;
	rb->last_skb = NULL;
	rb->buffer_bytes = 0;
	rb->packet_count = 0;

	spin_unlock_bh(&rb->buffer_lock);

	kfree(rb);
}
EXPORT_SYMBOL_GPL(tquic_reorder_destroy);

/*
 * ============================================================================
 * Core Operations
 * ============================================================================
 */

/**
 * tquic_reorder_insert - Insert packet into reorder buffer
 * @rb: Reorder buffer
 * @skb: Packet to insert (consumed on success)
 * @seq: Data sequence number
 * @len: Data length
 * @path_id: Path the packet arrived on
 *
 * Returns:
 *   1 if packet was delivered immediately (in-order)
 *   0 if packet was buffered (out-of-order)
 *   -EEXIST if duplicate
 *   -ENOBUFS if buffer full
 *   -EINVAL if packet too old
 */
int tquic_reorder_insert(struct tquic_reorder_buffer *rb, struct sk_buff *skb,
			 u64 seq, u32 len, u8 path_id)
{
	struct tquic_reorder_cb *cb;
	struct rb_node **p, *parent = NULL;
	/* int ret = 0; unused */

	if (!rb || !skb)
		return -EINVAL;

	spin_lock_bh(&rb->buffer_lock);

	/* Fast path: packet is exactly what we're expecting */
	if (seq == rb->next_expected) {
		rb->next_expected = seq + len;
		rb->stats.in_order_packets++;
		spin_unlock_bh(&rb->buffer_lock);
		return 1; /* Deliver immediately */
	}

	/* Check if packet is too old (already delivered) */
	if (seq_compare(seq, rb->next_expected) < 0) {
		rb->stats.dropped_packets++;
		spin_unlock_bh(&rb->buffer_lock);
		kfree_skb(skb);
		return -EINVAL;
	}

	/* Check memory limit */
	if (rb->buffer_bytes + skb->truesize > rb->max_buffer_bytes) {
		rb->stats.dropped_packets++;
		spin_unlock_bh(&rb->buffer_lock);
		kfree_skb(skb);
		return -ENOBUFS;
	}

	/* Store metadata in skb control block */
	cb = TQUIC_REORDER_CB(skb);
	cb->seq = seq;
	cb->len = len;
	cb->path_id = path_id;
	cb->arrival = ktime_get();

	/* Fast path: append to tail (common case for nearly-in-order) */
	if (rb->last_skb) {
		struct tquic_reorder_cb *last_cb =
			TQUIC_REORDER_CB(rb->last_skb);

		if (seq_compare(seq, last_cb->seq) > 0) {
			/* Append after last_skb */
			p = &rb->last_skb->rbnode.rb_right;
			parent = &rb->last_skb->rbnode;

			rb_link_node(&skb->rbnode, parent, p);
			rb_insert_color(&skb->rbnode, &rb->queue);
			rb->last_skb = skb;
			goto inserted;
		}
	}

	/* Standard RB-tree insertion */
	p = &rb->queue.rb_node;
	while (*p) {
		struct sk_buff *skb1 = rb_to_skb(*p);
		struct tquic_reorder_cb *cb1 = TQUIC_REORDER_CB(skb1);
		s64 cmp;

		parent = *p;
		cmp = seq_compare(seq, cb1->seq);

		if (cmp < 0) {
			p = &(*p)->rb_left;
		} else if (cmp > 0) {
			p = &(*p)->rb_right;
		} else {
			/* Duplicate packet */
			rb->stats.duplicate_packets++;
			spin_unlock_bh(&rb->buffer_lock);
			kfree_skb(skb);
			return -EEXIST;
		}
	}

	rb_link_node(&skb->rbnode, parent, p);
	rb_insert_color(&skb->rbnode, &rb->queue);

	/* Update last_skb if this is the new tail */
	if (!rb->last_skb ||
	    seq_compare(seq, TQUIC_REORDER_CB(rb->last_skb)->seq) > 0)
		rb->last_skb = skb;

inserted:
	rb->buffer_bytes += skb->truesize;
	rb->packet_count++;
	rb->stats.buffered_packets++;

	if (seq_compare(seq, rb->max_buffered) > 0)
		rb->max_buffered = seq;

	/* Track buffer peak */
	if (rb->buffer_bytes > rb->stats.buffer_peak_bytes)
		rb->stats.buffer_peak_bytes = rb->buffer_bytes;

	/* Update oldest arrival for timeout */
	if (rb->packet_count == 1 ||
	    ktime_before(cb->arrival, rb->oldest_arrival))
		rb->oldest_arrival = cb->arrival;

	/* Schedule gap timeout if not already scheduled */
	if (rb->wq && !rb->timeout_scheduled && rb->gap_timeout_ms > 0) {
		rb->timeout_scheduled = true;
		mod_delayed_work(rb->wq, &rb->timeout_work,
				 msecs_to_jiffies(rb->gap_timeout_ms));
	}

	spin_unlock_bh(&rb->buffer_lock);

	pr_debug("buffered seq=%llu len=%u path=%u (buffered=%u bytes=%zu)\n",
		 seq, len, path_id, rb->packet_count, rb->buffer_bytes);

	return 0;
}
EXPORT_SYMBOL_GPL(tquic_reorder_insert);

/**
 * tquic_reorder_drain - Deliver consecutive in-order packets from buffer
 * @rb: Reorder buffer
 * @deliver: Callback to deliver each packet
 * @ctx: Context for callback
 *
 * Returns number of packets delivered.
 * Call after insert returns 1 to continue draining.
 */
int tquic_reorder_drain(struct tquic_reorder_buffer *rb,
			void (*deliver)(void *ctx, struct sk_buff *skb),
			void *ctx)
{
	struct rb_node *node;
	int delivered = 0;

	if (!rb || !deliver)
		return 0;

	spin_lock_bh(&rb->buffer_lock);

	while ((node = rb_first(&rb->queue)) != NULL) {
		struct sk_buff *skb = rb_to_skb(node);
		struct tquic_reorder_cb *cb = TQUIC_REORDER_CB(skb);

		/* Stop if packet is not the next expected */
		if (seq_compare(cb->seq, rb->next_expected) > 0)
			break;

		/* Remove from tree */
		rb_erase(node, &rb->queue);
		rb->buffer_bytes -= skb->truesize;
		rb->packet_count--;

		/* Update last_skb if we removed it */
		if (rb->last_skb == skb)
			rb->last_skb = NULL;

		/* Update next expected */
		rb->next_expected = cb->seq + cb->len;
		rb->stats.delivered_packets++;
		delivered++;

		spin_unlock_bh(&rb->buffer_lock);

		/* Deliver to upper layer */
		deliver(ctx, skb);

		spin_lock_bh(&rb->buffer_lock);
	}

	/* Update oldest arrival if buffer is now empty */
	if (rb->packet_count == 0) {
		rb->oldest_arrival = 0;
		rb->timeout_scheduled = false;
	} else {
		/* Find new oldest */
		node = rb_first(&rb->queue);
		if (node) {
			struct sk_buff *first = rb_to_skb(node);
			rb->oldest_arrival = TQUIC_REORDER_CB(first)->arrival;
		}
	}

	spin_unlock_bh(&rb->buffer_lock);

	if (delivered > 0)
		pr_debug("drained %d packets, next_expected=%llu\n", delivered,
			 rb->next_expected);

	return delivered;
}
EXPORT_SYMBOL_GPL(tquic_reorder_drain);

/**
 * tquic_reorder_flush_timeout - Force delivery of timed-out packets
 * @rb: Reorder buffer
 * @deliver: Callback to deliver each packet
 * @ctx: Context for callback
 *
 * Called when gap timeout expires. Delivers all buffered packets
 * that have been waiting too long, skipping the gap.
 */
void tquic_reorder_flush_timeout(struct tquic_reorder_buffer *rb,
				 void (*deliver)(void *ctx,
						 struct sk_buff *skb),
				 void *ctx)
{
	struct rb_node *node;
	ktime_t threshold;
	u64 gap_start;
	int delivered = 0;

	if (!rb || !deliver)
		return;

	spin_lock_bh(&rb->buffer_lock);

	if (RB_EMPTY_ROOT(&rb->queue)) {
		rb->timeout_scheduled = false;
		spin_unlock_bh(&rb->buffer_lock);
		return;
	}

	threshold = ktime_sub_ms(ktime_get(), rb->gap_timeout_ms);
	gap_start = rb->next_expected;

	/* Check if oldest packet has timed out */
	if (ktime_after(rb->oldest_arrival, threshold)) {
		/* Not yet timed out, reschedule */
		rb->timeout_scheduled = false;
		spin_unlock_bh(&rb->buffer_lock);
		return;
	}

	pr_info("gap timeout: expected seq=%llu, jumping to buffered\n",
		gap_start);

	/* Jump next_expected to first buffered packet */
	node = rb_first(&rb->queue);
	if (node) {
		struct sk_buff *first = rb_to_skb(node);
		rb->next_expected = TQUIC_REORDER_CB(first)->seq;
	}

	rb->stats.gap_timeout_packets++;
	spin_unlock_bh(&rb->buffer_lock);

	/* Drain whatever is now deliverable */
	delivered = tquic_reorder_drain(rb, deliver, ctx);

	pr_info("gap timeout delivered %d packets after skipping gap\n",
		delivered);
}
EXPORT_SYMBOL_GPL(tquic_reorder_flush_timeout);

/*
 * ============================================================================
 * Adaptive Configuration
 * ============================================================================
 */

/**
 * tquic_reorder_update_timeout - Update gap timeout value
 * @rb: Reorder buffer
 * @timeout_ms: New timeout in milliseconds
 */
void tquic_reorder_update_timeout(struct tquic_reorder_buffer *rb,
				  u32 timeout_ms)
{
	if (!rb)
		return;

	timeout_ms = clamp(timeout_ms, (u32)TQUIC_REORDER_MIN_TIMEOUT_MS,
			   (u32)TQUIC_REORDER_MAX_TIMEOUT_MS);

	spin_lock_bh(&rb->buffer_lock);
	rb->gap_timeout_ms = timeout_ms;
	spin_unlock_bh(&rb->buffer_lock);

	pr_debug("updated gap timeout to %u ms\n", timeout_ms);
}
EXPORT_SYMBOL_GPL(tquic_reorder_update_timeout);

/**
 * tquic_reorder_update_rtt - Update path RTT for adaptive sizing
 * @rb: Reorder buffer
 * @path_rtt_us: RTT measurement in microseconds
 * @is_min: True if this is currently the minimum RTT path
 *
 * Tracks min/max RTT across paths to calculate RTT spread.
 */
void tquic_reorder_update_rtt(struct tquic_reorder_buffer *rb, u32 path_rtt_us,
			      bool is_min)
{
	u32 new_timeout;

	if (!rb || path_rtt_us == 0)
		return;

	spin_lock_bh(&rb->buffer_lock);

	if (path_rtt_us < rb->min_path_rtt)
		rb->min_path_rtt = path_rtt_us;
	if (path_rtt_us > rb->max_path_rtt)
		rb->max_path_rtt = path_rtt_us;

	/* Calculate RTT spread */
	if (rb->min_path_rtt != UINT_MAX && rb->max_path_rtt > rb->min_path_rtt)
		rb->rtt_spread = rb->max_path_rtt - rb->min_path_rtt;
	else
		rb->rtt_spread = 0;

	/* Adaptive gap timeout: 2 * rtt_spread + margin */
	if (rb->rtt_spread > 0) {
		new_timeout = (rb->rtt_spread / 1000) * 2 +
			      TQUIC_REORDER_GAP_TIMEOUT_MARGIN_MS;
		new_timeout = clamp(new_timeout,
				    (u32)TQUIC_REORDER_MIN_TIMEOUT_MS,
				    (u32)TQUIC_REORDER_MAX_TIMEOUT_MS);
		rb->gap_timeout_ms = new_timeout;
	}

	spin_unlock_bh(&rb->buffer_lock);

	pr_debug("RTT updated: min=%u max=%u spread=%u timeout=%u\n",
		 rb->min_path_rtt, rb->max_path_rtt, rb->rtt_spread,
		 rb->gap_timeout_ms);
}
EXPORT_SYMBOL_GPL(tquic_reorder_update_rtt);

/**
 * tquic_reorder_adapt_size - Adapt buffer size based on bandwidth/RTT
 * @rb: Reorder buffer
 * @aggregate_bandwidth: Total bandwidth across all paths (bytes/sec)
 *
 * Buffer size = rtt_spread_ms * bandwidth_bytes_per_ms * 2 (safety)
 */
void tquic_reorder_adapt_size(struct tquic_reorder_buffer *rb,
			      u64 aggregate_bandwidth)
{
	size_t new_size;
	u32 spread_ms;

	if (!rb || aggregate_bandwidth == 0)
		return;

	spin_lock_bh(&rb->buffer_lock);

	if (rb->rtt_spread == 0) {
		spin_unlock_bh(&rb->buffer_lock);
		return;
	}

	/* Calculate: spread_ms * bandwidth_bytes_per_ms * 2 */
	spread_ms = rb->rtt_spread / 1000;
	new_size = ((u64)spread_ms * (aggregate_bandwidth / 1000)) * 2;

	/* Clamp to limits */
	new_size = clamp(new_size, (size_t)TQUIC_REORDER_MIN_BUFFER,
			 (size_t)TQUIC_REORDER_MAX_BUFFER);

	rb->max_buffer_bytes = new_size;

	spin_unlock_bh(&rb->buffer_lock);

	pr_debug("adapted buffer size to %zu bytes (spread=%ums bw=%llu)\n",
		 new_size, spread_ms, aggregate_bandwidth);
}
EXPORT_SYMBOL_GPL(tquic_reorder_adapt_size);

/**
 * tquic_reorder_get_stats - Get reorder buffer statistics
 * @rb: Reorder buffer
 * @stats: Output statistics structure
 */
void tquic_reorder_get_stats(struct tquic_reorder_buffer *rb,
			     struct tquic_reorder_stats *stats)
{
	if (!rb || !stats)
		return;

	spin_lock_bh(&rb->buffer_lock);
	memcpy(stats, &rb->stats, sizeof(*stats));
	spin_unlock_bh(&rb->buffer_lock);
}
EXPORT_SYMBOL_GPL(tquic_reorder_get_stats);

MODULE_DESCRIPTION("TQUIC Adaptive Reorder Buffer for WAN Bonding");
MODULE_LICENSE("GPL");
MODULE_AUTHOR("Linux Foundation");
