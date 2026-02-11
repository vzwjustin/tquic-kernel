/* SPDX-License-Identifier: GPL-2.0 */
/*
 * TQUIC Adaptive Reorder Buffer for WAN Bonding
 *
 * Copyright (c) 2026 Justin Adams <spotty118@gmail.com>
 * Kernel implementation by Justin Adams <spotty118@gmail.com>
 *
 * Provides RB-tree based out-of-order packet buffering for multi-path
 * bandwidth aggregation with heterogeneous latencies (fiber + satellite).
 *
 * Based on MPTCP's out_of_order_queue pattern from net/mptcp/protocol.c.
 */

#ifndef _TQUIC_REORDER_H
#define _TQUIC_REORDER_H

#include <linux/types.h>
#include <linux/rbtree.h>
#include <linux/skbuff.h>
#include <linux/spinlock.h>
#include <linux/workqueue.h>
#include <linux/ktime.h>

/*
 * Reorder buffer configuration constants
 */
#define TQUIC_REORDER_MIN_BUFFER	(64 * 1024)	/* 64KB minimum */
#define TQUIC_REORDER_DEFAULT_BUFFER	(256 * 1024)	/* 256KB default */
#define TQUIC_REORDER_MAX_BUFFER	(4 * 1024 * 1024) /* 4MB max */

/* Default gap timeout: 2 * max_rtt_spread + margin */
#define TQUIC_REORDER_DEFAULT_TIMEOUT_MS	1300	/* For 600ms spread */
#define TQUIC_REORDER_MIN_TIMEOUT_MS		50
#define TQUIC_REORDER_MAX_TIMEOUT_MS		5000
#define TQUIC_REORDER_GAP_TIMEOUT_MARGIN_MS	100	/* Safety margin */

/*
 * SKB control block for reorder buffer sequence tracking
 *
 * Stored in skb->cb to track packet sequence number and arrival.
 */
struct tquic_reorder_cb {
	u64		seq;		/* Data sequence number */
	u32		len;		/* Data length */
	u8		path_id;	/* Path packet arrived on */
	ktime_t		arrival;	/* Arrival timestamp */
};

#define TQUIC_REORDER_CB(__skb)	\
	((struct tquic_reorder_cb *)&((__skb)->cb[0]))

/*
 * Reorder buffer statistics
 */
struct tquic_reorder_stats {
	u64	in_order_packets;	/* Delivered immediately in order */
	u64	buffered_packets;	/* Stored in buffer (out of order) */
	u64	delivered_packets;	/* Delivered from buffer (gap filled) */
	u64	gap_timeout_packets;	/* Delivered due to gap timeout */
	u64	dropped_packets;	/* Dropped (buffer full or old) */
	u64	duplicate_packets;	/* Duplicates detected */
	u64	buffer_peak_bytes;	/* Peak buffer usage */
};

/*
 * Adaptive reorder buffer using RB-tree
 *
 * Provides O(log n) insertion and efficient in-order delivery.
 * Handles heterogeneous latency paths (fiber ~20ms + satellite ~600ms).
 *
 * LOCKING:
 *   buffer_lock protects all buffer state.
 *   Can be called from BH context (softirq).
 */
struct tquic_reorder_buffer {
	/* RB-tree queue of out-of-order packets */
	struct rb_root	queue;		/* RB-tree root */
	struct sk_buff	*last_skb;	/* Fast path: last inserted skb */

	/* Sequence tracking */
	u64		next_expected;	/* Next sequence to deliver */
	u64		max_buffered;	/* Highest sequence in buffer */

	/* Buffer size management */
	size_t		buffer_bytes;	/* Current buffer usage (bytes) */
	size_t		max_buffer_bytes; /* Memory limit (sysctl) */
	u32		packet_count;	/* Number of buffered packets */

	/* Gap timeout handling */
	u32		gap_timeout_ms;	/* Gap timeout in milliseconds */
	ktime_t		oldest_arrival;	/* Arrival time of oldest packet */
	struct delayed_work timeout_work; /* Gap timeout work */
	bool		timeout_scheduled; /* Timeout work pending */

	/* RTT-based adaptive sizing */
	u32		min_path_rtt;	/* Minimum RTT across paths (us) */
	u32		max_path_rtt;	/* Maximum RTT across paths (us) */
	u32		rtt_spread;	/* max_rtt - min_rtt (us) */

	/* Locking */
	spinlock_t	buffer_lock;

	/* Statistics */
	struct tquic_reorder_stats stats;

	/* Back pointer */
	void		*priv;		/* Connection context */
	struct workqueue_struct *wq;	/* Workqueue for timeout */

	/* Delivery callback for timeout-triggered flushes */
	void		(*deliver_fn)(void *ctx, struct sk_buff *skb);
	void		*deliver_ctx;
};

/*
 * Reorder buffer API
 */

/* Lifecycle */
struct tquic_reorder_buffer *tquic_reorder_alloc(gfp_t gfp);
void tquic_reorder_destroy(struct tquic_reorder_buffer *rb);
int tquic_reorder_init(struct tquic_reorder_buffer *rb, size_t max_bytes,
		       struct workqueue_struct *wq, void *priv);

/* Core operations */
int tquic_reorder_insert(struct tquic_reorder_buffer *rb, struct sk_buff *skb,
			 u64 seq, u32 len, u8 path_id);
int tquic_reorder_drain(struct tquic_reorder_buffer *rb,
			void (*deliver)(void *ctx, struct sk_buff *skb),
			void *ctx);

/* Set delivery callback for timeout-triggered flushes */
void tquic_reorder_set_deliver(struct tquic_reorder_buffer *rb,
			       void (*deliver)(void *ctx, struct sk_buff *skb),
			       void *ctx);

/* Gap timeout */
void tquic_reorder_flush_timeout(struct tquic_reorder_buffer *rb,
				 void (*deliver)(void *ctx, struct sk_buff *skb),
				 void *ctx);
void tquic_reorder_update_timeout(struct tquic_reorder_buffer *rb,
				  u32 timeout_ms);

/* Adaptive sizing based on path RTT spread */
void tquic_reorder_update_rtt(struct tquic_reorder_buffer *rb,
			      u32 path_rtt_us, bool is_min);
void tquic_reorder_adapt_size(struct tquic_reorder_buffer *rb,
			      u64 aggregate_bandwidth);

/* Query functions */
static inline bool tquic_reorder_empty(struct tquic_reorder_buffer *rb)
{
	return RB_EMPTY_ROOT(&rb->queue);
}

static inline size_t tquic_reorder_bytes(struct tquic_reorder_buffer *rb)
{
	return READ_ONCE(rb->buffer_bytes);
}

static inline u32 tquic_reorder_count(struct tquic_reorder_buffer *rb)
{
	return READ_ONCE(rb->packet_count);
}

static inline u64 tquic_reorder_next_expected(struct tquic_reorder_buffer *rb)
{
	return READ_ONCE(rb->next_expected);
}

void tquic_reorder_get_stats(struct tquic_reorder_buffer *rb,
			     struct tquic_reorder_stats *stats);

/* Set next expected sequence (for connection setup) */
static inline void tquic_reorder_set_next_expected(
		struct tquic_reorder_buffer *rb, u64 seq)
{
	WRITE_ONCE(rb->next_expected, seq);
}

#endif /* _TQUIC_REORDER_H */
