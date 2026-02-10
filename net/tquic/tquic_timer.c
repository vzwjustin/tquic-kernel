// SPDX-License-Identifier: GPL-2.0-only
/*
 * TQUIC: Timer and Recovery System
 *
 * Copyright (c) 2026 Linux Foundation
 *
 * Implements comprehensive timer management for QUIC protocol operations
 * including loss detection, retransmission, pacing, and connection lifecycle.
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/timer.h>
#include <linux/hrtimer.h>
#include <linux/workqueue.h>
#include <linux/spinlock.h>
#include <linux/rbtree.h>
#include <linux/list.h>
#include <linux/skbuff.h>
#include <linux/jiffies.h>
#include <linux/refcount.h>
#include <linux/completion.h>
#include <net/tquic.h>
#include "cong/tquic_cong.h"

#include "tquic_compat.h"
#include "tquic_debug.h"

/* Forward declaration from core/quic_loss.c */
void tquic_set_loss_detection_timer(struct tquic_connection *conn);

/* Timer configuration constants (in microseconds unless noted) */
#define TQUIC_TIMER_GRANULARITY_US	1000		/* 1ms granularity */
#define TQUIC_INITIAL_RTT_US		333000		/* 333ms initial RTT */
#define TQUIC_MAX_ACK_DELAY_US		25000		/* 25ms max ACK delay */
#define TQUIC_DEFAULT_ACK_DELAY_US	25000		/* 25ms default */
#define TQUIC_ACK_DELAY_EXPONENT	3		/* 2^3 = 8 */
#define TQUIC_PTO_MULTIPLIER		2		/* PTO = 2 * smoothed_rtt */
#define TQUIC_MAX_PTO_COUNT		6		/* Max PTO probes */
#define TQUIC_PATH_CHALLENGE_TIMEOUT_MS	3000		/* 3s path validation */
#define TQUIC_PATH_CHALLENGE_RETRIES	3		/* Max path probes */
#define TQUIC_DRAIN_TIMEOUT_MULTIPLIER	3		/* 3 * PTO for draining */
#define TQUIC_KEEPALIVE_TIMEOUT_MS	15000		/* 15s default */
#define TQUIC_MIN_PACING_INTERVAL_NS	1000		/* 1us minimum */

/* Loss detection constants */
#define TQUIC_PACKET_THRESHOLD		3		/* Packet reorder threshold */
#define TQUIC_TIME_THRESHOLD_DIVISOR	8		/* 9/8 of max(RTT, latest_rtt) */
#define TQUIC_LOSS_REDUCTION_FACTOR	2		/* Halve cwnd on loss */
#define TQUIC_PERSISTENT_CONGESTION_THRESHOLD 3		/* PTOs for persistent cong */

/* Packet state for sent packet tracking */
enum tquic_pkt_state {
	TQUIC_PKT_OUTSTANDING,		/* Awaiting ACK */
	TQUIC_PKT_ACKED,		/* ACKed by peer */
	TQUIC_PKT_LOST,			/* Declared lost */
	TQUIC_PKT_RETRANSMITTED,	/* Retransmission scheduled */
};

/**
 * struct tquic_sent_packet - Metadata for sent packet tracking
 * @node: RB-tree node for packet number ordering
 * @list: List linkage for time-ordered traversal
 * @pkt_num: Packet number
 * @pn_space: Packet number space (Initial/Handshake/Application)
 * @path_id: Path this packet was sent on
 * @state: Current packet state
 * @ack_eliciting: True if packet requires acknowledgment
 * @in_flight: True if counted against congestion window
 * @sent_time: Timestamp when packet was sent
 * @sent_bytes: Size of packet in bytes
 * @frames: Bitmask of frame types included
 * @retrans_of: Packet number this is a retransmission of (or 0)
 */
struct tquic_sent_packet {
	struct rb_node node;
	struct list_head list;
	u64 pkt_num;
	u8 pn_space;
	u32 path_id;
	enum tquic_pkt_state state;
	bool ack_eliciting;
	bool in_flight;
	ktime_t sent_time;
	u32 sent_bytes;
	u32 frames;
	u64 retrans_of;
};

/**
 * struct tquic_pn_space - Per packet-number-space state
 * @largest_acked: Largest acknowledged packet number
 * @largest_sent: Largest sent packet number
 * @loss_time: Time for next time-based loss detection
 * @last_ack_time: Time of last ACK in this space
 * @ack_eliciting_in_flight: Count of ack-eliciting packets in flight
 * @sent_packets: RB-tree of sent packets by packet number
 * @sent_list: Time-ordered list of sent packets
 * @pending_acks: Packet numbers waiting to be ACKed
 * @pending_ack_count: Number of pending ACKs
 * @lock: Per-space lock
 */
#ifndef TQUIC_PN_SPACE_DEFINED
#define TQUIC_PN_SPACE_DEFINED
struct tquic_pn_space {
	u64 largest_acked;
	u64 largest_sent;
	ktime_t loss_time;
	ktime_t last_ack_time;
	u32 ack_eliciting_in_flight;

	struct rb_root sent_packets;
	struct list_head sent_list;

	u64 *pending_acks;
	u32 pending_ack_count;
	u32 pending_ack_capacity;

	spinlock_t lock;
};
#endif /* TQUIC_PN_SPACE_DEFINED */

/**
 * struct tquic_recovery_state - Connection recovery state
 * @conn: Parent connection
 * @pn_spaces: Per packet-number-space state
 * @smoothed_rtt: Smoothed RTT estimate (us)
 * @rtt_variance: RTT variance (us)
 * @min_rtt: Minimum RTT observed (us)
 * @latest_rtt: Most recent RTT sample (us)
 * @first_rtt_sample: Time of first RTT sample
 * @max_ack_delay: Peer's max ACK delay (us)
 * @pto_count: Number of PTO events without ACK
 * @bytes_in_flight: Total bytes outstanding
 * @congestion_window: Current congestion window
 * @ssthresh: Slow start threshold
 * @congestion_recovery_start: Time congestion recovery started
 * @persistent_congestion_start: Start of potential persistent congestion
 * @in_persistent_congestion: Currently in persistent congestion
 * @lock: Recovery state lock
 */
struct tquic_recovery_state {
	struct tquic_connection *conn;

	struct tquic_pn_space pn_spaces[TQUIC_PN_SPACE_COUNT];

	/* RTT estimation */
	u64 smoothed_rtt;
	u64 rtt_variance;
	u64 min_rtt;
	u64 latest_rtt;
	ktime_t first_rtt_sample;
	u64 max_ack_delay;

	/* PTO state */
	u32 pto_count;

	/* Congestion state */
	u64 bytes_in_flight;
	u64 congestion_window;
	u64 ssthresh;
	ktime_t congestion_recovery_start;
	ktime_t persistent_congestion_start;
	bool in_persistent_congestion;

	spinlock_t lock;
};

/**
 * struct tquic_timer_state - Connection timer state
 * @conn: Parent connection
 * @recovery: Recovery state reference
 * @idle_timer: Idle timeout timer
 * @ack_delay_timer: Delayed ACK timer
 * @loss_timer: Loss detection timer
 * @pto_timer: Probe timeout timer
 * @drain_timer: Connection draining timer
 * @keepalive_timer: Keep-alive timer
 * @pacing_timer: Packet pacing timer (high resolution)
 * @timer_work: Workqueue work for deferred timer processing
 * @retransmit_work: Workqueue work for retransmissions
 * @path_work: Workqueue work for path management
 * @wq: Dedicated workqueue
 * @pending_timer_mask: Bitmask of pending timer types
 * @idle_timeout_us: Configured idle timeout
 * @keepalive_interval_us: Keep-alive interval
 * @ack_delay_us: Current ACK delay setting
 * @next_pacing_time: Next allowed send time for pacing
 * @pacing_rate: Current pacing rate (bytes/s)
 * @pacing_burst: Packets to send in current burst
 * @active: Timer state is active
 * @shutting_down: Timer state is shutting down
 * @lock: Timer state lock
 * @completion: Completion for shutdown synchronization
 */
struct tquic_timer_state {
	struct tquic_connection *conn;
	struct tquic_recovery_state *recovery;

	/* Standard kernel timers */
	struct timer_list idle_timer;
	struct timer_list ack_delay_timer;
	struct timer_list loss_timer;
	struct timer_list pto_timer;
	struct timer_list drain_timer;
	struct timer_list keepalive_timer;

	/* High-resolution timer for pacing */
	struct hrtimer pacing_timer;

	/* Workqueue for deferred processing */
	struct work_struct timer_work;
	struct work_struct retransmit_work;
	struct work_struct path_work;
	struct workqueue_struct *wq;

	/* Timer state tracking */
	unsigned long pending_timer_mask;
#define TQUIC_TIMER_IDLE_BIT		0
#define TQUIC_TIMER_ACK_DELAY_BIT	1
#define TQUIC_TIMER_LOSS_BIT		2
#define TQUIC_TIMER_PTO_BIT		3
#define TQUIC_TIMER_DRAIN_BIT		4
#define TQUIC_TIMER_KEEPALIVE_BIT	5
#define TQUIC_TIMER_PACING_BIT		6

	/* Configuration */
	u64 idle_timeout_us;
	u64 keepalive_interval_us;
	u64 ack_delay_us;

	/* Pacing state */
	ktime_t next_pacing_time;
	u64 pacing_rate;
	u32 pacing_burst;

	/* Lifecycle */
	bool active;
	bool shutting_down;
	spinlock_t lock;
	struct completion completion;
};

/* Per-path timer state for path validation */
struct tquic_path_timer_state {
	struct tquic_path *path;
	struct timer_list validation_timer;
	struct work_struct validation_work;
	u8 challenge_data[8];
	u8 probe_count;
	bool validation_pending;
	ktime_t validation_start;
};

/* Global workqueue for timer processing */
static struct workqueue_struct *tquic_timer_wq;

/* Slab cache for sent packet metadata */
static struct kmem_cache *tquic_sent_pkt_cache;

/* Forward declarations */
static void tquic_timer_idle_expired(struct timer_list *t);
static void tquic_timer_ack_delay_expired(struct timer_list *t);
static void tquic_timer_loss_expired(struct timer_list *t);
static void tquic_timer_pto_expired(struct timer_list *t);
static void tquic_timer_drain_expired(struct timer_list *t);
static void tquic_timer_keepalive_expired(struct timer_list *t);
static enum hrtimer_restart tquic_timer_pacing_expired(struct hrtimer *t);
static void tquic_timer_work_fn(struct work_struct *work);
static void tquic_retransmit_work_fn(struct work_struct *work);
static void tquic_path_work_fn(struct work_struct *work);
static void tquic_path_validation_expired(struct timer_list *t);

/*
 * ============================================================================
 * RTT Estimation
 * ============================================================================
 */

/**
 * tquic_update_rtt - Update RTT estimates from an ACK
 * @recovery: Recovery state
 * @ack_delay: ACK delay reported by peer (us)
 * @rtt_sample: RTT sample from this ACK (us)
 * @is_handshake: True if this is a handshake packet
 */
static void tquic_update_rtt(struct tquic_recovery_state *recovery,
			     u64 ack_delay, u64 rtt_sample, bool is_handshake)
{
	/* Update minimum RTT (no smoothing) */
	if (rtt_sample < recovery->min_rtt)
		recovery->min_rtt = rtt_sample;

	/* First RTT sample */
	if (recovery->smoothed_rtt == 0) {
		recovery->smoothed_rtt = rtt_sample;
		recovery->rtt_variance = rtt_sample / 2;
		recovery->first_rtt_sample = ktime_get();
		recovery->latest_rtt = rtt_sample;
		return;
	}

	recovery->latest_rtt = rtt_sample;

	/*
	 * Adjust for ACK delay, but only for application data and only
	 * if the adjusted RTT is still larger than min_rtt
	 */
	if (!is_handshake) {
		u64 adjusted_rtt;

		ack_delay = min(ack_delay, recovery->max_ack_delay);
		adjusted_rtt = rtt_sample > ack_delay ?
			       rtt_sample - ack_delay : rtt_sample;

		if (adjusted_rtt >= recovery->min_rtt)
			rtt_sample = adjusted_rtt;
	}

	/* RFC 9002 EWMA update */
	recovery->rtt_variance = (3 * recovery->rtt_variance +
				  abs((s64)recovery->smoothed_rtt - (s64)rtt_sample)) / 4;
	recovery->smoothed_rtt = (7 * recovery->smoothed_rtt + rtt_sample) / 8;
}

/**
 * tquic_get_pto_duration - Calculate PTO duration
 * @recovery: Recovery state
 * @pn_space: Packet number space
 *
 * Returns: PTO duration in microseconds
 */
static u64 tquic_get_pto_duration(struct tquic_recovery_state *recovery,
				  int pn_space)
{
	u64 pto;

	/* PTO = smoothed_rtt + max(4 * rtt_variance, granularity) + max_ack_delay */
	pto = recovery->smoothed_rtt +
	      max(4 * recovery->rtt_variance, (u64)TQUIC_TIMER_GRANULARITY_US);

	/* Include max_ack_delay only for application data */
	if (pn_space == TQUIC_PN_SPACE_APPLICATION)
		pto += recovery->max_ack_delay;

	return pto;
}

/**
 * tquic_get_loss_time_threshold - Calculate time-based loss threshold
 * @recovery: Recovery state
 *
 * Returns: Loss time threshold in microseconds
 */
static u64 tquic_get_loss_time_threshold(struct tquic_recovery_state *recovery)
{
	u64 rtt = max(recovery->latest_rtt, recovery->smoothed_rtt);

	/* 9/8 * max(latest_rtt, smoothed_rtt) */
	return rtt + rtt / TQUIC_TIME_THRESHOLD_DIVISOR;
}

/*
 * ============================================================================
 * Sent Packet Management
 * ============================================================================
 */

/**
 * tquic_sent_pkt_alloc - Allocate sent packet metadata
 * @gfp: Allocation flags
 *
 * Returns: Allocated packet metadata or NULL
 */
static struct tquic_sent_packet *tquic_sent_pkt_alloc(gfp_t gfp)
{
	struct tquic_sent_packet *pkt;

	pkt = kmem_cache_zalloc(tquic_sent_pkt_cache, gfp);
	if (pkt) {
		RB_CLEAR_NODE(&pkt->node);
		INIT_LIST_HEAD(&pkt->list);
	}

	return pkt;
}

/**
 * tquic_sent_pkt_free - Free sent packet metadata
 * @pkt: Packet to free
 */
static void tquic_sent_pkt_free(struct tquic_sent_packet *pkt)
{
	if (pkt)
		kmem_cache_free(tquic_sent_pkt_cache, pkt);
}

/**
 * tquic_sent_pkt_insert - Insert sent packet into tracking structures
 * @pn_space: Packet number space
 * @pkt: Packet to insert
 */
static void tquic_sent_pkt_insert(struct tquic_pn_space *pn_space,
				  struct tquic_sent_packet *pkt)
{
	struct rb_node **link, *parent = NULL;
	struct tquic_sent_packet *entry;

	/* Insert into RB-tree by packet number */
	link = &pn_space->sent_packets.rb_node;
	while (*link) {
		parent = *link;
		entry = rb_entry(parent, struct tquic_sent_packet, node);

		if (pkt->pkt_num < entry->pkt_num)
			link = &parent->rb_left;
		else
			link = &parent->rb_right;
	}

	rb_link_node(&pkt->node, parent, link);
	rb_insert_color(&pkt->node, &pn_space->sent_packets);

	/* Append to time-ordered list */
	list_add_tail(&pkt->list, &pn_space->sent_list);
}

/**
 * tquic_sent_pkt_remove - Remove sent packet from tracking
 * @pn_space: Packet number space
 * @pkt: Packet to remove
 */
static void tquic_sent_pkt_remove(struct tquic_pn_space *pn_space,
				  struct tquic_sent_packet *pkt)
{
	if (!RB_EMPTY_NODE(&pkt->node))
		rb_erase(&pkt->node, &pn_space->sent_packets);

	list_del_init(&pkt->list);
}

/**
 * tquic_sent_pkt_find - Find sent packet by packet number
 * @pn_space: Packet number space
 * @pkt_num: Packet number to find
 *
 * Returns: Found packet or NULL
 */
static struct tquic_sent_packet *tquic_sent_pkt_find(struct tquic_pn_space *pn_space,
						     u64 pkt_num)
{
	struct rb_node *node = pn_space->sent_packets.rb_node;

	while (node) {
		struct tquic_sent_packet *entry;

		entry = rb_entry(node, struct tquic_sent_packet, node);

		if (pkt_num < entry->pkt_num)
			node = node->rb_left;
		else if (pkt_num > entry->pkt_num)
			node = node->rb_right;
		else
			return entry;
	}

	return NULL;
}

/*
 * ============================================================================
 * Timer Management
 * ============================================================================
 */

/**
 * tquic_timer_state_alloc - Allocate timer state for a connection
 * @conn: Parent connection
 *
 * Returns: Allocated timer state or NULL
 */
struct tquic_timer_state *tquic_timer_state_alloc(struct tquic_connection *conn)
{
	struct tquic_timer_state *ts;
	struct tquic_recovery_state *rs;
	int i;

	ts = kzalloc(sizeof(*ts), GFP_KERNEL);
	if (!ts)
		return NULL;

	rs = kzalloc(sizeof(*rs), GFP_KERNEL);
	if (!rs) {
		kfree(ts);
		return NULL;
	}

	ts->conn = conn;
	ts->recovery = rs;
	rs->conn = conn;

	/* Initialize locks */
	spin_lock_init(&ts->lock);
	spin_lock_init(&rs->lock);

	/* Initialize completion for shutdown */
	init_completion(&ts->completion);

	/* Initialize packet number spaces */
	for (i = 0; i < TQUIC_PN_SPACE_COUNT; i++) {
		struct tquic_pn_space *pns = &rs->pn_spaces[i];

		spin_lock_init(&pns->lock);
		pns->sent_packets = RB_ROOT;
		INIT_LIST_HEAD(&pns->sent_list);
		pns->largest_acked = U64_MAX; /* Invalid initial value */
		pns->loss_time = KTIME_MAX;

		/* Allocate pending ACK buffer */
		pns->pending_ack_capacity = 64;
		pns->pending_acks = kcalloc(pns->pending_ack_capacity,
					    sizeof(u64), GFP_KERNEL);
		if (!pns->pending_acks)
			goto err_free;
	}

	/* Initialize RTT estimates */
	rs->smoothed_rtt = TQUIC_INITIAL_RTT_US;
	rs->rtt_variance = TQUIC_INITIAL_RTT_US / 2;
	rs->min_rtt = U64_MAX;
	rs->max_ack_delay = TQUIC_DEFAULT_ACK_DELAY_US;

	/* Initialize congestion state */
	rs->congestion_window = 10 * 1200; /* 10 packets initial window */
	rs->ssthresh = U64_MAX;

	/* Setup standard timers */
	timer_setup(&ts->idle_timer, tquic_timer_idle_expired, 0);
	timer_setup(&ts->ack_delay_timer, tquic_timer_ack_delay_expired, 0);
	timer_setup(&ts->loss_timer, tquic_timer_loss_expired, 0);
	timer_setup(&ts->pto_timer, tquic_timer_pto_expired, 0);
	timer_setup(&ts->drain_timer, tquic_timer_drain_expired, 0);
	timer_setup(&ts->keepalive_timer, tquic_timer_keepalive_expired, 0);

	/* Setup high-resolution pacing timer */
	hrtimer_setup(&ts->pacing_timer, tquic_timer_pacing_expired,
		      CLOCK_MONOTONIC, HRTIMER_MODE_REL);

	/* Setup workqueue items */
	INIT_WORK(&ts->timer_work, tquic_timer_work_fn);
	INIT_WORK(&ts->retransmit_work, tquic_retransmit_work_fn);
	INIT_WORK(&ts->path_work, tquic_path_work_fn);

	/* Use global timer workqueue */
	ts->wq = tquic_timer_wq;

	/* Set defaults */
	ts->idle_timeout_us = conn->idle_timeout * 1000ULL;
	ts->keepalive_interval_us = TQUIC_KEEPALIVE_TIMEOUT_MS * 1000ULL;
	ts->ack_delay_us = TQUIC_DEFAULT_ACK_DELAY_US;
	ts->pacing_rate = 1200 * 100; /* Initial: 100 packets per second */

	ts->active = true;

	tquic_dbg("timer:allocated state for connection\n");

	return ts;

err_free:
	for (i = 0; i < TQUIC_PN_SPACE_COUNT; i++)
		kfree(rs->pn_spaces[i].pending_acks);
	kfree(rs);
	kfree(ts);
	return NULL;
}
EXPORT_SYMBOL_GPL(tquic_timer_state_alloc);

/**
 * tquic_timer_state_free - Free timer state
 * @ts: Timer state to free
 */
void tquic_timer_state_free(struct tquic_timer_state *ts)
{
	struct tquic_recovery_state *rs;
	unsigned long flags;
	int i;

	if (!ts)
		return;

	/* Mark as shutting down */
	spin_lock_irqsave(&ts->lock, flags);
	ts->shutting_down = true;
	ts->active = false;
	spin_unlock_irqrestore(&ts->lock, flags);

	/* Cancel all timers */
	del_timer_sync(&ts->idle_timer);
	del_timer_sync(&ts->ack_delay_timer);
	del_timer_sync(&ts->loss_timer);
	del_timer_sync(&ts->pto_timer);
	del_timer_sync(&ts->drain_timer);
	del_timer_sync(&ts->keepalive_timer);
	hrtimer_cancel(&ts->pacing_timer);

	/* Flush workqueue items */
	if (ts->wq) {
		cancel_work_sync(&ts->timer_work);
		cancel_work_sync(&ts->retransmit_work);
		cancel_work_sync(&ts->path_work);
	}

	rs = ts->recovery;
	if (rs) {
		/* Free packet number space resources */
		for (i = 0; i < TQUIC_PN_SPACE_COUNT; i++) {
			struct tquic_pn_space *pns = &rs->pn_spaces[i];
			struct tquic_sent_packet *pkt, *tmp;

			spin_lock_bh(&pns->lock);
			list_for_each_entry_safe(pkt, tmp, &pns->sent_list, list) {
				tquic_sent_pkt_remove(pns, pkt);
				tquic_sent_pkt_free(pkt);
			}
			spin_unlock_bh(&pns->lock);

			kfree(pns->pending_acks);
		}
		kfree(rs);
	}

	tquic_dbg("timer:freed state\n");

	kfree(ts);
}
EXPORT_SYMBOL_GPL(tquic_timer_state_free);

/*
 * ============================================================================
 * Idle Timeout Timer
 * ============================================================================
 */

/**
 * tquic_timer_idle_expired - Idle timeout timer callback
 * @t: Timer that expired
 */
static void tquic_timer_idle_expired(struct timer_list *t)
{
	struct tquic_timer_state *ts = from_timer(ts, t, idle_timer);
	struct tquic_connection *conn;
	unsigned long flags;

	spin_lock_irqsave(&ts->lock, flags);
	if (!ts->active || ts->shutting_down) {
		spin_unlock_irqrestore(&ts->lock, flags);
		return;
	}

	conn = ts->conn;
	set_bit(TQUIC_TIMER_IDLE_BIT, &ts->pending_timer_mask);
	spin_unlock_irqrestore(&ts->lock, flags);

	/* Schedule work to handle connection close */
	queue_work(ts->wq, &ts->timer_work);

	tquic_dbg("timer:idle timeout expired\n");
}

/**
 * tquic_timer_set_idle - Set or reset idle timeout timer
 * @ts: Timer state
 */
void tquic_timer_set_idle(struct tquic_timer_state *ts)
{
	unsigned long expires, flags;

	spin_lock_irqsave(&ts->lock, flags);
	if (!ts->active) {
		spin_unlock_irqrestore(&ts->lock, flags);
		return;
	}

	expires = jiffies + usecs_to_jiffies(ts->idle_timeout_us);
	mod_timer(&ts->idle_timer, expires);
	spin_unlock_irqrestore(&ts->lock, flags);
}
EXPORT_SYMBOL_GPL(tquic_timer_set_idle);

/**
 * tquic_timer_reset_idle - Reset idle timer on activity
 * @ts: Timer state
 */
void tquic_timer_reset_idle(struct tquic_timer_state *ts)
{
	tquic_timer_set_idle(ts);
}
EXPORT_SYMBOL_GPL(tquic_timer_reset_idle);

/*
 * ============================================================================
 * ACK Delay Timer
 * ============================================================================
 */

/**
 * tquic_timer_ack_delay_expired - ACK delay timer callback
 * @t: Timer that expired
 */
static void tquic_timer_ack_delay_expired(struct timer_list *t)
{
	struct tquic_timer_state *ts = from_timer(ts, t, ack_delay_timer);
	unsigned long flags;

	spin_lock_irqsave(&ts->lock, flags);
	if (!ts->active || ts->shutting_down) {
		spin_unlock_irqrestore(&ts->lock, flags);
		return;
	}

	set_bit(TQUIC_TIMER_ACK_DELAY_BIT, &ts->pending_timer_mask);
	spin_unlock_irqrestore(&ts->lock, flags);

	/* Schedule work to send pending ACKs */
	queue_work(ts->wq, &ts->timer_work);

	tquic_dbg("timer:ACK delay expired\n");
}

/**
 * tquic_timer_set_ack_delay - Set ACK delay timer
 * @ts: Timer state
 *
 * Called when receiving ack-eliciting packets that don't immediately
 * trigger an ACK.
 */
void tquic_timer_set_ack_delay(struct tquic_timer_state *ts)
{
	unsigned long expires, flags;

	spin_lock_irqsave(&ts->lock, flags);
	if (!ts->active) {
		spin_unlock_irqrestore(&ts->lock, flags);
		return;
	}

	/* Only set if not already pending */
	if (!timer_pending(&ts->ack_delay_timer)) {
		expires = jiffies + usecs_to_jiffies(ts->ack_delay_us);
		mod_timer(&ts->ack_delay_timer, expires);
	}
	spin_unlock_irqrestore(&ts->lock, flags);
}
EXPORT_SYMBOL_GPL(tquic_timer_set_ack_delay);

/**
 * tquic_timer_cancel_ack_delay - Cancel ACK delay timer
 * @ts: Timer state
 *
 * Called when an ACK is sent before the timer expires.
 */
void tquic_timer_cancel_ack_delay(struct tquic_timer_state *ts)
{
	unsigned long flags;

	spin_lock_irqsave(&ts->lock, flags);
	del_timer(&ts->ack_delay_timer);
	spin_unlock_irqrestore(&ts->lock, flags);
}
EXPORT_SYMBOL_GPL(tquic_timer_cancel_ack_delay);

/*
 * ============================================================================
 * Loss Detection Timer
 * ============================================================================
 */

/**
 * tquic_timer_loss_expired - Loss detection timer callback
 * @t: Timer that expired
 */
static void tquic_timer_loss_expired(struct timer_list *t)
{
	struct tquic_timer_state *ts = from_timer(ts, t, loss_timer);
	unsigned long flags;

	spin_lock_irqsave(&ts->lock, flags);
	if (!ts->active || ts->shutting_down) {
		spin_unlock_irqrestore(&ts->lock, flags);
		return;
	}

	set_bit(TQUIC_TIMER_LOSS_BIT, &ts->pending_timer_mask);
	spin_unlock_irqrestore(&ts->lock, flags);

	/* Schedule retransmission work */
	queue_work(ts->wq, &ts->retransmit_work);

	tquic_dbg("timer:loss timer expired\n");
}

/**
 * tquic_detect_lost_packets - Detect and mark lost packets
 * @ts: Timer state
 * @pn_space: Packet number space to check
 *
 * Returns: Number of packets declared lost
 */
static int tquic_detect_lost_packets(struct tquic_timer_state *ts, int pn_space)
{
	struct tquic_recovery_state *rs = ts->recovery;
	struct tquic_pn_space *pns = &rs->pn_spaces[pn_space];
	struct tquic_sent_packet *pkt, *tmp;
	u64 loss_delay;
	ktime_t now, lost_send_time;
	int lost_count = 0;

	if (pns->largest_acked == U64_MAX)
		return 0;

	now = ktime_get();
	loss_delay = tquic_get_loss_time_threshold(rs);
	lost_send_time = ktime_sub_us(now, loss_delay);

	spin_lock_bh(&pns->lock);

	list_for_each_entry_safe(pkt, tmp, &pns->sent_list, list) {
		if (pkt->pkt_num > pns->largest_acked)
			break;

		if (pkt->state != TQUIC_PKT_OUTSTANDING)
			continue;

		/*
		 * A packet is lost if:
		 * 1. It's more than PACKET_THRESHOLD older than largest_acked, OR
		 * 2. It was sent more than loss_delay ago
		 */
		if (pns->largest_acked >= pkt->pkt_num + TQUIC_PACKET_THRESHOLD ||
		    ktime_before(pkt->sent_time, lost_send_time)) {

			pkt->state = TQUIC_PKT_LOST;
			lost_count++;

			/* Update bytes in flight */
			if (pkt->in_flight) {
				spin_lock_bh(&rs->lock);
				rs->bytes_in_flight -= pkt->sent_bytes;
				spin_unlock_bh(&rs->lock);
			}

			/* Notify congestion controller of loss */
			if (ts->conn->active_path) {
				tquic_cong_on_loss(ts->conn->active_path,
						   pkt->sent_bytes);
			}

			tquic_dbg("timer:packet %llu declared lost\n",
				 pkt->pkt_num);
		}
	}

	/* Find earliest loss time for next timer */
	pns->loss_time = KTIME_MAX;
	list_for_each_entry(pkt, &pns->sent_list, list) {
		if (pkt->state != TQUIC_PKT_OUTSTANDING)
			continue;
		if (pkt->pkt_num >= pns->largest_acked)
			break;

		pns->loss_time = ktime_add_us(pkt->sent_time, loss_delay);
		break;
	}

	spin_unlock_bh(&pns->lock);

	return lost_count;
}

/**
 * tquic_timer_update_loss_timer - Update loss detection timer
 * @ts: Timer state
 */
void tquic_timer_update_loss_timer(struct tquic_timer_state *ts)
{
	struct tquic_recovery_state *rs = ts->recovery;
	ktime_t earliest_loss = KTIME_MAX;
	unsigned long expires, flags;
	int i;

	spin_lock_irqsave(&ts->lock, flags);
	if (!ts->active) {
		spin_unlock_irqrestore(&ts->lock, flags);
		return;
	}

	/* Find earliest loss time across all packet number spaces */
	for (i = 0; i < TQUIC_PN_SPACE_COUNT; i++) {
		struct tquic_pn_space *pns = &rs->pn_spaces[i];

		spin_lock(&pns->lock);
		if (ktime_before(pns->loss_time, earliest_loss))
			earliest_loss = pns->loss_time;
		spin_unlock(&pns->lock);
	}

	if (earliest_loss == KTIME_MAX) {
		del_timer(&ts->loss_timer);
	} else {
		s64 delay_us = ktime_us_delta(earliest_loss, ktime_get());

		if (delay_us <= 0)
			delay_us = 1;

		expires = jiffies + usecs_to_jiffies(delay_us);
		mod_timer(&ts->loss_timer, expires);
	}

	spin_unlock_irqrestore(&ts->lock, flags);
}
EXPORT_SYMBOL_GPL(tquic_timer_update_loss_timer);

/*
 * ============================================================================
 * Probe Timeout (PTO) Timer
 * ============================================================================
 */

/**
 * tquic_timer_pto_expired - PTO timer callback
 * @t: Timer that expired
 */
static void tquic_timer_pto_expired(struct timer_list *t)
{
	struct tquic_timer_state *ts = from_timer(ts, t, pto_timer);
	struct tquic_recovery_state *rs;
	unsigned long flags;

	spin_lock_irqsave(&ts->lock, flags);
	if (!ts->active || ts->shutting_down) {
		spin_unlock_irqrestore(&ts->lock, flags);
		return;
	}

	rs = ts->recovery;

	spin_lock(&rs->lock);
	rs->pto_count++;

	/* Check for persistent congestion */
	if (rs->pto_count >= TQUIC_PERSISTENT_CONGESTION_THRESHOLD &&
	    !rs->in_persistent_congestion) {
		rs->in_persistent_congestion = true;
		rs->congestion_window = 2 * 1200; /* Minimum window */
		rs->ssthresh = rs->congestion_window;
		tquic_dbg("timer:entering persistent congestion\n");
	}
	spin_unlock(&rs->lock);

	set_bit(TQUIC_TIMER_PTO_BIT, &ts->pending_timer_mask);
	spin_unlock_irqrestore(&ts->lock, flags);

	/* Schedule probe transmission */
	queue_work(ts->wq, &ts->retransmit_work);

	tquic_dbg("timer:PTO expired, count=%u\n", rs->pto_count);
}

/**
 * tquic_timer_update_pto - Update PTO timer
 * @ts: Timer state
 */
void tquic_timer_update_pto(struct tquic_timer_state *ts)
{
	struct tquic_recovery_state *rs = ts->recovery;
	ktime_t now, earliest_timeout = KTIME_MAX;
	unsigned long expires, flags;
	u64 pto_duration;
	int i;

	spin_lock_irqsave(&ts->lock, flags);
	if (!ts->active) {
		spin_unlock_irqrestore(&ts->lock, flags);
		return;
	}

	now = ktime_get();

	/* Check each packet number space */
	for (i = 0; i < TQUIC_PN_SPACE_COUNT; i++) {
		struct tquic_pn_space *pns = &rs->pn_spaces[i];
		ktime_t timeout;

		spin_lock(&pns->lock);
		if (pns->ack_eliciting_in_flight == 0) {
			spin_unlock(&pns->lock);
			continue;
		}

		/* Find earliest sent ack-eliciting packet */
		if (!list_empty(&pns->sent_list)) {
			struct tquic_sent_packet *pkt;

			list_for_each_entry(pkt, &pns->sent_list, list) {
				if (pkt->ack_eliciting &&
				    pkt->state == TQUIC_PKT_OUTSTANDING) {
					spin_lock(&rs->lock);
					pto_duration = tquic_get_pto_duration(rs, i);
					/*
				 * CF-214: Clamp pto_count to prevent
				 * undefined behavior from shifting past
				 * bit width, and cap exponential backoff.
				 */
				pto_duration *= (1ULL << min_t(u32, rs->pto_count, 16));
					spin_unlock(&rs->lock);

					/* Cap maximum PTO to 60 seconds (60,000,000 us) */
					if (pto_duration > 60000000ULL)
						pto_duration = 60000000ULL;

					timeout = ktime_add_us(pkt->sent_time, pto_duration);
					if (ktime_before(timeout, earliest_timeout))
						earliest_timeout = timeout;
					break;
				}
			}
		}
		spin_unlock(&pns->lock);
	}

	if (earliest_timeout == KTIME_MAX) {
		/* No ack-eliciting packets in flight */
		del_timer(&ts->pto_timer);
	} else {
		s64 delay_us = ktime_us_delta(earliest_timeout, now);

		if (delay_us <= 0)
			delay_us = 1;

		expires = jiffies + usecs_to_jiffies(delay_us);
		mod_timer(&ts->pto_timer, expires);
	}

	spin_unlock_irqrestore(&ts->lock, flags);
}
EXPORT_SYMBOL_GPL(tquic_timer_update_pto);

/*
 * ============================================================================
 * Connection Draining Timer
 * ============================================================================
 */

/**
 * tquic_timer_drain_expired - Drain timer callback
 * @t: Timer that expired
 */
static void tquic_timer_drain_expired(struct timer_list *t)
{
	struct tquic_timer_state *ts = from_timer(ts, t, drain_timer);
	unsigned long flags;

	spin_lock_irqsave(&ts->lock, flags);
	if (!ts->active || ts->shutting_down) {
		spin_unlock_irqrestore(&ts->lock, flags);
		return;
	}

	set_bit(TQUIC_TIMER_DRAIN_BIT, &ts->pending_timer_mask);
	spin_unlock_irqrestore(&ts->lock, flags);

	/* Schedule connection cleanup */
	queue_work(ts->wq, &ts->timer_work);

	tquic_dbg("timer:drain period completed\n");
}

/**
 * tquic_timer_start_drain - Start connection draining period
 * @ts: Timer state
 *
 * The draining period is 3 * PTO to allow any packets in transit
 * to be received before closing the connection.
 */
void tquic_timer_start_drain(struct tquic_timer_state *ts)
{
	struct tquic_recovery_state *rs = ts->recovery;
	unsigned long expires, flags;
	u64 drain_duration;

	spin_lock_irqsave(&ts->lock, flags);
	if (!ts->active) {
		spin_unlock_irqrestore(&ts->lock, flags);
		return;
	}

	/* Cancel other timers */
	del_timer(&ts->idle_timer);
	del_timer(&ts->ack_delay_timer);
	del_timer(&ts->loss_timer);
	del_timer(&ts->pto_timer);
	del_timer(&ts->keepalive_timer);

	/*
	 * Release ts->lock before hrtimer_cancel to avoid AB-BA deadlock:
	 * the pacing hrtimer callback takes ts->lock.
	 */
	spin_unlock_irqrestore(&ts->lock, flags);
	hrtimer_cancel(&ts->pacing_timer);
	spin_lock_irqsave(&ts->lock, flags);

	/* Set drain timeout to 3 * PTO */
	spin_lock(&rs->lock);
	drain_duration = TQUIC_DRAIN_TIMEOUT_MULTIPLIER *
			 tquic_get_pto_duration(rs, TQUIC_PN_SPACE_APPLICATION);
	spin_unlock(&rs->lock);

	expires = jiffies + usecs_to_jiffies(drain_duration);
	mod_timer(&ts->drain_timer, expires);

	spin_unlock_irqrestore(&ts->lock, flags);

	tquic_dbg("timer:started drain period, duration=%llu us\n",
		 drain_duration);
}
EXPORT_SYMBOL_GPL(tquic_timer_start_drain);

/*
 * ============================================================================
 * Keep-alive Timer
 * ============================================================================
 */

/**
 * tquic_timer_keepalive_expired - Keep-alive timer callback
 * @t: Timer that expired
 */
static void tquic_timer_keepalive_expired(struct timer_list *t)
{
	struct tquic_timer_state *ts = from_timer(ts, t, keepalive_timer);
	unsigned long flags;

	spin_lock_irqsave(&ts->lock, flags);
	if (!ts->active || ts->shutting_down) {
		spin_unlock_irqrestore(&ts->lock, flags);
		return;
	}

	set_bit(TQUIC_TIMER_KEEPALIVE_BIT, &ts->pending_timer_mask);
	spin_unlock_irqrestore(&ts->lock, flags);

	/* Schedule PING transmission */
	queue_work(ts->wq, &ts->timer_work);

	tquic_dbg("timer:keep-alive triggered\n");
}

/**
 * tquic_timer_set_keepalive - Set keep-alive timer
 * @ts: Timer state
 * @interval_ms: Keep-alive interval in milliseconds (0 to disable)
 */
void tquic_timer_set_keepalive(struct tquic_timer_state *ts, u32 interval_ms)
{
	unsigned long expires, flags;

	spin_lock_irqsave(&ts->lock, flags);
	if (!ts->active) {
		spin_unlock_irqrestore(&ts->lock, flags);
		return;
	}

	if (interval_ms == 0) {
		del_timer(&ts->keepalive_timer);
		ts->keepalive_interval_us = 0;
	} else {
		ts->keepalive_interval_us = (u64)interval_ms * 1000;
		expires = jiffies + msecs_to_jiffies(interval_ms);
		mod_timer(&ts->keepalive_timer, expires);
	}

	spin_unlock_irqrestore(&ts->lock, flags);
}
EXPORT_SYMBOL_GPL(tquic_timer_set_keepalive);

/**
 * tquic_timer_reset_keepalive - Reset keep-alive timer on activity
 * @ts: Timer state
 */
void tquic_timer_reset_keepalive(struct tquic_timer_state *ts)
{
	unsigned long expires, flags;

	spin_lock_irqsave(&ts->lock, flags);
	if (!ts->active || ts->keepalive_interval_us == 0) {
		spin_unlock_irqrestore(&ts->lock, flags);
		return;
	}

	expires = jiffies + usecs_to_jiffies(ts->keepalive_interval_us);
	mod_timer(&ts->keepalive_timer, expires);

	spin_unlock_irqrestore(&ts->lock, flags);
}
EXPORT_SYMBOL_GPL(tquic_timer_reset_keepalive);

/*
 * ============================================================================
 * Packet Pacing Timer (BBR support)
 * ============================================================================
 */

/**
 * tquic_timer_pacing_expired - Pacing timer callback (high resolution)
 * @t: High-resolution timer that expired
 *
 * Returns: Timer restart mode
 */
static enum hrtimer_restart tquic_timer_pacing_expired(struct hrtimer *t)
{
	struct tquic_timer_state *ts = container_of(t, struct tquic_timer_state,
						    pacing_timer);

	spin_lock(&ts->lock);
	if (!ts->active || ts->shutting_down) {
		spin_unlock(&ts->lock);
		return HRTIMER_NORESTART;
	}

	set_bit(TQUIC_TIMER_PACING_BIT, &ts->pending_timer_mask);
	ts->next_pacing_time = ktime_get();
	spin_unlock(&ts->lock);

	/* Schedule packet transmission from workqueue context */
	queue_work(ts->wq, &ts->timer_work);

	return HRTIMER_NORESTART;
}

/**
 * tquic_timer_schedule_pacing - Schedule next pacing timer
 * @ts: Timer state
 * @bytes_to_send: Number of bytes being sent
 *
 * Calculates the next send time based on pacing rate and schedules
 * the high-resolution timer.
 */
void tquic_timer_schedule_pacing(struct tquic_timer_state *ts, u32 bytes_to_send)
{
	ktime_t now, next_time;
	s64 interval_ns;
	unsigned long flags;

	spin_lock_irqsave(&ts->lock, flags);
	if (!ts->active || ts->pacing_rate == 0) {
		spin_unlock_irqrestore(&ts->lock, flags);
		return;
	}

	now = ktime_get();

	/* Calculate interval: bytes * 1e9 / rate */
	interval_ns = (s64)bytes_to_send * NSEC_PER_SEC / ts->pacing_rate;
	interval_ns = max_t(s64, interval_ns, TQUIC_MIN_PACING_INTERVAL_NS);

	next_time = ktime_add_ns(ts->next_pacing_time, interval_ns);

	/* Don't schedule in the past */
	if (ktime_before(next_time, now))
		next_time = ktime_add_ns(now, interval_ns);

	ts->next_pacing_time = next_time;

	hrtimer_start(&ts->pacing_timer, ktime_sub(next_time, now),
		      HRTIMER_MODE_REL);

	spin_unlock_irqrestore(&ts->lock, flags);
}
EXPORT_SYMBOL_GPL(tquic_timer_schedule_pacing);

/**
 * tquic_timer_set_pacing_rate - Set packet pacing rate
 * @ts: Timer state
 * @rate: Pacing rate in bytes per second
 */
void tquic_timer_set_pacing_rate(struct tquic_timer_state *ts, u64 rate)
{
	unsigned long flags;

	spin_lock_irqsave(&ts->lock, flags);
	ts->pacing_rate = rate;
	spin_unlock_irqrestore(&ts->lock, flags);
}
EXPORT_SYMBOL_GPL(tquic_timer_set_pacing_rate);

/**
 * tquic_timer_can_send_paced - Check if pacing allows sending
 * @ts: Timer state
 *
 * Returns: true if sending is allowed by pacing
 */
bool tquic_timer_can_send_paced(struct tquic_timer_state *ts)
{
	ktime_t now;
	bool can_send;
	unsigned long flags;

	spin_lock_irqsave(&ts->lock, flags);
	if (!ts->active || ts->pacing_rate == 0) {
		spin_unlock_irqrestore(&ts->lock, flags);
		return true;
	}

	now = ktime_get();
	can_send = !ktime_after(ts->next_pacing_time, now);
	spin_unlock_irqrestore(&ts->lock, flags);

	return can_send;
}
EXPORT_SYMBOL_GPL(tquic_timer_can_send_paced);

/*
 * ============================================================================
 * Path Validation Timer
 * ============================================================================
 */

/**
 * tquic_path_validation_expired - Path validation timer callback
 * @t: Timer that expired
 *
 * Called when path validation times out. Retries the PATH_CHALLENGE
 * or marks the path as failed after maximum retries.
 */
static void tquic_path_validation_expired(struct timer_list *t)
{
	struct tquic_path *path = from_timer(path, t, validation_timer);
	struct tquic_connection *conn;

	/* Get connection from path - use READ_ONCE for safe access */
	conn = READ_ONCE(path->conn);

	if (!conn)
		return;

	/* Ensure connection is still alive before accessing */
	if (!refcount_inc_not_zero(&conn->refcnt))
		return;

	spin_lock_bh(&conn->lock);

	/* Re-check path state under lock in case path was freed */
	if (path->state == TQUIC_PATH_FAILED) {
		spin_unlock_bh(&conn->lock);
		tquic_conn_put(conn);
		return;
	}

	path->probe_count++;

	if (path->probe_count >= TQUIC_PATH_CHALLENGE_RETRIES) {
		/* Path validation failed */
		path->state = TQUIC_PATH_FAILED;
		tquic_dbg("timer:path %u validation failed\n", path->path_id);
	} else {
		/* Retry path challenge */
		unsigned long expires;

		expires = jiffies + msecs_to_jiffies(TQUIC_PATH_CHALLENGE_TIMEOUT_MS);
		mod_timer(&path->validation_timer, expires);

		tquic_dbg("timer:path %u validation retry %u\n",
			 path->path_id, path->probe_count);
	}

	spin_unlock_bh(&conn->lock);
	tquic_conn_put(conn);
}

/**
 * tquic_timer_start_path_validation - Start path validation
 * @conn: Connection
 * @path: Path to validate
 */
void tquic_timer_start_path_validation(struct tquic_connection *conn,
				       struct tquic_path *path)
{
	unsigned long expires;

	spin_lock_bh(&conn->lock);

	path->state = TQUIC_PATH_PENDING;
	path->probe_count = 0;

	/* Generate new challenge data */
	get_random_bytes(path->challenge_data, sizeof(path->challenge_data));

	/* Setup validation timer */
	timer_setup(&path->validation_timer, tquic_path_validation_expired, 0);
	expires = jiffies + msecs_to_jiffies(TQUIC_PATH_CHALLENGE_TIMEOUT_MS);
	mod_timer(&path->validation_timer, expires);

	spin_unlock_bh(&conn->lock);

	tquic_dbg("timer:started path %u validation\n", path->path_id);
}
EXPORT_SYMBOL_GPL(tquic_timer_start_path_validation);

/**
 * tquic_timer_path_validated - Called when path validation succeeds
 * @conn: Connection
 * @path: Validated path
 */
void tquic_timer_path_validated(struct tquic_connection *conn,
				struct tquic_path *path)
{
	spin_lock_bh(&conn->lock);

	del_timer(&path->validation_timer);
	path->state = TQUIC_PATH_ACTIVE;
	path->probe_count = 0;

	spin_unlock_bh(&conn->lock);

	tquic_dbg("timer:path %u validated successfully\n", path->path_id);
}
EXPORT_SYMBOL_GPL(tquic_timer_path_validated);

/*
 * ============================================================================
 * Workqueue Handlers
 * ============================================================================
 */

/**
 * tquic_timer_work_fn - Main timer work function
 * @work: Work struct
 *
 * Lock ordering: ts->lock is acquired first, then conn->lock if needed.
 * The connection reference is held across the entire work function to
 * prevent use-after-free after dropping ts->lock.
 */
static void tquic_timer_work_fn(struct work_struct *work)
{
	struct tquic_timer_state *ts = container_of(work, struct tquic_timer_state,
						    timer_work);
	struct tquic_connection *conn;
	unsigned long pending, flags;

	spin_lock_irqsave(&ts->lock, flags);
	if (!ts->active || ts->shutting_down) {
		spin_unlock_irqrestore(&ts->lock, flags);
		return;
	}

	conn = ts->conn;

	/*
	 * Take a reference on the connection while we hold ts->lock
	 * to ensure conn remains valid after we drop the lock below.
	 */
	if (!tquic_conn_get(conn)) {
		spin_unlock_irqrestore(&ts->lock, flags);
		return;
	}

	pending = ts->pending_timer_mask;
	ts->pending_timer_mask = 0;
	spin_unlock_irqrestore(&ts->lock, flags);

	/* Handle idle timeout */
	if (test_bit(TQUIC_TIMER_IDLE_BIT, &pending)) {
		if (READ_ONCE(conn->state) == TQUIC_CONN_CONNECTED) {
			tquic_conn_close_with_error(conn,
						    EQUIC_NO_ERROR,
						    "idle timeout");
		}
	}

	/* Handle ACK delay expiration */
	if (test_bit(TQUIC_TIMER_ACK_DELAY_BIT, &pending)) {
		/* Would trigger sending pending ACKs */
		/* tquic_send_pending_acks(conn); */
	}

	/* Handle drain completion */
	if (test_bit(TQUIC_TIMER_DRAIN_BIT, &pending)) {
		tquic_conn_enter_closed(conn);
	}

	/* Handle keep-alive */
	if (test_bit(TQUIC_TIMER_KEEPALIVE_BIT, &pending)) {
		/* Would send PING frame */
		/* tquic_send_ping(conn); */

		/* Reschedule keep-alive timer */
		tquic_timer_reset_keepalive(ts);
	}

	/* Handle pacing - allow next packet send */
	if (test_bit(TQUIC_TIMER_PACING_BIT, &pending)) {
		/* Would trigger packet transmission */
		/* tquic_transmit_pending(conn); */
	}

	tquic_conn_put(conn);
}

/**
 * tquic_retransmit_work_fn - Retransmission work function
 * @work: Work struct
 */
static void tquic_retransmit_work_fn(struct work_struct *work)
{
	struct tquic_timer_state *ts = container_of(work, struct tquic_timer_state,
						    retransmit_work);
	struct tquic_connection *conn;
	struct tquic_recovery_state *rs;
	unsigned long pending, flags;
	int i, lost;

	spin_lock_irqsave(&ts->lock, flags);
	if (!ts->active || ts->shutting_down) {
		spin_unlock_irqrestore(&ts->lock, flags);
		return;
	}

	conn = ts->conn;

	/*
	 * Take a reference on the connection while we hold ts->lock
	 * to ensure conn remains valid after we drop the lock below.
	 * Loss detection and PTO handling access conn->active_path.
	 */
	if (!tquic_conn_get(conn)) {
		spin_unlock_irqrestore(&ts->lock, flags);
		return;
	}

	rs = ts->recovery;
	pending = ts->pending_timer_mask;
	spin_unlock_irqrestore(&ts->lock, flags);

	/* Handle loss detection */
	if (test_bit(TQUIC_TIMER_LOSS_BIT, &pending)) {
		for (i = 0; i < TQUIC_PN_SPACE_COUNT; i++) {
			lost = tquic_detect_lost_packets(ts, i);
			if (lost > 0) {
				tquic_dbg("timer:detected %d lost packets in space %d\n",
					 lost, i);
				/* Would trigger retransmission */
				/* tquic_retransmit_lost(conn, i); */
			}
		}

		/* Update loss timer for any remaining packets */
		tquic_timer_update_loss_timer(ts);
	}

	/* Handle PTO - send probe packets */
	if (test_bit(TQUIC_TIMER_PTO_BIT, &pending)) {
		/*
		 * PTO requires sending 1-2 ack-eliciting packets.
		 * Prefer retransmitting lost/unacked data, but send PING if none.
		 */
		/* tquic_send_pto_probe(conn); */

		/* Update PTO timer */
		tquic_timer_update_pto(ts);
	}

	tquic_conn_put(conn);
}

/**
 * tquic_path_work_fn - Path management work function
 * @work: Work struct
 */
static void tquic_path_work_fn(struct work_struct *work)
{
	struct tquic_timer_state *ts = container_of(work, struct tquic_timer_state,
						    path_work);
	struct tquic_connection *conn;
	unsigned long flags;

	spin_lock_irqsave(&ts->lock, flags);
	if (!ts->active || ts->shutting_down) {
		spin_unlock_irqrestore(&ts->lock, flags);
		return;
	}

	conn = ts->conn;

	/*
	 * Take a reference on the connection while we hold ts->lock
	 * to ensure conn remains valid after we drop the lock below.
	 * Path work handlers access conn for validation and failover.
	 */
	if (!tquic_conn_get(conn)) {
		spin_unlock_irqrestore(&ts->lock, flags);
		return;
	}
	spin_unlock_irqrestore(&ts->lock, flags);

	/* Handle path-related work like validation retries, failover, etc. */

	tquic_conn_put(conn);
}

/*
 * ============================================================================
 * Packet Sent/ACK Processing
 * ============================================================================
 */

/**
 * tquic_timer_on_packet_sent - Record packet transmission
 * @ts: Timer state
 * @pn_space: Packet number space
 * @pkt_num: Packet number
 * @bytes: Packet size in bytes
 * @ack_eliciting: True if packet requires ACK
 * @in_flight: True if packet counts against congestion window
 * @frames: Bitmask of frame types in packet
 *
 * Returns: 0 on success, negative error code on failure
 */
int tquic_timer_on_packet_sent(struct tquic_timer_state *ts, int pn_space,
			       u64 pkt_num, u32 bytes, bool ack_eliciting,
			       bool in_flight, u32 frames)
{
	struct tquic_recovery_state *rs = ts->recovery;
	struct tquic_pn_space *pns = &rs->pn_spaces[pn_space];
	struct tquic_sent_packet *pkt;

	pkt = tquic_sent_pkt_alloc(GFP_ATOMIC);
	if (!pkt)
		return -ENOMEM;

	pkt->pkt_num = pkt_num;
	pkt->pn_space = pn_space;
	pkt->sent_time = ktime_get();
	pkt->sent_bytes = bytes;
	pkt->ack_eliciting = ack_eliciting;
	pkt->in_flight = in_flight;
	pkt->state = TQUIC_PKT_OUTSTANDING;
	pkt->frames = frames;

	spin_lock_bh(&pns->lock);
	tquic_sent_pkt_insert(pns, pkt);

	if (pkt_num > pns->largest_sent)
		pns->largest_sent = pkt_num;

	if (ack_eliciting)
		pns->ack_eliciting_in_flight++;
	spin_unlock_bh(&pns->lock);

	if (in_flight) {
		spin_lock_bh(&rs->lock);
		rs->bytes_in_flight += bytes;
		spin_unlock_bh(&rs->lock);
	}

	/* Reset idle timer on packet sent */
	tquic_timer_reset_idle(ts);

	/* Update PTO timer */
	if (ack_eliciting)
		tquic_timer_update_pto(ts);

	return 0;
}
EXPORT_SYMBOL_GPL(tquic_timer_on_packet_sent);

/**
 * tquic_timer_on_ack_received - Process received ACK
 * @ts: Timer state
 * @pn_space: Packet number space
 * @largest_acked: Largest acknowledged packet number
 * @ack_delay_us: ACK delay from peer (in us)
 * @ack_ranges: Array of ACK ranges (pairs of first, last)
 * @num_ranges: Number of ACK ranges
 *
 * Returns: Number of newly acknowledged packets
 */
int tquic_timer_on_ack_received(struct tquic_timer_state *ts, int pn_space,
				u64 largest_acked, u64 ack_delay_us,
				u64 *ack_ranges, int num_ranges)
{
	struct tquic_recovery_state *rs = ts->recovery;
	struct tquic_pn_space *pns = &rs->pn_spaces[pn_space];
	struct tquic_sent_packet *pkt;
	ktime_t now = ktime_get();
	int newly_acked = 0;
	int i;
	bool is_handshake = (pn_space != TQUIC_PN_SPACE_APPLICATION);

	spin_lock_bh(&pns->lock);

	/*
	 * RFC 9000 Section 13.1: If an endpoint receives an ACK frame
	 * that acknowledges a packet number it has not yet sent, it
	 * SHOULD signal a connection error of type PROTOCOL_VIOLATION.
	 */
	if (largest_acked > pns->largest_sent) {
		spin_unlock_bh(&pns->lock);
		tquic_dbg("ACK for unsent pkt: largest_acked=%llu > largest_sent=%llu in space %u\n",
			 largest_acked, pns->largest_sent, pn_space);
		return -EPROTO;
	}

	/* Update largest acked */
	if (pns->largest_acked == U64_MAX || largest_acked > pns->largest_acked) {
		pns->largest_acked = largest_acked;

		/* Get RTT sample from largest newly acked packet */
		pkt = tquic_sent_pkt_find(pns, largest_acked);
		if (pkt && pkt->state == TQUIC_PKT_OUTSTANDING) {
			u64 rtt_sample = ktime_us_delta(now, pkt->sent_time);

			spin_lock_bh(&rs->lock);
			tquic_update_rtt(rs, ack_delay_us, rtt_sample, is_handshake);
			rs->pto_count = 0;
			rs->in_persistent_congestion = false;
			spin_unlock_bh(&rs->lock);
		}
	}

	pns->last_ack_time = now;

	/* Process ACK ranges */
	for (i = 0; i < num_ranges; i++) {
		u64 first = ack_ranges[i * 2];
		u64 last = ack_ranges[i * 2 + 1];
		u64 pn;

		for (pn = first; pn <= last; pn++) {
			pkt = tquic_sent_pkt_find(pns, pn);
			if (!pkt || pkt->state != TQUIC_PKT_OUTSTANDING)
				continue;

			pkt->state = TQUIC_PKT_ACKED;
			newly_acked++;

			if (pkt->ack_eliciting)
				pns->ack_eliciting_in_flight--;

			if (pkt->in_flight) {
				spin_lock_bh(&rs->lock);
				rs->bytes_in_flight -= pkt->sent_bytes;
				spin_unlock_bh(&rs->lock);
			}

			/* Notify congestion controller */
			/* Would call cong->on_ack() here */
		}
	}

	spin_unlock_bh(&pns->lock);

	/* Detect any newly lost packets */
	tquic_detect_lost_packets(ts, pn_space);

	/* Update timers */
	tquic_timer_update_loss_timer(ts);
	tquic_timer_update_pto(ts);
	tquic_timer_reset_idle(ts);

	return newly_acked;
}
EXPORT_SYMBOL_GPL(tquic_timer_on_ack_received);

/*
 * ============================================================================
 * Retransmission Handling
 * ============================================================================
 */

/**
 * tquic_timer_get_lost_packets - Get list of lost packets for retransmission
 * @ts: Timer state
 * @pn_space: Packet number space
 * @lost_list: List head to add lost packets to
 * @max_count: Maximum number of packets to return
 *
 * Returns: Number of lost packets added to list
 */
int tquic_timer_get_lost_packets(struct tquic_timer_state *ts, int pn_space,
				 struct list_head *lost_list, int max_count)
{
	struct tquic_recovery_state *rs = ts->recovery;
	struct tquic_pn_space *pns = &rs->pn_spaces[pn_space];
	struct tquic_sent_packet *pkt;
	int count = 0;

	spin_lock_bh(&pns->lock);

	list_for_each_entry(pkt, &pns->sent_list, list) {
		if (pkt->state != TQUIC_PKT_LOST)
			continue;

		if (count >= max_count)
			break;

		/* Mark as being retransmitted */
		pkt->state = TQUIC_PKT_RETRANSMITTED;
		count++;

		/* Caller will handle actual retransmission */
	}

	spin_unlock_bh(&pns->lock);

	return count;
}
EXPORT_SYMBOL_GPL(tquic_timer_get_lost_packets);

/**
 * tquic_timer_mark_retransmitted - Mark packet as retransmitted
 * @ts: Timer state
 * @pn_space: Packet number space
 * @old_pkt_num: Original packet number
 * @new_pkt_num: New packet number for retransmission
 */
void tquic_timer_mark_retransmitted(struct tquic_timer_state *ts, int pn_space,
				    u64 old_pkt_num, u64 new_pkt_num)
{
	struct tquic_recovery_state *rs = ts->recovery;
	struct tquic_pn_space *pns = &rs->pn_spaces[pn_space];
	struct tquic_sent_packet *pkt;

	spin_lock_bh(&pns->lock);

	pkt = tquic_sent_pkt_find(pns, old_pkt_num);
	if (pkt) {
		pkt->state = TQUIC_PKT_RETRANSMITTED;
		/* New packet will be tracked separately */
	}

	spin_unlock_bh(&pns->lock);
}
EXPORT_SYMBOL_GPL(tquic_timer_mark_retransmitted);

/*
 * ============================================================================
 * Statistics and Debugging
 * ============================================================================
 */

/**
 * tquic_timer_get_rtt_stats - Get RTT statistics
 * @ts: Timer state
 * @smoothed: Output for smoothed RTT (us)
 * @variance: Output for RTT variance (us)
 * @min: Output for minimum RTT (us)
 * @latest: Output for latest RTT sample (us)
 */
void tquic_timer_get_rtt_stats(struct tquic_timer_state *ts,
			       u64 *smoothed, u64 *variance,
			       u64 *min, u64 *latest)
{
	struct tquic_recovery_state *rs = ts->recovery;

	spin_lock_bh(&rs->lock);

	if (smoothed)
		*smoothed = rs->smoothed_rtt;
	if (variance)
		*variance = rs->rtt_variance;
	if (min)
		*min = rs->min_rtt == U64_MAX ? 0 : rs->min_rtt;
	if (latest)
		*latest = rs->latest_rtt;

	spin_unlock_bh(&rs->lock);
}
EXPORT_SYMBOL_GPL(tquic_timer_get_rtt_stats);

/**
 * tquic_timer_get_recovery_stats - Get recovery statistics
 * @ts: Timer state
 * @bytes_in_flight: Output for bytes in flight
 * @cwnd: Output for congestion window
 * @ssthresh: Output for slow start threshold
 * @pto_count: Output for PTO count
 */
void tquic_timer_get_recovery_stats(struct tquic_timer_state *ts,
				    u64 *bytes_in_flight, u64 *cwnd,
				    u64 *ssthresh, u32 *pto_count)
{
	struct tquic_recovery_state *rs = ts->recovery;

	spin_lock_bh(&rs->lock);

	if (bytes_in_flight)
		*bytes_in_flight = rs->bytes_in_flight;
	if (cwnd)
		*cwnd = rs->congestion_window;
	if (ssthresh)
		*ssthresh = rs->ssthresh == U64_MAX ? 0 : rs->ssthresh;
	if (pto_count)
		*pto_count = rs->pto_count;

	spin_unlock_bh(&rs->lock);
}
EXPORT_SYMBOL_GPL(tquic_timer_get_recovery_stats);

/*
 * ============================================================================
 * Legacy conn->timers[] Compatibility
 * ============================================================================
 *
 * Some core code paths still schedule per-connection timers via
 * tquic_timer_set/cancel/update. Provide lightweight helpers that operate on
 * conn->timers[] without pulling in the deprecated standalone timer code.
 */

static unsigned long tquic_timer_deadline_to_jiffies(ktime_t when)
{
	s64 delta_ns = ktime_to_ns(ktime_sub(when, ktime_get()));
	unsigned long delta_jiffies;

	if (delta_ns <= 0)
		return jiffies;

	delta_jiffies = nsecs_to_jiffies(delta_ns);
	if (delta_jiffies == 0)
		delta_jiffies = 1;

	return jiffies + delta_jiffies;
}

void tquic_timer_set(struct tquic_connection *conn, u8 timer_type, ktime_t when)
{
	if (!conn)
		return;

	if (timer_type >= TQUIC_TIMER_MAX)
		return;

	mod_timer(&conn->timers[timer_type], tquic_timer_deadline_to_jiffies(when));
}

void tquic_timer_cancel(struct tquic_connection *conn, u8 timer_type)
{
	if (!conn)
		return;

	if (timer_type >= TQUIC_TIMER_MAX)
		return;

	del_timer(&conn->timers[timer_type]);
}

void tquic_timer_update(struct tquic_connection *conn)
{
	if (!conn)
		return;

	/* Loss timer is managed by tquic_set_loss_detection_timer() */
	tquic_set_loss_detection_timer(conn);
}

/*
 * ============================================================================
 * Module Initialization
 * ============================================================================
 */

/**
 * tquic_timer_init - Initialize timer subsystem
 *
 * Returns: 0 on success, negative error code on failure
 */
int __init tquic_timer_init(void)
{
	/* Create slab cache for sent packet metadata */
	tquic_sent_pkt_cache = kmem_cache_create("tquic_sent_pkt",
						 sizeof(struct tquic_sent_packet),
						 0, SLAB_HWCACHE_ALIGN, NULL);
	if (!tquic_sent_pkt_cache)
		return -ENOMEM;

	/* Create workqueue for timer processing */
	tquic_timer_wq = alloc_workqueue("tquic_timer",
					 WQ_HIGHPRI | WQ_MEM_RECLAIM, 0);
	if (!tquic_timer_wq) {
		kmem_cache_destroy(tquic_sent_pkt_cache);
		return -ENOMEM;
	}

	tquic_info("timer:timer subsystem initialized\n");

	return 0;
}

/**
 * tquic_timer_exit - Cleanup timer subsystem
 */
void __exit tquic_timer_exit(void)
{
	if (tquic_timer_wq) {
		flush_workqueue(tquic_timer_wq);
		destroy_workqueue(tquic_timer_wq);
	}

	if (tquic_sent_pkt_cache)
		kmem_cache_destroy(tquic_sent_pkt_cache);

	tquic_info("timer:timer subsystem shutdown\n");
}

MODULE_DESCRIPTION("TQUIC Timer and Recovery System");
MODULE_LICENSE("GPL");
