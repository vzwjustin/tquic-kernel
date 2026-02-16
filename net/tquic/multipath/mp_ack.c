// SPDX-License-Identifier: GPL-2.0-only
/*
 * TQUIC: Multipath ACK Processing
 *
 * Copyright (c) 2026 Justin Adams <spotty118@gmail.com>
 * Kernel implementation by Justin Adams <spotty118@gmail.com>
 *
 * Implementation of per-path ACK processing for QUIC Multipath Extension
 * (RFC 9369). This module handles:
 *   - Per-path received packet tracking
 *   - MP_ACK frame generation
 *   - MP_ACK frame processing
 *   - Per-path RTT and loss detection
 *   - ECN validation per path
 */

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/list.h>
#include <linux/rbtree.h>
#include <linux/spinlock.h>
#include <linux/timer.h>
#include <linux/ktime.h>
#include <linux/math64.h>
#include <linux/limits.h>
#include <net/tquic.h>

#include "mp_frame.h"
#include "mp_ack.h"
#include "../core/varint.h"
#include "../tquic_debug.h"

/*
 * Per-path ACK state constants
 */
#define TQUIC_MP_ACK_DELAY_US		25000	/* 25ms default ACK delay */
#define TQUIC_MP_MAX_ACK_RANGES		256
#define TQUIC_MP_PACKET_THRESHOLD	3	/* RFC 9002 kPacketThreshold */
#define TQUIC_MP_TIME_THRESHOLD_NUM	9
#define TQUIC_MP_TIME_THRESHOLD_DEN	8
#define TQUIC_MP_INITIAL_RTT_US		333000	/* 333ms initial RTT */
#define TQUIC_MP_TIMER_GRANULARITY_US	1000	/* 1ms timer granularity */

/**
 * struct tquic_mp_ack_range_entry - ACK range for tracking received packets
 * @start: First packet number in range (inclusive)
 * @end: Last packet number in range (inclusive)
 * @list: List linkage
 */
struct tquic_mp_ack_range_entry {
	u64 start;
	u64 end;
	struct list_head list;
};

/**
 * struct tquic_mp_sent_packet - Metadata for a sent packet on a path
 * @pn: Packet number
 * @path_id: Path the packet was sent on
 * @sent_time: Time when packet was sent
 * @sent_bytes: Size of packet in bytes
 * @flags: Packet flags (ACK-eliciting, in-flight, etc.)
 * @pn_space: Packet number space
 * @node: RB-tree node
 * @list: Time-ordered list linkage
 */
struct tquic_mp_sent_packet {
	u64 pn;
	u64 path_id;
	ktime_t sent_time;
	u32 sent_bytes;
	u32 flags;
	u8 pn_space;
	struct rb_node node;
	struct list_head list;
};

/* Packet flags */
#define TQUIC_MP_PKT_ACK_ELICITING	BIT(0)
#define TQUIC_MP_PKT_IN_FLIGHT		BIT(1)
#define TQUIC_MP_PKT_HAS_CRYPTO		BIT(2)

/**
 * struct tquic_mp_rtt_state - Per-path RTT estimation state
 * @latest_rtt: Most recent RTT sample (us)
 * @smoothed_rtt: EWMA of RTT (us)
 * @rtt_var: RTT variance (us)
 * @min_rtt: Minimum RTT observed (us)
 * @max_ack_delay: Maximum ACK delay from peer (us)
 * @samples: Number of RTT samples
 */
struct tquic_mp_rtt_state {
	u64 latest_rtt;
	u64 smoothed_rtt;
	u64 rtt_var;
	u64 min_rtt;
	u64 max_ack_delay;
	u32 samples;
};

/**
 * struct tquic_mp_ecn_counts - Per-path ECN counters
 * @ect0: ECT(0) counter
 * @ect1: ECT(1) counter
 * @ce: ECN-CE counter
 */
struct tquic_mp_ecn_counts {
	u64 ect0;
	u64 ect1;
	u64 ce;
};

/**
 * struct tquic_mp_path_ack_state - Per-path ACK tracking state
 * @path: Associated path
 * @path_id: Path identifier
 *
 * @rtt: RTT estimation state
 *
 * @sent_packets: RB-tree of sent packets (per PN space)
 * @sent_packets_list: Time-ordered list of sent packets (per PN space)
 * @num_sent_packets: Count of sent packets (per PN space)
 *
 * @ack_ranges: Received packet ranges for ACK generation (per PN space)
 * @num_ack_ranges: Number of ACK ranges (per PN space)
 * @largest_received: Largest received packet number (per PN space)
 * @largest_received_time: Time largest was received (per PN space)
 *
 * @largest_acked: Largest acknowledged packet (per PN space)
 * @loss_time: Time threshold for loss detection (per PN space)
 * @last_ack_eliciting_time: Time of last ACK-eliciting send (per PN space)
 *
 * @bytes_in_flight: Bytes currently in flight
 * @packets_in_flight: Packets currently in flight
 * @ack_eliciting_in_flight: ACK-eliciting packets in flight (per PN space)
 *
 * @ecn_sent: ECN counts for sent packets
 * @ecn_acked: ECN counts from received ACKs
 * @ecn_validated: Whether ECN is validated
 * @ecn_capable: Whether ECN is enabled
 *
 * @pto_count: Consecutive PTO count
 * @in_persistent_congestion: In persistent congestion state
 *
 * @lock: Spinlock for synchronization
 */
struct tquic_mp_path_ack_state {
	struct tquic_path *path;
	u64 path_id;

	/* RTT estimation */
	struct tquic_mp_rtt_state rtt;

	/* Sent packet tracking per packet number space */
	struct rb_root sent_packets[TQUIC_PN_SPACE_COUNT];
	struct list_head sent_packets_list[TQUIC_PN_SPACE_COUNT];
	u32 num_sent_packets[TQUIC_PN_SPACE_COUNT];

	/* Received packet tracking for ACK generation */
	struct list_head ack_ranges[TQUIC_PN_SPACE_COUNT];
	u32 num_ack_ranges[TQUIC_PN_SPACE_COUNT];
	u64 largest_received[TQUIC_PN_SPACE_COUNT];
	ktime_t largest_received_time[TQUIC_PN_SPACE_COUNT];

	/* Loss detection state */
	u64 largest_acked[TQUIC_PN_SPACE_COUNT];
	ktime_t loss_time[TQUIC_PN_SPACE_COUNT];
	ktime_t last_ack_eliciting_time[TQUIC_PN_SPACE_COUNT];

	/* In-flight tracking */
	u64 bytes_in_flight;
	u32 packets_in_flight;
	u32 ack_eliciting_in_flight[TQUIC_PN_SPACE_COUNT];

	/* ECN state */
	struct tquic_mp_ecn_counts ecn_sent;
	struct tquic_mp_ecn_counts ecn_acked;
	bool ecn_validated;
	bool ecn_capable;

	/* PTO state */
	u32 pto_count;
	bool in_persistent_congestion;

	spinlock_t lock;
};

/* Memory caches */
static struct kmem_cache *mp_ack_state_cache;
static struct kmem_cache *mp_sent_packet_cache;
static struct kmem_cache *mp_ack_range_cache;

/*
 * =============================================================================
 * RTT Estimation (RFC 9002 Section 5)
 * =============================================================================
 */

/**
 * mp_rtt_init - Initialize RTT state
 * @rtt: RTT state to initialize
 */
static void mp_rtt_init(struct tquic_mp_rtt_state *rtt)
{
	rtt->latest_rtt = 0;
	rtt->smoothed_rtt = TQUIC_MP_INITIAL_RTT_US;
	rtt->rtt_var = TQUIC_MP_INITIAL_RTT_US / 2;
	rtt->min_rtt = ULLONG_MAX;
	rtt->max_ack_delay = TQUIC_MP_ACK_DELAY_US;
	rtt->samples = 0;
}

/**
 * mp_rtt_update - Update RTT estimates from a new sample
 * @rtt: RTT state
 * @rtt_sample: New RTT sample in microseconds
 * @ack_delay: ACK delay reported by peer
 * @is_handshake_confirmed: Whether handshake is confirmed
 */
static void mp_rtt_update(struct tquic_mp_rtt_state *rtt,
			  u64 rtt_sample, u64 ack_delay,
			  bool is_handshake_confirmed)
{
	u64 adjusted_rtt;

	tquic_dbg("mp_ack: rtt_update sample=%llu ack_delay=%llu srtt=%llu\n",
		  rtt_sample, ack_delay, rtt->smoothed_rtt);

	/* Update minimum RTT */
	if (rtt_sample < rtt->min_rtt)
		rtt->min_rtt = rtt_sample;

	rtt->latest_rtt = rtt_sample;
	rtt->samples++;

	/* First sample initializes smoothed values */
	if (rtt->samples == 1) {
		rtt->smoothed_rtt = rtt_sample;
		rtt->rtt_var = rtt_sample / 2;
		return;
	}

	/* Adjust RTT by ACK delay if handshake confirmed */
	adjusted_rtt = rtt_sample;
	if (is_handshake_confirmed) {
		u64 max_delay = min(ack_delay, rtt->max_ack_delay);

		if (rtt_sample >= rtt->min_rtt + max_delay)
			adjusted_rtt = rtt_sample - max_delay;
	}

	/* Update smoothed RTT and variance (RFC 9002 Section 5.3) */
	rtt->rtt_var = (3 * rtt->rtt_var +
			abs((s64)rtt->smoothed_rtt - (s64)adjusted_rtt)) / 4;
	rtt->smoothed_rtt = (7 * rtt->smoothed_rtt + adjusted_rtt) / 8;
}

/**
 * mp_get_pto - Calculate Probe Timeout for a path
 * @state: Path ACK state
 * @pn_space: Packet number space
 *
 * Returns PTO in microseconds.
 */
static u64 __maybe_unused mp_get_pto(struct tquic_mp_path_ack_state *state, int pn_space)
{
	struct tquic_mp_rtt_state *rtt = &state->rtt;
	u64 pto;
	u64 rtt_var_component;

	rtt_var_component = max(4 * rtt->rtt_var,
				(u64)TQUIC_MP_TIMER_GRANULARITY_US);
	pto = rtt->smoothed_rtt + rtt_var_component;

	/* Add max_ack_delay for application data space */
	if (pn_space == TQUIC_PN_SPACE_APPLICATION)
		pto += rtt->max_ack_delay;

	return pto;
}

/*
 * =============================================================================
 * Sent Packet Tracking
 * =============================================================================
 */

/**
 * mp_sent_packet_alloc - Allocate a sent packet metadata structure
 * @gfp: GFP flags
 */
static struct tquic_mp_sent_packet *mp_sent_packet_alloc(gfp_t gfp)
{
	struct tquic_mp_sent_packet *pkt;

	pkt = kmem_cache_zalloc(mp_sent_packet_cache, gfp);
	if (pkt) {
		RB_CLEAR_NODE(&pkt->node);
		INIT_LIST_HEAD(&pkt->list);
	}

	return pkt;
}

/**
 * mp_sent_packet_free - Free a sent packet metadata structure
 * @pkt: Packet to free
 */
static void mp_sent_packet_free(struct tquic_mp_sent_packet *pkt)
{
	if (pkt)
		kmem_cache_free(mp_sent_packet_cache, pkt);
}

/**
 * mp_sent_packet_insert - Insert sent packet into tracking structures
 * @state: Path ACK state
 * @pkt: Sent packet metadata
 */
static void mp_sent_packet_insert(struct tquic_mp_path_ack_state *state,
				  struct tquic_mp_sent_packet *pkt)
{
	int space = pkt->pn_space;
	struct rb_node **link = &state->sent_packets[space].rb_node;

	tquic_dbg("mp_ack: sent_insert pn=%llu space=%d bytes=%u\n",
		  pkt->pn, space, pkt->sent_bytes);
	struct rb_node *parent = NULL;
	struct tquic_mp_sent_packet *entry;

	/* Insert into RB-tree */
	while (*link) {
		parent = *link;
		entry = rb_entry(parent, struct tquic_mp_sent_packet, node);

		if (pkt->pn < entry->pn)
			link = &parent->rb_left;
		else if (pkt->pn > entry->pn)
			link = &parent->rb_right;
		else
			return; /* Duplicate */
	}

	rb_link_node(&pkt->node, parent, link);
	rb_insert_color(&pkt->node, &state->sent_packets[space]);

	/* Add to time-ordered list */
	list_add_tail(&pkt->list, &state->sent_packets_list[space]);
	state->num_sent_packets[space]++;
}

/**
 * mp_sent_packet_remove - Remove sent packet from tracking
 * @state: Path ACK state
 * @pkt: Packet to remove
 */
static void mp_sent_packet_remove(struct tquic_mp_path_ack_state *state,
				  struct tquic_mp_sent_packet *pkt)
{
	int space = pkt->pn_space;

	tquic_dbg("mp_ack: sent_remove pn=%llu space=%d\n", pkt->pn, space);

	if (!RB_EMPTY_NODE(&pkt->node)) {
		rb_erase(&pkt->node, &state->sent_packets[space]);
		RB_CLEAR_NODE(&pkt->node);
	}

	if (!list_empty(&pkt->list))
		list_del_init(&pkt->list);

	if (state->num_sent_packets[space] > 0)
		state->num_sent_packets[space]--;
}

/**
 * mp_sent_packet_find - Find a sent packet by packet number
 * @state: Path ACK state
 * @pn_space: Packet number space
 * @pn: Packet number
 *
 * Returns the sent packet or NULL if not found.
 */
static struct tquic_mp_sent_packet __maybe_unused *mp_sent_packet_find(
	struct tquic_mp_path_ack_state *state, int pn_space, u64 pn)
{
	struct rb_node *node = state->sent_packets[pn_space].rb_node;
	struct tquic_mp_sent_packet *entry;

	while (node) {
		entry = rb_entry(node, struct tquic_mp_sent_packet, node);

		if (pn < entry->pn)
			node = node->rb_left;
		else if (pn > entry->pn)
			node = node->rb_right;
		else
			return entry;
	}

	return NULL;
}

/*
 * =============================================================================
 * ACK Range Management
 * =============================================================================
 */

/**
 * mp_ack_range_alloc - Allocate an ACK range entry
 * @gfp: GFP flags
 */
static struct tquic_mp_ack_range_entry *mp_ack_range_alloc(gfp_t gfp)
{
	struct tquic_mp_ack_range_entry *range;

	range = kmem_cache_zalloc(mp_ack_range_cache, gfp);
	if (range)
		INIT_LIST_HEAD(&range->list);

	return range;
}

/**
 * mp_ack_range_free - Free an ACK range entry
 * @range: Range to free
 */
static void mp_ack_range_free(struct tquic_mp_ack_range_entry *range)
{
	if (range)
		kmem_cache_free(mp_ack_range_cache, range);
}

/*
 * =============================================================================
 * Per-Path ACK State Management
 * =============================================================================
 */

/**
 * tquic_mp_ack_state_create - Create per-path ACK state
 * @path: Path to create state for
 *
 * Returns allocated state or NULL on failure.
 */
struct tquic_mp_path_ack_state *tquic_mp_ack_state_create(struct tquic_path *path)
{
	struct tquic_mp_path_ack_state *state;
	int i;

	tquic_dbg("mp_ack: ack_state_create path=%u\n",
		  path ? path->path_id : 0);

	state = kmem_cache_zalloc(mp_ack_state_cache, GFP_KERNEL);
	if (!state)
		return NULL;

	state->path = path;
	state->path_id = path ? path->path_id : 0;
	spin_lock_init(&state->lock);

	/* Initialize RTT */
	mp_rtt_init(&state->rtt);

	/* Initialize per-space structures */
	for (i = 0; i < TQUIC_PN_SPACE_COUNT; i++) {
		state->sent_packets[i] = RB_ROOT;
		INIT_LIST_HEAD(&state->sent_packets_list[i]);
		INIT_LIST_HEAD(&state->ack_ranges[i]);
		state->largest_acked[i] = 0;
		state->largest_received[i] = 0;
		state->loss_time[i] = 0;
	}

	/* ECN enabled by default */
	state->ecn_capable = true;

	pr_debug("tquic_mp: created ACK state for path %llu\n", state->path_id);

	return state;
}
EXPORT_SYMBOL_GPL(tquic_mp_ack_state_create);

/**
 * tquic_mp_ack_state_destroy - Destroy per-path ACK state
 * @state: State to destroy
 */
void tquic_mp_ack_state_destroy(struct tquic_mp_path_ack_state *state)
{
	struct tquic_mp_sent_packet *pkt, *pkt_tmp;
	struct tquic_mp_ack_range_entry *range, *range_tmp;
	int i;

	tquic_dbg("mp_ack: ack_state_destroy path=%llu\n",
		  state ? state->path_id : 0);

	if (!state)
		return;

	spin_lock_bh(&state->lock);

	/* Free all sent packets */
	for (i = 0; i < TQUIC_PN_SPACE_COUNT; i++) {
		list_for_each_entry_safe(pkt, pkt_tmp,
					 &state->sent_packets_list[i], list) {
			list_del_init(&pkt->list);
			mp_sent_packet_free(pkt);
		}

		/* Free ACK ranges */
		list_for_each_entry_safe(range, range_tmp,
					 &state->ack_ranges[i], list) {
			list_del_init(&range->list);
			mp_ack_range_free(range);
		}
	}

	spin_unlock_bh(&state->lock);

	kmem_cache_free(mp_ack_state_cache, state);
}
EXPORT_SYMBOL_GPL(tquic_mp_ack_state_destroy);

/*
 * =============================================================================
 * Received Packet Recording
 * =============================================================================
 */

/**
 * tquic_mp_record_received - Record receipt of a packet on a path
 * @state: Path ACK state
 * @pn_space: Packet number space
 * @pn: Packet number received
 * @is_ack_eliciting: Whether packet requires an ACK
 *
 * Returns 0 on success or negative error.
 */
int tquic_mp_record_received(struct tquic_mp_path_ack_state *state,
			     int pn_space, u64 pn, bool is_ack_eliciting)
{
	struct tquic_mp_ack_range_entry *range, *prev_range = NULL;
	struct tquic_mp_ack_range_entry *new_range;
	ktime_t now = ktime_get();
	bool merged = false;

	if (!state)
		return -EINVAL;

	spin_lock_bh(&state->lock);

	/* Update largest received */
	if (pn > state->largest_received[pn_space]) {
		state->largest_received[pn_space] = pn;
		state->largest_received_time[pn_space] = now;
	}

	/* Try to merge into existing ranges (kept in descending order) */
	list_for_each_entry(range, &state->ack_ranges[pn_space], list) {
		/* Check if pn extends this range */
		if (pn >= range->start - 1 && pn <= range->end + 1) {
			if (pn < range->start)
				range->start = pn;
			else if (pn > range->end)
				range->end = pn;
			merged = true;

			/* Try to merge with previous range */
			if (prev_range && range->end + 1 >= prev_range->start) {
				prev_range->start = range->start;
				list_del_init(&range->list);
				mp_ack_range_free(range);
				state->num_ack_ranges[pn_space]--;
			}
			break;
		}

		/* Insert point found */
		if (pn > range->end + 1) {
			new_range = mp_ack_range_alloc(GFP_ATOMIC);
			if (!new_range) {
				spin_unlock_bh(&state->lock);
				return -ENOMEM;
			}

			new_range->start = pn;
			new_range->end = pn;
			list_add_tail(&new_range->list, &range->list);
			state->num_ack_ranges[pn_space]++;
			merged = true;
			break;
		}

		prev_range = range;
	}

	/* Add at end if not merged */
	if (!merged) {
		new_range = mp_ack_range_alloc(GFP_ATOMIC);
		if (!new_range) {
			spin_unlock_bh(&state->lock);
			return -ENOMEM;
		}

		new_range->start = pn;
		new_range->end = pn;
		list_add_tail(&new_range->list, &state->ack_ranges[pn_space]);
		state->num_ack_ranges[pn_space]++;
	}

	/* Limit number of ranges */
	while (state->num_ack_ranges[pn_space] > TQUIC_MP_MAX_ACK_RANGES) {
		range = list_last_entry(&state->ack_ranges[pn_space],
					struct tquic_mp_ack_range_entry, list);
		list_del_init(&range->list);
		mp_ack_range_free(range);
		state->num_ack_ranges[pn_space]--;
	}

	spin_unlock_bh(&state->lock);
	return 0;
}
EXPORT_SYMBOL_GPL(tquic_mp_record_received);

/*
 * =============================================================================
 * MP_ACK Frame Generation
 * =============================================================================
 */

/**
 * tquic_mp_generate_ack - Generate MP_ACK frame for a path
 * @state: Path ACK state
 * @pn_space: Packet number space
 * @buf: Output buffer
 * @buf_len: Buffer length
 * @include_ecn: Whether to include ECN counts
 * @ack_delay_exponent: ACK delay exponent for encoding
 *
 * Returns number of bytes written or negative error.
 */
int tquic_mp_generate_ack(struct tquic_mp_path_ack_state *state,
			  int pn_space, u8 *buf, size_t buf_len,
			  bool include_ecn, u8 ack_delay_exponent)
{
	struct tquic_mp_ack *frame;
	struct tquic_mp_ack_range_entry *range;
	u64 prev_smallest;
	u32 range_idx = 0;
	int ret;

	if (!state || !buf)
		return -EINVAL;

	/* Allocate frame dynamically - it's too large for stack */
	frame = kzalloc(sizeof(*frame), GFP_ATOMIC);
	if (!frame)
		return -ENOMEM;

	spin_lock_bh(&state->lock);

	if (list_empty(&state->ack_ranges[pn_space])) {
		spin_unlock_bh(&state->lock);
		kfree(frame);
		return -ENODATA;
	}

	frame->path_id = state->path_id;
	frame->has_ecn = include_ecn && state->ecn_validated;

	/* Get largest acknowledged from first range */
	range = list_first_entry(&state->ack_ranges[pn_space],
				 struct tquic_mp_ack_range_entry, list);
	frame->largest_ack = range->end;
	frame->first_ack_range = range->end - range->start;

	/* Calculate ACK delay */
	frame->ack_delay = ktime_us_delta(ktime_get(),
					 state->largest_received_time[pn_space]);

	/* Count additional ranges (excluding first) */
	frame->ack_range_count = state->num_ack_ranges[pn_space] - 1;

	/* Build additional ranges */
	prev_smallest = range->start;
	list_for_each_entry_continue(range, &state->ack_ranges[pn_space], list) {
		if (range_idx >= TQUIC_MP_MAX_ACK_RANGES)
			break;

		frame->ranges[range_idx].gap = prev_smallest - range->end - 2;
		frame->ranges[range_idx].ack_range_len = range->end - range->start;
		prev_smallest = range->start;
		range_idx++;
	}

	/* ECN counts if requested */
	if (frame->has_ecn) {
		frame->ect0_count = state->ecn_acked.ect0;
		frame->ect1_count = state->ecn_acked.ect1;
		frame->ecn_ce_count = state->ecn_acked.ce;
	}

	spin_unlock_bh(&state->lock);

	/* Write the frame */
	ret = tquic_mp_write_ack(frame, buf, buf_len, ack_delay_exponent);
	kfree(frame);
	return ret;
}
EXPORT_SYMBOL_GPL(tquic_mp_generate_ack);

/*
 * =============================================================================
 * MP_ACK Processing
 * =============================================================================
 */

/**
 * mp_ack_contains - Check if packet number is acknowledged by MP_ACK frame
 * @frame: Parsed MP_ACK frame
 * @pn: Packet number to check
 *
 * Returns true if pn is acknowledged.
 */
static bool mp_ack_contains(const struct tquic_mp_ack *frame, u64 pn)
{
	u64 range_start, range_end;
	u64 i;

	/* Check first range */
	range_end = frame->largest_ack;
	range_start = frame->largest_ack - frame->first_ack_range;

	if (pn >= range_start && pn <= range_end)
		return true;

	/* Check additional ranges */
	for (i = 0; i < frame->ack_range_count; i++) {
		range_end = range_start - frame->ranges[i].gap - 2;
		range_start = range_end - frame->ranges[i].ack_range_len;

		if (pn >= range_start && pn <= range_end)
			return true;
	}

	return false;
}

/**
 * mp_detect_lost_packets - Detect lost packets after receiving ACK
 * @state: Path ACK state
 * @pn_space: Packet number space
 * @lost_packets: List to add lost packets to
 *
 * Returns number of packets detected as lost.
 */
static int mp_detect_lost_packets(struct tquic_mp_path_ack_state *state,
				  int pn_space, struct list_head *lost_packets)
{
	u64 largest_acked = state->largest_acked[pn_space];
	ktime_t now = ktime_get();
	u64 time_threshold;
	ktime_t loss_delay;
	struct tquic_mp_sent_packet *pkt, *tmp;
	int lost_count = 0;
	ktime_t earliest_loss_time = 0;
	u64 max_rtt;

	/* Calculate time threshold */
	max_rtt = max(state->rtt.smoothed_rtt, state->rtt.latest_rtt);
	time_threshold = (max_rtt * TQUIC_MP_TIME_THRESHOLD_NUM) /
			 TQUIC_MP_TIME_THRESHOLD_DEN;
	time_threshold = max(time_threshold, (u64)TQUIC_MP_TIMER_GRANULARITY_US);
	loss_delay = ktime_set(0, time_threshold * NSEC_PER_USEC);

	list_for_each_entry_safe(pkt, tmp, &state->sent_packets_list[pn_space],
				 list) {
		/* Stop when reaching packets sent after largest acked */
		if (pkt->pn > largest_acked)
			break;

		/* Check packet threshold */
		if (largest_acked >= pkt->pn + TQUIC_MP_PACKET_THRESHOLD)
			goto mark_lost;

		/* Check time threshold */
		if (ktime_after(now, ktime_add(pkt->sent_time, loss_delay)))
			goto mark_lost;

		/* Track earliest potential loss time */
		if (largest_acked >= pkt->pn) {
			ktime_t potential = ktime_add(pkt->sent_time, loss_delay);

			if (!earliest_loss_time ||
			    ktime_before(potential, earliest_loss_time))
				earliest_loss_time = potential;
		}
		continue;

mark_lost:
		mp_sent_packet_remove(state, pkt);

		if (pkt->flags & TQUIC_MP_PKT_IN_FLIGHT) {
			state->bytes_in_flight -= pkt->sent_bytes;
			state->packets_in_flight--;
		}

		if (pkt->flags & TQUIC_MP_PKT_ACK_ELICITING)
			state->ack_eliciting_in_flight[pn_space]--;

		list_add_tail(&pkt->list, lost_packets);
		lost_count++;
	}

	state->loss_time[pn_space] = earliest_loss_time;
	return lost_count;
}

/**
 * tquic_mp_on_ack_received - Process received MP_ACK frame
 * @state: Path ACK state
 * @pn_space: Packet number space
 * @frame: Parsed MP_ACK frame
 * @conn: Connection
 *
 * Returns 0 on success or negative error.
 */
int tquic_mp_on_ack_received(struct tquic_mp_path_ack_state *state,
			     int pn_space, const struct tquic_mp_ack *frame,
			     struct tquic_connection *conn)
{
	LIST_HEAD(newly_acked);
	LIST_HEAD(lost_packets);
	struct tquic_mp_sent_packet *pkt, *tmp;
	struct tquic_mp_sent_packet *largest_acked_pkt = NULL;
	ktime_t now = ktime_get();
	u64 acked_bytes = 0;
	bool includes_ack_eliciting = false;
	int lost_count;

	if (!state || !frame)
		return -EINVAL;

	/* Validate path_id matches */
	if (frame->path_id != state->path_id) {
		pr_debug("tquic_mp: MP_ACK path_id mismatch: got %llu, expected %llu\n",
			 frame->path_id, state->path_id);
		return -EINVAL;
	}

	spin_lock_bh(&state->lock);

	/* Validate largest_acked */
	if (frame->largest_ack < state->largest_acked[pn_space]) {
		/* Old ACK, ignore */
		spin_unlock_bh(&state->lock);
		return 0;
	}

	/* Find newly acknowledged packets */
	list_for_each_entry_safe(pkt, tmp, &state->sent_packets_list[pn_space],
				 list) {
		if (!mp_ack_contains(frame, pkt->pn))
			continue;

		mp_sent_packet_remove(state, pkt);

		if (pkt->flags & TQUIC_MP_PKT_IN_FLIGHT) {
			state->bytes_in_flight -= pkt->sent_bytes;
			state->packets_in_flight--;
			acked_bytes += pkt->sent_bytes;
		}

		if (pkt->flags & TQUIC_MP_PKT_ACK_ELICITING) {
			state->ack_eliciting_in_flight[pn_space]--;
			includes_ack_eliciting = true;
		}

		if (pkt->pn == frame->largest_ack)
			largest_acked_pkt = pkt;

		list_add_tail(&pkt->list, &newly_acked);
	}

	/* Update largest acked */
	if (frame->largest_ack > state->largest_acked[pn_space])
		state->largest_acked[pn_space] = frame->largest_ack;

	/* Update RTT */
	if (largest_acked_pkt && includes_ack_eliciting) {
		u64 rtt_sample = ktime_us_delta(now, largest_acked_pkt->sent_time);

		if (rtt_sample > 0) {
			bool confirmed = (conn && READ_ONCE(conn->state) == TQUIC_CONN_CONNECTED);

			mp_rtt_update(&state->rtt, rtt_sample,
				      frame->ack_delay, confirmed);

			/* Update path stats */
			if (state->path) {
				state->path->stats.rtt_smoothed =
					(u32)state->rtt.smoothed_rtt;
				state->path->stats.rtt_variance =
					(u32)state->rtt.rtt_var;
				if (state->rtt.min_rtt != ULLONG_MAX)
					state->path->stats.rtt_min =
						(u32)state->rtt.min_rtt;
			}
		}
	}

	/* Detect lost packets */
	lost_count = mp_detect_lost_packets(state, pn_space, &lost_packets);

	/* Reset PTO count on acknowledgment */
	if (includes_ack_eliciting)
		state->pto_count = 0;

	spin_unlock_bh(&state->lock);

	/* Process ECN feedback */
	if (frame->has_ecn) {
		spin_lock_bh(&state->lock);

		if (frame->ect0_count < state->ecn_acked.ect0 ||
		    frame->ect1_count < state->ecn_acked.ect1 ||
		    frame->ecn_ce_count < state->ecn_acked.ce) {
			/* ECN counts decreased - disable ECN */
			state->ecn_capable = false;
			state->ecn_validated = false;
		} else {
			u64 ce_delta = frame->ecn_ce_count - state->ecn_acked.ce;

			state->ecn_acked.ect0 = frame->ect0_count;
			state->ecn_acked.ect1 = frame->ect1_count;
			state->ecn_acked.ce = frame->ecn_ce_count;

			if (!state->ecn_validated)
				state->ecn_validated = true;

			/* Signal congestion on CE increase */
			if (ce_delta > 0 && state->path && state->path->cong_ops) {
				if (state->path->cong_ops->on_loss)
					state->path->cong_ops->on_loss(
						state->path->cong, 0);
			}
		}

		spin_unlock_bh(&state->lock);
	}

	/* Notify congestion controller of acked bytes */
	if (state->path && state->path->cong_ops && acked_bytes > 0) {
		if (state->path->cong_ops->on_ack)
			state->path->cong_ops->on_ack(state->path->cong,
						      acked_bytes,
						      state->rtt.latest_rtt);
	}

	/* Notify congestion controller of lost packets */
	if (lost_count > 0 && state->path && state->path->cong_ops) {
		u64 lost_bytes = 0;

		list_for_each_entry(pkt, &lost_packets, list)
			lost_bytes += pkt->sent_bytes;

		if (state->path->cong_ops->on_loss)
			state->path->cong_ops->on_loss(state->path->cong,
						       lost_bytes);

		if (state->path)
			state->path->stats.lost_packets += lost_count;
	}

	/* Free acknowledged packets */
	list_for_each_entry_safe(pkt, tmp, &newly_acked, list) {
		list_del_init(&pkt->list);
		mp_sent_packet_free(pkt);
	}

	/* Free lost packets */
	list_for_each_entry_safe(pkt, tmp, &lost_packets, list) {
		list_del_init(&pkt->list);
		mp_sent_packet_free(pkt);
	}

	return 0;
}
EXPORT_SYMBOL_GPL(tquic_mp_on_ack_received);

/*
 * =============================================================================
 * Packet Sending Interface
 * =============================================================================
 */

/**
 * tquic_mp_on_packet_sent - Record a sent packet for a path
 * @state: Path ACK state
 * @pn_space: Packet number space
 * @pn: Packet number
 * @sent_bytes: Packet size
 * @is_ack_eliciting: Whether packet requires ACK
 * @in_flight: Whether packet counts as in-flight
 *
 * Returns 0 on success or negative error.
 */
int tquic_mp_on_packet_sent(struct tquic_mp_path_ack_state *state,
			    int pn_space, u64 pn, u32 sent_bytes,
			    bool is_ack_eliciting, bool in_flight)
{
	struct tquic_mp_sent_packet *pkt;
	ktime_t now = ktime_get();

	if (!state)
		return -EINVAL;

	pkt = mp_sent_packet_alloc(GFP_ATOMIC);
	if (!pkt)
		return -ENOMEM;

	pkt->pn = pn;
	pkt->path_id = state->path_id;
	pkt->sent_time = now;
	pkt->sent_bytes = sent_bytes;
	pkt->pn_space = pn_space;

	if (is_ack_eliciting)
		pkt->flags |= TQUIC_MP_PKT_ACK_ELICITING;
	if (in_flight)
		pkt->flags |= TQUIC_MP_PKT_IN_FLIGHT;

	spin_lock_bh(&state->lock);

	mp_sent_packet_insert(state, pkt);

	if (in_flight) {
		state->bytes_in_flight += sent_bytes;
		state->packets_in_flight++;
	}

	if (is_ack_eliciting) {
		state->last_ack_eliciting_time[pn_space] = now;
		state->ack_eliciting_in_flight[pn_space]++;
	}

	spin_unlock_bh(&state->lock);

	return 0;
}
EXPORT_SYMBOL_GPL(tquic_mp_on_packet_sent);

/*
 * =============================================================================
 * Statistics
 * =============================================================================
 */

/**
 * tquic_mp_get_rtt_stats - Get RTT statistics for a path
 * @state: Path ACK state
 * @latest: Output for latest RTT
 * @smoothed: Output for smoothed RTT
 * @variance: Output for RTT variance
 * @min_rtt: Output for minimum RTT
 */
void tquic_mp_get_rtt_stats(struct tquic_mp_path_ack_state *state,
			    u64 *latest, u64 *smoothed,
			    u64 *variance, u64 *min_rtt)
{
	if (!state)
		return;

	spin_lock_bh(&state->lock);

	if (latest)
		*latest = state->rtt.latest_rtt;
	if (smoothed)
		*smoothed = state->rtt.smoothed_rtt;
	if (variance)
		*variance = state->rtt.rtt_var;
	if (min_rtt)
		*min_rtt = (state->rtt.min_rtt != ULLONG_MAX) ?
			   state->rtt.min_rtt : 0;

	spin_unlock_bh(&state->lock);
}
EXPORT_SYMBOL_GPL(tquic_mp_get_rtt_stats);

/**
 * tquic_mp_get_in_flight - Get bytes and packets in flight for a path
 * @state: Path ACK state
 * @bytes: Output for bytes in flight
 * @packets: Output for packets in flight
 */
void tquic_mp_get_in_flight(struct tquic_mp_path_ack_state *state,
			    u64 *bytes, u32 *packets)
{
	if (!state)
		return;

	spin_lock_bh(&state->lock);

	if (bytes)
		*bytes = state->bytes_in_flight;
	if (packets)
		*packets = state->packets_in_flight;

	spin_unlock_bh(&state->lock);
}
EXPORT_SYMBOL_GPL(tquic_mp_get_in_flight);

/*
 * =============================================================================
 * Module Initialization
 * =============================================================================
 */

/**
 * tquic_mp_ack_init - Initialize multipath ACK module
 */
int __init tquic_mp_ack_init(void)
{
	mp_ack_state_cache = kmem_cache_create("tquic_mp_ack_state",
		sizeof(struct tquic_mp_path_ack_state), 0, SLAB_HWCACHE_ALIGN, NULL);
	if (!mp_ack_state_cache)
		goto err_ack_state;

	mp_sent_packet_cache = kmem_cache_create("tquic_mp_sent_packet",
		sizeof(struct tquic_mp_sent_packet), 0, SLAB_HWCACHE_ALIGN, NULL);
	if (!mp_sent_packet_cache)
		goto err_sent_packet;

	mp_ack_range_cache = kmem_cache_create("tquic_mp_ack_range",
		sizeof(struct tquic_mp_ack_range_entry), 0, SLAB_HWCACHE_ALIGN, NULL);
	if (!mp_ack_range_cache)
		goto err_ack_range;

	pr_info("tquic: Multipath ACK processing initialized (RFC 9369)\n");
	return 0;

err_ack_range:
	kmem_cache_destroy(mp_sent_packet_cache);
err_sent_packet:
	kmem_cache_destroy(mp_ack_state_cache);
err_ack_state:
	return -ENOMEM;
}

/**
 * tquic_mp_ack_exit - Cleanup multipath ACK module
 */
void tquic_mp_ack_exit(void)
{
	kmem_cache_destroy(mp_ack_range_cache);
	kmem_cache_destroy(mp_sent_packet_cache);
	kmem_cache_destroy(mp_ack_state_cache);

	pr_info("tquic: Multipath ACK processing cleaned up\n");
}

#ifndef TQUIC_OUT_OF_TREE
MODULE_DESCRIPTION("TQUIC Multipath ACK Processing (RFC 9369)");
MODULE_LICENSE("GPL");
#endif
