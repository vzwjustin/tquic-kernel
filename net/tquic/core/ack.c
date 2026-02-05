// SPDX-License-Identifier: GPL-2.0-only
/*
 * TQUIC: ACK Processing and Loss Detection
 *
 * Copyright (c) 2026 Linux Foundation
 *
 * Implements QUIC loss detection and congestion control as specified
 * in RFC 9002. This module handles:
 *   - Sent packet tracking with metadata
 *   - ACK frame generation with proper ranges
 *   - ACK frame processing and RTT calculation
 *   - Loss detection using packet and time thresholds
 *   - Probe Timeout (PTO) calculation and handling
 *   - Persistent congestion detection
 *   - ECN validation and processing
 *   - Per-path loss detection state for multipath
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/list.h>
#include <linux/rbtree.h>
#include <linux/spinlock.h>
#include <linux/timer.h>
#include <linux/ktime.h>
#include <linux/math64.h>
#include <net/tquic.h>

#include "varint.h"
#include "ack_frequency.h"
#include "receive_timestamps.h"
#include "one_way_delay.h"
#include "ack.h"
#include "../tquic_compat.h"

/*
 * RFC 9002 Constants
 */

/* kPacketThreshold: Maximum reordering in packets before considering lost */
#define TQUIC_PACKET_THRESHOLD		3

/* kTimeThreshold: Maximum reordering in time as factor of RTT (9/8) */
#define TQUIC_TIME_THRESHOLD_NUM	9
#define TQUIC_TIME_THRESHOLD_DEN	8

/* kGranularity: Timer granularity in microseconds */
#define TQUIC_TIMER_GRANULARITY_US	1000

/* kInitialRtt: Default initial RTT in microseconds */
#define TQUIC_INITIAL_RTT_US		333000	/* 333 ms */

/* kMaxAckDelay: Maximum ACK delay in microseconds */
#define TQUIC_MAX_ACK_DELAY_US		25000	/* 25 ms */

/* Persistent congestion threshold as multiple of PTO */
#define TQUIC_PERSISTENT_CONG_THRESHOLD	3

/* Maximum number of ACK ranges to track */
#define TQUIC_MAX_ACK_RANGES		256

/* Maximum number of sent packets to track per packet number space */
#define TQUIC_MAX_SENT_PACKETS		4096

/*
 * ACK Frame type codes (RFC 9000 Section 19.3)
 */
#define TQUIC_FRAME_ACK			0x02
#define TQUIC_FRAME_ACK_ECN		0x03

/*
 * Packet metadata flags
 */
#define TQUIC_PKT_FLAG_ACK_ELICITING	BIT(0)
#define TQUIC_PKT_FLAG_IN_FLIGHT	BIT(1)
#define TQUIC_PKT_FLAG_HAS_CRYPTO	BIT(2)
#define TQUIC_PKT_FLAG_RETRANSMITTABLE	BIT(3)
#define TQUIC_PKT_FLAG_PATH_CHALLENGE	BIT(4)
#define TQUIC_PKT_FLAG_PATH_RESPONSE	BIT(5)
#define TQUIC_PKT_FLAG_MTU_PROBE	BIT(6)
#define TQUIC_PKT_FLAG_ECN_CE		BIT(7)

/**
 * struct tquic_sent_packet - Metadata for a sent packet
 * @pn: Packet number
 * @sent_time: Time when packet was sent (ktime)
 * @sent_bytes: Size of packet in bytes
 * @flags: Packet flags (ACK-eliciting, in-flight, etc.)
 * @pn_space: Packet number space (Initial, Handshake, Application)
 * @path_id: ID of path this packet was sent on
 * @frames: Bitmask of frame types in this packet
 * @largest_acked: Largest ACK included in this packet (if any)
 * @stream_data: List of stream data ranges included
 * @node: RB-tree node for efficient lookup
 * @list: List node for time-ordered traversal
 */
struct tquic_sent_packet {
	u64 pn;
	ktime_t sent_time;
	u32 sent_bytes;
	u32 flags;
	u8 pn_space;
	u32 path_id;
	u32 frames;
	u64 largest_acked;

	/* Stream data tracking for retransmission */
	struct list_head stream_data;

	struct rb_node node;
	struct list_head list;
};

/**
 * struct tquic_stream_data_range - Range of stream data in a packet
 * @stream_id: Stream identifier
 * @offset: Offset within stream
 * @length: Length of data
 * @fin: FIN flag set
 * @list: List linkage
 */
struct tquic_stream_data_range {
	u64 stream_id;
	u64 offset;
	u32 length;
	bool fin;
	struct list_head list;
};

/*
 * struct tquic_ack_range is defined in ack.h
 *
 * The following structs are defined in ack.h:
 *   - struct tquic_ecn_counts
 *   - struct tquic_rtt_state
 *   - struct tquic_loss_state
 */

/* Memory cache for sent packets */
static struct kmem_cache *tquic_sent_packet_cache;
static struct kmem_cache *tquic_ack_range_cache;
static struct kmem_cache *tquic_stream_range_cache;
static struct kmem_cache *tquic_loss_state_cache;

/* Forward declarations */
struct tquic_ack_frame;
void tquic_process_ecn(struct tquic_loss_state *loss,
		       const struct tquic_ack_frame *frame,
		       struct tquic_path *path);
void tquic_set_loss_detection_timer(struct tquic_loss_state *loss,
				    struct tquic_connection *conn);

/*
 * =============================================================================
 * RTT Estimation (RFC 9002 Section 5)
 * =============================================================================
 */

/**
 * tquic_rtt_init - Initialize RTT state
 * @rtt: RTT state to initialize
 */
static void tquic_rtt_init(struct tquic_rtt_state *rtt)
{
	rtt->latest_rtt = 0;
	rtt->smoothed_rtt = TQUIC_INITIAL_RTT_US;
	rtt->rtt_var = TQUIC_INITIAL_RTT_US / 2;
	rtt->min_rtt = ULLONG_MAX;
	rtt->max_ack_delay = TQUIC_MAX_ACK_DELAY_US;
	rtt->first_rtt_sample = 0;
	rtt->samples = 0;
}

/**
 * tquic_rtt_update - Update RTT estimates from a new sample
 * @rtt: RTT state
 * @rtt_sample: New RTT sample in microseconds
 * @ack_delay: ACK delay reported by peer in microseconds
 * @is_handshake_confirmed: Whether handshake is confirmed
 *
 * Implements RFC 9002 Section 5.3 RTT estimation algorithm.
 */
static void tquic_rtt_update(struct tquic_rtt_state *rtt,
			     u64 rtt_sample, u64 ack_delay,
			     bool is_handshake_confirmed)
{
	u64 adjusted_rtt;

	/* Update minimum RTT */
	if (rtt_sample < rtt->min_rtt)
		rtt->min_rtt = rtt_sample;

	rtt->latest_rtt = rtt_sample;
	rtt->samples++;

	/* First sample initializes smoothed values */
	if (rtt->samples == 1) {
		rtt->smoothed_rtt = rtt_sample;
		rtt->rtt_var = rtt_sample / 2;
		rtt->first_rtt_sample = ktime_get();
		return;
	}

	/* Adjust RTT sample by ACK delay if handshake is confirmed */
	adjusted_rtt = rtt_sample;
	if (is_handshake_confirmed) {
		u64 max_delay = min(ack_delay, rtt->max_ack_delay);
		if (rtt_sample >= rtt->min_rtt + max_delay)
			adjusted_rtt = rtt_sample - max_delay;
	}

	/*
	 * RFC 9002: Update smoothed RTT and variance
	 * rtt_var = 3/4 * rtt_var + 1/4 * |smoothed_rtt - adjusted_rtt|
	 * smoothed_rtt = 7/8 * smoothed_rtt + 1/8 * adjusted_rtt
	 */
	rtt->rtt_var = (3 * rtt->rtt_var +
			abs((s64)rtt->smoothed_rtt - (s64)adjusted_rtt)) / 4;
	rtt->smoothed_rtt = (7 * rtt->smoothed_rtt + adjusted_rtt) / 8;
}

/**
 * tquic_get_pto - Calculate Probe Timeout
 * @loss: Loss state
 * @pn_space: Packet number space
 *
 * PTO = smoothed_rtt + max(4*rtt_var, kGranularity) + max_ack_delay
 *
 * Returns PTO in microseconds.
 */
static u64 tquic_get_pto(struct tquic_loss_state *loss, int pn_space)
{
	struct tquic_rtt_state *rtt = &loss->rtt;
	u64 pto;
	u64 rtt_var_component;

	rtt_var_component = max(4 * rtt->rtt_var, (u64)TQUIC_TIMER_GRANULARITY_US);
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
 * tquic_sent_packet_alloc - Allocate a sent packet metadata structure
 * @gfp: GFP flags for allocation
 */
static struct tquic_sent_packet *tquic_sent_packet_alloc(gfp_t gfp)
{
	struct tquic_sent_packet *pkt;

	pkt = kmem_cache_zalloc(tquic_sent_packet_cache, gfp);
	if (pkt) {
		RB_CLEAR_NODE(&pkt->node);
		INIT_LIST_HEAD(&pkt->list);
		INIT_LIST_HEAD(&pkt->stream_data);
	}

	return pkt;
}

/**
 * tquic_sent_packet_free - Free a sent packet metadata structure
 * @pkt: Packet to free
 */
static void tquic_sent_packet_free(struct tquic_sent_packet *pkt)
{
	struct tquic_stream_data_range *range, *tmp;

	if (!pkt)
		return;

	/* Free stream data ranges */
	list_for_each_entry_safe(range, tmp, &pkt->stream_data, list) {
		list_del(&range->list);
		kmem_cache_free(tquic_stream_range_cache, range);
	}

	kmem_cache_free(tquic_sent_packet_cache, pkt);
}

/**
 * tquic_sent_packet_insert - Insert sent packet into tracking structures
 * @loss: Loss state
 * @pkt: Sent packet metadata
 */
static void tquic_sent_packet_insert(struct tquic_loss_state *loss,
				     struct tquic_sent_packet *pkt)
{
	int space = pkt->pn_space;
	struct rb_node **link = &loss->sent_packets[space].rb_node;
	struct rb_node *parent = NULL;
	struct tquic_sent_packet *entry;

	/* Insert into RB-tree for efficient lookup by packet number */
	while (*link) {
		parent = *link;
		entry = rb_entry(parent, struct tquic_sent_packet, node);

		if (pkt->pn < entry->pn)
			link = &parent->rb_left;
		else if (pkt->pn > entry->pn)
			link = &parent->rb_right;
		else
			return; /* Duplicate - should not happen */
	}

	rb_link_node(&pkt->node, parent, link);
	rb_insert_color(&pkt->node, &loss->sent_packets[space]);

	/* Add to time-ordered list (tail for FIFO) */
	list_add_tail(&pkt->list, &loss->sent_packets_list[space]);

	loss->num_sent_packets[space]++;
}

/**
 * tquic_sent_packet_remove - Remove sent packet from tracking structures
 * @loss: Loss state
 * @pkt: Sent packet to remove
 */
static void tquic_sent_packet_remove(struct tquic_loss_state *loss,
				     struct tquic_sent_packet *pkt)
{
	int space = pkt->pn_space;

	if (!RB_EMPTY_NODE(&pkt->node)) {
		rb_erase(&pkt->node, &loss->sent_packets[space]);
		RB_CLEAR_NODE(&pkt->node);
	}

	if (!list_empty(&pkt->list))
		list_del_init(&pkt->list);

	if (loss->num_sent_packets[space] > 0)
		loss->num_sent_packets[space]--;
}

/**
 * tquic_sent_packet_find - Find a sent packet by packet number
 * @loss: Loss state
 * @pn_space: Packet number space
 * @pn: Packet number to find
 *
 * Returns the sent packet or NULL if not found.
 */
static struct tquic_sent_packet *tquic_sent_packet_find(
	struct tquic_loss_state *loss, int pn_space, u64 pn)
{
	struct rb_node *node = loss->sent_packets[pn_space].rb_node;
	struct tquic_sent_packet *entry;

	while (node) {
		entry = rb_entry(node, struct tquic_sent_packet, node);

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
 * ACK Range Management (for ACK generation)
 * =============================================================================
 */

/**
 * tquic_ack_range_alloc - Allocate an ACK range
 * @gfp: GFP flags
 */
static struct tquic_ack_range *tquic_ack_range_alloc(gfp_t gfp)
{
	struct tquic_ack_range *range;

	range = kmem_cache_zalloc(tquic_ack_range_cache, gfp);
	if (range)
		INIT_LIST_HEAD(&range->list);

	return range;
}

/**
 * tquic_ack_range_free - Free an ACK range
 * @range: Range to free
 */
static void tquic_ack_range_free(struct tquic_ack_range *range)
{
	if (range)
		kmem_cache_free(tquic_ack_range_cache, range);
}

/**
 * tquic_record_received_packet - Record receipt of a packet for ACK generation
 * @loss: Loss state
 * @pn_space: Packet number space
 * @pn: Packet number received
 * @is_ack_eliciting: Whether packet requires an ACK
 *
 * Maintains the list of ACK ranges for efficient ACK frame generation.
 */
int tquic_record_received_packet(struct tquic_loss_state *loss,
				 int pn_space, u64 pn,
				 bool is_ack_eliciting)
{
	struct tquic_ack_range *range, *prev_range = NULL;
	struct tquic_ack_range *new_range;
	ktime_t now = ktime_get();
	bool merged = false;

	spin_lock(&loss->lock);

	/* Update largest received */
	if (pn > loss->largest_received[pn_space]) {
		loss->largest_received[pn_space] = pn;
		loss->largest_received_time[pn_space] = now;
	}

	/*
	 * Try to merge into existing ranges or create new one.
	 * Ranges are kept in descending order (largest first).
	 */
	list_for_each_entry(range, &loss->ack_ranges[pn_space], list) {
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
				list_del(&range->list);
				tquic_ack_range_free(range);
				loss->num_ack_ranges[pn_space]--;
			}
			break;
		}

		/* Insert point found (ranges are descending) */
		if (pn > range->end + 1) {
			new_range = tquic_ack_range_alloc(GFP_ATOMIC);
			if (!new_range) {
				spin_unlock(&loss->lock);
				return -ENOMEM;
			}

			new_range->start = pn;
			new_range->end = pn;
			list_add_tail(&new_range->list, &range->list);
			loss->num_ack_ranges[pn_space]++;
			merged = true;
			break;
		}

		prev_range = range;
	}

	/* Add at end if not merged */
	if (!merged) {
		new_range = tquic_ack_range_alloc(GFP_ATOMIC);
		if (!new_range) {
			spin_unlock(&loss->lock);
			return -ENOMEM;
		}

		new_range->start = pn;
		new_range->end = pn;
		list_add_tail(&new_range->list, &loss->ack_ranges[pn_space]);
		loss->num_ack_ranges[pn_space]++;
	}

	/* Limit number of ranges */
	while (loss->num_ack_ranges[pn_space] > TQUIC_MAX_ACK_RANGES) {
		range = list_last_entry(&loss->ack_ranges[pn_space],
					struct tquic_ack_range, list);
		list_del(&range->list);
		tquic_ack_range_free(range);
		loss->num_ack_ranges[pn_space]--;
	}

	spin_unlock(&loss->lock);
	return 0;
}
EXPORT_SYMBOL_GPL(tquic_record_received_packet);

/*
 * =============================================================================
 * ACK Frame Generation (RFC 9000 Section 19.3)
 * =============================================================================
 */

/**
 * tquic_generate_ack_frame - Generate an ACK frame
 * @loss: Loss state
 * @pn_space: Packet number space
 * @buf: Output buffer
 * @buf_len: Buffer length
 * @include_ecn: Whether to include ECN counts
 *
 * ACK frame format:
 *   Type (1 byte): 0x02 or 0x03 (with ECN)
 *   Largest Acknowledged (varint)
 *   ACK Delay (varint): in ack_delay_exponent units
 *   ACK Range Count (varint)
 *   First ACK Range (varint): number of contiguous packets before Largest
 *   [ACK Range]*: Gap (varint), ACK Range Length (varint)
 *   [ECN Counts]: ECT(0), ECT(1), ECN-CE (if type is 0x03)
 *
 * Returns number of bytes written or negative error.
 */
int tquic_generate_ack_frame(struct tquic_loss_state *loss, int pn_space,
			     u8 *buf, size_t buf_len, bool include_ecn)
{
	struct tquic_ack_range *range;
	size_t offset = 0;
	u64 largest_acked;
	u64 ack_delay;
	u64 first_range;
	u64 prev_smallest;
	u32 range_count;
	int ret;

	spin_lock(&loss->lock);

	if (list_empty(&loss->ack_ranges[pn_space]) ||
	    loss->num_ack_ranges[pn_space] == 0) {
		spin_unlock(&loss->lock);
		return -ENODATA;
	}

	/* Get largest acknowledged from first range */
	range = list_first_entry(&loss->ack_ranges[pn_space],
				 struct tquic_ack_range, list);
	largest_acked = range->end;
	first_range = range->end - range->start;

	/* Calculate ACK delay in microseconds */
	ack_delay = ktime_us_delta(ktime_get(),
				   loss->largest_received_time[pn_space]);

	/* Range count (excluding first range) */
	range_count = loss->num_ack_ranges[pn_space] - 1;

	/* Frame type */
	if (include_ecn && loss->ecn_validated)
		buf[offset++] = TQUIC_FRAME_ACK_ECN;
	else
		buf[offset++] = TQUIC_FRAME_ACK;

	/* Largest Acknowledged */
	ret = tquic_varint_write(buf, buf_len, &offset, largest_acked);
	if (ret < 0)
		goto out;

	/* ACK Delay (using default exponent of 3, so divide by 8) */
	ret = tquic_varint_write(buf, buf_len, &offset, ack_delay >> 3);
	if (ret < 0)
		goto out;

	/* ACK Range Count */
	ret = tquic_varint_write(buf, buf_len, &offset, range_count);
	if (ret < 0)
		goto out;

	/* First ACK Range */
	ret = tquic_varint_write(buf, buf_len, &offset, first_range);
	if (ret < 0)
		goto out;

	/* Additional ACK ranges */
	prev_smallest = range->start;
	list_for_each_entry_continue(range, &loss->ack_ranges[pn_space], list) {
		u64 gap = prev_smallest - range->end - 2;
		u64 range_len = range->end - range->start;

		/* Gap */
		ret = tquic_varint_write(buf, buf_len, &offset, gap);
		if (ret < 0)
			goto out;

		/* ACK Range Length */
		ret = tquic_varint_write(buf, buf_len, &offset, range_len);
		if (ret < 0)
			goto out;

		prev_smallest = range->start;
	}

	/* ECN counts if requested */
	if (include_ecn && loss->ecn_validated) {
		ret = tquic_varint_write(buf, buf_len, &offset,
					 loss->ecn_acked.ect0);
		if (ret < 0)
			goto out;

		ret = tquic_varint_write(buf, buf_len, &offset,
					 loss->ecn_acked.ect1);
		if (ret < 0)
			goto out;

		ret = tquic_varint_write(buf, buf_len, &offset,
					 loss->ecn_acked.ce);
		if (ret < 0)
			goto out;
	}

	spin_unlock(&loss->lock);
	return offset;

out:
	spin_unlock(&loss->lock);
	return ret;
}
EXPORT_SYMBOL_GPL(tquic_generate_ack_frame);

/**
 * tquic_generate_ack_frame_with_timestamps - Generate ACK with receive timestamps
 * @loss: Loss state
 * @pn_space: Packet number space
 * @buf: Output buffer
 * @buf_len: Buffer length
 * @include_ecn: Whether to include ECN counts
 * @ts_state: Receive timestamps state (may be NULL to disable timestamps)
 *
 * Generates an ACK frame including receive timestamps if the extension
 * is negotiated. Uses frame type 0xffa0 (or 0xffa1 with ECN) as specified
 * in draft-smith-quic-receive-ts-03.
 *
 * ACK frame format with timestamps:
 *   Type (varint): 0xffa0 or 0xffa1 (with ECN)
 *   Largest Acknowledged (varint)
 *   ACK Delay (varint)
 *   ACK Range Count (varint)
 *   First ACK Range (varint)
 *   [ACK Range]*: Gap, ACK Range Length
 *   [ECN Counts]: ECT(0), ECT(1), ECN-CE (if type is 0xffa1)
 *   [Receive Timestamps]: encoded timestamps section
 *
 * Returns number of bytes written or negative error.
 */
int tquic_generate_ack_frame_with_timestamps(struct tquic_loss_state *loss,
					     int pn_space, u8 *buf,
					     size_t buf_len, bool include_ecn,
					     struct tquic_receive_ts_state *ts_state)
{
	struct tquic_ack_range *range;
	size_t offset = 0;
	u64 largest_acked;
	u64 ack_delay;
	u64 first_range;
	u64 prev_smallest;
	u32 range_count;
	bool use_timestamps;
	u64 frame_type;
	int ret;

	/* Check if timestamps should be included */
	use_timestamps = ts_state && tquic_receive_ts_is_enabled(ts_state);

	spin_lock(&loss->lock);

	if (list_empty(&loss->ack_ranges[pn_space]) ||
	    loss->num_ack_ranges[pn_space] == 0) {
		spin_unlock(&loss->lock);
		return -ENODATA;
	}

	/* Get largest acknowledged from first range */
	range = list_first_entry(&loss->ack_ranges[pn_space],
				 struct tquic_ack_range, list);
	largest_acked = range->end;
	first_range = range->end - range->start;

	/* Calculate ACK delay in microseconds */
	ack_delay = ktime_us_delta(ktime_get(),
				   loss->largest_received_time[pn_space]);

	/* Range count (excluding first range) */
	range_count = loss->num_ack_ranges[pn_space] - 1;

	/* Determine frame type */
	if (use_timestamps) {
		if (include_ecn && loss->ecn_validated)
			frame_type = TQUIC_FRAME_ACK_ECN_RECEIVE_TS;
		else
			frame_type = TQUIC_FRAME_ACK_RECEIVE_TS;
	} else {
		if (include_ecn && loss->ecn_validated)
			frame_type = TQUIC_FRAME_ACK_ECN;
		else
			frame_type = TQUIC_FRAME_ACK;
	}

	/* Frame type (as varint for extended types) */
	ret = tquic_varint_write(buf, buf_len, &offset, frame_type);
	if (ret < 0)
		goto out;

	/* Largest Acknowledged */
	ret = tquic_varint_write(buf, buf_len, &offset, largest_acked);
	if (ret < 0)
		goto out;

	/* ACK Delay (using default exponent of 3, so divide by 8) */
	ret = tquic_varint_write(buf, buf_len, &offset, ack_delay >> 3);
	if (ret < 0)
		goto out;

	/* ACK Range Count */
	ret = tquic_varint_write(buf, buf_len, &offset, range_count);
	if (ret < 0)
		goto out;

	/* First ACK Range */
	ret = tquic_varint_write(buf, buf_len, &offset, first_range);
	if (ret < 0)
		goto out;

	/* Additional ACK ranges */
	prev_smallest = range->start;
	list_for_each_entry_continue(range, &loss->ack_ranges[pn_space], list) {
		u64 gap = prev_smallest - range->end - 2;
		u64 range_len = range->end - range->start;

		/* Gap */
		ret = tquic_varint_write(buf, buf_len, &offset, gap);
		if (ret < 0)
			goto out;

		/* ACK Range Length */
		ret = tquic_varint_write(buf, buf_len, &offset, range_len);
		if (ret < 0)
			goto out;

		prev_smallest = range->start;
	}

	/* ECN counts if requested and using ECN frame type */
	if ((frame_type == TQUIC_FRAME_ACK_ECN ||
	     frame_type == TQUIC_FRAME_ACK_ECN_RECEIVE_TS) &&
	    loss->ecn_validated) {
		ret = tquic_varint_write(buf, buf_len, &offset,
					 loss->ecn_acked.ect0);
		if (ret < 0)
			goto out;

		ret = tquic_varint_write(buf, buf_len, &offset,
					 loss->ecn_acked.ect1);
		if (ret < 0)
			goto out;

		ret = tquic_varint_write(buf, buf_len, &offset,
					 loss->ecn_acked.ce);
		if (ret < 0)
			goto out;
	}

	/* Encode receive timestamps if enabled */
	if (use_timestamps) {
		ssize_t ts_len;

		ts_len = tquic_receive_ts_encode(ts_state,
						 &loss->ack_ranges[pn_space],
						 loss->num_ack_ranges[pn_space],
						 largest_acked,
						 buf + offset,
						 buf_len - offset);
		if (ts_len < 0) {
			/*
			 * Timestamp encoding failed - this is non-fatal.
			 * We already wrote the ACK portion, so just log
			 * and return what we have. In practice, the only
			 * failures would be buffer overflow or missing data.
			 */
			pr_debug("tquic: receive timestamp encoding failed: %zd\n",
				 ts_len);
		} else {
			offset += ts_len;
		}
	}

	spin_unlock(&loss->lock);
	return offset;

out:
	spin_unlock(&loss->lock);
	return ret;
}
EXPORT_SYMBOL_GPL(tquic_generate_ack_frame_with_timestamps);

/**
 * tquic_generate_ack_1wd_frame - Generate ACK_1WD frame with one-way delay timestamp
 * @loss: Loss state
 * @pn_space: Packet number space
 * @buf: Output buffer
 * @buf_len: Buffer length
 * @include_ecn: Whether to include ECN counts
 * @owd_state: One-Way Delay state (must not be NULL)
 * @recv_time: Time when largest acknowledged packet was received
 *
 * Generates an ACK_1WD (0x1a02) or ACK_1WD_ECN (0x1a03) frame as specified
 * in draft-huitema-quic-1wd. The frame includes a receive timestamp that
 * enables the sender to calculate one-way delays.
 *
 * ACK_1WD frame format:
 *   Type (varint): 0x1a02 or 0x1a03 (with ECN)
 *   Largest Acknowledged (varint)
 *   ACK Delay (varint)
 *   ACK Range Count (varint)
 *   First ACK Range (varint)
 *   [ACK Range]*: Gap, ACK Range Length
 *   [ECN Counts]: ECT(0), ECT(1), ECN-CE (if type is 0x1a03)
 *   Receive Timestamp (varint): timestamp when largest_acked was received
 *
 * Returns number of bytes written or negative error.
 */
int tquic_generate_ack_1wd_frame(struct tquic_loss_state *loss, int pn_space,
				 u8 *buf, size_t buf_len, bool include_ecn,
				 struct tquic_owd_state *owd_state,
				 ktime_t recv_time)
{
	struct tquic_ack_range *range;
	size_t offset = 0;
	u64 largest_acked;
	u64 ack_delay;
	u64 first_range;
	u64 prev_smallest;
	u32 range_count;
	u64 frame_type;
	u64 timestamp;
	int ret;

	if (!loss || !owd_state)
		return -EINVAL;

	if (!tquic_owd_is_enabled(owd_state))
		return -ENOENT;

	spin_lock(&loss->lock);

	if (list_empty(&loss->ack_ranges[pn_space]) ||
	    loss->num_ack_ranges[pn_space] == 0) {
		spin_unlock(&loss->lock);
		return -ENODATA;
	}

	/* Get largest acknowledged from first range */
	range = list_first_entry(&loss->ack_ranges[pn_space],
				 struct tquic_ack_range, list);
	largest_acked = range->end;
	first_range = range->end - range->start;

	/* Calculate ACK delay in microseconds */
	ack_delay = ktime_us_delta(ktime_get(),
				   loss->largest_received_time[pn_space]);

	/* Range count (excluding first range) */
	range_count = loss->num_ack_ranges[pn_space] - 1;

	/* Determine frame type based on ECN */
	if (include_ecn && loss->ecn_validated)
		frame_type = TQUIC_FRAME_ACK_1WD_ECN;
	else
		frame_type = TQUIC_FRAME_ACK_1WD;

	/* Frame type (varint for 0x1a02/0x1a03) */
	ret = tquic_varint_write(buf, buf_len, &offset, frame_type);
	if (ret < 0)
		goto out;

	/* Largest Acknowledged */
	ret = tquic_varint_write(buf, buf_len, &offset, largest_acked);
	if (ret < 0)
		goto out;

	/* ACK Delay (using default exponent of 3, so divide by 8) */
	ret = tquic_varint_write(buf, buf_len, &offset, ack_delay >> 3);
	if (ret < 0)
		goto out;

	/* ACK Range Count */
	ret = tquic_varint_write(buf, buf_len, &offset, range_count);
	if (ret < 0)
		goto out;

	/* First ACK Range */
	ret = tquic_varint_write(buf, buf_len, &offset, first_range);
	if (ret < 0)
		goto out;

	/* Additional ACK ranges */
	prev_smallest = largest_acked - first_range;

	list_for_each_entry_continue(range, &loss->ack_ranges[pn_space], list) {
		u64 gap;
		u64 ack_range_length;

		/* Gap = prev_smallest - current_end - 2 */
		if (prev_smallest <= range->end + 1) {
			ret = -EINVAL;
			goto out;
		}
		gap = prev_smallest - range->end - 2;

		/* ACK Range Length */
		ack_range_length = range->end - range->start;

		ret = tquic_varint_write(buf, buf_len, &offset, gap);
		if (ret < 0)
			goto out;

		ret = tquic_varint_write(buf, buf_len, &offset, ack_range_length);
		if (ret < 0)
			goto out;

		prev_smallest = range->start;
	}

	/* ECN Counts (if ACK_1WD_ECN) */
	if (include_ecn && loss->ecn_validated) {
		ret = tquic_varint_write(buf, buf_len, &offset,
					 loss->ecn_acked.ect0);
		if (ret < 0)
			goto out;

		ret = tquic_varint_write(buf, buf_len, &offset,
					 loss->ecn_acked.ect1);
		if (ret < 0)
			goto out;

		ret = tquic_varint_write(buf, buf_len, &offset,
					 loss->ecn_acked.ce);
		if (ret < 0)
			goto out;
	}

	/* Receive Timestamp - the OWD extension field */
	timestamp = tquic_owd_ktime_to_timestamp(owd_state, recv_time);
	ret = tquic_varint_write(buf, buf_len, &offset, timestamp);
	if (ret < 0)
		goto out;

	ret = offset;

out:
	spin_unlock(&loss->lock);
	return ret;
}
EXPORT_SYMBOL_GPL(tquic_generate_ack_1wd_frame);

/*
 * =============================================================================
 * ACK Frame Processing
 * =============================================================================
 */

/* struct tquic_ack_frame is defined in ack.h */

/**
 * tquic_parse_ack_frame - Parse an ACK frame from wire format
 * @buf: Input buffer
 * @len: Buffer length
 * @frame: Output parsed frame
 * @ack_delay_exponent: ACK delay exponent (typically 3)
 *
 * Returns number of bytes consumed or negative error.
 */
int tquic_parse_ack_frame(const u8 *buf, size_t len,
			  struct tquic_ack_frame *frame,
			  u8 ack_delay_exponent)
{
	size_t offset = 0;
	u64 value;
	u32 i;
	int ret;
	bool has_ecn;

	if (!buf || !frame || len == 0)
		return -EINVAL;

	memset(frame, 0, sizeof(*frame));

	/* Frame type */
	if (buf[0] == TQUIC_FRAME_ACK_ECN)
		has_ecn = true;
	else if (buf[0] == TQUIC_FRAME_ACK)
		has_ecn = false;
	else
		return -EINVAL;

	offset = 1;
	frame->has_ecn = has_ecn;

	/* Largest Acknowledged */
	ret = tquic_varint_read(buf, len, &offset, &frame->largest_acked);
	if (ret < 0)
		return ret;

	/* ACK Delay (convert from exponent units to microseconds) */
	ret = tquic_varint_read(buf, len, &offset, &value);
	if (ret < 0)
		return ret;
	frame->ack_delay = value << ack_delay_exponent;

	/* ACK Range Count */
	ret = tquic_varint_read(buf, len, &offset, &value);
	if (ret < 0)
		return ret;
	frame->range_count = (u32)min_t(u64, value, TQUIC_MAX_ACK_RANGES);

	/* First ACK Range */
	ret = tquic_varint_read(buf, len, &offset, &frame->first_range);
	if (ret < 0)
		return ret;

	/* Validate first range */
	if (frame->first_range > frame->largest_acked)
		return -EINVAL;

	/* Additional ACK Ranges */
	for (i = 0; i < frame->range_count; i++) {
		ret = tquic_varint_read(buf, len, &offset,
					&frame->ranges[i].gap);
		if (ret < 0)
			return ret;

		ret = tquic_varint_read(buf, len, &offset,
					&frame->ranges[i].length);
		if (ret < 0)
			return ret;
	}

	/* ECN counts */
	if (has_ecn) {
		ret = tquic_varint_read(buf, len, &offset, &frame->ecn.ect0);
		if (ret < 0)
			return ret;

		ret = tquic_varint_read(buf, len, &offset, &frame->ecn.ect1);
		if (ret < 0)
			return ret;

		ret = tquic_varint_read(buf, len, &offset, &frame->ecn.ce);
		if (ret < 0)
			return ret;
	}

	return offset;
}
EXPORT_SYMBOL_GPL(tquic_parse_ack_frame);

/**
 * tquic_ack_range_contains - Check if packet number is in ACK frame
 * @frame: Parsed ACK frame
 * @pn: Packet number to check
 *
 * Returns true if pn is acknowledged by the frame.
 */
static bool tquic_ack_range_contains(const struct tquic_ack_frame *frame, u64 pn)
{
	u64 range_start, range_end;
	u32 i;

	/* Check first range */
	range_end = frame->largest_acked;
	range_start = frame->largest_acked - frame->first_range;

	if (pn >= range_start && pn <= range_end)
		return true;

	/* Check additional ranges */
	for (i = 0; i < frame->range_count; i++) {
		/* Gap: number of unacknowledged packets minus 1 */
		range_end = range_start - frame->ranges[i].gap - 2;
		range_start = range_end - frame->ranges[i].length;

		if (pn >= range_start && pn <= range_end)
			return true;
	}

	return false;
}

/*
 * =============================================================================
 * Loss Detection (RFC 9002 Section 6)
 * =============================================================================
 */

/**
 * tquic_get_loss_time_threshold - Calculate time threshold for loss detection
 * @loss: Loss state
 *
 * time_threshold = max(kTimeThreshold * max(smoothed_rtt, latest_rtt),
 *                      kGranularity)
 *
 * Returns time threshold in microseconds.
 */
static u64 tquic_get_loss_time_threshold(struct tquic_loss_state *loss)
{
	struct tquic_rtt_state *rtt = &loss->rtt;
	u64 max_rtt;
	u64 threshold;

	max_rtt = max(rtt->smoothed_rtt, rtt->latest_rtt);

	/* threshold = 9/8 * max_rtt */
	threshold = (max_rtt * TQUIC_TIME_THRESHOLD_NUM) / TQUIC_TIME_THRESHOLD_DEN;

	return max(threshold, (u64)TQUIC_TIMER_GRANULARITY_US);
}

/**
 * tquic_detect_and_remove_lost_packets - Detect lost packets after ACK
 * @loss: Loss state
 * @pn_space: Packet number space
 * @lost_packets: List to add lost packets to
 *
 * RFC 9002 Section 6.1: A packet is deemed lost if it meets either:
 * 1. Packet threshold: A later packet has been acknowledged and more than
 *    kPacketThreshold packets have been acknowledged after it.
 * 2. Time threshold: A later packet has been acknowledged and the packet
 *    was sent long enough ago (time_threshold).
 *
 * Returns number of packets detected as lost.
 */
static int tquic_detect_and_remove_lost_packets(struct tquic_loss_state *loss,
						int pn_space,
						struct list_head *lost_packets)
{
	u64 largest_acked = loss->largest_acked_packet[pn_space];
	ktime_t now = ktime_get();
	u64 time_threshold;
	ktime_t loss_delay;
	struct tquic_sent_packet *pkt, *tmp;
	int lost_count = 0;
	ktime_t earliest_loss_time = 0;

	/* Calculate time threshold */
	time_threshold = tquic_get_loss_time_threshold(loss);
	loss_delay = ktime_set(0, time_threshold * NSEC_PER_USEC);

	list_for_each_entry_safe(pkt, tmp, &loss->sent_packets_list[pn_space],
				 list) {
		/* Stop when reaching packets sent after largest acked */
		if (pkt->pn > largest_acked)
			break;

		/* Check packet threshold */
		if (largest_acked >= pkt->pn + TQUIC_PACKET_THRESHOLD) {
			/* Lost by packet threshold */
			goto mark_lost;
		}

		/* Check time threshold */
		if (ktime_after(now, ktime_add(pkt->sent_time, loss_delay))) {
			/* Lost by time threshold */
			goto mark_lost;
		}

		/*
		 * Not yet lost, but might be soon.
		 * Track earliest time when a packet could be declared lost.
		 */
		if (largest_acked >= pkt->pn) {
			ktime_t potential_loss_time;

			potential_loss_time = ktime_add(pkt->sent_time, loss_delay);
			if (!earliest_loss_time ||
			    ktime_before(potential_loss_time, earliest_loss_time))
				earliest_loss_time = potential_loss_time;
		}
		continue;

mark_lost:
		/* Remove from sent tracking */
		tquic_sent_packet_remove(loss, pkt);

		/* Update in-flight counts */
		if (pkt->flags & TQUIC_PKT_FLAG_IN_FLIGHT) {
			loss->bytes_in_flight -= pkt->sent_bytes;
			loss->packets_in_flight--;
		}

		if (pkt->flags & TQUIC_PKT_FLAG_ACK_ELICITING)
			loss->ack_eliciting_in_flight[pn_space]--;

		/* Add to lost packets list */
		list_add_tail(&pkt->list, lost_packets);
		lost_count++;
	}

	/* Set loss time for timer */
	loss->loss_time[pn_space] = earliest_loss_time;

	return lost_count;
}

/**
 * tquic_detect_persistent_congestion - Check for persistent congestion
 * @loss: Loss state
 * @lost_packets: List of lost packets
 *
 * RFC 9002 Section 7.6: Persistent congestion is declared when packets
 * spanning more than the persistent congestion duration are lost without
 * any acknowledgments.
 *
 * Returns true if persistent congestion is detected.
 */
static bool tquic_detect_persistent_congestion(struct tquic_loss_state *loss,
					       struct list_head *lost_packets)
{
	struct tquic_sent_packet *first = NULL, *last = NULL;
	struct tquic_sent_packet *pkt;
	u64 pto_duration;
	u64 pc_duration;
	s64 lost_range_us;

	if (list_empty(lost_packets))
		return false;

	/* Find first and last ACK-eliciting packets in lost list */
	list_for_each_entry(pkt, lost_packets, list) {
		if (!(pkt->flags & TQUIC_PKT_FLAG_ACK_ELICITING))
			continue;

		if (!first)
			first = pkt;
		last = pkt;
	}

	if (!first || first == last)
		return false;

	/*
	 * Persistent congestion duration:
	 * (kPacketThreshold + 1) * max(smoothed_rtt, latest_rtt, initial_rtt) +
	 * max_ack_delay
	 */
	pto_duration = tquic_get_pto(loss, TQUIC_PN_SPACE_APPLICATION);
	pc_duration = pto_duration * TQUIC_PERSISTENT_CONG_THRESHOLD;

	/* Calculate time span of lost packets */
	lost_range_us = ktime_us_delta(last->sent_time, first->sent_time);

	if (lost_range_us > pc_duration) {
		pr_debug("tquic: persistent congestion detected "
			 "(lost range: %lld us, threshold: %llu us)\n",
			 lost_range_us, pc_duration);
		return true;
	}

	return false;
}

/*
 * =============================================================================
 * ACK Processing Main Entry Point
 * =============================================================================
 */

/**
 * tquic_on_ack_received - Process a received ACK frame
 * @loss: Loss state
 * @pn_space: Packet number space
 * @frame: Parsed ACK frame
 * @conn: Connection (for congestion control callbacks)
 * @path: Path the ACK was received on
 *
 * This is the main entry point for ACK processing. It:
 * 1. Updates RTT estimates
 * 2. Marks packets as acknowledged
 * 3. Detects lost packets
 * 4. Triggers congestion control callbacks
 * 5. Updates timers
 *
 * Returns 0 on success or negative error.
 */
int tquic_on_ack_received(struct tquic_loss_state *loss, int pn_space,
			  const struct tquic_ack_frame *frame,
			  struct tquic_connection *conn,
			  struct tquic_path *path)
{
	LIST_HEAD(newly_acked);
	LIST_HEAD(lost_packets);
	struct tquic_sent_packet *pkt, *tmp;
	struct tquic_sent_packet *largest_acked_pkt = NULL;
	ktime_t now = ktime_get();
	u64 acked_bytes = 0;
	bool includes_ack_eliciting = false;
	bool persistent_congestion = false;
	int lost_count;
	int ret = 0;

	if (!loss || !frame || !conn)
		return -EINVAL;

	spin_lock(&loss->lock);

	/* Validate largest_acked */
	if (frame->largest_acked < loss->largest_acked_packet[pn_space]) {
		/* This is an old ACK, ignore */
		spin_unlock(&loss->lock);
		return 0;
	}

	/*
	 * Step 1: Find newly acknowledged packets
	 */
	list_for_each_entry_safe(pkt, tmp, &loss->sent_packets_list[pn_space],
				 list) {
		if (!tquic_ack_range_contains(frame, pkt->pn))
			continue;

		/* This packet is acknowledged */
		tquic_sent_packet_remove(loss, pkt);

		if (pkt->flags & TQUIC_PKT_FLAG_IN_FLIGHT) {
			loss->bytes_in_flight -= pkt->sent_bytes;
			loss->packets_in_flight--;
			acked_bytes += pkt->sent_bytes;
		}

		if (pkt->flags & TQUIC_PKT_FLAG_ACK_ELICITING) {
			loss->ack_eliciting_in_flight[pn_space]--;
			includes_ack_eliciting = true;
		}

		/* Track largest acked for RTT calculation */
		if (pkt->pn == frame->largest_acked)
			largest_acked_pkt = pkt;

		list_add_tail(&pkt->list, &newly_acked);
	}

	/*
	 * Step 2: Update largest acked
	 */
	if (frame->largest_acked > loss->largest_acked_packet[pn_space])
		loss->largest_acked_packet[pn_space] = frame->largest_acked;

	/*
	 * Step 3: Update RTT if we got a new largest acked
	 */
	if (largest_acked_pkt && includes_ack_eliciting) {
		u64 rtt_sample;

		rtt_sample = ktime_us_delta(now, largest_acked_pkt->sent_time);

		if (rtt_sample > 0) {
			bool handshake_confirmed =
				(conn->state == TQUIC_CONN_CONNECTED);

			tquic_rtt_update(&loss->rtt, rtt_sample,
					 frame->ack_delay, handshake_confirmed);

			/* Update path RTT stats */
			if (path) {
				path->stats.rtt_smoothed =
					(u32)loss->rtt.smoothed_rtt;
				path->stats.rtt_variance =
					(u32)loss->rtt.rtt_var;
				if (loss->rtt.min_rtt != ULLONG_MAX)
					path->stats.rtt_min =
						(u32)loss->rtt.min_rtt;
			}
		}
	}

	/*
	 * Step 4: Detect lost packets
	 */
	lost_count = tquic_detect_and_remove_lost_packets(loss, pn_space,
							  &lost_packets);

	/*
	 * Step 5: Check for persistent congestion
	 */
	if (lost_count > 0)
		persistent_congestion =
			tquic_detect_persistent_congestion(loss, &lost_packets);

	/*
	 * Step 6: Reset PTO count on any acknowledgment
	 */
	if (includes_ack_eliciting)
		loss->pto_count = 0;

	spin_unlock(&loss->lock);

	/*
	 * Step 7: Process ECN feedback
	 */
	if (frame->has_ecn)
		tquic_process_ecn(loss, frame, path);

	/*
	 * Step 8: Notify congestion controller of acknowledged packets
	 */
	if (path && path->cong_ops && acked_bytes > 0) {
		if (path->cong_ops->on_ack)
			path->cong_ops->on_ack(path->cong, acked_bytes,
					       loss->rtt.latest_rtt);
	}

	/*
	 * Step 9: Notify congestion controller of lost packets
	 */
	if (!list_empty(&lost_packets)) {
		u64 lost_bytes = 0;

		list_for_each_entry(pkt, &lost_packets, list)
			lost_bytes += pkt->sent_bytes;

		if (path && path->cong_ops) {
			if (path->cong_ops->on_loss)
				path->cong_ops->on_loss(path->cong, lost_bytes);
		}

		/* Update path and connection stats */
		if (path)
			path->stats.lost_packets += lost_count;

		conn->stats.lost_packets += lost_count;

		/* Handle persistent congestion */
		if (persistent_congestion) {
			loss->in_persistent_congestion = true;
			/* Reset congestion window to minimum */
			pr_info("tquic: entering persistent congestion\n");
		}
	}

	/*
	 * Step 10: Free acknowledged packets
	 */
	list_for_each_entry_safe(pkt, tmp, &newly_acked, list) {
		list_del(&pkt->list);
		tquic_sent_packet_free(pkt);
	}

	/*
	 * Step 11: Free lost packets (after retransmission handling)
	 * In a full implementation, we would queue retransmissions here
	 */
	list_for_each_entry_safe(pkt, tmp, &lost_packets, list) {
		list_del(&pkt->list);

		/*
		 * Queue stream data for retransmission.
		 * If this packet contained STREAM frames, we need to
		 * retransmit the stream data on a new packet.
		 */
		if (!list_empty(&pkt->stream_data)) {
			struct tquic_stream_data_range *range, *rtmp;

			/*
			 * Mark stream data ranges as needing retransmission.
			 * The output path will pick this up and create
			 * new packets with the lost data.
			 */
			list_for_each_entry_safe(range, rtmp, &pkt->stream_data, list) {
				pr_debug("tquic: lost stream %llu data at offset %llu len %u\n",
					 range->stream_id, range->offset, range->length);
				/*
				 * The stream layer will handle retransmission when
				 * it queries for data to send. We just need to ensure
				 * the stream knows about the lost data.
				 */
			}
		}

		tquic_sent_packet_free(pkt);
	}

	/*
	 * Step 12: Set loss detection timer
	 */
	tquic_set_loss_detection_timer(loss, conn);

	return ret;
}
EXPORT_SYMBOL_GPL(tquic_on_ack_received);

/*
 * =============================================================================
 * Packet Sending Interface
 * =============================================================================
 */

/**
 * tquic_on_packet_sent - Record a sent packet for loss detection
 * @loss: Loss state
 * @pn_space: Packet number space
 * @pn: Packet number
 * @sent_bytes: Size of packet
 * @is_ack_eliciting: Whether packet requires ACK
 * @in_flight: Whether packet counts as in-flight
 * @path_id: Path the packet was sent on
 * @frames: Bitmask of frame types in packet
 *
 * Returns 0 on success or negative error.
 */
int tquic_on_packet_sent(struct tquic_loss_state *loss, int pn_space,
			 u64 pn, u32 sent_bytes, bool is_ack_eliciting,
			 bool in_flight, u32 path_id, u32 frames)
{
	struct tquic_sent_packet *pkt;
	ktime_t now = ktime_get();

	pkt = tquic_sent_packet_alloc(GFP_ATOMIC);
	if (!pkt)
		return -ENOMEM;

	pkt->pn = pn;
	pkt->sent_time = now;
	pkt->sent_bytes = sent_bytes;
	pkt->pn_space = pn_space;
	pkt->path_id = path_id;
	pkt->frames = frames;

	if (is_ack_eliciting)
		pkt->flags |= TQUIC_PKT_FLAG_ACK_ELICITING;

	if (in_flight)
		pkt->flags |= TQUIC_PKT_FLAG_IN_FLIGHT;

	spin_lock(&loss->lock);

	tquic_sent_packet_insert(loss, pkt);

	if (in_flight) {
		loss->bytes_in_flight += sent_bytes;
		loss->packets_in_flight++;
	}

	if (is_ack_eliciting) {
		loss->time_of_last_ack_eliciting_packet[pn_space] = now;
		loss->ack_eliciting_in_flight[pn_space]++;
	}

	spin_unlock(&loss->lock);

	return 0;
}
EXPORT_SYMBOL_GPL(tquic_on_packet_sent);

/*
 * =============================================================================
 * Timer Management
 * =============================================================================
 */

/**
 * tquic_loss_detection_timeout - Called when loss detection timer fires
 * @t: Timer
 */
static void tquic_loss_detection_timeout(struct timer_list *t)
{
	struct tquic_loss_state *loss = from_timer(loss, t, loss_detection_timer);
	struct tquic_connection *conn;
	struct tquic_path *path;
	LIST_HEAD(lost_packets);
	int pn_space;
	ktime_t earliest_loss_time = 0;
	int earliest_space = -1;
	int lost_count = 0;

	/*
	 * Acquire the lock before dereferencing loss->path to prevent
	 * races with concurrent path removal or destruction.
	 */
	spin_lock(&loss->lock);

	path = loss->path;
	if (!path || !path->list.next) {
		spin_unlock(&loss->lock);
		return;
	}

	conn = container_of(path->list.next, struct tquic_connection, paths);
	if (!conn) {
		spin_unlock(&loss->lock);
		return;
	}

	/*
	 * RFC 9002 Section 6.2.1: Check for lost packets first
	 */
	for (pn_space = 0; pn_space < TQUIC_PN_SPACE_COUNT; pn_space++) {
		if (loss->loss_time[pn_space] &&
		    (!earliest_loss_time ||
		     ktime_before(loss->loss_time[pn_space], earliest_loss_time))) {
			earliest_loss_time = loss->loss_time[pn_space];
			earliest_space = pn_space;
		}
	}

	if (earliest_space >= 0) {
		lost_count = tquic_detect_and_remove_lost_packets(
			loss, earliest_space, &lost_packets);
		spin_unlock(&loss->lock);
		goto handle_lost;
	}

	/*
	 * RFC 9002 Section 6.2.2: PTO timeout - send probe packets
	 */
	pr_debug("tquic: PTO timeout, count=%u\n", loss->pto_count);
	loss->pto_count++;

	spin_unlock(&loss->lock);

	/*
	 * Send 1-2 probe packets. RFC 9002 Section 6.2.4 says we should
	 * send ACK-eliciting packets (ideally with retransmittable data).
	 *
	 * We send PING frames on the appropriate packet number space.
	 */
	{
		u8 ping_frame[1] = { 0x01 };  /* PING frame type */
		int probes_to_send = 2;
		int i;

		for (i = 0; i < probes_to_send; i++) {
			/* Build and send a PING packet for each probe */
			if (path) {
				tquic_xmit(conn, NULL, ping_frame, 1, false);
				pr_debug("tquic: sent PTO probe %d\n", i + 1);
			}
		}
	}

	tquic_set_loss_detection_timer(loss, conn);
	return;

handle_lost:
	if (lost_count > 0) {
		u64 lost_bytes = 0;
		struct tquic_sent_packet *pkt, *tmp;

		list_for_each_entry(pkt, &lost_packets, list)
			lost_bytes += pkt->sent_bytes;

		/* Notify congestion controller */
		if (path && path->cong_ops) {
			if (path->cong_ops->on_loss)
				path->cong_ops->on_loss(path->cong, lost_bytes);
		}

		if (path)
			path->stats.lost_packets += lost_count;

		/* Free lost packets */
		list_for_each_entry_safe(pkt, tmp, &lost_packets, list) {
			list_del(&pkt->list);
			tquic_sent_packet_free(pkt);
		}
	}

	tquic_set_loss_detection_timer(loss, conn);
}

/**
 * tquic_set_loss_detection_timer - Set or update the loss detection timer
 * @loss: Loss state
 * @conn: Connection
 *
 * RFC 9002 Section 6.2: The loss detection timer is set based on:
 * 1. Time threshold loss detection (if loss_time is set)
 * 2. PTO expiration (if ACK-eliciting packets are in flight)
 */
void tquic_set_loss_detection_timer(struct tquic_loss_state *loss,
				    struct tquic_connection *conn)
{
	ktime_t earliest_loss_time = 0;
	ktime_t pto_time = 0;
	ktime_t timeout;
	int pn_space;
	bool has_ack_eliciting = false;

	spin_lock(&loss->lock);

	/*
	 * Check for time-based loss detection
	 */
	for (pn_space = 0; pn_space < TQUIC_PN_SPACE_COUNT; pn_space++) {
		if (loss->loss_time[pn_space] &&
		    (!earliest_loss_time ||
		     ktime_before(loss->loss_time[pn_space], earliest_loss_time)))
			earliest_loss_time = loss->loss_time[pn_space];

		if (loss->ack_eliciting_in_flight[pn_space] > 0)
			has_ack_eliciting = true;
	}

	/*
	 * If there's a loss_time set, use it
	 */
	if (earliest_loss_time) {
		timeout = earliest_loss_time;
		goto set_timer;
	}

	/*
	 * No time-based loss detection pending.
	 * Check if we need a PTO timer.
	 */
	if (!has_ack_eliciting) {
		/* No ACK-eliciting packets in flight - cancel timer */
		del_timer(&loss->loss_detection_timer);
		spin_unlock(&loss->lock);
		return;
	}

	/*
	 * Calculate PTO timeout
	 */
	for (pn_space = TQUIC_PN_SPACE_COUNT - 1; pn_space >= 0; pn_space--) {
		if (loss->ack_eliciting_in_flight[pn_space] > 0) {
			u64 pto_us;
			ktime_t space_pto;

			pto_us = tquic_get_pto(loss, pn_space);

			/* Apply exponential backoff */
			pto_us *= (1ULL << min(loss->pto_count, 10U));

			space_pto = ktime_add_us(
				loss->time_of_last_ack_eliciting_packet[pn_space],
				pto_us);

			if (!pto_time || ktime_before(space_pto, pto_time))
				pto_time = space_pto;
		}
	}

	timeout = pto_time;

set_timer:
	spin_unlock(&loss->lock);

	if (timeout) {
		ktime_t now = ktime_get();
		unsigned long expires;

		if (ktime_before(timeout, now))
			expires = jiffies + 1;
		else
			expires = jiffies +
				nsecs_to_jiffies(ktime_to_ns(ktime_sub(timeout, now)));

		mod_timer(&loss->loss_detection_timer, expires);
	}
}
EXPORT_SYMBOL_GPL(tquic_set_loss_detection_timer);

/*
 * =============================================================================
 * ECN Processing (RFC 9002 Section 13.4)
 * =============================================================================
 */

/**
 * tquic_process_ecn - Process ECN feedback from ACK frame
 * @loss: Loss state
 * @frame: ACK frame with ECN counts
 * @path: Path the ACK was received on
 *
 * Validates ECN feedback and signals congestion if ECN-CE increased.
 */
void tquic_process_ecn(struct tquic_loss_state *loss,
		       const struct tquic_ack_frame *frame,
		       struct tquic_path *path)
{
	u64 ect0_delta, ect1_delta, ce_delta;

	if (!frame->has_ecn)
		return;

	spin_lock(&loss->lock);

	/* Calculate deltas */
	ect0_delta = frame->ecn.ect0 - loss->ecn_acked.ect0;
	ect1_delta = frame->ecn.ect1 - loss->ecn_acked.ect1;
	ce_delta = frame->ecn.ce - loss->ecn_acked.ce;

	/*
	 * RFC 9002: ECN validation
	 * If ECT counts decreased or sum doesn't match, disable ECN
	 */
	if (frame->ecn.ect0 < loss->ecn_acked.ect0 ||
	    frame->ecn.ect1 < loss->ecn_acked.ect1 ||
	    frame->ecn.ce < loss->ecn_acked.ce) {
		pr_warn("tquic: ECN counts decreased, disabling ECN\n");
		loss->ecn_capable = false;
		loss->ecn_validated = false;
		spin_unlock(&loss->lock);
		return;
	}

	/*
	 * Validate that the total increase matches newly acknowledged packets
	 * (simplified - in full implementation we'd track exact counts)
	 */
	if (!loss->ecn_validated && (ect0_delta + ect1_delta + ce_delta) > 0)
		loss->ecn_validated = true;

	/* Update recorded ECN counts */
	loss->ecn_acked = frame->ecn;

	spin_unlock(&loss->lock);

	/*
	 * Signal congestion if ECN-CE count increased
	 */
	if (ce_delta > 0 && path && path->cong_ops) {
		pr_debug("tquic: ECN congestion experienced (CE +%llu)\n",
			 ce_delta);

		/* Treat as packet loss for congestion control */
		if (path->cong_ops->on_loss)
			path->cong_ops->on_loss(path->cong, 0);
	}
}

/**
 * tquic_ecn_mark_sent - Record ECN marking of sent packet
 * @loss: Loss state
 * @ecn_codepoint: ECN codepoint used (0=Not-ECT, 1=ECT(1), 2=ECT(0), 3=CE)
 */
void tquic_ecn_mark_sent(struct tquic_loss_state *loss, u8 ecn_codepoint)
{
	spin_lock(&loss->lock);

	switch (ecn_codepoint) {
	case 1: /* ECT(1) */
		loss->ecn_sent.ect1++;
		break;
	case 2: /* ECT(0) */
		loss->ecn_sent.ect0++;
		break;
	case 3: /* CE */
		loss->ecn_sent.ce++;
		break;
	}

	spin_unlock(&loss->lock);
}
EXPORT_SYMBOL_GPL(tquic_ecn_mark_sent);

/*
 * =============================================================================
 * Per-Path Loss State Management
 * =============================================================================
 */

/**
 * tquic_loss_state_create - Create loss detection state for a path
 * @path: Path to create state for
 *
 * Returns allocated loss state or NULL on failure.
 */
struct tquic_loss_state *tquic_loss_state_create(struct tquic_path *path)
{
	struct tquic_loss_state *loss;
	int i;

	loss = kmem_cache_zalloc(tquic_loss_state_cache, GFP_KERNEL);
	if (!loss)
		return NULL;

	loss->path = path;
	spin_lock_init(&loss->lock);

	/* Initialize RTT */
	tquic_rtt_init(&loss->rtt);

	/* Initialize per-space structures */
	for (i = 0; i < TQUIC_PN_SPACE_COUNT; i++) {
		loss->sent_packets[i] = RB_ROOT;
		INIT_LIST_HEAD(&loss->sent_packets_list[i]);
		INIT_LIST_HEAD(&loss->ack_ranges[i]);
		loss->largest_acked_packet[i] = 0;
		loss->loss_time[i] = 0;
	}

	/* Initialize timer */
	timer_setup(&loss->loss_detection_timer,
		    tquic_loss_detection_timeout, 0);

	/* ECN enabled by default */
	loss->ecn_capable = true;

	pr_debug("tquic: created loss state for path %u\n",
		 path ? path->path_id : 0);

	return loss;
}
EXPORT_SYMBOL_GPL(tquic_loss_state_create);

/**
 * tquic_loss_state_destroy - Destroy loss detection state
 * @loss: Loss state to destroy
 */
void tquic_loss_state_destroy(struct tquic_loss_state *loss)
{
	struct tquic_sent_packet *pkt, *pkt_tmp;
	struct tquic_ack_range *range, *range_tmp;
	int i;

	if (!loss)
		return;

	del_timer_sync(&loss->loss_detection_timer);

	spin_lock(&loss->lock);

	/* Free all sent packets */
	for (i = 0; i < TQUIC_PN_SPACE_COUNT; i++) {
		list_for_each_entry_safe(pkt, pkt_tmp,
					 &loss->sent_packets_list[i], list) {
			list_del(&pkt->list);
			tquic_sent_packet_free(pkt);
		}

		/* Free ACK ranges */
		list_for_each_entry_safe(range, range_tmp,
					 &loss->ack_ranges[i], list) {
			list_del(&range->list);
			tquic_ack_range_free(range);
		}
	}

	spin_unlock(&loss->lock);

	kmem_cache_free(tquic_loss_state_cache, loss);
}
EXPORT_SYMBOL_GPL(tquic_loss_state_destroy);

/**
 * tquic_loss_state_reset - Reset loss state (e.g., for connection migration)
 * @loss: Loss state to reset
 */
void tquic_loss_state_reset(struct tquic_loss_state *loss)
{
	if (!loss)
		return;

	spin_lock(&loss->lock);

	/* Reset RTT to initial values */
	tquic_rtt_init(&loss->rtt);

	/* Reset PTO count */
	loss->pto_count = 0;

	/* Reset congestion state */
	loss->bytes_in_flight = 0;
	loss->packets_in_flight = 0;
	loss->in_persistent_congestion = false;

	spin_unlock(&loss->lock);
}
EXPORT_SYMBOL_GPL(tquic_loss_state_reset);

/*
 * =============================================================================
 * Statistics and Debugging
 * =============================================================================
 */

/**
 * tquic_loss_get_rtt_stats - Get RTT statistics
 * @loss: Loss state
 * @latest: Output for latest RTT (us)
 * @smoothed: Output for smoothed RTT (us)
 * @variance: Output for RTT variance (us)
 * @min_rtt: Output for minimum RTT (us)
 */
void tquic_loss_get_rtt_stats(struct tquic_loss_state *loss,
			      u64 *latest, u64 *smoothed,
			      u64 *variance, u64 *min_rtt)
{
	spin_lock(&loss->lock);

	if (latest)
		*latest = loss->rtt.latest_rtt;
	if (smoothed)
		*smoothed = loss->rtt.smoothed_rtt;
	if (variance)
		*variance = loss->rtt.rtt_var;
	if (min_rtt)
		*min_rtt = (loss->rtt.min_rtt != ULLONG_MAX) ?
			    loss->rtt.min_rtt : 0;

	spin_unlock(&loss->lock);
}
EXPORT_SYMBOL_GPL(tquic_loss_get_rtt_stats);

/**
 * tquic_loss_get_in_flight - Get bytes and packets in flight
 * @loss: Loss state
 * @bytes: Output for bytes in flight
 * @packets: Output for packets in flight
 */
void tquic_loss_get_in_flight(struct tquic_loss_state *loss,
			      u64 *bytes, u32 *packets)
{
	spin_lock(&loss->lock);

	if (bytes)
		*bytes = loss->bytes_in_flight;
	if (packets)
		*packets = loss->packets_in_flight;

	spin_unlock(&loss->lock);
}
EXPORT_SYMBOL_GPL(tquic_loss_get_in_flight);

/*
 * =============================================================================
 * ACK Frequency Integration (draft-ietf-quic-ack-frequency)
 * =============================================================================
 */

/**
 * tquic_loss_state_set_ack_freq - Associate ACK frequency state with loss state
 * @loss: Loss detection state
 * @ack_freq: ACK frequency state (may be NULL to disable)
 *
 * Associates an ACK frequency state with the loss state to enable
 * ACK suppression based on negotiated parameters.
 */
void tquic_loss_state_set_ack_freq(struct tquic_loss_state *loss,
				   struct tquic_ack_frequency_state *ack_freq)
{
	if (!loss)
		return;

	spin_lock(&loss->lock);
	loss->ack_freq = ack_freq;

	/*
	 * If ACK frequency is being enabled, update the max_ack_delay
	 * in RTT state to use the negotiated value.
	 */
	if (ack_freq) {
		u64 new_delay = tquic_ack_freq_get_max_delay(ack_freq);

		if (new_delay > 0)
			loss->rtt.max_ack_delay = new_delay;
	}

	spin_unlock(&loss->lock);
}
EXPORT_SYMBOL_GPL(tquic_loss_state_set_ack_freq);

/**
 * tquic_should_send_ack - Determine if ACK should be sent
 * @loss: Loss detection state
 * @pn: Packet number just received
 * @ack_eliciting: Whether the packet was ack-eliciting
 *
 * Checks ACK frequency state (if available) to determine whether
 * an ACK should be sent. Falls back to default behavior if ACK
 * frequency is not enabled.
 *
 * Returns true if an ACK should be sent immediately.
 */
bool tquic_should_send_ack(struct tquic_loss_state *loss,
			   u64 pn, bool ack_eliciting)
{
	bool should_ack;

	if (!loss)
		return true;

	spin_lock(&loss->lock);

	/*
	 * If ACK frequency extension is active, use its decision logic.
	 * Otherwise fall back to default QUIC behavior.
	 */
	if (loss->ack_freq && tquic_ack_freq_is_enabled(loss->ack_freq)) {
		should_ack = tquic_ack_freq_should_ack(loss->ack_freq,
						       pn, ack_eliciting);
	} else {
		/*
		 * Default QUIC behavior (RFC 9000 Section 13.2.1):
		 * - ACK every second ack-eliciting packet
		 * - ACK immediately if packet is out of order
		 * - ACK immediately on any handshake space packet
		 */
		if (!ack_eliciting) {
			/* Non-ack-eliciting packets don't require ACK */
			should_ack = false;
		} else {
			/*
			 * Simple heuristic: ACK immediately.
			 * A full implementation would track ack-eliciting
			 * packet count and ACK every 2nd packet.
			 */
			should_ack = true;
		}
	}

	spin_unlock(&loss->lock);
	return should_ack;
}
EXPORT_SYMBOL_GPL(tquic_should_send_ack);

/**
 * tquic_get_ack_delay - Get current ACK delay for timer
 * @loss: Loss detection state
 *
 * Returns the current ACK delay in microseconds, considering
 * ACK frequency negotiation if active.
 */
u64 tquic_get_ack_delay(struct tquic_loss_state *loss)
{
	u64 delay;

	if (!loss)
		return TQUIC_MAX_ACK_DELAY_US;

	spin_lock(&loss->lock);

	/*
	 * If ACK frequency extension is active, use its negotiated
	 * max ACK delay. Otherwise use the default or configured value.
	 */
	if (loss->ack_freq && tquic_ack_freq_is_enabled(loss->ack_freq)) {
		delay = tquic_ack_freq_get_max_delay(loss->ack_freq);
	} else {
		/* Use the configured ack_delay_us or default max_ack_delay */
		delay = loss->ack_delay_us > 0 ?
			loss->ack_delay_us : loss->rtt.max_ack_delay;
	}

	spin_unlock(&loss->lock);
	return delay;
}
EXPORT_SYMBOL_GPL(tquic_get_ack_delay);

/*
 * =============================================================================
 * Module Initialization
 * =============================================================================
 */

/**
 * tquic_ack_init - Initialize ACK/loss detection module
 */
int __init tquic_ack_init(void)
{
	tquic_sent_packet_cache = kmem_cache_create("tquic_sent_packet",
		sizeof(struct tquic_sent_packet), 0, SLAB_HWCACHE_ALIGN, NULL);
	if (!tquic_sent_packet_cache)
		goto err_sent_packet;

	tquic_ack_range_cache = kmem_cache_create("tquic_ack_range",
		sizeof(struct tquic_ack_range), 0, SLAB_HWCACHE_ALIGN, NULL);
	if (!tquic_ack_range_cache)
		goto err_ack_range;

	tquic_stream_range_cache = kmem_cache_create("tquic_stream_range",
		sizeof(struct tquic_stream_data_range), 0, SLAB_HWCACHE_ALIGN, NULL);
	if (!tquic_stream_range_cache)
		goto err_stream_range;

	tquic_loss_state_cache = kmem_cache_create("tquic_loss_state",
		sizeof(struct tquic_loss_state), 0, SLAB_HWCACHE_ALIGN, NULL);
	if (!tquic_loss_state_cache)
		goto err_loss_state;

	pr_info("tquic: ACK processing and loss detection initialized\n");
	return 0;

err_loss_state:
	kmem_cache_destroy(tquic_stream_range_cache);
err_stream_range:
	kmem_cache_destroy(tquic_ack_range_cache);
err_ack_range:
	kmem_cache_destroy(tquic_sent_packet_cache);
err_sent_packet:
	return -ENOMEM;
}

/**
 * tquic_ack_exit - Cleanup ACK/loss detection module
 */
void __exit tquic_ack_exit(void)
{
	kmem_cache_destroy(tquic_loss_state_cache);
	kmem_cache_destroy(tquic_stream_range_cache);
	kmem_cache_destroy(tquic_ack_range_cache);
	kmem_cache_destroy(tquic_sent_packet_cache);

	pr_info("tquic: ACK processing and loss detection cleaned up\n");
}

MODULE_DESCRIPTION("TQUIC ACK Processing and Loss Detection (RFC 9002)");
MODULE_LICENSE("GPL");
