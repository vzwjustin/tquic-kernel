// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * TQUIC - True QUIC with WAN Bonding
 *
 * Loss detection and recovery implementation based on RFC 9002
 *
 * Copyright (c) 2026 Justin Adams <spotty118@gmail.com>
 * Kernel implementation by Justin Adams <spotty118@gmail.com>
 */

#include <linux/slab.h>
#include <linux/jiffies.h>
#include <linux/timer.h>
#include <linux/workqueue.h>
#include <linux/rcupdate.h>
#include <net/tquic.h>
#include "ack.h"
#include "../cong/tquic_cong.h"
#include "../cong/persistent_cong.h"
#include "../diag/trace.h"
#include "../tquic_debug.h"
#include "quic_loss.h"
#include "../tquic_init.h"

/* Maximum PTO probes before declaring connection dead */
#define TQUIC_MAX_PTO_COUNT		6

/* Forward declarations */
void tquic_loss_detection_detect_lost(struct tquic_connection *conn, u8 pn_space_idx);

/*
 * Helper to extract connection ID as u64 for tracing/debugging.
 * Uses first 8 bytes of connection ID.
 */
static inline u64 tquic_trace_conn_id(const struct tquic_cid *cid)
{
	u64 id = 0;
	int i;
	int len = cid->len > 8 ? 8 : cid->len;

	for (i = 0; i < len; i++)
		id = (id << 8) | cid->id[i];

	return id;
}

static struct tquic_path *tquic_loss_active_path_get(struct tquic_connection *conn)
{
	struct tquic_path *path;

	rcu_read_lock();
	path = rcu_dereference(conn->active_path);
	if (path && !tquic_path_get(path))
		path = NULL;
	rcu_read_unlock();

	return path;
}

/*
 * Frame queue helper - queue a frame for transmission
 */
static inline int tquic_conn_queue_frame(struct tquic_connection *conn,
					 struct sk_buff *skb)
{
	if (!conn || !skb)
		return -EINVAL;

	skb_queue_tail(&conn->pending_frames, skb);
	return 0;
}

/*
 * struct tquic_sent_packet - Tracks a sent packet for loss detection
 *
 * Used by loss detection to track packets in flight and detect
 * when they should be declared lost per RFC 9002.
 */
struct tquic_sent_packet {
	struct list_head list;
	struct rb_node node;
	u64 pn;
	ktime_t sent_time;
	u32 sent_bytes;
	u32 size;		/* Alias for sent_bytes for API compatibility */
	u8 pn_space;
	u32 path_id;
	bool ack_eliciting;
	bool in_flight;
	bool retransmitted;	/* Packet has been retransmitted */
	u32 frames;
	struct sk_buff *skb;
};

/*
 * RFC 9002 Constants
 *
 * Section 6.2: kTimeThreshold and kPacketThreshold
 * Section 6.2.2: kGranularity
 */
#define TQUIC_TIME_THRESHOLD_NUMER	9
#define TQUIC_TIME_THRESHOLD_DENOM	8
#define TQUIC_PACKET_THRESHOLD		3
#define TQUIC_GRANULARITY_US		1000	/* 1 ms in microseconds */
#define TQUIC_INITIAL_RTT_US		333000	/* 333 ms in microseconds */
#define TQUIC_MAX_ACK_DELAY_US		25000	/* 25 ms default max_ack_delay */

/* Slab cache for sent packet tracking */
static struct kmem_cache *tquic_sent_packet_cache __read_mostly;

/**
 * tquic_loss_cache_init - Initialize the sent packet slab cache
 *
 * Returns 0 on success, negative error code on failure.
 */
int __init tquic_loss_cache_init(void)
{
	tquic_sent_packet_cache = kmem_cache_create("tquic_sent_packet",
						   sizeof(struct tquic_sent_packet),
						   0, SLAB_HWCACHE_ALIGN, NULL);
	if (!tquic_sent_packet_cache)
		return -ENOMEM;

	return 0;
}

/**
 * tquic_loss_cache_destroy - Destroy the sent packet slab cache
 */
void tquic_loss_cache_destroy(void)
{
	kmem_cache_destroy(tquic_sent_packet_cache);
}

/**
 * tquic_sent_packet_alloc - Allocate a sent packet tracking structure
 * @gfp: GFP flags for allocation
 *
 * Returns allocated structure or NULL on failure.
 */
struct tquic_sent_packet *tquic_sent_packet_alloc(gfp_t gfp)
{
	struct tquic_sent_packet *pkt;

	pkt = kmem_cache_alloc(tquic_sent_packet_cache, gfp);
	if (pkt) {
		memset(pkt, 0, sizeof(*pkt));
		INIT_LIST_HEAD(&pkt->list);
		RB_CLEAR_NODE(&pkt->node);
	}

	return pkt;
}

/**
 * tquic_sent_packet_init - Initialize a sent packet with given values
 * @pkt: Packet to initialize
 * @pn: Packet number
 * @bytes: Number of bytes in packet
 * @pn_space: Packet number space
 * @ack_eliciting: True if packet is ACK-eliciting
 * @in_flight: True if packet counts toward bytes in flight
 */
void tquic_sent_packet_init(struct tquic_sent_packet *pkt,
			    u64 pn, u32 bytes, u8 pn_space,
			    bool ack_eliciting, bool in_flight)
{
	if (!pkt)
		return;

	pkt->pn = pn;
	pkt->sent_bytes = bytes;
	pkt->size = bytes;	/* Alias for compatibility */
	pkt->pn_space = pn_space;
	pkt->ack_eliciting = ack_eliciting;
	pkt->in_flight = in_flight;
	pkt->sent_time = ktime_get();
	pkt->retransmitted = false;
}

/**
 * tquic_sent_packet_free - Free a sent packet tracking structure
 * @pkt: Packet to free
 */
void tquic_sent_packet_free(struct tquic_sent_packet *pkt)
{
	if (!pkt)
		return;

	if (pkt->skb)
		kfree_skb(pkt->skb);

	kmem_cache_free(tquic_sent_packet_cache, pkt);
}

/**
 * tquic_rtt_init - Initialize RTT measurement state
 * @rtt: RTT state structure to initialize
 *
 * RFC 9002 Section 5.2: Prior to obtaining the first RTT sample,
 * the smoothed RTT is set to the initial RTT.
 */
static void tquic_rtt_init(struct tquic_rtt_state *rtt)
{
	tquic_dbg("tquic_rtt_init: setting initial srtt=%u us\n",
		  TQUIC_INITIAL_RTT_US);
	rtt->min_rtt = U64_MAX;
	rtt->smoothed_rtt = TQUIC_INITIAL_RTT_US;
	rtt->rtt_var = TQUIC_INITIAL_RTT_US / 2;
	rtt->latest_rtt = 0;
	rtt->first_rtt_sample = 0;
	rtt->samples = 0;
}

/**
 * tquic_rtt_update - Update RTT estimates based on new sample
 * @rtt: RTT state structure
 * @latest_rtt: Latest RTT measurement in microseconds
 * @ack_delay: ACK delay reported by peer in microseconds
 *
 * RFC 9002 Section 5.3: RTT estimation requires an acknowledgment
 * to be received for the largest packet number.
 */
void tquic_rtt_update(struct tquic_rtt_state *rtt, u64 latest_rtt, u64 ack_delay)
{
	u64 adjusted_rtt;

	/* Store latest RTT */
	rtt->latest_rtt = latest_rtt;

	/* First RTT sample */
	if (rtt->samples == 0) {
		rtt->min_rtt = latest_rtt;
		rtt->smoothed_rtt = latest_rtt;
		rtt->rtt_var = latest_rtt / 2;
		rtt->first_rtt_sample = ktime_get();
		rtt->samples = 1;
		return;
	}

	rtt->samples++;

	/* Update min_rtt */
	if (latest_rtt < rtt->min_rtt)
		rtt->min_rtt = latest_rtt;

	/*
	 * RFC 9002 Section 5.3:
	 * Adjust for ack_delay if plausible.
	 * ack_delay is only subtracted if the resulting RTT is at least
	 * as large as min_rtt; otherwise min_rtt is used.
	 */
	if (latest_rtt > rtt->min_rtt + ack_delay)
		adjusted_rtt = latest_rtt - ack_delay;
	else
		adjusted_rtt = latest_rtt;

	/*
	 * RFC 9002 Section 5.3:
	 * rttvar_sample = |smoothed_rtt - adjusted_rtt|
	 * rttvar = 3/4 * rttvar + 1/4 * rttvar_sample
	 * smoothed_rtt = 7/8 * smoothed_rtt + 1/8 * adjusted_rtt
	 */
	if (adjusted_rtt > rtt->smoothed_rtt) {
		rtt->rtt_var = (3 * rtt->rtt_var +
			       (adjusted_rtt - rtt->smoothed_rtt)) / 4;
	} else {
		rtt->rtt_var = (3 * rtt->rtt_var +
			       (rtt->smoothed_rtt - adjusted_rtt)) / 4;
	}

	rtt->smoothed_rtt = (7 * rtt->smoothed_rtt + adjusted_rtt) / 8;
}

/**
 * tquic_rtt_pto_for_space - Calculate PTO for a specific packet number space
 * @rtt: RTT state structure
 * @pn_space: Packet number space (Initial, Handshake, or Application)
 * @handshake_confirmed: Whether the handshake has been confirmed
 *
 * RFC 9002 Section 6.2.1:
 * PTO = smoothed_rtt + max(4*rttvar, kGranularity) + max_ack_delay
 *
 * max_ack_delay is only included for the Application Data space after
 * the handshake has been confirmed. During handshake, Initial and
 * Handshake packets are not delayed by the peer's ack delay timer.
 *
 * Returns PTO in milliseconds.
 */
static u32 tquic_rtt_pto_for_space(struct tquic_rtt_state *rtt,
				   u8 pn_space, bool handshake_confirmed)
{
	u64 pto_us;
	u64 var_component;

	/* Use 4 * rttvar or granularity, whichever is larger */
	var_component = 4 * rtt->rtt_var;
	if (var_component < TQUIC_GRANULARITY_US)
		var_component = TQUIC_GRANULARITY_US;

	/* PTO = smoothed_rtt + max(4*rttvar, kGranularity) */
	pto_us = rtt->smoothed_rtt + var_component;

	/*
	 * RFC 9002 Section 6.2.1:
	 * max_ack_delay is only added for Application Data packets
	 * once the handshake is confirmed.
	 *
	 * SECURITY FIX: Use peer's actual max_ack_delay transport parameter
	 * instead of hardcoded constant. This ensures accurate PTO calculation
	 * and prevents premature timeouts or excessive delays.
	 *
	 * For Initial/Handshake spaces, max_ack_delay is NOT added since
	 * peers are required to ACK these packets promptly without delay.
	 */
	if (pn_space == TQUIC_PN_SPACE_APPLICATION && handshake_confirmed)
		pto_us += rtt->max_ack_delay;

	/* Convert to milliseconds, rounding up */
	return (u32)((pto_us + 999) / 1000);
}

/**
 * tquic_rtt_pto - Calculate Probe Timeout (PTO) value
 * @rtt: RTT state structure
 *
 * RFC 9002 Section 6.2.1:
 * PTO = smoothed_rtt + max(4*rttvar, kGranularity) + max_ack_delay
 *
 * This is the legacy API that always includes max_ack_delay,
 * suitable for Application Data space with confirmed handshake.
 *
 * Returns PTO in milliseconds.
 */
u32 tquic_rtt_pto(struct tquic_rtt_state *rtt)
{
	return tquic_rtt_pto_for_space(rtt, TQUIC_PN_SPACE_APPLICATION, true);
}

/**
 * tquic_loss_time_threshold - Calculate time threshold for loss detection
 * @rtt: RTT state structure
 *
 * RFC 9002 Section 6.1.2:
 * time_threshold = max(kTimeThreshold * max(smoothed_rtt, latest_rtt),
 *                      kGranularity)
 *
 * Returns time threshold in microseconds.
 */
static u64 tquic_loss_time_threshold(struct tquic_rtt_state *rtt)
{
	u64 max_rtt;
	u64 time_threshold;

	/* max(smoothed_rtt, latest_rtt) */
	max_rtt = rtt->smoothed_rtt;
	if (rtt->latest_rtt > max_rtt)
		max_rtt = rtt->latest_rtt;

	/*
	 * kTimeThreshold * max_rtt (9/8 factor)
	 *
	 * SECURITY FIX: Check for overflow before multiplication.
	 * If max_rtt is extremely large, the multiplication could overflow.
	 */
	if (max_rtt > U64_MAX / TQUIC_TIME_THRESHOLD_NUMER)
		time_threshold = U64_MAX;
	else
		time_threshold = (max_rtt * TQUIC_TIME_THRESHOLD_NUMER) /
				 TQUIC_TIME_THRESHOLD_DENOM;

	/*
	 * Ensure at least kGranularity.
	 *
	 * TIMER GRANULARITY FIX: The kernel timer granularity depends on HZ.
	 * Using TQUIC_GRANULARITY_US (1ms) is appropriate for most systems,
	 * but we ensure it's not less than what the kernel can actually
	 * deliver. On most systems HZ=1000 gives 1ms granularity, but on
	 * older systems with HZ=100, the granularity is 10ms.
	 *
	 * For now, we keep 1ms as it's a good balance between responsiveness
	 * and timer overhead, and matches RFC 9002's kGranularity constant.
	 */
	if (time_threshold < TQUIC_GRANULARITY_US)
		time_threshold = TQUIC_GRANULARITY_US;

	return time_threshold;
}

/**
 * tquic_pn_space_has_ack_eliciting_in_flight - Check if space has unacked packets
 * @pn_space: Packet number space to check
 *
 * Returns true if there are ack-eliciting packets in flight.
 */
static bool tquic_pn_space_has_ack_eliciting_in_flight(
	struct tquic_pn_space *pn_space)
{
	return pn_space->ack_eliciting_in_flight > 0;
}

/**
 * tquic_conn_has_ack_eliciting_in_flight - Check if connection has unacked packets
 * @conn: TQUIC connection
 *
 * Returns true if there are ack-eliciting packets in flight in any space.
 */
static bool tquic_conn_has_ack_eliciting_in_flight(struct tquic_connection *conn)
{
	int i;

	if (!conn || !conn->pn_spaces)
		return false;

	for (i = 0; i < TQUIC_PN_SPACE_COUNT; i++) {
		if (!conn->pn_spaces[i].keys_discarded &&
		    tquic_pn_space_has_ack_eliciting_in_flight(&conn->pn_spaces[i]))
			return true;
	}

	return false;
}

/*
 * Loss detection state is stored directly in struct tquic_connection:
 *   conn->pto_count
 *   conn->loss_detection_timer
 *   conn->time_of_last_ack_eliciting
 *   conn->packet_threshold
 *   conn->time_threshold
 *
 * The previous per-CPU approach was incorrect since loss detection
 * state must be per-connection, not per-CPU.
 */

/**
 * tquic_loss_detection_init - Initialize loss detection state
 * @conn: TQUIC connection
 *
 * RFC 9002 Section 5.1: Initialize loss detection variables.
 *
 * Returns 0 on success, negative error code on failure.
 */
int tquic_loss_detection_init(struct tquic_connection *conn)
{
	int i;

	if (!conn)
		return -EINVAL;

	tquic_dbg("tquic_loss_detection_init: initializing loss detection\n");

	/* Initialize RTT on the active path */
	{
		struct tquic_path *path = tquic_loss_active_path_get(conn);

		if (path) {
			tquic_rtt_init(&path->rtt);
			tquic_path_put(path);
		}
	}

	/* Initialize loss detection variables directly on connection */
	conn->pto_count = 0;
	conn->loss_detection_timer = 0;
	conn->time_of_last_ack_eliciting = 0;

	/*
	 * RFC 9002 Section 6.1.1:
	 * kPacketThreshold is the maximum reordering in packets.
	 */
	conn->packet_threshold = TQUIC_PACKET_THRESHOLD;

	/*
	 * RFC 9002 Section 6.1.2:
	 * kTimeThreshold is the maximum reordering in time.
	 */
	conn->time_threshold = TQUIC_TIME_THRESHOLD_NUMER;

	/* Initialize packet number space loss state */
	if (conn->pn_spaces) {
		for (i = 0; i < TQUIC_PN_SPACE_COUNT; i++) {
			conn->pn_spaces[i].loss_time = 0;
			conn->pn_spaces[i].largest_acked = 0;
			INIT_LIST_HEAD(&conn->pn_spaces[i].sent_list);
			INIT_LIST_HEAD(&conn->pn_spaces[i].lost_packets);
		}
	}

	return 0;
}

/**
 * tquic_loss_detection_on_packet_sent - Handle packet transmission
 * @conn: TQUIC connection
 * @pkt: Sent packet information
 *
 * RFC 9002 Section A.5: OnPacketSent
 * Records packet for loss detection and congestion control.
 */
void tquic_loss_detection_on_packet_sent(struct tquic_connection *conn,
					struct tquic_sent_packet *pkt)
{
	struct tquic_pn_space *pn_space;
	struct tquic_path *path;
	unsigned long flags;

	if (!conn || !pkt)
		return;

	tquic_dbg("tquic_loss_detection_on_packet_sent: pn=%llu space=%u bytes=%u\n",
		  pkt->pn, pkt->pn_space, pkt->sent_bytes);

	if (!conn->pn_spaces || pkt->pn_space >= TQUIC_PN_SPACE_COUNT)
		return;

	path = tquic_loss_active_path_get(conn);
	pn_space = &conn->pn_spaces[pkt->pn_space];

	spin_lock_irqsave(&pn_space->lock, flags);

	/* Add to sent packets list (time-ordered), ordered by packet number */
	list_add_tail(&pkt->list, &pn_space->sent_list);

	/* Track largest sent packet number for ACK validation */
	if (pkt->pn > pn_space->largest_sent)
		pn_space->largest_sent = pkt->pn;

	/* Track ack-eliciting packets in flight */
	if (pkt->ack_eliciting) {
		pn_space->ack_eliciting_in_flight++;
		conn->time_of_last_ack_eliciting = pkt->sent_time;
	}

	spin_unlock_irqrestore(&pn_space->lock, flags);

	/* Update congestion control - use path-level CC */
	if (pkt->in_flight && path) {
		tquic_cong_on_ack(path, 0, 0); /* Signal packet sent */
		/* Update path CC bytes_in_flight */
		path->cc.bytes_in_flight += pkt->size;
	}

	/* Update loss detection timer */
	tquic_set_loss_detection_timer(conn);

	if (path)
		tquic_path_put(path);
}

/**
 * tquic_loss_get_ack_delay_us - Get peer's ack_delay in microseconds
 * @conn: TQUIC connection
 * @ack_delay_encoded: Encoded ack_delay from ACK frame
 *
 * RFC 9002 Section 5.3: ack_delay is decoded using ack_delay_exponent.
 *
 * Returns ack_delay in microseconds.
 */
static u64 tquic_loss_get_ack_delay_us(struct tquic_connection *conn,
				      u64 ack_delay_encoded)
{
	u32 ack_delay_exponent = conn->remote_params.ack_delay_exponent;
	u64 max_ack_delay_us;
	u64 ack_delay_us;

	/*
	 * RFC 9000 Section 18.2: ack_delay_exponent defaults to 3
	 * when the transport parameter is absent. A negotiated value
	 * of 0 is valid. Values above 20 are invalid per RFC 9000.
	 */
	if (ack_delay_exponent > 20)
		return 0; /* Invalid exponent, treat as zero delay */

	ack_delay_us = ack_delay_encoded << ack_delay_exponent;
	/* Cap at 16 seconds to prevent absurd values */
	ack_delay_us = min_t(u64, ack_delay_us, 16000000ULL);

	/*
	 * RFC 9002 Section 5.3: ack_delay must not exceed max_ack_delay
	 * for Application Data packets.
	 */
	max_ack_delay_us = conn->remote_params.max_ack_delay * 1000;
	if (max_ack_delay_us == 0)
		max_ack_delay_us = TQUIC_MAX_ACK_DELAY_US;

	if (ack_delay_us > max_ack_delay_us)
		ack_delay_us = max_ack_delay_us;

	return ack_delay_us;
}

/**
 * tquic_loss_is_pn_acked - Check if packet number is acknowledged by ACK frame
 * @ack: ACK information from received frame
 * @pn: Packet number to check
 *
 * Returns true if the packet number is covered by the ACK frame.
 */
static bool tquic_loss_is_pn_acked(struct tquic_ack_frame *ack, u64 pn)
{
	u64 range_start, range_end;
	u32 i;

	if (pn > ack->largest_acked)
		return false;

	/*
	 * RFC 9000 Section 19.3.1:
	 * First ACK Range acknowledges [largest_acked - first_ack_range, largest_acked]
	 */
	range_end = ack->largest_acked;
	if (ack->first_range > range_end)
		return false; /* malformed ACK */
	range_start = range_end - ack->first_range;

	if (pn >= range_start && pn <= range_end)
		return true;

	/* Check additional ranges */
	for (i = 0; i < ack->range_count; i++) {
		/*
		 * Each additional range:
		 * - Gap: Number of unacknowledged packets before this range
		 * - ACK Range: Number of acknowledged packets in this range
		 */
		if (ack->ranges[i].gap + 2 > range_start)
			return false; /* malformed ACK */
		range_end = range_start - ack->ranges[i].gap - 2;
		if (ack->ranges[i].length > range_end)
			return false; /* malformed ACK */
		range_start = range_end - ack->ranges[i].length;

		if (pn >= range_start && pn <= range_end)
			return true;
	}

	return false;
}

/**
 * tquic_loss_detection_on_ack_received - Process received ACK frame
 * @conn: TQUIC connection
 * @ack: ACK information from received frame
 * @pn_space_idx: Packet number space index
 *
 * RFC 9002 Section A.7: OnAckReceived
 * Processes acknowledgments, updates RTT, and detects lost packets.
 */
void tquic_loss_detection_on_ack_received(struct tquic_connection *conn,
					 struct tquic_ack_frame *ack,
					 u8 pn_space_idx)
{
	struct tquic_pn_space *pn_space;
	struct tquic_path *path;
	struct tquic_sent_packet *pkt, *tmp;
	struct tquic_sent_packet *newly_acked = NULL;
	ktime_t largest_acked_sent_time = 0;
	u64 acked_bytes = 0;
	bool includes_ack_eliciting = false;
	bool largest_acked_newly_acked = false;
	unsigned long flags;
	u64 ack_delay_us;
	u64 latest_rtt;

	if (!conn || !ack)
		return;

	tquic_dbg("tquic_loss_detection_on_ack_received: largest=%llu space=%u\n",
		  ack->largest_acked, pn_space_idx);

	if (pn_space_idx >= TQUIC_PN_SPACE_COUNT)
		return;

	if (!conn->pn_spaces)
		return;

	path = tquic_loss_active_path_get(conn);
	pn_space = &conn->pn_spaces[pn_space_idx];

	if (pn_space->keys_discarded)
		goto out_put_path;

	/*
	 * RFC 9000 Section 13.1: If an endpoint receives an ACK frame
	 * that acknowledges a packet number it has not yet sent, it
	 * SHOULD signal a connection error of type PROTOCOL_VIOLATION.
	 */
	if (ack->largest_acked > pn_space->largest_sent) {
		tquic_dbg("ACK for unsent pkt: largest_acked=%llu > largest_sent=%llu in space %u\n",
			 ack->largest_acked, pn_space->largest_sent,
			 pn_space_idx);
		conn->error_code = EQUIC_PROTOCOL_VIOLATION;
			tquic_conn_close_with_error(conn,
				EQUIC_PROTOCOL_VIOLATION,
				"ACK for unsent packet");
			goto out_put_path;
		}

	/*
	 * RFC 9002 Section 5.1:
	 * If the largest_acked is less than the largest acked packet number,
	 * this ACK is not advancing our knowledge and can be ignored.
	 */
	if (ack->largest_acked < pn_space->largest_acked)
		goto out_put_path;

	spin_lock_irqsave(&pn_space->lock, flags);

	/*
	 * Find newly acknowledged packets and remove them from sent list.
	 * RFC 9002 Section A.7: Process each newly acked packet.
	 */
	list_for_each_entry_safe(pkt, tmp, &pn_space->sent_list, list) {
		if (!tquic_loss_is_pn_acked(ack, pkt->pn))
			continue;

		/* This packet is newly acknowledged */
		trace_quic_packet_acked(tquic_trace_conn_id(&conn->scid),
					pkt->pn, pn_space_idx);

		if (pkt->ack_eliciting) {
			includes_ack_eliciting = true;
			pn_space->ack_eliciting_in_flight--;
		}

		if (pkt->in_flight)
			acked_bytes += pkt->size;

		/* Track if largest_acked was newly acked for RTT */
		if (pkt->pn == ack->largest_acked) {
			largest_acked_newly_acked = true;
			largest_acked_sent_time = pkt->sent_time;
		}

		/* Remove from sent list and prepare for cleanup */
		list_del_init(&pkt->list);
		pkt->list.next = (struct list_head *)newly_acked;
		newly_acked = pkt;
	}

	/* Update largest acked */
	if (ack->largest_acked > pn_space->largest_acked)
		pn_space->largest_acked = ack->largest_acked;

	spin_unlock_irqrestore(&pn_space->lock, flags);

	/*
	 * RFC 9002 Section 5.3:
	 * Update RTT if largest_acked was newly acknowledged.
	 * Only use Application Data space for adjusting ack_delay.
	 */
	if (largest_acked_newly_acked && path) {
		ktime_t now = ktime_get();

		latest_rtt = ktime_to_us(ktime_sub(now, largest_acked_sent_time));

		/*
		 * RFC 9002 Section 5.3:
		 * ack_delay is only used for Application Data packets.
		 */
		if (pn_space_idx == TQUIC_PN_SPACE_APPLICATION)
			ack_delay_us = tquic_loss_get_ack_delay_us(conn, ack->ack_delay);
		else
			ack_delay_us = 0;

		tquic_rtt_update(&path->rtt, latest_rtt, ack_delay_us);

		trace_quic_rtt_update(tquic_trace_conn_id(&conn->scid),
				      path->rtt.latest_rtt, path->rtt.min_rtt,
				      path->rtt.smoothed_rtt, path->rtt.rtt_var);

		/* Update path CC statistics */
		path->cc.smoothed_rtt_us = path->rtt.smoothed_rtt;
		path->cc.rtt_var_us = path->rtt.rtt_var;
		path->cc.min_rtt_us = path->rtt.min_rtt;
	}

	/* Update congestion control - use path-level CC API */
	if (path && acked_bytes > 0) {
		tquic_cong_on_ack(path, acked_bytes, path->rtt.latest_rtt);

		/* Update path stats for output_flush inflight calculation */
		path->stats.acked_bytes += acked_bytes;
	}

	/*
	 * Process ECN feedback (RFC 9000 Section 13.4)
	 *
	 * If the ACK frame contains ECN counts (ACK_ECN frame type 0x03),
	 * validate them and trigger congestion events for any new CE marks.
	 */
	if (path && (ack->ecn.ect0 || ack->ecn.ect1 || ack->ecn.ce)) {
		int ce_count = tquic_ecn_validate_ack(path, ack);

		if (ce_count > 0) {
			/* New CE marks received - trigger congestion response */
			tquic_ecn_process_ce(conn, path, ce_count);
		}
	}

	/* Reset PTO count since we got a valid ACK */
	if (includes_ack_eliciting)
		conn->pto_count = 0;

	/* Detect and handle lost packets */
	tquic_loss_detection_detect_lost(conn, pn_space_idx);

	/* Update timer */
	tquic_set_loss_detection_timer(conn);

	/* Free newly acknowledged packets */
	while (newly_acked) {
		pkt = newly_acked;
		newly_acked = (struct tquic_sent_packet *)pkt->list.next;
		tquic_sent_packet_free(pkt);
	}

out_put_path:
	if (path)
		tquic_path_put(path);
}

/**
 * tquic_loss_detection_detect_lost - Detect and process lost packets
 * @conn: TQUIC connection
 * @pn_space_idx: Packet number space index
 *
 * RFC 9002 Section A.8: DetectAndRemoveLostPackets
 * Uses both time and packet thresholds to detect lost packets.
 */
void tquic_loss_detection_detect_lost(struct tquic_connection *conn, u8 pn_space_idx)
{
	struct tquic_pn_space *pn_space;
	struct tquic_path *path;
	struct tquic_sent_packet *pkt, *tmp;
	struct list_head lost_list;
	ktime_t now;
	u64 loss_delay;
	ktime_t lost_time;
	ktime_t pkt_time_threshold;
	u64 lost_bytes = 0;
	unsigned long flags;

	if (!conn)
		return;

	if (pn_space_idx >= TQUIC_PN_SPACE_COUNT)
		return;

	if (!conn->pn_spaces)
		return;

	path = tquic_loss_active_path_get(conn);
	pn_space = &conn->pn_spaces[pn_space_idx];

	if (pn_space->keys_discarded)
		goto out_put_path;

	if (!path)
		goto out_put_path;

	INIT_LIST_HEAD(&lost_list);

	now = ktime_get();

	/*
	 * RFC 9002 Section 6.1.2:
	 * loss_delay = time_threshold(RTT)
	 * Packets sent more than loss_delay ago are deemed lost.
	 */
	loss_delay = tquic_loss_time_threshold(&path->rtt);

	tquic_conn_dbg(conn, "detect_lost space=%u loss_delay=%llu us\n",
		       pn_space_idx, loss_delay);

	/* Calculate the earliest time a packet can be sent and not be lost */
	pkt_time_threshold = ktime_sub_us(now, loss_delay);

	/* Reset loss_time for this packet number space */
	pn_space->loss_time = 0;

	spin_lock_irqsave(&pn_space->lock, flags);

	list_for_each_entry_safe(pkt, tmp, &pn_space->sent_list, list) {
		if (pkt->pn >= pn_space->largest_acked)
			continue;

		/*
		 * RFC 9002 Section 6.1:
		 * A packet is declared lost if:
		 * - Its packet number is kPacketThreshold smaller than
		 *   largest_acked, OR
		 * - It was sent kTimeThreshold ago
		 */
		if (pkt->pn + conn->packet_threshold <=
		    pn_space->largest_acked ||
		    ktime_before(pkt->sent_time, pkt_time_threshold)) {
			/* Mark as lost */
			trace_quic_packet_lost(tquic_trace_conn_id(&conn->scid),
					       pkt->pn, pn_space_idx);

			if (pkt->ack_eliciting)
				pn_space->ack_eliciting_in_flight--;

			if (pkt->in_flight)
				lost_bytes += pkt->size;

			/* Move to lost list */
			list_del_init(&pkt->list);
			list_add_tail(&pkt->list, &lost_list);
		} else {
			/*
			 * RFC 9002 Section 6.1.2:
			 * If a packet has not yet been declared lost, set
			 * loss_time to the time when it will be.
			 */
			lost_time = ktime_add_us(pkt->sent_time, loss_delay);
			if (pn_space->loss_time == 0 ||
			    lost_time < pn_space->loss_time)
				pn_space->loss_time = lost_time;
		}
	}

	spin_unlock_irqrestore(&pn_space->lock, flags);

	/* Process lost packets */
	if (!list_empty(&lost_list)) {
		LIST_HEAD(to_free);

		/* Update congestion control */
		if (lost_bytes > 0) {
			tquic_cong_on_loss(path, lost_bytes);
			conn->stats.lost_packets++;
		}

		/*
		 * Sort lost packets into retransmit vs free lists under
		 * the lock, then free outside the lock to avoid the
		 * unlock/relock pattern that creates a race window.
		 */
		spin_lock_irqsave(&pn_space->lock, flags);
		list_for_each_entry_safe(pkt, tmp, &lost_list, list) {
			list_del_init(&pkt->list);

			/*
			 * RFC 9002 Section 6.3:
			 * Only retransmit if the packet contained
			 * retransmittable frames.
			 */
			if (pkt->ack_eliciting && !pkt->retransmitted) {
				pkt->retransmitted = true;
				list_add_tail(&pkt->list,
					      &pn_space->lost_packets);
			} else {
				list_add_tail(&pkt->list, &to_free);
			}
		}
		spin_unlock_irqrestore(&pn_space->lock, flags);

		/* Free packets outside lock */
		list_for_each_entry_safe(pkt, tmp, &to_free, list) {
			list_del_init(&pkt->list);
			tquic_sent_packet_free(pkt);
		}
	}

out_put_path:
	if (path)
		tquic_path_put(path);
}

/**
 * tquic_loss_get_loss_time_space - Find packet number space with earliest loss time
 * @conn: TQUIC connection
 *
 * Returns the packet number space index with the earliest loss_time,
 * or -1 if no space has a pending loss time.
 */
static int tquic_loss_get_loss_time_space(struct tquic_connection *conn)
{
	ktime_t earliest = KTIME_MAX;
	int earliest_space = -1;
	int i;

	if (!conn || !conn->pn_spaces)
		return -1;

	for (i = 0; i < TQUIC_PN_SPACE_COUNT; i++) {
		struct tquic_pn_space *pn_space = &conn->pn_spaces[i];

		if (pn_space->keys_discarded)
			continue;

		if (pn_space->loss_time != 0 &&
		    ktime_before(pn_space->loss_time, earliest)) {
			earliest = pn_space->loss_time;
			earliest_space = i;
		}
	}

	return earliest_space;
}

/**
 * tquic_loss_get_pto_time_space - Find packet number space for PTO
 * @conn: TQUIC connection
 *
 * RFC 9002 Section 6.2.1:
 * Returns the packet number space index that should be used for PTO,
 * considering handshake state and in-flight packets.
 */
static int tquic_loss_get_pto_time_space(struct tquic_connection *conn)
{
	struct tquic_path *path;
	u32 pto;
	ktime_t earliest_time = KTIME_MAX;
	int earliest_space = -1;
	int i;
	bool handshake_complete;

	if (!conn || !conn->pn_spaces)
		return -1;

	path = tquic_loss_active_path_get(conn);
	if (!path)
		return TQUIC_PN_SPACE_APPLICATION;

	/* Use handshake_complete from connection state */
	handshake_complete = conn->handshake_complete;

	/*
	 * RFC 9002 Section 6.2.1:
	 * During handshake, use the earliest time among Initial and Handshake.
	 */
	if (!handshake_complete) {
		for (i = TQUIC_PN_SPACE_INITIAL; i <= TQUIC_PN_SPACE_HANDSHAKE; i++) {
			struct tquic_pn_space *pn_space = &conn->pn_spaces[i];
			ktime_t t;

			if (pn_space->keys_discarded)
				continue;

			if (!tquic_pn_space_has_ack_eliciting_in_flight(pn_space))
				continue;

			pto = tquic_rtt_pto_for_space(&path->rtt, i,
						      conn->handshake_confirmed);
			t = ktime_add_ms(pn_space->last_ack_time, pto);
			if (ktime_before(t, earliest_time)) {
				earliest_time = t;
				earliest_space = i;
			}
		}
	}

	/*
	 * RFC 9002 Section 6.2.1:
	 * If handshake is complete, use Application Data space.
	 */
	if (earliest_space == -1 && handshake_complete) {
		struct tquic_pn_space *pn_space = &conn->pn_spaces[TQUIC_PN_SPACE_APPLICATION];

		if (!pn_space->keys_discarded &&
		    tquic_pn_space_has_ack_eliciting_in_flight(pn_space))
			earliest_space = TQUIC_PN_SPACE_APPLICATION;
	}

	/*
	 * RFC 9002 Section 6.2.2.1:
	 * If there are no ack-eliciting packets in flight, arm the timer
	 * for the anti-deadlock mechanism on client.
	 */
	if (earliest_space == -1 && !conn->is_server && !handshake_complete) {
		if (!conn->pn_spaces[TQUIC_PN_SPACE_INITIAL].keys_discarded)
			earliest_space = TQUIC_PN_SPACE_INITIAL;
		else if (!conn->pn_spaces[TQUIC_PN_SPACE_HANDSHAKE].keys_discarded)
			earliest_space = TQUIC_PN_SPACE_HANDSHAKE;
	}

	tquic_path_put(path);
	return earliest_space;
}

/**
 * tquic_set_loss_detection_timer - Set the loss detection timer
 * @conn: TQUIC connection
 *
 * RFC 9002 Section A.6: SetLossDetectionTimer
 * Sets the timer based on loss time or PTO.
 */
void tquic_set_loss_detection_timer(struct tquic_connection *conn)
{
	struct tquic_path *path;
	ktime_t timeout = 0;
	int loss_space;
	int pto_space;
	u32 pto;

	if (!conn)
		return;

	tquic_dbg("tquic_set_loss_detection_timer: updating timer\n");

	path = tquic_loss_active_path_get(conn);
	if (!path)
		return;

	/*
	 * RFC 9002 Section 6.2.2.1:
	 * If no ack-eliciting packets in flight, cancel timer.
	 */
	if (!tquic_conn_has_ack_eliciting_in_flight(conn) &&
	    conn->handshake_complete) {
		conn->loss_detection_timer = 0;
		tquic_timer_cancel(conn, TQUIC_TIMER_LOSS);
		goto out_put_path;
	}

	/*
	 * RFC 9002 Section 6.2.1:
	 * First check for loss time (time-based loss detection).
	 */
	loss_space = tquic_loss_get_loss_time_space(conn);
	if (loss_space >= 0 && conn->pn_spaces) {
		timeout = conn->pn_spaces[loss_space].loss_time;
		goto set_timer;
	}

	/*
	 * RFC 9002 Section 6.2.1:
	 * If no loss time, use PTO.
	 */
	pto_space = tquic_loss_get_pto_time_space(conn);
	if (pto_space < 0) {
		conn->loss_detection_timer = 0;
		tquic_timer_cancel(conn, TQUIC_TIMER_LOSS);
		goto out_put_path;
	}

	/*
	 * RFC 9002 Section 6.2.1:
	 * PTO = smoothed_rtt + max(4*rttvar, kGranularity) + max_ack_delay
	 * The timer is set for PTO * (2 ^ pto_count)
	 * max_ack_delay only included for Application Data with confirmed HS.
	 */
	pto = tquic_rtt_pto_for_space(&path->rtt,
				      (u8)pto_space,
				      conn->handshake_confirmed);
	/* Cap exponential backoff to prevent shift overflow and bound PTO */
	{
		u8 shift = min_t(u8, conn->pto_count, 30);

		pto <<= shift;
		/* Cap maximum PTO to 60 seconds */
		if (pto > 60000000ULL)
			pto = 60000000ULL;
	}

	if (conn->time_of_last_ack_eliciting)
		timeout = ktime_add_ms(conn->time_of_last_ack_eliciting, pto);
	else
		timeout = ktime_add_ms(ktime_get(), pto);

	/* Don't schedule timer in the past */
	if (ktime_before(timeout, ktime_get()))
		timeout = ktime_add_us(ktime_get(), 1);

set_timer:
	conn->loss_detection_timer = timeout;
	tquic_timer_set(conn, TQUIC_TIMER_LOSS, timeout);

out_put_path:
	tquic_path_put(path);
}

/* PING frame type */
#ifndef TQUIC_FRAME_PING
#define TQUIC_FRAME_PING	0x01
#endif

/**
 * tquic_loss_send_probe - Send probe packets for PTO
 * @conn: TQUIC connection
 * @pn_space_idx: Packet number space to probe
 *
 * RFC 9002 Section 6.2.4:
 * When PTO expires, send 1-2 probe packets.
 */
static void tquic_loss_send_probe(struct tquic_connection *conn, u8 pn_space_idx)
{
	struct tquic_pn_space *pn_space;
	struct tquic_sent_packet *pkt;
	struct sk_buff *skb;
	unsigned long flags;

	if (!conn || !conn->pn_spaces)
		return;

	if (pn_space_idx >= TQUIC_PN_SPACE_COUNT)
		return;

	pn_space = &conn->pn_spaces[pn_space_idx];

	/*
	 * RFC 9002 Section 6.2.4:
	 * First, try to retransmit oldest unacked data.
	 */
	spin_lock_irqsave(&pn_space->lock, flags);
	pkt = list_first_entry_or_null(&pn_space->lost_packets,
				       struct tquic_sent_packet, list);
	if (pkt) {
		/* Clone the skb for retransmission */
		if (pkt->skb) {
			skb = skb_clone(pkt->skb, GFP_ATOMIC);
			if (skb) {
				spin_unlock_irqrestore(&pn_space->lock, flags);
				if (tquic_conn_queue_frame(conn, skb)) {
					/* Queue full, skip retransmit this cycle */
					kfree_skb(skb);
					return;
				}
				conn->stats.retransmissions++;
				return;
			} else {
				/* skb_clone failed - log and track the error */
				tquic_conn_warn(conn,
					"skb_clone failed probe retx pn=%llu\n",
					pkt->pn);
				spin_unlock_irqrestore(&pn_space->lock, flags);
				return;
			}
		}
	}
	spin_unlock_irqrestore(&pn_space->lock, flags);

	/*
	 * RFC 9002 Section 6.2.4:
	 * If there's nothing to retransmit, send a PING frame.
	 */
	skb = alloc_skb(16, GFP_ATOMIC);
	if (skb) {
		u8 *p = skb_put(skb, 1);
		*p = TQUIC_FRAME_PING;
		/* Best effort - if queue full, skip PING */
		if (tquic_conn_queue_frame(conn, skb))
			kfree_skb(skb);
	}

	/* Schedule TX work to send probe */
	schedule_work(&conn->tx_work);
}

/**
 * tquic_loss_detection_on_timeout - Handle loss detection timeout
 * @conn: TQUIC connection
 *
 * RFC 9002 Section A.9: OnLossDetectionTimeout
 * Handles timer expiration for loss detection.
 */
void tquic_loss_detection_on_timeout(struct tquic_connection *conn)
{
	int loss_space;
	int pto_space;
	ktime_t now = ktime_get();

	if (!conn || !conn->pn_spaces)
		return;

	tquic_dbg("tquic_loss_detection_on_timeout: pto_count=%u\n",
		  conn->pto_count);

	/*
	 * RFC 9002 Section 6.2.1:
	 * Check if this is a loss time timeout.
	 */
	loss_space = tquic_loss_get_loss_time_space(conn);
	if (loss_space >= 0 &&
	    conn->pn_spaces[loss_space].loss_time != 0 &&
	    !ktime_before(now, conn->pn_spaces[loss_space].loss_time)) {
		/* Time-based loss detection */
		tquic_loss_detection_detect_lost(conn, loss_space);
		tquic_set_loss_detection_timer(conn);
		return;
	}

	tquic_conn_info(conn, "PTO timeout pto_count=%u\n", conn->pto_count);

	/*
	 * RFC 9002 Section 6.2.1:
	 * PTO timeout. Increment pto_count and send probes.
	 */
	pto_space = tquic_loss_get_pto_time_space(conn);

	/*
	 * RFC 9002 Section 6.2.2.1:
	 * Anti-deadlock for client during handshake.
	 */
	if (!conn->handshake_complete) {
		if (conn->pn_spaces[TQUIC_PN_SPACE_INITIAL].keys_available &&
		    !conn->pn_spaces[TQUIC_PN_SPACE_INITIAL].keys_discarded) {
			pto_space = TQUIC_PN_SPACE_INITIAL;
		} else if (conn->pn_spaces[TQUIC_PN_SPACE_HANDSHAKE].keys_available &&
			   !conn->pn_spaces[TQUIC_PN_SPACE_HANDSHAKE].keys_discarded) {
			pto_space = TQUIC_PN_SPACE_HANDSHAKE;
		}
	}

	if (pto_space >= 0) {
		conn->pto_count++;

		/*
		 * Limit PTO probes to prevent connections from persisting
		 * indefinitely when the peer is unreachable.
		 * TQUIC_MAX_PTO_COUNT defined at top of this file.
		 */
		if (conn->pto_count > TQUIC_MAX_PTO_COUNT) {
			tquic_conn_info(conn,
					"PTO limit exceeded (%u), closing\n",
					conn->pto_count);
			conn->error_code = 0;
			conn->state = TQUIC_CONN_DRAINING;
			conn->draining = true;
			return;
		}

		/*
		 * RFC 9002 Section 6.2.4:
		 * Send 1-2 probe packets in the timeout space.
		 */
		tquic_loss_send_probe(conn, pto_space);

		/*
		 * RFC 9002 Section 6.2.4:
		 * Send a second probe for robustness if possible.
		 */
		tquic_loss_send_probe(conn, pto_space);
	}

	/* Reset timer */
	tquic_set_loss_detection_timer(conn);
}

/**
 * tquic_loss_on_packet_number_space_discarded - Handle discarding of a PN space
 * @conn: TQUIC connection
 * @pn_space_idx: Packet number space being discarded
 *
 * RFC 9002 Section 6.2.2:
 * When Initial or Handshake keys are discarded, remove all packets
 * in that space from bytes in flight.
 */
void tquic_loss_on_packet_number_space_discarded(struct tquic_connection *conn,
						u8 pn_space_idx)
{
	struct tquic_pn_space *pn_space;
	struct tquic_sent_packet *pkt, *tmp;
	struct tquic_path *path;
	u64 removed_bytes = 0;
	unsigned long flags;

	if (!conn || !conn->pn_spaces)
		return;

	if (pn_space_idx >= TQUIC_PN_SPACE_COUNT)
		return;

	path = tquic_loss_active_path_get(conn);
	pn_space = &conn->pn_spaces[pn_space_idx];

	spin_lock_irqsave(&pn_space->lock, flags);

	/* Remove all sent packets from this space */
	list_for_each_entry_safe(pkt, tmp, &pn_space->sent_list, list) {
		if (pkt->in_flight)
			removed_bytes += pkt->size;

		list_del_init(&pkt->list);
		spin_unlock_irqrestore(&pn_space->lock, flags);
		tquic_sent_packet_free(pkt);
		spin_lock_irqsave(&pn_space->lock, flags);
	}

	/* Remove all lost packets from this space */
	list_for_each_entry_safe(pkt, tmp, &pn_space->lost_packets, list) {
		list_del_init(&pkt->list);
		spin_unlock_irqrestore(&pn_space->lock, flags);
		tquic_sent_packet_free(pkt);
		spin_lock_irqsave(&pn_space->lock, flags);
	}

	pn_space->ack_eliciting_in_flight = 0;
	pn_space->loss_time = 0;
	pn_space->keys_discarded = 1;

	spin_unlock_irqrestore(&pn_space->lock, flags);

	/* Update congestion control */
	if (path && removed_bytes > 0) {
		if (path->cc.bytes_in_flight >= removed_bytes)
			path->cc.bytes_in_flight -= removed_bytes;
		else
			path->cc.bytes_in_flight = 0;
	}

	/* Update timer since we removed packets */
	tquic_set_loss_detection_timer(conn);

	if (path)
		tquic_path_put(path);
}

/**
 * tquic_loss_mark_packet_lost - Manually mark a packet as lost
 * @conn: TQUIC connection
 * @pn_space_idx: Packet number space
 * @pn: Packet number to mark as lost
 *
 * This can be used when detecting loss through ECN or other means.
 */
void tquic_loss_mark_packet_lost(struct tquic_connection *conn,
				u8 pn_space_idx, u64 pn)
{
	struct tquic_pn_space *pn_space;
	struct tquic_sent_packet *pkt, *tmp;
	struct tquic_path *path;
	unsigned long flags;

	if (!conn || !conn->pn_spaces)
		return;

	if (pn_space_idx >= TQUIC_PN_SPACE_COUNT)
		return;

	path = tquic_loss_active_path_get(conn);
	pn_space = &conn->pn_spaces[pn_space_idx];

	spin_lock_irqsave(&pn_space->lock, flags);

	list_for_each_entry_safe(pkt, tmp, &pn_space->sent_list, list) {
		if (pkt->pn != pn)
			continue;

		/* Found the packet */
		if (pkt->ack_eliciting)
			pn_space->ack_eliciting_in_flight--;

		/* Update congestion control */
		if (pkt->in_flight && path)
			tquic_cong_on_loss(path, pkt->size);

		/* Move to lost list for retransmission */
		list_del_init(&pkt->list);
			if (pkt->ack_eliciting && !pkt->retransmitted) {
				pkt->retransmitted = true;
				list_add_tail(&pkt->list, &pn_space->lost_packets);
			} else {
				spin_unlock_irqrestore(&pn_space->lock, flags);
				tquic_sent_packet_free(pkt);
				if (path)
					tquic_path_put(path);
				return;
			}

		break;
	}

	spin_unlock_irqrestore(&pn_space->lock, flags);

	conn->stats.lost_packets++;

	if (path)
		tquic_path_put(path);
}

/**
 * tquic_loss_get_bytes_in_flight - Get total bytes in flight
 * @conn: TQUIC connection
 *
 * Returns total bytes of in-flight packets across all packet number spaces.
 */
u64 tquic_loss_get_bytes_in_flight(struct tquic_connection *conn)
{
	u64 bytes = 0;
	int i;

	if (!conn || !conn->pn_spaces)
		return 0;

	for (i = 0; i < TQUIC_PN_SPACE_COUNT; i++) {
		struct tquic_pn_space *pn_space = &conn->pn_spaces[i];
		struct tquic_sent_packet *pkt;
		unsigned long flags;

		if (pn_space->keys_discarded)
			continue;

		spin_lock_irqsave(&pn_space->lock, flags);
		list_for_each_entry(pkt, &pn_space->sent_list, list) {
			if (pkt->in_flight)
				bytes += pkt->size;
		}
		spin_unlock_irqrestore(&pn_space->lock, flags);
	}

	return bytes;
}

/**
 * tquic_loss_get_oldest_unacked_time - Get send time of oldest unacked packet
 * @conn: TQUIC connection
 *
 * Returns ktime of oldest unacked packet, or 0 if none.
 */
ktime_t tquic_loss_get_oldest_unacked_time(struct tquic_connection *conn)
{
	ktime_t oldest = 0;
	int i;

	if (!conn || !conn->pn_spaces)
		return 0;

	for (i = 0; i < TQUIC_PN_SPACE_COUNT; i++) {
		struct tquic_pn_space *pn_space = &conn->pn_spaces[i];
		struct tquic_sent_packet *pkt;
		unsigned long flags;

		if (pn_space->keys_discarded)
			continue;

		spin_lock_irqsave(&pn_space->lock, flags);
		pkt = list_first_entry_or_null(&pn_space->sent_list,
					       struct tquic_sent_packet, list);
		if (pkt) {
			if (oldest == 0 || ktime_before(pkt->sent_time, oldest))
				oldest = pkt->sent_time;
		}
		spin_unlock_irqrestore(&pn_space->lock, flags);
	}

	return oldest;
}

/**
 * tquic_loss_retransmit_unacked - Retransmit all unacked data
 * @conn: TQUIC connection
 *
 * RFC 9002 Section 6.2.4:
 * In persistent congestion, retransmit all unacked data.
 */
void tquic_loss_retransmit_unacked(struct tquic_connection *conn)
{
	int i;

	if (!conn || !conn->pn_spaces)
		return;

	for (i = 0; i < TQUIC_PN_SPACE_COUNT; i++) {
		struct tquic_pn_space *pn_space = &conn->pn_spaces[i];
		struct tquic_sent_packet *pkt;
		unsigned long flags;

		if (pn_space->keys_discarded)
			continue;

		spin_lock_irqsave(&pn_space->lock, flags);

		list_for_each_entry(pkt, &pn_space->sent_list, list) {
			if (pkt->ack_eliciting && !pkt->retransmitted && pkt->skb) {
				struct sk_buff *skb = skb_clone(pkt->skb, GFP_ATOMIC);
				if (skb) {
					pkt->retransmitted = true;
					spin_unlock_irqrestore(&pn_space->lock, flags);
					if (tquic_conn_queue_frame(conn, skb)) {
						/* Queue full, stop retransmissions */
						kfree_skb(skb);
						return;
					}
					conn->stats.retransmissions++;
					spin_lock_irqsave(&pn_space->lock, flags);
				} else {
					/* skb_clone failed - log error and continue */
					tquic_conn_warn(conn,
						"skb_clone failed retx pn=%llu\n",
						pkt->pn);
					/* Continue to next packet to maximize recovery */
				}
			}
		}

		spin_unlock_irqrestore(&pn_space->lock, flags);
	}

	/* Schedule TX work to send retransmissions */
	schedule_work(&conn->tx_work);
}

/**
 * tquic_loss_check_persistent_congestion - Check for persistent congestion
 * @conn: TQUIC connection
 *
 * RFC 9002 Section 7.6:
 * Persistent congestion is established when all packets sent over a
 * time period spanning the PTO are lost.
 *
 * Returns true if persistent congestion is detected.
 */
bool tquic_loss_check_persistent_congestion(struct tquic_connection *conn)
{
	struct tquic_path *path;
	u32 pto;
	ktime_t duration;
	ktime_t oldest_lost_time = 0;
	ktime_t newest_lost_time = 0;
	int i;

	if (!conn || !conn->pn_spaces)
		return false;

	path = tquic_loss_active_path_get(conn);
	if (!path)
		return false;

	/* Need RTT sample for persistent congestion check */
	if (path->rtt.samples == 0) {
		tquic_path_put(path);
		return false;
	}

	/*
	 * RFC 9002 Section 7.6.2:
	 * pto = smoothed_rtt + max(4*rttvar, kGranularity) + max_ack_delay
	 * Persistent congestion period = pto * kPersistentCongestionThreshold
	 * kPersistentCongestionThreshold = 3
	 */
	pto = tquic_rtt_pto(&path->rtt);

	/* Find oldest and newest lost packet times */
	for (i = 0; i < TQUIC_PN_SPACE_COUNT; i++) {
		struct tquic_pn_space *pn_space = &conn->pn_spaces[i];
		struct tquic_sent_packet *pkt;
		unsigned long flags;

		if (pn_space->keys_discarded)
			continue;

		spin_lock_irqsave(&pn_space->lock, flags);
		list_for_each_entry(pkt, &pn_space->lost_packets, list) {
			if (oldest_lost_time == 0 ||
			    ktime_before(pkt->sent_time, oldest_lost_time))
				oldest_lost_time = pkt->sent_time;

			if (ktime_after(pkt->sent_time, newest_lost_time))
				newest_lost_time = pkt->sent_time;
		}
		spin_unlock_irqrestore(&pn_space->lock, flags);
	}

	if (oldest_lost_time == 0 || newest_lost_time == 0) {
		tquic_path_put(path);
		return false;
	}

	/*
	 * RFC 9002 Section 7.6.2:
	 * If the time between the oldest and newest lost packets spans
	 * more than the persistent congestion period, declare persistent
	 * congestion.
	 */
	duration = ktime_sub(newest_lost_time, oldest_lost_time);

	/* 3 * PTO in milliseconds converted to nanoseconds */
	if (ktime_to_ms(duration) > (u64)pto * 3) {
		struct tquic_persistent_cong_info pc_info;

		/*
		 * Build persistent congestion info for the CC algorithm.
		 * Per RFC 9002 Section 7.6.2: reset cwnd to minimum
		 * (2 * max_datagram_size).
		 */
		memset(&pc_info, 0, sizeof(pc_info));
		pc_info.min_cwnd = 2 * path->mtu;
		pc_info.max_datagram_size = path->mtu;
		pc_info.earliest_send_time = oldest_lost_time;
		pc_info.latest_send_time = newest_lost_time;
		pc_info.duration_us = ktime_to_us(duration);

		path->cc.cwnd = pc_info.min_cwnd;
		path->cc.bytes_in_flight = 0;

		/* Signal persistent congestion to CC algorithm */
		tquic_cong_on_persistent_congestion(path, &pc_info);

			tquic_path_put(path);
			return true;
		}

	tquic_path_put(path);
	return false;
}

/**
 * tquic_loss_cleanup_space - Clean up a packet number space
 * @conn: TQUIC connection
 * @pn_space_idx: Packet number space to clean up
 *
 * Frees all packets in the specified packet number space.
 */
void tquic_loss_cleanup_space(struct tquic_connection *conn, u8 pn_space_idx)
{
	struct tquic_pn_space *pn_space;
	struct tquic_sent_packet *pkt, *tmp;
	unsigned long flags;

	if (!conn || !conn->pn_spaces)
		return;

	if (pn_space_idx >= TQUIC_PN_SPACE_COUNT)
		return;

	pn_space = &conn->pn_spaces[pn_space_idx];

	spin_lock_irqsave(&pn_space->lock, flags);

	list_for_each_entry_safe(pkt, tmp, &pn_space->sent_list, list) {
		list_del_init(&pkt->list);
		spin_unlock_irqrestore(&pn_space->lock, flags);
		tquic_sent_packet_free(pkt);
		spin_lock_irqsave(&pn_space->lock, flags);
	}

	list_for_each_entry_safe(pkt, tmp, &pn_space->lost_packets, list) {
		list_del_init(&pkt->list);
		spin_unlock_irqrestore(&pn_space->lock, flags);
		tquic_sent_packet_free(pkt);
		spin_lock_irqsave(&pn_space->lock, flags);
	}

	pn_space->ack_eliciting_in_flight = 0;
	pn_space->loss_time = 0;

	spin_unlock_irqrestore(&pn_space->lock, flags);
}

/**
 * tquic_loss_cleanup - Clean up all loss detection state
 * @conn: TQUIC connection
 *
 * Called during connection teardown.
 */
void tquic_loss_cleanup(struct tquic_connection *conn)
{
	int i;

	if (!conn)
		return;

	/* Cancel timer */
	tquic_timer_cancel(conn, TQUIC_TIMER_LOSS);

	/* Clean up all packet number spaces */
	if (conn->pn_spaces) {
		for (i = 0; i < TQUIC_PN_SPACE_COUNT; i++)
			tquic_loss_cleanup_space(conn, i);
	}
}

/**
 * tquic_loss_detection_cleanup - Alias for tquic_loss_cleanup
 * @conn: TQUIC connection
 *
 * Provided for API compatibility.
 */
void tquic_loss_detection_cleanup(struct tquic_connection *conn)
{
	tquic_loss_cleanup(conn);
}

/*
 * Module exports
 */
EXPORT_SYMBOL_GPL(tquic_loss_cache_destroy);
EXPORT_SYMBOL_GPL(tquic_sent_packet_alloc);
EXPORT_SYMBOL_GPL(tquic_sent_packet_free);
EXPORT_SYMBOL_GPL(tquic_sent_packet_init);
EXPORT_SYMBOL_GPL(tquic_rtt_update);
EXPORT_SYMBOL_GPL(tquic_rtt_pto);
EXPORT_SYMBOL_GPL(tquic_loss_detection_init);
EXPORT_SYMBOL_GPL(tquic_loss_detection_on_packet_sent);
EXPORT_SYMBOL_GPL(tquic_loss_detection_on_ack_received);
EXPORT_SYMBOL_GPL(tquic_loss_detection_detect_lost);
EXPORT_SYMBOL_GPL(tquic_set_loss_detection_timer);
EXPORT_SYMBOL_GPL(tquic_loss_detection_on_timeout);
EXPORT_SYMBOL_GPL(tquic_loss_on_packet_number_space_discarded);
EXPORT_SYMBOL_GPL(tquic_loss_mark_packet_lost);
EXPORT_SYMBOL_GPL(tquic_loss_get_bytes_in_flight);
EXPORT_SYMBOL_GPL(tquic_loss_get_oldest_unacked_time);
EXPORT_SYMBOL_GPL(tquic_loss_retransmit_unacked);
EXPORT_SYMBOL_GPL(tquic_loss_check_persistent_congestion);
EXPORT_SYMBOL_GPL(tquic_loss_cleanup_space);
EXPORT_SYMBOL_GPL(tquic_loss_cleanup);
EXPORT_SYMBOL_GPL(tquic_loss_detection_cleanup);

/**
 * tquic_pn_space_get_sent_time - Look up sent_time for a packet number
 * @pn_space: Packet number space to search
 * @pkt_num: Packet number to find
 * @sent_time: Output parameter for the packet's sent time
 *
 * Searches the sent_list for the packet matching @pkt_num and returns
 * its sent_time via @sent_time.  The caller must hold pn_space->lock.
 *
 * Returns 0 on success, -ENOENT if packet not found.
 */
int tquic_pn_space_get_sent_time(struct tquic_pn_space *pn_space,
				 u64 pkt_num, ktime_t *sent_time)
{
	struct tquic_sent_packet *pkt;

	list_for_each_entry(pkt, &pn_space->sent_list, list) {
		if (pkt->pn == pkt_num) {
			*sent_time = pkt->sent_time;
			return 0;
		}
	}

	return -ENOENT;
}
EXPORT_SYMBOL_GPL(tquic_pn_space_get_sent_time);
