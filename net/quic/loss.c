// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * QUIC - Quick UDP Internet Connections
 *
 * Loss detection and recovery implementation based on RFC 9002
 *
 * Copyright (c) 2024 Linux QUIC Authors
 */

#include <linux/slab.h>
#include <linux/jiffies.h>
#include <linux/timer.h>
#include <net/quic.h>

/*
 * RFC 9002 Constants
 *
 * Section 6.2: kTimeThreshold and kPacketThreshold
 * Section 6.2.2: kGranularity
 */
#define QUIC_TIME_THRESHOLD_NUMER	9
#define QUIC_TIME_THRESHOLD_DENOM	8
#define QUIC_PACKET_THRESHOLD		3
#define QUIC_GRANULARITY_US		1000	/* 1 ms in microseconds */
#define QUIC_INITIAL_RTT_US		333000	/* 333 ms in microseconds */
#define QUIC_MAX_ACK_DELAY_US		25000	/* 25 ms default max_ack_delay */

/* Slab cache for sent packet tracking */
static struct kmem_cache *quic_sent_packet_cache __read_mostly;

/**
 * quic_loss_cache_init - Initialize the sent packet slab cache
 *
 * Returns 0 on success, negative error code on failure.
 */
int __init quic_loss_cache_init(void)
{
	quic_sent_packet_cache = kmem_cache_create("quic_sent_packet",
						   sizeof(struct quic_sent_packet),
						   0, SLAB_HWCACHE_ALIGN, NULL);
	if (!quic_sent_packet_cache)
		return -ENOMEM;

	return 0;
}

/**
 * quic_loss_cache_destroy - Destroy the sent packet slab cache
 */
void quic_loss_cache_destroy(void)
{
	kmem_cache_destroy(quic_sent_packet_cache);
}

/**
 * quic_sent_packet_alloc - Allocate a sent packet tracking structure
 * @gfp: GFP flags for allocation
 *
 * Returns allocated structure or NULL on failure.
 */
struct quic_sent_packet *quic_sent_packet_alloc(gfp_t gfp)
{
	struct quic_sent_packet *pkt;

	pkt = kmem_cache_alloc(quic_sent_packet_cache, gfp);
	if (pkt)
		memset(pkt, 0, sizeof(*pkt));

	return pkt;
}

/**
 * quic_sent_packet_free - Free a sent packet tracking structure
 * @pkt: Packet to free
 */
void quic_sent_packet_free(struct quic_sent_packet *pkt)
{
	if (!pkt)
		return;

	if (pkt->skb)
		kfree_skb(pkt->skb);

	kmem_cache_free(quic_sent_packet_cache, pkt);
}

/**
 * quic_rtt_init - Initialize RTT measurement state
 * @rtt: RTT state structure to initialize
 *
 * RFC 9002 Section 5.2: Prior to obtaining the first RTT sample,
 * the smoothed RTT is set to the initial RTT.
 */
static void quic_rtt_init(struct quic_rtt *rtt)
{
	rtt->min_rtt = U32_MAX;
	rtt->smoothed_rtt = QUIC_INITIAL_RTT_US;
	rtt->rttvar = QUIC_INITIAL_RTT_US / 2;
	rtt->latest_rtt = 0;
	rtt->first_rtt_sample = 0;
	rtt->has_sample = 0;
}

/**
 * quic_rtt_update - Update RTT estimates based on new sample
 * @rtt: RTT state structure
 * @latest_rtt: Latest RTT measurement in microseconds
 * @ack_delay: ACK delay reported by peer in microseconds
 *
 * RFC 9002 Section 5.3: RTT estimation requires an acknowledgment
 * to be received for the largest packet number.
 */
void quic_rtt_update(struct quic_rtt *rtt, u32 latest_rtt, u32 ack_delay)
{
	u32 adjusted_rtt;

	/* Store latest RTT */
	rtt->latest_rtt = latest_rtt;

	/* First RTT sample */
	if (!rtt->has_sample) {
		rtt->min_rtt = latest_rtt;
		rtt->smoothed_rtt = latest_rtt;
		rtt->rttvar = latest_rtt / 2;
		rtt->first_rtt_sample = ktime_get();
		rtt->has_sample = 1;
		return;
	}

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
		rtt->rttvar = (3 * rtt->rttvar +
			       (adjusted_rtt - rtt->smoothed_rtt)) / 4;
	} else {
		rtt->rttvar = (3 * rtt->rttvar +
			       (rtt->smoothed_rtt - adjusted_rtt)) / 4;
	}

	rtt->smoothed_rtt = (7 * rtt->smoothed_rtt + adjusted_rtt) / 8;
}

/**
 * quic_rtt_pto - Calculate Probe Timeout (PTO) value
 * @rtt: RTT state structure
 *
 * RFC 9002 Section 6.2.1:
 * PTO = smoothed_rtt + max(4*rttvar, kGranularity) + max_ack_delay
 *
 * Returns PTO in milliseconds.
 */
u32 quic_rtt_pto(struct quic_rtt *rtt)
{
	u32 pto_us;
	u32 var_component;

	/* Use 4 * rttvar or granularity, whichever is larger */
	var_component = 4 * rtt->rttvar;
	if (var_component < QUIC_GRANULARITY_US)
		var_component = QUIC_GRANULARITY_US;

	/* PTO = smoothed_rtt + max(4*rttvar, kGranularity) + max_ack_delay */
	pto_us = rtt->smoothed_rtt + var_component + QUIC_MAX_ACK_DELAY_US;

	/* Convert to milliseconds, rounding up */
	return (pto_us + 999) / 1000;
}

/**
 * quic_loss_time_threshold - Calculate time threshold for loss detection
 * @rtt: RTT state structure
 *
 * RFC 9002 Section 6.1.2:
 * time_threshold = max(kTimeThreshold * max(smoothed_rtt, latest_rtt),
 *                      kGranularity)
 *
 * Returns time threshold in microseconds.
 */
static u64 quic_loss_time_threshold(struct quic_rtt *rtt)
{
	u64 max_rtt;
	u64 time_threshold;

	/* max(smoothed_rtt, latest_rtt) */
	max_rtt = rtt->smoothed_rtt;
	if (rtt->latest_rtt > max_rtt)
		max_rtt = rtt->latest_rtt;

	/* kTimeThreshold * max_rtt (9/8 factor) */
	time_threshold = (max_rtt * QUIC_TIME_THRESHOLD_NUMER) /
			 QUIC_TIME_THRESHOLD_DENOM;

	/* Ensure at least kGranularity */
	if (time_threshold < QUIC_GRANULARITY_US)
		time_threshold = QUIC_GRANULARITY_US;

	return time_threshold;
}

/**
 * quic_pn_space_has_ack_eliciting_in_flight - Check if space has unacked packets
 * @pn_space: Packet number space to check
 *
 * Returns true if there are ack-eliciting packets in flight.
 */
static bool quic_pn_space_has_ack_eliciting_in_flight(
	struct quic_pn_space *pn_space)
{
	return pn_space->ack_eliciting_in_flight > 0;
}

/**
 * quic_conn_has_ack_eliciting_in_flight - Check if connection has unacked packets
 * @conn: QUIC connection
 *
 * Returns true if there are ack-eliciting packets in flight in any space.
 */
static bool quic_conn_has_ack_eliciting_in_flight(struct quic_connection *conn)
{
	int i;

	for (i = 0; i < QUIC_PN_SPACE_MAX; i++) {
		if (!conn->pn_spaces[i].keys_discarded &&
		    quic_pn_space_has_ack_eliciting_in_flight(&conn->pn_spaces[i]))
			return true;
	}

	return false;
}

/**
 * quic_loss_detection_init - Initialize loss detection state
 * @conn: QUIC connection
 *
 * RFC 9002 Section 5.1: Initialize loss detection variables.
 */
void quic_loss_detection_init(struct quic_connection *conn)
{
	int i;

	/* Initialize RTT on the active path */
	if (conn->active_path)
		quic_rtt_init(&conn->active_path->rtt);

	/* Initialize loss detection variables */
	conn->pto_count = 0;
	conn->loss_detection_timer = 0;
	conn->time_of_last_ack_eliciting = 0;

	/*
	 * RFC 9002 Section 6.1.1:
	 * kPacketThreshold is the maximum reordering in packets.
	 */
	conn->packet_threshold = QUIC_PACKET_THRESHOLD;

	/*
	 * RFC 9002 Section 6.1.2:
	 * kTimeThreshold is the maximum reordering in time.
	 */
	conn->time_threshold = QUIC_TIME_THRESHOLD_NUMER;

	/* Initialize packet number space loss state */
	for (i = 0; i < QUIC_PN_SPACE_MAX; i++) {
		conn->pn_spaces[i].loss_time = 0;
		conn->pn_spaces[i].largest_acked_pn = 0;
	}
}

/**
 * quic_loss_detection_on_packet_sent - Handle packet transmission
 * @conn: QUIC connection
 * @pkt: Sent packet information
 *
 * RFC 9002 Section A.5: OnPacketSent
 * Records packet for loss detection and congestion control.
 */
void quic_loss_detection_on_packet_sent(struct quic_connection *conn,
					struct quic_sent_packet *pkt)
{
	struct quic_pn_space *pn_space;
	struct quic_path *path = conn->active_path;
	unsigned long flags;

	if (!pkt)
		return;

	pn_space = &conn->pn_spaces[pkt->pn_space];

	spin_lock_irqsave(&pn_space->lock, flags);

	/* Add to sent packets list, ordered by packet number */
	list_add_tail(&pkt->list, &pn_space->sent_packets);

	/* Track ack-eliciting packets in flight */
	if (pkt->ack_eliciting) {
		pn_space->ack_eliciting_in_flight++;
		conn->time_of_last_ack_eliciting = pkt->sent_time;
	}

	spin_unlock_irqrestore(&pn_space->lock, flags);

	/* Update congestion control */
	if (pkt->in_flight && path) {
		quic_cc_on_packet_sent(&path->cc, pkt->size);
	}

	/* Update loss detection timer */
	quic_loss_detection_set_timer(conn);
}

/**
 * quic_loss_get_ack_delay_us - Get peer's ack_delay in microseconds
 * @conn: QUIC connection
 * @ack_delay_encoded: Encoded ack_delay from ACK frame
 *
 * RFC 9002 Section 5.3: ack_delay is decoded using ack_delay_exponent.
 *
 * Returns ack_delay in microseconds.
 */
static u32 quic_loss_get_ack_delay_us(struct quic_connection *conn,
				      u64 ack_delay_encoded)
{
	u32 ack_delay_exponent = conn->remote_params.ack_delay_exponent;
	u32 max_ack_delay_us;
	u64 ack_delay_us;

	/*
	 * RFC 9000 Section 18.2: ack_delay_exponent defaults to 3.
	 * ack_delay is encoded as ack_delay_encoded * 2^ack_delay_exponent
	 */
	if (ack_delay_exponent == 0)
		ack_delay_exponent = 3;

	ack_delay_us = ack_delay_encoded << ack_delay_exponent;

	/*
	 * RFC 9002 Section 5.3: ack_delay must not exceed max_ack_delay
	 * for Application Data packets.
	 */
	max_ack_delay_us = conn->remote_params.max_ack_delay * 1000;
	if (max_ack_delay_us == 0)
		max_ack_delay_us = QUIC_MAX_ACK_DELAY_US;

	if (ack_delay_us > max_ack_delay_us)
		ack_delay_us = max_ack_delay_us;

	return (u32)ack_delay_us;
}

/**
 * quic_loss_is_pn_acked - Check if packet number is acknowledged by ACK frame
 * @ack: ACK information from received frame
 * @pn: Packet number to check
 *
 * Returns true if the packet number is covered by the ACK frame.
 */
static bool quic_loss_is_pn_acked(struct quic_ack_info *ack, u64 pn)
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
	range_start = range_end - ack->ranges[0].ack_range;

	if (pn >= range_start && pn <= range_end)
		return true;

	/* Check additional ranges */
	for (i = 1; i < ack->ack_range_count; i++) {
		/*
		 * Each additional range:
		 * - Gap: Number of unacknowledged packets before this range
		 * - ACK Range: Number of acknowledged packets in this range
		 */
		range_end = range_start - ack->ranges[i].gap - 2;
		range_start = range_end - ack->ranges[i].ack_range;

		if (pn >= range_start && pn <= range_end)
			return true;
	}

	return false;
}

/**
 * quic_loss_detection_on_ack_received - Process received ACK frame
 * @conn: QUIC connection
 * @ack: ACK information from received frame
 * @pn_space_idx: Packet number space index
 *
 * RFC 9002 Section A.7: OnAckReceived
 * Processes acknowledgments, updates RTT, and detects lost packets.
 */
void quic_loss_detection_on_ack_received(struct quic_connection *conn,
					 struct quic_ack_info *ack,
					 u8 pn_space_idx)
{
	struct quic_pn_space *pn_space;
	struct quic_path *path = conn->active_path;
	struct quic_sent_packet *pkt, *tmp;
	struct quic_sent_packet *newly_acked = NULL;
	ktime_t largest_acked_sent_time = 0;
	u64 acked_bytes = 0;
	bool includes_ack_eliciting = false;
	bool largest_acked_newly_acked = false;
	unsigned long flags;
	u32 ack_delay_us;
	u32 latest_rtt;

	if (pn_space_idx >= QUIC_PN_SPACE_MAX)
		return;

	pn_space = &conn->pn_spaces[pn_space_idx];

	if (pn_space->keys_discarded)
		return;

	/*
	 * RFC 9002 Section 5.1:
	 * If the largest_acked is less than the largest acked packet number,
	 * this ACK is not advancing our knowledge and can be ignored.
	 */
	if (ack->largest_acked < pn_space->largest_acked_pn)
		return;

	spin_lock_irqsave(&pn_space->lock, flags);

	/*
	 * Find newly acknowledged packets and remove them from sent list.
	 * RFC 9002 Section A.7: Process each newly acked packet.
	 */
	list_for_each_entry_safe(pkt, tmp, &pn_space->sent_packets, list) {
		if (!quic_loss_is_pn_acked(ack, pkt->pn))
			continue;

		/* This packet is newly acknowledged */
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
		list_del(&pkt->list);
		pkt->list.next = (struct list_head *)newly_acked;
		newly_acked = pkt;
	}

	/* Update largest acked */
	if (ack->largest_acked > pn_space->largest_acked_pn)
		pn_space->largest_acked_pn = ack->largest_acked;

	spin_unlock_irqrestore(&pn_space->lock, flags);

	/*
	 * RFC 9002 Section 5.3:
	 * Update RTT if largest_acked was newly acknowledged.
	 * Only use Application Data space for adjusting ack_delay.
	 */
	if (largest_acked_newly_acked && path) {
		ktime_t now = ktime_get();

		latest_rtt = (u32)ktime_to_us(ktime_sub(now, largest_acked_sent_time));

		/*
		 * RFC 9002 Section 5.3:
		 * ack_delay is only used for Application Data packets.
		 */
		if (pn_space_idx == QUIC_PN_SPACE_APPLICATION)
			ack_delay_us = quic_loss_get_ack_delay_us(conn, ack->ack_delay);
		else
			ack_delay_us = 0;

		quic_rtt_update(&path->rtt, latest_rtt, ack_delay_us);

		/* Update statistics */
		conn->stats.min_rtt_us = path->rtt.min_rtt;
		conn->stats.smoothed_rtt_us = path->rtt.smoothed_rtt;
		conn->stats.rtt_variance_us = path->rtt.rttvar;
		conn->stats.latest_rtt_us = path->rtt.latest_rtt;
	}

	/* Update congestion control */
	if (path && acked_bytes > 0)
		quic_cc_on_ack(&path->cc, acked_bytes, &path->rtt);

	/* Reset PTO count since we got a valid ACK */
	if (includes_ack_eliciting)
		conn->pto_count = 0;

	/* Detect and handle lost packets */
	quic_loss_detection_detect_lost(conn, pn_space_idx);

	/* Update timer */
	quic_loss_detection_set_timer(conn);

	/* Free newly acknowledged packets */
	while (newly_acked) {
		pkt = newly_acked;
		newly_acked = (struct quic_sent_packet *)pkt->list.next;
		quic_sent_packet_free(pkt);
	}
}

/**
 * quic_loss_detection_detect_lost - Detect and process lost packets
 * @conn: QUIC connection
 * @pn_space_idx: Packet number space index
 *
 * RFC 9002 Section A.8: DetectAndRemoveLostPackets
 * Uses both time and packet thresholds to detect lost packets.
 */
void quic_loss_detection_detect_lost(struct quic_connection *conn, u8 pn_space_idx)
{
	struct quic_pn_space *pn_space;
	struct quic_path *path = conn->active_path;
	struct quic_sent_packet *pkt, *tmp;
	struct list_head lost_list;
	ktime_t now;
	u64 loss_delay;
	u64 lost_time;
	ktime_t pkt_time_threshold;
	u64 lost_bytes = 0;
	unsigned long flags;

	if (pn_space_idx >= QUIC_PN_SPACE_MAX)
		return;

	pn_space = &conn->pn_spaces[pn_space_idx];

	if (pn_space->keys_discarded)
		return;

	if (!path)
		return;

	INIT_LIST_HEAD(&lost_list);

	now = ktime_get();

	/*
	 * RFC 9002 Section 6.1.2:
	 * loss_delay = time_threshold(RTT)
	 * Packets sent more than loss_delay ago are deemed lost.
	 */
	loss_delay = quic_loss_time_threshold(&path->rtt);

	/* Calculate the earliest time a packet can be sent and not be lost */
	pkt_time_threshold = ktime_sub_us(now, loss_delay);

	/* Reset loss_time for this packet number space */
	pn_space->loss_time = 0;

	spin_lock_irqsave(&pn_space->lock, flags);

	list_for_each_entry_safe(pkt, tmp, &pn_space->sent_packets, list) {
		if (pkt->pn >= pn_space->largest_acked_pn)
			continue;

		/*
		 * RFC 9002 Section 6.1:
		 * A packet is declared lost if:
		 * - Its packet number is kPacketThreshold smaller than
		 *   largest_acked, OR
		 * - It was sent kTimeThreshold ago
		 */
		if (pkt->pn + conn->packet_threshold <= pn_space->largest_acked_pn ||
		    ktime_before(pkt->sent_time, pkt_time_threshold)) {
			/* Mark as lost */
			if (pkt->ack_eliciting)
				pn_space->ack_eliciting_in_flight--;

			if (pkt->in_flight)
				lost_bytes += pkt->size;

			/* Move to lost list */
			list_del(&pkt->list);
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
		/* Update congestion control */
		if (lost_bytes > 0) {
			quic_cc_on_loss(&path->cc, lost_bytes);
			conn->stats.packets_lost++;
		}

		/* Move lost packets to lost_packets list for retransmission */
		spin_lock_irqsave(&pn_space->lock, flags);
		list_for_each_entry_safe(pkt, tmp, &lost_list, list) {
			list_del(&pkt->list);

			/*
			 * RFC 9002 Section 6.3:
			 * Only retransmit if the packet contained retransmittable frames.
			 */
			if (pkt->ack_eliciting && !pkt->retransmitted) {
				pkt->retransmitted = 1;
				list_add_tail(&pkt->list, &pn_space->lost_packets);
			} else {
				/* Free packets that don't need retransmission */
				spin_unlock_irqrestore(&pn_space->lock, flags);
				quic_sent_packet_free(pkt);
				spin_lock_irqsave(&pn_space->lock, flags);
			}
		}
		spin_unlock_irqrestore(&pn_space->lock, flags);
	}
}

/**
 * quic_loss_get_loss_time_space - Find packet number space with earliest loss time
 * @conn: QUIC connection
 *
 * Returns the packet number space index with the earliest loss_time,
 * or -1 if no space has a pending loss time.
 */
static int quic_loss_get_loss_time_space(struct quic_connection *conn)
{
	ktime_t earliest = KTIME_MAX;
	int earliest_space = -1;
	int i;

	for (i = 0; i < QUIC_PN_SPACE_MAX; i++) {
		struct quic_pn_space *pn_space = &conn->pn_spaces[i];

		if (pn_space->keys_discarded)
			continue;

		if (pn_space->loss_time != 0 &&
		    pn_space->loss_time < earliest) {
			earliest = pn_space->loss_time;
			earliest_space = i;
		}
	}

	return earliest_space;
}

/**
 * quic_loss_get_pto_time_space - Find packet number space for PTO
 * @conn: QUIC connection
 *
 * RFC 9002 Section 6.2.1:
 * Returns the packet number space index that should be used for PTO,
 * considering handshake state and in-flight packets.
 */
static int quic_loss_get_pto_time_space(struct quic_connection *conn)
{
	u32 pto;
	ktime_t earliest_time = KTIME_MAX;
	int earliest_space = -1;
	int i;

	if (!conn->active_path)
		return QUIC_PN_SPACE_APPLICATION;

	pto = quic_rtt_pto(&conn->active_path->rtt);

	/*
	 * RFC 9002 Section 6.2.1:
	 * During handshake, use the earliest time among Initial and Handshake.
	 */
	if (!conn->handshake_confirmed) {
		for (i = QUIC_PN_SPACE_INITIAL; i <= QUIC_PN_SPACE_HANDSHAKE; i++) {
			struct quic_pn_space *pn_space = &conn->pn_spaces[i];
			ktime_t t;

			if (pn_space->keys_discarded)
				continue;

			if (!quic_pn_space_has_ack_eliciting_in_flight(pn_space))
				continue;

			t = ktime_add_ms(pn_space->last_ack_time, pto);
			if (t < earliest_time) {
				earliest_time = t;
				earliest_space = i;
			}
		}
	}

	/*
	 * RFC 9002 Section 6.2.1:
	 * If handshake is complete, use Application Data space.
	 */
	if (earliest_space == -1 && conn->handshake_confirmed) {
		struct quic_pn_space *pn_space = &conn->pn_spaces[QUIC_PN_SPACE_APPLICATION];

		if (!pn_space->keys_discarded &&
		    quic_pn_space_has_ack_eliciting_in_flight(pn_space))
			earliest_space = QUIC_PN_SPACE_APPLICATION;
	}

	/*
	 * RFC 9002 Section 6.2.2.1:
	 * If there are no ack-eliciting packets in flight, arm the timer
	 * for the anti-deadlock mechanism on client.
	 */
	if (earliest_space == -1 && !conn->is_server && !conn->handshake_confirmed) {
		if (!conn->pn_spaces[QUIC_PN_SPACE_INITIAL].keys_discarded)
			earliest_space = QUIC_PN_SPACE_INITIAL;
		else if (!conn->pn_spaces[QUIC_PN_SPACE_HANDSHAKE].keys_discarded)
			earliest_space = QUIC_PN_SPACE_HANDSHAKE;
	}

	return earliest_space;
}

/**
 * quic_loss_detection_set_timer - Set the loss detection timer
 * @conn: QUIC connection
 *
 * RFC 9002 Section A.6: SetLossDetectionTimer
 * Sets the timer based on loss time or PTO.
 */
void quic_loss_detection_set_timer(struct quic_connection *conn)
{
	ktime_t timeout = 0;
	int loss_space;
	int pto_space;
	u32 pto;

	if (!conn->active_path)
		return;

	/*
	 * RFC 9002 Section 6.2.2.1:
	 * If no ack-eliciting packets in flight, cancel timer.
	 */
	if (!quic_conn_has_ack_eliciting_in_flight(conn) &&
	    conn->handshake_confirmed) {
		conn->loss_detection_timer = 0;
		quic_timer_cancel(conn, QUIC_TIMER_LOSS);
		return;
	}

	/*
	 * RFC 9002 Section 6.2.1:
	 * First check for loss time (time-based loss detection).
	 */
	loss_space = quic_loss_get_loss_time_space(conn);
	if (loss_space >= 0) {
		timeout = conn->pn_spaces[loss_space].loss_time;
		goto set_timer;
	}

	/*
	 * RFC 9002 Section 6.2.1:
	 * If no loss time, use PTO.
	 */
	pto_space = quic_loss_get_pto_time_space(conn);
	if (pto_space < 0) {
		conn->loss_detection_timer = 0;
		quic_timer_cancel(conn, QUIC_TIMER_LOSS);
		return;
	}

	/*
	 * RFC 9002 Section 6.2.1:
	 * PTO = smoothed_rtt + max(4*rttvar, kGranularity) + max_ack_delay
	 * The timer is set for PTO * (2 ^ pto_count)
	 */
	pto = quic_rtt_pto(&conn->active_path->rtt);
	pto <<= conn->pto_count;  /* Exponential backoff */

	timeout = ktime_add_ms(conn->time_of_last_ack_eliciting, pto);

	/* Don't schedule timer in the past */
	if (ktime_before(timeout, ktime_get()))
		timeout = ktime_add_us(ktime_get(), 1);

set_timer:
	conn->loss_detection_timer = timeout;
	quic_timer_set(conn, QUIC_TIMER_LOSS, timeout);
}

/**
 * quic_loss_send_probe - Send probe packets for PTO
 * @conn: QUIC connection
 * @pn_space_idx: Packet number space to probe
 *
 * RFC 9002 Section 6.2.4:
 * When PTO expires, send 1-2 probe packets.
 */
static void quic_loss_send_probe(struct quic_connection *conn, u8 pn_space_idx)
{
	struct quic_pn_space *pn_space = &conn->pn_spaces[pn_space_idx];
	struct quic_sent_packet *pkt;
	struct sk_buff *skb;
	unsigned long flags;

	/*
	 * RFC 9002 Section 6.2.4:
	 * First, try to retransmit oldest unacked data.
	 */
	spin_lock_irqsave(&pn_space->lock, flags);
	pkt = list_first_entry_or_null(&pn_space->lost_packets,
				       struct quic_sent_packet, list);
	if (pkt) {
		/* Clone the skb for retransmission */
		if (pkt->skb) {
			skb = skb_clone(pkt->skb, GFP_ATOMIC);
			if (skb) {
				spin_unlock_irqrestore(&pn_space->lock, flags);
				skb_queue_tail(&conn->pending_frames, skb);
				conn->stats.packets_retransmitted++;
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
		*p = QUIC_FRAME_PING;
		skb_queue_tail(&conn->pending_frames, skb);
	}

	/* Schedule TX work to send probe */
	schedule_work(&conn->tx_work);
}

/**
 * quic_loss_detection_on_timeout - Handle loss detection timeout
 * @conn: QUIC connection
 *
 * RFC 9002 Section A.9: OnLossDetectionTimeout
 * Handles timer expiration for loss detection.
 */
void quic_loss_detection_on_timeout(struct quic_connection *conn)
{
	int loss_space;
	int pto_space;
	ktime_t now = ktime_get();

	/*
	 * RFC 9002 Section 6.2.1:
	 * Check if this is a loss time timeout.
	 */
	loss_space = quic_loss_get_loss_time_space(conn);
	if (loss_space >= 0 &&
	    conn->pn_spaces[loss_space].loss_time != 0 &&
	    ktime_after_eq(now, conn->pn_spaces[loss_space].loss_time)) {
		/* Time-based loss detection */
		quic_loss_detection_detect_lost(conn, loss_space);
		quic_loss_detection_set_timer(conn);
		return;
	}

	/*
	 * RFC 9002 Section 6.2.1:
	 * PTO timeout. Increment pto_count and send probes.
	 */
	pto_space = quic_loss_get_pto_time_space(conn);

	/*
	 * RFC 9002 Section 6.2.2.1:
	 * Anti-deadlock for client during handshake.
	 */
	if (!conn->handshake_confirmed) {
		if (conn->pn_spaces[QUIC_PN_SPACE_INITIAL].keys_available &&
		    !conn->pn_spaces[QUIC_PN_SPACE_INITIAL].keys_discarded) {
			pto_space = QUIC_PN_SPACE_INITIAL;
		} else if (conn->pn_spaces[QUIC_PN_SPACE_HANDSHAKE].keys_available &&
			   !conn->pn_spaces[QUIC_PN_SPACE_HANDSHAKE].keys_discarded) {
			pto_space = QUIC_PN_SPACE_HANDSHAKE;
		}
	}

	if (pto_space >= 0) {
		conn->pto_count++;

		/*
		 * RFC 9002 Section 6.2.4:
		 * Send 1-2 probe packets in the timeout space.
		 */
		quic_loss_send_probe(conn, pto_space);

		/*
		 * RFC 9002 Section 6.2.4:
		 * Send a second probe for robustness if possible.
		 */
		quic_loss_send_probe(conn, pto_space);

		/* Update congestion controller PTO count */
		if (conn->active_path)
			conn->active_path->cc.pto_count = conn->pto_count;
	}

	/* Reset timer */
	quic_loss_detection_set_timer(conn);
}

/**
 * quic_loss_on_packet_number_space_discarded - Handle discarding of a PN space
 * @conn: QUIC connection
 * @pn_space_idx: Packet number space being discarded
 *
 * RFC 9002 Section 6.2.2:
 * When Initial or Handshake keys are discarded, remove all packets
 * in that space from bytes in flight.
 */
void quic_loss_on_packet_number_space_discarded(struct quic_connection *conn,
						u8 pn_space_idx)
{
	struct quic_pn_space *pn_space;
	struct quic_sent_packet *pkt, *tmp;
	struct quic_path *path = conn->active_path;
	u64 removed_bytes = 0;
	unsigned long flags;

	if (pn_space_idx >= QUIC_PN_SPACE_MAX)
		return;

	pn_space = &conn->pn_spaces[pn_space_idx];

	spin_lock_irqsave(&pn_space->lock, flags);

	/* Remove all sent packets from this space */
	list_for_each_entry_safe(pkt, tmp, &pn_space->sent_packets, list) {
		if (pkt->in_flight)
			removed_bytes += pkt->size;

		list_del(&pkt->list);
		spin_unlock_irqrestore(&pn_space->lock, flags);
		quic_sent_packet_free(pkt);
		spin_lock_irqsave(&pn_space->lock, flags);
	}

	/* Remove all lost packets from this space */
	list_for_each_entry_safe(pkt, tmp, &pn_space->lost_packets, list) {
		list_del(&pkt->list);
		spin_unlock_irqrestore(&pn_space->lock, flags);
		quic_sent_packet_free(pkt);
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
	quic_loss_detection_set_timer(conn);
}

/**
 * quic_loss_mark_packet_lost - Manually mark a packet as lost
 * @conn: QUIC connection
 * @pn_space_idx: Packet number space
 * @pn: Packet number to mark as lost
 *
 * This can be used when detecting loss through ECN or other means.
 */
void quic_loss_mark_packet_lost(struct quic_connection *conn,
				u8 pn_space_idx, u64 pn)
{
	struct quic_pn_space *pn_space;
	struct quic_sent_packet *pkt, *tmp;
	struct quic_path *path = conn->active_path;
	unsigned long flags;

	if (pn_space_idx >= QUIC_PN_SPACE_MAX)
		return;

	pn_space = &conn->pn_spaces[pn_space_idx];

	spin_lock_irqsave(&pn_space->lock, flags);

	list_for_each_entry_safe(pkt, tmp, &pn_space->sent_packets, list) {
		if (pkt->pn != pn)
			continue;

		/* Found the packet */
		if (pkt->ack_eliciting)
			pn_space->ack_eliciting_in_flight--;

		/* Update congestion control */
		if (pkt->in_flight && path)
			quic_cc_on_loss(&path->cc, pkt->size);

		/* Move to lost list for retransmission */
		list_del(&pkt->list);
		if (pkt->ack_eliciting && !pkt->retransmitted) {
			pkt->retransmitted = 1;
			list_add_tail(&pkt->list, &pn_space->lost_packets);
		} else {
			spin_unlock_irqrestore(&pn_space->lock, flags);
			quic_sent_packet_free(pkt);
			return;
		}

		break;
	}

	spin_unlock_irqrestore(&pn_space->lock, flags);

	conn->stats.packets_lost++;
}

/**
 * quic_loss_get_bytes_in_flight - Get total bytes in flight
 * @conn: QUIC connection
 *
 * Returns total bytes of in-flight packets across all packet number spaces.
 */
u64 quic_loss_get_bytes_in_flight(struct quic_connection *conn)
{
	u64 bytes = 0;
	int i;

	for (i = 0; i < QUIC_PN_SPACE_MAX; i++) {
		struct quic_pn_space *pn_space = &conn->pn_spaces[i];
		struct quic_sent_packet *pkt;
		unsigned long flags;

		if (pn_space->keys_discarded)
			continue;

		spin_lock_irqsave(&pn_space->lock, flags);
		list_for_each_entry(pkt, &pn_space->sent_packets, list) {
			if (pkt->in_flight)
				bytes += pkt->size;
		}
		spin_unlock_irqrestore(&pn_space->lock, flags);
	}

	return bytes;
}

/**
 * quic_loss_get_oldest_unacked_time - Get send time of oldest unacked packet
 * @conn: QUIC connection
 *
 * Returns ktime of oldest unacked packet, or 0 if none.
 */
ktime_t quic_loss_get_oldest_unacked_time(struct quic_connection *conn)
{
	ktime_t oldest = 0;
	int i;

	for (i = 0; i < QUIC_PN_SPACE_MAX; i++) {
		struct quic_pn_space *pn_space = &conn->pn_spaces[i];
		struct quic_sent_packet *pkt;
		unsigned long flags;

		if (pn_space->keys_discarded)
			continue;

		spin_lock_irqsave(&pn_space->lock, flags);
		pkt = list_first_entry_or_null(&pn_space->sent_packets,
					       struct quic_sent_packet, list);
		if (pkt) {
			if (oldest == 0 || ktime_before(pkt->sent_time, oldest))
				oldest = pkt->sent_time;
		}
		spin_unlock_irqrestore(&pn_space->lock, flags);
	}

	return oldest;
}

/**
 * quic_loss_retransmit_unacked - Retransmit all unacked data
 * @conn: QUIC connection
 *
 * RFC 9002 Section 6.2.4:
 * In persistent congestion, retransmit all unacked data.
 */
void quic_loss_retransmit_unacked(struct quic_connection *conn)
{
	int i;

	for (i = 0; i < QUIC_PN_SPACE_MAX; i++) {
		struct quic_pn_space *pn_space = &conn->pn_spaces[i];
		struct quic_sent_packet *pkt;
		unsigned long flags;

		if (pn_space->keys_discarded)
			continue;

		spin_lock_irqsave(&pn_space->lock, flags);

		list_for_each_entry(pkt, &pn_space->sent_packets, list) {
			if (pkt->ack_eliciting && !pkt->retransmitted && pkt->skb) {
				struct sk_buff *skb = skb_clone(pkt->skb, GFP_ATOMIC);
				if (skb) {
					pkt->retransmitted = 1;
					spin_unlock_irqrestore(&pn_space->lock, flags);
					skb_queue_tail(&conn->pending_frames, skb);
					conn->stats.packets_retransmitted++;
					spin_lock_irqsave(&pn_space->lock, flags);
				}
			}
		}

		spin_unlock_irqrestore(&pn_space->lock, flags);
	}

	/* Schedule TX work to send retransmissions */
	schedule_work(&conn->tx_work);
}

/**
 * quic_loss_check_persistent_congestion - Check for persistent congestion
 * @conn: QUIC connection
 *
 * RFC 9002 Section 7.6:
 * Persistent congestion is established when all packets sent over a
 * time period spanning the PTO are lost.
 *
 * Returns true if persistent congestion is detected.
 */
bool quic_loss_check_persistent_congestion(struct quic_connection *conn)
{
	struct quic_path *path = conn->active_path;
	u32 pto;
	ktime_t duration;
	ktime_t oldest_lost_time = 0;
	ktime_t newest_lost_time = 0;
	int i;

	if (!path)
		return false;

	/* Need RTT sample for persistent congestion check */
	if (!path->rtt.has_sample)
		return false;

	/*
	 * RFC 9002 Section 7.6.2:
	 * pto = smoothed_rtt + max(4*rttvar, kGranularity) + max_ack_delay
	 * Persistent congestion period = pto * kPersistentCongestionThreshold
	 * kPersistentCongestionThreshold = 3
	 */
	pto = quic_rtt_pto(&path->rtt);

	/* Find oldest and newest lost packet times */
	for (i = 0; i < QUIC_PN_SPACE_MAX; i++) {
		struct quic_pn_space *pn_space = &conn->pn_spaces[i];
		struct quic_sent_packet *pkt;
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

	if (oldest_lost_time == 0 || newest_lost_time == 0)
		return false;

	/*
	 * RFC 9002 Section 7.6.2:
	 * If the time between the oldest and newest lost packets spans
	 * more than the persistent congestion period, declare persistent
	 * congestion.
	 */
	duration = ktime_sub(newest_lost_time, oldest_lost_time);

	/* 3 * PTO in milliseconds converted to nanoseconds */
	if (ktime_to_ms(duration) > (u64)pto * 3) {
		/* Reset congestion window */
		quic_cc_on_congestion_event(&path->cc);
		path->cc.cwnd = 2 * conn->active_path->mtu;
		path->cc.in_slow_start = 1;
		path->cc.in_recovery = 0;
		return true;
	}

	return false;
}

/**
 * quic_loss_cleanup_space - Clean up a packet number space
 * @conn: QUIC connection
 * @pn_space_idx: Packet number space to clean up
 *
 * Frees all packets in the specified packet number space.
 */
void quic_loss_cleanup_space(struct quic_connection *conn, u8 pn_space_idx)
{
	struct quic_pn_space *pn_space;
	struct quic_sent_packet *pkt, *tmp;
	unsigned long flags;

	if (pn_space_idx >= QUIC_PN_SPACE_MAX)
		return;

	pn_space = &conn->pn_spaces[pn_space_idx];

	spin_lock_irqsave(&pn_space->lock, flags);

	list_for_each_entry_safe(pkt, tmp, &pn_space->sent_packets, list) {
		list_del(&pkt->list);
		spin_unlock_irqrestore(&pn_space->lock, flags);
		quic_sent_packet_free(pkt);
		spin_lock_irqsave(&pn_space->lock, flags);
	}

	list_for_each_entry_safe(pkt, tmp, &pn_space->lost_packets, list) {
		list_del(&pkt->list);
		spin_unlock_irqrestore(&pn_space->lock, flags);
		quic_sent_packet_free(pkt);
		spin_lock_irqsave(&pn_space->lock, flags);
	}

	pn_space->ack_eliciting_in_flight = 0;
	pn_space->loss_time = 0;

	spin_unlock_irqrestore(&pn_space->lock, flags);
}

/**
 * quic_loss_cleanup - Clean up all loss detection state
 * @conn: QUIC connection
 *
 * Called during connection teardown.
 */
void quic_loss_cleanup(struct quic_connection *conn)
{
	int i;

	/* Cancel timer */
	quic_timer_cancel(conn, QUIC_TIMER_LOSS);

	/* Clean up all packet number spaces */
	for (i = 0; i < QUIC_PN_SPACE_MAX; i++)
		quic_loss_cleanup_space(conn, i);
}
