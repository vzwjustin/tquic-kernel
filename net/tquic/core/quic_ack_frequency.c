// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * TQUIC ACK_FREQUENCY Extension
 *
 * Implementation of draft-ietf-quic-ack-frequency
 *
 * The ACK_FREQUENCY frame allows an endpoint to control how often its peer
 * sends acknowledgments. This is useful for:
 * - Reducing ACK-heavy traffic on asymmetric links
 * - Improving performance by batching acknowledgments
 * - Adapting to network conditions
 *
 * Copyright (c) 2026 Justin Adams <spotty118@gmail.com>
 * Kernel implementation by Justin Adams <spotty118@gmail.com>
 */

#include <linux/slab.h>
#include <linux/skbuff.h>
#include <linux/ktime.h>
#include <net/tquic.h>

#include "quic_ack_frequency.h"

/*
 * ACK_FREQUENCY frame type (draft-ietf-quic-ack-frequency)
 * Frame type 0xaf
 *
 * ACK_FREQUENCY Frame {
 *   Type (i) = 0xaf,
 *   Sequence Number (i),
 *   Ack-Eliciting Threshold (i),
 *   Request Max Ack Delay (i),
 *   Reordering Threshold (i),
 * }
 */

/*
 * IMMEDIATE_ACK frame type (draft-ietf-quic-ack-frequency)
 * Frame type 0x1f
 *
 * A sender can use the IMMEDIATE_ACK frame to request the peer
 * to send an ACK immediately.
 *
 * IMMEDIATE_ACK Frame {
 *   Type (i) = 0x1f,
 * }
 */

/*
 * Note: struct tquic_ack_frequency_state is defined in quic_ack_frequency.h
 * The struct tracks both the parameters we've received from peer
 * (controlling how we send ACKs) and the parameters we've sent to peer
 * (controlling how they send ACKs to us).
 */

/*
 * tquic_ack_frequency_init - Initialize ACK_FREQUENCY state for a connection
 * @conn: The TQUIC connection
 *
 * Allocates and initializes the ACK_FREQUENCY state with default values
 * per draft-ietf-quic-ack-frequency. The default values match RFC 9000
 * behavior (ACK every other packet, 25ms max delay).
 */
void tquic_ack_frequency_init(struct tquic_connection *conn)
{
	struct tquic_ack_frequency_state *state;

	if (!conn)
		return;

	state = kzalloc(sizeof(*state), GFP_KERNEL);
	if (!state) {
		pr_warn("TQUIC: failed to allocate ACK_FREQUENCY state\n");
		return;
	}

	/*
	 * Initialize with defaults per draft-ietf-quic-ack-frequency.
	 * These defaults match RFC 9000 behavior:
	 * - ACK every 2 ack-eliciting packets (threshold = 2)
	 * - Max ACK delay of 25ms
	 * - Reordering threshold of 1 (immediate ACK on reorder)
	 */
	state->rx_sequence = 0;
	state->rx_ack_eliciting_threshold = TQUIC_ACK_FREQ_DEFAULT_THRESHOLD;
	state->rx_max_ack_delay_us = TQUIC_ACK_FREQ_DEFAULT_MAX_DELAY_US;
	state->rx_reordering_threshold = TQUIC_ACK_FREQ_DEFAULT_REORDER_THRESHOLD;

	state->tx_sequence = 0;
	state->tx_ack_eliciting_threshold = TQUIC_ACK_FREQ_DEFAULT_THRESHOLD;
	state->tx_max_ack_delay_us = TQUIC_ACK_FREQ_DEFAULT_MAX_DELAY_US;
	state->tx_reordering_threshold = TQUIC_ACK_FREQ_DEFAULT_REORDER_THRESHOLD;

	state->enabled = 0;		/* Disabled until negotiated */
	state->immediate_ack_pending = 0;
	state->update_pending = 0;

	conn->ack_freq_state = state;
}

/*
 * tquic_ack_frequency_destroy - Free ACK_FREQUENCY state for a connection
 * @conn: The TQUIC connection
 *
 * Frees the ACK_FREQUENCY state allocated by tquic_ack_frequency_init().
 * Should be called during connection teardown.
 */
void tquic_ack_frequency_destroy(struct tquic_connection *conn)
{
	if (!conn || !conn->ack_freq_state)
		return;

	kfree(conn->ack_freq_state);
	conn->ack_freq_state = NULL;
}

/*
 * tquic_ack_frequency_frame_len - Calculate length of ACK_FREQUENCY frame
 * @sequence: Sequence number
 * @threshold: Ack-eliciting threshold
 * @max_ack_delay_us: Max ACK delay in microseconds
 * @reorder_threshold: Reordering threshold
 *
 * Returns the number of bytes needed to encode the frame.
 */
static int tquic_ack_frequency_frame_len(u64 sequence, u64 threshold,
					u64 max_ack_delay_us,
					u64 reorder_threshold)
{
	int len = 0;

	/* Frame type (0xaf is a 2-byte varint) */
	len += 2;

	/* Sequence Number */
	len += tquic_varint_len(sequence);

	/* Ack-Eliciting Threshold */
	len += tquic_varint_len(threshold);

	/* Request Max Ack Delay (in microseconds) */
	len += tquic_varint_len(max_ack_delay_us);

	/* Reordering Threshold */
	len += tquic_varint_len(reorder_threshold);

	return len;
}

/*
 * tquic_ack_frequency_create - Build an ACK_FREQUENCY frame
 * @conn: The TQUIC connection
 * @skb: The sk_buff to append the frame to
 * @threshold: Ack-eliciting threshold to request
 * @max_ack_delay_us: Max ACK delay to request (in microseconds)
 * @reorder_threshold: Reordering threshold to request
 *
 * Generates an ACK_FREQUENCY frame to control peer's ACK behavior.
 *
 * Returns the number of bytes written, or negative error code.
 */
int tquic_ack_frequency_create(struct tquic_connection *conn,
			      struct sk_buff *skb,
			      u64 threshold,
			      u64 max_ack_delay_us,
			      u64 reorder_threshold)
{
	u8 *p;
	int frame_len;
	u64 sequence;
	struct tquic_ack_frequency_state *state;

	if (!conn || !skb)
		return -EINVAL;

	state = conn->ack_freq_state;
	if (!state)
		return -EINVAL;

	/*
	 * Get next sequence number for this ACK_FREQUENCY frame.
	 * The receiver uses this to ignore obsolete frames.
	 */
	sequence = state->tx_sequence++;

	/* Calculate required space */
	frame_len = tquic_ack_frequency_frame_len(sequence, threshold,
						 max_ack_delay_us,
						 reorder_threshold);

	/* Check if there's room in the skb */
	if (skb_tailroom(skb) < frame_len)
		return -ENOSPC;

	/* Frame type: 0xaf (encoded as 2-byte varint 0x40af) */
	p = skb_put(skb, 2);
	p[0] = 0x40;
	p[1] = 0xaf;

	/* Sequence Number */
	p = skb_put(skb, tquic_varint_len(sequence));
	tquic_varint_encode(sequence, p, tquic_varint_len(sequence));

	/* Ack-Eliciting Threshold */
	p = skb_put(skb, tquic_varint_len(threshold));
	tquic_varint_encode(threshold, p, tquic_varint_len(threshold));

	/* Request Max Ack Delay (microseconds) */
	p = skb_put(skb, tquic_varint_len(max_ack_delay_us));
	tquic_varint_encode(max_ack_delay_us, p, tquic_varint_len(max_ack_delay_us));

	/* Reordering Threshold */
	p = skb_put(skb, tquic_varint_len(reorder_threshold));
	tquic_varint_encode(reorder_threshold, p, tquic_varint_len(reorder_threshold));

	pr_debug("TQUIC: sent ACK_FREQUENCY seq=%llu threshold=%llu delay=%lluus reorder=%llu\n",
		 sequence, threshold, max_ack_delay_us, reorder_threshold);

	return frame_len;
}

/*
 * tquic_ack_frequency_parse - Parse an ACK_FREQUENCY frame
 * @conn: The TQUIC connection
 * @data: Pointer to the frame data (after frame type)
 * @len: Length of available data
 * @sequence: Output: parsed sequence number
 * @threshold: Output: parsed ack-eliciting threshold
 * @max_ack_delay_us: Output: parsed max ACK delay in microseconds
 * @reorder_threshold: Output: parsed reordering threshold
 *
 * Parses an ACK_FREQUENCY frame from received data.
 *
 * Returns the number of bytes consumed (not including frame type),
 * or negative error code.
 */
int tquic_ack_frequency_parse(struct tquic_connection *conn,
			     const u8 *data, int len,
			     u64 *sequence, u64 *threshold,
			     u64 *max_ack_delay_us, u64 *reorder_threshold)
{
	int offset = 0;
	int varint_len;

	/*
	 * SECURITY: Validate buffer size before processing.
	 * This function parses 4 variable-length integers (varints) from untrusted
	 * network data. Varints can be 1, 2, 4, or 8 bytes each per RFC 9000.
	 *
	 * Minimum valid frame:
	 *   - 4 varints, each 1 byte minimum = 4 bytes total
	 *   - This is a DoS check; actual buffer needs checking after each decode
	 *
	 * We don't assume single-byte varints; each tquic_varint_decode() call
	 * validates buffer bounds and returns the bytes consumed.
	 */
	if (!data || len < 4)
		return -EINVAL;

	/* Sequence Number */
	varint_len = tquic_varint_decode(data + offset, len - offset, sequence);
	if (varint_len < 0)
		return varint_len;
	offset += varint_len;

	/* Ack-Eliciting Threshold */
	varint_len = tquic_varint_decode(data + offset, len - offset, threshold);
	if (varint_len < 0)
		return varint_len;
	offset += varint_len;

	/* Request Max Ack Delay (microseconds) */
	varint_len = tquic_varint_decode(data + offset, len - offset,
					max_ack_delay_us);
	if (varint_len < 0)
		return varint_len;
	offset += varint_len;

	/* Reordering Threshold */
	varint_len = tquic_varint_decode(data + offset, len - offset,
					reorder_threshold);
	if (varint_len < 0)
		return varint_len;
	offset += varint_len;

	return offset;
}

/*
 * tquic_ack_frequency_process - Process a received ACK_FREQUENCY frame
 * @conn: The TQUIC connection
 * @data: Pointer to the frame data (after frame type)
 * @len: Length of available data
 *
 * Processes an ACK_FREQUENCY frame and updates the connection's ACK
 * generation parameters accordingly.
 *
 * Returns the number of bytes consumed, or negative error code.
 */
int tquic_ack_frequency_process(struct tquic_connection *conn,
			       const u8 *data, int len)
{
	u64 sequence;
	u64 threshold;
	u64 max_ack_delay_us;
	u64 reorder_threshold;
	int consumed;
	struct tquic_ack_frequency_state *state;

	if (!conn)
		return -EINVAL;

	state = conn->ack_freq_state;
	if (!state)
		return -EINVAL;

	/* Parse the frame */
	consumed = tquic_ack_frequency_parse(conn, data, len, &sequence,
					    &threshold, &max_ack_delay_us,
					    &reorder_threshold);
	if (consumed < 0)
		return consumed;

	/*
	 * Per draft-ietf-quic-ack-frequency:
	 * A receiving endpoint SHOULD ignore ACK_FREQUENCY frames that
	 * have a lower sequence number than the highest received.
	 */
	if (sequence <= state->rx_sequence && state->rx_sequence != 0) {
		pr_debug("TQUIC: ignoring stale ACK_FREQUENCY seq=%llu (current=%llu)\n",
			 sequence, state->rx_sequence);
		return consumed;
	}

	/* Update received sequence number */
	state->rx_sequence = sequence;

	/*
	 * Apply the new ACK generation parameters.
	 *
	 * These values control how we send ACKs to the peer:
	 * - threshold: Send ACK after receiving this many ack-eliciting packets
	 * - max_ack_delay_us: Maximum time to delay sending an ACK
	 * - reorder_threshold: Packets to allow out-of-order before immediate ACK
	 */
	state->rx_ack_eliciting_threshold = threshold;
	state->rx_max_ack_delay_us = max_ack_delay_us;
	state->rx_reordering_threshold = reorder_threshold;

	pr_debug("TQUIC: received ACK_FREQUENCY seq=%llu threshold=%llu delay=%lluus reorder=%llu\n",
		 sequence, threshold, max_ack_delay_us, reorder_threshold);

	return consumed;
}

/*
 * tquic_immediate_ack_create - Build an IMMEDIATE_ACK frame
 * @conn: The TQUIC connection
 * @skb: The sk_buff to append the frame to
 *
 * Generates an IMMEDIATE_ACK frame to request peer send ACK immediately.
 *
 * Returns the number of bytes written, or negative error code.
 */
int tquic_immediate_ack_create(struct tquic_connection *conn, struct sk_buff *skb)
{
	u8 *p;

	if (!conn || !skb)
		return -EINVAL;

	/* Check if there's room in the skb */
	if (skb_tailroom(skb) < 1)
		return -ENOSPC;

	/* Frame type: 0x1f */
	p = skb_put(skb, 1);
	*p = TQUIC_FRAME_IMMEDIATE_ACK;

	pr_debug("TQUIC: sent IMMEDIATE_ACK\n");

	return 1;
}

/*
 * tquic_immediate_ack_process - Process a received IMMEDIATE_ACK frame
 * @conn: The TQUIC connection
 *
 * Sets a flag to send an ACK immediately in the next packet.
 *
 * Returns 0 on success.
 */
int tquic_immediate_ack_process(struct tquic_connection *conn)
{
	struct tquic_ack_frequency_state *state;

	if (!conn)
		return -EINVAL;

	state = conn->ack_freq_state;

	/*
	 * Per draft-ietf-quic-ack-frequency:
	 * Upon receipt of an IMMEDIATE_ACK frame, the receiver SHOULD
	 * send an ACK frame immediately.
	 */
	if (state)
		state->immediate_ack_pending = 1;

	/* Set connection-level immediate ACK flag */
	set_bit(TQUIC_CONN_FLAG_IMMEDIATE_ACK, &conn->flags);

	pr_debug("TQUIC: received IMMEDIATE_ACK\n");

	/* Trigger immediate ACK by setting timer to now */
	if (conn->timer_state)
		tquic_timer_set_ack_delay(conn->timer_state);

	return 0;
}

/*
 * tquic_ack_frequency_should_send - Check if ACK should be sent per ACK_FREQUENCY
 * @conn: The TQUIC connection
 * @pn_space: The packet number space
 * @ack_eliciting_count: Number of ack-eliciting packets received since last ACK
 * @largest_recv_pn: Largest received packet number
 * @last_ack_largest: Largest PN in last sent ACK
 *
 * Determines if an ACK should be sent based on ACK_FREQUENCY parameters.
 *
 * Per draft-ietf-quic-ack-frequency, an ACK should be sent when:
 * 1. More than ack_eliciting_threshold packets received since last ACK
 * 2. max_ack_delay has elapsed since receiving an ack-eliciting packet
 * 3. A packet is received out-of-order beyond reordering_threshold
 * 4. IMMEDIATE_ACK was received
 *
 * Returns true if ACK should be sent.
 */
bool tquic_ack_frequency_should_send(struct tquic_connection *conn,
				    u8 pn_space,
				    u32 ack_eliciting_count,
				    u64 largest_recv_pn,
				    u64 last_ack_largest)
{
	struct tquic_ack_frequency_state *state;
	u64 threshold;
	u64 reorder_threshold;

	if (!conn || pn_space >= TQUIC_PN_SPACE_COUNT)
		return false;

	state = conn->ack_freq_state;

	/*
	 * Initial and Handshake packets always get immediate ACKs
	 * per RFC 9000 Section 13.2.1
	 */
	if (pn_space == TQUIC_PN_SPACE_INITIAL ||
	    pn_space == TQUIC_PN_SPACE_HANDSHAKE) {
		return ack_eliciting_count > 0;
	}

	/* Check for IMMEDIATE_ACK flag */
	if (test_and_clear_bit(TQUIC_CONN_FLAG_IMMEDIATE_ACK, &conn->flags))
		return true;

	/* Check state-level immediate ACK pending */
	if (state && state->immediate_ack_pending) {
		state->immediate_ack_pending = 0;
		return true;
	}

	/* Get threshold from ACK_FREQUENCY state or use default */
	if (state && state->rx_ack_eliciting_threshold > 0)
		threshold = state->rx_ack_eliciting_threshold;
	else
		threshold = TQUIC_ACK_FREQ_DEFAULT_THRESHOLD;

	/* Check ack-eliciting threshold */
	if (ack_eliciting_count > threshold)
		return true;

	/* Check reordering threshold */
	if (state && state->rx_reordering_threshold > 0)
		reorder_threshold = state->rx_reordering_threshold;
	else
		reorder_threshold = TQUIC_ACK_FREQ_DEFAULT_REORDER_THRESHOLD;

	/*
	 * Per draft-ietf-quic-ack-frequency Section 5:
	 * If a packet arrives that has a larger packet number than
	 * the largest received packet number plus reordering_threshold,
	 * an ACK should be sent immediately.
	 *
	 * This handles gap detection indicating potential loss.
	 */
	if (reorder_threshold > 0 && last_ack_largest > 0) {
		if (largest_recv_pn > last_ack_largest + reorder_threshold)
			return true;
	}

	return false;
}

/*
 * tquic_ack_frequency_set - Request peer to use specific ACK frequency
 * @conn: The TQUIC connection
 * @threshold: Ack-eliciting threshold (packets before ACK required)
 * @max_delay_ms: Maximum ACK delay in milliseconds
 * @reorder_threshold: Reordering threshold
 *
 * Queues an ACK_FREQUENCY frame to be sent to the peer.
 *
 * Returns 0 on success, negative error code on failure.
 */
int tquic_ack_frequency_set(struct tquic_connection *conn,
			   u64 threshold, u32 max_delay_ms,
			   u64 reorder_threshold)
{
	struct sk_buff *skb;
	int len;

	if (!conn)
		return -EINVAL;

	/* Allocate skb for the frame */
	skb = alloc_skb(64, GFP_KERNEL);
	if (!skb)
		return -ENOMEM;

	/* Create the ACK_FREQUENCY frame */
	len = tquic_ack_frequency_create(conn, skb, threshold,
					(u64)max_delay_ms * 1000,
					reorder_threshold);
	if (len < 0) {
		kfree_skb(skb);
		return len;
	}

	/* Queue for transmission in the control frames queue */
	skb_queue_tail(&conn->control_frames, skb);

	/* Schedule transmission */
	schedule_work(&conn->tx_work);

	return 0;
}

/*
 * Module initialization/cleanup - these functions are called from
 * the main TQUIC module init/exit.
 */
int __init tquic_ack_frequency_module_init(void)
{
	pr_debug("TQUIC ACK_FREQUENCY extension initialized\n");
	return 0;
}

void tquic_ack_frequency_module_exit(void)
{
	pr_debug("TQUIC ACK_FREQUENCY extension cleanup\n");
}

EXPORT_SYMBOL_GPL(tquic_ack_frequency_create);
EXPORT_SYMBOL_GPL(tquic_ack_frequency_parse);
EXPORT_SYMBOL_GPL(tquic_ack_frequency_process);
EXPORT_SYMBOL_GPL(tquic_immediate_ack_create);
EXPORT_SYMBOL_GPL(tquic_immediate_ack_process);
EXPORT_SYMBOL_GPL(tquic_ack_frequency_should_send);
EXPORT_SYMBOL_GPL(tquic_ack_frequency_set);
