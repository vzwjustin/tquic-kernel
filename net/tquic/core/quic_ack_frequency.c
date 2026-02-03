// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * QUIC ACK_FREQUENCY Extension
 *
 * Implementation of draft-ietf-quic-ack-frequency
 *
 * The ACK_FREQUENCY frame allows an endpoint to control how often its peer
 * sends acknowledgments. This is useful for:
 * - Reducing ACK-heavy traffic on asymmetric links
 * - Improving performance by batching acknowledgments
 * - Adapting to network conditions
 *
 * Copyright (c) 2024 Linux QUIC Authors
 */

#include <linux/slab.h>
#include <linux/skbuff.h>
#include <linux/ktime.h>
#include <net/quic.h>

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

/* Forward declarations for varint helpers */
extern int quic_varint_len(u64 val);
extern void quic_varint_encode(u64 val, u8 *buf);
extern int quic_varint_decode(const u8 *buf, size_t len, u64 *val);

/*
 * ACK_FREQUENCY state structure
 *
 * This tracks both the parameters we've received from peer
 * (controlling how we send ACKs) and the parameters we've sent to peer
 * (controlling how they send ACKs to us).
 */
struct quic_ack_frequency_state {
	/* Parameters received from peer (controlling our ACK behavior) */
	u64	rx_sequence;		/* Highest sequence number received */
	u64	rx_ack_eliciting_threshold; /* Packets before ACK required */
	u64	rx_max_ack_delay_us;	/* Max delay in microseconds */
	u64	rx_reordering_threshold; /* Reordering threshold */

	/* Parameters we've sent to peer (controlling their ACK behavior) */
	u64	tx_sequence;		/* Next sequence number to send */
	u64	tx_ack_eliciting_threshold; /* Requested threshold */
	u64	tx_max_ack_delay_us;	/* Requested max delay */
	u64	tx_reordering_threshold; /* Requested reordering threshold */

	/* State tracking */
	u8	enabled:1;		/* Extension negotiated */
	u8	immediate_ack_pending:1; /* IMMEDIATE_ACK received */
	u8	update_pending:1;	/* Need to send ACK_FREQUENCY */
};

/* Default values per draft-ietf-quic-ack-frequency */
#define QUIC_ACK_FREQ_DEFAULT_THRESHOLD		1
#define QUIC_ACK_FREQ_DEFAULT_REORDER_THRESHOLD	1
#define QUIC_ACK_FREQ_DEFAULT_MAX_DELAY_US	25000

/*
 * quic_ack_frequency_init - Initialize ACK_FREQUENCY state for a connection
 * @conn: The QUIC connection
 *
 * Allocates and initializes the ACK_FREQUENCY state with default values
 * per draft-ietf-quic-ack-frequency. The default values match RFC 9000
 * behavior (ACK every other packet, 25ms max delay).
 */
void quic_ack_frequency_init(struct quic_connection *conn)
{
	struct quic_ack_frequency_state *state;

	if (!conn)
		return;

	state = kzalloc(sizeof(*state), GFP_KERNEL);
	if (!state) {
		pr_warn("QUIC: failed to allocate ACK_FREQUENCY state\n");
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
	state->rx_ack_eliciting_threshold = QUIC_ACK_FREQ_DEFAULT_THRESHOLD;
	state->rx_max_ack_delay_us = QUIC_ACK_FREQ_DEFAULT_MAX_DELAY_US;
	state->rx_reordering_threshold = QUIC_ACK_FREQ_DEFAULT_REORDER_THRESHOLD;

	state->tx_sequence = 0;
	state->tx_ack_eliciting_threshold = QUIC_ACK_FREQ_DEFAULT_THRESHOLD;
	state->tx_max_ack_delay_us = QUIC_ACK_FREQ_DEFAULT_MAX_DELAY_US;
	state->tx_reordering_threshold = QUIC_ACK_FREQ_DEFAULT_REORDER_THRESHOLD;

	state->enabled = 0;		/* Disabled until negotiated */
	state->immediate_ack_pending = 0;
	state->update_pending = 0;

	conn->ack_freq = state;
}

/*
 * quic_ack_frequency_destroy - Free ACK_FREQUENCY state for a connection
 * @conn: The QUIC connection
 *
 * Frees the ACK_FREQUENCY state allocated by quic_ack_frequency_init().
 * Should be called during connection teardown.
 */
void quic_ack_frequency_destroy(struct quic_connection *conn)
{
	if (!conn || !conn->ack_freq)
		return;

	kfree(conn->ack_freq);
	conn->ack_freq = NULL;
}

/*
 * quic_ack_frequency_frame_len - Calculate length of ACK_FREQUENCY frame
 * @sequence: Sequence number
 * @threshold: Ack-eliciting threshold
 * @max_ack_delay_us: Max ACK delay in microseconds
 * @reorder_threshold: Reordering threshold
 *
 * Returns the number of bytes needed to encode the frame.
 */
static int quic_ack_frequency_frame_len(u64 sequence, u64 threshold,
					u64 max_ack_delay_us,
					u64 reorder_threshold)
{
	int len = 0;

	/* Frame type (0xaf is a 2-byte varint) */
	len += 2;

	/* Sequence Number */
	len += quic_varint_len(sequence);

	/* Ack-Eliciting Threshold */
	len += quic_varint_len(threshold);

	/* Request Max Ack Delay (in microseconds) */
	len += quic_varint_len(max_ack_delay_us);

	/* Reordering Threshold */
	len += quic_varint_len(reorder_threshold);

	return len;
}

/*
 * quic_ack_frequency_create - Build an ACK_FREQUENCY frame
 * @conn: The QUIC connection
 * @skb: The sk_buff to append the frame to
 * @threshold: Ack-eliciting threshold to request
 * @max_ack_delay_us: Max ACK delay to request (in microseconds)
 * @reorder_threshold: Reordering threshold to request
 *
 * Generates an ACK_FREQUENCY frame to control peer's ACK behavior.
 *
 * Returns the number of bytes written, or negative error code.
 */
int quic_ack_frequency_create(struct quic_connection *conn,
			      struct sk_buff *skb,
			      u64 threshold,
			      u64 max_ack_delay_us,
			      u64 reorder_threshold)
{
	u8 *p;
	int frame_len;
	u64 sequence;

	if (!conn || !skb)
		return -EINVAL;

	/*
	 * Get next sequence number for this ACK_FREQUENCY frame.
	 * The receiver uses this to ignore obsolete frames.
	 */
	sequence = conn->ack_freq_tx_seq++;

	/* Calculate required space */
	frame_len = quic_ack_frequency_frame_len(sequence, threshold,
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
	p = skb_put(skb, quic_varint_len(sequence));
	quic_varint_encode(sequence, p);

	/* Ack-Eliciting Threshold */
	p = skb_put(skb, quic_varint_len(threshold));
	quic_varint_encode(threshold, p);

	/* Request Max Ack Delay (microseconds) */
	p = skb_put(skb, quic_varint_len(max_ack_delay_us));
	quic_varint_encode(max_ack_delay_us, p);

	/* Reordering Threshold */
	p = skb_put(skb, quic_varint_len(reorder_threshold));
	quic_varint_encode(reorder_threshold, p);

	pr_debug("QUIC: sent ACK_FREQUENCY seq=%llu threshold=%llu delay=%lluus reorder=%llu\n",
		 sequence, threshold, max_ack_delay_us, reorder_threshold);

	return frame_len;
}

/*
 * quic_ack_frequency_parse - Parse an ACK_FREQUENCY frame
 * @conn: The QUIC connection
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
int quic_ack_frequency_parse(struct quic_connection *conn,
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
	 * We don't assume single-byte varints; each quic_varint_decode() call
	 * validates buffer bounds and returns the bytes consumed.
	 */
	if (!data || len < 4)
		return -EINVAL;

	/* Sequence Number */
	varint_len = quic_varint_decode(data + offset, len - offset, sequence);
	if (varint_len < 0)
		return varint_len;
	offset += varint_len;

	/* Ack-Eliciting Threshold */
	varint_len = quic_varint_decode(data + offset, len - offset, threshold);
	if (varint_len < 0)
		return varint_len;
	offset += varint_len;

	/* Request Max Ack Delay (microseconds) */
	varint_len = quic_varint_decode(data + offset, len - offset,
					max_ack_delay_us);
	if (varint_len < 0)
		return varint_len;
	offset += varint_len;

	/* Reordering Threshold */
	varint_len = quic_varint_decode(data + offset, len - offset,
					reorder_threshold);
	if (varint_len < 0)
		return varint_len;
	offset += varint_len;

	return offset;
}

/*
 * quic_ack_frequency_process - Process a received ACK_FREQUENCY frame
 * @conn: The QUIC connection
 * @data: Pointer to the frame data (after frame type)
 * @len: Length of available data
 *
 * Processes an ACK_FREQUENCY frame and updates the connection's ACK
 * generation parameters accordingly.
 *
 * Returns the number of bytes consumed, or negative error code.
 */
int quic_ack_frequency_process(struct quic_connection *conn,
			       const u8 *data, int len)
{
	u64 sequence;
	u64 threshold;
	u64 max_ack_delay_us;
	u64 reorder_threshold;
	int consumed;

	if (!conn)
		return -EINVAL;

	/* Parse the frame */
	consumed = quic_ack_frequency_parse(conn, data, len, &sequence,
					    &threshold, &max_ack_delay_us,
					    &reorder_threshold);
	if (consumed < 0)
		return consumed;

	/*
	 * Per draft-ietf-quic-ack-frequency:
	 * A receiving endpoint SHOULD ignore ACK_FREQUENCY frames that
	 * have a lower sequence number than the highest received.
	 */
	if (sequence <= conn->ack_freq_rx_seq && conn->ack_freq_rx_seq != 0) {
		pr_debug("QUIC: ignoring stale ACK_FREQUENCY seq=%llu (current=%llu)\n",
			 sequence, conn->ack_freq_rx_seq);
		return consumed;
	}

	/* Update received sequence number */
	conn->ack_freq_rx_seq = sequence;

	/*
	 * Apply the new ACK generation parameters.
	 *
	 * These values control how we send ACKs to the peer:
	 * - threshold: Send ACK after receiving this many ack-eliciting packets
	 * - max_ack_delay_us: Maximum time to delay sending an ACK
	 * - reorder_threshold: Packets to allow out-of-order before immediate ACK
	 */
	conn->ack_freq_threshold = threshold;
	conn->ack_freq_max_delay_us = max_ack_delay_us;
	conn->ack_freq_reorder_threshold = reorder_threshold;

	pr_debug("QUIC: received ACK_FREQUENCY seq=%llu threshold=%llu delay=%lluus reorder=%llu\n",
		 sequence, threshold, max_ack_delay_us, reorder_threshold);

	return consumed;
}

/*
 * quic_immediate_ack_create - Build an IMMEDIATE_ACK frame
 * @conn: The QUIC connection
 * @skb: The sk_buff to append the frame to
 *
 * Generates an IMMEDIATE_ACK frame to request peer send ACK immediately.
 *
 * Returns the number of bytes written, or negative error code.
 */
int quic_immediate_ack_create(struct quic_connection *conn, struct sk_buff *skb)
{
	u8 *p;

	if (!conn || !skb)
		return -EINVAL;

	/* Check if there's room in the skb */
	if (skb_tailroom(skb) < 1)
		return -ENOSPC;

	/* Frame type: 0x1f */
	p = skb_put(skb, 1);
	*p = QUIC_FRAME_IMMEDIATE_ACK;

	pr_debug("QUIC: sent IMMEDIATE_ACK\n");

	return 1;
}

/*
 * quic_immediate_ack_process - Process a received IMMEDIATE_ACK frame
 * @conn: The QUIC connection
 *
 * Sets a flag to send an ACK immediately in the next packet.
 *
 * Returns 0 on success.
 */
int quic_immediate_ack_process(struct quic_connection *conn)
{
	if (!conn)
		return -EINVAL;

	/*
	 * Per draft-ietf-quic-ack-frequency:
	 * Upon receipt of an IMMEDIATE_ACK frame, the receiver SHOULD
	 * send an ACK frame immediately.
	 */
	conn->immediate_ack_pending = 1;

	pr_debug("QUIC: received IMMEDIATE_ACK\n");

	/* Trigger immediate ACK by setting timer to now */
	quic_timer_set(conn, QUIC_TIMER_ACK, ktime_get());

	return 0;
}

/*
 * quic_ack_frequency_should_send - Check if ACK should be sent per ACK_FREQUENCY
 * @conn: The QUIC connection
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
bool quic_ack_frequency_should_send(struct quic_connection *conn,
				    u8 pn_space,
				    u32 ack_eliciting_count,
				    u64 largest_recv_pn,
				    u64 last_ack_largest)
{
	struct quic_pn_space *space;
	u64 threshold;
	u64 reorder_threshold;
	ktime_t now;
	s64 elapsed_us;
	u64 max_delay_us;

	if (!conn || pn_space >= QUIC_PN_SPACE_MAX)
		return false;

	space = &conn->pn_spaces[pn_space];

	/*
	 * Initial and Handshake packets always get immediate ACKs
	 * per RFC 9000 Section 13.2.1
	 */
	if (pn_space == QUIC_PN_SPACE_INITIAL ||
	    pn_space == QUIC_PN_SPACE_HANDSHAKE) {
		return ack_eliciting_count > 0;
	}

	/* Check for IMMEDIATE_ACK flag */
	if (conn->immediate_ack_pending) {
		conn->immediate_ack_pending = 0;
		return true;
	}

	/* Get threshold from ACK_FREQUENCY or use default */
	threshold = conn->ack_freq_threshold;
	if (threshold == 0)
		threshold = QUIC_ACK_FREQ_DEFAULT_THRESHOLD;

	/* Check ack-eliciting threshold */
	if (ack_eliciting_count > threshold)
		return true;

	/* Check reordering threshold */
	reorder_threshold = conn->ack_freq_reorder_threshold;
	if (reorder_threshold == 0)
		reorder_threshold = QUIC_ACK_FREQ_DEFAULT_REORDER_THRESHOLD;

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

	/* Check max_ack_delay timeout */
	if (ack_eliciting_count > 0) {
		now = ktime_get();
		elapsed_us = ktime_us_delta(now, space->last_ack_time);

		max_delay_us = conn->ack_freq_max_delay_us;
		if (max_delay_us == 0)
			max_delay_us = QUIC_ACK_FREQ_DEFAULT_MAX_DELAY_US;

		if (elapsed_us >= (s64)max_delay_us)
			return true;
	}

	return false;
}

/*
 * quic_ack_frequency_set - Request peer to use specific ACK frequency
 * @conn: The QUIC connection
 * @threshold: Ack-eliciting threshold (packets before ACK required)
 * @max_delay_ms: Maximum ACK delay in milliseconds
 * @reorder_threshold: Reordering threshold
 *
 * Queues an ACK_FREQUENCY frame to be sent to the peer.
 *
 * Returns 0 on success, negative error code on failure.
 */
int quic_ack_frequency_set(struct quic_connection *conn,
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
	len = quic_ack_frequency_create(conn, skb, threshold,
					(u64)max_delay_ms * 1000,
					reorder_threshold);
	if (len < 0) {
		kfree_skb(skb);
		return len;
	}

	/* Queue for transmission */
	if (quic_conn_queue_frame(conn, skb))
		return -ENOBUFS;

	/* Schedule transmission */
	schedule_work(&conn->tx_work);

	return 0;
}

/*
 * Module initialization/cleanup - these functions are called from
 * the main QUIC module init/exit.
 */
int __init quic_ack_frequency_module_init(void)
{
	pr_debug("QUIC ACK_FREQUENCY extension initialized\n");
	return 0;
}

void quic_ack_frequency_module_exit(void)
{
	pr_debug("QUIC ACK_FREQUENCY extension cleanup\n");
}

EXPORT_SYMBOL_GPL(quic_ack_frequency_create);
EXPORT_SYMBOL_GPL(quic_ack_frequency_parse);
EXPORT_SYMBOL_GPL(quic_ack_frequency_process);
EXPORT_SYMBOL_GPL(quic_immediate_ack_create);
EXPORT_SYMBOL_GPL(quic_immediate_ack_process);
EXPORT_SYMBOL_GPL(quic_ack_frequency_should_send);
EXPORT_SYMBOL_GPL(quic_ack_frequency_set);
