// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * QUIC - Quick UDP Internet Connections
 *
 * ACK frame generation and received packet tracking
 *
 * Implementation follows RFC 9000 Section 13.2 for generating acknowledgments.
 *
 * Copyright (c) 2024 Linux QUIC Authors
 */

#include <linux/slab.h>
#include <linux/skbuff.h>
#include <linux/list.h>
#include <linux/bitmap.h>
#include <linux/ktime.h>
#include <net/quic.h>

/*
 * Maximum number of ACK ranges to track per packet number space.
 * This limits memory usage while still allowing for reasonable
 * out-of-order packet tracking.
 */
#define QUIC_ACK_MAX_RANGES		256

/*
 * Maximum number of ack-eliciting packets to receive before
 * sending an ACK. RFC 9000 recommends sending an ACK after
 * receiving at least 2 ack-eliciting packets.
 */
#define QUIC_ACK_ELICITING_THRESHOLD	2

/*
 * Maximum delay before sending an ACK (in microseconds).
 * This is based on the default max_ack_delay of 25ms from RFC 9000.
 */
#define QUIC_MAX_ACK_DELAY_US		25000

/*
 * Default ack_delay_exponent per RFC 9000 Section 18.2.
 * The exponent used to decode the ACK Delay field is 3.
 */
#define QUIC_DEFAULT_ACK_DELAY_EXP	3

/*
 * Note: The current implementation uses the embedded quic_ack_info structure
 * from the quic_pn_space for ACK state tracking. The ranges[] array in that
 * structure provides sufficient capacity for most use cases. For connections
 * with extreme packet reordering, a more sophisticated interval tree or
 * linked-list based approach could be implemented in the future.
 */

/*
 * Helper function declarations for variable-length integer encoding.
 * These are defined in stream.c but declared here for local use.
 */
extern int quic_varint_len(u64 val);
extern void quic_varint_encode(u64 val, u8 *buf);
extern int quic_varint_decode(const u8 *buf, size_t len, u64 *val);

/*
 * quic_ack_compute_delay - Compute the ACK delay value for encoding
 * @conn: The QUIC connection
 * @pn_space: The packet number space
 *
 * Computes the ACK delay as the time since receiving the largest
 * acknowledged packet, scaled by the ack_delay_exponent.
 *
 * Returns the encoded ACK delay value.
 */
static u64 quic_ack_compute_delay(struct quic_connection *conn, u8 pn_space)
{
	struct quic_pn_space *space = &conn->pn_spaces[pn_space];
	ktime_t now = ktime_get();
	ktime_t recv_time = space->last_ack_time;
	s64 delay_us;
	u64 delay_encoded;
	u32 ack_delay_exponent;

	/* Use remote's ack_delay_exponent, default to 3 */
	ack_delay_exponent = conn->remote_params.ack_delay_exponent;
	if (ack_delay_exponent == 0)
		ack_delay_exponent = QUIC_DEFAULT_ACK_DELAY_EXP;

	/* Calculate delay in microseconds */
	if (ktime_compare(recv_time, 0) == 0) {
		/* No timestamp recorded, use 0 delay */
		return 0;
	}

	delay_us = ktime_us_delta(now, recv_time);
	if (delay_us < 0)
		delay_us = 0;

	/*
	 * Encode the delay: divide by 2^ack_delay_exponent
	 * The result represents the delay in units of 2^exponent microseconds.
	 */
	delay_encoded = (u64)delay_us >> ack_delay_exponent;

	/*
	 * Cap to max_ack_delay if configured. The receiver should not
	 * indicate a delay greater than max_ack_delay.
	 */
	if (conn->local_params.max_ack_delay > 0) {
		u64 max_delay = conn->local_params.max_ack_delay * 1000;
		max_delay >>= ack_delay_exponent;
		if (delay_encoded > max_delay)
			delay_encoded = max_delay;
	}

	return delay_encoded;
}

/*
 * quic_ack_decode_delay - Decode an ACK delay value from a received ACK
 * @conn: The QUIC connection
 * @encoded_delay: The encoded ACK delay from the frame
 *
 * Returns the ACK delay in microseconds.
 */
u64 quic_ack_decode_delay(struct quic_connection *conn, u64 encoded_delay)
{
	u32 ack_delay_exponent;

	/* Use peer's ack_delay_exponent */
	ack_delay_exponent = conn->remote_params.ack_delay_exponent;
	if (ack_delay_exponent == 0)
		ack_delay_exponent = QUIC_DEFAULT_ACK_DELAY_EXP;

	return encoded_delay << ack_delay_exponent;
}

/*
 * quic_ack_update_recv_ranges - Update received ranges with a new packet number
 * @conn: The QUIC connection
 * @pn_space: The packet number space
 * @pn: The received packet number
 *
 * Maintains a list of contiguous ranges of received packet numbers.
 * Adjacent ranges are merged when possible to minimize range count.
 */
static void quic_ack_update_recv_ranges(struct quic_connection *conn,
					u8 pn_space, u64 pn)
{
	struct quic_pn_space *space = &conn->pn_spaces[pn_space];
	struct quic_ack_info *ack_info = &space->recv_ack_info;
	int i, j;
	bool inserted = false;

	/*
	 * The ack_info->ranges[] array stores ranges in a specific format:
	 * ranges[0] = first ACK range (packets from largest_acked down)
	 * ranges[1..n] = gap + range pairs for additional ranges
	 *
	 * For simplicity, we rebuild the ranges each time by tracking
	 * all received packets. In production, a more sophisticated
	 * data structure like an interval tree would be used.
	 */

	/*
	 * Check if this packet number is already covered by existing ranges.
	 * If so, nothing to do.
	 */
	if (ack_info->largest_acked >= pn) {
		/* Check if within first range */
		u64 smallest_in_first = ack_info->largest_acked -
					ack_info->ranges[0].ack_range;
		if (pn >= smallest_in_first)
			return; /* Already covered */
	}

	/*
	 * Update largest_acked if this is a newer packet.
	 */
	if (pn > ack_info->largest_acked) {
		/*
		 * New largest packet number. Shift all ranges down and
		 * create a new first range.
		 */
		if (ack_info->largest_acked > 0 && ack_info->ack_range_count > 0) {
			/* There's an existing first range to preserve */
			u64 old_largest = ack_info->largest_acked;
			u64 old_first_range = ack_info->ranges[0].ack_range;
			u64 old_smallest = old_largest - old_first_range;

			if (pn == old_largest + 1) {
				/*
				 * Contiguous with previous largest.
				 * Just extend the first range.
				 */
				ack_info->largest_acked = pn;
				ack_info->ranges[0].ack_range = pn - old_smallest;
				inserted = true;
			} else {
				/*
				 * Gap between new packet and old largest.
				 * Need to shift ranges and create new first range.
				 */
				u64 gap = pn - old_largest - 2;

				/* Shift existing ranges */
				if (ack_info->ack_range_count < QUIC_ACK_MAX_RANGES) {
					for (j = ack_info->ack_range_count; j >= 1; j--) {
						ack_info->ranges[j].gap =
							ack_info->ranges[j - 1].gap;
						ack_info->ranges[j].ack_range =
							ack_info->ranges[j - 1].ack_range;
					}
					/* First gap is distance to old range */
					ack_info->ranges[1].gap = gap;
					ack_info->ranges[1].ack_range = old_first_range;
					ack_info->ack_range_count++;
				}

				ack_info->largest_acked = pn;
				ack_info->ranges[0].ack_range = 0; /* Single packet */
				inserted = true;
			}
		} else {
			/* First packet received in this space */
			ack_info->largest_acked = pn;
			ack_info->ranges[0].ack_range = 0;
			ack_info->ack_range_count = 1;
			inserted = true;
		}
	} else {
		/*
		 * Packet number is less than largest_acked.
		 * Need to find appropriate range to extend or create new range.
		 */
		u64 current_largest = ack_info->largest_acked;
		u64 current_smallest = current_largest - ack_info->ranges[0].ack_range;

		/* Check if extends first range downward */
		if (pn == current_smallest - 1) {
			ack_info->ranges[0].ack_range++;
			inserted = true;
		} else if (pn < current_smallest - 1) {
			/*
			 * Need to check additional ranges or create new range.
			 * For simplicity, scan through existing ranges.
			 */
			u64 prev_end = current_smallest;

			for (i = 1; i < ack_info->ack_range_count && i < QUIC_ACK_MAX_RANGES; i++) {
				u64 gap = ack_info->ranges[i].gap;
				u64 range_size = ack_info->ranges[i].ack_range;
				u64 range_end = prev_end - gap - 2;
				u64 range_start = range_end - range_size;

				if (pn >= range_start && pn <= range_end) {
					/* Already in this range */
					inserted = true;
					break;
				}

				if (pn == range_end + 1) {
					/* Extends range upward - may merge with previous */
					ack_info->ranges[i].ack_range++;

					/* Check if merges with previous range */
					if (i == 1 && gap == 0) {
						/* Merge into first range */
						ack_info->ranges[0].ack_range += range_size + 2;
						/* Shift remaining ranges */
						for (j = 1; j < ack_info->ack_range_count - 1; j++) {
							ack_info->ranges[j] = ack_info->ranges[j + 1];
						}
						ack_info->ack_range_count--;
					}
					inserted = true;
					break;
				}

				if (pn == range_start - 1) {
					/* Extends range downward */
					ack_info->ranges[i].ack_range++;
					inserted = true;
					break;
				}

				prev_end = range_start;
			}

			/*
			 * If not inserted into existing range, need to create new one.
			 * Find the right position and insert.
			 */
			if (!inserted && ack_info->ack_range_count < QUIC_ACK_MAX_RANGES) {
				/* Insert new single-packet range in proper position */
				prev_end = current_smallest;

				for (i = 1; i <= ack_info->ack_range_count; i++) {
					u64 next_range_start;

					if (i < ack_info->ack_range_count) {
						u64 gap = ack_info->ranges[i].gap;
						u64 range_size = ack_info->ranges[i].ack_range;
						u64 range_end = prev_end - gap - 2;
						next_range_start = range_end - range_size;

						if (pn > next_range_start) {
							/* Insert here */
							/* Shift ranges from i onward */
							for (j = ack_info->ack_range_count; j > i; j--) {
								ack_info->ranges[j] = ack_info->ranges[j - 1];
							}

							/* Calculate gaps */
							ack_info->ranges[i].gap = prev_end - pn - 2;
							ack_info->ranges[i].ack_range = 0;

							/* Update next range's gap */
							if (i + 1 < ack_info->ack_range_count + 1) {
								ack_info->ranges[i + 1].gap =
									pn - (prev_end - gap - 2) - 2;
							}

							ack_info->ack_range_count++;
							inserted = true;
							break;
						}

						prev_end = next_range_start;
					} else {
						/* Append at end */
						ack_info->ranges[i].gap = prev_end - pn - 2;
						ack_info->ranges[i].ack_range = 0;
						ack_info->ack_range_count++;
						inserted = true;
						break;
					}
				}
			}
		}
	}
}

/*
 * quic_ack_on_packet_received - Record a received packet for acknowledgment
 * @conn: The QUIC connection
 * @pn: The packet number of the received packet
 * @pn_space: The packet number space (Initial, Handshake, or Application)
 *
 * This function is called for each received packet to update the ACK state.
 * Per RFC 9000 Section 13.2, endpoints MUST acknowledge all packets that
 * were received and successfully processed.
 */
void quic_ack_on_packet_received(struct quic_connection *conn, u64 pn,
				 u8 pn_space)
{
	struct quic_pn_space *space;
	struct quic_ack_info *ack_info;
	unsigned long flags;

	if (!conn || pn_space >= QUIC_PN_SPACE_MAX)
		return;

	space = &conn->pn_spaces[pn_space];
	ack_info = &space->recv_ack_info;

	spin_lock_irqsave(&space->lock, flags);

	/* Update largest received packet number */
	if (pn > space->largest_recv_pn || space->largest_recv_pn == 0) {
		space->largest_recv_pn = pn;
		space->last_ack_time = ktime_get();
	}

	/* Update the received ranges for ACK frame generation */
	quic_ack_update_recv_ranges(conn, pn_space, pn);

	/*
	 * Track ack-eliciting packet count. An ack-eliciting packet is
	 * one that contains frames other than ACK, PADDING, or CONNECTION_CLOSE.
	 * For simplicity, we treat all received packets as ack-eliciting.
	 * In a full implementation, the caller would indicate this.
	 */
	space->ack_eliciting_in_flight++;

	/*
	 * Per RFC 9000 Section 13.2.1:
	 * - Send ACK immediately if this is an Initial or Handshake packet
	 * - Send ACK after receiving at least 2 ack-eliciting packets
	 * - Send ACK after max_ack_delay timeout
	 */
	if (pn_space == QUIC_PN_SPACE_INITIAL ||
	    pn_space == QUIC_PN_SPACE_HANDSHAKE) {
		/*
		 * During handshake, send ACKs immediately to speed up
		 * connection establishment.
		 */
		quic_timer_set(conn, QUIC_TIMER_ACK, ktime_get());
	} else if (space->ack_eliciting_in_flight >= QUIC_ACK_ELICITING_THRESHOLD) {
		/* Received enough ack-eliciting packets, send ACK soon */
		quic_timer_set(conn, QUIC_TIMER_ACK, ktime_get());
	} else {
		/*
		 * Set timer for max_ack_delay to ensure timely ACK.
		 * Use local max_ack_delay parameter.
		 */
		u64 max_delay_ms = conn->local_params.max_ack_delay;
		if (max_delay_ms == 0)
			max_delay_ms = 25; /* Default 25ms per RFC 9000 */

		quic_timer_set(conn, QUIC_TIMER_ACK,
			       ktime_add_ms(ktime_get(), max_delay_ms));
	}

	spin_unlock_irqrestore(&space->lock, flags);
}

/*
 * quic_ack_on_ack_eliciting_received - Mark that ack-eliciting packet received
 * @conn: The QUIC connection
 * @pn_space: The packet number space
 *
 * Call this when a packet containing ack-eliciting frames is received.
 * This helps determine when to send immediate ACKs.
 */
void quic_ack_on_ack_eliciting_received(struct quic_connection *conn,
					u8 pn_space)
{
	struct quic_pn_space *space;

	if (!conn || pn_space >= QUIC_PN_SPACE_MAX)
		return;

	space = &conn->pn_spaces[pn_space];
	space->ack_eliciting_in_flight++;

	/*
	 * RFC 9000 13.2.1: Send ACK after at most 2 ack-eliciting packets.
	 */
	if (space->ack_eliciting_in_flight >= QUIC_ACK_ELICITING_THRESHOLD) {
		quic_timer_set(conn, QUIC_TIMER_ACK, ktime_get());
	}
}

/*
 * quic_ack_on_ecn_received - Record ECN markings from received packet
 * @conn: The QUIC connection
 * @pn_space: The packet number space
 * @ecn: The ECN marking (0 = Not-ECT, 1 = ECT(1), 2 = ECT(0), 3 = CE)
 *
 * Updates ECN counters for inclusion in ACK_ECN frames.
 */
void quic_ack_on_ecn_received(struct quic_connection *conn, u8 pn_space,
			      u8 ecn)
{
	struct quic_pn_space *space;
	struct quic_ack_info *ack_info;

	if (!conn || pn_space >= QUIC_PN_SPACE_MAX)
		return;

	space = &conn->pn_spaces[pn_space];
	ack_info = &space->recv_ack_info;

	switch (ecn) {
	case 1: /* ECT(1) */
		ack_info->ecn_ect1++;
		break;
	case 2: /* ECT(0) */
		ack_info->ecn_ect0++;
		break;
	case 3: /* CE (Congestion Experienced) */
		ack_info->ecn_ce++;
		break;
	default:
		/* Not-ECT or unknown, ignore */
		break;
	}
}

/*
 * quic_ack_should_send - Determine if an ACK should be sent
 * @conn: The QUIC connection
 * @pn_space: The packet number space
 *
 * Returns true if an ACK frame should be included in the next packet
 * for this packet number space.
 */
bool quic_ack_should_send(struct quic_connection *conn, u8 pn_space)
{
	struct quic_pn_space *space;
	struct quic_ack_info *ack_info;
	ktime_t now;
	s64 elapsed_us;
	u64 max_delay_ms;

	if (!conn || pn_space >= QUIC_PN_SPACE_MAX)
		return false;

	space = &conn->pn_spaces[pn_space];
	ack_info = &space->recv_ack_info;

	/* Nothing to acknowledge */
	if (space->largest_recv_pn == 0 && ack_info->largest_acked == 0)
		return false;

	/*
	 * Check if keys for this space are still available.
	 * Don't send ACKs for discarded packet number spaces.
	 */
	if (space->keys_discarded)
		return false;

	/*
	 * RFC 9000 Section 13.2.1: Sending ACK Frames
	 *
	 * Send ACK in these cases:
	 * 1. Received at least ack_eliciting_threshold ack-eliciting packets
	 * 2. max_ack_delay has elapsed since receiving an ack-eliciting packet
	 * 3. During handshake (Initial/Handshake spaces), send immediately
	 */

	/* Immediate ACK during handshake */
	if (pn_space == QUIC_PN_SPACE_INITIAL ||
	    pn_space == QUIC_PN_SPACE_HANDSHAKE) {
		if (space->ack_eliciting_in_flight > 0)
			return true;
	}

	/* Check threshold */
	if (space->ack_eliciting_in_flight >= QUIC_ACK_ELICITING_THRESHOLD)
		return true;

	/* Check max_ack_delay timeout */
	if (space->ack_eliciting_in_flight > 0) {
		now = ktime_get();
		elapsed_us = ktime_us_delta(now, space->last_ack_time);

		max_delay_ms = conn->local_params.max_ack_delay;
		if (max_delay_ms == 0)
			max_delay_ms = 25; /* Default */

		if (elapsed_us >= (s64)(max_delay_ms * 1000))
			return true;
	}

	return false;
}

/*
 * quic_ack_frame_length - Calculate the length of an ACK frame
 * @ack_info: The ACK information to encode
 * @include_ecn: Whether to include ECN counts
 *
 * Returns the number of bytes needed to encode the ACK frame.
 */
static int quic_ack_frame_length(struct quic_ack_info *ack_info, bool include_ecn)
{
	int len = 0;
	int i;

	/* Frame type */
	len += 1;

	/* Largest Acknowledged */
	len += quic_varint_len(ack_info->largest_acked);

	/* ACK Delay */
	len += quic_varint_len(ack_info->ack_delay);

	/* ACK Range Count */
	len += quic_varint_len(ack_info->ack_range_count > 0 ?
			       ack_info->ack_range_count - 1 : 0);

	/* First ACK Range */
	len += quic_varint_len(ack_info->ranges[0].ack_range);

	/* Additional ACK Ranges (Gap + ACK Range pairs) */
	for (i = 1; i < ack_info->ack_range_count; i++) {
		len += quic_varint_len(ack_info->ranges[i].gap);
		len += quic_varint_len(ack_info->ranges[i].ack_range);
	}

	/* ECN Counts */
	if (include_ecn) {
		len += quic_varint_len(ack_info->ecn_ect0);
		len += quic_varint_len(ack_info->ecn_ect1);
		len += quic_varint_len(ack_info->ecn_ce);
	}

	return len;
}

/*
 * quic_ack_create - Build an ACK frame into a packet
 * @conn: The QUIC connection
 * @pn_space: The packet number space for this ACK
 * @skb: The sk_buff to append the ACK frame to
 *
 * Generates an ACK frame containing the received packet numbers for
 * the specified packet number space and appends it to the sk_buff.
 *
 * Returns the number of bytes written, or negative error code.
 */
int quic_ack_create(struct quic_connection *conn, u8 pn_space,
		    struct sk_buff *skb)
{
	struct quic_pn_space *space;
	struct quic_ack_info *ack_info;
	u8 *p;
	u8 frame_type;
	int frame_len;
	bool include_ecn;
	unsigned long flags;
	int i;

	if (!conn || !skb || pn_space >= QUIC_PN_SPACE_MAX)
		return -EINVAL;

	space = &conn->pn_spaces[pn_space];
	ack_info = &space->recv_ack_info;

	spin_lock_irqsave(&space->lock, flags);

	/* Nothing to acknowledge */
	if (space->largest_recv_pn == 0 && ack_info->largest_acked == 0) {
		spin_unlock_irqrestore(&space->lock, flags);
		return 0;
	}

	/* Ensure ack_info reflects current state */
	ack_info->largest_acked = space->largest_recv_pn;

	/* Compute ACK delay */
	ack_info->ack_delay = quic_ack_compute_delay(conn, pn_space);

	/* Determine if we should include ECN counts */
	include_ecn = (ack_info->ecn_ect0 > 0 ||
		       ack_info->ecn_ect1 > 0 ||
		       ack_info->ecn_ce > 0);

	/* Calculate required space */
	frame_len = quic_ack_frame_length(ack_info, include_ecn);

	/* Check if there's room in the skb */
	if (skb_tailroom(skb) < frame_len) {
		spin_unlock_irqrestore(&space->lock, flags);
		return -ENOSPC;
	}

	/* Frame type: 0x02 for ACK, 0x03 for ACK_ECN */
	frame_type = include_ecn ? QUIC_FRAME_ACK_ECN : QUIC_FRAME_ACK;

	p = skb_put(skb, 1);
	*p = frame_type;

	/* Largest Acknowledged */
	p = skb_put(skb, quic_varint_len(ack_info->largest_acked));
	quic_varint_encode(ack_info->largest_acked, p);

	/* ACK Delay */
	p = skb_put(skb, quic_varint_len(ack_info->ack_delay));
	quic_varint_encode(ack_info->ack_delay, p);

	/*
	 * ACK Range Count: Number of Gap and ACK Range fields that follow
	 * the First ACK Range. This is one less than ack_range_count since
	 * the first range is encoded separately.
	 */
	{
		u64 range_count = ack_info->ack_range_count > 0 ?
				  ack_info->ack_range_count - 1 : 0;
		p = skb_put(skb, quic_varint_len(range_count));
		quic_varint_encode(range_count, p);
	}

	/*
	 * First ACK Range: Number of contiguous packets preceding the
	 * Largest Acknowledged that are being acknowledged. A value of
	 * 0 indicates only the largest packet is acknowledged.
	 */
	p = skb_put(skb, quic_varint_len(ack_info->ranges[0].ack_range));
	quic_varint_encode(ack_info->ranges[0].ack_range, p);

	/*
	 * Additional ACK Ranges: Each contains a Gap field and an
	 * ACK Range field.
	 *
	 * Gap: Number of contiguous unacknowledged packets preceding the
	 * packet number one lower than the smallest in the preceding range.
	 *
	 * ACK Range: Number of contiguous acknowledged packets preceding
	 * the largest packet number in this range.
	 */
	for (i = 1; i < ack_info->ack_range_count; i++) {
		/* Gap */
		p = skb_put(skb, quic_varint_len(ack_info->ranges[i].gap));
		quic_varint_encode(ack_info->ranges[i].gap, p);

		/* ACK Range */
		p = skb_put(skb, quic_varint_len(ack_info->ranges[i].ack_range));
		quic_varint_encode(ack_info->ranges[i].ack_range, p);
	}

	/* ECN Counts (if ACK_ECN frame) */
	if (include_ecn) {
		/* ECT(0) Count */
		p = skb_put(skb, quic_varint_len(ack_info->ecn_ect0));
		quic_varint_encode(ack_info->ecn_ect0, p);

		/* ECT(1) Count */
		p = skb_put(skb, quic_varint_len(ack_info->ecn_ect1));
		quic_varint_encode(ack_info->ecn_ect1, p);

		/* ECN-CE Count */
		p = skb_put(skb, quic_varint_len(ack_info->ecn_ce));
		quic_varint_encode(ack_info->ecn_ce, p);
	}

	/*
	 * Reset ack-eliciting counter since we're sending an ACK.
	 * The counter will be incremented again as new packets arrive.
	 */
	space->ack_eliciting_in_flight = 0;

	spin_unlock_irqrestore(&space->lock, flags);

	return frame_len;
}

/*
 * quic_ack_parse - Parse an ACK frame from received data
 * @conn: The QUIC connection
 * @data: Pointer to the ACK frame data
 * @len: Length of available data
 * @ack_info: Output structure for parsed ACK information
 *
 * Parses an ACK or ACK_ECN frame and populates the ack_info structure.
 *
 * Returns the number of bytes consumed, or negative error code.
 */
int quic_ack_parse(struct quic_connection *conn, const u8 *data, int len,
		   struct quic_ack_info *ack_info)
{
	int offset = 0;
	int varint_len;
	u64 ack_range_count;
	u8 frame_type;
	int i;

	if (!data || !ack_info || len < 1)
		return -EINVAL;

	memset(ack_info, 0, sizeof(*ack_info));

	/* Frame type */
	frame_type = data[offset++];
	if (frame_type != QUIC_FRAME_ACK && frame_type != QUIC_FRAME_ACK_ECN)
		return -EINVAL;

	/* Largest Acknowledged */
	varint_len = quic_varint_decode(data + offset, len - offset,
					&ack_info->largest_acked);
	if (varint_len < 0)
		return varint_len;
	offset += varint_len;

	/* ACK Delay */
	varint_len = quic_varint_decode(data + offset, len - offset,
					&ack_info->ack_delay);
	if (varint_len < 0)
		return varint_len;
	offset += varint_len;

	/* Decode ACK delay using peer's exponent */
	ack_info->ack_delay = quic_ack_decode_delay(conn, ack_info->ack_delay);

	/* ACK Range Count */
	varint_len = quic_varint_decode(data + offset, len - offset,
					&ack_range_count);
	if (varint_len < 0)
		return varint_len;
	offset += varint_len;

	/* First ACK Range */
	varint_len = quic_varint_decode(data + offset, len - offset,
					&ack_info->ranges[0].ack_range);
	if (varint_len < 0)
		return varint_len;
	offset += varint_len;

	ack_info->ack_range_count = 1;

	/* Additional ACK Ranges */
	for (i = 0; i < ack_range_count && i < QUIC_ACK_MAX_RANGES - 1; i++) {
		/* Gap */
		varint_len = quic_varint_decode(data + offset, len - offset,
						&ack_info->ranges[i + 1].gap);
		if (varint_len < 0)
			return varint_len;
		offset += varint_len;

		/* ACK Range */
		varint_len = quic_varint_decode(data + offset, len - offset,
						&ack_info->ranges[i + 1].ack_range);
		if (varint_len < 0)
			return varint_len;
		offset += varint_len;

		ack_info->ack_range_count++;
	}

	/* Skip remaining ranges if too many */
	for (; i < ack_range_count; i++) {
		u64 dummy;

		varint_len = quic_varint_decode(data + offset, len - offset, &dummy);
		if (varint_len < 0)
			return varint_len;
		offset += varint_len;

		varint_len = quic_varint_decode(data + offset, len - offset, &dummy);
		if (varint_len < 0)
			return varint_len;
		offset += varint_len;
	}

	/* ECN Counts (if ACK_ECN frame) */
	if (frame_type == QUIC_FRAME_ACK_ECN) {
		/* ECT(0) Count */
		varint_len = quic_varint_decode(data + offset, len - offset,
						&ack_info->ecn_ect0);
		if (varint_len < 0)
			return varint_len;
		offset += varint_len;

		/* ECT(1) Count */
		varint_len = quic_varint_decode(data + offset, len - offset,
						&ack_info->ecn_ect1);
		if (varint_len < 0)
			return varint_len;
		offset += varint_len;

		/* ECN-CE Count */
		varint_len = quic_varint_decode(data + offset, len - offset,
						&ack_info->ecn_ce);
		if (varint_len < 0)
			return varint_len;
		offset += varint_len;
	}

	return offset;
}

/*
 * quic_ack_ranges_contain - Check if a packet number is acknowledged
 * @ack_info: The ACK information
 * @pn: The packet number to check
 *
 * Returns true if the packet number is within the acknowledged ranges.
 */
bool quic_ack_ranges_contain(const struct quic_ack_info *ack_info, u64 pn)
{
	u64 largest = ack_info->largest_acked;
	u64 smallest;
	int i;

	if (!ack_info || ack_info->ack_range_count == 0)
		return false;

	/* Check first range */
	smallest = largest - ack_info->ranges[0].ack_range;
	if (pn >= smallest && pn <= largest)
		return true;

	/* Check additional ranges */
	for (i = 1; i < ack_info->ack_range_count; i++) {
		/* Calculate next range bounds */
		largest = smallest - ack_info->ranges[i].gap - 2;
		smallest = largest - ack_info->ranges[i].ack_range;

		if (pn >= smallest && pn <= largest)
			return true;
	}

	return false;
}

/*
 * quic_ack_get_smallest_acked - Get smallest acknowledged packet number
 * @ack_info: The ACK information
 *
 * Returns the smallest packet number in the acknowledged ranges.
 */
u64 quic_ack_get_smallest_acked(const struct quic_ack_info *ack_info)
{
	u64 largest = ack_info->largest_acked;
	u64 smallest;
	int i;

	if (!ack_info || ack_info->ack_range_count == 0)
		return 0;

	/* Start with first range */
	smallest = largest - ack_info->ranges[0].ack_range;

	/* Traverse to last range */
	for (i = 1; i < ack_info->ack_range_count; i++) {
		largest = smallest - ack_info->ranges[i].gap - 2;
		smallest = largest - ack_info->ranges[i].ack_range;
	}

	return smallest;
}

/*
 * quic_ack_reset - Reset ACK state for a packet number space
 * @conn: The QUIC connection
 * @pn_space: The packet number space
 *
 * Clears all ACK tracking state. Used when discarding packet number spaces.
 */
void quic_ack_reset(struct quic_connection *conn, u8 pn_space)
{
	struct quic_pn_space *space;
	struct quic_ack_info *ack_info;
	unsigned long flags;

	if (!conn || pn_space >= QUIC_PN_SPACE_MAX)
		return;

	space = &conn->pn_spaces[pn_space];
	ack_info = &space->recv_ack_info;

	spin_lock_irqsave(&space->lock, flags);

	memset(ack_info, 0, sizeof(*ack_info));
	space->largest_recv_pn = 0;
	space->last_ack_time = 0;
	space->ack_eliciting_in_flight = 0;

	spin_unlock_irqrestore(&space->lock, flags);
}

/*
 * quic_ack_space_init - Initialize ACK state for a packet number space
 * @conn: The QUIC connection
 * @pn_space: The packet number space
 *
 * Initializes ACK tracking structures for the specified space.
 */
void quic_ack_space_init(struct quic_connection *conn, u8 pn_space)
{
	struct quic_pn_space *space;
	struct quic_ack_info *ack_info;

	if (!conn || pn_space >= QUIC_PN_SPACE_MAX)
		return;

	space = &conn->pn_spaces[pn_space];
	ack_info = &space->recv_ack_info;

	memset(ack_info, 0, sizeof(*ack_info));
}

/*
 * quic_ack_init - Initialize global ACK handling infrastructure
 *
 * Called during module initialization. Currently this function is a
 * placeholder as all ACK state is maintained per-connection in the
 * quic_pn_space structure.
 *
 * Returns 0 on success, negative error code on failure.
 */
int __init quic_ack_init(void)
{
	return 0;
}

/*
 * quic_ack_exit - Clean up global ACK handling infrastructure
 *
 * Called during module unload. Currently this function is a placeholder.
 */
void __exit quic_ack_exit(void)
{
}
