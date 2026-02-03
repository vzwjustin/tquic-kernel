// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * TQUIC - True QUIC with WAN Bonding
 *
 * ACK frame generation and received packet tracking
 *
 * Implementation follows RFC 9000 Section 13.2 for generating acknowledgments.
 *
 * Copyright (c) 2024-2026 Linux TQUIC Authors
 */

#include <linux/slab.h>
#include <linux/skbuff.h>
#include <linux/list.h>
#include <linux/bitmap.h>
#include <linux/ktime.h>
#include <net/tquic.h>
#include <net/tquic_frame.h>
#include "ack_frequency.h"

/*
 * Maximum number of ACK ranges to track per packet number space.
 * This limits memory usage while still allowing for reasonable
 * out-of-order packet tracking.
 */
#define TQUIC_ACK_MAX_RANGES		256

/*
 * Maximum number of ack-eliciting packets to receive before
 * sending an ACK. RFC 9000 recommends sending an ACK after
 * receiving at least 2 ack-eliciting packets.
 */
#define TQUIC_ACK_ELICITING_THRESHOLD	2

/*
 * Maximum delay before sending an ACK (in microseconds).
 * This is based on the default max_ack_delay of 25ms from RFC 9000.
 */
#define TQUIC_MAX_ACK_DELAY_US		25000

/*
 * Default ack_delay_exponent per RFC 9000 Section 18.2.
 * The exponent used to decode the ACK Delay field is 3.
 */
#define TQUIC_DEFAULT_ACK_DELAY_EXP	3

/*
 * Note: The current implementation uses the embedded tquic_ack_info structure
 * from the tquic_pn_space for ACK state tracking. The ranges[] array in that
 * structure provides sufficient capacity for most use cases. For connections
 * with extreme packet reordering, a more sophisticated interval tree or
 * linked-list based approach could be implemented in the future.
 */

/*
 * tquic_ack_info - ACK info for received packets (local definition)
 *
 * This structure mirrors the format used for tracking ACK ranges.
 * It is compatible with the tquic_frame_ack structure for encoding.
 */
struct tquic_ack_info {
	u64			largest_acked;
	u64			ack_delay;
	u64			ecn_ce;
	u64			ecn_ect0;
	u64			ecn_ect1;
	u32			ack_range_count;
	struct tquic_ack_range	ranges[TQUIC_ACK_MAX_RANGES];
};

/*
 * tquic_pn_space - Packet number space (local definition for ACK tracking)
 *
 * This structure mirrors the fields needed for ACK tracking.
 */
struct tquic_local_pn_space {
	spinlock_t		lock;
	u64			next_pn;
	u64			largest_acked_pn;
	u64			largest_recv_pn;
	u64			loss_time;
	ktime_t			last_ack_time;
	u32			ack_eliciting_in_flight;
	struct list_head	sent_packets;
	struct list_head	lost_packets;
	struct tquic_ack_info	recv_ack_info;
	u8			keys_available:1;
	u8			keys_discarded:1;
};

/*
 * Transport parameters structure (local definition)
 */
struct tquic_transport_params {
	u64 max_ack_delay;
	u32 ack_delay_exponent;
};

/*
 * Extended connection structure for ACK processing (local definition)
 *
 * This provides the fields needed by the ACK module.
 * The actual tquic_connection structure is defined in tquic.h.
 */
struct tquic_ack_conn_ctx {
	struct tquic_local_pn_space pn_spaces[TQUIC_PN_SPACE_COUNT];
	struct tquic_transport_params local_params;
	struct tquic_transport_params remote_params;
	u64 ack_freq_threshold;
	u64 ack_freq_reorder_threshold;
	u64 ack_freq_max_delay_us;
	u8 immediate_ack_pending;
};

/*
 * Helper to get ACK context from connection (cast helper)
 */
static inline struct tquic_ack_conn_ctx *tquic_ack_ctx(struct tquic_connection *conn)
{
	/*
	 * The ACK module operates on extended connection state.
	 * This cast assumes the connection has compatible layout.
	 * In production, this would access conn->timer_state or similar.
	 */
	return (struct tquic_ack_conn_ctx *)conn;
}

/*
 * Timer set function (forward declaration - implemented in tquic_timer.c)
 */
void tquic_timer_set_ack_delay(struct tquic_timer_state *ts);

/*
 * tquic_ack_compute_delay - Compute the ACK delay value for encoding
 * @conn: The TQUIC connection
 * @pn_space: The packet number space
 *
 * Computes the ACK delay as the time since receiving the largest
 * acknowledged packet, scaled by the ack_delay_exponent.
 *
 * Returns the encoded ACK delay value.
 */
static u64 tquic_ack_compute_delay(struct tquic_connection *conn, u8 pn_space)
{
	struct tquic_ack_conn_ctx *ctx = tquic_ack_ctx(conn);
	struct tquic_local_pn_space *space = &ctx->pn_spaces[pn_space];
	ktime_t now = ktime_get();
	ktime_t recv_time = space->last_ack_time;
	s64 delay_us;
	u64 delay_encoded;
	u32 ack_delay_exponent;

	/* Use remote's ack_delay_exponent, default to 3 */
	ack_delay_exponent = ctx->remote_params.ack_delay_exponent;
	if (ack_delay_exponent == 0)
		ack_delay_exponent = TQUIC_DEFAULT_ACK_DELAY_EXP;

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
	if (ctx->local_params.max_ack_delay > 0) {
		u64 max_delay = ctx->local_params.max_ack_delay * 1000;
		max_delay >>= ack_delay_exponent;
		if (delay_encoded > max_delay)
			delay_encoded = max_delay;
	}

	return delay_encoded;
}

/*
 * tquic_ack_decode_delay - Decode an ACK delay value from a received ACK
 * @conn: The TQUIC connection
 * @encoded_delay: The encoded ACK delay from the frame
 *
 * Returns the ACK delay in microseconds.
 */
u64 tquic_ack_decode_delay(struct tquic_connection *conn, u64 encoded_delay)
{
	struct tquic_ack_conn_ctx *ctx = tquic_ack_ctx(conn);
	u32 ack_delay_exponent;

	/* Use peer's ack_delay_exponent */
	ack_delay_exponent = ctx->remote_params.ack_delay_exponent;
	if (ack_delay_exponent == 0)
		ack_delay_exponent = TQUIC_DEFAULT_ACK_DELAY_EXP;

	return encoded_delay << ack_delay_exponent;
}

/*
 * tquic_ack_update_recv_ranges - Update received ranges with a new packet number
 * @conn: The TQUIC connection
 * @pn_space: The packet number space
 * @pn: The received packet number
 *
 * Maintains a list of contiguous ranges of received packet numbers.
 * Adjacent ranges are merged when possible to minimize range count.
 */
static void tquic_ack_update_recv_ranges(struct tquic_connection *conn,
					 u8 pn_space, u64 pn)
{
	struct tquic_ack_conn_ctx *ctx = tquic_ack_ctx(conn);
	struct tquic_local_pn_space *space = &ctx->pn_spaces[pn_space];
	struct tquic_ack_info *ack_info = &space->recv_ack_info;
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
					ack_info->ranges[0].ack_range_len;
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
			u64 old_first_range = ack_info->ranges[0].ack_range_len;
			u64 old_smallest = old_largest - old_first_range;

			if (pn == old_largest + 1) {
				/*
				 * Contiguous with previous largest.
				 * Just extend the first range.
				 */
				ack_info->largest_acked = pn;
				ack_info->ranges[0].ack_range_len = pn - old_smallest;
				inserted = true;
			} else {
				/*
				 * Gap between new packet and old largest.
				 * Need to shift ranges and create new first range.
				 */
				u64 gap = pn - old_largest - 2;

				/* Shift existing ranges */
				if (ack_info->ack_range_count < TQUIC_ACK_MAX_RANGES) {
					for (j = ack_info->ack_range_count; j >= 1; j--) {
						ack_info->ranges[j].gap =
							ack_info->ranges[j - 1].gap;
						ack_info->ranges[j].ack_range_len =
							ack_info->ranges[j - 1].ack_range_len;
					}
					/* First gap is distance to old range */
					ack_info->ranges[1].gap = gap;
					ack_info->ranges[1].ack_range_len = old_first_range;
					ack_info->ack_range_count++;
				}

				ack_info->largest_acked = pn;
				ack_info->ranges[0].ack_range_len = 0; /* Single packet */
				inserted = true;
			}
		} else {
			/* First packet received in this space */
			ack_info->largest_acked = pn;
			ack_info->ranges[0].ack_range_len = 0;
			ack_info->ack_range_count = 1;
			inserted = true;
		}
	} else {
		/*
		 * Packet number is less than largest_acked.
		 * Need to find appropriate range to extend or create new range.
		 */
		u64 current_largest = ack_info->largest_acked;
		u64 current_smallest = current_largest - ack_info->ranges[0].ack_range_len;

		/* Check if extends first range downward */
		if (pn == current_smallest - 1) {
			ack_info->ranges[0].ack_range_len++;
			inserted = true;
		} else if (pn < current_smallest - 1) {
			/*
			 * Need to check additional ranges or create new range.
			 * For simplicity, scan through existing ranges.
			 */
			u64 prev_end = current_smallest;

			for (i = 1; i < ack_info->ack_range_count && i < TQUIC_ACK_MAX_RANGES; i++) {
				u64 gap = ack_info->ranges[i].gap;
				u64 range_size = ack_info->ranges[i].ack_range_len;
				u64 range_end = prev_end - gap - 2;
				u64 range_start = range_end - range_size;

				if (pn >= range_start && pn <= range_end) {
					/* Already in this range */
					inserted = true;
					break;
				}

				if (pn == range_end + 1) {
					/* Extends range upward - may merge with previous */
					ack_info->ranges[i].ack_range_len++;

					/* Check if merges with previous range */
					if (i == 1 && gap == 0) {
						/* Merge into first range */
						ack_info->ranges[0].ack_range_len += range_size + 2;
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
					ack_info->ranges[i].ack_range_len++;
					inserted = true;
					break;
				}

				prev_end = range_start;
			}

			/*
			 * If not inserted into existing range, need to create new one.
			 * Find the right position and insert.
			 */
			if (!inserted && ack_info->ack_range_count < TQUIC_ACK_MAX_RANGES) {
				/* Insert new single-packet range in proper position */
				prev_end = current_smallest;

				for (i = 1; i <= ack_info->ack_range_count; i++) {
					u64 next_range_start;

					if (i < ack_info->ack_range_count) {
						u64 gap = ack_info->ranges[i].gap;
						u64 range_size = ack_info->ranges[i].ack_range_len;
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
							ack_info->ranges[i].ack_range_len = 0;

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
						ack_info->ranges[i].ack_range_len = 0;
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
 * tquic_ack_on_packet_received - Record a received packet for acknowledgment
 * @conn: The TQUIC connection
 * @pn: The packet number of the received packet
 * @pn_space: The packet number space (Initial, Handshake, or Application)
 *
 * This function is called for each received packet to update the ACK state.
 * Per RFC 9000 Section 13.2, endpoints MUST acknowledge all packets that
 * were received and successfully processed.
 */
void tquic_ack_on_packet_received(struct tquic_connection *conn, u64 pn,
				  u8 pn_space)
{
	struct tquic_ack_conn_ctx *ctx;
	struct tquic_local_pn_space *space;
	struct tquic_ack_info *ack_info;
	unsigned long flags;

	if (!conn || pn_space >= TQUIC_PN_SPACE_COUNT)
		return;

	ctx = tquic_ack_ctx(conn);
	space = &ctx->pn_spaces[pn_space];
	ack_info = &space->recv_ack_info;

	spin_lock_irqsave(&space->lock, flags);

	/* Update largest received packet number */
	if (pn > space->largest_recv_pn || space->largest_recv_pn == 0) {
		space->largest_recv_pn = pn;
		space->last_ack_time = ktime_get();
	}

	/* Update the received ranges for ACK frame generation */
	tquic_ack_update_recv_ranges(conn, pn_space, pn);

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
	if (pn_space == TQUIC_PN_SPACE_INITIAL ||
	    pn_space == TQUIC_PN_SPACE_HANDSHAKE) {
		/*
		 * During handshake, send ACKs immediately to speed up
		 * connection establishment.
		 */
		if (conn->timer_state)
			tquic_timer_set_ack_delay(conn->timer_state);
	} else if (space->ack_eliciting_in_flight >= TQUIC_ACK_ELICITING_THRESHOLD) {
		/* Received enough ack-eliciting packets, send ACK soon */
		if (conn->timer_state)
			tquic_timer_set_ack_delay(conn->timer_state);
	} else {
		/*
		 * Set timer for max_ack_delay to ensure timely ACK.
		 * Use local max_ack_delay parameter.
		 */
		if (conn->timer_state)
			tquic_timer_set_ack_delay(conn->timer_state);
	}

	spin_unlock_irqrestore(&space->lock, flags);
}

/*
 * tquic_ack_on_ack_eliciting_received - Mark that ack-eliciting packet received
 * @conn: The TQUIC connection
 * @pn_space: The packet number space
 *
 * Call this when a packet containing ack-eliciting frames is received.
 * This helps determine when to send immediate ACKs.
 */
void tquic_ack_on_ack_eliciting_received(struct tquic_connection *conn,
					 u8 pn_space)
{
	struct tquic_ack_conn_ctx *ctx;
	struct tquic_local_pn_space *space;

	if (!conn || pn_space >= TQUIC_PN_SPACE_COUNT)
		return;

	ctx = tquic_ack_ctx(conn);
	space = &ctx->pn_spaces[pn_space];
	space->ack_eliciting_in_flight++;

	/*
	 * RFC 9000 13.2.1: Send ACK after at most 2 ack-eliciting packets.
	 */
	if (space->ack_eliciting_in_flight >= TQUIC_ACK_ELICITING_THRESHOLD) {
		if (conn->timer_state)
			tquic_timer_set_ack_delay(conn->timer_state);
	}
}

/*
 * tquic_ack_on_ecn_received - Record ECN markings from received packet
 * @conn: The TQUIC connection
 * @pn_space: The packet number space
 * @ecn: The ECN marking (0 = Not-ECT, 1 = ECT(1), 2 = ECT(0), 3 = CE)
 *
 * Updates ECN counters for inclusion in ACK_ECN frames.
 */
void tquic_ack_on_ecn_received(struct tquic_connection *conn, u8 pn_space,
			       u8 ecn)
{
	struct tquic_ack_conn_ctx *ctx;
	struct tquic_local_pn_space *space;
	struct tquic_ack_info *ack_info;

	if (!conn || pn_space >= TQUIC_PN_SPACE_COUNT)
		return;

	ctx = tquic_ack_ctx(conn);
	space = &ctx->pn_spaces[pn_space];
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
 * tquic_ack_should_send - Determine if an ACK should be sent
 * @conn: The TQUIC connection
 * @pn_space: The packet number space
 *
 * Returns true if an ACK frame should be included in the next packet
 * for this packet number space.
 *
 * This function supports the ACK_FREQUENCY extension (draft-ietf-quic-ack-frequency)
 * when enabled, using peer-specified thresholds and delays.
 */
bool tquic_ack_should_send(struct tquic_connection *conn, u8 pn_space)
{
	struct tquic_ack_conn_ctx *ctx;
	struct tquic_local_pn_space *space;
	struct tquic_ack_info *ack_info;
	ktime_t now;
	s64 elapsed_us;
	u64 max_delay_us;
	u64 ack_threshold;

	if (!conn || pn_space >= TQUIC_PN_SPACE_COUNT)
		return false;

	ctx = tquic_ack_ctx(conn);
	space = &ctx->pn_spaces[pn_space];
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
	 * Check for IMMEDIATE_ACK flag (draft-ietf-quic-ack-frequency)
	 */
	if (ctx->immediate_ack_pending) {
		ctx->immediate_ack_pending = 0;
		return true;
	}

	/*
	 * RFC 9000 Section 13.2.1: Sending ACK Frames
	 *
	 * Send ACK in these cases:
	 * 1. Received at least ack_eliciting_threshold ack-eliciting packets
	 * 2. max_ack_delay has elapsed since receiving an ack-eliciting packet
	 * 3. During handshake (Initial/Handshake spaces), send immediately
	 *
	 * When ACK_FREQUENCY extension is in use, the threshold and delay
	 * values are taken from the peer's ACK_FREQUENCY frame parameters.
	 */

	/* Immediate ACK during handshake */
	if (pn_space == TQUIC_PN_SPACE_INITIAL ||
	    pn_space == TQUIC_PN_SPACE_HANDSHAKE) {
		if (space->ack_eliciting_in_flight > 0)
			return true;
	}

	/*
	 * Get ACK threshold from ACK_FREQUENCY or use default.
	 * Per draft-ietf-quic-ack-frequency, threshold of 1 means
	 * ACK after receiving 2 ack-eliciting packets (count > threshold).
	 */
	ack_threshold = ctx->ack_freq_threshold;
	if (ack_threshold == 0)
		ack_threshold = TQUIC_ACK_FREQ_DEFAULT_THRESHOLD;

	/* Check threshold */
	if (space->ack_eliciting_in_flight > ack_threshold)
		return true;

	/*
	 * Check reordering threshold (draft-ietf-quic-ack-frequency)
	 * If packets arrive out-of-order beyond the threshold, ACK immediately.
	 */
	if (ctx->ack_freq_reorder_threshold > 0) {
		/*
		 * This would require tracking the last ACKed packet number.
		 * For now, we rely on the threshold and delay checks.
		 */
	}

	/* Check max_ack_delay timeout */
	if (space->ack_eliciting_in_flight > 0) {
		now = ktime_get();
		elapsed_us = ktime_us_delta(now, space->last_ack_time);

		/*
		 * Use ACK_FREQUENCY max_ack_delay if set, otherwise use
		 * transport parameter (converted from ms to us).
		 */
		max_delay_us = ctx->ack_freq_max_delay_us;
		if (max_delay_us == 0) {
			u64 max_delay_ms = ctx->local_params.max_ack_delay;
			if (max_delay_ms == 0)
				max_delay_ms = 25; /* Default 25ms per RFC 9000 */
			max_delay_us = max_delay_ms * 1000;
		}

		if (elapsed_us >= (s64)max_delay_us)
			return true;
	}

	return false;
}

/*
 * tquic_ack_frame_length - Calculate the length of an ACK frame
 * @ack_info: The ACK information to encode
 * @include_ecn: Whether to include ECN counts
 *
 * Returns the number of bytes needed to encode the ACK frame.
 */
static int tquic_ack_frame_length(struct tquic_ack_info *ack_info, bool include_ecn)
{
	int len = 0;
	int i;

	/* Frame type */
	len += 1;

	/* Largest Acknowledged */
	len += tquic_varint_len(ack_info->largest_acked);

	/* ACK Delay */
	len += tquic_varint_len(ack_info->ack_delay);

	/* ACK Range Count */
	len += tquic_varint_len(ack_info->ack_range_count > 0 ?
			        ack_info->ack_range_count - 1 : 0);

	/* First ACK Range */
	len += tquic_varint_len(ack_info->ranges[0].ack_range_len);

	/* Additional ACK Ranges (Gap + ACK Range pairs) */
	for (i = 1; i < ack_info->ack_range_count; i++) {
		len += tquic_varint_len(ack_info->ranges[i].gap);
		len += tquic_varint_len(ack_info->ranges[i].ack_range_len);
	}

	/* ECN Counts */
	if (include_ecn) {
		len += tquic_varint_len(ack_info->ecn_ect0);
		len += tquic_varint_len(ack_info->ecn_ect1);
		len += tquic_varint_len(ack_info->ecn_ce);
	}

	return len;
}

/*
 * tquic_ack_create - Build an ACK frame into a packet
 * @conn: The TQUIC connection
 * @pn_space: The packet number space for this ACK
 * @skb: The sk_buff to append the ACK frame to
 *
 * Generates an ACK frame containing the received packet numbers for
 * the specified packet number space and appends it to the sk_buff.
 *
 * Returns the number of bytes written, or negative error code.
 */
int tquic_ack_create(struct tquic_connection *conn, u8 pn_space,
		     struct sk_buff *skb)
{
	struct tquic_ack_conn_ctx *ctx;
	struct tquic_local_pn_space *space;
	struct tquic_ack_info *ack_info;
	u8 *p;
	u8 frame_type;
	int frame_len;
	bool include_ecn;
	unsigned long flags;
	int i;

	if (!conn || !skb || pn_space >= TQUIC_PN_SPACE_COUNT)
		return -EINVAL;

	ctx = tquic_ack_ctx(conn);
	space = &ctx->pn_spaces[pn_space];
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
	ack_info->ack_delay = tquic_ack_compute_delay(conn, pn_space);

	/* Determine if we should include ECN counts */
	include_ecn = (ack_info->ecn_ect0 > 0 ||
		       ack_info->ecn_ect1 > 0 ||
		       ack_info->ecn_ce > 0);

	/* Calculate required space */
	frame_len = tquic_ack_frame_length(ack_info, include_ecn);

	/* Check if there's room in the skb */
	if (skb_tailroom(skb) < frame_len) {
		spin_unlock_irqrestore(&space->lock, flags);
		return -ENOSPC;
	}

	/* Frame type: 0x02 for ACK, 0x03 for ACK_ECN */
	frame_type = include_ecn ? TQUIC_FRAME_ACK_ECN : TQUIC_FRAME_ACK;

	p = skb_put(skb, 1);
	*p = frame_type;

	/* Largest Acknowledged */
	p = skb_put(skb, tquic_varint_len(ack_info->largest_acked));
	tquic_varint_encode(ack_info->largest_acked, p, tquic_varint_len(ack_info->largest_acked));

	/* ACK Delay */
	p = skb_put(skb, tquic_varint_len(ack_info->ack_delay));
	tquic_varint_encode(ack_info->ack_delay, p, tquic_varint_len(ack_info->ack_delay));

	/*
	 * ACK Range Count: Number of Gap and ACK Range fields that follow
	 * the First ACK Range. This is one less than ack_range_count since
	 * the first range is encoded separately.
	 */
	{
		u64 range_count = ack_info->ack_range_count > 0 ?
				  ack_info->ack_range_count - 1 : 0;
		p = skb_put(skb, tquic_varint_len(range_count));
		tquic_varint_encode(range_count, p, tquic_varint_len(range_count));
	}

	/*
	 * First ACK Range: Number of contiguous packets preceding the
	 * Largest Acknowledged that are being acknowledged. A value of
	 * 0 indicates only the largest packet is acknowledged.
	 */
	p = skb_put(skb, tquic_varint_len(ack_info->ranges[0].ack_range_len));
	tquic_varint_encode(ack_info->ranges[0].ack_range_len, p,
			    tquic_varint_len(ack_info->ranges[0].ack_range_len));

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
		p = skb_put(skb, tquic_varint_len(ack_info->ranges[i].gap));
		tquic_varint_encode(ack_info->ranges[i].gap, p,
				    tquic_varint_len(ack_info->ranges[i].gap));

		/* ACK Range */
		p = skb_put(skb, tquic_varint_len(ack_info->ranges[i].ack_range_len));
		tquic_varint_encode(ack_info->ranges[i].ack_range_len, p,
				    tquic_varint_len(ack_info->ranges[i].ack_range_len));
	}

	/* ECN Counts (if ACK_ECN frame) */
	if (include_ecn) {
		/* ECT(0) Count */
		p = skb_put(skb, tquic_varint_len(ack_info->ecn_ect0));
		tquic_varint_encode(ack_info->ecn_ect0, p, tquic_varint_len(ack_info->ecn_ect0));

		/* ECT(1) Count */
		p = skb_put(skb, tquic_varint_len(ack_info->ecn_ect1));
		tquic_varint_encode(ack_info->ecn_ect1, p, tquic_varint_len(ack_info->ecn_ect1));

		/* ECN-CE Count */
		p = skb_put(skb, tquic_varint_len(ack_info->ecn_ce));
		tquic_varint_encode(ack_info->ecn_ce, p, tquic_varint_len(ack_info->ecn_ce));
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
 * tquic_ack_parse - Parse an ACK frame from received data
 * @conn: The TQUIC connection
 * @data: Pointer to the ACK frame data
 * @len: Length of available data
 * @ack_info: Output structure for parsed ACK information
 *
 * Parses an ACK or ACK_ECN frame and populates the ack_info structure.
 *
 * Returns the number of bytes consumed, or negative error code.
 */
int tquic_ack_parse(struct tquic_connection *conn, const u8 *data, int len,
		    struct tquic_ack_info *ack_info)
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
	if (frame_type != TQUIC_FRAME_ACK && frame_type != TQUIC_FRAME_ACK_ECN)
		return -EINVAL;

	/* Largest Acknowledged */
	varint_len = tquic_varint_decode(data + offset, len - offset,
					 &ack_info->largest_acked);
	if (varint_len < 0)
		return varint_len;
	offset += varint_len;

	/* ACK Delay */
	varint_len = tquic_varint_decode(data + offset, len - offset,
					 &ack_info->ack_delay);
	if (varint_len < 0)
		return varint_len;
	offset += varint_len;

	/* Decode ACK delay using peer's exponent */
	ack_info->ack_delay = tquic_ack_decode_delay(conn, ack_info->ack_delay);

	/* ACK Range Count */
	varint_len = tquic_varint_decode(data + offset, len - offset,
					 &ack_range_count);
	if (varint_len < 0)
		return varint_len;
	offset += varint_len;

	/* First ACK Range */
	varint_len = tquic_varint_decode(data + offset, len - offset,
					 &ack_info->ranges[0].ack_range_len);
	if (varint_len < 0)
		return varint_len;
	offset += varint_len;

	ack_info->ack_range_count = 1;

	/* Additional ACK Ranges */
	for (i = 0; i < ack_range_count && i < TQUIC_ACK_MAX_RANGES - 1; i++) {
		/* Gap */
		varint_len = tquic_varint_decode(data + offset, len - offset,
						 &ack_info->ranges[i + 1].gap);
		if (varint_len < 0)
			return varint_len;
		offset += varint_len;

		/* ACK Range */
		varint_len = tquic_varint_decode(data + offset, len - offset,
						 &ack_info->ranges[i + 1].ack_range_len);
		if (varint_len < 0)
			return varint_len;
		offset += varint_len;

		ack_info->ack_range_count++;
	}

	/* Skip remaining ranges if too many */
	for (; i < ack_range_count; i++) {
		u64 dummy;

		varint_len = tquic_varint_decode(data + offset, len - offset, &dummy);
		if (varint_len < 0)
			return varint_len;
		offset += varint_len;

		varint_len = tquic_varint_decode(data + offset, len - offset, &dummy);
		if (varint_len < 0)
			return varint_len;
		offset += varint_len;
	}

	/* ECN Counts (if ACK_ECN frame) */
	if (frame_type == TQUIC_FRAME_ACK_ECN) {
		/* ECT(0) Count */
		varint_len = tquic_varint_decode(data + offset, len - offset,
						 &ack_info->ecn_ect0);
		if (varint_len < 0)
			return varint_len;
		offset += varint_len;

		/* ECT(1) Count */
		varint_len = tquic_varint_decode(data + offset, len - offset,
						 &ack_info->ecn_ect1);
		if (varint_len < 0)
			return varint_len;
		offset += varint_len;

		/* ECN-CE Count */
		varint_len = tquic_varint_decode(data + offset, len - offset,
						 &ack_info->ecn_ce);
		if (varint_len < 0)
			return varint_len;
		offset += varint_len;
	}

	return offset;
}

/*
 * tquic_ack_ranges_contain - Check if a packet number is acknowledged
 * @ack_info: The ACK information
 * @pn: The packet number to check
 *
 * Returns true if the packet number is within the acknowledged ranges.
 */
bool tquic_ack_ranges_contain(const struct tquic_ack_info *ack_info, u64 pn)
{
	u64 largest = ack_info->largest_acked;
	u64 smallest;
	int i;

	if (!ack_info || ack_info->ack_range_count == 0)
		return false;

	/* Check first range */
	smallest = largest - ack_info->ranges[0].ack_range_len;
	if (pn >= smallest && pn <= largest)
		return true;

	/* Check additional ranges */
	for (i = 1; i < ack_info->ack_range_count; i++) {
		/* Calculate next range bounds */
		largest = smallest - ack_info->ranges[i].gap - 2;
		smallest = largest - ack_info->ranges[i].ack_range_len;

		if (pn >= smallest && pn <= largest)
			return true;
	}

	return false;
}

/*
 * tquic_ack_get_smallest_acked - Get smallest acknowledged packet number
 * @ack_info: The ACK information
 *
 * Returns the smallest packet number in the acknowledged ranges.
 */
u64 tquic_ack_get_smallest_acked(const struct tquic_ack_info *ack_info)
{
	u64 largest = ack_info->largest_acked;
	u64 smallest;
	int i;

	if (!ack_info || ack_info->ack_range_count == 0)
		return 0;

	/* Start with first range */
	smallest = largest - ack_info->ranges[0].ack_range_len;

	/* Traverse to last range */
	for (i = 1; i < ack_info->ack_range_count; i++) {
		largest = smallest - ack_info->ranges[i].gap - 2;
		smallest = largest - ack_info->ranges[i].ack_range_len;
	}

	return smallest;
}

/*
 * tquic_ack_reset - Reset ACK state for a packet number space
 * @conn: The TQUIC connection
 * @pn_space: The packet number space
 *
 * Clears all ACK tracking state. Used when discarding packet number spaces.
 */
void tquic_ack_reset(struct tquic_connection *conn, u8 pn_space)
{
	struct tquic_ack_conn_ctx *ctx;
	struct tquic_local_pn_space *space;
	struct tquic_ack_info *ack_info;
	unsigned long flags;

	if (!conn || pn_space >= TQUIC_PN_SPACE_COUNT)
		return;

	ctx = tquic_ack_ctx(conn);
	space = &ctx->pn_spaces[pn_space];
	ack_info = &space->recv_ack_info;

	spin_lock_irqsave(&space->lock, flags);

	memset(ack_info, 0, sizeof(*ack_info));
	space->largest_recv_pn = 0;
	space->last_ack_time = 0;
	space->ack_eliciting_in_flight = 0;

	spin_unlock_irqrestore(&space->lock, flags);
}

/*
 * tquic_ack_space_init - Initialize ACK state for a packet number space
 * @conn: The TQUIC connection
 * @pn_space: The packet number space
 *
 * Initializes ACK tracking structures for the specified space.
 */
void tquic_ack_space_init(struct tquic_connection *conn, u8 pn_space)
{
	struct tquic_ack_conn_ctx *ctx;
	struct tquic_local_pn_space *space;
	struct tquic_ack_info *ack_info;

	if (!conn || pn_space >= TQUIC_PN_SPACE_COUNT)
		return;

	ctx = tquic_ack_ctx(conn);
	space = &ctx->pn_spaces[pn_space];
	ack_info = &space->recv_ack_info;

	memset(ack_info, 0, sizeof(*ack_info));
}

/*
 * Global ACK statistics for debugging and monitoring.
 * All per-connection ACK state is maintained in tquic_pn_space.
 */
static struct {
	atomic64_t acks_sent;		/* Total ACK frames sent */
	atomic64_t acks_received;	/* Total ACK frames processed */
	atomic64_t ack_ranges_sent;	/* Total ACK ranges transmitted */
	atomic64_t delayed_acks;	/* ACKs delayed by timer */
	atomic64_t immediate_acks;	/* ACKs sent immediately */
} tquic_ack_stats;

/*
 * tquic_ack_init - Initialize global ACK handling infrastructure
 *
 * Called during module initialization. Initializes global ACK
 * statistics counters. Per-connection ACK state is maintained
 * in the tquic_pn_space structure and initialized when connections
 * are created.
 *
 * Returns 0 on success, negative error code on failure.
 */
int __init tquic_ack_init(void)
{
	/* Initialize global statistics counters */
	atomic64_set(&tquic_ack_stats.acks_sent, 0);
	atomic64_set(&tquic_ack_stats.acks_received, 0);
	atomic64_set(&tquic_ack_stats.ack_ranges_sent, 0);
	atomic64_set(&tquic_ack_stats.delayed_acks, 0);
	atomic64_set(&tquic_ack_stats.immediate_acks, 0);

	pr_debug("TQUIC ACK subsystem initialized\n");
	return 0;
}

/*
 * tquic_ack_exit - Clean up global ACK handling infrastructure
 *
 * Called during module unload. Logs final ACK statistics for
 * debugging purposes.
 */
void __exit tquic_ack_exit(void)
{
	pr_debug("TQUIC ACK stats: sent=%lld received=%lld ranges=%lld delayed=%lld immediate=%lld\n",
		 atomic64_read(&tquic_ack_stats.acks_sent),
		 atomic64_read(&tquic_ack_stats.acks_received),
		 atomic64_read(&tquic_ack_stats.ack_ranges_sent),
		 atomic64_read(&tquic_ack_stats.delayed_acks),
		 atomic64_read(&tquic_ack_stats.immediate_acks));
}
