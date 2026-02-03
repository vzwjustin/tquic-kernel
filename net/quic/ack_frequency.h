/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * QUIC ACK_FREQUENCY Extension Header
 *
 * Implementation of draft-ietf-quic-ack-frequency
 *
 * Copyright (c) 2024 Linux QUIC Authors
 */

#ifndef _QUIC_ACK_FREQUENCY_H
#define _QUIC_ACK_FREQUENCY_H

#include <linux/types.h>
#include <linux/skbuff.h>

/* Forward declaration */
struct quic_connection;

/*
 * ACK_FREQUENCY frame type: 0xaf (draft-ietf-quic-ack-frequency)
 * IMMEDIATE_ACK frame type: 0x1f
 *
 * These are also defined in uapi/linux/quic.h
 */
#define QUIC_FRAME_ACK_FREQUENCY	0xaf
#define QUIC_FRAME_IMMEDIATE_ACK	0x1f

/*
 * Default values per draft-ietf-quic-ack-frequency:
 *
 * - ack_eliciting_threshold: 1
 *   By default, send an ACK after receiving 2 ack-eliciting packets
 *   (count > threshold, so with threshold=1, we ACK after 2 packets)
 *
 * - reordering_threshold: 1
 *   Immediately ACK packets that arrive out-of-order
 *
 * - max_ack_delay: 25ms (25000 microseconds)
 *   Default from RFC 9000
 */
#define QUIC_ACK_FREQ_DEFAULT_THRESHOLD		1
#define QUIC_ACK_FREQ_DEFAULT_REORDER_THRESHOLD	1
#define QUIC_ACK_FREQ_DEFAULT_MAX_DELAY_US	25000

/*
 * ACK_FREQUENCY state for a connection
 *
 * Tracks parameters received from peer and sent to peer.
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

/* Initialize ACK_FREQUENCY state for a connection */
void quic_ack_frequency_init(struct quic_connection *conn);

/* Create an ACK_FREQUENCY frame */
int quic_ack_frequency_create(struct quic_connection *conn,
			      struct sk_buff *skb,
			      u64 threshold,
			      u64 max_ack_delay_us,
			      u64 reorder_threshold);

/* Parse an ACK_FREQUENCY frame */
int quic_ack_frequency_parse(struct quic_connection *conn,
			     const u8 *data, int len,
			     u64 *sequence, u64 *threshold,
			     u64 *max_ack_delay_us, u64 *reorder_threshold);

/* Process a received ACK_FREQUENCY frame */
int quic_ack_frequency_process(struct quic_connection *conn,
			       const u8 *data, int len);

/* Create an IMMEDIATE_ACK frame */
int quic_immediate_ack_create(struct quic_connection *conn, struct sk_buff *skb);

/* Process a received IMMEDIATE_ACK frame */
int quic_immediate_ack_process(struct quic_connection *conn);

/* Check if ACK should be sent based on ACK_FREQUENCY parameters */
bool quic_ack_frequency_should_send(struct quic_connection *conn,
				    u8 pn_space,
				    u32 ack_eliciting_count,
				    u64 largest_recv_pn,
				    u64 last_ack_largest);

/* Request peer to use specific ACK frequency settings */
int quic_ack_frequency_set(struct quic_connection *conn,
			   u64 threshold, u32 max_delay_ms,
			   u64 reorder_threshold);

/* Module init/exit */
int __init quic_ack_frequency_init(void);
void quic_ack_frequency_exit(void);

#endif /* _QUIC_ACK_FREQUENCY_H */
