/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * TQUIC ACK_FREQUENCY Extension Header
 *
 * Implementation of draft-ietf-quic-ack-frequency
 *
 * Copyright (c) 2024-2026 Linux TQUIC Authors
 * Kernel implementation by Justin Adams <spotty118@gmail.com>
 */

#ifndef _TQUIC_CORE_ACK_FREQUENCY_H
#define _TQUIC_CORE_ACK_FREQUENCY_H

#include <linux/types.h>
#include <linux/skbuff.h>
#include <net/tquic.h>

/*
 * ACK_FREQUENCY frame type: 0xaf (draft-ietf-quic-ack-frequency)
 * IMMEDIATE_ACK frame type: 0x1f
 *
 * These are also defined in uapi/linux/tquic.h
 */
#define TQUIC_FRAME_ACK_FREQUENCY	0xaf
#define TQUIC_FRAME_IMMEDIATE_ACK	0x1f

/* Legacy aliases */
#define QUIC_FRAME_ACK_FREQUENCY	TQUIC_FRAME_ACK_FREQUENCY
#define QUIC_FRAME_IMMEDIATE_ACK	TQUIC_FRAME_IMMEDIATE_ACK

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
#define TQUIC_ACK_FREQ_DEFAULT_THRESHOLD	1
#define TQUIC_ACK_FREQ_DEFAULT_REORDER_THRESHOLD 1
#define TQUIC_ACK_FREQ_DEFAULT_MAX_DELAY_US	25000

/* Legacy aliases */
#define QUIC_ACK_FREQ_DEFAULT_THRESHOLD		TQUIC_ACK_FREQ_DEFAULT_THRESHOLD
#define QUIC_ACK_FREQ_DEFAULT_REORDER_THRESHOLD	TQUIC_ACK_FREQ_DEFAULT_REORDER_THRESHOLD
#define QUIC_ACK_FREQ_DEFAULT_MAX_DELAY_US	TQUIC_ACK_FREQ_DEFAULT_MAX_DELAY_US

/*
 * ACK_FREQUENCY state for a connection
 *
 * Tracks parameters received from peer and sent to peer.
 */
struct tquic_ack_frequency_state {
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

/* Legacy alias */
#define quic_ack_frequency_state	tquic_ack_frequency_state

/* Initialize ACK_FREQUENCY state for a connection */
void tquic_ack_frequency_init(struct tquic_connection *conn);

/* Free ACK_FREQUENCY state for a connection */
void tquic_ack_frequency_destroy(struct tquic_connection *conn);

/* Create an ACK_FREQUENCY frame */
int tquic_ack_frequency_create(struct tquic_connection *conn,
			       struct sk_buff *skb,
			       u64 threshold,
			       u64 max_ack_delay_us,
			       u64 reorder_threshold);

/* Parse an ACK_FREQUENCY frame */
int tquic_ack_frequency_parse(struct tquic_connection *conn,
			      const u8 *data, int len,
			      u64 *sequence, u64 *threshold,
			      u64 *max_ack_delay_us, u64 *reorder_threshold);

/* Process a received ACK_FREQUENCY frame */
int tquic_ack_frequency_process(struct tquic_connection *conn,
				const u8 *data, int len);

/* Create an IMMEDIATE_ACK frame */
int tquic_immediate_ack_create(struct tquic_connection *conn, struct sk_buff *skb);

/* Process a received IMMEDIATE_ACK frame */
int tquic_immediate_ack_process(struct tquic_connection *conn);

/* Check if ACK should be sent based on ACK_FREQUENCY parameters */
bool tquic_ack_frequency_should_send(struct tquic_connection *conn,
				     u8 pn_space,
				     u32 ack_eliciting_count,
				     u64 largest_recv_pn,
				     u64 last_ack_largest);

/* Request peer to use specific ACK frequency settings */
int tquic_ack_frequency_set(struct tquic_connection *conn,
			    u64 threshold, u32 max_delay_ms,
			    u64 reorder_threshold);

/* Module init/exit */
int __init tquic_ack_frequency_module_init(void);
void tquic_ack_frequency_module_exit(void);

/* Legacy aliases */
#define quic_ack_frequency_init		tquic_ack_frequency_init
#define quic_ack_frequency_destroy	tquic_ack_frequency_destroy
#define quic_ack_frequency_create	tquic_ack_frequency_create
#define quic_ack_frequency_parse	tquic_ack_frequency_parse
#define quic_ack_frequency_process	tquic_ack_frequency_process
#define quic_immediate_ack_create	tquic_immediate_ack_create
#define quic_immediate_ack_process	tquic_immediate_ack_process
#define quic_ack_frequency_should_send	tquic_ack_frequency_should_send
#define quic_ack_frequency_set		tquic_ack_frequency_set
#define quic_ack_frequency_module_init	tquic_ack_frequency_module_init
#define quic_ack_frequency_module_exit	tquic_ack_frequency_module_exit

#endif /* _TQUIC_CORE_ACK_FREQUENCY_H */
