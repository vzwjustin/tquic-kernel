/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * TQUIC: Multipath ACK Processing Header
 *
 * Copyright (c) 2026 Linux Foundation
 * Kernel implementation by Justin Adams <spotty118@gmail.com>
 *
 * API definitions for per-path ACK processing for QUIC Multipath
 * Extension (RFC 9369).
 */

#ifndef _TQUIC_MP_ACK_H
#define _TQUIC_MP_ACK_H

#include <linux/types.h>
#include <linux/ktime.h>
#include <net/tquic.h>

#include "mp_frame.h"

/* Forward declaration */
struct tquic_mp_path_ack_state;

/*
 * Per-Path ACK State Management
 */

/**
 * tquic_mp_ack_state_create - Create per-path ACK state
 * @path: Path to create state for
 *
 * Returns allocated state or NULL on failure.
 */
struct tquic_mp_path_ack_state *tquic_mp_ack_state_create(struct tquic_path *path);

/**
 * tquic_mp_ack_state_destroy - Destroy per-path ACK state
 * @state: State to destroy
 */
void tquic_mp_ack_state_destroy(struct tquic_mp_path_ack_state *state);

/*
 * Received Packet Recording
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
			     int pn_space, u64 pn, bool is_ack_eliciting);

/*
 * MP_ACK Frame Generation
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
			  bool include_ecn, u8 ack_delay_exponent);

/*
 * MP_ACK Processing
 */

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
			     struct tquic_connection *conn);

/*
 * Packet Sending Interface
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
			    bool is_ack_eliciting, bool in_flight);

/*
 * Statistics
 */

/**
 * tquic_mp_get_rtt_stats - Get RTT statistics for a path
 * @state: Path ACK state
 * @latest: Output for latest RTT (us)
 * @smoothed: Output for smoothed RTT (us)
 * @variance: Output for RTT variance (us)
 * @min_rtt: Output for minimum RTT (us)
 */
void tquic_mp_get_rtt_stats(struct tquic_mp_path_ack_state *state,
			    u64 *latest, u64 *smoothed,
			    u64 *variance, u64 *min_rtt);

/**
 * tquic_mp_get_in_flight - Get bytes and packets in flight for a path
 * @state: Path ACK state
 * @bytes: Output for bytes in flight
 * @packets: Output for packets in flight
 */
void tquic_mp_get_in_flight(struct tquic_mp_path_ack_state *state,
			    u64 *bytes, u32 *packets);

/*
 * Module Initialization
 */

/**
 * tquic_mp_ack_init - Initialize multipath ACK module
 */
int __init tquic_mp_ack_init(void);

/**
 * tquic_mp_ack_exit - Cleanup multipath ACK module
 */
void __exit tquic_mp_ack_exit(void);

#endif /* _TQUIC_MP_ACK_H */
