/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * TQUIC: ACK Frequency Extension (RFC 9002 Appendix A.7)
 *
 * Copyright (c) 2026 Linux Foundation
 *
 * Connection-level wrappers for ACK Frequency extension.
 *
 * This header provides the connection-level API for ACK frequency
 * negotiation and management. The core implementation is in
 * core/ack_frequency.c with the detailed state machine.
 *
 * Frame Types:
 *   - ACK_FREQUENCY (0xaf): Request peer adjust ACK behavior
 *   - IMMEDIATE_ACK (0x1f): Request immediate ACK from peer
 *
 * Transport Parameter:
 *   - min_ack_delay (0xff04de1a): Minimum ACK delay in microseconds
 *
 * Features:
 *   - Full negotiation state machine
 *   - Dynamic ACK frequency adjustment based on:
 *     - Congestion control state
 *     - RTT characteristics
 *     - Bandwidth estimates
 *     - Packet reordering
 *     - Application hints
 *     - ECN signals
 *   - Congestion control integration
 */

#ifndef _TQUIC_ACK_FREQUENCY_H
#define _TQUIC_ACK_FREQUENCY_H

#include <linux/types.h>
#include <linux/spinlock.h>
#include <net/tquic.h>

/* Include core ACK frequency definitions */
#include "core/ack_frequency.h"

/*
 * =============================================================================
 * Frame Type Constants (re-exported for convenience)
 * =============================================================================
 */

/* Note: Frame types are defined in core/ack_frequency.h:
 *   TQUIC_FRAME_ACK_FREQUENCY  = 0xaf
 *   TQUIC_FRAME_IMMEDIATE_ACK  = 0x1f
 *   TQUIC_TP_MIN_ACK_DELAY     = 0xff04de1a
 */

/*
 * =============================================================================
 * Legacy Definitions (for backward compatibility)
 * =============================================================================
 */

/* Default values - these map to core definitions */
#define TQUIC_DEFAULT_ACK_ELICITING_THRESHOLD	TQUIC_ACK_FREQ_DEFAULT_THRESHOLD
#define TQUIC_DEFAULT_MAX_ACK_DELAY_US		TQUIC_ACK_FREQ_DEFAULT_MAX_DELAY_US
#define TQUIC_DEFAULT_REORDER_THRESHOLD		TQUIC_ACK_FREQ_DEFAULT_REORDER_THRESHOLD

/* Ignore threshold for reorder_threshold field */
#define TQUIC_REORDER_THRESHOLD_IGNORE		0xffffffffffffffffULL

/*
 * =============================================================================
 * Connection-Level State Management
 * =============================================================================
 */

/**
 * tquic_ack_freq_conn_init - Initialize ACK frequency state for a connection
 * @conn: Connection to initialize
 *
 * Allocates and initializes the ACK frequency state, storing it in
 * conn->ack_freq_state. Must be called during connection setup before
 * transport parameter negotiation.
 *
 * Return: 0 on success, -ENOMEM on allocation failure, -EINVAL on bad param
 */
int tquic_ack_freq_conn_init(struct tquic_connection *conn);

/**
 * tquic_ack_freq_conn_cleanup - Clean up ACK frequency state
 * @conn: Connection to clean up
 *
 * Frees ACK frequency state stored in conn->ack_freq_state.
 * Called during connection teardown.
 */
void tquic_ack_freq_conn_cleanup(struct tquic_connection *conn);

/**
 * tquic_ack_freq_conn_enable - Enable ACK frequency extension
 * @conn: Connection
 * @peer_min_ack_delay: Peer's min_ack_delay transport parameter (microseconds)
 *
 * Called after transport parameter negotiation when both endpoints
 * advertise the min_ack_delay parameter.
 */
void tquic_ack_freq_conn_enable(struct tquic_connection *conn,
				u64 peer_min_ack_delay);

/**
 * tquic_ack_freq_conn_is_enabled - Check if ACK frequency is enabled
 * @conn: Connection to check
 *
 * Return: true if ACK frequency extension is negotiated and enabled
 */
bool tquic_ack_freq_conn_is_enabled(struct tquic_connection *conn);

/*
 * =============================================================================
 * Legacy API (for backward compatibility)
 * =============================================================================
 */

/* These functions are kept for backward compatibility but use the new core */

int tquic_ack_freq_init(struct tquic_connection *conn);
void tquic_ack_freq_cleanup(struct tquic_connection *conn);
void tquic_ack_freq_enable(struct tquic_connection *conn, u64 peer_min_ack_delay);
bool tquic_ack_freq_is_enabled(struct tquic_connection *conn);

/*
 * =============================================================================
 * Frame Generation (Connection-Level)
 * =============================================================================
 */

/**
 * tquic_gen_ack_frequency_frame - Generate ACK_FREQUENCY frame
 * @conn: Connection
 * @buf: Output buffer
 * @buf_len: Buffer length
 * @ack_eliciting_threshold: ACK-eliciting packets before ACK required
 * @request_max_ack_delay: Requested max ACK delay (microseconds)
 * @reorder_threshold: Reorder threshold (packets)
 * @seq_num: Output sequence number assigned
 *
 * Generates an ACK_FREQUENCY frame requesting the peer adjust its
 * ACK behavior. The sequence number is automatically incremented.
 *
 * Return: Number of bytes written, or negative error code
 */
int tquic_gen_ack_frequency_frame(struct tquic_connection *conn,
				  u8 *buf, size_t buf_len,
				  u64 ack_eliciting_threshold,
				  u64 request_max_ack_delay,
				  u64 reorder_threshold,
				  u64 *seq_num);

/**
 * tquic_gen_immediate_ack_frame - Generate IMMEDIATE_ACK frame
 * @buf: Output buffer
 * @buf_len: Buffer length
 *
 * Generates an IMMEDIATE_ACK frame requesting immediate ACK from peer.
 *
 * Return: Number of bytes written, or negative error code
 */
int tquic_gen_immediate_ack_frame(u8 *buf, size_t buf_len);

/**
 * tquic_ack_frequency_frame_size - Calculate ACK_FREQUENCY frame size
 * @ack_eliciting_threshold: ACK-eliciting threshold value
 * @request_max_ack_delay: Max ACK delay value
 * @reorder_threshold: Reorder threshold value
 * @seq_num: Sequence number value
 *
 * Return: Size in bytes needed for the frame
 */
size_t tquic_ack_frequency_frame_size(u64 ack_eliciting_threshold,
				      u64 request_max_ack_delay,
				      u64 reorder_threshold,
				      u64 seq_num);

/*
 * =============================================================================
 * Frame Parsing
 * =============================================================================
 */

/* Note: Frame parsing functions are available from core/ack_frequency.h:
 *   tquic_parse_ack_frequency_frame()
 *   tquic_parse_immediate_ack_frame()
 */

/*
 * =============================================================================
 * Frame Handling (Connection-Level)
 * =============================================================================
 */

/**
 * tquic_handle_ack_frequency_frame - Process received ACK_FREQUENCY frame
 * @conn: Connection
 * @frame: Parsed frame
 *
 * Updates the connection's ACK behavior according to the peer's request.
 * Only processes frames with sequence numbers greater than previously seen.
 *
 * Return: 0 on success, negative error code on failure
 */
int tquic_handle_ack_frequency_frame(struct tquic_connection *conn,
				     const struct tquic_ack_frequency_frame *frame);

/**
 * tquic_handle_immediate_ack_frame - Process received IMMEDIATE_ACK frame
 * @conn: Connection
 *
 * Triggers immediate ACK generation when IMMEDIATE_ACK is received.
 *
 * Return: 0 on success, negative error code on failure
 */
int tquic_handle_immediate_ack_frame(struct tquic_connection *conn);

/*
 * =============================================================================
 * ACK Decision Logic (Connection-Level)
 * =============================================================================
 */

/**
 * tquic_ack_freq_on_packet_received - Notify ACK frequency of packet receipt
 * @conn: Connection
 * @ack_eliciting: Whether the packet was ack-eliciting
 * @pkt_num: Packet number received
 * @expected_pkt_num: Expected next packet number (for reorder detection)
 *
 * Called when a packet is received to update ACK frequency state and
 * determine if an ACK should be sent.
 *
 * Return: true if an ACK should be sent, false otherwise
 */
bool tquic_ack_freq_on_packet_received(struct tquic_connection *conn,
				       bool ack_eliciting,
				       u64 pkt_num,
				       u64 expected_pkt_num);

/**
 * tquic_ack_freq_on_ack_sent - Notify ACK frequency that ACK was sent
 * @conn: Connection
 *
 * Called after an ACK frame is sent to reset the packet counter.
 */
void tquic_ack_freq_on_ack_sent(struct tquic_connection *conn);

/**
 * tquic_ack_freq_should_ack_immediately - Check if immediate ACK needed
 * @conn: Connection
 *
 * Return: true if immediate ACK should be sent
 */
bool tquic_ack_freq_should_ack_immediately(struct tquic_connection *conn);

/**
 * tquic_ack_freq_should_ack - Determine if ACK should be sent
 * @state: ACK frequency state
 * @pn: Packet number just received
 * @ack_eliciting: Whether the packet was ack-eliciting
 *
 * Implements the ACK suppression algorithm from draft-ietf-quic-ack-frequency.
 * Returns true if an ACK should be sent.
 */
bool tquic_ack_freq_should_ack(struct tquic_ack_frequency_state *state,
			       u64 pn, bool ack_eliciting);

/**
 * tquic_ack_freq_get_max_delay - Get current max ACK delay
 * @conn: Connection
 *
 * Return: Maximum ACK delay in microseconds
 */
u64 tquic_ack_freq_get_max_delay(struct tquic_connection *conn);

/*
 * =============================================================================
 * Transport Parameter Support
 * =============================================================================
 */

/**
 * tquic_ack_freq_encode_tp - Encode min_ack_delay transport parameter
 * @min_ack_delay_us: Minimum ACK delay in microseconds
 * @buf: Output buffer
 * @buf_len: Buffer length
 *
 * Return: Bytes written, or negative error code
 */
int tquic_ack_freq_encode_tp(u64 min_ack_delay_us, u8 *buf, size_t buf_len);

/**
 * tquic_ack_freq_decode_tp - Decode min_ack_delay transport parameter
 * @buf: Input buffer (parameter value)
 * @buf_len: Value length
 * @min_ack_delay_us: Output minimum ACK delay in microseconds
 *
 * Return: 0 on success, negative error code on failure
 */
int tquic_ack_freq_decode_tp(const u8 *buf, size_t buf_len, u64 *min_ack_delay_us);

/*
 * =============================================================================
 * Sender Control API (Connection-Level)
 * =============================================================================
 */

/**
 * tquic_ack_freq_request_update - Request peer update ACK behavior
 * @conn: Connection
 * @ack_elicit_threshold: Desired ack-eliciting threshold
 * @max_ack_delay_us: Desired max ACK delay (microseconds)
 * @reorder_threshold: Desired reorder threshold
 *
 * Schedules an ACK_FREQUENCY frame to be sent to the peer requesting
 * it change its ACK behavior.
 *
 * Return: 0 on success, negative error code on failure
 */
int tquic_ack_freq_request_update(struct tquic_connection *conn,
				  u64 ack_elicit_threshold,
				  u64 max_ack_delay_us,
				  u64 reorder_threshold);

/**
 * tquic_ack_freq_request_immediate_ack - Request immediate ACK from peer
 * @conn: Connection
 *
 * Schedules an IMMEDIATE_ACK frame to be sent requesting the peer
 * acknowledge all received packets immediately.
 *
 * Return: 0 on success, negative error code on failure
 */
int tquic_ack_freq_request_immediate_ack(struct tquic_connection *conn);

/**
 * tquic_ack_freq_has_pending_frames - Check for pending ACK frequency frames
 * @conn: Connection
 *
 * Return: true if ACK_FREQUENCY or IMMEDIATE_ACK frames need to be sent
 */
bool tquic_ack_freq_has_pending_frames(struct tquic_connection *conn);

/**
 * tquic_ack_freq_generate_pending_frames - Generate pending frames
 * @conn: Connection
 * @buf: Output buffer
 * @buf_len: Buffer length
 *
 * Generates any pending ACK_FREQUENCY or IMMEDIATE_ACK frames.
 *
 * Return: Bytes written, or negative error code
 */
int tquic_ack_freq_generate_pending_frames(struct tquic_connection *conn,
					   u8 *buf, size_t buf_len);

/*
 * =============================================================================
 * Congestion Control Integration (Connection-Level)
 * =============================================================================
 */

/**
 * tquic_ack_freq_conn_on_congestion - Notify of congestion event
 * @conn: Connection
 * @in_recovery: Whether CC is in recovery state
 *
 * Called by congestion control when entering/exiting recovery.
 */
void tquic_ack_freq_conn_on_congestion(struct tquic_connection *conn,
				       bool in_recovery);

/**
 * tquic_ack_freq_conn_on_rtt_update - Notify of RTT update
 * @conn: Connection
 * @rtt_us: Smoothed RTT in microseconds
 * @rtt_var_us: RTT variance in microseconds
 *
 * Adjusts ACK frequency based on path RTT characteristics.
 */
void tquic_ack_freq_conn_on_rtt_update(struct tquic_connection *conn,
				       u64 rtt_us, u64 rtt_var_us);

/**
 * tquic_ack_freq_conn_on_bandwidth_update - Notify of bandwidth estimate update
 * @conn: Connection
 * @bandwidth_bps: Estimated bandwidth in bytes per second
 *
 * Adjusts ACK frequency based on path bandwidth.
 */
void tquic_ack_freq_conn_on_bandwidth_update(struct tquic_connection *conn,
					     u64 bandwidth_bps);

/**
 * tquic_ack_freq_conn_on_reordering - Notify of packet reordering detection
 * @conn: Connection
 * @gap: Reorder gap in packets
 *
 * Adjusts reorder threshold based on observed reordering.
 */
void tquic_ack_freq_conn_on_reordering(struct tquic_connection *conn, u64 gap);

/**
 * tquic_ack_freq_conn_on_ecn - Notify of ECN congestion signal
 * @conn: Connection
 *
 * Adjusts ACK frequency in response to ECN-CE marks.
 */
void tquic_ack_freq_conn_on_ecn(struct tquic_connection *conn);

/**
 * tquic_ack_freq_conn_set_app_hint - Set application-level hint
 * @conn: Connection
 * @latency_sensitive: True if application is latency-sensitive
 * @throughput_focused: True if application prioritizes throughput
 *
 * Allows application to influence ACK frequency decisions.
 */
void tquic_ack_freq_conn_set_app_hint(struct tquic_connection *conn,
				      bool latency_sensitive,
				      bool throughput_focused);

/*
 * =============================================================================
 * Sysctl Accessors
 * =============================================================================
 */

/**
 * tquic_sysctl_get_ack_frequency_enabled - Get sysctl ack_frequency_enabled
 *
 * Return: true if ACK frequency extension is enabled globally
 */
bool tquic_sysctl_get_ack_frequency_enabled(void);

/**
 * tquic_sysctl_get_default_ack_delay_us - Get sysctl default_ack_delay_us
 *
 * Return: Default ACK delay in microseconds
 */
u32 tquic_sysctl_get_default_ack_delay_us(void);

/*
 * =============================================================================
 * Module Initialization
 * =============================================================================
 */

/**
 * tquic_ack_freq_module_init - Initialize ACK frequency module
 *
 * Called during TQUIC module initialization.
 *
 * Return: 0 on success, negative error on failure
 */
int tquic_ack_freq_module_init(void);

/**
 * tquic_ack_freq_module_exit - Clean up ACK frequency module
 *
 * Called during TQUIC module unload.
 */
void tquic_ack_freq_module_exit(void);

#endif /* _TQUIC_ACK_FREQUENCY_H */
