/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * TQUIC: ACK Frequency Extension (draft-ietf-quic-ack-frequency)
 *
 * Copyright (c) 2026 Linux Foundation
 *
 * Implements ACK_FREQUENCY and IMMEDIATE_ACK frames to allow sender
 * control over how frequently the peer generates acknowledgments.
 *
 * Frame Types:
 *   - ACK_FREQUENCY (0xaf): Negotiate delayed ACK behavior
 *   - IMMEDIATE_ACK (0xac): Request immediate ACK from peer
 *
 * Transport Parameter:
 *   - min_ack_delay (0x0e): Minimum ACK delay in microseconds
 */

#ifndef _TQUIC_ACK_FREQUENCY_H
#define _TQUIC_ACK_FREQUENCY_H

#include <linux/types.h>
#include <linux/spinlock.h>
#include <net/tquic.h>

/* Frame type values per draft-ietf-quic-ack-frequency */
#define TQUIC_FRAME_ACK_FREQUENCY	0xaf
#define TQUIC_FRAME_IMMEDIATE_ACK	0xac

/* Transport parameter ID for min_ack_delay (draft-ietf-quic-ack-frequency) */
#define TQUIC_TP_MIN_ACK_DELAY		0xff04de1aULL

/* Default values */
#define TQUIC_DEFAULT_ACK_ELICITING_THRESHOLD	2
#define TQUIC_DEFAULT_MAX_ACK_DELAY_US		25000	/* 25ms in microseconds */
#define TQUIC_DEFAULT_REORDER_THRESHOLD		0	/* No reordering tolerance */
#define TQUIC_MIN_ACK_DELAY_MIN_US		1	/* 1 microsecond minimum */
#define TQUIC_MIN_ACK_DELAY_MAX_US		16383000 /* ~16.4 seconds */

/* Ignore threshold for reorder_threshold field */
#define TQUIC_REORDER_THRESHOLD_IGNORE		0xffffffffffffffff

/**
 * struct tquic_ack_frequency_frame - ACK_FREQUENCY frame contents
 * @sequence_number: Monotonically increasing sequence number
 * @ack_eliciting_threshold: ACK-eliciting packets before ACK required
 * @request_max_ack_delay: Requested maximum ACK delay in microseconds
 * @reorder_threshold: Packet reordering threshold before immediate ACK
 *
 * Per draft-ietf-quic-ack-frequency Section 4:
 * The ACK_FREQUENCY frame (type 0xaf) allows an endpoint to request its
 * peer change its ACK behavior. The frame format is:
 *
 * ACK_FREQUENCY Frame {
 *   Type (i) = 0xaf,
 *   Sequence Number (i),
 *   Ack-Eliciting Threshold (i),
 *   Request Max Ack Delay (i),
 *   Reorder Threshold (i),
 * }
 */
struct tquic_ack_frequency_frame {
	u64 sequence_number;
	u64 ack_eliciting_threshold;
	u64 request_max_ack_delay;
	u64 reorder_threshold;
};

/**
 * struct tquic_ack_frequency_state - Per-connection ACK frequency state
 * @enabled: Whether ACK frequency extension is negotiated
 * @min_ack_delay_us: Our min_ack_delay transport parameter (microseconds)
 * @peer_min_ack_delay_us: Peer's min_ack_delay transport parameter
 * @last_sent_seq: Last sequence number sent in ACK_FREQUENCY frame
 * @last_recv_seq: Last sequence number received in ACK_FREQUENCY frame
 * @current_ack_elicit_threshold: Current ack-eliciting threshold from peer
 * @current_max_ack_delay_us: Current max ACK delay from peer (microseconds)
 * @current_reorder_threshold: Current reorder threshold from peer
 * @pending_send: ACK_FREQUENCY frame needs to be sent
 * @pending_immediate_ack: IMMEDIATE_ACK frame needs to be sent
 * @packets_since_ack: Ack-eliciting packets received since last ACK sent
 * @lock: Spinlock protecting this state
 */
struct tquic_ack_frequency_state {
	bool enabled;
	u64 min_ack_delay_us;
	u64 peer_min_ack_delay_us;

	u64 last_sent_seq;
	u64 last_recv_seq;

	u64 current_ack_elicit_threshold;
	u64 current_max_ack_delay_us;
	u64 current_reorder_threshold;

	bool pending_send;
	bool pending_immediate_ack;

	u64 packets_since_ack;

	spinlock_t lock;
};

/*
 * =============================================================================
 * ACK Frequency State Management
 * =============================================================================
 */

/**
 * tquic_ack_freq_init - Initialize ACK frequency state for a connection
 * @conn: Connection to initialize
 *
 * Allocates and initializes the ACK frequency state. Must be called
 * during connection setup before transport parameter negotiation.
 *
 * Return: 0 on success, -ENOMEM on allocation failure
 */
int tquic_ack_freq_init(struct tquic_connection *conn);

/**
 * tquic_ack_freq_cleanup - Clean up ACK frequency state
 * @conn: Connection to clean up
 *
 * Frees ACK frequency state. Called during connection teardown.
 */
void tquic_ack_freq_cleanup(struct tquic_connection *conn);

/**
 * tquic_ack_freq_enable - Enable ACK frequency extension after negotiation
 * @conn: Connection
 * @peer_min_ack_delay: Peer's min_ack_delay transport parameter
 *
 * Called after transport parameter negotiation if both endpoints
 * advertise the min_ack_delay parameter.
 */
void tquic_ack_freq_enable(struct tquic_connection *conn, u64 peer_min_ack_delay);

/**
 * tquic_ack_freq_is_enabled - Check if ACK frequency is enabled
 * @conn: Connection to check
 *
 * Return: true if ACK frequency extension is negotiated
 */
bool tquic_ack_freq_is_enabled(struct tquic_connection *conn);

/*
 * =============================================================================
 * Frame Generation
 * =============================================================================
 */

/**
 * tquic_gen_ack_frequency_frame - Generate ACK_FREQUENCY frame
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
 * The frame has no payload, just the type byte.
 *
 * Return: Number of bytes written (1), or negative error code
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

/**
 * tquic_parse_ack_frequency_frame - Parse ACK_FREQUENCY frame
 * @buf: Input buffer (starting after frame type byte)
 * @buf_len: Buffer length
 * @frame: Output frame structure
 *
 * Parses an ACK_FREQUENCY frame from the wire format.
 *
 * Return: Bytes consumed on success, negative error code on failure
 */
int tquic_parse_ack_frequency_frame(const u8 *buf, size_t buf_len,
				    struct tquic_ack_frequency_frame *frame);

/**
 * tquic_parse_immediate_ack_frame - Parse IMMEDIATE_ACK frame
 * @buf: Input buffer (starting at frame type byte)
 * @buf_len: Buffer length
 *
 * IMMEDIATE_ACK has no payload, so this just validates the frame type.
 *
 * Return: Bytes consumed (1) on success, negative error code on failure
 */
int tquic_parse_immediate_ack_frame(const u8 *buf, size_t buf_len);

/*
 * =============================================================================
 * Frame Handling
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
 * ACK Decision Logic
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
 * Sender Control API
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

/*
 * =============================================================================
 * Sysctl Accessors
 * =============================================================================
 */

/**
 * tquic_sysctl_get_ack_frequency_enabled - Get sysctl ack_frequency_enabled
 *
 * Return: true if ACK frequency extension is enabled
 */
bool tquic_sysctl_get_ack_frequency_enabled(void);

/**
 * tquic_sysctl_get_default_ack_delay_us - Get sysctl default_ack_delay_us
 *
 * Return: Default ACK delay in microseconds
 */
u32 tquic_sysctl_get_default_ack_delay_us(void);

#endif /* _TQUIC_ACK_FREQUENCY_H */
