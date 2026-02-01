/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * TQUIC: ACK Frequency Extension Header (draft-ietf-quic-ack-frequency)
 *
 * Copyright (c) 2026 Linux Foundation
 *
 * API definitions for the QUIC ACK Frequency extension which allows
 * endpoints to negotiate how often ACKs are sent.
 *
 * Frame Types:
 *   - ACK_FREQUENCY (0xAF): Request peer adjust ACK behavior
 *   - IMMEDIATE_ACK (0x1F): Request immediate ACK from peer
 *
 * Transport Parameter:
 *   - min_ack_delay (0xff04de1a): Minimum ACK delay in microseconds
 */

#ifndef _TQUIC_CORE_ACK_FREQUENCY_H
#define _TQUIC_CORE_ACK_FREQUENCY_H

#include <linux/types.h>
#include <linux/spinlock.h>

/* Forward declarations */
struct tquic_connection;
struct tquic_loss_state;
struct tquic_ack_frequency_state;
struct tquic_ack_frequency_frame;

/*
 * Frame type constants
 */
#define TQUIC_FRAME_ACK_FREQUENCY	0xAF
#define TQUIC_FRAME_IMMEDIATE_ACK	0x1F

/*
 * Transport parameter ID for min_ack_delay
 */
#define TQUIC_TP_MIN_ACK_DELAY		0xff04de1aULL

/*
 * Default values per draft-ietf-quic-ack-frequency
 */
#define TQUIC_ACK_FREQ_DEFAULT_THRESHOLD	2
#define TQUIC_ACK_FREQ_DEFAULT_MAX_DELAY_US	25000	/* 25ms */
#define TQUIC_ACK_FREQ_DEFAULT_REORDER_THRESHOLD 0

/*
 * Limits
 */
#define TQUIC_MIN_ACK_DELAY_MIN_US	1		/* 1 microsecond */
#define TQUIC_MIN_ACK_DELAY_MAX_US	16383000	/* ~16.4 seconds */
#define TQUIC_ACK_FREQ_MAX_THRESHOLD	255

/**
 * struct tquic_ack_frequency_frame - Parsed ACK_FREQUENCY frame
 * @sequence_number: Monotonically increasing sequence number
 * @ack_eliciting_threshold: ACK-eliciting packets before ACK required
 * @request_max_ack_delay: Requested maximum ACK delay (microseconds)
 * @reorder_threshold: Packet reordering threshold before immediate ACK
 *
 * Per draft-ietf-quic-ack-frequency Section 4:
 * The ACK_FREQUENCY frame (type 0xAF) allows an endpoint to request its
 * peer change its ACK behavior.
 *
 * ACK_FREQUENCY Frame {
 *   Type (i) = 0xAF,
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

/*
 * =============================================================================
 * ACK Frequency State Management
 * =============================================================================
 */

/**
 * tquic_ack_freq_state_create - Allocate and initialize ACK frequency state
 * @conn: Connection to create state for
 *
 * Allocates and initializes ACK frequency state for a connection.
 * Must be called during connection setup.
 *
 * Returns allocated state or NULL on failure.
 */
struct tquic_ack_frequency_state *tquic_ack_freq_state_create(
	struct tquic_connection *conn);

/**
 * tquic_ack_freq_state_destroy - Free ACK frequency state
 * @state: State to destroy
 *
 * Frees all resources associated with the ACK frequency state.
 */
void tquic_ack_freq_state_destroy(struct tquic_ack_frequency_state *state);

/**
 * tquic_ack_freq_enable - Enable ACK frequency after transport param negotiation
 * @state: ACK frequency state
 * @peer_min_ack_delay: Peer's min_ack_delay transport parameter (microseconds)
 *
 * Called when both endpoints have advertised min_ack_delay in transport
 * parameters. Enables the ACK frequency extension for the connection.
 */
void tquic_ack_freq_enable(struct tquic_ack_frequency_state *state,
			   u64 peer_min_ack_delay);

/**
 * tquic_ack_freq_is_enabled - Check if ACK frequency extension is active
 * @state: ACK frequency state
 *
 * Returns true if the extension is negotiated and enabled.
 */
bool tquic_ack_freq_is_enabled(const struct tquic_ack_frequency_state *state);

/*
 * =============================================================================
 * Frame Parsing
 * =============================================================================
 */

/**
 * tquic_parse_ack_frequency_frame - Parse ACK_FREQUENCY frame
 * @buf: Input buffer (starting after frame type)
 * @buf_len: Buffer length
 * @frame: Output parsed frame
 *
 * Parses an ACK_FREQUENCY frame from wire format.
 *
 * Returns bytes consumed on success, negative error on failure.
 */
int tquic_parse_ack_frequency_frame(const u8 *buf, size_t buf_len,
				    struct tquic_ack_frequency_frame *frame);

/**
 * tquic_parse_immediate_ack_frame - Parse IMMEDIATE_ACK frame
 * @buf: Input buffer (starting at frame type)
 * @buf_len: Buffer length
 *
 * IMMEDIATE_ACK has no payload beyond the frame type.
 *
 * Returns bytes consumed on success, negative error on failure.
 */
int tquic_parse_immediate_ack_frame(const u8 *buf, size_t buf_len);

/*
 * =============================================================================
 * Frame Generation
 * =============================================================================
 */

/**
 * tquic_write_ack_frequency_frame - Write ACK_FREQUENCY frame
 * @buf: Output buffer
 * @buf_len: Buffer length
 * @seq_num: Sequence number for this frame
 * @threshold: Ack-eliciting threshold
 * @max_delay: Request max ACK delay (microseconds)
 * @reorder: Reorder threshold
 *
 * Writes an ACK_FREQUENCY frame to the buffer.
 *
 * Returns bytes written on success, negative error on failure.
 */
int tquic_write_ack_frequency_frame(u8 *buf, size_t buf_len,
				    u64 seq_num, u64 threshold,
				    u64 max_delay, u64 reorder);

/**
 * tquic_write_immediate_ack_frame - Write IMMEDIATE_ACK frame
 * @buf: Output buffer
 * @buf_len: Buffer length
 *
 * Writes an IMMEDIATE_ACK frame to the buffer.
 *
 * Returns bytes written on success, negative error on failure.
 */
int tquic_write_immediate_ack_frame(u8 *buf, size_t buf_len);

/**
 * tquic_ack_frequency_frame_size - Calculate ACK_FREQUENCY frame size
 * @seq_num: Sequence number
 * @threshold: Ack-eliciting threshold
 * @max_delay: Max ACK delay
 * @reorder: Reorder threshold
 *
 * Returns size in bytes needed for the frame.
 */
size_t tquic_ack_frequency_frame_size(u64 seq_num, u64 threshold,
				      u64 max_delay, u64 reorder);

/**
 * tquic_immediate_ack_frame_size - Get IMMEDIATE_ACK frame size
 *
 * Returns size in bytes (1 for frame type 0x1F).
 */
size_t tquic_immediate_ack_frame_size(void);

/*
 * =============================================================================
 * Frame Handling
 * =============================================================================
 */

/**
 * tquic_handle_ack_frequency_frame - Process received ACK_FREQUENCY frame
 * @state: ACK frequency state
 * @frame: Parsed ACK_FREQUENCY frame
 *
 * Updates local ACK behavior based on peer's request.
 * Only processes frames with sequence numbers larger than previously seen.
 *
 * Returns 0 on success, negative error on failure.
 */
int tquic_handle_ack_frequency_frame(struct tquic_ack_frequency_state *state,
				     const struct tquic_ack_frequency_frame *frame);

/**
 * tquic_handle_immediate_ack_frame - Process received IMMEDIATE_ACK frame
 * @state: ACK frequency state
 *
 * Triggers immediate ACK on next ack-eliciting packet.
 *
 * Returns 0 on success, negative error on failure.
 */
int tquic_handle_immediate_ack_frame(struct tquic_ack_frequency_state *state);

/*
 * =============================================================================
 * ACK Decision Logic
 * =============================================================================
 */

/**
 * tquic_ack_freq_should_ack - Determine if ACK should be sent
 * @state: ACK frequency state
 * @pn: Packet number just received
 * @ack_eliciting: Whether the packet was ack-eliciting
 *
 * Implements the ACK suppression algorithm based on:
 * - IMMEDIATE_ACK pending
 * - Ack-eliciting threshold
 * - Reorder threshold
 *
 * Returns true if an ACK should be sent immediately.
 */
bool tquic_ack_freq_should_ack(struct tquic_ack_frequency_state *state,
			       u64 pn, bool ack_eliciting);

/**
 * tquic_ack_freq_on_ack_sent - Notify that ACK was sent
 * @state: ACK frequency state
 *
 * Resets the packet counter after sending an ACK.
 */
void tquic_ack_freq_on_ack_sent(struct tquic_ack_frequency_state *state);

/**
 * tquic_ack_freq_get_max_delay - Get current maximum ACK delay
 * @state: ACK frequency state
 *
 * Returns maximum ACK delay in microseconds.
 */
u64 tquic_ack_freq_get_max_delay(const struct tquic_ack_frequency_state *state);

/*
 * =============================================================================
 * Sender Control API
 * =============================================================================
 */

/**
 * tquic_ack_freq_request_update - Schedule ACK_FREQUENCY frame transmission
 * @state: ACK frequency state
 * @threshold: Desired ack-eliciting threshold
 * @max_delay_us: Desired max ACK delay (microseconds)
 * @reorder: Desired reorder threshold
 *
 * Schedules an ACK_FREQUENCY frame requesting peer update its ACK behavior.
 * The max_delay_us must be >= peer's min_ack_delay.
 *
 * Returns 0 on success, negative error on failure.
 */
int tquic_ack_freq_request_update(struct tquic_ack_frequency_state *state,
				  u64 threshold, u64 max_delay_us, u64 reorder);

/**
 * tquic_ack_freq_request_immediate_ack - Request peer send ACK immediately
 * @state: ACK frequency state
 *
 * Schedules an IMMEDIATE_ACK frame to be sent.
 *
 * Returns 0 on success.
 */
int tquic_ack_freq_request_immediate_ack(struct tquic_ack_frequency_state *state);

/**
 * tquic_ack_freq_generate_pending - Generate pending ACK frequency frames
 * @state: ACK frequency state
 * @buf: Output buffer
 * @buf_len: Buffer length
 *
 * Generates any pending ACK_FREQUENCY frames into the buffer.
 *
 * Returns bytes written, 0 if nothing pending, or negative error.
 */
int tquic_ack_freq_generate_pending(struct tquic_ack_frequency_state *state,
				    u8 *buf, size_t buf_len);

/**
 * tquic_ack_freq_has_pending - Check if there are pending frames to send
 * @state: ACK frequency state
 *
 * Returns true if ACK_FREQUENCY or IMMEDIATE_ACK frames are pending.
 */
bool tquic_ack_freq_has_pending(const struct tquic_ack_frequency_state *state);

/*
 * =============================================================================
 * Integration with Loss Detection
 * =============================================================================
 */

/**
 * tquic_ack_freq_update_loss_state - Update loss state with ACK freq params
 * @loss: Loss detection state
 * @state: ACK frequency state
 *
 * Updates the loss detection state's ACK delay based on negotiated
 * ACK frequency parameters.
 */
void tquic_ack_freq_update_loss_state(struct tquic_loss_state *loss,
				      const struct tquic_ack_frequency_state *state);

/*
 * =============================================================================
 * Module Initialization
 * =============================================================================
 */

/**
 * tquic_ack_freq_init - Initialize ACK frequency module
 *
 * Creates memory caches and initializes module state.
 *
 * Returns 0 on success, negative error on failure.
 */
int __init tquic_ack_freq_init(void);

/**
 * tquic_ack_freq_exit - Cleanup ACK frequency module
 *
 * Destroys memory caches and cleans up module state.
 */
void __exit tquic_ack_freq_exit(void);

#endif /* _TQUIC_CORE_ACK_FREQUENCY_H */
