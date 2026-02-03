/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * TQUIC: Reliable Stream Reset - RESET_STREAM_AT Frame
 *
 * Copyright (c) 2026 Linux Foundation
 *
 * Implementation of RESET_STREAM_AT frame as defined in
 * draft-ietf-quic-reliable-stream-reset-07.
 *
 * The RESET_STREAM_AT frame allows a sender to reset a stream while
 * guaranteeing reliable delivery of data up to a specified offset.
 * This enables partial delivery guarantees before stream termination.
 */

#ifndef _TQUIC_RELIABLE_RESET_H
#define _TQUIC_RELIABLE_RESET_H

#include <linux/types.h>
#include <linux/errno.h>
#include <net/tquic.h>

/* Forward declarations */
struct tquic_transport_params;

/*
 * Frame Type Constants (draft-ietf-quic-reliable-stream-reset-07)
 *
 * RESET_STREAM_AT (0x24): Resets a stream with partial delivery guarantee.
 * The sender commits to reliably delivering data up to reliable_size.
 */
#define TQUIC_FRAME_RESET_STREAM_AT	0x24

/*
 * Transport Parameter (draft-ietf-quic-reliable-stream-reset-07)
 *
 * An endpoint that understands this extension advertises the
 * reliable_stream_reset transport parameter (0x17cd). This is a
 * zero-length parameter indicating support for RESET_STREAM_AT frames.
 */
#define TQUIC_TP_RELIABLE_STREAM_RESET	0x17cd

/*
 * Error Codes
 */
#define TQUIC_RST_AT_ERR_INVALID_SIZE	0x01  /* reliable_size > final_size */
#define TQUIC_RST_AT_ERR_REDUCED_SIZE	0x02  /* reliable_size reduced */
#define TQUIC_RST_AT_ERR_NOT_SUPPORTED	0x03  /* Extension not negotiated */

/**
 * struct tquic_reset_stream_at - RESET_STREAM_AT frame fields
 * @stream_id: The stream identifier being reset
 * @error_code: Application-defined error code for the reset
 * @final_size: The final size of the stream (total bytes)
 * @reliable_size: Bytes that must be delivered reliably before reset
 *
 * Per draft-ietf-quic-reliable-stream-reset-07 Section 3:
 * - reliable_size MUST be <= final_size
 * - The sender guarantees reliable delivery up to reliable_size
 * - Data after reliable_size MAY be lost
 * - Once sent, reliable_size MUST NOT be reduced
 *
 * The receiver transitions the stream to reset state only after:
 * 1. Receiving all data up to reliable_size, OR
 * 2. Receiving a RESET_STREAM frame (which has no partial guarantee)
 */
struct tquic_reset_stream_at {
	u64 stream_id;
	u64 error_code;
	u64 final_size;
	u64 reliable_size;
};

/**
 * struct tquic_reliable_reset_state - Per-stream reliable reset state
 * @pending: A RESET_STREAM_AT is pending for this stream
 * @error_code: Error code to use when reset completes
 * @final_size: Final size from RESET_STREAM_AT
 * @reliable_size: Reliable size from RESET_STREAM_AT
 * @bytes_delivered: Bytes delivered to application so far
 *
 * This state is stored in the stream extension when a RESET_STREAM_AT
 * is received but the stream has not yet delivered reliable_size bytes.
 */
struct tquic_reliable_reset_state {
	bool pending;
	u64 error_code;
	u64 final_size;
	u64 reliable_size;
	u64 bytes_delivered;
};

/*
 * =============================================================================
 * ENCODING/DECODING API
 * =============================================================================
 */

/**
 * tquic_encode_reset_stream_at - Encode RESET_STREAM_AT frame to wire format
 * @frame: Frame data to encode
 * @buf: Output buffer for encoded frame
 * @buf_len: Size of output buffer
 *
 * Encodes the RESET_STREAM_AT frame as:
 *   Type (1 byte): 0x24
 *   Stream ID (variable-length integer)
 *   Application Protocol Error Code (variable-length integer)
 *   Final Size (variable-length integer)
 *   Reliable Size (variable-length integer)
 *
 * Returns: Number of bytes written on success, negative error code on failure
 *   -EINVAL: Invalid frame parameters (reliable_size > final_size)
 *   -ENOSPC: Buffer too small
 */
ssize_t tquic_encode_reset_stream_at(const struct tquic_reset_stream_at *frame,
				     u8 *buf, size_t buf_len);

/**
 * tquic_decode_reset_stream_at - Decode RESET_STREAM_AT frame from wire format
 * @buf: Input buffer containing encoded frame (starting after type byte)
 * @buf_len: Size of input buffer
 * @frame: Output frame structure
 *
 * Decodes the RESET_STREAM_AT frame fields. The caller should have already
 * verified the frame type byte (0x24) and advanced past it.
 *
 * Returns: Number of bytes consumed on success, negative error code on failure
 *   -EINVAL: Malformed frame or buffer too short
 *   -EPROTO: Protocol violation (reliable_size > final_size)
 */
ssize_t tquic_decode_reset_stream_at(const u8 *buf, size_t buf_len,
				     struct tquic_reset_stream_at *frame);

/**
 * tquic_reset_stream_at_size - Calculate encoded size of RESET_STREAM_AT frame
 * @frame: Frame data
 *
 * Returns: Number of bytes needed to encode the frame
 */
size_t tquic_reset_stream_at_size(const struct tquic_reset_stream_at *frame);

/*
 * =============================================================================
 * FRAME HANDLING API
 * =============================================================================
 */

/**
 * tquic_handle_reset_stream_at - Process received RESET_STREAM_AT frame
 * @conn: Connection that received the frame
 * @frame: Decoded frame data
 *
 * Processes a received RESET_STREAM_AT frame:
 * 1. Validates the frame against stream state
 * 2. If reliable_size bytes already delivered, complete reset immediately
 * 3. Otherwise, mark stream for deferred reset and continue delivery
 *
 * Per draft-ietf-quic-reliable-stream-reset-07 Section 4:
 * - Receiver MUST deliver data up to reliable_size before signaling reset
 * - Receiver MAY discard data after reliable_size
 * - If RESET_STREAM is received, it takes precedence (immediate reset)
 *
 * Returns: 0 on success, negative error code on failure
 *   -EINVAL: Invalid stream ID or frame parameters
 *   -EPROTO: Protocol violation
 */
int tquic_handle_reset_stream_at(struct tquic_connection *conn,
				 const struct tquic_reset_stream_at *frame);

/**
 * tquic_send_reset_stream_at - Generate and queue RESET_STREAM_AT frame
 * @conn: Connection to send on
 * @stream_id: Stream to reset
 * @error_code: Application-defined error code
 * @reliable_size: Bytes to deliver reliably before reset
 *
 * Sends a RESET_STREAM_AT frame for the specified stream. The sender
 * commits to reliably delivering data up to reliable_size.
 *
 * Prerequisites:
 * - Peer must have advertised reliable_stream_reset support
 * - reliable_size must not exceed data already sent
 * - reliable_size must not be reduced from previous RESET_STREAM_AT
 *
 * Returns: 0 on success, negative error code on failure
 *   -EINVAL: Invalid parameters
 *   -ENOENT: Stream not found
 *   -EOPNOTSUPP: Peer does not support reliable stream reset
 *   -EPROTO: reliable_size exceeds sent data or was reduced
 */
int tquic_send_reset_stream_at(struct tquic_connection *conn,
			       u64 stream_id, u64 error_code, u64 reliable_size);

/*
 * =============================================================================
 * STREAM STATE MACHINE INTEGRATION
 * =============================================================================
 */

/**
 * tquic_stream_check_reliable_reset - Check if stream can complete reliable reset
 * @conn: Connection
 * @stream: Stream to check
 *
 * Called after delivering data to application. Checks if the stream
 * has a pending reliable reset and if reliable_size bytes have been
 * delivered. If so, completes the reset.
 *
 * Returns: true if reset was completed, false otherwise
 */
bool tquic_stream_check_reliable_reset(struct tquic_connection *conn,
				       struct tquic_stream *stream);

/**
 * tquic_stream_set_reliable_reset - Mark stream for deferred reset
 * @stream: Stream to mark
 * @error_code: Error code for reset
 * @final_size: Final size of stream
 * @reliable_size: Bytes to deliver before reset
 *
 * Sets up the reliable reset state on a stream. Called when RESET_STREAM_AT
 * is received but reliable_size bytes have not yet been delivered.
 *
 * Returns: 0 on success, negative error code on failure
 */
int tquic_stream_set_reliable_reset(struct tquic_stream *stream,
				    u64 error_code, u64 final_size,
				    u64 reliable_size);

/**
 * tquic_stream_get_reliable_reset - Get pending reliable reset state
 * @stream: Stream to query
 * @state: Output state (may be NULL to just check if pending)
 *
 * Returns: true if reliable reset is pending, false otherwise
 */
bool tquic_stream_get_reliable_reset(struct tquic_stream *stream,
				     struct tquic_reliable_reset_state *state);

/**
 * tquic_stream_clear_reliable_reset - Clear pending reliable reset
 * @stream: Stream to clear
 *
 * Clears the reliable reset state. Called after reset is completed
 * or if a regular RESET_STREAM frame supersedes it.
 */
void tquic_stream_clear_reliable_reset(struct tquic_stream *stream);

/*
 * =============================================================================
 * TRANSPORT PARAMETER HELPERS
 * =============================================================================
 */

/**
 * tquic_supports_reliable_reset - Check if connection supports reliable reset
 * @conn: Connection to check
 *
 * Returns true if both local and remote endpoints support the
 * reliable_stream_reset extension.
 */
bool tquic_supports_reliable_reset(struct tquic_connection *conn);

/**
 * tquic_set_reliable_reset_support - Set local reliable reset support
 * @params: Transport parameters to update
 * @supported: Whether to advertise support
 *
 * Sets the reliable_stream_reset transport parameter for negotiation.
 */
void tquic_set_reliable_reset_support(struct tquic_transport_params *params,
				      bool supported);

#endif /* _TQUIC_RELIABLE_RESET_H */
