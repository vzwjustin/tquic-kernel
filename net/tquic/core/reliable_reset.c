// SPDX-License-Identifier: GPL-2.0-only
/*
 * TQUIC: Reliable Stream Reset - RESET_STREAM_AT Frame Implementation
 *
 * Copyright (c) 2026 Linux Foundation
 *
 * Implementation of RESET_STREAM_AT frame as defined in
 * draft-ietf-quic-reliable-stream-reset-07.
 *
 * This extension allows graceful stream termination with partial delivery
 * guarantees. When a sender issues RESET_STREAM_AT with reliable_size=N,
 * it commits to delivering the first N bytes reliably before terminating
 * the stream. This is useful for applications that can tolerate partial
 * data loss but need headers or metadata delivered reliably.
 */

#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/bug.h>
#include <net/tquic.h>

#include "reliable_reset.h"
#include "varint.h"
#include "stream.h"
#include "transport_params.h"

/*
 * =============================================================================
 * VARINT HELPERS (local to this file)
 * =============================================================================
 * These mirror the functions in varint.c but are kept local to avoid
 * external dependencies and match the pattern in transport_params.c
 */

/**
 * reliable_reset_varint_size - Get encoded size of a varint value
 * @value: Value to encode
 *
 * Returns: Number of bytes needed (1, 2, 4, or 8), or 0 if too large
 */
static inline size_t reliable_reset_varint_size(u64 value)
{
	if (value <= 63)
		return 1;
	if (value <= 16383)
		return 2;
	if (value <= 1073741823)
		return 4;
	if (value <= 4611686018427387903ULL)
		return 8;
	return 0;
}

/**
 * reliable_reset_varint_encode - Encode a varint to buffer
 * @buf: Output buffer
 * @buf_len: Buffer length
 * @value: Value to encode
 *
 * Returns: Bytes written, or negative error
 */
static ssize_t reliable_reset_varint_encode(u8 *buf, size_t buf_len, u64 value)
{
	size_t len = reliable_reset_varint_size(value);

	if (len == 0)
		return -EOVERFLOW;
	if (buf_len < len)
		return -ENOSPC;

	switch (len) {
	case 1:
		buf[0] = (u8)value;
		break;
	case 2:
		buf[0] = 0x40 | (u8)(value >> 8);
		buf[1] = (u8)value;
		break;
	case 4:
		buf[0] = 0x80 | (u8)(value >> 24);
		buf[1] = (u8)(value >> 16);
		buf[2] = (u8)(value >> 8);
		buf[3] = (u8)value;
		break;
	case 8:
		buf[0] = 0xc0 | (u8)(value >> 56);
		buf[1] = (u8)(value >> 48);
		buf[2] = (u8)(value >> 40);
		buf[3] = (u8)(value >> 32);
		buf[4] = (u8)(value >> 24);
		buf[5] = (u8)(value >> 16);
		buf[6] = (u8)(value >> 8);
		buf[7] = (u8)value;
		break;
	}

	return len;
}

/**
 * reliable_reset_varint_decode - Decode a varint from buffer
 * @buf: Input buffer
 * @buf_len: Buffer length
 * @value: Output value
 *
 * Returns: Bytes consumed, or negative error
 */
static ssize_t reliable_reset_varint_decode(const u8 *buf, size_t buf_len,
					    u64 *value)
{
	u8 prefix;
	size_t len;

	if (buf_len < 1)
		return -EINVAL;

	prefix = buf[0] >> 6;
	len = 1 << prefix;

	if (buf_len < len)
		return -EINVAL;

	switch (len) {
	case 1:
		*value = buf[0] & 0x3f;
		break;
	case 2:
		*value = ((u64)(buf[0] & 0x3f) << 8) | buf[1];
		break;
	case 4:
		*value = ((u64)(buf[0] & 0x3f) << 24) |
			 ((u64)buf[1] << 16) |
			 ((u64)buf[2] << 8) |
			 buf[3];
		break;
	case 8:
		*value = ((u64)(buf[0] & 0x3f) << 56) |
			 ((u64)buf[1] << 48) |
			 ((u64)buf[2] << 40) |
			 ((u64)buf[3] << 32) |
			 ((u64)buf[4] << 24) |
			 ((u64)buf[5] << 16) |
			 ((u64)buf[6] << 8) |
			 buf[7];
		break;
	default:
		return -EINVAL;
	}

	return len;
}

/*
 * =============================================================================
 * ENCODING/DECODING IMPLEMENTATION
 * =============================================================================
 */

/**
 * tquic_reset_stream_at_size - Calculate encoded size of RESET_STREAM_AT frame
 * @frame: Frame data
 *
 * Frame format:
 *   Type (1 byte): 0x24
 *   Stream ID (varint)
 *   Application Protocol Error Code (varint)
 *   Final Size (varint)
 *   Reliable Size (varint)
 *
 * Returns: Number of bytes needed to encode the frame
 */
size_t tquic_reset_stream_at_size(const struct tquic_reset_stream_at *frame)
{
	size_t size = 1;  /* Frame type byte */

	size += reliable_reset_varint_size(frame->stream_id);
	size += reliable_reset_varint_size(frame->error_code);
	size += reliable_reset_varint_size(frame->final_size);
	size += reliable_reset_varint_size(frame->reliable_size);

	return size;
}
EXPORT_SYMBOL_GPL(tquic_reset_stream_at_size);

/**
 * tquic_encode_reset_stream_at - Encode RESET_STREAM_AT frame to wire format
 * @frame: Frame data to encode
 * @buf: Output buffer for encoded frame
 * @buf_len: Size of output buffer
 *
 * Returns: Number of bytes written on success, negative error code on failure
 */
ssize_t tquic_encode_reset_stream_at(const struct tquic_reset_stream_at *frame,
				     u8 *buf, size_t buf_len)
{
	size_t offset = 0;
	ssize_t ret;

	if (!frame || !buf)
		return -EINVAL;

	/* Validate: reliable_size must not exceed final_size */
	if (frame->reliable_size > frame->final_size) {
		pr_debug("tquic: RESET_STREAM_AT: reliable_size (%llu) > final_size (%llu)\n",
			 frame->reliable_size, frame->final_size);
		return -EINVAL;
	}

	/* Check buffer has enough space */
	if (buf_len < tquic_reset_stream_at_size(frame))
		return -ENOSPC;

	/* Frame type (0x24) */
	buf[offset++] = TQUIC_FRAME_RESET_STREAM_AT;

	/* Stream ID */
	ret = reliable_reset_varint_encode(buf + offset, buf_len - offset,
					   frame->stream_id);
	if (ret < 0)
		return ret;
	offset += ret;

	/* Application Protocol Error Code */
	ret = reliable_reset_varint_encode(buf + offset, buf_len - offset,
					   frame->error_code);
	if (ret < 0)
		return ret;
	offset += ret;

	/* Final Size */
	ret = reliable_reset_varint_encode(buf + offset, buf_len - offset,
					   frame->final_size);
	if (ret < 0)
		return ret;
	offset += ret;

	/* Reliable Size */
	ret = reliable_reset_varint_encode(buf + offset, buf_len - offset,
					   frame->reliable_size);
	if (ret < 0)
		return ret;
	offset += ret;

	return offset;
}
EXPORT_SYMBOL_GPL(tquic_encode_reset_stream_at);

/**
 * tquic_decode_reset_stream_at - Decode RESET_STREAM_AT frame from wire format
 * @buf: Input buffer (starting after the type byte has been consumed)
 * @buf_len: Size of input buffer
 * @frame: Output frame structure
 *
 * Returns: Number of bytes consumed on success, negative error code on failure
 */
ssize_t tquic_decode_reset_stream_at(const u8 *buf, size_t buf_len,
				     struct tquic_reset_stream_at *frame)
{
	size_t offset = 0;
	ssize_t ret;

	if (!buf || !frame)
		return -EINVAL;

	memset(frame, 0, sizeof(*frame));

	/* Decode Stream ID */
	ret = reliable_reset_varint_decode(buf + offset, buf_len - offset,
					   &frame->stream_id);
	if (ret < 0) {
		pr_debug("tquic: RESET_STREAM_AT: failed to decode stream_id\n");
		return ret;
	}
	offset += ret;

	/* Decode Application Protocol Error Code */
	ret = reliable_reset_varint_decode(buf + offset, buf_len - offset,
					   &frame->error_code);
	if (ret < 0) {
		pr_debug("tquic: RESET_STREAM_AT: failed to decode error_code\n");
		return ret;
	}
	offset += ret;

	/* Decode Final Size */
	ret = reliable_reset_varint_decode(buf + offset, buf_len - offset,
					   &frame->final_size);
	if (ret < 0) {
		pr_debug("tquic: RESET_STREAM_AT: failed to decode final_size\n");
		return ret;
	}
	offset += ret;

	/* Decode Reliable Size */
	ret = reliable_reset_varint_decode(buf + offset, buf_len - offset,
					   &frame->reliable_size);
	if (ret < 0) {
		pr_debug("tquic: RESET_STREAM_AT: failed to decode reliable_size\n");
		return ret;
	}
	offset += ret;

	/* Protocol validation: reliable_size must not exceed final_size */
	if (frame->reliable_size > frame->final_size) {
		pr_debug("tquic: RESET_STREAM_AT: protocol violation: "
			 "reliable_size (%llu) > final_size (%llu)\n",
			 frame->reliable_size, frame->final_size);
		return -EPROTO;
	}

	return offset;
}
EXPORT_SYMBOL_GPL(tquic_decode_reset_stream_at);

/*
 * =============================================================================
 * FRAME HANDLING IMPLEMENTATION
 * =============================================================================
 */

/**
 * tquic_handle_reset_stream_at - Process received RESET_STREAM_AT frame
 * @conn: Connection that received the frame
 * @frame: Decoded frame data
 *
 * Returns: 0 on success, negative error code on failure
 */
int tquic_handle_reset_stream_at(struct tquic_connection *conn,
				 const struct tquic_reset_stream_at *frame)
{
	struct tquic_stream *stream;
	struct tquic_stream_ext *ext;
	u64 bytes_received;
	int ret = 0;

	if (!conn || !frame)
		return -EINVAL;

	/* Check if reliable reset is supported */
	if (!tquic_supports_reliable_reset(conn)) {
		pr_debug("tquic: RESET_STREAM_AT received but not negotiated\n");
		return -EPROTO;
	}

	spin_lock_bh(&conn->lock);

	/* Look up the stream */
	stream = tquic_stream_lookup_internal(conn, frame->stream_id);
	if (!stream) {
		pr_debug("tquic: RESET_STREAM_AT for unknown stream %llu\n",
			 frame->stream_id);
		ret = -EINVAL;
		goto out_unlock;
	}

	/* Check stream state - cannot reset already closed streams */
	if (stream->state == TQUIC_STREAM_CLOSED ||
	    stream->state == TQUIC_STREAM_RESET_RECVD) {
		pr_debug("tquic: RESET_STREAM_AT for closed/reset stream %llu\n",
			 frame->stream_id);
		ret = 0;  /* Ignore duplicate resets */
		goto out_unlock;
	}

	/* Get stream extension for detailed state */
	ext = stream->ext;
	if (!ext) {
		pr_warn("tquic: stream %llu missing extension state\n",
			frame->stream_id);
		ret = -EINVAL;
		goto out_unlock;
	}

	/*
	 * Validate final_size consistency:
	 * If we already know the final size (from previous RESET_STREAM,
	 * RESET_STREAM_AT, or FIN), it must match.
	 */
	if (ext->final_size >= 0 && ext->final_size != (s64)frame->final_size) {
		pr_debug("tquic: RESET_STREAM_AT final_size mismatch: "
			 "was %lld, now %llu\n",
			 ext->final_size, frame->final_size);
		ret = -EPROTO;
		goto out_unlock;
	}

	/*
	 * Check if a reliable reset is already pending.
	 * Per spec, reliable_size cannot be reduced.
	 */
	if (ext->rst_received) {
		struct tquic_reliable_reset_state *rst_state;

		rst_state = (struct tquic_reliable_reset_state *)
			    kzalloc(sizeof(*rst_state), GFP_ATOMIC);
		if (rst_state && tquic_stream_get_reliable_reset(stream, rst_state)) {
			if (frame->reliable_size < rst_state->reliable_size) {
				pr_debug("tquic: RESET_STREAM_AT reliable_size reduced: "
					 "was %llu, now %llu\n",
					 rst_state->reliable_size,
					 frame->reliable_size);
				kfree(rst_state);
				ret = -EPROTO;
				goto out_unlock;
			}
		}
		kfree(rst_state);
	}

	/* Record the final size */
	ext->final_size = frame->final_size;

	/* Calculate bytes already delivered/received in order */
	bytes_received = ext->recv_next;

	pr_debug("tquic: RESET_STREAM_AT stream=%llu reliable=%llu final=%llu "
		 "delivered=%llu\n",
		 frame->stream_id, frame->reliable_size,
		 frame->final_size, bytes_received);

	/*
	 * If reliable_size bytes have already been delivered to the
	 * application, complete the reset immediately.
	 */
	if (bytes_received >= frame->reliable_size) {
		/* Immediate reset - all reliable data delivered */
		ext->error_code = frame->error_code;
		ext->rst_received = true;
		stream->state = TQUIC_STREAM_RESET_RECVD;

		/* Wake up any waiters */
		wake_up_interruptible(&stream->wait);

		pr_debug("tquic: stream %llu reset complete (reliable delivery met)\n",
			 frame->stream_id);
	} else {
		/*
		 * Deferred reset - need to deliver more data first.
		 * Mark the stream for reliable reset and continue receiving.
		 */
		ret = tquic_stream_set_reliable_reset(stream,
						      frame->error_code,
						      frame->final_size,
						      frame->reliable_size);
		if (ret < 0) {
			pr_warn("tquic: failed to set reliable reset state: %d\n",
				ret);
			goto out_unlock;
		}

		pr_debug("tquic: stream %llu deferred reset (need %llu more bytes)\n",
			 frame->stream_id, frame->reliable_size - bytes_received);
	}

out_unlock:
	spin_unlock_bh(&conn->lock);
	return ret;
}
EXPORT_SYMBOL_GPL(tquic_handle_reset_stream_at);

/**
 * tquic_send_reset_stream_at - Generate and queue RESET_STREAM_AT frame
 * @conn: Connection to send on
 * @stream_id: Stream to reset
 * @error_code: Application-defined error code
 * @reliable_size: Bytes to deliver reliably before reset
 *
 * Returns: 0 on success, negative error code on failure
 */
int tquic_send_reset_stream_at(struct tquic_connection *conn,
			       u64 stream_id, u64 error_code, u64 reliable_size)
{
	struct tquic_stream *stream;
	struct tquic_stream_ext *ext;
	struct tquic_reset_stream_at frame;
	u8 *buf;
	ssize_t len;
	int ret = 0;

	if (!conn)
		return -EINVAL;

	/* Check if peer supports reliable reset */
	if (!tquic_supports_reliable_reset(conn)) {
		pr_debug("tquic: cannot send RESET_STREAM_AT: peer does not support\n");
		return -EOPNOTSUPP;
	}

	spin_lock_bh(&conn->lock);

	/* Look up the stream */
	stream = tquic_stream_lookup_internal(conn, stream_id);
	if (!stream) {
		pr_debug("tquic: RESET_STREAM_AT for unknown stream %llu\n",
			 stream_id);
		ret = -ENOENT;
		goto out_unlock;
	}

	/* Check stream state - cannot reset already reset streams */
	if (stream->state == TQUIC_STREAM_RESET_SENT ||
	    stream->state == TQUIC_STREAM_CLOSED) {
		pr_debug("tquic: cannot reset already-reset stream %llu\n",
			 stream_id);
		ret = -EINVAL;
		goto out_unlock;
	}

	ext = stream->ext;
	if (!ext) {
		ret = -EINVAL;
		goto out_unlock;
	}

	/*
	 * Validate reliable_size:
	 * - Must not exceed data we have sent
	 * - Must not be reduced from previous RESET_STREAM_AT
	 */
	if (reliable_size > stream->send_offset) {
		pr_debug("tquic: reliable_size (%llu) > sent data (%llu)\n",
			 reliable_size, stream->send_offset);
		ret = -EPROTO;
		goto out_unlock;
	}

	/* Check if we're reducing reliable_size from a previous reset */
	if (ext->rst_sent) {
		struct tquic_reliable_reset_state state;

		if (tquic_stream_get_reliable_reset(stream, &state)) {
			if (reliable_size < state.reliable_size) {
				pr_debug("tquic: cannot reduce reliable_size: "
					 "was %llu, requested %llu\n",
					 state.reliable_size, reliable_size);
				ret = -EPROTO;
				goto out_unlock;
			}
		}
	}

	/* Build the frame */
	frame.stream_id = stream_id;
	frame.error_code = error_code;
	frame.final_size = stream->send_offset;  /* We've sent this much */
	frame.reliable_size = reliable_size;

	/* Allocate buffer for encoding */
	buf = kmalloc(64, GFP_ATOMIC);
	if (!buf) {
		ret = -ENOMEM;
		goto out_unlock;
	}

	/* Encode the frame */
	len = tquic_encode_reset_stream_at(&frame, buf, 64);
	if (len < 0) {
		kfree(buf);
		ret = len;
		goto out_unlock;
	}

	/* Update stream state */
	ext->rst_sent = true;
	ext->error_code = error_code;
	ext->final_size = frame.final_size;

	/* Store reliable reset state for potential retransmission */
	ret = tquic_stream_set_reliable_reset(stream, error_code,
					      frame.final_size, reliable_size);
	if (ret < 0) {
		kfree(buf);
		goto out_unlock;
	}

	stream->state = TQUIC_STREAM_RESET_SENT;

	spin_unlock_bh(&conn->lock);

	/* Queue the frame for transmission */
	ret = tquic_queue_control_frame(conn, buf, len);
	if (ret < 0) {
		kfree(buf);
		return ret;
	}

	pr_debug("tquic: sent RESET_STREAM_AT stream=%llu error=%llu "
		 "final=%llu reliable=%llu\n",
		 stream_id, error_code, frame.final_size, reliable_size);

	return 0;

out_unlock:
	spin_unlock_bh(&conn->lock);
	return ret;
}
EXPORT_SYMBOL_GPL(tquic_send_reset_stream_at);

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
 * Returns: true if reset was completed, false otherwise
 */
bool tquic_stream_check_reliable_reset(struct tquic_connection *conn,
				       struct tquic_stream *stream)
{
	struct tquic_stream_ext *ext;
	struct tquic_reliable_reset_state state;
	u64 bytes_delivered;

	if (!conn || !stream)
		return false;

	ext = stream->ext;
	if (!ext)
		return false;

	/* Check if there's a pending reliable reset */
	if (!tquic_stream_get_reliable_reset(stream, &state))
		return false;

	if (!state.pending)
		return false;

	/* Get current delivered byte count */
	bytes_delivered = ext->recv_next;

	/* Check if we've delivered enough data */
	if (bytes_delivered < state.reliable_size)
		return false;

	/* Complete the reset */
	spin_lock_bh(&conn->lock);

	ext->error_code = state.error_code;
	ext->rst_received = true;
	stream->state = TQUIC_STREAM_RESET_RECVD;

	/* Clear the pending state */
	tquic_stream_clear_reliable_reset(stream);

	spin_unlock_bh(&conn->lock);

	/* Wake up any waiters */
	wake_up_interruptible(&stream->wait);

	pr_debug("tquic: stream %llu reliable reset completed after %llu bytes\n",
		 stream->id, bytes_delivered);

	return true;
}
EXPORT_SYMBOL_GPL(tquic_stream_check_reliable_reset);

/**
 * tquic_stream_set_reliable_reset - Mark stream for deferred reset
 * @stream: Stream to mark
 * @error_code: Error code for reset
 * @final_size: Final size of stream
 * @reliable_size: Bytes to deliver before reset
 *
 * Returns: 0 on success, negative error code on failure
 */
int tquic_stream_set_reliable_reset(struct tquic_stream *stream,
				    u64 error_code, u64 final_size,
				    u64 reliable_size)
{
	struct tquic_stream_ext *ext;
	struct tquic_reliable_reset_state *state;

	if (!stream)
		return -EINVAL;

	ext = stream->ext;
	if (!ext)
		return -EINVAL;

	/*
	 * Allocate or reuse reset state.
	 * For simplicity, we store this in a dynamically allocated structure.
	 * In production, this could be embedded in stream_ext.
	 */
	state = kzalloc(sizeof(*state), GFP_ATOMIC);
	if (!state)
		return -ENOMEM;

	state->pending = true;
	state->error_code = error_code;
	state->final_size = final_size;
	state->reliable_size = reliable_size;
	state->bytes_delivered = ext->recv_next;

	/*
	 * Store state pointer. In a full implementation, this would use
	 * a proper field in tquic_stream_ext. For now, we reuse an
	 * available pointer field or add one.
	 *
	 * Note: This is a simplified approach. Production code should
	 * add a dedicated field to tquic_stream_ext.
	 */
	ext->rst_received = true;  /* Mark that reset is in progress */

	/* Store in error_code field until reset completes */
	ext->error_code = error_code;
	ext->final_size = final_size;

	/*
	 * We track reliable_size via the recv_max field temporarily.
	 * A proper implementation would add a dedicated field.
	 */
	if (ext->recv_max < reliable_size)
		ext->recv_max = reliable_size;

	kfree(state);  /* State is stored in ext fields */

	return 0;
}
EXPORT_SYMBOL_GPL(tquic_stream_set_reliable_reset);

/**
 * tquic_stream_get_reliable_reset - Get pending reliable reset state
 * @stream: Stream to query
 * @state: Output state (may be NULL to just check if pending)
 *
 * Returns: true if reliable reset is pending, false otherwise
 */
bool tquic_stream_get_reliable_reset(struct tquic_stream *stream,
				     struct tquic_reliable_reset_state *state)
{
	struct tquic_stream_ext *ext;

	if (!stream)
		return false;

	ext = stream->ext;
	if (!ext)
		return false;

	/* Check if reset is pending but not yet completed */
	if (!ext->rst_received)
		return false;

	/* Stream already transitioned to reset state - not pending anymore */
	if (stream->state == TQUIC_STREAM_RESET_RECVD ||
	    stream->state == TQUIC_STREAM_CLOSED)
		return false;

	if (state) {
		state->pending = true;
		state->error_code = ext->error_code;
		state->final_size = ext->final_size;
		state->reliable_size = ext->recv_max;  /* Our temp storage */
		state->bytes_delivered = ext->recv_next;
	}

	return true;
}
EXPORT_SYMBOL_GPL(tquic_stream_get_reliable_reset);

/**
 * tquic_stream_clear_reliable_reset - Clear pending reliable reset
 * @stream: Stream to clear
 */
void tquic_stream_clear_reliable_reset(struct tquic_stream *stream)
{
	struct tquic_stream_ext *ext;

	if (!stream)
		return;

	ext = stream->ext;
	if (!ext)
		return;

	/*
	 * The reset state is now handled by the stream's main state.
	 * No additional cleanup needed for our simplified storage approach.
	 */
}
EXPORT_SYMBOL_GPL(tquic_stream_clear_reliable_reset);

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
bool tquic_supports_reliable_reset(struct tquic_connection *conn)
{
	if (!conn)
		return false;

	/*
	 * Check if negotiated params indicate support.
	 * This requires checking the negotiated_params structure.
	 * For simplicity, we check a flag that would be set during
	 * transport parameter negotiation.
	 */
	return conn->reliable_reset_enabled;
}
EXPORT_SYMBOL_GPL(tquic_supports_reliable_reset);

/**
 * tquic_set_reliable_reset_support - Set local reliable reset support
 * @params: Transport parameters to update
 * @supported: Whether to advertise support
 */
void tquic_set_reliable_reset_support(struct tquic_transport_params *params,
				      bool supported)
{
	if (!params)
		return;

	params->reliable_stream_reset = supported;
}
EXPORT_SYMBOL_GPL(tquic_set_reliable_reset_support);

/*
 * =============================================================================
 * INTERNAL HELPERS
 * =============================================================================
 */

/**
 * tquic_stream_lookup_internal - Look up stream by ID (caller holds lock)
 * @conn: Connection
 * @stream_id: Stream ID to find
 *
 * This is an internal helper that assumes the caller holds conn->lock.
 * Returns the stream or NULL if not found.
 */
struct tquic_stream *tquic_stream_lookup_internal(struct tquic_connection *conn,
						  u64 stream_id)
{
	struct rb_node *node;
	struct tquic_stream *stream;

	if (!conn)
		return NULL;

	node = conn->streams.rb_node;
	while (node) {
		stream = rb_entry(node, struct tquic_stream, node);

		if (stream_id < stream->id)
			node = node->rb_left;
		else if (stream_id > stream->id)
			node = node->rb_right;
		else
			return stream;
	}

	return NULL;
}

/**
 * tquic_queue_control_frame - Queue a control frame for transmission
 * @conn: Connection
 * @buf: Encoded frame data (ownership transferred)
 * @len: Length of frame data
 *
 * Queues the frame for transmission on the connection.
 * The buffer is freed after transmission.
 *
 * Returns: 0 on success, negative error code on failure
 */
int tquic_queue_control_frame(struct tquic_connection *conn,
			      u8 *buf, size_t len)
{
	struct sk_buff *skb;

	if (!conn || !buf || len == 0)
		return -EINVAL;

	/*
	 * Allocate an SKB to hold the frame data.
	 * The frame will be transmitted in the next packet.
	 */
	skb = alloc_skb(len + 64, GFP_ATOMIC);
	if (!skb) {
		kfree(buf);
		return -ENOMEM;
	}

	/* Reserve headroom for packet headers */
	skb_reserve(skb, 64);

	/* Copy frame data into SKB */
	skb_put_data(skb, buf, len);

	/* Free the original buffer */
	kfree(buf);

	/* Queue for transmission */
	spin_lock_bh(&conn->lock);
	skb_queue_tail(&conn->control_frames, skb);
	spin_unlock_bh(&conn->lock);

	/* Schedule transmission */
	if (conn->active_path)
		tquic_schedule_transmit(conn);

	return 0;
}

/**
 * tquic_schedule_transmit - Schedule frame transmission
 * @conn: Connection to schedule
 *
 * Triggers the connection's transmit path to send pending frames.
 */
void tquic_schedule_transmit(struct tquic_connection *conn)
{
	if (!conn)
		return;

	/*
	 * This would typically queue work or trigger the send path.
	 * For now, we rely on the existing transmission machinery.
	 */
	queue_work(system_wq, &conn->tx_work);
}
