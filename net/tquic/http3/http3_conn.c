// SPDX-License-Identifier: GPL-2.0-only
/*
 * TQUIC HTTP/3 Connection Management
 *
 * Copyright (c) 2026 Linux Foundation
 *
 * Implementation of HTTP/3 connection state management per RFC 9114.
 *
 * HTTP/3 connections are layered on QUIC connections and require:
 *   - A pair of control streams (one in each direction)
 *   - Optional QPACK encoder/decoder streams
 *   - Settings exchange before any request streams
 *
 * Control streams are unidirectional and MUST be opened before any
 * request streams. SETTINGS MUST be the first frame on each control stream.
 *
 * This file manages:
 *   - HTTP/3 connection lifecycle
 *   - Control stream creation and processing
 *   - Settings exchange
 *   - GOAWAY handling for graceful shutdown
 */

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/errno.h>
#include <linux/spinlock.h>
#include <linux/refcount.h>
#include <net/tquic.h>
#include <net/tquic_http3.h>

#include "http3_frame.h"

/* Control stream receive buffer size */
#define H3_CTRL_STREAM_BUF_SIZE		4096

/* Maximum frame size we accept on control stream */
#define H3_MAX_CTRL_FRAME_SIZE		(64 * 1024)

/*
 * =============================================================================
 * HTTP/3 Connection State Machine
 * =============================================================================
 *
 * States:
 *   IDLE -> CONNECTING: On tquic_h3_conn_create()
 *   CONNECTING -> CONNECTED: After SETTINGS exchanged
 *   CONNECTED -> GOAWAY_SENT: After sending GOAWAY
 *   CONNECTED -> GOAWAY_RECVD: After receiving GOAWAY
 *   GOAWAY_SENT/RECVD -> CLOSED: When draining complete
 */

/**
 * h3_conn_set_state - Update connection state
 * @h3conn: HTTP/3 connection
 * @new_state: New state to transition to
 *
 * Must be called with h3conn->lock held.
 */
static void h3_conn_set_state(struct tquic_http3_conn *h3conn,
			      enum tquic_h3_conn_state new_state)
{
	enum tquic_h3_conn_state old_state = h3conn->state;

	/* Validate transitions */
	switch (old_state) {
	case H3_CONN_IDLE:
		if (new_state != H3_CONN_CONNECTING)
			goto invalid;
		break;

	case H3_CONN_CONNECTING:
		if (new_state != H3_CONN_CONNECTED &&
		    new_state != H3_CONN_CLOSED)
			goto invalid;
		break;

	case H3_CONN_CONNECTED:
		if (new_state != H3_CONN_GOAWAY_SENT &&
		    new_state != H3_CONN_GOAWAY_RECVD &&
		    new_state != H3_CONN_CLOSED)
			goto invalid;
		break;

	case H3_CONN_GOAWAY_SENT:
	case H3_CONN_GOAWAY_RECVD:
		if (new_state != H3_CONN_CLOSED)
			goto invalid;
		break;

	case H3_CONN_CLOSED:
		/* Cannot transition out of CLOSED */
		goto invalid;

	default:
		goto invalid;
	}

	h3conn->state = new_state;
	return;

invalid:
	pr_warn_ratelimited("h3: invalid state transition %d -> %d\n",
			    old_state, new_state);
}

/*
 * =============================================================================
 * Control Stream Management
 * =============================================================================
 */

/**
 * h3_create_control_stream - Create local control stream
 * @h3conn: HTTP/3 connection
 *
 * Opens a unidirectional stream and writes the stream type byte.
 *
 * Returns: 0 on success, negative error on failure.
 */
static int h3_create_control_stream(struct tquic_http3_conn *h3conn)
{
	struct tquic_stream *stream;
	u8 stream_type_buf[1];
	int ret;

	/* Open unidirectional stream */
	stream = tquic_stream_open(h3conn->qconn, false);
	if (IS_ERR(stream))
		return PTR_ERR(stream);

	/* Write stream type byte */
	stream_type_buf[0] = H3_STREAM_TYPE_CONTROL;
	ret = tquic_stream_send(stream, stream_type_buf, 1, false);
	if (ret < 0) {
		tquic_stream_close(stream);
		return ret;
	}

	h3conn->ctrl_stream_local = stream;
	return 0;
}

/**
 * h3_create_qpack_streams - Create QPACK encoder/decoder streams
 * @h3conn: HTTP/3 connection
 *
 * Opens the QPACK encoder and decoder unidirectional streams.
 * These are optional but required if QPACK dynamic table is used.
 *
 * Returns: 0 on success, negative error on failure.
 */
static int h3_create_qpack_streams(struct tquic_http3_conn *h3conn)
{
	struct tquic_stream *enc_stream, *dec_stream;
	u8 stream_type_buf[1];
	int ret;

	/* Skip if dynamic table is disabled */
	if (h3conn->local_settings.qpack_max_table_capacity == 0 &&
	    h3conn->local_settings.qpack_blocked_streams == 0)
		return 0;

	/* Create encoder stream */
	enc_stream = tquic_stream_open(h3conn->qconn, false);
	if (IS_ERR(enc_stream))
		return PTR_ERR(enc_stream);

	stream_type_buf[0] = H3_STREAM_TYPE_QPACK_ENCODER;
	ret = tquic_stream_send(enc_stream, stream_type_buf, 1, false);
	if (ret < 0) {
		tquic_stream_close(enc_stream);
		return ret;
	}

	/* Create decoder stream */
	dec_stream = tquic_stream_open(h3conn->qconn, false);
	if (IS_ERR(dec_stream)) {
		tquic_stream_close(enc_stream);
		return PTR_ERR(dec_stream);
	}

	stream_type_buf[0] = H3_STREAM_TYPE_QPACK_DECODER;
	ret = tquic_stream_send(dec_stream, stream_type_buf, 1, false);
	if (ret < 0) {
		tquic_stream_close(enc_stream);
		tquic_stream_close(dec_stream);
		return ret;
	}

	h3conn->qpack_enc_stream = enc_stream;
	h3conn->qpack_dec_stream = dec_stream;
	return 0;
}

/**
 * h3_send_settings - Send SETTINGS frame on control stream
 * @h3conn: HTTP/3 connection
 *
 * SETTINGS must be the first frame sent on the control stream.
 *
 * Returns: 0 on success, negative error on failure.
 */
static int h3_send_settings(struct tquic_http3_conn *h3conn)
{
	u8 buf[256];  /* Plenty for SETTINGS frame */
	int ret;

	if (!h3conn->ctrl_stream_local)
		return -EINVAL;

	ret = tquic_h3_write_settings_frame(buf, sizeof(buf),
					    &h3conn->local_settings);
	if (ret < 0)
		return ret;

	return tquic_stream_send(h3conn->ctrl_stream_local, buf, ret, false);
}

/*
 * =============================================================================
 * Control Stream Frame Processing
 * =============================================================================
 */

/**
 * h3_process_settings_frame - Process received SETTINGS frame
 * @h3conn: HTTP/3 connection
 * @frame: Parsed SETTINGS frame
 *
 * Returns: 0 on success, negative error on failure.
 */
static int h3_process_settings_frame(struct tquic_http3_conn *h3conn,
				     const struct tquic_h3_frame *frame)
{
	u32 i;

	if (h3conn->peer_settings_received) {
		/* Duplicate SETTINGS is a protocol error */
		return -H3_FRAME_UNEXPECTED;
	}

	/* Process settings entries */
	for (i = 0; i < frame->settings.count; i++) {
		u64 id = frame->settings.entries[i].id;
		u64 value = frame->settings.entries[i].value;

		switch (id) {
		case H3_SETTINGS_QPACK_MAX_TABLE_CAPACITY:
			if (value > H3_MAX_QPACK_TABLE_CAPACITY)
				return -H3_SETTINGS_ERROR;
			h3conn->peer_settings.qpack_max_table_capacity = value;
			break;

		case H3_SETTINGS_MAX_FIELD_SECTION_SIZE:
			h3conn->peer_settings.max_field_section_size = value;
			break;

		case H3_SETTINGS_QPACK_BLOCKED_STREAMS:
			if (value > H3_MAX_QPACK_BLOCKED_STREAMS)
				return -H3_SETTINGS_ERROR;
			h3conn->peer_settings.qpack_blocked_streams = value;
			break;

		default:
			/* Unknown settings are ignored */
			break;
		}
	}

	h3conn->peer_settings_received = true;

	/* Transition to CONNECTED if we were waiting for settings */
	if (h3conn->state == H3_CONN_CONNECTING)
		h3_conn_set_state(h3conn, H3_CONN_CONNECTED);

	return 0;
}

/**
 * h3_process_goaway_frame - Process received GOAWAY frame
 * @h3conn: HTTP/3 connection
 * @frame: Parsed GOAWAY frame
 *
 * Returns: 0 on success, negative error on failure.
 */
static int h3_process_goaway_frame(struct tquic_http3_conn *h3conn,
				   const struct tquic_h3_frame *frame)
{
	u64 goaway_id = frame->goaway.id;

	/*
	 * For clients: ID is the largest stream ID that might be processed
	 * For servers: ID is the largest push ID that might be used
	 */
	if (h3conn->is_server) {
		/* Client sent GOAWAY with stream ID */
		if ((goaway_id & 0x3) != 0) {
			/* Must be client-initiated bidirectional stream */
			return -H3_ID_ERROR;
		}
	} else {
		/* Server sent GOAWAY with push ID */
		/* Push ID must not exceed what we granted */
		if (h3conn->push_enabled && goaway_id > h3conn->max_push_id)
			return -H3_ID_ERROR;
	}

	h3conn->goaway_id = goaway_id;

	if (h3conn->state == H3_CONN_CONNECTED)
		h3_conn_set_state(h3conn, H3_CONN_GOAWAY_RECVD);

	return 0;
}

/**
 * h3_process_max_push_id_frame - Process MAX_PUSH_ID frame
 * @h3conn: HTTP/3 connection
 * @frame: Parsed MAX_PUSH_ID frame
 *
 * Only valid for servers receiving from clients.
 *
 * Returns: 0 on success, negative error on failure.
 */
static int h3_process_max_push_id_frame(struct tquic_http3_conn *h3conn,
					const struct tquic_h3_frame *frame)
{
	if (!h3conn->is_server)
		return -H3_FRAME_UNEXPECTED;

	/* Push ID must not decrease */
	if (frame->max_push_id.push_id < h3conn->max_push_id)
		return -H3_ID_ERROR;

	h3conn->max_push_id = frame->max_push_id.push_id;
	h3conn->push_enabled = true;

	return 0;
}

/**
 * h3_process_cancel_push_frame - Process CANCEL_PUSH frame
 * @h3conn: HTTP/3 connection
 * @frame: Parsed CANCEL_PUSH frame
 *
 * Returns: 0 on success, negative error on failure.
 */
static int h3_process_cancel_push_frame(struct tquic_http3_conn *h3conn,
					const struct tquic_h3_frame *frame)
{
	u64 push_id = frame->cancel_push.push_id;

	/*
	 * The push ID must have been previously promised (server) or
	 * within the max_push_id range (client cancelling).
	 */
	if (!h3conn->is_server) {
		/* Client: we can only cancel pushes we've been promised */
		/* For now, just validate range */
		if (!h3conn->push_enabled)
			return -H3_ID_ERROR;
	} else {
		/* Server: client is cancelling a push we promised */
		if (push_id > h3conn->next_push_id)
			return -H3_ID_ERROR;
	}

	/*
	 * TODO: Actually cancel the push stream / promise.
	 * This requires tracking push state which is not yet implemented.
	 */

	return 0;
}

/**
 * h3_process_control_frame - Process frame from control stream
 * @h3conn: HTTP/3 connection
 * @frame: Parsed frame
 *
 * Dispatches control stream frames to appropriate handlers.
 *
 * Returns: 0 on success, negative error on failure.
 */
static int h3_process_control_frame(struct tquic_http3_conn *h3conn,
				    const struct tquic_h3_frame *frame)
{
	/* Validate frame type is allowed on control stream */
	if (!h3_frame_valid_on_control_stream(frame->type)) {
		return -H3_FRAME_UNEXPECTED;
	}

	switch (frame->type) {
	case H3_FRAME_SETTINGS:
		return h3_process_settings_frame(h3conn, frame);

	case H3_FRAME_GOAWAY:
		return h3_process_goaway_frame(h3conn, frame);

	case H3_FRAME_MAX_PUSH_ID:
		return h3_process_max_push_id_frame(h3conn, frame);

	case H3_FRAME_CANCEL_PUSH:
		return h3_process_cancel_push_frame(h3conn, frame);

	default:
		/* Unknown/GREASE frames are ignored */
		return 0;
	}
}

/*
 * =============================================================================
 * HTTP/3 Connection Lifecycle
 * =============================================================================
 */

/**
 * tquic_h3_conn_create - Create HTTP/3 connection over QUIC
 * @qconn: Underlying QUIC connection
 * @is_server: True if server-side
 * @settings: Local settings (or NULL for defaults)
 * @gfp: Memory allocation flags
 *
 * Returns: HTTP/3 connection on success, ERR_PTR on failure.
 */
struct tquic_http3_conn *tquic_h3_conn_create(struct tquic_connection *qconn,
					      bool is_server,
					      const struct tquic_h3_settings *settings,
					      gfp_t gfp)
{
	struct tquic_http3_conn *h3conn;
	int ret;

	if (!qconn)
		return ERR_PTR(-EINVAL);

	h3conn = kzalloc(sizeof(*h3conn), gfp);
	if (!h3conn)
		return ERR_PTR(-ENOMEM);

	h3conn->qconn = qconn;
	h3conn->is_server = is_server;
	h3conn->state = H3_CONN_IDLE;

	spin_lock_init(&h3conn->lock);
	refcount_set(&h3conn->refcnt, 1);

	/* Initialize local settings */
	if (settings)
		memcpy(&h3conn->local_settings, settings,
		       sizeof(h3conn->local_settings));
	else
		tquic_h3_settings_init(&h3conn->local_settings);

	/* Initialize peer settings to defaults */
	tquic_h3_settings_init(&h3conn->peer_settings);

	/* Transition to CONNECTING */
	h3_conn_set_state(h3conn, H3_CONN_CONNECTING);

	/* Create control stream */
	ret = h3_create_control_stream(h3conn);
	if (ret < 0)
		goto err_free;

	/* Create QPACK streams if needed */
	ret = h3_create_qpack_streams(h3conn);
	if (ret < 0)
		goto err_close_ctrl;

	/* Send our SETTINGS */
	ret = h3_send_settings(h3conn);
	if (ret < 0)
		goto err_close_qpack;

	return h3conn;

err_close_qpack:
	if (h3conn->qpack_enc_stream)
		tquic_stream_close(h3conn->qpack_enc_stream);
	if (h3conn->qpack_dec_stream)
		tquic_stream_close(h3conn->qpack_dec_stream);
err_close_ctrl:
	tquic_stream_close(h3conn->ctrl_stream_local);
err_free:
	kfree(h3conn);
	return ERR_PTR(ret);
}
EXPORT_SYMBOL_GPL(tquic_h3_conn_create);

/**
 * tquic_h3_conn_destroy - Destroy HTTP/3 connection
 * @h3conn: HTTP/3 connection
 */
void tquic_h3_conn_destroy(struct tquic_http3_conn *h3conn)
{
	if (!h3conn)
		return;

	spin_lock_bh(&h3conn->lock);
	h3_conn_set_state(h3conn, H3_CONN_CLOSED);
	spin_unlock_bh(&h3conn->lock);

	/* Close our streams (don't close remote streams) */
	if (h3conn->ctrl_stream_local)
		tquic_stream_close(h3conn->ctrl_stream_local);
	if (h3conn->qpack_enc_stream)
		tquic_stream_close(h3conn->qpack_enc_stream);
	if (h3conn->qpack_dec_stream)
		tquic_stream_close(h3conn->qpack_dec_stream);

	kfree(h3conn);
}
EXPORT_SYMBOL_GPL(tquic_h3_conn_destroy);

/**
 * tquic_h3_conn_put - Decrement reference count
 * @h3conn: HTTP/3 connection
 */
void tquic_h3_conn_put(struct tquic_http3_conn *h3conn)
{
	if (h3conn && refcount_dec_and_test(&h3conn->refcnt))
		tquic_h3_conn_destroy(h3conn);
}
EXPORT_SYMBOL_GPL(tquic_h3_conn_put);

/*
 * =============================================================================
 * Connection Polling and Event Processing
 * =============================================================================
 */

/**
 * h3_poll_control_stream - Process data from remote control stream
 * @h3conn: HTTP/3 connection
 *
 * Returns: 0 on success, negative error on failure.
 */
static int h3_poll_control_stream(struct tquic_http3_conn *h3conn)
{
	u8 buf[H3_CTRL_STREAM_BUF_SIZE];
	struct tquic_h3_frame frame;
	struct tquic_h3_frame_settings_entry entries[H3_MAX_SETTINGS_COUNT];
	int len, consumed;
	int ret = 0;

	if (!h3conn->ctrl_stream_remote)
		return 0;

	/* Read available data */
	len = tquic_stream_recv(h3conn->ctrl_stream_remote, buf, sizeof(buf));
	if (len <= 0)
		return len;

	/* Parse and process frames */
	consumed = 0;
	while (consumed < len) {
		ret = tquic_h3_parse_frame(buf + consumed, len - consumed,
					   &frame, entries,
					   ARRAY_SIZE(entries));
		if (ret == -EAGAIN) {
			/* Need more data, wait for next poll */
			ret = 0;
			break;
		}
		if (ret < 0)
			break;

		consumed += ret;

		ret = h3_process_control_frame(h3conn, &frame);
		if (ret < 0)
			break;
	}

	return ret;
}

/**
 * tquic_h3_conn_poll - Process pending HTTP/3 events
 * @h3conn: HTTP/3 connection
 *
 * Returns: 0 on success, negative error on failure.
 */
int tquic_h3_conn_poll(struct tquic_http3_conn *h3conn)
{
	int ret;

	if (!h3conn)
		return -EINVAL;

	spin_lock_bh(&h3conn->lock);

	if (h3conn->state == H3_CONN_CLOSED) {
		spin_unlock_bh(&h3conn->lock);
		return -ENOTCONN;
	}

	/* Process control stream */
	ret = h3_poll_control_stream(h3conn);

	spin_unlock_bh(&h3conn->lock);

	return ret;
}
EXPORT_SYMBOL_GPL(tquic_h3_conn_poll);

/*
 * =============================================================================
 * Graceful Shutdown (GOAWAY)
 * =============================================================================
 */

/**
 * tquic_h3_send_goaway - Send GOAWAY frame
 * @h3conn: HTTP/3 connection
 * @id: Last stream/push ID to process
 *
 * Returns: 0 on success, negative error on failure.
 */
int tquic_h3_send_goaway(struct tquic_http3_conn *h3conn, u64 id)
{
	u8 buf[32];
	int len;
	int ret;

	if (!h3conn || !h3conn->ctrl_stream_local)
		return -EINVAL;

	spin_lock_bh(&h3conn->lock);

	if (h3conn->state != H3_CONN_CONNECTED) {
		spin_unlock_bh(&h3conn->lock);
		return -EINVAL;
	}

	len = tquic_h3_write_goaway_frame(buf, sizeof(buf), id);
	if (len < 0) {
		spin_unlock_bh(&h3conn->lock);
		return len;
	}

	ret = tquic_stream_send(h3conn->ctrl_stream_local, buf, len, false);
	if (ret < 0) {
		spin_unlock_bh(&h3conn->lock);
		return ret;
	}

	h3conn->goaway_id = id;
	h3_conn_set_state(h3conn, H3_CONN_GOAWAY_SENT);

	spin_unlock_bh(&h3conn->lock);

	return 0;
}
EXPORT_SYMBOL_GPL(tquic_h3_send_goaway);

/**
 * tquic_h3_set_max_push_id - Set maximum push ID (client only)
 * @h3conn: HTTP/3 connection
 * @push_id: Maximum push ID to allow
 *
 * Returns: 0 on success, negative error on failure.
 */
int tquic_h3_set_max_push_id(struct tquic_http3_conn *h3conn, u64 push_id)
{
	u8 buf[32];
	int len;
	int ret;

	if (!h3conn || !h3conn->ctrl_stream_local)
		return -EINVAL;

	/* Only clients send MAX_PUSH_ID */
	if (h3conn->is_server)
		return -EINVAL;

	spin_lock_bh(&h3conn->lock);

	if (h3conn->state != H3_CONN_CONNECTED) {
		spin_unlock_bh(&h3conn->lock);
		return -EINVAL;
	}

	/* Push ID must not decrease */
	if (h3conn->push_enabled && push_id < h3conn->max_push_id) {
		spin_unlock_bh(&h3conn->lock);
		return -EINVAL;
	}

	len = tquic_h3_write_max_push_id_frame(buf, sizeof(buf), push_id);
	if (len < 0) {
		spin_unlock_bh(&h3conn->lock);
		return len;
	}

	ret = tquic_stream_send(h3conn->ctrl_stream_local, buf, len, false);
	if (ret < 0) {
		spin_unlock_bh(&h3conn->lock);
		return ret;
	}

	h3conn->max_push_id = push_id;
	h3conn->push_enabled = true;

	spin_unlock_bh(&h3conn->lock);

	return 0;
}
EXPORT_SYMBOL_GPL(tquic_h3_set_max_push_id);

/*
 * =============================================================================
 * Settings Access
 * =============================================================================
 */

/**
 * tquic_h3_get_peer_settings - Get peer's settings
 * @h3conn: HTTP/3 connection
 * @settings: Output parameter for settings
 *
 * Returns: 0 on success, -EAGAIN if settings not yet received.
 */
int tquic_h3_get_peer_settings(struct tquic_http3_conn *h3conn,
			       struct tquic_h3_settings *settings)
{
	if (!h3conn || !settings)
		return -EINVAL;

	spin_lock_bh(&h3conn->lock);

	if (!h3conn->peer_settings_received) {
		spin_unlock_bh(&h3conn->lock);
		return -EAGAIN;
	}

	memcpy(settings, &h3conn->peer_settings, sizeof(*settings));

	spin_unlock_bh(&h3conn->lock);

	return 0;
}
EXPORT_SYMBOL_GPL(tquic_h3_get_peer_settings);

/*
 * =============================================================================
 * Frame Sending Helper
 * =============================================================================
 */

/**
 * tquic_h3_send_frame - Send HTTP/3 frame on stream
 * @h3conn: HTTP/3 connection
 * @stream: QUIC stream to send on
 * @frame: Frame to send
 *
 * Returns: 0 on success, negative error on failure.
 */
int tquic_h3_send_frame(struct tquic_http3_conn *h3conn,
			struct tquic_stream *stream,
			const struct tquic_h3_frame *frame)
{
	u8 *buf;
	size_t size;
	int ret;

	if (!h3conn || !stream || !frame)
		return -EINVAL;

	size = tquic_h3_frame_size(frame);
	if (size == 0)
		return -EINVAL;

	buf = kmalloc(size, GFP_KERNEL);
	if (!buf)
		return -ENOMEM;

	ret = tquic_h3_write_frame(buf, size, frame);
	if (ret < 0) {
		kfree(buf);
		return ret;
	}

	ret = tquic_stream_send(stream, buf, ret, false);

	kfree(buf);
	return ret < 0 ? ret : 0;
}
EXPORT_SYMBOL_GPL(tquic_h3_send_frame);

/**
 * tquic_h3_write_frame - Write generic frame to buffer
 * @buf: Output buffer
 * @len: Buffer length
 * @frame: Frame to write
 *
 * Returns: Bytes written on success, negative error on failure.
 */
int tquic_h3_write_frame(u8 *buf, size_t len,
			 const struct tquic_h3_frame *frame)
{
	if (!buf || !frame)
		return -EINVAL;

	switch (frame->type) {
	case H3_FRAME_DATA:
		return tquic_h3_write_data_frame(buf, len,
						 frame->data.data,
						 frame->data.len);

	case H3_FRAME_HEADERS:
		return tquic_h3_write_headers_frame(buf, len,
						    frame->headers.data,
						    frame->headers.len);

	case H3_FRAME_CANCEL_PUSH:
		return tquic_h3_write_cancel_push_frame(buf, len,
							frame->cancel_push.push_id);

	case H3_FRAME_GOAWAY:
		return tquic_h3_write_goaway_frame(buf, len, frame->goaway.id);

	case H3_FRAME_MAX_PUSH_ID:
		return tquic_h3_write_max_push_id_frame(buf, len,
							frame->max_push_id.push_id);

	case H3_FRAME_PUSH_PROMISE:
		return tquic_h3_write_push_promise_frame(buf, len,
							 frame->push_promise.push_id,
							 frame->push_promise.data,
							 frame->push_promise.len);

	default:
		return -EINVAL;
	}
}
EXPORT_SYMBOL_GPL(tquic_h3_write_frame);

/*
 * =============================================================================
 * Module Initialization
 * =============================================================================
 */

/**
 * tquic_http3_init - Initialize HTTP/3 subsystem
 */
int __init tquic_http3_init(void)
{
	pr_info("TQUIC HTTP/3: Initializing (RFC 9114)\n");
	return 0;
}
EXPORT_SYMBOL_GPL(tquic_http3_init);

/**
 * tquic_http3_exit - Cleanup HTTP/3 subsystem
 */
void __exit tquic_http3_exit(void)
{
	pr_info("TQUIC HTTP/3: Exiting\n");
}
EXPORT_SYMBOL_GPL(tquic_http3_exit);

MODULE_DESCRIPTION("TQUIC HTTP/3 Connection Management");
MODULE_LICENSE("GPL");
