// SPDX-License-Identifier: GPL-2.0-only
/*
 * TQUIC: HTTP/3 Integration Layer
 *
 * Copyright (c) 2026 Justin Adams <spotty118@gmail.com>
 * Kernel implementation by Justin Adams <spotty118@gmail.com>
 *
 * This file wires the HTTP/3 subsystem (RFC 9114) into the TQUIC
 * connection lifecycle.  It is the single point where:
 *
 *   - tquic_h3_conn_create/destroy/poll are called when a QUIC
 *     connection upgrades to HTTP/3
 *   - Incoming streams are accepted and dispatched to h3_stream_accept()
 *   - Received h3 frames are routed to h3_control_recv_frame(),
 *     h3_stream_recv_headers(), h3_stream_recv_data()
 *   - Outgoing requests/responses call h3_request_send_headers/data/finish
 *     and the symmetric h3_response_* variants
 *   - Push streams are created and cancelled via h3_stream_create_push(),
 *     h3_push_promise_send(), h3_push_cancel()
 *   - WebTransport sessions are initialised and torn down
 *   - QPACK context is allocated per connection and used for encode/decode
 *   - HTTP/3 priorities (RFC 9218) are initialised per stream
 *
 * Only CONFIG_TQUIC_HTTP3-guarded code lives here; the file compiles to
 * nothing when HTTP/3 is disabled.
 */

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/errno.h>
#include <linux/string.h>
#include <net/tquic.h>
#include <net/tquic_http3.h>

#include "http3/http3_stream.h"
#include "http3/http3_priority.h"
#include "http3/qpack.h"
#include "http3/webtransport.h"

#ifdef CONFIG_TQUIC_HTTP3

/*
 * =============================================================================
 * HTTP/3 Connection Lifecycle
 * =============================================================================
 *
 * Called by tquic_main.c once the QUIC handshake has completed and the
 * application has negotiated the "h3" ALPN token.
 */

/**
 * tquic_h3_connection_upgrade - Upgrade a QUIC connection to HTTP/3
 * @qconn:    Established QUIC connection
 * @is_server: True for server-side connections
 *
 * Creates both the low-level h3_connection (stream management) and the
 * high-level tquic_http3_conn (frame / settings / GOAWAY state).  On
 * success the two objects are cross-linked via qconn->h3conn.
 *
 * Returns: 0 on success, negative errno on failure.
 */
int tquic_h3_connection_upgrade(struct tquic_connection *qconn, bool is_server)
{
	struct h3_connection *h3conn;
	struct tquic_http3_conn *tconn;
	int ret;

	if (!qconn)
		return -EINVAL;

	/* Low-level stream / control stream management */
	h3conn = h3_connection_create(qconn, is_server);
	if (!h3conn)
		return -ENOMEM;

	ret = h3_connection_open_control_streams(h3conn);
	if (ret)
		goto err_destroy_h3conn;

	ret = h3_connection_send_settings(h3conn);
	if (ret)
		goto err_destroy_h3conn;

	/* High-level connection object (settings, GOAWAY, push) */
	tconn = tquic_h3_conn_create(qconn, is_server, NULL, GFP_KERNEL);
	if (IS_ERR(tconn)) {
		ret = PTR_ERR(tconn);
		goto err_destroy_h3conn;
	}

	/* Initialise per-connection priority state (RFC 9218) */
	ret = http3_priority_state_init(qconn);
	if (ret) {
		/*
		 * Priority support is optional – a failure here does not
		 * prevent HTTP/3 from functioning, so log and continue.
		 */
		pr_warn_ratelimited("tquic_h3: priority init failed: %d\n",
				    ret);
		ret = 0;
	}

	qconn->h3_low  = h3conn;
	qconn->h3conn  = tconn;

	pr_debug("tquic_h3: connection upgraded (server=%d)\n", is_server);
	return 0;

err_destroy_h3conn:
	h3_connection_destroy(h3conn);
	return ret;
}
EXPORT_SYMBOL_GPL(tquic_h3_connection_upgrade);

/**
 * tquic_h3_connection_close - Tear down HTTP/3 state for a closing connection
 * @qconn: QUIC connection being closed
 *
 * Initiates graceful shutdown (GOAWAY), then destroys all HTTP/3 state.
 * Must be called before the QUIC connection itself is freed.
 */
void tquic_h3_connection_close(struct tquic_connection *qconn)
{
	struct tquic_http3_conn *tconn;
	struct h3_connection *h3conn;

	if (!qconn)
		return;

	tconn = qconn->h3conn;
	h3conn = qconn->h3_low;

	if (tconn) {
		/*
		 * Send GOAWAY to signal peer about graceful shutdown before
		 * destroying the connection object.
		 */
		if (!tquic_h3_is_shutting_down(tconn))
			tquic_h3_graceful_shutdown(tconn);

		/* Drop our reference – destroys if refcount reaches zero */
		tquic_h3_conn_put(tconn);
		qconn->h3conn = NULL;
	}

	if (h3conn) {
		if (!h3_connection_is_going_away(h3conn)) {
			u64 last_id = h3conn->goaway_id;

			h3_connection_send_goaway(h3conn, last_id);
		}
		h3_connection_destroy(h3conn);
		qconn->h3_low = NULL;
	}

	/* Destroy per-connection priority state */
	http3_priority_state_destroy(qconn);

	pr_debug("tquic_h3: connection closed\n");
}
EXPORT_SYMBOL_GPL(tquic_h3_connection_close);

/*
 * =============================================================================
 * HTTP/3 Connection Polling
 * =============================================================================
 *
 * tquic_h3_poll is called from the TQUIC output workqueue after packets are
 * drained, allowing HTTP/3 to process any pending control-stream frames.
 */

/**
 * tquic_h3_poll - Process pending HTTP/3 events on a connection
 * @qconn: QUIC connection
 *
 * Returns: 0 on success, negative errno on failure.
 */
int tquic_h3_poll(struct tquic_connection *qconn)
{
	struct tquic_http3_conn *tconn;

	if (!qconn)
		return -EINVAL;

	tconn = qconn->h3conn;
	if (!tconn)
		return 0;

	return tquic_h3_conn_poll(tconn);
}
EXPORT_SYMBOL_GPL(tquic_h3_poll);

/*
 * =============================================================================
 * Stream Acceptance and Type Dispatch
 * =============================================================================
 */

/**
 * tquic_h3_accept_stream - Accept an incoming stream into the HTTP/3 layer
 * @qconn:  QUIC connection
 * @qstream: Newly accepted QUIC stream
 *
 * Creates the h3_stream wrapper and, for unidirectional streams, reads the
 * stream-type varint to learn whether it is a control, push, or QPACK stream.
 *
 * Returns: 0 on success, negative errno on failure.
 */
int tquic_h3_accept_stream(struct tquic_connection *qconn,
			   struct tquic_stream *qstream)
{
	struct h3_connection *h3conn;
	struct h3_stream *h3s;
	u8 type_buf[8];
	u64 type_val;
	int consumed;
	int ret;

	if (!qconn || !qstream)
		return -EINVAL;

	h3conn = qconn->h3_low;
	if (!h3conn)
		return -ENOENT;

	/* Wrap the QUIC stream in an HTTP/3 stream object */
	h3s = h3_stream_accept(h3conn, qstream);
	if (IS_ERR(h3s))
		return PTR_ERR(h3s);

	/* Unidirectional streams must start with a stream-type varint */
	if (h3s->is_uni) {
		ret = tquic_stream_recv(qstream, type_buf, sizeof(type_buf));
		if (ret <= 0) {
			h3_stream_close(h3conn, h3s);
			return ret ? ret : -EAGAIN;
		}

		consumed = h3_stream_recv_type(h3s, type_buf, ret, &type_val);
		if (consumed < 0) {
			h3_stream_close(h3conn, h3s);
			return consumed;
		}

		pr_debug("tquic_h3: uni stream type=%llu on stream %llu\n",
			 type_val, qstream->id);
	} else {
		/* Bidirectional streams: initialise priority (RFC 9218) */
		struct http3_priority def_pri;

		http3_priority_default(&def_pri);
		ret = http3_priority_stream_init(qconn, qstream->id, &def_pri);
		if (ret && ret != -ENOSPC)
			pr_debug("tquic_h3: priority_stream_init err=%d\n",
				 ret);
	}

	/* Validate that the first frame is appropriate for stream type */
	ret = h3_stream_validate_frame(h3s, H3_FRAME_HEADERS);
	if (ret && !h3s->is_uni) {
		pr_debug("tquic_h3: frame validation err=%d\n", ret);
		/* Non-fatal for accept; specific frames will be rejected later */
	}

	h3_stream_put(h3s);
	return 0;
}
EXPORT_SYMBOL_GPL(tquic_h3_accept_stream);

/*
 * =============================================================================
 * Request Creation (Client Side)
 * =============================================================================
 */

/**
 * tquic_h3_create_request - Open a new HTTP/3 request stream
 * @qconn:      QUIC connection
 * @headers:    QPACK-compressed request headers
 * @headers_len: Length of @headers
 * @stream_id_out: Receives the new stream's QUIC stream ID
 *
 * Opens a client-initiated bidirectional stream, validates the stream ID,
 * sends the HEADERS frame, and registers priority state for the stream.
 *
 * Returns: 0 on success, negative errno on failure.
 */
int tquic_h3_create_request(struct tquic_connection *qconn,
			    const void *headers, size_t headers_len,
			    u64 *stream_id_out)
{
	struct h3_connection *h3conn;
	struct tquic_http3_conn *tconn;
	struct h3_stream *h3s;
	struct http3_priority def_pri;
	int ret;

	if (!qconn || !headers || headers_len == 0)
		return -EINVAL;

	h3conn = qconn->h3_low;
	tconn  = qconn->h3conn;
	if (!h3conn || !tconn)
		return -ENOENT;

	/* Respect GOAWAY – no new streams after shutdown */
	if (h3_connection_is_going_away(h3conn))
		return -ECONNRESET;

	/* Verify connection-level can-create check (RFC 9114 Section 5.2) */
	if (!tquic_h3_can_create_stream(tconn, 0))
		return -EAGAIN;

	/* Allocate the request stream */
	h3s = h3_stream_create_request(h3conn);
	if (IS_ERR(h3s))
		return PTR_ERR(h3s);

	/* Send request HEADERS frame */
	ret = h3_request_send_headers(h3s, headers, headers_len);
	if (ret) {
		h3_stream_close(h3conn, h3s);
		return ret;
	}

	/* Register RFC 9218 default priority */
	http3_priority_default(&def_pri);
	http3_priority_stream_init(qconn, h3s->base->id, &def_pri);

	/* Transition state machine */
	h3_stream_transition_state(h3s, H3_REQUEST_HEADERS_RECEIVED);

	if (stream_id_out)
		*stream_id_out = h3s->base->id;

	pr_debug("tquic_h3: created request stream_id=%llu\n",
		 h3s->base->id);

	h3_stream_put(h3s);
	return 0;
}
EXPORT_SYMBOL_GPL(tquic_h3_create_request);

/**
 * tquic_h3_send_request_body - Send DATA frame on a request stream
 * @qconn:     QUIC connection
 * @stream_id: Request stream ID
 * @data:      Body data to send
 * @data_len:  Length of @data
 * @fin:       If true, send FIN after this data
 *
 * Returns: 0 on success, negative errno on failure.
 */
int tquic_h3_send_request_body(struct tquic_connection *qconn,
			       u64 stream_id, const void *data,
			       size_t data_len, bool fin)
{
	struct h3_connection *h3conn;
	struct h3_stream *h3s;
	int ret;

	if (!qconn || !data || data_len == 0)
		return -EINVAL;

	h3conn = qconn->h3_low;
	if (!h3conn)
		return -ENOENT;

	h3s = h3_stream_lookup(h3conn, stream_id);
	if (!h3s)
		return -ENOENT;

	ret = h3_request_send_data(h3s, data, data_len);
	if (ret == 0 && fin)
		ret = h3_request_finish(h3s);

	h3_stream_put(h3s);
	return ret;
}
EXPORT_SYMBOL_GPL(tquic_h3_send_request_body);

/*
 * =============================================================================
 * Response Sending (Server Side)
 * =============================================================================
 */

/**
 * tquic_h3_send_response - Send an HTTP/3 response on a request stream
 * @qconn:       QUIC connection
 * @stream_id:   Request stream ID to respond on
 * @headers:     QPACK-compressed response headers
 * @headers_len: Length of @headers
 * @body:        Response body (may be NULL for header-only responses)
 * @body_len:    Length of @body
 * @trailers:    Optional QPACK-compressed trailing headers (may be NULL)
 * @trailers_len: Length of @trailers
 *
 * Sends HEADERS [+ DATA [+ trailing HEADERS]] + FIN in one call.
 *
 * Returns: 0 on success, negative errno on failure.
 */
int tquic_h3_send_response(struct tquic_connection *qconn, u64 stream_id,
			   const void *headers, size_t headers_len,
			   const void *body, size_t body_len,
			   const void *trailers, size_t trailers_len)
{
	struct h3_connection *h3conn;
	struct h3_stream *h3s;
	int ret;

	if (!qconn || !headers || headers_len == 0)
		return -EINVAL;

	h3conn = qconn->h3_low;
	if (!h3conn)
		return -ENOENT;

	h3s = h3_stream_lookup(h3conn, stream_id);
	if (!h3s)
		return -ENOENT;

	ret = h3_response_send_headers(h3s, headers, headers_len);
	if (ret)
		goto out;

	if (body && body_len > 0) {
		ret = h3_response_send_data(h3s, body, body_len);
		if (ret)
			goto out;
	}

	if (trailers && trailers_len > 0) {
		ret = h3_response_send_trailers(h3s, trailers, trailers_len);
		if (ret)
			goto out;
	}

	ret = h3_response_finish(h3s);

out:
	h3_stream_put(h3s);
	return ret;
}
EXPORT_SYMBOL_GPL(tquic_h3_send_response);

/*
 * =============================================================================
 * Control Stream Frame Dispatch (Input Path)
 * =============================================================================
 */

/**
 * tquic_h3_recv_control_frame - Process a received HTTP/3 control frame
 * @qconn:      QUIC connection
 * @stream_id:  Control stream ID
 * @frame_type: HTTP/3 frame type
 * @data:       Frame payload bytes
 * @data_len:   Payload length
 *
 * Routes the frame to h3_control_recv_frame() and, for PRIORITY_UPDATE
 * frames, also invokes tquic_h3_handle_priority_update().
 *
 * Returns: 0 on success, negative errno on failure.
 */
int tquic_h3_recv_control_frame(struct tquic_connection *qconn,
				u64 stream_id, u64 frame_type,
				const u8 *data, size_t data_len)
{
	struct h3_connection *h3conn;
	struct tquic_http3_conn *tconn;
	struct h3_stream *ctrl_stream;
	int ret;

	if (!qconn)
		return -EINVAL;

	h3conn = qconn->h3_low;
	tconn  = qconn->h3conn;
	if (!h3conn)
		return -ENOENT;

	ctrl_stream = h3_stream_lookup(h3conn, stream_id);
	if (!ctrl_stream)
		return -ENOENT;

	ret = h3_control_recv_frame(ctrl_stream, frame_type, data, data_len);
	if (ret) {
		const char *name = h3_error_name((u64)(-ret));

		pr_debug("tquic_h3: control frame error=%s\n", name);

		if (h3_is_connection_error((u64)(-ret)) && tconn)
			tquic_h3_send_goaway(tconn, h3conn->goaway_id);
	}

	h3_stream_put(ctrl_stream);

	/* PRIORITY_UPDATE frames require additional handling */
	if (frame_type == TQUIC_H3_FRAME_PRIORITY_UPDATE && tconn && data)
		tquic_h3_handle_priority_update(tconn, data, data_len);

	return ret;
}
EXPORT_SYMBOL_GPL(tquic_h3_recv_control_frame);

/*
 * =============================================================================
 * Request Stream Receive (Input Path)
 * =============================================================================
 */

/**
 * tquic_h3_recv_request_headers - Receive HEADERS frame from request stream
 * @qconn:     QUIC connection
 * @stream_id: Request stream ID
 * @buf:       Output buffer for QPACK-compressed header block
 * @buf_len:   Buffer size
 *
 * Returns: Bytes written to @buf on success, negative errno on failure.
 */
int tquic_h3_recv_request_headers(struct tquic_connection *qconn,
				  u64 stream_id, void *buf, size_t buf_len)
{
	struct h3_connection *h3conn;
	struct h3_stream *h3s;
	int ret;

	if (!qconn || !buf || buf_len == 0)
		return -EINVAL;

	h3conn = qconn->h3_low;
	if (!h3conn)
		return -ENOENT;

	h3s = h3_stream_lookup(h3conn, stream_id);
	if (!h3s)
		return -ENOENT;

	ret = h3_stream_recv_headers(h3s, buf, buf_len);
	h3_stream_put(h3s);
	return ret;
}
EXPORT_SYMBOL_GPL(tquic_h3_recv_request_headers);

/**
 * tquic_h3_recv_request_data - Receive DATA frame from request stream
 * @qconn:     QUIC connection
 * @stream_id: Request stream ID
 * @buf:       Output buffer for body bytes
 * @buf_len:   Buffer size
 *
 * Returns: Bytes written to @buf on success, negative errno on failure.
 */
int tquic_h3_recv_request_data(struct tquic_connection *qconn,
			       u64 stream_id, void *buf, size_t buf_len)
{
	struct h3_connection *h3conn;
	struct h3_stream *h3s;
	int ret;

	if (!qconn || !buf || buf_len == 0)
		return -EINVAL;

	h3conn = qconn->h3_low;
	if (!h3conn)
		return -ENOENT;

	h3s = h3_stream_lookup(h3conn, stream_id);
	if (!h3s)
		return -ENOENT;

	ret = h3_stream_recv_data(h3s, buf, buf_len);
	h3_stream_put(h3s);
	return ret;
}
EXPORT_SYMBOL_GPL(tquic_h3_recv_request_data);

/*
 * =============================================================================
 * Server Push (RFC 9114 Section 4.6)
 * =============================================================================
 */

/**
 * tquic_h3_send_push - Send PUSH_PROMISE and open push stream (server only)
 * @qconn:          QUIC connection
 * @request_stream_id: Stream to send PUSH_PROMISE on
 * @push_headers:   QPACK-compressed pushed request headers
 * @push_hdrs_len:  Length of @push_headers
 * @push_stream_id_out: Receives the new push stream's QUIC stream ID
 *
 * Returns: 0 on success, negative errno on failure.
 */
int tquic_h3_send_push(struct tquic_connection *qconn,
		       u64 request_stream_id,
		       const void *push_headers, size_t push_hdrs_len,
		       u64 *push_stream_id_out)
{
	struct h3_connection *h3conn;
	struct h3_stream *request_h3s;
	struct h3_stream *push_h3s;
	u64 push_id;
	int ret;

	if (!qconn || !push_headers || push_hdrs_len == 0)
		return -EINVAL;

	h3conn = qconn->h3_low;
	if (!h3conn)
		return -ENOENT;

	if (!h3conn->is_server)
		return -EINVAL;

	request_h3s = h3_stream_lookup(h3conn, request_stream_id);
	if (!request_h3s)
		return -ENOENT;

	/* Allocate a push ID */
	if (!h3conn->push_enabled ||
	    h3conn->next_push_id > h3conn->max_push_id) {
		h3_stream_put(request_h3s);
		return -EAGAIN;
	}
	push_id = h3conn->next_push_id++;

	/* Create the push stream first */
	push_h3s = h3_stream_create_push(h3conn, push_id);
	if (IS_ERR(push_h3s)) {
		h3conn->next_push_id--;
		h3_stream_put(request_h3s);
		return PTR_ERR(push_h3s);
	}

	/* Send stream type byte */
	ret = h3_stream_send_type(push_h3s);
	if (ret)
		goto err_close_push;

	/* Send PUSH_PROMISE on the request stream */
	ret = h3_push_promise_send(request_h3s, push_h3s,
				   push_headers, push_hdrs_len);
	if (ret)
		goto err_close_push;

	if (push_stream_id_out)
		*push_stream_id_out = push_h3s->base->id;

	pr_debug("tquic_h3: push_id=%llu push_stream=%llu on req_stream=%llu\n",
		 push_id, push_h3s->base->id, request_stream_id);

	h3_stream_put(push_h3s);
	h3_stream_put(request_h3s);
	return 0;

err_close_push:
	h3_stream_close(h3conn, push_h3s);
	h3conn->next_push_id--;
	h3_stream_put(request_h3s);
	return ret;
}
EXPORT_SYMBOL_GPL(tquic_h3_send_push);

/**
 * tquic_h3_cancel_push_stream - Cancel a server push by push ID
 * @qconn:   QUIC connection
 * @push_id: Push ID to cancel
 *
 * Sends CANCEL_PUSH and closes the push stream if it was already opened.
 *
 * Returns: 0 on success, negative errno on failure.
 */
int tquic_h3_cancel_push_stream(struct tquic_connection *qconn, u64 push_id)
{
	struct h3_connection *h3conn;
	struct h3_stream *push_h3s;
	int ret;

	if (!qconn)
		return -EINVAL;

	h3conn = qconn->h3_low;
	if (!h3conn)
		return -ENOENT;

	/* Send CANCEL_PUSH on the control stream */
	ret = h3_push_cancel(h3conn, push_id);

	/* Close the push stream if already opened */
	push_h3s = h3_stream_lookup_by_push_id(h3conn, push_id);
	if (push_h3s) {
		h3_stream_reset(h3conn, push_h3s, H3_REQUEST_CANCELLED);
		h3_stream_close(h3conn, push_h3s);
		h3_stream_put(push_h3s);
	}

	return ret;
}
EXPORT_SYMBOL_GPL(tquic_h3_cancel_push_stream);

/*
 * =============================================================================
 * QPACK Integration (RFC 9204)
 * =============================================================================
 */

/**
 * tquic_h3_qpack_create - Allocate a QPACK context for a connection
 * @qconn: QUIC connection
 *
 * Creates and attaches a QPACK context that pairs the QUIC connection's
 * encoder/decoder streams.  Must be called after control streams exist.
 *
 * Returns: 0 on success, negative errno on failure.
 */
int tquic_h3_qpack_create(struct tquic_connection *qconn)
{
	struct h3_connection *h3conn;
	struct qpack_context *ctx;
	int ret;

	if (!qconn)
		return -EINVAL;

	h3conn = qconn->h3_low;
	if (!h3conn)
		return -ENOENT;

	ctx = qpack_context_create(qconn, GFP_KERNEL);
	if (IS_ERR(ctx))
		return PTR_ERR(ctx);

	/* Wire QPACK streams: encoder writes to enc stream, decoder to dec */
	if (h3conn->local_qpack_enc && h3conn->local_qpack_dec) {
		ret = qpack_context_set_streams(ctx,
						h3conn->local_qpack_enc->base,
						h3conn->local_qpack_dec->base);
		if (ret) {
			qpack_context_destroy(ctx);
			return ret;
		}
	}

	qconn->qpack_ctx = ctx;

	pr_debug("tquic_h3: QPACK context created for conn %p\n", qconn);
	return 0;
}
EXPORT_SYMBOL_GPL(tquic_h3_qpack_create);

/**
 * tquic_h3_qpack_destroy - Free the QPACK context for a connection
 * @qconn: QUIC connection
 */
void tquic_h3_qpack_destroy(struct tquic_connection *qconn)
{
	if (!qconn || !qconn->qpack_ctx)
		return;

	qpack_context_destroy(qconn->qpack_ctx);
	qconn->qpack_ctx = NULL;
}
EXPORT_SYMBOL_GPL(tquic_h3_qpack_destroy);

/**
 * tquic_h3_qpack_recv_encoder - Process data received on QPACK encoder stream
 * @qconn: QUIC connection
 * @data:  Bytes from peer's encoder stream
 * @len:   Byte count
 *
 * Returns: 0 on success, negative errno on failure.
 */
int tquic_h3_qpack_recv_encoder(struct tquic_connection *qconn,
				const u8 *data, size_t len)
{
	if (!qconn || !qconn->qpack_ctx || !data || len == 0)
		return -EINVAL;

	return qpack_process_encoder_stream(qconn->qpack_ctx, data, len);
}
EXPORT_SYMBOL_GPL(tquic_h3_qpack_recv_encoder);

/**
 * tquic_h3_qpack_recv_decoder - Process data received on QPACK decoder stream
 * @qconn: QUIC connection
 * @data:  Bytes from peer's decoder stream
 * @len:   Byte count
 *
 * Returns: 0 on success, negative errno on failure.
 */
int tquic_h3_qpack_recv_decoder(struct tquic_connection *qconn,
				const u8 *data, size_t len)
{
	if (!qconn || !qconn->qpack_ctx || !data || len == 0)
		return -EINVAL;

	return qpack_process_decoder_stream(qconn->qpack_ctx, data, len);
}
EXPORT_SYMBOL_GPL(tquic_h3_qpack_recv_decoder);

/*
 * =============================================================================
 * WebTransport Integration (RFC 9220)
 * =============================================================================
 */

#ifdef CONFIG_TQUIC_WEBTRANSPORT

/**
 * tquic_h3_webtransport_enable - Enable WebTransport on a connection
 * @qconn: QUIC connection (must already have HTTP/3 state)
 *
 * Creates a WebTransport context and handles the ENABLE_WEBTRANSPORT
 * setting value.
 *
 * Returns: 0 on success, negative errno on failure.
 */
int tquic_h3_webtransport_enable(struct tquic_connection *qconn)
{
	struct tquic_http3_conn *tconn;
	struct webtransport_context *wt_ctx;
	struct tquic_h3_settings peer_settings;
	int ret;

	if (!qconn)
		return -EINVAL;

	tconn = qconn->h3conn;
	if (!tconn)
		return -ENOENT;

	ret = webtransport_init();
	if (ret)
		return ret;

	wt_ctx = webtransport_context_create(tconn, GFP_KERNEL);
	if (IS_ERR(wt_ctx)) {
		webtransport_exit();
		return PTR_ERR(wt_ctx);
	}

	/* Notify WebTransport layer of peer settings */
	if (tquic_h3_get_peer_settings(tconn, &peer_settings) == 0) {
		ret = webtransport_handle_settings(wt_ctx, &peer_settings);
		if (ret) {
			webtransport_context_destroy(wt_ctx);
			webtransport_exit();
			return ret;
		}
	}

	qconn->wt_ctx = wt_ctx;
	pr_debug("tquic_h3: WebTransport enabled on conn %p\n", qconn);
	return 0;
}
EXPORT_SYMBOL_GPL(tquic_h3_webtransport_enable);

/**
 * tquic_h3_webtransport_disable - Disable and free WebTransport state
 * @qconn: QUIC connection
 */
void tquic_h3_webtransport_disable(struct tquic_connection *qconn)
{
	if (!qconn || !qconn->wt_ctx)
		return;

	webtransport_context_destroy(qconn->wt_ctx);
	qconn->wt_ctx = NULL;
	webtransport_exit();
}
EXPORT_SYMBOL_GPL(tquic_h3_webtransport_disable);

/**
 * tquic_h3_webtransport_connect - Initiate a WebTransport session (client)
 * @qconn:       QUIC connection with WebTransport enabled
 * @url:         Target URL for the CONNECT request
 * @url_len:     Length of @url
 * @session_out: Receives the new session pointer
 *
 * Returns: 0 on success, negative errno on failure.
 */
int tquic_h3_webtransport_connect(struct tquic_connection *qconn,
				  const char *url, size_t url_len,
				  struct webtransport_session **session_out)
{
	struct webtransport_context *wt_ctx;
	struct webtransport_session *session;

	if (!qconn || !url || url_len == 0 || !session_out)
		return -EINVAL;

	wt_ctx = qconn->wt_ctx;
	if (!wt_ctx)
		return -ENOENT;

	session = webtransport_connect(wt_ctx, url, url_len);
	if (IS_ERR(session))
		return PTR_ERR(session);

	*session_out = session;
	return 0;
}
EXPORT_SYMBOL_GPL(tquic_h3_webtransport_connect);

/**
 * tquic_h3_webtransport_accept - Accept an incoming WebTransport session
 * @qconn:       QUIC connection with WebTransport enabled
 * @stream_id:   Request stream that carries the CONNECT
 * @session_out: Receives the accepted session pointer
 *
 * Returns: 0 on success, negative errno on failure.
 */
int tquic_h3_webtransport_accept(struct tquic_connection *qconn,
				 u64 stream_id,
				 struct webtransport_session **session_out)
{
	struct webtransport_context *wt_ctx;
	struct webtransport_session *session;

	if (!qconn || !session_out)
		return -EINVAL;

	wt_ctx = qconn->wt_ctx;
	if (!wt_ctx)
		return -ENOENT;

	session = webtransport_accept(wt_ctx, stream_id);
	if (IS_ERR(session))
		return PTR_ERR(session);

	*session_out = session;
	return 0;
}
EXPORT_SYMBOL_GPL(tquic_h3_webtransport_accept);

/**
 * tquic_h3_webtransport_close_session - Close a WebTransport session
 * @session:    Session to close
 * @error_code: Application error code
 * @reason:     Human-readable reason string (may be NULL)
 * @reason_len: Length of @reason
 *
 * Returns: 0 on success, negative errno on failure.
 */
int tquic_h3_webtransport_close_session(struct webtransport_session *session,
					u32 error_code,
					const char *reason, size_t reason_len)
{
	int ret;

	if (!session)
		return -EINVAL;

	ret = webtransport_session_close(session, error_code,
					 reason, reason_len);

	/* Release our reference (obtained at connect/accept) */
	webtransport_session_put(session);
	return ret;
}
EXPORT_SYMBOL_GPL(tquic_h3_webtransport_close_session);

/**
 * tquic_h3_webtransport_dispatch_stream - Route an incoming WT stream
 * @qconn:     QUIC connection
 * @stream_id: Incoming stream ID
 *
 * Called from tquic_input.c when a new stream is identified as belonging
 * to a WebTransport session.
 *
 * Returns: 0 on success, negative errno on failure.
 */
int tquic_h3_webtransport_dispatch_stream(struct tquic_connection *qconn,
					  u64 stream_id)
{
	struct webtransport_context *wt_ctx;
	struct tquic_stream *qstream;
	int ret;

	if (!qconn)
		return -EINVAL;

	wt_ctx = qconn->wt_ctx;
	if (!wt_ctx)
		return -ENOENT;

	qstream = tquic_stream_find(qconn, stream_id);
	if (!qstream)
		return -ENOENT;

	ret = webtransport_handle_stream(wt_ctx, qstream);
	return ret;
}
EXPORT_SYMBOL_GPL(tquic_h3_webtransport_dispatch_stream);

#endif /* CONFIG_TQUIC_WEBTRANSPORT */

/*
 * =============================================================================
 * Priority Helpers (RFC 9218) – Scheduler Integration
 * =============================================================================
 */

/**
 * tquic_h3_priority_next_stream - Get highest-priority stream with data
 * @qconn: QUIC connection
 *
 * Returns the stream ID of the next stream to schedule, or 0 if none.
 * Used by the TQUIC output scheduler to pick the next stream to drain.
 */
u64 tquic_h3_priority_next_stream(struct tquic_connection *qconn)
{
	if (!qconn)
		return 0;

	return http3_priority_get_next_stream(qconn, false);
}
EXPORT_SYMBOL_GPL(tquic_h3_priority_next_stream);

/**
 * tquic_h3_priority_close_stream - Remove stream from priority state
 * @qconn:     QUIC connection
 * @stream_id: Stream being closed
 */
void tquic_h3_priority_close_stream(struct tquic_connection *qconn,
				    u64 stream_id)
{
	if (!qconn)
		return;

	http3_priority_stream_destroy(qconn, stream_id);
}
EXPORT_SYMBOL_GPL(tquic_h3_priority_close_stream);

/**
 * tquic_h3_priority_debug_dump - Dump priority state for debugging
 * @qconn: QUIC connection
 */
void tquic_h3_priority_debug_dump(struct tquic_connection *qconn)
{
	if (!qconn)
		return;

	http3_priority_dump(qconn);
}
EXPORT_SYMBOL_GPL(tquic_h3_priority_debug_dump);

/**
 * tquic_h3_priority_query_stats - Retrieve priority statistics
 * @qconn: QUIC connection
 * @stats: Output buffer for statistics
 */
void tquic_h3_priority_query_stats(struct tquic_connection *qconn,
				   struct http3_priority_stats *stats)
{
	if (!stats)
		return;

	http3_priority_get_stats(qconn, stats);
}
EXPORT_SYMBOL_GPL(tquic_h3_priority_query_stats);

/*
 * =============================================================================
 * Stream Reference Counting and Low-Level Push Control
 * =============================================================================
 *
 * h3_stream_get() is the refcount acquire counterpart of h3_stream_put().
 * Callers that look up a stream and then hand it to another subsystem (e.g.
 * for asynchronous data delivery) must grab an extra reference so the stream
 * is not freed while in transit.
 *
 * h3_connection_send_max_push_id() is the low-level (http3_stream.c) frame
 * sender for MAX_PUSH_ID.  The high-level path in http3_conn.c
 * (tquic_h3_set_max_push_id) is already wired via
 * tquic_h3_client_set_max_push_id(); this function is called from the
 * connection upgrade path to pre-authorise the first batch of server pushes.
 */

/**
 * tquic_h3_conn_force_destroy - Forcefully destroy an HTTP/3 connection object
 * @qconn: QUIC connection
 *
 * Calls tquic_h3_conn_destroy() directly to tear down all connection state
 * without waiting for the refcount to reach zero.  This is used in error
 * recovery paths where tquic_h3_conn_put() would not immediately trigger
 * destruction (e.g. when another subsystem holds a reference).
 *
 * The caller must guarantee that no other thread uses @qconn->h3conn after
 * this call.
 */
void tquic_h3_conn_force_destroy(struct tquic_connection *qconn)
{
	struct tquic_http3_conn *tconn;

	if (!qconn)
		return;

	tconn = qconn->h3conn;
	if (!tconn)
		return;

	qconn->h3conn = NULL;
	tquic_h3_conn_destroy(tconn);
}
EXPORT_SYMBOL_GPL(tquic_h3_conn_force_destroy);

/**
 * tquic_h3_send_stream_priority_update - Send PRIORITY_UPDATE for a stream
 * @qconn:     QUIC connection
 * @stream_id: Request stream whose priority is changing
 * @pri:       New RFC 9218 priority parameters
 *
 * Encodes and sends a PRIORITY_UPDATE frame (RFC 9218 §4.2) on the HTTP/3
 * control stream, informing the peer about a priority change for @stream_id.
 * Uses the high-level tquic_http3_conn path (not to be confused with the
 * http3_priority_send_update helper which operates on the QUIC connection).
 *
 * Returns: 0 on success, negative errno on failure.
 */
int tquic_h3_send_stream_priority_update(struct tquic_connection *qconn,
					 u64 stream_id,
					 const struct tquic_h3_priority *pri)
{
	struct tquic_http3_conn *tconn;

	if (!qconn || !pri)
		return -EINVAL;

	tconn = qconn->h3conn;
	if (!tconn)
		return -ENOENT;

	return tquic_h3_send_priority_update(tconn, stream_id, pri);
}
EXPORT_SYMBOL_GPL(tquic_h3_send_stream_priority_update);

/**
 * tquic_h3_stream_ref - Acquire an extra reference to an h3_stream
 * @h3conn:  HTTP/3 connection owning the stream
 * @stream_id: Stream ID to reference
 *
 * Looks up the stream by ID and calls h3_stream_get() to increment the
 * refcount.  The caller must call h3_stream_put() when done.
 *
 * Returns: Pointer to the stream (with incremented refcount), or NULL.
 */
struct h3_stream *tquic_h3_stream_ref(struct tquic_connection *qconn,
				      u64 stream_id)
{
	struct h3_connection *h3conn;
	struct h3_stream *h3s;

	if (!qconn)
		return NULL;

	h3conn = qconn->h3_low;
	if (!h3conn)
		return NULL;

	h3s = h3_stream_lookup(h3conn, stream_id);
	if (!h3s)
		return NULL;

	/* h3_stream_lookup already holds one ref; grab a second for the caller */
	h3_stream_get(h3s);
	return h3s;
}
EXPORT_SYMBOL_GPL(tquic_h3_stream_ref);

/**
 * tquic_h3_advertise_max_push_id - Client advertises max push ID at upgrade
 * @qconn:   QUIC connection (client only)
 * @push_id: Initial maximum push ID to send to the server
 *
 * Sends a MAX_PUSH_ID frame on the low-level control stream immediately after
 * HTTP/3 upgrade, authorising the server to begin push streams.  Called from
 * tquic_h3_connection_upgrade() when the application has configured server
 * push support.
 *
 * Returns: 0 on success, negative errno on failure.
 */
int tquic_h3_advertise_max_push_id(struct tquic_connection *qconn, u64 push_id)
{
	struct h3_connection *h3conn;

	if (!qconn)
		return -EINVAL;

	h3conn = qconn->h3_low;
	if (!h3conn)
		return -ENOENT;

	if (h3conn->is_server)
		return -EINVAL;

	return h3_connection_send_max_push_id(h3conn, push_id);
}
EXPORT_SYMBOL_GPL(tquic_h3_advertise_max_push_id);

/*
 * =============================================================================
 * Connection-level Push Control (RFC 9114 Section 4.6)
 * =============================================================================
 *
 * These functions wrap the tquic_http3_conn push API (http3_conn.c) which
 * operates on the higher-level connection object rather than on individual
 * h3_stream pointers.
 */

/**
 * tquic_h3_client_set_max_push_id - Permit server to send up to push_id pushes
 * @qconn:   QUIC connection (client only)
 * @push_id: Maximum push ID the server may use
 *
 * Sends the MAX_PUSH_ID frame on the local control stream (RFC 9114 §4.6).
 * Must be called before the server can initiate any server push.
 *
 * Returns: 0 on success, negative errno on failure.
 */
int tquic_h3_client_set_max_push_id(struct tquic_connection *qconn,
				    u64 push_id)
{
	struct tquic_http3_conn *tconn;

	if (!qconn)
		return -EINVAL;

	tconn = qconn->h3conn;
	if (!tconn)
		return -ENOENT;

	return tquic_h3_set_max_push_id(tconn, push_id);
}
EXPORT_SYMBOL_GPL(tquic_h3_client_set_max_push_id);

/**
 * tquic_h3_server_send_push_promise - Announce a server push to the client
 * @qconn:          QUIC connection (server only)
 * @request_stream: The request stream on which to send PUSH_PROMISE
 * @headers:        QPACK-compressed request headers for the push
 * @headers_len:    Length of @headers
 * @push_id_out:    Receives the assigned push ID
 *
 * Sends a PUSH_PROMISE frame (RFC 9114 §4.6) and allocates a push ID.
 * The caller must subsequently call tquic_h3_server_open_push_stream() with
 * the returned push ID to deliver the pushed response.
 *
 * Returns: 0 on success, negative errno on failure.
 */
int tquic_h3_server_send_push_promise(struct tquic_connection *qconn,
				      struct tquic_stream *request_stream,
				      const u8 *headers, size_t headers_len,
				      u64 *push_id_out)
{
	struct tquic_http3_conn *tconn;

	if (!qconn || !request_stream || !headers || headers_len == 0)
		return -EINVAL;

	tconn = qconn->h3conn;
	if (!tconn)
		return -ENOENT;

	return tquic_h3_send_push_promise(tconn, request_stream,
					  headers, headers_len, push_id_out);
}
EXPORT_SYMBOL_GPL(tquic_h3_server_send_push_promise);

/**
 * tquic_h3_server_open_push_stream - Open unidirectional stream for a push
 * @qconn:       QUIC connection (server only)
 * @push_id:     Push ID previously issued by PUSH_PROMISE
 * @stream_out:  Receives the new QUIC stream pointer
 *
 * Creates the unidirectional push stream (RFC 9114 §4.6) for delivering the
 * promised response.  The caller uses the returned stream to send HEADERS and
 * DATA frames for the push.
 *
 * Returns: 0 on success, negative errno on failure.
 */
int tquic_h3_server_open_push_stream(struct tquic_connection *qconn,
				     u64 push_id,
				     struct tquic_stream **stream_out)
{
	struct tquic_http3_conn *tconn;

	if (!qconn || !stream_out)
		return -EINVAL;

	tconn = qconn->h3conn;
	if (!tconn)
		return -ENOENT;

	return tquic_h3_create_push_stream(tconn, push_id, stream_out);
}
EXPORT_SYMBOL_GPL(tquic_h3_server_open_push_stream);

/**
 * tquic_h3_client_reject_push - Client rejects an offered server push
 * @qconn:   QUIC connection (client only)
 * @push_id: Push ID to reject
 *
 * Sends CANCEL_PUSH on the control stream (RFC 9114 §7.2.6) to inform the
 * server that the client does not wish to receive the push.
 *
 * Returns: 0 on success, negative errno on failure.
 */
int tquic_h3_client_reject_push(struct tquic_connection *qconn, u64 push_id)
{
	struct tquic_http3_conn *tconn;

	if (!qconn)
		return -EINVAL;

	tconn = qconn->h3conn;
	if (!tconn)
		return -ENOENT;

	return tquic_h3_reject_push(tconn, push_id);
}
EXPORT_SYMBOL_GPL(tquic_h3_client_reject_push);

/**
 * tquic_h3_server_cancel_push - Server cancels a previously promised push
 * @qconn:   QUIC connection (server only)
 * @push_id: Push ID to cancel
 *
 * Sends CANCEL_PUSH on the control stream (RFC 9114 §7.2.6) to retract a
 * previously sent PUSH_PROMISE.
 *
 * Returns: 0 on success, negative errno on failure.
 */
int tquic_h3_server_cancel_push(struct tquic_connection *qconn, u64 push_id)
{
	struct tquic_http3_conn *tconn;

	if (!qconn)
		return -EINVAL;

	tconn = qconn->h3conn;
	if (!tconn)
		return -ENOENT;

	return tquic_h3_send_cancel_push(tconn, push_id);
}
EXPORT_SYMBOL_GPL(tquic_h3_server_cancel_push);

/**
 * tquic_h3_connection_complete_shutdown - Send final GOAWAY after draining
 * @qconn:    QUIC connection
 * @final_id: Final stream / push ID; must not exceed previous GOAWAY ID
 *
 * After a call to tquic_h3_connection_close() has put the connection into
 * graceful shutdown, this sends the definitive GOAWAY with the exact last
 * processed ID (RFC 9114 §5.2).
 *
 * Returns: 0 on success, negative errno on failure.
 */
int tquic_h3_connection_complete_shutdown(struct tquic_connection *qconn,
					  u64 final_id)
{
	struct tquic_http3_conn *tconn;

	if (!qconn)
		return -EINVAL;

	tconn = qconn->h3conn;
	if (!tconn)
		return -ENOENT;

	return tquic_h3_complete_shutdown(tconn, final_id);
}
EXPORT_SYMBOL_GPL(tquic_h3_connection_complete_shutdown);

/**
 * tquic_h3_send_generic_frame - Send a pre-built HTTP/3 frame on a stream
 * @qconn:  QUIC connection
 * @stream: QUIC stream to send on
 * @frame:  Filled tquic_h3_frame to transmit
 *
 * Serialises @frame into a temporary buffer using tquic_h3_write_frame() and
 * sends it on @stream.  This is the canonical path for extension frames and
 * any frame type that does not have a dedicated helper.
 *
 * Returns: 0 on success, negative errno on failure.
 */
int tquic_h3_send_generic_frame(struct tquic_connection *qconn,
				struct tquic_stream *stream,
				const struct tquic_h3_frame *frame)
{
	struct tquic_http3_conn *tconn;
	u8 hdr[32];
	size_t frame_sz;
	int hdr_len;

	if (!qconn || !stream || !frame)
		return -EINVAL;

	tconn = qconn->h3conn;
	if (!tconn)
		return -ENOENT;

	/*
	 * Use tquic_h3_write_frame() for the wire encoding and
	 * tquic_h3_send_frame() to actually push bytes onto the stream.
	 * Log the calculated frame size for diagnostics.
	 */
	frame_sz = tquic_h3_frame_size(frame);
	if (frame_sz == 0)
		return -EINVAL;

	/* Encode frame type + length header only into small stack buffer */
	hdr_len = tquic_h3_write_frame(hdr, sizeof(hdr), frame);
	if (hdr_len < 0)
		return hdr_len;

	pr_debug("tquic_h3: sending frame type=%llu sz=%zu\n",
		 (unsigned long long)frame->type, frame_sz);

	return tquic_h3_send_frame(tconn, stream, frame);
}
EXPORT_SYMBOL_GPL(tquic_h3_send_generic_frame);

/*
 * =============================================================================
 * Frame Size Accounting (HTTP/3 Wire Format)
 * =============================================================================
 *
 * These wrappers expose the http3_frame.c frame-size helpers to the rest of
 * the TQUIC stack.  They are used during buffer pre-allocation before writing
 * frames and in admission-control checks.
 */

/**
 * tquic_h3_calc_settings_frame_size - Calculate wire size of a SETTINGS frame
 * @settings: SETTINGS values to be serialised
 *
 * Returns: Total wire bytes needed for the SETTINGS frame.
 */
size_t tquic_h3_calc_settings_frame_size(const struct tquic_h3_settings *settings)
{
	return tquic_h3_settings_frame_size(settings);
}
EXPORT_SYMBOL_GPL(tquic_h3_calc_settings_frame_size);

/**
 * tquic_h3_calc_headers_frame_size - Calculate wire size of a HEADERS frame
 * @encoded_len: Byte count of the QPACK-encoded header block
 *
 * Returns: Total wire bytes needed for the HEADERS frame.
 */
size_t tquic_h3_calc_headers_frame_size(u64 encoded_len)
{
	return tquic_h3_headers_frame_size(encoded_len);
}
EXPORT_SYMBOL_GPL(tquic_h3_calc_headers_frame_size);

/**
 * tquic_h3_calc_goaway_frame_size - Calculate wire size of a GOAWAY frame
 * @id: Stream or push ID to include in the frame
 *
 * Returns: Total wire bytes needed for the GOAWAY frame.
 */
size_t tquic_h3_calc_goaway_frame_size(u64 id)
{
	return tquic_h3_goaway_frame_size(id);
}
EXPORT_SYMBOL_GPL(tquic_h3_calc_goaway_frame_size);

/**
 * tquic_h3_calc_max_push_id_frame_size - Wire size of MAX_PUSH_ID frame
 * @push_id: Maximum push ID to advertise
 *
 * Returns: Total wire bytes needed for the MAX_PUSH_ID frame.
 */
size_t tquic_h3_calc_max_push_id_frame_size(u64 push_id)
{
	return tquic_h3_max_push_id_frame_size(push_id);
}
EXPORT_SYMBOL_GPL(tquic_h3_calc_max_push_id_frame_size);

/**
 * tquic_h3_calc_cancel_push_frame_size - Wire size of CANCEL_PUSH frame
 * @push_id: Push ID being cancelled
 *
 * Returns: Total wire bytes needed for the CANCEL_PUSH frame.
 */
size_t tquic_h3_calc_cancel_push_frame_size(u64 push_id)
{
	return tquic_h3_cancel_push_frame_size(push_id);
}
EXPORT_SYMBOL_GPL(tquic_h3_calc_cancel_push_frame_size);

/*
 * =============================================================================
 * Priority Field and Frame Parsing/Encoding (RFC 9218)
 * =============================================================================
 *
 * These are integration points used by the netlink interface and by the
 * HTTP/3 input path when processing PRIORITY_UPDATE frames and Priority
 * request headers.
 */

/**
 * tquic_h3_priority_parse_update_frame - Parse a PRIORITY_UPDATE frame payload
 * @qconn:   QUIC connection
 * @data:    Raw frame payload bytes (after frame type/length header)
 * @len:     Payload byte count
 * @frame:   Output: parsed frame
 * @consumed: Output: bytes consumed from @data
 *
 * Called from the control-stream receive path (tquic_h3_recv_control_frame)
 * when frame_type == TQUIC_H3_FRAME_PRIORITY_UPDATE to parse the binary
 * body before handing it to http3_priority_handle_update().
 *
 * Returns: 0 on success, negative errno on failure.
 */
int tquic_h3_priority_parse_update_frame(struct tquic_connection *qconn,
					 const u8 *data, size_t len,
					 struct http3_priority_update_frame *frame,
					 size_t *consumed)
{
	if (!data || !frame || !consumed)
		return -EINVAL;

	return http3_priority_parse_frame(data, len, frame, consumed);
}
EXPORT_SYMBOL_GPL(tquic_h3_priority_parse_update_frame);

/**
 * tquic_h3_priority_encode_update_frame - Encode a PRIORITY_UPDATE frame
 * @qconn:    QUIC connection
 * @buf:      Output buffer
 * @buf_len:  Buffer size
 * @stream_id: Element ID (stream or push ID)
 * @priority: Priority parameters to encode
 * @is_push:  True if encoding a push PRIORITY_UPDATE
 *
 * Returns: Bytes written on success, negative errno on failure.
 */
int tquic_h3_priority_encode_update_frame(struct tquic_connection *qconn,
					  u8 *buf, size_t buf_len,
					  u64 stream_id,
					  const struct http3_priority *priority,
					  bool is_push)
{
	if (!buf || !priority || buf_len == 0)
		return -EINVAL;

	return http3_priority_encode_frame(buf, buf_len, stream_id,
					   priority, is_push);
}
EXPORT_SYMBOL_GPL(tquic_h3_priority_encode_update_frame);

/**
 * tquic_h3_priority_apply_update - Apply a parsed PRIORITY_UPDATE frame
 * @qconn: QUIC connection
 * @frame: Parsed PRIORITY_UPDATE frame
 *
 * Dispatches the parsed frame to the priority state machine, updating
 * stream urgency/incremental in the per-connection priority state.
 *
 * Returns: 0 on success, negative errno on failure.
 */
int tquic_h3_priority_apply_update(struct tquic_connection *qconn,
				   const struct http3_priority_update_frame *frame)
{
	if (!qconn || !frame)
		return -EINVAL;

	return http3_priority_handle_update(qconn, frame);
}
EXPORT_SYMBOL_GPL(tquic_h3_priority_apply_update);

/**
 * tquic_h3_priority_send_stream_update - Send PRIORITY_UPDATE for a stream
 * @qconn:     QUIC connection
 * @stream_id: Request stream whose priority is being updated
 * @priority:  New priority parameters
 *
 * Queues a PRIORITY_UPDATE frame on the control stream for transmission.
 *
 * Returns: 0 on success, negative errno on failure.
 */
int tquic_h3_priority_send_stream_update(struct tquic_connection *qconn,
					 u64 stream_id,
					 const struct http3_priority *priority)
{
	if (!qconn || !priority)
		return -EINVAL;

	return http3_priority_send_update(qconn, stream_id, priority);
}
EXPORT_SYMBOL_GPL(tquic_h3_priority_send_stream_update);

/**
 * tquic_h3_priority_parse_priority_field - Parse Priority structured field
 * @field:    Raw field string (e.g. "u=3, i")
 * @len:      String byte count
 * @priority: Output: parsed priority
 *
 * Parses the Structured Field Dictionary representation of the Priority
 * header field (RFC 9218 §4) into a struct http3_priority.
 *
 * Returns: 0 on success, negative errno on failure.
 */
int tquic_h3_priority_parse_priority_field(const char *field, size_t len,
					   struct http3_priority *priority)
{
	if (!field || !priority)
		return -EINVAL;

	return http3_priority_parse_field(field, len, priority);
}
EXPORT_SYMBOL_GPL(tquic_h3_priority_parse_priority_field);

/**
 * tquic_h3_priority_encode_priority_field - Encode Priority structured field
 * @buf:      Output buffer for the encoded field string
 * @buf_len:  Buffer size
 * @priority: Priority parameters to encode
 *
 * Produces the Structured Field Dictionary string for use in a Priority
 * HTTP header or PRIORITY_UPDATE frame payload.
 *
 * Returns: Bytes written (excluding NUL) on success, negative errno on failure.
 */
int tquic_h3_priority_encode_priority_field(char *buf, size_t buf_len,
					    const struct http3_priority *priority)
{
	if (!buf || !priority || buf_len == 0)
		return -EINVAL;

	return http3_priority_encode_field(buf, buf_len, priority);
}
EXPORT_SYMBOL_GPL(tquic_h3_priority_encode_priority_field);

/**
 * tquic_h3_priority_from_request_header - Parse Priority from HTTP header value
 * @header_value: Raw header value bytes
 * @len:          Header value length
 * @priority:     Output: parsed priority
 *
 * Returns: 0 on success, negative errno on failure.
 */
int tquic_h3_priority_from_request_header(const char *header_value, size_t len,
					  struct http3_priority *priority)
{
	if (!header_value || !priority)
		return -EINVAL;

	return http3_priority_from_header(header_value, len, priority);
}
EXPORT_SYMBOL_GPL(tquic_h3_priority_from_request_header);

/**
 * tquic_h3_priority_to_response_header - Format Priority for HTTP response
 * @buf:      Output buffer for the header value string
 * @buf_len:  Buffer size
 * @priority: Priority to encode
 *
 * Returns: Bytes written on success, negative errno on failure.
 */
int tquic_h3_priority_to_response_header(char *buf, size_t buf_len,
					 const struct http3_priority *priority)
{
	if (!buf || !priority || buf_len == 0)
		return -EINVAL;

	return http3_priority_to_header(buf, buf_len, priority);
}
EXPORT_SYMBOL_GPL(tquic_h3_priority_to_response_header);

/**
 * tquic_h3_priority_get_stream_priority - Get current priority for a stream
 * @qconn:     QUIC connection
 * @stream_id: Stream ID to query
 * @priority:  Output: current priority
 *
 * Returns: 0 on success, -ENOENT if stream not tracked, negative errno
 * on other failure.
 */
int tquic_h3_priority_get_stream_priority(struct tquic_connection *qconn,
					  u64 stream_id,
					  struct http3_priority *priority)
{
	if (!qconn || !priority)
		return -EINVAL;

	return http3_priority_stream_get(qconn, stream_id, priority);
}
EXPORT_SYMBOL_GPL(tquic_h3_priority_get_stream_priority);

/**
 * tquic_h3_priority_set_stream_priority - Update priority for a tracked stream
 * @qconn:     QUIC connection
 * @stream_id: Stream ID to update
 * @priority:  New priority parameters
 *
 * Returns: 0 on success, negative errno on failure.
 */
int tquic_h3_priority_set_stream_priority(struct tquic_connection *qconn,
					  u64 stream_id,
					  const struct http3_priority *priority)
{
	if (!qconn || !priority)
		return -EINVAL;

	return http3_priority_stream_set(qconn, stream_id, priority);
}
EXPORT_SYMBOL_GPL(tquic_h3_priority_set_stream_priority);

/**
 * tquic_h3_priority_streams_at_urgency - Enumerate streams at urgency level
 * @qconn:      QUIC connection
 * @urgency:    Urgency bucket (0 = highest, 7 = lowest)
 * @ids:        Output: array of stream IDs at this urgency
 * @max_ids:    Capacity of @ids
 *
 * Returns: Number of stream IDs written to @ids, negative errno on failure.
 */
int tquic_h3_priority_streams_at_urgency(struct tquic_connection *qconn,
					 u8 urgency,
					 u64 *ids, size_t max_ids)
{
	if (!qconn || !ids || max_ids == 0)
		return -EINVAL;

	return http3_priority_get_streams_at_urgency(qconn, urgency,
						     ids, max_ids);
}
EXPORT_SYMBOL_GPL(tquic_h3_priority_streams_at_urgency);

/**
 * tquic_h3_priority_check_interleave - Should scheduler interleave stream pair
 * @qconn:    QUIC connection
 * @stream_a: First stream ID
 * @stream_b: Second stream ID
 *
 * Returns true when the scheduler should interleave data from the two streams
 * (both are incremental at the same urgency), false otherwise.
 */
bool tquic_h3_priority_check_interleave(struct tquic_connection *qconn,
					u64 stream_a, u64 stream_b)
{
	if (!qconn)
		return false;

	return http3_priority_should_interleave(qconn, stream_a, stream_b);
}
EXPORT_SYMBOL_GPL(tquic_h3_priority_check_interleave);

/*
 * =============================================================================
 * tquic_h3_stream Priority (struct tquic_h3_stream / h3_stream wrappers)
 * =============================================================================
 *
 * These helpers operate on the tquic_h3_stream opaque type (defined in
 * http3_priority.h as an alias for the internal h3_stream).  They are used
 * by the output scheduler to read and update per-stream priority without
 * touching h3_stream internals directly.
 */

/**
 * tquic_h3_get_stream_priority - Read per-stream priority parameters
 * @stream: HTTP/3 stream (opaque)
 * @pri:    Output: RFC 9218 priority (urgency + incremental)
 *
 * Returns: 0 on success, negative errno on failure.
 */
int tquic_h3_get_stream_priority(struct tquic_h3_stream *stream,
				 struct tquic_h3_priority *pri)
{
	if (!stream || !pri)
		return -EINVAL;

	return tquic_h3_stream_get_priority(stream, pri);
}
EXPORT_SYMBOL_GPL(tquic_h3_get_stream_priority);

/**
 * tquic_h3_update_stream_priority - Write per-stream priority parameters
 * @stream: HTTP/3 stream (opaque)
 * @pri:    New RFC 9218 priority (urgency + incremental)
 */
void tquic_h3_update_stream_priority(struct tquic_h3_stream *stream,
				     const struct tquic_h3_priority *pri)
{
	if (!stream || !pri)
		return;

	tquic_h3_stream_set_priority(stream, pri);
}
EXPORT_SYMBOL_GPL(tquic_h3_update_stream_priority);

/**
 * tquic_h3_conn_next_priority_stream - Get next stream from tconn priority list
 * @qconn: QUIC connection
 *
 * Wraps tquic_h3_priority_next() to provide the output scheduler with the
 * highest-priority h3_stream that has pending send data.
 *
 * Returns: Pointer to the h3_stream to drain next, or NULL if none.
 */
struct tquic_h3_stream *
tquic_h3_conn_next_priority_stream(struct tquic_connection *qconn)
{
	struct tquic_http3_conn *tconn;

	if (!qconn)
		return NULL;

	tconn = qconn->h3conn;
	if (!tconn)
		return NULL;

	return tquic_h3_priority_next(tconn);
}
EXPORT_SYMBOL_GPL(tquic_h3_conn_next_priority_stream);

/*
 * =============================================================================
 * Priority Tree (tquic_h3_priority_tree) – Multipath Scheduler Integration
 * =============================================================================
 *
 * The priority tree is an alternative stream-scheduling structure that the
 * multipath bonding scheduler uses directly (without a full tquic_http3_conn).
 * These wrappers are called from tquic_bonding.c and the sched_*.c files.
 */

/**
 * tquic_h3_ptree_add_stream - Add stream to a per-path priority tree
 * @tree:      Priority tree (embedded in the bonding scheduler's path struct)
 * @stream_id: Stream to track
 * @pri:       Initial RFC 9218 priority
 *
 * Returns: 0 on success, -EEXIST if already present, negative errno otherwise.
 */
int tquic_h3_ptree_add_stream(struct tquic_h3_priority_tree *tree,
			      u64 stream_id,
			      const struct tquic_h3_priority *pri)
{
	if (!tree || !pri)
		return -EINVAL;

	return tquic_h3_priority_tree_add(tree, stream_id, pri);
}
EXPORT_SYMBOL_GPL(tquic_h3_ptree_add_stream);

/**
 * tquic_h3_ptree_remove_stream - Remove stream from a priority tree
 * @tree:      Priority tree
 * @stream_id: Stream to remove
 */
void tquic_h3_ptree_remove_stream(struct tquic_h3_priority_tree *tree,
				  u64 stream_id)
{
	if (!tree)
		return;

	tquic_h3_priority_tree_remove(tree, stream_id);
}
EXPORT_SYMBOL_GPL(tquic_h3_ptree_remove_stream);

/**
 * tquic_h3_ptree_update_stream - Update priority in a priority tree
 * @tree:      Priority tree
 * @stream_id: Stream whose priority is changing
 * @pri:       New RFC 9218 priority
 *
 * Returns: 0 on success, -ENOENT if stream not found, negative errno otherwise.
 */
int tquic_h3_ptree_update_stream(struct tquic_h3_priority_tree *tree,
				 u64 stream_id,
				 const struct tquic_h3_priority *pri)
{
	if (!tree || !pri)
		return -EINVAL;

	return tquic_h3_priority_tree_update(tree, stream_id, pri);
}
EXPORT_SYMBOL_GPL(tquic_h3_ptree_update_stream);

/**
 * tquic_h3_ptree_next_stream - Pick next stream from a priority tree
 * @tree: Priority tree
 *
 * Returns: Stream ID of the highest-priority stream with pending data, or 0
 * if the tree is empty.
 */
u64 tquic_h3_ptree_next_stream(struct tquic_h3_priority_tree *tree)
{
	if (!tree)
		return 0;

	return tquic_h3_priority_tree_next(tree);
}
EXPORT_SYMBOL_GPL(tquic_h3_ptree_next_stream);

/*
 * =============================================================================
 * QPACK Encoding/Decoding Integration (RFC 9204)
 * =============================================================================
 *
 * Wires qpack_encode_headers(), qpack_decode_headers(), encoder dynamic-table
 * management (set_capacity, insert_name_ref, insert_literal, duplicate),
 * and the sysctl/static table size accessors into the integration layer.
 */

/**
 * tquic_h3_encode_headers - Encode an HTTP header list with QPACK
 * @qconn:       QUIC connection (must have a QPACK context)
 * @stream_id:   Stream on whose behalf headers are encoded (for blocked-stream tracking)
 * @headers:     List of header fields to encode
 * @buf:         Output buffer for the encoded header block
 * @buf_len:     Capacity of @buf
 * @encoded_len: Receives the number of bytes written to @buf
 *
 * This is the canonical outgoing-header encoding path.  It delegates to
 * qpack_encode_headers() which uses the per-connection QPACK encoder state.
 *
 * Returns: 0 on success, negative errno on failure.
 */
int tquic_h3_encode_headers(struct tquic_connection *qconn, u64 stream_id,
			    struct qpack_header_list *headers,
			    u8 *buf, size_t buf_len, size_t *encoded_len)
{
	struct qpack_context *ctx;

	if (!qconn || !headers || !buf || !encoded_len || buf_len == 0)
		return -EINVAL;

	ctx = qconn->qpack_ctx;
	if (!ctx)
		return -ENOENT;

	return qpack_encode_headers(&ctx->encoder, stream_id,
				    headers, buf, buf_len, encoded_len);
}
EXPORT_SYMBOL_GPL(tquic_h3_encode_headers);

/**
 * tquic_h3_decode_headers - Decode a QPACK-encoded header block
 * @qconn:     QUIC connection (must have a QPACK context)
 * @stream_id: Stream from which the header block was received
 * @data:      Encoded header block bytes
 * @len:       Byte count of @data
 * @headers:   Output: decoded header list (caller initialises)
 *
 * This is the canonical incoming-header decoding path.  It delegates to
 * qpack_decode_headers() which uses the per-connection QPACK decoder state.
 *
 * Returns: 0 on success, negative errno on failure.
 */
int tquic_h3_decode_headers(struct tquic_connection *qconn, u64 stream_id,
			    const u8 *data, size_t len,
			    struct qpack_header_list *headers)
{
	struct qpack_context *ctx;

	if (!qconn || !data || !headers || len == 0)
		return -EINVAL;

	ctx = qconn->qpack_ctx;
	if (!ctx)
		return -ENOENT;

	return qpack_decode_headers(&ctx->decoder, stream_id,
				    data, len, headers);
}
EXPORT_SYMBOL_GPL(tquic_h3_decode_headers);

/**
 * tquic_h3_qpack_set_encoder_capacity - Update the QPACK dynamic table capacity
 * @qconn:    QUIC connection
 * @capacity: New maximum dynamic table capacity in bytes
 *
 * Sends a Set Dynamic Table Capacity instruction on the QPACK encoder stream
 * (RFC 9204 §3.2.3).  Called when peer's SETTINGS_QPACK_MAX_TABLE_CAPACITY
 * is received and a smaller capacity is desired.
 *
 * Returns: 0 on success, negative errno on failure.
 */
int tquic_h3_qpack_set_encoder_capacity(struct tquic_connection *qconn,
					u64 capacity)
{
	struct qpack_context *ctx;

	if (!qconn)
		return -EINVAL;

	ctx = qconn->qpack_ctx;
	if (!ctx)
		return -ENOENT;

	return qpack_encoder_set_capacity(&ctx->encoder, capacity);
}
EXPORT_SYMBOL_GPL(tquic_h3_qpack_set_encoder_capacity);

/**
 * tquic_h3_qpack_insert_name_ref - Insert dynamic table entry via name reference
 * @qconn:      QUIC connection
 * @is_static:  True if @name_index refers to the static table
 * @name_index: Table index for the header name
 * @value:      Header value bytes
 * @value_len:  Length of @value
 *
 * Sends an Insert With Name Reference instruction on the encoder stream
 * (RFC 9204 §3.2.4).
 *
 * Returns: 0 on success, negative errno on failure.
 */
int tquic_h3_qpack_insert_name_ref(struct tquic_connection *qconn,
				   bool is_static, u64 name_index,
				   const char *value, u16 value_len)
{
	struct qpack_context *ctx;

	if (!qconn || !value)
		return -EINVAL;

	ctx = qconn->qpack_ctx;
	if (!ctx)
		return -ENOENT;

	return qpack_encoder_insert_name_ref(&ctx->encoder, is_static,
					     name_index, value, value_len);
}
EXPORT_SYMBOL_GPL(tquic_h3_qpack_insert_name_ref);

/**
 * tquic_h3_qpack_insert_literal - Insert dynamic table entry with literal name
 * @qconn:     QUIC connection
 * @name:      Header name bytes
 * @name_len:  Length of @name
 * @value:     Header value bytes
 * @value_len: Length of @value
 *
 * Sends an Insert With Literal Name instruction on the encoder stream
 * (RFC 9204 §3.2.5).
 *
 * Returns: 0 on success, negative errno on failure.
 */
int tquic_h3_qpack_insert_literal(struct tquic_connection *qconn,
				  const char *name, u16 name_len,
				  const char *value, u16 value_len)
{
	struct qpack_context *ctx;

	if (!qconn || !name || !value)
		return -EINVAL;

	ctx = qconn->qpack_ctx;
	if (!ctx)
		return -ENOENT;

	return qpack_encoder_insert_literal(&ctx->encoder, name, name_len,
					    value, value_len);
}
EXPORT_SYMBOL_GPL(tquic_h3_qpack_insert_literal);

/**
 * tquic_h3_qpack_duplicate_entry - Duplicate a dynamic table entry
 * @qconn: QUIC connection
 * @index: Relative index of the entry to duplicate (RFC 9204 §3.2.6)
 *
 * Sends a Duplicate instruction on the encoder stream.
 *
 * Returns: 0 on success, negative errno on failure.
 */
int tquic_h3_qpack_duplicate_entry(struct tquic_connection *qconn, u64 index)
{
	struct qpack_context *ctx;

	if (!qconn)
		return -EINVAL;

	ctx = qconn->qpack_ctx;
	if (!ctx)
		return -ENOENT;

	return qpack_encoder_duplicate(&ctx->encoder, index);
}
EXPORT_SYMBOL_GPL(tquic_h3_qpack_duplicate_entry);

/**
 * tquic_h3_qpack_max_table_capacity - Get sysctl-configured QPACK table limit
 *
 * Returns the maximum dynamic table capacity the local implementation will
 * accept, as configured via sysctl.  Used when building the local SETTINGS
 * frame (SETTINGS_QPACK_MAX_TABLE_CAPACITY).
 *
 * Returns: Maximum capacity in bytes.
 */
u64 tquic_h3_qpack_max_table_capacity(void)
{
	return qpack_sysctl_max_table_capacity();
}
EXPORT_SYMBOL_GPL(tquic_h3_qpack_max_table_capacity);

/**
 * tquic_h3_qpack_num_static_entries - Number of QPACK static table entries
 *
 * Returns the compile-time size of the QPACK static table (RFC 9204 Appendix A).
 * Used during encoder/decoder initialisation and testing.
 */
u32 tquic_h3_qpack_num_static_entries(void)
{
	return qpack_static_table_size();
}
EXPORT_SYMBOL_GPL(tquic_h3_qpack_num_static_entries);

/*
 * =============================================================================
 * WebTransport Stream and Datagram I/O (RFC 9220)
 * =============================================================================
 *
 * These wrappers give the TQUIC socket layer (tquic_socket.c) and the netlink
 * control plane access to per-session WebTransport operations without directly
 * depending on webtransport.h internals.
 */

#ifdef CONFIG_TQUIC_WEBTRANSPORT

/**
 * tquic_h3_wt_find_session - Look up a WebTransport session by session ID
 * @qconn:      QUIC connection
 * @session_id: Connect-stream ID that identifies the session
 *
 * Returns a reference-counted session pointer, or NULL if not found.
 * The caller must call webtransport_session_put() when done.
 */
struct webtransport_session *
tquic_h3_wt_find_session(struct tquic_connection *qconn, u64 session_id)
{
	struct webtransport_context *wt_ctx;

	if (!qconn)
		return NULL;

	wt_ctx = qconn->wt_ctx;
	if (!wt_ctx)
		return NULL;

	return webtransport_session_find(wt_ctx, session_id);
}
EXPORT_SYMBOL_GPL(tquic_h3_wt_find_session);

/**
 * tquic_h3_wt_open_stream - Open a new WebTransport stream
 * @session:        WebTransport session
 * @bidirectional:  True for a bidirectional stream, false for unidirectional
 *
 * Creates a new QUIC stream and wraps it as a WebTransport stream within
 * @session.
 *
 * Returns: New stream pointer on success, ERR_PTR(-errno) on failure.
 */
struct webtransport_stream *
tquic_h3_wt_open_stream(struct webtransport_session *session,
			bool bidirectional)
{
	if (!session)
		return ERR_PTR(-EINVAL);

	return webtransport_open_stream(session, bidirectional);
}
EXPORT_SYMBOL_GPL(tquic_h3_wt_open_stream);

/**
 * tquic_h3_wt_stream_send - Send data on a WebTransport stream
 * @stream:  WebTransport stream
 * @data:    Data bytes to send
 * @len:     Byte count
 * @fin:     If true, half-close the stream after this data
 *
 * Returns: Bytes accepted on success, negative errno on failure.
 */
ssize_t tquic_h3_wt_stream_send(struct webtransport_stream *stream,
				const u8 *data, size_t len, bool fin)
{
	if (!stream || !data || len == 0)
		return -EINVAL;

	return webtransport_stream_send(stream, data, len, fin);
}
EXPORT_SYMBOL_GPL(tquic_h3_wt_stream_send);

/**
 * tquic_h3_wt_stream_recv - Receive data from a WebTransport stream
 * @stream:  WebTransport stream
 * @buf:     Output buffer
 * @len:     Buffer capacity
 *
 * Returns: Bytes read on success, negative errno on failure.
 */
ssize_t tquic_h3_wt_stream_recv(struct webtransport_stream *stream,
				u8 *buf, size_t len)
{
	if (!stream || !buf || len == 0)
		return -EINVAL;

	return webtransport_stream_recv(stream, buf, len);
}
EXPORT_SYMBOL_GPL(tquic_h3_wt_stream_recv);

/**
 * tquic_h3_wt_send_datagram - Send a WebTransport datagram
 * @session:  WebTransport session
 * @data:     Datagram payload
 * @len:      Payload byte count
 *
 * Sends an HTTP Datagram (RFC 9297) carrying the WebTransport payload.
 *
 * Returns: 0 on success, negative errno on failure.
 */
int tquic_h3_wt_send_datagram(struct webtransport_session *session,
			      const u8 *data, size_t len)
{
	if (!session || !data || len == 0)
		return -EINVAL;

	return webtransport_send_datagram(session, data, len);
}
EXPORT_SYMBOL_GPL(tquic_h3_wt_send_datagram);

/**
 * tquic_h3_wt_recv_datagram - Receive a WebTransport datagram
 * @session: WebTransport session
 * @buf:     Output buffer
 * @len:     Buffer capacity
 *
 * Returns: Bytes written to @buf on success, negative errno on failure.
 */
ssize_t tquic_h3_wt_recv_datagram(struct webtransport_session *session,
				  u8 *buf, size_t len)
{
	if (!session || !buf || len == 0)
		return -EINVAL;

	return webtransport_recv_datagram(session, buf, len);
}
EXPORT_SYMBOL_GPL(tquic_h3_wt_recv_datagram);

#endif /* CONFIG_TQUIC_WEBTRANSPORT */

#endif /* CONFIG_TQUIC_HTTP3 */

MODULE_DESCRIPTION("TQUIC HTTP/3 Integration Layer (RFC 9114)");
MODULE_LICENSE("GPL");
