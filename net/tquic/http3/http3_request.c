// SPDX-License-Identifier: GPL-2.0-only
/*
 * TQUIC HTTP/3: Request/Response Handling
 *
 * Copyright (c) 2026 Justin Adams <spotty118@gmail.com>
 * Kernel implementation by Justin Adams <spotty118@gmail.com>
 *
 * Implements HTTP/3 request/response handling per RFC 9114 Section 4.
 *
 * Request Stream State Machine:
 *   Client-initiated bidirectional streams carry request/response pairs.
 *
 *   Client sends:
 *     HEADERS (request) -> DATA* -> HEADERS (trailers, optional) -> FIN
 *
 *   Server sends:
 *     HEADERS (response) -> DATA* -> HEADERS (trailers, optional) -> FIN
 *
 * State transitions:
 *   IDLE -> HEADERS_RECEIVED (after receiving HEADERS frame)
 *   HEADERS_RECEIVED -> DATA (after receiving first DATA frame)
 *   DATA -> TRAILERS (after receiving trailing HEADERS)
 *   DATA/TRAILERS -> COMPLETE (after receiving FIN)
 *
 * Frame Sequence Rules:
 *   - HEADERS frame must be first
 *   - DATA frames may appear zero or more times
 *   - Trailing HEADERS frame is optional, must be last before FIN
 *   - PUSH_PROMISE may appear on request streams (server to client only)
 */

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/uio.h>
#include <linux/refcount.h>
#include <net/tquic.h>

#include "http3_stream.h"
#include "http3_frame.h"
#include "../core/varint.h"

/*
 * =============================================================================
 * Frame Building Helpers
 * =============================================================================
 */

/**
 * h3_build_frame_header - Build HTTP/3 frame header
 * @frame_type: Frame type
 * @payload_len: Payload length
 * @buf: Output buffer
 * @buflen: Buffer size
 *
 * Return: Number of bytes written, or negative error
 */
static int h3_build_frame_header(u64 frame_type, u64 payload_len,
				 u8 *buf, size_t buflen)
{
	u8 *p = buf;
	int ret;

	/* Frame type */
	ret = h3_varint_encode(frame_type, p, buflen);
	if (ret < 0)
		return ret;
	p += ret;
	buflen -= ret;

	/* Frame length */
	ret = h3_varint_encode(payload_len, p, buflen);
	if (ret < 0)
		return ret;
	p += ret;

	return p - buf;
}

/*
 * Varint encode/decode are provided by http3_frame.h / http3_frame.c.
 */

/*
 * =============================================================================
 * Request Stream Operations
 * =============================================================================
 */

/**
 * h3_request_send_headers - Send HEADERS frame on request stream
 * @h3s: HTTP/3 stream
 * @headers: Encoded header block (QPACK compressed)
 * @len: Header block length
 *
 * The first frame on a request stream must be a HEADERS frame.
 * The headers parameter should contain QPACK-compressed header fields.
 *
 * Return: 0 on success, negative error
 */
int h3_request_send_headers(struct h3_stream *h3s, const void *headers,
			    size_t len)
{
	u8 frame_hdr[16];
	int hdr_len;
	int ret;
	bool was_headers_sent;

	if (!h3s->is_request_stream) {
		pr_err("h3: not a request stream\n");
		return -EINVAL;
	}

	/*
	 * Validate state and atomically mark the send as in-progress
	 * to close the TOCTOU window between the state check and the
	 * actual send.  We set headers_sent under the lock before the
	 * I/O so that concurrent callers will see the updated state.
	 * On send failure we roll back.
	 */
	spin_lock(&h3s->lock);

	if (h3s->headers_sent) {
		/* Trailing headers */
		if (h3s->request_state != H3_REQUEST_DATA &&
		    h3s->request_state != H3_REQUEST_HEADERS_RECEIVED) {
			spin_unlock(&h3s->lock);
			return -H3_FRAME_UNEXPECTED;
		}
	} else {
		/* Initial headers */
		if (h3s->request_state != H3_REQUEST_IDLE) {
			spin_unlock(&h3s->lock);
			return -H3_FRAME_UNEXPECTED;
		}
	}

	was_headers_sent = h3s->headers_sent;
	h3s->headers_sent = true;

	spin_unlock(&h3s->lock);

	/* Build HEADERS frame header */
	hdr_len = h3_build_frame_header(H3_FRAME_HEADERS, len,
					frame_hdr, sizeof(frame_hdr));
	if (hdr_len < 0) {
		ret = hdr_len;
		goto rollback;
	}

	/* Send frame header */
	ret = tquic_stream_send(h3s->base, frame_hdr, hdr_len, false);
	if (ret < 0)
		goto rollback;

	/* Send header block */
	ret = tquic_stream_send(h3s->base, headers, len, false);
	if (ret < 0)
		goto rollback;

	spin_lock(&h3s->lock);
	h3s->bytes_sent += hdr_len + len;
	spin_unlock(&h3s->lock);

	pr_debug("h3: sent HEADERS frame (%zu bytes) on stream %llu\n",
		 len, h3s->base->id);

	return 0;

rollback:
	spin_lock(&h3s->lock);
	h3s->headers_sent = was_headers_sent;
	spin_unlock(&h3s->lock);
	return ret;
}
EXPORT_SYMBOL_GPL(h3_request_send_headers);

/**
 * h3_request_send_data - Send DATA frame on request stream
 * @h3s: HTTP/3 stream
 * @data: Request body data
 * @len: Data length
 *
 * Sends a DATA frame containing request or response body.
 * Multiple DATA frames may be sent.
 *
 * Return: 0 on success, negative error
 */
int h3_request_send_data(struct h3_stream *h3s, const void *data, size_t len)
{
	u8 frame_hdr[16];
	int hdr_len;
	int ret;

	if (!h3s->is_request_stream) {
		pr_err("h3: not a request stream\n");
		return -EINVAL;
	}

	spin_lock(&h3s->lock);

	/* DATA must come after HEADERS */
	if (!h3s->headers_sent) {
		spin_unlock(&h3s->lock);
		pr_err("h3: HEADERS must be sent before DATA\n");
		return -H3_FRAME_UNEXPECTED;
	}

	/* Cannot send DATA after trailers or FIN */
	if (h3s->trailers_received || h3s->fin_sent) {
		spin_unlock(&h3s->lock);
		pr_err("h3: cannot send DATA after trailers or FIN\n");
		return -H3_FRAME_UNEXPECTED;
	}

	/*
	 * Mark that a data send is in flight to prevent concurrent
	 * state-changing operations (e.g. trailers or FIN) from
	 * racing with this send.
	 */
	h3s->data_sending = true;

	spin_unlock(&h3s->lock);

	/* Build DATA frame header */
	hdr_len = h3_build_frame_header(H3_FRAME_DATA, len,
					frame_hdr, sizeof(frame_hdr));
	if (hdr_len < 0) {
		ret = hdr_len;
		goto out;
	}

	/* Send frame header */
	ret = tquic_stream_send(h3s->base, frame_hdr, hdr_len, false);
	if (ret < 0)
		goto out;

	/* Send data */
	ret = tquic_stream_send(h3s->base, data, len, false);
	if (ret < 0)
		goto out;

	spin_lock(&h3s->lock);
	h3s->data_offset += len;
	h3s->bytes_sent += hdr_len + len;
	h3s->data_sending = false;
	spin_unlock(&h3s->lock);

	pr_debug("h3: sent DATA frame (%zu bytes) on stream %llu\n",
		 len, h3s->base->id);

	return 0;

out:
	spin_lock(&h3s->lock);
	h3s->data_sending = false;
	spin_unlock(&h3s->lock);
	return ret;
}
EXPORT_SYMBOL_GPL(h3_request_send_data);

/**
 * h3_request_send_trailers - Send trailing HEADERS frame
 * @h3s: HTTP/3 stream
 * @trailers: Encoded trailer header block
 * @len: Trailer block length
 *
 * Sends trailing headers (e.g., Content-MD5) after all DATA frames.
 *
 * Return: 0 on success, negative error
 */
int h3_request_send_trailers(struct h3_stream *h3s, const void *trailers,
			     size_t len)
{
	u8 frame_hdr[16];
	int hdr_len;
	int ret;

	if (!h3s->is_request_stream)
		return -EINVAL;

	spin_lock(&h3s->lock);

	if (!h3s->headers_sent || h3s->fin_sent || h3s->data_sending) {
		spin_unlock(&h3s->lock);
		return -H3_FRAME_UNEXPECTED;
	}

	/* Prevent concurrent sends while trailers are in-flight */
	h3s->trailers_received = true;

	spin_unlock(&h3s->lock);

	/* Trailing HEADERS is just another HEADERS frame */
	hdr_len = h3_build_frame_header(H3_FRAME_HEADERS, len,
					frame_hdr, sizeof(frame_hdr));
	if (hdr_len < 0) {
		ret = hdr_len;
		goto rollback;
	}

	ret = tquic_stream_send(h3s->base, frame_hdr, hdr_len, false);
	if (ret < 0)
		goto rollback;

	ret = tquic_stream_send(h3s->base, trailers, len, false);
	if (ret < 0)
		goto rollback;

	spin_lock(&h3s->lock);
	h3s->bytes_sent += hdr_len + len;
	spin_unlock(&h3s->lock);

	pr_debug("h3: sent trailing HEADERS frame (%zu bytes) on stream %llu\n",
		 len, h3s->base->id);

	return 0;

rollback:
	spin_lock(&h3s->lock);
	h3s->trailers_received = false;
	spin_unlock(&h3s->lock);
	return ret;
}
EXPORT_SYMBOL_GPL(h3_request_send_trailers);

/**
 * h3_request_finish - Complete request by sending FIN
 * @h3s: HTTP/3 stream
 *
 * Sends FIN to indicate the request/response is complete.
 *
 * Return: 0 on success, negative error
 */
int h3_request_finish(struct h3_stream *h3s)
{
	int ret;

	if (!h3s->is_request_stream)
		return -EINVAL;

	spin_lock(&h3s->lock);

	if (h3s->fin_sent) {
		spin_unlock(&h3s->lock);
		return 0;
	}

	if (!h3s->headers_sent || h3s->data_sending) {
		spin_unlock(&h3s->lock);
		return -H3_REQUEST_INCOMPLETE;
	}

	/* Mark FIN as sent under the lock to prevent TOCTOU races */
	h3s->fin_sent = true;

	spin_unlock(&h3s->lock);

	/* Send empty data with FIN flag */
	ret = tquic_stream_send(h3s->base, NULL, 0, true);
	if (ret < 0) {
		/* Roll back on failure */
		spin_lock(&h3s->lock);
		h3s->fin_sent = false;
		spin_unlock(&h3s->lock);
		return ret;
	}

	spin_lock(&h3s->lock);
	h3s->request_state = H3_REQUEST_COMPLETE;
	spin_unlock(&h3s->lock);

	pr_debug("h3: finished request on stream %llu\n", h3s->base->id);

	return 0;
}
EXPORT_SYMBOL_GPL(h3_request_finish);

/*
 * =============================================================================
 * Response Stream Operations
 * =============================================================================
 */

/**
 * h3_response_send_headers - Send response HEADERS frame
 * @h3s: HTTP/3 stream
 * @headers: Encoded header block
 * @len: Header block length
 *
 * Server sends response headers on request stream.
 *
 * Return: 0 on success, negative error
 */
int h3_response_send_headers(struct h3_stream *h3s, const void *headers,
			     size_t len)
{
	/* Response headers use same format as request headers */
	return h3_request_send_headers(h3s, headers, len);
}
EXPORT_SYMBOL_GPL(h3_response_send_headers);

/**
 * h3_response_send_data - Send response DATA frame
 * @h3s: HTTP/3 stream
 * @data: Response body data
 * @len: Data length
 *
 * Return: 0 on success, negative error
 */
int h3_response_send_data(struct h3_stream *h3s, const void *data, size_t len)
{
	return h3_request_send_data(h3s, data, len);
}
EXPORT_SYMBOL_GPL(h3_response_send_data);

/**
 * h3_response_send_trailers - Send response trailing headers
 * @h3s: HTTP/3 stream
 * @trailers: Encoded trailer block
 * @len: Trailer block length
 *
 * Return: 0 on success, negative error
 */
int h3_response_send_trailers(struct h3_stream *h3s, const void *trailers,
			      size_t len)
{
	return h3_request_send_trailers(h3s, trailers, len);
}
EXPORT_SYMBOL_GPL(h3_response_send_trailers);

/**
 * h3_response_finish - Complete response by sending FIN
 * @h3s: HTTP/3 stream
 *
 * Return: 0 on success, negative error
 */
int h3_response_finish(struct h3_stream *h3s)
{
	return h3_request_finish(h3s);
}
EXPORT_SYMBOL_GPL(h3_response_finish);

/*
 * =============================================================================
 * Frame Receiving
 * =============================================================================
 */

/**
 * h3_parse_frame_header - Parse HTTP/3 frame header
 * @data: Input buffer
 * @len: Buffer length
 * @frame_type: Output frame type
 * @payload_len: Output payload length
 *
 * Return: Number of bytes consumed, or negative error
 */
static int h3_parse_frame_header(const u8 *data, size_t len,
				 u64 *frame_type, u64 *payload_len)
{
	int type_len, len_len;

	/* Decode frame type */
	type_len = h3_varint_decode(data, len, frame_type);
	if (type_len < 0)
		return type_len;

	/* Decode frame length */
	len_len = h3_varint_decode(data + type_len, len - type_len, payload_len);
	if (len_len < 0)
		return len_len;

	return type_len + len_len;
}

/**
 * h3_stream_recv_headers - Receive and process HEADERS frame
 * @h3s: HTTP/3 stream
 * @buf: Output buffer for header block
 * @len: Buffer size
 *
 * Receives a HEADERS frame from the stream. The output buffer
 * contains the QPACK-compressed header block that needs to be
 * decompressed separately.
 *
 * Return: Number of bytes received, or negative error
 */
int h3_stream_recv_headers(struct h3_stream *h3s, void *buf, size_t len)
{
	u8 frame_hdr[16];
	u64 frame_type, payload_len;
	int hdr_len;
	int ret;

	/* Read frame header */
	ret = tquic_stream_recv(h3s->base, frame_hdr, sizeof(frame_hdr));
	if (ret <= 0)
		return ret ? ret : -EAGAIN;

	hdr_len = h3_parse_frame_header(frame_hdr, ret, &frame_type, &payload_len);
	if (hdr_len < 0)
		return hdr_len;

	if (frame_type != H3_FRAME_HEADERS) {
		spin_lock(&h3s->lock);
		if (!h3s->headers_received) {
			spin_unlock(&h3s->lock);
			/* First frame must be HEADERS */
			return -H3_FRAME_UNEXPECTED;
		}
		spin_unlock(&h3s->lock);

		/* Not a HEADERS frame, could be DATA */
		return -EAGAIN;
	}

	/* CF-377: Validate payload_len against protocol max */
	if (payload_len > H3_MAX_FRAME_PAYLOAD_SIZE)
		return -H3_FRAME_ERROR;

	if (payload_len > len)
		return -ENOBUFS;

	/* Read header block */
	ret = tquic_stream_recv(h3s->base, buf, payload_len);
	if (ret < 0)
		return ret;

	spin_lock(&h3s->lock);

	if (!h3s->headers_received) {
		h3s->headers_received = true;
		h3s->request_state = H3_REQUEST_HEADERS_RECEIVED;
	} else {
		/* Trailing headers */
		h3s->trailers_received = true;
		h3s->request_state = H3_REQUEST_TRAILERS;
	}

	h3s->bytes_received += hdr_len + ret;

	spin_unlock(&h3s->lock);

	pr_debug("h3: received HEADERS frame (%d bytes) on stream %llu\n",
		 ret, h3s->base->id);

	return ret;
}
EXPORT_SYMBOL_GPL(h3_stream_recv_headers);

/**
 * h3_stream_recv_data - Receive DATA frame content
 * @h3s: HTTP/3 stream
 * @buf: Output buffer
 * @len: Buffer size
 *
 * Receives body data from a DATA frame.
 *
 * Return: Number of bytes received, or negative error
 */
int h3_stream_recv_data(struct h3_stream *h3s, void *buf, size_t len)
{
	u8 frame_hdr[16];
	u64 frame_type, payload_len;
	int hdr_len;
	int ret;

	spin_lock(&h3s->lock);

	if (!h3s->headers_received) {
		spin_unlock(&h3s->lock);
		return -H3_FRAME_UNEXPECTED;
	}

	spin_unlock(&h3s->lock);

	/* Read frame header */
	ret = tquic_stream_recv(h3s->base, frame_hdr, sizeof(frame_hdr));
	if (ret <= 0)
		return ret ? ret : -EAGAIN;

	hdr_len = h3_parse_frame_header(frame_hdr, ret, &frame_type, &payload_len);
	if (hdr_len < 0)
		return hdr_len;

	if (frame_type != H3_FRAME_DATA) {
		/* Could be trailing HEADERS or end of stream */
		if (frame_type == H3_FRAME_HEADERS) {
			/* Trailing headers - process separately */
			return 0;
		}
		return -H3_FRAME_UNEXPECTED;
	}

	/* Read as much data as possible */
	size_t to_read = min_t(size_t, payload_len, len);
	ret = tquic_stream_recv(h3s->base, buf, to_read);
	if (ret < 0)
		return ret;

	spin_lock(&h3s->lock);

	if (h3s->request_state == H3_REQUEST_HEADERS_RECEIVED)
		h3s->request_state = H3_REQUEST_DATA;

	h3s->data_offset += ret;
	h3s->bytes_received += hdr_len + ret;

	spin_unlock(&h3s->lock);

	pr_debug("h3: received DATA frame (%d bytes) on stream %llu\n",
		 ret, h3s->base->id);

	return ret;
}
EXPORT_SYMBOL_GPL(h3_stream_recv_data);

/*
 * =============================================================================
 * Push Stream Operations
 * =============================================================================
 */

/**
 * h3_push_promise_send - Send PUSH_PROMISE frame
 * @request_stream: Stream to send promise on
 * @push_stream: Associated push stream
 * @headers: Encoded request headers for pushed resource
 * @len: Header block length
 *
 * Server sends PUSH_PROMISE on a request stream to announce
 * a server push. The push stream must be opened separately.
 *
 * Return: 0 on success, negative error
 */
int h3_push_promise_send(struct h3_stream *request_stream,
			 struct h3_stream *push_stream,
			 const void *headers, size_t len)
{
	u8 buf[32];
	u8 *p = buf;
	int ret;

	if (!request_stream->is_request_stream) {
		pr_err("h3: PUSH_PROMISE must be on request stream\n");
		return -EINVAL;
	}

	if (push_stream->type != H3_STREAM_TYPE_PUSH) {
		pr_err("h3: push stream has wrong type\n");
		return -EINVAL;
	}

	/* Frame type */
	ret = h3_varint_encode(H3_FRAME_PUSH_PROMISE, p, buf + sizeof(buf) - p);
	if (ret < 0)
		return ret;
	p += ret;

	/* Frame length: push_id (varint) + header block */
	int push_id_len = h3_varint_len(push_stream->push_id);
	ret = h3_varint_encode(push_id_len + len, p, buf + sizeof(buf) - p);
	if (ret < 0)
		return ret;
	p += ret;

	/* Push ID */
	ret = h3_varint_encode(push_stream->push_id, p, buf + sizeof(buf) - p);
	if (ret < 0)
		return ret;
	p += ret;

	/* Send frame header with push ID */
	ret = tquic_stream_send(request_stream->base, buf, p - buf, false);
	if (ret < 0)
		return ret;

	/* Send header block */
	ret = tquic_stream_send(request_stream->base, headers, len, false);
	if (ret < 0)
		return ret;

	push_stream->push_state = H3_PUSH_PROMISED;

	pr_debug("h3: sent PUSH_PROMISE push_id=%llu on stream %llu\n",
		 push_stream->push_id, request_stream->base->id);

	return 0;
}
EXPORT_SYMBOL_GPL(h3_push_promise_send);

/**
 * h3_push_cancel - Send CANCEL_PUSH frame
 * @h3conn: HTTP/3 connection
 * @push_id: Push ID to cancel
 *
 * Client sends CANCEL_PUSH to indicate it doesn't want a pushed response.
 * Server can also send CANCEL_PUSH to abandon a push.
 *
 * Return: 0 on success, negative error
 */
int h3_push_cancel(struct h3_connection *h3conn, u64 push_id)
{
	struct h3_stream *control = h3conn->local_control;
	u8 buf[32];
	u8 *p = buf;
	int ret;

	if (!control)
		return -ENOTCONN;

	/* Frame type */
	ret = h3_varint_encode(H3_FRAME_CANCEL_PUSH, p, buf + sizeof(buf) - p);
	if (ret < 0)
		return ret;
	p += ret;

	/* Frame length */
	int push_id_len = h3_varint_len(push_id);
	ret = h3_varint_encode(push_id_len, p, buf + sizeof(buf) - p);
	if (ret < 0)
		return ret;
	p += ret;

	/* Push ID */
	ret = h3_varint_encode(push_id, p, buf + sizeof(buf) - p);
	if (ret < 0)
		return ret;
	p += ret;

	ret = tquic_stream_send(control->base, buf, p - buf, false);
	if (ret < 0)
		return ret;

	pr_debug("h3: sent CANCEL_PUSH push_id=%llu\n", push_id);

	return 0;
}
EXPORT_SYMBOL_GPL(h3_push_cancel);

/**
 * h3_varint_len - Get encoded length of a value
 * @value: Value to check
 *
 * Return: Number of bytes needed to encode value
 */
static int h3_varint_len(u64 value)
{
	if (value <= 63)
		return 1;
	if (value <= 16383)
		return 2;
	if (value <= 1073741823)
		return 4;
	return 8;
}

/*
 * =============================================================================
 * Control Stream Frame Handling
 * =============================================================================
 */

/**
 * h3_control_recv_frame - Process a frame from control stream
 * @h3s: Control stream
 * @frame_type: Frame type
 * @data: Frame payload
 * @len: Payload length
 *
 * Return: 0 on success, negative error
 */
int h3_control_recv_frame(struct h3_stream *h3s, u64 frame_type,
			  const u8 *data, size_t len)
{
	if (h3s->type != H3_STREAM_TYPE_CONTROL) {
		pr_err("h3: not a control stream\n");
		return -EINVAL;
	}

	switch (frame_type) {
	case H3_FRAME_SETTINGS:
		/*
		 * CF-193: Actually parse SETTINGS payload per RFC 9114
		 * Section 7.2.4. Delegate to the existing settings
		 * receiver which validates identifier/value pairs.
		 */
		pr_debug("h3: received SETTINGS frame (%zu bytes)\n", len);
		if (h3s->h3conn) {
			int sret = h3_connection_recv_settings(h3s->h3conn,
							       data, len);
			if (sret < 0)
				return sret;
		}
		break;

	case H3_FRAME_GOAWAY: {
		/*
		 * CF-193: Parse GOAWAY stream ID (single varint).
		 * RFC 9114 Section 5.2.
		 */
		u64 goaway_id;
		int vret;

		pr_debug("h3: received GOAWAY frame (%zu bytes)\n", len);
		vret = tquic_varint_decode(data, len, &goaway_id);
		if (vret < 0)
			return -EINVAL;
		if (h3s->h3conn)
			h3_connection_recv_goaway(h3s->h3conn, goaway_id);
		break;
	}

	case H3_FRAME_MAX_PUSH_ID: {
		/*
		 * CF-193: Parse MAX_PUSH_ID (single varint).
		 * RFC 9114 Section 7.2.7.
		 */
		u64 push_id;
		int vret;

		pr_debug("h3: received MAX_PUSH_ID frame (%zu bytes)\n", len);
		vret = tquic_varint_decode(data, len, &push_id);
		if (vret < 0)
			return -EINVAL;
		if (h3s->h3conn)
			h3_connection_set_max_push_id(h3s->h3conn, push_id);
		break;
	}

	case H3_FRAME_CANCEL_PUSH: {
		/*
		 * CF-193: Parse CANCEL_PUSH (single varint push ID).
		 * RFC 9114 Section 7.2.3.
		 */
		u64 push_id;
		int vret;

		pr_debug("h3: received CANCEL_PUSH frame (%zu bytes)\n", len);
		vret = tquic_varint_decode(data, len, &push_id);
		if (vret < 0)
			return -EINVAL;
		if (h3s->h3conn)
			h3_push_cancel(h3s->h3conn, push_id);
		break;
	}

	case H3_FRAME_DATA:
	case H3_FRAME_HEADERS:
	case H3_FRAME_PUSH_PROMISE:
		/* These frames are not allowed on control stream */
		return -H3_FRAME_UNEXPECTED;

	default:
		/* Unknown frame types should be ignored per RFC 9114 */
		pr_debug("h3: ignoring unknown frame type %llu\n", frame_type);
		break;
	}

	return 0;
}
EXPORT_SYMBOL_GPL(h3_control_recv_frame);

/*
 * =============================================================================
 * Stream Lookup by Push ID
 * =============================================================================
 */

/**
 * h3_stream_lookup_by_push_id - Find push stream by push ID
 * @h3conn: HTTP/3 connection
 * @push_id: Push ID to search for
 *
 * On success the returned stream has an elevated reference count.
 * The caller must call h3_stream_put() when done.
 *
 * Return: Stream (with incremented refcount) or NULL if not found
 */
struct h3_stream *h3_stream_lookup_by_push_id(struct h3_connection *h3conn,
					      u64 push_id)
{
	struct rb_node *node;
	struct h3_stream *h3s;
	int checked = 0;

	spin_lock(&h3conn->lock);

	/*
	 * CF-274: Linear scan through rb_tree by push_id. Bounded by
	 * stream_count to prevent excessive CPU under lock if the tree
	 * is large. Push streams are rare in practice.
	 */
	for (node = rb_first(&h3conn->streams); node; node = rb_next(node)) {
		if (++checked > h3conn->stream_count)
			break;

		h3s = rb_entry(node, struct h3_stream, node);

		if (h3s->type == H3_STREAM_TYPE_PUSH &&
		    h3s->push_id == push_id) {
			refcount_inc(&h3s->refcnt);
			spin_unlock(&h3conn->lock);
			return h3s;
		}
	}

	spin_unlock(&h3conn->lock);
	return NULL;
}
EXPORT_SYMBOL_GPL(h3_stream_lookup_by_push_id);

MODULE_DESCRIPTION("TQUIC HTTP/3 Request/Response Handling");
MODULE_LICENSE("GPL");
MODULE_AUTHOR("Linux Foundation");
