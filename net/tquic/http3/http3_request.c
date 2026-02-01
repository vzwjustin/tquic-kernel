// SPDX-License-Identifier: GPL-2.0-only
/*
 * TQUIC HTTP/3: Request/Response Handling
 *
 * Copyright (c) 2026 Linux Foundation
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
#include <net/tquic.h>

#include "http3_stream.h"
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

/**
 * h3_varint_encode - Encode a QUIC variable-length integer
 * @value: Value to encode
 * @buf: Output buffer
 * @buflen: Buffer length
 *
 * Return: Number of bytes written, or negative error
 */
static int h3_varint_encode(u64 value, u8 *buf, size_t buflen)
{
	int len;

	if (value <= 63) {
		len = 1;
		if (buflen < len)
			return -ENOBUFS;
		buf[0] = (u8)value;
	} else if (value <= 16383) {
		len = 2;
		if (buflen < len)
			return -ENOBUFS;
		buf[0] = 0x40 | (u8)(value >> 8);
		buf[1] = (u8)value;
	} else if (value <= 1073741823) {
		len = 4;
		if (buflen < len)
			return -ENOBUFS;
		buf[0] = 0x80 | (u8)(value >> 24);
		buf[1] = (u8)(value >> 16);
		buf[2] = (u8)(value >> 8);
		buf[3] = (u8)value;
	} else if (value <= 4611686018427387903ULL) {
		len = 8;
		if (buflen < len)
			return -ENOBUFS;
		buf[0] = 0xc0 | (u8)(value >> 56);
		buf[1] = (u8)(value >> 48);
		buf[2] = (u8)(value >> 40);
		buf[3] = (u8)(value >> 32);
		buf[4] = (u8)(value >> 24);
		buf[5] = (u8)(value >> 16);
		buf[6] = (u8)(value >> 8);
		buf[7] = (u8)value;
	} else {
		return -ERANGE;
	}

	return len;
}

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

	if (!h3s->is_request_stream) {
		pr_err("h3: not a request stream\n");
		return -EINVAL;
	}

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

	spin_unlock(&h3s->lock);

	/* Build HEADERS frame header */
	hdr_len = h3_build_frame_header(H3_FRAME_HEADERS, len,
					frame_hdr, sizeof(frame_hdr));
	if (hdr_len < 0)
		return hdr_len;

	/* Send frame header */
	ret = tquic_stream_send(h3s->base, frame_hdr, hdr_len, false);
	if (ret < 0)
		return ret;

	/* Send header block */
	ret = tquic_stream_send(h3s->base, headers, len, false);
	if (ret < 0)
		return ret;

	spin_lock(&h3s->lock);
	h3s->headers_sent = true;
	h3s->bytes_sent += hdr_len + len;
	spin_unlock(&h3s->lock);

	pr_debug("h3: sent HEADERS frame (%zu bytes) on stream %llu\n",
		 len, h3s->base->id);

	return 0;
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

	/* Cannot send DATA after trailers */
	if (h3s->trailers_received) {
		spin_unlock(&h3s->lock);
		pr_err("h3: cannot send DATA after trailers\n");
		return -H3_FRAME_UNEXPECTED;
	}

	spin_unlock(&h3s->lock);

	/* Build DATA frame header */
	hdr_len = h3_build_frame_header(H3_FRAME_DATA, len,
					frame_hdr, sizeof(frame_hdr));
	if (hdr_len < 0)
		return hdr_len;

	/* Send frame header */
	ret = tquic_stream_send(h3s->base, frame_hdr, hdr_len, false);
	if (ret < 0)
		return ret;

	/* Send data */
	ret = tquic_stream_send(h3s->base, data, len, false);
	if (ret < 0)
		return ret;

	spin_lock(&h3s->lock);
	h3s->data_offset += len;
	h3s->bytes_sent += hdr_len + len;
	spin_unlock(&h3s->lock);

	pr_debug("h3: sent DATA frame (%zu bytes) on stream %llu\n",
		 len, h3s->base->id);

	return 0;
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

	if (!h3s->headers_sent) {
		spin_unlock(&h3s->lock);
		return -H3_FRAME_UNEXPECTED;
	}

	spin_unlock(&h3s->lock);

	/* Trailing HEADERS is just another HEADERS frame */
	hdr_len = h3_build_frame_header(H3_FRAME_HEADERS, len,
					frame_hdr, sizeof(frame_hdr));
	if (hdr_len < 0)
		return hdr_len;

	ret = tquic_stream_send(h3s->base, frame_hdr, hdr_len, false);
	if (ret < 0)
		return ret;

	ret = tquic_stream_send(h3s->base, trailers, len, false);
	if (ret < 0)
		return ret;

	spin_lock(&h3s->lock);
	h3s->bytes_sent += hdr_len + len;
	spin_unlock(&h3s->lock);

	pr_debug("h3: sent trailing HEADERS frame (%zu bytes) on stream %llu\n",
		 len, h3s->base->id);

	return 0;
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

	if (!h3s->headers_sent) {
		spin_unlock(&h3s->lock);
		return -H3_REQUEST_INCOMPLETE;
	}

	spin_unlock(&h3s->lock);

	/* Send empty data with FIN flag */
	ret = tquic_stream_send(h3s->base, NULL, 0, true);
	if (ret < 0)
		return ret;

	spin_lock(&h3s->lock);
	h3s->fin_sent = true;
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
 * h3_varint_decode - Decode a QUIC variable-length integer
 * @data: Input buffer
 * @len: Buffer length
 * @value: Output value
 *
 * Return: Number of bytes consumed, or negative error
 */
static int h3_varint_decode(const u8 *data, size_t len, u64 *value)
{
	u8 prefix;
	int varint_len;

	if (len < 1)
		return -EAGAIN;

	prefix = data[0] >> 6;
	varint_len = 1 << prefix;

	if (len < varint_len)
		return -EAGAIN;

	switch (varint_len) {
	case 1:
		*value = data[0] & 0x3f;
		break;
	case 2:
		*value = ((u64)(data[0] & 0x3f) << 8) | data[1];
		break;
	case 4:
		*value = ((u64)(data[0] & 0x3f) << 24) |
			 ((u64)data[1] << 16) |
			 ((u64)data[2] << 8) |
			 data[3];
		break;
	case 8:
		*value = ((u64)(data[0] & 0x3f) << 56) |
			 ((u64)data[1] << 48) |
			 ((u64)data[2] << 40) |
			 ((u64)data[3] << 32) |
			 ((u64)data[4] << 24) |
			 ((u64)data[5] << 16) |
			 ((u64)data[6] << 8) |
			 data[7];
		break;
	default:
		return -EINVAL;
	}

	return varint_len;
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
		pr_debug("h3: received SETTINGS frame\n");
		/* Parse settings - implementation would extract parameters */
		break;

	case H3_FRAME_GOAWAY:
		pr_debug("h3: received GOAWAY frame\n");
		/* Parse stream ID from GOAWAY */
		break;

	case H3_FRAME_MAX_PUSH_ID:
		pr_debug("h3: received MAX_PUSH_ID frame\n");
		/* Parse and update max push ID */
		break;

	case H3_FRAME_CANCEL_PUSH:
		pr_debug("h3: received CANCEL_PUSH frame\n");
		/* Parse push ID and cancel */
		break;

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
 * Return: Stream or NULL if not found
 */
struct h3_stream *h3_stream_lookup_by_push_id(struct h3_connection *h3conn,
					      u64 push_id)
{
	struct rb_node *node;
	struct h3_stream *h3s;

	spin_lock(&h3conn->lock);

	for (node = rb_first(&h3conn->streams); node; node = rb_next(node)) {
		h3s = rb_entry(node, struct h3_stream, node);

		if (h3s->type == H3_STREAM_TYPE_PUSH &&
		    h3s->push_id == push_id) {
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
