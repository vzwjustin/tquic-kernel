// SPDX-License-Identifier: GPL-2.0-only
/*
 * TQUIC HTTP/3: Stream Type Management
 *
 * Copyright (c) 2026 Linux Foundation
 *
 * Implements HTTP/3 stream type mapping per RFC 9114 Section 6.
 *
 * Stream Types:
 *   Bidirectional:
 *     - Request streams: Carry HTTP request/response pairs
 *       Client-initiated: 0, 4, 8, 12, ...
 *
 *   Unidirectional (identified by stream type byte at start):
 *     - 0x00: Control stream (one per endpoint)
 *     - 0x01: Push stream (server to client)
 *     - 0x02: QPACK Encoder stream
 *     - 0x03: QPACK Decoder stream
 *
 * Critical Streams:
 *   Control, QPACK Encoder, and QPACK Decoder streams are critical.
 *   Closing a critical stream before connection close is an error
 *   (H3_CLOSED_CRITICAL_STREAM).
 */

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/rbtree.h>
#include <linux/list.h>
#include <net/tquic.h>

#include "http3_stream.h"
#include "../core/varint.h"

/* SLAB caches for HTTP/3 structures */
static struct kmem_cache *h3_connection_cache;
static struct kmem_cache *h3_stream_cache;

/*
 * =============================================================================
 * Varint Encoding/Decoding Helpers
 * =============================================================================
 */

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
		return -EINVAL;

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
 * HTTP/3 Error Handling
 * =============================================================================
 */

/**
 * h3_error_name - Get human-readable error code name
 * @error_code: HTTP/3 error code
 *
 * Return: Error name string
 */
const char *h3_error_name(u64 error_code)
{
	switch (error_code) {
	case H3_NO_ERROR:
		return "H3_NO_ERROR";
	case H3_GENERAL_PROTOCOL_ERROR:
		return "H3_GENERAL_PROTOCOL_ERROR";
	case H3_INTERNAL_ERROR:
		return "H3_INTERNAL_ERROR";
	case H3_STREAM_CREATION_ERROR:
		return "H3_STREAM_CREATION_ERROR";
	case H3_CLOSED_CRITICAL_STREAM:
		return "H3_CLOSED_CRITICAL_STREAM";
	case H3_FRAME_UNEXPECTED:
		return "H3_FRAME_UNEXPECTED";
	case H3_FRAME_ERROR:
		return "H3_FRAME_ERROR";
	case H3_EXCESSIVE_LOAD:
		return "H3_EXCESSIVE_LOAD";
	case H3_ID_ERROR:
		return "H3_ID_ERROR";
	case H3_SETTINGS_ERROR:
		return "H3_SETTINGS_ERROR";
	case H3_MISSING_SETTINGS:
		return "H3_MISSING_SETTINGS";
	case H3_REQUEST_REJECTED:
		return "H3_REQUEST_REJECTED";
	case H3_REQUEST_CANCELLED:
		return "H3_REQUEST_CANCELLED";
	case H3_REQUEST_INCOMPLETE:
		return "H3_REQUEST_INCOMPLETE";
	case H3_MESSAGE_ERROR:
		return "H3_MESSAGE_ERROR";
	case H3_CONNECT_ERROR:
		return "H3_CONNECT_ERROR";
	case H3_VERSION_FALLBACK:
		return "H3_VERSION_FALLBACK";
	case QPACK_DECOMPRESSION_FAILED:
		return "QPACK_DECOMPRESSION_FAILED";
	case QPACK_ENCODER_STREAM_ERROR:
		return "QPACK_ENCODER_STREAM_ERROR";
	case QPACK_DECODER_STREAM_ERROR:
		return "QPACK_DECODER_STREAM_ERROR";
	default:
		return "UNKNOWN";
	}
}
EXPORT_SYMBOL_GPL(h3_error_name);

/**
 * h3_is_connection_error - Check if error is connection-level
 * @error_code: HTTP/3 error code
 *
 * Return: true if this error should close the connection
 */
bool h3_is_connection_error(u64 error_code)
{
	switch (error_code) {
	case H3_NO_ERROR:
		return false;
	case H3_REQUEST_CANCELLED:
	case H3_REQUEST_REJECTED:
		return false;  /* Stream-level errors */
	default:
		return true;
	}
}
EXPORT_SYMBOL_GPL(h3_is_connection_error);

/*
 * =============================================================================
 * HTTP/3 Stream Management
 * =============================================================================
 */

/**
 * h3_stream_alloc - Allocate an HTTP/3 stream structure
 *
 * Return: New h3_stream or NULL on failure
 */
static struct h3_stream *h3_stream_alloc(void)
{
	struct h3_stream *h3s;

	h3s = kmem_cache_zalloc(h3_stream_cache, GFP_KERNEL);
	if (!h3s)
		return NULL;

	spin_lock_init(&h3s->lock);
	INIT_LIST_HEAD(&h3s->list);
	RB_CLEAR_NODE(&h3s->node);

	h3s->request_state = H3_REQUEST_IDLE;
	h3s->push_state = H3_PUSH_IDLE;
	h3s->content_length = -1;

	return h3s;
}

/**
 * h3_stream_free - Free an HTTP/3 stream structure
 * @h3s: Stream to free
 */
static void h3_stream_free(struct h3_stream *h3s)
{
	if (!h3s)
		return;

	kmem_cache_free(h3_stream_cache, h3s);
}

/**
 * h3_stream_insert - Insert stream into connection's tree
 * @h3conn: HTTP/3 connection
 * @h3s: Stream to insert
 *
 * Return: 0 on success, -EEXIST if stream ID exists
 */
static int h3_stream_insert(struct h3_connection *h3conn, struct h3_stream *h3s)
{
	struct rb_node **link = &h3conn->streams.rb_node;
	struct rb_node *parent = NULL;
	u64 stream_id;

	if (!h3s->base)
		return -EINVAL;

	stream_id = h3s->base->id;

	while (*link) {
		struct h3_stream *entry;

		parent = *link;
		entry = rb_entry(parent, struct h3_stream, node);

		if (stream_id < entry->base->id)
			link = &parent->rb_left;
		else if (stream_id > entry->base->id)
			link = &parent->rb_right;
		else
			return -EEXIST;
	}

	rb_link_node(&h3s->node, parent, link);
	rb_insert_color(&h3s->node, &h3conn->streams);
	h3conn->stream_count++;

	return 0;
}

/**
 * h3_stream_remove - Remove stream from connection's tree
 * @h3conn: HTTP/3 connection
 * @h3s: Stream to remove
 */
static void h3_stream_remove(struct h3_connection *h3conn, struct h3_stream *h3s)
{
	if (RB_EMPTY_NODE(&h3s->node))
		return;

	rb_erase(&h3s->node, &h3conn->streams);
	RB_CLEAR_NODE(&h3s->node);
	h3conn->stream_count--;
}

/**
 * h3_stream_lookup - Find an HTTP/3 stream by QUIC stream ID
 * @h3conn: HTTP/3 connection
 * @stream_id: QUIC stream ID
 *
 * Return: Stream or NULL if not found
 */
struct h3_stream *h3_stream_lookup(struct h3_connection *h3conn, u64 stream_id)
{
	struct rb_node *node;

	spin_lock(&h3conn->lock);

	node = h3conn->streams.rb_node;
	while (node) {
		struct h3_stream *h3s;

		h3s = rb_entry(node, struct h3_stream, node);

		if (stream_id < h3s->base->id)
			node = node->rb_left;
		else if (stream_id > h3s->base->id)
			node = node->rb_right;
		else {
			spin_unlock(&h3conn->lock);
			return h3s;
		}
	}

	spin_unlock(&h3conn->lock);
	return NULL;
}
EXPORT_SYMBOL_GPL(h3_stream_lookup);

/**
 * h3_stream_create_request - Create a new HTTP/3 request stream
 * @h3conn: HTTP/3 connection
 *
 * Creates a new client-initiated bidirectional stream for HTTP requests.
 * Stream IDs: 0, 4, 8, 12, ...
 *
 * Return: New stream or ERR_PTR on failure
 */
struct h3_stream *h3_stream_create_request(struct h3_connection *h3conn)
{
	struct h3_stream *h3s;
	struct tquic_stream *base;
	int ret;

	if (h3conn->is_server) {
		pr_err("h3: server cannot create request streams\n");
		return ERR_PTR(-EINVAL);
	}

	if (h3conn->goaway_received) {
		pr_debug("h3: cannot create request after GOAWAY\n");
		return ERR_PTR(-ECONNRESET);
	}

	/* Create underlying QUIC bidirectional stream */
	base = tquic_stream_open(h3conn->conn, true);
	if (IS_ERR(base))
		return ERR_CAST(base);

	/* Validate stream ID follows expected pattern */
	ret = h3_validate_request_stream_id(base->id, h3conn->is_server);
	if (ret) {
		tquic_stream_close(base);
		return ERR_PTR(ret);
	}

	/* Allocate HTTP/3 stream state */
	h3s = h3_stream_alloc();
	if (!h3s) {
		tquic_stream_close(base);
		return ERR_PTR(-ENOMEM);
	}

	h3s->base = base;
	h3s->is_request_stream = true;
	h3s->is_uni = false;
	h3s->request_state = H3_REQUEST_IDLE;

	/* Insert into connection's stream tree */
	spin_lock(&h3conn->lock);
	ret = h3_stream_insert(h3conn, h3s);
	spin_unlock(&h3conn->lock);

	if (ret) {
		h3_stream_free(h3s);
		tquic_stream_close(base);
		return ERR_PTR(ret);
	}

	pr_debug("h3: created request stream id=%llu\n", base->id);

	return h3s;
}
EXPORT_SYMBOL_GPL(h3_stream_create_request);

/**
 * h3_stream_create_push - Create a new HTTP/3 push stream
 * @h3conn: HTTP/3 connection
 * @push_id: Push ID for this stream
 *
 * Creates a server-initiated unidirectional push stream.
 * Only valid for server connections.
 *
 * Return: New stream or ERR_PTR on failure
 */
struct h3_stream *h3_stream_create_push(struct h3_connection *h3conn,
					u64 push_id)
{
	struct h3_stream *h3s;
	struct tquic_stream *base;
	int ret;

	if (!h3conn->is_server) {
		pr_err("h3: only server can create push streams\n");
		return ERR_PTR(-EINVAL);
	}

	if (!h3conn->push_enabled || push_id > h3conn->max_push_id) {
		pr_err("h3: push_id %llu exceeds max %llu\n",
		       push_id, h3conn->max_push_id);
		return ERR_PTR(-H3_ID_ERROR);
	}

	/* Create underlying QUIC unidirectional stream */
	base = tquic_stream_open(h3conn->conn, false);
	if (IS_ERR(base))
		return ERR_CAST(base);

	/* Allocate HTTP/3 stream state */
	h3s = h3_stream_alloc();
	if (!h3s) {
		tquic_stream_close(base);
		return ERR_PTR(-ENOMEM);
	}

	h3s->base = base;
	h3s->type = H3_STREAM_TYPE_PUSH;
	h3s->is_request_stream = false;
	h3s->is_uni = true;
	h3s->push_id = push_id;
	h3s->push_state = H3_PUSH_ACTIVE;

	/* Insert into connection's stream tree */
	spin_lock(&h3conn->lock);
	ret = h3_stream_insert(h3conn, h3s);
	spin_unlock(&h3conn->lock);

	if (ret) {
		h3_stream_free(h3s);
		tquic_stream_close(base);
		return ERR_PTR(ret);
	}

	pr_debug("h3: created push stream id=%llu push_id=%llu\n",
		 base->id, push_id);

	return h3s;
}
EXPORT_SYMBOL_GPL(h3_stream_create_push);

/**
 * h3_stream_accept - Accept an incoming stream and create HTTP/3 state
 * @h3conn: HTTP/3 connection
 * @base: Underlying QUIC stream
 *
 * Called when a new stream is opened by the peer.
 * For unidirectional streams, the type byte must be received to determine
 * the stream type.
 *
 * Return: New stream or ERR_PTR on failure
 */
struct h3_stream *h3_stream_accept(struct h3_connection *h3conn,
				   struct tquic_stream *base)
{
	struct h3_stream *h3s;
	int ret;

	h3s = h3_stream_alloc();
	if (!h3s)
		return ERR_PTR(-ENOMEM);

	h3s->base = base;
	h3s->is_uni = h3_stream_id_is_uni(base->id);

	if (h3s->is_uni) {
		/* Unidirectional stream - type byte pending */
		h3s->type_received = false;
		h3s->is_request_stream = false;
	} else {
		/* Bidirectional stream - must be request stream */
		ret = h3_validate_request_stream_id(base->id, h3conn->is_server);
		if (ret) {
			h3_stream_free(h3s);
			return ERR_PTR(ret);
		}
		h3s->is_request_stream = true;
		h3s->type_received = true;  /* No type byte for bidi */
	}

	spin_lock(&h3conn->lock);
	ret = h3_stream_insert(h3conn, h3s);
	spin_unlock(&h3conn->lock);

	if (ret) {
		h3_stream_free(h3s);
		return ERR_PTR(ret);
	}

	pr_debug("h3: accepted stream id=%llu uni=%d\n", base->id, h3s->is_uni);

	return h3s;
}
EXPORT_SYMBOL_GPL(h3_stream_accept);

/**
 * h3_stream_send_type - Send stream type byte for unidirectional stream
 * @h3s: HTTP/3 stream
 *
 * Must be called at the start of a unidirectional stream to identify
 * the stream type to the peer.
 *
 * Return: 0 on success, negative error
 */
int h3_stream_send_type(struct h3_stream *h3s)
{
	u8 buf[8];
	int len;
	int ret;

	if (!h3s->is_uni) {
		pr_err("h3: cannot send type on bidirectional stream\n");
		return -EINVAL;
	}

	if (h3s->type_sent) {
		pr_err("h3: stream type already sent\n");
		return -EALREADY;
	}

	/* Encode stream type as varint */
	len = h3_varint_encode(h3s->type, buf, sizeof(buf));
	if (len < 0)
		return len;

	/* Send type byte on stream */
	ret = tquic_stream_send(h3s->base, buf, len, false);
	if (ret < 0)
		return ret;

	h3s->type_sent = true;
	h3s->bytes_sent += len;

	pr_debug("h3: sent stream type %s on id=%llu\n",
		 h3_stream_type_name(h3s->type), h3s->base->id);

	return 0;
}
EXPORT_SYMBOL_GPL(h3_stream_send_type);

/**
 * h3_stream_recv_type - Receive and parse stream type byte
 * @h3s: HTTP/3 stream
 * @data: Received data
 * @len: Data length
 * @type_out: Output stream type
 *
 * Parses the stream type varint at the start of a unidirectional stream.
 *
 * Return: Number of bytes consumed, or negative error
 */
int h3_stream_recv_type(struct h3_stream *h3s, const u8 *data, size_t len,
			u64 *type_out)
{
	u64 type;
	int consumed;

	if (!h3s->is_uni) {
		pr_err("h3: bidirectional streams don't have type byte\n");
		return -EINVAL;
	}

	if (h3s->type_received) {
		pr_err("h3: stream type already received\n");
		return -EALREADY;
	}

	consumed = h3_varint_decode(data, len, &type);
	if (consumed < 0)
		return consumed;

	h3s->type = type;
	h3s->type_received = true;
	h3s->bytes_received += consumed;

	if (type_out)
		*type_out = type;

	pr_debug("h3: received stream type %s on id=%llu\n",
		 h3_stream_type_name(type), h3s->base->id);

	return consumed;
}
EXPORT_SYMBOL_GPL(h3_stream_recv_type);

/**
 * h3_stream_transition_state - Transition request stream state
 * @h3s: HTTP/3 stream
 * @new_state: Target state
 *
 * Validates and performs state transition for request streams.
 *
 * Return: 0 on success, -EINVAL on invalid transition
 */
int h3_stream_transition_state(struct h3_stream *h3s,
			       enum h3_request_state new_state)
{
	enum h3_request_state old_state = h3s->request_state;
	bool valid = false;

	/* Validate state transition */
	switch (old_state) {
	case H3_REQUEST_IDLE:
		valid = (new_state == H3_REQUEST_HEADERS_RECEIVED);
		break;
	case H3_REQUEST_HEADERS_RECEIVED:
		valid = (new_state == H3_REQUEST_DATA ||
			 new_state == H3_REQUEST_TRAILERS ||
			 new_state == H3_REQUEST_COMPLETE);
		break;
	case H3_REQUEST_DATA:
		valid = (new_state == H3_REQUEST_DATA ||
			 new_state == H3_REQUEST_TRAILERS ||
			 new_state == H3_REQUEST_COMPLETE);
		break;
	case H3_REQUEST_TRAILERS:
		valid = (new_state == H3_REQUEST_COMPLETE);
		break;
	case H3_REQUEST_COMPLETE:
		valid = false;  /* Terminal state */
		break;
	case H3_REQUEST_ERROR:
		valid = false;  /* Terminal state */
		break;
	}

	if (!valid) {
		pr_err("h3: invalid state transition %d -> %d\n",
		       old_state, new_state);
		return -EINVAL;
	}

	h3s->request_state = new_state;

	pr_debug("h3: stream %llu state %d -> %d\n",
		 h3s->base->id, old_state, new_state);

	return 0;
}
EXPORT_SYMBOL_GPL(h3_stream_transition_state);

/**
 * h3_stream_validate_frame - Validate frame is allowed on this stream
 * @h3s: HTTP/3 stream
 * @frame_type: Frame type to validate
 *
 * Checks that the frame type is allowed based on stream type and state.
 *
 * Return: 0 if valid, -H3_FRAME_UNEXPECTED if not allowed
 */
int h3_stream_validate_frame(struct h3_stream *h3s, u64 frame_type)
{
	/* Control stream frames */
	if (h3s->type == H3_STREAM_TYPE_CONTROL) {
		switch (frame_type) {
		case H3_FRAME_SETTINGS:
		case H3_FRAME_GOAWAY:
		case H3_FRAME_MAX_PUSH_ID:
		case H3_FRAME_CANCEL_PUSH:
			return 0;
		case H3_FRAME_DATA:
		case H3_FRAME_HEADERS:
		case H3_FRAME_PUSH_PROMISE:
			return -H3_FRAME_UNEXPECTED;
		}
	}

	/* Request stream frames */
	if (h3s->is_request_stream) {
		switch (frame_type) {
		case H3_FRAME_DATA:
		case H3_FRAME_HEADERS:
		case H3_FRAME_PUSH_PROMISE:
			return 0;
		case H3_FRAME_SETTINGS:
		case H3_FRAME_GOAWAY:
		case H3_FRAME_MAX_PUSH_ID:
		case H3_FRAME_CANCEL_PUSH:
			return -H3_FRAME_UNEXPECTED;
		}
	}

	/* Push stream frames */
	if (h3s->type == H3_STREAM_TYPE_PUSH) {
		switch (frame_type) {
		case H3_FRAME_DATA:
		case H3_FRAME_HEADERS:
			return 0;
		case H3_FRAME_PUSH_PROMISE:
		case H3_FRAME_SETTINGS:
		case H3_FRAME_GOAWAY:
		case H3_FRAME_MAX_PUSH_ID:
		case H3_FRAME_CANCEL_PUSH:
			return -H3_FRAME_UNEXPECTED;
		}
	}

	return 0;
}
EXPORT_SYMBOL_GPL(h3_stream_validate_frame);

/**
 * h3_stream_close - Close an HTTP/3 stream
 * @h3conn: HTTP/3 connection
 * @h3s: Stream to close
 */
void h3_stream_close(struct h3_connection *h3conn, struct h3_stream *h3s)
{
	if (!h3s)
		return;

	/* Check if closing a critical stream */
	if (h3s->is_uni && h3_stream_type_is_critical(h3s->type)) {
		pr_warn("h3: closing critical stream type %s\n",
			h3_stream_type_name(h3s->type));
		/* This would normally trigger H3_CLOSED_CRITICAL_STREAM error */
	}

	spin_lock(&h3conn->lock);
	h3_stream_remove(h3conn, h3s);
	spin_unlock(&h3conn->lock);

	/* Close underlying QUIC stream */
	if (h3s->base)
		tquic_stream_close(h3s->base);

	h3_stream_free(h3s);
}
EXPORT_SYMBOL_GPL(h3_stream_close);

/**
 * h3_stream_reset - Reset an HTTP/3 stream with error
 * @h3conn: HTTP/3 connection
 * @h3s: Stream to reset
 * @error_code: HTTP/3 error code
 *
 * Return: 0 on success, negative error
 */
int h3_stream_reset(struct h3_connection *h3conn, struct h3_stream *h3s,
		    u64 error_code)
{
	if (!h3s || !h3s->base)
		return -EINVAL;

	h3s->request_state = H3_REQUEST_ERROR;

	/* Reset underlying QUIC stream */
	tquic_stream_reset(h3s->base, error_code);

	pr_debug("h3: reset stream %llu with error %s\n",
		 h3s->base->id, h3_error_name(error_code));

	return 0;
}
EXPORT_SYMBOL_GPL(h3_stream_reset);

/*
 * =============================================================================
 * HTTP/3 Connection Management
 * =============================================================================
 */

/**
 * h3_connection_create - Create an HTTP/3 connection
 * @conn: Underlying QUIC connection
 * @is_server: True if this is a server connection
 *
 * Return: New connection or NULL on failure
 */
struct h3_connection *h3_connection_create(struct tquic_connection *conn,
					   bool is_server)
{
	struct h3_connection *h3conn;

	h3conn = kmem_cache_zalloc(h3_connection_cache, GFP_KERNEL);
	if (!h3conn)
		return NULL;

	h3conn->conn = conn;
	h3conn->is_server = is_server;
	h3conn->streams = RB_ROOT;
	spin_lock_init(&h3conn->lock);

	/* Initialize default settings */
	h3conn->local_settings.qpack_max_table_capacity =
		H3_DEFAULT_QPACK_MAX_TABLE_CAPACITY;
	h3conn->local_settings.max_field_section_size =
		H3_DEFAULT_MAX_FIELD_SECTION_SIZE;
	h3conn->local_settings.qpack_blocked_streams =
		H3_DEFAULT_QPACK_BLOCKED_STREAMS;

	/* Initialize push state */
	h3conn->max_push_id = 0;
	h3conn->next_push_id = 0;
	h3conn->push_enabled = false;

	pr_debug("h3: created connection is_server=%d\n", is_server);

	return h3conn;
}
EXPORT_SYMBOL_GPL(h3_connection_create);

/**
 * h3_connection_destroy - Destroy an HTTP/3 connection
 * @h3conn: Connection to destroy
 */
void h3_connection_destroy(struct h3_connection *h3conn)
{
	struct rb_node *node;

	if (!h3conn)
		return;

	spin_lock(&h3conn->lock);

	/* Close all streams */
	while ((node = rb_first(&h3conn->streams))) {
		struct h3_stream *h3s;

		h3s = rb_entry(node, struct h3_stream, node);
		rb_erase(node, &h3conn->streams);
		h3conn->stream_count--;

		if (h3s->base)
			tquic_stream_close(h3s->base);
		h3_stream_free(h3s);
	}

	spin_unlock(&h3conn->lock);

	kmem_cache_free(h3_connection_cache, h3conn);

	pr_debug("h3: destroyed connection\n");
}
EXPORT_SYMBOL_GPL(h3_connection_destroy);

/**
 * h3_connection_open_control_streams - Open required control streams
 * @h3conn: HTTP/3 connection
 *
 * Opens the local control stream and QPACK streams.
 * Must be called after the QUIC connection is established.
 *
 * Return: 0 on success, negative error
 */
int h3_connection_open_control_streams(struct h3_connection *h3conn)
{
	struct h3_stream *h3s;
	struct tquic_stream *base;
	int ret;

	if (h3conn->control_stream_opened)
		return 0;

	/* Create control stream */
	base = tquic_stream_open(h3conn->conn, false);
	if (IS_ERR(base))
		return PTR_ERR(base);

	h3s = h3_stream_alloc();
	if (!h3s) {
		tquic_stream_close(base);
		return -ENOMEM;
	}

	h3s->base = base;
	h3s->type = H3_STREAM_TYPE_CONTROL;
	h3s->is_uni = true;
	h3s->is_request_stream = false;

	spin_lock(&h3conn->lock);
	ret = h3_stream_insert(h3conn, h3s);
	spin_unlock(&h3conn->lock);

	if (ret) {
		h3_stream_free(h3s);
		tquic_stream_close(base);
		return ret;
	}

	h3conn->local_control = h3s;

	/* Send stream type */
	ret = h3_stream_send_type(h3s);
	if (ret) {
		h3_stream_close(h3conn, h3s);
		h3conn->local_control = NULL;
		return ret;
	}

	/* Create QPACK encoder stream */
	base = tquic_stream_open(h3conn->conn, false);
	if (IS_ERR(base)) {
		h3_stream_close(h3conn, h3conn->local_control);
		h3conn->local_control = NULL;
		return PTR_ERR(base);
	}

	h3s = h3_stream_alloc();
	if (!h3s) {
		tquic_stream_close(base);
		h3_stream_close(h3conn, h3conn->local_control);
		h3conn->local_control = NULL;
		return -ENOMEM;
	}

	h3s->base = base;
	h3s->type = H3_STREAM_TYPE_QPACK_ENCODER;
	h3s->is_uni = true;

	spin_lock(&h3conn->lock);
	ret = h3_stream_insert(h3conn, h3s);
	spin_unlock(&h3conn->lock);

	if (ret) {
		h3_stream_free(h3s);
		tquic_stream_close(base);
		h3_stream_close(h3conn, h3conn->local_control);
		h3conn->local_control = NULL;
		return ret;
	}

	h3conn->local_qpack_enc = h3s;
	h3_stream_send_type(h3s);

	/* Create QPACK decoder stream */
	base = tquic_stream_open(h3conn->conn, false);
	if (IS_ERR(base)) {
		h3_stream_close(h3conn, h3conn->local_qpack_enc);
		h3conn->local_qpack_enc = NULL;
		h3_stream_close(h3conn, h3conn->local_control);
		h3conn->local_control = NULL;
		return PTR_ERR(base);
	}

	h3s = h3_stream_alloc();
	if (!h3s) {
		tquic_stream_close(base);
		h3_stream_close(h3conn, h3conn->local_qpack_enc);
		h3conn->local_qpack_enc = NULL;
		h3_stream_close(h3conn, h3conn->local_control);
		h3conn->local_control = NULL;
		return -ENOMEM;
	}

	h3s->base = base;
	h3s->type = H3_STREAM_TYPE_QPACK_DECODER;
	h3s->is_uni = true;

	spin_lock(&h3conn->lock);
	ret = h3_stream_insert(h3conn, h3s);
	spin_unlock(&h3conn->lock);

	if (ret) {
		h3_stream_free(h3s);
		tquic_stream_close(base);
		h3_stream_close(h3conn, h3conn->local_qpack_enc);
		h3conn->local_qpack_enc = NULL;
		h3_stream_close(h3conn, h3conn->local_control);
		h3conn->local_control = NULL;
		return ret;
	}

	h3conn->local_qpack_dec = h3s;
	h3_stream_send_type(h3s);

	h3conn->control_stream_opened = true;

	pr_debug("h3: opened control streams\n");

	return 0;
}
EXPORT_SYMBOL_GPL(h3_connection_open_control_streams);

/**
 * h3_connection_send_settings - Send SETTINGS frame on control stream
 * @h3conn: HTTP/3 connection
 *
 * Return: 0 on success, negative error
 */
int h3_connection_send_settings(struct h3_connection *h3conn)
{
	struct h3_stream *control = h3conn->local_control;
	u8 buf[64];
	u8 *p = buf;
	int ret;

	if (!control) {
		pr_err("h3: control stream not open\n");
		return -ENOTCONN;
	}

	/* Build SETTINGS frame */
	/* Frame type */
	ret = h3_varint_encode(H3_FRAME_SETTINGS, p, buf + sizeof(buf) - p);
	if (ret < 0)
		return ret;
	p += ret;

	/* Frame length placeholder - we'll calculate and encode settings */
	u8 *len_pos = p;
	p += 1;  /* Reserve space for length (will be small) */

	u8 *settings_start = p;

	/* QPACK_MAX_TABLE_CAPACITY if non-zero */
	if (h3conn->local_settings.qpack_max_table_capacity > 0) {
		ret = h3_varint_encode(H3_SETTINGS_QPACK_MAX_TABLE_CAPACITY,
				       p, buf + sizeof(buf) - p);
		if (ret < 0)
			return ret;
		p += ret;

		ret = h3_varint_encode(h3conn->local_settings.qpack_max_table_capacity,
				       p, buf + sizeof(buf) - p);
		if (ret < 0)
			return ret;
		p += ret;
	}

	/* MAX_FIELD_SECTION_SIZE if non-zero */
	if (h3conn->local_settings.max_field_section_size > 0) {
		ret = h3_varint_encode(H3_SETTINGS_MAX_FIELD_SECTION_SIZE,
				       p, buf + sizeof(buf) - p);
		if (ret < 0)
			return ret;
		p += ret;

		ret = h3_varint_encode(h3conn->local_settings.max_field_section_size,
				       p, buf + sizeof(buf) - p);
		if (ret < 0)
			return ret;
		p += ret;
	}

	/* QPACK_BLOCKED_STREAMS if non-zero */
	if (h3conn->local_settings.qpack_blocked_streams > 0) {
		ret = h3_varint_encode(H3_SETTINGS_QPACK_BLOCKED_STREAMS,
				       p, buf + sizeof(buf) - p);
		if (ret < 0)
			return ret;
		p += ret;

		ret = h3_varint_encode(h3conn->local_settings.qpack_blocked_streams,
				       p, buf + sizeof(buf) - p);
		if (ret < 0)
			return ret;
		p += ret;
	}

	/* Encode frame length */
	size_t settings_len = p - settings_start;
	*len_pos = (u8)settings_len;

	/* Send on control stream */
	ret = tquic_stream_send(control->base, buf, p - buf, false);
	if (ret < 0)
		return ret;

	control->bytes_sent += (p - buf);

	pr_debug("h3: sent SETTINGS frame (%zu bytes)\n", p - buf);

	return 0;
}
EXPORT_SYMBOL_GPL(h3_connection_send_settings);

/**
 * h3_connection_send_goaway - Send GOAWAY frame
 * @h3conn: HTTP/3 connection
 * @stream_id: Stream ID to include in GOAWAY
 *
 * Return: 0 on success, negative error
 */
int h3_connection_send_goaway(struct h3_connection *h3conn, u64 stream_id)
{
	struct h3_stream *control = h3conn->local_control;
	u8 buf[32];
	u8 *p = buf;
	int ret;

	if (!control) {
		pr_err("h3: control stream not open\n");
		return -ENOTCONN;
	}

	if (h3conn->goaway_sent)
		return 0;

	/* Frame type */
	ret = h3_varint_encode(H3_FRAME_GOAWAY, p, buf + sizeof(buf) - p);
	if (ret < 0)
		return ret;
	p += ret;

	/* Frame length (varint of stream_id length) */
	int id_len = h3_varint_len(stream_id);
	ret = h3_varint_encode(id_len, p, buf + sizeof(buf) - p);
	if (ret < 0)
		return ret;
	p += ret;

	/* Stream ID */
	ret = h3_varint_encode(stream_id, p, buf + sizeof(buf) - p);
	if (ret < 0)
		return ret;
	p += ret;

	ret = tquic_stream_send(control->base, buf, p - buf, false);
	if (ret < 0)
		return ret;

	h3conn->goaway_sent = true;
	h3conn->goaway_id = stream_id;

	pr_debug("h3: sent GOAWAY stream_id=%llu\n", stream_id);

	return 0;
}
EXPORT_SYMBOL_GPL(h3_connection_send_goaway);

/**
 * h3_connection_recv_goaway - Process received GOAWAY frame
 * @h3conn: HTTP/3 connection
 * @stream_id: Stream ID from GOAWAY frame
 *
 * Return: 0 on success, negative error
 */
int h3_connection_recv_goaway(struct h3_connection *h3conn, u64 stream_id)
{
	if (h3conn->goaway_received && stream_id > h3conn->goaway_id) {
		/* GOAWAY stream ID must not increase */
		return -H3_ID_ERROR;
	}

	h3conn->goaway_received = true;
	h3conn->goaway_id = stream_id;

	pr_debug("h3: received GOAWAY stream_id=%llu\n", stream_id);

	return 0;
}
EXPORT_SYMBOL_GPL(h3_connection_recv_goaway);

/**
 * h3_connection_is_going_away - Check if connection is in GOAWAY state
 * @h3conn: HTTP/3 connection
 *
 * Return: true if GOAWAY has been sent or received
 */
bool h3_connection_is_going_away(struct h3_connection *h3conn)
{
	return h3conn->goaway_sent || h3conn->goaway_received;
}
EXPORT_SYMBOL_GPL(h3_connection_is_going_away);

/**
 * h3_connection_send_max_push_id - Send MAX_PUSH_ID frame
 * @h3conn: HTTP/3 connection
 * @push_id: Maximum push ID to advertise
 *
 * Only valid for client connections.
 *
 * Return: 0 on success, negative error
 */
int h3_connection_send_max_push_id(struct h3_connection *h3conn, u64 push_id)
{
	struct h3_stream *control = h3conn->local_control;
	u8 buf[32];
	u8 *p = buf;
	int ret;

	if (h3conn->is_server) {
		pr_err("h3: server cannot send MAX_PUSH_ID\n");
		return -EINVAL;
	}

	if (!control)
		return -ENOTCONN;

	/* Frame type */
	ret = h3_varint_encode(H3_FRAME_MAX_PUSH_ID, p, buf + sizeof(buf) - p);
	if (ret < 0)
		return ret;
	p += ret;

	/* Frame length */
	int id_len = h3_varint_len(push_id);
	ret = h3_varint_encode(id_len, p, buf + sizeof(buf) - p);
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

	h3conn->max_push_id = push_id;
	h3conn->push_enabled = true;

	pr_debug("h3: sent MAX_PUSH_ID push_id=%llu\n", push_id);

	return 0;
}
EXPORT_SYMBOL_GPL(h3_connection_send_max_push_id);

/*
 * =============================================================================
 * Module Initialization
 * =============================================================================
 */

/**
 * tquic_http3_init - Initialize HTTP/3 subsystem
 *
 * Return: 0 on success, negative error
 */
int __init tquic_http3_init(void)
{
	/* Create SLAB caches */
	h3_connection_cache = kmem_cache_create("h3_connection",
						sizeof(struct h3_connection),
						0, SLAB_HWCACHE_ALIGN, NULL);
	if (!h3_connection_cache)
		return -ENOMEM;

	h3_stream_cache = kmem_cache_create("h3_stream",
					    sizeof(struct h3_stream),
					    0, SLAB_HWCACHE_ALIGN, NULL);
	if (!h3_stream_cache) {
		kmem_cache_destroy(h3_connection_cache);
		return -ENOMEM;
	}

	pr_info("TQUIC HTTP/3: initialized\n");

	return 0;
}

/**
 * tquic_http3_exit - Cleanup HTTP/3 subsystem
 */
void __exit tquic_http3_exit(void)
{
	if (h3_stream_cache)
		kmem_cache_destroy(h3_stream_cache);
	if (h3_connection_cache)
		kmem_cache_destroy(h3_connection_cache);

	pr_info("TQUIC HTTP/3: exited\n");
}

MODULE_DESCRIPTION("TQUIC HTTP/3 Stream Type Mapping");
MODULE_LICENSE("GPL");
MODULE_AUTHOR("Linux Foundation");
