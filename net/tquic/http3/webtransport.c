// SPDX-License-Identifier: GPL-2.0-only
/*
 * TQUIC WebTransport Implementation (RFC 9220)
 *
 * Copyright (c) 2026 Linux Foundation
 *
 * WebTransport enables bidirectional stream-based communication over HTTP/3.
 * It uses Extended CONNECT (RFC 9220) with :protocol = "webtransport".
 */

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/errno.h>
#include <linux/string.h>
#include <net/tquic.h>
#include <net/tquic_http3.h>

#include "webtransport.h"
#include "qpack.h"
#include "../core/varint.h"

/* Slab caches */
static struct kmem_cache *wt_session_cache;
static struct kmem_cache *wt_stream_cache;

/*
 * Maximum size of the capsule reassembly buffer per session.
 * This limits memory consumption from peers that send very large
 * capsules or drip-feed data to grow the buffer indefinitely.
 */
#define WT_MAX_CAPSULE_BUF_SIZE		(64 * 1024)	/* 64 KB */

/*
 * =============================================================================
 * Module Initialization
 * =============================================================================
 */

int webtransport_init(void)
{
	wt_session_cache = kmem_cache_create("tquic_wt_session",
					     sizeof(struct webtransport_session),
					     0, SLAB_HWCACHE_ALIGN, NULL);
	if (!wt_session_cache)
		return -ENOMEM;

	wt_stream_cache = kmem_cache_create("tquic_wt_stream",
					    sizeof(struct webtransport_stream),
					    0, SLAB_HWCACHE_ALIGN, NULL);
	if (!wt_stream_cache) {
		kmem_cache_destroy(wt_session_cache);
		return -ENOMEM;
	}

	pr_info("webtransport: WebTransport (RFC 9220) initialized\n");
	return 0;
}
EXPORT_SYMBOL_GPL(webtransport_init);

void webtransport_exit(void)
{
	if (wt_stream_cache)
		kmem_cache_destroy(wt_stream_cache);
	if (wt_session_cache)
		kmem_cache_destroy(wt_session_cache);

	pr_info("webtransport: WebTransport unloaded\n");
}
EXPORT_SYMBOL_GPL(webtransport_exit);

/*
 * =============================================================================
 * Context Management
 * =============================================================================
 */

struct webtransport_context *webtransport_context_create(
	struct tquic_http3_conn *h3conn, gfp_t gfp)
{
	struct webtransport_context *ctx;

	if (!h3conn)
		return ERR_PTR(-EINVAL);

	ctx = kzalloc(sizeof(*ctx), gfp);
	if (!ctx)
		return ERR_PTR(-ENOMEM);

	ctx->h3conn = h3conn;
	ctx->enabled = false;
	ctx->sessions = RB_ROOT;
	INIT_LIST_HEAD(&ctx->session_list);
	spin_lock_init(&ctx->lock);

	return ctx;
}
EXPORT_SYMBOL_GPL(webtransport_context_create);

void webtransport_context_destroy(struct webtransport_context *ctx)
{
	struct webtransport_session *session, *tmp;
	unsigned long flags;
	LIST_HEAD(close_list);

	if (!ctx)
		return;

	/*
	 * Move all sessions to a local list under the lock, then
	 * release the lock before calling webtransport_session_put()
	 * which may sleep.  This avoids the previous pattern of
	 * dropping and reacquiring the lock during iteration, which
	 * allowed the list to be modified by concurrent operations
	 * while we were iterating over it.
	 */
	spin_lock_irqsave(&ctx->lock, flags);

	list_for_each_entry_safe(session, tmp, &ctx->session_list, list) {
		list_del(&session->list);
		rb_erase(&session->tree_node, &ctx->sessions);
		ctx->session_count--;
		list_add(&session->list, &close_list);
	}

	spin_unlock_irqrestore(&ctx->lock, flags);

	/* Now close sessions without holding the spinlock */
	list_for_each_entry_safe(session, tmp, &close_list, list) {
		list_del(&session->list);
		webtransport_session_put(session);
	}

	kfree(ctx);
}
EXPORT_SYMBOL_GPL(webtransport_context_destroy);

/*
 * =============================================================================
 * Session RB-Tree Operations
 * =============================================================================
 */

static struct webtransport_session *
session_lookup(struct webtransport_context *ctx, u64 session_id)
{
	struct rb_node *node = ctx->sessions.rb_node;

	while (node) {
		struct webtransport_session *s;

		s = rb_entry(node, struct webtransport_session, tree_node);

		if (session_id < s->session_id)
			node = node->rb_left;
		else if (session_id > s->session_id)
			node = node->rb_right;
		else
			return s;
	}

	return NULL;
}

static int session_insert(struct webtransport_context *ctx,
			  struct webtransport_session *session)
{
	struct rb_node **link = &ctx->sessions.rb_node;
	struct rb_node *parent = NULL;

	while (*link) {
		struct webtransport_session *s;

		parent = *link;
		s = rb_entry(parent, struct webtransport_session, tree_node);

		if (session->session_id < s->session_id)
			link = &parent->rb_left;
		else if (session->session_id > s->session_id)
			link = &parent->rb_right;
		else
			return -EEXIST;
	}

	rb_link_node(&session->tree_node, parent, link);
	rb_insert_color(&session->tree_node, &ctx->sessions);
	list_add_tail(&session->list, &ctx->session_list);
	ctx->session_count++;

	return 0;
}

/*
 * =============================================================================
 * Session Management
 * =============================================================================
 */

static struct webtransport_session *
session_alloc(struct webtransport_context *ctx, u64 session_id, gfp_t gfp)
{
	struct webtransport_session *session;

	session = kmem_cache_zalloc(wt_session_cache, gfp);
	if (!session)
		return NULL;

	session->session_id = session_id;
	session->state = WT_SESSION_CONNECTING;
	session->h3conn = ctx->h3conn;
	session->ctx = ctx;
	session->streams = RB_ROOT;
	INIT_LIST_HEAD(&session->list);
	spin_lock_init(&session->lock);
	refcount_set(&session->refcnt, 1);

	/* Initialize flow control */
	wt_flow_control_init(&session->flow);

	/* Initialize datagram queue */
	wt_datagram_queue_init(&session->dgram_recv_queue, 256, 1024 * 1024);
	session->dgram_context_id = session_id / 4;

	/* Initialize capsule parsing state */
	session->capsule_buf = NULL;
	session->capsule_buf_len = 0;
	session->capsule_buf_used = 0;
	session->capsule_header_complete = false;

	/* Default stream limits */
	session->max_streams_bidi = 100;
	session->max_streams_uni = 100;

	return session;
}

void webtransport_session_put(struct webtransport_session *session)
{
	if (!session)
		return;

	if (refcount_dec_and_test(&session->refcnt)) {
		/* Clean up datagram queue */
		wt_datagram_queue_destroy(&session->dgram_recv_queue);

		/* Free capsule buffer */
		kfree(session->capsule_buf);

		/* Free session data */
		kfree(session->url);
		kfree(session->close_msg);
		kmem_cache_free(wt_session_cache, session);
	}
}
EXPORT_SYMBOL_GPL(webtransport_session_put);

struct webtransport_session *webtransport_session_find(
	struct webtransport_context *ctx, u64 session_id)
{
	struct webtransport_session *session;
	unsigned long flags;

	spin_lock_irqsave(&ctx->lock, flags);
	session = session_lookup(ctx, session_id);
	if (session)
		webtransport_session_get(session);
	spin_unlock_irqrestore(&ctx->lock, flags);

	return session;
}
EXPORT_SYMBOL_GPL(webtransport_session_find);

/*
 * =============================================================================
 * Extended CONNECT Handling
 * =============================================================================
 */

/**
 * build_connect_headers - Build CONNECT request headers
 * @url: Target URL
 * @url_len: URL length
 * @headers: Output header list
 *
 * Returns: 0 on success, negative error on failure
 */
static int build_connect_headers(const char *url, size_t url_len,
				 struct qpack_header_list *headers)
{
	int ret;

	qpack_header_list_init(headers);

	/* :method = CONNECT */
	ret = qpack_header_list_add(headers, ":method", 7, "CONNECT", 7, false);
	if (ret)
		goto error;

	/* :protocol = webtransport */
	ret = qpack_header_list_add(headers, ":protocol", 9,
				    WEBTRANSPORT_PROTOCOL,
				    strlen(WEBTRANSPORT_PROTOCOL), false);
	if (ret)
		goto error;

	/* :scheme = https (WebTransport always uses HTTPS) */
	ret = qpack_header_list_add(headers, ":scheme", 7, "https", 5, false);
	if (ret)
		goto error;

	/* :path - extract from URL */
	/* For simplicity, use full URL as path */
	ret = qpack_header_list_add(headers, ":path", 5, url, url_len, false);
	if (ret)
		goto error;

	return 0;

error:
	qpack_header_list_destroy(headers);
	return ret;
}

struct webtransport_session *webtransport_connect(
	struct webtransport_context *ctx,
	const char *url, size_t url_len)
{
	struct webtransport_session *session;
	struct qpack_header_list headers;
	struct tquic_stream *stream;
	unsigned long flags;
	int ret;

	if (!ctx || !url || url_len == 0)
		return ERR_PTR(-EINVAL);

	if (!ctx->enabled)
		return ERR_PTR(-ENOTSUP);

	if (ctx->session_count >= WEBTRANSPORT_MAX_SESSIONS)
		return ERR_PTR(-ENOSPC);

	/* Open bidirectional stream for CONNECT */
	stream = tquic_stream_open(ctx->h3conn->qconn, true);
	if (IS_ERR(stream))
		return ERR_CAST(stream);

	/* Build CONNECT request headers */
	ret = build_connect_headers(url, url_len, &headers);
	if (ret) {
		tquic_stream_close(stream);
		return ERR_PTR(ret);
	}

	/* Create session */
	session = session_alloc(ctx, stream->stream_id, GFP_KERNEL);
	if (!session) {
		qpack_header_list_destroy(&headers);
		tquic_stream_close(stream);
		return ERR_PTR(-ENOMEM);
	}

	session->session_stream = stream;
	session->url = kmemdup(url, url_len, GFP_KERNEL);
	session->url_len = url_len;
	session->datagrams_enabled = true;  /* Request datagrams */

	/* Add to context */
	spin_lock_irqsave(&ctx->lock, flags);
	ret = session_insert(ctx, session);
	spin_unlock_irqrestore(&ctx->lock, flags);

	if (ret) {
		qpack_header_list_destroy(&headers);
		webtransport_session_put(session);
		return ERR_PTR(ret);
	}

	/* Send CONNECT request would happen here via QPACK encoding */
	/* For now, transition to connecting state */

	qpack_header_list_destroy(&headers);

	pr_debug("webtransport: session %llu connecting to %.*s\n",
		 session->session_id, (int)url_len, url);

	return session;
}
EXPORT_SYMBOL_GPL(webtransport_connect);

struct webtransport_session *webtransport_accept(
	struct webtransport_context *ctx,
	u64 stream_id,
	const struct qpack_header_list *headers)
{
	struct webtransport_session *session;
	unsigned long flags;
	int ret;

	if (!ctx || !headers)
		return ERR_PTR(-EINVAL);

	if (!ctx->enabled)
		return ERR_PTR(-ENOTSUP);

	/* Create session */
	session = session_alloc(ctx, stream_id, GFP_KERNEL);
	if (!session)
		return ERR_PTR(-ENOMEM);

	session->state = WT_SESSION_OPEN;
	session->datagrams_enabled = true;

	/* Add to context */
	spin_lock_irqsave(&ctx->lock, flags);
	ret = session_insert(ctx, session);
	spin_unlock_irqrestore(&ctx->lock, flags);

	if (ret) {
		webtransport_session_put(session);
		return ERR_PTR(ret);
	}

	pr_debug("webtransport: accepted session %llu\n", stream_id);

	return session;
}
EXPORT_SYMBOL_GPL(webtransport_accept);

/*
 * =============================================================================
 * Session Close
 * =============================================================================
 */

/**
 * encode_close_capsule - Encode CLOSE_WEBTRANSPORT_SESSION capsule
 * @buf: Output buffer
 * @len: Buffer length
 * @code: Application error code
 * @msg: Close message (may be NULL)
 * @msg_len: Message length
 *
 * Returns: Number of bytes written, or negative error
 */
static int encode_close_capsule(u8 *buf, size_t len,
				u32 code, const char *msg, size_t msg_len)
{
	size_t offset = 0;
	size_t payload_len;
	int ret;

	/* Capsule Type */
	ret = tquic_varint_encode(WEBTRANSPORT_CAPSULE_CLOSE_SESSION,
				  buf + offset, len - offset);
	if (ret < 0)
		return ret;
	offset += ret;

	/* Calculate payload length: 4 bytes for code + message */
	payload_len = 4 + msg_len;

	/* Capsule Length */
	ret = tquic_varint_encode(payload_len, buf + offset, len - offset);
	if (ret < 0)
		return ret;
	offset += ret;

	/* Application error code (4 bytes, big-endian) */
	if (offset + 4 > len)
		return -ENOSPC;
	buf[offset++] = (code >> 24) & 0xff;
	buf[offset++] = (code >> 16) & 0xff;
	buf[offset++] = (code >> 8) & 0xff;
	buf[offset++] = code & 0xff;

	/* Close message */
	if (msg && msg_len > 0) {
		if (offset + msg_len > len)
			return -ENOSPC;
		memcpy(buf + offset, msg, msg_len);
		offset += msg_len;
	}

	return offset;
}

int webtransport_session_close(struct webtransport_session *session,
			       u32 code, const char *msg, size_t msg_len)
{
	size_t buf_size = 128 + WEBTRANSPORT_MAX_URL_LEN;
	u8 *buf;
	int capsule_len;
	int ret;
	unsigned long flags;

	if (!session)
		return -EINVAL;

	spin_lock_irqsave(&session->lock, flags);

	if (session->state == WT_SESSION_CLOSED ||
	    session->state == WT_SESSION_CLOSING) {
		spin_unlock_irqrestore(&session->lock, flags);
		return 0;
	}

	session->state = WT_SESSION_CLOSING;
	session->close_code = code;
	if (msg && msg_len > 0) {
		session->close_msg = kmemdup(msg, msg_len, GFP_ATOMIC);
		session->close_msg_len = msg_len;
	}

	spin_unlock_irqrestore(&session->lock, flags);

	/*
	 * Heap-allocate the capsule encode buffer to avoid placing
	 * 8320 bytes (128 + WEBTRANSPORT_MAX_URL_LEN) on the kernel stack.
	 */
	buf = kmalloc(buf_size, GFP_KERNEL);
	if (!buf)
		return -ENOMEM;

	/* Encode and send CLOSE capsule */
	capsule_len = encode_close_capsule(buf, buf_size, code, msg, msg_len);
	if (capsule_len < 0) {
		kfree(buf);
		return capsule_len;
	}

	if (session->session_stream) {
		ret = tquic_stream_send(session->session_stream,
					buf, capsule_len, true);
		kfree(buf);
		if (ret < 0)
			return ret;
	} else {
		kfree(buf);
	}

	pr_debug("webtransport: session %llu closing with code %u\n",
		 session->session_id, code);

	return 0;
}
EXPORT_SYMBOL_GPL(webtransport_session_close);

/*
 * =============================================================================
 * Stream Operations
 * =============================================================================
 */

static struct webtransport_stream *
stream_lookup(struct webtransport_session *session, u64 stream_id)
{
	struct rb_node *node = session->streams.rb_node;

	while (node) {
		struct webtransport_stream *s;

		s = rb_entry(node, struct webtransport_stream, tree_node);

		if (stream_id < s->stream_id)
			node = node->rb_left;
		else if (stream_id > s->stream_id)
			node = node->rb_right;
		else
			return s;
	}

	return NULL;
}

static int stream_insert(struct webtransport_session *session,
			 struct webtransport_stream *stream)
{
	struct rb_node **link = &session->streams.rb_node;
	struct rb_node *parent = NULL;

	while (*link) {
		struct webtransport_stream *s;

		parent = *link;
		s = rb_entry(parent, struct webtransport_stream, tree_node);

		if (stream->stream_id < s->stream_id)
			link = &parent->rb_left;
		else if (stream->stream_id > s->stream_id)
			link = &parent->rb_right;
		else
			return -EEXIST;
	}

	rb_link_node(&stream->tree_node, parent, link);
	rb_insert_color(&stream->tree_node, &session->streams);
	session->stream_count++;

	return 0;
}

struct webtransport_stream *webtransport_open_stream(
	struct webtransport_session *session, bool bidirectional)
{
	struct webtransport_stream *wt_stream;
	struct tquic_stream *quic_stream;
	u8 header[16];
	size_t header_len = 0;
	int ret;
	unsigned long flags;

	if (!session)
		return ERR_PTR(-EINVAL);

	if (session->state != WT_SESSION_OPEN)
		return ERR_PTR(-EINVAL);

	/* Open QUIC stream */
	quic_stream = tquic_stream_open(session->h3conn->qconn, bidirectional);
	if (IS_ERR(quic_stream))
		return ERR_CAST(quic_stream);

	/* Allocate WebTransport stream wrapper */
	wt_stream = kmem_cache_zalloc(wt_stream_cache, GFP_KERNEL);
	if (!wt_stream) {
		tquic_stream_close(quic_stream);
		return ERR_PTR(-ENOMEM);
	}

	wt_stream->stream_id = quic_stream->stream_id;
	wt_stream->session = session;
	wt_stream->quic_stream = quic_stream;
	wt_stream->is_bidirectional = bidirectional;
	wt_stream->is_incoming = false;

	/* Build stream header: stream type + session ID */
	header[header_len++] = bidirectional ? WEBTRANSPORT_STREAM_BIDI :
					       WEBTRANSPORT_STREAM_UNI;
	ret = tquic_varint_encode(session->session_id,
				  header + header_len, sizeof(header) - header_len);
	if (ret < 0) {
		kmem_cache_free(wt_stream_cache, wt_stream);
		tquic_stream_close(quic_stream);
		return ERR_PTR(ret);
	}
	header_len += ret;

	/* Send stream header */
	ret = tquic_stream_send(quic_stream, header, header_len, false);
	if (ret < 0) {
		kmem_cache_free(wt_stream_cache, wt_stream);
		tquic_stream_close(quic_stream);
		return ERR_PTR(ret);
	}

	/* Add to session */
	spin_lock_irqsave(&session->lock, flags);
	ret = stream_insert(session, wt_stream);
	spin_unlock_irqrestore(&session->lock, flags);

	if (ret) {
		kmem_cache_free(wt_stream_cache, wt_stream);
		tquic_stream_close(quic_stream);
		return ERR_PTR(ret);
	}

	webtransport_session_get(session);

	pr_debug("webtransport: opened %s stream %llu in session %llu\n",
		 bidirectional ? "bidi" : "uni",
		 wt_stream->stream_id, session->session_id);

	return wt_stream;
}
EXPORT_SYMBOL_GPL(webtransport_open_stream);

ssize_t webtransport_stream_send(struct webtransport_stream *stream,
				 const void *data, size_t len, bool fin)
{
	if (!stream || !stream->quic_stream)
		return -EINVAL;

	return tquic_stream_send(stream->quic_stream, data, len, fin);
}
EXPORT_SYMBOL_GPL(webtransport_stream_send);

ssize_t webtransport_stream_recv(struct webtransport_stream *stream,
				 void *buf, size_t len, bool *fin)
{
	if (!stream || !stream->quic_stream)
		return -EINVAL;

	return tquic_stream_recv(stream->quic_stream, buf, len, fin);
}
EXPORT_SYMBOL_GPL(webtransport_stream_recv);

/*
 * =============================================================================
 * Capsule Protocol Implementation (RFC 9297)
 * =============================================================================
 */

/**
 * wt_capsule_encode - Encode a capsule to buffer
 * @type: Capsule type (varint)
 * @payload: Payload data
 * @payload_len: Payload length
 * @buf: Output buffer
 * @buf_len: Buffer size
 *
 * Capsule format: Type (varint) || Length (varint) || Payload
 *
 * Returns: Number of bytes written, or negative error
 */
int wt_capsule_encode(u64 type, const void *payload, size_t payload_len,
		      u8 *buf, size_t buf_len)
{
	size_t offset = 0;
	int ret;

	if (!buf)
		return -EINVAL;

	/* Encode capsule type */
	ret = tquic_varint_encode(type, buf + offset, buf_len - offset);
	if (ret < 0)
		return ret;
	offset += ret;

	/* Encode payload length */
	ret = tquic_varint_encode(payload_len, buf + offset, buf_len - offset);
	if (ret < 0)
		return ret;
	offset += ret;

	/* Copy payload */
	if (payload && payload_len > 0) {
		if (offset + payload_len > buf_len)
			return -ENOSPC;
		memcpy(buf + offset, payload, payload_len);
		offset += payload_len;
	}

	return offset;
}
EXPORT_SYMBOL_GPL(wt_capsule_encode);

/**
 * wt_capsule_decode - Decode a capsule from buffer
 * @buf: Input buffer
 * @buf_len: Buffer length
 * @capsule: Output capsule structure
 * @consumed: Bytes consumed from buffer
 *
 * Returns: 0 on success, -EAGAIN if need more data, negative error otherwise
 */
int wt_capsule_decode(const u8 *buf, size_t buf_len,
		      struct wt_capsule *capsule, size_t *consumed)
{
	size_t offset = 0;
	u64 type, length;
	size_t varint_len;
	int ret;

	if (!buf || !capsule || !consumed)
		return -EINVAL;

	if (buf_len < 2)
		return -EAGAIN;

	/* Decode capsule type */
	ret = tquic_varint_decode(buf + offset, buf_len - offset, &type);
	if (ret < 0)
		return ret == -ENODATA ? -EAGAIN : ret;
	varint_len = ret;
	offset += varint_len;

	if (offset >= buf_len)
		return -EAGAIN;

	/* Decode payload length */
	ret = tquic_varint_decode(buf + offset, buf_len - offset, &length);
	if (ret < 0)
		return ret == -ENODATA ? -EAGAIN : ret;
	varint_len = ret;
	offset += varint_len;

	/* Check if we have the full payload */
	if (offset + length > buf_len)
		return -EAGAIN;

	capsule->type = type;
	capsule->length = length;
	capsule->payload = buf + offset;

	*consumed = offset + length;

	return 0;
}
EXPORT_SYMBOL_GPL(wt_capsule_decode);

/**
 * wt_capsule_header_size - Calculate capsule header size
 * @type: Capsule type
 * @payload_len: Payload length
 *
 * Returns: Header size in bytes (type + length varints)
 */
size_t wt_capsule_header_size(u64 type, size_t payload_len)
{
	return tquic_varint_size(type) + tquic_varint_size(payload_len);
}
EXPORT_SYMBOL_GPL(wt_capsule_header_size);

/*
 * =============================================================================
 * Datagram Queue Operations
 * =============================================================================
 */

/**
 * wt_datagram_queue_init - Initialize datagram receive queue
 */
void wt_datagram_queue_init(struct webtransport_datagram_queue *queue,
			    u32 max_count, u64 max_bytes)
{
	if (!queue)
		return;

	INIT_LIST_HEAD(&queue->datagrams);
	queue->count = 0;
	queue->max_count = max_count;
	queue->total_bytes = 0;
	queue->max_bytes = max_bytes;
	spin_lock_init(&queue->lock);
}
EXPORT_SYMBOL_GPL(wt_datagram_queue_init);

/**
 * wt_datagram_queue_destroy - Free all datagrams and cleanup queue
 */
void wt_datagram_queue_destroy(struct webtransport_datagram_queue *queue)
{
	struct webtransport_datagram *dgram, *tmp;
	unsigned long flags;

	if (!queue)
		return;

	spin_lock_irqsave(&queue->lock, flags);
	list_for_each_entry_safe(dgram, tmp, &queue->datagrams, list) {
		list_del(&dgram->list);
		kfree(dgram->data);
		kfree(dgram);
	}
	queue->count = 0;
	queue->total_bytes = 0;
	spin_unlock_irqrestore(&queue->lock, flags);
}
EXPORT_SYMBOL_GPL(wt_datagram_queue_destroy);

/**
 * wt_datagram_queue_push - Add datagram to queue
 */
int wt_datagram_queue_push(struct webtransport_datagram_queue *queue,
			   const void *data, size_t len, gfp_t gfp)
{
	struct webtransport_datagram *dgram;
	unsigned long flags;
	int ret = 0;

	if (!queue || !data || len == 0)
		return -EINVAL;

	spin_lock_irqsave(&queue->lock, flags);

	/* Check limits */
	if (queue->count >= queue->max_count ||
	    queue->total_bytes + len > queue->max_bytes) {
		spin_unlock_irqrestore(&queue->lock, flags);
		return -ENOSPC;
	}

	spin_unlock_irqrestore(&queue->lock, flags);

	/* Allocate datagram structure */
	dgram = kmalloc(sizeof(*dgram), gfp);
	if (!dgram)
		return -ENOMEM;

	dgram->data = kmalloc(len, gfp);
	if (!dgram->data) {
		kfree(dgram);
		return -ENOMEM;
	}

	memcpy(dgram->data, data, len);
	dgram->len = len;
	INIT_LIST_HEAD(&dgram->list);

	spin_lock_irqsave(&queue->lock, flags);

	/* Re-check limits under lock */
	if (queue->count >= queue->max_count ||
	    queue->total_bytes + len > queue->max_bytes) {
		ret = -ENOSPC;
	} else {
		list_add_tail(&dgram->list, &queue->datagrams);
		queue->count++;
		queue->total_bytes += len;
	}

	spin_unlock_irqrestore(&queue->lock, flags);

	if (ret) {
		kfree(dgram->data);
		kfree(dgram);
	}

	return ret;
}
EXPORT_SYMBOL_GPL(wt_datagram_queue_push);

/**
 * wt_datagram_queue_pop - Remove and return next datagram from queue
 */
ssize_t wt_datagram_queue_pop(struct webtransport_datagram_queue *queue,
			      void *buf, size_t buf_len)
{
	struct webtransport_datagram *dgram;
	unsigned long flags;
	size_t copy_len;

	if (!queue || !buf)
		return -EINVAL;

	spin_lock_irqsave(&queue->lock, flags);

	if (list_empty(&queue->datagrams)) {
		spin_unlock_irqrestore(&queue->lock, flags);
		return -EAGAIN;
	}

	dgram = list_first_entry(&queue->datagrams,
				 struct webtransport_datagram, list);
	list_del(&dgram->list);
	queue->count--;
	queue->total_bytes -= dgram->len;

	spin_unlock_irqrestore(&queue->lock, flags);

	/* Copy data to user buffer */
	copy_len = min(buf_len, dgram->len);
	memcpy(buf, dgram->data, copy_len);

	kfree(dgram->data);
	kfree(dgram);

	return copy_len;
}
EXPORT_SYMBOL_GPL(wt_datagram_queue_pop);

/*
 * =============================================================================
 * Datagram Support (RFC 9297)
 * =============================================================================
 */

/**
 * webtransport_send_datagram - Send a datagram on a WebTransport session
 *
 * WebTransport datagrams are sent via HTTP/3 DATAGRAM frames (RFC 9297).
 * The datagram format is:
 *   Quarter Stream ID (varint) || Datagram Payload
 *
 * The Quarter Stream ID is session_id / 4, encoding the session this
 * datagram belongs to.
 */
int webtransport_send_datagram(struct webtransport_session *session,
			       const void *data, size_t len)
{
	struct tquic_connection *qconn;
	u8 *dgram_buf;
	size_t dgram_len;
	size_t header_len;
	u64 quarter_id;
	u64 max_dgram_size;
	int ret;

	if (!session || !data)
		return -EINVAL;

	if (!session->datagrams_enabled)
		return -EOPNOTSUPP;

	if (session->state != WT_SESSION_OPEN)
		return -EINVAL;

	if (!session->h3conn || !session->h3conn->qconn)
		return -EINVAL;

	qconn = session->h3conn->qconn;

	/* Get maximum datagram size from QUIC layer */
	max_dgram_size = tquic_datagram_max_size(qconn);
	if (max_dgram_size == 0)
		return -EOPNOTSUPP;

	/* Calculate quarter stream ID (session_id / 4) per RFC 9297 */
	quarter_id = session->session_id / 4;

	/* Calculate header size (varint for quarter ID) */
	header_len = tquic_varint_size(quarter_id);
	if (header_len == 0)
		return -EINVAL;

	/* Check if datagram fits */
	dgram_len = header_len + len;
	if (dgram_len > max_dgram_size)
		return -EMSGSIZE;

	/* Allocate buffer for datagram with header */
	dgram_buf = kmalloc(dgram_len, GFP_KERNEL);
	if (!dgram_buf)
		return -ENOMEM;

	/* Encode quarter stream ID header */
	ret = tquic_varint_encode(quarter_id, dgram_buf, header_len);
	if (ret < 0) {
		kfree(dgram_buf);
		return ret;
	}

	/* Copy datagram payload */
	memcpy(dgram_buf + header_len, data, len);

	/* Send via QUIC DATAGRAM frame */
	ret = tquic_send_datagram(qconn, dgram_buf, dgram_len);

	kfree(dgram_buf);

	if (ret == 0) {
		pr_debug("webtransport: sent datagram (%zu bytes) on session %llu\n",
			 len, session->session_id);
	}

	return ret;
}
EXPORT_SYMBOL_GPL(webtransport_send_datagram);

/**
 * webtransport_recv_datagram - Receive a datagram from a WebTransport session
 *
 * Returns the next datagram from the session's receive queue.
 */
ssize_t webtransport_recv_datagram(struct webtransport_session *session,
				   void *buf, size_t len)
{
	if (!session || !buf)
		return -EINVAL;

	if (!session->datagrams_enabled)
		return -EOPNOTSUPP;

	if (session->state != WT_SESSION_OPEN)
		return -EINVAL;

	return wt_datagram_queue_pop(&session->dgram_recv_queue, buf, len);
}
EXPORT_SYMBOL_GPL(webtransport_recv_datagram);

/**
 * wt_handle_incoming_datagram - Handle incoming QUIC datagram for WebTransport
 *
 * Called when a QUIC DATAGRAM frame is received. Demultiplexes the datagram
 * to the appropriate WebTransport session based on Quarter Stream ID.
 */
int wt_handle_incoming_datagram(struct webtransport_context *ctx,
				const u8 *data, size_t len)
{
	struct webtransport_session *session;
	u64 quarter_id;
	u64 session_id;
	size_t consumed;
	int ret;

	if (!ctx || !data || len < 1)
		return -EINVAL;

	/* Decode quarter stream ID */
	ret = tquic_varint_decode(data, len, &quarter_id);
	if (ret < 0)
		return ret;
	consumed = ret;

	/* Convert to session ID (quarter_id * 4) */
	session_id = quarter_id * 4;

	/* Find session */
	session = webtransport_session_find(ctx, session_id);
	if (!session) {
		pr_debug("webtransport: datagram for unknown session %llu\n",
			 session_id);
		return -ENOENT;
	}

	if (!session->datagrams_enabled) {
		webtransport_session_put(session);
		return -EOPNOTSUPP;
	}

	/* Queue the datagram (payload only, without header) */
	ret = wt_datagram_queue_push(&session->dgram_recv_queue,
				     data + consumed, len - consumed,
				     GFP_ATOMIC);

	webtransport_session_put(session);

	if (ret == 0) {
		pr_debug("webtransport: received datagram (%zu bytes) for session %llu\n",
			 len - consumed, session_id);
	}

	return ret;
}

/*
 * =============================================================================
 * Settings and Stream Handling
 * =============================================================================
 */

int webtransport_handle_settings(struct webtransport_context *ctx,
				 bool enabled)
{
	if (!ctx)
		return -EINVAL;

	ctx->enabled = enabled;

	pr_debug("webtransport: %s\n", enabled ? "enabled" : "disabled");

	return 0;
}
EXPORT_SYMBOL_GPL(webtransport_handle_settings);

int webtransport_handle_stream(struct webtransport_context *ctx,
			       u64 stream_id, const u8 *data, size_t len)
{
	struct webtransport_session *session;
	struct webtransport_stream *wt_stream;
	u8 stream_type;
	u64 session_id;
	int ret;
	unsigned long flags;

	if (!ctx || !data || len < 2)
		return -EINVAL;

	/* Parse stream type */
	stream_type = data[0];
	if (stream_type != WEBTRANSPORT_STREAM_UNI &&
	    stream_type != WEBTRANSPORT_STREAM_BIDI)
		return -EINVAL;

	/* Parse session ID */
	ret = tquic_varint_decode(data + 1, len - 1, &session_id);
	if (ret < 0)
		return ret;

	/* Find session */
	session = webtransport_session_find(ctx, session_id);
	if (!session)
		return -ENOENT;

	/* Create stream wrapper */
	wt_stream = kmem_cache_zalloc(wt_stream_cache, GFP_ATOMIC);
	if (!wt_stream) {
		webtransport_session_put(session);
		return -ENOMEM;
	}

	wt_stream->stream_id = stream_id;
	wt_stream->session = session;
	wt_stream->is_bidirectional = (stream_type == WEBTRANSPORT_STREAM_BIDI);
	wt_stream->is_incoming = true;

	/* Add to session */
	spin_lock_irqsave(&session->lock, flags);
	ret = stream_insert(session, wt_stream);
	spin_unlock_irqrestore(&session->lock, flags);

	if (ret) {
		kmem_cache_free(wt_stream_cache, wt_stream);
		webtransport_session_put(session);
		return ret;
	}

	pr_debug("webtransport: accepted %s stream %llu for session %llu\n",
		 wt_stream->is_bidirectional ? "bidi" : "uni",
		 stream_id, session_id);

	return 0;
}
EXPORT_SYMBOL_GPL(webtransport_handle_stream);

/*
 * =============================================================================
 * Flow Control Capsule Implementation
 * =============================================================================
 */

/**
 * wt_encode_flow_control_capsule - Encode a flow control capsule
 * @type: Capsule type
 * @value: The limit value
 * @buf: Output buffer
 * @buf_len: Buffer size
 *
 * Flow control capsules contain a single varint value.
 *
 * Returns: Number of bytes written, or negative error
 */
static int wt_encode_flow_control_capsule(u64 type, u64 value,
					  u8 *buf, size_t buf_len)
{
	u8 payload[8];
	int payload_len;

	payload_len = tquic_varint_encode(value, payload, sizeof(payload));
	if (payload_len < 0)
		return payload_len;

	return wt_capsule_encode(type, payload, payload_len, buf, buf_len);
}

/**
 * wt_send_flow_control_capsule - Send a flow control capsule on session stream
 */
static int wt_send_flow_control_capsule(struct webtransport_session *session,
					u64 type, u64 value)
{
	u8 buf[32];
	int len;

	if (!session || !session->session_stream)
		return -EINVAL;

	len = wt_encode_flow_control_capsule(type, value, buf, sizeof(buf));
	if (len < 0)
		return len;

	return tquic_stream_send(session->session_stream, buf, len, false);
}

/**
 * wt_send_max_data - Send WT_MAX_DATA capsule
 */
int wt_send_max_data(struct webtransport_session *session, u64 max_data)
{
	unsigned long flags;
	int ret;

	if (!session)
		return -EINVAL;

	spin_lock_irqsave(&session->lock, flags);
	session->flow.max_data_local = max_data;
	spin_unlock_irqrestore(&session->lock, flags);

	ret = wt_send_flow_control_capsule(session, WT_CAPSULE_MAX_DATA,
					   max_data);

	pr_debug("webtransport: session %llu sent MAX_DATA %llu\n",
		 session->session_id, max_data);

	return ret;
}
EXPORT_SYMBOL_GPL(wt_send_max_data);

/**
 * wt_send_max_streams - Send WT_MAX_STREAMS_BIDI or WT_MAX_STREAMS_UNIDI
 */
int wt_send_max_streams(struct webtransport_session *session,
			u64 max_streams, bool bidirectional)
{
	unsigned long flags;
	u64 type;
	int ret;

	if (!session)
		return -EINVAL;

	type = bidirectional ? WT_CAPSULE_MAX_STREAMS_BIDI :
			       WT_CAPSULE_MAX_STREAMS_UNIDI;

	spin_lock_irqsave(&session->lock, flags);
	if (bidirectional)
		session->flow.max_streams_bidi_local = max_streams;
	else
		session->flow.max_streams_uni_local = max_streams;
	spin_unlock_irqrestore(&session->lock, flags);

	ret = wt_send_flow_control_capsule(session, type, max_streams);

	pr_debug("webtransport: session %llu sent MAX_STREAMS_%s %llu\n",
		 session->session_id, bidirectional ? "BIDI" : "UNI",
		 max_streams);

	return ret;
}
EXPORT_SYMBOL_GPL(wt_send_max_streams);

/**
 * wt_send_data_blocked - Send WT_DATA_BLOCKED capsule
 */
int wt_send_data_blocked(struct webtransport_session *session, u64 limit)
{
	unsigned long flags;
	int ret;

	if (!session)
		return -EINVAL;

	spin_lock_irqsave(&session->lock, flags);
	session->flow.blocked_on_data = true;
	spin_unlock_irqrestore(&session->lock, flags);

	ret = wt_send_flow_control_capsule(session, WT_CAPSULE_DATA_BLOCKED,
					   limit);

	pr_debug("webtransport: session %llu sent DATA_BLOCKED at %llu\n",
		 session->session_id, limit);

	return ret;
}
EXPORT_SYMBOL_GPL(wt_send_data_blocked);

/**
 * wt_send_streams_blocked - Send WT_STREAMS_BLOCKED capsule
 */
int wt_send_streams_blocked(struct webtransport_session *session,
			    u64 limit, bool bidirectional)
{
	unsigned long flags;
	u64 type;
	int ret;

	if (!session)
		return -EINVAL;

	type = bidirectional ? WT_CAPSULE_STREAMS_BLOCKED_BIDI :
			       WT_CAPSULE_STREAMS_BLOCKED_UNIDI;

	spin_lock_irqsave(&session->lock, flags);
	if (bidirectional)
		session->flow.blocked_on_bidi = true;
	else
		session->flow.blocked_on_uni = true;
	spin_unlock_irqrestore(&session->lock, flags);

	ret = wt_send_flow_control_capsule(session, type, limit);

	pr_debug("webtransport: session %llu sent STREAMS_BLOCKED_%s at %llu\n",
		 session->session_id, bidirectional ? "BIDI" : "UNI", limit);

	return ret;
}
EXPORT_SYMBOL_GPL(wt_send_streams_blocked);

/**
 * wt_send_stream_data_blocked - Send WT_STREAM_DATA_BLOCKED capsule
 */
int wt_send_stream_data_blocked(struct webtransport_stream *stream, u64 limit)
{
	u8 buf[32];
	u8 payload[16];
	size_t payload_len = 0;
	int ret;

	if (!stream || !stream->session || !stream->session->session_stream)
		return -EINVAL;

	/* Encode: Stream ID (varint) || Limit (varint) */
	ret = tquic_varint_encode(stream->stream_id, payload, sizeof(payload));
	if (ret < 0)
		return ret;
	payload_len = ret;

	ret = tquic_varint_encode(limit, payload + payload_len,
				  sizeof(payload) - payload_len);
	if (ret < 0)
		return ret;
	payload_len += ret;

	ret = wt_capsule_encode(WT_CAPSULE_STREAM_DATA_BLOCKED, payload,
				payload_len, buf, sizeof(buf));
	if (ret < 0)
		return ret;

	pr_debug("webtransport: stream %llu sent STREAM_DATA_BLOCKED at %llu\n",
		 stream->stream_id, limit);

	return tquic_stream_send(stream->session->session_stream, buf, ret,
				 false);
}
EXPORT_SYMBOL_GPL(wt_send_stream_data_blocked);

/**
 * wt_send_reset_stream - Send WT_RESET_STREAM capsule
 */
int wt_send_reset_stream(struct webtransport_stream *stream, u64 error_code)
{
	u8 buf[32];
	u8 payload[16];
	size_t payload_len = 0;
	int ret;

	if (!stream || !stream->session || !stream->session->session_stream)
		return -EINVAL;

	/* Encode: Stream ID (varint) || Error Code (varint) */
	ret = tquic_varint_encode(stream->stream_id, payload, sizeof(payload));
	if (ret < 0)
		return ret;
	payload_len = ret;

	ret = tquic_varint_encode(error_code, payload + payload_len,
				  sizeof(payload) - payload_len);
	if (ret < 0)
		return ret;
	payload_len += ret;

	ret = wt_capsule_encode(WT_CAPSULE_RESET_STREAM, payload, payload_len,
				buf, sizeof(buf));
	if (ret < 0)
		return ret;

	pr_debug("webtransport: stream %llu sent RESET_STREAM with code %llu\n",
		 stream->stream_id, error_code);

	return tquic_stream_send(stream->session->session_stream, buf, ret,
				 false);
}
EXPORT_SYMBOL_GPL(wt_send_reset_stream);

/**
 * wt_send_stop_sending - Send WT_STOP_SENDING capsule
 */
int wt_send_stop_sending(struct webtransport_stream *stream, u64 error_code)
{
	u8 buf[32];
	u8 payload[16];
	size_t payload_len = 0;
	int ret;

	if (!stream || !stream->session || !stream->session->session_stream)
		return -EINVAL;

	/* Encode: Stream ID (varint) || Error Code (varint) */
	ret = tquic_varint_encode(stream->stream_id, payload, sizeof(payload));
	if (ret < 0)
		return ret;
	payload_len = ret;

	ret = tquic_varint_encode(error_code, payload + payload_len,
				  sizeof(payload) - payload_len);
	if (ret < 0)
		return ret;
	payload_len += ret;

	ret = wt_capsule_encode(WT_CAPSULE_STOP_SENDING, payload, payload_len,
				buf, sizeof(buf));
	if (ret < 0)
		return ret;

	pr_debug("webtransport: stream %llu sent STOP_SENDING with code %llu\n",
		 stream->stream_id, error_code);

	return tquic_stream_send(stream->session->session_stream, buf, ret,
				 false);
}
EXPORT_SYMBOL_GPL(wt_send_stop_sending);

/*
 * =============================================================================
 * WebTransport Session Capsules
 * =============================================================================
 */

/**
 * wt_send_close_session_capsule - Send CLOSE_WEBTRANSPORT_SESSION capsule
 */
int wt_send_close_session_capsule(struct webtransport_session *session,
				  u32 error_code, const char *reason,
				  size_t reason_len)
{
	u8 *buf;
	u8 *payload;
	size_t payload_len;
	size_t buf_len;
	int ret;

	if (!session || !session->session_stream)
		return -EINVAL;

	/* Payload: Error Code (4 bytes BE) || Reason (variable) */
	payload_len = 4 + reason_len;
	buf_len = wt_capsule_header_size(WEBTRANSPORT_CAPSULE_CLOSE_SESSION,
					 payload_len) + payload_len;

	buf = kmalloc(buf_len, GFP_KERNEL);
	if (!buf)
		return -ENOMEM;

	payload = kmalloc(payload_len, GFP_KERNEL);
	if (!payload) {
		kfree(buf);
		return -ENOMEM;
	}

	/* Encode error code as 32-bit big-endian */
	payload[0] = (error_code >> 24) & 0xff;
	payload[1] = (error_code >> 16) & 0xff;
	payload[2] = (error_code >> 8) & 0xff;
	payload[3] = error_code & 0xff;

	/* Copy reason if present */
	if (reason && reason_len > 0)
		memcpy(payload + 4, reason, reason_len);

	ret = wt_capsule_encode(WEBTRANSPORT_CAPSULE_CLOSE_SESSION,
				payload, payload_len, buf, buf_len);
	kfree(payload);

	if (ret < 0) {
		kfree(buf);
		return ret;
	}

	/* Send with FIN to close the session stream */
	ret = tquic_stream_send(session->session_stream, buf, ret, true);
	kfree(buf);

	pr_debug("webtransport: session %llu sent CLOSE_SESSION code=%u\n",
		 session->session_id, error_code);

	return ret;
}
EXPORT_SYMBOL_GPL(wt_send_close_session_capsule);

/**
 * wt_send_drain_session_capsule - Send DRAIN_WEBTRANSPORT_SESSION capsule
 */
int wt_send_drain_session_capsule(struct webtransport_session *session)
{
	u8 buf[16];
	int len;

	if (!session || !session->session_stream)
		return -EINVAL;

	/* DRAIN has empty payload */
	len = wt_capsule_encode(WEBTRANSPORT_CAPSULE_DRAIN_SESSION,
				NULL, 0, buf, sizeof(buf));
	if (len < 0)
		return len;

	pr_debug("webtransport: session %llu sent DRAIN_SESSION\n",
		 session->session_id);

	return tquic_stream_send(session->session_stream, buf, len, false);
}
EXPORT_SYMBOL_GPL(wt_send_drain_session_capsule);

/*
 * =============================================================================
 * Capsule Handling
 * =============================================================================
 */

/**
 * wt_handle_close_session - Handle CLOSE_WEBTRANSPORT_SESSION capsule
 */
static int wt_handle_close_session(struct webtransport_session *session,
				   const u8 *payload, size_t len)
{
	u32 error_code;
	unsigned long flags;

	if (len < 4)
		return -EINVAL;

	/* Decode error code (32-bit big-endian) */
	error_code = ((u32)payload[0] << 24) | ((u32)payload[1] << 16) |
		     ((u32)payload[2] << 8) | payload[3];

	spin_lock_irqsave(&session->lock, flags);
	session->state = WT_SESSION_CLOSED;
	session->close_code = error_code;

	/* Store close reason if present */
	if (len > 4) {
		session->close_msg = kmemdup(payload + 4, len - 4, GFP_ATOMIC);
		session->close_msg_len = len - 4;
	}
	spin_unlock_irqrestore(&session->lock, flags);

	pr_debug("webtransport: session %llu received CLOSE_SESSION code=%u\n",
		 session->session_id, error_code);

	return 0;
}

/**
 * wt_handle_drain_session - Handle DRAIN_WEBTRANSPORT_SESSION capsule
 */
static int wt_handle_drain_session(struct webtransport_session *session)
{
	unsigned long flags;

	spin_lock_irqsave(&session->lock, flags);
	if (session->state == WT_SESSION_OPEN)
		session->state = WT_SESSION_DRAINING;
	spin_unlock_irqrestore(&session->lock, flags);

	pr_debug("webtransport: session %llu received DRAIN_SESSION\n",
		 session->session_id);

	return 0;
}

/**
 * wt_handle_max_data - Handle WT_MAX_DATA capsule
 */
static int wt_handle_max_data(struct webtransport_session *session,
			      const u8 *payload, size_t len)
{
	u64 max_data;
	unsigned long flags;
	int ret;

	ret = tquic_varint_decode(payload, len, &max_data);
	if (ret < 0)
		return ret;

	spin_lock_irqsave(&session->lock, flags);
	if (max_data > session->flow.max_data_remote) {
		session->flow.max_data_remote = max_data;
		session->flow.blocked_on_data = false;
	}
	spin_unlock_irqrestore(&session->lock, flags);

	pr_debug("webtransport: session %llu received MAX_DATA %llu\n",
		 session->session_id, max_data);

	return 0;
}

/**
 * wt_handle_max_streams - Handle WT_MAX_STREAMS_BIDI/UNIDI capsule
 */
static int wt_handle_max_streams(struct webtransport_session *session,
				 const u8 *payload, size_t len,
				 bool bidirectional)
{
	u64 max_streams;
	unsigned long flags;
	int ret;

	ret = tquic_varint_decode(payload, len, &max_streams);
	if (ret < 0)
		return ret;

	spin_lock_irqsave(&session->lock, flags);
	if (bidirectional) {
		if (max_streams > session->flow.max_streams_bidi_remote) {
			session->flow.max_streams_bidi_remote = max_streams;
			session->flow.blocked_on_bidi = false;
		}
	} else {
		if (max_streams > session->flow.max_streams_uni_remote) {
			session->flow.max_streams_uni_remote = max_streams;
			session->flow.blocked_on_uni = false;
		}
	}
	spin_unlock_irqrestore(&session->lock, flags);

	pr_debug("webtransport: session %llu received MAX_STREAMS_%s %llu\n",
		 session->session_id, bidirectional ? "BIDI" : "UNI",
		 max_streams);

	return 0;
}

/**
 * wt_handle_data_blocked - Handle WT_DATA_BLOCKED capsule
 */
static int wt_handle_data_blocked(struct webtransport_session *session,
				  const u8 *payload, size_t len)
{
	u64 limit;
	int ret;

	ret = tquic_varint_decode(payload, len, &limit);
	if (ret < 0)
		return ret;

	pr_debug("webtransport: session %llu received DATA_BLOCKED at %llu\n",
		 session->session_id, limit);

	/* Optionally send a MAX_DATA update if we can allow more */
	return 0;
}

/**
 * wt_handle_streams_blocked - Handle WT_STREAMS_BLOCKED capsule
 */
static int wt_handle_streams_blocked(struct webtransport_session *session,
				     const u8 *payload, size_t len,
				     bool bidirectional)
{
	u64 limit;
	int ret;

	ret = tquic_varint_decode(payload, len, &limit);
	if (ret < 0)
		return ret;

	pr_debug("webtransport: session %llu received STREAMS_BLOCKED_%s at %llu\n",
		 session->session_id, bidirectional ? "BIDI" : "UNI", limit);

	return 0;
}

/**
 * wt_handle_capsule - Handle received capsule
 */
int wt_handle_capsule(struct webtransport_session *session,
		      const struct wt_capsule *capsule)
{
	if (!session || !capsule)
		return -EINVAL;

	switch (capsule->type) {
	case WEBTRANSPORT_CAPSULE_CLOSE_SESSION:
		return wt_handle_close_session(session, capsule->payload,
					       capsule->length);

	case WEBTRANSPORT_CAPSULE_DRAIN_SESSION:
		return wt_handle_drain_session(session);

	case WT_CAPSULE_MAX_DATA:
		return wt_handle_max_data(session, capsule->payload,
					  capsule->length);

	case WT_CAPSULE_MAX_STREAMS_BIDI:
		return wt_handle_max_streams(session, capsule->payload,
					     capsule->length, true);

	case WT_CAPSULE_MAX_STREAMS_UNIDI:
		return wt_handle_max_streams(session, capsule->payload,
					     capsule->length, false);

	case WT_CAPSULE_DATA_BLOCKED:
		return wt_handle_data_blocked(session, capsule->payload,
					      capsule->length);

	case WT_CAPSULE_STREAMS_BLOCKED_BIDI:
		return wt_handle_streams_blocked(session, capsule->payload,
						 capsule->length, true);

	case WT_CAPSULE_STREAMS_BLOCKED_UNIDI:
		return wt_handle_streams_blocked(session, capsule->payload,
						 capsule->length, false);

	case WT_CAPSULE_DATAGRAM:
		/* Datagrams in capsule form - queue the payload */
		return wt_datagram_queue_push(&session->dgram_recv_queue,
					      capsule->payload,
					      capsule->length, GFP_ATOMIC);

	default:
		/* Unknown capsule types must be ignored per RFC 9297 */
		pr_debug("webtransport: session %llu ignoring unknown capsule type %llu\n",
			 session->session_id, capsule->type);
		return 0;
	}
}
EXPORT_SYMBOL_GPL(wt_handle_capsule);

/*
 * =============================================================================
 * Extended CONNECT Validation (RFC 9220)
 * =============================================================================
 */

/**
 * find_header - Find a header in the header list
 */
static struct qpack_header_field *find_header(const struct qpack_header_list *headers,
					      const char *name, size_t name_len)
{
	struct qpack_header_field *field;

	list_for_each_entry(field, &headers->headers, list) {
		if (field->name_len == name_len &&
		    strncasecmp(field->name, name, name_len) == 0)
			return field;
	}

	return NULL;
}

/**
 * wt_validate_connect_request - Validate Extended CONNECT request
 *
 * Per RFC 9220, a valid WebTransport CONNECT request must have:
 * - :method = CONNECT
 * - :protocol = webtransport
 * - :scheme = https
 * - :authority (host)
 * - :path (resource path)
 *
 * Returns: 0 if valid, negative error code otherwise
 */
int wt_validate_connect_request(const struct qpack_header_list *headers)
{
	struct qpack_header_field *method, *protocol, *scheme;
	struct qpack_header_field *authority, *path;

	if (!headers)
		return -EINVAL;

	/* Check :method = CONNECT */
	method = find_header(headers, ":method", 7);
	if (!method || method->value_len != 7 ||
	    strncmp(method->value, "CONNECT", 7) != 0)
		return -EINVAL;

	/* Check :protocol = webtransport */
	protocol = find_header(headers, ":protocol", 9);
	if (!protocol ||
	    protocol->value_len != sizeof(WEBTRANSPORT_PROTOCOL) - 1 ||
	    strncmp(protocol->value, WEBTRANSPORT_PROTOCOL,
		    protocol->value_len) != 0)
		return -EINVAL;

	/* Check :scheme = https (WebTransport requires HTTPS) */
	scheme = find_header(headers, ":scheme", 7);
	if (!scheme || scheme->value_len != 5 ||
	    strncmp(scheme->value, "https", 5) != 0)
		return -EINVAL;

	/* Check :authority is present */
	authority = find_header(headers, ":authority", 10);
	if (!authority || authority->value_len == 0)
		return -EINVAL;

	/* Check :path is present */
	path = find_header(headers, ":path", 5);
	if (!path || path->value_len == 0)
		return -EINVAL;

	return 0;
}
EXPORT_SYMBOL_GPL(wt_validate_connect_request);

/**
 * wt_validate_connect_response - Validate Extended CONNECT response
 *
 * A valid WebTransport CONNECT response should have :status = 200.
 *
 * Returns: 0 if valid 200 response, negative error code otherwise
 */
int wt_validate_connect_response(const struct qpack_header_list *headers)
{
	struct qpack_header_field *status;

	if (!headers)
		return -EINVAL;

	/* Check :status = 200 */
	status = find_header(headers, ":status", 7);
	if (!status || status->value_len != 3 ||
	    strncmp(status->value, "200", 3) != 0)
		return -EINVAL;

	return 0;
}
EXPORT_SYMBOL_GPL(wt_validate_connect_response);

/*
 * =============================================================================
 * Session Stream Data Handling
 * =============================================================================
 */

/**
 * wt_process_session_stream_data - Process data on session stream
 *
 * Called when data arrives on the session CONNECT stream. Parses capsules
 * and dispatches them to appropriate handlers.
 */
int wt_process_session_stream_data(struct webtransport_session *session,
				   const u8 *data, size_t len)
{
	struct wt_capsule capsule;
	size_t consumed;
	size_t offset = 0;
	int ret;

	if (!session || !data)
		return -EINVAL;

	while (offset < len) {
		ret = wt_capsule_decode(data + offset, len - offset,
					&capsule, &consumed);
		if (ret == -EAGAIN) {
			/* Need more data - buffer the remainder */
			if (len - offset > 0) {
				size_t remain = len - offset;
				size_t new_size;
				u8 *newbuf;

				new_size = session->capsule_buf_used + remain;

				/*
				 * Enforce maximum capsule buffer size to
				 * prevent unbounded memory growth from a
				 * malicious or misbehaving peer.
				 */
				if (new_size > WT_MAX_CAPSULE_BUF_SIZE) {
					pr_warn("webtransport: session %llu capsule buffer limit exceeded (%zu > %u)\n",
						session->session_id,
						new_size,
						WT_MAX_CAPSULE_BUF_SIZE);
					return -ENOBUFS;
				}

				newbuf = krealloc(session->capsule_buf,
						  new_size, GFP_KERNEL);
				if (!newbuf)
					return -ENOMEM;

				memcpy(newbuf + session->capsule_buf_used,
				       data + offset, remain);
				session->capsule_buf = newbuf;
				session->capsule_buf_used += remain;
			}
			return 0;
		}

		if (ret < 0)
			return ret;

		/* Handle the capsule */
		ret = wt_handle_capsule(session, &capsule);
		if (ret < 0)
			return ret;

		offset += consumed;
	}

	return 0;
}
EXPORT_SYMBOL_GPL(wt_process_session_stream_data);

/*
 * =============================================================================
 * Flow Control Initialization
 * =============================================================================
 */

/**
 * wt_flow_control_init - Initialize flow control state for session
 */
void wt_flow_control_init(struct wt_flow_control *flow)
{
	if (!flow)
		return;

	/* Default limits - can be adjusted via capsules */
	flow->max_data_local = 256 * 1024;	/* 256 KB initial */
	flow->max_data_remote = 0;		/* Peer must send MAX_DATA */
	flow->data_sent = 0;
	flow->data_recv = 0;

	flow->max_streams_bidi_local = 100;
	flow->max_streams_bidi_remote = 0;
	flow->max_streams_uni_local = 100;
	flow->max_streams_uni_remote = 0;

	flow->streams_bidi_opened = 0;
	flow->streams_uni_opened = 0;

	flow->blocked_on_data = false;
	flow->blocked_on_bidi = false;
	flow->blocked_on_uni = false;
}
EXPORT_SYMBOL_GPL(wt_flow_control_init);

/**
 * wt_can_send_data - Check if session can send more data
 */
bool wt_can_send_data(struct webtransport_session *session, size_t len)
{
	bool can_send;
	unsigned long flags;

	if (!session)
		return false;

	spin_lock_irqsave(&session->lock, flags);
	can_send = (session->flow.data_sent + len <=
		    session->flow.max_data_remote);
	spin_unlock_irqrestore(&session->lock, flags);

	return can_send;
}
EXPORT_SYMBOL_GPL(wt_can_send_data);

/**
 * wt_can_open_stream - Check if session can open another stream
 */
bool wt_can_open_stream(struct webtransport_session *session, bool bidirectional)
{
	bool can_open;
	unsigned long flags;

	if (!session)
		return false;

	spin_lock_irqsave(&session->lock, flags);
	if (bidirectional) {
		can_open = (session->flow.streams_bidi_opened <
			    session->flow.max_streams_bidi_remote);
	} else {
		can_open = (session->flow.streams_uni_opened <
			    session->flow.max_streams_uni_remote);
	}
	spin_unlock_irqrestore(&session->lock, flags);

	return can_open;
}
EXPORT_SYMBOL_GPL(wt_can_open_stream);

MODULE_DESCRIPTION("TQUIC WebTransport (RFC 9220)");
MODULE_LICENSE("GPL");
MODULE_AUTHOR("Linux Foundation");
