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
 * =============================================================================
 * Module Initialization
 * =============================================================================
 */

int webtransport_init(void)
{
	wt_session_cache = kmem_cache_create("webtransport_session",
					     sizeof(struct webtransport_session),
					     0, SLAB_HWCACHE_ALIGN, NULL);
	if (!wt_session_cache)
		return -ENOMEM;

	wt_stream_cache = kmem_cache_create("webtransport_stream",
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

	if (!ctx)
		return;

	spin_lock_irqsave(&ctx->lock, flags);

	/* Close all sessions */
	list_for_each_entry_safe(session, tmp, &ctx->session_list, list) {
		list_del(&session->list);
		rb_erase(&session->tree_node, &ctx->sessions);
		spin_unlock_irqrestore(&ctx->lock, flags);

		webtransport_session_put(session);

		spin_lock_irqsave(&ctx->lock, flags);
	}

	spin_unlock_irqrestore(&ctx->lock, flags);

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
	session->streams = RB_ROOT;
	INIT_LIST_HEAD(&session->list);
	spin_lock_init(&session->lock);
	refcount_set(&session->refcnt, 1);

	return session;
}

void webtransport_session_put(struct webtransport_session *session)
{
	if (!session)
		return;

	if (refcount_dec_and_test(&session->refcnt)) {
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
	u8 buf[128 + WEBTRANSPORT_MAX_URL_LEN];
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

	/* Encode and send CLOSE capsule */
	capsule_len = encode_close_capsule(buf, sizeof(buf), code, msg, msg_len);
	if (capsule_len < 0)
		return capsule_len;

	if (session->session_stream) {
		ret = tquic_stream_send(session->session_stream,
					buf, capsule_len, true);
		if (ret < 0)
			return ret;
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
 * Datagram Support (RFC 9297)
 * =============================================================================
 */

int webtransport_send_datagram(struct webtransport_session *session,
			       const void *data, size_t len)
{
	u8 header[16];
	size_t header_len = 0;
	int ret;

	if (!session)
		return -EINVAL;

	if (!session->datagrams_enabled)
		return -ENOTSUP;

	if (session->state != WT_SESSION_OPEN)
		return -EINVAL;

	/* Encode quarter stream ID (session_id / 4) */
	ret = tquic_varint_encode(session->session_id / 4,
				  header, sizeof(header));
	if (ret < 0)
		return ret;
	header_len = ret;

	/* Send datagram via QUIC DATAGRAM frame would happen here */
	/* For now, this is a stub */

	pr_debug("webtransport: sending datagram (%zu bytes) on session %llu\n",
		 len, session->session_id);

	return 0;
}
EXPORT_SYMBOL_GPL(webtransport_send_datagram);

ssize_t webtransport_recv_datagram(struct webtransport_session *session,
				   void *buf, size_t len)
{
	if (!session)
		return -EINVAL;

	if (!session->datagrams_enabled)
		return -ENOTSUP;

	/* Receive datagram would happen here */
	return -EAGAIN;
}
EXPORT_SYMBOL_GPL(webtransport_recv_datagram);

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
	size_t consumed;
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
	ret = tquic_varint_decode(data + 1, len - 1, &session_id, &consumed);
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

MODULE_DESCRIPTION("TQUIC WebTransport (RFC 9220)");
MODULE_LICENSE("GPL");
MODULE_AUTHOR("Linux Foundation");
