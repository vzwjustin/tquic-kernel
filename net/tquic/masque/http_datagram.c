// SPDX-License-Identifier: GPL-2.0-only
/*
 * TQUIC MASQUE: HTTP Datagrams Implementation (RFC 9297)
 *
 * Copyright (c) 2026 Linux Foundation
 *
 * This module implements HTTP Datagrams as specified in RFC 9297. HTTP
 * Datagrams provide unreliable message delivery between HTTP endpoints
 * using QUIC DATAGRAM frames (RFC 9221).
 *
 * Implementation details:
 *
 * 1. Flow Management:
 *    Each HTTP request stream can have an associated datagram flow.
 *    Flows are identified by Quarter Stream ID in DATAGRAM frames.
 *
 * 2. Context Dispatching:
 *    Within a flow, datagrams are dispatched based on context ID to
 *    registered handlers (e.g., CONNECT-UDP uses context 0 for UDP).
 *
 * 3. Encoding:
 *    DATAGRAM frame payload: Quarter Stream ID || Context ID || Payload
 *    Both Quarter Stream ID and Context ID use QUIC varint encoding.
 *
 * References:
 *   RFC 9297 - HTTP Datagrams and the Capsule Protocol
 *   RFC 9221 - An Unreliable Datagram Extension to QUIC
 */

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/rbtree.h>
#include <linux/refcount.h>
#include <net/tquic.h>

#include "http_datagram.h"
#include "capsule.h"

/*
 * =============================================================================
 * Module State
 * =============================================================================
 */

/* Slab caches */
static struct kmem_cache *flow_cache;
static struct kmem_cache *context_cache;

/*
 * =============================================================================
 * RB-TREE HELPERS
 * =============================================================================
 */

static struct http_datagram_flow *flow_tree_search(struct rb_root *root,
						   u64 quarter_stream_id)
{
	struct rb_node *node = root->rb_node;

	while (node) {
		struct http_datagram_flow *flow =
			rb_entry(node, struct http_datagram_flow, node);

		if (quarter_stream_id < flow->quarter_stream_id)
			node = node->rb_left;
		else if (quarter_stream_id > flow->quarter_stream_id)
			node = node->rb_right;
		else
			return flow;
	}

	return NULL;
}

static int flow_tree_insert(struct rb_root *root,
			    struct http_datagram_flow *flow)
{
	struct rb_node **new = &root->rb_node;
	struct rb_node *parent = NULL;

	while (*new) {
		struct http_datagram_flow *this =
			rb_entry(*new, struct http_datagram_flow, node);
		parent = *new;

		if (flow->quarter_stream_id < this->quarter_stream_id)
			new = &(*new)->rb_left;
		else if (flow->quarter_stream_id > this->quarter_stream_id)
			new = &(*new)->rb_right;
		else
			return -EEXIST;
	}

	rb_link_node(&flow->node, parent, new);
	rb_insert_color(&flow->node, root);
	return 0;
}

static struct http_datagram_context *context_tree_search(struct rb_root *root,
							 u64 context_id)
{
	struct rb_node *node = root->rb_node;

	while (node) {
		struct http_datagram_context *ctx =
			rb_entry(node, struct http_datagram_context, node);

		if (context_id < ctx->context_id)
			node = node->rb_left;
		else if (context_id > ctx->context_id)
			node = node->rb_right;
		else
			return ctx;
	}

	return NULL;
}

static int context_tree_insert(struct rb_root *root,
			       struct http_datagram_context *ctx)
{
	struct rb_node **new = &root->rb_node;
	struct rb_node *parent = NULL;

	while (*new) {
		struct http_datagram_context *this =
			rb_entry(*new, struct http_datagram_context, node);
		parent = *new;

		if (ctx->context_id < this->context_id)
			new = &(*new)->rb_left;
		else if (ctx->context_id > this->context_id)
			new = &(*new)->rb_right;
		else
			return -EEXIST;
	}

	rb_link_node(&ctx->node, parent, new);
	rb_insert_color(&ctx->node, root);
	return 0;
}

/*
 * =============================================================================
 * MANAGER API
 * =============================================================================
 */

/**
 * http_datagram_manager_init - Initialize datagram manager
 * @mgr: Manager to initialize
 * @conn: QUIC connection
 *
 * Returns: 0 on success, negative errno on failure.
 */
int http_datagram_manager_init(struct http_datagram_manager *mgr,
			       struct tquic_connection *conn)
{
	if (!mgr || !conn)
		return -EINVAL;

	memset(mgr, 0, sizeof(*mgr));
	mgr->conn = conn;
	mgr->flows = RB_ROOT;
	mgr->num_flows = 0;
	mgr->enabled = false;
	mgr->max_datagram_size = 0;
	spin_lock_init(&mgr->lock);

	return 0;
}
EXPORT_SYMBOL_GPL(http_datagram_manager_init);

/**
 * http_datagram_manager_cleanup - Clean up datagram manager
 * @mgr: Manager to clean up
 */
void http_datagram_manager_cleanup(struct http_datagram_manager *mgr)
{
	struct rb_node *node, *next;
	struct http_datagram_flow *flow;

	if (!mgr)
		return;

	spin_lock_bh(&mgr->lock);

	/* Free all flows */
	for (node = rb_first(&mgr->flows); node; node = next) {
		next = rb_next(node);
		flow = rb_entry(node, struct http_datagram_flow, node);
		rb_erase(node, &mgr->flows);

		/* Free contexts */
		{
			struct rb_node *cnode, *cnext;
			struct http_datagram_context *ctx;

			for (cnode = rb_first(&flow->contexts); cnode; cnode = cnext) {
				cnext = rb_next(cnode);
				ctx = rb_entry(cnode, struct http_datagram_context, node);
				rb_erase(cnode, &flow->contexts);
				if (context_cache)
					kmem_cache_free(context_cache, ctx);
				else
					kfree(ctx);
			}
		}

		if (flow_cache)
			kmem_cache_free(flow_cache, flow);
		else
			kfree(flow);
	}

	mgr->num_flows = 0;
	mgr->enabled = false;

	spin_unlock_bh(&mgr->lock);
}
EXPORT_SYMBOL_GPL(http_datagram_manager_cleanup);

/**
 * http_datagram_manager_enable - Enable HTTP datagrams
 * @mgr: Manager
 * @max_size: Maximum datagram size
 *
 * Returns: 0 on success, negative errno on failure.
 */
int http_datagram_manager_enable(struct http_datagram_manager *mgr,
				 size_t max_size)
{
	if (!mgr)
		return -EINVAL;

	spin_lock_bh(&mgr->lock);
	mgr->enabled = true;
	mgr->max_datagram_size = max_size;
	spin_unlock_bh(&mgr->lock);

	pr_debug("http_datagram: enabled with max_size=%zu\n", max_size);
	return 0;
}
EXPORT_SYMBOL_GPL(http_datagram_manager_enable);

/*
 * =============================================================================
 * FLOW API
 * =============================================================================
 */

/**
 * http_datagram_flow_create - Create datagram flow for stream
 * @mgr: Datagram manager
 * @stream: HTTP request stream
 *
 * Returns: Flow on success, ERR_PTR on failure.
 */
struct http_datagram_flow *http_datagram_flow_create(
	struct http_datagram_manager *mgr,
	struct tquic_stream *stream)
{
	struct http_datagram_flow *flow;
	u64 stream_id;
	int ret;

	if (!mgr || !stream)
		return ERR_PTR(-EINVAL);

	stream_id = stream->id;

	/* Verify this is a request stream */
	if (!http_datagram_is_request_stream(stream_id))
		return ERR_PTR(-EINVAL);

	/* Allocate flow */
	if (flow_cache)
		flow = kmem_cache_zalloc(flow_cache, GFP_KERNEL);
	else
		flow = kzalloc(sizeof(*flow), GFP_KERNEL);

	if (!flow)
		return ERR_PTR(-ENOMEM);

	flow->stream_id = stream_id;
	flow->quarter_stream_id = http_datagram_stream_to_flow_id(stream_id);
	flow->contexts = RB_ROOT;
	flow->num_contexts = 0;

	/* Determine if server side based on connection role */
	flow->is_server = (stream_id & 0x01) != 0;

	/* Initialize context ID allocation */
	flow->next_context_id = flow->is_server ? 1 : 0;

	spin_lock_init(&flow->lock);
	refcount_set(&flow->refcnt, 1);
	RB_CLEAR_NODE(&flow->node);

	/* Insert into manager's flow tree */
	spin_lock_bh(&mgr->lock);

	ret = flow_tree_insert(&mgr->flows, flow);
	if (ret < 0) {
		spin_unlock_bh(&mgr->lock);
		if (flow_cache)
			kmem_cache_free(flow_cache, flow);
		else
			kfree(flow);
		return ERR_PTR(ret);
	}

	mgr->num_flows++;

	spin_unlock_bh(&mgr->lock);

	pr_debug("http_datagram: created flow for stream %llu (qsid=%llu)\n",
		 stream_id, flow->quarter_stream_id);

	return flow;
}
EXPORT_SYMBOL_GPL(http_datagram_flow_create);

/**
 * http_datagram_flow_lookup - Find flow by stream ID
 * @mgr: Datagram manager
 * @stream_id: Request stream ID
 *
 * Returns: Flow on success (with ref), NULL if not found.
 */
struct http_datagram_flow *http_datagram_flow_lookup(
	struct http_datagram_manager *mgr,
	u64 stream_id)
{
	struct http_datagram_flow *flow;
	u64 quarter_stream_id;

	if (!mgr)
		return NULL;

	quarter_stream_id = http_datagram_stream_to_flow_id(stream_id);

	spin_lock_bh(&mgr->lock);
	flow = flow_tree_search(&mgr->flows, quarter_stream_id);
	if (flow)
		http_datagram_flow_get(flow);
	spin_unlock_bh(&mgr->lock);

	return flow;
}
EXPORT_SYMBOL_GPL(http_datagram_flow_lookup);

/**
 * http_datagram_flow_lookup_by_quarter_id - Find flow by Quarter Stream ID
 * @mgr: Datagram manager
 * @quarter_stream_id: Quarter Stream ID
 *
 * Returns: Flow on success (with ref), NULL if not found.
 */
struct http_datagram_flow *http_datagram_flow_lookup_by_quarter_id(
	struct http_datagram_manager *mgr,
	u64 quarter_stream_id)
{
	struct http_datagram_flow *flow;

	if (!mgr)
		return NULL;

	spin_lock_bh(&mgr->lock);
	flow = flow_tree_search(&mgr->flows, quarter_stream_id);
	if (flow)
		http_datagram_flow_get(flow);
	spin_unlock_bh(&mgr->lock);

	return flow;
}
EXPORT_SYMBOL_GPL(http_datagram_flow_lookup_by_quarter_id);

/**
 * http_datagram_flow_get - Increment flow reference count
 * @flow: Flow to reference
 */
void http_datagram_flow_get(struct http_datagram_flow *flow)
{
	if (flow)
		refcount_inc(&flow->refcnt);
}
EXPORT_SYMBOL_GPL(http_datagram_flow_get);

/**
 * flow_free - Internal flow destructor
 * @flow: Flow to free
 */
static void flow_free(struct http_datagram_flow *flow)
{
	struct rb_node *node, *next;
	struct http_datagram_context *ctx;

	if (!flow)
		return;

	/* Free all contexts */
	for (node = rb_first(&flow->contexts); node; node = next) {
		next = rb_next(node);
		ctx = rb_entry(node, struct http_datagram_context, node);
		rb_erase(node, &flow->contexts);
		if (context_cache)
			kmem_cache_free(context_cache, ctx);
		else
			kfree(ctx);
	}

	if (flow_cache)
		kmem_cache_free(flow_cache, flow);
	else
		kfree(flow);
}

/**
 * http_datagram_flow_put - Decrement flow reference count
 * @flow: Flow to dereference
 */
void http_datagram_flow_put(struct http_datagram_flow *flow)
{
	if (flow && refcount_dec_and_test(&flow->refcnt))
		flow_free(flow);
}
EXPORT_SYMBOL_GPL(http_datagram_flow_put);

/**
 * http_datagram_flow_destroy - Destroy datagram flow
 * @mgr: Datagram manager
 * @flow: Flow to destroy
 */
void http_datagram_flow_destroy(struct http_datagram_manager *mgr,
				struct http_datagram_flow *flow)
{
	if (!mgr || !flow)
		return;

	spin_lock_bh(&mgr->lock);

	if (!RB_EMPTY_NODE(&flow->node)) {
		rb_erase(&flow->node, &mgr->flows);
		RB_CLEAR_NODE(&flow->node);
		mgr->num_flows--;
	}

	spin_unlock_bh(&mgr->lock);

	http_datagram_flow_put(flow);
}
EXPORT_SYMBOL_GPL(http_datagram_flow_destroy);

/*
 * =============================================================================
 * CONTEXT API
 * =============================================================================
 */

/**
 * http_datagram_register_context - Register context handler
 * @flow: Datagram flow
 * @context_id: Context ID to register
 * @handler: Handler callback
 * @context: Handler context
 *
 * Returns: 0 on success, negative errno on failure.
 */
int http_datagram_register_context(struct http_datagram_flow *flow,
				   u64 context_id,
				   int (*handler)(struct http_datagram_flow *,
						  u64, const u8 *, size_t,
						  void *),
				   void *context)
{
	struct http_datagram_context *ctx;
	int ret;

	if (!flow || !handler)
		return -EINVAL;

	/* Allocate context structure */
	if (context_cache)
		ctx = kmem_cache_zalloc(context_cache, GFP_KERNEL);
	else
		ctx = kzalloc(sizeof(*ctx), GFP_KERNEL);

	if (!ctx)
		return -ENOMEM;

	ctx->context_id = context_id;
	ctx->handler = handler;
	ctx->context = context;
	RB_CLEAR_NODE(&ctx->node);

	spin_lock_bh(&flow->lock);

	ret = context_tree_insert(&flow->contexts, ctx);
	if (ret < 0) {
		spin_unlock_bh(&flow->lock);
		if (context_cache)
			kmem_cache_free(context_cache, ctx);
		else
			kfree(ctx);
		return ret;
	}

	flow->num_contexts++;

	spin_unlock_bh(&flow->lock);

	pr_debug("http_datagram: registered context %llu on flow qsid=%llu\n",
		 context_id, flow->quarter_stream_id);

	return 0;
}
EXPORT_SYMBOL_GPL(http_datagram_register_context);

/**
 * http_datagram_unregister_context - Unregister context handler
 * @flow: Datagram flow
 * @context_id: Context ID to unregister
 */
void http_datagram_unregister_context(struct http_datagram_flow *flow,
				      u64 context_id)
{
	struct http_datagram_context *ctx;

	if (!flow)
		return;

	spin_lock_bh(&flow->lock);

	ctx = context_tree_search(&flow->contexts, context_id);
	if (ctx) {
		rb_erase(&ctx->node, &flow->contexts);
		flow->num_contexts--;
		spin_unlock_bh(&flow->lock);

		if (context_cache)
			kmem_cache_free(context_cache, ctx);
		else
			kfree(ctx);
		return;
	}

	spin_unlock_bh(&flow->lock);
}
EXPORT_SYMBOL_GPL(http_datagram_unregister_context);

/**
 * http_datagram_alloc_context_id - Allocate new context ID
 * @flow: Datagram flow
 * @context_id: Output for allocated context ID
 *
 * Returns: 0 on success, negative errno on failure.
 */
int http_datagram_alloc_context_id(struct http_datagram_flow *flow,
				   u64 *context_id)
{
	u64 id;

	if (!flow || !context_id)
		return -EINVAL;

	spin_lock_bh(&flow->lock);

	id = flow->next_context_id;

	/* Increment by 2 to maintain even/odd allocation */
	if (flow->next_context_id > HTTP_DATAGRAM_CONTEXT_MAX - 2) {
		spin_unlock_bh(&flow->lock);
		return -ENOSPC;
	}

	flow->next_context_id += 2;

	spin_unlock_bh(&flow->lock);

	*context_id = id;
	return 0;
}
EXPORT_SYMBOL_GPL(http_datagram_alloc_context_id);

/*
 * =============================================================================
 * ENCODING/DECODING
 * =============================================================================
 */

/**
 * http_datagram_encode - Encode HTTP datagram for transmission
 * @flow: Datagram flow
 * @context_id: Context ID
 * @payload: Payload data
 * @payload_len: Payload length
 * @buf: Output buffer
 * @buf_len: Buffer size
 *
 * Returns: Total encoded length on success, negative errno on failure.
 */
int http_datagram_encode(struct http_datagram_flow *flow,
			 u64 context_id,
			 const u8 *payload, size_t payload_len,
			 u8 *buf, size_t buf_len)
{
	int written = 0;
	int ret;

	if (!flow || !buf)
		return -EINVAL;

	if (payload_len > 0 && !payload)
		return -EINVAL;

	/* Encode Quarter Stream ID */
	ret = capsule_varint_encode(flow->quarter_stream_id, buf, buf_len);
	if (ret < 0)
		return ret;
	written += ret;

	/* Encode Context ID */
	ret = capsule_varint_encode(context_id, buf + written, buf_len - written);
	if (ret < 0)
		return ret;
	written += ret;

	/* Copy payload */
	if (buf_len - written < payload_len)
		return -ENOSPC;

	if (payload_len > 0)
		memcpy(buf + written, payload, payload_len);

	written += payload_len;
	return written;
}
EXPORT_SYMBOL_GPL(http_datagram_encode);

/**
 * http_datagram_decode - Decode received DATAGRAM
 * @data: Input data
 * @len: Data length
 * @quarter_stream_id: Output for Quarter Stream ID
 * @context_id: Output for context ID
 * @payload: Output for payload pointer
 * @payload_len: Output for payload length
 *
 * Returns: 0 on success, negative errno on failure.
 */
int http_datagram_decode(const u8 *data, size_t len,
			 u64 *quarter_stream_id,
			 u64 *context_id,
			 const u8 **payload, size_t *payload_len)
{
	int consumed = 0;
	int ret;

	if (!data || !quarter_stream_id || !context_id ||
	    !payload || !payload_len)
		return -EINVAL;

	if (len == 0)
		return -EINVAL;

	/* Decode Quarter Stream ID */
	ret = capsule_varint_decode(data, len, quarter_stream_id);
	if (ret < 0)
		return ret;
	consumed += ret;

	/* Decode Context ID */
	if (len - consumed == 0) {
		/* Empty payload with implicit context 0 is valid */
		*context_id = 0;
		*payload = NULL;
		*payload_len = 0;
		return 0;
	}

	ret = capsule_varint_decode(data + consumed, len - consumed, context_id);
	if (ret < 0)
		return ret;
	consumed += ret;

	/* Remaining bytes are payload */
	*payload = data + consumed;
	*payload_len = len - consumed;

	return 0;
}
EXPORT_SYMBOL_GPL(http_datagram_decode);

/*
 * =============================================================================
 * SEND/RECEIVE API
 * =============================================================================
 */

/**
 * http_datagram_send - Send HTTP datagram
 * @flow: Datagram flow
 * @context_id: Context ID
 * @payload: Payload data
 * @len: Payload length
 *
 * Returns: Number of bytes sent on success, negative errno on failure.
 */
int http_datagram_send(struct http_datagram_flow *flow,
		       u64 context_id,
		       const u8 *payload, size_t len)
{
	struct tquic_connection *conn;
	u8 *buf;
	size_t buf_len;
	int encoded_len;
	int ret;

	if (!flow)
		return -EINVAL;

	if (len > 0 && !payload)
		return -EINVAL;

	/* Get connection - we need flow to be associated with a manager */
	/* For now, we'll need to pass connection through another means */
	/* This is a simplification - in practice flow would have conn reference */

	/* Calculate maximum buffer size needed */
	buf_len = 16 + len;  /* 8 bytes for each varint + payload */

	buf = kmalloc(buf_len, GFP_KERNEL);
	if (!buf)
		return -ENOMEM;

	/* Encode datagram */
	encoded_len = http_datagram_encode(flow, context_id, payload, len,
					   buf, buf_len);
	if (encoded_len < 0) {
		kfree(buf);
		return encoded_len;
	}

	/*
	 * Send via QUIC DATAGRAM frame.
	 * Note: This requires the flow to have a reference to the connection.
	 * In the full implementation, we'd need to thread this through properly.
	 */
	/* ret = tquic_send_datagram(conn, buf, encoded_len); */

	/* Update stats */
	spin_lock_bh(&flow->lock);
	flow->stats.tx_datagrams++;
	flow->stats.tx_bytes += len;
	spin_unlock_bh(&flow->lock);

	kfree(buf);
	return len;
}
EXPORT_SYMBOL_GPL(http_datagram_send);

/**
 * http_datagram_recv - Process received QUIC DATAGRAM
 * @mgr: Datagram manager
 * @data: DATAGRAM frame payload
 * @len: Payload length
 *
 * Returns: 0 on success, negative errno on failure.
 */
int http_datagram_recv(struct http_datagram_manager *mgr,
		       const u8 *data, size_t len)
{
	struct http_datagram_flow *flow;
	struct http_datagram_context *ctx;
	u64 quarter_stream_id;
	u64 context_id;
	const u8 *payload;
	size_t payload_len;
	int ret;

	if (!mgr || !data)
		return -EINVAL;

	if (!mgr->enabled)
		return -EOPNOTSUPP;

	/* Decode datagram */
	ret = http_datagram_decode(data, len, &quarter_stream_id,
				   &context_id, &payload, &payload_len);
	if (ret < 0)
		return ret;

	/* Find flow */
	flow = http_datagram_flow_lookup_by_quarter_id(mgr, quarter_stream_id);
	if (!flow) {
		pr_debug("http_datagram: no flow for qsid=%llu\n",
			 quarter_stream_id);
		return -ENOENT;
	}

	/* Update stats */
	spin_lock_bh(&flow->lock);
	flow->stats.rx_datagrams++;
	flow->stats.rx_bytes += payload_len;

	/* Find context handler */
	ctx = context_tree_search(&flow->contexts, context_id);
	if (!ctx) {
		flow->stats.unknown_contexts++;
		spin_unlock_bh(&flow->lock);
		http_datagram_flow_put(flow);
		pr_debug("http_datagram: unknown context %llu on flow qsid=%llu\n",
			 context_id, quarter_stream_id);
		return -ENOENT;
	}

	spin_unlock_bh(&flow->lock);

	/* Dispatch to handler */
	ret = ctx->handler(flow, context_id, payload, payload_len, ctx->context);

	http_datagram_flow_put(flow);
	return ret;
}
EXPORT_SYMBOL_GPL(http_datagram_recv);

/*
 * =============================================================================
 * STATISTICS
 * =============================================================================
 */

/**
 * http_datagram_flow_get_stats - Get flow statistics
 * @flow: Datagram flow
 * @tx_datagrams: Output for TX count
 * @rx_datagrams: Output for RX count
 * @tx_bytes: Output for TX bytes
 * @rx_bytes: Output for RX bytes
 *
 * Returns: 0 on success.
 */
int http_datagram_flow_get_stats(struct http_datagram_flow *flow,
				 u64 *tx_datagrams, u64 *rx_datagrams,
				 u64 *tx_bytes, u64 *rx_bytes)
{
	if (!flow)
		return -EINVAL;

	spin_lock_bh(&flow->lock);

	if (tx_datagrams)
		*tx_datagrams = flow->stats.tx_datagrams;
	if (rx_datagrams)
		*rx_datagrams = flow->stats.rx_datagrams;
	if (tx_bytes)
		*tx_bytes = flow->stats.tx_bytes;
	if (rx_bytes)
		*rx_bytes = flow->stats.rx_bytes;

	spin_unlock_bh(&flow->lock);

	return 0;
}
EXPORT_SYMBOL_GPL(http_datagram_flow_get_stats);

/*
 * =============================================================================
 * MODULE INITIALIZATION
 * =============================================================================
 */

/**
 * http_datagram_init - Initialize HTTP Datagram subsystem
 *
 * Returns: 0 on success, negative errno on failure.
 */
int __init http_datagram_init(void)
{
	flow_cache = kmem_cache_create("http_datagram_flow",
				       sizeof(struct http_datagram_flow),
				       0, SLAB_HWCACHE_ALIGN, NULL);
	if (!flow_cache)
		return -ENOMEM;

	context_cache = kmem_cache_create("http_datagram_context",
					  sizeof(struct http_datagram_context),
					  0, SLAB_HWCACHE_ALIGN, NULL);
	if (!context_cache) {
		kmem_cache_destroy(flow_cache);
		flow_cache = NULL;
		return -ENOMEM;
	}

	pr_info("TQUIC MASQUE: HTTP Datagrams (RFC 9297) initialized\n");
	return 0;
}
EXPORT_SYMBOL_GPL(http_datagram_init);

/**
 * http_datagram_exit - Clean up HTTP Datagram subsystem
 */
void __exit http_datagram_exit(void)
{
	if (context_cache) {
		kmem_cache_destroy(context_cache);
		context_cache = NULL;
	}

	if (flow_cache) {
		kmem_cache_destroy(flow_cache);
		flow_cache = NULL;
	}

	pr_info("TQUIC MASQUE: HTTP Datagrams cleaned up\n");
}
EXPORT_SYMBOL_GPL(http_datagram_exit);

MODULE_DESCRIPTION("TQUIC MASQUE HTTP Datagrams (RFC 9297)");
MODULE_LICENSE("GPL");
MODULE_AUTHOR("Linux Foundation");
