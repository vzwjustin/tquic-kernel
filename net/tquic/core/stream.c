// SPDX-License-Identifier: GPL-2.0-only
/*
 * TQUIC: Stream Layer Implementation
 *
 * Copyright (c) 2026 Linux Foundation
 *
 * This file implements the QUIC stream layer including:
 * - Stream ID allocation (client/server, bidi/uni)
 * - Stream state machine per RFC 9000
 * - Send/receive buffer management
 * - Stream priority and dependency
 * - FIN/RST handling
 * - Flow control integration
 * - RB-tree based stream lookup
 * - Zero-copy and splice support
 */

#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/skbuff.h>
#include <linux/rbtree.h>
#include <linux/list.h>
#include <linux/spinlock.h>
#include <linux/wait.h>
#include <linux/uio.h>
#include <linux/splice.h>
#include <linux/pipe_fs_i.h>
#include <linux/highmem.h>
#include <linux/mm.h>
#include <net/sock.h>
#include <net/tquic.h>
#include "../tquic_compat.h"
#include "../tquic_debug.h"
#include "stream.h"

/* Stream ID bit layout per QUIC spec:
 * Bit 0: Initiator (0 = client, 1 = server)
 * Bit 1: Direction (0 = bidirectional, 1 = unidirectional)
 * Remaining bits: Stream sequence number
 */
#define STREAM_ID_INITIATOR_BIT		0x01
#define STREAM_ID_DIRECTION_BIT		0x02
#define STREAM_ID_MASK			0x03

/* Stream type helpers */
#define STREAM_TYPE_CLIENT_BIDI		0x00
#define STREAM_TYPE_SERVER_BIDI		0x01
#define STREAM_TYPE_CLIENT_UNI		0x02
#define STREAM_TYPE_SERVER_UNI		0x03

/*
 * SECURITY FIX (CF-136): Define a named constant for "unknown final size"
 * instead of using bare -1, which relies on implicit signed-to-unsigned
 * conversion. Use S64_MAX as the sentinel value for the s64 final_size
 * field, avoiding signed overflow concerns.
 */
#define TQUIC_STREAM_SIZE_UNKNOWN	S64_MAX

/* Memory pool initialization */

/**
 * tquic_stream_manager_create - Create a stream manager
 * @conn: Parent connection
 * @is_server: True if this is the server side
 *
 * Return: New stream manager or NULL on failure
 */
struct tquic_stream_manager *tquic_stream_manager_create(
	struct tquic_connection *conn, bool is_server)
{
	struct tquic_stream_manager *mgr;

	mgr = kzalloc(sizeof(*mgr), GFP_KERNEL);
	if (!mgr) {
		tquic_conn_err(conn, "stream manager alloc failed\n");
		return NULL;
	}

	mgr->conn = conn;
	mgr->is_server = is_server;
	mgr->streams = RB_ROOT;
	spin_lock_init(&mgr->lock);

	INIT_LIST_HEAD(&mgr->send_list);
	INIT_LIST_HEAD(&mgr->blocked_list);

	/* Initialize stream limits */
	mgr->max_bidi_local = TQUIC_MAX_STREAM_COUNT_BIDI;
	mgr->max_bidi_remote = TQUIC_MAX_STREAM_COUNT_BIDI;
	mgr->max_uni_local = TQUIC_MAX_STREAM_COUNT_UNI;
	mgr->max_uni_remote = TQUIC_MAX_STREAM_COUNT_UNI;

	/* Initialize next stream IDs based on role */
	if (is_server) {
		mgr->next_bidi_local = STREAM_TYPE_SERVER_BIDI;
		mgr->next_uni_local = STREAM_TYPE_SERVER_UNI;
		mgr->next_bidi_remote = STREAM_TYPE_CLIENT_BIDI;
		mgr->next_uni_remote = STREAM_TYPE_CLIENT_UNI;
	} else {
		mgr->next_bidi_local = STREAM_TYPE_CLIENT_BIDI;
		mgr->next_uni_local = STREAM_TYPE_CLIENT_UNI;
		mgr->next_bidi_remote = STREAM_TYPE_SERVER_BIDI;
		mgr->next_uni_remote = STREAM_TYPE_SERVER_UNI;
	}

	/* Connection-level flow control */
	mgr->max_data_local = TQUIC_DEFAULT_MAX_DATA;
	mgr->max_data_remote = TQUIC_DEFAULT_MAX_DATA;

	/*
	 * SECURITY: Initialize stream creation rate limiting
	 *
	 * Defaults are set here but can be overridden via sysctl or per-connection
	 * configuration. These defaults allow 100 streams per second which is
	 * sufficient for most legitimate use cases while protecting against
	 * stream exhaustion attacks.
	 */
	mgr->rate_limit_window_start = ktime_get();
	mgr->streams_in_window = 0;
	mgr->max_streams_per_window = 100;	/* 100 streams per second */
	mgr->rate_limit_window_ms = 1000;	/* 1 second window */
	mgr->consecutive_limit_hits = 0;
	mgr->rate_limit_exceeded = false;

	/* Create SLAB caches */
	mgr->stream_cache = kmem_cache_create("tquic_stream_ext",
					      sizeof(struct tquic_stream_ext),
					      0, SLAB_HWCACHE_ALIGN, NULL);
	if (!mgr->stream_cache)
		goto err_stream_cache;

	mgr->gap_cache = kmem_cache_create("tquic_stream_gap",
					   sizeof(struct tquic_stream_gap),
					   0, SLAB_HWCACHE_ALIGN, NULL);
	if (!mgr->gap_cache)
		goto err_gap_cache;

	mgr->chunk_cache = kmem_cache_create("tquic_recv_chunk",
					     sizeof(struct tquic_recv_chunk),
					     0, SLAB_HWCACHE_ALIGN, NULL);
	if (!mgr->chunk_cache)
		goto err_chunk_cache;

	return mgr;

err_chunk_cache:
	kmem_cache_destroy(mgr->gap_cache);
err_gap_cache:
	kmem_cache_destroy(mgr->stream_cache);
err_stream_cache:
	kfree(mgr);
	return NULL;
}
EXPORT_SYMBOL_GPL(tquic_stream_manager_create);

/**
 * tquic_stream_ext_alloc - Allocate extended stream state
 * @mgr: Stream manager
 *
 * Return: New extended state or NULL on failure
 */
static struct tquic_stream_ext *tquic_stream_ext_alloc(
	struct tquic_stream_manager *mgr)
{
	struct tquic_stream_ext *ext;

	ext = kmem_cache_zalloc(mgr->stream_cache, GFP_ATOMIC);
	if (!ext)
		return NULL;

	/* Initialize lists */
	INIT_LIST_HEAD(&ext->gaps);
	INIT_LIST_HEAD(&ext->dep_children);
	INIT_LIST_HEAD(&ext->dep_node);

	ext->recv_chunks = RB_ROOT;
	skb_queue_head_init(&ext->pending_frames);
	skb_queue_head_init(&ext->retransmit_queue);

	/* Default settings */
	ext->priority = TQUIC_STREAM_PRIO_NORMAL;
	ext->weight = 16;
	ext->sndbuf_limit = TQUIC_STREAM_SNDBUF_DEFAULT;
	ext->rcvbuf_limit = TQUIC_STREAM_RCVBUF_DEFAULT;
	ext->final_size = TQUIC_STREAM_SIZE_UNKNOWN;

	atomic_set(&ext->zerocopy_refs, 0);

	ext->stats.created = ktime_get();

	return ext;
}

/**
 * tquic_stream_ext_free - Free extended stream state
 * @mgr: Stream manager
 * @ext: Extended state to free
 */
static void tquic_stream_ext_free(struct tquic_stream_manager *mgr,
				  struct tquic_stream_ext *ext)
{
	struct tquic_stream_gap *gap, *tmp_gap;
	struct rb_node *node;

	if (!ext)
		return;

	/* Free gaps */
	list_for_each_entry_safe(gap, tmp_gap, &ext->gaps, list) {
		list_del(&gap->list);
		kmem_cache_free(mgr->gap_cache, gap);
	}

	/* Free recv chunks */
	while ((node = rb_first(&ext->recv_chunks))) {
		struct tquic_recv_chunk *chunk;
		chunk = rb_entry(node, struct tquic_recv_chunk, node);
		rb_erase(node, &ext->recv_chunks);
		if (chunk->skb)
			kfree_skb(chunk->skb);
		kmem_cache_free(mgr->chunk_cache, chunk);
	}

	/* Purge queues */
	skb_queue_purge(&ext->pending_frames);
	skb_queue_purge(&ext->retransmit_queue);

	kmem_cache_free(mgr->stream_cache, ext);
}

/* Stream state machine */

/**
 * tquic_stream_state_name - Get name of stream state
 * @state: Stream state
 *
 * Return: State name string
 */
static const char *tquic_stream_state_name(enum tquic_stream_state state)
{
	static const char *names[] = {
		[TQUIC_STREAM_IDLE] = "IDLE",
		[TQUIC_STREAM_OPEN] = "OPEN",
		[TQUIC_STREAM_SEND] = "SEND",
		[TQUIC_STREAM_RECV] = "RECV",
		[TQUIC_STREAM_SIZE_KNOWN] = "SIZE_KNOWN",
		[TQUIC_STREAM_DATA_SENT] = "DATA_SENT",
		[TQUIC_STREAM_DATA_RECVD] = "DATA_RECVD",
		[TQUIC_STREAM_RESET_SENT] = "RESET_SENT",
		[TQUIC_STREAM_RESET_RECVD] = "RESET_RECVD",
		[TQUIC_STREAM_CLOSED] = "CLOSED",
	};

	if (state < ARRAY_SIZE(names) && names[state])
		return names[state];
	return "UNKNOWN";
}

/**
 * tquic_stream_set_state - Transition stream to new state
 * @stream: The stream
 * @new_state: New state
 *
 * Return: 0 on success, -EINVAL on invalid transition
 */
static int tquic_stream_set_state(struct tquic_stream *stream,
				  enum tquic_stream_state new_state)
{
	enum tquic_stream_state old_state = stream->state;

	/* Validate state transitions per RFC 9000 */
	switch (old_state) {
	case TQUIC_STREAM_IDLE:
		/* Can go to OPEN, SEND, or RECV */
		if (new_state != TQUIC_STREAM_OPEN &&
		    new_state != TQUIC_STREAM_SEND &&
		    new_state != TQUIC_STREAM_RECV)
			return -EINVAL;
		break;

	case TQUIC_STREAM_OPEN:
		/*
		 * SECURITY FIX (CF-152): OPEN represents a bidirectional
		 * stream with both send and recv sides active (RFC 9000
		 * Section 3). Allow transitions to:
		 * - SEND: recv side completed (peer sent FIN)
		 * - RECV: send side completed (local sent FIN)
		 * - SIZE_KNOWN, DATA_SENT: send-side completion
		 * - RESET_SENT, RESET_RECVD: reset in either direction
		 */
		if (new_state != TQUIC_STREAM_SEND &&
		    new_state != TQUIC_STREAM_RECV &&
		    new_state != TQUIC_STREAM_SIZE_KNOWN &&
		    new_state != TQUIC_STREAM_DATA_SENT &&
		    new_state != TQUIC_STREAM_RESET_SENT &&
		    new_state != TQUIC_STREAM_RESET_RECVD)
			return -EINVAL;
		break;

	case TQUIC_STREAM_SEND:
		/* Sending side states */
		if (new_state != TQUIC_STREAM_DATA_SENT &&
		    new_state != TQUIC_STREAM_RESET_SENT &&
		    new_state != TQUIC_STREAM_CLOSED)
			return -EINVAL;
		break;

	case TQUIC_STREAM_RECV:
		/* Receiving side states */
		if (new_state != TQUIC_STREAM_SIZE_KNOWN &&
		    new_state != TQUIC_STREAM_RESET_RECVD &&
		    new_state != TQUIC_STREAM_CLOSED)
			return -EINVAL;
		break;

	case TQUIC_STREAM_SIZE_KNOWN:
		if (new_state != TQUIC_STREAM_DATA_RECVD &&
		    new_state != TQUIC_STREAM_RESET_RECVD &&
		    new_state != TQUIC_STREAM_CLOSED)
			return -EINVAL;
		break;

	case TQUIC_STREAM_DATA_SENT:
	case TQUIC_STREAM_DATA_RECVD:
	case TQUIC_STREAM_RESET_SENT:
	case TQUIC_STREAM_RESET_RECVD:
		/* Terminal states can only go to CLOSED */
		if (new_state != TQUIC_STREAM_CLOSED)
			return -EINVAL;
		break;

	case TQUIC_STREAM_CLOSED:
		/* Cannot transition from CLOSED */
		return -EINVAL;
	}

	stream->state = new_state;
	tquic_dbg("stream %llu state %s -> %s\n",
		  stream->id,
		  tquic_stream_state_name(old_state),
		  tquic_stream_state_name(new_state));

	return 0;
}

/* RB-tree stream lookup */

/**
 * tquic_stream_lookup - Find a stream by ID
 * @mgr: Stream manager
 * @stream_id: Stream ID to find
 *
 * Return: Stream or NULL if not found
 *
 * Note: Caller must hold mgr->lock or ensure RCU read lock
 */
struct tquic_stream *tquic_stream_lookup(struct tquic_stream_manager *mgr,
					 u64 stream_id)
{
	struct rb_node *node = mgr->streams.rb_node;

	while (node) {
		struct tquic_stream *stream;

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
EXPORT_SYMBOL_GPL(tquic_stream_lookup);

/**
 * tquic_stream_insert - Insert a stream into the tree
 * @mgr: Stream manager
 * @stream: Stream to insert
 *
 * Return: 0 on success, -EEXIST if stream ID already exists
 *
 * Note: Caller must hold mgr->lock
 */
static int tquic_stream_insert(struct tquic_stream_manager *mgr,
			       struct tquic_stream *stream)
{
	struct rb_node **link = &mgr->streams.rb_node;
	struct rb_node *parent = NULL;

	while (*link) {
		struct tquic_stream *entry;

		parent = *link;
		entry = rb_entry(parent, struct tquic_stream, node);

		if (stream->id < entry->id)
			link = &parent->rb_left;
		else if (stream->id > entry->id)
			link = &parent->rb_right;
		else
			return -EEXIST;
	}

	rb_link_node(&stream->node, parent, link);
	rb_insert_color(&stream->node, &mgr->streams);
	mgr->stream_count++;

	return 0;
}

/**
 * tquic_stream_remove - Remove a stream from the tree
 * @mgr: Stream manager
 * @stream: Stream to remove
 *
 * Note: Caller must hold mgr->lock
 */
static void tquic_stream_remove(struct tquic_stream_manager *mgr,
				struct tquic_stream *stream)
{
	rb_erase(&stream->node, &mgr->streams);
	mgr->stream_count--;
}

/* Stream ID allocation */

/**
 * tquic_stream_alloc_id - Allocate a new stream ID
 * @mgr: Stream manager
 * @bidi: True for bidirectional, false for unidirectional
 * @stream_id: Output stream ID
 *
 * Return: 0 on success, -ENOSPC if limit reached
 */
static int tquic_stream_alloc_id(struct tquic_stream_manager *mgr,
				 bool bidi, u64 *stream_id)
{
	u64 next_id;
	u32 *counter;
	u64 max_streams;

	if (bidi) {
		next_id = mgr->next_bidi_local;
		counter = &mgr->bidi_local;
		max_streams = mgr->max_bidi_local;
	} else {
		next_id = mgr->next_uni_local;
		counter = &mgr->uni_local;
		max_streams = mgr->max_uni_local;
	}

	/* Check stream limit */
	if (*counter >= max_streams) {
		tquic_warn("stream limit reached: %u >= %llu\n",
			   *counter, max_streams);
		return -ENOSPC;
	}

	*stream_id = next_id;

	/* Advance to next ID (IDs increment by 4) */
	if (bidi)
		mgr->next_bidi_local += 4;
	else
		mgr->next_uni_local += 4;

	(*counter)++;

	return 0;
}

/*
 * SECURITY: Stream creation rate limiting constants
 */
#define TQUIC_STREAM_RATE_LIMIT_DEFAULT		100	/* streams per window */
#define TQUIC_STREAM_RATE_WINDOW_MS_DEFAULT	1000	/* 1 second window */
#define TQUIC_STREAM_RATE_ABUSE_THRESHOLD	10	/* consecutive limit hits */

/**
 * tquic_stream_check_rate_limit - Check stream creation rate limit
 * @mgr: Stream manager
 * @new_streams: Number of new streams being requested
 *
 * SECURITY: Prevents stream ID exhaustion attacks by rate limiting how
 * quickly a peer can create new streams. This protects against:
 *
 * 1. Memory exhaustion - Each stream requires kernel memory allocation
 * 2. CPU exhaustion - Processing rapid stream creation frames
 * 3. Stream ID space exhaustion - Depleting the 62-bit stream ID space
 *
 * RFC 9000 allows up to 2^60 streams per direction, but rapid creation
 * should be rate limited to prevent abuse.
 *
 * Return: 0 if allowed, -EBUSY if rate limit exceeded, -ECONNABORTED if abuse
 */
static int tquic_stream_check_rate_limit(struct tquic_stream_manager *mgr,
					 u64 new_streams)
{
	ktime_t now = ktime_get();
	s64 elapsed_ms;

	/* Initialize defaults if not set */
	if (mgr->max_streams_per_window == 0)
		mgr->max_streams_per_window = TQUIC_STREAM_RATE_LIMIT_DEFAULT;
	if (mgr->rate_limit_window_ms == 0)
		mgr->rate_limit_window_ms = TQUIC_STREAM_RATE_WINDOW_MS_DEFAULT;

	/* Check for abuse flag - connection should be terminated */
	if (mgr->rate_limit_exceeded) {
		tquic_warn("connection flagged for stream abuse\n");
		return -ECONNABORTED;
	}

	/* Calculate time since window start */
	elapsed_ms = ktime_ms_delta(now, mgr->rate_limit_window_start);

	/* Reset window if expired */
	if (elapsed_ms >= mgr->rate_limit_window_ms) {
		mgr->rate_limit_window_start = now;
		mgr->streams_in_window = 0;
	}

	/* Check if new streams would exceed rate limit */
	if (mgr->streams_in_window + new_streams > mgr->max_streams_per_window) {
		mgr->consecutive_limit_hits++;

		tquic_warn("stream rate limit hit (%u streams in %lld ms, consecutive=%u)\n",
			   mgr->streams_in_window, elapsed_ms,
			   mgr->consecutive_limit_hits);

		/*
		 * If we've hit the limit multiple times consecutively,
		 * flag this connection as potentially abusive.
		 */
		if (mgr->consecutive_limit_hits >= TQUIC_STREAM_RATE_ABUSE_THRESHOLD) {
			tquic_err("connection flagged for stream exhaustion attack\n");
			mgr->rate_limit_exceeded = true;
			return -ECONNABORTED;
		}

		return -EBUSY;
	}

	/* Reset consecutive hit counter on successful check */
	if (mgr->consecutive_limit_hits > 0 &&
	    mgr->streams_in_window + new_streams <= mgr->max_streams_per_window / 2) {
		mgr->consecutive_limit_hits = 0;
	}

	/* Account for the new streams */
	mgr->streams_in_window += new_streams;

	return 0;
}

/**
 * tquic_stream_accept_id - Accept a remotely-initiated stream ID
 * @mgr: Stream manager
 * @stream_id: The stream ID
 *
 * Return: 0 on success, -EINVAL if invalid, -ENOSPC if limit exceeded,
 *         -EBUSY if rate limited, -ECONNABORTED if abuse detected
 */
static int tquic_stream_accept_id(struct tquic_stream_manager *mgr,
				  u64 stream_id)
{
	bool is_bidi = tquic_stream_id_is_bidi(stream_id);
	u64 *next_id;
	u32 *counter;
	u64 max_streams;
	u64 new_streams;
	int ret;

	/* Verify this is a remote-initiated stream */
	if (tquic_stream_is_local(mgr, stream_id))
		return -EINVAL;

	if (is_bidi) {
		next_id = &mgr->next_bidi_remote;
		counter = &mgr->bidi_remote;
		max_streams = mgr->max_bidi_remote;
	} else {
		next_id = &mgr->next_uni_remote;
		counter = &mgr->uni_remote;
		max_streams = mgr->max_uni_remote;
	}

	/* Check if this ID is expected */
	if (stream_id < *next_id)
		return -EINVAL;  /* Already exists or below range */

	/* Calculate how many streams this would create */
	new_streams = (stream_id - *next_id) / 4 + 1;

	/*
	 * SECURITY: Check MAX_STREAMS limit
	 * This enforces the peer's advertised stream limit.
	 */
	if (*counter + new_streams > max_streams) {
		tquic_dbg("MAX_STREAMS exceeded (have=%u, want=%llu, max=%llu)\n",
			  *counter, new_streams, max_streams);
		return -ENOSPC;
	}

	/*
	 * SECURITY: Check rate limit to prevent stream exhaustion attacks.
	 * This is an additional protection layer beyond MAX_STREAMS.
	 */
	ret = tquic_stream_check_rate_limit(mgr, new_streams);
	if (ret)
		return ret;

	/* Accept this ID and all IDs below it */
	*next_id = stream_id + 4;
	*counter += new_streams;

	return 0;
}

/* Stream creation and destruction */

/**
 * tquic_stream_create_internal - Internal stream creation
 * @mgr: Stream manager
 * @stream_id: Stream ID
 * @local: True if locally initiated
 *
 * Return: New stream or NULL on failure
 */
static struct tquic_stream *tquic_stream_create_internal(
	struct tquic_stream_manager *mgr, u64 stream_id, bool local)
{
	struct tquic_stream *stream;
	struct tquic_stream_ext *ext;
	bool is_bidi = tquic_stream_id_is_bidi(stream_id);

	stream = kzalloc(sizeof(*stream), GFP_ATOMIC);
	if (!stream)
		return NULL;

	ext = tquic_stream_ext_alloc(mgr);
	if (!ext) {
		kfree(stream);
		return NULL;
	}

	stream->id = stream_id;
	stream->conn = mgr->conn;

	/* Initialize buffers */
	skb_queue_head_init(&stream->send_buf);
	skb_queue_head_init(&stream->recv_buf);

	/* Set initial flow control limits */
	stream->max_send_data = TQUIC_DEFAULT_MAX_STREAM_DATA;
	stream->max_recv_data = TQUIC_DEFAULT_MAX_STREAM_DATA;

	/* Initialize state based on stream type and initiator */
	if (is_bidi) {
		stream->state = TQUIC_STREAM_OPEN;
	} else {
		/* Unidirectional: sender starts in SEND, receiver in RECV */
		if (local)
			stream->state = TQUIC_STREAM_SEND;
		else
			stream->state = TQUIC_STREAM_RECV;
	}

	stream->priority = ext->priority;
	init_waitqueue_head(&stream->wait);

	/* Store extended state in stream's ext field */
	stream->ext = ext;

	return stream;
}

/**
 * tquic_stream_create - Create a new locally-initiated stream
 * @mgr: Stream manager
 * @bidi: True for bidirectional stream
 *
 * Return: New stream or ERR_PTR on failure
 */
struct tquic_stream *tquic_stream_create(struct tquic_stream_manager *mgr,
					 bool bidi)
{
	struct tquic_stream *stream;
	u64 stream_id;
	int ret;

	spin_lock(&mgr->lock);

	ret = tquic_stream_alloc_id(mgr, bidi, &stream_id);
	if (ret) {
		spin_unlock(&mgr->lock);
		return ERR_PTR(ret);
	}

	stream = tquic_stream_create_internal(mgr, stream_id, true);
	if (!stream) {
		spin_unlock(&mgr->lock);
		return ERR_PTR(-ENOMEM);
	}

	ret = tquic_stream_insert(mgr, stream);
	if (ret) {
		spin_unlock(&mgr->lock);
		tquic_stream_ext_free(mgr, stream->ext);
		kfree(stream);
		return ERR_PTR(ret);
	}

	spin_unlock(&mgr->lock);

	tquic_dbg("created local stream %llu (bidi=%d)\n",
		  stream_id, bidi);

	return stream;
}
EXPORT_SYMBOL_GPL(tquic_stream_create);

/**
 * tquic_stream_get_or_create - Get existing stream or create for remote
 * @mgr: Stream manager
 * @stream_id: Stream ID
 *
 * Return: Stream or ERR_PTR on failure
 */
struct tquic_stream *tquic_stream_get_or_create(
	struct tquic_stream_manager *mgr, u64 stream_id)
{
	struct tquic_stream *stream;
	int ret;

	spin_lock(&mgr->lock);

	/* Check if stream already exists */
	stream = tquic_stream_lookup(mgr, stream_id);
	if (stream) {
		spin_unlock(&mgr->lock);
		return stream;
	}

	/* Validate and accept new remote stream */
	ret = tquic_stream_accept_id(mgr, stream_id);
	if (ret) {
		spin_unlock(&mgr->lock);
		return ERR_PTR(ret);
	}

	/* Create the stream */
	stream = tquic_stream_create_internal(mgr, stream_id, false);
	if (!stream) {
		spin_unlock(&mgr->lock);
		return ERR_PTR(-ENOMEM);
	}

	ret = tquic_stream_insert(mgr, stream);
	if (ret) {
		spin_unlock(&mgr->lock);
		tquic_stream_ext_free(mgr, stream->ext);
		kfree(stream);
		return ERR_PTR(ret);
	}

	spin_unlock(&mgr->lock);

	tquic_dbg("accepted remote stream %llu\n", stream_id);

	return stream;
}
EXPORT_SYMBOL_GPL(tquic_stream_get_or_create);

/**
 * tquic_stream_destroy - Destroy a stream
 * @mgr: Stream manager (may be NULL for direct cleanup)
 * @stream: Stream to destroy
 */
void tquic_stream_destroy(struct tquic_stream_manager *mgr,
			  struct tquic_stream *stream)
{
	struct sock *sk;
	struct sk_buff *skb;

	if (!stream)
		return;

	if (mgr) {
		spin_lock(&mgr->lock);
		tquic_stream_remove(mgr, stream);
		spin_unlock(&mgr->lock);
	}

	/* Get socket for memory accounting */
	sk = stream->conn ? stream->conn->sk : (mgr && mgr->conn ? mgr->conn->sk : NULL);

	/* Purge buffers with proper memory accounting */
	while ((skb = skb_dequeue(&stream->send_buf)) != NULL) {
		if (sk) {
			sk_mem_uncharge(sk, skb->truesize);
			/* sk_wmem_alloc handled by skb destructor */
		}
		kfree_skb(skb);
	}
	while ((skb = skb_dequeue(&stream->recv_buf)) != NULL) {
		if (sk) {
			sk_mem_uncharge(sk, skb->truesize);
			atomic_sub(skb->truesize, &sk->sk_rmem_alloc);
		}
		kfree_skb(skb);
	}

	/* Free extended stream state if allocated */
	if (stream->ext && mgr)
		tquic_stream_ext_free(mgr, stream->ext);

	/* Wake any waiters */
	wake_up_all(&stream->wait);

	tquic_dbg("destroyed stream %llu\n", stream->id);

	kfree(stream);
}
EXPORT_SYMBOL_GPL(tquic_stream_destroy);

/* Send buffer management */

/**
 * tquic_stream_send_allowed - Check if send is allowed
 * @mgr: Stream manager
 * @stream: The stream
 * @len: Bytes to send
 *
 * Return: Bytes allowed to send (may be less than requested)
 */
static size_t tquic_stream_send_allowed(struct tquic_stream_manager *mgr,
					struct tquic_stream *stream,
					size_t len)
{
	size_t allowed = len;
	u64 stream_limit, conn_limit;

	/* Check stream state */
	if (stream->state != TQUIC_STREAM_OPEN &&
	    stream->state != TQUIC_STREAM_SEND)
		return 0;

	if (stream->fin_sent)
		return 0;

	/* Stream-level flow control */
	stream_limit = stream->max_send_data - stream->send_offset;
	if (allowed > stream_limit) {
		allowed = stream_limit;
		stream->blocked = true;
	}

	/* Connection-level flow control */
	conn_limit = mgr->max_data_remote - mgr->data_sent;
	if (allowed > conn_limit) {
		allowed = conn_limit;
		mgr->data_blocked = true;
	}

	return allowed;
}

/**
 * tquic_stream_write - Write data to stream send buffer
 * @mgr: Stream manager
 * @stream: The stream
 * @from: Source iterator
 * @len: Length to write
 * @fin: Set FIN flag
 *
 * Return: Bytes written or negative error
 */
ssize_t tquic_stream_write(struct tquic_stream_manager *mgr,
			   struct tquic_stream *stream,
			   struct iov_iter *from, size_t len, bool fin)
{
	size_t copied = 0;
	size_t allowed;
	int err;

	if (!tquic_stream_can_send(mgr, stream))
		return -EINVAL;

	spin_lock(&mgr->lock);

	while (copied < len) {
		struct sk_buff *skb;
		size_t chunk;

		allowed = tquic_stream_send_allowed(mgr, stream, len - copied);
		if (allowed == 0) {
			if (copied == 0) {
				spin_unlock(&mgr->lock);
				return -EAGAIN;
			}
			break;
		}

		/* Limit chunk size for reasonable SKB sizes */
		chunk = min_t(size_t, allowed, 16384);

		skb = alloc_skb(chunk, GFP_ATOMIC);
		if (!skb) {
			if (copied == 0) {
				spin_unlock(&mgr->lock);
				return -ENOMEM;
			}
			break;
		}

		err = copy_from_iter(skb_put(skb, chunk), chunk, from);
		if (err != chunk) {
			kfree_skb(skb);
			if (copied == 0) {
				spin_unlock(&mgr->lock);
				return -EFAULT;
			}
			break;
		}

		/* Store stream offset in skb->cb */
		*(u64 *)skb->cb = stream->send_offset;

		skb_queue_tail(&stream->send_buf, skb);

		stream->send_offset += chunk;
		mgr->data_sent += chunk;
		copied += chunk;
	}

	/* Handle FIN */
	if (fin && copied == len) {
		stream->fin_sent = true;
		if (stream->state == TQUIC_STREAM_OPEN ||
		    stream->state == TQUIC_STREAM_SEND)
			tquic_stream_set_state(stream, TQUIC_STREAM_DATA_SENT);
	}

	spin_unlock(&mgr->lock);

	return copied;
}
EXPORT_SYMBOL_GPL(tquic_stream_write);

/**
 * tquic_stream_write_zerocopy - Zero-copy write to stream
 * @mgr: Stream manager
 * @stream: The stream
 * @pages: Array of pages
 * @nr_pages: Number of pages
 * @offset: Offset in first page
 * @len: Total length
 * @fin: Set FIN flag
 *
 * Return: Bytes written or negative error
 */
ssize_t tquic_stream_write_zerocopy(struct tquic_stream_manager *mgr,
				    struct tquic_stream *stream,
				    struct page **pages, int nr_pages,
				    size_t offset, size_t len, bool fin)
{
	size_t copied = 0;
	size_t allowed;
	int i;
	size_t page_offset = offset;

	if (!tquic_stream_can_send(mgr, stream))
		return -EINVAL;

	spin_lock(&mgr->lock);

	allowed = tquic_stream_send_allowed(mgr, stream, len);
	if (allowed == 0) {
		spin_unlock(&mgr->lock);
		return -EAGAIN;
	}

	len = min(len, allowed);

	for (i = 0; i < nr_pages && copied < len; i++) {
		struct sk_buff *skb;
		size_t page_len;
		skb_frag_t *frag;

		page_len = min_t(size_t, PAGE_SIZE - page_offset, len - copied);

		skb = alloc_skb(0, GFP_ATOMIC);
		if (!skb) {
			if (copied == 0) {
				spin_unlock(&mgr->lock);
				return -ENOMEM;
			}
			break;
		}

		/* Reference the page for zero-copy */
		get_page(pages[i]);

		frag = &skb_shinfo(skb)->frags[0];
		skb_frag_fill_page_desc(frag, pages[i], page_offset, page_len);
		skb_shinfo(skb)->nr_frags = 1;
		skb->len = page_len;
		skb->data_len = page_len;
		skb->truesize += page_len;

		/* Store stream offset */
		*(u64 *)skb->cb = stream->send_offset;

		skb_queue_tail(&stream->send_buf, skb);

		stream->send_offset += page_len;
		mgr->data_sent += page_len;
		copied += page_len;
		page_offset = 0;  /* Subsequent pages start at offset 0 */
	}

	if (fin && copied == len) {
		stream->fin_sent = true;
		if (stream->state == TQUIC_STREAM_OPEN ||
		    stream->state == TQUIC_STREAM_SEND)
			tquic_stream_set_state(stream, TQUIC_STREAM_DATA_SENT);
	}

	spin_unlock(&mgr->lock);

	return copied;
}
EXPORT_SYMBOL_GPL(tquic_stream_write_zerocopy);

/* Receive buffer management with reassembly */

/**
 * tquic_stream_recv_chunk_insert - Insert a received chunk for reassembly
 * @mgr: Stream manager
 * @stream: The stream
 * @offset: Stream offset
 * @data: Data pointer
 * @len: Data length
 * @skb: SKB containing data (or NULL if inline)
 * @fin: FIN flag
 *
 * Return: 0 on success, negative error
 */
static int tquic_stream_recv_chunk_insert(struct tquic_stream_manager *mgr,
					  struct tquic_stream *stream,
					  u64 offset, void *data, u32 len,
					  struct sk_buff *skb, bool fin)
{
	struct tquic_stream_ext *ext;
	struct tquic_recv_chunk *chunk;
	struct rb_node **link, *parent = NULL;

	/* Get extended state from stream's ext field */
	ext = stream->ext;

	/* Allocate chunk */
	chunk = kmem_cache_zalloc(mgr->chunk_cache, GFP_ATOMIC);
	if (!chunk)
		return -ENOMEM;

	chunk->offset = offset;
	chunk->length = len;
	chunk->data = data;
	chunk->skb = skb;
	chunk->fin = fin;

	if (skb)
		skb_get(skb);

	/*
	 * Insert into RB-tree ordered by offset for proper reassembly.
	 * This allows out-of-order data to be stored and delivered in order.
	 */
	if (ext) {
		link = &ext->recv_chunks.rb_node;

		while (*link) {
			struct tquic_recv_chunk *this;

			parent = *link;
			this = rb_entry(parent, struct tquic_recv_chunk, node);

			if (offset < this->offset) {
				link = &(*link)->rb_left;
			} else if (offset > this->offset) {
				link = &(*link)->rb_right;
			} else {
				/* Duplicate offset - discard */
				kmem_cache_free(mgr->chunk_cache, chunk);
				if (skb)
					kfree_skb(skb);
				return 0;
			}
		}

		rb_link_node(&chunk->node, parent, link);
		rb_insert_color(&chunk->node, &ext->recv_chunks);

		/* Update receive tracking */
		if (offset > ext->recv_max)
			ext->recv_max = offset + len;

		/* Deliver in-order chunks to recv_buf */
		while ((chunk = rb_entry_safe(rb_first(&ext->recv_chunks),
					      struct tquic_recv_chunk, node))) {
			if (chunk->offset != ext->recv_next)
				break;

			rb_erase(&chunk->node, &ext->recv_chunks);
			if (chunk->skb) {
				*(u64 *)chunk->skb->cb = chunk->offset;
				skb_queue_tail(&stream->recv_buf, chunk->skb);
			}
			ext->recv_next += chunk->length;
			ext->rcvbuf_used += chunk->length;
			kmem_cache_free(mgr->chunk_cache, chunk);
		}

		return 0;
	}

	/* Fallback: use simpler linear approach via recv_buf */
	if (skb) {
		*(u64 *)skb->cb = offset;
		skb_queue_tail(&stream->recv_buf, skb);
	}
	kmem_cache_free(mgr->chunk_cache, chunk);

	return 0;
}

/**
 * tquic_stream_recv_data - Process received stream data
 * @mgr: Stream manager
 * @stream: The stream
 * @offset: Stream offset
 * @skb: SKB containing data
 * @fin: FIN flag
 *
 * Return: 0 on success, negative error
 */
int tquic_stream_recv_data(struct tquic_stream_manager *mgr,
			   struct tquic_stream *stream,
			   u64 offset, struct sk_buff *skb, bool fin)
{
	int ret;

	if (!tquic_stream_can_recv(mgr, stream))
		return -EINVAL;

	/* Check receive state */
	if (stream->state != TQUIC_STREAM_OPEN &&
	    stream->state != TQUIC_STREAM_RECV &&
	    stream->state != TQUIC_STREAM_SIZE_KNOWN)
		return -EINVAL;

	spin_lock(&mgr->lock);

	/*
	 * SECURITY FIX (CF-233): Check for integer overflow before
	 * the flow control comparison. If skb->len is large relative
	 * to offset, their sum can wrap around u64, bypassing the
	 * flow control check entirely and allowing unbounded data
	 * injection.
	 */
	if (skb->len > U64_MAX - offset) {
		spin_unlock(&mgr->lock);
		return -EOVERFLOW;
	}

	/* Flow control check */
	if (offset + skb->len > stream->max_recv_data) {
		spin_unlock(&mgr->lock);
		return -EOVERFLOW;  /* Flow control violation */
	}

	/* Connection-level flow control */
	if (mgr->data_received + skb->len > mgr->max_data_local) {
		spin_unlock(&mgr->lock);
		return -EOVERFLOW;
	}

	/* Insert chunk for reassembly */
	ret = tquic_stream_recv_chunk_insert(mgr, stream, offset,
					     skb->data, skb->len, skb, fin);
	if (ret) {
		spin_unlock(&mgr->lock);
		return ret;
	}

	/* Update receive tracking */
	stream->recv_offset = max(stream->recv_offset, offset + skb->len);
	mgr->data_received += skb->len;

	/* Handle FIN */
	if (fin) {
		stream->fin_received = true;
		if (stream->state == TQUIC_STREAM_RECV)
			tquic_stream_set_state(stream, TQUIC_STREAM_SIZE_KNOWN);
	}

	spin_unlock(&mgr->lock);

	/* Wake up any readers */
	wake_up_interruptible(&stream->wait);

	return 0;
}
EXPORT_SYMBOL_GPL(tquic_stream_recv_data);

/**
 * tquic_stream_read - Read data from stream
 * @mgr: Stream manager
 * @stream: The stream
 * @to: Destination iterator
 * @len: Maximum length to read
 *
 * Return: Bytes read or negative error
 */
ssize_t tquic_stream_read(struct tquic_stream_manager *mgr,
			  struct tquic_stream *stream,
			  struct iov_iter *to, size_t len)
{
	size_t copied = 0;

	if (!tquic_stream_can_recv(mgr, stream))
		return -EINVAL;

	spin_lock(&mgr->lock);

	while (copied < len && !skb_queue_empty(&stream->recv_buf)) {
		struct sk_buff *skb;
		size_t chunk;
		int err;

		skb = skb_peek(&stream->recv_buf);
		if (!skb)
			break;

		chunk = min_t(size_t, len - copied, skb->len);

		err = copy_to_iter(skb->data, chunk, to);
		if (err != chunk) {
			if (copied == 0) {
				spin_unlock(&mgr->lock);
				return -EFAULT;
			}
			break;
		}

		copied += chunk;

		if (chunk < skb->len) {
			/* Partial read */
			skb_pull(skb, chunk);
		} else {
			/* Fully consumed */
			skb_unlink(skb, &stream->recv_buf);
			kfree_skb(skb);
		}
	}

	/* Check for end of stream */
	if (stream->fin_received && skb_queue_empty(&stream->recv_buf)) {
		if (stream->state == TQUIC_STREAM_SIZE_KNOWN)
			tquic_stream_set_state(stream, TQUIC_STREAM_DATA_RECVD);
	}

	spin_unlock(&mgr->lock);

	return copied;
}
EXPORT_SYMBOL_GPL(tquic_stream_read);

/* FIN handling (graceful close) */

/**
 * tquic_stream_shutdown_write - Shutdown write side of stream (send FIN)
 * @mgr: Stream manager
 * @stream: The stream
 *
 * Return: 0 on success, negative error
 */
int tquic_stream_shutdown_write(struct tquic_stream_manager *mgr,
				struct tquic_stream *stream)
{
	if (!tquic_stream_can_send(mgr, stream))
		return -EINVAL;

	spin_lock(&mgr->lock);

	if (stream->fin_sent) {
		spin_unlock(&mgr->lock);
		return 0;  /* Already sent */
	}

	stream->fin_sent = true;

	/* Transition state */
	if (stream->state == TQUIC_STREAM_OPEN ||
	    stream->state == TQUIC_STREAM_SEND)
		tquic_stream_set_state(stream, TQUIC_STREAM_DATA_SENT);

	spin_unlock(&mgr->lock);

	tquic_dbg("stream %llu FIN sent\n", stream->id);

	return 0;
}
EXPORT_SYMBOL_GPL(tquic_stream_shutdown_write);

/**
 * tquic_stream_shutdown_read - Shutdown read side of stream (send STOP_SENDING)
 * @mgr: Stream manager
 * @stream: The stream
 * @error_code: Application error code
 *
 * Return: 0 on success, negative error
 */
int tquic_stream_shutdown_read(struct tquic_stream_manager *mgr,
			       struct tquic_stream *stream,
			       u64 error_code)
{
	if (!tquic_stream_can_recv(mgr, stream))
		return -EINVAL;

	spin_lock(&mgr->lock);

	/* Mark that we sent STOP_SENDING */
	/* In real impl, would queue STOP_SENDING frame */

	spin_unlock(&mgr->lock);

	tquic_dbg("stream %llu STOP_SENDING error=%llu\n",
		  stream->id, error_code);

	return 0;
}
EXPORT_SYMBOL_GPL(tquic_stream_shutdown_read);

/* RST_STREAM handling (abrupt close) */

/**
 * tquic_stream_reset_send - Send RST_STREAM frame
 * @mgr: Stream manager
 * @stream: The stream
 * @error_code: Application error code
 *
 * Return: 0 on success, negative error
 */
int tquic_stream_reset_send(struct tquic_stream_manager *mgr,
			    struct tquic_stream *stream,
			    u64 error_code)
{
	struct sock *sk;
	struct sk_buff *skb;

	if (!tquic_stream_can_send(mgr, stream))
		return -EINVAL;

	sk = (mgr->conn) ? mgr->conn->sk : NULL;

	spin_lock(&mgr->lock);

	/* Clear send buffer with proper memory accounting */
	while ((skb = skb_dequeue(&stream->send_buf)) != NULL) {
		if (sk) {
			sk_mem_uncharge(sk, skb->truesize);
			/* sk_wmem_alloc handled by skb destructor */
		}
		kfree_skb(skb);
	}

	/* Record error and transition state via validator */
	{
		int ret;

		ret = tquic_stream_set_state(stream, TQUIC_STREAM_RESET_SENT);
		if (ret) {
			spin_unlock(&mgr->lock);
			tquic_dbg("stream %llu invalid reset_send transition from %d\n",
				  stream->id, stream->state);
			return ret;
		}
	}

	spin_unlock(&mgr->lock);

	tquic_dbg("stream %llu RST_STREAM sent error=%llu\n",
		  stream->id, error_code);

	return 0;
}
EXPORT_SYMBOL_GPL(tquic_stream_reset_send);

/**
 * tquic_stream_reset_recv - Process received RST_STREAM frame
 * @mgr: Stream manager
 * @stream: The stream
 * @error_code: Application error code
 * @final_size: Final size of stream data
 *
 * Return: 0 on success, negative error
 */
int tquic_stream_reset_recv(struct tquic_stream_manager *mgr,
			    struct tquic_stream *stream,
			    u64 error_code, u64 final_size)
{
	if (!tquic_stream_can_recv(mgr, stream))
		return -EINVAL;

	spin_lock(&mgr->lock);

	/* Discard receive buffer */
	skb_queue_purge(&stream->recv_buf);

	/* Transition state via validator */
	{
		int ret;

		ret = tquic_stream_set_state(stream, TQUIC_STREAM_RESET_RECVD);
		if (ret) {
			spin_unlock(&mgr->lock);
			tquic_dbg("stream %llu invalid reset_recv transition from %d\n",
				  stream->id, stream->state);
			return ret;
		}
	}

	spin_unlock(&mgr->lock);

	/* Wake up readers with error */
	wake_up_interruptible(&stream->wait);

	tquic_info("stream %llu RST_STREAM received error=%llu final=%llu\n",
		   stream->id, error_code, final_size);

	return 0;
}
EXPORT_SYMBOL_GPL(tquic_stream_reset_recv);

/* Stream priority and dependency */

/**
 * tquic_stream_set_priority - Set stream priority
 * @stream: The stream
 * @priority: Priority (0=urgent, 255=bulk)
 *
 * Return: 0 on success
 */
int tquic_stream_set_priority(struct tquic_stream *stream, u8 priority)
{
	stream->priority = priority;
	return 0;
}
EXPORT_SYMBOL_GPL(tquic_stream_set_priority);

/**
 * tquic_stream_set_dependency - Set stream dependency
 * @mgr: Stream manager
 * @stream: The stream
 * @dependency: ID of parent stream (0 for root)
 * @weight: Weight relative to siblings (1-256)
 * @exclusive: If true, become exclusive child
 *
 * Return: 0 on success, negative error
 */
int tquic_stream_set_dependency(struct tquic_stream_manager *mgr,
				struct tquic_stream *stream,
				u64 dependency, u16 weight, bool exclusive)
{
	struct tquic_stream *parent;

	if (weight < 1 || weight > 256)
		return -EINVAL;

	spin_lock(&mgr->lock);

	if (dependency != 0) {
		parent = tquic_stream_lookup(mgr, dependency);
		if (!parent) {
			spin_unlock(&mgr->lock);
			return -ENOENT;
		}
	}

	/* Update dependency (simplified - real impl would update tree) */

	spin_unlock(&mgr->lock);

	tquic_dbg("stream %llu dependency=%llu weight=%u exclusive=%d\n",
		  stream->id, dependency, weight, exclusive);

	return 0;
}
EXPORT_SYMBOL_GPL(tquic_stream_set_dependency);

/* Flow control integration */

/**
 * tquic_stream_update_max_data - Update stream max data (received MAX_STREAM_DATA)
 * @stream: The stream
 * @max_data: New maximum data
 *
 * Return: 0 on success
 */
int tquic_stream_update_max_data(struct tquic_stream *stream, u64 max_data)
{
	if (max_data > stream->max_send_data) {
		stream->max_send_data = max_data;
		stream->blocked = false;
		wake_up_interruptible(&stream->wait);
	}
	return 0;
}
EXPORT_SYMBOL_GPL(tquic_stream_update_max_data);

/**
 * tquic_stream_conn_update_max_data - Update connection max data
 * @mgr: Stream manager
 * @max_data: New maximum data
 *
 * Return: 0 on success
 */
int tquic_stream_conn_update_max_data(struct tquic_stream_manager *mgr,
				      u64 max_data)
{
	spin_lock(&mgr->lock);

	if (max_data > mgr->max_data_remote) {
		mgr->max_data_remote = max_data;
		mgr->data_blocked = false;
	}

	spin_unlock(&mgr->lock);

	return 0;
}
EXPORT_SYMBOL_GPL(tquic_stream_conn_update_max_data);

/**
 * tquic_stream_should_send_blocked - Check if STREAM_DATA_BLOCKED needed
 * @stream: The stream
 *
 * Return: true if blocked frame should be sent
 */
bool tquic_stream_should_send_blocked(struct tquic_stream *stream)
{
	return stream->blocked && stream->send_offset >= stream->max_send_data;
}
EXPORT_SYMBOL_GPL(tquic_stream_should_send_blocked);

/**
 * tquic_stream_advertise_max_data - Calculate MAX_STREAM_DATA to advertise
 * @stream: The stream
 *
 * Return: Max data value to advertise
 */
u64 tquic_stream_advertise_max_data(struct tquic_stream *stream)
{
	/* Advertise when buffer is half consumed */
	u64 consumed = stream->recv_offset;
	u64 window = stream->max_recv_data;

	if (consumed > window / 2)
		return consumed + window;

	return stream->max_recv_data;
}
EXPORT_SYMBOL_GPL(tquic_stream_advertise_max_data);

/* Stream iteration for frame generation */

/**
 * tquic_stream_iter_init - Initialize stream iterator
 * @iter: Iterator to initialize
 * @mgr: Stream manager
 * @min_priority: Minimum priority to consider (0=all)
 */
void tquic_stream_iter_init(struct tquic_stream_iter *iter,
			    struct tquic_stream_manager *mgr,
			    u8 min_priority)
{
	iter->mgr = mgr;
	iter->node = rb_first(&mgr->streams);
	iter->min_priority = min_priority;
}
EXPORT_SYMBOL_GPL(tquic_stream_iter_init);

/**
 * tquic_stream_iter_next - Get next stream with pending data
 * @iter: Iterator
 *
 * Return: Next stream or NULL
 */
struct tquic_stream *tquic_stream_iter_next(struct tquic_stream_iter *iter)
{
	while (iter->node) {
		struct tquic_stream *stream;

		stream = rb_entry(iter->node, struct tquic_stream, node);
		iter->node = rb_next(iter->node);

		/* Skip if below priority threshold */
		if (stream->priority > iter->min_priority)
			continue;

		/* Skip if no data to send */
		if (skb_queue_empty(&stream->send_buf) && !stream->fin_sent)
			continue;

		/* Skip if blocked */
		if (stream->blocked)
			continue;

		return stream;
	}

	return NULL;
}
EXPORT_SYMBOL_GPL(tquic_stream_iter_next);

/**
 * tquic_stream_for_each - Iterate over all streams
 * @mgr: Stream manager
 * @cb: Callback function
 * @ctx: Callback context
 *
 * Return: 0 on success, callback return value on early exit
 */
int tquic_stream_for_each(struct tquic_stream_manager *mgr,
			  int (*cb)(struct tquic_stream *stream, void *ctx),
			  void *ctx)
{
	struct rb_node *node;
	int ret;

	spin_lock(&mgr->lock);

	for (node = rb_first(&mgr->streams); node; node = rb_next(node)) {
		struct tquic_stream *stream;

		stream = rb_entry(node, struct tquic_stream, node);
		ret = cb(stream, ctx);
		if (ret) {
			spin_unlock(&mgr->lock);
			return ret;
		}
	}

	spin_unlock(&mgr->lock);
	return 0;
}
EXPORT_SYMBOL_GPL(tquic_stream_for_each);

/**
 * tquic_stream_get_sendable - Get streams with data ready to send
 * @mgr: Stream manager
 * @streams: Output array
 * @max_streams: Maximum streams to return
 *
 * Return: Number of streams added to array
 */
int tquic_stream_get_sendable(struct tquic_stream_manager *mgr,
			      struct tquic_stream **streams,
			      int max_streams)
{
	struct rb_node *node;
	int count = 0;

	spin_lock(&mgr->lock);

	for (node = rb_first(&mgr->streams);
	     node && count < max_streams;
	     node = rb_next(node)) {
		struct tquic_stream *stream;

		stream = rb_entry(node, struct tquic_stream, node);

		/* Check if stream has data to send */
		if (!skb_queue_empty(&stream->send_buf) && !stream->blocked) {
			streams[count++] = stream;
		}
	}

	spin_unlock(&mgr->lock);
	return count;
}
EXPORT_SYMBOL_GPL(tquic_stream_get_sendable);

/* Splice/sendfile support preparation */

/**
 * tquic_stream_splice_read - Splice data from stream to pipe
 * @mgr: Stream manager
 * @stream: The stream
 * @pipe: Target pipe
 * @len: Maximum bytes to splice
 * @flags: Splice flags
 *
 * Return: Bytes spliced or negative error
 */
ssize_t tquic_stream_splice_read(struct tquic_stream_manager *mgr,
				 struct tquic_stream *stream,
				 struct pipe_inode_info *pipe,
				 size_t len, unsigned int flags)
{
#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 5, 0)
	/* pipe ring API (head/tail/ring_size) was introduced in 5.5 */
	return -EOPNOTSUPP;
#else
	size_t spliced = 0;
	unsigned int head, tail, mask;

	if (!tquic_stream_can_recv(mgr, stream))
		return -EINVAL;

	spin_lock(&mgr->lock);

	while (spliced < len && !skb_queue_empty(&stream->recv_buf)) {
		struct sk_buff *skb;
		struct page *page;
		struct pipe_buffer buf;
		size_t chunk;
		ssize_t ret;

		skb = skb_peek(&stream->recv_buf);
		if (!skb)
			break;

		/* Check if pipe has space */
		head = pipe->head;
		tail = pipe->tail;
		mask = pipe->ring_size - 1;
		if (pipe_full(head, tail, pipe->max_usage))
			break;

		chunk = min_t(size_t, len - spliced, skb->len);

		/* Allocate page and copy data from skb */
		page = alloc_page(GFP_ATOMIC);
		if (!page) {
			if (spliced == 0) {
				spin_unlock(&mgr->lock);
				return -ENOMEM;
			}
			break;
		}

		memcpy(page_address(page), skb->data, chunk);

		/* Set up pipe_buffer for kernel 6.12+ add_to_pipe() */
		buf.page = page;
		buf.offset = 0;
		buf.len = chunk;
		buf.ops = &nosteal_pipe_buf_ops;
		buf.flags = 0;
		buf.private = 0;

		/* Add buffer to pipe */
		ret = add_to_pipe(pipe, &buf);
		if (ret < 0) {
			put_page(page);
			if (spliced == 0) {
				spin_unlock(&mgr->lock);
				return ret;
			}
			break;
		}

		spliced += chunk;

		if (chunk < skb->len) {
			skb_pull(skb, chunk);
		} else {
			skb_unlink(skb, &stream->recv_buf);
			kfree_skb(skb);
		}
	}

	spin_unlock(&mgr->lock);

	return spliced;
#endif /* >= 5.5 */
}
EXPORT_SYMBOL_GPL(tquic_stream_splice_read);

/**
 * tquic_stream_sendfile - Send file data to stream
 * @mgr: Stream manager
 * @stream: The stream
 * @file: Source file
 * @offset: File offset
 * @count: Bytes to send
 *
 * Return: Bytes sent or negative error
 */
ssize_t tquic_stream_sendfile(struct tquic_stream_manager *mgr,
			      struct tquic_stream *stream,
			      struct file *file, loff_t *offset,
			      size_t count)
{
	struct page *pages[16];
	size_t sent = 0;
	ssize_t ret;

	if (!tquic_stream_can_send(mgr, stream))
		return -EINVAL;

	while (sent < count) {
		size_t chunk;
		int nr_pages;
		int i;

		chunk = min_t(size_t, count - sent, 16 * PAGE_SIZE);

		/* Get pages from file */
		nr_pages = (chunk + PAGE_SIZE - 1) / PAGE_SIZE;

		for (i = 0; i < nr_pages; i++) {
			pages[i] = alloc_page(GFP_KERNEL);
			if (!pages[i]) {
				while (--i >= 0)
					put_page(pages[i]);
				return sent > 0 ? sent : -ENOMEM;
			}
		}

		/* Read from file */
		ret = kernel_read(file, page_address(pages[0]), chunk, offset);
		if (ret <= 0) {
			for (i = 0; i < nr_pages; i++)
				put_page(pages[i]);
			return sent > 0 ? sent : (ret ? ret : -EIO);
		}

		/* Write to stream using zero-copy */
		ret = tquic_stream_write_zerocopy(mgr, stream, pages, nr_pages,
						  0, ret, false);

		/* Release page references (stream has its own) */
		for (i = 0; i < nr_pages; i++)
			put_page(pages[i]);

		if (ret < 0)
			return sent > 0 ? sent : ret;

		sent += ret;
	}

	return sent;
}
EXPORT_SYMBOL_GPL(tquic_stream_sendfile);

/* Backpressure handling */

/**
 * tquic_stream_wait_for_space - Wait for send buffer space
 * @stream: The stream
 * @timeo: Timeout
 *
 * Return: 0 on success, -EAGAIN on timeout, -EINTR on signal
 */
int tquic_stream_wait_for_space(struct tquic_stream *stream, long *timeo)
{
	DEFINE_WAIT_FUNC(wait, woken_wake_function);
	int ret = 0;

	add_wait_queue(&stream->wait, &wait);

	while (stream->blocked) {
		if (!*timeo) {
			ret = -EAGAIN;
			break;
		}

		if (signal_pending(current)) {
			ret = -EINTR;
			break;
		}

		*timeo = wait_woken(&wait, TASK_INTERRUPTIBLE, *timeo);
	}

	remove_wait_queue(&stream->wait, &wait);

	return ret;
}
EXPORT_SYMBOL_GPL(tquic_stream_wait_for_space);

/**
 * tquic_stream_wait_for_data - Wait for data to read
 * @stream: The stream
 * @timeo: Timeout
 *
 * Return: 0 on success, -EAGAIN on timeout, -EINTR on signal
 */
int tquic_stream_wait_for_data(struct tquic_stream *stream, long *timeo)
{
	DEFINE_WAIT_FUNC(wait, woken_wake_function);
	int ret = 0;

	add_wait_queue(&stream->wait, &wait);

	while (skb_queue_empty(&stream->recv_buf) && !stream->fin_received) {
		if (!*timeo) {
			ret = -EAGAIN;
			break;
		}

		if (signal_pending(current)) {
			ret = -EINTR;
			break;
		}

		/* Check for reset */
		if (stream->state == TQUIC_STREAM_RESET_RECVD) {
			ret = -ECONNRESET;
			break;
		}

		*timeo = wait_woken(&wait, TASK_INTERRUPTIBLE, *timeo);
	}

	remove_wait_queue(&stream->wait, &wait);

	return ret;
}
EXPORT_SYMBOL_GPL(tquic_stream_wait_for_data);

/* Memory pressure handling */

/**
 * tquic_stream_memory_pressure - Handle memory pressure
 * @mgr: Stream manager
 *
 * This function is called when memory is low to free up resources.
 */
void tquic_stream_memory_pressure(struct tquic_stream_manager *mgr)
{
	struct rb_node *node;
	struct sock *sk = (mgr->conn) ? mgr->conn->sk : NULL;

	spin_lock(&mgr->lock);

	/* Close streams in CLOSED state that haven't been cleaned up */
	for (node = rb_first(&mgr->streams); node; ) {
		struct tquic_stream *stream;
		struct rb_node *next = rb_next(node);
		struct sk_buff *skb;

		stream = rb_entry(node, struct tquic_stream, node);

		if (stream->state == TQUIC_STREAM_CLOSED) {
			tquic_stream_remove(mgr, stream);

			/* Purge with memory accounting */
			while ((skb = skb_dequeue(&stream->send_buf)) != NULL) {
				if (sk) {
					sk_mem_uncharge(sk, skb->truesize);
					/* sk_wmem_alloc handled by skb destructor */
				}
				kfree_skb(skb);
			}
			while ((skb = skb_dequeue(&stream->recv_buf)) != NULL) {
				if (sk) {
					sk_mem_uncharge(sk, skb->truesize);
					atomic_sub(skb->truesize, &sk->sk_rmem_alloc);
				}
				kfree_skb(skb);
			}
			kfree(stream);
		}

		node = next;
	}

	spin_unlock(&mgr->lock);
}
EXPORT_SYMBOL_GPL(tquic_stream_memory_pressure);

/**
 * tquic_stream_get_buffer_usage - Get total buffer usage
 * @mgr: Stream manager
 * @send_bytes: Output send buffer usage
 * @recv_bytes: Output receive buffer usage
 */
void tquic_stream_get_buffer_usage(struct tquic_stream_manager *mgr,
				   u64 *send_bytes, u64 *recv_bytes)
{
	struct rb_node *node;
	u64 send = 0, recv = 0;

	spin_lock(&mgr->lock);

	for (node = rb_first(&mgr->streams); node; node = rb_next(node)) {
		struct tquic_stream *stream;
		struct sk_buff *skb;

		stream = rb_entry(node, struct tquic_stream, node);

		skb_queue_walk(&stream->send_buf, skb)
			send += skb->truesize;

		skb_queue_walk(&stream->recv_buf, skb)
			recv += skb->truesize;
	}

	spin_unlock(&mgr->lock);

	*send_bytes = send;
	*recv_bytes = recv;
}
EXPORT_SYMBOL_GPL(tquic_stream_get_buffer_usage);

/* Stream manager cleanup */

/**
 * tquic_stream_manager_destroy - Destroy stream manager and all streams
 * @mgr: Stream manager to destroy
 */
void tquic_stream_manager_destroy(struct tquic_stream_manager *mgr)
{
	struct rb_node *node;
	struct sock *sk;

	if (!mgr)
		return;

	sk = (mgr->conn) ? mgr->conn->sk : NULL;

	/* Destroy all streams */
	spin_lock(&mgr->lock);

	while ((node = rb_first(&mgr->streams))) {
		struct tquic_stream *stream;
		struct sk_buff *skb;

		stream = rb_entry(node, struct tquic_stream, node);
		rb_erase(node, &mgr->streams);

		/* Purge buffers with memory accounting */
		while ((skb = skb_dequeue(&stream->send_buf)) != NULL) {
			if (sk) {
				sk_mem_uncharge(sk, skb->truesize);
				/* sk_wmem_alloc handled by skb destructor */
			}
			kfree_skb(skb);
		}
		while ((skb = skb_dequeue(&stream->recv_buf)) != NULL) {
			if (sk) {
				sk_mem_uncharge(sk, skb->truesize);
				atomic_sub(skb->truesize, &sk->sk_rmem_alloc);
			}
			kfree_skb(skb);
		}
		wake_up_all(&stream->wait);
		tquic_stream_ext_free(mgr, stream->ext);
		kfree(stream);
	}

	spin_unlock(&mgr->lock);

	/* Destroy caches */
	if (mgr->chunk_cache)
		kmem_cache_destroy(mgr->chunk_cache);
	if (mgr->gap_cache)
		kmem_cache_destroy(mgr->gap_cache);
	if (mgr->stream_cache)
		kmem_cache_destroy(mgr->stream_cache);

	kfree(mgr);
}
EXPORT_SYMBOL_GPL(tquic_stream_manager_destroy);

/* Debugging and statistics */

/**
 * tquic_stream_dump - Dump stream state for debugging
 * @stream: The stream
 */
void tquic_stream_dump(struct tquic_stream *stream)
{
	tquic_info("Stream %llu:\n", stream->id);
	tquic_info("  State: %s\n", tquic_stream_state_name(stream->state));
	tquic_info("  Send offset: %llu, max: %llu\n",
		   stream->send_offset, stream->max_send_data);
	tquic_info("  Recv offset: %llu, max: %llu\n",
		   stream->recv_offset, stream->max_recv_data);
	tquic_info("  Priority: %u, blocked: %d\n",
		   stream->priority, stream->blocked);
	tquic_info("  FIN sent: %d, received: %d\n",
		   stream->fin_sent, stream->fin_received);
	tquic_info("  Send buf: %u skbs, recv buf: %u skbs\n",
		   skb_queue_len(&stream->send_buf),
		   skb_queue_len(&stream->recv_buf));
}
EXPORT_SYMBOL_GPL(tquic_stream_dump);

/**
 * tquic_stream_manager_dump - Dump all streams for debugging
 * @mgr: Stream manager
 */
void tquic_stream_manager_dump(struct tquic_stream_manager *mgr)
{
	struct rb_node *node;

	tquic_info("Stream Manager (%s):\n", mgr->is_server ? "server" : "client");
	tquic_info("  Total streams: %u\n", mgr->stream_count);
	tquic_info("  Bidi local/remote: %u/%u\n", mgr->bidi_local, mgr->bidi_remote);
	tquic_info("  Uni local/remote: %u/%u\n", mgr->uni_local, mgr->uni_remote);
	tquic_info("  Data sent/received: %llu/%llu\n",
		mgr->data_sent, mgr->data_received);

	spin_lock(&mgr->lock);
	for (node = rb_first(&mgr->streams); node; node = rb_next(node)) {
		struct tquic_stream *stream;
		stream = rb_entry(node, struct tquic_stream, node);
		tquic_stream_dump(stream);
	}
	spin_unlock(&mgr->lock);
}
EXPORT_SYMBOL_GPL(tquic_stream_manager_dump);

MODULE_DESCRIPTION("TQUIC Stream Layer");
MODULE_LICENSE("GPL");
MODULE_AUTHOR("Linux Foundation");
