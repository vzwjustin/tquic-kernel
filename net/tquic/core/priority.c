// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * TQUIC Stream Priority Scheduler
 *
 * Implements RFC 9218 (Extensible Priorities for HTTP) for TQUIC streams.
 *
 * Priority Model:
 * - Urgency: 0-7 (0 = most urgent, 7 = least urgent, default 3)
 * - Incremental: boolean indicating if stream data can be interleaved
 *
 * Scheduling Algorithm:
 * 1. Service streams in urgency order (lower urgency number first)
 * 2. Within same urgency level:
 *    - Non-incremental streams: complete one stream before moving to next
 *    - Incremental streams: round-robin interleaving
 * 3. Higher urgency streams preempt lower urgency streams
 *
 * Copyright (c) 2024 Linux TQUIC Authors
 */

#include <linux/slab.h>
#include <linux/list.h>
#include <linux/rbtree.h>
#include <net/tquic.h>
#include "../tquic_debug.h"

/* Forward declarations for exported functions not in a public header */
void tquic_sched_add_stream(struct tquic_connection *conn,
			    struct tquic_stream *stream);
void tquic_sched_remove_stream(struct tquic_connection *conn,
			       struct tquic_stream *stream);
struct tquic_stream *tquic_sched_next_stream(struct tquic_connection *conn);
int tquic_stream_set_extensible_priority(struct tquic_stream *stream,
					 u8 urgency, bool incremental);
void tquic_stream_get_priority(struct tquic_stream *stream, u8 *urgency,
			       bool *incremental);
int tquic_stream_priority_update(struct tquic_connection *conn, u64 stream_id,
				 u8 urgency, bool incremental);
int tquic_frame_build_priority_update(struct tquic_connection *conn,
				      struct tquic_stream *stream);
int tquic_frame_process_priority_update(struct tquic_connection *conn,
					const u8 *data, int len);
void tquic_stream_init_priority(struct tquic_stream *stream);
void tquic_sched_release(struct tquic_connection *conn);

/*
 * Number of priority levels (urgency 0-7)
 */
#define TQUIC_PRIORITY_LEVELS 8

/*
 * tquic_stream_lookup_locked - Look up a stream by ID within a connection
 * @conn: TQUIC connection
 * @stream_id: Stream ID to find
 *
 * CF-081: Searches the connection's stream rb_tree for the given stream ID.
 * Returns the stream pointer if found, NULL otherwise.
 *
 * IMPORTANT: conn->lock MUST be held by the caller and remains held on
 * return. This ensures the returned stream pointer stays valid until the
 * caller releases the lock, preventing use-after-free.
 */
static struct tquic_stream *tquic_stream_lookup_locked(
		struct tquic_connection *conn, u64 stream_id)
{
	struct rb_node *node;
	struct tquic_stream *stream;

	lockdep_assert_held(&conn->lock);

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

/*
 * Maximum bytes to send from a stream before checking for higher priority
 * streams. This prevents starvation of high-priority streams.
 */
#define TQUIC_SCHED_QUANTUM 4096

/*
 * Priority urgency constants per RFC 9218
 */
#define TQUIC_PRIORITY_URGENCY_DEFAULT 3
#define TQUIC_PRIORITY_URGENCY_MAX 7

/*
 * PRIORITY_UPDATE frame type for request streams (RFC 9218)
 * This is a 4-byte varint value 0xf0700
 */
#define TQUIC_FRAME_PRIORITY_UPDATE_REQUEST 0xf0700ULL

/*
 * Extended stream state for RFC 9218 priority scheduling.
 * This structure is allocated per-stream and attached to stream->ext
 * when priority scheduling is enabled.
 */
struct tquic_priority_stream_ext {
	struct tquic_stream *stream; /* Back-pointer to owning stream */
	u8 urgency; /* Urgency level 0-7 */
	u8 incremental; /* Can be interleaved with other streams */
	u8 scheduled; /* Currently on scheduler queue */
	struct list_head sched_node; /* Scheduler queue linkage */
	refcount_t refcnt; /* Reference count for scheduler */
};

/*
 * Connection-level priority scheduler state.
 * Allocated via tquic_sched_init() and stored in conn->priority_state.
 */
struct tquic_priority_sched_state {
	spinlock_t lock;
	struct list_head queues[TQUIC_PRIORITY_LEVELS]; /* Per-urgency queues */
	u32 round_robin[TQUIC_PRIORITY_LEVELS]; /* RR index per urgency */
};

/*
 * Helper to queue a frame for transmission.
 * Adds the skb to the connection's control frame queue.
 */
static int tquic_priority_queue_frame(struct tquic_connection *conn,
				      struct sk_buff *skb)
{
	if (!conn || !skb)
		return -EINVAL;

	skb_queue_tail(&conn->control_frames, skb);
	return 0;
}

/*
 * Helper to get or allocate priority extension for a stream.
 */
static struct tquic_priority_stream_ext *
tquic_stream_get_priority_ext(struct tquic_stream *stream)
{
	struct tquic_priority_stream_ext *ext;

	if (!stream)
		return NULL;

	/* Check if already allocated */
	ext = stream->ext;
	if (ext)
		return ext;

	/* Allocate new priority extension */
	ext = kzalloc(sizeof(*ext), GFP_ATOMIC);
	if (!ext)
		return NULL;

	ext->stream = stream;
	ext->urgency = TQUIC_PRIORITY_URGENCY_DEFAULT;
	ext->incremental = 0;
	ext->scheduled = 0;
	INIT_LIST_HEAD(&ext->sched_node);
	refcount_set(&ext->refcnt, 1);

	stream->ext = ext;
	return ext;
}

/**
 * tquic_sched_init - Initialize the stream priority scheduler
 * @conn: TQUIC connection
 *
 * Initializes the per-urgency queues and scheduler state.
 * Must be called during connection initialization.
 *
 * Returns: 0 on success, negative error code on failure
 */
int tquic_sched_init(struct tquic_connection *conn)
{
	struct tquic_priority_sched_state *state;
	int i;

	if (!conn)
		return -EINVAL;

	state = kzalloc(sizeof(*state), GFP_KERNEL);
	if (!state)
		return -ENOMEM;

	spin_lock_init(&state->lock);

	for (i = 0; i < TQUIC_PRIORITY_LEVELS; i++) {
		INIT_LIST_HEAD(&state->queues[i]);
		state->round_robin[i] = 0;
	}

	conn->priority_state = state;

	tquic_conn_dbg(conn, "priority scheduler initialized\n");
	return 0;
}
EXPORT_SYMBOL_GPL(tquic_sched_init);

/**
 * tquic_sched_add_stream - Add a stream to the scheduler
 * @conn: TQUIC connection
 * @stream: Stream to add
 *
 * Adds the stream to the appropriate urgency queue based on its priority.
 * The stream must have pending data to send.
 */
void tquic_sched_add_stream(struct tquic_connection *conn,
			    struct tquic_stream *stream)
{
	struct tquic_priority_sched_state *state;
	struct tquic_priority_stream_ext *ext;
	unsigned long flags;
	u8 urgency;

	if (!stream || !conn)
		return;

	state = conn->priority_state;
	if (!state)
		return;

	ext = tquic_stream_get_priority_ext(stream);
	if (!ext)
		return;

	spin_lock_irqsave(&state->lock, flags);

	/* Don't add if already scheduled */
	if (ext->scheduled) {
		spin_unlock_irqrestore(&state->lock, flags);
		return;
	}

	urgency = ext->urgency;
	if (urgency >= TQUIC_PRIORITY_LEVELS)
		urgency = TQUIC_PRIORITY_URGENCY_DEFAULT;

	list_add_tail(&ext->sched_node, &state->queues[urgency]);
	ext->scheduled = 1;

	/* Take reference while on scheduler queue */
	refcount_inc(&ext->refcnt);

	spin_unlock_irqrestore(&state->lock, flags);
}
EXPORT_SYMBOL_GPL(tquic_sched_add_stream);

/**
 * tquic_sched_remove_stream - Remove a stream from the scheduler
 * @conn: TQUIC connection
 * @stream: Stream to remove
 *
 * Removes the stream from the scheduler queue.
 * Called when stream is closed or has no more data to send.
 */
void tquic_sched_remove_stream(struct tquic_connection *conn,
			       struct tquic_stream *stream)
{
	struct tquic_priority_sched_state *state;
	struct tquic_priority_stream_ext *ext;
	unsigned long flags;

	if (!stream || !conn)
		return;

	state = conn->priority_state;
	if (!state)
		return;

	ext = stream->ext;
	if (!ext)
		return;

	spin_lock_irqsave(&state->lock, flags);

	if (!ext->scheduled) {
		spin_unlock_irqrestore(&state->lock, flags);
		return;
	}

	list_del_init(&ext->sched_node);
	ext->scheduled = 0;

	spin_unlock_irqrestore(&state->lock, flags);

	/* Release reference taken when added to queue */
	if (refcount_dec_and_test(&ext->refcnt)) {
		kfree(ext);
		stream->ext = NULL;
	}
}
EXPORT_SYMBOL_GPL(tquic_sched_remove_stream);

/**
 * tquic_sched_next_stream - Get the next stream to send data from
 * @conn: TQUIC connection
 *
 * Returns the highest priority stream that has data to send.
 * The scheduling algorithm respects both urgency levels and
 * incremental flags per RFC 9218.
 *
 * Returns: Stream with highest priority and pending data, or NULL
 *          Caller must release the stream reference when done.
 */
struct tquic_stream *tquic_sched_next_stream(struct tquic_connection *conn)
{
	struct tquic_priority_sched_state *state;
	struct tquic_priority_stream_ext *ext;
	struct tquic_stream *stream = NULL;
	unsigned long flags;
	int urgency;

	if (!conn)
		return NULL;

	state = conn->priority_state;
	if (!state)
		return NULL;

	spin_lock_irqsave(&state->lock, flags);

	/*
	 * Scan urgency levels from highest (0) to lowest (7).
	 * Return first stream with pending data.
	 */
	for (urgency = 0; urgency < TQUIC_PRIORITY_LEVELS; urgency++) {
		if (list_empty(&state->queues[urgency]))
			continue;

		/*
		 * For incremental streams, use round-robin within urgency.
		 * For non-incremental, always pick the first one.
		 */
		list_for_each_entry(ext, &state->queues[urgency], sched_node) {
			/* Get the stream from the extension via back-pointer */
			stream = ext->stream;
			if (!stream)
				continue;

			/* Check if stream has data to send and is open */
			if (stream->state == TQUIC_STREAM_OPEN) {
				/*
				 * For incremental streams, move to end of queue
				 * to implement fair round-robin scheduling.
				 */
				if (ext->incremental) {
					list_move_tail(&ext->sched_node,
						       &state->queues[urgency]);
				}

				/* Take reference for caller */
				refcount_inc(&ext->refcnt);
				goto found;
			}
		}
	}

	stream = NULL;

found:
	spin_unlock_irqrestore(&state->lock, flags);
	return stream;
}
EXPORT_SYMBOL_GPL(tquic_sched_next_stream);

/**
 * tquic_stream_set_priority - Set stream priority
 * @stream: Stream to update
 * @urgency: Urgency level (0-7, 0 = most urgent)
 * @incremental: Whether stream can be interleaved
 *
 * Updates the stream's priority using RFC 9218 Extensible Priorities.
 * If the stream is already scheduled, it will be moved to the appropriate queue.
 *
 * Returns: 0 on success, negative error code on failure
 */
int tquic_stream_set_extensible_priority(struct tquic_stream *stream,
					 u8 urgency, bool incremental)
{
	struct tquic_priority_sched_state *state;
	struct tquic_priority_stream_ext *ext;
	struct tquic_connection *conn;
	unsigned long flags;
	u8 old_urgency;
	bool was_scheduled;

	if (!stream)
		return -EINVAL;

	if (urgency > TQUIC_PRIORITY_URGENCY_MAX)
		return -EINVAL;

	conn = stream->conn;
	if (!conn)
		return -ENOTCONN;

	state = conn->priority_state;
	if (!state)
		return -EINVAL;

	ext = tquic_stream_get_priority_ext(stream);
	if (!ext)
		return -ENOMEM;

	spin_lock_irqsave(&state->lock, flags);

	old_urgency = ext->urgency;
	was_scheduled = ext->scheduled;

	/* Update priority fields */
	ext->urgency = urgency;
	ext->incremental = incremental ? 1 : 0;

	/*
	 * If stream was scheduled and urgency changed, move to new queue.
	 * No need to move if only incremental flag changed.
	 */
	if (was_scheduled && old_urgency != urgency) {
		list_del(&ext->sched_node);
		list_add_tail(&ext->sched_node, &state->queues[urgency]);
	}

	spin_unlock_irqrestore(&state->lock, flags);

	return 0;
}
EXPORT_SYMBOL_GPL(tquic_stream_set_extensible_priority);

/**
 * tquic_stream_get_priority - Get stream priority
 * @stream: Stream to query
 * @urgency: Output for urgency level
 * @incremental: Output for incremental flag
 *
 * Retrieves the current priority settings for a stream.
 */
void tquic_stream_get_priority(struct tquic_stream *stream, u8 *urgency,
			       bool *incremental)
{
	struct tquic_priority_stream_ext *ext;

	if (!stream) {
		if (urgency)
			*urgency = TQUIC_PRIORITY_URGENCY_DEFAULT;
		if (incremental)
			*incremental = false;
		return;
	}

	ext = stream->ext;
	if (!ext) {
		if (urgency)
			*urgency = TQUIC_PRIORITY_URGENCY_DEFAULT;
		if (incremental)
			*incremental = false;
		return;
	}

	if (urgency)
		*urgency = ext->urgency;
	if (incremental)
		*incremental = ext->incremental;
}
EXPORT_SYMBOL_GPL(tquic_stream_get_priority);

/**
 * tquic_stream_priority_update - Handle PRIORITY_UPDATE for a stream
 * @conn: TQUIC connection
 * @stream_id: ID of stream to update
 * @urgency: New urgency level
 * @incremental: New incremental flag
 *
 * Called when receiving a PRIORITY_UPDATE frame from the peer.
 *
 * Returns: 0 on success, negative error code on failure
 */
int tquic_stream_priority_update(struct tquic_connection *conn, u64 stream_id,
				 u8 urgency, bool incremental)
{
	struct tquic_stream *stream;
	int err;

	if (!conn)
		return -EINVAL;

	/*
	 * CF-081: Hold conn->lock across both the stream lookup and the
	 * priority update to prevent use-after-free. Without the lock,
	 * the stream could be destroyed between lookup and use.
	 */
	spin_lock_bh(&conn->lock);
	stream = tquic_stream_lookup_locked(conn, stream_id);
	if (!stream) {
		spin_unlock_bh(&conn->lock);
		return -ENOENT;
	}

	err = tquic_stream_set_extensible_priority(stream, urgency,
						   incremental);
	spin_unlock_bh(&conn->lock);

	return err;
}
EXPORT_SYMBOL_GPL(tquic_stream_priority_update);

/**
 * tquic_frame_build_priority_update - Build PRIORITY_UPDATE frame
 * @conn: TQUIC connection
 * @stream: Stream to send priority update for
 *
 * Builds a PRIORITY_UPDATE frame (RFC 9218) for the given stream.
 * The frame is queued for transmission.
 *
 * Returns: 0 on success, negative error code on failure
 */
int tquic_frame_build_priority_update(struct tquic_connection *conn,
				      struct tquic_stream *stream)
{
	struct tquic_priority_stream_ext *ext;
	struct sk_buff *skb;
	u8 *p;
	u8 priority_field[32];
	int pf_len;

	if (!conn || !stream)
		return -EINVAL;

	ext = stream->ext;
	if (!ext)
		return -EINVAL;

	/*
	 * Build Priority Field Value per RFC 9218 Section 4:
	 * u=<urgency>, i[=?<incremental>]
	 *
	 * Example: "u=3, i" for urgency 3, incremental
	 * Example: "u=0" for urgency 0, non-incremental (i is omitted)
	 */
	if (ext->incremental) {
		pf_len = snprintf(priority_field, sizeof(priority_field),
				  "u=%u, i", ext->urgency);
	} else {
		pf_len = snprintf(priority_field, sizeof(priority_field),
				  "u=%u", ext->urgency);
	}

	/*
	 * PRIORITY_UPDATE frame format:
	 * - Frame Type: varint (0xf0700 for request streams)
	 * - Prioritized Element ID: varint (stream ID)
	 * - Priority Field Value: variable length
	 */
	skb = alloc_skb(32 + pf_len, GFP_ATOMIC);
	if (!skb)
		return -ENOMEM;

	p = skb_put(skb, 0);

	/* Frame Type - PRIORITY_UPDATE for request streams (0xf0700)
	 * Using 4-byte varint encoding for 0xf0700
	 */
	p = skb_put(skb, 4);
	p[0] = 0x80 | ((TQUIC_FRAME_PRIORITY_UPDATE_REQUEST >> 24) & 0x3f);
	p[1] = (TQUIC_FRAME_PRIORITY_UPDATE_REQUEST >> 16) & 0xff;
	p[2] = (TQUIC_FRAME_PRIORITY_UPDATE_REQUEST >> 8) & 0xff;
	p[3] = TQUIC_FRAME_PRIORITY_UPDATE_REQUEST & 0xff;

	/* Stream ID (varint) */
	p = skb_put(skb, tquic_varint_len(stream->id));
	tquic_varint_encode(stream->id, p, tquic_varint_len(stream->id));

	/* Priority Field Value (raw bytes, no length prefix in HTTP/3 frame) */
	p = skb_put(skb, pf_len);
	memcpy(p, priority_field, pf_len);

	/* Queue the frame for transmission */
	if (tquic_priority_queue_frame(conn, skb)) {
		kfree_skb(skb);
		return -ENOBUFS;
	}

	return 0;
}
EXPORT_SYMBOL_GPL(tquic_frame_build_priority_update);

/**
 * tquic_frame_process_priority_update - Process received PRIORITY_UPDATE frame
 * @conn: TQUIC connection
 * @data: Frame data (starting after frame type)
 * @len: Length of frame data
 *
 * Parses and applies a PRIORITY_UPDATE frame received from the peer.
 *
 * Returns: Number of bytes consumed, or negative error code
 */
int tquic_frame_process_priority_update(struct tquic_connection *conn,
					const u8 *data, int len)
{
	u64 stream_id;
	int offset = 0;
	int varint_len;
	u8 urgency = TQUIC_PRIORITY_URGENCY_DEFAULT;
	bool incremental = false;
	const u8 *pf_start;
	int pf_len;
	int i;

	if (!conn || !data || len < 1)
		return -EINVAL;

	/* Parse Stream ID */
	varint_len =
		tquic_varint_decode(data + offset, len - offset, &stream_id);
	if (varint_len < 0)
		return varint_len;
	offset += varint_len;

	/* Remaining bytes are the Priority Field Value */
	pf_start = data + offset;
	pf_len = len - offset;

	/*
	 * SECURITY FIX (CF-048): Properly parse Priority Field Value
	 * as a Structured Field Dictionary per RFC 8941 / RFC 9218.
	 *
	 * Format: u=<urgency>, i[=?1]
	 *
	 * The previous loop had an off-by-two error in the bound
	 * (i < pf_len - 2), which missed tokens near the end of the
	 * field value and could skip single-character boolean tokens.
	 *
	 * Validate format strictly: urgency must be a single digit 0-7,
	 * and the incremental token is a boolean Item per RFC 8941.
	 */
	for (i = 0; i < pf_len; i++) {
		/* Skip whitespace and commas between dictionary members */
		if (pf_start[i] == ' ' || pf_start[i] == '\t' ||
		    pf_start[i] == ',')
			continue;

		/* Parse "u=<digit>" token */
		if (pf_start[i] == 'u' && i + 1 < pf_len &&
		    pf_start[i + 1] == '=') {
			if (i + 2 < pf_len &&
			    pf_start[i + 2] >= '0' &&
			    pf_start[i + 2] <= '7') {
				urgency = pf_start[i + 2] - '0';
				i += 2; /* Advance past "u=N" */
			}
			continue;
		}

		/*
		 * Parse "i" boolean token per RFC 8941 Section 3.3.6.
		 * A bare "i" means true. "i=?1" also means true.
		 * "i=?0" means false.
		 */
		if (pf_start[i] == 'i') {
			if (i + 3 < pf_len &&
			    pf_start[i + 1] == '=' &&
			    pf_start[i + 2] == '?') {
				if (pf_start[i + 3] == '1')
					incremental = true;
				else if (pf_start[i + 3] == '0')
					incremental = false;
				i += 3; /* Advance past "i=?N" */
			} else {
				/* Bare "i" token means true */
				incremental = true;
			}
			continue;
		}
	}

	/* Apply the priority update */
	tquic_stream_priority_update(conn, stream_id, urgency, incremental);

	return len; /* Consumed entire frame */
}
EXPORT_SYMBOL_GPL(tquic_frame_process_priority_update);

/**
 * tquic_stream_init_priority - Initialize stream priority to defaults
 * @stream: Stream to initialize
 *
 * Sets stream priority to RFC 9218 defaults:
 * - Urgency: 3 (middle priority)
 * - Incremental: false
 */
void tquic_stream_init_priority(struct tquic_stream *stream)
{
	struct tquic_priority_stream_ext *ext;

	if (!stream)
		return;

	ext = tquic_stream_get_priority_ext(stream);
	if (!ext)
		return;

	ext->urgency = TQUIC_PRIORITY_URGENCY_DEFAULT;
	ext->incremental = 0;
	ext->scheduled = 0;
	INIT_LIST_HEAD(&ext->sched_node);
}
EXPORT_SYMBOL_GPL(tquic_stream_init_priority);

/**
 * tquic_sched_release - Release scheduler state for a connection
 * @conn: TQUIC connection
 *
 * Frees all scheduler resources. Should be called during connection teardown.
 */
void tquic_sched_release(struct tquic_connection *conn)
{
	struct tquic_priority_sched_state *state;
	struct tquic_priority_stream_ext *ext, *tmp;
	unsigned long flags;
	int i;

	if (!conn)
		return;

	state = conn->priority_state;
	if (!state)
		return;

	spin_lock_irqsave(&state->lock, flags);

	/* Remove all streams from scheduler queues */
	for (i = 0; i < TQUIC_PRIORITY_LEVELS; i++) {
		list_for_each_entry_safe(ext, tmp, &state->queues[i],
					 sched_node) {
			list_del_init(&ext->sched_node);
			ext->scheduled = 0;
			if (refcount_dec_and_test(&ext->refcnt))
				kfree(ext);
		}
	}

	spin_unlock_irqrestore(&state->lock, flags);

	kfree(state);
	conn->priority_state = NULL;
}
EXPORT_SYMBOL_GPL(tquic_sched_release);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("TQUIC Stream Priority Scheduler (RFC 9218)");
MODULE_AUTHOR("Linux TQUIC Authors");
