// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * QUIC Stream Priority Scheduler
 *
 * Implements RFC 9218 (Extensible Priorities for HTTP) for QUIC streams.
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
 * Copyright (c) 2024 Linux QUIC Authors
 */

#include <linux/slab.h>
#include <linux/list.h>
#include <net/quic.h>

/*
 * Number of priority levels (urgency 0-7)
 */
#define QUIC_PRIORITY_LEVELS	8

/*
 * Maximum bytes to send from a stream before checking for higher priority
 * streams. This prevents starvation of high-priority streams.
 */
#define QUIC_SCHED_QUANTUM	4096

/**
 * quic_sched_init - Initialize the stream priority scheduler
 * @conn: QUIC connection
 *
 * Initializes the per-urgency queues and scheduler state.
 * Must be called during connection initialization.
 */
void quic_sched_init(struct quic_connection *conn)
{
	int i;

	spin_lock_init(&conn->sched_lock);

	for (i = 0; i < QUIC_PRIORITY_LEVELS; i++) {
		INIT_LIST_HEAD(&conn->sched_queues[i]);
		conn->sched_round_robin[i] = 0;
	}
}
EXPORT_SYMBOL_GPL(quic_sched_init);

/**
 * quic_sched_add_stream - Add a stream to the scheduler
 * @conn: QUIC connection
 * @stream: Stream to add
 *
 * Adds the stream to the appropriate urgency queue based on its priority.
 * The stream must have pending data to send.
 */
void quic_sched_add_stream(struct quic_connection *conn,
			   struct quic_stream *stream)
{
	unsigned long flags;
	u8 urgency;

	if (!stream || !conn)
		return;

	spin_lock_irqsave(&conn->sched_lock, flags);

	/* Don't add if already scheduled */
	if (stream->priority_scheduled) {
		spin_unlock_irqrestore(&conn->sched_lock, flags);
		return;
	}

	urgency = stream->priority_urgency;
	if (urgency >= QUIC_PRIORITY_LEVELS)
		urgency = QUIC_PRIORITY_URGENCY_DEFAULT;

	list_add_tail(&stream->sched_node, &conn->sched_queues[urgency]);
	stream->priority_scheduled = 1;

	/* Take reference while on scheduler queue */
	refcount_inc(&stream->refcnt);

	spin_unlock_irqrestore(&conn->sched_lock, flags);
}
EXPORT_SYMBOL_GPL(quic_sched_add_stream);

/**
 * quic_sched_remove_stream - Remove a stream from the scheduler
 * @conn: QUIC connection
 * @stream: Stream to remove
 *
 * Removes the stream from the scheduler queue.
 * Called when stream is closed or has no more data to send.
 */
void quic_sched_remove_stream(struct quic_connection *conn,
			      struct quic_stream *stream)
{
	unsigned long flags;

	if (!stream || !conn)
		return;

	spin_lock_irqsave(&conn->sched_lock, flags);

	if (!stream->priority_scheduled) {
		spin_unlock_irqrestore(&conn->sched_lock, flags);
		return;
	}

	list_del_init(&stream->sched_node);
	stream->priority_scheduled = 0;

	spin_unlock_irqrestore(&conn->sched_lock, flags);

	/* Release reference taken when added to queue */
	refcount_dec(&stream->refcnt);
}
EXPORT_SYMBOL_GPL(quic_sched_remove_stream);

/**
 * quic_sched_next_stream - Get the next stream to send data from
 * @conn: QUIC connection
 *
 * Returns the highest priority stream that has data to send.
 * The scheduling algorithm respects both urgency levels and
 * incremental flags per RFC 9218.
 *
 * Returns: Stream with highest priority and pending data, or NULL
 *          Caller must release the stream reference when done.
 */
struct quic_stream *quic_sched_next_stream(struct quic_connection *conn)
{
	unsigned long flags;
	struct quic_stream *stream = NULL;
	struct quic_stream *candidate;
	int urgency;

	if (!conn)
		return NULL;

	spin_lock_irqsave(&conn->sched_lock, flags);

	/*
	 * Scan urgency levels from highest (0) to lowest (7).
	 * Return first stream with pending data.
	 */
	for (urgency = 0; urgency < QUIC_PRIORITY_LEVELS; urgency++) {
		if (list_empty(&conn->sched_queues[urgency]))
			continue;

		/*
		 * For incremental streams, use round-robin within urgency.
		 * For non-incremental, always pick the first one.
		 */
		list_for_each_entry(candidate, &conn->sched_queues[urgency],
				    sched_node) {
			/* Check if stream has data to send */
			if (candidate->send.pending_bytes > 0 &&
			    candidate->state == QUIC_STREAM_STATE_OPEN) {
				stream = candidate;

				/*
				 * For incremental streams, move to end of queue
				 * to implement fair round-robin scheduling.
				 */
				if (stream->priority_incremental) {
					list_move_tail(&stream->sched_node,
						       &conn->sched_queues[urgency]);
				}

				/* Take reference for caller */
				refcount_inc(&stream->refcnt);
				goto found;
			}
		}
	}

found:
	spin_unlock_irqrestore(&conn->sched_lock, flags);
	return stream;
}
EXPORT_SYMBOL_GPL(quic_sched_next_stream);

/**
 * quic_stream_set_priority - Set stream priority
 * @stream: Stream to update
 * @urgency: Urgency level (0-7, 0 = most urgent)
 * @incremental: Whether stream can be interleaved
 *
 * Updates the stream's priority. If the stream is already scheduled,
 * it will be moved to the appropriate queue.
 *
 * Returns: 0 on success, negative error code on failure
 */
int quic_stream_set_priority(struct quic_stream *stream, u8 urgency,
			     bool incremental)
{
	struct quic_connection *conn;
	unsigned long flags;
	u8 old_urgency;
	bool was_scheduled;

	if (!stream)
		return -EINVAL;

	if (urgency > QUIC_PRIORITY_URGENCY_MAX)
		return -EINVAL;

	conn = stream->conn;
	if (!conn)
		return -ENOTCONN;

	spin_lock_irqsave(&conn->sched_lock, flags);

	old_urgency = stream->priority_urgency;
	was_scheduled = stream->priority_scheduled;

	/* Update priority fields */
	stream->priority_urgency = urgency;
	stream->priority_incremental = incremental ? 1 : 0;

	/*
	 * If stream was scheduled and urgency changed, move to new queue.
	 * No need to move if only incremental flag changed.
	 */
	if (was_scheduled && old_urgency != urgency) {
		list_del(&stream->sched_node);
		list_add_tail(&stream->sched_node, &conn->sched_queues[urgency]);
	}

	spin_unlock_irqrestore(&conn->sched_lock, flags);

	return 0;
}
EXPORT_SYMBOL_GPL(quic_stream_set_priority);

/**
 * quic_stream_get_priority - Get stream priority
 * @stream: Stream to query
 * @urgency: Output for urgency level
 * @incremental: Output for incremental flag
 *
 * Retrieves the current priority settings for a stream.
 */
void quic_stream_get_priority(struct quic_stream *stream, u8 *urgency,
			      bool *incremental)
{
	if (!stream) {
		if (urgency)
			*urgency = QUIC_PRIORITY_URGENCY_DEFAULT;
		if (incremental)
			*incremental = false;
		return;
	}

	if (urgency)
		*urgency = stream->priority_urgency;
	if (incremental)
		*incremental = stream->priority_incremental;
}
EXPORT_SYMBOL_GPL(quic_stream_get_priority);

/**
 * quic_stream_priority_update - Handle PRIORITY_UPDATE for a stream
 * @conn: QUIC connection
 * @stream_id: ID of stream to update
 * @urgency: New urgency level
 * @incremental: New incremental flag
 *
 * Called when receiving a PRIORITY_UPDATE frame from the peer.
 *
 * Returns: 0 on success, negative error code on failure
 */
int quic_stream_priority_update(struct quic_connection *conn, u64 stream_id,
				u8 urgency, bool incremental)
{
	struct quic_stream *stream;
	int err;

	if (!conn)
		return -EINVAL;

	stream = quic_stream_lookup(conn, stream_id);
	if (!stream)
		return -ENOENT;

	err = quic_stream_set_priority(stream, urgency, incremental);

	/* Release lookup reference */
	refcount_dec(&stream->refcnt);

	return err;
}
EXPORT_SYMBOL_GPL(quic_stream_priority_update);

/**
 * quic_frame_build_priority_update - Build PRIORITY_UPDATE frame
 * @conn: QUIC connection
 * @stream: Stream to send priority update for
 *
 * Builds a PRIORITY_UPDATE frame (RFC 9218) for the given stream.
 * The frame is queued for transmission.
 *
 * Returns: 0 on success, negative error code on failure
 */
int quic_frame_build_priority_update(struct quic_connection *conn,
				     struct quic_stream *stream)
{
	struct sk_buff *skb;
	u8 *p;
	u8 priority_field[32];
	int pf_len;

	if (!conn || !stream)
		return -EINVAL;

	/*
	 * Build Priority Field Value per RFC 9218 Section 4:
	 * u=<urgency>, i[=?<incremental>]
	 *
	 * Example: "u=3, i" for urgency 3, incremental
	 * Example: "u=0" for urgency 0, non-incremental (i is omitted)
	 */
	if (stream->priority_incremental) {
		pf_len = snprintf(priority_field, sizeof(priority_field),
				  "u=%u, i", stream->priority_urgency);
	} else {
		pf_len = snprintf(priority_field, sizeof(priority_field),
				  "u=%u", stream->priority_urgency);
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
	p[0] = 0x80 | ((QUIC_FRAME_PRIORITY_UPDATE_REQUEST >> 24) & 0x3f);
	p[1] = (QUIC_FRAME_PRIORITY_UPDATE_REQUEST >> 16) & 0xff;
	p[2] = (QUIC_FRAME_PRIORITY_UPDATE_REQUEST >> 8) & 0xff;
	p[3] = QUIC_FRAME_PRIORITY_UPDATE_REQUEST & 0xff;

	/* Stream ID (varint) */
	p = skb_put(skb, quic_varint_len(stream->id));
	quic_varint_encode(stream->id, p);

	/* Priority Field Value (raw bytes, no length prefix in HTTP/3 frame) */
	p = skb_put(skb, pf_len);
	memcpy(p, priority_field, pf_len);

	/* Queue the frame for transmission */
	if (quic_conn_queue_frame(conn, skb))
		return -ENOBUFS;

	return 0;
}
EXPORT_SYMBOL_GPL(quic_frame_build_priority_update);

/**
 * quic_frame_process_priority_update - Process received PRIORITY_UPDATE frame
 * @conn: QUIC connection
 * @data: Frame data (starting after frame type)
 * @len: Length of frame data
 *
 * Parses and applies a PRIORITY_UPDATE frame received from the peer.
 *
 * Returns: Number of bytes consumed, or negative error code
 */
int quic_frame_process_priority_update(struct quic_connection *conn,
				       const u8 *data, int len)
{
	u64 stream_id;
	int offset = 0;
	int varint_len;
	u8 urgency = QUIC_PRIORITY_URGENCY_DEFAULT;
	bool incremental = false;
	const u8 *pf_start;
	int pf_len;
	int i;

	if (!conn || !data || len < 1)
		return -EINVAL;

	/* Parse Stream ID */
	varint_len = quic_varint_decode(data + offset, len - offset, &stream_id);
	if (varint_len < 0)
		return varint_len;
	offset += varint_len;

	/* Remaining bytes are the Priority Field Value */
	pf_start = data + offset;
	pf_len = len - offset;

	/*
	 * Parse Priority Field Value (RFC 9218 Section 4)
	 * Format: u=<urgency>, i[=?<incremental>]
	 *
	 * Simple parsing - look for u= and i tokens
	 */
	for (i = 0; i < pf_len - 2; i++) {
		if (pf_start[i] == 'u' && pf_start[i + 1] == '=') {
			/* Parse urgency value */
			if (i + 2 < pf_len && pf_start[i + 2] >= '0' &&
			    pf_start[i + 2] <= '7') {
				urgency = pf_start[i + 2] - '0';
			}
		} else if (pf_start[i] == 'i') {
			/* Incremental flag present */
			incremental = true;
		}
	}

	/* Apply the priority update */
	quic_stream_priority_update(conn, stream_id, urgency, incremental);

	return len;  /* Consumed entire frame */
}
EXPORT_SYMBOL_GPL(quic_frame_process_priority_update);

/**
 * quic_stream_init_priority - Initialize stream priority to defaults
 * @stream: Stream to initialize
 *
 * Sets stream priority to RFC 9218 defaults:
 * - Urgency: 3 (middle priority)
 * - Incremental: false
 */
void quic_stream_init_priority(struct quic_stream *stream)
{
	if (!stream)
		return;

	stream->priority_urgency = QUIC_PRIORITY_URGENCY_DEFAULT;
	stream->priority_incremental = 0;
	stream->priority_scheduled = 0;
	INIT_LIST_HEAD(&stream->sched_node);
}
EXPORT_SYMBOL_GPL(quic_stream_init_priority);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("QUIC Stream Priority Scheduler (RFC 9218)");
MODULE_AUTHOR("Linux QUIC Authors");
