// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * QUIC - Quick UDP Internet Connections
 *
 * Flow Control Implementation per RFC 9000 Section 4
 *
 * Copyright (c) 2024 Linux QUIC Authors
 *
 * This file implements QUIC flow control mechanisms including:
 * - Connection-level flow control (MAX_DATA frames)
 * - Stream-level flow control (MAX_STREAM_DATA frames)
 * - Stream limit management (MAX_STREAMS frames)
 * - Blocked notification handling (DATA_BLOCKED, STREAM_DATA_BLOCKED,
 *   STREAMS_BLOCKED frames)
 */

#include <linux/slab.h>
#include <linux/skbuff.h>
#include <linux/spinlock.h>
#include <net/quic.h>

/*
 * RFC 9000 Section 4 - Flow Control
 *
 * QUIC implements flow control similar to HTTP/2, with both connection-level
 * and stream-level flow control. The receiver advertises the maximum amount
 * of data it is willing to receive using MAX_DATA and MAX_STREAM_DATA frames.
 * The sender must not send more data than the receiver has advertised.
 */

/* Default flow control window sizes */
#define QUIC_DEFAULT_MAX_DATA			(16 * 1024 * 1024)	/* 16 MB */
#define QUIC_DEFAULT_MAX_STREAM_DATA		(1 * 1024 * 1024)	/* 1 MB */
#define QUIC_DEFAULT_MAX_STREAMS		256

/* Flow control auto-tuning parameters */
#define QUIC_FC_WINDOW_UPDATE_THRESHOLD		2	/* Update at 1/2 window */
#define QUIC_FC_MIN_WINDOW			(64 * 1024)	/* 64 KB */
#define QUIC_FC_MAX_WINDOW			(64 * 1024 * 1024)	/* 64 MB */
#define QUIC_FC_AUTOTUNE_MULTIPLIER		2	/* Double window on autotune */

/* Forward declarations for internal functions */
static struct sk_buff *quic_flow_create_max_data_frame(struct quic_connection *conn,
						       u64 max_data);
static struct sk_buff *quic_flow_create_max_stream_data_frame(u64 stream_id,
							      u64 max_stream_data);
static struct sk_buff *quic_flow_create_max_streams_frame(u64 max_streams,
							  bool unidirectional);
static struct sk_buff *quic_flow_create_data_blocked_frame(u64 limit);
static struct sk_buff *quic_flow_create_stream_data_blocked_frame(u64 stream_id,
								  u64 limit);
static struct sk_buff *quic_flow_create_streams_blocked_frame(u64 limit,
							      bool unidirectional);

/*
 * Connection-level Flow Control Functions
 */

/**
 * quic_flow_control_init - Initialize flow control state for a connection
 * @conn: QUIC connection
 *
 * Initializes both local and remote flow control state based on transport
 * parameters. Called during connection setup.
 */
void quic_flow_control_init(struct quic_connection *conn)
{
	struct quic_flow_control *local = &conn->local_fc;
	struct quic_flow_control *remote = &conn->remote_fc;

	/* Initialize local flow control (what we advertise to peer) */
	local->max_data = conn->local_params.initial_max_data;
	local->max_data_next = local->max_data;
	local->data_sent = 0;
	local->data_received = 0;
	local->max_streams_bidi = conn->local_params.initial_max_streams_bidi;
	local->max_streams_uni = conn->local_params.initial_max_streams_uni;
	local->streams_opened_bidi = 0;
	local->streams_opened_uni = 0;
	local->blocked = 0;
	local->blocked_at = 0;

	/* Initialize remote flow control (limits from peer) */
	remote->max_data = conn->remote_params.initial_max_data;
	remote->max_data_next = remote->max_data;
	remote->data_sent = 0;
	remote->data_received = 0;
	remote->max_streams_bidi = conn->remote_params.initial_max_streams_bidi;
	remote->max_streams_uni = conn->remote_params.initial_max_streams_uni;
	remote->streams_opened_bidi = 0;
	remote->streams_opened_uni = 0;
	remote->blocked = 0;
	remote->blocked_at = 0;
}

/**
 * quic_flow_control_can_send - Check if connection-level flow control allows sending
 * @conn: QUIC connection
 * @bytes: Number of bytes to send
 *
 * RFC 9000 Section 4.1: A sender MUST NOT send data unless flow control
 * allows it. This checks the connection-level flow control limit.
 *
 * Returns: true if bytes can be sent, false otherwise
 */
bool quic_flow_control_can_send(struct quic_connection *conn, u64 bytes)
{
	struct quic_flow_control *fc = &conn->remote_fc;
	u64 available;
	bool can_send;

	if (bytes == 0)
		return true;

	spin_lock_bh(&conn->lock);

	/* Calculate available flow control credit */
	if (fc->max_data > fc->data_sent)
		available = fc->max_data - fc->data_sent;
	else
		available = 0;

	can_send = (bytes <= available);

	if (!can_send && !fc->blocked) {
		/*
		 * RFC 9000 Section 4.1: A sender SHOULD send a DATA_BLOCKED
		 * frame when it wishes to send data but is unable to do so
		 * due to connection-level flow control.
		 */
		fc->blocked = 1;
		fc->blocked_at = fc->max_data;
	}

	spin_unlock_bh(&conn->lock);

	return can_send;
}
EXPORT_SYMBOL(quic_flow_control_can_send);

/**
 * quic_flow_control_on_data_sent - Update flow control after sending data
 * @conn: QUIC connection
 * @bytes: Number of bytes sent
 *
 * Called after data is successfully sent to update the flow control state.
 */
void quic_flow_control_on_data_sent(struct quic_connection *conn, u64 bytes)
{
	struct quic_flow_control *fc = &conn->remote_fc;

	if (bytes == 0)
		return;

	spin_lock_bh(&conn->lock);

	fc->data_sent += bytes;

	/*
	 * If we're now at the limit, prepare DATA_BLOCKED frame
	 * to signal to the peer that we need more credit.
	 */
	if (fc->data_sent >= fc->max_data && !fc->blocked) {
		fc->blocked = 1;
		fc->blocked_at = fc->max_data;
	}

	spin_unlock_bh(&conn->lock);
}
EXPORT_SYMBOL(quic_flow_control_on_data_sent);

/**
 * quic_flow_control_on_data_recvd - Update flow control after receiving data
 * @conn: QUIC connection
 * @bytes: Number of bytes received
 *
 * Called when data is received. This may trigger sending a MAX_DATA frame
 * to update the peer's flow control limit.
 */
void quic_flow_control_on_data_recvd(struct quic_connection *conn, u64 bytes)
{
	struct quic_flow_control *fc = &conn->local_fc;
	u64 consumed;
	u64 threshold;
	bool should_update = false;

	if (bytes == 0)
		return;

	spin_lock_bh(&conn->lock);

	fc->data_received += bytes;

	/*
	 * RFC 9000 Section 4.2: A receiver MAY send a MAX_DATA frame as soon
	 * as it has consumed data, but doing so frequently can cause excessive
	 * overhead. A receiver sends MAX_DATA frames to update the maximum
	 * data it is willing to receive when it has consumed a significant
	 * portion of the initial window.
	 *
	 * We use a threshold of 1/2 of the window to trigger updates.
	 */
	consumed = fc->data_received;
	threshold = fc->max_data / QUIC_FC_WINDOW_UPDATE_THRESHOLD;

	if (consumed >= threshold) {
		/*
		 * Calculate next max_data value. We advance the window
		 * by the amount consumed, but also apply auto-tuning
		 * if appropriate.
		 */
		fc->max_data_next = fc->data_received +
				    (fc->max_data - fc->data_received);
		should_update = true;
	}

	spin_unlock_bh(&conn->lock);

	if (should_update)
		quic_flow_control_update_max_data(conn);
}
EXPORT_SYMBOL(quic_flow_control_on_data_recvd);

/**
 * quic_flow_control_update_max_data - Send MAX_DATA frame to peer
 * @conn: QUIC connection
 *
 * Sends a MAX_DATA frame to increase the connection-level flow control
 * limit advertised to the peer.
 */
void quic_flow_control_update_max_data(struct quic_connection *conn)
{
	struct quic_flow_control *fc = &conn->local_fc;
	struct sk_buff *skb;
	u64 new_max_data;

	spin_lock_bh(&conn->lock);

	/*
	 * Calculate new max_data. We extend the window beyond what
	 * has been received to allow the peer to send more data.
	 */
	new_max_data = fc->data_received +
		       (fc->max_data - (fc->max_data -
		       (fc->max_data - fc->data_received)));

	/* Apply auto-tuning: gradually increase window size */
	if (new_max_data < QUIC_FC_MAX_WINDOW) {
		u64 current_window = fc->max_data - fc->data_received;
		u64 new_window = min_t(u64, current_window * QUIC_FC_AUTOTUNE_MULTIPLIER,
				       QUIC_FC_MAX_WINDOW);
		new_max_data = fc->data_received + new_window;
	}

	/* Only send update if we're actually increasing the limit */
	if (new_max_data <= fc->max_data) {
		spin_unlock_bh(&conn->lock);
		return;
	}

	fc->max_data = new_max_data;
	fc->max_data_next = new_max_data;

	spin_unlock_bh(&conn->lock);

	/* Create and queue MAX_DATA frame */
	skb = quic_flow_create_max_data_frame(conn, new_max_data);
	if (!skb) {
		pr_err("QUIC: failed to allocate MAX_DATA frame\n");
		return;
	}

	/*
	 * Queue MAX_DATA frame for transmission.
	 * CRITICAL: Failure to send MAX_DATA allows the peer to send more data
	 * than we are willing to accept, which will eventually cause a
	 * FLOW_CONTROL_ERROR. This is NOT an optional "best effort" operation.
	 *
	 * If queueing fails due to memory pressure, we MUST log it and
	 * retry periodically via DATA_BLOCKED handling.
	 */
	if (quic_conn_queue_frame(conn, skb)) {
		pr_warn("QUIC: failed to queue MAX_DATA frame (queue full), will retry\n");
		kfree_skb(skb);
		/*
		 * Note: The peer is now operating with stale flow control limits.
		 * A DATA_BLOCKED frame from the peer will trigger a retry of
		 * MAX_DATA update. If peer never sends DATA_BLOCKED, the idle
		 * timeout will eventually close the connection.
		 */
		return;
	}

	/* Schedule transmission of the queued frame */
	schedule_work(&conn->tx_work);
}
EXPORT_SYMBOL(quic_flow_control_update_max_data);

/**
 * quic_flow_control_max_data_received - Handle received MAX_DATA frame
 * @conn: QUIC connection
 * @max_data: New max_data value from peer
 *
 * Called when a MAX_DATA frame is received from the peer. Updates the
 * connection-level flow control limit.
 */
void quic_flow_control_max_data_received(struct quic_connection *conn,
					 u64 max_data)
{
	struct quic_flow_control *fc = &conn->remote_fc;

	spin_lock_bh(&conn->lock);

	/*
	 * RFC 9000 Section 4.1: A sender MUST ignore any MAX_DATA frame
	 * that does not increase the maximum data value.
	 */
	if (max_data > fc->max_data) {
		fc->max_data = max_data;

		/* Clear blocked state if we now have credit */
		if (fc->blocked && fc->data_sent < fc->max_data) {
			fc->blocked = 0;
		}
	}

	spin_unlock_bh(&conn->lock);
}

/**
 * quic_flow_control_get_available - Get available connection flow control credit
 * @conn: QUIC connection
 *
 * Returns the number of bytes that can be sent at the connection level.
 */
u64 quic_flow_control_get_available(struct quic_connection *conn)
{
	struct quic_flow_control *fc = &conn->remote_fc;
	u64 available;

	spin_lock_bh(&conn->lock);
	if (fc->max_data > fc->data_sent)
		available = fc->max_data - fc->data_sent;
	else
		available = 0;
	spin_unlock_bh(&conn->lock);

	return available;
}

/*
 * Stream-level Flow Control Functions
 */

/**
 * quic_stream_flow_control_init - Initialize stream flow control
 * @stream: QUIC stream
 * @max_stream_data_local: Local max stream data limit
 * @max_stream_data_remote: Remote max stream data limit
 *
 * Initializes flow control state for a new stream.
 */
void quic_stream_flow_control_init(struct quic_stream *stream,
				   u64 max_stream_data_local,
				   u64 max_stream_data_remote)
{
	stream->max_stream_data_local = max_stream_data_local;
	stream->max_stream_data_remote = max_stream_data_remote;
	stream->send.max_stream_data = max_stream_data_remote;
	stream->recv.highest_offset = 0;
	stream->recv.final_size = QUIC_MAX_DATA;
}

/**
 * quic_stream_flow_control_can_send - Check if stream allows sending
 * @stream: QUIC stream
 * @bytes: Number of bytes to send
 *
 * RFC 9000 Section 4.1: Each stream has its own flow control limit.
 * A sender MUST NOT send data on a stream unless flow control allows.
 *
 * Returns: true if bytes can be sent, false otherwise
 */
bool quic_stream_flow_control_can_send(struct quic_stream *stream, u64 bytes)
{
	struct quic_stream_send_buf *send = &stream->send;
	u64 available;
	bool can_send;

	if (bytes == 0)
		return true;

	spin_lock(&send->lock);

	/* Calculate available stream flow control credit */
	if (send->max_stream_data > send->offset)
		available = send->max_stream_data - send->offset;
	else
		available = 0;

	can_send = (bytes <= available);

	spin_unlock(&send->lock);

	/*
	 * RFC 9000 Section 4.1: A sender SHOULD send a STREAM_DATA_BLOCKED
	 * frame when it wishes to send data but is unable to do so due to
	 * stream-level flow control.
	 */
	if (!can_send) {
		quic_stream_flow_control_send_blocked(stream);
	}

	return can_send;
}
EXPORT_SYMBOL(quic_stream_flow_control_can_send);

/**
 * quic_stream_flow_control_on_data_sent - Update stream after sending
 * @stream: QUIC stream
 * @bytes: Number of bytes sent
 *
 * Called after data is sent on a stream.
 */
void quic_stream_flow_control_on_data_sent(struct quic_stream *stream,
					   u64 bytes)
{
	if (bytes == 0)
		return;

	/* Stream offset is updated in the send path */
}
EXPORT_SYMBOL(quic_stream_flow_control_on_data_sent);

/**
 * quic_stream_flow_control_check_recv_limit - Check if receiving would exceed limits
 * @stream: QUIC stream
 * @offset: Offset of received data
 * @len: Length of received data
 *
 * RFC 9000 Section 4.1: A receiver MUST close the connection with a
 * FLOW_CONTROL_ERROR error if the sender violates the advertised
 * stream data limit.
 *
 * Returns: 0 if data can be accepted, -EDQUOT if limit exceeded
 */
int quic_stream_flow_control_check_recv_limit(struct quic_stream *stream,
					      u64 offset, u64 len)
{
	u64 new_highest;

	if (len == 0)
		return 0;

	/*
	 * RFC 9000 Section 4.1: The highest offset of data received on a
	 * stream MUST NOT exceed the MAX_STREAM_DATA limit for that stream.
	 *
	 * Check if receiving this data would exceed the stream-level
	 * flow control limit we advertised to the peer.
	 */
	new_highest = offset + len;
	if (new_highest > stream->max_stream_data_local) {
		/*
		 * RFC 9000 Section 4.1: A receiver advertises a maximum
		 * stream data limit. If the sender exceeds this limit,
		 * the receiver MUST close the connection with a
		 * FLOW_CONTROL_ERROR.
		 */
		return -EDQUOT;
	}

	return 0;
}
EXPORT_SYMBOL(quic_stream_flow_control_check_recv_limit);

/**
 * quic_stream_flow_control_on_data_recvd - Update stream after receiving
 * @stream: QUIC stream
 * @offset: Offset of received data
 * @len: Length of received data
 *
 * Called when data is received on a stream. May trigger MAX_STREAM_DATA.
 *
 * Note: The caller MUST call quic_stream_flow_control_check_recv_limit() first
 * to ensure the data does not exceed flow control limits.
 */
void quic_stream_flow_control_on_data_recvd(struct quic_stream *stream,
					    u64 offset, u64 len)
{
	struct quic_stream_recv_buf *recv = &stream->recv;
	u64 new_highest;
	u64 consumed;
	u64 threshold;
	bool should_update = false;

	spin_lock(&recv->lock);

	/*
	 * Track highest offset seen.
	 * Check for overflow before computing new_highest.
	 */
	if (len <= U64_MAX - offset) {
		new_highest = offset + len;
		if (new_highest > recv->highest_offset)
			recv->highest_offset = new_highest;
	}

	/*
	 * Check if we should send MAX_STREAM_DATA. We update when
	 * we've consumed a significant portion of the window.
	 */
	consumed = recv->offset;  /* Amount delivered to application */
	threshold = stream->max_stream_data_local / QUIC_FC_WINDOW_UPDATE_THRESHOLD;

	if (consumed >= threshold)
		should_update = true;

	spin_unlock(&recv->lock);

	if (should_update)
		quic_stream_flow_control_update_max_stream_data(stream);
}

/**
 * quic_stream_flow_control_update_max_stream_data - Send MAX_STREAM_DATA
 * @stream: QUIC stream
 *
 * Sends a MAX_STREAM_DATA frame to increase the stream's flow control limit.
 */
void quic_stream_flow_control_update_max_stream_data(struct quic_stream *stream)
{
	struct quic_connection *conn = stream->conn;
	struct quic_stream_recv_buf *recv = &stream->recv;
	struct sk_buff *skb;
	u64 new_max_stream_data;
	u64 consumed;
	u64 window;

	spin_lock(&recv->lock);

	consumed = recv->offset;
	window = stream->max_stream_data_local - consumed;

	/*
	 * Calculate new limit: current consumed plus original window size.
	 * Apply auto-tuning to gradually increase window.
	 */
	new_max_stream_data = consumed + window;

	/* Auto-tune: increase window if under max */
	if (new_max_stream_data < QUIC_FC_MAX_WINDOW) {
		u64 new_window = min_t(u64, window * QUIC_FC_AUTOTUNE_MULTIPLIER,
				       QUIC_FC_MAX_WINDOW);
		new_max_stream_data = consumed + new_window;
	}

	/* Only update if increasing the limit */
	if (new_max_stream_data <= stream->max_stream_data_local) {
		spin_unlock(&recv->lock);
		return;
	}

	stream->max_stream_data_local = new_max_stream_data;

	spin_unlock(&recv->lock);

	/* Create and queue MAX_STREAM_DATA frame */
	skb = quic_flow_create_max_stream_data_frame(stream->id,
						     new_max_stream_data);
	if (!skb) {
		pr_err("QUIC: failed to allocate MAX_STREAM_DATA frame for stream %llu\n",
		       stream->id);
		return;
	}

	/*
	 * Queue MAX_STREAM_DATA frame for transmission.
	 * CRITICAL: Failure to send MAX_STREAM_DATA has the same implications as
	 * MAX_DATA failure. The peer will be operating with stale flow control
	 * limits, which will eventually cause a FLOW_CONTROL_ERROR when the
	 * peer violates the advertised limit.
	 *
	 * If queueing fails, log it and rely on STREAM_DATA_BLOCKED from peer
	 * to trigger a retry, or idle timeout to close connection.
	 */
	if (quic_conn_queue_frame(conn, skb)) {
		pr_warn("QUIC: failed to queue MAX_STREAM_DATA for stream %llu (queue full), will retry\n",
			stream->id);
		kfree_skb(skb);
		return;
	}

	/* Schedule transmission of the queued frame */
	schedule_work(&conn->tx_work);
}

/**
 * quic_stream_flow_control_max_stream_data_received - Handle MAX_STREAM_DATA
 * @stream: QUIC stream
 * @max_stream_data: New limit from peer
 *
 * Called when a MAX_STREAM_DATA frame is received.
 */
void quic_stream_flow_control_max_stream_data_received(struct quic_stream *stream,
						       u64 max_stream_data)
{
	struct quic_stream_send_buf *send = &stream->send;

	spin_lock(&send->lock);

	/*
	 * RFC 9000 Section 4.1: A sender MUST ignore any MAX_STREAM_DATA
	 * frame that does not increase the stream data limit.
	 */
	if (max_stream_data > send->max_stream_data) {
		send->max_stream_data = max_stream_data;
		stream->max_stream_data_remote = max_stream_data;
	}

	spin_unlock(&send->lock);

	/* Wake any waiters blocked on flow control */
	wake_up(&stream->wait);
}

/**
 * quic_stream_flow_control_send_blocked - Send STREAM_DATA_BLOCKED frame
 * @stream: QUIC stream
 *
 * Sends a STREAM_DATA_BLOCKED frame to indicate we want to send more data
 * but are blocked by stream-level flow control.
 */
void quic_stream_flow_control_send_blocked(struct quic_stream *stream)
{
	struct quic_connection *conn = stream->conn;
	struct quic_stream_send_buf *send = &stream->send;
	struct sk_buff *skb;
	u64 limit;

	spin_lock(&send->lock);
	limit = send->max_stream_data;
	spin_unlock(&send->lock);

	skb = quic_flow_create_stream_data_blocked_frame(stream->id, limit);
	if (!skb) {
		pr_err("QUIC: failed to allocate STREAM_DATA_BLOCKED frame for stream %llu\n",
		       stream->id);
		return;
	}

	/*
	 * Queue STREAM_DATA_BLOCKED frame for transmission.
	 * RFC 9000 Section 4.1: "A sender SHOULD send a STREAM_DATA_BLOCKED
	 * frame when it wishes to send data but is unable to do so due to
	 * stream-level flow control."
	 *
	 * While this is labeled "advisory" in RFC 9000, it is IMPORTANT for
	 * congestion visibility and flow control negotiation. Silently dropping
	 * BLOCKED frames means the receiver never learns that we're blocked.
	 *
	 * Log failures so operators can diagnose flow control issues.
	 */
	if (quic_conn_queue_frame(conn, skb)) {
		pr_warn("QUIC: failed to queue STREAM_DATA_BLOCKED for stream %llu (queue full)\n",
			stream->id);
		kfree_skb(skb);
		return;
	}

	/* Schedule transmission of the queued frame */
	schedule_work(&conn->tx_work);
}

/**
 * quic_stream_flow_control_get_available - Get available stream credit
 * @stream: QUIC stream
 *
 * Returns the number of bytes that can be sent on this stream.
 */
u64 quic_stream_flow_control_get_available(struct quic_stream *stream)
{
	struct quic_stream_send_buf *send = &stream->send;
	u64 available;

	spin_lock(&send->lock);
	if (send->max_stream_data > send->offset)
		available = send->max_stream_data - send->offset;
	else
		available = 0;
	spin_unlock(&send->lock);

	return available;
}

/*
 * Stream Limit Management Functions (MAX_STREAMS)
 */

/**
 * quic_streams_can_open - Check if a new stream can be opened
 * @conn: QUIC connection
 * @unidirectional: true for unidirectional, false for bidirectional
 *
 * RFC 9000 Section 4.6: An endpoint MUST NOT exceed the limit set by
 * its peer. An endpoint that receives a frame with a stream ID exceeding
 * the limit it has sent MUST treat this as a connection error of type
 * STREAM_LIMIT_ERROR.
 *
 * Returns: true if a new stream can be opened, false otherwise
 */
bool quic_streams_can_open(struct quic_connection *conn, bool unidirectional)
{
	struct quic_flow_control *fc = &conn->remote_fc;
	bool can_open;

	spin_lock_bh(&conn->lock);

	if (unidirectional)
		can_open = (fc->streams_opened_uni < fc->max_streams_uni);
	else
		can_open = (fc->streams_opened_bidi < fc->max_streams_bidi);

	spin_unlock_bh(&conn->lock);

	return can_open;
}

/**
 * quic_streams_on_stream_opened - Update stream count after opening
 * @conn: QUIC connection
 * @unidirectional: true for unidirectional stream
 *
 * Called when a new locally-initiated stream is opened.
 */
void quic_streams_on_stream_opened(struct quic_connection *conn,
				   bool unidirectional)
{
	struct quic_flow_control *fc = &conn->remote_fc;

	spin_lock_bh(&conn->lock);

	if (unidirectional)
		fc->streams_opened_uni++;
	else
		fc->streams_opened_bidi++;

	spin_unlock_bh(&conn->lock);
}

/**
 * quic_streams_on_peer_stream_opened - Update peer stream count
 * @conn: QUIC connection
 * @unidirectional: true for unidirectional stream
 *
 * Called when a peer-initiated stream is received.
 */
void quic_streams_on_peer_stream_opened(struct quic_connection *conn,
					bool unidirectional)
{
	struct quic_flow_control *fc = &conn->local_fc;

	spin_lock_bh(&conn->lock);

	if (unidirectional)
		fc->streams_opened_uni++;
	else
		fc->streams_opened_bidi++;

	spin_unlock_bh(&conn->lock);

	/* Check if we should send MAX_STREAMS to allow more peer streams */
	quic_streams_check_update(conn, unidirectional);
}

/**
 * quic_streams_check_update - Check if MAX_STREAMS should be sent
 * @conn: QUIC connection
 * @unidirectional: true for unidirectional streams
 *
 * Checks if we should send a MAX_STREAMS frame to allow the peer
 * to open more streams.
 */
void quic_streams_check_update(struct quic_connection *conn, bool unidirectional)
{
	struct quic_flow_control *fc = &conn->local_fc;
	u64 opened, max_streams;
	u64 threshold;
	bool should_update = false;

	spin_lock_bh(&conn->lock);

	if (unidirectional) {
		opened = fc->streams_opened_uni;
		max_streams = fc->max_streams_uni;
	} else {
		opened = fc->streams_opened_bidi;
		max_streams = fc->max_streams_bidi;
	}

	/* Update when peer has used half of the available streams */
	threshold = max_streams / 2;
	if (opened >= threshold)
		should_update = true;

	spin_unlock_bh(&conn->lock);

	if (should_update)
		quic_streams_update_max_streams(conn, unidirectional);
}

/**
 * quic_streams_update_max_streams - Send MAX_STREAMS frame
 * @conn: QUIC connection
 * @unidirectional: true for unidirectional streams
 *
 * Sends a MAX_STREAMS frame to allow the peer to open more streams.
 */
void quic_streams_update_max_streams(struct quic_connection *conn,
				     bool unidirectional)
{
	struct quic_flow_control *fc = &conn->local_fc;
	struct sk_buff *skb;
	u64 new_max_streams;
	u64 current_max;

	spin_lock_bh(&conn->lock);

	if (unidirectional) {
		current_max = fc->max_streams_uni;
		/* Increase by original limit */
		new_max_streams = current_max +
				  conn->local_params.initial_max_streams_uni;
		if (new_max_streams > QUIC_MAX_STREAMS)
			new_max_streams = QUIC_MAX_STREAMS;
		fc->max_streams_uni = new_max_streams;
	} else {
		current_max = fc->max_streams_bidi;
		new_max_streams = current_max +
				  conn->local_params.initial_max_streams_bidi;
		if (new_max_streams > QUIC_MAX_STREAMS)
			new_max_streams = QUIC_MAX_STREAMS;
		fc->max_streams_bidi = new_max_streams;
	}

	spin_unlock_bh(&conn->lock);

	/* Only send if we actually increased the limit */
	if (new_max_streams > current_max) {
		skb = quic_flow_create_max_streams_frame(new_max_streams,
							 unidirectional);
		if (!skb) {
			pr_err("QUIC: failed to allocate MAX_STREAMS frame\n");
			return;
		}

		/*
		 * Queue MAX_STREAMS frame for transmission.
		 * CRITICAL: Failure to send MAX_STREAMS prevents the peer from
		 * opening new streams, limiting connection capacity. While the RFC
		 * says this is "advisory", it is essential for proper connection
		 * operation when the peer is blocked on stream limits.
		 *
		 * If queueing fails, log it. The peer's STREAMS_BLOCKED frame
		 * will eventually prompt a retry, or idle timeout closes connection.
		 */
		if (quic_conn_queue_frame(conn, skb)) {
			pr_warn("QUIC: failed to queue MAX_STREAMS frame (queue full), will retry\n");
			kfree_skb(skb);
			return;
		}

		/* Schedule transmission of the queued frame */
		schedule_work(&conn->tx_work);
	}
}

/**
 * quic_streams_max_streams_received - Handle received MAX_STREAMS frame
 * @conn: QUIC connection
 * @max_streams: New stream limit
 * @unidirectional: true for unidirectional streams
 *
 * Called when a MAX_STREAMS frame is received from the peer.
 */
void quic_streams_max_streams_received(struct quic_connection *conn,
				       u64 max_streams, bool unidirectional)
{
	struct quic_flow_control *fc = &conn->remote_fc;

	spin_lock_bh(&conn->lock);

	/*
	 * RFC 9000 Section 4.6: An endpoint MUST ignore any MAX_STREAMS
	 * frame that does not increase the stream limit.
	 */
	if (unidirectional) {
		if (max_streams > fc->max_streams_uni)
			fc->max_streams_uni = max_streams;
	} else {
		if (max_streams > fc->max_streams_bidi)
			fc->max_streams_bidi = max_streams;
	}

	spin_unlock_bh(&conn->lock);
}

/**
 * quic_streams_send_blocked - Send STREAMS_BLOCKED frame
 * @conn: QUIC connection
 * @unidirectional: true for unidirectional streams
 *
 * Sends a STREAMS_BLOCKED frame when we want to open more streams
 * but are blocked by the stream limit.
 */
void quic_streams_send_blocked(struct quic_connection *conn, bool unidirectional)
{
	struct quic_flow_control *fc = &conn->remote_fc;
	struct sk_buff *skb;
	u64 limit;

	spin_lock_bh(&conn->lock);
	limit = unidirectional ? fc->max_streams_uni : fc->max_streams_bidi;
	spin_unlock_bh(&conn->lock);

	skb = quic_flow_create_streams_blocked_frame(limit, unidirectional);
	if (!skb) {
		pr_err("QUIC: failed to allocate STREAMS_BLOCKED frame\n");
		return;
	}

	/*
	 * Queue STREAMS_BLOCKED frame for transmission.
	 * RFC 9000 Section 4.6: "A sender SHOULD send a STREAMS_BLOCKED frame
	 * when it wishes to open a stream but is unable to do so due to the
	 * stream limit set by its peer."
	 *
	 * Like STREAM_DATA_BLOCKED, while labeled "advisory", this is important
	 * for the receiver to understand we're blocked on stream limits.
	 *
	 * Log failures for visibility into flow control issues.
	 */
	if (quic_conn_queue_frame(conn, skb)) {
		pr_warn("QUIC: failed to queue STREAMS_BLOCKED frame (queue full)\n");
		kfree_skb(skb);
		return;
	}

	/* Schedule transmission of the queued frame */
	schedule_work(&conn->tx_work);
}

/*
 * Blocked Notification Handling
 */

/**
 * quic_flow_control_send_data_blocked - Send DATA_BLOCKED frame
 * @conn: QUIC connection
 *
 * Sends a DATA_BLOCKED frame to indicate we want to send more data
 * but are blocked by connection-level flow control.
 */
void quic_flow_control_send_data_blocked(struct quic_connection *conn)
{
	struct quic_flow_control *fc = &conn->remote_fc;
	struct sk_buff *skb;
	u64 limit;

	spin_lock_bh(&conn->lock);
	limit = fc->max_data;
	spin_unlock_bh(&conn->lock);

	skb = quic_flow_create_data_blocked_frame(limit);
	if (!skb) {
		pr_err("QUIC: failed to allocate DATA_BLOCKED frame\n");
		return;
	}

	/*
	 * Queue DATA_BLOCKED frame for transmission.
	 * RFC 9000 Section 4.1: "A sender SHOULD send a DATA_BLOCKED frame
	 * when it wishes to send data but is unable to do so due to
	 * connection-level flow control."
	 *
	 * While RFC 9000 Section 4.1 also states "A DATA_BLOCKED frame does not
	 * require any action by the receiver", it is IMPORTANT for the receiver
	 * to know that we need more flow control credit. Silently dropping this
	 * frame masks real flow control problems.
	 *
	 * Log failures to help diagnose connection-level flow control issues.
	 */
	if (quic_conn_queue_frame(conn, skb)) {
		pr_warn("QUIC: failed to queue DATA_BLOCKED frame (queue full)\n");
		kfree_skb(skb);
		return;
	}

	/* Schedule transmission of the queued frame */
	schedule_work(&conn->tx_work);
}

/**
 * quic_flow_control_data_blocked_received - Handle DATA_BLOCKED frame
 * @conn: QUIC connection
 * @limit: The limit at which the peer is blocked
 *
 * RFC 9000 Section 4.1: A DATA_BLOCKED frame does not require any action
 * by the receiver, but it can be useful for debugging.
 */
void quic_flow_control_data_blocked_received(struct quic_connection *conn,
					     u64 limit)
{
	/*
	 * The peer is blocked on connection-level flow control.
	 * This is informational - we may choose to send MAX_DATA sooner.
	 */
	quic_dbg("DATA_BLOCKED received at limit %llu\n", limit);

	/* Optionally trigger MAX_DATA update */
	quic_flow_control_update_max_data(conn);
}

/**
 * quic_stream_data_blocked_received - Handle STREAM_DATA_BLOCKED frame
 * @conn: QUIC connection
 * @stream_id: Stream ID
 * @limit: The limit at which the peer is blocked
 *
 * RFC 9000 Section 4.1: Informational frame indicating peer is blocked.
 */
void quic_stream_data_blocked_received(struct quic_connection *conn,
				       u64 stream_id, u64 limit)
{
	struct quic_stream *stream;

	quic_dbg("STREAM_DATA_BLOCKED received for stream %llu at limit %llu\n",
		 stream_id, limit);

	stream = quic_stream_lookup(conn, stream_id);
	if (stream) {
		/* Optionally trigger MAX_STREAM_DATA update */
		quic_stream_flow_control_update_max_stream_data(stream);
		refcount_dec(&stream->refcnt);
	}
}

/**
 * quic_streams_blocked_received - Handle STREAMS_BLOCKED frame
 * @conn: QUIC connection
 * @limit: The limit at which the peer is blocked
 * @unidirectional: true if for unidirectional streams
 *
 * RFC 9000 Section 4.6: Informational frame indicating peer wants more streams.
 */
void quic_streams_blocked_received(struct quic_connection *conn, u64 limit,
				   bool unidirectional)
{
	quic_dbg("STREAMS_BLOCKED received at limit %llu (uni=%d)\n",
		 limit, unidirectional);

	/* Optionally trigger MAX_STREAMS update */
	quic_streams_update_max_streams(conn, unidirectional);
}

/*
 * Frame Creation Helper Functions
 */

/**
 * quic_flow_create_max_data_frame - Create a MAX_DATA frame
 * @conn: QUIC connection
 * @max_data: Maximum data value to advertise
 *
 * RFC 9000 Section 19.9: MAX_DATA Frame
 *
 * MAX_DATA Frame {
 *   Type (i) = 0x10,
 *   Maximum Data (i),
 * }
 *
 * Returns: sk_buff containing the frame, or NULL on failure
 */
static struct sk_buff *quic_flow_create_max_data_frame(struct quic_connection *conn,
						       u64 max_data)
{
	struct sk_buff *skb;
	u8 *p;
	int frame_len;

	/* Calculate frame size: type (1 byte) + max_data (variable) */
	frame_len = 1 + quic_varint_len(max_data);

	skb = alloc_skb(frame_len + 16, GFP_ATOMIC);
	if (!skb)
		return NULL;

	/* Frame type */
	p = skb_put(skb, 1);
	*p = QUIC_FRAME_MAX_DATA;

	/* Maximum Data */
	p = skb_put(skb, quic_varint_len(max_data));
	quic_varint_encode(max_data, p);

	atomic64_inc(&conn->stats.frames_sent);

	return skb;
}

/**
 * quic_flow_create_max_stream_data_frame - Create a MAX_STREAM_DATA frame
 * @stream_id: Stream ID
 * @max_stream_data: Maximum stream data value
 *
 * RFC 9000 Section 19.10: MAX_STREAM_DATA Frame
 *
 * MAX_STREAM_DATA Frame {
 *   Type (i) = 0x11,
 *   Stream ID (i),
 *   Maximum Stream Data (i),
 * }
 *
 * Returns: sk_buff containing the frame, or NULL on failure
 */
static struct sk_buff *quic_flow_create_max_stream_data_frame(u64 stream_id,
							      u64 max_stream_data)
{
	struct sk_buff *skb;
	u8 *p;
	int frame_len;

	/* Calculate frame size */
	frame_len = 1 + quic_varint_len(stream_id) +
		    quic_varint_len(max_stream_data);

	skb = alloc_skb(frame_len + 16, GFP_ATOMIC);
	if (!skb)
		return NULL;

	/* Frame type */
	p = skb_put(skb, 1);
	*p = QUIC_FRAME_MAX_STREAM_DATA;

	/* Stream ID */
	p = skb_put(skb, quic_varint_len(stream_id));
	quic_varint_encode(stream_id, p);

	/* Maximum Stream Data */
	p = skb_put(skb, quic_varint_len(max_stream_data));
	quic_varint_encode(max_stream_data, p);

	return skb;
}

/**
 * quic_flow_create_max_streams_frame - Create a MAX_STREAMS frame
 * @max_streams: Maximum streams value
 * @unidirectional: true for unidirectional streams
 *
 * RFC 9000 Section 19.11: MAX_STREAMS Frames
 *
 * MAX_STREAMS Frame {
 *   Type (i) = 0x12..0x13,
 *   Maximum Streams (i),
 * }
 *
 * Returns: sk_buff containing the frame, or NULL on failure
 */
static struct sk_buff *quic_flow_create_max_streams_frame(u64 max_streams,
							  bool unidirectional)
{
	struct sk_buff *skb;
	u8 *p;
	int frame_len;
	u8 frame_type;

	frame_type = unidirectional ? QUIC_FRAME_MAX_STREAMS_UNI :
				      QUIC_FRAME_MAX_STREAMS_BIDI;

	/* Calculate frame size */
	frame_len = 1 + quic_varint_len(max_streams);

	skb = alloc_skb(frame_len + 16, GFP_ATOMIC);
	if (!skb)
		return NULL;

	/* Frame type */
	p = skb_put(skb, 1);
	*p = frame_type;

	/* Maximum Streams */
	p = skb_put(skb, quic_varint_len(max_streams));
	quic_varint_encode(max_streams, p);

	return skb;
}

/**
 * quic_flow_create_data_blocked_frame - Create a DATA_BLOCKED frame
 * @limit: The connection-level limit at which we are blocked
 *
 * RFC 9000 Section 19.12: DATA_BLOCKED Frame
 *
 * DATA_BLOCKED Frame {
 *   Type (i) = 0x14,
 *   Maximum Data (i),
 * }
 *
 * Returns: sk_buff containing the frame, or NULL on failure
 */
static struct sk_buff *quic_flow_create_data_blocked_frame(u64 limit)
{
	struct sk_buff *skb;
	u8 *p;
	int frame_len;

	frame_len = 1 + quic_varint_len(limit);

	skb = alloc_skb(frame_len + 16, GFP_ATOMIC);
	if (!skb)
		return NULL;

	/* Frame type */
	p = skb_put(skb, 1);
	*p = QUIC_FRAME_DATA_BLOCKED;

	/* Maximum Data (limit) */
	p = skb_put(skb, quic_varint_len(limit));
	quic_varint_encode(limit, p);

	return skb;
}

/**
 * quic_flow_create_stream_data_blocked_frame - Create STREAM_DATA_BLOCKED frame
 * @stream_id: Stream ID
 * @limit: The stream-level limit at which we are blocked
 *
 * RFC 9000 Section 19.13: STREAM_DATA_BLOCKED Frame
 *
 * STREAM_DATA_BLOCKED Frame {
 *   Type (i) = 0x15,
 *   Stream ID (i),
 *   Maximum Stream Data (i),
 * }
 *
 * Returns: sk_buff containing the frame, or NULL on failure
 */
static struct sk_buff *quic_flow_create_stream_data_blocked_frame(u64 stream_id,
								  u64 limit)
{
	struct sk_buff *skb;
	u8 *p;
	int frame_len;

	frame_len = 1 + quic_varint_len(stream_id) + quic_varint_len(limit);

	skb = alloc_skb(frame_len + 16, GFP_ATOMIC);
	if (!skb)
		return NULL;

	/* Frame type */
	p = skb_put(skb, 1);
	*p = QUIC_FRAME_STREAM_DATA_BLOCKED;

	/* Stream ID */
	p = skb_put(skb, quic_varint_len(stream_id));
	quic_varint_encode(stream_id, p);

	/* Maximum Stream Data (limit) */
	p = skb_put(skb, quic_varint_len(limit));
	quic_varint_encode(limit, p);

	return skb;
}

/**
 * quic_flow_create_streams_blocked_frame - Create STREAMS_BLOCKED frame
 * @limit: The stream limit at which we are blocked
 * @unidirectional: true for unidirectional streams
 *
 * RFC 9000 Section 19.14: STREAMS_BLOCKED Frames
 *
 * STREAMS_BLOCKED Frame {
 *   Type (i) = 0x16..0x17,
 *   Maximum Streams (i),
 * }
 *
 * Returns: sk_buff containing the frame, or NULL on failure
 */
static struct sk_buff *quic_flow_create_streams_blocked_frame(u64 limit,
							      bool unidirectional)
{
	struct sk_buff *skb;
	u8 *p;
	int frame_len;
	u8 frame_type;

	frame_type = unidirectional ? QUIC_FRAME_STREAMS_BLOCKED_UNI :
				      QUIC_FRAME_STREAMS_BLOCKED_BIDI;

	frame_len = 1 + quic_varint_len(limit);

	skb = alloc_skb(frame_len + 16, GFP_ATOMIC);
	if (!skb)
		return NULL;

	/* Frame type */
	p = skb_put(skb, 1);
	*p = frame_type;

	/* Maximum Streams (limit) */
	p = skb_put(skb, quic_varint_len(limit));
	quic_varint_encode(limit, p);

	return skb;
}

/*
 * Combined Flow Control Check Function
 */

/**
 * quic_flow_can_send_stream_data - Check all flow control limits
 * @stream: QUIC stream
 * @bytes: Number of bytes to send
 *
 * Performs combined check of both connection-level and stream-level
 * flow control to determine if data can be sent.
 *
 * Returns: true if data can be sent, false otherwise
 */
bool quic_flow_can_send_stream_data(struct quic_stream *stream, u64 bytes)
{
	struct quic_connection *conn = stream->conn;

	/* Check connection-level flow control first */
	if (!quic_flow_control_can_send(conn, bytes))
		return false;

	/* Check stream-level flow control */
	if (!quic_stream_flow_control_can_send(stream, bytes))
		return false;

	return true;
}

/**
 * quic_flow_on_stream_data_sent - Update all flow control after sending
 * @stream: QUIC stream
 * @bytes: Number of bytes sent
 *
 * Updates both connection-level and stream-level flow control state.
 */
void quic_flow_on_stream_data_sent(struct quic_stream *stream, u64 bytes)
{
	quic_flow_control_on_data_sent(stream->conn, bytes);
	quic_stream_flow_control_on_data_sent(stream, bytes);
}

/**
 * quic_flow_check_recv_limits - Check all receive flow control limits
 * @stream: QUIC stream
 * @offset: Offset of received data
 * @len: Length of received data
 *
 * RFC 9000 Section 4.1: A receiver MUST close the connection with a
 * FLOW_CONTROL_ERROR error if the sender violates the advertised
 * connection or stream data limits.
 *
 * Performs combined check of both connection-level and stream-level
 * flow control to determine if received data can be accepted.
 *
 * Returns: 0 if data can be accepted, -EDQUOT if limits exceeded
 */
int quic_flow_check_recv_limits(struct quic_stream *stream, u64 offset, u64 len)
{
	struct quic_connection *conn = stream->conn;
	int err;

	/*
	 * Check stream-level flow control first (RFC 9000 Section 4.1).
	 * The highest offset of data received on a stream MUST NOT exceed
	 * the MAX_STREAM_DATA limit for that stream.
	 */
	err = quic_stream_flow_control_check_recv_limit(stream, offset, len);
	if (err)
		return err;

	/*
	 * Check connection-level flow control (RFC 9000 Section 4.1).
	 * The sum of data received on all streams MUST NOT exceed
	 * the MAX_DATA limit for the connection.
	 */
	err = quic_flow_control_check_recv_limit(conn, len);
	if (err)
		return err;

	return 0;
}
EXPORT_SYMBOL(quic_flow_check_recv_limits);

/**
 * quic_flow_on_stream_data_recvd - Update all flow control after receiving
 * @stream: QUIC stream
 * @offset: Offset of received data
 * @len: Length of received data
 *
 * Updates both connection-level and stream-level flow control state.
 *
 * Note: The caller MUST call quic_flow_check_recv_limits() first to
 * ensure the data does not exceed flow control limits.
 */
void quic_flow_on_stream_data_recvd(struct quic_stream *stream,
				    u64 offset, u64 len)
{
	quic_flow_control_on_data_recvd(stream->conn, len);
	quic_stream_flow_control_on_data_recvd(stream, offset, len);
}

/*
 * Flow Control Debug and Statistics
 */

/**
 * quic_flow_get_stats - Get flow control statistics
 * @conn: QUIC connection
 * @local_max_data: Output for local max_data
 * @local_data_recvd: Output for local data received
 * @remote_max_data: Output for remote max_data
 * @remote_data_sent: Output for remote data sent
 *
 * Retrieves current flow control statistics for debugging.
 */
void quic_flow_get_stats(struct quic_connection *conn,
			 u64 *local_max_data, u64 *local_data_recvd,
			 u64 *remote_max_data, u64 *remote_data_sent)
{
	spin_lock_bh(&conn->lock);

	if (local_max_data)
		*local_max_data = conn->local_fc.max_data;
	if (local_data_recvd)
		*local_data_recvd = conn->local_fc.data_received;
	if (remote_max_data)
		*remote_max_data = conn->remote_fc.max_data;
	if (remote_data_sent)
		*remote_data_sent = conn->remote_fc.data_sent;

	spin_unlock_bh(&conn->lock);
}

/**
 * quic_stream_flow_get_stats - Get stream flow control statistics
 * @stream: QUIC stream
 * @send_offset: Output for send offset
 * @send_max: Output for max stream data (send)
 * @recv_offset: Output for receive offset
 * @recv_max: Output for max stream data (receive)
 *
 * Retrieves current stream flow control statistics.
 */
void quic_stream_flow_get_stats(struct quic_stream *stream,
				u64 *send_offset, u64 *send_max,
				u64 *recv_offset, u64 *recv_max)
{
	struct quic_stream_send_buf *send = &stream->send;
	struct quic_stream_recv_buf *recv = &stream->recv;

	spin_lock(&send->lock);
	if (send_offset)
		*send_offset = send->offset;
	if (send_max)
		*send_max = send->max_stream_data;
	spin_unlock(&send->lock);

	spin_lock(&recv->lock);
	if (recv_offset)
		*recv_offset = recv->offset;
	if (recv_max)
		*recv_max = stream->max_stream_data_local;
	spin_unlock(&recv->lock);
}

/*
 * Module initialization
 */

/**
 * quic_flow_init - Initialize flow control subsystem
 *
 * Called during QUIC module initialization.
 *
 * Returns: 0 on success, negative error code on failure
 */
int __init quic_flow_init(void)
{
	pr_info("QUIC flow control initialized\n");
	return 0;
}

/**
 * quic_flow_exit - Cleanup flow control subsystem
 *
 * Called during QUIC module unload.
 */
void quic_flow_exit(void)
{
	pr_info("QUIC flow control cleanup\n");
}
