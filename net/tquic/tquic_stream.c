// SPDX-License-Identifier: GPL-2.0-only
/*
 * TQUIC: Stream Socket Implementation
 *
 * Copyright (c) 2026 Linux Foundation
 *
 * Provides first-class stream file descriptors for QUIC stream multiplexing.
 * Each stream is a separate socket that can be used with poll/epoll/select.
 *
 * Per CONTEXT.md, TQUIC uses a streams-only I/O model where sendmsg/recvmsg
 * work on stream sockets, not the connection socket. The connection socket
 * is used for control operations (connect, listen, accept, stream creation).
 *
 * HTTP/3 Integration (RFC 9114):
 * When HTTP/3 mode is enabled, streams follow HTTP/3 semantics:
 *   - Bidirectional streams: Request/response pairs (client-initiated: 0, 4, 8...)
 *   - Unidirectional streams: Control, Push, QPACK (type byte at start)
 * Stream type validation and frame sequencing are enforced in HTTP/3 mode.
 */

#include <linux/module.h>
#include <linux/net.h>
#include <linux/socket.h>
#include <linux/file.h>
#include <linux/poll.h>
#include <linux/anon_inodes.h>
#include <linux/slab.h>
#include <net/sock.h>
#include <net/tquic.h>
#include <uapi/linux/tquic.h>

#include "protocol.h"
#include "http3/http3_stream.h"

/*
 * Helper to create file descriptor for a socket
 * Replacement for sock_map_fd which is not exported
 */
static int tquic_sock_map_fd(struct socket *sock, int flags)
{
	struct file *newfile;
	int fd = get_unused_fd_flags(flags);

	if (unlikely(fd < 0)) {
		sock_release(sock);
		return fd;
	}

	newfile = sock_alloc_file(sock, flags, "tquic-stream");
	if (IS_ERR(newfile)) {
		put_unused_fd(fd);
		return PTR_ERR(newfile);
	}

	fd_install(fd, newfile);
	return fd;
}

/*
 * Stream socket proto_ops forward declarations
 */
static int tquic_stream_release(struct socket *sock);
static int tquic_stream_sendmsg(struct socket *sock, struct msghdr *msg,
				size_t len);
static int tquic_stream_recvmsg(struct socket *sock, struct msghdr *msg,
				size_t len, int flags);
static __poll_t tquic_stream_poll(struct file *file, struct socket *sock,
				  poll_table *wait);

/*
 * Stream socket proto_ops
 *
 * Stream sockets support a subset of socket operations. Most "connection"
 * operations (bind, connect, listen, accept) return -EOPNOTSUPP since
 * the stream is already associated with a connection.
 */
static const struct proto_ops tquic_stream_ops = {
	.family		= PF_INET,
	.owner		= THIS_MODULE,
	.release	= tquic_stream_release,
	.bind		= sock_no_bind,
	.connect	= sock_no_connect,
	.socketpair	= sock_no_socketpair,
	.accept		= sock_no_accept,
	.getname	= sock_no_getname,
	.poll		= tquic_stream_poll,
	.ioctl		= sock_no_ioctl,
	.listen		= sock_no_listen,
	.shutdown	= sock_no_shutdown,
	.sendmsg	= tquic_stream_sendmsg,
	.recvmsg	= tquic_stream_recvmsg,
	.mmap		= sock_no_mmap,
};

/*
 * =============================================================================
 * STREAM MANAGEMENT FUNCTIONS
 * =============================================================================
 */

/**
 * tquic_stream_alloc - Allocate and initialize a stream structure
 * @conn: Parent connection
 * @is_bidi: True for bidirectional, false for unidirectional
 *
 * Internal helper to allocate stream and assign ID based on role.
 *
 * Stream ID encoding per RFC 9000 Section 2.1:
 *   - Bits 0-1 encode type: 0=client bidi, 1=server bidi,
 *                           2=client uni, 3=server uni
 *   - Client-initiated: even (bidi: 0,4,8..., uni: 2,6,10...)
 *   - Server-initiated: odd (bidi: 1,5,9..., uni: 3,7,11...)
 *
 * Returns: Allocated stream on success, NULL on failure
 */
static struct tquic_stream *tquic_stream_alloc(struct tquic_connection *conn,
					       bool is_bidi)
{
	struct tquic_stream *stream;
	u64 *next_id;

	if (!conn)
		return NULL;

	stream = kzalloc(sizeof(*stream), GFP_KERNEL);
	if (!stream)
		return NULL;

	/*
	 * Assign stream ID based on initiator role and direction.
	 * Stream IDs increment by 4 (to encode type in low 2 bits).
	 */
	spin_lock_bh(&conn->lock);

	if (is_bidi) {
		next_id = &conn->next_stream_id_bidi;
	} else {
		next_id = &conn->next_stream_id_uni;
	}

	stream->id = *next_id;
	*next_id += 4;

	spin_unlock_bh(&conn->lock);

	stream->conn = conn;
	stream->state = TQUIC_STREAM_OPEN;

	/* Initialize buffers */
	skb_queue_head_init(&stream->send_buf);
	skb_queue_head_init(&stream->recv_buf);

	/*
	 * Set initial flow control limits.
	 * These come from transport parameters negotiated during handshake.
	 * Using default values here; actual values would come from conn.
	 */
	stream->max_send_data = TQUIC_DEFAULT_MAX_STREAM_DATA;
	stream->max_recv_data = TQUIC_DEFAULT_MAX_STREAM_DATA;

	stream->send_offset = 0;
	stream->recv_offset = 0;
	stream->fin_received = false;
	stream->fin_sent = false;

	init_waitqueue_head(&stream->wait);

	pr_debug("tquic: allocated stream id=%llu bidi=%d\n",
		 stream->id, is_bidi);

	return stream;
}

/**
 * tquic_stream_add_to_conn - Add stream to connection's stream tree
 * @conn: Connection
 * @stream: Stream to add
 *
 * Adds stream to the connection's RB-tree for lookup by stream ID.
 * Must be called with appropriate locking.
 */
static void tquic_stream_add_to_conn(struct tquic_connection *conn,
				     struct tquic_stream *stream)
{
	struct rb_node **link = &conn->streams.rb_node;
	struct rb_node *parent = NULL;
	struct tquic_stream *entry;

	spin_lock_bh(&conn->lock);

	while (*link) {
		parent = *link;
		entry = rb_entry(parent, struct tquic_stream, node);

		if (stream->id < entry->id)
			link = &parent->rb_left;
		else
			link = &parent->rb_right;
	}

	rb_link_node(&stream->node, parent, link);
	rb_insert_color(&stream->node, &conn->streams);

	spin_unlock_bh(&conn->lock);
}

/**
 * tquic_stream_remove_from_conn - Remove stream from connection's tree
 * @conn: Connection
 * @stream: Stream to remove
 */
static void tquic_stream_remove_from_conn(struct tquic_connection *conn,
					  struct tquic_stream *stream)
{
	if (!conn || RB_EMPTY_NODE(&stream->node))
		return;

	spin_lock_bh(&conn->lock);
	rb_erase(&stream->node, &conn->streams);
	RB_CLEAR_NODE(&stream->node);
	spin_unlock_bh(&conn->lock);
}

/**
 * tquic_stream_free - Free a stream structure
 * @stream: Stream to free
 *
 * Cleans up stream resources. Should be called after stream is
 * removed from connection and all references are dropped.
 */
static void tquic_stream_free(struct tquic_stream *stream)
{
	if (!stream)
		return;

	/* Purge any remaining buffers */
	skb_queue_purge(&stream->send_buf);
	skb_queue_purge(&stream->recv_buf);

	pr_debug("tquic: freed stream id=%llu\n", stream->id);

	kfree(stream);
}

/**
 * tquic_stream_send_fin - Send FIN to gracefully close stream send side
 * @conn: Parent connection
 * @stream: Stream to close
 *
 * RFC 9000 Section 3.3: Signals that no more data will be sent on this stream.
 * Sends a STREAM frame with FIN bit set (and no data payload).
 *
 * Uses the core tquic_xmit() function from tquic_output.c which handles
 * frame construction, encryption, and transmission.
 *
 * Returns: 0 on success, negative errno on failure
 */
int tquic_stream_send_fin(struct tquic_connection *conn,
			  struct tquic_stream *stream)
{
	int ret;

	if (!conn || !stream)
		return -EINVAL;

	if (stream->fin_sent)
		return 0;  /* Already sent FIN */

	/*
	 * Use tquic_xmit with empty data and fin=true to send a STREAM
	 * frame with only the FIN bit set. This properly handles:
	 * - Frame generation with correct flags
	 * - Path selection
	 * - Encryption and header protection
	 * - Pacing and congestion control
	 */
	ret = tquic_xmit(conn, stream, NULL, 0, true);
	if (ret < 0)
		return ret;

	/* tquic_xmit already updates stream->fin_sent and send_offset */

	/* Update stream state based on bidirectional close status */
	if (stream->fin_received) {
		stream->state = TQUIC_STREAM_CLOSED;
	} else {
		stream->state = TQUIC_STREAM_SEND;  /* Half-closed (local) */
	}

	pr_debug("tquic: sent FIN on stream %llu at offset %llu\n",
		 stream->id, stream->send_offset);

	return 0;
}
EXPORT_SYMBOL_GPL(tquic_stream_send_fin);

/**
 * tquic_stream_lookup - Find a stream by ID in a connection
 * @conn: Connection to search
 * @stream_id: Stream ID to find
 *
 * Returns: Stream pointer on success, NULL if not found
 */
struct tquic_stream *tquic_stream_lookup(struct tquic_connection *conn,
					 u64 stream_id)
{
	struct rb_node *node;
	struct tquic_stream *stream;

	if (!conn)
		return NULL;

	spin_lock_bh(&conn->lock);

	node = conn->streams.rb_node;
	while (node) {
		stream = rb_entry(node, struct tquic_stream, node);

		if (stream_id < stream->id)
			node = node->rb_left;
		else if (stream_id > stream->id)
			node = node->rb_right;
		else {
			spin_unlock_bh(&conn->lock);
			return stream;
		}
	}

	spin_unlock_bh(&conn->lock);
	return NULL;
}
EXPORT_SYMBOL_GPL(tquic_stream_lookup);

/*
 * =============================================================================
 * STREAM SOCKET OPERATIONS
 * =============================================================================
 */

/**
 * tquic_stream_socket_create - Create a new stream socket
 * @conn: Parent connection
 * @parent_sk: Connection socket
 * @flags: Stream type flags (TQUIC_STREAM_BIDI or TQUIC_STREAM_UNIDI)
 * @stream_id: OUT - Assigned stream ID
 *
 * Creates a new stream on the connection and returns a file descriptor.
 * The stream socket is first-class and supports poll/epoll/select.
 *
 * Returns: File descriptor on success, negative errno on failure
 */
int tquic_stream_socket_create(struct tquic_connection *conn,
			       struct sock *parent_sk,
			       u32 flags, u64 *stream_id)
{
	struct socket *sock;
	struct tquic_stream_sock *ss;
	struct tquic_stream *stream;
	bool is_bidi;
	int fd, err;

	if (!conn || !parent_sk || !stream_id)
		return -EINVAL;

	is_bidi = !(flags & TQUIC_STREAM_UNIDI);

	/* Allocate stream structure */
	stream = tquic_stream_alloc(conn, is_bidi);
	if (!stream)
		return -ENOMEM;

	/* Create socket structure */
	err = sock_create_kern(sock_net(parent_sk), parent_sk->sk_family,
			       SOCK_STREAM, 0, &sock);
	if (err < 0) {
		tquic_stream_free(stream);
		return err;
	}

	/* Override ops to stream-specific */
	sock->ops = &tquic_stream_ops;

	/* Allocate stream socket state */
	ss = kzalloc(sizeof(*ss), GFP_KERNEL);
	if (!ss) {
		sock_release(sock);
		tquic_stream_free(stream);
		return -ENOMEM;
	}

	/* Link stream to socket state */
	ss->stream = stream;
	ss->conn = conn;
	ss->parent_sk = parent_sk;
	init_waitqueue_head(&ss->wait);

	/* Store stream socket state in sk_user_data */
	sock->sk->sk_user_data = ss;

	/* Add stream to connection's stream tree */
	tquic_stream_add_to_conn(conn, stream);

	/* Get file descriptor for the socket */
	fd = tquic_sock_map_fd(sock, O_CLOEXEC);
	if (fd < 0) {
		/* Note: tquic_sock_map_fd calls sock_release on failure */
		tquic_stream_remove_from_conn(conn, stream);
		kfree(ss);
		tquic_stream_free(stream);
		return fd;
	}

	*stream_id = stream->id;

	pr_debug("tquic: created stream socket, id=%llu fd=%d bidi=%d\n",
		 stream->id, fd, is_bidi);

	return fd;
}
EXPORT_SYMBOL_GPL(tquic_stream_socket_create);

/**
 * tquic_stream_release - Release a stream socket
 * @sock: Socket being released
 *
 * Called when the stream socket's file descriptor is closed.
 * Cleans up the stream and associated resources.
 */
static int tquic_stream_release(struct socket *sock)
{
	struct tquic_stream_sock *ss;
	struct tquic_stream *stream;
	struct tquic_connection *conn;

	if (!sock->sk)
		return 0;

	ss = sock->sk->sk_user_data;
	if (!ss)
		return 0;

	stream = ss->stream;
	conn = ss->conn;

	if (stream && conn) {
		/* Send FIN if not already sent and stream is still writable */
		if (!stream->fin_sent &&
		    (stream->state == TQUIC_STREAM_OPEN ||
		     stream->state == TQUIC_STREAM_SEND)) {
			tquic_stream_send_fin(conn, stream);
		}

		/* Remove from connection's stream tree */
		tquic_stream_remove_from_conn(conn, stream);

		tquic_stream_free(stream);
	}

	sock->sk->sk_user_data = NULL;
	kfree(ss);

	return 0;
}

/**
 * tquic_stream_sendmsg - Send data on stream socket
 * @sock: Stream socket
 * @msg: Message to send
 * @len: Length of data
 *
 * Copies data to stream's send buffer and triggers transmission.
 *
 * Returns: Number of bytes sent on success, negative errno on failure
 */
static int tquic_stream_sendmsg(struct socket *sock, struct msghdr *msg,
				size_t len)
{
	struct tquic_stream_sock *ss;
	struct tquic_stream *stream;
	struct tquic_connection *conn;
	struct sk_buff *skb;
	size_t copied = 0;

	if (!sock->sk)
		return -ENOTCONN;

	ss = sock->sk->sk_user_data;
	if (!ss || !ss->stream || !ss->conn)
		return -ENOTCONN;

	stream = ss->stream;
	conn = ss->conn;

	/* Check stream and connection state */
	if (stream->state == TQUIC_STREAM_CLOSED ||
	    stream->state == TQUIC_STREAM_RESET_SENT)
		return -EPIPE;

	if (conn->state != TQUIC_CONN_CONNECTED)
		return -ENOTCONN;

	/* Copy data to stream send buffer in chunks */
	while (copied < len) {
		size_t chunk = min_t(size_t, len - copied, 1200);

		skb = alloc_skb(chunk, GFP_KERNEL);
		if (!skb)
			return copied > 0 ? copied : -ENOMEM;

		if (copy_from_iter(skb_put(skb, chunk), chunk,
				   &msg->msg_iter) != chunk) {
			kfree_skb(skb);
			return copied > 0 ? copied : -EFAULT;
		}

		skb_queue_tail(&stream->send_buf, skb);
		stream->send_offset += chunk;
		copied += chunk;
	}

	/* Trigger transmission (stub in Phase 2, full impl Phase 3) */
	tquic_output_flush(conn);

	return copied;
}

/**
 * tquic_stream_recvmsg - Receive data from stream socket
 * @sock: Stream socket
 * @msg: Message buffer
 * @len: Maximum length to receive
 * @flags: Receive flags (MSG_DONTWAIT, MSG_PEEK, etc.)
 *
 * Copies data from stream's receive buffer to user space.
 * Blocks if no data available (unless MSG_DONTWAIT set).
 *
 * Returns: Number of bytes received on success, negative errno on failure
 */
static int tquic_stream_recvmsg(struct socket *sock, struct msghdr *msg,
				size_t len, int flags)
{
	struct tquic_stream_sock *ss;
	struct tquic_stream *stream;
	struct sk_buff *skb;
	size_t copied = 0;
	int err;

	if (!sock->sk)
		return -ENOTCONN;

	ss = sock->sk->sk_user_data;
	if (!ss || !ss->stream)
		return -ENOTCONN;

	stream = ss->stream;

	/* Wait for data if blocking */
	while (skb_queue_empty(&stream->recv_buf)) {
		if (stream->fin_received)
			return 0;  /* EOF */

		if (stream->state == TQUIC_STREAM_CLOSED ||
		    stream->state == TQUIC_STREAM_RESET_RECVD)
			return -ECONNRESET;

		if (flags & MSG_DONTWAIT)
			return -EAGAIN;

		err = wait_event_interruptible(ss->wait,
				!skb_queue_empty(&stream->recv_buf) ||
				stream->fin_received ||
				stream->state == TQUIC_STREAM_CLOSED ||
				stream->state == TQUIC_STREAM_RESET_RECVD);
		if (err)
			return -EINTR;
	}

	/* Copy data from receive buffer */
	while (copied < len && !skb_queue_empty(&stream->recv_buf)) {
		size_t chunk;

		skb = skb_dequeue(&stream->recv_buf);
		if (!skb)
			break;

		chunk = min_t(size_t, len - copied, skb->len);

		if (copy_to_iter(skb->data, chunk, &msg->msg_iter) != chunk) {
			/* Put skb back at head on error */
			skb_queue_head(&stream->recv_buf, skb);
			return copied > 0 ? copied : -EFAULT;
		}

		copied += chunk;
		stream->recv_offset += chunk;

		if (chunk < skb->len) {
			/* Partial read, put remainder back */
			skb_pull(skb, chunk);
			skb_queue_head(&stream->recv_buf, skb);
		} else {
			kfree_skb(skb);
		}
	}

	return copied;
}

/**
 * tquic_stream_poll - Poll for stream socket events
 * @file: File structure
 * @sock: Stream socket
 * @wait: Poll table
 *
 * Returns poll mask indicating readable/writable/error state.
 */
static __poll_t tquic_stream_poll(struct file *file, struct socket *sock,
				  poll_table *wait)
{
	struct tquic_stream_sock *ss;
	struct tquic_stream *stream;
	__poll_t mask = 0;

	if (!sock->sk)
		return EPOLLERR;

	ss = sock->sk->sk_user_data;
	if (!ss || !ss->stream)
		return EPOLLERR;

	stream = ss->stream;

	poll_wait(file, &ss->wait, wait);

	/* Check for readable data */
	if (!skb_queue_empty(&stream->recv_buf) || stream->fin_received)
		mask |= EPOLLIN | EPOLLRDNORM;

	/* Check for writable (flow control permitting) */
	if (stream->send_offset < stream->max_send_data &&
	    stream->state == TQUIC_STREAM_OPEN)
		mask |= EPOLLOUT | EPOLLWRNORM;

	/* Check for errors/hangup */
	if (stream->state == TQUIC_STREAM_CLOSED ||
	    stream->state == TQUIC_STREAM_RESET_RECVD)
		mask |= EPOLLHUP;

	if (stream->state == TQUIC_STREAM_RESET_SENT ||
	    stream->state == TQUIC_STREAM_RESET_RECVD)
		mask |= EPOLLERR;

	return mask;
}

/**
 * tquic_stream_wake - Wake up waiters on stream socket
 * @stream: Stream with incoming data or state change
 *
 * Called from packet input path when data arrives on a stream
 * or stream state changes.
 */
void tquic_stream_wake(struct tquic_stream *stream)
{
	/*
	 * The wait queue is in the tquic_stream_sock associated with
	 * the stream. Since we don't have a direct link from stream
	 * to stream_sock, we use the stream's own wait queue.
	 */
	if (stream)
		wake_up_interruptible(&stream->wait);
}
EXPORT_SYMBOL_GPL(tquic_stream_wake);

/**
 * tquic_wait_for_stream_credit - Wait until stream can be opened
 * @conn: Connection
 * @is_bidi: True for bidirectional, false for unidirectional
 * @nonblock: True if O_NONBLOCK set
 *
 * Blocks until peer grants more streams via MAX_STREAMS frame.
 * Returns immediately if stream credit is available.
 *
 * Returns: 0 when stream can be opened, negative errno on failure
 */
int tquic_wait_for_stream_credit(struct tquic_connection *conn,
				 bool is_bidi, bool nonblock)
{
	u64 next_id, max_streams;

	if (!conn)
		return -ENOTCONN;

	spin_lock_bh(&conn->lock);

	if (is_bidi) {
		next_id = conn->next_stream_id_bidi;
		max_streams = conn->max_streams_bidi;
	} else {
		next_id = conn->next_stream_id_uni;
		max_streams = conn->max_streams_uni;
	}

	spin_unlock_bh(&conn->lock);

	/*
	 * Stream IDs increment by 4. The next stream ID divided by 4
	 * gives the number of streams we've opened. Compare against
	 * peer's MAX_STREAMS limit.
	 */
	if ((next_id >> 2) < max_streams)
		return 0;  /* Credit available */

	/* Would need to block */
	if (nonblock)
		return -EAGAIN;

	/*
	 * Block waiting for MAX_STREAMS from peer.
	 * Use connection's socket wait queue.
	 */
	if (!conn->sk)
		return -ENOTCONN;

	return wait_event_interruptible(conn->sk->sk_wq->wait,
			((is_bidi ? conn->next_stream_id_bidi :
				    conn->next_stream_id_uni) >> 2) <
			(is_bidi ? conn->max_streams_bidi :
				   conn->max_streams_uni) ||
			conn->state != TQUIC_CONN_CONNECTED);
}
EXPORT_SYMBOL_GPL(tquic_wait_for_stream_credit);

/*
 * =============================================================================
 * HTTP/3 STREAM INTEGRATION
 * =============================================================================
 *
 * These functions integrate HTTP/3 stream semantics with the QUIC stream layer.
 * When HTTP/3 mode is enabled on a connection, streams follow RFC 9114 rules:
 *
 * Stream ID Encoding (RFC 9000 Section 2.1):
 *   - Bits 0-1: Type (0=client bidi, 1=server bidi, 2=client uni, 3=server uni)
 *   - Client-initiated bidi (request streams): 0, 4, 8, 12, ...
 *   - Server-initiated bidi: 1, 5, 9, 13, ... (not used in HTTP/3)
 *   - Client-initiated uni: 2, 6, 10, 14, ...
 *   - Server-initiated uni: 3, 7, 11, 15, ...
 *
 * HTTP/3 Stream Types (RFC 9114 Section 6.2):
 *   Unidirectional streams start with a type byte:
 *   - 0x00: Control stream (one per endpoint, required)
 *   - 0x01: Push stream (server to client only)
 *   - 0x02: QPACK Encoder stream
 *   - 0x03: QPACK Decoder stream
 */

/**
 * tquic_stream_is_http3_request - Check if stream is an HTTP/3 request stream
 * @stream: Stream to check
 *
 * HTTP/3 request streams are client-initiated bidirectional streams
 * (stream IDs: 0, 4, 8, 12, ...).
 *
 * Return: true if this is a request stream
 */
bool tquic_stream_is_http3_request(struct tquic_stream *stream)
{
	if (!stream)
		return false;

	/* Request streams are client-initiated bidirectional */
	return h3_stream_id_is_request(stream->id);
}
EXPORT_SYMBOL_GPL(tquic_stream_is_http3_request);

/**
 * tquic_stream_validate_http3_id - Validate stream ID for HTTP/3 semantics
 * @conn: Connection
 * @stream_id: Stream ID to validate
 * @is_local: True if locally initiated
 *
 * Validates that the stream ID follows HTTP/3 rules:
 *   - Client-initiated bidi streams: 0, 4, 8, 12, ...
 *   - Server cannot initiate bidi streams in HTTP/3
 *
 * Return: 0 on success, -H3_STREAM_CREATION_ERROR on failure
 */
int tquic_stream_validate_http3_id(struct tquic_connection *conn,
				   u64 stream_id, bool is_local)
{
	bool is_server = (conn->role == TQUIC_ROLE_SERVER);
	bool is_bidi = h3_stream_id_is_bidi(stream_id);
	bool is_client_initiated = h3_stream_id_is_client_initiated(stream_id);

	/* Validate bidirectional stream ownership */
	if (is_bidi) {
		if (is_local && is_server) {
			/*
			 * Server cannot initiate bidi streams in HTTP/3.
			 * Server uses push streams (unidirectional) instead.
			 */
			pr_err("tquic: server cannot open bidi stream in HTTP/3\n");
			return -H3_STREAM_CREATION_ERROR;
		}

		/* Validate client-initiated bidi stream ID sequence */
		if (is_client_initiated) {
			if ((stream_id & 0x03) != 0x00) {
				pr_err("tquic: invalid request stream ID %llu\n",
				       stream_id);
				return -H3_STREAM_CREATION_ERROR;
			}
		}
	}

	return 0;
}
EXPORT_SYMBOL_GPL(tquic_stream_validate_http3_id);

/**
 * tquic_stream_get_http3_type - Get HTTP/3 type for unidirectional stream
 * @stream: Unidirectional stream
 *
 * For unidirectional streams, the type is determined by the first byte
 * sent/received on the stream.
 *
 * Return: Stream type (0-3), or -1 if not yet known or not unidirectional
 */
int tquic_stream_get_http3_type(struct tquic_stream *stream)
{
	if (!stream)
		return -1;

	/* Bidirectional streams don't have a type byte */
	if (h3_stream_id_is_bidi(stream->id))
		return -1;

	/*
	 * The HTTP/3 stream type is stored in the stream's extended state.
	 * If not yet received, return -1 to indicate pending.
	 */
	if (!stream->ext)
		return -1;

	/* Type is stored in lower bits of priority field (reused for HTTP/3) */
	return stream->priority;
}
EXPORT_SYMBOL_GPL(tquic_stream_get_http3_type);

/**
 * tquic_stream_set_http3_type - Set HTTP/3 type for unidirectional stream
 * @stream: Unidirectional stream
 * @type: Stream type (H3_STREAM_TYPE_CONTROL, etc.)
 *
 * Sets the HTTP/3 stream type. Must be called before sending any data
 * on an outgoing unidirectional stream.
 *
 * Return: 0 on success, negative error
 */
int tquic_stream_set_http3_type(struct tquic_stream *stream, u8 type)
{
	if (!stream)
		return -EINVAL;

	if (h3_stream_id_is_bidi(stream->id)) {
		pr_err("tquic: cannot set type on bidirectional stream\n");
		return -EINVAL;
	}

	if (type > H3_STREAM_TYPE_QPACK_DECODER &&
	    !H3_STREAM_TYPE_IS_GREASE(type)) {
		pr_err("tquic: invalid HTTP/3 stream type %u\n", type);
		return -EINVAL;
	}

	stream->priority = type;

	pr_debug("tquic: set HTTP/3 stream type %s on id=%llu\n",
		 h3_stream_type_name(type), stream->id);

	return 0;
}
EXPORT_SYMBOL_GPL(tquic_stream_set_http3_type);

/**
 * tquic_stream_is_http3_critical - Check if stream is HTTP/3 critical
 * @stream: Stream to check
 *
 * Critical streams (Control, QPACK Encoder, QPACK Decoder) must not be
 * closed before the connection closes. Closing a critical stream results
 * in H3_CLOSED_CRITICAL_STREAM error.
 *
 * Return: true if stream is critical
 */
bool tquic_stream_is_http3_critical(struct tquic_stream *stream)
{
	int type;

	if (!stream)
		return false;

	if (h3_stream_id_is_bidi(stream->id))
		return false;

	type = tquic_stream_get_http3_type(stream);
	if (type < 0)
		return false;

	return h3_stream_type_is_critical(type);
}
EXPORT_SYMBOL_GPL(tquic_stream_is_http3_critical);

/**
 * tquic_stream_lookup_by_id - Look up stream by ID in connection
 * @conn: Connection to search
 * @stream_id: Stream ID to find
 *
 * Searches the connection's stream RB-tree for a stream with the given ID.
 *
 * Return: Stream if found, NULL otherwise
 */
struct tquic_stream *tquic_stream_lookup_by_id(struct tquic_connection *conn,
					       u64 stream_id)
{
	struct rb_node *node;

	if (!conn)
		return NULL;

	spin_lock_bh(&conn->lock);

	node = conn->streams.rb_node;
	while (node) {
		struct tquic_stream *stream;

		stream = rb_entry(node, struct tquic_stream, node);

		if (stream_id < stream->id)
			node = node->rb_left;
		else if (stream_id > stream->id)
			node = node->rb_right;
		else {
			spin_unlock_bh(&conn->lock);
			return stream;
		}
	}

	spin_unlock_bh(&conn->lock);
	return NULL;
}
EXPORT_SYMBOL_GPL(tquic_stream_lookup_by_id);

/**
 * tquic_stream_count_by_type - Count streams of a given HTTP/3 type
 * @conn: Connection to search
 * @type: HTTP/3 stream type to count
 *
 * Counts the number of unidirectional streams with the given HTTP/3 type.
 * Used to enforce "one control stream per endpoint" rule.
 *
 * Return: Number of streams matching the type
 */
int tquic_stream_count_by_type(struct tquic_connection *conn, u8 type)
{
	struct rb_node *node;
	int count = 0;

	if (!conn)
		return 0;

	spin_lock_bh(&conn->lock);

	for (node = rb_first(&conn->streams); node; node = rb_next(node)) {
		struct tquic_stream *stream;

		stream = rb_entry(node, struct tquic_stream, node);

		/* Only count unidirectional streams */
		if (!h3_stream_id_is_uni(stream->id))
			continue;

		if (stream->priority == type)
			count++;
	}

	spin_unlock_bh(&conn->lock);

	return count;
}
EXPORT_SYMBOL_GPL(tquic_stream_count_by_type);
