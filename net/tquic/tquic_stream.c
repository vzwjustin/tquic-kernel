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
	.setsockopt	= sock_no_setsockopt,
	.getsockopt	= sock_no_getsockopt,
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
	fd = sock_map_fd(sock, O_CLOEXEC);
	if (fd < 0) {
		tquic_stream_remove_from_conn(conn, stream);
		sock->sk->sk_user_data = NULL;
		kfree(ss);
		sock_release(sock);
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
		/* Remove from connection's stream tree */
		tquic_stream_remove_from_conn(conn, stream);

		/*
		 * TODO: Send FIN if not already sent (Phase 3).
		 * For now, just clean up the stream.
		 */

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
