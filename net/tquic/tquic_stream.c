// SPDX-License-Identifier: GPL-2.0-only
/*
 * TQUIC: Stream Socket Implementation
 *
 * Copyright (c) 2026 Linux Foundation
 * Kernel implementation by Justin Adams <spotty118@gmail.com>
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
#include "tquic_debug.h"
#include "http3/http3_stream.h"

/* Forward declaration for pacing integration (defined in tquic_output.c) */
extern void tquic_update_pacing(struct sock *sk, struct tquic_path *path);

/* Slab cache for stream objects -- defined in tquic_main.c */
extern struct kmem_cache *tquic_stream_cache;

/*
 * =============================================================================
 * SOCKET MEMORY ACCOUNTING
 * =============================================================================
 *
 * TQUIC implements proper socket memory accounting to integrate with the
 * kernel's memory pressure mechanisms (sk_mem_charge/sk_mem_uncharge).
 * This ensures:
 *
 * - Per-socket write buffer limits (sk_sndbuf / sk_wmem_alloc)
 * - Per-socket read buffer limits (sk_rcvbuf / sk_rmem_alloc)
 * - System-wide memory pressure tracking (sysctl_tquic_mem)
 * - Proper interaction with poll/epoll for write availability
 *
 * Memory is charged when data is buffered for transmission and uncharged
 * when data is consumed by the application or freed.
 */

/**
 * tquic_stream_wmem_charge - Charge memory for send buffer
 * @sk: Parent socket (connection socket for accounting)
 * @skb: SKB being added to send buffer
 *
 * Called when adding data to stream send buffer. Charges against the
 * connection socket's write memory.
 *
 * Returns: 0 on success, -ENOBUFS if memory limit exceeded
 */
static int tquic_stream_wmem_charge(struct sock *sk, struct sk_buff *skb)
{
	int amt = skb->truesize;

	if (!sk)
		return 0;

	/* Check if we have room in socket's send buffer */
	if (sk_wmem_schedule(sk, amt)) {
		sk_mem_charge(sk, amt);
		/*
		 * Use skb_set_owner_w() instead of atomic_add() on sk_wmem_alloc.
		 * Modern kernels (6.x) changed sk_wmem_alloc from atomic_t to
		 * refcount_t. skb_set_owner_w() properly handles the accounting
		 * and sets up the skb destructor to decrement on free.
		 */
		skb_set_owner_w(skb, sk);
		return 0;
	}

	return -ENOBUFS;
}

/**
 * tquic_stream_wmem_uncharge - Uncharge memory from send buffer
 * @sk: Parent socket
 * @skb: SKB being removed from send buffer
 *
 * Called when stream data has been acknowledged and can be freed.
 */
static void tquic_stream_wmem_uncharge(struct sock *sk, struct sk_buff *skb)
{
	int amt = skb->truesize;

	if (!sk)
		return;

	sk_mem_uncharge(sk, amt);
	/*
	 * Note: sk_wmem_alloc decrement is handled by the skb destructor
	 * set by skb_set_owner_w() in tquic_stream_wmem_charge().
	 * Modern kernels (6.x) use refcount_t for sk_wmem_alloc, so we
	 * cannot use atomic_sub() directly. The kfree_skb() call after
	 * this function will invoke the destructor.
	 */

	/* Wake up writers if socket was previously blocked */
	if (sk_stream_wspace(sk) > 0)
		sk->sk_write_space(sk);
}

/**
 * tquic_stream_rmem_charge - Charge memory for receive buffer
 * @sk: Parent socket
 * @skb: SKB being added to receive buffer
 *
 * Called when receiving data into stream buffer.
 *
 * Returns: 0 on success, -ENOBUFS if memory limit exceeded
 */
static int __maybe_unused tquic_stream_rmem_charge(struct sock *sk, struct sk_buff *skb)
{
	int amt = skb->truesize;

	if (!sk)
		return 0;

	/*
	 * Check receive buffer limits.
	 * Use sk_rmem_alloc_get() for kernel 6.12+ compatibility.
	 */
	if (sk_rmem_alloc_get(sk) + amt > sk->sk_rcvbuf)
		return -ENOBUFS;

	sk_mem_charge(sk, amt);
	/*
	 * Use skb_set_owner_r() instead of atomic_add() on sk_rmem_alloc.
	 * This properly handles refcount_t and sets up the skb destructor
	 * to decrement on free.
	 */
	skb_set_owner_r(skb, sk);
	return 0;
}

/**
 * tquic_stream_rmem_uncharge - Uncharge memory from receive buffer
 * @sk: Parent socket
 * @skb: SKB being consumed from receive buffer
 *
 * Called when application reads data from stream.
 */
static void tquic_stream_rmem_uncharge(struct sock *sk, struct sk_buff *skb)
{
	int amt = skb->truesize;

	if (!sk)
		return;

	sk_mem_uncharge(sk, amt);
	/*
	 * Note: sk_rmem_alloc decrement is handled by the skb destructor
	 * set by skb_set_owner_r() in tquic_stream_rmem_charge().
	 * Modern kernels (6.x) use refcount_t for sk_rmem_alloc, so we
	 * cannot use atomic_sub() directly. The kfree_skb() call after
	 * this function will invoke the destructor.
	 */
}

/**
 * tquic_stream_purge_wmem - Purge send buffer with memory accounting
 * @sk: Parent socket
 * @queue: SKB queue to purge
 *
 * Purges all SKBs from send buffer and properly uncharges memory.
 */
static void tquic_stream_purge_wmem(struct sock *sk, struct sk_buff_head *queue)
{
	struct sk_buff *skb;

	while ((skb = skb_dequeue(queue)) != NULL) {
		tquic_stream_wmem_uncharge(sk, skb);
		kfree_skb(skb);
	}
}

/**
 * tquic_stream_purge_rmem - Purge receive buffer with memory accounting
 * @sk: Parent socket
 * @queue: SKB queue to purge
 *
 * Purges all SKBs from receive buffer and properly uncharges memory.
 */
static void tquic_stream_purge_rmem(struct sock *sk, struct sk_buff_head *queue)
{
	struct sk_buff *skb;

	while ((skb = skb_dequeue(queue)) != NULL) {
		tquic_stream_rmem_uncharge(sk, skb);
		kfree_skb(skb);
	}
}

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

	stream = kmem_cache_zalloc(tquic_stream_cache, GFP_KERNEL);
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
	refcount_set(&stream->refcount, 1);

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

	tquic_dbg("allocated stream id=%llu bidi=%d\n",
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
	struct sock *sk;
	u64 queued = 0;
	struct sk_buff *skb_iter;

	if (!stream)
		return;

	/* Decrement per-type stream counter */
	if (stream->conn && h3_stream_id_is_uni(stream->id) &&
	    stream->priority < TQUIC_H3_STREAM_TYPE_MAX)
		stream->conn->h3_uni_stream_count[stream->priority]--;

	/*
	 * Get the parent socket for memory accounting.
	 * If the connection or socket is already gone, fall back
	 * to simple purge without memory accounting.
	 */
	sk = (stream->conn) ? stream->conn->sk : NULL;

	/*
	 * If we're dropping queued send data, release its connection-level flow
	 * control reservation so future sends on the same connection aren't
	 * artificially blocked.
	 */
	if (stream->conn) {
		spin_lock_bh(&stream->conn->lock);
		spin_lock_bh(&stream->send_buf.lock);
		skb_queue_walk(&stream->send_buf, skb_iter)
			queued += skb_iter->len;
		spin_unlock_bh(&stream->send_buf.lock);

		if (queued) {
			if (stream->conn->fc_data_reserved >= queued)
				stream->conn->fc_data_reserved -= queued;
			else
				stream->conn->fc_data_reserved = 0;
		}
		spin_unlock_bh(&stream->conn->lock);
	}

	/* Purge any remaining buffers with proper memory accounting */
	if (sk) {
		tquic_stream_purge_wmem(sk, &stream->send_buf);
		tquic_stream_purge_rmem(sk, &stream->recv_buf);
	} else {
		/* Fallback: no socket available, just purge */
		skb_queue_purge(&stream->send_buf);
		skb_queue_purge(&stream->recv_buf);
	}

	tquic_dbg("freed stream id=%llu\n", stream->id);

	kmem_cache_free(tquic_stream_cache, stream);
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

	tquic_dbg("sent FIN on stream %llu at offset %llu\n",
		 stream->id, stream->send_offset);

	return 0;
}
EXPORT_SYMBOL_GPL(tquic_stream_send_fin);

/**
 * tquic_stream_get - Take a reference on a stream
 * @stream: Stream to reference
 *
 * Returns: true if reference was taken, false if stream is being freed
 */
bool tquic_stream_get(struct tquic_stream *stream)
{
	return refcount_inc_not_zero(&stream->refcount);
}
EXPORT_SYMBOL_GPL(tquic_stream_get);

/**
 * tquic_stream_put - Release a stream reference
 * @stream: Stream to release
 *
 * When the last reference is dropped, the stream is freed.
 */
void tquic_stream_put(struct tquic_stream *stream)
{
	if (refcount_dec_and_test(&stream->refcount))
		tquic_stream_free(stream);
}
EXPORT_SYMBOL_GPL(tquic_stream_put);

/**
 * tquic_conn_stream_lookup - Find a stream by ID in a connection
 * @conn: Connection to search
 * @stream_id: Stream ID to find
 *
 * This version searches directly via the connection's rb-tree.
 * Takes a reference on the returned stream; caller must call
 * tquic_stream_put() when done.
 *
 * Returns: Stream pointer on success (with ref taken), NULL if not found
 */
struct tquic_stream *tquic_conn_stream_lookup(struct tquic_connection *conn,
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
			if (!tquic_stream_get(stream))
				stream = NULL;
			spin_unlock_bh(&conn->lock);
			return stream;
		}
	}

	spin_unlock_bh(&conn->lock);
	return NULL;
}
EXPORT_SYMBOL_GPL(tquic_conn_stream_lookup);

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

	/*
	 * Get file descriptor BEFORE linking sk_user_data and adding
	 * the stream to the connection tree.  tquic_sock_map_fd() calls
	 * sock_release() on failure, which invokes tquic_stream_release().
	 * If sk_user_data were already set, the release handler would
	 * free ss and stream, and then this error path would free them
	 * again -- a double-free.
	 */
	fd = tquic_sock_map_fd(sock, O_CLOEXEC);
	if (fd < 0) {
		/* sock was released by tquic_sock_map_fd on failure */
		kfree(ss);
		tquic_stream_free(stream);
		return fd;
	}

	/* Socket has a valid fd now -- safe to link everything */
	sock->sk->sk_user_data = ss;
	tquic_stream_add_to_conn(conn, stream);

	*stream_id = stream->id;

	tquic_dbg("created stream socket, id=%llu fd=%d bidi=%d\n",
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
		/*
		 * Take a connection refcount to ensure the connection
		 * stays alive while we clean up the stream.
		 */
		if (!tquic_conn_get(conn)) {
			/*
			 * CF-635: Connection is being destroyed.
			 * Still free the stream to avoid a leak.
			 */
			tquic_stream_free(stream);
			goto out;
		}

		/* Send FIN if not already sent and stream is still writable */
		if (!stream->fin_sent &&
		    (stream->state == TQUIC_STREAM_OPEN ||
		     stream->state == TQUIC_STREAM_SEND)) {
			tquic_stream_send_fin(conn, stream);
		}

		/* Remove from connection's stream tree */
		tquic_stream_remove_from_conn(conn, stream);

		tquic_stream_free(stream);
		tquic_conn_put(conn);
	}

out:
	sock->sk->sk_user_data = NULL;
	kfree(ss);

	return 0;
}

/**
 * tquic_stream_check_flow_control - Check if stream can send more data
 * @conn: Connection
 * @stream: Stream to check
 * @len: Bytes we want to send
 *
 * Checks both stream-level and connection-level flow control limits.
 * Returns the number of bytes allowed to send (may be less than requested).
 * Returns 0 if blocked (caller should wait or return -EAGAIN).
 */
static size_t tquic_stream_check_flow_control(struct tquic_connection *conn,
					      struct tquic_stream *stream,
					      size_t len)
{
	size_t allowed = len;
	u64 stream_limit, conn_limit;

	/*
	 * CF-297: Hold conn->lock across both stream-level and
	 * connection-level flow control checks to prevent TOCTOU
	 * races with concurrent sendmsg() on other streams sharing
	 * the same connection-level limit.
	 */
	spin_lock_bh(&conn->lock);

	/* Check stream-level flow control */
	if (stream->send_offset >= stream->max_send_data) {
		stream->blocked = true;
		spin_unlock_bh(&conn->lock);
		return 0;
	}

	stream_limit = stream->max_send_data - stream->send_offset;
	if (allowed > stream_limit)
		allowed = stream_limit;

	/* Check connection-level flow control */
	if (conn->data_sent + conn->fc_data_reserved >= conn->max_data_remote) {
		spin_unlock_bh(&conn->lock);
		return 0;
	}

	conn_limit = conn->max_data_remote - (conn->data_sent + conn->fc_data_reserved);
	if (allowed > conn_limit)
		allowed = conn_limit;

	spin_unlock_bh(&conn->lock);

	return allowed;
}

/**
 * tquic_stream_trigger_output - Trigger packet transmission after stream write
 * @conn: Connection with pending stream data
 * @stream: Stream that has new data
 * @sock: Socket (for pacing rate updates)
 *
 * This function implements the critical transmission trigger that ensures
 * data written to streams is actually transmitted. It performs:
 *
 * 1. Connection state validation
 * 2. Path selection for multipath WAN bonding
 * 3. Congestion window check
 * 4. Pacing integration (FQ qdisc or internal pacing)
 * 5. Direct transmission or work scheduling
 *
 * The trigger respects the TQUIC_NODELAY socket option for latency-sensitive
 * applications and integrates with the timer/recovery subsystem for proper
 * retransmission handling.
 */
static void tquic_stream_trigger_output(struct tquic_connection *conn,
					struct tquic_stream *stream,
					struct sock *sk)
{
	struct tquic_path *path;
	struct tquic_sock *tsk;
	struct net *net = NULL;
	u64 inflight;
	bool can_send;
	bool pacing_enabled = true;

	if (!conn || READ_ONCE(conn->state) != TQUIC_CONN_CONNECTED)
		return;

	/* Get socket options if available */
	if (sk) {
		tsk = tquic_sk(sk);
		net = sock_net(sk);
		if (net) {
			struct tquic_net *tn = tquic_pernet(net);
			if (tn)
				pacing_enabled = tn->pacing_enabled;
		}
	}

	/* Select the best path for transmission */
	path = tquic_select_path(conn, NULL);
	if (!path || path->state != TQUIC_PATH_ACTIVE) {
		/*
		 * No active path available. The timer subsystem will
		 * handle retransmission when a path becomes available.
		 */
		tquic_dbg("no active path for stream %llu transmission\n",
			 stream->id);
		return;
	}

	/*
	 * Check congestion window before attempting transmission.
	 * If cwnd is exhausted, data will be sent when ACKs arrive
	 * and the timer/recovery subsystem processes them.
	 */
	if (path->stats.cwnd > 0) {
		inflight = (path->stats.tx_bytes > path->stats.acked_bytes) ?
			   path->stats.tx_bytes - path->stats.acked_bytes : 0;
		can_send = (inflight < path->stats.cwnd);
	} else {
		/* No cwnd limit set yet (initial state) */
		can_send = true;
	}

	if (!can_send) {
		tquic_dbg("stream %llu blocked by cwnd (inflight=%llu, cwnd=%u)\n",
			 stream->id, inflight, path->stats.cwnd);
		return;
	}

	/*
	 * Pacing integration: Update socket pacing rate for FQ qdisc.
	 * If FQ is attached to the interface, it will handle pacing.
	 * Otherwise, internal pacing in tquic_output.c will be used.
	 */
	if (pacing_enabled && sk)
		tquic_update_pacing(sk, path);

	/*
	 * Transmission strategy:
	 *
	 * NODELAY mode: Transmit immediately via tquic_xmit() for lowest
	 * latency. This is appropriate for interactive applications.
	 *
	 * Normal mode: Use tquic_output_flush() which may coalesce frames
	 * from multiple streams and respect pacing. This is more efficient
	 * for bulk transfers.
	 *
	 * The actual transmission path in tquic_output.c will:
	 * - Generate STREAM frames from the send buffer
	 * - Apply encryption and header protection
	 * - Select path via the scheduler
	 * - Apply pacing if enabled
	 * - Track packets for loss detection/retransmission
	 */
	/*
	 * Always use output_flush for draining stream->send_buf. The previous
	 * "NODELAY direct tquic_xmit(skb->data)" path could duplicate queued data
	 * and race with the flush path.
	 */
	tquic_output_flush(conn);

	/*
	 * Schedule retransmission timer if not already running.
	 * The timer subsystem (tquic_timer.c) handles:
	 * - Loss detection timer (for unacked packets)
	 * - PTO timer (probe timeout)
	 * - Pacing timer (for rate-limited sending)
	 *
	 * Timer scheduling is handled internally by tquic_xmit/output_flush.
	 */
}

/**
 * tquic_stream_sendmsg - Send data on stream socket
 * @sock: Stream socket
 * @msg: Message to send
 * @len: Length of data
 *
 * Copies data to stream's send buffer and triggers transmission.
 * Implements flow control, pacing, and proper output scheduling.
 *
 * Flow control is enforced at two levels:
 * - Stream level: Cannot exceed stream->max_send_data
 * - Connection level: Cannot exceed conn->max_data_remote
 *
 * If flow control blocks sending, the function returns -EAGAIN for
 * non-blocking sockets or waits for MAX_STREAM_DATA/MAX_DATA frames
 * for blocking sockets.
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
	size_t allowed;
	bool nonblock;

	if (!sock->sk)
		return -ENOTCONN;

	ss = sock->sk->sk_user_data;
	if (!ss || !ss->stream || !ss->conn)
		return -ENOTCONN;

	stream = ss->stream;
	conn = ss->conn;

	/*
	 * Take a connection refcount so the connection cannot be
	 * destroyed while we are sending.  If the refcount is already
	 * zero the connection is being torn down.
	 */
	if (!tquic_conn_get(conn))
		return -ENOTCONN;

	nonblock = (msg->msg_flags & MSG_DONTWAIT) ||
		   (sock->file->f_flags & O_NONBLOCK);

	/* Check stream and connection state */
	if (stream->state == TQUIC_STREAM_CLOSED ||
	    stream->state == TQUIC_STREAM_RESET_SENT) {
		tquic_conn_put(conn);
		return -EPIPE;
	}

	if (READ_ONCE(conn->state) != TQUIC_CONN_CONNECTED) {
		tquic_conn_put(conn);
		return -ENOTCONN;
	}

	/* Check flow control before copying data */
	allowed = tquic_stream_check_flow_control(conn, stream, len);
	if (allowed == 0) {
		if (nonblock) {
			copied = -EAGAIN;
			goto out_put;
		}

		/*
		 * Block waiting for flow control credit.
		 * MAX_STREAM_DATA or MAX_DATA from peer will wake us.
		 */
		if (wait_event_interruptible(stream->wait,
				tquic_stream_check_flow_control(conn, stream, len) > 0 ||
				stream->state == TQUIC_STREAM_CLOSED ||
				READ_ONCE(conn->state) != TQUIC_CONN_CONNECTED)) {
			copied = -EINTR;
			goto out_put;
		}

		/* Re-check state after waking */
		if (stream->state == TQUIC_STREAM_CLOSED) {
			copied = -EPIPE;
			goto out_put;
		}
		if (READ_ONCE(conn->state) != TQUIC_CONN_CONNECTED) {
			copied = -ENOTCONN;
			goto out_put;
		}

		allowed = tquic_stream_check_flow_control(conn, stream, len);
		if (allowed == 0) {
			copied = -EAGAIN;
			goto out_put;
		}
	}

	/* Limit to flow control allowed amount */
	if (len > allowed)
		len = allowed;

	/* Copy data to stream send buffer in chunks */
	while (copied < len) {
		size_t chunk = min_t(size_t, len - copied, 1200);

		skb = alloc_skb(chunk, GFP_KERNEL);
		if (!skb) {
			if (copied == 0)
				copied = -ENOMEM;
			goto out_put;
		}

		if (copy_from_iter(skb_put(skb, chunk), chunk,
				   &msg->msg_iter) != chunk) {
			kfree_skb(skb);
			if (copied == 0)
				copied = -EFAULT;
			goto out_put;
		}

		/* Charge socket memory for this buffer */
		if (tquic_stream_wmem_charge(ss->parent_sk, skb)) {
			kfree_skb(skb);
			if (copied == 0)
				copied = -ENOBUFS;
			goto out_put;
		}

		/*
		 * Store stream offset in skb->cb for frame generation and reserve
		 * connection-level flow control for queued data (not yet sent).
		 */
		spin_lock_bh(&conn->lock);
		*(u64 *)skb->cb = stream->send_offset;
		stream->send_offset += chunk;
		conn->fc_data_reserved += chunk;
		spin_unlock_bh(&conn->lock);

		skb_queue_tail(&stream->send_buf, skb);
		copied += chunk;
	}

	/*
	 * Trigger transmission for the newly buffered data.
	 * This handles path selection, congestion control, pacing,
	 * and either immediate transmission or work scheduling.
	 */
	tquic_stream_trigger_output(conn, stream, ss->parent_sk);

out_put:
	tquic_conn_put(conn);
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
	struct tquic_connection *conn;
	struct tquic_stream *stream;
	struct sk_buff *skb;
	size_t copied = 0;
	int err;

	if (!sock->sk)
		return -ENOTCONN;

	ss = sock->sk->sk_user_data;
	if (!ss || !ss->stream || !ss->conn)
		return -ENOTCONN;

	stream = ss->stream;
	conn = ss->conn;

	/*
	 * CF-064: Take a connection refcount so the connection (and
	 * thereby the stream) cannot be destroyed while we are
	 * receiving.  If the refcount is already zero the connection
	 * is being torn down.
	 */
	if (!tquic_conn_get(conn))
		return -ENOTCONN;

	/* Wait for data if blocking */
	while (skb_queue_empty(&stream->recv_buf)) {
		if (stream->fin_received) {
			copied = 0;  /* EOF */
			goto out_put;
		}

		if (stream->state == TQUIC_STREAM_CLOSED ||
		    stream->state == TQUIC_STREAM_RESET_RECVD) {
			copied = -ECONNRESET;
			goto out_put;
		}

		if (flags & MSG_DONTWAIT) {
			copied = -EAGAIN;
			goto out_put;
		}

		err = wait_event_interruptible(ss->wait,
				!skb_queue_empty(&stream->recv_buf) ||
				stream->fin_received ||
				stream->state == TQUIC_STREAM_CLOSED ||
				stream->state == TQUIC_STREAM_RESET_RECVD);
		if (err) {
			copied = -EINTR;
			goto out_put;
		}
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
			if (copied == 0)
				copied = -EFAULT;
			goto out_put;
		}

		copied += chunk;
		stream->recv_offset += chunk;

		if (chunk < skb->len) {
			/* Partial read, put remainder back */
			skb_pull(skb, chunk);
			skb_queue_head(&stream->recv_buf, skb);
		} else {
			/* Full skb consumed - uncharge memory and free */
			tquic_stream_rmem_uncharge(ss->parent_sk, skb);
			kfree_skb(skb);
		}
	}

out_put:
	tquic_conn_put(conn);
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
			READ_ONCE(conn->state) != TQUIC_CONN_CONNECTED);
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
			tquic_err("server cannot open bidi stream in HTTP/3\n");
			return -H3_STREAM_CREATION_ERROR;
		}

		/* Validate client-initiated bidi stream ID sequence */
		if (is_client_initiated) {
			if ((stream_id & 0x03) != 0x00) {
				tquic_err("invalid request stream ID %llu\n",
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
		tquic_err("cannot set type on bidirectional stream\n");
		return -EINVAL;
	}

	if (type > H3_STREAM_TYPE_QPACK_DECODER &&
	    !H3_STREAM_TYPE_IS_GREASE(type)) {
		tquic_err("invalid HTTP/3 stream type %u\n", type);
		return -EINVAL;
	}

	stream->priority = type;

	/* Update per-type counter for O(1) stream counting */
	if (type < TQUIC_H3_STREAM_TYPE_MAX && stream->conn)
		stream->conn->h3_uni_stream_count[type]++;

	tquic_dbg("set HTTP/3 stream type %s on id=%llu\n",
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
	if (!conn)
		return 0;

	/* Use O(1) per-type counters for known HTTP/3 stream types */
	if (type < TQUIC_H3_STREAM_TYPE_MAX)
		return conn->h3_uni_stream_count[type];

	return 0;
}
EXPORT_SYMBOL_GPL(tquic_stream_count_by_type);
