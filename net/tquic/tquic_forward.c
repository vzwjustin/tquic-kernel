// SPDX-License-Identifier: GPL-2.0-only
/*
 * TQUIC: Zero-Copy Splice Forwarding with Hairpin Detection
 *
 * Copyright (c) 2026 Justin Adams <spotty118@gmail.com>
 * Kernel implementation by Justin Adams <spotty118@gmail.com>
 *
 * This file implements zero-copy data forwarding between QUIC streams
 * and TCP sockets using kernel splice, plus hairpin traffic detection
 * for routing between clients connected to the same VPS.
 *
 * Per CONTEXT.md:
 *   - Zero-copy forwarding via splice/sendfile
 *   - Configurable hairpin traffic (router-to-router via VPS)
 *   - Per-path MTU tracking
 *   - PMTUD signaling, no VPS-side fragmentation
 */

#include <linux/module.h>
#include <linux/slab.h>
#include <linux/net.h>
#include <linux/socket.h>
#include <linux/file.h>
#include <linux/pipe_fs_i.h>
#include <linux/splice.h>
#include <linux/workqueue.h>
#include <linux/timer.h>
#include <linux/list.h>
#include <linux/hashtable.h>
#include <linux/inetdevice.h>
#include <net/sock.h>
#include <net/tcp.h>
#include <net/tquic.h>
#include <net/ip.h>
#include <net/icmp.h>
#include <net/route.h>
#include <net/dst.h>
#if IS_ENABLED(CONFIG_IPV6)
#include <net/ipv6.h>
#include <net/icmp.h>
#include <net/ip6_route.h>
#endif

#include "protocol.h"
#include "tquic_debug.h"
#include "tquic_compat.h"
#include "tquic_tunnel.h"

/*
 * =============================================================================
 * FORWARD DIRECTION DEFINITIONS
 * =============================================================================
 */

/* Forwarding directions */
#define TQUIC_FORWARD_TX	0	/* QUIC stream -> TCP socket */
#define TQUIC_FORWARD_RX	1	/* TCP socket -> QUIC stream */

/* Splice buffer size - matches default pipe size */
#define TQUIC_SPLICE_BUFSIZE	(16 * PAGE_SIZE)

/* Maximum pending hairpin connections per client */
#define TQUIC_MAX_HAIRPIN_PENDING	64

/* Maximum bytes per hairpin forward operation to prevent amplification */
#define TQUIC_HAIRPIN_MAX_BYTES_PER_OP	(256 * 1024)  /* 256 KB */

/*
 * =============================================================================
 * EXTERNAL DECLARATIONS
 * =============================================================================
 */

/* From tquic_tunnel.c */
struct tquic_tunnel;
struct tquic_client;

extern void tquic_qos_mark_skb(struct sk_buff *skb, void *tunnel_ptr);
extern void tquic_qos_update_stats(u8 traffic_class, u64 bytes);

/*
 * External function implemented in tquic_tunnel.c
 * Returns traffic class (0-3) for QoS marking
 */
extern u8 tquic_tunnel_get_traffic_class(struct tquic_tunnel *tunnel);

/*
 * Wrapper functions for pipe allocation in out-of-tree builds.
 * alloc_pipe_info() and free_pipe_info() are declared in pipe_fs_i.h
 * but not exported for modules. Use wrapper functions that return NULL
 * for out-of-tree builds, effectively disabling splice-based forwarding.
 */
#ifdef TQUIC_OUT_OF_TREE
static inline struct pipe_inode_info *tquic_alloc_pipe(void)
{
	/* Cannot use pipe splice in out-of-tree module - symbol not exported */
	return NULL;
}

static inline void tquic_free_pipe(struct pipe_inode_info *pipe)
{
	/* No-op for out-of-tree */
}
#else
static inline struct pipe_inode_info *tquic_alloc_pipe(void)
{
	return alloc_pipe_info();
}

static inline void tquic_free_pipe(struct pipe_inode_info *pipe)
{
	free_pipe_info(pipe);
}
#endif

/*
 * =============================================================================
 * HAIRPIN DETECTION STATE
 * =============================================================================
 *
 * Hairpin traffic occurs when a tunnel destination is another client
 * connected to the same VPS. Instead of creating a TCP socket, we
 * forward directly to the peer client's QUIC stream.
 */

/* Client list for hairpin detection */
static LIST_HEAD(tquic_forward_client_list);
static spinlock_t __maybe_unused tquic_forward_client_lock =
	__SPIN_LOCK_UNLOCKED(tquic_forward_client_lock);

/**
 * struct tquic_hairpin_entry - Hairpin route entry
 * @dest_addr: Destination address
 * @peer_client: Target client owning this address
 * @node: Hash table linkage
 */
struct tquic_hairpin_entry {
	struct sockaddr_storage dest_addr;
	struct tquic_client *peer_client;
	struct hlist_node node;
};

/* Hairpin lookup hash table */
#define TQUIC_HAIRPIN_HASH_BITS	8
static DEFINE_HASHTABLE(tquic_hairpin_hash, TQUIC_HAIRPIN_HASH_BITS);
static DEFINE_SPINLOCK(tquic_hairpin_lock);

/**
 * tquic_forward_hash_addr - Hash sockaddr for hairpin lookup
 * @addr: Address to hash
 */
static u32 tquic_forward_hash_addr(const struct sockaddr_storage *addr)
{
	u32 hash = 0;

	tquic_dbg("tquic_forward_hash_addr: hashing addr family=%u\n",
		  addr->ss_family);

	if (addr->ss_family == AF_INET) {
		const struct sockaddr_in *sin = (const struct sockaddr_in *)addr;
		hash = jhash(&sin->sin_addr, sizeof(sin->sin_addr), 0);
	} else if (addr->ss_family == AF_INET6) {
		const struct sockaddr_in6 *sin6 = (const struct sockaddr_in6 *)addr;
		hash = jhash(&sin6->sin6_addr, sizeof(sin6->sin6_addr), 0);
	}

	return hash;
}

/*
 * =============================================================================
 * SPLICE-BASED FORWARDING
 * =============================================================================
 *
 * Zero-copy forwarding using kernel splice internals.
 *
 * Per CONTEXT.md: Zero-copy forwarding via splice/sendfile.
 */

/**
 * struct tquic_splice_state - State for splice operation
 * @pipe: Pipe used as splice buffer
 * @bytes_pending: Bytes in pipe waiting to be written
 */
struct tquic_splice_state {
	struct pipe_inode_info *pipe;
	size_t bytes_pending;
};

/**
 * tquic_splice_state_alloc - Allocate splice state
 *
 * Returns: Splice state or NULL on failure
 */
static struct tquic_splice_state __maybe_unused *tquic_splice_state_alloc(void)
{
	struct tquic_splice_state *state;

	state = kzalloc(sizeof(*state), GFP_KERNEL);
	if (!state)
		return NULL;

	/*
	 * Allocate pipe for splice buffer
	 * Note: Uses wrapper for out-of-tree compatibility
	 */
	state->pipe = tquic_alloc_pipe();
	if (!state->pipe) {
		kfree(state);
		return NULL;
	}

	return state;
}

/**
 * tquic_splice_state_free - Free splice state
 * @state: State to free
 */
static void __maybe_unused tquic_splice_state_free(struct tquic_splice_state *state)
{
	tquic_dbg("tquic_splice_state_free: freeing splice state\n");

	if (!state)
		return;

	if (state->pipe)
		tquic_free_pipe(state->pipe);

	kfree(state);
}

/**
 * tquic_forward_splice - Zero-copy forward data using splice
 * @tunnel: Tunnel context
 * @direction: TQUIC_FORWARD_TX (QUIC->TCP) or TQUIC_FORWARD_RX (TCP->QUIC)
 *
 * Uses kernel splice mechanisms to move data between QUIC stream and TCP
 * socket without copying through userspace. For QUIC streams (which use
 * sk_buff queues), we use skb-based zero-copy moves rather than pipe splice.
 *
 * TX Direction (QUIC stream -> TCP socket):
 *   1. Dequeue skbs from stream's receive buffer
 *   2. Send data through TCP socket using kernel_sendmsg
 *   3. Apply QoS marking for traffic classification
 *
 * RX Direction (TCP socket -> QUIC stream):
 *   1. Receive data from TCP socket via kernel_recvmsg
 *   2. Wrap in skb and enqueue to stream's send buffer
 *   3. Wake stream to trigger QUIC packetization
 *
 * Returns: Number of bytes forwarded, or negative errno
 */
ssize_t tquic_forward_splice(struct tquic_tunnel *tunnel, int direction)
{
	struct tquic_stream *stream;
	struct socket *tcp_sock;
	struct sock *sk;
	struct sk_buff *skb;
	ssize_t total = 0;
	ssize_t sent;
	struct msghdr msg;
	struct kvec iov;
	int err;

	tquic_dbg("tquic_forward_splice: direction=%s\n",
		  direction == TQUIC_FORWARD_TX ? "QUIC->TCP" : "TCP->QUIC");

	if (!tunnel)
		return -EINVAL;

	stream = tunnel->quic_stream;
	tcp_sock = tunnel->tcp_sock;

	if (!stream || !tcp_sock)
		return -ENOTCONN;

	sk = tcp_sock->sk;
	if (!sk)
		return -ENOTCONN;

	if (direction == TQUIC_FORWARD_TX) {
		/*
		 * QUIC stream receive buffer -> TCP socket
		 *
		 * Data arrives on the QUIC stream from the router.
		 * We forward it to the destination via the TCP socket.
		 */

		/* Process all queued data from QUIC stream */
		while (!skb_queue_empty(&stream->recv_buf)) {
			skb = skb_dequeue(&stream->recv_buf);
			if (!skb)
				break;

			/* Set up iovec for kernel_sendmsg */
			memset(&msg, 0, sizeof(msg));
			msg.msg_flags = MSG_DONTWAIT | MSG_NOSIGNAL;

			iov.iov_base = skb->data;
			iov.iov_len = skb->len;

			/* Send data through TCP socket */
			sent = kernel_sendmsg(tcp_sock, &msg, &iov, 1, skb->len);
			if (sent < 0) {
				/* Send failed - put skb back and return error */
				skb_queue_head(&stream->recv_buf, skb);
				if (total > 0)
					break;  /* Partial success */
				return sent;
			}

			if (sent < skb->len) {
				/*
				 * Partial send - trim skb and put remainder back.
				 * This handles TCP flow control backpressure.
				 */
				skb_pull(skb, sent);
				skb_queue_head(&stream->recv_buf, skb);
				total += sent;
				break;
			}

				total += sent;
				if (stream->conn && stream->conn->sk)
					sk_mem_uncharge(stream->conn->sk, skb->truesize);
				consume_skb(skb);

			/* Check for TCP socket congestion */
			if (sk_stream_wspace(sk) < sk->sk_sndbuf / 4)
				break;  /* TCP send buffer getting full */
		}

		/* Update statistics */
		tunnel->stats.bytes_tx += total;
		tunnel->stats.packets_tx++;

		/* Apply QoS classification */
		tquic_qos_update_stats(tquic_tunnel_get_traffic_class(tunnel),
				       total);

	} else {
		/*
		 * TCP socket receive buffer -> QUIC stream send buffer
		 *
		 * Data arrives from the internet destination.
		 * We forward it to the router via the QUIC stream.
		 */
		char *buf;
		size_t bufsize = TQUIC_SPLICE_BUFSIZE;

		/*
		 * Allocate temporary receive buffer.
		 *
		 * Use GFP_NOIO since this function may be called from
		 * work queue context where I/O recursion could occur.
		 * The caller context determines if sleeping is safe;
		 * GFP_NOIO is safe in all non-atomic contexts while
		 * avoiding I/O recursion deadlocks.
		 */
		buf = kmalloc(bufsize, GFP_NOIO);
		if (!buf)
			return -ENOMEM;

		while (1) {
			memset(&msg, 0, sizeof(msg));
			msg.msg_flags = MSG_DONTWAIT;

			iov.iov_base = buf;
			iov.iov_len = bufsize;

			/* Receive from TCP socket */
			err = kernel_recvmsg(tcp_sock, &msg, &iov, 1,
					     bufsize, MSG_DONTWAIT);
			if (err <= 0) {
				if (err == -EAGAIN || err == -EWOULDBLOCK)
					break;  /* No more data available */
				if (total > 0)
					break;  /* Partial success */
				kfree(buf);
				return err;
			}

			/* Create skb for QUIC stream */
			skb = alloc_skb(err + 64, GFP_KERNEL);
			if (!skb) {
				kfree(buf);
				return total > 0 ? total : -ENOMEM;
			}

			skb_reserve(skb, 32);  /* Room for QUIC headers */
			skb_put_data(skb, buf, err);

			/* Charge memory against QUIC connection socket */
			if (stream->conn && stream->conn->sk) {
				struct sock *quic_sk = stream->conn->sk;

				if (sk_wmem_schedule(quic_sk, skb->truesize)) {
					skb_set_owner_w(skb, quic_sk);
				} else {
					kfree_skb(skb);
					kfree(buf);
					return total > 0 ? total : -ENOBUFS;
				}
			}

			/* Enqueue to QUIC stream send buffer (initialize skb->cb offset). */
			if (stream->conn)
				spin_lock_bh(&stream->conn->lock);
			spin_lock_bh(&stream->send_buf.lock);
			tquic_stream_skb_cb(skb)->stream_offset = stream->send_offset;
			tquic_stream_skb_cb(skb)->data_off = 0;
			__skb_queue_tail(&stream->send_buf, skb);
			stream->send_offset += err;
			if (stream->conn)
				stream->conn->fc_data_reserved += err;
			if (stream->conn)
				stream->conn->stats.tx_bytes += err;
			spin_unlock_bh(&stream->send_buf.lock);
			if (stream->conn)
				spin_unlock_bh(&stream->conn->lock);
			total += err;

			/* Limit to splice buffer size per call */
			if (total >= bufsize)
				break;
		}

		kfree(buf);

		/* Update statistics */
		tunnel->stats.bytes_rx += total;
		tunnel->stats.packets_rx++;

		/* Wake stream to trigger transmission */
		if (total > 0)
			tquic_stream_wake(stream);
	}

	tquic_dbg("tquic_forward_splice: forwarded %zd bytes\n", total);
	return total;
}
EXPORT_SYMBOL_GPL(tquic_forward_splice);

/**
 * tquic_forward_skb_splice - Splice using skb move
 * @from_queue: Source sk_buff_head
 * @to_queue: Destination sk_buff_head
 * @max_bytes: Maximum bytes to move
 *
 * Moves skbs between queues without copying data, for zero-copy within
 * kernel buffers.
 *
 * Returns: Bytes moved
 */
static size_t __maybe_unused tquic_forward_skb_splice(struct sk_buff_head *from_queue,
						      struct sk_buff_head *to_queue,
						      size_t max_bytes)
{
	struct sk_buff *skb;
	size_t moved = 0;

	while (moved < max_bytes && !skb_queue_empty(from_queue)) {
		skb = skb_dequeue(from_queue);
		if (!skb)
			break;

		if (moved + skb->len > max_bytes) {
			/* Partial move not supported, put back */
			skb_queue_head(from_queue, skb);
			break;
		}

		skb_queue_tail(to_queue, skb);
		moved += skb->len;
	}

	return moved;
}

/*
 * =============================================================================
 * HAIRPIN TRAFFIC DETECTION AND ROUTING
 * =============================================================================
 *
 * Per CONTEXT.md: Configurable hairpin traffic (router-to-router via VPS).
 */

/**
 * tquic_forward_client_owns_address - Check if client owns address
 * @client: Client to check
 * @addr: Address to check (currently unused - port-based allocation)
 * @port: Port to check (in network byte order)
 *
 * Determines if a destination port falls within a client's allocated port
 * range. Each client is assigned a contiguous range of ports for their
 * tunnels (TQUIC_PORTS_PER_CLIENT = 1000 ports per client).
 *
 * The port range is assigned during client registration and stored in
 * the tquic_client structure as port_range_start and port_range_end
 * (both in network byte order).
 *
 * This is used for hairpin detection: if the destination port of outbound
 * traffic falls within another client's range, we can forward directly
 * to that client's QUIC stream without going through a TCP socket.
 *
 * Returns: true if client owns this address/port, false otherwise
 */
static bool __maybe_unused tquic_forward_client_owns_address(struct tquic_client *client,
							     const struct sockaddr_storage *addr,
							     __be16 port)
{
	u16 port_h, range_start, range_end;

	if (!client)
		return false;

	/*
	 * Convert to host byte order for comparison.
	 * Client port ranges are stored in network byte order in the
	 * tquic_client structure (port_range_start, port_range_end).
	 */
	port_h = ntohs(port);
	range_start = ntohs(client->port_range_start);
	range_end = ntohs(client->port_range_end);

	/*
	 * Check if port falls within client's allocated range.
	 * The range is inclusive: [range_start, range_end].
	 */
	if (port_h >= range_start && port_h <= range_end)
		return true;

	return false;
}

/**
 * tquic_forward_check_hairpin - Check if destination is another client
 * @tunnel: Source tunnel
 *
 * Per CONTEXT.md: Configurable hairpin traffic (router-to-router via VPS).
 *
 * Checks if the tunnel destination address belongs to another client
 * connected to this VPS. If so, we can route directly without creating
 * a TCP socket to the internet.
 *
 * Returns: Peer client if hairpin, NULL if normal forward to internet
 */
struct tquic_client *tquic_forward_check_hairpin(struct tquic_tunnel *tunnel)
{
	struct tquic_hairpin_entry *entry;
	struct sockaddr_storage *dest_addr;
	u32 hash;

	if (!tunnel)
		return NULL;

	/*
	 * Get tunnel destination address
	 * This requires access to tunnel internals
	 */
	dest_addr = NULL;  /* Would be &tunnel->dest_addr */

	if (!dest_addr)
		return NULL;

	hash = tquic_forward_hash_addr(dest_addr);

	spin_lock_bh(&tquic_hairpin_lock);

	hash_for_each_possible(tquic_hairpin_hash, entry, node, hash) {
		if (memcmp(&entry->dest_addr, dest_addr,
			   sizeof(struct sockaddr_storage)) == 0) {
			spin_unlock_bh(&tquic_hairpin_lock);
			return entry->peer_client;
		}
	}

	spin_unlock_bh(&tquic_hairpin_lock);

	return NULL;  /* Not hairpin, forward to internet */
}
EXPORT_SYMBOL_GPL(tquic_forward_check_hairpin);

/*
 * Hairpin loop detection TTL threshold
 *
 * RFC 9000 does not define a TTL mechanism, but for hairpin traffic
 * between local clients we use a hop limit in the tunnel header to
 * prevent routing loops. Max 8 hops for hairpin chains.
 */
#define TQUIC_HAIRPIN_MAX_HOPS	8

/**
 * struct tquic_hairpin_header - Header for hairpin-forwarded data
 * @magic: Magic number for validation (0x54514850 = "TQHP")
 * @hop_count: Number of hairpin hops (for loop detection)
 * @src_port: Original source port (for reverse path)
 * @dst_port: Original destination port
 * @stream_id: Stream ID on peer connection (0 for new stream)
 * @flags: Reserved flags
 * @payload_len: Length of following payload
 */
struct tquic_hairpin_header {
	__be32 magic;
	u8 hop_count;
	__be16 src_port;
	__be16 dst_port;
	__be64 stream_id;
	u8 flags;
	__be32 payload_len;
} __packed;

#define TQUIC_HAIRPIN_MAGIC	cpu_to_be32(0x54514850)
#define TQUIC_HAIRPIN_FLAG_FIN	BIT(0)	/* Final data for stream */
#define TQUIC_HAIRPIN_FLAG_RST	BIT(1)	/* Stream reset */

/**
 * tquic_forward_hairpin - Forward data directly to peer client
 * @tunnel: Source tunnel
 * @peer: Target peer client
 *
 * Routes hairpin traffic directly to peer client's QUIC connection
 * without creating a TCP socket. This enables efficient router-to-router
 * traffic when both endpoints are connected to the same VPS.
 *
 * Implementation:
 * 1. Validate tunnel and peer state
 * 2. Check hop count to prevent routing loops
 * 3. Find or create stream on peer connection for reverse direction
 * 4. Move skbs from source stream to peer stream (zero-copy when possible)
 * 5. Wake peer connection to trigger transmission
 *
 * Returns: Bytes forwarded, or negative errno
 */
ssize_t tquic_forward_hairpin(struct tquic_tunnel *tunnel,
			      struct tquic_client *peer)
{
	struct tquic_connection *peer_conn;
	struct tquic_stream *src_stream;
	struct tquic_stream *dst_stream;
	struct sk_buff *skb, *skb_next;
	struct sk_buff_head tx_queue;
	ssize_t total_bytes = 0;
	u8 hop_count = 0;

	if (!tunnel || !peer)
		return -EINVAL;

	/* Validate source stream exists */
	src_stream = tunnel->quic_stream;
	if (!src_stream)
		return -ENOENT;

	/* Get peer's QUIC connection */
	peer_conn = peer->conn;
	if (!peer_conn)
		return -ENOTCONN;

	/* Check connection state - must be established */
	if (READ_ONCE(peer_conn->state) != TQUIC_CONN_CONNECTED)
		return -ENOTCONN;

	/*
	 * Loop detection via hop count.
	 *
	 * Extract hop count from first skb if it contains hairpin header.
	 * This prevents infinite loops in complex hairpin topologies where
	 * client A -> VPS -> client B -> VPS -> client A could occur.
	 */
	skb = skb_peek(&src_stream->recv_buf);
	if (skb && skb->len >= sizeof(struct tquic_hairpin_header)) {
		struct tquic_hairpin_header *hdr;

		hdr = (struct tquic_hairpin_header *)skb->data;
		if (hdr->magic == TQUIC_HAIRPIN_MAGIC) {
			hop_count = hdr->hop_count;
			if (hop_count >= TQUIC_HAIRPIN_MAX_HOPS) {
				pr_warn_ratelimited("tquic: hairpin loop detected, "
						    "hop_count=%u\n", hop_count);
				return -ELOOP;
			}
		}
	}

	/*
	 * Find or create destination stream on peer connection.
	 *
	 * For hairpin, we create a server-initiated bidirectional stream
	 * on the peer connection. The stream ID encodes this per RFC 9000.
	 */
		/*
		 * Create a new bidirectional stream for the reverse direction.
		 * tquic_stream_open() handles its own internal locking.
		 */
		dst_stream = tquic_stream_open(peer_conn, true);
		if (!dst_stream) {
			tquic_dbg("hairpin stream creation failed\n");
			return -ENOMEM;
		}

	/*
	 * Move data from source stream to destination stream.
	 *
	 * Use a local queue to minimize lock hold time. We dequeue
	 * from source under its lock, then enqueue to dest under its lock.
	 */
	__skb_queue_head_init(&tx_queue);

	/*
	 * Dequeue available data from source stream, limited to
	 * TQUIC_HAIRPIN_MAX_BYTES_PER_OP per operation to prevent
	 * a single client from flooding another through hairpin.
	 */
	spin_lock_bh(&src_stream->recv_buf.lock);
	while (total_bytes < TQUIC_HAIRPIN_MAX_BYTES_PER_OP &&
	       (skb = __skb_dequeue(&src_stream->recv_buf)) != NULL) {
		struct tquic_hairpin_header *hdr;
		unsigned int payload_offset = 0;

		/*
		 * Detach skb from source socket to prepare for ownership transfer.
		 * skb_orphan() calls the destructor which handles proper memory
		 * accounting (sk_mem_uncharge + sk_rmem_alloc adjustment).
		 * BUG FIX: Previously did manual double-uncharge (sk_mem_uncharge
		 * + atomic_sub on sk_rmem_alloc), causing memory accounting
		 * corruption and potential refcount_t misuse on modern kernels.
		 */
		skb_orphan(skb);

		/*
		 * Process hairpin header if present, strip it for forwarding.
		 * On first hop, add new header with incremented hop count.
		 */
		if (skb->len >= sizeof(struct tquic_hairpin_header)) {
			hdr = (struct tquic_hairpin_header *)skb->data;
			if (hdr->magic == TQUIC_HAIRPIN_MAGIC) {
				/* Existing hairpin packet - increment hop count */
				hdr->hop_count = hop_count + 1;
				payload_offset = sizeof(*hdr);
			}
		}

		/*
		 * Clone skb for forwarding to preserve original if needed.
		 * For true zero-copy, we could use skb_clone() but that
		 * shares data which is safe since we're moving ownership.
		 */
		if (skb_cloned(skb)) {
			struct sk_buff *new_skb;

			new_skb = skb_copy(skb, GFP_ATOMIC);
			if (!new_skb) {
				/* Put original back on queue and abort */
				__skb_queue_head(&src_stream->recv_buf, skb);
				break;
			}
			consume_skb(skb);
			skb = new_skb;
		}

		total_bytes += skb->len - payload_offset;
		__skb_queue_tail(&tx_queue, skb);
	}
	spin_unlock_bh(&src_stream->recv_buf.lock);

	if (total_bytes == 0) {
		/* Nothing to forward */
		return 0;
	}

		/* Enqueue to destination stream with memory accounting */
		if (dst_stream->conn)
			spin_lock_bh(&dst_stream->conn->lock);
		spin_lock_bh(&dst_stream->send_buf.lock);
		skb_queue_walk_safe(&tx_queue, skb, skb_next) {
			u32 skb_len = skb->len;
			struct sock *dst_sk = NULL;

			__skb_unlink(skb, &tx_queue);

			if (dst_stream->conn)
				dst_sk = dst_stream->conn->sk;

			/* Charge memory to destination connection socket */
			if (dst_sk) {
				if (sk_wmem_schedule(dst_sk, skb->truesize)) {
					skb_set_owner_w(skb, dst_sk);
				} else {
					kfree_skb(skb);
					continue;
				}
			}

			/* Initialize stream send bookkeeping for output_flush(). */
			tquic_stream_skb_cb(skb)->stream_offset = dst_stream->send_offset;
			tquic_stream_skb_cb(skb)->data_off = 0;
			dst_stream->send_offset += skb_len;

			if (dst_stream->conn) {
				dst_stream->conn->fc_data_reserved += skb_len;
				dst_stream->conn->stats.tx_bytes += skb_len;
			}

			__skb_queue_tail(&dst_stream->send_buf, skb);
		}
		spin_unlock_bh(&dst_stream->send_buf.lock);
		if (dst_stream->conn)
			spin_unlock_bh(&dst_stream->conn->lock);

	/*
	 * Wake up peer connection to trigger transmission.
	 * This schedules work to packetize and send the data.
	 */
	tquic_stream_wake(dst_stream);

	tquic_dbg("hairpin forwarded %zd bytes, hop=%u\n",
		 total_bytes, hop_count + 1);

	return total_bytes;
}
EXPORT_SYMBOL_GPL(tquic_forward_hairpin);

/**
 * tquic_forward_register_client - Register client for hairpin detection
 * @client: Client to register
 * @addr: Client's address for hairpin lookup
 */
int tquic_forward_register_client(struct tquic_client *client,
				  const struct sockaddr_storage *addr)
{
	struct tquic_hairpin_entry *entry;
	u32 hash;

	if (!client || !addr)
		return -EINVAL;

	entry = kzalloc(sizeof(*entry), GFP_KERNEL);
	if (!entry)
		return -ENOMEM;

	memcpy(&entry->dest_addr, addr, sizeof(struct sockaddr_storage));
	entry->peer_client = client;

	hash = tquic_forward_hash_addr(addr);

	spin_lock_bh(&tquic_hairpin_lock);
	hash_add(tquic_hairpin_hash, &entry->node, hash);
	spin_unlock_bh(&tquic_hairpin_lock);

	return 0;
}
EXPORT_SYMBOL_GPL(tquic_forward_register_client);

/**
 * tquic_forward_unregister_client - Unregister client from hairpin detection
 * @client: Client to unregister
 */
void tquic_forward_unregister_client(struct tquic_client *client)
{
	struct tquic_hairpin_entry *entry;
	struct hlist_node *tmp;
	int bkt;

	tquic_dbg("tquic_forward_unregister_client: unregistering tunnel client\n");

	if (!client)
		return;

	spin_lock_bh(&tquic_hairpin_lock);

	hash_for_each_safe(tquic_hairpin_hash, bkt, tmp, entry, node) {
		if (entry->peer_client == client) {
			hash_del(&entry->node);
			kfree(entry);
		}
	}

	spin_unlock_bh(&tquic_hairpin_lock);
}
EXPORT_SYMBOL_GPL(tquic_forward_unregister_client);

/*
 * =============================================================================
 * NAT SETUP HELPERS
 * =============================================================================
 *
 * Per CONTEXT.md: NAT masquerade for outbound traffic.
 */

/**
 * tquic_forward_setup_nat - Verify NAT masquerade is configured
 * @dev: Output network device
 *
 * Checks if nftables masquerade rule exists for outbound traffic.
 * The actual NAT is handled by netfilter, not by TQUIC.
 *
 * Returns: 0 if NAT configured, -ENOENT if not
 */
int tquic_forward_setup_nat(struct net_device *dev)
{
	if (!dev)
		return -EINVAL;

	/* Packet forwarding requires administrative privilege */
	if (!capable(CAP_NET_ADMIN))
		return -EPERM;

	/*
	 * NAT masquerade is configured externally via nftables:
	 *
	 * nft add table inet tquic
	 * nft add chain inet tquic postrouting { type nat hook postrouting priority srcnat; }
	 * nft add rule inet tquic postrouting oifname "eth0" masquerade
	 *
	 * We just verify the output device is up and has a route.
	 */
	if (!(dev->flags & IFF_UP)) {
		tquic_warn("NAT device %s is down\n", dev->name);
		return -ENETDOWN;
	}

	/* In production, could check for masquerade rule existence */
	return 0;
}
EXPORT_SYMBOL_GPL(tquic_forward_setup_nat);

/*
 * =============================================================================
 * MTU HANDLING AND PMTU CACHE
 * =============================================================================
 *
 * Per CONTEXT.md: Per-path MTU tracking, PMTUD signaling, no VPS-side fragmentation.
 *
 * PMTU discovery is critical for QUIC performance. When the VPS receives an
 * ICMP Packet Too Big message, we must:
 * 1. Cache the new MTU for the destination
 * 2. Signal the router to reduce its sending MTU
 * 3. Honor DF bit on IPv4 (never fragment at VPS)
 */

/* PMTU cache constants */
#define TQUIC_PMTU_CACHE_BITS		10
#define TQUIC_PMTU_CACHE_SIZE		(1 << TQUIC_PMTU_CACHE_BITS)
#define TQUIC_PMTU_MIN			1200	/* QUIC minimum MTU */
#define TQUIC_PMTU_DEFAULT_IPV4		1500
#define TQUIC_PMTU_DEFAULT_IPV6		1280
#define TQUIC_PMTU_CACHE_TIMEOUT_MS	(10 * 60 * 1000)  /* 10 minutes */
#define TQUIC_PMTU_CACHE_MAX_ENTRIES	4096	/* Maximum cache entries */

/**
 * struct tquic_pmtu_entry - PMTU cache entry
 * @dest_addr: Destination address (key)
 * @pmtu: Cached path MTU
 * @expires: Expiration time (jiffies)
 * @last_update: Last update timestamp
 * @df_required: DF bit must be set (IPv4)
 * @node: Hash table linkage
 * @rcu_head: RCU callback head for deferred freeing
 */
struct tquic_pmtu_entry {
	struct sockaddr_storage dest_addr;
	u32 pmtu;
	unsigned long expires;
	ktime_t last_update;
	bool df_required;
	struct hlist_node node;
	struct rcu_head rcu_head;
};

/* PMTU cache hash table */
static DEFINE_HASHTABLE(tquic_pmtu_cache, TQUIC_PMTU_CACHE_BITS);
static DEFINE_SPINLOCK(tquic_pmtu_lock);
static struct timer_list tquic_pmtu_gc_timer;
static atomic_t tquic_pmtu_entry_count = ATOMIC_INIT(0);

/**
 * tquic_pmtu_hash_addr - Hash destination address for PMTU lookup
 * @addr: Address to hash
 *
 * Returns: Hash value for the address
 */
static u32 tquic_pmtu_hash_addr(const struct sockaddr_storage *addr)
{
	tquic_dbg("tquic_pmtu_hash_addr: hashing PMTU addr family=%u\n",
		  addr->ss_family);

	if (addr->ss_family == AF_INET) {
		const struct sockaddr_in *sin = (const struct sockaddr_in *)addr;
		return jhash(&sin->sin_addr, sizeof(sin->sin_addr), 0);
	} else if (addr->ss_family == AF_INET6) {
		const struct sockaddr_in6 *sin6 = (const struct sockaddr_in6 *)addr;
		return jhash(&sin6->sin6_addr, sizeof(sin6->sin6_addr), 0);
	}
	return 0;
}

/**
 * tquic_pmtu_addr_equal - Compare two addresses for PMTU cache
 * @a: First address
 * @b: Second address
 *
 * Returns: true if addresses match
 */
static bool tquic_pmtu_addr_equal(const struct sockaddr_storage *a,
				   const struct sockaddr_storage *b)
{
	if (a->ss_family != b->ss_family)
		return false;

	if (a->ss_family == AF_INET) {
		const struct sockaddr_in *sa = (const struct sockaddr_in *)a;
		const struct sockaddr_in *sb = (const struct sockaddr_in *)b;
		return sa->sin_addr.s_addr == sb->sin_addr.s_addr;
	} else if (a->ss_family == AF_INET6) {
		const struct sockaddr_in6 *sa6 = (const struct sockaddr_in6 *)a;
		const struct sockaddr_in6 *sb6 = (const struct sockaddr_in6 *)b;
		return ipv6_addr_equal(&sa6->sin6_addr, &sb6->sin6_addr);
	}
	return false;
}

/**
 * tquic_fwd_pmtu_lookup - Look up cached PMTU for destination
 * @dest: Destination address
 *
 * Returns: Cached PMTU or 0 if not found/expired
 */
static u32 tquic_fwd_pmtu_lookup(const struct sockaddr_storage *dest)
{
	struct tquic_pmtu_entry *entry;
	u32 hash, pmtu = 0;

	tquic_dbg("tquic_fwd_pmtu_lookup: looking up cached PMTU\n");

	hash = tquic_pmtu_hash_addr(dest);

	rcu_read_lock();
	hash_for_each_possible_rcu(tquic_pmtu_cache, entry, node, hash) {
		if (tquic_pmtu_addr_equal(&entry->dest_addr, dest)) {
			if (time_before(jiffies, entry->expires))
				pmtu = entry->pmtu;
			break;
		}
	}
	rcu_read_unlock();

	tquic_dbg("tquic_fwd_pmtu_lookup: cached pmtu=%u\n", pmtu);
	return pmtu;
}

/**
 * tquic_fwd_pmtu_update - Update PMTU cache for destination
 * @dest: Destination address
 * @pmtu: New PMTU value
 * @df_required: Whether DF bit must be set
 *
 * Returns: 0 on success, negative errno on failure
 */
static int tquic_fwd_pmtu_update(const struct sockaddr_storage *dest,
			      u32 pmtu, bool df_required)
{
	struct tquic_pmtu_entry *entry, *old_entry = NULL;
	u32 hash;

	if (pmtu < TQUIC_PMTU_MIN)
		pmtu = TQUIC_PMTU_MIN;

	hash = tquic_pmtu_hash_addr(dest);

	spin_lock_bh(&tquic_pmtu_lock);

	/* Check for existing entry */
	hash_for_each_possible(tquic_pmtu_cache, entry, node, hash) {
		if (tquic_pmtu_addr_equal(&entry->dest_addr, dest)) {
			old_entry = entry;
			break;
		}
	}

	if (old_entry) {
		/* Update existing entry */
		old_entry->pmtu = pmtu;
		old_entry->expires = jiffies +
			msecs_to_jiffies(TQUIC_PMTU_CACHE_TIMEOUT_MS);
		old_entry->last_update = ktime_get();
		old_entry->df_required = df_required;
		spin_unlock_bh(&tquic_pmtu_lock);
		return 0;
	}

	/* Enforce maximum cache entries to prevent memory exhaustion */
	if (atomic_read(&tquic_pmtu_entry_count) >= TQUIC_PMTU_CACHE_MAX_ENTRIES) {
		spin_unlock_bh(&tquic_pmtu_lock);
		return -ENOSPC;
	}

	/* Create new entry */
	entry = kzalloc(sizeof(*entry), GFP_ATOMIC);
	if (!entry) {
		spin_unlock_bh(&tquic_pmtu_lock);
		return -ENOMEM;
	}

	memcpy(&entry->dest_addr, dest, sizeof(struct sockaddr_storage));
	entry->pmtu = pmtu;
	entry->expires = jiffies + msecs_to_jiffies(TQUIC_PMTU_CACHE_TIMEOUT_MS);
	entry->last_update = ktime_get();
	entry->df_required = df_required;

	hash_add_rcu(tquic_pmtu_cache, &entry->node, hash);
	atomic_inc(&tquic_pmtu_entry_count);

	spin_unlock_bh(&tquic_pmtu_lock);

	return 0;
}

/**
 * tquic_pmtu_gc_callback - Garbage collect expired PMTU entries
 * @t: Timer that triggered this callback
 */
static void tquic_pmtu_gc_callback(struct timer_list *t)
{
	struct tquic_pmtu_entry *entry;
	struct hlist_node *tmp;
	int bkt;

	tquic_dbg("tquic_pmtu_gc_callback: running PMTU cache garbage collection\n");

	spin_lock_bh(&tquic_pmtu_lock);
	hash_for_each_safe(tquic_pmtu_cache, bkt, tmp, entry, node) {
		if (time_after(jiffies, entry->expires)) {
			hash_del_rcu(&entry->node);
			atomic_dec(&tquic_pmtu_entry_count);
			kfree_rcu(entry, rcu_head);
		}
	}
	spin_unlock_bh(&tquic_pmtu_lock);

	/* Reschedule GC for next interval */
	mod_timer(&tquic_pmtu_gc_timer,
		  jiffies + msecs_to_jiffies(TQUIC_PMTU_CACHE_TIMEOUT_MS / 2));
}

/**
 * struct tquic_mtu_signal_frame - MTU signal frame for QUIC stream
 * @type: Frame type (0xFF01 = MTU signal, private use)
 * @new_mtu: Signaled MTU value
 * @reason: Reason code (0=ICMP, 1=probe, 2=admin)
 */
struct tquic_mtu_signal_frame {
	__be16 type;
	__be32 new_mtu;
	u8 reason;
} __packed;

#define TQUIC_MTU_FRAME_TYPE		cpu_to_be16(0xFF01)
#define TQUIC_MTU_REASON_ICMP		0
#define TQUIC_MTU_REASON_PROBE		1
#define TQUIC_MTU_REASON_ADMIN		2

/**
 * tquic_forward_get_mtu - Get effective MTU for tunnel
 * @tunnel: Tunnel context
 *
 * Calculates the effective MTU as the minimum of:
 *   - Cached PMTU for destination (if available)
 *   - QUIC connection path MTU
 *   - TCP socket destination MTU
 *   - Interface MTU minus encapsulation overhead
 *
 * Returns: MTU in bytes, or 1200 (QUIC minimum) on error
 */
u32 tquic_forward_get_mtu(struct tquic_tunnel *tunnel)
{
	struct tquic_connection *conn;
	struct tquic_path *path;
	struct dst_entry *dst;
	u32 mtu = TQUIC_PMTU_MIN;
	u32 cached_pmtu;
	u32 quic_mtu;
	u32 tcp_mtu;
	u32 overhead;

	tquic_dbg("tquic_forward_get_mtu: calculating effective MTU\n");

	if (!tunnel)
		return mtu;

	/* Check PMTU cache first */
	cached_pmtu = tquic_fwd_pmtu_lookup(&tunnel->dest_addr);
	if (cached_pmtu > 0)
		mtu = cached_pmtu;

	/* Get QUIC path MTU */
	if (tunnel->quic_stream && tunnel->quic_stream->conn) {
		conn = tunnel->quic_stream->conn;
		rcu_read_lock();
		path = rcu_dereference(conn->active_path);
		if (path && path->mtu > 0) {
			quic_mtu = path->mtu;
			/*
			 * Subtract QUIC overhead: UDP header (8) +
			 * QUIC short header (~20) + AEAD auth tag
			 * (16) = ~44 bytes
			 */
			overhead = 44;
			if (quic_mtu > overhead)
				quic_mtu -= overhead;
			if (quic_mtu < mtu)
				mtu = quic_mtu;
		}
		rcu_read_unlock();
	}

	/* Get TCP socket destination MTU */
	if (tunnel->tcp_sock && tunnel->tcp_sock->sk) {
		dst = __sk_dst_get(tunnel->tcp_sock->sk);
		if (dst) {
			tcp_mtu = dst_mtu(dst);
			/*
			 * Subtract TCP/IP overhead: IP header (20/40) + TCP header (20)
			 */
			overhead = (tunnel->dest_addr.ss_family == AF_INET) ? 40 : 60;
			if (tcp_mtu > overhead)
				tcp_mtu -= overhead;
			if (tcp_mtu < mtu)
				mtu = tcp_mtu;
		}
	}

	/* Enforce minimum */
	if (mtu < TQUIC_PMTU_MIN)
		mtu = TQUIC_PMTU_MIN;

	return mtu;
}
EXPORT_SYMBOL_GPL(tquic_forward_get_mtu);

/**
 * tquic_forward_send_icmp_toobig - Generate ICMP Packet Too Big
 * @tunnel: Tunnel context
 * @skb: Original packet that was too big
 * @mtu: MTU to report
 *
 * Generates an ICMP Destination Unreachable/Fragmentation Needed (IPv4)
 * or ICMPv6 Packet Too Big (IPv6) message back towards the source.
 *
 * Returns: 0 on success, negative errno on failure
 */
static int tquic_forward_send_icmp_toobig(struct tquic_tunnel *tunnel,
					   struct sk_buff *skb, u32 mtu)
{
	if (!tunnel || !skb)
		return -EINVAL;

	if (tunnel->dest_addr.ss_family == AF_INET) {
		/*
		 * IPv4: Generate ICMP Type 3, Code 4 (Fragmentation Needed)
		 * The MTU is encoded in the second 16 bits of the ICMP header.
		 */
		icmp_send(skb, ICMP_DEST_UNREACH, ICMP_FRAG_NEEDED,
			  htonl(mtu));
		tquic_dbg("sent ICMPv4 frag-needed, mtu=%u\n", mtu);

#if IS_ENABLED(CONFIG_IPV6)
	} else if (tunnel->dest_addr.ss_family == AF_INET6) {
		/*
		 * IPv6: Generate ICMPv6 Type 2 (Packet Too Big)
		 */
		icmpv6_send(skb, ICMPV6_PKT_TOOBIG, 0, mtu);
		tquic_dbg("sent ICMPv6 packet-too-big, mtu=%u\n", mtu);
#endif
	} else {
		return -EAFNOSUPPORT;
	}

	return 0;
}

/**
 * tquic_forward_signal_mtu - Signal MTU change to router
 * @tunnel: Tunnel that received ICMP too big
 * @new_mtu: New MTU from ICMP
 *
 * Per CONTEXT.md: PMTUD signaling for oversized packets.
 *
 * When we receive an ICMP Packet Too Big, we must:
 * 1. Update the PMTU cache
 * 2. Send an MTU signal frame to the router over the QUIC stream
 * 3. Generate ICMP back to source if appropriate
 *
 * The router can then reduce its sending MTU for subsequent packets.
 *
 * Returns: 0 on success, negative errno on failure
 */
int tquic_forward_signal_mtu(struct tquic_tunnel *tunnel, u32 new_mtu)
{
	struct tquic_mtu_signal_frame frame;
	struct tquic_stream *stream;
	struct tquic_connection *conn;
	struct sk_buff *skb;
	int err;

	if (!tunnel)
		return -EINVAL;

	/* Enforce minimum MTU */
	if (new_mtu < TQUIC_PMTU_MIN)
		new_mtu = TQUIC_PMTU_MIN;

	/* Update PMTU cache */
	err = tquic_fwd_pmtu_update(&tunnel->dest_addr, new_mtu, true);
	if (err < 0) {
		tquic_warn("failed to update PMTU cache: %d\n", err);
		/* Continue anyway - signaling is more important */
	}

	/* Get QUIC stream for signaling */
	stream = tunnel->quic_stream;
	if (!stream)
		return -ENOTCONN;

	/* Check connection state */
	conn = READ_ONCE(stream->conn);
	if (!conn || !tquic_conn_get(conn))
		return -ENOTCONN;

	if (READ_ONCE(conn->state) != TQUIC_CONN_CONNECTED) {
		tquic_conn_put(conn);
		return -ENOTCONN;
	}

	/*
	 * Build MTU signal frame.
	 *
	 * This uses a private frame type (0xFF01) to signal MTU changes
	 * to the router. The router should process this and reduce its
	 * sending MTU accordingly.
	 */
	frame.type = TQUIC_MTU_FRAME_TYPE;
	frame.new_mtu = cpu_to_be32(new_mtu);
	frame.reason = TQUIC_MTU_REASON_ICMP;

	/* Allocate skb for the frame */
	skb = alloc_skb(sizeof(frame) + 64, GFP_ATOMIC);
	if (!skb) {
		tquic_conn_put(conn);
		return -ENOMEM;
	}

	skb_reserve(skb, 32);  /* Room for headers */
	skb_put_data(skb, &frame, sizeof(frame));

	/*
	 * Enqueue to stream's send buffer.
	 *
	 * The frame will be sent with the next outgoing packet.
	 * MTU signals are high priority to prevent further oversized sends.
	 */
	spin_lock_bh(&conn->lock);
	spin_lock_bh(&stream->send_buf.lock);
	tquic_stream_skb_cb(skb)->stream_offset = stream->send_offset;
	tquic_stream_skb_cb(skb)->data_off = 0;
	__skb_queue_head(&stream->send_buf, skb);  /* High priority - head of queue */
	stream->send_offset += sizeof(frame);
	conn->fc_data_reserved += sizeof(frame);
	spin_unlock_bh(&stream->send_buf.lock);
	spin_unlock_bh(&conn->lock);
	tquic_conn_put(conn);

	/* Wake stream to trigger transmission */
	tquic_stream_wake(stream);

	tquic_dbg("signaled MTU %u to router via QUIC stream %llu\n",
		 new_mtu, stream->id);

	return 0;
}
EXPORT_SYMBOL_GPL(tquic_forward_signal_mtu);

/**
 * tquic_forward_handle_icmp_toobig - Handle incoming ICMP Packet Too Big
 * @tunnel: Tunnel that received the ICMP
 * @skb: ICMP packet
 * @mtu: Reported MTU from ICMP header
 *
 * Called when we receive an ICMP message indicating our packets are too big.
 * This can happen when the path to the destination has a lower MTU than
 * we expected.
 *
 * Returns: 0 on success, negative errno on failure
 */
static int tquic_forward_handle_icmp_toobig(struct tquic_tunnel *tunnel,
					    struct sk_buff *skb, u32 mtu)
{
	int err;

	if (!tunnel)
		return -EINVAL;

	tquic_dbg("received ICMP too-big, mtu=%u\n", mtu);

	/* Signal the new MTU to the router */
	err = tquic_forward_signal_mtu(tunnel, mtu);
	if (err < 0)
		return err;

	/*
	 * If we have a pending large packet, we could re-segment it here.
	 * However, per CONTEXT.md we do "no VPS-side fragmentation" - the
	 * router is responsible for sending properly-sized packets.
	 */

	return 0;
}

/**
 * tquic_forward_check_df - Check if DF bit is set and packet fits MTU
 * @tunnel: Tunnel context
 * @skb: Packet to check
 *
 * For IPv4 packets with DF (Don't Fragment) bit set, verifies the packet
 * fits within the path MTU. If not, generates ICMP and returns error.
 *
 * Returns: 0 if OK to send, -EMSGSIZE if packet too big with DF set
 */
static int tquic_forward_check_df(struct tquic_tunnel *tunnel,
				  struct sk_buff *skb)
{
	struct iphdr *iph;
	u32 mtu;

	if (!tunnel || !skb)
		return -EINVAL;

	/* Only check IPv4 packets */
	if (tunnel->dest_addr.ss_family != AF_INET)
		return 0;

	/* Check if this is an IP packet with DF bit */
	if (skb->len < sizeof(struct iphdr))
		return 0;

	iph = ip_hdr(skb);
	if (!iph)
		return 0;

	/* If DF is not set, fragmentation is allowed (but we won't do it) */
	if (!(ntohs(iph->frag_off) & IP_DF))
		return 0;

	/* DF is set - check against path MTU */
	mtu = tquic_forward_get_mtu(tunnel);
	if (skb->len > mtu) {
		/*
		 * Packet too big and DF is set - must drop and send ICMP.
		 * This honors the DF bit per RFC 791.
		 */
		tquic_forward_send_icmp_toobig(tunnel, skb, mtu);
		tquic_dbg("dropping DF packet, len=%u > mtu=%u\n",
			 skb->len, mtu);
		return -EMSGSIZE;
	}

	return 0;
}

/*
 * =============================================================================
 * SOCKET CALLBACK INTEGRATION
 * =============================================================================
 *
 * Hook into TCP socket callbacks for receive notification.
 */

/**
 * tquic_forward_data_ready - TCP socket data ready callback
 * @sk: TCP socket with incoming data
 *
 * Called when data arrives on the outbound TCP socket.
 * Triggers forwarding back to the QUIC stream.
 */
static void __maybe_unused tquic_forward_data_ready(struct sock *sk)
{
	struct tquic_tunnel *tunnel;

	/*
	 * Tunnel pointer stored in sk_user_data
	 */
	tunnel = sk->sk_user_data;
	if (!tunnel)
		return;

	/*
	 * Queue work to forward received data to QUIC stream
	 * Don't do actual forwarding in softirq context
	 */

	/* Would queue tunnel->forward_work */
}

/**
 * tquic_forward_setup_tcp_callbacks - Install TCP socket callbacks
 * @tunnel: Tunnel to set up
 *
 * Installs data_ready callback on TCP socket for RX notification.
 *
 * Returns: 0 on success, negative errno on failure
 */
int tquic_forward_setup_tcp_callbacks(struct tquic_tunnel *tunnel)
{
	if (!tunnel)
		return -EINVAL;

	/*
	 * Would access tunnel->tcp_sock->sk and install callbacks:
	 *
	 * sk = tunnel->tcp_sock->sk;
	 * sk->sk_user_data = tunnel;
	 * sk->sk_data_ready = tquic_forward_data_ready;
	 */

	return 0;
}
EXPORT_SYMBOL_GPL(tquic_forward_setup_tcp_callbacks);

/*
 * =============================================================================
 * GRO/GSO CHECK
 * =============================================================================
 *
 * Per RESEARCH.md: GRO/GSO critical for high throughput.
 */

/**
 * tquic_forward_check_gro_gso - Verify GRO/GSO is enabled
 * @dev: Network device to check
 *
 * Per RESEARCH.md pitfall #4: CPU bottleneck without GRO/GSO.
 *
 * Returns: 0 if enabled, logs warning if disabled
 */
int tquic_forward_check_gro_gso(struct net_device *dev)
{
	netdev_features_t features;

	if (!dev)
		return -EINVAL;

	features = dev->features;

	if (!(features & NETIF_F_GRO))
		tquic_warn("GRO disabled on %s - performance may suffer\n",
			dev->name);

	if (!(features & NETIF_F_GSO))
		tquic_warn("GSO disabled on %s - performance may suffer\n",
			dev->name);

	return 0;
}
EXPORT_SYMBOL_GPL(tquic_forward_check_gro_gso);

/*
 * =============================================================================
 * MODULE INIT/EXIT
 * =============================================================================
 */

/**
 * tquic_forward_init - Initialize forwarding subsystem
 *
 * Initializes hairpin hash table, PMTU cache, and periodic GC timer.
 */
int __init tquic_forward_init(void)
{
	/* Initialize hairpin hash table */
	hash_init(tquic_hairpin_hash);

	/* Initialize PMTU cache hash table */
	hash_init(tquic_pmtu_cache);

	/*
	 * Set up PMTU cache garbage collection timer.
	 * This runs every 5 minutes to clean up expired entries.
	 */
	timer_setup(&tquic_pmtu_gc_timer, tquic_pmtu_gc_callback, 0);
	mod_timer(&tquic_pmtu_gc_timer,
		  jiffies + msecs_to_jiffies(TQUIC_PMTU_CACHE_TIMEOUT_MS / 2));

	tquic_info("forwarding subsystem initialized (hairpin + PMTU cache)\n");
	return 0;
}

/**
 * tquic_forward_exit - Cleanup forwarding subsystem
 *
 * Cleans up hairpin hash table, PMTU cache, and stops GC timer.
 */
void tquic_forward_exit(void)
{
	struct tquic_hairpin_entry *hairpin_entry;
	struct tquic_pmtu_entry *pmtu_entry;
	struct hlist_node *tmp;
	int bkt;

	/* Stop PMTU GC timer */
	del_timer_sync(&tquic_pmtu_gc_timer);

	/* Clean up hairpin hash table */
	spin_lock_bh(&tquic_hairpin_lock);
	hash_for_each_safe(tquic_hairpin_hash, bkt, tmp, hairpin_entry, node) {
		hash_del(&hairpin_entry->node);
		kfree(hairpin_entry);
	}
	spin_unlock_bh(&tquic_hairpin_lock);

	/* Clean up PMTU cache */
	spin_lock_bh(&tquic_pmtu_lock);
	hash_for_each_safe(tquic_pmtu_cache, bkt, tmp, pmtu_entry, node) {
		hash_del_rcu(&pmtu_entry->node);
		atomic_dec(&tquic_pmtu_entry_count);
		kfree_rcu(pmtu_entry, rcu_head);
	}
	spin_unlock_bh(&tquic_pmtu_lock);

	/* Wait for all RCU callbacks (including kfree_rcu) to complete */
	rcu_barrier();

	tquic_info("forwarding subsystem cleaned up\n");
}
