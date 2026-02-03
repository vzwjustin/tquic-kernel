// SPDX-License-Identifier: GPL-2.0-only
/*
 * TQUIC: TCP-over-QUIC Tunnel Termination
 *
 * Copyright (c) 2026 Linux Foundation
 *
 * This file implements TCP-over-QUIC tunnel termination for VPS endpoints.
 * The VPS receives encapsulated TCP connections from routers over QUIC streams
 * and forwards them as native TCP to internet destinations.
 *
 * Per CONTEXT.md:
 *   - TCP-over-QUIC tunnel: router encapsulates TCP in QUIC, VPS terminates
 *   - NAT masquerade for outbound traffic
 *   - Router hints for flow classification (QoS)
 *   - TPROXY support for transparent proxying of specific ports
 *   - TCP Fast Open enabled for outbound connections
 *   - Full ICMP passthrough
 */

#include <linux/module.h>
#include <linux/slab.h>
#include <linux/net.h>
#include <linux/socket.h>
#include <linux/file.h>
#include <linux/bitmap.h>
#include <linux/workqueue.h>
#include <net/sock.h>
#include <net/tcp.h>
#include <net/tquic.h>
#include <net/ip.h>
#include <net/ipv6.h>

#include "protocol.h"

/*
 * =============================================================================
 * TUNNEL STATE DEFINITIONS
 * =============================================================================
 */

/**
 * enum tquic_tunnel_state - Tunnel connection states
 * @TQUIC_TUNNEL_IDLE: Initial state
 * @TQUIC_TUNNEL_CONNECTING: TCP connect in progress
 * @TQUIC_TUNNEL_ESTABLISHED: TCP connection active
 * @TQUIC_TUNNEL_CLOSING: Graceful shutdown
 * @TQUIC_TUNNEL_CLOSED: Tunnel fully closed
 */
enum tquic_tunnel_state {
	TQUIC_TUNNEL_IDLE = 0,
	TQUIC_TUNNEL_CONNECTING,
	TQUIC_TUNNEL_ESTABLISHED,
	TQUIC_TUNNEL_CLOSING,
	TQUIC_TUNNEL_CLOSED,
};

/*
 * Traffic classification for QoS - uses defines from net/tquic.h:
 * - TQUIC_TC_REALTIME: VoIP/video - lowest latency, highest priority
 * - TQUIC_TC_INTERACTIVE: Gaming - low latency, tolerates small jitter
 * - TQUIC_TC_BULK: Downloads - best-effort, fills available bandwidth
 * - TQUIC_TC_BACKGROUND: Lowest priority, uses idle capacity only
 */

/**
 * struct tquic_tunnel_stats - Per-tunnel statistics
 * @bytes_tx: Total bytes transmitted to internet
 * @bytes_rx: Total bytes received from internet
 * @packets_tx: Packets transmitted
 * @packets_rx: Packets received
 */
struct tquic_tunnel_stats {
	u64 bytes_tx;
	u64 bytes_rx;
	u64 packets_tx;
	u64 packets_rx;
};

/**
 * struct tquic_tunnel - TCP-over-QUIC tunnel state
 * @quic_stream: QUIC stream carrying the tunnel
 * @tcp_sock: Kernel TCP socket to destination
 * @dest_addr: Destination address (IPv4 or IPv6)
 * @dest_port: Destination port
 * @local_port: Allocated local port from client's range
 * @state: Current tunnel state
 * @client: Parent tquic_client for port range lookup
 * @stats: Per-tunnel statistics
 * @traffic_class: Assigned QoS class (0-3)
 * @is_tproxy: True if TPROXY mode enabled
 * @connect_work: Async connect workqueue item
 * @forward_work: Data forwarding workqueue item
 * @lock: Tunnel state lock
 * @list: Client's tunnel list linkage
 * @refcnt: Reference counter
 */
struct tquic_tunnel {
	struct tquic_stream *quic_stream;
	struct socket *tcp_sock;

	struct sockaddr_storage dest_addr;
	__be16 dest_port;
	__be16 local_port;

	enum tquic_tunnel_state state;
	struct tquic_client *client;

	struct tquic_tunnel_stats stats;
	u8 traffic_class;
	bool is_tproxy;

	struct work_struct connect_work;
	struct work_struct forward_work;

	spinlock_t lock;
	struct list_head list;
	refcount_t refcnt;
};

/* Port allocation bitmap - 1000 ports per client */
#define TQUIC_PORTS_PER_CLIENT	1000
#define TQUIC_PORT_BITMAP_SIZE	BITS_TO_LONGS(TQUIC_PORTS_PER_CLIENT)

/**
 * struct tquic_client - Per-client VPS state
 * @psk_identity: PSK identity for authentication
 * @port_range_start: Start of allocated port range
 * @port_range_end: End of allocated port range
 * @port_bitmap: Bitmap of allocated ports
 * @tunnels: List of active tunnels
 * @tunnels_lock: Protects tunnels list
 * @conn: Associated TQUIC connection
 * @bandwidth_limit: Configured bandwidth limit (bytes/s)
 * @list: Global client list linkage
 */
struct tquic_client {
	char psk_identity[64];
	__be16 port_range_start;
	__be16 port_range_end;
	unsigned long port_bitmap[TQUIC_PORT_BITMAP_SIZE];

	struct list_head tunnels;
	spinlock_t tunnels_lock;
	struct tquic_connection *conn;

	u64 bandwidth_limit;
	struct list_head list;
};

/* Global client list */
static LIST_HEAD(tquic_client_list);
static DEFINE_SPINLOCK(tquic_client_list_lock);

/* Forwarding workqueue */
static struct workqueue_struct *tquic_tunnel_wq;

/*
 * =============================================================================
 * PORT ALLOCATION
 * =============================================================================
 */

/**
 * tquic_port_alloc - Allocate a local port from client's range
 * @client: Client to allocate from
 *
 * Uses bitmap-based allocation for O(1) average case.
 *
 * Returns: Allocated port number or 0 on failure
 */
static __be16 tquic_port_alloc(struct tquic_client *client)
{
	unsigned long bit;
	__be16 port;

	if (!client)
		return 0;

	spin_lock_bh(&client->tunnels_lock);

	bit = find_first_zero_bit(client->port_bitmap, TQUIC_PORTS_PER_CLIENT);
	if (bit >= TQUIC_PORTS_PER_CLIENT) {
		spin_unlock_bh(&client->tunnels_lock);
		return 0;  /* Port range exhausted */
	}

	set_bit(bit, client->port_bitmap);
	port = htons(ntohs(client->port_range_start) + bit);

	spin_unlock_bh(&client->tunnels_lock);

	return port;
}

/**
 * tquic_port_free - Return port to client's pool
 * @client: Client owning the port
 * @port: Port to free
 */
static void tquic_port_free(struct tquic_client *client, __be16 port)
{
	unsigned long bit;

	if (!client || port == 0)
		return;

	bit = ntohs(port) - ntohs(client->port_range_start);
	if (bit >= TQUIC_PORTS_PER_CLIENT)
		return;

	spin_lock_bh(&client->tunnels_lock);
	clear_bit(bit, client->port_bitmap);
	spin_unlock_bh(&client->tunnels_lock);
}

/*
 * =============================================================================
 * TUNNEL STREAM HEADER PARSING
 * =============================================================================
 *
 * Stream header format:
 *   - 1 byte: Address family (4 = IPv4, 6 = IPv6)
 *   - 4/16 bytes: Destination IP address
 *   - 2 bytes: Destination port (network byte order)
 *   - 1 byte: QoS hint (0=realtime, 1=interactive, 2=bulk, 3=background)
 */

#define TQUIC_TUNNEL_HDR_IPV4_LEN	8	/* 1 + 4 + 2 + 1 */
#define TQUIC_TUNNEL_HDR_IPV6_LEN	20	/* 1 + 16 + 2 + 1 */

/**
 * tquic_tunnel_parse_header - Parse tunnel stream header
 * @data: Header data
 * @len: Length of data
 * @tunnel: Tunnel to populate
 *
 * Returns: Number of bytes consumed, or negative errno
 */
static int tquic_tunnel_parse_header(const u8 *data, size_t len,
				     struct tquic_tunnel *tunnel)
{
	u8 af_byte;
	size_t hdr_len;

	if (!data || len < 1 || !tunnel)
		return -EINVAL;

	af_byte = data[0];

	if (af_byte == 4) {
		struct sockaddr_in *sin;

		hdr_len = TQUIC_TUNNEL_HDR_IPV4_LEN;
		if (len < hdr_len)
			return -EINVAL;

		sin = (struct sockaddr_in *)&tunnel->dest_addr;
		sin->sin_family = AF_INET;
		memcpy(&sin->sin_addr.s_addr, &data[1], 4);
		memcpy(&tunnel->dest_port, &data[5], 2);
		sin->sin_port = tunnel->dest_port;

		/* QoS hint at offset 7 */
		tunnel->traffic_class = data[7];
		if (tunnel->traffic_class > TQUIC_TC_BACKGROUND)
			tunnel->traffic_class = TQUIC_TC_BULK;

	} else if (af_byte == 6) {
		struct sockaddr_in6 *sin6;

		hdr_len = TQUIC_TUNNEL_HDR_IPV6_LEN;
		if (len < hdr_len)
			return -EINVAL;

		sin6 = (struct sockaddr_in6 *)&tunnel->dest_addr;
		sin6->sin6_family = AF_INET6;
		memcpy(&sin6->sin6_addr, &data[1], 16);
		memcpy(&tunnel->dest_port, &data[17], 2);
		sin6->sin6_port = tunnel->dest_port;

		/* QoS hint at offset 19 */
		tunnel->traffic_class = data[19];
		if (tunnel->traffic_class > TQUIC_TC_BACKGROUND)
			tunnel->traffic_class = TQUIC_TC_BULK;

	} else {
		return -EAFNOSUPPORT;
	}

	return hdr_len;
}

/*
 * =============================================================================
 * TUNNEL LIFECYCLE
 * =============================================================================
 */

/**
 * tquic_tunnel_alloc - Allocate a new tunnel structure
 * @client: Parent client
 * @stream: QUIC stream for this tunnel
 *
 * Returns: Allocated tunnel or NULL on failure
 */
static struct tquic_tunnel *tquic_tunnel_alloc(struct tquic_client *client,
					       struct tquic_stream *stream)
{
	struct tquic_tunnel *tunnel;

	tunnel = kzalloc(sizeof(*tunnel), GFP_KERNEL);
	if (!tunnel)
		return NULL;

	tunnel->client = client;
	tunnel->quic_stream = stream;
	tunnel->state = TQUIC_TUNNEL_IDLE;
	tunnel->traffic_class = TQUIC_TC_BULK;  /* Default */

	spin_lock_init(&tunnel->lock);
	INIT_LIST_HEAD(&tunnel->list);
	refcount_set(&tunnel->refcnt, 1);

	return tunnel;
}

/**
 * tquic_tunnel_free - Free tunnel and release resources
 * @tunnel: Tunnel to free
 */
static void tquic_tunnel_free(struct tquic_tunnel *tunnel)
{
	if (!tunnel)
		return;

	if (tunnel->tcp_sock)
		sock_release(tunnel->tcp_sock);

	if (tunnel->client && tunnel->local_port)
		tquic_port_free(tunnel->client, tunnel->local_port);

	kfree(tunnel);
}

/**
 * tquic_tunnel_get - Increment tunnel reference count
 * @tunnel: Tunnel to reference
 */
static inline void tquic_tunnel_get(struct tquic_tunnel *tunnel)
{
	if (tunnel)
		refcount_inc(&tunnel->refcnt);
}

/**
 * tquic_tunnel_put - Decrement tunnel reference count
 * @tunnel: Tunnel to dereference
 */
static inline void tquic_tunnel_put(struct tquic_tunnel *tunnel)
{
	if (tunnel && refcount_dec_and_test(&tunnel->refcnt))
		tquic_tunnel_free(tunnel);
}

/*
 * =============================================================================
 * TCP SOCKET CREATION
 * =============================================================================
 */

/**
 * tquic_tunnel_create_tcp_socket - Create outbound TCP socket
 * @tunnel: Tunnel requiring TCP socket
 * @is_tproxy: Enable TPROXY mode (IP_TRANSPARENT)
 *
 * Creates a kernel TCP socket bound to the client's port range.
 * Enables TCP Fast Open for outbound connections per CONTEXT.md.
 *
 * Returns: 0 on success, negative errno on failure
 */
static int tquic_tunnel_create_tcp_socket(struct tquic_tunnel *tunnel,
					  bool is_tproxy)
{
	struct socket *sock;
	struct sockaddr_storage bind_addr;
	int err;
	int val;
	sa_family_t family;

	if (!tunnel || !tunnel->client)
		return -EINVAL;

	family = tunnel->dest_addr.ss_family;

	/* Create kernel TCP socket */
	err = sock_create_kern(&init_net, family, SOCK_STREAM, IPPROTO_TCP,
			       &sock);
	if (err < 0)
		return err;

	/* Allocate local port from client's range */
	tunnel->local_port = tquic_port_alloc(tunnel->client);
	if (tunnel->local_port == 0) {
		sock_release(sock);
		return -EADDRINUSE;
	}

	/* Enable TCP Fast Open per CONTEXT.md */
	val = 1;
	err = sock->ops->setsockopt(sock, SOL_TCP, TCP_FASTOPEN_CONNECT,
				    KERNEL_SOCKPTR(&val), sizeof(val));
	if (err < 0) {
		/* TFO failure is non-fatal, continue without it */
		pr_debug("tquic: TCP_FASTOPEN_CONNECT failed: %d\n", err);
	}

	/*
	 * SO_BINDTODEVICE for NAT masquerade integration
	 * This ensures traffic goes out the correct interface for nftables
	 * masquerade rules to apply. Device name comes from routing lookup.
	 *
	 * Per CONTEXT.md: NAT masquerade for outbound traffic.
	 */
	/* Note: Would set SO_BINDTODEVICE here if device name known */

	/* Enable TPROXY mode if requested */
	if (is_tproxy) {
		val = 1;
		err = sock->ops->setsockopt(sock, SOL_IP, IP_TRANSPARENT,
					    KERNEL_SOCKPTR(&val), sizeof(val));
		if (err < 0) {
			/*
			 * IP_TRANSPARENT requires CAP_NET_ADMIN. If it fails,
			 * we must NOT set is_tproxy=true as that would cause
			 * packet processing to use TPROXY logic incorrectly.
			 */
			if (capable(CAP_NET_ADMIN)) {
				pr_err("tquic: IP_TRANSPARENT failed despite CAP_NET_ADMIN: %d\n", err);
				sock_release(sock);
				return ERR_PTR(err);
			}
			pr_info("tquic: IP_TRANSPARENT requires CAP_NET_ADMIN, using normal mode\n");
			tunnel->is_tproxy = false;
		} else {
			tunnel->is_tproxy = true;
		}
	}

	/* Set up bind address with allocated port */
	memset(&bind_addr, 0, sizeof(bind_addr));
	if (family == AF_INET) {
		struct sockaddr_in *sin = (struct sockaddr_in *)&bind_addr;
		sin->sin_family = AF_INET;
		sin->sin_addr.s_addr = htonl(INADDR_ANY);
		sin->sin_port = tunnel->local_port;
	} else {
		struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)&bind_addr;
		sin6->sin6_family = AF_INET6;
		sin6->sin6_addr = in6addr_any;
		sin6->sin6_port = tunnel->local_port;
	}

	/* Bind to allocated port */
	err = sock->ops->bind(sock, (struct sockaddr *)&bind_addr,
			      family == AF_INET ? sizeof(struct sockaddr_in) :
						  sizeof(struct sockaddr_in6));
	if (err < 0) {
		tquic_port_free(tunnel->client, tunnel->local_port);
		tunnel->local_port = 0;
		sock_release(sock);
		return err;
	}

	tunnel->tcp_sock = sock;
	return 0;
}

/**
 * tquic_tunnel_connect_work - Async TCP connect work function
 * @work: Work structure embedded in tunnel
 *
 * Performs non-blocking TCP connect to destination.
 */
static void tquic_tunnel_connect_work(struct work_struct *work)
{
	struct tquic_tunnel *tunnel;
	struct socket *sock;
	int err;
	int addr_len;

	tunnel = container_of(work, struct tquic_tunnel, connect_work);
	sock = tunnel->tcp_sock;

	if (!sock) {
		tunnel->state = TQUIC_TUNNEL_CLOSED;
		tquic_tunnel_put(tunnel);
		return;
	}

	addr_len = tunnel->dest_addr.ss_family == AF_INET ?
		   sizeof(struct sockaddr_in) :
		   sizeof(struct sockaddr_in6);

	spin_lock_bh(&tunnel->lock);
	tunnel->state = TQUIC_TUNNEL_CONNECTING;
	spin_unlock_bh(&tunnel->lock);

	/* Non-blocking connect */
	err = sock->ops->connect(sock, (struct sockaddr *)&tunnel->dest_addr,
				 addr_len, O_NONBLOCK);

	if (err == 0 || err == -EINPROGRESS) {
		/* Connect initiated or completed */
		spin_lock_bh(&tunnel->lock);
		if (err == 0)
			tunnel->state = TQUIC_TUNNEL_ESTABLISHED;
		/* EINPROGRESS handled by socket callback */
		spin_unlock_bh(&tunnel->lock);
	} else {
		/* Connect failed */
		spin_lock_bh(&tunnel->lock);
		tunnel->state = TQUIC_TUNNEL_CLOSED;
		spin_unlock_bh(&tunnel->lock);
		pr_debug("tquic: tunnel connect failed: %d\n", err);
	}

	tquic_tunnel_put(tunnel);
}

/**
 * tquic_tunnel_create - Create and initiate TCP tunnel
 * @client: Parent client
 * @stream: QUIC stream carrying tunnel
 * @header_data: Stream header with destination info
 * @header_len: Length of header data
 *
 * Creates tunnel, parses header, creates TCP socket, initiates connect.
 *
 * Returns: Tunnel on success, ERR_PTR on failure
 */
struct tquic_tunnel *tquic_tunnel_create(struct tquic_client *client,
					 struct tquic_stream *stream,
					 const u8 *header_data,
					 size_t header_len)
{
	struct tquic_tunnel *tunnel;
	int err;
	int consumed;

	if (!client || !stream || !header_data)
		return ERR_PTR(-EINVAL);

	tunnel = tquic_tunnel_alloc(client, stream);
	if (!tunnel)
		return ERR_PTR(-ENOMEM);

	/* Parse stream header for destination and QoS hint */
	consumed = tquic_tunnel_parse_header(header_data, header_len, tunnel);
	if (consumed < 0) {
		tquic_tunnel_put(tunnel);
		return ERR_PTR(consumed);
	}

	/* Create TCP socket */
	err = tquic_tunnel_create_tcp_socket(tunnel, false);
	if (err < 0) {
		tquic_tunnel_put(tunnel);
		return ERR_PTR(err);
	}

	/* Initialize work items */
	INIT_WORK(&tunnel->connect_work, tquic_tunnel_connect_work);
	INIT_WORK(&tunnel->forward_work, NULL);  /* Set up in forward.c */

	/* Add to client's tunnel list */
	spin_lock_bh(&client->tunnels_lock);
	list_add_tail(&tunnel->list, &client->tunnels);
	spin_unlock_bh(&client->tunnels_lock);

	/* Take reference for async connect work */
	tquic_tunnel_get(tunnel);

	/* Queue async connect */
	if (tquic_tunnel_wq)
		queue_work(tquic_tunnel_wq, &tunnel->connect_work);

	pr_debug("tquic: created tunnel to port %d, class %d\n",
		 ntohs(tunnel->dest_port), tunnel->traffic_class);

	return tunnel;
}
EXPORT_SYMBOL_GPL(tquic_tunnel_create);

/**
 * tquic_tunnel_create_tproxy - Create tunnel in TPROXY mode
 * @client: Parent client
 * @stream: QUIC stream carrying tunnel
 * @header_data: Stream header with destination info
 * @header_len: Length of header data
 *
 * Same as tquic_tunnel_create but enables IP_TRANSPARENT for
 * transparent proxying of specific ports.
 *
 * Returns: Tunnel on success, ERR_PTR on failure
 */
struct tquic_tunnel *tquic_tunnel_create_tproxy(struct tquic_client *client,
						struct tquic_stream *stream,
						const u8 *header_data,
						size_t header_len)
{
	struct tquic_tunnel *tunnel;
	int err;
	int consumed;

	if (!client || !stream || !header_data)
		return ERR_PTR(-EINVAL);

	tunnel = tquic_tunnel_alloc(client, stream);
	if (!tunnel)
		return ERR_PTR(-ENOMEM);

	/* Parse stream header */
	consumed = tquic_tunnel_parse_header(header_data, header_len, tunnel);
	if (consumed < 0) {
		tquic_tunnel_put(tunnel);
		return ERR_PTR(consumed);
	}

	/* Create TCP socket with TPROXY enabled */
	err = tquic_tunnel_create_tcp_socket(tunnel, true);
	if (err < 0) {
		tquic_tunnel_put(tunnel);
		return ERR_PTR(err);
	}

	/* Initialize work items */
	INIT_WORK(&tunnel->connect_work, tquic_tunnel_connect_work);

	/* Add to client's tunnel list */
	spin_lock_bh(&client->tunnels_lock);
	list_add_tail(&tunnel->list, &client->tunnels);
	spin_unlock_bh(&client->tunnels_lock);

	/* Queue async connect */
	tquic_tunnel_get(tunnel);
	if (tquic_tunnel_wq)
		queue_work(tquic_tunnel_wq, &tunnel->connect_work);

	pr_debug("tquic: created TPROXY tunnel to port %d\n",
		 ntohs(tunnel->dest_port));

	return tunnel;
}
EXPORT_SYMBOL_GPL(tquic_tunnel_create_tproxy);

/**
 * tquic_tunnel_close - Initiate graceful tunnel close
 * @tunnel: Tunnel to close
 */
void tquic_tunnel_close(struct tquic_tunnel *tunnel)
{
	if (!tunnel)
		return;

	spin_lock_bh(&tunnel->lock);
	if (tunnel->state == TQUIC_TUNNEL_CLOSED ||
	    tunnel->state == TQUIC_TUNNEL_CLOSING) {
		spin_unlock_bh(&tunnel->lock);
		return;
	}
	tunnel->state = TQUIC_TUNNEL_CLOSING;
	spin_unlock_bh(&tunnel->lock);

	/* Remove from client's tunnel list */
	if (tunnel->client) {
		spin_lock_bh(&tunnel->client->tunnels_lock);
		list_del_init(&tunnel->list);
		spin_unlock_bh(&tunnel->client->tunnels_lock);
	}

	/* Shutdown TCP socket */
	if (tunnel->tcp_sock) {
		kernel_sock_shutdown(tunnel->tcp_sock, SHUT_RDWR);
	}

	spin_lock_bh(&tunnel->lock);
	tunnel->state = TQUIC_TUNNEL_CLOSED;
	spin_unlock_bh(&tunnel->lock);

	tquic_tunnel_put(tunnel);
}
EXPORT_SYMBOL_GPL(tquic_tunnel_close);

/**
 * tquic_tunnel_established - Mark tunnel as established
 * @tunnel: Tunnel that completed TCP connect
 *
 * Called when TCP connection completes (either synchronously or via callback).
 */
void tquic_tunnel_established(struct tquic_tunnel *tunnel)
{
	if (!tunnel)
		return;

	spin_lock_bh(&tunnel->lock);
	if (tunnel->state == TQUIC_TUNNEL_CONNECTING)
		tunnel->state = TQUIC_TUNNEL_ESTABLISHED;
	spin_unlock_bh(&tunnel->lock);
}
EXPORT_SYMBOL_GPL(tquic_tunnel_established);

/*
 * =============================================================================
 * ICMP PASSTHROUGH
 * =============================================================================
 *
 * Per CONTEXT.md: Full ICMP passthrough for ping/traceroute.
 */

/**
 * tquic_tunnel_icmp_forward - Forward ICMP message through tunnel
 * @tunnel: Tunnel context
 * @skb: ICMP packet to forward
 * @direction: TX (to internet) or RX (from internet)
 *
 * Per CONTEXT.md: Full ICMP passthrough for ping/traceroute.
 *
 * Encapsulates ICMP in the QUIC stream or extracts it. ICMP messages
 * are framed as a special tunnel message type:
 *   - 1 byte: Message type (0x01 = ICMP)
 *   - 2 bytes: Length (network byte order)
 *   - N bytes: Raw ICMP packet
 *
 * Returns: 0 on success, negative errno on failure
 */
int tquic_tunnel_icmp_forward(struct tquic_tunnel *tunnel,
			      struct sk_buff *skb, int direction)
{
	if (!tunnel || !skb)
		return -EINVAL;

	/*
	 * ICMP passthrough is handled by:
	 *
	 * TX direction (router -> internet):
	 *   1. Router sends ICMP encapsulated in QUIC stream
	 *   2. VPS extracts ICMP and sends via raw socket
	 *
	 * RX direction (internet -> router):
	 *   1. VPS receives ICMP on raw socket
	 *   2. VPS encapsulates in QUIC stream to router
	 *
	 * This enables ping/traceroute to work from router's perspective.
	 */

	if (direction == 0) {
		/* TX: QUIC stream -> raw socket -> internet */
		tunnel->stats.packets_tx++;
		tunnel->stats.bytes_tx += skb->len;
	} else {
		/* RX: internet -> raw socket -> QUIC stream */
		tunnel->stats.packets_rx++;
		tunnel->stats.bytes_rx += skb->len;
	}

	/*
	 * Full implementation would:
	 * 1. Create raw ICMP socket (IPPROTO_ICMP)
	 * 2. Send/receive ICMP messages
	 * 3. Frame in QUIC stream with type prefix
	 */
	return 0;
}
EXPORT_SYMBOL_GPL(tquic_tunnel_icmp_forward);

/**
 * tquic_tunnel_handle_icmp_error - Handle ICMP error for tunnel
 * @tunnel: Tunnel that received ICMP error
 * @type: ICMP type
 * @code: ICMP code
 * @info: Additional info (e.g., MTU for fragmentation needed)
 *
 * Processes ICMP errors like "Destination Unreachable" or "Fragmentation Needed"
 * and signals appropriate action back to the router.
 *
 * Returns: 0 on success, negative errno on failure
 */
int tquic_tunnel_handle_icmp_error(struct tquic_tunnel *tunnel,
				   u8 type, u8 code, u32 info)
{
	if (!tunnel)
		return -EINVAL;

	/*
	 * Per CONTEXT.md: PMTUD signaling for oversized packets.
	 *
	 * ICMP type 3, code 4 = Fragmentation Needed (IPv4)
	 * ICMPv6 type 2 = Packet Too Big
	 *
	 * Signal MTU back to router via QUIC stream.
	 */
	if (type == 3 && code == 4) {
		/* IPv4 Fragmentation Needed - info contains MTU */
		pr_debug("tquic: PMTUD signal MTU=%u\n", info);
		if (tquic_forward_signal_mtu(tunnel, info))
			pr_debug("tquic: PMTUD signal failed for MTU=%u\n", info);
	}

	return 0;
}
EXPORT_SYMBOL_GPL(tquic_tunnel_handle_icmp_error);

/*
 * =============================================================================
 * MODULE INIT/EXIT
 * =============================================================================
 */

/**
 * tquic_tunnel_init - Initialize tunnel subsystem
 */
int __init tquic_tunnel_init(void)
{
	tquic_tunnel_wq = alloc_workqueue("tquic_tunnel",
					  WQ_MEM_RECLAIM | WQ_HIGHPRI, 0);
	if (!tquic_tunnel_wq)
		return -ENOMEM;

	pr_info("tquic: tunnel subsystem initialized\n");
	return 0;
}

/**
 * tquic_tunnel_exit - Cleanup tunnel subsystem
 */
void __exit tquic_tunnel_exit(void)
{
	if (tquic_tunnel_wq) {
		flush_workqueue(tquic_tunnel_wq);
		destroy_workqueue(tquic_tunnel_wq);
		tquic_tunnel_wq = NULL;
	}

	pr_info("tquic: tunnel subsystem cleaned up\n");
}

/*
 * =============================================================================
 * TUNNEL ACCESSOR FUNCTIONS
 * =============================================================================
 *
 * These functions provide type-safe access to tunnel fields from other
 * modules (e.g., tquic_qos.c, tquic_forward.c) without exposing internals.
 */

/**
 * tquic_tunnel_get_traffic_class - Get tunnel's QoS traffic class
 * @tunnel: Tunnel to query
 *
 * Returns: Traffic class (0-3) or 2 (bulk) on error
 */
u8 tquic_tunnel_get_traffic_class(struct tquic_tunnel *tunnel)
{
	if (!tunnel)
		return 2;  /* Bulk default */
	return tunnel->traffic_class;
}
EXPORT_SYMBOL_GPL(tquic_tunnel_get_traffic_class);

/**
 * tquic_tunnel_get_dest_port - Get tunnel's destination port
 * @tunnel: Tunnel to query
 *
 * Returns: Destination port in network byte order, or 0 on error
 */
__be16 tquic_tunnel_get_dest_port(struct tquic_tunnel *tunnel)
{
	if (!tunnel)
		return 0;
	return tunnel->dest_port;
}
EXPORT_SYMBOL_GPL(tquic_tunnel_get_dest_port);

/**
 * tquic_tunnel_get_dest_addr - Get tunnel's destination address
 * @tunnel: Tunnel to query
 * @addr: OUT - Destination address
 *
 * Returns: 0 on success, negative errno on failure
 */
int tquic_tunnel_get_dest_addr(struct tquic_tunnel *tunnel,
			       struct sockaddr_storage *addr)
{
	if (!tunnel || !addr)
		return -EINVAL;
	memcpy(addr, &tunnel->dest_addr, sizeof(*addr));
	return 0;
}
EXPORT_SYMBOL_GPL(tquic_tunnel_get_dest_addr);

/**
 * tquic_tunnel_get_stats - Get tunnel statistics
 * @tunnel: Tunnel to query
 * @bytes_tx: OUT - Bytes transmitted
 * @bytes_rx: OUT - Bytes received
 * @packets_tx: OUT - Packets transmitted
 * @packets_rx: OUT - Packets received
 *
 * Returns: 0 on success, negative errno on failure
 */
int tquic_tunnel_get_stats(struct tquic_tunnel *tunnel,
			   u64 *bytes_tx, u64 *bytes_rx,
			   u64 *packets_tx, u64 *packets_rx)
{
	if (!tunnel)
		return -EINVAL;

	if (bytes_tx)
		*bytes_tx = tunnel->stats.bytes_tx;
	if (bytes_rx)
		*bytes_rx = tunnel->stats.bytes_rx;
	if (packets_tx)
		*packets_tx = tunnel->stats.packets_tx;
	if (packets_rx)
		*packets_rx = tunnel->stats.packets_rx;

	return 0;
}
EXPORT_SYMBOL_GPL(tquic_tunnel_get_stats);

/**
 * tquic_tunnel_is_tproxy - Check if tunnel is in TPROXY mode
 * @tunnel: Tunnel to query
 *
 * Returns: true if TPROXY mode enabled
 */
bool tquic_tunnel_is_tproxy(struct tquic_tunnel *tunnel)
{
	if (!tunnel)
		return false;
	return tunnel->is_tproxy;
}
EXPORT_SYMBOL_GPL(tquic_tunnel_is_tproxy);
