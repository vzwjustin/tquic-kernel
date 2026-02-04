// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * TQUIC - Transport QUIC with Multipath WAN Bonding
 *
 * Packet output path implementation
 * - UDP socket management
 * - sendmsg integration
 * - Packet transmission
 *
 * Copyright (c) 2024 Linux QUIC Authors
 * Copyright (c) 2026 Linux Foundation
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/skbuff.h>
#include <linux/netdevice.h>
#include <linux/socket.h>
#include <linux/udp.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/in.h>
#include <linux/in6.h>
#include <linux/uio.h>
#include <linux/slab.h>
#include <net/sock.h>
#include <net/udp.h>
#include <net/ip.h>
#include <net/ipv6.h>
#include <net/route.h>
#include <net/ip6_route.h>
#include <net/inet_common.h>
#include <net/tquic.h>
#include <net/tquic_frame.h>

/* Output path configuration */
#define TQUIC_OUTPUT_BATCH_SIZE		16
#define TQUIC_OUTPUT_SKB_HEADROOM	128
#define TQUIC_OUTPUT_MAX_COALESCE	3

/*
 * Default TTL/hop limit - configurable via module parameter
 *
 * Valid range: 1-255 (IP TTL field is 8 bits, 0 means drop immediately)
 */
#define TQUIC_TTL_MIN		1
#define TQUIC_TTL_MAX		255
#define TQUIC_TTL_DEFAULT	64

static unsigned int tquic_default_ttl __read_mostly = TQUIC_TTL_DEFAULT;
module_param(tquic_default_ttl, uint, 0644);
MODULE_PARM_DESC(tquic_default_ttl,
	"Default TTL/hop limit for TQUIC packets, 1-255 (default 64)");

/*
 * tquic_get_validated_ttl - Get validated TTL value
 *
 * Returns TTL clamped to valid range [1, 255].
 * Uses default if value is out of range.
 */
static inline u8 tquic_get_validated_ttl(void)
{
	unsigned int val = READ_ONCE(tquic_default_ttl);

	if (val < TQUIC_TTL_MIN || val > TQUIC_TTL_MAX) {
		pr_warn_once("TQUIC: ttl %u out of range [%u-%u], using default %u\n",
			     val, TQUIC_TTL_MIN, TQUIC_TTL_MAX, TQUIC_TTL_DEFAULT);
		return TQUIC_TTL_DEFAULT;
	}
	return (u8)val;
}

/* Pacing configuration */
#define TQUIC_PACING_SHIFT		10
#define TQUIC_PACING_MARGIN_US		1000

/* Maximum pending frames to prevent memory exhaustion */
#define TQUIC_MAX_PENDING_FRAMES	256

/* Maximum packet size */
#define TQUIC_MAX_PACKET_SIZE		1500

/* Output control block */
struct tquic_output_cb {
	u64		pn;
	ktime_t		send_time;
	u32		length;
	u8		pn_space;
	u8		encrypted:1;
	u8		ack_eliciting:1;
	u8		in_flight:1;
	u8		retransmission:1;
};

#define TQUIC_OUTPUT_CB(skb) ((struct tquic_output_cb *)((skb)->cb))

/* Per-CPU output state for batching */
struct tquic_output_state {
	struct sk_buff_head	queue;
	int			pending;
	ktime_t			next_send_time;
};

static DEFINE_PER_CPU(struct tquic_output_state, tquic_output_state);

/* Sysctl memory limits - extern declarations */
extern int sysctl_tquic_wmem[3];
extern int sysctl_tquic_rmem[3];

/*
 * External function declarations for packet building.
 * These are provided by other modules in the tquic implementation.
 */
extern bool tquic_ack_should_send(struct tquic_connection *conn, u8 pn_space);
extern int tquic_crypto_encrypt(void *ctx, struct sk_buff *skb, u64 pn);
extern int tquic_crypto_protect_header(void *ctx, struct sk_buff *skb,
				       u8 pn_offset, u8 pn_len);

/* Timer types for pacing */
#define TQUIC_TIMER_PACING	5

/* Sent packet tracking structure */
struct tquic_sent_packet {
	struct list_head	list;
	u64			pn;
	ktime_t			sent_time;
	u32			size;
	u32			ack_eliciting:1;
	u32			in_flight:1;
	u32			retransmitted:1;
	u32			has_crypto:1;
	u8			pn_space;
	struct sk_buff		*skb;
};

/* Stream info for cmsg */
struct tquic_stream_info {
	u64	stream_id;
	u32	stream_flags;
};

/* Stream flags */
#define TQUIC_STREAM_FLAG_NEW	0x01
#define TQUIC_STREAM_FLAG_UNI	0x02
#define TQUIC_STREAM_FLAG_FIN	0x04

/* Recv chunk for stream reassembly */
struct tquic_recv_chunk {
	struct rb_node	node;
	u64		offset;
	u32		len;
	u8		data[];
};

/* Stream receive buffer */
struct tquic_stream_recv_buf {
	struct rb_root		data_tree;
	spinlock_t		lock;
	u64			offset;
	u64			highest_offset;
	u64			final_size;
	u32			pending;
	u8			fin_received:1;
	u8			reset_received:1;
};

/* Connection state values */
#define TQUIC_STATE_CONNECTED	TQUIC_CONN_CONNECTED

/* Stream state values */
#define TQUIC_STREAM_STATE_RESET_RECVD	TQUIC_STREAM_RESET_RECVD

/* Variable-length integer encoding constants */
#define TQUIC_VARINT_1BYTE_MAX		63ULL
#define TQUIC_VARINT_2BYTE_MAX		16383ULL
#define TQUIC_VARINT_4BYTE_MAX		1073741823ULL
#define TQUIC_VARINT_8BYTE_MAX		4611686018427387903ULL

#define TQUIC_VARINT_2BYTE_PREFIX	0x40
#define TQUIC_VARINT_4BYTE_PREFIX	0x80
#define TQUIC_VARINT_8BYTE_PREFIX	0xc0

/*
 * UDP Socket Management
 */

/*
 * tquic_create_udp_socket - Create and configure UDP socket for TQUIC
 * @tsk: TQUIC socket
 * @family: Address family (AF_INET or AF_INET6)
 *
 * Creates a kernel UDP socket for QUIC packet encapsulation. For kernel 6.12+,
 * we access socket fields directly instead of using kernel_setsockopt() which
 * has been removed.
 *
 * Returns 0 on success, negative error code on failure.
 */
static int tquic_create_udp_socket(struct tquic_sock *tsk, int family)
{
	struct socket *sock;
	struct sock *sk;
	struct udp_sock *up;
	int err;

	if (!tsk)
		return -EINVAL;

	err = sock_create_kern(sock_net((struct sock *)tsk), family,
			       SOCK_DGRAM, IPPROTO_UDP, &sock);
	if (err)
		return err;

	sk = sock->sk;
	up = (struct udp_sock *)sk;

	/*
	 * Disable UDP checksums for IPv4 if hardware can do it.
	 * For kernel 6.12+, we set the socket field directly instead
	 * of using kernel_setsockopt(SO_NO_CHECK).
	 */
	if (family == AF_INET)
		sk->sk_no_check_tx = 1;

	/* Enable non-blocking mode */
	sock->file = NULL;
	sk->sk_allocation = GFP_ATOMIC;

	/*
	 * Set socket buffer sizes directly on the socket.
	 * kernel_setsockopt() is removed in kernel 6.12+.
	 */
	sk->sk_sndbuf = sysctl_tquic_wmem[1];
	sk->sk_rcvbuf = sysctl_tquic_rmem[1];

	/*
	 * Mark as TQUIC encapsulation socket.
	 * encap_type = 1 indicates generic encapsulation.
	 */
	up->encap_type = 1;

	/* Link to TQUIC socket for callback dispatch */
	sk->sk_user_data = tsk;

	/*
	 * Enable GRO (Generic Receive Offload) on the UDP socket.
	 * For kernel 6.12+, we use set_bit() on udp_flags directly
	 * instead of kernel_setsockopt(UDP_GRO).
	 */
	set_bit(UDP_FLAGS_GRO_ENABLED, &up->udp_flags);

	/* Store the socket in the TQUIC socket structure */
	tsk->udp_sock = sock;

	return 0;
}

/*
 * tquic_bind_udp_socket - Bind UDP socket to local address
 * @tsk: TQUIC socket
 * @addr: Local address to bind to
 * @addr_len: Length of address structure
 *
 * Binds the UDP encapsulation socket to a local address. This allows the
 * QUIC connection to use a specific local port and/or address.
 *
 * Returns 0 on success, negative error code on failure.
 */
static int tquic_bind_udp_socket(struct tquic_sock *tsk,
				 struct sockaddr *addr, int addr_len)
{
	struct socket *sock;
	int err;

	if (!tsk)
		return -EINVAL;

	sock = tsk->udp_sock;
	if (!sock)
		return -ENOENT;

	/* Use kernel_bind to bind the UDP socket */
	err = kernel_bind(sock, addr, addr_len);
	if (err)
		return err;

	/* Store the bound address */
	memcpy(&tsk->bind_addr, addr, min_t(int, addr_len,
					    sizeof(tsk->bind_addr)));

	return 0;
}

/*
 * tquic_connect_udp_socket - Connect UDP socket to remote address
 * @tsk: TQUIC socket
 * @addr: Remote address to connect to
 * @addr_len: Length of address structure
 *
 * Connects the UDP encapsulation socket to a remote address. This sets the
 * default destination for outgoing packets, enabling sendmsg without
 * specifying the destination each time.
 *
 * Returns 0 on success, negative error code on failure.
 */
static int tquic_connect_udp_socket(struct tquic_sock *tsk,
				    struct sockaddr *addr, int addr_len)
{
	struct socket *sock;
	int err;

	if (!tsk)
		return -EINVAL;

	sock = tsk->udp_sock;
	if (!sock)
		return -ENOENT;

	/* Use kernel_connect to connect the UDP socket */
	err = kernel_connect(sock, addr, addr_len, O_NONBLOCK);
	if (err && err != -EINPROGRESS)
		return err;

	/* Store the connected address */
	memcpy(&tsk->connect_addr, addr, min_t(int, addr_len,
					       sizeof(tsk->connect_addr)));

	return 0;
}

/*
 * Packet Output Functions
 */

/* Allocate skb for TQUIC packet output */
struct sk_buff *tquic_alloc_tx_skb(struct tquic_connection *conn, u32 size)
{
	struct sock *sk = conn->sk;
	struct sk_buff *skb;
	int headroom;

	/* Calculate required headroom for headers */
	headroom = TQUIC_OUTPUT_SKB_HEADROOM;

	/* Account for memory limits */
	if (sk_wmem_alloc_get(sk) > sk->sk_sndbuf)
		return NULL;

	skb = alloc_skb(headroom + size + 16, GFP_ATOMIC);  /* +16 for AEAD tag */
	if (!skb)
		return NULL;

	skb_reserve(skb, headroom);

	/* Set socket for memory accounting */
	skb_set_owner_w(skb, sk);

	return skb;
}
EXPORT_SYMBOL(tquic_alloc_tx_skb);

/* Free TX skb */
void tquic_free_tx_skb(struct sk_buff *skb)
{
	kfree_skb(skb);
}
EXPORT_SYMBOL(tquic_free_tx_skb);

#ifndef TQUIC_OUT_OF_TREE
/* Get ECN marking for path - use path's cc state */
u8 tquic_ecn_get_marking(struct tquic_path *path)
{
	/* Default to ECT(0) if ECN is enabled, otherwise Not-ECT */
	return 0x02;  /* ECT(0) */
}

/* Track ECN-marked packet sent */
void tquic_ecn_on_packet_sent(struct tquic_path *path, u8 ecn_marking)
{
	/* Track ECN counts - implementation specific */
}
#endif /* TQUIC_OUT_OF_TREE */

/* Build UDP header for TQUIC packet */
static void tquic_build_udp_header(struct sk_buff *skb,
				   struct tquic_connection *conn,
				   int payload_len)
{
	struct udphdr *uh;
	struct tquic_path *path = conn->active_path;
	__be16 sport, dport;

	/* Get port numbers from path addresses */
	if (path->local_addr.ss_family == AF_INET) {
		struct sockaddr_in *sin = (struct sockaddr_in *)&path->local_addr;
		sport = sin->sin_port;
		sin = (struct sockaddr_in *)&path->remote_addr;
		dport = sin->sin_port;
	} else {
		struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)&path->local_addr;
		sport = sin6->sin6_port;
		sin6 = (struct sockaddr_in6 *)&path->remote_addr;
		dport = sin6->sin6_port;
	}

	/* Push UDP header */
	uh = skb_push(skb, sizeof(struct udphdr));
	skb_reset_transport_header(skb);

	uh->source = sport;
	uh->dest = dport;
	uh->len = htons(sizeof(struct udphdr) + payload_len);
	uh->check = 0;  /* Computed later or by hardware */
}

/* Build IPv4 header for TQUIC packet */
static int tquic_build_ipv4_header(struct sk_buff *skb,
				   struct tquic_connection *conn)
{
	struct tquic_path *path = conn->active_path;
	struct sockaddr_in *saddr = (struct sockaddr_in *)&path->local_addr;
	struct sockaddr_in *daddr = (struct sockaddr_in *)&path->remote_addr;
	struct iphdr *iph;
	struct rtable *rt;
	struct flowi4 fl4;

	/* Look up route */
	memset(&fl4, 0, sizeof(fl4));
	fl4.saddr = saddr->sin_addr.s_addr;
	fl4.daddr = daddr->sin_addr.s_addr;
	fl4.flowi4_proto = IPPROTO_UDP;
	fl4.fl4_sport = saddr->sin_port;
	fl4.fl4_dport = daddr->sin_port;

	rt = ip_route_output_key(sock_net(conn->sk), &fl4);
	if (IS_ERR(rt))
		return PTR_ERR(rt);

	skb_dst_set(skb, &rt->dst);

	/* Push IP header */
	iph = skb_push(skb, sizeof(struct iphdr));
	skb_reset_network_header(skb);

	iph->version = 4;
	iph->ihl = 5;
	/* Set ECN bits from path's ECN marking (RFC 9000 Section 13.4) */
	iph->tos = tquic_ecn_get_marking(path);
	iph->tot_len = htons(skb->len);
	iph->id = 0;
	iph->frag_off = htons(IP_DF);
	iph->ttl = tquic_get_validated_ttl();
	iph->protocol = IPPROTO_UDP;
	iph->check = 0;
	iph->saddr = fl4.saddr;
	iph->daddr = fl4.daddr;

	/* Compute IP header checksum */
	ip_send_check(iph);

	/* Compute UDP checksum */
	skb->ip_summed = CHECKSUM_PARTIAL;
	skb->csum_start = skb_transport_header(skb) - skb->head;
	skb->csum_offset = offsetof(struct udphdr, check);

	return 0;
}

#if IS_ENABLED(CONFIG_IPV6)
/* Build IPv6 header for TQUIC packet */
static int tquic_build_ipv6_header(struct sk_buff *skb,
				   struct tquic_connection *conn)
{
	struct tquic_path *path = conn->active_path;
	struct sockaddr_in6 *saddr = (struct sockaddr_in6 *)&path->local_addr;
	struct sockaddr_in6 *daddr = (struct sockaddr_in6 *)&path->remote_addr;
	struct ipv6hdr *ip6h;
	struct dst_entry *dst;
	struct flowi6 fl6;

	/* Look up route */
	memset(&fl6, 0, sizeof(fl6));
	fl6.saddr = saddr->sin6_addr;
	fl6.daddr = daddr->sin6_addr;
	fl6.flowi6_proto = IPPROTO_UDP;
	fl6.fl6_sport = saddr->sin6_port;
	fl6.fl6_dport = daddr->sin6_port;

	dst = ip6_route_output(sock_net(conn->sk), NULL, &fl6);
	if (IS_ERR(dst))
		return PTR_ERR(dst);

	if (dst->error) {
		dst_release(dst);
		return dst->error;
	}

	skb_dst_set(skb, dst);

	/* Push IPv6 header */
	ip6h = skb_push(skb, sizeof(struct ipv6hdr));
	skb_reset_network_header(skb);

	/* Set traffic class with ECN bits (RFC 9000 Section 13.4) */
	ip6_flow_hdr(ip6h, tquic_ecn_get_marking(path), 0);
	ip6h->payload_len = htons(skb->len - sizeof(struct ipv6hdr));
	ip6h->nexthdr = IPPROTO_UDP;
	ip6h->hop_limit = tquic_get_validated_ttl();
	ip6h->saddr = saddr->sin6_addr;
	ip6h->daddr = daddr->sin6_addr;

	/* Setup for UDP checksum */
	skb->ip_summed = CHECKSUM_PARTIAL;
	skb->csum_start = skb_transport_header(skb) - skb->head;
	skb->csum_offset = offsetof(struct udphdr, check);

	return 0;
}
#endif /* CONFIG_IPV6 */

/* Send skb directly to network device */
static int tquic_xmit_skb(struct sk_buff *skb, struct tquic_connection *conn)
{
	struct net_device *dev;
	int err;

	if (!skb_dst(skb))
		return -EHOSTUNREACH;

	dev = skb_dst(skb)->dev;
	skb->dev = dev;

	/* Set protocol */
	if (conn->active_path->local_addr.ss_family == AF_INET)
		skb->protocol = htons(ETH_P_IP);
	else
		skb->protocol = htons(ETH_P_IPV6);

	/* Send via IP layer */
	if (conn->active_path->local_addr.ss_family == AF_INET) {
		err = ip_local_out(sock_net(conn->sk), conn->sk, skb);
	} else {
#if IS_ENABLED(CONFIG_IPV6)
		err = ip6_local_out(sock_net(conn->sk), conn->sk, skb);
#else
		kfree_skb(skb);
		err = -EAFNOSUPPORT;
#endif
	}

	return err;
}

/*
 * tquic_sendmsg_locked - Send TQUIC packet using kernel_sendmsg interface
 * @tsk: TQUIC socket
 * @skb: Socket buffer containing the QUIC packet to send
 * @dest: Destination address (may be NULL if socket is connected)
 *
 * Sends a QUIC packet through the UDP encapsulation socket using the
 * kernel_sendmsg() interface. This is the sendmsg path for packet transmission.
 *
 * The caller must hold appropriate locks. The skb is consumed regardless of
 * success or failure (i.e., the caller should not free it).
 *
 * Returns number of bytes sent on success, negative error code on failure.
 */
static int tquic_sendmsg_locked(struct tquic_sock *tsk, struct sk_buff *skb,
				struct sockaddr *dest)
{
	struct socket *sock;
	struct msghdr msg;
	struct kvec iov;
	int addr_len;
	int ret;

	if (!tsk || !skb)
		return -EINVAL;

	sock = tsk->udp_sock;
	if (!sock) {
		kfree_skb(skb);
		return -ENOENT;
	}

	/* Initialize message header */
	memset(&msg, 0, sizeof(msg));

	/* Set destination address if provided */
	if (dest) {
		msg.msg_name = dest;
		if (dest->sa_family == AF_INET)
			addr_len = sizeof(struct sockaddr_in);
		else if (dest->sa_family == AF_INET6)
			addr_len = sizeof(struct sockaddr_in6);
		else {
			kfree_skb(skb);
			return -EAFNOSUPPORT;
		}
		msg.msg_namelen = addr_len;
	}

	/* Set up the I/O vector to point to skb data */
	iov.iov_base = skb->data;
	iov.iov_len = skb->len;

	/* Send the packet */
	ret = kernel_sendmsg(sock, &msg, &iov, 1, skb->len);

	/* Always consume the skb */
	kfree_skb(skb);

	return ret;
}

/*
 * tquic_output_set_ecn - Set ECN marking on UDP socket before sending
 * @sock: UDP socket to configure
 * @path: TQUIC path containing address family information
 *
 * Per RFC 9000 Section 13.4, we need to set ECN bits in the IP header.
 * For the sendmsg path, we do this by setting the TOS/traffic class
 * directly on the socket. This avoids kernel_setsockopt() which is
 * removed in kernel 6.12+.
 *
 * For IPv4, we set inet_sk(sk)->tos which controls the IP_TOS field.
 * For IPv6, we set inet6_sk(sk)->tclass which controls the traffic class.
 *
 * The ECN bits are the low 2 bits of the TOS/traffic class field:
 *   00 = Not-ECT (ECN not supported)
 *   01 = ECT(1)
 *   10 = ECT(0) - preferred for QUIC
 *   11 = CE (Congestion Experienced)
 */
static void tquic_output_set_ecn(struct socket *sock, struct tquic_path *path)
{
	u8 ecn_marking;

	if (!sock || !sock->sk || !path)
		return;

	ecn_marking = tquic_ecn_get_marking(path);

	/*
	 * Set ECN bits on the socket directly. For kernel 6.12+, we access
	 * socket fields directly instead of using kernel_setsockopt().
	 */
	if (path->local_addr.ss_family == AF_INET) {
		/*
		 * For IPv4, set the TOS field on inet socket.
		 * ECN bits are in the low 2 bits of the TOS byte.
		 */
		inet_sk(sock->sk)->tos = ecn_marking;
	}
#if IS_ENABLED(CONFIG_IPV6)
	else if (path->local_addr.ss_family == AF_INET6) {
		/*
		 * For IPv6, set the traffic class on inet6 socket.
		 * The traffic class includes DSCP (6 bits) + ECN (2 bits).
		 */
		inet6_sk(sock->sk)->tclass = ecn_marking;
	}
#endif
}

/* Congestion control on packet sent - use path's cc state */
static void tquic_cc_on_packet_sent(struct tquic_path *path, u32 bytes)
{
	path->cc.bytes_in_flight += bytes;
}

/* Get pacing delay from congestion control */
static u64 tquic_cc_pacing_delay(struct tquic_path *path, u32 bytes)
{
	/* Calculate delay based on pacing rate if available */
	return 0;  /* No delay by default */
}

/* Main output function - send single packet */
int tquic_output(struct tquic_connection *conn, struct sk_buff *skb)
{
	struct tquic_path *path = conn->active_path;
	struct tquic_output_cb *cb;
	int payload_len;
	int err;
	u8 ecn_marking;

	if (!path || !conn->sk)
		return -ENOENT;

	payload_len = skb->len;

	/*
	 * Set ECN marking on outgoing packet (RFC 9000 Section 13.4)
	 *
	 * Get the ECN marking before sending and track it for validation.
	 */
	ecn_marking = tquic_ecn_get_marking(path);

	/* Build headers */
	tquic_build_udp_header(skb, conn, payload_len);

	/* Build IP header and send */
	if (path->local_addr.ss_family == AF_INET) {
		err = tquic_build_ipv4_header(skb, conn);
		if (err) {
			kfree_skb(skb);
			return err;
		}
	} else {
#if IS_ENABLED(CONFIG_IPV6)
		err = tquic_build_ipv6_header(skb, conn);
		if (err) {
			kfree_skb(skb);
			return err;
		}
#else
		kfree_skb(skb);
		return -EAFNOSUPPORT;
#endif
	}

	err = tquic_xmit_skb(skb, conn);

	if (err >= 0) {
		/* Track ECN-marked packet sent for validation */
		tquic_ecn_on_packet_sent(path, ecn_marking);

		/* Update output callback */
		cb = TQUIC_OUTPUT_CB(skb);
		cb->send_time = ktime_get();
		cb->length = payload_len;
		cb->in_flight = 1;

		/* Update path statistics */
		path->stats.tx_bytes += payload_len;
		path->stats.tx_packets++;

		/* Update congestion control */
		tquic_cc_on_packet_sent(path, payload_len);

		err = 0;
	}

	return err;
}
EXPORT_SYMBOL(tquic_output);

/* Send multiple packets with coalescing support */
int tquic_output_batch(struct tquic_connection *conn,
		       struct sk_buff_head *queue)
{
	struct sk_buff *skb, *next;
	int sent = 0;
	int err = 0;

	skb_queue_walk_safe(queue, skb, next) {
		__skb_unlink(skb, queue);

		err = tquic_output(conn, skb);
		if (err) {
			kfree_skb(skb);
			break;
		}

		kfree_skb(skb);
		sent++;
	}

	return sent ? sent : err;
}
EXPORT_SYMBOL(tquic_output_batch);

/*
 * Pacing Support
 *
 * QUIC implements pacing to smooth out packet transmission and
 * avoid bursts that could cause congestion.
 */

/* Calculate pacing delay for next packet */
static ktime_t tquic_pacing_delay(struct tquic_connection *conn, u32 bytes)
{
	struct tquic_path *path = conn->active_path;
	u64 delay_ns;

	if (!path)
		return ns_to_ktime(0);

	/* Calculate delay: bytes / pacing_rate (in nanoseconds) */
	delay_ns = tquic_cc_pacing_delay(path, bytes);

	return ns_to_ktime(delay_ns);
}

/* Check if we should send now or wait for pacing */
static bool tquic_pacing_allow(struct tquic_connection *conn)
{
	/* For now, always allow sending - pacing managed by timer_state */
	return true;
}

/*
 * Queue packet to pacing queue and schedule timer
 *
 * When pacing doesn't allow immediate send, packets are queued and
 * a timer is set to transmit them at the appropriate time.
 */
static int tquic_pacing_queue_packet(struct tquic_connection *conn,
				     struct sk_buff *skb)
{
	/* Limit pacing queue to prevent memory exhaustion */
	if (skb_queue_len(&conn->control_frames) >= TQUIC_MAX_PENDING_FRAMES) {
		kfree_skb(skb);
		return -ENOBUFS;
	}

	/* Add to control frames queue for later transmission */
	skb_queue_tail(&conn->control_frames, skb);

	return 0;
}

/*
 * Paced output - respects pacing constraints
 *
 * Per RFC 9002 Section 7.7: "A sender SHOULD pace sending of all in-flight
 * packets based on input from the congestion controller."
 *
 * This function checks if pacing allows sending now. If not, the packet
 * is queued and a timer is scheduled to send it later at the appropriate
 * pacing interval.
 */
int tquic_output_paced(struct tquic_connection *conn, struct sk_buff *skb)
{
	struct tquic_path *path = conn->active_path;
	u64 delay_ns;
	ktime_t now;
	int err;

	/* Check pacing */
	if (!tquic_pacing_allow(conn)) {
		/* Queue for later transmission with timer */
		return tquic_pacing_queue_packet(conn, skb);
	}

	/* Send now */
	err = tquic_output(conn, skb);
	if (!err && path) {
		now = ktime_get();

		/* Calculate next allowed send time based on packet size */
		delay_ns = tquic_cc_pacing_delay(path, skb->len);
	}

	return err;
}
EXPORT_SYMBOL(tquic_output_paced);

/*
 * GSO Support for Output
 *
 * When sending large amounts of data, we can use GSO to batch
 * multiple TQUIC packets into a single super-packet for more
 * efficient kernel processing.
 */

/* Setup GSO for a batch of TQUIC packets */
static int tquic_setup_gso(struct sk_buff *skb, u16 gso_size, u16 segs)
{
	skb_shinfo(skb)->gso_size = gso_size;
	skb_shinfo(skb)->gso_segs = segs;
	skb_shinfo(skb)->gso_type = SKB_GSO_UDP_L4;

	return 0;
}

/* Send data using GSO if beneficial */
int tquic_output_gso(struct tquic_connection *conn, struct sk_buff_head *queue)
{
	struct sk_buff *skb, *gso_skb;
	u32 total_len = 0;
	u16 seg_count = 0;
	u16 mss;
	int err;

	/* Calculate MSS from path MTU */
	mss = conn->active_path->mtu - 40;  /* Subtract IP + UDP headers */
	if (mss > TQUIC_MAX_PACKET_SIZE)
		mss = TQUIC_MAX_PACKET_SIZE;

	/* Check if GSO is worthwhile (need at least 2 packets) */
	if (skb_queue_len(queue) < 2)
		return tquic_output_batch(conn, queue);

	/* Calculate total length and segment count */
	skb_queue_walk(queue, skb) {
		total_len += skb->len;
		seg_count++;
	}

	/* Limit segments */
	if (seg_count > 64)
		seg_count = 64;

	/* Allocate GSO skb */
	gso_skb = alloc_skb(TQUIC_OUTPUT_SKB_HEADROOM + total_len + 128, GFP_ATOMIC);
	if (!gso_skb)
		return tquic_output_batch(conn, queue);

	skb_reserve(gso_skb, TQUIC_OUTPUT_SKB_HEADROOM);

	/* Copy all packets into GSO skb */
	while ((skb = __skb_dequeue(queue)) != NULL) {
		u8 *p = skb_put(gso_skb, skb->len);
		skb_copy_bits(skb, 0, p, skb->len);
		kfree_skb(skb);
	}

	/* Setup GSO */
	tquic_setup_gso(gso_skb, mss, seg_count);

	/* Set socket for memory accounting */
	skb_set_owner_w(gso_skb, conn->sk);

	/* Send GSO packet */
	err = tquic_output(conn, gso_skb);
	if (err)
		kfree_skb(gso_skb);

	return err;
}
EXPORT_SYMBOL(tquic_output_gso);

/*
 * Coalesced Packet Support
 *
 * QUIC allows multiple packets at different encryption levels to be
 * coalesced into a single UDP datagram. This is especially useful
 * during the handshake.
 */

/* Coalesce multiple TQUIC packets */
struct sk_buff *tquic_coalesce_skbs(struct sk_buff_head *packets)
{
	struct sk_buff *coalesced, *skb;
	u32 total_len = 0;
	u8 *p;

	if (skb_queue_empty(packets))
		return NULL;

	/* Calculate total length */
	skb_queue_walk(packets, skb) {
		total_len += skb->len;
	}

	/* Check against maximum packet size */
	if (total_len > TQUIC_MAX_PACKET_SIZE)
		return NULL;

	/* Allocate coalesced skb */
	coalesced = alloc_skb(TQUIC_OUTPUT_SKB_HEADROOM + total_len + 16, GFP_ATOMIC);
	if (!coalesced)
		return NULL;

	skb_reserve(coalesced, TQUIC_OUTPUT_SKB_HEADROOM);

	/* Copy all packets */
	while ((skb = __skb_dequeue(packets)) != NULL) {
		p = skb_put(coalesced, skb->len);
		skb_copy_bits(skb, 0, p, skb->len);
		kfree_skb(skb);
	}

	return coalesced;
}
EXPORT_SYMBOL(tquic_coalesce_skbs);

/* Send coalesced packet */
int tquic_output_coalesced(struct tquic_connection *conn,
			   struct sk_buff_head *packets)
{
	struct sk_buff *skb;
	int err;

	skb = tquic_coalesce_skbs(packets);
	if (!skb)
		return -ENOMEM;

	/* Set socket for memory accounting */
	skb_set_owner_w(skb, conn->sk);

	err = tquic_output(conn, skb);
	if (err)
		kfree_skb(skb);

	return err;
}
EXPORT_SYMBOL(tquic_output_coalesced);

/*
 * Retransmission Support
 */

/* Retransmit a packet */
int tquic_retransmit(struct tquic_connection *conn, struct tquic_sent_packet *pkt)
{
	struct sk_buff *skb, *clone;
	int err;

	if (!pkt->skb)
		return -EINVAL;

	/* Clone the original skb */
	clone = skb_clone(pkt->skb, GFP_ATOMIC);
	if (!clone)
		return -ENOMEM;

	/* Mark as retransmission */
	TQUIC_OUTPUT_CB(clone)->retransmission = 1;

	/* Update packet number (will be set during encryption) */
	pkt->retransmitted = 1;

	err = tquic_output(conn, clone);
	if (err)
		kfree_skb(clone);

	return err;
}
EXPORT_SYMBOL(tquic_retransmit);

/*
 * sendmsg Interface
 *
 * Integration with socket sendmsg for user-space applications.
 */

/* Process sendmsg for TQUIC socket */
int tquic_do_sendmsg(struct sock *sk, struct msghdr *msg, size_t len)
{
	struct tquic_sock *tsk = tquic_sk(sk);
	struct tquic_connection *conn = tsk->conn;
	struct tquic_stream *stream = NULL;
	struct tquic_stream_info sinfo;
	struct cmsghdr *cmsg;
	struct sk_buff *skb;
	u64 stream_id = 0;
	u32 flags = 0;
	size_t remaining = len;
	size_t sent = 0;
	int err;

	if (!conn || conn->state != TQUIC_STATE_CONNECTED)
		return -ENOTCONN;

	/* Parse control message for stream info */
	for_each_cmsghdr(cmsg, msg) {
		if (!CMSG_OK(msg, cmsg))
			return -EINVAL;

		if (cmsg->cmsg_level != SOL_TQUIC)
			continue;

		if (cmsg->cmsg_type == TQUIC_STREAM_ID) {
			if (cmsg->cmsg_len < CMSG_LEN(sizeof(sinfo)))
				return -EINVAL;
			memcpy(&sinfo, CMSG_DATA(cmsg), sizeof(sinfo));
			stream_id = sinfo.stream_id;
			flags = sinfo.stream_flags;
		}
	}

	/* Find or create stream */
	if (flags & TQUIC_STREAM_FLAG_NEW) {
		stream = tquic_stream_open(conn, !(flags & TQUIC_STREAM_FLAG_UNI));
		if (!stream)
			return -ENOMEM;
		stream_id = stream->id;
	} else {
		/* Look up existing stream - simplified for this conversion */
		return -ENOENT;
	}

	/* Send data in MTU-sized chunks */
	while (remaining > 0) {
		size_t chunk_size;
		u8 *data;

		/* Calculate chunk size based on MTU and flow control */
		chunk_size = min_t(size_t, remaining,
				   conn->active_path->mtu - 100);

		/* Allocate and build STREAM frame */
		skb = tquic_alloc_tx_skb(conn, chunk_size + 32);
		if (!skb) {
			if (sent > 0)
				break;
			return -ENOMEM;
		}

		/* Build STREAM frame header */
		data = skb_put(skb, 1);
		*data = TQUIC_FRAME_STREAM_BASE | TQUIC_STREAM_FLAG_LEN;

		if (stream->send_offset > 0)
			*data |= TQUIC_STREAM_FLAG_OFF;

		if (remaining <= chunk_size && (flags & TQUIC_STREAM_FLAG_FIN))
			*data |= TQUIC_STREAM_FLAG_FIN;

		/* Encode stream ID */
		data = skb_put(skb, 8);
		{
			int varint_len = 0;
			if (stream_id < 64) {
				data[0] = stream_id;
				varint_len = 1;
			} else if (stream_id < 16384) {
				data[0] = 0x40 | (stream_id >> 8);
				data[1] = stream_id & 0xff;
				varint_len = 2;
			} else {
				/* Full 8-byte encoding */
				varint_len = 8;
			}
			skb_trim(skb, skb->len - (8 - varint_len));
		}

		/* Encode offset if needed */
		if (stream->send_offset > 0) {
			data = skb_put(skb, 8);
			/* Simplified varint encoding for offset */
			skb_trim(skb, skb->len - 6);
			data[0] = 0x40 | ((stream->send_offset >> 8) & 0x3f);
			data[1] = stream->send_offset & 0xff;
		}

		/* Encode length */
		data = skb_put(skb, 2);
		data[0] = 0x40 | ((chunk_size >> 8) & 0x3f);
		data[1] = chunk_size & 0xff;

		/* Copy data from user */
		data = skb_put(skb, chunk_size);
		if (!copy_from_iter_full(data, chunk_size, &msg->msg_iter)) {
			kfree_skb(skb);
			err = -EFAULT;
			goto out_put_stream;
		}

		/* Queue for transmission */
		skb_queue_tail(&conn->control_frames, skb);

		/* Update offsets */
		stream->send_offset += chunk_size;

		remaining -= chunk_size;
		sent += chunk_size;
	}

	/* Trigger transmission */
	if (sent > 0)
		schedule_work(&conn->tx_work);

	if (flags & TQUIC_STREAM_FLAG_FIN)
		stream->fin_sent = 1;

	err = sent;

out_put_stream:
	return err;
}
EXPORT_SYMBOL(tquic_do_sendmsg);

/*
 * TQUIC SKB Control Block
 *
 * This structure is used by tquic_packet_build to communicate packet metadata
 * to the crypto layer. The layout matches tquic_skb_cb defined in quic_packet.c
 * and quic_key_update.h.
 */
struct tquic_build_skb_cb {
	u64	pn;		/* Packet number */
	u32	header_len;	/* Header length (for AEAD AAD) */
	u8	pn_len;		/* Packet number length (1-4) */
	u8	packet_type;	/* Packet type (for long header) */
	u8	dcid_len;	/* DCID length */
	u8	scid_len;	/* SCID length */
};

#define TQUIC_BUILD_SKB_CB(skb) ((struct tquic_build_skb_cb *)((skb)->cb))

/*
 * tquic_packet_build - Build a QUIC packet for the given packet number space
 * @conn: TQUIC connection
 * @pn_space: Packet number space (INITIAL, HANDSHAKE, or APPLICATION)
 *
 * This function builds a complete QUIC packet including:
 * 1. Allocating an sk_buff
 * 2. Building the appropriate header (long for Initial/Handshake, short for 1-RTT)
 * 3. Including pending frames for that space (ACK, CRYPTO, STREAM, etc.)
 * 4. Applying AEAD encryption to the payload
 * 5. Applying header protection
 *
 * Per RFC 9000, the function handles three packet number spaces:
 * - TQUIC_PN_SPACE_INITIAL (0): Initial packets during handshake
 * - TQUIC_PN_SPACE_HANDSHAKE (1): Handshake packets
 * - TQUIC_PN_SPACE_APPLICATION (2): 1-RTT application data packets
 *
 * Returns: sk_buff containing the built packet, or NULL on failure
 */
struct sk_buff *tquic_packet_build(struct tquic_connection *conn, int pn_space)
{
	struct tquic_pn_space *space;
	struct tquic_path *path;
	struct sk_buff *skb;
	struct tquic_build_skb_cb *cb;
	u8 *header;
	u8 *payload;
	u8 *p;
	u64 pn;
	int header_len;
	int payload_len;
	int pn_len;
	int pn_offset;
	int total_len;
	int remaining;
	int ret;
	bool need_ack;
	bool is_long_header;
	u8 first_byte;
	u8 packet_type;

	if (!conn || pn_space < 0 || pn_space >= TQUIC_PN_SPACE_COUNT)
		return NULL;

	space = &conn->pn_spaces[pn_space];
	path = conn->active_path;

	if (!path)
		return NULL;

	/* Check if keys are available and not discarded */
	if (!space->keys_available || space->keys_discarded)
		return NULL;

	/*
	 * Allocate working buffers for header and payload construction.
	 * We build the packet in these buffers first, then copy to the skb
	 * after encryption is complete.
	 */
	header = kmalloc(128, GFP_ATOMIC);
	payload = kmalloc(path->mtu, GFP_ATOMIC);
	if (!header || !payload) {
		kfree(header);
		kfree(payload);
		return NULL;
	}

	/*
	 * Get next packet number and increment atomically.
	 * RFC 9000 Section 12.3: Packet numbers MUST increase by at least 1.
	 */
	pn = space->next_pn++;

	/*
	 * Determine packet type based on packet number space.
	 * Per RFC 9000:
	 * - Initial packets use long header with type 0x00
	 * - Handshake packets use long header with type 0x02
	 * - Application data (1-RTT) uses short header
	 */
	is_long_header = (pn_space != TQUIC_PN_SPACE_APPLICATION);

	/*
	 * Calculate packet number length.
	 * RFC 9000 Section 17.1: PN length is encoded using 2 bits,
	 * representing 1-4 bytes. For simplicity and to ensure packets
	 * are not rejected due to truncated PNs, we use 4 bytes for
	 * long headers and minimal encoding for short headers.
	 */
	if (is_long_header) {
		pn_len = 4;
	} else {
		/* For short header, use minimal encoding based on distance from largest_acked */
		u64 diff = pn - space->largest_acked;
		if (diff < 128)
			pn_len = 1;
		else if (diff < 32768)
			pn_len = 2;
		else if (diff < 8388608)
			pn_len = 3;
		else
			pn_len = 4;
	}

	/*
	 * Build packet header
	 */
	p = header;

	if (is_long_header) {
		/*
		 * Long Header Format (RFC 9000 Section 17.2):
		 *
		 * +-+-+-+-+-+-+-+-+
		 * |1|1|T T|X X X X|  First byte
		 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
		 * |                         Version (32)                         |
		 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
		 * | DCID Len (8)  |
		 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
		 * |               Destination Connection ID (0..160)           ...
		 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
		 * | SCID Len (8)  |
		 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
		 * |                 Source Connection ID (0..160)              ...
		 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
		 */
		switch (pn_space) {
		case TQUIC_PN_SPACE_INITIAL:
			packet_type = 0x00;  /* Initial */
			break;
		case TQUIC_PN_SPACE_HANDSHAKE:
			packet_type = 0x02;  /* Handshake */
			break;
		default:
			packet_type = 0x01;  /* 0-RTT (shouldn't reach here) */
			break;
		}

		/* First byte: form(1) | fixed(1) | type(2) | reserved(2) | pn_len(2) */
		first_byte = 0x80 | 0x40 | (packet_type << 4) | (pn_len - 1);
		*p++ = first_byte;

		/* Version (4 bytes, big-endian) */
		*p++ = (conn->version >> 24) & 0xff;
		*p++ = (conn->version >> 16) & 0xff;
		*p++ = (conn->version >> 8) & 0xff;
		*p++ = conn->version & 0xff;

		/* DCID Length + DCID */
		*p++ = conn->dcid.len;
		if (conn->dcid.len > 0) {
			memcpy(p, conn->dcid.id, conn->dcid.len);
			p += conn->dcid.len;
		}

		/* SCID Length + SCID */
		*p++ = conn->scid.len;
		if (conn->scid.len > 0) {
			memcpy(p, conn->scid.id, conn->scid.len);
			p += conn->scid.len;
		}

		/* Token (Initial packets only) */
		if (pn_space == TQUIC_PN_SPACE_INITIAL) {
			/* Token length (0 for client initial without retry) */
			*p++ = 0;
		}

		/* Length field placeholder - will be filled after payload is built */
		/* We reserve 2 bytes for length (sufficient for packets up to 16383 bytes) */
		pn_offset = p - header + 2;  /* After length field */

	} else {
		/*
		 * Short Header Format (RFC 9000 Section 17.3):
		 *
		 * +-+-+-+-+-+-+-+-+
		 * |0|1|S|R|R|K|P P|  First byte
		 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
		 * |               Destination Connection ID (0..160)           ...
		 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
		 * |                      Packet Number (8/16/24/32)            ...
		 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
		 */
		packet_type = 0xff;  /* Not used for short header */

		/* First byte: form(0) | fixed(1) | spin(0) | reserved(2) | key_phase | pn_len(2) */
		first_byte = 0x40 | (pn_len - 1);  /* Key phase 0, spin bit 0 */
		*p++ = first_byte;

		/* DCID (no length field - known from connection state) */
		if (conn->dcid.len > 0) {
			memcpy(p, conn->dcid.id, conn->dcid.len);
			p += conn->dcid.len;
		}

		pn_offset = p - header;
	}

	/*
	 * Build payload with pending frames
	 */
	payload_len = 0;
	remaining = path->mtu - (p - header) - pn_len - 16;  /* 16 = AEAD tag */

	if (is_long_header)
		remaining -= 2;  /* Account for length field */

	if (remaining <= 0) {
		kfree(header);
		kfree(payload);
		return NULL;
	}

	/*
	 * Check if we need to send an ACK frame for this space.
	 * RFC 9000 Section 13.2: ACK frames MUST be sent in packets
	 * of the same encryption level as the packets being acknowledged.
	 */
	need_ack = tquic_ack_should_send(conn, pn_space);

	if (need_ack) {
		/*
		 * Generate ACK frame. We use a simplified ACK with just
		 * the largest acknowledged packet number and first range.
		 */
		u8 *ack_start = payload + payload_len;
		u64 ack_delay;
		u64 first_range;
		int ack_len;

		/* Frame type: ACK (0x02) */
		*ack_start = 0x02;
		ack_len = 1;

		/* Largest Acknowledged */
		ret = tquic_varint_encode(space->largest_recv_pn,
					  ack_start + ack_len,
					  remaining - ack_len);
		if (ret < 0)
			goto skip_ack;
		ack_len += ret;

		/* ACK Delay (in microseconds, scaled by ack_delay_exponent) */
		ack_delay = 0;  /* Simplified - would compute from receive time */
		ret = tquic_varint_encode(ack_delay, ack_start + ack_len,
					  remaining - ack_len);
		if (ret < 0)
			goto skip_ack;
		ack_len += ret;

		/* ACK Range Count (0 = only first range) */
		ret = tquic_varint_encode(0, ack_start + ack_len,
					  remaining - ack_len);
		if (ret < 0)
			goto skip_ack;
		ack_len += ret;

		/* First ACK Range */
		first_range = space->largest_recv_pn;  /* Simplified */
		ret = tquic_varint_encode(first_range, ack_start + ack_len,
					  remaining - ack_len);
		if (ret < 0)
			goto skip_ack;
		ack_len += ret;

		payload_len += ack_len;
		remaining -= ack_len;
		space->last_ack_time = ktime_get();
	}

skip_ack:
	/*
	 * Add pending control frames from the connection's control_frames queue.
	 * These are pre-built frames waiting to be sent.
	 */
	while (!skb_queue_empty(&conn->control_frames) && remaining > 0) {
		struct sk_buff *frame_skb;

		frame_skb = skb_peek(&conn->control_frames);
		if (!frame_skb)
			break;

		if (frame_skb->len > remaining)
			break;

		/* Dequeue and copy frame data to payload */
		frame_skb = skb_dequeue(&conn->control_frames);
		memcpy(payload + payload_len, frame_skb->data, frame_skb->len);
		payload_len += frame_skb->len;
		remaining -= frame_skb->len;
		kfree_skb(frame_skb);
	}

	/*
	 * RFC 9000 Section 14.1: Initial packets MUST be padded to at least
	 * 1200 bytes to prevent amplification attacks.
	 */
	if (pn_space == TQUIC_PN_SPACE_INITIAL) {
		int min_payload = 1200 - (p - header) - 2 - pn_len - 16;
		if (payload_len < min_payload && min_payload <= remaining + payload_len) {
			/* Add PADDING frames (0x00) */
			int padding = min_payload - payload_len;
			memset(payload + payload_len, 0, padding);
			payload_len += padding;
		}
	}

	/*
	 * If no payload was generated, we shouldn't send an empty packet
	 * (unless there was an ACK to send).
	 */
	if (payload_len == 0 && !need_ack) {
		kfree(header);
		kfree(payload);
		return NULL;
	}

	/*
	 * Complete the header with Length field (long header only) and PN
	 */
	if (is_long_header) {
		/* Length = PN length + payload length + AEAD tag (16 bytes) */
		u64 length = pn_len + payload_len + 16;
		int len_bytes;

		/* Encode length using 2-byte varint (0x40 prefix) */
		header[pn_offset - 2] = 0x40 | ((length >> 8) & 0x3f);
		header[pn_offset - 1] = length & 0xff;
		len_bytes = 2;

		header_len = pn_offset;
	} else {
		header_len = pn_offset;
	}

	/* Encode packet number */
	switch (pn_len) {
	case 1:
		header[header_len++] = pn & 0xff;
		break;
	case 2:
		header[header_len++] = (pn >> 8) & 0xff;
		header[header_len++] = pn & 0xff;
		break;
	case 3:
		header[header_len++] = (pn >> 16) & 0xff;
		header[header_len++] = (pn >> 8) & 0xff;
		header[header_len++] = pn & 0xff;
		break;
	case 4:
		header[header_len++] = (pn >> 24) & 0xff;
		header[header_len++] = (pn >> 16) & 0xff;
		header[header_len++] = (pn >> 8) & 0xff;
		header[header_len++] = pn & 0xff;
		break;
	}

	/*
	 * Allocate sk_buff for the complete packet
	 */
	total_len = header_len + payload_len + 16;  /* 16 = AEAD tag */
	skb = alloc_skb(TQUIC_OUTPUT_SKB_HEADROOM + total_len, GFP_ATOMIC);
	if (!skb) {
		kfree(header);
		kfree(payload);
		return NULL;
	}

	skb_reserve(skb, TQUIC_OUTPUT_SKB_HEADROOM);

	/* Copy header to skb */
	skb_put_data(skb, header, header_len);

	/* Copy payload to skb */
	skb_put_data(skb, payload, payload_len);

	/* Set up packet control block for crypto */
	cb = TQUIC_BUILD_SKB_CB(skb);
	cb->pn = pn;
	cb->header_len = header_len;
	cb->pn_len = pn_len;
	cb->packet_type = packet_type;
	cb->dcid_len = conn->dcid.len;
	cb->scid_len = is_long_header ? conn->scid.len : 0;

	/*
	 * Apply AEAD encryption to the payload (RFC 9001 Section 5.3).
	 * The header serves as Additional Authenticated Data (AAD).
	 * The nonce is constructed from the IV XORed with the packet number.
	 */
	if (conn->crypto_state) {
		ret = tquic_crypto_encrypt(conn->crypto_state, skb, pn);
		if (ret < 0) {
			kfree_skb(skb);
			kfree(header);
			kfree(payload);
			return NULL;
		}
	}

	/*
	 * Apply header protection (RFC 9001 Section 5.4).
	 * This masks the packet number and part of the first byte to
	 * make it impossible to determine packet numbers without decryption.
	 */
	if (conn->crypto_state) {
		ret = tquic_crypto_protect_header(conn->crypto_state, skb,
						  pn_offset, pn_len);
		if (ret < 0) {
			kfree_skb(skb);
			kfree(header);
			kfree(payload);
			return NULL;
		}
	}

	/* Set socket owner for memory accounting */
	if (conn->sk)
		skb_set_owner_w(skb, conn->sk);

	/* Update packet number space state */
	space->largest_sent = pn;

	/* Update connection statistics */
	conn->stats.tx_packets++;

	kfree(header);
	kfree(payload);

	return skb;
}
EXPORT_SYMBOL(tquic_packet_build);

/*
 * Module Initialization
 */

/* Initialize output subsystem */
int __init tquic_output_init(void)
{
	int cpu;

	for_each_possible_cpu(cpu) {
		struct tquic_output_state *state;

		state = per_cpu_ptr(&tquic_output_state, cpu);
		skb_queue_head_init(&state->queue);
		state->pending = 0;
		state->next_send_time = ns_to_ktime(0);
	}

	pr_info("TQUIC: Output subsystem initialized\n");
	return 0;
}

/* Cleanup output subsystem */
void __exit tquic_output_exit(void)
{
	int cpu;

	for_each_possible_cpu(cpu) {
		struct tquic_output_state *state;

		state = per_cpu_ptr(&tquic_output_state, cpu);
		skb_queue_purge(&state->queue);
	}

	pr_info("TQUIC: Output subsystem cleanup complete\n");
}

/*
 * Stream and frame helper functions for output
 */

/* Helper to handle stream reset */
void tquic_stream_handle_reset(struct tquic_stream *stream, u64 error_code,
			       u64 final_size)
{
	stream->state = TQUIC_STREAM_STATE_RESET_RECVD;

	wake_up(&stream->wait);
}
EXPORT_SYMBOL(tquic_stream_handle_reset);

/* Helper to handle stop sending */
void tquic_stream_handle_stop_sending(struct tquic_stream *stream, u64 error_code)
{
	wake_up(&stream->wait);
}
EXPORT_SYMBOL(tquic_stream_handle_stop_sending);

/*
 * tquic_stream_recv_data is defined in core/stream.c with full implementation.
 * It has signature:
 *   int tquic_stream_recv_data(struct tquic_stream_manager *mgr,
 *                              struct tquic_stream *stream,
 *                              u64 offset, struct sk_buff *skb, bool fin)
 */

/* Process a frame in NEW_CONNECTION_ID format */
int tquic_frame_process_new_cid(struct tquic_connection *conn,
				const u8 *data, int len)
{
	int offset = 1;
	u64 seq, retire_prior_to;
	u8 cid_len;
	struct tquic_cid cid;
	u8 reset_token[16];
	int varint_len;

	/* Sequence Number */
	varint_len = tquic_varint_decode(data + offset, len - offset, &seq);
	if (varint_len < 0)
		return varint_len;
	offset += varint_len;

	/* Retire Prior To */
	varint_len = tquic_varint_decode(data + offset, len - offset, &retire_prior_to);
	if (varint_len < 0)
		return varint_len;
	offset += varint_len;

	/* Length */
	if (offset >= len)
		return -EINVAL;
	cid_len = data[offset++];
	if (cid_len > TQUIC_MAX_CID_LEN)
		return -EINVAL;

	/* Connection ID - use subtraction form to avoid integer overflow */
	if (cid_len > len - offset)
		return -EINVAL;
	cid.len = cid_len;
	memcpy(cid.id, data + offset, cid_len);
	offset += cid_len;

	/* Stateless Reset Token - use subtraction form to avoid overflow */
	if (len < 16 || offset > len - 16)
		return -EINVAL;
	memcpy(reset_token, data + offset, 16);
	offset += 16;

	tquic_conn_add_remote_cid(conn, &cid, seq, reset_token);

	return offset;
}
EXPORT_SYMBOL(tquic_frame_process_new_cid);

/*
 * Variable-length integer functions (tquic_varint_decode, tquic_varint_encode,
 * tquic_varint_len) are defined in core/varint.c and exported with
 * EXPORT_SYMBOL_GPL. This file uses those functions via the declarations
 * in <net/tquic.h> or <net/tquic_frame.h>.
 */

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Linux QUIC Authors");
MODULE_DESCRIPTION("TQUIC Packet Output Path");
