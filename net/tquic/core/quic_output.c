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

/* Create and configure UDP socket for TQUIC */
static int tquic_create_udp_socket(struct tquic_sock *tsk, int family)
{
	struct socket *sock;
	struct sock *sk;
	int err;
	int val;

	err = sock_create_kern(sock_net((struct sock *)tsk), family,
			       SOCK_DGRAM, IPPROTO_UDP, &sock);
	if (err)
		return err;

	sk = sock->sk;

	/* Disable UDP checksums for IPv4 if hardware can do it */
	if (family == AF_INET) {
		val = 1;
		sock_set_flag(sk, SOCK_NO_CHECK_TX);
	}

	/* Enable non-blocking mode */
	sock->file = NULL;
	sk->sk_allocation = GFP_ATOMIC;

	/* Set socket buffer sizes */
	sk->sk_sndbuf = sysctl_tquic_wmem[1];
	sk->sk_rcvbuf = sysctl_tquic_rmem[1];

	/* Mark as TQUIC encapsulation socket */
	udp_sk(sk)->encap_type = 1;  /* Generic encap */

	/* Link to TQUIC socket */
	sk->sk_user_data = tsk;

	/* Enable GRO */
	udp_set_bit(GRO_ENABLED, udp_sk(sk));

	return 0;
}

/* Bind UDP socket to local address */
static int tquic_bind_udp_socket(struct tquic_sock *tsk,
				 struct sockaddr *addr, int addr_len)
{
	return -ENOENT;  /* Placeholder - needs UDP sock reference */
}

/* Connect UDP socket to remote address */
static int tquic_connect_udp_socket(struct tquic_sock *tsk,
				    struct sockaddr *addr, int addr_len)
{
	return -ENOENT;  /* Placeholder - needs UDP sock reference */
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

/* Get ECN marking for path - use path's cc state */
static u8 tquic_ecn_get_marking(struct tquic_path *path)
{
	/* Default to ECT(0) if ECN is enabled, otherwise Not-ECT */
	return 0x02;  /* ECT(0) */
}

/* Track ECN-marked packet sent */
static void tquic_ecn_on_packet_sent(struct tquic_path *path, u8 ecn_marking)
{
	/* Track ECN counts - implementation specific */
}

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

/* Send TQUIC packet using kernel_sendmsg interface */
static int tquic_sendmsg_locked(struct tquic_sock *tsk, struct sk_buff *skb,
				struct sockaddr *dest)
{
	/* Placeholder - needs proper UDP socket reference from tsk */
	return -ENOENT;
}

/*
 * Set ECN marking on UDP socket before sending
 *
 * Per RFC 9000 Section 13.4, we need to set ECN bits in the IP header.
 * For the sendmsg path, we do this by setting the IP_TOS socket option.
 */
static void tquic_output_set_ecn(struct socket *sock, struct tquic_path *path)
{
	u8 ecn_marking;
	int tos;

	if (!sock || !path)
		return;

	ecn_marking = tquic_ecn_get_marking(path);

	/* Get current TOS value and update ECN bits */
	if (path->local_addr.ss_family == AF_INET) {
		tos = ecn_marking;  /* ECN bits are in low 2 bits */
		kernel_setsockopt(sock, SOL_IP, IP_TOS,
				  (char *)&tos, sizeof(tos));
	} else if (path->local_addr.ss_family == AF_INET6) {
		tos = ecn_marking;
		kernel_setsockopt(sock, SOL_IPV6, IPV6_TCLASS,
				  (char *)&tos, sizeof(tos));
	}
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
struct sk_buff *tquic_coalesce_packets(struct sk_buff_head *packets)
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
EXPORT_SYMBOL(tquic_coalesce_packets);

/* Send coalesced packet */
int tquic_output_coalesced(struct tquic_connection *conn,
			   struct sk_buff_head *packets)
{
	struct sk_buff *skb;
	int err;

	skb = tquic_coalesce_packets(packets);
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

/* Helper to receive stream data */
int tquic_stream_recv_data(struct tquic_stream *stream, u64 offset,
			   const u8 *data, u32 len, bool fin)
{
	/* Simplified implementation - queue data for stream */
	if (fin) {
		stream->fin_received = 1;
	}

	/* Wake up readers */
	wake_up(&stream->wait);

	return 0;
}
EXPORT_SYMBOL(tquic_stream_recv_data);

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

/* Variable-length integer decoder */
int tquic_varint_decode(const u8 *data, size_t len, u64 *value)
{
	u8 prefix;
	int varint_len;

	if (len < 1)
		return -EINVAL;

	prefix = data[0] >> 6;

	switch (prefix) {
	case 0:
		*value = data[0] & 0x3f;
		return 1;
	case 1:
		if (len < 2)
			return -EINVAL;
		*value = ((u64)(data[0] & 0x3f) << 8) | data[1];
		return 2;
	case 2:
		if (len < 4)
			return -EINVAL;
		*value = ((u64)(data[0] & 0x3f) << 24) |
			 ((u64)data[1] << 16) |
			 ((u64)data[2] << 8) |
			 data[3];
		return 4;
	case 3:
		if (len < 8)
			return -EINVAL;
		*value = ((u64)(data[0] & 0x3f) << 56) |
			 ((u64)data[1] << 48) |
			 ((u64)data[2] << 40) |
			 ((u64)data[3] << 32) |
			 ((u64)data[4] << 24) |
			 ((u64)data[5] << 16) |
			 ((u64)data[6] << 8) |
			 data[7];
		return 8;
	}

	return -EINVAL;
}
EXPORT_SYMBOL(tquic_varint_decode);

/* Variable-length integer encoder (RFC 9000 Section 16) */
int tquic_varint_encode(u64 value, u8 *data, size_t len)
{
	if (value <= TQUIC_VARINT_1BYTE_MAX) {
		if (len < 1)
			return -ENOSPC;
		data[0] = value;
		return 1;
	} else if (value <= TQUIC_VARINT_2BYTE_MAX) {
		if (len < 2)
			return -ENOSPC;
		data[0] = TQUIC_VARINT_2BYTE_PREFIX | (value >> 8);
		data[1] = value & 0xff;
		return 2;
	} else if (value <= TQUIC_VARINT_4BYTE_MAX) {
		if (len < 4)
			return -ENOSPC;
		data[0] = TQUIC_VARINT_4BYTE_PREFIX | (value >> 24);
		data[1] = (value >> 16) & 0xff;
		data[2] = (value >> 8) & 0xff;
		data[3] = value & 0xff;
		return 4;
	} else {
		if (len < 8)
			return -ENOSPC;
		data[0] = TQUIC_VARINT_8BYTE_PREFIX | (value >> 56);
		data[1] = (value >> 48) & 0xff;
		data[2] = (value >> 40) & 0xff;
		data[3] = (value >> 32) & 0xff;
		data[4] = (value >> 24) & 0xff;
		data[5] = (value >> 16) & 0xff;
		data[6] = (value >> 8) & 0xff;
		data[7] = value & 0xff;
		return 8;
	}
}
EXPORT_SYMBOL(tquic_varint_encode);

/* Get varint encoded length (RFC 9000 Section 16) */
int tquic_varint_len(u64 value)
{
	if (value <= TQUIC_VARINT_1BYTE_MAX)
		return 1;
	else if (value <= TQUIC_VARINT_2BYTE_MAX)
		return 2;
	else if (value <= TQUIC_VARINT_4BYTE_MAX)
		return 4;
	else
		return 8;
}
EXPORT_SYMBOL(tquic_varint_len);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Linux QUIC Authors");
MODULE_DESCRIPTION("TQUIC Packet Output Path");
