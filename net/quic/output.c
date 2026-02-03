// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * QUIC - Quick UDP Internet Connections
 *
 * Packet output path implementation
 * - UDP socket management
 * - sendmsg integration
 * - Packet transmission
 *
 * Copyright (c) 2024 Linux QUIC Authors
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
#include <net/quic.h>

/* Output path configuration */
#define QUIC_OUTPUT_BATCH_SIZE		16
#define QUIC_OUTPUT_SKB_HEADROOM	128
#define QUIC_OUTPUT_MAX_COALESCE	3

/* Default TTL/hop limit - configurable via module parameter */
static unsigned int quic_default_ttl __read_mostly = 64;
module_param(quic_default_ttl, uint, 0644);
MODULE_PARM_DESC(quic_default_ttl, "Default TTL/hop limit for QUIC packets (1-255)");

/* Pacing configuration */
#define QUIC_PACING_SHIFT		10
#define QUIC_PACING_MARGIN_US		1000

/* Output control block */
struct quic_output_cb {
	u64		pn;
	ktime_t		send_time;
	u32		length;
	u8		pn_space;
	u8		encrypted:1;
	u8		ack_eliciting:1;
	u8		in_flight:1;
	u8		retransmission:1;
};

#define QUIC_OUTPUT_CB(skb) ((struct quic_output_cb *)((skb)->cb))

/* Per-CPU output state for batching */
struct quic_output_state {
	struct sk_buff_head	queue;
	int			pending;
	ktime_t			next_send_time;
};

static DEFINE_PER_CPU(struct quic_output_state, quic_output_state);

/*
 * UDP Socket Management
 */

/* Create and configure UDP socket for QUIC */
static int quic_create_udp_socket(struct quic_sock *qsk, int family)
{
	struct socket *sock;
	struct sock *sk;
	int err;
	int val;

	err = sock_create_kern(sock_net((struct sock *)qsk), family,
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
	sk->sk_sndbuf = sysctl_quic_wmem[1];
	sk->sk_rcvbuf = sysctl_quic_rmem[1];

	/* Mark as QUIC encapsulation socket */
	udp_sk(sk)->encap_type = 1;  /* Generic encap */

	/* Link to QUIC socket */
	sk->sk_user_data = qsk;

	/* Enable GRO */
	udp_set_bit(GRO_ENABLED, udp_sk(sk));

	qsk->udp_sock = sock;

	return 0;
}

/* Bind UDP socket to local address */
static int quic_bind_udp_socket(struct quic_sock *qsk,
				struct sockaddr *addr, int addr_len)
{
	struct socket *sock = qsk->udp_sock;

	if (!sock)
		return -ENOENT;

	return kernel_bind(sock, addr, addr_len);
}

/* Connect UDP socket to remote address */
static int quic_connect_udp_socket(struct quic_sock *qsk,
				   struct sockaddr *addr, int addr_len)
{
	struct socket *sock = qsk->udp_sock;

	if (!sock)
		return -ENOENT;

	return kernel_connect(sock, addr, addr_len, 0);
}

/*
 * Packet Output Functions
 */

/* Allocate skb for QUIC packet output */
struct sk_buff *quic_alloc_tx_skb(struct quic_connection *conn, u32 size)
{
	struct quic_sock *qsk = conn->qsk;
	struct sock *sk = (struct sock *)qsk;
	struct sk_buff *skb;
	int headroom;

	/* Calculate required headroom for headers */
	headroom = QUIC_OUTPUT_SKB_HEADROOM;

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
EXPORT_SYMBOL(quic_alloc_tx_skb);

/* Free TX skb */
void quic_free_tx_skb(struct sk_buff *skb)
{
	kfree_skb(skb);
}
EXPORT_SYMBOL(quic_free_tx_skb);

/* Build UDP header for QUIC packet */
static void quic_build_udp_header(struct sk_buff *skb,
				  struct quic_connection *conn,
				  int payload_len)
{
	struct udphdr *uh;
	struct quic_path *path = conn->active_path;
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

/* Build IPv4 header for QUIC packet */
static int quic_build_ipv4_header(struct sk_buff *skb,
				  struct quic_connection *conn)
{
	struct quic_path *path = conn->active_path;
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

	rt = ip_route_output_key(sock_net((struct sock *)conn->qsk), &fl4);
	if (IS_ERR(rt))
		return PTR_ERR(rt);

	skb_dst_set(skb, &rt->dst);

	/* Push IP header */
	iph = skb_push(skb, sizeof(struct iphdr));
	skb_reset_network_header(skb);

	iph->version = 4;
	iph->ihl = 5;
	iph->tos = 0;
	iph->tot_len = htons(skb->len);
	iph->id = 0;
	iph->frag_off = htons(IP_DF);
	iph->ttl = quic_default_ttl;
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
/* Build IPv6 header for QUIC packet */
static int quic_build_ipv6_header(struct sk_buff *skb,
				  struct quic_connection *conn)
{
	struct quic_path *path = conn->active_path;
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

	dst = ip6_route_output(sock_net((struct sock *)conn->qsk), NULL, &fl6);
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

	ip6_flow_hdr(ip6h, 0, 0);
	ip6h->payload_len = htons(skb->len - sizeof(struct ipv6hdr));
	ip6h->nexthdr = IPPROTO_UDP;
	ip6h->hop_limit = quic_default_ttl;
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
static int quic_xmit_skb(struct sk_buff *skb, struct quic_connection *conn)
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
		err = ip_local_out(sock_net((struct sock *)conn->qsk),
				   (struct sock *)conn->qsk, skb);
	} else {
#if IS_ENABLED(CONFIG_IPV6)
		err = ip6_local_out(sock_net((struct sock *)conn->qsk),
				    (struct sock *)conn->qsk, skb);
#else
		kfree_skb(skb);
		err = -EAFNOSUPPORT;
#endif
	}

	return err;
}

/* Send QUIC packet using kernel_sendmsg interface */
static int quic_sendmsg_locked(struct quic_sock *qsk, struct sk_buff *skb,
			       struct sockaddr *dest)
{
	struct socket *sock = qsk->udp_sock;
	struct msghdr msg;
	struct kvec iov;
	int err;

	if (!sock)
		return -ENOENT;

	memset(&msg, 0, sizeof(msg));
	msg.msg_name = dest;

	if (dest->sa_family == AF_INET)
		msg.msg_namelen = sizeof(struct sockaddr_in);
	else if (dest->sa_family == AF_INET6)
		msg.msg_namelen = sizeof(struct sockaddr_in6);
	else
		return -EAFNOSUPPORT;

	iov.iov_base = skb->data;
	iov.iov_len = skb->len;

	err = kernel_sendmsg(sock, &msg, &iov, 1, skb->len);

	return err;
}

/* Main output function - send single packet */
int quic_output(struct quic_connection *conn, struct sk_buff *skb)
{
	struct quic_sock *qsk = conn->qsk;
	struct quic_path *path = conn->active_path;
	struct quic_output_cb *cb;
	int payload_len;
	int err;

	if (!path || !qsk || !qsk->udp_sock)
		return -ENOENT;

	payload_len = skb->len;

	/* Build headers */
	quic_build_udp_header(skb, conn, payload_len);

	/* Use sendmsg path for simplicity and correctness */
	err = quic_sendmsg_locked(qsk, skb,
				  (struct sockaddr *)&path->remote_addr);

	if (err >= 0) {
		/* Update output callback */
		cb = QUIC_OUTPUT_CB(skb);
		cb->send_time = ktime_get();
		cb->length = payload_len;
		cb->in_flight = 1;

		/* Update path statistics */
		path->bytes_sent += payload_len;

		/* Update congestion control */
		quic_cc_on_packet_sent(&path->cc, payload_len);

		err = 0;
	}

	return err;
}
EXPORT_SYMBOL(quic_output);

/* Send multiple packets with coalescing support */
int quic_output_batch(struct quic_connection *conn,
		      struct sk_buff_head *queue)
{
	struct sk_buff *skb, *next;
	int sent = 0;
	int err = 0;

	skb_queue_walk_safe(queue, skb, next) {
		__skb_unlink(skb, queue);

		err = quic_output(conn, skb);
		if (err) {
			kfree_skb(skb);
			break;
		}

		kfree_skb(skb);
		sent++;
	}

	return sent ? sent : err;
}
EXPORT_SYMBOL(quic_output_batch);

/*
 * Pacing Support
 *
 * QUIC implements pacing to smooth out packet transmission and
 * avoid bursts that could cause congestion.
 */

/* Calculate pacing delay for next packet */
static ktime_t quic_pacing_delay(struct quic_connection *conn, u32 bytes)
{
	struct quic_cc_state *cc = &conn->active_path->cc;
	u64 delay_ns;

	if (!cc->pacing_rate || cc->pacing_rate == ~0ULL)
		return ns_to_ktime(0);

	/* Calculate delay: bytes / pacing_rate (in nanoseconds) */
	delay_ns = (u64)bytes * NSEC_PER_SEC / cc->pacing_rate;

	return ns_to_ktime(delay_ns);
}

/* Check if we should send now or wait for pacing */
static bool quic_pacing_allow(struct quic_connection *conn)
{
	struct quic_cc_state *cc = &conn->active_path->cc;
	ktime_t now = ktime_get();
	s64 diff;

	if (!cc->last_sent_time)
		return true;

	diff = ktime_to_ns(ktime_sub(now, ns_to_ktime(cc->last_sent_time)));

	/* Allow small margin for timing jitter */
	return diff >= -QUIC_PACING_MARGIN_US * 1000;
}

/* Paced output - respects pacing constraints */
int quic_output_paced(struct quic_connection *conn, struct sk_buff *skb)
{
	struct quic_cc_state *cc = &conn->active_path->cc;
	int err;

	/* Check pacing */
	if (!quic_pacing_allow(conn)) {
		/* Queue for later transmission */
		skb_queue_tail(&conn->pending_frames, skb);
		return 0;
	}

	err = quic_output(conn, skb);
	if (!err) {
		/* Update pacing state */
		cc->last_sent_time = ktime_to_ns(ktime_get());
	}

	return err;
}
EXPORT_SYMBOL(quic_output_paced);

/*
 * GSO Support for Output
 *
 * When sending large amounts of data, we can use GSO to batch
 * multiple QUIC packets into a single super-packet for more
 * efficient kernel processing.
 */

/* Setup GSO for a batch of QUIC packets */
static int quic_setup_gso(struct sk_buff *skb, u16 gso_size, u16 segs)
{
	skb_shinfo(skb)->gso_size = gso_size;
	skb_shinfo(skb)->gso_segs = segs;
	skb_shinfo(skb)->gso_type = SKB_GSO_UDP_L4;

	return 0;
}

/* Send data using GSO if beneficial */
int quic_output_gso(struct quic_connection *conn, struct sk_buff_head *queue)
{
	struct sk_buff *skb, *gso_skb;
	u32 total_len = 0;
	u16 seg_count = 0;
	u16 mss;
	int err;

	/* Calculate MSS from path MTU */
	mss = conn->active_path->mtu - 40;  /* Subtract IP + UDP headers */
	if (mss > QUIC_MAX_PACKET_SIZE)
		mss = QUIC_MAX_PACKET_SIZE;

	/* Check if GSO is worthwhile (need at least 2 packets) */
	if (skb_queue_len(queue) < 2)
		return quic_output_batch(conn, queue);

	/* Calculate total length and segment count */
	skb_queue_walk(queue, skb) {
		total_len += skb->len;
		seg_count++;
	}

	/* Limit segments */
	if (seg_count > 64)
		seg_count = 64;

	/* Allocate GSO skb */
	gso_skb = alloc_skb(QUIC_OUTPUT_SKB_HEADROOM + total_len + 128, GFP_ATOMIC);
	if (!gso_skb)
		return quic_output_batch(conn, queue);

	skb_reserve(gso_skb, QUIC_OUTPUT_SKB_HEADROOM);

	/* Copy all packets into GSO skb */
	while ((skb = __skb_dequeue(queue)) != NULL) {
		u8 *p = skb_put(gso_skb, skb->len);
		skb_copy_bits(skb, 0, p, skb->len);
		kfree_skb(skb);
	}

	/* Setup GSO */
	quic_setup_gso(gso_skb, mss, seg_count);

	/* Set socket for memory accounting */
	skb_set_owner_w(gso_skb, (struct sock *)conn->qsk);

	/* Send GSO packet */
	err = quic_output(conn, gso_skb);
	if (err)
		kfree_skb(gso_skb);

	return err;
}
EXPORT_SYMBOL(quic_output_gso);

/*
 * Coalesced Packet Support
 *
 * QUIC allows multiple packets at different encryption levels to be
 * coalesced into a single UDP datagram. This is especially useful
 * during the handshake.
 */

/* Coalesce multiple QUIC packets */
struct sk_buff *quic_coalesce_packets(struct sk_buff_head *packets)
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
	if (total_len > QUIC_MAX_PACKET_SIZE)
		return NULL;

	/* Allocate coalesced skb */
	coalesced = alloc_skb(QUIC_OUTPUT_SKB_HEADROOM + total_len + 16, GFP_ATOMIC);
	if (!coalesced)
		return NULL;

	skb_reserve(coalesced, QUIC_OUTPUT_SKB_HEADROOM);

	/* Copy all packets */
	while ((skb = __skb_dequeue(packets)) != NULL) {
		p = skb_put(coalesced, skb->len);
		skb_copy_bits(skb, 0, p, skb->len);
		kfree_skb(skb);
	}

	return coalesced;
}
EXPORT_SYMBOL(quic_coalesce_packets);

/* Send coalesced packet */
int quic_output_coalesced(struct quic_connection *conn,
			  struct sk_buff_head *packets)
{
	struct sk_buff *skb;
	int err;

	skb = quic_coalesce_packets(packets);
	if (!skb)
		return -ENOMEM;

	/* Set socket for memory accounting */
	skb_set_owner_w(skb, (struct sock *)conn->qsk);

	err = quic_output(conn, skb);
	if (err)
		kfree_skb(skb);

	return err;
}
EXPORT_SYMBOL(quic_output_coalesced);

/*
 * Retransmission Support
 */

/* Retransmit a packet */
int quic_retransmit(struct quic_connection *conn, struct quic_sent_packet *pkt)
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
	QUIC_OUTPUT_CB(clone)->retransmission = 1;

	/* Update packet number (will be set during encryption) */
	pkt->retransmitted = 1;

	err = quic_output(conn, clone);
	if (err)
		kfree_skb(clone);

	return err;
}
EXPORT_SYMBOL(quic_retransmit);

/*
 * sendmsg Interface
 *
 * Integration with socket sendmsg for user-space applications.
 */

/* Process sendmsg for QUIC socket */
int quic_do_sendmsg(struct sock *sk, struct msghdr *msg, size_t len)
{
	struct quic_sock *qsk = quic_sk(sk);
	struct quic_connection *conn = qsk->conn;
	struct quic_stream *stream = NULL;
	struct quic_stream_info sinfo;
	struct cmsghdr *cmsg;
	struct sk_buff *skb;
	u64 stream_id = 0;
	u32 flags = 0;
	size_t remaining = len;
	size_t sent = 0;
	int err;

	if (!conn || conn->state != QUIC_STATE_CONNECTED)
		return -ENOTCONN;

	/* Parse control message for stream info */
	for_each_cmsghdr(cmsg, msg) {
		if (!CMSG_OK(msg, cmsg))
			return -EINVAL;

		if (cmsg->cmsg_level != SOL_QUIC)
			continue;

		if (cmsg->cmsg_type == QUIC_CMSG_STREAM_INFO) {
			if (cmsg->cmsg_len < CMSG_LEN(sizeof(sinfo)))
				return -EINVAL;
			memcpy(&sinfo, CMSG_DATA(cmsg), sizeof(sinfo));
			stream_id = sinfo.stream_id;
			flags = sinfo.stream_flags;
		}
	}

	/* Find or create stream */
	if (flags & QUIC_STREAM_FLAG_NEW) {
		stream_id = quic_stream_next_id(conn, flags & QUIC_STREAM_FLAG_UNI);
		stream = quic_stream_create(conn, stream_id);
		if (!stream)
			return -ENOMEM;
	} else {
		stream = quic_stream_lookup(conn, stream_id);
		if (!stream)
			return -ENOENT;
	}

	/* Send data in MTU-sized chunks */
	while (remaining > 0) {
		size_t chunk_size;
		u8 *data;

		/* Calculate chunk size based on MTU and flow control */
		chunk_size = min_t(size_t, remaining,
				   conn->active_path->mtu - 100);

		if (!quic_stream_flow_control_can_send(stream, chunk_size)) {
			if (sent > 0)
				break;
			if (msg->msg_flags & MSG_DONTWAIT)
				return -EAGAIN;
			/* Block until flow control allows */
			err = wait_event_interruptible(stream->wait,
				quic_stream_flow_control_can_send(stream, chunk_size));
			if (err)
				return err;
		}

		/* Allocate and build STREAM frame */
		skb = quic_alloc_tx_skb(conn, chunk_size + 32);
		if (!skb) {
			if (sent > 0)
				break;
			return -ENOMEM;
		}

		/* Build STREAM frame header */
		data = skb_put(skb, 1);
		*data = QUIC_FRAME_STREAM | 0x02;  /* With LENGTH */

		if (stream->send.offset > 0)
			*data |= 0x04;  /* With OFFSET */

		if (remaining <= chunk_size && (flags & QUIC_STREAM_FLAG_FIN))
			*data |= 0x01;  /* With FIN */

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
		if (stream->send.offset > 0) {
			data = skb_put(skb, 8);
			/* Simplified varint encoding for offset */
			skb_trim(skb, skb->len - 6);
			data[0] = 0x40 | ((stream->send.offset >> 8) & 0x3f);
			data[1] = stream->send.offset & 0xff;
		}

		/* Encode length */
		data = skb_put(skb, 2);
		data[0] = 0x40 | ((chunk_size >> 8) & 0x3f);
		data[1] = chunk_size & 0xff;

		/* Copy data from user */
		data = skb_put(skb, chunk_size);
		if (!copy_from_iter_full(data, chunk_size, &msg->msg_iter)) {
			kfree_skb(skb);
			return -EFAULT;
		}

		/* Queue for transmission */
		skb_queue_tail(&conn->pending_frames, skb);

		/* Update offsets */
		stream->send.offset += chunk_size;
		quic_stream_flow_control_on_data_sent(stream, chunk_size);
		quic_flow_control_on_data_sent(conn, chunk_size);

		remaining -= chunk_size;
		sent += chunk_size;
	}

	/* Trigger transmission */
	if (sent > 0)
		schedule_work(&conn->tx_work);

	if (flags & QUIC_STREAM_FLAG_FIN)
		stream->fin_sent = 1;

	refcount_dec(&stream->refcnt);

	return sent;
}
EXPORT_SYMBOL(quic_do_sendmsg);

/*
 * Module Initialization
 */

/* Initialize output subsystem */
int __init quic_output_init(void)
{
	int cpu;

	for_each_possible_cpu(cpu) {
		struct quic_output_state *state;

		state = per_cpu_ptr(&quic_output_state, cpu);
		skb_queue_head_init(&state->queue);
		state->pending = 0;
		state->next_send_time = ns_to_ktime(0);
	}

	pr_info("QUIC: Output subsystem initialized\n");
	return 0;
}

/* Cleanup output subsystem */
void __exit quic_output_exit(void)
{
	int cpu;

	for_each_possible_cpu(cpu) {
		struct quic_output_state *state;

		state = per_cpu_ptr(&quic_output_state, cpu);
		skb_queue_purge(&state->queue);
	}

	pr_info("QUIC: Output subsystem cleanup complete\n");
}

/*
 * Stream and frame helper functions for output
 */

/* Helper to handle stream reset */
void quic_stream_handle_reset(struct quic_stream *stream, u64 error_code,
			      u64 final_size)
{
	stream->reset_received = 1;
	stream->error_code = error_code;
	stream->recv.final_size = final_size;
	stream->state = QUIC_STREAM_STATE_RESET_RECVD;

	wake_up(&stream->wait);
}
EXPORT_SYMBOL(quic_stream_handle_reset);

/* Helper to handle stop sending */
void quic_stream_handle_stop_sending(struct quic_stream *stream, u64 error_code)
{
	stream->stop_sending_received = 1;
	stream->error_code = error_code;

	/* Should reset the stream in response */
	stream->reset_sent = 1;

	wake_up(&stream->wait);
}
EXPORT_SYMBOL(quic_stream_handle_stop_sending);

/* Helper to receive stream data */
int quic_stream_recv_data(struct quic_stream *stream, u64 offset,
			  const u8 *data, u32 len, bool fin)
{
	struct quic_recv_chunk *chunk;
	struct rb_node **link, *parent = NULL;
	struct quic_stream_recv_buf *recv = &stream->recv;

	spin_lock(&recv->lock);

	/* Check for duplicate or out-of-order data */
	if (offset < recv->offset) {
		/* Overlapping with already consumed data */
		u32 skip = recv->offset - offset;
		if (skip >= len) {
			spin_unlock(&recv->lock);
			return 0;  /* Already received */
		}
		offset += skip;
		data += skip;
		len -= skip;
	}

	/* Allocate chunk */
	chunk = kmalloc(sizeof(*chunk) + len, GFP_ATOMIC);
	if (!chunk) {
		spin_unlock(&recv->lock);
		return -ENOMEM;
	}

	chunk->offset = offset;
	chunk->len = len;
	memcpy(chunk->data, data, len);

	/* Insert into tree */
	link = &recv->data_tree.rb_node;
	while (*link) {
		struct quic_recv_chunk *entry;

		parent = *link;
		entry = rb_entry(parent, struct quic_recv_chunk, node);

		if (offset < entry->offset)
			link = &(*link)->rb_left;
		else if (offset > entry->offset)
			link = &(*link)->rb_right;
		else {
			/* Duplicate - ignore */
			kfree(chunk);
			spin_unlock(&recv->lock);
			return 0;
		}
	}

	rb_link_node(&chunk->node, parent, link);
	rb_insert_color(&chunk->node, &recv->data_tree);

	/* Update highest offset */
	if (offset + len > recv->highest_offset)
		recv->highest_offset = offset + len;

	/* Count pending bytes */
	recv->pending += len;

	/* Handle FIN */
	if (fin) {
		recv->fin_received = 1;
		recv->final_size = offset + len;
		stream->fin_received = 1;
	}

	spin_unlock(&recv->lock);

	/* Wake up readers */
	wake_up(&stream->wait);

	return 0;
}
EXPORT_SYMBOL(quic_stream_recv_data);

/* Process a frame in NEW_CONNECTION_ID format */
int quic_frame_process_new_cid(struct quic_connection *conn,
			       const u8 *data, int len)
{
	int offset = 1;
	u64 seq, retire_prior_to;
	u8 cid_len;
	struct quic_connection_id cid;
	u8 reset_token[16];
	int varint_len;

	/* Sequence Number */
	varint_len = quic_varint_decode(data + offset, len - offset, &seq);
	if (varint_len < 0)
		return varint_len;
	offset += varint_len;

	/* Retire Prior To */
	varint_len = quic_varint_decode(data + offset, len - offset, &retire_prior_to);
	if (varint_len < 0)
		return varint_len;
	offset += varint_len;

	/* Length */
	if (offset >= len)
		return -EINVAL;
	cid_len = data[offset++];
	if (cid_len > QUIC_MAX_CONNECTION_ID_LEN)
		return -EINVAL;

	/* Connection ID */
	if (offset + cid_len > len)
		return -EINVAL;
	cid.len = cid_len;
	memcpy(cid.data, data + offset, cid_len);
	offset += cid_len;

	/* Stateless Reset Token */
	if (offset + 16 > len)
		return -EINVAL;
	memcpy(reset_token, data + offset, 16);
	offset += 16;

	quic_conn_add_peer_cid(conn, &cid, seq, retire_prior_to, reset_token);

	return offset;
}
EXPORT_SYMBOL(quic_frame_process_new_cid);

/* Variable-length integer decoder */
int quic_varint_decode(const u8 *data, int len, u64 *value)
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
EXPORT_SYMBOL(quic_varint_decode);

/* Variable-length integer encoder (RFC 9000 Section 16) */
int quic_varint_encode(u64 value, u8 *data)
{
	if (value <= QUIC_VARINT_1BYTE_MAX) {
		data[0] = value;
		return 1;
	} else if (value <= QUIC_VARINT_2BYTE_MAX) {
		data[0] = QUIC_VARINT_2BYTE_PREFIX | (value >> 8);
		data[1] = value & 0xff;
		return 2;
	} else if (value <= QUIC_VARINT_4BYTE_MAX) {
		data[0] = QUIC_VARINT_4BYTE_PREFIX | (value >> 24);
		data[1] = (value >> 16) & 0xff;
		data[2] = (value >> 8) & 0xff;
		data[3] = value & 0xff;
		return 4;
	} else {
		data[0] = QUIC_VARINT_8BYTE_PREFIX | (value >> 56);
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
EXPORT_SYMBOL(quic_varint_encode);

/* Get varint encoded length (RFC 9000 Section 16) */
int quic_varint_len(u64 value)
{
	if (value <= QUIC_VARINT_1BYTE_MAX)
		return 1;
	else if (value <= QUIC_VARINT_2BYTE_MAX)
		return 2;
	else if (value <= QUIC_VARINT_4BYTE_MAX)
		return 4;
	else
		return 8;
}
EXPORT_SYMBOL(quic_varint_len);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Linux QUIC Authors");
MODULE_DESCRIPTION("QUIC Packet Output Path");
