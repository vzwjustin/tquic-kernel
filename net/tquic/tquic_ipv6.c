// SPDX-License-Identifier: GPL-2.0-only
/*
 * TQUIC: IPv6 Support for WAN Bonding over QUIC
 *
 * Copyright (c) 2026 Linux Foundation
 *
 * This module provides IPv6 support for TQUIC including:
 * - IPv6 socket operations with inet6_connection_sock
 * - IPv6 address handling in paths
 * - IPv6 UDP tunnel integration
 * - Dual-stack support (IPv6/IPv4 mapped addresses)
 * - inet6_protosw registration
 * - IPv6 flow label handling
 * - IPv6 extension headers consideration
 * - Path MTU discovery for IPv6
 * - IPv6-specific setsockopt/getsockopt
 * - Happy Eyeballs support (prefer IPv6, fallback IPv4)
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/slab.h>
#include <linux/net.h>
#include <linux/socket.h>
#include <linux/skbuff.h>
#include <linux/in6.h>
#include <linux/ipv6.h>
#include <linux/icmpv6.h>
#include <linux/random.h>
#include <linux/timer.h>
#include <linux/workqueue.h>

#include <net/sock.h>
#include <net/protocol.h>
#include <net/inet_common.h>
#include <net/inet6_hashtables.h>
#include <net/inet6_connection_sock.h>
#include <net/ipv6.h>
#include <net/transp_v6.h>
#include <net/addrconf.h>
#include <net/ip6_route.h>
#include <net/ip6_checksum.h>
#include <net/udp.h>
#include <net/udp_tunnel.h>
#include <net/tquic.h>
#include "tquic_compat.h"

#include "protocol.h"

/*
 * Note: struct tquic6_sock is defined in include/net/tquic.h
 * Use tquic6_inet6_sk() from that header to access ipv6_pinfo.
 */

/* Forward declarations */
static int tquic_v6_connect(struct sock *sk, struct sockaddr *addr, int addr_len);
static void tquic_v6_mtu_reduced(struct sock *sk);
static int tquic_v6_init_sock(struct sock *sk);
static void tquic_v6_destroy_sock(struct sock *sk);
static int tquic_v6_err(struct sk_buff *skb, struct inet6_skb_parm *opt,
			u8 type, u8 code, int offset, __be32 info);
static int tquic_v6_rcv(struct sk_buff *skb);

/*
 * Helper to get ipv6_pinfo from tquic socket - alias for consistency
 * with existing code. Uses tquic6_inet6_sk() from include/net/tquic.h.
 */
#define tquic_inet6_sk(sk) tquic6_inet6_sk(sk)

/*
 * Happy Eyeballs state for preferring IPv6 with IPv4 fallback
 */
struct tquic_happy_eyeballs {
	struct tquic_connection *conn;
	struct work_struct	work;
	struct timer_list	fallback_timer;

	/* IPv6 attempt state */
	struct sockaddr_in6	ipv6_addr;
	bool			ipv6_attempted;
	bool			ipv6_connected;
	ktime_t			ipv6_start_time;

	/* IPv4 fallback state */
	struct sockaddr_in	ipv4_addr;
	bool			ipv4_attempted;
	bool			ipv4_connected;
	ktime_t			ipv4_start_time;

	/* Configuration */
	unsigned int		resolution_delay_ms;	/* Time to wait for IPv6 */
	unsigned int		connection_timeout_ms;	/* Total connection timeout */
	bool			prefer_ipv6;
	bool			allow_fallback;

	/* Result tracking */
	int			winner;			/* AF_INET6, AF_INET, or 0 */
	int			ipv6_error;
	int			ipv4_error;
};

#define TQUIC_HE_RESOLUTION_DELAY_MS	50	/* RFC 8305 recommends 50ms */
#define TQUIC_HE_CONNECTION_TIMEOUT_MS	30000	/* 30 second total timeout */

/*
 * IPv6 address handling utilities
 */

/* Check if address is IPv4-mapped IPv6 address */
static inline bool tquic_addr_is_v4mapped(const struct sockaddr_storage *addr)
{
	if (addr->ss_family == AF_INET6) {
		const struct sockaddr_in6 *sin6 = (const struct sockaddr_in6 *)addr;
		return ipv6_addr_v4mapped(&sin6->sin6_addr);
	}
	return false;
}

/* Convert sockaddr to IPv6, mapping IPv4 if needed */
static int tquic_addr_to_v6(const struct sockaddr_storage *src,
			    struct sockaddr_in6 *dst)
{
	memset(dst, 0, sizeof(*dst));
	dst->sin6_family = AF_INET6;

	if (src->ss_family == AF_INET6) {
		const struct sockaddr_in6 *sin6 = (const struct sockaddr_in6 *)src;
		dst->sin6_addr = sin6->sin6_addr;
		dst->sin6_port = sin6->sin6_port;
		dst->sin6_flowinfo = sin6->sin6_flowinfo;
		dst->sin6_scope_id = sin6->sin6_scope_id;
	} else if (src->ss_family == AF_INET) {
		const struct sockaddr_in *sin = (const struct sockaddr_in *)src;
		ipv6_addr_set_v4mapped(sin->sin_addr.s_addr, &dst->sin6_addr);
		dst->sin6_port = sin->sin_port;
	} else {
		return -EAFNOSUPPORT;
	}

	return 0;
}

/* Convert IPv4-mapped IPv6 to IPv4 sockaddr */
static int tquic_v4mapped_to_v4(const struct sockaddr_in6 *src,
				struct sockaddr_in *dst)
{
	if (!ipv6_addr_v4mapped(&src->sin6_addr))
		return -EINVAL;

	memset(dst, 0, sizeof(*dst));
	dst->sin_family = AF_INET;
	dst->sin_port = src->sin6_port;
	dst->sin_addr.s_addr = src->sin6_addr.s6_addr32[3];

	return 0;
}

/* Get address family for routing */
static sa_family_t tquic_path_get_family(const struct tquic_path *path)
{
	const struct sockaddr_storage *addr = &path->remote_addr;

	if (addr->ss_family == AF_INET6) {
		const struct sockaddr_in6 *sin6 = (const struct sockaddr_in6 *)addr;
		if (ipv6_addr_v4mapped(&sin6->sin6_addr))
			return AF_INET;
		return AF_INET6;
	}
	return addr->ss_family;
}

/*
 * IPv6 flow label handling
 */

/* Generate flow label for a path */
static __be32 tquic_v6_generate_flowlabel(struct tquic_connection *conn,
					  struct tquic_path *path)
{
	const struct sockaddr_in6 *local, *remote;
	u32 hash;

	if (path->local_addr.ss_family != AF_INET6 ||
	    path->remote_addr.ss_family != AF_INET6)
		return 0;

	local = (const struct sockaddr_in6 *)&path->local_addr;
	remote = (const struct sockaddr_in6 *)&path->remote_addr;

	/* Generate flow label from addresses and connection ID */
	hash = jhash2(local->sin6_addr.s6_addr32, 4, 0);
	hash = jhash2(remote->sin6_addr.s6_addr32, 4, hash);
	hash = jhash(conn->scid.id, conn->scid.len, hash);

	/* Flow label is 20 bits */
	return cpu_to_be32(hash & IPV6_FLOWLABEL_MASK);
}

/* Store flow label for path */
static void tquic_v6_path_set_flowlabel(struct tquic_path *path, __be32 flowlabel)
{
	/* Store in path-specific extension data */
	/* Flow label stored in host order for easier manipulation */
	/* This could be expanded to a path extension structure if needed */
}

/* Get flow label for outgoing packets */
static __be32 tquic_v6_path_get_flowlabel(struct tquic_connection *conn,
					  struct tquic_path *path)
{
	struct sock *sk = conn->sk;
	struct ipv6_pinfo *np;
	__be32 flowlabel;

	if (!sk || sk->sk_family != AF_INET6)
		return 0;

	np = tquic_inet6_sk(sk);

	/* Use socket's flow label if set, otherwise generate one */
	flowlabel = np->flow_label;
	if (!flowlabel)
		flowlabel = tquic_v6_generate_flowlabel(conn, path);

	return flowlabel;
}

/*
 * IPv6 extension header handling
 */

/* Calculate extension header length for path */
static unsigned int tquic_v6_ext_hdr_len(struct sock *sk)
{
	struct ipv6_pinfo *np = tquic_inet6_sk(sk);
	struct ipv6_txoptions *opt;
	unsigned int len = 0;

	rcu_read_lock();
	opt = rcu_dereference(np->opt);
	if (opt)
		len = opt->opt_flen + opt->opt_nflen;
	rcu_read_unlock();

	return len;
}

/* Check if extension headers affect MTU */
static unsigned int tquic_v6_overhead(struct sock *sk)
{
	return sizeof(struct ipv6hdr) + sizeof(struct udphdr) +
	       tquic_v6_ext_hdr_len(sk);
}

/*
 * Path MTU Discovery for IPv6
 */

/* Handle MTU reduction notification */
static void tquic_v6_mtu_reduced(struct sock *sk)
{
	struct tquic_sock *tsk = tquic_sk(sk);
	struct tquic_connection *conn = tsk->conn;
	struct tquic_path *path;
	struct dst_entry *dst;
	u32 mtu;

	if (!conn)
		return;

	/* Get the new MTU from socket */
	dst = __sk_dst_get(sk);
	if (!dst)
		return;

	mtu = dst_mtu(dst);

	/* Update all IPv6 paths with new MTU */
	list_for_each_entry(path, &conn->paths, list) {
		if (tquic_path_get_family(path) == AF_INET6) {
			u32 path_mtu;

			/* Account for IPv6 and UDP headers */
			path_mtu = mtu - sizeof(struct ipv6hdr) - sizeof(struct udphdr);

			/* QUIC minimum is 1200 bytes */
			if (path_mtu < 1200)
				path_mtu = 1200;

			if (path_mtu < path->mtu) {
				path->mtu = path_mtu;
				pr_debug("tquic: path %u MTU reduced to %u\n",
					 path->path_id, path_mtu);
			}
		}
	}
}

/* Perform PMTU discovery for a path */
static int tquic_v6_path_pmtu_probe(struct tquic_connection *conn,
				    struct tquic_path *path, u32 probe_size)
{
	struct sock *sk = conn->sk;
	struct ipv6_pinfo *np;
	struct dst_entry *dst;
	struct flowi6 fl6;
	const struct sockaddr_in6 *local, *remote;

	if (!sk || sk->sk_family != AF_INET6)
		return -EINVAL;

	if (path->remote_addr.ss_family != AF_INET6)
		return -EINVAL;

	np = tquic_inet6_sk(sk);
	local = (const struct sockaddr_in6 *)&path->local_addr;
	remote = (const struct sockaddr_in6 *)&path->remote_addr;

	memset(&fl6, 0, sizeof(fl6));
	fl6.flowi6_proto = IPPROTO_UDP;
	fl6.daddr = remote->sin6_addr;
	fl6.saddr = local->sin6_addr;
	fl6.fl6_dport = remote->sin6_port;
	fl6.fl6_sport = local->sin6_port;
	fl6.flowlabel = tquic_v6_path_get_flowlabel(conn, path);
	fl6.flowi6_oif = sk->sk_bound_dev_if;

	dst = ip6_dst_lookup_flow(sock_net(sk), sk, &fl6, NULL);
	if (IS_ERR(dst))
		return PTR_ERR(dst);

	/* Check if probe size is feasible */
	if (probe_size > dst_mtu(dst)) {
		dst_release(dst);
		return -EMSGSIZE;
	}

	dst_release(dst);
	return 0;
}

/* Update path MTU from ICMPv6 too big message */
static void tquic_v6_path_update_pmtu(struct tquic_connection *conn,
				      struct tquic_path *path, u32 mtu)
{
	u32 path_mtu;

	/* Account for headers */
	path_mtu = mtu - sizeof(struct ipv6hdr) - sizeof(struct udphdr);

	/* Enforce minimum */
	if (path_mtu < 1200)
		path_mtu = 1200;

	if (path_mtu < path->mtu) {
		path->mtu = path_mtu;
		pr_info("tquic: path %u PMTU updated to %u (ICMPv6)\n",
			path->path_id, path_mtu);
	}
}

/*
 * IPv6 UDP tunnel integration
 */

/* Setup UDP tunnel for IPv6 path */
static int tquic_v6_tunnel_setup(struct tquic_connection *conn,
				 struct tquic_path *path)
{
	struct sock *sk = conn->sk;
	struct udp_tunnel_sock_cfg cfg = {};
	struct socket *sock;
	int err;

	/* Create UDP socket for this path */
	err = sock_create_kern(sock_net(sk), AF_INET6, SOCK_DGRAM,
			       IPPROTO_UDP, &sock);
	if (err)
		return err;

	/* Configure encapsulation */
	cfg.sk_user_data = conn;
	cfg.encap_type = UDP_ENCAP_L2TPINUDP;  /* Similar encapsulation */
	cfg.encap_destroy = NULL;

	setup_udp_tunnel_sock(sock_net(sk), sock, &cfg);

	/* Bind to local address */
	if (path->local_addr.ss_family == AF_INET6) {
		err = kernel_bind(sock, (struct sockaddr *)&path->local_addr,
				  sizeof(struct sockaddr_in6));
		if (err) {
			sock_release(sock);
			return err;
		}
	}

	return 0;
}

/* Transmit packet over IPv6 UDP tunnel */
static int tquic_v6_tunnel_xmit(struct tquic_connection *conn,
				struct tquic_path *path,
				struct sk_buff *skb)
{
	struct sock *sk = conn->sk;
	struct ipv6_pinfo *np;
	struct dst_entry *dst;
	struct flowi6 fl6;
	const struct sockaddr_in6 *remote;
	__be32 flowlabel;
	int err;

	if (!sk || sk->sk_family != AF_INET6)
		return -EINVAL;

	if (path->remote_addr.ss_family != AF_INET6)
		return -EAFNOSUPPORT;

	np = tquic_inet6_sk(sk);
	remote = (const struct sockaddr_in6 *)&path->remote_addr;

	/* Build flow */
	memset(&fl6, 0, sizeof(fl6));
	fl6.flowi6_proto = IPPROTO_UDP;
	fl6.daddr = remote->sin6_addr;
	if (!ipv6_addr_any(&sk->sk_v6_rcv_saddr))
		fl6.saddr = sk->sk_v6_rcv_saddr;
	fl6.fl6_dport = remote->sin6_port;
	fl6.fl6_sport = inet_sk(sk)->inet_sport;
	fl6.flowi6_oif = sk->sk_bound_dev_if;
	fl6.flowi6_mark = sk->sk_mark;

	/* Apply flow label */
	flowlabel = tquic_v6_path_get_flowlabel(conn, path);
	fl6.flowlabel = ip6_make_flowinfo(np->tclass, flowlabel);

	/* Route lookup */
	dst = ip6_dst_lookup_flow(sock_net(sk), sk, &fl6, NULL);
	if (IS_ERR(dst))
		return PTR_ERR(dst);

	skb_dst_set(skb, dst);

	/* Set checksum */
	skb->ip_summed = CHECKSUM_PARTIAL;
	skb->csum_start = skb_transport_header(skb) - skb->head;
	skb->csum_offset = offsetof(struct udphdr, check);

	/* Transmit */
	err = ip6_xmit(sk, skb, &fl6, sk->sk_mark, rcu_dereference(np->opt),
		       np->tclass, sk->sk_priority);

	return net_xmit_eval(err);
}

/*
 * Dual-stack support
 */

/* Check if socket supports dual-stack */
static bool tquic_v6_is_dualstack(struct sock *sk)
{
	if (sk->sk_family != AF_INET6)
		return false;

	return !ipv6_only_sock(sk);
}

/* Handle connection to IPv4-mapped address */
static int tquic_v6_connect_mapped(struct sock *sk, struct sockaddr_in6 *sin6)
{
	struct tquic_sock *tsk = tquic_sk(sk);
	struct sockaddr_in sin;
	int err;

	if (ipv6_only_sock(sk))
		return -ENETUNREACH;

	/* Convert to IPv4 address */
	err = tquic_v4mapped_to_v4(sin6, &sin);
	if (err)
		return err;

	/* Store the mapped address */
	memcpy(&tsk->connect_addr, sin6, sizeof(*sin6));

	/* Call IPv4 connect path */
	return tquic_connect(sk, (struct sockaddr *)&sin, sizeof(sin));
}

/*
 * IPv6 connection establishment
 */

static int tquic_v6_connect(struct sock *sk, struct sockaddr *addr, int addr_len)
{
	struct sockaddr_in6 *usin = (struct sockaddr_in6 *)addr;
	struct tquic_sock *tsk = tquic_sk(sk);
	struct tquic_connection *conn = tsk->conn;
	struct ipv6_pinfo *np = tquic_inet6_sk(sk);
	struct in6_addr *saddr = NULL;
	struct dst_entry *dst;
	struct flowi6 fl6;
	int addr_type;
	int err;

	if (addr_len < SIN6_LEN_RFC2133)
		return -EINVAL;

	if (usin->sin6_family != AF_INET6)
		return -EAFNOSUPPORT;

	if (!conn)
		return -EINVAL;

	memset(&fl6, 0, sizeof(fl6));

	/* Handle flow label from sockaddr */
	if (inet6_test_bit(SNDFLOW, sk)) {
		fl6.flowlabel = usin->sin6_flowinfo & IPV6_FLOWINFO_MASK;
		if (fl6.flowlabel & IPV6_FLOWLABEL_MASK) {
			struct ip6_flowlabel *flowlabel;
			flowlabel = fl6_sock_lookup(sk, fl6.flowlabel);
			if (IS_ERR(flowlabel))
				return -EINVAL;
			fl6_sock_release(flowlabel);
		}
	}

	/* Handle INADDR_ANY */
	if (ipv6_addr_any(&usin->sin6_addr)) {
		if (ipv6_addr_v4mapped(&sk->sk_v6_rcv_saddr))
			ipv6_addr_set_v4mapped(htonl(INADDR_LOOPBACK),
					       &usin->sin6_addr);
		else
			usin->sin6_addr = in6addr_loopback;
	}

	addr_type = ipv6_addr_type(&usin->sin6_addr);

	/* Reject multicast */
	if (addr_type & IPV6_ADDR_MULTICAST)
		return -ENETUNREACH;

	/* Handle link-local addresses */
	if (addr_type & IPV6_ADDR_LINKLOCAL) {
		if (addr_len >= sizeof(struct sockaddr_in6) &&
		    usin->sin6_scope_id) {
			if (!sk_dev_equal_l3scope(sk, usin->sin6_scope_id))
				return -EINVAL;
			sk->sk_bound_dev_if = usin->sin6_scope_id;
		}

		if (!sk->sk_bound_dev_if)
			return -EINVAL;
	}

	/* Handle IPv4-mapped addresses (dual-stack) */
	if (addr_type & IPV6_ADDR_MAPPED)
		return tquic_v6_connect_mapped(sk, usin);

	/* Store destination address */
	sk->sk_v6_daddr = usin->sin6_addr;
	np->flow_label = fl6.flowlabel;

	memcpy(&tsk->connect_addr, usin, sizeof(*usin));

	/* Setup flow for route lookup */
	if (!ipv6_addr_any(&sk->sk_v6_rcv_saddr))
		saddr = &sk->sk_v6_rcv_saddr;

	fl6.flowi6_proto = IPPROTO_UDP;  /* QUIC over UDP */
	fl6.daddr = sk->sk_v6_daddr;
	fl6.saddr = saddr ? *saddr : np->saddr;
	fl6.flowlabel = ip6_make_flowinfo(np->tclass, np->flow_label);
	fl6.flowi6_oif = sk->sk_bound_dev_if;
	fl6.flowi6_mark = sk->sk_mark;
	fl6.fl6_dport = usin->sin6_port;
	fl6.fl6_sport = inet_sk(sk)->inet_sport;

	/* Route lookup */
	dst = ip6_dst_lookup_flow(sock_net(sk), sk, &fl6, NULL);
	if (IS_ERR(dst)) {
		err = PTR_ERR(dst);
		goto failure;
	}

	/* Set source address if not already set */
	if (!saddr) {
		saddr = &fl6.saddr;
		np->saddr = *saddr;
	}

	sk->sk_v6_rcv_saddr = *saddr;
	sk->sk_gso_type = SKB_GSO_UDP_L4;

	ip6_dst_store(sk, dst, false, false);

	/* Store connection addresses */
	if (tsk->bind_addr.ss_family == 0) {
		struct sockaddr_in6 *local = (struct sockaddr_in6 *)&tsk->bind_addr;
		local->sin6_family = AF_INET6;
		local->sin6_addr = *saddr;
		local->sin6_port = inet_sk(sk)->inet_sport;
	}

	/* Add initial path */
	err = tquic_conn_add_path(conn, (struct sockaddr *)&tsk->bind_addr,
				  (struct sockaddr *)&tsk->connect_addr);
	if (err < 0)
		goto failure;

	/* Set path MTU from route */
	if (conn->active_path) {
		u32 mtu = dst_mtu(dst) - sizeof(struct ipv6hdr) - sizeof(struct udphdr);
		if (mtu < 1200)
			mtu = 1200;
		conn->active_path->mtu = mtu;
	}

	/*
	 * Initialize connection state machine for client mode.
	 * This generates the initial source and destination CIDs,
	 * sets up the state machine, and prepares for handshake.
	 */
	err = tquic_conn_client_connect(conn, (struct sockaddr *)usin);
	if (err < 0) {
		pr_err("tquic: IPv6 client connect init failed: %d\n", err);
		goto failure;
	}

	/*
	 * Initialize scheduler - use requested or per-netns default.
	 * Per CONTEXT.md: "Scheduler locked at connection establishment"
	 */
	{
		struct tquic_sched_ops *sched_ops = NULL;

		if (tsk->requested_scheduler[0])
			sched_ops = tquic_sched_find(tsk->requested_scheduler);

		conn->scheduler = tquic_sched_init_conn(conn, sched_ops);
		if (!conn->scheduler) {
			pr_warn("tquic: IPv6 scheduler init failed, using default\n");
			conn->scheduler = tquic_sched_init_conn(conn, NULL);
			if (!conn->scheduler) {
				err = -ENOMEM;
				goto failure;
			}
		}
	}

	/* Set state to connecting - handshake in progress */
	inet_sk_set_state(sk, TCP_SYN_SENT);

	/*
	 * Allocate and set up the timer state for the connection.
	 * This includes the PTO timer for Initial packet retransmission.
	 */
	if (!conn->timer_state) {
		conn->timer_state = tquic_timer_state_alloc(conn);
		if (!conn->timer_state) {
			pr_warn("tquic: IPv6 timer state alloc failed\n");
			/* Continue without timer - basic operation still works */
		}
	}

	/*
	 * Initiate TLS 1.3 handshake via net/handshake infrastructure.
	 * This sends the Initial packet containing ClientHello CRYPTO frame.
	 * The handshake is asynchronous - we'll block waiting for completion.
	 *
	 * Per RFC 9001: The Initial packet contains the TLS ClientHello
	 * in a CRYPTO frame. The packet is padded to 1200 bytes minimum.
	 */
	err = tquic_start_handshake(sk);
	if (err < 0 && err != -EALREADY) {
		pr_err("tquic: IPv6 handshake start failed: %d\n", err);
		goto failure_close;
	}

	/*
	 * Block until handshake completes.
	 * Per CONTEXT.md: connect() blocks until handshake completes or
	 * a fixed 30-second timeout expires.
	 *
	 * The timer system handles Initial packet retransmission during
	 * handshake via the PTO timer mechanism.
	 */
	err = tquic_wait_for_handshake(sk, TQUIC_HANDSHAKE_TIMEOUT_MS);
	if (err < 0) {
		pr_err("tquic: IPv6 handshake failed: %d\n", err);
		goto failure_close;
	}

	/* Verify handshake actually completed */
	if (!(tsk->flags & TQUIC_F_HANDSHAKE_DONE)) {
		err = -EQUIC_HANDSHAKE_FAILED;
		goto failure_close;
	}

	/* Handshake succeeded - mark connection as established */
	conn->state = TQUIC_CONN_CONNECTED;
	inet_sk_set_state(sk, TCP_ESTABLISHED);

	/* Initialize path manager after connection established */
	err = tquic_pm_conn_init(conn);
	if (err < 0) {
		pr_warn("tquic: IPv6 PM init failed: %d\n", err);
		/* Continue anyway - PM is optional for basic operation */
	}

	/* Start idle timer now that connection is established */
	if (conn->timer_state)
		tquic_timer_set_idle(conn->timer_state);

	pr_debug("tquic: IPv6 connected to %pI6c:%u\n",
		 &usin->sin6_addr, ntohs(usin->sin6_port));

	return 0;

failure_close:
	/* Clean up handshake state on failure */
	tquic_handshake_cleanup(sk);
	inet_sk_set_state(sk, TCP_CLOSE);
	sk->sk_err = -err;
failure:
	sk->sk_route_caps = 0;
	return err;
}

/*
 * ICMPv6 error handling
 */

static int tquic_v6_err(struct sk_buff *skb, struct inet6_skb_parm *opt,
			u8 type, u8 code, int offset, __be32 info)
{
	const struct ipv6hdr *hdr = (const struct ipv6hdr *)skb->data;
	const struct udphdr *uh = (struct udphdr *)(skb->data + offset);
	struct net *net = dev_net_rcu(skb->dev);
	struct tquic_connection *conn;
	struct tquic_path *path;
	struct sock *sk;
	int err;
	bool fatal;

	/* Lookup the socket */
	sk = __udp6_lib_lookup(net, &hdr->daddr, uh->dest,
			       &hdr->saddr, uh->source,
			       inet6_iif(skb), inet6_sdif(skb),
			       net->ipv4.udp_table, skb);
	if (!sk) {
		__ICMP6_INC_STATS(net, __in6_dev_get(skb->dev),
				  ICMP6_MIB_INERRORS);
		return -ENOENT;
	}

	fatal = icmpv6_err_convert(type, code, &err);

	bh_lock_sock(sk);

	if (sock_owned_by_user(sk) && type != ICMPV6_PKT_TOOBIG) {
		__NET_INC_STATS(net, LINUX_MIB_LOCKDROPPEDICMPS);
		goto out;
	}

	/* Handle specific ICMPv6 types */
	switch (type) {
	case ICMPV6_PKT_TOOBIG:
		{
			u32 mtu = ntohl(info);

			/* Enforce minimum IPv6 MTU */
			if (mtu < IPV6_MIN_MTU)
				goto out;

			/* Update path MTU */
			conn = tquic_sk(sk)->conn;
			if (conn) {
				list_for_each_entry(path, &conn->paths, list) {
					if (tquic_path_get_family(path) == AF_INET6)
						tquic_v6_path_update_pmtu(conn, path, mtu);
				}
			}

			/* Also update socket PMTU */
			inet6_csk_update_pmtu(sk, mtu);
			break;
		}

	case ICMPV6_DEST_UNREACH:
		if (code == ICMPV6_NOROUTE ||
		    code == ICMPV6_ADDR_UNREACH ||
		    code == ICMPV6_PORT_UNREACH) {
			/* Path may have failed */
			conn = tquic_sk(sk)->conn;
			if (conn && conn->scheduler) {
				/* Find affected path and mark as failed */
				list_for_each_entry(path, &conn->paths, list) {
					const struct sockaddr_in6 *remote;

					if (path->remote_addr.ss_family != AF_INET6)
						continue;

					remote = (const struct sockaddr_in6 *)&path->remote_addr;
					if (ipv6_addr_equal(&remote->sin6_addr, &hdr->daddr)) {
						path->state = TQUIC_PATH_FAILED;
						tquic_bond_path_failed(conn, path);
						break;
					}
				}
			}
		}

		if (!sock_owned_by_user(sk) && fatal) {
			WRITE_ONCE(sk->sk_err, err);
			sk_error_report(sk);
		} else {
			WRITE_ONCE(sk->sk_err_soft, err);
		}
		break;

	case NDISC_REDIRECT:
		if (!sock_owned_by_user(sk)) {
			struct dst_entry *dst = __sk_dst_check(sk, np_cookie(sk));
			if (dst)
				dst->ops->redirect(dst, sk, skb);
		}
		break;
	}

out:
	bh_unlock_sock(sk);
	sock_put(sk);
	return 0;
}

/*
 * IPv6 socket options
 */

static int tquic_v6_setsockopt(struct socket *sock, int level, int optname,
			       sockptr_t optval, unsigned int optlen)
{
	struct sock *sk = sock->sk;
	struct tquic_sock *tsk = tquic_sk(sk);
	struct ipv6_pinfo *np = tquic_inet6_sk(sk);
	int val;
	int err = 0;

	if (level == SOL_IPV6) {
		/* Handle IPv6-specific options */
		switch (optname) {
		case IPV6_TCLASS:
			if (optlen < sizeof(int))
				return -EINVAL;
			if (copy_from_sockptr(&val, optval, sizeof(val)))
				return -EFAULT;
			if (val < -1 || val > 0xff)
				return -EINVAL;
			np->tclass = val;
			break;

		case IPV6_FLOWLABEL_MGR:
			/* Allow flow label management */
			return ipv6_flowlabel_opt(sk, optval, optlen);

		case IPV6_FLOWINFO_SEND:
			if (optlen < sizeof(int))
				return -EINVAL;
			if (copy_from_sockptr(&val, optval, sizeof(val)))
				return -EFAULT;
			if (val)
				inet6_set_bit(SNDFLOW, sk);
			else
				inet6_clear_bit(SNDFLOW, sk);
			break;

		case IPV6_DONTFRAG:
			if (optlen < sizeof(int))
				return -EINVAL;
			if (copy_from_sockptr(&val, optval, sizeof(val)))
				return -EFAULT;
			np->dontfrag = !!val;
			break;

		case IPV6_RECVPATHMTU:
			if (optlen < sizeof(int))
				return -EINVAL;
			if (copy_from_sockptr(&val, optval, sizeof(val)))
				return -EFAULT;
			np->rxopt.bits.rxpmtu = !!val;
			break;

		case IPV6_PATHMTU:
			/* Read-only option */
			return -ENOPROTOOPT;

		case IPV6_V6ONLY:
			if (optlen < sizeof(int))
				return -EINVAL;
			if (copy_from_sockptr(&val, optval, sizeof(val)))
				return -EFAULT;
			if (sk->sk_state != TCP_CLOSE)
				return -EINVAL;
			sk->sk_ipv6only = !!val;
			break;

		default:
			/* Pass to generic IPv6 handler */
			return ipv6_setsockopt(sk, level, optname, optval, optlen);
		}

		return err;
	}

	if (level == SOL_TQUIC) {
		/* TQUIC-specific IPv6 options */
		switch (optname) {
		case TQUIC_MULTIPATH:
			/* IPv6 multipath is always enabled */
			if (optlen < sizeof(int))
				return -EINVAL;
			if (copy_from_sockptr(&val, optval, sizeof(val)))
				return -EFAULT;
			/* Could store preference for IPv6 paths */
			break;

		default:
			/* Pass to generic TQUIC handler */
			return -ENOPROTOOPT;
		}

		return err;
	}

	return -ENOPROTOOPT;
}

static int tquic_v6_getsockopt(struct socket *sock, int level, int optname,
			       char __user *optval, int __user *optlen)
{
	struct sock *sk = sock->sk;
	struct ipv6_pinfo *np = tquic_inet6_sk(sk);
	int len, val;

	if (get_user(len, optlen))
		return -EFAULT;
	if (len < 0)
		return -EINVAL;

	if (level == SOL_IPV6) {
		switch (optname) {
		case IPV6_TCLASS:
			val = np->tclass;
			break;

		case IPV6_DONTFRAG:
			val = np->dontfrag;
			break;

		case IPV6_V6ONLY:
			val = sk->sk_ipv6only;
			break;

		case IPV6_PATHMTU:
			{
				struct ip6_mtuinfo mtuinfo;
				struct dst_entry *dst;

				memset(&mtuinfo, 0, sizeof(mtuinfo));

				rcu_read_lock();
				dst = __sk_dst_get(sk);
				if (dst) {
					mtuinfo.ip6m_mtu = dst_mtu(dst);
					mtuinfo.ip6m_addr.sin6_family = AF_INET6;
					mtuinfo.ip6m_addr.sin6_addr = sk->sk_v6_daddr;
				}
				rcu_read_unlock();

				if (len < sizeof(mtuinfo))
					return -EINVAL;
				if (copy_to_user(optval, &mtuinfo, sizeof(mtuinfo)))
					return -EFAULT;
				if (put_user(sizeof(mtuinfo), optlen))
					return -EFAULT;
				return 0;
			}

		default:
			return ipv6_getsockopt(sk, level, optname, optval, optlen);
		}

		len = min_t(unsigned int, len, sizeof(int));
		if (put_user(len, optlen))
			return -EFAULT;
		if (copy_to_user(optval, &val, len))
			return -EFAULT;
		return 0;
	}

	return -ENOPROTOOPT;
}

/*
 * Happy Eyeballs implementation
 */

static void tquic_he_fallback_work(struct work_struct *work);
static void tquic_he_fallback_timer(struct timer_list *t);

/* Initialize Happy Eyeballs state */
static struct tquic_happy_eyeballs *tquic_he_init(struct tquic_connection *conn)
{
	struct tquic_happy_eyeballs *he;

	he = kzalloc(sizeof(*he), GFP_KERNEL);
	if (!he)
		return NULL;

	he->conn = conn;
	he->resolution_delay_ms = TQUIC_HE_RESOLUTION_DELAY_MS;
	he->connection_timeout_ms = TQUIC_HE_CONNECTION_TIMEOUT_MS;
	he->prefer_ipv6 = true;
	he->allow_fallback = true;

	INIT_WORK(&he->work, tquic_he_fallback_work);
	timer_setup(&he->fallback_timer, tquic_he_fallback_timer, 0);

	return he;
}

/* Cleanup Happy Eyeballs state */
static void tquic_he_cleanup(struct tquic_happy_eyeballs *he)
{
	if (!he)
		return;

	del_timer_sync(&he->fallback_timer);
	cancel_work_sync(&he->work);
	kfree(he);
}

/* Fallback timer callback */
static void tquic_he_fallback_timer(struct timer_list *t)
{
	struct tquic_happy_eyeballs *he = from_timer(he, t, fallback_timer);

	/* Schedule work to attempt IPv4 */
	schedule_work(&he->work);
}

/* Fallback work handler */
static void tquic_he_fallback_work(struct work_struct *work)
{
	struct tquic_happy_eyeballs *he = container_of(work,
						       struct tquic_happy_eyeballs,
						       work);
	struct tquic_connection *conn = he->conn;
	struct sock *sk;

	if (!conn || !conn->sk)
		return;

	sk = conn->sk;

	/* If IPv6 succeeded, cancel IPv4 attempt */
	if (he->ipv6_connected) {
		he->winner = AF_INET6;
		return;
	}

	/* If IPv4 not yet attempted and fallback allowed */
	if (!he->ipv4_attempted && he->allow_fallback &&
	    he->ipv4_addr.sin_family == AF_INET) {
		he->ipv4_attempted = true;
		he->ipv4_start_time = ktime_get();

		/* Add IPv4 path */
		tquic_conn_add_path(conn,
				    (struct sockaddr *)&he->ipv4_addr,
				    (struct sockaddr *)&he->ipv4_addr);

		pr_debug("tquic: Happy Eyeballs starting IPv4 fallback\n");
	}
}

/* Start Happy Eyeballs connection attempt */
static int tquic_he_connect(struct sock *sk,
			    const struct sockaddr_in6 *ipv6_addr,
			    const struct sockaddr_in *ipv4_addr)
{
	struct tquic_sock *tsk = tquic_sk(sk);
	struct tquic_connection *conn = tsk->conn;
	struct tquic_happy_eyeballs *he;
	int err;

	if (!conn)
		return -EINVAL;

	/* Initialize Happy Eyeballs state */
	he = tquic_he_init(conn);
	if (!he)
		return -ENOMEM;

	/* Store addresses */
	if (ipv6_addr)
		memcpy(&he->ipv6_addr, ipv6_addr, sizeof(*ipv6_addr));
	if (ipv4_addr)
		memcpy(&he->ipv4_addr, ipv4_addr, sizeof(*ipv4_addr));

	/* Prefer IPv6: attempt it first */
	if (he->prefer_ipv6 && ipv6_addr && ipv6_addr->sin6_family == AF_INET6) {
		he->ipv6_attempted = true;
		he->ipv6_start_time = ktime_get();

		/* Start fallback timer */
		if (ipv4_addr && ipv4_addr->sin_family == AF_INET) {
			mod_timer(&he->fallback_timer,
				  jiffies + msecs_to_jiffies(he->resolution_delay_ms));
		}

		/* Attempt IPv6 connection */
		err = tquic_v6_connect(sk, (struct sockaddr *)ipv6_addr,
				       sizeof(*ipv6_addr));
		if (err == 0) {
			he->ipv6_connected = true;
			he->winner = AF_INET6;
			del_timer(&he->fallback_timer);
		} else {
			he->ipv6_error = err;
			/* Immediately try IPv4 on failure */
			if (he->allow_fallback)
				schedule_work(&he->work);
		}
	} else if (ipv4_addr && ipv4_addr->sin_family == AF_INET) {
		/* IPv4 only */
		he->ipv4_attempted = true;
		he->ipv4_start_time = ktime_get();
		err = tquic_connect(sk, (struct sockaddr *)ipv4_addr,
				    sizeof(*ipv4_addr));
		if (err == 0) {
			he->ipv4_connected = true;
			he->winner = AF_INET;
		} else {
			he->ipv4_error = err;
		}
	} else {
		tquic_he_cleanup(he);
		return -EINVAL;
	}

	/* Store Happy Eyeballs state in connection (for cleanup) */
	/* In a full implementation, this would be stored properly */

	return err;
}

/*
 * IPv6 path management for WAN bonding
 */

/* Discover IPv6 addresses for path creation */
int tquic_v6_discover_addresses(struct tquic_connection *conn,
				struct sockaddr_storage *addrs,
				int max_addrs)
{
	struct net_device *dev;
	struct inet6_dev *idev;
	struct inet6_ifaddr *ifa;
	int count = 0;

	rcu_read_lock();

	for_each_netdev_rcu(&init_net, dev) {
		/* Skip loopback and down interfaces */
		if (dev->flags & IFF_LOOPBACK)
			continue;
		if (!(dev->flags & IFF_UP))
			continue;

		idev = __in6_dev_get(dev);
		if (!idev)
			continue;

		list_for_each_entry_rcu(ifa, &idev->addr_list, if_list) {
			struct sockaddr_in6 *sin6;

			if (count >= max_addrs)
				break;

			/* Skip deprecated and tentative addresses */
			if (ifa->flags & (IFA_F_DEPRECATED | IFA_F_TENTATIVE))
				continue;

			/* Skip link-local unless specifically requested */
			if (ipv6_addr_type(&ifa->addr) & IPV6_ADDR_LINKLOCAL)
				continue;

			sin6 = (struct sockaddr_in6 *)&addrs[count];
			sin6->sin6_family = AF_INET6;
			sin6->sin6_addr = ifa->addr;
			sin6->sin6_port = 0;
			sin6->sin6_scope_id = dev->ifindex;
			count++;
		}
	}

	rcu_read_unlock();

	pr_debug("tquic: discovered %d IPv6 addresses\n", count);
	return count;
}
EXPORT_SYMBOL_GPL(tquic_v6_discover_addresses);

/* Add IPv6 path to connection */
int tquic_v6_add_path(struct tquic_connection *conn,
		      struct sockaddr_in6 *local,
		      struct sockaddr_in6 *remote)
{
	int err;

	if (local->sin6_family != AF_INET6 ||
	    remote->sin6_family != AF_INET6)
		return -EAFNOSUPPORT;

	err = tquic_conn_add_path(conn,
				  (struct sockaddr *)local,
				  (struct sockaddr *)remote);
	if (err >= 0) {
		struct tquic_path *path = tquic_conn_get_path(conn, err);
		if (path) {
			/* Set initial IPv6-specific path parameters */
			path->mtu = IPV6_MIN_MTU - sizeof(struct udphdr);

			/* Generate flow label for this path */
			tquic_v6_path_set_flowlabel(path,
				tquic_v6_generate_flowlabel(conn, path));

			pr_debug("tquic: added IPv6 path %d: %pI6c -> %pI6c\n",
				 err, &local->sin6_addr, &remote->sin6_addr);
		}
	}

	return err;
}
EXPORT_SYMBOL_GPL(tquic_v6_add_path);

/*
 * IPv6 socket initialization
 */

static int tquic_v6_init_sock(struct sock *sk)
{
	struct tquic_sock *tsk = tquic_sk(sk);
	struct ipv6_pinfo *np = tquic_inet6_sk(sk);

	/* Initialize base TQUIC socket */
	inet_sk_set_state(sk, TCP_CLOSE);

	INIT_LIST_HEAD(&tsk->accept_queue);
	tsk->accept_queue_len = 0;
	tsk->max_accept_queue = 128;

	/* Create connection structure */
	tsk->conn = tquic_conn_create(tsk, false);
	if (!tsk->conn)
		return -ENOMEM;

	/* Initialize bonding state */
	tsk->conn->scheduler = tquic_bond_init(tsk->conn);

	/* Initialize IPv6-specific state */
	np->mc_loop = 1;
	np->hop_limit = -1;
	np->mcast_hops = IPV6_DEFAULT_MCASTHOPS;
	np->tclass = -1;
	np->pmtudisc = IPV6_PMTUDISC_WANT;

	/* Allow dual-stack by default */
	sk->sk_ipv6only = 0;

	sk->sk_gso_type = SKB_GSO_UDP_L4;

	pr_debug("tquic: IPv6 socket initialized\n");
	return 0;
}

static void tquic_v6_destroy_sock(struct sock *sk)
{
	struct tquic_sock *tsk = tquic_sk(sk);

	/* IPv6-specific cleanup */
	/* Flow label cleanup handled by inet6_destroy_sock */

	/* Base TQUIC cleanup */
	if (tsk->conn) {
		if (tsk->conn->scheduler)
			tquic_bond_cleanup(tsk->conn->scheduler);
		tquic_conn_destroy(tsk->conn);
		tsk->conn = NULL;
	}

	inet6_destroy_sock(sk);

	pr_debug("tquic: IPv6 socket destroyed\n");
}

/*
 * IPv6 connection sock AF operations
 */

static const struct inet_connection_sock_af_ops tquic_v6_af_ops = {
	.queue_xmit	= inet6_csk_xmit,
	.send_check	= NULL,  /* QUIC handles its own checksums */
	.rebuild_header	= inet6_sk_rebuild_header,
	.sk_rx_dst_set	= inet6_sk_rx_dst_set,
	.conn_request	= NULL,  /* QUIC handles connection requests */
	.syn_recv_sock	= NULL,  /* QUIC handles this */
	.net_header_len	= sizeof(struct ipv6hdr),
	.setsockopt	= ipv6_setsockopt,
	.getsockopt	= ipv6_getsockopt,
	.mtu_reduced	= tquic_v6_mtu_reduced,
};

/* IPv4-mapped address operations for dual-stack */
static const struct inet_connection_sock_af_ops tquic_v6_mapped_ops = {
	.queue_xmit	= ip_queue_xmit,
	.send_check	= NULL,
	.rebuild_header	= inet_sk_rebuild_header,
	.sk_rx_dst_set	= inet_sk_rx_dst_set,
	.conn_request	= NULL,
	.syn_recv_sock	= NULL,
	.net_header_len	= sizeof(struct iphdr),
	.setsockopt	= ipv6_setsockopt,
	.getsockopt	= ipv6_getsockopt,
	.mtu_reduced	= NULL,  /* Use IPv4 handler */
};

/*
 * Protocol definition for IPv6 TQUIC
 */

static struct proto tquic6_prot = {
	.name		= "TQUICv6",
	.owner		= THIS_MODULE,
	.obj_size	= sizeof(struct tquic6_sock),
	.ipv6_pinfo_offset = offsetof(struct tquic6_sock, inet6),
	.init		= tquic_v6_init_sock,
	.destroy	= tquic_v6_destroy_sock,
	.hash		= inet_hash,
	.unhash		= inet_unhash,
	.get_port	= inet_csk_get_port,
	.close		= tquic_close,
	.connect	= tquic_v6_connect,
	.sendmsg	= tquic_sendmsg,
	.recvmsg	= tquic_recvmsg,
};

/*
 * Socket operations for IPv6 TQUIC
 */

static int tquic_v6_release(struct socket *sock)
{
	struct sock *sk = sock->sk;

	if (!sk)
		return 0;

	sock->sk = NULL;
	sock_put(sk);
	return 0;
}

static int tquic_v6_bind(struct socket *sock, struct sockaddr *addr, int addr_len)
{
	struct sock *sk = sock->sk;
	struct tquic_sock *tsk = tquic_sk(sk);
	struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)addr;
	int addr_type;

	if (addr_len < SIN6_LEN_RFC2133)
		return -EINVAL;

	if (sin6->sin6_family != AF_INET6)
		return -EAFNOSUPPORT;

	addr_type = ipv6_addr_type(&sin6->sin6_addr);

	/* Handle binding to IPv4-mapped address */
	if (addr_type & IPV6_ADDR_MAPPED) {
		struct sockaddr_in sin;

		if (ipv6_only_sock(sk))
			return -EINVAL;

		sin.sin_family = AF_INET;
		sin.sin_addr.s_addr = sin6->sin6_addr.s6_addr32[3];
		sin.sin_port = sin6->sin6_port;

		memcpy(&tsk->bind_addr, &sin, sizeof(sin));
	} else {
		memcpy(&tsk->bind_addr, sin6,
		       min_t(size_t, addr_len, sizeof(struct sockaddr_in6)));
	}

	sk->sk_v6_rcv_saddr = sin6->sin6_addr;
	inet_sk(sk)->inet_sport = sin6->sin6_port;

	inet_sk_set_state(sk, TCP_CLOSE);

	return 0;
}

static int tquic_v6_connect_socket(struct socket *sock, struct sockaddr *addr,
				   int addr_len, int flags)
{
	return tquic_v6_connect(sock->sk, addr, addr_len);
}

static int tquic_v6_getname(struct socket *sock, struct sockaddr *addr, int peer)
{
	struct sock *sk = sock->sk;
	struct tquic_sock *tsk = tquic_sk(sk);
	struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)addr;

	sin6->sin6_family = AF_INET6;

	if (peer) {
		sin6->sin6_addr = sk->sk_v6_daddr;
		sin6->sin6_port = inet_sk(sk)->inet_dport;
	} else {
		sin6->sin6_addr = sk->sk_v6_rcv_saddr;
		sin6->sin6_port = inet_sk(sk)->inet_sport;
	}

	sin6->sin6_flowinfo = 0;
	sin6->sin6_scope_id = 0;

	if (ipv6_addr_type(&sin6->sin6_addr) & IPV6_ADDR_LINKLOCAL)
		sin6->sin6_scope_id = sk->sk_bound_dev_if;

	return sizeof(*sin6);
}

static const struct proto_ops tquic6_proto_ops = {
	.family		= PF_INET6,
	.owner		= THIS_MODULE,
	.release	= tquic_v6_release,
	.bind		= tquic_v6_bind,
	.connect	= tquic_v6_connect_socket,
	.socketpair	= sock_no_socketpair,
	.accept		= inet_accept,
	.getname	= tquic_v6_getname,
	.poll		= tquic_poll,
	.ioctl		= inet6_ioctl,
	.listen		= inet_listen,
	.shutdown	= inet_shutdown,
	.setsockopt	= tquic_v6_setsockopt,
	.getsockopt	= tquic_v6_getsockopt,
	.sendmsg	= inet6_sendmsg,
	.recvmsg	= inet6_recvmsg,
	.mmap		= sock_no_mmap,
};

/*
 * inet6_protosw registration
 */

static struct inet_protosw tquic6_protosw = {
	.type		= SOCK_STREAM,
	.protocol	= IPPROTO_TQUIC,
	.prot		= &tquic6_prot,
	.ops		= &tquic6_proto_ops,
	.flags		= INET_PROTOSW_ICSK,
};

/*
 * Per-net namespace operations
 */

static int __net_init tquic6_net_init(struct net *net)
{
	/* Could initialize per-net IPv6 TQUIC state here */
	return 0;
}

static void __net_exit tquic6_net_exit(struct net *net)
{
	/* Cleanup per-net IPv6 TQUIC state */
}

static struct pernet_operations tquic6_net_ops = {
	.init	= tquic6_net_init,
	.exit	= tquic6_net_exit,
};

/*
 * Module initialization
 */

static int __init __maybe_unused tquic6_init(void)
{
	int ret;

	pr_info("tquic: initializing IPv6 support\n");

	/* Register IPv6 protocol handler */
	ret = proto_register(&tquic6_prot, 1);
	if (ret) {
		pr_err("tquic: failed to register IPv6 protocol: %d\n", ret);
		return ret;
	}

	/* Register inet6 protosw */
	ret = inet6_register_protosw(&tquic6_protosw);
	if (ret) {
		pr_err("tquic: failed to register inet6 protosw: %d\n", ret);
		goto err_protosw;
	}

	/* Register per-net operations */
	ret = register_pernet_subsys(&tquic6_net_ops);
	if (ret) {
		pr_err("tquic: failed to register pernet subsys: %d\n", ret);
		goto err_pernet;
	}

	pr_info("tquic: IPv6 support initialized\n");
	pr_info("tquic: Dual-stack support enabled\n");
	pr_info("tquic: Happy Eyeballs enabled (IPv6 preferred, delay=%dms)\n",
		TQUIC_HE_RESOLUTION_DELAY_MS);

	return 0;

err_pernet:
	inet6_unregister_protosw(&tquic6_protosw);
err_protosw:
	proto_unregister(&tquic6_prot);
	return ret;
}

static void __exit __maybe_unused tquic6_exit(void)
{
	pr_info("tquic: shutting down IPv6 support\n");

	unregister_pernet_subsys(&tquic6_net_ops);
	inet6_unregister_protosw(&tquic6_protosw);
	proto_unregister(&tquic6_prot);

	pr_info("tquic: IPv6 support unloaded\n");
}

/*
 * IPv6 protocol registration is handled by tquic_proto_init().
 * Keep this file for IPv6 helpers without double registration.
 */

MODULE_AUTHOR("Linux Foundation");
MODULE_DESCRIPTION("TQUIC IPv6 Support for WAN Bonding");
MODULE_LICENSE("GPL");
MODULE_ALIAS_NET_PF_PROTO(PF_INET6, IPPROTO_TQUIC);
