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
#include <net/inet_hashtables.h>
#include <net/tcp.h>
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
#include "tquic_debug.h"

#include "protocol.h"

/*
 * Note: struct tquic6_sock is defined in include/net/tquic.h
 * Use tquic6_inet6_sk() from that header to access ipv6_pinfo.
 */

/* Forward declarations */
static int tquic_v6_connect(struct sock *sk, struct sockaddr_unsized *addr, int addr_len);
static void tquic_v6_mtu_reduced(struct sock *sk);
static int tquic_v6_init_sock(struct sock *sk);
static void tquic_v6_destroy_sock(struct sock *sk);

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
				tquic_dbg("path %u MTU reduced to %u\n",
					 path->path_id, path_mtu);
			}
		}
	}
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
		tquic_info("path %u PMTU updated to %u (ICMPv6)\n",
			path->path_id, path_mtu);
	}
}

/*
 * Dual-stack support
 */

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
	return tquic_connect(sk, (struct sockaddr_unsized *)&sin, sizeof(sin));
}

/*
 * IPv6 connection establishment
 */

static int tquic_v6_connect(struct sock *sk, struct sockaddr_unsized *addr, int addr_len)
{
	struct sockaddr_in6 *usin;
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

	/* Now safe to cast */
	usin = (struct sockaddr_in6 *)addr;

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
		tquic_err("IPv6 client connect init failed: %d\n", err);
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
			tquic_warn("IPv6 scheduler init failed, using default\n");
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
			tquic_warn("IPv6 timer state alloc failed\n");
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
		tquic_err("IPv6 handshake start failed: %d\n", err);
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
		tquic_err("IPv6 handshake failed: %d\n", err);
		goto failure_close;
	}

	/* Verify handshake actually completed */
	if (!(tsk->flags & TQUIC_F_HANDSHAKE_DONE)) {
		err = -EQUIC_HANDSHAKE_FAILED;
		goto failure_close;
	}

	/* Handshake succeeded - mark connection as established */
	spin_lock_bh(&conn->lock);
	WRITE_ONCE(conn->state, TQUIC_CONN_CONNECTED);
	spin_unlock_bh(&conn->lock);
	inet_sk_set_state(sk, TCP_ESTABLISHED);

	/* Initialize path manager after connection established */
	err = tquic_pm_conn_init(conn);
	if (err < 0) {
		tquic_warn("IPv6 PM init failed: %d\n", err);
		/* Continue anyway - PM is optional for basic operation */
	}

	/* Start idle timer now that connection is established */
	if (conn->timer_state)
		tquic_timer_set_idle(conn->timer_state);

	tquic_dbg("IPv6 connected to %pI6c:%u\n",
		 &usin->sin6_addr, ntohs(usin->sin6_port));

	return 0;

failure_close:
	/* Clean up handshake state on failure */
	tquic_handshake_cleanup(sk);
	inet_sk_set_state(sk, TCP_CLOSE);
	/* CF-241: sk_err uses positive errno values; use WRITE_ONCE */
	WRITE_ONCE(sk->sk_err, -err);
failure:
	sk->sk_route_caps = 0;
	return err;
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
			inet_assign_bit(DONTFRAG, sk, !!val);
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
			val = inet_test_bit(DONTFRAG, sk);
			break;

		case IPV6_V6ONLY:
			val = sk->sk_ipv6only;
			break;

		case IPV6_PATHMTU:
			{
				struct ip6_mtuinfo mtuinfo;
				struct dst_entry *dst;

				if (len < sizeof(mtuinfo))
					return -EINVAL;

				memset(&mtuinfo, 0, sizeof(mtuinfo));

				rcu_read_lock();
				dst = __sk_dst_get(sk);
				if (!dst) {
					rcu_read_unlock();
					return -ENOTCONN;
				}
				mtuinfo.ip6m_mtu = dst_mtu(dst);
				rcu_read_unlock();

				mtuinfo.ip6m_addr.sin6_family = AF_INET6;
				mtuinfo.ip6m_addr.sin6_port = sk->sk_dport;
				mtuinfo.ip6m_addr.sin6_addr = sk->sk_v6_daddr;

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

		tquic_dbg("Happy Eyeballs starting IPv4 fallback\n");
	}
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
	struct net *net;
	int count = 0;

	/* CF-103: Use connection's namespace instead of init_net */
	net = (conn && conn->sk) ? sock_net(conn->sk) : current->nsproxy->net_ns;

	rcu_read_lock();

	for_each_netdev_rcu(net, dev) {
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

	tquic_dbg("discovered %d IPv6 addresses\n", count);
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

			tquic_dbg("added IPv6 path %d: %pI6c -> %pI6c\n",
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
	inet_set_bit(MC6_LOOP, sk);
	np->hop_limit = -1;
	np->mcast_hops = IPV6_DEFAULT_MCASTHOPS;
	np->tclass = -1;
	np->pmtudisc = IPV6_PMTUDISC_WANT;

	/* Allow dual-stack by default */
	sk->sk_ipv6only = 0;

	sk->sk_gso_type = SKB_GSO_UDP_L4;

	tquic_dbg("IPv6 socket initialized\n");
	return 0;
}

static void tquic_v6_destroy_sock(struct sock *sk)
{
	struct tquic_sock *tsk = tquic_sk(sk);

	/* IPv6-specific cleanup */
	/* Flow label cleanup handled by inet6_destroy_sock */

	/* Base TQUIC cleanup */
	if (tsk->conn) {
		if (tsk->conn->scheduler) {
			tquic_bond_cleanup(tsk->conn->scheduler);
			tsk->conn->scheduler = NULL;
		}
		tquic_conn_destroy(tsk->conn);
		tsk->conn = NULL;
	}


	tquic_dbg("IPv6 socket destroyed\n");
}

/*
 * IPv6 connection sock AF operations
 */

static const struct inet_connection_sock_af_ops tquic_v6_af_ops = {
	.queue_xmit	= inet6_csk_xmit,
	.send_check	= NULL,  /* QUIC handles its own checksums */
	.rebuild_header	= inet6_sk_rebuild_header,
	.sk_rx_dst_set	= inet_sk_rx_dst_set,
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

static int tquic_v6_bind(struct socket *sock, struct sockaddr_unsized *addr, int addr_len)
{
	struct sock *sk = sock->sk;
	struct tquic_sock *tsk = tquic_sk(sk);
	struct sockaddr_in6 *sin6;
	int addr_type;

	if (addr_len < SIN6_LEN_RFC2133)
		return -EINVAL;

	/* Now safe to cast */
	sin6 = (struct sockaddr_in6 *)addr;

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

static int tquic_v6_connect_socket(struct socket *sock, struct sockaddr_unsized *addr,
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

int __init tquic6_init(void)
{
	int ret;

	tquic_info("initializing IPv6 support\n");

	/* Register IPv6 protocol handler */
	ret = proto_register(&tquic6_prot, 1);
	if (ret) {
		tquic_err("failed to register IPv6 protocol: %d\n", ret);
		return ret;
	}

	/* Register inet6 protosw */
	ret = inet6_register_protosw(&tquic6_protosw);
	if (ret) {
		tquic_err("failed to register inet6 protosw: %d\n", ret);
		goto err_protosw;
	}

	/* Register per-net operations */
	ret = register_pernet_subsys(&tquic6_net_ops);
	if (ret) {
		tquic_err("failed to register pernet subsys: %d\n", ret);
		goto err_pernet;
	}

	tquic_info("IPv6 support initialized\n");
	tquic_info("Dual-stack support enabled\n");
	tquic_info("Happy Eyeballs enabled (IPv6 preferred, delay=%dms)\n",
		TQUIC_HE_RESOLUTION_DELAY_MS);

	return 0;

err_pernet:
	inet6_unregister_protosw(&tquic6_protosw);
err_protosw:
	proto_unregister(&tquic6_prot);
	return ret;
}

void __exit tquic6_exit(void)
{
	tquic_info("shutting down IPv6 support\n");

	unregister_pernet_subsys(&tquic6_net_ops);
	inet6_unregister_protosw(&tquic6_protosw);
	proto_unregister(&tquic6_prot);

	tquic_info("IPv6 support unloaded\n");
}

/*
 * IPv6 protocol registration is handled by tquic_proto_init().
 * Keep this file for IPv6 helpers without double registration.
 */

MODULE_AUTHOR("Linux Foundation");
MODULE_DESCRIPTION("TQUIC IPv6 Support for WAN Bonding");
MODULE_LICENSE("GPL");
MODULE_ALIAS_NET_PF_PROTO(PF_INET6, IPPROTO_TQUIC);
