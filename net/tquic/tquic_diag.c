// SPDX-License-Identifier: GPL-2.0
/*
 * TQUIC socket monitoring support for ss tool
 *
 * Copyright (c) 2026 Linux Foundation
 *
 * This file implements the inet_diag handler for TQUIC connections,
 * enabling visibility of TQUIC connections in the ss utility.
 *
 * Following the MPTCP pattern in net/mptcp/mptcp_diag.c
 *
 * Requires kernel >= 5.7 due to inet_diag API refactoring
 * (inet_sk_diag_fill, dump, dump_one signatures all changed in 5.7).
 */

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/version.h>

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 7, 0)

#include <linux/net.h>
#include <linux/inet_diag.h>
#include <linux/netlink.h>
#include <net/netlink.h>
#include <net/sock.h>
#include <net/inet_connection_sock.h>
#include <net/tquic.h>
#include <uapi/linux/tquic_diag.h>
#include "tquic_debug.h"
#include "protocol.h"

/*
 * State name mapping for ss output
 *
 * Per CONTEXT.md: State names use hybrid format showing both
 * QUIC state and TCP equivalent in parentheses.
 */
static const char *tquic_state_names[] = {
	[TQUIC_CONN_IDLE]       = "IDLE (CLOSED)",
	[TQUIC_CONN_CONNECTING] = "CONNECTING (SYN_SENT)",
	[TQUIC_CONN_CONNECTED]  = "CONNECTED (ESTABLISHED)",
	[TQUIC_CONN_CLOSING]    = "CLOSING (FIN_WAIT1)",
	[TQUIC_CONN_DRAINING]   = "DRAINING (TIME_WAIT)",
	[TQUIC_CONN_CLOSED]     = "CLOSED (CLOSED)",
};

static inline const char *tquic_state_name(enum tquic_conn_state state)
{
	if (state >= ARRAY_SIZE(tquic_state_names))
		return "UNKNOWN";
	return tquic_state_names[state];
}

/*
 * Diag context for iteration
 *
 * Used to maintain state across multiple dump calls for pagination.
 */
struct tquic_diag_ctx {
	long s_slot;
	long s_num;
};

/*
 * External reference to global connection table from tquic_main.c
 */
extern struct rhashtable tquic_conn_table;
extern const struct rhashtable_params tquic_conn_params;

/*
 * Helper to count streams in the connection's rb-tree.
 * Caller must hold conn->streams_lock.
 */
static u32 tquic_count_streams_locked(struct tquic_connection *conn)
{
	struct rb_node *node;
	u32 count = 0;

	if (!conn)
		return 0;

	for (node = rb_first(&conn->streams); node; node = rb_next(node))
		count++;

	return count;
}

/*
 * Wrapper that acquires streams_lock before counting streams.
 * The streams rb-tree is protected by conn->streams_lock, not conn->lock.
 */
static u32 tquic_count_streams(struct tquic_connection *conn)
{
	u32 count;

	if (!conn)
		return 0;

	spin_lock_bh(&conn->streams_lock);
	count = tquic_count_streams_locked(conn);
	spin_unlock_bh(&conn->streams_lock);

	return count;
}

/*
 * sk_diag_dump - Dump a single socket to skb
 */
static int sk_diag_dump(struct sock *sk, struct sk_buff *skb,
			struct netlink_callback *cb,
			const struct inet_diag_req_v2 *req,
			bool net_admin)
{
	if (!inet_diag_bc_sk(cb->data, sk))
		return 0;

	return inet_sk_diag_fill(sk, inet_csk(sk), skb, cb, req, NLM_F_MULTI,
				 net_admin);
}

/*
 * tquic_diag_dump_one - Dump a single TQUIC connection by cookie
 *
 * Look up a specific connection using the provided cookie (which is
 * the socket cookie for TQUIC).
 */
static int tquic_diag_dump_one(struct netlink_callback *cb,
			       const struct inet_diag_req_v2 *req)
{
	struct sk_buff *in_skb = cb->skb;
	struct tquic_connection *conn = NULL;
	struct rhashtable_iter iter;
	struct sk_buff *rep;
	int err = -ENOENT;
	struct net *net;
	struct sock *sk;

	net = sock_net(in_skb->sk);

	/*
	 * Iterate connections looking for matching cookie.
	 * The cookie is stored in req->id.idiag_cookie[0].
	 */
	rhashtable_walk_enter(&tquic_conn_table, &iter);
	rhashtable_walk_start(&iter);

	while ((conn = rhashtable_walk_next(&iter)) != NULL) {
		if (IS_ERR(conn)) {
			conn = NULL;
			continue;
		}

		sk = READ_ONCE(conn->sk);
		if (!sk || !net_eq(sock_net(sk), net))
			continue;

		if (sock_i_ino(sk) == req->id.idiag_cookie[0]) {
			if (!refcount_inc_not_zero(&sk->sk_refcnt)) {
				conn = NULL;
				continue;
			}
			break;
		}
		conn = NULL;
	}

	rhashtable_walk_stop(&iter);
	rhashtable_walk_exit(&iter);

	if (!conn)
		goto out_nosk;

	sk = conn->sk;
	err = -ENOMEM;
	rep = nlmsg_new(nla_total_size(sizeof(struct inet_diag_msg)) +
			inet_diag_msg_attrs_size() +
			nla_total_size(sizeof(struct tquic_info)) +
			nla_total_size(sizeof(struct inet_diag_meminfo)) + 64,
			GFP_KERNEL);
	if (!rep)
		goto out;

	err = inet_sk_diag_fill(sk, inet_csk(sk), rep, cb, req, 0,
				netlink_net_capable(in_skb, CAP_NET_ADMIN));
	if (err < 0) {
		WARN_ON(err == -EMSGSIZE);
		kfree_skb(rep);
		goto out;
	}
	err = nlmsg_unicast(net->diag_nlsk, rep, NETLINK_CB(in_skb).portid);

out:
	sock_put(sk);

out_nosk:
	return err;
}

/*
 * tquic_diag_dump - Dump all TQUIC connections
 *
 * Iterate the global connection table and dump each connection
 * that matches the filter criteria and belongs to the requesting
 * network namespace.
 *
 * Per RESEARCH.md pitfall #5: Filter by net_eq() for namespace isolation.
 */
static void tquic_diag_dump(struct sk_buff *skb, struct netlink_callback *cb,
			    const struct inet_diag_req_v2 *r)
{
	bool net_admin = netlink_net_capable(cb->skb, CAP_NET_ADMIN);
	struct tquic_diag_ctx *diag_ctx = (void *)cb->ctx;
	struct net *net = sock_net(skb->sk);
	struct tquic_connection *conn;
	struct rhashtable_iter iter;
	long num = 0;

	BUILD_BUG_ON(sizeof(cb->ctx) < sizeof(*diag_ctx));

	rhashtable_walk_enter(&tquic_conn_table, &iter);
	rhashtable_walk_start(&iter);

	while ((conn = rhashtable_walk_next(&iter)) != NULL) {
		struct inet_sock *inet;
		struct sock *sk;
		int ret = 0;

		if (IS_ERR(conn))
			continue;

		/* Skip entries until we reach our saved position */
		if (num < diag_ctx->s_num) {
			num++;
			continue;
		}

		sk = READ_ONCE(conn->sk);
		if (!sk)
			goto next;

		/* Namespace isolation - only show connections from this netns */
		if (!net_eq(sock_net(sk), net))
			goto next;

		inet = inet_sk(sk);

		/* Filter by state if specified */
		if (!(r->idiag_states & (1 << sk->sk_state)))
			goto next;

		/* Filter by family if specified */
		if (r->sdiag_family != AF_UNSPEC &&
		    sk->sk_family != r->sdiag_family)
			goto next;

		/* Filter by source port if specified */
		if (r->id.idiag_sport != inet->inet_sport &&
		    r->id.idiag_sport)
			goto next;

		/* Filter by destination port if specified */
		if (r->id.idiag_dport != inet->inet_dport &&
		    r->id.idiag_dport)
			goto next;

		/* Get reference to socket */
		if (!refcount_inc_not_zero(&sk->sk_refcnt))
			goto next;

		ret = sk_diag_dump(sk, skb, cb, r, net_admin);
		sock_put(sk);

		if (ret < 0) {
			/* Will retry from this position */
			diag_ctx->s_num = num;
			break;
		}

next:
		num++;
		cond_resched();
	}

	rhashtable_walk_stop(&iter);
	rhashtable_walk_exit(&iter);

	diag_ctx->s_num = num;
}

/*
 * tquic_diag_get_info - Fill basic TQUIC info structure
 *
 * This fills the struct tquic_info that appears in basic ss output.
 * The info includes connection state, path count, stream count, RTT,
 * and traffic statistics.
 */
static void tquic_diag_get_info(struct sock *sk, struct inet_diag_msg *r,
				void *_info)
{
	struct tquic_sock *tsk = tquic_sk(sk);
	struct tquic_info *info = _info;
	struct tquic_connection *conn;

	r->idiag_rqueue = sk_rmem_alloc_get(sk);
	r->idiag_wqueue = sk_wmem_alloc_get(sk);

	if (!info)
		return;

	memset(info, 0, sizeof(*info));

	conn = tsk->conn;
	if (!conn)
		return;

	info->state = READ_ONCE(conn->state);
	info->paths_active = conn->num_paths;
	info->streams_active = tquic_count_streams(conn);

	/* RTT from active path if available */
	{
		struct tquic_path *apath = READ_ONCE(conn->active_path);

		if (apath)
			info->rtt = apath->stats.rtt_smoothed;
	}

	/* Aggregate statistics */
	info->bytes_sent = conn->stats.tx_bytes;
	info->bytes_received = conn->stats.rx_bytes;
	info->packets_lost = conn->stats.retransmissions;
}

/*
 * tquic_diag_get_aux_size - Calculate size needed for auxiliary data
 *
 * Returns the size needed for extended attributes including CIDs
 * and per-path information.
 */
static size_t __maybe_unused tquic_diag_get_aux_size(struct sock *sk, bool net_admin)
{
	struct tquic_sock *tsk = tquic_sk(sk);
	struct tquic_connection *conn = tsk->conn;
	size_t size = 0;
	u32 num_paths;

	if (!conn)
		return 0;

	/* Version */
	size += nla_total_size(sizeof(u32));

	/* Stream count */
	size += nla_total_size(sizeof(u32));

	/*
	 * CIDs are only visible to CAP_NET_ADMIN (sensitive info).
	 * Use maximum CID length for size estimation to avoid racing
	 * with CID changes between get_aux_size and get_aux calls.
	 */
	if (net_admin) {
		/* SCID - use max possible CID length (20 per RFC 9000) */
		size += nla_total_size(TQUIC_MAX_CID_LEN);
		/* DCID */
		size += nla_total_size(TQUIC_MAX_CID_LEN);
	}

	/* Per-path info: nested attribute with path data */
	num_paths = READ_ONCE(conn->num_paths);
	if (num_paths > 0) {
		/* Nest header */
		size += nla_total_size(0);
		/* Each path: id + state + rtt + cwnd + tx + rx + lost */
		size += num_paths * (
			nla_total_size(sizeof(u32)) +   /* path_id */
			nla_total_size(sizeof(u8)) +    /* state */
			nla_total_size(sizeof(u32)) +   /* rtt */
			nla_total_size(sizeof(u32)) +   /* cwnd */
			nla_total_size(sizeof(u64)) +   /* tx_bytes */
			nla_total_size(sizeof(u64)) +   /* rx_bytes */
			nla_total_size(sizeof(u64)) +   /* lost */
			nla_total_size(0)               /* nest end per path */
		);
	}

	return size;
}

/*
 * tquic_diag_get_aux - Fill extended TQUIC attributes
 *
 * This provides the extended information shown by `ss -i`:
 * - QUIC version
 * - Connection IDs (SCID/DCID) - only for CAP_NET_ADMIN
 * - Stream count
 * - Per-path breakdown with RTT, cwnd, bytes
 *
 * Per CONTEXT.md: Connection IDs shown in full hex for packet capture
 * correlation.
 */
static int tquic_diag_get_aux(struct sock *sk, bool net_admin,
			      struct sk_buff *skb)
{
	struct tquic_sock *tsk = tquic_sk(sk);
	struct tquic_connection *conn = tsk->conn;
	struct tquic_path *path;
	struct nlattr *paths_nest;
	u32 stream_count;

	if (!conn)
		return 0;

	/* Stream count */
	stream_count = tquic_count_streams(conn);

	/*
	 * Read version, CIDs, and path list under conn->lock to get a
	 * consistent snapshot. CIDs can change during key update and
	 * the len/id pair must be read atomically.
	 */
	spin_lock_bh(&conn->lock);

	/* QUIC version */
	if (nla_put_u32(skb, TQUIC_DIAG_ATTR_VERSION, conn->version)) {
		spin_unlock_bh(&conn->lock);
		return -EMSGSIZE;
	}

	if (nla_put_u32(skb, TQUIC_DIAG_ATTR_STREAMS, stream_count)) {
		spin_unlock_bh(&conn->lock);
		return -EMSGSIZE;
	}

	/*
	 * Connection IDs - only visible to CAP_NET_ADMIN
	 * CIDs are sensitive and needed for packet capture correlation,
	 * so require admin privileges.
	 */
	if (net_admin) {
		/* Source CID - full raw bytes for hex display */
		if (conn->scid.len > 0) {
			if (nla_put(skb, TQUIC_DIAG_ATTR_SCID,
				    conn->scid.len, conn->scid.id)) {
				spin_unlock_bh(&conn->lock);
				return -EMSGSIZE;
			}
		}

		/* Destination CID */
		if (conn->dcid.len > 0) {
			if (nla_put(skb, TQUIC_DIAG_ATTR_DCID,
				    conn->dcid.len, conn->dcid.id)) {
				spin_unlock_bh(&conn->lock);
				return -EMSGSIZE;
			}
		}
	}

	/* Per-path information as nested attributes (still under lock) */
	if (!list_empty(&conn->paths)) {
		paths_nest = nla_nest_start(skb, TQUIC_DIAG_ATTR_PATHS);
		if (!paths_nest) {
			spin_unlock_bh(&conn->lock);
			return -EMSGSIZE;
		}

		list_for_each_entry(path, &conn->paths, list) {
			struct nlattr *path_nest;

			path_nest = nla_nest_start(skb, 0);
			if (!path_nest) {
				nla_nest_cancel(skb, paths_nest);
				spin_unlock_bh(&conn->lock);
				return -EMSGSIZE;
			}

			if (nla_put_u32(skb, TQUIC_DIAG_PATH_ID, path->path_id))
				goto path_error;
			if (nla_put_u8(skb, TQUIC_DIAG_PATH_STATE, path->state))
				goto path_error;
			if (nla_put_u32(skb, TQUIC_DIAG_PATH_RTT,
					path->stats.rtt_smoothed))
				goto path_error;
			if (nla_put_u32(skb, TQUIC_DIAG_PATH_CWND,
					path->stats.cwnd))
				goto path_error;
			if (nla_put_u64_64bit(skb, TQUIC_DIAG_PATH_TX_BYTES,
					      path->stats.tx_bytes,
					      TQUIC_DIAG_PATH_UNSPEC))
				goto path_error;
			if (nla_put_u64_64bit(skb, TQUIC_DIAG_PATH_RX_BYTES,
					      path->stats.rx_bytes,
					      TQUIC_DIAG_PATH_UNSPEC))
				goto path_error;
			if (nla_put_u64_64bit(skb, TQUIC_DIAG_PATH_LOST,
					      path->stats.lost_packets,
					      TQUIC_DIAG_PATH_UNSPEC))
				goto path_error;

			nla_nest_end(skb, path_nest);
			continue;

path_error:
			nla_nest_cancel(skb, path_nest);
			nla_nest_cancel(skb, paths_nest);
			spin_unlock_bh(&conn->lock);
			return -EMSGSIZE;
		}

		nla_nest_end(skb, paths_nest);
	}
	spin_unlock_bh(&conn->lock);

	return 0;
}

/*
 * TQUIC inet_diag handler
 *
 * Registered with inet_diag_register() for IPPROTO_TQUIC (263).
 *
 * .owner field: added in 5.11, removed in 6.5
 */
static const struct inet_diag_handler tquic_diag_handler = {
	.dump		 = tquic_diag_dump,
	.dump_one	 = tquic_diag_dump_one,
	.idiag_get_info  = tquic_diag_get_info,
	.idiag_get_aux   = tquic_diag_get_aux,
	.idiag_type	 = IPPROTO_TQUIC,
	.idiag_info_size = sizeof(struct tquic_info),
};

/*
 * Module initialization
 */
int __init tquic_diag_init(void)
{
	return inet_diag_register(&tquic_diag_handler);
}

void __exit tquic_diag_exit(void)
{
	inet_diag_unregister(&tquic_diag_handler);
}

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("TQUIC socket monitoring via SOCK_DIAG");
/*
 * Per RESEARCH.md pitfall #4: MODULE_ALIAS enables auto-loading
 * when ss queries IPPROTO_TQUIC.
 * Format: AF_INET (2) - IPPROTO_TQUIC (263)
 */
MODULE_ALIAS_NET_PF_PROTO_TYPE(PF_NETLINK, NETLINK_SOCK_DIAG, 2-263);

#else /* LINUX_VERSION_CODE < 5.7.0 */

/*
 * TQUIC diag (ss tool support) requires the inet_diag API that was
 * refactored in kernel 5.7 (inet_sk_diag_fill, dump, and dump_one
 * callback signatures all changed). On kernels < 5.7, diag support
 * is not available - TQUIC connections will not appear in ss output
 * but all other functionality works normally.
 */
int __init tquic_diag_init(void)
{
	return 0;
}

void __exit tquic_diag_exit(void)
{
}

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("TQUIC socket monitoring via SOCK_DIAG");

#endif /* LINUX_VERSION_CODE >= 5.7.0 */
