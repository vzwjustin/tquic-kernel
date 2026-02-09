// SPDX-License-Identifier: GPL-2.0-only
/*
 * TQUIC Path Manager Netlink Interface
 *
 * Copyright (c) 2026 Linux Foundation
 *
 * Implements the PM-specific genetlink family with multicast event
 * notifications, following the MPTCP pm_netlink.c pattern.
 */

#include <linux/kernel.h>
#include <linux/module.h>
#include <net/genetlink.h>
#include <net/sock.h>
#include <net/tquic.h>

#include "../tquic_compat.h"
#include <net/tquic_pm.h>
#include <uapi/linux/tquic_pm.h>

/* Multicast group offsets */
#define TQUIC_PM_CMD_GRP_OFFSET  0
#define TQUIC_PM_EV_GRP_OFFSET   1

/* Rate limiting for events */
static DEFINE_RATELIMIT_STATE(tquic_pm_event_rl, HZ, 100);

/* Forward declaration - defined later in this file */
static struct genl_family tquic_pm_genl_family;

/*
 * Multicast groups for PM netlink family
 * Following MPTCP pattern: events group requires CAP_NET_ADMIN
 */
static const struct genl_multicast_group tquic_pm_mcgrps[] = {
	[TQUIC_PM_CMD_GRP_OFFSET] = { .name = TQUIC_PM_CMD_GRP_NAME },
	[TQUIC_PM_EV_GRP_OFFSET]  = { .name = TQUIC_PM_EV_GRP_NAME,
				      TQUIC_GENL_MCAST_FLAGS(GENL_MCAST_CAP_NET_ADMIN) },
};

/*
 * Netlink attribute policies
 */

/* Policy for nested address attributes */
static const struct nla_policy tquic_pm_address_nl_policy[TQUIC_PM_ADDR_ATTR_MAX + 1] = {
	[TQUIC_PM_ADDR_ATTR_FAMILY]	= { .type = NLA_U16 },
	[TQUIC_PM_ADDR_ATTR_ID]		= { .type = NLA_U8 },
	[TQUIC_PM_ADDR_ATTR_ADDR4]	= { .type = NLA_U32 },
	[TQUIC_PM_ADDR_ATTR_ADDR6]	= NLA_POLICY_EXACT_LEN(sizeof(struct in6_addr)),
	[TQUIC_PM_ADDR_ATTR_PORT]	= { .type = NLA_U16 },
	[TQUIC_PM_ADDR_ATTR_IF_IDX]	= { .type = NLA_S32 },
};

/* Main policy for PM commands */
static const struct nla_policy tquic_pm_policy[TQUIC_PM_ATTR_MAX + 1] = {
	[TQUIC_PM_ATTR_TOKEN]		= { .type = NLA_U32 },
	[TQUIC_PM_ATTR_PATH_ID]		= { .type = NLA_U8 },
	[TQUIC_PM_ATTR_FAMILY]		= { .type = NLA_U16 },
	[TQUIC_PM_ATTR_SADDR4]		= { .type = NLA_U32 },
	[TQUIC_PM_ATTR_SADDR6]		= NLA_POLICY_EXACT_LEN(sizeof(struct in6_addr)),
	[TQUIC_PM_ATTR_DADDR4]		= { .type = NLA_U32 },
	[TQUIC_PM_ATTR_DADDR6]		= NLA_POLICY_EXACT_LEN(sizeof(struct in6_addr)),
	[TQUIC_PM_ATTR_SPORT]		= { .type = NLA_U16 },
	[TQUIC_PM_ATTR_DPORT]		= { .type = NLA_U16 },
	[TQUIC_PM_ATTR_FLAGS]		= { .type = NLA_U32 },
	[TQUIC_PM_ATTR_STATE]		= { .type = NLA_U8 },
	[TQUIC_PM_ATTR_IF_IDX]		= { .type = NLA_S32 },
	[TQUIC_PM_ATTR_PRIORITY]	= { .type = NLA_U8 },
	[TQUIC_PM_ATTR_WEIGHT]		= { .type = NLA_U8 },
	[TQUIC_PM_ATTR_MAX_PATHS]	= { .type = NLA_U8 },
	[TQUIC_PM_ATTR_SUBFLOWS]	= { .type = NLA_U8 },
	[TQUIC_PM_ATTR_RTT]		= { .type = NLA_U32 },
	[TQUIC_PM_ATTR_RTTVAR]		= { .type = NLA_U32 },
	[TQUIC_PM_ATTR_MIN_RTT]		= { .type = NLA_U32 },
	[TQUIC_PM_ATTR_BANDWIDTH]	= { .type = NLA_U64 },
	[TQUIC_PM_ATTR_LOSS_RATE]	= { .type = NLA_U32 },
	[TQUIC_PM_ATTR_ERROR]		= { .type = NLA_STRING, .len = 128 },
};

/*
 * Helper: Parse nested address attributes
 *
 * Following MPTCP mptcp_pm_parse_addr pattern.
 * Sets extended ACK error messages for each failure.
 */
static int __maybe_unused tquic_pm_parse_addr(struct nlattr *attr, struct genl_info *info,
					      struct sockaddr_storage *addr, int *if_idx)
{
	struct nlattr *tb[TQUIC_PM_ADDR_ATTR_MAX + 1];
	u16 family;
	int err;

	if (!attr) {
		GENL_SET_ERR_MSG(info, "missing address info");
		return -EINVAL;
	}

	err = nla_parse_nested(tb, TQUIC_PM_ADDR_ATTR_MAX, attr,
			       tquic_pm_address_nl_policy, info->extack);
	if (err) {
		GENL_SET_ERR_MSG(info, "failed to parse nested address");
		return err;
	}

	if (!tb[TQUIC_PM_ADDR_ATTR_FAMILY]) {
		GENL_SET_ERR_MSG(info, "missing address family");
		return -EINVAL;
	}

	family = nla_get_u16(tb[TQUIC_PM_ADDR_ATTR_FAMILY]);

	if (family == AF_INET) {
		struct sockaddr_in *sin = (struct sockaddr_in *)addr;

		if (!tb[TQUIC_PM_ADDR_ATTR_ADDR4]) {
			GENL_SET_ERR_MSG(info, "missing IPv4 address");
			return -EINVAL;
		}

		memset(sin, 0, sizeof(*sin));
		sin->sin_family = AF_INET;
		sin->sin_addr.s_addr = nla_get_be32(tb[TQUIC_PM_ADDR_ATTR_ADDR4]);

		if (tb[TQUIC_PM_ADDR_ATTR_PORT])
			sin->sin_port = htons(nla_get_u16(tb[TQUIC_PM_ADDR_ATTR_PORT]));

	} else if (family == AF_INET6) {
		struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)addr;

		if (!tb[TQUIC_PM_ADDR_ATTR_ADDR6]) {
			GENL_SET_ERR_MSG(info, "missing IPv6 address");
			return -EINVAL;
		}

		memset(sin6, 0, sizeof(*sin6));
		sin6->sin6_family = AF_INET6;
		sin6->sin6_addr = nla_get_in6_addr(tb[TQUIC_PM_ADDR_ATTR_ADDR6]);

		if (tb[TQUIC_PM_ADDR_ATTR_PORT])
			sin6->sin6_port = htons(nla_get_u16(tb[TQUIC_PM_ADDR_ATTR_PORT]));

	} else {
		GENL_SET_ERR_MSG(info, "unknown address family");
		return -EINVAL;
	}

	if (if_idx && tb[TQUIC_PM_ADDR_ATTR_IF_IDX])
		*if_idx = nla_get_s32(tb[TQUIC_PM_ADDR_ATTR_IF_IDX]);

	return 0;
}

/*
 * Helper: Fill nested address attributes
 *
 * Following MPTCP mptcp_nl_fill_addr pattern.
 */
static int __maybe_unused tquic_pm_fill_addr(struct sk_buff *skb, int attr_type,
					     struct sockaddr_storage *addr, int if_idx)
{
	struct nlattr *nest;
	int err;

	nest = nla_nest_start(skb, attr_type);
	if (!nest)
		return -EMSGSIZE;

	if (addr->ss_family == AF_INET) {
		struct sockaddr_in *sin = (struct sockaddr_in *)addr;

		err = nla_put_u16(skb, TQUIC_PM_ADDR_ATTR_FAMILY, AF_INET);
		if (err)
			goto nla_put_failure;

		err = nla_put_be32(skb, TQUIC_PM_ADDR_ATTR_ADDR4, sin->sin_addr.s_addr);
		if (err)
			goto nla_put_failure;

		if (sin->sin_port) {
			err = nla_put_u16(skb, TQUIC_PM_ADDR_ATTR_PORT,
					  ntohs(sin->sin_port));
			if (err)
				goto nla_put_failure;
		}

	} else if (addr->ss_family == AF_INET6) {
		struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)addr;

		err = nla_put_u16(skb, TQUIC_PM_ADDR_ATTR_FAMILY, AF_INET6);
		if (err)
			goto nla_put_failure;

		err = nla_put_in6_addr(skb, TQUIC_PM_ADDR_ATTR_ADDR6, &sin6->sin6_addr);
		if (err)
			goto nla_put_failure;

		if (sin6->sin6_port) {
			err = nla_put_u16(skb, TQUIC_PM_ADDR_ATTR_PORT,
					  ntohs(sin6->sin6_port));
			if (err)
				goto nla_put_failure;
		}
	}

	if (if_idx) {
		err = nla_put_s32(skb, TQUIC_PM_ADDR_ATTR_IF_IDX, if_idx);
		if (err)
			goto nla_put_failure;
	}

	nla_nest_end(skb, nest);
	return 0;

nla_put_failure:
	nla_nest_cancel(skb, nest);
	return -EMSGSIZE;
}

/*
 * Command: TQUIC_PM_CMD_ADD_PATH
 *
 * Add a new path to a connection (userspace PM control).
 */
static int tquic_pm_nl_add_path(struct sk_buff *skb, struct genl_info *info)
{
	struct sockaddr_storage local_addr, remote_addr;
	struct tquic_connection *conn;
	u32 token;
	int if_idx = 0;
	int err;

	/* Require CAP_NET_ADMIN */
	if (!netlink_capable(skb, CAP_NET_ADMIN)) {
		GENL_SET_ERR_MSG(info, "operation requires CAP_NET_ADMIN");
		return -EPERM;
	}

	if (!info->attrs[TQUIC_PM_ATTR_TOKEN]) {
		GENL_SET_ERR_MSG(info, "missing connection token");
		return -EINVAL;
	}

	token = nla_get_u32(info->attrs[TQUIC_PM_ATTR_TOKEN]);

	/* Parse local address from SADDR attributes */
	if (info->attrs[TQUIC_PM_ATTR_FAMILY]) {
		u16 family = nla_get_u16(info->attrs[TQUIC_PM_ATTR_FAMILY]);

		if (family == AF_INET) {
			struct sockaddr_in *sin = (struct sockaddr_in *)&local_addr;

			if (!info->attrs[TQUIC_PM_ATTR_SADDR4]) {
				GENL_SET_ERR_MSG(info, "missing source IPv4 address");
				return -EINVAL;
			}

			memset(sin, 0, sizeof(*sin));
			sin->sin_family = AF_INET;
			sin->sin_addr.s_addr = nla_get_be32(info->attrs[TQUIC_PM_ATTR_SADDR4]);

			if (info->attrs[TQUIC_PM_ATTR_SPORT])
				sin->sin_port = htons(nla_get_u16(info->attrs[TQUIC_PM_ATTR_SPORT]));

		} else if (family == AF_INET6) {
			struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)&local_addr;

			if (!info->attrs[TQUIC_PM_ATTR_SADDR6]) {
				GENL_SET_ERR_MSG(info, "missing source IPv6 address");
				return -EINVAL;
			}

			memset(sin6, 0, sizeof(*sin6));
			sin6->sin6_family = AF_INET6;
			sin6->sin6_addr = nla_get_in6_addr(info->attrs[TQUIC_PM_ATTR_SADDR6]);

			if (info->attrs[TQUIC_PM_ATTR_SPORT])
				sin6->sin6_port = htons(nla_get_u16(info->attrs[TQUIC_PM_ATTR_SPORT]));

		} else {
			GENL_SET_ERR_MSG(info, "unsupported address family");
			return -EINVAL;
		}
	} else {
		GENL_SET_ERR_MSG(info, "missing address family");
		return -EINVAL;
	}

	/* Parse remote address from DADDR attributes */
	if (info->attrs[TQUIC_PM_ATTR_FAMILY]) {
		u16 family = nla_get_u16(info->attrs[TQUIC_PM_ATTR_FAMILY]);

		if (family == AF_INET) {
			struct sockaddr_in *sin = (struct sockaddr_in *)&remote_addr;

			if (!info->attrs[TQUIC_PM_ATTR_DADDR4]) {
				GENL_SET_ERR_MSG(info, "missing destination IPv4 address");
				return -EINVAL;
			}

			memset(sin, 0, sizeof(*sin));
			sin->sin_family = AF_INET;
			sin->sin_addr.s_addr = nla_get_be32(info->attrs[TQUIC_PM_ATTR_DADDR4]);

			if (info->attrs[TQUIC_PM_ATTR_DPORT])
				sin->sin_port = htons(nla_get_u16(info->attrs[TQUIC_PM_ATTR_DPORT]));

		} else if (family == AF_INET6) {
			struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)&remote_addr;

			if (!info->attrs[TQUIC_PM_ATTR_DADDR6]) {
				GENL_SET_ERR_MSG(info, "missing destination IPv6 address");
				return -EINVAL;
			}

			memset(sin6, 0, sizeof(*sin6));
			sin6->sin6_family = AF_INET6;
			sin6->sin6_addr = nla_get_in6_addr(info->attrs[TQUIC_PM_ATTR_DADDR6]);

			if (info->attrs[TQUIC_PM_ATTR_DPORT])
				sin6->sin6_port = htons(nla_get_u16(info->attrs[TQUIC_PM_ATTR_DPORT]));
		}
	}

	if (info->attrs[TQUIC_PM_ATTR_IF_IDX])
		if_idx = nla_get_s32(info->attrs[TQUIC_PM_ATTR_IF_IDX]);

	/* Find connection by token */
	conn = tquic_conn_lookup_by_token(genl_info_net(info), token);
	if (!conn) {
		GENL_SET_ERR_MSG(info, "connection not found");
		return -ENOENT;
	}

	/* Add path via connection API */
	err = tquic_conn_add_path(conn, (struct sockaddr *)&local_addr,
				  (struct sockaddr *)&remote_addr);
	if (err) {
		GENL_SET_ERR_MSG(info, "failed to add path");
		return err;
	}

	return 0;
}

/*
 * Command: TQUIC_PM_CMD_DEL_PATH
 *
 * Remove a path from a connection.
 */
static int tquic_pm_nl_del_path(struct sk_buff *skb, struct genl_info *info)
{
	struct tquic_connection *conn;
	u32 token;
	u8 path_id;
	int err;

	/* Require CAP_NET_ADMIN */
	if (!netlink_capable(skb, CAP_NET_ADMIN)) {
		GENL_SET_ERR_MSG(info, "operation requires CAP_NET_ADMIN");
		return -EPERM;
	}

	if (!info->attrs[TQUIC_PM_ATTR_TOKEN]) {
		GENL_SET_ERR_MSG(info, "missing connection token");
		return -EINVAL;
	}

	if (!info->attrs[TQUIC_PM_ATTR_PATH_ID]) {
		GENL_SET_ERR_MSG(info, "missing path ID");
		return -EINVAL;
	}

	token = nla_get_u32(info->attrs[TQUIC_PM_ATTR_TOKEN]);
	path_id = nla_get_u8(info->attrs[TQUIC_PM_ATTR_PATH_ID]);

	/* Find connection */
	conn = tquic_conn_lookup_by_token(genl_info_net(info), token);
	if (!conn) {
		GENL_SET_ERR_MSG(info, "connection not found");
		return -ENOENT;
	}

	/* Remove path */
	err = tquic_conn_remove_path(conn, path_id);
	if (err) {
		GENL_SET_ERR_MSG(info, "failed to remove path");
		return err;
	}

	return 0;
}

/*
 * Command: TQUIC_PM_CMD_GET_PATH
 *
 * Get path information with metrics.
 */
static int tquic_pm_nl_get_path(struct sk_buff *skb, struct genl_info *info)
{
	struct tquic_connection *conn;
	struct tquic_path *path;
	struct sk_buff *msg;
	void *hdr;
	u32 token;
	u8 path_id;
	int err;

	if (!info->attrs[TQUIC_PM_ATTR_TOKEN]) {
		GENL_SET_ERR_MSG(info, "missing connection token");
		return -EINVAL;
	}

	if (!info->attrs[TQUIC_PM_ATTR_PATH_ID]) {
		GENL_SET_ERR_MSG(info, "missing path ID");
		return -EINVAL;
	}

	token = nla_get_u32(info->attrs[TQUIC_PM_ATTR_TOKEN]);
	path_id = nla_get_u8(info->attrs[TQUIC_PM_ATTR_PATH_ID]);

	/* Find connection */
	conn = tquic_conn_lookup_by_token(genl_info_net(info), token);
	if (!conn) {
		GENL_SET_ERR_MSG(info, "connection not found");
		return -ENOENT;
	}

	/* Find path */
	path = tquic_conn_get_path(conn, path_id);
	if (!path) {
		GENL_SET_ERR_MSG(info, "path not found");
		return -ENOENT;
	}

	/* Build response */
	msg = nlmsg_new(NLMSG_DEFAULT_SIZE, GFP_KERNEL);
	if (!msg)
		return -ENOMEM;

	hdr = genlmsg_put_reply(msg, info, &tquic_pm_genl_family, 0,
				TQUIC_PM_CMD_GET_PATH);
	if (!hdr) {
		err = -EMSGSIZE;
		goto free_msg;
	}

	/* Add path metrics */
	if (nla_put_u8(msg, TQUIC_PM_ATTR_PATH_ID, path->path_id) ||
	    nla_put_u8(msg, TQUIC_PM_ATTR_STATE, path->state) ||
	    nla_put_u32(msg, TQUIC_PM_ATTR_RTT, path->stats.rtt_smoothed) ||
	    nla_put_u32(msg, TQUIC_PM_ATTR_RTTVAR, path->stats.rtt_variance) ||
	    nla_put_u32(msg, TQUIC_PM_ATTR_MIN_RTT, path->stats.rtt_min) ||
	    nla_put_u64_64bit(msg, TQUIC_PM_ATTR_BANDWIDTH,
			      path->stats.bandwidth, TQUIC_PM_ATTR_UNSPEC)) {
		err = -EMSGSIZE;
		goto cancel_msg;
	}

	genlmsg_end(msg, hdr);
	return genlmsg_reply(msg, info);

cancel_msg:
	genlmsg_cancel(msg, hdr);
free_msg:
	nlmsg_free(msg);
	return err;
}

/*
 * Command: TQUIC_PM_CMD_SET_FLAGS
 *
 * Update path flags (backup, priority).
 */
static int tquic_pm_nl_set_flags(struct sk_buff *skb, struct genl_info *info)
{
	struct tquic_connection *conn;
	struct tquic_path *path;
	u32 token, flags;
	u8 path_id;

	/* Require CAP_NET_ADMIN */
	if (!netlink_capable(skb, CAP_NET_ADMIN)) {
		GENL_SET_ERR_MSG(info, "operation requires CAP_NET_ADMIN");
		return -EPERM;
	}

	if (!info->attrs[TQUIC_PM_ATTR_TOKEN]) {
		GENL_SET_ERR_MSG(info, "missing connection token");
		return -EINVAL;
	}

	if (!info->attrs[TQUIC_PM_ATTR_PATH_ID]) {
		GENL_SET_ERR_MSG(info, "missing path ID");
		return -EINVAL;
	}

	if (!info->attrs[TQUIC_PM_ATTR_FLAGS]) {
		GENL_SET_ERR_MSG(info, "missing flags");
		return -EINVAL;
	}

	token = nla_get_u32(info->attrs[TQUIC_PM_ATTR_TOKEN]);
	path_id = nla_get_u8(info->attrs[TQUIC_PM_ATTR_PATH_ID]);
	flags = nla_get_u32(info->attrs[TQUIC_PM_ATTR_FLAGS]);

	/* Find connection and path */
	conn = tquic_conn_lookup_by_token(genl_info_net(info), token);
	if (!conn) {
		GENL_SET_ERR_MSG(info, "connection not found");
		return -ENOENT;
	}

	path = tquic_conn_get_path(conn, path_id);
	if (!path) {
		GENL_SET_ERR_MSG(info, "path not found");
		return -ENOENT;
	}

	/* Update flags */
	path->flags = flags;

	/* Update priority if provided */
	if (info->attrs[TQUIC_PM_ATTR_PRIORITY])
		path->priority = nla_get_u8(info->attrs[TQUIC_PM_ATTR_PRIORITY]);

	return 0;
}

/*
 * Command: TQUIC_PM_CMD_FLUSH_PATHS
 *
 * Remove all paths from a connection.
 */
static int tquic_pm_nl_flush_paths(struct sk_buff *skb, struct genl_info *info)
{
	struct tquic_connection *conn;
	u32 token;

	/* Require CAP_NET_ADMIN */
	if (!netlink_capable(skb, CAP_NET_ADMIN)) {
		GENL_SET_ERR_MSG(info, "operation requires CAP_NET_ADMIN");
		return -EPERM;
	}

	if (!info->attrs[TQUIC_PM_ATTR_TOKEN]) {
		GENL_SET_ERR_MSG(info, "missing connection token");
		return -EINVAL;
	}

	token = nla_get_u32(info->attrs[TQUIC_PM_ATTR_TOKEN]);

	/* Find connection */
	conn = tquic_conn_lookup_by_token(genl_info_net(info), token);
	if (!conn) {
		GENL_SET_ERR_MSG(info, "connection not found");
		return -ENOENT;
	}

	/* Flush all paths */
	tquic_conn_flush_paths(conn);

	return 0;
}

/*
 * Event sending: Multicast path events to userspace
 *
 * Following MPTCP mptcp_nl_mcast_send pattern.
 * Rate-limited via __ratelimit() using pernet event_rate_limit.
 */
int tquic_pm_nl_send_event(struct net *net, struct tquic_connection *conn,
			   struct tquic_path *path, int event_type)
{
	struct tquic_pm_pernet *pernet;
	struct sk_buff *skb;
	void *hdr;
	int err;

	/* Rate limit events */
	if (!__ratelimit(&tquic_pm_event_rl))
		return 0;

	/* Check pernet event rate limit */
	pernet = tquic_pm_get_pernet(net);
	if (!pernet || pernet->event_rate_limit == 0)
		return 0;

	/* Allocate message */
	skb = nlmsg_new(NLMSG_DEFAULT_SIZE, GFP_ATOMIC);
	if (!skb)
		return -ENOMEM;

	hdr = genlmsg_put(skb, 0, 0, &tquic_pm_genl_family, 0, event_type);
	if (!hdr) {
		err = -EMSGSIZE;
		goto free_skb;
	}

	/* Add event attributes */
	if (nla_put_u32(skb, TQUIC_PM_ATTR_TOKEN, conn->token) ||
	    nla_put_u8(skb, TQUIC_PM_ATTR_PATH_ID, path->path_id) ||
	    nla_put_u8(skb, TQUIC_PM_ATTR_STATE, path->state)) {
		err = -EMSGSIZE;
		goto cancel_msg;
	}

	/* Add path metrics if available */
	if (path->stats.rtt_smoothed &&
	    (nla_put_u32(skb, TQUIC_PM_ATTR_RTT, path->stats.rtt_smoothed) ||
	     nla_put_u32(skb, TQUIC_PM_ATTR_RTTVAR, path->stats.rtt_variance) ||
	     nla_put_u32(skb, TQUIC_PM_ATTR_MIN_RTT, path->stats.rtt_min))) {
		err = -EMSGSIZE;
		goto cancel_msg;
	}

	if (path->stats.bandwidth &&
	    nla_put_u64_64bit(skb, TQUIC_PM_ATTR_BANDWIDTH,
			      path->stats.bandwidth, TQUIC_PM_ATTR_UNSPEC)) {
		err = -EMSGSIZE;
		goto cancel_msg;
	}

	genlmsg_end(skb, hdr);

	/* Multicast to events group */
	genlmsg_multicast_netns(&tquic_pm_genl_family, net, skb, 0,
				TQUIC_PM_EV_GRP_OFFSET, GFP_ATOMIC);

	return 0;

cancel_msg:
	genlmsg_cancel(skb, hdr);
free_skb:
	nlmsg_free(skb);
	return err;
}
EXPORT_SYMBOL_GPL(tquic_pm_nl_send_event);

/*
 * Genetlink operations
 */
static const struct genl_ops tquic_pm_nl_ops[] = {
	{
		.cmd		= TQUIC_PM_CMD_ADD_PATH,
		.doit		= tquic_pm_nl_add_path,
		.flags		= GENL_ADMIN_PERM,
	},
	{
		.cmd		= TQUIC_PM_CMD_DEL_PATH,
		.doit		= tquic_pm_nl_del_path,
		.flags		= GENL_ADMIN_PERM,
	},
	{
		.cmd		= TQUIC_PM_CMD_GET_PATH,
		.doit		= tquic_pm_nl_get_path,
		.flags		= GENL_ADMIN_PERM,
	},
	{
		.cmd		= TQUIC_PM_CMD_SET_FLAGS,
		.doit		= tquic_pm_nl_set_flags,
		.flags		= GENL_ADMIN_PERM,
	},
	{
		.cmd		= TQUIC_PM_CMD_FLUSH_PATHS,
		.doit		= tquic_pm_nl_flush_paths,
		.flags		= GENL_ADMIN_PERM,
	},
};

/*
 * PM Genetlink family
 */
static struct genl_family tquic_pm_genl_family __ro_after_init = {
	.name		= TQUIC_PM_NAME,
	.version	= TQUIC_PM_VER,
	.maxattr	= TQUIC_PM_ATTR_MAX,
	.policy		= tquic_pm_policy,
	.netnsok	= true,
	.module		= THIS_MODULE,
	.ops		= tquic_pm_nl_ops,
	.n_ops		= ARRAY_SIZE(tquic_pm_nl_ops),
	TQUIC_GENL_RESV_START_OP(TQUIC_PM_CMD_REMOVE + 1)
	.mcgrps		= tquic_pm_mcgrps,
	.n_mcgrps	= ARRAY_SIZE(tquic_pm_mcgrps),
};

/*
 * Module initialization and cleanup
 */
int __init tquic_pm_nl_init(void)
{
	int ret;

	ret = genl_register_family(&tquic_pm_genl_family);
	if (ret) {
		pr_err("TQUIC PM: Failed to register genetlink family: %d\n", ret);
		return ret;
	}

	pr_info("TQUIC PM: Netlink interface initialized\n");
	return 0;
}

void __exit tquic_pm_nl_exit(void)
{
	genl_unregister_family(&tquic_pm_genl_family);
	pr_info("TQUIC PM: Netlink interface cleaned up\n");
}
