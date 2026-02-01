// SPDX-License-Identifier: GPL-2.0-only
/*
 * TQUIC: Netlink Interface for WAN Bonding Configuration
 *
 * Copyright (c) 2026 Linux Foundation
 *
 * Provides Generic Netlink interface for configuring TQUIC connections,
 * paths, and bonding parameters.
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/socket.h>
#include <linux/netlink.h>
#include <net/genetlink.h>
#include <net/sock.h>
#include <net/tquic.h>

/* Netlink family */
static struct genl_family tquic_genl_family;

/* Multicast groups */
static const struct genl_multicast_group tquic_mcgrps[] = {
	[TQUIC_NL_GRP_CONN] = { .name = "conn", },
	[TQUIC_NL_GRP_PATH] = { .name = "path", },
};

/* Attribute policy */
static const struct nla_policy tquic_genl_policy[TQUIC_ATTR_MAX + 1] = {
	[TQUIC_ATTR_CONN_ID]	= { .type = NLA_BINARY, .len = 20 },
	[TQUIC_ATTR_PATH_ID]	= { .type = NLA_U32 },
	[TQUIC_ATTR_LOCAL_ADDR]	= { .type = NLA_BINARY,
				    .len = sizeof(struct sockaddr_storage) },
	[TQUIC_ATTR_REMOTE_ADDR] = { .type = NLA_BINARY,
				     .len = sizeof(struct sockaddr_storage) },
	[TQUIC_ATTR_STATE]	= { .type = NLA_U8 },
	[TQUIC_ATTR_PRIORITY]	= { .type = NLA_U8 },
	[TQUIC_ATTR_WEIGHT]	= { .type = NLA_U8 },
	[TQUIC_ATTR_RTT]	= { .type = NLA_U32 },
	[TQUIC_ATTR_BANDWIDTH]	= { .type = NLA_U64 },
	[TQUIC_ATTR_CWND]	= { .type = NLA_U32 },
	[TQUIC_ATTR_BYTES_SENT]	= { .type = NLA_U64 },
	[TQUIC_ATTR_BYTES_RECV]	= { .type = NLA_U64 },
	[TQUIC_ATTR_PACKETS_LOST] = { .type = NLA_U64 },
	[TQUIC_ATTR_BOND_MODE]	= { .type = NLA_U8 },
	[TQUIC_ATTR_BOND_CONFIG] = { .type = NLA_BINARY,
				     .len = sizeof(struct tquic_bond_config) },
	[TQUIC_ATTR_PATH_INFO]	= { .type = NLA_BINARY,
				    .len = sizeof(struct tquic_path_info) },
	[TQUIC_ATTR_CONN_INFO]	= { .type = NLA_BINARY,
				    .len = sizeof(struct tquic_info) },
	[TQUIC_ATTR_BOND_STATS]	= { .type = NLA_BINARY,
				    .len = sizeof(struct tquic_bond_stats) },
	[TQUIC_ATTR_FLAGS]	= { .type = NLA_U32 },
	[TQUIC_ATTR_EVENT]	= { .type = NLA_U32 },
};

/*
 * Helper: Find connection by ID
 *
 * The connection ID is passed as a binary blob containing the CID.
 * We use the CID lookup function to find the corresponding connection.
 */
static struct tquic_connection *tquic_find_conn(struct nlattr *attr)
{
	struct tquic_cid cid;
	int len;

	if (!attr)
		return NULL;

	len = nla_len(attr);
	if (len <= 0 || len > TQUIC_MAX_CID_LEN)
		return NULL;

	memset(&cid, 0, sizeof(cid));
	cid.len = len;
	memcpy(cid.id, nla_data(attr), len);

	return tquic_conn_lookup_by_cid(&cid);
}

/*
 * TQUIC_CMD_GET_CONN - Get connection information
 */
static int tquic_nl_get_conn(struct sk_buff *skb, struct genl_info *info)
{
	struct tquic_connection *conn;
	struct tquic_info conn_info;
	struct sk_buff *msg;
	void *hdr;

	if (!info->attrs[TQUIC_ATTR_CONN_ID])
		return -EINVAL;

	conn = tquic_find_conn(info->attrs[TQUIC_ATTR_CONN_ID]);
	if (!conn)
		return -ENOENT;

	msg = nlmsg_new(NLMSG_DEFAULT_SIZE, GFP_KERNEL);
	if (!msg)
		return -ENOMEM;

	hdr = genlmsg_put(msg, info->snd_portid, info->snd_seq,
			  &tquic_genl_family, 0, TQUIC_CMD_GET_CONN);
	if (!hdr) {
		nlmsg_free(msg);
		return -EMSGSIZE;
	}

	/* Fill connection info */
	memset(&conn_info, 0, sizeof(conn_info));
	conn_info.state = conn->state;
	conn_info.version = conn->version;
	conn_info.paths_active = conn->num_paths;
	conn_info.bytes_sent = conn->stats.tx_bytes;
	conn_info.bytes_received = conn->stats.rx_bytes;
	conn_info.packets_sent = conn->stats.tx_packets;
	conn_info.packets_received = conn->stats.rx_packets;
	conn_info.packets_lost = conn->stats.lost_packets;
	conn_info.idle_timeout = conn->idle_timeout;

	if (conn->active_path) {
		conn_info.rtt = conn->active_path->stats.rtt_smoothed;
		conn_info.rtt_var = conn->active_path->stats.rtt_variance;
		conn_info.cwnd = conn->active_path->stats.cwnd;
	}

	if (nla_put(msg, TQUIC_ATTR_CONN_INFO, sizeof(conn_info), &conn_info)) {
		genlmsg_cancel(msg, hdr);
		nlmsg_free(msg);
		return -EMSGSIZE;
	}

	genlmsg_end(msg, hdr);
	return genlmsg_reply(msg, info);
}

/*
 * TQUIC_CMD_GET_PATH - Get path information
 */
static int tquic_nl_get_path(struct sk_buff *skb, struct genl_info *info)
{
	struct tquic_connection *conn;
	struct tquic_path *path;
	struct tquic_path_info path_info;
	struct sk_buff *msg;
	void *hdr;
	u32 path_id;

	if (!info->attrs[TQUIC_ATTR_CONN_ID] ||
	    !info->attrs[TQUIC_ATTR_PATH_ID])
		return -EINVAL;

	conn = tquic_find_conn(info->attrs[TQUIC_ATTR_CONN_ID]);
	if (!conn)
		return -ENOENT;

	path_id = nla_get_u32(info->attrs[TQUIC_ATTR_PATH_ID]);
	path = tquic_conn_get_path(conn, path_id);
	if (!path)
		return -ENOENT;

	msg = nlmsg_new(NLMSG_DEFAULT_SIZE, GFP_KERNEL);
	if (!msg)
		return -ENOMEM;

	hdr = genlmsg_put(msg, info->snd_portid, info->snd_seq,
			  &tquic_genl_family, 0, TQUIC_CMD_GET_PATH);
	if (!hdr) {
		nlmsg_free(msg);
		return -EMSGSIZE;
	}

	/* Fill path info */
	memset(&path_info, 0, sizeof(path_info));
	path_info.path_id = path->path_id;
	path_info.state = path->state;
	path_info.priority = path->priority;
	path_info.weight = path->weight;
	path_info.mtu = path->mtu;
	path_info.rtt = path->stats.rtt_smoothed;
	path_info.rtt_var = path->stats.rtt_variance;
	path_info.bandwidth = path->stats.bandwidth;
	path_info.cwnd = path->stats.cwnd;
	path_info.bytes_sent = path->stats.tx_bytes;
	path_info.bytes_received = path->stats.rx_bytes;
	path_info.packets_lost = path->stats.lost_packets;
	memcpy(&path_info.local_addr, &path->local_addr,
	       sizeof(struct sockaddr_storage));
	memcpy(&path_info.remote_addr, &path->remote_addr,
	       sizeof(struct sockaddr_storage));

	if (nla_put(msg, TQUIC_ATTR_PATH_INFO, sizeof(path_info), &path_info)) {
		genlmsg_cancel(msg, hdr);
		nlmsg_free(msg);
		return -EMSGSIZE;
	}

	genlmsg_end(msg, hdr);
	return genlmsg_reply(msg, info);
}

/*
 * TQUIC_CMD_ADD_PATH - Add a path to bonding
 */
static int tquic_nl_add_path(struct sk_buff *skb, struct genl_info *info)
{
	struct tquic_connection *conn;
	struct sockaddr_storage local, remote;
	int ret;

	if (!info->attrs[TQUIC_ATTR_CONN_ID] ||
	    !info->attrs[TQUIC_ATTR_LOCAL_ADDR] ||
	    !info->attrs[TQUIC_ATTR_REMOTE_ADDR])
		return -EINVAL;

	conn = tquic_find_conn(info->attrs[TQUIC_ATTR_CONN_ID]);
	if (!conn)
		return -ENOENT;

	nla_memcpy(&local, info->attrs[TQUIC_ATTR_LOCAL_ADDR], sizeof(local));
	nla_memcpy(&remote, info->attrs[TQUIC_ATTR_REMOTE_ADDR], sizeof(remote));

	ret = tquic_conn_add_path(conn, (struct sockaddr *)&local,
				  (struct sockaddr *)&remote);
	if (ret < 0)
		return ret;

	/* Optionally set priority and weight */
	if (info->attrs[TQUIC_ATTR_PRIORITY]) {
		struct tquic_path *path = tquic_conn_get_path(conn, ret);
		if (path)
			path->priority = nla_get_u8(info->attrs[TQUIC_ATTR_PRIORITY]);
	}

	if (info->attrs[TQUIC_ATTR_WEIGHT]) {
		struct tquic_path *path = tquic_conn_get_path(conn, ret);
		if (path)
			path->weight = nla_get_u8(info->attrs[TQUIC_ATTR_WEIGHT]);
	}

	/* Notify listeners about new path */
	{
		struct tquic_path *path = tquic_conn_get_path(conn, ret);
		if (path)
			tquic_nl_path_event(conn, path, TQUIC_PATH_EVENT_ADDED);
	}

	return ret;  /* Returns path ID */
}

/*
 * TQUIC_CMD_DEL_PATH - Remove a path from bonding
 */
static int tquic_nl_del_path(struct sk_buff *skb, struct genl_info *info)
{
	struct tquic_connection *conn;
	u32 path_id;

	if (!info->attrs[TQUIC_ATTR_CONN_ID] ||
	    !info->attrs[TQUIC_ATTR_PATH_ID])
		return -EINVAL;

	conn = tquic_find_conn(info->attrs[TQUIC_ATTR_CONN_ID]);
	if (!conn)
		return -ENOENT;

	path_id = nla_get_u32(info->attrs[TQUIC_ATTR_PATH_ID]);

	return tquic_conn_remove_path(conn, path_id);
}

/*
 * TQUIC_CMD_SET_PATH - Modify path parameters
 */
static int tquic_nl_set_path(struct sk_buff *skb, struct genl_info *info)
{
	struct tquic_connection *conn;
	struct tquic_path *path;
	u32 path_id;

	if (!info->attrs[TQUIC_ATTR_CONN_ID] ||
	    !info->attrs[TQUIC_ATTR_PATH_ID])
		return -EINVAL;

	conn = tquic_find_conn(info->attrs[TQUIC_ATTR_CONN_ID]);
	if (!conn)
		return -ENOENT;

	path_id = nla_get_u32(info->attrs[TQUIC_ATTR_PATH_ID]);
	path = tquic_conn_get_path(conn, path_id);
	if (!path)
		return -ENOENT;

	if (info->attrs[TQUIC_ATTR_PRIORITY])
		path->priority = nla_get_u8(info->attrs[TQUIC_ATTR_PRIORITY]);

	if (info->attrs[TQUIC_ATTR_WEIGHT])
		path->weight = nla_get_u8(info->attrs[TQUIC_ATTR_WEIGHT]);

	if (info->attrs[TQUIC_ATTR_STATE]) {
		u8 new_state = nla_get_u8(info->attrs[TQUIC_ATTR_STATE]);
		if (new_state == TQUIC_PATH_STATE_STANDBY)
			path->state = TQUIC_PATH_STANDBY;
		else if (new_state == TQUIC_PATH_STATE_ACTIVE)
			path->state = TQUIC_PATH_ACTIVE;
	}

	return 0;
}

/*
 * TQUIC_CMD_SET_BOND - Configure bonding parameters
 */
static int tquic_nl_set_bond(struct sk_buff *skb, struct genl_info *info)
{
	struct tquic_connection *conn;

	if (!info->attrs[TQUIC_ATTR_CONN_ID])
		return -EINVAL;

	conn = tquic_find_conn(info->attrs[TQUIC_ATTR_CONN_ID]);
	if (!conn)
		return -ENOENT;

	if (info->attrs[TQUIC_ATTR_BOND_MODE]) {
		u8 mode = nla_get_u8(info->attrs[TQUIC_ATTR_BOND_MODE]);
		return tquic_bond_set_mode(conn, mode);
	}

	if (info->attrs[TQUIC_ATTR_BOND_CONFIG]) {
		struct tquic_bond_config config;
		struct tquic_bond_state *bond = conn->scheduler;

		if (!bond)
			return -EINVAL;

		nla_memcpy(&config, info->attrs[TQUIC_ATTR_BOND_CONFIG],
			   sizeof(config));

		bond->mode = config.mode;
		bond->aggr_mode = config.aggr_mode;
		bond->failover_mode = config.failover_mode;
		bond->reorder_window = config.reorder_window;
	}

	return 0;
}

/*
 * TQUIC_CMD_GET_STATS - Get bonding statistics
 */
static int tquic_nl_get_stats(struct sk_buff *skb, struct genl_info *info)
{
	struct tquic_connection *conn;
	struct tquic_bond_stats stats;
	struct sk_buff *msg;
	void *hdr;
	int ret;

	if (!info->attrs[TQUIC_ATTR_CONN_ID])
		return -EINVAL;

	conn = tquic_find_conn(info->attrs[TQUIC_ATTR_CONN_ID]);
	if (!conn)
		return -ENOENT;

	ret = tquic_bond_get_stats(conn, &stats);
	if (ret)
		return ret;

	msg = nlmsg_new(NLMSG_DEFAULT_SIZE, GFP_KERNEL);
	if (!msg)
		return -ENOMEM;

	hdr = genlmsg_put(msg, info->snd_portid, info->snd_seq,
			  &tquic_genl_family, 0, TQUIC_CMD_GET_STATS);
	if (!hdr) {
		nlmsg_free(msg);
		return -EMSGSIZE;
	}

	if (nla_put(msg, TQUIC_ATTR_BOND_STATS, sizeof(stats), &stats)) {
		genlmsg_cancel(msg, hdr);
		nlmsg_free(msg);
		return -EMSGSIZE;
	}

	genlmsg_end(msg, hdr);
	return genlmsg_reply(msg, info);
}

/*
 * TQUIC_CMD_MIGRATE - Trigger path migration
 */
static int tquic_nl_migrate(struct sk_buff *skb, struct genl_info *info)
{
	struct tquic_connection *conn;
	struct tquic_path *path;
	u32 path_id;

	if (!info->attrs[TQUIC_ATTR_CONN_ID] ||
	    !info->attrs[TQUIC_ATTR_PATH_ID])
		return -EINVAL;

	conn = tquic_find_conn(info->attrs[TQUIC_ATTR_CONN_ID]);
	if (!conn)
		return -ENOENT;

	path_id = nla_get_u32(info->attrs[TQUIC_ATTR_PATH_ID]);
	path = tquic_conn_get_path(conn, path_id);
	if (!path)
		return -ENOENT;

	tquic_conn_migrate(conn, path);

	return 0;
}

/* Netlink operations */
static const struct genl_small_ops tquic_genl_ops[] = {
	{
		.cmd = TQUIC_CMD_GET_CONN,
		.validate = GENL_DONT_VALIDATE_STRICT | GENL_DONT_VALIDATE_DUMP,
		.doit = tquic_nl_get_conn,
	},
	{
		.cmd = TQUIC_CMD_GET_PATH,
		.validate = GENL_DONT_VALIDATE_STRICT | GENL_DONT_VALIDATE_DUMP,
		.doit = tquic_nl_get_path,
	},
	{
		.cmd = TQUIC_CMD_ADD_PATH,
		.validate = GENL_DONT_VALIDATE_STRICT | GENL_DONT_VALIDATE_DUMP,
		.doit = tquic_nl_add_path,
		.flags = GENL_ADMIN_PERM,
	},
	{
		.cmd = TQUIC_CMD_DEL_PATH,
		.validate = GENL_DONT_VALIDATE_STRICT | GENL_DONT_VALIDATE_DUMP,
		.doit = tquic_nl_del_path,
		.flags = GENL_ADMIN_PERM,
	},
	{
		.cmd = TQUIC_CMD_SET_PATH,
		.validate = GENL_DONT_VALIDATE_STRICT | GENL_DONT_VALIDATE_DUMP,
		.doit = tquic_nl_set_path,
		.flags = GENL_ADMIN_PERM,
	},
	{
		.cmd = TQUIC_CMD_SET_BOND,
		.validate = GENL_DONT_VALIDATE_STRICT | GENL_DONT_VALIDATE_DUMP,
		.doit = tquic_nl_set_bond,
		.flags = GENL_ADMIN_PERM,
	},
	{
		.cmd = TQUIC_CMD_GET_STATS,
		.validate = GENL_DONT_VALIDATE_STRICT | GENL_DONT_VALIDATE_DUMP,
		.doit = tquic_nl_get_stats,
	},
	{
		.cmd = TQUIC_CMD_MIGRATE,
		.validate = GENL_DONT_VALIDATE_STRICT | GENL_DONT_VALIDATE_DUMP,
		.doit = tquic_nl_migrate,
		.flags = GENL_ADMIN_PERM,
	},
};

/* Netlink family definition */
static struct genl_family tquic_genl_family __ro_after_init = {
	.name = TQUIC_GENL_NAME,
	.version = TQUIC_GENL_VERSION,
	.maxattr = TQUIC_ATTR_MAX,
	.policy = tquic_genl_policy,
	.module = THIS_MODULE,
	.small_ops = tquic_genl_ops,
	.n_small_ops = ARRAY_SIZE(tquic_genl_ops),
	.mcgrps = tquic_mcgrps,
	.n_mcgrps = ARRAY_SIZE(tquic_mcgrps),
};

/*
 * Send path event notification
 */
int tquic_nl_path_event(struct tquic_connection *conn,
			struct tquic_path *path,
			enum tquic_path_event event)
{
	struct sk_buff *msg;
	void *hdr;

	msg = nlmsg_new(NLMSG_DEFAULT_SIZE, GFP_ATOMIC);
	if (!msg)
		return -ENOMEM;

	hdr = genlmsg_put(msg, 0, 0, &tquic_genl_family, 0, TQUIC_CMD_PATH_EVENT);
	if (!hdr) {
		nlmsg_free(msg);
		return -EMSGSIZE;
	}

	if (nla_put(msg, TQUIC_ATTR_CONN_ID, conn->scid.len, conn->scid.id) ||
	    nla_put_u32(msg, TQUIC_ATTR_PATH_ID, path->path_id) ||
	    nla_put_u32(msg, TQUIC_ATTR_EVENT, event)) {
		genlmsg_cancel(msg, hdr);
		nlmsg_free(msg);
		return -EMSGSIZE;
	}

	genlmsg_end(msg, hdr);

	return genlmsg_multicast(&tquic_genl_family, msg, 0,
				 TQUIC_NL_GRP_PATH, GFP_ATOMIC);
}
EXPORT_SYMBOL_GPL(tquic_nl_path_event);

int __init tquic_netlink_init(void)
{
	return genl_register_family(&tquic_genl_family);
}

void __exit tquic_netlink_exit(void)
{
	genl_unregister_family(&tquic_genl_family);
}
