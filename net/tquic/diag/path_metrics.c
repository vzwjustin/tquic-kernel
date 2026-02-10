// SPDX-License-Identifier: GPL-2.0-only
/*
 * TQUIC Path-Specific Metrics Export
 *
 * Copyright (c) 2026 Linux Foundation
 *
 * This file implements path-specific metrics export for TQUIC connections:
 *   - Per-path metrics structure with RTT, bandwidth, congestion, and loss data
 *   - Netlink interface for metrics retrieval and subscription
 *   - Procfs interface at /proc/net/tquic/paths
 *   - Extended ss (sock_diag) integration
 *   - Continuous metrics streaming via netlink multicast
 *   - Path comparison helper for scheduler debugging
 */

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/socket.h>
#include <linux/netlink.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/rhashtable.h>
#include <linux/spinlock.h>
#include <linux/ktime.h>
#include <linux/timer.h>
#include <linux/workqueue.h>
#include <net/genetlink.h>
#include <net/sock.h>
#include <net/net_namespace.h>

/* Cap for netlink allocations to prevent unbounded memory use */
#ifndef TQUIC_MAX_PATHS
#define TQUIC_MAX_PATHS		16
#endif
#include <net/tquic.h>
#include "../tquic_compat.h"
#include <uapi/linux/tquic.h>
#include <uapi/linux/tquic_diag.h>

/*
 * =============================================================================
 * Per-Path Metrics Structure
 * =============================================================================
 */

/**
 * struct tquic_path_metrics - Comprehensive per-path metrics
 * @path_id: Unique path identifier
 *
 * RTT metrics (all in microseconds):
 * @min_rtt: Minimum observed RTT
 * @smoothed_rtt: Exponentially smoothed RTT
 * @rtt_variance: RTT variance for RTO calculation
 * @latest_rtt: Most recent RTT sample
 *
 * Bandwidth metrics (bytes/sec):
 * @bandwidth_estimate: Current bandwidth estimate
 * @delivery_rate: Observed delivery rate (bytes/sec)
 *
 * Congestion metrics:
 * @cwnd: Current congestion window (bytes)
 * @bytes_in_flight: Bytes currently in flight
 * @ssthresh: Slow start threshold (bytes)
 *
 * Loss metrics:
 * @packets_sent: Total packets sent on this path
 * @packets_received: Total packets received
 * @packets_lost: Total packets lost
 * @bytes_sent: Total bytes sent on this path
 * @bytes_received: Total bytes received
 * @bytes_lost: Total bytes lost
 *
 * ECN metrics:
 * @ect0_received: ECT(0) marked packets received
 * @ect1_received: ECT(1) marked packets received
 * @ce_received: CE (Congestion Experienced) marked packets received
 *
 * Path state:
 * @state: Current path state (enum tquic_path_state)
 * @validation_state: Validation state (pending, validated, etc.)
 * @is_active: True if this is the currently active path
 *
 * Timestamps:
 * @last_activity_us: Timestamp of last activity (microseconds since epoch)
 * @creation_time_us: When this path was created
 */
struct tquic_path_metrics {
	u32 path_id;

	/* RTT metrics (microseconds) */
	u64 min_rtt;
	u64 smoothed_rtt;
	u64 rtt_variance;
	u64 latest_rtt;

	/* Bandwidth metrics (bytes/sec) */
	u64 bandwidth_estimate;
	u64 delivery_rate;

	/* Congestion metrics */
	u64 cwnd;
	u64 bytes_in_flight;
	u64 ssthresh;

	/* Loss metrics */
	u64 packets_sent;
	u64 packets_received;
	u64 packets_lost;
	u64 bytes_sent;
	u64 bytes_received;
	u64 bytes_lost;

	/* ECN metrics */
	u64 ect0_received;
	u64 ect1_received;
	u64 ce_received;

	/* Path state */
	u8 state;
	u8 validation_state;
	bool is_active;

	/* Timestamps */
	u64 last_activity_us;
	u64 creation_time_us;
};

/**
 * struct tquic_diag_path_info - Extended path info for sock_diag
 * @path_id: Path identifier
 * @state: Path state
 * @rtt_us: Smoothed RTT in microseconds
 * @cwnd: Congestion window in bytes
 * @bytes_sent: Total bytes sent
 * @bytes_recv: Total bytes received
 */
struct tquic_diag_path_info {
	u32 path_id;
	u32 state;
	u32 rtt_us;
	u32 cwnd;
	u64 bytes_sent;
	u64 bytes_recv;
};

/*
 * =============================================================================
 * Netlink Interface for Path Metrics
 * =============================================================================
 */

/* Netlink commands for path metrics */
enum tquic_metrics_nl_commands {
	TQUIC_NL_CMD_GET_CONN_INFO = 0x10,
	TQUIC_NL_CMD_GET_PATH_METRICS,
	TQUIC_NL_CMD_GET_ALL_PATHS,
	TQUIC_NL_CMD_SUBSCRIBE_EVENTS,
	TQUIC_NL_CMD_METRICS_EVENT,	/* Multicast event notification */
	__TQUIC_NL_CMD_METRICS_MAX,
};
#define TQUIC_NL_CMD_METRICS_MAX (__TQUIC_NL_CMD_METRICS_MAX - 1)

/* Netlink attributes for path metrics */
enum tquic_metrics_nl_attrs {
	TQUIC_METRICS_ATTR_UNSPEC,
	TQUIC_METRICS_ATTR_CONN_ID,		/* Connection ID (binary) */
	TQUIC_METRICS_ATTR_CONN_TOKEN,		/* Connection token (u32) */
	TQUIC_METRICS_ATTR_PATH_ID,		/* Path ID (u32) */
	TQUIC_METRICS_ATTR_MIN_RTT,		/* Minimum RTT (u64, us) */
	TQUIC_METRICS_ATTR_SMOOTHED_RTT,	/* Smoothed RTT (u64, us) */
	TQUIC_METRICS_ATTR_RTT_VARIANCE,	/* RTT variance (u64, us) */
	TQUIC_METRICS_ATTR_LATEST_RTT,		/* Latest RTT (u64, us) */
	TQUIC_METRICS_ATTR_BANDWIDTH,		/* Bandwidth estimate (u64) */
	TQUIC_METRICS_ATTR_DELIVERY_RATE,	/* Delivery rate (u64) */
	TQUIC_METRICS_ATTR_CWND,		/* Congestion window (u64) */
	TQUIC_METRICS_ATTR_BYTES_IN_FLIGHT,	/* Bytes in flight (u64) */
	TQUIC_METRICS_ATTR_SSTHRESH,		/* Slow start threshold (u64) */
	TQUIC_METRICS_ATTR_PACKETS_SENT,	/* Packets sent (u64) */
	TQUIC_METRICS_ATTR_PACKETS_RECEIVED,	/* Packets received (u64) */
	TQUIC_METRICS_ATTR_PACKETS_LOST,	/* Packets lost (u64) */
	TQUIC_METRICS_ATTR_BYTES_SENT,		/* Bytes sent (u64) */
	TQUIC_METRICS_ATTR_BYTES_RECEIVED,	/* Bytes received (u64) */
	TQUIC_METRICS_ATTR_BYTES_LOST,		/* Bytes lost (u64) */
	TQUIC_METRICS_ATTR_ECT0_RECEIVED,	/* ECT(0) packets (u64) */
	TQUIC_METRICS_ATTR_ECT1_RECEIVED,	/* ECT(1) packets (u64) */
	TQUIC_METRICS_ATTR_CE_RECEIVED,		/* CE packets (u64) */
	TQUIC_METRICS_ATTR_PATH_STATE,		/* Path state (u8) */
	TQUIC_METRICS_ATTR_VALIDATION_STATE,	/* Validation state (u8) */
	TQUIC_METRICS_ATTR_IS_ACTIVE,		/* Is active path (u8) */
	TQUIC_METRICS_ATTR_LAST_ACTIVITY,	/* Last activity timestamp (u64) */
	TQUIC_METRICS_ATTR_CREATION_TIME,	/* Creation timestamp (u64) */
	TQUIC_METRICS_ATTR_SUBSCRIBE_INTERVAL,	/* Subscription interval (u32, ms) */
	TQUIC_METRICS_ATTR_PAD,
	__TQUIC_METRICS_ATTR_MAX,
};
#define TQUIC_METRICS_ATTR_MAX (__TQUIC_METRICS_ATTR_MAX - 1)

/* Multicast group for metrics events */
enum tquic_metrics_nl_groups {
	TQUIC_NL_GRP_METRICS = 10,	/* Path metrics updates */
};

/* External declarations */
extern struct rhashtable tquic_conn_table;

/* Forward declarations */
static struct genl_family tquic_metrics_family;

/* Netlink policy for metrics attributes */
static const struct nla_policy tquic_metrics_policy[TQUIC_METRICS_ATTR_MAX + 1] = {
	[TQUIC_METRICS_ATTR_CONN_ID]		= { .type = NLA_BINARY, .len = 20 },
	[TQUIC_METRICS_ATTR_CONN_TOKEN]		= { .type = NLA_U32 },
	[TQUIC_METRICS_ATTR_PATH_ID]		= { .type = NLA_U32 },
	[TQUIC_METRICS_ATTR_MIN_RTT]		= { .type = NLA_U64 },
	[TQUIC_METRICS_ATTR_SMOOTHED_RTT]	= { .type = NLA_U64 },
	[TQUIC_METRICS_ATTR_RTT_VARIANCE]	= { .type = NLA_U64 },
	[TQUIC_METRICS_ATTR_LATEST_RTT]		= { .type = NLA_U64 },
	[TQUIC_METRICS_ATTR_BANDWIDTH]		= { .type = NLA_U64 },
	[TQUIC_METRICS_ATTR_DELIVERY_RATE]	= { .type = NLA_U64 },
	[TQUIC_METRICS_ATTR_CWND]		= { .type = NLA_U64 },
	[TQUIC_METRICS_ATTR_BYTES_IN_FLIGHT]	= { .type = NLA_U64 },
	[TQUIC_METRICS_ATTR_SSTHRESH]		= { .type = NLA_U64 },
	[TQUIC_METRICS_ATTR_PACKETS_SENT]	= { .type = NLA_U64 },
	[TQUIC_METRICS_ATTR_PACKETS_RECEIVED]	= { .type = NLA_U64 },
	[TQUIC_METRICS_ATTR_PACKETS_LOST]	= { .type = NLA_U64 },
	[TQUIC_METRICS_ATTR_BYTES_SENT]		= { .type = NLA_U64 },
	[TQUIC_METRICS_ATTR_BYTES_RECEIVED]	= { .type = NLA_U64 },
	[TQUIC_METRICS_ATTR_BYTES_LOST]		= { .type = NLA_U64 },
	[TQUIC_METRICS_ATTR_ECT0_RECEIVED]	= { .type = NLA_U64 },
	[TQUIC_METRICS_ATTR_ECT1_RECEIVED]	= { .type = NLA_U64 },
	[TQUIC_METRICS_ATTR_CE_RECEIVED]	= { .type = NLA_U64 },
	[TQUIC_METRICS_ATTR_PATH_STATE]		= { .type = NLA_U8 },
	[TQUIC_METRICS_ATTR_VALIDATION_STATE]	= { .type = NLA_U8 },
	[TQUIC_METRICS_ATTR_IS_ACTIVE]		= { .type = NLA_U8 },
	[TQUIC_METRICS_ATTR_LAST_ACTIVITY]	= { .type = NLA_U64 },
	[TQUIC_METRICS_ATTR_CREATION_TIME]	= { .type = NLA_U64 },
	[TQUIC_METRICS_ATTR_SUBSCRIBE_INTERVAL]	= { .type = NLA_U32 },
};

/**
 * tquic_fill_path_metrics - Fill path metrics from tquic_path structure
 * @path: Source path structure
 * @metrics: Destination metrics structure
 * @conn: Parent connection (for active path check)
 *
 * Collects all metrics from a path into the metrics structure.
 * Must be called with appropriate locks held.
 */
static void tquic_fill_path_metrics(struct tquic_path *path,
				    struct tquic_path_metrics *metrics,
				    struct tquic_connection *conn)
{
	memset(metrics, 0, sizeof(*metrics));

	metrics->path_id = path->path_id;

	/* RTT metrics */
	metrics->min_rtt = path->stats.rtt_min;
	metrics->smoothed_rtt = path->stats.rtt_smoothed;
	metrics->rtt_variance = path->stats.rtt_variance;
	/* latest_rtt would come from most recent sample, use smoothed for now */
	metrics->latest_rtt = path->stats.rtt_smoothed;

	/* Bandwidth metrics */
	metrics->bandwidth_estimate = path->stats.bandwidth;
	metrics->delivery_rate = path->stats.bandwidth;  /* Same for now */

	/* Congestion metrics */
	metrics->cwnd = path->stats.cwnd;
	/* bytes_in_flight would come from congestion control state */
	if (path->cong_ops && path->cong && path->cong_ops->get_cwnd)
		metrics->cwnd = path->cong_ops->get_cwnd(path->cong);

	/* Loss metrics */
	metrics->packets_sent = path->stats.tx_packets;
	metrics->packets_received = path->stats.rx_packets;
	metrics->packets_lost = path->stats.lost_packets;
	metrics->bytes_sent = path->stats.tx_bytes;
	metrics->bytes_received = path->stats.rx_bytes;

	/* Path state */
	metrics->state = path->state;
	metrics->validation_state = path->validation.challenge_pending ? 1 : 0;
	metrics->is_active = (conn->active_path == path);

	/* Timestamps */
	metrics->last_activity_us = ktime_to_us(path->last_activity);
}

/**
 * tquic_nl_put_path_metrics - Put path metrics into netlink message
 * @skb: Socket buffer for message
 * @metrics: Metrics to serialize
 *
 * Returns: 0 on success, -EMSGSIZE on buffer overflow
 */
static int tquic_nl_put_path_metrics(struct sk_buff *skb,
				     const struct tquic_path_metrics *metrics)
{
	if (nla_put_u32(skb, TQUIC_METRICS_ATTR_PATH_ID, metrics->path_id))
		return -EMSGSIZE;

	/* RTT metrics */
	if (nla_put_u64_64bit(skb, TQUIC_METRICS_ATTR_MIN_RTT,
			      metrics->min_rtt, TQUIC_METRICS_ATTR_PAD) ||
	    nla_put_u64_64bit(skb, TQUIC_METRICS_ATTR_SMOOTHED_RTT,
			      metrics->smoothed_rtt, TQUIC_METRICS_ATTR_PAD) ||
	    nla_put_u64_64bit(skb, TQUIC_METRICS_ATTR_RTT_VARIANCE,
			      metrics->rtt_variance, TQUIC_METRICS_ATTR_PAD) ||
	    nla_put_u64_64bit(skb, TQUIC_METRICS_ATTR_LATEST_RTT,
			      metrics->latest_rtt, TQUIC_METRICS_ATTR_PAD))
		return -EMSGSIZE;

	/* Bandwidth metrics */
	if (nla_put_u64_64bit(skb, TQUIC_METRICS_ATTR_BANDWIDTH,
			      metrics->bandwidth_estimate, TQUIC_METRICS_ATTR_PAD) ||
	    nla_put_u64_64bit(skb, TQUIC_METRICS_ATTR_DELIVERY_RATE,
			      metrics->delivery_rate, TQUIC_METRICS_ATTR_PAD))
		return -EMSGSIZE;

	/* Congestion metrics */
	if (nla_put_u64_64bit(skb, TQUIC_METRICS_ATTR_CWND,
			      metrics->cwnd, TQUIC_METRICS_ATTR_PAD) ||
	    nla_put_u64_64bit(skb, TQUIC_METRICS_ATTR_BYTES_IN_FLIGHT,
			      metrics->bytes_in_flight, TQUIC_METRICS_ATTR_PAD) ||
	    nla_put_u64_64bit(skb, TQUIC_METRICS_ATTR_SSTHRESH,
			      metrics->ssthresh, TQUIC_METRICS_ATTR_PAD))
		return -EMSGSIZE;

	/* Loss metrics */
	if (nla_put_u64_64bit(skb, TQUIC_METRICS_ATTR_PACKETS_SENT,
			      metrics->packets_sent, TQUIC_METRICS_ATTR_PAD) ||
	    nla_put_u64_64bit(skb, TQUIC_METRICS_ATTR_PACKETS_RECEIVED,
			      metrics->packets_received, TQUIC_METRICS_ATTR_PAD) ||
	    nla_put_u64_64bit(skb, TQUIC_METRICS_ATTR_PACKETS_LOST,
			      metrics->packets_lost, TQUIC_METRICS_ATTR_PAD) ||
	    nla_put_u64_64bit(skb, TQUIC_METRICS_ATTR_BYTES_SENT,
			      metrics->bytes_sent, TQUIC_METRICS_ATTR_PAD) ||
	    nla_put_u64_64bit(skb, TQUIC_METRICS_ATTR_BYTES_RECEIVED,
			      metrics->bytes_received, TQUIC_METRICS_ATTR_PAD) ||
	    nla_put_u64_64bit(skb, TQUIC_METRICS_ATTR_BYTES_LOST,
			      metrics->bytes_lost, TQUIC_METRICS_ATTR_PAD))
		return -EMSGSIZE;

	/* ECN metrics */
	if (nla_put_u64_64bit(skb, TQUIC_METRICS_ATTR_ECT0_RECEIVED,
			      metrics->ect0_received, TQUIC_METRICS_ATTR_PAD) ||
	    nla_put_u64_64bit(skb, TQUIC_METRICS_ATTR_ECT1_RECEIVED,
			      metrics->ect1_received, TQUIC_METRICS_ATTR_PAD) ||
	    nla_put_u64_64bit(skb, TQUIC_METRICS_ATTR_CE_RECEIVED,
			      metrics->ce_received, TQUIC_METRICS_ATTR_PAD))
		return -EMSGSIZE;

	/* Path state */
	if (nla_put_u8(skb, TQUIC_METRICS_ATTR_PATH_STATE, metrics->state) ||
	    nla_put_u8(skb, TQUIC_METRICS_ATTR_VALIDATION_STATE,
		       metrics->validation_state) ||
	    nla_put_u8(skb, TQUIC_METRICS_ATTR_IS_ACTIVE, metrics->is_active))
		return -EMSGSIZE;

	/* Timestamps */
	if (nla_put_u64_64bit(skb, TQUIC_METRICS_ATTR_LAST_ACTIVITY,
			      metrics->last_activity_us, TQUIC_METRICS_ATTR_PAD) ||
	    nla_put_u64_64bit(skb, TQUIC_METRICS_ATTR_CREATION_TIME,
			      metrics->creation_time_us, TQUIC_METRICS_ATTR_PAD))
		return -EMSGSIZE;

	return 0;
}

/**
 * tquic_nl_get_path_metrics - Handle TQUIC_NL_CMD_GET_PATH_METRICS
 * @skb: Request socket buffer
 * @info: Generic netlink info
 *
 * Returns metrics for a specific path identified by connection token
 * and path ID.
 *
 * Returns: 0 on success, negative errno on failure
 */
int tquic_nl_get_path_metrics(struct sk_buff *skb, struct genl_info *info)
{
	struct tquic_connection *conn;
	struct tquic_path *path;
	struct tquic_path_metrics metrics;
	struct sk_buff *msg;
	struct net *net;
	void *hdr;
	u32 token, path_id;

	if (!info->attrs[TQUIC_METRICS_ATTR_CONN_TOKEN] ||
	    !info->attrs[TQUIC_METRICS_ATTR_PATH_ID])
		return -EINVAL;

	token = nla_get_u32(info->attrs[TQUIC_METRICS_ATTR_CONN_TOKEN]);
	path_id = nla_get_u32(info->attrs[TQUIC_METRICS_ATTR_PATH_ID]);

	net = genl_info_net(info);
	conn = tquic_conn_lookup_by_token(net, token);
	if (!conn)
		return -ENOENT;

	path = tquic_conn_get_path(conn, path_id);
	if (!path) {
		tquic_conn_put(conn);
		return -ENOENT;
	}

	/* Allocate response message */
	msg = nlmsg_new(NLMSG_DEFAULT_SIZE, GFP_KERNEL);
	if (!msg) {
		tquic_conn_put(conn);
		return -ENOMEM;
	}

	hdr = genlmsg_put(msg, info->snd_portid, info->snd_seq,
			  &tquic_metrics_family, 0, TQUIC_NL_CMD_GET_PATH_METRICS);
	if (!hdr) {
		nlmsg_free(msg);
		tquic_conn_put(conn);
		return -EMSGSIZE;
	}

	/* Fill metrics under lock */
	spin_lock_bh(&conn->lock);
	tquic_fill_path_metrics(path, &metrics, conn);
	spin_unlock_bh(&conn->lock);

	/* Serialize to netlink */
	if (tquic_nl_put_path_metrics(msg, &metrics)) {
		genlmsg_cancel(msg, hdr);
		nlmsg_free(msg);
		tquic_conn_put(conn);
		return -EMSGSIZE;
	}

	genlmsg_end(msg, hdr);
	tquic_conn_put(conn);
	return genlmsg_reply(msg, info);
}

/**
 * tquic_nl_get_all_paths - Handle TQUIC_NL_CMD_GET_ALL_PATHS
 * @skb: Request socket buffer
 * @info: Generic netlink info
 *
 * Returns metrics for all paths in a connection.
 *
 * Returns: 0 on success, negative errno on failure
 */
static int tquic_nl_get_all_paths(struct sk_buff *skb, struct genl_info *info)
{
	struct tquic_connection *conn;
	struct tquic_path *path;
	struct tquic_path_metrics metrics;
	struct sk_buff *msg;
	struct net *net;
	struct nlattr *paths_nest;
	void *hdr;
	u32 token;

	if (!info->attrs[TQUIC_METRICS_ATTR_CONN_TOKEN])
		return -EINVAL;

	token = nla_get_u32(info->attrs[TQUIC_METRICS_ATTR_CONN_TOKEN]);

	net = genl_info_net(info);
	conn = tquic_conn_lookup_by_token(net, token);
	if (!conn)
		return -ENOENT;

	/* Allocate response message -- cap to prevent unbounded allocation
	 * from attacker-influenced num_paths values.
	 */
	{
		u32 capped_paths = min_t(u32, conn->num_paths, TQUIC_MAX_PATHS);

		msg = nlmsg_new(NLMSG_DEFAULT_SIZE * capped_paths, GFP_KERNEL);
	}
	if (!msg) {
		tquic_conn_put(conn);
		return -ENOMEM;
	}

	hdr = genlmsg_put(msg, info->snd_portid, info->snd_seq,
			  &tquic_metrics_family, 0, TQUIC_NL_CMD_GET_ALL_PATHS);
	if (!hdr) {
		nlmsg_free(msg);
		tquic_conn_put(conn);
		return -EMSGSIZE;
	}

	/* Connection token */
	if (nla_put_u32(msg, TQUIC_METRICS_ATTR_CONN_TOKEN, token)) {
		genlmsg_cancel(msg, hdr);
		nlmsg_free(msg);
		tquic_conn_put(conn);
		return -EMSGSIZE;
	}

	/* Start nested paths attribute */
	paths_nest = nla_nest_start(msg, TQUIC_DIAG_ATTR_PATHS);
	if (!paths_nest) {
		genlmsg_cancel(msg, hdr);
		nlmsg_free(msg);
		tquic_conn_put(conn);
		return -EMSGSIZE;
	}

	/* Iterate all paths under lock */
	spin_lock_bh(&conn->lock);
	list_for_each_entry(path, &conn->paths, list) {
		struct nlattr *path_nest;

		path_nest = nla_nest_start(msg, 0);
		if (!path_nest) {
			spin_unlock_bh(&conn->lock);
			nla_nest_cancel(msg, paths_nest);
			genlmsg_cancel(msg, hdr);
			nlmsg_free(msg);
			tquic_conn_put(conn);
			return -EMSGSIZE;
		}

		tquic_fill_path_metrics(path, &metrics, conn);
		if (tquic_nl_put_path_metrics(msg, &metrics)) {
			spin_unlock_bh(&conn->lock);
			nla_nest_cancel(msg, path_nest);
			nla_nest_cancel(msg, paths_nest);
			genlmsg_cancel(msg, hdr);
			nlmsg_free(msg);
			tquic_conn_put(conn);
			return -EMSGSIZE;
		}

		nla_nest_end(msg, path_nest);
	}
	spin_unlock_bh(&conn->lock);

	nla_nest_end(msg, paths_nest);
	genlmsg_end(msg, hdr);
	tquic_conn_put(conn);
	return genlmsg_reply(msg, info);
}

/*
 * =============================================================================
 * Continuous Metrics Streaming via Netlink Multicast
 * =============================================================================
 */

/* Subscription state per-connection */
struct tquic_metrics_subscription {
	struct list_head list;
	struct tquic_connection *conn;
	u32 portid;			/* Subscriber's netlink portid */
	u32 interval_ms;		/* Update interval in milliseconds */
	struct timer_list timer;	/* Timer for periodic updates */
	struct work_struct work;	/* Work item for sending updates */
};

static LIST_HEAD(metrics_subscriptions);
static DEFINE_SPINLOCK(subscriptions_lock);

/**
 * tquic_metrics_send_update - Send metrics update to subscribers
 * @work: Work item
 *
 * Called from workqueue to send periodic metrics updates.
 */
static void tquic_metrics_send_update(struct work_struct *work)
{
	struct tquic_metrics_subscription *sub =
		container_of(work, struct tquic_metrics_subscription, work);
	struct tquic_connection *conn = sub->conn;
	struct tquic_path *path;
	struct tquic_path_metrics metrics;
	struct sk_buff *msg;
	void *hdr;

	if (!conn || conn->state == TQUIC_CONN_CLOSED)
		return;

	msg = nlmsg_new(NLMSG_DEFAULT_SIZE * min_t(u32, conn->num_paths,
						   TQUIC_MAX_PATHS),
			GFP_KERNEL);
	if (!msg)
		return;

	hdr = genlmsg_put(msg, 0, 0, &tquic_metrics_family, 0,
			  TQUIC_NL_CMD_METRICS_EVENT);
	if (!hdr) {
		nlmsg_free(msg);
		return;
	}

	if (nla_put_u32(msg, TQUIC_METRICS_ATTR_CONN_TOKEN, conn->token)) {
		genlmsg_cancel(msg, hdr);
		nlmsg_free(msg);
		return;
	}

	spin_lock_bh(&conn->lock);
	list_for_each_entry(path, &conn->paths, list) {
		struct nlattr *path_nest;

		path_nest = nla_nest_start(msg, 0);
		if (!path_nest)
			break;

		tquic_fill_path_metrics(path, &metrics, conn);
		if (tquic_nl_put_path_metrics(msg, &metrics)) {
			nla_nest_cancel(msg, path_nest);
			break;
		}

		nla_nest_end(msg, path_nest);
	}
	spin_unlock_bh(&conn->lock);

	genlmsg_end(msg, hdr);

	/* Send to multicast group */
	genlmsg_multicast(&tquic_metrics_family, msg, 0,
			  TQUIC_NL_GRP_METRICS, GFP_KERNEL);
}

/**
 * tquic_metrics_timer_fn - Timer callback for periodic metrics
 * @t: Timer structure
 */
static void tquic_metrics_timer_fn(struct timer_list *t)
{
	struct tquic_metrics_subscription *sub =
		from_timer(sub, t, timer);

	/* Schedule work to send update */
	schedule_work(&sub->work);

	/* Re-arm timer */
	mod_timer(&sub->timer, jiffies + msecs_to_jiffies(sub->interval_ms));
}

/**
 * tquic_nl_subscribe_events - Handle TQUIC_NL_CMD_SUBSCRIBE_EVENTS
 * @skb: Request socket buffer
 * @info: Generic netlink info
 *
 * Subscribe to periodic metrics updates for a connection.
 *
 * Returns: 0 on success, negative errno on failure
 */
static int tquic_nl_subscribe_events(struct sk_buff *skb, struct genl_info *info)
{
	struct tquic_metrics_subscription *sub;
	struct tquic_connection *conn;
	struct net *net;
	u32 token, interval_ms;

	if (!info->attrs[TQUIC_METRICS_ATTR_CONN_TOKEN])
		return -EINVAL;

	token = nla_get_u32(info->attrs[TQUIC_METRICS_ATTR_CONN_TOKEN]);

	/* Default interval 1000ms, min 100ms, max 60000ms */
	if (info->attrs[TQUIC_METRICS_ATTR_SUBSCRIBE_INTERVAL]) {
		interval_ms = nla_get_u32(info->attrs[TQUIC_METRICS_ATTR_SUBSCRIBE_INTERVAL]);
		interval_ms = clamp_val(interval_ms, 100, 60000);
	} else {
		interval_ms = 1000;
	}

	net = genl_info_net(info);
	conn = tquic_conn_lookup_by_token(net, token);
	if (!conn)
		return -ENOENT;

	sub = kzalloc(sizeof(*sub), GFP_KERNEL);
	if (!sub) {
		tquic_conn_put(conn);
		return -ENOMEM;
	}

	sub->conn = conn;
	sub->portid = info->snd_portid;
	sub->interval_ms = interval_ms;

	INIT_WORK(&sub->work, tquic_metrics_send_update);
	timer_setup(&sub->timer, tquic_metrics_timer_fn, 0);

	spin_lock_bh(&subscriptions_lock);
	list_add(&sub->list, &metrics_subscriptions);
	spin_unlock_bh(&subscriptions_lock);

	/* Start the timer */
	mod_timer(&sub->timer, jiffies + msecs_to_jiffies(interval_ms));

	return 0;
}

/**
 * tquic_metrics_unsubscribe_conn - Remove subscriptions for a connection
 * @conn: Connection being closed
 *
 * Called when a connection is destroyed to clean up any subscriptions.
 */
void tquic_metrics_unsubscribe_conn(struct tquic_connection *conn)
{
	struct tquic_metrics_subscription *sub, *tmp;
	LIST_HEAD(to_free);

	spin_lock_bh(&subscriptions_lock);
	list_for_each_entry_safe(sub, tmp, &metrics_subscriptions, list) {
		if (sub->conn == conn)
			list_move(&sub->list, &to_free);
	}
	spin_unlock_bh(&subscriptions_lock);

	list_for_each_entry_safe(sub, tmp, &to_free, list) {
		list_del(&sub->list);
		del_timer_sync(&sub->timer);
		cancel_work_sync(&sub->work);
		tquic_conn_put(sub->conn);
		kfree(sub);
	}
}
EXPORT_SYMBOL_GPL(tquic_metrics_unsubscribe_conn);

/* Netlink operations */
static const struct genl_ops tquic_metrics_ops[] = {
	{
		.cmd = TQUIC_NL_CMD_GET_PATH_METRICS,
		.validate = GENL_DONT_VALIDATE_STRICT | GENL_DONT_VALIDATE_DUMP,
		.doit = tquic_nl_get_path_metrics,
	},
	{
		.cmd = TQUIC_NL_CMD_GET_ALL_PATHS,
		.validate = GENL_DONT_VALIDATE_STRICT | GENL_DONT_VALIDATE_DUMP,
		.doit = tquic_nl_get_all_paths,
	},
	{
		.cmd = TQUIC_NL_CMD_SUBSCRIBE_EVENTS,
		.validate = GENL_DONT_VALIDATE_STRICT | GENL_DONT_VALIDATE_DUMP,
		.doit = tquic_nl_subscribe_events,
	},
};

/* Multicast groups */
static const struct genl_multicast_group tquic_metrics_mcgrps[] = {
	[0] = { .name = "metrics", },
};

/* Netlink family definition */
static struct genl_family tquic_metrics_family __ro_after_init = {
	.name = "TQUIC_METRICS",
	.version = 1,
	.maxattr = TQUIC_METRICS_ATTR_MAX,
	.policy = tquic_metrics_policy,
	.module = THIS_MODULE,
	.ops = tquic_metrics_ops,
	.n_ops = ARRAY_SIZE(tquic_metrics_ops),
	.mcgrps = tquic_metrics_mcgrps,
	.n_mcgrps = ARRAY_SIZE(tquic_metrics_mcgrps),
};

/*
 * =============================================================================
 * Procfs Interface: /proc/net/tquic/paths
 * =============================================================================
 *
 * Format: path_id state rtt cwnd bw loss_rate
 */

/* Per-namespace proc directory */
#define TQUIC_PROC_DIR "tquic"

/* Path state name mapping */
static const char * const path_state_names[] = {
	[TQUIC_PATH_UNUSED]	= "UNUSED",
	[TQUIC_PATH_PENDING]	= "PENDING",
	[TQUIC_PATH_VALIDATED]	= "VALID",
	[TQUIC_PATH_ACTIVE]	= "ACTIVE",
	[TQUIC_PATH_STANDBY]	= "STANDBY",
	[TQUIC_PATH_UNAVAILABLE]= "UNAVAIL",
	[TQUIC_PATH_FAILED]	= "FAILED",
	[TQUIC_PATH_CLOSED]	= "CLOSED",
};

static const char *get_path_state_name(enum tquic_path_state state)
{
	if (state >= ARRAY_SIZE(path_state_names))
		return "UNKNOWN";
	return path_state_names[state] ?: "UNKNOWN";
}

/* Iteration context for seq_file */
struct tquic_paths_iter {
	struct net *net;
	struct rhashtable_iter hti;
	struct tquic_connection *conn;
	struct tquic_path *path;
	int path_idx;
};

/**
 * tquic_paths_show - Display one path entry
 * @m: seq_file for output
 * @v: Current iterator position (path or header)
 *
 * Output format:
 *   conn_token path_id state rtt_us cwnd bw_kbps loss_pct
 */
static int tquic_paths_show(struct seq_file *m, void *v)
{
	struct tquic_paths_iter *iter = m->private;
	struct tquic_path *path;
	struct tquic_connection *conn;
	u64 loss_pct;

	if (v == SEQ_START_TOKEN) {
		/* Header row */
		seq_puts(m, "conn_token  path_id  state     rtt_us  cwnd       bw_kbps  loss_pct\n");
		return 0;
	}

	path = iter->path;
	conn = iter->conn;
	if (!path || !conn)
		return 0;

	/* Calculate loss percentage (scaled by 1000 for precision) */
	if (path->stats.tx_packets > 0)
		loss_pct = (path->stats.lost_packets * 1000) / path->stats.tx_packets;
	else
		loss_pct = 0;

	seq_printf(m, "%-11u %-8u %-9s %-7u %-10u %-8llu %llu.%01llu%%\n",
		   conn->token,
		   path->path_id,
		   get_path_state_name(path->state),
		   path->stats.rtt_smoothed,
		   path->stats.cwnd,
		   path->stats.bandwidth / 1000,  /* Convert to kbps */
		   loss_pct / 10,
		   loss_pct % 10);

	return 0;
}

static void *tquic_paths_seq_start(struct seq_file *m, loff_t *pos)
{
	struct tquic_paths_iter *iter = m->private;
	struct tquic_connection *conn;
	struct tquic_path *path;
	loff_t off = *pos;

	if (*pos == 0)
		return SEQ_START_TOKEN;

	off--;  /* Adjust for header */

	/* Iterate connections and paths */
	rhashtable_walk_enter(&tquic_conn_table, &iter->hti);
	rhashtable_walk_start(&iter->hti);

	while ((conn = rhashtable_walk_next(&iter->hti)) != NULL) {
		if (IS_ERR(conn))
			continue;

		/* Filter by namespace */
		if (!net_eq(sock_net(conn->sk), iter->net))
			continue;

		/* Iterate paths in this connection */
		list_for_each_entry(path, &conn->paths, list) {
			if (off == 0) {
				iter->conn = conn;
				iter->path = path;
				return iter;
			}
			off--;
		}
	}

	rhashtable_walk_stop(&iter->hti);
	rhashtable_walk_exit(&iter->hti);
	return NULL;
}

static void *tquic_paths_seq_next(struct seq_file *m, void *v, loff_t *pos)
{
	struct tquic_paths_iter *iter = m->private;
	struct tquic_connection *conn;
	struct tquic_path *path;

	(*pos)++;

	if (v == SEQ_START_TOKEN) {
		/* Start from first connection/path */
		rhashtable_walk_enter(&tquic_conn_table, &iter->hti);
		rhashtable_walk_start(&iter->hti);
		iter->conn = NULL;
		iter->path = NULL;
	}

	/* Try next path in current connection */
	if (iter->path && iter->conn) {
		path = list_next_entry(iter->path, list);
		if (&path->list != &iter->conn->paths) {
			iter->path = path;
			return iter;
		}
	}

	/* Move to next connection */
	while ((conn = rhashtable_walk_next(&iter->hti)) != NULL) {
		if (IS_ERR(conn))
			continue;

		if (!net_eq(sock_net(conn->sk), iter->net))
			continue;

		if (!list_empty(&conn->paths)) {
			iter->conn = conn;
			iter->path = list_first_entry(&conn->paths,
						      struct tquic_path, list);
			return iter;
		}
	}

	rhashtable_walk_stop(&iter->hti);
	rhashtable_walk_exit(&iter->hti);
	iter->conn = NULL;
	iter->path = NULL;
	return NULL;
}

static void tquic_paths_seq_stop(struct seq_file *m, void *v)
{
	struct tquic_paths_iter *iter = m->private;

	if (v && v != SEQ_START_TOKEN && iter->conn) {
		rhashtable_walk_stop(&iter->hti);
		rhashtable_walk_exit(&iter->hti);
	}
}

static const struct seq_operations tquic_paths_seq_ops = {
	.start	= tquic_paths_seq_start,
	.next	= tquic_paths_seq_next,
	.stop	= tquic_paths_seq_stop,
	.show	= tquic_paths_show,
};

static int tquic_paths_seq_open(struct inode *inode, struct file *file)
{
	struct seq_file *m;
	struct tquic_paths_iter *iter;
	int ret;

	ret = seq_open(file, &tquic_paths_seq_ops);
	if (ret)
		return ret;

	m = file->private_data;
	iter = kzalloc(sizeof(*iter), GFP_KERNEL);
	if (!iter) {
		seq_release(inode, file);
		return -ENOMEM;
	}

	iter->net = get_net(current->nsproxy->net_ns);
	m->private = iter;
	return 0;
}

static int tquic_paths_seq_release(struct inode *inode, struct file *file)
{
	struct seq_file *m = file->private_data;
	struct tquic_paths_iter *iter = m->private;

	if (iter) {
		put_net(iter->net);
		kfree(iter);
	}
	return seq_release(inode, file);
}

static const struct proc_ops tquic_paths_proc_ops = {
	.proc_open	= tquic_paths_seq_open,
	.proc_read	= seq_read,
	.proc_lseek	= seq_lseek,
	.proc_release	= tquic_paths_seq_release,
};

/*
 * =============================================================================
 * Path Comparison Helper for Scheduler Debugging
 * =============================================================================
 */

/**
 * struct tquic_path_comparison - Comparison result for two paths
 * @path_a: First path ID
 * @path_b: Second path ID
 * @rtt_diff_us: RTT difference (positive = A slower)
 * @bw_ratio: Bandwidth ratio (A/B * 1000)
 * @loss_diff: Loss rate difference (A - B, scaled by 1000)
 * @better_path: ID of the better path (0 if equivalent)
 * @reason: Reason for preference
 */
struct tquic_path_comparison {
	u32 path_a;
	u32 path_b;
	s64 rtt_diff_us;
	u32 bw_ratio;
	s32 loss_diff;
	u32 better_path;
	const char *reason;
};

/* Thresholds for path comparison */
#define PATH_CMP_RTT_THRESHOLD_US	5000	/* 5ms difference is significant */
#define PATH_CMP_BW_THRESHOLD_PCT	20	/* 20% bandwidth difference */
#define PATH_CMP_LOSS_THRESHOLD_PCT	1	/* 1% loss difference */

/**
 * tquic_compare_paths - Compare two paths for scheduler decision
 * @conn: Connection containing paths
 * @path_a: First path
 * @path_b: Second path
 * @result: Output comparison result
 *
 * Compares two paths and determines which is better for scheduling.
 * Considers RTT, bandwidth, loss rate, and current state.
 *
 * Returns: 0 on success, negative errno on failure
 */
int tquic_compare_paths(struct tquic_connection *conn,
			struct tquic_path *path_a,
			struct tquic_path *path_b,
			struct tquic_path_comparison *result)
{
	u64 loss_a, loss_b;

	if (!conn || !path_a || !path_b || !result)
		return -EINVAL;

	memset(result, 0, sizeof(*result));
	result->path_a = path_a->path_id;
	result->path_b = path_b->path_id;

	/* RTT comparison */
	result->rtt_diff_us = (s64)path_a->stats.rtt_smoothed -
			      (s64)path_b->stats.rtt_smoothed;

	/* Bandwidth ratio (A/B * 1000) */
	if (path_b->stats.bandwidth > 0)
		result->bw_ratio = (path_a->stats.bandwidth * 1000) /
				   path_b->stats.bandwidth;
	else if (path_a->stats.bandwidth > 0)
		result->bw_ratio = 2000;  /* A has BW, B doesn't */
	else
		result->bw_ratio = 1000;  /* Neither has measured BW */

	/* Loss rate comparison (per mille) */
	if (path_a->stats.tx_packets > 100)
		loss_a = (path_a->stats.lost_packets * 1000) /
			 path_a->stats.tx_packets;
	else
		loss_a = 0;

	if (path_b->stats.tx_packets > 100)
		loss_b = (path_b->stats.lost_packets * 1000) /
			 path_b->stats.tx_packets;
	else
		loss_b = 0;

	result->loss_diff = (s32)(loss_a - loss_b);

	/* Determine better path */
	/* Priority: State > Loss > RTT > Bandwidth */

	/* State check - active beats standby/pending */
	if (path_a->state == TQUIC_PATH_ACTIVE &&
	    path_b->state != TQUIC_PATH_ACTIVE) {
		result->better_path = path_a->path_id;
		result->reason = "state";
		return 0;
	}
	if (path_b->state == TQUIC_PATH_ACTIVE &&
	    path_a->state != TQUIC_PATH_ACTIVE) {
		result->better_path = path_b->path_id;
		result->reason = "state";
		return 0;
	}

	/* Significant loss difference */
	if (result->loss_diff < -PATH_CMP_LOSS_THRESHOLD_PCT * 10) {
		result->better_path = path_a->path_id;
		result->reason = "loss";
		return 0;
	}
	if (result->loss_diff > PATH_CMP_LOSS_THRESHOLD_PCT * 10) {
		result->better_path = path_b->path_id;
		result->reason = "loss";
		return 0;
	}

	/* Significant RTT difference */
	if (result->rtt_diff_us < -PATH_CMP_RTT_THRESHOLD_US) {
		result->better_path = path_a->path_id;
		result->reason = "rtt";
		return 0;
	}
	if (result->rtt_diff_us > PATH_CMP_RTT_THRESHOLD_US) {
		result->better_path = path_b->path_id;
		result->reason = "rtt";
		return 0;
	}

	/* Bandwidth advantage */
	if (result->bw_ratio > 1000 + PATH_CMP_BW_THRESHOLD_PCT * 10) {
		result->better_path = path_a->path_id;
		result->reason = "bandwidth";
		return 0;
	}
	if (result->bw_ratio < 1000 - PATH_CMP_BW_THRESHOLD_PCT * 10) {
		result->better_path = path_b->path_id;
		result->reason = "bandwidth";
		return 0;
	}

	/* Paths are equivalent */
	result->better_path = 0;
	result->reason = "equivalent";
	return 0;
}
EXPORT_SYMBOL_GPL(tquic_compare_paths);

/**
 * tquic_get_best_path - Find the best path in a connection
 * @conn: Connection to search
 * @flags: Selection flags (reserved for future use)
 *
 * Compares all paths and returns the best one for scheduling.
 *
 * Returns: Best path, or NULL if no suitable path found
 */
struct tquic_path *tquic_get_best_path(struct tquic_connection *conn, u32 flags)
{
	struct tquic_path *best = NULL;
	struct tquic_path *path;
	struct tquic_path_comparison cmp;

	if (!conn)
		return NULL;

	spin_lock_bh(&conn->lock);

	list_for_each_entry(path, &conn->paths, list) {
		/* Skip unusable paths */
		if (path->state == TQUIC_PATH_UNUSED ||
		    path->state == TQUIC_PATH_FAILED ||
		    path->state == TQUIC_PATH_CLOSED ||
		    path->state == TQUIC_PATH_UNAVAILABLE)
			continue;

		if (!best) {
			best = path;
			continue;
		}

		if (tquic_compare_paths(conn, path, best, &cmp) == 0) {
			if (cmp.better_path == path->path_id)
				best = path;
		}
	}

	spin_unlock_bh(&conn->lock);
	return best;
}
EXPORT_SYMBOL_GPL(tquic_get_best_path);

/*
 * =============================================================================
 * Extended ss (sock_diag) Integration
 * =============================================================================
 */

/**
 * tquic_diag_get_path_info - Get path info for sock_diag
 * @conn: Connection to get path info from
 * @infos: Array to fill with path info
 * @max_paths: Maximum number of paths to return
 *
 * Fills the tquic_diag_path_info array with information about each path.
 *
 * Returns: Number of paths filled
 */
int tquic_diag_get_path_info(struct tquic_connection *conn,
			     struct tquic_diag_path_info *infos,
			     int max_paths)
{
	struct tquic_path *path;
	int count = 0;

	if (!conn || !infos || max_paths <= 0)
		return 0;

	spin_lock_bh(&conn->lock);

	list_for_each_entry(path, &conn->paths, list) {
		if (count >= max_paths)
			break;

		infos[count].path_id = path->path_id;
		infos[count].state = path->state;
		infos[count].rtt_us = path->stats.rtt_smoothed;
		infos[count].cwnd = path->stats.cwnd;
		infos[count].bytes_sent = path->stats.tx_bytes;
		infos[count].bytes_recv = path->stats.rx_bytes;

		count++;
	}

	spin_unlock_bh(&conn->lock);
	return count;
}
EXPORT_SYMBOL_GPL(tquic_diag_get_path_info);

/*
 * =============================================================================
 * Module Initialization
 * =============================================================================
 */

static struct proc_dir_entry *tquic_proc_dir;

/**
 * tquic_path_metrics_init - Initialize path metrics subsystem
 * @net: Network namespace
 *
 * Creates proc directory and registers netlink family.
 *
 * Returns: 0 on success, negative errno on failure
 */
int __init tquic_path_metrics_init(struct net *net)
{
	int ret;

	/* Create /proc/net/tquic directory if it doesn't exist */
	tquic_proc_dir = proc_mkdir(TQUIC_PROC_DIR, net->proc_net);
	if (!tquic_proc_dir) {
		pr_warn("tquic: failed to create /proc/net/tquic\n");
		/* Continue anyway - procfs is optional */
	}

	/* Create /proc/net/tquic/paths */
	if (tquic_proc_dir) {
		if (!proc_create("paths", 0444, tquic_proc_dir,
				 &tquic_paths_proc_ops)) {
			pr_warn("tquic: failed to create /proc/net/tquic/paths\n");
		}
	}

	/* Register netlink family */
	ret = genl_register_family(&tquic_metrics_family);
	if (ret) {
		pr_err("tquic: failed to register metrics netlink family: %d\n",
		       ret);
		if (tquic_proc_dir) {
			remove_proc_entry("paths", tquic_proc_dir);
			remove_proc_entry(TQUIC_PROC_DIR, net->proc_net);
		}
		return ret;
	}

	pr_info("tquic: path metrics subsystem initialized\n");
	return 0;
}

/**
 * tquic_path_metrics_exit - Cleanup path metrics subsystem
 * @net: Network namespace
 */
void __exit tquic_path_metrics_exit(struct net *net)
{
	struct tquic_metrics_subscription *sub, *tmp;

	/* Cancel all subscriptions - splice under lock, then free outside */
	{
		LIST_HEAD(to_free);

		spin_lock_bh(&subscriptions_lock);
		list_splice_init(&metrics_subscriptions, &to_free);
		spin_unlock_bh(&subscriptions_lock);

		list_for_each_entry_safe(sub, tmp, &to_free, list) {
			list_del(&sub->list);
			del_timer_sync(&sub->timer);
			cancel_work_sync(&sub->work);
			tquic_conn_put(sub->conn);
			kfree(sub);
		}
	}

	/* Unregister netlink family */
	genl_unregister_family(&tquic_metrics_family);

	/* Remove proc entries */
	if (tquic_proc_dir) {
		remove_proc_entry("paths", tquic_proc_dir);
		remove_proc_entry(TQUIC_PROC_DIR, net->proc_net);
	}

	pr_info("tquic: path metrics subsystem exited\n");
}

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("TQUIC Path-Specific Metrics Export");
MODULE_AUTHOR("Linux Foundation");
