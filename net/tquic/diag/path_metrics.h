/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * TQUIC Path-Specific Metrics Export - Header
 *
 * Copyright (c) 2026 Linux Foundation
 *
 * This header provides the API for path-specific metrics export.
 */

#ifndef _TQUIC_PATH_METRICS_H
#define _TQUIC_PATH_METRICS_H

#include <linux/types.h>
#include <net/tquic.h>

/**
 * struct tquic_path_metrics - Comprehensive per-path metrics
 *
 * This structure contains all exportable metrics for a single path.
 * Used by netlink, procfs, and sock_diag interfaces.
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
 *
 * Compact structure for ss tool integration, containing the most
 * important per-path metrics.
 */
struct tquic_diag_path_info {
	u32 path_id;
	u32 state;
	u32 rtt_us;
	u32 cwnd;
	u64 bytes_sent;
	u64 bytes_recv;
};

/**
 * struct tquic_path_comparison - Comparison result for two paths
 *
 * Result of comparing two paths for scheduler decision making.
 */
struct tquic_path_comparison {
	u32 path_a;
	u32 path_b;
	s64 rtt_diff_us;	/* Positive = A slower */
	u32 bw_ratio;		/* A/B * 1000 */
	s32 loss_diff;		/* A - B, scaled by 1000 */
	u32 better_path;	/* ID of better path (0 if equivalent) */
	const char *reason;	/* Reason for preference */
};

/* Netlink commands for path metrics */
enum tquic_metrics_nl_commands {
	TQUIC_NL_CMD_GET_CONN_INFO = 0x10,
	TQUIC_NL_CMD_GET_PATH_METRICS,
	TQUIC_NL_CMD_GET_ALL_PATHS,
	TQUIC_NL_CMD_SUBSCRIBE_EVENTS,
	TQUIC_NL_CMD_METRICS_EVENT,
	__TQUIC_NL_CMD_METRICS_MAX,
};
#define TQUIC_NL_CMD_METRICS_MAX (__TQUIC_NL_CMD_METRICS_MAX - 1)

/* Netlink attributes for path metrics */
enum tquic_metrics_nl_attrs {
	TQUIC_METRICS_ATTR_UNSPEC,
	TQUIC_METRICS_ATTR_CONN_ID,
	TQUIC_METRICS_ATTR_CONN_TOKEN,
	TQUIC_METRICS_ATTR_PATH_ID,
	TQUIC_METRICS_ATTR_MIN_RTT,
	TQUIC_METRICS_ATTR_SMOOTHED_RTT,
	TQUIC_METRICS_ATTR_RTT_VARIANCE,
	TQUIC_METRICS_ATTR_LATEST_RTT,
	TQUIC_METRICS_ATTR_BANDWIDTH,
	TQUIC_METRICS_ATTR_DELIVERY_RATE,
	TQUIC_METRICS_ATTR_CWND,
	TQUIC_METRICS_ATTR_BYTES_IN_FLIGHT,
	TQUIC_METRICS_ATTR_SSTHRESH,
	TQUIC_METRICS_ATTR_PACKETS_SENT,
	TQUIC_METRICS_ATTR_PACKETS_RECEIVED,
	TQUIC_METRICS_ATTR_PACKETS_LOST,
	TQUIC_METRICS_ATTR_BYTES_SENT,
	TQUIC_METRICS_ATTR_BYTES_RECEIVED,
	TQUIC_METRICS_ATTR_BYTES_LOST,
	TQUIC_METRICS_ATTR_ECT0_RECEIVED,
	TQUIC_METRICS_ATTR_ECT1_RECEIVED,
	TQUIC_METRICS_ATTR_CE_RECEIVED,
	TQUIC_METRICS_ATTR_PATH_STATE,
	TQUIC_METRICS_ATTR_VALIDATION_STATE,
	TQUIC_METRICS_ATTR_IS_ACTIVE,
	TQUIC_METRICS_ATTR_LAST_ACTIVITY,
	TQUIC_METRICS_ATTR_CREATION_TIME,
	TQUIC_METRICS_ATTR_SUBSCRIBE_INTERVAL,
	TQUIC_METRICS_ATTR_PAD,
	__TQUIC_METRICS_ATTR_MAX,
};
#define TQUIC_METRICS_ATTR_MAX (__TQUIC_METRICS_ATTR_MAX - 1)

/* Multicast group for metrics events */
enum tquic_metrics_nl_groups {
	TQUIC_NL_GRP_METRICS = 10,
};

/*
 * API Functions
 */

/**
 * tquic_nl_get_path_metrics - Handle netlink request for path metrics
 * @skb: Request socket buffer
 * @info: Generic netlink info
 *
 * Returns: 0 on success, negative errno on failure
 */
int tquic_nl_get_path_metrics(struct sk_buff *skb, struct genl_info *info);

/**
 * tquic_metrics_unsubscribe_conn - Remove subscriptions for a connection
 * @conn: Connection being closed
 *
 * Called when a connection is destroyed to clean up any subscriptions.
 */
void tquic_metrics_unsubscribe_conn(struct tquic_connection *conn);

/**
 * tquic_compare_paths - Compare two paths for scheduler decision
 * @conn: Connection containing paths
 * @path_a: First path
 * @path_b: Second path
 * @result: Output comparison result
 *
 * Returns: 0 on success, negative errno on failure
 */
int tquic_compare_paths(struct tquic_connection *conn,
			struct tquic_path *path_a,
			struct tquic_path *path_b,
			struct tquic_path_comparison *result);

/**
 * tquic_get_best_path - Find the best path in a connection
 * @conn: Connection to search
 * @flags: Selection flags (reserved for future use)
 *
 * Returns: Best path, or NULL if no suitable path found
 */
struct tquic_path *tquic_get_best_path(struct tquic_connection *conn, u32 flags);

/**
 * tquic_diag_get_path_info - Get path info for sock_diag
 * @conn: Connection to get path info from
 * @infos: Array to fill with path info
 * @max_paths: Maximum number of paths to return
 *
 * Returns: Number of paths filled
 */
int tquic_diag_get_path_info(struct tquic_connection *conn,
			     struct tquic_diag_path_info *infos,
			     int max_paths);

/**
 * tquic_path_metrics_init - Initialize path metrics subsystem
 * @net: Network namespace
 *
 * Returns: 0 on success, negative errno on failure
 */
int __init tquic_path_metrics_init(struct net *net);

/**
 * tquic_path_metrics_exit - Cleanup path metrics subsystem
 * @net: Network namespace
 */
void __exit tquic_path_metrics_exit(struct net *net);

#endif /* _TQUIC_PATH_METRICS_H */
