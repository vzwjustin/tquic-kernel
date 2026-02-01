/* SPDX-License-Identifier: GPL-2.0 */
/*
 * TQUIC Packet Scheduler Public API
 *
 * Copyright (c) 2026 Linux Foundation
 *
 * This header defines the public API for the TQUIC packet scheduling
 * framework, including scheduler operations, path selection results,
 * and per-connection scheduler initialization.
 *
 * The scheduler framework follows the MPTCP scheduler pattern,
 * providing both built-in schedulers and support for external modules.
 */

#ifndef _NET_QUIC_TQUIC_SCHED_H
#define _NET_QUIC_TQUIC_SCHED_H

#include <linux/types.h>
#include <linux/list.h>
#include <linux/module.h>
#include <linux/cache.h>
#include <net/net_namespace.h>

/* Forward declarations */
struct net;

/*
 * =============================================================================
 * Path and Connection Structures
 * =============================================================================
 *
 * These structures define the path and connection state that schedulers
 * need to access for making scheduling decisions.
 */

/*
 * Maximum number of paths supported per connection
 */
#define TQUIC_MAX_PATHS		8

/*
 * Path states
 */
enum tquic_path_state {
	TQUIC_PATH_ACTIVE = 0,		/* Path is active and usable */
	TQUIC_PATH_STANDBY,		/* Path is standby (backup only) */
	TQUIC_PATH_FAILED,		/* Path has failed */
	TQUIC_PATH_PROBING,		/* Path is being probed */
};

/*
 * Per-path statistics
 */
struct tquic_path_stats {
	atomic64_t	packets_sent;
	atomic64_t	bytes_sent;
	atomic64_t	packets_acked;
	atomic64_t	packets_lost;
	atomic64_t	packets_retrans;
	u64		last_send_time;
	u64		last_ack_time;
	u64		rtt_smoothed;	/* Smoothed RTT in microseconds */
};

/*
 * Per-path congestion control state
 */
struct tquic_path_cc {
	u32		cwnd;		/* Congestion window (bytes) */
	u32		ssthresh;	/* Slow start threshold */
	u32		bytes_in_flight;
	u32		mss;		/* Maximum segment size */
	u64		last_rtt_us;	/* Last RTT measurement */
	u64		min_rtt_us;	/* Minimum RTT seen */
	u64		smoothed_rtt_us;/* Smoothed RTT (EWMA) */
	u64		rtt_var_us;	/* RTT variance */
	u32		loss_rate;	/* Loss rate (scaled by 1000) */
	u32		delivered;	/* Bytes delivered */
	u32		lost;		/* Bytes lost */
	u64		bandwidth;	/* Estimated bandwidth (bytes/sec) */
	bool		in_recovery;
	u64		recovery_start;
};

/*
 * Path information for scheduling decisions
 */
struct tquic_path {
	u8			path_id;
	enum tquic_path_state	state;
	u32			weight;		/* Configured weight */
	u32			priority;	/* Priority (lower = higher) */

	struct tquic_path_stats	stats;
	struct tquic_path_cc	cc;

	/* Scheduler-specific data */
	void			*sched_data;

	/* Path validation */
	bool			validated;
	u64			validation_time;

	/* Network interface binding */
	int			ifindex;

	struct list_head	list;
	struct rcu_head		rcu;
};

/*
 * Connection-level scheduler state
 */
struct tquic_connection {
	spinlock_t			lock;
	struct list_head		paths;
	int				num_paths;
	int				active_paths;

	/* Current scheduler */
	struct tquic_sched_ops		*scheduler;
	void				*sched_priv;

	/* Global statistics */
	struct {
		atomic64_t	total_packets;
		atomic64_t	total_bytes;
		atomic64_t	sched_decisions;
		atomic64_t	path_switches;
		atomic64_t	reinjections;
	} stats;

	/* Coupled congestion control */
	bool			coupled_cc;
	u64			aggregate_cwnd;

	/* Connection identifier for hashing */
	u64			conn_id;

	struct rcu_head		rcu;
};

/*
 * Scheduler name maximum length (matches TCP congestion control pattern)
 */
#define TQUIC_SCHED_NAME_MAX	16

/*
 * Scheduler flags for path selection
 *
 * TQUIC_SCHED_REDUNDANT: Request packet duplication on backup path
 *     When set in path_result->flags, the scheduler is requesting that
 *     the packet be sent on both primary and backup paths simultaneously.
 *     This is used for seamless failover and critical traffic.
 */
#define TQUIC_SCHED_REDUNDANT	(1 << 0)

/**
 * struct tquic_sched_path_result - Path selection result
 * @primary: Primary path for packet transmission
 * @backup: Backup path for failover (optional, may be NULL)
 * @flags: Flags affecting transmission (TQUIC_SCHED_REDUNDANT, etc.)
 *
 * This structure is returned by get_path() and provides the scheduler's
 * decision for routing a packet. The primary path is always required;
 * the backup path is optional and used for:
 *   - Immediate failover if primary fails
 *   - Redundant transmission (if TQUIC_SCHED_REDUNDANT is set)
 *
 * Per CONTEXT.md: "get_path() returns primary path + backup path for
 * redundant send capability"
 */
struct tquic_sched_path_result {
	struct tquic_path *primary;	/* Primary path for packet */
	struct tquic_path *backup;	/* Backup path (optional, for failover) */
	u32 flags;			/* TQUIC_SCHED_REDUNDANT if set */
};

/**
 * struct tquic_sched_ops - Scheduler operations vtable
 * @name: Human-readable scheduler name (must be unique, max 16 chars)
 * @owner: Module owner (for module reference counting)
 * @list: Internal list linkage (managed by framework)
 *
 * @get_path: Required - Select path(s) for next packet transmission
 *     Called for each packet to determine routing. Must fill in
 *     result->primary (required) and optionally result->backup.
 *     Returns 0 on success, -EAGAIN if no path available,
 *     -ENOENT if no paths exist.
 *
 * @init: Optional - Initialize scheduler state for a connection
 *     Called when scheduler is assigned to connection.
 *     Returns 0 on success, negative errno on failure.
 *
 * @release: Optional - Release scheduler resources for a connection
 *     Called when connection is destroyed or scheduler changes.
 *
 * @path_added: Optional - Notification that a new path was added
 *     Called after path validation succeeds.
 *
 * @path_removed: Optional - Notification that a path was removed
 *     Called before path is removed from connection.
 *
 * @ack_received: Optional - ACK feedback for scheduler adaptation
 *     Called when ACK is received for packets sent on a path.
 *     Provides delivery confirmation and RTT information.
 *
 * @loss_detected: Optional - Loss feedback for scheduler adaptation
 *     Called when packet loss is detected on a path.
 *     Schedulers can use this to avoid troubled paths.
 *
 * The structure is cache-line aligned for performance on hot paths.
 */
struct tquic_sched_ops {
	char name[TQUIC_SCHED_NAME_MAX];
	struct module *owner;
	struct list_head list;

	/* Required: select path for next packet */
	int (*get_path)(struct tquic_connection *conn,
			struct tquic_sched_path_result *result,
			u32 flags);

	/* Optional lifecycle hooks */
	void (*init)(struct tquic_connection *conn);
	void (*release)(struct tquic_connection *conn);

	/* Optional path events */
	void (*path_added)(struct tquic_connection *conn,
			   struct tquic_path *path);
	void (*path_removed)(struct tquic_connection *conn,
			     struct tquic_path *path);

	/* Optional feedback hooks */
	void (*ack_received)(struct tquic_connection *conn,
			     struct tquic_path *path, u64 acked_bytes);
	void (*loss_detected)(struct tquic_connection *conn,
			      struct tquic_path *path, u64 lost_bytes);
} ____cacheline_aligned_in_smp;

/*
 * =============================================================================
 * Scheduler Registration API
 * =============================================================================
 *
 * These functions manage the global registry of available schedulers.
 * They are typically called from module init/exit or during subsystem init.
 */

/**
 * tquic_register_scheduler - Register a new scheduler
 * @sched: Scheduler operations structure
 *
 * Register a scheduler for use with TQUIC connections. The scheduler's
 * name must be unique. The first registered scheduler becomes the default.
 *
 * Returns 0 on success, -EINVAL if invalid, -EEXIST if name exists.
 */
int tquic_register_scheduler(struct tquic_sched_ops *sched);

/**
 * tquic_unregister_scheduler - Unregister a scheduler
 * @sched: Scheduler to unregister
 *
 * Remove a scheduler from the registry. If this was the default scheduler,
 * another available scheduler becomes the default.
 */
void tquic_unregister_scheduler(struct tquic_sched_ops *sched);

/**
 * tquic_sched_find - Find scheduler by name
 * @name: Scheduler name to search for
 *
 * Look up a scheduler by name. Caller must hold RCU read lock.
 *
 * Returns pointer to scheduler ops, or NULL if not found.
 */
struct tquic_sched_ops *tquic_sched_find(const char *name);

/*
 * =============================================================================
 * Per-Connection Scheduler API
 * =============================================================================
 *
 * These functions manage scheduler assignment for individual connections.
 */

/**
 * tquic_sched_init_conn - Initialize scheduler for a connection
 * @conn: Connection to initialize
 * @name: Scheduler name (NULL to use per-netns default)
 *
 * Initialize the scheduler for a connection. Must be called before
 * the connection is established (state == IDLE).
 *
 * Per CONTEXT.md: "Scheduler locked at connection establishment,
 * cannot change mid-connection"
 *
 * Returns 0 on success, -EISCONN if connection already established,
 * -ENOENT if scheduler not found, -EBUSY if module load fails.
 */
int tquic_sched_init_conn(struct tquic_connection *conn, const char *name);

/**
 * tquic_sched_release_conn - Release scheduler resources for connection
 * @conn: Connection to release
 *
 * Release scheduler state and module reference for a connection.
 * Called during connection teardown.
 */
void tquic_sched_release_conn(struct tquic_connection *conn);

/**
 * tquic_sched_get_path - Get path selection for next packet
 * @conn: Connection to query
 * @result: Path selection result (output)
 * @flags: Scheduling flags
 *
 * Query the scheduler for the path(s) to use for the next packet.
 * This is the main path selection API called from the send path.
 *
 * Returns 0 on success with result filled in, -EAGAIN if no path
 * currently available, -ENOENT if no scheduler assigned.
 */
int tquic_sched_get_path(struct tquic_connection *conn,
			 struct tquic_sched_path_result *result,
			 u32 flags);

/*
 * =============================================================================
 * Per-Netns Default Scheduler API
 * =============================================================================
 *
 * These functions manage the per-network-namespace default scheduler.
 * Containers can have different default schedulers.
 */

/**
 * tquic_sched_set_default - Set default scheduler for a network namespace
 * @net: Network namespace
 * @name: Scheduler name
 *
 * Set the default scheduler for new connections in this namespace.
 * The scheduler is looked up and validated before being set.
 *
 * Returns 0 on success, -ENOENT if scheduler not found,
 * -EBUSY if module get fails.
 */
int tquic_sched_set_default(struct net *net, const char *name);

/**
 * tquic_sched_get_default - Get default scheduler name for a network namespace
 * @net: Network namespace
 *
 * Get the name of the default scheduler for this namespace.
 *
 * Returns scheduler name string (not to be freed), or "aggregate" as fallback.
 */
const char *tquic_sched_get_default(struct net *net);

/* Built-in scheduler: aggregate (default for WAN bonding) */
extern struct tquic_sched_ops tquic_sched_aggregate;

#endif /* _NET_QUIC_TQUIC_SCHED_H */
