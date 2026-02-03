// SPDX-License-Identifier: GPL-2.0
/* TQUIC Packet Scheduler for WAN Bonding
 *
 * Copyright (c) 2024-2026 Linux Foundation
 *
 * This implements packet scheduling algorithms for distributing QUIC
 * packets across multiple WAN paths in a bonded configuration.
 *
 * Schedulers determine which path(s) to use for each outgoing packet,
 * considering factors like RTT, loss rate, bandwidth, and congestion.
 */

#define pr_fmt(fmt) "TQUIC: " fmt

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/list.h>
#include <linux/rculist.h>
#include <linux/spinlock.h>
#include <linux/slab.h>
#include <linux/atomic.h>
#include <linux/jhash.h>
#include <linux/random.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <net/sock.h>
#include <net/net_namespace.h>
#include <net/netns/tquic.h>
#include <net/tquic.h>

/* Public scheduler API */
#include "tquic_sched.h"

/* Failover integration for retransmit queue priority */
#include "tquic_failover.h"

/*
 * Maximum number of paths supported per connection
 */
#define TQUIC_MAX_PATHS		8

/*
 * Scheduler name maximum length
 */
#define TQUIC_SCHED_NAME_MAX	16

/*
 * Default weights and parameters
 */
#define TQUIC_DEFAULT_WEIGHT		100
#define TQUIC_MAX_WEIGHT		1000
#define TQUIC_WEIGHT_SCALE		1000
#define TQUIC_RTT_EWMA_ALPHA		8	/* 1/8 for EWMA */
#define TQUIC_LOSS_EWMA_ALPHA		16	/* 1/16 for EWMA */
#define TQUIC_MIN_RTT_US		1000	/* 1ms minimum RTT */
#define TQUIC_DEFAULT_RTT_US		100000	/* 100ms default RTT */
#define TQUIC_REINJECTION_TIMEOUT_MS	50	/* Reinjection threshold */

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
 * Forward declarations
 */
struct tquic_connection;
struct tquic_path;
struct tquic_scheduler_ops;

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
	struct tquic_scheduler_ops	*sched;
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
 * Scheduler feedback information (from ACK/loss detection)
 */
struct tquic_sched_feedback {
	u8		path_id;
	bool		is_ack;		/* true = ACK, false = loss */
	u64		packet_number;
	u64		rtt_us;		/* RTT if ACK */
	u32		bytes;		/* Bytes acked/lost */
	u64		timestamp;
};

/*
 * Path selection result
 */
struct tquic_path_selection {
	struct tquic_path	*paths[TQUIC_MAX_PATHS];
	int			num_paths;	/* Number of paths selected */
	bool			duplicate;	/* Send on multiple paths */
};

/*
 * Scheduler operations vtable
 */
struct tquic_scheduler_ops {
	char			name[TQUIC_SCHED_NAME_MAX];
	struct module		*owner;
	struct list_head	list;

	/* Initialize scheduler for a connection */
	int (*init)(struct tquic_connection *conn);

	/* Release scheduler resources */
	void (*release)(struct tquic_connection *conn);

	/* Select path(s) for the next packet */
	int (*select_path)(struct tquic_connection *conn,
			   struct tquic_path_selection *sel);

	/* Notification: new path added */
	void (*path_added)(struct tquic_connection *conn,
			   struct tquic_path *path);

	/* Notification: path removed */
	void (*path_removed)(struct tquic_connection *conn,
			     struct tquic_path *path);

	/* Receive feedback (ACK or loss) */
	void (*feedback)(struct tquic_connection *conn,
			 const struct tquic_sched_feedback *fb);

	/* Get scheduler-specific info for diagnostics */
	size_t (*get_info)(struct tquic_connection *conn, char *buf,
			   size_t len);
} ____cacheline_aligned_in_smp;

/*
 * Global scheduler list
 */
static DEFINE_SPINLOCK(tquic_sched_list_lock);
static LIST_HEAD(tquic_sched_list);
static struct tquic_scheduler_ops *tquic_default_scheduler;

/*
 * Procfs for statistics (created per-netns via pernet_operations)
 */

/* =========================================================================
 * Utility Functions
 * ========================================================================= */

static inline u64 tquic_get_time_us(void)
{
	return ktime_get_ns() / 1000;
}

static inline bool tquic_path_usable(const struct tquic_path *path)
{
	return path->state == TQUIC_PATH_ACTIVE && path->validated;
}

static inline bool tquic_path_can_send(const struct tquic_path *path)
{
	if (!tquic_path_usable(path))
		return false;

	/* Check congestion window */
	return path->cc.bytes_in_flight < path->cc.cwnd;
}

static struct tquic_path *tquic_find_path(struct tquic_connection *conn, u8 path_id)
{
	struct tquic_path *path;

	list_for_each_entry_rcu(path, &conn->paths, list) {
		if (path->path_id == path_id)
			return path;
	}
	return NULL;
}

static int tquic_count_active_paths(struct tquic_connection *conn)
{
	struct tquic_path *path;
	int count = 0;

	list_for_each_entry_rcu(path, &conn->paths, list) {
		if (tquic_path_usable(path))
			count++;
	}
	return count;
}

/*
 * Update smoothed RTT using EWMA
 */
static void tquic_update_rtt(struct tquic_path *path, u64 rtt_us)
{
	if (rtt_us < TQUIC_MIN_RTT_US)
		rtt_us = TQUIC_MIN_RTT_US;

	path->cc.last_rtt_us = rtt_us;

	if (rtt_us < path->cc.min_rtt_us || path->cc.min_rtt_us == 0)
		path->cc.min_rtt_us = rtt_us;

	if (path->cc.smoothed_rtt_us == 0) {
		path->cc.smoothed_rtt_us = rtt_us;
		path->cc.rtt_var_us = rtt_us / 2;
	} else {
		u64 delta = (rtt_us > path->cc.smoothed_rtt_us) ?
			    (rtt_us - path->cc.smoothed_rtt_us) :
			    (path->cc.smoothed_rtt_us - rtt_us);

		path->cc.rtt_var_us = (path->cc.rtt_var_us * 3 + delta) / 4;
		path->cc.smoothed_rtt_us =
			(path->cc.smoothed_rtt_us * 7 + rtt_us) / 8;
	}
}

/*
 * Update loss rate using EWMA
 */
static void tquic_update_loss_rate(struct tquic_path *path, u32 acked, u32 lost)
{
	u32 total = acked + lost;
	u32 rate;

	if (total == 0)
		return;

	rate = (lost * TQUIC_WEIGHT_SCALE) / total;

	if (path->cc.loss_rate == 0)
		path->cc.loss_rate = rate;
	else
		path->cc.loss_rate = (path->cc.loss_rate * 15 + rate) / 16;
}

/*
 * Estimate bandwidth based on delivery rate
 */
static void tquic_update_bandwidth(struct tquic_path *path, u64 bytes, u64 interval_us)
{
	u64 bw;

	if (interval_us == 0)
		return;

	/* bytes/sec */
	bw = (bytes * 1000000ULL) / interval_us;

	if (path->cc.bandwidth == 0)
		path->cc.bandwidth = bw;
	else
		path->cc.bandwidth = (path->cc.bandwidth * 7 + bw) / 8;
}

/* =========================================================================
 * Scheduler Framework
 * ========================================================================= */

/*
 * Find scheduler by name (must hold RCU read lock)
 */
struct tquic_scheduler_ops *tquic_sched_find(const char *name)
{
	struct tquic_scheduler_ops *sched;

	list_for_each_entry_rcu(sched, &tquic_sched_list, list) {
		if (!strcmp(sched->name, name))
			return sched;
	}
	return NULL;
}
EXPORT_SYMBOL_GPL(tquic_sched_find);

/*
 * Register a new scheduler
 */
int tquic_sched_register(struct tquic_scheduler_ops *sched)
{
	int ret = 0;

	if (!sched || !sched->name[0] || !sched->select_path) {
		pr_err("Invalid scheduler: missing required ops\n");
		return -EINVAL;
	}

	spin_lock(&tquic_sched_list_lock);

	if (tquic_sched_find(sched->name)) {
		spin_unlock(&tquic_sched_list_lock);
		pr_err("Scheduler '%s' already registered\n", sched->name);
		return -EEXIST;
	}

	list_add_tail_rcu(&sched->list, &tquic_sched_list);

	/* First registered scheduler becomes default */
	if (!tquic_default_scheduler)
		tquic_default_scheduler = sched;

	spin_unlock(&tquic_sched_list_lock);

	pr_info("Registered scheduler: %s\n", sched->name);
	return ret;
}
EXPORT_SYMBOL_GPL(tquic_sched_register);

/*
 * Unregister a scheduler
 */
void tquic_sched_unregister(struct tquic_scheduler_ops *sched)
{
	if (!sched)
		return;

	spin_lock(&tquic_sched_list_lock);

	list_del_rcu(&sched->list);

	if (tquic_default_scheduler == sched) {
		/* Pick new default */
		if (!list_empty(&tquic_sched_list))
			tquic_default_scheduler = list_first_entry(
				&tquic_sched_list, struct tquic_scheduler_ops, list);
		else
			tquic_default_scheduler = NULL;
	}

	spin_unlock(&tquic_sched_list_lock);

	synchronize_rcu();

	pr_info("Unregistered scheduler: %s\n", sched->name);
}
EXPORT_SYMBOL_GPL(tquic_sched_unregister);

/*
 * Get list of available schedulers
 */
void tquic_sched_get_available(char *buf, size_t maxlen)
{
	struct tquic_scheduler_ops *sched;
	size_t offs = 0;

	rcu_read_lock();
	list_for_each_entry_rcu(sched, &tquic_sched_list, list) {
		offs += scnprintf(buf + offs, maxlen - offs, "%s%s",
				  offs == 0 ? "" : " ", sched->name);
		if (offs >= maxlen)
			break;
	}
	rcu_read_unlock();
}
EXPORT_SYMBOL_GPL(tquic_sched_get_available);

/*
 * Set scheduler for a connection
 *
 * Per CONTEXT.md: "Scheduler locked at connection establishment,
 * cannot change mid-connection"
 */
int tquic_sched_set(struct tquic_connection *conn, const char *name)
{
	struct tquic_scheduler_ops *old_sched, *new_sched;
	int ret = 0;

	/* Cannot change scheduler after connection established */
	if (conn->state != TQUIC_CONN_IDLE)
		return -EISCONN;

	rcu_read_lock();
	new_sched = tquic_sched_find(name);
	if (!new_sched) {
		rcu_read_unlock();
		return -ENOENT;
	}

	if (!try_module_get(new_sched->owner)) {
		rcu_read_unlock();
		return -EBUSY;
	}
	rcu_read_unlock();

	spin_lock(&conn->lock);

	old_sched = conn->sched;

	/* Release old scheduler */
	if (old_sched && old_sched->release)
		old_sched->release(conn);

	conn->sched = new_sched;
	conn->sched_priv = NULL;

	/* Initialize new scheduler */
	if (new_sched->init) {
		ret = new_sched->init(conn);
		if (ret) {
			conn->sched = old_sched;
			spin_unlock(&conn->lock);
			module_put(new_sched->owner);
			return ret;
		}
	}

	spin_unlock(&conn->lock);

	if (old_sched)
		module_put(old_sched->owner);

	pr_debug("Connection %llx: scheduler changed to %s\n",
		 conn->conn_id, name);

	return 0;
}
EXPORT_SYMBOL_GPL(tquic_sched_set);

/*
 * Get current scheduler name
 */
const char *tquic_sched_get(struct tquic_connection *conn)
{
	const char *name;

	rcu_read_lock();
	name = conn->sched ? conn->sched->name : "none";
	rcu_read_unlock();

	return name;
}
EXPORT_SYMBOL_GPL(tquic_sched_get);

/* =========================================================================
 * Round-Robin Scheduler
 * ========================================================================= */

struct tquic_rr_data {
	u8	next_path_id;
	u8	last_path_id;
};

static int tquic_rr_init(struct tquic_connection *conn)
{
	struct tquic_rr_data *rr;

	rr = kzalloc(sizeof(*rr), GFP_ATOMIC);
	if (!rr)
		return -ENOMEM;

	rr->next_path_id = 0;
	rr->last_path_id = 0;
	conn->sched_priv = rr;

	return 0;
}

static void tquic_rr_release(struct tquic_connection *conn)
{
	kfree(conn->sched_priv);
	conn->sched_priv = NULL;
}

static int tquic_rr_select_path(struct tquic_connection *conn,
				struct tquic_path_selection *sel)
{
	struct tquic_rr_data *rr = conn->sched_priv;
	struct tquic_path *path, *start_path = NULL;
	struct tquic_path *selected = NULL;
	int attempts = 0;

	sel->num_paths = 0;
	sel->duplicate = false;

	if (conn->num_paths == 0)
		return -ENOENT;

	rcu_read_lock();

	/* Find starting point */
	list_for_each_entry_rcu(path, &conn->paths, list) {
		if (path->path_id >= rr->next_path_id) {
			start_path = path;
			break;
		}
	}

	if (!start_path)
		start_path = list_first_entry_or_null(&conn->paths,
						      struct tquic_path, list);

	if (!start_path) {
		rcu_read_unlock();
		return -ENOENT;
	}

	/* Round-robin through paths, skipping failed/standby */
	path = start_path;
	do {
		if (tquic_path_can_send(path)) {
			selected = path;
			break;
		}

		/* Move to next path (circular) */
		if (list_is_last(&path->list, &conn->paths))
			path = list_first_entry(&conn->paths,
						struct tquic_path, list);
		else
			path = list_next_entry(path, list);

		attempts++;
	} while (path != start_path && attempts < conn->num_paths);

	if (selected) {
		sel->paths[0] = selected;
		sel->num_paths = 1;

		/* Update for next round */
		rr->last_path_id = selected->path_id;
		if (list_is_last(&selected->list, &conn->paths))
			rr->next_path_id = list_first_entry(&conn->paths,
					struct tquic_path, list)->path_id;
		else
			rr->next_path_id = list_next_entry(selected, list)->path_id;

		atomic64_inc(&conn->stats.sched_decisions);
		if (selected->path_id != rr->last_path_id)
			atomic64_inc(&conn->stats.path_switches);
	}

	rcu_read_unlock();

	return selected ? 0 : -EAGAIN;
}

static void tquic_rr_path_added(struct tquic_connection *conn,
				struct tquic_path *path)
{
	pr_debug("RR: path %u added\n", path->path_id);
}

static void tquic_rr_path_removed(struct tquic_connection *conn,
				  struct tquic_path *path)
{
	struct tquic_rr_data *rr = conn->sched_priv;

	if (rr && rr->next_path_id == path->path_id)
		rr->next_path_id = 0;

	pr_debug("RR: path %u removed\n", path->path_id);
}

static struct tquic_scheduler_ops tquic_sched_rr = {
	.name		= "round-robin",
	.owner		= THIS_MODULE,
	.init		= tquic_rr_init,
	.release	= tquic_rr_release,
	.select_path	= tquic_rr_select_path,
	.path_added	= tquic_rr_path_added,
	.path_removed	= tquic_rr_path_removed,
};

/* =========================================================================
 * Weighted Round-Robin Scheduler (Deficit Counter)
 * ========================================================================= */

struct tquic_weighted_path_data {
	u32	deficit;	/* Deficit counter */
	u32	weight;		/* Current weight */
};

struct tquic_weighted_data {
	u8	current_path_idx;
	u32	quantum;	/* Base quantum for deficit */
	struct tquic_weighted_path_data path_data[TQUIC_MAX_PATHS];
};

static int tquic_weighted_init(struct tquic_connection *conn)
{
	struct tquic_weighted_data *wd;
	struct tquic_path *path;
	int i = 0;

	wd = kzalloc(sizeof(*wd), GFP_ATOMIC);
	if (!wd)
		return -ENOMEM;

	wd->quantum = 1500;  /* Default quantum: ~1 MTU */
	wd->current_path_idx = 0;

	/* Initialize path weights from configured weights */
	rcu_read_lock();
	list_for_each_entry_rcu(path, &conn->paths, list) {
		if (i < TQUIC_MAX_PATHS) {
			wd->path_data[i].weight = path->weight;
			wd->path_data[i].deficit = 0;
			i++;
		}
	}
	rcu_read_unlock();

	conn->sched_priv = wd;
	return 0;
}

static void tquic_weighted_release(struct tquic_connection *conn)
{
	kfree(conn->sched_priv);
	conn->sched_priv = NULL;
}

static int tquic_weighted_select_path(struct tquic_connection *conn,
				      struct tquic_path_selection *sel)
{
	struct tquic_weighted_data *wd = conn->sched_priv;
	struct tquic_path *path;
	struct tquic_path *selected = NULL;
	int path_idx, start_idx;
	int rounds = 0;
	u32 max_deficit = 0;

	sel->num_paths = 0;
	sel->duplicate = false;

	if (!wd || conn->num_paths == 0)
		return -ENOENT;

	rcu_read_lock();

	start_idx = wd->current_path_idx % conn->num_paths;
	path_idx = start_idx;

	/*
	 * Deficit Round-Robin: each path has a deficit counter.
	 * When selected, add quantum * weight to deficit.
	 * Send if deficit > 0, then subtract packet size.
	 */
	do {
		int idx = 0;

		list_for_each_entry_rcu(path, &conn->paths, list) {
			if (idx == path_idx) {
				if (tquic_path_can_send(path)) {
					struct tquic_weighted_path_data *pd;

					pd = &wd->path_data[path_idx];

					/* Add weighted quantum to deficit */
					pd->deficit += (wd->quantum * pd->weight) /
						       TQUIC_DEFAULT_WEIGHT;

					if (pd->deficit > max_deficit) {
						max_deficit = pd->deficit;
						selected = path;
						wd->current_path_idx = path_idx;
					}
				}
				break;
			}
			idx++;
		}

		path_idx = (path_idx + 1) % conn->num_paths;
		rounds++;

	} while (path_idx != start_idx && rounds < conn->num_paths * 2);

	if (selected) {
		struct tquic_weighted_path_data *pd;

		pd = &wd->path_data[wd->current_path_idx];

		/* Deduct from deficit (assume MTU-sized packet) */
		if (pd->deficit >= wd->quantum)
			pd->deficit -= wd->quantum;
		else
			pd->deficit = 0;

		sel->paths[0] = selected;
		sel->num_paths = 1;

		/* Move to next path for fairness */
		wd->current_path_idx = (wd->current_path_idx + 1) % conn->num_paths;

		atomic64_inc(&conn->stats.sched_decisions);
	}

	rcu_read_unlock();

	return selected ? 0 : -EAGAIN;
}

/*
 * Set weights for weighted scheduler
 */
int tquic_weighted_set_weights(struct tquic_connection *conn,
			       const u32 *weights, int num_weights)
{
	struct tquic_weighted_data *wd;
	struct tquic_path *path;
	int i;

	spin_lock(&conn->lock);

	wd = conn->sched_priv;
	if (!wd || strcmp(conn->sched->name, "weighted") != 0) {
		spin_unlock(&conn->lock);
		return -EINVAL;
	}

	/* Update path weights */
	i = 0;
	list_for_each_entry(path, &conn->paths, list) {
		if (i < num_weights && i < TQUIC_MAX_PATHS) {
			u32 w = weights[i];

			if (w > TQUIC_MAX_WEIGHT)
				w = TQUIC_MAX_WEIGHT;
			if (w == 0)
				w = 1;

			path->weight = w;
			wd->path_data[i].weight = w;
		}
		i++;
	}

	spin_unlock(&conn->lock);

	return 0;
}
EXPORT_SYMBOL_GPL(tquic_weighted_set_weights);

static void tquic_weighted_path_added(struct tquic_connection *conn,
				      struct tquic_path *path)
{
	struct tquic_weighted_data *wd = conn->sched_priv;
	int idx;

	if (!wd)
		return;

	idx = conn->num_paths - 1;
	if (idx >= 0 && idx < TQUIC_MAX_PATHS) {
		wd->path_data[idx].weight = path->weight;
		wd->path_data[idx].deficit = 0;
	}
}

static void tquic_weighted_path_removed(struct tquic_connection *conn,
					struct tquic_path *path)
{
	struct tquic_weighted_data *wd = conn->sched_priv;

	if (wd && wd->current_path_idx >= conn->num_paths)
		wd->current_path_idx = 0;
}

static struct tquic_scheduler_ops tquic_sched_weighted = {
	.name		= "weighted",
	.owner		= THIS_MODULE,
	.init		= tquic_weighted_init,
	.release	= tquic_weighted_release,
	.select_path	= tquic_weighted_select_path,
	.path_added	= tquic_weighted_path_added,
	.path_removed	= tquic_weighted_path_removed,
};

/* =========================================================================
 * Lowest Latency Scheduler
 * ========================================================================= */

struct tquic_lowlat_data {
	u8	primary_path_id;
	u8	backup_path_id;
	u64	last_rtt_check;
	bool	primary_failed;
};

static int tquic_lowlat_init(struct tquic_connection *conn)
{
	struct tquic_lowlat_data *ld;

	ld = kzalloc(sizeof(*ld), GFP_ATOMIC);
	if (!ld)
		return -ENOMEM;

	ld->primary_path_id = TQUIC_INVALID_PATH_ID;
	ld->backup_path_id = TQUIC_INVALID_PATH_ID;
	ld->primary_failed = false;

	conn->sched_priv = ld;
	return 0;
}

static void tquic_lowlat_release(struct tquic_connection *conn)
{
	kfree(conn->sched_priv);
	conn->sched_priv = NULL;
}

/*
 * Find the path with lowest RTT
 */
static struct tquic_path *tquic_lowlat_find_best(struct tquic_connection *conn,
						 struct tquic_path *exclude)
{
	struct tquic_path *path, *best = NULL;
	u64 min_rtt = U64_MAX;

	list_for_each_entry_rcu(path, &conn->paths, list) {
		u64 rtt;

		if (path == exclude)
			continue;

		if (!tquic_path_can_send(path))
			continue;

		rtt = path->cc.smoothed_rtt_us;
		if (rtt == 0)
			rtt = TQUIC_DEFAULT_RTT_US;

		if (rtt < min_rtt) {
			min_rtt = rtt;
			best = path;
		}
	}

	return best;
}

static int tquic_lowlat_select_path(struct tquic_connection *conn,
				    struct tquic_path_selection *sel)
{
	struct tquic_lowlat_data *ld = conn->sched_priv;
	struct tquic_path *primary, *backup;
	struct tquic_path *selected = NULL;

	sel->num_paths = 0;
	sel->duplicate = false;

	if (!ld || conn->num_paths == 0)
		return -ENOENT;

	rcu_read_lock();

	/* Try to use current primary path */
	primary = tquic_find_path(conn, ld->primary_path_id);

	if (primary && tquic_path_can_send(primary) && !ld->primary_failed) {
		selected = primary;
	} else {
		/* Primary unavailable, find new best path */
		selected = tquic_lowlat_find_best(conn, NULL);

		if (selected) {
			/* Update primary */
			if (primary != selected) {
				ld->backup_path_id = ld->primary_path_id;
				ld->primary_path_id = selected->path_id;
				ld->primary_failed = false;
				atomic64_inc(&conn->stats.path_switches);
			}
		}
	}

	/* If still no path, try backup */
	if (!selected && ld->backup_path_id != TQUIC_INVALID_PATH_ID) {
		backup = tquic_find_path(conn, ld->backup_path_id);
		if (backup && tquic_path_can_send(backup))
			selected = backup;
	}

	if (selected) {
		sel->paths[0] = selected;
		sel->num_paths = 1;
		atomic64_inc(&conn->stats.sched_decisions);
	}

	rcu_read_unlock();

	return selected ? 0 : -EAGAIN;
}

static void tquic_lowlat_feedback(struct tquic_connection *conn,
				  const struct tquic_sched_feedback *fb)
{
	struct tquic_lowlat_data *ld = conn->sched_priv;
	struct tquic_path *path;

	if (!ld)
		return;

	rcu_read_lock();

	path = tquic_find_path(conn, fb->path_id);
	if (!path) {
		rcu_read_unlock();
		return;
	}

	if (fb->is_ack) {
		/* RTT update */
		tquic_update_rtt(path, fb->rtt_us);
		atomic64_add(fb->bytes, &path->stats.packets_acked);

		/* Check if we should switch to a better path */
		if (fb->path_id == ld->primary_path_id) {
			struct tquic_path *better;

			better = tquic_lowlat_find_best(conn, NULL);
			if (better && better != path) {
				/* Switch if significantly better (20% lower RTT) */
				u64 curr_rtt = path->cc.smoothed_rtt_us;
				u64 new_rtt = better->cc.smoothed_rtt_us;

				if (new_rtt > 0 && new_rtt < (curr_rtt * 80 / 100)) {
					ld->backup_path_id = ld->primary_path_id;
					ld->primary_path_id = better->path_id;
					atomic64_inc(&conn->stats.path_switches);
				}
			}
		}
	} else {
		/* Loss detected */
		atomic64_inc(&path->stats.packets_lost);

		/* Mark primary as failed if too many losses */
		if (fb->path_id == ld->primary_path_id) {
			u64 sent = atomic64_read(&path->stats.packets_sent);
			u64 lost = atomic64_read(&path->stats.packets_lost);

			/* If loss rate > 20%, consider path failed */
			if (sent > 10 && (lost * 100 / sent) > 20) {
				ld->primary_failed = true;
				pr_debug("LowLat: primary path %u marked as failed\n",
					 ld->primary_path_id);
			}
		}
	}

	rcu_read_unlock();
}

static void tquic_lowlat_path_added(struct tquic_connection *conn,
				    struct tquic_path *path)
{
	struct tquic_lowlat_data *ld = conn->sched_priv;

	if (!ld)
		return;

	/* If no primary yet, use this path */
	if (ld->primary_path_id == TQUIC_INVALID_PATH_ID)
		ld->primary_path_id = path->path_id;
	else if (ld->backup_path_id == TQUIC_INVALID_PATH_ID)
		ld->backup_path_id = path->path_id;
}

static void tquic_lowlat_path_removed(struct tquic_connection *conn,
				      struct tquic_path *path)
{
	struct tquic_lowlat_data *ld = conn->sched_priv;

	if (!ld)
		return;

	if (ld->primary_path_id == path->path_id) {
		ld->primary_path_id = ld->backup_path_id;
		ld->backup_path_id = TQUIC_INVALID_PATH_ID;
		ld->primary_failed = false;
	} else if (ld->backup_path_id == path->path_id) {
		ld->backup_path_id = TQUIC_INVALID_PATH_ID;
	}
}

static struct tquic_scheduler_ops tquic_sched_lowlat = {
	.name		= "lowlat",
	.owner		= THIS_MODULE,
	.init		= tquic_lowlat_init,
	.release	= tquic_lowlat_release,
	.select_path	= tquic_lowlat_select_path,
	.feedback	= tquic_lowlat_feedback,
	.path_added	= tquic_lowlat_path_added,
	.path_removed	= tquic_lowlat_path_removed,
};

/* =========================================================================
 * Redundant Scheduler (Send on Multiple Paths)
 * ========================================================================= */

struct tquic_redundant_data {
	u8	redundancy_level;	/* Number of paths to use */
	bool	all_paths;		/* Use all available paths */
	u64	last_seq_sent;
	u8	dedup_window[256];	/* Received sequence dedup */
	u16	dedup_head;
};

static int tquic_redundant_init(struct tquic_connection *conn)
{
	struct tquic_redundant_data *rd;

	rd = kzalloc(sizeof(*rd), GFP_ATOMIC);
	if (!rd)
		return -ENOMEM;

	rd->redundancy_level = 2;  /* Default: send on 2 paths */
	rd->all_paths = false;
	rd->dedup_head = 0;

	conn->sched_priv = rd;
	return 0;
}

static void tquic_redundant_release(struct tquic_connection *conn)
{
	kfree(conn->sched_priv);
	conn->sched_priv = NULL;
}

static int tquic_redundant_select_path(struct tquic_connection *conn,
				       struct tquic_path_selection *sel)
{
	struct tquic_redundant_data *rd = conn->sched_priv;
	struct tquic_path *path;
	int count = 0;
	int target;

	sel->num_paths = 0;
	sel->duplicate = true;  /* Redundant scheduler duplicates */

	if (!rd || conn->num_paths == 0)
		return -ENOENT;

	target = rd->all_paths ? TQUIC_MAX_PATHS : rd->redundancy_level;

	rcu_read_lock();

	/*
	 * Select multiple paths ordered by priority/RTT
	 * We prefer paths with lower RTT for primary copies
	 */
	list_for_each_entry_rcu(path, &conn->paths, list) {
		if (!tquic_path_can_send(path))
			continue;

		if (count < target && count < TQUIC_MAX_PATHS) {
			/* Insert sorted by RTT */
			int i;
			u64 path_rtt = path->cc.smoothed_rtt_us;

			if (path_rtt == 0)
				path_rtt = TQUIC_DEFAULT_RTT_US;

			for (i = count; i > 0; i--) {
				u64 other_rtt = sel->paths[i-1]->cc.smoothed_rtt_us;

				if (other_rtt == 0)
					other_rtt = TQUIC_DEFAULT_RTT_US;

				if (path_rtt >= other_rtt)
					break;

				sel->paths[i] = sel->paths[i-1];
			}
			sel->paths[i] = path;
			count++;
		}
	}

	sel->num_paths = count;

	if (count > 0)
		atomic64_inc(&conn->stats.sched_decisions);

	rcu_read_unlock();

	return count > 0 ? 0 : -EAGAIN;
}

/*
 * Set redundancy level
 */
int tquic_redundant_set_level(struct tquic_connection *conn, u8 level)
{
	struct tquic_redundant_data *rd;

	spin_lock(&conn->lock);

	rd = conn->sched_priv;
	if (!rd || strcmp(conn->sched->name, "redundant") != 0) {
		spin_unlock(&conn->lock);
		return -EINVAL;
	}

	if (level == 0) {
		rd->all_paths = true;
	} else {
		rd->all_paths = false;
		rd->redundancy_level = min_t(u8, level, TQUIC_MAX_PATHS);
	}

	spin_unlock(&conn->lock);

	return 0;
}
EXPORT_SYMBOL_GPL(tquic_redundant_set_level);

/*
 * Check if packet is duplicate (for receive-side deduplication)
 */
bool tquic_redundant_is_duplicate(struct tquic_connection *conn, u64 seq)
{
	struct tquic_redundant_data *rd;
	u8 seq_byte;
	int i;

	rd = conn->sched_priv;
	if (!rd)
		return false;

	seq_byte = (u8)(seq & 0xFF);

	/* Check recent sequence numbers */
	for (i = 0; i < 256; i++) {
		if (rd->dedup_window[i] == seq_byte) {
			return true;  /* Duplicate found */
		}
	}

	/* Not a duplicate, record it */
	rd->dedup_window[rd->dedup_head] = seq_byte;
	rd->dedup_head = (rd->dedup_head + 1) & 0xFF;

	return false;
}
EXPORT_SYMBOL_GPL(tquic_redundant_is_duplicate);

static void tquic_redundant_path_added(struct tquic_connection *conn,
				       struct tquic_path *path)
{
	pr_debug("Redundant: path %u added\n", path->path_id);
}

static void tquic_redundant_path_removed(struct tquic_connection *conn,
					 struct tquic_path *path)
{
	pr_debug("Redundant: path %u removed\n", path->path_id);
}

static struct tquic_scheduler_ops tquic_sched_redundant = {
	.name		= "redundant",
	.owner		= THIS_MODULE,
	.init		= tquic_redundant_init,
	.release	= tquic_redundant_release,
	.select_path	= tquic_redundant_select_path,
	.path_added	= tquic_redundant_path_added,
	.path_removed	= tquic_redundant_path_removed,
};

/* =========================================================================
 * Adaptive/Intelligent Scheduler
 * ========================================================================= */

/*
 * Path scoring factors (scaled by 1000)
 */
#define ADAPTIVE_RTT_WEIGHT		400
#define ADAPTIVE_LOSS_WEIGHT		300
#define ADAPTIVE_BW_WEIGHT		200
#define ADAPTIVE_CWND_WEIGHT		100

/*
 * Adaptive scheduler state
 */
struct tquic_adaptive_path_state {
	u64	score;			/* Computed path score */
	u32	recent_loss_count;
	u64	last_score_update;
	bool	in_penalty;		/* Temporarily penalized */
	u64	penalty_until;
};

struct tquic_adaptive_data {
	struct tquic_adaptive_path_state path_state[TQUIC_MAX_PATHS];

	/* Coupled congestion control (MPTCP-like) */
	bool	coupled_cc;
	u64	alpha;			/* Coupling factor */
	u64	total_cwnd;

	/* Reinjection state */
	bool	reinjection_enabled;
	u64	reinject_threshold_us;	/* RTT threshold for reinjection */

	/* Scoring parameters (tunable) */
	u32	rtt_weight;
	u32	loss_weight;
	u32	bw_weight;
	u32	cwnd_weight;

	/* Statistics */
	u64	reinjections;
	u64	score_updates;
};

static int tquic_adaptive_init(struct tquic_connection *conn)
{
	struct tquic_adaptive_data *ad;

	ad = kzalloc(sizeof(*ad), GFP_ATOMIC);
	if (!ad)
		return -ENOMEM;

	/* Default weights */
	ad->rtt_weight = ADAPTIVE_RTT_WEIGHT;
	ad->loss_weight = ADAPTIVE_LOSS_WEIGHT;
	ad->bw_weight = ADAPTIVE_BW_WEIGHT;
	ad->cwnd_weight = ADAPTIVE_CWND_WEIGHT;

	/* Enable coupled CC by default */
	ad->coupled_cc = true;
	ad->alpha = TQUIC_WEIGHT_SCALE;  /* Start at 1.0 */

	/* Enable reinjection by default */
	ad->reinjection_enabled = true;
	ad->reinject_threshold_us = TQUIC_REINJECTION_TIMEOUT_MS * 1000;

	conn->sched_priv = ad;
	conn->coupled_cc = ad->coupled_cc;

	return 0;
}

static void tquic_adaptive_release(struct tquic_connection *conn)
{
	kfree(conn->sched_priv);
	conn->sched_priv = NULL;
}

/*
 * Calculate path score (higher is better)
 */
static u64 tquic_adaptive_calc_score(struct tquic_adaptive_data *ad,
				     struct tquic_path *path,
				     struct tquic_adaptive_path_state *ps)
{
	u64 score = 0;
	u64 rtt_score, loss_score, bw_score, cwnd_score;
	u64 rtt_us, max_bw, cwnd_avail;

	/* RTT score: lower RTT = higher score */
	rtt_us = path->cc.smoothed_rtt_us;
	if (rtt_us == 0)
		rtt_us = TQUIC_DEFAULT_RTT_US;

	/* Normalize RTT to 0-1000 range (assuming max RTT of 500ms) */
	if (rtt_us > 500000)
		rtt_score = 0;
	else
		rtt_score = ((500000 - rtt_us) * 1000) / 500000;

	/* Loss score: lower loss rate = higher score */
	if (path->cc.loss_rate > 500)  /* >50% loss */
		loss_score = 0;
	else
		loss_score = ((500 - path->cc.loss_rate) * 1000) / 500;

	/* Bandwidth score: higher bandwidth = higher score */
	max_bw = 125000000ULL;  /* Assume 1Gbps max */
	if (path->cc.bandwidth >= max_bw)
		bw_score = 1000;
	else
		bw_score = (path->cc.bandwidth * 1000) / max_bw;

	/* CWND availability score */
	if (path->cc.cwnd == 0)
		cwnd_score = 0;
	else {
		cwnd_avail = path->cc.cwnd - path->cc.bytes_in_flight;
		cwnd_score = (cwnd_avail * 1000) / path->cc.cwnd;
	}

	/* Weighted combination */
	score = (rtt_score * ad->rtt_weight +
		 loss_score * ad->loss_weight +
		 bw_score * ad->bw_weight +
		 cwnd_score * ad->cwnd_weight) / 1000;

	/* Apply penalty if path is temporarily penalized */
	if (ps->in_penalty) {
		u64 now = tquic_get_time_us();
		if (now < ps->penalty_until)
			score = score / 4;  /* 75% reduction */
		else
			ps->in_penalty = false;
	}

	ps->score = score;
	ps->last_score_update = tquic_get_time_us();

	return score;
}

/*
 * Update coupled congestion control alpha
 * Based on MPTCP's LIA (Linked Increases Algorithm)
 */
static void tquic_adaptive_update_alpha(struct tquic_adaptive_data *ad,
					struct tquic_connection *conn)
{
	struct tquic_path *path;
	u64 max_rtt = 0;
	u64 sum_cwnd = 0;
	u64 sum_rtt_cwnd = 0;

	if (!ad->coupled_cc)
		return;

	rcu_read_lock();

	/* Calculate max RTT and sums */
	list_for_each_entry_rcu(path, &conn->paths, list) {
		if (!tquic_path_usable(path))
			continue;

		u64 rtt = path->cc.smoothed_rtt_us;
		if (rtt == 0)
			rtt = TQUIC_DEFAULT_RTT_US;

		if (rtt > max_rtt)
			max_rtt = rtt;

		sum_cwnd += path->cc.cwnd;
		sum_rtt_cwnd += path->cc.cwnd / rtt;
	}

	rcu_read_unlock();

	/* LIA alpha calculation:
	 * alpha = (total_cwnd * max_rtt^2) / sum(cwnd_i / rtt_i)^2
	 * Simplified to avoid overflow
	 */
	if (sum_rtt_cwnd > 0 && max_rtt > 0) {
		u64 numerator = sum_cwnd * (max_rtt / 1000);
		u64 denominator = (sum_rtt_cwnd * sum_rtt_cwnd) / 1000;

		if (denominator > 0)
			ad->alpha = numerator / denominator;
		else
			ad->alpha = TQUIC_WEIGHT_SCALE;

		/* Clamp alpha */
		if (ad->alpha > TQUIC_WEIGHT_SCALE * 10)
			ad->alpha = TQUIC_WEIGHT_SCALE * 10;
		if (ad->alpha < TQUIC_WEIGHT_SCALE / 10)
			ad->alpha = TQUIC_WEIGHT_SCALE / 10;
	}

	ad->total_cwnd = sum_cwnd;
	conn->aggregate_cwnd = sum_cwnd;
}

static int tquic_adaptive_select_path(struct tquic_connection *conn,
				      struct tquic_path_selection *sel)
{
	struct tquic_adaptive_data *ad = conn->sched_priv;
	struct tquic_path *path, *best_path = NULL;
	u64 best_score = 0;
	int path_idx = 0;

	sel->num_paths = 0;
	sel->duplicate = false;

	if (!ad || conn->num_paths == 0)
		return -ENOENT;

	rcu_read_lock();

	/* Update alpha for coupled CC */
	tquic_adaptive_update_alpha(ad, conn);

	/* Find path with highest score */
	list_for_each_entry_rcu(path, &conn->paths, list) {
		struct tquic_adaptive_path_state *ps;
		u64 score;

		if (!tquic_path_can_send(path)) {
			path_idx++;
			continue;
		}

		ps = &ad->path_state[path_idx % TQUIC_MAX_PATHS];
		score = tquic_adaptive_calc_score(ad, path, ps);

		if (score > best_score || best_path == NULL) {
			best_score = score;
			best_path = path;
		}

		path_idx++;
		ad->score_updates++;
	}

	if (best_path) {
		sel->paths[0] = best_path;
		sel->num_paths = 1;
		atomic64_inc(&conn->stats.sched_decisions);
	}

	rcu_read_unlock();

	return best_path ? 0 : -EAGAIN;
}

static void tquic_adaptive_feedback(struct tquic_connection *conn,
				    const struct tquic_sched_feedback *fb)
{
	struct tquic_adaptive_data *ad = conn->sched_priv;
	struct tquic_path *path;
	int path_idx = 0;

	if (!ad)
		return;

	rcu_read_lock();

	/* Find path and its state */
	list_for_each_entry_rcu(path, &conn->paths, list) {
		if (path->path_id == fb->path_id)
			break;
		path_idx++;
	}

	if (path->path_id != fb->path_id) {
		rcu_read_unlock();
		return;
	}

	if (fb->is_ack) {
		struct tquic_adaptive_path_state *ps;

		/* Update RTT */
		tquic_update_rtt(path, fb->rtt_us);

		/* Update bandwidth estimate */
		if (fb->rtt_us > 0)
			tquic_update_bandwidth(path, fb->bytes, fb->rtt_us);

		/* Update statistics */
		atomic64_add(fb->bytes, &path->stats.packets_acked);
		path->cc.delivered += fb->bytes;

		/* Clear loss count on successful ACKs */
		ps = &ad->path_state[path_idx % TQUIC_MAX_PATHS];
		if (ps->recent_loss_count > 0)
			ps->recent_loss_count--;

		/* Coupled CC: increase cwnd */
		if (ad->coupled_cc && path->cc.cwnd < path->cc.ssthresh) {
			/* Slow start */
			path->cc.cwnd += fb->bytes;
		} else if (ad->coupled_cc) {
			/* Congestion avoidance with LIA */
			u64 increase = (fb->bytes * ad->alpha * path->cc.mss) /
				       (ad->total_cwnd * TQUIC_WEIGHT_SCALE);
			if (increase < 1)
				increase = 1;
			path->cc.cwnd += increase;
		}
	} else {
		struct tquic_adaptive_path_state *ps;

		/* Loss detected */
		atomic64_inc(&path->stats.packets_lost);
		path->cc.lost += fb->bytes;

		/* Update loss rate */
		tquic_update_loss_rate(path, path->cc.delivered, path->cc.lost);

		/* Penalize path on repeated losses */
		ps = &ad->path_state[path_idx % TQUIC_MAX_PATHS];
		ps->recent_loss_count++;

		if (ps->recent_loss_count >= 3 && !ps->in_penalty) {
			/* Apply temporary penalty */
			ps->in_penalty = true;
			ps->penalty_until = tquic_get_time_us() +
					    path->cc.smoothed_rtt_us * 4;
		}

		/* Coupled CC: decrease cwnd */
		if (ad->coupled_cc && !path->cc.in_recovery) {
			path->cc.in_recovery = true;
			path->cc.recovery_start = fb->packet_number;
			path->cc.ssthresh = path->cc.cwnd / 2;
			if (path->cc.ssthresh < 2 * path->cc.mss)
				path->cc.ssthresh = 2 * path->cc.mss;
			path->cc.cwnd = path->cc.ssthresh;
		}

		/* Consider reinjection on different path */
		if (ad->reinjection_enabled && conn->num_paths > 1) {
			atomic64_inc(&conn->stats.reinjections);
			ad->reinjections++;
		}
	}

	rcu_read_unlock();
}

static void tquic_adaptive_path_added(struct tquic_connection *conn,
				      struct tquic_path *path)
{
	struct tquic_adaptive_data *ad = conn->sched_priv;
	int idx;

	if (!ad)
		return;

	/* Initialize path state */
	idx = (conn->num_paths - 1) % TQUIC_MAX_PATHS;
	memset(&ad->path_state[idx], 0, sizeof(ad->path_state[idx]));

	/* Update coupled CC */
	tquic_adaptive_update_alpha(ad, conn);

	pr_debug("Adaptive: path %u added, total paths: %d\n",
		 path->path_id, conn->num_paths);
}

static void tquic_adaptive_path_removed(struct tquic_connection *conn,
					struct tquic_path *path)
{
	struct tquic_adaptive_data *ad = conn->sched_priv;

	if (!ad)
		return;

	/* Update coupled CC */
	tquic_adaptive_update_alpha(ad, conn);

	pr_debug("Adaptive: path %u removed, total paths: %d\n",
		 path->path_id, conn->num_paths);
}

static size_t tquic_adaptive_get_info(struct tquic_connection *conn,
				      char *buf, size_t len)
{
	struct tquic_adaptive_data *ad = conn->sched_priv;

	if (!ad)
		return 0;

	return scnprintf(buf, len,
			 "alpha=%llu total_cwnd=%llu reinjections=%llu "
			 "coupled_cc=%d score_updates=%llu",
			 ad->alpha, ad->total_cwnd, ad->reinjections,
			 ad->coupled_cc, ad->score_updates);
}

/*
 * Configure adaptive scheduler parameters
 */
int tquic_adaptive_configure(struct tquic_connection *conn,
			     bool coupled_cc, bool reinjection,
			     u32 rtt_weight, u32 loss_weight,
			     u32 bw_weight, u32 cwnd_weight)
{
	struct tquic_adaptive_data *ad;

	spin_lock(&conn->lock);

	ad = conn->sched_priv;
	if (!ad || strcmp(conn->sched->name, "adaptive") != 0) {
		spin_unlock(&conn->lock);
		return -EINVAL;
	}

	ad->coupled_cc = coupled_cc;
	conn->coupled_cc = coupled_cc;
	ad->reinjection_enabled = reinjection;

	/* Validate weights sum to 1000 */
	if (rtt_weight + loss_weight + bw_weight + cwnd_weight != 1000) {
		spin_unlock(&conn->lock);
		return -EINVAL;
	}

	ad->rtt_weight = rtt_weight;
	ad->loss_weight = loss_weight;
	ad->bw_weight = bw_weight;
	ad->cwnd_weight = cwnd_weight;

	spin_unlock(&conn->lock);

	return 0;
}
EXPORT_SYMBOL_GPL(tquic_adaptive_configure);

/*
 * Request packet reinjection on a different path
 */
int tquic_adaptive_reinject(struct tquic_connection *conn,
			    u64 packet_number, u8 original_path_id)
{
	struct tquic_adaptive_data *ad;
	struct tquic_path *path, *best = NULL;
	u64 best_score = 0;
	int path_idx = 0;

	spin_lock(&conn->lock);

	ad = conn->sched_priv;
	if (!ad || !ad->reinjection_enabled) {
		spin_unlock(&conn->lock);
		return -EINVAL;
	}

	/* Find best path excluding original */
	list_for_each_entry(path, &conn->paths, list) {
		struct tquic_adaptive_path_state *ps;
		u64 score;

		if (path->path_id == original_path_id) {
			path_idx++;
			continue;
		}

		if (!tquic_path_can_send(path)) {
			path_idx++;
			continue;
		}

		ps = &ad->path_state[path_idx % TQUIC_MAX_PATHS];
		score = ps->score;

		if (score > best_score || best == NULL) {
			best_score = score;
			best = path;
		}
		path_idx++;
	}

	spin_unlock(&conn->lock);

	if (!best)
		return -ENOENT;

	/* Caller should send packet on best->path_id */
	return best->path_id;
}
EXPORT_SYMBOL_GPL(tquic_adaptive_reinject);

static struct tquic_scheduler_ops tquic_sched_adaptive = {
	.name		= "adaptive",
	.owner		= THIS_MODULE,
	.init		= tquic_adaptive_init,
	.release	= tquic_adaptive_release,
	.select_path	= tquic_adaptive_select_path,
	.feedback	= tquic_adaptive_feedback,
	.path_added	= tquic_adaptive_path_added,
	.path_removed	= tquic_adaptive_path_removed,
	.get_info	= tquic_adaptive_get_info,
};

/* =========================================================================
 * Connection and Path Management
 * ========================================================================= */

/*
 * Initialize a new connection
 */
struct tquic_connection *tquic_connection_alloc(u64 conn_id, gfp_t gfp)
{
	struct tquic_connection *conn;

	conn = kzalloc(sizeof(*conn), gfp);
	if (!conn)
		return NULL;

	spin_lock_init(&conn->lock);
	INIT_LIST_HEAD(&conn->paths);
	conn->conn_id = conn_id;
	conn->num_paths = 0;
	conn->active_paths = 0;

	/* Set default scheduler */
	rcu_read_lock();
	conn->sched = tquic_default_scheduler;
	if (conn->sched && !try_module_get(conn->sched->owner)) {
		conn->sched = NULL;
	}
	rcu_read_unlock();

	if (conn->sched && conn->sched->init) {
		if (conn->sched->init(conn)) {
			if (conn->sched)
				module_put(conn->sched->owner);
			kfree(conn);
			return NULL;
		}
	}

	return conn;
}
EXPORT_SYMBOL_GPL(tquic_connection_alloc);

/*
 * Free a connection
 */
void tquic_connection_free(struct tquic_connection *conn)
{
	struct tquic_path *path, *tmp;

	if (!conn)
		return;

	spin_lock(&conn->lock);

	/* Release scheduler */
	if (conn->sched) {
		if (conn->sched->release)
			conn->sched->release(conn);
		module_put(conn->sched->owner);
	}

	/* Free all paths */
	list_for_each_entry_safe(path, tmp, &conn->paths, list) {
		list_del(&path->list);
		kfree(path->sched_data);
		kfree(path);
	}

	spin_unlock(&conn->lock);

	kfree(conn);
}
EXPORT_SYMBOL_GPL(tquic_connection_free);

/*
 * Add a path to a connection
 */
struct tquic_path *tquic_path_add(struct tquic_connection *conn, u8 path_id,
				  int ifindex, gfp_t gfp)
{
	struct tquic_path *path;

	path = kzalloc(sizeof(*path), gfp);
	if (!path)
		return NULL;

	path->path_id = path_id;
	path->state = TQUIC_PATH_PROBING;
	path->weight = TQUIC_DEFAULT_WEIGHT;
	path->priority = 0;
	path->ifindex = ifindex;
	path->validated = false;

	/* Initialize congestion control */
	path->cc.mss = 1200;  /* QUIC default */
	path->cc.cwnd = 10 * path->cc.mss;  /* Initial window */
	path->cc.ssthresh = U32_MAX;
	path->cc.smoothed_rtt_us = 0;
	path->cc.min_rtt_us = 0;

	INIT_LIST_HEAD(&path->list);

	spin_lock(&conn->lock);

	/* Check for duplicate */
	if (tquic_find_path(conn, path_id)) {
		spin_unlock(&conn->lock);
		kfree(path);
		return NULL;
	}

	list_add_tail_rcu(&path->list, &conn->paths);
	conn->num_paths++;

	/* Notify scheduler */
	if (conn->sched && conn->sched->path_added)
		conn->sched->path_added(conn, path);

	spin_unlock(&conn->lock);

	return path;
}
EXPORT_SYMBOL_GPL(tquic_path_add);

/*
 * Remove a path from a connection
 */
void tquic_path_remove(struct tquic_connection *conn, u8 path_id)
{
	struct tquic_path *path;

	spin_lock(&conn->lock);

	path = tquic_find_path(conn, path_id);
	if (!path) {
		spin_unlock(&conn->lock);
		return;
	}

	/* Notify scheduler before removal */
	if (conn->sched && conn->sched->path_removed)
		conn->sched->path_removed(conn, path);

	list_del_rcu(&path->list);
	conn->num_paths--;

	if (path->state == TQUIC_PATH_ACTIVE)
		conn->active_paths--;

	spin_unlock(&conn->lock);

	synchronize_rcu();

	kfree(path->sched_data);
	kfree(path);
}
EXPORT_SYMBOL_GPL(tquic_path_remove);

/*
 * Mark a path as validated and active
 */
void tquic_path_validate(struct tquic_connection *conn, u8 path_id)
{
	struct tquic_path *path;

	spin_lock(&conn->lock);

	path = tquic_find_path(conn, path_id);
	if (path && !path->validated) {
		path->validated = true;
		path->validation_time = tquic_get_time_us();
		path->state = TQUIC_PATH_ACTIVE;
		conn->active_paths++;
	}

	spin_unlock(&conn->lock);
}
EXPORT_SYMBOL_GPL(tquic_path_validate);

/*
 * Set path state
 */
void tquic_path_set_state(struct tquic_connection *conn, u8 path_id,
			  enum tquic_path_state state)
{
	struct tquic_path *path;
	enum tquic_path_state old_state;

	spin_lock(&conn->lock);

	path = tquic_find_path(conn, path_id);
	if (!path) {
		spin_unlock(&conn->lock);
		return;
	}

	old_state = path->state;
	path->state = state;

	/* Update active count */
	if (old_state == TQUIC_PATH_ACTIVE && state != TQUIC_PATH_ACTIVE)
		conn->active_paths--;
	else if (old_state != TQUIC_PATH_ACTIVE && state == TQUIC_PATH_ACTIVE)
		conn->active_paths++;

	spin_unlock(&conn->lock);
}
EXPORT_SYMBOL_GPL(tquic_path_set_state);

/*
 * Check if failover queue has pending retransmissions
 *
 * The failover context is accessed through the connection's scheduler pointer,
 * which may point to a path manager with a bonding context containing failover.
 * For now, we provide a direct API via the failover context.
 */

/**
 * tquic_sched_has_failover_pending - Check for pending failover retransmissions
 * @fc: Failover context (from bonding)
 *
 * Returns true if there are packets awaiting retransmission.
 * Scheduler should check this before pulling new data.
 */
bool tquic_sched_has_failover_pending(struct tquic_failover_ctx *fc)
{
	return tquic_failover_has_pending(fc);
}
EXPORT_SYMBOL_GPL(tquic_sched_has_failover_pending);

/**
 * tquic_sched_get_failover_packet - Get next packet from failover retransmit queue
 * @fc: Failover context
 *
 * Returns the next packet to retransmit, or NULL if queue is empty.
 * Caller should retransmit this packet before sending new data.
 */
struct tquic_sent_packet *tquic_sched_get_failover_packet(struct tquic_failover_ctx *fc)
{
	return tquic_failover_get_next(fc);
}
EXPORT_SYMBOL_GPL(tquic_sched_get_failover_packet);

/*
 * Select path(s) for sending
 */
int tquic_select_path(struct tquic_connection *conn,
		      struct tquic_path_selection *sel)
{
	int ret;

	if (!conn || !conn->sched || !sel)
		return -EINVAL;

	rcu_read_lock();
	ret = conn->sched->select_path(conn, sel);
	rcu_read_unlock();

	return ret;
}
EXPORT_SYMBOL_GPL(tquic_select_path);

/*
 * Report feedback to scheduler
 */
void tquic_sched_feedback(struct tquic_connection *conn,
			  const struct tquic_sched_feedback *fb)
{
	if (!conn || !fb)
		return;

	rcu_read_lock();

	/* Update path statistics directly */
	struct tquic_path *path = tquic_find_path(conn, fb->path_id);
	if (path) {
		if (fb->is_ack) {
			tquic_update_rtt(path, fb->rtt_us);
			atomic64_inc(&path->stats.packets_acked);
		} else {
			atomic64_inc(&path->stats.packets_lost);
		}
	}

	/* Notify scheduler */
	if (conn->sched && conn->sched->feedback)
		conn->sched->feedback(conn, fb);

	rcu_read_unlock();
}
EXPORT_SYMBOL_GPL(tquic_sched_feedback);

/*
 * Record packet sent on path
 */
void tquic_path_packet_sent(struct tquic_connection *conn, u8 path_id,
			    u32 bytes)
{
	struct tquic_path *path;

	rcu_read_lock();

	path = tquic_find_path(conn, path_id);
	if (path) {
		atomic64_inc(&path->stats.packets_sent);
		atomic64_add(bytes, &path->stats.bytes_sent);
		path->stats.last_send_time = tquic_get_time_us();
		path->cc.bytes_in_flight += bytes;
	}

	atomic64_inc(&conn->stats.total_packets);
	atomic64_add(bytes, &conn->stats.total_bytes);

	rcu_read_unlock();
}
EXPORT_SYMBOL_GPL(tquic_path_packet_sent);

/*
 * Record packet ACKed on path
 */
void tquic_path_packet_acked(struct tquic_connection *conn, u8 path_id,
			     u32 bytes, u64 rtt_us)
{
	struct tquic_sched_feedback fb = {
		.path_id = path_id,
		.is_ack = true,
		.rtt_us = rtt_us,
		.bytes = bytes,
		.timestamp = tquic_get_time_us(),
	};

	rcu_read_lock();

	struct tquic_path *path = tquic_find_path(conn, path_id);
	if (path) {
		if (path->cc.bytes_in_flight >= bytes)
			path->cc.bytes_in_flight -= bytes;
		else
			path->cc.bytes_in_flight = 0;

		path->stats.last_ack_time = fb.timestamp;

		/* Exit recovery if ACK covers recovery point */
		if (path->cc.in_recovery &&
		    fb.packet_number >= path->cc.recovery_start) {
			path->cc.in_recovery = false;
		}
	}

	rcu_read_unlock();

	tquic_sched_feedback(conn, &fb);
}
EXPORT_SYMBOL_GPL(tquic_path_packet_acked);

/*
 * Record packet lost on path
 */
void tquic_path_packet_lost(struct tquic_connection *conn, u8 path_id,
			    u64 packet_number, u32 bytes)
{
	struct tquic_sched_feedback fb = {
		.path_id = path_id,
		.is_ack = false,
		.packet_number = packet_number,
		.bytes = bytes,
		.timestamp = tquic_get_time_us(),
	};

	rcu_read_lock();

	struct tquic_path *path = tquic_find_path(conn, path_id);
	if (path) {
		if (path->cc.bytes_in_flight >= bytes)
			path->cc.bytes_in_flight -= bytes;
		else
			path->cc.bytes_in_flight = 0;

		atomic64_inc(&path->stats.packets_retrans);
	}

	rcu_read_unlock();

	tquic_sched_feedback(conn, &fb);
}
EXPORT_SYMBOL_GPL(tquic_path_packet_lost);

/* =========================================================================
 * Statistics and Procfs
 * ========================================================================= */

static int tquic_sched_stats_show(struct seq_file *m, void *v)
{
	struct tquic_scheduler_ops *sched;
	struct net *net = seq_file_net(m);
	const char *default_name;

	seq_puts(m, "TQUIC Packet Schedulers\n");
	seq_puts(m, "========================\n\n");

	/* Get per-netns default scheduler name */
	default_name = tquic_sched_get_default(net);
	if (!default_name)
		default_name = "aggregate";

	seq_printf(m, "Namespace default: %s\n\n", default_name);
	seq_puts(m, "Available schedulers:\n");

	rcu_read_lock();
	list_for_each_entry_rcu(sched, &tquic_sched_list, list) {
		bool is_default = (strcmp(sched->name, default_name) == 0);
		seq_printf(m, "  %s%s\n", sched->name,
			   is_default ? " (default)" : "");
	}
	rcu_read_unlock();

	seq_puts(m, "\n");

	return 0;
}

static int tquic_sched_stats_open(struct inode *inode, struct file *file)
{
	return single_open_net(inode, file, tquic_sched_stats_show);
}

static const struct proc_ops tquic_sched_stats_ops = {
	.proc_open	= tquic_sched_stats_open,
	.proc_read	= seq_read,
	.proc_lseek	= seq_lseek,
	.proc_release	= single_release_net,
};

/*
 * Get connection statistics
 */
void tquic_get_conn_stats(struct tquic_connection *conn,
			  u64 *total_packets, u64 *total_bytes,
			  u64 *sched_decisions, u64 *path_switches,
			  u64 *reinjections)
{
	if (!conn)
		return;

	if (total_packets)
		*total_packets = atomic64_read(&conn->stats.total_packets);
	if (total_bytes)
		*total_bytes = atomic64_read(&conn->stats.total_bytes);
	if (sched_decisions)
		*sched_decisions = atomic64_read(&conn->stats.sched_decisions);
	if (path_switches)
		*path_switches = atomic64_read(&conn->stats.path_switches);
	if (reinjections)
		*reinjections = atomic64_read(&conn->stats.reinjections);
}
EXPORT_SYMBOL_GPL(tquic_get_conn_stats);

/*
 * Get path statistics
 */
void tquic_get_path_stats(struct tquic_connection *conn, u8 path_id,
			  u64 *packets_sent, u64 *bytes_sent,
			  u64 *packets_acked, u64 *packets_lost,
			  u64 *smoothed_rtt_us, u64 *min_rtt_us,
			  u32 *cwnd, u32 *loss_rate)
{
	struct tquic_path *path;

	if (!conn)
		return;

	rcu_read_lock();

	path = tquic_find_path(conn, path_id);
	if (path) {
		if (packets_sent)
			*packets_sent = atomic64_read(&path->stats.packets_sent);
		if (bytes_sent)
			*bytes_sent = atomic64_read(&path->stats.bytes_sent);
		if (packets_acked)
			*packets_acked = atomic64_read(&path->stats.packets_acked);
		if (packets_lost)
			*packets_lost = atomic64_read(&path->stats.packets_lost);
		if (smoothed_rtt_us)
			*smoothed_rtt_us = path->cc.smoothed_rtt_us;
		if (min_rtt_us)
			*min_rtt_us = path->cc.min_rtt_us;
		if (cwnd)
			*cwnd = path->cc.cwnd;
		if (loss_rate)
			*loss_rate = path->cc.loss_rate;
	}

	rcu_read_unlock();
}
EXPORT_SYMBOL_GPL(tquic_get_path_stats);

/* =========================================================================
 * Default Scheduler Configuration
 * ========================================================================= */

static char tquic_default_sched_name[TQUIC_SCHED_NAME_MAX] = "adaptive";

/* =========================================================================
 * Per-Netns Default Scheduler (for container-friendly configuration)
 * ========================================================================= */

/*
 * Get per-netns default scheduler (RCU protected)
 */
static inline struct tquic_scheduler_ops *
tquic_get_default_sched_netns(struct net *net)
{
	return rcu_dereference(net->tquic.default_scheduler);
}

/*
 * Set default scheduler for a network namespace
 *
 * This allows containers to have different default schedulers.
 * The scheduler is validated before being set.
 */
int tquic_sched_set_default(struct net *net, const char *name)
{
	struct tquic_scheduler_ops *sched, *old;

	if (!net || !name || !name[0])
		return -EINVAL;

	rcu_read_lock();
	sched = tquic_sched_find(name);
	if (!sched) {
		rcu_read_unlock();
		return -ENOENT;
	}

	if (!try_module_get(sched->owner)) {
		rcu_read_unlock();
		return -EBUSY;
	}
	rcu_read_unlock();

	spin_lock(&tquic_sched_list_lock);
	old = rcu_dereference_protected(net->tquic.default_scheduler,
					lockdep_is_held(&tquic_sched_list_lock));
	rcu_assign_pointer(net->tquic.default_scheduler, sched);
	strscpy(net->tquic.sched_name, name, NETNS_TQUIC_SCHED_NAME_MAX);
	spin_unlock(&tquic_sched_list_lock);

	if (old)
		module_put(old->owner);

	synchronize_rcu();

	return 0;
}
EXPORT_SYMBOL_GPL(tquic_sched_set_default);

/*
 * Get default scheduler name for a network namespace
 */
const char *tquic_sched_get_default(struct net *net)
{
	struct tquic_scheduler_ops *sched;
	const char *name;

	if (!net)
		return "aggregate";

	rcu_read_lock();
	sched = tquic_get_default_sched_netns(net);
	if (sched)
		name = sched->name;
	else
		name = "aggregate";
	rcu_read_unlock();

	return name;
}
EXPORT_SYMBOL_GPL(tquic_sched_get_default);

/* =========================================================================
 * Per-Connection Scheduler Initialization (New API from tquic_sched.h)
 * ========================================================================= */

/*
 * Initialize scheduler for a connection
 *
 * Per CONTEXT.md: "Scheduler locked at connection establishment,
 * cannot change mid-connection"
 *
 * If name is NULL or empty, uses per-netns default.
 */
int tquic_sched_init_conn(struct tquic_connection *conn, const char *name)
{
	struct tquic_scheduler_ops *sched;
	struct net *net;

	if (!conn || !conn->sk)
		return -EINVAL;

	/* Scheduler can only be set before connection established */
	if (conn->state != TQUIC_CONN_IDLE)
		return -EISCONN;

	net = sock_net(conn->sk);

	if (name && name[0]) {
		/* Explicit scheduler name specified */
		rcu_read_lock();
		sched = tquic_sched_find(name);
		rcu_read_unlock();
	} else {
		/* Use per-netns default */
		rcu_read_lock();
		sched = tquic_get_default_sched_netns(net);
		if (!sched) {
			/* Fall back to global default */
			sched = tquic_default_scheduler;
		}
		rcu_read_unlock();
	}

	if (!sched)
		return -ENOENT;

	if (!try_module_get(sched->owner))
		return -EBUSY;

	spin_lock(&conn->lock);

	/* Release any existing scheduler */
	if (conn->sched) {
		struct tquic_scheduler_ops *old = conn->sched;
		if (old->release)
			old->release(conn);
		module_put(old->owner);
	}

	conn->sched = sched;
	conn->sched_priv = NULL;

	/* Initialize scheduler state for this connection */
	if (sched->init) {
		int ret = sched->init(conn);
		if (ret) {
			conn->sched = NULL;
			spin_unlock(&conn->lock);
			module_put(sched->owner);
			return ret;
		}
	}

	spin_unlock(&conn->lock);

	pr_debug("Connection %llx: scheduler initialized to %s\n",
		 conn->conn_id, sched->name);

	return 0;
}
EXPORT_SYMBOL_GPL(tquic_sched_init_conn);

/*
 * Release scheduler resources for a connection
 */
void tquic_sched_release_conn(struct tquic_connection *conn)
{
	struct tquic_scheduler_ops *sched;

	if (!conn)
		return;

	spin_lock(&conn->lock);
	sched = conn->sched;
	if (sched) {
		if (sched->release)
			sched->release(conn);
		conn->sched = NULL;
		conn->sched_priv = NULL;
	}
	spin_unlock(&conn->lock);

	if (sched)
		module_put(sched->owner);
}
EXPORT_SYMBOL_GPL(tquic_sched_release_conn);

/*
 * Get path selection for next packet (new API with path_result struct)
 */
int tquic_sched_get_path(struct tquic_connection *conn,
			 struct tquic_sched_path_result *result,
			 u32 flags)
{
	struct tquic_scheduler_ops *sched;
	int ret;

	if (!conn || !result)
		return -EINVAL;

	memset(result, 0, sizeof(*result));

	rcu_read_lock();
	sched = conn->sched;
	if (!sched || !sched->select_path) {
		rcu_read_unlock();
		return -ENOENT;
	}

	/*
	 * The existing select_path uses tquic_path_selection struct.
	 * We adapt it to the new tquic_sched_path_result struct.
	 * The internal select_path fills sel->paths[] and sel->num_paths.
	 */
	{
		struct tquic_path_selection sel = {0};
		sel.duplicate = false;

		ret = sched->select_path(conn, &sel);
		if (ret == 0 && sel.num_paths > 0) {
			result->primary = sel.paths[0];
			if (sel.num_paths > 1)
				result->backup = sel.paths[1];
			if (sel.duplicate)
				result->flags |= TQUIC_SCHED_REDUNDANT;
		}
	}

	rcu_read_unlock();

	return ret;
}
EXPORT_SYMBOL_GPL(tquic_sched_get_path);

/* =========================================================================
 * Global Default Scheduler Configuration (Legacy API)
 * ========================================================================= */

/*
 * Set default scheduler by name
 */
int tquic_set_default_scheduler(const char *name)
{
	struct tquic_scheduler_ops *sched;

	rcu_read_lock();
	sched = tquic_sched_find(name);
	rcu_read_unlock();

	if (!sched)
		return -ENOENT;

	spin_lock(&tquic_sched_list_lock);
	tquic_default_scheduler = sched;
	strscpy(tquic_default_sched_name, name, TQUIC_SCHED_NAME_MAX);
	spin_unlock(&tquic_sched_list_lock);

	return 0;
}
EXPORT_SYMBOL_GPL(tquic_set_default_scheduler);

/*
 * Get default scheduler name
 */
const char *tquic_get_default_scheduler(void)
{
	return tquic_default_sched_name;
}
EXPORT_SYMBOL_GPL(tquic_get_default_scheduler);

/* =========================================================================
 * Per-Network Namespace Initialization
 * ========================================================================= */

/*
 * Per-netns scheduler initialization
 *
 * Each network namespace gets its own default scheduler setting.
 * This allows containers to have different scheduler defaults.
 */
static int __net_init tquic_sched_net_init(struct net *net)
{
	struct proc_dir_entry *pde;

	/* Initialize per-netns default scheduler to aggregate */
	RCU_INIT_POINTER(net->tquic.default_scheduler, NULL);
	strscpy(net->tquic.sched_name, "aggregate",
		sizeof(net->tquic.sched_name));

	/* Create per-netns proc entry */
	pde = proc_mkdir("tquic", net->proc_net);
	if (pde) {
		proc_create_net_single("schedulers", 0444, pde,
				       tquic_sched_stats_show, NULL);
	}

	pr_debug("TQUIC scheduler initialized for netns\n");
	return 0;
}

static void __net_exit tquic_sched_net_exit(struct net *net)
{
	struct tquic_scheduler_ops *sched;

	/* Release per-netns default scheduler reference */
	rcu_read_lock();
	sched = rcu_dereference(net->tquic.default_scheduler);
	rcu_read_unlock();

	if (sched)
		module_put(sched->owner);

	RCU_INIT_POINTER(net->tquic.default_scheduler, NULL);

	/* Remove per-netns proc entries */
	remove_proc_subtree("tquic", net->proc_net);

	pr_debug("TQUIC scheduler exited for netns\n");
}

static struct pernet_operations tquic_sched_net_ops = {
	.init = tquic_sched_net_init,
	.exit = tquic_sched_net_exit,
};

/* =========================================================================
 * Module Initialization
 * ========================================================================= */

static int __init tquic_scheduler_init(void)
{
	int ret;

	pr_info("Initializing TQUIC packet scheduler framework\n");

	/* Register built-in schedulers first (before pernet ops) */
	ret = tquic_sched_register(&tquic_sched_rr);
	if (ret)
		pr_warn("Failed to register round-robin scheduler\n");

	ret = tquic_sched_register(&tquic_sched_weighted);
	if (ret)
		pr_warn("Failed to register weighted scheduler\n");

	ret = tquic_sched_register(&tquic_sched_lowlat);
	if (ret)
		pr_warn("Failed to register lowlat scheduler\n");

	ret = tquic_sched_register(&tquic_sched_redundant);
	if (ret)
		pr_warn("Failed to register redundant scheduler\n");

	ret = tquic_sched_register(&tquic_sched_adaptive);
	if (ret)
		pr_warn("Failed to register adaptive scheduler\n");

	/* Set adaptive as global default */
	tquic_set_default_scheduler("adaptive");

	/* Register per-netns operations (creates proc entries per namespace) */
	ret = register_pernet_subsys(&tquic_sched_net_ops);
	if (ret) {
		pr_err("Failed to register pernet operations\n");
		goto err_pernet;
	}

	pr_info("TQUIC scheduler framework initialized\n");

	return 0;

err_pernet:
	tquic_sched_unregister(&tquic_sched_adaptive);
	tquic_sched_unregister(&tquic_sched_redundant);
	tquic_sched_unregister(&tquic_sched_lowlat);
	tquic_sched_unregister(&tquic_sched_weighted);
	tquic_sched_unregister(&tquic_sched_rr);
	return ret;
}

static void __exit tquic_scheduler_exit(void)
{
	pr_info("Unloading TQUIC packet scheduler framework\n");

	/* Unregister pernet operations (removes proc entries) */
	unregister_pernet_subsys(&tquic_sched_net_ops);

	/* Unregister built-in schedulers */
	tquic_sched_unregister(&tquic_sched_adaptive);
	tquic_sched_unregister(&tquic_sched_redundant);
	tquic_sched_unregister(&tquic_sched_lowlat);
	tquic_sched_unregister(&tquic_sched_weighted);
	tquic_sched_unregister(&tquic_sched_rr);

	pr_info("TQUIC scheduler framework unloaded\n");
}

module_init(tquic_scheduler_init);
module_exit(tquic_scheduler_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Linux Foundation");
MODULE_DESCRIPTION("TQUIC Packet Scheduler for WAN Bonding");
MODULE_VERSION("1.0");
