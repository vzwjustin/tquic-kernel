// SPDX-License-Identifier: GPL-2.0-only
/*
 * TQUIC: Multipath Packet Scheduler Framework
 *
 * Copyright (c) 2026 Linux Foundation
 *
 * Provides a pluggable scheduler framework for distributing packets
 * across multiple WAN paths for true bandwidth aggregation.
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/list.h>
#include <linux/rculist.h>
#include <linux/spinlock.h>
#include <net/sock.h>
#include <net/tquic.h>

/* Registered schedulers */
static LIST_HEAD(tquic_sched_list);
static DEFINE_SPINLOCK(tquic_sched_lock);

/* Default scheduler */
static struct tquic_sched_ops *default_scheduler;

/*
 * Scheduler registration
 */
int tquic_sched_register(struct tquic_sched_ops *ops)
{
	if (!ops || !ops->name || !ops->select)
		return -EINVAL;

	spin_lock(&tquic_sched_lock);
	list_add_tail_rcu(&ops->list, &tquic_sched_list);

	/* First registered becomes default */
	if (!default_scheduler)
		default_scheduler = ops;

	spin_unlock(&tquic_sched_lock);

	pr_info("tquic_sched: registered scheduler '%s'\n", ops->name);
	return 0;
}
EXPORT_SYMBOL_GPL(tquic_sched_register);

void tquic_sched_unregister(struct tquic_sched_ops *ops)
{
	spin_lock(&tquic_sched_lock);

	list_del_rcu(&ops->list);

	if (default_scheduler == ops) {
		default_scheduler = list_first_entry_or_null(
			&tquic_sched_list, struct tquic_sched_ops, list);
	}

	spin_unlock(&tquic_sched_lock);

	synchronize_rcu();

	pr_info("tquic_sched: unregistered scheduler '%s'\n", ops->name);
}
EXPORT_SYMBOL_GPL(tquic_sched_unregister);

/*
 * Find scheduler by name
 */
struct tquic_sched_ops *tquic_sched_find(const char *name)
{
	struct tquic_sched_ops *ops;

	rcu_read_lock();
	list_for_each_entry_rcu(ops, &tquic_sched_list, list) {
		if (strcmp(ops->name, name) == 0) {
			if (!try_module_get(ops->owner)) {
				ops = NULL;
			}
			rcu_read_unlock();
			return ops;
		}
	}
	rcu_read_unlock();

	return NULL;
}
EXPORT_SYMBOL_GPL(tquic_sched_find);

/*
 * Get default scheduler
 */
struct tquic_sched_ops *tquic_sched_default(void)
{
	struct tquic_sched_ops *ops;

	rcu_read_lock();
	ops = rcu_dereference(default_scheduler);
	if (ops && !try_module_get(ops->owner))
		ops = NULL;
	rcu_read_unlock();

	return ops;
}
EXPORT_SYMBOL_GPL(tquic_sched_default);

/*
 * Set default scheduler
 */
int tquic_sched_set_default(const char *name)
{
	struct tquic_sched_ops *ops;

	ops = tquic_sched_find(name);
	if (!ops)
		return -ENOENT;

	spin_lock(&tquic_sched_lock);
	default_scheduler = ops;
	spin_unlock(&tquic_sched_lock);

	module_put(ops->owner);

	pr_info("tquic_sched: set default scheduler to '%s'\n", name);
	return 0;
}
EXPORT_SYMBOL_GPL(tquic_sched_set_default);

/*
 * Initialize scheduler for a connection
 */
void *tquic_sched_init_conn(struct tquic_connection *conn,
			    struct tquic_sched_ops *ops)
{
	if (!ops)
		ops = tquic_sched_default();

	if (!ops)
		return NULL;

	if (ops->init)
		return ops->init(conn);

	return ops;  /* Return ops as state if no init needed */
}
EXPORT_SYMBOL_GPL(tquic_sched_init_conn);

/*
 * Release scheduler for a connection
 */
void tquic_sched_release_conn(struct tquic_sched_ops *ops, void *state)
{
	if (ops && ops->release)
		ops->release(state);

	if (ops)
		module_put(ops->owner);
}
EXPORT_SYMBOL_GPL(tquic_sched_release_conn);

/*
 * =============================================================================
 * Built-in Schedulers
 * =============================================================================
 */

/*
 * Round-Robin Scheduler
 */
struct rr_sched_data {
	atomic_t counter;
};

static void *rr_init(struct tquic_connection *conn)
{
	struct rr_sched_data *data;

	data = kzalloc(sizeof(*data), GFP_KERNEL);
	if (data)
		atomic_set(&data->counter, 0);

	return data;
}

static void rr_release(void *state)
{
	kfree(state);
}

static struct tquic_path *rr_select(void *state, struct tquic_connection *conn,
				    struct sk_buff *skb)
{
	struct rr_sched_data *data = state;
	struct tquic_path *path;
	u32 idx = 0;
	u32 target;

	if (!data)
		return conn->active_path;

	target = atomic_inc_return(&data->counter) % conn->num_paths;

	list_for_each_entry(path, &conn->paths, list) {
		if (path->state != TQUIC_PATH_ACTIVE)
			continue;

		if (idx++ == target)
			return path;
	}

	return conn->active_path;
}

static struct tquic_sched_ops tquic_sched_rr = {
	.name = "roundrobin",
	.init = rr_init,
	.release = rr_release,
	.select = rr_select,
};

/*
 * Minimum RTT Scheduler
 */
static struct tquic_path *minrtt_select(void *state, struct tquic_connection *conn,
					struct sk_buff *skb)
{
	struct tquic_path *path, *best = NULL;
	u32 min_rtt = UINT_MAX;

	list_for_each_entry(path, &conn->paths, list) {
		if (path->state != TQUIC_PATH_ACTIVE)
			continue;

		if (path->stats.rtt_smoothed < min_rtt) {
			min_rtt = path->stats.rtt_smoothed;
			best = path;
		}
	}

	return best ?: conn->active_path;
}

static struct tquic_sched_ops tquic_sched_minrtt = {
	.name = "minrtt",
	.select = minrtt_select,
};

/*
 * Weighted Round-Robin Scheduler
 */
struct wrr_sched_data {
	atomic_t counter;
	u32 total_weight;
};

static void *wrr_init(struct tquic_connection *conn)
{
	struct wrr_sched_data *data;
	struct tquic_path *path;

	data = kzalloc(sizeof(*data), GFP_KERNEL);
	if (!data)
		return NULL;

	atomic_set(&data->counter, 0);

	/* Calculate total weight */
	list_for_each_entry(path, &conn->paths, list) {
		if (path->state == TQUIC_PATH_ACTIVE)
			data->total_weight += path->weight;
	}

	return data;
}

static void wrr_release(void *state)
{
	kfree(state);
}

static struct tquic_path *wrr_select(void *state, struct tquic_connection *conn,
				     struct sk_buff *skb)
{
	struct wrr_sched_data *data = state;
	struct tquic_path *path;
	u32 target, cumulative = 0;

	if (!data || data->total_weight == 0)
		return conn->active_path;

	target = atomic_inc_return(&data->counter) % data->total_weight;

	list_for_each_entry(path, &conn->paths, list) {
		if (path->state != TQUIC_PATH_ACTIVE)
			continue;

		cumulative += path->weight;
		if (target < cumulative)
			return path;
	}

	return conn->active_path;
}

static void wrr_feedback(void *state, struct tquic_path *path,
			 struct sk_buff *skb, bool success)
{
	struct wrr_sched_data *data = state;

	if (!data)
		return;

	/* Recalculate total weight on path changes */
	/* This is a simplified implementation */
}

static struct tquic_sched_ops tquic_sched_wrr = {
	.name = "weighted",
	.init = wrr_init,
	.release = wrr_release,
	.select = wrr_select,
	.feedback = wrr_feedback,
};

/*
 * BLEST (BLocking ESTimation) Scheduler
 * Designed to minimize head-of-line blocking in multipath scenarios
 */
struct blest_sched_data {
	u64 lambda;  /* Smoothing factor */
};

static void *blest_init(struct tquic_connection *conn)
{
	struct blest_sched_data *data;

	data = kzalloc(sizeof(*data), GFP_KERNEL);
	if (data)
		data->lambda = 1000;  /* Default lambda value */

	return data;
}

static void blest_release(void *state)
{
	kfree(state);
}

static struct tquic_path *blest_select(void *state, struct tquic_connection *conn,
				       struct sk_buff *skb)
{
	struct tquic_path *path, *best = NULL;
	u64 min_blocking = ULLONG_MAX;

	list_for_each_entry(path, &conn->paths, list) {
		u64 blocking_time;
		u64 owd_diff;

		if (path->state != TQUIC_PATH_ACTIVE)
			continue;

		/* Estimate blocking time */
		/* OWD = RTT/2 (simplified) */
		owd_diff = 0;
		if (conn->active_path && path != conn->active_path) {
			s64 diff = (s64)path->stats.rtt_smoothed -
				   (s64)conn->active_path->stats.rtt_smoothed;
			if (diff > 0)
				owd_diff = diff / 2;
		}

		/* Calculate blocking estimate */
		blocking_time = owd_diff;

		/* Add queuing delay estimate based on cwnd utilization */
		if (path->stats.cwnd > 0) {
			/* Simplified: assume some bytes in flight */
			u64 queue_delay = (skb->len * path->stats.rtt_smoothed) /
					  path->stats.cwnd;
			blocking_time += queue_delay;
		}

		if (blocking_time < min_blocking) {
			min_blocking = blocking_time;
			best = path;
		}
	}

	return best ?: conn->active_path;
}

static struct tquic_sched_ops tquic_sched_blest = {
	.name = "blest",
	.init = blest_init,
	.release = blest_release,
	.select = blest_select,
};

/*
 * Redundant Scheduler - sends on all paths
 */
static struct tquic_path *redundant_select(void *state,
					   struct tquic_connection *conn,
					   struct sk_buff *skb)
{
	/* For redundant mode, we return NULL to indicate
	 * the caller should send on ALL active paths */
	return NULL;
}

static struct tquic_sched_ops tquic_sched_redundant = {
	.name = "redundant",
	.select = redundant_select,
};

/*
 * ECF (Earliest Completion First) Scheduler
 */
static struct tquic_path *ecf_select(void *state, struct tquic_connection *conn,
				     struct sk_buff *skb)
{
	struct tquic_path *path, *best = NULL;
	u64 min_completion = ULLONG_MAX;

	list_for_each_entry(path, &conn->paths, list) {
		u64 completion_time;
		u64 transmission_time;
		u64 propagation_delay;

		if (path->state != TQUIC_PATH_ACTIVE)
			continue;

		/* Estimate transmission time */
		if (path->stats.bandwidth > 0)
			transmission_time = (skb->len * 1000000ULL) /
					    path->stats.bandwidth;
		else
			transmission_time = 10000;  /* 10ms default */

		/* Propagation delay = RTT/2 */
		propagation_delay = path->stats.rtt_smoothed / 2;

		/* Total completion time estimate */
		completion_time = transmission_time + propagation_delay;

		if (completion_time < min_completion) {
			min_completion = completion_time;
			best = path;
		}
	}

	return best ?: conn->active_path;
}

static struct tquic_sched_ops tquic_sched_ecf = {
	.name = "ecf",
	.select = ecf_select,
};

/*
 * Module initialization
 */
static int __init tquic_sched_module_init(void)
{
	/* Register built-in schedulers */
	tquic_sched_register(&tquic_sched_rr);
	tquic_sched_register(&tquic_sched_minrtt);
	tquic_sched_register(&tquic_sched_wrr);
	tquic_sched_register(&tquic_sched_blest);
	tquic_sched_register(&tquic_sched_redundant);
	tquic_sched_register(&tquic_sched_ecf);

	/* Set minrtt as default */
	tquic_sched_set_default("minrtt");

	pr_info("tquic_sched: scheduler framework initialized\n");
	return 0;
}

static void __exit tquic_sched_module_exit(void)
{
	tquic_sched_unregister(&tquic_sched_ecf);
	tquic_sched_unregister(&tquic_sched_redundant);
	tquic_sched_unregister(&tquic_sched_blest);
	tquic_sched_unregister(&tquic_sched_wrr);
	tquic_sched_unregister(&tquic_sched_minrtt);
	tquic_sched_unregister(&tquic_sched_rr);

	pr_info("tquic_sched: scheduler framework cleanup complete\n");
}

module_init(tquic_sched_module_init);
module_exit(tquic_sched_module_exit);

MODULE_DESCRIPTION("TQUIC Multipath Packet Scheduler Framework");
MODULE_LICENSE("GPL");
