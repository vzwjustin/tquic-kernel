// SPDX-License-Identifier: GPL-2.0-only
/*
 * Minimal multipath scheduler registry for out-of-tree builds.
 *
 * This replaces the dependency on multipath/tquic_scheduler.c, which relies
 * on in-kernel netns fields not available in the DietPi kernel. We keep the
 * multipath scheduler registration API functional and safe.
 *
 * Copyright (c) 2026 Justin Adams <spotty118@gmail.com>
 * Kernel implementation by Justin Adams <spotty118@gmail.com>
 */

#include <linux/list.h>
#include <linux/module.h>
#include <linux/rculist.h>
#include <linux/rcupdate.h>
#include <linux/spinlock.h>
#include <linux/string.h>
#include <net/tquic.h>

#include "../tquic_init.h"
#include "../tquic_debug.h"
#include "tquic_sched.h"

static DEFINE_SPINLOCK(tquic_mp_sched_list_lock);
static LIST_HEAD(tquic_mp_sched_list);

static struct tquic_mp_sched_ops *tquic_mp_sched_get(const char *name)
{
	struct tquic_mp_sched_ops *sched = NULL;
	struct tquic_mp_sched_ops *iter;

	tquic_dbg("sched_reg: get name=%s\n", name ? name : "(null)");

	spin_lock(&tquic_mp_sched_list_lock);

	if (name && name[0]) {
		list_for_each_entry(iter, &tquic_mp_sched_list, list) {
			if (!strcmp(iter->name, name)) {
				sched = iter;
				break;
			}
		}
	} else {
		/* Prefer aggregate as implicit default; fallback to first. */
		list_for_each_entry(iter, &tquic_mp_sched_list, list) {
			if (!strcmp(iter->name, "aggregate")) {
				sched = iter;
				break;
			}
		}

		if (!sched)
			sched = list_first_entry_or_null(&tquic_mp_sched_list,
							 struct tquic_mp_sched_ops,
							 list);
	}

	if (sched && !try_module_get(sched->owner))
		sched = NULL;

	spin_unlock(&tquic_mp_sched_list_lock);
	return sched;
}

int tquic_mp_register_scheduler(struct tquic_mp_sched_ops *sched)
{
	struct tquic_mp_sched_ops *existing;

	if (!sched || !sched->name[0]) {
		pr_err("Invalid mp scheduler: missing name\n");
		return -EINVAL;
	}

	if (!sched->get_path) {
		pr_err("MP Scheduler '%s': missing required get_path callback\n",
		       sched->name);
		return -EINVAL;
	}

	spin_lock(&tquic_mp_sched_list_lock);

	list_for_each_entry(existing, &tquic_mp_sched_list, list) {
		if (!strcmp(existing->name, sched->name)) {
			spin_unlock(&tquic_mp_sched_list_lock);
			pr_err("MP Scheduler '%s' already registered\n",
			       sched->name);
			return -EEXIST;
		}
	}

	list_add_tail_rcu(&sched->list, &tquic_mp_sched_list);
	spin_unlock(&tquic_mp_sched_list_lock);

	tquic_info("registered multipath scheduler: %s\n", sched->name);
	return 0;
}
EXPORT_SYMBOL_GPL(tquic_mp_register_scheduler);

void tquic_mp_unregister_scheduler(struct tquic_mp_sched_ops *sched)
{
	bool removed = false;
	struct tquic_mp_sched_ops *iter;

	if (!sched)
		return;

	spin_lock(&tquic_mp_sched_list_lock);
	list_for_each_entry(iter, &tquic_mp_sched_list, list) {
		if (iter == sched) {
			list_del_rcu(&sched->list);
			removed = true;
			break;
		}
	}
	spin_unlock(&tquic_mp_sched_list_lock);

	if (!removed)
		return;

	synchronize_rcu();
	tquic_info("unregistered multipath scheduler: %s\n", sched->name);
}
EXPORT_SYMBOL_GPL(tquic_mp_unregister_scheduler);

struct tquic_mp_sched_ops *tquic_mp_sched_find(const char *name)
{
	struct tquic_mp_sched_ops *sched, *ret = NULL;

	tquic_dbg("sched_reg: find name=%s\n", name ? name : "(null)");

	if (!name || !name[0])
		return NULL;

	rcu_read_lock();
	list_for_each_entry_rcu(sched, &tquic_mp_sched_list, list) {
		if (!strcmp(sched->name, name)) {
			ret = sched;
			break;
		}
	}
	rcu_read_unlock();
	return ret;
}
EXPORT_SYMBOL_GPL(tquic_mp_sched_find);

int tquic_mp_sched_init_conn(struct tquic_connection *conn, const char *name)
{
	struct tquic_mp_sched_ops *sched;
	struct tquic_mp_sched_ops *old;
	int ret = 0;

	tquic_dbg("sched_reg: init_conn name=%s\n", name ? name : "(default)");

	if (!conn)
		return -EINVAL;

	sched = tquic_mp_sched_get(name);
	if (!sched)
		return -ENOENT;

	spin_lock_bh(&conn->lock);
	old = rcu_dereference_protected(conn->mp_sched_ops, 1);
	rcu_assign_pointer(conn->mp_sched_ops, NULL);
	spin_unlock_bh(&conn->lock);

	if (old)
		synchronize_rcu();

	if (old) {
		if (old->release)
			old->release(conn);
		module_put(old->owner);
	}

	if (sched->init) {
		ret = sched->init(conn);
		if (ret) {
			module_put(sched->owner);
			return ret;
		}
	}

	spin_lock_bh(&conn->lock);
	rcu_assign_pointer(conn->mp_sched_ops, sched);
	spin_unlock_bh(&conn->lock);

	return 0;
}
EXPORT_SYMBOL_GPL(tquic_mp_sched_init_conn);

void tquic_mp_sched_release_conn(struct tquic_connection *conn)
{
	struct tquic_mp_sched_ops *sched;

	tquic_dbg("sched_reg: release_conn\n");

	if (!conn)
		return;

	spin_lock_bh(&conn->lock);
	sched = rcu_dereference_protected(conn->mp_sched_ops, 1);
	rcu_assign_pointer(conn->mp_sched_ops, NULL);
	spin_unlock_bh(&conn->lock);

	if (!sched)
		return;

	synchronize_rcu();

	if (sched->release)
		sched->release(conn);

	module_put(sched->owner);
}
EXPORT_SYMBOL_GPL(tquic_mp_sched_release_conn);

int tquic_mp_sched_get_path(struct tquic_connection *conn,
			    struct tquic_sched_path_result *result,
			    u32 flags)
{
	struct tquic_mp_sched_ops *sched;
	int ret;

	if (!conn || !result)
		return -EINVAL;

	memset(result, 0, sizeof(*result));

	rcu_read_lock();
	sched = rcu_dereference(conn->mp_sched_ops);
	if (!sched || !sched->get_path) {
		rcu_read_unlock();
		return -ENOENT;
	}

	ret = sched->get_path(conn, result, flags);
	rcu_read_unlock();

	return ret;
}
EXPORT_SYMBOL_GPL(tquic_mp_sched_get_path);

void tquic_mp_sched_notify_sent(struct tquic_connection *conn,
				struct tquic_path *path, u32 sent_bytes)
{
	struct tquic_mp_sched_ops *sched;

	if (!conn || !path)
		return;

	rcu_read_lock();
	sched = rcu_dereference(conn->mp_sched_ops);
	if (sched && sched->packet_sent)
		sched->packet_sent(conn, path, sent_bytes);
	rcu_read_unlock();
}
EXPORT_SYMBOL_GPL(tquic_mp_sched_notify_sent);

void tquic_mp_sched_notify_ack(struct tquic_connection *conn,
			       struct tquic_path *path, u64 acked_bytes)
{
	struct tquic_mp_sched_ops *sched;

	if (!conn || !path)
		return;

	rcu_read_lock();
	sched = rcu_dereference(conn->mp_sched_ops);
	if (sched && sched->ack_received)
		sched->ack_received(conn, path, acked_bytes);
	rcu_read_unlock();
}
EXPORT_SYMBOL_GPL(tquic_mp_sched_notify_ack);

void tquic_mp_sched_notify_loss(struct tquic_connection *conn,
				struct tquic_path *path, u64 lost_bytes)
{
	struct tquic_mp_sched_ops *sched;

	if (!conn || !path)
		return;

	rcu_read_lock();
	sched = rcu_dereference(conn->mp_sched_ops);
	if (sched && sched->loss_detected)
		sched->loss_detected(conn, path, lost_bytes);
	rcu_read_unlock();
}
EXPORT_SYMBOL_GPL(tquic_mp_sched_notify_loss);

int __init tquic_scheduler_init(void)
{
	pr_info("Initializing TQUIC multipath scheduler registry\n");
	return 0;
}

void tquic_scheduler_exit(void)
{
	pr_info("Unloading TQUIC multipath scheduler registry\n");
}
