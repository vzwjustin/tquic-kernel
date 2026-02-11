// SPDX-License-Identifier: GPL-2.0-only
/*
 * Minimal multipath scheduler registry for out-of-tree builds.
 *
 * This replaces the dependency on multipath/tquic_scheduler.c, which relies
 * on in-kernel netns fields not available in the DietPi kernel. We keep the
 * multipath scheduler registration API functional and safe.
 *
 * Copyright (c) 2024-2026 Linux Foundation
 * Kernel implementation by Justin Adams <spotty118@gmail.com>
 */

#include <linux/list.h>
#include <linux/module.h>
#include <linux/rcupdate.h>
#include <linux/spinlock.h>
#include <linux/string.h>
#include <net/tquic.h>

#include "../tquic_init.h"
#include "../tquic_debug.h"

static DEFINE_SPINLOCK(tquic_mp_sched_list_lock);
static LIST_HEAD(tquic_mp_sched_list);

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
	struct tquic_mp_sched_ops *sched;

	list_for_each_entry_rcu(sched, &tquic_mp_sched_list, list) {
		if (!strcmp(sched->name, name))
			return sched;
	}
	return NULL;
}
EXPORT_SYMBOL_GPL(tquic_mp_sched_find);

void tquic_mp_sched_notify_sent(struct tquic_connection *conn,
				struct tquic_path *path, u32 sent_bytes)
{
	struct tquic_mp_sched_ops *sched;
	struct tquic_mp_sched_ops *iter;

	if (!conn || !path)
		return;

	rcu_read_lock();
	sched = conn->scheduler;
	if (sched) {
		list_for_each_entry_rcu(iter, &tquic_mp_sched_list, list) {
			if (iter == sched) {
				if (iter->packet_sent)
					iter->packet_sent(conn, path,
							  sent_bytes);
				break;
			}
		}
	}
	rcu_read_unlock();
}
EXPORT_SYMBOL_GPL(tquic_mp_sched_notify_sent);

void tquic_mp_sched_notify_ack(struct tquic_connection *conn,
			       struct tquic_path *path, u64 acked_bytes)
{
	struct tquic_mp_sched_ops *sched;
	struct tquic_mp_sched_ops *iter;

	if (!conn || !path)
		return;

	rcu_read_lock();
	sched = conn->scheduler;
	if (sched) {
		list_for_each_entry_rcu(iter, &tquic_mp_sched_list, list) {
			if (iter == sched) {
				if (iter->ack_received)
					iter->ack_received(conn, path, acked_bytes);
				break;
			}
		}
	}
	rcu_read_unlock();
}
EXPORT_SYMBOL_GPL(tquic_mp_sched_notify_ack);

void tquic_mp_sched_notify_loss(struct tquic_connection *conn,
				struct tquic_path *path, u64 lost_bytes)
{
	struct tquic_mp_sched_ops *sched;
	struct tquic_mp_sched_ops *iter;

	if (!conn || !path)
		return;

	rcu_read_lock();
	sched = conn->scheduler;
	if (sched) {
		list_for_each_entry_rcu(iter, &tquic_mp_sched_list, list) {
			if (iter == sched) {
				if (iter->loss_detected)
					iter->loss_detected(conn, path, lost_bytes);
				break;
			}
		}
	}
	rcu_read_unlock();
}
EXPORT_SYMBOL_GPL(tquic_mp_sched_notify_loss);

int __init tquic_scheduler_init(void)
{
	pr_info("Initializing TQUIC multipath scheduler registry\n");
	return 0;
}
EXPORT_SYMBOL_GPL(tquic_scheduler_init);

void __exit tquic_scheduler_exit(void)
{
	pr_info("Unloading TQUIC multipath scheduler registry\n");
}
EXPORT_SYMBOL_GPL(tquic_scheduler_exit);
