// SPDX-License-Identifier: GPL-2.0-only
/*
 * TQUIC out-of-tree build stubs
 *
 * Provide minimal implementations for symbols that are not built
 * in the out-of-tree configuration.
 */

#include <linux/module.h>
#include <linux/skbuff.h>
#include <net/tquic.h>
#include <net/tquic_pm.h>

struct tquic_path_manager;

#ifdef TQUIC_OUT_OF_TREE

int tquic_path_init_module(void)
{
	return 0;
}

void tquic_path_exit_module(void)
{
}

void tquic_path_put(struct tquic_path *path)
{
}

void tquic_trace_path_validated(struct tquic_connection *conn, u32 path_id,
				u64 validation_time_us)
{
}

int tquic_mp_register_scheduler(struct tquic_mp_sched_ops *sched)
{
	return 0;
}

void tquic_mp_unregister_scheduler(struct tquic_mp_sched_ops *sched)
{
}

void tquic_mp_sched_notify_ack(struct tquic_connection *conn,
			       struct tquic_path *path, u64 acked_bytes)
{
}

void tquic_mp_sched_notify_loss(struct tquic_connection *conn,
				struct tquic_path *path, u64 lost_bytes)
{
}

void tquic_crypto_destroy(void *crypto)
{
}

int tquic_udp_encap_init(struct tquic_sock *tsk)
{
	return -EOPNOTSUPP;
}

int tquic_udp_send(struct tquic_sock *tsk, struct sk_buff *skb,
		   struct tquic_path *path)
{
	kfree_skb(skb);
	return -EOPNOTSUPP;
}

int __init tquic_scheduler_init(void)
{
	return 0;
}

void __exit tquic_scheduler_exit(void)
{
}

struct tquic_mp_sched_ops *tquic_mp_sched_find(const char *name)
{
	return NULL;
}

/* Minimal out-of-tree helpers expected by bonding/multipath */
struct tquic_path *tquic_pm_get_path(struct tquic_pm_state *pm, u32 path_id)
{
	if (!pm || !pm->conn)
		return NULL;

	return tquic_conn_get_path(pm->conn, path_id);
}

int tquic_pm_get_active_paths(struct tquic_path_manager *pm,
			      struct tquic_path **paths, int max_paths)
{
	struct tquic_pm_state *state = (struct tquic_pm_state *)pm;
	struct tquic_connection *conn;
	struct tquic_path *path;
	int count = 0;

	if (!state || !paths || max_paths <= 0)
		return 0;

	conn = state->conn;
	if (!conn)
		return 0;

	spin_lock_bh(&conn->paths_lock);
	list_for_each_entry(path, &conn->paths, list) {
		if (path->state == TQUIC_PATH_ACTIVE ||
		    path->state == TQUIC_PATH_VALIDATED ||
		    path->state == TQUIC_PATH_STANDBY) {
			paths[count++] = path;
			if (count >= max_paths)
				break;
		}
	}
	spin_unlock_bh(&conn->paths_lock);

	return count;
}

const char *tquic_path_state_names[] = {
	[TQUIC_PATH_UNUSED]	= "UNUSED",
	[TQUIC_PATH_PENDING]	= "PENDING",
	[TQUIC_PATH_VALIDATED]	= "VALID",
	[TQUIC_PATH_ACTIVE]	= "ACTIVE",
	[TQUIC_PATH_STANDBY]	= "STANDBY",
	[TQUIC_PATH_UNAVAILABLE]= "UNAVAIL",
	[TQUIC_PATH_FAILED]	= "FAILED",
	[TQUIC_PATH_CLOSED]	= "CLOSED",
};

EXPORT_SYMBOL_GPL(tquic_path_init_module);
EXPORT_SYMBOL_GPL(tquic_path_exit_module);
EXPORT_SYMBOL_GPL(tquic_path_put);
EXPORT_SYMBOL_GPL(tquic_trace_path_validated);
EXPORT_SYMBOL_GPL(tquic_mp_register_scheduler);
EXPORT_SYMBOL_GPL(tquic_mp_unregister_scheduler);
EXPORT_SYMBOL_GPL(tquic_mp_sched_notify_ack);
EXPORT_SYMBOL_GPL(tquic_mp_sched_notify_loss);
EXPORT_SYMBOL_GPL(tquic_crypto_destroy);
EXPORT_SYMBOL_GPL(tquic_udp_encap_init);
EXPORT_SYMBOL_GPL(tquic_udp_send);
EXPORT_SYMBOL_GPL(tquic_scheduler_init);
EXPORT_SYMBOL_GPL(tquic_scheduler_exit);
EXPORT_SYMBOL_GPL(tquic_mp_sched_find);
EXPORT_SYMBOL_GPL(tquic_pm_get_path);
EXPORT_SYMBOL_GPL(tquic_pm_get_active_paths);
EXPORT_SYMBOL_GPL(tquic_path_state_names);

#endif /* TQUIC_OUT_OF_TREE */
