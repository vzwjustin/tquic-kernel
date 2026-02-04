// SPDX-License-Identifier: GPL-2.0-only
/*
 * TQUIC out-of-tree build stubs
 *
 * Provide minimal implementations for symbols that are not built
 * in the out-of-tree configuration.
 */

#include <linux/module.h>
#include <net/tquic.h>

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

/*
 * Path manager API stubs
 * These are called by mp_frame.c and tquic_bonding.c
 */
struct tquic_path *tquic_pm_get_path(struct tquic_pm_state *pm, u32 path_id)
{
	/* Stub: Return NULL indicating no path found */
	return NULL;
}

int tquic_pm_get_active_paths(struct tquic_path_manager *pm,
			      struct tquic_path **paths, int max_paths)
{
	/* Stub: Return 0 indicating no active paths */
	return 0;
}

/*
 * Crypto API wrapper
 * The implementation is tquic_crypto_derive_init_secrets() but callers
 * use tquic_crypto_derive_initial_secrets()
 */
extern int tquic_crypto_derive_init_secrets(struct tquic_connection *conn,
					    struct tquic_cid *cid);

int tquic_crypto_derive_initial_secrets(struct tquic_connection *conn,
					struct tquic_cid *cid)
{
	return tquic_crypto_derive_init_secrets(conn, cid);
}

/*
 * Path state name table
 * Used by mp_frame.c for debug/trace messages
 */
const char *tquic_path_state_names[] = {
	[TQUIC_PATH_UNUSED]     = "UNUSED",
	[TQUIC_PATH_PENDING]    = "PENDING",
	[TQUIC_PATH_VALIDATED]  = "VALIDATED",
	[TQUIC_PATH_ACTIVE]     = "ACTIVE",
	[TQUIC_PATH_STANDBY]    = "STANDBY",
	[TQUIC_PATH_UNAVAILABLE]= "UNAVAILABLE",
	[TQUIC_PATH_FAILED]     = "FAILED",
	[TQUIC_PATH_CLOSED]     = "CLOSED",
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
EXPORT_SYMBOL_GPL(tquic_pm_get_path);
EXPORT_SYMBOL_GPL(tquic_pm_get_active_paths);
EXPORT_SYMBOL_GPL(tquic_crypto_derive_initial_secrets);
EXPORT_SYMBOL_GPL(tquic_path_state_names);

#endif /* TQUIC_OUT_OF_TREE */
