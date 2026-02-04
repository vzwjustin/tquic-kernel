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

EXPORT_SYMBOL_GPL(tquic_path_init_module);
EXPORT_SYMBOL_GPL(tquic_path_exit_module);
EXPORT_SYMBOL_GPL(tquic_path_put);
EXPORT_SYMBOL_GPL(tquic_trace_path_validated);
EXPORT_SYMBOL_GPL(tquic_mp_register_scheduler);
EXPORT_SYMBOL_GPL(tquic_mp_unregister_scheduler);
EXPORT_SYMBOL_GPL(tquic_mp_sched_notify_ack);
EXPORT_SYMBOL_GPL(tquic_mp_sched_notify_loss);
EXPORT_SYMBOL_GPL(tquic_crypto_destroy);

#endif /* TQUIC_OUT_OF_TREE */
