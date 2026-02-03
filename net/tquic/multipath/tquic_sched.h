/* SPDX-License-Identifier: GPL-2.0 */
/*
 * TQUIC Multipath Packet Scheduler API
 *
 * Copyright (c) 2026 Linux Foundation
 *
 * This header defines the multipath-specific scheduler API which extends
 * the basic scheduler interface in net/tquic.h with advanced path selection
 * and feedback mechanisms.
 *
 * Note: This defines struct tquic_mp_sched_ops which is distinct from
 * struct tquic_sched_ops in net/tquic.h. The multipath scheduler has
 * additional callbacks for path events and feedback.
 */

#ifndef _NET_QUIC_TQUIC_SCHED_H
#define _NET_QUIC_TQUIC_SCHED_H

#include <linux/types.h>
#include <linux/list.h>
#include <linux/module.h>
#include <linux/cache.h>
#include <net/net_namespace.h>

/* Forward declarations - use net/tquic.h for actual definitions */
struct tquic_connection;
struct tquic_path;
struct net;

/*
 * Scheduler-Specific Constants
 */

#ifndef TQUIC_INVALID_PATH_ID
#define TQUIC_INVALID_PATH_ID	0xFF
#endif

#ifndef TQUIC_SCHED_NAME_MAX
#define TQUIC_SCHED_NAME_MAX	16
#endif

/*
 * Scheduler flags for path selection
 */
#define TQUIC_MP_SCHED_REDUNDANT	(1 << 0)

/**
 * struct tquic_mp_sched_path_result - Multipath path selection result
 * @primary: Primary path for packet transmission
 * @backup: Backup path for failover (optional, may be NULL)
 * @flags: Flags affecting transmission
 */
struct tquic_mp_sched_path_result {
	struct tquic_path *primary;
	struct tquic_path *backup;
	u32 flags;
};

/**
 * struct tquic_mp_sched_ops - Multipath scheduler operations
 *
 * This is the extended scheduler interface for multipath QUIC,
 * distinct from the basic tquic_sched_ops in net/tquic.h.
 */
struct tquic_mp_sched_ops {
	char name[TQUIC_SCHED_NAME_MAX];
	struct module *owner;
	struct list_head list;

	/* Required: select path for next packet */
	int (*get_path)(struct tquic_connection *conn,
			struct tquic_mp_sched_path_result *result,
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
 * Multipath Scheduler Registration API
 */

int tquic_mp_register_scheduler(struct tquic_mp_sched_ops *sched);
void tquic_mp_unregister_scheduler(struct tquic_mp_sched_ops *sched);
struct tquic_mp_sched_ops *tquic_mp_sched_find(const char *name);

/*
 * Per-Connection Multipath Scheduler API
 */
int tquic_mp_sched_init_conn(struct tquic_connection *conn, const char *name);
void tquic_mp_sched_release_conn(struct tquic_connection *conn);
int tquic_mp_sched_get_path(struct tquic_connection *conn,
			    struct tquic_mp_sched_path_result *result,
			    u32 flags);

/*
 * Per-Netns Default Scheduler
 */
int tquic_mp_sched_set_default(struct net *net, const char *name);
const char *tquic_mp_sched_get_default(struct net *net);

/* Built-in scheduler */
extern struct tquic_mp_sched_ops tquic_mp_sched_aggregate;

/*
 * Scheduler Notification API
 */
void tquic_mp_sched_notify_ack(struct tquic_connection *conn,
			       struct tquic_path *path,
			       u64 acked_bytes);
void tquic_mp_sched_notify_loss(struct tquic_connection *conn,
				struct tquic_path *path,
				u64 lost_bytes);

/*
 * Legacy compatibility macros - map old names to new mp_ prefixed names
 * for files that haven't been updated yet.
 */
#ifndef TQUIC_SCHED_NO_COMPAT
#define tquic_sched_path_result		tquic_mp_sched_path_result
#define TQUIC_SCHED_REDUNDANT		TQUIC_MP_SCHED_REDUNDANT
#endif

#endif /* _NET_QUIC_TQUIC_SCHED_H */
