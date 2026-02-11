/* SPDX-License-Identifier: GPL-2.0 */
/*
 * TQUIC Multipath Packet Scheduler API
 *
 * Copyright (c) 2026 Linux Foundation
 * Kernel implementation by Justin Adams <spotty118@gmail.com>
 *
 * This header provides local scheduler API extensions for the multipath
 * scheduler implementations. The main API types (struct tquic_mp_sched_ops,
 * struct tquic_sched_path_result) are defined in include/net/tquic.h.
 *
 * This header adds:
 * - Per-connection scheduler API
 * - Per-netns default scheduler API
 * - Scheduler notification API
 * - Maximum paths constant
 */

#ifndef _NET_TQUIC_SCHED_H
#define _NET_TQUIC_SCHED_H

#include <linux/types.h>
#include <linux/list.h>
#include <linux/module.h>
#include <linux/cache.h>
#include <net/net_namespace.h>
#include <net/tquic.h>

/*
 * Scheduler-Specific Constants
 */

#ifndef TQUIC_INVALID_PATH_ID
#define TQUIC_INVALID_PATH_ID	0xFF
#endif

/*
 * Maximum paths per connection (for scheduler state arrays)
 */
#ifndef TQUIC_MAX_PATHS
#define TQUIC_MAX_PATHS		16
#endif

/*
 * Scheduler flags for path selection
 */
#define TQUIC_MP_SCHED_REDUNDANT	TQUIC_SCHED_F_REDUNDANT

/*
 * Per-Connection Multipath Scheduler API (Public Interface)
 *
 * Note: These function prototypes use the public tquic_connection type.
 * The internal implementations (tquic_int_mp_sched_*) work with the
 * internal tquic_int_connection type.
 */
int tquic_mp_sched_init_conn(struct tquic_connection *conn, const char *name);
void tquic_mp_sched_release_conn(struct tquic_connection *conn);
int tquic_mp_sched_get_path(struct tquic_connection *conn,
			    struct tquic_sched_path_result *result,
			    u32 flags);

/*
 * Internal Scheduler API
 *
 * These functions work with internal scheduler types (tquic_int_connection,
 * tquic_int_path). Use these when working within the internal scheduler
 * implementation where compatibility macros redefine types.
 */
struct tquic_int_connection;
struct tquic_path_selection;
int tquic_int_mp_sched_init_conn(struct tquic_int_connection *conn, const char *name);
void tquic_int_mp_sched_release_conn(struct tquic_int_connection *conn);
int tquic_int_mp_sched_get_path(struct tquic_int_connection *conn,
				struct tquic_sched_path_result *result,
				u32 flags);
int tquic_int_select_path(struct tquic_int_connection *conn,
			  struct tquic_path_selection *sel);
void tquic_int_path_validate(struct tquic_int_connection *conn, u8 path_id);

/*
 * Per-Netns Default Scheduler
 */
int tquic_mp_sched_set_default(struct net *net, const char *name);
const char *tquic_mp_sched_get_default(struct net *net);

/* Built-in scheduler declaration */
extern struct tquic_mp_sched_ops tquic_mp_sched_aggregate;

/*
 * Legacy compatibility aliases - map local names to net/tquic.h types
 */
#ifndef TQUIC_SCHED_NO_COMPAT
#define tquic_mp_sched_path_result	tquic_sched_path_result
#define TQUIC_SCHED_REDUNDANT		TQUIC_SCHED_F_REDUNDANT
#endif

#endif /* _NET_TQUIC_SCHED_H */
