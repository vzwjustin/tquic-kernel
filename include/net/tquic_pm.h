/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * TQUIC Path Manager Internal Header
 *
 * Copyright (c) 2026 Linux Foundation
 *
 * Internal structures and functions for the TQUIC path manager subsystem.
 * This header is for kernel-internal use only.
 */

#ifndef _NET_TQUIC_PM_H
#define _NET_TQUIC_PM_H

#include <linux/types.h>
#include <linux/spinlock.h>
#include <linux/list.h>
#include <net/net_namespace.h>
#include <net/netns/generic.h>

struct net;
struct tquic_connection;
struct tquic_path;

/*
 * Path Manager Types
 *
 * Following MPTCP pattern, path managers can be either kernel-driven
 * (automatic path discovery) or userspace-driven (netlink controlled).
 */
enum tquic_pm_type {
	TQUIC_PM_TYPE_KERNEL = 0,	/* Kernel automatic PM */
	TQUIC_PM_TYPE_USERSPACE = 1,	/* Userspace PM via netlink */
	__TQUIC_PM_TYPE_MAX
};

#define TQUIC_PM_TYPE_MAX (__TQUIC_PM_TYPE_MAX - 1)

/*
 * Path Manager Operations
 *
 * Each PM type implements these callbacks for lifecycle management
 * and path event handling.
 */
struct tquic_pm_ops {
	const char *name;

	/* PM lifecycle */
	int (*init)(struct net *net);
	void (*release)(struct net *net);

	/* Path management operations */
	int (*add_path)(struct tquic_connection *conn,
			struct sockaddr *local,
			struct sockaddr *remote);
	int (*del_path)(struct tquic_connection *conn, u32 path_id);

	/* Path event notification */
	void (*path_event)(struct tquic_connection *conn,
			   struct tquic_path *path,
			   int event);
};

/*
 * Path Manager Endpoint
 *
 * Represents a local endpoint that can be used for path creation.
 */
struct tquic_pm_endpoint {
	struct list_head list;
	struct sockaddr_storage addr;
	int if_idx;			/* Interface index */
	u8 flags;			/* TQUIC_PM_ADDR_FLAG_* from UAPI */
	u8 priority;
	u8 weight;
};

/*
 * Per-Network Namespace PM State
 *
 * Each network namespace has independent PM configuration and state.
 * This follows the pattern established by MPTCP.
 */
struct tquic_pm_pernet {
	/* Configuration (exposed via sysctl) */
	u8 pm_type;			/* enum tquic_pm_type */
	u8 auto_discover;		/* Auto-discover paths on interface up */
	u8 max_paths;			/* Maximum paths per connection (1-8) */
	u8 validation_retries;		/* Path validation retry count */
	int event_rate_limit;		/* Rate limit for path events (events/s) */

	/* Endpoint management */
	spinlock_t lock;		/* Protects endpoint_list */
	struct list_head endpoint_list;	/* List of local endpoints */

	/* Path ID allocation */
	unsigned long next_path_id;	/* Bitmap for path ID allocation */
};

/*
 * Per-Connection PM State
 *
 * Tracks PM-specific state for each connection.
 */
struct tquic_pm_state {
	struct tquic_pm_ops *ops;	/* Current PM ops */
	void *priv;			/* PM-specific private data */
};

/* PM type registration */
int tquic_pm_register(struct tquic_pm_ops *ops, enum tquic_pm_type type);
void tquic_pm_unregister(enum tquic_pm_type type);
struct tquic_pm_ops *tquic_pm_get_type(struct net *net);

/* Per-netns PM accessor */
struct tquic_pm_pernet *tquic_pm_get_pernet(struct net *net);

/* Connection lifecycle */
int tquic_pm_conn_init(struct tquic_connection *conn);
void tquic_pm_conn_release(struct tquic_connection *conn);

/* Path ID allocation */
u32 tquic_pm_alloc_path_id(struct net *net);
void tquic_pm_free_path_id(struct net *net, u32 path_id);

/* Module initialization */
int __init tquic_pm_types_init(void);
void __exit tquic_pm_types_exit(void);

/* Netlink interface */
int __init tquic_pm_nl_init(void);
void __exit tquic_pm_nl_exit(void);
int tquic_pm_nl_send_event(struct net *net, struct tquic_connection *conn,
			   struct tquic_path *path, int event_type);

/* Userspace PM */
int __init tquic_pm_userspace_init(void);
void __exit tquic_pm_userspace_exit(void);
extern struct tquic_pm_ops userspace_pm_ops;

#endif /* _NET_TQUIC_PM_H */
