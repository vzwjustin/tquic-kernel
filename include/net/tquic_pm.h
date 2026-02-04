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
#include <linux/workqueue.h>
#include <linux/notifier.h>
#include <net/net_namespace.h>
#include <net/netns/generic.h>
#include <uapi/linux/tquic_pm.h>

struct net;
struct tquic_connection;
struct tquic_path;
struct tquic_bonding_ctx;

/*
 * Path Manager Types
 *
 * Following MPTCP pattern, path managers can be either kernel-driven
 * (automatic path discovery) or userspace-driven (netlink controlled).
 */
enum tquic_pm_type {
	TQUIC_PM_TYPE_KERNEL = 0, /* Kernel automatic PM */
	TQUIC_PM_TYPE_USERSPACE = 1, /* Userspace PM via netlink */
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
	int (*add_path)(struct tquic_connection *conn, struct sockaddr *local,
			struct sockaddr *remote);
	int (*del_path)(struct tquic_connection *conn, u32 path_id);

	/* Path event notification */
	void (*path_event)(struct tquic_connection *conn,
			   struct tquic_path *path, int event);
};

/*
 * Path Manager Endpoint
 *
 * Represents a local endpoint that can be used for path creation.
 */
struct tquic_pm_endpoint {
	struct list_head list;
	struct sockaddr_storage addr;
	int if_idx; /* Interface index */
	u8 flags; /* TQUIC_PM_ADDR_FLAG_* from UAPI */
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
	u8 pm_type; /* enum tquic_pm_type */
	u8 auto_discover; /* Auto-discover paths on interface up */
	u8 max_paths; /* Maximum paths per connection (1-8) */
	u8 validation_retries; /* Path validation retry count */
	int event_rate_limit; /* Rate limit for path events (events/s) */

	/* Endpoint management */
	spinlock_t lock; /* Protects endpoint_list */
	struct list_head endpoint_list; /* List of local endpoints */

	/* Path ID allocation */
	unsigned long next_path_id; /* Bitmap for path ID allocation */
};

/*
 * Per-Connection PM State
 *
 * Tracks PM-specific state for each connection, including the list
 * of paths managed by this connection and the primary/backup path
 * selections used by schedulers.
 */
struct tquic_pm_state {
	struct tquic_pm_ops *ops; /* Current PM ops */
	void *priv; /* PM-specific private data */

	/* Bonding context (WAN bonding module) */
	struct tquic_bonding_ctx *bonding_ctx;

	/* Path management */
	struct list_head paths; /* List of paths (via tquic_path.pm_list) */
	struct tquic_path *primary_path; /* Primary/preferred path */
	struct tquic_path *backup_path; /* Backup path for failover */
	spinlock_t paths_lock; /* Protects path list modifications */

	/* Path counts */
	u8 num_paths; /* Total number of paths */
	u8 num_active; /* Number of active paths */

	/* Connection reference */
	struct tquic_connection *conn;

	/* Probe scheduling */
	struct delayed_work probe_work;
	u32 probe_interval;

	/* Interface monitoring */
	struct notifier_block netdev_notifier;
	bool monitoring;

	/* Auto-discovery settings */
	bool auto_discover;
	bool prefer_ipv6;
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

/* Internal PM functions */
struct tquic_pm_state *tquic_pm_init(struct tquic_connection *conn);
int tquic_pm_enable_monitoring(struct tquic_pm_state *pm);
void tquic_pm_cleanup(struct tquic_pm_state *pm);

bool tquic_pm_check_address_change(struct tquic_connection *conn,
				   const struct sockaddr_storage *from_addr,
				   struct tquic_path *path);
int tquic_pm_notify_observed_address(struct tquic_connection *conn,
				     struct tquic_path *path);
int tquic_pm_init_address_discovery(struct tquic_connection *conn);
void tquic_pm_cleanup_address_discovery(struct tquic_connection *conn);

/* Forward declarations for additional addresses */
struct tquic_additional_address;
struct tquic_cid;
enum tquic_addr_select_policy;

int tquic_pm_init_additional_addresses(struct tquic_connection *conn);
void tquic_pm_cleanup_additional_addresses(struct tquic_connection *conn);
int tquic_pm_add_local_additional_address(struct tquic_connection *conn,
					  const struct sockaddr_storage *addr,
					  const struct tquic_cid *cid);
int tquic_pm_remove_local_additional_address(
	struct tquic_connection *conn, const struct sockaddr_storage *addr);
struct tquic_path *
tquic_pm_create_path_to_additional(struct tquic_connection *conn,
				   struct tquic_additional_address *addr_entry);
int tquic_pm_validate_additional_address(
	struct tquic_connection *conn,
	struct tquic_additional_address *addr_entry);
struct tquic_additional_address *
tquic_pm_get_best_additional_address(struct tquic_connection *conn,
				     enum tquic_addr_select_policy policy);
void tquic_pm_on_path_validated_additional(struct tquic_connection *conn,
					   struct tquic_path *path);
void tquic_pm_on_path_failed_additional(struct tquic_connection *conn,
					struct tquic_path *path);
int tquic_pm_coordinate_preferred_and_additional(struct tquic_connection *conn);

/* Path lookup and enumeration APIs */
struct tquic_path *tquic_pm_get_path(struct tquic_pm_state *pm, u32 path_id);
int tquic_pm_get_active_paths(struct tquic_path_manager *pm,
			      struct tquic_path **paths, int max_paths);

/* Path state name table for debug/trace output */
extern const char *tquic_path_state_names[];

#endif /* _NET_TQUIC_PM_H */
