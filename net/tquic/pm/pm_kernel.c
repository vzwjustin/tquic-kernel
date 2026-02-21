// SPDX-License-Identifier: GPL-2.0-only
/*
 * TQUIC Kernel Automatic Path Manager
 *
 * Copyright (c) 2026 Justin Adams <spotty118@gmail.com>
 * Kernel implementation by Justin Adams <spotty118@gmail.com>
 *
 * Implements automatic path discovery for WAN bonding. This PM type
 * discovers paths when network interfaces with default routes come up,
 * filtering out virtual/bridge interfaces that shouldn't be used for
 * WAN bonding.
 *
 * Following MPTCP pattern for interface filtering and netdev notifier usage.
 */

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/netdevice.h>
#include <linux/inetdevice.h>
#include <linux/if_arp.h>
#include <linux/rtnetlink.h>
#include <net/ip_fib.h>
#include <net/route.h>
#include <net/net_namespace.h>
#include <net/tquic.h>
#include "../tquic_compat.h"
#include "../tquic_debug.h"
#include <net/tquic_pm.h>
#include "../tquic_init.h"
#include "../protocol.h"
#include "../bond/tquic_bpm.h"

/* Kernel PM private data per-namespace */
struct tquic_pm_kernel_data {
	struct notifier_block netdev_notifier;
};

struct tquic_pm_kernel_conn_ref {
	struct list_head list;
	struct tquic_connection *conn;
};

/**
 * tquic_pm_kernel_has_default_route - Check if device has default route
 * @dev: Network device
 *
 * Returns true if the device has a default route (0.0.0.0/0).
 * This is a key indicator that the interface is suitable for WAN bonding.
 */
static bool tquic_pm_kernel_has_default_route(struct net_device *dev)
{
	struct fib_result res;
	struct flowi4 fl4 = {};
	struct net *net = dev_net(dev);
	int err;

	/* Check for IPv4 default route via this interface */
	fl4.flowi4_oif = dev->ifindex;
	fl4.daddr = cpu_to_be32(0x08080808); /* 8.8.8.8 as test dest */

	err = fib_lookup(net, &fl4, &res, 0);
	if (err == 0) {
		/* Found a route - check if it uses this device */
		if (FIB_RES_DEV(res) == dev)
			return true;
	}

	return false;
}

/**
 * tquic_pm_kernel_should_add_path - Filter interfaces for path creation
 * @dev: Network device to evaluate
 * @pernet: Per-netns PM configuration
 *
 * Returns true if this interface should be used for automatic path creation.
 *
 * Filtering criteria from RESEARCH.md pitfall analysis:
 * - Reject loopback (no WAN connectivity)
 * - Reject bridge ports (already aggregated)
 * - Reject OVS ports (overlay networking)
 * - Reject MACVLAN (virtual interface)
 * - Reject ARPHRD_VOID/LOOPBACK (no real hardware)
 * - Require IPv4 address
 * - Require default route
 * - Respect max_paths limit
 */
static bool tquic_pm_kernel_should_add_path(struct net_device *dev,
					    struct tquic_pm_pernet *pernet)
{
	struct in_device *in_dev;

	/* Basic flags check */
	if (dev->flags & IFF_LOOPBACK)
		return false;

	/* Hardware type filtering */
	if (dev->type == ARPHRD_VOID || dev->type == ARPHRD_LOOPBACK)
		return false;

	/* Virtual interface filtering */
	if (netif_is_bridge_port(dev))
		return false;

	if (netif_is_ovs_port(dev))
		return false;

	if (netif_is_macvlan(dev))
		return false;

	/* Check for IPv4 address */
	rcu_read_lock();
	in_dev = __in_dev_get_rcu(dev);
	if (!in_dev || !in_dev->ifa_list) {
		rcu_read_unlock();
		return false;
	}
	rcu_read_unlock();

	/* Check for default route */
	if (!tquic_pm_kernel_has_default_route(dev))
		return false;

	return true;
}

/**
 * tquic_pm_kernel_mark_unavailable - Mark path unavailable on interface down
 * @conn: Connection
 * @dev: Network device going down
 *
 * Preserves path state for fast recovery when interface comes back up.
 * This follows the "fast failover" pattern from CONTEXT.md.
 */
static void tquic_pm_kernel_mark_unavailable(struct tquic_connection *conn,
					     struct net_device *dev)
{
	struct tquic_path *path;

	rcu_read_lock();
	list_for_each_entry_rcu(path, &conn->paths, list) {
		/* Check if path uses this interface */
		if (path->dev != dev)
			continue;

		if (path->state == TQUIC_PATH_ACTIVE ||
		    path->state == TQUIC_PATH_VALIDATED ||
		    path->state == TQUIC_PATH_STANDBY) {
			/* Preserve state for recovery */
			path->saved_state = path->state;
			path->state = TQUIC_PATH_UNAVAILABLE;

			/* Stop validation timer */
			del_timer(&path->validation.timer);

			/* Emit event via PM netlink */
			if (conn->sk)
				tquic_pm_nl_send_event(sock_net(conn->sk), conn,
						       path,
						       TQUIC_PM_EVENT_DEGRADED);

			pr_debug(
				"tquic: path %u marked unavailable (interface %s down)\n",
				path->path_id, dev->name);
		}
	}
	rcu_read_unlock();

	/* Notify bonding layer to failover */
	tquic_bond_interface_down(conn, dev);
}

/**
 * tquic_pm_kernel_try_recover - Try to recover unavailable paths
 * @conn: Connection
 * @dev: Network device that came back up
 *
 * Revalidates paths that were marked UNAVAILABLE when this interface went down.
 */
static void tquic_pm_kernel_try_recover(struct tquic_connection *conn,
					struct net_device *dev)
{
	struct tquic_path *path;
	int recovered = 0;

	rcu_read_lock();
	list_for_each_entry_rcu(path, &conn->paths, list) {
		if (path->dev != dev)
			continue;

		if (path->state == TQUIC_PATH_UNAVAILABLE) {
			/* Interface back up - revalidate path */
			pr_debug(
				"tquic: path %u recovering (interface %s up)\n",
				path->path_id, dev->name);

			/* Start revalidation */
			path->state = TQUIC_PATH_PENDING;
			path->validation.retries = 0;
			tquic_path_start_validation(conn, path);

			recovered++;
		}
	}
	rcu_read_unlock();

	if (recovered > 0) {
		pr_info("tquic: %d paths recovering on interface %s\n",
			recovered, dev->name);
	}
}

/**
 * tquic_pm_kernel_try_add_path - Attempt to add path for an interface
 * @conn: Connection
 * @dev: Network device
 * @pernet: Per-netns PM configuration
 *
 * Creates a new path using the local address from the device.
 * Requires RTNL lock (held by caller - netdev notifier).
 */
static int tquic_pm_kernel_try_add_path(struct tquic_connection *conn,
					struct net_device *dev,
					struct tquic_pm_pernet *pernet)
{
	struct in_device *in_dev;
	struct in_ifaddr *ifa;
	struct sockaddr_in local_addr = { 0 };
	struct sockaddr_in remote_addr = { 0 };
	int ret;

	ASSERT_RTNL();

	/* Check max_paths limit */
	spin_lock_bh(&conn->lock);
	if (conn->num_paths >= pernet->max_paths) {
		spin_unlock_bh(&conn->lock);
		return -ENOSPC;
	}
	spin_unlock_bh(&conn->lock);

	/* Get first IPv4 address from device */
	in_dev = __in_dev_get_rtnl(dev);
	if (!in_dev || !in_dev->ifa_list)
		return -EADDRNOTAVAIL;

	ifa = in_dev->ifa_list;

	/* Build local address */
	local_addr.sin_family = AF_INET;
	local_addr.sin_addr.s_addr = ifa->ifa_local;
	local_addr.sin_port = 0; /* Ephemeral port assigned later */

	/* Remote address comes from connection's peer address */
	if (conn->sk) {
		struct tquic_sock *tsk = tquic_sk(conn->sk);
		struct sockaddr_in *peer;

		peer = (struct sockaddr_in *)&tsk->connect_addr;
		if (peer->sin_family == AF_INET) {
			remote_addr = *peer;
		} else {
			return -EAFNOSUPPORT;
		}
	} else {
		return -EINVAL;
	}

	/* Add the path */
	ret = tquic_conn_add_path(conn, (struct sockaddr *)&local_addr,
				  (struct sockaddr *)&remote_addr);
	if (ret < 0) {
		pr_debug("TQUIC PM kernel: Failed to add path for dev %s: %d\n",
			 dev->name, ret);
		return ret;
	}

	pr_info("TQUIC PM kernel: Added path for dev %s (%pI4)\n", dev->name,
		&local_addr.sin_addr);

	return 0;
}

static void tquic_pm_kernel_collect_conn_refs(struct tquic_net *tn,
					      struct list_head *conn_refs,
					      bool connected_only)
{
	struct tquic_connection *conn;

	spin_lock_bh(&tn->conn_lock);
	list_for_each_entry(conn, &tn->connections, pm_node) {
		struct tquic_pm_kernel_conn_ref *ref;

		if (connected_only &&
		    READ_ONCE(conn->state) != TQUIC_CONN_CONNECTED)
			continue;

		if (!refcount_inc_not_zero(&conn->refcnt))
			continue;

		ref = kmalloc(sizeof(*ref), GFP_ATOMIC);
		if (!ref) {
			tquic_conn_put(conn);
			continue;
		}

		ref->conn = conn;
		list_add_tail(&ref->list, conn_refs);
	}
	spin_unlock_bh(&tn->conn_lock);
}

static void tquic_pm_kernel_release_conn_refs(struct list_head *conn_refs)
{
	struct tquic_pm_kernel_conn_ref *ref, *tmp;

	list_for_each_entry_safe(ref, tmp, conn_refs, list) {
		list_del_init(&ref->list);
		tquic_conn_put(ref->conn);
		kfree(ref);
	}
}

/**
 * tquic_pm_kernel_netdev_event - Netdevice notifier callback
 * @nb: Notifier block
 * @event: Event type
 * @ptr: Event data (struct net_device)
 *
 * Handles interface up/down/change events for automatic path discovery.
 */
static int tquic_pm_kernel_netdev_event(struct notifier_block *nb,
					unsigned long event, void *ptr)
{
	struct net_device *dev = netdev_notifier_info_to_dev(ptr);
	struct tquic_pm_pernet *pernet;
	struct net *net = dev_net(dev);
	struct tquic_net *tn;

	(void)nb;
	pernet = tquic_pm_get_pernet(net);
	tn = tquic_pernet(net);

	if (!pernet || !tn || !pernet->auto_discover)
		return NOTIFY_DONE;

	switch (event) {
	case NETDEV_UP:
		/* Interface came up - first try to recover, then discover new */
		{
			LIST_HEAD(conn_refs);
			struct tquic_pm_kernel_conn_ref *ref;

			tquic_pm_kernel_collect_conn_refs(tn, &conn_refs, true);

			list_for_each_entry(ref, &conn_refs, list)
				tquic_pm_kernel_try_recover(ref->conn, dev);

			/* Then: discover new paths through this interface */
			if (tquic_pm_kernel_should_add_path(dev, pernet)) {
				list_for_each_entry(ref, &conn_refs, list)
					tquic_pm_kernel_try_add_path(
						ref->conn, dev, pernet);
			}

			tquic_pm_kernel_release_conn_refs(&conn_refs);
		}
		break;

	case NETDEV_DOWN:
		/* Interface went down - mark paths unavailable */
		{
			LIST_HEAD(conn_refs);
			struct tquic_pm_kernel_conn_ref *ref;

			tquic_pm_kernel_collect_conn_refs(tn, &conn_refs,
							  false);

			list_for_each_entry(ref, &conn_refs, list)
				tquic_pm_kernel_mark_unavailable(ref->conn,
								 dev);

			tquic_pm_kernel_release_conn_refs(&conn_refs);
		}
		break;

	case NETDEV_CHANGE:
		/* Carrier state changed - handle same as up/down */
		if (netif_carrier_ok(dev)) {
			/* Carrier up - same as NETDEV_UP for recovery */
			LIST_HEAD(conn_refs);
			struct tquic_pm_kernel_conn_ref *ref;

			tquic_pm_kernel_collect_conn_refs(tn, &conn_refs, true);

			list_for_each_entry(ref, &conn_refs, list)
				tquic_pm_kernel_try_recover(ref->conn, dev);

			tquic_pm_kernel_release_conn_refs(&conn_refs);
		} else {
			/* Carrier down - same as NETDEV_DOWN */
			LIST_HEAD(conn_refs);
			struct tquic_pm_kernel_conn_ref *ref;

			tquic_pm_kernel_collect_conn_refs(tn, &conn_refs,
							  false);

			list_for_each_entry(ref, &conn_refs, list)
				tquic_pm_kernel_mark_unavailable(ref->conn,
								 dev);

			tquic_pm_kernel_release_conn_refs(&conn_refs);
		}
		break;
	}

	return NOTIFY_DONE;
}

/**
 * tquic_pm_kernel_path_event - Handle path events
 * @conn: Connection
 * @path: Path that had the event
 * @event: Event type (TQUIC_PM_EVENT_*)
 *
 * Mirrors path state changes into the bpm and triggers migration when a
 * newly validated path is better than the current primary.
 */
static void tquic_pm_kernel_path_event(struct tquic_connection *conn,
				       struct tquic_path *path, int event)
{
	struct tquic_bpm_path_manager *bpm;
	struct tquic_bpm_path *bpath;

	pr_debug("TQUIC PM kernel: Path %u event %d\n", path->path_id, event);

	if (!conn || !conn->pm)
		return;

	bpm = conn->pm->priv;
	if (!bpm)
		return;

	bpath = tquic_bpm_get_path(bpm, path->path_id);
	if (!bpath)
		return;

	switch (event) {
	case TQUIC_PM_EVENT_VALIDATED:
		/*
		 * Path validated -- promote to VALIDATED in the bpm and
		 * trigger a migration check.  tquic_migrate_to_path() is a
		 * no-op if this path is not better than the current primary.
		 */
		tquic_bpm_path_set_state(bpath, TQUIC_BPM_PATH_VALIDATED);
		tquic_migrate_to_path(bpm, bpath);

		/*
		 * Log the current number of active paths in the bpm for
		 * diagnostics.  tquic_bpm_get_active_paths() returns only
		 * VALIDATED, ACTIVE, or STANDBY bpm paths.
		 */
		{
			struct tquic_bpm_path *active[TQUIC_MAX_PATHS];
			int n;

			n = tquic_bpm_get_active_paths(bpm, active,
						       ARRAY_SIZE(active));
			pr_debug("TQUIC PM kernel: %d active bpm path(s) after validation of path %u\n",
				 n, path->path_id);
		}
		break;

	case TQUIC_PM_EVENT_FAILED:
		/*
		 * Path failed -- mark FAILED in bpm.  The bpm on_path_failed
		 * callback will trigger failover to the backup path.
		 */
		tquic_bpm_path_set_state(bpath, TQUIC_BPM_PATH_FAILED);
		break;

	default:
		break;
	}
}

/**
 * tquic_pm_kernel_init - Initialize kernel PM for a netns
 * @net: Network namespace
 *
 * Registers netdevice notifier and sets up per-netns kernel PM data.
 * Stores the kdata pointer in pernet->pm_data for later retrieval
 * and cleanup. Guards against double-init (idempotent).
 */
static int tquic_pm_kernel_init(struct net *net)
{
	struct tquic_pm_pernet *pernet;
	struct tquic_pm_kernel_data *kdata;
	int ret;

	pernet = tquic_pm_get_pernet(net);
	if (!pernet)
		return -ENOENT;

	/* Already initialized for this namespace - idempotent */
	if (pernet->pm_data)
		return 0;

	kdata = kzalloc(sizeof(*kdata), GFP_KERNEL);
	if (!kdata)
		return -ENOMEM;

	/* Register netdevice notifier */
	kdata->netdev_notifier.notifier_call = tquic_pm_kernel_netdev_event;
	ret = tquic_register_netdevice_notifier_net(net,
						    &kdata->netdev_notifier);
	if (ret < 0) {
		pr_err("TQUIC PM kernel: Failed to register netdev notifier: %d\n",
		       ret);
		kfree(kdata);
		return ret;
	}

	/* Store in pernet for retrieval and cleanup */
	pernet->pm_data = kdata;

	pr_info("TQUIC PM kernel: Initialized for netns\n");
	return 0;
}

/**
 * tquic_pm_kernel_release - Cleanup kernel PM for a netns
 * @net: Network namespace
 *
 * Unregisters the netdevice notifier and frees the per-namespace
 * kernel PM data. Called during pernet exit or PM type switch.
 */
static void tquic_pm_kernel_release(struct net *net)
{
	struct tquic_pm_pernet *pernet;
	struct tquic_pm_kernel_data *kdata;

	pernet = tquic_pm_get_pernet(net);
	if (!pernet || !pernet->pm_data)
		return;

	kdata = pernet->pm_data;

	/* Unregister netdevice notifier */
	tquic_unregister_netdevice_notifier_net(net, &kdata->netdev_notifier);

	kfree(kdata);
	pernet->pm_data = NULL;

	pr_info("TQUIC PM kernel: Released for netns\n");
}

/**
 * tquic_pm_kernel_conn_init - Initialize kernel PM for a specific connection
 * @conn: Connection
 *
 * Creates a tquic_bpm_path_manager instance, stores it in conn->pm->priv,
 * then scans existing interfaces for auto-discovery.  Also kicks off
 * async path discovery and WAN signal-strength monitoring via the bpm.
 * This complements the netdevice notifier which only catches future events.
 *
 * Returns 0 on success, negative error code on failure.
 */
static int tquic_pm_kernel_conn_init(struct tquic_connection *conn)
{
	struct tquic_bpm_path_manager *bpm;
	struct tquic_pm_pernet *pernet;
	struct net_device *dev;
	struct net *net;

	if (!conn || !conn->sk || !conn->pm)
		return -EINVAL;

	net = sock_net(conn->sk);

	/*
	 * Allocate a bpm instance for this connection.  The bpm manages
	 * path lifecycle (validation, scoring, migration) and integrates
	 * with the bonding layer via callbacks.
	 */
	bpm = tquic_bpm_init(net, GFP_KERNEL);
	if (!bpm)
		return -ENOMEM;

	conn->pm->priv = bpm;

	/*
	 * Kick off async path discovery: enumerate local interfaces and
	 * add candidate paths.  Runs via workqueue so it is softirq-safe.
	 */
	tquic_bpm_discover_paths(bpm);

	/*
	 * Start WAN signal-strength monitoring so that the bpm can trigger
	 * proactive migration when an interface degrades (e.g. weak LTE).
	 */
	tquic_wan_monitor_start(bpm);

	pernet = tquic_pm_get_pernet(net);
	if (!pernet || !pernet->auto_discover) {
		pr_debug("tquic kernel PM: bpm %p ready (auto_discover off)\n",
			 bpm);
		return 0;
	}

	/*
	 * Scan currently-UP interfaces and add paths for any that meet the
	 * WAN-bonding criteria.  The netdevice notifier handles future events.
	 */
	rtnl_lock();
	for_each_netdev(net, dev) {
		if (!(dev->flags & IFF_UP))
			continue;

		if (tquic_pm_kernel_should_add_path(dev, pernet)) {
			/*
			 * Ignore per-device errors: a failed add (e.g. max
			 * paths, no IPv4) must not abort discovery of others.
			 */
			tquic_pm_kernel_try_add_path(conn, dev, pernet);
		}
	}
	rtnl_unlock();

	pr_debug("tquic kernel PM: bpm %p initialized for conn %p\n",
		 bpm, conn);
	return 0;
}

/**
 * tquic_pm_kernel_add_path - Add a path via kernel PM bpm
 * @conn: Connection
 * @local: Local address for the new path
 * @remote: Remote address for the new path
 *
 * Creates a bpm path entry and starts RFC 9000 Section 8.2 validation.
 *
 * Returns 0 on success, negative error code on failure.
 */
static int tquic_pm_kernel_add_path(struct tquic_connection *conn,
				    struct sockaddr *local,
				    struct sockaddr *remote)
{
	struct tquic_bpm_path_manager *bpm;
	struct tquic_bpm_path *bpath;

	if (!conn || !conn->pm)
		return -EINVAL;

	bpm = conn->pm->priv;
	if (!bpm)
		return -ENODEV;

	bpath = tquic_bpm_add_path(bpm, local, remote, -1);
	if (!bpath)
		return -ENOMEM;

	tquic_dbg("kernel PM: added bpm path %u\n", bpath->path_id);
	return 0;
}

/**
 * tquic_pm_kernel_del_path - Remove a path via kernel PM bpm
 * @conn: Connection
 * @path_id: ID of path to remove
 *
 * Looks up the bpm path and removes it.
 *
 * Returns 0 on success, -ENOENT if not found.
 */
static int tquic_pm_kernel_del_path(struct tquic_connection *conn,
				    u32 path_id)
{
	struct tquic_bpm_path_manager *bpm;
	struct tquic_bpm_path *bpath;

	if (!conn || !conn->pm)
		return -EINVAL;

	bpm = conn->pm->priv;
	if (!bpm)
		return -ENODEV;

	bpath = tquic_bpm_get_path(bpm, path_id);
	if (!bpath)
		return -ENOENT;

	tquic_bpm_remove_path(bpm, bpath);
	tquic_dbg("kernel PM: removed bpm path %u\n", path_id);
	return 0;
}

/**
 * tquic_pm_kernel_conn_release - Release bpm for a connection
 * @conn: Connection being torn down
 *
 * Destroys the tquic_bpm_path_manager instance allocated by
 * tquic_pm_kernel_conn_init().  Cancels all outstanding path work,
 * removes paths from the bpm registry, and frees the structure.
 */
static void tquic_pm_kernel_conn_release(struct tquic_connection *conn)
{
	struct tquic_bpm_path_manager *bpm;

	if (!conn || !conn->pm)
		return;

	bpm = conn->pm->priv;
	if (!bpm)
		return;

	tquic_bpm_destroy(bpm);
	conn->pm->priv = NULL;
}

/* Kernel PM operations structure */
static struct tquic_pm_ops kernel_pm_ops = {
	.name		= "kernel",
	.init		= tquic_pm_kernel_init,
	.release	= tquic_pm_kernel_release,
	.conn_init	= tquic_pm_kernel_conn_init,
	.conn_release	= tquic_pm_kernel_conn_release,
	.add_path	= tquic_pm_kernel_add_path,
	.del_path	= tquic_pm_kernel_del_path,
	.path_event	= tquic_pm_kernel_path_event,
};

/**
 * tquic_pm_kernel_module_init - Register kernel PM type
 *
 * Called during TQUIC module initialization to register kernel PM.
 */
int __init tquic_pm_kernel_module_init(void)
{
	int ret;

	ret = tquic_pm_register(&kernel_pm_ops, TQUIC_PM_TYPE_KERNEL);
	if (ret < 0) {
		pr_err("TQUIC PM kernel: Registration failed: %d\n", ret);
		return ret;
	}

	pr_info("TQUIC PM kernel: Registered\n");
	return 0;
}

/**
 * tquic_pm_kernel_module_exit - Unregister kernel PM type
 */
void tquic_pm_kernel_module_exit(void)
{
	tquic_pm_unregister(TQUIC_PM_TYPE_KERNEL);
	pr_info("TQUIC PM kernel: Unregistered\n");
}
