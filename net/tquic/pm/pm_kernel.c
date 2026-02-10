// SPDX-License-Identifier: GPL-2.0-only
/*
 * TQUIC Kernel Automatic Path Manager
 *
 * Copyright (c) 2026 Linux Foundation
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

/* Kernel PM private data per-namespace */
struct tquic_pm_kernel_data {
	struct notifier_block netdev_notifier;
	struct list_head conn_list;	/* Connections in this netns */
	spinlock_t conn_lock;
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
						       path, TQUIC_PM_EVENT_DEGRADED);

			pr_debug("tquic: path %u marked unavailable (interface %s down)\n",
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
			pr_debug("tquic: path %u recovering (interface %s up)\n",
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
	struct sockaddr_in local_addr = {0};
	struct sockaddr_in remote_addr = {0};
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

	pr_info("TQUIC PM kernel: Added path for dev %s (%pI4)\n",
		dev->name, &local_addr.sin_addr);

	return 0;
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
					unsigned long event,
					void *ptr)
{
	struct net_device *dev = netdev_notifier_info_to_dev(ptr);
	struct tquic_pm_kernel_data *kdata;
	struct tquic_pm_pernet *pernet;
	struct net *net = dev_net(dev);

	kdata = container_of(nb, struct tquic_pm_kernel_data, netdev_notifier);
	pernet = tquic_pm_get_pernet(net);

	if (!pernet || !pernet->auto_discover)
		return NOTIFY_DONE;

	switch (event) {
	case NETDEV_UP:
		/* Interface came up - first try to recover, then discover new */
		{
			struct tquic_connection *conn, *tmp;

			spin_lock_bh(&kdata->conn_lock);
			list_for_each_entry_safe(conn, tmp, &kdata->conn_list, pm_node) {
				/* Skip if connection not established yet */
				if (READ_ONCE(conn->state) != TQUIC_CONN_CONNECTED)
					continue;

				/* First: try to recover unavailable paths */
				tquic_pm_kernel_try_recover(conn, dev);
			}
			spin_unlock_bh(&kdata->conn_lock);

			/* Then: discover new paths through this interface */
			if (tquic_pm_kernel_should_add_path(dev, pernet)) {
				spin_lock_bh(&kdata->conn_lock);
				list_for_each_entry_safe(conn, tmp, &kdata->conn_list, pm_node) {
					if (READ_ONCE(conn->state) != TQUIC_CONN_CONNECTED)
						continue;

					tquic_pm_kernel_try_add_path(conn, dev, pernet);
				}
				spin_unlock_bh(&kdata->conn_lock);
			}
		}
		break;

	case NETDEV_DOWN:
		/* Interface went down - mark paths unavailable */
		{
			struct tquic_connection *conn, *tmp;

			spin_lock_bh(&kdata->conn_lock);
			list_for_each_entry_safe(conn, tmp, &kdata->conn_list, pm_node) {
				tquic_pm_kernel_mark_unavailable(conn, dev);
			}
			spin_unlock_bh(&kdata->conn_lock);
		}
		break;

	case NETDEV_CHANGE:
		/* Carrier state changed - handle same as up/down */
		if (netif_carrier_ok(dev)) {
			/* Carrier up - same as NETDEV_UP for recovery */
			struct tquic_connection *conn, *tmp;

			spin_lock_bh(&kdata->conn_lock);
			list_for_each_entry_safe(conn, tmp, &kdata->conn_list, pm_node) {
				if (READ_ONCE(conn->state) != TQUIC_CONN_CONNECTED)
					continue;

				tquic_pm_kernel_try_recover(conn, dev);
			}
			spin_unlock_bh(&kdata->conn_lock);
		} else {
			/* Carrier down - same as NETDEV_DOWN */
			struct tquic_connection *conn, *tmp;

			spin_lock_bh(&kdata->conn_lock);
			list_for_each_entry_safe(conn, tmp, &kdata->conn_list, pm_node) {
				tquic_pm_kernel_mark_unavailable(conn, dev);
			}
			spin_unlock_bh(&kdata->conn_lock);
		}
		break;
	}

	return NOTIFY_DONE;
}

/**
 * tquic_pm_kernel_path_event - Handle path events
 * @conn: Connection
 * @path: Path that had the event
 * @event: Event type
 *
 * Internal tracking callback for path state changes.
 */
static void tquic_pm_kernel_path_event(struct tquic_connection *conn,
				       struct tquic_path *path,
				       int event)
{
	/* Kernel PM is mostly passive - path validation happens
	 * automatically via PATH_CHALLENGE/PATH_RESPONSE.
	 * This callback is for internal tracking if needed.
	 */
	pr_debug("TQUIC PM kernel: Path %u event %d\n", path->path_id, event);
}

/**
 * tquic_pm_kernel_init - Initialize kernel PM for a netns
 * @net: Network namespace
 *
 * Registers netdevice notifier and sets up per-netns kernel PM data.
 */
static int tquic_pm_kernel_init(struct net *net)
{
	struct tquic_pm_kernel_data *kdata;
	int ret;

	kdata = kzalloc(sizeof(*kdata), GFP_KERNEL);
	if (!kdata)
		return -ENOMEM;

	spin_lock_init(&kdata->conn_lock);
	INIT_LIST_HEAD(&kdata->conn_list);

	/* Register netdevice notifier */
	kdata->netdev_notifier.notifier_call = tquic_pm_kernel_netdev_event;
	ret = tquic_register_netdevice_notifier_net(net, &kdata->netdev_notifier);
	if (ret < 0) {
		pr_err("TQUIC PM kernel: Failed to register netdev notifier: %d\n",
		       ret);
		kfree(kdata);
		return ret;
	}

	pr_info("TQUIC PM kernel: Initialized for netns\n");
	return 0;
}

/**
 * tquic_pm_kernel_release - Cleanup kernel PM for a netns
 * @net: Network namespace
 */
static void tquic_pm_kernel_release(struct net *net)
{
	/* Note: Per-netns kernel data cleanup happens in pernet exit.
	 * This is called when PM type switches away from kernel PM.
	 */
	pr_info("TQUIC PM kernel: Released for netns\n");
}

/* Kernel PM operations structure */
static struct tquic_pm_ops kernel_pm_ops = {
	.name = "kernel",
	.init = tquic_pm_kernel_init,
	.release = tquic_pm_kernel_release,
	.add_path = NULL,	/* Auto-managed, not externally controlled */
	.del_path = NULL,	/* Auto-managed */
	.path_event = tquic_pm_kernel_path_event,
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
void __exit tquic_pm_kernel_module_exit(void)
{
	tquic_pm_unregister(TQUIC_PM_TYPE_KERNEL);
	pr_info("TQUIC PM kernel: Unregistered\n");
}
