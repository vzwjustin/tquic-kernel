// SPDX-License-Identifier: GPL-2.0-only
/*
 * TQUIC Userspace Path Manager
 *
 * Copyright (c) 2026 Justin Adams <spotty118@gmail.com>
 * Kernel implementation by Justin Adams <spotty118@gmail.com>
 *
 * Implements a userspace-controlled path manager where all path management
 * decisions are delegated to a userspace daemon via netlink. All path events
 * are forwarded to userspace for monitoring and reactive control.
 */

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <net/sock.h>
#include <net/tquic.h>
#include <net/tquic_pm.h>
#include "../tquic_debug.h"
#include <uapi/linux/tquic_pm.h>

/*
 * Per-connection userspace PM state
 *
 * Minimal state since all decisions come from userspace.
 */
struct tquic_pm_userspace_state {
	struct tquic_connection *conn;
	bool initialized;
};

/*
 * Initialize userspace PM for a connection
 *
 * Allocates minimal state and notifies userspace that a new connection
 * is ready for path management.
 */
static int tquic_pm_userspace_init_net(struct net *net)
{
	/* Per-netns initialization - nothing needed for userspace PM */
	pr_debug("TQUIC PM: Userspace PM initialized for netns\n");
	return 0;
}

/*
 * Release userspace PM for a connection
 *
 * Notifies userspace that connection is closing.
 */
static void tquic_pm_userspace_release(struct net *net)
{
	/* Per-netns cleanup - nothing needed for userspace PM */
	pr_debug("TQUIC PM: Userspace PM released for netns\n");
}

/*
 * Add path (userspace-triggered)
 *
 * Called when userspace sends TQUIC_PM_CMD_ADD_PATH netlink command.
 * Validates parameters and calls core path addition logic.
 */
static int tquic_pm_userspace_add_path(struct tquic_connection *conn,
				       struct sockaddr *local,
				       struct sockaddr *remote)
{
	struct net *net = sock_net(conn->sk);
	struct tquic_path *path;
	int err;

	/* Validate parameters */
	if (!local || !remote) {
		pr_warn("TQUIC PM: Invalid address parameters for add_path\n");
		return -EINVAL;
	}

	if (local->sa_family != remote->sa_family) {
		pr_warn("TQUIC PM: Address family mismatch\n");
		return -EINVAL;
	}

	/* Call core path addition (from connection management) */
	err = tquic_conn_add_path(conn, local, remote);
	if (err) {
		pr_warn("TQUIC PM: Failed to add path: %d\n", err);
		return err;
	}

	/* Find the newly added path to emit event */
	list_for_each_entry_reverse(path, &conn->paths, list) {
		/* Emit CREATED event to userspace */
		tquic_pm_nl_send_event(net, conn, path, TQUIC_PM_EVENT_CREATED);
		break;
	}

	pr_debug("TQUIC PM: Path added via userspace control\n");
	return 0;
}

/*
 * Delete path (userspace-triggered)
 *
 * Called when userspace sends TQUIC_PM_CMD_DEL_PATH netlink command.
 */
static int tquic_pm_userspace_del_path(struct tquic_connection *conn,
				       u32 path_id)
{
	struct net *net = sock_net(conn->sk);
	struct tquic_path *path;
	int err;

	/* Find path before removal to emit event */
	path = tquic_conn_get_path(conn, path_id);
	if (path) {
		/* Emit REMOVED event before deletion */
		tquic_pm_nl_send_event(net, conn, path, TQUIC_PM_EVENT_REMOVED);
	}

	/* Call core path removal */
	err = tquic_conn_remove_path(conn, path_id);
	if (err) {
		pr_warn("TQUIC PM: Failed to remove path %u: %d\n", path_id, err);
		return err;
	}

	pr_debug("TQUIC PM: Path %u removed via userspace control\n", path_id);
	return 0;
}

/*
 * Path event notification
 *
 * Called by core connection code when path state changes.
 * Forwards all events to userspace via netlink multicast.
 */
static void tquic_pm_userspace_path_event(struct tquic_connection *conn,
					  struct tquic_path *path,
					  int event)
{
	struct net *net = sock_net(conn->sk);
	int netlink_event;

	/* Map internal event to netlink event type */
	switch (event) {
	case 0: /* PATH_ADDED */
		netlink_event = TQUIC_PM_EVENT_CREATED;
		break;
	case 1: /* PATH_VALIDATED */
		netlink_event = TQUIC_PM_EVENT_VALIDATED;
		break;
	case 2: /* PATH_FAILED */
		netlink_event = TQUIC_PM_EVENT_FAILED;
		break;
	case 3: /* PATH_REMOVED */
		netlink_event = TQUIC_PM_EVENT_REMOVED;
		break;
	case 4: /* PATH_DEGRADED */
		netlink_event = TQUIC_PM_EVENT_DEGRADED;
		break;
	default:
		pr_debug("TQUIC PM: Unknown path event %d\n", event);
		return;
	}

	/* Forward to userspace via netlink multicast */
	tquic_pm_nl_send_event(net, conn, path, netlink_event);

	pr_debug("TQUIC PM: Forwarded event %d for path %u to userspace\n",
		 netlink_event, path->path_id);
}

/*
 * Userspace PM operations structure
 */
struct tquic_pm_ops userspace_pm_ops = {
	.name		= "userspace",
	.init		= tquic_pm_userspace_init_net,
	.release	= tquic_pm_userspace_release,
	.add_path	= tquic_pm_userspace_add_path,
	.del_path	= tquic_pm_userspace_del_path,
	.path_event	= tquic_pm_userspace_path_event,
};

/*
 * Module initialization
 *
 * Register userspace PM type with the PM framework.
 */
int __init tquic_pm_userspace_init_module(void)
{
	int ret;

	ret = tquic_pm_register(&userspace_pm_ops, TQUIC_PM_TYPE_USERSPACE);
	if (ret) {
		pr_err("TQUIC PM: Failed to register userspace PM: %d\n", ret);
		return ret;
	}

	pr_info("TQUIC PM: Userspace path manager registered\n");
	return 0;
}

/*
 * Module cleanup
 */
void __exit tquic_pm_userspace_exit_module(void)
{
	tquic_pm_unregister(TQUIC_PM_TYPE_USERSPACE);
	pr_info("TQUIC PM: Userspace path manager unregistered\n");
}

/* Export for integration into tquic_pm module */
int __init tquic_pm_userspace_init(void)
{
	return tquic_pm_userspace_init_module();
}

void tquic_pm_userspace_exit(void)
{
	tquic_pm_userspace_exit_module();
}
