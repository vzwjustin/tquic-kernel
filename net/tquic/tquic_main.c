// SPDX-License-Identifier: GPL-2.0-only
/*
 * TQUIC: WAN Bonding over QUIC - Main Module
 *
 * Copyright (c) 2026 Justin Adams <spotty118@gmail.com>
 * Kernel implementation by Justin Adams <spotty118@gmail.com>
 *
 * This is the main entry point for the TQUIC subsystem, providing
 * WAN bonding capabilities using the QUIC protocol.
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/slab.h>
#include <linux/rculist.h>
#include <linux/rhashtable.h>
#include <linux/net.h>
#include <linux/socket.h>
#include <linux/skbuff.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/timer.h>
#include <net/sock.h>
#include <net/protocol.h>
#include <net/inet_common.h>
#include <net/udp.h>
#include <net/udp_tunnel.h>
#include <net/route.h>
#include <net/dst.h>
#include <net/tquic.h>
#include <net/tquic_pm.h>
#include "protocol.h"
#include "grease.h"
#if IS_ENABLED(CONFIG_TQUIC_IO_URING)
#include "io_uring.h"
#endif
#if IS_ENABLED(CONFIG_TQUIC_NAPI)
#include "napi.h"
#endif
/* Use core ack_frequency.h instead of wrapper to avoid conflicting declarations */
#include "core/ack_frequency.h"
#include "tquic_preferred_addr.h"
#include "rate_limit.h"
#include "tquic_ratelimit.h"
#include "tquic_retry.h"
#include "tquic_stateless_reset.h"
#include "tquic_token.h"
#include "tquic_compat.h"
#include "tquic_init.h"
#include "tquic_debug.h"
#include "core/quic_loss.h"
#if IS_REACHABLE(CONFIG_TQUIC_DIAG)
#include "diag/path_metrics.h"
#endif

/* Module info */
MODULE_AUTHOR("Justin Adams <spotty118@gmail.com>");
MODULE_DESCRIPTION("TQUIC: WAN Bonding over QUIC");
MODULE_LICENSE("GPL");
MODULE_VERSION("1.0.0");

/* Global state */
struct rhashtable tquic_conn_table;
EXPORT_SYMBOL_GPL(tquic_conn_table);
struct kmem_cache *tquic_conn_cache;
EXPORT_SYMBOL_GPL(tquic_conn_cache);
struct kmem_cache *tquic_stream_cache;
EXPORT_SYMBOL_GPL(tquic_stream_cache);
extern struct kmem_cache *tquic_path_cache;

/*
 * Slab cache for per-packet RX decryption buffers.
 *
 * Every received QUIC packet requires a temporary buffer for decrypted
 * payload. Using kmalloc(GFP_ATOMIC) per packet on the hot path causes
 * significant overhead from the general-purpose allocator. A dedicated
 * slab cache with fixed-size objects eliminates that overhead for the
 * common case (packets <= TQUIC_RX_BUF_SIZE bytes).
 *
 * Size: 2048 bytes covers all standard QUIC packets (MTU <= 1500).
 * Packets exceeding this size fall back to kmalloc.
 */
#define TQUIC_RX_BUF_SIZE	2048
struct kmem_cache *tquic_rx_buf_cache;
EXPORT_SYMBOL_GPL(tquic_rx_buf_cache);

/* Connection hashtable params */
const struct rhashtable_params tquic_conn_params = {
	.key_len = sizeof(struct tquic_cid),
	.key_offset = offsetof(struct tquic_connection, scid),
	.head_offset = offsetof(struct tquic_connection, node),
	.automatic_shrinking = true,
};

/*
 * Scheduler registration is handled by multipath/tquic_scheduler.c which
 * provides tquic_register_scheduler() and tquic_unregister_scheduler().
 */

/* Default scheduler name */
static char tquic_default_scheduler[TQUIC_MAX_SCHED_NAME] = "minrtt";
module_param_string(scheduler, tquic_default_scheduler,
		    sizeof(tquic_default_scheduler), 0600);
MODULE_PARM_DESC(scheduler, "Default packet scheduler for WAN bonding");

/* Default congestion control */
static char tquic_default_cong[TQUIC_MAX_CONG_NAME] = "cubic";
module_param_string(congestion, tquic_default_cong,
		    sizeof(tquic_default_cong), 0600);
MODULE_PARM_DESC(congestion, "Default congestion control algorithm");

/* Default bonding mode */
static int tquic_default_bond_mode = TQUIC_BOND_MODE_AGGREGATE;
module_param_named(bond_mode, tquic_default_bond_mode, int, 0600);
MODULE_PARM_DESC(bond_mode, "Default WAN bonding mode");

/*
 * Connection Management
 *
 * Note: tquic_conn_create is defined in net/tquic/core/quic_connection.c
 * with signature: tquic_conn_create(struct tquic_sock *tsk, bool is_server)
 */

void tquic_conn_destroy(struct tquic_connection *conn)
{
	struct tquic_path *path, *tmp_path;
	LIST_HEAD(dead_paths);
	struct rb_node *node;
	void *sched;

	tquic_dbg("tquic_conn_destroy: conn=%p\n", conn);

	if (!conn)
		return;

	/*
	 * SECURITY FIX (CF-119): This function must only be called from
	 * tquic_conn_put() when the refcount has already reached zero.
	 * Direct callers must use tquic_conn_put() instead.
	 */
	WARN_ON_ONCE(refcount_read(&conn->refcnt) != 0);

	/* Unbind from server client tracking before teardown */
	tquic_server_unbind_client(conn);

#if IS_REACHABLE(CONFIG_TQUIC_DIAG)
	/* Drop any outstanding per-connection metrics subscriptions. */
	tquic_metrics_unsubscribe_conn(conn);
#endif

	/* Release path manager state if still attached */
	tquic_pm_conn_release(conn);

	/* Clean up state machine first */
	if (conn->state_machine) {
		u32 magic = *(u32 *)conn->state_machine;

		switch (magic) {
		case TQUIC_SM_MAGIC_CONN_STATE:
			tquic_conn_state_cleanup(conn);
			break;
		case TQUIC_SM_MAGIC_MIGRATION:
			tquic_migration_cleanup(conn);
			break;
		case TQUIC_SM_MAGIC_SESSION:
			tquic_session_cleanup(conn);
			break;
		default:
			WARN_ON_ONCE(1);
			kfree(conn->state_machine);
			conn->state_machine = NULL;
			break;
		}
	}

	/* Remove from global table */
	rhashtable_remove_fast(&tquic_conn_table, &conn->node, tquic_conn_params);

	/*
	 * Free timer state (cancels pacing hrtimer + ts->timer_work).
	 * tquic_timer_work_fn() may schedule conn->tx_work on its last run,
	 * so cancel tx/rx/close work AFTER this call to catch any last-moment
	 * scheduling.
	 */
	if (conn->timer_state)
		tquic_timer_state_free(conn->timer_state);
	cancel_work_sync(&conn->tx_work);
	cancel_work_sync(&conn->rx_work);
	cancel_work_sync(&conn->close_work);

	/*
	 * Phase 1: unlink all paths from the RCU list and collect them.
	 * Do NOT call synchronize_rcu() here — we batch all removals so a
	 * single grace period covers every path and the scheduler pointer.
	 */
	list_for_each_entry_safe(path, tmp_path, &conn->paths, list) {
		list_del_rcu(&path->list);
		timer_delete_sync(&path->validation_timer);
		timer_delete_sync(&path->validation.timer);
		skb_queue_purge(&path->response.queue);
		list_add(&path->list, &dead_paths);
	}

	/*
	 * Phase 2: NULL the scheduler pointer before the grace period so
	 * that concurrent RCU readers see NULL rather than a freed pointer
	 * as soon as the quiescent state completes.
	 */
	sched = conn->scheduler;
	conn->scheduler = NULL;

	/*
	 * Free all streams with proper accounting and refcount safety.
	 *
	 * Historically we freed streams directly here. That is unsafe if any
	 * concurrent code still holds a transient tquic_stream_get() reference
	 * (e.g. softirq delivery paths) while the socket drops its last conn ref.
	 *
	 * Tear-down strategy:
	 * - Remove from rb-tree under conn->lock so new lookups can't find it.
	 * - Purge/uncharge buffers while conn + sk are still valid.
	 * - Detach stream->conn so a delayed final tquic_stream_put() won't
	 *   dereference freed connection memory in tquic_stream_free().
	 * - Drop the tree ownership reference via tquic_stream_put().
	 */
	spin_lock_bh(&conn->lock);
	while ((node = rb_first(&conn->streams))) {
		struct tquic_stream *stream = rb_entry(node, struct tquic_stream, node);
		struct sk_buff *skb;
		u64 queued = 0;

		rb_erase(node, &conn->streams);
		RB_CLEAR_NODE(&stream->node);
		spin_unlock_bh(&conn->lock);

		/* Purge send buffer and accumulate queued bytes for FC reservation. */
		while ((skb = skb_dequeue(&stream->send_buf)) != NULL) {
			queued += skb->len;
			if (conn->sk)
				sk_mem_uncharge(conn->sk, skb->truesize);
			kfree_skb(skb);
		}

		if (queued) {
			spin_lock_bh(&conn->lock);
			if (conn->fc_data_reserved >= queued)
				conn->fc_data_reserved -= queued;
			else
				conn->fc_data_reserved = 0;
			spin_unlock_bh(&conn->lock);
		}

		/* Purge receive buffer. */
		while ((skb = skb_dequeue(&stream->recv_buf)) != NULL) {
			if (conn->sk)
				sk_mem_uncharge(conn->sk, skb->truesize);
			kfree_skb(skb);
		}

		/*
		 * Prevent late stream_free from touching a freed connection if
		 * some ref holder races with teardown.
		 */
		WRITE_ONCE(stream->conn, NULL);

		/* Drop tree ownership reference. */
		tquic_stream_put(stream);

		spin_lock_bh(&conn->lock);
	}
	spin_unlock_bh(&conn->lock);

	/* Free crypto state if allocated */
	tquic_crypto_cleanup(conn->crypto_state);

	/* Free zerocopy state if allocated */
	if (conn->zc_state)
		tquic_zc_state_free(conn);

	/*
	 * Phase 3: single grace period covers both the path list removals
	 * (list_del_rcu above) and the scheduler pointer store.  Waiting
	 * once rather than once-per-path avoids O(N) quiescent-state waits
	 * when a connection has multiple bonded paths.
	 */
	synchronize_rcu();

	/*
	 * Phase 4: free all collected paths now that no RCU reader can
	 * observe them on conn->paths.
	 */
	list_for_each_entry_safe(path, tmp_path, &dead_paths, list) {
		INIT_LIST_HEAD(&path->list);
		tquic_path_put(path);
	}

	/*
	 * Phase 5: free the scheduler state now that the grace period has
	 * elapsed and conn->scheduler is already NULL.
	 */
	if (sched) {
		if (test_bit(TQUIC_F_BONDING_ENABLED, &conn->flags)) {
			tquic_bond_cleanup(sched);
			clear_bit(TQUIC_F_BONDING_ENABLED, &conn->flags);
		} else {
			kfree(sched);
		}
	}

	/*
	 * SECURITY FIX (CF-134, updated): tquic_conn_create() now uses
	 * kmem_cache_zalloc(tquic_conn_cache), so free via the same cache.
	 */
	kmem_cache_free(tquic_conn_cache, conn);
}
EXPORT_SYMBOL_GPL(tquic_conn_destroy);

/*
 * Path Management for WAN Bonding
 */

static int tquic_conn_alloc_path_id_locked(struct tquic_connection *conn)
{
	bool used[TQUIC_MAX_PATHS] = { 0 };
	struct tquic_path *path;
	u32 id;

	tquic_conn_dbg(conn, "alloc_path_id_locked: num_paths=%u\n",
		       conn->num_paths);

	list_for_each_entry(path, &conn->paths, list) {
		if (path->path_id < TQUIC_MAX_PATHS)
			used[path->path_id] = true;
	}

	for (id = 0; id < TQUIC_MAX_PATHS; id++) {
		if (!used[id]) {
			tquic_conn_dbg(conn, "alloc_path_id_locked: ret=%u\n",
				       id);
			return id;
		}
	}

	tquic_conn_dbg(conn, "alloc_path_id_locked: ret=-ENOSPC\n");
	return -ENOSPC;
}

int tquic_conn_add_path(struct tquic_connection *conn,
			struct sockaddr *local, struct sockaddr *remote)
{
	struct tquic_path *path;
	int path_id;

	if (conn->num_paths >= TQUIC_MAX_PATHS)
		return -ENOSPC;

	path = kmem_cache_zalloc(tquic_path_cache, GFP_KERNEL);
	if (!path)
		return -ENOMEM;
	spin_lock_init(&path->loss_tracker.lock);

	/* Set back-pointer to parent connection */
	refcount_set(&path->refcnt, 1);
	path->conn = conn;
	path->state = TQUIC_PATH_PENDING;
	path->path_id = 0;
	/*
	 * Probe the actual interface MTU via a route lookup.
	 * The QUIC max datagram size is the interface MTU minus
	 * IP (20 or 40) and UDP (8) header overhead.
	 * Fall back to 1200 (RFC 9000 minimum) if lookup fails.
	 */
	{
		u32 pmtu = 1200;

		if (remote->sa_family == AF_INET) {
			struct sockaddr_in *sin = (struct sockaddr_in *)remote;
			struct flowi4 fl4 = {};
			struct rtable *rt;

			fl4.daddr = sin->sin_addr.s_addr;
			fl4.flowi4_proto = IPPROTO_UDP;
			rt = ip_route_output_key(conn->sk ?
					sock_net(conn->sk) : &init_net, &fl4);
			if (!IS_ERR(rt)) {
				pmtu = dst_mtu(&rt->dst);
				ip_rt_put(rt);
				/* Subtract IP + UDP headers */
				if (pmtu > 28)
					pmtu -= 28;
			}
		}
		/* Enforce QUIC minimum of 1200 */
		if (pmtu < 1200)
			pmtu = 1200;
		path->mtu = pmtu;
	}
	path->priority = 128;  /* Default middle priority */
	path->weight = 1;

	/*
	 * Copy addresses with correct size based on address family.
	 * The path was zero-allocated, so any trailing bytes in
	 * sockaddr_storage are already zeroed.
	 */
	if (local->sa_family == AF_INET)
		memcpy(&path->local_addr, local, sizeof(struct sockaddr_in));
	else if (local->sa_family == AF_INET6)
		memcpy(&path->local_addr, local, sizeof(struct sockaddr_in6));
	else
		goto err_afnosupport;

	if (remote->sa_family == AF_INET)
		memcpy(&path->remote_addr, remote, sizeof(struct sockaddr_in));
	else if (remote->sa_family == AF_INET6)
		memcpy(&path->remote_addr, remote, sizeof(struct sockaddr_in6));
	else
		goto err_afnosupport;

	/* Initialize stats */
	memset(&path->stats, 0, sizeof(path->stats));
	path->stats.rtt_smoothed = TQUIC_DEFAULT_RTT * 1000; /* Convert to us */

	/* Generate path-specific connection ID */
	get_random_bytes(path->local_cid.id, TQUIC_DEFAULT_CID_LEN);
	path->local_cid.len = TQUIC_DEFAULT_CID_LEN;
	path->local_cid.seq_num = 0;

	/* Setup validation timers */
	timer_setup(&path->validation.timer, tquic_path_validation_timeout, 0);
	/*
	 * Legacy validation_timer is reinitialized by
	 * tquic_timer_start_path_validation() before use, but set
	 * the callback here to avoid a NULL function pointer if the
	 * timer fires unexpectedly.
	 */
	timer_setup(&path->validation_timer, tquic_path_validation_timeout, 0);

	/* Initialize validation state */
	path->validation.challenge_pending = false;
	path->validation.retries = 0;

	/* Initialize response queue */
	skb_queue_head_init(&path->response.queue);
	atomic_set(&path->response.count, 0);

	/* Legacy challenge data - still used by some code */
	get_random_bytes(path->challenge_data, sizeof(path->challenge_data));

	spin_lock_bh(&conn->paths_lock);
	if (conn->num_paths >= TQUIC_MAX_PATHS) {
		spin_unlock_bh(&conn->paths_lock);
		tquic_path_put(path);
		return -ENOSPC;
	}

	path_id = tquic_conn_alloc_path_id_locked(conn);
	if (path_id < 0) {
		spin_unlock_bh(&conn->paths_lock);
		tquic_path_put(path);
		return path_id;
	}
	path->path_id = path_id;
	path->local_cid.seq_num = path_id;

	list_add_tail_rcu(&path->list, &conn->paths);
	conn->num_paths++;

	/* First path becomes active */
	if (!rcu_access_pointer(conn->active_path))
		rcu_assign_pointer(conn->active_path, path);
	spin_unlock_bh(&conn->paths_lock);

	tquic_conn_dbg(conn, "added path %u\n", path->path_id);

	/*
	 * Start validation for additional paths only.  The initial path
	 * (path_id == 0) is validated by the TLS handshake itself
	 * (RFC 9000 Section 8.1): "A server considers a client address
	 * validated if a Handshake packet is successfully processed."
	 * Sending PATH_CHALLENGE before Application keys are available
	 * would fail anyway since it must be in a 1-RTT packet.
	 */
	if (path->path_id != 0) {
		if (tquic_path_start_validation(conn, path) < 0)
			tquic_conn_warn(conn,
					"failed to start validation for path %u\n",
					path->path_id);
	} else {
		path->state = TQUIC_PATH_ACTIVE;

		/*
		 * Initial path (path_id 0) is validated by the TLS handshake.
		 * Notify userspace that this path is now active.  conn->sk is
		 * guaranteed non-NULL for established connections; the netlink
		 * function guards against it internally.
		 */
		tquic_nl_path_event(conn, path, TQUIC_PATH_EVENT_ADD);
	}

	return path->path_id;

err_afnosupport:
	kmem_cache_free(tquic_path_cache, path);
	return -EAFNOSUPPORT;
}
EXPORT_SYMBOL_GPL(tquic_conn_add_path);

int tquic_conn_remove_path(struct tquic_connection *conn, u32 path_id)
{
	struct tquic_path *path, *tmp;
	bool found = false;

	spin_lock_bh(&conn->paths_lock);
	list_for_each_entry_safe(path, tmp, &conn->paths, list) {
		if (path->path_id == path_id) {
			/* Don't remove last path */
			if (conn->num_paths <= 1) {
				spin_unlock_bh(&conn->paths_lock);
				return -EINVAL;
			}

				list_del_rcu(&path->list);
				conn->num_paths--;

			/* Update active path if needed */
			if (rcu_access_pointer(conn->active_path) == path) {
				struct tquic_path *new_active;

				new_active =
					list_first_entry_or_null(&conn->paths,
								 struct tquic_path,
								 list);
				rcu_assign_pointer(conn->active_path, new_active);
			}

			found = true;
			break;
		}
	}
	spin_unlock_bh(&conn->paths_lock);

	if (!found)
		return -ENOENT;

	/* Stop validation timer */
	timer_delete_sync(&path->validation.timer);
	timer_delete_sync(&path->validation_timer);

	/* Flush response queue */
	skb_queue_purge(&path->response.queue);
	atomic_set(&path->response.count, 0);

	/* Wait for RCU readers before dropping list ownership reference. */
	synchronize_rcu();
	INIT_LIST_HEAD(&path->list);
	tquic_path_put(path);

	tquic_conn_dbg(conn, "removed path %u\n", path_id);

	return 0;
}
EXPORT_SYMBOL_GPL(tquic_conn_remove_path);

struct tquic_path *tquic_conn_get_path(struct tquic_connection *conn, u32 path_id)
{
	struct tquic_path *path;

	spin_lock_bh(&conn->paths_lock);
	list_for_each_entry(path, &conn->paths, list) {
		if (path->path_id == path_id) {
			if (!tquic_path_get(path))
				path = NULL;
			spin_unlock_bh(&conn->paths_lock);
			return path;
		}
	}
	spin_unlock_bh(&conn->paths_lock);

	return NULL;
}
EXPORT_SYMBOL_GPL(tquic_conn_get_path);

void tquic_conn_migrate(struct tquic_connection *conn, struct tquic_path *new_path)
{
	bool migrated = false;

	spin_lock_bh(&conn->paths_lock);
	if (new_path->state == TQUIC_PATH_ACTIVE ||
	    new_path->state == TQUIC_PATH_STANDBY) {
		rcu_assign_pointer(conn->active_path, new_path);
		migrated = true;
	}
	spin_unlock_bh(&conn->paths_lock);

	if (migrated) {
		spin_lock_bh(&conn->lock);
		conn->stats.path_migrations++;
		spin_unlock_bh(&conn->lock);
		tquic_conn_info(conn, "migrated to path %u\n", new_path->path_id);
	}
}
EXPORT_SYMBOL_GPL(tquic_conn_migrate);

/*
 * Path Manager Connection Lifecycle
 */

/**
 * tquic_pm_conn_init - Initialize path manager for connection
 * @conn: Connection to initialize PM for
 *
 * Called when connection is established. Selects PM type based on
 * sysctl configuration and initializes PM state. For kernel PM with
 * auto_discover enabled, triggers initial path discovery.
 *
 * Also adds the connection to the per-netns connection list for
 * lookup by token (used by netlink and diagnostics interfaces).
 *
 * Returns 0 on success, negative error on failure.
 */
int tquic_pm_conn_init(struct tquic_connection *conn)
{
	struct net *net;
	struct tquic_pm_pernet *pernet;
	struct tquic_pm_ops *ops;
	struct tquic_pm_state *pm_state;
	struct tquic_net *tn;

	if (!conn || !conn->sk)
		return -EINVAL;

	net = sock_net(conn->sk);

	pernet = tquic_pm_get_pernet(net);
	if (!pernet)
		return -ENOENT;

	tn = tquic_pernet(net);
	if (!tn)
		return -ENOENT;

	/* Get PM ops for current type */
	ops = tquic_pm_get_type(net);
	if (!ops) {
		tquic_warn("no PM ops registered for type %u\n",
			   pernet->pm_type);
		return -ENOENT;
	}

	/* Allocate PM state */
	pm_state = kzalloc(sizeof(*pm_state), GFP_KERNEL);
	if (!pm_state)
		return -ENOMEM;

	pm_state->ops = ops;
	pm_state->priv = NULL;

	conn->pm = pm_state;

	/* Generate unique connection token for netlink identification */
	conn->token = get_random_u32();

	/*
	 * Initialize pm_node list head and add to per-netns connection list.
	 * This enables lookup by token via tquic_conn_lookup_by_token().
	 * List access is serialized by tn->conn_lock.
	 */
	INIT_LIST_HEAD(&conn->pm_node);
	spin_lock_bh(&tn->conn_lock);
	list_add_tail(&conn->pm_node, &tn->connections);
	atomic_inc(&tn->conn_count);
	spin_unlock_bh(&tn->conn_lock);

	/*
	 * Note: PM-type per-namespace init (ops->init) is called once per
	 * namespace in tquic_pm_net_init(), not per connection. Calling it
	 * here caused duplicate notifier registration failures in non-init
	 * namespaces (the "known issue" from Round 11).
	 */

	/* For kernel PM with auto_discover, trigger initial discovery
	 * This discovers paths for already-up interfaces with default routes
	 */
	if (pernet->pm_type == TQUIC_PM_TYPE_KERNEL &&
	    pernet->auto_discover) {
		/* Initial discovery happens via netdevice notifier
		 * when interfaces are already up. The notifier was
		 * registered in tquic_pm_kernel_init().
		 */
		tquic_dbg("kernel PM initialized with auto_discover\n");
	}

	/*
	 * Populate the netlink shadow DB so that userspace GET commands
	 * (TQUIC_NL_CMD_CONN_GET, TQUIC_NL_CMD_PATH_LIST) can find this
	 * connection immediately after establishment.  conn->token was
	 * assigned above; use it as the 64-bit conn_id throughout the
	 * netlink layer.  Failure is non-fatal: only GET queries are
	 * affected; multicast events still flow via tquic_nl_path_event().
	 */
	if (tquic_nl_conn_register(net, (u64)conn->token) < 0)
		tquic_warn("netlink shadow DB registration failed for conn %u\n",
			   conn->token);

	return 0;
}
EXPORT_SYMBOL_GPL(tquic_pm_conn_init);

/**
 * tquic_pm_conn_release - Clean up path manager state for connection
 * @conn: Connection to release PM for
 *
 * Called when connection is being closed. Releases PM-specific state
 * and removes the connection from the per-netns connection list.
 */
void tquic_pm_conn_release(struct tquic_connection *conn)
{
	struct tquic_pm_state *pm_state;
	struct net *net;
	struct tquic_net *tn;

	tquic_dbg("tquic_pm_conn_release: conn=%p\n", conn);

	if (!conn || !conn->pm)
		return;

	pm_state = conn->pm;

	/*
	 * PM type .release() is a per-netns lifecycle callback.
	 * It is invoked from PM per-netns exit/type switch paths,
	 * not during per-connection teardown.
	 */

	/*
	 * Remove from per-netns connection list.
	 * This must be done before freeing the pm_state to ensure
	 * concurrent lookups via tquic_conn_lookup_by_token() are safe.
	 */
	if (conn->sk) {
		net = sock_net(conn->sk);
		tn = tquic_pernet(net);
		if (tn) {
			spin_lock_bh(&tn->conn_lock);
			if (!list_empty(&conn->pm_node)) {
				list_del_init(&conn->pm_node);
				atomic_dec(&tn->conn_count);
			}
			spin_unlock_bh(&tn->conn_lock);

			/*
			 * Ensure RCU grace period before connection can be freed.
			 * The caller (tquic_conn_destroy) should handle this.
			 */
		}
	}

	/* Free PM-specific private data if any */
	kfree(pm_state->priv);

	kfree(pm_state);
	conn->pm = NULL;
}
EXPORT_SYMBOL_GPL(tquic_pm_conn_release);

/*
 * Stream Management
 */

struct tquic_stream *tquic_stream_open(struct tquic_connection *conn, bool bidi)
{
	struct tquic_stream *stream;
	struct rb_node **link, *parent = NULL;
	u64 stream_id;

	stream = kmem_cache_zalloc(tquic_stream_cache, GFP_KERNEL);
	if (!stream)
		return NULL;

	RB_CLEAR_NODE(&stream->node);

	/* Allocate stream ID, enforcing MAX_STREAMS per RFC 9000 Section 4.6 */
	spin_lock_bh(&conn->lock);
	if (bidi) {
		if (conn->next_stream_id_bidi / 4 >= conn->max_streams_bidi) {
			spin_unlock_bh(&conn->lock);
			kmem_cache_free(tquic_stream_cache, stream);
			return NULL;
		}
		stream_id = conn->next_stream_id_bidi;
		conn->next_stream_id_bidi += 4;
	} else {
		if (conn->next_stream_id_uni / 4 >= conn->max_streams_uni) {
			spin_unlock_bh(&conn->lock);
			kmem_cache_free(tquic_stream_cache, stream);
			return NULL;
		}
		stream_id = conn->next_stream_id_uni;
		conn->next_stream_id_uni += 4;
	}
	spin_unlock_bh(&conn->lock);

	stream->id = stream_id;
	stream->state = TQUIC_STREAM_OPEN;
	stream->conn = conn;
	refcount_set(&stream->refcount, 1);

	skb_queue_head_init(&stream->send_buf);
	skb_queue_head_init(&stream->recv_buf);

	stream->max_send_data = TQUIC_DEFAULT_MAX_STREAM_DATA;
	stream->max_recv_data = TQUIC_DEFAULT_MAX_STREAM_DATA;

	init_waitqueue_head(&stream->wait);

	/* Insert into connection's stream tree */
	spin_lock_bh(&conn->lock);
	link = &conn->streams.rb_node;
	while (*link) {
		struct tquic_stream *entry;

		parent = *link;
		entry = rb_entry(parent, struct tquic_stream, node);

		if (stream->id < entry->id)
			link = &parent->rb_left;
		else
			link = &parent->rb_right;
	}
	rb_link_node(&stream->node, parent, link);
	rb_insert_color(&stream->node, &conn->streams);
	conn->stats.streams_opened++;
	spin_unlock_bh(&conn->lock);

	return stream;
}
EXPORT_SYMBOL_GPL(tquic_stream_open);

/**
 * tquic_stream_open_incoming - Create a stream for a remotely-initiated stream ID
 * @conn: QUIC connection
 * @stream_id: Stream ID received from the peer
 *
 * Validates the stream ID against the local MAX_STREAMS limit advertised
 * to the peer.  If the peer exceeds the limit this is a protocol violation
 * (STREAM_LIMIT_ERROR, RFC 9000 Section 4.6).
 *
 * Returns: new stream on success, NULL if limit exceeded or OOM.
 */
/*
 * H-001: Lock-free stream creation helper.
 * Caller must hold conn->lock during the entire lookup-and-create
 * sequence to prevent races.
 */
static struct tquic_stream *
tquic_stream_create_locked(struct tquic_connection *conn, u64 stream_id)
{
	struct tquic_stream *stream;
	struct rb_node **link, *parent = NULL;
	bool bidi = (stream_id & 0x02) == 0;
	u64 stream_seq = stream_id >> 2;
	u64 max_streams;

	/*
	 * Validate against our local MAX_STREAMS limit (RFC 9000 Section 4.6).
	 * This function is only called for peer-initiated (incoming) streams,
	 * so the limit is what WE advertised to the peer in our transport
	 * parameters, not what the peer advertised to us.
	 * Caller already holds conn->lock — read directly.
	 */
	max_streams = bidi ? conn->local_params.initial_max_streams_bidi
			   : conn->local_params.initial_max_streams_uni;

	if (stream_seq >= max_streams)
		return NULL;

	stream = kmem_cache_zalloc(tquic_stream_cache, GFP_ATOMIC);
	if (!stream)
		return NULL;

	RB_CLEAR_NODE(&stream->node);

	stream->id = stream_id;
	stream->state = TQUIC_STREAM_OPEN;
	stream->conn = conn;
	refcount_set(&stream->refcount, 1);

	skb_queue_head_init(&stream->send_buf);
	skb_queue_head_init(&stream->recv_buf);

	stream->max_send_data = TQUIC_DEFAULT_MAX_STREAM_DATA;
	stream->max_recv_data = TQUIC_DEFAULT_MAX_STREAM_DATA;

	init_waitqueue_head(&stream->wait);

	/*
	 * Insert into connection's stream tree. Caller holds conn->lock.
	 * Double-check for races: another thread might have created the
	 * stream between our lookup and this insertion.
	 */
	link = &conn->streams.rb_node;
	while (*link) {
		struct tquic_stream *entry;

		parent = *link;
		entry = rb_entry(parent, struct tquic_stream, node);

		if (stream->id < entry->id) {
			link = &parent->rb_left;
		} else if (stream->id > entry->id) {
			link = &parent->rb_right;
		} else {
			/* Stream already exists - race with another packet. */
			kmem_cache_free(tquic_stream_cache, stream);
			return entry;
		}
	}
	rb_link_node(&stream->node, parent, link);
	rb_insert_color(&stream->node, &conn->streams);

	/* Caller already holds conn->lock — update stats directly. */
	conn->stats.streams_opened++;

	return stream;
}

struct tquic_stream *tquic_stream_open_incoming(struct tquic_connection *conn,
						u64 stream_id)
{
	struct tquic_stream *stream;

	spin_lock_bh(&conn->lock);
	stream = tquic_stream_create_locked(conn, stream_id);
	/*
	 * Caller gets a transient reference; tree ownership remains as the
	 * base reference.
	 */
	if (stream && !tquic_stream_get(stream))
		stream = NULL;
	spin_unlock_bh(&conn->lock);

	return stream;
}
EXPORT_SYMBOL_GPL(tquic_stream_open_incoming);

void tquic_stream_close(struct tquic_stream *stream)
{
	struct tquic_connection *conn;
	bool removed = false;

	tquic_dbg("tquic_stream_close: stream=%p id=%llu\n",
		  stream, stream ? stream->id : 0);

	if (!stream)
		return;

	conn = READ_ONCE(stream->conn);
	if (!conn)
		return;

	/* Stream tree modifications are protected by conn->lock (protocol.h). */
	spin_lock_bh(&conn->lock);
	if (!RB_EMPTY_NODE(&stream->node)) {
		rb_erase(&stream->node, &conn->streams);
		RB_CLEAR_NODE(&stream->node);
		removed = true;
	}
	spin_unlock_bh(&conn->lock);

	if (removed) {
		spin_lock_bh(&conn->lock);
		conn->stats.streams_closed++;
		spin_unlock_bh(&conn->lock);
	}

	/*
	 * Drop tree ownership reference. Any in-flight users that acquired
	 * their own refs can complete safely before final free.
	 */
	if (removed)
		tquic_stream_put(stream);
}
EXPORT_SYMBOL_GPL(tquic_stream_close);

/*
 * Scheduler Registration
 *
 * tquic_register_scheduler() and tquic_unregister_scheduler() are defined
 * in multipath/tquic_scheduler.c which provides the complete scheduler
 * registration framework with validation and per-netns support.
 */

/*
 * Congestion Control Registration
 * NOTE: tquic_register_cong and tquic_unregister_cong are defined in
 * cong/tquic_cong.c to avoid duplicate symbol definitions.
 */

/*
 * Proc Filesystem Interface
 *
 * The proc interface is implemented in tquic_proc.c and initialized
 * per-netns via pernet_operations in tquic_proto.c.
 */

/*
 * External subsystem initialization function declarations are now in tquic_init.h
 */

/*
 * Module Initialization
 */

int __ref tquic_init(void)
{
	int err;

	pr_info("tquic: written by Justin Adams\n");
	tquic_info("initializing TQUIC WAN bonding subsystem\n");

	/* Create slab caches */
	tquic_conn_cache = kmem_cache_create("tquic_connection",
					     sizeof(struct tquic_connection),
					     0, SLAB_HWCACHE_ALIGN, NULL);
	if (!tquic_conn_cache) {
		err = -ENOMEM;
		goto err_conn_cache;
	}

	tquic_stream_cache = kmem_cache_create("tquic_stream",
					       sizeof(struct tquic_stream),
					       0, SLAB_HWCACHE_ALIGN, NULL);
	if (!tquic_stream_cache) {
		err = -ENOMEM;
		goto err_stream_cache;
	}

	/* tquic_path_cache created by tquic_path_init_module() */

	tquic_rx_buf_cache = kmem_cache_create("tquic_rx_buf",
					       TQUIC_RX_BUF_SIZE,
					       0, SLAB_HWCACHE_ALIGN, NULL);
	if (!tquic_rx_buf_cache) {
		err = -ENOMEM;
		goto err_rx_buf_cache;
	}

	/* Create TX pending frame slab cache */
	err = tquic_output_tx_init();
	if (err)
		goto err_frame_cache;

	/* Initialize connection hashtable */
	err = rhashtable_init(&tquic_conn_table, &tquic_conn_params);
	if (err)
		goto err_hashtable;

	/* Initialize CID cache/hash used by the connection-creation path */
	err = tquic_cid_hash_init();
	if (err)
		goto err_cid_hash;

	/* Initialize global CID table */
	err = tquic_cid_table_init();
	if (err)
		goto err_cid_table;

	/* Initialize connection state machine (CID lookup table, retry AEAD) */
	err = tquic_connection_init();
	if (err)
		goto err_connection;

	/* Initialize timer subsystem */
	err = tquic_timer_init();
	if (err)
		goto err_timer;

	/* Initialize loss detection slab cache */
	err = tquic_loss_cache_init();
	if (err)
		goto err_loss_cache;

	/* Initialize UDP tunnel subsystem */
	err = tquic_udp_init();
	if (err)
		goto err_udp;

	/* Initialize address validation token subsystem */
	err = tquic_token_init();
	if (err)
		goto err_token;

	/* Initialize stateless reset subsystem */
	err = tquic_stateless_reset_init();
	if (err)
		goto err_stateless_reset;

	/* Initialize Retry subsystem */
	err = tquic_retry_init();
	if (err)
		goto err_retry;

	/* Initialize preferred address support */
	err = tquic_pref_addr_init();
	if (err)
		goto err_pref_addr;

	/* Initialize GREASE support */
	err = tquic_grease_init();
	if (err)
		goto err_grease;

	/* Initialize PMTUD subsystem */
	err = tquic_pmtud_init();
	if (err)
		goto err_pmtud;

	/* Initialize QoS subsystem */
	err = tquic_qos_init();
	if (err)
		goto err_qos;

	/* Initialize tunnel subsystem */
	err = tquic_tunnel_init();
	if (err)
		goto err_tunnel;

	/* Initialize forwarding subsystem */
	err = tquic_forward_init();
	if (err)
		goto err_forward;

	/* Initialize security hardening */
	err = tquic_security_hardening_init();
	if (err)
		goto err_security;

	/* Initialize ACK frequency extension */
	err = tquic_ack_freq_module_init();
	if (err)
		goto err_ack_freq;

	/* Initialize persistent congestion tracking */
	err = tquic_persistent_cong_module_init();
	if (err)
		goto err_persistent_cong;

	/* Initialize crypto subsystem */
	err = tquic_cert_verify_init();
	if (err)
		goto err_cert_verify;

	err = tquic_zero_rtt_module_init();
	if (err)
		goto err_zero_rtt;

	err = tquic_hw_offload_init();
	if (err)
		goto err_hw_offload;

	/* Initialize congestion control data tracking */
	err = tquic_cong_data_module_init();
	if (err)
		goto err_cong_data;

	/* Initialize congestion control algorithms */
	err = tquic_bbrv2_init();
	if (err)
		goto err_bbrv2;

	err = tquic_bbrv3_init();
	if (err)
		goto err_bbrv3;

	err = tquic_prague_init();
	if (err)
		goto err_prague;

	/* Initialize multipath extensions */
	err = tquic_mp_ack_init();
	if (err)
		goto err_mp_ack;

	err = tquic_mp_frame_init();
	if (err)
		goto err_mp_frame;

	err = tquic_mp_abandon_init();
	if (err)
		goto err_mp_abandon;

	err = tquic_mp_deadline_init();
	if (err)
		goto err_mp_deadline;

	/* Initialize scheduler framework (must be before individual schedulers) */
	err = tquic_scheduler_init();
	if (err)
		goto err_scheduler;

#ifdef TQUIC_OUT_OF_TREE
	/* Register built-in old-style schedulers for the sched/ framework */
	err = tquic_sched_framework_init();
	if (err)
		goto err_sched_framework;
#endif

	/* Initialize individual schedulers */
	err = tquic_sched_minrtt_init();
	if (err)
		goto err_sched_minrtt;

	err = tquic_sched_aggregate_init();
	if (err)
		goto err_sched_aggregate;

	err = tquic_sched_weighted_init();
	if (err)
		goto err_sched_weighted;

	err = tquic_sched_blest_init();
	if (err)
		goto err_sched_blest;

	err = tquic_sched_ecf_init();
	if (err)
		goto err_sched_ecf;

	/* Initialize bonding subsystem */
	err = tquic_bonding_init_module();
	if (err)
		goto err_bonding;

	err = tquic_path_init_module();
	if (err)
		goto err_path_mgmt;

	err = coupled_cc_init_module();
	if (err)
		goto err_coupled_cc;

	/* Initialize path managers */
	err = tquic_pm_types_init();
	if (err)
		goto err_pm_types;

	err = tquic_pm_nl_init();
	if (err)
		goto err_pm_nl;

	err = tquic_pm_userspace_init();
	if (err)
		goto err_pm_userspace;

	err = tquic_pm_kernel_module_init();
	if (err)
		goto err_pm_kernel;

	err = tquic_nat_keepalive_module_init();
	if (err)
		goto err_nat_keepalive;

	err = tquic_nat_lifecycle_module_init();
	if (err)
		goto err_nat_lifecycle;

	/* Initialize server subsystem */
	err = tquic_server_init();
	if (err)
		goto err_server;

#if IS_ENABLED(CONFIG_TQUIC_NAPI)
	/* Initialize NAPI subsystem */
	err = tquic_napi_subsys_init();
	if (err)
		goto err_napi;
#endif

#if IS_ENABLED(CONFIG_TQUIC_IO_URING)
	/* Initialize io_uring subsystem */
	err = tquic_io_uring_init();
	if (err)
		goto err_io_uring;
#endif

	/* Initialize netlink interface (uses tquic_nl_init) */
	err = tquic_nl_init();
	if (err)
		goto err_netlink;

	/* Initialize sysctl interface */
	err = tquic_sysctl_init(&init_net);
	if (err)
		goto err_sysctl;

	/* Register protocol handlers */
	err = tquic_proto_init();
	if (err)
		goto err_proto;

	/* Proc interface is initialized per-netns via pernet_operations */

	/* Initialize inet_diag handler for ss tool */
	err = tquic_diag_init();
	if (err)
		goto err_diag;

	/* Initialize GRO/GSO offload support */
	err = tquic_offload_init();
	if (err)
		goto err_offload;

	/* Initialize rate limiting for DDoS protection */
	err = tquic_rate_limit_module_init();
	if (err)
		goto err_rate_limit;

	/* Initialize advanced rate limiting with cookies */
	err = tquic_ratelimit_module_init();
	if (err)
		goto err_ratelimit;

	/* Initialize debug infrastructure (debugfs) */
	err = tquic_debug_init();
	if (err)
		goto err_debug;

	tquic_info("TQUIC WAN bonding subsystem initialized\n");
	tquic_info("default bond mode: %d, scheduler: %s, congestion: %s\n",
		   tquic_default_bond_mode, tquic_default_scheduler, tquic_default_cong);

	return 0;

err_debug:
	tquic_ratelimit_module_exit();
err_ratelimit:
	tquic_rate_limit_module_exit();
err_rate_limit:
	tquic_offload_exit();
err_offload:
	tquic_diag_exit();
err_diag:
	tquic_proto_exit();
err_proto:
	tquic_sysctl_exit();
err_sysctl:
	tquic_nl_exit();
err_netlink:
#if IS_ENABLED(CONFIG_TQUIC_IO_URING)
	tquic_io_uring_exit();
err_io_uring:
#endif
#if IS_ENABLED(CONFIG_TQUIC_NAPI)
	tquic_napi_subsys_exit();
err_napi:
#endif
	tquic_server_exit();
err_server:
	tquic_nat_lifecycle_module_exit();
err_nat_lifecycle:
	tquic_nat_keepalive_module_exit();
err_nat_keepalive:
	tquic_pm_kernel_module_exit();
err_pm_kernel:
	tquic_pm_userspace_exit();
err_pm_userspace:
	tquic_pm_nl_exit();
err_pm_nl:
	tquic_pm_types_exit();
err_pm_types:
	coupled_cc_exit_module();
err_coupled_cc:
	tquic_path_exit_module();
err_path_mgmt:
	tquic_bonding_exit_module();
err_bonding:
	tquic_sched_ecf_exit();
err_sched_ecf:
	tquic_sched_blest_exit();
err_sched_blest:
	tquic_sched_weighted_exit();
err_sched_weighted:
	tquic_sched_aggregate_exit();
err_sched_aggregate:
	tquic_sched_minrtt_exit();
err_sched_minrtt:
#ifdef TQUIC_OUT_OF_TREE
	tquic_sched_framework_exit();
#endif
err_sched_framework:
	tquic_scheduler_exit();
err_scheduler:
	tquic_mp_deadline_exit();
err_mp_deadline:
	tquic_mp_abandon_exit();
err_mp_abandon:
	tquic_mp_frame_exit();
err_mp_frame:
	tquic_mp_ack_exit();
err_mp_ack:
	tquic_prague_exit();
err_prague:
	tquic_bbrv3_exit();
err_bbrv3:
	tquic_bbrv2_exit();
err_bbrv2:
	tquic_cong_data_module_exit();
err_cong_data:
	tquic_hw_offload_exit();
err_hw_offload:
	tquic_zero_rtt_module_exit();
err_zero_rtt:
	tquic_cert_verify_exit();
err_cert_verify:
	tquic_persistent_cong_module_exit();
err_persistent_cong:
	tquic_ack_freq_module_exit();
err_ack_freq:
	tquic_security_hardening_exit();
err_security:
	tquic_forward_exit();
err_forward:
	tquic_tunnel_exit();
err_tunnel:
	tquic_qos_exit();
err_qos:
	tquic_pmtud_exit();
err_pmtud:
	tquic_grease_exit();
err_grease:
	tquic_pref_addr_exit();
err_pref_addr:
	tquic_retry_exit();
err_retry:
	tquic_stateless_reset_exit();
err_stateless_reset:
	tquic_token_exit();
err_token:
	tquic_udp_exit();
err_udp:
	tquic_loss_cache_destroy();
err_loss_cache:
	tquic_timer_exit();
err_timer:
	tquic_connection_exit();
err_connection:
	tquic_cid_table_exit();
err_cid_table:
	tquic_cid_hash_cleanup();
err_cid_hash:
	rhashtable_destroy(&tquic_conn_table);
err_hashtable:
	tquic_output_tx_exit();
err_frame_cache:
	kmem_cache_destroy(tquic_rx_buf_cache);
err_rx_buf_cache:
	/* tquic_path_cache destroyed by tquic_path_exit_module() */
	kmem_cache_destroy(tquic_stream_cache);
err_stream_cache:
	kmem_cache_destroy(tquic_conn_cache);
err_conn_cache:
	return err;
}

void __exit tquic_exit(void)
{
	tquic_info("shutting down TQUIC WAN bonding subsystem\n");

	/* Cleanup in reverse order of initialization */
	tquic_debug_exit();
	tquic_ratelimit_module_exit();
	tquic_rate_limit_module_exit();
	tquic_offload_exit();
	tquic_diag_exit();
	tquic_proto_exit();
	/* Proc interface is cleaned up per-netns via pernet_operations */
	tquic_sysctl_exit();
	tquic_nl_exit();
#if IS_ENABLED(CONFIG_TQUIC_IO_URING)
	tquic_io_uring_exit();
#endif
#if IS_ENABLED(CONFIG_TQUIC_NAPI)
	tquic_napi_subsys_exit();
#endif
	tquic_server_exit();

	/* Cleanup path managers */
	tquic_nat_lifecycle_module_exit();
	tquic_nat_keepalive_module_exit();
	tquic_pm_kernel_module_exit();
	tquic_pm_userspace_exit();
	tquic_pm_nl_exit();
	tquic_pm_types_exit();

	/* Cleanup bonding subsystem */
	coupled_cc_exit_module();
	tquic_path_exit_module();
	tquic_bonding_exit_module();

	/* Cleanup schedulers (reverse order) */
	tquic_sched_ecf_exit();
	tquic_sched_blest_exit();
	tquic_sched_weighted_exit();
	tquic_sched_aggregate_exit();
	tquic_sched_minrtt_exit();
#ifdef TQUIC_OUT_OF_TREE
	tquic_sched_framework_exit();
#endif
	tquic_scheduler_exit();

	/* Cleanup multipath extensions */
	tquic_mp_deadline_exit();
	tquic_mp_abandon_exit();
	tquic_mp_frame_exit();
	tquic_mp_ack_exit();

	/* Cleanup congestion control */
	tquic_prague_exit();
	tquic_bbrv3_exit();
	tquic_bbrv2_exit();
	tquic_cong_data_module_exit();

	/* Cleanup crypto subsystem */
	tquic_hw_offload_exit();
	tquic_zero_rtt_module_exit();
	tquic_cert_verify_exit();

	/* Cleanup core subsystems */
	tquic_persistent_cong_module_exit();
	tquic_ack_freq_module_exit();
	tquic_security_hardening_exit();
	tquic_forward_exit();
	tquic_tunnel_exit();
	tquic_qos_exit();
	tquic_pmtud_exit();
	tquic_grease_exit();
	tquic_pref_addr_exit();
	tquic_retry_exit();
	tquic_stateless_reset_exit();
	tquic_token_exit();
	tquic_udp_exit();
	tquic_loss_cache_destroy();
	tquic_timer_exit();
	tquic_connection_exit();
	tquic_cid_table_exit();
	tquic_cid_hash_cleanup();

	/* Cleanup global data structures */
	rhashtable_destroy(&tquic_conn_table);
	tquic_output_tx_exit();
	kmem_cache_destroy(tquic_rx_buf_cache);
	/* tquic_path_cache destroyed by tquic_path_exit_module() at line 1297 */
	kmem_cache_destroy(tquic_stream_cache);
	kmem_cache_destroy(tquic_conn_cache);

	tquic_info("TQUIC WAN bonding subsystem unloaded\n");
}

module_init(tquic_init);
module_exit(tquic_exit);
