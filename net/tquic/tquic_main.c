// SPDX-License-Identifier: GPL-2.0-only
/*
 * TQUIC: WAN Bonding over QUIC - Main Module
 *
 * Copyright (c) 2026 Linux Foundation
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
#include <net/sock.h>
#include <net/protocol.h>
#include <net/inet_common.h>
#include <net/udp.h>
#include <net/udp_tunnel.h>
#include <net/tquic.h>
#include <net/tquic_pm.h>
#include "protocol.h"
#include "grease.h"
#include "io_uring.h"
#include "napi.h"
#include "tquic_ack_frequency.h"
#include "tquic_preferred_addr.h"
#include "tquic_ratelimit.h"
#include "tquic_retry.h"
#include "tquic_stateless_reset.h"
#include "tquic_token.h"

/* Module info */
MODULE_AUTHOR("Linux Foundation");
MODULE_DESCRIPTION("TQUIC: WAN Bonding over QUIC");
MODULE_LICENSE("GPL");
MODULE_VERSION("1.0.0");

/* Global state */
struct rhashtable tquic_conn_table;
EXPORT_SYMBOL_GPL(tquic_conn_table);
static DEFINE_SPINLOCK(tquic_lock);
static struct kmem_cache *tquic_conn_cache;
static struct kmem_cache *tquic_stream_cache;
static struct kmem_cache *tquic_path_cache;
static struct proc_dir_entry *tquic_proc_dir;

/* Connection hashtable params */
static const struct rhashtable_params tquic_conn_params = {
	.key_len = sizeof(struct tquic_cid),
	.key_offset = offsetof(struct tquic_connection, scid),
	.head_offset = offsetof(struct tquic_connection, node),
	.automatic_shrinking = true,
};

/* Registered schedulers */
static LIST_HEAD(tquic_schedulers);
static DEFINE_RWLOCK(tquic_sched_lock);

/* Registered congestion controllers */
static LIST_HEAD(tquic_cong_list);
static DEFINE_RWLOCK(tquic_cong_lock);

/* Default scheduler name */
static char tquic_default_scheduler[TQUIC_MAX_SCHED_NAME] = "minrtt";
module_param_string(scheduler, tquic_default_scheduler,
		    sizeof(tquic_default_scheduler), 0644);
MODULE_PARM_DESC(scheduler, "Default packet scheduler for WAN bonding");

/* Default congestion control */
static char tquic_default_cong[TQUIC_MAX_CONG_NAME] = "cubic";
module_param_string(congestion, tquic_default_cong,
		    sizeof(tquic_default_cong), 0644);
MODULE_PARM_DESC(congestion, "Default congestion control algorithm");

/* Default bonding mode */
static int tquic_default_bond_mode = TQUIC_BOND_MODE_AGGREGATE;
module_param_named(bond_mode, tquic_default_bond_mode, int, 0644);
MODULE_PARM_DESC(bond_mode, "Default WAN bonding mode");

/*
 * Connection Management
 */

struct tquic_connection *tquic_conn_create(struct sock *sk, gfp_t gfp)
{
	struct tquic_connection *conn;

	conn = kmem_cache_zalloc(tquic_conn_cache, gfp);
	if (!conn)
		return NULL;

	conn->state = TQUIC_CONN_IDLE;
	conn->version = TQUIC_VERSION_CURRENT;
	conn->sk = sk;

	INIT_LIST_HEAD(&conn->paths);
	conn->streams = RB_ROOT;

	spin_lock_init(&conn->lock);
	refcount_set(&conn->refcnt, 1);

	/* Initialize flow control defaults */
	conn->max_data_local = TQUIC_DEFAULT_MAX_DATA;
	conn->max_data_remote = TQUIC_DEFAULT_MAX_DATA;
	conn->max_streams_bidi = TQUIC_MAX_STREAM_COUNT_BIDI;
	conn->max_streams_uni = TQUIC_MAX_STREAM_COUNT_UNI;

	/* Set default idle timeout */
	conn->idle_timeout = TQUIC_DEFAULT_IDLE_TIMEOUT;

	/* Initialize timer state (manages idle, ack, loss, and PTO timers) */
	conn->timer_state = tquic_timer_state_alloc(conn);
	if (!conn->timer_state) {
		kmem_cache_free(tquic_conn_cache, conn);
		return NULL;
	}

	/* Generate local connection ID */
	get_random_bytes(conn->scid.id, TQUIC_DEFAULT_CID_LEN);
	conn->scid.len = TQUIC_DEFAULT_CID_LEN;
	conn->scid.seq_num = 0;

	/* Initialize state machine pointer (allocated on demand) */
	conn->state_machine = NULL;

	/* Add to global table */
	rhashtable_insert_fast(&tquic_conn_table, &conn->node, tquic_conn_params);

	return conn;
}
EXPORT_SYMBOL_GPL(tquic_conn_create);

void tquic_conn_destroy(struct tquic_connection *conn)
{
	struct tquic_path *path, *tmp_path;
	struct rb_node *node;

	if (!conn)
		return;

	/* Clean up state machine first */
	if (conn->state_machine)
		tquic_conn_state_cleanup(conn);

	/* Remove from global table */
	rhashtable_remove_fast(&tquic_conn_table, &conn->node, tquic_conn_params);

	/* Free timer state (cancels all timers) */
	if (conn->timer_state)
		tquic_timer_state_free(conn->timer_state);

	/* Free all paths */
	list_for_each_entry_safe(path, tmp_path, &conn->paths, list) {
		list_del(&path->list);
		del_timer_sync(&path->validation_timer);
		kmem_cache_free(tquic_path_cache, path);
	}

	/* Free all streams with proper memory accounting */
	while ((node = rb_first(&conn->streams))) {
		struct tquic_stream *stream = rb_entry(node, struct tquic_stream, node);
		struct sk_buff *skb;

		rb_erase(node, &conn->streams);

		/* Uncharge memory when purging buffers */
		while ((skb = skb_dequeue(&stream->send_buf)) != NULL) {
			if (conn->sk) {
				sk_mem_uncharge(conn->sk, skb->truesize);
				atomic_sub(skb->truesize, &conn->sk->sk_wmem_alloc);
			}
			kfree_skb(skb);
		}
		while ((skb = skb_dequeue(&stream->recv_buf)) != NULL) {
			if (conn->sk) {
				sk_mem_uncharge(conn->sk, skb->truesize);
				atomic_sub(skb->truesize, &conn->sk->sk_rmem_alloc);
			}
			kfree_skb(skb);
		}
		kmem_cache_free(tquic_stream_cache, stream);
	}

	/* Free crypto state if allocated */
	kfree(conn->crypto_state);

	/* Free scheduler state if allocated */
	kfree(conn->scheduler);

	kmem_cache_free(tquic_conn_cache, conn);
}
EXPORT_SYMBOL_GPL(tquic_conn_destroy);

/*
 * Path Management for WAN Bonding
 */

int tquic_conn_add_path(struct tquic_connection *conn,
			struct sockaddr *local, struct sockaddr *remote)
{
	struct tquic_path *path;

	if (conn->num_paths >= TQUIC_MAX_PATHS)
		return -ENOSPC;

	path = kmem_cache_zalloc(tquic_path_cache, GFP_KERNEL);
	if (!path)
		return -ENOMEM;

	/* Set back-pointer to parent connection */
	path->conn = conn;
	path->state = TQUIC_PATH_PENDING;
	path->path_id = conn->num_paths;
	path->mtu = 1200;  /* Initial conservative MTU */
	path->priority = 128;  /* Default middle priority */
	path->weight = 1;

	memcpy(&path->local_addr, local, sizeof(struct sockaddr_storage));
	memcpy(&path->remote_addr, remote, sizeof(struct sockaddr_storage));

	/* Initialize stats */
	memset(&path->stats, 0, sizeof(path->stats));
	path->stats.rtt_smoothed = TQUIC_DEFAULT_RTT * 1000; /* Convert to us */

	/* Generate path-specific connection ID */
	get_random_bytes(path->local_cid.id, TQUIC_DEFAULT_CID_LEN);
	path->local_cid.len = TQUIC_DEFAULT_CID_LEN;
	path->local_cid.seq_num = conn->num_paths;

	/* Setup validation timer (use new validation.timer) */
	timer_setup(&path->validation.timer, tquic_path_validation_timeout, 0);
	timer_setup(&path->validation_timer, NULL, 0); /* Keep legacy for compatibility */

	/* Initialize validation state */
	path->validation.challenge_pending = false;
	path->validation.retries = 0;

	/* Initialize response queue */
	skb_queue_head_init(&path->response.queue);
	atomic_set(&path->response.count, 0);

	/* Legacy challenge data - still used by some code */
	get_random_bytes(path->challenge_data, sizeof(path->challenge_data));

	spin_lock(&conn->lock);
	list_add_tail(&path->list, &conn->paths);
	conn->num_paths++;

	/* First path becomes active */
	if (!conn->active_path)
		conn->active_path = path;
	spin_unlock(&conn->lock);

	pr_debug("tquic: added path %u to connection\n", path->path_id);

	/* Start validation immediately for non-backup paths */
	if (tquic_path_start_validation(conn, path) < 0)
		pr_warn("tquic: failed to start validation for path %u\n",
			path->path_id);

	return path->path_id;
}
EXPORT_SYMBOL_GPL(tquic_conn_add_path);

int tquic_conn_remove_path(struct tquic_connection *conn, u32 path_id)
{
	struct tquic_path *path, *tmp;
	bool found = false;

	spin_lock(&conn->lock);
	list_for_each_entry_safe(path, tmp, &conn->paths, list) {
		if (path->path_id == path_id) {
			/* Don't remove last path */
			if (conn->num_paths <= 1) {
				spin_unlock(&conn->lock);
				return -EINVAL;
			}

			list_del(&path->list);
			conn->num_paths--;

			/* Update active path if needed */
			if (conn->active_path == path) {
				conn->active_path = list_first_entry_or_null(
					&conn->paths, struct tquic_path, list);
			}

			found = true;
			break;
		}
	}
	spin_unlock(&conn->lock);

	if (!found)
		return -ENOENT;

	/* Stop validation timer */
	del_timer_sync(&path->validation.timer);
	del_timer_sync(&path->validation_timer);

	/* Flush response queue */
	skb_queue_purge(&path->response.queue);
	atomic_set(&path->response.count, 0);

	kmem_cache_free(tquic_path_cache, path);

	pr_debug("tquic: removed path %u from connection\n", path_id);

	return 0;
}
EXPORT_SYMBOL_GPL(tquic_conn_remove_path);

struct tquic_path *tquic_conn_get_path(struct tquic_connection *conn, u32 path_id)
{
	struct tquic_path *path;

	rcu_read_lock();
	list_for_each_entry_rcu(path, &conn->paths, list) {
		if (path->path_id == path_id) {
			rcu_read_unlock();
			return path;
		}
	}
	rcu_read_unlock();

	return NULL;
}
EXPORT_SYMBOL_GPL(tquic_conn_get_path);

void tquic_conn_migrate(struct tquic_connection *conn, struct tquic_path *new_path)
{
	spin_lock(&conn->lock);
	if (new_path->state == TQUIC_PATH_ACTIVE ||
	    new_path->state == TQUIC_PATH_STANDBY) {
		conn->active_path = new_path;
		conn->stats.path_migrations++;
		pr_debug("tquic: migrated to path %u\n", new_path->path_id);
	}
	spin_unlock(&conn->lock);
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
	struct net *net = sock_net(conn->sk);
	struct tquic_pm_pernet *pernet;
	struct tquic_pm_ops *ops;
	struct tquic_pm_state *pm_state;
	struct tquic_net *tn;
	int ret;

	if (!conn || !conn->sk)
		return -EINVAL;

	pernet = tquic_pm_get_pernet(net);
	if (!pernet)
		return -ENOENT;

	tn = tquic_pernet(net);
	if (!tn)
		return -ENOENT;

	/* Get PM ops for current type */
	ops = tquic_pm_get_type(net);
	if (!ops) {
		pr_warn("TQUIC: No PM ops registered for type %u\n",
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
	 * Use RCU-safe list operations for concurrent read access.
	 */
	INIT_LIST_HEAD(&conn->pm_node);
	spin_lock_bh(&tn->conn_lock);
	list_add_tail_rcu(&conn->pm_node, &tn->connections);
	atomic_inc(&tn->conn_count);
	spin_unlock_bh(&tn->conn_lock);

	/* Call PM-specific init if available */
	if (ops->init) {
		ret = ops->init(net);
		if (ret < 0) {
			pr_err("TQUIC: PM init failed: %d\n", ret);
			/* Remove from connection list on failure */
			spin_lock_bh(&tn->conn_lock);
			list_del_rcu(&conn->pm_node);
			atomic_dec(&tn->conn_count);
			spin_unlock_bh(&tn->conn_lock);
			kfree(pm_state);
			conn->pm = NULL;
			return ret;
		}
	}

	/* For kernel PM with auto_discover, trigger initial discovery
	 * This discovers paths for already-up interfaces with default routes
	 */
	if (pernet->pm_type == TQUIC_PM_TYPE_KERNEL &&
	    pernet->auto_discover) {
		/* Initial discovery happens via netdevice notifier
		 * when interfaces are already up. The notifier was
		 * registered in tquic_pm_kernel_init().
		 */
		pr_debug("TQUIC: Kernel PM initialized with auto_discover\n");
	}

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

	if (!conn || !conn->pm)
		return;

	pm_state = conn->pm;

	/* Call PM-specific release if available */
	if (pm_state->ops && pm_state->ops->release && conn->sk) {
		net = sock_net(conn->sk);
		pm_state->ops->release(net);
	}

	/*
	 * Remove from per-netns connection list.
	 * This must be done before freeing the pm_state to ensure
	 * concurrent lookups via tquic_conn_lookup_by_token() are safe.
	 */
	if (conn->sk) {
		net = sock_net(conn->sk);
		tn = tquic_pernet(net);
		if (tn && !list_empty(&conn->pm_node)) {
			spin_lock_bh(&tn->conn_lock);
			list_del_rcu(&conn->pm_node);
			atomic_dec(&tn->conn_count);
			spin_unlock_bh(&tn->conn_lock);

			/*
			 * Ensure RCU grace period before connection can be freed.
			 * The caller (tquic_conn_destroy) should handle this.
			 */
		}
	}

	/* Free PM-specific private data if any */
	if (pm_state->priv)
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

	/* Allocate stream ID */
	spin_lock(&conn->lock);
	if (bidi) {
		stream_id = conn->next_stream_id_bidi;
		conn->next_stream_id_bidi += 4;
	} else {
		stream_id = conn->next_stream_id_uni;
		conn->next_stream_id_uni += 4;
	}
	spin_unlock(&conn->lock);

	stream->id = stream_id;
	stream->state = TQUIC_STREAM_OPEN;
	stream->conn = conn;

	skb_queue_head_init(&stream->send_buf);
	skb_queue_head_init(&stream->recv_buf);

	stream->max_send_data = TQUIC_DEFAULT_MAX_STREAM_DATA;
	stream->max_recv_data = TQUIC_DEFAULT_MAX_STREAM_DATA;

	init_waitqueue_head(&stream->wait);

	/* Insert into connection's stream tree */
	spin_lock(&conn->lock);
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
	spin_unlock(&conn->lock);

	return stream;
}
EXPORT_SYMBOL_GPL(tquic_stream_open);

void tquic_stream_close(struct tquic_stream *stream)
{
	struct tquic_connection *conn = stream->conn;
	struct sk_buff *skb;

	spin_lock(&conn->lock);
	rb_erase(&stream->node, &conn->streams);
	conn->stats.streams_closed++;
	spin_unlock(&conn->lock);

	/* Purge with proper memory accounting */
	while ((skb = skb_dequeue(&stream->send_buf)) != NULL) {
		if (conn->sk) {
			sk_mem_uncharge(conn->sk, skb->truesize);
			atomic_sub(skb->truesize, &conn->sk->sk_wmem_alloc);
		}
		kfree_skb(skb);
	}
	while ((skb = skb_dequeue(&stream->recv_buf)) != NULL) {
		if (conn->sk) {
			sk_mem_uncharge(conn->sk, skb->truesize);
			atomic_sub(skb->truesize, &conn->sk->sk_rmem_alloc);
		}
		kfree_skb(skb);
	}

	kmem_cache_free(tquic_stream_cache, stream);
}
EXPORT_SYMBOL_GPL(tquic_stream_close);

/*
 * Scheduler Registration
 */

int tquic_register_scheduler(struct tquic_sched_ops *ops)
{
	write_lock(&tquic_sched_lock);
	list_add_tail(&ops->list, &tquic_schedulers);
	write_unlock(&tquic_sched_lock);

	pr_info("tquic: registered scheduler '%s'\n", ops->name);
	return 0;
}
EXPORT_SYMBOL_GPL(tquic_register_scheduler);

void tquic_unregister_scheduler(struct tquic_sched_ops *ops)
{
	write_lock(&tquic_sched_lock);
	list_del(&ops->list);
	write_unlock(&tquic_sched_lock);

	pr_info("tquic: unregistered scheduler '%s'\n", ops->name);
}
EXPORT_SYMBOL_GPL(tquic_unregister_scheduler);

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
 * Module Initialization
 */

int __init tquic_init(void)
{
	int err;

	pr_info("tquic: initializing TQUIC WAN bonding subsystem\n");

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

	tquic_path_cache = kmem_cache_create("tquic_path",
					     sizeof(struct tquic_path),
					     0, SLAB_HWCACHE_ALIGN, NULL);
	if (!tquic_path_cache) {
		err = -ENOMEM;
		goto err_path_cache;
	}

	/* Initialize connection hashtable */
	err = rhashtable_init(&tquic_conn_table, &tquic_conn_params);
	if (err)
		goto err_hashtable;

	/* Initialize global CID table */
	err = tquic_cid_table_init();
	if (err)
		goto err_cid_table;

	/* Initialize timer subsystem */
	err = tquic_timer_init();
	if (err)
		goto err_timer;

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

	/* Initialize io_uring subsystem */
	err = tquic_io_uring_init();
	if (err)
		goto err_io_uring;

	/* Initialize netlink interface */
	err = tquic_netlink_init();
	if (err)
		goto err_netlink;

	/* Initialize sysctl interface */
	err = tquic_sysctl_init();
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
	err = tquic_ratelimit_module_init();
	if (err)
		goto err_ratelimit;

	pr_info("tquic: TQUIC WAN bonding subsystem initialized\n");
	pr_info("tquic: Default bond mode: %d, scheduler: %s, congestion: %s\n",
		tquic_default_bond_mode, tquic_default_scheduler, tquic_default_cong);

	return 0;

err_ratelimit:
	tquic_offload_exit();
err_offload:
	tquic_diag_exit();
err_diag:
	tquic_proto_exit();
err_proto:
	tquic_sysctl_exit();
err_sysctl:
	tquic_netlink_exit();
err_netlink:
	tquic_io_uring_exit();
err_io_uring:
#if IS_ENABLED(CONFIG_TQUIC_NAPI)
	tquic_napi_subsys_exit();
err_napi:
#endif
	tquic_server_exit();
err_server:
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
	tquic_timer_exit();
err_timer:
	tquic_cid_table_exit();
err_cid_table:
	rhashtable_destroy(&tquic_conn_table);
err_hashtable:
	kmem_cache_destroy(tquic_path_cache);
err_path_cache:
	kmem_cache_destroy(tquic_stream_cache);
err_stream_cache:
	kmem_cache_destroy(tquic_conn_cache);
err_conn_cache:
	return err;
}

void __exit tquic_exit(void)
{
	pr_info("tquic: shutting down TQUIC WAN bonding subsystem\n");

	tquic_ratelimit_module_exit();
	tquic_offload_exit();
	tquic_diag_exit();
	tquic_proto_exit();
	/* Proc interface is cleaned up per-netns via pernet_operations */
	tquic_sysctl_exit();
	tquic_netlink_exit();
	tquic_io_uring_exit();
#if IS_ENABLED(CONFIG_TQUIC_NAPI)
	tquic_napi_subsys_exit();
#endif
	tquic_server_exit();
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
	tquic_timer_exit();
	tquic_cid_table_exit();
	rhashtable_destroy(&tquic_conn_table);
	kmem_cache_destroy(tquic_path_cache);
	kmem_cache_destroy(tquic_stream_cache);
	kmem_cache_destroy(tquic_conn_cache);

	pr_info("tquic: TQUIC WAN bonding subsystem unloaded\n");
}

module_init(tquic_init);
module_exit(tquic_exit);
