// SPDX-License-Identifier: GPL-2.0-only
/*
 * TQUIC: Connection Migration Implementation
 *
 * Copyright (c) 2026 Linux Foundation
 *
 * Implements RFC 9000 Section 9 Connection Migration for TQUIC WAN bonding.
 * Supports:
 * - Automatic migration on path degradation (high RTT, packet loss)
 * - Explicit migration via sockopt
 * - Server-side migration handling (NAT rebinding)
 * - Session TTL for persistent state across router reconnects
 *
 * RFC 9000 Connection Migration Overview:
 * - Connection migration allows a connection to continue even when the
 *   endpoint's IP address or port changes (e.g., NAT rebinding, WiFi->LTE)
 * - Migration uses PATH_CHALLENGE/PATH_RESPONSE frames to validate new paths
 * - Each migration should use a fresh connection ID to prevent linkability
 * - Server must validate client address before sending significant data
 */

#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/errno.h>
#include <linux/timer.h>
#include <linux/workqueue.h>
#include <linux/random.h>
#include <linux/netdevice.h>
#include <net/sock.h>
#include <net/tquic.h>
#include "protocol.h"
#include "cong/tquic_cong.h"
#include "tquic_preferred_addr.h"
#include "core/additional_addresses.h"

#include "tquic_compat.h"

/* Sysctl accessor forward declaration */
int tquic_sysctl_get_prefer_preferred_address(void);

/* Timer callback forward declaration */
static void tquic_migration_timeout(struct timer_list *t);

/* Migration constants */
#define TQUIC_MIGRATION_PTO_MULTIPLIER	3	/* 3x PTO for validation timeout */
#define TQUIC_MIGRATION_MAX_RETRIES	3	/* Max PATH_CHALLENGE retries */
#define TQUIC_MIGRATION_DEFAULT_TIMEOUT_MS 1000	/* Default 1s timeout */

/* Path quality degradation thresholds */
#define TQUIC_PATH_DEGRADED_RTT_MULT	3	/* RTT > 3x min_rtt = degraded */
#define TQUIC_PATH_DEGRADED_LOSS_PCT	10	/* >10% loss = degraded */
#define TQUIC_PATH_PROBE_TIMEOUT_MS	100	/* Probe interval when degraded */

/* Anti-amplification limit per RFC 9000 Section 8 */
#define TQUIC_ANTI_AMPLIFICATION_LIMIT	3	/* Max 3x amplification */

/* Forward declaration for tquic_client */
struct tquic_client {
	char psk_identity[64];
	u8 psk_identity_len;
	u8 psk[32];
	u16 port_range_start;
	u16 port_range_end;
	u64 bandwidth_limit;
	atomic_t connection_count;
	atomic64_t tx_bytes;
	atomic64_t rx_bytes;
	atomic_t active_paths;
	u8 traffic_class_weights[4];
	u32 conn_rate_limit;
	atomic_t rate_tokens;
	ktime_t rate_last_refill;
	spinlock_t rate_lock;
	u32 session_ttl;
	struct rhash_head node;
	struct rcu_head rcu_head;
};

/**
 * struct tquic_migration_state - Migration state machine
 * @status: Current migration status (TQUIC_MIGRATE_*)
 * @old_path: Previous active path
 * @new_path: Target path for migration
 * @old_cid: Previous connection ID
 * @new_cid: Fresh CID for new path
 * @challenge_data: 8 bytes of PATH_CHALLENGE data
 * @challenge_sent: When PATH_CHALLENGE was sent
 * @retries: Number of validation retries
 * @probe_rtt: RTT measured from validation
 * @error_code: Error code if migration failed
 * @flags: Migration flags (TQUIC_MIGRATE_FLAG_*)
 * @timer: Validation timeout timer
 * @work: Deferred migration work
 * @lock: Protects migration state
 */
struct tquic_migration_state {
	enum tquic_migrate_status status;
	struct tquic_path *old_path;
	struct tquic_path *new_path;
	struct tquic_cid old_cid;
	struct tquic_cid new_cid;
	u8 challenge_data[8];
	ktime_t challenge_sent;
	u8 retries;
	u32 probe_rtt;
	u32 error_code;
	u32 flags;
	struct timer_list timer;
	struct work_struct work;
	spinlock_t lock;
};

/*
 * =============================================================================
 * HELPER FUNCTIONS
 * =============================================================================
 */

/**
 * sockaddr_equal - Compare two socket addresses
 */
static bool sockaddr_equal(const struct sockaddr_storage *a,
			   const struct sockaddr_storage *b)
{
	if (a->ss_family != b->ss_family)
		return false;

	if (a->ss_family == AF_INET) {
		const struct sockaddr_in *a4 = (const struct sockaddr_in *)a;
		const struct sockaddr_in *b4 = (const struct sockaddr_in *)b;
		return a4->sin_addr.s_addr == b4->sin_addr.s_addr &&
		       a4->sin_port == b4->sin_port;
	}

#if IS_ENABLED(CONFIG_IPV6)
	if (a->ss_family == AF_INET6) {
		const struct sockaddr_in6 *a6 = (const struct sockaddr_in6 *)a;
		const struct sockaddr_in6 *b6 = (const struct sockaddr_in6 *)b;
		return ipv6_addr_equal(&a6->sin6_addr, &b6->sin6_addr) &&
		       a6->sin6_port == b6->sin6_port;
	}
#endif

	return false;
}

/**
 * tquic_path_is_degraded - Check if path quality has degraded
 * @path: Path to check
 *
 * Returns true if path shows signs of degradation (high RTT or loss).
 */
static bool tquic_path_is_degraded(struct tquic_path *path)
{
	struct tquic_path_stats *stats = &path->stats;
	u64 loss_rate;

	if (path->state != TQUIC_PATH_ACTIVE)
		return true;

	/* Check RTT degradation */
	if (stats->rtt_min > 0 && stats->rtt_smoothed > 0) {
		if (stats->rtt_smoothed > stats->rtt_min * TQUIC_PATH_DEGRADED_RTT_MULT)
			return true;
	}

	/* Check packet loss */
	if (stats->tx_packets > 100) {
		loss_rate = (stats->lost_packets * 100) / stats->tx_packets;
		if (loss_rate > TQUIC_PATH_DEGRADED_LOSS_PCT)
			return true;
	}

	return false;
}

/**
 * tquic_path_compute_score - Compute path quality score
 * @path: Path to score
 *
 * Higher score = better path for migration target selection.
 */
static u64 tquic_path_compute_score(struct tquic_path *path)
{
	struct tquic_path_stats *stats = &path->stats;
	u64 score = 1000000;  /* Base score */

	/* Only consider validated or active paths */
	if (path->state != TQUIC_PATH_ACTIVE &&
	    path->state != TQUIC_PATH_VALIDATED &&
	    path->state != TQUIC_PATH_STANDBY)
		return 0;

	/* Factor in RTT (lower is better) */
	if (stats->rtt_smoothed > 0)
		score = score * 1000 / stats->rtt_smoothed;

	/* Factor in bandwidth (higher is better) */
	if (stats->bandwidth > 0)
		score = (score * stats->bandwidth) >> 20;

	/* Penalize for loss */
	if (stats->tx_packets > 0 && stats->lost_packets > 0) {
		u64 loss_pct = (stats->lost_packets * 100) / stats->tx_packets;
		score = score * (100 - min(loss_pct, 90ULL)) / 100;
	}

	/* Apply priority (lower priority value = preferred) */
	score = score * (256 - path->priority) / 256;

	/* Apply weight */
	score = score * path->weight;

	return score;
}

/**
 * tquic_migration_timeout_us - Calculate migration timeout
 * @path: Path being validated
 *
 * Returns timeout in microseconds (3x PTO per RFC 9000).
 */
static u32 tquic_migration_timeout_us(struct tquic_path *path)
{
	u32 timeout_us;

	if (path->stats.rtt_smoothed == 0) {
		timeout_us = TQUIC_MIGRATION_DEFAULT_TIMEOUT_MS * 1000;
	} else {
		/* PTO = SRTT + max(4*RTTVAR, 1ms) */
		u32 pto_us = path->stats.rtt_smoothed +
			     max(path->stats.rtt_variance * 4, 1000U);
		timeout_us = pto_us * TQUIC_MIGRATION_PTO_MULTIPLIER;
	}

	/* Clamp to reasonable bounds */
	return clamp(timeout_us, 100000U, 10000000U);
}

/*
 * =============================================================================
 * PATH MANAGEMENT
 * =============================================================================
 */

/**
 * tquic_path_find_by_addr - Find path by address
 * @conn: Connection to search
 * @addr: Address to find
 *
 * Searches conn->paths list for a path matching the given address.
 * Must be called with paths_lock held or in RCU read section.
 *
 * Returns: Path pointer or NULL if not found
 */
struct tquic_path *tquic_path_find_by_addr(struct tquic_connection *conn,
					   const struct sockaddr_storage *addr)
{
	struct tquic_path *path;

	if (!conn || !addr)
		return NULL;

	list_for_each_entry_rcu(path, &conn->paths, list) {
		if (sockaddr_equal(&path->local_addr, addr) ||
		    sockaddr_equal(&path->remote_addr, addr))
			return path;
	}

	return NULL;
}
EXPORT_SYMBOL_GPL(tquic_path_find_by_addr);

/**
 * tquic_path_create - Create new path for migration
 * @conn: Connection to add path to
 * @local: Local address for path
 * @remote: Remote address for path
 *
 * Allocates a new path, initializes its state, and adds it to the connection.
 * Does NOT start path validation - caller must do that.
 *
 * Returns: New path pointer or NULL on failure
 */
struct tquic_path *tquic_path_create(struct tquic_connection *conn,
				     const struct sockaddr_storage *local,
				     const struct sockaddr_storage *remote)
{
	struct tquic_path *path;
	static atomic_t path_id_gen = ATOMIC_INIT(0);

	if (!conn || !local || !remote)
		return NULL;

	/* Check path limit */
	if (conn->num_paths >= conn->max_paths)
		return NULL;

	path = kzalloc(sizeof(*path), GFP_KERNEL);
	if (!path)
		return NULL;

	/* Initialize path */
	path->conn = conn;
	path->path_id = atomic_inc_return(&path_id_gen);
	path->state = TQUIC_PATH_PENDING;
	path->saved_state = TQUIC_PATH_UNUSED;

	/* Copy addresses */
	memcpy(&path->local_addr, local,
	       local->ss_family == AF_INET ?
	       sizeof(struct sockaddr_in) : sizeof(struct sockaddr_in6));
	memcpy(&path->remote_addr, remote,
	       remote->ss_family == AF_INET ?
	       sizeof(struct sockaddr_in) : sizeof(struct sockaddr_in6));

	/* Initialize with conservative estimates */
	path->stats.rtt_smoothed = TQUIC_DEFAULT_RTT * 1000;  /* 100ms default */
	path->stats.rtt_variance = path->stats.rtt_smoothed / 2;
	path->stats.cwnd = 14720;  /* Initial cwnd */

	/* Default weight and priority */
	path->weight = 1;
	path->priority = 0;
	path->mtu = 1200;  /* QUIC minimum */

	/* Initialize validation state */
	timer_setup(&path->validation.timer, tquic_path_validation_timeout, 0);
	skb_queue_head_init(&path->response.queue);
	atomic_set(&path->response.count, 0);

	INIT_LIST_HEAD(&path->list);

	/* Initialize congestion control */
	if (tquic_cong_init_path(path, NULL) < 0)
		pr_debug("tquic: CC init failed for path %u (non-fatal)\n",
			 path->path_id);

	/* Add to connection's path list */
	spin_lock_bh(&conn->paths_lock);
	list_add_tail_rcu(&path->list, &conn->paths);
	conn->num_paths++;
	spin_unlock_bh(&conn->paths_lock);

	pr_debug("tquic: created path %u for migration\n", path->path_id);

	return path;
}
EXPORT_SYMBOL_GPL(tquic_path_create);

/**
 * tquic_path_free - Free a path
 * @path: Path to free
 *
 * Removes path from connection and frees all resources.
 */
void tquic_path_free(struct tquic_path *path)
{
	struct tquic_connection *conn;

	if (!path)
		return;

	conn = path->conn;

	/* Cancel validation timer */
	del_timer_sync(&path->validation.timer);

	/* Purge response queue */
	skb_queue_purge(&path->response.queue);

	/* Release congestion control state */
	tquic_cong_release_path(path);

	/* Release device reference */
	if (path->dev)
		dev_put(path->dev);

	/* Remove from connection's path list */
	if (conn) {
		spin_lock_bh(&conn->paths_lock);
		list_del_rcu(&path->list);
		conn->num_paths--;
		spin_unlock_bh(&conn->paths_lock);

		/* Wait for RCU readers */
		synchronize_rcu();
	}

	kfree(path);
}
EXPORT_SYMBOL_GPL(tquic_path_free);

/**
 * tquic_migration_send_path_challenge - Send PATH_CHALLENGE frame
 * @conn: Connection
 * @path: Path to send challenge on
 *
 * Generates random challenge data and sends PATH_CHALLENGE on the path.
 *
 * Returns: 0 on success, negative errno on failure
 */
int tquic_migration_send_path_challenge(struct tquic_connection *conn,
					struct tquic_path *path)
{
	if (!conn || !path)
		return -EINVAL;

	/* Generate 8 bytes of cryptographically random challenge data */
	get_random_bytes(path->validation.challenge_data,
			 sizeof(path->validation.challenge_data));

	/* Also store in legacy field for compatibility */
	memcpy(path->challenge_data, path->validation.challenge_data, 8);

	/* Record send time */
	path->validation.challenge_sent = ktime_get();
	path->validation.challenge_pending = true;

	/* Send via existing path challenge infrastructure */
	return tquic_send_path_challenge(conn, path);
}
EXPORT_SYMBOL_GPL(tquic_migration_send_path_challenge);

/**
 * tquic_migration_path_event - Notify userspace of path event
 * @conn: Connection
 * @path: Path that changed
 * @event: Event type (TQUIC_PATH_EVENT_*)
 */
void tquic_migration_path_event(struct tquic_connection *conn,
				struct tquic_path *path, int event)
{
	if (!conn || !path)
		return;

	/* Send netlink notification */
	tquic_nl_path_event(conn, path, event);

	pr_debug("tquic: path %u event %d\n", path->path_id, event);
}
EXPORT_SYMBOL_GPL(tquic_migration_path_event);

/*
 * =============================================================================
 * MIGRATION STATE MACHINE
 * =============================================================================
 */

/**
 * tquic_migration_state_alloc - Allocate migration state
 * @conn: Connection
 *
 * Returns: New migration state or NULL on failure
 */
static struct tquic_migration_state *tquic_migration_state_alloc(
	struct tquic_connection *conn)
{
	struct tquic_migration_state *ms;

	ms = kzalloc(sizeof(*ms), GFP_KERNEL);
	if (!ms)
		return NULL;

	ms->status = TQUIC_MIGRATE_NONE;
	spin_lock_init(&ms->lock);
	timer_setup(&ms->timer, tquic_migration_timeout, 0);

	return ms;
}

/**
 * tquic_migration_timeout - Validation timeout handler
 */
static void tquic_migration_timeout(struct timer_list *t)
{
	struct tquic_migration_state *ms;
	struct tquic_connection *conn;
	struct tquic_path *path;

	ms = from_timer(ms, t, timer);
	if (!ms || !ms->new_path)
		return;

	conn = ms->new_path->conn;
	path = ms->new_path;

	spin_lock_bh(&ms->lock);

	if (ms->status != TQUIC_MIGRATE_PROBING) {
		spin_unlock_bh(&ms->lock);
		return;
	}

	ms->retries++;

	if (ms->retries >= TQUIC_MIGRATION_MAX_RETRIES) {
		/* Migration failed */
		pr_warn("tquic: migration to path %u failed after %u retries\n",
			path->path_id, ms->retries);

		ms->status = TQUIC_MIGRATE_FAILED;
		ms->error_code = EQUIC_NO_VIABLE_PATH;
		path->state = TQUIC_PATH_FAILED;

		spin_unlock_bh(&ms->lock);

		/* Notify failure */
		tquic_migration_path_event(conn, path, TQUIC_PATH_EVENT_FAILED);
		return;
	}

	spin_unlock_bh(&ms->lock);

	/* Retry PATH_CHALLENGE */
	pr_debug("tquic: retrying PATH_CHALLENGE on path %u (attempt %u)\n",
		 path->path_id, ms->retries + 1);

	tquic_migration_send_path_challenge(conn, path);

	/* Reschedule timeout */
	mod_timer(&ms->timer, jiffies +
		  usecs_to_jiffies(tquic_migration_timeout_us(path)));
}

/**
 * tquic_migration_work_handler - Deferred migration completion
 */
static void tquic_migration_work_handler(struct work_struct *work)
{
	struct tquic_migration_state *ms;
	struct tquic_connection *conn;
	struct tquic_path *old_path, *new_path;

	ms = container_of(work, struct tquic_migration_state, work);
	if (!ms || !ms->new_path)
		return;

	conn = ms->new_path->conn;

	spin_lock_bh(&ms->lock);

	if (ms->status != TQUIC_MIGRATE_VALIDATED) {
		spin_unlock_bh(&ms->lock);
		return;
	}

	old_path = ms->old_path;
	new_path = ms->new_path;

	/* Complete migration unless probe-only */
	if (!(ms->flags & TQUIC_MIGRATE_FLAG_PROBE_ONLY)) {
		spin_lock(&conn->lock);
		conn->active_path = new_path;
		conn->stats.path_migrations++;
		spin_unlock(&conn->lock);

		pr_info("tquic: migration complete to path %u (RTT: %u us)\n",
			new_path->path_id, ms->probe_rtt);

		/* Demote old path to standby */
		if (old_path && old_path != new_path) {
			old_path->state = TQUIC_PATH_STANDBY;
		}
	}

	ms->status = TQUIC_MIGRATE_NONE;
	ms->old_path = NULL;
	ms->new_path = NULL;

	spin_unlock_bh(&ms->lock);

	/* Notify completion */
	tquic_migration_path_event(conn, new_path, TQUIC_PATH_EVENT_ACTIVE);
}

/*
 * =============================================================================
 * AUTOMATIC MIGRATION
 * =============================================================================
 */

/**
 * tquic_migrate_auto - Automatic migration on path degradation or NAT rebind
 * @conn: Connection
 * @path: Current path (may be degraded or have new address)
 * @new_addr: New remote address detected (NULL for quality-based migration)
 *
 * Detects when the current path has degraded (high RTT, packet loss) or
 * when a NAT rebinding has occurred, and initiates migration to a better path.
 *
 * Per RFC 9000 Section 9:
 * - On receiving packet from new address: validate before sending data
 * - Limit data to unvalidated address (anti-amplification)
 * - Probe both old and new paths initially
 *
 * Returns: 0 on success, negative errno on failure
 */
int tquic_migrate_auto(struct tquic_connection *conn,
		       struct tquic_path *path,
		       struct sockaddr_storage *new_addr)
{
	struct tquic_migration_state *ms;
	struct tquic_path *best_path = NULL;
	struct tquic_path *iter;
	u64 best_score = 0;
	int ret;

	if (!conn)
		return -EINVAL;

	if (conn->state != TQUIC_CONN_CONNECTED)
		return -ENOTCONN;

	/* Check if migration is already in progress */
	ms = (struct tquic_migration_state *)conn->state_machine;
	if (ms && ms->status == TQUIC_MIGRATE_PROBING)
		return -EBUSY;

	/*
	 * Case 1: NAT rebinding - new_addr is provided
	 * Peer sent from a different source address, need to validate.
	 *
	 * Per RFC 9000 Section 9.3.1: NAT rebinding is always permitted
	 * as it's a passive change (peer changed address, we respond).
	 * This is not considered active migration.
	 */
	if (new_addr) {
		pr_debug("tquic: auto-migration triggered by NAT rebind\n");

		/* Update path's remote address */
		if (path) {
			spin_lock_bh(&conn->paths_lock);
			memcpy(&path->remote_addr, new_addr, sizeof(*new_addr));
			path->last_activity = ktime_get();
			spin_unlock_bh(&conn->paths_lock);

			/* Validate the new address */
			ret = tquic_path_start_validation(conn, path);
			if (ret < 0)
				pr_debug("tquic: NAT rebind validation failed: %d\n", ret);

			/* Don't send significant data until validated */
			path->state = TQUIC_PATH_PENDING;
		}

		conn->stats.path_migrations++;
		return 0;
	}

	/*
	 * Case 2: Quality degradation - active migration to better path
	 *
	 * Check if active migration is disabled (RFC 9000 Section 9.1).
	 * If disabled, we cannot initiate migration to a new path.
	 */
	if (conn->migration_disabled) {
		pr_debug("tquic: auto-migration rejected - migration disabled\n");
		return -EPERM;
	}

	/* Check if current path actually needs migration */
	if (path && !tquic_path_is_degraded(path)) {
		/* Current path is fine, no migration needed */
		return 0;
	}

	pr_debug("tquic: auto-migration triggered by path degradation\n");

	/* Find best alternative path */
	rcu_read_lock();
	list_for_each_entry_rcu(iter, &conn->paths, list) {
		u64 score;

		/* Skip current degraded path */
		if (iter == path)
			continue;

		/* Skip non-usable paths */
		if (iter->state != TQUIC_PATH_ACTIVE &&
		    iter->state != TQUIC_PATH_VALIDATED &&
		    iter->state != TQUIC_PATH_STANDBY)
			continue;

		score = tquic_path_compute_score(iter);
		if (score > best_score) {
			best_score = score;
			best_path = iter;
		}
	}
	rcu_read_unlock();

	if (!best_path) {
		pr_debug("tquic: no alternative path for migration\n");
		return -ENOENT;
	}

	/* Allocate or get migration state */
	if (!ms) {
		ms = tquic_migration_state_alloc(conn);
		if (!ms)
			return -ENOMEM;
		conn->state_machine = ms;
	}

	/* Set up migration */
	spin_lock_bh(&ms->lock);

	ms->status = TQUIC_MIGRATE_PROBING;
	ms->old_path = conn->active_path;
	ms->new_path = best_path;
	ms->retries = 0;
	ms->flags = 0;

	spin_unlock_bh(&ms->lock);

	/* Get fresh CID for new path if available */
	ret = tquic_cid_get_for_migration(conn, &ms->new_cid);
	if (ret == 0) {
		/* Assign new CID to path */
		memcpy(&best_path->remote_cid, &ms->new_cid,
		       sizeof(best_path->remote_cid));
	}

	/* Send PATH_CHALLENGE on new path */
	ret = tquic_path_start_validation(conn, best_path);
	if (ret < 0) {
		spin_lock_bh(&ms->lock);
		ms->status = TQUIC_MIGRATE_NONE;
		ms->new_path = NULL;
		spin_unlock_bh(&ms->lock);
		return ret;
	}

	/* Set up timeout timer */
	ms->timer.function = tquic_migration_timeout;
	mod_timer(&ms->timer, jiffies +
		  usecs_to_jiffies(tquic_migration_timeout_us(best_path)));

	pr_info("tquic: auto-migration started to path %u\n", best_path->path_id);

	return 0;
}
EXPORT_SYMBOL_GPL(tquic_migrate_auto);

/*
 * =============================================================================
 * EXPLICIT MIGRATION
 * =============================================================================
 */

/**
 * tquic_migrate_explicit - Explicit migration via sockopt
 * @conn: Connection to migrate
 * @new_local: New local address to migrate to
 * @flags: Migration flags (TQUIC_MIGRATE_FLAG_*)
 *
 * Application-requested migration to a specific local address.
 * Creates new path if needed, validates it, and switches traffic.
 *
 * TQUIC_MIGRATE_FLAG_PROBE_ONLY: Validate path without switching traffic
 * TQUIC_MIGRATE_FLAG_FORCE: Migrate even if current path is healthy
 *
 * Returns: 0 on success (migration started), negative errno on failure
 */
int tquic_migrate_explicit(struct tquic_connection *conn,
			   struct sockaddr_storage *new_local,
			   u32 flags)
{
	struct tquic_migration_state *ms;
	struct tquic_path *new_path;
	int ret;

	if (!conn || !new_local)
		return -EINVAL;

	if (conn->state != TQUIC_CONN_CONNECTED)
		return -ENOTCONN;

	/*
	 * Check if active migration is disabled (RFC 9000 Section 9.1)
	 *
	 * Per RFC 9000: "If the disable_active_migration transport parameter
	 * is received, an endpoint that uses a different local address MUST NOT
	 * send packets to the peer."
	 *
	 * Note: Migration to preferred_address is handled separately by
	 * tquic_migrate_to_preferred_address() which bypasses this check.
	 */
	if (conn->migration_disabled) {
		pr_debug("tquic: explicit migration rejected - migration disabled\n");
		return -EPERM;
	}

	/* Check if migration is already in progress */
	ms = (struct tquic_migration_state *)conn->state_machine;
	if (ms && ms->status == TQUIC_MIGRATE_PROBING)
		return -EBUSY;

	/* If not forcing, check if current path is OK */
	if (!(flags & TQUIC_MIGRATE_FLAG_FORCE) &&
	    conn->active_path &&
	    !tquic_path_is_degraded(conn->active_path)) {
		pr_debug("tquic: explicit migration rejected - current path OK\n");
		return -EALREADY;
	}

	/* Check if we already have a path with this local address */
	rcu_read_lock();
	new_path = tquic_path_find_by_addr(conn, new_local);
	rcu_read_unlock();

	if (!new_path) {
		/* Create new path with the specified local address */
		if (!conn->active_path) {
			pr_warn("tquic: no active path to get remote address\n");
			return -EINVAL;
		}

		new_path = tquic_path_create(conn, new_local,
					     &conn->active_path->remote_addr);
		if (!new_path)
			return -ENOMEM;
	}

	/* Allocate or get migration state */
	if (!ms) {
		ms = tquic_migration_state_alloc(conn);
		if (!ms) {
			tquic_path_free(new_path);
			return -ENOMEM;
		}
		conn->state_machine = ms;
	}

	/* Set up migration work handler */
	INIT_WORK(&ms->work, tquic_migration_work_handler);

	/* Set up migration state */
	spin_lock_bh(&ms->lock);

	ms->status = TQUIC_MIGRATE_PROBING;
	ms->old_path = conn->active_path;
	ms->new_path = new_path;
	ms->retries = 0;
	ms->flags = flags;
	ms->error_code = 0;

	spin_unlock_bh(&ms->lock);

	/* Get fresh CID for new path */
	ret = tquic_cid_get_for_migration(conn, &ms->new_cid);
	if (ret == 0) {
		memcpy(&new_path->remote_cid, &ms->new_cid,
		       sizeof(new_path->remote_cid));
		pr_debug("tquic: assigned fresh CID for migration\n");
	}

	/* Start path validation */
	ret = tquic_path_start_validation(conn, new_path);
	if (ret < 0) {
		spin_lock_bh(&ms->lock);
		ms->status = TQUIC_MIGRATE_FAILED;
		ms->error_code = -ret;
		spin_unlock_bh(&ms->lock);
		return ret;
	}

	/* Set up timeout timer */
	ms->timer.function = tquic_migration_timeout;
	mod_timer(&ms->timer, jiffies +
		  usecs_to_jiffies(tquic_migration_timeout_us(new_path)));

	pr_info("tquic: explicit migration started to path %u (flags=0x%x)\n",
		new_path->path_id, flags);

	return 0;
}
EXPORT_SYMBOL_GPL(tquic_migrate_explicit);

/**
 * tquic_migration_get_status - Get current migration status
 * @conn: Connection
 * @info: OUT - Migration status information
 *
 * Returns: 0 on success
 */
int tquic_migration_get_status(struct tquic_connection *conn,
			       struct tquic_migrate_info *info)
{
	struct tquic_migration_state *ms;

	memset(info, 0, sizeof(*info));
	info->status = TQUIC_MIGRATE_NONE;

	if (!conn)
		return 0;

	ms = (struct tquic_migration_state *)conn->state_machine;
	if (!ms)
		return 0;

	spin_lock_bh(&ms->lock);

	info->status = ms->status;
	info->probe_rtt = ms->probe_rtt;
	info->error_code = ms->error_code;

	if (ms->old_path) {
		info->old_path_id = ms->old_path->path_id;
		memcpy(&info->old_local, &ms->old_path->local_addr,
		       sizeof(info->old_local));
	}

	if (ms->new_path) {
		info->new_path_id = ms->new_path->path_id;
		memcpy(&info->new_local, &ms->new_path->local_addr,
		       sizeof(info->new_local));
		memcpy(&info->remote, &ms->new_path->remote_addr,
		       sizeof(info->remote));
	}

	spin_unlock_bh(&ms->lock);

	return 0;
}
EXPORT_SYMBOL_GPL(tquic_migration_get_status);

/**
 * tquic_migration_cleanup - Clean up migration state
 * @conn: Connection
 *
 * Cleans up all migration-related state including:
 * - General migration state machine
 * - Preferred address migration state (RFC 9000 Section 9.6)
 */
void tquic_migration_cleanup(struct tquic_connection *conn)
{
	struct tquic_migration_state *ms;

	if (!conn)
		return;

	/* Clean up general migration state */
	ms = (struct tquic_migration_state *)conn->state_machine;
	if (ms) {
		/* Cancel timer */
		del_timer_sync(&ms->timer);

		/* Cancel any pending work */
		cancel_work_sync(&ms->work);

		/* Clear state */
		conn->state_machine = NULL;
		kfree(ms);
	}

	/* Clean up preferred address migration state (RFC 9000 Section 9.6) */
	tquic_pref_addr_client_cleanup(conn);
}
EXPORT_SYMBOL_GPL(tquic_migration_cleanup);

/*
 * =============================================================================
 * PATH_CHALLENGE / PATH_RESPONSE HANDLING
 * =============================================================================
 */

/**
 * tquic_migration_handle_path_challenge - Handle received PATH_CHALLENGE
 * @conn: Connection
 * @path: Path frame arrived on
 * @data: 8-byte challenge data
 *
 * Per RFC 9000 Section 8.2: Must respond with PATH_RESPONSE echoing
 * the same 8 bytes on the same path.
 *
 * Returns: 0 on success, negative errno on failure
 */
int tquic_migration_handle_path_challenge(struct tquic_connection *conn,
					  struct tquic_path *path,
					  const u8 *data)
{
	if (!conn || !path || !data)
		return -EINVAL;

	pr_debug("tquic: PATH_CHALLENGE received on path %u\n", path->path_id);

	/* Delegate to path validation module which handles rate limiting */
	return tquic_path_handle_challenge(conn, path, data);
}
EXPORT_SYMBOL_GPL(tquic_migration_handle_path_challenge);

/**
 * tquic_migration_handle_path_response - Handle received PATH_RESPONSE
 * @conn: Connection
 * @path: Path frame arrived on
 * @data: 8-byte response data
 *
 * Validates that response matches our pending challenge.
 * If valid, marks path as validated and completes migration if pending.
 *
 * Returns: 0 on success, negative errno on failure
 */
int tquic_migration_handle_path_response(struct tquic_connection *conn,
					 struct tquic_path *path,
					 const u8 *data)
{
	struct tquic_migration_state *ms;
	ktime_t now = ktime_get();
	int ret;

	if (!conn || !path || !data)
		return -EINVAL;

	pr_debug("tquic: PATH_RESPONSE received on path %u\n", path->path_id);

	/* First, let the path validation module handle it */
	ret = tquic_path_handle_response(conn, path, data);
	if (ret < 0)
		return ret;

	/* Check if this completes a pending migration */
	ms = (struct tquic_migration_state *)conn->state_machine;
	if (!ms || ms->status != TQUIC_MIGRATE_PROBING)
		return 0;

	spin_lock_bh(&ms->lock);

	if (ms->new_path != path) {
		spin_unlock_bh(&ms->lock);
		return 0;
	}

	/* Verify challenge data matches */
	if (memcmp(data, ms->challenge_data, 8) != 0) {
		spin_unlock_bh(&ms->lock);
		pr_debug("tquic: PATH_RESPONSE mismatch for migration\n");
		return -EINVAL;
	}

	/* Cancel timeout timer */
	del_timer(&ms->timer);

	/* Calculate RTT */
	ms->probe_rtt = ktime_us_delta(now, path->validation.challenge_sent);

	/* Mark migration validated */
	ms->status = TQUIC_MIGRATE_VALIDATED;
	path->state = TQUIC_PATH_ACTIVE;

	spin_unlock_bh(&ms->lock);

	pr_info("tquic: migration validated for path %u (RTT: %u us)\n",
		path->path_id, ms->probe_rtt);

	/* Schedule deferred migration completion */
	schedule_work(&ms->work);

	return 0;
}
EXPORT_SYMBOL_GPL(tquic_migration_handle_path_response);

/*
 * =============================================================================
 * SERVER-SIDE MIGRATION HANDLING
 * =============================================================================
 */

/**
 * tquic_server_handle_migration - Handle server-side connection migration
 * @conn: Connection receiving the migrated packet
 * @path: Path packet arrived on
 * @new_remote: New remote address detected
 *
 * Per RFC 9000 Section 9.3: Server must validate new client address
 * before sending significant data (anti-amplification).
 *
 * Returns: 0 on success, negative errno on failure
 */
int tquic_server_handle_migration(struct tquic_connection *conn,
				  struct tquic_path *path,
				  const struct sockaddr_storage *new_remote)
{
	int ret;

	if (!conn || !path || !new_remote)
		return -EINVAL;

	/* Only server-side connections should call this */
	if (conn->role != TQUIC_ROLE_SERVER) {
		pr_debug("tquic: migration handler called on client connection\n");
		return -EINVAL;
	}

	pr_debug("tquic: handling server-side migration for path %u\n",
		 path->path_id);

	/* Check if this is NAT rebinding (same CID, different address) */
	if (!sockaddr_equal(&path->remote_addr, new_remote)) {
		pr_info("tquic: detected NAT rebinding on path %u\n",
			path->path_id);

		/*
		 * Update path's remote address.
		 * Per RFC 9000 Section 9.3.2: This could be NAT rebinding,
		 * so we update the address but start validation.
		 */
		spin_lock_bh(&conn->paths_lock);
		memcpy(&path->remote_addr, new_remote, sizeof(*new_remote));
		path->last_activity = ktime_get();

		/* Save state and set to pending until validated */
		path->saved_state = path->state;
		path->state = TQUIC_PATH_PENDING;
		spin_unlock_bh(&conn->paths_lock);

		/*
		 * Trigger PATH_CHALLENGE validation.
		 * Per RFC 9000, must validate before sending significant data.
		 */
		ret = tquic_path_start_validation(conn, path);
		if (ret < 0) {
			pr_debug("tquic: failed to start path validation: %d\n", ret);
			/* Restore state on failure */
			spin_lock_bh(&conn->paths_lock);
			path->state = path->saved_state;
			spin_unlock_bh(&conn->paths_lock);
		}
	}

	/* Update statistics */
	conn->stats.path_migrations++;

	/* Notify userspace about migration */
	tquic_migration_path_event(conn, path, TQUIC_PATH_EVENT_MIGRATE);

	return 0;
}
EXPORT_SYMBOL_GPL(tquic_server_handle_migration);

/*
 * =============================================================================
 * SESSION STATE TTL FOR ROUTER RECONNECTS
 * =============================================================================
 */

/**
 * struct tquic_session_state - Session state preserved during path loss
 */
struct tquic_session_state {
	struct tquic_connection *conn;
	struct timer_list timer;
	ktime_t start_time;
	u32 ttl_ms;
	struct sk_buff_head packet_queue;
	u32 queue_timeout_ms;
};

static void tquic_session_ttl_expired(struct timer_list *t)
{
	struct tquic_session_state *state;
	struct tquic_connection *conn;

	state = from_timer(state, t, timer);
	conn = state->conn;

	pr_info("tquic: session TTL expired for connection token=%u\n",
		conn->token);

	/* Close connection - all paths failed and TTL expired */
	tquic_conn_close_with_error(conn, EQUIC_NO_VIABLE_PATH,
				    "session TTL expired");

	/* Clean up queued packets */
	skb_queue_purge(&state->packet_queue);

	/* Clear state from connection */
	conn->state_machine = NULL;

	/* Free session state */
	kfree(state);
}

int tquic_server_start_session_ttl(struct tquic_connection *conn)
{
	struct tquic_session_state *state;
	struct tquic_client *client;
	u32 ttl_ms;

	if (!conn)
		return -EINVAL;

	/* Get TTL from client config if server-side, else use default */
	client = conn->client;
	if (client)
		ttl_ms = client->session_ttl;
	else
		ttl_ms = 120000;  /* Default 120s */

	/* Check if we already have session state */
	if (conn->state_machine) {
		pr_debug("tquic: session TTL already active\n");
		return 0;
	}

	state = kzalloc(sizeof(*state), GFP_ATOMIC);
	if (!state)
		return -ENOMEM;

	state->conn = conn;
	state->start_time = ktime_get();
	state->ttl_ms = ttl_ms;
	state->queue_timeout_ms = 30000;  /* 30s per CONTEXT.md */
	skb_queue_head_init(&state->packet_queue);

	timer_setup(&state->timer, tquic_session_ttl_expired, 0);
	mod_timer(&state->timer, jiffies + msecs_to_jiffies(ttl_ms));

	conn->state_machine = state;

	pr_info("tquic: session TTL started for connection token=%u (ttl=%ums)\n",
		conn->token, ttl_ms);

	return 0;
}
EXPORT_SYMBOL_GPL(tquic_server_start_session_ttl);

int tquic_server_session_resume(struct tquic_connection *conn,
				struct tquic_path *path)
{
	struct tquic_session_state *state;
	struct sk_buff *skb;

	if (!conn || !path)
		return -EINVAL;

	state = (struct tquic_session_state *)conn->state_machine;
	if (!state)
		return 0;

	pr_info("tquic: session resumed for connection token=%u\n",
		conn->token);

	/* Cancel TTL timer */
	del_timer_sync(&state->timer);

	/* Drain queued packets */
	while ((skb = skb_dequeue(&state->packet_queue)) != NULL)
		kfree_skb(skb);

	/* Free session state */
	conn->state_machine = NULL;
	kfree(state);

	/* Notify that path was recovered */
	tquic_migration_path_event(conn, path, TQUIC_PATH_EVENT_RECOVERED);

	return 0;
}
EXPORT_SYMBOL_GPL(tquic_server_session_resume);

int tquic_server_queue_packet(struct tquic_connection *conn,
			      struct sk_buff *skb)
{
	struct tquic_session_state *state;
	s64 elapsed_ms;

	if (!conn || !skb)
		return -EINVAL;

	state = (struct tquic_session_state *)conn->state_machine;
	if (!state) {
		kfree_skb(skb);
		return 0;
	}

	/* Check queue timeout (30s) */
	elapsed_ms = ktime_ms_delta(ktime_get(), state->start_time);
	if (elapsed_ms >= state->queue_timeout_ms) {
		pr_debug("tquic: queue timeout reached, dropping packet\n");
		kfree_skb(skb);
		return 0;
	}

	/* Check queue size */
	if (skb_queue_len(&state->packet_queue) >= 1024) {
		struct sk_buff *old_skb;
		pr_debug("tquic: queue full, dropping oldest packet\n");
		old_skb = skb_dequeue(&state->packet_queue);
		if (old_skb)
			kfree_skb(old_skb);
	}

	skb_queue_tail(&state->packet_queue, skb);

	return 0;
}
EXPORT_SYMBOL_GPL(tquic_server_queue_packet);

void tquic_server_check_path_recovery(struct tquic_connection *conn)
{
	struct tquic_path *path;

	if (!conn)
		return;

	spin_lock_bh(&conn->paths_lock);
	list_for_each_entry(path, &conn->paths, list) {
		if (path->state == TQUIC_PATH_UNAVAILABLE) {
			/* Check if network device is back up */
			if (path->dev && netif_running(path->dev)) {
				/* Restore state and trigger validation */
				path->state = path->saved_state;
				if (path->state == TQUIC_PATH_UNUSED)
					path->state = TQUIC_PATH_PENDING;

				spin_unlock_bh(&conn->paths_lock);
				tquic_path_start_validation(conn, path);
				spin_lock_bh(&conn->paths_lock);

				pr_debug("tquic: attempting path %u recovery\n",
					 path->path_id);
			}
		}
	}
	spin_unlock_bh(&conn->paths_lock);
}
EXPORT_SYMBOL_GPL(tquic_server_check_path_recovery);

/*
 * =============================================================================
 * PREFERRED ADDRESS MIGRATION (RFC 9000 Section 9.6)
 * =============================================================================
 */

/**
 * tquic_migrate_to_preferred_address - Migrate to server's preferred address
 * @conn: Connection
 *
 * Initiates migration to the server's preferred address as received in
 * transport parameters. This is called automatically after handshake if
 * prefer_preferred_address sysctl is enabled, or can be called explicitly.
 *
 * Per RFC 9000 Section 9.6:
 * - Client MAY migrate to preferred address after handshake
 * - Must validate the new path before switching
 * - Use the CID provided in the preferred_address parameter
 *
 * Returns: 0 on success, negative errno on failure
 */
int tquic_migrate_to_preferred_address(struct tquic_connection *conn)
{
	struct tquic_pref_addr_migration *pref_migration;
	struct tquic_migration_state *ms;
	struct tquic_path *new_path;
	struct sockaddr_storage remote_addr;
	sa_family_t family;
	int ret;

	if (!conn)
		return -EINVAL;

	if (conn->state != TQUIC_CONN_CONNECTED)
		return -ENOTCONN;

	if (conn->role != TQUIC_ROLE_CLIENT) {
		pr_debug("tquic: only clients can migrate to preferred address\n");
		return -EINVAL;
	}

	/* Check if migration is already in progress */
	ms = (struct tquic_migration_state *)conn->state_machine;
	if (ms && ms->status == TQUIC_MIGRATE_PROBING)
		return -EBUSY;

	/*
	 * Access preferred address migration state.
	 * This is stored in conn->preferred_addr by tquic_pref_addr_client_received()
	 * after transport parameter negotiation.
	 *
	 * Per RFC 9000 Section 9.6, the preferred_address transport parameter
	 * contains the server's preferred address(es), connection ID, and
	 * stateless reset token. The client stores this for migration.
	 */
	pref_migration = (struct tquic_pref_addr_migration *)conn->preferred_addr;

	/*
	 * Validate preferred address is available.
	 * Per RFC 9000 Section 9.6, the preferred_address transport parameter
	 * is only sent by servers and contains the address client should migrate to.
	 */
	if (!pref_migration) {
		pr_debug("tquic: no preferred address migration state\n");
		return -ENOENT;
	}

	if (pref_migration->state != TQUIC_PREF_ADDR_AVAILABLE) {
		pr_debug("tquic: preferred address not available (state=%d)\n",
			 pref_migration->state);
		return -ENOENT;
	}

	/* Check if we have at least one valid address */
	if (!pref_migration->server_addr.ipv4_valid &&
	    !pref_migration->server_addr.ipv6_valid) {
		pr_debug("tquic: no valid preferred address configured\n");
		return -ENOENT;
	}

	/*
	 * Select address family for migration.
	 * Prefer same family as current connection for better success chance.
	 */
	ret = tquic_pref_addr_client_select_address(conn, &family);
	if (ret < 0) {
		pr_debug("tquic: failed to select preferred address family: %d\n", ret);
		return ret;
	}

	/* Build remote address based on selected family */
	memset(&remote_addr, 0, sizeof(remote_addr));
	if (family == AF_INET) {
		struct sockaddr_in *sin = (struct sockaddr_in *)&remote_addr;
		memcpy(sin, &pref_migration->server_addr.ipv4_addr, sizeof(*sin));
		pr_debug("tquic: migrating to preferred IPv4 address %pI4:%u\n",
			 &sin->sin_addr, ntohs(sin->sin_port));
	} else {
		struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)&remote_addr;
		memcpy(sin6, &pref_migration->server_addr.ipv6_addr, sizeof(*sin6));
		pr_debug("tquic: migrating to preferred IPv6 address %pI6c:%u\n",
			 &sin6->sin6_addr, ntohs(sin6->sin6_port));
	}

	/*
	 * Create new path for preferred address migration.
	 * Per RFC 9000 Section 9.6, use the CID provided in the preferred_address
	 * transport parameter for the new path.
	 */
	new_path = tquic_pref_addr_create_path(conn, &remote_addr,
					       &pref_migration->server_addr.cid,
					       pref_migration->server_addr.reset_token);
	if (IS_ERR(new_path)) {
		pr_err("tquic: failed to create path for preferred address: %ld\n",
		       PTR_ERR(new_path));
		return PTR_ERR(new_path);
	}

	/* Update migration state */
	pref_migration->migration_path = new_path;
	pref_migration->state = TQUIC_PREF_ADDR_VALIDATING;
	pref_migration->validation_started = ktime_get();
	pref_migration->retry_count = 0;
	pref_migration->migration_attempts++;

	/*
	 * Start path validation with PATH_CHALLENGE.
	 * Per RFC 9000 Section 8.2, must validate path before switching traffic.
	 */
	ret = tquic_pref_addr_validate_path(conn, new_path);
	if (ret < 0) {
		pr_err("tquic: failed to start preferred address path validation: %d\n", ret);
		pref_migration->state = TQUIC_PREF_ADDR_FAILED;
		pref_migration->validation_failures++;
		tquic_path_free(new_path);
		pref_migration->migration_path = NULL;
		return ret;
	}

	pr_info("tquic: started migration to preferred address (family=%s)\n",
		family == AF_INET ? "IPv4" : "IPv6");

	return 0;
}
EXPORT_SYMBOL_GPL(tquic_migrate_to_preferred_address);

/**
 * tquic_migration_on_handshake_complete - Handle post-handshake migration setup
 * @conn: Connection
 *
 * Called when handshake completes. If a preferred address was received
 * and auto-migration is enabled, initiates migration.
 */
void tquic_migration_on_handshake_complete(struct tquic_connection *conn)
{
	struct net *net;

	if (!conn || !conn->sk)
		return;

	if (conn->role != TQUIC_ROLE_CLIENT)
		return;

	net = sock_net(conn->sk);

	/* Check if auto-migration to preferred address is enabled */
	if (!tquic_sysctl_get_prefer_preferred_address())
		return;

	/*
	 * Check if we received a preferred address in transport params.
	 * If so, and auto-migration is enabled, start migration.
	 */
	if (tquic_migrate_to_preferred_address(conn) == 0) {
		pr_debug("tquic: auto-migrating to preferred address\n");
	}
}
EXPORT_SYMBOL_GPL(tquic_migration_on_handshake_complete);

/*
 * =============================================================================
 * ADDITIONAL ADDRESSES MIGRATION (draft-piraux-quic-additional-addresses)
 * =============================================================================
 */

/**
 * tquic_migrate_to_additional_address - Migrate to a specific additional address
 * @conn: Connection
 * @addr_entry: Additional address entry to migrate to
 *
 * Initiates migration to a specific additional address from the peer's
 * additional_addresses transport parameter.
 *
 * Return: 0 on success, negative errno on failure
 */
int tquic_migrate_to_additional_address(struct tquic_connection *conn,
					struct tquic_additional_address *addr_entry)
{
	struct tquic_migration_state *ms;
	struct tquic_path *new_path;
	struct sockaddr_storage local_addr;
	int ret;

	if (!conn || !addr_entry)
		return -EINVAL;

	if (conn->state != TQUIC_CONN_CONNECTED)
		return -ENOTCONN;

	/*
	 * Unlike preferred_address, migration to additional addresses
	 * is subject to the disable_active_migration flag.
	 */
	if (conn->migration_disabled) {
		pr_debug("tquic: additional address migration rejected - migration disabled\n");
		return -EPERM;
	}

	/* Check if migration is already in progress */
	ms = (struct tquic_migration_state *)conn->state_machine;
	if (ms && ms->status == TQUIC_MIGRATE_PROBING)
		return -EBUSY;

	/* Validate the address entry */
	if (!addr_entry->active) {
		pr_debug("tquic: additional address not active\n");
		return -EINVAL;
	}

	if (!tquic_additional_addr_is_valid(&addr_entry->addr)) {
		pr_debug("tquic: additional address validation failed\n");
		return -EINVAL;
	}

	/* Get local address from current path */
	if (conn->active_path) {
		memcpy(&local_addr, &conn->active_path->local_addr,
		       sizeof(local_addr));
	} else {
		memset(&local_addr, 0, sizeof(local_addr));
		local_addr.ss_family = addr_entry->addr.ss_family;
	}

	/* Create path to the additional address */
	new_path = tquic_path_create(conn, &local_addr, &addr_entry->addr);
	if (!new_path) {
		pr_err("tquic: failed to create path for additional address\n");
		return -ENOMEM;
	}

	/* Set the remote CID from the additional address */
	memcpy(&new_path->remote_cid, &addr_entry->cid,
	       sizeof(new_path->remote_cid));

	/*
	 * Note: Stateless reset token registration is handled via cid_pool.
	 * The token from addr_entry->stateless_reset_token is stored with
	 * the CID in the connection's cid_pool for reset detection. If reset
	 * token validation is needed, it should be added to cid_pool lookup.
	 */

	/* Allocate or get migration state */
	if (!ms) {
		ms = kzalloc(sizeof(*ms), GFP_KERNEL);
		if (!ms) {
			tquic_path_free(new_path);
			return -ENOMEM;
		}
		spin_lock_init(&ms->lock);
		timer_setup(&ms->timer, NULL, 0);
		INIT_WORK(&ms->work, tquic_migration_work_handler);
		conn->state_machine = ms;
	}

	/* Set up migration state */
	spin_lock_bh(&ms->lock);
	ms->status = TQUIC_MIGRATE_PROBING;
	ms->old_path = conn->active_path;
	ms->new_path = new_path;
	ms->retries = 0;
	ms->flags = 0;
	ms->error_code = 0;
	spin_unlock_bh(&ms->lock);

	/* Start path validation */
	ret = tquic_path_start_validation(conn, new_path);
	if (ret < 0) {
		spin_lock_bh(&ms->lock);
		ms->status = TQUIC_MIGRATE_FAILED;
		ms->error_code = -ret;
		ms->new_path = NULL;
		spin_unlock_bh(&ms->lock);
		tquic_path_free(new_path);
		return ret;
	}

	/* Set up timeout timer */
	ms->timer.function = tquic_migration_timeout;
	mod_timer(&ms->timer, jiffies +
		  usecs_to_jiffies(tquic_migration_timeout_us(new_path)));

	/* Mark address as in use */
	addr_entry->last_used = ktime_get();

	pr_info("tquic: started migration to additional address (IPv%u)\n",
		addr_entry->ip_version);

	return 0;
}
EXPORT_SYMBOL_GPL(tquic_migrate_to_additional_address);

/**
 * tquic_migrate_select_additional_address - Select and migrate to best additional address
 * @conn: Connection
 * @policy: Address selection policy
 *
 * Selects the best additional address using the specified policy and
 * initiates migration to it.
 *
 * Return: 0 on success, negative errno on failure
 */
int tquic_migrate_select_additional_address(struct tquic_connection *conn,
					    enum tquic_addr_select_policy policy)
{
	struct tquic_additional_addresses *remote_addrs;
	struct tquic_additional_address *selected;
	sa_family_t current_family = AF_UNSPEC;

	if (!conn)
		return -EINVAL;

	remote_addrs = conn->additional_remote_addrs;
	if (!remote_addrs || remote_addrs->count == 0) {
		pr_debug("tquic: no additional addresses available\n");
		return -ENOENT;
	}

	/* Get current address family */
	if (conn->active_path)
		current_family = conn->active_path->remote_addr.ss_family;

	/* Select address */
	spin_lock_bh(&remote_addrs->lock);
	selected = tquic_additional_addr_select(remote_addrs, policy,
						current_family);
	spin_unlock_bh(&remote_addrs->lock);

	if (!selected) {
		pr_debug("tquic: no suitable additional address found\n");
		return -ENOENT;
	}

	return tquic_migrate_to_additional_address(conn, selected);
}
EXPORT_SYMBOL_GPL(tquic_migrate_select_additional_address);

/**
 * tquic_migrate_additional_addr_on_validated - Handle additional address path validation
 * @conn: Connection
 * @path: Validated path
 *
 * Called when a path to an additional address is successfully validated.
 * Updates the address entry and completes the migration.
 *
 * Return: 0 on success, negative errno on failure
 */
int tquic_migrate_additional_addr_on_validated(struct tquic_connection *conn,
					       struct tquic_path *path)
{
	struct tquic_additional_addresses *remote_addrs;
	struct tquic_additional_address *addr_entry;
	u32 rtt_us;

	if (!conn || !path)
		return -EINVAL;

	remote_addrs = conn->additional_remote_addrs;
	if (!remote_addrs)
		return 0;

	/* Find the address entry for this path */
	spin_lock_bh(&remote_addrs->lock);
	addr_entry = tquic_additional_addr_find(remote_addrs, &path->remote_addr);
	if (addr_entry) {
		/* Mark as validated */
		tquic_additional_addr_validate(addr_entry);

		/* Update RTT estimate from path validation */
		rtt_us = path->stats.rtt_smoothed;
		if (rtt_us > 0)
			tquic_additional_addr_update_rtt(addr_entry, rtt_us);

		pr_debug("tquic: additional address validated (RTT: %u us)\n",
			 rtt_us);
	}
	spin_unlock_bh(&remote_addrs->lock);

	return 0;
}
EXPORT_SYMBOL_GPL(tquic_migrate_additional_addr_on_validated);

/**
 * tquic_migrate_additional_addr_on_failed - Handle additional address validation failure
 * @conn: Connection
 * @path: Failed path
 * @error: Error code
 *
 * Called when path validation to an additional address fails.
 * Marks the address as invalid.
 */
void tquic_migrate_additional_addr_on_failed(struct tquic_connection *conn,
					     struct tquic_path *path,
					     int error)
{
	struct tquic_additional_addresses *remote_addrs;
	struct tquic_additional_address *addr_entry;

	if (!conn || !path)
		return;

	remote_addrs = conn->additional_remote_addrs;
	if (!remote_addrs)
		return;

	/* Find and invalidate the address entry */
	spin_lock_bh(&remote_addrs->lock);
	addr_entry = tquic_additional_addr_find(remote_addrs, &path->remote_addr);
	if (addr_entry) {
		tquic_additional_addr_invalidate(addr_entry);
		pr_warn("tquic: additional address validation failed (error: %d)\n",
			error);
	}
	spin_unlock_bh(&remote_addrs->lock);
}
EXPORT_SYMBOL_GPL(tquic_migrate_additional_addr_on_failed);

/**
 * tquic_migrate_validate_all_additional - Validate all additional addresses
 * @conn: Connection
 *
 * Starts path validation probes to all additional addresses received from
 * the peer. This allows measuring RTT and reachability before migration
 * is needed.
 *
 * Return: Number of validation probes started, or negative errno on failure
 */
int tquic_migrate_validate_all_additional(struct tquic_connection *conn)
{
	struct tquic_additional_addresses *remote_addrs;
	struct tquic_additional_address *entry;
	struct sockaddr_storage local_addr;
	struct tquic_path *probe_path;
	int count = 0;
	int ret;

	if (!conn)
		return -EINVAL;

	if (conn->state != TQUIC_CONN_CONNECTED)
		return -ENOTCONN;

	remote_addrs = conn->additional_remote_addrs;
	if (!remote_addrs || remote_addrs->count == 0)
		return 0;

	/* Get local address for probing */
	if (conn->active_path) {
		memcpy(&local_addr, &conn->active_path->local_addr,
		       sizeof(local_addr));
	} else {
		return -ENOENT;
	}

	spin_lock_bh(&remote_addrs->lock);
	list_for_each_entry(entry, &remote_addrs->addresses, list) {
		/* Skip already validated or inactive addresses */
		if (entry->validated || !entry->active)
			continue;

		spin_unlock_bh(&remote_addrs->lock);

		/* Create probe path */
		probe_path = tquic_path_create(conn, &local_addr, &entry->addr);
		if (probe_path) {
			memcpy(&probe_path->remote_cid, &entry->cid,
			       sizeof(entry->cid));

			/* Send PATH_CHALLENGE (probe only, don't migrate) */
			ret = tquic_path_start_validation(conn, probe_path);
			if (ret == 0) {
				count++;
				pr_debug("tquic: probing additional address %d\n",
					 count);
			} else {
				tquic_path_free(probe_path);
			}
		}

		spin_lock_bh(&remote_addrs->lock);
	}
	spin_unlock_bh(&remote_addrs->lock);

	pr_info("tquic: started validation probes to %d additional addresses\n",
		count);

	return count;
}
EXPORT_SYMBOL_GPL(tquic_migrate_validate_all_additional);

/**
 * tquic_additional_addr_migration_cleanup - Clean up additional address migration state
 * @conn: Connection
 *
 * Cleans up additional addresses state during connection teardown.
 */
void tquic_additional_addr_migration_cleanup(struct tquic_connection *conn)
{
	if (!conn)
		return;

	tquic_additional_addr_conn_cleanup(conn);
}
EXPORT_SYMBOL_GPL(tquic_additional_addr_migration_cleanup);

MODULE_DESCRIPTION("TQUIC Connection Migration");
MODULE_LICENSE("GPL");
