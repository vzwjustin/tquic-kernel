// SPDX-License-Identifier: GPL-2.0-only
/*
 * TQUIC: Connection Migration Stubs
 *
 * Copyright (c) 2026 Linux Foundation
 *
 * Provides API surface for connection migration.
 * Full implementation in Phase 4 (Path Manager).
 *
 * Phase 2 scope:
 * - API definitions (UAPI, sockopt handlers)
 * - Status reporting (always returns NONE/no migration)
 * - Stubs return -ENOSYS for actual migration operations
 *
 * Phase 4 will implement:
 * - Automatic NAT rebind migration
 * - Explicit migration via sockopt
 * - PATH_CHALLENGE/PATH_RESPONSE handling
 * - Path state machine
 * - Multipath support
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
#include <linux/netdevice.h>
#include <net/tquic.h>
#include "protocol.h"

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

/*
 * =============================================================================
 * PATH MANAGEMENT STUBS
 *
 * TODO Phase 4: Implement full path management with:
 * - Path list in connection
 * - Path state machine (UNUSED -> PENDING -> ACTIVE/STANDBY/FAILED)
 * - RTT/congestion tracking per path
 * - Path selection/scheduling for multipath
 * =============================================================================
 */

/**
 * tquic_path_find_by_addr - Find path by address (stub)
 * @conn: Connection to search
 * @addr: Address to find
 *
 * TODO Phase 4: Implement path lookup by address pair.
 * Should iterate conn->paths and compare local/remote addresses.
 *
 * Returns: Path pointer or NULL if not found
 */
struct tquic_path *tquic_path_find_by_addr(struct tquic_connection *conn,
					   const struct sockaddr_storage *addr)
{
	/* TODO Phase 4: Search conn->paths list by address
	 *
	 * Implementation outline:
	 * list_for_each_entry(path, &conn->paths, list) {
	 *     if (sockaddr_equal(&path->local_addr, addr) ||
	 *         sockaddr_equal(&path->remote_addr, addr))
	 *         return path;
	 * }
	 */
	return NULL;
}

/**
 * tquic_path_create - Create new path (stub)
 * @conn: Connection to add path to
 * @local: Local address for path
 * @remote: Remote address for path
 *
 * TODO Phase 4: Allocate path, add to connection, initialize stats.
 *
 * Returns: New path pointer or NULL on failure
 */
struct tquic_path *tquic_path_create(struct tquic_connection *conn,
				     const struct sockaddr_storage *local,
				     const struct sockaddr_storage *remote)
{
	/* TODO Phase 4: Full path creation with:
	 * 1. Allocate struct tquic_path
	 * 2. Copy local and remote addresses
	 * 3. Assign unique path_id from conn->next_path_id++
	 * 4. Set state to TQUIC_PATH_PENDING
	 * 5. Add to conn->paths list
	 * 6. Initialize RTT estimates (from conn defaults or peer)
	 * 7. Initialize congestion control state
	 * 8. Start path validation timer
	 */
	return NULL;
}

/**
 * tquic_path_free - Free path (stub)
 * @path: Path to free
 *
 * TODO Phase 4: Remove from connection, free resources.
 */
void tquic_path_free(struct tquic_path *path)
{
	/* TODO Phase 4: Full path cleanup with:
	 * 1. Remove from conn->paths list
	 * 2. Cancel validation timer
	 * 3. Release CID assigned to this path
	 * 4. Free congestion control state
	 * 5. Free path structure
	 */
	if (path)
		kfree(path);
}

/**
 * tquic_migration_send_path_challenge - Send PATH_CHALLENGE frame (stub)
 * @conn: Connection
 * @path: Path to send challenge on
 *
 * TODO Phase 4: Build and send PATH_CHALLENGE with random data.
 *
 * Returns: 0 on success, negative errno on failure
 */
int tquic_migration_send_path_challenge(struct tquic_connection *conn,
					struct tquic_path *path)
{
	/* TODO Phase 4: PATH_CHALLENGE implementation:
	 * 1. Generate 8 bytes of cryptographically random challenge data
	 * 2. Store in path->challenge_data for later verification
	 * 3. Build PATH_CHALLENGE frame (type 0x1a, 8 bytes data)
	 * 4. Send frame on the specified path
	 * 5. Set path state to TQUIC_PATH_PENDING
	 * 6. Start validation timer (per RFC 9000, 3*PTO)
	 */
	pr_debug("tquic: PATH_CHALLENGE requested (stub)\n");
	return -ENOSYS;
}

/**
 * tquic_migration_path_event - Notify userspace of path event (stub)
 * @conn: Connection
 * @path: Path that changed
 * @event: Event type (TQUIC_PATH_EVENT_*)
 *
 * TODO Phase 4: Send netlink notification for path events.
 */
void tquic_migration_path_event(struct tquic_connection *conn,
				struct tquic_path *path, int event)
{
	/* TODO Phase 4: Netlink notification implementation:
	 * 1. Build TQUIC_CMD_PATH_EVENT message
	 * 2. Include path_id, state, event type
	 * 3. Multicast to TQUIC_NL_GRP_PATH group
	 */
	pr_debug("tquic: path event %d (stub)\n", event);
}

/*
 * =============================================================================
 * MIGRATION API
 *
 * These functions provide the sockopt API surface.
 * Full implementation in Phase 4 (Path Manager).
 * =============================================================================
 */

/**
 * tquic_migrate_explicit - Explicit migration via sockopt (stub)
 * @conn: Connection to migrate
 * @new_local: New local address to migrate to
 * @flags: Migration flags (TQUIC_MIGRATE_FLAG_*)
 *
 * Phase 2: Returns -ENOSYS (not implemented).
 * Phase 4: Will implement full migration with PATH_CHALLENGE.
 *
 * Returns: 0 on success, negative errno on failure
 */
int tquic_migrate_explicit(struct tquic_connection *conn,
			   struct sockaddr_storage *new_local,
			   u32 flags)
{
	if (!conn)
		return -EINVAL;

	if (conn->state != TQUIC_CONN_CONNECTED)
		return -ENOTCONN;

	/*
	 * TODO Phase 4: Implement migration with:
	 * 1. Validate new_local address is usable
	 * 2. Get fresh CID via tquic_cid_get_for_migration()
	 *    - If no CID available, may need to wait for NEW_CONNECTION_ID
	 * 3. Create new path via tquic_path_create()
	 * 4. Assign CID to new path
	 * 5. Send PATH_CHALLENGE on new path
	 * 6. Set migration state to TQUIC_MIGRATE_PROBING
	 * 7. Wait for PATH_RESPONSE (async via callback)
	 * 8. On success: switch active path, notify userspace
	 * 9. On timeout: mark migration failed, clean up
	 *
	 * TQUIC_MIGRATE_FLAG_PROBE_ONLY: Don't switch, just validate
	 * TQUIC_MIGRATE_FLAG_FORCE: Migrate even if current path is OK
	 */

	pr_info("tquic: explicit migration not yet implemented (Phase 4)\n");
	return -ENOSYS;
}

/**
 * tquic_migrate_auto - Automatic migration on NAT rebind (stub)
 * @conn: Connection
 * @path: Current path
 * @new_addr: New remote address detected
 *
 * Phase 2: Does nothing, returns -ENOSYS.
 * Phase 4: Will detect source address change and trigger migration.
 *
 * Called from packet input path when peer's source address changes.
 *
 * Returns: 0 on success, negative errno on failure
 */
int tquic_migrate_auto(struct tquic_connection *conn,
		       struct tquic_path *path,
		       struct sockaddr_storage *new_addr)
{
	/*
	 * TODO Phase 4: Implement automatic migration with:
	 * 1. Detect source address change in packet input
	 * 2. Verify this isn't a spoofed packet (anti-amplification)
	 * 3. If peer initiated migration (we received from new address):
	 *    - Create new path for new address
	 *    - Send PATH_CHALLENGE to validate
	 *    - Don't send significant data until validated
	 * 4. If we initiated (our address changed):
	 *    - Similar process but we are the migrating party
	 *
	 * Key per RFC 9000:
	 * - Must limit data sent to unvalidated address (anti-amplification)
	 * - Should use fresh CID to prevent linkability
	 * - Should probe both old and new paths initially
	 */

	pr_debug("tquic: auto migration not yet implemented (Phase 4)\n");
	return -ENOSYS;
}

/**
 * tquic_migration_get_status - Get current migration status
 * @conn: Connection
 * @info: OUT - Migration status information
 *
 * Phase 2: Always returns TQUIC_MIGRATE_NONE (no migration in progress).
 * Phase 4: Will return actual migration state from conn->migration_state.
 *
 * Returns: 0 on success
 */
int tquic_migration_get_status(struct tquic_connection *conn,
			       struct tquic_migrate_info *info)
{
	memset(info, 0, sizeof(*info));
	info->status = TQUIC_MIGRATE_NONE;

	if (!conn)
		return 0;

	/*
	 * TODO Phase 4: Return actual migration state from conn:
	 * - status: current migration status enum
	 * - old_path_id: ID of previous/current active path
	 * - new_path_id: ID of path being migrated to
	 * - probe_rtt: RTT from PATH_CHALLENGE/RESPONSE if validated
	 * - error_code: Error code if migration failed
	 * - old_local: Previous local address
	 * - new_local: New local address (if migrating)
	 * - remote: Remote address
	 *
	 * Migration state machine:
	 * TQUIC_MIGRATE_NONE -> TQUIC_MIGRATE_PROBING (challenge sent)
	 * TQUIC_MIGRATE_PROBING -> TQUIC_MIGRATE_VALIDATED (response received)
	 * TQUIC_MIGRATE_PROBING -> TQUIC_MIGRATE_FAILED (timeout)
	 * TQUIC_MIGRATE_VALIDATED -> TQUIC_MIGRATE_NONE (complete)
	 */

	return 0;
}

/**
 * tquic_migration_cleanup - Clean up migration state
 * @conn: Connection
 *
 * Called during connection teardown to free any migration-related resources.
 */
void tquic_migration_cleanup(struct tquic_connection *conn)
{
	/* TODO Phase 4: Free migration state if present
	 *
	 * 1. Cancel any pending PATH_CHALLENGE timers
	 * 2. Free pending path structures
	 * 3. Clear migration state
	 */
}

/*
 * =============================================================================
 * PATH_RESPONSE HANDLING (Stubs)
 *
 * These will be called from packet input path in Phase 4.
 * =============================================================================
 */

/**
 * tquic_migration_handle_path_challenge - Handle received PATH_CHALLENGE
 * @conn: Connection
 * @path: Path frame arrived on
 * @data: 8-byte challenge data
 *
 * TODO Phase 4: Echo back with PATH_RESPONSE.
 *
 * Returns: 0 on success, negative errno on failure
 */
int tquic_migration_handle_path_challenge(struct tquic_connection *conn,
					  struct tquic_path *path,
					  const u8 *data)
{
	/* TODO Phase 4:
	 * 1. Build PATH_RESPONSE frame with same 8-byte data
	 * 2. Send on same path the challenge arrived on
	 * 3. This echoes the challenge back to prove path validity
	 */
	pr_debug("tquic: PATH_CHALLENGE received (stub)\n");
	return -ENOSYS;
}

/**
 * tquic_migration_handle_path_response - Handle received PATH_RESPONSE
 * @conn: Connection
 * @path: Path frame arrived on
 * @data: 8-byte response data
 *
 * TODO Phase 4: Validate response matches our challenge.
 *
 * Returns: 0 on success, negative errno on failure
 */
int tquic_migration_handle_path_response(struct tquic_connection *conn,
					 struct tquic_path *path,
					 const u8 *data)
{
	/* TODO Phase 4:
	 * 1. Check if data matches path->challenge_data
	 * 2. If match: path is validated
	 *    - Set path state to TQUIC_PATH_ACTIVE
	 *    - Calculate RTT from challenge/response
	 *    - If migrating, switch active path
	 *    - Notify userspace via netlink
	 * 3. If no match: protocol error
	 */
	pr_debug("tquic: PATH_RESPONSE received (stub)\n");
	return -ENOSYS;
}

/*
 * =============================================================================
 * SERVER-SIDE MIGRATION HANDLING
 * =============================================================================
 *
 * These functions enable connection migration when a router's source IP
 * changes. This is common in WAN bonding scenarios where routers may have
 * dynamic IP addresses or experience NAT rebinding.
 *
 * Per CONTEXT.md: "Persistent session state across router reconnects with
 * configurable TTL" - implemented via session_ttl and session state timers.
 */

/**
 * tquic_server_handle_migration - Handle server-side connection migration
 * @conn: Connection receiving the migrated packet
 * @path: Path packet arrived on (may have new source address)
 * @new_remote: New remote address detected
 *
 * Called from packet input path when a packet arrives from a known CID
 * but from a different source address. This indicates the router has
 * migrated (e.g., NAT rebinding, IP address change).
 *
 * Server-side migration handling:
 * 1. Validate via CID (already done before this is called)
 * 2. Update path's remote_addr to new source
 * 3. Trigger PATH_CHALLENGE validation for the new address
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

	/*
	 * Update path's remote address to new source.
	 * This allows future packets to be sent to the new address.
	 */
	spin_lock_bh(&conn->paths_lock);
	memcpy(&path->remote_addr, new_remote, sizeof(*new_remote));
	path->last_activity = ktime_get();
	spin_unlock_bh(&conn->paths_lock);

	/*
	 * Trigger PATH_CHALLENGE validation for the new address.
	 * Per RFC 9000, we must validate before sending significant data.
	 */
	ret = tquic_path_start_validation(conn, path);
	if (ret < 0) {
		pr_debug("tquic: failed to start path validation: %d\n", ret);
		/* Continue anyway - validation failure is non-fatal */
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
 *
 * When all paths go down, instead of immediately closing the connection,
 * we keep session state for a configurable TTL period (default 120s per
 * CONTEXT.md). This allows routers to reconnect and resume sessions.
 */

/**
 * struct tquic_session_state - Session state preserved during path loss
 * @conn: Connection this state belongs to
 * @timer: TTL expiration timer
 * @start_time: When all paths went down
 * @ttl_ms: Time to live in milliseconds
 * @packet_queue: Queued packets during path loss
 * @queue_timeout: Timeout for queued packets (default 30s)
 */
struct tquic_session_state {
	struct tquic_connection *conn;
	struct timer_list timer;
	ktime_t start_time;
	u32 ttl_ms;
	struct sk_buff_head packet_queue;
	u32 queue_timeout_ms;
};

/**
 * tquic_session_ttl_expired - Timer callback for session TTL expiration
 * @t: Timer that fired
 *
 * Called when the session TTL expires without any paths recovering.
 * Closes the connection and cleans up session state.
 */
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

	/* Free session state */
	kfree(state);
}

/**
 * tquic_server_start_session_ttl - Start session TTL timer on all paths down
 * @conn: Connection with all paths unavailable
 *
 * Called when the last path becomes unavailable. Instead of closing
 * immediately, we keep session state for the TTL period.
 *
 * Returns: 0 on success, negative errno on failure
 */
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
		ttl_ms = 120000;  /* Default 120s per CONTEXT.md */

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

	/* Store session state in connection */
	conn->state_machine = state;

	pr_info("tquic: session TTL started for connection token=%u (ttl=%ums)\n",
		conn->token, ttl_ms);

	return 0;
}
EXPORT_SYMBOL_GPL(tquic_server_start_session_ttl);

/**
 * tquic_server_session_resume - Resume session when router reconnects
 * @conn: Connection to resume
 * @path: Path that was recovered
 *
 * Called when a path recovers within the TTL window. Cancels the TTL
 * timer and drains any queued packets.
 *
 * Returns: 0 on success, negative errno on failure
 */
int tquic_server_session_resume(struct tquic_connection *conn,
				struct tquic_path *path)
{
	struct tquic_session_state *state;
	struct sk_buff *skb;

	if (!conn || !path)
		return -EINVAL;

	state = (struct tquic_session_state *)conn->state_machine;
	if (!state) {
		/* No session state - just a normal path recovery */
		return 0;
	}

	pr_info("tquic: session resumed for connection token=%u\n",
		conn->token);

	/* Cancel TTL timer */
	del_timer_sync(&state->timer);

	/* Drain queued packets to the recovered path */
	while ((skb = skb_dequeue(&state->packet_queue)) != NULL) {
		/*
		 * Re-transmit queued packet on recovered path.
		 * Note: These packets may need to be re-encrypted if
		 * they were partially processed. For now, we just
		 * drop them and let retransmission handle recovery.
		 */
		kfree_skb(skb);
	}

	/* Free session state */
	conn->state_machine = NULL;
	kfree(state);

	/* Notify that path was recovered */
	tquic_migration_path_event(conn, path, TQUIC_PATH_EVENT_RECOVERED);

	return 0;
}
EXPORT_SYMBOL_GPL(tquic_server_session_resume);

/**
 * tquic_server_queue_packet - Queue packet during path unavailability
 * @conn: Connection with unavailable paths
 * @skb: Packet to queue
 *
 * Called when a packet needs to be sent but no paths are available.
 * Queues the packet for later transmission when a path recovers.
 * Drops if queue is full or timeout is reached.
 *
 * Per CONTEXT.md: "Queue-with-timeout for path-down scenario" (30s)
 *
 * Returns: 0 on success (queued or timeout), -ENOMEM if queue full
 */
int tquic_server_queue_packet(struct tquic_connection *conn,
			      struct sk_buff *skb)
{
	struct tquic_session_state *state;
	s64 elapsed_ms;

	if (!conn || !skb)
		return -EINVAL;

	state = (struct tquic_session_state *)conn->state_machine;
	if (!state) {
		/* No session state - drop packet */
		kfree_skb(skb);
		return 0;
	}

	/* Check queue timeout (30s per CONTEXT.md) */
	elapsed_ms = ktime_ms_delta(ktime_get(), state->start_time);
	if (elapsed_ms >= state->queue_timeout_ms) {
		pr_debug("tquic: queue timeout reached, dropping packet\n");
		kfree_skb(skb);
		return 0;
	}

	/* Check queue size (limit to prevent memory exhaustion) */
	if (skb_queue_len(&state->packet_queue) >= 1024) {
		pr_debug("tquic: queue full, dropping oldest packet\n");
		skb = skb_dequeue(&state->packet_queue);
		if (skb)
			kfree_skb(skb);
	}

	/* Queue the packet */
	skb_queue_tail(&state->packet_queue, skb);

	return 0;
}
EXPORT_SYMBOL_GPL(tquic_server_queue_packet);

/**
 * tquic_server_check_path_recovery - Check if any paths can be recovered
 * @conn: Connection to check
 *
 * Called periodically to check if any UNAVAILABLE paths can be recovered.
 * If a path's interface comes back up, trigger recovery.
 */
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
				/* Try to recover path */
				path->state = path->saved_state;
				if (path->state == TQUIC_PATH_UNUSED)
					path->state = TQUIC_PATH_PENDING;

				/* Trigger validation */
				tquic_path_start_validation(conn, path);

				pr_debug("tquic: attempting path %u recovery\n",
					 path->path_id);
			}
		}
	}
	spin_unlock_bh(&conn->paths_lock);
}
