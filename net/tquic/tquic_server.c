// SPDX-License-Identifier: GPL-2.0-only
/*
 * TQUIC: Multi-tenant Server Connection Handling
 *
 * Copyright (c) 2026 Linux Foundation
 *
 * Implements server-side TQUIC multi-tenant connection acceptance with PSK
 * authentication and rate limiting. This enables a single VPS to accept
 * connections from multiple home routers, each identified by unique PSK
 * identity for isolation, with abuse prevention via connection rate limiting.
 *
 * Key features:
 * - Per-client (router) connection tracking via PSK identity
 * - Token bucket rate limiting per client (default 10 conn/sec)
 * - Session TTL for router reconnects (default 120s)
 * - Queue-with-timeout for temporary path loss (30s)
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/rhashtable.h>
#include <linux/atomic.h>
#include <linux/workqueue.h>
#include <linux/timer.h>
#include <linux/ratelimit.h>
#include <net/tquic.h>

#include "protocol.h"
#include "tquic_mib.h"

/*
 * Maximum PSK identity length (RFC 8446 Section 4.2.11)
 */
#define TQUIC_MAX_PSK_IDENTITY_LEN	64

/*
 * Default rate limit: 10 connections per second per client
 */
#define TQUIC_DEFAULT_CONN_RATE_LIMIT	10

/*
 * Default session TTL: 120 seconds per CONTEXT.md
 */
#define TQUIC_DEFAULT_SESSION_TTL_MS	120000

/*
 * Default queue timeout: 30 seconds per CONTEXT.md
 */
#define TQUIC_DEFAULT_QUEUE_TIMEOUT_MS	30000

/**
 * struct tquic_client - Per-router client state for multi-tenant VPS
 * @psk_identity: PSK identity string (up to 64 bytes)
 * @psk_identity_len: Length of PSK identity
 * @psk: Pre-shared key (32 bytes for TLS 1.3 PSK)
 * @port_range_start: Start of assigned port range
 * @port_range_end: End of assigned port range
 * @bandwidth_limit: Bandwidth limit in bytes/sec (0 = unlimited)
 * @connection_count: Number of active connections
 * @tx_bytes: Total bytes transmitted
 * @rx_bytes: Total bytes received
 * @active_paths: Number of active paths across all connections
 * @traffic_class_weights: QoS weights per traffic class
 * @conn_rate_limit: Max connections per second (default 10)
 * @rate_tokens: Current token bucket level
 * @rate_last_refill: Last token refill time
 * @session_ttl: Session state TTL in ms (default 120s)
 * @node: RHT node for hashtable linkage
 * @rcu_head: RCU callback for deferred freeing
 */
struct tquic_client {
	char psk_identity[TQUIC_MAX_PSK_IDENTITY_LEN];
	u8 psk_identity_len;
	u8 psk[32];  /* TLS 1.3 PSK */

	/* Port allocation */
	u16 port_range_start;
	u16 port_range_end;

	/* Resource limits */
	u64 bandwidth_limit;

	/* Statistics */
	atomic_t connection_count;
	atomic64_t tx_bytes;
	atomic64_t rx_bytes;
	atomic_t active_paths;

	/* QoS weights per traffic class */
	u8 traffic_class_weights[4];

	/* Rate limiting - token bucket */
	u32 conn_rate_limit;
	atomic_t rate_tokens;
	ktime_t rate_last_refill;
	spinlock_t rate_lock;

	/* Session TTL for router reconnects */
	u32 session_ttl;

	/* RHT linkage */
	struct rhash_head node;
	struct rcu_head rcu_head;
};

/*
 * Client hashtable keyed by PSK identity string
 */
static const struct rhashtable_params tquic_client_params = {
	.key_len = TQUIC_MAX_PSK_IDENTITY_LEN,
	.key_offset = offsetof(struct tquic_client, psk_identity),
	.head_offset = offsetof(struct tquic_client, node),
	.automatic_shrinking = true,
};

static struct rhashtable tquic_client_table;
static bool tquic_client_table_initialized;
static DEFINE_MUTEX(tquic_client_mutex);

/*
 * Rate limit state for logging
 */
static DEFINE_RATELIMIT_STATE(tquic_rate_limit_log, 5 * HZ, 1);

/**
 * tquic_client_rate_refill - Refill rate limit tokens based on elapsed time
 * @client: Client to refill tokens for
 *
 * Implements token bucket refill. Tokens are added based on the time elapsed
 * since the last refill, up to the maximum bucket size (conn_rate_limit).
 *
 * Must be called with rate_lock held.
 */
static void tquic_client_rate_refill(struct tquic_client *client)
{
	ktime_t now = ktime_get();
	s64 elapsed_ns;
	u64 tokens_to_add;
	int current_tokens;

	elapsed_ns = ktime_to_ns(ktime_sub(now, client->rate_last_refill));
	if (elapsed_ns <= 0)
		return;

	/* Calculate tokens to add: (elapsed_ns / 1e9) * rate_limit */
	tokens_to_add = (u64)elapsed_ns * client->conn_rate_limit;
	tokens_to_add = div_u64(tokens_to_add, NSEC_PER_SEC);

	if (tokens_to_add == 0)
		return;

	current_tokens = atomic_read(&client->rate_tokens);
	current_tokens += (int)min_t(u64, tokens_to_add, INT_MAX);

	/* Cap at bucket size (1 second of burst) */
	if (current_tokens > (int)client->conn_rate_limit)
		current_tokens = client->conn_rate_limit;

	atomic_set(&client->rate_tokens, current_tokens);
	client->rate_last_refill = now;
}

/**
 * tquic_client_rate_limit_check - Check if connection is allowed by rate limit
 * @client: Client to check
 *
 * Implements token bucket rate limiting. Returns true if connection is allowed
 * (token consumed), false if rate limit exceeded.
 *
 * Per CONTEXT.md: Connection rate limiting per client for abuse prevention.
 *
 * Returns: true if connection allowed, false if rate limited
 */
bool tquic_client_rate_limit_check(struct tquic_client *client)
{
	int tokens;
	bool allowed = false;
	unsigned long flags;

	if (!client)
		return false;

	spin_lock_irqsave(&client->rate_lock, flags);

	/* Refill tokens based on elapsed time */
	tquic_client_rate_refill(client);

	/* Try to consume a token */
	tokens = atomic_read(&client->rate_tokens);
	if (tokens > 0) {
		atomic_dec(&client->rate_tokens);
		allowed = true;
	} else {
		/* Rate limit hit - log (ratelimited) */
		if (__ratelimit(&tquic_rate_limit_log)) {
			pr_info("tquic: rate limit exceeded for client '%.*s'\n",
				client->psk_identity_len, client->psk_identity);
		}
	}

	spin_unlock_irqrestore(&client->rate_lock, flags);

	return allowed;
}
EXPORT_SYMBOL_GPL(tquic_client_rate_limit_check);

/**
 * tquic_client_alloc - Allocate and initialize a new client structure
 * @identity: PSK identity string
 * @identity_len: Length of identity (1-64 bytes)
 *
 * Returns: Newly allocated client or NULL on failure
 */
static struct tquic_client *tquic_client_alloc(const char *identity,
					       size_t identity_len)
{
	struct tquic_client *client;

	if (!identity || identity_len == 0 ||
	    identity_len > TQUIC_MAX_PSK_IDENTITY_LEN)
		return NULL;

	client = kzalloc(sizeof(*client), GFP_KERNEL);
	if (!client)
		return NULL;

	memcpy(client->psk_identity, identity, identity_len);
	client->psk_identity_len = identity_len;

	/* Initialize rate limiting with defaults */
	client->conn_rate_limit = TQUIC_DEFAULT_CONN_RATE_LIMIT;
	atomic_set(&client->rate_tokens, client->conn_rate_limit);
	client->rate_last_refill = ktime_get();
	spin_lock_init(&client->rate_lock);

	/* Initialize session TTL */
	client->session_ttl = TQUIC_DEFAULT_SESSION_TTL_MS;

	/* Initialize counters */
	atomic_set(&client->connection_count, 0);
	atomic64_set(&client->tx_bytes, 0);
	atomic64_set(&client->rx_bytes, 0);
	atomic_set(&client->active_paths, 0);

	/* Default QoS weights (equal) */
	client->traffic_class_weights[0] = 25;
	client->traffic_class_weights[1] = 25;
	client->traffic_class_weights[2] = 25;
	client->traffic_class_weights[3] = 25;

	return client;
}

/**
 * tquic_client_free_rcu - RCU callback to free client
 * @head: RCU head embedded in client structure
 */
static void tquic_client_free_rcu(struct rcu_head *head)
{
	struct tquic_client *client;

	client = container_of(head, struct tquic_client, rcu_head);
	kfree(client);
}

/**
 * tquic_client_lookup_by_psk - Look up client by PSK identity
 * @identity: PSK identity string
 * @identity_len: Length of identity
 *
 * Called during TLS handshake to find matching client configuration.
 * RCU protected - caller must be in RCU read section.
 *
 * Returns: Client pointer or NULL if not found
 */
struct tquic_client *tquic_client_lookup_by_psk(const char *identity,
						size_t identity_len)
{
	struct tquic_client *client;
	char lookup_key[TQUIC_MAX_PSK_IDENTITY_LEN] = {0};

	if (!identity || identity_len == 0 ||
	    identity_len > TQUIC_MAX_PSK_IDENTITY_LEN)
		return NULL;

	if (!tquic_client_table_initialized)
		return NULL;

	/* Prepare padded key for lookup */
	memcpy(lookup_key, identity, identity_len);

	rcu_read_lock();
	client = rhashtable_lookup(&tquic_client_table, lookup_key,
				   tquic_client_params);
	rcu_read_unlock();

	return client;
}
EXPORT_SYMBOL_GPL(tquic_client_lookup_by_psk);

/**
 * tquic_client_register - Register a new client configuration
 * @identity: PSK identity string
 * @identity_len: Length of identity
 * @psk: 32-byte pre-shared key
 *
 * Registers a client configuration for PSK-based authentication.
 *
 * Returns: 0 on success, negative errno on failure
 */
int tquic_client_register(const char *identity, size_t identity_len,
			  const u8 *psk)
{
	struct tquic_client *client;
	int ret;

	if (!psk)
		return -EINVAL;

	client = tquic_client_alloc(identity, identity_len);
	if (!client)
		return -ENOMEM;

	memcpy(client->psk, psk, 32);

	mutex_lock(&tquic_client_mutex);
	if (!tquic_client_table_initialized) {
		mutex_unlock(&tquic_client_mutex);
		kfree(client);
		return -ENODEV;
	}

	ret = rhashtable_insert_fast(&tquic_client_table, &client->node,
				     tquic_client_params);
	mutex_unlock(&tquic_client_mutex);

	if (ret) {
		kfree(client);
		return ret;
	}

	pr_info("tquic: registered client '%.*s'\n",
		(int)identity_len, identity);
	return 0;
}
EXPORT_SYMBOL_GPL(tquic_client_register);

/**
 * tquic_client_unregister - Unregister a client configuration
 * @identity: PSK identity string
 * @identity_len: Length of identity
 *
 * Returns: 0 on success, -ENOENT if not found
 */
int tquic_client_unregister(const char *identity, size_t identity_len)
{
	struct tquic_client *client;
	char lookup_key[TQUIC_MAX_PSK_IDENTITY_LEN] = {0};
	int ret;

	if (!identity || identity_len == 0 ||
	    identity_len > TQUIC_MAX_PSK_IDENTITY_LEN)
		return -EINVAL;

	memcpy(lookup_key, identity, identity_len);

	mutex_lock(&tquic_client_mutex);
	if (!tquic_client_table_initialized) {
		mutex_unlock(&tquic_client_mutex);
		return -ENODEV;
	}

	client = rhashtable_lookup(&tquic_client_table, lookup_key,
				   tquic_client_params);
	if (!client) {
		mutex_unlock(&tquic_client_mutex);
		return -ENOENT;
	}

	ret = rhashtable_remove_fast(&tquic_client_table, &client->node,
				     tquic_client_params);
	mutex_unlock(&tquic_client_mutex);

	if (ret == 0) {
		/* Defer freeing until RCU grace period */
		call_rcu(&client->rcu_head, tquic_client_free_rcu);
		pr_info("tquic: unregistered client '%.*s'\n",
			(int)identity_len, identity);
	}

	return ret;
}
EXPORT_SYMBOL_GPL(tquic_client_unregister);

/**
 * tquic_server_bind_client - Bind client to connection after PSK auth
 * @conn: Connection to bind
 * @client: Client configuration
 *
 * Called after successful PSK authentication AND rate limit check.
 * Increments client connection count.
 *
 * Returns: 0 on success
 */
int tquic_server_bind_client(struct tquic_connection *conn,
			     struct tquic_client *client)
{
	if (!conn || !client)
		return -EINVAL;

	/* Store client pointer in connection */
	conn->client = client;

	/* Increment connection count */
	atomic_inc(&client->connection_count);

	pr_debug("tquic: bound connection to client '%.*s' (count=%d)\n",
		 client->psk_identity_len, client->psk_identity,
		 atomic_read(&client->connection_count));

	return 0;
}
EXPORT_SYMBOL_GPL(tquic_server_bind_client);

/**
 * tquic_server_unbind_client - Unbind client from connection on close
 * @conn: Connection to unbind
 *
 * Called when connection is closed. Decrements client connection count.
 */
void tquic_server_unbind_client(struct tquic_connection *conn)
{
	struct tquic_client *client;

	if (!conn)
		return;

	client = conn->client;
	if (!client)
		return;

	/* Decrement connection count */
	atomic_dec(&client->connection_count);

	pr_debug("tquic: unbound connection from client '%.*s' (count=%d)\n",
		 client->psk_identity_len, client->psk_identity,
		 atomic_read(&client->connection_count));

	conn->client = NULL;
}
EXPORT_SYMBOL_GPL(tquic_server_unbind_client);

/**
 * tquic_server_get_client_psk - Get PSK for client during handshake
 * @identity: PSK identity from ClientHello
 * @identity_len: Length of identity
 * @psk: Output buffer for PSK (32 bytes)
 *
 * Called by TLS handshake to retrieve PSK for client authentication.
 *
 * Returns: 0 on success with PSK copied to output, -ENOENT if not found
 */
int tquic_server_get_client_psk(const char *identity, size_t identity_len,
				u8 *psk)
{
	struct tquic_client *client;

	if (!psk)
		return -EINVAL;

	client = tquic_client_lookup_by_psk(identity, identity_len);
	if (!client)
		return -ENOENT;

	memcpy(psk, client->psk, 32);
	return 0;
}
EXPORT_SYMBOL_GPL(tquic_server_get_client_psk);

/**
 * tquic_client_set_rate_limit - Set connection rate limit for client
 * @identity: PSK identity string
 * @identity_len: Length of identity
 * @rate_limit: Max connections per second (0 = use default)
 *
 * Returns: 0 on success, negative errno on failure
 */
int tquic_client_set_rate_limit(const char *identity, size_t identity_len,
				u32 rate_limit)
{
	struct tquic_client *client;
	unsigned long flags;

	client = tquic_client_lookup_by_psk(identity, identity_len);
	if (!client)
		return -ENOENT;

	if (rate_limit == 0)
		rate_limit = TQUIC_DEFAULT_CONN_RATE_LIMIT;

	spin_lock_irqsave(&client->rate_lock, flags);
	client->conn_rate_limit = rate_limit;
	/* Reset token bucket to new rate */
	atomic_set(&client->rate_tokens, rate_limit);
	client->rate_last_refill = ktime_get();
	spin_unlock_irqrestore(&client->rate_lock, flags);

	return 0;
}
EXPORT_SYMBOL_GPL(tquic_client_set_rate_limit);

/**
 * tquic_client_set_session_ttl - Set session TTL for client
 * @identity: PSK identity string
 * @identity_len: Length of identity
 * @ttl_ms: Session TTL in milliseconds (0 = use default)
 *
 * Returns: 0 on success, negative errno on failure
 */
int tquic_client_set_session_ttl(const char *identity, size_t identity_len,
				 u32 ttl_ms)
{
	struct tquic_client *client;

	client = tquic_client_lookup_by_psk(identity, identity_len);
	if (!client)
		return -ENOENT;

	if (ttl_ms == 0)
		ttl_ms = TQUIC_DEFAULT_SESSION_TTL_MS;

	client->session_ttl = ttl_ms;
	return 0;
}
EXPORT_SYMBOL_GPL(tquic_client_set_session_ttl);

/**
 * tquic_client_get_stats - Get statistics for a client
 * @identity: PSK identity string
 * @identity_len: Length of identity
 * @conn_count: Output connection count
 * @tx_bytes: Output TX bytes
 * @rx_bytes: Output RX bytes
 *
 * Returns: 0 on success, negative errno on failure
 */
int tquic_client_get_stats(const char *identity, size_t identity_len,
			   int *conn_count, u64 *tx_bytes, u64 *rx_bytes)
{
	struct tquic_client *client;

	client = tquic_client_lookup_by_psk(identity, identity_len);
	if (!client)
		return -ENOENT;

	if (conn_count)
		*conn_count = atomic_read(&client->connection_count);
	if (tx_bytes)
		*tx_bytes = atomic64_read(&client->tx_bytes);
	if (rx_bytes)
		*rx_bytes = atomic64_read(&client->rx_bytes);

	return 0;
}
EXPORT_SYMBOL_GPL(tquic_client_get_stats);

/*
 * =============================================================================
 * SERVER ACCEPT PATH
 * =============================================================================
 */

/**
 * tquic_server_accept - Process incoming connection on server socket
 * @sk: Server socket
 * @skb: Initial packet
 * @client_addr: Client source address
 *
 * Called from UDP receive path when Initial packet arrives.
 * Validates PSK, checks rate limit, and initiates handshake.
 *
 * Returns: 0 on success (handshake initiated), negative errno on failure
 */
int tquic_server_accept(struct sock *sk, struct sk_buff *skb,
			struct sockaddr_storage *client_addr)
{
	/* Delegate to tquic_server_handshake which handles the full flow */
	return tquic_server_handshake(sk, skb, client_addr);
}
EXPORT_SYMBOL_GPL(tquic_server_accept);

/*
 * =============================================================================
 * MODULE INIT/EXIT
 * =============================================================================
 */

/**
 * tquic_server_init - Initialize server subsystem
 *
 * Returns: 0 on success
 */
int __init tquic_server_init(void)
{
	int ret;

	mutex_lock(&tquic_client_mutex);
	ret = rhashtable_init(&tquic_client_table, &tquic_client_params);
	if (ret == 0)
		tquic_client_table_initialized = true;
	mutex_unlock(&tquic_client_mutex);

	if (ret) {
		pr_err("tquic: failed to initialize client table: %d\n", ret);
		return ret;
	}

	pr_info("tquic: server subsystem initialized\n");
	return 0;
}

/**
 * tquic_server_exit - Cleanup server subsystem
 */
void __exit tquic_server_exit(void)
{
	mutex_lock(&tquic_client_mutex);
	if (tquic_client_table_initialized) {
		rhashtable_destroy(&tquic_client_table);
		tquic_client_table_initialized = false;
	}
	mutex_unlock(&tquic_client_mutex);

	pr_info("tquic: server subsystem exited\n");
}
