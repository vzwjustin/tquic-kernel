// SPDX-License-Identifier: GPL-2.0-only
/*
 * TQUIC: Multi-tenant Server Connection Handling
 *
 * Copyright (c) 2026 Justin Adams <spotty118@gmail.com>
 * Kernel implementation by Justin Adams <spotty118@gmail.com>
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
#include <linux/string.h>
#include <linux/rhashtable.h>
#include <linux/atomic.h>
#include <linux/refcount.h>
#include <linux/workqueue.h>
#include <linux/timer.h>
#include <linux/ratelimit.h>
#include <net/tquic.h>

#include "protocol.h"
#include "tquic_debug.h"
#include "tquic_mib.h"
#include "tquic_retry.h"
#include "tquic_sysctl.h"

/*
 * Maximum PSK identity length (RFC 8446 Section 4.2.11)
 */
#define TQUIC_MAX_PSK_IDENTITY_LEN	64
#define TQUIC_PSK_KEY_LEN		(TQUIC_MAX_PSK_IDENTITY_LEN + 1)

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
 * @refcnt: Object lifetime reference count
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

	/* Lifetime management: table ref + active connection refs */
	refcount_t refcnt;

	/* RHT linkage */
	struct rhash_head node;
	struct rcu_head rcu_head;
};

/*
 * Client hashtable keyed by PSK identity string
 */
static const struct rhashtable_params tquic_client_params = {
	/*
	 * Include psk_identity_len in the key so binary identities that share
	 * the same prefix but differ in trailing bytes/length do not alias.
	 */
	.key_len = TQUIC_PSK_KEY_LEN,
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
			tquic_info("rate limit exceeded for client (id_len=%d)\n",
				client->psk_identity_len);
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
	refcount_set(&client->refcnt, 1); /* Hashtable ownership */

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

	/* Clear entire struct including PSK material before freeing */
	kfree_sensitive(client);
}

static inline void tquic_client_put(struct tquic_client *client)
{
	if (client && refcount_dec_and_test(&client->refcnt))
		call_rcu(&client->rcu_head, tquic_client_free_rcu);
}

/**
 * tquic_client_lookup_by_psk - Look up client by PSK identity
 * @identity: PSK identity string
 * @identity_len: Length of identity
 *
 * Called during TLS handshake to find matching client configuration.
 *
 * WARNING: RCU locking contract
 * On success, returns with rcu_read_lock() held -- the caller MUST call
 * rcu_read_unlock() when it is done with the returned pointer.  Failing
 * to release the RCU read lock will stall RCU grace periods and can lead
 * to unbounded memory growth or soft-lockups.
 * On failure (NULL return), no RCU lock is held.
 *
 * Returns: Client pointer (RCU read lock held) or NULL if not found
 */
struct tquic_client *tquic_client_lookup_by_psk(const char *identity,
						size_t identity_len)
{
	struct tquic_client *client;
	u8 lookup_key[TQUIC_PSK_KEY_LEN] = { 0 };

	if (!identity || identity_len == 0 ||
	    identity_len > TQUIC_MAX_PSK_IDENTITY_LEN)
		return NULL;

	if (!READ_ONCE(tquic_client_table_initialized))
		return NULL;

	/* Prepare padded key for lookup */
	memcpy(lookup_key, identity, identity_len);
	lookup_key[TQUIC_MAX_PSK_IDENTITY_LEN] = (u8)identity_len;

	rcu_read_lock();
	client = rhashtable_lookup(&tquic_client_table, lookup_key,
				   tquic_client_params);
	if (!client)
		rcu_read_unlock();

	/* If client is found, rcu_read_lock remains held; caller must unlock */
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
		kfree_sensitive(client);
		return -ENODEV;
	}

	ret = rhashtable_insert_fast(&tquic_client_table, &client->node,
				     tquic_client_params);
	mutex_unlock(&tquic_client_mutex);

	if (ret) {
		kfree_sensitive(client);
		return ret;
	}

	tquic_dbg("registered client '%.*s'\n",
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
	u8 lookup_key[TQUIC_PSK_KEY_LEN] = { 0 };
	int ret;

	if (!identity || identity_len == 0 ||
	    identity_len > TQUIC_MAX_PSK_IDENTITY_LEN)
		return -EINVAL;

	memcpy(lookup_key, identity, identity_len);
	lookup_key[TQUIC_MAX_PSK_IDENTITY_LEN] = (u8)identity_len;

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
		/*
		 * Drop hashtable ownership. If active connections still hold
		 * references, free is deferred until the last unbind.
		 */
		tquic_client_put(client);
		tquic_dbg("unregistered client '%.*s'\n",
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

	/*
	 * Take a persistent ref for connection lifetime. This prevents
	 * unregister from freeing the client while conn->client points to it.
	 */
	if (!refcount_inc_not_zero(&client->refcnt))
		return -ENOENT;

	/* Increment before publishing pointer to pair with unbind decrement. */
	atomic_inc(&client->connection_count);

	/* Bind once per connection to prevent ref leaks/double counting */
	if (cmpxchg(&conn->client, NULL, client) != NULL) {
		atomic_dec(&client->connection_count);
		tquic_client_put(client);
		return -EALREADY;
	}

	tquic_dbg("bound connection to client (id_len=%d, count=%d)\n",
		 client->psk_identity_len,
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

	/* Clear pointer before dropping the last ref to avoid stale reads. */
	client = xchg(&conn->client, NULL);
	if (!client)
		return;

	/* Decrement connection count */
	atomic_dec(&client->connection_count);

	tquic_dbg("unbound connection from client (id_len=%d, count=%d)\n",
		 client->psk_identity_len,
		 atomic_read(&client->connection_count));

	tquic_client_put(client);
}
EXPORT_SYMBOL_GPL(tquic_server_unbind_client);

u32 tquic_server_conn_session_ttl(struct tquic_connection *conn,
				  u32 default_ttl_ms)
{
	struct tquic_client *client;
	u32 ttl_ms;

	if (!conn)
		return default_ttl_ms;

	/*
	 * Hold RCU read lock around the pointer dereference so that
	 * a concurrent tquic_server_unbind_client + call_rcu cannot
	 * free the client before we take a persistent reference.
	 */
	rcu_read_lock();
	client = READ_ONCE(conn->client);
	if (!client) {
		rcu_read_unlock();
		return default_ttl_ms;
	}

	if (!refcount_inc_not_zero(&client->refcnt)) {
		rcu_read_unlock();
		return default_ttl_ms;
	}
	rcu_read_unlock();

	ttl_ms = READ_ONCE(client->session_ttl);
	if (!ttl_ms)
		ttl_ms = default_ttl_ms;

	tquic_client_put(client);
	return ttl_ms;
}
EXPORT_SYMBOL_GPL(tquic_server_conn_session_ttl);

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
	rcu_read_unlock();
	return 0;
}
EXPORT_SYMBOL_GPL(tquic_server_get_client_psk);

int tquic_client_copy_psk(const struct tquic_client *client, u8 *psk)
{
	if (!client || !psk)
		return -EINVAL;

	memcpy(psk, client->psk, 32);
	return 0;
}
EXPORT_SYMBOL_GPL(tquic_client_copy_psk);

/**
 * tquic_client_set_rate_limit - Set connection rate limit for client
 * @identity: PSK identity string
 * @identity_len: Length of identity
 * @rate_limit: Max connections per second (0 = use default)
 *
 * Returns: 0 on success, negative errno on failure
 */
static int tquic_client_set_rate_limit(const char *identity,
				       size_t identity_len, u32 rate_limit)
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

	rcu_read_unlock();
	return 0;
}

/**
 * tquic_client_set_session_ttl - Set session TTL for client
 * @identity: PSK identity string
 * @identity_len: Length of identity
 * @ttl_ms: Session TTL in milliseconds (0 = use default)
 *
 * Returns: 0 on success, negative errno on failure
 */
static int tquic_client_set_session_ttl(const char *identity,
					size_t identity_len, u32 ttl_ms)
{
	struct tquic_client *client;

	client = tquic_client_lookup_by_psk(identity, identity_len);
	if (!client)
		return -ENOENT;

	if (ttl_ms == 0)
		ttl_ms = TQUIC_DEFAULT_SESSION_TTL_MS;

	client->session_ttl = ttl_ms;
	rcu_read_unlock();
	return 0;
}

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
static int tquic_client_get_stats(const char *identity, size_t identity_len,
				  int *conn_count, u64 *tx_bytes,
				  u64 *rx_bytes)
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

	rcu_read_unlock();
	return 0;
}

/*
 * =============================================================================
 * SERVER ACCEPT PATH
 * =============================================================================
 */

/**
 * tquic_server_check_retry_required - Check if Retry packet should be sent
 * @sk: Server socket
 * @skb: Initial packet
 * @client_addr: Client source address
 * @version: QUIC version from packet
 * @dcid: Destination CID from packet
 * @dcid_len: DCID length
 * @scid: Source CID from packet
 * @scid_len: SCID length
 * @token: Token from Initial packet (NULL if none)
 * @token_len: Token length
 *
 * Called when a new Initial packet arrives without a known connection.
 * If Retry is enabled via sysctl and no valid token is present, sends
 * a Retry packet to validate the client address.
 *
 * Per RFC 9000 Section 8.1: Retry is used to force clients to demonstrate
 * they can receive packets at their claimed source address, mitigating
 * amplification attacks.
 *
 * Returns:
 *   0: Continue with handshake (no Retry needed or valid token present)
 *   1: Retry packet sent, caller should drop the Initial packet
 *   negative errno on error
 */
static int tquic_server_check_retry_required(struct sock *sk,
					     struct sk_buff *skb,
					     struct sockaddr_storage *client_addr,
					     u32 version,
					     const u8 *dcid, u8 dcid_len,
					     const u8 *scid, u8 scid_len,
					     const u8 *token, size_t token_len)
{
	struct net *net;
	int ret;

	if (!sk)
		return -EINVAL;

	net = sock_net(sk);

	/* Check if Retry is required via sysctl */
	if (!tquic_retry_is_required(net))
		return 0;  /* Retry not required, continue with handshake */

	/*
	 * If the client included a token, validate it.
	 * A valid token proves the client already completed a Retry exchange
	 * for this connection attempt.
	 */
	if (token && token_len > 0) {
		u8 odcid[TQUIC_MAX_CID_LEN];
		u8 odcid_len;

		/*
		 * Validate the Retry token. This checks:
		 * - Token decryption succeeds (proves server generated it)
		 * - Client IP matches encoded IP (proves address ownership)
		 * - Timestamp is within validity window (prevents replay)
		 */
		ret = tquic_retry_token_validate(NULL, /* use global state */
						 token, token_len,
						 client_addr,
						 odcid, &odcid_len);
		if (ret == 0) {
			/* Valid token - continue with handshake */
			tquic_dbg("valid Retry token, proceeding with handshake\n");
			return 0;
		}

		/*
		 * Token validation failed. This could be:
		 * - Token from different server (decryption fails)
		 * - Client IP changed (address mismatch)
		 * - Token expired (timestamp too old)
		 * - Malformed token
		 *
		 * Send a new Retry packet to validate the current address.
		 */
		tquic_dbg("Retry token validation failed: %d\n", ret);
	}

	/*
	 * No valid token - send Retry packet.
	 *
	 * Per RFC 9000 Section 8.1.2:
	 * "A server MUST NOT send more than one Retry packet in response
	 * to a single UDP datagram."
	 *
	 * The Retry packet includes:
	 * - New server-chosen SCID
	 * - Retry Token encoding: ODCID, client IP, timestamp
	 * - Retry Integrity Tag (computed with fixed key from RFC 9001)
	 */
	ret = tquic_retry_send(sk, client_addr, version,
			       dcid, dcid_len, scid, scid_len);
	if (ret) {
		tquic_dbg("failed to send Retry packet: %d\n", ret);
		return ret;
	}

	/* Update statistics */
	TQUIC_INC_STATS(net, TQUIC_MIB_RETRYPACKETSTX);

	tquic_dbg("sent Retry packet to client\n");

	return 1;  /* Retry sent, drop the Initial packet */
}

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
		WRITE_ONCE(tquic_client_table_initialized, true);
	mutex_unlock(&tquic_client_mutex);

	if (ret) {
		tquic_err("failed to initialize client table: %d\n", ret);
		return ret;
	}

	tquic_info("server subsystem initialized\n");
	return 0;
}

/**
 * tquic_server_exit - Cleanup server subsystem
 *
 * Walks the rhashtable to clear sensitive material from all remaining
 * client entries before destroying the table.
 */
void tquic_server_exit(void)
{
	struct rhashtable_iter iter;
	struct tquic_client *client;

	mutex_lock(&tquic_client_mutex);
	if (READ_ONCE(tquic_client_table_initialized)) {
		/*
		 * Block new lookups before teardown, then wait for in-flight
		 * RCU readers to drain.
		 */
		WRITE_ONCE(tquic_client_table_initialized, false);
		synchronize_rcu();

		/* Walk the table and scrub all client entries */
		rhashtable_walk_enter(&tquic_client_table, &iter);
		rhashtable_walk_start(&iter);

		while ((client = rhashtable_walk_next(&iter)) != NULL) {
			if (IS_ERR(client))
				continue;
			/* Remove entry from table */
			rhashtable_remove_fast(&tquic_client_table,
					       &client->node,
					       tquic_client_params);
			/* Drop table ref; connection refs keep object alive. */
			tquic_client_put(client);
		}

		rhashtable_walk_stop(&iter);
		rhashtable_walk_exit(&iter);

		rhashtable_destroy(&tquic_client_table);
	}
	mutex_unlock(&tquic_client_mutex);

	tquic_info("server subsystem exited\n");
}
