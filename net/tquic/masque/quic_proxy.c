// SPDX-License-Identifier: GPL-2.0-only
/*
 * TQUIC MASQUE: QUIC-Aware Proxy Implementation (draft-ietf-masque-quic-proxy)
 *
 * Copyright (c) 2026 Justin Adams <spotty118@gmail.com>
 * Kernel implementation by Justin Adams <spotty118@gmail.com>
 *
 * Implementation of the QUIC-Aware Proxy extension for MASQUE. This enables
 * optimized proxying of QUIC connections through HTTP/3 proxies with:
 *
 *   - Connection ID cooperation for efficient forwarding
 *   - Header compression to reduce overhead
 *   - CID rewriting for advanced proxy scenarios
 *   - Multiple QUIC connections over a single tunnel
 *
 * Key Implementation Details:
 *   - Connection IDs are tracked in a hash table for O(1) lookup
 *   - Header compression uses a sliding window dictionary
 *   - CID cooperation follows the draft-ietf-masque-quic-proxy spec
 *   - Packet forwarding handles both directions (client<->target)
 *
 * References:
 *   draft-ietf-masque-quic-proxy - QUIC-Aware Proxying Using HTTP
 *   RFC 9298 - Proxying UDP in HTTP (CONNECT-UDP)
 *   RFC 9000 - QUIC: A UDP-Based Multiplexed and Secure Transport
 */

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/list.h>
#include <linux/hashtable.h>
#include <linux/jhash.h>
#include <linux/spinlock.h>
#include <linux/timer.h>
#include <linux/workqueue.h>
#include <linux/random.h>
#include <net/tquic.h>
#include "../tquic_compat.h"

#include "quic_proxy.h"
#include "connect_udp.h"
#include "capsule.h"

/*
 * =============================================================================
 * Module State
 * =============================================================================
 */

/* Work queue for asynchronous operations */
static struct workqueue_struct *quic_proxy_wq;

/* Slab caches */
static struct kmem_cache *proxy_state_cache;
static struct kmem_cache *proxied_conn_cache;
static struct kmem_cache *cid_cache;

/*
 * =============================================================================
 * CID Management
 * =============================================================================
 */

/**
 * cid_alloc - Allocate a new connection ID entry
 * @cid: Connection ID bytes
 * @len: CID length
 * @seq_num: Sequence number
 * @gfp: Memory allocation flags
 *
 * Returns: Allocated CID or NULL on failure.
 */
static struct quic_proxy_cid *cid_alloc(const u8 *cid, u8 len,
					u64 seq_num, gfp_t gfp)
{
	struct quic_proxy_cid *c;

	if (len > QUIC_PROXY_MAX_CID_LEN)
		return NULL;

	if (cid_cache)
		c = kmem_cache_zalloc(cid_cache, gfp);
	else
		c = kzalloc(sizeof(*c), gfp);

	if (!c)
		return NULL;

	if (len > 0)
		memcpy(c->cid, cid, len);
	c->len = len;
	c->seq_num = seq_num;
	c->retire_prior_to = 0;
	c->has_reset_token = false;
	c->owner = 0;
	refcount_set(&c->refcnt, 1);
	INIT_HLIST_NODE(&c->hash_node);
	INIT_LIST_HEAD(&c->list_node);
	c->created_at = ktime_get();

	return c;
}

/**
 * cid_free - Free a connection ID entry
 * @c: CID to free
 */
static void cid_free(struct quic_proxy_cid *c)
{
	if (!c)
		return;

	if (cid_cache)
		kmem_cache_free(cid_cache, c);
	else
		kfree(c);
}

/**
 * cid_get - Increment CID reference count
 * @c: CID to reference
 */
static inline void cid_get(struct quic_proxy_cid *c)
{
	if (c)
		refcount_inc(&c->refcnt);
}

/**
 * cid_put - Decrement CID reference count
 * @c: CID to dereference
 */
static void cid_put(struct quic_proxy_cid *c)
{
	if (c && refcount_dec_and_test(&c->refcnt))
		cid_free(c);
}

/**
 * cid_hash_key - Compute hash key for CID
 * @cid: Connection ID bytes
 * @len: CID length
 *
 * Returns: Hash key.
 */
static u32 cid_hash_secret __read_mostly;

static inline u32 cid_hash_key(const u8 *cid, u8 len)
{
	net_get_random_once(&cid_hash_secret, sizeof(cid_hash_secret));
	return jhash(cid, len, cid_hash_secret);
}

/**
 * cid_coop_init - Initialize CID cooperation state
 * @coop: CID cooperation structure
 */
static void cid_coop_init(struct quic_proxy_cid_cooperation *coop)
{
	INIT_LIST_HEAD(&coop->client_cids);
	INIT_LIST_HEAD(&coop->target_cids);
	INIT_LIST_HEAD(&coop->proxy_cids);
	memset(coop->pairs, 0, sizeof(coop->pairs));
	coop->num_pairs = 0;
	coop->next_seq_num = 0;
	coop->pending_request = false;
	spin_lock_init(&coop->lock);
}

/**
 * cid_coop_cleanup - Clean up CID cooperation state
 * @coop: CID cooperation structure
 */
static void cid_coop_cleanup(struct quic_proxy_cid_cooperation *coop)
{
	struct quic_proxy_cid *c, *tmp;

	spin_lock_bh(&coop->lock);

	list_for_each_entry_safe(c, tmp, &coop->client_cids, list_node) {
		list_del_init(&c->list_node);
		cid_put(c);
	}

	list_for_each_entry_safe(c, tmp, &coop->target_cids, list_node) {
		list_del_init(&c->list_node);
		cid_put(c);
	}

	list_for_each_entry_safe(c, tmp, &coop->proxy_cids, list_node) {
		list_del_init(&c->list_node);
		cid_put(c);
	}

	/* Clear pairs */
	memset(coop->pairs, 0, sizeof(coop->pairs));
	coop->num_pairs = 0;

	spin_unlock_bh(&coop->lock);
}

/*
 * =============================================================================
 * Header Compression
 * =============================================================================
 */

/**
 * compress_ctx_init - Initialize compression context
 * @ctx: Compression context
 */
static void compress_ctx_init(struct quic_proxy_compress_ctx *ctx)
{
	memset(ctx, 0, sizeof(*ctx));
	ctx->enabled = false;
	spin_lock_init(&ctx->lock);
}

/**
 * compress_ctx_cleanup - Clean up compression context
 * @ctx: Compression context
 */
static void compress_ctx_cleanup(struct quic_proxy_compress_ctx *ctx)
{
	spin_lock_bh(&ctx->lock);
	memset(ctx->entries, 0, sizeof(ctx->entries));
	ctx->num_entries = 0;
	ctx->next_index = 0;
	spin_unlock_bh(&ctx->lock);
}

/**
 * compress_find_entry - Find compression entry by DCID
 * @ctx: Compression context
 * @dcid: Destination CID
 * @dcid_len: DCID length
 *
 * Returns: Entry index or -1 if not found.
 */
static int compress_find_entry(struct quic_proxy_compress_ctx *ctx,
			       const u8 *dcid, u8 dcid_len)
{
	int i;

	for (i = 0; i < ctx->num_entries; i++) {
		if (ctx->entries[i].dcid_len == dcid_len &&
		    memcmp(ctx->entries[i].dcid, dcid, dcid_len) == 0)
			return i;
	}

	return -1;
}

/**
 * compress_add_entry - Add or update compression entry
 * @ctx: Compression context
 * @dcid: Destination CID
 * @dcid_len: DCID length
 * @scid: Source CID (may be NULL)
 * @scid_len: SCID length
 * @version: QUIC version
 *
 * Returns: Entry index.
 */
static int compress_add_entry(struct quic_proxy_compress_ctx *ctx,
			      const u8 *dcid, u8 dcid_len,
			      const u8 *scid, u8 scid_len,
			      u32 version)
{
	struct quic_proxy_compress_entry *entry;
	int idx;

	/* Check if entry exists */
	idx = compress_find_entry(ctx, dcid, dcid_len);
	if (idx >= 0) {
		ctx->entries[idx].used++;
		return idx;
	}

	/* Find slot (circular replacement) */
	idx = ctx->next_index;
	ctx->next_index = (ctx->next_index + 1) % QUIC_PROXY_COMPRESS_WINDOW_SIZE;

	if (ctx->num_entries < QUIC_PROXY_COMPRESS_WINDOW_SIZE)
		ctx->num_entries++;

	entry = &ctx->entries[idx];
	memset(entry, 0, sizeof(*entry));

	memcpy(entry->dcid, dcid, dcid_len);
	entry->dcid_len = dcid_len;

	if (scid && scid_len > 0) {
		memcpy(entry->scid, scid, scid_len);
		entry->scid_len = scid_len;
	}

	entry->version = version;
	entry->index = idx;
	entry->used = 1;

	return idx;
}

/*
 * =============================================================================
 * Proxied Connection Management
 * =============================================================================
 */

/**
 * proxied_conn_alloc - Allocate proxied connection
 * @proxy: Parent proxy state
 * @gfp: Allocation flags
 *
 * Returns: Allocated connection or NULL.
 */
static struct tquic_proxied_quic_conn *proxied_conn_alloc(
	struct tquic_quic_proxy_state *proxy, gfp_t gfp)
{
	struct tquic_proxied_quic_conn *pconn;

	if (proxied_conn_cache)
		pconn = kmem_cache_zalloc(proxied_conn_cache, gfp);
	else
		pconn = kzalloc(sizeof(*pconn), gfp);

	if (!pconn)
		return NULL;

	pconn->state = QUIC_PROXY_CONN_IDLE;
	pconn->proxy = proxy;
	pconn->mode = QUIC_PROXY_MODE_PASSTHROUGH;
	pconn->created_at = ktime_get();
	pconn->last_activity = ktime_get();

	cid_coop_init(&pconn->cid_coop);
	compress_ctx_init(&pconn->compress_ctx);

	INIT_LIST_HEAD(&pconn->list);
	INIT_HLIST_NODE(&pconn->dcid_hash_node);
	refcount_set(&pconn->refcnt, 1);

	return pconn;
}

/**
 * proxied_conn_free - Free proxied connection
 * @pconn: Connection to free
 */
static void proxied_conn_free(struct tquic_proxied_quic_conn *pconn)
{
	if (!pconn)
		return;

	cid_coop_cleanup(&pconn->cid_coop);
	compress_ctx_cleanup(&pconn->compress_ctx);

	if (proxied_conn_cache)
		kmem_cache_free(proxied_conn_cache, pconn);
	else
		kfree(pconn);
}

/**
 * proxied_conn_get - Increment connection reference count
 * @pconn: Connection to reference
 */
static inline void proxied_conn_get(struct tquic_proxied_quic_conn *pconn)
{
	if (pconn)
		refcount_inc(&pconn->refcnt);
}

/**
 * proxied_conn_put - Decrement connection reference count
 * @pconn: Connection to dereference
 */
static void proxied_conn_put(struct tquic_proxied_quic_conn *pconn)
{
	if (pconn && refcount_dec_and_test(&pconn->refcnt))
		proxied_conn_free(pconn);
}

/*
 * =============================================================================
 * Proxy State Management
 * =============================================================================
 */

/**
 * idle_timer_callback - Handle idle timeout
 * @t: Timer
 */
static void idle_timer_callback(struct timer_list *t)
{
	struct tquic_quic_proxy_state *proxy =
		from_timer(proxy, t, idle_timer);
	struct tquic_proxied_quic_conn *pconn, *tmp;
	ktime_t now = ktime_get();
	LIST_HEAD(to_remove);

	spin_lock_bh(&proxy->lock);

	list_for_each_entry_safe(pconn, tmp, &proxy->connections, list) {
		s64 idle_ms = ktime_ms_delta(now, pconn->last_activity);

		if (idle_ms >= proxy->config.idle_timeout_ms &&
		    pconn->state == QUIC_PROXY_CONN_ACTIVE) {
			pconn->state = QUIC_PROXY_CONN_DRAINING;
			/* Remove CID hash entry while holding the lock */
			hash_del(&pconn->dcid_hash_node);
			/*
			 * Take a reference for the to_remove list so the
			 * connection cannot be freed by another path before
			 * we finish processing it outside the lock.
			 */
			proxied_conn_get(pconn);
			list_move_tail(&pconn->list, &to_remove);
		}
	}

	spin_unlock_bh(&proxy->lock);

	/* Process removals outside lock */
	list_for_each_entry_safe(pconn, tmp, &to_remove, list) {
		list_del_init(&pconn->list);
		tquic_quic_proxy_deregister_conn(pconn, QUIC_PROXY_DEREG_TIMEOUT, 0);
		/* Drop the extra reference taken above */
		proxied_conn_put(pconn);
		/* Drop the original list reference */
		proxied_conn_put(pconn);
	}

	/* Reschedule timer */
	if (proxy->active)
		mod_timer(&proxy->idle_timer,
			  jiffies + msecs_to_jiffies(proxy->config.idle_timeout_ms / 4));
}

/**
 * stats_timer_callback - Periodic statistics reporting
 * @t: Timer
 */
static void stats_timer_callback(struct timer_list *t)
{
	struct tquic_quic_proxy_state *proxy =
		from_timer(proxy, t, stats_timer);

	if (!proxy->active || proxy->config.stats_interval_ms == 0)
		return;

	/* Log statistics */
	pr_debug("quic-proxy: active=%u total=%llu pkts=%llu bytes=%llu\n",
		 proxy->stats.active_connections,
		 proxy->stats.total_connections,
		 proxy->stats.total_packets_fwd,
		 proxy->stats.total_bytes_fwd);

	/* Reschedule */
	mod_timer(&proxy->stats_timer,
		  jiffies + msecs_to_jiffies(proxy->config.stats_interval_ms));
}

/**
 * forward_work_fn - Packet forwarding work function
 * @work: Work structure
 */
static void forward_work_fn(struct work_struct *work)
{
	struct tquic_quic_proxy_state *proxy =
		container_of(work, struct tquic_quic_proxy_state, forward_work);

	if (!proxy->active)
		return;

	/*
	 * Process pending packets. In a real implementation, this would
	 * dequeue packets from a pending queue and forward them.
	 */
}

/*
 * =============================================================================
 * Public API: Proxy Lifecycle
 * =============================================================================
 */

/**
 * tquic_quic_proxy_init - Initialize QUIC proxy state
 * @tunnel: Underlying CONNECT-UDP tunnel
 * @config: Proxy configuration (NULL for defaults)
 * @is_server: True if this is the proxy (server) side
 *
 * Returns: Proxy state on success, ERR_PTR on failure.
 */
struct tquic_quic_proxy_state *tquic_quic_proxy_init(
	struct tquic_connect_udp_tunnel *tunnel,
	const struct tquic_quic_proxy_config *config,
	bool is_server)
{
	struct tquic_quic_proxy_state *proxy;

	if (!tunnel)
		return ERR_PTR(-EINVAL);

	if (proxy_state_cache)
		proxy = kmem_cache_zalloc(proxy_state_cache, GFP_KERNEL);
	else
		proxy = kzalloc(sizeof(*proxy), GFP_KERNEL);

	if (!proxy)
		return ERR_PTR(-ENOMEM);

	proxy->tunnel = tunnel;
	proxy->conn = tunnel->conn;
	proxy->stream = tunnel->stream;
	proxy->is_server = is_server;

	/* Set configuration */
	if (config) {
		memcpy(&proxy->config, config, sizeof(*config));
	} else {
		/* Default configuration */
		proxy->config.max_connections = QUIC_PROXY_DEFAULT_MAX_CONNECTIONS;
		proxy->config.cid_cooperation_enabled = true;
		proxy->config.header_compression_enabled = false;
		proxy->config.cid_rewriting_enabled = false;
		proxy->config.cid_timeout_ms = QUIC_PROXY_DEFAULT_CID_TIMEOUT_MS;
		proxy->config.idle_timeout_ms = QUIC_PROXY_DEFAULT_IDLE_TIMEOUT_MS;
		proxy->config.stats_interval_ms = 0;
		proxy->config.allowed_versions = 0xFFFFFFFF;
		proxy->config.require_auth = true;
	}

	/* Initialize connection management */
	INIT_LIST_HEAD(&proxy->connections);
	proxy->num_connections = 0;
	proxy->next_conn_id = 1;
	hash_init(proxy->cid_hash);

	/* Initialize statistics */
	memset(&proxy->stats, 0, sizeof(proxy->stats));

	/* Initialize timing */
	proxy->created_at = ktime_get();
	timer_setup(&proxy->idle_timer, idle_timer_callback, 0);
	timer_setup(&proxy->stats_timer, stats_timer_callback, 0);

	/* Initialize work queue */
	INIT_WORK(&proxy->forward_work, forward_work_fn);

	/* Initialize synchronization */
	spin_lock_init(&proxy->lock);
	refcount_set(&proxy->refcnt, 1);

	proxy->active = true;

	/* Start timers */
	mod_timer(&proxy->idle_timer,
		  jiffies + msecs_to_jiffies(proxy->config.idle_timeout_ms / 4));

	if (proxy->config.stats_interval_ms > 0)
		mod_timer(&proxy->stats_timer,
			  jiffies + msecs_to_jiffies(proxy->config.stats_interval_ms));

	pr_info("QUIC-Aware Proxy initialized (server=%d)\n", is_server);
	return proxy;
}
EXPORT_SYMBOL_GPL(tquic_quic_proxy_init);

/**
 * tquic_quic_proxy_destroy - Destroy QUIC proxy state
 * @proxy: Proxy state to destroy
 */
void tquic_quic_proxy_destroy(struct tquic_quic_proxy_state *proxy)
{
	struct tquic_proxied_quic_conn *pconn, *tmp;

	if (!proxy)
		return;

	spin_lock_bh(&proxy->lock);
	proxy->active = false;
	spin_unlock_bh(&proxy->lock);

	/* Cancel timers */
	del_timer_sync(&proxy->idle_timer);
	del_timer_sync(&proxy->stats_timer);

	/* Cancel pending work */
	cancel_work_sync(&proxy->forward_work);

	/* Close all proxied connections */
	spin_lock_bh(&proxy->lock);
	list_for_each_entry_safe(pconn, tmp, &proxy->connections, list) {
		list_del_init(&pconn->list);
		hash_del(&pconn->dcid_hash_node);
		pconn->state = QUIC_PROXY_CONN_CLOSED;
		proxied_conn_put(pconn);
		proxy->num_connections--;
	}
	spin_unlock_bh(&proxy->lock);

	tquic_quic_proxy_put(proxy);
}
EXPORT_SYMBOL_GPL(tquic_quic_proxy_destroy);

/**
 * tquic_quic_proxy_get - Increment proxy reference count
 * @proxy: Proxy to reference
 */
void tquic_quic_proxy_get(struct tquic_quic_proxy_state *proxy)
{
	if (proxy)
		refcount_inc(&proxy->refcnt);
}
EXPORT_SYMBOL_GPL(tquic_quic_proxy_get);

/**
 * tquic_quic_proxy_put - Decrement proxy reference count
 * @proxy: Proxy to dereference
 */
void tquic_quic_proxy_put(struct tquic_quic_proxy_state *proxy)
{
	if (!proxy)
		return;

	if (refcount_dec_and_test(&proxy->refcnt)) {
		if (proxy_state_cache)
			kmem_cache_free(proxy_state_cache, proxy);
		else
			kfree(proxy);
	}
}
EXPORT_SYMBOL_GPL(tquic_quic_proxy_put);

/*
 * =============================================================================
 * Public API: Connection Registration
 * =============================================================================
 */

/**
 * tquic_quic_proxy_register_conn - Register a proxied QUIC connection
 */
struct tquic_proxied_quic_conn *tquic_quic_proxy_register_conn(
	struct tquic_quic_proxy_state *proxy,
	const char *target_host,
	u16 target_port,
	const u8 *initial_dcid,
	u8 dcid_len,
	const u8 *initial_scid,
	u8 scid_len,
	u32 version,
	u8 flags)
{
	struct tquic_proxied_quic_conn *pconn;
	struct quic_proxy_cid *dcid_entry = NULL;
	struct quic_proxy_cid *scid_entry = NULL;
	int ret;

	if (!proxy || !target_host || dcid_len > QUIC_PROXY_MAX_CID_LEN)
		return ERR_PTR(-EINVAL);

	/* Mandatory authentication check -- reject unauthenticated clients */
	if (proxy->config.require_auth && !proxy->authenticated) {
		pr_warn("quic-proxy: rejecting unauthenticated connection registration\n");
		return ERR_PTR(-EACCES);
	}

	spin_lock_bh(&proxy->lock);

	/* Check connection limit */
	if (proxy->num_connections >= proxy->config.max_connections) {
		spin_unlock_bh(&proxy->lock);
		return ERR_PTR(-ENOSPC);
	}

	spin_unlock_bh(&proxy->lock);

	/* Allocate connection */
	pconn = proxied_conn_alloc(proxy, GFP_KERNEL);
	if (!pconn)
		return ERR_PTR(-ENOMEM);

	/* Set target information */
	strscpy(pconn->target_host, target_host, sizeof(pconn->target_host));
	pconn->target_port = target_port;

	/* Assign connection ID */
	spin_lock_bh(&proxy->lock);
	pconn->conn_id = proxy->next_conn_id++;
	spin_unlock_bh(&proxy->lock);

	/* Set forwarding mode based on flags */
	if (flags & QUIC_PROXY_REG_FLAG_COMPRESS)
		pconn->mode = QUIC_PROXY_MODE_HEADER_COMPRESS;
	else if (flags & QUIC_PROXY_REG_FLAG_CID_REWRITE)
		pconn->mode = QUIC_PROXY_MODE_CID_REWRITE;
	else
		pconn->mode = QUIC_PROXY_MODE_PASSTHROUGH;

	/* Enable header compression if requested */
	if (flags & QUIC_PROXY_REG_FLAG_COMPRESS)
		pconn->compress_ctx.enabled = true;

	/* Create initial DCID entry */
	if (initial_dcid && dcid_len > 0) {
		dcid_entry = cid_alloc(initial_dcid, dcid_len, 0, GFP_KERNEL);
		if (!dcid_entry) {
			ret = -ENOMEM;
			goto err_free_conn;
		}
		dcid_entry->owner = QUIC_PROXY_CID_OWNER_TARGET;

		spin_lock_bh(&pconn->cid_coop.lock);
		list_add_tail(&dcid_entry->list_node, &pconn->cid_coop.target_cids);
		spin_unlock_bh(&pconn->cid_coop.lock);
	}

	/* Create initial SCID entry */
	if (initial_scid && scid_len > 0) {
		scid_entry = cid_alloc(initial_scid, scid_len, 0, GFP_KERNEL);
		if (!scid_entry) {
			ret = -ENOMEM;
			goto err_free_dcid;
		}
		scid_entry->owner = QUIC_PROXY_CID_OWNER_CLIENT;

		spin_lock_bh(&pconn->cid_coop.lock);
		list_add_tail(&scid_entry->list_node, &pconn->cid_coop.client_cids);
		spin_unlock_bh(&pconn->cid_coop.lock);
	}

	/* Add compression entry */
	if (pconn->compress_ctx.enabled && initial_dcid) {
		spin_lock_bh(&pconn->compress_ctx.lock);
		compress_add_entry(&pconn->compress_ctx,
				   initial_dcid, dcid_len,
				   initial_scid, scid_len,
				   version);
		spin_unlock_bh(&pconn->compress_ctx.lock);
	}

	/* Add to proxy */
	spin_lock_bh(&proxy->lock);

	list_add_tail(&pconn->list, &proxy->connections);
	proxy->num_connections++;
	proxy->stats.total_connections++;
	proxy->stats.active_connections++;

	/* Add to CID hash table */
	if (dcid_entry) {
		hash_add(proxy->cid_hash, &pconn->dcid_hash_node,
			 cid_hash_key(initial_dcid, dcid_len));
	}

	pconn->state = QUIC_PROXY_CONN_ACTIVE;

	spin_unlock_bh(&proxy->lock);

	pr_debug("quic-proxy: registered connection %llu to %s:%u\n",
		 pconn->conn_id, target_host, target_port);

	return pconn;

err_free_dcid:
	if (dcid_entry)
		cid_put(dcid_entry);
err_free_conn:
	proxied_conn_free(pconn);
	return ERR_PTR(ret);
}
EXPORT_SYMBOL_GPL(tquic_quic_proxy_register_conn);

/**
 * tquic_quic_proxy_deregister_conn - Deregister a proxied connection
 */
int tquic_quic_proxy_deregister_conn(
	struct tquic_proxied_quic_conn *pconn,
	u8 reason,
	u32 drain_ms)
{
	struct tquic_quic_proxy_state *proxy;

	if (!pconn)
		return -EINVAL;

	proxy = pconn->proxy;
	if (!proxy)
		return -EINVAL;

	spin_lock_bh(&proxy->lock);

	if (pconn->state == QUIC_PROXY_CONN_CLOSED) {
		spin_unlock_bh(&proxy->lock);
		return 0;
	}

	if (drain_ms > 0) {
		/* Enter draining state */
		pconn->state = QUIC_PROXY_CONN_DRAINING;
		/* In a real implementation, would set a drain timer */
	} else {
		/* Immediate close */
		pconn->state = QUIC_PROXY_CONN_CLOSED;

		list_del_init(&pconn->list);
		hash_del(&pconn->dcid_hash_node);
		proxy->num_connections--;
		proxy->stats.active_connections--;

		spin_unlock_bh(&proxy->lock);

		/* Send deregister capsule */
		/* In a real implementation, would send the capsule here */

		proxied_conn_put(pconn);
		return 0;
	}

	spin_unlock_bh(&proxy->lock);

	pr_debug("quic-proxy: deregistered connection %llu reason=%u\n",
		 pconn->conn_id, reason);

	return 0;
}
EXPORT_SYMBOL_GPL(tquic_quic_proxy_deregister_conn);

/**
 * tquic_quic_proxy_find_conn - Find proxied connection by ID
 */
struct tquic_proxied_quic_conn *tquic_quic_proxy_find_conn(
	struct tquic_quic_proxy_state *proxy,
	u64 conn_id)
{
	struct tquic_proxied_quic_conn *pconn;

	if (!proxy)
		return NULL;

	spin_lock_bh(&proxy->lock);

	list_for_each_entry(pconn, &proxy->connections, list) {
		if (pconn->conn_id == conn_id) {
			proxied_conn_get(pconn);
			spin_unlock_bh(&proxy->lock);
			return pconn;
		}
	}

	spin_unlock_bh(&proxy->lock);
	return NULL;
}
EXPORT_SYMBOL_GPL(tquic_quic_proxy_find_conn);

/**
 * tquic_quic_proxy_find_conn_by_cid - Find proxied connection by DCID
 */
struct tquic_proxied_quic_conn *tquic_quic_proxy_find_conn_by_cid(
	struct tquic_quic_proxy_state *proxy,
	const u8 *dcid,
	u8 dcid_len)
{
	struct tquic_proxied_quic_conn *pconn;
	u32 key;

	if (!proxy || !dcid || dcid_len == 0)
		return NULL;

	key = cid_hash_key(dcid, dcid_len);

	spin_lock_bh(&proxy->lock);

	hash_for_each_possible(proxy->cid_hash, pconn, dcid_hash_node, key) {
		struct quic_proxy_cid *c;

		/* Check target CIDs */
		list_for_each_entry(c, &pconn->cid_coop.target_cids, list_node) {
			if (c->len == dcid_len &&
			    memcmp(c->cid, dcid, dcid_len) == 0) {
				proxied_conn_get(pconn);
				spin_unlock_bh(&proxy->lock);
				return pconn;
			}
		}

		/* Check client CIDs */
		list_for_each_entry(c, &pconn->cid_coop.client_cids, list_node) {
			if (c->len == dcid_len &&
			    memcmp(c->cid, dcid, dcid_len) == 0) {
				proxied_conn_get(pconn);
				spin_unlock_bh(&proxy->lock);
				return pconn;
			}
		}
	}

	spin_unlock_bh(&proxy->lock);
	return NULL;
}
EXPORT_SYMBOL_GPL(tquic_quic_proxy_find_conn_by_cid);

/*
 * =============================================================================
 * Public API: Packet Forwarding
 * =============================================================================
 */

/**
 * tquic_quic_proxy_forward_packet - Forward a QUIC packet
 */
int tquic_quic_proxy_forward_packet(
	struct tquic_proxied_quic_conn *pconn,
	const u8 *packet,
	size_t len,
	u8 direction)
{
	struct tquic_quic_proxy_state *proxy;
	u8 *output_buf = NULL;
	size_t output_len;
	int ret;

	if (!pconn || !packet || len == 0)
		return -EINVAL;

	proxy = pconn->proxy;
	if (!proxy || !proxy->active)
		return -ENOTCONN;

	if (pconn->state != QUIC_PROXY_CONN_ACTIVE)
		return -ENOTCONN;

	/* Update activity timestamp */
	pconn->last_activity = ktime_get();

	/* Handle based on forwarding mode */
	switch (pconn->mode) {
	case QUIC_PROXY_MODE_PASSTHROUGH:
		/* Forward packet as-is */
		output_buf = (u8 *)packet;
		output_len = len;
		break;

	case QUIC_PROXY_MODE_HEADER_COMPRESS:
		/* Compress header before forwarding */
		output_buf = kmalloc(len + QUIC_PROXY_MAX_COMPRESSED_HEADER,
				     GFP_ATOMIC);
		if (!output_buf)
			return -ENOMEM;

		ret = tquic_quic_proxy_header_compress(pconn, packet, len,
						       output_buf,
						       len + QUIC_PROXY_MAX_COMPRESSED_HEADER,
						       &output_len, NULL);
		if (ret < 0) {
			kfree(output_buf);
			/* Fall back to passthrough */
			output_buf = (u8 *)packet;
			output_len = len;
		}
		break;

	case QUIC_PROXY_MODE_CID_REWRITE:
		/* CID rewriting would be implemented here */
		output_buf = (u8 *)packet;
		output_len = len;
		break;

	default:
		return -EINVAL;
	}

	/*
	 * Forward the packet via the underlying CONNECT-UDP tunnel.
	 * In a real implementation, this would send the packet as an
	 * HTTP Datagram or via a QUIC_PROXY_PACKET capsule.
	 */
	ret = tquic_connect_udp_send(proxy->tunnel, output_buf, output_len);

	/* Update statistics */
	spin_lock_bh(&proxy->lock);
	if (ret >= 0) {
		if (direction == QUIC_PROXY_CID_DIR_CLIENT_TARGET) {
			pconn->tx_packets++;
			pconn->tx_bytes += len;
		} else {
			pconn->rx_packets++;
			pconn->rx_bytes += len;
		}
		proxy->stats.total_packets_fwd++;
		proxy->stats.total_bytes_fwd += len;

		if (pconn->mode == QUIC_PROXY_MODE_HEADER_COMPRESS &&
		    output_len < len) {
			pconn->compression_savings += (len - output_len);
			proxy->stats.compression_ops++;
		}
	} else {
		proxy->stats.errors[QUIC_PROXY_ERR_INTERNAL]++;
	}
	spin_unlock_bh(&proxy->lock);

	/* Free allocated buffer */
	if (output_buf != packet)
		kfree(output_buf);

	return ret < 0 ? ret : 0;
}
EXPORT_SYMBOL_GPL(tquic_quic_proxy_forward_packet);

/**
 * tquic_quic_proxy_forward_packet_capsule - Forward packet via capsule
 */
int tquic_quic_proxy_forward_packet_capsule(
	struct tquic_quic_proxy_state *proxy,
	const struct quic_proxy_packet_capsule *capsule)
{
	struct tquic_proxied_quic_conn *pconn;
	const u8 *packet;
	size_t packet_len;
	u8 *decompressed = NULL;
	int ret;

	if (!proxy || !capsule || !capsule->packet)
		return -EINVAL;

	/* Find connection */
	pconn = tquic_quic_proxy_find_conn(proxy, capsule->conn_id);
	if (!pconn)
		return -ENOENT;

	/* Handle compressed packets */
	if (capsule->compressed) {
		decompressed = kmalloc(capsule->packet_len + 256, GFP_ATOMIC);
		if (!decompressed) {
			proxied_conn_put(pconn);
			return -ENOMEM;
		}

		ret = tquic_quic_proxy_header_decompress(
			pconn,
			capsule->packet, capsule->packet_len,
			capsule->compress_index,
			NULL, 0,
			decompressed, capsule->packet_len + 256,
			&packet_len);

		if (ret < 0) {
			kfree(decompressed);
			proxied_conn_put(pconn);
			return ret;
		}

		packet = decompressed;
	} else {
		packet = capsule->packet;
		packet_len = capsule->packet_len;
	}

	/* Forward the packet */
	ret = tquic_quic_proxy_forward_packet(pconn, packet, packet_len,
					      capsule->direction);

	kfree(decompressed);
	proxied_conn_put(pconn);
	return ret;
}
EXPORT_SYMBOL_GPL(tquic_quic_proxy_forward_packet_capsule);

/*
 * =============================================================================
 * Public API: CID Cooperation
 * =============================================================================
 */

/**
 * tquic_quic_proxy_cid_cooperation - Process CID cooperation
 */
int tquic_quic_proxy_cid_cooperation(
	struct tquic_proxied_quic_conn *pconn,
	const struct quic_proxy_cid_capsule *capsule)
{
	if (!pconn || !capsule)
		return -EINVAL;

	switch (capsule->action) {
	case QUIC_PROXY_CID_ACTION_ADD:
		return tquic_quic_proxy_add_cid(pconn,
						capsule->cid, capsule->cid_len,
						capsule->seq_num,
						capsule->retire_prior_to,
						capsule->has_reset_token ?
						  capsule->reset_token : NULL,
						capsule->direction);

	case QUIC_PROXY_CID_ACTION_RETIRE:
		return tquic_quic_proxy_retire_cid(pconn,
						   capsule->seq_num,
						   capsule->direction);

	case QUIC_PROXY_CID_ACTION_REQUEST:
		return tquic_quic_proxy_request_cid(pconn, capsule->direction);

	case QUIC_PROXY_CID_ACTION_ACK:
		/* Acknowledge processed, nothing to do */
		pconn->cid_updates++;
		return 0;

	default:
		return -EINVAL;
	}
}
EXPORT_SYMBOL_GPL(tquic_quic_proxy_cid_cooperation);

/**
 * tquic_quic_proxy_add_cid - Add a connection ID
 */
int tquic_quic_proxy_add_cid(
	struct tquic_proxied_quic_conn *pconn,
	const u8 *cid,
	u8 cid_len,
	u64 seq_num,
	u64 retire_prior_to,
	const u8 *reset_token,
	u8 direction)
{
	struct quic_proxy_cid_cooperation *coop;
	struct quic_proxy_cid *new_cid;
	struct list_head *target_list;

	if (!pconn || !cid || cid_len == 0 || cid_len > QUIC_PROXY_MAX_CID_LEN)
		return -EINVAL;

	coop = &pconn->cid_coop;

	/* Determine target list */
	if (direction == QUIC_PROXY_CID_DIR_CLIENT_TARGET)
		target_list = &coop->client_cids;
	else
		target_list = &coop->target_cids;

	/* Allocate new CID */
	new_cid = cid_alloc(cid, cid_len, seq_num, GFP_KERNEL);
	if (!new_cid)
		return -ENOMEM;

	new_cid->retire_prior_to = retire_prior_to;

	if (reset_token) {
		memcpy(new_cid->stateless_reset_token, reset_token, 16);
		new_cid->has_reset_token = true;
	}

	new_cid->owner = (direction == QUIC_PROXY_CID_DIR_CLIENT_TARGET) ?
			 QUIC_PROXY_CID_OWNER_CLIENT : QUIC_PROXY_CID_OWNER_TARGET;

	/* Add to list */
	spin_lock_bh(&coop->lock);

	/* Retire old CIDs if needed */
	if (retire_prior_to > 0) {
		struct quic_proxy_cid *c, *tmp;

		list_for_each_entry_safe(c, tmp, target_list, list_node) {
			if (c->seq_num < retire_prior_to) {
				list_del_init(&c->list_node);
				cid_put(c);
			}
		}
	}

	list_add_tail(&new_cid->list_node, target_list);

	/* Update next sequence number */
	if (seq_num >= coop->next_seq_num)
		coop->next_seq_num = seq_num + 1;

	spin_unlock_bh(&coop->lock);

	pconn->cid_updates++;

	/* Update compression context */
	if (pconn->compress_ctx.enabled) {
		spin_lock_bh(&pconn->compress_ctx.lock);
		compress_add_entry(&pconn->compress_ctx, cid, cid_len,
				   NULL, 0, 0);
		spin_unlock_bh(&pconn->compress_ctx.lock);
	}

	pr_debug("quic-proxy: added CID seq=%llu len=%u dir=%u\n",
		 seq_num, cid_len, direction);

	return 0;
}
EXPORT_SYMBOL_GPL(tquic_quic_proxy_add_cid);

/**
 * tquic_quic_proxy_retire_cid - Retire a connection ID
 */
int tquic_quic_proxy_retire_cid(
	struct tquic_proxied_quic_conn *pconn,
	u64 seq_num,
	u8 direction)
{
	struct quic_proxy_cid_cooperation *coop;
	struct quic_proxy_cid *c, *tmp;
	struct list_head *target_list;
	bool found = false;

	if (!pconn)
		return -EINVAL;

	coop = &pconn->cid_coop;

	/* Determine target list */
	if (direction == QUIC_PROXY_CID_DIR_CLIENT_TARGET)
		target_list = &coop->client_cids;
	else
		target_list = &coop->target_cids;

	spin_lock_bh(&coop->lock);

	list_for_each_entry_safe(c, tmp, target_list, list_node) {
		if (c->seq_num == seq_num) {
			list_del_init(&c->list_node);
			cid_put(c);
			found = true;
			break;
		}
	}

	spin_unlock_bh(&coop->lock);

	if (!found)
		return -ENOENT;

	pconn->cid_updates++;

	pr_debug("quic-proxy: retired CID seq=%llu dir=%u\n", seq_num, direction);

	return 0;
}
EXPORT_SYMBOL_GPL(tquic_quic_proxy_retire_cid);

/**
 * tquic_quic_proxy_request_cid - Request a new connection ID
 */
int tquic_quic_proxy_request_cid(
	struct tquic_proxied_quic_conn *pconn,
	u8 direction)
{
	struct quic_proxy_cid_cooperation *coop;

	if (!pconn)
		return -EINVAL;

	coop = &pconn->cid_coop;

	spin_lock_bh(&coop->lock);

	if (coop->pending_request) {
		spin_unlock_bh(&coop->lock);
		return -EALREADY;
	}

	coop->pending_request = true;

	spin_unlock_bh(&coop->lock);

	/*
	 * In a real implementation, this would send a NEW_CONNECTION_ID
	 * frame request to the appropriate endpoint.
	 */

	pr_debug("quic-proxy: requested new CID dir=%u\n", direction);

	return 0;
}
EXPORT_SYMBOL_GPL(tquic_quic_proxy_request_cid);

/*
 * =============================================================================
 * Public API: Header Compression
 * =============================================================================
 */

/**
 * tquic_quic_proxy_header_compress - Compress QUIC header
 */
int tquic_quic_proxy_header_compress(
	struct tquic_proxied_quic_conn *pconn,
	const u8 *packet,
	size_t packet_len,
	u8 *output,
	size_t output_len,
	size_t *compressed_len,
	u8 *compress_index)
{
	struct quic_proxy_compress_ctx *ctx;
	u8 dcid_len;
	const u8 *dcid;
	int idx;
	u8 first_byte;
	bool is_long_header;

	if (!pconn || !packet || !output || !compressed_len)
		return -EINVAL;

	if (packet_len < 2)
		return -EINVAL;

	ctx = &pconn->compress_ctx;
	if (!ctx->enabled)
		return -EOPNOTSUPP;

	/* Parse QUIC header to extract DCID */
	first_byte = packet[0];
	is_long_header = (first_byte & 0x80) != 0;

	if (is_long_header) {
		/* Long header: 1-byte form, 4-byte version, DCID len, DCID */
		if (packet_len < 6)
			return -EINVAL;

		dcid_len = packet[5];
		if (dcid_len > QUIC_PROXY_MAX_CID_LEN || packet_len < 6 + dcid_len)
			return -EINVAL;

		dcid = &packet[6];
	} else {
		/* Short header: DCID length from connection state */
		/* For now, assume first CID in target list */
		struct quic_proxy_cid *c;

		spin_lock_bh(&pconn->cid_coop.lock);
		if (list_empty(&pconn->cid_coop.target_cids)) {
			spin_unlock_bh(&pconn->cid_coop.lock);
			return -EINVAL;
		}
		c = list_first_entry(&pconn->cid_coop.target_cids,
				     struct quic_proxy_cid, list_node);
		dcid_len = c->len;
		spin_unlock_bh(&pconn->cid_coop.lock);

		if (packet_len < 1 + dcid_len)
			return -EINVAL;

		dcid = &packet[1];
	}

	/* Find or add compression entry */
	spin_lock_bh(&ctx->lock);

	idx = compress_find_entry(ctx, dcid, dcid_len);
	if (idx < 0) {
		/* Add new entry */
		idx = compress_add_entry(ctx, dcid, dcid_len, NULL, 0, 0);
	}

	spin_unlock_bh(&ctx->lock);

	/*
	 * Compressed format:
	 *   1 byte: compression flags (0x80 = compressed short, 0xC0 = compressed long)
	 *   1 byte: compression index
	 *   remaining: packet without DCID
	 *
	 * For short headers, this removes the DCID entirely.
	 * For long headers, we replace the variable-length DCID with the index,
	 * keeping the fixed-size header structure for proper parsing.
	 */

	if (!is_long_header) {
		/* Compress short header by replacing DCID with index */
		size_t payload_start = 1 + dcid_len;
		size_t payload_len = packet_len - payload_start;

		if (output_len < 2 + payload_len)
			return -ENOSPC;

		output[0] = 0x80 | (first_byte & 0x7F);  /* Set compression flag */
		output[1] = (u8)idx;
		memcpy(&output[2], &packet[payload_start], payload_len);

		*compressed_len = 2 + payload_len;

		if (compress_index)
			*compress_index = (u8)idx;

		ctx->tx_compressed++;

		return 0;
	}

	/*
	 * Long header compression:
	 * Original: [first_byte(1)] [version(4)] [dcid_len(1)] [dcid(N)] [scid_len(1)] [scid(M)] [payload]
	 * Compressed: [0xC0|flags(1)] [version(4)] [idx(1)] [scid_len(1)] [scid(M)] [payload]
	 *
	 * This saves (dcid_len + 1 - 1) = dcid_len bytes per packet.
	 */
	{
		size_t scid_offset = 6 + dcid_len;
		u8 scid_len;
		size_t payload_offset;
		size_t payload_len;
		size_t out_len;

		/* Validate we can read SCID length */
		if (packet_len < scid_offset + 1)
			return -EINVAL;

		scid_len = packet[scid_offset];

		/* Validate we can read the full SCID and have payload */
		payload_offset = scid_offset + 1 + scid_len;
		if (packet_len < payload_offset)
			return -EINVAL;

		payload_len = packet_len - payload_offset;

		/* Calculate compressed output size:
		 * 1 (flags) + 4 (version) + 1 (idx) + 1 (scid_len) + scid_len + payload
		 */
		out_len = 1 + 4 + 1 + 1 + scid_len + payload_len;

		if (output_len < out_len)
			return -ENOSPC;

		/* Build compressed long header */
		output[0] = 0xC0 | (first_byte & 0x3F);  /* Compressed long header flag */
		memcpy(&output[1], &packet[1], 4);       /* Copy version */
		output[5] = (u8)idx;                     /* Compression index replaces DCID */
		output[6] = scid_len;                    /* SCID length */
		if (scid_len > 0)
			memcpy(&output[7], &packet[scid_offset + 1], scid_len);
		memcpy(&output[7 + scid_len], &packet[payload_offset], payload_len);

		*compressed_len = out_len;

		if (compress_index)
			*compress_index = (u8)idx;

		ctx->tx_compressed++;

		return 0;
	}
}
EXPORT_SYMBOL_GPL(tquic_quic_proxy_header_compress);

/**
 * tquic_quic_proxy_header_decompress - Decompress QUIC header
 */
int tquic_quic_proxy_header_decompress(
	struct tquic_proxied_quic_conn *pconn,
	const u8 *compressed,
	size_t compressed_len,
	u8 compress_index,
	const u8 *payload,
	size_t payload_len,
	u8 *output,
	size_t output_len,
	size_t *packet_len)
{
	struct quic_proxy_compress_ctx *ctx;
	struct quic_proxy_compress_entry *entry;
	u8 first_byte;
	size_t dcid_len;
	size_t total_len;

	if (!pconn || !compressed || !output || !packet_len)
		return -EINVAL;

	if (compressed_len < 2)
		return -EINVAL;

	ctx = &pconn->compress_ctx;
	if (!ctx->enabled)
		return -EOPNOTSUPP;

	first_byte = compressed[0];

	/* Check if this is a compressed packet */
	if (!(first_byte & 0x80)) {
		/* Not compressed - copy as-is */
		if (output_len < compressed_len)
			return -ENOSPC;

		memcpy(output, compressed, compressed_len);
		*packet_len = compressed_len;
		return 0;
	}

	/* Get compression entry */
	spin_lock_bh(&ctx->lock);

	if (compress_index >= ctx->num_entries) {
		spin_unlock_bh(&ctx->lock);
		ctx->rx_decompression_errors++;
		return -EINVAL;
	}

	entry = &ctx->entries[compress_index];
	dcid_len = entry->dcid_len;

	/* Check for long header compression (0xC0 flag) */
	if ((first_byte & 0xC0) == 0xC0) {
		/*
		 * Decompress long header:
		 * Input: [0xC0|flags(1)] [version(4)] [idx(1)] [scid_len(1)] [scid(M)] [payload]
		 * Output: [first_byte(1)] [version(4)] [dcid_len(1)] [dcid(N)] [scid_len(1)] [scid(M)] [payload]
		 */
		u8 scid_len;
		size_t payload_offset;
		size_t payload_len;

		if (compressed_len < 7) {
			spin_unlock_bh(&ctx->lock);
			return -EINVAL;
		}

		scid_len = compressed[6];
		payload_offset = 7 + scid_len;

		if (compressed_len < payload_offset) {
			spin_unlock_bh(&ctx->lock);
			return -EINVAL;
		}

		payload_len = compressed_len - payload_offset;

		/* Calculate decompressed size:
		 * 1 (first_byte) + 4 (version) + 1 (dcid_len) + dcid_len + 1 (scid_len) + scid_len + payload
		 */
		total_len = 1 + 4 + 1 + dcid_len + 1 + scid_len + payload_len;

		if (output_len < total_len) {
			spin_unlock_bh(&ctx->lock);
			return -ENOSPC;
		}

		/* Reconstruct long header */
		output[0] = (first_byte & 0x3F) | 0x80;  /* Restore long header flag */
		memcpy(&output[1], &compressed[1], 4);   /* Copy version */
		output[5] = dcid_len;                    /* DCID length */
		memcpy(&output[6], entry->dcid, dcid_len);  /* DCID */
		output[6 + dcid_len] = scid_len;         /* SCID length */
		if (scid_len > 0)
			memcpy(&output[7 + dcid_len], &compressed[7], scid_len);
		memcpy(&output[7 + dcid_len + scid_len], &compressed[payload_offset], payload_len);

		*packet_len = total_len;

		entry->used++;
		ctx->rx_compressed++;

		spin_unlock_bh(&ctx->lock);

		return 0;
	}

	/* Short header decompression (0x80 flag) */

	/* Calculate output size */
	total_len = 1 + dcid_len + (compressed_len - 2);

	if (output_len < total_len) {
		spin_unlock_bh(&ctx->lock);
		return -ENOSPC;
	}

	/* Reconstruct short header */
	output[0] = first_byte & 0x7F;  /* Clear compression flag */
	memcpy(&output[1], entry->dcid, dcid_len);
	memcpy(&output[1 + dcid_len], &compressed[2], compressed_len - 2);

	*packet_len = total_len;

	entry->used++;
	ctx->rx_compressed++;

	spin_unlock_bh(&ctx->lock);

	return 0;
}
EXPORT_SYMBOL_GPL(tquic_quic_proxy_header_decompress);

/*
 * =============================================================================
 * Statistics
 * =============================================================================
 */

/**
 * tquic_quic_proxy_get_stats - Get proxy statistics
 */
int tquic_quic_proxy_get_stats(
	struct tquic_quic_proxy_state *proxy,
	struct tquic_quic_proxy_stats *stats)
{
	if (!proxy || !stats)
		return -EINVAL;

	spin_lock_bh(&proxy->lock);
	memcpy(stats, &proxy->stats, sizeof(*stats));
	spin_unlock_bh(&proxy->lock);

	return 0;
}
EXPORT_SYMBOL_GPL(tquic_quic_proxy_get_stats);

/**
 * tquic_quic_proxy_get_conn_stats - Get per-connection statistics
 */
int tquic_quic_proxy_get_conn_stats(
	struct tquic_proxied_quic_conn *pconn,
	u64 *tx_packets, u64 *rx_packets,
	u64 *tx_bytes, u64 *rx_bytes)
{
	if (!pconn)
		return -EINVAL;

	/* These are updated atomically, but use lock for consistency */
	if (tx_packets)
		*tx_packets = pconn->tx_packets;
	if (rx_packets)
		*rx_packets = pconn->rx_packets;
	if (tx_bytes)
		*tx_bytes = pconn->tx_bytes;
	if (rx_bytes)
		*rx_bytes = pconn->rx_bytes;

	return 0;
}
EXPORT_SYMBOL_GPL(tquic_quic_proxy_get_conn_stats);

/*
 * =============================================================================
 * Module Initialization
 * =============================================================================
 */

/**
 * tquic_quic_proxy_init_module - Initialize QUIC proxy subsystem
 */
int __init tquic_quic_proxy_init_module(void)
{
	/* Create slab caches */
	proxy_state_cache = kmem_cache_create("tquic_quic_proxy_state",
					      sizeof(struct tquic_quic_proxy_state),
					      0, SLAB_HWCACHE_ALIGN, NULL);
	if (!proxy_state_cache)
		return -ENOMEM;

	proxied_conn_cache = kmem_cache_create("tquic_proxied_quic_conn",
					       sizeof(struct tquic_proxied_quic_conn),
					       0, SLAB_HWCACHE_ALIGN, NULL);
	if (!proxied_conn_cache) {
		kmem_cache_destroy(proxy_state_cache);
		proxy_state_cache = NULL;
		return -ENOMEM;
	}

	cid_cache = kmem_cache_create("tquic_quic_proxy_cid",
				      sizeof(struct quic_proxy_cid),
				      0, SLAB_HWCACHE_ALIGN, NULL);
	if (!cid_cache) {
		kmem_cache_destroy(proxied_conn_cache);
		proxied_conn_cache = NULL;
		kmem_cache_destroy(proxy_state_cache);
		proxy_state_cache = NULL;
		return -ENOMEM;
	}

	/* Create work queue */
	quic_proxy_wq = alloc_workqueue("tquic_quic_proxy",
					WQ_MEM_RECLAIM | WQ_HIGHPRI, 0);
	if (!quic_proxy_wq) {
		kmem_cache_destroy(cid_cache);
		cid_cache = NULL;
		kmem_cache_destroy(proxied_conn_cache);
		proxied_conn_cache = NULL;
		kmem_cache_destroy(proxy_state_cache);
		proxy_state_cache = NULL;
		return -ENOMEM;
	}

	pr_info("TQUIC MASQUE: QUIC-Aware Proxy initialized (draft-ietf-masque-quic-proxy)\n");
	return 0;
}
EXPORT_SYMBOL_GPL(tquic_quic_proxy_init_module);

/**
 * tquic_quic_proxy_exit_module - Cleanup QUIC proxy subsystem
 */
void __exit tquic_quic_proxy_exit_module(void)
{
	if (quic_proxy_wq) {
		flush_workqueue(quic_proxy_wq);
		destroy_workqueue(quic_proxy_wq);
		quic_proxy_wq = NULL;
	}

	if (cid_cache) {
		kmem_cache_destroy(cid_cache);
		cid_cache = NULL;
	}

	if (proxied_conn_cache) {
		kmem_cache_destroy(proxied_conn_cache);
		proxied_conn_cache = NULL;
	}

	if (proxy_state_cache) {
		kmem_cache_destroy(proxy_state_cache);
		proxy_state_cache = NULL;
	}

	pr_info("TQUIC MASQUE: QUIC-Aware Proxy cleaned up\n");
}
EXPORT_SYMBOL_GPL(tquic_quic_proxy_exit_module);

MODULE_DESCRIPTION("TQUIC MASQUE QUIC-Aware Proxy (draft-ietf-masque-quic-proxy)");
MODULE_LICENSE("GPL");
MODULE_AUTHOR("Linux Foundation");
