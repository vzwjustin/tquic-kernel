// SPDX-License-Identifier: GPL-2.0-only
/*
 * TQUIC: Stateless Reset Packet Support
 *
 * Copyright (c) 2026 Linux Foundation
 *
 * Implements stateless reset per RFC 9000 Section 10.3.
 *
 * A stateless reset is a last-resort mechanism for an endpoint that has
 * lost state (e.g., after a crash) to terminate a connection. The reset
 * packet is designed to:
 *
 * 1. Look like a regular short header packet (to avoid middlebox issues)
 * 2. Be recognizable by the peer via a token received in NEW_CONNECTION_ID
 * 3. Not be usable for amplification attacks (must be shorter than trigger)
 * 4. Be indistinguishable from random data to third parties
 *
 * Token Generation (RFC 9000 Section 10.3.2):
 * - Tokens are generated deterministically using HMAC-SHA256(static_key, CID)
 * - This allows regeneration after state loss
 * - The static key should be protected and ideally constant across restarts
 *
 * Packet Format:
 * +------------------+-------------------+----------------------+
 * | First byte (1)   | Random bytes (4+) | Reset token (16)     |
 * +------------------+-------------------+----------------------+
 * |                  |                   |                      |
 * | Short header     | Unpredictable     | HMAC of original CID |
 * | form bit = 0     | content           |                      |
 * | Fixed bit = 1    |                   |                      |
 * +------------------+-------------------+----------------------+
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/random.h>
#include <linux/skbuff.h>
#include <linux/udp.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/net.h>
#include <linux/socket.h>
#include <linux/in.h>
#include <linux/in6.h>
#include <crypto/hash.h>
#include <crypto/utils.h>
#include <net/sock.h>
#include <net/udp.h>
#include <net/ip.h>
#include <net/ipv6.h>
#include <net/ip6_route.h>
#include <net/route.h>
#include <net/tquic.h>

#include "tquic_stateless_reset.h"
#include "tquic_mib.h"
#include "tquic_cid.h"
#include "protocol.h"

/*
 * Global stateless reset context
 * Initialized during module load
 */
static struct tquic_stateless_reset_ctx global_reset_ctx;
static bool global_ctx_initialized;

/*
 * Rate limiting configuration
 * Prevents amplification attacks when sending stateless resets
 */
#define TQUIC_RESET_RATE_LIMIT_TOKENS	100
#define TQUIC_RESET_RATE_LIMIT_REFILL_MS	1000
#define TQUIC_RESET_RATE_LIMIT_REFILL_AMOUNT	10

/*
 * Sysctl-controlled enable flag
 * Default is enabled per RFC 9000 requirement
 */
static int tquic_stateless_reset_enabled = 1;

/*
 * =============================================================================
 * Token Generation using HMAC-SHA256
 * =============================================================================
 */

/*
 * Generate stateless reset token using HMAC-SHA256
 *
 * Per RFC 9000 Section 10.3.2:
 * "An endpoint could generate a stateless reset token by using HMAC
 * with a static key over the connection ID, for example."
 *
 * We use HMAC-SHA256 and truncate to 128 bits (16 bytes).
 */
void tquic_stateless_reset_generate_token(const struct tquic_cid *cid,
					  const u8 *static_key,
					  u8 *token)
{
	struct crypto_shash *tfm;
	struct shash_desc *desc;
	u8 hmac_result[32];  /* SHA256 produces 32 bytes */
	int ret;

	if (!cid || !static_key || !token) {
		if (token)
			memset(token, 0, TQUIC_STATELESS_RESET_TOKEN_LEN);
		return;
	}

	/* Allocate HMAC-SHA256 transform */
	tfm = crypto_alloc_shash("hmac(sha256)", 0, 0);
	if (IS_ERR(tfm)) {
		pr_warn("tquic: failed to allocate HMAC-SHA256 for reset token\n");
		/* Fallback: use random bytes to avoid leaking static key */
		get_random_bytes(token, TQUIC_STATELESS_RESET_TOKEN_LEN);
		return;
	}

	/* Set the static key */
	ret = crypto_shash_setkey(tfm, static_key,
				  TQUIC_STATELESS_RESET_SECRET_LEN);
	if (ret) {
		pr_warn("tquic: HMAC setkey failed: %d\n", ret);
		crypto_free_shash(tfm);
		get_random_bytes(token, TQUIC_STATELESS_RESET_TOKEN_LEN);
		return;
	}

	/* Allocate descriptor */
	desc = kzalloc(sizeof(*desc) + crypto_shash_descsize(tfm), GFP_ATOMIC);
	if (!desc) {
		crypto_free_shash(tfm);
		get_random_bytes(token, TQUIC_STATELESS_RESET_TOKEN_LEN);
		return;
	}

	desc->tfm = tfm;

	/* Compute HMAC over the CID */
	ret = crypto_shash_digest(desc, cid->id, cid->len, hmac_result);
	if (ret) {
		pr_warn("tquic: HMAC digest failed: %d\n", ret);
		get_random_bytes(token, TQUIC_STATELESS_RESET_TOKEN_LEN);
	} else {
		/* Truncate to 128 bits (first 16 bytes) */
		memcpy(token, hmac_result, TQUIC_STATELESS_RESET_TOKEN_LEN);
	}

	/* Cleanup */
	kfree(desc);
	crypto_free_shash(tfm);

	/* Wipe intermediate result */
	memzero_explicit(hmac_result, sizeof(hmac_result));
}
EXPORT_SYMBOL_GPL(tquic_stateless_reset_generate_token);

/*
 * Verify a stateless reset token
 */
bool tquic_stateless_reset_verify_token(const struct tquic_cid *cid,
					const u8 *static_key,
					const u8 *token)
{
	u8 expected_token[TQUIC_STATELESS_RESET_TOKEN_LEN];

	if (!cid || !static_key || !token)
		return false;

	tquic_stateless_reset_generate_token(cid, static_key, expected_token);

	/* Constant-time comparison to prevent timing attacks */
	return crypto_memneq(token, expected_token,
			     TQUIC_STATELESS_RESET_TOKEN_LEN) == 0;
}
EXPORT_SYMBOL_GPL(tquic_stateless_reset_verify_token);

/*
 * =============================================================================
 * Packet Construction
 * =============================================================================
 */

/*
 * Build a stateless reset packet
 *
 * Per RFC 9000 Section 10.3:
 * - Must be at least 21 bytes (1 + 4 + 16)
 * - Should be smaller than the packet that triggered it (anti-amplification)
 * - First byte must look like a short header (form bit = 0, fixed bit = 1)
 * - Must contain unpredictable bytes before the token
 */
int tquic_stateless_reset_build(u8 *buf, size_t buf_len,
				const u8 *token, size_t incoming_pkt_len)
{
	size_t packet_len;
	size_t random_len;

	if (!buf || !token)
		return -EINVAL;

	if (buf_len < TQUIC_STATELESS_RESET_MIN_LEN)
		return -EINVAL;

	/*
	 * Per RFC 9000 Section 10.3.3:
	 * "The endpoint SHOULD ensure that the packet it sends is smaller
	 * than the packet it received to avoid being used for amplification."
	 *
	 * We aim for a packet slightly smaller than the incoming one,
	 * but at least the minimum size.
	 */
	if (incoming_pkt_len > 0) {
		/* Target: incoming - 1, but at least minimum */
		if (incoming_pkt_len <= TQUIC_STATELESS_RESET_MIN_LEN) {
			/*
			 * Incoming too small - cannot send reset without
			 * amplification risk. Return error.
			 */
			return -ENOSPC;
		}
		packet_len = min_t(size_t, incoming_pkt_len - 1, buf_len);
		packet_len = max_t(size_t, packet_len,
				   TQUIC_STATELESS_RESET_MIN_LEN);
	} else {
		/* No size constraint, use minimum */
		packet_len = TQUIC_STATELESS_RESET_MIN_LEN;
	}

	/* Clamp to maximum */
	packet_len = min_t(size_t, packet_len, TQUIC_STATELESS_RESET_MAX_LEN);

	/*
	 * First byte: must look like a valid short header
	 * Format: 0b01XXXXXX where:
	 * - Bit 7 (form) = 0 (short header)
	 * - Bit 6 (fixed) = 1 (required for QUIC packets)
	 * - Bits 5-0: random, unpredictable values
	 *
	 * We generate a random byte and mask appropriately.
	 */
	get_random_bytes(buf, 1);
	buf[0] = (buf[0] & 0x3F) | 0x40;  /* Form=0, Fixed=1, rest random */

	/*
	 * Random bytes between first byte and token
	 * Must be unpredictable to prevent fingerprinting
	 */
	random_len = packet_len - 1 - TQUIC_STATELESS_RESET_TOKEN_LEN;
	if (random_len > 0)
		get_random_bytes(buf + 1, random_len);

	/*
	 * Stateless reset token in last 16 bytes
	 */
	memcpy(buf + packet_len - TQUIC_STATELESS_RESET_TOKEN_LEN,
	       token, TQUIC_STATELESS_RESET_TOKEN_LEN);

	return packet_len;
}
EXPORT_SYMBOL_GPL(tquic_stateless_reset_build);

/*
 * =============================================================================
 * Rate Limiting
 * =============================================================================
 *
 * Rate limiting prevents stateless reset from being used in amplification
 * attacks. We use a token bucket algorithm.
 */

static bool tquic_stateless_reset_rate_limit(struct tquic_stateless_reset_ctx *ctx)
{
	ktime_t now;
	s64 elapsed_ms;
	u32 refill;

	if (!ctx)
		return false;

	spin_lock(&ctx->lock);

	now = ktime_get();
	elapsed_ms = ktime_ms_delta(now, ctx->rate_limit_last);

	/* Refill tokens based on elapsed time */
	if (elapsed_ms >= TQUIC_RESET_RATE_LIMIT_REFILL_MS) {
		refill = (elapsed_ms / TQUIC_RESET_RATE_LIMIT_REFILL_MS) *
			 TQUIC_RESET_RATE_LIMIT_REFILL_AMOUNT;
		ctx->rate_limit_tokens = min_t(u32,
					       ctx->rate_limit_tokens + refill,
					       TQUIC_RESET_RATE_LIMIT_TOKENS);
		ctx->rate_limit_last = now;
	}

	/* Check if we have tokens available */
	if (ctx->rate_limit_tokens == 0) {
		spin_unlock(&ctx->lock);
		return false;  /* Rate limited */
	}

	/* Consume a token */
	ctx->rate_limit_tokens--;

	spin_unlock(&ctx->lock);
	return true;  /* Allowed */
}

/*
 * =============================================================================
 * Packet Transmission
 * =============================================================================
 */

/*
 * Send a stateless reset packet via UDP
 */
int tquic_stateless_reset_send(struct sock *sk,
			       const struct sockaddr_storage *local_addr,
			       const struct sockaddr_storage *remote_addr,
			       const struct tquic_cid *cid,
			       const u8 *static_key,
			       size_t incoming_pkt_len)
{
	u8 token[TQUIC_STATELESS_RESET_TOKEN_LEN];
	u8 *pkt_buf;
	struct sk_buff *skb;
	struct flowi4 fl4;
	struct flowi6 fl6;
	struct rtable *rt4;
	struct dst_entry *dst;
	struct udphdr *uh;
	struct net *net;
	int pkt_len;
	int ret;

	if (!local_addr || !remote_addr || !cid || !static_key)
		return -EINVAL;

	/* Check if stateless reset is enabled */
	if (!tquic_sysctl_get_stateless_reset_enabled())
		return -EACCES;

	/* Check rate limit */
	if (!tquic_stateless_reset_rate_limit(&global_reset_ctx)) {
		pr_debug("tquic: stateless reset rate limited\n");
		return -EAGAIN;
	}

	/* Generate token from CID */
	tquic_stateless_reset_generate_token(cid, static_key, token);

	/* Allocate packet buffer */
	pkt_buf = kmalloc(TQUIC_STATELESS_RESET_MAX_LEN, GFP_ATOMIC);
	if (!pkt_buf)
		return -ENOMEM;

	/* Build the reset packet */
	pkt_len = tquic_stateless_reset_build(pkt_buf, TQUIC_STATELESS_RESET_MAX_LEN,
					      token, incoming_pkt_len);
	if (pkt_len < 0) {
		kfree(pkt_buf);
		return pkt_len;
	}

	/* Get network namespace */
	net = sk ? sock_net(sk) : &init_net;

	/* Allocate SKB */
	skb = alloc_skb(pkt_len + MAX_HEADER + sizeof(struct udphdr), GFP_ATOMIC);
	if (!skb) {
		kfree(pkt_buf);
		return -ENOMEM;
	}

	skb_reserve(skb, MAX_HEADER + sizeof(struct udphdr));

	/* Copy packet data */
	skb_put_data(skb, pkt_buf, pkt_len);
	kfree(pkt_buf);

	/* Handle IPv4 vs IPv6 */
	if (remote_addr->ss_family == AF_INET) {
		const struct sockaddr_in *sin_local;
		const struct sockaddr_in *sin_remote;

		sin_local = (const struct sockaddr_in *)local_addr;
		sin_remote = (const struct sockaddr_in *)remote_addr;

		/* Setup flow */
		memset(&fl4, 0, sizeof(fl4));
		fl4.daddr = sin_remote->sin_addr.s_addr;
		fl4.saddr = sin_local->sin_addr.s_addr;
		fl4.flowi4_proto = IPPROTO_UDP;

		/* Route lookup */
		rt4 = ip_route_output_key(net, &fl4);
		if (IS_ERR(rt4)) {
			kfree_skb(skb);
			return PTR_ERR(rt4);
		}

		skb->protocol = htons(ETH_P_IP);
		skb_dst_set(skb, &rt4->dst);

		/* Add UDP header */
		uh = skb_push(skb, sizeof(struct udphdr));
		uh->source = sin_local->sin_port;
		uh->dest = sin_remote->sin_port;
		uh->len = htons(pkt_len + sizeof(struct udphdr));
		uh->check = 0;

		/* Calculate UDP checksum */
		skb->ip_summed = CHECKSUM_PARTIAL;
		skb->csum_start = skb_transport_header(skb) - skb->head;
		skb->csum_offset = offsetof(struct udphdr, check);

		/* Send via IP */
		ret = ip_local_out(net, NULL, skb);

#if IS_ENABLED(CONFIG_IPV6)
	} else if (remote_addr->ss_family == AF_INET6) {
		const struct sockaddr_in6 *sin6_local;
		const struct sockaddr_in6 *sin6_remote;

		sin6_local = (const struct sockaddr_in6 *)local_addr;
		sin6_remote = (const struct sockaddr_in6 *)remote_addr;

		/* Setup flow */
		memset(&fl6, 0, sizeof(fl6));
		fl6.daddr = sin6_remote->sin6_addr;
		fl6.saddr = sin6_local->sin6_addr;
		fl6.flowi6_proto = IPPROTO_UDP;
		fl6.fl6_dport = sin6_remote->sin6_port;
		fl6.fl6_sport = sin6_local->sin6_port;

		/* Route lookup */
		dst = ip6_route_output(net, NULL, &fl6);
		if (IS_ERR(dst)) {
			kfree_skb(skb);
			return PTR_ERR(dst);
		}

		skb->protocol = htons(ETH_P_IPV6);
		skb_dst_set(skb, dst);

		/* Add UDP header */
		uh = skb_push(skb, sizeof(struct udphdr));
		uh->source = sin6_local->sin6_port;
		uh->dest = sin6_remote->sin6_port;
		uh->len = htons(pkt_len + sizeof(struct udphdr));
		uh->check = 0;

		skb->ip_summed = CHECKSUM_PARTIAL;
		skb->csum_start = skb_transport_header(skb) - skb->head;
		skb->csum_offset = offsetof(struct udphdr, check);

		/* Send via IPv6 */
		ret = ip6_local_out(net, NULL, skb);
#endif
	} else {
		kfree_skb(skb);
		return -EAFNOSUPPORT;
	}

	/* Update statistics */
	if (ret >= 0) {
		TQUIC_INC_STATS(net, TQUIC_MIB_STATELESSRESETSTX);
		pr_debug("tquic: sent stateless reset, len=%d\n", pkt_len);
	}

	return ret;
}
EXPORT_SYMBOL_GPL(tquic_stateless_reset_send);

/*
 * =============================================================================
 * Detection
 * =============================================================================
 */

/*
 * Check if a packet is a stateless reset by comparing against known tokens
 */
bool tquic_stateless_reset_detect(const u8 *data, size_t len,
				  const u8 (*tokens)[TQUIC_STATELESS_RESET_TOKEN_LEN],
				  int num_tokens)
{
	const u8 *pkt_token;
	int i;

	if (!data || !tokens || num_tokens <= 0)
		return false;

	/* Must be at least minimum length */
	if (len < TQUIC_STATELESS_RESET_MIN_LEN)
		return false;

	/*
	 * Must look like a short header packet
	 * First bit (form) must be 0
	 */
	if (data[0] & 0x80)
		return false;

	/* Token is in last 16 bytes */
	pkt_token = data + len - TQUIC_STATELESS_RESET_TOKEN_LEN;

	/* Compare against all known tokens */
	for (i = 0; i < num_tokens; i++) {
		/* Constant-time comparison */
		if (crypto_memneq(pkt_token, tokens[i],
				  TQUIC_STATELESS_RESET_TOKEN_LEN) == 0)
			return true;
	}

	return false;
}
EXPORT_SYMBOL_GPL(tquic_stateless_reset_detect);

/*
 * Check if a packet is a stateless reset for a specific connection
 *
 * Looks up peer tokens stored from NEW_CONNECTION_ID frames
 */
bool tquic_stateless_reset_detect_conn(struct tquic_connection *conn,
				       const u8 *data, size_t len)
{
	struct tquic_cid_pool *pool;
	struct tquic_cid_entry *entry;
	const u8 *pkt_token;
	bool found = false;

	if (!conn || !data)
		return false;

	/* Must be at least minimum length */
	if (len < TQUIC_STATELESS_RESET_MIN_LEN)
		return false;

	/* Must look like a short header */
	if (data[0] & 0x80)
		return false;

	/* Token is in last 16 bytes */
	pkt_token = data + len - TQUIC_STATELESS_RESET_TOKEN_LEN;

	/* Check against peer tokens stored in CID pool */
	pool = conn->cid_pool;
	if (!pool)
		return false;

	spin_lock_bh(&((struct tquic_cid_pool *)pool)->lock);

	/*
	 * Iterate through remote CIDs (peer's CIDs we use when sending)
	 * and check their associated reset tokens
	 */
	{
		struct list_head *remote_list;

		/* Access remote_cids list from pool structure */
		remote_list = &((struct tquic_cid_pool *)pool)->remote_cids;

		list_for_each_entry(entry, remote_list, list) {
			if (crypto_memneq(pkt_token, entry->reset_token,
					  TQUIC_STATELESS_RESET_TOKEN_LEN) == 0) {
				found = true;
				break;
			}
		}
	}

	spin_unlock_bh(&((struct tquic_cid_pool *)pool)->lock);

	if (found) {
		struct net *net = conn->sk ? sock_net(conn->sk) : NULL;

		if (net)
			TQUIC_INC_STATS(net, TQUIC_MIB_STATELESSRESETSRX);
		pr_debug("tquic: detected stateless reset for connection\n");
	}

	return found;
}
EXPORT_SYMBOL_GPL(tquic_stateless_reset_detect_conn);

/*
 * =============================================================================
 * Token Storage for Peer Tokens
 * =============================================================================
 */

/*
 * Store a peer's stateless reset token (received in NEW_CONNECTION_ID)
 */
int tquic_stateless_reset_add_peer_token(struct tquic_connection *conn,
					 const struct tquic_cid *cid,
					 const u8 *token)
{
	/*
	 * Peer tokens are stored in the CID pool along with the CID entry.
	 * The tquic_cid_add_remote() function in tquic_cid.c handles this.
	 * This function is provided for explicit token management if needed.
	 */
	if (!conn || !cid || !token)
		return -EINVAL;

	return tquic_cid_add_remote(conn, cid, cid->seq_num,
				    cid->retire_prior_to, token);
}
EXPORT_SYMBOL_GPL(tquic_stateless_reset_add_peer_token);

/*
 * Remove a peer's stateless reset token
 */
void tquic_stateless_reset_remove_peer_token(struct tquic_connection *conn,
					     const struct tquic_cid *cid)
{
	/*
	 * Token removal happens when the CID is retired via
	 * tquic_cid_retire_remote() in tquic_cid.c
	 */
	if (!conn || !cid)
		return;

	tquic_cid_retire_remote(conn, cid->seq_num);
}
EXPORT_SYMBOL_GPL(tquic_stateless_reset_remove_peer_token);

/*
 * =============================================================================
 * Context Management
 * =============================================================================
 */

int tquic_stateless_reset_ctx_init(struct tquic_stateless_reset_ctx *ctx)
{
	if (!ctx)
		return -EINVAL;

	/* Generate random static key */
	get_random_bytes(ctx->static_key, TQUIC_STATELESS_RESET_SECRET_LEN);

	ctx->enabled = true;
	ctx->rate_limit_tokens = TQUIC_RESET_RATE_LIMIT_TOKENS;
	ctx->rate_limit_last = ktime_get();
	spin_lock_init(&ctx->lock);

	return 0;
}
EXPORT_SYMBOL_GPL(tquic_stateless_reset_ctx_init);

void tquic_stateless_reset_ctx_destroy(struct tquic_stateless_reset_ctx *ctx)
{
	if (!ctx)
		return;

	/* Securely wipe the static key */
	memzero_explicit(ctx->static_key, TQUIC_STATELESS_RESET_SECRET_LEN);
	ctx->enabled = false;
}
EXPORT_SYMBOL_GPL(tquic_stateless_reset_ctx_destroy);

void tquic_stateless_reset_set_enabled(struct tquic_stateless_reset_ctx *ctx,
				       bool enabled)
{
	if (!ctx)
		return;

	spin_lock(&ctx->lock);
	ctx->enabled = enabled;
	spin_unlock(&ctx->lock);
}
EXPORT_SYMBOL_GPL(tquic_stateless_reset_set_enabled);

bool tquic_stateless_reset_is_enabled(struct tquic_stateless_reset_ctx *ctx)
{
	bool enabled;

	if (!ctx)
		return false;

	spin_lock(&ctx->lock);
	enabled = ctx->enabled;
	spin_unlock(&ctx->lock);

	return enabled;
}
EXPORT_SYMBOL_GPL(tquic_stateless_reset_is_enabled);

/*
 * =============================================================================
 * Global Context Access
 * =============================================================================
 */

/*
 * Get the global static key for token generation
 * Used by CID management when generating tokens for NEW_CONNECTION_ID
 */
const u8 *tquic_stateless_reset_get_static_key(void)
{
	if (!global_ctx_initialized)
		return NULL;

	return global_reset_ctx.static_key;
}
EXPORT_SYMBOL_GPL(tquic_stateless_reset_get_static_key);

/*
 * =============================================================================
 * Sysctl Integration
 * =============================================================================
 */

bool tquic_sysctl_get_stateless_reset_enabled(void)
{
	return tquic_stateless_reset_enabled != 0;
}
EXPORT_SYMBOL_GPL(tquic_sysctl_get_stateless_reset_enabled);

/*
 * =============================================================================
 * Module Initialization
 * =============================================================================
 */

int __init tquic_stateless_reset_init(void)
{
	int ret;

	ret = tquic_stateless_reset_ctx_init(&global_reset_ctx);
	if (ret) {
		pr_err("tquic: failed to initialize stateless reset context\n");
		return ret;
	}

	global_ctx_initialized = true;

	pr_info("tquic: stateless reset subsystem initialized\n");
	return 0;
}

void __exit tquic_stateless_reset_exit(void)
{
	if (global_ctx_initialized) {
		tquic_stateless_reset_ctx_destroy(&global_reset_ctx);
		global_ctx_initialized = false;
	}

	pr_info("tquic: stateless reset subsystem exited\n");
}

MODULE_DESCRIPTION("TQUIC Stateless Reset Support");
MODULE_LICENSE("GPL");
