// SPDX-License-Identifier: GPL-2.0-only
/*
 * TQUIC: 0-RTT Early Data Support (RFC 9001 Sections 4.6-4.7)
 *
 * Copyright (c) 2026 Linux Foundation
 *
 * Implements TLS 1.3 0-RTT early data for QUIC connections:
 * - Session ticket storage after successful handshake
 * - 0-RTT key derivation from resumption_master_secret
 * - Early data transmission before handshake completes
 * - Server accept/reject via early_data_indication
 * - Anti-replay protection using bloom filter with TTL
 *
 * Security Notes (RFC 9001 Section 9.2):
 * - 0-RTT data is replayable; applications must be idempotent
 * - Server anti-replay uses single-use ticket + bloom filter
 * - Ticket age validation prevents old ticket reuse
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/random.h>
#include <linux/jhash.h>
#include <linux/bitmap.h>
#include <crypto/aead.h>
#include <crypto/hash.h>
#include <crypto/skcipher.h>
#include <net/tquic.h>

#include "zero_rtt.h"
#include "../tquic_mib.h"

/*
 * =============================================================================
 * Module Configuration
 * =============================================================================
 */

/* Global ticket store (client-side) */
static struct tquic_ticket_store global_ticket_store;

/* Global replay filter (server-side) */
static struct tquic_replay_filter global_replay_filter;

/* Server-side ticket encryption key (generated at module init) */
static u8 server_ticket_key[TQUIC_SESSION_TICKET_KEY_LEN];
static bool server_ticket_key_valid;

/*
 * Cryptographically random seeds for replay filter bloom hash.
 * Initialized at module load to prevent hash prediction attacks.
 */
static u32 replay_hash_seed1 __read_mostly;
static u32 replay_hash_seed2 __read_mostly;

/* TLS 1.3 cipher suites */
#define TLS_AES_128_GCM_SHA256		0x1301
#define TLS_AES_256_GCM_SHA384		0x1302
#define TLS_CHACHA20_POLY1305_SHA256	0x1303

/* HKDF labels for 0-RTT (RFC 9001 Section 5.1) */
#define TQUIC_HKDF_LABEL_EARLY		"c e traffic"
#define TQUIC_HKDF_LABEL_0RTT_KEY	"quic key"
#define TQUIC_HKDF_LABEL_0RTT_IV	"quic iv"
#define TQUIC_HKDF_LABEL_0RTT_HP	"quic hp"

/*
 * =============================================================================
 * Helper Functions
 * =============================================================================
 */

/*
 * Get hash algorithm name for cipher suite
 */
static const char *tquic_cipher_to_hash_name(u16 cipher_suite)
{
	switch (cipher_suite) {
	case TLS_AES_128_GCM_SHA256:
	case TLS_CHACHA20_POLY1305_SHA256:
		return "hmac(sha256)";
	case TLS_AES_256_GCM_SHA384:
		return "hmac(sha384)";
	default:
		return "hmac(sha256)";
	}
}

/*
 * Get hash length for cipher suite
 */
static u32 tquic_cipher_to_hash_len(u16 cipher_suite)
{
	switch (cipher_suite) {
	case TLS_AES_128_GCM_SHA256:
	case TLS_CHACHA20_POLY1305_SHA256:
		return 32;
	case TLS_AES_256_GCM_SHA384:
		return 48;
	default:
		return 32;
	}
}

/*
 * Get key length for cipher suite
 */
static u32 tquic_cipher_to_key_len(u16 cipher_suite)
{
	switch (cipher_suite) {
	case TLS_AES_128_GCM_SHA256:
		return 16;
	case TLS_AES_256_GCM_SHA384:
	case TLS_CHACHA20_POLY1305_SHA256:
		return 32;
	default:
		return 16;
	}
}

/*
 * Get AEAD algorithm name for cipher suite
 */
static const char *tquic_cipher_to_aead_name(u16 cipher_suite)
{
	switch (cipher_suite) {
	case TLS_AES_128_GCM_SHA256:
	case TLS_AES_256_GCM_SHA384:
		return "gcm(aes)";
	case TLS_CHACHA20_POLY1305_SHA256:
		return "rfc7539(chacha20,poly1305)";
	default:
		return "gcm(aes)";
	}
}

/*
 * HKDF-Extract
 */
static int tquic_hkdf_extract(struct crypto_shash *hash,
			      const u8 *salt, size_t salt_len,
			      const u8 *ikm, size_t ikm_len,
			      u8 *prk, size_t prk_len)
{
	SHASH_DESC_ON_STACK(desc, hash);
	int ret;

	desc->tfm = hash;

	ret = crypto_shash_setkey(hash, salt, salt_len);
	if (ret)
		return ret;

	ret = crypto_shash_init(desc);
	if (ret)
		return ret;

	ret = crypto_shash_update(desc, ikm, ikm_len);
	if (ret)
		return ret;

	return crypto_shash_final(desc, prk);
}

/*
 * HKDF-Expand-Label for TLS 1.3
 */
static int tquic_hkdf_expand_label(struct crypto_shash *hash,
				   const u8 *secret, u32 secret_len,
				   const char *label, u32 label_len,
				   const u8 *context, u32 context_len,
				   u8 *out, u32 out_len)
{
	u8 hkdf_label[256];
	u8 *p = hkdf_label;
	u32 hkdf_label_len;
	SHASH_DESC_ON_STACK(desc, hash);
	u8 t[64];
	int ret;
	u32 i, n, hash_len;

	hash_len = crypto_shash_digestsize(hash);

	/* Construct HKDF label: length || "tls13 " || label || context */
	*p++ = (out_len >> 8) & 0xff;
	*p++ = out_len & 0xff;
	*p++ = 6 + label_len;	/* "tls13 " prefix + label */
	memcpy(p, "tls13 ", 6);
	p += 6;
	memcpy(p, label, label_len);
	p += label_len;
	*p++ = context_len;
	if (context_len > 0) {
		memcpy(p, context, context_len);
		p += context_len;
	}
	hkdf_label_len = p - hkdf_label;

	desc->tfm = hash;

	/* HKDF-Expand */
	n = (out_len + hash_len - 1) / hash_len;

	for (i = 0; i < n; i++) {
		ret = crypto_shash_setkey(hash, secret, secret_len);
		if (ret)
			return ret;

		ret = crypto_shash_init(desc);
		if (ret)
			return ret;

		if (i > 0) {
			ret = crypto_shash_update(desc, t, hash_len);
			if (ret)
				return ret;
		}

		ret = crypto_shash_update(desc, hkdf_label, hkdf_label_len);
		if (ret)
			return ret;

		t[0] = i + 1;
		ret = crypto_shash_update(desc, t, 1);
		if (ret)
			return ret;

		ret = crypto_shash_final(desc, t);
		if (ret)
			return ret;

		memcpy(out + i * hash_len, t,
		       min_t(u32, hash_len, out_len - i * hash_len));
	}

	return 0;
}

/*
 * Derive-Secret from TLS 1.3 key schedule
 */
static int tquic_derive_secret(struct crypto_shash *hash,
			       const u8 *secret, u32 secret_len,
			       const char *label,
			       const u8 *messages_hash, u32 hash_len,
			       u8 *out)
{
	return tquic_hkdf_expand_label(hash, secret, secret_len,
				       label, strlen(label),
				       messages_hash, hash_len,
				       out, hash_len);
}

/*
 * =============================================================================
 * Session Ticket Store
 * =============================================================================
 */

/*
 * Compare server names for RB-tree
 */
static int ticket_cmp(const char *a, u8 a_len, const char *b, u8 b_len)
{
	int len = min(a_len, b_len);
	int cmp = memcmp(a, b, len);

	if (cmp != 0)
		return cmp;
	return (int)a_len - (int)b_len;
}

/*
 * Find ticket in RB-tree
 */
static struct tquic_session_ticket *ticket_store_find_locked(
	struct tquic_ticket_store *store,
	const char *server_name, u8 server_name_len)
{
	struct rb_node *node = store->tickets.rb_node;

	while (node) {
		struct tquic_session_ticket *ticket =
			rb_entry(node, struct tquic_session_ticket, node);
		int cmp = ticket_cmp(server_name, server_name_len,
				     ticket->server_name, ticket->server_name_len);

		if (cmp < 0)
			node = node->rb_left;
		else if (cmp > 0)
			node = node->rb_right;
		else
			return ticket;
	}

	return NULL;
}

/*
 * Insert ticket into RB-tree
 */
static int ticket_store_insert_locked(struct tquic_ticket_store *store,
				      struct tquic_session_ticket *ticket)
{
	struct rb_node **new = &store->tickets.rb_node;
	struct rb_node *parent = NULL;

	while (*new) {
		struct tquic_session_ticket *existing =
			rb_entry(*new, struct tquic_session_ticket, node);
		int cmp = ticket_cmp(ticket->server_name, ticket->server_name_len,
				     existing->server_name, existing->server_name_len);

		parent = *new;
		if (cmp < 0)
			new = &(*new)->rb_left;
		else if (cmp > 0)
			new = &(*new)->rb_right;
		else
			return -EEXIST;	/* Already exists */
	}

	rb_link_node(&ticket->node, parent, new);
	rb_insert_color(&ticket->node, &store->tickets);
	list_add(&ticket->list, &store->lru_list);
	store->count++;

	return 0;
}

/*
 * Remove ticket from store
 */
static void ticket_store_remove_locked(struct tquic_ticket_store *store,
				       struct tquic_session_ticket *ticket)
{
	rb_erase(&ticket->node, &store->tickets);
	list_del(&ticket->list);
	store->count--;
}

/*
 * Free ticket memory
 */
static void ticket_free(struct tquic_session_ticket *ticket)
{
	if (!ticket)
		return;

	kfree(ticket->ticket);
	memzero_explicit(&ticket->plaintext, sizeof(ticket->plaintext));
	kfree(ticket);
}

/*
 * Evict oldest ticket from store
 */
static void ticket_store_evict_oldest_locked(struct tquic_ticket_store *store)
{
	struct tquic_session_ticket *oldest;

	if (list_empty(&store->lru_list))
		return;

	oldest = list_last_entry(&store->lru_list,
				 struct tquic_session_ticket, list);
	ticket_store_remove_locked(store, oldest);
	ticket_free(oldest);
}

/*
 * Check if ticket is expired
 */
static bool ticket_is_expired(struct tquic_session_ticket *ticket)
{
	u64 now = ktime_get_real_seconds();
	u64 age;

	if (now < ticket->plaintext.creation_time)
		return true;

	age = now - ticket->plaintext.creation_time;
	return age > ticket->plaintext.max_age;
}

/*
 * =============================================================================
 * Session Ticket Public API
 * =============================================================================
 */

int tquic_zero_rtt_store_ticket(const char *server_name, u8 server_name_len,
				const u8 *ticket_data, u32 ticket_len,
				const struct tquic_session_ticket_plaintext *plaintext)
{
	struct tquic_session_ticket *ticket, *old;
	int ret;

	if (!server_name || server_name_len == 0 || server_name_len > 255)
		return -EINVAL;

	if (!ticket_data || ticket_len == 0 || ticket_len > TQUIC_SESSION_TICKET_MAX_LEN)
		return -EINVAL;

	if (!plaintext)
		return -EINVAL;

	/* Allocate ticket */
	ticket = kzalloc(sizeof(*ticket), GFP_KERNEL);
	if (!ticket)
		return -ENOMEM;

	ticket->ticket = kmalloc(ticket_len, GFP_KERNEL);
	if (!ticket->ticket) {
		kfree(ticket);
		return -ENOMEM;
	}

	/* Copy ticket data */
	memcpy(ticket->server_name, server_name, server_name_len);
	ticket->server_name_len = server_name_len;
	memcpy(ticket->ticket, ticket_data, ticket_len);
	ticket->ticket_len = ticket_len;
	memcpy(&ticket->plaintext, plaintext, sizeof(*plaintext));
	refcount_set(&ticket->refcount, 1);
	INIT_LIST_HEAD(&ticket->list);

	/* Insert into store */
	spin_lock_bh(&global_ticket_store.lock);

	/* Remove old ticket for same server if exists */
	old = ticket_store_find_locked(&global_ticket_store,
				       server_name, server_name_len);
	if (old) {
		ticket_store_remove_locked(&global_ticket_store, old);
		ticket_free(old);
	}

	/* Evict if at capacity */
	while (global_ticket_store.count >= global_ticket_store.max_count)
		ticket_store_evict_oldest_locked(&global_ticket_store);

	ret = ticket_store_insert_locked(&global_ticket_store, ticket);

	spin_unlock_bh(&global_ticket_store.lock);

	if (ret < 0) {
		kfree(ticket->ticket);
		kfree(ticket);
		return ret;
	}

	pr_debug("tquic: stored session ticket for %.*s\n",
		 server_name_len, server_name);

	return 0;
}
EXPORT_SYMBOL_GPL(tquic_zero_rtt_store_ticket);

struct tquic_session_ticket *tquic_zero_rtt_lookup_ticket(
	const char *server_name, u8 server_name_len)
{
	struct tquic_session_ticket *ticket;

	if (!server_name || server_name_len == 0)
		return NULL;

	spin_lock_bh(&global_ticket_store.lock);

	ticket = ticket_store_find_locked(&global_ticket_store,
					  server_name, server_name_len);
	if (ticket) {
		/* Check expiration */
		if (ticket_is_expired(ticket)) {
			ticket_store_remove_locked(&global_ticket_store, ticket);
			spin_unlock_bh(&global_ticket_store.lock);
			ticket_free(ticket);
			return NULL;
		}

		/* Move to front of LRU */
		list_del(&ticket->list);
		list_add(&ticket->list, &global_ticket_store.lru_list);

		/* Take reference */
		refcount_inc(&ticket->refcount);
	}

	spin_unlock_bh(&global_ticket_store.lock);

	return ticket;
}
EXPORT_SYMBOL_GPL(tquic_zero_rtt_lookup_ticket);

void tquic_zero_rtt_put_ticket(struct tquic_session_ticket *ticket)
{
	if (!ticket)
		return;

	if (refcount_dec_and_test(&ticket->refcount))
		ticket_free(ticket);
}
EXPORT_SYMBOL_GPL(tquic_zero_rtt_put_ticket);

void tquic_zero_rtt_remove_ticket(const char *server_name, u8 server_name_len)
{
	struct tquic_session_ticket *ticket;

	if (!server_name || server_name_len == 0)
		return;

	spin_lock_bh(&global_ticket_store.lock);

	ticket = ticket_store_find_locked(&global_ticket_store,
					  server_name, server_name_len);
	if (ticket) {
		ticket_store_remove_locked(&global_ticket_store, ticket);
		spin_unlock_bh(&global_ticket_store.lock);
		ticket_free(ticket);
		return;
	}

	spin_unlock_bh(&global_ticket_store.lock);
}
EXPORT_SYMBOL_GPL(tquic_zero_rtt_remove_ticket);

/*
 * =============================================================================
 * 0-RTT Key Derivation
 * =============================================================================
 */

int tquic_zero_rtt_derive_keys(struct tquic_zero_rtt_keys *keys,
			       const u8 *psk, u32 psk_len,
			       u16 cipher_suite)
{
	struct crypto_shash *hash;
	u8 early_secret[TQUIC_ZERO_RTT_SECRET_MAX_LEN];
	u8 zeros[TQUIC_ZERO_RTT_SECRET_MAX_LEN] = {0};
	u8 empty_hash[TQUIC_ZERO_RTT_SECRET_MAX_LEN];
	u32 hash_len;
	int ret;

	if (!keys || !psk || psk_len == 0)
		return -EINVAL;

	memset(keys, 0, sizeof(*keys));

	hash_len = tquic_cipher_to_hash_len(cipher_suite);
	keys->key_len = tquic_cipher_to_key_len(cipher_suite);
	keys->iv_len = TQUIC_ZERO_RTT_IV_MAX_LEN;
	keys->secret_len = hash_len;

	/* Allocate hash transform */
	hash = crypto_alloc_shash(tquic_cipher_to_hash_name(cipher_suite), 0, 0);
	if (IS_ERR(hash)) {
		pr_err("tquic: failed to allocate hash for 0-RTT key derivation\n");
		return PTR_ERR(hash);
	}

	/*
	 * TLS 1.3 Key Schedule for 0-RTT (RFC 8446 Section 7.1):
	 *
	 * PSK -> HKDF-Extract -> early_secret
	 *                            |
	 *                            v
	 *     Derive-Secret(., "c e traffic", ClientHello)
	 *                            |
	 *                            v
	 *                 client_early_traffic_secret
	 *
	 * For simplicity, we use an empty transcript here. The actual
	 * implementation should include the ClientHello hash.
	 */

	/* early_secret = HKDF-Extract(0, PSK) */
	ret = tquic_hkdf_extract(hash, zeros, hash_len, psk, psk_len,
				 early_secret, hash_len);
	if (ret) {
		pr_err("tquic: HKDF-Extract failed for early_secret: %d\n", ret);
		goto out;
	}

	/* Compute empty transcript hash */
	{
		SHASH_DESC_ON_STACK(desc, hash);
		desc->tfm = hash;
		ret = crypto_shash_init(desc);
		if (ret)
			goto out;
		ret = crypto_shash_final(desc, empty_hash);
		if (ret)
			goto out;
	}

	/* client_early_traffic_secret = Derive-Secret(early_secret, "c e traffic", "") */
	ret = tquic_derive_secret(hash, early_secret, hash_len,
				  TQUIC_HKDF_LABEL_EARLY, empty_hash, hash_len,
				  keys->secret);
	if (ret) {
		pr_err("tquic: Derive-Secret failed for 0-RTT: %d\n", ret);
		goto out;
	}

	/* Derive AEAD key: HKDF-Expand-Label(secret, "quic key", "", key_len) */
	ret = tquic_hkdf_expand_label(hash, keys->secret, hash_len,
				      TQUIC_HKDF_LABEL_0RTT_KEY,
				      strlen(TQUIC_HKDF_LABEL_0RTT_KEY),
				      NULL, 0, keys->key, keys->key_len);
	if (ret) {
		pr_err("tquic: 0-RTT key derivation failed: %d\n", ret);
		goto out;
	}

	/* Derive IV: HKDF-Expand-Label(secret, "quic iv", "", 12) */
	ret = tquic_hkdf_expand_label(hash, keys->secret, hash_len,
				      TQUIC_HKDF_LABEL_0RTT_IV,
				      strlen(TQUIC_HKDF_LABEL_0RTT_IV),
				      NULL, 0, keys->iv, keys->iv_len);
	if (ret) {
		pr_err("tquic: 0-RTT IV derivation failed: %d\n", ret);
		goto out;
	}

	/* Derive HP key: HKDF-Expand-Label(secret, "quic hp", "", key_len) */
	ret = tquic_hkdf_expand_label(hash, keys->secret, hash_len,
				      TQUIC_HKDF_LABEL_0RTT_HP,
				      strlen(TQUIC_HKDF_LABEL_0RTT_HP),
				      NULL, 0, keys->hp_key, keys->key_len);
	if (ret) {
		pr_err("tquic: 0-RTT HP key derivation failed: %d\n", ret);
		goto out;
	}

	keys->valid = true;
	ret = 0;

	pr_debug("tquic: 0-RTT keys derived successfully\n");

out:
	memzero_explicit(early_secret, sizeof(early_secret));
	crypto_free_shash(hash);
	return ret;
}
EXPORT_SYMBOL_GPL(tquic_zero_rtt_derive_keys);

int tquic_zero_rtt_derive_secret(u8 *out, u32 out_len,
				 const u8 *psk, u32 psk_len,
				 const u8 *client_hello_hash, u32 hash_len,
				 u16 cipher_suite)
{
	struct crypto_shash *hash;
	u8 early_secret[TQUIC_ZERO_RTT_SECRET_MAX_LEN];
	u8 zeros[TQUIC_ZERO_RTT_SECRET_MAX_LEN] = {0};
	u32 expected_hash_len;
	int ret;

	if (!out || !psk || !client_hello_hash)
		return -EINVAL;

	expected_hash_len = tquic_cipher_to_hash_len(cipher_suite);
	if (out_len != expected_hash_len || hash_len != expected_hash_len)
		return -EINVAL;

	hash = crypto_alloc_shash(tquic_cipher_to_hash_name(cipher_suite), 0, 0);
	if (IS_ERR(hash))
		return PTR_ERR(hash);

	/* early_secret = HKDF-Extract(0, PSK) */
	ret = tquic_hkdf_extract(hash, zeros, expected_hash_len, psk, psk_len,
				 early_secret, expected_hash_len);
	if (ret)
		goto out;

	/* client_early_traffic_secret = Derive-Secret(early_secret, "c e traffic", CH) */
	ret = tquic_derive_secret(hash, early_secret, expected_hash_len,
				  TQUIC_HKDF_LABEL_EARLY, client_hello_hash,
				  hash_len, out);

out:
	memzero_explicit(early_secret, sizeof(early_secret));
	crypto_free_shash(hash);
	return ret;
}
EXPORT_SYMBOL_GPL(tquic_zero_rtt_derive_secret);

/*
 * =============================================================================
 * Anti-Replay Protection
 * =============================================================================
 */

int tquic_replay_filter_init(struct tquic_replay_filter *filter, u32 ttl_seconds)
{
	if (!filter)
		return -EINVAL;

	spin_lock_init(&filter->lock);
	bitmap_zero(filter->bits, TQUIC_REPLAY_BLOOM_BITS);
	filter->current_bucket = 0;
	filter->last_rotation = ktime_get();
	filter->ttl_seconds = ttl_seconds > 0 ? ttl_seconds : TQUIC_REPLAY_TTL_SECONDS;

	return 0;
}
EXPORT_SYMBOL_GPL(tquic_replay_filter_init);

void tquic_replay_filter_cleanup(struct tquic_replay_filter *filter)
{
	if (!filter)
		return;

	spin_lock_bh(&filter->lock);
	bitmap_zero(filter->bits, TQUIC_REPLAY_BLOOM_BITS);
	spin_unlock_bh(&filter->lock);
}
EXPORT_SYMBOL_GPL(tquic_replay_filter_cleanup);

/*
 * Rotate bloom filter buckets based on TTL
 */
static void replay_filter_rotate(struct tquic_replay_filter *filter)
{
	ktime_t now = ktime_get();
	s64 elapsed;

	elapsed = ktime_to_ms(ktime_sub(now, filter->last_rotation));

	/* Rotate every TTL/2 to maintain coverage */
	if (elapsed > (filter->ttl_seconds * 500)) {
		/* Clear half the bits by rotating */
		bitmap_zero(filter->bits, TQUIC_REPLAY_BLOOM_BITS / 2);
		filter->last_rotation = now;
		filter->current_bucket ^= 1;
	}
}

/*
 * Compute bloom filter hash indices
 *
 * Uses cryptographically random seeds initialized at module load
 * to prevent hash prediction attacks on the replay filter.
 */
static void replay_filter_hash(const u8 *data, u32 len, u32 *indices)
{
	u32 h1, h2;
	int i;

	/* Use jhash with random seeds initialized at module load */
	h1 = jhash(data, len, replay_hash_seed1);
	h2 = jhash(data, len, replay_hash_seed2);

	for (i = 0; i < TQUIC_REPLAY_BLOOM_HASHES; i++)
		indices[i] = (h1 + i * h2) % TQUIC_REPLAY_BLOOM_BITS;
}

int tquic_replay_filter_check(struct tquic_replay_filter *filter,
			      const u8 *ticket, u32 ticket_len)
{
	u32 indices[TQUIC_REPLAY_BLOOM_HASHES];
	bool is_replay = true;
	int i;

	if (!filter || !ticket || ticket_len == 0)
		return -EINVAL;

	replay_filter_hash(ticket, ticket_len, indices);

	spin_lock_bh(&filter->lock);

	/* Rotate if needed */
	replay_filter_rotate(filter);

	/* Check if all bits are set (potential replay) */
	for (i = 0; i < TQUIC_REPLAY_BLOOM_HASHES; i++) {
		if (!test_bit(indices[i], filter->bits)) {
			is_replay = false;
			break;
		}
	}

	if (is_replay) {
		spin_unlock_bh(&filter->lock);
		pr_debug("tquic: replay detected for ticket\n");
		return -EEXIST;
	}

	/* Set bits to mark ticket as seen */
	for (i = 0; i < TQUIC_REPLAY_BLOOM_HASHES; i++)
		set_bit(indices[i], filter->bits);

	spin_unlock_bh(&filter->lock);

	return 0;
}
EXPORT_SYMBOL_GPL(tquic_replay_filter_check);

/*
 * =============================================================================
 * Session Ticket Encoding/Decoding
 * =============================================================================
 */

int tquic_session_ticket_encode(const struct tquic_session_ticket_plaintext *plaintext,
				const u8 *ticket_key, u32 key_len,
				u8 *out, u32 *out_len)
{
	struct crypto_aead *aead;
	struct aead_request *req;
	struct scatterlist sg[2];
	u8 nonce[TQUIC_SESSION_TICKET_NONCE_LEN];
	u8 *payload;
	u32 payload_len, header_len;
	u8 *p;
	int ret;

	if (!plaintext || !ticket_key || !out || !out_len)
		return -EINVAL;

	if (key_len != TQUIC_SESSION_TICKET_KEY_LEN)
		return -EINVAL;

	/* Calculate payload size */
	payload_len = plaintext->psk_len + 4 + 8 + 2 +	/* PSK, max_age, creation_time, cipher */
		      1 + plaintext->alpn_len +		/* ALPN length + data */
		      4 + plaintext->transport_params_len;	/* TP length + data */

	header_len = 1 + TQUIC_SESSION_TICKET_NONCE_LEN;	/* Version + Nonce */

	if (*out_len < header_len + payload_len + TQUIC_SESSION_TICKET_TAG_LEN)
		return -ENOSPC;

	/* Allocate AEAD */
	aead = crypto_alloc_aead("gcm(aes)", 0, 0);
	if (IS_ERR(aead))
		return PTR_ERR(aead);

	ret = crypto_aead_setkey(aead, ticket_key, key_len);
	if (ret) {
		crypto_free_aead(aead);
		return ret;
	}

	crypto_aead_setauthsize(aead, TQUIC_SESSION_TICKET_TAG_LEN);

	/* Allocate request and payload buffer */
	req = aead_request_alloc(aead, GFP_KERNEL);
	if (!req) {
		crypto_free_aead(aead);
		return -ENOMEM;
	}

	payload = kmalloc(payload_len + TQUIC_SESSION_TICKET_TAG_LEN, GFP_KERNEL);
	if (!payload) {
		aead_request_free(req);
		crypto_free_aead(aead);
		return -ENOMEM;
	}

	/* Build payload */
	p = payload;

	/* PSK */
	memcpy(p, plaintext->psk, plaintext->psk_len);
	p += plaintext->psk_len;

	/* Max age (4 bytes, big-endian) */
	*p++ = (plaintext->max_age >> 24) & 0xff;
	*p++ = (plaintext->max_age >> 16) & 0xff;
	*p++ = (plaintext->max_age >> 8) & 0xff;
	*p++ = plaintext->max_age & 0xff;

	/* Creation time (8 bytes, big-endian) */
	*p++ = (plaintext->creation_time >> 56) & 0xff;
	*p++ = (plaintext->creation_time >> 48) & 0xff;
	*p++ = (plaintext->creation_time >> 40) & 0xff;
	*p++ = (plaintext->creation_time >> 32) & 0xff;
	*p++ = (plaintext->creation_time >> 24) & 0xff;
	*p++ = (plaintext->creation_time >> 16) & 0xff;
	*p++ = (plaintext->creation_time >> 8) & 0xff;
	*p++ = plaintext->creation_time & 0xff;

	/* Cipher suite (2 bytes, big-endian) */
	*p++ = (plaintext->cipher_suite >> 8) & 0xff;
	*p++ = plaintext->cipher_suite & 0xff;

	/* ALPN */
	*p++ = plaintext->alpn_len;
	memcpy(p, plaintext->alpn, plaintext->alpn_len);
	p += plaintext->alpn_len;

	/* Transport parameters */
	*p++ = (plaintext->transport_params_len >> 24) & 0xff;
	*p++ = (plaintext->transport_params_len >> 16) & 0xff;
	*p++ = (plaintext->transport_params_len >> 8) & 0xff;
	*p++ = plaintext->transport_params_len & 0xff;
	memcpy(p, plaintext->transport_params, plaintext->transport_params_len);

	/* Generate nonce */
	get_random_bytes(nonce, sizeof(nonce));

	/* Build output: Version || Nonce || Encrypted(payload) || Tag */
	out[0] = TQUIC_SESSION_TICKET_VERSION;
	memcpy(out + 1, nonce, sizeof(nonce));

	/* Encrypt payload */
	sg_init_one(&sg[0], payload, payload_len + TQUIC_SESSION_TICKET_TAG_LEN);
	aead_request_set_crypt(req, sg, sg, payload_len, nonce);
	aead_request_set_ad(req, 0);

	ret = crypto_aead_encrypt(req);
	if (ret) {
		kfree(payload);
		aead_request_free(req);
		crypto_free_aead(aead);
		return ret;
	}

	/* Copy encrypted payload + tag to output */
	memcpy(out + header_len, payload, payload_len + TQUIC_SESSION_TICKET_TAG_LEN);
	*out_len = header_len + payload_len + TQUIC_SESSION_TICKET_TAG_LEN;

	kfree(payload);
	aead_request_free(req);
	crypto_free_aead(aead);

	return 0;
}
EXPORT_SYMBOL_GPL(tquic_session_ticket_encode);

int tquic_session_ticket_decode(const u8 *ticket, u32 ticket_len,
				const u8 *ticket_key, u32 key_len,
				struct tquic_session_ticket_plaintext *out)
{
	struct crypto_aead *aead;
	struct aead_request *req;
	struct scatterlist sg[2];
	u8 nonce[TQUIC_SESSION_TICKET_NONCE_LEN];
	u8 *payload;
	u32 payload_len, header_len;
	const u8 *p;
	int ret;

	if (!ticket || !ticket_key || !out)
		return -EINVAL;

	header_len = 1 + TQUIC_SESSION_TICKET_NONCE_LEN;
	if (ticket_len < header_len + TQUIC_SESSION_TICKET_TAG_LEN)
		return -EINVAL;

	/* Check version */
	if (ticket[0] != TQUIC_SESSION_TICKET_VERSION)
		return -EPROTO;

	/* Extract nonce */
	memcpy(nonce, ticket + 1, sizeof(nonce));

	payload_len = ticket_len - header_len;

	/* Allocate AEAD */
	aead = crypto_alloc_aead("gcm(aes)", 0, 0);
	if (IS_ERR(aead))
		return PTR_ERR(aead);

	ret = crypto_aead_setkey(aead, ticket_key, key_len);
	if (ret) {
		crypto_free_aead(aead);
		return ret;
	}

	crypto_aead_setauthsize(aead, TQUIC_SESSION_TICKET_TAG_LEN);

	/* Allocate request and payload buffer */
	req = aead_request_alloc(aead, GFP_KERNEL);
	if (!req) {
		crypto_free_aead(aead);
		return -ENOMEM;
	}

	payload = kmalloc(payload_len, GFP_KERNEL);
	if (!payload) {
		aead_request_free(req);
		crypto_free_aead(aead);
		return -ENOMEM;
	}

	memcpy(payload, ticket + header_len, payload_len);

	/* Decrypt */
	sg_init_one(&sg[0], payload, payload_len);
	aead_request_set_crypt(req, sg, sg, payload_len, nonce);
	aead_request_set_ad(req, 0);

	ret = crypto_aead_decrypt(req);
	if (ret) {
		kfree(payload);
		aead_request_free(req);
		crypto_free_aead(aead);
		return ret;
	}

	payload_len -= TQUIC_SESSION_TICKET_TAG_LEN;

	/* Parse payload */
	memset(out, 0, sizeof(*out));
	p = payload;

	/* PSK (first 32 or 48 bytes based on cipher) */
	/* For simplicity, assume 32-byte PSK (SHA-256) */
	out->psk_len = 32;
	if (payload_len < out->psk_len + 4 + 8 + 2 + 1) {
		ret = -EINVAL;
		goto out_free;
	}
	memcpy(out->psk, p, out->psk_len);
	p += out->psk_len;

	/* Max age */
	out->max_age = (p[0] << 24) | (p[1] << 16) | (p[2] << 8) | p[3];
	p += 4;

	/* Creation time */
	out->creation_time = ((u64)p[0] << 56) | ((u64)p[1] << 48) |
			     ((u64)p[2] << 40) | ((u64)p[3] << 32) |
			     ((u64)p[4] << 24) | ((u64)p[5] << 16) |
			     ((u64)p[6] << 8) | (u64)p[7];
	p += 8;

	/* Cipher suite */
	out->cipher_suite = (p[0] << 8) | p[1];
	p += 2;

	/* ALPN */
	out->alpn_len = *p++;
	if (out->alpn_len > TQUIC_ALPN_MAX_LEN ||
	    p + out->alpn_len > payload + payload_len) {
		ret = -EINVAL;
		goto out_free;
	}
	memcpy(out->alpn, p, out->alpn_len);
	out->alpn[out->alpn_len] = '\0';
	p += out->alpn_len;

	/* Transport parameters */
	if (p + 4 > payload + payload_len) {
		ret = -EINVAL;
		goto out_free;
	}
	out->transport_params_len = (p[0] << 24) | (p[1] << 16) |
				    (p[2] << 8) | p[3];
	p += 4;

	if (out->transport_params_len > sizeof(out->transport_params) ||
	    p + out->transport_params_len > payload + payload_len) {
		ret = -EINVAL;
		goto out_free;
	}
	memcpy(out->transport_params, p, out->transport_params_len);

	ret = 0;

out_free:
	kfree(payload);
	aead_request_free(req);
	crypto_free_aead(aead);
	return ret;
}
EXPORT_SYMBOL_GPL(tquic_session_ticket_decode);

/*
 * =============================================================================
 * 0-RTT Connection Operations
 * =============================================================================
 */

int tquic_zero_rtt_init(struct tquic_connection *conn)
{
	struct tquic_zero_rtt_state_s *state;

	if (!conn)
		return -EINVAL;

	state = kzalloc(sizeof(*state), GFP_KERNEL);
	if (!state)
		return -ENOMEM;

	state->state = TQUIC_0RTT_NONE;
	conn->zero_rtt_state = state;

	return 0;
}
EXPORT_SYMBOL_GPL(tquic_zero_rtt_init);

void tquic_zero_rtt_cleanup(struct tquic_connection *conn)
{
	struct tquic_zero_rtt_state_s *state;

	if (!conn || !conn->zero_rtt_state)
		return;

	state = conn->zero_rtt_state;

	/* Securely wipe keys */
	memzero_explicit(&state->keys, sizeof(state->keys));

	/* Release ticket reference */
	if (state->ticket)
		tquic_zero_rtt_put_ticket(state->ticket);

	kfree(state);
	conn->zero_rtt_state = NULL;
}
EXPORT_SYMBOL_GPL(tquic_zero_rtt_cleanup);

int tquic_zero_rtt_attempt(struct tquic_connection *conn,
			   const char *server_name, u8 server_name_len)
{
	struct tquic_zero_rtt_state_s *state;
	struct tquic_session_ticket *ticket;
	int ret;

	if (!conn || !conn->zero_rtt_state)
		return -EINVAL;

	if (!tquic_sysctl_get_zero_rtt_enabled())
		return -ENOENT;

	state = conn->zero_rtt_state;

	/* Look up session ticket */
	ticket = tquic_zero_rtt_lookup_ticket(server_name, server_name_len);
	if (!ticket) {
		pr_debug("tquic: no session ticket for %.*s\n",
			 server_name_len, server_name);
		return -ENOENT;
	}

	/* Derive 0-RTT keys */
	ret = tquic_zero_rtt_derive_keys(&state->keys,
					 ticket->plaintext.psk,
					 ticket->plaintext.psk_len,
					 ticket->plaintext.cipher_suite);
	if (ret) {
		tquic_zero_rtt_put_ticket(ticket);
		return ret;
	}

	state->ticket = ticket;
	state->cipher_suite = ticket->plaintext.cipher_suite;
	state->state = TQUIC_0RTT_ATTEMPTING;
	state->early_data_max = 16384;	/* Default 16KB */
	state->early_data_sent = 0;

	pr_debug("tquic: attempting 0-RTT for %.*s\n",
		 server_name_len, server_name);

	return 0;
}
EXPORT_SYMBOL_GPL(tquic_zero_rtt_attempt);

int tquic_zero_rtt_accept(struct tquic_connection *conn)
{
	struct tquic_zero_rtt_state_s *state;
	int ret;

	if (!conn || !conn->zero_rtt_state)
		return -EINVAL;

	state = conn->zero_rtt_state;

	/* Check anti-replay */
	if (state->ticket) {
		ret = tquic_replay_filter_check(&global_replay_filter,
						state->ticket->ticket,
						state->ticket->ticket_len);
		if (ret == -EEXIST) {
			pr_debug("tquic: 0-RTT replay detected, rejecting\n");
			state->state = TQUIC_0RTT_REJECTED;
			return -EEXIST;
		}
	}

	state->state = TQUIC_0RTT_ACCEPTED;
	state->early_data_received = 0;

	pr_debug("tquic: 0-RTT accepted\n");

	/* MIB counter (TQUIC_MIB_0RTTACCEPTED) is updated by caller in tquic_input.c */

	return 0;
}
EXPORT_SYMBOL_GPL(tquic_zero_rtt_accept);

void tquic_zero_rtt_reject(struct tquic_connection *conn)
{
	struct tquic_zero_rtt_state_s *state;

	if (!conn || !conn->zero_rtt_state)
		return;

	state = conn->zero_rtt_state;
	state->state = TQUIC_0RTT_REJECTED;

	/* Wipe keys since they won't be used */
	memzero_explicit(&state->keys, sizeof(state->keys));

	pr_debug("tquic: 0-RTT rejected\n");
}
EXPORT_SYMBOL_GPL(tquic_zero_rtt_reject);

void tquic_zero_rtt_confirmed(struct tquic_connection *conn)
{
	struct tquic_zero_rtt_state_s *state;

	if (!conn || !conn->zero_rtt_state)
		return;

	state = conn->zero_rtt_state;

	if (state->state == TQUIC_0RTT_ATTEMPTING)
		state->state = TQUIC_0RTT_ACCEPTED;

	pr_debug("tquic: 0-RTT confirmed\n");
}
EXPORT_SYMBOL_GPL(tquic_zero_rtt_confirmed);

/*
 * =============================================================================
 * 0-RTT Packet Operations
 * =============================================================================
 */

bool tquic_zero_rtt_can_send(struct tquic_connection *conn)
{
	struct tquic_zero_rtt_state_s *state;

	if (!conn || !conn->zero_rtt_state)
		return false;

	state = conn->zero_rtt_state;

	if (state->state != TQUIC_0RTT_ATTEMPTING &&
	    state->state != TQUIC_0RTT_ACCEPTED)
		return false;

	if (!state->keys.valid)
		return false;

	if (state->early_data_sent >= state->early_data_max)
		return false;

	return true;
}
EXPORT_SYMBOL_GPL(tquic_zero_rtt_can_send);

/*
 * Create nonce for AEAD
 */
static void tquic_create_nonce(const u8 *iv, u64 pkt_num, u8 *nonce)
{
	int i;

	memcpy(nonce, iv, 12);
	for (i = 0; i < 8; i++)
		nonce[11 - i] ^= (pkt_num >> (i * 8)) & 0xff;
}

int tquic_zero_rtt_encrypt(struct tquic_connection *conn,
			   const u8 *header, size_t header_len,
			   const u8 *payload, size_t payload_len,
			   u64 pkt_num, u8 *out, size_t *out_len)
{
	struct tquic_zero_rtt_state_s *state;
	struct crypto_aead *aead;
	struct aead_request *req;
	struct scatterlist sg[2];
	u8 nonce[12];
	int ret;

	if (!conn || !conn->zero_rtt_state)
		return -EINVAL;

	state = conn->zero_rtt_state;
	if (!state->keys.valid)
		return -ENOKEY;

	/*
	 * CRITICAL: Ensure packet number is strictly increasing to prevent
	 * nonce reuse. In AEAD (AES-GCM, ChaCha20-Poly1305), reusing a nonce
	 * with the same key completely compromises the encryption - allowing
	 * plaintext recovery and authentication bypass.
	 *
	 * RFC 9001 Section 5.3: "The nonce, N, is formed by combining the
	 * packet protection IV with the packet number."
	 *
	 * Since packet numbers must be unique per key, we enforce strict
	 * monotonicity to guarantee nonce uniqueness.
	 */
	if (state->pn_initialized && pkt_num <= state->largest_sent_pn) {
		WARN_ONCE(1, "TQUIC: 0-RTT packet number reuse detected! "
			  "pn=%llu largest_sent=%llu - cryptographic compromise prevented\n",
			  pkt_num, state->largest_sent_pn);
		return -EINVAL;
	}

	/* Allocate AEAD */
	aead = crypto_alloc_aead(tquic_cipher_to_aead_name(state->cipher_suite), 0, 0);
	if (IS_ERR(aead))
		return PTR_ERR(aead);

	ret = crypto_aead_setkey(aead, state->keys.key, state->keys.key_len);
	if (ret) {
		crypto_free_aead(aead);
		return ret;
	}

	crypto_aead_setauthsize(aead, 16);

	req = aead_request_alloc(aead, GFP_ATOMIC);
	if (!req) {
		crypto_free_aead(aead);
		return -ENOMEM;
	}

	tquic_create_nonce(state->keys.iv, pkt_num, nonce);

	/* Copy payload to output for in-place encryption */
	memcpy(out, payload, payload_len);

	sg_init_table(sg, 2);
	sg_set_buf(&sg[0], header, header_len);
	sg_set_buf(&sg[1], out, payload_len + 16);

	aead_request_set_crypt(req, sg, sg, payload_len, nonce);
	aead_request_set_ad(req, header_len);

	ret = crypto_aead_encrypt(req);

	aead_request_free(req);
	crypto_free_aead(aead);

	if (ret == 0) {
		*out_len = payload_len + 16;
		state->early_data_sent += payload_len;
		/* Update largest sent packet number after successful encryption */
		state->largest_sent_pn = pkt_num;
		state->pn_initialized = true;
	}

	return ret;
}
EXPORT_SYMBOL_GPL(tquic_zero_rtt_encrypt);

int tquic_zero_rtt_decrypt(struct tquic_connection *conn,
			   const u8 *header, size_t header_len,
			   u8 *payload, size_t payload_len,
			   u64 pkt_num, u8 *out, size_t *out_len)
{
	struct tquic_zero_rtt_state_s *state;
	struct crypto_aead *aead;
	struct aead_request *req;
	struct scatterlist sg[2];
	u8 nonce[12];
	int ret;

	if (!conn || !conn->zero_rtt_state)
		return -EINVAL;

	state = conn->zero_rtt_state;
	if (!state->keys.valid)
		return -ENOKEY;

	if (payload_len < 16)
		return -EINVAL;

	/*
	 * Replay protection: Check that packet number is greater than
	 * the largest received packet number. While QUIC allows out-of-order
	 * delivery, packets with very old packet numbers are suspicious.
	 *
	 * RFC 9000 Section 13.2.3: "Endpoints MUST discard packets that are
	 * too old to be decoded or that have packet numbers that have been
	 * previously received."
	 *
	 * Note: A full implementation would use a sliding window to allow
	 * some reordering while still detecting replays. For 0-RTT early data,
	 * we use strict ordering as a conservative approach since 0-RTT data
	 * is particularly sensitive to replay attacks (RFC 9001 Section 9.2).
	 */
	if (state->pn_initialized && pkt_num <= state->largest_recv_pn) {
		pr_debug("TQUIC: 0-RTT potential replay detected - "
			 "pn=%llu largest_recv=%llu\n",
			 pkt_num, state->largest_recv_pn);
		return -EINVAL;
	}

	/* Allocate AEAD */
	aead = crypto_alloc_aead(tquic_cipher_to_aead_name(state->cipher_suite), 0, 0);
	if (IS_ERR(aead))
		return PTR_ERR(aead);

	ret = crypto_aead_setkey(aead, state->keys.key, state->keys.key_len);
	if (ret) {
		crypto_free_aead(aead);
		return ret;
	}

	crypto_aead_setauthsize(aead, 16);

	req = aead_request_alloc(aead, GFP_ATOMIC);
	if (!req) {
		crypto_free_aead(aead);
		return -ENOMEM;
	}

	tquic_create_nonce(state->keys.iv, pkt_num, nonce);

	sg_init_table(sg, 2);
	sg_set_buf(&sg[0], header, header_len);
	sg_set_buf(&sg[1], payload, payload_len);

	aead_request_set_crypt(req, sg, sg, payload_len, nonce);
	aead_request_set_ad(req, header_len);

	ret = crypto_aead_decrypt(req);

	aead_request_free(req);
	crypto_free_aead(aead);

	if (ret == 0) {
		*out_len = payload_len - 16;
		memcpy(out, payload, *out_len);
		state->early_data_received += *out_len;
		/*
		 * Update largest received packet number after successful
		 * decryption for replay protection. Only update if this
		 * packet number is larger (allows for some reordering in
		 * the case where strict check above is relaxed).
		 */
		if (!state->pn_initialized || pkt_num > state->largest_recv_pn) {
			state->largest_recv_pn = pkt_num;
			state->pn_initialized = true;
		}
	}

	return ret;
}
EXPORT_SYMBOL_GPL(tquic_zero_rtt_decrypt);

/*
 * =============================================================================
 * State Query
 * =============================================================================
 */

enum tquic_zero_rtt_state tquic_zero_rtt_get_state(struct tquic_connection *conn)
{
	struct tquic_zero_rtt_state_s *state;

	if (!conn || !conn->zero_rtt_state)
		return TQUIC_0RTT_NONE;

	state = conn->zero_rtt_state;
	return state->state;
}
EXPORT_SYMBOL_GPL(tquic_zero_rtt_get_state);

const char *tquic_zero_rtt_state_name(enum tquic_zero_rtt_state state)
{
	switch (state) {
	case TQUIC_0RTT_NONE:
		return "NONE";
	case TQUIC_0RTT_ATTEMPTING:
		return "ATTEMPTING";
	case TQUIC_0RTT_ACCEPTED:
		return "ACCEPTED";
	case TQUIC_0RTT_REJECTED:
		return "REJECTED";
	default:
		return "UNKNOWN";
	}
}
EXPORT_SYMBOL_GPL(tquic_zero_rtt_state_name);

/*
 * =============================================================================
 * Module Initialization
 * =============================================================================
 *
 * Note: Sysctl accessor functions (tquic_sysctl_get_zero_rtt_enabled and
 * tquic_sysctl_get_zero_rtt_max_age) are implemented in tquic_sysctl.c
 * along with the other sysctl-related code.
 */

int __init tquic_zero_rtt_module_init(void)
{
	int ret;

	/* Initialize global ticket store */
	spin_lock_init(&global_ticket_store.lock);
	global_ticket_store.tickets = RB_ROOT;
	INIT_LIST_HEAD(&global_ticket_store.lru_list);
	global_ticket_store.count = 0;
	global_ticket_store.max_count = 1024;	/* Default max tickets */

	/*
	 * Initialize replay filter hash seeds with cryptographically
	 * random values to prevent hash prediction attacks.
	 */
	get_random_bytes(&replay_hash_seed1, sizeof(replay_hash_seed1));
	get_random_bytes(&replay_hash_seed2, sizeof(replay_hash_seed2));

	/* Initialize global replay filter */
	ret = tquic_replay_filter_init(&global_replay_filter,
				       TQUIC_REPLAY_TTL_SECONDS);
	if (ret) {
		pr_err("tquic: failed to initialize replay filter: %d\n", ret);
		return ret;
	}

	/* Generate server ticket key */
	get_random_bytes(server_ticket_key, sizeof(server_ticket_key));
	server_ticket_key_valid = true;

	pr_info("tquic: 0-RTT early data support initialized\n");

	return 0;
}

void __exit tquic_zero_rtt_module_exit(void)
{
	struct tquic_session_ticket *ticket, *tmp;

	/* Clean up ticket store */
	spin_lock_bh(&global_ticket_store.lock);
	list_for_each_entry_safe(ticket, tmp, &global_ticket_store.lru_list, list) {
		ticket_store_remove_locked(&global_ticket_store, ticket);
		ticket_free(ticket);
	}
	spin_unlock_bh(&global_ticket_store.lock);

	/* Clean up replay filter */
	tquic_replay_filter_cleanup(&global_replay_filter);

	/* Wipe server ticket key */
	memzero_explicit(server_ticket_key, sizeof(server_ticket_key));
	server_ticket_key_valid = false;

	pr_info("tquic: 0-RTT early data support cleaned up\n");
}

MODULE_DESCRIPTION("TQUIC 0-RTT Early Data Support (RFC 9001)");
MODULE_LICENSE("GPL");
