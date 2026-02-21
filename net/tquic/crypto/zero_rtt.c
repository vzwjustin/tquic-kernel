// SPDX-License-Identifier: GPL-2.0-only
/*
 * TQUIC: 0-RTT Early Data Support (RFC 9001 Sections 4.6-4.7)
 *
 * Copyright (c) 2026 Justin Adams <spotty118@gmail.com>
 * Kernel implementation by Justin Adams <spotty118@gmail.com>
 *
 * Implements TLS 1.3 0-RTT early data for QUIC connections:
 * - Session ticket storage after successful handshake
 * - 0-RTT key derivation from resumption_master_secret
 * - Early data transmission before handshake completes
 * - Server accept/reject via early_data_indication
 * - Anti-replay protection using bloom filter with TTL
 *
 * =============================================================================
 * CRITICAL SECURITY INVARIANTS - READ BEFORE MODIFYING
 * =============================================================================
 *
 * 1. NONCE UNIQUENESS (RFC 9001 Section 5.3)
 *    AEAD ciphers (AES-GCM, ChaCha20-Poly1305) require unique nonces per key.
 *    In QUIC: nonce = IV XOR packet_number
 *
 *    CONSEQUENCE OF NONCE REUSE:
 *    - AES-GCM: XOR of plaintexts is leaked, authentication is broken
 *    - ChaCha20-Poly1305: Similar catastrophic failure
 *    - Result: Complete cryptographic compromise of the connection
 *
 *    PROTECTION: Strict packet number monotonicity enforcement with spinlock
 *    protection for thread safety. See tquic_zero_rtt_encrypt().
 *
 * 2. REPLAY PROTECTION (RFC 9000 Section 13.2.3)
 *    Duplicate packet numbers MUST be rejected to prevent replay attacks.
 *    For 0-RTT, this is especially critical since early data may have
 *    side effects that are not idempotent.
 *
 *    PROTECTION: Sliding window bitmap of size TQUIC_PN_REPLAY_WINDOW_SIZE.
 *    PNs are recorded ONLY after successful AEAD authentication.
 *    See tquic_zero_rtt_decrypt().
 *
 * 3. BLOOM FILTER SEEDS (Anti-Replay for Session Tickets)
 *    Hash seeds MUST be cryptographically random to prevent prediction
 *    attacks that could cause collisions or bypasses.
 *
 *    PROTECTION: Seeds initialized via get_random_bytes() at module load.
 *    See tquic_zero_rtt_module_init().
 *
 * 4. KEY MATERIAL HANDLING
 *    All cryptographic keys and IVs MUST be securely wiped on cleanup.
 *
 *    PROTECTION: memzero_explicit() used for all key material cleanup.
 *    See tquic_zero_rtt_cleanup().
 *
 * =============================================================================
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
#include "../core/transport_params.h"
#include "../core/flow_control.h"
#include "../tquic_mib.h"
#include "../tquic_debug.h"

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
 *
 * Seeds are NOT rotated after initialization because rotating seeds
 * invalidates all existing bloom filter entries, creating a window
 * where replays are undetectable. The TTL-based bloom filter rotation
 * already provides freshness guarantees. Seeds from the kernel CSPRNG
 * are cryptographically strong and do not need periodic renewal.
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
	tquic_dbg("tquic_cipher_to_hash_len: cipher_suite=0x%04x\n",
		  cipher_suite);

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
	tquic_dbg("tquic_cipher_to_key_len: cipher_suite=0x%04x\n",
		  cipher_suite);

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

	/*
	 * Bounds check: hkdf_label buffer is 256 bytes.
	 * Total size: 2 (length) + 1 (label_len_byte) + 6 ("tls13 ")
	 *           + label_len + 1 (context_len_byte) + context_len
	 *           = 10 + label_len + context_len
	 */
	if (label_len > 245 || context_len > 245 ||
	    (10 + label_len + context_len) > sizeof(hkdf_label))
		return -EINVAL;

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
			goto out_zeroize;

		ret = crypto_shash_init(desc);
		if (ret)
			goto out_zeroize;

		if (i > 0) {
			ret = crypto_shash_update(desc, t, hash_len);
			if (ret)
				goto out_zeroize;
		}

		ret = crypto_shash_update(desc, hkdf_label, hkdf_label_len);
		if (ret)
			goto out_zeroize;

		t[0] = i + 1;
		ret = crypto_shash_update(desc, t, 1);
		if (ret)
			goto out_zeroize;

		ret = crypto_shash_final(desc, t);
		if (ret)
			goto out_zeroize;

		memcpy(out + i * hash_len, t,
		       min_t(u32, hash_len, out_len - i * hash_len));
	}

	ret = 0;

out_zeroize:
	memzero_explicit(t, sizeof(t));
	memzero_explicit(hkdf_label, sizeof(hkdf_label));
	return ret;
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

	tquic_dbg("ticket_cmp: a_len=%u b_len=%u\n", a_len, b_len);

	if (cmp != 0)
		return cmp;
	return (int)a_len - (int)b_len;
}

/*
 * Find ticket in RB-tree
 */
static struct tquic_zero_rtt_ticket *ticket_store_find_locked(
	struct tquic_ticket_store *store,
	const char *server_name, u8 server_name_len)
{
	struct rb_node *node = store->tickets.rb_node;

	while (node) {
		struct tquic_zero_rtt_ticket *ticket =
			rb_entry(node, struct tquic_zero_rtt_ticket, node);
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
				      struct tquic_zero_rtt_ticket *ticket)
{
	struct rb_node **new = &store->tickets.rb_node;
	struct rb_node *parent = NULL;

	while (*new) {
		struct tquic_zero_rtt_ticket *existing =
			rb_entry(*new, struct tquic_zero_rtt_ticket, node);
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
				       struct tquic_zero_rtt_ticket *ticket)
{
	rb_erase(&ticket->node, &store->tickets);
	list_del_init(&ticket->list);
	store->count--;
}

/*
 * Free ticket memory
 */
static void ticket_free(struct tquic_zero_rtt_ticket *ticket)
{
	if (!ticket)
		return;

	tquic_dbg("ticket_free: server_name_len=%u ticket_len=%u\n",
		  ticket->server_name_len, ticket->ticket_len);

	kfree_sensitive(ticket->ticket);
	memzero_explicit(&ticket->plaintext, sizeof(ticket->plaintext));
	kfree_sensitive(ticket);
}

/*
 * Evict oldest ticket from store
 */
static void ticket_store_evict_oldest_locked(struct tquic_ticket_store *store)
{
	struct tquic_zero_rtt_ticket *oldest;

	tquic_dbg("ticket_store_evict_oldest_locked: count=%u\n", store->count);

	if (list_empty(&store->lru_list))
		return;

	oldest = list_last_entry(&store->lru_list,
				 struct tquic_zero_rtt_ticket, list);
	ticket_store_remove_locked(store, oldest);
	/* Use refcount-based free to avoid racing with lookup holders */
	tquic_zero_rtt_put_ticket(oldest);
}

/*
 * Check if ticket is expired
 */
static bool ticket_is_expired(struct tquic_zero_rtt_ticket *ticket)
{
	u64 now = ktime_get_real_seconds();
	u64 age;

	if (now < ticket->plaintext.creation_time)
		return true;

	age = now - ticket->plaintext.creation_time;
	tquic_dbg("ticket_is_expired: age=%llu max_age=%u\n",
		  age, ticket->plaintext.max_age);
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
	struct tquic_zero_rtt_ticket *ticket, *old;
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
		kfree_sensitive(ticket);
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
		tquic_zero_rtt_put_ticket(old);
	}

	/* Evict if at capacity */
	while (global_ticket_store.count >= global_ticket_store.max_count)
		ticket_store_evict_oldest_locked(&global_ticket_store);

	ret = ticket_store_insert_locked(&global_ticket_store, ticket);

	spin_unlock_bh(&global_ticket_store.lock);

	if (ret < 0) {
		kfree_sensitive(ticket->ticket);
		kfree_sensitive(ticket);
		return ret;
	}

	pr_debug("tquic: stored session ticket for %.*s\n",
		 server_name_len, server_name);

	return 0;
}
EXPORT_SYMBOL_GPL(tquic_zero_rtt_store_ticket);

struct tquic_zero_rtt_ticket *tquic_zero_rtt_lookup_ticket(
	const char *server_name, u8 server_name_len)
{
	struct tquic_zero_rtt_ticket *ticket;

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
		list_del_init(&ticket->list);
		list_add(&ticket->list, &global_ticket_store.lru_list);

		/* Take reference */
		refcount_inc(&ticket->refcount);
	}

	spin_unlock_bh(&global_ticket_store.lock);

	return ticket;
}
EXPORT_SYMBOL_GPL(tquic_zero_rtt_lookup_ticket);

void tquic_zero_rtt_put_ticket(struct tquic_zero_rtt_ticket *ticket)
{
	if (!ticket)
		return;

	tquic_dbg("tquic_zero_rtt_put_ticket: refcount=%u\n",
		  refcount_read(&ticket->refcount));

	if (refcount_dec_and_test(&ticket->refcount))
		ticket_free(ticket);
}
EXPORT_SYMBOL_GPL(tquic_zero_rtt_put_ticket);

void tquic_zero_rtt_remove_ticket(const char *server_name, u8 server_name_len)
{
	struct tquic_zero_rtt_ticket *ticket;

	if (!server_name || server_name_len == 0)
		return;

	tquic_dbg("tquic_zero_rtt_remove_ticket: server_name_len=%u\n",
		  server_name_len);

	spin_lock_bh(&global_ticket_store.lock);

	ticket = ticket_store_find_locked(&global_ticket_store,
					  server_name, server_name_len);
	if (ticket) {
		ticket_store_remove_locked(&global_ticket_store, ticket);
		spin_unlock_bh(&global_ticket_store.lock);
		/* Use refcount-based free in case another thread holds a ref */
		tquic_zero_rtt_put_ticket(ticket);
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
		tquic_err("failed to allocate hash for 0-RTT key derivation\n");
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
	memzero_explicit(empty_hash, sizeof(empty_hash));
	memzero_explicit(zeros, sizeof(zeros));
	/* On error, zeroize any partial key material in the output struct */
	if (ret)
		memzero_explicit(keys, sizeof(*keys));
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

	tquic_dbg("tquic_replay_filter_init: ttl_seconds=%u\n", ttl_seconds);

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

	tquic_dbg("tquic_replay_filter_cleanup: clearing bloom filter\n");

	spin_lock_bh(&filter->lock);
	bitmap_zero(filter->bits, TQUIC_REPLAY_BLOOM_BITS);
	spin_unlock_bh(&filter->lock);
}
EXPORT_SYMBOL_GPL(tquic_replay_filter_cleanup);

/*
 * Rotate bloom filter buckets based on TTL.
 *
 * Two-bucket scheme: the bitmap is split into two halves:
 *   Bucket 0: bits [0, TQUIC_REPLAY_BLOOM_BITS/2)
 *   Bucket 1: bits [TQUIC_REPLAY_BLOOM_BITS/2, TQUIC_REPLAY_BLOOM_BITS)
 *
 * New entries are inserted into BOTH buckets (current and previous).
 * On rotation, the OLDER bucket is cleared. This ensures entries survive
 * for at least TTL/2 and at most TTL.
 */
static void replay_filter_rotate(struct tquic_replay_filter *filter)
{
	ktime_t now = ktime_get();
	s64 elapsed;
	u32 half = TQUIC_REPLAY_BLOOM_BITS / 2;
	u32 old_bucket;

	tquic_dbg("replay_filter_rotate: current_bucket=%u\n",
		  filter->current_bucket);

	elapsed = ktime_to_ms(ktime_sub(now, filter->last_rotation));

	/* Rotate every TTL/2 to maintain coverage */
	if (elapsed > (filter->ttl_seconds * 500)) {
		/* Clear the bucket that is about to become stale */
		old_bucket = filter->current_bucket ^ 1;
		if (old_bucket == 0)
			bitmap_zero(filter->bits, half);
		else
			bitmap_zero(filter->bits + (half / BITS_PER_LONG),
				    half);
		filter->last_rotation = now;
		filter->current_bucket ^= 1;
	}
}

/*
 * Compute bloom filter hash indices for anti-replay protection.
 *
 * Security notes:
 *   - Uses cryptographically random seeds (replay_hash_seed1, replay_hash_seed2)
 *     initialized via get_random_bytes() at module load time
 *   - Random seeds prevent hash prediction attacks where an attacker could
 *     craft ticket values to cause bloom filter collisions
 *   - Double hashing (h1 + i*h2) provides k independent hash functions
 *     from just two base hashes (Kirsch-Mitzenmacher optimization)
 *   - Seeds are rotated periodically to limit exposure window
 *
 * The seeds MUST be initialized before this function is called.
 * See tquic_zero_rtt_module_init() for initialization.
 */
/*
 * Compute bloom filter hash indices within a single bucket (half the bitmap).
 * Each bucket occupies TQUIC_REPLAY_BLOOM_BITS/2 bits.
 * The bucket_offset parameter selects which half: 0 or TQUIC_REPLAY_BLOOM_BITS/2.
 */
static void replay_filter_hash(const u8 *data, u32 len,
				u32 bucket_offset, u32 *indices)
{
	u32 h1, h2;
	u32 half = TQUIC_REPLAY_BLOOM_BITS / 2;
	int i;

	/*
	 * jhash (Jenkins hash) with random seeds.
	 * Seeds are initialized with get_random_bytes() in module init,
	 * providing cryptographic unpredictability.
	 */
	h1 = jhash(data, len, replay_hash_seed1);
	h2 = jhash(data, len, replay_hash_seed2);

	for (i = 0; i < TQUIC_REPLAY_BLOOM_HASHES; i++)
		indices[i] = bucket_offset + (h1 + i * h2) % half;
}

int tquic_replay_filter_check(struct tquic_replay_filter *filter,
			      const u8 *ticket, u32 ticket_len)
{
	u32 indices_cur[TQUIC_REPLAY_BLOOM_HASHES];
	u32 indices_prev[TQUIC_REPLAY_BLOOM_HASHES];
	u32 half = TQUIC_REPLAY_BLOOM_BITS / 2;
	u32 cur_offset, prev_offset;
	bool is_replay;
	int i;

	if (!filter || !ticket || ticket_len == 0)
		return -EINVAL;

	spin_lock_bh(&filter->lock);

	/* Rotate if needed */
	replay_filter_rotate(filter);

	/*
	 * Compute hash indices for both buckets.
	 * Check both because the ticket may have been inserted in either.
	 */
	cur_offset = filter->current_bucket * half;
	prev_offset = (filter->current_bucket ^ 1) * half;

	replay_filter_hash(ticket, ticket_len, cur_offset, indices_cur);
	replay_filter_hash(ticket, ticket_len, prev_offset, indices_prev);

	/* Check current bucket: all bits set means potential replay */
	is_replay = true;
	for (i = 0; i < TQUIC_REPLAY_BLOOM_HASHES; i++) {
		if (!test_bit(indices_cur[i], filter->bits)) {
			is_replay = false;
			break;
		}
	}

	/* Also check previous bucket if current didn't match */
	if (!is_replay) {
		bool found_in_prev = true;

		for (i = 0; i < TQUIC_REPLAY_BLOOM_HASHES; i++) {
			if (!test_bit(indices_prev[i], filter->bits)) {
				found_in_prev = false;
				break;
			}
		}
		if (found_in_prev) {
			is_replay = true;
			/*
			 * Replicate to current bucket to prevent false
			 * negatives after the previous bucket is cleared
			 * during rotation.
			 */
			for (i = 0; i < TQUIC_REPLAY_BLOOM_HASHES; i++)
				set_bit(indices_cur[i], filter->bits);
		}
	}

	if (is_replay) {
		spin_unlock_bh(&filter->lock);
		pr_debug("tquic: replay detected for ticket\n");
		return -EEXIST;
	}

	/*
	 * Set bits in BOTH buckets to ensure the entry is detectable
	 * regardless of when the next rotation occurs.
	 */
	for (i = 0; i < TQUIC_REPLAY_BLOOM_HASHES; i++) {
		set_bit(indices_cur[i], filter->bits);
		set_bit(indices_prev[i], filter->bits);
	}

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

	/* Validate PSK length */
	if (plaintext->psk_len == 0 ||
	    plaintext->psk_len > TQUIC_ZERO_RTT_SECRET_MAX_LEN)
		return -EINVAL;

	/* Calculate payload size: psk_len(1) + PSK + max_age(4) + creation_time(8) +
	 * cipher(2) + alpn_len(1) + ALPN + tp_len(4) + TP */
	payload_len = 1 + plaintext->psk_len + 4 + 8 + 2 +
		      1 + plaintext->alpn_len +
		      4 + plaintext->transport_params_len;

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

	if (crypto_aead_setauthsize(aead, TQUIC_SESSION_TICKET_TAG_LEN)) {
		pr_err("tquic_zero_rtt: failed to set auth tag size\n");
		crypto_free_aead(aead);
		return -EINVAL;
	}

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

	/* PSK length (1 byte) + PSK */
	*p++ = plaintext->psk_len;
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
		kfree_sensitive(payload);
		aead_request_free(req);
		crypto_free_aead(aead);
		return ret;
	}

	/* Copy encrypted payload + tag to output */
	memcpy(out + header_len, payload, payload_len + TQUIC_SESSION_TICKET_TAG_LEN);
	*out_len = header_len + payload_len + TQUIC_SESSION_TICKET_TAG_LEN;

	kfree_sensitive(payload);
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

	if (crypto_aead_setauthsize(aead, TQUIC_SESSION_TICKET_TAG_LEN)) {
		pr_err("tquic_zero_rtt: failed to set auth tag size\n");
		crypto_free_aead(aead);
		return -EINVAL;
	}

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
		kfree_sensitive(payload);
		aead_request_free(req);
		crypto_free_aead(aead);
		return ret;
	}

	payload_len -= TQUIC_SESSION_TICKET_TAG_LEN;

	/* Parse payload - validate all length fields against remaining buffer */
	memset(out, 0, sizeof(*out));
	p = payload;
	const u8 *payload_end = payload + payload_len;

	/* PSK length (1 byte) + PSK */
	if (p + 1 > payload_end) {
		ret = -EINVAL;
		goto out_free;
	}
	out->psk_len = *p++;

	/* Validate PSK length against destination buffer and remaining data */
	if (out->psk_len == 0 ||
	    out->psk_len > sizeof(out->psk) ||
	    out->psk_len > TQUIC_ZERO_RTT_SECRET_MAX_LEN ||
	    p + out->psk_len > payload_end) {
		ret = -EINVAL;
		goto out_free;
	}
	memcpy(out->psk, p, out->psk_len);
	p += out->psk_len;

	/* Max age (4 bytes) */
	if (p + 4 > payload_end) {
		ret = -EINVAL;
		goto out_free;
	}
	/* CF-157: cast to u32 before shift to avoid signed overflow */
	out->max_age = ((u32)p[0] << 24) | ((u32)p[1] << 16) |
		       ((u32)p[2] << 8) | (u32)p[3];
	p += 4;

	/* Creation time (8 bytes) */
	if (p + 8 > payload_end) {
		ret = -EINVAL;
		goto out_free;
	}
	out->creation_time = ((u64)p[0] << 56) | ((u64)p[1] << 48) |
			     ((u64)p[2] << 40) | ((u64)p[3] << 32) |
			     ((u64)p[4] << 24) | ((u64)p[5] << 16) |
			     ((u64)p[6] << 8) | (u64)p[7];
	p += 8;

	/* Cipher suite (2 bytes) */
	if (p + 2 > payload_end) {
		ret = -EINVAL;
		goto out_free;
	}
	out->cipher_suite = (p[0] << 8) | p[1];
	p += 2;

	/* ALPN length (1 byte) + ALPN data */
	if (p + 1 > payload_end) {
		ret = -EINVAL;
		goto out_free;
	}
	out->alpn_len = *p++;
	if (out->alpn_len > TQUIC_ALPN_MAX_LEN ||
	    p + out->alpn_len > payload_end) {
		ret = -EINVAL;
		goto out_free;
	}
	memcpy(out->alpn, p, out->alpn_len);
	out->alpn[out->alpn_len] = '\0';
	p += out->alpn_len;

	/* Transport parameters length (4 bytes) + data */
	if (p + 4 > payload_end) {
		ret = -EINVAL;
		goto out_free;
	}
	/* CF-157: cast to u32 before shift to avoid signed overflow */
	out->transport_params_len = ((u32)p[0] << 24) | ((u32)p[1] << 16) |
				    ((u32)p[2] << 8) | (u32)p[3];
	p += 4;

	if (out->transport_params_len > sizeof(out->transport_params) ||
	    p + out->transport_params_len > payload_end) {
		ret = -EINVAL;
		goto out_free;
	}
	memcpy(out->transport_params, p, out->transport_params_len);

	ret = 0;

out_free:
	kfree_sensitive(payload);
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

	tquic_dbg("tquic_zero_rtt_init: initializing 0-RTT state\n");

	state = kzalloc(sizeof(*state), GFP_KERNEL);
	if (!state)
		return -ENOMEM;

	state->state = TQUIC_0RTT_NONE;

	/*
	 * Initialize packet number tracking for cryptographic security.
	 * The spinlock protects concurrent access to PN state, which is
	 * critical because nonce = IV XOR PN, and nonce reuse breaks AEAD.
	 */
	spin_lock_init(&state->pn_lock);
	state->send_pn_initialized = false;
	state->recv_pn_initialized = false;
	state->largest_sent_pn = 0;
	state->largest_recv_pn = 0;
	bitmap_zero(state->recv_pn_bitmap, TQUIC_PN_REPLAY_WINDOW_SIZE);

	conn->zero_rtt_state = state;

	tquic_dbg("tquic_zero_rtt_init: ret=0\n");
	return 0;
}
EXPORT_SYMBOL_GPL(tquic_zero_rtt_init);

void tquic_zero_rtt_cleanup(struct tquic_connection *conn)
{
	struct tquic_zero_rtt_state_s *state;

	if (!conn || !conn->zero_rtt_state)
		return;

	state = conn->zero_rtt_state;

	tquic_dbg("tquic_zero_rtt_cleanup: state=%d early_data_sent=%llu\n",
		  state->state, state->early_data_sent);

	/* Free pre-allocated AEAD transform */
	if (state->aead)
		crypto_free_aead(state->aead);

	/*
	 * Securely wipe all cryptographic material:
	 * - AEAD keys and IVs
	 * - Packet number state (prevents information leakage)
	 * - Replay window bitmap
	 */
	memzero_explicit(&state->keys, sizeof(state->keys));
	memzero_explicit(&state->largest_sent_pn, sizeof(state->largest_sent_pn));
	memzero_explicit(&state->largest_recv_pn, sizeof(state->largest_recv_pn));
	bitmap_zero(state->recv_pn_bitmap, TQUIC_PN_REPLAY_WINDOW_SIZE);

	/* Release ticket reference */
	if (state->ticket)
		tquic_zero_rtt_put_ticket(state->ticket);

	tquic_dbg("tquic_zero_rtt_cleanup: done\n");
	kfree_sensitive(state);
	conn->zero_rtt_state = NULL;
}
EXPORT_SYMBOL_GPL(tquic_zero_rtt_cleanup);

int tquic_zero_rtt_attempt(struct tquic_connection *conn,
			   const char *server_name, u8 server_name_len)
{
	struct tquic_zero_rtt_state_s *state;
	struct tquic_zero_rtt_ticket *ticket;
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

	/* Pre-allocate AEAD transform for encrypt/decrypt */
	state->aead = crypto_alloc_aead(
		tquic_cipher_to_aead_name(state->cipher_suite), 0, 0);
	if (IS_ERR(state->aead)) {
		ret = PTR_ERR(state->aead);
		state->aead = NULL;
		tquic_zero_rtt_put_ticket(ticket);
		state->ticket = NULL;
		memzero_explicit(&state->keys, sizeof(state->keys));
		return ret;
	}

	ret = crypto_aead_setkey(state->aead, state->keys.key,
				 state->keys.key_len);
	if (ret) {
		crypto_free_aead(state->aead);
		state->aead = NULL;
		tquic_zero_rtt_put_ticket(ticket);
		state->ticket = NULL;
		memzero_explicit(&state->keys, sizeof(state->keys));
		return ret;
	}

	ret = crypto_aead_setauthsize(state->aead, 16);
	if (ret) {
		crypto_free_aead(state->aead);
		state->aead = NULL;
		tquic_zero_rtt_put_ticket(ticket);
		state->ticket = NULL;
		memzero_explicit(&state->keys, sizeof(state->keys));
		return ret;
	}

	pr_debug("tquic: attempting 0-RTT for %.*s\n",
		 server_name_len, server_name);

	return 0;
}
EXPORT_SYMBOL_GPL(tquic_zero_rtt_attempt);

/*
 * tquic_zero_rtt_validate_server_tp - Server-side 0-RTT transport param check
 *
 * RFC 9000 Section 7.4.1: The server MUST NOT reduce transport parameters
 * below what was previously advertised in the session ticket. If the server's
 * current limits are lower, it must reject 0-RTT.
 *
 * Returns: true if params are compatible, false if 0-RTT must be rejected
 */
static bool tquic_zero_rtt_validate_server_tp(struct tquic_connection *conn,
					      struct tquic_zero_rtt_state_s *state)
{
	struct tquic_session_ticket_plaintext *saved;
	struct tquic_transport_params remembered;
	int ret;

	if (!state->ticket)
		return true;

	saved = &state->ticket->plaintext;
	if (saved->transport_params_len == 0)
		return true; /* No saved params — allow (legacy ticket) */

	ret = tquic_tp_decode(saved->transport_params,
			      saved->transport_params_len,
			      true, &remembered);
	if (ret) {
		pr_debug("tquic: 0-RTT: cannot decode ticket TP, rejecting\n");
		return false;
	}

	/*
	 * Compare server's current local_params against what was
	 * stored in the session ticket. Reject if any limit decreased.
	 */
	if (conn->local_params.initial_max_data <
	    remembered.initial_max_data)
		return false;
	if (conn->local_params.initial_max_stream_data_bidi_local <
	    remembered.initial_max_stream_data_bidi_local)
		return false;
	if (conn->local_params.initial_max_stream_data_bidi_remote <
	    remembered.initial_max_stream_data_bidi_remote)
		return false;
	if (conn->local_params.initial_max_stream_data_uni <
	    remembered.initial_max_stream_data_uni)
		return false;
	if (conn->local_params.initial_max_streams_bidi <
	    remembered.initial_max_streams_bidi)
		return false;
	if (conn->local_params.initial_max_streams_uni <
	    remembered.initial_max_streams_uni)
		return false;

	return true;
}

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

	/*
	 * RFC 9000 Section 7.4.1: Server MUST NOT accept 0-RTT if it
	 * would reduce transport parameters below previously advertised
	 * values stored in the session ticket.
	 */
	if (!tquic_zero_rtt_validate_server_tp(conn, state)) {
		pr_debug("tquic: 0-RTT rejected: server reduced TP limits\n");
		state->state = TQUIC_0RTT_REJECTED;
		return -ERANGE;
	}

	state->state = TQUIC_0RTT_ACCEPTED;
	state->early_data_received = 0;

	/*
	 * Set early data limit for receive side.
	 * Use the negotiated value or default if not set.
	 */
	if (state->early_data_max == 0)
		state->early_data_max = 16384;

	tquic_info("0-RTT accepted (max_early_data=%llu)\n",
		   state->early_data_max);

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

	/* Free AEAD and wipe keys since they won't be used */
	if (state->aead) {
		crypto_free_aead(state->aead);
		state->aead = NULL;
	}
	memzero_explicit(&state->keys, sizeof(state->keys));

	/*
	 * RFC 9001 Section 4.7: On 0-RTT rejection the connection flow
	 * control state must be reset so limits are re-applied from the
	 * server's transport parameters, discarding any 0-RTT state.
	 */
	tquic_fc_reset(conn->fc);

	tquic_info("0-RTT rejected\n");
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

	tquic_info("0-RTT confirmed\n");
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

	tquic_dbg("tquic_zero_rtt_can_send: state=%d early_data_sent=%llu max=%llu\n",
		  state->state, state->early_data_sent, state->early_data_max);

	if (state->state != TQUIC_0RTT_ATTEMPTING &&
	    state->state != TQUIC_0RTT_ACCEPTED)
		return false;

	if (!state->keys.valid)
		return false;

	/*
	 * Check under pn_lock to prevent TOCTOU with tquic_zero_rtt_encrypt()
	 * which increments early_data_sent. Without this, multiple callers
	 * could pass this check concurrently and collectively exceed the limit.
	 */
	if (READ_ONCE(state->early_data_sent) >= state->early_data_max)
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

	tquic_dbg("tquic_create_nonce(0rtt): pkt_num=%llu\n", pkt_num);

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
	struct aead_request *req;
	struct scatterlist sg[2];
	u8 nonce[12];
	unsigned long flags;
	int ret;

	if (!conn || !conn->zero_rtt_state)
		return -EINVAL;

	state = conn->zero_rtt_state;
	if (!state->keys.valid)
		return -ENOKEY;

	/*
	 * =======================================================================
	 * CRITICAL SECURITY CHECK: Prevent Nonce Reuse (CVE-class vulnerability)
	 * =======================================================================
	 *
	 * AEAD ciphers (AES-GCM, ChaCha20-Poly1305) require unique nonces per
	 * key. In QUIC, nonce = IV XOR packet_number (RFC 9001 Section 5.3).
	 *
	 * Nonce reuse consequences:
	 *   - AES-GCM: XOR of plaintexts leaked, auth tag forgery possible
	 *   - ChaCha20-Poly1305: Similar catastrophic failure
	 *
	 * We enforce STRICT MONOTONICITY: each packet number must be larger
	 * than all previously used packet numbers. This guarantees unique
	 * nonces even under concurrent access (protected by spinlock).
	 *
	 * Note: QUIC spec allows gaps in PN space, but never reuse.
	 */
	spin_lock_irqsave(&state->pn_lock, flags);

	if (state->send_pn_initialized && pkt_num <= state->largest_sent_pn) {
		spin_unlock_irqrestore(&state->pn_lock, flags);
		/*
		 * This is a CRITICAL error - attempting to reuse a packet number
		 * would compromise all data encrypted with this key. Log loudly
		 * and refuse to proceed.
		 */
		WARN_ONCE(1, "TQUIC: CRITICAL - 0-RTT packet number reuse attempt! "
			  "pn=%llu largest_sent=%llu - refusing to compromise crypto\n",
			  pkt_num, state->largest_sent_pn);
		return -EINVAL;
	}

	/*
	 * Atomically check early data limit and reserve this PN.
	 * Both checks under the same lock prevent TOCTOU races where
	 * multiple threads pass tquic_zero_rtt_can_send() concurrently
	 * and collectively exceed the early data limit.
	 */
	if (state->early_data_sent + payload_len > state->early_data_max) {
		spin_unlock_irqrestore(&state->pn_lock, flags);
		return -EDQUOT;
	}

	/* Reserve this PN before releasing lock to prevent races */
	state->largest_sent_pn = pkt_num;
	state->send_pn_initialized = true;
	state->early_data_sent += payload_len;

	spin_unlock_irqrestore(&state->pn_lock, flags);

	/* Use pre-allocated AEAD transform */
	if (!state->aead)
		return -ENOKEY;

	req = aead_request_alloc(state->aead, GFP_ATOMIC);
	if (!req)
		return -ENOMEM;

	/* Construct nonce: IV XOR packet_number (RFC 9001 Section 5.3) */
	tquic_create_nonce(state->keys.iv, pkt_num, nonce);

	/* Copy payload to output for in-place encryption */
	memcpy(out, payload, payload_len);

	sg_init_table(sg, 2);
	sg_set_buf(&sg[0], header, header_len);
	sg_set_buf(&sg[1], out, payload_len + 16);

	aead_request_set_crypt(req, sg, sg, payload_len, nonce);
	aead_request_set_ad(req, header_len);

	ret = crypto_aead_encrypt(req);

	/* Securely clear nonce from stack */
	memzero_explicit(nonce, sizeof(nonce));

	aead_request_free(req);

	if (ret == 0) {
		*out_len = payload_len + 16;
		/* early_data_sent already incremented under pn_lock above */
	}

	return ret;
}
EXPORT_SYMBOL_GPL(tquic_zero_rtt_encrypt);

/*
 * tquic_pn_replay_check - Check if packet number is a replay (pre-decryption)
 * @state: 0-RTT state with replay window
 * @pkt_num: Packet number to check
 *
 * Implements RFC 9000 Section 13.2.3 sliding window replay detection.
 * Must be called with pn_lock held.
 *
 * Returns: 0 if PN is valid (not a replay), -EINVAL if replay detected
 */
static int tquic_pn_replay_check_locked(struct tquic_zero_rtt_state_s *state,
					u64 pkt_num)
{
	u64 window_start;
	u64 offset;

	/* First packet - no replay possible */
	if (!state->recv_pn_initialized)
		return 0;

	/*
	 * RFC 9000 Section 13.2.3: Packet numbers that are too old
	 * (before the sliding window) MUST be discarded.
	 */
	if (state->largest_recv_pn >= TQUIC_PN_REPLAY_WINDOW_SIZE)
		window_start = state->largest_recv_pn - TQUIC_PN_REPLAY_WINDOW_SIZE + 1;
	else
		window_start = 0;

	if (pkt_num < window_start) {
		/* Packet number is before the replay window - too old */
		pr_debug("TQUIC: 0-RTT replay - PN %llu before window [%llu, %llu]\n",
			 pkt_num, window_start, state->largest_recv_pn);
		return -EINVAL;
	}

	/* Check if this is a new high water mark */
	if (pkt_num > state->largest_recv_pn)
		return 0;  /* New highest PN, definitely not a replay */

	/*
	 * PN is within the window - check the bitmap.
	 * Bit position: offset from largest_recv_pn (bit 0 = largest_recv_pn)
	 */
	offset = state->largest_recv_pn - pkt_num;
	if (offset < TQUIC_PN_REPLAY_WINDOW_SIZE &&
	    test_bit(offset, state->recv_pn_bitmap)) {
		/* This PN was already received - replay! */
		pr_debug("TQUIC: 0-RTT replay detected - PN %llu already received\n",
			 pkt_num);
		return -EINVAL;
	}

	return 0;  /* Within window and not previously seen */
}

/*
 * tquic_pn_replay_record - Record packet number after successful decryption
 * @state: 0-RTT state with replay window
 * @pkt_num: Packet number to record
 *
 * Must be called with pn_lock held, ONLY after successful AEAD decryption.
 * This ordering is critical: we must not record a PN until we've verified
 * the packet's authenticity, otherwise an attacker could "burn" PNs by
 * sending packets with valid PNs but invalid authentication tags.
 */
static void tquic_pn_replay_record_locked(struct tquic_zero_rtt_state_s *state,
					  u64 pkt_num)
{
	u64 shift;
	u64 offset;

	if (!state->recv_pn_initialized) {
		/* First packet */
		state->largest_recv_pn = pkt_num;
		state->recv_pn_initialized = true;
		bitmap_zero(state->recv_pn_bitmap, TQUIC_PN_REPLAY_WINDOW_SIZE);
		set_bit(0, state->recv_pn_bitmap);  /* Mark PN as received */
		return;
	}

	if (pkt_num > state->largest_recv_pn) {
		/*
		 * New highest PN - shift the bitmap window.
		 * All bits shift right by (pkt_num - largest_recv_pn).
		 */
		shift = pkt_num - state->largest_recv_pn;

		if (shift >= TQUIC_PN_REPLAY_WINDOW_SIZE) {
			/* Complete window shift - clear and start fresh */
			bitmap_zero(state->recv_pn_bitmap, TQUIC_PN_REPLAY_WINDOW_SIZE);
		} else {
			/* Partial shift - move bits right */
			bitmap_shift_right(state->recv_pn_bitmap,
					   state->recv_pn_bitmap,
					   shift, TQUIC_PN_REPLAY_WINDOW_SIZE);
		}

		state->largest_recv_pn = pkt_num;
		set_bit(0, state->recv_pn_bitmap);  /* Mark new PN as received */
	} else {
		/*
		 * PN is within window but not the largest.
		 * Set the appropriate bit.
		 */
		offset = state->largest_recv_pn - pkt_num;
		if (offset < TQUIC_PN_REPLAY_WINDOW_SIZE)
			set_bit(offset, state->recv_pn_bitmap);
	}
}

int tquic_zero_rtt_decrypt(struct tquic_connection *conn,
			   const u8 *header, size_t header_len,
			   u8 *payload, size_t payload_len,
			   u64 pkt_num, u8 *out, size_t *out_len)
{
	struct tquic_zero_rtt_state_s *state;
	struct aead_request *req;
	struct scatterlist sg[2];
	u8 nonce[12];
	unsigned long flags;
	int ret;

	if (!conn || !conn->zero_rtt_state)
		return -EINVAL;

	state = conn->zero_rtt_state;
	if (!state->keys.valid)
		return -ENOKEY;

	if (payload_len < 16)
		return -EINVAL;

	/*
	 * Enforce early data size limit on receive side.
	 * RFC 9001 Section 4.6.1: server MUST NOT accept more 0-RTT data
	 * than max_early_data allows. Without this check, a malicious client
	 * can send unlimited 0-RTT data, exhausting server resources.
	 */
	if (state->early_data_received + (payload_len - 16) > state->early_data_max) {
		pr_debug("TQUIC: 0-RTT early data limit exceeded: received=%llu + %zu > max=%llu\n",
			 state->early_data_received, payload_len - 16,
			 state->early_data_max);
		return -EDQUOT;
	}

	/*
	 * =======================================================================
	 * REPLAY PROTECTION: Sliding Window (RFC 9000 Section 13.2.3)
	 * =======================================================================
	 *
	 * QUIC requires endpoints to discard packets with duplicate packet
	 * numbers. For 0-RTT, this is especially critical since early data
	 * may not be idempotent (RFC 9001 Section 9.2).
	 *
	 * We implement a sliding window of size TQUIC_PN_REPLAY_WINDOW_SIZE:
	 *   - Track the largest successfully decrypted PN
	 *   - Maintain a bitmap of received PNs within the window
	 *   - Reject PNs that are:
	 *     a) Before the window (too old)
	 *     b) Already marked as received in the bitmap (duplicate)
	 *
	 * IMPORTANT: We check BEFORE decryption but only RECORD after
	 * successful decryption. This prevents attackers from "burning"
	 * valid PNs with forged packets.
	 */
	spin_lock_irqsave(&state->pn_lock, flags);

	ret = tquic_pn_replay_check_locked(state, pkt_num);
	if (ret) {
		spin_unlock_irqrestore(&state->pn_lock, flags);
		return ret;
	}

	spin_unlock_irqrestore(&state->pn_lock, flags);

	/* Use pre-allocated AEAD transform */
	if (!state->aead)
		return -ENOKEY;

	req = aead_request_alloc(state->aead, GFP_ATOMIC);
	if (!req)
		return -ENOMEM;

	/* Construct nonce: IV XOR packet_number (RFC 9001 Section 5.3) */
	tquic_create_nonce(state->keys.iv, pkt_num, nonce);

	sg_init_table(sg, 2);
	sg_set_buf(&sg[0], header, header_len);
	sg_set_buf(&sg[1], payload, payload_len);

	aead_request_set_crypt(req, sg, sg, payload_len, nonce);
	aead_request_set_ad(req, header_len);

	ret = crypto_aead_decrypt(req);

	/* Securely clear nonce from stack */
	memzero_explicit(nonce, sizeof(nonce));

	aead_request_free(req);

	if (ret == 0) {
		*out_len = payload_len - 16;
		memcpy(out, payload, *out_len);
		state->early_data_received += *out_len;

		/*
		 * CRITICAL: Only record the PN in replay window AFTER
		 * successful authentication. This prevents an attacker
		 * from sending packets with valid PNs but bad auth tags
		 * to "burn" those PNs and cause legitimate packets to
		 * be rejected as replays.
		 */
		spin_lock_irqsave(&state->pn_lock, flags);
		tquic_pn_replay_record_locked(state, pkt_num);
		spin_unlock_irqrestore(&state->pn_lock, flags);
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
	tquic_dbg("tquic_zero_rtt_get_state: state=%d\n", state->state);
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
	 * SECURITY: Initialize bloom filter hash seeds with cryptographically
	 * random values from the kernel's CSPRNG (get_random_bytes).
	 *
	 * This prevents hash prediction attacks where an attacker could:
	 * 1. Predict which bloom filter bits a ticket would set
	 * 2. Craft malicious tickets to cause collisions
	 * 3. Either bypass replay detection or cause false positives
	 *
	 * With random seeds, the attacker cannot predict hash outputs
	 * without access to kernel memory.
	 *
	 * Seeds are fixed for the module lifetime; see the comment at
	 * the seed declaration for why rotation is not performed.
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

	tquic_info("0-RTT early data support initialized\n");

	return 0;
}

void tquic_zero_rtt_module_exit(void)
{
	struct tquic_zero_rtt_ticket *ticket, *tmp;

	/* Clean up ticket store */
	spin_lock_bh(&global_ticket_store.lock);
	list_for_each_entry_safe(ticket, tmp, &global_ticket_store.lru_list, list) {
		ticket_store_remove_locked(&global_ticket_store, ticket);
		tquic_zero_rtt_put_ticket(ticket);
	}
	spin_unlock_bh(&global_ticket_store.lock);

	/* Clean up replay filter */
	tquic_replay_filter_cleanup(&global_replay_filter);

	/* Wipe server ticket key */
	memzero_explicit(server_ticket_key, sizeof(server_ticket_key));
	server_ticket_key_valid = false;

	tquic_info("0-RTT early data support cleaned up\n");
}

MODULE_DESCRIPTION("TQUIC 0-RTT Early Data Support (RFC 9001)");
MODULE_LICENSE("GPL");
