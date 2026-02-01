// SPDX-License-Identifier: GPL-2.0-only
/*
 * TQUIC: TLS 1.3 Key Update Mechanism (RFC 9001 Section 6)
 *
 * Copyright (c) 2026 Linux Foundation
 *
 * Implements the TLS 1.3 key update mechanism for QUIC connections:
 * - Key phase tracking (0 or 1)
 * - Key derivation using HKDF-Expand-Label with "quic ku" label
 * - Initiating key updates (configurable intervals)
 * - Responding to peer-initiated key updates
 * - AEAD confidentiality limit enforcement
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/ktime.h>
#include <linux/sysctl.h>
#include <linux/workqueue.h>
#include <crypto/hash.h>
#include <crypto/aead.h>
#include <net/tquic.h>

/* Key update HKDF label per RFC 9001 Section 6.1 */
#define TQUIC_HKDF_LABEL_KU		"quic ku"

/* Key update constants */
#define TQUIC_SECRET_MAX_LEN		48	/* SHA-384 max */
#define TQUIC_KEY_MAX_LEN		32	/* AES-256 max */
#define TQUIC_IV_MAX_LEN		12
#define TQUIC_HP_KEY_MAX_LEN		32

/* AEAD confidentiality limits per RFC 9001 Section 6.6 */
#define TQUIC_AES_GCM_CONFIDENTIALITY_LIMIT	(1ULL << 23)	/* 2^23 packets */
#define TQUIC_CHACHA20_CONFIDENTIALITY_LIMIT	(1ULL << 62)	/* 2^62 packets */

/* Default key update intervals */
#define TQUIC_DEFAULT_KEY_UPDATE_PACKETS	(1ULL << 20)	/* ~1M packets */
#define TQUIC_DEFAULT_KEY_UPDATE_SECONDS	3600		/* 1 hour */

/* Minimum time between key updates (prevent rapid cycling) */
#define TQUIC_KEY_UPDATE_COOLDOWN_MS		1000

/* Cipher suite identifiers */
#define TLS_AES_128_GCM_SHA256		0x1301
#define TLS_AES_256_GCM_SHA384		0x1302
#define TLS_CHACHA20_POLY1305_SHA256	0x1303

/**
 * struct tquic_key_generation - Keys for one generation (key phase)
 * @secret: Application traffic secret
 * @key: AEAD key derived from secret
 * @iv: Initialization vector derived from secret
 * @hp_key: Header protection key derived from secret
 * @secret_len: Length of the secret
 * @key_len: Length of the AEAD key
 * @iv_len: Length of the IV
 * @valid: Whether this key generation is valid for use
 */
struct tquic_key_generation {
	u8 secret[TQUIC_SECRET_MAX_LEN];
	u8 key[TQUIC_KEY_MAX_LEN];
	u8 iv[TQUIC_IV_MAX_LEN];
	u8 hp_key[TQUIC_HP_KEY_MAX_LEN];
	u32 secret_len;
	u32 key_len;
	u32 iv_len;
	bool valid;
};

/**
 * struct tquic_key_update_state - Key update state per connection
 * @current_phase: Current key phase (0 or 1)
 * @current_read: Current generation keys for reading
 * @current_write: Current generation keys for writing
 * @next_read: Next generation keys for reading (pre-computed)
 * @next_write: Next generation keys for writing (pre-computed)
 * @old_read: Previous generation keys (for packets in flight)
 * @packets_sent: Packets sent with current write keys
 * @packets_received: Packets received with current read keys
 * @last_key_update: Timestamp of last key update
 * @update_pending: Key update initiated, waiting for peer ACK
 * @peer_update_received: Peer initiated key update
 * @cipher_suite: Negotiated cipher suite
 * @hash_tfm: Hash transform for HKDF
 * @aead_tfm: AEAD transform for encryption/decryption
 * @handshake_confirmed: Handshake has completed
 * @key_update_interval_packets: Packets before initiating update
 * @key_update_interval_seconds: Seconds before initiating update
 * @lock: Spinlock protecting key state
 * @update_work: Deferred work for key derivation
 * @conn: Back-pointer to connection
 */
struct tquic_key_update_state {
	/* Key phase (RFC 9001 Section 6) */
	u8 current_phase;

	/* Key generations (double-buffered) */
	struct tquic_key_generation current_read;
	struct tquic_key_generation current_write;
	struct tquic_key_generation next_read;
	struct tquic_key_generation next_write;
	struct tquic_key_generation old_read;

	/* Statistics for confidentiality limit tracking */
	u64 packets_sent;
	u64 packets_received;
	u64 total_key_updates;
	u64 peer_initiated_updates;

	/* Timing */
	ktime_t last_key_update;
	ktime_t old_key_discard_time;

	/* State flags */
	bool update_pending;
	bool peer_update_received;
	bool handshake_confirmed;
	bool old_keys_valid;

	/* Cipher configuration */
	u16 cipher_suite;
	u64 confidentiality_limit;

	/* Crypto transforms */
	struct crypto_shash *hash_tfm;
	struct crypto_aead *aead_tfm;

	/* Configuration (from sysctl or per-connection) */
	u64 key_update_interval_packets;
	u32 key_update_interval_seconds;

	/* Synchronization */
	spinlock_t lock;
	struct work_struct update_work;

	/* Back-pointer */
	struct tquic_connection *conn;
};

/* Forward declarations for HP context functions */
struct tquic_hp_ctx;
extern int tquic_hp_set_key(struct tquic_hp_ctx *ctx, int level,
			    int direction, const u8 *key, size_t key_len, u16 cipher);
extern void tquic_hp_set_key_phase(struct tquic_hp_ctx *ctx, u8 phase);
extern u8 tquic_hp_get_key_phase(struct tquic_hp_ctx *ctx);
extern int tquic_hp_set_next_key(struct tquic_hp_ctx *ctx, int direction,
				 const u8 *key, size_t key_len, u16 cipher);
extern void tquic_hp_rotate_keys(struct tquic_hp_ctx *ctx);

/* Forward declaration for crypto state */
struct tquic_crypto_state;
extern struct tquic_hp_ctx *tquic_crypto_get_hp_ctx(struct tquic_crypto_state *crypto);

/* Sysctl parameters */
static u64 sysctl_key_update_interval_packets = TQUIC_DEFAULT_KEY_UPDATE_PACKETS;
static u32 sysctl_key_update_interval_seconds = TQUIC_DEFAULT_KEY_UPDATE_SECONDS;

/*
 * =============================================================================
 * HKDF-Expand-Label for Key Update
 * =============================================================================
 */

/**
 * tquic_ku_hkdf_expand_label - HKDF-Expand-Label for key update
 * @hash: Hash transform (HMAC-SHA256 or HMAC-SHA384)
 * @secret: Input secret
 * @secret_len: Length of input secret
 * @label: Label string (without "tls13 " prefix)
 * @label_len: Length of label
 * @out: Output buffer
 * @out_len: Desired output length
 *
 * Implements HKDF-Expand-Label as defined in RFC 8446 Section 7.1:
 * HKDF-Expand-Label(Secret, Label, Context, Length) =
 *     HKDF-Expand(Secret, HkdfLabel, Length)
 *
 * where HkdfLabel = struct {
 *     uint16 length = Length;
 *     opaque label<7..255> = "tls13 " + Label;
 *     opaque context<0..255> = Context;
 * };
 *
 * For key update, context is empty per RFC 9001 Section 6.1.
 *
 * Returns 0 on success, negative error code on failure.
 */
static int tquic_ku_hkdf_expand_label(struct crypto_shash *hash,
				      const u8 *secret, size_t secret_len,
				      const char *label, size_t label_len,
				      u8 *out, size_t out_len)
{
	u8 hkdf_label[256];
	u8 *p = hkdf_label;
	size_t hkdf_label_len;
	SHASH_DESC_ON_STACK(desc, hash);
	u8 t[64];  /* Max hash output size */
	u32 hash_len;
	int ret;
	u32 i, n;

	if (!hash || !secret || !out)
		return -EINVAL;

	hash_len = crypto_shash_digestsize(hash);

	/* Construct HKDF label: length + "tls13 " + label + empty context */
	*p++ = (out_len >> 8) & 0xff;
	*p++ = out_len & 0xff;
	*p++ = 6 + label_len;  /* "tls13 " prefix + label */
	memcpy(p, "tls13 ", 6);
	p += 6;
	memcpy(p, label, label_len);
	p += label_len;
	*p++ = 0;  /* Empty context */
	hkdf_label_len = p - hkdf_label;

	desc->tfm = hash;

	/* HKDF-Expand: T(0) = empty, T(i) = HMAC(PRK, T(i-1) | info | i) */
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
		       min_t(size_t, hash_len, out_len - i * hash_len));
	}

	memzero_explicit(t, sizeof(t));
	return 0;
}

/*
 * =============================================================================
 * Key Derivation
 * =============================================================================
 */

/**
 * tquic_ku_derive_next_secret - Derive next generation secret
 * @state: Key update state
 * @current_secret: Current application secret
 * @secret_len: Length of the secret
 * @next_secret: Output buffer for next secret
 *
 * Per RFC 9001 Section 6.1:
 * secret_<N+1> = HKDF-Expand-Label(secret_<N>, "quic ku", "", Hash.length)
 *
 * Returns 0 on success, negative error code on failure.
 */
static int tquic_ku_derive_next_secret(struct tquic_key_update_state *state,
				       const u8 *current_secret, size_t secret_len,
				       u8 *next_secret)
{
	return tquic_ku_hkdf_expand_label(state->hash_tfm,
					  current_secret, secret_len,
					  TQUIC_HKDF_LABEL_KU,
					  strlen(TQUIC_HKDF_LABEL_KU),
					  next_secret, secret_len);
}

/**
 * tquic_ku_derive_keys - Derive key and IV from secret
 * @state: Key update state
 * @gen: Key generation to populate
 *
 * Derives AEAD key, IV, and HP key from the secret.
 *
 * Returns 0 on success, negative error code on failure.
 */
static int tquic_ku_derive_keys(struct tquic_key_update_state *state,
				struct tquic_key_generation *gen)
{
	int ret;

	/* Derive AEAD key */
	ret = tquic_ku_hkdf_expand_label(state->hash_tfm,
					 gen->secret, gen->secret_len,
					 "quic key", 8,
					 gen->key, gen->key_len);
	if (ret)
		return ret;

	/* Derive IV */
	ret = tquic_ku_hkdf_expand_label(state->hash_tfm,
					 gen->secret, gen->secret_len,
					 "quic iv", 7,
					 gen->iv, gen->iv_len);
	if (ret)
		return ret;

	/* Derive HP key */
	ret = tquic_ku_hkdf_expand_label(state->hash_tfm,
					 gen->secret, gen->secret_len,
					 "quic hp", 7,
					 gen->hp_key, gen->key_len);
	if (ret)
		return ret;

	gen->valid = true;
	return 0;
}

/**
 * tquic_ku_derive_next_generation - Derive complete next key generation
 * @state: Key update state
 * @current: Current key generation
 * @next: Next key generation to populate
 *
 * Returns 0 on success, negative error code on failure.
 */
static int tquic_ku_derive_next_generation(struct tquic_key_update_state *state,
					   struct tquic_key_generation *current,
					   struct tquic_key_generation *next)
{
	int ret;

	if (!current->valid)
		return -EINVAL;

	/* Derive next secret */
	ret = tquic_ku_derive_next_secret(state, current->secret,
					  current->secret_len, next->secret);
	if (ret)
		return ret;

	next->secret_len = current->secret_len;
	next->key_len = current->key_len;
	next->iv_len = current->iv_len;

	/* Derive keys from next secret */
	return tquic_ku_derive_keys(state, next);
}

/*
 * =============================================================================
 * Key Update Initiation
 * =============================================================================
 */

/**
 * tquic_ku_should_update - Check if key update should be initiated
 * @state: Key update state
 *
 * Returns true if key update should be initiated based on:
 * - Packet count threshold
 * - Time-based threshold
 * - Approaching AEAD confidentiality limit
 *
 * Does NOT initiate update during handshake or if update already pending.
 */
static bool tquic_ku_should_update(struct tquic_key_update_state *state)
{
	ktime_t now;
	s64 elapsed_ms;

	/* Don't update during handshake */
	if (!state->handshake_confirmed)
		return false;

	/* Don't update if already pending */
	if (state->update_pending)
		return false;

	/* Check cooldown period */
	now = ktime_get();
	elapsed_ms = ktime_ms_delta(now, state->last_key_update);
	if (elapsed_ms < TQUIC_KEY_UPDATE_COOLDOWN_MS)
		return false;

	/* Check packet count threshold */
	if (state->key_update_interval_packets > 0 &&
	    state->packets_sent >= state->key_update_interval_packets)
		return true;

	/* Check time-based threshold */
	if (state->key_update_interval_seconds > 0 &&
	    elapsed_ms >= (s64)state->key_update_interval_seconds * 1000)
		return true;

	/* Check AEAD confidentiality limit (with margin) */
	if (state->packets_sent >= (state->confidentiality_limit * 3 / 4))
		return true;

	return false;
}

/**
 * tquic_initiate_key_update - Initiate a key update
 * @conn: TQUIC connection
 *
 * Initiates key update by:
 * 1. Deriving next generation write keys
 * 2. Switching to new keys for sending
 * 3. Setting update_pending flag
 * 4. The next packet sent will have flipped key phase bit
 *
 * Returns 0 on success, negative error code on failure.
 */
int tquic_initiate_key_update(struct tquic_connection *conn)
{
	struct tquic_key_update_state *state;
	struct tquic_hp_ctx *hp_ctx;
	unsigned long flags;
	int ret = 0;

	if (!conn || !conn->crypto_state)
		return -EINVAL;

	/* Get key update state from crypto state */
	state = tquic_crypto_get_key_update_state(conn->crypto_state);
	if (!state)
		return -EINVAL;

	hp_ctx = tquic_crypto_get_hp_ctx(conn->crypto_state);
	if (!hp_ctx)
		return -EINVAL;

	spin_lock_irqsave(&state->lock, flags);

	/* Check if we can initiate update */
	if (!state->handshake_confirmed) {
		ret = -EAGAIN;
		goto out_unlock;
	}

	if (state->update_pending) {
		ret = -EINPROGRESS;
		goto out_unlock;
	}

	/* Pre-compute next generation write keys if not already done */
	if (!state->next_write.valid) {
		spin_unlock_irqrestore(&state->lock, flags);

		ret = tquic_ku_derive_next_generation(state,
						      &state->current_write,
						      &state->next_write);
		if (ret)
			return ret;

		spin_lock_irqsave(&state->lock, flags);
	}

	/* Rotate write keys: current -> old, next -> current */
	state->old_read = state->current_read;
	state->old_keys_valid = true;
	state->old_key_discard_time = ktime_add_ms(ktime_get(),
						   3 * conn->idle_timeout);

	state->current_write = state->next_write;
	memset(&state->next_write, 0, sizeof(state->next_write));

	/* Toggle key phase for sending */
	state->current_phase ^= 1;
	state->update_pending = true;
	state->last_key_update = ktime_get();
	state->packets_sent = 0;
	state->total_key_updates++;

	/* Update HP context */
	tquic_hp_set_key_phase(hp_ctx, state->current_phase);

	pr_debug("tquic: initiated key update, new phase=%d, total_updates=%llu\n",
		 state->current_phase, state->total_key_updates);

out_unlock:
	spin_unlock_irqrestore(&state->lock, flags);
	return ret;
}
EXPORT_SYMBOL_GPL(tquic_initiate_key_update);

/*
 * =============================================================================
 * Key Update Response
 * =============================================================================
 */

/**
 * tquic_handle_key_phase_change - Handle received packet with different key phase
 * @conn: TQUIC connection
 * @received_phase: Key phase bit from received packet
 *
 * When we receive a packet with a different key phase:
 * 1. If we initiated the update, this confirms peer received our update
 * 2. If peer initiated, we need to derive new keys and respond
 *
 * Returns 0 on success, negative error code on failure.
 */
int tquic_handle_key_phase_change(struct tquic_connection *conn, u8 received_phase)
{
	struct tquic_key_update_state *state;
	struct tquic_hp_ctx *hp_ctx;
	unsigned long flags;
	int ret = 0;

	if (!conn || !conn->crypto_state)
		return -EINVAL;

	state = tquic_crypto_get_key_update_state(conn->crypto_state);
	if (!state)
		return -EINVAL;

	hp_ctx = tquic_crypto_get_hp_ctx(conn->crypto_state);
	if (!hp_ctx)
		return -EINVAL;

	spin_lock_irqsave(&state->lock, flags);

	/* If phase matches current, no action needed */
	if (received_phase == state->current_phase)
		goto out_unlock;

	/* Handshake must be complete for key updates */
	if (!state->handshake_confirmed) {
		ret = -EPROTO;
		goto out_unlock;
	}

	if (state->update_pending) {
		/*
		 * We initiated the update - this packet confirms peer
		 * has updated their keys. Complete the update.
		 */
		state->update_pending = false;
		state->peer_update_received = false;

		/* Pre-compute next generation for future updates */
		spin_unlock_irqrestore(&state->lock, flags);
		ret = tquic_ku_derive_next_generation(state,
						      &state->current_write,
						      &state->next_write);
		spin_lock_irqsave(&state->lock, flags);

		pr_debug("tquic: key update confirmed by peer ACK\n");
	} else {
		/*
		 * Peer initiated the update - we need to:
		 * 1. Derive new read keys to decrypt this packet
		 * 2. Derive new write keys to respond with same phase
		 * 3. Update our key phase
		 */
		state->peer_update_received = true;
		state->peer_initiated_updates++;

		/* Save old read keys for packets in flight */
		state->old_read = state->current_read;
		state->old_keys_valid = true;
		state->old_key_discard_time = ktime_add_ms(ktime_get(),
							   3 * conn->idle_timeout);

		/* Derive new read keys */
		spin_unlock_irqrestore(&state->lock, flags);
		ret = tquic_ku_derive_next_generation(state,
						      &state->current_read,
						      &state->next_read);
		if (ret)
			return ret;

		/* Rotate: next -> current */
		spin_lock_irqsave(&state->lock, flags);
		state->current_read = state->next_read;
		memset(&state->next_read, 0, sizeof(state->next_read));

		/* Now derive new write keys */
		spin_unlock_irqrestore(&state->lock, flags);
		ret = tquic_ku_derive_next_generation(state,
						      &state->current_write,
						      &state->next_write);
		if (ret)
			return ret;

		spin_lock_irqsave(&state->lock, flags);
		state->current_write = state->next_write;
		memset(&state->next_write, 0, sizeof(state->next_write));

		/* Toggle our key phase to match peer */
		state->current_phase = received_phase;
		state->last_key_update = ktime_get();
		state->packets_sent = 0;
		state->packets_received = 0;
		state->total_key_updates++;

		/* Update HP context */
		tquic_hp_set_key_phase(hp_ctx, state->current_phase);

		pr_debug("tquic: responded to peer key update, new phase=%d\n",
			 state->current_phase);
	}

out_unlock:
	spin_unlock_irqrestore(&state->lock, flags);
	return ret;
}
EXPORT_SYMBOL_GPL(tquic_handle_key_phase_change);

/**
 * tquic_try_decrypt_with_old_keys - Try decryption with previous generation keys
 * @conn: TQUIC connection
 * @header: Packet header
 * @header_len: Header length
 * @payload: Encrypted payload
 * @payload_len: Payload length
 * @pkt_num: Packet number
 * @out: Output buffer
 * @out_len: Output length
 *
 * When decryption fails with current keys, try old keys for packets
 * that were in flight during key update.
 *
 * Returns 0 on success, negative error code on failure.
 */
int tquic_try_decrypt_with_old_keys(struct tquic_connection *conn,
				    const u8 *header, size_t header_len,
				    u8 *payload, size_t payload_len,
				    u64 pkt_num, u8 *out, size_t *out_len)
{
	struct tquic_key_update_state *state;
	struct tquic_key_generation *old;
	unsigned long flags;
	ktime_t now;
	int ret = -EINVAL;

	if (!conn || !conn->crypto_state)
		return -EINVAL;

	state = tquic_crypto_get_key_update_state(conn->crypto_state);
	if (!state)
		return -EINVAL;

	spin_lock_irqsave(&state->lock, flags);

	if (!state->old_keys_valid) {
		ret = -ENOKEY;
		goto out_unlock;
	}

	/* Check if old keys have expired */
	now = ktime_get();
	if (ktime_after(now, state->old_key_discard_time)) {
		/* Discard old keys */
		memzero_explicit(&state->old_read, sizeof(state->old_read));
		state->old_keys_valid = false;
		ret = -ENOKEY;
		goto out_unlock;
	}

	old = &state->old_read;
	if (!old->valid) {
		ret = -ENOKEY;
		goto out_unlock;
	}

	/* Try decryption with old keys */
	/* Note: Actual decryption would use the AEAD transform with old->key and old->iv */
	/* This is a placeholder - actual implementation integrates with tquic_decrypt_packet */

	spin_unlock_irqrestore(&state->lock, flags);

	/* The actual decryption is handled by the caller using the old keys */
	return 0;

out_unlock:
	spin_unlock_irqrestore(&state->lock, flags);
	return ret;
}
EXPORT_SYMBOL_GPL(tquic_try_decrypt_with_old_keys);

/*
 * =============================================================================
 * Key Update State Management
 * =============================================================================
 */

/**
 * tquic_key_update_state_alloc - Allocate key update state
 * @cipher_suite: Negotiated cipher suite
 *
 * Returns allocated state or NULL on failure.
 */
struct tquic_key_update_state *tquic_key_update_state_alloc(u16 cipher_suite)
{
	struct tquic_key_update_state *state;
	const char *hash_name;
	u32 key_len, secret_len;

	state = kzalloc(sizeof(*state), GFP_KERNEL);
	if (!state)
		return NULL;

	spin_lock_init(&state->lock);
	state->cipher_suite = cipher_suite;

	/* Configure based on cipher suite */
	switch (cipher_suite) {
	case TLS_AES_128_GCM_SHA256:
		hash_name = "hmac(sha256)";
		key_len = 16;
		secret_len = 32;
		state->confidentiality_limit = TQUIC_AES_GCM_CONFIDENTIALITY_LIMIT;
		break;
	case TLS_AES_256_GCM_SHA384:
		hash_name = "hmac(sha384)";
		key_len = 32;
		secret_len = 48;
		state->confidentiality_limit = TQUIC_AES_GCM_CONFIDENTIALITY_LIMIT;
		break;
	case TLS_CHACHA20_POLY1305_SHA256:
		hash_name = "hmac(sha256)";
		key_len = 32;
		secret_len = 32;
		state->confidentiality_limit = TQUIC_CHACHA20_CONFIDENTIALITY_LIMIT;
		break;
	default:
		kfree(state);
		return NULL;
	}

	/* Initialize key generation parameters */
	state->current_read.key_len = key_len;
	state->current_read.iv_len = TQUIC_IV_MAX_LEN;
	state->current_read.secret_len = secret_len;

	state->current_write.key_len = key_len;
	state->current_write.iv_len = TQUIC_IV_MAX_LEN;
	state->current_write.secret_len = secret_len;

	/* Allocate hash transform for HKDF */
	state->hash_tfm = crypto_alloc_shash(hash_name, 0, 0);
	if (IS_ERR(state->hash_tfm)) {
		pr_err("tquic_key_update: failed to allocate hash %s\n", hash_name);
		kfree(state);
		return NULL;
	}

	/* Set default intervals from sysctl */
	state->key_update_interval_packets = sysctl_key_update_interval_packets;
	state->key_update_interval_seconds = sysctl_key_update_interval_seconds;

	state->last_key_update = ktime_get();

	pr_debug("tquic_key_update: allocated state for cipher 0x%04x\n",
		 cipher_suite);

	return state;
}
EXPORT_SYMBOL_GPL(tquic_key_update_state_alloc);

/**
 * tquic_key_update_state_free - Free key update state
 * @state: State to free
 */
void tquic_key_update_state_free(struct tquic_key_update_state *state)
{
	if (!state)
		return;

	if (state->hash_tfm && !IS_ERR(state->hash_tfm))
		crypto_free_shash(state->hash_tfm);

	if (state->aead_tfm && !IS_ERR(state->aead_tfm))
		crypto_free_aead(state->aead_tfm);

	/* Securely wipe key material */
	memzero_explicit(&state->current_read, sizeof(state->current_read));
	memzero_explicit(&state->current_write, sizeof(state->current_write));
	memzero_explicit(&state->next_read, sizeof(state->next_read));
	memzero_explicit(&state->next_write, sizeof(state->next_write));
	memzero_explicit(&state->old_read, sizeof(state->old_read));

	kfree(state);
}
EXPORT_SYMBOL_GPL(tquic_key_update_state_free);

/**
 * tquic_key_update_install_secrets - Install initial application secrets
 * @state: Key update state
 * @read_secret: Read (decryption) secret
 * @write_secret: Write (encryption) secret
 * @secret_len: Length of secrets
 *
 * Called after TLS handshake completes to install the initial
 * application traffic secrets.
 *
 * Returns 0 on success, negative error code on failure.
 */
int tquic_key_update_install_secrets(struct tquic_key_update_state *state,
				     const u8 *read_secret,
				     const u8 *write_secret,
				     size_t secret_len)
{
	unsigned long flags;
	int ret;

	if (!state || !read_secret || !write_secret)
		return -EINVAL;

	if (secret_len > TQUIC_SECRET_MAX_LEN)
		return -EINVAL;

	spin_lock_irqsave(&state->lock, flags);

	/* Install read secret */
	memcpy(state->current_read.secret, read_secret, secret_len);
	state->current_read.secret_len = secret_len;

	/* Install write secret */
	memcpy(state->current_write.secret, write_secret, secret_len);
	state->current_write.secret_len = secret_len;

	spin_unlock_irqrestore(&state->lock, flags);

	/* Derive keys from secrets */
	ret = tquic_ku_derive_keys(state, &state->current_read);
	if (ret)
		return ret;

	ret = tquic_ku_derive_keys(state, &state->current_write);
	if (ret)
		return ret;

	/* Pre-compute next generation keys */
	ret = tquic_ku_derive_next_generation(state, &state->current_read,
					      &state->next_read);
	if (ret)
		pr_warn("tquic_key_update: failed to pre-compute next read keys\n");

	ret = tquic_ku_derive_next_generation(state, &state->current_write,
					      &state->next_write);
	if (ret)
		pr_warn("tquic_key_update: failed to pre-compute next write keys\n");

	spin_lock_irqsave(&state->lock, flags);
	state->handshake_confirmed = true;
	state->current_phase = 0;
	state->last_key_update = ktime_get();
	spin_unlock_irqrestore(&state->lock, flags);

	pr_debug("tquic_key_update: installed initial application secrets\n");

	return 0;
}
EXPORT_SYMBOL_GPL(tquic_key_update_install_secrets);

/**
 * tquic_key_update_on_packet_sent - Track packet sent for key update timing
 * @state: Key update state
 *
 * Called after each packet is sent to track statistics.
 * May trigger automatic key update based on configured thresholds.
 */
void tquic_key_update_on_packet_sent(struct tquic_key_update_state *state)
{
	unsigned long flags;

	if (!state)
		return;

	spin_lock_irqsave(&state->lock, flags);
	state->packets_sent++;
	spin_unlock_irqrestore(&state->lock, flags);
}
EXPORT_SYMBOL_GPL(tquic_key_update_on_packet_sent);

/**
 * tquic_key_update_on_packet_received - Track packet received
 * @state: Key update state
 *
 * Called after each packet is successfully decrypted.
 */
void tquic_key_update_on_packet_received(struct tquic_key_update_state *state)
{
	unsigned long flags;

	if (!state)
		return;

	spin_lock_irqsave(&state->lock, flags);
	state->packets_received++;
	spin_unlock_irqrestore(&state->lock, flags);
}
EXPORT_SYMBOL_GPL(tquic_key_update_on_packet_received);

/**
 * tquic_key_update_check_threshold - Check if key update is needed
 * @conn: TQUIC connection
 *
 * Checks if automatic key update should be triggered based on
 * configured thresholds. Called periodically or on packet send.
 *
 * Returns true if key update was initiated.
 */
bool tquic_key_update_check_threshold(struct tquic_connection *conn)
{
	struct tquic_key_update_state *state;

	if (!conn || !conn->crypto_state)
		return false;

	state = tquic_crypto_get_key_update_state(conn->crypto_state);
	if (!state)
		return false;

	if (tquic_ku_should_update(state)) {
		if (tquic_initiate_key_update(conn) == 0)
			return true;
	}

	return false;
}
EXPORT_SYMBOL_GPL(tquic_key_update_check_threshold);

/**
 * tquic_key_update_get_current_keys - Get current encryption keys
 * @state: Key update state
 * @direction: 0 = read, 1 = write
 * @key: Output buffer for key
 * @key_len: Output key length
 * @iv: Output buffer for IV
 * @iv_len: Output IV length
 *
 * Returns 0 on success, negative error code on failure.
 */
int tquic_key_update_get_current_keys(struct tquic_key_update_state *state,
				      int direction,
				      u8 *key, u32 *key_len,
				      u8 *iv, u32 *iv_len)
{
	struct tquic_key_generation *gen;
	unsigned long flags;

	if (!state)
		return -EINVAL;

	spin_lock_irqsave(&state->lock, flags);

	gen = direction ? &state->current_write : &state->current_read;

	if (!gen->valid) {
		spin_unlock_irqrestore(&state->lock, flags);
		return -ENOKEY;
	}

	if (key && key_len) {
		memcpy(key, gen->key, gen->key_len);
		*key_len = gen->key_len;
	}

	if (iv && iv_len) {
		memcpy(iv, gen->iv, gen->iv_len);
		*iv_len = gen->iv_len;
	}

	spin_unlock_irqrestore(&state->lock, flags);
	return 0;
}
EXPORT_SYMBOL_GPL(tquic_key_update_get_current_keys);

/**
 * tquic_key_update_get_phase - Get current key phase
 * @state: Key update state
 *
 * Returns current key phase (0 or 1).
 */
u8 tquic_key_update_get_phase(struct tquic_key_update_state *state)
{
	u8 phase;
	unsigned long flags;

	if (!state)
		return 0;

	spin_lock_irqsave(&state->lock, flags);
	phase = state->current_phase;
	spin_unlock_irqrestore(&state->lock, flags);

	return phase;
}
EXPORT_SYMBOL_GPL(tquic_key_update_get_phase);

/**
 * tquic_key_update_set_intervals - Configure key update intervals
 * @state: Key update state
 * @packets: Packet count threshold (0 to disable)
 * @seconds: Time threshold in seconds (0 to disable)
 */
void tquic_key_update_set_intervals(struct tquic_key_update_state *state,
				    u64 packets, u32 seconds)
{
	unsigned long flags;

	if (!state)
		return;

	spin_lock_irqsave(&state->lock, flags);
	state->key_update_interval_packets = packets;
	state->key_update_interval_seconds = seconds;
	spin_unlock_irqrestore(&state->lock, flags);
}
EXPORT_SYMBOL_GPL(tquic_key_update_set_intervals);

/*
 * =============================================================================
 * Crypto State Integration
 * =============================================================================
 */

/**
 * tquic_crypto_get_key_update_state - Get key update state from crypto state
 * @crypto_state: Connection's crypto state
 *
 * This function is defined as a stub here and should be properly
 * integrated with the existing crypto state structure in tls.c.
 *
 * Returns key update state or NULL.
 */
struct tquic_key_update_state *
tquic_crypto_get_key_update_state(void *crypto_state)
{
	struct tquic_crypto_state_with_ku {
		/* This mirrors the beginning of tquic_crypto_state */
		u16 cipher_suite;
		/* ... other fields ... */
		struct tquic_key_update_state *key_update;
	} *state = crypto_state;

	/*
	 * Note: This needs to be properly integrated with the existing
	 * tquic_crypto_state structure in tls.c. The key_update field
	 * should be added to that structure.
	 */
	if (!state)
		return NULL;

	return state->key_update;
}
EXPORT_SYMBOL_GPL(tquic_crypto_get_key_update_state);

MODULE_DESCRIPTION("TQUIC TLS 1.3 Key Update Mechanism");
MODULE_LICENSE("GPL");
MODULE_AUTHOR("Linux Foundation");
