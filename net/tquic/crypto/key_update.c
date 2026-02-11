// SPDX-License-Identifier: GPL-2.0-only
/*
 * TQUIC: TLS 1.3 Key Update Mechanism (RFC 9001 Section 6)
 *
 * Copyright (c) 2026 Justin Adams <spotty118@gmail.com>
 * Kernel implementation by Justin Adams <spotty118@gmail.com>
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

#include "key_update.h"
#include "extended_key_update.h"
#include "header_protection.h"
#include "../tquic_debug.h"

/* Key update HKDF label per RFC 9001 Section 6.1 */
#define TQUIC_HKDF_LABEL_KU		"quic ku"

/* AEAD confidentiality limits per RFC 9001 Section 6.6 */
#define TQUIC_AES_GCM_CONFIDENTIALITY_LIMIT	(1ULL << 23)	/* 2^23 packets */
#define TQUIC_CHACHA20_CONFIDENTIALITY_LIMIT	(1ULL << 62)	/* 2^62 packets */

/* Default key update intervals */
#define TQUIC_DEFAULT_KEY_UPDATE_PACKETS	(1ULL << 20)	/* ~1M packets */
#define TQUIC_DEFAULT_KEY_UPDATE_SECONDS	3600		/* 1 hour */

/* Minimum time between key updates (prevent rapid cycling) */
#define TQUIC_KEY_UPDATE_COOLDOWN_MS		1000

/*
 * Key update timeout: if the peer does not respond with the new key
 * phase within this many PTOs, revert the key update.  3 * PTO is
 * consistent with the draining period in RFC 9000 and the persistent
 * congestion threshold in RFC 9002.
 */
#define TQUIC_KEY_UPDATE_TIMEOUT_PTO_MULT	3

/* Cipher suite identifiers */
#define TLS_AES_128_GCM_SHA256		0x1301
#define TLS_AES_256_GCM_SHA384		0x1302
#define TLS_CHACHA20_POLY1305_SHA256	0x1303

/*
 * Note: struct tquic_key_generation and struct tquic_key_update_state
 * are defined in key_update.h to allow sharing with extended_key_update.c
 */

/* Forward declaration - defined at end of this file */
struct tquic_key_update_state *tquic_crypto_get_key_update_state(void *crypto_state);

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

	/*
	 * Bounds check: the HkdfLabel buffer is 256 bytes.
	 * Contents: 2 (length) + 1 (label length byte) + 6 ("tls13 ")
	 *         + label_len + 1 (context length byte) = 10 + label_len.
	 * Reject if this would overflow the stack buffer.
	 */
	if (label_len > 245)
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
			goto out;

		ret = crypto_shash_init(desc);
		if (ret)
			goto out;

		if (i > 0) {
			ret = crypto_shash_update(desc, t, hash_len);
			if (ret)
				goto out;
		}

		ret = crypto_shash_update(desc, hkdf_label, hkdf_label_len);
		if (ret)
			goto out;

		{
			u8 counter = i + 1;

			ret = crypto_shash_update(desc, &counter, 1);
		}
		if (ret)
			goto out;

		ret = crypto_shash_final(desc, t);
		if (ret)
			goto out;

		memcpy(out + i * hash_len, t,
		       min_t(size_t, hash_len, out_len - i * hash_len));
	}

	ret = 0;

out:
	memzero_explicit(t, sizeof(t));
	memzero_explicit(hkdf_label, sizeof(hkdf_label));
	return ret;
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
 * @cur_gen: Current key generation (named to avoid kernel 'current' macro)
 * @next: Next key generation to populate
 *
 * Returns 0 on success, negative error code on failure.
 */
static int tquic_ku_derive_next_generation(struct tquic_key_update_state *state,
					   struct tquic_key_generation *cur_gen,
					   struct tquic_key_generation *next)
{
	int ret;

	if (!cur_gen->valid)
		return -EINVAL;

	/* Derive next secret */
	ret = tquic_ku_derive_next_secret(state, cur_gen->secret,
					  cur_gen->secret_len, next->secret);
	if (ret)
		return ret;

	next->secret_len = cur_gen->secret_len;
	next->key_len = cur_gen->key_len;
	next->iv_len = cur_gen->iv_len;

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

	if (state->keys_installing) {
		ret = -EBUSY;
		goto out_unlock;
	}

	/* Pre-compute next generation write keys if not already done */
	if (!state->next_write.valid) {
		struct tquic_key_generation staged_next;
		struct tquic_key_generation staged_cur_write;

		/*
		 * Copy current_write under lock for use during derivation.
		 * Drop the lock while deriving to avoid sleeping with
		 * spinlock held, then re-check state for consistency.
		 */
		staged_cur_write = state->current_write;
		memset(&staged_next, 0, sizeof(staged_next));
		spin_unlock_irqrestore(&state->lock, flags);

		ret = tquic_ku_derive_next_generation(state,
						      &staged_cur_write,
						      &staged_next);
		memzero_explicit(&staged_cur_write,
				 sizeof(staged_cur_write));
		if (ret) {
			memzero_explicit(&staged_next,
					 sizeof(staged_next));
			return ret;
		}

		spin_lock_irqsave(&state->lock, flags);

		/*
		 * Re-check: if state changed while we were unlocked
		 * (concurrent key update), discard our staged keys.
		 */
		if (state->update_pending || state->next_write.valid) {
			memzero_explicit(&staged_next,
					 sizeof(staged_next));
			ret = -EINPROGRESS;
			goto out_unlock;
		}

		state->next_write = staged_next;
	}

	/* Rotate write keys: current -> old, next -> current */
	state->old_read = state->current_read;
	state->old_keys_valid = true;
	state->old_key_discard_time = ktime_add_ms(ktime_get(),
						   3 * conn->idle_timeout);

	state->current_write = state->next_write;
	memzero_explicit(&state->next_write, sizeof(state->next_write));

	/* Toggle key phase for sending */
	state->current_phase ^= 1;
	state->update_pending = true;
	state->last_key_update = ktime_get();
	state->packets_sent = 0;
	state->total_key_updates++;
	state->pending_generation = state->total_key_updates;

	/* Update HP context */
	tquic_hp_set_key_phase(hp_ctx, state->current_phase);

	tquic_info("initiated key update, new phase=%d, total_updates=%llu\n",
		   state->current_phase, state->total_key_updates);

	/*
	 * Arm the key update timeout timer.  If the peer does not
	 * respond with a packet bearing the new key phase within
	 * 3 * PTO, the timer callback will revert the update so
	 * the connection does not get permanently stuck.
	 */
	{
		struct tquic_path *path;
		u32 pto_ms = 0;
		ktime_t deadline;

		rcu_read_lock();
		path = rcu_dereference(conn->active_path);
		if (path)
			pto_ms = tquic_rtt_pto(&path->rtt);
		rcu_read_unlock();

		if (pto_ms > 0) {
			deadline = ktime_add_ms(ktime_get(),
						TQUIC_KEY_UPDATE_TIMEOUT_PTO_MULT *
						pto_ms);
			tquic_timer_set(conn, TQUIC_TIMER_KEY_UPDATE, deadline);
		}
	}

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

	if (state->keys_installing) {
		ret = -EBUSY;
		goto out_unlock;
	}

	if (state->update_pending) {
		/*
		 * We initiated the update - this packet confirms peer
		 * has updated their keys. Complete the update.
		 */
		struct tquic_key_generation staged_next;
		struct tquic_key_generation staged_cur_write;

		state->update_pending = false;
		state->peer_update_received = false;

		/* Cancel the key update timeout timer */
		tquic_timer_cancel(conn, TQUIC_TIMER_KEY_UPDATE);

		/*
		 * Pre-compute next generation for future updates.
		 * Use staging to avoid modifying state while unlocked.
		 */
		staged_cur_write = state->current_write;
		memset(&staged_next, 0, sizeof(staged_next));
		spin_unlock_irqrestore(&state->lock, flags);

		ret = tquic_ku_derive_next_generation(state,
						      &staged_cur_write,
						      &staged_next);
		memzero_explicit(&staged_cur_write,
				 sizeof(staged_cur_write));

		spin_lock_irqsave(&state->lock, flags);
		if (ret == 0)
			state->next_write = staged_next;
		else
			memzero_explicit(&staged_next,
					 sizeof(staged_next));

		tquic_info("key update confirmed by peer ACK\n");
	} else {
		/*
		 * Peer initiated the update - we need to:
		 * 1. Derive new read keys to decrypt this packet
		 * 2. Derive new write keys to respond with same phase
		 * 3. Update our key phase
		 */
		struct tquic_key_generation staged_read;
		struct tquic_key_generation staged_write;
		struct tquic_key_generation staged_cur_read;
		struct tquic_key_generation staged_cur_write;

		state->peer_update_received = true;
		state->peer_initiated_updates++;

		/*
		 * Snapshot current keys under lock, then derive new
		 * keys into local staging variables while unlocked.
		 */
		staged_cur_read = state->current_read;
		staged_cur_write = state->current_write;
		memset(&staged_read, 0, sizeof(staged_read));
		memset(&staged_write, 0, sizeof(staged_write));
		spin_unlock_irqrestore(&state->lock, flags);

		/* Derive new read keys */
		ret = tquic_ku_derive_next_generation(state,
						      &staged_cur_read,
						      &staged_read);
		if (ret) {
			memzero_explicit(&staged_cur_read,
					 sizeof(staged_cur_read));
			memzero_explicit(&staged_cur_write,
					 sizeof(staged_cur_write));
			memzero_explicit(&staged_read,
					 sizeof(staged_read));
			spin_lock_irqsave(&state->lock, flags);
			state->peer_update_received = false;
			state->peer_initiated_updates--;
			goto out_unlock;
		}

		/* Derive new write keys */
		ret = tquic_ku_derive_next_generation(state,
						      &staged_cur_write,
						      &staged_write);
		memzero_explicit(&staged_cur_read,
				 sizeof(staged_cur_read));
		memzero_explicit(&staged_cur_write,
				 sizeof(staged_cur_write));
		if (ret) {
			memzero_explicit(&staged_read,
					 sizeof(staged_read));
			memzero_explicit(&staged_write,
					 sizeof(staged_write));
			spin_lock_irqsave(&state->lock, flags);
			state->peer_update_received = false;
			state->peer_initiated_updates--;
			goto out_unlock;
		}

		/* Re-acquire lock and commit the staged keys */
		spin_lock_irqsave(&state->lock, flags);

		/*
		 * Re-check after reacquiring lock - another handler may
		 * have already rotated the keys while we were deriving.
		 * If the phase already matches received_phase, a
		 * concurrent handler won the race; discard our keys.
		 */
		if (state->current_phase == received_phase) {
			spin_unlock_irqrestore(&state->lock, flags);
			memzero_explicit(&staged_read,
					 sizeof(staged_read));
			memzero_explicit(&staged_write,
					 sizeof(staged_write));
			return 0;
		}

		/* Save old read keys for packets in flight */
		state->old_read = state->current_read;
		state->old_keys_valid = true;
		state->old_key_discard_time = ktime_add_ms(ktime_get(),
							   3 * conn->idle_timeout);

		state->current_read = staged_read;
		state->current_write = staged_write;
		memzero_explicit(&state->next_read, sizeof(state->next_read));
		memzero_explicit(&state->next_write, sizeof(state->next_write));

		/* Toggle our key phase to match peer */
		state->current_phase = received_phase;
		state->last_key_update = ktime_get();
		state->packets_sent = 0;
		state->packets_received = 0;
		state->total_key_updates++;

		/* Update HP context */
		tquic_hp_set_key_phase(hp_ctx, state->current_phase);

		tquic_info("responded to peer key update, new phase=%d\n",
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

	/*
	 * Validate old keys are available for decryption.
	 *
	 * This function validates that old keys exist and haven't expired,
	 * but the actual AEAD decryption happens in tquic_decrypt_packet()
	 * which calls crypto_aead_decrypt() with the appropriate key material.
	 *
	 * The caller should:
	 * 1. Call this function to verify old keys are available
	 * 2. On success (return 0), use tquic_key_update_get_old_read_keys()
	 *    to retrieve the actual key/IV for decryption
	 * 3. Attempt decryption with those keys via crypto_aead_decrypt()
	 *
	 * This separation allows the caller to handle both current and old
	 * key decryption attempts efficiently without holding the lock
	 * during the potentially expensive crypto operations.
	 */

	spin_unlock_irqrestore(&state->lock, flags);

	/* Success: old keys are available and valid for the caller to use */
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

	kfree_sensitive(state);
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
	struct tquic_key_generation staged_read, staged_write;
	struct tquic_key_generation staged_next_read, staged_next_write;
	unsigned long flags;
	int ret;

	if (!state || !read_secret || !write_secret)
		return -EINVAL;

	if (secret_len > TQUIC_SECRET_MAX_LEN)
		return -EINVAL;

	spin_lock_irqsave(&state->lock, flags);

	/* Prevent concurrent installation (CF-149) */
	if (state->keys_installing) {
		spin_unlock_irqrestore(&state->lock, flags);
		return -EBUSY;
	}
	state->keys_installing = true;

	/*
	 * Set up staged copies under lock so derivation can proceed
	 * without holding the spinlock (CF-033).
	 */
	memzero_explicit(&staged_read, sizeof(staged_read));
	memcpy(staged_read.secret, read_secret, secret_len);
	staged_read.secret_len = secret_len;
	staged_read.key_len = state->current_read.key_len;
	staged_read.iv_len = state->current_read.iv_len;

	memzero_explicit(&staged_write, sizeof(staged_write));
	memcpy(staged_write.secret, write_secret, secret_len);
	staged_write.secret_len = secret_len;
	staged_write.key_len = state->current_write.key_len;
	staged_write.iv_len = state->current_write.iv_len;

	memzero_explicit(&staged_next_read, sizeof(staged_next_read));
	memzero_explicit(&staged_next_write, sizeof(staged_next_write));

	spin_unlock_irqrestore(&state->lock, flags);

	/* Derive keys from staged local copies */
	ret = tquic_ku_derive_keys(state, &staged_read);
	if (ret)
		goto out_clear;

	ret = tquic_ku_derive_keys(state, &staged_write);
	if (ret)
		goto out_clear;

	/* Pre-compute next generation keys (best effort) */
	if (tquic_ku_derive_next_generation(state, &staged_read,
					    &staged_next_read))
		pr_warn("tquic_key_update: failed to pre-compute next read keys\n");

	if (tquic_ku_derive_next_generation(state, &staged_write,
					    &staged_next_write))
		pr_warn("tquic_key_update: failed to pre-compute next write keys\n");

	/* Commit all derived keys atomically under lock */
	spin_lock_irqsave(&state->lock, flags);
	state->current_read = staged_read;
	state->current_write = staged_write;
	if (staged_next_read.valid)
		state->next_read = staged_next_read;
	if (staged_next_write.valid)
		state->next_write = staged_next_write;
	state->handshake_confirmed = true;
	state->current_phase = 0;
	state->last_key_update = ktime_get();
	state->keys_installing = false;
	spin_unlock_irqrestore(&state->lock, flags);

	memzero_explicit(&staged_read, sizeof(staged_read));
	memzero_explicit(&staged_write, sizeof(staged_write));
	memzero_explicit(&staged_next_read, sizeof(staged_next_read));
	memzero_explicit(&staged_next_write, sizeof(staged_next_write));

	pr_debug("tquic_key_update: installed initial application secrets\n");

	return 0;

out_clear:
	spin_lock_irqsave(&state->lock, flags);
	state->keys_installing = false;
	spin_unlock_irqrestore(&state->lock, flags);
	memzero_explicit(&staged_read, sizeof(staged_read));
	memzero_explicit(&staged_write, sizeof(staged_write));
	memzero_explicit(&staged_next_read, sizeof(staged_next_read));
	memzero_explicit(&staged_next_write, sizeof(staged_next_write));
	return ret;
}
EXPORT_SYMBOL_GPL(tquic_key_update_install_secrets);

/**
 * tquic_key_update_on_packet_sent - Track packet sent for key update timing
 * @state: Key update state
 *
 * Called after each packet is sent to track statistics.
 * May trigger automatic key update based on configured thresholds.
 *
 * Returns 0 on success, -ENOSPC if the AEAD confidentiality limit has
 * been reached and a key update is required before further encryption.
 */
int tquic_key_update_on_packet_sent(struct tquic_key_update_state *state)
{
	unsigned long flags;
	int ret = 0;

	if (!state)
		return -EINVAL;

	spin_lock_irqsave(&state->lock, flags);
	state->packets_sent++;

	/*
	 * Hard enforcement of AEAD confidentiality limits per
	 * RFC 9001 Section 6.6. If the counter reaches the limit,
	 * refuse further encryption until a key update occurs.
	 */
	if (state->packets_sent >= state->confidentiality_limit) {
		pr_err("tquic_key_update: AEAD confidentiality limit reached "
		       "(sent=%llu, limit=%llu), key update required\n",
		       state->packets_sent, state->confidentiality_limit);
		ret = -ENOSPC;
	}

	spin_unlock_irqrestore(&state->lock, flags);
	return ret;
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
 * If extended key update is enabled, uses that mechanism instead
 * of the RFC 9001 key phase bit mechanism.
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
		/*
		 * Check if extended key update is enabled and use it
		 * for coordinated key updates with acknowledgment.
		 */
		if (tquic_eku_is_enabled(conn)) {
			s64 ret = tquic_eku_request(conn, 0);
			if (ret >= 0)
				return true;
			/*
			 * Fall through to RFC 9001 if EKU request fails.
			 * This provides graceful degradation.
			 */
			pr_debug("tquic: EKU request failed (%lld), using RFC 9001\n",
				 ret);
		}

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
 * tquic_key_update_get_current_secret - Get current traffic secret
 * @state: Key update state
 * @direction: 0 = read, 1 = write
 * @secret: Output buffer for traffic secret
 * @secret_len: Output secret length
 *
 * Returns 0 on success, negative error code on failure.
 */
int tquic_key_update_get_current_secret(struct tquic_key_update_state *state,
					int direction,
					u8 *secret, u32 *secret_len)
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

	if (secret && secret_len) {
		memcpy(secret, gen->secret, gen->secret_len);
		*secret_len = gen->secret_len;
	}

	spin_unlock_irqrestore(&state->lock, flags);
	return 0;
}
EXPORT_SYMBOL_GPL(tquic_key_update_get_current_secret);

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
 * @crypto_state: Connection's crypto state (struct tquic_crypto_state *)
 *
 * Retrieves the key update state from the connection's crypto state.
 * The crypto_state parameter is the opaque pointer stored in
 * conn->crypto_state, which is actually a struct tquic_crypto_state.
 *
 * Returns key update state or NULL if not available.
 */
struct tquic_key_update_state *
tquic_crypto_get_key_update_state(void *crypto_state)
{
	/*
	 * Mirror the layout of struct tquic_crypto_state from tls.c so
	 * that we can use offsetof() rather than a hardcoded byte offset.
	 * This is still a layering violation -- ideally tls.c would export
	 * a helper -- but it is at least resilient to field-size changes
	 * because the compiler computes the offset.
	 *
	 * Keep this in sync with struct tquic_crypto_state in tls.c.
	 */
#define TQUIC_ENC_LEVEL_COUNT	4
#define TQUIC_SECRET_MAX_LEN_	64
#define TQUIC_KEY_MAX_LEN_	32
#define TQUIC_IV_MAX_LEN_	12
#define TQUIC_HP_KEY_MAX_LEN_	32
	struct tquic_crypto_state_mirror {
		u16 cipher_suite;
		u32 version;
		struct {
			u8 secret[TQUIC_SECRET_MAX_LEN_];
			u8 key[TQUIC_KEY_MAX_LEN_];
			u8 iv[TQUIC_IV_MAX_LEN_];
			u8 hp_key[TQUIC_HP_KEY_MAX_LEN_];
			u32 secret_len;
			u32 key_len;
			u32 iv_len;
			bool valid;
		} read_keys[TQUIC_ENC_LEVEL_COUNT],
		  write_keys[TQUIC_ENC_LEVEL_COUNT];
		int read_level;   /* enum tquic_enc_level */
		int write_level;
		u32 key_phase;
		bool key_update_pending;
		struct tquic_key_update_state *key_update;
		/* remaining fields omitted */
	} *cs;
#undef TQUIC_ENC_LEVEL_COUNT
#undef TQUIC_SECRET_MAX_LEN_
#undef TQUIC_KEY_MAX_LEN_
#undef TQUIC_IV_MAX_LEN_
#undef TQUIC_HP_KEY_MAX_LEN_

	if (!crypto_state)
		return NULL;

	cs = crypto_state;

	/* Sanity check: cipher_suite should be a known TLS 1.3 value */
	if (cs->cipher_suite == 0)
		return NULL;

	return cs->key_update;
}
EXPORT_SYMBOL_GPL(tquic_crypto_get_key_update_state);

/*
 * =============================================================================
 * Extended Key Update Integration
 * =============================================================================
 */

/**
 * tquic_key_update_with_psk - Derive keys with additional PSK material
 * @conn: TQUIC connection
 * @psk: Pre-shared key material to mix in
 * @psk_len: Length of PSK material
 *
 * Derives new keys by first mixing the PSK with current secrets using
 * HKDF-Extract, then performing standard key derivation.
 *
 * This is used by the Extended Key Update extension to incorporate
 * external key material (e.g., from post-quantum key exchange).
 *
 * Returns 0 on success, negative error code on failure.
 */
int tquic_key_update_with_psk(struct tquic_connection *conn,
			      const u8 *psk, size_t psk_len)
{
	struct tquic_key_update_state *state;
	u8 mixed_read_secret[TQUIC_SECRET_MAX_LEN];
	u8 mixed_write_secret[TQUIC_SECRET_MAX_LEN];
	u8 local_read_secret[TQUIC_SECRET_MAX_LEN];
	u8 local_write_secret[TQUIC_SECRET_MAX_LEN];
	size_t local_read_secret_len;
	size_t local_write_secret_len;
	unsigned long flags;
	int ret;

	if (!conn || !conn->crypto_state)
		return -EINVAL;

	if (!psk || psk_len == 0 || psk_len > TQUIC_SECRET_MAX_LEN)
		return -EINVAL;

	state = tquic_crypto_get_key_update_state(conn->crypto_state);
	if (!state)
		return -EINVAL;

	spin_lock_irqsave(&state->lock, flags);

	if (!state->handshake_confirmed) {
		spin_unlock_irqrestore(&state->lock, flags);
		return -EAGAIN;
	}

	if (!state->current_read.valid || !state->current_write.valid) {
		spin_unlock_irqrestore(&state->lock, flags);
		return -EINVAL;
	}

	/*
	 * Copy secrets into local variables while holding the lock
	 * to avoid racing with concurrent key updates (CF-033).
	 */
	memcpy(local_read_secret, state->current_read.secret,
	       state->current_read.secret_len);
	local_read_secret_len = state->current_read.secret_len;
	memcpy(local_write_secret, state->current_write.secret,
	       state->current_write.secret_len);
	local_write_secret_len = state->current_write.secret_len;

	spin_unlock_irqrestore(&state->lock, flags);

	/*
	 * Mix PSK with current secrets using HKDF-Extract:
	 * mixed_secret = HKDF-Extract(current_secret, psk)
	 *
	 * This provides additional entropy from the external PSK
	 * while maintaining forward secrecy properties.
	 */
	ret = crypto_shash_setkey(state->hash_tfm,
				  local_read_secret,
				  local_read_secret_len);
	if (ret)
		goto cleanup;

	/* For read direction */
	{
		SHASH_DESC_ON_STACK(desc, state->hash_tfm);
		desc->tfm = state->hash_tfm;

		ret = crypto_shash_init(desc);
		if (ret)
			goto cleanup;

		ret = crypto_shash_update(desc, psk, psk_len);
		if (ret)
			goto cleanup;

		ret = crypto_shash_final(desc, mixed_read_secret);
		if (ret)
			goto cleanup;
	}

	/* For write direction */
	ret = crypto_shash_setkey(state->hash_tfm,
				  local_write_secret,
				  local_write_secret_len);
	if (ret)
		goto cleanup;

	{
		SHASH_DESC_ON_STACK(desc, state->hash_tfm);
		desc->tfm = state->hash_tfm;

		ret = crypto_shash_init(desc);
		if (ret)
			goto cleanup;

		ret = crypto_shash_update(desc, psk, psk_len);
		if (ret)
			goto cleanup;

		ret = crypto_shash_final(desc, mixed_write_secret);
		if (ret)
			goto cleanup;
	}

	/*
	 * Install the mixed secrets as the base for next key derivation.
	 * The actual key derivation will happen in tquic_initiate_key_update().
	 */
	spin_lock_irqsave(&state->lock, flags);

	memcpy(state->current_read.secret, mixed_read_secret,
	       state->current_read.secret_len);
	memcpy(state->current_write.secret, mixed_write_secret,
	       state->current_write.secret_len);

	/* Invalidate pre-computed next keys so they'll be re-derived */
	state->next_read.valid = false;
	state->next_write.valid = false;

	spin_unlock_irqrestore(&state->lock, flags);

	/* Now perform the standard key update */
	ret = tquic_initiate_key_update(conn);

cleanup:
	memzero_explicit(mixed_read_secret, sizeof(mixed_read_secret));
	memzero_explicit(mixed_write_secret, sizeof(mixed_write_secret));
	memzero_explicit(local_read_secret, sizeof(local_read_secret));
	memzero_explicit(local_write_secret, sizeof(local_write_secret));

	return ret;
}
EXPORT_SYMBOL_GPL(tquic_key_update_with_psk);

/**
 * tquic_key_update_get_old_read_keys - Get previous generation read keys
 * @state: Key update state
 * @key: Output buffer for AEAD key
 * @key_len: Output: key length
 * @iv: Output buffer for IV
 * @iv_len: Output: IV length
 *
 * Returns 0 on success, -ENOKEY if old keys not available.
 */
int tquic_key_update_get_old_read_keys(struct tquic_key_update_state *state,
				       u8 *key, u32 *key_len,
				       u8 *iv, u32 *iv_len)
{
	struct tquic_key_generation *old;
	unsigned long flags;

	if (!state)
		return -EINVAL;

	spin_lock_irqsave(&state->lock, flags);

	if (!state->old_keys_valid) {
		spin_unlock_irqrestore(&state->lock, flags);
		return -ENOKEY;
	}

	old = &state->old_read;
	if (!old->valid) {
		spin_unlock_irqrestore(&state->lock, flags);
		return -ENOKEY;
	}

	if (key && key_len) {
		memcpy(key, old->key, old->key_len);
		*key_len = old->key_len;
	}

	if (iv && iv_len) {
		memcpy(iv, old->iv, old->iv_len);
		*iv_len = old->iv_len;
	}

	spin_unlock_irqrestore(&state->lock, flags);
	return 0;
}
EXPORT_SYMBOL_GPL(tquic_key_update_get_old_read_keys);

/*
 * =============================================================================
 * Key Update Timeout / Revert
 * =============================================================================
 */

/**
 * tquic_key_update_timeout - Handle key update timeout
 * @conn: TQUIC connection
 *
 * Called when the TQUIC_TIMER_KEY_UPDATE timer fires because the peer
 * has not responded with a packet bearing the new key phase within
 * 3 * PTO.  Reverts the key update so the connection is not
 * permanently stuck in the update_pending state.
 *
 * The revert restores the previous key phase and write keys so
 * that the endpoint can continue communicating (or at least
 * clean up gracefully via idle/loss timeout).
 */
void tquic_key_update_timeout(struct tquic_connection *conn)
{
	struct tquic_key_update_state *state;
	struct tquic_hp_ctx *hp_ctx;
	unsigned long flags;

	if (!conn || !conn->crypto_state)
		return;

	state = tquic_crypto_get_key_update_state(conn->crypto_state);
	if (!state)
		return;

	hp_ctx = tquic_crypto_get_hp_ctx(conn->crypto_state);

	spin_lock_irqsave(&state->lock, flags);

	if (!state->update_pending) {
		/*
		 * Confirmed before the timer fired -- nothing to do.
		 */
		spin_unlock_irqrestore(&state->lock, flags);
		return;
	}

	/*
	 * Verify we are reverting the same key update that armed
	 * this timer, not a subsequent one (race with concurrent
	 * initiation that confirmed and re-initiated).
	 */
	if (state->pending_generation != state->total_key_updates) {
		spin_unlock_irqrestore(&state->lock, flags);
		return;
	}

	tquic_info("key update timed out (peer did not respond), reverting phase=%d\n",
		   state->current_phase);

	/*
	 * Revert the key phase to the pre-update value.
	 * Initiation toggled it, so toggle again to restore.
	 */
	state->current_phase ^= 1;

	/*
	 * Restore write keys from old_read.  When we initiated the
	 * update, old_read was set to a copy of current_read (the
	 * pre-update generation).  Since RX keys have not been
	 * rotated yet (that only happens on peer confirmation), the
	 * old_read snapshot is still valid for the previous gen.
	 *
	 * We copy old_read -> current_write to get back to the
	 * generation that the peer last acknowledged.
	 */
	if (state->old_keys_valid && state->old_read.valid) {
		state->current_write = state->old_read;
	} else {
		/*
		 * Fallback: use current_read which should still be
		 * the pre-update generation since RX was not rotated.
		 */
		if (state->current_read.valid)
			state->current_write = state->current_read;
	}

	/* Invalidate pre-computed next-gen keys so they are re-derived */
	state->next_write.valid = false;

	/* Clear pending state */
	state->update_pending = false;
	state->total_key_updates--;  /* Don't count the failed attempt */

	/* Discard old keys -- no longer meaningful after revert */
	if (state->old_keys_valid) {
		memzero_explicit(&state->old_read, sizeof(state->old_read));
		state->old_keys_valid = false;
	}

	/* Restore HP context to reverted phase */
	if (hp_ctx)
		tquic_hp_set_key_phase(hp_ctx, state->current_phase);

	spin_unlock_irqrestore(&state->lock, flags);

	tquic_info("key update reverted, restored phase=%d\n",
		   state->current_phase);
}
EXPORT_SYMBOL_GPL(tquic_key_update_timeout);

MODULE_DESCRIPTION("TQUIC TLS 1.3 Key Update Mechanism");
MODULE_LICENSE("GPL");
MODULE_AUTHOR("Linux Foundation");
