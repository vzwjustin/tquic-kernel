// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * TQUIC Key Update Mechanism (RFC 9001 Section 6)
 *
 * This module implements the QUIC key update mechanism which allows
 * encryption keys to be updated during a connection without interruption.
 *
 * Key update features:
 * - Either endpoint can initiate by toggling the KEY_PHASE bit
 * - New keys are derived using HKDF-Expand-Label with "quic ku" label
 * - Old keys retained briefly for handling reordered packets
 * - Keys discarded after a timeout (3x PTO recommended)
 *
 * Copyright (c) 2026 Justin Adams <spotty118@gmail.com>
 * Kernel implementation by Justin Adams <spotty118@gmail.com>
 */

#include <linux/slab.h>
#include <linux/errno.h>
#include <linux/string.h>
#include <crypto/aead.h>
#include <crypto/hash.h>
#include <net/tquic.h>
#include <net/tquic_frame.h>
#include "../tquic_debug.h"

/* Key update header - internal definitions for crypto state */

/*
 * TQUIC Cipher types (mirrors TLS 1.3 cipher suites)
 */
enum tquic_cipher_type {
	TQUIC_CIPHER_AES_128_GCM_SHA256 = 0x1301,
	TQUIC_CIPHER_AES_256_GCM_SHA384 = 0x1302,
	TQUIC_CIPHER_CHACHA20_POLY1305_SHA256 = 0x1303,
};

/*
 * Maximum key/IV/secret sizes
 */
#define TQUIC_MAX_KEY_LEN	32
#define TQUIC_MAX_IV_LEN	12
#define TQUIC_MAX_SECRET_LEN	64

/**
 * struct tquic_crypto_secret - Cryptographic secrets for a direction
 * @secret: Current secret (for key derivation)
 * @secret_len: Length of secret
 * @key: Derived encryption key
 * @key_len: Length of key
 * @iv: Derived IV
 * @iv_len: Length of IV
 */
struct tquic_crypto_secret {
	u8 secret[TQUIC_MAX_SECRET_LEN];
	u8 secret_len;
	u8 key[TQUIC_MAX_KEY_LEN];
	u8 key_len;
	u8 iv[TQUIC_MAX_IV_LEN];
	u8 iv_len;
};

/**
 * struct tquic_crypto_ctx - Per-level crypto context
 * @tx: Transmit direction secrets and keys
 * @rx: Receive direction secrets and keys
 * @rx_prev: Previous receive keys (for handling reordered packets)
 * @tx_aead: Transmit AEAD transform
 * @rx_aead: Receive AEAD transform
 * @rx_aead_prev: Previous receive AEAD (for reordered packets)
 * @hash: Hash algorithm for key derivation
 * @cipher_type: Cipher suite in use
 * @key_phase: Current TX key phase (0 or 1)
 * @rx_key_phase: Expected RX key phase
 * @rx_prev_valid: Whether previous RX keys are valid
 * @keys_available: Keys have been installed
 * @key_update_pending: Key update initiated, awaiting confirmation
 * @key_update_pn: First packet number with new keys
 */
struct tquic_crypto_ctx {
	struct tquic_crypto_secret tx;
	struct tquic_crypto_secret rx;
	struct tquic_crypto_secret rx_prev;

	struct crypto_aead *tx_aead;
	struct crypto_aead *rx_aead;
	struct crypto_aead *rx_aead_prev;

	struct crypto_shash *hash;
	enum tquic_cipher_type cipher_type;

	u8 key_phase:1;
	u8 rx_key_phase:1;
	u8 rx_prev_valid:1;
	u8 keys_available:1;
	u8 key_update_pending:1;
	u64 key_update_pn;
};

/*
 * Timer function declarations (from tquic_timer.c)
 */
void tquic_timer_set(struct tquic_connection *conn, u8 timer_type, ktime_t when);
void tquic_timer_cancel(struct tquic_connection *conn, u8 timer_type);

/* RTT measurement (from quic_loss.c) */
u32 tquic_rtt_pto(struct tquic_rtt_state *rtt);

/*
 * Key update timeout multiplier.
 * If the peer has not responded with the new key phase within
 * 3 * PTO, revert the key update to prevent permanent stuck state.
 * 3 * PTO is consistent with the draining period and persistent
 * congestion threshold in RFC 9002.
 */
#define TQUIC_KEY_UPDATE_TIMEOUT_PTO_MULT	3

/*
 * TQUIC_SKB_CB - Get control block from skb
 */
struct tquic_skb_cb {
	u32 header_len;
	u32 payload_len;
	u64 pn;
	u8 pn_space;
	u8 key_phase;
};

#define TQUIC_SKB_CB(skb) ((struct tquic_skb_cb *)&((skb)->cb[0]))

/*
 * Key discard timeout per RFC 9001 Section 6.1:
 * "Keys SHOULD be retained for three times the current Probe Timeout (PTO)"
 * Default to 3 * 333ms = ~1 second as a safe minimum.
 */
#define TQUIC_KEY_DISCARD_TIMEOUT_MS	1000

/* HKDF labels */
static const char tquic_ku_label[] = "quic ku";
static const char tquic_key_label[] = "quic key";
static const char tquic_iv_label[] = "quic iv";

/* Forward declarations */
struct hkdf_ctx {
	struct crypto_shash *hash;
	u32 hash_len;
};

extern int tquic_hkdf_expand_label(struct hkdf_ctx *ctx, const u8 *prk,
				   const char *label, size_t label_len,
				   const u8 *context, size_t context_len,
				   u8 *out, size_t out_len);

/*
 * tquic_key_update_tx - Update transmit keys for key update
 * @conn: TQUIC connection
 *
 * Derives new TX secret and keys using HKDF-Expand-Label with "quic ku" label.
 * Per RFC 9001 Section 6.1:
 *   secret_<n+1> = HKDF-Expand-Label(secret_<n>, "quic ku", "", Hash.length)
 *
 * Returns 0 on success, negative error code on failure.
 */
static int tquic_key_update_tx(struct tquic_connection *conn)
{
	struct tquic_crypto_ctx *ctx = 
		(struct tquic_crypto_ctx *)conn->crypto[TQUIC_CRYPTO_APPLICATION];
	struct hkdf_ctx hkdf;
	u8 new_secret[64];
	int err;

	if (!ctx || !ctx->hash || !ctx->keys_available)
		return -EINVAL;

	hkdf.hash = ctx->hash;
	hkdf.hash_len = ctx->tx.secret_len;

	/* Derive new secret from current TX secret */
	err = tquic_hkdf_expand_label(&hkdf, ctx->tx.secret, tquic_ku_label,
				strlen(tquic_ku_label), NULL, 0,
				new_secret, ctx->tx.secret_len);
	if (err)
		return err;

	/* Update TX secret */
	memcpy(ctx->tx.secret, new_secret, ctx->tx.secret_len);

	/* Derive new TX key */
	err = tquic_hkdf_expand_label(&hkdf, ctx->tx.secret, tquic_key_label,
				strlen(tquic_key_label), NULL, 0,
				ctx->tx.key, ctx->tx.key_len);
	if (err)
		goto out;

	/* Derive new TX IV */
	err = tquic_hkdf_expand_label(&hkdf, ctx->tx.secret, tquic_iv_label,
				strlen(tquic_iv_label), NULL, 0,
				ctx->tx.iv, ctx->tx.iv_len);
	if (err)
		goto out;

	/* Install new key on TX AEAD */
	err = crypto_aead_setkey(ctx->tx_aead, ctx->tx.key, ctx->tx.key_len);

out:
	memzero_explicit(new_secret, sizeof(new_secret));
	return err;
}

/*
 * tquic_key_update_rx - Update receive keys for key update
 * @conn: TQUIC connection
 *
 * Saves current RX keys as previous (for reordered packets), then derives
 * new RX secret and keys. Per RFC 9001 Section 6.1, old keys must be
 * retained briefly to handle reordered packets.
 *
 * Returns 0 on success, negative error code on failure.
 */
static int tquic_key_update_rx(struct tquic_connection *conn)
{
	struct tquic_crypto_ctx *ctx = 
		(struct tquic_crypto_ctx *)conn->crypto[TQUIC_CRYPTO_APPLICATION];
	struct hkdf_ctx hkdf;
	u8 new_secret[64];
	const char *aead_name;
	int err;

	if (!ctx || !ctx->hash || !ctx->keys_available)
		return -EINVAL;

	hkdf.hash = ctx->hash;
	hkdf.hash_len = ctx->rx.secret_len;

	/* Determine AEAD algorithm name */
	switch (ctx->cipher_type) {
	case TQUIC_CIPHER_AES_128_GCM_SHA256:
	case TQUIC_CIPHER_AES_256_GCM_SHA384:
		aead_name = "gcm(aes)";
		break;
	case TQUIC_CIPHER_CHACHA20_POLY1305_SHA256:
		aead_name = "rfc7539(chacha20,poly1305)";
		break;
	default:
		return -EINVAL;
	}

	/*
	 * Save current RX keys as previous for handling reordered packets.
	 * Free any existing previous AEAD first.
	 */
	if (ctx->rx_aead_prev)
		crypto_free_aead(ctx->rx_aead_prev);

	/* Allocate new AEAD for previous keys */
	ctx->rx_aead_prev = crypto_alloc_aead(aead_name, 0, 0);
	if (IS_ERR(ctx->rx_aead_prev)) {
		ctx->rx_aead_prev = NULL;
		ctx->rx_prev_valid = 0;
		/* Continue without previous key support - not fatal */
		tquic_conn_warn(conn, "could not allocate previous RX AEAD\n");
	} else {
		/* Copy current RX secret to previous */
		memcpy(&ctx->rx_prev, &ctx->rx, sizeof(ctx->rx_prev));

		/* Set key on previous AEAD */
		err = crypto_aead_setkey(ctx->rx_aead_prev, ctx->rx_prev.key,
					 ctx->rx_prev.key_len);
		if (err) {
			crypto_free_aead(ctx->rx_aead_prev);
			ctx->rx_aead_prev = NULL;
			ctx->rx_prev_valid = 0;
		} else {
			err = crypto_aead_setauthsize(ctx->rx_aead_prev, 16);
			if (err) {
				crypto_free_aead(ctx->rx_aead_prev);
				ctx->rx_aead_prev = NULL;
				ctx->rx_prev_valid = 0;
			} else {
				ctx->rx_prev_valid = 1;
			}
		}
	}

	/* Derive new RX secret from current RX secret */
	err = tquic_hkdf_expand_label(&hkdf, ctx->rx.secret, tquic_ku_label,
				strlen(tquic_ku_label), NULL, 0,
				new_secret, ctx->rx.secret_len);
	if (err)
		return err;

	/* Update RX secret */
	memcpy(ctx->rx.secret, new_secret, ctx->rx.secret_len);

	/* Derive new RX key */
	err = tquic_hkdf_expand_label(&hkdf, ctx->rx.secret, tquic_key_label,
				strlen(tquic_key_label), NULL, 0,
				ctx->rx.key, ctx->rx.key_len);
	if (err)
		goto out;

	/* Derive new RX IV */
	err = tquic_hkdf_expand_label(&hkdf, ctx->rx.secret, tquic_iv_label,
				strlen(tquic_iv_label), NULL, 0,
				ctx->rx.iv, ctx->rx.iv_len);
	if (err)
		goto out;

	/* Install new key on RX AEAD */
	err = crypto_aead_setkey(ctx->rx_aead, ctx->rx.key, ctx->rx.key_len);

out:
	memzero_explicit(new_secret, sizeof(new_secret));
	return err;
}

/*
 * tquic_crypto_initiate_key_update - Initiate a key update (RFC 9001 Section 6.1)
 * @conn: TQUIC connection
 *
 * Called when the local endpoint wants to update keys. This:
 * 1. Updates TX keys and toggles TX key phase
 * 2. Marks key update as pending (awaiting peer's response)
 * 3. Records the first packet number sent with new keys
 *
 * Per RFC 9001 Section 6.2, an endpoint MUST NOT initiate a subsequent
 * key update until it has received an acknowledgment for a packet sent
 * with the new keys.
 *
 * Returns 0 on success, -EAGAIN if key update already pending, other
 * negative error code on failure.
 */
int tquic_crypto_initiate_key_update(struct tquic_connection *conn)
{
	struct tquic_crypto_ctx *ctx = 
		(struct tquic_crypto_ctx *)conn->crypto[TQUIC_CRYPTO_APPLICATION];
	struct tquic_pn_space *pn_space = &conn->pn_spaces[TQUIC_PN_SPACE_APPLICATION];
	int err;

	if (!ctx || !ctx->keys_available)
		return -EINVAL;

	/* Check if we're already in a key update (RFC 9001 Section 6.2) */
	if (ctx->key_update_pending)
		return -EAGAIN;

	/* Update TX keys */
	err = tquic_key_update_tx(conn);
	if (err)
		return err;

	/* Toggle TX key phase */
	ctx->key_phase = !ctx->key_phase;

	/* Mark key update as pending and record first PN with new keys */
	ctx->key_update_pending = 1;
	ctx->key_update_pn = pn_space->next_pn;

	/*
	 * Arm the key update timeout timer.  If the peer does not respond
	 * with a packet bearing the new key phase within 3 * PTO, the
	 * timer callback will revert the update so the connection does
	 * not get permanently stuck in the update_pending state.
	 */
	if (conn->active_path) {
		u32 pto_ms = tquic_rtt_pto(&conn->active_path->rtt);
		ktime_t deadline;

		deadline = ktime_add_ms(ktime_get(),
					TQUIC_KEY_UPDATE_TIMEOUT_PTO_MULT *
					pto_ms);
		tquic_timer_set(conn, TQUIC_TIMER_KEY_UPDATE, deadline);
	}

	tquic_conn_info(conn, "key update initiated phase=%u first_pn=%llu\n",
			ctx->key_phase, ctx->key_update_pn);

	return 0;
}
EXPORT_SYMBOL_GPL(tquic_crypto_initiate_key_update);

/*
 * tquic_crypto_on_key_phase_change - Handle received packet with different key phase
 * @conn: TQUIC connection
 * @rx_key_phase: Key phase bit from received packet
 *
 * Called when a packet is received with a key phase different from expected.
 * Per RFC 9001 Section 6.2:
 * - If we initiated the update, this confirms the peer received our update
 * - If the peer initiated, we need to update our RX keys and respond
 *
 * Returns 0 on success, negative error code on failure.
 */
int tquic_crypto_on_key_phase_change(struct tquic_connection *conn, u8 rx_key_phase)
{
	struct tquic_crypto_ctx *ctx = 
		(struct tquic_crypto_ctx *)conn->crypto[TQUIC_CRYPTO_APPLICATION];
	ktime_t discard_time;
	int err;

	if (!ctx || !ctx->keys_available)
		return -EINVAL;

	/*
	 * RFC 9001 Section 6.2: Detect consecutive key updates
	 *
	 * "An endpoint that receives a second update before it has sent an
	 * acknowledgment for the packet that initiated the key update MUST
	 * treat this as a connection error of type KEY_UPDATE_ERROR."
	 *
	 * If peer initiates a key update while we have one pending (and not
	 * yet confirmed by peer), this is a consecutive update error.
	 */
	if (ctx->key_update_pending && rx_key_phase != ctx->key_phase) {
		tquic_conn_err(conn, "consecutive key update (pending=%u rx=%u cur=%u)\n",
			       ctx->key_update_pending, rx_key_phase,
			       ctx->key_phase);
		/*
		 * Return KEY_UPDATE_ERROR. Caller should close connection
		 * with error code 0x0E (KEY_UPDATE_ERROR per RFC 9001).
		 */
		return -EKEYREJECTED;
	}

	/*
	 * Case 1: We initiated the key update and peer has responded with
	 * a packet using the new key phase. Our pending state is confirmed.
	 *
	 * Per RFC 9001 Section 6.2: An endpoint that initiates a key update
	 * sends with the new keys before receiving with them. When we receive
	 * a packet with the new key phase, it confirms the peer has accepted
	 * our update. We now update our RX keys to complete the transition.
	 */
	if (ctx->key_update_pending && rx_key_phase == ctx->key_phase) {
		/*
		 * Update RX keys to match the new phase.
		 * TX keys were already updated when we initiated the update.
		 * If RX update fails here, the connection cannot proceed as
		 * we cannot decrypt future packets from the peer.
		 */
		err = tquic_key_update_rx(conn);
		if (err) {
			tquic_conn_err(conn, "RX key update failed in confirmation phase (err=%d)\n",
				       err);
			/*
			 * This is a critical failure. TX keys are already updated
			 * but RX keys failed. Per RFC 9001, this makes the
			 * connection unusable - we can send but not receive.
			 * Return error to trigger connection closure.
			 */
			return err;
		}

		ctx->rx_key_phase = rx_key_phase;
		ctx->key_update_pending = 0;

		/*
		 * Peer confirmed our key update -- cancel the timeout
		 * timer that would otherwise revert the update.
		 */
		tquic_timer_cancel(conn, TQUIC_TIMER_KEY_UPDATE);

		/* Start timer to discard old RX keys (RFC 9001 Section 6.1) */
		discard_time = ktime_add_ms(ktime_get(), TQUIC_KEY_DISCARD_TIMEOUT_MS);
		tquic_timer_set(conn, TQUIC_TIMER_KEY_DISCARD, discard_time);

		tquic_conn_info(conn, "key update confirmed by peer, phase=%u\n",
				rx_key_phase);
		return 0;
	}

	/*
	 * Case 2: Peer initiated a key update. We need to:
	 * 1. Update our RX keys to decrypt the new packet
	 * 2. Update our TX keys to respond with the new phase
	 *
	 * CRITICAL: Per RFC 9001 Section 6.2, both keys must be updated
	 * atomically to avoid asymmetric key state. If either update fails,
	 * we must rollback to maintain key phase synchronization.
	 */
	if (rx_key_phase != ctx->rx_key_phase) {
		struct tquic_crypto_secret saved_rx;
		struct crypto_aead *saved_rx_aead_prev;
		u8 saved_rx_key_phase;
		u8 saved_rx_prev_valid;

		/* Save current RX state for potential rollback */
		memcpy(&saved_rx, &ctx->rx, sizeof(saved_rx));
		saved_rx_aead_prev = ctx->rx_aead_prev;
		saved_rx_key_phase = ctx->rx_key_phase;
		saved_rx_prev_valid = ctx->rx_prev_valid;

		/*
		 * Update RX keys first.
		 * This saves current keys as "previous" and derives new keys.
		 */
		err = tquic_key_update_rx(conn);
		if (err) {
			tquic_conn_warn(conn, "RX key update failed, err=%d\n", err);
			memzero_explicit(&saved_rx, sizeof(saved_rx));
			return err;
		}

		/* Update RX key phase to match received packet */
		ctx->rx_key_phase = rx_key_phase;

		/*
		 * Now update TX keys to match.
		 * If this fails, we MUST rollback RX keys to avoid asymmetry.
		 */
		err = tquic_key_update_tx(conn);
		if (err) {
			/*
			 * TX update failed - CRITICAL: rollback RX update.
			 * Per RFC 9001 Section 6.2, asymmetric key state causes
			 * decryption failures and connection breakage.
			 */
			tquic_conn_warn(conn, "TX key update failed after RX update, rolling back (err=%d)\n",
					err);

			/* Rollback: restore saved RX state */
			memcpy(&ctx->rx, &saved_rx, sizeof(ctx->rx));
			ctx->rx_key_phase = saved_rx_key_phase;
			ctx->rx_prev_valid = saved_rx_prev_valid;

			/* Free the newly allocated previous AEAD that we don't need */
			if (ctx->rx_aead_prev && ctx->rx_aead_prev != saved_rx_aead_prev)
				crypto_free_aead(ctx->rx_aead_prev);

			/* Restore saved previous AEAD */
			ctx->rx_aead_prev = saved_rx_aead_prev;

			/*
			 * Re-install the old RX key on the current AEAD.
			 * This ensures decryption continues with pre-update keys.
			 */
			err = crypto_aead_setkey(ctx->rx_aead, ctx->rx.key,
						 ctx->rx.key_len);
			if (err) {
				/*
				 * Rollback failed - connection is now in
				 * inconsistent state. Per RFC 9001, this is a
				 * fatal error requiring connection termination.
				 */
				tquic_conn_err(conn, "RX key rollback failed, connection unusable (err=%d)\n",
					       err);
				/* Return KEY_UPDATE_ERROR code */
				memzero_explicit(&saved_rx, sizeof(saved_rx));
				return -EKEYREJECTED;
			}

			/*
			 * Return original TX update error to caller.
			 * The connection remains usable with old keys.
			 */
			memzero_explicit(&saved_rx, sizeof(saved_rx));
			return err;
		}

		/* Both updates succeeded - commit the new key phase */
		ctx->key_phase = rx_key_phase;

		/* Start timer to discard old RX keys (RFC 9001 Section 6.1) */
		discard_time = ktime_add_ms(ktime_get(), TQUIC_KEY_DISCARD_TIMEOUT_MS);
		tquic_timer_set(conn, TQUIC_TIMER_KEY_DISCARD, discard_time);

		tquic_conn_info(conn, "responded to peer key update, new phase=%u\n",
				rx_key_phase);
		memzero_explicit(&saved_rx, sizeof(saved_rx));
		return 0;
	}

	/* Key phase matches expected - no action needed */
	return 0;
}
EXPORT_SYMBOL_GPL(tquic_crypto_on_key_phase_change);

/*
 * tquic_crypto_discard_old_keys - Discard previous generation keys
 * @conn: TQUIC connection
 *
 * Called by key discard timer to free old keys. Per RFC 9001 Section 6.1,
 * keys SHOULD be discarded when it's unlikely that any packet protected
 * with the old keys will be received.
 */
void tquic_crypto_discard_old_keys(struct tquic_connection *conn)
{
	struct tquic_crypto_ctx *ctx = 
		(struct tquic_crypto_ctx *)conn->crypto[TQUIC_CRYPTO_APPLICATION];

	if (!ctx)
		return;

	if (ctx->rx_aead_prev) {
		crypto_free_aead(ctx->rx_aead_prev);
		ctx->rx_aead_prev = NULL;
	}

	ctx->rx_prev_valid = 0;
	memzero_explicit(&ctx->rx_prev, sizeof(ctx->rx_prev));

	tquic_conn_dbg(conn, "discarded old keys\n");
}
EXPORT_SYMBOL_GPL(tquic_crypto_discard_old_keys);

/*
 * tquic_crypto_revert_key_update - Revert a timed-out key update
 * @conn: TQUIC connection
 *
 * Called by the TQUIC_TIMER_KEY_UPDATE timer when the peer has not
 * responded with the new key phase within 3 * PTO.  This prevents
 * the connection from being permanently stuck in the key_update_pending
 * state.
 *
 * The revert process:
 * 1. Toggle key_phase back to the pre-update value
 * 2. Restore TX keys from the old read keys (which were saved as a
 *    snapshot of the pre-update generation when we initiated)
 * 3. Clear the key_update_pending flag
 *
 * After revert, the endpoint can attempt a fresh key update later
 * if desired, or close the connection if the peer is unresponsive.
 *
 * NOTE: This is a recovery mechanism.  If the peer is truly
 * unreachable, the idle or loss timers will eventually close the
 * connection.  The purpose here is solely to unblock the key update
 * state machine so it does not prevent further key updates.
 */
void tquic_crypto_revert_key_update(struct tquic_connection *conn)
{
	struct tquic_crypto_ctx *ctx;
	int err;

	if (!conn)
		return;

	ctx = (struct tquic_crypto_ctx *)conn->crypto[TQUIC_CRYPTO_APPLICATION];
	if (!ctx)
		return;

	if (!ctx->key_update_pending) {
		/* Update was confirmed before the timer fired -- nothing to do */
		return;
	}

	tquic_conn_warn(conn,
			"key update timed out (peer did not respond), reverting phase=%u\n",
			ctx->key_phase);

	/*
	 * Revert the TX key phase to the value before we initiated.
	 * Since initiation toggled the phase, toggling again restores it.
	 */
	ctx->key_phase = !ctx->key_phase;

	/*
	 * Restore TX keys from the current RX secret.
	 *
	 * When we initiated the key update in tquic_crypto_initiate_key_update(),
	 * the old TX secret was already overwritten by tquic_key_update_tx().
	 * However, the RX keys have not been updated yet (that happens only
	 * when the peer confirms), so the current RX secret still corresponds
	 * to the pre-update generation.  We can re-derive TX keys from the
	 * current RX secret because at this point both directions should use
	 * the same generation of secrets.
	 */
	memcpy(ctx->tx.secret, ctx->rx.secret, ctx->rx.secret_len);
	ctx->tx.secret_len = ctx->rx.secret_len;

	/*
	 * Validate cipher type before attempting key derivation.
	 */
	switch (ctx->cipher_type) {
	case TQUIC_CIPHER_AES_128_GCM_SHA256:
	case TQUIC_CIPHER_AES_256_GCM_SHA384:
	case TQUIC_CIPHER_CHACHA20_POLY1305_SHA256:
		break;
	default:
		tquic_conn_err(conn,
			       "key update revert: unknown cipher type 0x%x\n",
			       ctx->cipher_type);
		ctx->key_update_pending = 0;
		return;
	}

	/*
	 * Re-derive TX key and IV from the restored secret using the same
	 * HKDF-Expand-Label derivation used during initial key install.
	 */
	{
		struct hkdf_ctx hkdf = {
			.hash = ctx->hash,
			.hash_len = ctx->tx.secret_len,
		};

		err = tquic_hkdf_expand_label(&hkdf, ctx->tx.secret,
					       tquic_key_label,
					       strlen(tquic_key_label),
					       NULL, 0,
					       ctx->tx.key, ctx->tx.key_len);
		if (err) {
			tquic_conn_err(conn,
				       "key update revert: TX key derive failed (err=%d)\n",
				       err);
			ctx->key_update_pending = 0;
			return;
		}

		err = tquic_hkdf_expand_label(&hkdf, ctx->tx.secret,
					       tquic_iv_label,
					       strlen(tquic_iv_label),
					       NULL, 0,
					       ctx->tx.iv, ctx->tx.iv_len);
		if (err) {
			tquic_conn_err(conn,
				       "key update revert: TX IV derive failed (err=%d)\n",
				       err);
			ctx->key_update_pending = 0;
			return;
		}
	}

	/* Install the restored key on the TX AEAD transform */
	err = crypto_aead_setkey(ctx->tx_aead, ctx->tx.key, ctx->tx.key_len);
	if (err) {
		tquic_conn_err(conn,
			       "key update revert: TX AEAD setkey failed (err=%d)\n",
			       err);
		/*
		 * The TX AEAD is now in an indeterminate state.
		 * The connection is likely unusable; fall through
		 * and clear the pending flag so cleanup can proceed.
		 */
	}

	/* Clear the pending flag so future key updates can proceed */
	ctx->key_update_pending = 0;

	/*
	 * Discard old (pre-update) read keys if they were saved --
	 * they are no longer meaningful since we reverted.
	 */
	if (ctx->rx_prev_valid) {
		if (ctx->rx_aead_prev) {
			crypto_free_aead(ctx->rx_aead_prev);
			ctx->rx_aead_prev = NULL;
		}
		ctx->rx_prev_valid = 0;
		memzero_explicit(&ctx->rx_prev, sizeof(ctx->rx_prev));
	}

	/* Cancel the key discard timer if it was armed */
	tquic_timer_cancel(conn, TQUIC_TIMER_KEY_DISCARD);

	tquic_conn_info(conn,
			"key update reverted, restored phase=%u\n",
			ctx->key_phase);
}
EXPORT_SYMBOL_GPL(tquic_crypto_revert_key_update);

/*
 * Compute nonce for AEAD encryption/decryption
 */
static void tquic_compute_nonce(const u8 *iv, u64 pn, u8 *nonce)
{
	int i;

	memcpy(nonce, iv, 12);

	/* XOR packet number into last 8 bytes of IV */
	for (i = 0; i < 8; i++)
		nonce[11 - i] ^= (pn >> (i * 8)) & 0xff;
}

/*
 * tquic_crypto_decrypt_with_phase - Decrypt packet considering key phase
 * @ctx: Crypto context
 * @skb: Socket buffer containing encrypted packet
 * @pn: Packet number for nonce construction
 * @key_phase: Key phase bit from packet header
 *
 * Attempts decryption with current or previous keys based on key phase.
 * Per RFC 9001 Section 6.3, endpoints should try decryption with both
 * current and previous keys when necessary to handle reordering.
 *
 * Returns 0 on success, -EKEYREJECTED if key update needed,
 * other negative error code on failure.
 */
int tquic_crypto_decrypt_with_phase(struct tquic_crypto_ctx *ctx,
				    struct sk_buff *skb, u64 pn, u8 key_phase)
{
	struct aead_request *req;
	struct scatterlist sg[2];
	u8 nonce[12];
	u8 *payload;
	u32 payload_len;
	u32 header_len;
	int err;

	if (!ctx->rx_aead || !ctx->keys_available)
		return -EINVAL;

	header_len = TQUIC_SKB_CB(skb)->header_len;
	payload = skb->data + header_len;
	payload_len = skb->len - header_len;

	if (payload_len < 16)
		return -EINVAL;

	/*
	 * If key phase matches expected, use current keys.
	 */
	if (key_phase == ctx->rx_key_phase) {
		/* Normal case: use current RX keys */
		tquic_compute_nonce(ctx->rx.iv, pn, nonce);

		req = aead_request_alloc(ctx->rx_aead, GFP_ATOMIC);
		if (!req)
			return -ENOMEM;

		sg_init_table(sg, 2);
		sg_set_buf(&sg[0], skb->data, header_len);
		sg_set_buf(&sg[1], payload, payload_len);

		aead_request_set_crypt(req, &sg[1], &sg[1], payload_len, nonce);
		aead_request_set_ad(req, header_len);

		err = crypto_aead_decrypt(req);
		aead_request_free(req);

		if (!err)
			skb_trim(skb, skb->len - 16);

		return err;
	}

	/*
	 * Key phase differs - try previous keys first for reordered packets
	 */
	if (ctx->rx_prev_valid && ctx->rx_aead_prev) {
		tquic_compute_nonce(ctx->rx_prev.iv, pn, nonce);

		req = aead_request_alloc(ctx->rx_aead_prev, GFP_ATOMIC);
		if (!req)
			return -ENOMEM;

		sg_init_table(sg, 2);
		sg_set_buf(&sg[0], skb->data, header_len);
		sg_set_buf(&sg[1], payload, payload_len);

		aead_request_set_crypt(req, &sg[1], &sg[1], payload_len, nonce);
		aead_request_set_ad(req, header_len);

		err = crypto_aead_decrypt(req);
		aead_request_free(req);

		if (!err) {
			skb_trim(skb, skb->len - 16);
			return 0;
		}
	}

	/*
	 * Decryption with previous keys failed or not available.
	 * This indicates a genuine key update from peer.
	 */
	return -EKEYREJECTED;
}
EXPORT_SYMBOL_GPL(tquic_crypto_decrypt_with_phase);

/*
 * tquic_crypto_get_key_phase - Get current TX key phase
 * @ctx: Crypto context
 *
 * Returns current key phase bit (0 or 1) for packet construction.
 */
u8 tquic_crypto_get_key_phase(struct tquic_crypto_ctx *ctx)
{
	return ctx->key_phase;
}
EXPORT_SYMBOL_GPL(tquic_crypto_get_key_phase);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("TQUIC Key Update Mechanism");
MODULE_AUTHOR("Linux QUIC Authors");
