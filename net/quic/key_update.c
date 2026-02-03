// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * QUIC Key Update Mechanism (RFC 9001 Section 6)
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
 * Copyright (c) 2024 Linux QUIC Authors
 */

#include <linux/slab.h>
#include <linux/errno.h>
#include <crypto/aead.h>
#include <crypto/hash.h>
#include <net/quic.h>
#include "key_update.h"

/*
 * Key discard timeout per RFC 9001 Section 6.1:
 * "Keys SHOULD be retained for three times the current Probe Timeout (PTO)"
 * Default to 3 * 333ms = ~1 second as a safe minimum.
 */
#define QUIC_KEY_DISCARD_TIMEOUT_MS	1000

/* HKDF labels */
static const char quic_ku_label[] = "quic ku";
static const char quic_key_label[] = "quic key";
static const char quic_iv_label[] = "quic iv";

/* Forward declarations */
struct hkdf_ctx {
	struct crypto_shash *hash;
	u32 hash_len;
};

extern int hkdf_expand_label(struct hkdf_ctx *ctx, const u8 *prk,
			     const char *label, size_t label_len,
			     const u8 *context, size_t context_len,
			     u8 *out, size_t out_len);

/*
 * quic_key_update_tx - Update transmit keys for key update
 * @conn: QUIC connection
 *
 * Derives new TX secret and keys using HKDF-Expand-Label with "quic ku" label.
 * Per RFC 9001 Section 6.1:
 *   secret_<n+1> = HKDF-Expand-Label(secret_<n>, "quic ku", "", Hash.length)
 *
 * Returns 0 on success, negative error code on failure.
 */
static int quic_key_update_tx(struct quic_connection *conn)
{
	struct quic_crypto_ctx *ctx = &conn->crypto[QUIC_CRYPTO_APPLICATION];
	struct hkdf_ctx hkdf;
	u8 new_secret[64];
	int err;

	if (!ctx->hash || !ctx->keys_available)
		return -EINVAL;

	hkdf.hash = ctx->hash;
	hkdf.hash_len = ctx->tx.secret_len;

	/* Derive new secret from current TX secret */
	err = hkdf_expand_label(&hkdf, ctx->tx.secret, quic_ku_label,
				strlen(quic_ku_label), NULL, 0,
				new_secret, ctx->tx.secret_len);
	if (err)
		return err;

	/* Update TX secret */
	memcpy(ctx->tx.secret, new_secret, ctx->tx.secret_len);

	/* Derive new TX key */
	err = hkdf_expand_label(&hkdf, ctx->tx.secret, quic_key_label,
				strlen(quic_key_label), NULL, 0,
				ctx->tx.key, ctx->tx.key_len);
	if (err)
		goto out;

	/* Derive new TX IV */
	err = hkdf_expand_label(&hkdf, ctx->tx.secret, quic_iv_label,
				strlen(quic_iv_label), NULL, 0,
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
 * quic_key_update_rx - Update receive keys for key update
 * @conn: QUIC connection
 *
 * Saves current RX keys as previous (for reordered packets), then derives
 * new RX secret and keys. Per RFC 9001 Section 6.1, old keys must be
 * retained briefly to handle reordered packets.
 *
 * Returns 0 on success, negative error code on failure.
 */
static int quic_key_update_rx(struct quic_connection *conn)
{
	struct quic_crypto_ctx *ctx = &conn->crypto[QUIC_CRYPTO_APPLICATION];
	struct hkdf_ctx hkdf;
	u8 new_secret[64];
	const char *aead_name;
	int err;

	if (!ctx->hash || !ctx->keys_available)
		return -EINVAL;

	hkdf.hash = ctx->hash;
	hkdf.hash_len = ctx->rx.secret_len;

	/* Determine AEAD algorithm name */
	switch (ctx->cipher_type) {
	case QUIC_CIPHER_AES_128_GCM_SHA256:
	case QUIC_CIPHER_AES_256_GCM_SHA384:
		aead_name = "gcm(aes)";
		break;
	case QUIC_CIPHER_CHACHA20_POLY1305_SHA256:
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
		pr_debug("QUIC: could not allocate previous RX AEAD\n");
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
	err = hkdf_expand_label(&hkdf, ctx->rx.secret, quic_ku_label,
				strlen(quic_ku_label), NULL, 0,
				new_secret, ctx->rx.secret_len);
	if (err)
		return err;

	/* Update RX secret */
	memcpy(ctx->rx.secret, new_secret, ctx->rx.secret_len);

	/* Derive new RX key */
	err = hkdf_expand_label(&hkdf, ctx->rx.secret, quic_key_label,
				strlen(quic_key_label), NULL, 0,
				ctx->rx.key, ctx->rx.key_len);
	if (err)
		goto out;

	/* Derive new RX IV */
	err = hkdf_expand_label(&hkdf, ctx->rx.secret, quic_iv_label,
				strlen(quic_iv_label), NULL, 0,
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
 * quic_crypto_initiate_key_update - Initiate a key update (RFC 9001 Section 6.1)
 * @conn: QUIC connection
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
int quic_crypto_initiate_key_update(struct quic_connection *conn)
{
	struct quic_crypto_ctx *ctx = &conn->crypto[QUIC_CRYPTO_APPLICATION];
	struct quic_pn_space *pn_space = &conn->pn_spaces[QUIC_PN_SPACE_APPLICATION];
	int err;

	if (!ctx->keys_available)
		return -EINVAL;

	/* Check if we're already in a key update (RFC 9001 Section 6.2) */
	if (ctx->key_update_pending)
		return -EAGAIN;

	/* Update TX keys */
	err = quic_key_update_tx(conn);
	if (err)
		return err;

	/* Toggle TX key phase */
	ctx->key_phase = !ctx->key_phase;
	conn->key_phase = ctx->key_phase;

	/* Mark key update as pending and record first PN with new keys */
	ctx->key_update_pending = 1;
	ctx->key_update_pn = pn_space->next_pn;

	pr_debug("QUIC: initiated key update, new phase=%u, first_pn=%llu\n",
		 ctx->key_phase, ctx->key_update_pn);

	return 0;
}
EXPORT_SYMBOL_GPL(quic_crypto_initiate_key_update);

/*
 * quic_crypto_on_key_phase_change - Handle received packet with different key phase
 * @conn: QUIC connection
 * @rx_key_phase: Key phase bit from received packet
 *
 * Called when a packet is received with a key phase different from expected.
 * Per RFC 9001 Section 6.2:
 * - If we initiated the update, this confirms the peer received our update
 * - If the peer initiated, we need to update our RX keys and respond
 *
 * Returns 0 on success, negative error code on failure.
 */
int quic_crypto_on_key_phase_change(struct quic_connection *conn, u8 rx_key_phase)
{
	struct quic_crypto_ctx *ctx = &conn->crypto[QUIC_CRYPTO_APPLICATION];
	ktime_t discard_time;
	int err;

	if (!ctx->keys_available)
		return -EINVAL;

	/*
	 * Case 1: We initiated the key update and peer has responded with
	 * a packet using the new key phase. Our pending state is confirmed.
	 */
	if (ctx->key_update_pending && rx_key_phase == ctx->key_phase) {
		/* Update RX keys to match the new phase */
		err = quic_key_update_rx(conn);
		if (err)
			return err;

		ctx->rx_key_phase = rx_key_phase;
		ctx->key_update_pending = 0;

		/* Start timer to discard old RX keys */
		discard_time = ktime_add_ms(ktime_get(), QUIC_KEY_DISCARD_TIMEOUT_MS);
		quic_timer_set(conn, QUIC_TIMER_KEY_DISCARD, discard_time);

		pr_debug("QUIC: key update confirmed by peer, phase=%u\n",
			 rx_key_phase);
		return 0;
	}

	/*
	 * Case 2: Peer initiated a key update. We need to:
	 * 1. Update our RX keys to decrypt the new packet
	 * 2. Update our TX keys to respond with the new phase
	 */
	if (rx_key_phase != ctx->rx_key_phase) {
		/* Update RX keys first */
		err = quic_key_update_rx(conn);
		if (err)
			return err;

		ctx->rx_key_phase = rx_key_phase;

		/* Now update TX keys to match */
		err = quic_key_update_tx(conn);
		if (err) {
			/* RX update succeeded but TX failed - problematic state */
			pr_warn("QUIC: TX key update failed after RX update\n");
			return err;
		}

		ctx->key_phase = rx_key_phase;
		conn->key_phase = ctx->key_phase;

		/* Start timer to discard old RX keys */
		discard_time = ktime_add_ms(ktime_get(), QUIC_KEY_DISCARD_TIMEOUT_MS);
		quic_timer_set(conn, QUIC_TIMER_KEY_DISCARD, discard_time);

		pr_debug("QUIC: responded to peer key update, new phase=%u\n",
			 rx_key_phase);
		return 0;
	}

	/* Key phase matches expected - no action needed */
	return 0;
}
EXPORT_SYMBOL_GPL(quic_crypto_on_key_phase_change);

/*
 * quic_crypto_discard_old_keys - Discard previous generation keys
 * @conn: QUIC connection
 *
 * Called by key discard timer to free old keys. Per RFC 9001 Section 6.1,
 * keys SHOULD be discarded when it's unlikely that any packet protected
 * with the old keys will be received.
 */
void quic_crypto_discard_old_keys(struct quic_connection *conn)
{
	struct quic_crypto_ctx *ctx = &conn->crypto[QUIC_CRYPTO_APPLICATION];

	if (ctx->rx_aead_prev) {
		crypto_free_aead(ctx->rx_aead_prev);
		ctx->rx_aead_prev = NULL;
	}

	ctx->rx_prev_valid = 0;
	memzero_explicit(&ctx->rx_prev, sizeof(ctx->rx_prev));

	pr_debug("QUIC: discarded old keys\n");
}
EXPORT_SYMBOL_GPL(quic_crypto_discard_old_keys);

/*
 * Compute nonce for AEAD encryption/decryption
 */
static void quic_compute_nonce(const u8 *iv, u64 pn, u8 *nonce)
{
	int i;

	memcpy(nonce, iv, 12);

	/* XOR packet number into last 8 bytes of IV */
	for (i = 0; i < 8; i++)
		nonce[11 - i] ^= (pn >> (i * 8)) & 0xff;
}

/*
 * quic_crypto_decrypt_with_phase - Decrypt packet considering key phase
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
int quic_crypto_decrypt_with_phase(struct quic_crypto_ctx *ctx,
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

	header_len = QUIC_SKB_CB(skb)->header_len;
	payload = skb->data + header_len;
	payload_len = skb->len - header_len;

	if (payload_len < 16)
		return -EINVAL;

	/*
	 * If key phase matches expected, use current keys.
	 */
	if (key_phase == ctx->rx_key_phase) {
		/* Normal case: use current RX keys */
		quic_compute_nonce(ctx->rx.iv, pn, nonce);

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
		quic_compute_nonce(ctx->rx_prev.iv, pn, nonce);

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
EXPORT_SYMBOL_GPL(quic_crypto_decrypt_with_phase);

/*
 * quic_crypto_get_key_phase - Get current TX key phase
 * @ctx: Crypto context
 *
 * Returns current key phase bit (0 or 1) for packet construction.
 */
u8 quic_crypto_get_key_phase(struct quic_crypto_ctx *ctx)
{
	return ctx->key_phase;
}
EXPORT_SYMBOL_GPL(quic_crypto_get_key_phase);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("QUIC Key Update Mechanism");
MODULE_AUTHOR("Linux QUIC Authors");
