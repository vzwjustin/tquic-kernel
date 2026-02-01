// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * QUIC - Quick UDP Internet Connections
 *
 * Cryptographic operations for TLS 1.3 integration
 *
 * Copyright (c) 2024 Linux QUIC Authors
 */

#include <linux/slab.h>
#include <crypto/aead.h>
#include <crypto/hash.h>
#include <crypto/skcipher.h>
#include <crypto/gcm.h>
#include <net/quic.h>

/* QUIC v1 initial salt (RFC 9001 Section 5.2) */
static const u8 quic_v1_initial_salt[20] = {
	0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3,
	0x4d, 0x17, 0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad,
	0xcc, 0xbb, 0x7f, 0x0a
};

/* QUIC v2 initial salt (RFC 9369) */
static const u8 quic_v2_initial_salt[20] = {
	0x0d, 0xed, 0xe3, 0xde, 0xf7, 0x00, 0xa6, 0xdb,
	0x81, 0x93, 0x81, 0xbe, 0x6e, 0x26, 0x9d, 0xcb,
	0xf9, 0xbd, 0x2e, 0xd9
};

/* HKDF labels for QUIC */
static const char quic_client_in_label[] = "client in";
static const char quic_server_in_label[] = "server in";
static const char quic_key_label[] = "quic key";
static const char quic_iv_label[] = "quic iv";
static const char quic_hp_label[] = "quic hp";
static const char quic_ku_label[] = "quic ku";

struct hkdf_ctx {
	struct crypto_shash *hash;
	u32 hash_len;
};

static int hkdf_extract(struct hkdf_ctx *ctx, const u8 *salt, size_t salt_len,
			const u8 *ikm, size_t ikm_len, u8 *prk)
{
	SHASH_DESC_ON_STACK(desc, ctx->hash);
	int err;

	err = crypto_shash_setkey(ctx->hash, salt, salt_len);
	if (err)
		return err;

	desc->tfm = ctx->hash;
	return crypto_shash_digest(desc, ikm, ikm_len, prk);
}

static int hkdf_expand_label(struct hkdf_ctx *ctx, const u8 *prk,
			     const char *label, size_t label_len,
			     const u8 *context, size_t context_len,
			     u8 *out, size_t out_len)
{
	SHASH_DESC_ON_STACK(desc, ctx->hash);
	u8 info[256];
	u8 t[64];
	size_t info_len;
	size_t done = 0;
	u8 iter = 1;
	int err;

	/* Build HKDF-Expand-Label info
	 * struct {
	 *   uint16 length = Length;
	 *   opaque label<7..255> = "tls13 " + Label;
	 *   opaque context<0..255> = Context;
	 * } HkdfLabel;
	 */
	info[0] = (out_len >> 8) & 0xff;
	info[1] = out_len & 0xff;
	info[2] = 6 + label_len;  /* "tls13 " + label */
	memcpy(&info[3], "tls13 ", 6);
	memcpy(&info[9], label, label_len);
	info[9 + label_len] = context_len;
	if (context_len > 0)
		memcpy(&info[10 + label_len], context, context_len);
	info_len = 10 + label_len + context_len;

	err = crypto_shash_setkey(ctx->hash, prk, ctx->hash_len);
	if (err)
		return err;

	desc->tfm = ctx->hash;

	/* T(0) = empty string */
	memset(t, 0, sizeof(t));

	while (done < out_len) {
		u8 input[256 + 64 + 1];
		size_t input_len = 0;
		size_t copy_len;

		if (iter > 1) {
			memcpy(input, t, ctx->hash_len);
			input_len = ctx->hash_len;
		}

		memcpy(input + input_len, info, info_len);
		input_len += info_len;
		input[input_len++] = iter;

		err = crypto_shash_digest(desc, input, input_len, t);
		if (err)
			return err;

		copy_len = min(out_len - done, (size_t)ctx->hash_len);
		memcpy(out + done, t, copy_len);
		done += copy_len;
		iter++;
	}

	return 0;
}

int quic_crypto_init(struct quic_crypto_ctx *ctx, u16 cipher_type)
{
	const char *aead_name;
	const char *cipher_name;
	const char *hash_name;
	int key_len;

	switch (cipher_type) {
	case QUIC_CIPHER_AES_128_GCM_SHA256:
		aead_name = "gcm(aes)";
		cipher_name = "ecb(aes)";
		hash_name = "hmac(sha256)";
		key_len = 16;
		break;
	case QUIC_CIPHER_AES_256_GCM_SHA384:
		aead_name = "gcm(aes)";
		cipher_name = "ecb(aes)";
		hash_name = "hmac(sha384)";
		key_len = 32;
		break;
	case QUIC_CIPHER_CHACHA20_POLY1305_SHA256:
		aead_name = "rfc7539(chacha20,poly1305)";
		cipher_name = "chacha20";
		hash_name = "hmac(sha256)";
		key_len = 32;
		break;
	default:
		return -EINVAL;
	}

	ctx->cipher_type = cipher_type;

	/* Allocate TX AEAD */
	ctx->tx_aead = crypto_alloc_aead(aead_name, 0, 0);
	if (IS_ERR(ctx->tx_aead)) {
		int err = PTR_ERR(ctx->tx_aead);
		ctx->tx_aead = NULL;
		return err;
	}

	/* Allocate RX AEAD */
	ctx->rx_aead = crypto_alloc_aead(aead_name, 0, 0);
	if (IS_ERR(ctx->rx_aead)) {
		int err = PTR_ERR(ctx->rx_aead);
		crypto_free_aead(ctx->tx_aead);
		ctx->tx_aead = NULL;
		ctx->rx_aead = NULL;
		return err;
	}

	/* Allocate TX header protection cipher */
	ctx->tx_hp = crypto_alloc_cipher(cipher_name, 0, 0);
	if (IS_ERR(ctx->tx_hp)) {
		int err = PTR_ERR(ctx->tx_hp);
		crypto_free_aead(ctx->rx_aead);
		crypto_free_aead(ctx->tx_aead);
		ctx->tx_aead = NULL;
		ctx->rx_aead = NULL;
		ctx->tx_hp = NULL;
		return err;
	}

	/* Allocate RX header protection cipher */
	ctx->rx_hp = crypto_alloc_cipher(cipher_name, 0, 0);
	if (IS_ERR(ctx->rx_hp)) {
		int err = PTR_ERR(ctx->rx_hp);
		crypto_free_cipher(ctx->tx_hp);
		crypto_free_aead(ctx->rx_aead);
		crypto_free_aead(ctx->tx_aead);
		ctx->tx_aead = NULL;
		ctx->rx_aead = NULL;
		ctx->tx_hp = NULL;
		ctx->rx_hp = NULL;
		return err;
	}

	/* Allocate hash for key derivation */
	ctx->hash = crypto_alloc_shash(hash_name, 0, 0);
	if (IS_ERR(ctx->hash)) {
		int err = PTR_ERR(ctx->hash);
		crypto_free_cipher(ctx->rx_hp);
		crypto_free_cipher(ctx->tx_hp);
		crypto_free_aead(ctx->rx_aead);
		crypto_free_aead(ctx->tx_aead);
		ctx->tx_aead = NULL;
		ctx->rx_aead = NULL;
		ctx->tx_hp = NULL;
		ctx->rx_hp = NULL;
		ctx->hash = NULL;
		return err;
	}

	ctx->tx.key_len = key_len;
	ctx->rx.key_len = key_len;
	ctx->tx.iv_len = 12;
	ctx->rx.iv_len = 12;
	ctx->tx.hp_key_len = key_len;
	ctx->rx.hp_key_len = key_len;

	return 0;
}

void quic_crypto_destroy(struct quic_crypto_ctx *ctx)
{
	if (ctx->hash)
		crypto_free_shash(ctx->hash);
	if (ctx->rx_hp)
		crypto_free_cipher(ctx->rx_hp);
	if (ctx->tx_hp)
		crypto_free_cipher(ctx->tx_hp);
	if (ctx->rx_aead)
		crypto_free_aead(ctx->rx_aead);
	if (ctx->tx_aead)
		crypto_free_aead(ctx->tx_aead);

	memset(ctx, 0, sizeof(*ctx));
}

int quic_crypto_derive_initial_secrets(struct quic_connection *conn,
				       struct quic_connection_id *cid)
{
	struct quic_crypto_ctx *ctx = &conn->crypto[QUIC_CRYPTO_INITIAL];
	struct hkdf_ctx hkdf;
	const u8 *salt;
	u8 initial_secret[32];
	u8 client_secret[32];
	u8 server_secret[32];
	int err;

	/* Initialize with AES-128-GCM-SHA256 for initial packets */
	err = quic_crypto_init(ctx, QUIC_CIPHER_AES_128_GCM_SHA256);
	if (err)
		return err;

	hkdf.hash = ctx->hash;
	hkdf.hash_len = 32;  /* SHA-256 */

	/* Select salt based on version */
	if (conn->version == QUIC_VERSION_2)
		salt = quic_v2_initial_salt;
	else
		salt = quic_v1_initial_salt;

	/* Extract initial secret */
	err = hkdf_extract(&hkdf, salt, 20, cid->data, cid->len, initial_secret);
	if (err)
		goto out;

	/* Derive client and server secrets */
	err = hkdf_expand_label(&hkdf, initial_secret, quic_client_in_label,
				strlen(quic_client_in_label), NULL, 0,
				client_secret, 32);
	if (err)
		goto out;

	err = hkdf_expand_label(&hkdf, initial_secret, quic_server_in_label,
				strlen(quic_server_in_label), NULL, 0,
				server_secret, 32);
	if (err)
		goto out;

	/* Derive keys and IVs */
	if (conn->is_server) {
		/* Server: RX uses client secret, TX uses server secret */
		err = quic_crypto_derive_secrets(ctx, client_secret, 32);
		if (err)
			goto out;
		memcpy(ctx->rx.secret, client_secret, 32);
		memcpy(ctx->tx.secret, server_secret, 32);
	} else {
		/* Client: TX uses client secret, RX uses server secret */
		err = quic_crypto_derive_secrets(ctx, client_secret, 32);
		if (err)
			goto out;
		memcpy(ctx->tx.secret, client_secret, 32);
		memcpy(ctx->rx.secret, server_secret, 32);
	}

	/* Derive TX keys */
	err = hkdf_expand_label(&hkdf, ctx->tx.secret, quic_key_label,
				strlen(quic_key_label), NULL, 0,
				ctx->tx.key, ctx->tx.key_len);
	if (err)
		goto out;

	err = hkdf_expand_label(&hkdf, ctx->tx.secret, quic_iv_label,
				strlen(quic_iv_label), NULL, 0,
				ctx->tx.iv, ctx->tx.iv_len);
	if (err)
		goto out;

	err = hkdf_expand_label(&hkdf, ctx->tx.secret, quic_hp_label,
				strlen(quic_hp_label), NULL, 0,
				ctx->tx.hp_key, ctx->tx.hp_key_len);
	if (err)
		goto out;

	/* Derive RX keys */
	err = hkdf_expand_label(&hkdf, ctx->rx.secret, quic_key_label,
				strlen(quic_key_label), NULL, 0,
				ctx->rx.key, ctx->rx.key_len);
	if (err)
		goto out;

	err = hkdf_expand_label(&hkdf, ctx->rx.secret, quic_iv_label,
				strlen(quic_iv_label), NULL, 0,
				ctx->rx.iv, ctx->rx.iv_len);
	if (err)
		goto out;

	err = hkdf_expand_label(&hkdf, ctx->rx.secret, quic_hp_label,
				strlen(quic_hp_label), NULL, 0,
				ctx->rx.hp_key, ctx->rx.hp_key_len);
	if (err)
		goto out;

	/* Set keys on crypto transforms */
	err = crypto_aead_setkey(ctx->tx_aead, ctx->tx.key, ctx->tx.key_len);
	if (err)
		goto out;

	err = crypto_aead_setkey(ctx->rx_aead, ctx->rx.key, ctx->rx.key_len);
	if (err)
		goto out;

	err = crypto_cipher_setkey(ctx->tx_hp, ctx->tx.hp_key, ctx->tx.hp_key_len);
	if (err)
		goto out;

	err = crypto_cipher_setkey(ctx->rx_hp, ctx->rx.hp_key, ctx->rx.hp_key_len);
	if (err)
		goto out;

	err = crypto_aead_setauthsize(ctx->tx_aead, 16);
	if (err)
		goto out;

	err = crypto_aead_setauthsize(ctx->rx_aead, 16);
	if (err)
		goto out;

	ctx->keys_available = 1;
	ctx->tx.secret_len = 32;
	ctx->rx.secret_len = 32;

out:
	memzero_explicit(initial_secret, sizeof(initial_secret));
	memzero_explicit(client_secret, sizeof(client_secret));
	memzero_explicit(server_secret, sizeof(server_secret));
	return err;
}

int quic_crypto_derive_secrets(struct quic_crypto_ctx *ctx,
			       const u8 *secret, u32 secret_len)
{
	struct hkdf_ctx hkdf;
	int err;

	if (!ctx->hash)
		return -EINVAL;

	hkdf.hash = ctx->hash;
	hkdf.hash_len = secret_len;

	/* Derive key */
	err = hkdf_expand_label(&hkdf, secret, quic_key_label,
				strlen(quic_key_label), NULL, 0,
				ctx->tx.key, ctx->tx.key_len);
	if (err)
		return err;

	/* Derive IV */
	err = hkdf_expand_label(&hkdf, secret, quic_iv_label,
				strlen(quic_iv_label), NULL, 0,
				ctx->tx.iv, ctx->tx.iv_len);
	if (err)
		return err;

	/* Derive HP key */
	err = hkdf_expand_label(&hkdf, secret, quic_hp_label,
				strlen(quic_hp_label), NULL, 0,
				ctx->tx.hp_key, ctx->tx.hp_key_len);
	if (err)
		return err;

	return 0;
}

static void quic_crypto_compute_nonce(const u8 *iv, u64 pn, u8 *nonce)
{
	int i;

	memcpy(nonce, iv, 12);

	/* XOR packet number into last 8 bytes of IV */
	for (i = 0; i < 8; i++)
		nonce[11 - i] ^= (pn >> (i * 8)) & 0xff;
}

int quic_crypto_encrypt(struct quic_crypto_ctx *ctx, struct sk_buff *skb,
			u64 pn)
{
	struct aead_request *req;
	struct scatterlist sg[2];
	u8 nonce[12];
	u8 *payload;
	u32 payload_len;
	u32 header_len;
	int err;

	if (!ctx->tx_aead || !ctx->keys_available)
		return -EINVAL;

	header_len = QUIC_SKB_CB(skb)->header_len;
	payload = skb->data + header_len;
	payload_len = skb->len - header_len;

	quic_crypto_compute_nonce(ctx->tx.iv, pn, nonce);

	req = aead_request_alloc(ctx->tx_aead, GFP_ATOMIC);
	if (!req)
		return -ENOMEM;

	/* Expand skb for authentication tag */
	if (skb_tailroom(skb) < 16) {
		err = pskb_expand_head(skb, 0, 16 - skb_tailroom(skb), GFP_ATOMIC);
		if (err) {
			aead_request_free(req);
			return err;
		}
	}

	sg_init_table(sg, 2);
	sg_set_buf(&sg[0], skb->data, header_len);  /* AAD */
	sg_set_buf(&sg[1], payload, payload_len + 16);  /* Payload + tag space */

	aead_request_set_crypt(req, &sg[1], &sg[1], payload_len, nonce);
	aead_request_set_ad(req, header_len);

	err = crypto_aead_encrypt(req);

	aead_request_free(req);

	if (!err)
		skb_put(skb, 16);  /* Add auth tag to length */

	return err;
}

int quic_crypto_decrypt(struct quic_crypto_ctx *ctx, struct sk_buff *skb,
			u64 pn)
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
		return -EINVAL;  /* Too short for auth tag */

	quic_crypto_compute_nonce(ctx->rx.iv, pn, nonce);

	req = aead_request_alloc(ctx->rx_aead, GFP_ATOMIC);
	if (!req)
		return -ENOMEM;

	sg_init_table(sg, 2);
	sg_set_buf(&sg[0], skb->data, header_len);  /* AAD */
	sg_set_buf(&sg[1], payload, payload_len);  /* Payload + tag */

	aead_request_set_crypt(req, &sg[1], &sg[1], payload_len, nonce);
	aead_request_set_ad(req, header_len);

	err = crypto_aead_decrypt(req);

	aead_request_free(req);

	if (!err)
		skb_trim(skb, skb->len - 16);  /* Remove auth tag from length */

	return err;
}

int quic_crypto_hp_mask(struct quic_crypto_ctx *ctx, const u8 *sample,
			u8 *mask)
{
	int err;

	if (!ctx->rx_hp)
		return -EINVAL;

	/* For AES, we encrypt a block of zeros with the sample as part of the input */
	if (ctx->cipher_type == QUIC_CIPHER_AES_128_GCM_SHA256 ||
	    ctx->cipher_type == QUIC_CIPHER_AES_256_GCM_SHA384) {
		crypto_cipher_encrypt_one(ctx->rx_hp, mask, sample);
	} else {
		/* ChaCha20: counter=sample[0..3], nonce=sample[4..15] */
		/* Encrypt zeros to get mask - simplified */
		memset(mask, 0, 5);
		crypto_cipher_encrypt_one(ctx->rx_hp, mask, sample);
	}

	return err;
}

int quic_crypto_update_keys(struct quic_connection *conn)
{
	struct quic_crypto_ctx *ctx = &conn->crypto[QUIC_CRYPTO_APPLICATION];
	struct hkdf_ctx hkdf;
	u8 new_secret[64];
	int err;

	if (!ctx->hash || !ctx->keys_available)
		return -EINVAL;

	hkdf.hash = ctx->hash;
	hkdf.hash_len = ctx->tx.secret_len;

	/* Derive new secret from current secret */
	err = hkdf_expand_label(&hkdf, ctx->tx.secret, quic_ku_label,
				strlen(quic_ku_label), NULL, 0,
				new_secret, ctx->tx.secret_len);
	if (err)
		return err;

	/* Derive new keys from new secret */
	memcpy(ctx->tx.secret, new_secret, ctx->tx.secret_len);

	err = hkdf_expand_label(&hkdf, ctx->tx.secret, quic_key_label,
				strlen(quic_key_label), NULL, 0,
				ctx->tx.key, ctx->tx.key_len);
	if (err)
		goto out;

	err = hkdf_expand_label(&hkdf, ctx->tx.secret, quic_iv_label,
				strlen(quic_iv_label), NULL, 0,
				ctx->tx.iv, ctx->tx.iv_len);
	if (err)
		goto out;

	/* Update AEAD key */
	err = crypto_aead_setkey(ctx->tx_aead, ctx->tx.key, ctx->tx.key_len);
	if (err)
		goto out;

	/* Toggle key phase */
	ctx->key_phase = !ctx->key_phase;
	conn->key_phase = ctx->key_phase;

out:
	memzero_explicit(new_secret, sizeof(new_secret));
	return err;
}

/* Helper to apply header protection */
int quic_crypto_protect_header(struct quic_crypto_ctx *ctx, struct sk_buff *skb,
			       u8 pn_offset, u8 pn_len)
{
	u8 mask[16];
	u8 *sample;
	u8 *header;
	int i;

	if (skb->len < pn_offset + 4 + 16)
		return -EINVAL;

	/* Sample starts 4 bytes after packet number */
	sample = skb->data + pn_offset + 4;

	/* Generate mask using TX HP key */
	if (ctx->cipher_type == QUIC_CIPHER_AES_128_GCM_SHA256 ||
	    ctx->cipher_type == QUIC_CIPHER_AES_256_GCM_SHA384) {
		crypto_cipher_encrypt_one(ctx->tx_hp, mask, sample);
	} else {
		memset(mask, 0, 16);
		crypto_cipher_encrypt_one(ctx->tx_hp, mask, sample);
	}

	header = skb->data;

	/* Apply mask to first byte */
	if (header[0] & 0x80) {
		/* Long header */
		header[0] ^= mask[0] & 0x0f;
	} else {
		/* Short header */
		header[0] ^= mask[0] & 0x1f;
	}

	/* Apply mask to packet number */
	for (i = 0; i < pn_len; i++)
		skb->data[pn_offset + i] ^= mask[1 + i];

	return 0;
}

/* Helper to remove header protection */
int quic_crypto_unprotect_header(struct quic_crypto_ctx *ctx, struct sk_buff *skb,
				 u8 *pn_offset, u8 *pn_len)
{
	u8 mask[16];
	u8 *sample;
	u8 *header;
	int sample_offset;
	int i;

	header = skb->data;

	/* Determine packet number offset based on header type */
	if (header[0] & 0x80) {
		/* Long header - need to parse DCID/SCID lengths */
		u8 dcid_len = header[5];
		u8 scid_len;

		if (skb->len < 7 + dcid_len)
			return -EINVAL;

		scid_len = header[6 + dcid_len];

		if (skb->len < 7 + dcid_len + 1 + scid_len + 4 + 16)
			return -EINVAL;

		*pn_offset = 7 + dcid_len + 1 + scid_len;

		/* For Initial packets, also need to skip token length and token */
		/* Simplified: assume handshake packet without token */
	} else {
		/* Short header - DCID starts at byte 1 */
		*pn_offset = 1 + 8;  /* Assume 8-byte connection ID */
	}

	sample_offset = *pn_offset + 4;
	if (skb->len < sample_offset + 16)
		return -EINVAL;

	sample = skb->data + sample_offset;

	/* Generate mask using RX HP key */
	if (ctx->cipher_type == QUIC_CIPHER_AES_128_GCM_SHA256 ||
	    ctx->cipher_type == QUIC_CIPHER_AES_256_GCM_SHA384) {
		crypto_cipher_encrypt_one(ctx->rx_hp, mask, sample);
	} else {
		memset(mask, 0, 16);
		crypto_cipher_encrypt_one(ctx->rx_hp, mask, sample);
	}

	/* Remove mask from first byte */
	if (header[0] & 0x80) {
		header[0] ^= mask[0] & 0x0f;
		*pn_len = (header[0] & 0x03) + 1;
	} else {
		header[0] ^= mask[0] & 0x1f;
		*pn_len = (header[0] & 0x03) + 1;
	}

	/* Remove mask from packet number */
	for (i = 0; i < *pn_len; i++)
		skb->data[*pn_offset + i] ^= mask[1 + i];

	return 0;
}
