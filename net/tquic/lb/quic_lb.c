// SPDX-License-Identifier: GPL-2.0-only
/*
 * TQUIC: QUIC Load Balancing Support
 *
 * Copyright (c) 2026 Linux Foundation
 *
 * Implementation of QUIC-LB (draft-ietf-quic-load-balancers) for
 * server ID encoding in connection IDs to enable stateless load balancing.
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/random.h>
#include <crypto/aes.h>
#include <crypto/skcipher.h>
#include <asm/unaligned.h>

#include "quic_lb.h"

/* Memory cache for configs */
static struct kmem_cache *lb_config_cache;

/**
 * tquic_lb_config_create - Create a QUIC-LB configuration
 * @config_rotation: Configuration rotation codepoint (0-6)
 * @server_id: Server identifier
 * @server_id_len: Length of server ID (1-15)
 * @nonce_len: Length of nonce (4-18)
 * @encryption_key: AES-128 key (NULL for plaintext mode)
 *
 * Returns allocated config or NULL on failure.
 */
struct tquic_lb_config *tquic_lb_config_create(u8 config_rotation,
					       const u8 *server_id,
					       u8 server_id_len,
					       u8 nonce_len,
					       const u8 *encryption_key)
{
	struct tquic_lb_config *cfg;

	/* Validate parameters */
	if (config_rotation > TQUIC_LB_CONFIG_ROTATION_MAX)
		return NULL;
	if (server_id_len < TQUIC_LB_SERVER_ID_MIN_LEN ||
	    server_id_len > TQUIC_LB_SERVER_ID_MAX_LEN)
		return NULL;
	if (nonce_len < TQUIC_LB_NONCE_MIN_LEN ||
	    nonce_len > TQUIC_LB_NONCE_MAX_LEN)
		return NULL;
	if (server_id_len + nonce_len > TQUIC_LB_CID_PAYLOAD_MAX)
		return NULL;

	cfg = kmem_cache_zalloc(lb_config_cache, GFP_KERNEL);
	if (!cfg)
		return NULL;

	cfg->config_rotation = config_rotation;
	cfg->server_id_len = server_id_len;
	cfg->nonce_len = nonce_len;
	memcpy(cfg->server_id, server_id, server_id_len);
	spin_lock_init(&cfg->lock);

	if (encryption_key) {
		memcpy(cfg->encryption_key, encryption_key,
		       TQUIC_LB_AES_BLOCK_SIZE);

		/* Allocate AES cipher */
		cfg->aes_tfm = crypto_alloc_cipher("aes", 0, 0);
		if (IS_ERR(cfg->aes_tfm)) {
			kmem_cache_free(lb_config_cache, cfg);
			return NULL;
		}

		if (crypto_cipher_setkey(cfg->aes_tfm, encryption_key,
					 TQUIC_LB_AES_BLOCK_SIZE)) {
			crypto_free_cipher(cfg->aes_tfm);
			kmem_cache_free(lb_config_cache, cfg);
			return NULL;
		}

		/* Determine encryption mode */
		if (server_id_len + nonce_len == TQUIC_LB_AES_BLOCK_SIZE)
			cfg->mode = TQUIC_LB_MODE_SINGLE_PASS;
		else
			cfg->mode = TQUIC_LB_MODE_FOUR_PASS;
	} else {
		cfg->mode = TQUIC_LB_MODE_PLAINTEXT;
		cfg->aes_tfm = NULL;
	}

	/* Initialize nonce counter with random value */
	get_random_bytes(&cfg->nonce_counter, sizeof(cfg->nonce_counter));

	pr_debug("tquic_lb: created config rotation=%u mode=%d\n",
		 config_rotation, cfg->mode);

	return cfg;
}
EXPORT_SYMBOL_GPL(tquic_lb_config_create);

/**
 * tquic_lb_config_destroy - Destroy a QUIC-LB configuration
 * @cfg: Configuration to destroy
 */
void tquic_lb_config_destroy(struct tquic_lb_config *cfg)
{
	if (!cfg)
		return;

	if (cfg->aes_tfm)
		crypto_free_cipher(cfg->aes_tfm);

	kmem_cache_free(lb_config_cache, cfg);
}
EXPORT_SYMBOL_GPL(tquic_lb_config_destroy);

/**
 * tquic_lb_generate_nonce - Generate a unique nonce
 * @cfg: QUIC-LB configuration
 * @nonce: Output buffer for nonce
 * @nonce_len: Length of nonce to generate
 *
 * Generates a unique nonce by combining a counter with random bytes.
 * Returns 0 on success.
 */
int tquic_lb_generate_nonce(struct tquic_lb_config *cfg,
			    u8 *nonce, size_t nonce_len)
{
	u64 counter;

	if (!cfg || !nonce || nonce_len < TQUIC_LB_NONCE_MIN_LEN)
		return -EINVAL;

	spin_lock(&cfg->lock);
	counter = cfg->nonce_counter++;
	spin_unlock(&cfg->lock);

	/* First 8 bytes from counter (or less if nonce is shorter) */
	if (nonce_len >= 8) {
		put_unaligned_be64(counter, nonce);
		/* Fill remaining with random */
		if (nonce_len > 8)
			get_random_bytes(nonce + 8, nonce_len - 8);
	} else {
		/* Short nonce: use lower bytes of counter */
		memcpy(nonce, ((u8 *)&counter) + (8 - nonce_len), nonce_len);
	}

	return 0;
}
EXPORT_SYMBOL_GPL(tquic_lb_generate_nonce);

/**
 * tquic_lb_encrypt_single_pass - Single-pass AES-ECB encryption
 * @cfg: QUIC-LB configuration
 * @plaintext: 16-byte input
 * @ciphertext: 16-byte output
 *
 * Used when server_id + nonce = 16 bytes exactly.
 * Returns 0 on success.
 */
int tquic_lb_encrypt_single_pass(struct tquic_lb_config *cfg,
				 const u8 *plaintext, u8 *ciphertext)
{
	if (!cfg || !cfg->aes_tfm)
		return -EINVAL;

	crypto_cipher_encrypt_one(cfg->aes_tfm, ciphertext, plaintext);
	return 0;
}
EXPORT_SYMBOL_GPL(tquic_lb_encrypt_single_pass);

/**
 * tquic_lb_decrypt_single_pass - Single-pass AES-ECB decryption
 * @cfg: QUIC-LB configuration
 * @ciphertext: 16-byte input
 * @plaintext: 16-byte output
 *
 * Returns 0 on success.
 */
int tquic_lb_decrypt_single_pass(struct tquic_lb_config *cfg,
				 const u8 *ciphertext, u8 *plaintext)
{
	if (!cfg || !cfg->aes_tfm)
		return -EINVAL;

	crypto_cipher_decrypt_one(cfg->aes_tfm, plaintext, ciphertext);
	return 0;
}
EXPORT_SYMBOL_GPL(tquic_lb_decrypt_single_pass);

/**
 * tquic_lb_encrypt_four_pass - Four-pass Feistel network encryption
 * @cfg: QUIC-LB configuration
 * @plaintext: Input data
 * @len: Length of data
 * @ciphertext: Output buffer
 *
 * Used when server_id + nonce != 16 bytes.
 * Implements a 4-round Feistel network with AES-ECB as the round function.
 * Returns 0 on success.
 */
int tquic_lb_encrypt_four_pass(struct tquic_lb_config *cfg,
			       const u8 *plaintext, size_t len,
			       u8 *ciphertext)
{
	u8 left[16], right[16], tmp[16], round_out[16];
	size_t half_len;
	int i, round;

	if (!cfg || !cfg->aes_tfm || len > 32)
		return -EINVAL;

	half_len = (len + 1) / 2;

	/* Split into left and right halves */
	memset(left, 0, sizeof(left));
	memset(right, 0, sizeof(right));
	memcpy(left, plaintext, half_len);
	memcpy(right, plaintext + half_len, len - half_len);

	/* 4-round Feistel network */
	for (round = 0; round < 4; round++) {
		/* Prepare round input: right half padded to 16 bytes */
		memset(tmp, 0, sizeof(tmp));
		memcpy(tmp, right, half_len);
		tmp[15] = round;  /* Include round number */

		/* Apply AES-ECB round function */
		crypto_cipher_encrypt_one(cfg->aes_tfm, round_out, tmp);

		/* XOR with left half */
		for (i = 0; i < half_len; i++)
			left[i] ^= round_out[i];

		/* Swap halves (except last round) */
		if (round < 3) {
			memcpy(tmp, left, half_len);
			memcpy(left, right, half_len);
			memcpy(right, tmp, half_len);
		}
	}

	/* Combine halves into output */
	memcpy(ciphertext, left, half_len);
	memcpy(ciphertext + half_len, right, len - half_len);

	return 0;
}
EXPORT_SYMBOL_GPL(tquic_lb_encrypt_four_pass);

/**
 * tquic_lb_decrypt_four_pass - Four-pass Feistel network decryption
 * @cfg: QUIC-LB configuration
 * @ciphertext: Input data
 * @len: Length of data
 * @plaintext: Output buffer
 *
 * Reverses the 4-round Feistel encryption.
 * Returns 0 on success.
 */
int tquic_lb_decrypt_four_pass(struct tquic_lb_config *cfg,
			       const u8 *ciphertext, size_t len,
			       u8 *plaintext)
{
	u8 left[16], right[16], tmp[16], round_out[16];
	size_t half_len;
	int i, round;

	if (!cfg || !cfg->aes_tfm || len > 32)
		return -EINVAL;

	half_len = (len + 1) / 2;

	/* Split into left and right halves */
	memset(left, 0, sizeof(left));
	memset(right, 0, sizeof(right));
	memcpy(left, ciphertext, half_len);
	memcpy(right, ciphertext + half_len, len - half_len);

	/* Reverse 4-round Feistel network */
	for (round = 3; round >= 0; round--) {
		/* Swap halves first (except first reverse round) */
		if (round < 3) {
			memcpy(tmp, left, half_len);
			memcpy(left, right, half_len);
			memcpy(right, tmp, half_len);
		}

		/* Prepare round input */
		memset(tmp, 0, sizeof(tmp));
		memcpy(tmp, right, half_len);
		tmp[15] = round;

		/* Apply AES-ECB round function */
		crypto_cipher_encrypt_one(cfg->aes_tfm, round_out, tmp);

		/* XOR with left half */
		for (i = 0; i < half_len; i++)
			left[i] ^= round_out[i];
	}

	/* Combine halves into output */
	memcpy(plaintext, left, half_len);
	memcpy(plaintext + half_len, right, len - half_len);

	return 0;
}
EXPORT_SYMBOL_GPL(tquic_lb_decrypt_four_pass);

/**
 * tquic_lb_encode_cid - Encode a QUIC-LB connection ID
 * @cfg: QUIC-LB configuration
 * @cid: Output CID structure
 *
 * Generates a connection ID with the server ID encoded according
 * to the configuration's mode (plaintext, single-pass, or four-pass).
 * Returns 0 on success.
 */
int tquic_lb_encode_cid(struct tquic_lb_config *cfg, struct tquic_lb_cid *cid)
{
	u8 nonce[TQUIC_LB_NONCE_MAX_LEN];
	u8 plaintext[TQUIC_LB_CID_PAYLOAD_MAX];
	size_t payload_len;
	int ret;

	if (!cfg || !cid)
		return -EINVAL;

	payload_len = cfg->server_id_len + cfg->nonce_len;

	/* Generate nonce */
	ret = tquic_lb_generate_nonce(cfg, nonce, cfg->nonce_len);
	if (ret)
		return ret;

	/* Build first octet: config_rotation | length_self_description */
	cid->first_octet = (cfg->config_rotation << TQUIC_LB_CONFIG_ROTATION_SHIFT) |
			   (payload_len & TQUIC_LB_LENGTH_SELF_DESC_MASK);

	/* Build plaintext: server_id || nonce */
	memcpy(plaintext, cfg->server_id, cfg->server_id_len);
	memcpy(plaintext + cfg->server_id_len, nonce, cfg->nonce_len);

	/* Apply encryption based on mode */
	switch (cfg->mode) {
	case TQUIC_LB_MODE_PLAINTEXT:
		memcpy(cid->payload, plaintext, payload_len);
		break;

	case TQUIC_LB_MODE_SINGLE_PASS:
		ret = tquic_lb_encrypt_single_pass(cfg, plaintext, cid->payload);
		if (ret)
			return ret;
		break;

	case TQUIC_LB_MODE_FOUR_PASS:
		ret = tquic_lb_encrypt_four_pass(cfg, plaintext, payload_len,
						 cid->payload);
		if (ret)
			return ret;
		break;
	}

	/* Build complete CID */
	cid->cid[0] = cid->first_octet;
	memcpy(cid->cid + 1, cid->payload, payload_len);
	cid->cid_len = 1 + payload_len;

	return 0;
}
EXPORT_SYMBOL_GPL(tquic_lb_encode_cid);

/**
 * tquic_lb_decode_cid - Decode a QUIC-LB connection ID
 * @cfg: QUIC-LB configuration
 * @cid: Connection ID bytes
 * @cid_len: Length of CID
 * @decoded: Output decoded information
 *
 * Extracts the server ID from an encoded connection ID.
 * Returns 0 on success.
 */
int tquic_lb_decode_cid(struct tquic_lb_config *cfg,
			const u8 *cid, size_t cid_len,
			struct tquic_lb_decoded *decoded)
{
	u8 plaintext[TQUIC_LB_CID_PAYLOAD_MAX];
	size_t payload_len;
	u8 config_rotation;
	int ret;

	if (!cfg || !cid || !decoded || cid_len < 2)
		return -EINVAL;

	decoded->valid = false;

	/* Extract config rotation from first octet */
	config_rotation = (cid[0] & TQUIC_LB_CONFIG_ROTATION_MASK) >>
			  TQUIC_LB_CONFIG_ROTATION_SHIFT;

	/* Check if this CID matches our configuration */
	if (config_rotation != cfg->config_rotation) {
		pr_debug("tquic_lb: config rotation mismatch %u != %u\n",
			 config_rotation, cfg->config_rotation);
		return -EINVAL;
	}

	payload_len = cfg->server_id_len + cfg->nonce_len;
	if (cid_len != 1 + payload_len) {
		pr_debug("tquic_lb: CID length mismatch %zu != %zu\n",
			 cid_len, 1 + payload_len);
		return -EINVAL;
	}

	/* Decrypt based on mode */
	switch (cfg->mode) {
	case TQUIC_LB_MODE_PLAINTEXT:
		memcpy(plaintext, cid + 1, payload_len);
		break;

	case TQUIC_LB_MODE_SINGLE_PASS:
		ret = tquic_lb_decrypt_single_pass(cfg, cid + 1, plaintext);
		if (ret)
			return ret;
		break;

	case TQUIC_LB_MODE_FOUR_PASS:
		ret = tquic_lb_decrypt_four_pass(cfg, cid + 1, payload_len,
						 plaintext);
		if (ret)
			return ret;
		break;
	}

	/* Extract server ID */
	decoded->config_rotation = config_rotation;
	decoded->server_id_len = cfg->server_id_len;
	memcpy(decoded->server_id, plaintext, cfg->server_id_len);
	decoded->valid = true;

	return 0;
}
EXPORT_SYMBOL_GPL(tquic_lb_decode_cid);

/**
 * tquic_lb_init - Initialize QUIC-LB module
 */
int __init tquic_lb_init(void)
{
	lb_config_cache = kmem_cache_create("tquic_lb_config",
					    sizeof(struct tquic_lb_config),
					    0, SLAB_HWCACHE_ALIGN, NULL);
	if (!lb_config_cache)
		return -ENOMEM;

	pr_info("tquic: QUIC-LB load balancing support initialized\n");
	return 0;
}

/**
 * tquic_lb_exit - Cleanup QUIC-LB module
 */
void __exit tquic_lb_exit(void)
{
	kmem_cache_destroy(lb_config_cache);
	pr_info("tquic: QUIC-LB load balancing support cleaned up\n");
}

MODULE_DESCRIPTION("TQUIC QUIC-LB Load Balancing Support");
MODULE_LICENSE("GPL");
