// SPDX-License-Identifier: GPL-2.0-only
/*
 * TQUIC: TLS 1.3 Crypto Integration
 *
 * Copyright (c) 2026 Justin Adams <spotty118@gmail.com>
 * Kernel implementation by Justin Adams <spotty118@gmail.com>
 *
 * Provides TLS 1.3 handshake and packet protection for TQUIC connections.
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/random.h>
#include <crypto/aead.h>
#include <crypto/hash.h>
#include <crypto/skcipher.h>
#include <crypto/aes.h>
#include <net/tquic.h>

#include "../tquic_debug.h"
#include "header_protection.h"
#include "tls.h"

/* TLS 1.3 constants */
#define TLS_HANDSHAKE_TYPE_CLIENT_HELLO	1
#define TLS_HANDSHAKE_TYPE_SERVER_HELLO	2
#define TLS_HANDSHAKE_TYPE_ENCRYPTED_EXT 8
#define TLS_HANDSHAKE_TYPE_CERTIFICATE	11
#define TLS_HANDSHAKE_TYPE_CERT_VERIFY	15
#define TLS_HANDSHAKE_TYPE_FINISHED	20

/* QUIC TLS secrets */
#define TQUIC_SECRET_MAX_LEN		48  /* SHA-384 */
#define TQUIC_KEY_MAX_LEN		32  /* AES-256 */
#define TQUIC_IV_MAX_LEN		12
#define TQUIC_HP_KEY_MAX_LEN		32

/* Cipher suites */
#define TLS_AES_128_GCM_SHA256		0x1301
#define TLS_AES_256_GCM_SHA384		0x1302
#define TLS_CHACHA20_POLY1305_SHA256	0x1303

/* QUIC v1 initial salt (RFC 9001) */
static const u8 tquic_v1_initial_salt[20] = {
	0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3,
	0x4d, 0x17, 0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad,
	0xcc, 0xbb, 0x7f, 0x0a
};

/* QUIC v2 initial salt (RFC 9369) */
static const u8 tquic_v2_initial_salt[20] = {
	0x0d, 0xed, 0xe3, 0xde, 0xf7, 0x00, 0xa6, 0xdb,
	0x81, 0x93, 0x81, 0xbe, 0x6e, 0x26, 0x9d, 0xcb,
	0xf9, 0xbd, 0x2e, 0xd9
};

/* HKDF label types */
enum tquic_hkdf_label_type {
	TQUIC_LABEL_KEY = 0,
	TQUIC_LABEL_IV,
	TQUIC_LABEL_HP,
	TQUIC_LABEL_KU,
};

/* QUIC v1 HKDF labels (RFC 9001) */
#define TQUIC_V1_LABEL_KEY		"quic key"
#define TQUIC_V1_LABEL_IV		"quic iv"
#define TQUIC_V1_LABEL_HP		"quic hp"
#define TQUIC_V1_LABEL_KU		"quic ku"

/* QUIC v2 HKDF labels (RFC 9369) */
#define TQUIC_V2_LABEL_KEY		"quicv2 key"
#define TQUIC_V2_LABEL_IV		"quicv2 iv"
#define TQUIC_V2_LABEL_HP		"quicv2 hp"
#define TQUIC_V2_LABEL_KU		"quicv2 ku"

/* Legacy aliases for compatibility */
#define TQUIC_HKDF_LABEL_KEY		TQUIC_V1_LABEL_KEY
#define TQUIC_HKDF_LABEL_IV		TQUIC_V1_LABEL_IV
#define TQUIC_HKDF_LABEL_HP		TQUIC_V1_LABEL_HP
#define TQUIC_HKDF_LABEL_KU		TQUIC_V1_LABEL_KU

/**
 * tquic_get_initial_salt - Get the initial salt for a QUIC version
 * @version: QUIC version number
 * @salt_len: OUT - length of the salt
 *
 * Returns the appropriate initial salt based on QUIC version.
 * For QUIC v1 (0x00000001), returns the RFC 9001 salt.
 * For QUIC v2 (0x6b3343cf), returns the RFC 9369 salt.
 *
 * Return: Pointer to salt bytes, or NULL for unsupported versions
 */
static const u8 *tquic_get_initial_salt(u32 version, size_t *salt_len)
{
	switch (version) {
	case TQUIC_VERSION_1:
		*salt_len = sizeof(tquic_v1_initial_salt);
		return tquic_v1_initial_salt;
	case TQUIC_VERSION_2:
		*salt_len = sizeof(tquic_v2_initial_salt);
		return tquic_v2_initial_salt;
	default:
		/* Unknown version - return v1 as fallback for draft versions */
		*salt_len = sizeof(tquic_v1_initial_salt);
		return tquic_v1_initial_salt;
	}
}

/**
 * tquic_get_hkdf_label - Get the HKDF label for a QUIC version
 * @version: QUIC version number
 * @label_type: Type of label (TQUIC_LABEL_KEY, IV, HP, or KU)
 * @label_len: OUT - length of the label string
 *
 * Returns the appropriate HKDF label based on QUIC version and label type.
 * For QUIC v1, returns labels like "quic key".
 * For QUIC v2, returns labels like "quicv2 key" per RFC 9369.
 *
 * Return: Pointer to label string, or NULL for invalid label_type
 */
static const char *tquic_get_hkdf_label(u32 version, int label_type,
					size_t *label_len)
{
	bool is_v2 = (version == TQUIC_VERSION_2);

	switch (label_type) {
	case TQUIC_LABEL_KEY:
		if (is_v2) {
			*label_len = strlen(TQUIC_V2_LABEL_KEY);
			return TQUIC_V2_LABEL_KEY;
		}
		*label_len = strlen(TQUIC_V1_LABEL_KEY);
		return TQUIC_V1_LABEL_KEY;

	case TQUIC_LABEL_IV:
		if (is_v2) {
			*label_len = strlen(TQUIC_V2_LABEL_IV);
			return TQUIC_V2_LABEL_IV;
		}
		*label_len = strlen(TQUIC_V1_LABEL_IV);
		return TQUIC_V1_LABEL_IV;

	case TQUIC_LABEL_HP:
		if (is_v2) {
			*label_len = strlen(TQUIC_V2_LABEL_HP);
			return TQUIC_V2_LABEL_HP;
		}
		*label_len = strlen(TQUIC_V1_LABEL_HP);
		return TQUIC_V1_LABEL_HP;

	case TQUIC_LABEL_KU:
		if (is_v2) {
			*label_len = strlen(TQUIC_V2_LABEL_KU);
			return TQUIC_V2_LABEL_KU;
		}
		*label_len = strlen(TQUIC_V1_LABEL_KU);
		return TQUIC_V1_LABEL_KU;

	default:
		*label_len = 0;
		return NULL;
	}
}

/* enum tquic_enc_level provided by tls.h */

/* Keys for one direction */
struct tquic_keys {
	u8 secret[TQUIC_SECRET_MAX_LEN];
	u8 key[TQUIC_KEY_MAX_LEN];
	u8 iv[TQUIC_IV_MAX_LEN];
	u8 hp_key[TQUIC_HP_KEY_MAX_LEN];
	u32 secret_len;
	u32 key_len;
	u32 iv_len;
	bool valid;
};

/* Crypto state per connection */
struct tquic_crypto_state {
	/* Cipher suite */
	u16 cipher_suite;

	/* QUIC version for key derivation (RFC 9369) */
	u32 version;

	/* Keys per encryption level */
	struct tquic_keys read_keys[TQUIC_ENC_LEVEL_COUNT];
	struct tquic_keys write_keys[TQUIC_ENC_LEVEL_COUNT];

	/* Current encryption level */
	enum tquic_enc_level read_level;
	enum tquic_enc_level write_level;

	/* Key update state (RFC 9001 Section 6) */
	u32 key_phase;
	bool key_update_pending;
	struct tquic_key_update_state *key_update;	/* Full key update state */

	/* Crypto handles -- separate TX/RX AEADs to avoid race (CF-047) */
	struct crypto_aead *aead_tx;
	struct crypto_aead *aead_rx;
	struct crypto_skcipher *hp_cipher;
	struct crypto_shash *hash;

	/* Header protection context */
	struct tquic_hp_ctx *hp_ctx;

	/* Handshake transcript */
	u8 *transcript;
	u32 transcript_len;
	u32 transcript_alloc;

	/* Handshake state */
	bool handshake_complete;
	bool early_data_accepted;
};

/*
 * HKDF-Extract using HMAC
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
 * HKDF-Expand-Label for QUIC
 */
static int tquic_hkdf_expand_label(struct crypto_shash *hash,
				   const u8 *secret, size_t secret_len,
				   const char *label, size_t label_len,
				   u8 *out, size_t out_len)
{
	u8 hkdf_label[256];
	u8 *p = hkdf_label;
	size_t hkdf_label_len;
	SHASH_DESC_ON_STACK(desc, hash);
	u8 t[64];
	int ret;
	u32 i, n;

	/*
	 * Validate label_len to prevent stack buffer overflow.
	 * Max content: 2 (length) + 1 (prefix_len) + 6 ("tls13 ") +
	 *              label_len + 1 (context len) <= 256
	 */
	if (label_len > 245) {
		ret = -EINVAL;
		goto out_zeroize;
	}

	/* Construct HKDF label: length + "tls13 " + label + context (empty) */
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

	/* HKDF-Expand */
	n = (out_len + crypto_shash_digestsize(hash) - 1) /
	    crypto_shash_digestsize(hash);

	for (i = 0; i < n; i++) {
		u8 counter = i + 1; /* RFC 5869: counter is 1-based */

		ret = crypto_shash_setkey(hash, secret, secret_len);
		if (ret)
			goto out_zeroize;

		ret = crypto_shash_init(desc);
		if (ret)
			goto out_zeroize;

		if (i > 0) {
			ret = crypto_shash_update(desc, t,
						  crypto_shash_digestsize(hash));
			if (ret)
				goto out_zeroize;
		}

		ret = crypto_shash_update(desc, hkdf_label, hkdf_label_len);
		if (ret)
			goto out_zeroize;

		ret = crypto_shash_update(desc, &counter, 1);
		if (ret)
			goto out_zeroize;

		ret = crypto_shash_final(desc, t);
		if (ret)
			goto out_zeroize;

		memcpy(out + i * crypto_shash_digestsize(hash), t,
		       min_t(size_t, crypto_shash_digestsize(hash),
			     out_len - i * crypto_shash_digestsize(hash)));
	}

	ret = 0;

out_zeroize:
	memzero_explicit(t, sizeof(t));
	memzero_explicit(hkdf_label, sizeof(hkdf_label));
	return ret;
}

/*
 * Derive keys from secret (version-aware)
 * @crypto: Crypto state
 * @keys: Key structure to populate
 * @version: QUIC version for selecting appropriate HKDF labels
 */
static int tquic_derive_keys_versioned(struct tquic_crypto_state *crypto,
				       struct tquic_keys *keys, u32 version)
{
	const char *label;
	size_t label_len;
	int ret;

	/* Derive key using version-appropriate label */
	label = tquic_get_hkdf_label(version, TQUIC_LABEL_KEY, &label_len);
	if (!label)
		return -EINVAL;

	ret = tquic_hkdf_expand_label(crypto->hash, keys->secret,
				      keys->secret_len, label, label_len,
				      keys->key, keys->key_len);
	if (ret)
		return ret;

	/* Derive IV using version-appropriate label */
	label = tquic_get_hkdf_label(version, TQUIC_LABEL_IV, &label_len);
	if (!label)
		return -EINVAL;

	ret = tquic_hkdf_expand_label(crypto->hash, keys->secret,
				      keys->secret_len, label, label_len,
				      keys->iv, keys->iv_len);
	if (ret)
		return ret;

	/* Derive HP key using version-appropriate label */
	label = tquic_get_hkdf_label(version, TQUIC_LABEL_HP, &label_len);
	if (!label)
		return -EINVAL;

	ret = tquic_hkdf_expand_label(crypto->hash, keys->secret,
				      keys->secret_len, label, label_len,
				      keys->hp_key, keys->key_len);
	if (ret)
		return ret;

	keys->valid = true;
	return 0;
}

/*
 * Derive keys from secret (legacy wrapper using v1 labels)
 */
static int __maybe_unused tquic_derive_keys(struct tquic_crypto_state *crypto,
					    struct tquic_keys *keys)
{
	return tquic_derive_keys_versioned(crypto, keys, TQUIC_VERSION_1);
}

/*
 * Set up header protection keys in the HP context after derivation
 */
static int tquic_setup_hp_keys(struct tquic_crypto_state *crypto,
			       enum tquic_enc_level level)
{
	struct tquic_keys *read_keys = &crypto->read_keys[level];
	struct tquic_keys *write_keys = &crypto->write_keys[level];
	int ret;

	if (!crypto->hp_ctx)
		return -EINVAL;

	/* Set read HP key */
	if (read_keys->valid) {
		ret = tquic_hp_set_key(crypto->hp_ctx,
				       (enum tquic_hp_enc_level)level, 0,
				       read_keys->hp_key, read_keys->key_len,
				       crypto->cipher_suite);
		if (ret)
			return ret;
	}

	/* Set write HP key */
	if (write_keys->valid) {
		ret = tquic_hp_set_key(crypto->hp_ctx,
				       (enum tquic_hp_enc_level)level, 1,
				       write_keys->hp_key, write_keys->key_len,
				       crypto->cipher_suite);
		if (ret)
			return ret;
	}

	return 0;
}

/*
 * Derive initial keys from connection ID (version-aware)
 *
 * RFC 9369 Section 3.1 specifies different initial salts and HKDF labels
 * for QUIC v2. This function uses version-aware helpers to select the
 * correct cryptographic parameters.
 *
 * @crypto: Crypto state structure
 * @dcid: Destination Connection ID (used as input key material)
 * @is_server: True if this is the server side
 * @version: QUIC version (TQUIC_VERSION_1 or TQUIC_VERSION_2)
 */
static int tquic_derive_initial_keys_versioned(struct tquic_crypto_state *crypto,
					       const struct tquic_cid *dcid,
					       bool is_server, u32 version)
{
	u8 initial_secret[32];
	u8 client_secret[32];
	u8 server_secret[32];
	struct tquic_keys *read_keys, *write_keys;
	const u8 *salt;
	size_t salt_len;
	int ret;

	/* Get version-appropriate initial salt (RFC 9369 Section 3.1) */
	salt = tquic_get_initial_salt(version, &salt_len);
	if (!salt)
		return -EINVAL;

	/* Derive initial secret using version-specific salt */
	ret = tquic_hkdf_extract(crypto->hash, salt, salt_len,
				 dcid->id, dcid->len,
				 initial_secret, sizeof(initial_secret));
	if (ret)
		goto out_zeroize;

	/* Derive client and server secrets */
	ret = tquic_hkdf_expand_label(crypto->hash, initial_secret, 32,
				      "client in", 9,
				      client_secret, 32);
	if (ret)
		goto out_zeroize;

	ret = tquic_hkdf_expand_label(crypto->hash, initial_secret, 32,
				      "server in", 9,
				      server_secret, 32);
	if (ret)
		goto out_zeroize;

	/* Set up read/write keys based on role */
	if (is_server) {
		read_keys = &crypto->read_keys[TQUIC_ENC_INITIAL];
		write_keys = &crypto->write_keys[TQUIC_ENC_INITIAL];
		memcpy(read_keys->secret, client_secret, 32);
		memcpy(write_keys->secret, server_secret, 32);
	} else {
		read_keys = &crypto->read_keys[TQUIC_ENC_INITIAL];
		write_keys = &crypto->write_keys[TQUIC_ENC_INITIAL];
		memcpy(read_keys->secret, server_secret, 32);
		memcpy(write_keys->secret, client_secret, 32);
	}

	read_keys->secret_len = 32;
	read_keys->key_len = 16;  /* AES-128 */
	read_keys->iv_len = 12;

	write_keys->secret_len = 32;
	write_keys->key_len = 16;
	write_keys->iv_len = 12;

	/* Derive actual keys using version-appropriate labels */
	ret = tquic_derive_keys_versioned(crypto, read_keys, version);
	if (ret)
		goto out_zeroize;

	ret = tquic_derive_keys_versioned(crypto, write_keys, version);
	if (ret)
		goto out_zeroize;

	ret = 0;

out_zeroize:
	/* Clear sensitive intermediate secrets */
	memzero_explicit(initial_secret, sizeof(initial_secret));
	memzero_explicit(client_secret, sizeof(client_secret));
	memzero_explicit(server_secret, sizeof(server_secret));

	return ret;
}

/*
 * Derive initial keys from connection ID (legacy wrapper - uses v1)
 */
static int __maybe_unused tquic_derive_initial_keys(struct tquic_crypto_state *crypto,
						    const struct tquic_cid *dcid,
						    bool is_server)
{
	return tquic_derive_initial_keys_versioned(crypto, dcid, is_server,
						   TQUIC_VERSION_1);
}

/*
 * Create nonce for AEAD encryption
 *
 * The nonce is formed by XORing the IV with the reconstructed packet number.
 * This is the standard nonce construction per RFC 9001 Section 5.3.
 */
static void tquic_create_nonce(const u8 *iv, u64 pkt_num, u8 *nonce)
{
	int i;

	memcpy(nonce, iv, 12);

	/* XOR packet number into nonce */
	for (i = 0; i < 8; i++) {
		nonce[11 - i] ^= (pkt_num >> (i * 8)) & 0xff;
	}
}

/*
 * Create nonce for AEAD encryption with multipath path ID
 *
 * For multipath QUIC (draft-ietf-quic-multipath), the path ID is incorporated
 * into the nonce to ensure cryptographic separation between paths.
 *
 * Per draft-ietf-quic-multipath-17 Section 5.1.1:
 * "When multipath is used, each path has its own packet number space.
 *  The nonce is formed by XORing the IV with (path_id << 32 | packet_number)."
 *
 * This ensures that even if the same packet number is used on different paths,
 * the nonces will be different, maintaining AEAD security guarantees.
 */
static void tquic_create_nonce_multipath(const u8 *iv, u64 pkt_num,
					 u32 path_id, u8 *nonce)
{
	int i;

	memcpy(nonce, iv, 12);

	/*
	 * Combine path_id and packet number per draft-ietf-quic-multipath:
	 * XOR the full 62-bit packet number into the low 8 bytes first,
	 * then XOR the path_id into bytes 4..7 of the nonce. This ensures
	 * the full packet number space is used and provides cryptographic
	 * domain separation between paths without truncation.
	 */

	/* XOR full 8-byte packet number into nonce (same as single-path) */
	for (i = 0; i < 8; i++)
		nonce[11 - i] ^= (pkt_num >> (i * 8)) & 0xff;

	/* XOR path_id into nonce bytes 4..7 for path separation */
	for (i = 0; i < 4; i++)
		nonce[7 - i] ^= (path_id >> (i * 8)) & 0xff;
}

/*
 * Encrypt packet payload
 */
int tquic_encrypt_packet(struct tquic_crypto_state *crypto,
			 u8 *header, size_t header_len,
			 u8 *payload, size_t payload_len,
			 u64 pkt_num, u8 *out, size_t *out_len)
{
	struct tquic_keys *keys = &crypto->write_keys[crypto->write_level];
	DECLARE_CRYPTO_WAIT(wait);
	u8 nonce[12];
	struct aead_request *req;
	struct scatterlist sg[2];
	int ret;

	if (!keys->valid)
		return -EINVAL;

	tquic_create_nonce(keys->iv, pkt_num, nonce);

	/* Key is set once at installation time (CF-145), use TX handle */
	req = aead_request_alloc(crypto->aead_tx, GFP_ATOMIC);
	if (!req) {
		ret = -ENOMEM;
		goto out_zeroize;
	}

	sg_init_table(sg, 2);
	sg_set_buf(&sg[0], header, header_len);
	sg_set_buf(&sg[1], payload, payload_len + 16);  /* + auth tag */

	aead_request_set_crypt(req, sg, sg, payload_len, nonce);
	aead_request_set_ad(req, header_len);
	aead_request_set_callback(req, CRYPTO_TFM_REQ_MAY_BACKLOG,
				  crypto_req_done, &wait);

	ret = crypto_wait_req(crypto_aead_encrypt(req), &wait);

	aead_request_free(req);

	if (ret == 0)
		*out_len = payload_len + 16;  /* Payload + auth tag */

out_zeroize:
	memzero_explicit(nonce, sizeof(nonce));
	return ret;
}
EXPORT_SYMBOL_GPL(tquic_encrypt_packet);

/*
 * Decrypt packet payload
 */
int tquic_decrypt_packet(struct tquic_crypto_state *crypto,
			 const u8 *header, size_t header_len,
			 u8 *payload, size_t payload_len,
			 u64 pkt_num, u8 *out, size_t *out_len)
{
	struct tquic_keys *keys = &crypto->read_keys[crypto->read_level];
	DECLARE_CRYPTO_WAIT(wait);
	u8 nonce[12];
	struct aead_request *req;
	struct scatterlist sg[2];
	int ret;

	if (!keys->valid)
		return -EINVAL;

	if (payload_len < 16)
		return -EINVAL;  /* Too short for auth tag */

	tquic_create_nonce(keys->iv, pkt_num, nonce);

	/* Key is set once at installation time (CF-145), use RX handle */
	req = aead_request_alloc(crypto->aead_rx, GFP_ATOMIC);
	if (!req) {
		ret = -ENOMEM;
		goto out_zeroize;
	}

	sg_init_table(sg, 2);
	sg_set_buf(&sg[0], header, header_len);
	sg_set_buf(&sg[1], payload, payload_len);

	aead_request_set_crypt(req, sg, sg, payload_len, nonce);
	aead_request_set_ad(req, header_len);
	aead_request_set_callback(req, CRYPTO_TFM_REQ_MAY_BACKLOG,
				  crypto_req_done, &wait);

	ret = crypto_wait_req(crypto_aead_decrypt(req), &wait);

	aead_request_free(req);

	if (ret == 0)
		*out_len = payload_len - 16;  /* Remove auth tag */

out_zeroize:
	memzero_explicit(nonce, sizeof(nonce));
	return ret;
}
EXPORT_SYMBOL_GPL(tquic_decrypt_packet);

/*
 * Encrypt packet payload for multipath QUIC
 *
 * This version includes the path_id in the nonce construction to ensure
 * cryptographic separation between paths per draft-ietf-quic-multipath.
 */
int tquic_encrypt_packet_multipath(struct tquic_crypto_state *crypto,
				   u8 *header, size_t header_len,
				   u8 *payload, size_t payload_len,
				   u64 pkt_num, u32 path_id,
				   u8 *out, size_t *out_len)
{
	struct tquic_keys *keys = &crypto->write_keys[crypto->write_level];
	DECLARE_CRYPTO_WAIT(wait);
	u8 nonce[12];
	struct aead_request *req;
	struct scatterlist sg[2];
	int ret;

	if (!keys->valid)
		return -EINVAL;

	/* Use multipath nonce with path_id */
	tquic_create_nonce_multipath(keys->iv, pkt_num, path_id, nonce);

	/* Key is set once at installation time (CF-145), use TX handle */
	req = aead_request_alloc(crypto->aead_tx, GFP_ATOMIC);
	if (!req) {
		ret = -ENOMEM;
		goto out_zeroize;
	}

	sg_init_table(sg, 2);
	sg_set_buf(&sg[0], header, header_len);
	sg_set_buf(&sg[1], payload, payload_len + 16);

	aead_request_set_crypt(req, sg, sg, payload_len, nonce);
	aead_request_set_ad(req, header_len);
	aead_request_set_callback(req, CRYPTO_TFM_REQ_MAY_BACKLOG,
				  crypto_req_done, &wait);

	ret = crypto_wait_req(crypto_aead_encrypt(req), &wait);

	aead_request_free(req);

	if (ret == 0)
		*out_len = payload_len + 16;

out_zeroize:
	memzero_explicit(nonce, sizeof(nonce));
	return ret;
}
EXPORT_SYMBOL_GPL(tquic_encrypt_packet_multipath);

/*
 * Decrypt packet payload for multipath QUIC
 *
 * This version includes the path_id in the nonce construction to ensure
 * cryptographic separation between paths per draft-ietf-quic-multipath.
 */
int tquic_decrypt_packet_multipath(struct tquic_crypto_state *crypto,
				   const u8 *header, size_t header_len,
				   u8 *payload, size_t payload_len,
				   u64 pkt_num, u32 path_id,
				   u8 *out, size_t *out_len)
{
	struct tquic_keys *keys = &crypto->read_keys[crypto->read_level];
	DECLARE_CRYPTO_WAIT(wait);
	u8 nonce[12];
	struct aead_request *req;
	struct scatterlist sg[2];
	int ret;

	if (!keys->valid)
		return -EINVAL;

	if (payload_len < 16)
		return -EINVAL;

	/* Use multipath nonce with path_id */
	tquic_create_nonce_multipath(keys->iv, pkt_num, path_id, nonce);

	/* Key is set once at installation time (CF-145), use RX handle */
	req = aead_request_alloc(crypto->aead_rx, GFP_ATOMIC);
	if (!req) {
		ret = -ENOMEM;
		goto out_zeroize;
	}

	sg_init_table(sg, 2);
	sg_set_buf(&sg[0], header, header_len);
	sg_set_buf(&sg[1], payload, payload_len);

	aead_request_set_crypt(req, sg, sg, payload_len, nonce);
	aead_request_set_ad(req, header_len);
	aead_request_set_callback(req, CRYPTO_TFM_REQ_MAY_BACKLOG,
				  crypto_req_done, &wait);

	ret = crypto_wait_req(crypto_aead_decrypt(req), &wait);

	aead_request_free(req);

	if (ret == 0)
		*out_len = payload_len - 16;

out_zeroize:
	memzero_explicit(nonce, sizeof(nonce));
	return ret;
}
EXPORT_SYMBOL_GPL(tquic_decrypt_packet_multipath);

/*
 * Initialize crypto state (version-aware)
 *
 * RFC 9369 defines QUIC v2 with different initial salts and HKDF labels.
 * This function initializes crypto state using the appropriate version-specific
 * parameters.
 *
 * @dcid: Destination Connection ID for initial key derivation
 * @is_server: True if this is the server side
 * @version: QUIC version (TQUIC_VERSION_1 or TQUIC_VERSION_2)
 *
 * Returns: Initialized crypto state, or NULL on failure
 */
struct tquic_crypto_state *tquic_crypto_init_versioned(const struct tquic_cid *dcid,
						       bool is_server, u32 version)
{
	struct tquic_crypto_state *crypto;
	int ret;

	crypto = kzalloc(sizeof(*crypto), GFP_KERNEL);
	if (!crypto)
		return NULL;

	crypto->cipher_suite = TLS_AES_128_GCM_SHA256;
	crypto->version = version;

	/* Allocate separate TX/RX AEAD handles to avoid race (CF-047) */
	crypto->aead_tx = crypto_alloc_aead("gcm(aes)", 0, 0);
	if (IS_ERR(crypto->aead_tx)) {
		tquic_err("failed to allocate TX AEAD\n");
		kfree_sensitive(crypto);
		return NULL;
	}

	crypto->aead_rx = crypto_alloc_aead("gcm(aes)", 0, 0);
	if (IS_ERR(crypto->aead_rx)) {
		tquic_err("failed to allocate RX AEAD\n");
		crypto_free_aead(crypto->aead_tx);
		kfree_sensitive(crypto);
		return NULL;
	}

	crypto->hash = crypto_alloc_shash("hmac(sha256)", 0, 0);
	if (IS_ERR(crypto->hash)) {
		tquic_err("failed to allocate HMAC\n");
		crypto_free_aead(crypto->aead_rx);
		crypto_free_aead(crypto->aead_tx);
		kfree_sensitive(crypto);
		return NULL;
	}

	crypto->hp_cipher = crypto_alloc_skcipher("ecb(aes)", 0, 0);
	if (IS_ERR(crypto->hp_cipher)) {
		tquic_err("failed to allocate HP cipher\n");
		crypto_free_shash(crypto->hash);
		crypto_free_aead(crypto->aead_rx);
		crypto_free_aead(crypto->aead_tx);
		kfree_sensitive(crypto);
		return NULL;
	}

	/* Allocate header protection context */
	crypto->hp_ctx = tquic_hp_ctx_alloc();
	if (!crypto->hp_ctx) {
		tquic_err("failed to allocate HP context\n");
		crypto_free_skcipher(crypto->hp_cipher);
		crypto_free_shash(crypto->hash);
		crypto_free_aead(crypto->aead_rx);
		crypto_free_aead(crypto->aead_tx);
		kfree_sensitive(crypto);
		return NULL;
	}

	/* Set AEAD auth tag length on both handles */
	ret = crypto_aead_setauthsize(crypto->aead_tx, 16);
	if (ret) {
		tquic_err("failed to set TX auth tag size: %d\n", ret);
		tquic_crypto_cleanup(crypto);
		return NULL;
	}

	ret = crypto_aead_setauthsize(crypto->aead_rx, 16);
	if (ret) {
		tquic_err("failed to set RX auth tag size: %d\n", ret);
		tquic_crypto_cleanup(crypto);
		return NULL;
	}

	/* Derive initial keys using version-appropriate salt and labels */
	ret = tquic_derive_initial_keys_versioned(crypto, dcid, is_server, version);
	if (ret) {
		tquic_err("failed to derive initial keys for v%s\n",
			  version == TQUIC_VERSION_2 ? "2" : "1");
		tquic_crypto_cleanup(crypto);
		return NULL;
	}

	/* Set up initial HP keys */
	ret = tquic_setup_hp_keys(crypto, TQUIC_ENC_INITIAL);
	if (ret) {
		tquic_err("failed to set up initial HP keys\n");
		tquic_crypto_cleanup(crypto);
		return NULL;
	}

	/* Install AEAD keys at init time so per-packet setkey is unnecessary */
	ret = crypto_aead_setkey(crypto->aead_rx,
				 crypto->read_keys[TQUIC_ENC_INITIAL].key,
				 crypto->read_keys[TQUIC_ENC_INITIAL].key_len);
	if (ret) {
		tquic_err("failed to set initial RX AEAD key\n");
		tquic_crypto_cleanup(crypto);
		return NULL;
	}

	ret = crypto_aead_setkey(crypto->aead_tx,
				 crypto->write_keys[TQUIC_ENC_INITIAL].key,
				 crypto->write_keys[TQUIC_ENC_INITIAL].key_len);
	if (ret) {
		tquic_err("failed to set initial TX AEAD key\n");
		tquic_crypto_cleanup(crypto);
		return NULL;
	}

	crypto->read_level = TQUIC_ENC_INITIAL;
	crypto->write_level = TQUIC_ENC_INITIAL;

	/* Sync HP context levels */
	tquic_hp_set_level(crypto->hp_ctx,
			   (enum tquic_hp_enc_level)TQUIC_ENC_INITIAL,
			   (enum tquic_hp_enc_level)TQUIC_ENC_INITIAL);

	tquic_dbg("initialized crypto state for QUIC v%s\n",
		  version == TQUIC_VERSION_2 ? "2" : "1");

	return crypto;
}
EXPORT_SYMBOL_GPL(tquic_crypto_init_versioned);

/*
 * Initialize crypto state (legacy wrapper - uses v1)
 *
 * This is the backward-compatible version that defaults to QUIC v1.
 * New code should use tquic_crypto_init_versioned() with an explicit version.
 */
struct tquic_crypto_state *tquic_crypto_init(const struct tquic_cid *dcid,
					     bool is_server)
{
	return tquic_crypto_init_versioned(dcid, is_server, TQUIC_VERSION_1);
}
EXPORT_SYMBOL_GPL(tquic_crypto_init);

/*
 * Cleanup crypto state
 */
void tquic_crypto_cleanup(struct tquic_crypto_state *crypto)
{
	int i;

	if (!crypto)
		return;

	/* Free header protection context */
	if (crypto->hp_ctx)
		tquic_hp_ctx_free(crypto->hp_ctx);

	if (crypto->aead_tx && !IS_ERR(crypto->aead_tx))
		crypto_free_aead(crypto->aead_tx);

	if (crypto->aead_rx && !IS_ERR(crypto->aead_rx))
		crypto_free_aead(crypto->aead_rx);

	if (crypto->hash && !IS_ERR(crypto->hash))
		crypto_free_shash(crypto->hash);

	if (crypto->hp_cipher && !IS_ERR(crypto->hp_cipher))
		crypto_free_skcipher(crypto->hp_cipher);

	/* Zeroize all key material before freeing */
	for (i = 0; i < TQUIC_ENC_LEVEL_COUNT; i++) {
		memzero_explicit(&crypto->read_keys[i],
				 sizeof(crypto->read_keys[i]));
		memzero_explicit(&crypto->write_keys[i],
				 sizeof(crypto->write_keys[i]));
	}

	/* Zeroize transcript (may contain sensitive handshake data) */
	if (crypto->transcript) {
		memzero_explicit(crypto->transcript, crypto->transcript_alloc);
		kfree_sensitive(crypto->transcript);
	}

	kfree_sensitive(crypto);
}
EXPORT_SYMBOL_GPL(tquic_crypto_cleanup);

/*
 * Check if handshake is complete
 */
bool tquic_crypto_handshake_complete(struct tquic_crypto_state *crypto)
{
	return crypto ? crypto->handshake_complete : false;
}
EXPORT_SYMBOL_GPL(tquic_crypto_handshake_complete);

/*
 * Apply header protection to an outgoing packet
 */
#ifndef TQUIC_OUT_OF_TREE
int tquic_crypto_protect_header(struct tquic_crypto_state *crypto,
				u8 *packet, size_t packet_len,
				size_t pn_offset)
{
	if (!crypto || !crypto->hp_ctx)
		return -EINVAL;

	return tquic_hp_protect(crypto->hp_ctx, packet, packet_len, pn_offset);
}
EXPORT_SYMBOL_GPL(tquic_crypto_protect_header);

/*
 * Remove header protection from an incoming packet
 */
int tquic_crypto_unprotect_header(struct tquic_crypto_state *crypto,
				  u8 *packet, size_t packet_len,
				  size_t pn_offset, u8 *pn_len,
				  u8 *key_phase)
{
	if (!crypto || !crypto->hp_ctx)
		return -EINVAL;

	return tquic_hp_unprotect(crypto->hp_ctx, packet, packet_len,
				  pn_offset, pn_len, key_phase);
}
EXPORT_SYMBOL_GPL(tquic_crypto_unprotect_header);
#endif /* TQUIC_OUT_OF_TREE */

/*
 * Get the header protection context (for direct access if needed)
 */
struct tquic_hp_ctx *tquic_crypto_get_hp_ctx(struct tquic_crypto_state *crypto)
{
	return crypto ? crypto->hp_ctx : NULL;
}
EXPORT_SYMBOL_GPL(tquic_crypto_get_hp_ctx);

/*
 * Update encryption level and sync HP context
 */
void tquic_crypto_set_level(struct tquic_crypto_state *crypto,
			    enum tquic_enc_level read_level,
			    enum tquic_enc_level write_level)
{
	if (!crypto)
		return;

	crypto->read_level = read_level;
	crypto->write_level = write_level;

	/* Re-install AEAD keys for the new active levels (CF-145) */
	if (crypto->read_keys[read_level].valid && crypto->aead_rx) {
		int ret;

		ret = crypto_aead_setkey(crypto->aead_rx,
					crypto->read_keys[read_level].key,
					crypto->read_keys[read_level].key_len);
		WARN_ON_ONCE(ret);
	}

	if (crypto->write_keys[write_level].valid && crypto->aead_tx) {
		int ret;

		ret = crypto_aead_setkey(crypto->aead_tx,
					crypto->write_keys[write_level].key,
					crypto->write_keys[write_level].key_len);
		WARN_ON_ONCE(ret);
	}

	/* Sync HP context levels */
	if (crypto->hp_ctx)
		tquic_hp_set_level(crypto->hp_ctx,
				   (enum tquic_hp_enc_level)read_level,
				   (enum tquic_hp_enc_level)write_level);
}
EXPORT_SYMBOL_GPL(tquic_crypto_set_level);

/*
 * Install keys for a new encryption level (version-aware)
 *
 * This is called when TLS provides new secrets (e.g., after ClientHello/ServerHello).
 * Uses the QUIC version stored in crypto state to derive keys with the appropriate
 * HKDF labels per RFC 9001 (v1) or RFC 9369 (v2).
 *
 * @crypto: Crypto state
 * @level: Encryption level for the new keys
 * @read_secret: Secret for decryption (may be NULL)
 * @read_secret_len: Length of read secret
 * @write_secret: Secret for encryption (may be NULL)
 * @write_secret_len: Length of write secret
 *
 * Returns: 0 on success, negative error code on failure
 */
int tquic_crypto_install_keys(struct tquic_crypto_state *crypto,
			      enum tquic_enc_level level,
			      const u8 *read_secret, size_t read_secret_len,
			      const u8 *write_secret, size_t write_secret_len)
{
	struct tquic_keys *read_keys = &crypto->read_keys[level];
	struct tquic_keys *write_keys = &crypto->write_keys[level];
	u32 version;
	int ret;

	if (!crypto || level >= TQUIC_ENC_LEVEL_COUNT)
		return -EINVAL;

	/* Use stored version for key derivation */
	version = crypto->version ? crypto->version : TQUIC_VERSION_1;

	/* Set up read keys */
	if (read_secret && read_secret_len > 0) {
		memcpy(read_keys->secret, read_secret,
		       min_t(size_t, read_secret_len, TQUIC_SECRET_MAX_LEN));
		read_keys->secret_len = min_t(size_t, read_secret_len,
					      TQUIC_SECRET_MAX_LEN);

		/* Determine key/iv lengths based on cipher suite */
		switch (crypto->cipher_suite) {
		case TLS_AES_128_GCM_SHA256:
			read_keys->key_len = 16;
			read_keys->iv_len = 12;
			break;
		case TLS_AES_256_GCM_SHA384:
			read_keys->key_len = 32;
			read_keys->iv_len = 12;
			break;
		case TLS_CHACHA20_POLY1305_SHA256:
			read_keys->key_len = 32;
			read_keys->iv_len = 12;
			break;
		default:
			return -EINVAL;
		}

		/* Use version-aware key derivation */
		ret = tquic_derive_keys_versioned(crypto, read_keys, version);
		if (ret)
			return ret;

		/* Install AEAD key if this is the active read level */
		if (level == crypto->read_level) {
			ret = crypto_aead_setkey(crypto->aead_rx,
						 read_keys->key,
						 read_keys->key_len);
			if (ret)
				return ret;
		}
	}

	/* Set up write keys */
	if (write_secret && write_secret_len > 0) {
		memcpy(write_keys->secret, write_secret,
		       min_t(size_t, write_secret_len, TQUIC_SECRET_MAX_LEN));
		write_keys->secret_len = min_t(size_t, write_secret_len,
					       TQUIC_SECRET_MAX_LEN);

		switch (crypto->cipher_suite) {
		case TLS_AES_128_GCM_SHA256:
			write_keys->key_len = 16;
			write_keys->iv_len = 12;
			break;
		case TLS_AES_256_GCM_SHA384:
			write_keys->key_len = 32;
			write_keys->iv_len = 12;
			break;
		case TLS_CHACHA20_POLY1305_SHA256:
			write_keys->key_len = 32;
			write_keys->iv_len = 12;
			break;
		default:
			return -EINVAL;
		}

		/* Use version-aware key derivation */
		ret = tquic_derive_keys_versioned(crypto, write_keys, version);
		if (ret)
			return ret;

		/* Install AEAD key if this is the active write level */
		if (level == crypto->write_level) {
			ret = crypto_aead_setkey(crypto->aead_tx,
						 write_keys->key,
						 write_keys->key_len);
			if (ret)
				return ret;
		}
	}

	/* Set up HP keys for this level */
	ret = tquic_setup_hp_keys(crypto, level);
	if (ret)
		return ret;

	tquic_info("installed keys for level %d (v%s)\n",
		   level, version == TQUIC_VERSION_2 ? "2" : "1");

	return 0;
}
EXPORT_SYMBOL_GPL(tquic_crypto_install_keys);

/*
 * Get the QUIC version used by this crypto state
 */
u32 tquic_crypto_get_version(struct tquic_crypto_state *crypto)
{
	return crypto ? crypto->version : TQUIC_VERSION_1;
}
EXPORT_SYMBOL_GPL(tquic_crypto_get_version);

/*
 * Set the QUIC version for key derivation
 *
 * This should be called when version negotiation completes to ensure
 * subsequent key derivations use the correct HKDF labels.
 */
void tquic_crypto_set_version(struct tquic_crypto_state *crypto, u32 version)
{
	if (crypto)
		crypto->version = version;
}
EXPORT_SYMBOL_GPL(tquic_crypto_set_version);

MODULE_DESCRIPTION("TQUIC TLS 1.3 Crypto Integration");
MODULE_LICENSE("GPL");
