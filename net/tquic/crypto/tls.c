// SPDX-License-Identifier: GPL-2.0-only
/*
 * TQUIC: TLS 1.3 Crypto Integration
 *
 * Copyright (c) 2026 Linux Foundation
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

/* QUIC version salt for initial keys */
static const u8 tquic_v1_salt[] = {
	0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3,
	0x4d, 0x17, 0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad,
	0xcc, 0xbb, 0x7f, 0x0a
};

/* HKDF labels */
#define TQUIC_HKDF_LABEL_KEY		"quic key"
#define TQUIC_HKDF_LABEL_IV		"quic iv"
#define TQUIC_HKDF_LABEL_HP		"quic hp"
#define TQUIC_HKDF_LABEL_KU		"quic ku"

/* Encryption level */
enum tquic_enc_level {
	TQUIC_ENC_INITIAL,
	TQUIC_ENC_HANDSHAKE,
	TQUIC_ENC_APPLICATION,
	TQUIC_ENC_LEVEL_COUNT,
};

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

/* Forward declaration for header protection context */
struct tquic_hp_ctx;

/* Header protection context allocation/free (from header_protection.c) */
extern struct tquic_hp_ctx *tquic_hp_ctx_alloc(void);
extern void tquic_hp_ctx_free(struct tquic_hp_ctx *ctx);
extern int tquic_hp_set_key(struct tquic_hp_ctx *ctx, int level,
			    int direction, const u8 *key, size_t key_len, u16 cipher);
extern void tquic_hp_set_level(struct tquic_hp_ctx *ctx, int read_level, int write_level);
extern int tquic_hp_protect(struct tquic_hp_ctx *ctx, u8 *packet,
			    size_t packet_len, size_t pn_offset);
extern int tquic_hp_unprotect(struct tquic_hp_ctx *ctx, u8 *packet,
			      size_t packet_len, size_t pn_offset,
			      u8 *pn_len, u8 *key_phase);

/* Crypto state per connection */
struct tquic_crypto_state {
	/* Cipher suite */
	u16 cipher_suite;

	/* Keys per encryption level */
	struct tquic_keys read_keys[TQUIC_ENC_LEVEL_COUNT];
	struct tquic_keys write_keys[TQUIC_ENC_LEVEL_COUNT];

	/* Current encryption level */
	enum tquic_enc_level read_level;
	enum tquic_enc_level write_level;

	/* Key update state */
	u32 key_phase;
	bool key_update_pending;

	/* Crypto handles */
	struct crypto_aead *aead;
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
		ret = crypto_shash_setkey(hash, secret, secret_len);
		if (ret)
			return ret;

		ret = crypto_shash_init(desc);
		if (ret)
			return ret;

		if (i > 0) {
			ret = crypto_shash_update(desc, t,
						  crypto_shash_digestsize(hash));
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

		memcpy(out + i * crypto_shash_digestsize(hash), t,
		       min_t(size_t, crypto_shash_digestsize(hash),
			     out_len - i * crypto_shash_digestsize(hash)));
	}

	return 0;
}

/*
 * Derive keys from secret
 */
static int tquic_derive_keys(struct tquic_crypto_state *crypto,
			     struct tquic_keys *keys)
{
	int ret;

	ret = tquic_hkdf_expand_label(crypto->hash, keys->secret,
				      keys->secret_len, TQUIC_HKDF_LABEL_KEY,
				      strlen(TQUIC_HKDF_LABEL_KEY),
				      keys->key, keys->key_len);
	if (ret)
		return ret;

	ret = tquic_hkdf_expand_label(crypto->hash, keys->secret,
				      keys->secret_len, TQUIC_HKDF_LABEL_IV,
				      strlen(TQUIC_HKDF_LABEL_IV),
				      keys->iv, keys->iv_len);
	if (ret)
		return ret;

	ret = tquic_hkdf_expand_label(crypto->hash, keys->secret,
				      keys->secret_len, TQUIC_HKDF_LABEL_HP,
				      strlen(TQUIC_HKDF_LABEL_HP),
				      keys->hp_key, keys->key_len);
	if (ret)
		return ret;

	keys->valid = true;
	return 0;
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
		ret = tquic_hp_set_key(crypto->hp_ctx, level, 0,
				       read_keys->hp_key, read_keys->key_len,
				       crypto->cipher_suite);
		if (ret)
			return ret;
	}

	/* Set write HP key */
	if (write_keys->valid) {
		ret = tquic_hp_set_key(crypto->hp_ctx, level, 1,
				       write_keys->hp_key, write_keys->key_len,
				       crypto->cipher_suite);
		if (ret)
			return ret;
	}

	return 0;
}

/*
 * Derive initial keys from connection ID
 */
static int tquic_derive_initial_keys(struct tquic_crypto_state *crypto,
				     const struct tquic_cid *dcid,
				     bool is_server)
{
	u8 initial_secret[32];
	u8 client_secret[32];
	u8 server_secret[32];
	struct tquic_keys *read_keys, *write_keys;
	int ret;

	/* Derive initial secret */
	ret = tquic_hkdf_extract(crypto->hash, tquic_v1_salt,
				 sizeof(tquic_v1_salt),
				 dcid->id, dcid->len,
				 initial_secret, sizeof(initial_secret));
	if (ret)
		return ret;

	/* Derive client and server secrets */
	ret = tquic_hkdf_expand_label(crypto->hash, initial_secret, 32,
				      "client in", 9,
				      client_secret, 32);
	if (ret)
		return ret;

	ret = tquic_hkdf_expand_label(crypto->hash, initial_secret, 32,
				      "server in", 9,
				      server_secret, 32);
	if (ret)
		return ret;

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

	/* Derive actual keys */
	ret = tquic_derive_keys(crypto, read_keys);
	if (ret)
		return ret;

	ret = tquic_derive_keys(crypto, write_keys);
	if (ret)
		return ret;

	return 0;
}

/*
 * Create nonce for AEAD encryption
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
 * Encrypt packet payload
 */
int tquic_encrypt_packet(struct tquic_crypto_state *crypto,
			 u8 *header, size_t header_len,
			 u8 *payload, size_t payload_len,
			 u64 pkt_num, u8 *out, size_t *out_len)
{
	struct tquic_keys *keys = &crypto->write_keys[crypto->write_level];
	u8 nonce[12];
	struct aead_request *req;
	struct scatterlist sg[2];
	int ret;

	if (!keys->valid)
		return -EINVAL;

	tquic_create_nonce(keys->iv, pkt_num, nonce);

	req = aead_request_alloc(crypto->aead, GFP_ATOMIC);
	if (!req)
		return -ENOMEM;

	/* Set up AEAD request */
	ret = crypto_aead_setkey(crypto->aead, keys->key, keys->key_len);
	if (ret) {
		aead_request_free(req);
		return ret;
	}

	sg_init_table(sg, 2);
	sg_set_buf(&sg[0], header, header_len);
	sg_set_buf(&sg[1], payload, payload_len + 16);  /* + auth tag */

	aead_request_set_crypt(req, sg, sg, payload_len, nonce);
	aead_request_set_ad(req, header_len);

	ret = crypto_aead_encrypt(req);

	aead_request_free(req);

	*out_len = payload_len + 16;  /* Payload + auth tag */
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
	u8 nonce[12];
	struct aead_request *req;
	struct scatterlist sg[2];
	int ret;

	if (!keys->valid)
		return -EINVAL;

	if (payload_len < 16)
		return -EINVAL;  /* Too short for auth tag */

	tquic_create_nonce(keys->iv, pkt_num, nonce);

	req = aead_request_alloc(crypto->aead, GFP_ATOMIC);
	if (!req)
		return -ENOMEM;

	ret = crypto_aead_setkey(crypto->aead, keys->key, keys->key_len);
	if (ret) {
		aead_request_free(req);
		return ret;
	}

	sg_init_table(sg, 2);
	sg_set_buf(&sg[0], header, header_len);
	sg_set_buf(&sg[1], payload, payload_len);

	aead_request_set_crypt(req, sg, sg, payload_len, nonce);
	aead_request_set_ad(req, header_len);

	ret = crypto_aead_decrypt(req);

	aead_request_free(req);

	if (ret == 0)
		*out_len = payload_len - 16;  /* Remove auth tag */

	return ret;
}
EXPORT_SYMBOL_GPL(tquic_decrypt_packet);

/*
 * Initialize crypto state
 */
struct tquic_crypto_state *tquic_crypto_init(const struct tquic_cid *dcid,
					     bool is_server)
{
	struct tquic_crypto_state *crypto;
	int ret;

	crypto = kzalloc(sizeof(*crypto), GFP_KERNEL);
	if (!crypto)
		return NULL;

	crypto->cipher_suite = TLS_AES_128_GCM_SHA256;

	/* Allocate crypto transforms */
	crypto->aead = crypto_alloc_aead("gcm(aes)", 0, 0);
	if (IS_ERR(crypto->aead)) {
		pr_err("tquic_crypto: failed to allocate AEAD\n");
		kfree(crypto);
		return NULL;
	}

	crypto->hash = crypto_alloc_shash("hmac(sha256)", 0, 0);
	if (IS_ERR(crypto->hash)) {
		pr_err("tquic_crypto: failed to allocate HMAC\n");
		crypto_free_aead(crypto->aead);
		kfree(crypto);
		return NULL;
	}

	crypto->hp_cipher = crypto_alloc_skcipher("ecb(aes)", 0, 0);
	if (IS_ERR(crypto->hp_cipher)) {
		pr_err("tquic_crypto: failed to allocate HP cipher\n");
		crypto_free_shash(crypto->hash);
		crypto_free_aead(crypto->aead);
		kfree(crypto);
		return NULL;
	}

	/* Allocate header protection context */
	crypto->hp_ctx = tquic_hp_ctx_alloc();
	if (!crypto->hp_ctx) {
		pr_err("tquic_crypto: failed to allocate HP context\n");
		crypto_free_skcipher(crypto->hp_cipher);
		crypto_free_shash(crypto->hash);
		crypto_free_aead(crypto->aead);
		kfree(crypto);
		return NULL;
	}

	/* Set AEAD auth tag length */
	crypto_aead_setauthsize(crypto->aead, 16);

	/* Derive initial keys */
	ret = tquic_derive_initial_keys(crypto, dcid, is_server);
	if (ret) {
		pr_err("tquic_crypto: failed to derive initial keys\n");
		tquic_crypto_cleanup(crypto);
		return NULL;
	}

	/* Set up initial HP keys */
	ret = tquic_setup_hp_keys(crypto, TQUIC_ENC_INITIAL);
	if (ret) {
		pr_err("tquic_crypto: failed to set up initial HP keys\n");
		tquic_crypto_cleanup(crypto);
		return NULL;
	}

	crypto->read_level = TQUIC_ENC_INITIAL;
	crypto->write_level = TQUIC_ENC_INITIAL;

	/* Sync HP context levels */
	tquic_hp_set_level(crypto->hp_ctx, TQUIC_ENC_INITIAL, TQUIC_ENC_INITIAL);

	pr_debug("tquic_crypto: initialized crypto state with HP\n");

	return crypto;
}
EXPORT_SYMBOL_GPL(tquic_crypto_init);

/*
 * Cleanup crypto state
 */
void tquic_crypto_cleanup(struct tquic_crypto_state *crypto)
{
	if (!crypto)
		return;

	/* Free header protection context */
	if (crypto->hp_ctx)
		tquic_hp_ctx_free(crypto->hp_ctx);

	if (crypto->aead && !IS_ERR(crypto->aead))
		crypto_free_aead(crypto->aead);

	if (crypto->hash && !IS_ERR(crypto->hash))
		crypto_free_shash(crypto->hash);

	if (crypto->hp_cipher && !IS_ERR(crypto->hp_cipher))
		crypto_free_skcipher(crypto->hp_cipher);

	kfree(crypto->transcript);
	kfree(crypto);
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

	/* Sync HP context levels */
	if (crypto->hp_ctx)
		tquic_hp_set_level(crypto->hp_ctx, read_level, write_level);
}
EXPORT_SYMBOL_GPL(tquic_crypto_set_level);

/*
 * Install keys for a new encryption level
 * This is called when TLS provides new secrets (e.g., after ClientHello/ServerHello)
 */
int tquic_crypto_install_keys(struct tquic_crypto_state *crypto,
			      enum tquic_enc_level level,
			      const u8 *read_secret, size_t read_secret_len,
			      const u8 *write_secret, size_t write_secret_len)
{
	struct tquic_keys *read_keys = &crypto->read_keys[level];
	struct tquic_keys *write_keys = &crypto->write_keys[level];
	int ret;

	if (!crypto || level >= TQUIC_ENC_LEVEL_COUNT)
		return -EINVAL;

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

		ret = tquic_derive_keys(crypto, read_keys);
		if (ret)
			return ret;
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

		ret = tquic_derive_keys(crypto, write_keys);
		if (ret)
			return ret;
	}

	/* Set up HP keys for this level */
	ret = tquic_setup_hp_keys(crypto, level);
	if (ret)
		return ret;

	pr_debug("tquic_crypto: installed keys for level %d\n", level);

	return 0;
}
EXPORT_SYMBOL_GPL(tquic_crypto_install_keys);

MODULE_DESCRIPTION("TQUIC TLS 1.3 Crypto Integration");
MODULE_LICENSE("GPL");
