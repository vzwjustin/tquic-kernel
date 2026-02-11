// SPDX-License-Identifier: GPL-2.0-only
/*
 * TQUIC: QUIC Header Protection (RFC 9001 Section 5.4)
 *
 * Copyright (c) 2026 Linux Foundation
 * Kernel implementation by Justin Adams <spotty118@gmail.com>
 *
 * Implements QUIC header protection using AES-ECB or ChaCha20 to generate
 * masks for protecting/unprotecting packet headers. This prevents middleboxes
 * from observing packet numbers and certain header fields.
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/err.h>
#include <crypto/skcipher.h>
#include <crypto/aes.h>
#include <crypto/chacha.h>
#include <linux/unaligned.h>
#include <net/tquic.h>

#include "../tquic_debug.h"

/* Header protection constants per RFC 9001 */
#define TQUIC_HP_SAMPLE_LEN		16	/* Sample length for HP */
#define TQUIC_HP_MASK_LEN		5	/* Mask length (1 byte header + 4 bytes PN) */
#define TQUIC_MAX_PN_LEN		4	/* Maximum packet number length */
#define TQUIC_MIN_PN_LEN		1	/* Minimum packet number length */

/* QUIC header form bit */
#define TQUIC_HEADER_FORM_BIT		0x80	/* 1 = Long, 0 = Short */
#define TQUIC_HEADER_FIXED_BIT		0x40	/* Fixed bit (always 1) */

/* Long header type mask (2 bits) */
#define TQUIC_LONG_HEADER_TYPE_MASK	0x30
#define TQUIC_LONG_HEADER_PN_LEN_MASK	0x03	/* Lower 2 bits encode PN length - 1 */

/* Short header masks */
#define TQUIC_SHORT_HEADER_SPIN_BIT	0x20	/* Spin bit for latency measurement */
#define TQUIC_SHORT_HEADER_RESERVED	0x18	/* Reserved bits */
#define TQUIC_SHORT_HEADER_KEY_PHASE	0x04	/* Key phase bit */
#define TQUIC_SHORT_HEADER_PN_LEN_MASK	0x03	/* Lower 2 bits encode PN length - 1 */

/* Long header packet types */
#define TQUIC_LONG_TYPE_INITIAL		0x00
#define TQUIC_LONG_TYPE_0RTT		0x01
#define TQUIC_LONG_TYPE_HANDSHAKE	0x02
#define TQUIC_LONG_TYPE_RETRY		0x03

/* Cipher suite identifiers for HP */
#define TQUIC_HP_CIPHER_AES_128		0
#define TQUIC_HP_CIPHER_AES_256		1
#define TQUIC_HP_CIPHER_CHACHA20	2

/* Encryption levels matching tls.c */
enum tquic_hp_enc_level {
	TQUIC_HP_LEVEL_INITIAL = 0,
	TQUIC_HP_LEVEL_HANDSHAKE,
	TQUIC_HP_LEVEL_APPLICATION,
	TQUIC_HP_LEVEL_COUNT,
};

/**
 * struct tquic_hp_key - Header protection key for one direction
 * @key: The HP key material
 * @key_len: Length of the HP key (16 or 32 bytes)
 * @cipher_type: Type of cipher (AES-128, AES-256, or ChaCha20)
 * @valid: Whether this key has been set
 * @tfm: AES cipher transform (NULL for ChaCha20)
 */
struct tquic_hp_key {
	u8 key[32];		/* Max key size for AES-256/ChaCha20 */
	u32 key_len;
	u8 cipher_type;
	bool valid;
	struct crypto_skcipher *tfm;	/* For AES-ECB */
	struct skcipher_request *req;	/* Pre-allocated request */
};

/**
 * struct tquic_hp_ctx - Header protection context per connection
 * @read_keys: HP keys for decryption (per encryption level)
 * @write_keys: HP keys for encryption (per encryption level)
 * @current_read_level: Current encryption level for reading
 * @current_write_level: Current encryption level for writing
 * @key_phase: Current key phase for 1-RTT packets
 * @next_key_phase: Next key phase keys (for key update)
 * @lock: Spinlock for thread safety
 */
struct tquic_hp_ctx {
	struct tquic_hp_key read_keys[TQUIC_HP_LEVEL_COUNT];
	struct tquic_hp_key write_keys[TQUIC_HP_LEVEL_COUNT];
	enum tquic_hp_enc_level current_read_level;
	enum tquic_hp_enc_level current_write_level;

	/* Key phase handling for 1-RTT packets */
	u8 key_phase;
	struct tquic_hp_key next_read_key;	/* For key update */
	struct tquic_hp_key next_write_key;
	bool key_update_pending;

	spinlock_t lock;
};

/* Forward declarations to silence -Wmissing-prototypes */
int tquic_hp_extract_sample(const u8 *packet, size_t packet_len,
			    size_t pn_offset, u8 *sample);
int tquic_hp_detect_pn_length(u8 first_byte);
int tquic_hp_protect_long(struct tquic_hp_ctx *ctx, u8 *packet,
			  size_t packet_len, size_t pn_offset,
			  enum tquic_hp_enc_level level);
int tquic_hp_unprotect_long(struct tquic_hp_ctx *ctx, u8 *packet,
			    size_t packet_len, size_t pn_offset,
			    enum tquic_hp_enc_level level, u8 *pn_len);
int tquic_hp_protect_short(struct tquic_hp_ctx *ctx, u8 *packet,
			   size_t packet_len, size_t pn_offset);
int tquic_hp_unprotect_short(struct tquic_hp_ctx *ctx, u8 *packet,
			     size_t packet_len, size_t pn_offset,
			     u8 *pn_len, u8 *key_phase);
u8 tquic_hp_get_key_phase(struct tquic_hp_ctx *ctx);
void tquic_hp_set_key_phase(struct tquic_hp_ctx *ctx, u8 phase);
int tquic_hp_set_key(struct tquic_hp_ctx *ctx, enum tquic_hp_enc_level level,
		     int direction, const u8 *key, size_t key_len, u16 cipher);
void tquic_hp_clear_key(struct tquic_hp_ctx *ctx,
			enum tquic_hp_enc_level level, int direction);
int tquic_hp_set_next_key(struct tquic_hp_ctx *ctx, int direction,
			  const u8 *key, size_t key_len, u16 cipher);
void tquic_hp_rotate_keys(struct tquic_hp_ctx *ctx);
u64 tquic_hp_decode_pn(u64 truncated_pn, u8 pn_len, u64 largest_pn);
u8 tquic_hp_encode_pn_length(u64 pn, u64 largest_acked);
u64 tquic_hp_read_pn(const u8 *packet, u8 pn_len);
void tquic_hp_write_pn(u8 *packet, u64 pn, u8 pn_len);
void tquic_hp_set_level(struct tquic_hp_ctx *ctx,
			enum tquic_hp_enc_level read_level,
			enum tquic_hp_enc_level write_level);
struct tquic_hp_ctx *tquic_hp_ctx_alloc(void);
void tquic_hp_ctx_free(struct tquic_hp_ctx *ctx);
int tquic_hp_protect(struct tquic_hp_ctx *ctx, u8 *packet,
		     size_t packet_len, size_t pn_offset);
int tquic_hp_unprotect(struct tquic_hp_ctx *ctx, u8 *packet,
		       size_t packet_len, size_t pn_offset,
		       u8 *pn_len, u8 *key_phase);
bool tquic_hp_has_key(struct tquic_hp_ctx *ctx, enum tquic_hp_enc_level level,
		      int direction);

/*
 * Generate HP mask using AES-ECB
 *
 * Per RFC 9001 Section 5.4.3:
 * mask = AES-ECB(hp_key, sample)
 * Only the first 5 bytes of the output are used
 */
static int tquic_hp_mask_aes(struct tquic_hp_key *hp_key,
			     const u8 *sample, u8 *mask)
{
	struct skcipher_request *req;
	struct scatterlist sg_in, sg_out;
	u8 ecb_output[AES_BLOCK_SIZE];
	DECLARE_CRYPTO_WAIT(wait);
	int ret;

	if (!hp_key->tfm)
		return -EINVAL;

	/* Use pre-allocated request if available, else fall back */
	req = hp_key->req;
	if (!req) {
		req = skcipher_request_alloc(hp_key->tfm, GFP_ATOMIC);
		if (!req)
			return -ENOMEM;
	}

	/* Set up scatterlists for single block encryption */
	sg_init_one(&sg_in, sample, AES_BLOCK_SIZE);
	sg_init_one(&sg_out, ecb_output, AES_BLOCK_SIZE);

	skcipher_request_set_callback(req, CRYPTO_TFM_REQ_MAY_BACKLOG,
				      crypto_req_done, &wait);
	skcipher_request_set_crypt(req, &sg_in, &sg_out, AES_BLOCK_SIZE, NULL);

	ret = crypto_wait_req(crypto_skcipher_encrypt(req), &wait);
	if (ret == 0) {
		/* Copy first 5 bytes as mask */
		memcpy(mask, ecb_output, TQUIC_HP_MASK_LEN);
	}

	if (req != hp_key->req)
		skcipher_request_free(req);
	memzero_explicit(ecb_output, sizeof(ecb_output));

	return ret;
}

/*
 * Generate HP mask using ChaCha20
 *
 * Per RFC 9001 Section 5.4.4:
 * counter = sample[0..3]
 * nonce = sample[4..15]
 * mask = ChaCha20(hp_key, counter, nonce, {0,0,0,0,0})
 *
 * Uses the pre-allocated cipher transform from hp_key->tfm for
 * performance and to avoid sleeping allocations in atomic context.
 */
static int tquic_hp_mask_chacha20(struct tquic_hp_key *hp_key,
				  const u8 *sample, u8 *mask)
{
	struct skcipher_request *req;
	struct scatterlist sg;
	u8 zeros[TQUIC_HP_MASK_LEN] = {0};
	DECLARE_CRYPTO_WAIT(wait);
	int ret;

	if (!hp_key->tfm)
		return -EINVAL;

	/* Use pre-allocated request if available, else fall back */
	req = hp_key->req;
	if (!req) {
		req = skcipher_request_alloc(hp_key->tfm, GFP_ATOMIC);
		if (!req)
			return -ENOMEM;
	}

	sg_init_one(&sg, zeros, TQUIC_HP_MASK_LEN);
	skcipher_request_set_callback(req, CRYPTO_TFM_REQ_MAY_BACKLOG,
				      crypto_req_done, &wait);
	skcipher_request_set_crypt(req, &sg, &sg, TQUIC_HP_MASK_LEN,
				   (u8 *)sample);

	ret = crypto_wait_req(crypto_skcipher_encrypt(req), &wait);
	if (ret == 0)
		memcpy(mask, zeros, TQUIC_HP_MASK_LEN);

	if (req != hp_key->req)
		skcipher_request_free(req);

	return ret;
}

/**
 * tquic_hp_generate_mask - Generate header protection mask
 * @hp_key: Header protection key
 * @sample: 16-byte sample from ciphertext
 * @mask: Output buffer for 5-byte mask
 *
 * Returns 0 on success, negative error code on failure.
 */
static int tquic_hp_generate_mask(struct tquic_hp_key *hp_key,
				  const u8 *sample, u8 *mask)
{
	if (!hp_key->valid)
		return -EINVAL;

	switch (hp_key->cipher_type) {
	case TQUIC_HP_CIPHER_AES_128:
	case TQUIC_HP_CIPHER_AES_256:
		return tquic_hp_mask_aes(hp_key, sample, mask);
	case TQUIC_HP_CIPHER_CHACHA20:
		return tquic_hp_mask_chacha20(hp_key, sample, mask);
	default:
		return -EINVAL;
	}
}

/**
 * tquic_hp_extract_sample - Extract sample from encrypted packet
 * @packet: Pointer to the full QUIC packet
 * @packet_len: Length of the packet
 * @pn_offset: Offset to the packet number field
 * @sample: Output buffer for 16-byte sample
 *
 * Per RFC 9001 Section 5.4.2, the sample is taken starting 4 bytes after
 * the start of the Packet Number field (assuming 4-byte PN).
 *
 * Returns 0 on success, -EINVAL if packet is too short.
 */
int tquic_hp_extract_sample(const u8 *packet, size_t packet_len,
			    size_t pn_offset, u8 *sample)
{
	size_t sample_offset;

	/*
	 * Sample starts 4 bytes after pn_offset (assuming max PN length)
	 * This ensures we sample from ciphertext, not the PN itself
	 */
	sample_offset = pn_offset + TQUIC_MAX_PN_LEN;

	if (sample_offset + TQUIC_HP_SAMPLE_LEN > packet_len)
		return -EINVAL;

	memcpy(sample, packet + sample_offset, TQUIC_HP_SAMPLE_LEN);
	return 0;
}
EXPORT_SYMBOL_GPL(tquic_hp_extract_sample);

/**
 * tquic_hp_detect_pn_length - Detect packet number length from protected header
 * @first_byte: The (unprotected) first byte of the header
 *
 * The packet number length is encoded in the lower 2 bits of the first byte
 * as (length - 1), so:
 *   0b00 = 1 byte, 0b01 = 2 bytes, 0b10 = 3 bytes, 0b11 = 4 bytes
 *
 * Returns the packet number length (1-4).
 */
int tquic_hp_detect_pn_length(u8 first_byte)
{
	return (first_byte & TQUIC_SHORT_HEADER_PN_LEN_MASK) + 1;
}
EXPORT_SYMBOL_GPL(tquic_hp_detect_pn_length);

/**
 * tquic_hp_is_long_header - Check if packet has long header
 * @first_byte: First byte of the packet
 *
 * Returns true if this is a long header packet.
 */
static inline bool tquic_hp_is_long_header(u8 first_byte)
{
	return (first_byte & TQUIC_HEADER_FORM_BIT) != 0;
}

/**
 * tquic_hp_get_long_header_type - Get long header packet type
 * @first_byte: First byte of the packet (unprotected)
 *
 * Returns the packet type (0-3).
 */
static inline u8 tquic_hp_get_long_header_type(u8 first_byte)
{
	return (first_byte & TQUIC_LONG_HEADER_TYPE_MASK) >> 4;
}

/*
 * Apply/remove header protection for long header packets
 *
 * Per RFC 9001 Section 5.4.1:
 * - Bits 0x0f of the first byte are protected (packet type + reserved + PN length)
 * - Packet number bytes are XORed with mask[1..4]
 */
static int tquic_hp_process_long_header(u8 *packet, size_t packet_len,
					size_t pn_offset, const u8 *mask,
					bool protect)
{
	u8 pn_len;
	int i;

	/* Protect/unprotect first byte: XOR lower 4 bits with mask[0] */
	packet[0] ^= (mask[0] & 0x0f);

	/*
	 * For protection: PN length was already encoded before HP
	 * For unprotection: We can now read the PN length
	 */
	pn_len = tquic_hp_detect_pn_length(packet[0]);

	if (pn_offset + pn_len > packet_len)
		return -EINVAL;

	/* XOR packet number bytes with mask[1..pn_len] */
	for (i = 0; i < pn_len; i++)
		packet[pn_offset + i] ^= mask[1 + i];

	return 0;
}

/*
 * Apply/remove header protection for short header packets
 *
 * Per RFC 9001 Section 5.4.1:
 * - Bits 0x1f of the first byte are protected (spin + reserved + key phase + PN length)
 * - Packet number bytes are XORed with mask[1..4]
 */
static int tquic_hp_process_short_header(u8 *packet, size_t packet_len,
					 size_t pn_offset, const u8 *mask,
					 bool protect)
{
	u8 pn_len;
	int i;

	/* Protect/unprotect first byte: XOR lower 5 bits with mask[0] */
	packet[0] ^= (mask[0] & 0x1f);

	/* Get packet number length from (now readable) first byte */
	pn_len = tquic_hp_detect_pn_length(packet[0]);

	if (pn_offset + pn_len > packet_len)
		return -EINVAL;

	/* XOR packet number bytes with mask[1..pn_len] */
	for (i = 0; i < pn_len; i++)
		packet[pn_offset + i] ^= mask[1 + i];

	return 0;
}

/**
 * tquic_hp_protect_long - Apply header protection to a long header packet
 * @ctx: Header protection context
 * @packet: Packet buffer (modified in place)
 * @packet_len: Length of the packet
 * @pn_offset: Offset to the packet number field
 * @level: Encryption level for key selection
 *
 * Returns 0 on success, negative error code on failure.
 */
int tquic_hp_protect_long(struct tquic_hp_ctx *ctx, u8 *packet,
			  size_t packet_len, size_t pn_offset,
			  enum tquic_hp_enc_level level)
{
	struct tquic_hp_key *hp_key;
	u8 sample[TQUIC_HP_SAMPLE_LEN];
	u8 mask[TQUIC_HP_MASK_LEN];
	int ret;

	if (!ctx || level >= TQUIC_HP_LEVEL_COUNT)
		return -EINVAL;

	hp_key = &ctx->write_keys[level];
	if (!hp_key->valid)
		return -ENOKEY;

	/* Extract sample from ciphertext */
	ret = tquic_hp_extract_sample(packet, packet_len, pn_offset, sample);
	if (ret)
		return ret;

	/* Generate mask */
	ret = tquic_hp_generate_mask(hp_key, sample, mask);
	if (ret)
		return ret;

	/* Apply protection */
	ret = tquic_hp_process_long_header(packet, packet_len, pn_offset,
					   mask, true);

	memzero_explicit(mask, sizeof(mask));
	return ret;
}
EXPORT_SYMBOL_GPL(tquic_hp_protect_long);

/**
 * tquic_hp_unprotect_long - Remove header protection from a long header packet
 * @ctx: Header protection context
 * @packet: Packet buffer (modified in place)
 * @packet_len: Length of the packet
 * @pn_offset: Offset to the packet number field
 * @level: Encryption level for key selection
 * @pn_len: Output: detected packet number length
 *
 * Returns 0 on success, negative error code on failure.
 */
int tquic_hp_unprotect_long(struct tquic_hp_ctx *ctx, u8 *packet,
			    size_t packet_len, size_t pn_offset,
			    enum tquic_hp_enc_level level, u8 *pn_len)
{
	struct tquic_hp_key *hp_key;
	u8 sample[TQUIC_HP_SAMPLE_LEN];
	u8 mask[TQUIC_HP_MASK_LEN];
	int ret;

	if (!ctx || level >= TQUIC_HP_LEVEL_COUNT)
		return -EINVAL;

	hp_key = &ctx->read_keys[level];
	if (!hp_key->valid)
		return -ENOKEY;

	/* Extract sample from ciphertext */
	ret = tquic_hp_extract_sample(packet, packet_len, pn_offset, sample);
	if (ret)
		return ret;

	/* Generate mask */
	ret = tquic_hp_generate_mask(hp_key, sample, mask);
	if (ret)
		return ret;

	/* Remove protection */
	ret = tquic_hp_process_long_header(packet, packet_len, pn_offset,
					   mask, false);
	if (ret == 0 && pn_len)
		*pn_len = tquic_hp_detect_pn_length(packet[0]);

	memzero_explicit(mask, sizeof(mask));
	return ret;
}
EXPORT_SYMBOL_GPL(tquic_hp_unprotect_long);

/**
 * tquic_hp_protect_short - Apply header protection to a short header packet
 * @ctx: Header protection context
 * @packet: Packet buffer (modified in place)
 * @packet_len: Length of the packet
 * @pn_offset: Offset to the packet number field
 *
 * Short headers always use application-level keys.
 *
 * Returns 0 on success, negative error code on failure.
 */
int tquic_hp_protect_short(struct tquic_hp_ctx *ctx, u8 *packet,
			   size_t packet_len, size_t pn_offset)
{
	struct tquic_hp_key *hp_key;
	u8 sample[TQUIC_HP_SAMPLE_LEN];
	u8 mask[TQUIC_HP_MASK_LEN];
	int ret;

	if (!ctx)
		return -EINVAL;

	hp_key = &ctx->write_keys[TQUIC_HP_LEVEL_APPLICATION];
	if (!hp_key->valid)
		return -ENOKEY;

	/* Extract sample from ciphertext */
	ret = tquic_hp_extract_sample(packet, packet_len, pn_offset, sample);
	if (ret)
		return ret;

	/* Generate mask */
	ret = tquic_hp_generate_mask(hp_key, sample, mask);
	if (ret)
		return ret;

	/* Apply protection */
	ret = tquic_hp_process_short_header(packet, packet_len, pn_offset,
					    mask, true);

	memzero_explicit(mask, sizeof(mask));
	return ret;
}
EXPORT_SYMBOL_GPL(tquic_hp_protect_short);

/**
 * tquic_hp_unprotect_short - Remove header protection from a short header packet
 * @ctx: Header protection context
 * @packet: Packet buffer (modified in place)
 * @packet_len: Length of the packet
 * @pn_offset: Offset to the packet number field
 * @pn_len: Output: detected packet number length
 * @key_phase: Output: key phase bit value
 *
 * Returns 0 on success, negative error code on failure.
 */
int tquic_hp_unprotect_short(struct tquic_hp_ctx *ctx, u8 *packet,
			     size_t packet_len, size_t pn_offset,
			     u8 *pn_len, u8 *key_phase)
{
	struct tquic_hp_key *hp_key;
	u8 sample[TQUIC_HP_SAMPLE_LEN];
	u8 mask[TQUIC_HP_MASK_LEN];
	int ret;

	if (!ctx)
		return -EINVAL;

	hp_key = &ctx->read_keys[TQUIC_HP_LEVEL_APPLICATION];
	if (!hp_key->valid)
		return -ENOKEY;

	/* Extract sample from ciphertext */
	ret = tquic_hp_extract_sample(packet, packet_len, pn_offset, sample);
	if (ret)
		return ret;

	/* Generate mask */
	ret = tquic_hp_generate_mask(hp_key, sample, mask);
	if (ret)
		return ret;

	/* Remove protection */
	ret = tquic_hp_process_short_header(packet, packet_len, pn_offset,
					    mask, false);
	if (ret == 0) {
		if (pn_len)
			*pn_len = tquic_hp_detect_pn_length(packet[0]);
		if (key_phase)
			*key_phase = (packet[0] & TQUIC_SHORT_HEADER_KEY_PHASE) ? 1 : 0;
	}

	memzero_explicit(mask, sizeof(mask));
	return ret;
}
EXPORT_SYMBOL_GPL(tquic_hp_unprotect_short);

/**
 * tquic_hp_get_key_phase - Get current key phase value
 * @ctx: Header protection context
 *
 * Returns the current key phase (0 or 1).
 */
u8 tquic_hp_get_key_phase(struct tquic_hp_ctx *ctx)
{
	return ctx ? ctx->key_phase : 0;
}
EXPORT_SYMBOL_GPL(tquic_hp_get_key_phase);

/**
 * tquic_hp_set_key_phase - Set the current key phase
 * @ctx: Header protection context
 * @phase: New key phase value (0 or 1)
 */
void tquic_hp_set_key_phase(struct tquic_hp_ctx *ctx, u8 phase)
{
	unsigned long flags;

	if (!ctx)
		return;

	spin_lock_irqsave(&ctx->lock, flags);
	ctx->key_phase = phase & 1;
	spin_unlock_irqrestore(&ctx->lock, flags);
}
EXPORT_SYMBOL_GPL(tquic_hp_set_key_phase);

/*
 * Allocate and configure cipher for header protection.
 * For AES cipher types, allocates ecb(aes).
 * For ChaCha20, allocates chacha20.
 * Must NOT be called under spinlock (may sleep).
 */
static int tquic_hp_setup_cipher(struct tquic_hp_key *hp_key)
{
	const char *alg_name;
	int ret;

	/* Free any existing transform to prevent leaks on overwrite */
	if (hp_key->req) {
		skcipher_request_free(hp_key->req);
		hp_key->req = NULL;
	}
	if (hp_key->tfm) {
		crypto_free_skcipher(hp_key->tfm);
		hp_key->tfm = NULL;
	}

	switch (hp_key->cipher_type) {
	case TQUIC_HP_CIPHER_AES_128:
	case TQUIC_HP_CIPHER_AES_256:
		alg_name = "ecb(aes)";
		break;
	case TQUIC_HP_CIPHER_CHACHA20:
		alg_name = "chacha20";
		break;
	default:
		return -EINVAL;
	}

	hp_key->tfm = crypto_alloc_skcipher(alg_name, 0, 0);
	if (IS_ERR(hp_key->tfm)) {
		ret = PTR_ERR(hp_key->tfm);
		hp_key->tfm = NULL;
		return ret;
	}

	ret = crypto_skcipher_setkey(hp_key->tfm, hp_key->key, hp_key->key_len);
	if (ret) {
		crypto_free_skcipher(hp_key->tfm);
		hp_key->tfm = NULL;
		return ret;
	}

	/* Pre-allocate skcipher request to avoid per-call GFP_ATOMIC alloc */
	hp_key->req = skcipher_request_alloc(hp_key->tfm, GFP_KERNEL);
	if (!hp_key->req) {
		crypto_free_skcipher(hp_key->tfm);
		hp_key->tfm = NULL;
		return -ENOMEM;
	}

	return 0;
}

/**
 * tquic_hp_set_key - Set header protection key for an encryption level
 * @ctx: Header protection context
 * @level: Encryption level
 * @direction: 0 = read (decrypt), 1 = write (encrypt)
 * @key: Key material
 * @key_len: Length of key (16, 32)
 * @cipher: Cipher suite (TLS_AES_128_GCM_SHA256, etc.)
 *
 * Returns 0 on success, negative error code on failure.
 */
int tquic_hp_set_key(struct tquic_hp_ctx *ctx, enum tquic_hp_enc_level level,
		     int direction, const u8 *key, size_t key_len, u16 cipher)
{
	struct tquic_hp_key *hp_key;
	struct crypto_skcipher *old_tfm;
	unsigned long flags;
	int ret = 0;

	if (!ctx || level >= TQUIC_HP_LEVEL_COUNT)
		return -EINVAL;

	if (direction)
		hp_key = &ctx->write_keys[level];
	else
		hp_key = &ctx->read_keys[level];

	/*
	 * Invalidate and save old tfm under lock, then do all sleeping
	 * operations (crypto_free, crypto_alloc) outside the lock.
	 */
	spin_lock_irqsave(&ctx->lock, flags);
	hp_key->valid = false;
	old_tfm = hp_key->tfm;
	hp_key->tfm = NULL;

	/* Determine cipher type and key length based on cipher suite */
	switch (cipher) {
	case 0x1301:  /* TLS_AES_128_GCM_SHA256 */
		if (key_len < 16) {
			ret = -EINVAL;
			goto out;
		}
		hp_key->cipher_type = TQUIC_HP_CIPHER_AES_128;
		hp_key->key_len = 16;
		memcpy(hp_key->key, key, 16);
		break;

	case 0x1302:  /* TLS_AES_256_GCM_SHA384 */
		if (key_len < 32) {
			ret = -EINVAL;
			goto out;
		}
		hp_key->cipher_type = TQUIC_HP_CIPHER_AES_256;
		hp_key->key_len = 32;
		memcpy(hp_key->key, key, 32);
		break;

	case 0x1303:  /* TLS_CHACHA20_POLY1305_SHA256 */
		if (key_len < 32) {
			ret = -EINVAL;
			goto out;
		}
		hp_key->cipher_type = TQUIC_HP_CIPHER_CHACHA20;
		hp_key->key_len = 32;
		memcpy(hp_key->key, key, 32);
		break;

	default:
		ret = -EINVAL;
		goto out;
	}
	spin_unlock_irqrestore(&ctx->lock, flags);

	/* Free old tfm outside spinlock (may sleep) */
	if (old_tfm)
		crypto_free_skcipher(old_tfm);

	/* Set up cipher transform outside spinlock (may sleep) */
	ret = tquic_hp_setup_cipher(hp_key);
	if (ret)
		return ret;

	spin_lock_irqsave(&ctx->lock, flags);
	hp_key->valid = true;
out:
	spin_unlock_irqrestore(&ctx->lock, flags);
	return ret;
}
EXPORT_SYMBOL_GPL(tquic_hp_set_key);

/**
 * tquic_hp_clear_key - Clear header protection key for an encryption level
 * @ctx: Header protection context
 * @level: Encryption level
 * @direction: 0 = read, 1 = write
 */
void tquic_hp_clear_key(struct tquic_hp_ctx *ctx, enum tquic_hp_enc_level level,
			int direction)
{
	struct tquic_hp_key *hp_key;
	struct crypto_skcipher *old_tfm;
	unsigned long flags;

	if (!ctx || level >= TQUIC_HP_LEVEL_COUNT)
		return;

	if (direction)
		hp_key = &ctx->write_keys[level];
	else
		hp_key = &ctx->read_keys[level];

	spin_lock_irqsave(&ctx->lock, flags);

	old_tfm = hp_key->tfm;
	hp_key->tfm = NULL;

	memzero_explicit(hp_key->key, sizeof(hp_key->key));
	hp_key->key_len = 0;
	hp_key->valid = false;

	spin_unlock_irqrestore(&ctx->lock, flags);

	/* Free cipher transform outside spinlock (may sleep) */
	if (old_tfm)
		crypto_free_skcipher(old_tfm);
}
EXPORT_SYMBOL_GPL(tquic_hp_clear_key);

/**
 * tquic_hp_set_next_key - Set next key for key update (key phase change)
 * @ctx: Header protection context
 * @direction: 0 = read, 1 = write
 * @key: Key material
 * @key_len: Length of key
 * @cipher: Cipher suite
 *
 * Used during key update to prepare the next key phase.
 *
 * Returns 0 on success, negative error code on failure.
 */
int tquic_hp_set_next_key(struct tquic_hp_ctx *ctx, int direction,
			  const u8 *key, size_t key_len, u16 cipher)
{
	struct tquic_hp_key *hp_key;
	struct crypto_skcipher *old_tfm;
	unsigned long flags;
	int ret = 0;

	if (!ctx)
		return -EINVAL;

	hp_key = direction ? &ctx->next_write_key : &ctx->next_read_key;

	spin_lock_irqsave(&ctx->lock, flags);

	/* Invalidate and save old tfm under lock */
	hp_key->valid = false;
	old_tfm = hp_key->tfm;
	hp_key->tfm = NULL;

	/* Set up key based on cipher suite */
	switch (cipher) {
	case 0x1301:  /* TLS_AES_128_GCM_SHA256 */
		if (key_len < 16) {
			ret = -EINVAL;
			goto out;
		}
		hp_key->cipher_type = TQUIC_HP_CIPHER_AES_128;
		hp_key->key_len = 16;
		memcpy(hp_key->key, key, 16);
		break;

	case 0x1302:  /* TLS_AES_256_GCM_SHA384 */
		if (key_len < 32) {
			ret = -EINVAL;
			goto out;
		}
		hp_key->cipher_type = TQUIC_HP_CIPHER_AES_256;
		hp_key->key_len = 32;
		memcpy(hp_key->key, key, 32);
		break;

	case 0x1303:  /* TLS_CHACHA20_POLY1305_SHA256 */
		if (key_len < 32) {
			ret = -EINVAL;
			goto out;
		}
		hp_key->cipher_type = TQUIC_HP_CIPHER_CHACHA20;
		hp_key->key_len = 32;
		memcpy(hp_key->key, key, 32);
		break;

	default:
		ret = -EINVAL;
		goto out;
	}
	spin_unlock_irqrestore(&ctx->lock, flags);

	/* Free old tfm outside spinlock (may sleep) */
	if (old_tfm)
		crypto_free_skcipher(old_tfm);

	/* Set up cipher transform outside spinlock (may sleep) */
	ret = tquic_hp_setup_cipher(hp_key);
	if (ret)
		return ret;

	spin_lock_irqsave(&ctx->lock, flags);
	hp_key->valid = true;
	ctx->key_update_pending = true;

out:
	spin_unlock_irqrestore(&ctx->lock, flags);
	return ret;
}
EXPORT_SYMBOL_GPL(tquic_hp_set_next_key);

/**
 * tquic_hp_rotate_keys - Rotate to next key phase
 * @ctx: Header protection context
 *
 * Swaps current application keys with next keys after key update completes.
 */
void tquic_hp_rotate_keys(struct tquic_hp_ctx *ctx)
{
	struct tquic_hp_key tmp;
	unsigned long flags;

	if (!ctx)
		return;

	spin_lock_irqsave(&ctx->lock, flags);

	if (!ctx->key_update_pending)
		goto out;

	/* Rotate read key - zeroize old key material */
	tmp = ctx->read_keys[TQUIC_HP_LEVEL_APPLICATION];
	ctx->read_keys[TQUIC_HP_LEVEL_APPLICATION] = ctx->next_read_key;
	memzero_explicit(tmp.key, sizeof(tmp.key));
	ctx->next_read_key = tmp;

	/* Rotate write key - zeroize old key material */
	tmp = ctx->write_keys[TQUIC_HP_LEVEL_APPLICATION];
	ctx->write_keys[TQUIC_HP_LEVEL_APPLICATION] = ctx->next_write_key;
	memzero_explicit(tmp.key, sizeof(tmp.key));
	ctx->next_write_key = tmp;

	/* Toggle key phase */
	ctx->key_phase ^= 1;
	ctx->key_update_pending = false;

out:
	spin_unlock_irqrestore(&ctx->lock, flags);
}
EXPORT_SYMBOL_GPL(tquic_hp_rotate_keys);

/**
 * tquic_hp_decode_pn - Decode truncated packet number
 * @truncated_pn: The truncated packet number from the packet
 * @pn_len: Length of the truncated packet number (1-4)
 * @largest_pn: Largest packet number received so far
 *
 * Per RFC 9000 Appendix A, reconstruct the full packet number.
 *
 * Returns the decoded full packet number.
 */
u64 tquic_hp_decode_pn(u64 truncated_pn, u8 pn_len, u64 largest_pn)
{
	u64 expected_pn = largest_pn + 1;
	u64 pn_win = 1ULL << (pn_len * 8);
	u64 pn_hwin = pn_win / 2;
	u64 pn_mask = pn_win - 1;
	u64 candidate_pn;

	/* Compute candidate based on expected and truncated */
	candidate_pn = (expected_pn & ~pn_mask) | truncated_pn;

	/*
	 * Adjust if the candidate is too far from expected.
	 * The algorithm picks the value closest to expected_pn.
	 */
	if (candidate_pn <= expected_pn - pn_hwin && candidate_pn < (1ULL << 62) - pn_win)
		return candidate_pn + pn_win;
	if (candidate_pn > expected_pn + pn_hwin && candidate_pn >= pn_win)
		return candidate_pn - pn_win;

	return candidate_pn;
}
EXPORT_SYMBOL_GPL(tquic_hp_decode_pn);

/**
 * tquic_hp_encode_pn_length - Determine minimum PN encoding length
 * @pn: Packet number to encode
 * @largest_acked: Largest acknowledged packet number
 *
 * Per RFC 9000 Section 17.1, encode PN with enough bytes so receiver
 * can unambiguously reconstruct it.
 *
 * Returns the required packet number length (1-4).
 */
u8 tquic_hp_encode_pn_length(u64 pn, u64 largest_acked)
{
	u64 num_unacked = pn - largest_acked;

	/*
	 * Encode with enough bits so the gap to the largest acked
	 * is less than half the encoding space.
	 */
	if (num_unacked < (1 << 7))
		return 1;
	if (num_unacked < (1 << 15))
		return 2;
	if (num_unacked < (1 << 23))
		return 3;
	return 4;
}
EXPORT_SYMBOL_GPL(tquic_hp_encode_pn_length);

/**
 * tquic_hp_read_pn - Read packet number from packet
 * @packet: Pointer to packet number field
 * @pn_len: Length of packet number (1-4)
 *
 * Returns the packet number value (big-endian decoding).
 */
u64 tquic_hp_read_pn(const u8 *packet, u8 pn_len)
{
	u64 pn = 0;
	int i;

	for (i = 0; i < pn_len; i++)
		pn = (pn << 8) | packet[i];

	return pn;
}
EXPORT_SYMBOL_GPL(tquic_hp_read_pn);

/**
 * tquic_hp_write_pn - Write packet number to packet
 * @packet: Pointer to packet number field
 * @pn: Packet number to write
 * @pn_len: Length to use (1-4)
 */
void tquic_hp_write_pn(u8 *packet, u64 pn, u8 pn_len)
{
	int i;

	for (i = pn_len - 1; i >= 0; i--) {
		packet[i] = pn & 0xff;
		pn >>= 8;
	}
}
EXPORT_SYMBOL_GPL(tquic_hp_write_pn);

/**
 * tquic_hp_set_level - Set current encryption level
 * @ctx: Header protection context
 * @read_level: New read encryption level
 * @write_level: New write encryption level
 */
void tquic_hp_set_level(struct tquic_hp_ctx *ctx,
			enum tquic_hp_enc_level read_level,
			enum tquic_hp_enc_level write_level)
{
	unsigned long flags;

	if (!ctx)
		return;

	spin_lock_irqsave(&ctx->lock, flags);
	if (read_level < TQUIC_HP_LEVEL_COUNT)
		ctx->current_read_level = read_level;
	if (write_level < TQUIC_HP_LEVEL_COUNT)
		ctx->current_write_level = write_level;
	spin_unlock_irqrestore(&ctx->lock, flags);
}
EXPORT_SYMBOL_GPL(tquic_hp_set_level);

/**
 * tquic_hp_ctx_alloc - Allocate header protection context
 *
 * Returns allocated context or NULL on failure.
 */
struct tquic_hp_ctx *tquic_hp_ctx_alloc(void)
{
	struct tquic_hp_ctx *ctx;

	ctx = kzalloc(sizeof(*ctx), GFP_KERNEL);
	if (!ctx)
		return NULL;

	spin_lock_init(&ctx->lock);
	ctx->current_read_level = TQUIC_HP_LEVEL_INITIAL;
	ctx->current_write_level = TQUIC_HP_LEVEL_INITIAL;
	ctx->key_phase = 0;

	return ctx;
}
EXPORT_SYMBOL_GPL(tquic_hp_ctx_alloc);

/*
 * Free a single HP key structure
 */
static void tquic_hp_free_key(struct tquic_hp_key *hp_key)
{
	if (hp_key->req) {
		skcipher_request_free(hp_key->req);
		hp_key->req = NULL;
	}
	if (hp_key->tfm) {
		crypto_free_skcipher(hp_key->tfm);
		hp_key->tfm = NULL;
	}
	memzero_explicit(hp_key->key, sizeof(hp_key->key));
	hp_key->valid = false;
}

/**
 * tquic_hp_ctx_free - Free header protection context
 * @ctx: Context to free
 */
void tquic_hp_ctx_free(struct tquic_hp_ctx *ctx)
{
	int i;

	if (!ctx)
		return;

	/* Free all keys */
	for (i = 0; i < TQUIC_HP_LEVEL_COUNT; i++) {
		tquic_hp_free_key(&ctx->read_keys[i]);
		tquic_hp_free_key(&ctx->write_keys[i]);
	}

	tquic_hp_free_key(&ctx->next_read_key);
	tquic_hp_free_key(&ctx->next_write_key);

	kfree(ctx);
}
EXPORT_SYMBOL_GPL(tquic_hp_ctx_free);

/**
 * tquic_hp_protect - Apply header protection to any packet type
 * @ctx: Header protection context
 * @packet: Packet buffer (modified in place)
 * @packet_len: Length of the packet
 * @pn_offset: Offset to the packet number field
 *
 * Automatically detects long vs short header and applies appropriate protection.
 *
 * Returns 0 on success, negative error code on failure.
 */
int tquic_hp_protect(struct tquic_hp_ctx *ctx, u8 *packet,
		     size_t packet_len, size_t pn_offset)
{
	u8 first_byte;
	enum tquic_hp_enc_level level;

	if (!ctx || !packet || packet_len == 0)
		return -EINVAL;

	first_byte = packet[0];

	if (tquic_hp_is_long_header(first_byte)) {
		/* Determine level from packet type */
		switch (tquic_hp_get_long_header_type(first_byte)) {
		case TQUIC_LONG_TYPE_INITIAL:
			level = TQUIC_HP_LEVEL_INITIAL;
			break;
		case TQUIC_LONG_TYPE_HANDSHAKE:
			level = TQUIC_HP_LEVEL_HANDSHAKE;
			break;
		case TQUIC_LONG_TYPE_0RTT:
			level = TQUIC_HP_LEVEL_APPLICATION;
			break;
		default:
			return -EINVAL;  /* Retry packets don't have HP */
		}
		return tquic_hp_protect_long(ctx, packet, packet_len,
					     pn_offset, level);
	}

	/* Short header - always application level */
	return tquic_hp_protect_short(ctx, packet, packet_len, pn_offset);
}
EXPORT_SYMBOL_GPL(tquic_hp_protect);

/**
 * tquic_hp_unprotect - Remove header protection from any packet type
 * @ctx: Header protection context
 * @packet: Packet buffer (modified in place)
 * @packet_len: Length of the packet
 * @pn_offset: Offset to the packet number field
 * @pn_len: Output: detected packet number length
 * @key_phase: Output: key phase bit (only for short headers, may be NULL)
 *
 * Automatically detects long vs short header and removes protection.
 *
 * Returns 0 on success, negative error code on failure.
 */
int tquic_hp_unprotect(struct tquic_hp_ctx *ctx, u8 *packet,
		       size_t packet_len, size_t pn_offset,
		       u8 *pn_len, u8 *key_phase)
{
	u8 first_byte_protected;
	u8 first_byte_mask_bit;
	enum tquic_hp_enc_level level;

	if (!ctx || !packet || packet_len == 0)
		return -EINVAL;

	/*
	 * We need to determine the header form from the protected first byte.
	 * The form bit (0x80) is not protected, so we can read it directly.
	 */
	first_byte_protected = packet[0];
	first_byte_mask_bit = first_byte_protected & TQUIC_HEADER_FORM_BIT;

	if (first_byte_mask_bit) {
		/* Long header - determine level from packet type */
		u8 type_bits = (first_byte_protected & TQUIC_LONG_HEADER_TYPE_MASK) >> 4;

		/*
		 * Note: For protected packets, the type bits may be obfuscated.
		 * However, the high 2 bits of the type are not protected, so we
		 * can still distinguish Initial/Handshake based on context.
		 * In practice, the receiver knows which level to expect.
		 */
		switch (type_bits) {
		case TQUIC_LONG_TYPE_INITIAL:
			level = TQUIC_HP_LEVEL_INITIAL;
			break;
		case TQUIC_LONG_TYPE_HANDSHAKE:
			level = TQUIC_HP_LEVEL_HANDSHAKE;
			break;
		case TQUIC_LONG_TYPE_0RTT:
			level = TQUIC_HP_LEVEL_APPLICATION;
			break;
		default:
			return -EINVAL;
		}

		if (key_phase)
			*key_phase = 0;  /* No key phase for long headers */

		return tquic_hp_unprotect_long(ctx, packet, packet_len,
					       pn_offset, level, pn_len);
	}

	/* Short header - application level */
	return tquic_hp_unprotect_short(ctx, packet, packet_len,
					pn_offset, pn_len, key_phase);
}
EXPORT_SYMBOL_GPL(tquic_hp_unprotect);

/**
 * tquic_hp_has_key - Check if HP key is available for a level
 * @ctx: Header protection context
 * @level: Encryption level
 * @direction: 0 = read, 1 = write
 *
 * Returns true if the key is valid and available.
 */
bool tquic_hp_has_key(struct tquic_hp_ctx *ctx, enum tquic_hp_enc_level level,
		      int direction)
{
	struct tquic_hp_key *hp_key;

	if (!ctx || level >= TQUIC_HP_LEVEL_COUNT)
		return false;

	hp_key = direction ? &ctx->write_keys[level] : &ctx->read_keys[level];
	return hp_key->valid;
}
EXPORT_SYMBOL_GPL(tquic_hp_has_key);

MODULE_DESCRIPTION("TQUIC Header Protection (RFC 9001 Section 5.4)");
MODULE_LICENSE("GPL");
MODULE_AUTHOR("Linux Foundation");
