/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * TQUIC: QUIC Header Protection API (RFC 9001 Section 5.4)
 *
 * Copyright (c) 2026 Justin Adams <spotty118@gmail.com>
 * Kernel implementation by Justin Adams <spotty118@gmail.com>
 *
 * Public interface for QUIC header protection operations.
 */

#ifndef _TQUIC_HEADER_PROTECTION_H
#define _TQUIC_HEADER_PROTECTION_H

#include <linux/types.h>
#include <linux/spinlock.h>
#include <crypto/skcipher.h>

/* Header protection sample and mask lengths (RFC 9001) */
#define TQUIC_HP_SAMPLE_LEN		16	/* Sample length for HP */
#define TQUIC_HP_MASK_LEN		5	/* Mask length */
#define TQUIC_MAX_PN_LEN		4	/* Maximum packet number length */
#define TQUIC_MIN_PN_LEN		1	/* Minimum packet number length */

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
 * @req: Pre-allocated skcipher request
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
 * @next_read_key: Next key phase read key (for key update)
 * @next_write_key: Next key phase write key (for key update)
 * @key_update_pending: Whether a key update is in progress
 * @lock: Protects all fields in this structure
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

/*
 * Header Protection API
 */

/* Context lifecycle */
struct tquic_hp_ctx *tquic_hp_ctx_alloc(void);
void tquic_hp_ctx_free(struct tquic_hp_ctx *ctx);

/* Key management */
int tquic_hp_set_key(struct tquic_hp_ctx *ctx, enum tquic_hp_enc_level level,
		     int direction, const u8 *key, size_t key_len, u16 cipher);
void tquic_hp_clear_key(struct tquic_hp_ctx *ctx,
			enum tquic_hp_enc_level level, int direction);
void tquic_hp_set_level(struct tquic_hp_ctx *ctx,
			enum tquic_hp_enc_level read_level,
			enum tquic_hp_enc_level write_level);
bool tquic_hp_has_key(struct tquic_hp_ctx *ctx, enum tquic_hp_enc_level level,
		      int direction);

/* Key phase for 1-RTT packets */
u8 tquic_hp_get_key_phase(struct tquic_hp_ctx *ctx);
void tquic_hp_set_key_phase(struct tquic_hp_ctx *ctx, u8 phase);

/* Key update support */
int tquic_hp_set_next_key(struct tquic_hp_ctx *ctx, int direction,
			  const u8 *key, size_t key_len, u16 cipher);
void tquic_hp_rotate_keys(struct tquic_hp_ctx *ctx);

/* Packet protection/unprotection */
int tquic_hp_protect(struct tquic_hp_ctx *ctx, u8 *packet,
		     size_t packet_len, size_t pn_offset);
int tquic_hp_unprotect(struct tquic_hp_ctx *ctx, u8 *packet,
		       size_t packet_len, size_t pn_offset,
		       u8 *pn_len, u8 *key_phase);

/* Long header packet protection */
int tquic_hp_protect_long(struct tquic_hp_ctx *ctx, u8 *packet,
			  size_t packet_len, size_t pn_offset,
			  enum tquic_hp_enc_level level);
int tquic_hp_unprotect_long(struct tquic_hp_ctx *ctx, u8 *packet,
			    size_t packet_len, size_t pn_offset,
			    enum tquic_hp_enc_level level, u8 *pn_len);

/* Short header packet protection */
int tquic_hp_protect_short(struct tquic_hp_ctx *ctx, u8 *packet,
			   size_t packet_len, size_t pn_offset);
int tquic_hp_unprotect_short(struct tquic_hp_ctx *ctx, u8 *packet,
			     size_t packet_len, size_t pn_offset,
			     u8 *pn_len, u8 *key_phase);

/* Sample extraction */
int tquic_hp_extract_sample(const u8 *packet, size_t packet_len,
			    size_t pn_offset, u8 *sample);

/* Packet number utilities */
int tquic_hp_detect_pn_length(u8 first_byte);
u64 tquic_hp_decode_pn(u64 truncated_pn, u8 pn_len, u64 largest_pn);
u8 tquic_hp_encode_pn_length(u64 pn, u64 largest_acked);
u64 tquic_hp_read_pn(const u8 *packet, u8 pn_len);
void tquic_hp_write_pn(u8 *packet, u64 pn, u8 pn_len);

/*
 * Crypto state integration
 */

/* Forward declaration */
struct tquic_crypto_state;

/* Get HP context from crypto state (defined in crypto/tls.c) */
struct tquic_hp_ctx *tquic_crypto_get_hp_ctx(struct tquic_crypto_state *crypto);

#endif /* _TQUIC_HEADER_PROTECTION_H */
