/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * TQUIC: QUIC Load Balancing Support
 *
 * Copyright (c) 2026 Linux Foundation
 *
 * Implementation of QUIC-LB (draft-ietf-quic-load-balancers) for
 * server ID encoding in connection IDs to enable stateless load balancing.
 */

#ifndef _TQUIC_QUIC_LB_H
#define _TQUIC_QUIC_LB_H

#include <linux/types.h>
#include <linux/spinlock.h>
#include <crypto/aes.h>
#include <crypto/skcipher.h>

/* QUIC-LB configuration rotation codepoints (3 bits, 0-6, 7 reserved) */
#define TQUIC_LB_CONFIG_ROTATION_MASK	0xE0
#define TQUIC_LB_CONFIG_ROTATION_SHIFT	5
#define TQUIC_LB_CONFIG_ROTATION_MAX	6
#define TQUIC_LB_CONFIG_ROTATION_RESERVED 7

/* Length self-description (5 bits) */
#define TQUIC_LB_LENGTH_SELF_DESC_MASK	0x1F

/* Server ID constraints */
#define TQUIC_LB_SERVER_ID_MIN_LEN	1
#define TQUIC_LB_SERVER_ID_MAX_LEN	15

/* Nonce constraints */
#define TQUIC_LB_NONCE_MIN_LEN		4
#define TQUIC_LB_NONCE_MAX_LEN		18

/* Total CID constraint: server_id + nonce <= 19 */
#define TQUIC_LB_CID_PAYLOAD_MAX	19

/* AES block size for encryption */
#define TQUIC_LB_AES_BLOCK_SIZE		16

/**
 * enum tquic_lb_mode - QUIC-LB CID encoding modes
 * @TQUIC_LB_MODE_PLAINTEXT: Server ID visible in CID
 * @TQUIC_LB_MODE_SINGLE_PASS: AES-128-ECB when server_id + nonce = 16
 * @TQUIC_LB_MODE_FOUR_PASS: Feistel network for other lengths
 */
enum tquic_lb_mode {
	TQUIC_LB_MODE_PLAINTEXT = 0,
	TQUIC_LB_MODE_SINGLE_PASS,
	TQUIC_LB_MODE_FOUR_PASS,
};

/**
 * struct tquic_lb_config - QUIC-LB configuration
 * @config_rotation: 3-bit codepoint (0-6)
 * @server_id_len: Server ID length (1-15 bytes)
 * @nonce_len: Nonce length (4-18 bytes)
 * @server_id: Server identifier
 * @encryption_key: AES-128-ECB key (NULL for plaintext mode)
 * @mode: Encoding mode (plaintext, single-pass, four-pass)
 * @aes_tfm: AES ECB skcipher transform for encryption (kernel 6.12+ API)
 * @nonce_counter: Counter for nonce generation
 * @lock: Spinlock for thread safety
 */
struct tquic_lb_config {
	u8 config_rotation;
	u8 server_id_len;
	u8 nonce_len;
	u8 server_id[TQUIC_LB_SERVER_ID_MAX_LEN];
	u8 encryption_key[TQUIC_LB_AES_BLOCK_SIZE];
	enum tquic_lb_mode mode;
	struct crypto_sync_skcipher *aes_tfm;
	u64 nonce_counter;
	spinlock_t lock;
};

/**
 * struct tquic_lb_cid - Encoded QUIC-LB connection ID
 * @first_octet: config_rotation | length_self_desc
 * @payload: Encoded server_id + nonce
 * @cid: Complete connection ID
 * @cid_len: Total CID length
 */
struct tquic_lb_cid {
	u8 first_octet;
	u8 payload[TQUIC_LB_CID_PAYLOAD_MAX];
	u8 cid[20];
	u8 cid_len;
};

/**
 * struct tquic_lb_decoded - Decoded server information from CID
 * @config_rotation: Configuration codepoint
 * @server_id: Extracted server ID
 * @server_id_len: Server ID length
 * @valid: Whether decoding was successful
 */
struct tquic_lb_decoded {
	u8 config_rotation;
	u8 server_id[TQUIC_LB_SERVER_ID_MAX_LEN];
	u8 server_id_len;
	bool valid;
};

/* Configuration management */
struct tquic_lb_config *tquic_lb_config_create(u8 config_rotation,
					       const u8 *server_id,
					       u8 server_id_len,
					       u8 nonce_len,
					       const u8 *encryption_key);
void tquic_lb_config_destroy(struct tquic_lb_config *cfg);

/* CID encoding/decoding */
int tquic_lb_encode_cid(struct tquic_lb_config *cfg,
			struct tquic_lb_cid *cid);
int tquic_lb_decode_cid(struct tquic_lb_config *cfg,
			const u8 *cid, size_t cid_len,
			struct tquic_lb_decoded *decoded);

/* Nonce management */
int tquic_lb_generate_nonce(struct tquic_lb_config *cfg,
			    u8 *nonce, size_t nonce_len);

/* Encryption helpers */
int tquic_lb_encrypt_single_pass(struct tquic_lb_config *cfg,
				 const u8 *plaintext, u8 *ciphertext);
int tquic_lb_decrypt_single_pass(struct tquic_lb_config *cfg,
				 const u8 *ciphertext, u8 *plaintext);
int tquic_lb_encrypt_four_pass(struct tquic_lb_config *cfg,
			       const u8 *plaintext, size_t len,
			       u8 *ciphertext);
int tquic_lb_decrypt_four_pass(struct tquic_lb_config *cfg,
			       const u8 *ciphertext, size_t len,
			       u8 *plaintext);

/* Module init/exit */
int __init tquic_lb_init(void);
void __exit tquic_lb_exit(void);

#endif /* _TQUIC_QUIC_LB_H */
