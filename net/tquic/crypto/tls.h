/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * TQUIC: TLS/Crypto Packet Encryption Declarations
 *
 * Copyright (c) 2026 Justin Adams <spotty118@gmail.com>
 */

#ifndef _TQUIC_CRYPTO_TLS_H
#define _TQUIC_CRYPTO_TLS_H

struct tquic_crypto_state;
enum tquic_enc_level;

/* Packet encryption/decryption */
int tquic_encrypt_packet(struct tquic_crypto_state *crypto,
			 u8 *header, size_t header_len,
			 u8 *payload, size_t payload_len,
			 u64 pkt_num, u8 *out, size_t *out_len);
int tquic_decrypt_packet(struct tquic_crypto_state *crypto,
			 const u8 *header, size_t header_len,
			 u8 *payload, size_t payload_len,
			 u64 pkt_num, u8 *out, size_t *out_len);

/* Multipath packet encryption/decryption */
int tquic_encrypt_packet_multipath(struct tquic_crypto_state *crypto,
				   u8 *header, size_t header_len,
				   u8 *payload, size_t payload_len,
				   u64 pkt_num, u32 path_id,
				   u8 *out, size_t *out_len);
int tquic_decrypt_packet_multipath(struct tquic_crypto_state *crypto,
				   const u8 *header, size_t header_len,
				   u8 *payload, size_t payload_len,
				   u64 pkt_num, u32 path_id,
				   u8 *out, size_t *out_len);

/* Crypto state management */
void tquic_crypto_cleanup(struct tquic_crypto_state *crypto);
bool tquic_crypto_handshake_complete(struct tquic_crypto_state *crypto);

/* Header protection */
int tquic_crypto_protect_header(struct tquic_crypto_state *crypto,
				u8 *packet, size_t packet_len,
				size_t pn_offset);
int tquic_crypto_unprotect_header(struct tquic_crypto_state *crypto,
				  u8 *packet, size_t packet_len,
				  size_t pn_offset, u8 *pn_len,
				  u8 *key_phase);

/* Encryption level management */
void tquic_crypto_set_level(struct tquic_crypto_state *crypto,
			    enum tquic_enc_level read_level,
			    enum tquic_enc_level write_level);
int tquic_crypto_install_keys(struct tquic_crypto_state *crypto,
			      enum tquic_enc_level level,
			      const u8 *read_secret, size_t read_secret_len,
			      const u8 *write_secret, size_t write_secret_len);

/* Version management */
u32 tquic_crypto_get_version(struct tquic_crypto_state *crypto);
void tquic_crypto_set_version(struct tquic_crypto_state *crypto, u32 version);

#endif /* _TQUIC_CRYPTO_TLS_H */
