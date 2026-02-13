/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * TQUIC: TLS/Crypto Packet Encryption Declarations
 *
 * Copyright (c) 2026 Justin Adams <spotty118@gmail.com>
 */

#ifndef _TQUIC_CRYPTO_TLS_H
#define _TQUIC_CRYPTO_TLS_H

struct tquic_crypto_state;

/* Packet encryption/decryption */
int tquic_encrypt_packet(struct tquic_crypto_state *crypto,
			 const u8 *plaintext, u32 plaintext_len,
			 const u8 *header, u32 header_len,
			 u64 pn, u8 *out, u32 *out_len);
int tquic_decrypt_packet(struct tquic_crypto_state *crypto,
			 const u8 *ciphertext, u32 ciphertext_len,
			 const u8 *header, u32 header_len,
			 u64 pn, u8 *out, u32 *out_len);

/* Multipath packet encryption/decryption */
int tquic_encrypt_packet_multipath(struct tquic_crypto_state *crypto,
				   const u8 *plaintext, u32 plaintext_len,
				   const u8 *header, u32 header_len,
				   u64 pn, u32 path_id,
				   u8 *out, u32 *out_len);
int tquic_decrypt_packet_multipath(struct tquic_crypto_state *crypto,
				   const u8 *ciphertext, u32 ciphertext_len,
				   const u8 *header, u32 header_len,
				   u64 pn, u32 path_id,
				   u8 *out, u32 *out_len);

/* Crypto state management */
void tquic_crypto_cleanup(struct tquic_crypto_state *crypto);
bool tquic_crypto_handshake_complete(struct tquic_crypto_state *crypto);

/* Header protection */
int tquic_crypto_protect_header(struct tquic_crypto_state *crypto,
				u8 *header, u32 header_len,
				const u8 *sample);
int tquic_crypto_unprotect_header(struct tquic_crypto_state *crypto,
				  u8 *header, u32 header_len,
				  const u8 *sample);

/* Encryption level management */
void tquic_crypto_set_level(struct tquic_crypto_state *crypto,
			    u8 level);
int tquic_crypto_install_keys(struct tquic_crypto_state *crypto,
			      u8 level, const u8 *read_secret,
			      const u8 *write_secret, u32 secret_len);

/* Version management */
u32 tquic_crypto_get_version(struct tquic_crypto_state *crypto);
void tquic_crypto_set_version(struct tquic_crypto_state *crypto, u32 version);

#endif /* _TQUIC_CRYPTO_TLS_H */
