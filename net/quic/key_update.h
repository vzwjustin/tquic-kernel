/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * QUIC Key Update Mechanism Header (RFC 9001 Section 6)
 *
 * Declarations for QUIC key update functionality including:
 * - Key phase tracking and detection
 * - Key derivation for update
 * - Old key retention for reordered packets
 * - Key discard timing
 *
 * Copyright (c) 2024 Linux QUIC Authors
 */

#ifndef _NET_QUIC_KEY_UPDATE_H
#define _NET_QUIC_KEY_UPDATE_H

#include <linux/types.h>

struct quic_connection;
struct quic_crypto_ctx;
struct sk_buff;

/*
 * Extended crypto context fields for key update support.
 * These fields should be added to struct quic_crypto_ctx in include/net/quic.h:
 *
 * struct crypto_aead	*rx_aead_prev;     // Previous RX AEAD for reordered pkts
 * struct quic_crypto_secret rx_prev;      // Previous RX keys
 * u8	rx_prev_valid:1;                   // Previous keys available
 * u8	rx_key_phase:1;                    // Expected RX key phase
 * u8	key_update_pending:1;              // Awaiting ACK for key update
 * u64	key_update_pn;                     // First PN with new keys
 */

/*
 * Key Update Functions
 */

/**
 * quic_crypto_initiate_key_update - Initiate a key update
 * @conn: QUIC connection
 *
 * Called to start a key update. Updates TX keys and toggles key phase.
 * Per RFC 9001 Section 6.2, cannot initiate another update until the
 * current one is acknowledged.
 *
 * Return: 0 on success, -EAGAIN if update pending, negative on error
 */
int quic_crypto_initiate_key_update(struct quic_connection *conn);

/**
 * quic_crypto_on_key_phase_change - Handle received key phase change
 * @conn: QUIC connection
 * @rx_key_phase: Key phase bit from received packet
 *
 * Called when a packet is received with a different key phase than expected.
 * Updates keys as needed for both local-initiated and peer-initiated updates.
 *
 * Return: 0 on success, negative error code on failure
 */
int quic_crypto_on_key_phase_change(struct quic_connection *conn, u8 rx_key_phase);

/**
 * quic_crypto_discard_old_keys - Discard old keys after timeout
 * @conn: QUIC connection
 *
 * Called by key discard timer to free previous generation keys.
 * Per RFC 9001 Section 6.1, keys should be retained for ~3x PTO.
 */
void quic_crypto_discard_old_keys(struct quic_connection *conn);

/**
 * quic_crypto_decrypt_with_phase - Decrypt considering key phase
 * @ctx: Crypto context
 * @skb: Socket buffer with encrypted packet
 * @pn: Packet number for nonce
 * @key_phase: Key phase from packet header
 *
 * Attempts decryption with appropriate keys based on key phase.
 * For reordered packets (after key update), tries previous keys first.
 *
 * Return: 0 on success, -EKEYREJECTED if key update needed, negative on error
 */
int quic_crypto_decrypt_with_phase(struct quic_crypto_ctx *ctx,
				   struct sk_buff *skb, u64 pn, u8 key_phase);

/**
 * quic_crypto_get_key_phase - Get current TX key phase
 * @ctx: Crypto context
 *
 * Return: Current key phase bit (0 or 1)
 */
u8 quic_crypto_get_key_phase(struct quic_crypto_ctx *ctx);

/*
 * Constants
 */

/* Key phase bit in short header first byte (RFC 9000 Section 17.3.1) */
#define QUIC_SHORT_KEY_PHASE_BIT	0x04

/* Key discard timeout (default 3x PTO, ~1 second minimum) */
#define QUIC_KEY_DISCARD_TIMEOUT_MS	1000

/*
 * QUIC_SKB_CB - Access QUIC per-packet metadata in skb->cb
 *
 * Structure stored in skb->cb for packet processing:
 *   u64 pn;           - Full packet number
 *   u32 header_len;   - Length of QUIC header
 *   u8  pn_len;       - Encoded packet number length
 *   u8  packet_type;  - Packet type
 *   u8  dcid_len;     - DCID length
 *   u8  scid_len;     - SCID length (long header only)
 */
struct quic_skb_cb {
	u64	pn;
	u32	header_len;
	u8	pn_len;
	u8	packet_type;
	u8	dcid_len;
	u8	scid_len;
};

#define QUIC_SKB_CB(skb) ((struct quic_skb_cb *)((skb)->cb))

#endif /* _NET_QUIC_KEY_UPDATE_H */
