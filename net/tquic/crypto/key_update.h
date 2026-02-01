/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * TQUIC: TLS 1.3 Key Update Mechanism Header (RFC 9001 Section 6)
 *
 * Copyright (c) 2026 Linux Foundation
 *
 * This header provides the API for TLS 1.3 key updates in QUIC:
 * - Key phase tracking and rotation
 * - Key derivation using HKDF
 * - Automatic and manual key updates
 * - AEAD confidentiality limit enforcement
 */

#ifndef _TQUIC_KEY_UPDATE_H
#define _TQUIC_KEY_UPDATE_H

#include <linux/types.h>
#include <linux/ktime.h>

/* Forward declarations */
struct tquic_connection;
struct tquic_key_update_state;
struct crypto_shash;
struct crypto_aead;

/* Key update constants */
#define TQUIC_KEY_UPDATE_SECRET_MAX_LEN		48
#define TQUIC_KEY_UPDATE_KEY_MAX_LEN		32
#define TQUIC_KEY_UPDATE_IV_MAX_LEN		12

/* Default thresholds */
#define TQUIC_KEY_UPDATE_DEFAULT_PACKETS	(1ULL << 20)
#define TQUIC_KEY_UPDATE_DEFAULT_SECONDS	3600

/* AEAD confidentiality limits (RFC 9001 Section 6.6) */
#define TQUIC_AEAD_AES_GCM_LIMIT		(1ULL << 23)
#define TQUIC_AEAD_CHACHA20_LIMIT		(1ULL << 62)

/**
 * struct tquic_key_update_config - Key update configuration
 * @interval_packets: Trigger update after this many packets (0 = disable)
 * @interval_seconds: Trigger update after this many seconds (0 = disable)
 * @auto_update: Enable automatic key updates
 */
struct tquic_key_update_config {
	u64 interval_packets;
	u32 interval_seconds;
	bool auto_update;
};

/**
 * struct tquic_key_update_stats - Key update statistics
 * @packets_current_keys: Packets with current keys
 * @total_key_updates: Total key updates performed
 * @peer_initiated: Peer-initiated updates
 * @self_initiated: Self-initiated updates
 * @last_update_time: Timestamp of last key update
 */
struct tquic_key_update_stats {
	u64 packets_current_keys;
	u64 total_key_updates;
	u64 peer_initiated;
	u64 self_initiated;
	ktime_t last_update_time;
};

/*
 * =============================================================================
 * State Management
 * =============================================================================
 */

/**
 * tquic_key_update_state_alloc - Allocate key update state
 * @cipher_suite: Negotiated TLS 1.3 cipher suite
 *
 * Allocates and initializes key update state for a connection.
 * Must be called after cipher suite negotiation during handshake.
 *
 * Returns allocated state or NULL on failure.
 */
struct tquic_key_update_state *tquic_key_update_state_alloc(u16 cipher_suite);

/**
 * tquic_key_update_state_free - Free key update state
 * @state: State to free
 *
 * Securely wipes all key material and frees the state.
 */
void tquic_key_update_state_free(struct tquic_key_update_state *state);

/**
 * tquic_key_update_install_secrets - Install initial application secrets
 * @state: Key update state
 * @read_secret: Client/Server application traffic secret (read direction)
 * @write_secret: Client/Server application traffic secret (write direction)
 * @secret_len: Length of secrets (32 for SHA-256, 48 for SHA-384)
 *
 * Called after TLS 1.3 handshake completes to install the initial
 * application traffic secrets. Derives AEAD keys and IVs.
 *
 * Returns 0 on success, negative error code on failure.
 */
int tquic_key_update_install_secrets(struct tquic_key_update_state *state,
				     const u8 *read_secret,
				     const u8 *write_secret,
				     size_t secret_len);

/*
 * =============================================================================
 * Key Update Operations
 * =============================================================================
 */

/**
 * tquic_initiate_key_update - Initiate key update
 * @conn: TQUIC connection
 *
 * Initiates a key update by:
 * 1. Deriving next generation secrets using HKDF-Expand-Label
 * 2. Switching write keys to new generation
 * 3. Toggling key phase bit for outgoing packets
 *
 * The next packet sent will use the new keys and flipped key phase.
 * Old read keys are retained for packets in flight.
 *
 * Returns 0 on success, -EAGAIN if handshake not complete,
 * -EINPROGRESS if update already pending.
 */
int tquic_initiate_key_update(struct tquic_connection *conn);

/**
 * tquic_handle_key_phase_change - Handle received packet with different key phase
 * @conn: TQUIC connection
 * @received_phase: Key phase bit from received short header packet
 *
 * Called when a received packet has a key phase different from current:
 * - If we initiated the update, this confirms peer received our update
 * - If peer initiated, derive new keys and respond with same phase
 *
 * Returns 0 on success, negative error code on failure.
 */
int tquic_handle_key_phase_change(struct tquic_connection *conn, u8 received_phase);

/**
 * tquic_try_decrypt_with_old_keys - Try decryption with previous generation keys
 * @conn: TQUIC connection
 * @header: Packet header (for AAD)
 * @header_len: Header length
 * @payload: Encrypted payload
 * @payload_len: Payload length including auth tag
 * @pkt_num: Decoded packet number
 * @out: Output buffer for decrypted data
 * @out_len: Output: decrypted data length
 *
 * When decryption fails with current keys, try old keys for packets
 * that were in flight during a key update.
 *
 * Returns 0 on success, -ENOKEY if no old keys available.
 */
int tquic_try_decrypt_with_old_keys(struct tquic_connection *conn,
				    const u8 *header, size_t header_len,
				    u8 *payload, size_t payload_len,
				    u64 pkt_num, u8 *out, size_t *out_len);

/*
 * =============================================================================
 * Key Access
 * =============================================================================
 */

/**
 * tquic_key_update_get_current_keys - Get current encryption keys
 * @state: Key update state
 * @direction: 0 = read (decrypt), 1 = write (encrypt)
 * @key: Output buffer for AEAD key
 * @key_len: Output: key length
 * @iv: Output buffer for IV
 * @iv_len: Output: IV length
 *
 * Returns 0 on success, -ENOKEY if keys not available.
 */
int tquic_key_update_get_current_keys(struct tquic_key_update_state *state,
				      int direction,
				      u8 *key, u32 *key_len,
				      u8 *iv, u32 *iv_len);

/**
 * tquic_key_update_get_phase - Get current key phase
 * @state: Key update state
 *
 * Returns current key phase (0 or 1) for short header packets.
 */
u8 tquic_key_update_get_phase(struct tquic_key_update_state *state);

/*
 * =============================================================================
 * Statistics and Configuration
 * =============================================================================
 */

/**
 * tquic_key_update_on_packet_sent - Track packet sent
 * @state: Key update state
 *
 * Called after each packet is sent to track statistics
 * for automatic key update triggering.
 */
void tquic_key_update_on_packet_sent(struct tquic_key_update_state *state);

/**
 * tquic_key_update_on_packet_received - Track packet received
 * @state: Key update state
 *
 * Called after each packet is successfully decrypted.
 */
void tquic_key_update_on_packet_received(struct tquic_key_update_state *state);

/**
 * tquic_key_update_check_threshold - Check if automatic key update needed
 * @conn: TQUIC connection
 *
 * Checks if key update should be triggered based on:
 * - Packet count threshold
 * - Time-based threshold
 * - Approaching AEAD confidentiality limit
 *
 * Returns true if key update was initiated.
 */
bool tquic_key_update_check_threshold(struct tquic_connection *conn);

/**
 * tquic_key_update_set_intervals - Configure key update intervals
 * @state: Key update state
 * @packets: Packet count threshold (0 to disable)
 * @seconds: Time threshold in seconds (0 to disable)
 */
void tquic_key_update_set_intervals(struct tquic_key_update_state *state,
				    u64 packets, u32 seconds);

/*
 * =============================================================================
 * Integration with Crypto State
 * =============================================================================
 */

/**
 * tquic_crypto_get_key_update_state - Get key update state from crypto state
 * @crypto_state: Connection's crypto state (void* for flexibility)
 *
 * Returns the key update state embedded in the crypto state.
 */
struct tquic_key_update_state *tquic_crypto_get_key_update_state(void *crypto_state);

#endif /* _TQUIC_KEY_UPDATE_H */
