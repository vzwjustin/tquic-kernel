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
#include <linux/spinlock.h>
#include <linux/workqueue.h>

/* Forward declarations */
struct tquic_connection;
struct crypto_shash;
struct crypto_aead;

/* Key material max lengths */
#define TQUIC_SECRET_MAX_LEN		48	/* SHA-384 max */
#define TQUIC_KEY_MAX_LEN		32	/* AES-256 max */
#define TQUIC_IV_MAX_LEN		12
#define TQUIC_HP_KEY_MAX_LEN		32

/* Key update constants - legacy names for compatibility */
#define TQUIC_KEY_UPDATE_SECRET_MAX_LEN		TQUIC_SECRET_MAX_LEN
#define TQUIC_KEY_UPDATE_KEY_MAX_LEN		TQUIC_KEY_MAX_LEN
#define TQUIC_KEY_UPDATE_IV_MAX_LEN		TQUIC_IV_MAX_LEN

/**
 * struct tquic_key_generation - Keys for one generation (key phase)
 * @secret: Application traffic secret
 * @key: AEAD key derived from secret
 * @iv: Initialization vector derived from secret
 * @hp_key: Header protection key derived from secret
 * @secret_len: Length of the secret
 * @key_len: Length of the AEAD key
 * @iv_len: Length of the IV
 * @valid: Whether this key generation is valid for use
 */
struct tquic_key_generation {
	u8 secret[TQUIC_SECRET_MAX_LEN];
	u8 key[TQUIC_KEY_MAX_LEN];
	u8 iv[TQUIC_IV_MAX_LEN];
	u8 hp_key[TQUIC_HP_KEY_MAX_LEN];
	u32 secret_len;
	u32 key_len;
	u32 iv_len;
	bool valid;
};

/**
 * struct tquic_key_update_state - Key update state per connection
 * @current_phase: Current key phase (0 or 1)
 * @current_read: Current generation keys for reading
 * @current_write: Current generation keys for writing
 * @next_read: Next generation keys for reading (pre-computed)
 * @next_write: Next generation keys for writing (pre-computed)
 * @old_read: Previous generation keys (for packets in flight)
 * @packets_sent: Packets sent with current write keys
 * @packets_received: Packets received with current read keys
 * @total_key_updates: Total number of key updates performed
 * @peer_initiated_updates: Key updates initiated by peer
 * @last_key_update: Timestamp of last key update
 * @old_key_discard_time: When to discard old keys
 * @update_pending: Key update initiated, waiting for peer ACK
 * @peer_update_received: Peer initiated key update
 * @handshake_confirmed: Handshake has completed
 * @old_keys_valid: Old keys are still valid for decryption
 * @cipher_suite: Negotiated cipher suite
 * @confidentiality_limit: AEAD confidentiality limit
 * @hash_tfm: Hash transform for HKDF
 * @aead_tfm: AEAD transform for encryption/decryption
 * @key_update_interval_packets: Packets before initiating update
 * @key_update_interval_seconds: Seconds before initiating update
 * @lock: Spinlock protecting key state
 * @update_work: Deferred work for key derivation
 * @conn: Back-pointer to connection
 */
struct tquic_key_update_state {
	/* Key phase (RFC 9001 Section 6) */
	u8 current_phase;

	/* Key generations (double-buffered) */
	struct tquic_key_generation current_read;
	struct tquic_key_generation current_write;
	struct tquic_key_generation next_read;
	struct tquic_key_generation next_write;
	struct tquic_key_generation old_read;

	/* Statistics for confidentiality limit tracking */
	u64 packets_sent;
	u64 packets_received;
	u64 total_key_updates;
	u64 peer_initiated_updates;

	/* Timing */
	ktime_t last_key_update;
	ktime_t old_key_discard_time;

	/* State flags */
	bool update_pending;
	bool peer_update_received;
	bool handshake_confirmed;
	bool old_keys_valid;

	/* Cipher configuration */
	u16 cipher_suite;
	u64 confidentiality_limit;

	/* Crypto transforms */
	struct crypto_shash *hash_tfm;
	struct crypto_aead *aead_tfm;

	/* Configuration (from sysctl or per-connection) */
	u64 key_update_interval_packets;
	u32 key_update_interval_seconds;

	/* Synchronization */
	spinlock_t lock;
	struct work_struct update_work;

	/* Back-pointer */
	struct tquic_connection *conn;
};

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

/*
 * =============================================================================
 * Extended Key Update Integration
 * =============================================================================
 */

/**
 * tquic_key_update_with_psk - Derive keys with additional PSK material
 * @conn: TQUIC connection
 * @psk: Pre-shared key material to mix in
 * @psk_len: Length of PSK material
 *
 * Derives new keys by first mixing the PSK with current secrets using
 * HKDF-Extract, then performing standard key derivation.
 *
 * This is used by the Extended Key Update extension to incorporate
 * external key material (e.g., from post-quantum key exchange).
 *
 * Returns 0 on success, negative error code on failure.
 */
int tquic_key_update_with_psk(struct tquic_connection *conn,
			      const u8 *psk, size_t psk_len);

/**
 * tquic_key_update_get_old_read_keys - Get previous generation read keys
 * @state: Key update state
 * @key: Output buffer for AEAD key
 * @key_len: Output: key length
 * @iv: Output buffer for IV
 * @iv_len: Output: IV length
 *
 * Retrieves the previous generation read keys for decrypting packets
 * that were in flight during a key update.
 *
 * Returns 0 on success, -ENOKEY if old keys not available.
 */
int tquic_key_update_get_old_read_keys(struct tquic_key_update_state *state,
				       u8 *key, u32 *key_len,
				       u8 *iv, u32 *iv_len);

#endif /* _TQUIC_KEY_UPDATE_H */
