/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * TQUIC: Extended Key Update Extension (draft-ietf-quic-extended-key-update-01)
 *
 * Copyright (c) 2026 Linux Foundation
 * Kernel implementation by Justin Adams <spotty118@gmail.com>
 *
 * This header provides the API for Extended Key Update in QUIC:
 * - KEY_UPDATE_REQUEST and KEY_UPDATE_RESPONSE frame handling
 * - PSK injection for external key material
 * - State machine for coordinated key updates
 * - Backward compatibility with RFC 9001 key updates
 *
 * The Extended Key Update extension allows endpoints to:
 * 1. Request key updates explicitly with acknowledgment
 * 2. Inject external PSK material into key derivation
 * 3. Coordinate key updates between peers
 */

#ifndef _TQUIC_EXTENDED_KEY_UPDATE_H
#define _TQUIC_EXTENDED_KEY_UPDATE_H

#include <linux/types.h>
#include <linux/ktime.h>
#include <linux/spinlock.h>
#include <linux/workqueue.h>

/* Forward declarations */
struct tquic_connection;
struct tquic_key_update_state;
struct crypto_shash;

/*
 * =============================================================================
 * Frame Types (draft-ietf-quic-extended-key-update-01 Section 4)
 * =============================================================================
 */

/**
 * Extended Key Update Frame Types
 *
 * KEY_UPDATE_REQUEST (0x40): Initiates an extended key update with a
 * request ID that must be acknowledged by the peer.
 *
 * KEY_UPDATE_RESPONSE (0x41): Acknowledges a KEY_UPDATE_REQUEST and
 * confirms the key update was processed.
 */
#define TQUIC_FRAME_KEY_UPDATE_REQUEST		0x40  /* Provisional assignment */
#define TQUIC_FRAME_KEY_UPDATE_RESPONSE		0x41  /* Provisional assignment */

/*
 * =============================================================================
 * Transport Parameter (draft-ietf-quic-extended-key-update-01 Section 3)
 * =============================================================================
 */

/**
 * Transport Parameter ID for Extended Key Update
 *
 * This transport parameter indicates support for the extended key update
 * mechanism. The value is a varint indicating the maximum number of
 * outstanding key update requests the endpoint can handle.
 */
#define TQUIC_TP_EXTENDED_KEY_UPDATE		0x3a  /* Provisional assignment */

/* Maximum PSK material length */
#define TQUIC_EKU_PSK_MAX_LEN			64

/* Maximum outstanding key update requests */
#define TQUIC_EKU_MAX_OUTSTANDING_REQUESTS	16

/* Key update request timeout (milliseconds) */
#define TQUIC_EKU_REQUEST_TIMEOUT_MS		30000

/*
 * =============================================================================
 * State Machine States
 * =============================================================================
 */

/**
 * enum tquic_eku_state - Extended Key Update state machine states
 * @TQUIC_EKU_STATE_IDLE: No key update in progress
 * @TQUIC_EKU_STATE_REQUEST_SENT: KEY_UPDATE_REQUEST sent, waiting for response
 * @TQUIC_EKU_STATE_REQUEST_RECEIVED: KEY_UPDATE_REQUEST received, processing
 * @TQUIC_EKU_STATE_RESPONSE_SENT: KEY_UPDATE_RESPONSE sent
 * @TQUIC_EKU_STATE_UPDATE_COMPLETE: Key update completed
 * @TQUIC_EKU_STATE_ERROR: Error occurred during key update
 */
enum tquic_eku_state {
	TQUIC_EKU_STATE_IDLE = 0,
	TQUIC_EKU_STATE_REQUEST_SENT,
	TQUIC_EKU_STATE_REQUEST_RECEIVED,
	TQUIC_EKU_STATE_RESPONSE_SENT,
	TQUIC_EKU_STATE_UPDATE_COMPLETE,
	TQUIC_EKU_STATE_ERROR,
};

/**
 * enum tquic_eku_flags - Extended Key Update flags
 * @TQUIC_EKU_FLAG_ENABLED: Extended key update is negotiated and enabled
 * @TQUIC_EKU_FLAG_PSK_INJECTED: External PSK material has been injected
 * @TQUIC_EKU_FLAG_IMMEDIATE_UPDATE: Request immediate key rotation
 * @TQUIC_EKU_FLAG_URGENT: Urgent key update (e.g., key compromise suspected)
 */
enum tquic_eku_flags {
	TQUIC_EKU_FLAG_ENABLED		= BIT(0),
	TQUIC_EKU_FLAG_PSK_INJECTED	= BIT(1),
	TQUIC_EKU_FLAG_IMMEDIATE_UPDATE	= BIT(2),
	TQUIC_EKU_FLAG_URGENT		= BIT(3),
};

/*
 * =============================================================================
 * Data Structures
 * =============================================================================
 */

/**
 * struct tquic_eku_request - Pending key update request
 * @request_id: Unique identifier for this request
 * @timestamp: When the request was sent/received
 * @flags: Request flags (urgent, immediate, etc.)
 * @psk: Optional PSK material for this request
 * @psk_len: Length of PSK material
 * @retransmit_count: Number of retransmissions
 * @list: List linkage for pending requests
 */
struct tquic_eku_request {
	u64 request_id;
	ktime_t timestamp;
	u32 flags;
	u8 psk[TQUIC_EKU_PSK_MAX_LEN];
	size_t psk_len;
	u8 retransmit_count;
	struct list_head list;
};

/**
 * struct tquic_extended_key_update_state - Extended Key Update state
 * @state: Current state machine state
 * @flags: Configuration and status flags
 * @next_request_id: Next request ID to use
 * @local_max_outstanding: Max outstanding requests we advertised
 * @remote_max_outstanding: Max outstanding requests peer advertised
 * @pending_requests: List of pending outgoing requests
 * @received_requests: List of received requests awaiting processing
 * @pending_count: Number of pending outgoing requests
 * @received_count: Number of received requests
 * @total_requests_sent: Statistics: total requests sent
 * @total_responses_sent: Statistics: total responses sent
 * @total_updates_completed: Statistics: total updates completed
 * @injected_psk: Currently injected PSK material
 * @injected_psk_len: Length of injected PSK
 * @injected_psk_id: Identifier for injected PSK (for logging/debugging)
 * @last_update_time: Timestamp of last completed update
 * @request_timeout: Timeout for pending requests
 * @key_update_state: Pointer to base key update state
 * @conn: Back-pointer to connection
 * @lock: Spinlock protecting state
 * @timeout_work: Deferred work for request timeouts
 */
struct tquic_extended_key_update_state {
	/* State machine */
	enum tquic_eku_state state;
	u32 flags;

	/* Request tracking */
	u64 next_request_id;
	u32 local_max_outstanding;
	u32 remote_max_outstanding;

	/* Request lists */
	struct list_head pending_requests;
	struct list_head received_requests;
	u32 pending_count;
	u32 received_count;

	/* Statistics */
	u64 total_requests_sent;
	u64 total_responses_sent;
	u64 total_updates_completed;

	/* PSK injection */
	u8 injected_psk[TQUIC_EKU_PSK_MAX_LEN];
	size_t injected_psk_len;
	u32 injected_psk_id;

	/* Timing */
	ktime_t last_update_time;
	u32 request_timeout;

	/* Integration */
	struct tquic_key_update_state *key_update_state;
	struct crypto_shash *hash_tfm;	/* Own hash_tfm to avoid KU lock */
	struct tquic_connection *conn;

	/* Synchronization */
	spinlock_t lock;
	struct delayed_work timeout_work;
};

/**
 * struct tquic_eku_frame_request - KEY_UPDATE_REQUEST frame
 * @request_id: Unique identifier for this request
 * @flags: Request flags (from tquic_eku_flags)
 * @psk_len: Length of optional PSK hint (0 if not present)
 * @psk_hint: Optional PSK hint data (hash of PSK ID)
 */
struct tquic_eku_frame_request {
	u64 request_id;
	u32 flags;
	u8 psk_len;
	u8 psk_hint[32];  /* SHA-256 hash of PSK ID if present */
};

/**
 * struct tquic_eku_frame_response - KEY_UPDATE_RESPONSE frame
 * @request_id: Request ID being acknowledged
 * @status: Status code (0 = success)
 */
struct tquic_eku_frame_response {
	u64 request_id;
	u8 status;
};

/* Response status codes */
#define TQUIC_EKU_STATUS_SUCCESS		0x00
#define TQUIC_EKU_STATUS_BUSY			0x01
#define TQUIC_EKU_STATUS_UNSUPPORTED		0x02
#define TQUIC_EKU_STATUS_PSK_MISMATCH		0x03
#define TQUIC_EKU_STATUS_INTERNAL_ERROR		0x04

/*
 * =============================================================================
 * State Management API
 * =============================================================================
 */

/**
 * tquic_eku_init - Initialize extended key update state
 * @conn: TQUIC connection
 * @max_outstanding: Maximum outstanding requests to support
 *
 * Allocates and initializes extended key update state for a connection.
 * Called during connection setup if both peers negotiate EKU support.
 *
 * Returns: 0 on success, negative error code on failure
 */
int tquic_eku_init(struct tquic_connection *conn, u32 max_outstanding);

/**
 * tquic_eku_free - Free extended key update state
 * @conn: TQUIC connection
 *
 * Frees all resources associated with extended key update state.
 */
void tquic_eku_free(struct tquic_connection *conn);

/**
 * tquic_eku_negotiate - Handle EKU transport parameter negotiation
 * @conn: TQUIC connection
 * @local_max: Local maximum outstanding requests
 * @remote_max: Remote peer's maximum outstanding requests
 *
 * Called after transport parameters are exchanged to finalize
 * EKU negotiation.
 *
 * Returns: 0 on success, negative error code on failure
 */
int tquic_eku_negotiate(struct tquic_connection *conn,
			u32 local_max, u32 remote_max);

/**
 * tquic_eku_is_enabled - Check if extended key update is enabled
 * @conn: TQUIC connection
 *
 * Returns: true if EKU is negotiated and enabled
 */
bool tquic_eku_is_enabled(struct tquic_connection *conn);

/*
 * =============================================================================
 * Key Update Request/Response API
 * =============================================================================
 */

/**
 * tquic_eku_request - Initiate an extended key update request
 * @conn: TQUIC connection
 * @flags: Request flags (TQUIC_EKU_FLAG_*)
 *
 * Initiates a key update request that will be acknowledged by the peer.
 * Unlike RFC 9001 key updates which are implicit via key phase bit,
 * extended key updates use explicit request/response frames.
 *
 * Returns: Request ID on success (>= 0), negative error code on failure
 *          -EAGAIN if too many outstanding requests
 *          -EBUSY if state machine is busy
 *          -ENOTSUP if EKU is not enabled
 */
s64 tquic_eku_request(struct tquic_connection *conn, u32 flags);

/**
 * tquic_eku_handle_request - Handle incoming KEY_UPDATE_REQUEST frame
 * @conn: TQUIC connection
 * @frame: Parsed request frame
 *
 * Processes an incoming key update request from the peer:
 * 1. Validates request parameters
 * 2. Derives new keys (potentially with PSK material)
 * 3. Sends KEY_UPDATE_RESPONSE
 *
 * Returns: 0 on success, negative error code on failure
 */
int tquic_eku_handle_request(struct tquic_connection *conn,
			     const struct tquic_eku_frame_request *frame);

/**
 * tquic_eku_handle_response - Handle incoming KEY_UPDATE_RESPONSE frame
 * @conn: TQUIC connection
 * @frame: Parsed response frame
 *
 * Processes an incoming response to our key update request:
 * 1. Matches response to pending request
 * 2. Completes key rotation if status is success
 * 3. Updates state machine
 *
 * Returns: 0 on success, negative error code on failure
 */
int tquic_eku_handle_response(struct tquic_connection *conn,
			      const struct tquic_eku_frame_response *frame);

/*
 * =============================================================================
 * PSK Injection API
 * =============================================================================
 */

/**
 * tquic_eku_inject_psk - Inject external PSK material
 * @conn: TQUIC connection
 * @psk: PSK material to inject
 * @psk_len: Length of PSK material
 * @psk_id: Identifier for the PSK (for debugging/logging)
 *
 * Injects external Pre-Shared Key material that will be mixed into
 * the next key derivation. This provides additional entropy and
 * can be used for:
 * - Post-quantum key exchange integration
 * - External key agreement protocols
 * - Hardware security module integration
 *
 * The PSK is mixed into key derivation using HKDF-Extract.
 *
 * Returns: 0 on success, negative error code on failure
 */
int tquic_eku_inject_psk(struct tquic_connection *conn,
			 const u8 *psk, size_t psk_len, u32 psk_id);

/**
 * tquic_eku_clear_psk - Clear injected PSK material
 * @conn: TQUIC connection
 *
 * Securely wipes the injected PSK material. Should be called
 * after key update completes or when PSK is no longer needed.
 */
void tquic_eku_clear_psk(struct tquic_connection *conn);

/**
 * tquic_eku_has_psk - Check if PSK material is currently injected
 * @conn: TQUIC connection
 *
 * Returns: true if PSK material is available
 */
bool tquic_eku_has_psk(struct tquic_connection *conn);

/*
 * =============================================================================
 * Key Derivation API
 * =============================================================================
 */

/**
 * tquic_eku_derive_keys - Derive keys with extended mechanism
 * @conn: TQUIC connection
 * @include_psk: Whether to include injected PSK in derivation
 *
 * Derives the next generation of keys using the extended mechanism:
 * 1. If PSK is available and include_psk is true, mix PSK using HKDF-Extract
 * 2. Apply standard QUIC key update derivation
 * 3. Update both read and write keys atomically
 *
 * This function coordinates with the base key_update.c module.
 *
 * Returns: 0 on success, negative error code on failure
 */
int tquic_eku_derive_keys(struct tquic_connection *conn, bool include_psk);

/*
 * =============================================================================
 * Frame Encoding/Decoding API
 * =============================================================================
 */

/**
 * tquic_eku_encode_request - Encode KEY_UPDATE_REQUEST frame
 * @frame: Request frame to encode
 * @buf: Output buffer
 * @buflen: Buffer length
 *
 * Returns: Number of bytes written, or negative error code
 */
ssize_t tquic_eku_encode_request(const struct tquic_eku_frame_request *frame,
				 u8 *buf, size_t buflen);

/**
 * tquic_eku_decode_request - Decode KEY_UPDATE_REQUEST frame
 * @buf: Input buffer (after frame type byte)
 * @buflen: Buffer length
 * @frame: Output frame structure
 *
 * Returns: Number of bytes consumed, or negative error code
 */
ssize_t tquic_eku_decode_request(const u8 *buf, size_t buflen,
				 struct tquic_eku_frame_request *frame);

/**
 * tquic_eku_encode_response - Encode KEY_UPDATE_RESPONSE frame
 * @frame: Response frame to encode
 * @buf: Output buffer
 * @buflen: Buffer length
 *
 * Returns: Number of bytes written, or negative error code
 */
ssize_t tquic_eku_encode_response(const struct tquic_eku_frame_response *frame,
				  u8 *buf, size_t buflen);

/**
 * tquic_eku_decode_response - Decode KEY_UPDATE_RESPONSE frame
 * @buf: Input buffer (after frame type byte)
 * @buflen: Buffer length
 * @frame: Output frame structure
 *
 * Returns: Number of bytes consumed, or negative error code
 */
ssize_t tquic_eku_decode_response(const u8 *buf, size_t buflen,
				  struct tquic_eku_frame_response *frame);

/*
 * =============================================================================
 * Backward Compatibility with RFC 9001
 * =============================================================================
 */

/**
 * tquic_eku_use_rfc9001_fallback - Check if RFC 9001 fallback should be used
 * @conn: TQUIC connection
 *
 * Returns true if extended key update is not negotiated and the
 * implementation should fall back to RFC 9001 key phase bit mechanism.
 *
 * Returns: true if RFC 9001 fallback should be used
 */
bool tquic_eku_use_rfc9001_fallback(struct tquic_connection *conn);

/**
 * tquic_eku_trigger_rfc9001_update - Trigger RFC 9001 style key update
 * @conn: TQUIC connection
 *
 * Triggers a key update using the RFC 9001 key phase bit mechanism.
 * Used as fallback when extended key update is not negotiated.
 *
 * Returns: 0 on success, negative error code on failure
 */
int tquic_eku_trigger_rfc9001_update(struct tquic_connection *conn);

/*
 * =============================================================================
 * Statistics and Debugging
 * =============================================================================
 */

/**
 * struct tquic_eku_stats - Extended Key Update statistics
 * @requests_sent: Total KEY_UPDATE_REQUEST frames sent
 * @requests_received: Total KEY_UPDATE_REQUEST frames received
 * @responses_sent: Total KEY_UPDATE_RESPONSE frames sent
 * @responses_received: Total KEY_UPDATE_RESPONSE frames received
 * @updates_completed: Total successful key updates
 * @updates_failed: Total failed key updates
 * @psk_injections: Total PSK injections
 * @timeouts: Total request timeouts
 * @rfc9001_fallbacks: Times RFC 9001 fallback was used
 */
struct tquic_eku_stats {
	u64 requests_sent;
	u64 requests_received;
	u64 responses_sent;
	u64 responses_received;
	u64 updates_completed;
	u64 updates_failed;
	u64 psk_injections;
	u64 timeouts;
	u64 rfc9001_fallbacks;
};

/**
 * tquic_eku_get_stats - Get extended key update statistics
 * @conn: TQUIC connection
 * @stats: Output statistics structure
 *
 * Returns: 0 on success, negative error code if EKU not enabled
 */
int tquic_eku_get_stats(struct tquic_connection *conn,
			struct tquic_eku_stats *stats);

/**
 * tquic_eku_get_state_name - Get human-readable state name
 * @state: State value
 *
 * Returns: Static string describing the state
 */
const char *tquic_eku_get_state_name(enum tquic_eku_state state);

#endif /* _TQUIC_EXTENDED_KEY_UPDATE_H */
