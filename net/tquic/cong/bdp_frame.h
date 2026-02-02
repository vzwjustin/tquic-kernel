/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * TQUIC: BDP Frame Extension (draft-kuhn-quic-bdpframe-extension-05)
 *
 * Copyright (c) 2026 Linux Foundation
 *
 * This header implements the BDP (Bandwidth-Delay Product) Frame extension
 * for QUIC, enabling endpoints to exchange network path characteristics
 * for Careful Resume of congestion control state.
 *
 * The BDP Frame allows a server to send estimated path characteristics
 * to a client, which can store them and use them when reconnecting to
 * safely initialize congestion control with previously observed values.
 */

#ifndef _TQUIC_BDP_FRAME_H
#define _TQUIC_BDP_FRAME_H

#include <linux/types.h>
#include <linux/crypto.h>
#include <crypto/hash.h>
#include <net/tquic.h>

/*
 * BDP Frame Type
 * Provisional allocation: 0x1f (per draft-kuhn-quic-bdpframe-extension-05)
 */
#define TQUIC_FRAME_BDP			0x1f

/*
 * Transport Parameter ID for enable_bdp_frame
 * This is a provisional value; real deployment should use IANA allocation
 */
#define TQUIC_TP_ENABLE_BDP_FRAME	0xff0bdf01ULL

/*
 * BDP Frame Version
 */
#define TQUIC_BDP_FRAME_VERSION		0x05

/*
 * HMAC key length for BDP frame authentication
 */
#define TQUIC_BDP_HMAC_KEY_LEN		32

/*
 * HMAC output length (SHA-256 truncated to 128 bits for wire efficiency)
 */
#define TQUIC_BDP_HMAC_LEN		16

/*
 * Endpoint token length
 * Used to identify the server that generated the BDP frame
 */
#define TQUIC_BDP_TOKEN_LEN		16

/*
 * Maximum BDP frame lifetime (24 hours in seconds)
 * BDP frames older than this should be discarded
 */
#define TQUIC_BDP_MAX_LIFETIME_SEC	86400

/*
 * Default BDP frame lifetime (1 hour in seconds)
 */
#define TQUIC_BDP_DEFAULT_LIFETIME_SEC	3600

/*
 * BDP validation thresholds
 * Used by Careful Resume to validate incoming BDP values
 */
#define TQUIC_BDP_MIN_RTT_US		1000		/* 1ms minimum RTT */
#define TQUIC_BDP_MAX_RTT_US		300000000	/* 300s maximum RTT */
#define TQUIC_BDP_MIN_CWND		(2 * 1200)	/* 2 packets minimum */
#define TQUIC_BDP_MAX_CWND		(100 * 1024 * 1024) /* 100MB max */
#define TQUIC_BDP_MIN_BDP		(2 * 1200)	/* 2 packets minimum */
#define TQUIC_BDP_MAX_BDP		(500 * 1024 * 1024) /* 500MB max */

/*
 * Careful Resume phases
 */
enum tquic_careful_resume_phase {
	TQUIC_CR_PHASE_DISABLED = 0,	/* Not using Careful Resume */
	TQUIC_CR_PHASE_RECONNECTION,	/* Reconnection phase: validating */
	TQUIC_CR_PHASE_UNVALIDATED,	/* Using saved, not yet validated */
	TQUIC_CR_PHASE_SAFE_RETREAT,	/* Detected issue, retreating */
	TQUIC_CR_PHASE_NORMAL,		/* Normal operation after validation */
};

/**
 * struct tquic_bdp_frame - BDP Frame wire format structure
 * @bdp: Bandwidth-Delay Product in bytes
 * @saved_cwnd: Congestion window when BDP was measured (bytes)
 * @saved_rtt: RTT when BDP was measured (microseconds)
 * @lifetime: Frame validity duration (seconds)
 * @endpoint_token: Server-generated token for identification
 * @hmac: HMAC-SHA256 truncated authentication tag
 *
 * The BDP Frame contains path characteristics observed by the server
 * during a previous connection. The client stores this information
 * and can present it when reconnecting to enable Careful Resume.
 *
 * Wire format (variable length):
 *   Type (1 byte): 0x1f
 *   BDP (varint): Bandwidth-delay product in bytes
 *   Saved CWND (varint): Congestion window in bytes
 *   Saved RTT (varint): Round-trip time in microseconds
 *   Lifetime (varint): Validity period in seconds
 *   Endpoint Token (16 bytes): Server identification token
 *   HMAC (16 bytes): Authentication tag
 */
struct tquic_bdp_frame {
	u64 bdp;
	u64 saved_cwnd;
	u64 saved_rtt;
	u64 lifetime;
	u8 endpoint_token[TQUIC_BDP_TOKEN_LEN];
	u8 hmac[TQUIC_BDP_HMAC_LEN];
};

/**
 * struct tquic_bdp_state - Per-connection BDP state
 * @enabled: BDP frame extension negotiated
 * @have_saved: Have valid saved BDP from previous connection
 * @have_generated: Have generated BDP for sending to client
 * @applied: Careful Resume has been applied
 * @saved: Saved BDP frame (received from peer or restored)
 * @generated: Generated BDP frame for sending
 * @cr_phase: Current Careful Resume phase
 * @cr_start_time: Time when Careful Resume started
 * @cr_original_cwnd: Original cwnd before Careful Resume
 * @cr_target_cwnd: Target cwnd from saved BDP
 * @cr_validated_rtt: RTT validation sample
 * @cr_acks_since_resume: ACK count since resume started
 * @cr_bytes_acked: Bytes acknowledged since resume
 * @cr_bytes_lost: Bytes lost since resume
 * @hmac_key: HMAC key for BDP authentication
 * @hmac_key_set: Whether HMAC key has been configured
 * @lock: Spinlock for state protection
 *
 * This structure tracks BDP frame state for a connection, including
 * both received and generated BDP frames, and Careful Resume state.
 */
struct tquic_bdp_state {
	bool enabled;
	bool have_saved;
	bool have_generated;
	bool applied;

	struct tquic_bdp_frame saved;
	struct tquic_bdp_frame generated;

	/* Careful Resume state */
	enum tquic_careful_resume_phase cr_phase;
	ktime_t cr_start_time;
	u64 cr_original_cwnd;
	u64 cr_target_cwnd;
	u64 cr_validated_rtt;
	u32 cr_acks_since_resume;
	u64 cr_bytes_acked;
	u64 cr_bytes_lost;

	/* HMAC authentication */
	u8 hmac_key[TQUIC_BDP_HMAC_KEY_LEN];
	bool hmac_key_set;

	spinlock_t lock;
};

/*
 * =============================================================================
 * BDP Frame API
 * =============================================================================
 */

/**
 * tquic_bdp_init - Initialize BDP state for a connection
 * @conn: Connection to initialize BDP state for
 *
 * Allocates and initializes the BDP state structure for the connection.
 * Called during connection setup if BDP frame extension is negotiated.
 *
 * Return: 0 on success, negative error code on failure
 */
int tquic_bdp_init(struct tquic_connection *conn);

/**
 * tquic_bdp_release - Release BDP state for a connection
 * @conn: Connection to release BDP state for
 *
 * Frees the BDP state structure. Called during connection teardown.
 */
void tquic_bdp_release(struct tquic_connection *conn);

/**
 * tquic_bdp_set_hmac_key - Set HMAC key for BDP authentication
 * @conn: Connection
 * @key: HMAC key (32 bytes)
 * @key_len: Length of key
 *
 * Sets the HMAC key used to authenticate BDP frames. Should be called
 * before generating or validating BDP frames.
 *
 * Return: 0 on success, negative error code on failure
 */
int tquic_bdp_set_hmac_key(struct tquic_connection *conn, const u8 *key,
			   size_t key_len);

/**
 * tquic_encode_bdp_frame - Encode BDP frame to wire format
 * @frame: BDP frame structure to encode
 * @buf: Output buffer
 * @buflen: Buffer length
 *
 * Encodes a BDP frame into wire format for transmission.
 *
 * Return: Number of bytes written, or negative error code
 */
ssize_t tquic_encode_bdp_frame(const struct tquic_bdp_frame *frame,
			       u8 *buf, size_t buflen);

/**
 * tquic_decode_bdp_frame - Decode BDP frame from wire format
 * @buf: Input buffer containing encoded frame
 * @buflen: Buffer length
 * @frame: Output BDP frame structure
 *
 * Decodes a BDP frame from wire format. Does not validate HMAC;
 * caller should use tquic_validate_bdp_frame() for validation.
 *
 * Return: Number of bytes consumed, or negative error code
 */
ssize_t tquic_decode_bdp_frame(const u8 *buf, size_t buflen,
			       struct tquic_bdp_frame *frame);

/**
 * tquic_generate_bdp_frame - Generate BDP frame from current CC state
 * @conn: Connection
 * @path: Path to generate BDP for
 * @frame: Output BDP frame structure
 *
 * Generates a BDP frame containing current path characteristics from
 * the congestion control state. Called by server to create BDP frame
 * for the client.
 *
 * Return: 0 on success, negative error code on failure
 */
int tquic_generate_bdp_frame(struct tquic_connection *conn,
			     struct tquic_path *path,
			     struct tquic_bdp_frame *frame);

/**
 * tquic_validate_bdp_frame - Validate received BDP frame with HMAC
 * @conn: Connection
 * @frame: BDP frame to validate
 *
 * Validates the BDP frame by checking:
 * - HMAC authentication tag
 * - Frame lifetime (not expired)
 * - Endpoint token matches
 * - Values are within acceptable ranges
 *
 * Return: 0 if valid, negative error code if invalid
 */
int tquic_validate_bdp_frame(struct tquic_connection *conn,
			     const struct tquic_bdp_frame *frame);

/**
 * tquic_apply_bdp_frame - Apply BDP frame to congestion control
 * @conn: Connection
 * @path: Path to apply BDP to
 * @frame: Validated BDP frame
 *
 * Applies the BDP frame to congestion control using Careful Resume.
 * This gradually increases the congestion window toward the saved
 * value while validating the path characteristics.
 *
 * Return: 0 on success, negative error code on failure
 */
int tquic_apply_bdp_frame(struct tquic_connection *conn,
			  struct tquic_path *path,
			  const struct tquic_bdp_frame *frame);

/**
 * tquic_bdp_generate_endpoint_token - Generate endpoint token
 * @conn: Connection
 * @token: Output buffer (TQUIC_BDP_TOKEN_LEN bytes)
 *
 * Generates a unique endpoint token for this server that can be used
 * to identify BDP frames generated by this server.
 *
 * Return: 0 on success, negative error code on failure
 */
int tquic_bdp_generate_endpoint_token(struct tquic_connection *conn, u8 *token);

/**
 * tquic_bdp_compute_hmac - Compute HMAC for BDP frame
 * @conn: Connection (for HMAC key)
 * @frame: BDP frame (hmac field will be filled)
 *
 * Computes HMAC-SHA256 over the BDP frame fields and stores the
 * truncated result in the frame's hmac field.
 *
 * Return: 0 on success, negative error code on failure
 */
int tquic_bdp_compute_hmac(struct tquic_connection *conn,
			   struct tquic_bdp_frame *frame);

/**
 * tquic_bdp_verify_hmac - Verify HMAC for BDP frame
 * @conn: Connection (for HMAC key)
 * @frame: BDP frame to verify
 *
 * Verifies the HMAC authentication tag in the BDP frame.
 *
 * Return: 0 if valid, -EBADMSG if invalid, other negative on error
 */
int tquic_bdp_verify_hmac(struct tquic_connection *conn,
			  const struct tquic_bdp_frame *frame);

/**
 * tquic_bdp_is_enabled - Check if BDP frame extension is enabled
 * @conn: Connection
 *
 * Return: true if BDP frame extension is negotiated and enabled
 */
bool tquic_bdp_is_enabled(struct tquic_connection *conn);

/**
 * tquic_bdp_should_send - Check if we should send a BDP frame
 * @conn: Connection
 *
 * Returns true if we should send a BDP frame to the peer.
 * Typically called on connection close or significant CC changes.
 *
 * Return: true if BDP frame should be sent
 */
bool tquic_bdp_should_send(struct tquic_connection *conn);

/**
 * tquic_bdp_store_for_reconnect - Store BDP frame for future reconnection
 * @conn: Connection
 * @frame: BDP frame to store
 *
 * Stores the BDP frame in connection state for potential future use
 * when reconnecting to the same server.
 *
 * Return: 0 on success, negative error code on failure
 */
int tquic_bdp_store_for_reconnect(struct tquic_connection *conn,
				  const struct tquic_bdp_frame *frame);

/**
 * tquic_bdp_restore_for_reconnect - Restore BDP frame for reconnection
 * @conn: Connection
 * @frame: Output BDP frame
 *
 * Attempts to restore a previously stored BDP frame for this connection.
 * Should be called during connection setup to check for saved state.
 *
 * Return: 0 if found and restored, -ENOENT if not found, other negative on error
 */
int tquic_bdp_restore_for_reconnect(struct tquic_connection *conn,
				    struct tquic_bdp_frame *frame);

/*
 * =============================================================================
 * Careful Resume API (integrated with BDP Frame)
 * =============================================================================
 */

/**
 * tquic_careful_resume_init - Initialize Careful Resume from BDP
 * @path: Path to initialize
 * @frame: Validated BDP frame
 *
 * Initializes the Careful Resume algorithm using values from a
 * validated BDP frame. This sets up the target cwnd and RTT for
 * gradual congestion window increase.
 *
 * Return: 0 on success, negative error code on failure
 */
int tquic_careful_resume_init(struct tquic_path *path,
			      const struct tquic_bdp_frame *frame);

/**
 * tquic_careful_resume_validate - Validate Careful Resume parameters
 * @path: Path being validated
 * @observed_rtt: Observed RTT on current connection (microseconds)
 *
 * Validates that the current path characteristics are compatible
 * with the saved BDP values. Called during Careful Resume to detect
 * if the path has changed significantly.
 *
 * Return: true if parameters are safe, false if should retreat
 */
bool tquic_careful_resume_validate(struct tquic_path *path, u64 observed_rtt);

/**
 * tquic_careful_resume_apply - Apply Careful Resume to CC
 * @path: Path to apply to
 * @bytes_acked: Bytes acknowledged in this ACK
 * @rtt_us: RTT sample in microseconds
 *
 * Called on ACK during Careful Resume phase. Gradually increases
 * the congestion window toward the target while monitoring for
 * congestion signals.
 *
 * Return: true if still in Careful Resume, false if complete
 */
bool tquic_careful_resume_apply(struct tquic_path *path, u64 bytes_acked,
				u64 rtt_us);

/**
 * tquic_careful_resume_on_loss - Handle loss during Careful Resume
 * @path: Path that experienced loss
 * @bytes_lost: Bytes lost
 *
 * Called on loss detection during Careful Resume. May trigger
 * safe retreat to conservative CC state.
 */
void tquic_careful_resume_on_loss(struct tquic_path *path, u64 bytes_lost);

/**
 * tquic_careful_resume_safe_retreat - Execute safe retreat
 * @path: Path to retreat on
 *
 * Called when Careful Resume detects the path has changed and
 * saved values are no longer valid. Retreats to conservative
 * slow start from minimum cwnd.
 */
void tquic_careful_resume_safe_retreat(struct tquic_path *path);

/**
 * tquic_careful_resume_get_phase - Get current Careful Resume phase
 * @conn: Connection
 *
 * Return: Current Careful Resume phase
 */
enum tquic_careful_resume_phase tquic_careful_resume_get_phase(
	struct tquic_connection *conn);

/**
 * tquic_careful_resume_complete - Mark Careful Resume as complete
 * @conn: Connection
 * @path: Path that completed validation
 *
 * Called when Careful Resume has successfully validated the saved
 * parameters and the connection can proceed with normal CC.
 */
void tquic_careful_resume_complete(struct tquic_connection *conn,
				   struct tquic_path *path);

#endif /* _TQUIC_BDP_FRAME_H */
