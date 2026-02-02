/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * TQUIC: Congestion Control Data Exchange (draft-yuan-quic-congestion-data-00)
 *
 * Copyright (c) 2026 Linux Foundation
 *
 * This header implements the Congestion Control Data exchange extension
 * for QUIC, enabling endpoints to share congestion control state information.
 * This supports:
 * - Connection resumption with saved CC state (Careful Resume)
 * - Server-to-client CC hints for better initial performance
 * - Privacy-preserving optional disclosure controls
 *
 * The CONGESTION_DATA frame allows an endpoint to send a snapshot of its
 * congestion control state to the peer, which can store and use the data
 * when reconnecting to safely initialize congestion control parameters.
 *
 * SECURITY: Peer data MUST NOT be blindly trusted. All received values
 * are validated and capped to safe ranges before use.
 */

#ifndef _TQUIC_CONG_DATA_H
#define _TQUIC_CONG_DATA_H

#include <linux/types.h>
#include <linux/spinlock.h>
#include <linux/ktime.h>
#include <crypto/hash.h>
#include <net/tquic.h>

/* Forward declarations */
struct tquic_connection;
struct tquic_path;

/*
 * =============================================================================
 * Constants and Frame Type
 * =============================================================================
 */

/*
 * CONGESTION_DATA Frame Type
 * Provisional allocation per draft-yuan-quic-congestion-data-00
 */
#define TQUIC_FRAME_CONGESTION_DATA		0xff0cd001ULL

/*
 * Transport Parameter ID for enable_cong_data
 * Provisional value - real deployment should use IANA allocation
 */
#define TQUIC_TP_ENABLE_CONG_DATA		0xff0cd002ULL

/*
 * Protocol version for CONGESTION_DATA frames
 */
#define TQUIC_CONG_DATA_VERSION			0x01

/*
 * Maximum CONGESTION_DATA frame size (excluding frame type)
 */
#define TQUIC_CONG_DATA_MAX_SIZE		256

/*
 * HMAC authentication parameters
 */
#define TQUIC_CONG_DATA_HMAC_KEY_LEN		32
#define TQUIC_CONG_DATA_HMAC_LEN		16	/* Truncated SHA-256 */

/*
 * Endpoint token for identifying the source
 */
#define TQUIC_CONG_DATA_TOKEN_LEN		16

/*
 * Maximum frame lifetime (24 hours in seconds)
 * Data older than this should be discarded
 */
#define TQUIC_CONG_DATA_MAX_LIFETIME_SEC	86400

/*
 * Default frame lifetime (2 hours in seconds)
 */
#define TQUIC_CONG_DATA_DEFAULT_LIFETIME_SEC	7200

/*
 * Minimum interval between sending CONGESTION_DATA frames (milliseconds)
 * Prevents flooding the peer with updates
 */
#define TQUIC_CONG_DATA_MIN_INTERVAL_MS		1000

/*
 * Maximum outstanding unacknowledged frames
 */
#define TQUIC_CONG_DATA_MAX_OUTSTANDING		4

/*
 * =============================================================================
 * Validation Thresholds (Careful Resume Principles)
 * =============================================================================
 *
 * These thresholds ensure we don't blindly trust peer-provided data.
 * Values outside these ranges are capped or rejected.
 */

/* Bandwidth estimate bounds */
#define TQUIC_CONG_DATA_MIN_BWE_BPS		1000ULL		/* 1 Kbps */
#define TQUIC_CONG_DATA_MAX_BWE_BPS		100000000000ULL	/* 100 Gbps */

/* RTT bounds (microseconds) */
#define TQUIC_CONG_DATA_MIN_RTT_US		100ULL		/* 100 us */
#define TQUIC_CONG_DATA_MAX_RTT_US		300000000ULL	/* 300 seconds */

/* Loss rate bounds (scaled by 10000, so 10000 = 100%) */
#define TQUIC_CONG_DATA_MIN_LOSS_RATE		0
#define TQUIC_CONG_DATA_MAX_LOSS_RATE		10000

/* Congestion window bounds (bytes) */
#define TQUIC_CONG_DATA_MIN_CWND		(2 * 1200)	/* 2 packets */
#define TQUIC_CONG_DATA_MAX_CWND		(100 * 1024 * 1024) /* 100 MB */

/* SSTHRESH bounds (bytes) */
#define TQUIC_CONG_DATA_MIN_SSTHRESH		(2 * 1200)
#define TQUIC_CONG_DATA_MAX_SSTHRESH		(100 * 1024 * 1024)

/*
 * RTT ratio threshold for Careful Resume
 * If observed RTT / saved RTT > this ratio, retreat to slow start
 */
#define TQUIC_CONG_DATA_RTT_RATIO_THRESHOLD	200	/* 2.0x scaled by 100 */

/*
 * Loss threshold for Careful Resume
 * If loss rate exceeds this during resume, retreat to slow start
 */
#define TQUIC_CONG_DATA_LOSS_THRESHOLD		500	/* 5% scaled by 10000 */

/*
 * =============================================================================
 * Privacy Controls
 * =============================================================================
 *
 * Endpoints may choose to limit what information they share.
 */

/* Privacy levels for CONGESTION_DATA exchange */
enum tquic_cong_data_privacy {
	TQUIC_CONG_PRIVACY_FULL = 0,	/* Share all metrics */
	TQUIC_CONG_PRIVACY_PARTIAL,	/* Share BWE and RTT only */
	TQUIC_CONG_PRIVACY_MINIMAL,	/* Share RTT only */
	TQUIC_CONG_PRIVACY_DISABLED,	/* Don't share any data */
};

/* Flags for optional fields in CONGESTION_DATA frame */
#define TQUIC_CONG_DATA_FLAG_HAS_CWND		BIT(0)
#define TQUIC_CONG_DATA_FLAG_HAS_SSTHRESH	BIT(1)
#define TQUIC_CONG_DATA_FLAG_HAS_PACING_RATE	BIT(2)
#define TQUIC_CONG_DATA_FLAG_HAS_DELIVERY_RATE	BIT(3)
#define TQUIC_CONG_DATA_FLAG_AUTHENTICATED	BIT(7)

/*
 * =============================================================================
 * Data Structures
 * =============================================================================
 */

/**
 * struct tquic_cong_data - Congestion state snapshot
 * @seq_num: Sequence number for ordering and deduplication
 * @bwe: Bandwidth estimate in bits per second
 * @min_rtt: Minimum observed RTT in microseconds
 * @loss_rate: Loss rate scaled by 10000 (10000 = 100%)
 * @timestamp: When data was collected (Unix timestamp in seconds)
 * @flags: Optional field presence flags
 * @cwnd: Congestion window in bytes (optional)
 * @ssthresh: Slow start threshold in bytes (optional)
 * @pacing_rate: Pacing rate in bytes per second (optional)
 * @delivery_rate: Delivery rate in bytes per second (optional)
 * @endpoint_token: Source identification token
 * @hmac: HMAC authentication tag (if authenticated)
 *
 * Wire format (all fields are QUIC varints unless noted):
 *   Frame Type (varint): 0xff0cd001
 *   Sequence Number (varint)
 *   Flags (varint): Indicates which optional fields are present
 *   BWE (varint): Bandwidth estimate in bps
 *   Min RTT (varint): Minimum RTT in microseconds
 *   Loss Rate (varint): Loss rate scaled by 10000
 *   Timestamp (varint): Unix timestamp in seconds
 *   [Optional fields based on flags]
 *   CWND (varint): If FLAG_HAS_CWND
 *   SSTHRESH (varint): If FLAG_HAS_SSTHRESH
 *   Pacing Rate (varint): If FLAG_HAS_PACING_RATE
 *   Delivery Rate (varint): If FLAG_HAS_DELIVERY_RATE
 *   [If FLAG_AUTHENTICATED]
 *   Endpoint Token (16 bytes): Server identification
 *   HMAC (16 bytes): HMAC-SHA256 truncated
 */
struct tquic_cong_data {
	u64 seq_num;
	u64 bwe;
	u64 min_rtt;
	u32 loss_rate;
	u64 timestamp;
	u8 flags;

	/* Optional fields */
	u64 cwnd;
	u64 ssthresh;
	u64 pacing_rate;
	u64 delivery_rate;

	/* Authentication (optional) */
	u8 endpoint_token[TQUIC_CONG_DATA_TOKEN_LEN];
	u8 hmac[TQUIC_CONG_DATA_HMAC_LEN];
};

/**
 * struct tquic_cong_data_state - Per-connection CONGESTION_DATA state
 * @enabled: Extension negotiated and enabled
 * @privacy_level: What information to share
 * @have_received: Have received valid data from peer
 * @have_sent: Have sent data to peer
 * @received: Most recent received congestion data
 * @last_received_seq: Highest sequence number received (for ordering)
 * @to_send: Data queued for sending
 * @last_sent_seq: Last sequence number sent
 * @last_sent_time: Time of last send (for rate limiting)
 * @outstanding: Number of unacknowledged frames
 * @applied: Whether received data has been applied to CC
 * @apply_phase: Current phase of Careful Resume
 * @apply_start_time: When application started
 * @saved_cwnd: Original cwnd before applying received data
 * @target_cwnd: Target cwnd from received data
 * @validated_rtt: RTT validated against received data
 * @acks_since_apply: ACKs received since apply started
 * @bytes_acked_since_apply: Bytes acked since apply started
 * @bytes_lost_since_apply: Bytes lost since apply started
 * @hmac_key: HMAC key for authentication
 * @hmac_key_set: Whether HMAC key has been configured
 * @lock: Spinlock for state protection
 *
 * Note: This structure maintains both sending and receiving state
 * for CONGESTION_DATA frames on a connection.
 */
struct tquic_cong_data_state {
	/* Feature state */
	bool enabled;
	enum tquic_cong_data_privacy privacy_level;

	/* Receive state */
	bool have_received;
	struct tquic_cong_data received;
	u64 last_received_seq;

	/* Send state */
	bool have_sent;
	struct tquic_cong_data to_send;
	u64 last_sent_seq;
	ktime_t last_sent_time;
	u8 outstanding;

	/* Application state (Careful Resume) */
	bool applied;
	u8 apply_phase;
	ktime_t apply_start_time;
	u64 saved_cwnd;
	u64 target_cwnd;
	u64 validated_rtt;
	u32 acks_since_apply;
	u64 bytes_acked_since_apply;
	u64 bytes_lost_since_apply;

	/* Authentication */
	u8 hmac_key[TQUIC_CONG_DATA_HMAC_KEY_LEN];
	bool hmac_key_set;

	spinlock_t lock;
};

/* Apply phases for Careful Resume */
enum tquic_cong_data_apply_phase {
	TQUIC_CONG_DATA_PHASE_NONE = 0,		/* Not applying */
	TQUIC_CONG_DATA_PHASE_VALIDATING,	/* Validating RTT */
	TQUIC_CONG_DATA_PHASE_RAMPING,		/* Ramping up cwnd */
	TQUIC_CONG_DATA_PHASE_COMPLETE,		/* Application complete */
	TQUIC_CONG_DATA_PHASE_RETREATED,	/* Safe retreat executed */
};

/**
 * struct tquic_cong_data_export - Exported congestion data for session storage
 * @version: Export format version
 * @data: Congestion data snapshot
 * @export_time: When data was exported
 * @server_name_len: Length of server name
 * @server_name: Server hostname for matching
 *
 * This structure is used for persisting congestion data across
 * connection resumption (e.g., with 0-RTT).
 */
struct tquic_cong_data_export {
	u8 version;
	struct tquic_cong_data data;
	u64 export_time;
	u8 server_name_len;
	char server_name[256];
};

/*
 * =============================================================================
 * API Functions
 * =============================================================================
 */

/**
 * tquic_cong_data_init - Initialize CONGESTION_DATA state for a connection
 * @conn: Connection to initialize state for
 *
 * Allocates and initializes the congestion data exchange state.
 * Called during connection setup if the extension is negotiated.
 *
 * Return: 0 on success, negative error code on failure
 */
int tquic_cong_data_init(struct tquic_connection *conn);

/**
 * tquic_cong_data_release - Release CONGESTION_DATA state
 * @conn: Connection to release state for
 *
 * Frees the congestion data exchange state. Called during teardown.
 */
void tquic_cong_data_release(struct tquic_connection *conn);

/**
 * tquic_cong_data_encode - Encode CONGESTION_DATA frame to wire format
 * @data: Congestion data to encode
 * @buf: Output buffer
 * @buflen: Buffer length
 *
 * Encodes a CONGESTION_DATA frame for transmission. The frame type
 * is included in the output.
 *
 * Return: Number of bytes written, or negative error code
 */
ssize_t tquic_cong_data_encode(const struct tquic_cong_data *data,
			       u8 *buf, size_t buflen);

/**
 * tquic_cong_data_decode - Decode CONGESTION_DATA frame from wire format
 * @buf: Input buffer (positioned after frame type)
 * @buflen: Buffer length
 * @data: Output congestion data structure
 *
 * Decodes a CONGESTION_DATA frame. The caller should have already
 * consumed the frame type from the buffer.
 *
 * Return: Number of bytes consumed, or negative error code
 */
ssize_t tquic_cong_data_decode(const u8 *buf, size_t buflen,
			       struct tquic_cong_data *data);

/**
 * tquic_cong_data_generate - Generate CONGESTION_DATA from current CC state
 * @conn: Connection
 * @path: Path to generate data for
 * @data: Output congestion data structure
 *
 * Creates a congestion data snapshot from the current congestion
 * control state of the specified path. Respects privacy settings.
 *
 * Return: 0 on success, negative error code on failure
 */
int tquic_cong_data_generate(struct tquic_connection *conn,
			     struct tquic_path *path,
			     struct tquic_cong_data *data);

/**
 * tquic_cong_data_apply - Apply received congestion data to CC
 * @conn: Connection
 * @path: Path to apply data to
 * @data: Validated congestion data from peer
 *
 * Applies received congestion data using Careful Resume principles.
 * The data is NOT blindly trusted - it is validated and capped to
 * safe ranges, and the congestion window is gradually increased.
 *
 * Return: 0 on success, negative error code on failure/rejection
 */
int tquic_cong_data_apply(struct tquic_connection *conn,
			  struct tquic_path *path,
			  const struct tquic_cong_data *data);

/**
 * tquic_cong_data_validate - Validate received congestion data
 * @conn: Connection
 * @data: Congestion data to validate
 *
 * Validates congestion data values are within acceptable ranges.
 * This does NOT verify HMAC - use tquic_cong_data_verify_hmac() for that.
 *
 * Return: 0 if valid, negative error code if invalid
 */
int tquic_cong_data_validate(struct tquic_connection *conn,
			     const struct tquic_cong_data *data);

/**
 * tquic_cong_data_export - Export congestion data for session storage
 * @conn: Connection
 * @path: Path to export data for
 * @server_name: Server hostname
 * @server_name_len: Length of server name
 * @export: Output export structure
 *
 * Exports the current congestion data for storage (e.g., for use
 * with 0-RTT connection resumption).
 *
 * Return: 0 on success, negative error code on failure
 */
int tquic_cong_data_export(struct tquic_connection *conn,
			   struct tquic_path *path,
			   const char *server_name, u8 server_name_len,
			   struct tquic_cong_data_export *export);

/**
 * tquic_cong_data_import - Import congestion data from stored session
 * @conn: Connection
 * @path: Path to import data for
 * @export: Exported data to import
 *
 * Imports previously exported congestion data. The data is validated
 * and applied using Careful Resume principles.
 *
 * Return: 0 on success, -ESTALE if data expired, other negative on error
 */
int tquic_cong_data_import(struct tquic_connection *conn,
			   struct tquic_path *path,
			   const struct tquic_cong_data_export *export);

/**
 * tquic_cong_data_on_ack - Handle ACK during Careful Resume
 * @conn: Connection
 * @path: Path that received ACK
 * @bytes_acked: Bytes acknowledged
 * @rtt_us: RTT sample in microseconds
 *
 * Called on ACK receipt when Careful Resume is in progress.
 * Validates RTT against saved data and advances the resume phase.
 *
 * Return: true if still in Careful Resume, false if complete/retreated
 */
bool tquic_cong_data_on_ack(struct tquic_connection *conn,
			    struct tquic_path *path,
			    u64 bytes_acked, u64 rtt_us);

/**
 * tquic_cong_data_on_loss - Handle loss during Careful Resume
 * @conn: Connection
 * @path: Path that experienced loss
 * @bytes_lost: Bytes lost
 *
 * Called on loss detection when Careful Resume is in progress.
 * May trigger safe retreat if loss rate is too high.
 */
void tquic_cong_data_on_loss(struct tquic_connection *conn,
			     struct tquic_path *path,
			     u64 bytes_lost);

/**
 * tquic_cong_data_safe_retreat - Execute safe retreat
 * @conn: Connection
 * @path: Path to retreat on
 *
 * Called when Careful Resume detects the path has changed significantly.
 * Retreats to conservative slow start from minimum cwnd.
 */
void tquic_cong_data_safe_retreat(struct tquic_connection *conn,
				  struct tquic_path *path);

/**
 * tquic_cong_data_set_hmac_key - Set HMAC key for authentication
 * @conn: Connection
 * @key: HMAC key (32 bytes)
 * @key_len: Length of key
 *
 * Sets the HMAC key used to authenticate CONGESTION_DATA frames.
 * Should be called before generating or validating authenticated frames.
 *
 * Return: 0 on success, negative error code on failure
 */
int tquic_cong_data_set_hmac_key(struct tquic_connection *conn,
				 const u8 *key, size_t key_len);

/**
 * tquic_cong_data_compute_hmac - Compute HMAC for congestion data
 * @conn: Connection (for HMAC key)
 * @data: Congestion data (hmac field will be filled)
 *
 * Computes HMAC-SHA256 over the congestion data fields and stores
 * the truncated result in the data's hmac field.
 *
 * Return: 0 on success, negative error code on failure
 */
int tquic_cong_data_compute_hmac(struct tquic_connection *conn,
				 struct tquic_cong_data *data);

/**
 * tquic_cong_data_verify_hmac - Verify HMAC for congestion data
 * @conn: Connection (for HMAC key)
 * @data: Congestion data to verify
 *
 * Verifies the HMAC authentication tag in the congestion data.
 *
 * Return: 0 if valid, -EBADMSG if invalid, other negative on error
 */
int tquic_cong_data_verify_hmac(struct tquic_connection *conn,
				const struct tquic_cong_data *data);

/**
 * tquic_cong_data_set_privacy - Set privacy level for congestion data sharing
 * @conn: Connection
 * @level: Privacy level to set
 *
 * Controls what information is included in generated CONGESTION_DATA frames.
 *
 * Return: 0 on success, negative error code on failure
 */
int tquic_cong_data_set_privacy(struct tquic_connection *conn,
				enum tquic_cong_data_privacy level);

/**
 * tquic_cong_data_is_enabled - Check if extension is enabled
 * @conn: Connection
 *
 * Return: true if CONGESTION_DATA extension is negotiated and enabled
 */
bool tquic_cong_data_is_enabled(struct tquic_connection *conn);

/**
 * tquic_cong_data_should_send - Check if we should send congestion data
 * @conn: Connection
 * @path: Path to check
 *
 * Checks if conditions are met to send a CONGESTION_DATA frame:
 * - Extension enabled
 * - Not rate limited
 * - Privacy allows sharing
 * - Outstanding frame count under limit
 *
 * Return: true if we should send, false otherwise
 */
bool tquic_cong_data_should_send(struct tquic_connection *conn,
				 struct tquic_path *path);

/**
 * tquic_cong_data_on_frame_acked - Handle ACK of CONGESTION_DATA frame
 * @conn: Connection
 * @seq_num: Sequence number of acked frame
 *
 * Called when a sent CONGESTION_DATA frame is acknowledged.
 * Decrements outstanding frame count.
 */
void tquic_cong_data_on_frame_acked(struct tquic_connection *conn, u64 seq_num);

/**
 * tquic_cong_data_on_frame_lost - Handle loss of CONGESTION_DATA frame
 * @conn: Connection
 * @seq_num: Sequence number of lost frame
 *
 * Called when a sent CONGESTION_DATA frame is detected as lost.
 * May trigger retransmission.
 */
void tquic_cong_data_on_frame_lost(struct tquic_connection *conn, u64 seq_num);

/**
 * tquic_cong_data_handle_frame - Handle received CONGESTION_DATA frame
 * @conn: Connection
 * @buf: Frame payload (after frame type)
 * @buflen: Payload length
 *
 * Called by frame handler when CONGESTION_DATA frame is received.
 * Decodes, validates, and optionally applies the received data.
 *
 * Return: Number of bytes consumed, or negative error code
 */
ssize_t tquic_cong_data_handle_frame(struct tquic_connection *conn,
				     const u8 *buf, size_t buflen);

/**
 * tquic_cong_data_generate_token - Generate endpoint token
 * @conn: Connection
 * @token: Output buffer (TQUIC_CONG_DATA_TOKEN_LEN bytes)
 *
 * Generates a unique endpoint token for identifying the source
 * of congestion data frames.
 *
 * Return: 0 on success, negative error code on failure
 */
int tquic_cong_data_generate_token(struct tquic_connection *conn, u8 *token);

/**
 * tquic_cong_data_get_apply_phase - Get current Careful Resume phase
 * @conn: Connection
 *
 * Return: Current apply phase
 */
enum tquic_cong_data_apply_phase tquic_cong_data_get_apply_phase(
	struct tquic_connection *conn);

/**
 * tquic_cong_data_get_phase_name - Get string name for apply phase
 * @phase: Apply phase
 *
 * Return: Human-readable phase name
 */
const char *tquic_cong_data_get_phase_name(enum tquic_cong_data_apply_phase phase);

/*
 * =============================================================================
 * 0-RTT Integration
 * =============================================================================
 */

/**
 * tquic_cong_data_store_for_zero_rtt - Store data for 0-RTT resumption
 * @conn: Connection
 * @path: Path to store data for
 * @server_name: Server hostname
 * @server_name_len: Length of server name
 *
 * Stores the current congestion data for use with 0-RTT connection
 * resumption to the same server.
 *
 * Return: 0 on success, negative error code on failure
 */
int tquic_cong_data_store_for_zero_rtt(struct tquic_connection *conn,
				       struct tquic_path *path,
				       const char *server_name,
				       u8 server_name_len);

/**
 * tquic_cong_data_load_for_zero_rtt - Load data for 0-RTT resumption
 * @conn: Connection
 * @path: Path to load data for
 * @server_name: Server hostname
 * @server_name_len: Length of server name
 *
 * Attempts to load previously stored congestion data for 0-RTT
 * connection resumption.
 *
 * Return: 0 on success, -ENOENT if not found, other negative on error
 */
int tquic_cong_data_load_for_zero_rtt(struct tquic_connection *conn,
				      struct tquic_path *path,
				      const char *server_name,
				      u8 server_name_len);

/*
 * =============================================================================
 * Module Init/Exit
 * =============================================================================
 */

/**
 * tquic_cong_data_module_init - Initialize CONGESTION_DATA subsystem
 *
 * Called during module load.
 *
 * Return: 0 on success, negative error code on failure
 */
int __init tquic_cong_data_module_init(void);

/**
 * tquic_cong_data_module_exit - Clean up CONGESTION_DATA subsystem
 *
 * Called during module unload.
 */
void __exit tquic_cong_data_module_exit(void);

#endif /* _TQUIC_CONG_DATA_H */
