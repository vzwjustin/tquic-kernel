/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * TQUIC: QUIC Multipath Frame Definitions
 *
 * Copyright (c) 2026 Linux Foundation
 *
 * Frame definitions and APIs for QUIC Multipath Extension (RFC 9369).
 * This header defines the multipath-specific frame types:
 *   - PATH_ABANDON (0x17)
 *   - MP_NEW_CONNECTION_ID (0x40)
 *   - MP_RETIRE_CONNECTION_ID (0x41)
 *   - MP_ACK (0x42)
 *   - PATH_STATUS (0x43)
 */

#ifndef _TQUIC_MULTIPATH_MP_FRAME_H
#define _TQUIC_MULTIPATH_MP_FRAME_H

#include <linux/types.h>
#include <linux/list.h>
#include <net/tquic.h>

/*
 * Multipath Frame Types (RFC 9369)
 *
 * These frame types are used when multipath is negotiated via the
 * enable_multipath transport parameter. The frame types are assigned
 * in the QUIC multipath extension space.
 */
#define TQUIC_MP_FRAME_PATH_ABANDON		0x15c0
#define TQUIC_MP_FRAME_MP_NEW_CONNECTION_ID	0x40
#define TQUIC_MP_FRAME_MP_RETIRE_CONNECTION_ID	0x41
#define TQUIC_MP_FRAME_MP_ACK			0x42
#define TQUIC_MP_FRAME_MP_ACK_ECN		0x43
#define TQUIC_MP_FRAME_PATH_STATUS		0x15c08

/*
 * PATH_STATUS values (RFC 9369 Section 5.6)
 */
#define TQUIC_PATH_STATUS_STANDBY	0
#define TQUIC_PATH_STATUS_AVAILABLE	1
#define TQUIC_PATH_STATUS_ABANDONED	2

/*
 * Transport Parameter IDs for Multipath (RFC 9369 Section 3)
 */
#define TQUIC_TP_ENABLE_MULTIPATH	0x0f00
#define TQUIC_TP_INITIAL_MAX_PATHS	0x0f01

/*
 * Multipath Transport Parameter Values
 */
#define TQUIC_MP_MODE_DISABLED		0
#define TQUIC_MP_MODE_ENABLED		1

/*
 * Maximum ACK ranges in MP_ACK frame
 */
#define TQUIC_MP_MAX_ACK_RANGES		256

/*
 * Maximum reason phrase length for PATH_ABANDON
 */
#define TQUIC_MP_MAX_REASON_LEN		256

/*
 * Stateless reset token length
 */
#define TQUIC_MP_RESET_TOKEN_LEN	16

/**
 * struct tquic_mp_path_abandon - PATH_ABANDON frame (RFC 9369 Section 5.3)
 * @path_id: Identifier of the path being abandoned
 * @error_code: Error code indicating reason for abandonment
 * @reason_len: Length of the reason phrase
 * @reason: Human-readable reason phrase (optional)
 *
 * PATH_ABANDON Frame {
 *   Type (i) = 0x17,
 *   Path Identifier (i),
 *   Error Code (i),
 *   Reason Phrase Length (i),
 *   Reason Phrase (..),
 * }
 */
struct tquic_mp_path_abandon {
	u64 path_id;
	u64 error_code;
	u64 reason_len;
	u8 reason[TQUIC_MP_MAX_REASON_LEN];
};

/**
 * struct tquic_mp_new_connection_id - MP_NEW_CONNECTION_ID frame
 * @path_id: Path this CID is associated with
 * @seq_num: Sequence number for this CID
 * @retire_prior_to: Retire CIDs with sequence numbers less than this
 * @cid_len: Length of the connection ID
 * @cid: The connection ID bytes
 * @stateless_reset_token: 16-byte stateless reset token
 *
 * MP_NEW_CONNECTION_ID Frame {
 *   Type (i) = 0x40,
 *   Path Identifier (i),
 *   Sequence Number (i),
 *   Retire Prior To (i),
 *   Length (8),
 *   Connection ID (8..160),
 *   Stateless Reset Token (128),
 * }
 */
struct tquic_mp_new_connection_id {
	u64 path_id;
	u64 seq_num;
	u64 retire_prior_to;
	u8 cid_len;
	u8 cid[TQUIC_MAX_CID_LEN];
	u8 stateless_reset_token[TQUIC_MP_RESET_TOKEN_LEN];
};

/**
 * struct tquic_mp_retire_connection_id - MP_RETIRE_CONNECTION_ID frame
 * @path_id: Path the CID belongs to
 * @seq_num: Sequence number of the CID to retire
 *
 * MP_RETIRE_CONNECTION_ID Frame {
 *   Type (i) = 0x41,
 *   Path Identifier (i),
 *   Sequence Number (i),
 * }
 */
struct tquic_mp_retire_connection_id {
	u64 path_id;
	u64 seq_num;
};

/**
 * struct tquic_mp_ack_range - ACK range within MP_ACK frame
 * @gap: Number of unacknowledged packets before this range minus 1
 * @ack_range_len: Number of acknowledged packets in this range minus 1
 */
struct tquic_mp_ack_range {
	u64 gap;
	u64 ack_range_len;
};

/**
 * struct tquic_mp_ack - MP_ACK frame (RFC 9369 Section 5.4)
 * @path_id: Path this ACK applies to
 * @largest_ack: Largest packet number being acknowledged
 * @ack_delay: ACK delay in microseconds (after exponent applied)
 * @ack_range_count: Number of additional ACK ranges
 * @first_ack_range: Size of first ACK range
 * @ranges: Additional ACK ranges
 * @has_ecn: Whether ECN counts are present (frame type 0x43)
 * @ect0_count: ECT(0) counter
 * @ect1_count: ECT(1) counter
 * @ecn_ce_count: ECN-CE counter
 *
 * MP_ACK Frame {
 *   Type (i) = 0x42..0x43,
 *   Path Identifier (i),
 *   Largest Acknowledged (i),
 *   ACK Delay (i),
 *   ACK Range Count (i),
 *   First ACK Range (i),
 *   ACK Range (..) ...,
 *   [ECN Counts (..)],
 * }
 */
struct tquic_mp_ack {
	u64 path_id;
	u64 largest_ack;
	u64 ack_delay;
	u64 ack_range_count;
	u64 first_ack_range;
	struct tquic_mp_ack_range ranges[TQUIC_MP_MAX_ACK_RANGES];
	bool has_ecn;
	u64 ect0_count;
	u64 ect1_count;
	u64 ecn_ce_count;
};

/**
 * struct tquic_mp_path_status - PATH_STATUS frame (RFC 9369 Section 5.6)
 * @path_id: Identifier of the path
 * @seq_num: Sequence number for ordering PATH_STATUS frames
 * @status: Path status (standby, available, etc.)
 * @priority: Path priority level (0 = highest)
 *
 * PATH_STATUS Frame {
 *   Type (i) = 0x44,
 *   Path Identifier (i),
 *   Path Status Sequence Number (i),
 *   Path Status (i),
 *   Priority (i),
 * }
 */
struct tquic_mp_path_status {
	u64 path_id;
	u64 seq_num;
	u64 status;
	u64 priority;
};

/**
 * struct tquic_mp_transport_params - Multipath transport parameters
 * @enable_multipath: Whether multipath is enabled (0x0f00)
 * @initial_max_paths: Maximum number of paths (0x0f01)
 */
struct tquic_mp_transport_params {
	u8 enable_multipath;
	u64 initial_max_paths;
};

/*
 * Frame parsing functions
 */

/**
 * tquic_mp_parse_path_abandon - Parse PATH_ABANDON frame
 * @buf: Input buffer
 * @len: Buffer length
 * @frame: Output parsed frame
 *
 * Returns number of bytes consumed or negative error.
 */
int tquic_mp_parse_path_abandon(const u8 *buf, size_t len,
				struct tquic_mp_path_abandon *frame);

/**
 * tquic_mp_parse_new_connection_id - Parse MP_NEW_CONNECTION_ID frame
 * @buf: Input buffer
 * @len: Buffer length
 * @frame: Output parsed frame
 *
 * Returns number of bytes consumed or negative error.
 */
int tquic_mp_parse_new_connection_id(const u8 *buf, size_t len,
				     struct tquic_mp_new_connection_id *frame);

/**
 * tquic_mp_parse_retire_connection_id - Parse MP_RETIRE_CONNECTION_ID frame
 * @buf: Input buffer
 * @len: Buffer length
 * @frame: Output parsed frame
 *
 * Returns number of bytes consumed or negative error.
 */
int tquic_mp_parse_retire_connection_id(const u8 *buf, size_t len,
					struct tquic_mp_retire_connection_id *frame);

/**
 * tquic_mp_parse_ack - Parse MP_ACK frame
 * @buf: Input buffer
 * @len: Buffer length
 * @frame: Output parsed frame
 * @ack_delay_exponent: ACK delay exponent for conversion
 *
 * Returns number of bytes consumed or negative error.
 */
int tquic_mp_parse_ack(const u8 *buf, size_t len,
		       struct tquic_mp_ack *frame, u8 ack_delay_exponent);

/**
 * tquic_mp_parse_path_status - Parse PATH_STATUS frame
 * @buf: Input buffer
 * @len: Buffer length
 * @frame: Output parsed frame
 *
 * Returns number of bytes consumed or negative error.
 */
int tquic_mp_parse_path_status(const u8 *buf, size_t len,
			       struct tquic_mp_path_status *frame);

/*
 * Frame generation functions
 */

/**
 * tquic_mp_write_path_abandon - Write PATH_ABANDON frame
 * @frame: Frame to write
 * @buf: Output buffer
 * @len: Buffer length
 *
 * Returns number of bytes written or negative error.
 */
int tquic_mp_write_path_abandon(const struct tquic_mp_path_abandon *frame,
				u8 *buf, size_t len);

/**
 * tquic_mp_write_new_connection_id - Write MP_NEW_CONNECTION_ID frame
 * @frame: Frame to write
 * @buf: Output buffer
 * @len: Buffer length
 *
 * Returns number of bytes written or negative error.
 */
int tquic_mp_write_new_connection_id(const struct tquic_mp_new_connection_id *frame,
				     u8 *buf, size_t len);

/**
 * tquic_mp_write_retire_connection_id - Write MP_RETIRE_CONNECTION_ID frame
 * @frame: Frame to write
 * @buf: Output buffer
 * @len: Buffer length
 *
 * Returns number of bytes written or negative error.
 */
int tquic_mp_write_retire_connection_id(const struct tquic_mp_retire_connection_id *frame,
					u8 *buf, size_t len);

/**
 * tquic_mp_write_ack - Write MP_ACK frame
 * @frame: Frame to write
 * @buf: Output buffer
 * @len: Buffer length
 * @ack_delay_exponent: ACK delay exponent for encoding
 *
 * Returns number of bytes written or negative error.
 */
int tquic_mp_write_ack(const struct tquic_mp_ack *frame,
		       u8 *buf, size_t len, u8 ack_delay_exponent);

/**
 * tquic_mp_write_path_status - Write PATH_STATUS frame
 * @frame: Frame to write
 * @buf: Output buffer
 * @len: Buffer length
 *
 * Returns number of bytes written or negative error.
 */
int tquic_mp_write_path_status(const struct tquic_mp_path_status *frame,
			       u8 *buf, size_t len);

/*
 * Frame size calculation functions
 */

/**
 * tquic_mp_path_abandon_size - Calculate encoded size of PATH_ABANDON
 * @frame: Frame to measure
 *
 * Returns encoded size in bytes.
 */
size_t tquic_mp_path_abandon_size(const struct tquic_mp_path_abandon *frame);

/**
 * tquic_mp_new_connection_id_size - Calculate encoded size of MP_NEW_CONNECTION_ID
 * @frame: Frame to measure
 *
 * Returns encoded size in bytes.
 */
size_t tquic_mp_new_connection_id_size(const struct tquic_mp_new_connection_id *frame);

/**
 * tquic_mp_retire_connection_id_size - Calculate encoded size of MP_RETIRE_CONNECTION_ID
 * @frame: Frame to measure
 *
 * Returns encoded size in bytes.
 */
size_t tquic_mp_retire_connection_id_size(const struct tquic_mp_retire_connection_id *frame);

/**
 * tquic_mp_ack_size - Calculate encoded size of MP_ACK
 * @frame: Frame to measure
 *
 * Returns encoded size in bytes.
 */
size_t tquic_mp_ack_size(const struct tquic_mp_ack *frame);

/**
 * tquic_mp_path_status_size - Calculate encoded size of PATH_STATUS
 * @frame: Frame to measure
 *
 * Returns encoded size in bytes.
 */
size_t tquic_mp_path_status_size(const struct tquic_mp_path_status *frame);

/*
 * Frame type checking
 */

/**
 * tquic_is_mp_frame - Check if frame type is a multipath frame
 * @frame_type: Frame type to check
 *
 * Returns true if the frame type is a multipath-specific frame.
 */
static inline bool tquic_is_mp_frame(u64 frame_type)
{
	switch (frame_type) {
	case TQUIC_MP_FRAME_PATH_ABANDON:
	case TQUIC_MP_FRAME_MP_NEW_CONNECTION_ID:
	case TQUIC_MP_FRAME_MP_RETIRE_CONNECTION_ID:
	case TQUIC_MP_FRAME_MP_ACK:
	case TQUIC_MP_FRAME_MP_ACK_ECN:
	case TQUIC_MP_FRAME_PATH_STATUS:
		return true;
	default:
		return false;
	}
}

/**
 * tquic_is_mp_ack_frame - Check if frame type is an MP_ACK frame
 * @frame_type: Frame type to check
 *
 * Returns true if the frame is MP_ACK or MP_ACK_ECN.
 */
static inline bool tquic_is_mp_ack_frame(u64 frame_type)
{
	return frame_type == TQUIC_MP_FRAME_MP_ACK ||
	       frame_type == TQUIC_MP_FRAME_MP_ACK_ECN;
}

/*
 * Module initialization
 */

/**
 * tquic_mp_frame_init - Initialize multipath frame module
 *
 * Returns 0 on success or negative error.
 */
int __init tquic_mp_frame_init(void);

/**
 * tquic_mp_frame_exit - Cleanup multipath frame module
 */
void __exit tquic_mp_frame_exit(void);

#endif /* _TQUIC_MULTIPATH_MP_FRAME_H */
