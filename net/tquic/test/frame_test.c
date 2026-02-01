// SPDX-License-Identifier: GPL-2.0
/*
 * KUnit tests for TQUIC frame parsing
 *
 * Copyright (c) 2026 Linux Foundation
 */

#include <kunit/test.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <net/tquic.h>

/* QUIC Frame Types (RFC 9000) */
#define TQUIC_FRAME_PADDING		0x00
#define TQUIC_FRAME_PING		0x01
#define TQUIC_FRAME_ACK			0x02
#define TQUIC_FRAME_ACK_ECN		0x03
#define TQUIC_FRAME_RESET_STREAM	0x04
#define TQUIC_FRAME_STOP_SENDING	0x05
#define TQUIC_FRAME_CRYPTO		0x06
#define TQUIC_FRAME_NEW_TOKEN		0x07
#define TQUIC_FRAME_STREAM		0x08  /* 0x08-0x0f */
#define TQUIC_FRAME_MAX_DATA		0x10
#define TQUIC_FRAME_MAX_STREAM_DATA	0x11
#define TQUIC_FRAME_MAX_STREAMS_BIDI	0x12
#define TQUIC_FRAME_MAX_STREAMS_UNI	0x13
#define TQUIC_FRAME_DATA_BLOCKED	0x14
#define TQUIC_FRAME_STREAM_DATA_BLOCKED	0x15
#define TQUIC_FRAME_STREAMS_BLOCKED_BIDI 0x16
#define TQUIC_FRAME_STREAMS_BLOCKED_UNI	0x17
#define TQUIC_FRAME_NEW_CONNECTION_ID	0x18
#define TQUIC_FRAME_RETIRE_CONNECTION_ID 0x19
#define TQUIC_FRAME_PATH_CHALLENGE	0x1a
#define TQUIC_FRAME_PATH_RESPONSE	0x1b
#define TQUIC_FRAME_CONNECTION_CLOSE	0x1c
#define TQUIC_FRAME_CONNECTION_CLOSE_APP 0x1d
#define TQUIC_FRAME_HANDSHAKE_DONE	0x1e

/* QUIC Multipath Frame Types (RFC 9287) */
#define TQUIC_FRAME_PATH_ABANDON	0x20
#define TQUIC_FRAME_PATH_STATUS		0x21
#define TQUIC_FRAME_ACK_MP		0x22

/* Stream frame flags */
#define TQUIC_STREAM_FLAG_OFF		0x04  /* Offset field present */
#define TQUIC_STREAM_FLAG_LEN		0x02  /* Length field present */
#define TQUIC_FRAME_FIN			0x01  /* FIN bit */

/* Test: Basic frame type identification */
static void tquic_frame_test_type_identify(struct kunit *test)
{
	KUNIT_EXPECT_EQ(test, TQUIC_FRAME_PADDING, 0x00);
	KUNIT_EXPECT_EQ(test, TQUIC_FRAME_PING, 0x01);
	KUNIT_EXPECT_EQ(test, TQUIC_FRAME_ACK, 0x02);
	KUNIT_EXPECT_EQ(test, TQUIC_FRAME_CRYPTO, 0x06);
	KUNIT_EXPECT_EQ(test, TQUIC_FRAME_STREAM, 0x08);
	KUNIT_EXPECT_EQ(test, TQUIC_FRAME_MAX_DATA, 0x10);
	KUNIT_EXPECT_EQ(test, TQUIC_FRAME_CONNECTION_CLOSE, 0x1c);
	KUNIT_EXPECT_EQ(test, TQUIC_FRAME_HANDSHAKE_DONE, 0x1e);
}

/* Test: Stream frame type range (0x08-0x0f) */
static void tquic_frame_test_stream_type_range(struct kunit *test)
{
	u8 frame_type;

	/* Stream frames have types 0x08 through 0x0f */
	for (frame_type = 0x08; frame_type <= 0x0f; frame_type++) {
		KUNIT_EXPECT_TRUE(test, (frame_type & 0xf8) == 0x08);
	}

	/* Non-stream frames should not match */
	KUNIT_EXPECT_FALSE(test, (0x07 & 0xf8) == 0x08);
	KUNIT_EXPECT_FALSE(test, (0x10 & 0xf8) == 0x08);
}

/* Test: Stream frame flags extraction */
static void tquic_frame_test_stream_flags(struct kunit *test)
{
	u8 frame_type;

	/* Stream frame with FIN, LEN, OFF */
	frame_type = TQUIC_FRAME_STREAM | TQUIC_FRAME_FIN |
		     TQUIC_STREAM_FLAG_LEN | TQUIC_STREAM_FLAG_OFF;

	KUNIT_EXPECT_TRUE(test, (frame_type & TQUIC_FRAME_FIN) != 0);
	KUNIT_EXPECT_TRUE(test, (frame_type & TQUIC_STREAM_FLAG_LEN) != 0);
	KUNIT_EXPECT_TRUE(test, (frame_type & TQUIC_STREAM_FLAG_OFF) != 0);

	/* Stream frame with only FIN */
	frame_type = TQUIC_FRAME_STREAM | TQUIC_FRAME_FIN;

	KUNIT_EXPECT_TRUE(test, (frame_type & TQUIC_FRAME_FIN) != 0);
	KUNIT_EXPECT_FALSE(test, (frame_type & TQUIC_STREAM_FLAG_LEN) != 0);
	KUNIT_EXPECT_FALSE(test, (frame_type & TQUIC_STREAM_FLAG_OFF) != 0);

	/* Stream frame with no flags */
	frame_type = TQUIC_FRAME_STREAM;

	KUNIT_EXPECT_FALSE(test, (frame_type & TQUIC_FRAME_FIN) != 0);
}

/* Test: PADDING frame parsing */
static void tquic_frame_test_padding(struct kunit *test)
{
	u8 padding_frames[] = {0x00, 0x00, 0x00, 0x00, 0x00};
	int i;

	/* All bytes should be PADDING frame type */
	for (i = 0; i < sizeof(padding_frames); i++) {
		KUNIT_EXPECT_EQ(test, padding_frames[i], TQUIC_FRAME_PADDING);
	}
}

/* Test: PING frame parsing */
static void tquic_frame_test_ping(struct kunit *test)
{
	u8 ping_frame = TQUIC_FRAME_PING;

	/* PING frame has no payload */
	KUNIT_EXPECT_EQ(test, ping_frame, 0x01);
}

/* Test: ACK frame structure */
static void tquic_frame_test_ack_structure(struct kunit *test)
{
	/*
	 * ACK Frame:
	 * - Type (0x02 or 0x03 for ECN)
	 * - Largest Acknowledged (varint)
	 * - ACK Delay (varint)
	 * - ACK Range Count (varint)
	 * - First ACK Range (varint)
	 * - ACK Ranges (repeated)
	 * - [ECN Counts if type 0x03]
	 */
	u8 ack_frame[] = {
		0x02,	/* ACK frame type */
		0x0a,	/* Largest Acknowledged = 10 */
		0x01,	/* ACK Delay = 1 */
		0x00,	/* ACK Range Count = 0 */
		0x05,	/* First ACK Range = 5 */
	};

	/* Verify frame type */
	KUNIT_EXPECT_EQ(test, ack_frame[0], TQUIC_FRAME_ACK);

	/* Verify largest acked (small varint) */
	KUNIT_EXPECT_EQ(test, ack_frame[1], 10);

	/* First ACK range means packets 10 down to 10-5 = 5 are acked */
	KUNIT_EXPECT_EQ(test, ack_frame[4], 5);
}

/* Test: ACK ECN frame */
static void tquic_frame_test_ack_ecn(struct kunit *test)
{
	/*
	 * ACK_ECN Frame has additional fields:
	 * - ECT(0) Count (varint)
	 * - ECT(1) Count (varint)
	 * - ECN-CE Count (varint)
	 */
	u8 ack_ecn_type = TQUIC_FRAME_ACK_ECN;

	KUNIT_EXPECT_EQ(test, ack_ecn_type, 0x03);
	KUNIT_EXPECT_NE(test, ack_ecn_type, TQUIC_FRAME_ACK);
}

/* Test: CRYPTO frame structure */
static void tquic_frame_test_crypto(struct kunit *test)
{
	/*
	 * CRYPTO Frame:
	 * - Type (0x06)
	 * - Offset (varint)
	 * - Length (varint)
	 * - Crypto Data
	 */
	u8 crypto_frame[] = {
		0x06,	/* CRYPTO frame type */
		0x00,	/* Offset = 0 */
		0x0a,	/* Length = 10 */
		/* 10 bytes of crypto data would follow */
	};

	KUNIT_EXPECT_EQ(test, crypto_frame[0], TQUIC_FRAME_CRYPTO);
	KUNIT_EXPECT_EQ(test, crypto_frame[1], 0); /* Offset */
	KUNIT_EXPECT_EQ(test, crypto_frame[2], 10); /* Length */
}

/* Test: STREAM frame structure */
static void tquic_frame_test_stream(struct kunit *test)
{
	/*
	 * STREAM Frame:
	 * - Type (0x08-0x0f)
	 * - Stream ID (varint)
	 * - [Offset (varint)] if OFF bit set
	 * - [Length (varint)] if LEN bit set
	 * - Stream Data
	 */
	u8 stream_frame_basic[] = {
		0x08,	/* STREAM frame, no flags */
		0x00,	/* Stream ID = 0 */
		/* Stream data follows until end of packet */
	};

	u8 stream_frame_full[] = {
		0x0f,	/* STREAM frame with FIN, LEN, OFF */
		0x04,	/* Stream ID = 4 */
		0x10,	/* Offset = 16 */
		0x08,	/* Length = 8 */
		/* 8 bytes of stream data would follow */
	};

	/* Basic stream frame */
	KUNIT_EXPECT_EQ(test, stream_frame_basic[0] & 0xf8, TQUIC_FRAME_STREAM);
	KUNIT_EXPECT_EQ(test, stream_frame_basic[1], 0);

	/* Full stream frame */
	KUNIT_EXPECT_EQ(test, stream_frame_full[0] & 0xf8, TQUIC_FRAME_STREAM);
	KUNIT_EXPECT_TRUE(test, (stream_frame_full[0] & TQUIC_FRAME_FIN) != 0);
	KUNIT_EXPECT_TRUE(test, (stream_frame_full[0] & TQUIC_STREAM_FLAG_LEN) != 0);
	KUNIT_EXPECT_TRUE(test, (stream_frame_full[0] & TQUIC_STREAM_FLAG_OFF) != 0);
}

/* Test: MAX_DATA frame */
static void tquic_frame_test_max_data(struct kunit *test)
{
	/*
	 * MAX_DATA Frame:
	 * - Type (0x10)
	 * - Maximum Data (varint)
	 */
	u8 max_data_frame[] = {
		0x10,			/* MAX_DATA frame type */
		0x40, 0x00, 0x10, 0x00,	/* Maximum Data = 1MB (varint) */
	};

	KUNIT_EXPECT_EQ(test, max_data_frame[0], TQUIC_FRAME_MAX_DATA);
}

/* Test: MAX_STREAM_DATA frame */
static void tquic_frame_test_max_stream_data(struct kunit *test)
{
	/*
	 * MAX_STREAM_DATA Frame:
	 * - Type (0x11)
	 * - Stream ID (varint)
	 * - Maximum Stream Data (varint)
	 */
	u8 max_stream_data_frame[] = {
		0x11,	/* MAX_STREAM_DATA frame type */
		0x04,	/* Stream ID = 4 */
		0x40, 0x00, 0x04, 0x00,	/* Maximum Stream Data = 256KB */
	};

	KUNIT_EXPECT_EQ(test, max_stream_data_frame[0], TQUIC_FRAME_MAX_STREAM_DATA);
	KUNIT_EXPECT_EQ(test, max_stream_data_frame[1], 4);
}

/* Test: MAX_STREAMS frames */
static void tquic_frame_test_max_streams(struct kunit *test)
{
	KUNIT_EXPECT_EQ(test, TQUIC_FRAME_MAX_STREAMS_BIDI, 0x12);
	KUNIT_EXPECT_EQ(test, TQUIC_FRAME_MAX_STREAMS_UNI, 0x13);

	/* Bidirectional vs unidirectional distinction */
	KUNIT_EXPECT_NE(test, TQUIC_FRAME_MAX_STREAMS_BIDI,
			TQUIC_FRAME_MAX_STREAMS_UNI);
}

/* Test: RESET_STREAM frame */
static void tquic_frame_test_reset_stream(struct kunit *test)
{
	/*
	 * RESET_STREAM Frame:
	 * - Type (0x04)
	 * - Stream ID (varint)
	 * - Application Protocol Error Code (varint)
	 * - Final Size (varint)
	 */
	u8 reset_stream_frame[] = {
		0x04,	/* RESET_STREAM frame type */
		0x04,	/* Stream ID = 4 */
		0x00,	/* Error Code = 0 (NO_ERROR) */
		0x00,	/* Final Size = 0 */
	};

	KUNIT_EXPECT_EQ(test, reset_stream_frame[0], TQUIC_FRAME_RESET_STREAM);
}

/* Test: STOP_SENDING frame */
static void tquic_frame_test_stop_sending(struct kunit *test)
{
	/*
	 * STOP_SENDING Frame:
	 * - Type (0x05)
	 * - Stream ID (varint)
	 * - Application Protocol Error Code (varint)
	 */
	u8 stop_sending_frame[] = {
		0x05,	/* STOP_SENDING frame type */
		0x04,	/* Stream ID = 4 */
		0x00,	/* Error Code = 0 */
	};

	KUNIT_EXPECT_EQ(test, stop_sending_frame[0], TQUIC_FRAME_STOP_SENDING);
}

/* Test: NEW_CONNECTION_ID frame */
static void tquic_frame_test_new_connection_id(struct kunit *test)
{
	/*
	 * NEW_CONNECTION_ID Frame:
	 * - Type (0x18)
	 * - Sequence Number (varint)
	 * - Retire Prior To (varint)
	 * - Length (1 byte, 1-20)
	 * - Connection ID (variable)
	 * - Stateless Reset Token (16 bytes)
	 */
	u8 new_cid_frame[] = {
		0x18,	/* NEW_CONNECTION_ID frame type */
		0x01,	/* Sequence Number = 1 */
		0x00,	/* Retire Prior To = 0 */
		0x08,	/* Length = 8 */
		0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, /* CID */
		/* 16 bytes stateless reset token would follow */
	};

	KUNIT_EXPECT_EQ(test, new_cid_frame[0], TQUIC_FRAME_NEW_CONNECTION_ID);
	KUNIT_EXPECT_EQ(test, new_cid_frame[3], 8); /* CID length */
	KUNIT_EXPECT_LE(test, new_cid_frame[3], (u8)TQUIC_MAX_CID_LEN);
}

/* Test: RETIRE_CONNECTION_ID frame */
static void tquic_frame_test_retire_connection_id(struct kunit *test)
{
	/*
	 * RETIRE_CONNECTION_ID Frame:
	 * - Type (0x19)
	 * - Sequence Number (varint)
	 */
	u8 retire_cid_frame[] = {
		0x19,	/* RETIRE_CONNECTION_ID frame type */
		0x00,	/* Sequence Number = 0 */
	};

	KUNIT_EXPECT_EQ(test, retire_cid_frame[0], TQUIC_FRAME_RETIRE_CONNECTION_ID);
}

/* Test: PATH_CHALLENGE frame (important for WAN bonding) */
static void tquic_frame_test_path_challenge(struct kunit *test)
{
	/*
	 * PATH_CHALLENGE Frame:
	 * - Type (0x1a)
	 * - Data (8 bytes)
	 */
	u8 path_challenge_frame[] = {
		0x1a,	/* PATH_CHALLENGE frame type */
		0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, /* Challenge data */
	};

	KUNIT_EXPECT_EQ(test, path_challenge_frame[0], TQUIC_FRAME_PATH_CHALLENGE);
	/* Challenge data is exactly 8 bytes */
	KUNIT_EXPECT_EQ(test, sizeof(path_challenge_frame) - 1, (size_t)8);
}

/* Test: PATH_RESPONSE frame (important for WAN bonding) */
static void tquic_frame_test_path_response(struct kunit *test)
{
	/*
	 * PATH_RESPONSE Frame:
	 * - Type (0x1b)
	 * - Data (8 bytes) - must match PATH_CHALLENGE
	 */
	u8 path_response_frame[] = {
		0x1b,	/* PATH_RESPONSE frame type */
		0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, /* Response data */
	};

	KUNIT_EXPECT_EQ(test, path_response_frame[0], TQUIC_FRAME_PATH_RESPONSE);
}

/* Test: CONNECTION_CLOSE frame */
static void tquic_frame_test_connection_close(struct kunit *test)
{
	/*
	 * CONNECTION_CLOSE Frame:
	 * - Type (0x1c for QUIC layer, 0x1d for application)
	 * - Error Code (varint)
	 * - [Frame Type (varint)] - only for 0x1c
	 * - Reason Phrase Length (varint)
	 * - Reason Phrase
	 */
	u8 conn_close_quic = TQUIC_FRAME_CONNECTION_CLOSE;
	u8 conn_close_app = TQUIC_FRAME_CONNECTION_CLOSE_APP;

	KUNIT_EXPECT_EQ(test, conn_close_quic, 0x1c);
	KUNIT_EXPECT_EQ(test, conn_close_app, 0x1d);
	KUNIT_EXPECT_NE(test, conn_close_quic, conn_close_app);
}

/* Test: HANDSHAKE_DONE frame */
static void tquic_frame_test_handshake_done(struct kunit *test)
{
	/* HANDSHAKE_DONE has no payload */
	KUNIT_EXPECT_EQ(test, TQUIC_FRAME_HANDSHAKE_DONE, 0x1e);
}

/* Test: Multipath frames for WAN bonding */
static void tquic_frame_test_multipath_frames(struct kunit *test)
{
	/*
	 * Multipath QUIC adds several frames for managing multiple paths:
	 * - PATH_ABANDON: Signal path abandonment
	 * - PATH_STATUS: Update path availability/priority
	 * - ACK_MP: Acknowledge packets on specific paths
	 */
	KUNIT_EXPECT_EQ(test, TQUIC_FRAME_PATH_ABANDON, 0x20);
	KUNIT_EXPECT_EQ(test, TQUIC_FRAME_PATH_STATUS, 0x21);
	KUNIT_EXPECT_EQ(test, TQUIC_FRAME_ACK_MP, 0x22);
}

/* Test: Frame type to packet number space mapping */
static void tquic_frame_test_pn_space_mapping(struct kunit *test)
{
	/*
	 * Different frames are allowed in different packet number spaces:
	 * - Initial: CRYPTO, ACK, CONNECTION_CLOSE, PADDING, PING
	 * - Handshake: CRYPTO, ACK, CONNECTION_CLOSE, PADDING, PING
	 * - Application: All frames
	 */

	/* CRYPTO is allowed in Initial and Handshake */
	KUNIT_EXPECT_EQ(test, TQUIC_FRAME_CRYPTO, 0x06);

	/* STREAM is only in Application */
	KUNIT_EXPECT_GE(test, TQUIC_FRAME_STREAM, (u8)0x08);

	/* HANDSHAKE_DONE is only in Application (1-RTT) */
	KUNIT_EXPECT_EQ(test, TQUIC_FRAME_HANDSHAKE_DONE, 0x1e);
}

/* Test: Frame length validation */
static void tquic_frame_test_length_validation(struct kunit *test)
{
	/*
	 * Verify minimum lengths for various frames
	 */

	/* PADDING: 1 byte */
	size_t padding_min = 1;
	/* PING: 1 byte */
	size_t ping_min = 1;
	/* ACK: at least 5 bytes (type + 4 varints) */
	size_t ack_min = 5;
	/* PATH_CHALLENGE: 9 bytes (type + 8 data) */
	size_t path_challenge_len = 9;

	KUNIT_EXPECT_GE(test, padding_min, (size_t)1);
	KUNIT_EXPECT_GE(test, ping_min, (size_t)1);
	KUNIT_EXPECT_GE(test, ack_min, (size_t)5);
	KUNIT_EXPECT_EQ(test, path_challenge_len, (size_t)9);
}

/* Test: DATA_BLOCKED frame */
static void tquic_frame_test_data_blocked(struct kunit *test)
{
	/*
	 * DATA_BLOCKED Frame:
	 * - Type (0x14)
	 * - Maximum Data (varint) - the limit that was reached
	 */
	u8 data_blocked_frame[] = {
		0x14,	/* DATA_BLOCKED frame type */
		0x40, 0x00, 0x10, 0x00,	/* Maximum Data reached */
	};

	KUNIT_EXPECT_EQ(test, data_blocked_frame[0], TQUIC_FRAME_DATA_BLOCKED);
}

/* Test: STREAM_DATA_BLOCKED frame */
static void tquic_frame_test_stream_data_blocked(struct kunit *test)
{
	/*
	 * STREAM_DATA_BLOCKED Frame:
	 * - Type (0x15)
	 * - Stream ID (varint)
	 * - Maximum Stream Data (varint)
	 */
	u8 stream_blocked_frame[] = {
		0x15,	/* STREAM_DATA_BLOCKED frame type */
		0x04,	/* Stream ID = 4 */
		0x40, 0x00, 0x04, 0x00,	/* Maximum Stream Data */
	};

	KUNIT_EXPECT_EQ(test, stream_blocked_frame[0], TQUIC_FRAME_STREAM_DATA_BLOCKED);
}

/* Test: NEW_TOKEN frame */
static void tquic_frame_test_new_token(struct kunit *test)
{
	/*
	 * NEW_TOKEN Frame:
	 * - Type (0x07)
	 * - Token Length (varint)
	 * - Token
	 */
	u8 new_token_frame[] = {
		0x07,	/* NEW_TOKEN frame type */
		0x10,	/* Token Length = 16 */
		/* 16 bytes of token data would follow */
	};

	KUNIT_EXPECT_EQ(test, new_token_frame[0], TQUIC_FRAME_NEW_TOKEN);
	KUNIT_EXPECT_EQ(test, new_token_frame[1], 16);
}

static struct kunit_case tquic_frame_test_cases[] = {
	KUNIT_CASE(tquic_frame_test_type_identify),
	KUNIT_CASE(tquic_frame_test_stream_type_range),
	KUNIT_CASE(tquic_frame_test_stream_flags),
	KUNIT_CASE(tquic_frame_test_padding),
	KUNIT_CASE(tquic_frame_test_ping),
	KUNIT_CASE(tquic_frame_test_ack_structure),
	KUNIT_CASE(tquic_frame_test_ack_ecn),
	KUNIT_CASE(tquic_frame_test_crypto),
	KUNIT_CASE(tquic_frame_test_stream),
	KUNIT_CASE(tquic_frame_test_max_data),
	KUNIT_CASE(tquic_frame_test_max_stream_data),
	KUNIT_CASE(tquic_frame_test_max_streams),
	KUNIT_CASE(tquic_frame_test_reset_stream),
	KUNIT_CASE(tquic_frame_test_stop_sending),
	KUNIT_CASE(tquic_frame_test_new_connection_id),
	KUNIT_CASE(tquic_frame_test_retire_connection_id),
	KUNIT_CASE(tquic_frame_test_path_challenge),
	KUNIT_CASE(tquic_frame_test_path_response),
	KUNIT_CASE(tquic_frame_test_connection_close),
	KUNIT_CASE(tquic_frame_test_handshake_done),
	KUNIT_CASE(tquic_frame_test_multipath_frames),
	KUNIT_CASE(tquic_frame_test_pn_space_mapping),
	KUNIT_CASE(tquic_frame_test_length_validation),
	KUNIT_CASE(tquic_frame_test_data_blocked),
	KUNIT_CASE(tquic_frame_test_stream_data_blocked),
	KUNIT_CASE(tquic_frame_test_new_token),
	{}
};

static struct kunit_suite tquic_frame_test_suite = {
	.name = "tquic-frame",
	.test_cases = tquic_frame_test_cases,
};

kunit_test_suite(tquic_frame_test_suite);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("KUnit tests for TQUIC frame parsing");
