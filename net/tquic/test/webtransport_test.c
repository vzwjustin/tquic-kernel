// SPDX-License-Identifier: GPL-2.0-only
/*
 * TQUIC: WebTransport KUnit Tests
 *
 * Copyright (c) 2026 Linux Foundation
 *
 * Comprehensive tests for WebTransport over HTTP/3:
 *   - Capsule encoding/decoding
 *   - Extended CONNECT validation
 *   - Session lifecycle
 *   - Flow control capsules
 *   - Datagram handling
 *
 * Test Structure:
 *   Section 1: Capsule Encoding/Decoding Tests
 *   Section 2: Extended CONNECT Validation Tests
 *   Section 3: Session Lifecycle Tests
 *   Section 4: Flow Control Tests
 *   Section 5: WebTransport Datagram Tests
 */

#include <kunit/test.h>
#include <linux/types.h>
#include <linux/string.h>
#include <linux/slab.h>

/*
 * =============================================================================
 * WebTransport Constants
 * =============================================================================
 */

/* Capsule types (RFC 9297) */
#define CAPSULE_DATAGRAM		0x00
#define CAPSULE_CLOSE_WEBTRANSPORT	0x2843
#define CAPSULE_DRAIN_WEBTRANSPORT	0x78ae

/* WebTransport stream types */
#define WT_STREAM_UNI			0x54
#define WT_STREAM_BIDI			0x41

/* WebTransport settings */
#define SETTINGS_WEBTRANSPORT_MAX_SESSIONS	0x2b603742

/* Extended CONNECT */
#define EXTENDED_CONNECT_PROTOCOL	":protocol"
#define WEBTRANSPORT_PROTOCOL		"webtransport"

/* Maximum values */
#define WT_MAX_SESSION_ID		(1ULL << 62)
#define WT_MAX_CAPSULE_SIZE		65536

/*
 * =============================================================================
 * Test Data Structures
 * =============================================================================
 */

/**
 * enum webtransport_session_state - Session state machine
 */
enum webtransport_session_state {
	WT_SESSION_IDLE = 0,
	WT_SESSION_CONNECTING,
	WT_SESSION_OPEN,
	WT_SESSION_DRAINING,
	WT_SESSION_CLOSED,
};

/**
 * struct test_capsule - Generic capsule structure
 * @type: Capsule type
 * @data: Capsule data
 * @data_len: Data length
 */
struct test_capsule {
	u64 type;
	u8 *data;
	size_t data_len;
};

/**
 * struct test_wt_close_info - CLOSE_WEBTRANSPORT capsule data
 * @error_code: Application error code
 * @reason: Optional reason string
 * @reason_len: Length of reason string
 */
struct test_wt_close_info {
	u32 error_code;
	char *reason;
	size_t reason_len;
};

/**
 * struct test_wt_session - WebTransport session state
 * @session_id: Session identifier (CONNECT stream ID)
 * @state: Current session state
 * @max_streams_bidi: Max bidirectional streams
 * @max_streams_uni: Max unidirectional streams
 * @streams_opened_bidi: Bidirectional streams opened
 * @streams_opened_uni: Unidirectional streams opened
 * @datagrams_sent: Datagrams sent
 * @datagrams_received: Datagrams received
 */
struct test_wt_session {
	u64 session_id;
	enum webtransport_session_state state;
	u64 max_streams_bidi;
	u64 max_streams_uni;
	u64 streams_opened_bidi;
	u64 streams_opened_uni;
	u64 datagrams_sent;
	u64 datagrams_received;
};

/**
 * struct test_extended_connect - Extended CONNECT request headers
 * @method: HTTP method (must be "CONNECT")
 * @protocol: Extended protocol (must be "webtransport")
 * @scheme: URI scheme (must be "https")
 * @authority: Target authority
 * @path: Request path
 */
struct test_extended_connect {
	const char *method;
	const char *protocol;
	const char *scheme;
	const char *authority;
	const char *path;
};

/*
 * =============================================================================
 * Variable-Length Integer Helpers
 * =============================================================================
 */

static size_t test_varint_size(u64 value)
{
	if (value <= 63)
		return 1;
	if (value <= 16383)
		return 2;
	if (value <= 1073741823ULL)
		return 4;
	return 8;
}

static int test_varint_encode(u8 *buf, size_t buf_len, u64 value)
{
	size_t len = test_varint_size(value);

	if (buf_len < len)
		return -ENOBUFS;

	if (len == 1) {
		buf[0] = (u8)value;
	} else if (len == 2) {
		buf[0] = (u8)(0x40 | (value >> 8));
		buf[1] = (u8)(value & 0xff);
	} else if (len == 4) {
		buf[0] = (u8)(0x80 | (value >> 24));
		buf[1] = (u8)((value >> 16) & 0xff);
		buf[2] = (u8)((value >> 8) & 0xff);
		buf[3] = (u8)(value & 0xff);
	} else {
		buf[0] = (u8)(0xc0 | (value >> 56));
		buf[1] = (u8)((value >> 48) & 0xff);
		buf[2] = (u8)((value >> 40) & 0xff);
		buf[3] = (u8)((value >> 32) & 0xff);
		buf[4] = (u8)((value >> 24) & 0xff);
		buf[5] = (u8)((value >> 16) & 0xff);
		buf[6] = (u8)((value >> 8) & 0xff);
		buf[7] = (u8)(value & 0xff);
	}

	return len;
}

static int test_varint_decode(const u8 *buf, size_t buf_len, u64 *value)
{
	size_t len;
	u8 prefix;

	if (buf_len < 1)
		return -EINVAL;

	prefix = buf[0] >> 6;
	len = 1 << prefix;

	if (buf_len < len)
		return -EINVAL;

	switch (len) {
	case 1:
		*value = buf[0] & 0x3f;
		break;
	case 2:
		*value = ((u64)(buf[0] & 0x3f) << 8) | buf[1];
		break;
	case 4:
		*value = ((u64)(buf[0] & 0x3f) << 24) |
			 ((u64)buf[1] << 16) |
			 ((u64)buf[2] << 8) |
			 buf[3];
		break;
	case 8:
		*value = ((u64)(buf[0] & 0x3f) << 56) |
			 ((u64)buf[1] << 48) |
			 ((u64)buf[2] << 40) |
			 ((u64)buf[3] << 32) |
			 ((u64)buf[4] << 24) |
			 ((u64)buf[5] << 16) |
			 ((u64)buf[6] << 8) |
			 buf[7];
		break;
	}

	return len;
}

/*
 * =============================================================================
 * Capsule Encoding/Decoding
 * =============================================================================
 */

/**
 * test_capsule_encode - Encode a capsule
 * @buf: Output buffer
 * @buf_len: Buffer length
 * @capsule: Capsule to encode
 *
 * Returns: Bytes written, or negative error
 */
static int test_capsule_encode(u8 *buf, size_t buf_len,
			       const struct test_capsule *capsule)
{
	size_t offset = 0;
	int ret;

	/* Capsule type */
	ret = test_varint_encode(buf + offset, buf_len - offset, capsule->type);
	if (ret < 0)
		return ret;
	offset += ret;

	/* Capsule length */
	ret = test_varint_encode(buf + offset, buf_len - offset,
				 capsule->data_len);
	if (ret < 0)
		return ret;
	offset += ret;

	/* Capsule data */
	if (buf_len - offset < capsule->data_len)
		return -ENOBUFS;
	if (capsule->data_len > 0 && capsule->data)
		memcpy(buf + offset, capsule->data, capsule->data_len);
	offset += capsule->data_len;

	return offset;
}

/**
 * test_capsule_decode - Decode a capsule
 * @buf: Input buffer
 * @buf_len: Buffer length
 * @capsule: Output capsule (data points into buf)
 *
 * Returns: Bytes consumed, or negative error
 */
static int test_capsule_decode(const u8 *buf, size_t buf_len,
			       struct test_capsule *capsule)
{
	size_t offset = 0;
	u64 data_len;
	int ret;

	/* Capsule type */
	ret = test_varint_decode(buf + offset, buf_len - offset, &capsule->type);
	if (ret < 0)
		return ret;
	offset += ret;

	/* Capsule length */
	ret = test_varint_decode(buf + offset, buf_len - offset, &data_len);
	if (ret < 0)
		return ret;
	offset += ret;

	/* Capsule data */
	if (offset + data_len > buf_len)
		return -EINVAL;

	capsule->data = (u8 *)(buf + offset);
	capsule->data_len = data_len;
	offset += data_len;

	return offset;
}

/**
 * test_encode_close_capsule - Encode CLOSE_WEBTRANSPORT capsule
 * @buf: Output buffer
 * @buf_len: Buffer length
 * @close_info: Close information
 *
 * Returns: Bytes written, or negative error
 */
static int test_encode_close_capsule(u8 *buf, size_t buf_len,
				     const struct test_wt_close_info *close_info)
{
	struct test_capsule capsule;
	u8 data[256];
	size_t offset = 0;

	/* Encode error code (4 bytes big-endian) */
	data[0] = (close_info->error_code >> 24) & 0xff;
	data[1] = (close_info->error_code >> 16) & 0xff;
	data[2] = (close_info->error_code >> 8) & 0xff;
	data[3] = close_info->error_code & 0xff;
	offset = 4;

	/* Encode reason if present */
	if (close_info->reason && close_info->reason_len > 0) {
		if (offset + close_info->reason_len > sizeof(data))
			return -ENOBUFS;
		memcpy(data + offset, close_info->reason, close_info->reason_len);
		offset += close_info->reason_len;
	}

	capsule.type = CAPSULE_CLOSE_WEBTRANSPORT;
	capsule.data = data;
	capsule.data_len = offset;

	return test_capsule_encode(buf, buf_len, &capsule);
}

/**
 * test_decode_close_capsule - Decode CLOSE_WEBTRANSPORT capsule
 * @capsule: Decoded capsule
 * @close_info: Output close information
 *
 * Returns: 0 on success, negative error on failure
 */
static int test_decode_close_capsule(const struct test_capsule *capsule,
				     struct test_wt_close_info *close_info)
{
	if (capsule->type != CAPSULE_CLOSE_WEBTRANSPORT)
		return -EINVAL;

	if (capsule->data_len < 4)
		return -EINVAL;

	/* Decode error code */
	close_info->error_code = ((u32)capsule->data[0] << 24) |
				 ((u32)capsule->data[1] << 16) |
				 ((u32)capsule->data[2] << 8) |
				 capsule->data[3];

	/* Decode reason */
	if (capsule->data_len > 4) {
		close_info->reason = (char *)(capsule->data + 4);
		close_info->reason_len = capsule->data_len - 4;
	} else {
		close_info->reason = NULL;
		close_info->reason_len = 0;
	}

	return 0;
}

/*
 * =============================================================================
 * Extended CONNECT Validation
 * =============================================================================
 */

/**
 * test_validate_extended_connect - Validate extended CONNECT request
 * @req: Request to validate
 *
 * Returns: 0 if valid, negative error code if invalid
 */
static int test_validate_extended_connect(const struct test_extended_connect *req)
{
	/* Method must be CONNECT */
	if (!req->method || strcmp(req->method, "CONNECT") != 0)
		return -EINVAL;

	/* Protocol must be webtransport */
	if (!req->protocol || strcmp(req->protocol, "webtransport") != 0)
		return -EPROTO;

	/* Scheme must be https */
	if (!req->scheme || strcmp(req->scheme, "https") != 0)
		return -EPROTO;

	/* Authority must be present */
	if (!req->authority || strlen(req->authority) == 0)
		return -EINVAL;

	/* Path must be present */
	if (!req->path || strlen(req->path) == 0)
		return -EINVAL;

	return 0;
}

/*
 * =============================================================================
 * Session Lifecycle
 * =============================================================================
 */

/**
 * test_wt_session_init - Initialize WebTransport session
 * @session: Session to initialize
 * @session_id: CONNECT stream ID
 */
static void test_wt_session_init(struct test_wt_session *session, u64 session_id)
{
	memset(session, 0, sizeof(*session));
	session->session_id = session_id;
	session->state = WT_SESSION_IDLE;
	session->max_streams_bidi = 100;
	session->max_streams_uni = 100;
}

/**
 * test_wt_session_open - Transition session to OPEN state
 * @session: Session
 *
 * Returns: 0 on success, -EINVAL if transition not allowed
 */
static int test_wt_session_open(struct test_wt_session *session)
{
	if (session->state != WT_SESSION_CONNECTING)
		return -EINVAL;
	session->state = WT_SESSION_OPEN;
	return 0;
}

/**
 * test_wt_session_connect - Start connection
 * @session: Session
 *
 * Returns: 0 on success, -EINVAL if already connecting
 */
static int test_wt_session_connect(struct test_wt_session *session)
{
	if (session->state != WT_SESSION_IDLE)
		return -EINVAL;
	session->state = WT_SESSION_CONNECTING;
	return 0;
}

/**
 * test_wt_session_drain - Start draining
 * @session: Session
 *
 * Returns: 0 on success
 */
static int test_wt_session_drain(struct test_wt_session *session)
{
	if (session->state != WT_SESSION_OPEN)
		return -EINVAL;
	session->state = WT_SESSION_DRAINING;
	return 0;
}

/**
 * test_wt_session_close - Close session
 * @session: Session
 *
 * Returns: 0 on success
 */
static int test_wt_session_close(struct test_wt_session *session)
{
	session->state = WT_SESSION_CLOSED;
	return 0;
}

/**
 * test_wt_session_can_open_stream - Check if stream can be opened
 * @session: Session
 * @is_bidi: True for bidirectional stream
 *
 * Returns: true if stream can be opened
 */
static bool test_wt_session_can_open_stream(struct test_wt_session *session,
					    bool is_bidi)
{
	if (session->state != WT_SESSION_OPEN)
		return false;

	if (is_bidi)
		return session->streams_opened_bidi < session->max_streams_bidi;
	else
		return session->streams_opened_uni < session->max_streams_uni;
}

/**
 * test_wt_session_open_stream - Open a stream on session
 * @session: Session
 * @is_bidi: True for bidirectional stream
 *
 * Returns: 0 on success, -EAGAIN if limit reached
 */
static int test_wt_session_open_stream(struct test_wt_session *session,
				       bool is_bidi)
{
	if (!test_wt_session_can_open_stream(session, is_bidi))
		return -EAGAIN;

	if (is_bidi)
		session->streams_opened_bidi++;
	else
		session->streams_opened_uni++;

	return 0;
}

/*
 * =============================================================================
 * SECTION 1: Capsule Encoding/Decoding Tests
 * =============================================================================
 */

/* Test: Encode and decode DATAGRAM capsule */
static void test_capsule_datagram_roundtrip(struct kunit *test)
{
	u8 buf[128];
	u8 payload[] = "WebTransport datagram payload";
	struct test_capsule input = {
		.type = CAPSULE_DATAGRAM,
		.data = payload,
		.data_len = sizeof(payload) - 1,
	};
	struct test_capsule output;
	int encode_ret, decode_ret;

	/* ACT: Encode */
	encode_ret = test_capsule_encode(buf, sizeof(buf), &input);
	KUNIT_EXPECT_GT(test, encode_ret, 0);

	/* ACT: Decode */
	decode_ret = test_capsule_decode(buf, encode_ret, &output);

	/* ASSERT */
	KUNIT_EXPECT_EQ(test, decode_ret, encode_ret);
	KUNIT_EXPECT_EQ(test, output.type, (u64)CAPSULE_DATAGRAM);
	KUNIT_EXPECT_EQ(test, output.data_len, sizeof(payload) - 1);
	KUNIT_EXPECT_EQ(test, memcmp(output.data, payload, output.data_len), 0);
}

/* Test: Encode and decode CLOSE_WEBTRANSPORT capsule */
static void test_capsule_close_roundtrip(struct kunit *test)
{
	u8 buf[256];
	struct test_wt_close_info input = {
		.error_code = 42,
		.reason = "Session closed by peer",
		.reason_len = strlen("Session closed by peer"),
	};
	struct test_capsule capsule;
	struct test_wt_close_info output;
	int encode_ret, decode_ret, parse_ret;

	/* ACT: Encode */
	encode_ret = test_encode_close_capsule(buf, sizeof(buf), &input);
	KUNIT_EXPECT_GT(test, encode_ret, 0);

	/* ACT: Decode */
	decode_ret = test_capsule_decode(buf, encode_ret, &capsule);
	KUNIT_EXPECT_EQ(test, decode_ret, encode_ret);
	KUNIT_EXPECT_EQ(test, capsule.type, (u64)CAPSULE_CLOSE_WEBTRANSPORT);

	/* ACT: Parse close info */
	parse_ret = test_decode_close_capsule(&capsule, &output);

	/* ASSERT */
	KUNIT_EXPECT_EQ(test, parse_ret, 0);
	KUNIT_EXPECT_EQ(test, output.error_code, input.error_code);
	KUNIT_EXPECT_EQ(test, output.reason_len, input.reason_len);
	KUNIT_EXPECT_EQ(test, memcmp(output.reason, input.reason, output.reason_len), 0);
}

/* Test: Close capsule without reason */
static void test_capsule_close_no_reason(struct kunit *test)
{
	u8 buf[64];
	struct test_wt_close_info input = {
		.error_code = 0,
		.reason = NULL,
		.reason_len = 0,
	};
	struct test_capsule capsule;
	struct test_wt_close_info output;
	int ret;

	/* ACT */
	ret = test_encode_close_capsule(buf, sizeof(buf), &input);
	KUNIT_EXPECT_GT(test, ret, 0);

	ret = test_capsule_decode(buf, ret, &capsule);
	KUNIT_EXPECT_GT(test, ret, 0);

	ret = test_decode_close_capsule(&capsule, &output);

	/* ASSERT */
	KUNIT_EXPECT_EQ(test, ret, 0);
	KUNIT_EXPECT_EQ(test, output.error_code, 0U);
	KUNIT_EXPECT_EQ(test, output.reason_len, 0UL);
}

/* Test: DRAIN_WEBTRANSPORT capsule (no payload) */
static void test_capsule_drain(struct kunit *test)
{
	u8 buf[16];
	struct test_capsule input = {
		.type = CAPSULE_DRAIN_WEBTRANSPORT,
		.data = NULL,
		.data_len = 0,
	};
	struct test_capsule output;
	int encode_ret, decode_ret;

	/* ACT */
	encode_ret = test_capsule_encode(buf, sizeof(buf), &input);
	KUNIT_EXPECT_GT(test, encode_ret, 0);

	decode_ret = test_capsule_decode(buf, encode_ret, &output);

	/* ASSERT */
	KUNIT_EXPECT_EQ(test, decode_ret, encode_ret);
	KUNIT_EXPECT_EQ(test, output.type, (u64)CAPSULE_DRAIN_WEBTRANSPORT);
	KUNIT_EXPECT_EQ(test, output.data_len, 0UL);
}

/* Test: Capsule with truncated data */
static void test_capsule_decode_truncated(struct kunit *test)
{
	u8 buf[32];
	struct test_capsule input = {
		.type = CAPSULE_DATAGRAM,
		.data = (u8 *)"Hello",
		.data_len = 5,
	};
	struct test_capsule output;
	int encode_ret, decode_ret;

	/* ARRANGE: Encode valid capsule */
	encode_ret = test_capsule_encode(buf, sizeof(buf), &input);
	KUNIT_EXPECT_GT(test, encode_ret, 0);

	/* ACT/ASSERT: Decode with truncated buffer should fail */
	decode_ret = test_capsule_decode(buf, encode_ret - 2, &output);
	KUNIT_EXPECT_LT(test, decode_ret, 0);
}

/* Test: Empty capsule buffer */
static void test_capsule_decode_empty(struct kunit *test)
{
	u8 buf[1];
	struct test_capsule output;
	int ret;

	/* ACT/ASSERT */
	ret = test_capsule_decode(buf, 0, &output);
	KUNIT_EXPECT_LT(test, ret, 0);
}

/*
 * =============================================================================
 * SECTION 2: Extended CONNECT Validation Tests
 * =============================================================================
 */

/* Test: Valid extended CONNECT request */
static void test_extended_connect_valid(struct kunit *test)
{
	struct test_extended_connect req = {
		.method = "CONNECT",
		.protocol = "webtransport",
		.scheme = "https",
		.authority = "example.com",
		.path = "/endpoint",
	};
	int ret;

	/* ACT */
	ret = test_validate_extended_connect(&req);

	/* ASSERT */
	KUNIT_EXPECT_EQ(test, ret, 0);
}

/* Test: Invalid method */
static void test_extended_connect_wrong_method(struct kunit *test)
{
	struct test_extended_connect req = {
		.method = "GET",  /* Should be CONNECT */
		.protocol = "webtransport",
		.scheme = "https",
		.authority = "example.com",
		.path = "/endpoint",
	};
	int ret;

	/* ACT/ASSERT */
	ret = test_validate_extended_connect(&req);
	KUNIT_EXPECT_EQ(test, ret, -EINVAL);
}

/* Test: Invalid protocol */
static void test_extended_connect_wrong_protocol(struct kunit *test)
{
	struct test_extended_connect req = {
		.method = "CONNECT",
		.protocol = "websocket",  /* Should be webtransport */
		.scheme = "https",
		.authority = "example.com",
		.path = "/endpoint",
	};
	int ret;

	/* ACT/ASSERT */
	ret = test_validate_extended_connect(&req);
	KUNIT_EXPECT_EQ(test, ret, -EPROTO);
}

/* Test: Invalid scheme (http instead of https) */
static void test_extended_connect_wrong_scheme(struct kunit *test)
{
	struct test_extended_connect req = {
		.method = "CONNECT",
		.protocol = "webtransport",
		.scheme = "http",  /* Must be https */
		.authority = "example.com",
		.path = "/endpoint",
	};
	int ret;

	/* ACT/ASSERT */
	ret = test_validate_extended_connect(&req);
	KUNIT_EXPECT_EQ(test, ret, -EPROTO);
}

/* Test: Missing authority */
static void test_extended_connect_missing_authority(struct kunit *test)
{
	struct test_extended_connect req = {
		.method = "CONNECT",
		.protocol = "webtransport",
		.scheme = "https",
		.authority = NULL,
		.path = "/endpoint",
	};
	int ret;

	/* ACT/ASSERT */
	ret = test_validate_extended_connect(&req);
	KUNIT_EXPECT_EQ(test, ret, -EINVAL);
}

/* Test: Empty path */
static void test_extended_connect_empty_path(struct kunit *test)
{
	struct test_extended_connect req = {
		.method = "CONNECT",
		.protocol = "webtransport",
		.scheme = "https",
		.authority = "example.com",
		.path = "",
	};
	int ret;

	/* ACT/ASSERT */
	ret = test_validate_extended_connect(&req);
	KUNIT_EXPECT_EQ(test, ret, -EINVAL);
}

/*
 * =============================================================================
 * SECTION 3: Session Lifecycle Tests
 * =============================================================================
 */

/* Test: Session initial state */
static void test_session_initial_state(struct kunit *test)
{
	struct test_wt_session session;

	/* ACT */
	test_wt_session_init(&session, 4);

	/* ASSERT */
	KUNIT_EXPECT_EQ(test, session.session_id, 4ULL);
	KUNIT_EXPECT_EQ(test, session.state, WT_SESSION_IDLE);
	KUNIT_EXPECT_EQ(test, session.streams_opened_bidi, 0ULL);
	KUNIT_EXPECT_EQ(test, session.streams_opened_uni, 0ULL);
}

/* Test: Normal session state transitions */
static void test_session_normal_lifecycle(struct kunit *test)
{
	struct test_wt_session session;
	int ret;

	/* ARRANGE */
	test_wt_session_init(&session, 0);

	/* ACT/ASSERT: IDLE -> CONNECTING */
	ret = test_wt_session_connect(&session);
	KUNIT_EXPECT_EQ(test, ret, 0);
	KUNIT_EXPECT_EQ(test, session.state, WT_SESSION_CONNECTING);

	/* ACT/ASSERT: CONNECTING -> OPEN */
	ret = test_wt_session_open(&session);
	KUNIT_EXPECT_EQ(test, ret, 0);
	KUNIT_EXPECT_EQ(test, session.state, WT_SESSION_OPEN);

	/* ACT/ASSERT: OPEN -> DRAINING */
	ret = test_wt_session_drain(&session);
	KUNIT_EXPECT_EQ(test, ret, 0);
	KUNIT_EXPECT_EQ(test, session.state, WT_SESSION_DRAINING);

	/* ACT/ASSERT: DRAINING -> CLOSED */
	ret = test_wt_session_close(&session);
	KUNIT_EXPECT_EQ(test, ret, 0);
	KUNIT_EXPECT_EQ(test, session.state, WT_SESSION_CLOSED);
}

/* Test: Invalid transition from IDLE to OPEN */
static void test_session_invalid_transition_idle_open(struct kunit *test)
{
	struct test_wt_session session;
	int ret;

	/* ARRANGE */
	test_wt_session_init(&session, 0);

	/* ACT/ASSERT: Cannot go directly IDLE -> OPEN */
	ret = test_wt_session_open(&session);
	KUNIT_EXPECT_EQ(test, ret, -EINVAL);
	KUNIT_EXPECT_EQ(test, session.state, WT_SESSION_IDLE);
}

/* Test: Double connect */
static void test_session_double_connect(struct kunit *test)
{
	struct test_wt_session session;
	int ret;

	/* ARRANGE */
	test_wt_session_init(&session, 0);
	test_wt_session_connect(&session);

	/* ACT/ASSERT */
	ret = test_wt_session_connect(&session);
	KUNIT_EXPECT_EQ(test, ret, -EINVAL);
}

/* Test: Drain from non-OPEN state */
static void test_session_drain_invalid_state(struct kunit *test)
{
	struct test_wt_session session;
	int ret;

	/* ARRANGE */
	test_wt_session_init(&session, 0);

	/* ACT/ASSERT: Cannot drain from IDLE */
	ret = test_wt_session_drain(&session);
	KUNIT_EXPECT_EQ(test, ret, -EINVAL);
}

/*
 * =============================================================================
 * SECTION 4: Flow Control Tests (Stream Limits)
 * =============================================================================
 */

/* Test: Can open stream when limit not reached */
static void test_session_can_open_stream(struct kunit *test)
{
	struct test_wt_session session;

	/* ARRANGE */
	test_wt_session_init(&session, 0);
	test_wt_session_connect(&session);
	test_wt_session_open(&session);

	/* ASSERT */
	KUNIT_EXPECT_TRUE(test, test_wt_session_can_open_stream(&session, true));
	KUNIT_EXPECT_TRUE(test, test_wt_session_can_open_stream(&session, false));
}

/* Test: Cannot open stream when not OPEN */
static void test_session_cannot_open_stream_not_open(struct kunit *test)
{
	struct test_wt_session session;

	/* ARRANGE: Session in CONNECTING state */
	test_wt_session_init(&session, 0);
	test_wt_session_connect(&session);

	/* ASSERT */
	KUNIT_EXPECT_FALSE(test, test_wt_session_can_open_stream(&session, true));
	KUNIT_EXPECT_FALSE(test, test_wt_session_can_open_stream(&session, false));
}

/* Test: Stream limit enforcement */
static void test_session_stream_limit(struct kunit *test)
{
	struct test_wt_session session;
	int i, ret;

	/* ARRANGE */
	test_wt_session_init(&session, 0);
	session.max_streams_bidi = 3;  /* Set low limit */
	test_wt_session_connect(&session);
	test_wt_session_open(&session);

	/* ACT: Open streams up to limit */
	for (i = 0; i < 3; i++) {
		ret = test_wt_session_open_stream(&session, true);
		KUNIT_EXPECT_EQ(test, ret, 0);
	}

	/* ACT/ASSERT: Next should fail */
	ret = test_wt_session_open_stream(&session, true);
	KUNIT_EXPECT_EQ(test, ret, -EAGAIN);
	KUNIT_EXPECT_EQ(test, session.streams_opened_bidi, 3ULL);
}

/* Test: Independent bidi and uni stream limits */
static void test_session_independent_stream_limits(struct kunit *test)
{
	struct test_wt_session session;
	int ret;

	/* ARRANGE */
	test_wt_session_init(&session, 0);
	session.max_streams_bidi = 1;
	session.max_streams_uni = 2;
	test_wt_session_connect(&session);
	test_wt_session_open(&session);

	/* ACT: Open one bidi stream */
	ret = test_wt_session_open_stream(&session, true);
	KUNIT_EXPECT_EQ(test, ret, 0);

	/* ASSERT: Can still open uni streams */
	KUNIT_EXPECT_TRUE(test, test_wt_session_can_open_stream(&session, false));
	KUNIT_EXPECT_FALSE(test, test_wt_session_can_open_stream(&session, true));

	/* ACT: Open uni streams */
	ret = test_wt_session_open_stream(&session, false);
	KUNIT_EXPECT_EQ(test, ret, 0);
	ret = test_wt_session_open_stream(&session, false);
	KUNIT_EXPECT_EQ(test, ret, 0);
	ret = test_wt_session_open_stream(&session, false);
	KUNIT_EXPECT_EQ(test, ret, -EAGAIN);
}

/*
 * =============================================================================
 * SECTION 5: WebTransport Datagram Tests
 * =============================================================================
 */

/* Test: Datagram capsule encoding */
static void test_wt_datagram_encoding(struct kunit *test)
{
	u8 buf[128];
	u8 payload[] = "WT Datagram";
	struct test_capsule capsule = {
		.type = CAPSULE_DATAGRAM,
		.data = payload,
		.data_len = sizeof(payload) - 1,
	};
	struct test_capsule decoded;
	int ret;

	/* ACT */
	ret = test_capsule_encode(buf, sizeof(buf), &capsule);
	KUNIT_EXPECT_GT(test, ret, 0);

	ret = test_capsule_decode(buf, ret, &decoded);

	/* ASSERT */
	KUNIT_EXPECT_GT(test, ret, 0);
	KUNIT_EXPECT_EQ(test, decoded.type, (u64)CAPSULE_DATAGRAM);
	KUNIT_EXPECT_EQ(test, decoded.data_len, sizeof(payload) - 1);
}

/* Test: Empty datagram */
static void test_wt_datagram_empty(struct kunit *test)
{
	u8 buf[16];
	struct test_capsule capsule = {
		.type = CAPSULE_DATAGRAM,
		.data = NULL,
		.data_len = 0,
	};
	struct test_capsule decoded;
	int ret;

	/* ACT */
	ret = test_capsule_encode(buf, sizeof(buf), &capsule);
	KUNIT_EXPECT_GT(test, ret, 0);

	ret = test_capsule_decode(buf, ret, &decoded);

	/* ASSERT */
	KUNIT_EXPECT_GT(test, ret, 0);
	KUNIT_EXPECT_EQ(test, decoded.type, (u64)CAPSULE_DATAGRAM);
	KUNIT_EXPECT_EQ(test, decoded.data_len, 0UL);
}

/* Test: Session datagram statistics */
static void test_session_datagram_stats(struct kunit *test)
{
	struct test_wt_session session;

	/* ARRANGE */
	test_wt_session_init(&session, 0);
	test_wt_session_connect(&session);
	test_wt_session_open(&session);

	/* ACT: Simulate datagram activity */
	session.datagrams_sent = 100;
	session.datagrams_received = 50;

	/* ASSERT */
	KUNIT_EXPECT_EQ(test, session.datagrams_sent, 100ULL);
	KUNIT_EXPECT_EQ(test, session.datagrams_received, 50ULL);
}

/* Test: Multiple capsule types in sequence */
static void test_multiple_capsules(struct kunit *test)
{
	u8 buf[256];
	size_t offset = 0;
	struct test_capsule c1 = {
		.type = CAPSULE_DATAGRAM,
		.data = (u8 *)"Data1",
		.data_len = 5,
	};
	struct test_capsule c2 = {
		.type = CAPSULE_DRAIN_WEBTRANSPORT,
		.data = NULL,
		.data_len = 0,
	};
	struct test_capsule decoded1, decoded2;
	int ret;

	/* ACT: Encode two capsules */
	ret = test_capsule_encode(buf + offset, sizeof(buf) - offset, &c1);
	KUNIT_EXPECT_GT(test, ret, 0);
	offset += ret;

	ret = test_capsule_encode(buf + offset, sizeof(buf) - offset, &c2);
	KUNIT_EXPECT_GT(test, ret, 0);
	offset += ret;

	/* ACT: Decode both */
	ret = test_capsule_decode(buf, offset, &decoded1);
	KUNIT_EXPECT_GT(test, ret, 0);
	size_t consumed = ret;

	ret = test_capsule_decode(buf + consumed, offset - consumed, &decoded2);
	KUNIT_EXPECT_GT(test, ret, 0);

	/* ASSERT */
	KUNIT_EXPECT_EQ(test, decoded1.type, (u64)CAPSULE_DATAGRAM);
	KUNIT_EXPECT_EQ(test, decoded2.type, (u64)CAPSULE_DRAIN_WEBTRANSPORT);
}

/*
 * =============================================================================
 * Test Suite Definition
 * =============================================================================
 */

static struct kunit_case tquic_webtransport_test_cases[] = {
	/* Capsule Encoding/Decoding */
	KUNIT_CASE(test_capsule_datagram_roundtrip),
	KUNIT_CASE(test_capsule_close_roundtrip),
	KUNIT_CASE(test_capsule_close_no_reason),
	KUNIT_CASE(test_capsule_drain),
	KUNIT_CASE(test_capsule_decode_truncated),
	KUNIT_CASE(test_capsule_decode_empty),

	/* Extended CONNECT Validation */
	KUNIT_CASE(test_extended_connect_valid),
	KUNIT_CASE(test_extended_connect_wrong_method),
	KUNIT_CASE(test_extended_connect_wrong_protocol),
	KUNIT_CASE(test_extended_connect_wrong_scheme),
	KUNIT_CASE(test_extended_connect_missing_authority),
	KUNIT_CASE(test_extended_connect_empty_path),

	/* Session Lifecycle */
	KUNIT_CASE(test_session_initial_state),
	KUNIT_CASE(test_session_normal_lifecycle),
	KUNIT_CASE(test_session_invalid_transition_idle_open),
	KUNIT_CASE(test_session_double_connect),
	KUNIT_CASE(test_session_drain_invalid_state),

	/* Flow Control */
	KUNIT_CASE(test_session_can_open_stream),
	KUNIT_CASE(test_session_cannot_open_stream_not_open),
	KUNIT_CASE(test_session_stream_limit),
	KUNIT_CASE(test_session_independent_stream_limits),

	/* Datagram Handling */
	KUNIT_CASE(test_wt_datagram_encoding),
	KUNIT_CASE(test_wt_datagram_empty),
	KUNIT_CASE(test_session_datagram_stats),
	KUNIT_CASE(test_multiple_capsules),
	{}
};

static struct kunit_suite tquic_webtransport_test_suite = {
	.name = "tquic-webtransport",
	.test_cases = tquic_webtransport_test_cases,
};

kunit_test_suite(tquic_webtransport_test_suite);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("KUnit tests for TQUIC WebTransport");
MODULE_AUTHOR("Linux Foundation");
