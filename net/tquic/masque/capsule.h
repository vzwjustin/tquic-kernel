/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * TQUIC MASQUE: Capsule Protocol (RFC 9297)
 *
 * Copyright (c) 2026 Linux Foundation
 * Kernel implementation by Justin Adams <spotty118@gmail.com>
 *
 * The Capsule Protocol provides a mechanism for sending discrete messages
 * over an HTTP connection. Capsules are used by CONNECT-UDP, CONNECT-IP,
 * and WebTransport to send control messages on the request stream.
 *
 * Capsule Frame Format (RFC 9297 Section 3.2):
 *   Capsule Type (varint) || Capsule Length (varint) || Capsule Value
 *
 * Standard Capsule Types (RFC 9297 Section 5):
 *   0x00: DATAGRAM (deprecated, use QUIC DATAGRAM frames)
 *
 * CONNECT-IP Capsule Types (RFC 9484 Section 4):
 *   0x01: ADDRESS_ASSIGN
 *   0x02: ADDRESS_REQUEST
 *   0x03: ROUTE_ADVERTISEMENT
 *
 * WebTransport Capsule Types:
 *   0x2843: CLOSE_WEBTRANSPORT_SESSION
 *   0x2844: DRAIN_WEBTRANSPORT_SESSION
 *
 * Unknown capsule types MUST be ignored per RFC 9297 Section 3.3.
 */

#ifndef _TQUIC_MASQUE_CAPSULE_H
#define _TQUIC_MASQUE_CAPSULE_H

#include <linux/types.h>
#include <linux/list.h>
#include <linux/spinlock.h>
#include <net/tquic.h>

/*
 * =============================================================================
 * CAPSULE TYPE DEFINITIONS
 * =============================================================================
 */

/* RFC 9297: Base Capsule Types */
#define CAPSULE_TYPE_DATAGRAM			0x00

/* RFC 9484: CONNECT-IP Capsule Types */
#define CAPSULE_TYPE_ADDRESS_ASSIGN		0x01
#define CAPSULE_TYPE_ADDRESS_REQUEST		0x02
#define CAPSULE_TYPE_ROUTE_ADVERTISEMENT	0x03

/* WebTransport Capsule Types (draft-ietf-webtrans-http3) */
#define CAPSULE_TYPE_CLOSE_WEBTRANSPORT		0x2843
#define CAPSULE_TYPE_DRAIN_WEBTRANSPORT		0x2844

/* QUIC-Aware Proxy Capsule Types (draft-ietf-masque-quic-proxy) */
#define CAPSULE_TYPE_QUIC_PROXY_REGISTER	0x4143
#define CAPSULE_TYPE_QUIC_PROXY_CID		0x4144
#define CAPSULE_TYPE_QUIC_PROXY_PACKET		0x4145
#define CAPSULE_TYPE_QUIC_PROXY_DEREGISTER	0x4146
#define CAPSULE_TYPE_QUIC_PROXY_ERROR		0x4147
#define CAPSULE_TYPE_QUIC_PROXY_ACK		0x4148
#define CAPSULE_TYPE_QUIC_PROXY_MTU		0x4149
#define CAPSULE_TYPE_QUIC_PROXY_KEEPALIVE	0x414A
#define CAPSULE_TYPE_QUIC_PROXY_STATS		0x414B

/* RFC 9297: GREASE capsule types (format: 0x1f * N + 0x21) */
#define CAPSULE_TYPE_IS_GREASE(t)	(((t) >= 0x21) && (((t) - 0x21) % 0x1f == 0))

/* Maximum capsule payload size (practical limit) */
#define CAPSULE_MAX_PAYLOAD_SIZE		65535

/* Maximum capsule header size (2 varints of 8 bytes each) */
#define CAPSULE_MAX_HEADER_SIZE			16

/* Capsule buffer sizes */
#define CAPSULE_PARSE_BUFFER_SIZE		(CAPSULE_MAX_HEADER_SIZE + 256)

/*
 * =============================================================================
 * CAPSULE DATA STRUCTURES
 * =============================================================================
 */

/**
 * enum capsule_parse_state - Capsule parser state machine
 * @CAPSULE_PARSE_TYPE: Parsing capsule type varint
 * @CAPSULE_PARSE_LENGTH: Parsing capsule length varint
 * @CAPSULE_PARSE_VALUE: Parsing capsule value bytes
 * @CAPSULE_PARSE_COMPLETE: Capsule fully parsed
 * @CAPSULE_PARSE_ERROR: Parse error occurred
 */
enum capsule_parse_state {
	CAPSULE_PARSE_TYPE = 0,
	CAPSULE_PARSE_LENGTH,
	CAPSULE_PARSE_VALUE,
	CAPSULE_PARSE_COMPLETE,
	CAPSULE_PARSE_ERROR,
};

/**
 * struct capsule_header - Parsed capsule header
 * @type: Capsule type
 * @length: Payload length
 * @header_len: Total header length in bytes
 */
struct capsule_header {
	u64 type;
	u64 length;
	int header_len;
};

/**
 * struct capsule - Complete capsule structure
 * @type: Capsule type
 * @length: Payload length
 * @value: Payload data (dynamically allocated)
 * @list: List linkage for capsule queues
 */
struct capsule {
	u64 type;
	u64 length;
	u8 *value;
	struct list_head list;
};

/**
 * struct capsule_parser - Streaming capsule parser
 * @state: Current parse state
 * @header: Parsed header information
 * @buffer: Accumulation buffer for partial data
 * @buf_len: Current buffer length
 * @value_offset: Offset into value being parsed
 * @current: Currently parsing capsule (allocated when length known)
 * @pending: List of fully parsed capsules
 * @lock: Parser lock
 *
 * The parser handles streaming input and accumulates capsules
 * as they arrive over the QUIC stream.
 */
struct capsule_parser {
	enum capsule_parse_state state;
	struct capsule_header header;
	u8 buffer[CAPSULE_PARSE_BUFFER_SIZE];
	size_t buf_len;
	size_t value_offset;
	struct capsule *cur_capsule;
	struct list_head pending;
	spinlock_t lock;
};

/**
 * struct capsule_handler - Capsule type handler registration
 * @type: Capsule type this handler processes
 * @name: Human-readable name
 * @handler: Callback function for processing
 * @context: Handler-specific context
 * @list: List linkage
 *
 * Handlers are registered for specific capsule types. When a capsule
 * of that type is received, the handler callback is invoked.
 */
struct capsule_handler {
	u64 type;
	const char *name;
	int (*handler)(struct capsule *cap, void *context);
	void *context;
	struct list_head list;
};

/**
 * struct capsule_registry - Registry of capsule type handlers
 * @handlers: List of registered handlers
 * @unknown_handler: Handler for unknown capsule types (optional)
 * @lock: Registry lock
 */
struct capsule_registry {
	struct list_head handlers;
	int (*unknown_handler)(struct capsule *cap, void *context);
	void *unknown_context;
	spinlock_t lock;
};

/*
 * =============================================================================
 * VARINT ENCODING/DECODING
 * =============================================================================
 */

/**
 * capsule_varint_size - Get encoded size of varint
 * @value: Value to encode
 *
 * Returns: 1, 2, 4, or 8 bytes required.
 */
static inline int capsule_varint_size(u64 value)
{
	if (value <= 63)
		return 1;
	if (value <= 16383)
		return 2;
	if (value <= 1073741823)
		return 4;
	return 8;
}

/**
 * capsule_varint_encode - Encode value as QUIC varint
 * @value: Value to encode
 * @buf: Output buffer
 * @len: Buffer length
 *
 * Returns: Bytes written on success, negative errno on failure.
 */
int capsule_varint_encode(u64 value, u8 *buf, size_t len);

/**
 * capsule_varint_decode - Decode QUIC varint from buffer
 * @buf: Input buffer
 * @len: Buffer length
 * @value: Output value
 *
 * Returns: Bytes consumed on success, negative errno on failure.
 */
int capsule_varint_decode(const u8 *buf, size_t len, u64 *value);

/*
 * =============================================================================
 * CAPSULE ENCODING
 * =============================================================================
 */

/**
 * capsule_encode_header - Encode capsule header
 * @type: Capsule type
 * @payload_len: Payload length
 * @buf: Output buffer
 * @len: Buffer length
 *
 * Returns: Header length on success, negative errno on failure.
 */
int capsule_encode_header(u64 type, u64 payload_len, u8 *buf, size_t len);

/**
 * capsule_encode - Encode complete capsule
 * @type: Capsule type
 * @payload: Payload data (may be NULL if payload_len is 0)
 * @payload_len: Payload length
 * @buf: Output buffer
 * @len: Buffer length
 *
 * Returns: Total bytes written on success, negative errno on failure.
 */
int capsule_encode(u64 type, const u8 *payload, size_t payload_len,
		   u8 *buf, size_t len);

/**
 * capsule_alloc - Allocate capsule structure
 * @type: Capsule type
 * @payload_len: Payload length to allocate
 * @gfp: Memory allocation flags
 *
 * Returns: Allocated capsule or NULL on failure.
 */
struct capsule *capsule_alloc(u64 type, size_t payload_len, gfp_t gfp);

/**
 * capsule_free - Free capsule structure
 * @cap: Capsule to free
 */
void capsule_free(struct capsule *cap);

/*
 * =============================================================================
 * CAPSULE PARSING
 * =============================================================================
 */

/**
 * capsule_parser_init - Initialize capsule parser
 * @parser: Parser to initialize
 */
void capsule_parser_init(struct capsule_parser *parser);

/**
 * capsule_parser_cleanup - Clean up parser resources
 * @parser: Parser to clean up
 *
 * Frees any pending capsules and resets parser state.
 */
void capsule_parser_cleanup(struct capsule_parser *parser);

/**
 * capsule_parser_feed - Feed data to parser
 * @parser: Parser instance
 * @data: Input data
 * @len: Data length
 *
 * Feeds data to the parser for processing. May result in zero or more
 * complete capsules being added to the pending list.
 *
 * Returns: Bytes consumed on success, negative errno on failure.
 */
int capsule_parser_feed(struct capsule_parser *parser,
			const u8 *data, size_t len);

/**
 * capsule_parser_next - Get next parsed capsule
 * @parser: Parser instance
 *
 * Returns and removes the next complete capsule from the pending list.
 * Caller is responsible for freeing the returned capsule.
 *
 * Returns: Capsule on success, NULL if no capsules pending.
 */
struct capsule *capsule_parser_next(struct capsule_parser *parser);

/**
 * capsule_parser_has_pending - Check if parser has pending capsules
 * @parser: Parser instance
 *
 * Returns: true if capsules are pending.
 */
bool capsule_parser_has_pending(struct capsule_parser *parser);

/**
 * capsule_decode_header - Decode capsule header from buffer
 * @buf: Input buffer
 * @len: Buffer length
 * @header: Output header structure
 *
 * Returns: Bytes consumed on success, -EAGAIN if more data needed,
 *          negative errno on error.
 */
int capsule_decode_header(const u8 *buf, size_t len,
			  struct capsule_header *header);

/*
 * =============================================================================
 * CAPSULE TYPE REGISTRY
 * =============================================================================
 */

/**
 * capsule_registry_init - Initialize capsule registry
 * @registry: Registry to initialize
 */
void capsule_registry_init(struct capsule_registry *registry);

/**
 * capsule_registry_cleanup - Clean up registry
 * @registry: Registry to clean up
 */
void capsule_registry_cleanup(struct capsule_registry *registry);

/**
 * capsule_register_handler - Register capsule type handler
 * @registry: Registry to register with
 * @type: Capsule type
 * @name: Handler name (for debugging)
 * @handler: Handler callback
 * @context: Handler context
 *
 * Returns: 0 on success, negative errno on failure.
 */
int capsule_register_handler(struct capsule_registry *registry,
			     u64 type, const char *name,
			     int (*handler)(struct capsule *cap, void *ctx),
			     void *context);

/**
 * capsule_unregister_handler - Unregister capsule type handler
 * @registry: Registry to unregister from
 * @type: Capsule type
 */
void capsule_unregister_handler(struct capsule_registry *registry, u64 type);

/**
 * capsule_set_unknown_handler - Set handler for unknown capsule types
 * @registry: Registry
 * @handler: Handler callback
 * @context: Handler context
 *
 * Unknown capsule types MUST be ignored per RFC 9297. This handler
 * is called for logging/debugging purposes only.
 */
void capsule_set_unknown_handler(struct capsule_registry *registry,
				 int (*handler)(struct capsule *cap, void *ctx),
				 void *context);

/**
 * capsule_dispatch - Dispatch capsule to appropriate handler
 * @registry: Registry to use
 * @cap: Capsule to dispatch
 *
 * Finds the registered handler for the capsule type and invokes it.
 * Unknown types are passed to the unknown handler if set, otherwise ignored.
 *
 * Returns: Handler return value, or 0 if ignored.
 */
int capsule_dispatch(struct capsule_registry *registry, struct capsule *cap);

/*
 * =============================================================================
 * CAPSULE TYPE HELPERS
 * =============================================================================
 */

/**
 * capsule_type_name - Get human-readable capsule type name
 * @type: Capsule type
 *
 * Returns: Type name string.
 */
const char *capsule_type_name(u64 type);

/**
 * capsule_type_is_known - Check if capsule type is known
 * @type: Capsule type
 *
 * Returns: true if type is a known standard type.
 */
bool capsule_type_is_known(u64 type);

/*
 * =============================================================================
 * STREAM CAPSULE SEND/RECV
 * =============================================================================
 */

/**
 * capsule_send - Send capsule on stream
 * @stream: QUIC stream
 * @cap: Capsule to send
 *
 * Encodes and sends the capsule on the given stream.
 *
 * Returns: 0 on success, negative errno on failure.
 */
int capsule_send(struct tquic_stream *stream, struct capsule *cap);

/**
 * capsule_send_raw - Send raw capsule data on stream
 * @stream: QUIC stream
 * @type: Capsule type
 * @payload: Payload data
 * @payload_len: Payload length
 *
 * Returns: 0 on success, negative errno on failure.
 */
int capsule_send_raw(struct tquic_stream *stream, u64 type,
		     const u8 *payload, size_t payload_len);

/*
 * =============================================================================
 * MODULE INITIALIZATION
 * =============================================================================
 */

int __init tquic_capsule_init(void);
void __exit tquic_capsule_exit(void);

#endif /* _TQUIC_MASQUE_CAPSULE_H */
