// SPDX-License-Identifier: GPL-2.0-only
/*
 * TQUIC MASQUE: Capsule Protocol Implementation (RFC 9297)
 *
 * Copyright (c) 2026 Linux Foundation
 *
 * The Capsule Protocol provides a framing mechanism for sending discrete
 * messages over HTTP request/response streams. This implementation supports
 * the full capsule frame format with streaming parsing and type registration.
 *
 * Key implementation details:
 *   - Streaming parser handles partial data arrival
 *   - Type registry allows modular capsule handler registration
 *   - Unknown capsule types are silently ignored per RFC 9297 Section 3.3
 *   - GREASE capsule types are recognized and ignored
 *
 * References:
 *   RFC 9297 - HTTP Datagrams and the Capsule Protocol
 *   RFC 9484 - Proxying IP in HTTP (CONNECT-IP capsules)
 */

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/list.h>
#include <linux/spinlock.h>
#include <net/tquic.h>

#include "capsule.h"

/*
 * =============================================================================
 * Module State
 * =============================================================================
 */

/* Slab cache for capsule structures */
static struct kmem_cache *capsule_cache;

/* Global handler registry (for standard types) */
static struct capsule_registry global_registry;

/*
 * =============================================================================
 * VARINT ENCODING/DECODING
 * =============================================================================
 */

/**
 * capsule_varint_encode - Encode value as QUIC varint
 * @value: Value to encode
 * @buf: Output buffer
 * @len: Buffer length
 *
 * Returns: Bytes written on success, negative errno on failure.
 */
int capsule_varint_encode(u64 value, u8 *buf, size_t len)
{
	int size = capsule_varint_size(value);

	if (len < size)
		return -ENOSPC;

	switch (size) {
	case 1:
		buf[0] = (u8)value;
		break;
	case 2:
		buf[0] = 0x40 | ((value >> 8) & 0x3f);
		buf[1] = value & 0xff;
		break;
	case 4:
		buf[0] = 0x80 | ((value >> 24) & 0x3f);
		buf[1] = (value >> 16) & 0xff;
		buf[2] = (value >> 8) & 0xff;
		buf[3] = value & 0xff;
		break;
	case 8:
		buf[0] = 0xc0 | ((value >> 56) & 0x3f);
		buf[1] = (value >> 48) & 0xff;
		buf[2] = (value >> 40) & 0xff;
		buf[3] = (value >> 32) & 0xff;
		buf[4] = (value >> 24) & 0xff;
		buf[5] = (value >> 16) & 0xff;
		buf[6] = (value >> 8) & 0xff;
		buf[7] = value & 0xff;
		break;
	default:
		return -EINVAL;
	}

	return size;
}
EXPORT_SYMBOL_GPL(capsule_varint_encode);

/**
 * capsule_varint_decode - Decode QUIC varint from buffer
 * @buf: Input buffer
 * @len: Buffer length
 * @value: Output value
 *
 * Returns: Bytes consumed on success, negative errno on failure.
 */
int capsule_varint_decode(const u8 *buf, size_t len, u64 *value)
{
	int size;
	u64 result;

	if (!buf || !value || len == 0)
		return -EINVAL;

	/* Determine varint length from first two bits */
	size = 1 << ((buf[0] >> 6) & 0x3);
	if (len < size)
		return -EAGAIN;

	switch (size) {
	case 1:
		result = buf[0] & 0x3f;
		break;
	case 2:
		result = ((u64)(buf[0] & 0x3f) << 8) | buf[1];
		break;
	case 4:
		result = ((u64)(buf[0] & 0x3f) << 24) |
			 ((u64)buf[1] << 16) |
			 ((u64)buf[2] << 8) |
			 buf[3];
		break;
	case 8:
		result = ((u64)(buf[0] & 0x3f) << 56) |
			 ((u64)buf[1] << 48) |
			 ((u64)buf[2] << 40) |
			 ((u64)buf[3] << 32) |
			 ((u64)buf[4] << 24) |
			 ((u64)buf[5] << 16) |
			 ((u64)buf[6] << 8) |
			 buf[7];
		break;
	default:
		return -EINVAL;
	}

	*value = result;
	return size;
}
EXPORT_SYMBOL_GPL(capsule_varint_decode);

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
int capsule_encode_header(u64 type, u64 payload_len, u8 *buf, size_t len)
{
	int type_size, len_size;
	int written = 0;
	int ret;

	if (!buf)
		return -EINVAL;

	type_size = capsule_varint_size(type);
	len_size = capsule_varint_size(payload_len);

	if (len < type_size + len_size)
		return -ENOSPC;

	ret = capsule_varint_encode(type, buf, len);
	if (ret < 0)
		return ret;
	written += ret;

	ret = capsule_varint_encode(payload_len, buf + written, len - written);
	if (ret < 0)
		return ret;
	written += ret;

	return written;
}
EXPORT_SYMBOL_GPL(capsule_encode_header);

/**
 * capsule_encode - Encode complete capsule
 * @type: Capsule type
 * @payload: Payload data
 * @payload_len: Payload length
 * @buf: Output buffer
 * @len: Buffer length
 *
 * Returns: Total bytes written on success, negative errno on failure.
 */
int capsule_encode(u64 type, const u8 *payload, size_t payload_len,
		   u8 *buf, size_t len)
{
	int header_len;
	int ret;

	if (!buf)
		return -EINVAL;

	if (payload_len > 0 && !payload)
		return -EINVAL;

	/* Encode header */
	ret = capsule_encode_header(type, payload_len, buf, len);
	if (ret < 0)
		return ret;
	header_len = ret;

	/* Check space for payload */
	if (len - header_len < payload_len)
		return -ENOSPC;

	/* Copy payload */
	if (payload_len > 0)
		memcpy(buf + header_len, payload, payload_len);

	return header_len + payload_len;
}
EXPORT_SYMBOL_GPL(capsule_encode);

/**
 * capsule_alloc - Allocate capsule structure
 * @type: Capsule type
 * @payload_len: Payload length to allocate
 * @gfp: Memory allocation flags
 *
 * Returns: Allocated capsule or NULL on failure.
 */
struct capsule *capsule_alloc(u64 type, size_t payload_len, gfp_t gfp)
{
	struct capsule *cap;

	if (capsule_cache)
		cap = kmem_cache_zalloc(capsule_cache, gfp);
	else
		cap = kzalloc(sizeof(*cap), gfp);

	if (!cap)
		return NULL;

	cap->type = type;
	cap->length = payload_len;

	if (payload_len > 0) {
		cap->value = kmalloc(payload_len, gfp);
		if (!cap->value) {
			if (capsule_cache)
				kmem_cache_free(capsule_cache, cap);
			else
				kfree(cap);
			return NULL;
		}
	} else {
		cap->value = NULL;
	}

	INIT_LIST_HEAD(&cap->list);
	return cap;
}
EXPORT_SYMBOL_GPL(capsule_alloc);

/**
 * capsule_free - Free capsule structure
 * @cap: Capsule to free
 */
void capsule_free(struct capsule *cap)
{
	if (!cap)
		return;

	kfree(cap->value);

	if (capsule_cache)
		kmem_cache_free(capsule_cache, cap);
	else
		kfree(cap);
}
EXPORT_SYMBOL_GPL(capsule_free);

/*
 * =============================================================================
 * CAPSULE PARSING
 * =============================================================================
 */

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
			  struct capsule_header *header)
{
	int consumed = 0;
	int ret;

	if (!buf || !header)
		return -EINVAL;

	if (len == 0)
		return -EAGAIN;

	/* Decode type */
	ret = capsule_varint_decode(buf, len, &header->type);
	if (ret < 0)
		return ret;
	consumed += ret;

	/* Decode length */
	if (len - consumed == 0)
		return -EAGAIN;

	ret = capsule_varint_decode(buf + consumed, len - consumed,
				    &header->length);
	if (ret < 0)
		return ret;
	consumed += ret;

	header->header_len = consumed;
	return consumed;
}
EXPORT_SYMBOL_GPL(capsule_decode_header);

/**
 * capsule_parser_init - Initialize capsule parser
 * @parser: Parser to initialize
 */
void capsule_parser_init(struct capsule_parser *parser)
{
	if (!parser)
		return;

	memset(parser, 0, sizeof(*parser));
	parser->state = CAPSULE_PARSE_TYPE;
	INIT_LIST_HEAD(&parser->pending);
	spin_lock_init(&parser->lock);
}
EXPORT_SYMBOL_GPL(capsule_parser_init);

/**
 * capsule_parser_cleanup - Clean up parser resources
 * @parser: Parser to clean up
 */
void capsule_parser_cleanup(struct capsule_parser *parser)
{
	struct capsule *cap, *tmp;

	if (!parser)
		return;

	spin_lock_bh(&parser->lock);

	/* Free current capsule if any */
	if (parser->cur_capsule) {
		capsule_free(parser->cur_capsule);
		parser->cur_capsule = NULL;
	}

	/* Free pending capsules */
	list_for_each_entry_safe(cap, tmp, &parser->pending, list) {
		list_del(&cap->list);
		capsule_free(cap);
	}

	parser->state = CAPSULE_PARSE_TYPE;
	parser->buf_len = 0;
	parser->value_offset = 0;

	spin_unlock_bh(&parser->lock);
}
EXPORT_SYMBOL_GPL(capsule_parser_cleanup);

/**
 * capsule_parser_feed - Feed data to parser
 * @parser: Parser instance
 * @data: Input data
 * @len: Data length
 *
 * Returns: Bytes consumed on success, negative errno on failure.
 */
int capsule_parser_feed(struct capsule_parser *parser,
			const u8 *data, size_t len)
{
	size_t consumed = 0;
	int ret;

	if (!parser || !data)
		return -EINVAL;

	spin_lock_bh(&parser->lock);

	while (consumed < len) {
		switch (parser->state) {
		case CAPSULE_PARSE_TYPE:
		case CAPSULE_PARSE_LENGTH:
			/*
			 * Accumulate header bytes. We need up to 16 bytes
			 * for the header (two 8-byte varints).
			 */
			while (consumed < len &&
			       parser->buf_len < CAPSULE_PARSE_BUFFER_SIZE) {
				parser->buffer[parser->buf_len++] =
					data[consumed++];

				/* Try to parse header */
				ret = capsule_decode_header(parser->buffer,
							    parser->buf_len,
							    &parser->header);
				if (ret >= 0) {
					/* Header complete, allocate capsule */
					parser->cur_capsule = capsule_alloc(
						parser->header.type,
						parser->header.length,
						GFP_ATOMIC);
					if (!parser->cur_capsule) {
						parser->state = CAPSULE_PARSE_ERROR;
						spin_unlock_bh(&parser->lock);
						return -ENOMEM;
					}

					/* Move to value parsing */
					parser->buf_len = 0;
					parser->value_offset = 0;

					if (parser->header.length == 0) {
						/* No value, capsule complete */
						list_add_tail(&parser->cur_capsule->list,
							      &parser->pending);
						parser->cur_capsule = NULL;
						parser->state = CAPSULE_PARSE_TYPE;
					} else {
						parser->state = CAPSULE_PARSE_VALUE;
					}
					break;
				} else if (ret != -EAGAIN) {
					/* Parse error */
					parser->state = CAPSULE_PARSE_ERROR;
					spin_unlock_bh(&parser->lock);
					return ret;
				}
				/* Need more data, continue accumulating */
			}
			break;

		case CAPSULE_PARSE_VALUE:
			/* Copy value bytes */
			while (consumed < len &&
			       parser->value_offset < parser->header.length) {
				parser->cur_capsule->value[parser->value_offset++] =
					data[consumed++];
			}

			/* Check if value complete */
			if (parser->value_offset >= parser->header.length) {
				/* Capsule complete */
				list_add_tail(&parser->cur_capsule->list,
					      &parser->pending);
				parser->cur_capsule = NULL;
				parser->state = CAPSULE_PARSE_TYPE;
				parser->buf_len = 0;
				parser->value_offset = 0;
			}
			break;

		case CAPSULE_PARSE_ERROR:
			/* Stuck in error state */
			spin_unlock_bh(&parser->lock);
			return -EINVAL;

		default:
			parser->state = CAPSULE_PARSE_ERROR;
			spin_unlock_bh(&parser->lock);
			return -EINVAL;
		}
	}

	spin_unlock_bh(&parser->lock);
	return consumed;
}
EXPORT_SYMBOL_GPL(capsule_parser_feed);

/**
 * capsule_parser_next - Get next parsed capsule
 * @parser: Parser instance
 *
 * Returns: Capsule on success, NULL if no capsules pending.
 */
struct capsule *capsule_parser_next(struct capsule_parser *parser)
{
	struct capsule *cap = NULL;

	if (!parser)
		return NULL;

	spin_lock_bh(&parser->lock);

	if (!list_empty(&parser->pending)) {
		cap = list_first_entry(&parser->pending, struct capsule, list);
		list_del(&cap->list);
	}

	spin_unlock_bh(&parser->lock);
	return cap;
}
EXPORT_SYMBOL_GPL(capsule_parser_next);

/**
 * capsule_parser_has_pending - Check if parser has pending capsules
 * @parser: Parser instance
 *
 * Returns: true if capsules are pending.
 */
bool capsule_parser_has_pending(struct capsule_parser *parser)
{
	bool has_pending;

	if (!parser)
		return false;

	spin_lock_bh(&parser->lock);
	has_pending = !list_empty(&parser->pending);
	spin_unlock_bh(&parser->lock);

	return has_pending;
}
EXPORT_SYMBOL_GPL(capsule_parser_has_pending);

/*
 * =============================================================================
 * CAPSULE TYPE REGISTRY
 * =============================================================================
 */

/**
 * capsule_registry_init - Initialize capsule registry
 * @registry: Registry to initialize
 */
void capsule_registry_init(struct capsule_registry *registry)
{
	if (!registry)
		return;

	INIT_LIST_HEAD(&registry->handlers);
	registry->unknown_handler = NULL;
	registry->unknown_context = NULL;
	spin_lock_init(&registry->lock);
}
EXPORT_SYMBOL_GPL(capsule_registry_init);

/**
 * capsule_registry_cleanup - Clean up registry
 * @registry: Registry to clean up
 */
void capsule_registry_cleanup(struct capsule_registry *registry)
{
	struct capsule_handler *handler, *tmp;

	if (!registry)
		return;

	spin_lock_bh(&registry->lock);

	list_for_each_entry_safe(handler, tmp, &registry->handlers, list) {
		list_del(&handler->list);
		kfree(handler);
	}

	registry->unknown_handler = NULL;
	registry->unknown_context = NULL;

	spin_unlock_bh(&registry->lock);
}
EXPORT_SYMBOL_GPL(capsule_registry_cleanup);

/**
 * capsule_register_handler - Register capsule type handler
 * @registry: Registry to register with
 * @type: Capsule type
 * @name: Handler name
 * @handler: Handler callback
 * @context: Handler context
 *
 * Returns: 0 on success, negative errno on failure.
 */
int capsule_register_handler(struct capsule_registry *registry,
			     u64 type, const char *name,
			     int (*handler)(struct capsule *cap, void *ctx),
			     void *context)
{
	struct capsule_handler *h, *existing;

	if (!registry || !handler)
		return -EINVAL;

	h = kzalloc(sizeof(*h), GFP_KERNEL);
	if (!h)
		return -ENOMEM;

	h->type = type;
	h->name = name;
	h->handler = handler;
	h->context = context;
	INIT_LIST_HEAD(&h->list);

	spin_lock_bh(&registry->lock);

	/* Check for existing handler */
	list_for_each_entry(existing, &registry->handlers, list) {
		if (existing->type == type) {
			spin_unlock_bh(&registry->lock);
			kfree(h);
			return -EEXIST;
		}
	}

	list_add_tail(&h->list, &registry->handlers);

	spin_unlock_bh(&registry->lock);

	pr_debug("capsule: registered handler for type 0x%llx (%s)\n",
		 type, name ? name : "unnamed");

	return 0;
}
EXPORT_SYMBOL_GPL(capsule_register_handler);

/**
 * capsule_unregister_handler - Unregister capsule type handler
 * @registry: Registry to unregister from
 * @type: Capsule type
 */
void capsule_unregister_handler(struct capsule_registry *registry, u64 type)
{
	struct capsule_handler *handler, *tmp;

	if (!registry)
		return;

	spin_lock_bh(&registry->lock);

	list_for_each_entry_safe(handler, tmp, &registry->handlers, list) {
		if (handler->type == type) {
			list_del(&handler->list);
			kfree(handler);
			break;
		}
	}

	spin_unlock_bh(&registry->lock);
}
EXPORT_SYMBOL_GPL(capsule_unregister_handler);

/**
 * capsule_set_unknown_handler - Set handler for unknown capsule types
 * @registry: Registry
 * @handler: Handler callback
 * @context: Handler context
 */
void capsule_set_unknown_handler(struct capsule_registry *registry,
				 int (*handler)(struct capsule *cap, void *ctx),
				 void *context)
{
	if (!registry)
		return;

	spin_lock_bh(&registry->lock);
	registry->unknown_handler = handler;
	registry->unknown_context = context;
	spin_unlock_bh(&registry->lock);
}
EXPORT_SYMBOL_GPL(capsule_set_unknown_handler);

/**
 * capsule_dispatch - Dispatch capsule to appropriate handler
 * @registry: Registry to use
 * @cap: Capsule to dispatch
 *
 * Returns: Handler return value, or 0 if ignored.
 */
int capsule_dispatch(struct capsule_registry *registry, struct capsule *cap)
{
	struct capsule_handler *handler;
	int (*unknown_handler)(struct capsule *, void *);
	void *unknown_context;
	int ret = 0;

	if (!registry || !cap)
		return -EINVAL;

	spin_lock_bh(&registry->lock);

	/* Look for registered handler */
	list_for_each_entry(handler, &registry->handlers, list) {
		if (handler->type == cap->type) {
			spin_unlock_bh(&registry->lock);
			return handler->handler(cap, handler->context);
		}
	}

	/* No registered handler - check for unknown handler */
	unknown_handler = registry->unknown_handler;
	unknown_context = registry->unknown_context;

	spin_unlock_bh(&registry->lock);

	/*
	 * RFC 9297 Section 3.3: Unknown capsule types MUST be silently ignored.
	 * We call the unknown handler for logging purposes only.
	 */
	if (unknown_handler) {
		ret = unknown_handler(cap, unknown_context);
	} else if (CAPSULE_TYPE_IS_GREASE(cap->type)) {
		/* GREASE types are always ignored */
		pr_debug("capsule: ignoring GREASE capsule type 0x%llx\n",
			 cap->type);
	} else {
		pr_debug("capsule: ignoring unknown capsule type 0x%llx\n",
			 cap->type);
	}

	return ret;
}
EXPORT_SYMBOL_GPL(capsule_dispatch);

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
const char *capsule_type_name(u64 type)
{
	switch (type) {
	case CAPSULE_TYPE_DATAGRAM:
		return "DATAGRAM";
	case CAPSULE_TYPE_ADDRESS_ASSIGN:
		return "ADDRESS_ASSIGN";
	case CAPSULE_TYPE_ADDRESS_REQUEST:
		return "ADDRESS_REQUEST";
	case CAPSULE_TYPE_ROUTE_ADVERTISEMENT:
		return "ROUTE_ADVERTISEMENT";
	case CAPSULE_TYPE_CLOSE_WEBTRANSPORT:
		return "CLOSE_WEBTRANSPORT_SESSION";
	case CAPSULE_TYPE_DRAIN_WEBTRANSPORT:
		return "DRAIN_WEBTRANSPORT_SESSION";
	/* QUIC-Aware Proxy capsule types (draft-ietf-masque-quic-proxy) */
	case CAPSULE_TYPE_QUIC_PROXY_REGISTER:
		return "QUIC_PROXY_REGISTER";
	case CAPSULE_TYPE_QUIC_PROXY_CID:
		return "QUIC_PROXY_CID";
	case CAPSULE_TYPE_QUIC_PROXY_PACKET:
		return "QUIC_PROXY_PACKET";
	case CAPSULE_TYPE_QUIC_PROXY_DEREGISTER:
		return "QUIC_PROXY_DEREGISTER";
	case CAPSULE_TYPE_QUIC_PROXY_ERROR:
		return "QUIC_PROXY_ERROR";
	case CAPSULE_TYPE_QUIC_PROXY_ACK:
		return "QUIC_PROXY_ACK";
	case CAPSULE_TYPE_QUIC_PROXY_MTU:
		return "QUIC_PROXY_MTU";
	case CAPSULE_TYPE_QUIC_PROXY_KEEPALIVE:
		return "QUIC_PROXY_KEEPALIVE";
	case CAPSULE_TYPE_QUIC_PROXY_STATS:
		return "QUIC_PROXY_STATS";
	default:
		if (CAPSULE_TYPE_IS_GREASE(type))
			return "GREASE";
		return "UNKNOWN";
	}
}
EXPORT_SYMBOL_GPL(capsule_type_name);

/**
 * capsule_type_is_known - Check if capsule type is known
 * @type: Capsule type
 *
 * Returns: true if type is a known standard type.
 */
bool capsule_type_is_known(u64 type)
{
	switch (type) {
	case CAPSULE_TYPE_DATAGRAM:
	case CAPSULE_TYPE_ADDRESS_ASSIGN:
	case CAPSULE_TYPE_ADDRESS_REQUEST:
	case CAPSULE_TYPE_ROUTE_ADVERTISEMENT:
	case CAPSULE_TYPE_CLOSE_WEBTRANSPORT:
	case CAPSULE_TYPE_DRAIN_WEBTRANSPORT:
	/* QUIC-Aware Proxy capsule types (draft-ietf-masque-quic-proxy) */
	case CAPSULE_TYPE_QUIC_PROXY_REGISTER:
	case CAPSULE_TYPE_QUIC_PROXY_CID:
	case CAPSULE_TYPE_QUIC_PROXY_PACKET:
	case CAPSULE_TYPE_QUIC_PROXY_DEREGISTER:
	case CAPSULE_TYPE_QUIC_PROXY_ERROR:
	case CAPSULE_TYPE_QUIC_PROXY_ACK:
	case CAPSULE_TYPE_QUIC_PROXY_MTU:
	case CAPSULE_TYPE_QUIC_PROXY_KEEPALIVE:
	case CAPSULE_TYPE_QUIC_PROXY_STATS:
		return true;
	default:
		return false;
	}
}
EXPORT_SYMBOL_GPL(capsule_type_is_known);

/*
 * =============================================================================
 * STREAM CAPSULE SEND
 * =============================================================================
 */

/**
 * capsule_send - Send capsule on stream
 * @stream: QUIC stream
 * @cap: Capsule to send
 *
 * Returns: 0 on success, negative errno on failure.
 */
int capsule_send(struct tquic_stream *stream, struct capsule *cap)
{
	u8 *buf;
	size_t buf_len;
	int ret;

	if (!stream || !cap)
		return -EINVAL;

	/* Calculate buffer size */
	buf_len = CAPSULE_MAX_HEADER_SIZE + cap->length;

	buf = kmalloc(buf_len, GFP_KERNEL);
	if (!buf)
		return -ENOMEM;

	/* Encode capsule */
	ret = capsule_encode(cap->type, cap->value, cap->length, buf, buf_len);
	if (ret < 0) {
		kfree(buf);
		return ret;
	}

	/* Send on stream */
	ret = tquic_xmit(stream->conn, stream, buf, ret, false);

	kfree(buf);
	return ret < 0 ? ret : 0;
}
EXPORT_SYMBOL_GPL(capsule_send);

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
		     const u8 *payload, size_t payload_len)
{
	u8 *buf;
	size_t buf_len;
	int ret;

	if (!stream)
		return -EINVAL;

	if (payload_len > 0 && !payload)
		return -EINVAL;

	/* Calculate buffer size */
	buf_len = CAPSULE_MAX_HEADER_SIZE + payload_len;

	buf = kmalloc(buf_len, GFP_KERNEL);
	if (!buf)
		return -ENOMEM;

	/* Encode capsule */
	ret = capsule_encode(type, payload, payload_len, buf, buf_len);
	if (ret < 0) {
		kfree(buf);
		return ret;
	}

	/* Send on stream */
	ret = tquic_xmit(stream->conn, stream, buf, ret, false);

	kfree(buf);
	return ret < 0 ? ret : 0;
}
EXPORT_SYMBOL_GPL(capsule_send_raw);

/*
 * =============================================================================
 * MODULE INITIALIZATION
 * =============================================================================
 */

/**
 * tquic_capsule_init - Initialize capsule subsystem
 *
 * Returns: 0 on success, negative errno on failure.
 */
int __init tquic_capsule_init(void)
{
	/* Create slab cache */
	capsule_cache = kmem_cache_create("tquic_capsule",
					  sizeof(struct capsule),
					  0, SLAB_HWCACHE_ALIGN, NULL);
	if (!capsule_cache)
		return -ENOMEM;

	/* Initialize global registry */
	capsule_registry_init(&global_registry);

	pr_info("TQUIC MASQUE: Capsule Protocol (RFC 9297) initialized\n");
	return 0;
}
EXPORT_SYMBOL_GPL(tquic_capsule_init);

/**
 * tquic_capsule_exit - Clean up capsule subsystem
 */
void __exit tquic_capsule_exit(void)
{
	/* Clean up global registry */
	capsule_registry_cleanup(&global_registry);

	/* Destroy slab cache */
	if (capsule_cache) {
		kmem_cache_destroy(capsule_cache);
		capsule_cache = NULL;
	}

	pr_info("TQUIC MASQUE: Capsule Protocol cleaned up\n");
}
EXPORT_SYMBOL_GPL(tquic_capsule_exit);

MODULE_DESCRIPTION("TQUIC MASQUE Capsule Protocol (RFC 9297)");
MODULE_LICENSE("GPL");
MODULE_AUTHOR("Linux Foundation");
