// SPDX-License-Identifier: GPL-2.0-only
/*
 * QPACK Encoder - RFC 9204
 *
 * Copyright (c) 2026 Linux Foundation
 *
 * The QPACK encoder compresses HTTP header fields for HTTP/3.
 * It uses both static and dynamic tables to achieve compression,
 * and sends instructions on the encoder stream to update the
 * decoder's dynamic table.
 *
 * Encoder stream instructions (sent to decoder):
 * - Set Dynamic Table Capacity
 * - Insert With Name Reference
 * - Insert With Literal Name
 * - Duplicate
 *
 * Header field representations (in request/response streams):
 * - Indexed Field Line (static or dynamic)
 * - Indexed Field Line with Post-Base Index
 * - Literal Field Line with Name Reference
 * - Literal Field Line with Post-Base Name Reference
 * - Literal Field Line with Literal Name
 */

#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/module.h>
#include <net/tquic.h>

#include "qpack.h"

/* Maximum encoded integer size */
#define MAX_ENCODED_INT_SIZE	10

/* Required insert count encoding per RFC 9204 Section 4.5.1 */
#define QPACK_MAX_ENTRIES_DIVISOR	1024

/**
 * qpack_encoder_init - Initialize QPACK encoder
 * @enc: Encoder to initialize
 * @conn: Parent connection
 * @max_table_capacity: Maximum dynamic table capacity
 * @max_blocked_streams: Maximum blocked streams
 *
 * Returns: 0 on success, negative error code on failure
 */
int qpack_encoder_init(struct qpack_encoder *enc,
		       struct tquic_connection *conn,
		       u64 max_table_capacity,
		       u32 max_blocked_streams)
{
	int ret;

	if (!enc || !conn)
		return -EINVAL;

	memset(enc, 0, sizeof(*enc));
	enc->conn = conn;
	enc->max_blocked_streams = max_blocked_streams;
	enc->use_huffman = true;

	ret = qpack_dynamic_table_init(&enc->dynamic_table, max_table_capacity);
	if (ret)
		return ret;

	INIT_LIST_HEAD(&enc->blocked_streams);
	spin_lock_init(&enc->lock);

	return 0;
}
EXPORT_SYMBOL_GPL(qpack_encoder_init);

/**
 * qpack_encoder_destroy - Release encoder resources
 * @enc: Encoder to destroy
 */
void qpack_encoder_destroy(struct qpack_encoder *enc)
{
	struct qpack_blocked_stream *blocked, *tmp;
	unsigned long flags;

	if (!enc)
		return;

	spin_lock_irqsave(&enc->lock, flags);
	list_for_each_entry_safe(blocked, tmp, &enc->blocked_streams, list) {
		list_del(&blocked->list);
		kfree(blocked);
	}
	spin_unlock_irqrestore(&enc->lock, flags);

	qpack_dynamic_table_destroy(&enc->dynamic_table);
}
EXPORT_SYMBOL_GPL(qpack_encoder_destroy);

/**
 * qpack_encoder_set_stream - Set encoder stream
 * @enc: Encoder
 * @stream: Unidirectional stream for encoder instructions
 */
void qpack_encoder_set_stream(struct qpack_encoder *enc,
			      struct tquic_stream *stream)
{
	if (enc)
		enc->encoder_stream = stream;
}
EXPORT_SYMBOL_GPL(qpack_encoder_set_stream);

/**
 * encode_required_insert_count - Encode Required Insert Count
 * @insert_count: Required insert count
 * @max_entries: Maximum table entries
 * @buf: Output buffer
 * @buf_len: Buffer length
 * @encoded_len: Output - encoded length
 *
 * Returns: 0 on success, negative error code on failure
 *
 * Per RFC 9204 Section 4.5.1, Required Insert Count is encoded
 * modulo 2 * MaxEntries + 1 for wrap-around handling.
 */
static int encode_required_insert_count(u64 insert_count, u32 max_entries,
					u8 *buf, size_t buf_len,
					size_t *encoded_len)
{
	u64 encoded_value;

	if (insert_count == 0) {
		if (buf_len < 1)
			return -ENOSPC;
		buf[0] = 0;
		*encoded_len = 1;
		return 0;
	}

	/* Encode: (InsertCount mod (2 * MaxEntries)) + 1 */
	if (max_entries > 0)
		encoded_value = (insert_count % (2 * max_entries)) + 1;
	else
		encoded_value = insert_count;

	return qpack_encode_integer(encoded_value, 8, 0, buf, buf_len, encoded_len);
}

/**
 * encode_base - Encode Base value
 * @required_insert_count: Required Insert Count
 * @base: Base value
 * @buf: Output buffer
 * @buf_len: Buffer length
 * @encoded_len: Output - encoded length
 *
 * Returns: 0 on success, negative error code on failure
 *
 * Per RFC 9204 Section 4.5.1.2, Base is encoded as:
 * - If Base >= Required Insert Count: Delta Base with S=0
 * - If Base < Required Insert Count: Delta Base with S=1
 */
static int encode_base(u64 required_insert_count, u64 base,
		       u8 *buf, size_t buf_len, size_t *encoded_len)
{
	u64 delta_base;
	u8 sign_bit;

	if (base >= required_insert_count) {
		/* S=0: Base = ReqInsertCount + DeltaBase */
		delta_base = base - required_insert_count;
		sign_bit = 0;
	} else {
		/* S=1: Base = ReqInsertCount - DeltaBase - 1 */
		delta_base = required_insert_count - base - 1;
		sign_bit = 0x80;  /* S bit in 8-bit prefix */
	}

	return qpack_encode_integer(delta_base, 7, sign_bit, buf, buf_len, encoded_len);
}

/**
 * encode_indexed_static - Encode indexed field line (static table)
 * @index: Static table index
 * @buf: Output buffer
 * @buf_len: Buffer length
 * @encoded_len: Output - encoded length
 *
 * Returns: 0 on success, negative error code on failure
 *
 * Format: 1T (6-bit index) where T=1 for static table
 */
static int encode_indexed_static(u32 index, u8 *buf, size_t buf_len,
				 size_t *encoded_len)
{
	/* Prefix: 1 (indexed) + 1 (static) = 0xC0, 6-bit index */
	return qpack_encode_integer(index, 6, 0xC0, buf, buf_len, encoded_len);
}

/**
 * encode_indexed_dynamic - Encode indexed field line (dynamic table)
 * @relative_index: Relative index from base
 * @buf: Output buffer
 * @buf_len: Buffer length
 * @encoded_len: Output - encoded length
 *
 * Returns: 0 on success, negative error code on failure
 *
 * Format: 1T (6-bit index) where T=0 for dynamic table
 */
static int encode_indexed_dynamic(u64 relative_index, u8 *buf, size_t buf_len,
				  size_t *encoded_len)
{
	/* Prefix: 1 (indexed) + 0 (dynamic) = 0x80, 6-bit index */
	return qpack_encode_integer(relative_index, 6, 0x80, buf, buf_len, encoded_len);
}

/**
 * encode_indexed_post_base - Encode indexed field line with post-base index
 * @post_base_index: Post-base index
 * @buf: Output buffer
 * @buf_len: Buffer length
 * @encoded_len: Output - encoded length
 *
 * Returns: 0 on success, negative error code on failure
 *
 * Format: 0001 (4-bit index)
 */
static int encode_indexed_post_base(u64 post_base_index, u8 *buf, size_t buf_len,
				    size_t *encoded_len)
{
	return qpack_encode_integer(post_base_index, 4, 0x10, buf, buf_len, encoded_len);
}

/**
 * encode_literal_name_ref_static - Encode literal with static name reference
 * @index: Static table index
 * @value: Header value
 * @value_len: Value length
 * @never_index: Never index flag
 * @huffman: Use Huffman coding
 * @buf: Output buffer
 * @buf_len: Buffer length
 * @encoded_len: Output - encoded length
 *
 * Returns: 0 on success, negative error code on failure
 *
 * Format: 01NT (4-bit index) + value
 */
static int encode_literal_name_ref_static(u32 index, const char *value,
					  u16 value_len, bool never_index,
					  bool huffman, u8 *buf, size_t buf_len,
					  size_t *encoded_len)
{
	u8 prefix;
	size_t idx_len, val_len;
	int ret;

	/* Prefix: 01 + N + T where N=never_index, T=1 for static */
	prefix = 0x50 | (never_index ? 0x20 : 0);

	ret = qpack_encode_integer(index, 4, prefix, buf, buf_len, &idx_len);
	if (ret)
		return ret;

	ret = qpack_encode_string(value, value_len, huffman,
				  buf + idx_len, buf_len - idx_len, &val_len);
	if (ret)
		return ret;

	*encoded_len = idx_len + val_len;
	return 0;
}

/**
 * encode_literal_name_ref_dynamic - Encode literal with dynamic name reference
 * @relative_index: Relative index
 * @value: Header value
 * @value_len: Value length
 * @never_index: Never index flag
 * @huffman: Use Huffman coding
 * @buf: Output buffer
 * @buf_len: Buffer length
 * @encoded_len: Output - encoded length
 *
 * Returns: 0 on success, negative error code on failure
 */
static int encode_literal_name_ref_dynamic(u64 relative_index, const char *value,
					   u16 value_len, bool never_index,
					   bool huffman, u8 *buf, size_t buf_len,
					   size_t *encoded_len)
{
	u8 prefix;
	size_t idx_len, val_len;
	int ret;

	/* Prefix: 01 + N + T where N=never_index, T=0 for dynamic */
	prefix = 0x40 | (never_index ? 0x20 : 0);

	ret = qpack_encode_integer(relative_index, 4, prefix, buf, buf_len, &idx_len);
	if (ret)
		return ret;

	ret = qpack_encode_string(value, value_len, huffman,
				  buf + idx_len, buf_len - idx_len, &val_len);
	if (ret)
		return ret;

	*encoded_len = idx_len + val_len;
	return 0;
}

/**
 * encode_literal - Encode literal field line with literal name
 * @name: Header name
 * @name_len: Name length
 * @value: Header value
 * @value_len: Value length
 * @never_index: Never index flag
 * @huffman: Use Huffman coding
 * @buf: Output buffer
 * @buf_len: Buffer length
 * @encoded_len: Output - encoded length
 *
 * Returns: 0 on success, negative error code on failure
 *
 * Format: 001N (3-bit name length) + name + value
 */
static int encode_literal(const char *name, u16 name_len,
			  const char *value, u16 value_len,
			  bool never_index, bool huffman,
			  u8 *buf, size_t buf_len, size_t *encoded_len)
{
	u8 prefix;
	size_t name_enc_len, val_enc_len;
	int ret;

	/* Prefix: 001N where N=never_index */
	prefix = 0x20 | (never_index ? 0x10 : 0);

	/* Encode name as string with prefix */
	ret = qpack_encode_string(name, name_len, huffman,
				  buf, buf_len, &name_enc_len);
	if (ret)
		return ret;

	/* Set the prefix bits on first byte */
	buf[0] = (buf[0] & 0x0F) | prefix;

	ret = qpack_encode_string(value, value_len, huffman,
				  buf + name_enc_len, buf_len - name_enc_len,
				  &val_enc_len);
	if (ret)
		return ret;

	*encoded_len = name_enc_len + val_enc_len;
	return 0;
}

/**
 * qpack_encode_headers - Encode header list
 * @enc: Encoder
 * @stream_id: Request/response stream ID
 * @headers: Header list to encode
 * @buf: Output buffer
 * @buf_len: Buffer length
 * @encoded_len: Output - encoded length
 *
 * Returns: 0 on success, negative error code on failure
 */
int qpack_encode_headers(struct qpack_encoder *enc,
			 u64 stream_id,
			 struct qpack_header_list *headers,
			 u8 *buf, size_t buf_len, size_t *encoded_len)
{
	struct qpack_header_field *hdr;
	u64 required_insert_count = 0;
	u64 base;
	size_t prefix_len, hdr_len;
	size_t offset = 0;
	unsigned long flags;
	int ret;
	int static_idx;
	s64 dynamic_idx;

	if (!enc || !headers || !buf || !encoded_len)
		return -EINVAL;

	spin_lock_irqsave(&enc->lock, flags);

	/* Calculate required insert count based on dynamic table references */
	base = enc->dynamic_table.insert_count;

	/* For simplicity, we don't reference unacknowledged entries initially */
	required_insert_count = 0;

	spin_unlock_irqrestore(&enc->lock, flags);

	/* Encode prefix: Required Insert Count + Base */
	ret = encode_required_insert_count(required_insert_count,
					   enc->dynamic_table.max_entries,
					   buf, buf_len, &prefix_len);
	if (ret)
		return ret;
	offset = prefix_len;

	ret = encode_base(required_insert_count, base,
			  buf + offset, buf_len - offset, &prefix_len);
	if (ret)
		return ret;
	offset += prefix_len;

	/* Encode each header field */
	list_for_each_entry(hdr, &headers->headers, list) {
		/* Try static table first (exact match) */
		static_idx = qpack_static_find(hdr->name, hdr->name_len,
					       hdr->value, hdr->value_len);
		if (static_idx >= 0) {
			ret = encode_indexed_static(static_idx,
						    buf + offset,
						    buf_len - offset,
						    &hdr_len);
			if (ret)
				return ret;
			offset += hdr_len;
			continue;
		}

		/* Try dynamic table (exact match) */
		spin_lock_irqsave(&enc->lock, flags);
		dynamic_idx = qpack_dynamic_table_find(&enc->dynamic_table,
						       hdr->name, hdr->name_len,
						       hdr->value, hdr->value_len);
		spin_unlock_irqrestore(&enc->lock, flags);

		if (dynamic_idx >= 0 && (u64)dynamic_idx < base) {
			u64 relative_idx = base - dynamic_idx - 1;
			ret = encode_indexed_dynamic(relative_idx,
						     buf + offset,
						     buf_len - offset,
						     &hdr_len);
			if (ret)
				return ret;
			offset += hdr_len;
			continue;
		}

		/* Try static table name reference */
		static_idx = qpack_static_find_name(hdr->name, hdr->name_len);
		if (static_idx >= 0) {
			ret = encode_literal_name_ref_static(static_idx,
							     hdr->value,
							     hdr->value_len,
							     hdr->never_index,
							     enc->use_huffman,
							     buf + offset,
							     buf_len - offset,
							     &hdr_len);
			if (ret)
				return ret;
			offset += hdr_len;
			continue;
		}

		/* Try dynamic table name reference */
		spin_lock_irqsave(&enc->lock, flags);
		dynamic_idx = qpack_dynamic_table_find_name(&enc->dynamic_table,
							    hdr->name,
							    hdr->name_len);
		spin_unlock_irqrestore(&enc->lock, flags);

		if (dynamic_idx >= 0 && (u64)dynamic_idx < base) {
			u64 relative_idx = base - dynamic_idx - 1;
			ret = encode_literal_name_ref_dynamic(relative_idx,
							      hdr->value,
							      hdr->value_len,
							      hdr->never_index,
							      enc->use_huffman,
							      buf + offset,
							      buf_len - offset,
							      &hdr_len);
			if (ret)
				return ret;
			offset += hdr_len;
			continue;
		}

		/* Fall back to literal encoding */
		ret = encode_literal(hdr->name, hdr->name_len,
				     hdr->value, hdr->value_len,
				     hdr->never_index, enc->use_huffman,
				     buf + offset, buf_len - offset, &hdr_len);
		if (ret)
			return ret;
		offset += hdr_len;
	}

	*encoded_len = offset;
	return 0;
}
EXPORT_SYMBOL_GPL(qpack_encode_headers);

/**
 * qpack_encoder_process_decoder_stream - Process decoder stream data
 * @enc: Encoder
 * @data: Decoder stream data
 * @len: Data length
 *
 * Returns: 0 on success, negative error code on failure
 *
 * Processes decoder instructions:
 * - Section Acknowledgment
 * - Stream Cancellation
 * - Insert Count Increment
 */
int qpack_encoder_process_decoder_stream(struct qpack_encoder *enc,
					 const u8 *data, size_t len)
{
	size_t offset = 0;
	u64 value;
	size_t consumed;
	int ret;

	if (!enc || !data || len == 0)
		return -EINVAL;

	while (offset < len) {
		u8 first_byte = data[offset];

		if (first_byte & 0x80) {
			/* Section Acknowledgment: 1xxxxxxx */
			ret = qpack_decode_integer(data + offset, len - offset,
						   7, &value, &consumed);
			if (ret)
				return ret;
			offset += consumed;

			/* Stream ID acknowledged - update known state */
			/* TODO: Track per-stream insert counts */
		} else if (first_byte & 0x40) {
			/* Stream Cancellation: 01xxxxxx */
			ret = qpack_decode_integer(data + offset, len - offset,
						   6, &value, &consumed);
			if (ret)
				return ret;
			offset += consumed;

			/* Stream cancelled - remove from blocked list if present */
		} else {
			/* Insert Count Increment: 00xxxxxx */
			ret = qpack_decode_integer(data + offset, len - offset,
						   6, &value, &consumed);
			if (ret)
				return ret;
			offset += consumed;

			/* Update known received count */
			enc->known_received_count += value;
			qpack_dynamic_table_acknowledge(&enc->dynamic_table,
							enc->known_received_count);
		}
	}

	return 0;
}
EXPORT_SYMBOL_GPL(qpack_encoder_process_decoder_stream);

/*
 * =============================================================================
 * Encoder Stream Instructions
 * =============================================================================
 */

/**
 * qpack_encoder_set_capacity - Send Set Dynamic Table Capacity
 * @enc: Encoder
 * @capacity: New capacity
 *
 * Returns: 0 on success, negative error code on failure
 */
int qpack_encoder_set_capacity(struct qpack_encoder *enc, u64 capacity)
{
	u8 buf[MAX_ENCODED_INT_SIZE];
	size_t encoded_len;
	int ret;

	if (!enc || !enc->encoder_stream)
		return -EINVAL;

	/* Encode: 001xxxxx with 5-bit prefix */
	ret = qpack_encode_integer(capacity, 5, 0x20, buf, sizeof(buf), &encoded_len);
	if (ret)
		return ret;

	/* Update local table capacity */
	ret = qpack_dynamic_table_set_capacity(&enc->dynamic_table, capacity);
	if (ret)
		return ret;

	/* Send instruction on encoder stream */
	return tquic_stream_send(enc->encoder_stream, buf, encoded_len, false);
}
EXPORT_SYMBOL_GPL(qpack_encoder_set_capacity);

/**
 * qpack_encoder_insert_name_ref - Send Insert With Name Reference
 * @enc: Encoder
 * @is_static: True for static table reference
 * @name_index: Table index for name
 * @value: Header value
 * @value_len: Value length
 *
 * Returns: 0 on success, negative error code on failure
 */
int qpack_encoder_insert_name_ref(struct qpack_encoder *enc,
				  bool is_static, u64 name_index,
				  const char *value, u16 value_len)
{
	u8 buf[QPACK_MAX_HEADER_VALUE_LEN + 32];
	size_t offset = 0;
	size_t encoded_len;
	int ret;

	if (!enc || !enc->encoder_stream)
		return -EINVAL;

	/* Encode: 1T (6-bit index) where T=1 for static */
	if (is_static)
		ret = qpack_encode_integer(name_index, 6, 0xC0, buf, sizeof(buf), &encoded_len);
	else
		ret = qpack_encode_integer(name_index, 6, 0x80, buf, sizeof(buf), &encoded_len);

	if (ret)
		return ret;
	offset = encoded_len;

	/* Encode value */
	ret = qpack_encode_string(value, value_len, enc->use_huffman,
				  buf + offset, sizeof(buf) - offset, &encoded_len);
	if (ret)
		return ret;
	offset += encoded_len;

	/* Insert into local dynamic table */
	if (is_static) {
		const struct qpack_static_entry *entry = qpack_static_get(name_index);
		if (entry) {
			ret = qpack_dynamic_table_insert(&enc->dynamic_table,
							 entry->name, entry->name_len,
							 value, value_len);
		}
	}
	/* Note: For dynamic reference, caller should provide name separately */

	if (ret)
		return ret;

	/* Send instruction on encoder stream */
	return tquic_stream_send(enc->encoder_stream, buf, offset, false);
}
EXPORT_SYMBOL_GPL(qpack_encoder_insert_name_ref);

/**
 * qpack_encoder_insert_literal - Send Insert With Literal Name
 * @enc: Encoder
 * @name: Header name
 * @name_len: Name length
 * @value: Header value
 * @value_len: Value length
 *
 * Returns: 0 on success, negative error code on failure
 */
int qpack_encoder_insert_literal(struct qpack_encoder *enc,
				 const char *name, u16 name_len,
				 const char *value, u16 value_len)
{
	u8 buf[QPACK_MAX_HEADER_NAME_LEN + QPACK_MAX_HEADER_VALUE_LEN + 64];
	size_t offset = 0;
	size_t encoded_len;
	int ret;

	if (!enc || !enc->encoder_stream || !name)
		return -EINVAL;

	/* Encode: 01 (6-bit name length prefix) + name + value */
	ret = qpack_encode_string(name, name_len, enc->use_huffman,
				  buf, sizeof(buf), &encoded_len);
	if (ret)
		return ret;

	/* Set prefix: 01xxxxxx */
	buf[0] = (buf[0] & 0x3F) | 0x40;
	offset = encoded_len;

	ret = qpack_encode_string(value, value_len, enc->use_huffman,
				  buf + offset, sizeof(buf) - offset, &encoded_len);
	if (ret)
		return ret;
	offset += encoded_len;

	/* Insert into local dynamic table */
	ret = qpack_dynamic_table_insert(&enc->dynamic_table,
					 name, name_len, value, value_len);
	if (ret)
		return ret;

	/* Send instruction on encoder stream */
	return tquic_stream_send(enc->encoder_stream, buf, offset, false);
}
EXPORT_SYMBOL_GPL(qpack_encoder_insert_literal);

/**
 * qpack_encoder_duplicate - Send Duplicate instruction
 * @enc: Encoder
 * @index: Relative index to duplicate
 *
 * Returns: 0 on success, negative error code on failure
 */
int qpack_encoder_duplicate(struct qpack_encoder *enc, u64 index)
{
	u8 buf[MAX_ENCODED_INT_SIZE];
	size_t encoded_len;
	int ret;

	if (!enc || !enc->encoder_stream)
		return -EINVAL;

	/* Encode: 000xxxxx with 5-bit prefix */
	ret = qpack_encode_integer(index, 5, 0x00, buf, sizeof(buf), &encoded_len);
	if (ret)
		return ret;

	/* Duplicate in local table */
	ret = qpack_dynamic_table_duplicate(&enc->dynamic_table, index);
	if (ret)
		return ret;

	/* Send instruction on encoder stream */
	return tquic_stream_send(enc->encoder_stream, buf, encoded_len, false);
}
EXPORT_SYMBOL_GPL(qpack_encoder_duplicate);

MODULE_DESCRIPTION("QPACK Encoder for HTTP/3");
MODULE_LICENSE("GPL");
