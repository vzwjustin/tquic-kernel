// SPDX-License-Identifier: GPL-2.0-only
/*
 * QPACK Decoder - RFC 9204
 *
 * Copyright (c) 2026 Linux Foundation
 *
 * The QPACK decoder decompresses HTTP header fields for HTTP/3.
 * It maintains a dynamic table synchronized with the encoder and
 * sends acknowledgments on the decoder stream.
 *
 * Decoder stream instructions (sent to encoder):
 * - Section Acknowledgment
 * - Stream Cancellation
 * - Insert Count Increment
 *
 * The decoder processes:
 * - Encoder stream instructions (table updates)
 * - Header field representations (in request/response streams)
 */

#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/module.h>
#include <net/tquic.h>

#include "qpack.h"

/* Maximum encoded integer size */
#define MAX_ENCODED_INT_SIZE	10

/**
 * qpack_decoder_init - Initialize QPACK decoder
 * @dec: Decoder to initialize
 * @conn: Parent connection
 * @max_table_capacity: Maximum dynamic table capacity
 * @max_blocked_streams: Maximum blocked streams
 *
 * Returns: 0 on success, negative error code on failure
 */
int qpack_decoder_init(struct qpack_decoder *dec,
		       struct tquic_connection *conn,
		       u64 max_table_capacity,
		       u32 max_blocked_streams)
{
	int ret;

	if (!dec || !conn)
		return -EINVAL;

	memset(dec, 0, sizeof(*dec));
	dec->conn = conn;
	dec->max_blocked_streams = max_blocked_streams;

	ret = qpack_dynamic_table_init(&dec->dynamic_table, max_table_capacity);
	if (ret)
		return ret;

	INIT_LIST_HEAD(&dec->blocked_streams);
	spin_lock_init(&dec->lock);

	return 0;
}
EXPORT_SYMBOL_GPL(qpack_decoder_init);

/**
 * qpack_decoder_destroy - Release decoder resources
 * @dec: Decoder to destroy
 */
void qpack_decoder_destroy(struct qpack_decoder *dec)
{
	struct qpack_blocked_stream *blocked, *tmp;
	unsigned long flags;

	if (!dec)
		return;

	spin_lock_irqsave(&dec->lock, flags);
	list_for_each_entry_safe(blocked, tmp, &dec->blocked_streams, list) {
		list_del(&blocked->list);
		kfree(blocked);
	}
	spin_unlock_irqrestore(&dec->lock, flags);

	qpack_dynamic_table_destroy(&dec->dynamic_table);
}
EXPORT_SYMBOL_GPL(qpack_decoder_destroy);

/**
 * qpack_decoder_set_stream - Set decoder stream
 * @dec: Decoder
 * @stream: Unidirectional stream for decoder instructions
 */
void qpack_decoder_set_stream(struct qpack_decoder *dec,
			      struct tquic_stream *stream)
{
	if (dec)
		dec->decoder_stream = stream;
}
EXPORT_SYMBOL_GPL(qpack_decoder_set_stream);

/**
 * decode_required_insert_count - Decode Required Insert Count
 * @encoded: Encoded value
 * @max_entries: Maximum table entries
 * @total_inserts: Total insertions so far
 *
 * Returns: Decoded Required Insert Count
 */
static u64 decode_required_insert_count(u64 encoded, u32 max_entries,
					u64 total_inserts)
{
	u64 full_range;
	u64 max_value;
	u64 max_wrapped;
	u64 req_insert_count;

	if (encoded == 0)
		return 0;

	if (max_entries == 0)
		return encoded - 1;

	full_range = 2 * max_entries;
	max_value = total_inserts + max_entries;
	max_wrapped = max_value / full_range * full_range;
	req_insert_count = max_wrapped + encoded - 1;

	if (req_insert_count > max_value) {
		if (req_insert_count <= full_range)
			return 0;  /* Error: would be negative */
		req_insert_count -= full_range;
	}

	return req_insert_count;
}

/**
 * decode_header_indexed_static - Decode indexed header (static table)
 * @index: Static table index
 * @headers: Output header list
 *
 * Returns: 0 on success, negative error code on failure
 */
static int decode_header_indexed_static(u32 index,
					struct qpack_header_list *headers)
{
	const struct qpack_static_entry *entry;

	entry = qpack_static_get(index);
	if (!entry)
		return -EINVAL;

	return qpack_header_list_add(headers, entry->name, entry->name_len,
				     entry->value, entry->value_len, false);
}

/**
 * decode_header_indexed_dynamic - Decode indexed header (dynamic table)
 * @dec: Decoder
 * @relative_index: Relative index from base
 * @base: Base value
 * @headers: Output header list
 *
 * Returns: 0 on success, negative error code on failure
 */
static int decode_header_indexed_dynamic(struct qpack_decoder *dec,
					 u64 relative_index, u64 base,
					 struct qpack_header_list *headers)
{
	struct qpack_dynamic_entry *entry;
	unsigned long flags;
	int ret;

	spin_lock_irqsave(&dec->lock, flags);
	entry = qpack_dynamic_table_get_relative(&dec->dynamic_table,
						 relative_index, base);
	if (!entry) {
		spin_unlock_irqrestore(&dec->lock, flags);
		return -EINVAL;
	}

	ret = qpack_header_list_add(headers, entry->name, entry->name_len,
				    entry->value, entry->value_len, false);
	spin_unlock_irqrestore(&dec->lock, flags);

	return ret;
}

/**
 * decode_header_indexed_post_base - Decode indexed header (post-base)
 * @dec: Decoder
 * @post_base_index: Post-base index
 * @base: Base value
 * @headers: Output header list
 *
 * Returns: 0 on success, negative error code on failure
 */
static int decode_header_indexed_post_base(struct qpack_decoder *dec,
					   u64 post_base_index, u64 base,
					   struct qpack_header_list *headers)
{
	struct qpack_dynamic_entry *entry;
	unsigned long flags;
	int ret;

	spin_lock_irqsave(&dec->lock, flags);
	entry = qpack_dynamic_table_get_post_base(&dec->dynamic_table,
						  post_base_index, base);
	if (!entry) {
		spin_unlock_irqrestore(&dec->lock, flags);
		return -EINVAL;
	}

	ret = qpack_header_list_add(headers, entry->name, entry->name_len,
				    entry->value, entry->value_len, false);
	spin_unlock_irqrestore(&dec->lock, flags);

	return ret;
}

/**
 * qpack_decode_headers - Decode header block
 * @dec: Decoder
 * @stream_id: Request/response stream ID
 * @data: Encoded header block
 * @len: Data length
 * @headers: Output header list
 *
 * Returns: 0 on success, negative error code on failure
 */
int qpack_decode_headers(struct qpack_decoder *dec,
			 u64 stream_id,
			 const u8 *data, size_t len,
			 struct qpack_header_list *headers)
{
	size_t offset = 0;
	size_t consumed;
	u64 encoded_ric, delta_base;
	u64 required_insert_count, base;
	bool sign;
	int ret;

	if (!dec || !data || len == 0 || !headers)
		return -EINVAL;

	qpack_header_list_init(headers);

	/* Decode Required Insert Count */
	ret = qpack_decode_integer(data + offset, len - offset, 8,
				   &encoded_ric, &consumed);
	if (ret)
		return ret;
	offset += consumed;

	required_insert_count = decode_required_insert_count(
		encoded_ric, dec->dynamic_table.max_entries,
		dec->dynamic_table.insert_count);

	/* Decode Sign bit and Delta Base */
	if (offset >= len)
		return -EINVAL;

	sign = !!(data[offset] & 0x80);

	ret = qpack_decode_integer(data + offset, len - offset, 7,
				   &delta_base, &consumed);
	if (ret)
		return ret;
	offset += consumed;

	/* Calculate Base */
	if (sign) {
		/* S=1: Base = Required Insert Count - Delta Base - 1 */
		if (delta_base >= required_insert_count)
			return -EINVAL;
		base = required_insert_count - delta_base - 1;
	} else {
		/* S=0: Base = Required Insert Count + Delta Base */
		base = required_insert_count + delta_base;
	}

	/* Check if we need to wait for table updates */
	if (required_insert_count > dec->dynamic_table.insert_count) {
		/* Would need to block - not implemented yet */
		return -EAGAIN;
	}

	/* Decode header field lines */
	while (offset < len) {
		u8 first_byte = data[offset];
		u64 index;
		char name_buf[QPACK_MAX_HEADER_NAME_LEN];
		char value_buf[QPACK_MAX_HEADER_VALUE_LEN];
		size_t name_len, value_len;
		bool never_index;

		if (first_byte & 0x80) {
			/* Indexed Field Line: 1xxxxxxx */
			bool is_static = !!(first_byte & 0x40);

			ret = qpack_decode_integer(data + offset, len - offset,
						   6, &index, &consumed);
			if (ret)
				goto error;
			offset += consumed;

			if (is_static) {
				ret = decode_header_indexed_static(index, headers);
			} else {
				ret = decode_header_indexed_dynamic(dec, index,
								    base, headers);
			}
			if (ret)
				goto error;

		} else if (first_byte & 0x40) {
			/* Literal with Name Reference: 01xxxxxx */
			bool is_static = !!(first_byte & 0x10);
			never_index = !!(first_byte & 0x20);

			ret = qpack_decode_integer(data + offset, len - offset,
						   4, &index, &consumed);
			if (ret)
				goto error;
			offset += consumed;

			/* Get name from table */
			if (is_static) {
				const struct qpack_static_entry *entry;
				entry = qpack_static_get(index);
				if (!entry) {
					ret = -EINVAL;
					goto error;
				}
				if (entry->name_len >= sizeof(name_buf)) {
					ret = -ENOSPC;
					goto error;
				}
				memcpy(name_buf, entry->name, entry->name_len);
				name_len = entry->name_len;
			} else {
				struct qpack_dynamic_entry *entry;
				unsigned long flags;

				spin_lock_irqsave(&dec->lock, flags);
				entry = qpack_dynamic_table_get_relative(
					&dec->dynamic_table, index, base);
				if (!entry) {
					spin_unlock_irqrestore(&dec->lock, flags);
					ret = -EINVAL;
					goto error;
				}
				if (entry->name_len >= sizeof(name_buf)) {
					spin_unlock_irqrestore(&dec->lock, flags);
					ret = -ENOSPC;
					goto error;
				}
				memcpy(name_buf, entry->name, entry->name_len);
				name_len = entry->name_len;
				spin_unlock_irqrestore(&dec->lock, flags);
			}

			/* Decode value */
			ret = qpack_decode_string(data + offset, len - offset,
						  value_buf, sizeof(value_buf),
						  &value_len, &consumed);
			if (ret)
				goto error;
			offset += consumed;

			ret = qpack_header_list_add(headers, name_buf, name_len,
						    value_buf, value_len,
						    never_index);
			if (ret)
				goto error;

		} else if (first_byte & 0x20) {
			/* Literal with Literal Name: 001xxxxx */
			never_index = !!(first_byte & 0x10);

			/* Decode name */
			ret = qpack_decode_string(data + offset, len - offset,
						  name_buf, sizeof(name_buf),
						  &name_len, &consumed);
			if (ret)
				goto error;
			offset += consumed;

			/* Decode value */
			ret = qpack_decode_string(data + offset, len - offset,
						  value_buf, sizeof(value_buf),
						  &value_len, &consumed);
			if (ret)
				goto error;
			offset += consumed;

			ret = qpack_header_list_add(headers, name_buf, name_len,
						    value_buf, value_len,
						    never_index);
			if (ret)
				goto error;

		} else if (first_byte & 0x10) {
			/* Indexed Field Line with Post-Base Index: 0001xxxx */
			ret = qpack_decode_integer(data + offset, len - offset,
						   4, &index, &consumed);
			if (ret)
				goto error;
			offset += consumed;

			ret = decode_header_indexed_post_base(dec, index, base,
							      headers);
			if (ret)
				goto error;

		} else {
			/* Literal with Post-Base Name Reference: 0000xxxx */
			never_index = !!(first_byte & 0x08);

			ret = qpack_decode_integer(data + offset, len - offset,
						   3, &index, &consumed);
			if (ret)
				goto error;
			offset += consumed;

			/* Get name from post-base dynamic table entry */
			{
				struct qpack_dynamic_entry *entry;
				unsigned long flags;

				spin_lock_irqsave(&dec->lock, flags);
				entry = qpack_dynamic_table_get_post_base(
					&dec->dynamic_table, index, base);
				if (!entry) {
					spin_unlock_irqrestore(&dec->lock, flags);
					ret = -EINVAL;
					goto error;
				}
				if (entry->name_len >= sizeof(name_buf)) {
					spin_unlock_irqrestore(&dec->lock, flags);
					ret = -ENOSPC;
					goto error;
				}
				memcpy(name_buf, entry->name, entry->name_len);
				name_len = entry->name_len;
				spin_unlock_irqrestore(&dec->lock, flags);
			}

			/* Decode value */
			ret = qpack_decode_string(data + offset, len - offset,
						  value_buf, sizeof(value_buf),
						  &value_len, &consumed);
			if (ret)
				goto error;
			offset += consumed;

			ret = qpack_header_list_add(headers, name_buf, name_len,
						    value_buf, value_len,
						    never_index);
			if (ret)
				goto error;
		}
	}

	/* Send Section Acknowledgment */
	if (required_insert_count > 0 && dec->decoder_stream) {
		qpack_decoder_send_section_ack(dec, stream_id);
	}

	return 0;

error:
	qpack_header_list_destroy(headers);
	return ret;
}
EXPORT_SYMBOL_GPL(qpack_decode_headers);

/**
 * qpack_decoder_process_encoder_stream - Process encoder stream data
 * @dec: Decoder
 * @data: Encoder stream data
 * @len: Data length
 *
 * Returns: 0 on success, negative error code on failure
 *
 * Processes encoder instructions:
 * - Set Dynamic Table Capacity
 * - Insert With Name Reference
 * - Insert With Literal Name
 * - Duplicate
 */
int qpack_decoder_process_encoder_stream(struct qpack_decoder *dec,
					 const u8 *data, size_t len)
{
	size_t offset = 0;
	u64 value, index;
	size_t consumed;
	char name_buf[QPACK_MAX_HEADER_NAME_LEN];
	char value_buf[QPACK_MAX_HEADER_VALUE_LEN];
	size_t name_len, value_len;
	int ret;
	u64 inserts_before = 0;

	if (!dec || !data || len == 0)
		return -EINVAL;

	inserts_before = dec->dynamic_table.insert_count;

	while (offset < len) {
		u8 first_byte = data[offset];

		if (first_byte & 0x80) {
			/* Insert With Name Reference: 1xxxxxxx */
			bool is_static = !!(first_byte & 0x40);

			ret = qpack_decode_integer(data + offset, len - offset,
						   6, &index, &consumed);
			if (ret)
				return ret;
			offset += consumed;

			/* Decode value */
			ret = qpack_decode_string(data + offset, len - offset,
						  value_buf, sizeof(value_buf),
						  &value_len, &consumed);
			if (ret)
				return ret;
			offset += consumed;

			/* Get name and insert */
			if (is_static) {
				const struct qpack_static_entry *entry;
				entry = qpack_static_get(index);
				if (!entry)
					return -EINVAL;

				ret = qpack_dynamic_table_insert(&dec->dynamic_table,
								 entry->name,
								 entry->name_len,
								 value_buf,
								 value_len);
			} else {
				struct qpack_dynamic_entry *entry;
				unsigned long flags;

				spin_lock_irqsave(&dec->lock, flags);
				entry = qpack_dynamic_table_get(&dec->dynamic_table,
								index);
				if (!entry) {
					spin_unlock_irqrestore(&dec->lock, flags);
					return -EINVAL;
				}

				if (entry->name_len >= sizeof(name_buf)) {
					spin_unlock_irqrestore(&dec->lock, flags);
					return -ENOSPC;
				}
				memcpy(name_buf, entry->name, entry->name_len);
				name_len = entry->name_len;
				spin_unlock_irqrestore(&dec->lock, flags);

				ret = qpack_dynamic_table_insert(&dec->dynamic_table,
								 name_buf, name_len,
								 value_buf, value_len);
			}
			if (ret)
				return ret;

		} else if (first_byte & 0x40) {
			/* Insert With Literal Name: 01xxxxxx */

			/* Decode name */
			ret = qpack_decode_string(data + offset, len - offset,
						  name_buf, sizeof(name_buf),
						  &name_len, &consumed);
			if (ret)
				return ret;
			offset += consumed;

			/* Decode value */
			ret = qpack_decode_string(data + offset, len - offset,
						  value_buf, sizeof(value_buf),
						  &value_len, &consumed);
			if (ret)
				return ret;
			offset += consumed;

			ret = qpack_dynamic_table_insert(&dec->dynamic_table,
							 name_buf, name_len,
							 value_buf, value_len);
			if (ret)
				return ret;

		} else if (first_byte & 0x20) {
			/* Set Dynamic Table Capacity: 001xxxxx */
			ret = qpack_decode_integer(data + offset, len - offset,
						   5, &value, &consumed);
			if (ret)
				return ret;
			offset += consumed;

			ret = qpack_dynamic_table_set_capacity(&dec->dynamic_table,
							       value);
			if (ret)
				return ret;

		} else {
			/* Duplicate: 000xxxxx */
			ret = qpack_decode_integer(data + offset, len - offset,
						   5, &index, &consumed);
			if (ret)
				return ret;
			offset += consumed;

			ret = qpack_dynamic_table_duplicate(&dec->dynamic_table,
							    index);
			if (ret)
				return ret;
		}
	}

	/* Send Insert Count Increment if needed */
	if (dec->decoder_stream &&
	    dec->dynamic_table.insert_count > inserts_before) {
		u64 increment = dec->dynamic_table.insert_count - inserts_before;
		qpack_decoder_send_insert_count_inc(dec, increment);
	}

	return 0;
}
EXPORT_SYMBOL_GPL(qpack_decoder_process_encoder_stream);

/*
 * =============================================================================
 * Decoder Stream Instructions
 * =============================================================================
 */

/**
 * qpack_decoder_send_section_ack - Send Section Acknowledgment
 * @dec: Decoder
 * @stream_id: Stream ID to acknowledge
 *
 * Returns: 0 on success, negative error code on failure
 */
int qpack_decoder_send_section_ack(struct qpack_decoder *dec, u64 stream_id)
{
	u8 buf[MAX_ENCODED_INT_SIZE];
	size_t encoded_len;
	int ret;

	if (!dec || !dec->decoder_stream)
		return -EINVAL;

	/* Encode: 1xxxxxxx with 7-bit prefix */
	ret = qpack_encode_integer(stream_id, 7, 0x80, buf, sizeof(buf), &encoded_len);
	if (ret)
		return ret;

	return tquic_stream_send(dec->decoder_stream, buf, encoded_len, false);
}
EXPORT_SYMBOL_GPL(qpack_decoder_send_section_ack);

/**
 * qpack_decoder_send_stream_cancel - Send Stream Cancellation
 * @dec: Decoder
 * @stream_id: Stream ID to cancel
 *
 * Returns: 0 on success, negative error code on failure
 */
int qpack_decoder_send_stream_cancel(struct qpack_decoder *dec, u64 stream_id)
{
	u8 buf[MAX_ENCODED_INT_SIZE];
	size_t encoded_len;
	int ret;

	if (!dec || !dec->decoder_stream)
		return -EINVAL;

	/* Encode: 01xxxxxx with 6-bit prefix */
	ret = qpack_encode_integer(stream_id, 6, 0x40, buf, sizeof(buf), &encoded_len);
	if (ret)
		return ret;

	return tquic_stream_send(dec->decoder_stream, buf, encoded_len, false);
}
EXPORT_SYMBOL_GPL(qpack_decoder_send_stream_cancel);

/**
 * qpack_decoder_send_insert_count_inc - Send Insert Count Increment
 * @dec: Decoder
 * @increment: Insert count increment value
 *
 * Returns: 0 on success, negative error code on failure
 */
int qpack_decoder_send_insert_count_inc(struct qpack_decoder *dec, u64 increment)
{
	u8 buf[MAX_ENCODED_INT_SIZE];
	size_t encoded_len;
	int ret;

	if (!dec || !dec->decoder_stream || increment == 0)
		return -EINVAL;

	/* Encode: 00xxxxxx with 6-bit prefix */
	ret = qpack_encode_integer(increment, 6, 0x00, buf, sizeof(buf), &encoded_len);
	if (ret)
		return ret;

	return tquic_stream_send(dec->decoder_stream, buf, encoded_len, false);
}
EXPORT_SYMBOL_GPL(qpack_decoder_send_insert_count_inc);

MODULE_DESCRIPTION("QPACK Decoder for HTTP/3");
MODULE_LICENSE("GPL");
