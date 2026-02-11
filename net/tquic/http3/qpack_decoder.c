// SPDX-License-Identifier: GPL-2.0-only
/*
 * QPACK Decoder - RFC 9204
 *
 * Copyright (c) 2026 Linux Foundation
 * Kernel implementation by Justin Adams <spotty118@gmail.com>
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

/*
 * Maximum total memory for blocked stream data buffers per connection.
 * This prevents a malicious peer from causing unbounded memory growth
 * by sending many header blocks that reference future dynamic table entries.
 */
#define QPACK_MAX_BLOCKED_MEMORY	(1024 * 1024)	/* 1 MB */

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
		dec->blocked_stream_bytes -= blocked->data_len;
		kfree(blocked->data);
		kfree(blocked);
	}
	dec->blocked_stream_count = 0;
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

/* Forward declaration -- defined below qpack_decode_headers() */
static int qpack_decode_header_fields(struct qpack_decoder *dec,
				      const u8 *data, size_t len,
				      size_t offset, u64 base,
				      struct qpack_header_list *headers,
				      char *name_buf, char *value_buf);

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
		struct qpack_blocked_stream *blocked;
		unsigned long flags;

		/*
		 * Stream requires entries not yet in the dynamic table.
		 * Per RFC 9204 Section 2.1.2, we must block this stream
		 * until the required entries have been inserted.
		 *
		 * Check if we're at the blocked stream limit.
		 */
		spin_lock_irqsave(&dec->lock, flags);

		if (dec->blocked_stream_count >= dec->max_blocked_streams) {
			spin_unlock_irqrestore(&dec->lock, flags);
			/*
			 * At limit - connection error per RFC 9204 Section 4.2:
			 * "If the decoder encounters more blocked streams than it
			 * announced with SETTINGS_QPACK_BLOCKED_STREAMS, this MUST
			 * be treated as a connection error of type
			 * QPACK_DECOMPRESSION_FAILED."
			 */
			pr_debug("qpack: blocked stream limit reached (%u)\n",
				 dec->max_blocked_streams);
			return -ENOBUFS;
		}

		/*
		 * Enforce a per-connection memory limit on buffered blocked
		 * stream data to prevent unbounded memory exhaustion from a
		 * malicious peer sending many large header blocks that
		 * reference future dynamic table entries.
		 */
		if (dec->blocked_stream_bytes + len > QPACK_MAX_BLOCKED_MEMORY) {
			spin_unlock_irqrestore(&dec->lock, flags);
			pr_warn("qpack: blocked stream memory limit exceeded (%zu + %zu > %u)\n",
				dec->blocked_stream_bytes, len,
				QPACK_MAX_BLOCKED_MEMORY);
			return -ENOBUFS;
		}

		spin_unlock_irqrestore(&dec->lock, flags);

		/* Add stream to blocked list */
		blocked = kzalloc(sizeof(*blocked), GFP_ATOMIC);
		if (!blocked)
			return -ENOMEM;

		blocked->stream_id = stream_id;
		blocked->required_insert_count = required_insert_count;
		blocked->data = kmemdup(data, len, GFP_ATOMIC);
		if (!blocked->data) {
			kfree(blocked);
			return -ENOMEM;
		}
		blocked->data_len = len;

		spin_lock_irqsave(&dec->lock, flags);

		/* Re-check limits under lock after allocation */
		if (dec->blocked_stream_count >= dec->max_blocked_streams ||
		    dec->blocked_stream_bytes + len > QPACK_MAX_BLOCKED_MEMORY) {
			spin_unlock_irqrestore(&dec->lock, flags);
			kfree(blocked->data);
			kfree(blocked);
			return -ENOBUFS;
		}

		list_add_tail(&blocked->list, &dec->blocked_streams);
		dec->blocked_stream_count++;
		dec->blocked_stream_bytes += len;

		spin_unlock_irqrestore(&dec->lock, flags);

		pr_debug("qpack: stream %llu blocked waiting for insert_count %llu (have %llu)\n",
			 stream_id, required_insert_count,
			 dec->dynamic_table.insert_count);

		/*
		 * Return -EAGAIN to indicate the decode is pending.
		 * The caller should not treat this as an error but
		 * rather as "decode in progress, will complete later".
		 */
		return -EAGAIN;
	}

	/*
	 * Heap-allocate decode buffers to avoid kernel stack overflow.
	 * QPACK_MAX_HEADER_VALUE_LEN (8192) alone exceeds safe stack usage.
	 */
	{
		char *name_buf, *value_buf;

		name_buf = kmalloc(QPACK_MAX_HEADER_NAME_LEN, GFP_ATOMIC);
		value_buf = kmalloc(QPACK_MAX_HEADER_VALUE_LEN, GFP_ATOMIC);
		if (!name_buf || !value_buf) {
			kfree(name_buf);
			kfree(value_buf);
			qpack_header_list_destroy(headers);
			return -ENOMEM;
		}

		ret = qpack_decode_header_fields(dec, data, len, offset,
						 base, headers,
						 name_buf, value_buf);
		kfree(name_buf);
		kfree(value_buf);

		if (ret < 0) {
			qpack_header_list_destroy(headers);
			return ret;
		}
	}

	/* Send Section Acknowledgment */
	if (required_insert_count > 0 && dec->decoder_stream) {
		qpack_decoder_send_section_ack(dec, stream_id);
	}

	return 0;
}
EXPORT_SYMBOL_GPL(qpack_decode_headers);

/**
 * qpack_decode_header_fields - Decode header field lines with provided buffers
 * @dec: Decoder
 * @data: Encoded header block
 * @len: Data length
 * @offset: Starting offset within data
 * @base: Base value for dynamic table addressing
 * @headers: Output header list
 * @name_buf: Pre-allocated name buffer (QPACK_MAX_HEADER_NAME_LEN bytes)
 * @value_buf: Pre-allocated value buffer (QPACK_MAX_HEADER_VALUE_LEN bytes)
 *
 * Returns: final offset on success, negative error code on failure
 */
static int qpack_decode_header_fields(struct qpack_decoder *dec,
				      const u8 *data, size_t len,
				      size_t offset, u64 base,
				      struct qpack_header_list *headers,
				      char *name_buf, char *value_buf)
{
	size_t consumed;
	u64 index;
	size_t name_len, value_len;
	bool never_index;
	int ret;

	while (offset < len) {
		u8 first_byte = data[offset];

		if (first_byte & 0x80) {
			/* Indexed Field Line: 1xxxxxxx */
			bool is_static = !!(first_byte & 0x40);

			ret = qpack_decode_integer(data + offset, len - offset,
						   6, &index, &consumed);
			if (ret)
				return ret;
			offset += consumed;

			if (is_static) {
				ret = decode_header_indexed_static(index, headers);
			} else {
				ret = decode_header_indexed_dynamic(dec, index,
								    base, headers);
			}
			if (ret)
				return ret;

		} else if (first_byte & 0x40) {
			/* Literal with Name Reference: 01xxxxxx */
			bool is_static = !!(first_byte & 0x10);
			never_index = !!(first_byte & 0x20);

			ret = qpack_decode_integer(data + offset, len - offset,
						   4, &index, &consumed);
			if (ret)
				return ret;
			offset += consumed;

			/* Get name from table */
			if (is_static) {
				const struct qpack_static_entry *entry;
				entry = qpack_static_get(index);
				if (!entry) {
					ret = -EINVAL;
					return ret;
				}
				if (entry->name_len >= QPACK_MAX_HEADER_NAME_LEN) {
					ret = -ENOSPC;
					return ret;
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
					return ret;
				}
				if (entry->name_len >= QPACK_MAX_HEADER_NAME_LEN) {
					spin_unlock_irqrestore(&dec->lock, flags);
					ret = -ENOSPC;
					return ret;
				}
				memcpy(name_buf, entry->name, entry->name_len);
				name_len = entry->name_len;
				spin_unlock_irqrestore(&dec->lock, flags);
			}

			/* Decode value */
			ret = qpack_decode_string(data + offset, len - offset,
						  value_buf, QPACK_MAX_HEADER_VALUE_LEN,
						  &value_len, &consumed);
			if (ret)
				return ret;
			offset += consumed;

			ret = qpack_header_list_add(headers, name_buf, name_len,
						    value_buf, value_len,
						    never_index);
			if (ret)
				return ret;

		} else if (first_byte & 0x20) {
			/* Literal with Literal Name: 001xxxxx */
			never_index = !!(first_byte & 0x10);

			/* Decode name */
			ret = qpack_decode_string(data + offset, len - offset,
						  name_buf, QPACK_MAX_HEADER_NAME_LEN,
						  &name_len, &consumed);
			if (ret)
				return ret;
			offset += consumed;

			/* Decode value */
			ret = qpack_decode_string(data + offset, len - offset,
						  value_buf, QPACK_MAX_HEADER_VALUE_LEN,
						  &value_len, &consumed);
			if (ret)
				return ret;
			offset += consumed;

			ret = qpack_header_list_add(headers, name_buf, name_len,
						    value_buf, value_len,
						    never_index);
			if (ret)
				return ret;

		} else if (first_byte & 0x10) {
			/* Indexed Field Line with Post-Base Index: 0001xxxx */
			ret = qpack_decode_integer(data + offset, len - offset,
						   4, &index, &consumed);
			if (ret)
				return ret;
			offset += consumed;

			ret = decode_header_indexed_post_base(dec, index, base,
							      headers);
			if (ret)
				return ret;

		} else {
			/* Literal with Post-Base Name Reference: 0000xxxx */
			never_index = !!(first_byte & 0x08);

			ret = qpack_decode_integer(data + offset, len - offset,
						   3, &index, &consumed);
			if (ret)
				return ret;
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
					return ret;
				}
				if (entry->name_len >= QPACK_MAX_HEADER_NAME_LEN) {
					spin_unlock_irqrestore(&dec->lock, flags);
					ret = -ENOSPC;
					return ret;
				}
				memcpy(name_buf, entry->name, entry->name_len);
				name_len = entry->name_len;
				spin_unlock_irqrestore(&dec->lock, flags);
			}

			/* Decode value */
			ret = qpack_decode_string(data + offset, len - offset,
						  value_buf, QPACK_MAX_HEADER_VALUE_LEN,
						  &value_len, &consumed);
			if (ret)
				return ret;
			offset += consumed;

			ret = qpack_header_list_add(headers, name_buf, name_len,
						    value_buf, value_len,
						    never_index);
			if (ret)
				return ret;
		}
	}

	return 0;
}

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
	char *name_buf, *value_buf;
	size_t name_len, value_len;
	int ret;
	u64 inserts_before = 0;

	if (!dec || !data || len == 0)
		return -EINVAL;

	/*
	 * Heap-allocate decode buffers to avoid kernel stack overflow.
	 * QPACK_MAX_HEADER_VALUE_LEN (8192) alone exceeds safe stack usage.
	 */
	name_buf = kmalloc(QPACK_MAX_HEADER_NAME_LEN, GFP_ATOMIC);
	value_buf = kmalloc(QPACK_MAX_HEADER_VALUE_LEN, GFP_ATOMIC);
	if (!name_buf || !value_buf) {
		kfree(name_buf);
		kfree(value_buf);
		return -ENOMEM;
	}

	inserts_before = dec->dynamic_table.insert_count;

	while (offset < len) {
		u8 first_byte = data[offset];

		if (first_byte & 0x80) {
			/* Insert With Name Reference: 1xxxxxxx */
			bool is_static = !!(first_byte & 0x40);

			ret = qpack_decode_integer(data + offset, len - offset,
						   6, &index, &consumed);
			if (ret)
				goto out_free;
			offset += consumed;

			/* Decode value */
			ret = qpack_decode_string(data + offset, len - offset,
						  value_buf, QPACK_MAX_HEADER_VALUE_LEN,
						  &value_len, &consumed);
			if (ret)
				goto out_free;
			offset += consumed;

			/* Get name and insert */
			if (is_static) {
				const struct qpack_static_entry *entry;
				entry = qpack_static_get(index);
				if (!entry) {
					ret = -EINVAL;
					goto out_free;
				}

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
					ret = -EINVAL;
					goto out_free;
				}

				if (entry->name_len >= QPACK_MAX_HEADER_NAME_LEN) {
					spin_unlock_irqrestore(&dec->lock, flags);
					ret = -ENOSPC;
					goto out_free;
				}
				memcpy(name_buf, entry->name, entry->name_len);
				name_len = entry->name_len;
				spin_unlock_irqrestore(&dec->lock, flags);

				ret = qpack_dynamic_table_insert(&dec->dynamic_table,
								 name_buf, name_len,
								 value_buf, value_len);
			}
			if (ret)
				goto out_free;

		} else if (first_byte & 0x40) {
			/* Insert With Literal Name: 01xxxxxx */

			/* Decode name */
			ret = qpack_decode_string(data + offset, len - offset,
						  name_buf, QPACK_MAX_HEADER_NAME_LEN,
						  &name_len, &consumed);
			if (ret)
				goto out_free;
			offset += consumed;

			/* Decode value */
			ret = qpack_decode_string(data + offset, len - offset,
						  value_buf, QPACK_MAX_HEADER_VALUE_LEN,
						  &value_len, &consumed);
			if (ret)
				goto out_free;
			offset += consumed;

			ret = qpack_dynamic_table_insert(&dec->dynamic_table,
							 name_buf, name_len,
							 value_buf, value_len);
			if (ret)
				goto out_free;

		} else if (first_byte & 0x20) {
			/* Set Dynamic Table Capacity: 001xxxxx */
			ret = qpack_decode_integer(data + offset, len - offset,
						   5, &value, &consumed);
			if (ret)
				goto out_free;
			offset += consumed;

			ret = qpack_dynamic_table_set_capacity(&dec->dynamic_table,
							       value);
			if (ret)
				goto out_free;

		} else {
			/* Duplicate: 000xxxxx */
			ret = qpack_decode_integer(data + offset, len - offset,
						   5, &index, &consumed);
			if (ret)
				goto out_free;
			offset += consumed;

			ret = qpack_dynamic_table_duplicate(&dec->dynamic_table,
							    index);
			if (ret)
				goto out_free;
		}
	}

	/* Send Insert Count Increment if needed */
	if (dec->decoder_stream &&
	    dec->dynamic_table.insert_count > inserts_before) {
		u64 increment = dec->dynamic_table.insert_count - inserts_before;
		qpack_decoder_send_insert_count_inc(dec, increment);

		/* Try to unblock any streams that were waiting for table updates */
		qpack_decoder_process_blocked_streams(dec);
	}

	ret = 0;

out_free:
	kfree(name_buf);
	kfree(value_buf);
	return ret;
}
EXPORT_SYMBOL_GPL(qpack_decoder_process_encoder_stream);

/**
 * qpack_decoder_process_blocked_streams - Try to decode blocked streams
 * @dec: Decoder
 *
 * Processes any blocked streams that can now be decoded because the
 * dynamic table has been updated with the required entries.
 *
 * Returns: Number of streams unblocked
 */
int qpack_decoder_process_blocked_streams(struct qpack_decoder *dec)
{
	struct qpack_blocked_stream *blocked, *tmp;
	LIST_HEAD(ready_list);
	unsigned long flags;
	int unblocked = 0;

	if (!dec)
		return 0;

	spin_lock_irqsave(&dec->lock, flags);

	/* Find streams that can now be decoded */
	list_for_each_entry_safe(blocked, tmp, &dec->blocked_streams, list) {
		if (blocked->required_insert_count <= dec->dynamic_table.insert_count) {
			list_del(&blocked->list);
			list_add_tail(&blocked->list, &ready_list);
			dec->blocked_stream_count--;
			dec->blocked_stream_bytes -= blocked->data_len;
		}
	}

	spin_unlock_irqrestore(&dec->lock, flags);

	/* Process ready streams outside the lock */
	list_for_each_entry_safe(blocked, tmp, &ready_list, list) {
		struct qpack_header_list headers;
		int ret;

		pr_debug("qpack: unblocking stream %llu (insert_count now %llu)\n",
			 blocked->stream_id, dec->dynamic_table.insert_count);

		ret = qpack_decode_headers(dec, blocked->stream_id,
					   blocked->data, blocked->data_len,
					   &headers);
		if (ret == 0) {
			/*
			 * Successfully decoded - deliver headers to HTTP/3 layer.
			 * This callback should be set up by the HTTP/3 connection.
			 */
			if (dec->on_headers_decoded)
				dec->on_headers_decoded(dec->conn, blocked->stream_id,
							&headers);
			qpack_header_list_destroy(&headers);
			unblocked++;
		} else if (ret != -EAGAIN) {
			/* Real error - log and continue */
			pr_warn("qpack: failed to decode unblocked stream %llu: %d\n",
				blocked->stream_id, ret);
		}
		/* If ret == -EAGAIN, stream is re-blocked (needs more inserts) */

		list_del(&blocked->list);
		kfree(blocked->data);
		kfree(blocked);
	}

	return unblocked;
}
EXPORT_SYMBOL_GPL(qpack_decoder_process_blocked_streams);

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
