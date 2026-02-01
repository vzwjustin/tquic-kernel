/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * QPACK Header Compression for HTTP/3
 *
 * Copyright (c) 2026 Linux Foundation
 *
 * QPACK is a header compression format for HTTP/3 as defined in RFC 9204.
 * It is designed to work with QUIC's independent stream processing while
 * avoiding head-of-line blocking issues that affected HPACK in HTTP/2.
 *
 * This implementation provides:
 * - Static table with 99 predefined entries (RFC 9204 Appendix A)
 * - Dynamic table for connection-specific headers
 * - Encoder stream (unidirectional type 0x02) for table updates
 * - Decoder stream (unidirectional type 0x03) for acknowledgments
 * - Huffman coding per RFC 7541 Appendix B
 */

#ifndef _TQUIC_QPACK_H
#define _TQUIC_QPACK_H

#include <linux/types.h>
#include <linux/list.h>
#include <linux/spinlock.h>
#include <linux/refcount.h>

/* QPACK stream types (unidirectional) per RFC 9204 Section 4 */
#define QPACK_STREAM_TYPE_ENCODER	0x02
#define QPACK_STREAM_TYPE_DECODER	0x03

/* QPACK constants */
#define QPACK_STATIC_TABLE_SIZE		99
#define QPACK_DEFAULT_MAX_TABLE_CAPACITY	4096
#define QPACK_MAX_HEADER_NAME_LEN	256
#define QPACK_MAX_HEADER_VALUE_LEN	8192
#define QPACK_MAX_BLOCKED_STREAMS	100

/* Instruction prefixes (encoder stream) - RFC 9204 Section 4.3 */
#define QPACK_ENC_SET_CAPACITY_PREFIX		0x20	/* 001xxxxx */
#define QPACK_ENC_INSERT_NAME_REF_PREFIX	0x80	/* 1xxxxxxx */
#define QPACK_ENC_INSERT_LITERAL_PREFIX		0x40	/* 01xxxxxx */
#define QPACK_ENC_DUPLICATE_PREFIX		0x00	/* 000xxxxx */

/* Instruction prefixes (decoder stream) - RFC 9204 Section 4.4 */
#define QPACK_DEC_SECTION_ACK_PREFIX		0x80	/* 1xxxxxxx */
#define QPACK_DEC_STREAM_CANCEL_PREFIX		0x40	/* 01xxxxxx */
#define QPACK_DEC_INSERT_COUNT_INC_PREFIX	0x00	/* 00xxxxxx */

/* Header field representation prefixes - RFC 9204 Section 4.5 */
#define QPACK_HDR_INDEXED_STATIC_PREFIX		0x80	/* 1xxxxxxx (T=1) */
#define QPACK_HDR_INDEXED_DYNAMIC_PREFIX	0x80	/* 1xxxxxxx (T=0) */
#define QPACK_HDR_INDEXED_POST_BASE_PREFIX	0x10	/* 0001xxxx */
#define QPACK_HDR_LITERAL_NAME_REF_PREFIX	0x40	/* 01xxxxxx */
#define QPACK_HDR_LITERAL_POST_BASE_PREFIX	0x00	/* 0000xxxx */
#define QPACK_HDR_LITERAL_NAME_PREFIX		0x20	/* 001xxxxx */

/* Forward declarations */
struct tquic_connection;
struct tquic_stream;
struct qpack_encoder;
struct qpack_decoder;
struct qpack_header_field;

/**
 * struct qpack_static_entry - Static table entry
 * @name: Header field name
 * @name_len: Length of name
 * @value: Header field value (may be NULL)
 * @value_len: Length of value
 */
struct qpack_static_entry {
	const char *name;
	u16 name_len;
	const char *value;
	u16 value_len;
};

/**
 * struct qpack_dynamic_entry - Dynamic table entry
 * @name: Header field name (allocated)
 * @name_len: Length of name
 * @value: Header field value (allocated)
 * @value_len: Length of value
 * @size: Entry size (name_len + value_len + 32)
 * @absolute_index: Absolute index in dynamic table
 * @list: Linked list node for FIFO ordering
 * @refcnt: Reference count for blocking
 */
struct qpack_dynamic_entry {
	char *name;
	u16 name_len;
	char *value;
	u16 value_len;
	u32 size;
	u64 absolute_index;
	struct list_head list;
	refcount_t refcnt;
};

/**
 * struct qpack_dynamic_table - Dynamic table state
 * @entries: List of dynamic entries (newest first)
 * @capacity: Maximum table size in bytes
 * @size: Current table size in bytes
 * @max_entries: Maximum number of entries
 * @num_entries: Current number of entries
 * @insert_count: Number of entries inserted
 * @acked_insert_count: Insert count acknowledged by peer
 * @lock: Spinlock for table access
 */
struct qpack_dynamic_table {
	struct list_head entries;
	u64 capacity;
	u64 size;
	u32 max_entries;
	u32 num_entries;
	u64 insert_count;
	u64 acked_insert_count;
	spinlock_t lock;
};

/**
 * struct qpack_header_field - Decoded header field
 * @name: Header name
 * @name_len: Length of name
 * @value: Header value
 * @value_len: Length of value
 * @never_index: True if field should never be indexed
 * @list: Linked list node
 */
struct qpack_header_field {
	char *name;
	u16 name_len;
	char *value;
	u16 value_len;
	bool never_index;
	struct list_head list;
};

/**
 * struct qpack_header_list - List of header fields
 * @headers: List of qpack_header_field entries
 * @count: Number of headers
 * @total_size: Total uncompressed size
 */
struct qpack_header_list {
	struct list_head headers;
	u32 count;
	u64 total_size;
};

/**
 * struct qpack_blocked_stream - Stream blocked on dynamic table
 * @stream_id: QUIC stream ID
 * @required_insert_count: Required insert count to unblock
 * @list: Linked list node
 */
struct qpack_blocked_stream {
	u64 stream_id;
	u64 required_insert_count;
	struct list_head list;
};

/**
 * struct qpack_encoder - QPACK encoder state
 * @conn: Parent connection
 * @encoder_stream: Encoder stream for sending instructions
 * @dynamic_table: Encoder's dynamic table
 * @max_blocked_streams: Maximum number of blocked streams
 * @blocked_streams: List of blocked streams
 * @num_blocked: Number of currently blocked streams
 * @known_received_count: Known received insert count from decoder
 * @use_huffman: Whether to use Huffman coding
 * @lock: Spinlock for encoder state
 */
struct qpack_encoder {
	struct tquic_connection *conn;
	struct tquic_stream *encoder_stream;
	struct qpack_dynamic_table dynamic_table;
	u32 max_blocked_streams;
	struct list_head blocked_streams;
	u32 num_blocked;
	u64 known_received_count;
	bool use_huffman;
	spinlock_t lock;
};

/**
 * struct qpack_decoder - QPACK decoder state
 * @conn: Parent connection
 * @decoder_stream: Decoder stream for sending acknowledgments
 * @dynamic_table: Decoder's dynamic table
 * @max_blocked_streams: Maximum number of blocked streams
 * @blocked_streams: List of blocked streams
 * @num_blocked: Number of currently blocked streams
 * @lock: Spinlock for decoder state
 */
struct qpack_decoder {
	struct tquic_connection *conn;
	struct tquic_stream *decoder_stream;
	struct qpack_dynamic_table dynamic_table;
	u32 max_blocked_streams;
	struct list_head blocked_streams;
	u32 num_blocked;
	spinlock_t lock;
};

/**
 * struct qpack_context - Combined QPACK encoder/decoder context
 * @encoder: Encoder state
 * @decoder: Decoder state
 * @conn: Parent connection
 */
struct qpack_context {
	struct qpack_encoder encoder;
	struct qpack_decoder decoder;
	struct tquic_connection *conn;
};

/*
 * =============================================================================
 * Static Table API (qpack_static.c)
 * =============================================================================
 */

/* Get static table entry by index (0-98) */
const struct qpack_static_entry *qpack_static_get(u32 index);

/* Find static table entry by name (returns index or -1) */
int qpack_static_find_name(const char *name, u16 name_len);

/* Find static table entry by name and value (returns index or -1) */
int qpack_static_find(const char *name, u16 name_len,
		      const char *value, u16 value_len);

/* Get static table size */
u32 qpack_static_table_size(void);

/*
 * =============================================================================
 * Dynamic Table API (qpack_dynamic.c)
 * =============================================================================
 */

/* Initialize dynamic table */
int qpack_dynamic_table_init(struct qpack_dynamic_table *table, u64 capacity);

/* Release dynamic table resources */
void qpack_dynamic_table_destroy(struct qpack_dynamic_table *table);

/* Set dynamic table capacity (may evict entries) */
int qpack_dynamic_table_set_capacity(struct qpack_dynamic_table *table,
				     u64 capacity);

/* Insert entry into dynamic table */
int qpack_dynamic_table_insert(struct qpack_dynamic_table *table,
			       const char *name, u16 name_len,
			       const char *value, u16 value_len);

/* Duplicate entry in dynamic table */
int qpack_dynamic_table_duplicate(struct qpack_dynamic_table *table,
				  u64 index);

/* Get entry by absolute index */
struct qpack_dynamic_entry *qpack_dynamic_table_get(
	struct qpack_dynamic_table *table, u64 absolute_index);

/* Get entry by relative index (for field line encoding) */
struct qpack_dynamic_entry *qpack_dynamic_table_get_relative(
	struct qpack_dynamic_table *table, u64 relative_index, u64 base);

/* Get entry by post-base index */
struct qpack_dynamic_entry *qpack_dynamic_table_get_post_base(
	struct qpack_dynamic_table *table, u64 post_base_index, u64 base);

/* Find entry by name (returns absolute index or -1) */
s64 qpack_dynamic_table_find_name(struct qpack_dynamic_table *table,
				  const char *name, u16 name_len);

/* Find entry by name and value (returns absolute index or -1) */
s64 qpack_dynamic_table_find(struct qpack_dynamic_table *table,
			     const char *name, u16 name_len,
			     const char *value, u16 value_len);

/* Acknowledge insertions up to given count */
void qpack_dynamic_table_acknowledge(struct qpack_dynamic_table *table,
				     u64 insert_count);

/*
 * =============================================================================
 * Encoder API (qpack_encoder.c)
 * =============================================================================
 */

/* Initialize encoder */
int qpack_encoder_init(struct qpack_encoder *enc,
		       struct tquic_connection *conn,
		       u64 max_table_capacity,
		       u32 max_blocked_streams);

/* Release encoder resources */
void qpack_encoder_destroy(struct qpack_encoder *enc);

/* Set encoder stream for sending instructions */
void qpack_encoder_set_stream(struct qpack_encoder *enc,
			      struct tquic_stream *stream);

/* Encode headers into request/push header block */
int qpack_encode_headers(struct qpack_encoder *enc,
			 u64 stream_id,
			 struct qpack_header_list *headers,
			 u8 *buf, size_t buf_len, size_t *encoded_len);

/* Process decoder acknowledgments */
int qpack_encoder_process_decoder_stream(struct qpack_encoder *enc,
					 const u8 *data, size_t len);

/*
 * Encoder stream instructions
 */

/* Send Set Dynamic Table Capacity instruction */
int qpack_encoder_set_capacity(struct qpack_encoder *enc, u64 capacity);

/* Send Insert With Name Reference instruction */
int qpack_encoder_insert_name_ref(struct qpack_encoder *enc,
				  bool is_static, u64 name_index,
				  const char *value, u16 value_len);

/* Send Insert With Literal Name instruction */
int qpack_encoder_insert_literal(struct qpack_encoder *enc,
				 const char *name, u16 name_len,
				 const char *value, u16 value_len);

/* Send Duplicate instruction */
int qpack_encoder_duplicate(struct qpack_encoder *enc, u64 index);

/*
 * =============================================================================
 * Decoder API (qpack_decoder.c)
 * =============================================================================
 */

/* Initialize decoder */
int qpack_decoder_init(struct qpack_decoder *dec,
		       struct tquic_connection *conn,
		       u64 max_table_capacity,
		       u32 max_blocked_streams);

/* Release decoder resources */
void qpack_decoder_destroy(struct qpack_decoder *dec);

/* Set decoder stream for sending acknowledgments */
void qpack_decoder_set_stream(struct qpack_decoder *dec,
			      struct tquic_stream *stream);

/* Decode headers from request/push header block */
int qpack_decode_headers(struct qpack_decoder *dec,
			 u64 stream_id,
			 const u8 *data, size_t len,
			 struct qpack_header_list *headers);

/* Process encoder instructions */
int qpack_decoder_process_encoder_stream(struct qpack_decoder *dec,
					 const u8 *data, size_t len);

/*
 * Decoder stream instructions
 */

/* Send Section Acknowledgment */
int qpack_decoder_send_section_ack(struct qpack_decoder *dec, u64 stream_id);

/* Send Stream Cancellation */
int qpack_decoder_send_stream_cancel(struct qpack_decoder *dec, u64 stream_id);

/* Send Insert Count Increment */
int qpack_decoder_send_insert_count_inc(struct qpack_decoder *dec, u64 increment);

/*
 * =============================================================================
 * Main QPACK API (qpack.c)
 * =============================================================================
 */

/* Create QPACK context for connection */
struct qpack_context *qpack_context_create(struct tquic_connection *conn,
					   u64 max_table_capacity,
					   u32 max_blocked_streams);

/* Destroy QPACK context */
void qpack_context_destroy(struct qpack_context *ctx);

/* Set encoder/decoder streams after connection setup */
int qpack_context_set_streams(struct qpack_context *ctx,
			      struct tquic_stream *encoder_stream,
			      struct tquic_stream *decoder_stream);

/* Process incoming data on encoder stream */
int qpack_process_encoder_stream(struct qpack_context *ctx,
				 const u8 *data, size_t len);

/* Process incoming data on decoder stream */
int qpack_process_decoder_stream(struct qpack_context *ctx,
				 const u8 *data, size_t len);

/*
 * =============================================================================
 * Header List Helpers
 * =============================================================================
 */

/* Initialize header list */
void qpack_header_list_init(struct qpack_header_list *list);

/* Add header to list */
int qpack_header_list_add(struct qpack_header_list *list,
			  const char *name, u16 name_len,
			  const char *value, u16 value_len,
			  bool never_index);

/* Free all headers in list */
void qpack_header_list_destroy(struct qpack_header_list *list);

/* Find header by name (first match) */
struct qpack_header_field *qpack_header_list_find(struct qpack_header_list *list,
						  const char *name, u16 name_len);

/*
 * =============================================================================
 * Huffman Coding API
 * =============================================================================
 */

/* Encode data using Huffman coding */
int qpack_huffman_encode(const u8 *src, size_t src_len,
			 u8 *dst, size_t dst_len, size_t *encoded_len);

/* Decode Huffman-encoded data */
int qpack_huffman_decode(const u8 *src, size_t src_len,
			 u8 *dst, size_t dst_len, size_t *decoded_len);

/* Calculate Huffman-encoded length */
size_t qpack_huffman_encoded_len(const u8 *src, size_t src_len);

/*
 * =============================================================================
 * Integer Encoding/Decoding (QPACK uses HPACK integer format)
 * =============================================================================
 */

/* Encode integer with given prefix bits */
int qpack_encode_integer(u64 value, u8 prefix_bits, u8 prefix_value,
			 u8 *buf, size_t buf_len, size_t *encoded_len);

/* Decode integer with given prefix bits */
int qpack_decode_integer(const u8 *buf, size_t buf_len, u8 prefix_bits,
			 u64 *value, size_t *consumed);

/*
 * =============================================================================
 * String Encoding/Decoding
 * =============================================================================
 */

/* Encode string (with optional Huffman) */
int qpack_encode_string(const char *str, u16 str_len, bool huffman,
			u8 *buf, size_t buf_len, size_t *encoded_len);

/* Decode string */
int qpack_decode_string(const u8 *buf, size_t buf_len,
			char *str, size_t str_max_len,
			size_t *str_len, size_t *consumed);

/*
 * =============================================================================
 * Module Initialization
 * =============================================================================
 */

/* Initialize QPACK subsystem */
int __init qpack_init(void);

/* Cleanup QPACK subsystem */
void __exit qpack_exit(void);

/* Sysctl accessor */
u64 qpack_sysctl_max_table_capacity(void);

#endif /* _TQUIC_QPACK_H */
