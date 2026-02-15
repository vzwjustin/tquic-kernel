// SPDX-License-Identifier: GPL-2.0-only
/*
 * TQUIC HTTP/3 Settings Handling
 *
 * Copyright (c) 2026 Justin Adams <spotty118@gmail.com>
 * Kernel implementation by Justin Adams <spotty118@gmail.com>
 *
 * Implementation of HTTP/3 settings management per RFC 9114 Section 7.2.4.
 *
 * SETTINGS frames are exchanged on the control stream at connection start.
 * Each endpoint MUST send SETTINGS as its first frame on the control stream.
 * Settings apply to the entire connection and cannot be changed afterward.
 *
 * Standard settings:
 *   - SETTINGS_QPACK_MAX_TABLE_CAPACITY (0x01): QPACK dynamic table size limit
 *   - SETTINGS_MAX_FIELD_SECTION_SIZE (0x06): Max encoded header size
 *   - SETTINGS_QPACK_BLOCKED_STREAMS (0x07): Streams blocked on QPACK decoder
 *
 * Unknown settings MUST be ignored for forward compatibility.
 * GREASE settings (0x1f * N + 0x21) MUST be ignored.
 */

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/types.h>
#include <linux/errno.h>
#include <linux/string.h>
#include <net/tquic_http3.h>

#include "http3_frame.h"
#include "http3_priority.h"

/*
 * =============================================================================
 * Settings Initialization
 * =============================================================================
 */

/**
 * tquic_h3_settings_init - Initialize settings to default values
 * @settings: Settings structure to initialize
 *
 * Per RFC 9114, the defaults are:
 *   - QPACK_MAX_TABLE_CAPACITY: 0 (no dynamic table)
 *   - MAX_FIELD_SECTION_SIZE: unlimited (we use 16KB as practical default)
 *   - QPACK_BLOCKED_STREAMS: 0 (no blocked streams)
 *   - ENABLE_PRIORITY: true (RFC 9218 extensible priorities enabled)
 */
void tquic_h3_settings_init(struct tquic_h3_settings *settings)
{
	if (!settings)
		return;

	settings->qpack_max_table_capacity = H3_DEFAULT_QPACK_MAX_TABLE_CAPACITY;
	settings->max_field_section_size = H3_DEFAULT_MAX_FIELD_SECTION_SIZE;
	settings->qpack_blocked_streams = H3_DEFAULT_QPACK_BLOCKED_STREAMS;
	settings->enable_priority = true;  /* RFC 9218 default */
}
EXPORT_SYMBOL_GPL(tquic_h3_settings_init);

/*
 * =============================================================================
 * Settings Validation
 * =============================================================================
 */

/**
 * h3_settings_validate - Validate settings values
 * @settings: Settings to validate
 *
 * Checks that settings values are within acceptable ranges.
 *
 * Returns: 0 on success, -H3_SETTINGS_ERROR on invalid settings.
 */
static int h3_settings_validate(const struct tquic_h3_settings *settings)
{
	/* QPACK_MAX_TABLE_CAPACITY: any value is valid, but we cap for safety */
	if (settings->qpack_max_table_capacity > H3_MAX_QPACK_TABLE_CAPACITY)
		return -H3_SETTINGS_ERROR;

	/* MAX_FIELD_SECTION_SIZE: any value is valid */
	if (settings->max_field_section_size > H3_MAX_FIELD_SECTION_SIZE)
		return -H3_SETTINGS_ERROR;

	/* QPACK_BLOCKED_STREAMS: should be reasonable */
	if (settings->qpack_blocked_streams > H3_MAX_QPACK_BLOCKED_STREAMS)
		return -H3_SETTINGS_ERROR;

	return 0;
}

/*
 * =============================================================================
 * Settings Encoding
 * =============================================================================
 */

/**
 * h3_encode_settings - Encode settings to buffer
 * @settings: Settings to encode
 * @buf: Output buffer
 * @len: Buffer length
 *
 * Encodes non-default settings as (identifier, value) pairs.
 * Each pair uses varint encoding for both fields.
 *
 * Returns: Bytes written on success, negative error on failure.
 */
int h3_encode_settings(const struct tquic_h3_settings *settings,
		       u8 *buf, size_t len)
{
	size_t offset = 0;
	int ret;

	if (!settings || !buf)
		return -EINVAL;

	/*
	 * Encode QPACK_MAX_TABLE_CAPACITY if non-zero
	 * (0 is the default, so sending it is optional but harmless)
	 */
	if (settings->qpack_max_table_capacity != 0) {
		ret = h3_varint_encode(H3_SETTINGS_QPACK_MAX_TABLE_CAPACITY,
				       buf + offset, len - offset);
		if (ret < 0)
			return ret;
		offset += ret;

		ret = h3_varint_encode(settings->qpack_max_table_capacity,
				       buf + offset, len - offset);
		if (ret < 0)
			return ret;
		offset += ret;
	}

	/*
	 * Encode MAX_FIELD_SECTION_SIZE if non-default
	 * Per RFC 9114: "If this parameter is absent, no limit is imposed."
	 * We treat our default as different from "unlimited" to allow explicit control.
	 */
	if (settings->max_field_section_size != H3_DEFAULT_MAX_FIELD_SECTION_SIZE) {
		ret = h3_varint_encode(H3_SETTINGS_MAX_FIELD_SECTION_SIZE,
				       buf + offset, len - offset);
		if (ret < 0)
			return ret;
		offset += ret;

		ret = h3_varint_encode(settings->max_field_section_size,
				       buf + offset, len - offset);
		if (ret < 0)
			return ret;
		offset += ret;
	}

	/*
	 * Encode QPACK_BLOCKED_STREAMS if non-zero
	 * 0 is the default (no streams may be blocked).
	 */
	if (settings->qpack_blocked_streams != 0) {
		ret = h3_varint_encode(H3_SETTINGS_QPACK_BLOCKED_STREAMS,
				       buf + offset, len - offset);
		if (ret < 0)
			return ret;
		offset += ret;

		ret = h3_varint_encode(settings->qpack_blocked_streams,
				       buf + offset, len - offset);
		if (ret < 0)
			return ret;
		offset += ret;
	}

	/*
	 * Encode SETTINGS_ENABLE_PRIORITY (RFC 9218)
	 * True by default, encode 1 if enabled, 0 if disabled
	 */
	if (settings->enable_priority) {
		ret = h3_varint_encode(TQUIC_H3_SETTINGS_ENABLE_PRIORITY,
				       buf + offset, len - offset);
		if (ret < 0)
			return ret;
		offset += ret;

		ret = h3_varint_encode(1, buf + offset, len - offset);
		if (ret < 0)
			return ret;
		offset += ret;
	}

	return offset;
}

/*
 * =============================================================================
 * Settings Decoding
 * =============================================================================
 */

/**
 * h3_decode_settings - Decode settings from buffer
 * @buf: Input buffer containing settings payload
 * @len: Payload length
 * @settings: Output settings structure
 *
 * Decodes (identifier, value) pairs from the settings payload.
 * Unknown identifiers are ignored per RFC 9114.
 *
 * Returns: 0 on success, negative error on failure.
 */
int h3_decode_settings(const u8 *buf, size_t len,
		       struct tquic_h3_settings *settings)
{
	size_t offset = 0;
	u64 seen_mask = 0;  /* Track which settings we've seen */
	int ret;

	if (!buf || !settings)
		return -EINVAL;

	/* Initialize to defaults first */
	tquic_h3_settings_init(settings);

	while (offset < len) {
		u64 id, value;

		/* Decode setting identifier */
		ret = h3_varint_decode(buf + offset, len - offset, &id);
		if (ret < 0)
			return ret;
		offset += ret;

		/* Check for truncated payload */
		if (offset >= len)
			return -H3_FRAME_ERROR;

		/* Decode setting value */
		ret = h3_varint_decode(buf + offset, len - offset, &value);
		if (ret < 0)
			return ret;
		offset += ret;

		/* Skip GREASE identifiers */
		if (tquic_h3_is_grease_id(id))
			continue;

		/*
		 * Process known settings.
		 * Per RFC 9114 Section 7.2.4.1: "The same setting identifier
		 * MUST NOT occur more than once in the SETTINGS frame."
		 */
		switch (id) {
		case H3_SETTINGS_QPACK_MAX_TABLE_CAPACITY:
			if (seen_mask & (1ULL << 0))
				return -H3_SETTINGS_ERROR;
			seen_mask |= (1ULL << 0);
			settings->qpack_max_table_capacity = value;
			break;

		case H3_SETTINGS_MAX_FIELD_SECTION_SIZE:
			if (seen_mask & (1ULL << 1))
				return -H3_SETTINGS_ERROR;
			seen_mask |= (1ULL << 1);
			settings->max_field_section_size = value;
			break;

		case H3_SETTINGS_QPACK_BLOCKED_STREAMS:
			if (seen_mask & (1ULL << 2))
				return -H3_SETTINGS_ERROR;
			seen_mask |= (1ULL << 2);
			settings->qpack_blocked_streams = value;
			break;

		case TQUIC_H3_SETTINGS_ENABLE_PRIORITY:
			/* RFC 9218: SETTINGS_ENABLE_PRIORITY (0x11) */
			if (seen_mask & (1ULL << 3))
				return -H3_SETTINGS_ERROR;
			seen_mask |= (1ULL << 3);
			settings->enable_priority = (value != 0);
			break;

		default:
			/*
			 * Unknown settings MUST be ignored per RFC 9114.
			 * This enables forward compatibility with future
			 * extensions.
			 */
			break;
		}
	}

	/* Validate the decoded settings */
	return h3_settings_validate(settings);
}

/*
 * =============================================================================
 * Settings Comparison and Utilities
 * =============================================================================
 */

/**
 * h3_settings_equal - Compare two settings structures
 * @a: First settings
 * @b: Second settings
 *
 * Returns: true if settings are identical.
 */
bool h3_settings_equal(const struct tquic_h3_settings *a,
		       const struct tquic_h3_settings *b)
{
	if (!a || !b)
		return false;

	return (a->qpack_max_table_capacity == b->qpack_max_table_capacity) &&
	       (a->max_field_section_size == b->max_field_section_size) &&
	       (a->qpack_blocked_streams == b->qpack_blocked_streams) &&
	       (a->enable_priority == b->enable_priority);
}

/**
 * h3_settings_copy - Copy settings structure
 * @dst: Destination settings
 * @src: Source settings
 */
void h3_settings_copy(struct tquic_h3_settings *dst,
		      const struct tquic_h3_settings *src)
{
	if (!dst || !src)
		return;

	dst->qpack_max_table_capacity = src->qpack_max_table_capacity;
	dst->max_field_section_size = src->max_field_section_size;
	dst->qpack_blocked_streams = src->qpack_blocked_streams;
	dst->enable_priority = src->enable_priority;
}

/**
 * h3_settings_merge - Merge non-default settings into target
 * @dst: Target settings (updated in place)
 * @src: Source settings with values to merge
 *
 * Only copies values that differ from defaults.
 */
void h3_settings_merge(struct tquic_h3_settings *dst,
		       const struct tquic_h3_settings *src)
{
	if (!dst || !src)
		return;

	if (src->qpack_max_table_capacity != H3_DEFAULT_QPACK_MAX_TABLE_CAPACITY)
		dst->qpack_max_table_capacity = src->qpack_max_table_capacity;

	if (src->max_field_section_size != H3_DEFAULT_MAX_FIELD_SECTION_SIZE)
		dst->max_field_section_size = src->max_field_section_size;

	if (src->qpack_blocked_streams != H3_DEFAULT_QPACK_BLOCKED_STREAMS)
		dst->qpack_blocked_streams = src->qpack_blocked_streams;
}

/*
 * =============================================================================
 * Settings Negotiation
 * =============================================================================
 *
 * HTTP/3 settings are not "negotiated" in the traditional sense - each
 * endpoint independently declares its limits and the peer must respect them.
 * However, we provide helpers for determining effective limits.
 */

/**
 * h3_settings_get_effective_table_size - Get effective QPACK table size
 * @local: Local settings (our capability)
 * @peer: Peer settings (their limit for our encoder)
 *
 * Returns the minimum of the two values, which is the effective size
 * we may use for our dynamic table encoder.
 */
u64 h3_settings_get_effective_table_size(const struct tquic_h3_settings *local,
					 const struct tquic_h3_settings *peer)
{
	u64 local_val = local ? local->qpack_max_table_capacity : 0;
	u64 peer_val = peer ? peer->qpack_max_table_capacity : 0;

	/*
	 * The encoder's dynamic table size is limited by the decoder's
	 * QPACK_MAX_TABLE_CAPACITY setting. We use the minimum to be
	 * safe, though technically only the peer's limit applies to
	 * our encoder.
	 */
	return min(local_val, peer_val);
}

/**
 * h3_settings_get_effective_header_size - Get effective max header size
 * @local: Local settings
 * @peer: Peer settings
 *
 * Returns the minimum of the two MAX_FIELD_SECTION_SIZE values.
 * This determines the maximum size of encoded headers we should send.
 */
u64 h3_settings_get_effective_header_size(const struct tquic_h3_settings *local,
					  const struct tquic_h3_settings *peer)
{
	u64 local_val = local ? local->max_field_section_size :
			       H3_DEFAULT_MAX_FIELD_SECTION_SIZE;
	u64 peer_val = peer ? peer->max_field_section_size :
			     H3_DEFAULT_MAX_FIELD_SECTION_SIZE;

	/* Use peer's limit for what we send, local for what we accept */
	return min(local_val, peer_val);
}

/*
 * =============================================================================
 * Settings Debug/Display
 * =============================================================================
 */

/**
 * h3_settings_identifier_name - Get setting identifier name
 * @id: Setting identifier
 *
 * Returns: Human-readable name string.
 */
const char *h3_settings_identifier_name(u64 id)
{
	switch (id) {
	case H3_SETTINGS_QPACK_MAX_TABLE_CAPACITY:
		return "QPACK_MAX_TABLE_CAPACITY";
	case H3_SETTINGS_MAX_FIELD_SECTION_SIZE:
		return "MAX_FIELD_SECTION_SIZE";
	case H3_SETTINGS_QPACK_BLOCKED_STREAMS:
		return "QPACK_BLOCKED_STREAMS";
	case TQUIC_H3_SETTINGS_ENABLE_PRIORITY:
		return "ENABLE_PRIORITY";
	default:
		if (tquic_h3_is_grease_id(id))
			return "GREASE";
		return "UNKNOWN";
	}
}

#ifdef CONFIG_DEBUG_FS
/**
 * h3_settings_debugfs_show - Show settings in debugfs format
 * @seq: Seq file to write to
 * @settings: Settings to display
 * @prefix: Optional prefix string
 */
void h3_settings_debugfs_show(struct seq_file *seq,
			      const struct tquic_h3_settings *settings,
			      const char *prefix)
{
	if (!seq || !settings)
		return;

	seq_printf(seq, "%sQPACK_MAX_TABLE_CAPACITY: %llu\n",
		   prefix ? prefix : "",
		   settings->qpack_max_table_capacity);
	seq_printf(seq, "%sMAX_FIELD_SECTION_SIZE: %llu\n",
		   prefix ? prefix : "",
		   settings->max_field_section_size);
	seq_printf(seq, "%sQPACK_BLOCKED_STREAMS: %llu\n",
		   prefix ? prefix : "",
		   settings->qpack_blocked_streams);
}
#endif /* CONFIG_DEBUG_FS */

MODULE_DESCRIPTION("TQUIC HTTP/3 Settings Handling");
MODULE_LICENSE("GPL");
