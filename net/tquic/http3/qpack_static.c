// SPDX-License-Identifier: GPL-2.0-only
/*
 * QPACK Static Table - RFC 9204 Appendix A
 *
 * Copyright (c) 2026 Justin Adams <spotty118@gmail.com>
 * Kernel implementation by Justin Adams <spotty118@gmail.com>
 *
 * The QPACK static table contains 99 predefined header field entries.
 * These entries are commonly used in HTTP/3 and provide efficient
 * encoding without dynamic table overhead.
 *
 * Indices range from 0 to 98 (inclusive).
 */

#include <linux/kernel.h>
#include <linux/string.h>
#include <linux/module.h>

#include "qpack.h"

/*
 * Static table entries from RFC 9204 Appendix A
 *
 * Each entry consists of a name and optional value.
 * The format follows the HPACK static table with HTTP/3 additions.
 */
static const struct qpack_static_entry qpack_static_table[QPACK_STATIC_TABLE_SIZE] = {
	/* Index 0 */
	{ ":authority", 10, "", 0 },
	/* Index 1 */
	{ ":path", 5, "/", 1 },
	/* Index 2 */
	{ "age", 3, "0", 1 },
	/* Index 3 */
	{ "content-disposition", 19, "", 0 },
	/* Index 4 */
	{ "content-length", 14, "0", 1 },
	/* Index 5 */
	{ "cookie", 6, "", 0 },
	/* Index 6 */
	{ "date", 4, "", 0 },
	/* Index 7 */
	{ "etag", 4, "", 0 },
	/* Index 8 */
	{ "if-modified-since", 17, "", 0 },
	/* Index 9 */
	{ "if-none-match", 13, "", 0 },
	/* Index 10 */
	{ "last-modified", 13, "", 0 },
	/* Index 11 */
	{ "link", 4, "", 0 },
	/* Index 12 */
	{ "location", 8, "", 0 },
	/* Index 13 */
	{ "referer", 7, "", 0 },
	/* Index 14 */
	{ "set-cookie", 10, "", 0 },
	/* Index 15 */
	{ ":method", 7, "CONNECT", 7 },
	/* Index 16 */
	{ ":method", 7, "DELETE", 6 },
	/* Index 17 */
	{ ":method", 7, "GET", 3 },
	/* Index 18 */
	{ ":method", 7, "HEAD", 4 },
	/* Index 19 */
	{ ":method", 7, "OPTIONS", 7 },
	/* Index 20 */
	{ ":method", 7, "POST", 4 },
	/* Index 21 */
	{ ":method", 7, "PUT", 3 },
	/* Index 22 */
	{ ":scheme", 7, "http", 4 },
	/* Index 23 */
	{ ":scheme", 7, "https", 5 },
	/* Index 24 */
	{ ":status", 7, "103", 3 },
	/* Index 25 */
	{ ":status", 7, "200", 3 },
	/* Index 26 */
	{ ":status", 7, "304", 3 },
	/* Index 27 */
	{ ":status", 7, "404", 3 },
	/* Index 28 */
	{ ":status", 7, "503", 3 },
	/* Index 29 */
	{ "accept", 6, "*/*", 3 },
	/* Index 30 */
	{ "accept", 6, "application/dns-message", 23 },
	/* Index 31 */
	{ "accept-encoding", 15, "gzip, deflate, br", 17 },
	/* Index 32 */
	{ "accept-ranges", 13, "bytes", 5 },
	/* Index 33 */
	{ "access-control-allow-headers", 28, "cache-control", 13 },
	/* Index 34 */
	{ "access-control-allow-headers", 28, "content-type", 12 },
	/* Index 35 */
	{ "access-control-allow-origin", 27, "*", 1 },
	/* Index 36 */
	{ "cache-control", 13, "max-age=0", 9 },
	/* Index 37 */
	{ "cache-control", 13, "max-age=2592000", 15 },
	/* Index 38 */
	{ "cache-control", 13, "max-age=604800", 14 },
	/* Index 39 */
	{ "cache-control", 13, "no-cache", 8 },
	/* Index 40 */
	{ "cache-control", 13, "no-store", 8 },
	/* Index 41 */
	{ "cache-control", 13, "public, max-age=31536000", 24 },
	/* Index 42 */
	{ "content-encoding", 16, "br", 2 },
	/* Index 43 */
	{ "content-encoding", 16, "gzip", 4 },
	/* Index 44 */
	{ "content-type", 12, "application/dns-message", 23 },
	/* Index 45 */
	{ "content-type", 12, "application/javascript", 22 },
	/* Index 46 */
	{ "content-type", 12, "application/json", 16 },
	/* Index 47 */
	{ "content-type", 12, "application/x-www-form-urlencoded", 33 },
	/* Index 48 */
	{ "content-type", 12, "image/gif", 9 },
	/* Index 49 */
	{ "content-type", 12, "image/jpeg", 10 },
	/* Index 50 */
	{ "content-type", 12, "image/png", 9 },
	/* Index 51 */
	{ "content-type", 12, "text/css", 8 },
	/* Index 52 */
	{ "content-type", 12, "text/html; charset=utf-8", 24 },
	/* Index 53 */
	{ "content-type", 12, "text/plain", 10 },
	/* Index 54 */
	{ "content-type", 12, "text/plain;charset=utf-8", 24 },
	/* Index 55 */
	{ "range", 5, "bytes=0-", 8 },
	/* Index 56 */
	{ "strict-transport-security", 25, "max-age=31536000", 16 },
	/* Index 57 */
	{ "strict-transport-security", 25, "max-age=31536000; includesubdomains", 35 },
	/* Index 58 */
	{ "strict-transport-security", 25, "max-age=31536000; includesubdomains; preload", 44 },
	/* Index 59 */
	{ "vary", 4, "accept-encoding", 15 },
	/* Index 60 */
	{ "vary", 4, "origin", 6 },
	/* Index 61 */
	{ "x-content-type-options", 22, "nosniff", 7 },
	/* Index 62 */
	{ "x-xss-protection", 16, "1; mode=block", 13 },
	/* Index 63 */
	{ ":status", 7, "100", 3 },
	/* Index 64 */
	{ ":status", 7, "204", 3 },
	/* Index 65 */
	{ ":status", 7, "206", 3 },
	/* Index 66 */
	{ ":status", 7, "302", 3 },
	/* Index 67 */
	{ ":status", 7, "400", 3 },
	/* Index 68 */
	{ ":status", 7, "403", 3 },
	/* Index 69 */
	{ ":status", 7, "421", 3 },
	/* Index 70 */
	{ ":status", 7, "425", 3 },
	/* Index 71 */
	{ ":status", 7, "500", 3 },
	/* Index 72 */
	{ "accept-language", 15, "", 0 },
	/* Index 73 */
	{ "access-control-allow-credentials", 32, "FALSE", 5 },
	/* Index 74 */
	{ "access-control-allow-credentials", 32, "TRUE", 4 },
	/* Index 75 */
	{ "access-control-allow-headers", 28, "*", 1 },
	/* Index 76 */
	{ "access-control-allow-methods", 28, "get", 3 },
	/* Index 77 */
	{ "access-control-allow-methods", 28, "get, post, options", 18 },
	/* Index 78 */
	{ "access-control-allow-methods", 28, "options", 7 },
	/* Index 79 */
	{ "access-control-expose-headers", 29, "content-length", 14 },
	/* Index 80 */
	{ "access-control-request-headers", 30, "content-type", 12 },
	/* Index 81 */
	{ "access-control-request-method", 29, "get", 3 },
	/* Index 82 */
	{ "access-control-request-method", 29, "post", 4 },
	/* Index 83 */
	{ "alt-svc", 7, "clear", 5 },
	/* Index 84 */
	{ "authorization", 13, "", 0 },
	/* Index 85 */
	{ "content-security-policy", 23, "script-src 'none'; object-src 'none'; base-uri 'none'", 53 },
	/* Index 86 */
	{ "early-data", 10, "1", 1 },
	/* Index 87 */
	{ "expect-ct", 9, "", 0 },
	/* Index 88 */
	{ "forwarded", 9, "", 0 },
	/* Index 89 */
	{ "if-range", 8, "", 0 },
	/* Index 90 */
	{ "origin", 6, "", 0 },
	/* Index 91 */
	{ "purpose", 7, "prefetch", 8 },
	/* Index 92 */
	{ "server", 6, "", 0 },
	/* Index 93 */
	{ "timing-allow-origin", 19, "*", 1 },
	/* Index 94 */
	{ "upgrade-insecure-requests", 25, "1", 1 },
	/* Index 95 */
	{ "user-agent", 10, "", 0 },
	/* Index 96 */
	{ "x-forwarded-for", 15, "", 0 },
	/* Index 97 */
	{ "x-frame-options", 15, "deny", 4 },
	/* Index 98 */
	{ "x-frame-options", 15, "sameorigin", 10 },
};

/**
 * qpack_static_get - Get static table entry by index
 * @index: Static table index (0-98)
 *
 * Returns: Pointer to static entry, or NULL if index out of range
 */
const struct qpack_static_entry *qpack_static_get(u32 index)
{
	if (index >= QPACK_STATIC_TABLE_SIZE)
		return NULL;

	return &qpack_static_table[index];
}
EXPORT_SYMBOL_GPL(qpack_static_get);

/**
 * qpack_static_find_name - Find static table entry by name only
 * @name: Header field name to find
 * @name_len: Length of name
 *
 * Returns: Index of first matching entry, or -1 if not found
 *
 * This function finds the first entry with a matching name,
 * regardless of value. Useful for encoding headers that match
 * a static name but have a different value.
 */
int qpack_static_find_name(const char *name, u16 name_len)
{
	u32 i;

	if (!name || name_len == 0)
		return -1;

	for (i = 0; i < QPACK_STATIC_TABLE_SIZE; i++) {
		if (qpack_static_table[i].name_len == name_len &&
		    memcmp(qpack_static_table[i].name, name, name_len) == 0)
			return i;
	}

	return -1;
}
EXPORT_SYMBOL_GPL(qpack_static_find_name);

/**
 * qpack_static_find - Find static table entry by name and value
 * @name: Header field name
 * @name_len: Length of name
 * @value: Header field value
 * @value_len: Length of value
 *
 * Returns: Index of matching entry, or -1 if not found
 *
 * Searches for an exact match of both name and value.
 * This provides the most efficient encoding when found.
 */
int qpack_static_find(const char *name, u16 name_len,
		      const char *value, u16 value_len)
{
	u32 i;

	if (!name || name_len == 0)
		return -1;

	for (i = 0; i < QPACK_STATIC_TABLE_SIZE; i++) {
		const struct qpack_static_entry *entry = &qpack_static_table[i];

		/* Check name match first */
		if (entry->name_len != name_len ||
		    memcmp(entry->name, name, name_len) != 0)
			continue;

		/* Check value match */
		if (entry->value_len == value_len) {
			if (value_len == 0)
				return i;
			if (value && memcmp(entry->value, value, value_len) == 0)
				return i;
		}
	}

	return -1;
}
EXPORT_SYMBOL_GPL(qpack_static_find);

/**
 * qpack_static_table_size - Get the static table size
 *
 * Returns: Number of entries in the static table (99)
 */
u32 qpack_static_table_size(void)
{
	return QPACK_STATIC_TABLE_SIZE;
}
EXPORT_SYMBOL_GPL(qpack_static_table_size);

MODULE_DESCRIPTION("QPACK Static Table for HTTP/3");
MODULE_LICENSE("GPL");
