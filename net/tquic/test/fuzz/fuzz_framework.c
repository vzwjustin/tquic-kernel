// SPDX-License-Identifier: GPL-2.0-only
/*
 * TQUIC Fuzzing Framework Implementation
 *
 * Copyright (c) 2026 Justin Adams <spotty118@gmail.com>
 * Kernel implementation by Justin Adams <spotty118@gmail.com>
 *
 * Provides mutation-based fuzzing for QUIC packet processing.
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/random.h>
#include <linux/debugfs.h>
#include <linux/seq_file.h>
#include <linux/workqueue.h>
#include <net/tquic.h>

#include "fuzz_framework.h"
#include "../../protocol.h"

/*
 * =============================================================================
 * Global State
 * =============================================================================
 */

struct tquic_fuzz_state *tquic_fuzzer;
EXPORT_SYMBOL_GPL(tquic_fuzzer);

static struct dentry *fuzz_debugfs_dir;
static struct workqueue_struct *fuzz_wq;
static bool fuzz_initialized;

/*
 * =============================================================================
 * Random Number Generation
 * =============================================================================
 */

static inline u64 fuzz_rand64(void)
{
	u64 val;
	get_random_bytes(&val, sizeof(val));
	return val;
}

static inline u32 fuzz_rand32(void)
{
	return get_random_u32();
}

static inline u32 fuzz_rand_range(u32 min, u32 max)
{
	if (min >= max)
		return min;
	return min + (fuzz_rand32() % (max - min + 1));
}

/*
 * =============================================================================
 * Mutation Functions
 * =============================================================================
 */

void tquic_fuzz_bit_flip(u8 *data, size_t len, int count)
{
	int i;

	if (!data || len == 0)
		return;

	for (i = 0; i < count; i++) {
		size_t byte_pos = fuzz_rand32() % len;
		int bit_pos = fuzz_rand32() % 8;
		data[byte_pos] ^= (1 << bit_pos);
	}
}
EXPORT_SYMBOL_GPL(tquic_fuzz_bit_flip);

void tquic_fuzz_byte_flip(u8 *data, size_t len, int count)
{
	int i;

	if (!data || len == 0)
		return;

	for (i = 0; i < count; i++) {
		size_t pos = fuzz_rand32() % len;
		data[pos] ^= 0xFF;
	}
}
EXPORT_SYMBOL_GPL(tquic_fuzz_byte_flip);

void tquic_fuzz_arithmetic(u8 *data, size_t len, int width)
{
	size_t pos;
	int delta;

	if (!data || len < width)
		return;

	pos = fuzz_rand32() % (len - width + 1);
	delta = (int)(fuzz_rand32() % 71) - 35;  /* -35 to +35 */

	switch (width) {
	case 1:
		data[pos] += delta;
		break;
	case 2:
		if (pos + 1 < len) {
			u16 val = (data[pos] << 8) | data[pos + 1];
			val += delta;
			data[pos] = val >> 8;
			data[pos + 1] = val & 0xFF;
		}
		break;
	case 4:
		if (pos + 3 < len) {
			u32 val = (data[pos] << 24) | (data[pos + 1] << 16) |
				  (data[pos + 2] << 8) | data[pos + 3];
			val += delta;
			data[pos] = val >> 24;
			data[pos + 1] = (val >> 16) & 0xFF;
			data[pos + 2] = (val >> 8) & 0xFF;
			data[pos + 3] = val & 0xFF;
		}
		break;
	}
}
EXPORT_SYMBOL_GPL(tquic_fuzz_arithmetic);

void tquic_fuzz_interesting(u8 *data, size_t len)
{
	size_t pos;
	u64 val;
	int width;

	if (!data || len == 0)
		return;

	val = fuzz_interesting_u64[fuzz_rand32() % FUZZ_INTERESTING_U64_COUNT];
	width = fuzz_rand_range(1, min_t(size_t, 8, len));
	pos = fuzz_rand32() % (len - width + 1);

	switch (width) {
	case 1:
		data[pos] = val & 0xFF;
		break;
	case 2:
		data[pos] = (val >> 8) & 0xFF;
		data[pos + 1] = val & 0xFF;
		break;
	case 4:
		data[pos] = (val >> 24) & 0xFF;
		data[pos + 1] = (val >> 16) & 0xFF;
		data[pos + 2] = (val >> 8) & 0xFF;
		data[pos + 3] = val & 0xFF;
		break;
	case 8:
		data[pos] = (val >> 56) & 0xFF;
		data[pos + 1] = (val >> 48) & 0xFF;
		data[pos + 2] = (val >> 40) & 0xFF;
		data[pos + 3] = (val >> 32) & 0xFF;
		data[pos + 4] = (val >> 24) & 0xFF;
		data[pos + 5] = (val >> 16) & 0xFF;
		data[pos + 6] = (val >> 8) & 0xFF;
		data[pos + 7] = val & 0xFF;
		break;
	}
}
EXPORT_SYMBOL_GPL(tquic_fuzz_interesting);

size_t tquic_fuzz_havoc(u8 *data, size_t len, size_t max_len)
{
	int ops = fuzz_rand_range(1, 16);
	int i;

	if (!data || len == 0)
		return len;

	for (i = 0; i < ops; i++) {
		switch (fuzz_rand32() % 8) {
		case 0:
			tquic_fuzz_bit_flip(data, len, fuzz_rand_range(1, 4));
			break;
		case 1:
			tquic_fuzz_byte_flip(data, len, fuzz_rand_range(1, 4));
			break;
		case 2:
			tquic_fuzz_arithmetic(data, len, 1 << (fuzz_rand32() % 3));
			break;
		case 3:
			tquic_fuzz_interesting(data, len);
			break;
		case 4:
			/* Insert random bytes */
			if (len < max_len) {
				size_t pos = fuzz_rand32() % (len + 1);
				size_t insert_len = fuzz_rand_range(1, min_t(size_t, 16, max_len - len));
				memmove(data + pos + insert_len, data + pos, len - pos);
				get_random_bytes(data + pos, insert_len);
				len += insert_len;
			}
			break;
		case 5:
			/* Delete random bytes */
			if (len > 1) {
				size_t pos = fuzz_rand32() % len;
				size_t del_len = fuzz_rand_range(1, min_t(size_t, 16, len - pos));
				memmove(data + pos, data + pos + del_len, len - pos - del_len);
				len -= del_len;
			}
			break;
		case 6:
			/* Overwrite with random */
			{
				size_t pos = fuzz_rand32() % len;
				size_t over_len = fuzz_rand_range(1, min_t(size_t, 16, len - pos));
				get_random_bytes(data + pos, over_len);
			}
			break;
		case 7:
			/* Clone/copy within buffer */
			if (len > 4) {
				size_t src = fuzz_rand32() % (len - 2);
				size_t dst = fuzz_rand32() % (len - 2);
				size_t copy_len = fuzz_rand_range(1, min_t(size_t, 8, len - max(src, dst)));
				memmove(data + dst, data + src, copy_len);
			}
			break;
		}
	}

	return len;
}
EXPORT_SYMBOL_GPL(tquic_fuzz_havoc);

size_t tquic_fuzz_mutate(u8 *data, size_t len, size_t max_len, u32 strategies)
{
	u32 choice;

	if (!data || len == 0)
		return 0;

	if (strategies == 0)
		strategies = TQUIC_MUTATE_ALL;

	choice = fuzz_rand32() % 8;

	switch (choice) {
	case 0:
		if (strategies & TQUIC_MUTATE_BIT_FLIP)
			tquic_fuzz_bit_flip(data, len, fuzz_rand_range(1, 8));
		break;
	case 1:
		if (strategies & TQUIC_MUTATE_BYTE_FLIP)
			tquic_fuzz_byte_flip(data, len, fuzz_rand_range(1, 4));
		break;
	case 2:
		if (strategies & TQUIC_MUTATE_ARITHMETIC)
			tquic_fuzz_arithmetic(data, len, 1 << (fuzz_rand32() % 3));
		break;
	case 3:
		if (strategies & TQUIC_MUTATE_INTERESTING)
			tquic_fuzz_interesting(data, len);
		break;
	case 4:
	case 5:
	case 6:
	case 7:
		if (strategies & TQUIC_MUTATE_HAVOC)
			len = tquic_fuzz_havoc(data, len, max_len);
		break;
	}

	return len;
}
EXPORT_SYMBOL_GPL(tquic_fuzz_mutate);

/*
 * =============================================================================
 * Varint Fuzzing
 * =============================================================================
 */

size_t tquic_fuzz_varint(u8 *buf, size_t size)
{
	u64 val;
	int encoding;

	if (!buf || size == 0)
		return 0;

	/* Choose random encoding length */
	encoding = 1 << (fuzz_rand32() % 4);  /* 1, 2, 4, or 8 */
	if (encoding > size)
		encoding = size;

	/* Generate value appropriate for encoding */
	switch (encoding) {
	case 1:
		val = fuzz_rand32() & 0x3F;
		buf[0] = val;
		break;
	case 2:
		val = fuzz_rand32() & 0x3FFF;
		buf[0] = 0x40 | ((val >> 8) & 0x3F);
		buf[1] = val & 0xFF;
		break;
	case 4:
		val = fuzz_rand32() & 0x3FFFFFFF;
		buf[0] = 0x80 | ((val >> 24) & 0x3F);
		buf[1] = (val >> 16) & 0xFF;
		buf[2] = (val >> 8) & 0xFF;
		buf[3] = val & 0xFF;
		break;
	case 8:
		val = fuzz_rand64() & 0x3FFFFFFFFFFFFFFFULL;
		buf[0] = 0xC0 | ((val >> 56) & 0x3F);
		buf[1] = (val >> 48) & 0xFF;
		buf[2] = (val >> 40) & 0xFF;
		buf[3] = (val >> 32) & 0xFF;
		buf[4] = (val >> 24) & 0xFF;
		buf[5] = (val >> 16) & 0xFF;
		buf[6] = (val >> 8) & 0xFF;
		buf[7] = val & 0xFF;
		break;
	default:
		return 0;
	}

	return encoding;
}
EXPORT_SYMBOL_GPL(tquic_fuzz_varint);

size_t tquic_fuzz_varint_invalid(u8 *buf, size_t size)
{
	int choice;

	if (!buf || size < 2)
		return 0;

	choice = fuzz_rand32() % 4;

	switch (choice) {
	case 0:
		/* Truncated 2-byte varint */
		buf[0] = 0x40 | (fuzz_rand32() & 0x3F);
		return 1;
	case 1:
		/* Truncated 4-byte varint */
		buf[0] = 0x80 | (fuzz_rand32() & 0x3F);
		buf[1] = fuzz_rand32() & 0xFF;
		return min_t(size_t, 2, size);
	case 2:
		/* Truncated 8-byte varint */
		buf[0] = 0xC0 | (fuzz_rand32() & 0x3F);
		get_random_bytes(buf + 1, min_t(size_t, 3, size - 1));
		return min_t(size_t, 4, size);
	case 3:
		/* Non-minimal encoding */
		buf[0] = 0x40;
		buf[1] = fuzz_rand32() & 0x3F;  /* Could fit in 1 byte */
		return 2;
	}

	return 0;
}
EXPORT_SYMBOL_GPL(tquic_fuzz_varint_invalid);

/*
 * =============================================================================
 * Packet Fuzzing
 * =============================================================================
 */

size_t tquic_fuzz_initial_packet(u8 *buf, size_t size)
{
	size_t offset = 0;
	u8 dcid_len, scid_len;

	if (!buf || size < 64)
		return 0;

	/* Long header form bit + fixed bit + packet type (Initial = 0) */
	buf[offset++] = 0xC0 | (fuzz_rand32() & 0x0F);

	/* Version */
	buf[offset++] = 0x00;
	buf[offset++] = 0x00;
	buf[offset++] = 0x00;
	buf[offset++] = 0x01;  /* QUIC v1 */

	/* DCID length and DCID */
	dcid_len = fuzz_rand_range(0, 20);
	buf[offset++] = dcid_len;
	get_random_bytes(buf + offset, dcid_len);
	offset += dcid_len;

	/* SCID length and SCID */
	scid_len = fuzz_rand_range(0, 20);
	buf[offset++] = scid_len;
	get_random_bytes(buf + offset, scid_len);
	offset += scid_len;

	/* Token length (varint) and token */
	offset += tquic_fuzz_varint(buf + offset, size - offset);

	/* Length (varint) */
	offset += tquic_fuzz_varint(buf + offset, size - offset);

	/* Packet number (1-4 bytes) */
	{
		int pn_len = fuzz_rand_range(1, 4);
		get_random_bytes(buf + offset, pn_len);
		offset += pn_len;
	}

	/* Random payload */
	{
		size_t payload_len = fuzz_rand_range(16, min_t(size_t, 256, size - offset));
		get_random_bytes(buf + offset, payload_len);
		offset += payload_len;
	}

	return offset;
}
EXPORT_SYMBOL_GPL(tquic_fuzz_initial_packet);

size_t tquic_fuzz_short_header_packet(u8 *buf, size_t size)
{
	size_t offset = 0;
	u8 dcid_len;

	if (!buf || size < 32)
		return 0;

	/* Short header: fixed bit set, form bit clear */
	buf[offset++] = 0x40 | (fuzz_rand32() & 0x3F);

	/* DCID (variable length, typically 8-20 bytes) */
	dcid_len = fuzz_rand_range(0, 20);
	get_random_bytes(buf + offset, dcid_len);
	offset += dcid_len;

	/* Packet number (1-4 bytes, length encoded in first byte) */
	{
		int pn_len = ((buf[0] & 0x03) + 1);
		get_random_bytes(buf + offset, pn_len);
		offset += pn_len;
	}

	/* Random payload */
	{
		size_t payload_len = fuzz_rand_range(16, min_t(size_t, 128, size - offset));
		get_random_bytes(buf + offset, payload_len);
		offset += payload_len;
	}

	return offset;
}
EXPORT_SYMBOL_GPL(tquic_fuzz_short_header_packet);

size_t tquic_fuzz_packet(u8 *buf, size_t size,
			 const u8 *template, size_t template_len)
{
	size_t len;

	if (!buf || size == 0)
		return 0;

	if (template && template_len > 0 && template_len <= size) {
		/* Mutate template */
		memcpy(buf, template, template_len);
		len = tquic_fuzz_mutate(buf, template_len, size, TQUIC_MUTATE_ALL);
	} else {
		/* Generate random packet */
		if (fuzz_rand32() & 1)
			len = tquic_fuzz_initial_packet(buf, size);
		else
			len = tquic_fuzz_short_header_packet(buf, size);
	}

	return len;
}
EXPORT_SYMBOL_GPL(tquic_fuzz_packet);

/*
 * =============================================================================
 * Corpus Management
 * =============================================================================
 */

int tquic_fuzz_corpus_add(struct tquic_fuzz_state *state,
			  const u8 *data, size_t len, u32 coverage)
{
	struct tquic_fuzz_input *input;

	if (!state || !data || len == 0)
		return -EINVAL;

	input = kzalloc(sizeof(*input), GFP_KERNEL);
	if (!input)
		return -ENOMEM;

	input->data = kmemdup(data, len, GFP_KERNEL);
	if (!input->data) {
		kfree(input);
		return -ENOMEM;
	}

	input->len = len;
	input->coverage = coverage;

	spin_lock(&state->corpus_lock);
	list_add_tail(&input->list, &state->corpus);
	atomic64_inc(&state->stats.corpus_size);
	spin_unlock(&state->corpus_lock);

	return 0;
}
EXPORT_SYMBOL_GPL(tquic_fuzz_corpus_add);

size_t tquic_fuzz_corpus_get(struct tquic_fuzz_state *state,
			     u8 *buf, size_t size)
{
	struct tquic_fuzz_input *input;
	size_t len = 0;
	int count, idx;

	if (!state || !buf || size == 0)
		return 0;

	spin_lock(&state->corpus_lock);

	count = atomic64_read(&state->stats.corpus_size);
	if (count == 0) {
		spin_unlock(&state->corpus_lock);
		return 0;
	}

	idx = fuzz_rand32() % count;
	list_for_each_entry(input, &state->corpus, list) {
		if (idx-- == 0) {
			len = min(input->len, size);
			memcpy(buf, input->data, len);
			break;
		}
	}

	spin_unlock(&state->corpus_lock);
	return len;
}
EXPORT_SYMBOL_GPL(tquic_fuzz_corpus_get);

void tquic_fuzz_corpus_clear(struct tquic_fuzz_state *state)
{
	struct tquic_fuzz_input *input, *tmp;

	if (!state)
		return;

	spin_lock(&state->corpus_lock);
	list_for_each_entry_safe(input, tmp, &state->corpus, list) {
		list_del_init(&input->list);
		kfree(input->data);
		kfree(input);
	}
	atomic64_set(&state->stats.corpus_size, 0);
	spin_unlock(&state->corpus_lock);
}
EXPORT_SYMBOL_GPL(tquic_fuzz_corpus_clear);

/*
 * =============================================================================
 * Execution Harness
 * =============================================================================
 */

/* Fuzz target connection state */
struct tquic_fuzz_conn {
	struct tquic_connection *conn;
	void *crypto_state;
	bool initialized;
};

/* Global fuzz connection (reused across iterations) */
static DEFINE_MUTEX(fuzz_conn_lock);
static struct tquic_fuzz_conn fuzz_client;
static struct tquic_fuzz_conn fuzz_server;

/**
 * tquic_fuzz_init_conn - Initialize a fuzzing connection
 * @fconn: Fuzz connection to initialize
 * @is_server: True for server, false for client
 *
 * Returns: 0 on success, negative errno on failure
 */
static int tquic_fuzz_init_conn(struct tquic_fuzz_conn *fconn, bool is_server)
{
	struct tquic_cid cid;

	if (fconn->initialized)
		return 0;

	/* Generate deterministic CID for reproducibility */
	cid.len = 8;
	memset(cid.id, is_server ? 0xAA : 0xBB, cid.len);

	fconn->conn = tquic_conn_alloc(GFP_KERNEL);
	if (!fconn->conn)
		return -ENOMEM;

	fconn->conn->scid = cid;
	fconn->conn->role = is_server ? TQUIC_CONN_SERVER : TQUIC_CONN_CLIENT;
	fconn->conn->state = TQUIC_CONN_CONNECTED;
	fconn->conn->version = TQUIC_VERSION_1;

	/* Initialize transport parameters */
	tquic_tp_init(&fconn->conn->local_params);
	if (is_server)
		tquic_tp_set_defaults_server(&fconn->conn->local_params);
	else
		tquic_tp_set_defaults_client(&fconn->conn->local_params);

	/* Initialize crypto state */
	fconn->crypto_state = tquic_crypto_init_versioned(&cid, is_server,
							  TQUIC_VERSION_1);
	if (!fconn->crypto_state) {
		tquic_conn_put(fconn->conn);
		fconn->conn = NULL;
		return -ENOMEM;
	}

	fconn->conn->crypto_state = fconn->crypto_state;
	fconn->initialized = true;

	return 0;
}

/**
 * tquic_fuzz_cleanup_conn - Clean up a fuzzing connection
 * @fconn: Fuzz connection to clean up
 */
static void tquic_fuzz_cleanup_conn(struct tquic_fuzz_conn *fconn)
{
	if (!fconn->initialized)
		return;

	if (fconn->crypto_state) {
		tquic_crypto_cleanup(fconn->crypto_state);
		fconn->crypto_state = NULL;
	}

	if (fconn->conn) {
		fconn->conn->crypto_state = NULL;  /* Already freed above */
		tquic_conn_put(fconn->conn);
		fconn->conn = NULL;
	}

	fconn->initialized = false;
}

/**
 * tquic_fuzz_run_once - Execute one fuzzing iteration
 * @state: Fuzzer state
 * @input: Fuzzed input data
 * @len: Input length
 *
 * Processes the fuzzed input through the QUIC stack. This function:
 * 1. Parses the input as a QUIC packet
 * 2. Processes it through the appropriate handler
 * 3. Records any crashes or interesting behavior
 *
 * Returns: 0 on success, negative errno on failure
 */
int tquic_fuzz_run_once(struct tquic_fuzz_state *state,
			const u8 *input, size_t len)
{
	struct tquic_fuzz_conn *target;
	bool is_long_header;
	int ret = 0;

	if (!state || !input || len == 0)
		return -EINVAL;

	atomic64_inc(&state->stats.iterations);

	/* Need at least 1 byte to determine header type */
	if (len < 1)
		return 0;

	mutex_lock(&fuzz_conn_lock);

	/* Determine target based on packet type */
	is_long_header = (input[0] & 0x80) != 0;

	/* Initialize connections if needed */
	if (state->targets & TQUIC_FUZZ_TARGET_SERVER) {
		ret = tquic_fuzz_init_conn(&fuzz_server, true);
		if (ret < 0)
			goto out_unlock;
	}

	if (state->targets & TQUIC_FUZZ_TARGET_CLIENT) {
		ret = tquic_fuzz_init_conn(&fuzz_client, false);
		if (ret < 0)
			goto out_unlock;
	}

	/* Select target - long headers typically go to server */
	if (is_long_header && (state->targets & TQUIC_FUZZ_TARGET_SERVER))
		target = &fuzz_server;
	else if (state->targets & TQUIC_FUZZ_TARGET_CLIENT)
		target = &fuzz_client;
	else if (state->targets & TQUIC_FUZZ_TARGET_SERVER)
		target = &fuzz_server;
	else {
		ret = -EINVAL;
		goto out_unlock;
	}

	if (!target->conn) {
		ret = -ENOENT;
		goto out_unlock;
	}

	pr_debug("tquic_fuzz: processing %zu byte %s packet to %s\n",
		 len, is_long_header ? "long" : "short",
		 target == &fuzz_server ? "server" : "client");

	/* Process through different fuzz targets */
	if (state->targets & TQUIC_FUZZ_TARGET_PACKET) {
		/* Full packet processing */
		ret = tquic_conn_process_packet(target->conn, input, len);
		if (ret < 0 && ret != -EINVAL && ret != -EBADMSG) {
			/* Unexpected error - potential bug */
			atomic64_inc(&state->stats.unique_crashes);
			pr_warn("tquic_fuzz: unexpected error %d processing packet\n", ret);
		}
	}

	if (state->targets & TQUIC_FUZZ_TARGET_FRAME) {
		/* Frame decoding only (skip packet header) */
		size_t header_len = is_long_header ? 7 : 1;
		if (len > header_len) {
			ret = tquic_frame_decode(target->conn, input + header_len,
						 len - header_len);
			if (ret < 0 && ret != -EINVAL && ret != -EBADMSG) {
				atomic64_inc(&state->stats.unique_crashes);
				pr_warn("tquic_fuzz: unexpected error %d decoding frame\n", ret);
			}
		}
	}

	if (state->targets & TQUIC_FUZZ_TARGET_CRYPTO) {
		/* Crypto processing (header protection removal, decryption) */
		u8 *packet_copy;

		packet_copy = kmemdup(input, len, GFP_KERNEL);
		if (packet_copy) {
			ret = tquic_crypto_unprotect_header(target->conn->crypto_state,
							    packet_copy, len, 0,
							    NULL, NULL);
			if (ret == 0 && len > 20) {
				/* Try decryption */
				u8 decrypted[4096];
				size_t decrypted_len;

				ret = tquic_decrypt_packet(target->conn->crypto_state,
							   packet_copy, 20,
							   packet_copy + 20, len - 20,
							   0, decrypted, &decrypted_len);
			}
			kfree(packet_copy);
		}
	}

	if (state->targets & TQUIC_FUZZ_TARGET_TRANSPORT_PARAMS) {
		/* Transport parameter decoding */
		struct tquic_transport_params params;

		ret = tquic_tp_decode(input, len, true, &params);
		if (ret < 0 && ret != -EINVAL && ret != -EOVERFLOW) {
			atomic64_inc(&state->stats.unique_crashes);
			pr_warn("tquic_fuzz: unexpected error %d decoding transport params\n", ret);
		}
	}

	ret = 0;  /* Don't propagate expected errors */

out_unlock:
	mutex_unlock(&fuzz_conn_lock);
	return ret;
}
EXPORT_SYMBOL_GPL(tquic_fuzz_run_once);

/**
 * tquic_fuzz_reset_state - Reset fuzzing state for new run
 * @state: Fuzzer state to reset
 *
 * Cleans up and reinitializes the fuzzing connections.
 */
void tquic_fuzz_reset_state(struct tquic_fuzz_state *state)
{
	mutex_lock(&fuzz_conn_lock);
	tquic_fuzz_cleanup_conn(&fuzz_client);
	tquic_fuzz_cleanup_conn(&fuzz_server);
	mutex_unlock(&fuzz_conn_lock);
}
EXPORT_SYMBOL_GPL(tquic_fuzz_reset_state);

static void fuzz_work_fn(struct work_struct *work)
{
	struct tquic_fuzz_state *state = tquic_fuzzer;
	u8 *buf;
	size_t len;

	if (!state || !state->running)
		return;

	buf = kmalloc(4096, GFP_KERNEL);
	if (!buf)
		return;

	while (state->running) {
		/* Get input from corpus or generate new */
		len = tquic_fuzz_corpus_get(state, buf, 4096);
		if (len == 0) {
			/* Generate new input */
			len = tquic_fuzz_packet(buf, 4096, NULL, 0);
		} else {
			/* Mutate corpus input */
			len = tquic_fuzz_mutate(buf, len, 4096, state->mutations);
		}

		/* Execute */
		tquic_fuzz_run_once(state, buf, len);

		/* Yield periodically */
		if ((atomic64_read(&state->stats.iterations) % 1000) == 0)
			cond_resched();
	}

	kfree(buf);
}

static DECLARE_WORK(fuzz_work, fuzz_work_fn);

int tquic_fuzz_start(struct tquic_fuzz_state *state, u64 iterations)
{
	if (!state)
		return -EINVAL;

	if (state->running)
		return -EBUSY;

	state->running = true;
	queue_work(fuzz_wq, &fuzz_work);

	pr_info("tquic_fuzz: started fuzzing\n");
	return 0;
}
EXPORT_SYMBOL_GPL(tquic_fuzz_start);

void tquic_fuzz_stop(struct tquic_fuzz_state *state)
{
	if (!state)
		return;

	state->running = false;
	flush_workqueue(fuzz_wq);

	pr_info("tquic_fuzz: stopped (%llu iterations, %llu crashes)\n",
		atomic64_read(&state->stats.iterations),
		atomic64_read(&state->stats.crashes));
}
EXPORT_SYMBOL_GPL(tquic_fuzz_stop);

/*
 * =============================================================================
 * DebugFS Interface
 * =============================================================================
 */

static int fuzz_stats_show(struct seq_file *m, void *v)
{
	struct tquic_fuzz_state *state = tquic_fuzzer;

	if (!state) {
		seq_puts(m, "Fuzzer not initialized\n");
		return 0;
	}

	seq_puts(m, "TQUIC Fuzzing Statistics\n");
	seq_puts(m, "========================\n\n");
	seq_printf(m, "Mode:           %s\n",
		   state->mode == TQUIC_FUZZ_MODE_OFF ? "off" :
		   state->mode == TQUIC_FUZZ_MODE_RANDOM ? "random" :
		   state->mode == TQUIC_FUZZ_MODE_GUIDED ? "guided" : "unknown");
	seq_printf(m, "Running:        %s\n", state->running ? "yes" : "no");
	seq_printf(m, "Iterations:     %llu\n",
		   atomic64_read(&state->stats.iterations));
	seq_printf(m, "Crashes:        %llu\n",
		   atomic64_read(&state->stats.crashes));
	seq_printf(m, "Hangs:          %llu\n",
		   atomic64_read(&state->stats.hangs));
	seq_printf(m, "Unique Crashes: %llu\n",
		   atomic64_read(&state->stats.unique_crashes));
	seq_printf(m, "Corpus Size:    %llu\n",
		   atomic64_read(&state->stats.corpus_size));

	return 0;
}

static int fuzz_stats_open(struct inode *inode, struct file *file)
{
	return single_open(file, fuzz_stats_show, NULL);
}

static const struct file_operations fuzz_stats_fops = {
	.owner = THIS_MODULE,
	.open = fuzz_stats_open,
	.read = seq_read,
	.llseek = seq_lseek,
	.release = single_release,
};

/*
 * =============================================================================
 * Module Init/Exit
 * =============================================================================
 */

int tquic_fuzz_init(void)
{
	if (fuzz_initialized)
		return 0;

	/* Allocate global state */
	tquic_fuzzer = kzalloc(sizeof(*tquic_fuzzer), GFP_KERNEL);
	if (!tquic_fuzzer)
		return -ENOMEM;

	tquic_fuzzer->mode = TQUIC_FUZZ_MODE_RANDOM;
	tquic_fuzzer->targets = TQUIC_FUZZ_TARGET_ALL;
	tquic_fuzzer->mutations = TQUIC_MUTATE_ALL;
	INIT_LIST_HEAD(&tquic_fuzzer->corpus);
	spin_lock_init(&tquic_fuzzer->corpus_lock);
	tquic_fuzzer->seed = fuzz_rand64();

	/* Create workqueue */
	fuzz_wq = alloc_workqueue("tquic_fuzz", WQ_UNBOUND, 1);
	if (!fuzz_wq) {
		kfree(tquic_fuzzer);
		tquic_fuzzer = NULL;
		return -ENOMEM;
	}

	/* Create debugfs interface */
	fuzz_debugfs_dir = debugfs_create_dir("tquic_fuzz", NULL);
	if (fuzz_debugfs_dir) {
		debugfs_create_file("stats", 0444, fuzz_debugfs_dir,
				    NULL, &fuzz_stats_fops);
		debugfs_create_u32("mode", 0644, fuzz_debugfs_dir,
				   &tquic_fuzzer->mode);
		debugfs_create_u32("targets", 0644, fuzz_debugfs_dir,
				   &tquic_fuzzer->targets);
	}

	fuzz_initialized = true;
	pr_info("tquic_fuzz: framework initialized\n");

	return 0;
}

void tquic_fuzz_exit(void)
{
	if (!fuzz_initialized)
		return;

	/* Stop any running fuzzing */
	if (tquic_fuzzer)
		tquic_fuzz_stop(tquic_fuzzer);

	/* Clean up fuzz connections */
	mutex_lock(&fuzz_conn_lock);
	tquic_fuzz_cleanup_conn(&fuzz_client);
	tquic_fuzz_cleanup_conn(&fuzz_server);
	mutex_unlock(&fuzz_conn_lock);

	/* Remove debugfs */
	debugfs_remove_recursive(fuzz_debugfs_dir);

	/* Destroy workqueue */
	if (fuzz_wq)
		destroy_workqueue(fuzz_wq);

	/* Free corpus and state */
	if (tquic_fuzzer) {
		tquic_fuzz_corpus_clear(tquic_fuzzer);
		kfree(tquic_fuzzer);
		tquic_fuzzer = NULL;
	}

	fuzz_initialized = false;
	pr_info("tquic_fuzz: framework shutdown\n");
}

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("TQUIC Fuzzing Framework");
MODULE_AUTHOR("Linux Foundation");
