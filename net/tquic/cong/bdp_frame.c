// SPDX-License-Identifier: GPL-2.0-only
/*
 * TQUIC: BDP Frame Extension Implementation
 *
 * Copyright (c) 2026 Justin Adams <spotty118@gmail.com>
 * Kernel implementation by Justin Adams <spotty118@gmail.com>
 *
 * Implementation of BDP Frame extension per draft-kuhn-quic-bdpframe-extension-05.
 * This enables safe restoration of congestion control state across
 * connection resumption using Careful Resume.
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/random.h>
#include <linux/timekeeping.h>
#include <crypto/hash.h>
#include <crypto/utils.h>
#ifndef SHA256_DIGEST_SIZE
#define SHA256_DIGEST_SIZE 32
#endif
#include <net/tquic.h>

#include "bdp_frame.h"
#include "tquic_cong.h"
#include "../core/varint.h"
#include "../protocol.h"
#include "../tquic_debug.h"

/*
 * =============================================================================
 * BDP State Management
 * =============================================================================
 */

/**
 * tquic_bdp_init - Initialize BDP state for a connection
 */
int tquic_bdp_init(struct tquic_connection *conn)
{
	struct tquic_bdp_state *bdp;

	if (!conn)
		return -EINVAL;

	bdp = kzalloc(sizeof(*bdp), GFP_KERNEL);
	if (!bdp)
		return -ENOMEM;

	spin_lock_init(&bdp->lock);
	bdp->enabled = false;
	bdp->have_saved = false;
	bdp->have_generated = false;
	bdp->applied = false;
	bdp->cr_phase = TQUIC_CR_PHASE_DISABLED;
	bdp->hmac_key_set = false;

	conn->bdp_state = bdp;

	tquic_dbg("bdp: initialized BDP state for connection\n");
	return 0;
}
EXPORT_SYMBOL_GPL(tquic_bdp_init);

/**
 * tquic_bdp_release - Release BDP state for a connection
 */
void tquic_bdp_release(struct tquic_connection *conn)
{
	struct tquic_bdp_state *bdp;

	if (!conn)
		return;

	bdp = conn->bdp_state;
	if (!bdp)
		return;

	/* Clear sensitive data */
	memzero_explicit(bdp->hmac_key, sizeof(bdp->hmac_key));
	memzero_explicit(&bdp->saved.hmac, sizeof(bdp->saved.hmac));
	memzero_explicit(&bdp->generated.hmac, sizeof(bdp->generated.hmac));

	kfree(bdp);
	conn->bdp_state = NULL;

	tquic_dbg("bdp: released BDP state\n");
}
EXPORT_SYMBOL_GPL(tquic_bdp_release);

/**
 * tquic_bdp_set_hmac_key - Set HMAC key for BDP authentication
 */
int tquic_bdp_set_hmac_key(struct tquic_connection *conn, const u8 *key,
			   size_t key_len)
{
	struct tquic_bdp_state *bdp;
	unsigned long flags;

	if (!conn || !key)
		return -EINVAL;

	bdp = conn->bdp_state;
	if (!bdp)
		return -ENOENT;

	if (key_len > TQUIC_BDP_HMAC_KEY_LEN)
		key_len = TQUIC_BDP_HMAC_KEY_LEN;

	spin_lock_irqsave(&bdp->lock, flags);
	memset(bdp->hmac_key, 0, sizeof(bdp->hmac_key));
	memcpy(bdp->hmac_key, key, key_len);
	bdp->hmac_key_set = true;
	spin_unlock_irqrestore(&bdp->lock, flags);

	tquic_dbg("bdp: HMAC key set (%zu bytes)\n", key_len);
	return 0;
}
EXPORT_SYMBOL_GPL(tquic_bdp_set_hmac_key);

/*
 * =============================================================================
 * BDP Frame Encoding/Decoding
 * =============================================================================
 */

/**
 * tquic_encode_bdp_frame - Encode BDP frame to wire format
 *
 * Wire format:
 *   Frame Type (varint): 0x1f
 *   BDP (varint)
 *   Saved CWND (varint)
 *   Saved RTT (varint)
 *   Lifetime (varint)
 *   Endpoint Token (16 bytes)
 *   HMAC (16 bytes)
 */
ssize_t tquic_encode_bdp_frame(const struct tquic_bdp_frame *frame,
			       u8 *buf, size_t buflen)
{
	size_t offset = 0;
	int ret;

	if (!frame || !buf)
		return -EINVAL;

	/* Frame type */
	ret = tquic_varint_write(buf, buflen, &offset, TQUIC_FRAME_BDP);
	if (ret < 0)
		return ret;

	/* BDP */
	ret = tquic_varint_write(buf, buflen, &offset, frame->bdp);
	if (ret < 0)
		return ret;

	/* Saved CWND */
	ret = tquic_varint_write(buf, buflen, &offset, frame->saved_cwnd);
	if (ret < 0)
		return ret;

	/* Saved RTT */
	ret = tquic_varint_write(buf, buflen, &offset, frame->saved_rtt);
	if (ret < 0)
		return ret;

	/* Lifetime */
	ret = tquic_varint_write(buf, buflen, &offset, frame->lifetime);
	if (ret < 0)
		return ret;

	/* Endpoint Token (fixed 16 bytes) */
	if (buflen - offset < TQUIC_BDP_TOKEN_LEN)
		return -ENOSPC;
	memcpy(buf + offset, frame->endpoint_token, TQUIC_BDP_TOKEN_LEN);
	offset += TQUIC_BDP_TOKEN_LEN;

	/* HMAC (fixed 16 bytes) */
	if (buflen - offset < TQUIC_BDP_HMAC_LEN)
		return -ENOSPC;
	memcpy(buf + offset, frame->hmac, TQUIC_BDP_HMAC_LEN);
	offset += TQUIC_BDP_HMAC_LEN;

	tquic_dbg("bdp: encoded frame, bdp=%llu cwnd=%llu rtt=%llu lifetime=%llu\n",
		 frame->bdp, frame->saved_cwnd, frame->saved_rtt, frame->lifetime);

	return offset;
}
EXPORT_SYMBOL_GPL(tquic_encode_bdp_frame);

/**
 * tquic_decode_bdp_frame - Decode BDP frame from wire format
 */
ssize_t tquic_decode_bdp_frame(const u8 *buf, size_t buflen,
			       struct tquic_bdp_frame *frame)
{
	size_t offset = 0;
	u64 frame_type;
	int ret;

	if (!buf || !frame)
		return -EINVAL;

	/* Frame type */
	ret = tquic_varint_read(buf, buflen, &offset, &frame_type);
	if (ret < 0)
		return ret;

	if (frame_type != TQUIC_FRAME_BDP) {
		tquic_dbg("bdp: unexpected frame type 0x%llx\n", frame_type);
		return -EPROTO;
	}

	/* BDP */
	ret = tquic_varint_read(buf, buflen, &offset, &frame->bdp);
	if (ret < 0)
		return ret;

	/* Saved CWND */
	ret = tquic_varint_read(buf, buflen, &offset, &frame->saved_cwnd);
	if (ret < 0)
		return ret;

	/* Saved RTT */
	ret = tquic_varint_read(buf, buflen, &offset, &frame->saved_rtt);
	if (ret < 0)
		return ret;

	/* Lifetime */
	ret = tquic_varint_read(buf, buflen, &offset, &frame->lifetime);
	if (ret < 0)
		return ret;

	/* Endpoint Token (fixed 16 bytes) */
	if (buflen - offset < TQUIC_BDP_TOKEN_LEN)
		return -EINVAL;
	memcpy(frame->endpoint_token, buf + offset, TQUIC_BDP_TOKEN_LEN);
	offset += TQUIC_BDP_TOKEN_LEN;

	/* HMAC (fixed 16 bytes) */
	if (buflen - offset < TQUIC_BDP_HMAC_LEN)
		return -EINVAL;
	memcpy(frame->hmac, buf + offset, TQUIC_BDP_HMAC_LEN);
	offset += TQUIC_BDP_HMAC_LEN;

	tquic_dbg("bdp: decoded frame, bdp=%llu cwnd=%llu rtt=%llu lifetime=%llu\n",
		 frame->bdp, frame->saved_cwnd, frame->saved_rtt, frame->lifetime);

	return offset;
}
EXPORT_SYMBOL_GPL(tquic_decode_bdp_frame);

/*
 * =============================================================================
 * HMAC Authentication
 * =============================================================================
 */

/*
 * Build HMAC input data from BDP frame fields
 * Format: BDP || CWND || RTT || Lifetime || Token
 */
static int bdp_build_hmac_data(const struct tquic_bdp_frame *frame,
			       u8 *data, size_t *data_len)
{
	size_t offset = 0;
	int ret;

	/* BDP (8 bytes, big-endian) */
	data[offset++] = (frame->bdp >> 56) & 0xff;
	data[offset++] = (frame->bdp >> 48) & 0xff;
	data[offset++] = (frame->bdp >> 40) & 0xff;
	data[offset++] = (frame->bdp >> 32) & 0xff;
	data[offset++] = (frame->bdp >> 24) & 0xff;
	data[offset++] = (frame->bdp >> 16) & 0xff;
	data[offset++] = (frame->bdp >> 8) & 0xff;
	data[offset++] = frame->bdp & 0xff;

	/* Saved CWND (8 bytes, big-endian) */
	data[offset++] = (frame->saved_cwnd >> 56) & 0xff;
	data[offset++] = (frame->saved_cwnd >> 48) & 0xff;
	data[offset++] = (frame->saved_cwnd >> 40) & 0xff;
	data[offset++] = (frame->saved_cwnd >> 32) & 0xff;
	data[offset++] = (frame->saved_cwnd >> 24) & 0xff;
	data[offset++] = (frame->saved_cwnd >> 16) & 0xff;
	data[offset++] = (frame->saved_cwnd >> 8) & 0xff;
	data[offset++] = frame->saved_cwnd & 0xff;

	/* Saved RTT (8 bytes, big-endian) */
	data[offset++] = (frame->saved_rtt >> 56) & 0xff;
	data[offset++] = (frame->saved_rtt >> 48) & 0xff;
	data[offset++] = (frame->saved_rtt >> 40) & 0xff;
	data[offset++] = (frame->saved_rtt >> 32) & 0xff;
	data[offset++] = (frame->saved_rtt >> 24) & 0xff;
	data[offset++] = (frame->saved_rtt >> 16) & 0xff;
	data[offset++] = (frame->saved_rtt >> 8) & 0xff;
	data[offset++] = frame->saved_rtt & 0xff;

	/* Lifetime (8 bytes, big-endian) */
	data[offset++] = (frame->lifetime >> 56) & 0xff;
	data[offset++] = (frame->lifetime >> 48) & 0xff;
	data[offset++] = (frame->lifetime >> 40) & 0xff;
	data[offset++] = (frame->lifetime >> 32) & 0xff;
	data[offset++] = (frame->lifetime >> 24) & 0xff;
	data[offset++] = (frame->lifetime >> 16) & 0xff;
	data[offset++] = (frame->lifetime >> 8) & 0xff;
	data[offset++] = frame->lifetime & 0xff;

	/* Endpoint Token (16 bytes) */
	memcpy(data + offset, frame->endpoint_token, TQUIC_BDP_TOKEN_LEN);
	offset += TQUIC_BDP_TOKEN_LEN;

	*data_len = offset;
	return 0;
}

/**
 * tquic_bdp_compute_hmac - Compute HMAC for BDP frame
 */
int tquic_bdp_compute_hmac(struct tquic_connection *conn,
			   struct tquic_bdp_frame *frame)
{
	struct tquic_bdp_state *bdp;
	struct crypto_shash *tfm;
	struct shash_desc *desc;
	u8 hmac_data[64];
	u8 full_hmac[SHA256_DIGEST_SIZE];
	u8 local_key[TQUIC_BDP_HMAC_KEY_LEN];
	size_t hmac_data_len;
	unsigned long flags;
	int ret;

	if (!conn || !frame)
		return -EINVAL;

	bdp = conn->bdp_state;
	if (!bdp || !bdp->hmac_key_set)
		return -ENOKEY;

	/* Build HMAC input data */
	ret = bdp_build_hmac_data(frame, hmac_data, &hmac_data_len);
	if (ret < 0)
		return ret;

	/* Allocate HMAC transform */
	tfm = crypto_alloc_shash("hmac(sha256)", 0, 0);
	if (IS_ERR(tfm)) {
		tquic_err("bdp: failed to allocate hmac(sha256)\n");
		return PTR_ERR(tfm);
	}

	desc = kzalloc(sizeof(*desc) + crypto_shash_descsize(tfm), GFP_KERNEL);
	if (!desc) {
		crypto_free_shash(tfm);
		return -ENOMEM;
	}

	desc->tfm = tfm;

	/* Copy key under lock, then set it outside lock context */
	spin_lock_irqsave(&bdp->lock, flags);
	memcpy(local_key, bdp->hmac_key, TQUIC_BDP_HMAC_KEY_LEN);
	spin_unlock_irqrestore(&bdp->lock, flags);

	ret = crypto_shash_setkey(tfm, local_key, TQUIC_BDP_HMAC_KEY_LEN);
	memzero_explicit(local_key, TQUIC_BDP_HMAC_KEY_LEN);

	if (ret < 0) {
		tquic_err("bdp: failed to set HMAC key: %d\n", ret);
		goto out;
	}

	/* Compute HMAC */
	ret = crypto_shash_digest(desc, hmac_data, hmac_data_len, full_hmac);
	if (ret < 0) {
		tquic_err("bdp: HMAC computation failed: %d\n", ret);
		goto out;
	}

	/* Truncate to 128 bits for wire efficiency */
	memcpy(frame->hmac, full_hmac, TQUIC_BDP_HMAC_LEN);
	ret = 0;

	tquic_dbg("bdp: computed HMAC for frame\n");

out:
	memzero_explicit(full_hmac, sizeof(full_hmac));
	memzero_explicit(hmac_data, sizeof(hmac_data));
	kfree(desc);
	crypto_free_shash(tfm);
	return ret;
}
EXPORT_SYMBOL_GPL(tquic_bdp_compute_hmac);

/**
 * tquic_bdp_verify_hmac - Verify HMAC for BDP frame
 */
int tquic_bdp_verify_hmac(struct tquic_connection *conn,
			  const struct tquic_bdp_frame *frame)
{
	struct tquic_bdp_frame verify_frame;
	int ret;

	if (!conn || !frame)
		return -EINVAL;

	/* Copy frame and compute HMAC */
	memcpy(&verify_frame, frame, sizeof(verify_frame));

	ret = tquic_bdp_compute_hmac(conn, &verify_frame);
	if (ret < 0)
		return ret;

	/* Constant-time comparison */
	if (crypto_memneq(verify_frame.hmac, frame->hmac, TQUIC_BDP_HMAC_LEN)) {
		tquic_dbg("bdp: HMAC verification failed\n");
		memzero_explicit(&verify_frame, sizeof(verify_frame));
		return -EBADMSG;
	}

	memzero_explicit(&verify_frame, sizeof(verify_frame));
	tquic_dbg("bdp: HMAC verification succeeded\n");
	return 0;
}
EXPORT_SYMBOL_GPL(tquic_bdp_verify_hmac);

/*
 * =============================================================================
 * BDP Frame Generation and Validation
 * =============================================================================
 */

/**
 * tquic_bdp_generate_endpoint_token - Generate endpoint token
 */
int tquic_bdp_generate_endpoint_token(struct tquic_connection *conn, u8 *token)
{
	struct tquic_bdp_state *bdp;
	struct crypto_shash *tfm;
	struct shash_desc *desc;
	u8 input[32];
	u8 hash[SHA256_DIGEST_SIZE];
	unsigned long flags;
	int ret;

	if (!conn || !token)
		return -EINVAL;

	bdp = conn->bdp_state;
	if (!bdp || !bdp->hmac_key_set)
		return -ENOKEY;

	/* Build input: HMAC key + "endpoint_token" label */
	spin_lock_irqsave(&bdp->lock, flags);
	memcpy(input, bdp->hmac_key, 16);
	spin_unlock_irqrestore(&bdp->lock, flags);
	memcpy(input + 16, "endpoint_token", 14);

	/* Hash to derive token */
	tfm = crypto_alloc_shash("sha256", 0, 0);
	if (IS_ERR(tfm)) {
		memzero_explicit(input, sizeof(input));
		return PTR_ERR(tfm);
	}

	desc = kzalloc(sizeof(*desc) + crypto_shash_descsize(tfm), GFP_KERNEL);
	if (!desc) {
		crypto_free_shash(tfm);
		memzero_explicit(input, sizeof(input));
		return -ENOMEM;
	}

	desc->tfm = tfm;

	ret = crypto_shash_digest(desc, input, 30, hash);
	if (ret < 0) {
		kfree(desc);
		crypto_free_shash(tfm);
		memzero_explicit(input, sizeof(input));
		return ret;
	}

	/* Use first 16 bytes of hash as token */
	memcpy(token, hash, TQUIC_BDP_TOKEN_LEN);

	memzero_explicit(input, sizeof(input));
	memzero_explicit(hash, sizeof(hash));
	kfree(desc);
	crypto_free_shash(tfm);

	return 0;
}
EXPORT_SYMBOL_GPL(tquic_bdp_generate_endpoint_token);

/**
 * tquic_generate_bdp_frame - Generate BDP frame from current CC state
 */
int tquic_generate_bdp_frame(struct tquic_connection *conn,
			     struct tquic_path *path,
			     struct tquic_bdp_frame *frame)
{
	struct tquic_bdp_state *bdp;
	u64 cwnd, rtt;
	int ret;

	if (!conn || !path || !frame)
		return -EINVAL;

	bdp = conn->bdp_state;
	if (!bdp)
		return -ENOENT;

	if (!bdp->enabled) {
		tquic_dbg("bdp: extension not enabled\n");
		return -ENOENT;
	}

	memset(frame, 0, sizeof(*frame));

	/* Get current CC state */
	cwnd = tquic_cong_get_cwnd(path);
	rtt = path->stats.rtt_smoothed;

	if (cwnd < TQUIC_BDP_MIN_CWND || rtt < TQUIC_BDP_MIN_RTT_US) {
		tquic_dbg("bdp: insufficient CC state for BDP frame\n");
		return -EAGAIN;
	}

	/* Calculate BDP (bytes) = cwnd (already in bytes) */
	frame->bdp = cwnd;
	frame->saved_cwnd = cwnd;
	frame->saved_rtt = rtt;
	frame->lifetime = TQUIC_BDP_DEFAULT_LIFETIME_SEC;

	/* Generate endpoint token */
	ret = tquic_bdp_generate_endpoint_token(conn, frame->endpoint_token);
	if (ret < 0)
		return ret;

	/* Compute HMAC */
	ret = tquic_bdp_compute_hmac(conn, frame);
	if (ret < 0)
		return ret;

	tquic_info("bdp: generated frame, bdp=%llu cwnd=%llu rtt=%llu\n",
		frame->bdp, frame->saved_cwnd, frame->saved_rtt);

	/* Store in connection state */
	spin_lock_bh(&bdp->lock);
	memcpy(&bdp->generated, frame, sizeof(bdp->generated));
	bdp->have_generated = true;
	spin_unlock_bh(&bdp->lock);

	return 0;
}
EXPORT_SYMBOL_GPL(tquic_generate_bdp_frame);

/**
 * tquic_validate_bdp_frame - Validate received BDP frame
 */
int tquic_validate_bdp_frame(struct tquic_connection *conn,
			     const struct tquic_bdp_frame *frame)
{
	struct tquic_bdp_state *bdp;
	u8 expected_token[TQUIC_BDP_TOKEN_LEN];
	int ret;

	if (!conn || !frame)
		return -EINVAL;

	bdp = conn->bdp_state;
	if (!bdp)
		return -ENOENT;

	/* Validate ranges */
	if (frame->bdp < TQUIC_BDP_MIN_BDP || frame->bdp > TQUIC_BDP_MAX_BDP) {
		tquic_dbg("bdp: BDP out of range: %llu\n", frame->bdp);
		return -ERANGE;
	}

	if (frame->saved_cwnd < TQUIC_BDP_MIN_CWND ||
	    frame->saved_cwnd > TQUIC_BDP_MAX_CWND) {
		tquic_dbg("bdp: cwnd out of range: %llu\n", frame->saved_cwnd);
		return -ERANGE;
	}

	if (frame->saved_rtt < TQUIC_BDP_MIN_RTT_US ||
	    frame->saved_rtt > TQUIC_BDP_MAX_RTT_US) {
		tquic_dbg("bdp: RTT out of range: %llu\n", frame->saved_rtt);
		return -ERANGE;
	}

	if (frame->lifetime > TQUIC_BDP_MAX_LIFETIME_SEC) {
		tquic_dbg("bdp: lifetime too long: %llu\n", frame->lifetime);
		return -ERANGE;
	}

	if (frame->lifetime == 0) {
		tquic_dbg("bdp: zero lifetime\n");
		return -ERANGE;
	}

	/*
	 * Validate saved_cwnd is consistent with BDP and RTT.
	 * BDP = cwnd should hold approximately. Reject frames where
	 * saved_cwnd vastly exceeds BDP (more than 4x), which suggests
	 * manipulation or corruption.
	 */
	if (frame->saved_cwnd > frame->bdp * 4) {
		tquic_dbg("bdp: cwnd %llu inconsistent with BDP %llu\n",
			  frame->saved_cwnd, frame->bdp);
		return -ERANGE;
	}

	/* Generate expected token and compare */
	ret = tquic_bdp_generate_endpoint_token(conn, expected_token);
	if (ret < 0)
		return ret;

	if (crypto_memneq(expected_token, frame->endpoint_token,
			  TQUIC_BDP_TOKEN_LEN)) {
		tquic_dbg("bdp: endpoint token mismatch\n");
		memzero_explicit(expected_token, sizeof(expected_token));
		return -EACCES;
	}
	memzero_explicit(expected_token, sizeof(expected_token));

	/* Verify HMAC */
	ret = tquic_bdp_verify_hmac(conn, frame);
	if (ret < 0) {
		tquic_dbg("bdp: HMAC verification failed\n");
		return ret;
	}

	tquic_info("bdp: frame validated successfully\n");
	return 0;
}
EXPORT_SYMBOL_GPL(tquic_validate_bdp_frame);

/**
 * tquic_apply_bdp_frame - Apply BDP frame using Careful Resume
 */
int tquic_apply_bdp_frame(struct tquic_connection *conn,
			  struct tquic_path *path,
			  const struct tquic_bdp_frame *frame)
{
	struct tquic_bdp_state *bdp;
	int ret;

	if (!conn || !path || !frame)
		return -EINVAL;

	bdp = conn->bdp_state;
	if (!bdp)
		return -ENOENT;

	/* Store saved frame */
	spin_lock_bh(&bdp->lock);
	memcpy(&bdp->saved, frame, sizeof(bdp->saved));
	bdp->have_saved = true;
	spin_unlock_bh(&bdp->lock);

	/* Initialize Careful Resume */
	ret = tquic_careful_resume_init(path, frame);
	if (ret < 0) {
		tquic_warn("bdp: Careful Resume init failed: %d\n", ret);
		return ret;
	}

	spin_lock_bh(&bdp->lock);
	bdp->applied = true;
	bdp->cr_phase = TQUIC_CR_PHASE_RECONNECTION;
	bdp->cr_start_time = ktime_get();
	bdp->cr_target_cwnd = frame->saved_cwnd;
	spin_unlock_bh(&bdp->lock);

	tquic_info("bdp: applied BDP frame, target cwnd=%llu\n",
		frame->saved_cwnd);

	return 0;
}
EXPORT_SYMBOL_GPL(tquic_apply_bdp_frame);

/*
 * =============================================================================
 * Utility Functions
 * =============================================================================
 */

/**
 * tquic_bdp_is_enabled - Check if BDP frame extension is enabled
 */
bool tquic_bdp_is_enabled(struct tquic_connection *conn)
{
	struct tquic_bdp_state *bdp;

	if (!conn)
		return false;

	bdp = conn->bdp_state;
	return bdp && bdp->enabled;
}
EXPORT_SYMBOL_GPL(tquic_bdp_is_enabled);

/**
 * tquic_bdp_should_send - Check if we should send a BDP frame
 */
bool tquic_bdp_should_send(struct tquic_connection *conn)
{
	struct tquic_bdp_state *bdp;
	bool should_send;

	if (!conn)
		return false;

	bdp = conn->bdp_state;
	if (!bdp || !bdp->enabled)
		return false;

	spin_lock_bh(&bdp->lock);
	/* Send BDP frame if:
	 * 1. We haven't generated one yet, or
	 * 2. Connection is closing and we want to provide updated values
	 */
	should_send = !bdp->have_generated;
	spin_unlock_bh(&bdp->lock);

	return should_send;
}
EXPORT_SYMBOL_GPL(tquic_bdp_should_send);

/**
 * tquic_bdp_store_for_reconnect - Store BDP frame for future reconnection
 */
int tquic_bdp_store_for_reconnect(struct tquic_connection *conn,
				  const struct tquic_bdp_frame *frame)
{
	struct tquic_bdp_state *bdp;

	if (!conn || !frame)
		return -EINVAL;

	bdp = conn->bdp_state;
	if (!bdp)
		return -ENOENT;

	spin_lock_bh(&bdp->lock);
	memcpy(&bdp->saved, frame, sizeof(bdp->saved));
	bdp->have_saved = true;
	spin_unlock_bh(&bdp->lock);

	tquic_dbg("bdp: stored frame for reconnection\n");
	return 0;
}
EXPORT_SYMBOL_GPL(tquic_bdp_store_for_reconnect);

/**
 * tquic_bdp_restore_for_reconnect - Restore BDP frame for reconnection
 */
int tquic_bdp_restore_for_reconnect(struct tquic_connection *conn,
				    struct tquic_bdp_frame *frame)
{
	struct tquic_bdp_state *bdp;

	if (!conn || !frame)
		return -EINVAL;

	bdp = conn->bdp_state;
	if (!bdp)
		return -ENOENT;

	spin_lock_bh(&bdp->lock);
	if (!bdp->have_saved) {
		spin_unlock_bh(&bdp->lock);
		return -ENOENT;
	}

	memcpy(frame, &bdp->saved, sizeof(*frame));
	spin_unlock_bh(&bdp->lock);

	tquic_dbg("bdp: restored frame for reconnection\n");
	return 0;
}
EXPORT_SYMBOL_GPL(tquic_bdp_restore_for_reconnect);

/**
 * tquic_careful_resume_get_phase - Get current Careful Resume phase
 */
enum tquic_careful_resume_phase tquic_careful_resume_get_phase(
	struct tquic_connection *conn)
{
	struct tquic_bdp_state *bdp;
	enum tquic_careful_resume_phase phase;

	if (!conn)
		return TQUIC_CR_PHASE_DISABLED;

	bdp = conn->bdp_state;
	if (!bdp)
		return TQUIC_CR_PHASE_DISABLED;

	spin_lock_bh(&bdp->lock);
	phase = bdp->cr_phase;
	spin_unlock_bh(&bdp->lock);

	return phase;
}
EXPORT_SYMBOL_GPL(tquic_careful_resume_get_phase);

/**
 * tquic_careful_resume_complete - Mark Careful Resume as complete
 */
void tquic_careful_resume_complete(struct tquic_connection *conn,
				   struct tquic_path *path)
{
	struct tquic_bdp_state *bdp;

	if (!conn)
		return;

	bdp = conn->bdp_state;
	if (!bdp)
		return;

	spin_lock_bh(&bdp->lock);
	bdp->cr_phase = TQUIC_CR_PHASE_NORMAL;
	spin_unlock_bh(&bdp->lock);

	tquic_info("bdp: Careful Resume completed successfully\n");
}
EXPORT_SYMBOL_GPL(tquic_careful_resume_complete);

MODULE_DESCRIPTION("TQUIC BDP Frame Extension");
MODULE_LICENSE("GPL");
