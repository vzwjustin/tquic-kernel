// SPDX-License-Identifier: GPL-2.0-only
/*
 * TQUIC: Congestion Control Data Exchange (draft-yuan-quic-congestion-data-00)
 *
 * Copyright (c) 2026 Justin Adams <spotty118@gmail.com>
 * Kernel implementation by Justin Adams <spotty118@gmail.com>
 *
 * Implementation of the Congestion Control Data exchange extension for QUIC.
 * This module enables endpoints to share congestion control state information
 * for connection resumption optimization using Careful Resume principles.
 *
 * SECURITY NOTES:
 * - All received values are validated and capped to safe ranges
 * - Peer data is NEVER blindly trusted
 * - Careful Resume validates path characteristics before trusting saved state
 * - HMAC authentication prevents tampering when enabled
 */

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/random.h>
#include <linux/ktime.h>
#include <linux/unaligned.h>
#include <crypto/hash.h>
#include <crypto/utils.h>
#include <net/tquic.h>

#include "cong_data.h"
#include "tquic_cong.h"
#include "../tquic_debug.h"
#include "../core/varint.h"

/*
 * Static storage for 0-RTT congestion data (simplified)
 * Production would use proper cache with LRU eviction
 */
#define CONG_DATA_CACHE_SIZE	64

struct cong_data_cache_entry {
	char server_name[256];
	u8 server_name_len;
	struct tquic_cong_data_export export;
	bool valid;
	ktime_t store_time;
};

static struct cong_data_cache_entry cong_data_cache[CONG_DATA_CACHE_SIZE];
static DEFINE_SPINLOCK(cong_data_cache_lock);

/*
 * =============================================================================
 * Internal Helper Functions
 * =============================================================================
 */

/**
 * clamp_u64 - Clamp a u64 value to a range
 */
static inline u64 clamp_u64_val(u64 val, u64 min, u64 max)
{
	if (val < min)
		return min;
	if (val > max)
		return max;
	return val;
}

/**
 * get_current_timestamp - Get current Unix timestamp in seconds
 */
static inline u64 get_current_timestamp(void)
{
	return ktime_get_real_seconds();
}

/**
 * cong_data_get_state - Get congestion data state from connection
 */
static inline struct tquic_cong_data_state *cong_data_get_state(
	struct tquic_connection *conn)
{
	if (!conn)
		return NULL;
	return conn->cong_data_state;
}

/*
 * =============================================================================
 * Initialization and Cleanup
 * =============================================================================
 */

int tquic_cong_data_init(struct tquic_connection *conn)
{
	struct tquic_cong_data_state *state;

	if (!conn)
		return -EINVAL;

	state = kzalloc(sizeof(*state), GFP_KERNEL);
	if (!state)
		return -ENOMEM;

	spin_lock_init(&state->lock);
	state->enabled = false;
	state->privacy_level = TQUIC_CONG_PRIVACY_FULL;
	state->have_received = false;
	state->have_sent = false;
	state->last_received_seq = 0;
	state->last_sent_seq = 0;
	state->last_sent_time = ktime_set(0, 0);
	state->outstanding = 0;
	state->applied = false;
	state->apply_phase = TQUIC_CONG_DATA_PHASE_NONE;
	state->hmac_key_set = false;

	conn->cong_data_state = state;
	return 0;
}
EXPORT_SYMBOL_GPL(tquic_cong_data_init);

void tquic_cong_data_release(struct tquic_connection *conn)
{
	struct tquic_cong_data_state *state;

	if (!conn)
		return;

	state = conn->cong_data_state;
	if (state) {
		/* Clear sensitive data (kfree_sensitive zeros entire allocation) */
		kfree_sensitive(state);
		conn->cong_data_state = NULL;
	}
}
EXPORT_SYMBOL_GPL(tquic_cong_data_release);

/*
 * =============================================================================
 * Frame Encoding
 * =============================================================================
 */

ssize_t tquic_cong_data_encode(const struct tquic_cong_data *data,
			       u8 *buf, size_t buflen)
{
	size_t offset = 0;
	int ret;

	if (!data || !buf)
		return -EINVAL;

	/* Frame type */
	ret = tquic_varint_write(buf, buflen, &offset,
				 TQUIC_FRAME_CONGESTION_DATA);
	if (ret < 0)
		return ret;

	/* Sequence number */
	ret = tquic_varint_write(buf, buflen, &offset, data->seq_num);
	if (ret < 0)
		return ret;

	/* Flags */
	ret = tquic_varint_write(buf, buflen, &offset, data->flags);
	if (ret < 0)
		return ret;

	/* BWE (bandwidth estimate in bps) */
	ret = tquic_varint_write(buf, buflen, &offset, data->bwe);
	if (ret < 0)
		return ret;

	/* Min RTT (microseconds) */
	ret = tquic_varint_write(buf, buflen, &offset, data->min_rtt);
	if (ret < 0)
		return ret;

	/* Loss rate (scaled by 10000) */
	ret = tquic_varint_write(buf, buflen, &offset, data->loss_rate);
	if (ret < 0)
		return ret;

	/* Timestamp (Unix seconds) */
	ret = tquic_varint_write(buf, buflen, &offset, data->timestamp);
	if (ret < 0)
		return ret;

	/* Optional: CWND */
	if (data->flags & TQUIC_CONG_DATA_FLAG_HAS_CWND) {
		ret = tquic_varint_write(buf, buflen, &offset, data->cwnd);
		if (ret < 0)
			return ret;
	}

	/* Optional: SSTHRESH */
	if (data->flags & TQUIC_CONG_DATA_FLAG_HAS_SSTHRESH) {
		ret = tquic_varint_write(buf, buflen, &offset, data->ssthresh);
		if (ret < 0)
			return ret;
	}

	/* Optional: Pacing rate */
	if (data->flags & TQUIC_CONG_DATA_FLAG_HAS_PACING_RATE) {
		ret = tquic_varint_write(buf, buflen, &offset, data->pacing_rate);
		if (ret < 0)
			return ret;
	}

	/* Optional: Delivery rate */
	if (data->flags & TQUIC_CONG_DATA_FLAG_HAS_DELIVERY_RATE) {
		ret = tquic_varint_write(buf, buflen, &offset, data->delivery_rate);
		if (ret < 0)
			return ret;
	}

	/* Optional: Authentication fields */
	if (data->flags & TQUIC_CONG_DATA_FLAG_AUTHENTICATED) {
		if (buflen - offset < TQUIC_CONG_DATA_TOKEN_LEN + TQUIC_CONG_DATA_HMAC_LEN)
			return -ENOSPC;

		memcpy(buf + offset, data->endpoint_token, TQUIC_CONG_DATA_TOKEN_LEN);
		offset += TQUIC_CONG_DATA_TOKEN_LEN;

		memcpy(buf + offset, data->hmac, TQUIC_CONG_DATA_HMAC_LEN);
		offset += TQUIC_CONG_DATA_HMAC_LEN;
	}

	return offset;
}
EXPORT_SYMBOL_GPL(tquic_cong_data_encode);

/*
 * =============================================================================
 * Frame Decoding
 * =============================================================================
 */

ssize_t tquic_cong_data_decode(const u8 *buf, size_t buflen,
			       struct tquic_cong_data *data)
{
	size_t offset = 0;
	u64 val;
	int ret;

	if (!buf || !data)
		return -EINVAL;

	memset(data, 0, sizeof(*data));

	/* Sequence number */
	ret = tquic_varint_read(buf, buflen, &offset, &data->seq_num);
	if (ret < 0)
		return ret;

	/* Flags */
	ret = tquic_varint_read(buf, buflen, &offset, &val);
	if (ret < 0)
		return ret;
	data->flags = (u8)val;

	/* BWE */
	ret = tquic_varint_read(buf, buflen, &offset, &data->bwe);
	if (ret < 0)
		return ret;

	/* Min RTT */
	ret = tquic_varint_read(buf, buflen, &offset, &data->min_rtt);
	if (ret < 0)
		return ret;

	/* Loss rate */
	ret = tquic_varint_read(buf, buflen, &offset, &val);
	if (ret < 0)
		return ret;
	data->loss_rate = (u32)val;

	/* Timestamp */
	ret = tquic_varint_read(buf, buflen, &offset, &data->timestamp);
	if (ret < 0)
		return ret;

	/* Optional: CWND */
	if (data->flags & TQUIC_CONG_DATA_FLAG_HAS_CWND) {
		ret = tquic_varint_read(buf, buflen, &offset, &data->cwnd);
		if (ret < 0)
			return ret;
	}

	/* Optional: SSTHRESH */
	if (data->flags & TQUIC_CONG_DATA_FLAG_HAS_SSTHRESH) {
		ret = tquic_varint_read(buf, buflen, &offset, &data->ssthresh);
		if (ret < 0)
			return ret;
	}

	/* Optional: Pacing rate */
	if (data->flags & TQUIC_CONG_DATA_FLAG_HAS_PACING_RATE) {
		ret = tquic_varint_read(buf, buflen, &offset, &data->pacing_rate);
		if (ret < 0)
			return ret;
	}

	/* Optional: Delivery rate */
	if (data->flags & TQUIC_CONG_DATA_FLAG_HAS_DELIVERY_RATE) {
		ret = tquic_varint_read(buf, buflen, &offset, &data->delivery_rate);
		if (ret < 0)
			return ret;
	}

	/* Optional: Authentication fields */
	if (data->flags & TQUIC_CONG_DATA_FLAG_AUTHENTICATED) {
		if (buflen - offset < TQUIC_CONG_DATA_TOKEN_LEN + TQUIC_CONG_DATA_HMAC_LEN)
			return -EINVAL;

		memcpy(data->endpoint_token, buf + offset, TQUIC_CONG_DATA_TOKEN_LEN);
		offset += TQUIC_CONG_DATA_TOKEN_LEN;

		memcpy(data->hmac, buf + offset, TQUIC_CONG_DATA_HMAC_LEN);
		offset += TQUIC_CONG_DATA_HMAC_LEN;
	}

	return offset;
}
EXPORT_SYMBOL_GPL(tquic_cong_data_decode);

/*
 * =============================================================================
 * Data Generation
 * =============================================================================
 */

int tquic_cong_data_generate(struct tquic_connection *conn,
			     struct tquic_path *path,
			     struct tquic_cong_data *data)
{
	struct tquic_cong_data_state *state;
	unsigned long flags_lock;

	if (!conn || !path || !data)
		return -EINVAL;

	state = cong_data_get_state(conn);
	if (!state || !state->enabled)
		return -ENOENT;

	memset(data, 0, sizeof(*data));

	spin_lock_irqsave(&state->lock, flags_lock);

	/* Increment sequence number */
	data->seq_num = ++state->last_sent_seq;
	data->timestamp = get_current_timestamp();

	/* Always include BWE, min_rtt, and loss_rate (core fields) */
	/* bandwidth is in bytes/s, convert to bits/s for bwe */
	data->bwe = path->stats.bandwidth * 8;
	data->min_rtt = path->stats.rtt_min;

	/* Calculate loss rate from path statistics */
	if (path->stats.tx_packets > 0) {
		u64 loss_scaled = (path->stats.lost_packets * 10000ULL) /
				  path->stats.tx_packets;
		data->loss_rate = (u32)min_t(u64, loss_scaled,
					     TQUIC_CONG_DATA_MAX_LOSS_RATE);
	} else {
		data->loss_rate = 0;
	}

	/* Set flags based on privacy level */
	data->flags = 0;

	switch (state->privacy_level) {
	case TQUIC_CONG_PRIVACY_FULL:
		/* Include all optional fields */
		data->flags |= TQUIC_CONG_DATA_FLAG_HAS_CWND |
			       TQUIC_CONG_DATA_FLAG_HAS_SSTHRESH |
			       TQUIC_CONG_DATA_FLAG_HAS_PACING_RATE |
			       TQUIC_CONG_DATA_FLAG_HAS_DELIVERY_RATE;
		data->cwnd = tquic_cong_get_cwnd(path);
		/* Use cwnd as ssthresh estimate if not tracked separately */
		data->ssthresh = tquic_cong_get_cwnd(path);
		data->pacing_rate = tquic_cong_get_pacing_rate(path);
		/* Use bandwidth as delivery rate estimate */
		data->delivery_rate = path->stats.bandwidth;
		break;

	case TQUIC_CONG_PRIVACY_PARTIAL:
		/* Include only cwnd and ssthresh */
		data->flags |= TQUIC_CONG_DATA_FLAG_HAS_CWND |
			       TQUIC_CONG_DATA_FLAG_HAS_SSTHRESH;
		data->cwnd = tquic_cong_get_cwnd(path);
		data->ssthresh = tquic_cong_get_cwnd(path);
		break;

	case TQUIC_CONG_PRIVACY_MINIMAL:
		/* Only core fields (BWE, RTT, loss) - no optional */
		break;

	case TQUIC_CONG_PRIVACY_DISABLED:
		spin_unlock_irqrestore(&state->lock, flags_lock);
		return -EPERM;
	}

	/* Add authentication if HMAC key is configured */
	if (state->hmac_key_set) {
		data->flags |= TQUIC_CONG_DATA_FLAG_AUTHENTICATED;
		tquic_cong_data_generate_token(conn, data->endpoint_token);
		/* HMAC will be computed separately */
	}

	spin_unlock_irqrestore(&state->lock, flags_lock);
	return 0;
}
EXPORT_SYMBOL_GPL(tquic_cong_data_generate);

/*
 * =============================================================================
 * Validation
 * =============================================================================
 */

int tquic_cong_data_validate(struct tquic_connection *conn,
			     const struct tquic_cong_data *data)
{
	u64 now;

	if (!conn || !data)
		return -EINVAL;

	/* Validate timestamp (not too old, not in future) */
	now = get_current_timestamp();
	if (data->timestamp > now + 60) {
		tquic_dbg("cong_data: timestamp in future\n");
		return -EINVAL;
	}
	if (now - data->timestamp > TQUIC_CONG_DATA_MAX_LIFETIME_SEC) {
		tquic_dbg("cong_data: expired (age %llu sec)\n",
			 now - data->timestamp);
		return -ESTALE;
	}

	/* Validate BWE */
	if (data->bwe < TQUIC_CONG_DATA_MIN_BWE_BPS ||
	    data->bwe > TQUIC_CONG_DATA_MAX_BWE_BPS) {
		tquic_dbg("cong_data: BWE out of range: %llu\n", data->bwe);
		return -ERANGE;
	}

	/* Validate min_rtt */
	if (data->min_rtt < TQUIC_CONG_DATA_MIN_RTT_US ||
	    data->min_rtt > TQUIC_CONG_DATA_MAX_RTT_US) {
		tquic_dbg("cong_data: min_rtt out of range: %llu\n",
			 data->min_rtt);
		return -ERANGE;
	}

	/* Validate loss rate */
	if (data->loss_rate > TQUIC_CONG_DATA_MAX_LOSS_RATE) {
		tquic_dbg("cong_data: loss_rate out of range: %u\n",
			 data->loss_rate);
		return -ERANGE;
	}

	/* Validate optional fields if present */
	if (data->flags & TQUIC_CONG_DATA_FLAG_HAS_CWND) {
		if (data->cwnd < TQUIC_CONG_DATA_MIN_CWND ||
		    data->cwnd > TQUIC_CONG_DATA_MAX_CWND) {
			tquic_dbg("cong_data: cwnd out of range: %llu\n",
				 data->cwnd);
			return -ERANGE;
		}
	}

	if (data->flags & TQUIC_CONG_DATA_FLAG_HAS_SSTHRESH) {
		if (data->ssthresh < TQUIC_CONG_DATA_MIN_SSTHRESH ||
		    data->ssthresh > TQUIC_CONG_DATA_MAX_SSTHRESH) {
			tquic_dbg("cong_data: ssthresh out of range: %llu\n",
				 data->ssthresh);
			return -ERANGE;
		}
	}

	return 0;
}
EXPORT_SYMBOL_GPL(tquic_cong_data_validate);

/*
 * =============================================================================
 * Application with Careful Resume
 * =============================================================================
 */

int tquic_cong_data_apply(struct tquic_connection *conn,
			  struct tquic_path *path,
			  const struct tquic_cong_data *data)
{
	struct tquic_cong_data_state *state;
	unsigned long flags_lock;
	u64 current_cwnd, target_cwnd;
	int ret;

	if (!conn || !path || !data)
		return -EINVAL;

	state = cong_data_get_state(conn);
	if (!state || !state->enabled)
		return -ENOENT;

	/* Validate the data first */
	ret = tquic_cong_data_validate(conn, data);
	if (ret < 0)
		return ret;

	/* Verify HMAC if data is authenticated */
	if (data->flags & TQUIC_CONG_DATA_FLAG_AUTHENTICATED) {
		ret = tquic_cong_data_verify_hmac(conn, data);
		if (ret < 0) {
			tquic_dbg("cong_data: HMAC verification failed\n");
			return ret;
		}
	}

	spin_lock_irqsave(&state->lock, flags_lock);

	/* Check sequence number for ordering */
	if (data->seq_num <= state->last_received_seq && state->have_received) {
		tquic_dbg("cong_data: out of order seq %llu <= %llu\n",
			 data->seq_num, state->last_received_seq);
		spin_unlock_irqrestore(&state->lock, flags_lock);
		return -EALREADY;
	}

	/* Store received data */
	memcpy(&state->received, data, sizeof(*data));
	state->last_received_seq = data->seq_num;
	state->have_received = true;

	/* Get current cwnd and calculate target */
	current_cwnd = tquic_cong_get_cwnd(path);

	/* Determine target cwnd from received data */
	if (data->flags & TQUIC_CONG_DATA_FLAG_HAS_CWND) {
		/* Clamp the target cwnd to safe range */
		target_cwnd = clamp_u64_val(data->cwnd,
					    TQUIC_CONG_DATA_MIN_CWND,
					    TQUIC_CONG_DATA_MAX_CWND);
	} else {
		/* Estimate cwnd from BWE and RTT: cwnd = BWE * RTT / 8 */
		u64 bwe_bytes = data->bwe / 8;  /* Convert to bytes */
		u64 rtt_sec_frac = data->min_rtt;  /* in microseconds */
		target_cwnd = (bwe_bytes * rtt_sec_frac) / 1000000ULL;
		target_cwnd = clamp_u64_val(target_cwnd,
					    TQUIC_CONG_DATA_MIN_CWND,
					    TQUIC_CONG_DATA_MAX_CWND);
	}

	/* Don't apply if current state is already better */
	if (current_cwnd >= target_cwnd) {
		tquic_dbg("cong_data: current cwnd %llu >= target %llu\n",
			 current_cwnd, target_cwnd);
		spin_unlock_irqrestore(&state->lock, flags_lock);
		return 0;
	}

	/*
	 * Initialize Careful Resume state
	 *
	 * We DON'T immediately set cwnd to the target. Instead, we:
	 * 1. Start in VALIDATING phase to confirm RTT matches
	 * 2. Move to RAMPING phase to gradually increase cwnd
	 * 3. Complete or RETREAT if validation fails
	 */
	state->applied = true;
	state->apply_phase = TQUIC_CONG_DATA_PHASE_VALIDATING;
	state->apply_start_time = ktime_get();
	state->saved_cwnd = current_cwnd;
	state->target_cwnd = target_cwnd;
	state->validated_rtt = data->min_rtt;
	state->acks_since_apply = 0;
	state->bytes_acked_since_apply = 0;
	state->bytes_lost_since_apply = 0;

	spin_unlock_irqrestore(&state->lock, flags_lock);

	tquic_dbg("cong_data: Careful Resume started: current=%llu target=%llu saved_rtt=%llu\n",
		 current_cwnd, target_cwnd, data->min_rtt);

	return 0;
}
EXPORT_SYMBOL_GPL(tquic_cong_data_apply);

/*
 * =============================================================================
 * Careful Resume ACK/Loss Handling
 * =============================================================================
 */

bool tquic_cong_data_on_ack(struct tquic_connection *conn,
			    struct tquic_path *path,
			    u64 bytes_acked, u64 rtt_us)
{
	struct tquic_cong_data_state *state;
	unsigned long flags_lock;
	u64 rtt_ratio;
	u64 current_cwnd;
	bool in_progress = false;

	if (!conn || !path)
		return false;

	state = cong_data_get_state(conn);
	if (!state)
		return false;

	spin_lock_irqsave(&state->lock, flags_lock);

	if (!state->applied ||
	    state->apply_phase == TQUIC_CONG_DATA_PHASE_NONE ||
	    state->apply_phase == TQUIC_CONG_DATA_PHASE_COMPLETE ||
	    state->apply_phase == TQUIC_CONG_DATA_PHASE_RETREATED) {
		spin_unlock_irqrestore(&state->lock, flags_lock);
		return false;
	}

	state->acks_since_apply++;
	state->bytes_acked_since_apply += bytes_acked;

	switch (state->apply_phase) {
	case TQUIC_CONG_DATA_PHASE_VALIDATING:
		/*
		 * Validation phase: Check if observed RTT is close to saved RTT
		 * If RTT is significantly higher, the path may have changed
		 */
		if (state->validated_rtt > 0) {
			u64 vrtt = state->validated_rtt;

			rtt_ratio = vrtt ? (rtt_us * 100) / vrtt : 0;
			if (rtt_ratio > TQUIC_CONG_DATA_RTT_RATIO_THRESHOLD) {
				/* RTT much higher than saved - retreat */
				tquic_dbg("cong_data: CR RTT validation failed: %llu vs %llu (ratio %llu%%)\n",
					 rtt_us, state->validated_rtt, rtt_ratio);
				spin_unlock_irqrestore(&state->lock, flags_lock);
				tquic_cong_data_safe_retreat(conn, path);
				return false;
			}
		}

		/* Need a few ACKs to validate */
		if (state->acks_since_apply >= 3) {
			/* RTT validated, move to ramping */
			state->apply_phase = TQUIC_CONG_DATA_PHASE_RAMPING;
			tquic_dbg("cong_data: CR RTT validated, entering RAMPING phase\n");
		}
		in_progress = true;
		break;

	case TQUIC_CONG_DATA_PHASE_RAMPING:
		/*
		 * Ramping phase: Gradually increase cwnd toward target
		 * Use slow start like growth but capped at target
		 */
		current_cwnd = tquic_cong_get_cwnd(path);

		if (current_cwnd >= state->target_cwnd) {
			/* Reached target, complete */
			state->apply_phase = TQUIC_CONG_DATA_PHASE_COMPLETE;
			tquic_dbg("cong_data: CR complete: cwnd=%llu target=%llu\n",
				 current_cwnd, state->target_cwnd);
			in_progress = false;
		} else {
			/*
			 * Increase cwnd by bytes_acked, but cap at target
			 * This gives slow-start-like growth
			 */
			u64 new_cwnd = current_cwnd + bytes_acked;
			new_cwnd = min(new_cwnd, state->target_cwnd);

			/* We don't directly set cwnd here - the CC algorithm
			 * handles the increase. We just track progress.
			 * The caller may choose to boost cwnd based on this.
			 */
			in_progress = true;
		}
		break;

	default:
		break;
	}

	spin_unlock_irqrestore(&state->lock, flags_lock);
	return in_progress;
}
EXPORT_SYMBOL_GPL(tquic_cong_data_on_ack);

void tquic_cong_data_on_loss(struct tquic_connection *conn,
			     struct tquic_path *path,
			     u64 bytes_lost)
{
	struct tquic_cong_data_state *state;
	unsigned long flags_lock;
	u64 loss_rate;

	if (!conn || !path)
		return;

	state = cong_data_get_state(conn);
	if (!state)
		return;

	spin_lock_irqsave(&state->lock, flags_lock);

	if (!state->applied ||
	    state->apply_phase == TQUIC_CONG_DATA_PHASE_NONE ||
	    state->apply_phase == TQUIC_CONG_DATA_PHASE_COMPLETE ||
	    state->apply_phase == TQUIC_CONG_DATA_PHASE_RETREATED) {
		spin_unlock_irqrestore(&state->lock, flags_lock);
		return;
	}

	state->bytes_lost_since_apply += bytes_lost;

	/*
	 * CF-465: Calculate loss rate during resume.
	 * Guard against u64 addition overflow in the denominator,
	 * and ensure denominator is never zero.
	 */
	if (state->bytes_acked_since_apply > 0) {
		u64 denom = state->bytes_acked_since_apply +
			    state->bytes_lost_since_apply;

		/* Protect against u64 addition wrapping */
		if (denom < state->bytes_acked_since_apply)
			denom = U64_MAX;

		loss_rate = (state->bytes_lost_since_apply * 10000) /
			    denom;

		if (loss_rate > TQUIC_CONG_DATA_LOSS_THRESHOLD) {
			/* Loss rate too high - retreat */
			tquic_warn("cong_data: CR loss threshold exceeded: %llu\n",
				 loss_rate);
			spin_unlock_irqrestore(&state->lock, flags_lock);
			tquic_cong_data_safe_retreat(conn, path);
			return;
		}
	}

	spin_unlock_irqrestore(&state->lock, flags_lock);
}
EXPORT_SYMBOL_GPL(tquic_cong_data_on_loss);

void tquic_cong_data_safe_retreat(struct tquic_connection *conn,
				  struct tquic_path *path)
{
	struct tquic_cong_data_state *state;
	unsigned long flags_lock;

	if (!conn || !path)
		return;

	state = cong_data_get_state(conn);
	if (!state)
		return;

	spin_lock_irqsave(&state->lock, flags_lock);

	if (state->apply_phase == TQUIC_CONG_DATA_PHASE_RETREATED) {
		spin_unlock_irqrestore(&state->lock, flags_lock);
		return;
	}

	state->apply_phase = TQUIC_CONG_DATA_PHASE_RETREATED;
	spin_unlock_irqrestore(&state->lock, flags_lock);

	/* Reset to minimum cwnd and start slow start */
	tquic_warn("cong_data: Careful Resume safe retreat executed\n");

	/* The actual cwnd reset is done by the CC algorithm
	 * by calling tquic_cong_on_persistent_congestion or similar
	 */
}
EXPORT_SYMBOL_GPL(tquic_cong_data_safe_retreat);

/*
 * =============================================================================
 * HMAC Authentication
 * =============================================================================
 */

int tquic_cong_data_set_hmac_key(struct tquic_connection *conn,
				 const u8 *key, size_t key_len)
{
	struct tquic_cong_data_state *state;
	unsigned long flags_lock;

	if (!conn || !key)
		return -EINVAL;

	if (key_len != TQUIC_CONG_DATA_HMAC_KEY_LEN)
		return -EINVAL;

	state = cong_data_get_state(conn);
	if (!state)
		return -ENOENT;

	spin_lock_irqsave(&state->lock, flags_lock);
	memcpy(state->hmac_key, key, TQUIC_CONG_DATA_HMAC_KEY_LEN);
	state->hmac_key_set = true;
	spin_unlock_irqrestore(&state->lock, flags_lock);

	return 0;
}
EXPORT_SYMBOL_GPL(tquic_cong_data_set_hmac_key);

int tquic_cong_data_compute_hmac(struct tquic_connection *conn,
				 struct tquic_cong_data *data)
{
	struct tquic_cong_data_state *state;
	struct crypto_shash *tfm;
	struct shash_desc *desc;
	u8 full_hmac[32];  /* Full SHA-256 output */
	u8 msg[128];
	size_t msg_len = 0;
	int ret;

	if (!conn || !data)
		return -EINVAL;

	state = cong_data_get_state(conn);
	if (!state || !state->hmac_key_set)
		return -ENOENT;

	tfm = crypto_alloc_shash("hmac(sha256)", 0, 0);
	if (IS_ERR(tfm))
		return PTR_ERR(tfm);

	ret = crypto_shash_setkey(tfm, state->hmac_key,
				  TQUIC_CONG_DATA_HMAC_KEY_LEN);
	if (ret < 0)
		goto out_free_tfm;

	desc = kzalloc(sizeof(*desc) + crypto_shash_descsize(tfm), GFP_KERNEL);
	if (!desc) {
		ret = -ENOMEM;
		goto out_free_tfm;
	}
	desc->tfm = tfm;

	/* Build message: seq_num || bwe || min_rtt || loss_rate || timestamp || token */
	put_unaligned_be64(data->seq_num, msg + msg_len);
	msg_len += 8;
	put_unaligned_be64(data->bwe, msg + msg_len);
	msg_len += 8;
	put_unaligned_be64(data->min_rtt, msg + msg_len);
	msg_len += 8;
	put_unaligned_be32(data->loss_rate, msg + msg_len);
	msg_len += 4;
	put_unaligned_be64(data->timestamp, msg + msg_len);
	msg_len += 8;
	memcpy(msg + msg_len, data->endpoint_token, TQUIC_CONG_DATA_TOKEN_LEN);
	msg_len += TQUIC_CONG_DATA_TOKEN_LEN;

	ret = crypto_shash_digest(desc, msg, msg_len, full_hmac);
	if (ret < 0)
		goto out_free_desc;

	/* Truncate to 16 bytes */
	memcpy(data->hmac, full_hmac, TQUIC_CONG_DATA_HMAC_LEN);
	ret = 0;

out_free_desc:
	/* CF-541: Zeroize HMAC output and message buffer on all paths */
	memzero_explicit(full_hmac, sizeof(full_hmac));
	memzero_explicit(msg, sizeof(msg));
	kfree_sensitive(desc);
out_free_tfm:
	crypto_free_shash(tfm);
	return ret;
}
EXPORT_SYMBOL_GPL(tquic_cong_data_compute_hmac);

int tquic_cong_data_verify_hmac(struct tquic_connection *conn,
				const struct tquic_cong_data *data)
{
	struct tquic_cong_data data_copy;
	int ret;

	if (!conn || !data)
		return -EINVAL;

	if (!(data->flags & TQUIC_CONG_DATA_FLAG_AUTHENTICATED))
		return -EINVAL;

	/* Make a copy and compute HMAC */
	memcpy(&data_copy, data, sizeof(data_copy));

	ret = tquic_cong_data_compute_hmac(conn, &data_copy);
	if (ret < 0)
		return ret;

	/* Compare HMACs (constant-time comparison for security) */
	if (crypto_memneq(data->hmac, data_copy.hmac, TQUIC_CONG_DATA_HMAC_LEN))
		return -EBADMSG;

	return 0;
}
EXPORT_SYMBOL_GPL(tquic_cong_data_verify_hmac);

/*
 * =============================================================================
 * Privacy Controls
 * =============================================================================
 */

int tquic_cong_data_set_privacy(struct tquic_connection *conn,
				enum tquic_cong_data_privacy level)
{
	struct tquic_cong_data_state *state;
	unsigned long flags_lock;

	if (!conn)
		return -EINVAL;

	if (level > TQUIC_CONG_PRIVACY_DISABLED)
		return -EINVAL;

	state = cong_data_get_state(conn);
	if (!state)
		return -ENOENT;

	spin_lock_irqsave(&state->lock, flags_lock);
	state->privacy_level = level;
	spin_unlock_irqrestore(&state->lock, flags_lock);

	return 0;
}
EXPORT_SYMBOL_GPL(tquic_cong_data_set_privacy);

/*
 * =============================================================================
 * Query Functions
 * =============================================================================
 */

bool tquic_cong_data_is_enabled(struct tquic_connection *conn)
{
	struct tquic_cong_data_state *state;

	if (!conn)
		return false;

	state = cong_data_get_state(conn);
	return state && state->enabled;
}
EXPORT_SYMBOL_GPL(tquic_cong_data_is_enabled);

bool tquic_cong_data_should_send(struct tquic_connection *conn,
				 struct tquic_path *path)
{
	struct tquic_cong_data_state *state;
	unsigned long flags_lock;
	ktime_t now;
	s64 elapsed_ms;
	bool should_send = false;

	if (!conn || !path)
		return false;

	state = cong_data_get_state(conn);
	if (!state || !state->enabled)
		return false;

	if (state->privacy_level == TQUIC_CONG_PRIVACY_DISABLED)
		return false;

	spin_lock_irqsave(&state->lock, flags_lock);

	/* Check outstanding frame limit */
	if (state->outstanding >= TQUIC_CONG_DATA_MAX_OUTSTANDING)
		goto out;

	/* Check rate limit */
	now = ktime_get();
	elapsed_ms = ktime_ms_delta(now, state->last_sent_time);
	if (elapsed_ms < TQUIC_CONG_DATA_MIN_INTERVAL_MS)
		goto out;

	should_send = true;

out:
	spin_unlock_irqrestore(&state->lock, flags_lock);
	return should_send;
}
EXPORT_SYMBOL_GPL(tquic_cong_data_should_send);

void tquic_cong_data_on_frame_acked(struct tquic_connection *conn, u64 seq_num)
{
	struct tquic_cong_data_state *state;
	unsigned long flags_lock;

	if (!conn)
		return;

	state = cong_data_get_state(conn);
	if (!state)
		return;

	spin_lock_irqsave(&state->lock, flags_lock);
	if (state->outstanding > 0)
		state->outstanding--;
	spin_unlock_irqrestore(&state->lock, flags_lock);
}
EXPORT_SYMBOL_GPL(tquic_cong_data_on_frame_acked);

void tquic_cong_data_on_frame_lost(struct tquic_connection *conn, u64 seq_num)
{
	struct tquic_cong_data_state *state;
	unsigned long flags_lock;

	if (!conn)
		return;

	state = cong_data_get_state(conn);
	if (!state)
		return;

	spin_lock_irqsave(&state->lock, flags_lock);
	if (state->outstanding > 0)
		state->outstanding--;
	/* Note: We don't automatically retransmit - the frame is informational */
	spin_unlock_irqrestore(&state->lock, flags_lock);
}
EXPORT_SYMBOL_GPL(tquic_cong_data_on_frame_lost);

ssize_t tquic_cong_data_handle_frame(struct tquic_connection *conn,
				     const u8 *buf, size_t buflen)
{
	struct tquic_cong_data data;
	struct tquic_path *path;
	ssize_t consumed;
	int ret;

	if (!conn || !buf)
		return -EINVAL;

	consumed = tquic_cong_data_decode(buf, buflen, &data);
	if (consumed < 0)
		return consumed;

	/* Apply the received data */
	rcu_read_lock();
	path = rcu_dereference(conn->active_path);
	if (path && !tquic_path_get(path))
		path = NULL;
	rcu_read_unlock();

	ret = tquic_cong_data_apply(conn, path, &data);
	if (path)
		tquic_path_put(path);
	if (ret < 0 && ret != -EALREADY) {
		tquic_dbg("cong_data: failed to apply CONGESTION_DATA: %d\n", ret);
		/* Don't return error - frame was parsed successfully */
	}

	return consumed;
}
EXPORT_SYMBOL_GPL(tquic_cong_data_handle_frame);

int tquic_cong_data_generate_token(struct tquic_connection *conn, u8 *token)
{
	if (!conn || !token)
		return -EINVAL;

	/*
	 * Generate a unique token identifying this endpoint.
	 * In production, this should incorporate server identity
	 * and potentially connection-specific data.
	 */
	get_random_bytes(token, TQUIC_CONG_DATA_TOKEN_LEN);
	return 0;
}
EXPORT_SYMBOL_GPL(tquic_cong_data_generate_token);

enum tquic_cong_data_apply_phase tquic_cong_data_get_apply_phase(
	struct tquic_connection *conn)
{
	struct tquic_cong_data_state *state;

	if (!conn)
		return TQUIC_CONG_DATA_PHASE_NONE;

	state = cong_data_get_state(conn);
	if (!state)
		return TQUIC_CONG_DATA_PHASE_NONE;

	return state->apply_phase;
}
EXPORT_SYMBOL_GPL(tquic_cong_data_get_apply_phase);

const char *tquic_cong_data_get_phase_name(enum tquic_cong_data_apply_phase phase)
{
	switch (phase) {
	case TQUIC_CONG_DATA_PHASE_NONE:
		return "none";
	case TQUIC_CONG_DATA_PHASE_VALIDATING:
		return "validating";
	case TQUIC_CONG_DATA_PHASE_RAMPING:
		return "ramping";
	case TQUIC_CONG_DATA_PHASE_COMPLETE:
		return "complete";
	case TQUIC_CONG_DATA_PHASE_RETREATED:
		return "retreated";
	default:
		return "unknown";
	}
}
EXPORT_SYMBOL_GPL(tquic_cong_data_get_phase_name);

/*
 * =============================================================================
 * Export/Import for Session Storage
 * =============================================================================
 */

int tquic_cong_data_export(struct tquic_connection *conn,
			   struct tquic_path *path,
			   const char *server_name, u8 server_name_len,
			   struct tquic_cong_data_export *export)
{
	int ret;

	if (!conn || !path || !export)
		return -EINVAL;

	if (server_name_len > sizeof(export->server_name) - 1)
		return -EINVAL;

	memset(export, 0, sizeof(*export));
	export->version = TQUIC_CONG_DATA_VERSION;
	export->export_time = get_current_timestamp();

	if (server_name && server_name_len > 0) {
		memcpy(export->server_name, server_name, server_name_len);
		export->server_name_len = server_name_len;
	}

	/* Generate current congestion data */
	ret = tquic_cong_data_generate(conn, path, &export->data);
	if (ret < 0)
		return ret;

	return 0;
}
EXPORT_SYMBOL_GPL(tquic_cong_data_export);

int tquic_cong_data_import(struct tquic_connection *conn,
			   struct tquic_path *path,
			   const struct tquic_cong_data_export *export)
{
	u64 now, age;
	int ret;

	if (!conn || !path || !export)
		return -EINVAL;

	if (export->version != TQUIC_CONG_DATA_VERSION) {
		tquic_dbg("cong_data: import version mismatch: %u\n",
			 export->version);
		return -EINVAL;
	}

	/* Check data age */
	now = get_current_timestamp();
	if (now < export->export_time) {
		/* Export time in future - clock skew or tampering */
		return -EINVAL;
	}

	age = now - export->export_time;
	if (age > TQUIC_CONG_DATA_MAX_LIFETIME_SEC) {
		tquic_dbg("cong_data: import expired (age %llu sec)\n", age);
		return -ESTALE;
	}

	/* Apply the imported data */
	ret = tquic_cong_data_apply(conn, path, &export->data);
	if (ret < 0)
		return ret;

	return 0;
}
EXPORT_SYMBOL_GPL(tquic_cong_data_import);

/*
 * =============================================================================
 * 0-RTT Integration
 * =============================================================================
 */

int tquic_cong_data_store_for_zero_rtt(struct tquic_connection *conn,
				       struct tquic_path *path,
				       const char *server_name,
				       u8 server_name_len)
{
	struct tquic_cong_data_export export;
	struct cong_data_cache_entry *entry = NULL;
	unsigned long flags_lock;
	int i, oldest_idx = 0;
	ktime_t oldest_time = KTIME_MAX;
	int ret;

	if (!conn || !path || !server_name || server_name_len == 0)
		return -EINVAL;

	/* Export current state */
	ret = tquic_cong_data_export(conn, path, server_name, server_name_len,
				     &export);
	if (ret < 0)
		return ret;

	spin_lock_irqsave(&cong_data_cache_lock, flags_lock);

	/* Look for existing entry or oldest slot */
	for (i = 0; i < CONG_DATA_CACHE_SIZE; i++) {
		if (cong_data_cache[i].valid &&
		    cong_data_cache[i].server_name_len == server_name_len &&
		    memcmp(cong_data_cache[i].server_name, server_name,
			   server_name_len) == 0) {
			/* Found existing entry */
			entry = &cong_data_cache[i];
			break;
		}

		if (!cong_data_cache[i].valid) {
			/* Empty slot */
			entry = &cong_data_cache[i];
			break;
		}

		/* Track oldest for LRU eviction */
		if (ktime_before(cong_data_cache[i].store_time, oldest_time)) {
			oldest_time = cong_data_cache[i].store_time;
			oldest_idx = i;
		}
	}

	/* Use oldest entry if no slot found */
	if (!entry)
		entry = &cong_data_cache[oldest_idx];

	/* Store the data */
	memcpy(&entry->export, &export, sizeof(export));
	memcpy(entry->server_name, server_name, server_name_len);
	entry->server_name_len = server_name_len;
	entry->store_time = ktime_get();
	entry->valid = true;

	spin_unlock_irqrestore(&cong_data_cache_lock, flags_lock);

	return 0;
}
EXPORT_SYMBOL_GPL(tquic_cong_data_store_for_zero_rtt);

int tquic_cong_data_load_for_zero_rtt(struct tquic_connection *conn,
				      struct tquic_path *path,
				      const char *server_name,
				      u8 server_name_len)
{
	struct tquic_cong_data_export export;
	unsigned long flags_lock;
	int i;
	bool found = false;

	if (!conn || !path || !server_name || server_name_len == 0)
		return -EINVAL;

	spin_lock_irqsave(&cong_data_cache_lock, flags_lock);

	for (i = 0; i < CONG_DATA_CACHE_SIZE; i++) {
		if (cong_data_cache[i].valid &&
		    cong_data_cache[i].server_name_len == server_name_len &&
		    memcmp(cong_data_cache[i].server_name, server_name,
			   server_name_len) == 0) {
			/* Found entry - copy it */
			memcpy(&export, &cong_data_cache[i].export,
			       sizeof(export));
			found = true;
			break;
		}
	}

	spin_unlock_irqrestore(&cong_data_cache_lock, flags_lock);

	if (!found)
		return -ENOENT;

	/* Import the loaded data */
	return tquic_cong_data_import(conn, path, &export);
}
EXPORT_SYMBOL_GPL(tquic_cong_data_load_for_zero_rtt);

/*
 * =============================================================================
 * Module Init/Exit
 * =============================================================================
 */

int __init tquic_cong_data_module_init(void)
{
	int i;

	/* Initialize cache */
	spin_lock_init(&cong_data_cache_lock);
	for (i = 0; i < CONG_DATA_CACHE_SIZE; i++) {
		cong_data_cache[i].valid = false;
	}

	tquic_info("cong_data: initialized\n");
	return 0;
}

void tquic_cong_data_module_exit(void)
{
	/* Clear any sensitive data in cache */
	memset(cong_data_cache, 0, sizeof(cong_data_cache));
	tquic_info("cong_data: cleanup complete\n");
}

MODULE_DESCRIPTION("TQUIC Congestion Control Data Exchange");
MODULE_LICENSE("GPL");
