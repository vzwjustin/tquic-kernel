// SPDX-License-Identifier: GPL-2.0-only
/*
 * TQUIC: QUIC Receive Timestamps Extension Implementation
 *
 * Copyright (c) 2026 Linux Foundation
 *
 * Implements the QUIC Receive Timestamps extension as specified in
 * draft-smith-quic-receive-ts-03. This extension enables endpoints to
 * report packet receive timestamps in ACK frames for:
 *   - Improved RTT estimation
 *   - Better congestion control
 *   - One-way delay measurement
 *   - Network path characterization
 *
 * Key features:
 *   - Microsecond precision timestamps
 *   - Delta compression with configurable exponent
 *   - Ring buffer for efficient timestamp storage
 *   - Session-wide timestamp basis for compact encoding
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/ktime.h>
#include <linux/spinlock.h>
#include <linux/list.h>
#include <net/tquic.h>

#include "receive_timestamps.h"
#include "varint.h"
#include "ack.h"

/* Memory cache for timestamp state */
static struct kmem_cache *tquic_receive_ts_cache;

/*
 * =============================================================================
 * Internal Helper Functions
 * =============================================================================
 */

/**
 * ktime_to_us_relative - Convert ktime to microseconds relative to basis
 * @time: Time to convert
 * @basis: Reference time point
 *
 * Returns time in microseconds since basis, or 0 if time is before basis.
 */
static inline u64 ktime_to_us_relative(ktime_t time, ktime_t basis)
{
	s64 delta_ns;

	if (ktime_before(time, basis))
		return 0;

	delta_ns = ktime_to_ns(ktime_sub(time, basis));
	return div64_s64(delta_ns, NSEC_PER_USEC);
}

/**
 * apply_exponent - Apply exponent scaling to timestamp delta
 * @delta_us: Delta in microseconds
 * @exponent: Scaling exponent
 *
 * Returns delta >> exponent (scaled down).
 */
static inline u64 apply_exponent(u64 delta_us, u8 exponent)
{
	if (exponent >= 64)
		return 0;
	return delta_us >> exponent;
}

/**
 * unapply_exponent - Reverse exponent scaling
 * @scaled: Scaled delta value
 * @exponent: Scaling exponent
 *
 * Returns scaled << exponent (scaled up).
 */
static inline u64 unapply_exponent(u64 scaled, u8 exponent)
{
	if (exponent >= 64)
		return 0;
	return scaled << exponent;
}

/**
 * ring_index - Calculate ring buffer index with wrap-around
 * @head: Current head position
 * @offset: Offset from head (negative = older entries)
 * @size: Ring buffer size
 */
static inline u32 ring_index(u32 head, s32 offset, u32 size)
{
	s32 idx = (s32)head + offset;

	while (idx < 0)
		idx += size;

	return (u32)(idx % size);
}

/*
 * =============================================================================
 * Initialization and Cleanup
 * =============================================================================
 */

/**
 * tquic_receive_ts_init - Initialize receive timestamps state
 * @state: State structure to initialize
 *
 * Returns 0 on success, negative error code on failure.
 */
int tquic_receive_ts_init(struct tquic_receive_ts_state *state)
{
	if (!state)
		return -EINVAL;

	memset(state, 0, sizeof(*state));
	spin_lock_init(&state->lock);

	/* Allocate ring buffer */
	state->ring_buffer = kvcalloc(TQUIC_RECEIVE_TS_RINGBUF_SIZE,
				      sizeof(struct tquic_pkt_timestamp),
				      GFP_KERNEL);
	if (!state->ring_buffer)
		return -ENOMEM;

	/* Set defaults */
	state->params.max_receive_timestamps_per_ack =
		TQUIC_DEFAULT_MAX_RECEIVE_TIMESTAMPS;
	state->params.receive_timestamps_exponent =
		TQUIC_DEFAULT_RECEIVE_TS_EXPONENT;
	state->params.enabled = false;

	state->exponent = TQUIC_DEFAULT_RECEIVE_TS_EXPONENT;
	state->max_timestamps = TQUIC_DEFAULT_MAX_RECEIVE_TIMESTAMPS;

	state->timestamp_basis_set = false;
	state->ring_head = 0;
	state->ring_count = 0;

	pr_debug("tquic: receive timestamps state initialized\n");
	return 0;
}
EXPORT_SYMBOL_GPL(tquic_receive_ts_init);

/**
 * tquic_receive_ts_destroy - Destroy receive timestamps state
 * @state: State to destroy
 */
void tquic_receive_ts_destroy(struct tquic_receive_ts_state *state)
{
	if (!state)
		return;

	spin_lock(&state->lock);

	if (state->ring_buffer) {
		kvfree(state->ring_buffer);
		state->ring_buffer = NULL;
	}

	spin_unlock(&state->lock);

	pr_debug("tquic: receive timestamps state destroyed\n");
}
EXPORT_SYMBOL_GPL(tquic_receive_ts_destroy);

/**
 * tquic_receive_ts_reset - Reset receive timestamps state
 * @state: State to reset
 */
void tquic_receive_ts_reset(struct tquic_receive_ts_state *state)
{
	u32 i;

	if (!state)
		return;

	spin_lock(&state->lock);

	/* Clear ring buffer */
	for (i = 0; i < TQUIC_RECEIVE_TS_RINGBUF_SIZE; i++)
		state->ring_buffer[i].valid = false;

	state->ring_head = 0;
	state->ring_count = 0;

	/* Reset timestamp basis */
	state->timestamp_basis_set = false;
	state->timestamp_basis = 0;
	state->timestamp_basis_us = 0;
	state->timestamp_basis_pn = 0;

	spin_unlock(&state->lock);

	pr_debug("tquic: receive timestamps state reset\n");
}
EXPORT_SYMBOL_GPL(tquic_receive_ts_reset);

/*
 * =============================================================================
 * Parameter Negotiation
 * =============================================================================
 */

/**
 * tquic_receive_ts_set_local_params - Set local receive timestamp parameters
 */
void tquic_receive_ts_set_local_params(struct tquic_receive_ts_state *state,
				       u32 max_timestamps, u8 exponent)
{
	if (!state)
		return;

	spin_lock(&state->lock);

	/* Clamp values to valid ranges */
	if (max_timestamps > TQUIC_MAX_RECEIVE_TIMESTAMPS)
		max_timestamps = TQUIC_MAX_RECEIVE_TIMESTAMPS;

	if (exponent > TQUIC_MAX_RECEIVE_TS_EXPONENT)
		exponent = TQUIC_MAX_RECEIVE_TS_EXPONENT;

	state->params.max_receive_timestamps_per_ack = max_timestamps;
	state->params.receive_timestamps_exponent = exponent;

	spin_unlock(&state->lock);

	pr_debug("tquic: local receive ts params: max=%u exp=%u\n",
		 max_timestamps, exponent);
}
EXPORT_SYMBOL_GPL(tquic_receive_ts_set_local_params);

/**
 * tquic_receive_ts_set_peer_params - Set peer's receive timestamp parameters
 */
void tquic_receive_ts_set_peer_params(struct tquic_receive_ts_state *state,
				      u64 max_timestamps, u8 exponent)
{
	if (!state)
		return;

	spin_lock(&state->lock);

	/*
	 * Store peer's parameters. The peer's max_timestamps tells us
	 * how many timestamps they want to receive. The exponent tells
	 * us what precision they want.
	 */
	if (max_timestamps > TQUIC_MAX_RECEIVE_TIMESTAMPS)
		max_timestamps = TQUIC_MAX_RECEIVE_TIMESTAMPS;

	if (exponent > TQUIC_MAX_RECEIVE_TS_EXPONENT)
		exponent = TQUIC_MAX_RECEIVE_TS_EXPONENT;

	/* Use peer's values for what we send */
	state->max_timestamps = (u32)max_timestamps;
	state->exponent = exponent;

	spin_unlock(&state->lock);

	pr_debug("tquic: peer receive ts params: max=%llu exp=%u\n",
		 max_timestamps, exponent);
}
EXPORT_SYMBOL_GPL(tquic_receive_ts_set_peer_params);

/**
 * tquic_receive_ts_negotiate - Negotiate receive timestamp parameters
 */
bool tquic_receive_ts_negotiate(struct tquic_receive_ts_state *state)
{
	if (!state)
		return false;

	spin_lock(&state->lock);

	/*
	 * Extension is enabled if both sides advertised support.
	 * Support is indicated by non-zero max_receive_timestamps_per_ack.
	 */
	if (state->params.max_receive_timestamps_per_ack > 0 &&
	    state->max_timestamps > 0) {
		state->params.enabled = true;
		pr_info("tquic: receive timestamps extension enabled "
			"(max=%u, exp=%u)\n",
			state->max_timestamps, state->exponent);
	} else {
		state->params.enabled = false;
		pr_debug("tquic: receive timestamps extension not negotiated\n");
	}

	spin_unlock(&state->lock);

	return state->params.enabled;
}
EXPORT_SYMBOL_GPL(tquic_receive_ts_negotiate);

/**
 * tquic_receive_ts_is_enabled - Check if receive timestamps are enabled
 */
bool tquic_receive_ts_is_enabled(struct tquic_receive_ts_state *state)
{
	bool enabled;

	if (!state)
		return false;

	spin_lock(&state->lock);
	enabled = state->params.enabled;
	spin_unlock(&state->lock);

	return enabled;
}
EXPORT_SYMBOL_GPL(tquic_receive_ts_is_enabled);

/*
 * =============================================================================
 * Timestamp Recording
 * =============================================================================
 */

/**
 * tquic_receive_ts_record - Record receive timestamp for a packet
 */
int tquic_receive_ts_record(struct tquic_receive_ts_state *state,
			    u64 pn, ktime_t recv_time)
{
	struct tquic_pkt_timestamp *entry;
	u64 recv_time_us;

	if (!state || !state->ring_buffer)
		return -EINVAL;

	spin_lock(&state->lock);

	/* Set timestamp basis on first packet if not set */
	if (!state->timestamp_basis_set) {
		state->timestamp_basis = recv_time;
		state->timestamp_basis_us = 0;
		state->timestamp_basis_pn = pn;
		state->timestamp_basis_set = true;
		pr_debug("tquic: timestamp basis set at pn=%llu\n", pn);
	}

	/* Calculate time relative to basis in microseconds */
	recv_time_us = ktime_to_us_relative(recv_time, state->timestamp_basis);

	/* Store in ring buffer */
	entry = &state->ring_buffer[state->ring_head];
	entry->pn = pn;
	entry->recv_time_us = recv_time_us;
	entry->valid = true;

	/* Advance head pointer */
	state->ring_head = (state->ring_head + 1) % TQUIC_RECEIVE_TS_RINGBUF_SIZE;

	if (state->ring_count < TQUIC_RECEIVE_TS_RINGBUF_SIZE)
		state->ring_count++;

	spin_unlock(&state->lock);

	return 0;
}
EXPORT_SYMBOL_GPL(tquic_receive_ts_record);

/**
 * tquic_receive_ts_lookup - Look up timestamp for a packet number
 */
int tquic_receive_ts_lookup(struct tquic_receive_ts_state *state,
			    u64 pn, u64 *recv_time_us)
{
	u32 i, idx;
	int ret = -ENOENT;

	if (!state || !state->ring_buffer || !recv_time_us)
		return -EINVAL;

	spin_lock(&state->lock);

	/* Search backwards from head (most recent first) */
	for (i = 0; i < state->ring_count; i++) {
		idx = ring_index(state->ring_head, -(s32)(i + 1),
				 TQUIC_RECEIVE_TS_RINGBUF_SIZE);
		if (state->ring_buffer[idx].valid &&
		    state->ring_buffer[idx].pn == pn) {
			*recv_time_us = state->ring_buffer[idx].recv_time_us;
			ret = 0;
			break;
		}
	}

	spin_unlock(&state->lock);
	return ret;
}
EXPORT_SYMBOL_GPL(tquic_receive_ts_lookup);

/*
 * =============================================================================
 * ACK Frame Encoding
 * =============================================================================
 */

/**
 * encode_timestamp_ranges - Encode timestamp ranges into buffer
 * @state: Receive timestamps state
 * @ack_ranges: List of ACK ranges
 * @num_ranges: Number of ranges
 * @largest_acked: Largest acked packet number
 * @buf: Output buffer
 * @buf_len: Buffer length
 * @timestamps_encoded: Output: number of timestamps encoded
 *
 * Encodes timestamps for packets in the ACK ranges using delta compression.
 *
 * Wire format (draft-smith-quic-receive-ts-03 Section 4):
 *   Largest Acked Timestamp Delta (varint)
 *   Timestamp Range Count (varint)
 *   For each range:
 *     Gap (varint) - packets between this range and previous
 *     Timestamp Delta Count (varint) - number of deltas in this range
 *     Timestamp Deltas (varint[]) - delta-encoded timestamps
 *
 * Returns number of bytes written, or negative error.
 */
static ssize_t encode_timestamp_ranges(struct tquic_receive_ts_state *state,
				       const struct list_head *ack_ranges,
				       u32 num_ranges, u64 largest_acked,
				       u8 *buf, size_t buf_len,
				       u32 *timestamps_encoded)
{
	size_t offset = 0;
	u64 largest_acked_ts = 0;
	u64 prev_ts = 0;
	u64 prev_pn = largest_acked;
	u32 ts_count = 0;
	u32 range_count = 0;
	size_t range_count_offset;
	struct tquic_ack_range *range;
	int ret;

	*timestamps_encoded = 0;

	/* Look up timestamp for largest acked packet */
	ret = tquic_receive_ts_lookup(state, largest_acked, &largest_acked_ts);
	if (ret < 0) {
		/* No timestamp for largest acked - use 0 */
		largest_acked_ts = 0;
	}

	/* Encode Largest Acked Timestamp Delta (from timestamp basis) */
	ret = tquic_varint_write(buf, buf_len, &offset,
				 apply_exponent(largest_acked_ts,
						state->exponent));
	if (ret < 0)
		return ret;

	/* Reserve space for Timestamp Range Count (will fill in later) */
	range_count_offset = offset;
	ret = tquic_varint_write(buf, buf_len, &offset, 0);
	if (ret < 0)
		return ret;

	prev_ts = largest_acked_ts;

	/* Process each ACK range */
	list_for_each_entry(range, ack_ranges, list) {
		u64 pn;
		u64 range_start_pn;
		size_t deltas_count_offset;
		u32 range_deltas = 0;

		if (ts_count >= state->max_timestamps)
			break;

		/* For first range, start from largest_acked */
		if (range_count == 0) {
			range_start_pn = largest_acked;
		} else {
			/* Encode gap from previous range */
			u64 gap = prev_pn - range->end - 2;
			ret = tquic_varint_write(buf, buf_len, &offset, gap);
			if (ret < 0)
				return ret;
			range_start_pn = range->end;
		}

		/* Reserve space for Timestamp Delta Count */
		deltas_count_offset = offset;
		ret = tquic_varint_write(buf, buf_len, &offset, 0);
		if (ret < 0)
			return ret;

		/* Encode timestamps for packets in this range (high to low) */
		for (pn = range_start_pn; pn >= range->start; pn--) {
			u64 pkt_ts;
			u64 delta;

			if (ts_count >= state->max_timestamps)
				break;

			ret = tquic_receive_ts_lookup(state, pn, &pkt_ts);
			if (ret < 0)
				continue;  /* No timestamp for this packet */

			/* Calculate delta from previous timestamp */
			if (pkt_ts >= prev_ts)
				delta = pkt_ts - prev_ts;
			else
				delta = 0;  /* Shouldn't happen, but handle it */

			/* Apply exponent and encode */
			ret = tquic_varint_write(buf, buf_len, &offset,
						 apply_exponent(delta,
								state->exponent));
			if (ret < 0)
				return ret;

			prev_ts = pkt_ts;
			range_deltas++;
			ts_count++;

			if (pn == 0)
				break;
		}

		/* Update delta count for this range */
		if (range_deltas > 0) {
			size_t saved_offset = offset;
			offset = deltas_count_offset;
			/* Re-encode the delta count at reserved position */
			tquic_varint_write(buf, buf_len, &offset, range_deltas);
			offset = saved_offset;
			range_count++;
		}

		prev_pn = range->start;
	}

	/* Update timestamp range count */
	{
		size_t saved_offset = offset;
		offset = range_count_offset;
		tquic_varint_write(buf, buf_len, &offset, range_count);
		offset = saved_offset;
	}

	*timestamps_encoded = ts_count;
	state->timestamps_sent += ts_count;

	return offset;
}

/**
 * tquic_receive_ts_encode - Encode timestamps into ACK frame
 */
ssize_t tquic_receive_ts_encode(struct tquic_receive_ts_state *state,
				const struct list_head *ack_ranges,
				u32 num_ranges, u64 largest_acked,
				u8 *buf, size_t buf_len)
{
	u32 timestamps_encoded = 0;
	ssize_t ret;

	if (!state || !ack_ranges || !buf)
		return -EINVAL;

	if (!state->params.enabled)
		return 0;

	spin_lock(&state->lock);

	if (!state->timestamp_basis_set) {
		spin_unlock(&state->lock);
		return 0;  /* No basis set yet */
	}

	ret = encode_timestamp_ranges(state, ack_ranges, num_ranges,
				      largest_acked, buf, buf_len,
				      &timestamps_encoded);

	spin_unlock(&state->lock);

	pr_debug("tquic: encoded %u receive timestamps (%zd bytes)\n",
		 timestamps_encoded, ret > 0 ? ret : 0);

	return ret;
}
EXPORT_SYMBOL_GPL(tquic_receive_ts_encode);

/**
 * tquic_receive_ts_get_frame_type - Get appropriate ACK frame type
 */
u64 tquic_receive_ts_get_frame_type(struct tquic_receive_ts_state *state,
				    bool include_ecn)
{
	if (!state || !state->params.enabled) {
		/* Standard ACK types */
		return include_ecn ? TQUIC_FRAME_ACK_ECN : TQUIC_FRAME_ACK;
	}

	/* ACK types with receive timestamps */
	return include_ecn ? TQUIC_FRAME_ACK_ECN_RECEIVE_TIMESTAMPS :
			     TQUIC_FRAME_ACK_RECEIVE_TIMESTAMPS;
}
EXPORT_SYMBOL_GPL(tquic_receive_ts_get_frame_type);

/*
 * =============================================================================
 * ACK Frame Decoding
 * =============================================================================
 */

/**
 * tquic_receive_ts_decode - Decode timestamps from ACK frame
 */
ssize_t tquic_receive_ts_decode(struct tquic_receive_ts_state *state,
				const u8 *buf, size_t len,
				struct tquic_ack_timestamps *timestamps)
{
	size_t offset = 0;
	u64 largest_ts_delta;
	u64 range_count;
	u32 i;
	int ret;

	if (!state || !buf || !timestamps)
		return -EINVAL;

	memset(timestamps, 0, sizeof(*timestamps));

	/* Decode Largest Acked Timestamp Delta */
	ret = tquic_varint_read(buf, len, &offset, &largest_ts_delta);
	if (ret < 0)
		return ret;

	timestamps->largest_acked_timestamp =
		unapply_exponent(largest_ts_delta, state->exponent);

	/* Decode Timestamp Range Count */
	ret = tquic_varint_read(buf, len, &offset, &range_count);
	if (ret < 0)
		return ret;

	if (range_count > TQUIC_MAX_RECEIVE_TIMESTAMPS)
		return -EINVAL;

	timestamps->timestamp_range_count = (u32)range_count;

	if (range_count == 0)
		return offset;

	/* Allocate ranges array */
	timestamps->ranges = kcalloc(range_count,
				     sizeof(struct tquic_timestamp_range),
				     GFP_ATOMIC);
	if (!timestamps->ranges)
		return -ENOMEM;

	/* Decode each range */
	for (i = 0; i < range_count; i++) {
		u64 gap = 0;
		u64 delta_count;
		u32 j;

		/* Gap (not for first range) */
		if (i > 0) {
			ret = tquic_varint_read(buf, len, &offset, &gap);
			if (ret < 0)
				goto err_free;
		}
		timestamps->ranges[i].gap = gap;

		/* Timestamp Delta Count */
		ret = tquic_varint_read(buf, len, &offset, &delta_count);
		if (ret < 0)
			goto err_free;

		if (delta_count > TQUIC_MAX_RECEIVE_TIMESTAMPS) {
			ret = -EINVAL;
			goto err_free;
		}

		timestamps->ranges[i].timestamp_delta_count = delta_count;

		if (delta_count == 0)
			continue;

		/* Allocate deltas array */
		timestamps->ranges[i].timestamp_deltas =
			kcalloc(delta_count, sizeof(u64), GFP_ATOMIC);
		if (!timestamps->ranges[i].timestamp_deltas) {
			ret = -ENOMEM;
			goto err_free;
		}

		/* Decode timestamp deltas */
		for (j = 0; j < delta_count; j++) {
			u64 scaled_delta;

			ret = tquic_varint_read(buf, len, &offset, &scaled_delta);
			if (ret < 0)
				goto err_free;

			timestamps->ranges[i].timestamp_deltas[j] =
				unapply_exponent(scaled_delta, state->exponent);
		}
	}

	spin_lock(&state->lock);
	state->timestamps_received += range_count;
	spin_unlock(&state->lock);

	return offset;

err_free:
	tquic_receive_ts_free_decoded(timestamps);
	return ret;
}
EXPORT_SYMBOL_GPL(tquic_receive_ts_decode);

/**
 * tquic_receive_ts_free_decoded - Free decoded timestamps structure
 */
void tquic_receive_ts_free_decoded(struct tquic_ack_timestamps *timestamps)
{
	u32 i;

	if (!timestamps)
		return;

	if (timestamps->ranges) {
		for (i = 0; i < timestamps->timestamp_range_count; i++) {
			kfree(timestamps->ranges[i].timestamp_deltas);
		}
		kfree(timestamps->ranges);
	}

	memset(timestamps, 0, sizeof(*timestamps));
}
EXPORT_SYMBOL_GPL(tquic_receive_ts_free_decoded);

/**
 * tquic_receive_ts_get_owd - Calculate one-way delay from timestamps
 */
s64 tquic_receive_ts_get_owd(struct tquic_receive_ts_state *state,
			     ktime_t sent_time, u64 peer_recv_timestamp)
{
	u64 sent_us;

	if (!state)
		return -EINVAL;

	spin_lock(&state->lock);

	if (!state->timestamp_basis_set) {
		spin_unlock(&state->lock);
		return -ENODATA;
	}

	/*
	 * Note: One-way delay measurement requires clock synchronization
	 * between endpoints. Without synchronization, this value represents
	 * clock difference + network delay.
	 *
	 * OWD = peer_recv_time - local_sent_time
	 */
	sent_us = ktime_to_us_relative(sent_time, state->timestamp_basis);

	spin_unlock(&state->lock);

	/* This is signed because clocks may be unsynchronized */
	return (s64)peer_recv_timestamp - (s64)sent_us;
}
EXPORT_SYMBOL_GPL(tquic_receive_ts_get_owd);

/*
 * =============================================================================
 * Timestamp Basis Management
 * =============================================================================
 */

/**
 * tquic_receive_ts_set_basis - Set the timestamp basis
 */
void tquic_receive_ts_set_basis(struct tquic_receive_ts_state *state,
				ktime_t basis_time, u64 basis_pn)
{
	if (!state)
		return;

	spin_lock(&state->lock);

	state->timestamp_basis = basis_time;
	state->timestamp_basis_us = 0;
	state->timestamp_basis_pn = basis_pn;
	state->timestamp_basis_set = true;

	spin_unlock(&state->lock);

	pr_debug("tquic: timestamp basis set: pn=%llu\n", basis_pn);
}
EXPORT_SYMBOL_GPL(tquic_receive_ts_set_basis);

/**
 * tquic_receive_ts_get_basis - Get the timestamp basis
 */
bool tquic_receive_ts_get_basis(struct tquic_receive_ts_state *state,
				ktime_t *basis_time, u64 *basis_pn)
{
	bool is_set;

	if (!state)
		return false;

	spin_lock(&state->lock);

	is_set = state->timestamp_basis_set;
	if (is_set) {
		if (basis_time)
			*basis_time = state->timestamp_basis;
		if (basis_pn)
			*basis_pn = state->timestamp_basis_pn;
	}

	spin_unlock(&state->lock);

	return is_set;
}
EXPORT_SYMBOL_GPL(tquic_receive_ts_get_basis);

/*
 * =============================================================================
 * Statistics
 * =============================================================================
 */

/**
 * tquic_receive_ts_get_stats - Get receive timestamps statistics
 */
void tquic_receive_ts_get_stats(struct tquic_receive_ts_state *state,
				u64 *timestamps_sent,
				u64 *timestamps_received,
				u32 *ring_utilization)
{
	if (!state)
		return;

	spin_lock(&state->lock);

	if (timestamps_sent)
		*timestamps_sent = state->timestamps_sent;
	if (timestamps_received)
		*timestamps_received = state->timestamps_received;
	if (ring_utilization) {
		*ring_utilization = (state->ring_count * 100) /
				    TQUIC_RECEIVE_TS_RINGBUF_SIZE;
	}

	spin_unlock(&state->lock);
}
EXPORT_SYMBOL_GPL(tquic_receive_ts_get_stats);

/*
 * =============================================================================
 * Module Init/Exit
 * =============================================================================
 */

/**
 * tquic_receive_ts_module_init - Initialize receive timestamps module
 */
int __init tquic_receive_ts_module_init(void)
{
	tquic_receive_ts_cache = kmem_cache_create("tquic_receive_ts",
		sizeof(struct tquic_receive_ts_state),
		0, SLAB_HWCACHE_ALIGN, NULL);

	if (!tquic_receive_ts_cache)
		return -ENOMEM;

	pr_info("tquic: receive timestamps module initialized\n");
	return 0;
}

/**
 * tquic_receive_ts_module_exit - Cleanup receive timestamps module
 */
void __exit tquic_receive_ts_module_exit(void)
{
	kmem_cache_destroy(tquic_receive_ts_cache);
	pr_info("tquic: receive timestamps module cleanup complete\n");
}

MODULE_DESCRIPTION("TQUIC Receive Timestamps Extension (draft-smith-quic-receive-ts-03)");
MODULE_LICENSE("GPL");
