// SPDX-License-Identifier: GPL-2.0-only
/*
 * TQUIC: One-Way Delay Measurement Extension Implementation
 *
 * Copyright (c) 2026 Linux Foundation
 *
 * Implementation of draft-huitema-quic-1wd (One-Way Delay Measurement)
 * for QUIC. Enables accurate measurement of asymmetric link delays
 * through timestamp-enhanced ACK frames.
 *
 * Algorithm Overview:
 * 1. Sender records send time for each packet
 * 2. Receiver includes receive timestamp in ACK_1WD frame
 * 3. Sender calculates one-way delays using timestamps
 * 4. Clock skew is estimated and compensated using minimum offset method
 *
 * Clock Skew Handling:
 * Since endpoints have unsynchronized clocks, we estimate the skew by
 * tracking the minimum observed (remote_time - local_time - RTT/2).
 * This exploits the fact that the true one-way delay cannot be negative,
 * so the minimum offset bounds the clock skew.
 */

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/rbtree.h>
#include <linux/list.h>
#include <linux/ktime.h>
#include <linux/sort.h>
#include <linux/spinlock.h>
#include <net/tquic.h>

#include "one_way_delay.h"
#include "varint.h"
#include "ack.h"

/* Maximum timestamp records to keep (limits memory usage) */
#define MAX_TS_RECORDS		1024

/* Timestamp record slab cache */
static struct kmem_cache *ts_record_cache;

/*
 * =============================================================================
 * Variable-Length Integer Helpers (local copies for self-containment)
 * =============================================================================
 */

static inline size_t owd_varint_len(u64 value)
{
	if (value <= 63)
		return 1;
	if (value <= 16383)
		return 2;
	if (value <= 1073741823ULL)
		return 4;
	return 8;
}

static ssize_t owd_varint_encode(u8 *buf, size_t buflen, u64 value)
{
	size_t len = owd_varint_len(value);

	if (buflen < len)
		return -ENOSPC;

	switch (len) {
	case 1:
		buf[0] = (u8)value;
		break;
	case 2:
		buf[0] = (u8)(0x40 | (value >> 8));
		buf[1] = (u8)value;
		break;
	case 4:
		buf[0] = (u8)(0x80 | (value >> 24));
		buf[1] = (u8)(value >> 16);
		buf[2] = (u8)(value >> 8);
		buf[3] = (u8)value;
		break;
	case 8:
		buf[0] = (u8)(0xc0 | (value >> 56));
		buf[1] = (u8)(value >> 48);
		buf[2] = (u8)(value >> 40);
		buf[3] = (u8)(value >> 32);
		buf[4] = (u8)(value >> 24);
		buf[5] = (u8)(value >> 16);
		buf[6] = (u8)(value >> 8);
		buf[7] = (u8)value;
		break;
	}

	return len;
}

static ssize_t owd_varint_decode(const u8 *buf, size_t buflen, u64 *value)
{
	u8 prefix;
	size_t len;

	if (buflen < 1)
		return -EINVAL;

	prefix = buf[0] >> 6;
	len = 1 << prefix;

	if (buflen < len)
		return -EINVAL;

	switch (len) {
	case 1:
		*value = buf[0] & 0x3f;
		break;
	case 2:
		*value = ((u64)(buf[0] & 0x3f) << 8) | buf[1];
		break;
	case 4:
		*value = ((u64)(buf[0] & 0x3f) << 24) |
			 ((u64)buf[1] << 16) |
			 ((u64)buf[2] << 8) |
			 buf[3];
		break;
	case 8:
		*value = ((u64)(buf[0] & 0x3f) << 56) |
			 ((u64)buf[1] << 48) |
			 ((u64)buf[2] << 40) |
			 ((u64)buf[3] << 32) |
			 ((u64)buf[4] << 24) |
			 ((u64)buf[5] << 16) |
			 ((u64)buf[6] << 8) |
			 buf[7];
		break;
	}

	return len;
}

/*
 * =============================================================================
 * Timestamp Record Management
 * =============================================================================
 */

static struct tquic_owd_timestamp_record *
ts_record_alloc(u64 pn, ktime_t send_time, u32 path_id)
{
	struct tquic_owd_timestamp_record *rec;

	rec = kmem_cache_alloc(ts_record_cache, GFP_ATOMIC);
	if (!rec)
		return NULL;

	RB_CLEAR_NODE(&rec->node);
	INIT_LIST_HEAD(&rec->list);
	rec->pn = pn;
	rec->send_time = send_time;
	rec->path_id = path_id;

	return rec;
}

static void ts_record_free(struct tquic_owd_timestamp_record *rec)
{
	if (rec)
		kmem_cache_free(ts_record_cache, rec);
}

static struct tquic_owd_timestamp_record *
ts_record_lookup(struct tquic_owd_state *owd, u64 pn)
{
	struct rb_node *node = owd->ts_records_root.rb_node;

	while (node) {
		struct tquic_owd_timestamp_record *rec =
			rb_entry(node, struct tquic_owd_timestamp_record, node);

		if (pn < rec->pn)
			node = node->rb_left;
		else if (pn > rec->pn)
			node = node->rb_right;
		else
			return rec;
	}

	return NULL;
}

static int ts_record_insert(struct tquic_owd_state *owd,
			    struct tquic_owd_timestamp_record *rec)
{
	struct rb_node **link = &owd->ts_records_root.rb_node;
	struct rb_node *parent = NULL;
	struct tquic_owd_timestamp_record *entry;

	while (*link) {
		parent = *link;
		entry = rb_entry(parent, struct tquic_owd_timestamp_record, node);

		if (rec->pn < entry->pn)
			link = &(*link)->rb_left;
		else if (rec->pn > entry->pn)
			link = &(*link)->rb_right;
		else
			return -EEXIST;  /* Duplicate packet number */
	}

	rb_link_node(&rec->node, parent, link);
	rb_insert_color(&rec->node, &owd->ts_records_root);
	list_add_tail(&rec->list, &owd->ts_records_list);
	owd->ts_records_count++;

	return 0;
}

static void ts_record_remove(struct tquic_owd_state *owd,
			     struct tquic_owd_timestamp_record *rec)
{
	if (!RB_EMPTY_NODE(&rec->node)) {
		rb_erase(&rec->node, &owd->ts_records_root);
		RB_CLEAR_NODE(&rec->node);
	}
	list_del_init(&rec->list);
	owd->ts_records_count--;
}

/* Clean up old timestamp records to bound memory usage */
static void ts_record_cleanup_old(struct tquic_owd_state *owd)
{
	struct tquic_owd_timestamp_record *rec, *tmp;
	ktime_t cutoff;
	int removed = 0;

	/* Remove records older than 60 seconds or if we have too many */
	cutoff = ktime_sub_ms(ktime_get(), 60000);

	list_for_each_entry_safe(rec, tmp, &owd->ts_records_list, list) {
		if (owd->ts_records_count <= MAX_TS_RECORDS / 2 &&
		    ktime_after(rec->send_time, cutoff))
			break;

		ts_record_remove(owd, rec);
		ts_record_free(rec);
		removed++;

		if (removed >= 100)  /* Batch limit */
			break;
	}
}

/*
 * =============================================================================
 * Clock Skew Estimation
 * =============================================================================
 */

/*
 * Update clock skew estimate using minimum offset method.
 *
 * The idea: For a packet with send time T_s, receive time T_r (remote clock),
 * and assuming true forward OWD is D_f:
 *   T_r = T_s + D_f + skew
 *
 * We observe: offset = T_r - T_s = D_f + skew
 *
 * Since D_f >= 0, the minimum observed offset provides an upper bound on skew.
 * Similarly, using reverse measurements gives a lower bound.
 *
 * For simplicity, we use the minimum offset approach: track minimum offsets
 * and assume skew is approximately (min_offset - min_RTT/2).
 */
void tquic_owd_update_skew(struct tquic_owd_state *owd,
			   ktime_t local_time, u64 remote_time_us,
			   u64 rtt_us)
{
	struct tquic_owd_skew_estimator *skew;
	s64 local_time_us;
	s64 offset;
	s64 min_offset;
	int i;

	if (!owd)
		return;

	skew = &owd->skew;
	local_time_us = ktime_to_us(local_time);

	/* Calculate raw offset (remote - local) */
	offset = (s64)remote_time_us - local_time_us;

	/* Add sample to circular buffer */
	skew->samples[skew->sample_idx] = offset;
	skew->sample_idx = (skew->sample_idx + 1) % TQUIC_OWD_SKEW_SAMPLE_COUNT;
	if (skew->sample_count < TQUIC_OWD_SKEW_SAMPLE_COUNT)
		skew->sample_count++;

	/* Find minimum offset (most negative value indicates forward-heavy path) */
	min_offset = skew->samples[0];
	for (i = 1; i < skew->sample_count; i++) {
		if (skew->samples[i] < min_offset)
			min_offset = skew->samples[i];
	}

	/*
	 * Estimate skew as minimum offset minus half RTT.
	 * This assumes the minimum offset corresponds to minimum queueing,
	 * so offset ~= true_forward_delay + skew, and min forward ~= RTT/2.
	 */
	skew->estimated_skew_us = min_offset - (s64)(rtt_us / 2);

	/* Clamp skew to reasonable bounds */
	if (skew->estimated_skew_us > (s64)TQUIC_OWD_MAX_CLOCK_SKEW_US)
		skew->estimated_skew_us = (s64)TQUIC_OWD_MAX_CLOCK_SKEW_US;
	if (skew->estimated_skew_us < -(s64)TQUIC_OWD_MAX_CLOCK_SKEW_US)
		skew->estimated_skew_us = -(s64)TQUIC_OWD_MAX_CLOCK_SKEW_US;

	skew->last_update = ktime_get();

	/* Mark as stable after collecting enough samples */
	if (skew->sample_count >= TQUIC_OWD_MIN_SAMPLES) {
		s64 variance = 0;
		s64 mean = 0;

		/* Calculate mean */
		for (i = 0; i < skew->sample_count; i++)
			mean += skew->samples[i];
		mean /= skew->sample_count;

		/* Calculate variance */
		for (i = 0; i < skew->sample_count; i++) {
			s64 diff = skew->samples[i] - mean;
			variance += diff * diff;
		}
		variance /= skew->sample_count;
		skew->skew_variance_us = variance;

		/* Consider stable if variance is low relative to RTT */
		skew->stable = (variance < (rtt_us * rtt_us / 16));
		owd->flags |= TQUIC_OWD_FLAG_SKEW_VALID;
	}
}

bool tquic_owd_get_skew(const struct tquic_owd_state *owd, s64 *skew_us)
{
	if (!owd || !(owd->flags & TQUIC_OWD_FLAG_SKEW_VALID))
		return false;

	*skew_us = owd->skew.estimated_skew_us;
	return owd->skew.stable;
}

/*
 * =============================================================================
 * Core OWD State Management
 * =============================================================================
 */

struct tquic_owd_state *tquic_owd_state_create(struct tquic_connection *conn)
{
	struct tquic_owd_state *owd;

	owd = kzalloc(sizeof(*owd), GFP_KERNEL);
	if (!owd)
		return NULL;

	spin_lock_init(&owd->lock);
	owd->ts_records_root = RB_ROOT;
	INIT_LIST_HEAD(&owd->ts_records_list);

	/* Set default values */
	owd->local_resolution_us = TQUIC_OWD_DEFAULT_RESOLUTION_US;
	owd->effective_resolution_us = TQUIC_OWD_DEFAULT_RESOLUTION_US;
	owd->reference_time = ktime_get();
	owd->min_forward_us = S64_MAX;
	owd->min_reverse_us = S64_MAX;

	return owd;
}
EXPORT_SYMBOL_GPL(tquic_owd_state_create);

void tquic_owd_state_destroy(struct tquic_owd_state *owd)
{
	struct tquic_owd_timestamp_record *rec, *tmp;

	if (!owd)
		return;

	/* Free all timestamp records */
	list_for_each_entry_safe(rec, tmp, &owd->ts_records_list, list) {
		list_del(&rec->list);
		ts_record_free(rec);
	}

	kfree(owd);
}
EXPORT_SYMBOL_GPL(tquic_owd_state_destroy);

int tquic_owd_init(struct tquic_owd_state *owd, u64 local_resolution_us)
{
	if (!owd)
		return -EINVAL;

	/* Validate resolution */
	if (local_resolution_us < TQUIC_OWD_MIN_RESOLUTION_US ||
	    local_resolution_us > TQUIC_OWD_MAX_RESOLUTION_US)
		return -ERANGE;

	spin_lock_bh(&owd->lock);
	owd->local_resolution_us = local_resolution_us;
	owd->reference_time = ktime_get();
	spin_unlock_bh(&owd->lock);

	return 0;
}
EXPORT_SYMBOL_GPL(tquic_owd_init);

int tquic_owd_enable(struct tquic_owd_state *owd, u64 peer_resolution_us)
{
	if (!owd)
		return -EINVAL;

	/* Validate peer resolution */
	if (peer_resolution_us < TQUIC_OWD_MIN_RESOLUTION_US ||
	    peer_resolution_us > TQUIC_OWD_MAX_RESOLUTION_US)
		return -ERANGE;

	spin_lock_bh(&owd->lock);

	owd->peer_resolution_us = peer_resolution_us;

	/* Use the coarser of the two resolutions */
	owd->effective_resolution_us = max(owd->local_resolution_us,
					   peer_resolution_us);

	owd->flags |= TQUIC_OWD_FLAG_ENABLED | TQUIC_OWD_FLAG_ACTIVE;

	spin_unlock_bh(&owd->lock);

	pr_debug("tquic_owd: enabled with resolution %llu us\n",
		 owd->effective_resolution_us);

	return 0;
}
EXPORT_SYMBOL_GPL(tquic_owd_enable);

void tquic_owd_reset(struct tquic_owd_state *owd)
{
	struct tquic_owd_timestamp_record *rec, *tmp;

	if (!owd)
		return;

	spin_lock_bh(&owd->lock);

	/* Free timestamp records */
	list_for_each_entry_safe(rec, tmp, &owd->ts_records_list, list) {
		ts_record_remove(owd, rec);
		ts_record_free(rec);
	}

	/* Reset estimates but keep negotiated parameters */
	owd->forward_delay_us = 0;
	owd->reverse_delay_us = 0;
	owd->forward_delay_var_us = 0;
	owd->reverse_delay_var_us = 0;
	owd->min_forward_us = S64_MAX;
	owd->min_reverse_us = S64_MAX;
	owd->flags &= ~(TQUIC_OWD_FLAG_SKEW_VALID |
			TQUIC_OWD_FLAG_FORWARD_VALID |
			TQUIC_OWD_FLAG_REVERSE_VALID |
			TQUIC_OWD_FLAG_ASYMMETRIC);

	/* Reset skew estimator */
	memset(&owd->skew, 0, sizeof(owd->skew));

	/* Reset history */
	memset(owd->history, 0, sizeof(owd->history));
	owd->history_idx = 0;
	owd->sample_count = 0;

	/* Reset reference time */
	owd->reference_time = ktime_get();

	spin_unlock_bh(&owd->lock);
}
EXPORT_SYMBOL_GPL(tquic_owd_reset);

/*
 * =============================================================================
 * ACK_1WD Frame Encoding
 * =============================================================================
 */

int tquic_owd_encode_ack_timestamp(struct tquic_owd_state *owd,
				   ktime_t recv_time,
				   u8 *buf, size_t buf_len)
{
	u64 timestamp;

	if (!owd || !buf)
		return -EINVAL;

	if (!(owd->flags & TQUIC_OWD_FLAG_ENABLED))
		return -ENOENT;

	timestamp = tquic_owd_ktime_to_timestamp(owd, recv_time);
	owd->last_send_ts = timestamp;

	return owd_varint_encode(buf, buf_len, timestamp);
}
EXPORT_SYMBOL_GPL(tquic_owd_encode_ack_timestamp);

int tquic_owd_decode_ack_timestamp(struct tquic_owd_state *owd,
				   const u8 *buf, size_t buf_len,
				   u64 *recv_timestamp)
{
	ssize_t ret;

	if (!owd || !buf || !recv_timestamp)
		return -EINVAL;

	ret = owd_varint_decode(buf, buf_len, recv_timestamp);
	if (ret > 0)
		owd->last_recv_ts = *recv_timestamp;

	return ret;
}
EXPORT_SYMBOL_GPL(tquic_owd_decode_ack_timestamp);

int tquic_owd_generate_ack_1wd(struct tquic_owd_state *owd,
			       struct tquic_loss_state *loss,
			       int pn_space, u8 *buf, size_t buf_len,
			       bool include_ecn, ktime_t recv_time)
{
	size_t offset = 0;
	ssize_t ret;
	u64 frame_type;
	u64 timestamp;
	u64 largest_acked;
	u64 ack_delay;
	u64 first_range;
	u64 prev_smallest;
	u32 range_count;
	struct tquic_ack_range *range;

	if (!owd || !loss || !buf)
		return -EINVAL;

	if (!(owd->flags & TQUIC_OWD_FLAG_ENABLED))
		return -ENOENT;

	/* Get current time before acquiring lock to avoid ktime_get() overhead
	 * while holding spinlock, which can cause lock contention on some archs */
	timestamp = ktime_to_us(ktime_get());

	spin_lock_bh(&loss->lock);

	if (list_empty(&loss->ack_ranges[pn_space])) {
		spin_unlock_bh(&loss->lock);
		return -ENODATA;
	}

	/* Get largest acknowledged from first range */
	range = list_first_entry(&loss->ack_ranges[pn_space],
				 struct tquic_ack_range, list);
	largest_acked = range->end;
	first_range = range->end - range->start;

	/* Calculate ACK delay in microseconds */
	ack_delay = timestamp - ktime_to_us(loss->largest_received_time[pn_space]);

	/* Range count (excluding first range) */
	range_count = loss->num_ack_ranges[pn_space] - 1;

	/*
	 * ACK_1WD Frame Format (draft-huitema-quic-1wd):
	 *   Frame Type (varint): 0x1a02 or 0x1a03
	 *   Largest Acknowledged (varint)
	 *   ACK Delay (varint)
	 *   ACK Range Count (varint)
	 *   First ACK Range (varint)
	 *   [ACK Ranges...]
	 *   [ECN Counts if 0x1a03...]
	 *   Receive Timestamp (varint)  <-- Added by OWD extension
	 */

	/* Frame type */
	frame_type = include_ecn ? TQUIC_FRAME_ACK_1WD_ECN : TQUIC_FRAME_ACK_1WD;
	ret = owd_varint_encode(buf + offset, buf_len - offset, frame_type);
	if (ret < 0)
		goto out;
	offset += ret;

	/* Largest Acknowledged */
	ret = owd_varint_encode(buf + offset, buf_len - offset, largest_acked);
	if (ret < 0)
		goto out;
	offset += ret;

	/* ACK Delay (using default exponent of 3, so divide by 8) */
	ret = owd_varint_encode(buf + offset, buf_len - offset, ack_delay >> 3);
	if (ret < 0)
		goto out;
	offset += ret;

	/* ACK Range Count */
	ret = owd_varint_encode(buf + offset, buf_len - offset, range_count);
	if (ret < 0)
		goto out;
	offset += ret;

	/* First ACK Range */
	ret = owd_varint_encode(buf + offset, buf_len - offset, first_range);
	if (ret < 0)
		goto out;
	offset += ret;

	/* Additional ACK ranges */
	prev_smallest = range->start;
	list_for_each_entry_continue(range, &loss->ack_ranges[pn_space], list) {
		u64 gap = prev_smallest - range->end - 2;
		u64 range_len = range->end - range->start;

		/* Gap */
		ret = owd_varint_encode(buf + offset, buf_len - offset, gap);
		if (ret < 0)
			goto out;
		offset += ret;

		/* ACK Range Length */
		ret = owd_varint_encode(buf + offset, buf_len - offset, range_len);
		if (ret < 0)
			goto out;
		offset += ret;

		prev_smallest = range->start;
	}

	/* ECN counts if requested */
	if (include_ecn && loss->ecn_validated) {
		ret = owd_varint_encode(buf + offset, buf_len - offset,
					loss->ecn_acked.ect0);
		if (ret < 0)
			goto out;
		offset += ret;

		ret = owd_varint_encode(buf + offset, buf_len - offset,
					loss->ecn_acked.ect1);
		if (ret < 0)
			goto out;
		offset += ret;

		ret = owd_varint_encode(buf + offset, buf_len - offset,
					loss->ecn_acked.ce);
		if (ret < 0)
			goto out;
		offset += ret;
	}

	/* Encode receive timestamp at the end (OWD extension) */
	timestamp = tquic_owd_ktime_to_timestamp(owd, recv_time);
	ret = owd_varint_encode(buf + offset, buf_len - offset, timestamp);
	if (ret < 0)
		goto out;
	offset += ret;

	owd->last_send_ts = timestamp;

	spin_unlock_bh(&loss->lock);
	return offset;

out:
	spin_unlock_bh(&loss->lock);
	return ret;
}
EXPORT_SYMBOL_GPL(tquic_owd_generate_ack_1wd);

int tquic_owd_parse_ack_1wd(const u8 *buf, size_t len,
			    struct tquic_ack_1wd_frame *frame,
			    u8 ack_delay_exponent)
{
	size_t offset = 0;
	ssize_t ret;
	u64 frame_type;
	u64 range_count;
	u32 i;

	if (!buf || !frame)
		return -EINVAL;

	memset(frame, 0, sizeof(*frame));

	/* Frame type */
	ret = owd_varint_decode(buf + offset, len - offset, &frame_type);
	if (ret < 0)
		return ret;
	offset += ret;

	if (frame_type == TQUIC_FRAME_ACK_1WD_ECN)
		frame->has_ecn = true;
	else if (frame_type != TQUIC_FRAME_ACK_1WD)
		return -EINVAL;

	/* Largest Acknowledged */
	ret = owd_varint_decode(buf + offset, len - offset, &frame->largest_acked);
	if (ret < 0)
		return ret;
	offset += ret;

	/* ACK Delay */
	ret = owd_varint_decode(buf + offset, len - offset, &frame->ack_delay);
	if (ret < 0)
		return ret;
	offset += ret;
	/* Convert from encoded value to microseconds */
	frame->ack_delay = frame->ack_delay << ack_delay_exponent;

	/* ACK Range Count */
	ret = owd_varint_decode(buf + offset, len - offset, &range_count);
	if (ret < 0)
		return ret;
	offset += ret;
	frame->range_count = (u32)range_count;

	/* First ACK Range */
	ret = owd_varint_decode(buf + offset, len - offset, &frame->first_range);
	if (ret < 0)
		return ret;
	offset += ret;

	/* Additional ACK Ranges */
	for (i = 0; i < frame->range_count && i < 256; i++) {
		ret = owd_varint_decode(buf + offset, len - offset,
					&frame->ranges[i].gap);
		if (ret < 0)
			return ret;
		offset += ret;

		ret = owd_varint_decode(buf + offset, len - offset,
					&frame->ranges[i].length);
		if (ret < 0)
			return ret;
		offset += ret;
	}

	/* ECN Counts (if ACK_1WD_ECN) */
	if (frame->has_ecn) {
		ret = owd_varint_decode(buf + offset, len - offset,
					&frame->ecn.ect0);
		if (ret < 0)
			return ret;
		offset += ret;

		ret = owd_varint_decode(buf + offset, len - offset,
					&frame->ecn.ect1);
		if (ret < 0)
			return ret;
		offset += ret;

		ret = owd_varint_decode(buf + offset, len - offset,
					&frame->ecn.ce);
		if (ret < 0)
			return ret;
		offset += ret;
	}

	/* Receive Timestamp (OWD extension field) */
	ret = owd_varint_decode(buf + offset, len - offset,
				&frame->receive_timestamp);
	if (ret < 0)
		return ret;
	offset += ret;

	return offset;
}
EXPORT_SYMBOL_GPL(tquic_owd_parse_ack_1wd);

/*
 * =============================================================================
 * One-Way Delay Calculation
 * =============================================================================
 */

int tquic_owd_on_packet_sent(struct tquic_owd_state *owd, u64 pn,
			     ktime_t send_time, u32 path_id)
{
	struct tquic_owd_timestamp_record *rec;
	int ret;

	if (!owd)
		return -EINVAL;

	if (!(owd->flags & TQUIC_OWD_FLAG_ENABLED))
		return 0;  /* Not an error, just not enabled */

	rec = ts_record_alloc(pn, send_time, path_id);
	if (!rec)
		return -ENOMEM;

	spin_lock_bh(&owd->lock);

	/* Clean up old records if needed */
	if (owd->ts_records_count >= MAX_TS_RECORDS)
		ts_record_cleanup_old(owd);

	ret = ts_record_insert(owd, rec);
	if (ret < 0) {
		spin_unlock_bh(&owd->lock);
		ts_record_free(rec);
		return ret;
	}

	spin_unlock_bh(&owd->lock);
	return 0;
}
EXPORT_SYMBOL_GPL(tquic_owd_on_packet_sent);

int tquic_owd_calculate(struct tquic_owd_state *owd,
			ktime_t send_time, u64 remote_recv_ts,
			ktime_t ack_recv_time,
			struct tquic_owd_sample *sample)
{
	s64 send_time_us;
	s64 recv_time_us;
	s64 ack_recv_time_us;
	s64 skew_us = 0;
	s64 forward, reverse;
	u64 rtt_us;

	if (!owd || !sample)
		return -EINVAL;

	memset(sample, 0, sizeof(*sample));
	sample->timestamp = ack_recv_time;

	/* Convert times to microseconds */
	send_time_us = ktime_to_us(send_time);
	recv_time_us = tquic_owd_timestamp_to_us(owd, remote_recv_ts);
	ack_recv_time_us = ktime_to_us(ack_recv_time);

	/* Calculate RTT for reference */
	rtt_us = ack_recv_time_us - send_time_us;
	if (rtt_us <= 0)
		return -EINVAL;  /* Invalid timing */

	sample->rtt_us = rtt_us;

	/* Get clock skew estimate if available */
	if (owd->flags & TQUIC_OWD_FLAG_SKEW_VALID)
		skew_us = owd->skew.estimated_skew_us;

	/*
	 * Calculate forward delay (sender -> receiver):
	 * Forward = (remote_recv_time - skew) - send_time
	 *
	 * The remote recv time is in remote clock units, so we subtract
	 * the estimated skew to convert to local clock reference.
	 */
	forward = (recv_time_us - skew_us) - send_time_us;

	/*
	 * Calculate reverse delay (receiver -> sender):
	 * Reverse = ack_recv_time - (remote_recv_time - skew)
	 */
	reverse = ack_recv_time_us - (recv_time_us - skew_us);

	/*
	 * Sanity checks: one-way delays should be positive and sum to ~RTT.
	 * Allow some tolerance for clock drift and measurement noise.
	 */
	if (forward < 0) {
		/* Clock skew not well estimated, fall back to RTT/2 */
		forward = rtt_us / 2;
		reverse = rtt_us - forward;
	} else if (reverse < 0) {
		reverse = rtt_us / 2;
		forward = rtt_us - reverse;
	}

	/* Clamp to reasonable bounds */
	if (forward > (s64)rtt_us)
		forward = rtt_us;
	if (reverse > (s64)rtt_us)
		reverse = rtt_us;

	sample->forward_delay_us = forward;
	sample->reverse_delay_us = reverse;
	sample->valid = true;

	return 0;
}
EXPORT_SYMBOL_GPL(tquic_owd_calculate);

/*
 * Update smoothed OWD estimates using EWMA
 */
static void owd_update_estimates(struct tquic_owd_state *owd,
				 const struct tquic_owd_sample *sample)
{
	s64 forward_diff, reverse_diff;

	if (!sample->valid)
		return;

	/* Update minimum values */
	if (sample->forward_delay_us < owd->min_forward_us)
		owd->min_forward_us = sample->forward_delay_us;
	if (sample->reverse_delay_us < owd->min_reverse_us)
		owd->min_reverse_us = sample->reverse_delay_us;

	/* First sample initializes the estimates */
	if (owd->sample_count == 0) {
		owd->forward_delay_us = sample->forward_delay_us;
		owd->reverse_delay_us = sample->reverse_delay_us;
		owd->forward_delay_var_us = sample->forward_delay_us / 2;
		owd->reverse_delay_var_us = sample->reverse_delay_us / 2;
	} else {
		/* EWMA update: new = old + alpha * (sample - old) */
		/* Using alpha = 1/8 (shift by 3) */
		forward_diff = sample->forward_delay_us - owd->forward_delay_us;
		reverse_diff = sample->reverse_delay_us - owd->reverse_delay_us;

		owd->forward_delay_us += forward_diff >> TQUIC_OWD_ALPHA_SHIFT;
		owd->reverse_delay_us += reverse_diff >> TQUIC_OWD_ALPHA_SHIFT;

		/* Update variance (RFC 6298 style) */
		if (forward_diff < 0)
			forward_diff = -forward_diff;
		if (reverse_diff < 0)
			reverse_diff = -reverse_diff;

		owd->forward_delay_var_us +=
			((u64)forward_diff - owd->forward_delay_var_us) >> 2;
		owd->reverse_delay_var_us +=
			((u64)reverse_diff - owd->reverse_delay_var_us) >> 2;
	}

	/* Store in history */
	owd->history[owd->history_idx] = *sample;
	owd->history_idx = (owd->history_idx + 1) % TQUIC_OWD_HISTORY_SIZE;
	owd->sample_count++;

	/* Update flags */
	if (owd->sample_count >= TQUIC_OWD_MIN_SAMPLES) {
		owd->flags |= TQUIC_OWD_FLAG_FORWARD_VALID |
			      TQUIC_OWD_FLAG_REVERSE_VALID;

		/* Check for asymmetry (difference > 20% of RTT) */
		s64 diff = owd->forward_delay_us - owd->reverse_delay_us;
		if (diff < 0)
			diff = -diff;

		if (diff * 5 > (owd->forward_delay_us + owd->reverse_delay_us))
			owd->flags |= TQUIC_OWD_FLAG_ASYMMETRIC;
		else
			owd->flags &= ~TQUIC_OWD_FLAG_ASYMMETRIC;
	}
}

int tquic_owd_on_ack_1wd_received(struct tquic_owd_state *owd,
				  const struct tquic_ack_1wd_frame *frame,
				  ktime_t recv_time,
				  struct tquic_path *path)
{
	struct tquic_owd_timestamp_record *rec;
	struct tquic_owd_sample sample;
	int ret;

	if (!owd || !frame)
		return -EINVAL;

	if (!(owd->flags & TQUIC_OWD_FLAG_ENABLED))
		return 0;

	spin_lock_bh(&owd->lock);

	/* Find the send timestamp for the largest acknowledged packet */
	rec = ts_record_lookup(owd, frame->largest_acked);
	if (!rec) {
		spin_unlock_bh(&owd->lock);
		return -ENOENT;  /* No record found - packet too old */
	}

	/* Calculate one-way delays */
	ret = tquic_owd_calculate(owd, rec->send_time, frame->receive_timestamp,
				  recv_time, &sample);
	if (ret < 0) {
		spin_unlock_bh(&owd->lock);
		return ret;
	}

	sample.pn = frame->largest_acked;

	/* Update skew estimate */
	tquic_owd_update_skew(owd, recv_time,
			      tquic_owd_timestamp_to_us(owd, frame->receive_timestamp),
			      sample.rtt_us);

	/* Update smoothed estimates */
	owd_update_estimates(owd, &sample);

	/* Clean up the used timestamp record */
	ts_record_remove(owd, rec);
	ts_record_free(rec);

	spin_unlock_bh(&owd->lock);

	return 0;
}
EXPORT_SYMBOL_GPL(tquic_owd_on_ack_1wd_received);

/*
 * =============================================================================
 * OWD Query API
 * =============================================================================
 */

bool tquic_owd_get_forward_delay(const struct tquic_owd_state *owd,
				 s64 *delay_us)
{
	if (!owd || !delay_us)
		return false;

	if (!(owd->flags & TQUIC_OWD_FLAG_FORWARD_VALID))
		return false;

	*delay_us = owd->forward_delay_us;
	return true;
}
EXPORT_SYMBOL_GPL(tquic_owd_get_forward_delay);

bool tquic_owd_get_reverse_delay(const struct tquic_owd_state *owd,
				 s64 *delay_us)
{
	if (!owd || !delay_us)
		return false;

	if (!(owd->flags & TQUIC_OWD_FLAG_REVERSE_VALID))
		return false;

	*delay_us = owd->reverse_delay_us;
	return true;
}
EXPORT_SYMBOL_GPL(tquic_owd_get_reverse_delay);

bool tquic_owd_get_delays(const struct tquic_owd_state *owd,
			  s64 *forward_us, s64 *reverse_us)
{
	if (!tquic_owd_has_valid_estimates(owd))
		return false;

	if (forward_us)
		*forward_us = owd->forward_delay_us;
	if (reverse_us)
		*reverse_us = owd->reverse_delay_us;

	return true;
}
EXPORT_SYMBOL_GPL(tquic_owd_get_delays);

bool tquic_owd_get_min_delays(const struct tquic_owd_state *owd,
			      s64 *min_forward_us, s64 *min_reverse_us)
{
	if (!owd || owd->sample_count == 0)
		return false;

	if (min_forward_us)
		*min_forward_us = owd->min_forward_us;
	if (min_reverse_us)
		*min_reverse_us = owd->min_reverse_us;

	return true;
}
EXPORT_SYMBOL_GPL(tquic_owd_get_min_delays);

bool tquic_owd_is_asymmetric(const struct tquic_owd_state *owd,
			     u32 threshold_pct)
{
	s64 diff, sum;

	if (!tquic_owd_has_valid_estimates(owd))
		return false;

	diff = owd->forward_delay_us - owd->reverse_delay_us;
	if (diff < 0)
		diff = -diff;

	sum = owd->forward_delay_us + owd->reverse_delay_us;
	if (sum == 0)
		return false;

	/* Check if diff/sum * 100 > threshold_pct */
	return (diff * 100) > (sum * threshold_pct / 2);
}
EXPORT_SYMBOL_GPL(tquic_owd_is_asymmetric);

u32 tquic_owd_get_asymmetry_ratio(const struct tquic_owd_state *owd)
{
	if (!tquic_owd_has_valid_estimates(owd))
		return 1000;

	if (owd->reverse_delay_us == 0)
		return 2000;  /* Infinite forward asymmetry */

	/* Scale by 1000 to preserve precision */
	return (u32)((owd->forward_delay_us * 1000) / owd->reverse_delay_us);
}
EXPORT_SYMBOL_GPL(tquic_owd_get_asymmetry_ratio);

/*
 * =============================================================================
 * Multipath Scheduler Integration
 * =============================================================================
 */

int tquic_owd_get_path_info(struct tquic_owd_state *owd,
			    struct tquic_path *path,
			    struct tquic_owd_path_info *info)
{
	if (!owd || !path || !info)
		return -EINVAL;

	memset(info, 0, sizeof(*info));
	info->path_id = path->path_id;

	if (!tquic_owd_has_valid_estimates(owd)) {
		/* No OWD data - use RTT/2 as estimate */
		s64 half_rtt = path->stats.rtt_smoothed / 2;
		info->forward_delay_us = half_rtt;
		info->reverse_delay_us = half_rtt;
		info->asymmetry_ratio = 1000;
		info->is_asymmetric = false;
		info->confidence = 0;
		return 0;
	}

	info->forward_delay_us = owd->forward_delay_us;
	info->reverse_delay_us = owd->reverse_delay_us;
	info->asymmetry_ratio = tquic_owd_get_asymmetry_ratio(owd);
	info->is_asymmetric = (owd->flags & TQUIC_OWD_FLAG_ASYMMETRIC) != 0;

	/* Calculate confidence based on sample count and variance */
	if (owd->sample_count >= 16 && owd->skew.stable)
		info->confidence = 100;
	else if (owd->sample_count >= 8)
		info->confidence = 80;
	else if (owd->sample_count >= TQUIC_OWD_MIN_SAMPLES)
		info->confidence = 60;
	else
		info->confidence = 30;

	return 0;
}
EXPORT_SYMBOL_GPL(tquic_owd_get_path_info);

int tquic_owd_compare_paths(struct tquic_owd_state *owd,
			    struct tquic_path *path_a,
			    struct tquic_path *path_b,
			    bool prefer_forward)
{
	struct tquic_owd_path_info info_a, info_b;
	s64 delay_a, delay_b;
	int ret;

	ret = tquic_owd_get_path_info(owd, path_a, &info_a);
	if (ret < 0)
		return 0;

	ret = tquic_owd_get_path_info(owd, path_b, &info_b);
	if (ret < 0)
		return 0;

	/* Select which delay to compare based on traffic direction */
	if (prefer_forward) {
		delay_a = info_a.forward_delay_us;
		delay_b = info_b.forward_delay_us;
	} else {
		delay_a = info_a.reverse_delay_us;
		delay_b = info_b.reverse_delay_us;
	}

	/* Negative = A better, Positive = B better */
	if (delay_a < delay_b)
		return -1;
	if (delay_a > delay_b)
		return 1;
	return 0;
}
EXPORT_SYMBOL_GPL(tquic_owd_compare_paths);

/*
 * =============================================================================
 * RTT Integration
 * =============================================================================
 */

void tquic_owd_update_from_rtt(struct tquic_owd_state *owd, u64 rtt_us)
{
	if (!owd)
		return;

	/* If we don't have valid OWD estimates, use RTT/2 as approximation */
	if (!tquic_owd_has_valid_estimates(owd)) {
		owd->forward_delay_us = rtt_us / 2;
		owd->reverse_delay_us = rtt_us / 2;
	}
}
EXPORT_SYMBOL_GPL(tquic_owd_update_from_rtt);

bool tquic_owd_validate_against_rtt(struct tquic_owd_state *owd, u64 rtt_us)
{
	s64 owd_sum;
	s64 diff;

	if (!tquic_owd_has_valid_estimates(owd))
		return true;  /* Nothing to validate */

	owd_sum = owd->forward_delay_us + owd->reverse_delay_us;
	diff = owd_sum - (s64)rtt_us;
	if (diff < 0)
		diff = -diff;

	/*
	 * OWD sum should approximately equal RTT.
	 * Allow 20% tolerance for measurement noise and clock drift.
	 */
	if (diff * 5 > (s64)rtt_us) {
		pr_debug("tquic_owd: OWD sum %lld inconsistent with RTT %llu\n",
			 owd_sum, rtt_us);
		return false;
	}

	return true;
}
EXPORT_SYMBOL_GPL(tquic_owd_validate_against_rtt);

/*
 * =============================================================================
 * Statistics and Debugging
 * =============================================================================
 */

void tquic_owd_get_statistics(const struct tquic_owd_state *owd,
			      u64 *sample_count,
			      u64 *forward_var_us,
			      u64 *reverse_var_us)
{
	if (!owd)
		return;

	if (sample_count)
		*sample_count = owd->sample_count;
	if (forward_var_us)
		*forward_var_us = owd->forward_delay_var_us;
	if (reverse_var_us)
		*reverse_var_us = owd->reverse_delay_var_us;
}
EXPORT_SYMBOL_GPL(tquic_owd_get_statistics);

bool tquic_owd_get_recent_sample(const struct tquic_owd_state *owd,
				 struct tquic_owd_sample *sample)
{
	u32 idx;

	if (!owd || !sample || owd->sample_count == 0)
		return false;

	idx = (owd->history_idx + TQUIC_OWD_HISTORY_SIZE - 1) %
	      TQUIC_OWD_HISTORY_SIZE;
	*sample = owd->history[idx];

	return sample->valid;
}
EXPORT_SYMBOL_GPL(tquic_owd_get_recent_sample);

void tquic_owd_debug_print(const struct tquic_owd_state *owd,
			   const char *prefix)
{
	if (!owd) {
		pr_debug("%s: OWD state is NULL\n", prefix);
		return;
	}

	pr_debug("%s: flags=0x%x enabled=%d samples=%llu\n",
		 prefix, owd->flags,
		 !!(owd->flags & TQUIC_OWD_FLAG_ENABLED),
		 owd->sample_count);

	if (tquic_owd_has_valid_estimates(owd)) {
		pr_debug("%s: forward=%lld us reverse=%lld us asymmetry=%u\n",
			 prefix, owd->forward_delay_us, owd->reverse_delay_us,
			 tquic_owd_get_asymmetry_ratio(owd));
		pr_debug("%s: min_forward=%lld us min_reverse=%lld us\n",
			 prefix, owd->min_forward_us, owd->min_reverse_us);
	}

	if (owd->flags & TQUIC_OWD_FLAG_SKEW_VALID) {
		pr_debug("%s: clock_skew=%lld us stable=%d\n",
			 prefix, owd->skew.estimated_skew_us,
			 owd->skew.stable);
	}
}
EXPORT_SYMBOL_GPL(tquic_owd_debug_print);

/*
 * =============================================================================
 * Module Initialization
 * =============================================================================
 */

int __init tquic_owd_module_init(void)
{
	ts_record_cache = kmem_cache_create("tquic_owd_ts_record",
					    sizeof(struct tquic_owd_timestamp_record),
					    0, SLAB_HWCACHE_ALIGN, NULL);
	if (!ts_record_cache) {
		pr_err("tquic_owd: failed to create timestamp record cache\n");
		return -ENOMEM;
	}

	pr_info("tquic_owd: One-Way Delay measurement module initialized\n");
	return 0;
}

void __exit tquic_owd_module_exit(void)
{
	if (ts_record_cache)
		kmem_cache_destroy(ts_record_cache);

	pr_info("tquic_owd: One-Way Delay measurement module exited\n");
}

#ifndef TQUIC_OUT_OF_TREE
module_init(tquic_owd_module_init);
module_exit(tquic_owd_module_exit);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("TQUIC One-Way Delay Measurement Extension (draft-huitema-quic-1wd)");
MODULE_AUTHOR("Linux Foundation");
#endif
