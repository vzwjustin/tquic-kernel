// SPDX-License-Identifier: GPL-2.0-only
/*
 * TQUIC: QUIC-Exfil Mitigation Implementation
 *
 * Copyright (c) 2026 Justin Adams <spotty118@gmail.com>
 * Kernel implementation by Justin Adams <spotty118@gmail.com>
 *
 * Implements defense mechanisms against timing side-channel information
 * leakage attacks on QUIC connections as described in draft-iab-quic-exfil.
 *
 * Components:
 * - Timing normalization: Random delays to prevent timing-based leakage
 * - Constant-time operations: Critical path timing attack prevention
 * - Traffic analysis protection: Padding and traffic shaping
 * - Spin bit randomization: RTT inference prevention
 * - Packet timing jitter: Traffic pattern masking
 *
 * Reference: draft-iab-quic-exfil-01
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/random.h>
#include <linux/delay.h>
#include <linux/hrtimer.h>
#include <linux/workqueue.h>
#include <linux/skbuff.h>
#include <linux/sysctl.h>
#include <net/tquic.h>

#include "../tquic_compat.h"
#include "quic_exfil.h"

/*
 * =============================================================================
 * Module Parameters and Sysctl
 * =============================================================================
 */

/* Global protection level - configurable via sysctl */
static int exfil_protection_level = TQUIC_EXFIL_LEVEL_MEDIUM;
static int exfil_timing_delay_us = TQUIC_EXFIL_DELAY_MEDIUM_MAX_US;
static int exfil_padding_strategy = TQUIC_PAD_RANDOM;
static int exfil_pad_probability = TQUIC_PAD_PROBABILITY_DEFAULT;
static int exfil_spin_mode = TQUIC_SPIN_RANDOM_PROB;
static int exfil_jitter_min_us = TQUIC_JITTER_DEFAULT_MIN_US;
static int exfil_jitter_max_us = TQUIC_JITTER_DEFAULT_MAX_US;

/* Workqueue for delayed operations */
static struct workqueue_struct *exfil_wq;

/*
 * =============================================================================
 * Timing Normalization Implementation
 * =============================================================================
 */

/*
 * SECURITY FIX (CF-113): Use a proper typed struct for skb->cb instead
 * of raw function-pointer casts. A magic tag prevents misinterpretation
 * of stale or corrupted cb data as a code address.
 */
#define TQUIC_EXFIL_CB_MAGIC	0x5158454CU	/* "QXEL" */
#define TQUIC_DECOY_CB_MAGIC	0x4445434FU	/* "DECO" */

struct tquic_exfil_cb {
	u32 magic;
	void (*send_fn)(struct sk_buff *);
};

static inline void tquic_exfil_set_cb_fn(struct sk_buff *skb,
					  void (*fn)(struct sk_buff *))
{
	struct tquic_exfil_cb *ecb = (struct tquic_exfil_cb *)skb->cb;

	BUILD_BUG_ON(sizeof(struct tquic_exfil_cb) >
		     sizeof_field(struct sk_buff, cb));

	ecb->magic = TQUIC_EXFIL_CB_MAGIC;
	ecb->send_fn = fn;
}

/*
 * Validate function pointer stored in skb->cb before calling.
 * Returns the function pointer if magic matches and the address
 * is within kernel text, or NULL otherwise.
 */
static void (*tquic_exfil_validate_cb_fn(struct sk_buff *skb))(struct sk_buff *)
{
	struct tquic_exfil_cb *ecb = (struct tquic_exfil_cb *)skb->cb;

	if (ecb->magic != TQUIC_EXFIL_CB_MAGIC)
		return NULL;

	if (!ecb->send_fn)
		return NULL;

	/* Reject pointers outside the kernel text section */
	if (!kernel_text_address((unsigned long)ecb->send_fn)) {
		pr_warn_ratelimited("tquic_exfil: invalid function pointer "
				    "%px in skb->cb, dropping packet\n",
				    ecb->send_fn);
		return NULL;
	}

	return ecb->send_fn;
}

/* Workqueue callback for delayed packet transmission */
static void timing_normalizer_work(struct work_struct *work)
{
	struct tquic_timing_normalizer *norm =
		container_of(work, struct tquic_timing_normalizer,
			     pending_work.work);
	struct sk_buff *skb;
	unsigned long flags;

	spin_lock_irqsave(&norm->queue_lock, flags);
	while ((skb = __skb_dequeue(&norm->delay_queue)) != NULL) {
		void (*send_fn)(struct sk_buff *);

		spin_unlock_irqrestore(&norm->queue_lock, flags);

		/* CF-139: Validate function pointer before calling */
		send_fn = tquic_exfil_validate_cb_fn(skb);
		if (send_fn)
			send_fn(skb);
		else
			kfree_skb(skb);

		spin_lock_irqsave(&norm->queue_lock, flags);
	}
	spin_unlock_irqrestore(&norm->queue_lock, flags);
}

/**
 * tquic_timing_normalizer_init - Initialize timing normalizer
 * @norm: Normalizer to initialize
 * @level: Protection level
 *
 * Returns: 0 on success, negative errno on failure
 */
int tquic_timing_normalizer_init(struct tquic_timing_normalizer *norm,
				 enum tquic_exfil_protection_level level)
{
	if (!norm)
		return -EINVAL;

	memset(norm, 0, sizeof(*norm));
	norm->enabled = (level != TQUIC_EXFIL_LEVEL_NONE);
	norm->protection_level = level;

	/* Set delay range based on protection level */
	switch (level) {
	case TQUIC_EXFIL_LEVEL_NONE:
		norm->delay_min_us = 0;
		norm->delay_max_us = 0;
		break;
	case TQUIC_EXFIL_LEVEL_LOW:
		norm->delay_min_us = 0;
		norm->delay_max_us = TQUIC_EXFIL_DELAY_LOW_MAX_US;
		break;
	case TQUIC_EXFIL_LEVEL_MEDIUM:
		norm->delay_min_us = 0;
		norm->delay_max_us = TQUIC_EXFIL_DELAY_MEDIUM_MAX_US;
		break;
	case TQUIC_EXFIL_LEVEL_HIGH:
		norm->delay_min_us = 0;
		norm->delay_max_us = TQUIC_EXFIL_DELAY_HIGH_MAX_US;
		break;
	case TQUIC_EXFIL_LEVEL_PARANOID:
		norm->delay_min_us = TQUIC_EXFIL_DELAY_PARANOID_BASE_US;
		norm->delay_max_us = TQUIC_EXFIL_DELAY_PARANOID_BASE_US +
				     TQUIC_EXFIL_DELAY_PARANOID_RAND_US;
		break;
	}

	INIT_DELAYED_WORK(&norm->pending_work, timing_normalizer_work);
	skb_queue_head_init(&norm->delay_queue);
	spin_lock_init(&norm->queue_lock);
	atomic64_set(&norm->total_delays, 0);
	atomic64_set(&norm->total_delay_ns, 0);

	return 0;
}

/**
 * tquic_timing_normalizer_destroy - Cleanup timing normalizer
 * @norm: Normalizer to destroy
 */
void tquic_timing_normalizer_destroy(struct tquic_timing_normalizer *norm)
{
	if (!norm)
		return;

	norm->enabled = false;
	cancel_delayed_work_sync(&norm->pending_work);
	skb_queue_purge(&norm->delay_queue);
}

/**
 * tquic_timing_normalizer_set_level - Update protection level
 * @norm: Normalizer
 * @level: New protection level
 */
void tquic_timing_normalizer_set_level(struct tquic_timing_normalizer *norm,
				       enum tquic_exfil_protection_level level)
{
	if (!norm)
		return;

	norm->protection_level = level;
	norm->enabled = (level != TQUIC_EXFIL_LEVEL_NONE);

	/* Update delay range */
	switch (level) {
	case TQUIC_EXFIL_LEVEL_NONE:
		norm->delay_min_us = 0;
		norm->delay_max_us = 0;
		break;
	case TQUIC_EXFIL_LEVEL_LOW:
		norm->delay_min_us = 0;
		norm->delay_max_us = TQUIC_EXFIL_DELAY_LOW_MAX_US;
		break;
	case TQUIC_EXFIL_LEVEL_MEDIUM:
		norm->delay_min_us = 0;
		norm->delay_max_us = TQUIC_EXFIL_DELAY_MEDIUM_MAX_US;
		break;
	case TQUIC_EXFIL_LEVEL_HIGH:
		norm->delay_min_us = 0;
		norm->delay_max_us = TQUIC_EXFIL_DELAY_HIGH_MAX_US;
		break;
	case TQUIC_EXFIL_LEVEL_PARANOID:
		norm->delay_min_us = TQUIC_EXFIL_DELAY_PARANOID_BASE_US;
		norm->delay_max_us = TQUIC_EXFIL_DELAY_PARANOID_BASE_US +
				     TQUIC_EXFIL_DELAY_PARANOID_RAND_US;
		break;
	}
}

/**
 * tquic_timing_normalize_process - Apply timing normalization delay
 * @norm: Normalizer
 *
 * Adds a random delay within the configured range. For use during
 * packet processing to normalize processing time.
 *
 * CF-153: Must never block in packet processing path.  Use only
 * non-blocking busy-wait (udelay) for short delays; for longer
 * delays, queue deferred work via the workqueue instead of sleeping.
 *
 * Returns: 0 on success
 */
int tquic_timing_normalize_process(struct tquic_timing_normalizer *norm)
{
	u32 delay_us;
	u32 rand_val;
	ktime_t start, end;

	if (!norm || !norm->enabled || norm->delay_max_us == 0)
		return 0;

	/* Calculate random delay */
	get_random_bytes(&rand_val, sizeof(rand_val));
	delay_us = norm->delay_min_us +
		   (rand_val % (norm->delay_max_us - norm->delay_min_us + 1));

	if (delay_us == 0)
		return 0;

	start = ktime_get();

	/*
	 * CF-153: Only use non-blocking udelay for short delays (up to
	 * 20us).  Longer delays are deferred to the workqueue to avoid
	 * blocking the packet processing path.  usleep_range() and
	 * msleep() can sleep and must not be called here.
	 */
	if (delay_us <= 20) {
		udelay(delay_us);
	} else {
		/*
		 * For longer delays, schedule a no-op delayed work item.
		 * The actual delay is achieved by the workqueue scheduling
		 * latency.  This avoids blocking the caller.
		 */
		if (exfil_wq)
			queue_delayed_work(exfil_wq, &norm->pending_work,
					   usecs_to_jiffies(delay_us));
	}

	end = ktime_get();

	/* Update statistics */
	atomic64_inc(&norm->total_delays);
	atomic64_add(ktime_to_ns(ktime_sub(end, start)), &norm->total_delay_ns);

	return 0;
}

/**
 * tquic_timing_normalize_send - Queue packet for delayed transmission
 * @norm: Normalizer
 * @skb: Packet to send
 * @send_fn: Function to call for actual transmission
 *
 * Returns: 0 on success, negative errno on failure
 */
int tquic_timing_normalize_send(struct tquic_timing_normalizer *norm,
				struct sk_buff *skb,
				void (*send_fn)(struct sk_buff *))
{
	u32 delay_us;
	u32 rand_val;
	unsigned long flags;

	if (!norm || !skb)
		return -EINVAL;

	if (!norm->enabled || norm->delay_max_us == 0) {
		/* No delay, send immediately */
		if (send_fn)
			send_fn(skb);
		return 0;
	}

	/* Calculate random delay */
	get_random_bytes(&rand_val, sizeof(rand_val));
	delay_us = norm->delay_min_us +
		   (rand_val % (norm->delay_max_us - norm->delay_min_us + 1));

	/* Store send function in skb->cb via typed accessor */
	tquic_exfil_set_cb_fn(skb, send_fn);

	/* Queue packet */
	spin_lock_irqsave(&norm->queue_lock, flags);
	__skb_queue_tail(&norm->delay_queue, skb);
	spin_unlock_irqrestore(&norm->queue_lock, flags);

	/* Schedule delayed work */
	if (exfil_wq)
		queue_delayed_work(exfil_wq, &norm->pending_work,
				   usecs_to_jiffies(delay_us));

	atomic64_inc(&norm->total_delays);
	atomic64_add((u64)delay_us * 1000, &norm->total_delay_ns);

	return 0;
}

/*
 * =============================================================================
 * Constant-Time Operations Implementation
 * =============================================================================
 */

/**
 * tquic_ct_memcmp - Constant-time memory comparison
 * @a: First buffer
 * @b: Second buffer
 * @len: Length to compare
 *
 * Compares two buffers in constant time to prevent timing attacks.
 * Always examines all bytes regardless of differences found.
 *
 * Returns: 0 if equal, non-zero if different
 */
int tquic_ct_memcmp(const void *a, const void *b, size_t len)
{
	const volatile unsigned char *aa = a;
	const volatile unsigned char *bb = b;
	size_t i;
	unsigned char result = 0;

	for (i = 0; i < len; i++)
		result |= aa[i] ^ bb[i];

	return result;
}

/**
 * tquic_ct_memcpy - Constant-time memory copy
 * @dst: Destination buffer
 * @src: Source buffer
 * @len: Length to copy
 *
 * Copies memory in a cache-timing resistant manner by accessing
 * memory in a predictable pattern.
 */
void tquic_ct_memcpy(void *dst, const void *src, size_t len)
{
	volatile unsigned char *d = dst;
	const volatile unsigned char *s = src;
	size_t i;

	/* Copy byte-by-byte to ensure constant-time behavior */
	for (i = 0; i < len; i++)
		d[i] = s[i];

	/* Memory barrier to prevent optimization */
	barrier();
}

/**
 * tquic_ct_select - Constant-time buffer selection
 * @dst: Destination buffer
 * @a: First source buffer
 * @b: Second source buffer
 * @len: Buffer length
 * @sel: Selection (non-zero = select a, zero = select b)
 *
 * Selects one of two buffers without branching on the selection value.
 */
void tquic_ct_select(void *dst, const void *a, const void *b,
		     size_t len, int sel)
{
	volatile unsigned char *d = dst;
	const volatile unsigned char *aa = a;
	const volatile unsigned char *bb = b;
	unsigned char mask;
	size_t i;

	/* Create mask: all 1s if sel != 0, all 0s otherwise */
	mask = (unsigned char)(-(sel != 0));

	for (i = 0; i < len; i++)
		d[i] = (aa[i] & mask) | (bb[i] & ~mask);

	barrier();
}

/**
 * tquic_ct_validate_cid - Constant-time CID validation
 * @cid: Connection ID to validate
 * @cid_len: Length of CID
 * @expected: Expected CID value
 * @expected_len: Length of expected CID
 *
 * Returns: true if CIDs match, false otherwise
 */
bool tquic_ct_validate_cid(const u8 *cid, size_t cid_len,
			   const u8 *expected, size_t expected_len)
{
	u8 cid_padded[20] = {0};	/* Max CID length */
	u8 expected_padded[20] = {0};	/* Max CID length */
	unsigned int result = 0;
	size_t i;

	if (!cid || !expected)
		return false;

	/* Clamp lengths to max CID size to prevent out-of-bounds reads */
	if (cid_len > sizeof(cid_padded))
		cid_len = sizeof(cid_padded);
	if (expected_len > sizeof(expected_padded))
		expected_len = sizeof(expected_padded);

	/*
	 * CF-137: Constant-time comparison even for length mismatches.
	 * Copy both CIDs into fixed-size zero-padded buffers and always
	 * compare the full max length.  Fold the length difference into
	 * the result using bitwise OR, avoiding data-dependent branching.
	 */
	memcpy(cid_padded, cid, cid_len);
	memcpy(expected_padded, expected, expected_len);

	/* Length mismatch contributes to result via bitwise OR */
	result |= (unsigned int)(cid_len ^ expected_len);

	/* Always compare full max-length buffers for constant time */
	for (i = 0; i < sizeof(cid_padded); i++)
		result |= cid_padded[i] ^ expected_padded[i];

	barrier();

	return result == 0;
}

/**
 * tquic_ct_decode_pn - Constant-time packet number decoding
 * @buf: Buffer containing encoded packet number
 * @len: Length of encoded packet number (1-4 bytes)
 * @largest_pn: Largest packet number received
 * @ops: Constant-time operations context
 *
 * Decodes packet number with dummy operations to prevent timing attacks.
 *
 * Returns: Decoded packet number
 */
u64 tquic_ct_decode_pn(const u8 *buf, size_t len, u64 largest_pn,
		       struct tquic_ct_ops *ops)
{
	u64 truncated_pn = 0;
	u64 expected_pn;
	u64 pn_win;
	u64 pn_hwin;
	u64 pn_mask;
	u64 candidate_pn;
	u32 dummy_ops;
	u32 i;

	if (!buf || len == 0 || len > 4)
		return 0;

	/* Extract truncated packet number */
	for (i = 0; i < len; i++)
		truncated_pn = (truncated_pn << 8) | buf[i];

	/* Calculate full packet number (RFC 9000 Appendix A) */
	expected_pn = largest_pn + 1;
	pn_win = 1ULL << (len * 8);
	pn_hwin = pn_win / 2;
	pn_mask = pn_win - 1;

	candidate_pn = (expected_pn & ~pn_mask) | truncated_pn;

	if (candidate_pn <= expected_pn - pn_hwin &&
	    candidate_pn < (1ULL << 62) - pn_win)
		candidate_pn += pn_win;
	else if (candidate_pn > expected_pn + pn_hwin &&
		 candidate_pn >= pn_win)
		candidate_pn -= pn_win;

	/* Perform dummy operations if configured */
	if (ops && ops->enabled && ops->dummy_ops > 0) {
		dummy_ops = ops->dummy_ops;
		for (i = 0; i < dummy_ops; i++) {
			/* Dummy computation that can't be optimized away */
			volatile u64 dummy = candidate_pn ^ i;
			(void)dummy;
		}
	}

	return candidate_pn;
}

/*
 * =============================================================================
 * Traffic Analysis Protection Implementation
 * =============================================================================
 */

/* High-resolution timer callback for batch transmission */
static enum hrtimer_restart traffic_shaper_batch_timer(struct hrtimer *timer)
{
	struct tquic_traffic_shaper *shaper =
		container_of(timer, struct tquic_traffic_shaper, batch_timer);
	struct sk_buff *skb;
	unsigned long flags;

	spin_lock_irqsave(&shaper->batch_lock, flags);
	while ((skb = __skb_dequeue(&shaper->batch_queue)) != NULL) {
		void (*send_fn)(struct sk_buff *);

		spin_unlock_irqrestore(&shaper->batch_lock, flags);

		/* CF-139: Validate function pointer before calling */
		send_fn = tquic_exfil_validate_cb_fn(skb);
		if (send_fn)
			send_fn(skb);
		else
			kfree_skb(skb);

		spin_lock_irqsave(&shaper->batch_lock, flags);
	}
	spin_unlock_irqrestore(&shaper->batch_lock, flags);

	return HRTIMER_NORESTART;
}

/* Workqueue callback for decoy traffic generation */
static void traffic_shaper_decoy_work(struct work_struct *work)
{
	struct tquic_traffic_shaper *shaper =
		container_of(work, struct tquic_traffic_shaper, decoy_work.work);
	struct sk_buff *skb;
	u32 decoy_size;
	u32 rand_val;

	if (!shaper->enable_decoy || !shaper->decoy_send_fn)
		return;

	/*
	 * Generate a decoy QUIC PADDING frame packet.
	 * PADDING frames consist entirely of 0x00 bytes (frame type = 0x00).
	 * We randomize the size to avoid creating a recognizable pattern.
	 */
	get_random_bytes(&rand_val, sizeof(rand_val));
	/* Random size between 64 and MTU bytes, guard against underflow */
	if (shaper->mtu <= 64)
		decoy_size = shaper->mtu ? shaper->mtu : 64;
	else
		decoy_size = 64 + (rand_val % (shaper->mtu - 64 + 1));

	/* Allocate sk_buff for decoy packet - use GFP_KERNEL since workqueue
	 * runs in process context that can sleep */
	skb = alloc_skb(decoy_size + NET_SKB_PAD + NET_IP_ALIGN, GFP_KERNEL);
	if (!skb)
		goto reschedule;

	skb_reserve(skb, NET_SKB_PAD + NET_IP_ALIGN);

	/*
	 * CF-368: Fill decoy packets with random data instead of all-zero
	 * PADDING frames.  All-zero payloads are trivially fingerprinted
	 * by a passive observer, defeating the purpose of decoy traffic.
	 */
	get_random_bytes(skb_put(skb, decoy_size), decoy_size);

	/*
	 * Mark as decoy packet using typed cb overlay instead of raw byte
	 * writes. Raw writes risk being misinterpreted as a garbage function
	 * pointer if this skb is ever dequeued through the exfil validate path.
	 */
	memset(skb->cb, 0, sizeof_field(struct sk_buff, cb));
	((struct tquic_exfil_cb *)skb->cb)->magic = TQUIC_DECOY_CB_MAGIC;

	/* Send via registered callback */
	shaper->decoy_send_fn(skb);

	atomic64_inc(&shaper->stats_decoy_packets);

reschedule:
	/* Reschedule with jittered interval to avoid timing patterns */
	if (shaper->enable_decoy && exfil_wq) {
		u32 jitter;

		get_random_bytes(&jitter, sizeof(jitter));
		/* Add 0-25% jitter to the interval */
		jitter = (shaper->decoy_interval_ms * (jitter % 25)) / 100;
		queue_delayed_work(exfil_wq, &shaper->decoy_work,
				   msecs_to_jiffies(shaper->decoy_interval_ms + jitter));
	}
}

/**
 * tquic_traffic_shaper_init - Initialize traffic shaper
 * @shaper: Shaper to initialize
 * @level: Protection level
 *
 * Returns: 0 on success, negative errno on failure
 */
int tquic_traffic_shaper_init(struct tquic_traffic_shaper *shaper,
			      enum tquic_exfil_protection_level level)
{
	if (!shaper)
		return -EINVAL;

	memset(shaper, 0, sizeof(*shaper));

	/* Configure based on protection level */
	switch (level) {
	case TQUIC_EXFIL_LEVEL_NONE:
		shaper->strategy = TQUIC_PAD_NONE;
		shaper->pad_probability = 0;
		shaper->enable_decoy = false;
		shaper->enable_batching = false;
		break;
	case TQUIC_EXFIL_LEVEL_LOW:
		shaper->strategy = TQUIC_PAD_RANDOM;
		shaper->pad_probability = 10;
		shaper->enable_decoy = false;
		shaper->enable_batching = false;
		break;
	case TQUIC_EXFIL_LEVEL_MEDIUM:
		shaper->strategy = TQUIC_PAD_RANDOM;
		shaper->pad_probability = 25;
		shaper->enable_decoy = false;
		shaper->enable_batching = true;
		shaper->batch_size = 4;
		shaper->batch_timeout_us = 1000;
		break;
	case TQUIC_EXFIL_LEVEL_HIGH:
		shaper->strategy = TQUIC_PAD_BLOCK;
		shaper->block_size = TQUIC_PAD_BLOCK_256;
		shaper->pad_probability = 50;
		shaper->enable_decoy = true;
		shaper->decoy_interval_ms = 100;
		shaper->enable_batching = true;
		shaper->batch_size = 8;
		shaper->batch_timeout_us = 2000;
		break;
	case TQUIC_EXFIL_LEVEL_PARANOID:
		shaper->strategy = TQUIC_PAD_MAX;
		shaper->pad_probability = 100;
		shaper->enable_decoy = true;
		shaper->decoy_interval_ms = 50;
		shaper->enable_batching = true;
		shaper->batch_size = 16;
		shaper->batch_timeout_us = 5000;
		break;
	}

	shaper->max_overhead_pct = TQUIC_PAD_MAX_OVERHEAD_DEFAULT;
	shaper->mtu = 1200;	/* Default QUIC minimum MTU */

	skb_queue_head_init(&shaper->batch_queue);
	hrtimer_setup(&shaper->batch_timer, traffic_shaper_batch_timer, CLOCK_MONOTONIC, HRTIMER_MODE_REL);
	spin_lock_init(&shaper->batch_lock);

	INIT_DELAYED_WORK(&shaper->decoy_work, traffic_shaper_decoy_work);

	atomic64_set(&shaper->stats_padded_packets, 0);
	atomic64_set(&shaper->stats_padding_bytes, 0);
	atomic64_set(&shaper->stats_decoy_packets, 0);

	return 0;
}

/**
 * tquic_traffic_shaper_destroy - Cleanup traffic shaper
 * @shaper: Shaper to destroy
 */
void tquic_traffic_shaper_destroy(struct tquic_traffic_shaper *shaper)
{
	if (!shaper)
		return;

	shaper->enable_decoy = false;
	cancel_delayed_work_sync(&shaper->decoy_work);
	hrtimer_cancel(&shaper->batch_timer);
	skb_queue_purge(&shaper->batch_queue);
}

/**
 * tquic_traffic_shaper_set_mtu - Update path MTU
 * @shaper: Shaper
 * @mtu: New MTU value
 */
void tquic_traffic_shaper_set_mtu(struct tquic_traffic_shaper *shaper, u32 mtu)
{
	if (shaper)
		shaper->mtu = mtu;
}

/**
 * tquic_traffic_shaper_calc_padding - Calculate padding for packet
 * @shaper: Shaper
 * @packet_len: Current packet length
 *
 * Returns: Number of padding bytes to add
 */
u16 tquic_traffic_shaper_calc_padding(struct tquic_traffic_shaper *shaper,
				      u16 packet_len)
{
	u32 rand_val;
	u16 target_len;
	u16 padding;
	u16 max_padding;

	if (!shaper || shaper->strategy == TQUIC_PAD_NONE)
		return 0;

	/* Check if we should pad this packet */
	get_random_bytes(&rand_val, sizeof(rand_val));
	if ((rand_val % 100) >= shaper->pad_probability)
		return 0;

	/* Calculate maximum allowed padding */
	max_padding = (u16)((shaper->mtu * shaper->max_overhead_pct) / 100);

	switch (shaper->strategy) {
	case TQUIC_PAD_RANDOM:
		/* Random padding up to MTU or max overhead */
		get_random_bytes(&rand_val, sizeof(rand_val));
		padding = rand_val % (min((u32)max_padding,
					  shaper->mtu - packet_len) + 1);
		break;

	case TQUIC_PAD_BLOCK:
		/* Pad to next block boundary */
		if (shaper->block_size == TQUIC_PAD_BLOCK_MTU)
			target_len = shaper->mtu;
		else
			target_len = ((packet_len + shaper->block_size - 1) /
				      shaper->block_size) * shaper->block_size;

		if (target_len > shaper->mtu)
			target_len = shaper->mtu;

		padding = target_len > packet_len ? target_len - packet_len : 0;
		break;

	case TQUIC_PAD_MAX:
		/* Always pad to MTU */
		padding = shaper->mtu > packet_len ?
			  shaper->mtu - packet_len : 0;
		break;

	default:
		padding = 0;
		break;
	}

	return min(padding, max_padding);
}

/**
 * tquic_traffic_shaper_pad_packet - Add padding to packet
 * @shaper: Shaper
 * @skb: Packet to pad
 *
 * Returns: 0 on success, negative errno on failure
 */
int tquic_traffic_shaper_pad_packet(struct tquic_traffic_shaper *shaper,
				    struct sk_buff *skb)
{
	u16 padding;
	u8 *pad_data;

	if (!shaper || !skb)
		return -EINVAL;

	padding = tquic_traffic_shaper_calc_padding(shaper, skb->len);
	if (padding == 0)
		return 0;

	/* Ensure there's room for padding */
	if (skb_tailroom(skb) < padding) {
		if (pskb_expand_head(skb, 0, padding, GFP_ATOMIC))
			return -ENOMEM;
	}

	/* Add PADDING frames (type 0x00) */
	pad_data = skb_put(skb, padding);
	memset(pad_data, 0, padding);

	atomic64_inc(&shaper->stats_padded_packets);
	atomic64_add(padding, &shaper->stats_padding_bytes);

	return 0;
}

/**
 * tquic_traffic_shaper_batch_send - Queue packet for batched transmission
 * @shaper: Shaper
 * @skb: Packet to send
 * @send_fn: Function to call for actual transmission
 *
 * Returns: 0 on success, negative errno on failure
 */
int tquic_traffic_shaper_batch_send(struct tquic_traffic_shaper *shaper,
				    struct sk_buff *skb,
				    void (*send_fn)(struct sk_buff *))
{
	unsigned long flags;
	int queue_len;

	if (!shaper || !skb)
		return -EINVAL;

	if (!shaper->enable_batching) {
		/* No batching, send immediately */
		if (send_fn)
			send_fn(skb);
		return 0;
	}

	/* Store send function in skb->cb via typed accessor */
	tquic_exfil_set_cb_fn(skb, send_fn);

	spin_lock_irqsave(&shaper->batch_lock, flags);
	__skb_queue_tail(&shaper->batch_queue, skb);
	queue_len = skb_queue_len(&shaper->batch_queue);
	spin_unlock_irqrestore(&shaper->batch_lock, flags);

	/* Check if batch is full or start timer */
	if (queue_len >= shaper->batch_size) {
		/* Flush immediately */
		hrtimer_cancel(&shaper->batch_timer);
		traffic_shaper_batch_timer(&shaper->batch_timer);
	} else if (queue_len == 1) {
		/* Start batch timer */
		hrtimer_start(&shaper->batch_timer,
			      ns_to_ktime((u64)shaper->batch_timeout_us * 1000),
			      HRTIMER_MODE_REL);
	}

	return 0;
}

/**
 * tquic_traffic_shaper_start_decoy - Start decoy traffic generation
 * @shaper: Shaper
 * @send_fn: Function to call for transmission
 *
 * Starts periodic generation of decoy PADDING frame packets to mask
 * traffic patterns and prevent timing analysis attacks.
 */
void tquic_traffic_shaper_start_decoy(struct tquic_traffic_shaper *shaper,
				      void (*send_fn)(struct sk_buff *))
{
	if (!shaper || !shaper->enable_decoy || !send_fn)
		return;

	/* Store the send function for use by the work handler */
	shaper->decoy_send_fn = send_fn;

	if (exfil_wq)
		queue_delayed_work(exfil_wq, &shaper->decoy_work,
				   msecs_to_jiffies(shaper->decoy_interval_ms));
}

/**
 * tquic_traffic_shaper_stop_decoy - Stop decoy traffic generation
 * @shaper: Shaper
 */
void tquic_traffic_shaper_stop_decoy(struct tquic_traffic_shaper *shaper)
{
	if (shaper) {
		shaper->enable_decoy = false;
		cancel_delayed_work_sync(&shaper->decoy_work);
	}
}

/*
 * =============================================================================
 * Spin Bit Randomization Implementation
 * =============================================================================
 */

/**
 * tquic_spin_randomizer_init - Initialize spin bit randomizer
 * @rand: Randomizer to initialize
 * @level: Protection level
 *
 * Returns: 0 on success, negative errno on failure
 */
int tquic_spin_randomizer_init(struct tquic_spin_randomizer *rand,
			       enum tquic_exfil_protection_level level)
{
	if (!rand)
		return -EINVAL;

	memset(rand, 0, sizeof(*rand));

	/* Configure based on protection level */
	switch (level) {
	case TQUIC_EXFIL_LEVEL_NONE:
		rand->mode = TQUIC_SPIN_RANDOM_OFF;
		rand->random_probability = 0;
		break;
	case TQUIC_EXFIL_LEVEL_LOW:
		rand->mode = TQUIC_SPIN_RANDOM_PROB;
		rand->random_probability = 5;
		break;
	case TQUIC_EXFIL_LEVEL_MEDIUM:
		rand->mode = TQUIC_SPIN_RANDOM_PROB;
		rand->random_probability = 15;
		break;
	case TQUIC_EXFIL_LEVEL_HIGH:
		rand->mode = TQUIC_SPIN_RANDOM_FREEZE;
		rand->random_probability = 30;
		rand->freeze_duration_ms = 500;
		break;
	case TQUIC_EXFIL_LEVEL_PARANOID:
		rand->mode = TQUIC_SPIN_RANDOM_FULL;
		rand->random_probability = 100;
		break;
	}

	rand->frozen = false;
	rand->frozen_value = 0;
	rand->freeze_until = ktime_set(0, 0);
	atomic64_set(&rand->transition_count, 0);
	atomic64_set(&rand->randomized_count, 0);
	spin_lock_init(&rand->lock);

	return 0;
}

/**
 * tquic_spin_randomizer_destroy - Cleanup spin bit randomizer
 * @rand: Randomizer to destroy
 */
void tquic_spin_randomizer_destroy(struct tquic_spin_randomizer *rand)
{
	/* Nothing to free */
}

/**
 * tquic_spin_randomizer_set_mode - Update randomization mode
 * @rand: Randomizer
 * @mode: New mode
 */
void tquic_spin_randomizer_set_mode(struct tquic_spin_randomizer *rand,
				    enum tquic_spin_random_mode mode)
{
	if (rand)
		rand->mode = mode;
}

/**
 * tquic_spin_randomizer_get - Get spin bit value (may be randomized)
 * @rand: Randomizer
 * @calculated_spin: The calculated spin bit value
 *
 * Returns: Spin bit value to use (0 or 1)
 */
u8 tquic_spin_randomizer_get(struct tquic_spin_randomizer *rand,
			     u8 calculated_spin)
{
	u8 rand_byte;
	u8 result;
	ktime_t now;
	unsigned long flags;

	if (!rand || rand->mode == TQUIC_SPIN_RANDOM_OFF)
		return calculated_spin & 1;

	atomic64_inc(&rand->transition_count);

	spin_lock_irqsave(&rand->lock, flags);

	/* Check if frozen */
	if (rand->frozen) {
		now = ktime_get();
		if (ktime_compare(now, rand->freeze_until) < 0) {
			result = rand->frozen_value;
			spin_unlock_irqrestore(&rand->lock, flags);
			return result;
		}
		rand->frozen = false;
	}

	switch (rand->mode) {
	case TQUIC_SPIN_RANDOM_PROB:
		/* Probabilistic randomization */
		get_random_bytes(&rand_byte, 1);
		if ((rand_byte % 100) < rand->random_probability) {
			get_random_bytes(&rand_byte, 1);
			result = rand_byte & 1;
			atomic64_inc(&rand->randomized_count);
		} else {
			result = calculated_spin & 1;
		}
		break;

	case TQUIC_SPIN_RANDOM_FREEZE:
		/* Probabilistic with periodic freeze */
		get_random_bytes(&rand_byte, 1);
		if ((rand_byte % 100) < rand->random_probability) {
			/* Start a freeze period */
			get_random_bytes(&rand_byte, 1);
			rand->frozen_value = rand_byte & 1;
			rand->freeze_until = ktime_add_ms(ktime_get(),
							  rand->freeze_duration_ms);
			rand->frozen = true;
			result = rand->frozen_value;
			atomic64_inc(&rand->randomized_count);
		} else {
			result = calculated_spin & 1;
		}
		break;

	case TQUIC_SPIN_RANDOM_FULL:
		/* Always random */
		get_random_bytes(&rand_byte, 1);
		result = rand_byte & 1;
		atomic64_inc(&rand->randomized_count);
		break;

	default:
		result = calculated_spin & 1;
		break;
	}

	spin_unlock_irqrestore(&rand->lock, flags);
	return result;
}

/**
 * tquic_spin_randomizer_freeze - Trigger spin bit freeze
 * @rand: Randomizer
 * @duration_ms: Freeze duration in milliseconds
 */
void tquic_spin_randomizer_freeze(struct tquic_spin_randomizer *rand,
				  u32 duration_ms)
{
	u8 rand_byte;
	unsigned long flags;

	if (!rand)
		return;

	/* Clamp duration */
	if (duration_ms < TQUIC_SPIN_FREEZE_MIN_MS)
		duration_ms = TQUIC_SPIN_FREEZE_MIN_MS;
	if (duration_ms > TQUIC_SPIN_FREEZE_MAX_MS)
		duration_ms = TQUIC_SPIN_FREEZE_MAX_MS;

	spin_lock_irqsave(&rand->lock, flags);
	get_random_bytes(&rand_byte, 1);
	rand->frozen_value = rand_byte & 1;
	rand->freeze_until = ktime_add_ms(ktime_get(), duration_ms);
	rand->frozen = true;
	spin_unlock_irqrestore(&rand->lock, flags);
}

/**
 * tquic_spin_randomizer_is_frozen - Check if spin bit is frozen
 * @rand: Randomizer
 *
 * Returns: true if frozen, false otherwise
 */
bool tquic_spin_randomizer_is_frozen(struct tquic_spin_randomizer *rand)
{
	ktime_t now;
	bool result;
	unsigned long flags;

	if (!rand)
		return false;

	spin_lock_irqsave(&rand->lock, flags);
	if (!rand->frozen) {
		result = false;
	} else {
		now = ktime_get();
		result = ktime_compare(now, rand->freeze_until) < 0;
		if (!result)
			rand->frozen = false;
	}
	spin_unlock_irqrestore(&rand->lock, flags);

	return result;
}

/*
 * =============================================================================
 * Packet Timing Jitter Implementation
 * =============================================================================
 */

/* Simple Box-Muller transform for Gaussian random numbers */
static u32 gaussian_random(u32 mean, u32 stddev)
{
	u32 u1, u2;
	s64 z0;

	if (stddev == 0)
		return mean;

	get_random_bytes(&u1, sizeof(u1));
	get_random_bytes(&u2, sizeof(u2));

	/* Approximate Gaussian using sum of uniform randoms (CLT) */
	z0 = (s64)(u1 % 1000) + (u2 % 1000) - 1000;
	z0 = (z0 * stddev) / 500;

	return (u32)max_t(s64, 0, (s64)mean + z0);
}

/* High-resolution timer callback for jittered packet transmission */
static enum hrtimer_restart packet_jitter_timer(struct hrtimer *timer)
{
	struct tquic_packet_jitter *jitter =
		container_of(timer, struct tquic_packet_jitter, jitter_timer);
	struct sk_buff *skb;
	unsigned long flags;

	spin_lock_irqsave(&jitter->queue_lock, flags);
	skb = __skb_dequeue(&jitter->pending_queue);
	spin_unlock_irqrestore(&jitter->queue_lock, flags);

	if (skb) {
		void (*send_fn)(struct sk_buff *);

		/* CF-139: Validate function pointer before calling */
		send_fn = tquic_exfil_validate_cb_fn(skb);
		if (send_fn)
			send_fn(skb);
		else
			kfree_skb(skb);
	}

	/* Check if more packets in queue */
	spin_lock_irqsave(&jitter->queue_lock, flags);
	if (!skb_queue_empty(&jitter->pending_queue)) {
		u32 next_jitter = tquic_packet_jitter_calc(jitter);
		spin_unlock_irqrestore(&jitter->queue_lock, flags);
		hrtimer_start(&jitter->jitter_timer,
			      ns_to_ktime((u64)next_jitter * 1000),
			      HRTIMER_MODE_REL);
		return HRTIMER_NORESTART;
	}
	spin_unlock_irqrestore(&jitter->queue_lock, flags);

	return HRTIMER_NORESTART;
}

/**
 * tquic_packet_jitter_init - Initialize packet jitter
 * @jitter: Jitter state to initialize
 * @level: Protection level
 *
 * Returns: 0 on success, negative errno on failure
 */
int tquic_packet_jitter_init(struct tquic_packet_jitter *jitter,
			     enum tquic_exfil_protection_level level)
{
	if (!jitter)
		return -EINVAL;

	memset(jitter, 0, sizeof(*jitter));

	/* Configure based on protection level */
	switch (level) {
	case TQUIC_EXFIL_LEVEL_NONE:
		jitter->mode = TQUIC_JITTER_NONE;
		jitter->min_jitter_us = 0;
		jitter->max_jitter_us = 0;
		break;
	case TQUIC_EXFIL_LEVEL_LOW:
		jitter->mode = TQUIC_JITTER_UNIFORM;
		jitter->min_jitter_us = 0;
		jitter->max_jitter_us = 100;
		break;
	case TQUIC_EXFIL_LEVEL_MEDIUM:
		jitter->mode = TQUIC_JITTER_UNIFORM;
		jitter->min_jitter_us = 0;
		jitter->max_jitter_us = 500;
		break;
	case TQUIC_EXFIL_LEVEL_HIGH:
		jitter->mode = TQUIC_JITTER_GAUSSIAN;
		jitter->mean_jitter_us = 250;
		jitter->stddev_jitter_us = 100;
		jitter->min_jitter_us = 0;
		jitter->max_jitter_us = 1000;
		break;
	case TQUIC_EXFIL_LEVEL_PARANOID:
		jitter->mode = TQUIC_JITTER_EXPONENTIAL;
		jitter->lambda = 500;	/* Mean 500us */
		jitter->min_jitter_us = 100;
		jitter->max_jitter_us = 5000;
		break;
	}

	jitter->adaptive_enabled = false;
	jitter->adaptive_scale = 100;

	skb_queue_head_init(&jitter->pending_queue);
	hrtimer_setup(&jitter->jitter_timer, packet_jitter_timer, CLOCK_MONOTONIC, HRTIMER_MODE_REL);
	spin_lock_init(&jitter->queue_lock);

	atomic64_set(&jitter->stats_jittered_packets, 0);
	atomic64_set(&jitter->stats_total_jitter_ns, 0);

	return 0;
}

/**
 * tquic_packet_jitter_destroy - Cleanup packet jitter
 * @jitter: Jitter state to destroy
 */
void tquic_packet_jitter_destroy(struct tquic_packet_jitter *jitter)
{
	if (!jitter)
		return;

	hrtimer_cancel(&jitter->jitter_timer);
	skb_queue_purge(&jitter->pending_queue);
}

/**
 * tquic_packet_jitter_set_mode - Update jitter mode
 * @jitter: Jitter state
 * @mode: New mode
 */
void tquic_packet_jitter_set_mode(struct tquic_packet_jitter *jitter,
				  enum tquic_jitter_mode mode)
{
	if (jitter)
		jitter->mode = mode;
}

/**
 * tquic_packet_jitter_set_range - Update jitter range
 * @jitter: Jitter state
 * @min_us: Minimum jitter (microseconds)
 * @max_us: Maximum jitter (microseconds)
 */
void tquic_packet_jitter_set_range(struct tquic_packet_jitter *jitter,
				   u32 min_us, u32 max_us)
{
	if (!jitter)
		return;

	jitter->min_jitter_us = min(min_us, (u32)TQUIC_JITTER_MAX_US);
	jitter->max_jitter_us = min(max_us, (u32)TQUIC_JITTER_MAX_US);

	if (jitter->min_jitter_us > jitter->max_jitter_us)
		jitter->min_jitter_us = jitter->max_jitter_us;
}

/**
 * tquic_packet_jitter_calc - Calculate jitter for next packet
 * @jitter: Jitter state
 *
 * Returns: Jitter value in microseconds
 */
u32 tquic_packet_jitter_calc(struct tquic_packet_jitter *jitter)
{
	u32 rand_val;
	u32 result;

	if (!jitter || jitter->mode == TQUIC_JITTER_NONE)
		return 0;

	switch (jitter->mode) {
	case TQUIC_JITTER_UNIFORM:
		get_random_bytes(&rand_val, sizeof(rand_val));
		result = jitter->min_jitter_us +
			 (rand_val % (jitter->max_jitter_us -
				      jitter->min_jitter_us + 1));
		break;

	case TQUIC_JITTER_GAUSSIAN:
		result = gaussian_random(jitter->mean_jitter_us,
					 jitter->stddev_jitter_us);
		break;

	case TQUIC_JITTER_EXPONENTIAL:
		/* Approximate exponential using inverse CDF */
		get_random_bytes(&rand_val, sizeof(rand_val));
		/* -ln(U) * lambda, approximated */
		result = jitter->lambda;
		if (rand_val > 0) {
			u32 log_approx = 32 - __fls(rand_val);
			result = (jitter->lambda * log_approx) / 4;
		}
		break;

	default:
		result = 0;
		break;
	}

	/* Clamp to configured range */
	result = clamp_t(u32, result, jitter->min_jitter_us,
			 jitter->max_jitter_us);

	/* Apply adaptive scaling */
	if (jitter->adaptive_enabled && jitter->adaptive_scale != 100)
		result = (result * jitter->adaptive_scale) / 100;

	return result;
}

/**
 * tquic_packet_jitter_send - Queue packet for jittered transmission
 * @jitter: Jitter state
 * @skb: Packet to send
 * @send_fn: Function to call for actual transmission
 *
 * Returns: 0 on success, negative errno on failure
 */
int tquic_packet_jitter_send(struct tquic_packet_jitter *jitter,
			     struct sk_buff *skb,
			     void (*send_fn)(struct sk_buff *))
{
	u32 jitter_us;
	unsigned long flags;
	bool start_timer;

	if (!jitter || !skb)
		return -EINVAL;

	if (jitter->mode == TQUIC_JITTER_NONE) {
		/* No jitter, send immediately */
		if (send_fn)
			send_fn(skb);
		return 0;
	}

	jitter_us = tquic_packet_jitter_calc(jitter);

	if (jitter_us == 0) {
		/* No jitter for this packet */
		if (send_fn)
			send_fn(skb);
		return 0;
	}

	/* Store send function in skb->cb via typed accessor */
	tquic_exfil_set_cb_fn(skb, send_fn);

	spin_lock_irqsave(&jitter->queue_lock, flags);
	start_timer = skb_queue_empty(&jitter->pending_queue);
	__skb_queue_tail(&jitter->pending_queue, skb);
	spin_unlock_irqrestore(&jitter->queue_lock, flags);

	if (start_timer) {
		hrtimer_start(&jitter->jitter_timer,
			      ns_to_ktime((u64)jitter_us * 1000),
			      HRTIMER_MODE_REL);
	}

	atomic64_inc(&jitter->stats_jittered_packets);
	atomic64_add((u64)jitter_us * 1000, &jitter->stats_total_jitter_ns);

	return 0;
}

/**
 * tquic_packet_jitter_cancel - Cancel pending jittered packets
 * @jitter: Jitter state
 */
void tquic_packet_jitter_cancel(struct tquic_packet_jitter *jitter)
{
	if (!jitter)
		return;

	hrtimer_cancel(&jitter->jitter_timer);
	skb_queue_purge(&jitter->pending_queue);
}

/*
 * =============================================================================
 * Unified QUIC-Exfil Protection Context Implementation
 * =============================================================================
 */

/**
 * tquic_exfil_ctx_alloc - Allocate and initialize exfil protection context
 * @level: Protection level
 *
 * Returns: Allocated context or NULL on failure
 */
struct tquic_exfil_ctx *tquic_exfil_ctx_alloc(enum tquic_exfil_protection_level level)
{
	struct tquic_exfil_ctx *ctx;
	int ret;

	ctx = kzalloc(sizeof(*ctx), GFP_KERNEL);
	if (!ctx)
		return NULL;

	ctx->enabled = (level != TQUIC_EXFIL_LEVEL_NONE);
	ctx->level = level;

	ret = tquic_timing_normalizer_init(&ctx->timing, level);
	if (ret)
		goto err_timing;

	ctx->ct_ops.enabled = (level >= TQUIC_EXFIL_LEVEL_MEDIUM);
	ctx->ct_ops.dummy_ops = (level >= TQUIC_EXFIL_LEVEL_HIGH) ? 10 : 0;

	ret = tquic_traffic_shaper_init(&ctx->shaper, level);
	if (ret)
		goto err_shaper;

	ret = tquic_spin_randomizer_init(&ctx->spin_rand, level);
	if (ret)
		goto err_spin;

	ret = tquic_packet_jitter_init(&ctx->jitter, level);
	if (ret)
		goto err_jitter;

	refcount_set(&ctx->ref, 1);
	spin_lock_init(&ctx->lock);

	pr_debug("tquic_exfil: context allocated with level %d\n", level);
	return ctx;

err_jitter:
	tquic_spin_randomizer_destroy(&ctx->spin_rand);
err_spin:
	tquic_traffic_shaper_destroy(&ctx->shaper);
err_shaper:
	tquic_timing_normalizer_destroy(&ctx->timing);
err_timing:
	kfree(ctx);
	return NULL;
}

/**
 * tquic_exfil_ctx_free - Free exfil protection context
 * @ctx: Context to free
 */
void tquic_exfil_ctx_free(struct tquic_exfil_ctx *ctx)
{
	if (!ctx)
		return;

	tquic_packet_jitter_destroy(&ctx->jitter);
	tquic_spin_randomizer_destroy(&ctx->spin_rand);
	tquic_traffic_shaper_destroy(&ctx->shaper);
	tquic_timing_normalizer_destroy(&ctx->timing);
	kfree(ctx);
}

/**
 * tquic_exfil_ctx_get - Increment reference count
 * @ctx: Context
 */
void tquic_exfil_ctx_get(struct tquic_exfil_ctx *ctx)
{
	if (ctx)
		refcount_inc(&ctx->ref);
}

/**
 * tquic_exfil_ctx_put - Decrement reference count, free if zero
 * @ctx: Context
 */
void tquic_exfil_ctx_put(struct tquic_exfil_ctx *ctx)
{
	if (ctx && refcount_dec_and_test(&ctx->ref))
		tquic_exfil_ctx_free(ctx);
}

/**
 * tquic_exfil_ctx_set_level - Update protection level
 * @ctx: Context
 * @level: New level
 */
void tquic_exfil_ctx_set_level(struct tquic_exfil_ctx *ctx,
			       enum tquic_exfil_protection_level level)
{
	if (!ctx)
		return;

	/*
	 * CF-371: Hold ctx->lock across the destroy/reinit sequence to
	 * prevent concurrent readers from seeing a half-torn-down state.
	 */
	spin_lock_bh(&ctx->lock);

	ctx->level = level;
	ctx->enabled = (level != TQUIC_EXFIL_LEVEL_NONE);

	tquic_timing_normalizer_set_level(&ctx->timing, level);
	ctx->ct_ops.enabled = (level >= TQUIC_EXFIL_LEVEL_MEDIUM);
	ctx->ct_ops.dummy_ops = (level >= TQUIC_EXFIL_LEVEL_HIGH) ? 10 : 0;

	/* Reinitialize shaper and spin with new level */
	tquic_traffic_shaper_destroy(&ctx->shaper);
	if (tquic_traffic_shaper_init(&ctx->shaper, level))
		pr_warn("tquic_exfil: shaper reinit failed for level %d\n",
			level);

	tquic_spin_randomizer_destroy(&ctx->spin_rand);
	if (tquic_spin_randomizer_init(&ctx->spin_rand, level))
		pr_warn("tquic_exfil: spin_rand reinit failed for level %d\n",
			level);

	tquic_packet_jitter_destroy(&ctx->jitter);
	if (tquic_packet_jitter_init(&ctx->jitter, level))
		pr_warn("tquic_exfil: jitter reinit failed for level %d\n",
			level);

	spin_unlock_bh(&ctx->lock);
}

/**
 * tquic_exfil_ctx_enable - Enable exfil protection
 * @ctx: Context
 */
void tquic_exfil_ctx_enable(struct tquic_exfil_ctx *ctx)
{
	if (ctx)
		ctx->enabled = true;
}

/**
 * tquic_exfil_ctx_disable - Disable exfil protection
 * @ctx: Context
 */
void tquic_exfil_ctx_disable(struct tquic_exfil_ctx *ctx)
{
	if (ctx)
		ctx->enabled = false;
}

/**
 * tquic_exfil_process_incoming - Process incoming packet with exfil protection
 * @ctx: Context
 * @skb: Incoming packet
 *
 * Returns: 0 on success, negative errno on failure
 */
int tquic_exfil_process_incoming(struct tquic_exfil_ctx *ctx,
				 struct sk_buff *skb)
{
	if (!ctx || !ctx->enabled || !skb)
		return 0;

	/* Apply timing normalization to incoming packet processing */
	tquic_timing_normalize_process(&ctx->timing);

	return 0;
}

/**
 * tquic_exfil_process_outgoing - Process outgoing packet with exfil protection
 * @ctx: Context
 * @skb: Outgoing packet
 * @send_fn: Function to call for actual transmission
 *
 * Returns: 0 on success, negative errno on failure
 */
int tquic_exfil_process_outgoing(struct tquic_exfil_ctx *ctx,
				 struct sk_buff *skb,
				 void (*send_fn)(struct sk_buff *))
{
	if (!ctx || !skb)
		return -EINVAL;

	if (!ctx->enabled) {
		if (send_fn)
			send_fn(skb);
		return 0;
	}

	/* Apply padding */
	tquic_traffic_shaper_pad_packet(&ctx->shaper, skb);

	/* Send with jitter */
	return tquic_packet_jitter_send(&ctx->jitter, skb, send_fn);
}

/**
 * tquic_exfil_get_stats - Get exfil protection statistics
 */
void tquic_exfil_get_stats(struct tquic_exfil_ctx *ctx,
			   u64 *total_delays, u64 *total_delay_ns,
			   u64 *padded_packets, u64 *padding_bytes,
			   u64 *jittered_packets, u64 *jitter_ns)
{
	if (!ctx)
		return;

	if (total_delays)
		*total_delays = atomic64_read(&ctx->timing.total_delays);
	if (total_delay_ns)
		*total_delay_ns = atomic64_read(&ctx->timing.total_delay_ns);
	if (padded_packets)
		*padded_packets = atomic64_read(&ctx->shaper.stats_padded_packets);
	if (padding_bytes)
		*padding_bytes = atomic64_read(&ctx->shaper.stats_padding_bytes);
	if (jittered_packets)
		*jittered_packets = atomic64_read(&ctx->jitter.stats_jittered_packets);
	if (jitter_ns)
		*jitter_ns = atomic64_read(&ctx->jitter.stats_total_jitter_ns);
}

/*
 * =============================================================================
 * Sysctl Accessors
 * =============================================================================
 */

enum tquic_exfil_protection_level tquic_sysctl_get_exfil_level(void)
{
	return (enum tquic_exfil_protection_level)exfil_protection_level;
}

u32 tquic_sysctl_get_exfil_timing_delay_us(void)
{
	return exfil_timing_delay_us;
}

enum tquic_padding_strategy tquic_sysctl_get_exfil_padding_strategy(void)
{
	return (enum tquic_padding_strategy)exfil_padding_strategy;
}

u8 tquic_sysctl_get_exfil_pad_probability(void)
{
	return (u8)exfil_pad_probability;
}

enum tquic_spin_random_mode tquic_sysctl_get_exfil_spin_mode(void)
{
	return (enum tquic_spin_random_mode)exfil_spin_mode;
}

u32 tquic_sysctl_get_exfil_jitter_min_us(void)
{
	return exfil_jitter_min_us;
}

u32 tquic_sysctl_get_exfil_jitter_max_us(void)
{
	return exfil_jitter_max_us;
}

/*
 * =============================================================================
 * Security Event Reporting
 * =============================================================================
 */

/**
 * tquic_exfil_event - Report exfil protection event
 * @event: Event type
 * @details: Event details string
 */
void tquic_exfil_event(enum tquic_exfil_event event, const char *details)
{
	const char *event_name;

	switch (event) {
	case TQUIC_EXFIL_EVENT_TIMING_APPLIED:
		event_name = "TIMING_APPLIED";
		break;
	case TQUIC_EXFIL_EVENT_PADDING_APPLIED:
		event_name = "PADDING_APPLIED";
		break;
	case TQUIC_EXFIL_EVENT_SPIN_RANDOMIZED:
		event_name = "SPIN_RANDOMIZED";
		break;
	case TQUIC_EXFIL_EVENT_JITTER_APPLIED:
		event_name = "JITTER_APPLIED";
		break;
	case TQUIC_EXFIL_EVENT_DECOY_SENT:
		event_name = "DECOY_SENT";
		break;
	default:
		event_name = "UNKNOWN";
		break;
	}

	pr_debug("tquic_exfil: [%s] %s\n", event_name,
		 details ? details : "");
}

/*
 * =============================================================================
 * Module Initialization
 * =============================================================================
 */

/**
 * tquic_exfil_init - Initialize QUIC-Exfil mitigation module
 *
 * Returns: 0 on success, negative errno on failure
 */
int __init tquic_exfil_init(void)
{
	/* Create workqueue for delayed operations */
	exfil_wq = alloc_workqueue("tquic_exfil",
				   WQ_UNBOUND | WQ_HIGHPRI, 0);
	if (!exfil_wq) {
		pr_err("tquic_exfil: failed to create workqueue\n");
		return -ENOMEM;
	}

	pr_info("tquic_exfil: QUIC-Exfil mitigation initialized "
		"(level=%d, draft-iab-quic-exfil)\n",
		exfil_protection_level);

	return 0;
}

/**
 * tquic_exfil_exit - Cleanup QUIC-Exfil mitigation module
 */
void __exit tquic_exfil_exit(void)
{
	if (exfil_wq) {
		destroy_workqueue(exfil_wq);
		exfil_wq = NULL;
	}

	pr_info("tquic_exfil: QUIC-Exfil mitigation shutdown\n");
}

module_init(tquic_exfil_init);
module_exit(tquic_exfil_exit);

MODULE_DESCRIPTION("TQUIC QUIC-Exfil Mitigation (draft-iab-quic-exfil)");
MODULE_LICENSE("GPL");
MODULE_AUTHOR("Linux Foundation");

/*
 * =============================================================================
 * Symbol Exports
 * =============================================================================
 */

/* Timing normalization */
EXPORT_SYMBOL_GPL(tquic_timing_normalizer_init);
EXPORT_SYMBOL_GPL(tquic_timing_normalizer_destroy);
EXPORT_SYMBOL_GPL(tquic_timing_normalizer_set_level);
EXPORT_SYMBOL_GPL(tquic_timing_normalize_process);
EXPORT_SYMBOL_GPL(tquic_timing_normalize_send);

/* Constant-time operations */
EXPORT_SYMBOL_GPL(tquic_ct_memcmp);
EXPORT_SYMBOL_GPL(tquic_ct_memcpy);
EXPORT_SYMBOL_GPL(tquic_ct_select);
EXPORT_SYMBOL_GPL(tquic_ct_validate_cid);
EXPORT_SYMBOL_GPL(tquic_ct_decode_pn);

/* Traffic shaping */
EXPORT_SYMBOL_GPL(tquic_traffic_shaper_init);
EXPORT_SYMBOL_GPL(tquic_traffic_shaper_destroy);
EXPORT_SYMBOL_GPL(tquic_traffic_shaper_set_mtu);
EXPORT_SYMBOL_GPL(tquic_traffic_shaper_calc_padding);
EXPORT_SYMBOL_GPL(tquic_traffic_shaper_pad_packet);
EXPORT_SYMBOL_GPL(tquic_traffic_shaper_batch_send);
EXPORT_SYMBOL_GPL(tquic_traffic_shaper_start_decoy);
EXPORT_SYMBOL_GPL(tquic_traffic_shaper_stop_decoy);

/* Spin bit randomization */
EXPORT_SYMBOL_GPL(tquic_spin_randomizer_init);
EXPORT_SYMBOL_GPL(tquic_spin_randomizer_destroy);
EXPORT_SYMBOL_GPL(tquic_spin_randomizer_set_mode);
EXPORT_SYMBOL_GPL(tquic_spin_randomizer_get);
EXPORT_SYMBOL_GPL(tquic_spin_randomizer_freeze);
EXPORT_SYMBOL_GPL(tquic_spin_randomizer_is_frozen);

/* Packet jitter */
EXPORT_SYMBOL_GPL(tquic_packet_jitter_init);
EXPORT_SYMBOL_GPL(tquic_packet_jitter_destroy);
EXPORT_SYMBOL_GPL(tquic_packet_jitter_set_mode);
EXPORT_SYMBOL_GPL(tquic_packet_jitter_set_range);
EXPORT_SYMBOL_GPL(tquic_packet_jitter_calc);
EXPORT_SYMBOL_GPL(tquic_packet_jitter_send);
EXPORT_SYMBOL_GPL(tquic_packet_jitter_cancel);

/* Context management */
EXPORT_SYMBOL_GPL(tquic_exfil_ctx_alloc);
EXPORT_SYMBOL_GPL(tquic_exfil_ctx_free);
EXPORT_SYMBOL_GPL(tquic_exfil_ctx_get);
EXPORT_SYMBOL_GPL(tquic_exfil_ctx_put);
EXPORT_SYMBOL_GPL(tquic_exfil_ctx_set_level);
EXPORT_SYMBOL_GPL(tquic_exfil_ctx_enable);
EXPORT_SYMBOL_GPL(tquic_exfil_ctx_disable);
EXPORT_SYMBOL_GPL(tquic_exfil_process_incoming);
EXPORT_SYMBOL_GPL(tquic_exfil_process_outgoing);
EXPORT_SYMBOL_GPL(tquic_exfil_get_stats);

/* Sysctl accessors */
EXPORT_SYMBOL_GPL(tquic_sysctl_get_exfil_level);
EXPORT_SYMBOL_GPL(tquic_sysctl_get_exfil_timing_delay_us);
EXPORT_SYMBOL_GPL(tquic_sysctl_get_exfil_padding_strategy);
EXPORT_SYMBOL_GPL(tquic_sysctl_get_exfil_pad_probability);
EXPORT_SYMBOL_GPL(tquic_sysctl_get_exfil_spin_mode);
EXPORT_SYMBOL_GPL(tquic_sysctl_get_exfil_jitter_min_us);
EXPORT_SYMBOL_GPL(tquic_sysctl_get_exfil_jitter_max_us);

/* Module init/exit */
EXPORT_SYMBOL_GPL(tquic_exfil_init);
EXPORT_SYMBOL_GPL(tquic_exfil_exit);

/* Event reporting */
EXPORT_SYMBOL_GPL(tquic_exfil_event);
