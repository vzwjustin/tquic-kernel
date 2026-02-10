// SPDX-License-Identifier: GPL-2.0-only
/*
 * TQUIC: Prague Congestion Control
 *
 * Copyright (c) 2026 Linux Foundation
 *
 * Prague congestion control designed for L4S networks. Provides:
 * - Scalable ECN response (cwnd *= 1 - alpha/2)
 * - RTT-independence through virtual RTT scaling
 * - Coexistence with classic ECN traffic
 * - Smooth cwnd evolution via proportional response
 */

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/slab.h>

#include "prague.h"
#include "l4s.h"
#include "../tquic_debug.h"

/* Default parameters */
static u32 prague_alpha_init = PRAGUE_ALPHA_MAX / 16;	/* 6.25% */
static u32 prague_rtt_target = PRAGUE_RTT_TARGET_US;
static bool prague_rtt_scaling = true;
static bool prague_classic_fallback = true;

module_param(prague_alpha_init, uint, 0644);
MODULE_PARM_DESC(prague_alpha_init, "Initial alpha value (default: 64)");
module_param(prague_rtt_target, uint, 0644);
MODULE_PARM_DESC(prague_rtt_target, "Target RTT in microseconds (default: 25000)");
module_param(prague_rtt_scaling, bool, 0644);
MODULE_PARM_DESC(prague_rtt_scaling, "Enable RTT-independence scaling (default: true)");
module_param(prague_classic_fallback, bool, 0644);
MODULE_PARM_DESC(prague_classic_fallback, "Fall back to classic ECN if needed (default: true)");

/**
 * prague_get_mss - Get MSS from path or use default
 * @p: Prague state
 *
 * Return: Maximum segment size
 */
static u32 prague_get_mss(struct prague *p)
{
	if (p->path && p->path->mtu > 0)
		return p->path->mtu;
	return PRAGUE_DEFAULT_MSS;
}

/**
 * prague_init - Initialize Prague congestion control
 * @path: Path to initialize CC for
 *
 * Return: Pointer to allocated prague state, or NULL on failure
 */
static void *prague_init(struct tquic_path *path)
{
	struct prague *p;
	u32 initial_cwnd;

	p = kzalloc(sizeof(*p), GFP_KERNEL);
	if (!p)
		return NULL;

	p->path = path;
	initial_cwnd = 10 * prague_get_mss(p);

	p->state = PRAGUE_OPEN;
	p->alpha = prague_alpha_init;
	p->cwnd = initial_cwnd;
	p->ssthresh = UINT_MAX;
	p->bytes_acked = 0;
	p->ecn_bytes = 0;
	p->loss_cwnd = 0;
	p->prior_cwnd = 0;
	p->rtt_min_us = UINT_MAX;
	p->rtt_us = 0;
	p->rtt_cnt = 0;
	p->in_slow_start = true;
	p->ce_state = 0;
	p->acked_bytes_ecn = 0;

	/* Set parameters */
	p->params.ecn_alpha_init = prague_alpha_init;
	p->params.rtt_target_us = prague_rtt_target;
	p->params.rtt_scaling = prague_rtt_scaling;
	p->params.classic_ecn_fallback = prague_classic_fallback;

	return p;
}

/**
 * prague_release - Release Prague state
 * @cong_data: Prague state to release
 */
static void prague_release(void *cong_data)
{
	kfree(cong_data);
}

/**
 * prague_get_cwnd - Get current congestion window
 * @cong_data: Prague state
 *
 * Return: Current cwnd in bytes
 */
static u64 prague_get_cwnd(void *cong_data)
{
	struct prague *p = cong_data;

	if (!p)
		return 10 * PRAGUE_DEFAULT_MSS;

	return p->cwnd;
}

/**
 * prague_get_pacing_rate - Get pacing rate
 * @cong_data: Prague state
 *
 * Return: Pacing rate in bytes/sec (0 if no pacing)
 */
static u64 prague_get_pacing_rate(void *cong_data)
{
	/* Prague doesn't implement explicit pacing */
	return 0;
}

/**
 * prague_rtt_scale - Apply RTT-independence scaling
 * @p: Prague state
 * @value: Value to scale
 *
 * Scales the value based on RTT to achieve RTT-independence.
 * Uses virtual RTT to slow down response for short RTTs.
 *
 * Return: Scaled value
 */
static u32 prague_rtt_scale(struct prague *p, u32 value)
{
	u32 rtt_us;
	u32 scaled;

	if (!p->params.rtt_scaling || p->rtt_us == 0)
		return value;

	rtt_us = max(p->rtt_us, PRAGUE_RTT_SCALING_MIN_US);

	/* Scale = target_rtt / actual_rtt, clamped */
	if (rtt_us >= p->params.rtt_target_us) {
		scaled = value;
	} else {
		/* Virtual RTT = actual_rtt * (target/actual) */
		scaled = (value * rtt_us) / p->params.rtt_target_us;
		scaled = max(scaled, value >> PRAGUE_RTT_VIRT_SHIFT);
	}

	return scaled;
}

/**
 * prague_update_alpha - Update ECN marking fraction estimate
 * @p: Prague state
 * @acked_bytes: Bytes acknowledged
 * @ce_bytes: Bytes that experienced CE marking
 *
 * Updates alpha using EWMA: alpha = (1-g)*alpha + g*(ce_bytes/acked_bytes)
 */
static void prague_update_alpha(struct prague *p, u64 acked_bytes, u64 ce_bytes)
{
	u32 ce_ratio;
	u32 new_alpha;

	if (acked_bytes == 0)
		return;

	/* Calculate CE ratio scaled by ALPHA_MAX */
	ce_ratio = (ce_bytes * PRAGUE_ALPHA_MAX) / acked_bytes;

	/* EWMA update: alpha = alpha - (alpha >> G_SHIFT) + (ce_ratio >> G_SHIFT) */
	new_alpha = p->alpha - (p->alpha >> PRAGUE_G_SHIFT) +
		    (ce_ratio >> PRAGUE_G_SHIFT);

	/* Clamp to valid range */
	p->alpha = clamp(new_alpha, 1U, PRAGUE_ALPHA_MAX);
}

/**
 * prague_ecn_reduce - Reduce cwnd in response to ECN marks
 * @p: Prague state
 *
 * Implements scalable ECN response: cwnd = cwnd * (1 - alpha/2)
 */
static void prague_ecn_reduce(struct prague *p)
{
	u32 reduction;
	u32 alpha_scaled;
	u32 mss = prague_get_mss(p);

	/* Scale alpha by RTT if enabled */
	alpha_scaled = prague_rtt_scale(p, p->alpha);

	/* Reduction = cwnd * alpha / 2 */
	reduction = (p->cwnd * alpha_scaled) >> (PRAGUE_ALPHA_SHIFT + 1);
	reduction = max(reduction, 1U);

	p->prior_cwnd = p->cwnd;
	p->cwnd = max(p->cwnd - reduction, PRAGUE_MIN_CWND * mss);
	p->state = PRAGUE_ECN_REDUCED;
	tquic_dbg("prague: ECN reduce, cwnd %llu -> %llu alpha=%u\n",
		  p->prior_cwnd, p->cwnd, p->alpha);

	/* Exit slow start on first ECN mark */
	if (p->in_slow_start) {
		p->in_slow_start = false;
		p->ssthresh = p->cwnd;
	}
}

/**
 * prague_on_ack - Process acknowledgment
 * @cong_data: Prague state
 * @bytes_acked: Bytes acknowledged
 * @rtt_us: RTT sample in microseconds
 *
 * Updates cwnd based on acked bytes. In slow start, doubles cwnd.
 * In congestion avoidance, increases by MSS per RTT.
 */
static void prague_on_ack(void *cong_data, u64 bytes_acked, u64 rtt_us)
{
	struct prague *p = cong_data;
	u32 increase;
	u32 mss;

	if (!p)
		return;

	mss = prague_get_mss(p);

	/* Update RTT estimates */
	if (rtt_us > 0) {
		if (p->rtt_us == 0)
			p->rtt_us = rtt_us;
		else
			p->rtt_us = (p->rtt_us * 7 + rtt_us) >> 3;

		if (rtt_us < p->rtt_min_us)
			p->rtt_min_us = rtt_us;
		p->rtt_cnt++;
	}

	p->bytes_acked += bytes_acked;

	/* Don't increase cwnd if in recovery */
	if (p->state == PRAGUE_RECOVERY)
		return;

	if (p->in_slow_start && p->cwnd < p->ssthresh) {
		/* Slow start: increase by acked bytes */
		p->cwnd += bytes_acked;
	} else {
		/* Congestion avoidance: increase by MSS per RTT */
		p->in_slow_start = false;
		increase = (bytes_acked * mss) / p->cwnd;
		increase = prague_rtt_scale(p, increase);
		p->cwnd += increase;
	}

	/* Reset ECN state after increase */
	if (p->state == PRAGUE_ECN_REDUCED)
		p->state = PRAGUE_OPEN;
}

/**
 * prague_on_ecn - Process ECN congestion signal
 * @cong_data: Prague state
 * @ecn_ce_count: Number of CE-marked packets
 *
 * Implements Prague's scalable ECN response.
 */
static void prague_on_ecn(void *cong_data, u64 ecn_ce_count)
{
	struct prague *p = cong_data;
	u64 ce_bytes;
	u32 mss;

	if (!p || ecn_ce_count == 0)
		return;

	mss = prague_get_mss(p);

	/*
	 * CF-212: Use check_mul_overflow to prevent integer overflow.
	 * ecn_ce_count comes from the ACK frame and could be very large.
	 */
	if (check_mul_overflow(ecn_ce_count, (u64)mss, &ce_bytes))
		ce_bytes = U64_MAX;

	/* Update alpha estimate */
	prague_update_alpha(p, p->acked_bytes_ecn + ce_bytes, ce_bytes);

	/* Accumulate CE state for proportional response */
	p->ce_state += ecn_ce_count;
	p->ecn_bytes += ce_bytes;
	p->acked_bytes_ecn += ce_bytes;

	/* Reduce once per RTT (when enough data acknowledged) */
	if (p->acked_bytes_ecn >= p->cwnd) {
		prague_ecn_reduce(p);
		p->ce_state = 0;
		p->ecn_bytes = 0;
		p->acked_bytes_ecn = 0;
	}
}

/**
 * prague_on_loss - Process packet loss event
 * @cong_data: Prague state
 * @bytes_lost: Bytes lost
 *
 * Loss indicates severe congestion - apply multiplicative decrease.
 */
static void prague_on_loss(void *cong_data, u64 bytes_lost)
{
	struct prague *p = cong_data;
	u32 mss;

	if (!p)
		return;

	mss = prague_get_mss(p);

	/* Avoid multiple reductions per loss event */
	if (p->state == PRAGUE_RECOVERY)
		return;

	p->loss_cwnd = p->cwnd;
	p->prior_cwnd = p->cwnd;

	/* Classic multiplicative decrease: cwnd = cwnd * beta_loss */
	p->cwnd = (p->cwnd * PRAGUE_BETA_LOSS) / PRAGUE_BETA_SCALE;
	p->cwnd = max(p->cwnd, PRAGUE_MIN_CWND * mss);

	p->ssthresh = p->cwnd;
	p->state = PRAGUE_RECOVERY;
	p->in_slow_start = false;
	tquic_warn("prague: loss, cwnd %llu -> %llu\n",
		   p->loss_cwnd, p->cwnd);
}

/**
 * prague_on_persistent_congestion - Handle persistent congestion
 * @cong_data: Prague state
 * @info: Persistent congestion info
 */
static void prague_on_persistent_congestion(void *cong_data,
					    struct tquic_persistent_cong_info *info)
{
	struct prague *p = cong_data;
	u32 mss;

	if (!p)
		return;

	mss = prague_get_mss(p);

	/* Reset to minimum cwnd per RFC 9002 Section 7.6 */
	p->cwnd = 2 * mss;
	p->ssthresh = p->cwnd;
	p->state = PRAGUE_OPEN;
	p->in_slow_start = true;
	p->alpha = prague_alpha_init;
	tquic_warn("prague: persistent congestion, cwnd reset to %llu\n",
		   p->cwnd);
}

/**
 * prague_can_send - Check if we can send more data
 * @cong_data: Prague state
 * @bytes: Bytes to send
 *
 * Return: true if can send
 */
static bool prague_can_send(void *cong_data, u64 bytes)
{
	struct prague *p = cong_data;

	if (!p)
		return true;

	return bytes <= p->cwnd;
}

struct tquic_cong_ops prague_cong_ops = {
	.name = "prague",
	.owner = THIS_MODULE,
	.init = prague_init,
	.release = prague_release,
	.on_ack = prague_on_ack,
	.on_ecn = prague_on_ecn,
	.on_loss = prague_on_loss,
	.on_persistent_congestion = prague_on_persistent_congestion,
	.get_cwnd = prague_get_cwnd,
	.get_pacing_rate = prague_get_pacing_rate,
	.can_send = prague_can_send,
};

int __init tquic_prague_init(void)
{
	tquic_info("cc: prague algorithm registered\n");
	return tquic_register_cong(&prague_cong_ops);
}

void __exit tquic_prague_exit(void)
{
	tquic_unregister_cong(&prague_cong_ops);
}

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("TQUIC Prague Congestion Control");
MODULE_AUTHOR("Linux Foundation");
