// SPDX-License-Identifier: GPL-2.0-only
/*
 * TQUIC: Copa Congestion Control
 *
 * Copyright (c) 2026 Justin Adams <spotty118@gmail.com>
 * Kernel implementation by Justin Adams <spotty118@gmail.com>
 *
 * Copa (Competitive Online Pacing Algorithm) for TQUIC multipath WAN bonding.
 *
 * Copa is a delay-based congestion control algorithm that aims to maintain
 * low queuing delay while remaining competitive with loss-based algorithms.
 * It uses RTT measurements to adjust the congestion window, targeting a
 * specific ratio between standing RTT and minimum RTT.
 *
 * Reference:
 *   Arun, V., & Balakrishnan, H. (2018). Copa: Practical Delay-Based
 *   Congestion Control for the Internet. NSDI '18.
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/math64.h>
#include <net/tquic.h>
#include "../tquic_debug.h"
#include "persistent_cong.h"

/* Copa parameters */
#define COPA_DELTA_SCALE	1000	/* Scale for delta parameter */
#define COPA_DEFAULT_DELTA	500	/* Default delta = 0.5 (scaled) */
#define COPA_MIN_DELTA		100	/* Minimum delta = 0.1 */
#define COPA_MAX_DELTA		1000	/* Maximum delta = 1.0 */

/* RTT filter window (microseconds) */
#define COPA_RTT_WINDOW_US	(10 * USEC_PER_SEC)	/* 10 seconds */
#define COPA_STANDING_WINDOW_US	(100 * USEC_PER_MSEC)	/* 100ms for standing RTT */

/* Initial and minimum cwnd */
#define COPA_INIT_CWND		(10 * 1200)	/* 10 packets */
#define COPA_MIN_CWND		(2 * 1200)	/* 2 packets */

/* Velocity parameter for competitive mode */
#define COPA_VELOCITY_MIN	1
#define COPA_VELOCITY_MAX	16

/* Direction for velocity changes */
enum copa_direction {
	COPA_DIR_NONE = 0,
	COPA_DIR_UP,
	COPA_DIR_DOWN,
};

/* RTT sample for min RTT tracking */
struct copa_rtt_sample {
	u32 rtt_us;
	ktime_t time;
};

/* ECN beta factor for Copa (delay-based should be more responsive) */
#define COPA_ECN_BETA		700	/* 0.7 scaled by 1000 */

/* Per-path Copa state */
struct tquic_copa {
	/* Core Copa state */
	u64 cwnd;		/* Current congestion window */
	u64 ssthresh;		/* Slow start threshold */
	bool in_slow_start;	/* Slow start phase */

	/* RTT tracking */
	u32 rtt_min_us;		/* Minimum RTT ever observed */
	ktime_t rtt_min_time;	/* When min RTT was observed */
	u32 rtt_standing_us;	/* Standing RTT (recent min) */
	ktime_t rtt_standing_time;

	/* RTT samples for standing RTT calculation */
	struct copa_rtt_sample rtt_samples[16];
	u32 rtt_sample_head;
	u32 rtt_sample_count;

	/* Velocity state for competitive mode */
	u32 velocity;		/* Current velocity multiplier */
	enum copa_direction direction;	/* Last direction of change */
	u32 direction_count;	/* Count of same-direction changes */

	/* Pacing */
	u64 pacing_rate;	/* Current pacing rate */

	/* Parameters */
	u32 delta;		/* Target queuing delay factor (scaled) */

	/* Statistics */
	u64 bytes_acked_total;
	u64 last_cwnd;		/* For change detection */

	/* ECN state per RFC 9002 Section 7 */
	ktime_t last_ecn_time;	/* Time of last ECN response */
	bool ecn_in_round;	/* ECN CE received in current round */
	u64 ecn_ce_total;	/* Total CE marks received */
};

/*
 * Update standing RTT with new sample
 * Standing RTT is the minimum RTT observed in the recent window
 */
static void copa_update_standing_rtt(struct tquic_copa *copa, u32 rtt_us,
				     ktime_t now)
{
	ktime_t window_start;
	u32 min_rtt = rtt_us;
	int i, valid_samples = 0;

	tquic_dbg("copa: update_standing_rtt rtt=%u cur_standing=%u\n",
		  rtt_us, copa->rtt_standing_us);

	/* Add new sample */
	copa->rtt_samples[copa->rtt_sample_head].rtt_us = rtt_us;
	copa->rtt_samples[copa->rtt_sample_head].time = now;
	copa->rtt_sample_head = (copa->rtt_sample_head + 1) % 16;
	if (copa->rtt_sample_count < 16)
		copa->rtt_sample_count++;

	/* Calculate standing RTT from samples in window */
	window_start = ktime_sub_us(now, COPA_STANDING_WINDOW_US);

	for (i = 0; i < copa->rtt_sample_count; i++) {
		struct copa_rtt_sample *s = &copa->rtt_samples[i];

		if (ktime_after(s->time, window_start)) {
			if (s->rtt_us < min_rtt)
				min_rtt = s->rtt_us;
			valid_samples++;
		}
	}

	if (valid_samples > 0) {
		copa->rtt_standing_us = min_rtt;
		copa->rtt_standing_time = now;
	}
}

/*
 * Update minimum RTT
 * Min RTT expires after COPA_RTT_WINDOW_US to handle route changes
 */
static void copa_update_min_rtt(struct tquic_copa *copa, u32 rtt_us, ktime_t now)
{
	tquic_dbg("copa: update_min_rtt rtt=%u cur_min=%u\n",
		  rtt_us, copa->rtt_min_us);

	/* Check if min RTT has expired */
	if (copa->rtt_min_us == 0 ||
	    ktime_us_delta(now, copa->rtt_min_time) > COPA_RTT_WINDOW_US) {
		/* Reset min RTT */
		copa->rtt_min_us = rtt_us;
		copa->rtt_min_time = now;
	} else if (rtt_us <= copa->rtt_min_us) {
		/* New minimum */
		copa->rtt_min_us = rtt_us;
		copa->rtt_min_time = now;
	}
}

/*
 * Calculate target cwnd based on Copa algorithm
 * Target: cwnd = delta * BDP, where BDP = bandwidth * RTT_min
 */
static u64 copa_target_cwnd(struct tquic_copa *copa)
{
	u64 target;
	u32 queuing_delay;

	tquic_dbg("copa: target_cwnd rtt_min=%u standing=%u delta=%u cwnd=%llu\n",
		  copa->rtt_min_us, copa->rtt_standing_us, copa->delta, copa->cwnd);

	if (copa->rtt_min_us == 0 || copa->rtt_standing_us == 0)
		return copa->cwnd;

	/*
	 * Copa targets: RTT_standing / RTT_min = 1 + 1/delta
	 * Which means: queuing_delay = RTT_standing - RTT_min = RTT_min/delta
	 *
	 * The cwnd adjustment is:
	 *   If RTT_standing > RTT_min * (1 + 1/delta): decrease
	 *   If RTT_standing < RTT_min * (1 + 1/delta): increase
	 */

	/* Calculate actual queuing delay */
	if (copa->rtt_standing_us > copa->rtt_min_us)
		queuing_delay = copa->rtt_standing_us - copa->rtt_min_us;
	else
		queuing_delay = 0;

	/*
	 * Target cwnd based on delay:
	 * cwnd = (delta / (1 + delta)) * cwnd_max
	 *
	 * Simplified: cwnd ~= rate * RTT_min * delta / (delta + 1)
	 */
	target = copa->cwnd;

	/* Target queuing delay threshold: RTT_min / delta */
	if (copa->delta > 0) {
		u32 target_delay = copa->rtt_min_us * COPA_DELTA_SCALE / copa->delta;

		if (queuing_delay > target_delay) {
			/* Too much delay, decrease cwnd */
			target = copa->cwnd - (copa->cwnd / (2 * copa->delta / COPA_DELTA_SCALE + 2));
		} else {
			/* Can increase cwnd */
			target = copa->cwnd + (1200 * copa->delta / COPA_DELTA_SCALE);
		}
	}

	return max(target, (u64)COPA_MIN_CWND);
}

/*
 * Update velocity for competitive mode
 * Velocity accelerates cwnd changes when consistently moving in one direction
 */
static void copa_update_velocity(struct tquic_copa *copa, enum copa_direction dir)
{
	tquic_dbg("copa: update_velocity dir=%d prev_dir=%d vel=%u count=%u\n",
		  dir, copa->direction, copa->velocity, copa->direction_count);

	if (dir == copa->direction) {
		copa->direction_count++;
		if (copa->direction_count >= 3) {
			/* Accelerate in same direction */
			copa->velocity = min(copa->velocity * 2, (u32)COPA_VELOCITY_MAX);
			copa->direction_count = 0;
		}
	} else {
		/* Direction changed, reset velocity */
		copa->velocity = COPA_VELOCITY_MIN;
		copa->direction = dir;
		copa->direction_count = 1;
	}
}

/*
 * Initialize Copa state for a path
 */
static void *tquic_copa_init(struct tquic_path *path)
{
	struct tquic_copa *copa;

	copa = kzalloc(sizeof(*copa), GFP_KERNEL);
	if (!copa)
		return NULL;

	copa->cwnd = COPA_INIT_CWND;
	copa->ssthresh = ULLONG_MAX;
	copa->in_slow_start = true;
	copa->delta = COPA_DEFAULT_DELTA;
	copa->velocity = COPA_VELOCITY_MIN;
	copa->direction = COPA_DIR_NONE;
	copa->rtt_min_us = 0;
	copa->rtt_standing_us = 0;

	tquic_dbg("copa: initialized for path %u, delta=%u\n",
		  path->path_id, copa->delta);

	return copa;
}

static void tquic_copa_release(void *state)
{
	kfree(state);
}

/*
 * Called when a packet is sent
 */
static void tquic_copa_on_sent(void *state, u64 bytes, ktime_t sent_time)
{
	/* Track bytes in flight if needed for pacing */
}

/*
 * Called when ACK is received - main Copa logic
 */
static void tquic_copa_on_ack(void *state, u64 bytes_acked, u64 rtt_us)
{
	struct tquic_copa *copa = state;
	ktime_t now;
	u64 target, adjustment;
	enum copa_direction dir;

	if (!copa || rtt_us == 0)
		return;

	now = ktime_get();
	copa->bytes_acked_total += bytes_acked;

	/*
	 * Reset ECN round flag if an RTT has elapsed since the last
	 * ECN response, per RFC 9002 Section 7.1 (once-per-RTT limit).
	 */
	if (copa->ecn_in_round && copa->rtt_min_us > 0) {
		s64 elapsed = ktime_us_delta(now, copa->last_ecn_time);

		if (elapsed >= (s64)copa->rtt_min_us)
			copa->ecn_in_round = false;
	}

	/* Update RTT measurements */
	copa_update_min_rtt(copa, rtt_us, now);
	copa_update_standing_rtt(copa, rtt_us, now);

	/* Slow start phase */
	if (copa->in_slow_start) {
		copa->cwnd += bytes_acked;

		/* Exit slow start if queuing delay builds up */
		if (copa->rtt_standing_us > 0 && copa->rtt_min_us > 0) {
			u32 delay_ratio = copa->rtt_standing_us * COPA_DELTA_SCALE /
					  copa->rtt_min_us;

			/* Exit if delay ratio exceeds threshold */
			if (delay_ratio > COPA_DELTA_SCALE + COPA_DELTA_SCALE / copa->delta) {
				copa->in_slow_start = false;
				copa->ssthresh = copa->cwnd;
				tquic_dbg("copa: exiting slow start, cwnd=%llu\n",
					  copa->cwnd);
			}
		}

		if (copa->cwnd >= copa->ssthresh) {
			copa->in_slow_start = false;
		}

		goto update_pacing;
	}

	/* Copa congestion avoidance */
	target = copa_target_cwnd(copa);

	/* Determine direction of change */
	if (target > copa->cwnd)
		dir = COPA_DIR_UP;
	else if (target < copa->cwnd)
		dir = COPA_DIR_DOWN;
	else
		dir = COPA_DIR_NONE;

	/* Update velocity based on direction consistency */
	if (dir != COPA_DIR_NONE)
		copa_update_velocity(copa, dir);

	/* Apply velocity-adjusted cwnd change */
	if (target > copa->cwnd) {
		/* Increase cwnd (guard against cwnd == 0) */
		if (copa->cwnd > 0) {
			/*
			 * Avoid overflow in velocity * bytes_acked * delta.
			 * Compute (velocity * delta) / (cwnd * COPA_DELTA_SCALE)
			 * first (smaller intermediate), then multiply by
			 * bytes_acked.
			 */
			u64 factor = div64_u64(
				(u64)copa->velocity * copa->delta,
				(u64)copa->cwnd * COPA_DELTA_SCALE);
			adjustment = factor * bytes_acked;
		} else {
			adjustment = bytes_acked;
		}
		adjustment = max(adjustment, (u64)1);
		copa->cwnd += adjustment;
	} else if (target < copa->cwnd) {
		/* Decrease cwnd (guard against underflow) */
		adjustment = (copa->velocity * copa->cwnd) /
			     (copa->delta * 2 + COPA_DELTA_SCALE);
		if (copa->cwnd > COPA_MIN_CWND)
			adjustment = min(adjustment, copa->cwnd - (u64)COPA_MIN_CWND);
		else
			adjustment = 0;
		copa->cwnd -= adjustment;
	}

	copa->cwnd = max(copa->cwnd, (u64)COPA_MIN_CWND);

update_pacing:
	/* Update pacing rate: cwnd / RTT_min */
	if (copa->rtt_min_us > 0) {
		/* Cap cwnd before multiplication to prevent u64 overflow */
		u64 capped = min_t(u64, copa->cwnd, U64_MAX / USEC_PER_SEC);

		copa->pacing_rate = div64_u64(capped * USEC_PER_SEC,
					      copa->rtt_min_us);
	}

	copa->last_cwnd = copa->cwnd;
}

/*
 * Called on packet loss
 * Copa is delay-based, so loss has limited impact, but we still react
 */
static void tquic_copa_on_loss(void *state, u64 bytes_lost)
{
	struct tquic_copa *copa = state;

	if (!copa)
		return;

	/*
	 * Copa doesn't directly reduce cwnd on loss since it's delay-based.
	 * However, loss indicates potential congestion, so we:
	 * 1. Reset velocity to be conservative
	 * 2. Set direction to down to encourage reduction
	 */
	copa->velocity = COPA_VELOCITY_MIN;
	copa->direction = COPA_DIR_DOWN;
	copa->direction_count = 0;

	/*
	 * If we're in slow start, exit and reduce window.
	 * This helps Copa compete with loss-based algorithms.
	 */
	if (copa->in_slow_start) {
		copa->in_slow_start = false;
		copa->ssthresh = copa->cwnd * 7 / 10;  /* 0.7 factor */
		copa->cwnd = copa->ssthresh;
	}

	tquic_warn("copa: loss detected, cwnd=%llu velocity=%u\n",
		   copa->cwnd, copa->velocity);
}

/*
 * Called on RTT update
 */
static void tquic_copa_on_rtt(void *state, u64 rtt_us)
{
	struct tquic_copa *copa = state;
	ktime_t now;

	if (!copa || rtt_us == 0)
		return;

	tquic_dbg("copa: on_rtt rtt_us=%llu min=%u standing=%u\n",
		  rtt_us, copa->rtt_min_us, copa->rtt_standing_us);

	now = ktime_get();
	copa_update_min_rtt(copa, rtt_us, now);
	copa_update_standing_rtt(copa, rtt_us, now);
}

/*
 * Called on ECN Congestion Experienced (CE) marks
 *
 * Copa is delay-based and naturally responds to queue buildup through
 * RTT measurements. However, ECN provides an explicit congestion signal
 * that Copa should respect, especially when competing with loss-based
 * algorithms.
 *
 * Per RFC 9002 Section 7:
 * - Treat ECN-CE as congestion signal
 * - Reduce sending rate
 * - Don't reduce more than once per RTT
 *
 * Copa's response to ECN:
 * 1. Immediately reduce cwnd (more aggressive than RTT-based reduction)
 * 2. Reset velocity to prevent aggressive increases
 * 3. Set direction to DOWN to encourage continued reduction
 * 4. Update delta to be more conservative if ECN is persistent
 */
static void tquic_copa_on_ecn(void *state, u64 ecn_ce_count)
{
	struct tquic_copa *copa = state;
	ktime_t now;
	s64 time_since_last;

	if (!copa || ecn_ce_count == 0)
		return;

	now = ktime_get();
	copa->ecn_ce_total += ecn_ce_count;

	/*
	 * Per RFC 9002: Don't respond more than once per RTT.
	 * Use min_rtt for rate limiting.
	 */
	if (copa->ecn_in_round) {
		tquic_dbg("copa: ECN CE ignored (already responded this round)\n");
		return;
	}

	/* Time-based rate limiting using min_rtt */
	if (copa->rtt_min_us > 0) {
		time_since_last = ktime_us_delta(now, copa->last_ecn_time);
		if (time_since_last < copa->rtt_min_us) {
			tquic_dbg("copa: ECN CE ignored (within RTT window)\n");
			return;
		}
	}

	/*
	 * Copa ECN Response:
	 *
	 * Copa normally relies on RTT increases to detect congestion.
	 * ECN provides a more explicit signal that we should reduce.
	 *
	 * We apply a multiplicative decrease similar to loss-based
	 * algorithms, but slightly less aggressive since Copa will
	 * naturally reduce further if RTT remains high.
	 */

	/* Exit slow start if active */
	if (copa->in_slow_start) {
		copa->in_slow_start = false;
		copa->ssthresh = copa->cwnd;
	}

	/* Reduce cwnd by beta_ecn factor (0.7) */
	copa->cwnd = max(copa->cwnd * COPA_ECN_BETA / COPA_DELTA_SCALE,
			 (u64)COPA_MIN_CWND);

	/* Update ssthresh */
	copa->ssthresh = copa->cwnd;

	/*
	 * Reset velocity to prevent aggressive increase after reduction.
	 * Set direction to DOWN so Copa continues being conservative.
	 */
	copa->velocity = COPA_VELOCITY_MIN;
	copa->direction = COPA_DIR_DOWN;
	copa->direction_count = 0;

	/*
	 * If ECN-CE is persistent, make delta more conservative.
	 * This targets lower queuing delay.
	 */
	if (copa->ecn_ce_total > 5 && copa->delta > COPA_MIN_DELTA) {
		/* Reduce delta to target even lower queuing delay */
		copa->delta = max(copa->delta - 50, (u32)COPA_MIN_DELTA);
	}

	/* Update pacing rate */
	if (copa->rtt_min_us > 0) {
		copa->pacing_rate = copa->cwnd * USEC_PER_SEC / copa->rtt_min_us;
	}

	/* Mark that we responded to ECN in this round */
	copa->ecn_in_round = true;
	copa->last_ecn_time = now;

	tquic_dbg("copa: ECN CE response, ce_count=%llu total=%llu cwnd=%llu delta=%u\n",
		  ecn_ce_count, copa->ecn_ce_total, copa->cwnd, copa->delta);
}

static u64 tquic_copa_get_cwnd(void *state)
{
	struct tquic_copa *copa = state;
	return copa ? copa->cwnd : COPA_INIT_CWND;
}

static u64 tquic_copa_get_pacing_rate(void *state)
{
	struct tquic_copa *copa = state;
	return copa ? copa->pacing_rate : 0;
}

static bool tquic_copa_can_send(void *state, u64 bytes)
{
	struct tquic_copa *copa = state;

	if (!copa)
		return true;

	/* Copa uses both cwnd and pacing */
	return true;
}

/*
 * Called on persistent congestion (RFC 9002 Section 7.6)
 *
 * For Copa (delay-based), persistent congestion indicates that
 * our RTT measurements were severely wrong or the path characteristics
 * changed dramatically.
 *
 * We reset:
 * 1. cwnd to minimum
 * 2. RTT measurements (they're clearly stale)
 * 3. Velocity and direction state
 * 4. Delta parameter (make more conservative)
 */
static void tquic_copa_on_persistent_cong(void *state,
					  struct tquic_persistent_cong_info *info)
{
	struct tquic_copa *copa = state;

	if (!copa || !info)
		return;

	tquic_warn("copa: persistent congestion, cwnd %llu -> %llu\n",
		   copa->cwnd, info->min_cwnd);

	/* Reset cwnd to minimum per RFC 9002 */
	copa->cwnd = info->min_cwnd;
	copa->ssthresh = info->min_cwnd;

	/* Exit slow start */
	copa->in_slow_start = false;

	/* Reset RTT measurements - they're clearly stale */
	copa->rtt_min_us = 0;
	copa->rtt_standing_us = 0;
	copa->rtt_sample_count = 0;
	copa->rtt_sample_head = 0;

	/* Reset velocity state to be conservative */
	copa->velocity = COPA_VELOCITY_MIN;
	copa->direction = COPA_DIR_NONE;
	copa->direction_count = 0;

	/* Reset pacing rate */
	copa->pacing_rate = 0;

	/* Reset ECN state */
	copa->ecn_in_round = false;
	copa->ecn_ce_total = 0;

	/*
	 * Make delta more conservative after persistent congestion.
	 * This targets lower queuing delay.
	 */
	if (copa->delta > COPA_MIN_DELTA)
		copa->delta = max(copa->delta / 2, (u32)COPA_MIN_DELTA);
}

static struct tquic_cong_ops __maybe_unused tquic_copa_ops = {
	.name = "copa",
	.owner = THIS_MODULE,
	.init = tquic_copa_init,
	.release = tquic_copa_release,
	.on_packet_sent = tquic_copa_on_sent,
	.on_ack = tquic_copa_on_ack,
	.on_loss = tquic_copa_on_loss,
	.on_rtt_update = tquic_copa_on_rtt,
	.on_ecn = tquic_copa_on_ecn,  /* ECN CE handler per RFC 9002 */
	.on_persistent_congestion = tquic_copa_on_persistent_cong,
	.get_cwnd = tquic_copa_get_cwnd,
	.get_pacing_rate = tquic_copa_get_pacing_rate,
	.can_send = tquic_copa_can_send,
};

#ifndef TQUIC_OUT_OF_TREE
static int __init tquic_copa_module_init(void)
{
	tquic_info("cc: copa algorithm registered\n");
	return tquic_register_cong(&tquic_copa_ops);
}

static void __exit tquic_copa_module_exit(void)
{
	tquic_unregister_cong(&tquic_copa_ops);
}

module_init(tquic_copa_module_init);
module_exit(tquic_copa_module_exit);
#endif /* !TQUIC_OUT_OF_TREE */

MODULE_DESCRIPTION("TQUIC Copa Congestion Control");
MODULE_AUTHOR("Linux Foundation");
MODULE_LICENSE("GPL");
MODULE_ALIAS("tquic-cong-copa");
