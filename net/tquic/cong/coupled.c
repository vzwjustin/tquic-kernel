// SPDX-License-Identifier: GPL-2.0-only
/*
 * TQUIC: Coupled Multipath Congestion Control
 *
 * Copyright (c) 2026 Justin Adams <spotty118@gmail.com>
 * Kernel implementation by Justin Adams <spotty118@gmail.com>
 *
 * This module implements coupled congestion control algorithms for
 * multipath WAN bonding, ensuring fairness and efficiency across paths.
 *
 * Implements:
 * - LIA  (Linked Increases Algorithm)
 * - OLIA (Opportunistic Linked Increases Algorithm) - RFC 6356
 * - BALIA (Balanced Linked Adaptation)
 * - Shared bottleneck detection
 * - Per-path subflow management with CUBIC/BBR integration
 *
 * The goal is to achieve resource pooling (combining bandwidth of all
 * paths) while being fair to single-path flows sharing a bottleneck.
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/list.h>
#include <linux/spinlock.h>
#include <linux/math64.h>
#include <linux/random.h>
#include <net/tquic.h>
#include "../tquic_compat.h"
#include "../tquic_debug.h"
#include "persistent_cong.h"
#include "coupled.h"

/* Algorithm selection (internal enum maps to public enum in coupled.h) */
enum coupled_algo {
	COUPLED_ALGO_LIA = 0,
	COUPLED_ALGO_OLIA,
	COUPLED_ALGO_BALIA,
};

/* Scaling factors (fixed-point arithmetic) */
#define COUPLED_SCALE		1024
#define COUPLED_SCALE_SHIFT	10
#define COUPLED_ALPHA_SCALE	(1ULL << 20)

/* Window parameters */
#define COUPLED_MIN_CWND	(2 * 1200)	/* 2 packets */
#define COUPLED_INIT_CWND	(10 * 1200)	/* 10 packets */
#define COUPLED_MAX_CWND	(1ULL << 30)	/* ~1GB */

/* LIA parameters */
#define LIA_ALPHA_DEFAULT	COUPLED_SCALE	/* alpha = 1.0 */

/* OLIA parameters (RFC 6356) */
#define OLIA_EPSILON_NUM	1
#define OLIA_EPSILON_DEN	10	/* epsilon = 0.1 */

/* BALIA parameters */
#define BALIA_X_MIN		100	/* Minimum x value (scaled) */

/* Shared bottleneck detection thresholds */
#define SBD_RTT_VARIANCE_THRESH	50	/* 50us variance threshold */
#define SBD_CORR_THRESH		800	/* Correlation threshold (0.8 scaled by 1000) */
#define SBD_HISTORY_LEN		16	/* RTT history for correlation */

/* Slow start exit threshold */
#define SS_EXIT_THRESH		2	/* Exit after bandwidth stops doubling */

/*
 * Per-subflow (path) state for coupled congestion control
 */
struct coupled_subflow {
	/* Basic state */
	u64 cwnd;		/* Congestion window (bytes) */
	u64 ssthresh;		/* Slow start threshold */
	u32 rtt_us;		/* Smoothed RTT (us) */
	u32 rtt_min;		/* Minimum RTT (us) */
	u32 rtt_var;		/* RTT variance (us) */

	/* Delivery tracking */
	u64 delivered;		/* Total bytes delivered */
	u64 delivered_ce;	/* Bytes marked with ECN CE */
	u64 lost;		/* Total bytes lost */
	u64 in_flight;		/* Bytes in flight */

	/* CUBIC integration */
	u64 cubic_cwnd;		/* CUBIC target cwnd */
	u64 cubic_w_max;	/* Window before last reduction */
	u64 cubic_k;		/* Time to reach w_max */
	u64 cubic_epoch_start;	/* Epoch start time */

	/* BBR integration */
	u64 bbr_bw;		/* Estimated bandwidth */
	u32 bbr_min_rtt;	/* BBR min RTT */
	u64 bbr_pacing_rate;	/* Pacing rate */

	/* State flags */
	bool in_slow_start;
	bool ecn_ce_marked;
	bool loss_in_round;

	/* Round tracking */
	u64 round_start_delivered;
	u64 next_round_delivered;
	u32 round_count;

	/* RTT history for shared bottleneck detection */
	u32 rtt_history[SBD_HISTORY_LEN];
	u32 rtt_history_idx;
	u32 rtt_history_count;

	/* Per-subflow alpha for coupled increase */
	u64 alpha;

	/* Path reference */
	struct tquic_path *path;
	u32 path_id;

	/* List linkage in coupled state */
	struct list_head list;
};

/*
 * Shared bottleneck detection state
 */
struct sbd_state {
	bool detected;		/* Shared bottleneck detected */
	u32 correlation;	/* RTT correlation (scaled by 1000) */
	u64 last_check;		/* Timestamp of last check */
	u32 check_interval;	/* Check interval (ms) */

	/* Per-pair correlation matrix */
	s32 *corr_matrix;	/* N x N correlation values */
	u32 num_subflows;
};

/*
 * Coupled congestion control state (per-connection)
 */
struct coupled_state {
	/* Algorithm selection */
	enum coupled_algo algo;

	/* Subflow management */
	struct list_head subflows;
	u32 num_subflows;
	spinlock_t lock;

	/* Global alpha for coupled increase */
	u64 global_alpha;

	/* Aggregate statistics */
	u64 total_cwnd;		/* Sum of all cwnds */
	u64 total_bw;		/* Sum of all bandwidths */
	u32 best_rtt;		/* Minimum RTT across paths */
	u32 max_rtt;		/* Maximum RTT across paths */

	/* Shared bottleneck detection */
	struct sbd_state sbd;

	/* Fair share calculation */
	u64 fair_share;		/* Calculated fair share per subflow */

	/* Resource pooling metric */
	u64 pooling_benefit;	/* Measured pooling benefit */

	/* Connection reference */
	struct tquic_connection *conn;

	/* Integration mode */
	bool use_cubic;
	bool use_bbr;
};

/* Forward declarations */
static void coupled_update_alpha(struct coupled_state *state);
static void coupled_update_sbd(struct coupled_state *state);
static u64 coupled_calc_increase(struct coupled_state *state,
				 struct coupled_subflow *sf);

/*
 * =============================================================================
 * Utility Functions
 * =============================================================================
 */

/*
 * Integer square root (from kernel lib)
 */
static u32 coupled_isqrt(u64 n)
{
	u64 x, x1;

	if (n == 0)
		return 0;

	x = n;
	x1 = (x + 1) / 2;

	while (x1 < x) {
		x = x1;
		x1 = (x + n / x) / 2;
	}

	return (u32)x;
}

/*
 * Cube root approximation using Newton-Raphson
 */
static u32 coupled_cbrt(u64 a)
{
	u32 x, b, shift;

	if (a == 0)
		return 0;

	b = fls64(a);
	shift = (b + 2) / 3;
	x = 1 << shift;

	x = (2 * x + (u32)div64_u64(a, (u64)x * x)) / 3;
	x = (2 * x + (u32)div64_u64(a, (u64)x * x)) / 3;
	x = (2 * x + (u32)div64_u64(a, (u64)x * x)) / 3;

	return x;
}

/*
 * Calculate sum of congestion windows across all subflows
 */
static u64 coupled_sum_cwnd(struct coupled_state *state)
{
	struct coupled_subflow *sf;
	u64 sum = 0;

	list_for_each_entry(sf, &state->subflows, list) {
		if (sf->path && sf->path->state == TQUIC_PATH_ACTIVE)
			sum += sf->cwnd;
	}

	return sum ?: 1;  /* Avoid division by zero */
}

/*
 * Calculate sum of (cwnd / rtt) across all subflows
 * This represents the aggregate throughput
 */
static u64 coupled_sum_cwnd_rtt(struct coupled_state *state)
{
	struct coupled_subflow *sf;
	u64 sum = 0;

	list_for_each_entry(sf, &state->subflows, list) {
		if (sf->path && sf->path->state == TQUIC_PATH_ACTIVE &&
		    sf->rtt_us > 0) {
			sum += div64_u64(sf->cwnd * COUPLED_SCALE, sf->rtt_us);
		}
	}

	return sum ?: 1;
}

/*
 * Find the best (minimum) RTT among all subflows
 */
static u32 coupled_best_rtt(struct coupled_state *state)
{
	struct coupled_subflow *sf;
	u32 best = UINT_MAX;

	list_for_each_entry(sf, &state->subflows, list) {
		if (sf->path && sf->path->state == TQUIC_PATH_ACTIVE &&
		    sf->rtt_us > 0 && sf->rtt_us < best) {
			best = sf->rtt_us;
		}
	}

	return best != UINT_MAX ? best : 1;
}

/*
 * Calculate max(cwnd_i / rtt_i^2) for OLIA
 */
static u64 coupled_max_cwnd_rtt2(struct coupled_state *state)
{
	struct coupled_subflow *sf;
	u64 max_val = 0;

	list_for_each_entry(sf, &state->subflows, list) {
		u64 val;

		if (sf->path && sf->path->state == TQUIC_PATH_ACTIVE &&
		    sf->rtt_us > 0) {
			/* cwnd / rtt^2, scaled */
			val = div64_u64(sf->cwnd * COUPLED_ALPHA_SCALE,
					(u64)sf->rtt_us * sf->rtt_us);
			if (val > max_val)
				max_val = val;
		}
	}

	return max_val ?: 1;
}

/*
 * =============================================================================
 * LIA - Linked Increases Algorithm
 * =============================================================================
 *
 * LIA couples the increase behavior of all subflows so that the aggregate
 * throughput is equal to what a single TCP flow would achieve.
 *
 * Increase: For each ACK on subflow i, increase cwnd_i by:
 *   min(alpha / cwnd_total, 1 / cwnd_i)
 *
 * where alpha = cwnd_total * max_rtt / (sum(cwnd_j / rtt_j))^2
 */

static u64 lia_calc_alpha(struct coupled_state *state)
{
	u64 sum_cwnd_rtt;
	u64 total_cwnd;
	u32 max_rtt = 0;
	struct coupled_subflow *sf;
	u64 alpha;

	total_cwnd = coupled_sum_cwnd(state);
	sum_cwnd_rtt = coupled_sum_cwnd_rtt(state);

	/* Find max RTT */
	list_for_each_entry(sf, &state->subflows, list) {
		if (sf->path && sf->path->state == TQUIC_PATH_ACTIVE &&
		    sf->rtt_us > max_rtt) {
			max_rtt = sf->rtt_us;
		}
	}

	if (max_rtt == 0)
		max_rtt = 1;

	/*
	 * alpha = cwnd_total * max_rtt / (sum(cwnd_j / rtt_j))^2
	 *
	 * Scale for fixed-point arithmetic:
	 * alpha_scaled = total_cwnd * max_rtt * SCALE^2 / sum_cwnd_rtt^2
	 *
	 * Split to avoid u64 overflow from three-term numerator.
	 * Divide first by denominator, then multiply by remaining.
	 */
	{
		u64 denominator;

		denominator = sum_cwnd_rtt * sum_cwnd_rtt / COUPLED_SCALE;
		if (denominator == 0)
			denominator = 1;

		alpha = div64_u64(total_cwnd * COUPLED_ALPHA_SCALE,
				  denominator);

		/* Guard against overflow on multiply by max_rtt */
		if (alpha > 0 && max_rtt > div64_u64(U64_MAX, alpha))
			alpha = U64_MAX;
		else
			alpha = alpha * max_rtt;
	}

	return alpha;
}

static u64 lia_calc_increase(struct coupled_state *state,
			     struct coupled_subflow *sf)
{
	u64 total_cwnd = coupled_sum_cwnd(state);
	u64 alpha = state->global_alpha;
	u64 increase1, increase2;

	/* increase = min(alpha / cwnd_total, 1 / cwnd_i) */

	/* alpha / cwnd_total */
	increase1 = div64_u64(alpha, total_cwnd);

	/* 1 / cwnd_i, scaled */
	increase2 = div64_u64(COUPLED_ALPHA_SCALE, sf->cwnd);

	return min(increase1, increase2);
}

/*
 * =============================================================================
 * OLIA - Opportunistic Linked Increases Algorithm (RFC 6356)
 * =============================================================================
 *
 * OLIA improves on LIA by allowing subflows on uncongested paths to
 * increase faster while maintaining TCP fairness on shared bottlenecks.
 *
 * Increase: For each ACK on subflow i:
 *   cwnd_i += (cwnd_i / rtt_i^2) / (max_j(cwnd_j / rtt_j^2)) *
 *             alpha / cwnd_total + epsilon_i / cwnd_i
 *
 * where alpha ensures TCP fairness at shared bottlenecks
 */

static u64 olia_calc_alpha(struct coupled_state *state)
{
	u64 sum_cwnd_rtt;
	u64 total_cwnd;
	u32 best_rtt;
	u64 alpha;
	u64 rtt_sq;
	u64 denominator;

	total_cwnd = coupled_sum_cwnd(state);
	sum_cwnd_rtt = coupled_sum_cwnd_rtt(state);
	best_rtt = coupled_best_rtt(state);

	/*
	 * OLIA alpha formula (RFC 6356):
	 * alpha = cwnd_total * best_rtt^2 / (sum(cwnd_j * rtt_best / rtt_j))^2
	 *
	 * This ensures the aggregate is TCP-friendly.
	 *
	 * To avoid u64 overflow from four-term multiplication, split into
	 * two separate divisions:
	 *   alpha = (total_cwnd * ALPHA_SCALE / denom) * (best_rtt^2 / 1)
	 * where denom = sum_cwnd_rtt^2 / COUPLED_SCALE + 1
	 */
	denominator = sum_cwnd_rtt * sum_cwnd_rtt / COUPLED_SCALE + 1;
	rtt_sq = (u64)best_rtt * best_rtt;

	/*
	 * First compute total_cwnd * ALPHA_SCALE / denominator,
	 * then multiply by rtt_sq. This avoids the four-way
	 * multiplication that can overflow u64.
	 */
	alpha = div64_u64(total_cwnd * COUPLED_ALPHA_SCALE, denominator);

	/* Guard against overflow on the second multiply */
	if (alpha > 0 && rtt_sq > div64_u64(U64_MAX, alpha))
		alpha = U64_MAX;
	else
		alpha = alpha * rtt_sq;

	return alpha;
}

static u64 olia_calc_increase(struct coupled_state *state,
			      struct coupled_subflow *sf)
{
	u64 total_cwnd = coupled_sum_cwnd(state);
	u64 max_cwnd_rtt2 = coupled_max_cwnd_rtt2(state);
	u64 my_cwnd_rtt2;
	u64 alpha = state->global_alpha;
	u64 increase;
	u64 epsilon_term;

	if (sf->rtt_us == 0)
		return 0;

	/* cwnd_i / rtt_i^2 */
	my_cwnd_rtt2 = div64_u64(sf->cwnd * COUPLED_ALPHA_SCALE,
				 (u64)sf->rtt_us * sf->rtt_us);

	/*
	 * Main increase term:
	 * (cwnd_i / rtt_i^2) / max_j(cwnd_j / rtt_j^2) * alpha / cwnd_total
	 *
	 * Rewrite to avoid overflow: divide first, then multiply.
	 * ratio = my_cwnd_rtt2 / max_cwnd_rtt2 (0..1 in fixed-point)
	 * increase = ratio * alpha / total_cwnd
	 */
	{
		u64 ratio;
		u64 denom;

		ratio = div64_u64(my_cwnd_rtt2 * COUPLED_ALPHA_SCALE,
				  max_cwnd_rtt2);
		denom = total_cwnd ?: 1;
		increase = div64_u64(ratio * (alpha / COUPLED_SCALE + 1),
				     denom);
	}

	/*
	 * Epsilon term for opportunistic increase:
	 * epsilon / cwnd_i
	 *
	 * This allows paths with unused capacity to grow faster.
	 * Guard sf->cwnd * OLIA_EPSILON_DEN against zero denominator.
	 */
	{
		u64 eps_denom = sf->cwnd * OLIA_EPSILON_DEN;

		if (eps_denom == 0)
			eps_denom = 1;
		epsilon_term = div64_u64(COUPLED_ALPHA_SCALE * OLIA_EPSILON_NUM,
					 eps_denom);
	}

	/* Add epsilon only if this path appears to have unused capacity */
	if (sf->rtt_us <= state->best_rtt + SBD_RTT_VARIANCE_THRESH)
		increase += epsilon_term;

	return increase;
}

/*
 * =============================================================================
 * BALIA - Balanced Linked Adaptation
 * =============================================================================
 *
 * BALIA balances between responsiveness and TCP-friendliness, providing
 * better performance in heterogeneous networks.
 *
 * BALIA uses a parameter x to balance the tradeoff:
 *   x = 1: Behaves like OLIA (TCP-friendly)
 *   x > 1: More aggressive (better utilization)
 *   x < 1: More conservative (better fairness)
 */

static u64 balia_calc_x(struct coupled_state *state, struct coupled_subflow *sf)
{
	u64 total_cwnd = coupled_sum_cwnd(state);
	u64 sum_cwnd_rtt = coupled_sum_cwnd_rtt(state);
	u64 x;

	if (sf->rtt_us == 0 || total_cwnd == 0)
		return COUPLED_SCALE;

	/*
	 * x = (cwnd_i / rtt_i) / (sum(cwnd_j / rtt_j) / n)
	 *
	 * This measures how this subflow compares to average
	 */
	x = div64_u64(sf->cwnd * COUPLED_SCALE * state->num_subflows,
		      sf->rtt_us * sum_cwnd_rtt / COUPLED_SCALE + 1);

	/* Clamp x to reasonable bounds */
	x = clamp(x, (u64)BALIA_X_MIN, (u64)(10 * COUPLED_SCALE));

	return x;
}

static u64 balia_calc_increase(struct coupled_state *state,
			       struct coupled_subflow *sf)
{
	u64 total_cwnd = coupled_sum_cwnd(state);
	u64 x = balia_calc_x(state, sf);
	u64 alpha = state->global_alpha;
	u64 increase;

	/*
	 * BALIA increase:
	 * (1 + alpha/x) * alpha / cwnd_total / (1 + alpha)
	 *
	 * When x = 1: reduces to OLIA-like behavior
	 * When x > 1: smaller increase (path is doing well)
	 * When x < 1: larger increase (path needs help)
	 */
	increase = div64_u64((COUPLED_SCALE + alpha * COUPLED_SCALE / x) *
			     alpha,
			     total_cwnd * (COUPLED_SCALE + alpha) + 1);

	return increase;
}

/*
 * =============================================================================
 * Shared Bottleneck Detection (SBD)
 * =============================================================================
 *
 * Detect when multiple subflows share a common bottleneck by analyzing
 * RTT correlation. If RTTs are highly correlated, paths likely share
 * a bottleneck and coupled CC should be more conservative.
 */

/*
 * Calculate Pearson correlation coefficient between two RTT series
 */
static s32 sbd_calc_correlation(u32 *rtt1, u32 *rtt2, u32 len)
{
	s64 sum_x = 0, sum_y = 0;
	s64 sum_xy = 0, sum_x2 = 0, sum_y2 = 0;
	s64 mean_x, mean_y;
	s64 numerator, denominator;
	u32 i;

	if (len < 4)
		return 0;

	/* Calculate means */
	for (i = 0; i < len; i++) {
		sum_x += rtt1[i];
		sum_y += rtt2[i];
	}
	mean_x = div64_s64(sum_x, len);
	mean_y = div64_s64(sum_y, len);

	/* Calculate correlation components */
	for (i = 0; i < len; i++) {
		s64 dx = rtt1[i] - mean_x;
		s64 dy = rtt2[i] - mean_y;

		sum_xy += dx * dy;
		sum_x2 += dx * dx;
		sum_y2 += dy * dy;
	}

	/* Calculate Pearson correlation coefficient */
	denominator = coupled_isqrt(sum_x2) * coupled_isqrt(sum_y2);
	if (denominator == 0)
		return 0;

	numerator = sum_xy * 1000;  /* Scale by 1000 */
	return (s32)div64_s64(numerator, denominator);
}

/*
 * Update shared bottleneck detection state
 */
static void coupled_update_sbd(struct coupled_state *state)
{
	struct coupled_subflow *sf1, *sf2;
	s32 max_corr = 0;
	u32 idx = 0;

	if (state->num_subflows < 2)
		return;

	/* Compare RTT histories pairwise */
	list_for_each_entry(sf1, &state->subflows, list) {
		list_for_each_entry(sf2, &state->subflows, list) {
			s32 corr;

			if (sf1 == sf2)
				continue;

			if (sf1->rtt_history_count < SBD_HISTORY_LEN / 2 ||
			    sf2->rtt_history_count < SBD_HISTORY_LEN / 2)
				continue;

			corr = sbd_calc_correlation(sf1->rtt_history,
						    sf2->rtt_history,
						    min(sf1->rtt_history_count,
							sf2->rtt_history_count));

			if (corr > max_corr)
				max_corr = corr;
		}
		idx++;
	}

	state->sbd.correlation = max_corr;
	state->sbd.detected = (max_corr > SBD_CORR_THRESH);

	if (state->sbd.detected) {
		tquic_dbg("coupled: shared bottleneck detected "
			 "(correlation=%d)\n", max_corr);
	}
}

/*
 * Add RTT sample to history for SBD
 */
static void coupled_sbd_add_sample(struct coupled_subflow *sf, u32 rtt_us)
{
	sf->rtt_history[sf->rtt_history_idx] = rtt_us;
	sf->rtt_history_idx = (sf->rtt_history_idx + 1) % SBD_HISTORY_LEN;
	if (sf->rtt_history_count < SBD_HISTORY_LEN)
		sf->rtt_history_count++;
}

/*
 * =============================================================================
 * CUBIC Integration for Per-Path Congestion Control
 * =============================================================================
 */

#define CUBIC_C		410	/* C = 0.4 scaled by 1024 */
#define CUBIC_BETA	717	/* beta = 0.7 scaled by 1024 */
#define CUBIC_SCALE	1024

static void cubic_update(struct coupled_subflow *sf, u64 now_us)
{
	u64 t, offs, delta;

	if (sf->cubic_epoch_start == 0) {
		sf->cubic_epoch_start = now_us;

		if (sf->cwnd < sf->cubic_w_max) {
			sf->cubic_k = coupled_cbrt(
				(sf->cubic_w_max - sf->cwnd) * CUBIC_SCALE / CUBIC_C);
		} else {
			sf->cubic_k = 0;
		}
	}

	/* Time since epoch in ms */
	t = (now_us - sf->cubic_epoch_start) / 1000;

	/* W_cubic(t) = C(t-K)^3 + W_max */
	if (t < sf->cubic_k) {
		offs = sf->cubic_k - t;
		delta = (CUBIC_C * offs * offs * offs) >> 30;
		sf->cubic_cwnd = sf->cubic_w_max - delta;
	} else {
		offs = t - sf->cubic_k;
		delta = (CUBIC_C * offs * offs * offs) >> 30;
		sf->cubic_cwnd = sf->cubic_w_max + delta;
	}
}

static void cubic_on_loss(struct coupled_subflow *sf)
{
	sf->cubic_w_max = sf->cwnd;
	sf->ssthresh = max(sf->cwnd * CUBIC_BETA / CUBIC_SCALE,
			   (u64)COUPLED_MIN_CWND);
	sf->cwnd = sf->ssthresh;
	sf->cubic_epoch_start = 0;
	sf->in_slow_start = false;
}

/*
 * =============================================================================
 * BBR Integration for Bandwidth Estimation
 * =============================================================================
 */

static void bbr_update_bw(struct coupled_subflow *sf, u64 bytes_acked,
			  u64 rtt_us)
{
	u64 bw_sample;

	if (rtt_us == 0)
		return;

	/* Calculate delivery rate, avoiding u64 overflow */
	bw_sample = div64_u64(bytes_acked * 1000ULL,
			      rtt_us) * 1000ULL;

	/* Max filter for bandwidth */
	if (bw_sample > sf->bbr_bw)
		sf->bbr_bw = bw_sample;
	else
		sf->bbr_bw = (sf->bbr_bw * 15 + bw_sample) / 16;

	/* Update pacing rate */
	sf->bbr_pacing_rate = sf->bbr_bw;
}

static void bbr_update_min_rtt(struct coupled_subflow *sf, u32 rtt_us)
{
	if (rtt_us < sf->bbr_min_rtt || sf->bbr_min_rtt == 0)
		sf->bbr_min_rtt = rtt_us;
}

/*
 * =============================================================================
 * Coupled Alpha Calculation
 * =============================================================================
 *
 * The global alpha controls how aggressively the coupled flows increase
 * their windows. It's designed to make the aggregate behave like a
 * single TCP flow at shared bottlenecks.
 */

static void coupled_update_alpha(struct coupled_state *state)
{
	switch (state->algo) {
	case COUPLED_ALGO_LIA:
		state->global_alpha = lia_calc_alpha(state);
		break;

	case COUPLED_ALGO_OLIA:
		state->global_alpha = olia_calc_alpha(state);
		break;

	case COUPLED_ALGO_BALIA:
		/* BALIA uses per-subflow x parameter instead of global alpha */
		state->global_alpha = olia_calc_alpha(state);
		break;
	}

	/* Adjust alpha based on shared bottleneck detection */
	if (state->sbd.detected) {
		/* More conservative when sharing bottleneck */
		state->global_alpha = state->global_alpha * 7 / 10;
	}

	/* Update aggregate statistics */
	state->total_cwnd = coupled_sum_cwnd(state);
	state->best_rtt = coupled_best_rtt(state);
}

/*
 * Calculate the increase amount for a subflow
 */
static u64 coupled_calc_increase(struct coupled_state *state,
				 struct coupled_subflow *sf)
{
	u64 increase;

	switch (state->algo) {
	case COUPLED_ALGO_LIA:
		increase = lia_calc_increase(state, sf);
		break;

	case COUPLED_ALGO_OLIA:
		increase = olia_calc_increase(state, sf);
		break;

	case COUPLED_ALGO_BALIA:
		increase = balia_calc_increase(state, sf);
		break;

	default:
		increase = div64_u64(COUPLED_ALPHA_SCALE, sf->cwnd);
	}

	return increase;
}

/*
 * =============================================================================
 * Subflow Management
 * =============================================================================
 */

static struct coupled_subflow *coupled_find_subflow(struct coupled_state *state,
						    u32 path_id)
{
	struct coupled_subflow *sf;

	list_for_each_entry(sf, &state->subflows, list) {
		if (sf->path_id == path_id)
			return sf;
	}

	return NULL;
}

static struct coupled_subflow *coupled_add_subflow(struct coupled_state *state,
						   struct tquic_path *path)
{
	struct coupled_subflow *sf;

	sf = kzalloc(sizeof(*sf), GFP_ATOMIC);
	if (!sf)
		return NULL;

	sf->path = path;
	sf->path_id = path->path_id;
	sf->cwnd = COUPLED_INIT_CWND;
	sf->ssthresh = COUPLED_MAX_CWND;
	sf->in_slow_start = true;
	sf->alpha = COUPLED_SCALE;

	/* Initialize CUBIC state */
	sf->cubic_w_max = sf->cwnd;

	spin_lock(&state->lock);
	list_add_tail(&sf->list, &state->subflows);
	state->num_subflows++;
	spin_unlock(&state->lock);

	tquic_dbg("coupled: added subflow for path %u (total: %u)\n",
		 path->path_id, state->num_subflows);

	return sf;
}

static void coupled_remove_subflow(struct coupled_state *state,
				   struct coupled_subflow *sf)
{
	spin_lock(&state->lock);
	list_del(&sf->list);
	state->num_subflows--;
	spin_unlock(&state->lock);

	tquic_dbg("coupled: removed subflow for path %u (total: %u)\n",
		 sf->path_id, state->num_subflows);

	kfree(sf);
}

/*
 * =============================================================================
 * Congestion Control Operations
 * =============================================================================
 */

/*
 * Initialize coupled congestion control for a path
 */
static void *coupled_init(struct tquic_path *path)
{
	struct coupled_state *state;
	struct coupled_subflow *sf;
	struct tquic_connection *conn;

	if (!path)
		return NULL;

	/* Get connection from path (path should be part of connection) */
	conn = container_of(path->list.prev, struct tquic_connection, paths);

	/* Check if coupled state already exists for this connection */
	state = conn->sched_priv;

	if (!state) {
		/* First path - create coupled state */
		state = kzalloc(sizeof(*state), GFP_KERNEL);
		if (!state)
			return NULL;

		state->conn = conn;
		state->algo = COUPLED_ALGO_OLIA;  /* Default to OLIA */
		state->global_alpha = COUPLED_SCALE;
		state->use_cubic = true;
		state->use_bbr = false;

		INIT_LIST_HEAD(&state->subflows);
		spin_lock_init(&state->lock);

		state->sbd.check_interval = 1000;  /* 1 second */

		conn->sched_priv = state;

		tquic_info("coupled: initialized for connection (algo: OLIA)\n");
	}

	/* Add subflow for this path */
	sf = coupled_add_subflow(state, path);
	if (!sf) {
		if (state->num_subflows == 0) {
			kfree(state);
			conn->sched_priv = NULL;
		}
		return NULL;
	}

	/* Update global alpha with new subflow */
	coupled_update_alpha(state);

	return sf;
}

/*
 * Release coupled congestion control for a path
 */
static void coupled_release(void *cong_data)
{
	struct coupled_subflow *sf = cong_data;
	struct coupled_state *state;
	struct tquic_connection *conn;

	if (!sf)
		return;

	/* Find the coupled state */
	conn = container_of(sf->path->list.prev, struct tquic_connection, paths);
	state = conn->sched_priv;

	if (!state)
		return;

	coupled_remove_subflow(state, sf);

	/* Clean up state if last subflow */
	if (state->num_subflows == 0) {
		kfree(state->sbd.corr_matrix);
		kfree(state);
		conn->sched_priv = NULL;
		tquic_info("coupled: released for connection\n");
	} else {
		/* Update alpha without this subflow */
		coupled_update_alpha(state);
	}
}

/*
 * Called when a packet is sent
 */
static void coupled_on_sent(void *cong_data, u64 bytes, ktime_t sent_time)
{
	struct coupled_subflow *sf = cong_data;

	if (!sf)
		return;

	sf->in_flight += bytes;
}

/*
 * Called when an ACK is received - main congestion control logic
 */
static void coupled_on_ack(void *cong_data, u64 bytes_acked, u64 rtt_us)
{
	struct coupled_subflow *sf = cong_data;
	struct coupled_state *state;
	struct tquic_connection *conn;
	u64 increase;
	u64 now_us = ktime_to_us(ktime_get());

	if (!sf || !sf->path)
		return;

	conn = container_of(sf->path->list.prev, struct tquic_connection, paths);
	state = conn->sched_priv;

	if (!state)
		return;

	/* Update RTT */
	if (rtt_us > 0) {
		if (sf->rtt_us == 0)
			sf->rtt_us = rtt_us;
		else
			sf->rtt_us = (sf->rtt_us * 7 + rtt_us) / 8;

		if (sf->rtt_min == 0 || rtt_us < sf->rtt_min)
			sf->rtt_min = rtt_us;

		/* Add to RTT history for SBD */
		coupled_sbd_add_sample(sf, rtt_us);
	}

	/* Update delivery tracking */
	sf->delivered += bytes_acked;
	if (sf->in_flight >= bytes_acked)
		sf->in_flight -= bytes_acked;
	else
		sf->in_flight = 0;

	/* Update BBR bandwidth estimate */
	if (state->use_bbr) {
		bbr_update_bw(sf, bytes_acked, rtt_us);
		bbr_update_min_rtt(sf, rtt_us);
	}

	/* Slow start */
	if (sf->in_slow_start) {
		sf->cwnd += bytes_acked;

		/* Exit slow start if cwnd >= ssthresh */
		if (sf->cwnd >= sf->ssthresh) {
			sf->in_slow_start = false;
			tquic_dbg("coupled: path %u exiting slow start "
				 "(cwnd=%llu)\n", sf->path_id, sf->cwnd);
		}

		goto update_path;
	}

	/* Congestion avoidance - coupled increase */

	/* Periodically update shared bottleneck detection */
	if (now_us - state->sbd.last_check >
	    state->sbd.check_interval * 1000) {
		coupled_update_sbd(state);
		state->sbd.last_check = now_us;
	}

	/* Update global alpha */
	coupled_update_alpha(state);

	/* Update CUBIC if enabled */
	if (state->use_cubic)
		cubic_update(sf, now_us);

	/* Calculate coupled increase */
	increase = coupled_calc_increase(state, sf);

	/* Scale increase by bytes_acked */
	increase = increase * bytes_acked / COUPLED_ALPHA_SCALE;

	/* If CUBIC is enabled, take max of coupled and CUBIC increase */
	if (state->use_cubic && sf->cubic_cwnd > sf->cwnd && sf->cwnd > 0) {
		u64 cubic_inc = sf->cubic_cwnd - sf->cwnd;

		cubic_inc = div64_u64(cubic_inc * bytes_acked, sf->cwnd);
		increase = max(increase, cubic_inc);
	}

	/* Apply increase */
	sf->cwnd += increase;

	/* Clamp cwnd */
	sf->cwnd = clamp(sf->cwnd, (u64)COUPLED_MIN_CWND, COUPLED_MAX_CWND);

update_path:
	/* Update path statistics */
	if (sf->path) {
		sf->path->stats.cwnd = (u32)min(sf->cwnd, (u64)UINT_MAX);
		if (sf->rtt_us > 0)
			sf->path->stats.rtt_smoothed = sf->rtt_us;
		if (state->use_bbr)
			sf->path->stats.bandwidth = sf->bbr_bw;
	}
}

/*
 * Called on packet loss
 */
static void coupled_on_loss(void *cong_data, u64 bytes_lost)
{
	struct coupled_subflow *sf = cong_data;
	struct coupled_state *state;
	struct tquic_connection *conn;

	if (!sf || !sf->path)
		return;

	conn = container_of(sf->path->list.prev, struct tquic_connection, paths);
	state = conn->sched_priv;

	if (!state)
		return;

	sf->lost += bytes_lost;
	sf->loss_in_round = true;

	/* Use CUBIC loss response */
	if (state->use_cubic)
		cubic_on_loss(sf);
	else {
		/* Standard multiplicative decrease */
		sf->ssthresh = max(sf->cwnd / 2, (u64)COUPLED_MIN_CWND);
		sf->cwnd = sf->ssthresh;
	}

	sf->in_slow_start = false;

	/* Update path stats */
	if (sf->path)
		sf->path->stats.cwnd = (u32)min(sf->cwnd, (u64)UINT_MAX);

	tquic_warn("coupled: loss on path %u, cwnd=%llu ssthresh=%llu\n",
		 sf->path_id, sf->cwnd, sf->ssthresh);

	/* Update global alpha after loss */
	coupled_update_alpha(state);
}

/*
 * Called on RTT update
 */
static void coupled_on_rtt(void *cong_data, u64 rtt_us)
{
	struct coupled_subflow *sf = cong_data;

	if (!sf)
		return;

	/* Update minimum RTT */
	if (sf->rtt_min == 0 || rtt_us < sf->rtt_min)
		sf->rtt_min = rtt_us;

	/* Update smoothed RTT */
	if (sf->rtt_us == 0)
		sf->rtt_us = rtt_us;
	else
		sf->rtt_us = (sf->rtt_us * 7 + rtt_us) / 8;

	/* RTT variance */
	if (sf->rtt_var == 0)
		sf->rtt_var = rtt_us / 2;
	else {
		s64 delta = (s64)rtt_us - sf->rtt_us;
		sf->rtt_var = (sf->rtt_var * 3 + abs(delta)) / 4;
	}
}

/*
 * Get current congestion window
 */
static u64 coupled_get_cwnd(void *cong_data)
{
	struct coupled_subflow *sf = cong_data;

	if (!sf)
		return COUPLED_INIT_CWND;

	return sf->cwnd;
}

/*
 * Get current pacing rate
 */
static u64 coupled_get_pacing_rate(void *cong_data)
{
	struct coupled_subflow *sf = cong_data;

	if (!sf)
		return 0;

	/* Use BBR pacing rate if available */
	if (sf->bbr_pacing_rate > 0)
		return sf->bbr_pacing_rate;

	/* Estimate based on cwnd and RTT, avoid overflow */
	if (sf->rtt_us > 0)
		return div64_u64(sf->cwnd * 1000ULL, sf->rtt_us) * 1000ULL;

	return sf->cwnd * 10;  /* Fallback */
}

/*
 * Check if we can send more data
 */
static bool coupled_can_send(void *cong_data, u64 bytes)
{
	struct coupled_subflow *sf = cong_data;

	if (!sf)
		return true;

	return sf->in_flight + bytes <= sf->cwnd;
}

/*
 * Called on persistent congestion (RFC 9002 Section 7.6)
 *
 * For coupled CC, persistent congestion on one subflow affects
 * only that subflow's cwnd (per CONTEXT.md: "Loss on one path
 * reduces only that path's CWND").
 *
 * However, we must recalculate the global alpha after resetting
 * this subflow, which may affect increase rates on other paths.
 */
static void coupled_on_persistent_cong(void *cong_data,
				       struct tquic_persistent_cong_info *info)
{
	struct coupled_subflow *sf = cong_data;
	struct coupled_state *state;
	struct tquic_connection *conn;

	if (!sf || !sf->path || !info)
		return;

	conn = container_of(sf->path->list.prev, struct tquic_connection, paths);
	state = conn->sched_priv;

	tquic_warn("coupled: persistent congestion on path %u, cwnd %llu -> %llu\n",
		sf->path_id, sf->cwnd, info->min_cwnd);

	/* Reset this subflow's cwnd to minimum per RFC 9002 */
	sf->cwnd = info->min_cwnd;
	sf->ssthresh = info->min_cwnd;
	sf->in_slow_start = false;

	/* Reset CUBIC state for this subflow */
	sf->cubic_w_max = info->min_cwnd;
	sf->cubic_epoch_start = 0;

	/* Reset BBR state for this subflow */
	sf->bbr_bw = 0;

	/* Clear in-flight tracking */
	sf->in_flight = 0;

	/* Mark loss in round */
	sf->loss_in_round = true;

	/* Update path stats */
	if (sf->path)
		sf->path->stats.cwnd = (u32)min(sf->cwnd, (u64)UINT_MAX);

	/* Recalculate global alpha after this subflow's reset */
	if (state)
		coupled_update_alpha(state);
}

/*
 * =============================================================================
 * Module Interface
 * =============================================================================
 */

/* Congestion control operations for registration */
static struct tquic_cong_ops tquic_coupled_ops = {
	.name = "coupled",
	.owner = THIS_MODULE,
	.init = coupled_init,
	.release = coupled_release,
	.on_packet_sent = coupled_on_sent,
	.on_ack = coupled_on_ack,
	.on_loss = coupled_on_loss,
	.on_rtt_update = coupled_on_rtt,
	.on_persistent_congestion = coupled_on_persistent_cong,
	.get_cwnd = coupled_get_cwnd,
	.get_pacing_rate = coupled_get_pacing_rate,
	.can_send = coupled_can_send,
};

/* OLIA-specific registration */
static struct tquic_cong_ops tquic_olia_ops = {
	.name = "olia",
	.owner = THIS_MODULE,
	.init = coupled_init,
	.release = coupled_release,
	.on_packet_sent = coupled_on_sent,
	.on_ack = coupled_on_ack,
	.on_loss = coupled_on_loss,
	.on_rtt_update = coupled_on_rtt,
	.on_persistent_congestion = coupled_on_persistent_cong,
	.get_cwnd = coupled_get_cwnd,
	.get_pacing_rate = coupled_get_pacing_rate,
	.can_send = coupled_can_send,
};

/* LIA-specific registration */
static struct tquic_cong_ops tquic_lia_ops = {
	.name = "lia",
	.owner = THIS_MODULE,
	.init = coupled_init,
	.release = coupled_release,
	.on_packet_sent = coupled_on_sent,
	.on_ack = coupled_on_ack,
	.on_loss = coupled_on_loss,
	.on_rtt_update = coupled_on_rtt,
	.on_persistent_congestion = coupled_on_persistent_cong,
	.get_cwnd = coupled_get_cwnd,
	.get_pacing_rate = coupled_get_pacing_rate,
	.can_send = coupled_can_send,
};

/* BALIA-specific registration */
static struct tquic_cong_ops tquic_balia_ops = {
	.name = "balia",
	.owner = THIS_MODULE,
	.init = coupled_init,
	.release = coupled_release,
	.on_packet_sent = coupled_on_sent,
	.on_ack = coupled_on_ack,
	.on_loss = coupled_on_loss,
	.on_rtt_update = coupled_on_rtt,
	.on_persistent_congestion = coupled_on_persistent_cong,
	.get_cwnd = coupled_get_cwnd,
	.get_pacing_rate = coupled_get_pacing_rate,
	.can_send = coupled_can_send,
};

/*
 * =============================================================================
 * Sysctl Interface for Runtime Configuration
 * =============================================================================
 */

static int coupled_default_algo = COUPLED_ALGO_OLIA;
static int coupled_use_cubic = 1;
static int coupled_use_bbr = 0;
static int coupled_sbd_enabled = 1;

/*
 * =============================================================================
 * Proc Interface for Statistics
 * =============================================================================
 */

#ifdef CONFIG_PROC_FS
#include <linux/proc_fs.h>
#include <linux/seq_file.h>

static int coupled_stats_show(struct seq_file *m, void *v)
{
	seq_puts(m, "TQUIC Coupled Congestion Control Statistics\n");
	seq_puts(m, "============================================\n");
	seq_printf(m, "Default algorithm: %s\n",
		   coupled_default_algo == COUPLED_ALGO_LIA ? "LIA" :
		   coupled_default_algo == COUPLED_ALGO_OLIA ? "OLIA" : "BALIA");
	seq_printf(m, "CUBIC integration: %s\n", coupled_use_cubic ? "yes" : "no");
	seq_printf(m, "BBR integration: %s\n", coupled_use_bbr ? "yes" : "no");
	seq_printf(m, "SBD enabled: %s\n", coupled_sbd_enabled ? "yes" : "no");

	return 0;
}

static int coupled_stats_open(struct inode *inode, struct file *file)
{
	return single_open(file, coupled_stats_show, NULL);
}

static const struct proc_ops coupled_stats_ops = {
	.proc_open = coupled_stats_open,
	.proc_read = seq_read,
	.proc_lseek = seq_lseek,
	.proc_release = single_release,
};

static struct proc_dir_entry *coupled_proc_dir;
#endif /* CONFIG_PROC_FS */

/*
 * =============================================================================
 * Connection-Level Coupled CC API
 * =============================================================================
 *
 * These functions provide the connection-level API for coupled CC that is
 * called by tquic_cong.c coordination layer.
 *
 * Per CONTEXT.md: "Coupled CC is opt-in via sysctl/sockopt"
 * Per RESEARCH.md: "OLIA as default" coupled algorithm
 */

/*
 * tquic_coupled_create - Create coupled CC state for a connection
 * @conn: Connection to create coupled state for
 * @algo: Coupled algorithm (OLIA, LIA, or BALIA)
 *
 * Allocates and initializes connection-level coupled CC state.
 * OLIA is the default per RESEARCH.md recommendation.
 *
 * Return: Pointer to coupled state, or NULL on failure
 */
struct tquic_coupled_state *tquic_coupled_create(struct tquic_connection *conn,
						  enum tquic_coupled_algo algo)
{
	struct coupled_state *state;

	if (!conn)
		return NULL;

	state = kzalloc(sizeof(*state), GFP_KERNEL);
	if (!state)
		return NULL;

	state->conn = conn;

	/* Map external enum to internal enum */
	switch (algo) {
	case TQUIC_COUPLED_LIA:
		state->algo = COUPLED_ALGO_LIA;
		break;
	case TQUIC_COUPLED_BALIA:
		state->algo = COUPLED_ALGO_BALIA;
		break;
	case TQUIC_COUPLED_OLIA:
	default:
		state->algo = COUPLED_ALGO_OLIA;  /* Default to OLIA */
		break;
	}

	state->global_alpha = COUPLED_SCALE;
	state->use_cubic = coupled_use_cubic;
	state->use_bbr = coupled_use_bbr;

	INIT_LIST_HEAD(&state->subflows);
	spin_lock_init(&state->lock);

	state->sbd.check_interval = 1000;  /* 1 second */

	tquic_info("coupled: created coupled state (algo=%d)\n", state->algo);

	return (struct tquic_coupled_state *)state;
}
EXPORT_SYMBOL_GPL(tquic_coupled_create);

/*
 * tquic_coupled_destroy - Destroy coupled CC state
 * @cstate: Coupled state to destroy
 *
 * Releases all resources associated with coupled CC state.
 * All paths should be detached before calling this.
 */
void tquic_coupled_destroy(struct tquic_coupled_state *cstate)
{
	struct coupled_state *state = (struct coupled_state *)cstate;
	struct coupled_subflow *sf, *tmp;

	if (!state)
		return;

	/* Remove any remaining subflows */
	spin_lock(&state->lock);
	list_for_each_entry_safe(sf, tmp, &state->subflows, list) {
		list_del(&sf->list);
		kfree(sf);
	}
	spin_unlock(&state->lock);

	/* Free correlation matrix if allocated */
	kfree(state->sbd.corr_matrix);
	kfree(state);

	tquic_info("coupled: destroyed coupled state\n");
}
EXPORT_SYMBOL_GPL(tquic_coupled_destroy);

/*
 * tquic_coupled_attach_path - Attach a path to coupled CC
 * @cstate: Coupled CC state
 * @path: Path to attach
 *
 * Creates a subflow for the path and integrates it into coupled CC.
 * The path will participate in coupled CWND coordination.
 *
 * Return: 0 on success, -errno on failure
 */
int tquic_coupled_attach_path(struct tquic_coupled_state *cstate,
			      struct tquic_path *path)
{
	struct coupled_state *state = (struct coupled_state *)cstate;
	struct coupled_subflow *sf;

	if (!state || !path)
		return -EINVAL;

	/* Check if already attached under lock */
	spin_lock(&state->lock);
	sf = coupled_find_subflow(state, path->path_id);
	if (sf) {
		spin_unlock(&state->lock);
		tquic_dbg("coupled: path %u already attached\n",
			 path->path_id);
		return -EEXIST;
	}
	spin_unlock(&state->lock);

	/* Add subflow for this path (takes lock internally) */
	sf = coupled_add_subflow(state, path);
	if (!sf)
		return -ENOMEM;

	/* Update global alpha with new subflow */
	coupled_update_alpha(state);

	tquic_dbg("coupled: attached path %u\n", path->path_id);
	return 0;
}
EXPORT_SYMBOL_GPL(tquic_coupled_attach_path);

/*
 * tquic_coupled_detach_path - Detach a path from coupled CC
 * @cstate: Coupled CC state
 * @path: Path to detach
 *
 * Removes the path's subflow from coupled CC.
 * The path will no longer participate in coupled CWND coordination.
 */
void tquic_coupled_detach_path(struct tquic_coupled_state *cstate,
			       struct tquic_path *path)
{
	struct coupled_state *state = (struct coupled_state *)cstate;
	struct coupled_subflow *sf;

	if (!state || !path)
		return;

	spin_lock(&state->lock);
	sf = coupled_find_subflow(state, path->path_id);
	if (!sf) {
		spin_unlock(&state->lock);
		tquic_dbg("coupled: path %u not attached\n", path->path_id);
		return;
	}
	spin_unlock(&state->lock);

	/* Remove subflow (takes lock internally) */
	coupled_remove_subflow(state, sf);

	/* Update alpha without this subflow */
	if (state->num_subflows > 0)
		coupled_update_alpha(state);

	tquic_dbg("coupled: detached path %u\n", path->path_id);
}
EXPORT_SYMBOL_GPL(tquic_coupled_detach_path);

/*
 * tquic_coupled_on_ack_ext - External ACK handler for coupled CC
 * @cstate: Coupled CC state
 * @path: Path that received the ACK
 * @bytes_acked: Number of bytes acknowledged
 * @rtt_us: RTT sample in microseconds
 *
 * Called by the CC framework to process ACK events through coupled CC.
 * This coordinates CWND updates across all paths.
 */
void tquic_coupled_on_ack_ext(struct tquic_coupled_state *cstate,
			      struct tquic_path *path,
			      u64 bytes_acked, u64 rtt_us)
{
	struct coupled_state *state = (struct coupled_state *)cstate;
	struct coupled_subflow *sf;

	if (!state || !path)
		return;

	sf = coupled_find_subflow(state, path->path_id);
	if (!sf) {
		tquic_dbg("coupled: ACK on unattached path %u\n",
			 path->path_id);
		return;
	}

	/* Delegate to internal ACK handler */
	coupled_on_ack(sf, bytes_acked, rtt_us);
}
EXPORT_SYMBOL_GPL(tquic_coupled_on_ack_ext);

/*
 * tquic_coupled_on_loss_ext - External loss handler for coupled CC
 * @cstate: Coupled CC state
 * @path: Path that experienced loss
 * @bytes_lost: Number of bytes lost
 *
 * Called by the CC framework to process loss events through coupled CC.
 * Per CONTEXT.md: "Loss on one path reduces only that path's CWND"
 * Coupled CC redistributes traffic to other paths but does not reduce their CWND.
 */
void tquic_coupled_on_loss_ext(struct tquic_coupled_state *cstate,
			       struct tquic_path *path,
			       u64 bytes_lost)
{
	struct coupled_state *state = (struct coupled_state *)cstate;
	struct coupled_subflow *sf;

	if (!state || !path)
		return;

	sf = coupled_find_subflow(state, path->path_id);
	if (!sf) {
		tquic_dbg("coupled: loss on unattached path %u\n",
			 path->path_id);
		return;
	}

	/* Delegate to internal loss handler - only affects this path's CWND */
	coupled_on_loss(sf, bytes_lost);
}
EXPORT_SYMBOL_GPL(tquic_coupled_on_loss_ext);

/*
 * =============================================================================
 * Module Init/Exit
 * =============================================================================
 */

static int __init __maybe_unused tquic_coupled_init(void)
{
	int ret;

	tquic_info("coupled: initializing multipath congestion control\n");

	/* Register all algorithm variants */
	ret = tquic_register_cong(&tquic_coupled_ops);
	if (ret) {
		tquic_err("coupled: failed to register 'coupled'\n");
		return ret;
	}

	ret = tquic_register_cong(&tquic_olia_ops);
	if (ret) {
		tquic_err("coupled: failed to register 'olia'\n");
		goto err_olia;
	}

	ret = tquic_register_cong(&tquic_lia_ops);
	if (ret) {
		tquic_err("coupled: failed to register 'lia'\n");
		goto err_lia;
	}

	ret = tquic_register_cong(&tquic_balia_ops);
	if (ret) {
		tquic_err("coupled: failed to register 'balia'\n");
		goto err_balia;
	}

#ifdef CONFIG_PROC_FS
	coupled_proc_dir = proc_mkdir("tquic_coupled", NULL);
	if (coupled_proc_dir) {
		proc_create("stats", 0444, coupled_proc_dir, &coupled_stats_ops);
	}
#endif

	tquic_info("coupled: registered algorithms: coupled, olia, lia, balia\n");
	tquic_info("coupled: features: SBD=%d, CUBIC=%d, BBR=%d\n",
		coupled_sbd_enabled, coupled_use_cubic, coupled_use_bbr);

	return 0;

err_balia:
	tquic_unregister_cong(&tquic_lia_ops);
err_lia:
	tquic_unregister_cong(&tquic_olia_ops);
err_olia:
	tquic_unregister_cong(&tquic_coupled_ops);
	return ret;
}

static void __exit __maybe_unused tquic_coupled_exit(void)
{
	tquic_info("coupled: unloading multipath congestion control\n");

#ifdef CONFIG_PROC_FS
	if (coupled_proc_dir) {
		remove_proc_entry("stats", coupled_proc_dir);
		remove_proc_entry("tquic_coupled", NULL);
	}
#endif

	tquic_unregister_cong(&tquic_balia_ops);
	tquic_unregister_cong(&tquic_lia_ops);
	tquic_unregister_cong(&tquic_olia_ops);
	tquic_unregister_cong(&tquic_coupled_ops);

	tquic_info("coupled: unloaded\n");
}

#ifndef TQUIC_OUT_OF_TREE
module_init(tquic_coupled_init);
module_exit(tquic_coupled_exit);

MODULE_DESCRIPTION("TQUIC Coupled Multipath Congestion Control (OLIA/LIA/BALIA)");
MODULE_AUTHOR("Linux Foundation");
MODULE_LICENSE("GPL");
MODULE_ALIAS("tquic-cong-coupled");
MODULE_ALIAS("tquic-cong-olia");
MODULE_ALIAS("tquic-cong-lia");
MODULE_ALIAS("tquic-cong-balia");
#endif
