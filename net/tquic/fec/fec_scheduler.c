// SPDX-License-Identifier: GPL-2.0-only
/*
 * TQUIC FEC Scheduler
 *
 * Copyright (c) 2026 Linux Foundation
 *
 * Adaptive FEC rate scheduling for QUIC based on observed loss patterns.
 * Decides when and how many repair symbols to send.
 *
 * The scheduler monitors packet loss and adjusts the FEC rate to balance
 * recovery capability against bandwidth overhead:
 *   - Low loss: Minimal FEC (e.g., 5% overhead)
 *   - Medium loss: Moderate FEC (e.g., 10-20% overhead)
 *   - High loss: Aggressive FEC (e.g., 30-50% overhead)
 *
 * Integration with loss detection:
 *   - Receives loss reports from the QUIC loss detection module
 *   - Uses EWMA to smooth loss rate estimates
 *   - Triggers immediate repair when block has losses and repair is ready
 */

#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/ktime.h>

#include "fec.h"

/* Default FEC rate parameters (percent) */
#define FEC_DEFAULT_RATE	10	/* 10% overhead */
#define FEC_MIN_RATE		2	/* Minimum 2% */
#define FEC_MAX_RATE		50	/* Maximum 50% */

/* Loss rate thresholds (permille = parts per thousand) */
#define LOSS_THRESHOLD_LOW	10	/* 1% loss */
#define LOSS_THRESHOLD_MEDIUM	50	/* 5% loss */
#define LOSS_THRESHOLD_HIGH	100	/* 10% loss */

/* EWMA smoothing factor (1/16 = 6.25%) */
#define EWMA_SHIFT		4

/* Rate adjustment parameters */
#define RATE_ADJUST_INTERVAL_MS	100	/* Adjust rate every 100ms */
#define RATE_INCREASE_STEP	5	/* Increase by 5% */
#define RATE_DECREASE_STEP	2	/* Decrease by 2% */

/* Default window size for loss tracking */
#define DEFAULT_LOSS_WINDOW	100

/**
 * tquic_fec_scheduler_init - Initialize FEC scheduler
 * @state: FEC state
 * @initial_rate: Initial FEC rate (percent)
 * @adaptive: Enable adaptive rate adjustment
 *
 * Return: 0 on success, negative error on failure
 */
int tquic_fec_scheduler_init(struct tquic_fec_state *state,
			     u8 initial_rate, bool adaptive)
{
	struct tquic_fec_scheduler *sched;

	if (!state)
		return -EINVAL;

	sched = &state->scheduler;

	spin_lock_init(&sched->lock);

	sched->target_fec_rate = initial_rate ?
				min_t(u8, initial_rate, 100) :
				FEC_DEFAULT_RATE;
	sched->min_fec_rate = FEC_MIN_RATE;
	sched->max_fec_rate = FEC_MAX_RATE;
	sched->adaptive = adaptive;
	sched->loss_window = DEFAULT_LOSS_WINDOW;
	sched->loss_count = 0;
	sched->packet_count = 0;
	sched->current_loss_rate = 0;
	sched->last_adjustment = ktime_get();

	return 0;
}
EXPORT_SYMBOL_GPL(tquic_fec_scheduler_init);

/**
 * tquic_fec_scheduler_destroy - Clean up FEC scheduler
 * @state: FEC state
 */
void tquic_fec_scheduler_destroy(struct tquic_fec_state *state)
{
	/* Nothing to free currently, but keep for future expansion */
}
EXPORT_SYMBOL_GPL(tquic_fec_scheduler_destroy);

/**
 * update_loss_rate - Update EWMA loss rate estimate
 * @sched: FEC scheduler
 *
 * Computes an exponentially weighted moving average of the loss rate.
 */
static void update_loss_rate(struct tquic_fec_scheduler *sched)
{
	u32 new_rate;

	if (sched->packet_count == 0) {
		sched->current_loss_rate = 0;
		return;
	}

	/*
	 * Calculate current window loss rate (permille).
	 * Use u64 intermediate to prevent u32 overflow on loss_count * 1000.
	 */
	new_rate = (u32)div64_u64((u64)sched->loss_count * 1000,
				  sched->packet_count);
	if (new_rate > 1000)
		new_rate = 1000;

	/* EWMA: new_avg = old_avg + (new_sample - old_avg) / 16 */
	sched->current_loss_rate = sched->current_loss_rate +
		((s32)new_rate - (s32)sched->current_loss_rate) /
		(1 << EWMA_SHIFT);
}

/**
 * tquic_fec_report_loss - Report packet loss to scheduler
 * @state: FEC state
 * @pkt_num: Lost packet number
 *
 * Called by loss detection when a packet is declared lost.
 */
void tquic_fec_report_loss(struct tquic_fec_state *state, u64 pkt_num)
{
	struct tquic_fec_scheduler *sched;

	if (!state)
		return;

	sched = &state->scheduler;

	spin_lock_bh(&sched->lock);

	sched->loss_count++;
	sched->packet_count++;

	/* Update loss rate estimate */
	update_loss_rate(sched);

	/* Reset window if full */
	if (sched->packet_count >= sched->loss_window) {
		sched->loss_count = sched->loss_count >> 1;
		sched->packet_count = sched->packet_count >> 1;
	}

	spin_unlock_bh(&sched->lock);
}
EXPORT_SYMBOL_GPL(tquic_fec_report_loss);

/**
 * tquic_fec_report_ack - Report packet acknowledgment to scheduler
 * @state: FEC state
 * @pkt_num: Acknowledged packet number
 *
 * Called when a packet is acknowledged, for loss rate tracking.
 */
void tquic_fec_report_ack(struct tquic_fec_state *state, u64 pkt_num)
{
	struct tquic_fec_scheduler *sched;

	if (!state)
		return;

	sched = &state->scheduler;

	spin_lock_bh(&sched->lock);

	sched->packet_count++;

	/* Update loss rate estimate */
	update_loss_rate(sched);

	/* Reset window if full */
	if (sched->packet_count >= sched->loss_window) {
		sched->loss_count = sched->loss_count >> 1;
		sched->packet_count = sched->packet_count >> 1;
	}

	spin_unlock_bh(&sched->lock);
}
EXPORT_SYMBOL_GPL(tquic_fec_report_ack);

/**
 * tquic_fec_adjust_rate - Adjust FEC rate based on loss statistics
 * @state: FEC state
 *
 * Called periodically to adapt the FEC rate to observed loss patterns.
 */
void tquic_fec_adjust_rate(struct tquic_fec_state *state)
{
	struct tquic_fec_scheduler *sched;
	ktime_t now;
	s64 elapsed_ms;
	u8 new_rate;

	if (!state)
		return;

	sched = &state->scheduler;

	if (!sched->adaptive)
		return;

	spin_lock_bh(&sched->lock);

	now = ktime_get();
	elapsed_ms = ktime_ms_delta(now, sched->last_adjustment);

	/* Only adjust at intervals */
	if (elapsed_ms < RATE_ADJUST_INTERVAL_MS) {
		spin_unlock_bh(&sched->lock);
		return;
	}

	sched->last_adjustment = now;
	new_rate = sched->target_fec_rate;

	/*
	 * Adjust FEC rate based on loss rate:
	 *   - Very low loss (< 1%): Decrease rate
	 *   - Low loss (1-5%): Maintain rate
	 *   - Medium loss (5-10%): Increase rate moderately
	 *   - High loss (> 10%): Increase rate aggressively
	 */
	if (sched->current_loss_rate < LOSS_THRESHOLD_LOW) {
		/* Very low loss - reduce overhead */
		if (new_rate > sched->min_fec_rate + RATE_DECREASE_STEP)
			new_rate -= RATE_DECREASE_STEP;
		else
			new_rate = sched->min_fec_rate;
	} else if (sched->current_loss_rate < LOSS_THRESHOLD_MEDIUM) {
		/* Low loss - maintain current rate */
	} else if (sched->current_loss_rate < LOSS_THRESHOLD_HIGH) {
		/* Medium loss - increase rate */
		if (new_rate + RATE_INCREASE_STEP <= sched->max_fec_rate)
			new_rate += RATE_INCREASE_STEP;
		else
			new_rate = sched->max_fec_rate;
	} else {
		/* High loss - increase rate aggressively */
		if (new_rate + RATE_INCREASE_STEP * 2 <= sched->max_fec_rate)
			new_rate += RATE_INCREASE_STEP * 2;
		else
			new_rate = sched->max_fec_rate;
	}

	sched->target_fec_rate = new_rate;

	spin_unlock_bh(&sched->lock);
}
EXPORT_SYMBOL_GPL(tquic_fec_adjust_rate);

/**
 * tquic_fec_should_send_repair - Decide if repair symbol should be sent
 * @state: FEC state
 * @pkt_num: Current packet number
 *
 * Decision logic for when to send repair symbols:
 *   1. Always send when a source block is complete
 *   2. Consider proactive repair based on FEC rate
 *   3. Check if there are pending repair symbols to send
 *
 * Return: true if repair should be sent
 */
bool tquic_fec_should_send_repair(struct tquic_fec_state *state, u64 pkt_num)
{
	struct tquic_fec_encoder *enc;
	struct tquic_fec_scheduler *sched;
	bool should_send = false;
	u32 repair_interval;

	if (!state || !state->enabled)
		return false;

	enc = &state->encoder;
	sched = &state->scheduler;

	spin_lock_bh(&enc->lock);
	spin_lock(&sched->lock);

	/* Check if there are pending repairs */
	if (!list_empty(&enc->pending_blocks)) {
		should_send = true;
		goto out;
	}

	/*
	 * Calculate repair interval based on FEC rate
	 * FEC rate of 10% means send repair every 10 source packets
	 */
	if (sched->target_fec_rate > 0) {
		repair_interval = 100 / sched->target_fec_rate;

		/*
		 * Proactive repair: send based on interval
		 * This ensures repair symbols are sent even if block isn't full
		 */
		if (enc->symbols_in_block > 0 &&
		    enc->symbols_in_block >= repair_interval) {
			should_send = true;
		}
	}

	/*
	 * High loss mode: more aggressive repair
	 * Send repair earlier when loss rate is high
	 */
	if (sched->current_loss_rate >= LOSS_THRESHOLD_HIGH &&
	    enc->symbols_in_block >= enc->block_size / 2) {
		should_send = true;
	}

out:
	spin_unlock(&sched->lock);
	spin_unlock_bh(&enc->lock);

	return should_send;
}
EXPORT_SYMBOL_GPL(tquic_fec_should_send_repair);

/**
 * tquic_fec_get_current_rate - Get current FEC rate
 * @state: FEC state
 *
 * Return: Current FEC rate (percent)
 */
u8 tquic_fec_get_current_rate(struct tquic_fec_state *state)
{
	struct tquic_fec_scheduler *sched;
	u8 rate;

	if (!state)
		return 0;

	sched = &state->scheduler;

	spin_lock_bh(&sched->lock);
	rate = sched->target_fec_rate;
	spin_unlock_bh(&sched->lock);

	return rate;
}
EXPORT_SYMBOL_GPL(tquic_fec_get_current_rate);

/**
 * tquic_fec_set_rate_bounds - Set FEC rate bounds
 * @state: FEC state
 * @min_rate: Minimum FEC rate (percent)
 * @max_rate: Maximum FEC rate (percent)
 *
 * Return: 0 on success, negative error on failure
 */
int tquic_fec_set_rate_bounds(struct tquic_fec_state *state,
			      u8 min_rate, u8 max_rate)
{
	struct tquic_fec_scheduler *sched;

	if (!state)
		return -EINVAL;

	if (min_rate > max_rate || max_rate > 100)
		return -EINVAL;

	sched = &state->scheduler;

	spin_lock_bh(&sched->lock);

	sched->min_fec_rate = min_rate;
	sched->max_fec_rate = max_rate;

	/* Clamp current rate to new bounds */
	if (sched->target_fec_rate < min_rate)
		sched->target_fec_rate = min_rate;
	else if (sched->target_fec_rate > max_rate)
		sched->target_fec_rate = max_rate;

	spin_unlock_bh(&sched->lock);

	return 0;
}
EXPORT_SYMBOL_GPL(tquic_fec_set_rate_bounds);

/**
 * tquic_fec_get_loss_rate - Get current estimated loss rate
 * @state: FEC state
 *
 * Return: Current loss rate in permille (parts per thousand)
 */
u32 tquic_fec_get_loss_rate(struct tquic_fec_state *state)
{
	struct tquic_fec_scheduler *sched;
	u32 rate;

	if (!state)
		return 0;

	sched = &state->scheduler;

	spin_lock_bh(&sched->lock);
	rate = sched->current_loss_rate;
	spin_unlock_bh(&sched->lock);

	return rate;
}
EXPORT_SYMBOL_GPL(tquic_fec_get_loss_rate);

/**
 * tquic_fec_scheduler_reset - Reset scheduler statistics
 * @state: FEC state
 *
 * Resets loss tracking for new connection phase.
 */
void tquic_fec_scheduler_reset(struct tquic_fec_state *state)
{
	struct tquic_fec_scheduler *sched;

	if (!state)
		return;

	sched = &state->scheduler;

	spin_lock_bh(&sched->lock);

	sched->loss_count = 0;
	sched->packet_count = 0;
	sched->current_loss_rate = 0;
	sched->last_adjustment = ktime_get();

	spin_unlock_bh(&sched->lock);
}
EXPORT_SYMBOL_GPL(tquic_fec_scheduler_reset);

/**
 * tquic_fec_compute_repair_count - Compute number of repair symbols to generate
 * @state: FEC state
 * @block_size: Number of source symbols in block
 *
 * Returns the recommended number of repair symbols based on current FEC rate.
 *
 * Return: Number of repair symbols to generate
 */
u8 tquic_fec_compute_repair_count(struct tquic_fec_state *state, u8 block_size)
{
	struct tquic_fec_scheduler *sched;
	u32 repair_count;

	if (!state || block_size == 0)
		return 1;

	sched = &state->scheduler;

	spin_lock_bh(&sched->lock);

	/* repair_count = block_size * fec_rate / 100 */
	repair_count = ((u32)block_size * sched->target_fec_rate + 99) / 100;

	/* Ensure at least 1 repair symbol */
	if (repair_count < 1)
		repair_count = 1;

	/* Cap at max repair symbols */
	if (repair_count > TQUIC_FEC_MAX_REPAIR_SYMBOLS)
		repair_count = TQUIC_FEC_MAX_REPAIR_SYMBOLS;

	spin_unlock_bh(&sched->lock);

	return (u8)repair_count;
}
EXPORT_SYMBOL_GPL(tquic_fec_compute_repair_count);
