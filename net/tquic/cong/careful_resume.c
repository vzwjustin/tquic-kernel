// SPDX-License-Identifier: GPL-2.0-only
/*
 * TQUIC: Careful Resume Implementation
 *
 * Copyright (c) 2026 Justin Adams <spotty118@gmail.com>
 * Kernel implementation by Justin Adams <spotty118@gmail.com>
 *
 * Implementation of the Careful Resume algorithm for safe restoration
 * of congestion control state, as specified in the BDP Frame extension
 * (draft-kuhn-quic-bdpframe-extension-05).
 *
 * Careful Resume allows endpoints to safely use saved congestion control
 * values when reconnecting, by gradually increasing the cwnd toward
 * the saved value while monitoring for congestion signals.
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <net/tquic.h>

#include "bdp_frame.h"
#include "tquic_cong.h"
#include "../protocol.h"
#include "../tquic_debug.h"

/*
 * Careful Resume Parameters
 *
 * These follow the recommendations in draft-kuhn-quic-bdpframe-extension-05
 * Section 5 (Careful Resume procedure).
 */

/*
 * RTT tolerance factor for path validation
 * If observed RTT > saved_rtt * CR_RTT_TOLERANCE, path has changed
 */
#define CR_RTT_TOLERANCE_NUM		2
#define CR_RTT_TOLERANCE_DEN		1

/*
 * Minimum RTT increase to trigger retreat (microseconds)
 * Absolute threshold to avoid false positives on very low RTT paths
 */
#define CR_RTT_INCREASE_THRESHOLD_US	10000	/* 10ms */

/*
 * Pipe filling phase: slow increase factor
 * Instead of jumping to target cwnd, increase by this factor per RTT
 */
#define CR_PIPE_FILL_FACTOR_NUM		3
#define CR_PIPE_FILL_FACTOR_DEN		2

/*
 * Maximum number of RTTs for pipe filling phase
 * After this many RTTs, consider validation complete
 */
#define CR_PIPE_FILL_MAX_RTTS		4

/*
 * Loss tolerance during Careful Resume (percentage)
 * If loss rate exceeds this, trigger safe retreat
 */
#define CR_LOSS_TOLERANCE_PERCENT	5

/*
 * Minimum bytes to validate before completing Careful Resume
 * Must ACK at least one cwnd worth of data
 */
#define CR_MIN_BYTES_TO_VALIDATE(cwnd)	((cwnd) * 2)

/*
 * Per-path Careful Resume state
 * This extends the path structure during Careful Resume
 */
struct careful_resume_state {
	bool active;			/* Careful Resume is active */
	enum tquic_careful_resume_phase phase;

	/* Target values from BDP frame */
	u64 target_cwnd;		/* Target cwnd from saved state */
	u64 target_bdp;			/* Target BDP from saved state */
	u64 saved_rtt;			/* RTT from when BDP was measured */

	/* Current state */
	u64 initial_cwnd;		/* Starting cwnd (conservative) */
	u64 current_cwnd;		/* Current cwnd during resume */
	u64 bytes_acked;		/* Total bytes ACKed since start */
	u64 bytes_lost;			/* Total bytes lost since start */
	u32 rtts_elapsed;		/* Number of RTTs since start */
	ktime_t start_time;		/* When Careful Resume started */
	ktime_t last_rtt_sample;	/* Time of last RTT sample */

	/* RTT validation */
	u64 min_observed_rtt;		/* Minimum observed RTT */
	u64 max_observed_rtt;		/* Maximum observed RTT */
	u32 rtt_samples;		/* Number of RTT samples */

	/* Original CC state for safe retreat */
	u64 original_ssthresh;
	void *original_cc_state;	/* Backup of CC-specific state */
};

/*
 * Careful Resume state is stored per-path in the path's private data
 * (path->cr_state). Using a global array indexed by path_id is unsafe
 * because path_ids are reused across connections, leading to data
 * corruption between concurrent connections.
 *
 * Instead, we store the state pointer in the path structure.
 * The tquic_path structure has a void *cr_state field for this purpose.
 */

/*
 * Get Careful Resume state for a path
 */
static struct careful_resume_state *get_cr_state(struct tquic_path *path)
{
	if (!path)
		return NULL;

	return path->cr_state;
}

/*
 * Create Careful Resume state for a path
 */
static struct careful_resume_state *create_cr_state(struct tquic_path *path)
{
	struct careful_resume_state *state;

	if (!path)
		return NULL;

	/* Check if already exists */
	if (path->cr_state)
		return path->cr_state;

	state = kzalloc(sizeof(*state), GFP_KERNEL);
	if (!state)
		return NULL;

	path->cr_state = state;
	return state;
}

/*
 * Release Careful Resume state for a path
 */
static void release_cr_state(struct tquic_path *path)
{
	struct careful_resume_state *state;

	if (!path)
		return;

	state = path->cr_state;
	path->cr_state = NULL;

	if (state) {
		kfree(state->original_cc_state);
		kfree(state);
	}
}

/**
 * tquic_careful_resume_init - Initialize Careful Resume from BDP
 * @path: Path to initialize
 * @frame: Validated BDP frame
 *
 * Initializes Careful Resume using the BDP frame values. The cwnd starts
 * at a conservative value and gradually increases toward the target.
 *
 * Per draft-kuhn-quic-bdpframe-extension-05 Section 5.1:
 * "The sender SHOULD start with a conservative initial cwnd and
 * gradually increase it toward the saved cwnd value."
 */
int tquic_careful_resume_init(struct tquic_path *path,
			      const struct tquic_bdp_frame *frame)
{
	struct careful_resume_state *state;
	u64 initial_cwnd;

	if (!path || !frame)
		return -EINVAL;

	/* Get or create state */
	state = get_cr_state(path);
	if (!state) {
		state = create_cr_state(path);
		if (!state)
			return -ENOMEM;
	}

	/*
	 * Per draft recommendation, start with conservative cwnd:
	 * - Use initial cwnd (10 packets) or min(saved_cwnd/4, 10 packets)
	 * This prevents sending burst that overwhelms changed path
	 */
	initial_cwnd = min_t(u64, frame->saved_cwnd / 4,
			     TQUIC_BDP_MIN_CWND * 5);
	initial_cwnd = max_t(u64, initial_cwnd, TQUIC_BDP_MIN_CWND);

	/*
	 * Initialize state.
	 *
	 * Cap the target cwnd at a reasonable maximum to prevent
	 * an attacker-crafted BDP frame from restoring an absurdly
	 * large cwnd. The target should not exceed the BDP value
	 * (which represents actual measured capacity) and should be
	 * capped at a practical maximum (10MB) to limit damage from
	 * stale or malicious BDP frames.
	 */
	state->active = true;
	state->phase = TQUIC_CR_PHASE_RECONNECTION;
	state->target_cwnd = min_t(u64, frame->saved_cwnd,
				   min_t(u64, frame->bdp,
					  10ULL * 1024 * 1024));
	state->target_bdp = frame->bdp;
	state->saved_rtt = frame->saved_rtt;
	state->initial_cwnd = initial_cwnd;
	state->current_cwnd = initial_cwnd;
	state->bytes_acked = 0;
	state->bytes_lost = 0;
	state->rtts_elapsed = 0;
	state->start_time = ktime_get();
	state->last_rtt_sample = ktime_get();
	state->min_observed_rtt = ULLONG_MAX;
	state->max_observed_rtt = 0;
	state->rtt_samples = 0;

	/* Save original CC state for potential retreat */
	state->original_ssthresh = path->cc.ssthresh;

	/* Set path's cwnd to conservative initial value */
	path->cc.cwnd = initial_cwnd;

	tquic_info("cr: initialized for path %u, target_cwnd=%llu initial=%llu saved_rtt=%llu\n",
		path->path_id, state->target_cwnd, initial_cwnd, state->saved_rtt);

	return 0;
}
EXPORT_SYMBOL_GPL(tquic_careful_resume_init);

/**
 * tquic_careful_resume_validate - Validate Careful Resume parameters
 * @path: Path being validated
 * @observed_rtt: Observed RTT on current connection (microseconds)
 *
 * Validates that the current path characteristics are compatible with
 * the saved BDP values. If the path has changed significantly (e.g.,
 * RTT increased substantially), returns false to trigger safe retreat.
 */
bool tquic_careful_resume_validate(struct tquic_path *path, u64 observed_rtt)
{
	struct careful_resume_state *state;
	u64 rtt_threshold;
	u64 rtt_increase;

	if (!path)
		return false;

	state = get_cr_state(path);
	if (!state || !state->active)
		return false;

	/* Record RTT sample */
	state->rtt_samples++;
	if (observed_rtt < state->min_observed_rtt)
		state->min_observed_rtt = observed_rtt;
	if (observed_rtt > state->max_observed_rtt)
		state->max_observed_rtt = observed_rtt;

	/*
	 * Per draft Section 5.2: "The sender SHOULD validate that the
	 * path characteristics have not changed significantly."
	 *
	 * Check if RTT has increased beyond tolerance:
	 * observed_rtt > saved_rtt * CR_RTT_TOLERANCE
	 */
	rtt_threshold = state->saved_rtt * CR_RTT_TOLERANCE_NUM / CR_RTT_TOLERANCE_DEN;

	if (observed_rtt > rtt_threshold) {
		rtt_increase = observed_rtt - state->saved_rtt;

		/* Also require absolute increase above threshold */
		if (rtt_increase > CR_RTT_INCREASE_THRESHOLD_US) {
			tquic_info("cr: path %u RTT increased significantly: "
				"observed=%llu saved=%llu threshold=%llu\n",
				path->path_id, observed_rtt, state->saved_rtt,
				rtt_threshold);
			return false;
		}
	}

	/*
	 * Check loss rate during Careful Resume
	 * If loss rate > CR_LOSS_TOLERANCE_PERCENT, retreat
	 */
	if (state->bytes_acked > 0) {
		u64 total = state->bytes_acked + state->bytes_lost;
		u64 loss_rate = state->bytes_lost * 100 / total;

		if (loss_rate > CR_LOSS_TOLERANCE_PERCENT) {
			tquic_info("cr: path %u high loss rate during resume: "
				"%llu%% (lost=%llu acked=%llu)\n",
				path->path_id, loss_rate,
				state->bytes_lost, state->bytes_acked);
			return false;
		}
	}

	return true;
}
EXPORT_SYMBOL_GPL(tquic_careful_resume_validate);

/**
 * tquic_careful_resume_apply - Apply Careful Resume to CC
 * @path: Path to apply to
 * @bytes_acked: Bytes acknowledged in this ACK
 * @rtt_us: RTT sample in microseconds
 *
 * Called on each ACK during Careful Resume. Gradually increases the
 * cwnd toward the target while validating path characteristics.
 *
 * The increase follows a controlled ramp:
 * - Phase 1 (Reconnection): Validate path is similar
 * - Phase 2 (Unvalidated): Gradually increase cwnd
 * - Phase 3 (Normal): Full target reached, switch to normal CC
 */
bool tquic_careful_resume_apply(struct tquic_path *path, u64 bytes_acked,
				u64 rtt_us)
{
	struct careful_resume_state *state;
	struct tquic_connection *conn;
	u64 new_cwnd;
	ktime_t now;
	s64 time_elapsed;
	u32 expected_rtts;

	if (!path)
		return false;

	state = get_cr_state(path);
	if (!state || !state->active)
		return false;

	/* Update tracking */
	state->bytes_acked += bytes_acked;
	now = ktime_get();

	/* Validate path hasn't changed */
	if (rtt_us > 0 && !tquic_careful_resume_validate(path, rtt_us)) {
		tquic_info("cr: validation failed, triggering safe retreat\n");
		tquic_careful_resume_safe_retreat(path);
		return false;
	}

	/*
	 * Calculate RTTs elapsed based on time and saved RTT
	 * This gives us a rough idea of how much data we've sent
	 */
	if (state->saved_rtt > 0) {
		time_elapsed = ktime_us_delta(now, state->start_time);
		expected_rtts = time_elapsed / state->saved_rtt;
		if (expected_rtts > state->rtts_elapsed)
			state->rtts_elapsed = expected_rtts;
	}

	/*
	 * Gradual cwnd increase per draft Section 5.3:
	 * "The cwnd SHOULD be increased gradually, not immediately
	 * set to the saved value."
	 *
	 * Increase by factor of 1.5 per RTT until reaching target
	 */
	new_cwnd = state->current_cwnd;

	switch (state->phase) {
	case TQUIC_CR_PHASE_RECONNECTION:
		/*
		 * Phase 1: Just started, collect RTT samples
		 * Stay at initial cwnd until we have enough samples
		 */
		if (state->rtt_samples >= 3) {
			state->phase = TQUIC_CR_PHASE_UNVALIDATED;
			tquic_dbg("cr: path %u transitioning to unvalidated phase\n",
				 path->path_id);
		}
		break;

	case TQUIC_CR_PHASE_UNVALIDATED:
		/*
		 * Phase 2: Gradually increase cwnd toward target
		 * Increase by factor per RTT
		 */
		if (state->rtts_elapsed > 0) {
			new_cwnd = state->initial_cwnd;

			/* Exponential increase capped at target */
			for (u32 i = 0; i < state->rtts_elapsed && i < CR_PIPE_FILL_MAX_RTTS; i++) {
				new_cwnd = new_cwnd * CR_PIPE_FILL_FACTOR_NUM /
					   CR_PIPE_FILL_FACTOR_DEN;
			}

			new_cwnd = min_t(u64, new_cwnd, state->target_cwnd);
			state->current_cwnd = new_cwnd;
			path->cc.cwnd = new_cwnd;
		}

		/*
		 * Check if we've completed pipe filling:
		 * - Reached target cwnd, OR
		 * - Validated enough data (2x cwnd worth), OR
		 * - Exceeded max RTTs for validation
		 */
		if (new_cwnd >= state->target_cwnd ||
		    state->bytes_acked >= CR_MIN_BYTES_TO_VALIDATE(state->target_cwnd) ||
		    state->rtts_elapsed >= CR_PIPE_FILL_MAX_RTTS) {

			conn = path->conn;
			if (conn) {
				tquic_careful_resume_complete(conn, path);
			}
			state->phase = TQUIC_CR_PHASE_NORMAL;
			state->active = false;

			tquic_info("cr: path %u completed, final cwnd=%llu target=%llu\n",
				path->path_id, new_cwnd, state->target_cwnd);

			return false;  /* Careful Resume complete */
		}
		break;

	case TQUIC_CR_PHASE_SAFE_RETREAT:
		/* In safe retreat, let normal CC handle things */
		return false;

	case TQUIC_CR_PHASE_NORMAL:
	case TQUIC_CR_PHASE_DISABLED:
		/* Not in Careful Resume */
		return false;
	}

	return true;  /* Still in Careful Resume */
}
EXPORT_SYMBOL_GPL(tquic_careful_resume_apply);

/**
 * tquic_careful_resume_on_loss - Handle loss during Careful Resume
 * @path: Path that experienced loss
 * @bytes_lost: Bytes lost
 *
 * Called on loss detection. Accumulates loss count and may trigger
 * safe retreat if loss rate becomes too high.
 */
void tquic_careful_resume_on_loss(struct tquic_path *path, u64 bytes_lost)
{
	struct careful_resume_state *state;
	u64 total, loss_rate;

	if (!path)
		return;

	state = get_cr_state(path);
	if (!state || !state->active)
		return;

	state->bytes_lost += bytes_lost;

	/* Check if loss rate triggers retreat */
	total = state->bytes_acked + state->bytes_lost;
	if (total > state->initial_cwnd) {
		loss_rate = state->bytes_lost * 100 / total;

		if (loss_rate > CR_LOSS_TOLERANCE_PERCENT) {
			tquic_info("cr: path %u high loss during resume "
				"(%llu%%), triggering retreat\n",
				path->path_id, loss_rate);
			tquic_careful_resume_safe_retreat(path);
		}
	}
}
EXPORT_SYMBOL_GPL(tquic_careful_resume_on_loss);

/**
 * tquic_careful_resume_safe_retreat - Execute safe retreat
 * @path: Path to retreat on
 *
 * Called when Careful Resume detects the path has changed and saved
 * values are no longer valid. Resets to conservative slow start from
 * the minimum cwnd.
 *
 * Per draft Section 5.4: "If validation fails, the sender SHOULD
 * retreat to slow start with a conservative cwnd."
 */
void tquic_careful_resume_safe_retreat(struct tquic_path *path)
{
	struct careful_resume_state *state;
	struct tquic_connection *conn;
	struct tquic_bdp_state *bdp;
	u64 min_cwnd;

	if (!path)
		return;

	state = get_cr_state(path);
	if (!state)
		return;

	/*
	 * Reset to minimum cwnd (2 packets per RFC 9002)
	 * This is conservative but safe
	 */
	min_cwnd = TQUIC_BDP_MIN_CWND;

	path->cc.cwnd = min_cwnd;
	path->cc.ssthresh = state->original_ssthresh;

	/* Mark state as safe retreat */
	state->phase = TQUIC_CR_PHASE_SAFE_RETREAT;
	state->active = false;

	/* Update connection BDP state */
	conn = path->conn;
	if (conn) {
		bdp = conn->bdp_state;
		if (bdp) {
			spin_lock_bh(&bdp->lock);
			bdp->cr_phase = TQUIC_CR_PHASE_SAFE_RETREAT;
			spin_unlock_bh(&bdp->lock);
		}
	}

	tquic_info("cr: safe retreat executed for path %u, cwnd reset to %llu\n",
		path->path_id, min_cwnd);

	/* Clean up state - will use normal CC from here */
	release_cr_state(path);
}
EXPORT_SYMBOL_GPL(tquic_careful_resume_safe_retreat);

/*
 * Module initialization
 */
static int __init tquic_careful_resume_init_module(void)
{
	tquic_info("careful_resume: initialized\n");
	return 0;
}

static void __exit tquic_careful_resume_exit_module(void)
{
	/*
	 * Per-path CR state is freed when paths are destroyed.
	 * No global state to clean up.
	 */
	tquic_info("careful_resume: cleaned up\n");
}

#ifndef TQUIC_OUT_OF_TREE
module_init(tquic_careful_resume_init_module);
module_exit(tquic_careful_resume_exit_module);

MODULE_DESCRIPTION("TQUIC Careful Resume for BDP Frame Extension");
MODULE_LICENSE("GPL");
#endif
