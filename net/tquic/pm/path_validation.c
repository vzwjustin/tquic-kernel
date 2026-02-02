// SPDX-License-Identifier: GPL-2.0-only
/*
 * TQUIC: Path Validation (PATH_CHALLENGE/PATH_RESPONSE)
 *
 * Copyright (c) 2026 Linux Foundation
 *
 * Implements RFC 9000 Section 8.2 Path Validation with adaptive timeouts
 * based on smoothed RTT. Ensures paths are validated before data transmission
 * and handles validation across diverse network conditions (LAN to satellite).
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/timer.h>
#include <linux/random.h>
#include <linux/skbuff.h>
#include <crypto/utils.h>
#include <net/sock.h>
#include <net/tquic.h>
#include <uapi/linux/tquic_pm.h>

/* Path validation constants */
#define TQUIC_VALIDATION_MIN_TIMEOUT_US	100000   /* 100ms */
#define TQUIC_VALIDATION_MAX_TIMEOUT_US	10000000 /* 10 seconds */
#define TQUIC_VALIDATION_DEFAULT_TIMEOUT_US 1000000 /* 1 second */
#define TQUIC_VALIDATION_RTT_MULTIPLIER	3        /* 3x SRTT */
#define TQUIC_VALIDATION_MAX_RETRIES	3

/*
 * RFC 6298: SRTT and RTTVAR calculation
 */
static void tquic_pm_update_rtt(struct tquic_path *path, u32 rtt_sample_us)
{
	struct tquic_path_stats *stats = &path->stats;

	if (stats->rtt_smoothed == 0) {
		/* First measurement - RFC 6298 Section 2.2 */
		stats->rtt_smoothed = rtt_sample_us;
		stats->rtt_variance = rtt_sample_us / 2;
	} else {
		/* Update SRTT and RTTVAR - RFC 6298 Section 2.3 */
		s32 delta = rtt_sample_us - stats->rtt_smoothed;

		/* RTTVAR = (1 - beta) * RTTVAR + beta * |delta|
		 * beta = 1/4 */
		stats->rtt_variance = stats->rtt_variance -
			(stats->rtt_variance / 4) +
			(abs(delta) / 4);

		/* SRTT = (1 - alpha) * SRTT + alpha * RTT
		 * alpha = 1/8 */
		stats->rtt_smoothed = stats->rtt_smoothed -
			(stats->rtt_smoothed / 8) +
			(rtt_sample_us / 8);
	}

	/* Update minimum RTT */
	if (stats->rtt_min == 0 || rtt_sample_us < stats->rtt_min)
		stats->rtt_min = rtt_sample_us;

	pr_debug("tquic_pm: path %u RTT updated - sample: %u us, SRTT: %u us, RTTVAR: %u us, min: %u us\n",
		 path->path_id, rtt_sample_us, stats->rtt_smoothed,
		 stats->rtt_variance, stats->rtt_min);
}

/*
 * Calculate adaptive validation timeout based on RTT
 * Returns timeout in microseconds
 */
static u32 tquic_validation_timeout_us(struct tquic_path *path)
{
	u32 timeout_us;

	if (path->stats.rtt_smoothed == 0) {
		/* No RTT measurement yet - use default */
		timeout_us = TQUIC_VALIDATION_DEFAULT_TIMEOUT_US;
	} else {
		/* RFC 9000: Use 3x SRTT for path validation
		 * Add 4x RTTVAR for variance tolerance */
		timeout_us = path->stats.rtt_smoothed * TQUIC_VALIDATION_RTT_MULTIPLIER;

		/* Add variance component: max(1ms, 4*RTTVAR) */
		u32 variance_us = max(1000U, path->stats.rtt_variance * 4);
		timeout_us += variance_us;
	}

	/* Clamp to reasonable bounds for LAN to satellite */
	timeout_us = clamp(timeout_us,
			   TQUIC_VALIDATION_MIN_TIMEOUT_US,
			   TQUIC_VALIDATION_MAX_TIMEOUT_US);

	return timeout_us;
}

/*
 * Path validation timeout - retry or mark failed
 */
void tquic_path_validation_timeout(struct timer_list *t)
{
	struct tquic_path *path = from_timer(path, t, validation.timer);
	struct tquic_connection *conn = path->conn;
	struct net *net;

	if (!conn || !conn->sk)
		return;

	net = sock_net(conn->sk);

	pr_debug("tquic_pm: path %u validation timeout (retry %u)\n",
		 path->path_id, path->validation.retries);

	/* Check retry limit */
	if (path->validation.retries >= TQUIC_VALIDATION_MAX_RETRIES) {
		/* Max retries exceeded - validation failed */
		pr_warn("tquic_pm: path %u validation failed after %u retries\n",
			path->path_id, path->validation.retries);

		path->state = TQUIC_PATH_FAILED;
		path->validation.challenge_pending = false;
		del_timer(&path->validation.timer);

		/* Emit path failed event */
		tquic_nl_path_event(conn, path, TQUIC_PM_EVENT_FAILED);

		/* Trigger failover to other paths */
		tquic_bond_path_failed(conn, path);

		return;
	}

	/* Retry validation */
	path->validation.retries++;

	/* Resend PATH_CHALLENGE */
	if (tquic_path_send_challenge(conn, path) == 0) {
		/* Schedule next timeout with adaptive value */
		u32 timeout_us = tquic_validation_timeout_us(path);

		pr_debug("tquic_pm: path %u retry %u scheduled in %u us\n",
			 path->path_id, path->validation.retries, timeout_us);

		mod_timer(&path->validation.timer,
			  jiffies + usecs_to_jiffies(timeout_us));
	} else {
		pr_err("tquic_pm: path %u failed to send retry challenge\n",
		       path->path_id);
		path->state = TQUIC_PATH_FAILED;
		path->validation.challenge_pending = false;
		tquic_bond_path_failed(conn, path);
	}
}
EXPORT_SYMBOL_GPL(tquic_path_validation_timeout);

/*
 * Send PATH_CHALLENGE frame on path
 */
int tquic_path_send_challenge(struct tquic_connection *conn,
			       struct tquic_path *path)
{
	/* Generate new challenge data if not retrying */
	if (path->validation.retries == 0) {
		get_random_bytes(path->validation.challenge_data,
				 sizeof(path->validation.challenge_data));
	}

	/* Record when challenge was sent */
	path->validation.challenge_sent = ktime_get();
	path->validation.challenge_pending = true;

	/* Send PATH_CHALLENGE frame via existing connection.c helper */
	tquic_send_path_challenge(conn, path);

	pr_debug("tquic_pm: sent PATH_CHALLENGE on path %u (attempt %u)\n",
		 path->path_id, path->validation.retries + 1);

	return 0;
}
EXPORT_SYMBOL_GPL(tquic_path_send_challenge);

/*
 * Start path validation
 */
int tquic_path_start_validation(struct tquic_connection *conn,
				 struct tquic_path *path)
{
	u32 timeout_us;
	int ret;

	pr_debug("tquic_pm: starting validation for path %u\n", path->path_id);

	/* Initialize validation state */
	path->state = TQUIC_PATH_PENDING;
	path->validation.retries = 0;
	path->validation.challenge_pending = false;

	/* Send initial PATH_CHALLENGE */
	ret = tquic_path_send_challenge(conn, path);
	if (ret < 0) {
		pr_err("tquic_pm: failed to send initial PATH_CHALLENGE: %d\n", ret);
		return ret;
	}

	/* Calculate adaptive timeout */
	timeout_us = tquic_validation_timeout_us(path);

	pr_debug("tquic_pm: path %u validation timeout set to %u us\n",
		 path->path_id, timeout_us);

	/* Start retransmission timer */
	mod_timer(&path->validation.timer,
		  jiffies + usecs_to_jiffies(timeout_us));

	return 0;
}
EXPORT_SYMBOL_GPL(tquic_path_start_validation);

/*
 * Handle received PATH_CHALLENGE - queue PATH_RESPONSE
 */
int tquic_path_handle_challenge(struct tquic_connection *conn,
				 struct tquic_path *path,
				 const u8 *data)
{
	struct sk_buff *skb;

	pr_debug("tquic_pm: received PATH_CHALLENGE on path %u\n", path->path_id);

	/* Check response queue depth to prevent memory exhaustion
	 * RFC 9000 Section 8.2.1: Limit outstanding responses */
	if (atomic_read(&path->response.count) >= TQUIC_MAX_PENDING_RESPONSES) {
		pr_warn("tquic_pm: path %u response queue full (%d), dropping challenge\n",
			path->path_id, TQUIC_MAX_PENDING_RESPONSES);
		return -ENOBUFS;
	}

	/* Allocate skb to hold challenge data for response
	 * We'll send this in the output path */
	skb = alloc_skb(8, GFP_ATOMIC);
	if (!skb) {
		pr_err("tquic_pm: failed to allocate response skb\n");
		return -ENOMEM;
	}

	/* Copy challenge data to skb */
	skb_put_data(skb, data, 8);

	/* Queue response */
	skb_queue_tail(&path->response.queue, skb);
	atomic_inc(&path->response.count);

	pr_debug("tquic_pm: queued PATH_RESPONSE on path %u (%d in queue)\n",
		 path->path_id, atomic_read(&path->response.count));

	/*
	 * SECURITY: Trigger immediate transmission of PATH_RESPONSE.
	 *
	 * RFC 9000 Section 8.2.2 requires PATH_RESPONSE to be sent promptly:
	 * "An endpoint MUST send each PATH_RESPONSE frame on the network path
	 * where the corresponding PATH_CHALLENGE was received."
	 *
	 * Delaying PATH_RESPONSE could:
	 * 1. Allow amplification attacks by accumulating challenge/response pairs
	 * 2. Cause path validation timeouts for legitimate peers
	 * 3. Create timing vulnerabilities in migration scenarios
	 *
	 * We trigger immediate output by marking the socket writable and
	 * scheduling the connection's transmit tasklet.
	 */
	if (conn && conn->sk) {
		/* Mark socket as having urgent data to send */
		set_bit(TQUIC_PATH_RESPONSE_PENDING, &conn->flags);

		/* Wake up any waiting writers and trigger immediate output */
		sk_data_ready(conn->sk);

		/* Schedule immediate transmission via tasklet */
		if (conn->tasklet_scheduled) {
			tasklet_hi_schedule(&conn->tx_tasklet);
		}

		pr_debug("tquic_pm: triggered immediate PATH_RESPONSE transmission on path %u\n",
			 path->path_id);
	}

	return 0;
}
EXPORT_SYMBOL_GPL(tquic_path_handle_challenge);

/*
 * Handle received PATH_RESPONSE - validate path
 */
int tquic_path_handle_response(struct tquic_connection *conn,
				struct tquic_path *path,
				const u8 *data)
{
	ktime_t now = ktime_get();
	u32 rtt_us;

	pr_debug("tquic_pm: received PATH_RESPONSE on path %u\n", path->path_id);

	/* Verify challenge is pending */
	if (!path->validation.challenge_pending) {
		pr_debug("tquic_pm: unexpected PATH_RESPONSE on path %u (no pending challenge)\n",
			 path->path_id);
		return -EINVAL;
	}

	/*
	 * SECURITY: Match response data against sent challenge using
	 * constant-time comparison to prevent timing side-channel attacks.
	 *
	 * An attacker who can observe response timing could iteratively
	 * discover the challenge bytes if we used memcmp(), which returns
	 * early on mismatch. crypto_memneq() compares all 8 bytes regardless
	 * of where mismatches occur.
	 */
	if (crypto_memneq(data, path->validation.challenge_data, 8) != 0) {
		pr_warn("tquic_pm: PATH_RESPONSE mismatch on path %u\n",
			path->path_id);
		return -EINVAL;
	}

	/* Calculate RTT sample from challenge_sent to now */
	rtt_us = ktime_us_delta(now, path->validation.challenge_sent);

	pr_info("tquic_pm: path %u validated - RTT: %u us\n",
		path->path_id, rtt_us);

	/* Update RTT statistics using RFC 6298 algorithm */
	tquic_pm_update_rtt(path, rtt_us);

	/* Mark path as validated/active
	 * If recovering from UNAVAILABLE, restore saved state */
	if (path->saved_state != TQUIC_PATH_UNUSED &&
	    path->saved_state != TQUIC_PATH_UNAVAILABLE) {
		path->state = path->saved_state;
		path->saved_state = TQUIC_PATH_UNUSED;
		pr_info("tquic_pm: path %u recovered to state %d\n",
			path->path_id, path->state);
	} else {
		path->state = TQUIC_PATH_ACTIVE;
	}

	path->validation.challenge_pending = false;
	path->validation.retries = 0;

	/* Stop retransmission timer */
	del_timer(&path->validation.timer);

	/* Update activity timestamp */
	path->last_activity = now;

	/* Emit validation success event */
	tquic_nl_path_event(conn, path, TQUIC_PM_EVENT_VALIDATED);

	/* Notify bonding layer path is available again */
	tquic_bond_path_recovered(conn, path);

	return 0;
}
EXPORT_SYMBOL_GPL(tquic_path_handle_response);

MODULE_DESCRIPTION("TQUIC Path Validation");
MODULE_LICENSE("GPL");
