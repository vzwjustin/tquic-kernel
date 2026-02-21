// SPDX-License-Identifier: GPL-2.0-only
/*
 * TQUIC: Path Validation (PATH_CHALLENGE/PATH_RESPONSE)
 *
 * Copyright (c) 2026 Justin Adams <spotty118@gmail.com>
 * Kernel implementation by Justin Adams <spotty118@gmail.com>
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
#include "../tquic_compat.h"
#include "../tquic_debug.h"
#include "../tquic_preferred_addr.h"
#include <net/tquic_pm.h>
#include <uapi/linux/tquic_pm.h>

/* Path validation constants */
#define TQUIC_VALIDATION_MIN_TIMEOUT_US 100000 /* 100ms */
#define TQUIC_VALIDATION_MAX_TIMEOUT_US 10000000 /* 10 seconds */
#define TQUIC_VALIDATION_DEFAULT_TIMEOUT_US 1000000 /* 1 second */
#define TQUIC_VALIDATION_RTT_MULTIPLIER 3 /* 3x SRTT */
#define TQUIC_VALIDATION_MAX_RETRIES 3

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

	pr_debug(
		"tquic_pm: path %u RTT updated - sample: %u us, SRTT: %u us, RTTVAR: %u us, min: %u us\n",
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

	tquic_dbg("tquic_validation_timeout_us: path_id=%u srtt=%u rttvar=%u\n",
		  path->path_id, path->stats.rtt_smoothed,
		  path->stats.rtt_variance);

	if (path->stats.rtt_smoothed == 0) {
		/* No RTT measurement yet - use default */
		timeout_us = TQUIC_VALIDATION_DEFAULT_TIMEOUT_US;
	} else {
		/* RFC 9000: Use 3x SRTT for path validation
		 * Add 4x RTTVAR for variance tolerance */
		timeout_us = path->stats.rtt_smoothed *
			     TQUIC_VALIDATION_RTT_MULTIPLIER;

		/* Add variance component: max(1ms, 4*RTTVAR) */
		u32 variance_us = max(1000U, path->stats.rtt_variance * 4);
		timeout_us += variance_us;
	}

	/* Clamp to reasonable bounds for LAN to satellite */
	timeout_us = clamp(timeout_us, TQUIC_VALIDATION_MIN_TIMEOUT_US,
			   TQUIC_VALIDATION_MAX_TIMEOUT_US);

	tquic_dbg("tquic_validation_timeout_us: path_id=%u timeout=%u us\n",
		  path->path_id, timeout_us);

	return timeout_us;
}

/*
 * Path validation timeout - retry or mark failed
 *
 * Runs in timer/softirq context. Must hold paths_lock when modifying
 * path state to prevent races with tquic_path_handle_response() and
 * other concurrent state transitions.
 */
void tquic_path_validation_timeout(struct timer_list *t)
{
	struct tquic_path *path = from_timer(path, t, validation.timer);
	struct tquic_connection *conn = path->conn;
	struct net *net;

	if (!conn || !conn->sk)
		return;

	net = sock_net(conn->sk);

	spin_lock_bh(&conn->paths_lock);

	/*
	 * Check whether the validation was already completed by
	 * tquic_path_handle_response() racing with this timer.
	 * If challenge_pending is false the response arrived between
	 * the timer firing and acquiring paths_lock -- nothing to do.
	 */
	if (!path->validation.challenge_pending) {
		spin_unlock_bh(&conn->paths_lock);
		return;
	}

	pr_debug("tquic_pm: path %u validation timeout (retry %u)\n",
		 path->path_id, path->validation.retries);

	/* Check retry limit */
	if (path->validation.retries >= TQUIC_VALIDATION_MAX_RETRIES) {
		/* Max retries exceeded - validation failed */
		tquic_warn("path %u validation failed after %u retries\n",
			   path->path_id, path->validation.retries);

		path->state = TQUIC_PATH_FAILED;
		path->validation.challenge_pending = false;
		path->anti_amplification.active = false;
		del_timer(&path->validation.timer);

		tquic_path_get(path);
		spin_unlock_bh(&conn->paths_lock);

		/* Emit path failed event via PM netlink */
		tquic_pm_nl_send_event(net, conn, path, TQUIC_PM_EVENT_FAILED);

		/*
		 * Wire: tquic_pref_addr_client_on_failed —
		 *
		 * If this path was the preferred-address migration path,
		 * notify the preferred address subsystem that migration
		 * validation has failed.  The subsystem cleans up the
		 * migration_path pointer and marks the state as FAILED.
		 * Non-fatal: continue with bonding failover regardless.
		 */
		if (!conn->is_server && conn->preferred_addr) {
			struct tquic_pref_addr_migration *m =
				(struct tquic_pref_addr_migration *)
					conn->preferred_addr;

			if (m->state == TQUIC_PREF_ADDR_VALIDATING &&
			    m->migration_path == path)
				tquic_pref_addr_client_on_failed(conn,
								 -ETIMEDOUT);
		}

#ifdef CONFIG_TQUIC_MULTIPATH
		/*
		 * Send PATH_ABANDON to peer (RFC 9369).
		 * tquic_send_path_abandon transitions the path to CLOSED
		 * and triggers bonding failover internally.
		 */
		tquic_send_path_abandon(conn, path, 0);
#else
		/* Trigger failover to other paths */
		tquic_bond_path_failed(conn, path);
#endif

		tquic_path_put(path);
		return;
	}

	/* Retry validation */
	path->validation.retries++;

	/*
	 * CF-285: Take a reference on the path before releasing the
	 * lock so the path cannot be freed while we send the retry
	 * challenge and arm the timer.  Cache local copies of fields
	 * that we only need for logging.
	 */
	{
		u8 retry_path_id = path->path_id;
		u32 retry_count = path->validation.retries;
		u32 timeout_us = tquic_validation_timeout_us(path);

		tquic_path_get(path);
		spin_unlock_bh(&conn->paths_lock);

		/* Resend PATH_CHALLENGE */
		if (tquic_path_send_challenge(conn, path) == 0) {
			pr_debug(
				"tquic_pm: path %u retry %u scheduled in %u us\n",
				retry_path_id, retry_count, timeout_us);

			mod_timer(&path->validation.timer,
				  jiffies + usecs_to_jiffies(timeout_us));
		} else {
			pr_err("tquic_pm: path %u failed to send retry challenge\n",
			       retry_path_id);
			spin_lock_bh(&conn->paths_lock);
			path->state = TQUIC_PATH_FAILED;
			path->validation.challenge_pending = false;
			path->anti_amplification.active = false;
			spin_unlock_bh(&conn->paths_lock);
#ifdef CONFIG_TQUIC_MULTIPATH
			tquic_send_path_abandon(conn, path, 0);
#else
			tquic_bond_path_failed(conn, path);
#endif
		}

		tquic_path_put(path);
	}
}
EXPORT_SYMBOL_GPL(tquic_path_validation_timeout);

/*
 * Send PATH_CHALLENGE frame on path
 */
int tquic_path_send_challenge(struct tquic_connection *conn,
			      struct tquic_path *path)
{
	/*
	 * BUG FIX: Do NOT generate challenge data here.
	 * tquic_send_path_challenge() will generate it and store in
	 * path->challenge_data. We must use that same data for validation.
	 *
	 * Previous bug: Generated random bytes in path->validation.challenge_data
	 * here, then tquic_send_path_challenge() generated DIFFERENT random bytes
	 * in path->challenge_data and sent those on the wire. PATH_RESPONSE
	 * validation compared against path->validation.challenge_data, causing
	 * 100% validation failure even when peer responded correctly.
	 */

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

	/*
	 * Enable anti-amplification limits (RFC 9000 Section 8.1).
	 *
	 * Before path validation completes, an endpoint MUST limit the
	 * amount of data it sends to the unvalidated address to three
	 * times the amount of data received from that address.
	 */
	atomic64_set(&path->anti_amplification.bytes_received, 0);
	atomic64_set(&path->anti_amplification.bytes_sent, 0);
	path->anti_amplification.active = true;

	/* Send initial PATH_CHALLENGE */
	ret = tquic_path_send_challenge(conn, path);
	if (ret < 0) {
		pr_err("tquic_pm: failed to send initial PATH_CHALLENGE: %d\n",
		       ret);
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
 * Handle received PATH_CHALLENGE - send PATH_RESPONSE immediately
 */
int tquic_path_handle_challenge(struct tquic_connection *conn,
				struct tquic_path *path, const u8 *data)
{
	int ret;

	if (!conn || !path || !data)
		return -EINVAL;

	pr_debug("tquic_pm: received PATH_CHALLENGE on path %u\n",
		 path->path_id);

	/*
	 * RFC 9000 Section 8.2.2: PATH_RESPONSE MUST be sent on the same path
	 * and promptly. Send immediately to avoid stalling on deferred queues.
	 */
	ret = tquic_send_path_response(conn, path, data);
	if (ret < 0) {
		pr_warn("tquic_pm: failed to send PATH_RESPONSE on path %u: %d\n",
			path->path_id, ret);
		return ret;
	}

	return 0;
}
EXPORT_SYMBOL_GPL(tquic_path_handle_challenge);

/*
 * Handle received PATH_RESPONSE - validate path
 */
int tquic_path_handle_response(struct tquic_connection *conn,
			       struct tquic_path *path, const u8 *data)
{
	ktime_t now = ktime_get();
	u32 rtt_us;

	pr_debug("tquic_pm: received PATH_RESPONSE on path %u\n",
		 path->path_id);

	/*
	 * Acquire paths_lock to prevent races with the validation
	 * timeout handler which also modifies path state.
	 */
	spin_lock_bh(&conn->paths_lock);

	/* Verify challenge is pending */
	if (!path->validation.challenge_pending) {
		spin_unlock_bh(&conn->paths_lock);
		pr_debug(
			"tquic_pm: unexpected PATH_RESPONSE on path %u (no pending challenge)\n",
			path->path_id);
		return -EINVAL;
	}

	/*
	 * BUG FIX: Check against path->challenge_data (set by connection.c)
	 * instead of path->validation.challenge_data (which is no longer used).
	 * This matches the actual challenge bytes sent on the wire.
	 *
	 * SECURITY: Match response data against sent challenge using
	 * constant-time comparison to prevent timing side-channel attacks.
	 *
	 * An attacker who can observe response timing could iteratively
	 * discover the challenge bytes if we used memcmp(), which returns
	 * early on mismatch. crypto_memneq() compares all 8 bytes regardless
	 * of where mismatches occur.
	 */
	if (crypto_memneq(data, path->challenge_data, 8) != 0) {
		spin_unlock_bh(&conn->paths_lock);
		tquic_warn("PATH_RESPONSE mismatch on path %u\n",
			   path->path_id);
		return -EINVAL;
	}

	/* Calculate RTT sample from challenge_sent to now */
	rtt_us = ktime_us_delta(now, path->validation.challenge_sent);

	tquic_info("path %u validated - RTT: %u us\n", path->path_id, rtt_us);

	/* Update RTT statistics using RFC 6298 algorithm */
	tquic_pm_update_rtt(path, rtt_us);

	/*
	 * Mark path as validated/active.
	 *
	 * If recovering from UNAVAILABLE, restore saved state but only if
	 * it was a valid operational state. TQUIC_PATH_PENDING must not be
	 * restored as it would skip the completed validation.
	 *
	 * RFC 9000 Section 9.3: When a new path is validated after
	 * peer-initiated migration, update conn->active_path so the
	 * endpoint uses the validated path for subsequent traffic.
	 */
	if (path->saved_state == TQUIC_PATH_ACTIVE ||
	    path->saved_state == TQUIC_PATH_STANDBY ||
	    path->saved_state == TQUIC_PATH_VALIDATED) {
		path->state = path->saved_state;
		path->saved_state = TQUIC_PATH_UNUSED;
		tquic_info("path %u recovered to state %d\n", path->path_id,
			   path->state);
	} else {
		path->state = TQUIC_PATH_ACTIVE;
		path->saved_state = TQUIC_PATH_UNUSED;
	}

	/*
	 * If this path became ACTIVE (either from saved_state or the
	 * default branch above), promote it to conn->active_path and
	 * demote the previous active path to STANDBY.
	 */
	if (path->state == TQUIC_PATH_ACTIVE) {
		struct tquic_path *old_active;

		old_active = rcu_dereference_protected(
			conn->active_path, lockdep_is_held(&conn->paths_lock));
		rcu_assign_pointer(conn->active_path, path);
		if (old_active && old_active != path)
			old_active->state = TQUIC_PATH_STANDBY;
	}

	path->validation.challenge_pending = false;
	path->validation.retries = 0;

	/*
	 * Disable anti-amplification limits (RFC 9000 Section 8.1).
	 * Path is now validated so we can send data freely.
	 */
	path->anti_amplification.active = false;

	/* Stop retransmission timer */
	del_timer(&path->validation.timer);

	/* Update activity timestamp */
	path->last_activity = now;

	spin_unlock_bh(&conn->paths_lock);

	/* Emit validation success event via PM netlink */
	if (conn && conn->sk)
		tquic_pm_nl_send_event(sock_net(conn->sk), conn, path,
				       TQUIC_PM_EVENT_VALIDATED);

	/*
	 * Wire: tquic_pref_addr_client_on_validated —
	 *
	 * If this is a client and the validated path is the
	 * preferred-address migration path, notify the preferred address
	 * subsystem.  It will promote the path to active_path and update
	 * conn->stats.path_migrations.
	 *
	 * We must call this BEFORE tquic_bond_path_recovered() because
	 * the subsystem's rcu_assign_pointer(conn->active_path, path)
	 * may overlap with bonding's path selection.  Non-fatal if the
	 * path is not the preferred-address path.
	 */
	if (conn && !conn->is_server && conn->preferred_addr) {
		struct tquic_pref_addr_migration *m =
			(struct tquic_pref_addr_migration *)conn->preferred_addr;

		if (m->state == TQUIC_PREF_ADDR_VALIDATING &&
		    m->migration_path == path)
			tquic_pref_addr_client_on_validated(conn, path);
	}

	/* Notify bonding layer path is available again */
	tquic_bond_path_recovered(conn, path);

	return 0;
}
EXPORT_SYMBOL_GPL(tquic_path_handle_response);

MODULE_DESCRIPTION("TQUIC Path Validation");
MODULE_LICENSE("GPL");
