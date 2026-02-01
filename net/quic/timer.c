// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * QUIC - Quick UDP Internet Connections
 *
 * Timer management implementation per RFC 9002
 *
 * Copyright (c) 2024 Linux QUIC Authors
 */

#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/timer.h>
#include <linux/jiffies.h>
#include <net/quic.h>

/* Timer constants per RFC 9002 */
#define QUIC_TIMER_GRANULARITY_MS	1	/* Timer granularity in ms */
#define QUIC_TIMER_MAX_BACKOFF		6	/* Maximum PTO backoff */
#define QUIC_TIMER_IDLE_TIMEOUT_MS	30000	/* Default idle timeout */
#define QUIC_TIMER_ACK_DELAY_MS		25	/* Max ACK delay */

/* Timer state tracking */
struct quic_timer_state {
	ktime_t		deadline;
	bool		armed;
	u32		backoff_count;
};

/*
 * Convert ktime to jiffies for timer_list
 */
static unsigned long quic_ktime_to_jiffies(ktime_t when)
{
	s64 delta_ns = ktime_to_ns(ktime_sub(when, ktime_get()));
	unsigned long delta_jiffies;

	if (delta_ns <= 0)
		return jiffies;

	delta_jiffies = nsecs_to_jiffies(delta_ns);
	if (delta_jiffies == 0)
		delta_jiffies = 1;

	return jiffies + delta_jiffies;
}

/*
 * Loss detection timer callback
 *
 * Per RFC 9002 Section 6.2: When the loss detection timer expires,
 * the timer's mode determines the action to be performed.
 */
static void quic_timer_loss_handler(struct timer_list *t)
{
	struct quic_connection *conn = from_timer(conn, t, timers[QUIC_TIMER_LOSS]);
	unsigned long flags;

	if (!conn)
		return;

	spin_lock_irqsave(&conn->lock, flags);

	/* Check connection state */
	if (conn->state == QUIC_STATE_CLOSED ||
	    conn->state == QUIC_STATE_DRAINING) {
		spin_unlock_irqrestore(&conn->lock, flags);
		return;
	}

	/* Clear timer deadline */
	conn->timer_deadlines[QUIC_TIMER_LOSS] = 0;

	spin_unlock_irqrestore(&conn->lock, flags);

	/* Invoke loss detection timeout handler */
	quic_loss_detection_on_timeout(conn);

	/* Update timers */
	quic_timer_update(conn);
}

/*
 * ACK timer callback
 *
 * Per RFC 9000: An endpoint MUST acknowledge all ack-eliciting
 * Initial and Handshake packets immediately
 */
static void quic_timer_ack_handler(struct timer_list *t)
{
	struct quic_connection *conn = from_timer(conn, t, timers[QUIC_TIMER_ACK]);
	unsigned long flags;
	int i;

	if (!conn)
		return;

	spin_lock_irqsave(&conn->lock, flags);

	/* Check connection state */
	if (conn->state == QUIC_STATE_CLOSED ||
	    conn->state == QUIC_STATE_DRAINING) {
		spin_unlock_irqrestore(&conn->lock, flags);
		return;
	}

	/* Clear timer deadline */
	conn->timer_deadlines[QUIC_TIMER_ACK] = 0;

	spin_unlock_irqrestore(&conn->lock, flags);

	/* Generate ACK frames for each packet number space */
	for (i = 0; i < QUIC_PN_SPACE_MAX; i++) {
		if (quic_ack_should_send(conn, i)) {
			struct sk_buff *skb = alloc_skb(256, GFP_ATOMIC);
			if (skb) {
				int len = quic_ack_create(conn, i, skb);
				if (len > 0) {
					skb_queue_tail(&conn->pending_frames, skb);
				} else {
					kfree_skb(skb);
				}
			}
		}
	}

	/* Schedule transmission */
	schedule_work(&conn->tx_work);
}

/*
 * Idle timer callback
 *
 * Per RFC 9000 Section 10.1: If a max_idle_timeout is specified by
 * either endpoint in its transport parameters, the connection is
 * silently closed and its state is discarded when it remains idle
 */
static void quic_timer_idle_handler(struct timer_list *t)
{
	struct quic_connection *conn = from_timer(conn, t, timers[QUIC_TIMER_IDLE]);
	unsigned long flags;

	if (!conn)
		return;

	spin_lock_irqsave(&conn->lock, flags);

	/* Check connection state */
	if (conn->state == QUIC_STATE_CLOSED) {
		spin_unlock_irqrestore(&conn->lock, flags);
		return;
	}

	/* Clear timer deadline */
	conn->timer_deadlines[QUIC_TIMER_IDLE] = 0;

	/* Connection has been idle too long - close it */
	conn->state = QUIC_STATE_CLOSED;
	conn->error_code = QUIC_ERROR_NO_ERROR;

	spin_unlock_irqrestore(&conn->lock, flags);

	/* Wake up any waiting threads */
	if (conn->qsk)
		wake_up(&conn->qsk->event_wait);
}

/*
 * Handshake timer callback
 *
 * Per RFC 9000 Section 7: The QUIC handshake is considered complete
 * when the TLS handshake is complete
 */
static void quic_timer_handshake_handler(struct timer_list *t)
{
	struct quic_connection *conn = from_timer(conn, t, timers[QUIC_TIMER_HANDSHAKE]);
	unsigned long flags;

	if (!conn)
		return;

	spin_lock_irqsave(&conn->lock, flags);

	/* Check if handshake already complete */
	if (conn->handshake_complete ||
	    conn->state == QUIC_STATE_CLOSED) {
		spin_unlock_irqrestore(&conn->lock, flags);
		return;
	}

	/* Clear timer deadline */
	conn->timer_deadlines[QUIC_TIMER_HANDSHAKE] = 0;

	/* Handshake timeout - close connection */
	conn->state = QUIC_STATE_CLOSED;
	conn->error_code = QUIC_ERROR_INTERNAL_ERROR;

	spin_unlock_irqrestore(&conn->lock, flags);

	/* Wake up any waiting threads */
	if (conn->qsk)
		wake_up(&conn->qsk->event_wait);
}

/*
 * Path probe timer callback
 *
 * Per RFC 9000 Section 8.2.4: An endpoint SHOULD NOT probe a new path
 * with packets that are larger than the current maximum datagram size
 */
static void quic_timer_path_probe_handler(struct timer_list *t)
{
	struct quic_connection *conn = from_timer(conn, t, timers[QUIC_TIMER_PATH_PROBE]);
	struct quic_path *path;
	unsigned long flags;

	if (!conn)
		return;

	spin_lock_irqsave(&conn->lock, flags);

	/* Check connection state */
	if (conn->state == QUIC_STATE_CLOSED ||
	    conn->state == QUIC_STATE_DRAINING) {
		spin_unlock_irqrestore(&conn->lock, flags);
		return;
	}

	/* Clear timer deadline */
	conn->timer_deadlines[QUIC_TIMER_PATH_PROBE] = 0;

	spin_unlock_irqrestore(&conn->lock, flags);

	/* Check all paths that need probing */
	list_for_each_entry(path, &conn->paths, list) {
		if (quic_path_needs_probe(path)) {
			quic_path_on_probe_timeout(path);
		}
	}
}

/*
 * Initialize all timers for a connection
 *
 * This function sets up the timer infrastructure for loss detection,
 * ACK generation, idle timeout, handshake, and path probing.
 */
void quic_timer_init(struct quic_connection *conn)
{
	int i;

	if (!conn)
		return;

	/* Initialize all timer deadlines to 0 (unset) */
	for (i = 0; i < QUIC_TIMER_MAX; i++)
		conn->timer_deadlines[i] = 0;

	/* Set up timer callbacks */
	timer_setup(&conn->timers[QUIC_TIMER_LOSS], quic_timer_loss_handler, 0);
	timer_setup(&conn->timers[QUIC_TIMER_ACK], quic_timer_ack_handler, 0);
	timer_setup(&conn->timers[QUIC_TIMER_IDLE], quic_timer_idle_handler, 0);
	timer_setup(&conn->timers[QUIC_TIMER_HANDSHAKE], quic_timer_handshake_handler, 0);
	timer_setup(&conn->timers[QUIC_TIMER_PATH_PROBE], quic_timer_path_probe_handler, 0);
}

/*
 * Set a timer to fire at the specified time
 *
 * Per RFC 9002 Section 6.2: The loss detection timer is a single timer
 * and takes the earliest of three computed timeouts.
 */
void quic_timer_set(struct quic_connection *conn, u8 timer_type, ktime_t when)
{
	unsigned long flags;
	unsigned long expires;

	if (!conn || timer_type >= QUIC_TIMER_MAX)
		return;

	/* Validate deadline is in the future */
	if (ktime_before(when, ktime_get())) {
		/* Fire immediately - set to minimal future time */
		when = ktime_add_ms(ktime_get(), 1);
	}

	spin_lock_irqsave(&conn->lock, flags);

	/* Record the deadline */
	conn->timer_deadlines[timer_type] = when;

	/* Convert to jiffies and arm the timer */
	expires = quic_ktime_to_jiffies(when);

	spin_unlock_irqrestore(&conn->lock, flags);

	/* Modify the timer (handles both armed and unarmed states) */
	mod_timer(&conn->timers[timer_type], expires);
}

/*
 * Cancel a timer
 *
 * This function safely cancels a pending timer without waiting
 * for any running callback to complete (use with caution).
 */
void quic_timer_cancel(struct quic_connection *conn, u8 timer_type)
{
	unsigned long flags;

	if (!conn || timer_type >= QUIC_TIMER_MAX)
		return;

	spin_lock_irqsave(&conn->lock, flags);

	/* Clear the deadline */
	conn->timer_deadlines[timer_type] = 0;

	spin_unlock_irqrestore(&conn->lock, flags);

	/* Delete the timer - use del_timer not del_timer_sync to avoid deadlock */
	del_timer(&conn->timers[timer_type]);
}

/*
 * Cancel all timers synchronously
 *
 * This function should be called when destroying a connection
 * to ensure no timer callbacks are running.
 */
void quic_timer_cancel_all(struct quic_connection *conn)
{
	int i;

	if (!conn)
		return;

	for (i = 0; i < QUIC_TIMER_MAX; i++) {
		conn->timer_deadlines[i] = 0;
		del_timer_sync(&conn->timers[i]);
	}
}

/*
 * Calculate the loss detection timer deadline
 *
 * Per RFC 9002 Section 6.2: The loss detection timer is set based on
 * the timer's mode, which is set by the latest event.
 */
static ktime_t quic_timer_calculate_loss_deadline(struct quic_connection *conn)
{
	struct quic_path *path = conn->active_path;
	struct quic_pn_space *pn_space;
	ktime_t earliest_loss_time = 0;
	ktime_t pto_deadline = 0;
	u32 pto;
	int i;
	bool has_ack_eliciting = false;
	ktime_t earliest_sent_time = 0;

	/* Check for loss time in each packet number space */
	for (i = 0; i < QUIC_PN_SPACE_MAX; i++) {
		pn_space = &conn->pn_spaces[i];

		if (pn_space->loss_time != 0) {
			ktime_t loss_time = pn_space->loss_time;
			if (earliest_loss_time == 0 ||
			    ktime_before(loss_time, earliest_loss_time)) {
				earliest_loss_time = loss_time;
			}
		}

		/* Track earliest sent time for ack-eliciting packets */
		if (pn_space->ack_eliciting_in_flight > 0) {
			has_ack_eliciting = true;
			/* Would need to track earliest sent time per space */
		}
	}

	/* If there's a loss time set, use it */
	if (earliest_loss_time != 0)
		return earliest_loss_time;

	/* If no ack-eliciting packets in flight, don't set timer */
	if (!has_ack_eliciting && conn->handshake_confirmed)
		return 0;

	/* Calculate PTO */
	if (path)
		pto = quic_path_pto(path);
	else
		pto = 333000;  /* Default PTO in microseconds */

	/* Apply backoff */
	pto = pto << min(conn->pto_count, (u32)QUIC_TIMER_MAX_BACKOFF);

	/* Calculate deadline from time of last ack-eliciting packet */
	if (conn->time_of_last_ack_eliciting != 0) {
		pto_deadline = ktime_add_us(conn->time_of_last_ack_eliciting, pto);
	} else {
		/* Use current time if no ack-eliciting packets sent */
		pto_deadline = ktime_add_us(ktime_get(), pto);
	}

	/* For anti-deadlock during handshake, always arm timer */
	if (!conn->handshake_confirmed && pto_deadline == 0) {
		pto_deadline = ktime_add_us(ktime_get(), pto);
	}

	return pto_deadline;
}

/*
 * Calculate the ACK timer deadline
 *
 * Per RFC 9000 Section 13.2.1: An endpoint MUST send an ACK frame
 * within its advertised max_ack_delay after receiving an ack-eliciting packet
 */
static ktime_t quic_timer_calculate_ack_deadline(struct quic_connection *conn)
{
	struct quic_pn_space *pn_space;
	ktime_t earliest = 0;
	int i;

	for (i = 0; i < QUIC_PN_SPACE_MAX; i++) {
		pn_space = &conn->pn_spaces[i];

		/* Check if there are unacked packets that need ACKing */
		if (pn_space->last_ack_time != 0 && quic_ack_should_send(conn, i)) {
			ktime_t deadline;
			u32 delay_ms;

			/* Initial and Handshake packets: ACK immediately */
			if (i == QUIC_PN_SPACE_INITIAL || i == QUIC_PN_SPACE_HANDSHAKE)
				delay_ms = 0;
			else
				delay_ms = QUIC_TIMER_ACK_DELAY_MS;

			deadline = ktime_add_ms(pn_space->last_ack_time, delay_ms);

			if (earliest == 0 || ktime_before(deadline, earliest))
				earliest = deadline;
		}
	}

	return earliest;
}

/*
 * Calculate the idle timer deadline
 *
 * Per RFC 9000 Section 10.1: Each endpoint advertises a max_idle_timeout,
 * but the effective timeout is the minimum of the two
 */
static ktime_t quic_timer_calculate_idle_deadline(struct quic_connection *conn)
{
	u64 local_timeout = conn->local_params.max_idle_timeout;
	u64 remote_timeout = conn->remote_params.max_idle_timeout;
	u64 idle_timeout;
	u64 pto;

	/* Use minimum of local and remote, or 0 for no timeout */
	if (local_timeout == 0 && remote_timeout == 0)
		return 0;  /* No idle timeout */

	if (local_timeout == 0)
		idle_timeout = remote_timeout;
	else if (remote_timeout == 0)
		idle_timeout = local_timeout;
	else
		idle_timeout = min(local_timeout, remote_timeout);

	/* Per RFC 9000 Section 10.1: idle timeout is at least three times
	 * the current PTO to accommodate packet loss
	 */
	if (conn->active_path)
		pto = quic_path_pto(conn->active_path);
	else
		pto = 333000;  /* Default PTO */

	pto = (pto + 999) / 1000;  /* Convert to milliseconds */
	idle_timeout = max(idle_timeout, 3 * pto);

	return ktime_add_ms(ktime_get(), idle_timeout);
}

/*
 * Update all timers based on current connection state
 *
 * This function is called after events that may change timer deadlines,
 * such as packet transmission, ACK reception, or state changes.
 */
void quic_timer_update(struct quic_connection *conn)
{
	ktime_t loss_deadline;
	ktime_t ack_deadline;
	ktime_t idle_deadline;

	if (!conn)
		return;

	/* Skip if connection is closed or draining */
	if (conn->state == QUIC_STATE_CLOSED ||
	    conn->state == QUIC_STATE_DRAINING)
		return;

	/* Calculate loss detection timer */
	loss_deadline = quic_timer_calculate_loss_deadline(conn);
	if (loss_deadline != 0) {
		quic_timer_set(conn, QUIC_TIMER_LOSS, loss_deadline);
	} else {
		quic_timer_cancel(conn, QUIC_TIMER_LOSS);
	}

	/* Calculate ACK timer */
	ack_deadline = quic_timer_calculate_ack_deadline(conn);
	if (ack_deadline != 0) {
		quic_timer_set(conn, QUIC_TIMER_ACK, ack_deadline);
	} else {
		quic_timer_cancel(conn, QUIC_TIMER_ACK);
	}

	/* Calculate idle timer */
	idle_deadline = quic_timer_calculate_idle_deadline(conn);
	if (idle_deadline != 0) {
		quic_timer_set(conn, QUIC_TIMER_IDLE, idle_deadline);
	}

	/* Handshake timer is set separately when connection is initiated */

	/* Path probe timer is set by path validation code */
}

/*
 * Reset idle timer (called on packet activity)
 *
 * Per RFC 9000 Section 10.1: When a packet is received, the endpoint
 * that receives the packet restarts its idle timer
 */
void quic_timer_reset_idle(struct quic_connection *conn)
{
	ktime_t idle_deadline;

	if (!conn)
		return;

	idle_deadline = quic_timer_calculate_idle_deadline(conn);
	if (idle_deadline != 0)
		quic_timer_set(conn, QUIC_TIMER_IDLE, idle_deadline);
}

/*
 * Get the time until the next timer fires
 *
 * Returns the time in microseconds, or 0 if no timer is set
 */
u64 quic_timer_next_timeout_us(struct quic_connection *conn)
{
	ktime_t now = ktime_get();
	ktime_t earliest = 0;
	int i;

	if (!conn)
		return 0;

	for (i = 0; i < QUIC_TIMER_MAX; i++) {
		ktime_t deadline = conn->timer_deadlines[i];

		if (deadline == 0)
			continue;

		if (earliest == 0 || ktime_before(deadline, earliest))
			earliest = deadline;
	}

	if (earliest == 0)
		return 0;

	if (ktime_before(earliest, now))
		return 0;

	return ktime_to_us(ktime_sub(earliest, now));
}

/*
 * Check if any timer is pending
 */
bool quic_timer_pending(struct quic_connection *conn, u8 timer_type)
{
	if (!conn || timer_type >= QUIC_TIMER_MAX)
		return false;

	return timer_pending(&conn->timers[timer_type]);
}

/*
 * Arm the PTO timer after packet transmission
 *
 * Per RFC 9002 Section 6.2.1: A sender SHOULD restart its PTO timer
 * every time an ack-eliciting packet is sent
 */
void quic_timer_on_packet_sent(struct quic_connection *conn, bool ack_eliciting)
{
	if (!conn)
		return;

	if (ack_eliciting) {
		conn->time_of_last_ack_eliciting = ktime_get();
	}

	/* Reset idle timer on any activity */
	quic_timer_reset_idle(conn);

	/* Update loss detection timer */
	quic_timer_update(conn);
}

/*
 * Reset PTO count after receiving ACK
 *
 * Per RFC 9002 Section 6.2.1: The PTO backoff factor is reset when
 * an ACK is received
 */
void quic_timer_on_ack_received(struct quic_connection *conn)
{
	if (!conn)
		return;

	/* Reset PTO count */
	conn->pto_count = 0;

	/* Reset idle timer */
	quic_timer_reset_idle(conn);

	/* Recalculate timers */
	quic_timer_update(conn);
}

/*
 * Handle PTO timeout
 *
 * Per RFC 9002 Section 6.2.4: When the PTO timer expires, a sender
 * MUST send one or more packets containing ack-eliciting frames
 */
void quic_timer_on_pto_timeout(struct quic_connection *conn)
{
	if (!conn)
		return;

	/* Increment PTO count for backoff */
	if (conn->pto_count < QUIC_TIMER_MAX_BACKOFF)
		conn->pto_count++;

	/* Update timers with backed off PTO */
	quic_timer_update(conn);
}

/*
 * Start handshake timer
 */
void quic_timer_start_handshake(struct quic_connection *conn, u64 timeout_ms)
{
	ktime_t deadline;

	if (!conn)
		return;

	if (timeout_ms == 0)
		timeout_ms = 10000;  /* Default 10 second handshake timeout */

	deadline = ktime_add_ms(ktime_get(), timeout_ms);
	quic_timer_set(conn, QUIC_TIMER_HANDSHAKE, deadline);
}

/*
 * Stop handshake timer (called when handshake completes)
 */
void quic_timer_stop_handshake(struct quic_connection *conn)
{
	if (!conn)
		return;

	quic_timer_cancel(conn, QUIC_TIMER_HANDSHAKE);
}

/*
 * Arm path validation timer
 */
void quic_timer_start_path_validation(struct quic_connection *conn, u64 timeout_ms)
{
	ktime_t deadline;

	if (!conn)
		return;

	if (timeout_ms == 0)
		timeout_ms = 1000;  /* Default 1 second probe timeout */

	deadline = ktime_add_ms(ktime_get(), timeout_ms);
	quic_timer_set(conn, QUIC_TIMER_PATH_PROBE, deadline);
}

/*
 * Debug: Get timer state for diagnostics
 */
void quic_timer_get_state(struct quic_connection *conn, u8 timer_type,
			  ktime_t *deadline, bool *armed)
{
	if (!conn || timer_type >= QUIC_TIMER_MAX) {
		if (deadline)
			*deadline = 0;
		if (armed)
			*armed = false;
		return;
	}

	if (deadline)
		*deadline = conn->timer_deadlines[timer_type];
	if (armed)
		*armed = timer_pending(&conn->timers[timer_type]);
}
