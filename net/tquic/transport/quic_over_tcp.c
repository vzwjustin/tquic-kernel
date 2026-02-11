// SPDX-License-Identifier: GPL-2.0-only
/*
 * TQUIC: QUIC over TCP Transport Implementation
 *
 * Copyright (c) 2026 Linux Foundation
 * Kernel implementation by Justin Adams <spotty118@gmail.com>
 *
 * Implements QUIC packet transport over TCP for environments where
 * UDP is unavailable or unreliable. Based on draft-ietf-quic-over-tcp.
 *
 * Key Features:
 * - Length-prefixed framing for QUIC packets over TCP stream
 * - Packet coalescing for improved efficiency
 * - Flow control coordination between TCP and QUIC
 * - Congestion control coordination to prevent double response
 * - MTU handling adapted for TCP transport
 * - Keepalive coordination for NAT/firewall traversal
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/net.h>
#include <linux/socket.h>
#include <linux/tcp.h>
#include <linux/in.h>
#include <linux/in6.h>
#include <linux/workqueue.h>
#include <linux/kthread.h>
#include <linux/timer.h>
#include <linux/jiffies.h>
#include <net/sock.h>
#include <net/tcp.h>
#include <net/ipv6.h>

#include "../tquic_compat.h"

#include "quic_over_tcp.h"
#include "../protocol.h"

/*
 * =============================================================================
 * Global State
 * =============================================================================
 */

static struct workqueue_struct *quic_tcp_wq;
static bool quic_tcp_initialized;

/* Global statistics */
static struct {
	atomic64_t connections;
	atomic64_t listeners;
	atomic64_t total_packets_rx;
	atomic64_t total_packets_tx;
	atomic64_t fallback_triggers;
} quic_tcp_global_stats;

/*
 * =============================================================================
 * Buffer Management
 * =============================================================================
 */

static int rx_buf_init(struct quic_tcp_rx_buffer *buf, size_t size)
{
	buf->data = kvmalloc(size, GFP_KERNEL);
	if (!buf->data)
		return -ENOMEM;

	buf->size = size;
	buf->head = 0;
	buf->tail = 0;
	spin_lock_init(&buf->lock);

	return 0;
}

static void rx_buf_free(struct quic_tcp_rx_buffer *buf)
{
	kvfree(buf->data);
	buf->data = NULL;
}

static size_t rx_buf_used(struct quic_tcp_rx_buffer *buf)
{
	return buf->tail - buf->head;
}

static size_t rx_buf_free_space(struct quic_tcp_rx_buffer *buf)
{
	return buf->size - rx_buf_used(buf);
}

static int rx_buf_write(struct quic_tcp_rx_buffer *buf,
			const void *data, size_t len)
{
	size_t free_space;

	spin_lock_bh(&buf->lock);

	/* Compact buffer if needed */
	if (buf->head > 0 && buf->tail + len > buf->size) {
		size_t used = rx_buf_used(buf);
		memmove(buf->data, buf->data + buf->head, used);
		buf->head = 0;
		buf->tail = used;
	}

	free_space = rx_buf_free_space(buf);
	if (len > free_space) {
		spin_unlock_bh(&buf->lock);
		return -ENOSPC;
	}

	memcpy(buf->data + buf->tail, data, len);
	buf->tail += len;

	spin_unlock_bh(&buf->lock);
	return len;
}

static int rx_buf_read(struct quic_tcp_rx_buffer *buf,
		       void *data, size_t len)
{
	size_t avail;

	spin_lock_bh(&buf->lock);

	avail = rx_buf_used(buf);
	if (len > avail)
		len = avail;

	if (len > 0) {
		memcpy(data, buf->data + buf->head, len);
		buf->head += len;
	}

	spin_unlock_bh(&buf->lock);
	return len;
}

static int rx_buf_peek(struct quic_tcp_rx_buffer *buf,
		       void *data, size_t len)
{
	size_t avail;

	spin_lock_bh(&buf->lock);

	avail = rx_buf_used(buf);
	if (len > avail)
		len = avail;

	if (len > 0)
		memcpy(data, buf->data + buf->head, len);

	spin_unlock_bh(&buf->lock);
	return len;
}

static void rx_buf_consume(struct quic_tcp_rx_buffer *buf, size_t len)
{
	spin_lock_bh(&buf->lock);
	buf->head += min(len, rx_buf_used(buf));
	spin_unlock_bh(&buf->lock);
}

/* TX buffer functions */
static int tx_buf_init(struct quic_tcp_tx_buffer *buf, size_t size)
{
	buf->data = kvmalloc(size, GFP_KERNEL);
	if (!buf->data)
		return -ENOMEM;

	buf->size = size;
	buf->len = 0;
	buf->packets = 0;
	spin_lock_init(&buf->lock);

	return 0;
}

static void tx_buf_free(struct quic_tcp_tx_buffer *buf)
{
	kvfree(buf->data);
	buf->data = NULL;
}

/*
 * =============================================================================
 * Flow Control Coordination
 * =============================================================================
 *
 * QUIC over TCP requires coordination between TCP's flow control (handled
 * transparently by the kernel TCP stack) and QUIC's application-layer flow
 * control. We track buffer levels and coordinate window updates.
 */

static void flow_ctrl_init(struct quic_tcp_flow_control *fc)
{
	spin_lock_init(&fc->lock);
	fc->recv_window = QUIC_TCP_RX_BUF_SIZE;
	fc->send_window = QUIC_TCP_TX_BUF_SIZE;
	fc->bytes_in_flight = 0;
	fc->recv_blocked = false;
	fc->send_blocked = false;
	fc->last_window_update = ktime_get();
}

void quic_tcp_update_recv_window(struct quic_tcp_connection *conn)
{
	struct quic_tcp_flow_control *fc = &conn->flow_ctrl;
	size_t buf_used;
	bool was_blocked;
	bool now_blocked;

	if (!conn)
		return;

	spin_lock_bh(&conn->rx_buf.lock);
	buf_used = rx_buf_used(&conn->rx_buf);
	spin_unlock_bh(&conn->rx_buf.lock);

	spin_lock_bh(&fc->lock);

	was_blocked = fc->recv_blocked;
	fc->recv_window = QUIC_TCP_RX_BUF_SIZE - buf_used;

	/* Check for high/low water marks */
	if (buf_used >= QUIC_TCP_FC_HIGH_WATER) {
		if (!fc->recv_blocked) {
			fc->recv_blocked = true;
			atomic64_inc(&conn->stats.flow_control_pauses);
			pr_debug("quic_tcp: receive flow control activated\n");
		}
	} else if (buf_used <= QUIC_TCP_FC_LOW_WATER) {
		fc->recv_blocked = false;
	}

	now_blocked = fc->recv_blocked;
	fc->last_window_update = ktime_get();

	spin_unlock_bh(&fc->lock);

	/* Notify on state transition */
	if (was_blocked != now_blocked)
		quic_tcp_notify_flow_control(conn, now_blocked);

	/* Signal if we transitioned from blocked to unblocked */
	if (was_blocked && !now_blocked) {
		/* Resume receiving */
		queue_work(quic_tcp_wq, &conn->rx_work);
	}
}
EXPORT_SYMBOL_GPL(quic_tcp_update_recv_window);

u64 quic_tcp_get_send_credit(struct quic_tcp_connection *conn)
{
	struct quic_tcp_flow_control *fc;
	u64 credit;

	if (!conn)
		return 0;

	fc = &conn->flow_ctrl;

	spin_lock_bh(&fc->lock);
	if (fc->send_blocked) {
		credit = 0;
	} else {
		/* Available credit is send window minus bytes in flight */
		if (fc->send_window > fc->bytes_in_flight)
			credit = fc->send_window - fc->bytes_in_flight;
		else
			credit = 0;
	}
	spin_unlock_bh(&fc->lock);

	return credit;
}
EXPORT_SYMBOL_GPL(quic_tcp_get_send_credit);

void quic_tcp_set_flow_control_callback(struct quic_tcp_connection *conn,
					void (*callback)(void *data, bool blocked),
					void *data)
{
	unsigned long flags;

	if (!conn)
		return;

	spin_lock_irqsave(&conn->lock, flags);
	conn->fc_callback = callback;
	conn->fc_callback_data = data;
	spin_unlock_irqrestore(&conn->lock, flags);
}

/**
 * quic_tcp_notify_flow_control - Notify flow control state change
 * @conn: Connection
 * @blocked: True if flow is blocked, false if unblocked
 *
 * Internal helper to invoke the flow control callback when state changes.
 */
static void quic_tcp_notify_flow_control(struct quic_tcp_connection *conn,
					 bool blocked)
{
	void (*callback)(void *data, bool blocked);
	void *data;
	unsigned long flags;

	if (!conn)
		return;

	spin_lock_irqsave(&conn->lock, flags);
	callback = conn->fc_callback;
	data = conn->fc_callback_data;
	spin_unlock_irqrestore(&conn->lock, flags);

	if (callback)
		callback(data, blocked);
}
EXPORT_SYMBOL_GPL(quic_tcp_set_flow_control_callback);

/*
 * =============================================================================
 * Congestion Control Coordination
 * =============================================================================
 *
 * When QUIC runs over TCP, we need to avoid double congestion response.
 * TCP already handles congestion control for the underlying connection.
 * We can:
 * 1. Disable QUIC CC entirely and let TCP handle it (DISABLED mode)
 * 2. Pass TCP's CC info to QUIC for informational purposes (PASSTHROUGH mode)
 * 3. Use adaptive coordination (ADAPTIVE mode)
 */

static void cc_state_init(struct quic_tcp_cc_state *cc)
{
	spin_lock_init(&cc->lock);
	cc->mode = QUIC_TCP_CC_DISABLED;  /* Default: let TCP handle CC */
	cc->tcp_cwnd = 0;
	cc->tcp_rtt = 0;
	cc->tcp_rtt_var = 0;
	cc->last_update = ktime_get();
	cc->loss_events = 0;
	cc->ecn_ce_count = 0;
}

static void cc_state_update_from_tcp(struct quic_tcp_connection *conn)
{
	struct sock *sk;
	struct tcp_sock *tp;

	if (!conn || !conn->tcp_sk)
		return;

	sk = conn->tcp_sk->sk;
	if (!sk)
		return;

	/*
	 * Kernel 6.12+ removed kernel_getsockopt().
	 * Access tcp_sock fields directly via tcp_sk() macro.
	 */
	tp = tcp_sk(sk);
	if (!tp)
		return;

	spin_lock_bh(&conn->cc_state.lock);

	conn->cc_state.tcp_cwnd = tp->snd_cwnd * tp->mss_cache;
	conn->cc_state.tcp_rtt = tp->srtt_us >> 3;  /* Convert from shifted value */
	conn->cc_state.tcp_rtt_var = tp->mdev_us >> 2;  /* RTT variance */
	conn->cc_state.last_update = ktime_get();

	spin_unlock_bh(&conn->cc_state.lock);
}

int quic_tcp_get_cc_info(struct quic_tcp_connection *conn,
			 u32 *cwnd, u32 *rtt, u32 *rtt_var)
{
	if (!conn)
		return -EINVAL;

	/* Refresh CC state from TCP */
	cc_state_update_from_tcp(conn);

	spin_lock_bh(&conn->cc_state.lock);

	if (cwnd)
		*cwnd = conn->cc_state.tcp_cwnd;
	if (rtt)
		*rtt = conn->cc_state.tcp_rtt;
	if (rtt_var)
		*rtt_var = conn->cc_state.tcp_rtt_var;

	spin_unlock_bh(&conn->cc_state.lock);

	return 0;
}
EXPORT_SYMBOL_GPL(quic_tcp_get_cc_info);

int quic_tcp_set_cc_mode(struct quic_tcp_connection *conn, int mode)
{
	if (!conn)
		return -EINVAL;

	if (mode < QUIC_TCP_CC_DISABLED || mode > QUIC_TCP_CC_ADAPTIVE)
		return -EINVAL;

	spin_lock_bh(&conn->cc_state.lock);
	conn->cc_state.mode = mode;
	spin_unlock_bh(&conn->cc_state.lock);

	pr_debug("quic_tcp: CC mode set to %d\n", mode);
	return 0;
}
EXPORT_SYMBOL_GPL(quic_tcp_set_cc_mode);

void quic_tcp_on_loss_event(struct quic_tcp_connection *conn)
{
	if (!conn)
		return;

	spin_lock_bh(&conn->cc_state.lock);
	conn->cc_state.loss_events++;

	/*
	 * In PASSTHROUGH or ADAPTIVE mode, we track loss events
	 * but don't reduce sending rate (TCP handles that).
	 * This information can be useful for QUIC-level retransmissions.
	 */
	if (conn->cc_state.mode == QUIC_TCP_CC_ADAPTIVE) {
		/* Could implement adaptive behavior here */
		pr_debug("quic_tcp: loss event %u in adaptive mode\n",
			 conn->cc_state.loss_events);
	}

	spin_unlock_bh(&conn->cc_state.lock);
}
EXPORT_SYMBOL_GPL(quic_tcp_on_loss_event);

/*
 * =============================================================================
 * MTU Handling
 * =============================================================================
 *
 * Over TCP, we don't have traditional PMTUD concerns since TCP handles
 * segmentation. However, we still need to respect QUIC packet size limits
 * and provide a sensible MTU to the QUIC layer.
 */

static void mtu_state_init(struct quic_tcp_mtu_state *mtu)
{
	mtu->current_mtu = QUIC_TCP_DEFAULT_MTU;
	mtu->max_mtu = QUIC_TCP_MAX_MTU;
	mtu->min_mtu = QUIC_TCP_MIN_MTU;
	mtu->probe_size = 0;
	mtu->probe_count = 0;
	mtu->last_probe = ktime_set(0, 0);
	mtu->state = QUIC_TCP_MTU_SEARCH_COMPLETE;  /* No probing needed for TCP */
}

u32 quic_tcp_get_mtu(struct quic_tcp_connection *conn)
{
	if (!conn)
		return QUIC_TCP_DEFAULT_MTU;

	return conn->mtu_state.current_mtu;
}
EXPORT_SYMBOL_GPL(quic_tcp_get_mtu);

int quic_tcp_probe_mtu(struct quic_tcp_connection *conn, u32 size)
{
	if (!conn)
		return -EINVAL;

	/*
	 * Over TCP, MTU probing is not needed since TCP handles segmentation.
	 * We simply validate the requested size is within bounds.
	 */
	if (size < QUIC_TCP_MIN_MTU || size > QUIC_TCP_MAX_MTU)
		return -EINVAL;

	/* For TCP, we can always use the requested size */
	conn->mtu_state.current_mtu = size;
	conn->mtu_state.state = QUIC_TCP_MTU_SEARCH_COMPLETE;

	pr_debug("quic_tcp: MTU set to %u\n", size);
	return 0;
}
EXPORT_SYMBOL_GPL(quic_tcp_probe_mtu);

int quic_tcp_set_mtu(struct quic_tcp_connection *conn, u32 mtu)
{
	if (!conn)
		return -EINVAL;

	if (mtu < QUIC_TCP_MIN_MTU || mtu > QUIC_TCP_MAX_MTU)
		return -EINVAL;

	conn->mtu_state.current_mtu = mtu;
	return 0;
}
EXPORT_SYMBOL_GPL(quic_tcp_set_mtu);

/*
 * =============================================================================
 * Keepalive Coordination
 * =============================================================================
 *
 * Coordinate keepalives between TCP (handled by kernel) and QUIC (PING frames).
 * We generally prefer QUIC-level keepalives since they're more meaningful to
 * the application, but TCP keepalives can help maintain NAT mappings.
 */

static void keepalive_timer_callback(struct timer_list *t)
{
	struct quic_tcp_keepalive *ka = from_timer(ka, t, timer);
	struct quic_tcp_connection *conn = container_of(ka,
		struct quic_tcp_connection, keepalive);

	if (conn->state != QUIC_TCP_STATE_CONNECTED)
		return;

	/* Queue keepalive work */
	queue_work(quic_tcp_wq, &conn->keepalive_work);
}

static void keepalive_init(struct quic_tcp_keepalive *ka)
{
	ka->tcp_enabled = false;
	ka->quic_enabled = true;  /* Default to QUIC keepalives */
	ka->interval_ms = QUIC_TCP_KEEPALIVE_INTERVAL_MS;
	ka->timeout_ms = QUIC_TCP_KEEPALIVE_TIMEOUT_MS;
	ka->last_activity = ktime_get();
	ka->last_keepalive = ktime_set(0, 0);
	ka->pending_pong = false;
	timer_setup(&ka->timer, keepalive_timer_callback, 0);
}

static void keepalive_start(struct quic_tcp_connection *conn)
{
	struct quic_tcp_keepalive *ka = &conn->keepalive;

	if (!ka->quic_enabled && !ka->tcp_enabled)
		return;

	ka->last_activity = ktime_get();
	mod_timer(&ka->timer, jiffies + msecs_to_jiffies(ka->interval_ms));
}

static void keepalive_stop(struct quic_tcp_connection *conn)
{
	del_timer_sync(&conn->keepalive.timer);
}

static void quic_tcp_keepalive_work(struct work_struct *work)
{
	struct quic_tcp_connection *conn =
		container_of(work, struct quic_tcp_connection, keepalive_work);
	struct quic_tcp_keepalive *ka = &conn->keepalive;
	s64 idle_ms;

	if (conn->state != QUIC_TCP_STATE_CONNECTED)
		return;

	idle_ms = ktime_ms_delta(ktime_get(), ka->last_activity);

	/* Check if we need to send a keepalive */
	if (idle_ms >= ka->interval_ms) {
		if (ka->quic_enabled) {
			/* Send QUIC PING */
			quic_tcp_send_ping(conn);
			atomic64_inc(&conn->stats.keepalives_sent);
		}

		/* Reset timer for next interval */
		mod_timer(&ka->timer, jiffies + msecs_to_jiffies(ka->interval_ms));
	} else {
		/* Reschedule for remaining time */
		mod_timer(&ka->timer,
			  jiffies + msecs_to_jiffies(ka->interval_ms - idle_ms));
	}

	/* Check for timeout */
	if (ka->pending_pong && idle_ms >= ka->timeout_ms) {
		pr_warn("quic_tcp: keepalive timeout, closing connection\n");
		conn->state = QUIC_TCP_STATE_CLOSING;
		queue_work(quic_tcp_wq, &conn->close_work);
	}
}

int quic_tcp_set_keepalive(struct quic_tcp_connection *conn,
			   bool enable, u32 interval_ms, u32 timeout_ms)
{
	struct quic_tcp_keepalive *ka;

	if (!conn)
		return -EINVAL;

	ka = &conn->keepalive;

	ka->quic_enabled = enable;
	ka->interval_ms = interval_ms ?: QUIC_TCP_KEEPALIVE_INTERVAL_MS;
	ka->timeout_ms = timeout_ms ?: QUIC_TCP_KEEPALIVE_TIMEOUT_MS;

	if (enable && conn->state == QUIC_TCP_STATE_CONNECTED) {
		keepalive_start(conn);
	} else {
		keepalive_stop(conn);
	}

	/* Also configure TCP keepalive if requested */
	if (ka->tcp_enabled && conn->tcp_sk) {
		struct sock *sk = conn->tcp_sk->sk;
		int idle = ka->interval_ms / 1000;
		int intvl = ka->interval_ms / 1000 / 3;

		/*
		 * Kernel 6.12+ removed kernel_setsockopt().
		 * Access socket fields directly instead.
		 */
		lock_sock(sk);
		sock_set_keepalive(sk);
		if (idle > 0)
			tcp_sock_set_keepidle(sk, idle);
		if (intvl > 0)
			tcp_sock_set_keepintvl(sk, intvl);
		tcp_sock_set_keepcnt(sk, 3);
		release_sock(sk);
	}

	return 0;
}
EXPORT_SYMBOL_GPL(quic_tcp_set_keepalive);

void quic_tcp_activity(struct quic_tcp_connection *conn)
{
	if (!conn)
		return;

	conn->keepalive.last_activity = ktime_get();
	conn->keepalive.pending_pong = false;
}
EXPORT_SYMBOL_GPL(quic_tcp_activity);

int quic_tcp_send_ping(struct quic_tcp_connection *conn)
{
	/*
	 * QUIC PING frame is type 0x01, no payload.
	 * For a minimal PING, we need a short header + PING frame.
	 * This is a simplified implementation.
	 */
	static const u8 ping_frame[] = { 0x01 };  /* PING frame type */

	if (!conn || conn->state != QUIC_TCP_STATE_CONNECTED)
		return -ENOTCONN;

	/* Mark that we're expecting a response */
	conn->keepalive.pending_pong = true;
	conn->keepalive.last_keepalive = ktime_get();

	/*
	 * In a full implementation, this would construct a proper
	 * QUIC short header packet with the PING frame.
	 * For now, we rely on the QUIC connection layer to handle this.
	 */
	if (conn->quic_conn) {
		/* Would trigger QUIC connection to send PING */
		pr_debug("quic_tcp: sending QUIC PING\n");
	}

	return 0;
}
EXPORT_SYMBOL_GPL(quic_tcp_send_ping);

/*
 * =============================================================================
 * TCP Socket Operations
 * =============================================================================
 */

static void quic_tcp_data_ready(struct sock *sk)
{
	struct quic_tcp_connection *conn = sk->sk_user_data;

	if (conn) {
		quic_tcp_activity(conn);
		queue_work(quic_tcp_wq, &conn->rx_work);
	}
}

/* Separate callback for listener sockets to avoid type confusion */
static void quic_tcp_listener_data_ready(struct sock *sk)
{
	struct quic_tcp_listener *listener = sk->sk_user_data;

	if (listener && listener->running)
		queue_work(quic_tcp_wq, &listener->accept_work);
}

static void quic_tcp_write_space(struct sock *sk)
{
	struct quic_tcp_connection *conn = sk->sk_user_data;

	if (conn) {
		bool was_blocked;

		/* Update flow control state */
		spin_lock_bh(&conn->flow_ctrl.lock);
		was_blocked = conn->flow_ctrl.send_blocked;
		conn->flow_ctrl.send_blocked = false;
		spin_unlock_bh(&conn->flow_ctrl.lock);

		/* Notify if we transitioned from blocked to unblocked */
		if (was_blocked)
			quic_tcp_notify_flow_control(conn, false);

		queue_work(quic_tcp_wq, &conn->tx_work);
	}
}

static void quic_tcp_state_change(struct sock *sk)
{
	struct quic_tcp_connection *conn = sk->sk_user_data;

	if (!conn)
		return;

	switch (sk->sk_state) {
	case TCP_ESTABLISHED:
		conn->state = QUIC_TCP_STATE_CONNECTED;
		keepalive_start(conn);
		pr_debug("quic_tcp: connection established\n");
		break;

	case TCP_CLOSE:
	case TCP_CLOSE_WAIT:
		conn->state = QUIC_TCP_STATE_CLOSED;
		keepalive_stop(conn);
		queue_work(quic_tcp_wq, &conn->close_work);
		break;
	}
}

static void setup_tcp_callbacks(struct quic_tcp_connection *conn)
{
	struct sock *sk = conn->tcp_sk->sk;

	write_lock_bh(&sk->sk_callback_lock);

	/* Save original callbacks */
	conn->saved_data_ready = sk->sk_data_ready;
	conn->saved_write_space = sk->sk_write_space;
	conn->saved_state_change = sk->sk_state_change;

	/* Install our callbacks */
	sk->sk_user_data = conn;
	sk->sk_data_ready = quic_tcp_data_ready;
	sk->sk_write_space = quic_tcp_write_space;
	sk->sk_state_change = quic_tcp_state_change;

	write_unlock_bh(&sk->sk_callback_lock);
}

static void restore_tcp_callbacks(struct quic_tcp_connection *conn)
{
	struct sock *sk;

	if (!conn || !conn->tcp_sk)
		return;

	sk = conn->tcp_sk->sk;

	write_lock_bh(&sk->sk_callback_lock);

	if (conn->saved_data_ready)
		sk->sk_data_ready = conn->saved_data_ready;
	if (conn->saved_write_space)
		sk->sk_write_space = conn->saved_write_space;
	if (conn->saved_state_change)
		sk->sk_state_change = conn->saved_state_change;

	sk->sk_user_data = NULL;

	write_unlock_bh(&sk->sk_callback_lock);
}

/*
 * =============================================================================
 * Receive Processing
 * =============================================================================
 */

static void quic_tcp_rx_work(struct work_struct *work)
{
	struct quic_tcp_connection *conn =
		container_of(work, struct quic_tcp_connection, rx_work);
	struct msghdr msg = { .msg_flags = MSG_DONTWAIT };
	struct kvec iov;
	u8 tmp_buf[4096];
	int ret;

	if (conn->state != QUIC_TCP_STATE_CONNECTED)
		return;

	/* Check flow control */
	if (conn->flow_ctrl.recv_blocked) {
		pr_debug("quic_tcp: receive blocked by flow control\n");
		return;
	}

	/* Read data from TCP socket */
	iov.iov_base = tmp_buf;
	iov.iov_len = sizeof(tmp_buf);

	while ((ret = kernel_recvmsg(conn->tcp_sk, &msg, &iov, 1,
				     sizeof(tmp_buf), MSG_DONTWAIT)) > 0) {
		/* Add to RX buffer */
		if (rx_buf_write(&conn->rx_buf, tmp_buf, ret) < 0) {
			pr_warn("quic_tcp: RX buffer full\n");
			break;
		}

		atomic64_inc(&conn->stats.tcp_segments_rx);

		/* Update flow control */
		quic_tcp_update_recv_window(conn);

		if (conn->flow_ctrl.recv_blocked)
			break;
	}

	/* Process complete QUIC packets from buffer */
	while (rx_buf_used(&conn->rx_buf) >= QUIC_TCP_LENGTH_FIELD_SIZE) {
		__be16 len_be;
		u16 pkt_len;
		u8 *pkt_buf;

		/* Peek at length field */
		if (rx_buf_peek(&conn->rx_buf, &len_be, sizeof(len_be)) < 2)
			break;

		pkt_len = ntohs(len_be);

		/* Validate length */
		if (pkt_len < QUIC_TCP_MIN_PACKET_SIZE ||
		    pkt_len > QUIC_TCP_MAX_PACKET_SIZE) {
			pr_warn("quic_tcp: invalid packet length %u\n", pkt_len);
			atomic64_inc(&conn->stats.framing_errors);
			/* Skip length field and try to resync */
			rx_buf_consume(&conn->rx_buf, sizeof(len_be));
			continue;
		}

		/* Check if full packet available */
		if (rx_buf_used(&conn->rx_buf) < sizeof(len_be) + pkt_len)
			break;

		/* Consume length field */
		rx_buf_consume(&conn->rx_buf, sizeof(len_be));

		/* Read packet */
		pkt_buf = kmalloc(pkt_len, GFP_KERNEL);
		if (!pkt_buf)
			break;

		if (rx_buf_read(&conn->rx_buf, pkt_buf, pkt_len) < pkt_len) {
			kfree(pkt_buf);
			break;
		}

		/* Deliver to callback or QUIC connection */
		if (conn->packet_callback) {
			conn->packet_callback(conn->callback_data, pkt_buf, pkt_len);
		} else if (conn->quic_conn) {
			/* Would call QUIC packet input here */
			pr_debug("quic_tcp: received %u byte QUIC packet\n", pkt_len);
		}

		atomic64_inc(&conn->stats.packets_rx);
		atomic64_add(pkt_len, &conn->stats.bytes_rx);
		atomic64_inc(&quic_tcp_global_stats.total_packets_rx);

		kfree(pkt_buf);

		/* Update receive window after processing */
		quic_tcp_update_recv_window(conn);
	}
}

/*
 * =============================================================================
 * Transmit Processing
 * =============================================================================
 */

static int do_tcp_send(struct quic_tcp_connection *conn,
		       const void *data, size_t len)
{
	struct msghdr msg = { .msg_flags = MSG_DONTWAIT };
	struct kvec iov = { .iov_base = (void *)data, .iov_len = len };
	int ret;

	ret = kernel_sendmsg(conn->tcp_sk, &msg, &iov, 1, len);
	if (ret > 0)
		atomic64_inc(&conn->stats.tcp_segments_tx);

	return ret;
}

static void quic_tcp_tx_work(struct work_struct *work)
{
	struct quic_tcp_connection *conn =
		container_of(work, struct quic_tcp_connection, tx_work);

	/* Flush any pending coalesced packets */
	quic_tcp_flush(conn);
}

int quic_tcp_send(struct quic_tcp_connection *conn,
		  const void *data, size_t len)
{
	struct quic_tcp_tx_buffer *tx = &conn->tx_buf;
	__be16 len_be;
	int ret;

	if (!conn || conn->state != QUIC_TCP_STATE_CONNECTED)
		return -ENOTCONN;

	if (len < QUIC_TCP_MIN_PACKET_SIZE || len > QUIC_TCP_MAX_PACKET_SIZE)
		return -EINVAL;

	/* Check flow control */
	if (conn->flow_ctrl.send_blocked) {
		atomic64_inc(&conn->stats.flow_control_pauses);
		return -EAGAIN;
	}

	spin_lock_bh(&tx->lock);

	/* Check if we should flush first */
	if (tx->len + sizeof(len_be) + len > tx->size ||
	    tx->packets >= QUIC_TCP_MAX_COALESCE) {
		spin_unlock_bh(&tx->lock);
		quic_tcp_flush(conn);
		spin_lock_bh(&tx->lock);
	}

	/* Record first packet time for coalesce timeout */
	if (tx->packets == 0)
		tx->timestamp = ktime_get();

	/* Add framed packet to buffer */
	len_be = htons(len);
	memcpy(tx->data + tx->len, &len_be, sizeof(len_be));
	tx->len += sizeof(len_be);
	memcpy(tx->data + tx->len, data, len);
	tx->len += len;
	tx->packets++;

	atomic64_inc(&conn->stats.packets_tx);
	atomic64_add(len, &conn->stats.bytes_tx);
	atomic64_inc(&quic_tcp_global_stats.total_packets_tx);

	spin_unlock_bh(&tx->lock);

	/* Mark activity for keepalive */
	quic_tcp_activity(conn);

	/* Immediate flush if configured or only one packet */
	if (!conn->config.coalesce_enabled || tx->packets == 1) {
		ret = quic_tcp_flush(conn);
		if (ret < 0)
			return ret;
	}

	return len;
}
EXPORT_SYMBOL_GPL(quic_tcp_send);

int quic_tcp_flush(struct quic_tcp_connection *conn)
{
	struct quic_tcp_tx_buffer *tx = &conn->tx_buf;
	int ret = 0;
	bool notify_blocked = false;

	if (!conn || conn->state != QUIC_TCP_STATE_CONNECTED)
		return -ENOTCONN;

	spin_lock_bh(&tx->lock);

	if (tx->len > 0) {
		ret = do_tcp_send(conn, tx->data, tx->len);

		if (ret < 0) {
			/* Send failed, check if blocked */
			if (ret == -EAGAIN || ret == -EWOULDBLOCK) {
				spin_lock_bh(&conn->flow_ctrl.lock);
				if (!conn->flow_ctrl.send_blocked) {
					conn->flow_ctrl.send_blocked = true;
					notify_blocked = true;
				}
				spin_unlock_bh(&conn->flow_ctrl.lock);
			}
		} else {
			if (tx->packets > 1)
				atomic64_inc(&conn->stats.coalesce_count);

			tx->len = 0;
			tx->packets = 0;
		}
	}

	spin_unlock_bh(&tx->lock);

	/* Notify outside of locks to avoid potential deadlocks */
	if (notify_blocked)
		quic_tcp_notify_flow_control(conn, true);

	return ret;
}
EXPORT_SYMBOL_GPL(quic_tcp_flush);

int quic_tcp_recv(struct quic_tcp_connection *conn, void *buf, size_t size)
{
	/* Packets are delivered asynchronously via rx_work and callback */
	return -EWOULDBLOCK;
}
EXPORT_SYMBOL_GPL(quic_tcp_recv);

/*
 * =============================================================================
 * Packet Delivery Callbacks
 * =============================================================================
 */

void quic_tcp_set_packet_callback(struct quic_tcp_connection *conn,
				  void (*callback)(void *data, const u8 *packet, size_t len),
				  void *data)
{
	if (!conn)
		return;

	spin_lock_bh(&conn->lock);
	conn->packet_callback = callback;
	conn->callback_data = data;
	spin_unlock_bh(&conn->lock);
}
EXPORT_SYMBOL_GPL(quic_tcp_set_packet_callback);

void quic_tcp_set_listener_callback(struct quic_tcp_listener *listener,
				    void (*callback)(void *data, struct quic_tcp_connection *conn),
				    void *data)
{
	if (!listener)
		return;

	spin_lock(&listener->conn_lock);
	listener->new_conn_callback = callback;
	listener->callback_data = data;
	spin_unlock(&listener->conn_lock);
}
EXPORT_SYMBOL_GPL(quic_tcp_set_listener_callback);

/*
 * =============================================================================
 * Configuration
 * =============================================================================
 */

int quic_tcp_set_config(struct quic_tcp_connection *conn,
			struct quic_tcp_config *config)
{
	if (!conn || !config)
		return -EINVAL;

	spin_lock_bh(&conn->lock);
	memcpy(&conn->config, config, sizeof(*config));
	spin_unlock_bh(&conn->lock);

	/* Apply TCP socket options */
	if (conn->tcp_sk) {
		struct sock *sk = conn->tcp_sk->sk;

		/*
		 * Kernel 6.12+ removed kernel_setsockopt().
		 * Use tcp_sock_set_* helpers instead.
		 */
		if (config->tcp_nodelay)
			tcp_sock_set_nodelay(sk);

		if (config->tcp_cork)
			tcp_sock_set_cork(sk, true);
		else
			tcp_sock_set_cork(sk, false);
	}

	/* Update CC mode */
	quic_tcp_set_cc_mode(conn, config->cc_mode);

	/* Update keepalive settings */
	if (config->keepalive_interval > 0) {
		quic_tcp_set_keepalive(conn, true,
				       config->keepalive_interval,
				       config->keepalive_interval * 4);
	}

	return 0;
}
EXPORT_SYMBOL_GPL(quic_tcp_set_config);

int quic_tcp_get_config(struct quic_tcp_connection *conn,
			struct quic_tcp_config *config)
{
	if (!conn || !config)
		return -EINVAL;

	spin_lock_bh(&conn->lock);
	memcpy(config, &conn->config, sizeof(*config));
	spin_unlock_bh(&conn->lock);

	return 0;
}
EXPORT_SYMBOL_GPL(quic_tcp_get_config);

/*
 * =============================================================================
 * Statistics
 * =============================================================================
 */

void quic_tcp_get_stats(struct quic_tcp_connection *conn,
			struct quic_tcp_stats *stats)
{
	if (!conn || !stats)
		return;

	stats->packets_rx = atomic64_read(&conn->stats.packets_rx);
	stats->packets_tx = atomic64_read(&conn->stats.packets_tx);
	stats->bytes_rx = atomic64_read(&conn->stats.bytes_rx);
	stats->bytes_tx = atomic64_read(&conn->stats.bytes_tx);
	stats->coalesce_count = atomic64_read(&conn->stats.coalesce_count);
	stats->tcp_segments_rx = atomic64_read(&conn->stats.tcp_segments_rx);
	stats->tcp_segments_tx = atomic64_read(&conn->stats.tcp_segments_tx);
	stats->framing_errors = atomic64_read(&conn->stats.framing_errors);
	stats->flow_control_pauses = atomic64_read(&conn->stats.flow_control_pauses);
	stats->keepalives_sent = atomic64_read(&conn->stats.keepalives_sent);
	stats->keepalives_recv = atomic64_read(&conn->stats.keepalives_recv);
}
EXPORT_SYMBOL_GPL(quic_tcp_get_stats);

/*
 * =============================================================================
 * Connection Management
 * =============================================================================
 */

static void quic_tcp_close_work(struct work_struct *work)
{
	struct quic_tcp_connection *conn =
		container_of(work, struct quic_tcp_connection, close_work);

	pr_debug("quic_tcp: connection closed\n");

	/* Stop keepalive */
	keepalive_stop(conn);

	/* Notify QUIC connection */
	if (conn->quic_conn) {
		/* Would notify QUIC of transport failure */
	}
}

static void init_connection_defaults(struct quic_tcp_connection *conn)
{
	/* Initialize flow control */
	flow_ctrl_init(&conn->flow_ctrl);

	/* Initialize congestion control coordination */
	cc_state_init(&conn->cc_state);

	/* Initialize MTU state */
	mtu_state_init(&conn->mtu_state);

	/* Initialize keepalive */
	keepalive_init(&conn->keepalive);

	/* Initialize default config */
	conn->config.coalesce_enabled = true;
	conn->config.coalesce_timeout = QUIC_TCP_COALESCE_TIMEOUT_US;
	conn->config.max_coalesce = QUIC_TCP_MAX_COALESCE;
	conn->config.tcp_nodelay = true;
	conn->config.tcp_cork = false;
	conn->config.cc_mode = QUIC_TCP_CC_DISABLED;
	conn->config.keepalive_interval = QUIC_TCP_KEEPALIVE_INTERVAL_MS;
	conn->config.mtu_discovery = false;  /* Not needed for TCP */
}

struct quic_tcp_connection *quic_tcp_connect(struct sockaddr *addr,
					     int addrlen,
					     struct tquic_connection *quic_conn)
{
	struct quic_tcp_connection *conn;
	int ret;

	if (!quic_tcp_initialized)
		return ERR_PTR(-ENODEV);

	conn = kzalloc(sizeof(*conn), GFP_KERNEL);
	if (!conn)
		return ERR_PTR(-ENOMEM);

	/* Initialize buffers */
	ret = rx_buf_init(&conn->rx_buf, QUIC_TCP_RX_BUF_SIZE);
	if (ret)
		goto err_free_conn;

	ret = tx_buf_init(&conn->tx_buf, QUIC_TCP_TX_BUF_SIZE);
	if (ret)
		goto err_free_rx;

	/* CF-077: refuse to create socket without valid namespace */
	if (!quic_conn || !quic_conn->sk) {
		pr_warn_once("tquic_tcp: cannot create socket without connection\n");
		ret = -EINVAL;
		goto err_free_tx;
	}

	ret = sock_create_kern(sock_net(quic_conn->sk),
			       addr->sa_family,
			       SOCK_STREAM,
			       IPPROTO_TCP,
			       &conn->tcp_sk);
	if (ret)
		goto err_free_tx;

	/* Initialize state */
	conn->quic_conn = quic_conn;
	conn->state = QUIC_TCP_STATE_CONNECTING;
	spin_lock_init(&conn->lock);
	atomic_set(&conn->refcount, 1);
	INIT_LIST_HEAD(&conn->list);
	INIT_WORK(&conn->rx_work, quic_tcp_rx_work);
	INIT_WORK(&conn->tx_work, quic_tcp_tx_work);
	INIT_WORK(&conn->close_work, quic_tcp_close_work);
	INIT_WORK(&conn->keepalive_work, quic_tcp_keepalive_work);

	/* Initialize subsystems */
	init_connection_defaults(conn);

	/* Set socket options */
	/*
	 * Kernel 6.12+ removed kernel_setsockopt().
	 * Use tcp_sock_set_nodelay() helper instead.
	 */
	tcp_sock_set_nodelay(conn->tcp_sk->sk);

	/* Setup callbacks before connect */
	setup_tcp_callbacks(conn);

	/* Connect */
	ret = kernel_connect(conn->tcp_sk, addr, addrlen, O_NONBLOCK);
	if (ret && ret != -EINPROGRESS)
		goto err_free_sock;

	atomic64_inc(&quic_tcp_global_stats.connections);
	pr_info("quic_tcp: connecting...\n");

	return conn;

err_free_sock:
	restore_tcp_callbacks(conn);
	sock_release(conn->tcp_sk);
err_free_tx:
	tx_buf_free(&conn->tx_buf);
err_free_rx:
	rx_buf_free(&conn->rx_buf);
err_free_conn:
	kfree(conn);
	return ERR_PTR(ret);
}
EXPORT_SYMBOL_GPL(quic_tcp_connect);

void quic_tcp_close(struct quic_tcp_connection *conn)
{
	if (!conn)
		return;

	conn->state = QUIC_TCP_STATE_CLOSING;

	/* Stop keepalive */
	keepalive_stop(conn);

	/* Cancel pending work */
	cancel_work_sync(&conn->rx_work);
	cancel_work_sync(&conn->tx_work);
	cancel_work_sync(&conn->keepalive_work);

	/* Flush pending data */
	quic_tcp_flush(conn);

	/* Restore callbacks and close TCP socket */
	if (conn->tcp_sk) {
		restore_tcp_callbacks(conn);
		kernel_sock_shutdown(conn->tcp_sk, SHUT_RDWR);
		sock_release(conn->tcp_sk);
		conn->tcp_sk = NULL;
	}

	/* Free buffers */
	rx_buf_free(&conn->rx_buf);
	tx_buf_free(&conn->tx_buf);

	conn->state = QUIC_TCP_STATE_CLOSED;

	kfree(conn);
}
EXPORT_SYMBOL_GPL(quic_tcp_close);

void quic_tcp_conn_put(struct quic_tcp_connection *conn)
{
	if (!conn)
		return;

	if (atomic_dec_and_test(&conn->refcount))
		quic_tcp_close(conn);
}
EXPORT_SYMBOL_GPL(quic_tcp_conn_put);

/*
 * =============================================================================
 * QUIC Stack Integration
 * =============================================================================
 */

int quic_tcp_attach_to_path(struct quic_tcp_connection *conn,
			    struct tquic_path *path)
{
	if (!conn || !path)
		return -EINVAL;

	/* Store connection reference in path's transport data */
	/* This would typically be done via path->transport_data or similar */

	pr_debug("quic_tcp: attached to QUIC path %u\n", path->path_id);
	return 0;
}
EXPORT_SYMBOL_GPL(quic_tcp_attach_to_path);

int quic_tcp_detach_from_path(struct quic_tcp_connection *conn)
{
	if (!conn)
		return -EINVAL;

	pr_debug("quic_tcp: detached from QUIC path\n");
	return 0;
}
EXPORT_SYMBOL_GPL(quic_tcp_detach_from_path);

/*
 * =============================================================================
 * Listener Management
 * =============================================================================
 */

static void quic_tcp_accept_work(struct work_struct *work)
{
	struct quic_tcp_listener *listener =
		container_of(work, struct quic_tcp_listener, accept_work);
	struct socket *newsock;
	struct quic_tcp_connection *conn;
	int ret;

	while (listener->running) {
		ret = kernel_accept(listener->tcp_sk, &newsock, O_NONBLOCK);
		if (ret == -EAGAIN || ret == -EWOULDBLOCK) {
			/* No pending connections, wait to be woken up */
			break;
		}
		if (ret < 0)
			break;

		/* Create connection for accepted socket */
		conn = kzalloc(sizeof(*conn), GFP_KERNEL);
		if (!conn) {
			sock_release(newsock);
			continue;
		}

		ret = rx_buf_init(&conn->rx_buf, QUIC_TCP_RX_BUF_SIZE);
		if (ret) {
			sock_release(newsock);
			kfree(conn);
			continue;
		}

		ret = tx_buf_init(&conn->tx_buf, QUIC_TCP_TX_BUF_SIZE);
		if (ret) {
			rx_buf_free(&conn->rx_buf);
			sock_release(newsock);
			kfree(conn);
			continue;
		}

		conn->tcp_sk = newsock;
		conn->state = QUIC_TCP_STATE_CONNECTED;
		spin_lock_init(&conn->lock);
		atomic_set(&conn->refcount, 1);
		INIT_LIST_HEAD(&conn->list);
		INIT_WORK(&conn->rx_work, quic_tcp_rx_work);
		INIT_WORK(&conn->tx_work, quic_tcp_tx_work);
		INIT_WORK(&conn->close_work, quic_tcp_close_work);
		INIT_WORK(&conn->keepalive_work, quic_tcp_keepalive_work);

		init_connection_defaults(conn);
		setup_tcp_callbacks(conn);

		/* Start keepalive */
		keepalive_start(conn);

		/* Add to listener's connection list */
		spin_lock(&listener->conn_lock);
		list_add_tail(&conn->list, &listener->connections);
		spin_unlock(&listener->conn_lock);

		/* Notify via callback */
		if (listener->new_conn_callback) {
			listener->new_conn_callback(listener->callback_data, conn);
		}

		atomic64_inc(&quic_tcp_global_stats.connections);
		pr_info("quic_tcp: accepted connection\n");
	}
}

struct quic_tcp_listener *quic_tcp_listen(u16 port)
{
	struct quic_tcp_listener *listener;
	struct sockaddr_in6 addr;
	int ret;

	if (!quic_tcp_initialized)
		return ERR_PTR(-ENODEV);

	listener = kzalloc(sizeof(*listener), GFP_KERNEL);
	if (!listener)
		return ERR_PTR(-ENOMEM);

	/*
	 * SECURITY FIX (CF-077): Use the caller's network namespace
	 * instead of init_net to support containers/namespaces.
	 */
	ret = sock_create_kern(current->nsproxy->net_ns, AF_INET6,
			       SOCK_STREAM, IPPROTO_TCP,
			       &listener->tcp_sk);
	if (ret)
		goto err_free;

	/* Set socket options */
	/*
	 * Kernel 6.12+ removed kernel_setsockopt().
	 * Access socket fields directly.
	 */
	{
		struct sock *sk = listener->tcp_sk->sk;

		lock_sock(sk);
		sk->sk_reuse = SK_CAN_REUSE;
		/* Set IPV6_V6ONLY via ipv6_pinfo->ipv6only flag */
		if (sk->sk_family == AF_INET6) {
			struct ipv6_pinfo *np = inet6_sk(sk);
			if (np)
				np->ipv6only = 1;
		}
		release_sock(sk);
	}

	/* Bind */
	memset(&addr, 0, sizeof(addr));
	addr.sin6_family = AF_INET6;
	addr.sin6_port = htons(port);
	addr.sin6_addr = in6addr_any;

	ret = kernel_bind(listener->tcp_sk, (struct sockaddr_unsized *)&addr,
			  sizeof(addr));
	if (ret)
		goto err_sock;

	/* Listen */
	ret = kernel_listen(listener->tcp_sk, 128);
	if (ret)
		goto err_sock;

	/* Initialize state */
	listener->port = port;
	listener->running = true;
	INIT_LIST_HEAD(&listener->connections);
	spin_lock_init(&listener->conn_lock);
	INIT_WORK(&listener->accept_work, quic_tcp_accept_work);

	/* Setup data_ready callback for accept - use listener-specific callback */
	{
		struct sock *sk = listener->tcp_sk->sk;
		write_lock_bh(&sk->sk_callback_lock);
		sk->sk_user_data = listener;
		sk->sk_data_ready = quic_tcp_listener_data_ready;
		write_unlock_bh(&sk->sk_callback_lock);
	}

	atomic64_inc(&quic_tcp_global_stats.listeners);
	pr_info("quic_tcp: listening on port %u\n", port);

	return listener;

err_sock:
	sock_release(listener->tcp_sk);
err_free:
	kfree(listener);
	return ERR_PTR(ret);
}
EXPORT_SYMBOL_GPL(quic_tcp_listen);

void quic_tcp_stop_listen(struct quic_tcp_listener *listener)
{
	struct quic_tcp_connection *conn, *tmp;

	if (!listener)
		return;

	listener->running = false;
	cancel_work_sync(&listener->accept_work);

	/* Close all accepted connections */
	spin_lock(&listener->conn_lock);
	list_for_each_entry_safe(conn, tmp, &listener->connections, list) {
		list_del(&conn->list);
		spin_unlock(&listener->conn_lock);
		quic_tcp_close(conn);
		spin_lock(&listener->conn_lock);
	}
	spin_unlock(&listener->conn_lock);

	/* Close listening socket */
	if (listener->tcp_sk) {
		sock_release(listener->tcp_sk);
		listener->tcp_sk = NULL;
	}

	pr_info("quic_tcp: stopped listening on port %u\n", listener->port);
	kfree(listener);
}
EXPORT_SYMBOL_GPL(quic_tcp_stop_listen);

struct quic_tcp_connection *quic_tcp_accept(struct quic_tcp_listener *listener)
{
	struct quic_tcp_connection *conn = NULL;

	if (!listener)
		return NULL;

	spin_lock(&listener->conn_lock);
	if (!list_empty(&listener->connections)) {
		conn = list_first_entry(&listener->connections,
					struct quic_tcp_connection, list);
		list_del(&conn->list);
	}
	spin_unlock(&listener->conn_lock);

	return conn;
}
EXPORT_SYMBOL_GPL(quic_tcp_accept);

/*
 * =============================================================================
 * Module Init/Exit
 * =============================================================================
 */

int tquic_over_tcp_init(void)
{
	if (quic_tcp_initialized)
		return 0;

	quic_tcp_wq = alloc_workqueue("quic_tcp", WQ_HIGHPRI | WQ_UNBOUND, 0);
	if (!quic_tcp_wq)
		return -ENOMEM;

	quic_tcp_initialized = true;
	pr_info("quic_tcp: QUIC-over-TCP transport initialized\n");

	return 0;
}

void tquic_over_tcp_exit(void)
{
	if (!quic_tcp_initialized)
		return;

	if (quic_tcp_wq) {
		flush_workqueue(quic_tcp_wq);
		destroy_workqueue(quic_tcp_wq);
		quic_tcp_wq = NULL;
	}

	quic_tcp_initialized = false;
	pr_info("quic_tcp: QUIC-over-TCP transport shutdown\n");
}

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("TQUIC over TCP Transport (draft-ietf-quic-over-tcp)");
MODULE_AUTHOR("Linux Foundation");
