/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * TQUIC: QUIC over TCP Transport
 *
 * Copyright (c) 2026 Linux Foundation
 *
 * This module implements QUIC tunneled over TCP for environments where
 * UDP is blocked or unreliable. Based on draft-ietf-quic-over-tcp.
 *
 * Use Cases:
 * - Enterprise networks blocking UDP
 * - Firewall traversal
 * - Middleboxes that mangle UDP
 * - Testing/debugging with TCP tooling
 *
 * Framing:
 * - Each QUIC packet is prefixed with a 2-byte length field
 * - Multiple QUIC packets can be coalesced in a TCP segment
 * - TCP handles reliability, so QUIC loss recovery is adapted
 *
 * Flow Control Coordination:
 * - QUIC flow control operates independently over the TCP stream
 * - TCP flow control is handled by the kernel TCP stack
 * - We coordinate to prevent buffer bloat
 *
 * Congestion Control Interaction:
 * - TCP provides its own congestion control
 * - QUIC CC is disabled to prevent double congestion response
 * - RTT measurements use TCP's view or application-level timing
 */

#ifndef _TQUIC_OVER_TCP_H
#define _TQUIC_OVER_TCP_H

#include <linux/types.h>
#include <linux/net.h>
#include <linux/socket.h>
#include <linux/skbuff.h>
#include <linux/workqueue.h>
#include <linux/timer.h>
#include <linux/ktime.h>
#include <net/sock.h>

struct tquic_connection;
struct tquic_path;

/*
 * =============================================================================
 * Constants
 * =============================================================================
 */

/* Framing format */
#define QUIC_TCP_LENGTH_FIELD_SIZE	2  /* 16-bit length prefix */
#define QUIC_TCP_MAX_PACKET_SIZE	16384  /* Max QUIC packet over TCP */
#define QUIC_TCP_MIN_PACKET_SIZE	21     /* Min QUIC packet */

/* Buffer sizes */
#define QUIC_TCP_RX_BUF_SIZE		65536
#define QUIC_TCP_TX_BUF_SIZE		65536

/* Coalescing */
#define QUIC_TCP_MAX_COALESCE		16  /* Max packets per TCP segment */
#define QUIC_TCP_COALESCE_TIMEOUT_US	1000  /* Coalesce timeout */

/* Connection states */
#define QUIC_TCP_STATE_CLOSED		0
#define QUIC_TCP_STATE_CONNECTING	1
#define QUIC_TCP_STATE_CONNECTED	2
#define QUIC_TCP_STATE_CLOSING		3
#define QUIC_TCP_STATE_HANDSHAKE	4  /* TCP connected, QUIC handshake */

/* MTU constants for TCP transport */
#define QUIC_TCP_MIN_MTU		1200  /* QUIC minimum */
#define QUIC_TCP_DEFAULT_MTU		1350  /* Conservative default */
#define QUIC_TCP_MAX_MTU		16384 /* Maximum over TCP */

/* Keepalive constants */
#define QUIC_TCP_KEEPALIVE_INTERVAL_MS	15000  /* 15 seconds */
#define QUIC_TCP_KEEPALIVE_TIMEOUT_MS	60000  /* 1 minute */

/* Flow control coordination */
#define QUIC_TCP_FC_HIGH_WATER		(QUIC_TCP_RX_BUF_SIZE * 3 / 4)
#define QUIC_TCP_FC_LOW_WATER		(QUIC_TCP_RX_BUF_SIZE / 4)

/* Congestion control mode */
#define QUIC_TCP_CC_DISABLED		0  /* Let TCP handle CC */
#define QUIC_TCP_CC_PASSTHROUGH		1  /* Pass TCP info to QUIC */
#define QUIC_TCP_CC_ADAPTIVE		2  /* Adaptive coordination */

/*
 * =============================================================================
 * Structures
 * =============================================================================
 */

/**
 * struct quic_tcp_frame - Framed QUIC packet for TCP
 * @length:  Packet length (network byte order)
 * @data:    QUIC packet data
 */
struct quic_tcp_frame {
	__be16 length;
	u8 data[];
} __packed;

/**
 * struct quic_tcp_rx_buffer - Receive buffer for TCP stream reassembly
 * @data:        Buffer data
 * @size:        Buffer size
 * @head:        Read position
 * @tail:        Write position
 * @lock:        Buffer lock
 */
struct quic_tcp_rx_buffer {
	u8 *data;
	size_t size;
	size_t head;
	size_t tail;
	spinlock_t lock;
};

/**
 * struct quic_tcp_tx_buffer - Transmit buffer for coalescing
 * @data:        Buffer data
 * @size:        Buffer size
 * @len:         Current data length
 * @packets:     Number of coalesced packets
 * @timestamp:   First packet timestamp
 * @lock:        Buffer lock
 */
struct quic_tcp_tx_buffer {
	u8 *data;
	size_t size;
	size_t len;
	int packets;
	ktime_t timestamp;
	spinlock_t lock;
};

/**
 * struct quic_tcp_stats - Per-connection statistics
 * @packets_rx:       QUIC packets received
 * @packets_tx:       QUIC packets transmitted
 * @bytes_rx:         Bytes received
 * @bytes_tx:         Bytes transmitted
 * @coalesce_count:   Coalesced transmissions
 * @tcp_segments_rx:  TCP segments received
 * @tcp_segments_tx:  TCP segments transmitted
 * @framing_errors:   Framing errors
 * @flow_control_pauses: Times paused for flow control
 * @keepalives_sent:  Keepalive packets sent
 * @keepalives_recv:  Keepalive packets received
 */
struct quic_tcp_stats {
	atomic64_t packets_rx;
	atomic64_t packets_tx;
	atomic64_t bytes_rx;
	atomic64_t bytes_tx;
	atomic64_t coalesce_count;
	atomic64_t tcp_segments_rx;
	atomic64_t tcp_segments_tx;
	atomic64_t framing_errors;
	atomic64_t flow_control_pauses;
	atomic64_t keepalives_sent;
	atomic64_t keepalives_recv;
};

/**
 * struct quic_tcp_flow_control - Flow control coordination state
 * @recv_window:      Current receive window advertised
 * @send_window:      Current send window available
 * @bytes_in_flight:  Bytes sent but not acknowledged
 * @recv_blocked:     Receive blocked (buffer full)
 * @send_blocked:     Send blocked (peer window)
 * @last_window_update: Time of last window update
 * @lock:             Flow control lock
 */
struct quic_tcp_flow_control {
	u64 recv_window;
	u64 send_window;
	u64 bytes_in_flight;
	bool recv_blocked;
	bool send_blocked;
	ktime_t last_window_update;
	spinlock_t lock;
};

/**
 * struct quic_tcp_cc_state - Congestion control coordination state
 * @mode:             CC coordination mode
 * @tcp_cwnd:         TCP's congestion window (from tcp_info)
 * @tcp_rtt:          TCP's RTT estimate (us)
 * @tcp_rtt_var:      TCP's RTT variance (us)
 * @last_update:      Time of last CC state update
 * @loss_events:      Number of loss events detected
 * @ecn_ce_count:     ECN CE marks received
 * @lock:             CC state lock
 */
struct quic_tcp_cc_state {
	int mode;
	u32 tcp_cwnd;
	u32 tcp_rtt;
	u32 tcp_rtt_var;
	ktime_t last_update;
	u32 loss_events;
	u64 ecn_ce_count;
	spinlock_t lock;
};

/**
 * struct quic_tcp_mtu_state - MTU discovery state
 * @current_mtu:      Currently used MTU
 * @max_mtu:          Maximum MTU for this connection
 * @min_mtu:          Minimum MTU (QUIC requirement)
 * @probe_size:       Current probe size
 * @probe_count:      Number of probes sent
 * @last_probe:       Time of last probe
 * @state:            MTU probe state machine
 */
struct quic_tcp_mtu_state {
	u32 current_mtu;
	u32 max_mtu;
	u32 min_mtu;
	u32 probe_size;
	u8 probe_count;
	ktime_t last_probe;
	int state;
};

/* MTU probe states */
#define QUIC_TCP_MTU_SEARCHING	0
#define QUIC_TCP_MTU_SEARCH_COMPLETE	1
#define QUIC_TCP_MTU_ERROR	2

/**
 * struct quic_tcp_keepalive - Keepalive coordination state
 * @tcp_enabled:      TCP keepalive enabled
 * @quic_enabled:     QUIC PING keepalive enabled
 * @interval_ms:      Keepalive interval in milliseconds
 * @timeout_ms:       Keepalive timeout in milliseconds
 * @last_activity:    Time of last activity
 * @last_keepalive:   Time of last keepalive sent
 * @pending_pong:     Awaiting PONG response
 * @timer:            Keepalive timer
 */
struct quic_tcp_keepalive {
	bool tcp_enabled;
	bool quic_enabled;
	u32 interval_ms;
	u32 timeout_ms;
	ktime_t last_activity;
	ktime_t last_keepalive;
	bool pending_pong;
	struct timer_list timer;
};

/**
 * struct quic_tcp_config - QUIC-over-TCP configuration
 * @coalesce_enabled:  Enable packet coalescing
 * @coalesce_timeout:  Coalesce timeout (microseconds)
 * @max_coalesce:      Maximum packets to coalesce
 * @tcp_nodelay:       Set TCP_NODELAY on socket
 * @tcp_cork:          Use TCP_CORK for batching
 * @cc_mode:           Congestion control coordination mode
 * @keepalive_interval: Keepalive interval (ms)
 * @mtu_discovery:     Enable MTU discovery
 */
struct quic_tcp_config {
	bool coalesce_enabled;
	u32 coalesce_timeout;
	u32 max_coalesce;
	bool tcp_nodelay;
	bool tcp_cork;
	int cc_mode;
	u32 keepalive_interval;
	bool mtu_discovery;
};

/**
 * struct quic_tcp_connection - QUIC-over-TCP connection state
 * @tcp_sk:           Underlying TCP socket
 * @quic_conn:        Associated QUIC connection
 * @state:            Connection state
 * @rx_buf:           Receive buffer
 * @tx_buf:           Transmit buffer
 * @stats:            Connection statistics
 * @flow_ctrl:        Flow control coordination
 * @cc_state:         Congestion control coordination
 * @mtu_state:        MTU discovery state
 * @keepalive:        Keepalive coordination
 * @config:           Connection configuration
 * @rx_work:          Receive work item
 * @tx_work:          Transmit work item
 * @close_work:       Close work item
 * @keepalive_work:   Keepalive work item
 * @lock:             Connection lock
 * @refcount:         Reference count
 * @list:             Connection list linkage
 * @packet_callback:  Callback when QUIC packet received
 * @callback_data:    User data for callback
 */
struct quic_tcp_connection {
	struct socket *tcp_sk;
	struct tquic_connection *quic_conn;
	int state;
	struct quic_tcp_rx_buffer rx_buf;
	struct quic_tcp_tx_buffer tx_buf;
	struct quic_tcp_stats stats;
	struct quic_tcp_flow_control flow_ctrl;
	struct quic_tcp_cc_state cc_state;
	struct quic_tcp_mtu_state mtu_state;
	struct quic_tcp_keepalive keepalive;
	struct quic_tcp_config config;
	struct work_struct rx_work;
	struct work_struct tx_work;
	struct work_struct close_work;
	struct work_struct keepalive_work;
	spinlock_t lock;
	atomic_t refcount;
	struct list_head list;

	/* Packet delivery callback */
	void (*packet_callback)(void *data, const u8 *packet, size_t len);
	void *callback_data;

	/* Saved TCP callbacks for restore */
	void (*saved_data_ready)(struct sock *sk);
	void (*saved_write_space)(struct sock *sk);
	void (*saved_state_change)(struct sock *sk);
};

/**
 * struct quic_tcp_listener - QUIC-over-TCP server listener
 * @tcp_sk:           Listening TCP socket
 * @accept_work:      Accept work item
 * @connections:      List of connections
 * @conn_lock:        Connection list lock
 * @port:             Listening port
 * @running:          Listener is running
 * @new_conn_callback: Callback for new connections
 * @callback_data:    User data for callback
 */
struct quic_tcp_listener {
	struct socket *tcp_sk;
	struct work_struct accept_work;
	struct list_head connections;
	spinlock_t conn_lock;
	u16 port;
	bool running;
	void (*new_conn_callback)(void *data, struct quic_tcp_connection *conn);
	void *callback_data;
};

/*
 * =============================================================================
 * Connection Management
 * =============================================================================
 */

/**
 * quic_tcp_connect - Create outgoing QUIC-over-TCP connection
 * @addr: Destination address
 * @addrlen: Address length
 * @quic_conn: QUIC connection to associate
 *
 * Returns: Connection on success, ERR_PTR on failure
 */
struct quic_tcp_connection *quic_tcp_connect(struct sockaddr *addr,
					     int addrlen,
					     struct tquic_connection *quic_conn);

/**
 * quic_tcp_close - Close QUIC-over-TCP connection
 * @conn: Connection to close
 */
void quic_tcp_close(struct quic_tcp_connection *conn);

/**
 * quic_tcp_send - Send QUIC packet over TCP
 * @conn: Connection
 * @data: QUIC packet data
 * @len: Packet length
 *
 * Returns: Bytes sent, negative errno on error
 */
int quic_tcp_send(struct quic_tcp_connection *conn,
		  const void *data, size_t len);

/**
 * quic_tcp_flush - Flush coalesced packets
 * @conn: Connection
 *
 * Returns: 0 on success, negative errno on error
 */
int quic_tcp_flush(struct quic_tcp_connection *conn);

/**
 * quic_tcp_recv - Receive QUIC packets from TCP
 * @conn: Connection
 * @buf: Receive buffer
 * @size: Buffer size
 *
 * Returns: Bytes received, negative errno on error
 */
int quic_tcp_recv(struct quic_tcp_connection *conn,
		  void *buf, size_t size);

/*
 * =============================================================================
 * Listener Management
 * =============================================================================
 */

/**
 * quic_tcp_listen - Start QUIC-over-TCP listener
 * @port: Port to listen on
 *
 * Returns: Listener on success, ERR_PTR on failure
 */
struct quic_tcp_listener *quic_tcp_listen(u16 port);

/**
 * quic_tcp_stop_listen - Stop QUIC-over-TCP listener
 * @listener: Listener to stop
 */
void quic_tcp_stop_listen(struct quic_tcp_listener *listener);

/**
 * quic_tcp_accept - Accept incoming connection
 * @listener: Listener
 *
 * Returns: Connection on success, NULL if none pending
 */
struct quic_tcp_connection *quic_tcp_accept(struct quic_tcp_listener *listener);

/*
 * =============================================================================
 * Configuration
 * =============================================================================
 */

/**
 * quic_tcp_set_config - Set configuration
 * @conn: Connection
 * @config: Configuration
 *
 * Returns: 0 on success, negative errno on error
 */
int quic_tcp_set_config(struct quic_tcp_connection *conn,
			struct quic_tcp_config *config);

/**
 * quic_tcp_get_config - Get current configuration
 * @conn: Connection
 * @config: Buffer for configuration
 *
 * Returns: 0 on success, negative errno on error
 */
int quic_tcp_get_config(struct quic_tcp_connection *conn,
			struct quic_tcp_config *config);

/*
 * =============================================================================
 * Flow Control Coordination
 * =============================================================================
 */

/**
 * quic_tcp_update_recv_window - Update receive window based on buffer state
 * @conn: Connection
 *
 * Called when receive buffer state changes to coordinate with QUIC flow control.
 */
void quic_tcp_update_recv_window(struct quic_tcp_connection *conn);

/**
 * quic_tcp_get_send_credit - Get available send credit
 * @conn: Connection
 *
 * Returns: Bytes available to send considering both TCP and QUIC flow control
 */
u64 quic_tcp_get_send_credit(struct quic_tcp_connection *conn);

/**
 * quic_tcp_set_flow_control_callback - Set flow control notification callback
 * @conn: Connection
 * @callback: Function called when flow control state changes
 * @data: User data for callback
 */
void quic_tcp_set_flow_control_callback(struct quic_tcp_connection *conn,
					void (*callback)(void *data, bool blocked),
					void *data);

/*
 * =============================================================================
 * Congestion Control Coordination
 * =============================================================================
 */

/**
 * quic_tcp_get_cc_info - Get TCP congestion control information
 * @conn: Connection
 * @cwnd: Output - congestion window (bytes)
 * @rtt: Output - RTT estimate (us)
 * @rtt_var: Output - RTT variance (us)
 *
 * Returns: 0 on success, negative errno on error
 */
int quic_tcp_get_cc_info(struct quic_tcp_connection *conn,
			 u32 *cwnd, u32 *rtt, u32 *rtt_var);

/**
 * quic_tcp_set_cc_mode - Set congestion control coordination mode
 * @conn: Connection
 * @mode: CC mode (QUIC_TCP_CC_DISABLED, PASSTHROUGH, or ADAPTIVE)
 *
 * Returns: 0 on success, negative errno on error
 */
int quic_tcp_set_cc_mode(struct quic_tcp_connection *conn, int mode);

/**
 * quic_tcp_on_loss_event - Notify of application-layer loss detection
 * @conn: Connection
 *
 * Called when QUIC detects packet loss. In passthrough mode, this may
 * influence TCP behavior.
 */
void quic_tcp_on_loss_event(struct quic_tcp_connection *conn);

/*
 * =============================================================================
 * MTU Handling
 * =============================================================================
 */

/**
 * quic_tcp_get_mtu - Get current MTU for the connection
 * @conn: Connection
 *
 * Returns: Current MTU in bytes
 */
u32 quic_tcp_get_mtu(struct quic_tcp_connection *conn);

/**
 * quic_tcp_probe_mtu - Initiate MTU probe
 * @conn: Connection
 * @size: Size to probe
 *
 * Returns: 0 on success, negative errno on error
 */
int quic_tcp_probe_mtu(struct quic_tcp_connection *conn, u32 size);

/**
 * quic_tcp_set_mtu - Set MTU for the connection
 * @conn: Connection
 * @mtu: New MTU value
 *
 * Returns: 0 on success, negative errno on error
 */
int quic_tcp_set_mtu(struct quic_tcp_connection *conn, u32 mtu);

/*
 * =============================================================================
 * Keepalive Coordination
 * =============================================================================
 */

/**
 * quic_tcp_set_keepalive - Configure keepalive settings
 * @conn: Connection
 * @enable: Enable keepalive
 * @interval_ms: Keepalive interval in milliseconds
 * @timeout_ms: Keepalive timeout in milliseconds
 *
 * Returns: 0 on success, negative errno on error
 */
int quic_tcp_set_keepalive(struct quic_tcp_connection *conn,
			   bool enable, u32 interval_ms, u32 timeout_ms);

/**
 * quic_tcp_activity - Mark activity on connection
 * @conn: Connection
 *
 * Called when data is sent or received to reset keepalive timer.
 */
void quic_tcp_activity(struct quic_tcp_connection *conn);

/**
 * quic_tcp_send_ping - Send QUIC PING for keepalive
 * @conn: Connection
 *
 * Returns: 0 on success, negative errno on error
 */
int quic_tcp_send_ping(struct quic_tcp_connection *conn);

/*
 * =============================================================================
 * Packet Delivery Callbacks
 * =============================================================================
 */

/**
 * quic_tcp_set_packet_callback - Set callback for received QUIC packets
 * @conn: Connection
 * @callback: Function called when QUIC packet received
 * @data: User data for callback
 */
void quic_tcp_set_packet_callback(struct quic_tcp_connection *conn,
				  void (*callback)(void *data, const u8 *packet, size_t len),
				  void *data);

/**
 * quic_tcp_set_listener_callback - Set callback for new connections
 * @listener: Listener
 * @callback: Function called when new connection accepted
 * @data: User data for callback
 */
void quic_tcp_set_listener_callback(struct quic_tcp_listener *listener,
				    void (*callback)(void *data, struct quic_tcp_connection *conn),
				    void *data);

/*
 * =============================================================================
 * Statistics
 * =============================================================================
 */

/**
 * quic_tcp_get_stats - Get connection statistics
 * @conn: Connection
 * @stats: Buffer for statistics
 */
void quic_tcp_get_stats(struct quic_tcp_connection *conn,
			struct quic_tcp_stats *stats);

/*
 * =============================================================================
 * Reference Counting
 * =============================================================================
 */

/**
 * quic_tcp_conn_get - Increment connection reference count
 * @conn: Connection
 */
static inline void quic_tcp_conn_get(struct quic_tcp_connection *conn)
{
	if (conn)
		atomic_inc(&conn->refcount);
}

/**
 * quic_tcp_conn_put - Decrement connection reference count
 * @conn: Connection
 *
 * Connection is freed when reference count reaches zero.
 */
void quic_tcp_conn_put(struct quic_tcp_connection *conn);

/*
 * =============================================================================
 * Module Init/Exit
 * =============================================================================
 */

int tquic_over_tcp_init(void);
void tquic_over_tcp_exit(void);

/*
 * =============================================================================
 * Integration with QUIC Stack
 * =============================================================================
 */

/**
 * quic_tcp_attach_to_path - Attach TCP connection to QUIC path
 * @conn: TCP connection
 * @path: QUIC path
 *
 * Used when fallback from UDP to TCP occurs.
 *
 * Returns: 0 on success, negative errno on error
 */
int quic_tcp_attach_to_path(struct quic_tcp_connection *conn,
			    struct tquic_path *path);

/**
 * quic_tcp_detach_from_path - Detach TCP connection from QUIC path
 * @conn: TCP connection
 *
 * Returns: 0 on success, negative errno on error
 */
int quic_tcp_detach_from_path(struct quic_tcp_connection *conn);

#endif /* _TQUIC_OVER_TCP_H */
