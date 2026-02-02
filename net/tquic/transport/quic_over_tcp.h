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
 * - TCP handles reliability, so QUIC loss recovery is disabled
 */

#ifndef _TQUIC_OVER_TCP_H
#define _TQUIC_OVER_TCP_H

#include <linux/types.h>
#include <linux/net.h>
#include <linux/socket.h>
#include <linux/skbuff.h>
#include <linux/workqueue.h>
#include <net/sock.h>

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
};

/**
 * struct quic_tcp_connection - QUIC-over-TCP connection state
 * @tcp_sk:           Underlying TCP socket
 * @quic_conn:        Associated QUIC connection
 * @state:            Connection state
 * @rx_buf:           Receive buffer
 * @tx_buf:           Transmit buffer
 * @stats:            Connection statistics
 * @rx_work:          Receive work item
 * @tx_work:          Transmit work item
 * @close_work:       Close work item
 * @lock:             Connection lock
 * @refcount:         Reference count
 * @list:             Connection list linkage
 */
struct quic_tcp_connection {
	struct socket *tcp_sk;
	struct tquic_connection *quic_conn;
	int state;
	struct quic_tcp_rx_buffer rx_buf;
	struct quic_tcp_tx_buffer tx_buf;
	struct quic_tcp_stats stats;
	struct work_struct rx_work;
	struct work_struct tx_work;
	struct work_struct close_work;
	spinlock_t lock;
	atomic_t refcount;
	struct list_head list;
};

/**
 * struct quic_tcp_listener - QUIC-over-TCP server listener
 * @tcp_sk:           Listening TCP socket
 * @accept_work:      Accept work item
 * @connections:      List of connections
 * @conn_lock:        Connection list lock
 * @port:             Listening port
 * @running:          Listener is running
 */
struct quic_tcp_listener {
	struct socket *tcp_sk;
	struct work_struct accept_work;
	struct list_head connections;
	spinlock_t conn_lock;
	u16 port;
	bool running;
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
 * struct quic_tcp_config - QUIC-over-TCP configuration
 * @coalesce_enabled:  Enable packet coalescing
 * @coalesce_timeout:  Coalesce timeout (microseconds)
 * @max_coalesce:      Maximum packets to coalesce
 * @tcp_nodelay:       Set TCP_NODELAY on socket
 * @tcp_cork:          Use TCP_CORK for batching
 */
struct quic_tcp_config {
	bool coalesce_enabled;
	u32 coalesce_timeout;
	u32 max_coalesce;
	bool tcp_nodelay;
	bool tcp_cork;
};

/**
 * quic_tcp_set_config - Set configuration
 * @conn: Connection
 * @config: Configuration
 *
 * Returns: 0 on success, negative errno on error
 */
int quic_tcp_set_config(struct quic_tcp_connection *conn,
			struct quic_tcp_config *config);

/*
 * =============================================================================
 * Module Init/Exit
 * =============================================================================
 */

int tquic_over_tcp_init(void);
void tquic_over_tcp_exit(void);

#endif /* _TQUIC_OVER_TCP_H */
