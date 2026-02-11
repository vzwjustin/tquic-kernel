/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * TQUIC: Tunnel and Client Structure Definitions
 *
 * Copyright (c) 2026 Linux Foundation
 * Kernel implementation by Justin Adams <spotty118@gmail.com>
 *
 * Shared header for tunnel management structures used by both
 * tquic_tunnel.c and tquic_forward.c.
 */

#ifndef _TQUIC_TUNNEL_H
#define _TQUIC_TUNNEL_H

#include <linux/types.h>
#include <linux/list.h>
#include <linux/spinlock.h>
#include <linux/workqueue.h>
#include <linux/refcount.h>
#include <linux/socket.h>
#include <net/tquic.h>

/*
 * =============================================================================
 * Tunnel State Machine
 * =============================================================================
 */

enum tquic_tunnel_state {
	TQUIC_TUNNEL_IDLE = 0,
	TQUIC_TUNNEL_CONNECTING,
	TQUIC_TUNNEL_ESTABLISHED,
	TQUIC_TUNNEL_CLOSING,
	TQUIC_TUNNEL_CLOSED,
};

/*
 * =============================================================================
 * Per-Tunnel Statistics
 * =============================================================================
 */

/**
 * struct tquic_tunnel_stats - Per-tunnel statistics
 * @bytes_tx: Total bytes transmitted to internet
 * @bytes_rx: Total bytes received from internet
 * @packets_tx: Packets transmitted
 * @packets_rx: Packets received
 */
struct tquic_tunnel_stats {
	u64 bytes_tx;
	u64 bytes_rx;
	u64 packets_tx;
	u64 packets_rx;
};

/*
 * =============================================================================
 * Tunnel Structure
 * =============================================================================
 */

/* Forward declarations */
struct tquic_client;
struct tquic_stream;

/**
 * struct tquic_tunnel - TCP-over-QUIC tunnel state
 * @quic_stream: QUIC stream carrying the tunnel
 * @tcp_sock: Kernel TCP socket to destination
 * @dest_addr: Destination address (IPv4 or IPv6)
 * @dest_port: Destination port
 * @local_port: Allocated local port from client's range
 * @state: Current tunnel state
 * @client: Parent tquic_client for port range lookup
 * @stats: Per-tunnel statistics
 * @traffic_class: Assigned QoS class (0-3)
 * @is_tproxy: True if TPROXY mode enabled
 * @connect_work: Async connect workqueue item
 * @forward_work: Data forwarding workqueue item
 * @lock: Tunnel state lock
 * @list: Client's tunnel list linkage
 * @refcnt: Reference counter
 */
struct tquic_tunnel {
	struct tquic_stream *quic_stream;
	struct socket *tcp_sock;

	struct sockaddr_storage dest_addr;
	__be16 dest_port;
	__be16 local_port;

	enum tquic_tunnel_state state;
	struct tquic_client *client;

	struct tquic_tunnel_stats stats;
	u8 traffic_class;
	bool is_tproxy;

	struct work_struct connect_work;
	struct work_struct forward_work;

	spinlock_t lock;
	struct list_head list;
	refcount_t refcnt;
};

/*
 * =============================================================================
 * Client Structure
 * =============================================================================
 */

/* Port allocation bitmap - 1000 ports per client */
#define TQUIC_PORTS_PER_CLIENT	1000
#define TQUIC_PORT_BITMAP_SIZE	BITS_TO_LONGS(TQUIC_PORTS_PER_CLIENT)

/**
 * struct tquic_client - Per-client VPS state
 * @psk_identity: PSK identity for authentication
 * @port_range_start: Start of allocated port range
 * @port_range_end: End of allocated port range
 * @port_bitmap: Bitmap of allocated ports
 * @tunnels: List of active tunnels
 * @tunnels_lock: Protects tunnels list
 * @conn: Associated TQUIC connection
 * @bandwidth_limit: Configured bandwidth limit (bytes/s)
 * @list: Global client list linkage
 */
struct tquic_client {
	char psk_identity[64];
	__be16 port_range_start;
	__be16 port_range_end;
	unsigned long port_bitmap[TQUIC_PORT_BITMAP_SIZE];

	struct list_head tunnels;
	spinlock_t tunnels_lock;
	struct tquic_connection *conn;

	u64 bandwidth_limit;
	struct list_head list;
};

/*
 * Note: Function declarations are in include/net/tquic.h
 * This header only defines the structures needed by multiple .c files
 */

#endif /* _TQUIC_TUNNEL_H */
