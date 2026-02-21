/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * TQUIC MASQUE CONNECT-IP Header
 *
 * Copyright (c) 2026 Justin Adams <spotty118@gmail.com>
 * Kernel implementation by Justin Adams <spotty118@gmail.com>
 *
 * API definitions for CONNECT-IP (RFC 9484) implementation.
 * CONNECT-IP provides IP proxying over HTTP, enabling IP tunnel
 * establishment through QUIC connections.
 */

#ifndef _TQUIC_MASQUE_CONNECT_IP_H
#define _TQUIC_MASQUE_CONNECT_IP_H

#include <linux/types.h>
#include <linux/list.h>
#include <linux/spinlock.h>
#include <linux/refcount.h>
#include <linux/in6.h>
#include <net/tquic.h>

/*
 * =============================================================================
 * CAPSULE TYPE DEFINITIONS (RFC 9484 Section 4)
 * =============================================================================
 */

/* CONNECT-IP capsule types */
#define TQUIC_CAPSULE_ADDRESS_ASSIGN		0x01
#define TQUIC_CAPSULE_ADDRESS_REQUEST		0x02
#define TQUIC_CAPSULE_ROUTE_ADVERTISEMENT	0x03

/* HTTP Datagram context ID for IP packets */
#define TQUIC_CONNECT_IP_CONTEXT_ID		0

/* MTU requirements */
#define TQUIC_CONNECT_IP_MIN_MTU_IPV4		68	/* RFC 791 */
#define TQUIC_CONNECT_IP_MIN_MTU_IPV6		1280	/* RFC 8200 */

/* Address and route limits */
#define TQUIC_CONNECT_IP_MAX_ADDRESSES		16
#define TQUIC_CONNECT_IP_MAX_ROUTES		64

/*
 * =============================================================================
 * DATA STRUCTURES
 * =============================================================================
 */

/* Forward declaration */
struct tquic_connect_ip_tunnel;

/**
 * struct tquic_ip_address - IP address entry for CONNECT-IP
 * @version: IP version (4 or 6)
 * @addr: IP address union
 * @prefix_len: Prefix length (CIDR notation)
 * @request_id: Request ID associated with this address
 * @list: List linkage
 *
 * Represents an IP address assigned via ADDRESS_ASSIGN or
 * requested via ADDRESS_REQUEST capsules.
 */
struct tquic_ip_address {
	u8 version;			/* 4 or 6 */
	union {
		__be32 v4;
		struct in6_addr v6;
	} addr;
	u8 prefix_len;
	u64 request_id;
	struct list_head list;
};

/**
 * struct tquic_address_assign - ADDRESS_ASSIGN capsule structure
 * @request_id: Request ID (echoed from ADDRESS_REQUEST or server-generated)
 * @ip_version: IP version (4 or 6)
 * @addr: IP address bytes (4 for IPv4, 16 for IPv6)
 * @prefix_len: Prefix length
 *
 * Wire format per RFC 9484 Section 4.1.
 */
struct tquic_address_assign {
	u64 request_id;
	u8 ip_version;
	u8 addr[16];
	u8 prefix_len;
};

/**
 * struct tquic_address_request - ADDRESS_REQUEST capsule structure
 * @request_id: Request ID for correlation
 * @ip_version: Requested IP version (4 or 6)
 * @prefix_len: Requested prefix length (0 = any)
 *
 * Wire format per RFC 9484 Section 4.2.
 */
struct tquic_address_request {
	u64 request_id;
	u8 ip_version;
	u8 prefix_len;
};

/**
 * struct tquic_route_adv - ROUTE_ADVERTISEMENT capsule entry
 * @ip_version: IP version (4 or 6)
 * @start_addr: Start of address range
 * @end_addr: End of address range
 * @ipproto: IP protocol (0 = any, 1-255 = specific)
 *
 * Wire format per RFC 9484 Section 4.3.
 */
struct tquic_route_adv {
	u8 ip_version;
	u8 start_addr[16];
	u8 end_addr[16];
	u8 ipproto;
};

/**
 * struct tquic_connect_ip_tunnel - CONNECT-IP tunnel state
 * @stream: HTTP/3 CONNECT stream for this tunnel
 * @local_addrs: List of locally assigned IP addresses
 * @remote_addrs: List of remote (peer) IP addresses
 * @num_local_addrs: Count of local addresses
 * @num_remote_addrs: Count of remote addresses
 * @routes: List of advertised routes
 * @num_routes: Count of routes
 * @ipproto: IP protocol filter (0 = any, 1-255 = specific)
 * @raw_sock: Raw socket for IP packet injection (optional)
 * @next_request_id: Next request ID for address requests
 * @mtu: Current tunnel MTU
 * @lock: Protects tunnel state
 * @refcnt: Reference counter
 *
 * Main structure for managing a CONNECT-IP tunnel.
 */
struct tquic_connect_ip_tunnel {
	struct tquic_stream *stream;

	/* Assigned addresses */
	struct list_head local_addrs;
	struct list_head remote_addrs;
	u8 num_local_addrs;
	u8 num_remote_addrs;

	/* Routes */
	struct list_head routes;
	u16 num_routes;

	/* IP protocol filter (0 = any, 1-255 = specific) */
	u8 ipproto;

	/* Raw socket for IP packet injection */
	struct socket *raw_sock;

	/* Request ID counter */
	u64 next_request_id;

	/* MTU (minimum 1280 for IPv6) */
	u32 mtu;

	spinlock_t lock;
	refcount_t refcnt;
};

/*
 * =============================================================================
 * TUNNEL LIFECYCLE API
 * =============================================================================
 */

/**
 * tquic_connect_ip_tunnel_alloc - Allocate a new CONNECT-IP tunnel
 * @stream: HTTP/3 CONNECT stream to associate with tunnel
 *
 * Creates a new CONNECT-IP tunnel bound to the given stream.
 * The tunnel must be freed with tquic_connect_ip_tunnel_put().
 *
 * Returns: Allocated tunnel on success, NULL on failure.
 */
struct tquic_connect_ip_tunnel *tquic_connect_ip_tunnel_alloc(
	struct tquic_stream *stream);

/**
 * tquic_connect_ip_tunnel_get - Increment tunnel reference count
 * @tunnel: Tunnel to reference
 */
void tquic_connect_ip_tunnel_get(struct tquic_connect_ip_tunnel *tunnel);

/**
 * tquic_connect_ip_tunnel_put - Decrement tunnel reference count
 * @tunnel: Tunnel to dereference
 *
 * Frees the tunnel when reference count reaches zero.
 */
void tquic_connect_ip_tunnel_put(struct tquic_connect_ip_tunnel *tunnel);

/*
 * =============================================================================
 * CAPSULE SEND API
 * =============================================================================
 */

/**
 * tquic_connect_ip_send_address_assign - Send ADDRESS_ASSIGN capsule
 * @tunnel: CONNECT-IP tunnel
 * @addr: Address to assign
 *
 * Server sends this capsule to assign IP address(es) to the client.
 * The address is also added to the tunnel's local_addrs list.
 *
 * Returns: 0 on success, negative errno on failure.
 */
int tquic_connect_ip_send_address_assign(
	struct tquic_connect_ip_tunnel *tunnel,
	const struct tquic_ip_address *addr);

/**
 * tquic_connect_ip_request_address - Send ADDRESS_REQUEST capsule
 * @tunnel: CONNECT-IP tunnel
 * @version: IP version to request (4 or 6)
 * @prefix_len: Requested prefix length (0 = any)
 *
 * Client sends this capsule to request IP address assignment
 * from the server. A request ID is automatically generated.
 *
 * Returns: Request ID on success (positive), negative errno on failure.
 */
int tquic_connect_ip_request_address(
	struct tquic_connect_ip_tunnel *tunnel,
	u8 version, u8 prefix_len);

/**
 * tquic_connect_ip_advertise_routes - Send ROUTE_ADVERTISEMENT capsule
 * @tunnel: CONNECT-IP tunnel
 * @routes: Array of routes to advertise
 * @count: Number of routes
 *
 * Server sends this capsule to advertise reachable IP routes.
 * Routes are also added to the tunnel's routes list.
 *
 * Returns: 0 on success, negative errno on failure.
 */
int tquic_connect_ip_advertise_routes(
	struct tquic_connect_ip_tunnel *tunnel,
	const struct tquic_route_adv *routes,
	size_t count);

/*
 * =============================================================================
 * IP PACKET FORWARDING API
 * =============================================================================
 */

/**
 * tquic_connect_ip_send - Forward IP packet through tunnel
 * @tunnel: CONNECT-IP tunnel
 * @skb: Socket buffer containing IP packet
 *
 * Encapsulates the IP packet in an HTTP Datagram with context ID 0
 * and sends it through the tunnel. The packet must be a valid IPv4
 * or IPv6 packet.
 *
 * The packet is validated against:
 *   - IP header validity
 *   - MTU constraints (minimum 1280 for IPv6)
 *   - Protocol filter (if set)
 *
 * Returns: 0 on success, negative errno on failure.
 *   -EMSGSIZE: Packet exceeds MTU
 *   -EPROTONOSUPPORT: Protocol not allowed by filter
 *   -EOPNOTSUPP: Datagrams not enabled on connection
 */
int tquic_connect_ip_send(struct tquic_connect_ip_tunnel *tunnel,
			  struct sk_buff *skb);

/**
 * tquic_connect_ip_recv - Receive IP packet from tunnel
 * @tunnel: CONNECT-IP tunnel
 * @skb: Output socket buffer pointer
 *
 * Receives an HTTP Datagram with context ID 0 and extracts the
 * IP packet. The caller is responsible for freeing the returned skb.
 *
 * Returns: 0 on success, -EAGAIN if no packet available,
 *          negative errno on error.
 */
int tquic_connect_ip_recv(struct tquic_connect_ip_tunnel *tunnel,
			  struct sk_buff **skb);

/*
 * =============================================================================
 * CAPSULE PROCESSING API
 * =============================================================================
 */

/**
 * tquic_connect_ip_process_capsule - Process received capsule
 * @tunnel: CONNECT-IP tunnel
 * @buf: Capsule data
 * @len: Capsule length
 *
 * Parses and processes incoming capsules (ADDRESS_ASSIGN,
 * ADDRESS_REQUEST, ROUTE_ADVERTISEMENT). Updates tunnel state
 * based on capsule contents.
 *
 * Returns: Bytes consumed on success, negative errno on failure.
 *          -EAGAIN if more data needed.
 */
int tquic_connect_ip_process_capsule(
	struct tquic_connect_ip_tunnel *tunnel,
	const u8 *buf, size_t len);

/*
 * =============================================================================
 * CONFIGURATION API
 * =============================================================================
 */

/**
 * tquic_connect_ip_set_mtu - Set tunnel MTU
 * @tunnel: CONNECT-IP tunnel
 * @mtu: New MTU value
 *
 * Sets the tunnel MTU. Enforces minimum MTU of 1280 for IPv6 support
 * per RFC 8200.
 *
 * Returns: 0 on success, negative errno on failure.
 */
int tquic_connect_ip_set_mtu(struct tquic_connect_ip_tunnel *tunnel, u32 mtu);

/**
 * tquic_connect_ip_get_mtu - Get tunnel MTU
 * @tunnel: CONNECT-IP tunnel
 *
 * Returns: Current tunnel MTU (minimum 1280).
 */
u32 tquic_connect_ip_get_mtu(struct tquic_connect_ip_tunnel *tunnel);

/**
 * tquic_connect_ip_set_protocol_filter - Set IP protocol filter
 * @tunnel: CONNECT-IP tunnel
 * @ipproto: IP protocol (0 = any, 1-255 = specific protocol)
 *
 * When set to a non-zero value, only packets matching the specified
 * IP protocol number are allowed through the tunnel. Common values:
 *   1 = ICMP, 6 = TCP, 17 = UDP, 58 = ICMPv6
 *
 * Returns: 0 on success, negative errno on failure.
 */
int tquic_connect_ip_set_protocol_filter(
	struct tquic_connect_ip_tunnel *tunnel,
	u8 ipproto);

/*
 * =============================================================================
 * KERNEL ROUTING TABLE INTEGRATION
 * =============================================================================
 *
 * CONNECT-IP tunnels can be integrated with the kernel routing table to
 * enable transparent IP forwarding. This section provides the API for
 * creating virtual network interfaces and installing routes.
 */

/* Virtual interface name prefix */
#define TQUIC_CONNECT_IP_IFNAME_PREFIX	"tquic"

/* Maximum virtual interfaces per tunnel */
#define TQUIC_CONNECT_IP_MAX_IFACES	4

/**
 * struct tquic_connect_ip_route_entry - Route table entry
 * @dst_addr: Destination address
 * @dst_prefix_len: Destination prefix length
 * @gateway: Gateway address (optional)
 * @priority: Route priority/metric
 * @table_id: Routing table ID (RT_TABLE_MAIN if 0)
 * @list: List linkage
 */
struct tquic_connect_ip_route_entry {
	union {
		__be32 v4;
		struct in6_addr v6;
	} dst_addr;
	u8 dst_prefix_len;
	union {
		__be32 v4;
		struct in6_addr v6;
	} gateway;
	u32 priority;
	u32 table_id;
	u8 ip_version;
	struct list_head list;
};

/**
 * struct tquic_connect_ip_iface - Virtual network interface
 * @net_device: Network device
 * @tunnel: Associated tunnel
 * @routes: List of installed routes
 * @num_routes: Number of installed routes
 * @stats: Interface statistics
 * @list: List linkage
 */
struct tquic_connect_ip_iface {
	struct net_device *net_device;
	struct tquic_connect_ip_tunnel *tunnel;
	struct list_head routes;
	u32 num_routes;
	struct net_device_stats stats;
	struct list_head list;
};

/**
 * tquic_connect_ip_create_iface - Create virtual network interface
 * @tunnel: CONNECT-IP tunnel
 * @name: Interface name (or NULL for auto-generated)
 * @iface: Output for created interface
 *
 * Creates a virtual network interface bound to the tunnel. Packets
 * transmitted on the interface are forwarded through the tunnel.
 *
 * Returns: 0 on success, negative errno on failure.
 */
int tquic_connect_ip_create_iface(struct tquic_connect_ip_tunnel *tunnel,
				  const char *name,
				  struct tquic_connect_ip_iface **iface);

/**
 * tquic_connect_ip_destroy_iface - Destroy virtual network interface
 * @iface: Interface to destroy
 *
 * Removes the interface and all associated routes.
 */
void tquic_connect_ip_destroy_iface(struct tquic_connect_ip_iface *iface);

/**
 * tquic_connect_ip_add_route - Add route to kernel routing table
 * @iface: Virtual interface
 * @entry: Route entry to add
 *
 * Installs a route in the kernel routing table pointing to the
 * virtual interface. The route will forward matching packets
 * through the CONNECT-IP tunnel.
 *
 * Returns: 0 on success, negative errno on failure.
 */
int tquic_connect_ip_add_route(struct tquic_connect_ip_iface *iface,
			       const struct tquic_connect_ip_route_entry *entry);

/**
 * tquic_connect_ip_del_route - Remove route from kernel routing table
 * @iface: Virtual interface
 * @entry: Route entry to remove
 *
 * Returns: 0 on success, negative errno on failure.
 */
int tquic_connect_ip_del_route(struct tquic_connect_ip_iface *iface,
			       const struct tquic_connect_ip_route_entry *entry);

/**
 * tquic_connect_ip_flush_routes - Remove all routes for interface
 * @iface: Virtual interface
 *
 * Returns: 0 on success, negative errno on failure.
 */
int tquic_connect_ip_flush_routes(struct tquic_connect_ip_iface *iface);

/**
 * tquic_connect_ip_set_iface_addr - Set interface IP address
 * @iface: Virtual interface
 * @addr: IP address
 * @prefix_len: Prefix length
 *
 * Configures the IP address on the virtual interface.
 *
 * Returns: 0 on success, negative errno on failure.
 */
int tquic_connect_ip_set_iface_addr(struct tquic_connect_ip_iface *iface,
				    const struct tquic_ip_address *addr);

/**
 * tquic_connect_ip_set_iface_mtu - Set interface MTU
 * @iface: Virtual interface
 * @mtu: MTU value
 *
 * Returns: 0 on success, negative errno on failure.
 */
int tquic_connect_ip_set_iface_mtu(struct tquic_connect_ip_iface *iface,
				   u32 mtu);

/*
 * =============================================================================
 * IP FORWARDING CONTROL
 * =============================================================================
 */

/**
 * tquic_connect_ip_enable_forwarding - Enable IP forwarding on tunnel
 * @tunnel: CONNECT-IP tunnel
 * @enable: true to enable, false to disable
 *
 * When enabled, received IP packets are injected into the kernel
 * network stack for forwarding. When disabled, packets are only
 * passed to registered handlers.
 *
 * Returns: 0 on success, negative errno on failure.
 */
int tquic_connect_ip_enable_forwarding(struct tquic_connect_ip_tunnel *tunnel,
				       bool enable);

/**
 * tquic_connect_ip_inject_packet - Inject received packet into kernel
 * @tunnel: CONNECT-IP tunnel
 * @skb: Socket buffer containing IP packet
 *
 * Injects the received IP packet into the kernel network stack
 * as if it was received on the virtual interface.
 *
 * Returns: 0 on success, negative errno on failure.
 */
int tquic_connect_ip_inject_packet(struct tquic_connect_ip_tunnel *tunnel,
				   struct sk_buff *skb);

/*
 * =============================================================================
 * TUNNEL STATISTICS
 * =============================================================================
 */

/**
 * struct tquic_connect_ip_stats - CONNECT-IP tunnel statistics
 * @tx_packets: Packets transmitted
 * @rx_packets: Packets received
 * @tx_bytes: Bytes transmitted
 * @rx_bytes: Bytes received
 * @tx_errors: Transmission errors
 * @rx_errors: Reception errors
 * @tx_dropped: Packets dropped on transmit
 * @rx_dropped: Packets dropped on receive
 * @addr_assign_sent: ADDRESS_ASSIGN capsules sent
 * @addr_assign_recv: ADDRESS_ASSIGN capsules received
 * @addr_request_sent: ADDRESS_REQUEST capsules sent
 * @addr_request_recv: ADDRESS_REQUEST capsules received
 * @route_adv_sent: ROUTE_ADVERTISEMENT capsules sent
 * @route_adv_recv: ROUTE_ADVERTISEMENT capsules received
 */
struct tquic_connect_ip_stats {
	u64 tx_packets;
	u64 rx_packets;
	u64 tx_bytes;
	u64 rx_bytes;
	u64 tx_errors;
	u64 rx_errors;
	u64 tx_dropped;
	u64 rx_dropped;
	u64 addr_assign_sent;
	u64 addr_assign_recv;
	u64 addr_request_sent;
	u64 addr_request_recv;
	u64 route_adv_sent;
	u64 route_adv_recv;
};

/**
 * tquic_connect_ip_get_stats - Get tunnel statistics
 * @tunnel: CONNECT-IP tunnel
 * @stats: Output for statistics
 *
 * Returns: 0 on success, negative errno on failure.
 */
int tquic_connect_ip_get_stats(struct tquic_connect_ip_tunnel *tunnel,
			       struct tquic_connect_ip_stats *stats);

/*
 * =============================================================================
 * MODULE INITIALIZATION
 * =============================================================================
 */

int __init tquic_connect_ip_init(void);
void __exit tquic_connect_ip_exit(void);

#endif /* _TQUIC_MASQUE_CONNECT_IP_H */
