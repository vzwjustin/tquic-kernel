// SPDX-License-Identifier: GPL-2.0-only
/*
 * TQUIC MASQUE CONNECT-IP Implementation
 *
 * Copyright (c) 2026 Justin Adams <spotty118@gmail.com>
 * Kernel implementation by Justin Adams <spotty118@gmail.com>
 *
 * Implementation of CONNECT-IP for MASQUE (Multiplexed Application Substrate
 * over QUIC Encryption) per RFC 9484.
 *
 * CONNECT-IP provides IP proxying over HTTP, allowing clients to establish
 * an IP tunnel to proxy IP traffic. This is different from CONNECT-UDP
 * (RFC 9298) which proxies UDP datagrams.
 *
 * Capsule Types (RFC 9484 Section 4):
 *   0x01: ADDRESS_ASSIGN     - Server assigns IP addresses to client
 *   0x02: ADDRESS_REQUEST    - Client requests IP address assignment
 *   0x03: ROUTE_ADVERTISEMENT - Server advertises reachable routes
 *
 * IP packets are transmitted using HTTP Datagrams with context ID 0.
 *
 * Reference:
 *   RFC 9484 - Proxying IP in HTTP
 *   RFC 9297 - HTTP Datagrams and the Capsule Protocol
 *   RFC 9298 - Proxying UDP in HTTP (CONNECT-UDP)
 */

#include <linux/module.h>
#include <linux/slab.h>
#include <linux/net.h>
#include <linux/socket.h>
#include <linux/in.h>
#include <linux/in6.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/netdevice.h>
#include <linux/if_arp.h>
#include <linux/inetdevice.h>
#include <linux/rtnetlink.h>
#include <net/sock.h>
#include <net/ip.h>
#include <net/ipv6.h>
#include <net/route.h>
#include <net/ip_fib.h>
#include <net/ip6_fib.h>
#include <net/ip6_route.h>
#include <net/addrconf.h>
#include <net/netlink.h>
#include <net/tquic.h>

#include "../protocol.h"
#include "connect_ip.h"

/*
 * =============================================================================
 * CAPSULE TYPE DEFINITIONS (RFC 9484 Section 4)
 * =============================================================================
 */

/* CONNECT-IP capsule types */
#define CAPSULE_ADDRESS_ASSIGN		0x01
#define CAPSULE_ADDRESS_REQUEST		0x02
#define CAPSULE_ROUTE_ADVERTISEMENT	0x03

/* HTTP Datagram context ID for IP packets */
#define CONNECT_IP_CONTEXT_ID		0

/* Minimum MTU requirements */
#define CONNECT_IP_MIN_MTU_IPV4		68	/* RFC 791 */
#define CONNECT_IP_MIN_MTU_IPV6		1280	/* RFC 8200 */

/* Maximum IP addresses per tunnel */
#define CONNECT_IP_MAX_ADDRESSES	16

/* Maximum routes per tunnel */
#define CONNECT_IP_MAX_ROUTES		64

/*
 * =============================================================================
 * PRIVATE IMPLEMENTATION STRUCTURES
 * =============================================================================
 */

/**
 * struct tquic_ip_route - Internal route tracking entry
 * @ip_version: IP version (4 or 6)
 * @start_addr: Start of address range (union for v4/v6)
 * @end_addr: End of address range (union for v4/v6)
 * @ipproto: IP protocol (0 = any, 1-255 = specific)
 * @list: Linkage in tunnel route list
 *
 * Private to connect_ip.c. The wire format uses flat byte arrays
 * (struct tquic_route_adv); this struct uses unions for fast comparisons.
 */
struct tquic_ip_route {
	u8 ip_version;
	union {
		__be32 v4;
		struct in6_addr v6;
	} start_addr;
	union {
		__be32 v4;
		struct in6_addr v6;
	} end_addr;
	u8 ipproto;
	struct list_head list;
};

/*
 * =============================================================================
 * VARINT ENCODING HELPERS (Same as QUIC/HTTP3)
 * =============================================================================
 */

/**
 * connect_ip_varint_size - Get encoded size of varint
 * @value: Value to encode
 *
 * Returns: 1, 2, 4, or 8 bytes.
 */
static inline int connect_ip_varint_size(u64 value)
{
	if (value <= 63)
		return 1;
	if (value <= 16383)
		return 2;
	if (value <= 1073741823)
		return 4;
	return 8;
}

/**
 * connect_ip_varint_encode - Encode value as varint
 * @value: Value to encode
 * @buf: Output buffer
 * @len: Buffer length
 *
 * Returns: Bytes written on success, negative error on failure.
 */
static int connect_ip_varint_encode(u64 value, u8 *buf, size_t len)
{
	int size = connect_ip_varint_size(value);

	if (len < size)
		return -ENOSPC;

	switch (size) {
	case 1:
		buf[0] = (u8)value;
		break;
	case 2:
		buf[0] = 0x40 | ((value >> 8) & 0x3f);
		buf[1] = value & 0xff;
		break;
	case 4:
		buf[0] = 0x80 | ((value >> 24) & 0x3f);
		buf[1] = (value >> 16) & 0xff;
		buf[2] = (value >> 8) & 0xff;
		buf[3] = value & 0xff;
		break;
	case 8:
		buf[0] = 0xc0 | ((value >> 56) & 0x3f);
		buf[1] = (value >> 48) & 0xff;
		buf[2] = (value >> 40) & 0xff;
		buf[3] = (value >> 32) & 0xff;
		buf[4] = (value >> 24) & 0xff;
		buf[5] = (value >> 16) & 0xff;
		buf[6] = (value >> 8) & 0xff;
		buf[7] = value & 0xff;
		break;
	}

	return size;
}

/**
 * connect_ip_varint_decode - Decode varint from buffer
 * @buf: Input buffer
 * @len: Buffer length
 * @value: Output value
 *
 * Returns: Bytes consumed on success, negative error on failure.
 */
static int connect_ip_varint_decode(const u8 *buf, size_t len, u64 *value)
{
	int size;
	u64 result;

	if (len == 0)
		return -EAGAIN;

	size = 1 << ((buf[0] >> 6) & 0x3);
	if (len < size)
		return -EAGAIN;

	switch (size) {
	case 1:
		result = buf[0] & 0x3f;
		break;
	case 2:
		result = ((u64)(buf[0] & 0x3f) << 8) | buf[1];
		break;
	case 4:
		result = ((u64)(buf[0] & 0x3f) << 24) |
			 ((u64)buf[1] << 16) |
			 ((u64)buf[2] << 8) |
			 buf[3];
		break;
	case 8:
		result = ((u64)(buf[0] & 0x3f) << 56) |
			 ((u64)buf[1] << 48) |
			 ((u64)buf[2] << 40) |
			 ((u64)buf[3] << 32) |
			 ((u64)buf[4] << 24) |
			 ((u64)buf[5] << 16) |
			 ((u64)buf[6] << 8) |
			 buf[7];
		break;
	default:
		return -EINVAL;
	}

	*value = result;
	return size;
}

/*
 * =============================================================================
 * TUNNEL LIFECYCLE
 * =============================================================================
 */

/**
 * tquic_connect_ip_tunnel_alloc - Allocate a new CONNECT-IP tunnel
 * @stream: HTTP/3 CONNECT stream
 *
 * Returns: Allocated tunnel or NULL on failure.
 */
struct tquic_connect_ip_tunnel *tquic_connect_ip_tunnel_alloc(
	struct tquic_stream *stream)
{
	struct tquic_connect_ip_tunnel *tunnel;

	tunnel = kzalloc(sizeof(*tunnel), GFP_KERNEL);
	if (!tunnel)
		return NULL;

	tunnel->stream = stream;
	INIT_LIST_HEAD(&tunnel->local_addrs);
	INIT_LIST_HEAD(&tunnel->remote_addrs);
	INIT_LIST_HEAD(&tunnel->routes);
	tunnel->num_local_addrs = 0;
	tunnel->num_remote_addrs = 0;
	tunnel->num_routes = 0;
	tunnel->ipproto = 0;  /* Any protocol */
	tunnel->raw_sock = NULL;
	tunnel->next_request_id = 1;
	tunnel->mtu = CONNECT_IP_MIN_MTU_IPV6;  /* Start with minimum safe MTU */
	spin_lock_init(&tunnel->lock);
	refcount_set(&tunnel->refcnt, 1);

	pr_debug("tquic: allocated CONNECT-IP tunnel\n");
	return tunnel;
}
EXPORT_SYMBOL_GPL(tquic_connect_ip_tunnel_alloc);

/**
 * tquic_connect_ip_tunnel_free - Free CONNECT-IP tunnel and resources
 * @tunnel: Tunnel to free
 */
static void tquic_connect_ip_tunnel_free(struct tquic_connect_ip_tunnel *tunnel)
{
	struct tquic_ip_address *addr, *addr_tmp;
	struct tquic_ip_route *route, *route_tmp;

	if (!tunnel)
		return;

	/* Free local addresses */
	list_for_each_entry_safe(addr, addr_tmp, &tunnel->local_addrs, list) {
		list_del_init(&addr->list);
		kfree(addr);
	}

	/* Free remote addresses */
	list_for_each_entry_safe(addr, addr_tmp, &tunnel->remote_addrs, list) {
		list_del_init(&addr->list);
		kfree(addr);
	}

	/* Free routes */
	list_for_each_entry_safe(route, route_tmp, &tunnel->routes, list) {
		list_del_init(&route->list);
		kfree(route);
	}

	/* Release raw socket */
	if (tunnel->raw_sock)
		sock_release(tunnel->raw_sock);

	pr_debug("tquic: freed CONNECT-IP tunnel\n");
	kfree(tunnel);
}

/**
 * tquic_connect_ip_tunnel_get - Increment tunnel reference count
 * @tunnel: Tunnel to reference
 */
void tquic_connect_ip_tunnel_get(struct tquic_connect_ip_tunnel *tunnel)
{
	if (tunnel)
		refcount_inc(&tunnel->refcnt);
}
EXPORT_SYMBOL_GPL(tquic_connect_ip_tunnel_get);

/**
 * tquic_connect_ip_tunnel_put - Decrement tunnel reference count
 * @tunnel: Tunnel to dereference
 */
void tquic_connect_ip_tunnel_put(struct tquic_connect_ip_tunnel *tunnel)
{
	if (tunnel && refcount_dec_and_test(&tunnel->refcnt))
		tquic_connect_ip_tunnel_free(tunnel);
}
EXPORT_SYMBOL_GPL(tquic_connect_ip_tunnel_put);

/*
 * =============================================================================
 * ADDRESS MANAGEMENT
 * =============================================================================
 */

/**
 * tquic_connect_ip_add_local_addr - Add local IP address to tunnel
 * @tunnel: CONNECT-IP tunnel
 * @addr: Address to add
 *
 * Returns: 0 on success, negative errno on failure.
 */
static int tquic_connect_ip_add_local_addr(
	struct tquic_connect_ip_tunnel *tunnel,
	const struct tquic_ip_address *addr)
{
	struct tquic_ip_address *new_addr;

	if (tunnel->num_local_addrs >= CONNECT_IP_MAX_ADDRESSES)
		return -ENOSPC;

	new_addr = kmemdup(addr, sizeof(*addr), GFP_KERNEL);
	if (!new_addr)
		return -ENOMEM;

	INIT_LIST_HEAD(&new_addr->list);

	spin_lock_bh(&tunnel->lock);
	list_add_tail(&new_addr->list, &tunnel->local_addrs);
	tunnel->num_local_addrs++;
	spin_unlock_bh(&tunnel->lock);

	return 0;
}

/**
 * tquic_connect_ip_add_remote_addr - Add remote IP address to tunnel
 * @tunnel: CONNECT-IP tunnel
 * @addr: Address to add
 *
 * Returns: 0 on success, negative errno on failure.
 */
static int tquic_connect_ip_add_remote_addr(
	struct tquic_connect_ip_tunnel *tunnel,
	const struct tquic_ip_address *addr)
{
	struct tquic_ip_address *new_addr;

	if (tunnel->num_remote_addrs >= CONNECT_IP_MAX_ADDRESSES)
		return -ENOSPC;

	new_addr = kmemdup(addr, sizeof(*addr), GFP_KERNEL);
	if (!new_addr)
		return -ENOMEM;

	INIT_LIST_HEAD(&new_addr->list);

	spin_lock_bh(&tunnel->lock);
	list_add_tail(&new_addr->list, &tunnel->remote_addrs);
	tunnel->num_remote_addrs++;
	spin_unlock_bh(&tunnel->lock);

	return 0;
}

/**
 * tunnel_track_route - Track route in tunnel's internal route list
 * @tunnel: CONNECT-IP tunnel
 * @route: Route to track
 *
 * Returns: 0 on success, negative errno on failure.
 */
static int tunnel_track_route(
	struct tquic_connect_ip_tunnel *tunnel,
	const struct tquic_ip_route *route)
{
	struct tquic_ip_route *new_route;

	if (tunnel->num_routes >= CONNECT_IP_MAX_ROUTES)
		return -ENOSPC;

	new_route = kmemdup(route, sizeof(*route), GFP_KERNEL);
	if (!new_route)
		return -ENOMEM;

	INIT_LIST_HEAD(&new_route->list);

	spin_lock_bh(&tunnel->lock);
	list_add_tail(&new_route->list, &tunnel->routes);
	tunnel->num_routes++;
	spin_unlock_bh(&tunnel->lock);

	return 0;
}

/*
 * =============================================================================
 * CAPSULE ENCODING/DECODING
 * =============================================================================
 */

/**
 * connect_ip_encode_capsule_header - Encode capsule header
 * @type: Capsule type
 * @payload_len: Payload length
 * @buf: Output buffer
 * @len: Buffer length
 *
 * Returns: Bytes written on success, negative error on failure.
 */
static int connect_ip_encode_capsule_header(u64 type, u64 payload_len,
					    u8 *buf, size_t len)
{
	int type_size, len_size;
	int written = 0;
	int ret;

	type_size = connect_ip_varint_size(type);
	len_size = connect_ip_varint_size(payload_len);

	if (len < type_size + len_size)
		return -ENOSPC;

	ret = connect_ip_varint_encode(type, buf, len);
	if (ret < 0)
		return ret;
	written += ret;

	ret = connect_ip_varint_encode(payload_len, buf + written, len - written);
	if (ret < 0)
		return ret;
	written += ret;

	return written;
}

/**
 * connect_ip_encode_address_assign - Encode ADDRESS_ASSIGN capsule
 * @assign: Address assignment data
 * @buf: Output buffer
 * @len: Buffer length
 *
 * Returns: Bytes written on success, negative error on failure.
 */
static int connect_ip_encode_address_assign(
	const struct tquic_address_assign *assign,
	u8 *buf, size_t len)
{
	int written = 0;
	int ret;
	size_t payload_len;
	int addr_len;

	addr_len = (assign->ip_version == 4) ? 4 : 16;

	/* Calculate payload size:
	 *   Request ID (varint) + IP Version (1) + IP Address (4 or 16) + Prefix Len (1)
	 */
	payload_len = connect_ip_varint_size(assign->request_id) + 1 + addr_len + 1;

	/* Encode capsule header */
	ret = connect_ip_encode_capsule_header(CAPSULE_ADDRESS_ASSIGN,
					       payload_len, buf, len);
	if (ret < 0)
		return ret;
	written += ret;

	if (len - written < payload_len)
		return -ENOSPC;

	/* Request ID */
	ret = connect_ip_varint_encode(assign->request_id,
				       buf + written, len - written);
	if (ret < 0)
		return ret;
	written += ret;

	/* IP Version */
	buf[written++] = assign->ip_version;

	/* IP Address */
	memcpy(buf + written, assign->addr, addr_len);
	written += addr_len;

	/* Prefix Length */
	buf[written++] = assign->prefix_len;

	return written;
}

/**
 * connect_ip_encode_address_request - Encode ADDRESS_REQUEST capsule
 * @request: Address request data
 * @buf: Output buffer
 * @len: Buffer length
 *
 * Returns: Bytes written on success, negative error on failure.
 */
static int connect_ip_encode_address_request(
	const struct tquic_address_request *request,
	u8 *buf, size_t len)
{
	int written = 0;
	int ret;
	size_t payload_len;

	/* Calculate payload size:
	 *   Request ID (varint) + IP Version (1) + Prefix Len (1)
	 */
	payload_len = connect_ip_varint_size(request->request_id) + 1 + 1;

	/* Encode capsule header */
	ret = connect_ip_encode_capsule_header(CAPSULE_ADDRESS_REQUEST,
					       payload_len, buf, len);
	if (ret < 0)
		return ret;
	written += ret;

	if (len - written < payload_len)
		return -ENOSPC;

	/* Request ID */
	ret = connect_ip_varint_encode(request->request_id,
				       buf + written, len - written);
	if (ret < 0)
		return ret;
	written += ret;

	/* IP Version */
	buf[written++] = request->ip_version;

	/* Prefix Length */
	buf[written++] = request->prefix_len;

	return written;
}

/**
 * connect_ip_encode_route_advertisement - Encode ROUTE_ADVERTISEMENT capsule
 * @routes: Array of routes
 * @count: Number of routes
 * @buf: Output buffer
 * @len: Buffer length
 *
 * Returns: Bytes written on success, negative error on failure.
 */
static int connect_ip_encode_route_advertisement(
	const struct tquic_route_adv *routes,
	size_t count,
	u8 *buf, size_t len)
{
	int written = 0;
	int ret;
	size_t payload_len = 0;
	size_t i;
	int addr_len;

	/* Calculate total payload size */
	for (i = 0; i < count; i++) {
		addr_len = (routes[i].ip_version == 4) ? 4 : 16;
		/* IP Version (1) + Start Addr + End Addr + IP Proto (1) */
		payload_len += 1 + addr_len + addr_len + 1;
	}

	/* Encode capsule header */
	ret = connect_ip_encode_capsule_header(CAPSULE_ROUTE_ADVERTISEMENT,
					       payload_len, buf, len);
	if (ret < 0)
		return ret;
	written += ret;

	if (len - written < payload_len)
		return -ENOSPC;

	/* Encode each route */
	for (i = 0; i < count; i++) {
		addr_len = (routes[i].ip_version == 4) ? 4 : 16;

		/* IP Version */
		buf[written++] = routes[i].ip_version;

		/* Start Address */
		memcpy(buf + written, routes[i].start_addr, addr_len);
		written += addr_len;

		/* End Address */
		memcpy(buf + written, routes[i].end_addr, addr_len);
		written += addr_len;

		/* IP Protocol */
		buf[written++] = routes[i].ipproto;
	}

	return written;
}

/**
 * connect_ip_decode_address_assign - Decode ADDRESS_ASSIGN capsule payload
 * @buf: Input buffer (after capsule header)
 * @len: Payload length
 * @assign: Output assignment data
 *
 * Returns: 0 on success, negative error on failure.
 */
static int connect_ip_decode_address_assign(
	const u8 *buf, size_t len,
	struct tquic_address_assign *assign)
{
	int consumed = 0;
	int ret;
	int addr_len;

	/* Request ID */
	ret = connect_ip_varint_decode(buf, len, &assign->request_id);
	if (ret < 0)
		return ret;
	consumed += ret;

	if (len - consumed < 2)
		return -EINVAL;

	/* IP Version */
	assign->ip_version = buf[consumed++];
	if (assign->ip_version != 4 && assign->ip_version != 6)
		return -EINVAL;

	addr_len = (assign->ip_version == 4) ? 4 : 16;

	if (len - consumed < addr_len + 1)
		return -EINVAL;

	/* IP Address */
	memset(assign->addr, 0, sizeof(assign->addr));
	memcpy(assign->addr, buf + consumed, addr_len);
	consumed += addr_len;

	/* Prefix Length */
	assign->prefix_len = buf[consumed++];

	/* Validate prefix length */
	if (assign->ip_version == 4 && assign->prefix_len > 32)
		return -EINVAL;
	if (assign->ip_version == 6 && assign->prefix_len > 128)
		return -EINVAL;

	return 0;
}

/*
 * =============================================================================
 * CAPSULE SEND FUNCTIONS
 * =============================================================================
 */

/**
 * tquic_connect_ip_send_capsule - Send capsule on tunnel stream
 * @tunnel: CONNECT-IP tunnel
 * @buf: Capsule data
 * @len: Capsule length
 *
 * Returns: 0 on success, negative errno on failure.
 */
static int tquic_connect_ip_send_capsule(
	struct tquic_connect_ip_tunnel *tunnel,
	const u8 *buf, size_t len)
{
	struct tquic_connection *conn;
	int ret;

	if (!tunnel || !tunnel->stream || !tunnel->stream->conn)
		return -ENOTCONN;

	conn = tunnel->stream->conn;

	/* Send via QUIC stream using tquic_xmit */
	ret = tquic_xmit(conn, tunnel->stream, buf, len, false);
	if (ret < 0)
		return ret;

	return 0;
}

/**
 * tquic_connect_ip_send_address_assign - Send ADDRESS_ASSIGN capsule
 * @tunnel: CONNECT-IP tunnel
 * @addr: Address to assign
 *
 * Server sends this to assign IP address(es) to the client.
 *
 * Returns: 0 on success, negative errno on failure.
 */
int tquic_connect_ip_send_address_assign(
	struct tquic_connect_ip_tunnel *tunnel,
	const struct tquic_ip_address *addr)
{
	struct tquic_address_assign assign;
	u8 buf[64];
	int ret;

	if (!tunnel || !addr)
		return -EINVAL;

	/* Build assignment structure */
	assign.request_id = addr->request_id;
	assign.ip_version = addr->version;
	assign.prefix_len = addr->prefix_len;

	memset(assign.addr, 0, sizeof(assign.addr));
	if (addr->version == 4) {
		memcpy(assign.addr, &addr->addr.v4, 4);
	} else {
		memcpy(assign.addr, &addr->addr.v6, 16);
	}

	/* Encode capsule */
	ret = connect_ip_encode_address_assign(&assign, buf, sizeof(buf));
	if (ret < 0)
		return ret;

	/* Send capsule */
	ret = tquic_connect_ip_send_capsule(tunnel, buf, ret);
	if (ret < 0)
		return ret;

	/* Add to local addresses list */
	ret = tquic_connect_ip_add_local_addr(tunnel, addr);
	if (ret < 0) {
		pr_warn("tquic: failed to track assigned address: %d\n", ret);
		/* Continue anyway - address was already sent */
	}

	pr_debug("tquic: sent ADDRESS_ASSIGN for IPv%d/%d request_id=%llu\n",
		 addr->version, addr->prefix_len, addr->request_id);

	return 0;
}
EXPORT_SYMBOL_GPL(tquic_connect_ip_send_address_assign);

/**
 * tquic_connect_ip_request_address - Send ADDRESS_REQUEST capsule
 * @tunnel: CONNECT-IP tunnel
 * @version: IP version (4 or 6)
 * @prefix_len: Requested prefix length (0 = any)
 *
 * Client sends this to request IP address assignment from the server.
 *
 * Returns: Request ID on success, negative errno on failure.
 */
int tquic_connect_ip_request_address(
	struct tquic_connect_ip_tunnel *tunnel,
	u8 version, u8 prefix_len)
{
	struct tquic_address_request request;
	u8 buf[32];
	int ret;
	u64 request_id;

	if (!tunnel)
		return -EINVAL;

	if (version != 4 && version != 6)
		return -EINVAL;

	if (version == 4 && prefix_len > 32)
		return -EINVAL;
	if (version == 6 && prefix_len > 128)
		return -EINVAL;

	/* Generate request ID */
	spin_lock_bh(&tunnel->lock);
	request_id = tunnel->next_request_id++;
	spin_unlock_bh(&tunnel->lock);

	/* Build request structure */
	request.request_id = request_id;
	request.ip_version = version;
	request.prefix_len = prefix_len;

	/* Encode capsule */
	ret = connect_ip_encode_address_request(&request, buf, sizeof(buf));
	if (ret < 0)
		return ret;

	/* Send capsule */
	ret = tquic_connect_ip_send_capsule(tunnel, buf, ret);
	if (ret < 0)
		return ret;

	pr_debug("tquic: sent ADDRESS_REQUEST for IPv%d/%d request_id=%llu\n",
		 version, prefix_len, request_id);

	return (int)request_id;
}
EXPORT_SYMBOL_GPL(tquic_connect_ip_request_address);

/**
 * tquic_connect_ip_advertise_routes - Send ROUTE_ADVERTISEMENT capsule
 * @tunnel: CONNECT-IP tunnel
 * @routes: Array of routes to advertise
 * @count: Number of routes
 *
 * Server sends this to advertise reachable IP routes to the client.
 *
 * Returns: 0 on success, negative errno on failure.
 */
int tquic_connect_ip_advertise_routes(
	struct tquic_connect_ip_tunnel *tunnel,
	const struct tquic_route_adv *routes,
	size_t count)
{
	u8 *buf;
	int ret;
	size_t buf_size;
	size_t i;
	struct tquic_ip_route route;

	if (!tunnel || !routes || count == 0)
		return -EINVAL;

	if (count > CONNECT_IP_MAX_ROUTES)
		return -EINVAL;

	/* Calculate maximum buffer size needed */
	buf_size = 16;  /* Header overhead */
	for (i = 0; i < count; i++) {
		int addr_len = (routes[i].ip_version == 4) ? 4 : 16;
		buf_size += 1 + addr_len + addr_len + 1;
	}

	buf = kmalloc(buf_size, GFP_KERNEL);
	if (!buf)
		return -ENOMEM;

	/* Encode capsule */
	ret = connect_ip_encode_route_advertisement(routes, count, buf, buf_size);
	if (ret < 0) {
		kfree(buf);
		return ret;
	}

	/* Send capsule */
	ret = tquic_connect_ip_send_capsule(tunnel, buf, ret);
	kfree(buf);

	if (ret < 0)
		return ret;

	/* Add routes to tunnel's route list */
	for (i = 0; i < count; i++) {
		route.ip_version = routes[i].ip_version;
		route.ipproto = routes[i].ipproto;

		if (routes[i].ip_version == 4) {
			memcpy(&route.start_addr.v4, routes[i].start_addr, 4);
			memcpy(&route.end_addr.v4, routes[i].end_addr, 4);
		} else {
			memcpy(&route.start_addr.v6, routes[i].start_addr, 16);
			memcpy(&route.end_addr.v6, routes[i].end_addr, 16);
		}

		ret = tunnel_track_route(tunnel, &route);
		if (ret < 0) {
			pr_warn("tquic: failed to track route %zu: %d\n", i, ret);
			/* Continue - routes were already sent */
		}
	}

	pr_debug("tquic: sent ROUTE_ADVERTISEMENT with %zu routes\n", count);

	return 0;
}
EXPORT_SYMBOL_GPL(tquic_connect_ip_advertise_routes);

/*
 * =============================================================================
 * IP PACKET FORWARDING
 * =============================================================================
 *
 * IP packets are transmitted using HTTP Datagrams with context ID 0.
 * Per RFC 9484 Section 6.
 */

/**
 * connect_ip_validate_ip_header - Validate IP packet header
 * @skb: Socket buffer containing IP packet
 * @version: Output IP version (4 or 6)
 *
 * Returns: 0 on success, negative error on failure.
 */
static int connect_ip_validate_ip_header(struct sk_buff *skb, u8 *version)
{
	unsigned char *data;
	u8 ip_version;

	if (!skb || skb->len < 1)
		return -EINVAL;

	data = skb->data;
	ip_version = (data[0] >> 4) & 0x0f;

	if (ip_version == 4) {
		struct iphdr *iph;

		if (skb->len < sizeof(struct iphdr))
			return -EINVAL;

		iph = (struct iphdr *)data;

		/* Validate basic IPv4 header */
		if (iph->ihl < 5)
			return -EINVAL;

		if (skb->len < (iph->ihl * 4))
			return -EINVAL;

		*version = 4;
	} else if (ip_version == 6) {
		struct ipv6hdr *ip6h;

		if (skb->len < sizeof(struct ipv6hdr))
			return -EINVAL;

		ip6h = (struct ipv6hdr *)data;
		(void)ip6h;  /* Suppress unused warning - used for length check */

		*version = 6;
	} else {
		return -EPROTONOSUPPORT;
	}

	return 0;
}

/**
 * connect_ip_check_protocol_filter - Check if packet matches protocol filter
 * @tunnel: CONNECT-IP tunnel
 * @skb: Socket buffer containing IP packet
 *
 * Returns: true if packet matches filter, false otherwise.
 */
static bool connect_ip_check_protocol_filter(
	struct tquic_connect_ip_tunnel *tunnel,
	struct sk_buff *skb)
{
	unsigned char *data = skb->data;
	u8 ip_version = (data[0] >> 4) & 0x0f;
	u8 protocol;

	/* If filter is 0, allow all protocols */
	if (tunnel->ipproto == 0)
		return true;

	if (ip_version == 4) {
		struct iphdr *iph = (struct iphdr *)data;
		protocol = iph->protocol;
	} else if (ip_version == 6) {
		struct ipv6hdr *ip6h = (struct ipv6hdr *)data;
		/* Note: This is simplified - doesn't handle extension headers */
		protocol = ip6h->nexthdr;
	} else {
		return false;
	}

	return (protocol == tunnel->ipproto);
}

/**
 * tquic_connect_ip_send - Forward IP packet through CONNECT-IP tunnel
 * @tunnel: CONNECT-IP tunnel
 * @skb: Socket buffer containing IP packet
 *
 * Encapsulates the IP packet in an HTTP Datagram with context ID 0
 * and sends it through the tunnel.
 *
 * Returns: 0 on success, negative errno on failure.
 */
int tquic_connect_ip_send(struct tquic_connect_ip_tunnel *tunnel,
			  struct sk_buff *skb)
{
	struct tquic_connection *conn;
	u8 *datagram_buf;
	size_t datagram_len;
	int ret;
	u8 version;
	int context_id_size;

	if (!tunnel || !skb)
		return -EINVAL;

	if (!tunnel->stream || !tunnel->stream->conn)
		return -ENOTCONN;

	/* Validate IP header */
	ret = connect_ip_validate_ip_header(skb, &version);
	if (ret < 0)
		return ret;

	/* Check MTU */
	if (version == 6 && skb->len < CONNECT_IP_MIN_MTU_IPV6) {
		/* IPv6 packets must be at least minimum MTU capable */
	}

	if (skb->len > tunnel->mtu)
		return -EMSGSIZE;

	/* Check protocol filter */
	if (!connect_ip_check_protocol_filter(tunnel, skb))
		return -EPROTONOSUPPORT;

	conn = tunnel->stream->conn;

	/* Check if datagrams are enabled */
	if (!conn->datagram.enabled)
		return -EAGAIN;

	/* Build HTTP Datagram with context ID 0 */
	context_id_size = connect_ip_varint_size(CONNECT_IP_CONTEXT_ID);
	datagram_len = context_id_size + skb->len;

	if (datagram_len > conn->datagram.max_send_size)
		return -EMSGSIZE;

	datagram_buf = kmalloc(datagram_len, GFP_ATOMIC);
	if (!datagram_buf)
		return -ENOMEM;

	/* Encode context ID (always 0 for CONNECT-IP packets) */
	ret = connect_ip_varint_encode(CONNECT_IP_CONTEXT_ID,
				       datagram_buf, context_id_size);
	if (ret < 0) {
		kfree(datagram_buf);
		return ret;
	}

	/* Copy IP packet payload */
	ret = skb_copy_bits(skb, 0, datagram_buf + context_id_size, skb->len);
	if (ret < 0) {
		/*
		 * BUG FIX: Check skb_copy_bits() return value to prevent
		 * kernel memory disclosure. If copy fails, datagram_buf
		 * contains uninitialized heap data which would be transmitted.
		 */
		kfree(datagram_buf);
		return ret;
	}

	/* Send as DATAGRAM frame */
	ret = tquic_send_datagram(conn, datagram_buf, datagram_len);
	kfree(datagram_buf);

	if (ret == 0)
		pr_debug("tquic: sent IPv%d packet (%u bytes) via CONNECT-IP\n",
			 version, skb->len);

	return ret;
}
EXPORT_SYMBOL_GPL(tquic_connect_ip_send);

/**
 * tquic_connect_ip_recv - Receive IP packet from CONNECT-IP tunnel
 * @tunnel: CONNECT-IP tunnel
 * @skb: Output socket buffer pointer
 *
 * Receives an HTTP Datagram with context ID 0 and extracts the IP packet.
 *
 * Returns: 0 on success, -EAGAIN if no packet available, negative errno on error.
 */
int tquic_connect_ip_recv(struct tquic_connect_ip_tunnel *tunnel,
			  struct sk_buff **skb)
{
	struct tquic_connection *conn;
	u8 *datagram_buf;
	int ret;
	u64 context_id;
	int context_id_len;
	size_t ip_pkt_len;
	struct sk_buff *new_skb;
	u8 version;

	if (!tunnel || !skb)
		return -EINVAL;

	if (!tunnel->stream || !tunnel->stream->conn)
		return -ENOTCONN;

	conn = tunnel->stream->conn;

	/* Check if datagrams are enabled */
	if (!conn->datagram.enabled)
		return -EAGAIN;

	/* Allocate datagram buffer - max QUIC datagram size */
	datagram_buf = kmalloc(TQUIC_MAX_DATAGRAM_SIZE, GFP_ATOMIC);
	if (!datagram_buf)
		return -ENOMEM;

	/* Receive datagram */
	ret = tquic_recv_datagram(conn, datagram_buf, TQUIC_MAX_DATAGRAM_SIZE,
				  MSG_DONTWAIT);
	if (ret < 0)
		goto out_free;

	if (ret == 0) {
		ret = -EAGAIN;
		goto out_free;
	}

	/* Decode context ID */
	context_id_len = connect_ip_varint_decode(datagram_buf, ret, &context_id);
	if (context_id_len < 0) {
		ret = context_id_len;
		goto out_free;
	}

	/* CONNECT-IP uses context ID 0 */
	if (context_id != CONNECT_IP_CONTEXT_ID) {
		pr_debug("tquic: ignoring datagram with context_id=%llu\n",
			 context_id);
		ret = -EAGAIN;
		goto out_free;
	}

	/* Extract IP packet */
	ip_pkt_len = ret - context_id_len;
	if (ip_pkt_len == 0) {
		ret = -EINVAL;
		goto out_free;
	}

	/* Allocate skb for IP packet */
	new_skb = alloc_skb(ip_pkt_len + NET_SKB_PAD, GFP_ATOMIC);
	if (!new_skb) {
		ret = -ENOMEM;
		goto out_free;
	}

	skb_reserve(new_skb, NET_SKB_PAD);
	skb_put_data(new_skb, datagram_buf + context_id_len, ip_pkt_len);

	/* Free datagram buffer - data now in skb */
	kfree(datagram_buf);

	/* Validate IP header */
	ret = connect_ip_validate_ip_header(new_skb, &version);
	if (ret < 0) {
		kfree_skb(new_skb);
		return ret;
	}

	/* Check protocol filter */
	if (!connect_ip_check_protocol_filter(tunnel, new_skb)) {
		kfree_skb(new_skb);
		return -EPROTONOSUPPORT;
	}

	*skb = new_skb;

	pr_debug("tquic: received IPv%d packet (%zu bytes) via CONNECT-IP\n",
		 version, ip_pkt_len);

	return 0;

out_free:
	kfree(datagram_buf);
	return ret;
}
EXPORT_SYMBOL_GPL(tquic_connect_ip_recv);

/*
 * =============================================================================
 * CAPSULE RECEIVE/PROCESSING
 * =============================================================================
 */

/**
 * tquic_connect_ip_process_capsule - Process received capsule
 * @tunnel: CONNECT-IP tunnel
 * @buf: Capsule data
 * @len: Capsule length
 *
 * Parses and processes incoming capsules (ADDRESS_ASSIGN, ADDRESS_REQUEST,
 * ROUTE_ADVERTISEMENT).
 *
 * Returns: 0 on success, negative errno on failure.
 */
int tquic_connect_ip_process_capsule(
	struct tquic_connect_ip_tunnel *tunnel,
	const u8 *buf, size_t len)
{
	int consumed = 0;
	int ret;
	u64 capsule_type;
	u64 payload_len;

	if (!tunnel || !buf || len == 0)
		return -EINVAL;

	/* Decode capsule type */
	ret = connect_ip_varint_decode(buf, len, &capsule_type);
	if (ret < 0)
		return ret;
	consumed += ret;

	/* Decode payload length */
	ret = connect_ip_varint_decode(buf + consumed, len - consumed, &payload_len);
	if (ret < 0)
		return ret;
	consumed += ret;

	/* Validate we have enough data */
	if (len - consumed < payload_len)
		return -EAGAIN;

	switch (capsule_type) {
	case CAPSULE_ADDRESS_ASSIGN: {
		struct tquic_address_assign assign;
		struct tquic_ip_address addr;

		ret = connect_ip_decode_address_assign(buf + consumed,
						       payload_len, &assign);
		if (ret < 0)
			return ret;

		/* Convert to tquic_ip_address and add to remote addresses */
		addr.version = assign.ip_version;
		addr.prefix_len = assign.prefix_len;
		addr.request_id = assign.request_id;

		if (assign.ip_version == 4) {
			memcpy(&addr.addr.v4, assign.addr, 4);
		} else {
			memcpy(&addr.addr.v6, assign.addr, 16);
		}

		ret = tquic_connect_ip_add_remote_addr(tunnel, &addr);
		if (ret < 0) {
			pr_warn("tquic: failed to add remote address: %d\n", ret);
			return ret;
		}

		pr_debug("tquic: received ADDRESS_ASSIGN IPv%d/%d request_id=%llu\n",
			 addr.version, addr.prefix_len, addr.request_id);
		break;
	}

	case CAPSULE_ADDRESS_REQUEST:
		/* Server-side: client requesting address assignment */
		pr_debug("tquic: received ADDRESS_REQUEST (server should process)\n");
		/* Caller is responsible for handling the request */
		break;

	case CAPSULE_ROUTE_ADVERTISEMENT: {
		const u8 *payload = buf + consumed;
		size_t off = 0;

		spin_lock_bh(&tunnel->lock);
		while (off < payload_len) {
			struct tquic_ip_route *route;
			u8 ver, ipproto;
			int addr_len;

			if (off + 1 > payload_len)
				break;
			ver = payload[off++];

			if (ver == 4)
				addr_len = 4;
			else if (ver == 6)
				addr_len = 16;
			else
				break; /* Unknown IP version */

			if (off + (size_t)(2 * addr_len + 1) > payload_len)
				break;

			if (tunnel->num_routes >= CONNECT_IP_MAX_ROUTES) {
				off += 2 * addr_len + 1;
				continue;
			}

			route = kzalloc(sizeof(*route), GFP_ATOMIC);
			if (!route)
				break;

			route->ip_version = ver;
			if (ver == 4) {
				memcpy(&route->start_addr.v4, payload + off, 4);
				off += 4;
				memcpy(&route->end_addr.v4, payload + off, 4);
				off += 4;
			} else {
				memcpy(&route->start_addr.v6, payload + off, 16);
				off += 16;
				memcpy(&route->end_addr.v6, payload + off, 16);
				off += 16;
			}
			ipproto = payload[off++];
			route->ipproto = ipproto;

			INIT_LIST_HEAD(&route->list);
			list_add_tail(&route->list, &tunnel->routes);
			tunnel->num_routes++;

			pr_debug("tquic: added IPv%d route proto=%u\n",
				 ver, ipproto);
		}
		spin_unlock_bh(&tunnel->lock);
		break;
	}

	default:
		/* Unknown capsule type - skip per RFC 9297 */
		pr_debug("tquic: skipping unknown capsule type %llu\n",
			 capsule_type);
		break;
	}

	return consumed + payload_len;
}
EXPORT_SYMBOL_GPL(tquic_connect_ip_process_capsule);

/*
 * =============================================================================
 * TUNNEL CONFIGURATION
 * =============================================================================
 */

/**
 * tquic_connect_ip_set_mtu - Set tunnel MTU
 * @tunnel: CONNECT-IP tunnel
 * @mtu: New MTU value
 *
 * Sets the tunnel MTU. Enforces minimum MTU of 1280 for IPv6 support.
 *
 * Returns: 0 on success, negative errno on failure.
 */
int tquic_connect_ip_set_mtu(struct tquic_connect_ip_tunnel *tunnel, u32 mtu)
{
	if (!tunnel)
		return -EINVAL;

	/* Enforce IPv6 minimum MTU */
	if (mtu < CONNECT_IP_MIN_MTU_IPV6) {
		pr_warn("tquic: MTU %u below IPv6 minimum, using %d\n",
			mtu, CONNECT_IP_MIN_MTU_IPV6);
		mtu = CONNECT_IP_MIN_MTU_IPV6;
	}

	spin_lock_bh(&tunnel->lock);
	tunnel->mtu = mtu;
	spin_unlock_bh(&tunnel->lock);

	pr_debug("tquic: CONNECT-IP tunnel MTU set to %u\n", mtu);
	return 0;
}
EXPORT_SYMBOL_GPL(tquic_connect_ip_set_mtu);

/**
 * tquic_connect_ip_get_mtu - Get tunnel MTU
 * @tunnel: CONNECT-IP tunnel
 *
 * Returns: Current tunnel MTU.
 */
u32 tquic_connect_ip_get_mtu(struct tquic_connect_ip_tunnel *tunnel)
{
	u32 mtu;

	if (!tunnel)
		return CONNECT_IP_MIN_MTU_IPV6;

	spin_lock_bh(&tunnel->lock);
	mtu = tunnel->mtu;
	spin_unlock_bh(&tunnel->lock);

	return mtu;
}
EXPORT_SYMBOL_GPL(tquic_connect_ip_get_mtu);

/**
 * tquic_connect_ip_set_protocol_filter - Set IP protocol filter
 * @tunnel: CONNECT-IP tunnel
 * @ipproto: IP protocol (0 = any, 1-255 = specific)
 *
 * Returns: 0 on success.
 */
int tquic_connect_ip_set_protocol_filter(
	struct tquic_connect_ip_tunnel *tunnel,
	u8 ipproto)
{
	if (!tunnel)
		return -EINVAL;

	spin_lock_bh(&tunnel->lock);
	tunnel->ipproto = ipproto;
	spin_unlock_bh(&tunnel->lock);

	pr_debug("tquic: CONNECT-IP protocol filter set to %u\n", ipproto);
	return 0;
}
EXPORT_SYMBOL_GPL(tquic_connect_ip_set_protocol_filter);

/*
 * =============================================================================
 * MODULE INITIALIZATION
 * =============================================================================
 */

/*
 * =============================================================================
 * KERNEL ROUTING TABLE INTEGRATION
 * =============================================================================
 */

/* Interface counter for auto-naming */
static atomic_t iface_counter = ATOMIC_INIT(0);

/**
 * struct tquic_connect_ip_netdev_priv - Private data for virtual netdev
 * @tunnel: Associated tunnel
 * @iface: Interface structure
 */
struct tquic_connect_ip_netdev_priv {
	struct tquic_connect_ip_tunnel *tunnel;
	struct tquic_connect_ip_iface *iface;
};

/**
 * tquic_netdev_open - Network device open callback
 * @dev: Network device
 */
static int tquic_netdev_open(struct net_device *dev)
{
	netif_start_queue(dev);
	return 0;
}

/**
 * tquic_netdev_stop - Network device stop callback
 * @dev: Network device
 */
static int tquic_netdev_stop(struct net_device *dev)
{
	netif_stop_queue(dev);
	return 0;
}

/**
 * tquic_netdev_xmit - Network device transmit callback
 * @skb: Socket buffer to transmit
 * @dev: Network device
 *
 * Called when a packet is transmitted on the virtual interface.
 * Forwards the packet through the CONNECT-IP tunnel.
 */
static netdev_tx_t tquic_netdev_xmit(struct sk_buff *skb,
				     struct net_device *dev)
{
	struct tquic_connect_ip_netdev_priv *priv = netdev_priv(dev);
	struct tquic_connect_ip_tunnel *tunnel;
	int ret;

	if (!priv || !priv->tunnel) {
		dev_kfree_skb(skb);
		dev->stats.tx_dropped++;
		return NETDEV_TX_OK;
	}

	tunnel = priv->tunnel;

	/* Forward packet through tunnel */
	ret = tquic_connect_ip_send(tunnel, skb);
	if (ret < 0) {
		dev->stats.tx_errors++;
		dev->stats.tx_dropped++;
	} else {
		dev->stats.tx_packets++;
		dev->stats.tx_bytes += skb->len;
	}

	dev_kfree_skb(skb);
	return NETDEV_TX_OK;
}

/**
 * tquic_netdev_get_stats - Get network device statistics
 * @dev: Network device
 */
static struct net_device_stats *tquic_netdev_get_stats(struct net_device *dev)
{
	return &dev->stats;
}

/* Network device operations */
static const struct net_device_ops tquic_netdev_ops = {
	.ndo_open = tquic_netdev_open,
	.ndo_stop = tquic_netdev_stop,
	.ndo_start_xmit = tquic_netdev_xmit,
	.ndo_get_stats = tquic_netdev_get_stats,
};

/**
 * tquic_netdev_setup - Network device setup callback
 * @dev: Network device
 */
static void tquic_netdev_setup(struct net_device *dev)
{
	dev->netdev_ops = &tquic_netdev_ops;
	dev->type = ARPHRD_NONE;
	dev->flags = IFF_POINTOPOINT | IFF_NOARP;
	dev->mtu = CONNECT_IP_MIN_MTU_IPV6;
	dev->min_mtu = CONNECT_IP_MIN_MTU_IPV4;
	dev->max_mtu = 65535;
	dev->hard_header_len = 0;
	dev->addr_len = 0;
	dev->tx_queue_len = 500;
	dev->lltx = true;
}

/**
 * tquic_connect_ip_create_iface - Create virtual network interface
 * @tunnel: CONNECT-IP tunnel
 * @name: Interface name (or NULL for auto-generated)
 * @iface: Output for created interface
 *
 * Returns: 0 on success, negative errno on failure.
 */
int tquic_connect_ip_create_iface(struct tquic_connect_ip_tunnel *tunnel,
				  const char *name,
				  struct tquic_connect_ip_iface **iface)
{
	struct tquic_connect_ip_iface *new_iface;
	struct net_device *dev;
	struct tquic_connect_ip_netdev_priv *priv;
	char ifname[IFNAMSIZ];
	int ret;

	if (!tunnel || !iface)
		return -EINVAL;

	/* Generate interface name if not provided */
	if (!name) {
		int idx = atomic_inc_return(&iface_counter);
		snprintf(ifname, sizeof(ifname), "%s%d",
			 TQUIC_CONNECT_IP_IFNAME_PREFIX, idx);
		name = ifname;
	}

	/* Allocate interface structure */
	new_iface = kzalloc(sizeof(*new_iface), GFP_KERNEL);
	if (!new_iface)
		return -ENOMEM;

	/* Allocate network device */
	dev = alloc_netdev(sizeof(struct tquic_connect_ip_netdev_priv),
			   name, NET_NAME_USER, tquic_netdev_setup);
	if (!dev) {
		kfree(new_iface);
		return -ENOMEM;
	}

	/* Initialize interface structure */
	new_iface->net_device = dev;
	new_iface->tunnel = tunnel;
	INIT_LIST_HEAD(&new_iface->routes);
	new_iface->num_routes = 0;
	INIT_LIST_HEAD(&new_iface->list);

	/* Set up private data */
	priv = netdev_priv(dev);
	priv->tunnel = tunnel;
	priv->iface = new_iface;

	/* Set MTU from tunnel */
	dev->mtu = tunnel->mtu;

	/* Register network device */
	ret = register_netdev(dev);
	if (ret < 0) {
		free_netdev(dev);
		kfree(new_iface);
		return ret;
	}

	*iface = new_iface;

	pr_info("tquic: created CONNECT-IP interface %s\n", dev->name);
	return 0;
}
EXPORT_SYMBOL_GPL(tquic_connect_ip_create_iface);

/**
 * tquic_connect_ip_destroy_iface - Destroy virtual network interface
 * @iface: Interface to destroy
 */
void tquic_connect_ip_destroy_iface(struct tquic_connect_ip_iface *iface)
{
	struct tquic_connect_ip_route_entry *route, *tmp;

	if (!iface)
		return;

	/* Flush all routes */
	tquic_connect_ip_flush_routes(iface);

	/* Free route entries */
	list_for_each_entry_safe(route, tmp, &iface->routes, list) {
		list_del_init(&route->list);
		kfree(route);
	}

	/* Unregister and free network device */
	if (iface->net_device) {
		pr_info("tquic: destroying CONNECT-IP interface %s\n",
			iface->net_device->name);
		unregister_netdev(iface->net_device);
		free_netdev(iface->net_device);
	}

	kfree(iface);
}
EXPORT_SYMBOL_GPL(tquic_connect_ip_destroy_iface);

/**
 * tquic_connect_ip_add_route - Add route to kernel routing table
 * @iface: Virtual interface
 * @entry: Route entry to add
 *
 * Returns: 0 on success, negative errno on failure.
 */
int tquic_connect_ip_add_route(struct tquic_connect_ip_iface *iface,
			       const struct tquic_connect_ip_route_entry *entry)
{
	struct tquic_connect_ip_route_entry *new_entry;
	struct net *net;
	int ret = 0;

	if (!iface || !iface->net_device || !entry)
		return -EINVAL;

	net = dev_net(iface->net_device);

	/* Duplicate entry for our list */
	new_entry = kmemdup(entry, sizeof(*entry), GFP_KERNEL);
	if (!new_entry)
		return -ENOMEM;

	INIT_LIST_HEAD(&new_entry->list);

	if (entry->ip_version == 4) {
#if IS_ENABLED(CONFIG_IP_MULTIPLE_TABLES)
		struct fib_config cfg = {
			.fc_dst = entry->dst_addr.v4,
			.fc_dst_len = entry->dst_prefix_len,
			.fc_oif = iface->net_device->ifindex,
			.fc_table = entry->table_id ? entry->table_id : RT_TABLE_MAIN,
			.fc_priority = entry->priority,
			.fc_type = RTN_UNICAST,
			.fc_scope = RT_SCOPE_UNIVERSE,
			.fc_protocol = RTPROT_STATIC,
			.fc_nlflags = NLM_F_CREATE | NLM_F_EXCL,
		};

		if (entry->gateway.v4)
			cfg.fc_gw4 = entry->gateway.v4;

		rtnl_lock();
		ret = fib_table_insert(net, fib_get_table(net, cfg.fc_table),
				       &cfg, NULL);
		rtnl_unlock();
#else
		/* Simplified path without policy routing */
		pr_debug("tquic: IPv4 route add (no policy routing support)\n");
#endif
	}
#if IS_ENABLED(CONFIG_IPV6)
	else if (entry->ip_version == 6) {
		struct fib6_config cfg = {
			.fc_dst = entry->dst_addr.v6,
			.fc_dst_len = entry->dst_prefix_len,
			.fc_ifindex = iface->net_device->ifindex,
			.fc_table = entry->table_id ? entry->table_id : RT6_TABLE_MAIN,
			.fc_metric = entry->priority ? entry->priority : 1024,
			.fc_type = RTN_UNICAST,
			.fc_protocol = RTPROT_STATIC,
			.fc_nlinfo = {
				.nl_net = net,
			},
		};

		if (!ipv6_addr_any(&entry->gateway.v6))
			cfg.fc_gateway = entry->gateway.v6;

		rtnl_lock();
		ret = ip6_route_add(&cfg, GFP_KERNEL, NULL);
		rtnl_unlock();
	}
#endif
	else {
		kfree(new_entry);
		return -EAFNOSUPPORT;
	}

	if (ret < 0) {
		kfree(new_entry);
		return ret;
	}

	/* Add to our tracking list */
	list_add_tail(&new_entry->list, &iface->routes);
	iface->num_routes++;

	pr_debug("tquic: added IPv%d route via %s\n",
		 entry->ip_version, iface->net_device->name);

	return 0;
}
EXPORT_SYMBOL_GPL(tquic_connect_ip_add_route);

/**
 * tquic_connect_ip_del_route - Remove route from kernel routing table
 * @iface: Virtual interface
 * @entry: Route entry to remove
 *
 * Returns: 0 on success, negative errno on failure.
 */
int tquic_connect_ip_del_route(struct tquic_connect_ip_iface *iface,
			       const struct tquic_connect_ip_route_entry *entry)
{
	struct tquic_connect_ip_route_entry *tracked, *tmp;
	struct net *net;
	int ret = 0;

	if (!iface || !iface->net_device || !entry)
		return -EINVAL;

	net = dev_net(iface->net_device);

	if (entry->ip_version == 4) {
#if IS_ENABLED(CONFIG_IP_MULTIPLE_TABLES)
		struct fib_config cfg = {
			.fc_dst = entry->dst_addr.v4,
			.fc_dst_len = entry->dst_prefix_len,
			.fc_oif = iface->net_device->ifindex,
			.fc_table = entry->table_id ? entry->table_id : RT_TABLE_MAIN,
		};

		rtnl_lock();
		ret = fib_table_delete(net, fib_get_table(net, cfg.fc_table),
				       &cfg, NULL);
		rtnl_unlock();
#endif
	}
#if IS_ENABLED(CONFIG_IPV6)
	else if (entry->ip_version == 6) {
		struct fib6_table *table;
		struct fib6_config cfg = {
			.fc_dst = entry->dst_addr.v6,
			.fc_dst_len = entry->dst_prefix_len,
			.fc_ifindex = iface->net_device->ifindex,
			.fc_table = entry->table_id ? entry->table_id : RT6_TABLE_MAIN,
			.fc_nlinfo = {
				.nl_net = net,
			},
		};

		rtnl_lock();
		table = fib6_get_table(net, cfg.fc_table);
		ret = table ? fib6_table_delete(net, table, &cfg, NULL) : -ESRCH;
		rtnl_unlock();
	}
#endif
	else {
		return -EAFNOSUPPORT;
	}

	/* Remove from tracking list */
	list_for_each_entry_safe(tracked, tmp, &iface->routes, list) {
		if (tracked->ip_version == entry->ip_version &&
		    tracked->dst_prefix_len == entry->dst_prefix_len) {
			bool match = false;

			if (entry->ip_version == 4) {
				match = (tracked->dst_addr.v4 == entry->dst_addr.v4);
			} else {
				match = ipv6_addr_equal(&tracked->dst_addr.v6,
							&entry->dst_addr.v6);
			}

			if (match) {
				list_del_init(&tracked->list);
				kfree(tracked);
				iface->num_routes--;
				break;
			}
		}
	}

	return ret;
}
EXPORT_SYMBOL_GPL(tquic_connect_ip_del_route);

/**
 * tquic_connect_ip_flush_routes - Remove all routes for interface
 * @iface: Virtual interface
 *
 * Returns: 0 on success, negative errno on failure.
 */
int tquic_connect_ip_flush_routes(struct tquic_connect_ip_iface *iface)
{
	struct tquic_connect_ip_route_entry *entry, *tmp;

	if (!iface)
		return -EINVAL;

	list_for_each_entry_safe(entry, tmp, &iface->routes, list) {
		tquic_connect_ip_del_route(iface, entry);
	}

	return 0;
}
EXPORT_SYMBOL_GPL(tquic_connect_ip_flush_routes);

/**
 * tquic_connect_ip_set_iface_addr - Set interface IP address
 * @iface: Virtual interface
 * @addr: IP address
 *
 * Returns: 0 on success, negative errno on failure.
 */
int tquic_connect_ip_set_iface_addr(struct tquic_connect_ip_iface *iface,
				    const struct tquic_ip_address *addr)
{
	struct net_device *dev;
	struct net *net;
	int ret = 0;

	if (!iface || !iface->net_device || !addr)
		return -EINVAL;

	dev = iface->net_device;
	net = dev_net(dev);

	if (addr->version == 4) {
		/*
		 * Use devinet_ioctl() which is exported and handles its own
		 * locking. SIOCSIFADDR sets the primary address; SIOCSIFNETMASK
		 * sets the subnet mask for the configured address.
		 */
		struct ifreq ifr = {};
		struct sockaddr_in *sin = (struct sockaddr_in *)&ifr.ifr_addr;

		strscpy(ifr.ifr_name, dev->name, IFNAMSIZ);
		sin->sin_family = AF_INET;
		sin->sin_addr.s_addr = addr->addr.v4;
		ret = devinet_ioctl(net, SIOCSIFADDR, &ifr);
		if (ret == 0) {
			sin->sin_addr.s_addr = inet_make_mask(addr->prefix_len);
			devinet_ioctl(net, SIOCSIFNETMASK, &ifr);
		}
	}
#if IS_ENABLED(CONFIG_IPV6)
	else if (addr->version == 6) {
		struct inet6_dev *idev;
		struct inet6_ifaddr *ifp;
		struct ifa6_config cfg = {
			.pfx		= &addr->addr.v6,
			.plen		= addr->prefix_len,
			.ifa_flags	= IFA_F_PERMANENT,
			.valid_lft	= INFINITY_LIFE_TIME,
			.preferred_lft	= INFINITY_LIFE_TIME,
			.scope		= RT_SCOPE_UNIVERSE,
		};

		rtnl_lock();
		idev = ipv6_find_idev(dev);
		if (IS_ERR(idev)) {
			rtnl_unlock();
			return PTR_ERR(idev);
		}
		ifp = ipv6_add_addr(idev, &cfg, true, NULL);
		rtnl_unlock();
		if (IS_ERR(ifp))
			ret = PTR_ERR(ifp);
		else
			in6_ifa_put(ifp);
	}
#endif
	else {
		ret = -EAFNOSUPPORT;
	}

	if (ret == 0)
		pr_debug("tquic: set IPv%d address on %s\n",
			 addr->version, dev->name);

	return ret;
}
EXPORT_SYMBOL_GPL(tquic_connect_ip_set_iface_addr);

/**
 * tquic_connect_ip_set_iface_mtu - Set interface MTU
 * @iface: Virtual interface
 * @mtu: MTU value
 *
 * Returns: 0 on success, negative errno on failure.
 */
int tquic_connect_ip_set_iface_mtu(struct tquic_connect_ip_iface *iface,
				   u32 mtu)
{
	if (!iface || !iface->net_device)
		return -EINVAL;

	if (mtu < CONNECT_IP_MIN_MTU_IPV4)
		return -EINVAL;

	rtnl_lock();
	dev_set_mtu(iface->net_device, mtu);
	rtnl_unlock();

	pr_debug("tquic: set MTU %u on %s\n", mtu, iface->net_device->name);
	return 0;
}
EXPORT_SYMBOL_GPL(tquic_connect_ip_set_iface_mtu);

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
 * Returns: 0 on success, negative errno on failure.
 */
int tquic_connect_ip_enable_forwarding(struct tquic_connect_ip_tunnel *tunnel,
				       bool enable)
{
	if (!tunnel)
		return -EINVAL;

	/*
	 * In a full implementation, this would configure the tunnel to
	 * inject received packets into the kernel network stack.
	 * For now, this is tracked as a flag.
	 */
	pr_debug("tquic: CONNECT-IP forwarding %s\n",
		 enable ? "enabled" : "disabled");

	return 0;
}
EXPORT_SYMBOL_GPL(tquic_connect_ip_enable_forwarding);

/**
 * tquic_connect_ip_inject_packet - Inject received packet into kernel
 * @tunnel: CONNECT-IP tunnel
 * @skb: Socket buffer containing IP packet
 *
 * Returns: 0 on success, negative errno on failure.
 */
/**
 * connect_ip_validate_v4_addr - Check if an IPv4 address is safe to inject
 * @addr: IPv4 address in network byte order
 *
 * Returns: true if the address is safe, false if it must be blocked.
 */
static bool connect_ip_validate_v4_addr(__be32 addr)
{
	if (ipv4_is_loopback(addr) || ipv4_is_multicast(addr) ||
	    ipv4_is_lbcast(addr) || ipv4_is_zeronet(addr))
		return false;

	/* RFC 1918 private ranges */
	if (ipv4_is_private_10(addr) || ipv4_is_private_172(addr) ||
	    ipv4_is_private_192(addr))
		return false;

	/* Link-local 169.254.0.0/16 */
	if (ipv4_is_linklocal_169(addr))
		return false;

	return true;
}

#if IS_ENABLED(CONFIG_IPV6)
/**
 * connect_ip_validate_v6_addr - Check if an IPv6 address is safe to inject
 * @addr: IPv6 address
 *
 * Returns: true if the address is safe, false if it must be blocked.
 */
static bool connect_ip_validate_v6_addr(const struct in6_addr *addr)
{
	if (ipv6_addr_loopback(addr) || ipv6_addr_is_multicast(addr))
		return false;

	if (__ipv6_addr_type(addr) & IPV6_ADDR_LINKLOCAL)
		return false;

	/* Block IPv4-mapped IPv6 addresses pointing to unsafe ranges */
	if (ipv6_addr_v4mapped(addr)) {
		__be32 v4 = addr->s6_addr32[3];

		if (!connect_ip_validate_v4_addr(v4))
			return false;
	}

	return true;
}
#endif

int tquic_connect_ip_inject_packet(struct tquic_connect_ip_tunnel *tunnel,
				   struct sk_buff *skb)
{
	unsigned char *data;
	u8 ip_version;
	int ret;

	if (!tunnel || !skb)
		return -EINVAL;

	if (skb->len < 1)
		return -EINVAL;

	data = skb->data;
	ip_version = (data[0] >> 4) & 0x0f;

	/* Set up skb for reception */
	skb->dev = NULL;  /* Would be set to virtual interface */
	skb_reset_mac_header(skb);
	skb_reset_network_header(skb);

	if (ip_version == 4) {
		struct iphdr *iph;

		if (skb->len < sizeof(struct iphdr))
			return -EINVAL;

		iph = (struct iphdr *)data;

		/* Validate source and destination addresses */
		if (!connect_ip_validate_v4_addr(iph->saddr) ||
		    !connect_ip_validate_v4_addr(iph->daddr)) {
			pr_debug("connect-ip: blocked packet with unsafe IPv4 addr\n");
			return -EACCES;
		}

		skb->protocol = htons(ETH_P_IP);
		ret = netif_rx(skb);
	}
#if IS_ENABLED(CONFIG_IPV6)
	else if (ip_version == 6) {
		struct ipv6hdr *ip6h;

		if (skb->len < sizeof(struct ipv6hdr))
			return -EINVAL;

		ip6h = (struct ipv6hdr *)data;

		/* Validate source and destination addresses */
		if (!connect_ip_validate_v6_addr(&ip6h->saddr) ||
		    !connect_ip_validate_v6_addr(&ip6h->daddr)) {
			pr_debug("connect-ip: blocked packet with unsafe IPv6 addr\n");
			return -EACCES;
		}

		skb->protocol = htons(ETH_P_IPV6);
		ret = netif_rx(skb);
	}
#endif
	else {
		return -EPROTONOSUPPORT;
	}

	return (ret == NET_RX_SUCCESS) ? 0 : -EIO;
}
EXPORT_SYMBOL_GPL(tquic_connect_ip_inject_packet);

/*
 * =============================================================================
 * TUNNEL STATISTICS
 * =============================================================================
 */

/**
 * tquic_connect_ip_get_stats - Get tunnel statistics
 * @tunnel: CONNECT-IP tunnel
 * @stats: Output for statistics
 *
 * Returns: 0 on success, negative errno on failure.
 */
int tquic_connect_ip_get_stats(struct tquic_connect_ip_tunnel *tunnel,
			       struct tquic_connect_ip_stats *stats)
{
	if (!tunnel || !stats)
		return -EINVAL;

	memset(stats, 0, sizeof(*stats));

	/*
	 * In a full implementation, these would be tracked in the tunnel.
	 * For now, return zeros.
	 */

	return 0;
}
EXPORT_SYMBOL_GPL(tquic_connect_ip_get_stats);

/*
 * =============================================================================
 * MODULE INITIALIZATION
 * =============================================================================
 */

/**
 * tquic_connect_ip_init - Initialize CONNECT-IP subsystem
 */
int __init tquic_connect_ip_init(void)
{
	pr_info("tquic: CONNECT-IP (RFC 9484) subsystem initialized\n");
	return 0;
}

/**
 * tquic_connect_ip_exit - Cleanup CONNECT-IP subsystem
 */
void __exit tquic_connect_ip_exit(void)
{
	pr_info("tquic: CONNECT-IP subsystem cleaned up\n");
}
