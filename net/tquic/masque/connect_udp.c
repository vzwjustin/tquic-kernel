// SPDX-License-Identifier: GPL-2.0-only
/*
 * TQUIC MASQUE: CONNECT-UDP Protocol Implementation
 *
 * Copyright (c) 2026 Linux Foundation
 *
 * Implementation of CONNECT-UDP for MASQUE as specified in RFC 9298.
 *
 * CONNECT-UDP enables a client to establish a UDP tunnel through an HTTP/3
 * proxy. UDP datagrams are encapsulated in HTTP Datagrams (RFC 9297) using
 * context ID 0.
 *
 * Key features:
 *   - URI template: /.well-known/masque/udp/{target_host}/{target_port}/
 *   - Max UDP payload: 65,527 bytes (65535 - 8 byte UDP header)
 *   - Minimum idle timeout: 2 minutes
 *   - Context IDs: even = client allocated, odd = proxy allocated
 *   - Don't Fragment bit set on IPv4 for PMTUD
 */

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/net.h>
#include <linux/socket.h>
#include <linux/workqueue.h>
#include <linux/timer.h>
#include <linux/ctype.h>
#include <linux/inet.h>
#include <net/sock.h>
#include <net/udp.h>
#include <net/ip.h>
#include <net/ipv6.h>
#include <net/tquic.h>
#include <net/tquic_http3.h>
#include <linux/unaligned.h>

#include "connect_udp.h"
#include "../core/varint.h"
#include "../protocol.h"

/*
 * =============================================================================
 * Module State
 * =============================================================================
 */

/* Work queue for asynchronous operations */
static struct workqueue_struct *connect_udp_wq;

/* Slab cache for tunnel structures */
static struct kmem_cache *tunnel_cache;

/*
 * =============================================================================
 * URI Template Parsing (RFC 9298 Section 3)
 * =============================================================================
 *
 * The well-known path template is:
 *   /.well-known/masque/udp/{target_host}/{target_port}/
 *
 * Where:
 *   - {target_host} is the target hostname or IP address (percent-encoded)
 *   - {target_port} is the target UDP port number
 */

/* Well-known path prefix */
#define CONNECT_UDP_PATH_PREFIX		"/.well-known/masque/udp/"
#define CONNECT_UDP_PATH_PREFIX_LEN	24

/**
 * percent_decode_char - Decode a percent-encoded character
 * @s: Pointer to '%XX' sequence
 * @c: Output for decoded character
 *
 * Returns: 0 on success, -EINVAL on invalid encoding.
 */
static int percent_decode_char(const char *s, char *c)
{
	unsigned int val;

	if (s[0] != '%' || !isxdigit(s[1]) || !isxdigit(s[2]))
		return -EINVAL;

	val = (hex_to_bin(s[1]) << 4) | hex_to_bin(s[2]);
	if (val == 0)
		return -EINVAL;  /* Null not allowed */

	*c = (char)val;
	return 0;
}

/**
 * percent_decode - Decode percent-encoded string in place
 * @s: String to decode (modified in place)
 *
 * Returns: Length of decoded string on success, negative errno on error.
 */
static int percent_decode(char *s)
{
	char *src = s;
	char *dst = s;
	int len = 0;

	while (*src) {
		if (*src == '%') {
			char c;
			int ret = percent_decode_char(src, &c);
			if (ret < 0)
				return ret;
			*dst++ = c;
			src += 3;
		} else {
			*dst++ = *src++;
		}
		len++;
	}
	*dst = '\0';
	return len;
}

/**
 * tquic_connect_udp_parse_template - Parse CONNECT-UDP URI template
 * @path: Request path
 * @host: Output buffer for hostname
 * @host_len: Size of host buffer
 * @port: Output for port number
 *
 * Returns: 0 on success, negative errno on error.
 */
int tquic_connect_udp_parse_template(const char *path,
				     char *host, size_t host_len,
				     u16 *port)
{
	const char *p;
	const char *host_start, *host_end;
	const char *port_start, *port_end;
	char port_str[8];
	unsigned long port_val;
	size_t copy_len;
	int ret;

	if (!path || !host || !port || host_len == 0)
		return -EINVAL;

	/* Check path prefix */
	if (strncmp(path, CONNECT_UDP_PATH_PREFIX,
		    CONNECT_UDP_PATH_PREFIX_LEN) != 0)
		return -EINVAL;

	p = path + CONNECT_UDP_PATH_PREFIX_LEN;

	/* Find host portion (ends at next '/') */
	host_start = p;
	host_end = strchr(p, '/');
	if (!host_end || host_end == host_start)
		return -EINVAL;

	/* Copy host with bounds checking */
	copy_len = host_end - host_start;
	if (copy_len >= host_len)
		return -ENOBUFS;

	memcpy(host, host_start, copy_len);
	host[copy_len] = '\0';

	/* Percent-decode the hostname */
	ret = percent_decode(host);
	if (ret < 0)
		return ret;

	/* Find port portion (ends at next '/' or end of string) */
	port_start = host_end + 1;
	port_end = strchr(port_start, '/');
	if (!port_end)
		port_end = port_start + strlen(port_start);

	if (port_end == port_start)
		return -EINVAL;

	copy_len = port_end - port_start;
	if (copy_len >= sizeof(port_str))
		return -EINVAL;

	memcpy(port_str, port_start, copy_len);
	port_str[copy_len] = '\0';

	/* Parse port number */
	ret = kstrtoul(port_str, 10, &port_val);
	if (ret)
		return -EINVAL;

	if (port_val == 0 || port_val > 65535)
		return -ERANGE;

	*port = (u16)port_val;
	return 0;
}
EXPORT_SYMBOL_GPL(tquic_connect_udp_parse_template);

/**
 * percent_encode_char - Check if character needs percent encoding
 * @c: Character to check
 *
 * Returns: true if character needs encoding in URI host component.
 */
static bool needs_percent_encode(char c)
{
	/* Unreserved characters per RFC 3986 */
	if (isalnum(c))
		return false;
	if (c == '-' || c == '.' || c == '_' || c == '~')
		return false;
	/* Allow IPv6 address characters */
	if (c == ':' || c == '[' || c == ']')
		return false;
	return true;
}

/**
 * tquic_connect_udp_build_path - Build CONNECT-UDP request path
 * @host: Target hostname
 * @port: Target port
 * @buf: Output buffer
 * @buf_len: Buffer size
 *
 * Returns: Number of bytes written (including null), negative errno on error.
 */
int tquic_connect_udp_build_path(const char *host, u16 port,
				 char *buf, size_t buf_len)
{
	char *p;
	const char *src;
	size_t remaining;
	int written;

	if (!host || !buf || buf_len == 0)
		return -EINVAL;

	/* Start with prefix */
	if (buf_len < CONNECT_UDP_PATH_PREFIX_LEN + 1)
		return -ENOBUFS;

	memcpy(buf, CONNECT_UDP_PATH_PREFIX, CONNECT_UDP_PATH_PREFIX_LEN);
	p = buf + CONNECT_UDP_PATH_PREFIX_LEN;
	remaining = buf_len - CONNECT_UDP_PATH_PREFIX_LEN;

	/* Percent-encode hostname */
	for (src = host; *src; src++) {
		if (needs_percent_encode(*src)) {
			if (remaining < 4)  /* %XX + nul or more */
				return -ENOBUFS;
			snprintf(p, remaining, "%%%02X", (u8)*src);
			p += 3;
			remaining -= 3;
		} else {
			if (remaining < 2)
				return -ENOBUFS;
			*p++ = *src;
			remaining--;
		}
	}

	/* Add separator and port */
	written = snprintf(p, remaining, "/%u/", port);
	if (written < 0 || written >= remaining)
		return -ENOBUFS;

	return (buf_len - remaining + written + 1);
}
EXPORT_SYMBOL_GPL(tquic_connect_udp_build_path);

/*
 * =============================================================================
 * HTTP Datagram Encoding/Decoding (RFC 9297)
 * =============================================================================
 *
 * HTTP Datagram format:
 *   Context ID (varint) || Payload
 *
 * For CONNECT-UDP, context ID 0 is used for UDP payload.
 */

/**
 * tquic_http_datagram_encode - Encode HTTP Datagram
 * @context_id: Context ID
 * @payload: Payload data
 * @payload_len: Payload length
 * @buf: Output buffer
 * @buf_len: Buffer size
 *
 * Returns: Number of bytes written on success, negative errno on error.
 */
int tquic_http_datagram_encode(u64 context_id,
			       const u8 *payload, size_t payload_len,
			       u8 *buf, size_t buf_len)
{
	int varint_len;
	size_t total_len;

	if (!buf || (!payload && payload_len > 0))
		return -EINVAL;

	/* Calculate varint length for context ID */
	varint_len = tquic_varint_size(context_id);
	if (varint_len == 0)
		return -EINVAL;

	total_len = varint_len + payload_len;
	if (total_len > buf_len)
		return -ENOBUFS;

	/* Encode context ID */
	tquic_varint_encode(context_id, buf, varint_len);

	/* Copy payload */
	if (payload_len > 0)
		memcpy(buf + varint_len, payload, payload_len);

	return total_len;
}
EXPORT_SYMBOL_GPL(tquic_http_datagram_encode);

/**
 * tquic_http_datagram_decode - Decode HTTP Datagram
 * @buf: Input buffer
 * @buf_len: Input length
 * @context_id: Output context ID
 * @payload: Output payload pointer
 * @payload_len: Output payload length
 *
 * Returns: Number of bytes consumed on success, negative errno on error.
 */
int tquic_http_datagram_decode(const u8 *buf, size_t buf_len,
			       u64 *context_id,
			       const u8 **payload, size_t *payload_len)
{
	int varint_len;

	if (!buf || !context_id || !payload || !payload_len)
		return -EINVAL;

	if (buf_len == 0)
		return -EINVAL;

	/* Decode context ID */
	varint_len = tquic_varint_decode(buf, buf_len, context_id);
	if (varint_len < 0)
		return varint_len;

	/* Set payload pointer and length */
	*payload = buf + varint_len;
	*payload_len = buf_len - varint_len;

	return buf_len;
}
EXPORT_SYMBOL_GPL(tquic_http_datagram_decode);

/*
 * =============================================================================
 * Tunnel Lifecycle Management
 * =============================================================================
 */

/**
 * tunnel_alloc - Allocate a new tunnel structure
 * @conn: Parent connection
 * @is_server: True if proxy side
 * @gfp: Memory allocation flags
 *
 * Returns: Allocated tunnel or NULL on failure.
 */
static struct tquic_connect_udp_tunnel *tunnel_alloc(
	struct tquic_connection *conn, bool is_server, gfp_t gfp)
{
	struct tquic_connect_udp_tunnel *tunnel;

	if (tunnel_cache)
		tunnel = kmem_cache_zalloc(tunnel_cache, gfp);
	else
		tunnel = kzalloc(sizeof(*tunnel), gfp);

	if (!tunnel)
		return NULL;

	tunnel->conn = conn;
	tunnel->is_server = is_server;
	tunnel->state = CONNECT_UDP_IDLE;
	tunnel->idle_timeout_ms = TQUIC_CONNECT_UDP_IDLE_TIMEOUT;
	tunnel->last_activity = ktime_get();

	/* Context ID allocation: client starts at 0 (even), proxy at 1 (odd) */
	tunnel->next_context_id = is_server ? 1 : 0;

	spin_lock_init(&tunnel->lock);
	refcount_set(&tunnel->refcnt, 1);
	INIT_LIST_HEAD(&tunnel->list);

	return tunnel;
}

/**
 * tunnel_free - Free tunnel resources
 * @tunnel: Tunnel to free
 */
static void tunnel_free(struct tquic_connect_udp_tunnel *tunnel)
{
	if (!tunnel)
		return;

	/* Close UDP socket */
	if (tunnel->udp_sock) {
		sock_release(tunnel->udp_sock);
		tunnel->udp_sock = NULL;
	}

	/* Cancel timers */
	del_timer_sync(&tunnel->idle_timer);

	/* Free structure */
	if (tunnel_cache)
		kmem_cache_free(tunnel_cache, tunnel);
	else
		kfree(tunnel);
}

/**
 * tquic_connect_udp_put - Decrement tunnel reference count
 * @tunnel: Tunnel to dereference
 */
void tquic_connect_udp_put(struct tquic_connect_udp_tunnel *tunnel)
{
	if (tunnel && refcount_dec_and_test(&tunnel->refcnt))
		tunnel_free(tunnel);
}
EXPORT_SYMBOL_GPL(tquic_connect_udp_put);

/*
 * =============================================================================
 * UDP Socket Management
 * =============================================================================
 */

/**
 * create_udp_socket - Create kernel UDP socket for proxy forwarding
 * @tunnel: Tunnel needing UDP socket
 * @family: Address family (AF_INET or AF_INET6)
 *
 * Returns: 0 on success, negative errno on error.
 */
static int create_udp_socket(struct tquic_connect_udp_tunnel *tunnel,
			     sa_family_t family)
{
	struct socket *sock;
	int val;
	int ret;

	ret = sock_create_kern(&init_net, family, SOCK_DGRAM, IPPROTO_UDP, &sock);
	if (ret < 0)
		return ret;

	/*
	 * Set Don't Fragment bit for IPv4 (RFC 9298 recommends PMTUD)
	 * Per RFC 9298 Section 4.3: "proxies SHOULD NOT fragment..."
	 */
	if (family == AF_INET) {
		val = IP_PMTUDISC_DO;
		ret = sock->ops->setsockopt(sock, IPPROTO_IP, IP_MTU_DISCOVER,
					    KERNEL_SOCKPTR(&val), sizeof(val));
		if (ret < 0) {
			/* Non-fatal, continue without DF */
			pr_debug("connect-udp: IP_MTU_DISCOVER failed: %d\n", ret);
		}
	}
#if IS_ENABLED(CONFIG_IPV6)
	else if (family == AF_INET6) {
		val = IPV6_PMTUDISC_DO;
		ret = sock->ops->setsockopt(sock, IPPROTO_IPV6, IPV6_MTU_DISCOVER,
					    KERNEL_SOCKPTR(&val), sizeof(val));
		if (ret < 0) {
			pr_debug("connect-udp: IPV6_MTU_DISCOVER failed: %d\n", ret);
		}
	}
#endif

	tunnel->udp_sock = sock;
	return 0;
}

/**
 * resolve_target - Resolve target hostname to address
 * @tunnel: Tunnel with target information
 *
 * Attempts to parse the hostname as an IP address. For actual DNS resolution,
 * this would need to use userspace or a kernel DNS resolver.
 *
 * Returns: 0 on success, negative errno on error.
 */
static int resolve_target(struct tquic_connect_udp_tunnel *tunnel)
{
	struct tquic_connect_udp_target *target = &tunnel->target;
	struct sockaddr_in *sin;
	struct sockaddr_in6 *sin6;
	int ret;

	if (target->resolved)
		return 0;

	/* Try IPv4 first */
	sin = (struct sockaddr_in *)&target->addr;
	ret = in4_pton(target->host, strlen(target->host),
		       (u8 *)&sin->sin_addr.s_addr, -1, NULL);
	if (ret == 1) {
		sin->sin_family = AF_INET;
		sin->sin_port = htons(target->port);
		target->resolved = true;
		return 0;
	}

#if IS_ENABLED(CONFIG_IPV6)
	/* Try IPv6 */
	sin6 = (struct sockaddr_in6 *)&target->addr;
	ret = in6_pton(target->host, strlen(target->host),
		       (u8 *)&sin6->sin6_addr, -1, NULL);
	if (ret == 1) {
		sin6->sin6_family = AF_INET6;
		sin6->sin6_port = htons(target->port);
		target->resolved = true;
		return 0;
	}
#endif

	/*
	 * For hostname resolution, would need to either:
	 * 1. Defer to userspace (request_key or similar)
	 * 2. Use the kernel DNS resolver (if available)
	 * 3. Return error and let proxy handle out-of-band
	 *
	 * For now, fail if not a literal IP address.
	 */
	return -EINVAL;
}

/*
 * =============================================================================
 * Idle Timeout Handling
 * =============================================================================
 */

/**
 * idle_timer_callback - Handle idle timeout expiration
 * @t: Timer that fired
 */
static void idle_timer_callback(struct timer_list *t)
{
	struct tquic_connect_udp_tunnel *tunnel =
		from_timer(tunnel, t, idle_timer);

	spin_lock_bh(&tunnel->lock);

	if (tunnel->state == CONNECT_UDP_ESTABLISHED) {
		ktime_t now = ktime_get();
		s64 idle_ms = ktime_ms_delta(now, tunnel->last_activity);

		if (idle_ms >= tunnel->idle_timeout_ms) {
			/* Idle timeout expired, close tunnel */
			tunnel->state = CONNECT_UDP_CLOSING;
			spin_unlock_bh(&tunnel->lock);

			tquic_connect_udp_close(tunnel);
			return;
		}

		/* Reschedule timer for remaining time */
		mod_timer(&tunnel->idle_timer,
			  jiffies + msecs_to_jiffies(tunnel->idle_timeout_ms - idle_ms));
	}

	spin_unlock_bh(&tunnel->lock);
}

/**
 * reset_idle_timer - Reset the idle timeout timer
 * @tunnel: Tunnel to reset timer for
 *
 * Called on activity to prevent idle timeout.
 */
static void reset_idle_timer(struct tquic_connect_udp_tunnel *tunnel)
{
	tunnel->last_activity = ktime_get();
	mod_timer(&tunnel->idle_timer,
		  jiffies + msecs_to_jiffies(tunnel->idle_timeout_ms));
}

/*
 * =============================================================================
 * Client-Side Implementation
 * =============================================================================
 */

/**
 * tquic_connect_udp_connect - Create CONNECT-UDP tunnel (client)
 * @conn: QUIC connection to proxy
 * @host: Target hostname
 * @port: Target port
 * @tunnel: Output parameter for tunnel
 *
 * Returns: 0 on success, negative errno on error.
 */
int tquic_connect_udp_connect(struct tquic_connection *conn,
			      const char *host, u16 port,
			      struct tquic_connect_udp_tunnel **tunnel)
{
	struct tquic_connect_udp_tunnel *t;
	struct tquic_stream *stream;
	size_t host_len;
	int ret;

	if (!conn || !host || !tunnel)
		return -EINVAL;

	if (port == 0)
		return -EINVAL;

	host_len = strlen(host);
	if (host_len == 0 || host_len >= TQUIC_CONNECT_UDP_HOST_MAX)
		return -EINVAL;

	/* Check connection state */
	if (conn->state != TQUIC_CONN_CONNECTED)
		return -ENOTCONN;

	/* Allocate tunnel */
	t = tunnel_alloc(conn, false, GFP_KERNEL);
	if (!t)
		return -ENOMEM;

	/* Set up target */
	memcpy(t->target.host, host, host_len + 1);
	t->target.port = port;

	/* Try to resolve target (for return traffic matching) */
	resolve_target(t);

	/* Open bidirectional stream for HTTP/3 request */
	stream = tquic_stream_open(conn, true);
	if (IS_ERR(stream)) {
		ret = PTR_ERR(stream);
		goto err_free;
	}

	t->stream = stream;

	/* Initialize idle timer */
	timer_setup(&t->idle_timer, idle_timer_callback, 0);

	/* Transition to REQUESTING state */
	spin_lock_bh(&t->lock);
	t->state = CONNECT_UDP_REQUESTING;
	spin_unlock_bh(&t->lock);

	/*
	 * At this point, the caller should send the extended CONNECT request
	 * with the following pseudo-headers:
	 *   :method = CONNECT
	 *   :protocol = connect-udp
	 *   :scheme = https
	 *   :authority = <proxy authority>
	 *   :path = /.well-known/masque/udp/{host}/{port}/
	 *
	 * This is typically handled by the HTTP/3 layer.
	 */

	*tunnel = t;
	return 0;

err_free:
	tunnel_free(t);
	return ret;
}
EXPORT_SYMBOL_GPL(tquic_connect_udp_connect);

/**
 * tquic_connect_udp_wait - Wait for tunnel establishment
 * @tunnel: Tunnel to wait on
 * @timeout_ms: Timeout in milliseconds
 *
 * Returns: 0 on success, negative errno on error.
 */
int tquic_connect_udp_wait(struct tquic_connect_udp_tunnel *tunnel,
			   u32 timeout_ms)
{
	unsigned long deadline;
	int ret = 0;

	if (!tunnel)
		return -EINVAL;

	if (timeout_ms > 0)
		deadline = jiffies + msecs_to_jiffies(timeout_ms);
	else
		deadline = MAX_JIFFY_OFFSET;

	while (1) {
		enum tquic_connect_udp_state state;

		spin_lock_bh(&tunnel->lock);
		state = tunnel->state;
		spin_unlock_bh(&tunnel->lock);

		switch (state) {
		case CONNECT_UDP_ESTABLISHED:
			return 0;

		case CONNECT_UDP_ERROR:
		case CONNECT_UDP_CLOSED:
			/* Check HTTP status for specific error */
			if (tunnel->http_status >= 400 &&
			    tunnel->http_status < 500)
				return -ECONNREFUSED;
			if (tunnel->http_status >= 500)
				return -EREMOTEIO;
			return -ECONNRESET;

		case CONNECT_UDP_REQUESTING:
			/* Still waiting */
			break;

		default:
			return -EINVAL;
		}

		/* Check timeout */
		if (time_after(jiffies, deadline))
			return -ETIMEDOUT;

		/* Sleep with timeout */
		ret = wait_event_interruptible_timeout(
			tunnel->stream->wait,
			tunnel->state != CONNECT_UDP_REQUESTING,
			msecs_to_jiffies(100));

		if (ret < 0)
			return -EINTR;
	}
}
EXPORT_SYMBOL_GPL(tquic_connect_udp_wait);

/*
 * =============================================================================
 * Server-Side (Proxy) Implementation
 * =============================================================================
 */

/**
 * tquic_connect_udp_accept - Accept CONNECT-UDP request (proxy)
 * @conn: Connection from client
 * @stream: Request stream
 * @tunnel: Output parameter for tunnel
 *
 * Returns: 0 on success, negative errno on error.
 */
int tquic_connect_udp_accept(struct tquic_connection *conn,
			     struct tquic_stream *stream,
			     struct tquic_connect_udp_tunnel **tunnel)
{
	struct tquic_connect_udp_tunnel *t;
	int ret;

	if (!conn || !stream || !tunnel)
		return -EINVAL;

	/* Allocate tunnel as server */
	t = tunnel_alloc(conn, true, GFP_KERNEL);
	if (!t)
		return -ENOMEM;

	t->stream = stream;

	/* Initialize idle timer */
	timer_setup(&t->idle_timer, idle_timer_callback, 0);

	/*
	 * The caller should have parsed the request headers to extract
	 * target host and port from the :path pseudo-header using
	 * tquic_connect_udp_parse_template().
	 */

	*tunnel = t;
	return 0;
}
EXPORT_SYMBOL_GPL(tquic_connect_udp_accept);

/**
 * tquic_connect_udp_respond - Send CONNECT-UDP response
 * @tunnel: Tunnel to respond on
 * @status_code: HTTP status code
 *
 * Returns: 0 on success, negative errno on error.
 */
int tquic_connect_udp_respond(struct tquic_connect_udp_tunnel *tunnel,
			      u16 status_code)
{
	int ret;

	if (!tunnel)
		return -EINVAL;

	spin_lock_bh(&tunnel->lock);

	if (tunnel->state != CONNECT_UDP_IDLE) {
		spin_unlock_bh(&tunnel->lock);
		return -EINVAL;
	}

	tunnel->http_status = status_code;

	if (status_code == 200) {
		/* Success - create UDP socket and transition to established */
		if (tunnel->target.resolved) {
			ret = create_udp_socket(tunnel,
						tunnel->target.addr.ss_family);
			if (ret < 0) {
				tunnel->state = CONNECT_UDP_ERROR;
				spin_unlock_bh(&tunnel->lock);
				return ret;
			}
		}

		tunnel->state = CONNECT_UDP_ESTABLISHED;
		reset_idle_timer(tunnel);
	} else {
		/* Error response */
		tunnel->state = CONNECT_UDP_ERROR;
	}

	spin_unlock_bh(&tunnel->lock);

	/*
	 * The actual HTTP response headers should be sent by the HTTP/3 layer:
	 *   :status = <status_code>
	 *   capsule-protocol = ?1  (for successful responses)
	 *
	 * This function just updates internal state.
	 */

	return 0;
}
EXPORT_SYMBOL_GPL(tquic_connect_udp_respond);

/*
 * =============================================================================
 * Data Transfer Implementation
 * =============================================================================
 */

/**
 * tquic_connect_udp_send - Send UDP datagram through tunnel
 * @tunnel: Tunnel to send on
 * @data: UDP payload
 * @len: Payload length
 *
 * Returns: Number of bytes sent, or negative errno on error.
 */
int tquic_connect_udp_send(struct tquic_connect_udp_tunnel *tunnel,
			   const u8 *data, size_t len)
{
	u8 *datagram_buf;
	int datagram_len;
	int ret;

	if (!tunnel || (!data && len > 0))
		return -EINVAL;

	if (len > TQUIC_CONNECT_UDP_MAX_PAYLOAD)
		return -EMSGSIZE;

	spin_lock_bh(&tunnel->lock);

	if (tunnel->state != CONNECT_UDP_ESTABLISHED) {
		spin_unlock_bh(&tunnel->lock);
		return -ENOTCONN;
	}

	/* Reset idle timer on activity */
	reset_idle_timer(tunnel);

	spin_unlock_bh(&tunnel->lock);

	/* Allocate buffer for HTTP Datagram encoding */
	datagram_buf = kmalloc(len + 8, GFP_KERNEL);  /* 8 bytes max for varint */
	if (!datagram_buf)
		return -ENOMEM;

	/* Encode as HTTP Datagram with context ID 0 */
	datagram_len = tquic_http_datagram_encode(TQUIC_CONNECT_UDP_CONTEXT_ID,
						  data, len,
						  datagram_buf, len + 8);
	if (datagram_len < 0) {
		kfree(datagram_buf);
		return datagram_len;
	}

	/*
	 * Send via QUIC DATAGRAM frame (RFC 9221)
	 *
	 * The QUIC connection must have negotiated DATAGRAM frame support.
	 * If not available, would need to use stream-based capsules.
	 */
	ret = tquic_send_datagram(tunnel->conn, datagram_buf, datagram_len);

	if (ret >= 0) {
		spin_lock_bh(&tunnel->lock);
		tunnel->stats.tx_datagrams++;
		tunnel->stats.tx_bytes += len;
		spin_unlock_bh(&tunnel->lock);
		ret = len;
	} else {
		spin_lock_bh(&tunnel->lock);
		tunnel->stats.tx_errors++;
		spin_unlock_bh(&tunnel->lock);
	}

	kfree(datagram_buf);
	return ret;
}
EXPORT_SYMBOL_GPL(tquic_connect_udp_send);

/**
 * tquic_connect_udp_recv - Receive UDP datagram from tunnel
 * @tunnel: Tunnel to receive from
 * @buf: Output buffer
 * @len: Buffer size
 *
 * Returns: Number of bytes received, or negative errno on error.
 */
int tquic_connect_udp_recv(struct tquic_connect_udp_tunnel *tunnel,
			   u8 *buf, size_t len)
{
	u8 *datagram_buf;
	u64 context_id;
	const u8 *payload;
	size_t payload_len;
	int ret;

	if (!tunnel || !buf)
		return -EINVAL;

	spin_lock_bh(&tunnel->lock);

	if (tunnel->state != CONNECT_UDP_ESTABLISHED) {
		spin_unlock_bh(&tunnel->lock);
		return -ENOTCONN;
	}

	spin_unlock_bh(&tunnel->lock);

	/* Allocate buffer for receiving HTTP Datagram */
	datagram_buf = kmalloc(TQUIC_CONNECT_UDP_MAX_PAYLOAD + 8, GFP_KERNEL);
	if (!datagram_buf)
		return -ENOMEM;

	/* Receive QUIC DATAGRAM */
	ret = tquic_recv_datagram(tunnel->conn, datagram_buf,
				  TQUIC_CONNECT_UDP_MAX_PAYLOAD + 8, 0);
	if (ret <= 0) {
		kfree(datagram_buf);
		return ret < 0 ? ret : -EAGAIN;
	}

	/* Decode HTTP Datagram */
	ret = tquic_http_datagram_decode(datagram_buf, ret,
					 &context_id, &payload, &payload_len);
	if (ret < 0) {
		kfree(datagram_buf);
		spin_lock_bh(&tunnel->lock);
		tunnel->stats.rx_errors++;
		spin_unlock_bh(&tunnel->lock);
		return ret;
	}

	/* Verify context ID is 0 (UDP payload) */
	if (context_id != TQUIC_CONNECT_UDP_CONTEXT_ID) {
		kfree(datagram_buf);
		/* Non-zero context IDs are for future extensions, ignore */
		return -EAGAIN;
	}

	/* Copy payload to user buffer */
	if (payload_len > len) {
		/* Truncate if buffer too small */
		payload_len = len;
	}
	memcpy(buf, payload, payload_len);

	spin_lock_bh(&tunnel->lock);
	tunnel->stats.rx_datagrams++;
	tunnel->stats.rx_bytes += payload_len;
	reset_idle_timer(tunnel);
	spin_unlock_bh(&tunnel->lock);

	kfree(datagram_buf);
	return payload_len;
}
EXPORT_SYMBOL_GPL(tquic_connect_udp_recv);

/**
 * tquic_connect_udp_sendv - Vectored send
 * @tunnel: Tunnel to send on
 * @iov: I/O vectors
 * @iovcnt: Number of vectors
 *
 * Returns: Number of bytes sent, or negative errno on error.
 */
int tquic_connect_udp_sendv(struct tquic_connect_udp_tunnel *tunnel,
			    const struct iovec *iov, int iovcnt)
{
	u8 *buf;
	size_t total_len = 0;
	size_t offset = 0;
	int i;
	int ret;

	if (!tunnel || !iov || iovcnt <= 0)
		return -EINVAL;

	/* Calculate total length */
	for (i = 0; i < iovcnt; i++)
		total_len += iov[i].iov_len;

	if (total_len > TQUIC_CONNECT_UDP_MAX_PAYLOAD)
		return -EMSGSIZE;

	/* Allocate and copy to contiguous buffer */
	buf = kmalloc(total_len, GFP_KERNEL);
	if (!buf)
		return -ENOMEM;

	for (i = 0; i < iovcnt; i++) {
		memcpy(buf + offset, iov[i].iov_base, iov[i].iov_len);
		offset += iov[i].iov_len;
	}

	ret = tquic_connect_udp_send(tunnel, buf, total_len);

	kfree(buf);
	return ret;
}
EXPORT_SYMBOL_GPL(tquic_connect_udp_sendv);

/**
 * tquic_connect_udp_poll - Poll for events
 * @tunnel: Tunnel to poll
 * @events: Events to check
 *
 * Returns: Bitmask of ready events.
 */
__poll_t tquic_connect_udp_poll(struct tquic_connect_udp_tunnel *tunnel,
				short events)
{
	__poll_t mask = 0;

	if (!tunnel)
		return EPOLLERR;

	spin_lock_bh(&tunnel->lock);

	switch (tunnel->state) {
	case CONNECT_UDP_ESTABLISHED:
		if (events & POLLOUT)
			mask |= EPOLLOUT;
		/* Would check receive queue for POLLIN */
		break;

	case CONNECT_UDP_ERROR:
	case CONNECT_UDP_CLOSED:
		mask |= EPOLLERR | EPOLLHUP;
		break;

	default:
		break;
	}

	spin_unlock_bh(&tunnel->lock);

	return mask;
}
EXPORT_SYMBOL_GPL(tquic_connect_udp_poll);

/*
 * =============================================================================
 * Tunnel Closure
 * =============================================================================
 */

/**
 * tquic_connect_udp_close - Close CONNECT-UDP tunnel
 * @tunnel: Tunnel to close
 */
void tquic_connect_udp_close(struct tquic_connect_udp_tunnel *tunnel)
{
	if (!tunnel)
		return;

	spin_lock_bh(&tunnel->lock);

	if (tunnel->state == CONNECT_UDP_CLOSED) {
		spin_unlock_bh(&tunnel->lock);
		return;
	}

	tunnel->state = CONNECT_UDP_CLOSED;
	spin_unlock_bh(&tunnel->lock);

	/* Cancel idle timer */
	del_timer_sync(&tunnel->idle_timer);

	/* Close UDP socket */
	if (tunnel->udp_sock) {
		sock_release(tunnel->udp_sock);
		tunnel->udp_sock = NULL;
	}

	/* Close QUIC stream */
	if (tunnel->stream) {
		tquic_stream_close(tunnel->stream);
		tunnel->stream = NULL;
	}

	/* Release reference */
	tquic_connect_udp_put(tunnel);
}
EXPORT_SYMBOL_GPL(tquic_connect_udp_close);

/*
 * =============================================================================
 * Configuration
 * =============================================================================
 */

/**
 * tquic_connect_udp_set_idle_timeout - Set tunnel idle timeout
 * @tunnel: Tunnel to configure
 * @timeout_ms: Timeout in milliseconds
 *
 * Returns: 0 on success, -EINVAL if timeout too short.
 */
int tquic_connect_udp_set_idle_timeout(struct tquic_connect_udp_tunnel *tunnel,
				       u32 timeout_ms)
{
	if (!tunnel)
		return -EINVAL;

	/* Enforce minimum 2-minute timeout per RFC 9298 */
	if (timeout_ms < TQUIC_CONNECT_UDP_IDLE_TIMEOUT)
		return -EINVAL;

	spin_lock_bh(&tunnel->lock);
	tunnel->idle_timeout_ms = timeout_ms;
	spin_unlock_bh(&tunnel->lock);

	return 0;
}
EXPORT_SYMBOL_GPL(tquic_connect_udp_set_idle_timeout);

/**
 * tquic_connect_udp_get_stats - Get tunnel statistics
 * @tunnel: Tunnel to query
 * @stats: Output parameter
 *
 * Returns: 0 on success, negative errno on error.
 */
int tquic_connect_udp_get_stats(struct tquic_connect_udp_tunnel *tunnel,
				struct tquic_connect_udp_stats *stats)
{
	if (!tunnel || !stats)
		return -EINVAL;

	spin_lock_bh(&tunnel->lock);
	memcpy(stats, &tunnel->stats, sizeof(*stats));
	spin_unlock_bh(&tunnel->lock);

	return 0;
}
EXPORT_SYMBOL_GPL(tquic_connect_udp_get_stats);

/**
 * tquic_connect_udp_get_target - Get tunnel target info
 * @tunnel: Tunnel to query
 * @target: Output parameter
 *
 * Returns: 0 on success, negative errno on error.
 */
int tquic_connect_udp_get_target(struct tquic_connect_udp_tunnel *tunnel,
				 struct tquic_connect_udp_target *target)
{
	if (!tunnel || !target)
		return -EINVAL;

	spin_lock_bh(&tunnel->lock);
	memcpy(target, &tunnel->target, sizeof(*target));
	spin_unlock_bh(&tunnel->lock);

	return 0;
}
EXPORT_SYMBOL_GPL(tquic_connect_udp_get_target);

/*
 * =============================================================================
 * Proxy-Side UDP Forwarding
 * =============================================================================
 *
 * These functions handle forwarding UDP datagrams between the QUIC tunnel
 * and the target server.
 */

/**
 * forward_to_target - Forward received datagram to target
 * @tunnel: Proxy tunnel
 * @data: UDP payload
 * @len: Payload length
 *
 * Called when the proxy receives a datagram from the client via QUIC.
 * Forwards the datagram to the target UDP endpoint.
 *
 * Returns: Number of bytes sent, or negative errno on error.
 */
static int forward_to_target(struct tquic_connect_udp_tunnel *tunnel,
			     const u8 *data, size_t len)
{
	struct msghdr msg = {};
	struct kvec iov;
	int ret;

	if (!tunnel->udp_sock || !tunnel->target.resolved)
		return -ENOTCONN;

	iov.iov_base = (void *)data;
	iov.iov_len = len;

	msg.msg_name = &tunnel->target.addr;
	msg.msg_namelen = sizeof(tunnel->target.addr);

	ret = kernel_sendmsg(tunnel->udp_sock, &msg, &iov, 1, len);

	if (ret >= 0) {
		spin_lock_bh(&tunnel->lock);
		tunnel->stats.tx_datagrams++;
		tunnel->stats.tx_bytes += len;
		spin_unlock_bh(&tunnel->lock);
	} else {
		spin_lock_bh(&tunnel->lock);
		tunnel->stats.tx_errors++;
		spin_unlock_bh(&tunnel->lock);
	}

	return ret;
}

/**
 * forward_from_target - Forward datagram from target to client
 * @tunnel: Proxy tunnel
 *
 * Called when the proxy receives a datagram from the target UDP endpoint.
 * Forwards the datagram to the client via QUIC.
 *
 * Returns: Number of bytes forwarded, or negative errno on error.
 */
static int forward_from_target(struct tquic_connect_udp_tunnel *tunnel)
{
	struct msghdr msg = {};
	struct kvec iov;
	u8 *buf;
	int ret;

	if (!tunnel->udp_sock)
		return -ENOTCONN;

	buf = kmalloc(TQUIC_CONNECT_UDP_MAX_PAYLOAD, GFP_KERNEL);
	if (!buf)
		return -ENOMEM;

	iov.iov_base = buf;
	iov.iov_len = TQUIC_CONNECT_UDP_MAX_PAYLOAD;

	ret = kernel_recvmsg(tunnel->udp_sock, &msg, &iov, 1,
			     TQUIC_CONNECT_UDP_MAX_PAYLOAD, MSG_DONTWAIT);
	if (ret <= 0) {
		kfree(buf);
		return ret < 0 ? ret : -EAGAIN;
	}

	/* Send to client via QUIC */
	ret = tquic_connect_udp_send(tunnel, buf, ret);

	kfree(buf);
	return ret;
}

/**
 * invoke_recv_handler - Invoke the receive handler callback
 * @tunnel: Tunnel that received the datagram
 * @context_id: Context ID from the HTTP Datagram
 * @data: Payload data
 * @len: Payload length
 *
 * Invokes the registered receive handler callback if one is set.
 * The handler is invoked with the tunnel lock released.
 *
 * Returns: Return value from the handler, or 0 if no handler is set.
 */
static int invoke_recv_handler(struct tquic_connect_udp_tunnel *tunnel,
			       u64 context_id, const u8 *data, size_t len)
{
	tquic_connect_udp_datagram_handler handler;
	void *ctx;
	unsigned long flags;

	spin_lock_irqsave(&tunnel->lock, flags);
	handler = tunnel->recv_handler;
	ctx = tunnel->recv_handler_ctx;
	spin_unlock_irqrestore(&tunnel->lock, flags);

	if (handler)
		return handler(tunnel, context_id, data, len, ctx);

	return 0;
}

/**
 * process_incoming_quic_datagrams - Process datagrams from QUIC layer
 * @tunnel: Tunnel to process
 *
 * Processes incoming QUIC datagrams and either forwards them (proxy mode)
 * or invokes the receive handler (client mode).
 *
 * Returns: Number of datagrams processed, or negative errno on error.
 */
static int process_incoming_quic_datagrams(struct tquic_connect_udp_tunnel *tunnel)
{
	u8 *datagram_buf;
	u64 context_id;
	const u8 *payload;
	size_t payload_len;
	int ret;
	int processed = 0;

	datagram_buf = kmalloc(TQUIC_CONNECT_UDP_MAX_PAYLOAD + 8, GFP_KERNEL);
	if (!datagram_buf)
		return -ENOMEM;

	while (1) {
		/* Receive QUIC DATAGRAM non-blocking */
		ret = tquic_recv_datagram(tunnel->conn, datagram_buf,
					  TQUIC_CONNECT_UDP_MAX_PAYLOAD + 8,
					  MSG_DONTWAIT);
		if (ret <= 0)
			break;

		/* Decode HTTP Datagram */
		ret = tquic_http_datagram_decode(datagram_buf, ret,
						 &context_id, &payload,
						 &payload_len);
		if (ret < 0) {
			spin_lock_bh(&tunnel->lock);
			tunnel->stats.rx_errors++;
			spin_unlock_bh(&tunnel->lock);
			continue;
		}

		/* Update statistics */
		spin_lock_bh(&tunnel->lock);
		tunnel->stats.rx_datagrams++;
		tunnel->stats.rx_bytes += payload_len;
		reset_idle_timer(tunnel);
		spin_unlock_bh(&tunnel->lock);

		/* Invoke receive handler if registered */
		if (tunnel->recv_handler) {
			invoke_recv_handler(tunnel, context_id, payload,
					    payload_len);
		} else if (tunnel->is_server &&
			   context_id == TQUIC_CONNECT_UDP_CONTEXT_ID) {
			/* Proxy mode: forward to target */
			forward_to_target(tunnel, payload, payload_len);
		}

		processed++;
	}

	kfree(datagram_buf);
	return processed > 0 ? processed : ret;
}

/**
 * proxy_forward_work - Work function for asynchronous forwarding
 * @work: Work structure
 */
static void proxy_forward_work(struct work_struct *work)
{
	struct tquic_connect_udp_tunnel *tunnel =
		container_of(work, struct tquic_connect_udp_tunnel, forward_work);

	if (tunnel->state != CONNECT_UDP_ESTABLISHED)
		return;

	/* Process any incoming QUIC datagrams */
	process_incoming_quic_datagrams(tunnel);

	/* Forward any pending datagrams from target */
	while (forward_from_target(tunnel) > 0)
		;
}

/*
 * =============================================================================
 * Module Initialization
 * =============================================================================
 */

/**
 * tquic_connect_udp_init - Initialize CONNECT-UDP subsystem
 *
 * Returns: 0 on success, negative errno on error.
 */
int __init tquic_connect_udp_init(void)
{
	/* Create slab cache for tunnel structures */
	tunnel_cache = kmem_cache_create("tquic_connect_udp_tunnel",
					 sizeof(struct tquic_connect_udp_tunnel),
					 0, SLAB_HWCACHE_ALIGN, NULL);
	if (!tunnel_cache)
		return -ENOMEM;

	/* Create work queue */
	connect_udp_wq = alloc_workqueue("tquic_connect_udp",
					 WQ_MEM_RECLAIM | WQ_HIGHPRI, 0);
	if (!connect_udp_wq) {
		kmem_cache_destroy(tunnel_cache);
		tunnel_cache = NULL;
		return -ENOMEM;
	}

	pr_info("TQUIC MASQUE: CONNECT-UDP initialized (RFC 9298)\n");
	return 0;
}
EXPORT_SYMBOL_GPL(tquic_connect_udp_init);

/**
 * tquic_connect_udp_exit - Cleanup CONNECT-UDP subsystem
 */
void __exit tquic_connect_udp_exit(void)
{
	if (connect_udp_wq) {
		flush_workqueue(connect_udp_wq);
		destroy_workqueue(connect_udp_wq);
		connect_udp_wq = NULL;
	}

	if (tunnel_cache) {
		kmem_cache_destroy(tunnel_cache);
		tunnel_cache = NULL;
	}

	pr_info("TQUIC MASQUE: CONNECT-UDP cleaned up\n");
}
EXPORT_SYMBOL_GPL(tquic_connect_udp_exit);

/*
 * =============================================================================
 * Extended CONNECT Validation (RFC 9220)
 * =============================================================================
 */

/**
 * tquic_extended_connect_validate - Validate extended CONNECT request
 * @req: Extended CONNECT request to validate
 * @expected_protocol: Expected protocol string
 *
 * Returns: 0 if valid, negative errno if invalid.
 */
int tquic_extended_connect_validate(const struct tquic_extended_connect_request *req,
				    const char *expected_protocol)
{
	if (!req || !expected_protocol)
		return -EINVAL;

	/* Method must be CONNECT */
	if (!req->method || strcmp(req->method, "CONNECT") != 0)
		return -EINVAL;

	/* Protocol must match expected */
	if (!req->protocol || strcmp(req->protocol, expected_protocol) != 0)
		return -EINVAL;

	/* Scheme must be present for extended CONNECT */
	if (!req->scheme || strlen(req->scheme) == 0)
		return -EINVAL;

	/* Authority must be present */
	if (!req->authority || strlen(req->authority) == 0)
		return -EINVAL;

	/* Path must be present */
	if (!req->path || strlen(req->path) == 0)
		return -EINVAL;

	return 0;
}
EXPORT_SYMBOL_GPL(tquic_extended_connect_validate);

/*
 * =============================================================================
 * Proxy-Status Header Implementation (RFC 9209)
 * =============================================================================
 */

/**
 * tquic_proxy_status_format - Format Proxy-Status header value
 * @status: Proxy status to format
 * @buf: Output buffer
 * @len: Buffer length
 *
 * Formats according to RFC 8941 Structured Field Values:
 *   proxy_name; error=error_type; details="..."
 *
 * Returns: Length of formatted string, or negative errno on error.
 */
int tquic_proxy_status_format(const struct tquic_proxy_status *status,
			      char *buf, size_t len)
{
	int written;

	if (!status || !buf || len == 0)
		return -EINVAL;

	/* Start with proxy name as a token */
	if (status->proxy_name[0]) {
		written = snprintf(buf, len, "%s", status->proxy_name);
	} else {
		/* Use generic proxy identifier if no name set */
		written = snprintf(buf, len, "proxy");
	}

	if (written < 0 || written >= len)
		return -ENOSPC;

	/* Add error type parameter if present */
	if (status->error_type) {
		int ret = snprintf(buf + written, len - written,
				   "; error=%s", status->error_type);
		if (ret < 0 || ret >= len - written)
			return -ENOSPC;
		written += ret;
	}

	/* Add details parameter if present */
	if (status->details[0]) {
		int ret = snprintf(buf + written, len - written,
				   "; details=\"%s\"", status->details);
		if (ret < 0 || ret >= len - written)
			return -ENOSPC;
		written += ret;
	}

	/* Add next-hop parameter if present */
	if (status->next_hop[0]) {
		int ret = snprintf(buf + written, len - written,
				   "; next-hop=\"%s\"", status->next_hop);
		if (ret < 0 || ret >= len - written)
			return -ENOSPC;
		written += ret;
	}

	return written;
}
EXPORT_SYMBOL_GPL(tquic_proxy_status_format);

/**
 * tquic_proxy_status_parse - Parse Proxy-Status header value
 * @value: Header value string
 * @status: Output for parsed status
 *
 * Returns: 0 on success, negative errno on error.
 */
int tquic_proxy_status_parse(const char *value,
			     struct tquic_proxy_status *status)
{
	const char *p, *end;
	char *dst;
	size_t copy_len;

	if (!value || !status)
		return -EINVAL;

	memset(status, 0, sizeof(*status));

	p = value;

	/* Skip leading whitespace */
	while (*p && (*p == ' ' || *p == '\t'))
		p++;

	if (!*p)
		return -EINVAL;

	/* Parse proxy name (token) */
	end = p;
	while (*end && *end != ';' && *end != ' ' && *end != '\t')
		end++;

	copy_len = end - p;
	if (copy_len >= sizeof(status->proxy_name))
		copy_len = sizeof(status->proxy_name) - 1;

	memcpy(status->proxy_name, p, copy_len);
	status->proxy_name[copy_len] = '\0';

	p = end;

	/* Parse parameters */
	while (*p) {
		/* Skip whitespace and semicolons */
		while (*p && (*p == ' ' || *p == '\t' || *p == ';'))
			p++;

		if (!*p)
			break;

		/* Look for known parameters */
		if (strncmp(p, "error=", 6) == 0) {
			p += 6;
			/* Error type is a token */
			end = p;
			while (*end && *end != ';' && *end != ' ' && *end != '\t')
				end++;

			/* Match against known error types */
			if (strncmp(p, PROXY_STATUS_DNS_TIMEOUT,
				    strlen(PROXY_STATUS_DNS_TIMEOUT)) == 0) {
				status->error_type = PROXY_STATUS_DNS_TIMEOUT;
			} else if (strncmp(p, PROXY_STATUS_DNS_ERROR,
					   strlen(PROXY_STATUS_DNS_ERROR)) == 0) {
				status->error_type = PROXY_STATUS_DNS_ERROR;
			} else if (strncmp(p, PROXY_STATUS_DESTINATION_NOT_FOUND,
					   strlen(PROXY_STATUS_DESTINATION_NOT_FOUND)) == 0) {
				status->error_type = PROXY_STATUS_DESTINATION_NOT_FOUND;
			} else if (strncmp(p, PROXY_STATUS_DESTINATION_UNAVAILABLE,
					   strlen(PROXY_STATUS_DESTINATION_UNAVAILABLE)) == 0) {
				status->error_type = PROXY_STATUS_DESTINATION_UNAVAILABLE;
			} else if (strncmp(p, PROXY_STATUS_CONNECTION_REFUSED,
					   strlen(PROXY_STATUS_CONNECTION_REFUSED)) == 0) {
				status->error_type = PROXY_STATUS_CONNECTION_REFUSED;
			} else if (strncmp(p, PROXY_STATUS_PROXY_INTERNAL_ERROR,
					   strlen(PROXY_STATUS_PROXY_INTERNAL_ERROR)) == 0) {
				status->error_type = PROXY_STATUS_PROXY_INTERNAL_ERROR;
			}
			/* Add more as needed */

			p = end;
		} else if (strncmp(p, "details=\"", 9) == 0) {
			p += 9;
			dst = status->details;
			while (*p && *p != '"' &&
			       dst < status->details + sizeof(status->details) - 1) {
				if (*p == '\\' && *(p + 1))
					p++;
				*dst++ = *p++;
			}
			*dst = '\0';
			if (*p == '"')
				p++;
		} else if (strncmp(p, "next-hop=\"", 10) == 0) {
			p += 10;
			dst = status->next_hop;
			while (*p && *p != '"' &&
			       dst < status->next_hop + sizeof(status->next_hop) - 1) {
				if (*p == '\\' && *(p + 1))
					p++;
				*dst++ = *p++;
			}
			*dst = '\0';
			if (*p == '"')
				p++;
		} else {
			/* Skip unknown parameter */
			while (*p && *p != ';')
				p++;
		}
	}

	return 0;
}
EXPORT_SYMBOL_GPL(tquic_proxy_status_parse);

/**
 * tquic_connect_udp_set_proxy_status - Set proxy status for error response
 * @tunnel: Tunnel
 * @error_type: Error type token
 * @details: Optional details string
 *
 * Returns: 0 on success, negative errno on error.
 */
int tquic_connect_udp_set_proxy_status(struct tquic_connect_udp_tunnel *tunnel,
				       const char *error_type,
				       const char *details)
{
	/*
	 * In a full implementation, this would store the proxy status
	 * in the tunnel structure for inclusion in the HTTP response.
	 * For now, we just log it.
	 */
	if (!tunnel || !error_type)
		return -EINVAL;

	pr_debug("connect-udp: proxy status error=%s details=%s\n",
		 error_type, details ? details : "(none)");

	return 0;
}
EXPORT_SYMBOL_GPL(tquic_connect_udp_set_proxy_status);

/*
 * =============================================================================
 * Context ID Management (RFC 9298 Section 4)
 * =============================================================================
 */

/**
 * tquic_connect_udp_alloc_context_id - Allocate new context ID
 * @tunnel: Tunnel to allocate on
 * @context_id: Output for allocated context ID
 *
 * Returns: 0 on success, negative errno on failure.
 */
int tquic_connect_udp_alloc_context_id(struct tquic_connect_udp_tunnel *tunnel,
				       u64 *context_id)
{
	u64 id;

	if (!tunnel || !context_id)
		return -EINVAL;

	spin_lock_bh(&tunnel->lock);

	id = tunnel->next_context_id;

	/* Check for overflow (very unlikely) */
	if (tunnel->next_context_id > (1ULL << 62) - 2) {
		spin_unlock_bh(&tunnel->lock);
		return -ENOSPC;
	}

	/* Increment by 2 to maintain even/odd allocation */
	tunnel->next_context_id += 2;

	spin_unlock_bh(&tunnel->lock);

	*context_id = id;

	pr_debug("connect-udp: allocated context ID %llu\n", id);
	return 0;
}
EXPORT_SYMBOL_GPL(tquic_connect_udp_alloc_context_id);

/**
 * tquic_connect_udp_register_context - Register context handler
 * @tunnel: Tunnel
 * @context_id: Context ID to register
 * @handler: Handler callback
 * @context: Handler context
 *
 * Returns: 0 on success, negative errno on failure.
 */
int tquic_connect_udp_register_context(struct tquic_connect_udp_tunnel *tunnel,
				       u64 context_id,
				       int (*handler)(struct tquic_connect_udp_tunnel *,
						      u64, const u8 *, size_t, void *),
				       void *context)
{
	/*
	 * In a full implementation, this would maintain a table of
	 * context ID handlers. For now, context 0 is the only
	 * supported context (UDP payload).
	 */
	if (!tunnel || !handler)
		return -EINVAL;

	if (context_id != TQUIC_CONNECT_UDP_CONTEXT_ID) {
		/* Only context 0 is currently supported */
		pr_debug("connect-udp: context %llu registration (unsupported)\n",
			 context_id);
	}

	return 0;
}
EXPORT_SYMBOL_GPL(tquic_connect_udp_register_context);

/**
 * tquic_connect_udp_unregister_context - Unregister context handler
 * @tunnel: Tunnel
 * @context_id: Context ID to unregister
 */
void tquic_connect_udp_unregister_context(struct tquic_connect_udp_tunnel *tunnel,
					  u64 context_id)
{
	if (!tunnel)
		return;

	pr_debug("connect-udp: context %llu unregistered\n", context_id);
}
EXPORT_SYMBOL_GPL(tquic_connect_udp_unregister_context);

/**
 * tquic_connect_udp_set_recv_handler - Set receive handler
 * @tunnel: Tunnel
 * @handler: Handler callback
 * @context: Handler context
 *
 * Sets the callback function that will be invoked when datagrams are
 * received on the tunnel. The handler is called with the tunnel, context ID,
 * payload data, payload length, and user-provided context.
 */
void tquic_connect_udp_set_recv_handler(struct tquic_connect_udp_tunnel *tunnel,
					tquic_connect_udp_datagram_handler handler,
					void *context)
{
	unsigned long flags;

	if (!tunnel)
		return;

	spin_lock_irqsave(&tunnel->lock, flags);
	tunnel->recv_handler = handler;
	tunnel->recv_handler_ctx = context;
	spin_unlock_irqrestore(&tunnel->lock, flags);

	pr_debug("connect-udp: receive handler %s\n",
		 handler ? "registered" : "cleared");
}
EXPORT_SYMBOL_GPL(tquic_connect_udp_set_recv_handler);

MODULE_DESCRIPTION("TQUIC MASQUE CONNECT-UDP Protocol (RFC 9298)");
MODULE_LICENSE("GPL");
MODULE_AUTHOR("Linux Foundation");
