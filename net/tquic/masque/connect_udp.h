/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * TQUIC MASQUE: CONNECT-UDP Protocol Header
 *
 * Copyright (c) 2026 Justin Adams <spotty118@gmail.com>
 * Kernel implementation by Justin Adams <spotty118@gmail.com>
 *
 * This header provides CONNECT-UDP support for MASQUE (Multiplexed Application
 * Substrate over QUIC Encryption) as specified in RFC 9298.
 *
 * CONNECT-UDP establishes a UDP tunnel through an HTTP/3 proxy, allowing
 * clients to send UDP datagrams to arbitrary destinations through the proxy.
 *
 * The well-known URI template for CONNECT-UDP is:
 *   /.well-known/masque/udp/{target_host}/{target_port}/
 *
 * UDP payloads are encapsulated in HTTP Datagrams (RFC 9297) with context ID 0.
 */

#ifndef _TQUIC_MASQUE_CONNECT_UDP_H
#define _TQUIC_MASQUE_CONNECT_UDP_H

#include <linux/types.h>
#include <linux/socket.h>
#include <linux/spinlock.h>
#include <linux/timer.h>
#include <linux/workqueue.h>
#include <linux/refcount.h>
#include <net/sock.h>
#include <net/tquic.h>

/* Forward declarations */
struct tquic_connection;
struct tquic_stream;

/*
 * =============================================================================
 * CONNECT-UDP Constants (RFC 9298)
 * =============================================================================
 */

/* Well-known path template for CONNECT-UDP */
#define TQUIC_CONNECT_UDP_TEMPLATE	"/.well-known/masque/udp/%s/%u/"

/* Maximum hostname length in URI */
#define TQUIC_CONNECT_UDP_HOST_MAX	256

/* Maximum UDP payload per RFC 9298 (65535 - 8 UDP header = 65527) */
#define TQUIC_CONNECT_UDP_MAX_PAYLOAD	65527

/* Minimum idle timeout for tunnels (2 minutes = 120000 ms) */
#define TQUIC_CONNECT_UDP_IDLE_TIMEOUT	120000

/* Context ID for UDP payload (RFC 9298 Section 4) */
#define TQUIC_CONNECT_UDP_CONTEXT_ID	0

/* HTTP Datagram format version */
#define TQUIC_HTTP_DATAGRAM_FORMAT	0

/* Default socket options */
#define TQUIC_CONNECT_UDP_DF_BIT	1	/* Set Don't Fragment */

/*
 * CONNECT-UDP error codes mapped to HTTP status codes
 */
#define CONNECT_UDP_ERR_SUCCESS			200
#define CONNECT_UDP_ERR_BAD_REQUEST		400
#define CONNECT_UDP_ERR_FORBIDDEN		403
#define CONNECT_UDP_ERR_URI_TOO_LONG		414
#define CONNECT_UDP_ERR_INTERNAL_ERROR		500
#define CONNECT_UDP_ERR_BAD_GATEWAY		502
#define CONNECT_UDP_ERR_SERVICE_UNAVAILABLE	503
#define CONNECT_UDP_ERR_GATEWAY_TIMEOUT		504

/*
 * =============================================================================
 * CONNECT-UDP Data Structures
 * =============================================================================
 */

/**
 * enum tquic_connect_udp_state - Tunnel state machine
 * @CONNECT_UDP_IDLE: Initial state
 * @CONNECT_UDP_REQUESTING: CONNECT-UDP request sent, awaiting response
 * @CONNECT_UDP_ESTABLISHED: Tunnel established, data can flow
 * @CONNECT_UDP_CLOSING: Graceful shutdown initiated
 * @CONNECT_UDP_CLOSED: Tunnel closed
 * @CONNECT_UDP_ERROR: Error state
 */
enum tquic_connect_udp_state {
	CONNECT_UDP_IDLE = 0,
	CONNECT_UDP_REQUESTING,
	CONNECT_UDP_ESTABLISHED,
	CONNECT_UDP_CLOSING,
	CONNECT_UDP_CLOSED,
	CONNECT_UDP_ERROR,
};

/**
 * struct tquic_connect_udp_target - Target endpoint information
 * @host: Target hostname or IP address string
 * @port: Target UDP port
 * @addr: Resolved socket address
 * @resolved: True if address has been resolved
 *
 * Holds the target endpoint information parsed from the CONNECT-UDP request
 * or specified by the client.
 */
struct tquic_connect_udp_target {
	char host[TQUIC_CONNECT_UDP_HOST_MAX];
	u16 port;
	struct sockaddr_storage addr;
	bool resolved;
};

/**
 * struct tquic_connect_udp_stats - Per-tunnel statistics
 * @tx_datagrams: Number of datagrams sent
 * @rx_datagrams: Number of datagrams received
 * @tx_bytes: Total bytes sent (payload only)
 * @rx_bytes: Total bytes received (payload only)
 * @tx_errors: Transmission errors
 * @rx_errors: Reception errors
 * @drops: Dropped datagrams
 */
struct tquic_connect_udp_stats {
	u64 tx_datagrams;
	u64 rx_datagrams;
	u64 tx_bytes;
	u64 rx_bytes;
	u64 tx_errors;
	u64 rx_errors;
	u64 drops;
};

/**
 * struct tquic_connect_udp_tunnel - CONNECT-UDP tunnel state
 * @stream: QUIC stream for HTTP/3 request/response
 * @conn: Parent QUIC connection
 * @target: Target endpoint information
 * @udp_sock: Kernel UDP socket for proxy-to-target communication
 * @state: Current tunnel state
 *
 * Context IDs (RFC 9298 Section 4):
 * @next_context_id: Next context ID to allocate
 *   - Even context IDs are allocated by the client
 *   - Odd context IDs are allocated by the proxy
 *
 * @http_status: HTTP response status code (for client)
 * @capsule_protocol: True if Capsule-Protocol header present
 *
 * Timing:
 * @idle_timeout_ms: Idle timeout in milliseconds
 * @last_activity: Timestamp of last activity
 * @idle_timer: Timer for idle timeout
 *
 * Work queues:
 * @forward_work: Work item for data forwarding
 *
 * Statistics:
 * @stats: Per-tunnel statistics
 *
 * Synchronization:
 * @lock: Protects tunnel state
 * @refcnt: Reference counter
 *
 * Linkage:
 * @list: List node for connection's tunnel list
 * @is_server: True if this is server-side (proxy)
 *
 * Receive handler:
 * @recv_handler: Callback for received datagrams
 * @recv_handler_ctx: Context for receive handler callback
 */
struct tquic_connect_udp_tunnel {
	struct tquic_stream *stream;
	struct tquic_connection *conn;
	struct tquic_connect_udp_target target;
	struct socket *udp_sock;
	enum tquic_connect_udp_state state;

	/* Context ID management (even = client, odd = proxy) */
	u64 next_context_id;

	/* HTTP response state */
	u16 http_status;
	bool capsule_protocol;

	/* Timing */
	u32 idle_timeout_ms;
	ktime_t last_activity;
	struct timer_list idle_timer;

	/* Work queue */
	struct work_struct forward_work;

	/* Statistics */
	struct tquic_connect_udp_stats stats;

	/* Synchronization */
	spinlock_t lock;
	refcount_t refcnt;

	/* Linkage */
	struct list_head list;
	bool is_server;

	/* Receive handler callback */
	tquic_connect_udp_datagram_handler recv_handler;
	void *recv_handler_ctx;
};

/**
 * struct tquic_connect_udp_request - Parsed CONNECT-UDP request
 * @method: HTTP method (should be "CONNECT")
 * @protocol: Extended CONNECT protocol (should be "connect-udp")
 * @authority: Request authority
 * @path: Request path (URI template)
 * @host: Parsed target host
 * @port: Parsed target port
 *
 * Used by the proxy side to parse incoming CONNECT-UDP requests.
 */
struct tquic_connect_udp_request {
	const char *method;
	const char *protocol;
	const char *authority;
	const char *path;
	char host[TQUIC_CONNECT_UDP_HOST_MAX];
	u16 port;
};

/*
 * =============================================================================
 * URI Template Parsing
 * =============================================================================
 */

/**
 * tquic_connect_udp_parse_template - Parse CONNECT-UDP URI template
 * @path: Request path (e.g., "/.well-known/masque/udp/example.com/443/")
 * @host: Output buffer for parsed hostname
 * @host_len: Size of host buffer
 * @port: Output for parsed port number
 *
 * Parses the well-known CONNECT-UDP URI template to extract the target
 * host and port. The path must match the expected format.
 *
 * Returns: 0 on success, negative errno on error.
 *   -EINVAL: Invalid path format
 *   -ENOBUFS: Host buffer too small
 *   -ERANGE: Port number out of range
 */
int tquic_connect_udp_parse_template(const char *path,
				     char *host, size_t host_len,
				     u16 *port);

/**
 * tquic_connect_udp_build_path - Build CONNECT-UDP request path
 * @host: Target hostname or IP address
 * @port: Target port number
 * @buf: Output buffer for path
 * @buf_len: Size of output buffer
 *
 * Builds the well-known CONNECT-UDP URI path from host and port.
 *
 * Returns: Number of bytes written (including null terminator),
 *          or negative errno on error.
 */
int tquic_connect_udp_build_path(const char *host, u16 port,
				 char *buf, size_t buf_len);

/*
 * =============================================================================
 * Client-Side API
 * =============================================================================
 */

/**
 * tquic_connect_udp_connect - Create CONNECT-UDP tunnel (client)
 * @conn: QUIC connection to proxy
 * @host: Target hostname or IP address
 * @port: Target UDP port
 * @tunnel: Output parameter for created tunnel
 *
 * Initiates a CONNECT-UDP request to establish a UDP tunnel through the
 * proxy. The tunnel is initially in REQUESTING state and transitions to
 * ESTABLISHED upon receiving a 2xx response.
 *
 * The caller must have HTTP/3 established on the connection.
 *
 * Returns: 0 on success, negative errno on error.
 *   -EINVAL: Invalid parameters
 *   -ENOMEM: Memory allocation failed
 *   -ENOTCONN: Connection not established
 *   -EOPNOTSUPP: HTTP/3 not enabled on connection
 */
int tquic_connect_udp_connect(struct tquic_connection *conn,
			      const char *host, u16 port,
			      struct tquic_connect_udp_tunnel **tunnel);

/**
 * tquic_connect_udp_wait - Wait for tunnel establishment
 * @tunnel: Tunnel to wait on
 * @timeout_ms: Maximum wait time in milliseconds (0 = infinite)
 *
 * Blocks until the tunnel is established or an error occurs.
 *
 * Returns: 0 on success (tunnel established), negative errno on error.
 *   -ETIMEDOUT: Timeout waiting for response
 *   -ECONNREFUSED: Proxy rejected the request
 *   -EINTR: Interrupted by signal
 */
int tquic_connect_udp_wait(struct tquic_connect_udp_tunnel *tunnel,
			   u32 timeout_ms);

/*
 * =============================================================================
 * Server-Side (Proxy) API
 * =============================================================================
 */

/**
 * tquic_connect_udp_accept - Accept CONNECT-UDP request (proxy)
 * @conn: QUIC connection from client
 * @stream: HTTP/3 request stream
 * @tunnel: Output parameter for created tunnel
 *
 * Called by the proxy when receiving a CONNECT-UDP extended CONNECT request.
 * Creates a tunnel and prepares to forward UDP traffic.
 *
 * The proxy should:
 *   1. Validate the request
 *   2. Create the outbound UDP socket
 *   3. Send appropriate HTTP response
 *
 * Returns: 0 on success, negative errno on error.
 *   -EINVAL: Invalid request
 *   -ENOMEM: Memory allocation failed
 *   -EACCES: Target not allowed by policy
 */
int tquic_connect_udp_accept(struct tquic_connection *conn,
			     struct tquic_stream *stream,
			     struct tquic_connect_udp_tunnel **tunnel);

/**
 * tquic_connect_udp_respond - Send CONNECT-UDP response (proxy)
 * @tunnel: Tunnel to respond on
 * @status_code: HTTP status code (200 for success)
 *
 * Sends the HTTP response for the CONNECT-UDP request.
 * Status 200 indicates success; any other status indicates failure.
 *
 * Returns: 0 on success, negative errno on error.
 */
int tquic_connect_udp_respond(struct tquic_connect_udp_tunnel *tunnel,
			      u16 status_code);

/**
 * tquic_connect_udp_parse_request - Parse CONNECT-UDP request headers
 * @headers: QPACK-decoded headers
 * @num_headers: Number of headers
 * @request: Output parameter for parsed request
 *
 * Parses HTTP headers from a CONNECT-UDP request. Validates that:
 *   - Method is CONNECT
 *   - :protocol is "connect-udp"
 *   - Path matches the well-known template
 *
 * Returns: 0 on success, negative errno on error.
 */
int tquic_connect_udp_parse_request(const void *headers, size_t num_headers,
				    struct tquic_connect_udp_request *request);

/*
 * =============================================================================
 * Data Transfer API
 * =============================================================================
 */

/**
 * tquic_connect_udp_send - Send UDP datagram through tunnel
 * @tunnel: Tunnel to send on
 * @data: UDP payload data
 * @len: Length of payload (max TQUIC_CONNECT_UDP_MAX_PAYLOAD)
 *
 * Sends a UDP datagram through the CONNECT-UDP tunnel using HTTP Datagrams
 * with context ID 0 (RFC 9298 Section 4).
 *
 * On the client side, this sends to the proxy which forwards to the target.
 * On the proxy side, this sends the received UDP datagram to the target.
 *
 * Returns: Number of bytes sent on success, negative errno on error.
 *   -EMSGSIZE: Payload exceeds maximum size
 *   -ENOTCONN: Tunnel not established
 *   -EAGAIN: Would block (congestion/flow control)
 */
int tquic_connect_udp_send(struct tquic_connect_udp_tunnel *tunnel,
			   const u8 *data, size_t len);

/**
 * tquic_connect_udp_recv - Receive UDP datagram from tunnel
 * @tunnel: Tunnel to receive from
 * @buf: Buffer for received data
 * @len: Buffer size
 *
 * Receives a UDP datagram from the CONNECT-UDP tunnel.
 *
 * Returns: Number of bytes received on success, negative errno on error.
 *   -EAGAIN: No data available
 *   -ENOTCONN: Tunnel not established
 */
int tquic_connect_udp_recv(struct tquic_connect_udp_tunnel *tunnel,
			   u8 *buf, size_t len);

/**
 * tquic_connect_udp_sendv - Send UDP datagram with iovec
 * @tunnel: Tunnel to send on
 * @iov: I/O vector array
 * @iovcnt: Number of I/O vectors
 *
 * Vectored send for scatter-gather I/O.
 *
 * Returns: Number of bytes sent on success, negative errno on error.
 */
int tquic_connect_udp_sendv(struct tquic_connect_udp_tunnel *tunnel,
			    const struct iovec *iov, int iovcnt);

/**
 * tquic_connect_udp_poll - Check for pending data/events
 * @tunnel: Tunnel to poll
 * @events: Events to check (POLLIN, POLLOUT, etc.)
 *
 * Returns: Bitmask of ready events.
 */
__poll_t tquic_connect_udp_poll(struct tquic_connect_udp_tunnel *tunnel,
				short events);

/*
 * =============================================================================
 * Tunnel Lifecycle
 * =============================================================================
 */

/**
 * tquic_connect_udp_close - Close CONNECT-UDP tunnel
 * @tunnel: Tunnel to close
 *
 * Initiates graceful shutdown of the tunnel. The underlying stream
 * is closed and resources are released.
 */
void tquic_connect_udp_close(struct tquic_connect_udp_tunnel *tunnel);

/**
 * tquic_connect_udp_get - Increment tunnel reference count
 * @tunnel: Tunnel to reference
 */
static inline void tquic_connect_udp_get(struct tquic_connect_udp_tunnel *tunnel)
{
	if (tunnel)
		refcount_inc(&tunnel->refcnt);
}

/**
 * tquic_connect_udp_put - Decrement tunnel reference count
 * @tunnel: Tunnel to dereference
 *
 * Releases tunnel when reference count reaches zero.
 */
void tquic_connect_udp_put(struct tquic_connect_udp_tunnel *tunnel);

/*
 * =============================================================================
 * Configuration and Options
 * =============================================================================
 */

/**
 * tquic_connect_udp_set_idle_timeout - Set tunnel idle timeout
 * @tunnel: Tunnel to configure
 * @timeout_ms: Timeout in milliseconds (minimum 120000)
 *
 * Sets the idle timeout for the tunnel. Per RFC 9298, the minimum
 * timeout is 2 minutes (120000 ms).
 *
 * Returns: 0 on success, -EINVAL if timeout is too short.
 */
int tquic_connect_udp_set_idle_timeout(struct tquic_connect_udp_tunnel *tunnel,
				       u32 timeout_ms);

/**
 * tquic_connect_udp_get_stats - Get tunnel statistics
 * @tunnel: Tunnel to query
 * @stats: Output parameter for statistics
 *
 * Returns: 0 on success, negative errno on error.
 */
int tquic_connect_udp_get_stats(struct tquic_connect_udp_tunnel *tunnel,
				struct tquic_connect_udp_stats *stats);

/**
 * tquic_connect_udp_get_target - Get tunnel target information
 * @tunnel: Tunnel to query
 * @target: Output parameter for target info
 *
 * Returns: 0 on success, negative errno on error.
 */
int tquic_connect_udp_get_target(struct tquic_connect_udp_tunnel *tunnel,
				 struct tquic_connect_udp_target *target);

/*
 * =============================================================================
 * HTTP Datagram Encoding (RFC 9297)
 * =============================================================================
 */

/**
 * tquic_http_datagram_encode - Encode HTTP Datagram
 * @context_id: Context ID (use TQUIC_CONNECT_UDP_CONTEXT_ID)
 * @payload: UDP payload data
 * @payload_len: Payload length
 * @buf: Output buffer
 * @buf_len: Buffer size
 *
 * Encodes a UDP payload as an HTTP Datagram for transmission.
 * Format: Context ID (varint) || Payload
 *
 * Returns: Number of bytes written on success, negative errno on error.
 */
int tquic_http_datagram_encode(u64 context_id,
			       const u8 *payload, size_t payload_len,
			       u8 *buf, size_t buf_len);

/**
 * tquic_http_datagram_decode - Decode HTTP Datagram
 * @buf: Input buffer containing HTTP Datagram
 * @buf_len: Input buffer length
 * @context_id: Output parameter for context ID
 * @payload: Output parameter for payload pointer
 * @payload_len: Output parameter for payload length
 *
 * Decodes an HTTP Datagram to extract context ID and payload.
 *
 * Returns: Number of bytes consumed on success, negative errno on error.
 */
int tquic_http_datagram_decode(const u8 *buf, size_t buf_len,
			       u64 *context_id,
			       const u8 **payload, size_t *payload_len);

/*
 * =============================================================================
 * Extended CONNECT Protocol (RFC 8441, RFC 9220)
 * =============================================================================
 */

/* Extended CONNECT protocol identifier */
#define TQUIC_CONNECT_UDP_PROTOCOL	"connect-udp"

/**
 * struct tquic_extended_connect_request - Extended CONNECT request headers
 * @method: Must be "CONNECT"
 * @protocol: Extended protocol (e.g., "connect-udp", "connect-ip")
 * @scheme: URI scheme (e.g., "https")
 * @authority: Target authority
 * @path: Request path (URI template)
 *
 * Per RFC 9220, extended CONNECT requests include:
 *   :method = CONNECT
 *   :protocol = <extension protocol>
 *   :scheme = <scheme>
 *   :authority = <authority>
 *   :path = <path>
 */
struct tquic_extended_connect_request {
	const char *method;
	const char *protocol;
	const char *scheme;
	const char *authority;
	const char *path;
};

/**
 * tquic_extended_connect_validate - Validate extended CONNECT request
 * @req: Extended CONNECT request to validate
 * @expected_protocol: Expected protocol string
 *
 * Validates that the request is a properly formed extended CONNECT
 * with the expected protocol.
 *
 * Returns: 0 if valid, negative errno if invalid.
 */
int tquic_extended_connect_validate(const struct tquic_extended_connect_request *req,
				    const char *expected_protocol);

/*
 * =============================================================================
 * Proxy-Status Header (RFC 9209)
 * =============================================================================
 *
 * The Proxy-Status header field allows proxies to convey information about
 * their handling of a request/response. For MASQUE proxies, this is used to
 * communicate errors that occurred during tunnel establishment or operation.
 */

/* Proxy-Status error types (RFC 9209 Section 2.3) */
#define PROXY_STATUS_DNS_TIMEOUT		"dns_timeout"
#define PROXY_STATUS_DNS_ERROR			"dns_error"
#define PROXY_STATUS_DESTINATION_NOT_FOUND	"destination_not_found"
#define PROXY_STATUS_DESTINATION_UNAVAILABLE	"destination_unavailable"
#define PROXY_STATUS_DESTINATION_IP_PROHIBITED	"destination_ip_prohibited"
#define PROXY_STATUS_DESTINATION_IP_UNROUTABLE	"destination_ip_unroutable"
#define PROXY_STATUS_CONNECTION_REFUSED		"connection_refused"
#define PROXY_STATUS_CONNECTION_TERMINATED	"connection_terminated"
#define PROXY_STATUS_CONNECTION_TIMEOUT		"connection_timeout"
#define PROXY_STATUS_CONNECTION_READ_TIMEOUT	"connection_read_timeout"
#define PROXY_STATUS_CONNECTION_WRITE_TIMEOUT	"connection_write_timeout"
#define PROXY_STATUS_CONNECTION_LIMIT_REACHED	"connection_limit_reached"
#define PROXY_STATUS_TLS_PROTOCOL_ERROR		"tls_protocol_error"
#define PROXY_STATUS_TLS_CERTIFICATE_ERROR	"tls_certificate_error"
#define PROXY_STATUS_TLS_ALERT_RECEIVED		"tls_alert_received"
#define PROXY_STATUS_HTTP_REQUEST_ERROR		"http_request_error"
#define PROXY_STATUS_HTTP_REQUEST_DENIED	"http_request_denied"
#define PROXY_STATUS_HTTP_RESPONSE_INCOMPLETE	"http_response_incomplete"
#define PROXY_STATUS_HTTP_RESPONSE_HEADER_SECTION_SIZE "http_response_header_section_size"
#define PROXY_STATUS_HTTP_RESPONSE_HEADER_SIZE	"http_response_header_size"
#define PROXY_STATUS_HTTP_RESPONSE_BODY_SIZE	"http_response_body_size"
#define PROXY_STATUS_HTTP_RESPONSE_TRAILER_SECTION_SIZE "http_response_trailer_section_size"
#define PROXY_STATUS_HTTP_RESPONSE_TRAILER_SIZE	"http_response_trailer_size"
#define PROXY_STATUS_HTTP_RESPONSE_TRANSFER_CODING "http_response_transfer_coding"
#define PROXY_STATUS_HTTP_RESPONSE_CONTENT_CODING "http_response_content_coding"
#define PROXY_STATUS_HTTP_RESPONSE_TIMEOUT	"http_response_timeout"
#define PROXY_STATUS_HTTP_UPGRADE_FAILED	"http_upgrade_failed"
#define PROXY_STATUS_HTTP_PROTOCOL_ERROR	"http_protocol_error"
#define PROXY_STATUS_PROXY_INTERNAL_RESPONSE	"proxy_internal_response"
#define PROXY_STATUS_PROXY_INTERNAL_ERROR	"proxy_internal_error"
#define PROXY_STATUS_PROXY_CONFIGURATION_ERROR	"proxy_configuration_error"
#define PROXY_STATUS_PROXY_LOOP_DETECTED	"proxy_loop_detected"

/* Maximum Proxy-Status header value length */
#define PROXY_STATUS_MAX_LEN	512

/**
 * struct tquic_proxy_status - Proxy-Status header value
 * @proxy_name: Proxy identifier (e.g., hostname)
 * @error_type: Error type token (from above defines)
 * @details: Optional human-readable details
 * @next_hop: Optional next-hop information
 *
 * Represents a parsed or to-be-generated Proxy-Status header value.
 */
struct tquic_proxy_status {
	char proxy_name[64];
	const char *error_type;
	char details[256];
	char next_hop[128];
};

/**
 * tquic_proxy_status_format - Format Proxy-Status header value
 * @status: Proxy status to format
 * @buf: Output buffer
 * @len: Buffer length
 *
 * Formats the Proxy-Status structured header value according to RFC 8941.
 *
 * Returns: Length of formatted string, or negative errno on error.
 */
int tquic_proxy_status_format(const struct tquic_proxy_status *status,
			      char *buf, size_t len);

/**
 * tquic_proxy_status_parse - Parse Proxy-Status header value
 * @value: Header value string
 * @status: Output for parsed status
 *
 * Returns: 0 on success, negative errno on error.
 */
int tquic_proxy_status_parse(const char *value,
			     struct tquic_proxy_status *status);

/**
 * tquic_connect_udp_set_proxy_status - Set proxy status for error response
 * @tunnel: Tunnel
 * @error_type: Error type token
 * @details: Optional details string (may be NULL)
 *
 * Sets the proxy status to be included in an error response.
 *
 * Returns: 0 on success, negative errno on error.
 */
int tquic_connect_udp_set_proxy_status(struct tquic_connect_udp_tunnel *tunnel,
				       const char *error_type,
				       const char *details);

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
 * Allocates the next available context ID. Client allocates even IDs,
 * server allocates odd IDs.
 *
 * Returns: 0 on success, negative errno on failure.
 */
int tquic_connect_udp_alloc_context_id(struct tquic_connect_udp_tunnel *tunnel,
				       u64 *context_id);

/**
 * tquic_connect_udp_register_context - Register context handler
 * @tunnel: Tunnel
 * @context_id: Context ID to register
 * @handler: Handler callback for received datagrams
 * @context: Handler context
 *
 * Registers a handler for datagrams with the specified context ID.
 * Context ID 0 is pre-registered for UDP payload.
 *
 * Returns: 0 on success, negative errno on failure.
 */
int tquic_connect_udp_register_context(struct tquic_connect_udp_tunnel *tunnel,
				       u64 context_id,
				       int (*handler)(struct tquic_connect_udp_tunnel *,
						      u64, const u8 *, size_t, void *),
				       void *context);

/**
 * tquic_connect_udp_unregister_context - Unregister context handler
 * @tunnel: Tunnel
 * @context_id: Context ID to unregister
 */
void tquic_connect_udp_unregister_context(struct tquic_connect_udp_tunnel *tunnel,
					  u64 context_id);

/*
 * =============================================================================
 * Datagram Receive Callback
 * =============================================================================
 */

/**
 * tquic_connect_udp_datagram_handler - QUIC datagram receive callback type
 * @tunnel: Tunnel that received the datagram
 * @context_id: Context ID
 * @data: Payload data
 * @len: Payload length
 * @context: Handler context
 *
 * Returns: 0 on success, negative errno on error.
 */
typedef int (*tquic_connect_udp_datagram_handler)(
	struct tquic_connect_udp_tunnel *tunnel,
	u64 context_id,
	const u8 *data, size_t len,
	void *context);

/**
 * tquic_connect_udp_set_recv_handler - Set receive handler
 * @tunnel: Tunnel
 * @handler: Handler callback
 * @context: Handler context
 *
 * Sets the callback invoked when datagrams are received on the tunnel.
 */
void tquic_connect_udp_set_recv_handler(struct tquic_connect_udp_tunnel *tunnel,
					tquic_connect_udp_datagram_handler handler,
					void *context);

/*
 * =============================================================================
 * Module Initialization
 * =============================================================================
 */

int __init tquic_connect_udp_init(void);
void __exit tquic_connect_udp_exit(void);

#endif /* _TQUIC_MASQUE_CONNECT_UDP_H */
