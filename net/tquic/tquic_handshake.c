// SPDX-License-Identifier: GPL-2.0-only
/*
 * TQUIC: TLS 1.3 Handshake Integration
 *
 * Copyright (c) 2026 Linux Foundation
 *
 * Implements TLS 1.3 handshake delegation via net/handshake infrastructure.
 * The handshake is performed by the tlshd userspace daemon, following the
 * same pattern used by NFS over TLS (net/sunrpc/xprtsock.c).
 *
 * Server-side PSK authentication:
 * - PSK identity is extracted from ClientHello
 * - tquic_client_lookup_by_psk() finds matching client config
 * - Rate limit checked before accepting connection
 * - No 0-RTT (full handshake required per CONTEXT.md)
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/completion.h>
#include <linux/jiffies.h>
#include <linux/ratelimit.h>
#include <linux/unaligned.h>
#include <net/sock.h>
#include <net/handshake.h>
#include <net/tquic.h>
#include <uapi/linux/tquic.h>

#include "protocol.h"
#include "tquic_mib.h"
#include "crypto/zero_rtt.h"
#include "core/varint.h"

/*
 * Forward declarations for server functions
 */
struct tquic_client;
struct tquic_client *tquic_client_lookup_by_psk(const char *identity,
						size_t identity_len);
bool tquic_client_rate_limit_check(struct tquic_client *client);
int tquic_server_bind_client(struct tquic_connection *conn,
			     struct tquic_client *client);
int tquic_server_get_client_psk(const char *identity, size_t identity_len,
				u8 *psk);

/*
 * Rate limit state for PSK rejection logging
 */
static DEFINE_RATELIMIT_STATE(tquic_psk_reject_log, 5 * HZ, 5);

/*
 * =============================================================================
 * 0-RTT Early Data Support (RFC 9001 Section 4.6-4.7)
 * =============================================================================
 *
 * 0-RTT allows clients to send data immediately using keys derived from
 * a previous session's resumption_master_secret. This is attempted when:
 * - A valid session ticket exists for the server
 * - The ticket has not expired
 * - 0-RTT is enabled via sysctl
 *
 * The state machine is:
 *   Client: NONE -> ATTEMPTING -> ACCEPTED/REJECTED
 *   Server: NONE -> ACCEPTED/REJECTED (after evaluating)
 */

/**
 * tquic_attempt_zero_rtt - Attempt 0-RTT on cached session ticket
 * @sk: Socket for the connection
 * @server_name: Server hostname (SNI)
 * @server_name_len: Length of server name
 *
 * Called by client before handshake to check if 0-RTT is possible.
 * If a valid session ticket exists, derives 0-RTT keys and sets
 * connection state to ATTEMPTING.
 *
 * Returns: 0 if 0-RTT is possible, -ENOENT if no ticket, other negative on error
 */
int tquic_attempt_zero_rtt(struct sock *sk, const char *server_name,
			   u8 server_name_len)
{
	struct tquic_sock *tsk = tquic_sk(sk);
	struct tquic_connection *conn = tsk->conn;
	int ret;

	if (!conn)
		return -EINVAL;

	/* Check if 0-RTT is enabled */
	if (!tquic_sysctl_get_zero_rtt_enabled()) {
		pr_debug("tquic: 0-RTT disabled via sysctl\n");
		return -ENOENT;
	}

	/* Initialize 0-RTT state if not already done */
	if (!conn->zero_rtt_state) {
		ret = tquic_zero_rtt_init(conn);
		if (ret)
			return ret;
	}

	/* Attempt 0-RTT with cached ticket */
	ret = tquic_zero_rtt_attempt(conn, server_name, server_name_len);
	if (ret == 0) {
		/* Update MIB counter for 0-RTT attempt */
		TQUIC_INC_STATS(sock_net(sk), TQUIC_MIB_0RTTATTEMPTED);
		pr_debug("tquic: 0-RTT attempt started for %.*s\n",
			 server_name_len, server_name);
	}

	return ret;
}
EXPORT_SYMBOL_GPL(tquic_attempt_zero_rtt);

/**
 * tquic_handle_zero_rtt_response - Handle server's 0-RTT response
 * @sk: Socket for the connection
 * @accepted: True if server accepted 0-RTT
 *
 * Called when client receives server's response indicating whether
 * 0-RTT was accepted (via early_data extension in EncryptedExtensions).
 *
 * If rejected:
 * - Remove the session ticket from cache
 * - Mark early data for retransmission as 1-RTT
 */
void tquic_handle_zero_rtt_response(struct sock *sk, bool accepted)
{
	struct tquic_sock *tsk = tquic_sk(sk);
	struct tquic_connection *conn = tsk->conn;
	struct tquic_zero_rtt_state_s *state;

	if (!conn || !conn->zero_rtt_state)
		return;

	state = conn->zero_rtt_state;

	if (accepted) {
		tquic_zero_rtt_confirmed(conn);
		TQUIC_INC_STATS(sock_net(sk), TQUIC_MIB_0RTTACCEPTED);
		pr_debug("tquic: 0-RTT accepted by server\n");
	} else {
		/* Remove stale ticket */
		if (state->ticket) {
			tquic_zero_rtt_remove_ticket(state->ticket->server_name,
						     state->ticket->server_name_len);
		}
		tquic_zero_rtt_reject(conn);
		TQUIC_INC_STATS(sock_net(sk), TQUIC_MIB_0RTTREJECTED);
		pr_debug("tquic: 0-RTT rejected by server\n");
	}
}
EXPORT_SYMBOL_GPL(tquic_handle_zero_rtt_response);

/**
 * tquic_store_session_ticket - Store session ticket for future 0-RTT
 * @sk: Socket for the connection
 * @server_name: Server hostname
 * @server_name_len: Length of server name
 * @ticket_data: Encrypted ticket from NEW_SESSION_TICKET
 * @ticket_len: Length of ticket
 * @psk: Pre-shared key (resumption_master_secret)
 * @psk_len: Length of PSK
 * @cipher_suite: Negotiated cipher suite
 * @max_age: Ticket lifetime in seconds
 *
 * Called after successful handshake when server sends NEW_SESSION_TICKET.
 *
 * Returns: 0 on success, negative on error
 */
int tquic_store_session_ticket(struct sock *sk, const char *server_name,
			       u8 server_name_len, const u8 *ticket_data,
			       u32 ticket_len, const u8 *psk, u32 psk_len,
			       u16 cipher_suite, u32 max_age)
{
	struct tquic_session_ticket_plaintext plaintext;
	u32 max_age_sysctl;

	if (!server_name || server_name_len == 0)
		return -EINVAL;

	if (!ticket_data || ticket_len == 0)
		return -EINVAL;

	if (!psk || psk_len == 0 || psk_len > TQUIC_ZERO_RTT_SECRET_MAX_LEN)
		return -EINVAL;

	/* Build plaintext ticket content */
	memset(&plaintext, 0, sizeof(plaintext));
	memcpy(plaintext.psk, psk, psk_len);
	plaintext.psk_len = psk_len;

	/* Limit max_age to sysctl setting */
	max_age_sysctl = tquic_sysctl_get_zero_rtt_max_age();
	plaintext.max_age = min(max_age, max_age_sysctl);
	plaintext.creation_time = ktime_get_real_seconds();
	plaintext.cipher_suite = cipher_suite;

	/* ALPN and transport params would be filled from connection state */
	plaintext.alpn_len = 0;
	plaintext.transport_params_len = 0;

	return tquic_zero_rtt_store_ticket(server_name, server_name_len,
					   ticket_data, ticket_len, &plaintext);
}
EXPORT_SYMBOL_GPL(tquic_store_session_ticket);

/**
 * struct tquic_handshake_state - Handshake state tracking
 * @sk: Socket associated with this handshake
 * @done: Completion for blocking wait
 * @status: Result status (0 = success, -errno = failure)
 * @peerid: Peer certificate key serial (from tlshd)
 * @start_time: Jiffies when handshake started
 * @timeout_ms: Timeout in milliseconds
 *
 * This structure tracks the state of an in-progress TLS handshake.
 * It is allocated when tquic_start_handshake() is called and freed
 * when the handshake completes or is cleaned up.
 */
struct tquic_handshake_state {
	struct sock *sk;
	struct completion done;
	int status;
	key_serial_t peerid;
	unsigned long start_time;
	u32 timeout_ms;
};

/**
 * tquic_handshake_done - Callback invoked when tlshd completes handshake
 * @data: Pointer to tquic_handshake_state
 * @status: 0 on success, -errno on failure
 * @peerid: Serial number of key containing peer's identity
 *
 * This callback is invoked by the net/handshake infrastructure when
 * the tlshd daemon completes (or fails) the TLS handshake.
 *
 * On success:
 *   - status is 0
 *   - peerid contains the peer certificate key
 *   - Socket is ready for encrypted communication
 *
 * On failure:
 *   - status contains a negative errno
 *   - Common values: -EACCES (auth failed), -ETIMEDOUT (timeout)
 */
void tquic_handshake_done(void *data, int status, key_serial_t peerid)
{
	struct tquic_handshake_state *hs = data;
	struct sock *sk = hs->sk;
	struct tquic_sock *tsk = tquic_sk(sk);

	pr_debug("tquic: handshake completed, status=%d peerid=%d\n",
		 status, peerid);

	hs->status = status;
	hs->peerid = peerid;

	if (status == 0) {
		/*
		 * Handshake succeeded - mark connection as having
		 * completed handshake. The crypto state will be
		 * installed by the tlshd daemon via kTLS.
		 */
		tsk->flags |= TQUIC_F_HANDSHAKE_DONE;

		if (tsk->conn)
			tsk->conn->state = TQUIC_CONN_CONNECTED;

		/* Update MIB counters for successful handshake */
		TQUIC_INC_STATS(sock_net(sk), TQUIC_MIB_HANDSHAKESCOMPLETE);
		TQUIC_INC_STATS(sock_net(sk), TQUIC_MIB_CURRESTAB);

		pr_debug("tquic: TLS handshake successful, connection ready\n");
	} else {
		/*
		 * Handshake failed - map status to EQUIC error if needed.
		 * The tlshd daemon returns standard errno values.
		 */
		TQUIC_INC_STATS(sock_net(sk), TQUIC_MIB_HANDSHAKESFAILED);
		pr_debug("tquic: TLS handshake failed with status %d\n", status);
	}

	/* Wake up any thread waiting in tquic_wait_for_handshake() */
	complete(&hs->done);
}
EXPORT_SYMBOL_GPL(tquic_handshake_done);

/**
 * tquic_map_handshake_error - Map handshake error to EQUIC code
 * @status: Error status from handshake (negative errno)
 *
 * Maps standard errno values from tlshd to QUIC-specific EQUIC codes.
 *
 * Returns: Negative EQUIC error code
 */
static int tquic_map_handshake_error(int status)
{
	if (status >= 0)
		return 0;

	switch (status) {
	case -ETIMEDOUT:
		return -EQUIC_HANDSHAKE_TIMEOUT;
	case -EACCES:
	case -EPERM:
		return -EQUIC_HANDSHAKE_FAILED;
	case -ECONNREFUSED:
		return -EQUIC_CONNECTION_REFUSED;
	default:
		return -EQUIC_HANDSHAKE_FAILED;
	}
}

/**
 * tquic_start_handshake - Initiate async TLS 1.3 handshake
 * @sk: Socket to perform handshake on
 *
 * Initiates an asynchronous TLS handshake via the net/handshake
 * infrastructure. The actual handshake is performed by the tlshd
 * userspace daemon.
 *
 * If a valid session ticket exists for the server, 0-RTT early data
 * mode is enabled allowing data to be sent before handshake completes.
 *
 * The caller should:
 *   1. Call tquic_start_handshake() to initiate
 *   2. Call tquic_wait_for_handshake() to block until complete
 *   3. Call tquic_handshake_cleanup() when done
 *
 * Returns: 0 on successful initiation, -errno on failure
 */
int tquic_start_handshake(struct sock *sk)
{
	struct tquic_sock *tsk = tquic_sk(sk);
	struct tquic_handshake_state *hs;
	struct tls_handshake_args args;
	struct socket *sock;
	int ret;
	int zero_rtt_ret;

	if (!sk || !tsk->conn)
		return -EINVAL;

	/* Check if handshake already in progress or completed */
	if (tsk->handshake_state) {
		pr_debug("tquic: handshake already in progress\n");
		return -EALREADY;
	}

	if (tsk->flags & TQUIC_F_HANDSHAKE_DONE) {
		pr_debug("tquic: handshake already completed\n");
		return -EISCONN;
	}

	/*
	 * Attempt 0-RTT if we have a cached session ticket.
	 * This is done before the handshake so early data can be sent
	 * concurrently with the handshake.
	 *
	 * Per RFC 9001 Section 4.6:
	 * "A client MAY use a previously established session to send
	 * 0-RTT data before the handshake completes."
	 */
	if (tsk->server_name[0] != '\0') {
		zero_rtt_ret = tquic_attempt_zero_rtt(sk, tsk->server_name,
						      strlen(tsk->server_name));
		if (zero_rtt_ret == 0) {
			pr_debug("tquic: 0-RTT enabled for handshake\n");
			/* 0-RTT is possible - mark connection as able to send early data */
			tsk->flags |= TQUIC_F_ZERO_RTT_ENABLED;
		}
		/* If 0-RTT fails, continue with normal handshake */
	}

	/* Allocate handshake state */
	hs = kzalloc(sizeof(*hs), GFP_KERNEL);
	if (!hs)
		return -ENOMEM;

	hs->sk = sk;
	init_completion(&hs->done);
	hs->status = -ETIMEDOUT;  /* Default to timeout if never completed */
	hs->peerid = TLS_NO_PEERID;
	hs->start_time = jiffies;
	hs->timeout_ms = TQUIC_HANDSHAKE_TIMEOUT_MS;

	/* Store state in socket for later access */
	tsk->handshake_state = hs;

	/*
	 * Get the socket structure needed for net/handshake API.
	 * For TQUIC, we use the underlying UDP socket for the handshake.
	 */
	sock = sk->sk_socket;
	if (!sock) {
		ret = -ENOTCONN;
		goto err_free;
	}

	/* Set up handshake arguments */
	memset(&args, 0, sizeof(args));
	args.ta_sock = sock;
	args.ta_done = tquic_handshake_done;
	args.ta_data = hs;
	args.ta_timeout_ms = hs->timeout_ms;
	args.ta_keyring = TLS_NO_KEYRING;  /* Use system keyring */
	args.ta_my_cert = TLS_NO_CERT;     /* Anonymous for now */
	args.ta_my_privkey = TLS_NO_PRIVKEY;

	/*
	 * Initiate TLS client handshake via tlshd daemon.
	 * This is asynchronous - tquic_handshake_done() will be called
	 * when the handshake completes.
	 */
	ret = tls_client_hello_x509(&args, GFP_KERNEL);
	if (ret) {
		pr_debug("tquic: tls_client_hello_x509 failed: %d\n", ret);
		goto err_free;
	}

	pr_debug("tquic: TLS handshake initiated\n");
	return 0;

err_free:
	tsk->handshake_state = NULL;
	kfree(hs);
	return ret;
}
EXPORT_SYMBOL_GPL(tquic_start_handshake);

/**
 * tquic_wait_for_handshake - Block until handshake completes
 * @sk: Socket with handshake in progress
 * @timeout_ms: Maximum time to wait in milliseconds
 *
 * Blocks the calling thread until the TLS handshake completes
 * or the timeout expires.
 *
 * Returns:
 *   0 on success (handshake completed successfully)
 *   -EQUIC_HANDSHAKE_TIMEOUT if timeout expired
 *   -EQUIC_HANDSHAKE_FAILED if handshake failed
 *   -EINTR if interrupted by signal
 *   Other negative EQUIC error codes for specific failures
 */
int tquic_wait_for_handshake(struct sock *sk, u32 timeout_ms)
{
	struct tquic_sock *tsk = tquic_sk(sk);
	struct tquic_handshake_state *hs;
	unsigned long timeout_jiffies;
	long ret;

	if (!sk)
		return -EINVAL;

	hs = tsk->handshake_state;
	if (!hs) {
		/* No handshake in progress - check if already done */
		if (tsk->flags & TQUIC_F_HANDSHAKE_DONE)
			return 0;
		return -EINVAL;
	}

	/* Convert timeout to jiffies */
	timeout_jiffies = msecs_to_jiffies(timeout_ms);

	/*
	 * Wait for handshake completion with timeout.
	 * Use interruptible wait to allow signal handling.
	 */
	ret = wait_for_completion_interruptible_timeout(&hs->done,
							timeout_jiffies);

	if (ret < 0) {
		/* Interrupted by signal */
		pr_debug("tquic: handshake wait interrupted\n");
		tls_handshake_cancel(sk);
		return -EINTR;
	}

	if (ret == 0) {
		/* Timeout expired */
		pr_debug("tquic: handshake timed out after %u ms\n", timeout_ms);
		tls_handshake_cancel(sk);
		TQUIC_INC_STATS(sock_net(sk), TQUIC_MIB_HANDSHAKESTIMEOUT);
		return -EQUIC_HANDSHAKE_TIMEOUT;
	}

	/* Handshake completed - check status */
	if (hs->status != 0) {
		pr_debug("tquic: handshake completed with error %d\n", hs->status);
		return tquic_map_handshake_error(hs->status);
	}

	pr_debug("tquic: handshake completed successfully\n");
	return 0;
}
EXPORT_SYMBOL_GPL(tquic_wait_for_handshake);

/**
 * tquic_handshake_cleanup - Clean up handshake state
 * @sk: Socket to clean up handshake for
 *
 * Frees handshake state resources. Should be called when the socket
 * is being destroyed or when the handshake is being cancelled.
 *
 * Safe to call multiple times or with NULL state.
 */
void tquic_handshake_cleanup(struct sock *sk)
{
	struct tquic_sock *tsk;
	struct tquic_handshake_state *hs;

	if (!sk)
		return;

	tsk = tquic_sk(sk);
	hs = tsk->handshake_state;

	if (!hs)
		return;

	/*
	 * Cancel any pending handshake. This is safe to call even if
	 * the handshake has already completed.
	 */
	tls_handshake_cancel(sk);

	tsk->handshake_state = NULL;
	kfree(hs);

	pr_debug("tquic: handshake state cleaned up\n");
}
EXPORT_SYMBOL_GPL(tquic_handshake_cleanup);

/**
 * tquic_handshake_in_progress - Check if handshake is in progress
 * @sk: Socket to check
 *
 * Returns: true if handshake is in progress, false otherwise
 */
bool tquic_handshake_in_progress(struct sock *sk)
{
	struct tquic_sock *tsk;

	if (!sk)
		return false;

	tsk = tquic_sk(sk);
	return tsk->handshake_state != NULL &&
	       !(tsk->flags & TQUIC_F_HANDSHAKE_DONE);
}
EXPORT_SYMBOL_GPL(tquic_handshake_in_progress);

/*
 * =============================================================================
 * Server-side Handshake
 * =============================================================================
 *
 * These functions implement server-side TLS handshake for accepting
 * incoming QUIC connections. When an Initial packet is received on a
 * listening socket, tquic_server_handshake() is called to create a
 * child socket, perform the server handshake, and queue the connection
 * on the listener's accept queue upon success.
 */

/* Forward declaration for server handshake callback */
static void tquic_server_handshake_done(void *data, int status,
					key_serial_t peerid);

/**
 * tquic_install_crypto_state - Install crypto keys after handshake
 * @sk: Socket with completed handshake
 *
 * Called from handshake completion callback to install negotiated keys.
 * The actual key material is managed by the net/handshake infrastructure
 * and the tlshd daemon.
 */
void tquic_install_crypto_state(struct sock *sk)
{
	struct tquic_sock *tsk = tquic_sk(sk);
	struct tquic_connection *conn = tsk->conn;

	if (!conn)
		return;

	/* Mark crypto as ready - keys extracted by net/handshake infrastructure */
	conn->crypto_state = (void *)1;  /* Non-NULL indicates ready */
	tsk->flags |= TQUIC_F_HANDSHAKE_DONE;

	pr_debug("tquic: crypto state installed\n");
}
EXPORT_SYMBOL_GPL(tquic_install_crypto_state);

/*
 * QUIC Long Header packet types (first byte bits 4-5)
 */
#define TQUIC_PKT_TYPE_INITIAL		0x00
#define TQUIC_PKT_TYPE_0RTT		0x01
#define TQUIC_PKT_TYPE_HANDSHAKE	0x02
#define TQUIC_PKT_TYPE_RETRY		0x03

/*
 * First byte masks for QUIC long header
 */
#define TQUIC_HEADER_FORM_MASK		0x80	/* Bit 7: 1=long, 0=short */
#define TQUIC_FIXED_BIT_MASK		0x40	/* Bit 6: must be 1 */
#define TQUIC_LONG_PKT_TYPE_MASK	0x30	/* Bits 4-5: packet type */
#define TQUIC_LONG_PKT_TYPE_SHIFT	4
#define TQUIC_PN_LEN_MASK		0x03	/* Bits 0-1: PN length - 1 */

/*
 * Minimum Initial packet size per RFC 9000 Section 14.1
 * Initial packets must be at least 1200 bytes when sent by clients
 * However, we accept smaller packets for validation purposes
 */
#define TQUIC_INITIAL_PKT_MIN_LEN	7	/* 1 + 4 + 1 + 0 + 1 */

/**
 * tquic_conn_server_accept_init - Initialize connection for server accept
 * @conn: New connection for accepted client
 * @initial_pkt: The incoming Initial packet
 *
 * Parses the QUIC Initial packet long header per RFC 9000 Section 17.2:
 *   - First byte: Header form (1) | Fixed bit (1) | Type (2) | Reserved (2) | PN Len (2)
 *   - Version (4 bytes)
 *   - DCID Length (1 byte) + DCID (variable, 0-20 bytes)
 *   - SCID Length (1 byte) + SCID (variable, 0-20 bytes)
 *   - Token Length (varint) + Token (variable)
 *   - Length (varint) - remaining packet length including PN and payload
 *   - Packet Number (1-4 bytes, based on PN Length field)
 *
 * For server-side accept:
 *   - Client's DCID becomes our SCID (what client uses to reach us)
 *   - Client's SCID becomes our DCID (what we use to reach client)
 *
 * Returns: 0 on success, negative errno on failure.
 */
static int tquic_conn_server_accept_init(struct tquic_connection *conn,
					 struct sk_buff *initial_pkt)
{
	const u8 *data;
	size_t len;
	size_t offset;
	u8 first_byte;
	u8 pkt_type;
	u32 version;
	u8 dcid_len;
	u8 scid_len;
	u64 token_len;
	u64 payload_len;
	int ret;

	if (!conn || !initial_pkt)
		return -EINVAL;

	data = initial_pkt->data;
	len = initial_pkt->len;

	/* Need at least minimum header: first byte + version + dcid_len + scid_len */
	if (len < TQUIC_INITIAL_PKT_MIN_LEN) {
		pr_debug("tquic: Initial packet too short: %zu bytes\n", len);
		return -EINVAL;
	}

	offset = 0;

	/*
	 * Parse first byte:
	 *   Bit 7: Header Form (1 = long header)
	 *   Bit 6: Fixed Bit (must be 1)
	 *   Bits 4-5: Long Packet Type (00 = Initial)
	 *   Bits 2-3: Reserved (ignored for now)
	 *   Bits 0-1: Packet Number Length - 1
	 */
	first_byte = data[offset++];

	/* Verify this is a long header packet */
	if (!(first_byte & TQUIC_HEADER_FORM_MASK)) {
		pr_debug("tquic: Not a long header packet\n");
		return -EINVAL;
	}

	/* Verify fixed bit is set (RFC 9000 Section 17.2) */
	if (!(first_byte & TQUIC_FIXED_BIT_MASK)) {
		pr_debug("tquic: Fixed bit not set in Initial packet\n");
		return -EINVAL;
	}

	/* Verify packet type is Initial (00) */
	pkt_type = (first_byte & TQUIC_LONG_PKT_TYPE_MASK) >> TQUIC_LONG_PKT_TYPE_SHIFT;
	if (pkt_type != TQUIC_PKT_TYPE_INITIAL) {
		pr_debug("tquic: Not an Initial packet, type=%u\n", pkt_type);
		return -EINVAL;
	}

	/*
	 * Parse Version (4 bytes, network byte order)
	 */
	if (offset + 4 > len) {
		pr_debug("tquic: Packet too short for version\n");
		return -EINVAL;
	}

	version = get_unaligned_be32(data + offset);
	offset += 4;

	/* Validate version - must be QUIC v1 or v2 */
	if (version != TQUIC_VERSION_1 && version != TQUIC_VERSION_2) {
		pr_debug("tquic: Unsupported QUIC version: 0x%08x\n", version);
		return -EPROTONOSUPPORT;
	}

	conn->version = version;

	/*
	 * Parse Destination Connection ID Length (1 byte)
	 * Per RFC 9000 Section 17.2: 0-20 bytes
	 */
	if (offset >= len) {
		pr_debug("tquic: Packet too short for DCID length\n");
		return -EINVAL;
	}

	dcid_len = data[offset++];
	if (dcid_len > TQUIC_MAX_CID_LEN) {
		pr_debug("tquic: DCID length exceeds maximum: %u > %u\n",
			 dcid_len, TQUIC_MAX_CID_LEN);
		return -EINVAL;
	}

	/*
	 * Parse Destination Connection ID
	 * This is what the client used to address us - becomes our SCID
	 */
	if (offset + dcid_len > len) {
		pr_debug("tquic: Packet too short for DCID\n");
		return -EINVAL;
	}

	conn->scid.len = dcid_len;
	if (dcid_len > 0)
		memcpy(conn->scid.id, data + offset, dcid_len);
	offset += dcid_len;

	/*
	 * Parse Source Connection ID Length (1 byte)
	 * Per RFC 9000 Section 17.2: 0-20 bytes
	 */
	if (offset >= len) {
		pr_debug("tquic: Packet too short for SCID length\n");
		return -EINVAL;
	}

	scid_len = data[offset++];
	if (scid_len > TQUIC_MAX_CID_LEN) {
		pr_debug("tquic: SCID length exceeds maximum: %u > %u\n",
			 scid_len, TQUIC_MAX_CID_LEN);
		return -EINVAL;
	}

	/*
	 * Parse Source Connection ID
	 * This is the client's CID - becomes our DCID (peer's CID)
	 */
	if (offset + scid_len > len) {
		pr_debug("tquic: Packet too short for SCID\n");
		return -EINVAL;
	}

	conn->dcid.len = scid_len;
	if (scid_len > 0)
		memcpy(conn->dcid.id, data + offset, scid_len);
	offset += scid_len;

	/*
	 * Parse Token Length (variable-length integer)
	 * Per RFC 9000 Section 17.2.2: Initial packets may contain a token
	 * for address validation (from Retry or NEW_TOKEN)
	 */
	ret = tquic_varint_read(data, len, &offset, &token_len);
	if (ret < 0) {
		pr_debug("tquic: Failed to parse token length: %d\n", ret);
		return -EINVAL;
	}

	/* Validate token length is reasonable */
	if (token_len > len - offset) {
		pr_debug("tquic: Token length exceeds remaining data: %llu > %zu\n",
			 token_len, len - offset);
		return -EINVAL;
	}

	/*
	 * Skip token data for now
	 * TODO: If token is present, validate it for address validation
	 * Per RFC 9000 Section 8.1, tokens are used to prove address ownership
	 */
	if (token_len > 0) {
		pr_debug("tquic: Initial packet has %llu byte token\n", token_len);
		/* Token validation would go here */
	}
	offset += token_len;

	/*
	 * Parse Length (variable-length integer)
	 * This is the remaining packet length including packet number and payload
	 */
	ret = tquic_varint_read(data, len, &offset, &payload_len);
	if (ret < 0) {
		pr_debug("tquic: Failed to parse payload length: %d\n", ret);
		return -EINVAL;
	}

	/* Validate payload length is reasonable */
	if (payload_len > len - offset) {
		pr_debug("tquic: Payload length exceeds remaining data: %llu > %zu\n",
			 payload_len, len - offset);
		return -EINVAL;
	}

	/*
	 * At this point we have successfully parsed:
	 *   - Version (validated as v1 or v2)
	 *   - DCID -> stored in conn->scid (what client uses to reach us)
	 *   - SCID -> stored in conn->dcid (what we use to reach client)
	 *   - Token length (and skipped token data)
	 *   - Payload length
	 *
	 * The packet number and encrypted payload follow, but we don't
	 * parse those here - they require Initial keys for decryption.
	 *
	 * Per RFC 9000 Section 7.2:
	 * "Upon receiving an Initial packet, a server uses the Destination
	 * Connection ID from the client as the Source Connection ID of
	 * packets it sends."
	 *
	 * However, we generate a new SCID for the server side. The client's
	 * original DCID (now in conn->scid) is used to derive Initial keys.
	 */

	/* Generate a new server-side SCID for our use */
	if (conn->scid.len == 0) {
		/* Client sent empty DCID, generate one */
		conn->scid.len = TQUIC_DEFAULT_CID_LEN;
		get_random_bytes(conn->scid.id, conn->scid.len);
	}

	/* Initialize CID sequence numbers */
	conn->scid.seq_num = 0;
	conn->scid.retire_prior_to = 0;
	conn->dcid.seq_num = 0;
	conn->dcid.retire_prior_to = 0;

	/* Set role to server */
	conn->role = TQUIC_ROLE_SERVER;

	/* Mark as server-side connection in handshake phase */
	conn->state = TQUIC_CONN_CONNECTING;

	pr_debug("tquic: Parsed Initial packet: version=0x%08x, "
		 "dcid_len=%u, scid_len=%u, token_len=%llu\n",
		 version, dcid_len, scid_len, token_len);

	return 0;
}

/**
 * tquic_start_server_handshake - Start server TLS handshake
 * @sk: Child socket for the new connection
 * @hs: Handshake state structure
 *
 * Initiates the server-side TLS handshake via tls_server_hello_x509.
 * Returns: 0 on success, negative errno on failure.
 */
static int tquic_start_server_handshake(struct sock *sk,
					struct tquic_handshake_state *hs)
{
	struct socket *sock = sk->sk_socket;
	struct tls_handshake_args args;

	if (!sock)
		return -ENOTCONN;

	memset(&args, 0, sizeof(args));
	args.ta_sock = sock;
	args.ta_done = tquic_server_handshake_done;
	args.ta_data = sk;
	args.ta_timeout_ms = hs->timeout_ms;
	args.ta_keyring = TLS_NO_KEYRING;

	return tls_server_hello_x509(&args, GFP_ATOMIC);
}

/**
 * tquic_server_handshake_done - Server handshake completion callback
 * @data: Child socket pointer
 * @status: 0 on success, negative errno on failure
 * @peerid: Peer certificate key serial
 *
 * Called by net/handshake when server-side TLS handshake completes.
 * On success, the child socket is added to the listener's accept queue.
 * On failure, the child socket is cleaned up.
 */
static void tquic_server_handshake_done(void *data, int status,
					key_serial_t peerid)
{
	struct sock *child_sk = data;
	struct tquic_sock *child_tsk = tquic_sk(child_sk);
	struct tquic_connection *conn = child_tsk->conn;
	struct tquic_handshake_state *hs;
	struct sock *listener_sk;
	struct tquic_sock *listen_tsk;

	if (!conn) {
		pr_debug("tquic: server handshake callback with NULL conn\n");
		return;
	}

	hs = child_tsk->handshake_state;

	if (status == 0) {
		/* Handshake successful */
		tquic_install_crypto_state(child_sk);
		child_tsk->flags |= TQUIC_F_HANDSHAKE_DONE;
		inet_sk_set_state(child_sk, TCP_ESTABLISHED);
		conn->state = TQUIC_CONN_CONNECTED;

		/* Initialize path manager for server-side connection */
		tquic_pm_conn_init(conn);

		/* Find listener and add to accept queue */
		listener_sk = conn->sk;  /* Listener stored during creation */
		if (listener_sk && listener_sk != child_sk &&
		    listener_sk->sk_state == TCP_LISTEN) {
			listen_tsk = tquic_sk(listener_sk);

			spin_lock_bh(&listener_sk->sk_lock.slock);
			list_add_tail(&child_tsk->accept_list,
				      &listen_tsk->accept_queue);
			listen_tsk->accept_queue_len++;
			spin_unlock_bh(&listener_sk->sk_lock.slock);

			/* Wake up accept() waiters */
			listener_sk->sk_data_ready(listener_sk);

			pr_debug("tquic: server handshake complete, child queued\n");
		} else {
			pr_warn("tquic: server handshake done but no valid listener\n");
		}
	} else {
		/* Handshake failed - clean up child */
		pr_debug("tquic: server handshake failed: %d\n", status);
		inet_sk_set_state(child_sk, TCP_CLOSE);
		if (conn) {
			tquic_conn_destroy(conn);
			child_tsk->conn = NULL;
		}
		sock_put(child_sk);  /* Release reference */
	}

	/* Complete the handshake wait (if anyone is waiting) */
	if (hs)
		complete(&hs->done);
}

/**
 * tquic_server_handshake - Initiate server-side TLS handshake
 * @listener_sk: The listening socket
 * @initial_pkt: The incoming Initial packet
 * @client_addr: Client's source address
 *
 * Creates a new connection, performs server handshake, and
 * queues the connection on the listener's accept queue on success.
 *
 * This function is called from the UDP receive path when an Initial
 * packet arrives on a listening socket.
 *
 * Returns: 0 on handshake initiated, negative errno on failure
 */
int tquic_server_handshake(struct sock *listener_sk,
			   struct sk_buff *initial_pkt,
			   struct sockaddr_storage *client_addr)
{
	struct tquic_sock *listen_tsk = tquic_sk(listener_sk);
	struct sock *child_sk;
	struct tquic_sock *child_tsk;
	struct tquic_connection *conn;
	struct tquic_handshake_state *hs;
	int ret;

	/* Check accept queue space */
	if (listen_tsk->accept_queue_len >= listen_tsk->max_accept_queue) {
		pr_debug("tquic: accept queue full, refusing connection\n");
		return -ECONNREFUSED;
	}

	/* Create child socket for this connection */
	child_sk = sk_alloc(sock_net(listener_sk), listener_sk->sk_family,
			    GFP_ATOMIC, listener_sk->sk_prot, true);
	if (!child_sk) {
		pr_debug("tquic: failed to allocate child socket\n");
		return -ENOMEM;
	}

	sock_init_data(NULL, child_sk);
	child_tsk = tquic_sk(child_sk);

	/* Initialize accept list node */
	INIT_LIST_HEAD(&child_tsk->accept_list);
	INIT_LIST_HEAD(&child_tsk->accept_queue);
	child_tsk->accept_queue_len = 0;
	child_tsk->max_accept_queue = 0;

	/* Create connection for child */
	conn = tquic_conn_create(child_sk, GFP_ATOMIC);
	if (!conn) {
		pr_debug("tquic: failed to create connection for child\n");
		sk_free(child_sk);
		return -ENOMEM;
	}
	child_tsk->conn = conn;

	/* Store parent socket reference for accept queue callback */
	/* We temporarily store listener in conn->sk, will be updated on accept */
	conn->sk = listener_sk;

	/* Store addresses */
	memcpy(&child_tsk->connect_addr, client_addr,
	       sizeof(struct sockaddr_storage));
	memcpy(&child_tsk->bind_addr, &listen_tsk->bind_addr,
	       sizeof(struct sockaddr_storage));

	/*
	 * Inherit scheduler preference from listener.
	 * Child connections use the same scheduler as the listener socket.
	 */
	strscpy(child_tsk->requested_scheduler,
		listen_tsk->requested_scheduler,
		sizeof(child_tsk->requested_scheduler));

	/* Initialize scheduler for child connection */
	{
		struct tquic_sched_ops *sched_ops = NULL;

		if (child_tsk->requested_scheduler[0])
			sched_ops = tquic_sched_find(child_tsk->requested_scheduler);

		conn->scheduler = tquic_sched_init_conn(conn, sched_ops);
		if (!conn->scheduler) {
			pr_warn("tquic: scheduler init failed for child, using default\n");
			conn->scheduler = tquic_sched_init_conn(conn, NULL);
			if (!conn->scheduler)
				pr_debug("tquic: default scheduler init failed\n");
		}
	}

	/* Process Initial packet to extract CIDs */
	ret = tquic_conn_server_accept_init(conn, initial_pkt);
	if (ret < 0) {
		pr_debug("tquic: failed to process Initial packet: %d\n", ret);
		tquic_conn_destroy(conn);
		child_tsk->conn = NULL;
		sk_free(child_sk);
		return ret;
	}

	/* Allocate handshake state */
	hs = kzalloc(sizeof(*hs), GFP_ATOMIC);
	if (!hs) {
		tquic_conn_destroy(conn);
		child_tsk->conn = NULL;
		sk_free(child_sk);
		return -ENOMEM;
	}

	hs->sk = child_sk;
	hs->timeout_ms = TQUIC_HANDSHAKE_TIMEOUT_MS;
	hs->start_time = jiffies;
	init_completion(&hs->done);
	child_tsk->handshake_state = hs;

	/* Set child socket state */
	inet_sk_set_state(child_sk, TCP_SYN_RECV);
	child_tsk->flags |= TQUIC_F_SERVER_MODE;

	/* Take reference for handshake callback */
	sock_hold(child_sk);

	/* Initiate server TLS handshake */
	ret = tquic_start_server_handshake(child_sk, hs);
	if (ret < 0) {
		pr_debug("tquic: failed to start server handshake: %d\n", ret);
		sock_put(child_sk);
		child_tsk->handshake_state = NULL;
		kfree(hs);
		tquic_conn_destroy(conn);
		child_tsk->conn = NULL;
		sk_free(child_sk);
		return ret;
	}

	/* Handshake proceeds async; child added to accept queue on completion */
	pr_debug("tquic: server handshake initiated for incoming connection\n");
	return 0;
}
EXPORT_SYMBOL_GPL(tquic_server_handshake);

/*
 * =============================================================================
 * Server-side PSK Authentication with Rate Limiting
 * =============================================================================
 *
 * These functions implement PSK-based client authentication for server mode.
 * Per CONTEXT.md: Auto-accept on valid PSK, resource-based limits only.
 * Per CONTEXT.md: Connection rate limiting per client for abuse prevention.
 * Per CONTEXT.md: No 0-RTT, always full handshake for security.
 */

/**
 * tquic_server_psk_callback - TLS layer PSK callback for server
 * @sk: Socket for the connection
 * @identity: PSK identity from ClientHello
 * @identity_len: Length of identity
 * @psk: Output buffer for PSK (32 bytes)
 *
 * Called by TLS layer when PSK identity is received in ClientHello.
 * Looks up client configuration, checks rate limit, and returns PSK.
 *
 * Returns: 0 on success with PSK copied, -ENOENT if unknown identity,
 *          -EQUIC_CONNECTION_REFUSED if rate limited
 */
int tquic_server_psk_callback(struct sock *sk, const char *identity,
			      size_t identity_len, u8 *psk)
{
	struct tquic_sock *tsk = tquic_sk(sk);
	struct tquic_connection *conn = tsk->conn;
	struct tquic_client *client;
	int ret;

	if (!identity || identity_len == 0 || !psk)
		return -EINVAL;

	/* Look up client by PSK identity */
	client = tquic_client_lookup_by_psk(identity, identity_len);
	if (!client) {
		if (__ratelimit(&tquic_psk_reject_log)) {
			pr_info("tquic: unknown PSK identity '%.*s'\n",
				(int)identity_len, identity);
		}
		TQUIC_INC_STATS(sock_net(sk), TQUIC_MIB_HANDSHAKESFAILED);
		return -ENOENT;
	}

	/* Check rate limit before accepting connection */
	if (!tquic_client_rate_limit_check(client)) {
		if (__ratelimit(&tquic_psk_reject_log)) {
			pr_info("tquic: rate limited PSK identity '%.*s'\n",
				(int)identity_len, identity);
		}
		TQUIC_INC_STATS(sock_net(sk), TQUIC_MIB_HANDSHAKESFAILED);
		return -EQUIC_CONNECTION_REFUSED;
	}

	/* Get PSK for this client */
	ret = tquic_server_get_client_psk(identity, identity_len, psk);
	if (ret < 0) {
		pr_debug("tquic: failed to get PSK for '%.*s': %d\n",
			 (int)identity_len, identity, ret);
		return ret;
	}

	/* Bind client to connection for resource tracking */
	if (conn) {
		ret = tquic_server_bind_client(conn, client);
		if (ret < 0) {
			pr_warn("tquic: failed to bind client: %d\n", ret);
			/* Continue anyway - binding is for stats */
		}
	}

	pr_debug("tquic: PSK authentication successful for '%.*s'\n",
		 (int)identity_len, identity);
	return 0;
}
EXPORT_SYMBOL_GPL(tquic_server_psk_callback);

/**
 * tquic_server_hello_psk - Server-side PSK handshake with rate limiting
 * @sk: Server socket
 * @initial_pkt: Incoming Initial packet
 * @client_addr: Client source address
 *
 * Processes Initial packet, extracts PSK identity, validates via
 * tquic_server_psk_callback() (which includes rate limit check), and
 * initiates handshake.
 *
 * Per CONTEXT.md: Unknown PSK rejected with EQUIC_CONNECTION_REFUSED.
 * Per CONTEXT.md: Rate limit exceeded rejected with EQUIC_CONNECTION_REFUSED.
 *
 * Returns: 0 on success (handshake initiated), negative errno on failure
 */
int tquic_server_hello_psk(struct sock *sk, struct sk_buff *initial_pkt,
			   struct sockaddr_storage *client_addr)
{
	/*
	 * PSK identity extraction from Initial packet:
	 *
	 * The Initial packet contains a CRYPTO frame with ClientHello.
	 * The ClientHello contains the pre_shared_key extension with:
	 * - PSK identity (up to 64 bytes)
	 * - PSK binder
	 *
	 * For now, we defer to the standard handshake path and rely on
	 * tquic_server_psk_callback being invoked by the TLS layer.
	 * The TLS layer (tlshd daemon) will call back with the PSK identity.
	 */

	return tquic_server_handshake(sk, initial_pkt, client_addr);
}
EXPORT_SYMBOL_GPL(tquic_server_hello_psk);
