// SPDX-License-Identifier: GPL-2.0-only
/*
 * TQUIC: TLS 1.3 Handshake Integration
 *
 * Copyright (c) 2026 Justin Adams <spotty118@gmail.com>
 * Kernel implementation by Justin Adams <spotty118@gmail.com>
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
#include <linux/string.h>
#include <linux/completion.h>
#include <linux/jiffies.h>
#include <linux/ratelimit.h>
#include <linux/unaligned.h>
#include <net/sock.h>
#include <net/handshake.h>
#include <net/tquic.h>
#include <net/tquic/handshake.h>
#include <uapi/linux/tquic.h>

#include "protocol.h"
#include "tquic_debug.h"
#include "tquic_mib.h"
#include "tquic_token.h"
#include "tquic_retry.h"
#include "crypto/zero_rtt.h"
#include "core/early_data.h"
#include "core/transport_params.h"
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
int tquic_client_copy_psk(const struct tquic_client *client, u8 *psk);

/*
 * Forward declarations for crypto/tls.c functions
 */
#include "crypto/tls.h"
struct tquic_crypto_state *tquic_crypto_init_versioned(
	const struct tquic_cid *scid, bool is_server, u32 version);

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
	struct tquic_connection *conn;
	int ret;

	conn = tquic_sock_conn_get(tsk);
	if (!conn)
		return -EINVAL;

	/* Check if 0-RTT is enabled */
	if (!tquic_sysctl_get_zero_rtt_enabled()) {
		tquic_dbg("0-RTT disabled via sysctl\n");
		tquic_conn_put(conn);
		return -ENOENT;
	}

	/* Initialize 0-RTT state if not already done */
	if (!conn->zero_rtt_state) {
		ret = tquic_zero_rtt_init(conn);
		if (ret) {
			tquic_conn_put(conn);
			return ret;
		}
	}

	/* Attempt 0-RTT with cached ticket */
	ret = tquic_zero_rtt_attempt(conn, server_name, server_name_len);
	if (ret == 0) {
		/* Update MIB counter for 0-RTT attempt */
		TQUIC_INC_STATS(sock_net(sk), TQUIC_MIB_0RTTATTEMPTED);
		tquic_dbg("0-RTT attempt started for %.*s\n",
			 server_name_len, server_name);
	}

	tquic_conn_put(conn);
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
/*
 * tquic_validate_zero_rtt_transport_params - Validate 0-RTT transport params
 *
 * RFC 9001 Section 4.6.1: A client that receives transport parameters from
 * a server in a new handshake MUST check that the values are at least as
 * permissive as the values remembered from the session ticket. If any
 * transport parameter is reduced below the remembered value, the client
 * MUST reject 0-RTT.
 *
 * Returns: true if params are compatible, false if 0-RTT must be rejected
 */
static bool tquic_validate_zero_rtt_transport_params(
	struct tquic_connection *conn)
{
	struct tquic_zero_rtt_state_s *state = conn->zero_rtt_state;
	struct tquic_session_ticket_plaintext *saved;
	struct tquic_transport_params remembered;
	int ret;

	if (!state || !state->ticket)
		return true;	/* No saved params to check */

	saved = &state->ticket->plaintext;

	/* No saved transport params — cannot validate, reject 0-RTT */
	if (saved->transport_params_len == 0) {
		tquic_dbg("0-RTT: no saved transport params in ticket\n");
		return false;
	}

	/* Decode the remembered transport parameters from session ticket */
	ret = tquic_tp_decode(saved->transport_params,
			      saved->transport_params_len,
			      true, &remembered);
	if (ret) {
		tquic_dbg("0-RTT: failed to decode saved transport params\n");
		return false;
	}

	/*
	 * RFC 9000 Section 7.4.1: All six transport parameters that
	 * MUST NOT be reduced below the remembered values.
	 * Compare new server params against the saved session ticket params.
	 */
	if (conn->remote_params.initial_max_data <
	    remembered.initial_max_data) {
		tquic_dbg("0-RTT: server reduced initial_max_data\n");
		return false;
	}

	if (conn->remote_params.initial_max_stream_data_bidi_local <
	    remembered.initial_max_stream_data_bidi_local) {
		tquic_dbg("0-RTT: server reduced max_stream_data_bidi_local\n");
		return false;
	}

	if (conn->remote_params.initial_max_stream_data_bidi_remote <
	    remembered.initial_max_stream_data_bidi_remote) {
		tquic_dbg("0-RTT: server reduced max_stream_data_bidi_remote\n");
		return false;
	}

	if (conn->remote_params.initial_max_stream_data_uni <
	    remembered.initial_max_stream_data_uni) {
		tquic_dbg("0-RTT: server reduced max_stream_data_uni\n");
		return false;
	}

	if (conn->remote_params.initial_max_streams_bidi <
	    remembered.initial_max_streams_bidi) {
		tquic_dbg("0-RTT: server reduced max_streams_bidi\n");
		return false;
	}

	if (conn->remote_params.initial_max_streams_uni <
	    remembered.initial_max_streams_uni) {
		tquic_dbg("0-RTT: server reduced max_streams_uni\n");
		return false;
	}

	return true;
}

void tquic_handle_zero_rtt_response(struct sock *sk, bool accepted)
{
	struct tquic_sock *tsk = tquic_sk(sk);
	struct tquic_connection *conn;
	struct tquic_zero_rtt_state_s *state;

	conn = tquic_sock_conn_get(tsk);
	if (!conn || !conn->zero_rtt_state)
		goto out_put;

	state = conn->zero_rtt_state;

	if (accepted) {
		/*
		 * RFC 9001 Section 4.6.1: Validate that new transport
		 * parameters are at least as permissive as the remembered
		 * values. If the server reduced limits, we must treat 0-RTT
		 * as rejected because our early data may have exceeded
		 * the new limits.
		 */
		if (!tquic_validate_zero_rtt_transport_params(conn)) {
			tquic_dbg("0-RTT transport params incompatible, "
				 "treating as rejected\n");
			accepted = false;
			/* Fall through to rejection path below */
		}
	}

	if (accepted) {
		tquic_zero_rtt_confirmed(conn);
		TQUIC_INC_STATS(sock_net(sk), TQUIC_MIB_0RTTACCEPTED);
		tquic_dbg("0-RTT accepted by server\n");
	} else {
		/* Remove stale ticket */
		if (state->ticket) {
			tquic_zero_rtt_remove_ticket(state->ticket->server_name,
						     state->ticket->server_name_len);
		}
			tquic_zero_rtt_reject(conn);
			TQUIC_INC_STATS(sock_net(sk), TQUIC_MIB_0RTTREJECTED);
			tquic_dbg("0-RTT rejected by server\n");

			/*
			 * Trigger retransmission of 0-RTT data as 1-RTT.
		 * This calls tquic_zero_rtt_reject() and moves buffered
		 * 0-RTT packets to the 1-RTT retransmit queue.
		 */
		tquic_early_data_reject(conn);
	}

out_put:
	if (conn)
		tquic_conn_put(conn);
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

	/*
	 * CF-527: Store transport parameters for 0-RTT validation
	 * (RFC 9000 Section 7.4.1). The server's transport params are
	 * stored so the client can verify the server doesn't reduce
	 * limits when accepting 0-RTT in a future connection.
	 */
	plaintext.alpn_len = 0;
	{
		struct tquic_sock *tsk = tquic_sk(sk);
		struct tquic_connection *conn = tsk ? tquic_sock_conn_get(tsk) : NULL;

		if (conn) {
			ssize_t tp_len;

			tp_len = tquic_tp_encode(&conn->remote_params,
						 true, plaintext.transport_params,
						 sizeof(plaintext.transport_params));
			if (tp_len > 0)
				plaintext.transport_params_len = tp_len;
			else
				plaintext.transport_params_len = 0;
			tquic_conn_put(conn);
		} else {
			plaintext.transport_params_len = 0;
		}
	}

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
	struct tquic_connection *conn;

	tquic_dbg("handshake completed, status=%d peerid=%d\n",
		 status, peerid);

	hs->status = status;
	hs->peerid = peerid;

	conn = tquic_sock_conn_get(tsk);
	if (conn) {
		u64 duration_us = jiffies_to_usecs(jiffies - hs->start_time);

		tquic_trace_handshake_complete(conn, status, duration_us);
	}

	if (status == 0) {
		/*
		 * Handshake succeeded - mark connection as having
		 * completed handshake. The crypto state will be
		 * installed by the tlshd daemon via kTLS.
		 */
	tsk->flags |= TQUIC_F_HANDSHAKE_DONE;

		if (conn)
			tquic_conn_set_state(conn, TQUIC_CONN_CONNECTED,
					     TQUIC_REASON_NORMAL);

		/* Update MIB counters for successful handshake */
		TQUIC_INC_STATS(sock_net(sk), TQUIC_MIB_HANDSHAKESCOMPLETE);
		TQUIC_INC_STATS(sock_net(sk), TQUIC_MIB_CURRESTAB);

		tquic_dbg("TLS handshake successful, connection ready\n");
	} else {
		/*
		 * Handshake failed - map status to EQUIC error if needed.
		 * The tlshd daemon returns standard errno values.
		 */
		TQUIC_INC_STATS(sock_net(sk), TQUIC_MIB_HANDSHAKESFAILED);
		tquic_dbg("TLS handshake failed with status %d\n", status);
	}

	/* Wake up any thread waiting in tquic_wait_for_handshake() */
	complete(&hs->done);
	if (conn)
		tquic_conn_put(conn);
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
	struct tquic_connection *conn;
	struct tquic_handshake_state *hs;
	struct tls_handshake_args args;
	struct socket *sock;
	int ret;
	int zero_rtt_ret;

	if (!sk)
		return -EINVAL;

	conn = tquic_sock_conn_get(tsk);
	if (!conn)
		return -EINVAL;

	tquic_trace_handshake_start(conn, conn->is_server,
				    false, tsk->cert_verify.verify_mode);

	/*
	 * Test bypass: when TQUIC_VERIFY_NONE is set, skip the TLS
	 * handshake entirely. This is INSECURE and only for testing
	 * the QUIC transport layer without requiring tlshd or a
	 * real TLS handshake implementation.
	 */
	if (tsk->cert_verify.verify_mode == TQUIC_VERIFY_NONE) {
		u64 bypass_max_data;
		u64 bypass_max_streams_bidi;
		u64 bypass_max_streams_uni;

		/*
		 * In bypass mode, repeated calls should be idempotent once
		 * handshake completion is already published.
		 */
		if (tsk->flags & TQUIC_F_HANDSHAKE_DONE) {
			tquic_dbg("handshake already completed (VERIFY_NONE bypass)\n");
			tquic_conn_put(conn);
			return 0;
		}

		if (tsk->handshake_state) {
			tquic_dbg("handshake bypass already in progress\n");
			tquic_conn_put(conn);
			return -EALREADY;
		}

		tquic_warn("INSECURE bypass - skipping TLS handshake (verify_mode=NONE)\n");

		hs = kzalloc(sizeof(*hs), GFP_KERNEL);
		if (!hs) {
			tquic_conn_put(conn);
			return -ENOMEM;
		}

		hs->sk = sk;
		init_completion(&hs->done);
		hs->status = 0;
		hs->peerid = TLS_NO_PEERID;
		hs->start_time = jiffies;
		hs->timeout_ms = TQUIC_HANDSHAKE_TIMEOUT_MS;

		tsk->handshake_state = hs;
		tsk->flags |= TQUIC_F_HANDSHAKE_DONE;

		/*
		 * In bypass mode no peer transport parameters are exchanged.
		 * Seed remote send limits from local defaults so test traffic
		 * can flow while keeping bounded limits.
		 */
		bypass_max_data = conn->local_params.initial_max_data;
		if (!bypass_max_data)
			bypass_max_data = TQUIC_DEFAULT_MAX_DATA;

		bypass_max_streams_bidi =
			conn->local_params.initial_max_streams_bidi;
		if (!bypass_max_streams_bidi)
			bypass_max_streams_bidi = 100;

		bypass_max_streams_uni =
			conn->local_params.initial_max_streams_uni;
		if (!bypass_max_streams_uni)
			bypass_max_streams_uni = 100;

		spin_lock_bh(&conn->lock);
		WRITE_ONCE(conn->max_data_remote, bypass_max_data);
		WRITE_ONCE(conn->max_streams_bidi, bypass_max_streams_bidi);
		WRITE_ONCE(conn->max_streams_uni, bypass_max_streams_uni);
		conn->remote_params.initial_max_data = bypass_max_data;
		conn->remote_params.initial_max_streams_bidi =
			bypass_max_streams_bidi;
		conn->remote_params.initial_max_streams_uni =
			bypass_max_streams_uni;
		conn->remote_fc.max_data = bypass_max_data;
		conn->remote_fc.max_streams_bidi = bypass_max_streams_bidi;
		conn->remote_fc.max_streams_uni = bypass_max_streams_uni;
		spin_unlock_bh(&conn->lock);

		tquic_conn_set_state(conn, TQUIC_CONN_CONNECTED,
				     TQUIC_REASON_NORMAL);

		complete(&hs->done);

		tquic_warn("handshake bypassed, connection marked ready\n");
		tquic_conn_put(conn);
		return 0;
	}

	/* Check if handshake already in progress or completed */
	if (tsk->handshake_state) {
		tquic_dbg("handshake already in progress\n");
		tquic_conn_put(conn);
		return -EALREADY;
	}

	if (tsk->flags & TQUIC_F_HANDSHAKE_DONE) {
		tquic_dbg("handshake already completed\n");
		tquic_conn_put(conn);
		return -EISCONN;
	}

	/*
	 * Inline TLS 1.3 handshake path.
	 *
	 * When possible, perform the TLS handshake directly in-kernel
	 * using the crypto/handshake.c state machine. This avoids the
	 * round-trip to the tlshd userspace daemon and is required for
	 * proper QUIC-TLS integration where CRYPTO frames carry the
	 * handshake messages.
	 *
	 * The inline path:
	 * 1. Allocates a tquic_handshake context
	 * 2. Configures SNI, ALPN, transport params
	 * 3. Generates ClientHello into crypto_buffer[INITIAL]
	 * 4. Returns - further processing happens via CRYPTO frame rx
	 */
	{
		struct tquic_handshake *ihs;
		struct tquic_hs_transport_params tp;
		u8 *ch_buf;
		u32 ch_len = 0;
		struct sk_buff *ch_skb;

		ihs = tquic_hs_init(false);
		if (!ihs) {
			tquic_warn("inline handshake init failed, falling back to tlshd\n");
			goto tlshd_fallback;
		}

		/* Configure SNI */
		if (tsk->server_name[0] != '\0') {
			ret = tquic_hs_set_sni(ihs, tsk->server_name);
			if (ret < 0) {
				tquic_hs_cleanup(ihs);
				goto tlshd_fallback;
			}
		}

		/* Set ALPN - default to h3 for QUIC */
		{
			const char *alpn_protos[] = { "h3" };

			ret = tquic_hs_set_alpn(ihs, alpn_protos, 1);
			if (ret < 0) {
				tquic_hs_cleanup(ihs);
				goto tlshd_fallback;
			}
		}

		/* Configure local transport parameters from connection */
		memset(&tp, 0, sizeof(tp));
		tp.max_idle_timeout = conn->idle_timeout;
		tp.max_udp_payload_size = 65527;
		tp.initial_max_data = conn->max_data_local;
		tp.initial_max_stream_data_bidi_local =
			conn->local_params.initial_max_stream_data_bidi_local;
		tp.initial_max_stream_data_bidi_remote =
			conn->local_params.initial_max_stream_data_bidi_remote;
		tp.initial_max_stream_data_uni =
			conn->local_params.initial_max_stream_data_uni;
		tp.initial_max_streams_bidi = conn->max_streams_bidi;
		tp.initial_max_streams_uni = conn->max_streams_uni;
		tp.ack_delay_exponent = 3;
		tp.max_ack_delay = 25;
		tp.active_conn_id_limit = 8;
		tp.disable_active_migration = conn->migration_disabled;

		/* Set initial SCID */
		tp.initial_scid_len = conn->scid.len;
		if (conn->scid.len > 0)
			memcpy(tp.initial_scid, conn->scid.id, conn->scid.len);

		ret = tquic_hs_set_transport_params(ihs, &tp);
		if (ret < 0) {
			tquic_hs_cleanup(ihs);
			goto tlshd_fallback;
		}

		/* Generate ClientHello */
		ch_buf = kmalloc(4096, GFP_KERNEL);
		if (!ch_buf) {
			tquic_hs_cleanup(ihs);
			goto tlshd_fallback;
		}

		ret = tquic_hs_generate_client_hello(ihs, ch_buf, 4096,
						     &ch_len);
		if (ret < 0) {
			kfree(ch_buf);
			tquic_hs_cleanup(ihs);
			goto tlshd_fallback;
		}

		/*
		 * Allocate handshake tracking state BEFORE queueing the
		 * SKB.  If this allocation fails we can return cleanly
		 * without having queued an SKB that nobody will free.
		 */
			hs = kzalloc(sizeof(*hs), GFP_KERNEL);
			if (!hs) {
				kfree(ch_buf);
				tquic_hs_cleanup(ihs);
				tquic_conn_put(conn);
				return -ENOMEM;
			}

		/* Defensive cap: ch_len must fit within the 4096-byte buffer */
		if (ch_len == 0 || ch_len > 4096) {
			kfree(ch_buf);
			kfree_sensitive(hs);
			tquic_hs_cleanup(ihs);
			goto tlshd_fallback;
		}

		/* Queue ClientHello in Initial crypto buffer */
		ch_skb = alloc_skb(ch_len, GFP_KERNEL);
		if (!ch_skb) {
			kfree(ch_buf);
			kfree_sensitive(hs);
			tquic_hs_cleanup(ihs);
			goto tlshd_fallback;
		}
		skb_put_data(ch_skb, ch_buf, ch_len);
		kfree(ch_buf);

		skb_queue_tail(&conn->crypto_buffer[TQUIC_PN_SPACE_INITIAL],
			       ch_skb);

		hs->sk = sk;
		init_completion(&hs->done);
		hs->status = -ETIMEDOUT;
		hs->peerid = TLS_NO_PEERID;
		hs->start_time = jiffies;
		hs->timeout_ms = TQUIC_HANDSHAKE_TIMEOUT_MS;

		tsk->handshake_state = hs;
		tsk->inline_hs = ihs;

		tquic_dbg("inline TLS handshake initiated, ClientHello queued (%u bytes)\n",
			 ch_len);
		tquic_conn_put(conn);
		return 0;
	}

tlshd_fallback:
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
			tquic_dbg("0-RTT enabled for handshake\n");
			/* 0-RTT is possible - mark connection as able to send early data */
			tsk->flags |= TQUIC_F_ZERO_RTT_ENABLED;
		}
		/* If 0-RTT fails, continue with normal handshake */
	}

	/* Allocate handshake state */
	hs = kzalloc(sizeof(*hs), GFP_KERNEL);
	if (!hs) {
		tquic_conn_put(conn);
		return -ENOMEM;
	}

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
		tquic_dbg("tls_client_hello_x509 failed: %d\n", ret);
		goto err_free;
	}

	tquic_dbg("TLS handshake initiated\n");
	tquic_conn_put(conn);
	return 0;

err_free:
	tsk->handshake_state = NULL;
	/* CF-429: Use kfree_sensitive for key-material structs */
	kfree_sensitive(hs);
	tquic_conn_put(conn);
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
		tquic_dbg("handshake wait interrupted\n");
		tls_handshake_cancel(sk);
		return -EINTR;
	}

	if (ret == 0) {
		/* Timeout expired */
		tquic_dbg("handshake timed out after %u ms\n", timeout_ms);
		tls_handshake_cancel(sk);
		TQUIC_INC_STATS(sock_net(sk), TQUIC_MIB_HANDSHAKESTIMEOUT);
		return -EQUIC_HANDSHAKE_TIMEOUT;
	}

	/* Handshake completed - check status */
	if (hs->status != 0) {
		tquic_dbg("handshake completed with error %d\n", hs->status);
		return tquic_map_handshake_error(hs->status);
	}

	tquic_dbg("handshake completed successfully\n");
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

	/* Clean up inline handshake if present */
	if (tsk->inline_hs) {
		tquic_hs_cleanup(tsk->inline_hs);
		tsk->inline_hs = NULL;
	}

	tsk->handshake_state = NULL;

	/* CF-429: Use kfree_sensitive for key-material structs */
	kfree_sensitive(hs);

	tquic_dbg("handshake state cleaned up\n");
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
 * Inline TLS Handshake - CRYPTO Frame Processing
 * =============================================================================
 *
 * These functions implement in-kernel processing of TLS handshake messages
 * carried in QUIC CRYPTO frames. This avoids the round-trip to the tlshd
 * userspace daemon and provides proper QUIC-TLS integration.
 */

/**
 * tquic_inline_hs_abort - Abort inline handshake on error
 * @sk: Socket with inline handshake
 * @err: Error code
 *
 * Cleans up the inline handshake state and marks the handshake as failed.
 */
static void tquic_inline_hs_abort(struct sock *sk, int err)
{
	struct tquic_sock *tsk = tquic_sk(sk);

	tquic_dbg("inline handshake aborted: %d\n", err);

	if (tsk->inline_hs) {
		tquic_hs_cleanup(tsk->inline_hs);
		tsk->inline_hs = NULL;
	}

	TQUIC_INC_STATS(sock_net(sk), TQUIC_MIB_HANDSHAKESFAILED);

	if (tsk->handshake_state) {
		tsk->handshake_state->status = err;
		complete(&tsk->handshake_state->done);
	}
}

/**
 * tquic_inline_hs_apply_transport_params - Apply peer transport parameters
 * @sk: Socket with completed inline handshake
 *
 * Copies the peer's transport parameters from the TLS handshake context
 * into the QUIC connection's remote_params structure.
 */
static void tquic_inline_hs_apply_transport_params(struct sock *sk)
{
	struct tquic_sock *tsk = tquic_sk(sk);
	struct tquic_handshake *ihs = tsk->inline_hs;
	struct tquic_connection *conn;
	struct tquic_hs_transport_params peer_tp;

	if (!ihs)
		return;

	conn = tquic_sock_conn_get(tsk);
	if (!conn)
		return;

	if (tquic_hs_get_transport_params(ihs, &peer_tp) < 0)
		goto out_put;

	/* Apply peer transport parameters to connection */
	conn->remote_params.max_idle_timeout = peer_tp.max_idle_timeout;
	conn->remote_params.max_udp_payload_size = peer_tp.max_udp_payload_size;
	conn->remote_params.initial_max_data = peer_tp.initial_max_data;
	conn->remote_params.initial_max_stream_data_bidi_local =
		peer_tp.initial_max_stream_data_bidi_local;
	conn->remote_params.initial_max_stream_data_bidi_remote =
		peer_tp.initial_max_stream_data_bidi_remote;
	conn->remote_params.initial_max_stream_data_uni =
		peer_tp.initial_max_stream_data_uni;
	conn->remote_params.initial_max_streams_bidi =
		peer_tp.initial_max_streams_bidi;
	conn->remote_params.initial_max_streams_uni =
		peer_tp.initial_max_streams_uni;
	conn->remote_params.ack_delay_exponent =
		peer_tp.ack_delay_exponent;
	conn->remote_params.max_ack_delay = peer_tp.max_ack_delay;
	conn->remote_params.disable_active_migration =
		peer_tp.disable_active_migration;
	conn->remote_params.active_connection_id_limit =
		peer_tp.active_conn_id_limit;

	/* Apply flow control limits */
	conn->max_data_remote = peer_tp.initial_max_data;
	conn->max_streams_bidi = peer_tp.initial_max_streams_bidi;
	conn->max_streams_uni = peer_tp.initial_max_streams_uni;

	tquic_dbg("applied peer transport params: max_data=%llu, max_streams_bidi=%llu\n",
		 peer_tp.initial_max_data, peer_tp.initial_max_streams_bidi);

out_put:
	tquic_conn_put(conn);
}

/**
 * tquic_inline_hs_install_keys - Install QUIC keys from inline handshake
 * @sk: Socket with inline handshake
 * @level: Crypto level to install (TQUIC_CRYPTO_HANDSHAKE or APPLICATION)
 *
 * Derives QUIC packet protection keys from the TLS secrets and installs
 * them into the connection's crypto state.
 *
 * Returns: 0 on success, negative errno on error
 */
static int tquic_inline_hs_install_keys(struct sock *sk, int level)
{
	struct tquic_sock *tsk = tquic_sk(sk);
	struct tquic_handshake *ihs = tsk->inline_hs;
	struct tquic_connection *conn;
	struct tquic_crypto_state *crypto;
	u8 client_key[TLS_KEY_MAX_LEN], server_key[TLS_KEY_MAX_LEN];
	u8 client_iv[TLS_IV_MAX_LEN], server_iv[TLS_IV_MAX_LEN];
	u8 client_hp[TLS_KEY_MAX_LEN], server_hp[TLS_KEY_MAX_LEN];
	u32 ck_len, sk_len, ci_len, si_len, ch_len, sh_len;
	u8 client_secret[TLS_SECRET_MAX_LEN];
	u8 server_secret[TLS_SECRET_MAX_LEN];
	/* CF-523: Initialize with buffer sizes for bounds checking */
	u32 cs_len = sizeof(client_secret);
	u32 ss_len = sizeof(server_secret);
	int hs_level;
	int ret;

	if (!ihs)
		return -EINVAL;

	conn = tquic_sock_conn_get(tsk);
	if (!conn)
		return -EINVAL;

	/* Map TQUIC_CRYPTO_* to tquic_hs_get_quic_keys level param */
	switch (level) {
	case TQUIC_CRYPTO_HANDSHAKE:
		hs_level = 1;
		break;
	case TQUIC_CRYPTO_APPLICATION:
		hs_level = 2;
		break;
	default:
		ret = -EINVAL;
		goto out_zero;
	}

	/* Derive QUIC keys from the handshake secrets */
	ret = tquic_hs_get_quic_keys(ihs, hs_level,
				     client_key, &ck_len,
				     client_iv, &ci_len,
				     client_hp, &ch_len,
				     server_key, &sk_len,
				     server_iv, &si_len,
				     server_hp, &sh_len);
	if (ret < 0) {
		tquic_dbg("failed to derive keys for level %d: %d\n",
			 level, ret);
		goto out_zero;
	}

	/* Get secrets for crypto state installation */
	if (level == TQUIC_CRYPTO_HANDSHAKE) {
		ret = tquic_hs_get_handshake_secrets(ihs,
						     client_secret, &cs_len,
						     server_secret, &ss_len);
	} else {
		ret = tquic_hs_get_app_secrets(ihs,
					       client_secret, &cs_len,
					       server_secret, &ss_len);
	}
	if (ret < 0) {
		tquic_dbg("failed to get secrets for level %d: %d\n",
			 level, ret);
		goto out_zero;
	}

	/*
	 * Install keys into the connection's crypto state.
	 * For client: write_secret = client_secret, read_secret = server_secret
	 */
	crypto = conn->crypto_state;
	if (!crypto) {
		/* Initialize crypto state if not yet done */
		crypto = tquic_crypto_init_versioned(&conn->scid,
						     conn->is_server,
						     conn->version);
		if (!crypto) {
			ret = -ENOMEM;
			goto out_zero;
		}
		conn->crypto_state = crypto;
	}

	ret = tquic_crypto_install_keys(crypto, level,
					server_secret, ss_len,
					client_secret, cs_len);
	if (ret < 0) {
		tquic_dbg("failed to install keys for level %d: %d\n",
			 level, ret);
	}

out_zero:
	memzero_explicit(client_key, sizeof(client_key));
	memzero_explicit(server_key, sizeof(server_key));
	memzero_explicit(client_iv, sizeof(client_iv));
	memzero_explicit(server_iv, sizeof(server_iv));
	memzero_explicit(client_hp, sizeof(client_hp));
	memzero_explicit(server_hp, sizeof(server_hp));
	memzero_explicit(client_secret, sizeof(client_secret));
	memzero_explicit(server_secret, sizeof(server_secret));

	tquic_conn_put(conn);
	return ret;
}

/**
 * tquic_inline_hs_recv_crypto - Process received CRYPTO frame data
 * @sk: Socket with inline handshake in progress
 * @data: CRYPTO frame payload (TLS handshake messages)
 * @len: Length of data
 * @enc_level: Encryption level the data was received at
 *
 * Called from tquic_process_crypto_frame() when inline TLS is active.
 * Routes the TLS handshake message through the state machine, generates
 * any response messages, and installs keys as they become available.
 *
 * Returns: 0 on success, negative errno on error
 */
int tquic_inline_hs_recv_crypto(struct sock *sk, const u8 *data, u32 len,
				int enc_level)
{
	struct tquic_sock *tsk = tquic_sk(sk);
	struct tquic_handshake *ihs = tsk->inline_hs;
	struct tquic_connection *conn;
	enum tquic_hs_state prev_state;
	u8 *resp_buf = NULL;
	u32 resp_len = 0;
	struct sk_buff *resp_skb;
	int pn_space;
	int ret;

	if (!ihs)
		return -EINVAL;

	conn = tquic_sock_conn_get(tsk);
	if (!conn)
		return -EINVAL;

	prev_state = tquic_hs_get_state(ihs);

	/* Allocate buffer for response messages */
	resp_buf = kmalloc(4096, GFP_ATOMIC);
	if (!resp_buf) {
		tquic_conn_put(conn);
		return -ENOMEM;
	}

	/* Process the TLS record through the state machine */
	ret = tquic_hs_process_record(ihs, data, len,
				      resp_buf, 4096, &resp_len);
	if (ret < 0) {
		tquic_dbg("inline hs process_record failed: %d\n", ret);
		kfree(resp_buf);
		tquic_inline_hs_abort(sk, ret);
		tquic_conn_put(conn);
		return ret;
	}

	/*
	 * Install keys when the state machine transitions to a new level.
	 *
	 * After ServerHello: handshake-level keys become available
	 * After server Finished: application-level keys become available
	 */
	if (prev_state == TQUIC_HS_WAIT_SH &&
	    tquic_hs_get_state(ihs) >= TQUIC_HS_WAIT_EE) {
		/* Install handshake-level keys */
		ret = tquic_inline_hs_install_keys(sk, TQUIC_CRYPTO_HANDSHAKE);
		if (ret < 0) {
			kfree(resp_buf);
			tquic_inline_hs_abort(sk, ret);
			tquic_conn_put(conn);
			return ret;
		}
		conn->crypto_level = TQUIC_CRYPTO_HANDSHAKE;
	}

	if (tquic_hs_is_complete(ihs) && !conn->handshake_complete) {
		/* Install application-level keys */
		ret = tquic_inline_hs_install_keys(sk, TQUIC_CRYPTO_APPLICATION);
		if (ret < 0) {
			kfree(resp_buf);
			tquic_inline_hs_abort(sk, ret);
			tquic_conn_put(conn);
			return ret;
		}

		/* Apply peer transport parameters */
		tquic_inline_hs_apply_transport_params(sk);

		/* Mark handshake complete */
		conn->handshake_complete = true;
		conn->crypto_level = TQUIC_CRYPTO_APPLICATION;
		tquic_conn_set_state(conn, TQUIC_CONN_CONNECTED,
				     TQUIC_REASON_NORMAL);
		tsk->flags |= TQUIC_F_HANDSHAKE_DONE;

		TQUIC_INC_STATS(sock_net(sk), TQUIC_MIB_HANDSHAKESCOMPLETE);
		TQUIC_INC_STATS(sock_net(sk), TQUIC_MIB_CURRESTAB);

		/* Wake up waiters */
		if (tsk->handshake_state)
			complete(&tsk->handshake_state->done);

		tquic_dbg("inline TLS handshake complete\n");
	}

	/* Queue any response messages */
		if (resp_len > 0) {
		/* Defensive cap: resp_len must fit within the 4096-byte buffer */
			if (resp_len > 4096) {
				kfree(resp_buf);
				tquic_conn_put(conn);
				return -EINVAL;
			}
			resp_skb = alloc_skb(resp_len, GFP_ATOMIC);
			if (!resp_skb) {
				kfree(resp_buf);
				tquic_conn_put(conn);
				return -ENOMEM;
			}
		skb_put_data(resp_skb, resp_buf, resp_len);

		/*
		 * Response goes to the appropriate PN space:
		 * - If we're in handshake level, use HANDSHAKE space
		 * - Client Finished goes in HANDSHAKE space
		 */
		if (conn->crypto_level >= TQUIC_CRYPTO_HANDSHAKE)
			pn_space = TQUIC_PN_SPACE_HANDSHAKE;
		else
			pn_space = TQUIC_PN_SPACE_INITIAL;

		skb_queue_tail(&conn->crypto_buffer[pn_space], resp_skb);
	}

	kfree(resp_buf);
	tquic_conn_put(conn);
	return 0;
}
EXPORT_SYMBOL_GPL(tquic_inline_hs_recv_crypto);

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

/*
 * Sentinel value for conn->crypto_state indicating that crypto keys have
 * been installed by the net/handshake infrastructure and the connection is
 * ready for encrypted communication.  This is intentionally a non-NULL,
 * non-dereferenceable pointer used solely as a boolean flag.
 */
#define TQUIC_CRYPTO_STATE_SENTINEL	((void *)1)

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
	struct tquic_connection *conn;

	conn = tquic_sock_conn_get(tsk);
	if (!conn)
		return;

	/* Mark crypto as ready - keys extracted by net/handshake infrastructure */
	conn->crypto_state = TQUIC_CRYPTO_STATE_SENTINEL;
	tsk->flags |= TQUIC_F_HANDSHAKE_DONE;

	tquic_dbg("crypto state installed\n");
	tquic_conn_put(conn);
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
		tquic_dbg("Initial packet too short: %zu bytes\n", len);
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
		tquic_dbg("Not a long header packet\n");
		return -EINVAL;
	}

	/* Verify fixed bit is set (RFC 9000 Section 17.2) */
	if (!(first_byte & TQUIC_FIXED_BIT_MASK)) {
		tquic_dbg("Fixed bit not set in Initial packet\n");
		return -EINVAL;
	}

	/* Verify packet type is Initial (00) */
	pkt_type = (first_byte & TQUIC_LONG_PKT_TYPE_MASK) >> TQUIC_LONG_PKT_TYPE_SHIFT;
	if (pkt_type != TQUIC_PKT_TYPE_INITIAL) {
		tquic_dbg("Not an Initial packet, type=%u\n", pkt_type);
		return -EINVAL;
	}

	/*
	 * Parse Version (4 bytes, network byte order)
	 */
	if (offset + 4 > len) {
		tquic_dbg("Packet too short for version\n");
		return -EINVAL;
	}

	version = get_unaligned_be32(data + offset);
	offset += 4;

	/* Validate version - must be QUIC v1 or v2 */
	if (version != TQUIC_VERSION_1 && version != TQUIC_VERSION_2) {
		tquic_dbg("Unsupported QUIC version: 0x%08x\n", version);
		return -EPROTONOSUPPORT;
	}

	conn->version = version;

	/*
	 * Parse Destination Connection ID Length (1 byte)
	 * Per RFC 9000 Section 17.2: 0-20 bytes
	 */
	if (offset >= len) {
		tquic_dbg("Packet too short for DCID length\n");
		return -EINVAL;
	}

	dcid_len = data[offset++];
	if (dcid_len > TQUIC_MAX_CID_LEN) {
		tquic_dbg("DCID length exceeds maximum: %u > %u\n",
			 dcid_len, TQUIC_MAX_CID_LEN);
		return -EINVAL;
	}

	/*
	 * Parse Destination Connection ID
	 * This is what the client used to address us - becomes our SCID
	 */
	if (offset + dcid_len > len) {
		tquic_dbg("Packet too short for DCID\n");
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
		tquic_dbg("Packet too short for SCID length\n");
		return -EINVAL;
	}

	scid_len = data[offset++];
	if (scid_len > TQUIC_MAX_CID_LEN) {
		tquic_dbg("SCID length exceeds maximum: %u > %u\n",
			 scid_len, TQUIC_MAX_CID_LEN);
		return -EINVAL;
	}

	/*
	 * Parse Source Connection ID
	 * This is the client's CID - becomes our DCID (peer's CID)
	 */
	if (offset + scid_len > len) {
		tquic_dbg("Packet too short for SCID\n");
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
		tquic_dbg("Failed to parse token length: %d\n", ret);
		return -EINVAL;
	}

	/* Validate token length is reasonable */
	if (token_len > len - offset) {
		tquic_dbg("Token length exceeds remaining data: %llu > %zu\n",
			 token_len, len - offset);
		return -EINVAL;
	}

	/*
	 * Token validation for address validation (RFC 9000 Section 8.1)
	 *
	 * Tokens can come from:
	 * 1. A Retry packet (short-lived, verifies address ownership)
	 * 2. A NEW_TOKEN frame (long-lived, speeds up future connections)
	 *
	 * Token validation proves the client owns the source address,
	 * allowing the server to skip amplification limiting.
	 *
	 * Validation failure is not fatal - we just proceed without
	 * address validation credit (subject to amplification limits).
	 */
	if (token_len > 0) {
		const u8 *token_data = data + offset;
		struct tquic_path *apath;
		struct sockaddr_storage client_addr;
		struct tquic_cid original_dcid;
		int token_ret;

		tquic_dbg("Initial packet has %llu byte token\n", token_len);

		/* Get client address from path or connection */
		memset(&client_addr, 0, sizeof(client_addr));
		rcu_read_lock();
		apath = rcu_dereference(conn->active_path);
		if (apath) {
			memcpy(&client_addr, &apath->remote_addr,
			       sizeof(client_addr));
		}
		rcu_read_unlock();

		/*
		 * Attempt to validate the token. We try both Retry token
		 * validation (short lifetime, retry subsystem format) and
		 * regular NEW_TOKEN validation (long lifetime).
		 *
		 * Retry and NEW_TOKEN tokens use different formats, so Retry
		 * validation is delegated to tquic_retry_token_validate_global().
		 * Try Retry first since it is common immediately after a Retry.
		 */
		memset(&original_dcid, 0, sizeof(original_dcid));

		token_ret = tquic_retry_token_validate_global(
			token_data, (size_t)token_len,
			&client_addr,
			original_dcid.id, &original_dcid.len);

		if (token_ret == 0) {
			/*
			 * Valid retry token - address is validated.
			 * The original_dcid should match what we derive
			 * Initial keys from.
			 */
			tquic_dbg("Valid retry token, address validated\n");
			/* Mark address as validated - skip amplification limit */
			rcu_read_lock();
			apath = rcu_dereference(conn->active_path);
			if (apath)
				WRITE_ONCE(apath->state,
					   TQUIC_PATH_VALIDATED);
			rcu_read_unlock();
		} else {
			/*
			 * Try NEW_TOKEN validation (longer lifetime)
			 */
			token_ret = tquic_token_validate(
				NULL,  /* Use global server key */
				&client_addr,
				token_data, (u32)token_len,
				0,  /* Default lifetime */
				NULL);  /* No DCID for NEW_TOKEN */

			if (token_ret == 0) {
				tquic_dbg("Valid NEW_TOKEN, address validated\n");
				rcu_read_lock();
				apath = rcu_dereference(conn->active_path);
				if (apath)
					WRITE_ONCE(apath->state,
						   TQUIC_PATH_VALIDATED);
				rcu_read_unlock();
			} else {
				/*
				 * Token invalid - not fatal. The server will
				 * apply amplification limits until address
				 * is validated via PATH_CHALLENGE/RESPONSE.
				 */
				tquic_dbg("Token validation failed: %d\n",
					 token_ret);
			}
		}
	}
	offset += token_len;

	/*
	 * Parse Length (variable-length integer)
	 * This is the remaining packet length including packet number and payload
	 */
	ret = tquic_varint_read(data, len, &offset, &payload_len);
	if (ret < 0) {
		tquic_dbg("Failed to parse payload length: %d\n", ret);
		return -EINVAL;
	}

	/* Validate payload length is reasonable */
	if (payload_len > len - offset) {
		tquic_dbg("Payload length exceeds remaining data: %llu > %zu\n",
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
	tquic_conn_set_state(conn, TQUIC_CONN_CONNECTING,
			     TQUIC_REASON_NORMAL);

	tquic_dbg("Parsed Initial packet: version=0x%08x, "
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
		tquic_dbg("server handshake callback with NULL conn\n");
		return;
	}

	hs = child_tsk->handshake_state;

	if (status == 0) {
		/* Handshake successful */
		struct tquic_negotiated_params negotiated_params;
		int ret;

		tquic_install_crypto_state(child_sk);
		child_tsk->flags |= TQUIC_F_HANDSHAKE_DONE;

		/*
		 * Negotiate transport parameters (RFC 9000 Section 7.4).
		 * Server must set its local params to server defaults,
		 * then negotiate with client's received params.
		 */
		tquic_tp_set_defaults_server(&conn->local_params);

		/*
		 * Negotiate parameters between server's local and client's remote.
		 * This ensures both endpoints agree on connection limits.
		 */
		ret = tquic_tp_negotiate(&conn->local_params,
					 &conn->remote_params,
					 &negotiated_params);
		if (ret < 0) {
			tquic_warn("transport parameter negotiation failed: %d\n", ret);
			/* Continue with local defaults - best effort */
		} else {
			/*
			 * Apply negotiated parameters to the connection.
			 * This sets flow control limits, idle timeout, etc.
			 */
			ret = tquic_tp_apply(conn, &negotiated_params);
			if (ret < 0)
				tquic_warn("failed to apply negotiated params: %d\n", ret);
		}

		inet_sk_set_state(child_sk, TCP_ESTABLISHED);
		tquic_conn_set_state(conn, TQUIC_CONN_CONNECTED,
				     TQUIC_REASON_NORMAL);

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
			atomic_inc(&listen_tsk->accept_queue_len);
			spin_unlock_bh(&listener_sk->sk_lock.slock);

			/* Wake up accept() waiters */
			listener_sk->sk_data_ready(listener_sk);

			tquic_dbg("server handshake complete, child queued\n");
		} else {
			tquic_warn("server handshake done but no valid listener\n");
		}
		} else {
			/* Handshake failed - clean up child */
			tquic_dbg("server handshake failed: %d\n", status);
			inet_sk_set_state(child_sk, TCP_CLOSE);
			if (conn) {
				struct tquic_stream *dstream = NULL;
				/*
				 * Release the listener reference that was taken in
				 * tquic_server_handshake() before dropping the conn.
				 */
				if (conn->sk) {
					sock_put(conn->sk);
					conn->sk = NULL;
				}
				write_lock_bh(&child_sk->sk_callback_lock);
				if (child_tsk->conn == conn) {
					dstream = child_tsk->default_stream;
					child_tsk->default_stream = NULL;
					child_tsk->conn = NULL;
				}
				write_unlock_bh(&child_sk->sk_callback_lock);
				if (dstream)
					tquic_stream_put(dstream);
				tquic_conn_put(conn);
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
	if (atomic_read(&listen_tsk->accept_queue_len) >= listen_tsk->max_accept_queue) {
		tquic_dbg("accept queue full, refusing connection\n");
		return -ECONNREFUSED;
	}

	/* Create child socket for this connection */
	child_sk = sk_alloc(sock_net(listener_sk), listener_sk->sk_family,
			    GFP_ATOMIC, listener_sk->sk_prot, true);
	if (!child_sk) {
		tquic_dbg("failed to allocate child socket\n");
		return -ENOMEM;
	}

	sock_init_data(NULL, child_sk);
	child_tsk = tquic_sk(child_sk);

	/* Initialize accept list node */
	INIT_LIST_HEAD(&child_tsk->accept_list);
	INIT_LIST_HEAD(&child_tsk->accept_queue);
	atomic_set(&child_tsk->accept_queue_len, 0);
	child_tsk->max_accept_queue = 0;
	child_tsk->default_stream = NULL;

	/* Create connection for child (server-side) */
	conn = tquic_conn_create(child_tsk, true);
		if (!conn) {
			tquic_dbg("failed to create connection for child\n");
			sk_free(child_sk);
			return -ENOMEM;
		}
		write_lock_bh(&child_sk->sk_callback_lock);
		child_tsk->conn = conn;
		write_unlock_bh(&child_sk->sk_callback_lock);

	/*
	 * Store parent socket reference for accept queue callback.
	 * We temporarily store listener in conn->sk, will be updated on
	 * accept.  Take a reference so the listener cannot be freed while
	 * the async handshake callback still needs it.
	 */
	sock_hold(listener_sk);
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

	/* Child connections use the default path selection until bonded. */

	/* Process Initial packet to extract CIDs */
	ret = tquic_conn_server_accept_init(conn, initial_pkt);
		if (ret < 0) {
			struct tquic_stream *dstream = NULL;

			tquic_dbg("failed to process Initial packet: %d\n", ret);
			sock_put(listener_sk);
			conn->sk = NULL;
			write_lock_bh(&child_sk->sk_callback_lock);
			if (child_tsk->conn == conn) {
				dstream = child_tsk->default_stream;
				child_tsk->default_stream = NULL;
				child_tsk->conn = NULL;
			}
			write_unlock_bh(&child_sk->sk_callback_lock);
			if (dstream)
				tquic_stream_put(dstream);
			tquic_conn_put(conn);
			sk_free(child_sk);
			return ret;
		}

	/* Allocate handshake state */
		hs = kzalloc(sizeof(*hs), GFP_ATOMIC);
		if (!hs) {
			struct tquic_stream *dstream = NULL;

			sock_put(listener_sk);
			conn->sk = NULL;
			write_lock_bh(&child_sk->sk_callback_lock);
			if (child_tsk->conn == conn) {
				dstream = child_tsk->default_stream;
				child_tsk->default_stream = NULL;
				child_tsk->conn = NULL;
			}
			write_unlock_bh(&child_sk->sk_callback_lock);
			if (dstream)
				tquic_stream_put(dstream);
			tquic_conn_put(conn);
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
			struct tquic_stream *dstream = NULL;

			tquic_dbg("failed to start server handshake: %d\n", ret);
			sock_put(child_sk);
			child_tsk->handshake_state = NULL;
			kfree_sensitive(hs);
			/* Release listener ref taken above before dropping conn */
			sock_put(listener_sk);
			conn->sk = NULL;
			write_lock_bh(&child_sk->sk_callback_lock);
			if (child_tsk->conn == conn) {
				dstream = child_tsk->default_stream;
				child_tsk->default_stream = NULL;
				child_tsk->conn = NULL;
			}
			write_unlock_bh(&child_sk->sk_callback_lock);
			if (dstream)
				tquic_stream_put(dstream);
			tquic_conn_put(conn);
			sk_free(child_sk);
			return ret;
		}

	/* Handshake proceeds async; child added to accept queue on completion */
	tquic_dbg("server handshake initiated for incoming connection\n");
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
	struct tquic_connection *conn = NULL;
	struct tquic_client *client;

	if (!identity || identity_len == 0 || !psk)
		return -EINVAL;

	/* Look up client by PSK identity (returns with rcu_read_lock held) */
	client = tquic_client_lookup_by_psk(identity, identity_len);
	if (!client) {
		if (__ratelimit(&tquic_psk_reject_log)) {
			tquic_dbg("unknown PSK identity\n");
		}
		TQUIC_INC_STATS(sock_net(sk), TQUIC_MIB_HANDSHAKESFAILED);
		return -ENOENT;
	}

	/* Check rate limit before accepting connection */
	if (!tquic_client_rate_limit_check(client)) {
		if (__ratelimit(&tquic_psk_reject_log)) {
			tquic_dbg("PSK connection rate limited\n");
		}
		rcu_read_unlock();
		TQUIC_INC_STATS(sock_net(sk), TQUIC_MIB_HANDSHAKESFAILED);
		return -EQUIC_CONNECTION_REFUSED;
	}

	/* Copy PSK while client pointer is protected by RCU read lock. */
	if (tquic_client_copy_psk(client, psk)) {
		rcu_read_unlock();
		TQUIC_INC_STATS(sock_net(sk), TQUIC_MIB_HANDSHAKESFAILED);
		return -EINVAL;
	}

	/* Bind client to connection for resource tracking */
	conn = tquic_sock_conn_get(tsk);
	if (conn) {
		int ret = tquic_server_bind_client(conn, client);
		if (ret < 0) {
			tquic_warn("failed to bind client: %d\n", ret);
			/* Continue anyway - binding is for stats */
		}
		tquic_conn_put(conn);
	}

	rcu_read_unlock();

	tquic_dbg("PSK authentication successful\n");
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
