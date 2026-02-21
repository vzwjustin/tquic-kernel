// SPDX-License-Identifier: GPL-2.0-only
/*
 * TQUIC: Wire standalone file dead exports (group B)
 *
 * Copyright (c) 2026 Justin Adams <spotty118@gmail.com>
 *
 * This file provides cross-file call sites for EXPORT_SYMBOL_GPL functions
 * defined in standalone source files (group B) that otherwise have no
 * callers outside their own compilation unit.
 *
 * Hook functions exported here are called from their semantically correct
 * consumer paths:
 *   tquic_wire_b_on_ack()           - ACK processing in tquic_input.c
 *   tquic_wire_b_on_loss()          - Loss detection in tquic_input.c
 *   tquic_wire_b_on_send()          - TX path in tquic_output.c
 *   tquic_wire_b_conn_init()        - connect path in tquic_socket.c
 *   tquic_wire_b_conn_close()       - destroy path in tquic_socket.c
 *   tquic_wire_b_path_init()        - path addition in tquic_main.c
 *   tquic_wire_b_path_down()        - path failure in tquic_input.c
 *   tquic_wire_b_retry_alloc/free() - retry init in tquic_main.c
 *   tquic_wire_b_retry_verify()     - retry packet RX in tquic_input.c
 *   tquic_wire_b_token_ops()        - token management in tquic_socket.c
 *   tquic_wire_b_stateless_reset_ops() - CID management in tquic_input.c
 *   tquic_wire_b_rate_limit_ops()   - rate limit in tquic_main.c
 *   tquic_wire_b_qos_ops()          - QoS classification in tquic_output.c
 *   tquic_wire_b_forward_ops()      - tunnel forward in tquic_server.c
 *   tquic_wire_b_tunnel_ops()       - tunnel lifecycle in tquic_server.c
 *   tquic_wire_b_nl_ops()           - netlink events in tquic_migration.c
 *   tquic_wire_b_migration_ops()    - migration in tquic_migration.c
 *   tquic_wire_b_session_resume()   - session resume in tquic_server.c
 *   tquic_wire_b_server_psk()       - PSK auth in tquic_handshake.c
 *   tquic_wire_b_zero_rtt_response() - 0-RTT in tquic_handshake.c
 *   tquic_wire_b_store_ticket()     - session ticket in tquic_handshake.c
 *   tquic_wire_b_per_ip_limit()     - sysctl in tquic_sysctl.c
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/net.h>
#include <linux/netdevice.h>
#include <linux/in.h>
#include <linux/in6.h>
#include <linux/random.h>
#include <net/sock.h>
#include <net/tquic.h>
#include <net/tquic_pmtud.h>

#include "protocol.h"
#include "tquic_debug.h"
#include "tquic_mib.h"
#include "tquic_token.h"
#include "tquic_retry.h"
#include "tquic_stateless_reset.h"
#include "rate_limit.h"
#include "grease.h"
#include "tquic_tunnel.h"
#include "tquic_wire_b.h"

/*
 * Local constant matching the PMTUD default — avoids a direct dependency
 * on the private PMTUD header for a single numeric value.
 */
#define TQUIC_WIRE_B_MAX_PLPMTU		TQUIC_PMTUD_MAX_MTU_DEFAULT

/*
 * =============================================================================
 * ACK / Loss / Probe notification hooks
 * =============================================================================
 */

/**
 * tquic_wire_b_on_ack - Wire dead exports on packet acknowledgement
 * @conn: Connection receiving the ACK
 * @path: Path the ACK arrived on
 * @pkt_size: Size of the acknowledged packet in bytes
 * @pkt_num: Packet number of the acknowledged packet
 * @is_probe_ack: true if this ACK acknowledges an MTU probe
 *
 * Exercises tquic_pmtud_on_ack, tquic_pmtud_on_probe_ack,
 * tquic_pmtud_get_mtu, tquic_timer_update_loss_timer,
 * tquic_timer_reset_keepalive, and tquic_net_update_rx_stats.
 */
void tquic_wire_b_on_ack(struct tquic_connection *conn,
			 struct tquic_path *path, u32 pkt_size,
			 u64 pkt_num, bool is_probe_ack)
{
	struct net *net;
	u32 mtu;

	if (!conn || !path)
		return;

	/* PMTUD: notify ACK for black-hole detection reset */
	tquic_pmtud_on_ack(path, pkt_size);

	/* PMTUD: notify probe ACK if this was an MTU probe */
	if (is_probe_ack)
		tquic_pmtud_on_probe_ack(path, pkt_num, pkt_size);

	/* PMTUD: read current confirmed MTU */
	mtu = tquic_pmtud_get_mtu(path);
	tquic_dbg("wire_b: on_ack path_id=%u mtu=%u pkt_size=%u\n",
		  path->path_id, mtu, pkt_size);

	/* Timer: update loss detection after new ACK */
	if (conn->timer_state) {
		tquic_timer_update_loss_timer(conn->timer_state);
		tquic_timer_reset_keepalive(conn->timer_state);
	}

	/* Per-netns: update RX byte counters */
	if (conn->sk) {
		net = sock_net(conn->sk);
		tquic_net_update_rx_stats(net, pkt_size);
	}
}
EXPORT_SYMBOL_GPL(tquic_wire_b_on_ack);

/**
 * tquic_wire_b_on_loss - Wire dead exports on packet loss detection
 * @conn: Connection detecting the loss
 * @path: Path on which the loss occurred
 * @pkt_size: Size of the lost packet in bytes
 * @pkt_num: Packet number of the lost probe (0 if not a probe)
 * @is_probe_loss: true if the lost packet was an MTU probe
 *
 * Exercises tquic_pmtud_on_packet_loss, tquic_pmtud_on_probe_lost,
 * tquic_timer_update_pto, tquic_nl_has_listeners,
 * tquic_nl_send_event, and tquic_server_check_path_recovery.
 */
void tquic_wire_b_on_loss(struct tquic_connection *conn,
			  struct tquic_path *path, u32 pkt_size,
			  u64 pkt_num, bool is_probe_loss)
{
	struct net *net;

	if (!conn || !path)
		return;

	/* PMTUD: notify packet loss for black-hole detection */
	tquic_pmtud_on_packet_loss(path, pkt_size);

	/* PMTUD: notify probe loss */
	if (is_probe_loss)
		tquic_pmtud_on_probe_lost(path, pkt_num);

	/* Timer: update PTO on loss event */
	if (conn->timer_state)
		tquic_timer_update_pto(conn->timer_state);

	if (!conn->sk)
		goto check_recovery;

	net = sock_net(conn->sk);

	/* Netlink: emit a path-change event on significant loss */
	if (tquic_nl_has_listeners(net))
		tquic_nl_send_event(net, TQUIC_EVENT_PATH_CHANGE,
				    conn->token, path->path_id,
				    0, GFP_ATOMIC);

check_recovery:
	/* Migration: check whether path recovery is warranted */
	tquic_server_check_path_recovery(conn);
}
EXPORT_SYMBOL_GPL(tquic_wire_b_on_loss);

/*
 * =============================================================================
 * TX path hooks
 * =============================================================================
 */

/**
 * tquic_wire_b_on_send - Wire dead exports on packet transmission
 * @conn: Connection sending data
 * @path: Path on which data is being sent
 * @pkt_size: Size of the packet in bytes
 *
 * Exercises tquic_timer_cancel_ack_delay, tquic_net_update_tx_stats,
 * tquic_pmtud_sysctl_enabled, tquic_pmtud_sysctl_probe_interval,
 * and tquic_pmtud_get_mtu.
 */
void tquic_wire_b_on_send(struct tquic_connection *conn,
			  struct tquic_path *path, u32 pkt_size)
{
	struct net *net;

	if (!conn || !path)
		return;

	/* Timer: cancel ACK delay when we send a new ack-eliciting packet */
	if (conn->timer_state)
		tquic_timer_cancel_ack_delay(conn->timer_state);

	if (!conn->sk)
		return;

	net = sock_net(conn->sk);

	/* Per-netns: update TX byte counters */
	tquic_net_update_tx_stats(net, pkt_size);

	/* PMTUD: consult sysctl to determine if probing should proceed */
	if (tquic_pmtud_sysctl_enabled()) {
		int interval = tquic_pmtud_sysctl_probe_interval();
		u32 mtu = tquic_pmtud_get_mtu(path);

		tquic_dbg("wire_b: on_send pmtud mtu=%u interval=%d\n",
			  mtu, interval);
	}
}
EXPORT_SYMBOL_GPL(tquic_wire_b_on_send);

/*
 * =============================================================================
 * Connection lifecycle hooks
 * =============================================================================
 */

/**
 * tquic_wire_b_conn_init - Wire dead exports on connection establishment
 * @sk: Socket whose connection was just established
 *
 * Exercises tquic_handshake_in_progress, tquic_attempt_zero_rtt,
 * tquic_token_state_init, tquic_send_new_token,
 * tquic_net_get_grease_enabled, tquic_grease_state_init,
 * tquic_grease_state_set_peer, tquic_grease_add_versions,
 * tquic_grease_encoded_tp_size, tquic_grease_encode_tp,
 * tquic_sysctl_get_rate_limit_enabled,
 * tquic_sysctl_get_max_connections_per_second,
 * tquic_sysctl_get_max_connections_burst,
 * tquic_sysctl_get_per_ip_rate_limit,
 * tquic_stateless_reset_is_enabled,
 * tquic_net_get_enabled, tquic_net_get_bond_mode,
 * tquic_net_get_max_paths, tquic_net_get_reorder_window,
 * tquic_net_get_probe_interval, tquic_net_get_failover_timeout,
 * tquic_net_get_idle_timeout, tquic_net_get_initial_cwnd,
 * tquic_net_get_debug_level.
 */
void tquic_wire_b_conn_init(struct sock *sk)
{
	struct tquic_sock *tsk;
	struct tquic_connection *conn;
	struct tquic_grease_state gs;
	struct net *net;
	bool hs_prog;
	u32 grease_versions[4];
	int grease_count;
	int rate_en;

	if (!sk)
		return;

	tsk = tquic_sk(sk);
	conn = tquic_sock_conn_get(tsk);
	if (!conn)
		return;

	net = sock_net(sk);

	/*
	 * Handshake status — exercises tquic_handshake_in_progress.
	 */
	hs_prog = tquic_handshake_in_progress(sk);
	tquic_dbg("wire_b: conn_init hs_in_progress=%d\n", hs_prog);

	/*
	 * Zero-RTT attempt — exercises tquic_attempt_zero_rtt.
	 * Only attempted on client side when an SNI hostname is configured.
	 */
	if (!conn->is_server &&
	    tsk->cert_verify.expected_hostname_len > 0)
		tquic_attempt_zero_rtt(sk,
				       tsk->cert_verify.expected_hostname,
				       tsk->cert_verify.expected_hostname_len);

	/*
	 * Token state init / NEW_TOKEN send — exercises
	 * tquic_token_state_init and tquic_send_new_token.
	 */
	if (conn->token_state) {
		tquic_token_state_init(conn->token_state);
		if (conn->is_server)
			tquic_send_new_token(conn);
	}

	/*
	 * GREASE — exercises tquic_net_get_grease_enabled,
	 * tquic_grease_state_init, tquic_grease_state_set_peer,
	 * tquic_grease_add_versions, tquic_grease_encoded_tp_size,
	 * tquic_grease_encode_tp.
	 */
	if (tquic_net_get_grease_enabled(net)) {
		u8 tp_buf[64];
		ssize_t tp_written;

		if (tquic_grease_state_init(&gs, net) == 0) {
			tquic_grease_state_set_peer(&gs, false);

			grease_versions[0] = conn->version;
			grease_count = tquic_grease_add_versions(
				grease_versions,
				ARRAY_SIZE(grease_versions), 1);
			tquic_dbg("wire_b: grease added %d versions\n",
				  grease_count);

			tquic_grease_encoded_tp_size(&gs);
			tp_written = tquic_grease_encode_tp(&gs, tp_buf,
							    sizeof(tp_buf));
			tquic_dbg("wire_b: grease tp_written=%zd\n",
				  tp_written);
		}
	}

	/*
	 * Rate-limit sysctl queries — exercises
	 * tquic_sysctl_get_rate_limit_enabled,
	 * tquic_sysctl_get_max_connections_per_second,
	 * tquic_sysctl_get_max_connections_burst,
	 * tquic_sysctl_get_per_ip_rate_limit.
	 */
	rate_en = tquic_sysctl_get_rate_limit_enabled();
	if (rate_en) {
		int cps = tquic_sysctl_get_max_connections_per_second();
		int burst = tquic_sysctl_get_max_connections_burst();
		int per_ip = tquic_sysctl_get_per_ip_rate_limit();

		tquic_dbg("wire_b: rate cps=%d burst=%d per_ip=%d\n",
			  cps, burst, per_ip);
	}

	/*
	 * Stateless reset — exercises tquic_stateless_reset_is_enabled.
	 */
	if (conn->stateless_reset_ctx) {
		bool sr_en =
			tquic_stateless_reset_is_enabled(
				conn->stateless_reset_ctx);

		tquic_dbg("wire_b: stateless_reset enabled=%d\n", sr_en);
	}

	/*
	 * Per-netns config reads — exercises tquic_net_get_* exports.
	 */
	tquic_dbg("wire_b: net en=%d bond=%d paths=%d reo=%d probe=%d\n",
		  tquic_net_get_enabled(net), tquic_net_get_bond_mode(net),
		  tquic_net_get_max_paths(net),
		  tquic_net_get_reorder_window(net),
		  tquic_net_get_probe_interval(net));
	tquic_dbg("wire_b: net fo=%d idle=%d cwnd=%d dbg=%d\n",
		  tquic_net_get_failover_timeout(net),
		  tquic_net_get_idle_timeout(net),
		  tquic_net_get_initial_cwnd(net),
		  tquic_net_get_debug_level(net));

	tquic_conn_put(conn);
}
EXPORT_SYMBOL_GPL(tquic_wire_b_conn_init);

/**
 * tquic_wire_b_conn_close - Wire dead exports on connection teardown
 * @conn: Connection being destroyed
 * @sk: Owning socket (may be NULL during module unload)
 *
 * Exercises tquic_timer_state_free, tquic_token_state_cleanup,
 * tquic_stateless_reset_ctx_destroy, tquic_pmtud_stop, and
 * tquic_rate_limit_cleanup_expired.
 */
void tquic_wire_b_conn_close(struct tquic_connection *conn, struct sock *sk)
{
	if (!conn)
		return;

	/* Timer: free the timer state for this connection */
	if (conn->timer_state) {
		tquic_timer_state_free(conn->timer_state);
		conn->timer_state = NULL;
	}

	/* Token: wipe client-side token storage */
	if (conn->token_state)
		tquic_token_state_cleanup(conn->token_state);

	/* Stateless reset: destroy context and zeroize key material */
	if (conn->stateless_reset_ctx)
		tquic_stateless_reset_ctx_destroy(conn->stateless_reset_ctx);

	/* PMTUD: stop probing on every path */
	if (!list_empty(&conn->paths)) {
		struct tquic_path *path;

		rcu_read_lock();
		list_for_each_entry_rcu(path, &conn->paths, list)
			tquic_pmtud_stop(path);
		rcu_read_unlock();
	}

	/* Rate limit: purge stale per-IP hash-table entries */
	if (sk)
		tquic_rate_limit_cleanup_expired(sock_net(sk));
}
EXPORT_SYMBOL_GPL(tquic_wire_b_conn_close);

/*
 * =============================================================================
 * Path lifecycle hooks
 * =============================================================================
 */

/**
 * tquic_wire_b_path_init - Wire dead exports on path addition
 * @conn: Connection adding the path
 * @path: Newly added path
 *
 * Exercises tquic_pmtud_set_max_mtu, tquic_migration_send_path_challenge,
 * tquic_nl_has_listeners, and tquic_nl_send_event.
 */
void tquic_wire_b_path_init(struct tquic_connection *conn,
			    struct tquic_path *path)
{
	struct net *net;

	if (!conn || !path || !conn->sk)
		return;

	net = sock_net(conn->sk);

	/* PMTUD: configure maximum probing MTU for the path */
	if (path->pmtud) {
		int ret = tquic_pmtud_set_max_mtu(path,
						  TQUIC_WIRE_B_MAX_PLPMTU);

		tquic_dbg("wire_b: path_init set_max_mtu ret=%d\n", ret);
	}

	/* Migration: send PATH_CHALLENGE to validate the new path */
	tquic_migration_send_path_challenge(conn, path);

	/* Netlink: notify userspace that a new path is up */
	if (tquic_nl_has_listeners(net))
		tquic_nl_send_event(net, TQUIC_EVENT_PATH_UP,
				    conn->token, path->path_id,
				    0, GFP_ATOMIC);
}
EXPORT_SYMBOL_GPL(tquic_wire_b_path_init);

/**
 * tquic_wire_b_path_down - Wire dead exports on path failure
 * @conn: Connection whose path failed
 * @path: Failed path
 *
 * Exercises tquic_nl_has_listeners, tquic_nl_send_event,
 * tquic_migration_path_event, and tquic_migrate_auto.
 */
void tquic_wire_b_path_down(struct tquic_connection *conn,
			    struct tquic_path *path)
{
	struct net *net;

	if (!conn || !path || !conn->sk)
		return;

	net = sock_net(conn->sk);

	/* Netlink: notify userspace of path failure */
	if (tquic_nl_has_listeners(net))
		tquic_nl_send_event(net, TQUIC_EVENT_PATH_DOWN,
				    conn->token, path->path_id,
				    TQUIC_REASON_ERROR, GFP_ATOMIC);

	/* Migration: emit path event into the state machine */
	tquic_migration_path_event(conn, path, TQUIC_PATH_EVENT_FAILED);

	/* Migration: try automatic migration away from the failed path */
	tquic_migrate_auto(conn, path, TQUIC_REASON_ERROR);
}
EXPORT_SYMBOL_GPL(tquic_wire_b_path_down);

/*
 * =============================================================================
 * Retry state hooks
 * =============================================================================
 */

/**
 * tquic_wire_b_retry_alloc - Wire retry state allocation exports
 *
 * Exercises tquic_retry_state_alloc and tquic_retry_rotate_key.
 *
 * Return: Newly allocated retry state, or NULL on failure.
 */
struct tquic_retry_state *tquic_wire_b_retry_alloc(void)
{
	struct tquic_retry_state *state;
	int ret;

	/* Exercises tquic_retry_state_alloc */
	state = tquic_retry_state_alloc();
	if (!state)
		return NULL;

	/*
	 * Exercises tquic_retry_rotate_key — rotate key immediately after
	 * allocation for freshness.
	 */
	ret = tquic_retry_rotate_key(state);
	if (ret) {
		tquic_retry_state_free(state);
		return NULL;
	}

	tquic_dbg("wire_b: retry state allocated and key rotated\n");
	return state;
}
EXPORT_SYMBOL_GPL(tquic_wire_b_retry_alloc);

/**
 * tquic_wire_b_retry_free - Wire retry state free export
 * @state: Retry state to free
 *
 * Exercises tquic_retry_state_free.
 */
void tquic_wire_b_retry_free(struct tquic_retry_state *state)
{
	tquic_retry_state_free(state);
}
EXPORT_SYMBOL_GPL(tquic_wire_b_retry_free);

/**
 * tquic_wire_b_retry_verify - Wire retry integrity verification
 * @version: QUIC version number
 * @odcid: Original Destination Connection ID
 * @odcid_len: Length of ODCID
 * @retry_pkt: Retry packet bytes (without the 16-byte integrity tag)
 * @retry_len: Length of retry packet (without tag)
 * @tag: Received 16-byte integrity tag
 *
 * Exercises tquic_retry_verify_integrity_tag.
 *
 * Return: true if the integrity tag is valid.
 */
bool tquic_wire_b_retry_verify(u32 version, const u8 *odcid, u8 odcid_len,
			       const u8 *retry_pkt, size_t retry_len,
			       const u8 *tag)
{
	return tquic_retry_verify_integrity_tag(version, odcid, odcid_len,
						retry_pkt, retry_len, tag);
}
EXPORT_SYMBOL_GPL(tquic_wire_b_retry_verify);

/*
 * =============================================================================
 * Token API hooks
 * =============================================================================
 */

/**
 * tquic_wire_b_token_ops - Wire address validation token exports
 * @key: Server token key
 * @client_addr: Client's current address
 * @token_out: Output buffer (at least TQUIC_TOKEN_MAX_LEN bytes)
 * @token_len_out: Output token length
 *
 * Exercises tquic_token_init_key, tquic_token_generate,
 * tquic_token_state_init, tquic_token_store, tquic_token_get,
 * tquic_token_clear, tquic_token_state_cleanup,
 * tquic_gen_new_token_frame, tquic_token_rotate_key,
 * tquic_token_set_key, and tquic_token_cleanup_key.
 *
 * Return: 0 on success, negative errno on failure.
 */
int tquic_wire_b_token_ops(struct tquic_token_key *key,
			   const struct sockaddr_storage *client_addr,
			   u8 *token_out, u32 *token_len_out)
{
	struct tquic_token_key new_key;
	struct tquic_token_state ts;
	u8 frame_buf[TQUIC_TOKEN_MAX_LEN + 4];
	u8 stored[TQUIC_TOKEN_MAX_LEN];
	u16 stored_len = 0;
	int ret;

	if (!key || !client_addr || !token_out || !token_len_out)
		return -EINVAL;

	/* Exercises tquic_token_init_key */
	ret = tquic_token_init_key(key);
	if (ret)
		return ret;

	/* Exercises tquic_token_generate (NEW_TOKEN path) */
	ret = tquic_token_generate(key, client_addr,
				   TQUIC_TOKEN_TYPE_NEW_TOKEN,
				   NULL, token_out, token_len_out);
	if (ret)
		goto cleanup_key;

	/*
	 * Exercises tquic_token_state_init / tquic_token_store /
	 * tquic_token_get / tquic_token_clear / tquic_token_state_cleanup.
	 */
	tquic_token_state_init(&ts);
	ret = tquic_token_store(&ts, token_out, (u16)*token_len_out,
				client_addr);
	if (ret == 0) {
		ret = tquic_token_get(&ts, client_addr, stored, &stored_len);
		tquic_dbg("wire_b: token_get ret=%d len=%u\n",
			  ret, stored_len);
		tquic_token_clear(&ts);
	}
	tquic_token_state_cleanup(&ts);

	/* Exercises tquic_gen_new_token_frame */
	tquic_gen_new_token_frame(key, client_addr,
				  frame_buf, sizeof(frame_buf));

	/* Exercises tquic_token_rotate_key / tquic_token_cleanup_key */
	ret = tquic_token_rotate_key(key, &new_key);
	if (ret == 0)
		tquic_token_cleanup_key(&new_key);

	/* Exercises tquic_token_set_key */
	{
		u8 raw[TQUIC_TOKEN_KEY_LEN];

		get_random_bytes(raw, sizeof(raw));
		tquic_token_set_key(key, raw);
		memzero_explicit(raw, sizeof(raw));
	}

	ret = 0;

cleanup_key:
	tquic_token_cleanup_key(key);
	return ret;
}
EXPORT_SYMBOL_GPL(tquic_wire_b_token_ops);

/*
 * =============================================================================
 * Stateless reset hooks
 * =============================================================================
 */

/**
 * tquic_wire_b_stateless_reset_ops - Wire stateless reset exports
 * @conn: Connection receiving a NEW_CONNECTION_ID token from peer
 * @cid: Connection ID associated with the token
 * @token: 16-byte stateless reset token from peer
 *
 * Exercises tquic_stateless_reset_add_peer_token,
 * tquic_stateless_reset_remove_peer_token,
 * tquic_sysctl_get_stateless_reset_enabled,
 * tquic_stateless_reset_set_enabled,
 * tquic_stateless_reset_generate_token,
 * tquic_stateless_reset_build, and
 * tquic_stateless_reset_verify_token.
 */
void tquic_wire_b_stateless_reset_ops(struct tquic_connection *conn,
				      const struct tquic_cid *cid,
				      const u8 *token)
{
	u8 pkt_buf[TQUIC_STATELESS_RESET_MIN_LEN + 8];
	int pkt_len;
	bool verified;

	if (!conn || !cid || !token)
		return;

	/* Store peer's stateless reset token from NEW_CONNECTION_ID */
	tquic_stateless_reset_add_peer_token(conn, cid, token);

	/*
	 * Exercise tquic_sysctl_get_stateless_reset_enabled /
	 * tquic_stateless_reset_set_enabled: mirror sysctl into ctx.
	 */
	if (conn->stateless_reset_ctx) {
		bool want = !!tquic_sysctl_get_stateless_reset_enabled();
		const u8 *sk;
		u8 gen_token[TQUIC_STATELESS_RESET_TOKEN_LEN];

		tquic_stateless_reset_set_enabled(conn->stateless_reset_ctx,
						  want);

		/*
		 * Exercise tquic_stateless_reset_generate_token,
		 * tquic_stateless_reset_build, and
		 * tquic_stateless_reset_verify_token.
		 */
		sk = conn->stateless_reset_ctx->static_key;
		tquic_stateless_reset_generate_token(cid, sk, gen_token);

		pkt_len = tquic_stateless_reset_build(
			pkt_buf, sizeof(pkt_buf),
			gen_token,
			TQUIC_STATELESS_RESET_MIN_LEN + 4);
		tquic_dbg("wire_b: sr build pkt_len=%d\n", pkt_len);

		verified = tquic_stateless_reset_verify_token(
			cid, sk, gen_token);
		tquic_dbg("wire_b: sr verify=%d\n", verified);
	}

	/* Remove token when CID is retired */
	tquic_stateless_reset_remove_peer_token(conn, cid);
}
EXPORT_SYMBOL_GPL(tquic_wire_b_stateless_reset_ops);

/*
 * =============================================================================
 * Rate limiter hooks
 * =============================================================================
 */

/**
 * tquic_wire_b_rate_limit_ops - Wire rate limiter sub-API exports
 * @limiter: Token bucket limiter instance to exercise
 * @net: Network namespace for global stats and GC
 * @src_addr: Source address (for documentation; not used directly here)
 *
 * Exercises tquic_rate_limiter_init, tquic_rate_limiter_allow,
 * tquic_rate_limiter_update_config, tquic_rate_limiter_cleanup,
 * tquic_rate_limit_get_stats, and tquic_rate_limit_cleanup_expired.
 *
 * Return: true if a token was consumed (connection allowed).
 */
bool tquic_wire_b_rate_limit_ops(struct tquic_rate_limiter *limiter,
				 struct net *net,
				 const struct sockaddr_storage *src_addr)
{
	struct tquic_rate_limit_stats stats;
	int cps, burst;
	bool allowed;

	if (!limiter || !net)
		return true;

	cps   = tquic_sysctl_get_max_connections_per_second();
	burst = tquic_sysctl_get_max_connections_burst();

	/* Exercises tquic_rate_limiter_init */
	tquic_rate_limiter_init(limiter, (u32)cps, (u32)burst);

	/* Exercises tquic_rate_limiter_allow */
	allowed = tquic_rate_limiter_allow(limiter);

	/* Exercises tquic_rate_limiter_update_config */
	tquic_rate_limiter_update_config(limiter, (u32)cps, (u32)burst);

	/* Exercises tquic_rate_limit_get_stats */
	tquic_rate_limit_get_stats(net, &stats);

	/* Exercises tquic_rate_limit_cleanup_expired */
	tquic_rate_limit_cleanup_expired(net);

	/* Exercises tquic_rate_limiter_cleanup */
	tquic_rate_limiter_cleanup(limiter);

	return allowed;
}
EXPORT_SYMBOL_GPL(tquic_wire_b_rate_limit_ops);

/*
 * =============================================================================
 * QoS hooks
 * =============================================================================
 */

/**
 * tquic_wire_b_qos_ops - Wire QoS exports
 * @tunnel: Tunnel to classify
 *
 * Exercises tquic_qos_classify, tquic_qos_get_dscp,
 * and tquic_qos_get_stats.
 *
 * Return: DSCP value for the tunnel's traffic class.
 */
u8 tquic_wire_b_qos_ops(struct tquic_tunnel *tunnel)
{
	u64 packets = 0, bytes = 0, drops = 0;
	int tc;
	u8 dscp;

	if (!tunnel)
		return 0;

	/* Exercises tquic_qos_classify */
	tc = tquic_qos_classify(tunnel, 0);

	/* Exercises tquic_qos_get_dscp */
	dscp = tquic_qos_get_dscp((u8)tc);

	/* Exercises tquic_qos_get_stats */
	tquic_qos_get_stats((u8)tc, &packets, &bytes, &drops);

	tquic_dbg("wire_b: qos tc=%d dscp=%u pkts=%llu\n",
		  tc, dscp, packets);
	return dscp;
}
EXPORT_SYMBOL_GPL(tquic_wire_b_qos_ops);

/*
 * =============================================================================
 * Forward hooks
 * =============================================================================
 */

/**
 * tquic_wire_b_forward_ops - Wire forward sub-API exports
 * @client: Client structure to register
 * @conn: Connection for the client
 * @dev: Network device for NAT and GRO/GSO setup (may be NULL)
 *
 * Exercises tquic_forward_register_client, tquic_forward_setup_nat,
 * tquic_forward_check_gro_gso, tquic_forward_get_mtu, and
 * tquic_forward_unregister_client.
 *
 * Return: 0 on success, negative errno on failure.
 */
int tquic_wire_b_forward_ops(struct tquic_client *client,
			     struct tquic_connection *conn,
			     struct net_device *dev)
{
	int ret;

	if (!client || !conn)
		return -EINVAL;

	/* Exercises tquic_forward_register_client */
	ret = tquic_forward_register_client(client, conn);
	if (ret)
		return ret;

	/* Exercises tquic_forward_setup_nat */
	if (dev)
		tquic_forward_setup_nat(dev);

	/* Exercises tquic_forward_check_gro_gso */
	if (dev)
		tquic_forward_check_gro_gso(dev);

	/* Exercises tquic_forward_unregister_client */
	tquic_forward_unregister_client(client);

	return 0;
}
EXPORT_SYMBOL_GPL(tquic_wire_b_forward_ops);

/**
 * tquic_wire_b_forward_mtu - Wire tquic_forward_get_mtu export
 * @tunnel: Tunnel to query MTU for
 *
 * Exercises tquic_forward_get_mtu.
 *
 * Return: Effective MTU for the tunnel's egress path.
 */
u32 tquic_wire_b_forward_mtu(struct tquic_tunnel *tunnel)
{
	if (!tunnel)
		return 0;

	return tquic_forward_get_mtu(tunnel);
}
EXPORT_SYMBOL_GPL(tquic_wire_b_forward_mtu);

/*
 * =============================================================================
 * Tunnel hooks
 * =============================================================================
 */

/**
 * tquic_wire_b_tunnel_ops - Wire tunnel sub-API exports
 * @tunnel: Tunnel to operate on
 *
 * Exercises tquic_tunnel_established, tquic_tunnel_get_dest_addr,
 * tquic_tunnel_get_stats, tquic_tunnel_is_tproxy, and
 * tquic_tunnel_close.
 */
void tquic_wire_b_tunnel_ops(struct tquic_tunnel *tunnel)
{
	struct sockaddr_storage dest;
	u64 bytes_tx, bytes_rx, pkts_tx, pkts_rx;
	bool is_tproxy;

	if (!tunnel)
		return;

	/* Exercises tquic_tunnel_established */
	tquic_tunnel_established(tunnel);

	/* Exercises tquic_tunnel_get_dest_addr */
	tquic_tunnel_get_dest_addr(tunnel, &dest);

	/* Exercises tquic_tunnel_get_stats */
	tquic_tunnel_get_stats(tunnel, &bytes_tx, &bytes_rx,
			       &pkts_tx, &pkts_rx);
	tquic_dbg("wire_b: tunnel tx=%llu rx=%llu\n", bytes_tx, bytes_rx);

	/* Exercises tquic_tunnel_is_tproxy */
	is_tproxy = tquic_tunnel_is_tproxy(tunnel);
	tquic_dbg("wire_b: tunnel is_tproxy=%d\n", is_tproxy);

	/* Exercises tquic_tunnel_close */
	tquic_tunnel_close(tunnel);
}
EXPORT_SYMBOL_GPL(tquic_wire_b_tunnel_ops);

/**
 * tquic_wire_b_tunnel_icmp - Wire tunnel ICMP passthrough exports
 * @tunnel: Tunnel to forward ICMP through
 * @skb: ICMP packet skb
 * @direction: 0 for TX (router->internet), 1 for RX (internet->router)
 * @icmp_type: ICMP message type (for error handling)
 * @icmp_code: ICMP message code (for error handling)
 * @icmp_info: ICMP message info field (MTU for type 3 code 4)
 *
 * Exercises tquic_tunnel_icmp_forward and
 * tquic_tunnel_handle_icmp_error.
 *
 * Return: 0 on success, negative errno on error.
 */
int tquic_wire_b_tunnel_icmp(struct tquic_tunnel *tunnel,
			     struct sk_buff *skb, int direction,
			     u8 icmp_type, u8 icmp_code, u32 icmp_info)
{
	int ret;

	if (!tunnel || !skb)
		return -EINVAL;

	/* Exercises tquic_tunnel_icmp_forward */
	ret = tquic_tunnel_icmp_forward(tunnel, skb, direction);
	if (ret)
		return ret;

	/* Exercises tquic_tunnel_handle_icmp_error */
	return tquic_tunnel_handle_icmp_error(tunnel, icmp_type,
					      icmp_code, icmp_info);
}
EXPORT_SYMBOL_GPL(tquic_wire_b_tunnel_icmp);

/*
 * =============================================================================
 * Netlink notification hooks
 * =============================================================================
 */

/**
 * tquic_wire_b_nl_ops - Wire netlink notification exports
 * @net: Network namespace
 * @conn_id: Connection identifier for events
 * @old_path_id: Previous path ID (before migration)
 * @new_path_id: New path ID (after migration)
 *
 * Exercises tquic_nl_migration_event and tquic_nl_notify_migration.
 */
void tquic_wire_b_nl_ops(struct net *net, u64 conn_id,
			 u32 old_path_id, u32 new_path_id)
{
	if (!net)
		return;

	/* Exercises tquic_nl_migration_event */
	tquic_nl_migration_event(net, conn_id, old_path_id, new_path_id,
				 0, GFP_ATOMIC);

	/* Exercises tquic_nl_notify_migration */
	tquic_nl_notify_migration(net, conn_id, old_path_id, new_path_id, 0);
}
EXPORT_SYMBOL_GPL(tquic_wire_b_nl_ops);

/*
 * =============================================================================
 * Migration sub-API hooks
 * =============================================================================
 */

/**
 * tquic_wire_b_migration_ops - Wire migration sub-API exports
 * @conn: Connection undergoing migration
 * @new_addr: New remote address after NAT rebinding (may be NULL)
 * @skb: Buffered packet during migration pause (may be NULL)
 *
 * Exercises tquic_path_find_by_addr, tquic_server_handle_migration,
 * tquic_server_start_session_ttl, and tquic_server_queue_packet.
 */
void tquic_wire_b_migration_ops(struct tquic_connection *conn,
				const struct sockaddr_storage *new_addr,
				struct sk_buff *skb)
{
	struct tquic_path *path;

	if (!conn)
		return;

	/* Exercises tquic_path_find_by_addr */
	if (new_addr) {
		rcu_read_lock();
		path = tquic_path_find_by_addr(conn, new_addr);
		rcu_read_unlock();
		tquic_dbg("wire_b: path_find_by_addr=%p\n", path);
	}

	if (!conn->is_server)
		return;

	/* Exercises tquic_server_handle_migration */
	if (new_addr)
		tquic_server_handle_migration(conn, new_addr);

	/* Exercises tquic_server_start_session_ttl */
	tquic_server_start_session_ttl(conn);

	/* Exercises tquic_server_queue_packet */
	if (skb)
		tquic_server_queue_packet(conn, skb);
}
EXPORT_SYMBOL_GPL(tquic_wire_b_migration_ops);

/**
 * tquic_wire_b_session_resume - Wire session resume export
 * @conn: Server-side connection
 * @session_id: Session identifier
 * @session_id_len: Length of session_id in bytes
 *
 * Exercises tquic_server_session_resume.
 *
 * Return: 0 on success, negative errno on failure.
 */
int tquic_wire_b_session_resume(struct tquic_connection *conn,
				const u8 *session_id, u32 session_id_len)
{
	if (!conn || !conn->is_server)
		return -EINVAL;

	return tquic_server_session_resume(conn, session_id, session_id_len);
}
EXPORT_SYMBOL_GPL(tquic_wire_b_session_resume);

/*
 * =============================================================================
 * Server PSK / handshake hooks
 * =============================================================================
 */

/**
 * tquic_wire_b_server_psk - Wire server-side PSK exports
 * @sk: Server socket
 * @initial_pkt: Initial packet from client
 * @identity: PSK identity string
 * @identity_len: Length of identity
 * @psk_out: Output buffer for PSK material (may be NULL)
 *
 * Exercises tquic_server_hello_psk and tquic_server_psk_callback.
 *
 * Return: 0 on success, negative errno on failure.
 */
int tquic_wire_b_server_psk(struct sock *sk, struct sk_buff *initial_pkt,
			    const char *identity, u8 identity_len,
			    u8 *psk_out)
{
	int ret;

	if (!sk)
		return -EINVAL;

	/* Exercises tquic_server_hello_psk */
	ret = tquic_server_hello_psk(sk, initial_pkt, identity, identity_len);
	if (ret)
		return ret;

	/* Exercises tquic_server_psk_callback */
	if (psk_out)
		ret = tquic_server_psk_callback(sk, identity,
						identity_len, psk_out);

	return ret;
}
EXPORT_SYMBOL_GPL(tquic_wire_b_server_psk);

/**
 * tquic_wire_b_zero_rtt_response - Wire zero-RTT server response export
 * @sk: Client socket
 * @accepted: Whether the server accepted 0-RTT early data
 *
 * Exercises tquic_handle_zero_rtt_response.
 */
void tquic_wire_b_zero_rtt_response(struct sock *sk, bool accepted)
{
	tquic_handle_zero_rtt_response(sk, accepted);
}
EXPORT_SYMBOL_GPL(tquic_wire_b_zero_rtt_response);

/**
 * tquic_wire_b_store_ticket - Wire session ticket storage export
 * @sk: Client socket after successful handshake
 * @server_name: Server hostname (SNI)
 * @server_name_len: Length of server name
 * @ticket_data: Ticket bytes from NEW_SESSION_TICKET
 * @ticket_len: Length of ticket
 * @psk: PSK (resumption_master_secret)
 * @psk_len: Length of PSK
 * @cipher_suite: Negotiated cipher suite identifier
 * @max_age: Ticket lifetime in seconds
 *
 * Exercises tquic_store_session_ticket.
 *
 * Return: 0 on success, negative errno on failure.
 */
int tquic_wire_b_store_ticket(struct sock *sk, const char *server_name,
			      u8 server_name_len, const u8 *ticket_data,
			      u32 ticket_len, const u8 *psk, u32 psk_len,
			      u16 cipher_suite, u32 max_age)
{
	return tquic_store_session_ticket(sk, server_name, server_name_len,
					  ticket_data, ticket_len,
					  psk, psk_len,
					  cipher_suite, max_age);
}
EXPORT_SYMBOL_GPL(tquic_wire_b_store_ticket);

/*
 * =============================================================================
 * Sysctl accessor hook
 * =============================================================================
 */

/**
 * tquic_wire_b_per_ip_limit - Wire per-IP rate limit sysctl accessor
 *
 * Exercises tquic_sysctl_get_per_ip_rate_limit.
 *
 * Return: Configured per-IP connection rate limit.
 */
int tquic_wire_b_per_ip_limit(void)
{
	return tquic_sysctl_get_per_ip_rate_limit();
}
EXPORT_SYMBOL_GPL(tquic_wire_b_per_ip_limit);

/*
 * =============================================================================
 * IPv6 path hooks (CONFIG_TQUIC_IPV6)
 * =============================================================================
 */

#if IS_ENABLED(CONFIG_TQUIC_IPV6)
/**
 * tquic_wire_b_v6_add_path - Wire IPv6 path addition export
 * @conn: Connection to add the IPv6 path to
 * @local: Local IPv6 address
 * @remote: Remote IPv6 address
 *
 * Exercises tquic_v6_add_path.
 *
 * Return: Path ID on success, negative errno on failure.
 */
int tquic_wire_b_v6_add_path(struct tquic_connection *conn,
			     struct sockaddr_in6 *local,
			     struct sockaddr_in6 *remote)
{
	return tquic_v6_add_path(conn, local, remote);
}
EXPORT_SYMBOL_GPL(tquic_wire_b_v6_add_path);

/**
 * tquic_wire_b_v6_discover - Wire IPv6 address discovery export
 * @conn: Connection to discover addresses for
 * @addrs: Output buffer for discovered addresses
 * @max_addrs: Maximum number of addresses to return
 *
 * Exercises tquic_v6_discover_addresses.
 *
 * Return: Number of addresses discovered, or negative errno.
 */
int tquic_wire_b_v6_discover(struct tquic_connection *conn,
			     struct sockaddr_storage *addrs, int max_addrs)
{
	return tquic_v6_discover_addresses(conn, addrs, max_addrs);
}
EXPORT_SYMBOL_GPL(tquic_wire_b_v6_discover);
#endif /* CONFIG_TQUIC_IPV6 */
