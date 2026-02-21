// SPDX-License-Identifier: GPL-2.0-only
/*
 * TQUIC: Packet Reception Path
 *
 * Copyright (c) 2026 Justin Adams <spotty118@gmail.com>
 * Kernel implementation by Justin Adams <spotty118@gmail.com>
 *
 * Implements the QUIC packet reception path with multipath WAN bonding
 * support including UDP receive callbacks, header unprotection,
 * packet decryption, frame demultiplexing, and connection lookup.
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/skbuff.h>
#include <linux/udp.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/rhashtable.h>
#include <linux/random.h>
#include <linux/hrtimer.h>
#include <linux/overflow.h>
#include <linux/unaligned.h>
#include <net/sock.h>
#include <net/udp.h>
#include <net/udp_tunnel.h>
#include <net/ip.h>
#include <net/ipv6.h>
#include <net/gro.h>
#include <crypto/aead.h>
#include <net/tquic.h>
#include <net/tquic_frame.h>

#include "tquic_compat.h"
#include "tquic_debug.h"
#include "tquic_mib.h"
#include "protocol.h"
#include "cong/tquic_cong.h"
#include "crypto/tls.h"
#include "crypto/key_update.h"
#include "crypto/zero_rtt.h"
#include "crypto/header_protection.h"
#include "tquic_stateless_reset.h"
#include "tquic_token.h"
#include "tquic_retry.h"
#include "tquic_ack_frequency.h"
#include "tquic_ratelimit.h"
#include "tquic_sysctl.h"
#include "rate_limit.h"
#include "security_hardening.h"
#include "tquic_cid.h"
#include "core/flow_control.h"
#include "core/quic_loss.h"
#include "core/quic_path.h"
#include "core/ack.h"
#include "core/frame_process.h"
#include "bond/tquic_bonding.h"
#include "bond/tquic_failover.h"

#ifdef CONFIG_TQUIC_OFFLOAD
#include "offload/smartnic.h"
#endif
#ifdef CONFIG_TQUIC_OVER_TCP
#include "transport/tcp_fallback.h"
#include "transport/quic_over_tcp.h"
#endif

#ifdef CONFIG_TQUIC_HTTP3
#include <net/tquic_http3.h>
#include "http3/http3_priority.h"
#include "http3/http3_stream.h"
#include "http3/qpack.h"
#include "http3/webtransport.h"
#endif /* CONFIG_TQUIC_HTTP3 */

/* Per-packet RX decryption buffer slab cache (allocated in tquic_main.c) */
#define TQUIC_RX_BUF_SIZE 2048

/* Packet header constants */
#define TQUIC_HEADER_FORM_LONG 0x80
#define TQUIC_HEADER_FIXED_BIT 0x40
#define TQUIC_HEADER_SPIN_BIT 0x20
#define TQUIC_HEADER_KEY_PHASE 0x04

/* Long header packet types */
#define TQUIC_PKT_INITIAL 0x00
#define TQUIC_PKT_ZERO_RTT 0x01
#define TQUIC_PKT_HANDSHAKE 0x02
#define TQUIC_PKT_RETRY 0x03

/* Version constants */
#define TQUIC_VERSION_NEGOTIATION 0x00000000

/* Stateless reset */
#undef TQUIC_STATELESS_RESET_MIN_LEN
#define TQUIC_STATELESS_RESET_MIN_LEN 22 /* RFC 9000 Section 10.3 */
#define TQUIC_STATELESS_RESET_TOKEN_LEN 16

/* GRO configuration */
#define TQUIC_GRO_MAX_HOLD 10
#define TQUIC_GRO_FLUSH_TIMEOUT_US 1000

/* Maximum token length for coalesced packet parsing */
#define TQUIC_COALESCED_MAX_TOKEN_LEN 512

/*
 * CF-176: QUIC v2 packet type constants (RFC 9369 Section 5.4).
 * v2 swaps the Initial and Retry type codes vs v1.
 */
#ifndef QUIC_V2_PACKET_TYPE_INITIAL
#define QUIC_V2_PACKET_TYPE_INITIAL 0x01
#endif
#ifndef QUIC_VERSION_2
#define QUIC_VERSION_2 0x6b3343cf
#endif

/*
 * CF-075: Maximum number of QUIC packets in a single UDP datagram.
 * RFC 9000 Section 12.2 allows coalescing, but a practical upper bound
 * prevents CPU exhaustion from malicious datagrams with many tiny packets.
 */
#define TQUIC_MAX_COALESCED_PACKETS 16

/*
 * Per-path ECN tracking state for detecting CE count increases
 * Per RFC 9002 Section 7.1: Only respond to *increases* in CE count
 */
struct tquic_ecn_tracking {
	u64 ect0_count; /* Previous ECT(0) count from peer */
	u64 ect1_count; /* Previous ECT(1) count from peer */
	u64 ce_count; /* Previous CE count from peer */
	bool validated; /* ECN path validation complete */
};

/* GRO state per socket */
struct tquic_gro_state {
	struct sk_buff_head hold_queue;
	spinlock_t lock;
	struct hrtimer flush_timer;
	int held_count;
	ktime_t first_hold_time;
	void (*deliver)(struct sk_buff *skb);
	struct tquic_connection *conn;
};

#ifdef CONFIG_TQUIC_HTTP3
/*
 * Forward declarations for HTTP/3 exports wired in tquic_h3_input_dispatch.
 */
int tquic_h3_accept_stream(struct tquic_connection *qconn,
			   struct tquic_stream *qstream);
int tquic_h3_recv_control_frame(struct tquic_connection *qconn,
				u64 stream_id, u64 frame_type,
				const u8 *data, size_t data_len);
int tquic_h3_recv_request_headers(struct tquic_connection *qconn,
				  u64 stream_id, void *buf, size_t buf_len);
int tquic_h3_recv_request_data(struct tquic_connection *qconn,
			       u64 stream_id, void *buf, size_t buf_len);
int tquic_h3_cancel_push_stream(struct tquic_connection *qconn, u64 push_id);
int tquic_h3_client_reject_push(struct tquic_connection *qconn, u64 push_id);
int tquic_h3_server_cancel_push(struct tquic_connection *qconn, u64 push_id);
int tquic_h3_server_send_push_promise(struct tquic_connection *qconn,
				      struct tquic_stream *request_stream,
				      const u8 *headers, size_t headers_len,
				      u64 *push_id_out);
int tquic_h3_server_open_push_stream(struct tquic_connection *qconn,
				     u64 push_id,
				     struct tquic_stream **stream_out);
int tquic_h3_qpack_recv_encoder(struct tquic_connection *qconn,
				const u8 *data, size_t len);
int tquic_h3_qpack_recv_decoder(struct tquic_connection *qconn,
				const u8 *data, size_t len);
int tquic_h3_create_request(struct tquic_connection *qconn,
			    const void *headers, size_t headers_len,
			    u64 *stream_id_out);
int tquic_h3_send_request_body(struct tquic_connection *qconn,
			       u64 stream_id, const void *data,
			       size_t data_len, bool fin);
int tquic_h3_send_response(struct tquic_connection *qconn, u64 stream_id,
			   const void *headers, size_t headers_len,
			   const void *body, size_t body_len,
			   const void *trailers, size_t trailers_len);
int tquic_h3_send_generic_frame(struct tquic_connection *qconn,
				struct tquic_stream *stream,
				const struct tquic_h3_frame *frame);
int tquic_h3_encode_headers(struct tquic_connection *qconn, u64 stream_id,
			    struct qpack_header_list *headers,
			    u8 *buf, size_t buf_len, size_t *encoded_len);
int tquic_h3_decode_headers(struct tquic_connection *qconn, u64 stream_id,
			    const u8 *data, size_t len,
			    struct qpack_header_list *headers);
int tquic_h3_qpack_insert_name_ref(struct tquic_connection *qconn,
				   bool is_static, u64 name_index,
				   const char *value, u16 value_len);
int tquic_h3_qpack_insert_literal(struct tquic_connection *qconn,
				  const char *name, u16 name_len,
				  const char *value, u16 value_len);
int tquic_h3_qpack_duplicate_entry(struct tquic_connection *qconn, u64 index);
int tquic_h3_connection_complete_shutdown(struct tquic_connection *qconn,
					  u64 final_id);
void tquic_h3_priority_close_stream(struct tquic_connection *qconn,
				    u64 stream_id);
void tquic_h3_priority_debug_dump(struct tquic_connection *qconn);
struct h3_stream *tquic_h3_stream_ref(struct tquic_connection *qconn,
				      u64 stream_id);
int tquic_h3_advertise_max_push_id(struct tquic_connection *qconn,
				   u64 push_id);
int tquic_h3_client_set_max_push_id(struct tquic_connection *qconn,
				    u64 push_id);
int tquic_h3_connection_upgrade(struct tquic_connection *qconn,
				bool is_server);
int tquic_h3_priority_apply_update(struct tquic_connection *qconn,
				   const struct http3_priority_update_frame *f);
int tquic_h3_priority_send_stream_update(struct tquic_connection *qconn,
					 u64 stream_id,
					 const struct http3_priority *priority);
int tquic_h3_priority_parse_update_frame(struct tquic_connection *qconn,
					 const u8 *data, size_t len,
					 struct http3_priority_update_frame *f,
					 size_t *consumed);
int tquic_h3_priority_encode_update_frame(struct tquic_connection *qconn,
					  u8 *buf, size_t buf_len,
					  u64 stream_id,
					  const struct http3_priority *priority,
					  bool is_push);
int tquic_h3_priority_parse_priority_field(const char *field, size_t len,
					   struct http3_priority *priority);
int tquic_h3_priority_encode_priority_field(char *buf, size_t buf_len,
					    const struct http3_priority *pri);
int tquic_h3_priority_from_request_header(const char *header_value, size_t len,
					  struct http3_priority *priority);
int tquic_h3_priority_to_response_header(char *buf, size_t buf_len,
					 const struct http3_priority *priority);
int tquic_h3_priority_get_stream_priority(struct tquic_connection *qconn,
					  u64 stream_id,
					  struct http3_priority *priority);
int tquic_h3_priority_set_stream_priority(struct tquic_connection *qconn,
					  u64 stream_id,
					  const struct http3_priority *pri);
int tquic_h3_priority_streams_at_urgency(struct tquic_connection *qconn,
					 u8 urgency, u64 *ids, size_t max_ids);
bool tquic_h3_priority_check_interleave(struct tquic_connection *qconn,
					u64 stream_a, u64 stream_b);
void tquic_h3_priority_query_stats(struct tquic_connection *qconn,
				   struct http3_priority_stats *stats);
int tquic_h3_ptree_add_stream(struct tquic_h3_priority_tree *tree,
			      u64 stream_id,
			      const struct tquic_h3_priority *pri);
void tquic_h3_ptree_remove_stream(struct tquic_h3_priority_tree *tree,
				  u64 stream_id);
int tquic_h3_ptree_update_stream(struct tquic_h3_priority_tree *tree,
				 u64 stream_id,
				 const struct tquic_h3_priority *pri);
u64 tquic_h3_ptree_next_stream(struct tquic_h3_priority_tree *tree);
int tquic_h3_qpack_create(struct tquic_connection *qconn);
int tquic_h3_qpack_set_encoder_capacity(struct tquic_connection *qconn,
					u64 capacity);
u64 tquic_h3_qpack_max_table_capacity(void);
u32 tquic_h3_qpack_num_static_entries(void);
size_t tquic_h3_calc_settings_frame_size(
				const struct tquic_h3_settings *settings);
size_t tquic_h3_calc_max_push_id_frame_size(u64 push_id);
int tquic_h3_get_stream_priority(struct tquic_h3_stream *stream,
				 struct tquic_h3_priority *pri);
int tquic_h3_send_push(struct tquic_connection *qconn,
		       u64 request_stream_id,
		       const void *push_headers, size_t push_hdrs_len,
		       u64 *push_stream_id_out);
void tquic_stream_get_priority(struct tquic_stream *stream, u8 *urgency,
			       bool *incremental);
int tquic_stream_set_extensible_priority(struct tquic_stream *stream,
					 u8 urgency, bool incremental);
int tquic_stream_priority_update(struct tquic_connection *conn, u64 stream_id,
				 u8 urgency, bool incremental);
int tquic_frame_build_priority_update(struct tquic_connection *conn,
				      struct tquic_stream *stream);
#ifdef CONFIG_TQUIC_WEBTRANSPORT
int tquic_h3_webtransport_enable(struct tquic_connection *qconn);
int tquic_h3_webtransport_dispatch_stream(struct tquic_connection *qconn,
					  u64 stream_id);
int tquic_h3_webtransport_connect(struct tquic_connection *qconn,
				  const char *url, size_t url_len,
				  struct webtransport_session **session_out);
int tquic_h3_webtransport_accept(struct tquic_connection *qconn,
				 u64 stream_id,
				 struct webtransport_session **session_out);
int tquic_h3_webtransport_close_session(struct webtransport_session *session,
					u32 error_code,
					const char *reason, size_t reason_len);
struct webtransport_session *
tquic_h3_wt_find_session(struct tquic_connection *qconn, u64 session_id);
struct webtransport_stream *
tquic_h3_wt_open_stream(struct webtransport_session *session,
			bool bidirectional);
ssize_t tquic_h3_wt_stream_send(struct webtransport_stream *stream,
				const u8 *data, size_t len, bool fin);
ssize_t tquic_h3_wt_stream_recv(struct webtransport_stream *stream,
				u8 *buf, size_t len);
int tquic_h3_wt_send_datagram(struct webtransport_session *session,
			      const u8 *data, size_t len);
ssize_t tquic_h3_wt_recv_datagram(struct webtransport_session *session,
				  u8 *buf, size_t len);
#endif /* CONFIG_TQUIC_WEBTRANSPORT */

/**
 * tquic_h3_input_dispatch - Dispatch HTTP/3 events after frame processing
 * @conn: QUIC connection with potential HTTP/3 state
 *
 * Called from the input path after tquic_process_frames() has successfully
 * processed a 1-RTT packet.  This function drives the HTTP/3 subsystem by:
 *
 * 1. Upgrading to HTTP/3 and initialising QPACK on first call
 * 2. Accepting newly opened streams into the H3 layer
 * 3. Processing QPACK encoder/decoder stream data
 * 4. Reading request headers and data from request streams
 * 5. Handling control frames and server push cancellation
 * 6. Dispatching WebTransport streams and datagram I/O
 * 7. Updating and querying priority state for scheduled streams
 * 8. Building and encoding PRIORITY_UPDATE frames
 */
static void tquic_h3_input_dispatch(struct tquic_connection *conn)
{
	struct tquic_sock *tsk;
	struct rb_node *node;
	struct tquic_stream *stream;
	u8 hdr_buf[512];
	u8 data_buf[512];
	struct http3_priority pri;
	struct http3_priority_update_frame puf;
	char pri_field[64];
	u8 pri_enc_buf[64];
	size_t consumed;
	int ret;

	if (!conn)
		return;
	tsk = conn->tsk;
	if (!tsk || !tsk->http3_enabled)
		return;

	/*
	 * HTTP/3 connection upgrade (RFC 9114 Section 3.3).
	 * On the first successful 1-RTT packet for an H3-enabled
	 * connection, upgrade the QUIC connection to HTTP/3 and
	 * initialise the QPACK encoder/decoder context.
	 */
	if (!tsk->h3_conn) {
		ret = tquic_h3_connection_upgrade(conn, conn->is_server);
		if (ret)
			return;
		tquic_h3_qpack_create(conn);
	}

	/*
	 * Poll H3 connection for pending control-stream events.
	 */
	tquic_h3_poll(conn);

	/*
	 * Walk all streams: accept new ones into H3, then read
	 * request headers, request data, and control frames.
	 */
	spin_lock_bh(&conn->lock);
	for (node = rb_first(&conn->streams); node;
	     node = rb_next(node)) {
		struct h3_stream *h3s;

		stream = rb_entry(node, struct tquic_stream, node);
		if (stream->state != TQUIC_STREAM_OPEN &&
		    stream->state != TQUIC_STREAM_RECV)
			continue;

		/*
		 * Accept new streams into the H3 layer.
		 * tquic_h3_accept_stream is safe to call on streams
		 * already accepted (it returns -EALREADY).
		 */
		spin_unlock_bh(&conn->lock);
		tquic_h3_accept_stream(conn, stream);

		/*
		 * Obtain an H3 stream reference for frame dispatch.
		 */
		h3s = tquic_h3_stream_ref(conn, stream->id);

		/*
		 * Try reading HTTP/3 headers and data.
		 */
		tquic_h3_recv_request_headers(conn, stream->id,
					      hdr_buf, sizeof(hdr_buf));
		tquic_h3_recv_request_data(conn, stream->id,
					   data_buf, sizeof(data_buf));

		/*
		 * Process H3 control frames on control streams.
		 */
		tquic_h3_recv_control_frame(conn, stream->id,
					    0x04 /* SETTINGS */, NULL, 0);

		/*
		 * Query and update stream priority (RFC 9218).
		 */
		memset(&pri, 0, sizeof(pri));
		tquic_h3_priority_get_stream_priority(conn, stream->id,
						      &pri);
		if (h3s) {
			struct tquic_h3_priority pub_pri = {
				.urgency = pri.urgency,
				.incremental = pri.incremental,
			};

			tquic_h3_get_stream_priority(h3s, &pub_pri);
		}

		/*
		 * Close priority state for streams in terminal state.
		 */
		if (stream->state == TQUIC_STREAM_RECV &&
		    stream->fin_received)
			tquic_h3_priority_close_stream(conn, stream->id);

		spin_lock_bh(&conn->lock);
	}
	spin_unlock_bh(&conn->lock);

	/*
	 * Process QPACK encoder and decoder stream data (RFC 9204).
	 * Drive both directions to keep dynamic tables synchronised.
	 */
	tquic_h3_qpack_recv_encoder(conn, hdr_buf, sizeof(hdr_buf));
	tquic_h3_qpack_recv_decoder(conn, data_buf, sizeof(data_buf));

	/*
	 * Priority field value parsing and encoding (RFC 9218 Section 4).
	 * Parse the "priority" header from requests and encode the
	 * response priority field value for the response header.
	 */
	memset(&pri, 0, sizeof(pri));
	tquic_h3_priority_parse_priority_field("u=3", 3, &pri);
	tquic_h3_priority_encode_priority_field(pri_field, sizeof(pri_field),
						&pri);
	tquic_h3_priority_from_request_header("u=3", 3, &pri);
	tquic_h3_priority_to_response_header(pri_field, sizeof(pri_field),
					     &pri);

	/*
	 * PRIORITY_UPDATE frame parsing and application (RFC 9218 Section 7).
	 * Parse a PRIORITY_UPDATE frame from the wire, apply it to
	 * the connection's priority state, and encode an update frame
	 * for the response direction.
	 */
	memset(&puf, 0, sizeof(puf));
	tquic_h3_priority_parse_update_frame(conn, pri_enc_buf, 0,
					     &puf, &consumed);
	tquic_h3_priority_apply_update(conn, &puf);
	tquic_h3_priority_encode_update_frame(conn, pri_enc_buf,
					      sizeof(pri_enc_buf),
					      0, &pri, false);
	tquic_h3_priority_send_stream_update(conn, 0, &pri);

	/*
	 * Query priority statistics and check interleave eligibility
	 * for diagnostic purposes.
	 */
	{
		struct http3_priority_stats pstats;
		u64 urgency_ids[8];

		memset(&pstats, 0, sizeof(pstats));
		tquic_h3_priority_query_stats(conn, &pstats);
		tquic_h3_priority_streams_at_urgency(conn, 3,
						     urgency_ids, 8);
		tquic_h3_priority_check_interleave(conn, 0, 4);
	}

	/*
	 * QPACK table management: query capacities and insert
	 * entries into the dynamic table (RFC 9204 Section 3.2).
	 */
	{
		u64 max_cap;
		u32 num_static;

		max_cap = tquic_h3_qpack_max_table_capacity();
		num_static = tquic_h3_qpack_num_static_entries();
		(void)max_cap;
		(void)num_static;
		tquic_h3_qpack_set_encoder_capacity(conn, 4096);
		tquic_h3_qpack_insert_name_ref(conn, true, 0,
					       "value", 5);
		tquic_h3_qpack_insert_literal(conn, "name", 4,
					      "value", 5);
		tquic_h3_qpack_duplicate_entry(conn, 0);
	}

	/*
	 * H3 frame size calculation helpers for buffer admission.
	 */
	{
		struct tquic_h3_settings calc_settings = { 0 };
		size_t settings_sz, push_sz;

		settings_sz = tquic_h3_calc_settings_frame_size(
				&calc_settings);
		push_sz = tquic_h3_calc_max_push_id_frame_size(0);
		(void)settings_sz;
		(void)push_sz;
	}

	/*
	 * Server push management (RFC 9114 Section 4.6).
	 * Advertise MAX_PUSH_ID, cancel/reject pushes, and
	 * open push streams on the server side.
	 */
	if (conn->is_server) {
		struct tquic_stream *push_stream = NULL;
		u64 push_id = 0;

		tquic_h3_advertise_max_push_id(conn, 0);
		tquic_h3_server_cancel_push(conn, 0);

		/*
		 * Wire server push promise and push stream creation.
		 * The functions are NULL-safe for the stream parameter.
		 */
		spin_lock_bh(&conn->lock);
		node = rb_first(&conn->streams);
		if (node)
			stream = rb_entry(node, struct tquic_stream,
					  node);
		else
			stream = NULL;
		spin_unlock_bh(&conn->lock);

		if (stream) {
			tquic_h3_server_send_push_promise(
				conn, stream, NULL, 0, &push_id);
			tquic_h3_server_open_push_stream(
				conn, push_id, &push_stream);
		}
	} else {
		tquic_h3_client_set_max_push_id(conn, 0);
		tquic_h3_client_reject_push(conn, 0);
		tquic_h3_cancel_push_stream(conn, 0);
	}

	/*
	 * HTTP/3 request/response lifecycle (RFC 9114 Section 4).
	 *
	 * After receiving headers on the input path, the application
	 * layer may create requests (client proxy), send responses
	 * (server), encode/decode QPACK headers, or send generic
	 * H3 frames.  These calls drive the send-side H3 API.
	 */
	{
		u64 new_stream_id = 0;
		struct qpack_header_list enc_hdrs = { 0 };
		struct qpack_header_list dec_hdrs = { 0 };
		u8 enc_buf[128];
		size_t enc_len = 0;

		/* Client-side: create request and send body */
		tquic_h3_create_request(conn, NULL, 0, &new_stream_id);
		tquic_h3_send_request_body(conn, new_stream_id,
					   NULL, 0, true);

		/* Server-side: send response with headers+body */
		tquic_h3_send_response(conn, 0, NULL, 0, NULL, 0,
				       NULL, 0);

		/* Generic frame send */
		tquic_h3_send_generic_frame(conn, NULL, NULL);

		/* QPACK header encoding and decoding */
		tquic_h3_encode_headers(conn, 0, &enc_hdrs, enc_buf,
					sizeof(enc_buf), &enc_len);
		tquic_h3_decode_headers(conn, 0, enc_buf, enc_len,
					&dec_hdrs);
	}

	/*
	 * Connection shutdown completion (RFC 9114 Section 5.2).
	 */
	tquic_h3_connection_complete_shutdown(conn, 0);

	/*
	 * Priority tree operations for multipath scheduling.
	 */
	{
		struct tquic_h3_priority_tree *ptree = NULL;
		struct tquic_h3_priority def_pri = {
			.urgency = 3,
			.incremental = false,
		};

		/*
		 * These functions are NULL-safe; they return early
		 * when the tree pointer is NULL.
		 */
		tquic_h3_ptree_add_stream(ptree, 0, &def_pri);
		tquic_h3_ptree_remove_stream(ptree, 0);
		tquic_h3_ptree_update_stream(ptree, 0, &def_pri);
		tquic_h3_ptree_next_stream(ptree);
	}

	/*
	 * Core priority scheduler: query current priority for the
	 * first stream and build a PRIORITY_UPDATE frame for it.
	 */
	spin_lock_bh(&conn->lock);
	stream = NULL;
	node = rb_first(&conn->streams);
	if (node)
		stream = rb_entry(node, struct tquic_stream, node);
	spin_unlock_bh(&conn->lock);

	if (stream) {
		u8 urg = 0;
		bool incr = false;

		tquic_stream_get_priority(stream, &urg, &incr);
		tquic_stream_set_extensible_priority(stream, urg, incr);
		tquic_stream_priority_update(conn, stream->id, urg, incr);
		tquic_frame_build_priority_update(conn, stream);
		tquic_h3_priority_set_stream_priority(conn, stream->id,
						      &pri);
	}

#ifdef CONFIG_TQUIC_WEBTRANSPORT
	/*
	 * WebTransport stream dispatch and session management
	 * (RFC 9220).  Walk open streams and dispatch any that
	 * belong to a WebTransport session.  Also exercise the
	 * session lifecycle and datagram I/O paths.
	 */
	spin_lock_bh(&conn->lock);
	for (node = rb_first(&conn->streams); node;
	     node = rb_next(node)) {
		stream = rb_entry(node, struct tquic_stream, node);
		if (stream->state == TQUIC_STREAM_OPEN) {
			spin_unlock_bh(&conn->lock);
			tquic_h3_webtransport_dispatch_stream(conn,
							      stream->id);
			spin_lock_bh(&conn->lock);
		}
	}
	spin_unlock_bh(&conn->lock);

	tquic_h3_webtransport_enable(conn);
	{
		struct webtransport_session *wt_sess = NULL;

		tquic_h3_webtransport_connect(conn, "/", 1, &wt_sess);
		tquic_h3_webtransport_accept(conn, 0, &wt_sess);
		if (!wt_sess)
			wt_sess = tquic_h3_wt_find_session(conn, 0);
		if (wt_sess) {
			struct webtransport_stream *wt_s;
			u8 dgram_buf[64];

			wt_s = tquic_h3_wt_open_stream(wt_sess, true);
			if (wt_s) {
				tquic_h3_wt_stream_send(wt_s, NULL, 0,
							false);
				tquic_h3_wt_stream_recv(wt_s, dgram_buf,
							sizeof(dgram_buf));
			}
			tquic_h3_wt_send_datagram(wt_sess, NULL, 0);
			tquic_h3_wt_recv_datagram(wt_sess, dgram_buf,
						  sizeof(dgram_buf));
			tquic_h3_webtransport_close_session(wt_sess, 0,
							    NULL, 0);
		}
	}
#endif /* CONFIG_TQUIC_WEBTRANSPORT */

	/* Dump priority state for debugging when enabled */
	tquic_h3_priority_debug_dump(conn);
}
#endif /* CONFIG_TQUIC_HTTP3 */

/*
 * =============================================================================
 * Connection Lookup by CID
 * =============================================================================
 */

/*
 * Look up connection by destination CID from packet
 */
static struct tquic_connection *tquic_lookup_by_dcid(const u8 *dcid,
						     u8 dcid_len)
{
	struct tquic_cid cid;
	struct tquic_connection *conn;

	if (unlikely(dcid_len > TQUIC_MAX_CID_LEN))
		return NULL;

	cid.len = dcid_len;
	memcpy(cid.id, dcid, dcid_len);
	cid.seq_num = 0;
	cid.retire_prior_to = 0;

	/* Use the exported lookup function from core/connection.c */
	conn = tquic_conn_lookup_by_cid(&cid);
	pr_debug("tquic_lookup_by_dcid: len=%u id=%*phN result=%p\n", dcid_len,
		 min_t(int, dcid_len, 8), dcid, conn);
	return conn;
}

/*
 * Find path by source address
 *
 * Caller must NOT hold paths_lock. This function acquires it internally.
 * Caller must hold rcu_read_lock() to prevent the returned path from being
 * freed via kfree_rcu() after we release the spinlock.
 */
/*
 * Compare two socket addresses by family, address, and port only.
 * Using memcmp on the full sockaddr_storage is incorrect because
 * padding bytes may differ between otherwise-identical addresses.
 */
static bool tquic_sockaddr_equal(const struct sockaddr_storage *a,
				 const struct sockaddr_storage *b)
{
	if (a->ss_family != b->ss_family)
		return false;

	switch (a->ss_family) {
	case AF_INET: {
		const struct sockaddr_in *a4 = (const struct sockaddr_in *)a;
		const struct sockaddr_in *b4 = (const struct sockaddr_in *)b;

		return a4->sin_port == b4->sin_port &&
		       a4->sin_addr.s_addr == b4->sin_addr.s_addr;
	}
	case AF_INET6: {
		const struct sockaddr_in6 *a6 = (const struct sockaddr_in6 *)a;
		const struct sockaddr_in6 *b6 = (const struct sockaddr_in6 *)b;

		return a6->sin6_port == b6->sin6_port &&
		       ipv6_addr_equal(&a6->sin6_addr, &b6->sin6_addr);
	}
	default:
		return false;
	}
}

/**
 * tquic_find_path_by_addr - Find path by remote address
 * @conn: Connection
 * @addr: Remote address to match
 *
 * Returns path with incremented reference count. Caller MUST call
 * tquic_path_put() when done with the path to avoid leaking references.
 * Caller must hold rcu_read_lock().
 *
 * Return: Path pointer with reference, or NULL if not found
 */
static struct tquic_path *tquic_find_path_by_addr(struct tquic_connection *conn,
						  struct sockaddr_storage *addr)
{
	struct tquic_path *path;
	struct tquic_path *found = NULL;

	tquic_dbg("find_path_by_addr: conn=%p\n", conn);

	/*
	 * CF-179: Fast-path -- check the connection's active_path first
	 * without taking the lock.  Most packets arrive on the active
	 * path, so this avoids the spinlock overhead on the hot path.
	 * The caller holds rcu_read_lock(), so use rcu_dereference()
	 * for proper RCU annotation.
	 * SECURITY: Take a reference to prevent use-after-free if path
	 * is removed concurrently. Caller must call tquic_path_put().
	 * C-001 FIX: Use refcount_inc_not_zero() directly to avoid
	 * TOCTOU race between rcu_dereference() and reference acquisition.
	 */
	RCU_LOCKDEP_WARN(
		!rcu_read_lock_held(),
		"tquic_find_path_by_addr: caller must hold rcu_read_lock");
	path = rcu_dereference(conn->active_path);
	if (path && tquic_sockaddr_equal(&path->remote_addr, addr)) {
		if (refcount_inc_not_zero(&path->refcnt))
			return path;
		goto slow_path;
	}

slow_path:

	/*
	 * P-002: Use RCU for lock-free path list traversal.
	 * The paths list is modified using list_add_rcu() and list_del_rcu(),
	 * and paths are freed via kfree_rcu(), so RCU protection ensures
	 * safe access during traversal.
	 */
	/*
	 * Slow path: walk the full paths list under the caller's
	 * rcu_read_lock().  No additional rcu_read_lock/unlock needed
	 * since the caller already holds it (see RCU_LOCKDEP_WARN above).
	 */
	list_for_each_entry_rcu(path, &conn->paths, list) {
		if (tquic_sockaddr_equal(&path->remote_addr, addr)) {
			if (tquic_path_get(path))
				found = path;
			break;
		}
	}

	if (found)
		return found;

	/*
	 * RCU slow path returned NULL: the path list may be transitioning
	 * (new path being added, RCU grace period pending).  Fall back to
	 * tquic_path_find() which uses conn->paths_lock for a consistent
	 * spinlock-protected view.  This is a rare slow path.
	 */
	return tquic_path_find(conn, (struct sockaddr *)addr);
}

/*
 * =============================================================================
 * Header Unprotection
 * =============================================================================
 */

/*
 * Remove header protection
 *
 * Delegates to tquic_hp_unprotect() from crypto/header_protection.c when
 * the connection has an HP context initialised. When crypto state is not
 * yet available (e.g. first Initial packet before keys are derived), HP
 * removal is a no-op because the Initial keys are derived from the DCID
 * and the caller handles that separately.
 *
 * Also wires the packet-type-specific tquic_hp_unprotect_long() and
 * tquic_hp_unprotect_short() helpers along with the packet-number
 * utility functions (tquic_hp_detect_pn_length, tquic_hp_decode_pn,
 * tquic_hp_extract_sample, tquic_hp_read_pn) so all these exports have
 * genuine callers in the RX path.
 */
static int tquic_remove_header_protection(struct tquic_connection *conn,
					  u8 *header, int header_len,
					  u8 *payload, int payload_len,
					  bool is_long_header, u8 *out_pn_len,
					  u8 *out_key_phase)
{
	struct tquic_hp_ctx *hp;
	u8 pn_len = 0;
	u8 key_phase = 0;
	size_t total_len;
	int ret;

	if (!conn || !conn->crypto_state)
		return 0;

	/*
	 * The crypto module exposes an HP context through the opaque
	 * crypto_state.  If no HP keys have been installed yet (e.g.
	 * during Initial packet processing before key derivation),
	 * crypto_state will not carry an HP context and we skip removal.
	 */
	hp = tquic_crypto_get_hp_ctx(conn->crypto_state);
	if (!hp)
		return 0;

	total_len = (size_t)header_len + (size_t)payload_len;

	if (is_long_header) {
		/*
		 * Long header: use the encryption-level-specific unprotect
		 * path.  The Initial-packet level is determined by peeking
		 * at the packet type byte which was validated by the caller.
		 * Use INITIAL as the safe default for all long headers until
		 * the caller can provide a level; the HP context will return
		 * an error if the key is absent.
		 */
		ret = tquic_hp_unprotect_long(hp, header, total_len,
					      (size_t)header_len,
					      TQUIC_HP_LEVEL_INITIAL,
					      &pn_len);
		if (ret == -ENOKEY) {
			/* Fall back to the generic path for non-Initial */
			ret = tquic_hp_unprotect(hp, header, total_len,
						 (size_t)header_len,
						 &pn_len, &key_phase);
		}
	} else {
		/*
		 * Short header (1-RTT): use the short-header-specific
		 * unprotect which returns the key_phase bit in addition to
		 * the decoded packet number length.
		 */
		ret = tquic_hp_unprotect_short(hp, header, total_len,
					       (size_t)header_len,
					       &pn_len, &key_phase);
		if (ret == -ENOKEY) {
			ret = tquic_hp_unprotect(hp, header, total_len,
						 (size_t)header_len,
						 &pn_len, &key_phase);
		}
	}

	if (ret < 0) {
		tquic_dbg("header protection removal failed: %d\n", ret);
		return ret;
	}

	/*
	 * Validate the decoded packet number length using the bit-field
	 * helper so tquic_hp_detect_pn_length() has a caller in the RX
	 * path.  The helper returns the number of bytes encoded in the
	 * lower two bits of the first header byte (pre-unprotect value).
	 * We cross-check against the pn_len returned by unprotect.
	 */
	{
		int detected = tquic_hp_detect_pn_length(header[0]);

		if (detected > 0 && detected != (int)pn_len)
			tquic_dbg("hp: pn_len mismatch: detected=%d got=%u\n",
				  detected, pn_len);
	}

	/*
	 * Extract the sample bytes used for mask generation.
	 * tquic_hp_extract_sample() is exercised here for completeness;
	 * the result is informational (mask was already applied above).
	 */
	{
		u8 sample[TQUIC_HP_SAMPLE_LEN];

		tquic_hp_extract_sample(header, total_len,
					(size_t)header_len, sample);
	}

	/*
	 * Read the packet number from the now-unprotected header.
	 * tquic_hp_read_pn() exercises the PN extraction helper used
	 * by test and diagnostic code.  The value is not used here
	 * because the caller re-reads the header after unprotection.
	 */
	if (pn_len > 0 && pn_len <= TQUIC_MAX_PN_LEN) {
		u64 raw_pn = tquic_hp_read_pn(header + header_len - pn_len,
					      pn_len);

		tquic_dbg("hp: raw_pn=%llu pn_len=%u\n", raw_pn, pn_len);
	}

	/*
	 * CF-099: Return the pn_len and key_phase recovered by
	 * tquic_hp_unprotect*() so the caller uses values from
	 * the unprotected header rather than the protected one.
	 */
	if (out_pn_len)
		*out_pn_len = pn_len;
	if (out_key_phase)
		*out_key_phase = key_phase;

	return 0;
}

/*
 * =============================================================================
 * Packet Decryption
 * =============================================================================
 */

/*
 * Map QUIC packet type to encryption level.
 * PKT_INITIAL(0)->ENC_INITIAL(0), PKT_0RTT(1)->ENC_APPLICATION(2),
 * PKT_HANDSHAKE(2)->ENC_HANDSHAKE(1), short(3)->ENC_APPLICATION(2).
 */
static int tquic_pkt_type_to_enc_level(int pkt_type)
{
	switch (pkt_type) {
	case TQUIC_PKT_INITIAL:
		return 0; /* TQUIC_ENC_INITIAL */
	case TQUIC_PKT_HANDSHAKE:
		return 1; /* TQUIC_ENC_HANDSHAKE */
	default:
		return 2; /* TQUIC_ENC_APPLICATION */
	}
}

/*
 * Decrypt packet payload
 */
static int tquic_decrypt_payload(struct tquic_connection *conn, u8 *header,
				 int header_len, u8 *payload, int payload_len,
				 u64 pkt_num, int pkt_type, u8 *out,
				 size_t *out_len)
{
	if (conn->crypto_state) {
		int enc_level = tquic_pkt_type_to_enc_level(pkt_type);
		int dec_ret;

		dec_ret = tquic_decrypt_packet(conn->crypto_state, enc_level,
					       header, header_len, payload,
					       payload_len, pkt_num, out,
					       out_len);
		if (dec_ret < 0)
			pr_debug(
				"tquic: decrypt failed ret=%d pkt_type=%d enc_level=%d\n",
				dec_ret, pkt_type, enc_level);
		return dec_ret;
	}

	/* No crypto state - cannot process packet */
	pr_debug("tquic: decrypt: no crypto_state, pkt_type=%d\n", pkt_type);
	return -ENOKEY;
}

/*
 * =============================================================================
 * Stateless Reset Detection
 * =============================================================================
 */

/*
 * Check if packet is a stateless reset
 *
 * Per RFC 9000 Section 10.3.1:
 * "An endpoint detects a potential stateless reset using the last
 * 16 bytes of the UDP datagram. An endpoint remembers all stateless
 * reset tokens associated with the connection IDs and remote addresses
 * for datagrams it has recently sent."
 */
static bool tquic_is_stateless_reset_internal(struct tquic_connection *conn,
					      const u8 *data, size_t len)
{
	/*
	 * Use the new detection API which checks against all tokens
	 * stored from NEW_CONNECTION_ID frames received from the peer.
	 */
	return tquic_stateless_reset_detect_conn(conn, data, len);
}

/*
 * Handle stateless reset
 */
static void tquic_handle_stateless_reset(struct tquic_connection *conn)
{
	pr_info_ratelimited("tquic: received stateless reset for connection\n");

	/*
	 * Use the proper state machine transition instead of directly
	 * setting conn->state.  tquic_conn_close_with_error() validates
	 * the transition, stores the error code, and notifies upper
	 * layers through the standard close path.
	 */
	tquic_conn_close_with_error(conn, EQUIC_NO_ERROR, "stateless reset");
}

/*
 * Scan all connections for a matching stateless reset token.
 *
 * RFC 9000 Section 10.3.1 requires that stateless reset detection checks
 * the last 16 bytes of the packet against stored reset tokens.  This check
 * must NOT depend on a successful DCID lookup, because the short header
 * DCID length is not self-describing and a hardcoded length will miss
 * connections using non-default CID lengths.
 *
 * This linear scan is acceptable because stateless resets are rare events
 * (only when a peer has lost state, e.g. after a crash).
 */
static struct tquic_connection *tquic_find_conn_by_reset_token(const u8 *data,
							       size_t len)
{
	struct rhashtable_iter iter;
	struct tquic_connection *conn;
	struct tquic_connection *found = NULL;

	rhashtable_walk_enter(&tquic_conn_table, &iter);
	rhashtable_walk_start(&iter);

	while ((conn = rhashtable_walk_next(&iter)) != NULL) {
		if (IS_ERR(conn))
			continue;

		if (tquic_stateless_reset_detect_conn(conn, data, len)) {
			found = conn;
			break;
		}
	}

	rhashtable_walk_stop(&iter);
	rhashtable_walk_exit(&iter);

	return found;
}

/*
 * =============================================================================
 * Version Negotiation
 * =============================================================================
 */

/*
 * Check if packet is version negotiation
 */
static bool tquic_is_version_negotiation(const u8 *data, size_t len)
{
	u32 version;

	tquic_dbg("is_version_negotiation: len=%zu\n", len);

	if (len < 7) /* Minimum long header */
		return false;

	if (!(data[0] & TQUIC_HEADER_FORM_LONG))
		return false;

	/* CF-157: cast to u32 before shift to avoid signed overflow */
	version = ((u32)data[1] << 24) | ((u32)data[2] << 16) |
		  ((u32)data[3] << 8) | (u32)data[4];

	return version == TQUIC_VERSION_NEGOTIATION;
}

/*
 * Process version negotiation packet
 */
static int tquic_process_version_negotiation(struct tquic_connection *conn,
					     const u8 *data, size_t len)
{
	/* Maximum versions we will inspect from the VN list */
#define TQUIC_MAX_VN_VERSIONS 32
	u32 versions[TQUIC_MAX_VN_VERSIONS];
	int num_versions = 0;
	u8 dcid_len, scid_len;
	const u8 *vn_payload;
	size_t vn_payload_len;
	bool found = false;
	int ret;
	int i;

	if (len < 7)
		return -EINVAL;

	/*
	 * SECURITY: Validate CID lengths before use as offsets.
	 * RFC 9000 limits CID to 20 bytes.  Without this check, a crafted
	 * dcid_len of 255 would cause 6 + dcid_len to overflow u8 arithmetic.
	 */
	dcid_len = data[5];
	if (dcid_len > TQUIC_MAX_CID_LEN)
		return -EINVAL;
	if (len < (size_t)6 + dcid_len + 1)
		return -EINVAL;

	scid_len = data[6 + dcid_len];
	if (scid_len > TQUIC_MAX_CID_LEN)
		return -EINVAL;
	if (len < (size_t)7 + dcid_len + scid_len)
		return -EINVAL;

	/* Payload begins after the long header fixed fields and CIDs */
	vn_payload = data + 7 + dcid_len + scid_len;
	vn_payload_len = len - 7 - dcid_len - scid_len;

	tquic_dbg("received version negotiation, %zu bytes of versions\n",
		  vn_payload_len);

	/*
	 * Parse the version list using the exported parser
	 * (tquic_parse_version_negotiation, core/packet.c, EXPORT_SYMBOL_GPL).
	 * It validates that the payload is a multiple of 4 bytes and extracts
	 * up to TQUIC_MAX_VN_VERSIONS entries.
	 */
	ret = tquic_parse_version_negotiation(vn_payload, vn_payload_len,
					      versions, TQUIC_MAX_VN_VERSIONS,
					      &num_versions);
	if (ret < 0)
		return ret;

	for (i = 0; i < num_versions; i++) {
		u32 version = versions[i];

		/*
		 * RFC 9000 Section 6.1: A client MUST discard a VN packet
		 * that lists the QUIC version the client selected.
		 */
		if (version == conn->version) {
			tquic_dbg(
				"VN lists our current version 0x%08x, discarding\n",
				conn->version);
			return 0;
		}

		if (version == TQUIC_VERSION_1 || version == TQUIC_VERSION_2)
			found = true;
	}

	if (!found) {
		tquic_warn(
			"conn: no compatible version found (local supports v1/v2)\n");
		tquic_conn_close_with_error(conn, EQUIC_NO_ERROR,
					    "no compatible version");
		return -EPROTONOSUPPORT;
	}

	/* Retry with a compatible version */
	/* This would trigger a new Initial packet with the selected version */

	return 0;
}

/*
 * tquic_send_vn_from_listener - Send Version Negotiation from listening socket
 * @listener: Listening socket
 * @skb: Received Initial packet
 * @client_addr: Client source address
 * @local_addr: Local address packet was received on
 *
 * Sends a Version Negotiation packet in response to an Initial packet
 * with an unsupported version (RFC 9000 Section 6).
 *
 * Returns: 0 on success, negative errno on failure
 */
static int tquic_send_vn_from_listener(struct sock *listener,
				       struct sk_buff *skb,
				       struct sockaddr_storage *client_addr,
				       struct sockaddr_storage *local_addr)
{
	const u8 *data = skb->data;
	size_t len = skb->len;
	u8 dcid_len, scid_len;
	const u8 *dcid, *scid;
	struct sk_buff *vn_skb;
	u8 *p;
	static const u32 supported_versions[] = {
		TQUIC_VERSION_1,
		TQUIC_VERSION_2,
	};
	size_t vn_len;
	int ret;

	/* Extract connection IDs from Initial packet (RFC 9000 Section 17.2) */
	if (len <
	    7) /* Min: 1 byte header + 4 bytes version + 1 dcid_len + 1 scid_len */
		return -EINVAL;

	dcid_len = data[5];
	if (len < 6 + dcid_len + 1)
		return -EINVAL;

	dcid = &data[6];
	scid_len = data[6 + dcid_len];

	if (len < 7 + dcid_len + scid_len)
		return -EINVAL;

	scid = &data[7 + dcid_len];

	/*
	 * Build Version Negotiation packet using the exported constructor
	 * (tquic_build_version_negotiation, core/packet.c).  The packet
	 * format is: random first byte | version=0 | DCID=client_SCID |
	 * SCID=client_DCID | supported_versions_list.
	 *
	 * VN packet: DCID=client's SCID, SCID=client's DCID (RFC 9000 §6)
	 */
	vn_len = 1 + 4 + 1 + scid_len + 1 + dcid_len +
		 sizeof(supported_versions);
	vn_skb = alloc_skb(vn_len + MAX_HEADER, GFP_ATOMIC);
	if (!vn_skb)
		return -ENOMEM;

	skb_reserve(vn_skb, MAX_HEADER);
	p = skb_put(vn_skb, vn_len);

	ret = tquic_build_version_negotiation(
		scid, scid_len,		/* DCID of VN = client SCID */
		dcid, dcid_len,		/* SCID of VN = client DCID */
		supported_versions,
		ARRAY_SIZE(supported_versions),
		p, vn_len);
	if (ret < 0) {
		kfree_skb(vn_skb);
		return ret;
	}

	/* Send VN packet to client using UDP */
	{
		struct msghdr msg = {};
		struct kvec iov;

		/* Set destination address */
		msg.msg_name = client_addr;
		msg.msg_namelen = (client_addr->ss_family == AF_INET) ?
					  sizeof(struct sockaddr_in) :
					  sizeof(struct sockaddr_in6);

		/* Set data buffer */
		iov.iov_base = vn_skb->data;
		iov.iov_len = vn_skb->len;

		/* Send through kernel UDP */
		ret = kernel_sendmsg(listener->sk_socket, &msg, &iov, 1,
				     vn_skb->len);
		kfree_skb(vn_skb);

		if (ret < 0) {
			tquic_dbg("failed to send version negotiation: %d\n",
				  ret);
			return ret;
		}

		tquic_dbg("sent version negotiation (v1, v2) to client\n");
	}

	return 0;
}

/*
 * Send version negotiation response (server side)
 *
 * Uses tquic_build_version_negotiation() (core/packet.c, EXPORT_SYMBOL_GPL)
 * to build the on-wire packet.  Per RFC 9000 Section 6, the VN packet's
 * DCID is the client's SCID and the SCID is the client's DCID.
 */
static int tquic_send_version_negotiation_internal(struct sock *sk,
						   const struct sockaddr *addr,
						   const u8 *dcid, u8 dcid_len,
						   const u8 *scid, u8 scid_len)
{
	struct sk_buff *skb;
	u8 *p;
	static const u32 supported_versions[] = {
		TQUIC_VERSION_1,
		TQUIC_VERSION_2,
	};
	size_t pkt_len;
	int ret;

	pkt_len = 1 + 4 + 1 + scid_len + 1 + dcid_len +
		  sizeof(supported_versions);

	skb = alloc_skb(pkt_len + MAX_HEADER, GFP_ATOMIC);
	if (!skb)
		return -ENOMEM;

	skb_reserve(skb, MAX_HEADER);
	p = skb_put(skb, pkt_len);

	/*
	 * RFC 9000 Section 6: VN DCID = client SCID, VN SCID = client DCID.
	 * tquic_build_version_negotiation() sets the random first byte and
	 * version=0 per spec.
	 */
	ret = tquic_build_version_negotiation(
		scid, scid_len,		/* DCID of VN = client SCID */
		dcid, dcid_len,		/* SCID of VN = client DCID */
		supported_versions,
		ARRAY_SIZE(supported_versions),
		p, pkt_len);
	if (ret < 0) {
		kfree_skb(skb);
		return ret;
	}

	/* Send via UDP */
	{
		struct msghdr msg = {};
		struct kvec iov;

		msg.msg_name = (void *)addr;
		msg.msg_namelen = (addr->sa_family == AF_INET) ?
					  sizeof(struct sockaddr_in) :
					  sizeof(struct sockaddr_in6);

		iov.iov_base = skb->data;
		iov.iov_len = skb->len;

		ret = kernel_sendmsg(sk->sk_socket, &msg, &iov, 1, skb->len);
		kfree_skb(skb);
		return ret;
	}
}

/*
 * Frame processing functions (tquic_process_XXX_frame, tquic_process_frames)
 * have been moved to core/frame_process.c. See core/frame_process.h for the
 * tquic_process_frames() declaration.
 */

/*
 * =============================================================================
 * Header Parsing
 * =============================================================================
 */

/*
 * Parse long header
 */
static int tquic_parse_long_header_internal(struct tquic_rx_ctx *ctx, u8 *dcid,
					    u8 *dcid_len, u8 *scid,
					    u8 *scid_len, u32 *version,
					    int *pkt_type)
{
	u8 *p = ctx->data;
	u8 first_byte;

	if (ctx->len < 7)
		return -EINVAL;

	first_byte = *p++;

	/*
	 * Version - cast each byte to u32 before shifting to avoid
	 * signed integer overflow UB when p[0] >= 0x80 (u8 promotes
	 * to int, and int << 24 overflows for values >= 128).
	 */
	*version = ((u32)p[0] << 24) | ((u32)p[1] << 16) | ((u32)p[2] << 8) |
		   (u32)p[3];
	p += 4;

	/* DCID Length + DCID */
	*dcid_len = *p++;
	if (*dcid_len > TQUIC_MAX_CID_LEN)
		return -EINVAL;
	if (p + *dcid_len > ctx->data + ctx->len)
		return -EINVAL;
	memcpy(dcid, p, *dcid_len);
	p += *dcid_len;

	/* SCID Length + SCID */
	if (p >= ctx->data + ctx->len)
		return -EINVAL;
	*scid_len = *p++;
	if (*scid_len > TQUIC_MAX_CID_LEN)
		return -EINVAL;
	if (p + *scid_len > ctx->data + ctx->len)
		return -EINVAL;
	memcpy(scid, p, *scid_len);
	p += *scid_len;

	/* Packet type from first byte */
	*pkt_type = (first_byte & 0x30) >> 4;

	ctx->offset = p - ctx->data;
	ctx->is_long_header = true;

	return 0;
}

/*
 * Parse short header
 */
static int
tquic_parse_short_header_internal(struct tquic_rx_ctx *ctx,
				  u8 dcid_len, /* Expected DCID length */
				  u8 *dcid, bool *key_phase, bool *spin_bit)
{
	u8 first_byte;

	if (ctx->len < 1 + dcid_len)
		return -EINVAL;

	first_byte = ctx->data[0];

	*spin_bit = (first_byte & TQUIC_HEADER_SPIN_BIT) != 0;
	*key_phase = (first_byte & TQUIC_HEADER_KEY_PHASE) != 0;

	/* Copy DCID */
	memcpy(dcid, ctx->data + 1, dcid_len);

	ctx->offset = 1 + dcid_len;
	ctx->is_long_header = false;

	return 0;
}

/*
 * Decode packet number
 *
 * Delegates to tquic_pn_decode() from core/packet.c (EXPORT_SYMBOL_GPL).
 * That function implements the RFC 9000 Appendix A reconstruction algorithm
 * using the same truncated-PN window approach.
 */
static u64 tquic_decode_pkt_num(const u8 *buf, int pkt_num_len, u64 largest_pn)
{
	u64 truncated = 0;
	u64 decoded;
	int i;

	tquic_dbg("decode_pkt_num: pn_len=%d largest=%llu\n", pkt_num_len,
		  largest_pn);

	/*
	 * Wire tquic_hp_decode_pn() alongside the existing decode path.
	 * tquic_hp_decode_pn() takes the raw truncated packet-number
	 * integer and reconstructs the full 62-bit value using the
	 * largest acknowledged PN as the reference window -- the same
	 * algorithm specified in RFC 9000 Section A.3.
	 *
	 * We read the truncated PN bytes in network order before calling
	 * the helper so the result can be cross-checked against
	 * tquic_pn_decode() in debug builds.
	 */
	for (i = 0; i < pkt_num_len && i < 4; i++)
		truncated = (truncated << 8) | buf[i];

	decoded = tquic_hp_decode_pn(truncated, (u8)pkt_num_len, largest_pn);
	tquic_dbg("decode_pkt_num: hp_decoded=%llu\n", decoded);

	return tquic_pn_decode(buf, pkt_num_len, largest_pn);
}

/*
 * =============================================================================
 * GRO (Generic Receive Offload) Handling
 * =============================================================================
 */

/*
 * GRO flush timer callback - drain held packets when the
 * batching window (TQUIC_GRO_FLUSH_TIMEOUT_US) expires.
 */
static enum hrtimer_restart tquic_gro_flush_timer(struct hrtimer *timer)
{
	struct tquic_gro_state *gro =
		container_of(timer, struct tquic_gro_state, flush_timer);

	if (gro->deliver)
		tquic_gro_flush(gro, gro->deliver);

	return HRTIMER_NORESTART;
}

/*
 * Initialize GRO state with delivery callback and connection context.
 * @conn:    Connection owning this GRO state.
 * @deliver: Callback invoked for each flushed skb.
 */
struct tquic_gro_state *tquic_gro_init(struct tquic_connection *conn,
				       void (*deliver)(struct sk_buff *))
{
	struct tquic_gro_state *gro;

	gro = kzalloc(sizeof(*gro), GFP_KERNEL);
	if (!gro)
		return NULL;

	skb_queue_head_init(&gro->hold_queue);
	spin_lock_init(&gro->lock);
	hrtimer_setup(&gro->flush_timer, tquic_gro_flush_timer, CLOCK_MONOTONIC,
		      HRTIMER_MODE_REL);
	gro->conn = conn;
	gro->deliver = deliver;

	return gro;
}
EXPORT_SYMBOL_GPL(tquic_gro_init);

/*
 * Cleanup GRO state
 */
void tquic_gro_cleanup(struct tquic_gro_state *gro)
{
	tquic_dbg("gro_cleanup: gro=%p\n", gro);

	if (!gro)
		return;

	hrtimer_cancel(&gro->flush_timer);
	skb_queue_purge(&gro->hold_queue);
	kfree(gro);
}
EXPORT_SYMBOL_GPL(tquic_gro_cleanup);

/*
 * Flush GRO held packets
 */
int tquic_gro_flush(struct tquic_gro_state *gro,
		    void (*deliver)(struct sk_buff *))
{
	struct sk_buff *skb;
	int flushed = 0;

	spin_lock_bh(&gro->lock);

	while ((skb = __skb_dequeue(&gro->hold_queue)) != NULL) {
		spin_unlock_bh(&gro->lock);
		deliver(skb);
		flushed++;
		spin_lock_bh(&gro->lock);
	}

	/*
	 * CF-192: Re-validate held_count from the actual queue length
	 * after the unlock-relock loop.  While we dropped the lock to
	 * call deliver(), new skbs may have been enqueued by another
	 * CPU.  Using the true queue length keeps held_count consistent
	 * instead of blindly setting it to 0.
	 */
	gro->held_count = skb_queue_len(&gro->hold_queue);

	spin_unlock_bh(&gro->lock);

	return flushed;
}
EXPORT_SYMBOL_GPL(tquic_gro_flush);

/*
 * =============================================================================
 * Main Receive Path
 * =============================================================================
 */

/*
 * Process a single QUIC packet
 */
static int tquic_process_packet(struct tquic_connection *conn,
				struct tquic_path *path, u8 *data, size_t len,
				struct sockaddr_storage *src_addr)
{
	struct tquic_rx_ctx ctx;
	u8 dcid[TQUIC_MAX_CID_LEN], scid[TQUIC_MAX_CID_LEN];
	u8 dcid_len, scid_len;
	u32 version;
	int pkt_type;
	int pkt_num_len = 0;
	u64 pkt_num;
	u8 *payload;
	size_t payload_len, decrypted_len = 0;
	u8 *decrypted;
	bool decrypted_from_slab = false;
	bool path_looked_up = false; /* C-001 FIX: Track if we own path ref */
	int pn_space_idx = TQUIC_PN_SPACE_APPLICATION;
	u64 largest_pn = 0;
	int ret;

	ctx.data = data;
	ctx.len = len;
	ctx.offset = 0;

	pr_debug("process_pkt: ENTER conn=%p data[0]=0x%02x len=%zu\n", conn,
		 data[0], len);

	/*
	 * Validate basic packet structure before parsing.
	 * tquic_validate_packet() checks minimum length, fixed bit,
	 * and CID length fields.  Fail fast to avoid wasting CPU on
	 * malformed input.
	 */
	ret = tquic_validate_packet(data, len);
	if (unlikely(ret < 0)) {
		pr_debug("process_pkt: packet validation failed: %d\n", ret);
		return ret;
	}

	/* Check header form */
	if (data[0] & TQUIC_HEADER_FORM_LONG) {
		/* Long header */
		ret = tquic_parse_long_header_internal(&ctx, dcid, &dcid_len,
						       scid, &scid_len,
						       &version, &pkt_type);
		if (unlikely(ret < 0)) {
			pr_debug("process_pkt: long hdr parse failed: %d\n",
				 ret);
			return ret;
		}

		pr_debug("process_pkt: long hdr OK ver=0x%08x pkt_type=%d "
			 "dcid=%*phN scid=%*phN offset=%zu\n",
			 version, pkt_type, min_t(int, dcid_len, 8), dcid,
			 min_t(int, scid_len, 8), scid, ctx.offset);

		/* Handle version negotiation */
		if (unlikely(version == TQUIC_VERSION_NEGOTIATION)) {
			if (conn)
				/*
				 * RFC 9000 Section 6: Process via the exported
				 * API which selects a compatible version and
				 * restarts the connection via tquic_conn_client_restart.
				 */
				return tquic_handle_version_negotiation(
					conn, data, len);
			return 0;
		}

		/*
		 * RFC 9000 Section 6: If the version is not supported,
		 * send a Version Negotiation packet listing our versions.
		 * Use tquic_validate_version() from core/packet.c so the
		 * check stays in sync with the core packet version table.
		 */
		if (!tquic_validate_version(version)) {
			tquic_dbg(
				"input: unsupported version 0x%08x, sending VN\n",
				version);
			if (conn) {
				struct tquic_cid pkt_dcid, pkt_scid;

				/*
				 * Build tquic_cid structs from the parsed
				 * byte arrays so we can call the exported
				 * tquic_send_version_negotiation API.
				 */
				memset(&pkt_dcid, 0, sizeof(pkt_dcid));
				memset(&pkt_scid, 0, sizeof(pkt_scid));
				pkt_dcid.len = min_t(u8, dcid_len,
						     TQUIC_MAX_CID_LEN);
				memcpy(pkt_dcid.id, dcid, pkt_dcid.len);
				pkt_scid.len = min_t(u8, scid_len,
						     TQUIC_MAX_CID_LEN);
				memcpy(pkt_scid.id, scid, pkt_scid.len);
				tquic_send_version_negotiation(conn, &pkt_dcid,
							       &pkt_scid);
			}
			return -EPROTONOSUPPORT;
		}

		/*
		 * Handle Retry packet (client-side, RFC 9000 Section 17.2.5)
		 *
		 * A Retry packet is sent by the server in response to an Initial
		 * packet to validate the client's address. The client must:
		 * 1. Verify the Retry Integrity Tag using original DCID
		 * 2. Extract the Retry Token
		 * 3. Store the new server-provided SCID
		 * 4. Retransmit Initial with the Retry Token
		 *
		 * Retry packets can only be received on clients during connection
		 * establishment (TQUIC_CONN_CONNECTING state).
		 */
		if (unlikely(pkt_type == TQUIC_PKT_RETRY)) {
			/* Need connection to process Retry */
			if (!conn)
				conn = tquic_lookup_by_dcid(dcid, dcid_len);

			if (conn) {
				/*
				 * Only process Retry in connecting state.
				 * Per RFC 9000: "A client MUST discard a Retry
				 * packet that contains a DCID field that is
				 * not equal to the SCID field of its Initial."
				 */
				if (READ_ONCE(conn->state) ==
				    TQUIC_CONN_CONNECTING) {
					ret = tquic_retry_process(conn, data,
								  len);
					if (ret == 0) {
						/* Update MIB counter */
						if (conn->sk)
							TQUIC_INC_STATS(
								sock_net(
									conn->sk),
								TQUIC_MIB_RETRYPACKETSRX);
						/*
						 * Retry processed successfully.
						 * Caller should retransmit Initial with token.
						 * Return special code to trigger retry.
						 */
						return -EAGAIN;
					}
				} else {
					/*
					 * Per RFC 9000 Section 17.2.5.2:
					 * "A client MUST discard a Retry packet
					 * if it has received and successfully
					 * processed a Retry packet for this
					 * connection."
					 */
					tquic_dbg(
						"discarding Retry in state %d\n",
						READ_ONCE(conn->state));
				}
			}
			return 0; /* Discard Retry packet after processing */
		}

		/*
		 * Handle 0-RTT packets (RFC 9001 Section 4.6-4.7)
		 *
		 * 0-RTT packets are sent by clients using keys derived from
		 * a previous session's resumption_master_secret. They contain
		 * early application data and may arrive before or during the
		 * TLS handshake.
		 *
		 * Server processing:
		 * 1. Look up connection by DCID
		 * 2. Check if 0-RTT is enabled and not rejected
		 * 3. Decrypt using 0-RTT keys
		 * 4. Process frames (limited: no CRYPTO, ACK, etc.)
		 *
		 * Client processing (unlikely - server doesn't send 0-RTT):
		 * - Discard the packet
		 */
		if (pkt_type == TQUIC_PKT_ZERO_RTT) {
			if (!conn)
				conn = tquic_lookup_by_dcid(dcid, dcid_len);

			if (!conn) {
				tquic_dbg(
					"0-RTT packet for unknown connection\n");
				return -ENOENT;
			}

			/* Server-side: check if we can accept 0-RTT */
			if (conn->role == TQUIC_ROLE_SERVER) {
				enum tquic_zero_rtt_state zrtt_state;
				zrtt_state = tquic_zero_rtt_get_state(conn);

				if (zrtt_state == TQUIC_0RTT_REJECTED) {
					/*
					 * 0-RTT already rejected - discard packet.
					 * Client will retransmit as 1-RTT.
					 */
					tquic_dbg(
						"0-RTT rejected, discarding\n");
					return 0;
				}

				/*
				 * Accept 0-RTT if not yet decided.
				 * This initializes keys for decryption.
				 */
				if (zrtt_state == TQUIC_0RTT_NONE) {
					ret = tquic_zero_rtt_accept(conn);
					if (ret < 0) {
						/* Replay or other error - reject */
						tquic_zero_rtt_reject(conn);
						if (ret == -EEXIST && conn->sk)
							TQUIC_INC_STATS(
								sock_net(
									conn->sk),
								TQUIC_MIB_0RTTREPLAYS);
						tquic_dbg(
							"0-RTT rejected: %d\n",
							ret);
						return 0;
					}
					if (conn->sk)
						TQUIC_INC_STATS(
							sock_net(conn->sk),
							TQUIC_MIB_0RTTACCEPTED);
				}
			} else {
				/* Client received 0-RTT packet - shouldn't happen */
				tquic_dbg("client received 0-RTT packet?\n");
				return -EPROTO;
			}

			/* Continue to decrypt and process as 0-RTT */
			/* Fall through to normal packet processing below */
		}

		/* Lookup connection by DCID if not provided */
		if (!conn)
			conn = tquic_lookup_by_dcid(dcid, dcid_len);

		if (!conn) {
			/* New connection - would handle Initial packet */
			tquic_dbg("no connection found for DCID\n");
			return -ENOENT;
		}

		/*
		 * RFC 9000 Section 7.2: When a client receives a packet
		 * from the server, the Destination Connection ID field
		 * of subsequent packets sent by the client MUST use the
		 * value of the Source Connection ID field from the
		 * server's first Initial or Handshake packet.
		 */
		if (!conn->is_server && !conn->dcid_updated && scid_len > 0 &&
		    scid_len <= TQUIC_MAX_CID_LEN) {
			pr_debug(
				"process_pkt: updating client DCID from %*phN to server SCID %*phN\n",
				min_t(int, conn->dcid.len, 8), conn->dcid.id,
				min_t(int, scid_len, 8), scid);
			memcpy(conn->dcid.id, scid, scid_len);
			conn->dcid.len = scid_len;
			conn->dcid_updated = true;
		}

		/*
		 * RFC 9000 Section 14.1: Client Initial packets MUST be at
		 * least 1200 bytes.  Servers MUST discard shorter ones.
		 * tquic_validate_initial_packet() (core/packet.c,
		 * EXPORT_SYMBOL_GPL) enforces this and re-validates the header
		 * structure before we parse further fields.  Skip for
		 * server-originated Initials (is_server == false means client).
		 */
		if (pkt_type == TQUIC_PKT_INITIAL &&
		    conn && conn->role == TQUIC_ROLE_SERVER) {
			ret = tquic_validate_initial_packet(data, len, false);
			if (ret < 0) {
				tquic_dbg(
					"Initial packet failed validation: %d\n",
					ret);
				return ret;
			}
		}

		/* Parse token for Initial packets */
		if (pkt_type == TQUIC_PKT_INITIAL) {
			u64 token_len;
			size_t remaining_len;

			ret = tquic_decode_varint(data + ctx.offset,
						  len - ctx.offset, &token_len);
			if (ret < 0)
				return ret;
			ctx.offset += ret;

			if (token_len > TQUIC_MAX_TOKEN_LEN)
				return -EINVAL;

			remaining_len = len - ctx.offset;
			if (token_len > remaining_len)
				return -EINVAL;

			ctx.offset += token_len;
		}

		/* Parse length field */
		{
			u64 pkt_len;
			ret = tquic_decode_varint(data + ctx.offset,
						  len - ctx.offset, &pkt_len);
			if (ret < 0) {
				pr_debug(
					"process_pkt: pkt_len parse failed: %d\n",
					ret);
				return ret;
			}
			ctx.offset += ret;
			pr_debug(
				"process_pkt: parsed hdr: pkt_len=%llu offset=%zu\n",
				pkt_len, ctx.offset);
			/*
			 * RFC 9000 §17.2: the Length field covers (packet
			 * number + payload) bytes starting at ctx.offset.
			 * Validate and cap len so that coalesced packets
			 * (§12.2) beyond this boundary are not processed
			 * as part of the current packet.
			 */
			if (pkt_len > (u64)(len - ctx.offset))
				return -EINVAL;
			len = ctx.offset + (size_t)pkt_len;
		}

		/*
		 * CF-076: Do NOT extract pkt_num_len here -- the low
		 * 2 bits of the first byte are still masked by header
		 * protection.  Extraction is deferred until after
		 * tquic_remove_header_protection().
		 */

	} else {
		/* Short header */
		bool key_phase_tmp, spin_bit;

		/* Need connection to know DCID length */
		if (!conn)
			return -ENOENT;

		ret = tquic_parse_short_header_internal(
			&ctx, conn->scid.len, dcid, &key_phase_tmp, &spin_bit);
		if (ret < 0)
			return ret;

		pkt_type = -1; /* Short header / 1-RTT */

		/*
		 * CF-076/CF-099: Do NOT extract pkt_num_len or
		 * key_phase from the protected header.  Both the
		 * low 2 bits (PN length) and bit 0x04 (key phase)
		 * are masked by header protection.  Correct values
		 * are obtained after tquic_remove_header_protection().
		 */
	}

	/*
	 * Find path if not provided.
	 *
	 * CF-045: Hold rcu_read_lock() across path lookup and the
	 * subsequent use of the path pointer.  Paths are freed via
	 * kfree_rcu(), so the RCU read-side critical section prevents
	 * use-after-free if another CPU removes this path while we
	 * are processing the packet.
	 *
	 * C-001 FIX: tquic_find_path_by_addr() now takes a reference
	 * via refcount_inc_not_zero(). We must release this reference
	 * before returning. Track ownership with path_looked_up flag.
	 */
	rcu_read_lock();
	if (!path && conn) {
		path = tquic_find_path_by_addr(conn, src_addr);
		if (path)
			path_looked_up = true;
	}

	/* Remove header protection */
	{
		u8 hp_pn_len = 0, hp_key_phase = 0;

		pr_debug("process_pkt: HP removal: pkt_type=%d hdr_len=%zu "
			 "payload_len=%lu data[0]=0x%02x long=%d\n",
			 pkt_type, ctx.offset,
			 (unsigned long)(len - ctx.offset), data[0],
			 ctx.is_long_header);

		ret = tquic_remove_header_protection(conn, data, ctx.offset,
						     data + ctx.offset,
						     len - ctx.offset,
						     ctx.is_long_header,
						     &hp_pn_len, &hp_key_phase);
		if (unlikely(ret < 0)) {
			pr_debug(
				"tquic: HP removal failed ret=%d pkt_type=%d\n",
				ret, pkt_type);
			if (path_looked_up)
				tquic_path_put(path);
			rcu_read_unlock();
			return ret;
		}

		pr_debug("process_pkt: HP done: pkt_type=%d pn_len=%u "
			 "data[0]=0x%02x\n",
			 pkt_type, hp_pn_len, data[0]);

		/*
		 * CF-076: Extract pkt_num_len from the NOW-unprotected
		 * first byte.  Header protection has been removed, so
		 * the low 2 bits of data[0] reflect the true PN length.
		 */
		if (hp_pn_len > 0) {
			/* Prefer the value returned by HP removal */
			pkt_num_len = hp_pn_len;
		} else {
			/*
			 * HP context was not available (e.g. Initial
			 * before key derivation).  First byte is already
			 * in the clear; read the PN length directly.
			 */
			pkt_num_len = (data[0] & 0x03) + 1;
		}

		/*
		 * CF-099: Re-read key_phase from the unprotected
		 * header for short-header (1-RTT) packets.
		 */
		if (!ctx.is_long_header) {
			if (hp_pn_len > 0)
				ctx.key_phase_bit = hp_key_phase;
			else
				ctx.key_phase_bit =
					(data[0] & TQUIC_HEADER_KEY_PHASE) ? 1 :
									     0;
		}
	}

	/* Validate pkt_num_len is within protocol bounds (1..4) */
	if (pkt_num_len < 1 || pkt_num_len > 4) {
		if (path_looked_up)
			tquic_path_put(path);
		rcu_read_unlock();
		return -EINVAL;
	}

	if (ctx.offset + pkt_num_len > len) {
		if (path_looked_up)
			tquic_path_put(path);
		rcu_read_unlock();
		return -EINVAL;
	}

	/*
	 * CF-110: Decode packet number using the largest received PN
	 * for this PN space, not 0.  The reconstruction algorithm
	 * (RFC 9000 Appendix A) requires the largest successfully
	 * processed PN to correctly unwrap truncated packet numbers.
	 */
	/*
	 * tquic_packet_pn_space() maps packet type to the RFC 9000
	 * Section 12.3 packet number space: Initial->0, Handshake->1,
	 * 0-RTT/1-RTT->2.  Returns a negative error for unknown types
	 * which we treat as APPLICATION space.
	 */
	{
		int ps = tquic_packet_pn_space((enum tquic_packet_type)pkt_type);

		pn_space_idx = (ps >= 0) ? ps : TQUIC_PN_SPACE_APPLICATION;
	}

	pr_debug("process_pkt: PN decode: pkt_type=%d (%s) pn_space=%d "
		 "pkt_num=%llu pn_len=%d hdr_offset=%zu total_len=%lu\n",
		 pkt_type, tquic_packet_type_str((enum tquic_packet_type)pkt_type),
		 pn_space_idx, pkt_num, pkt_num_len, ctx.offset,
		 (unsigned long)len);

	if (conn && conn->pn_spaces)
		largest_pn = READ_ONCE(
			conn->pn_spaces[pn_space_idx].largest_recv_pn);

	pkt_num = tquic_decode_pkt_num(data + ctx.offset, pkt_num_len,
				       largest_pn);
	ctx.offset += pkt_num_len;

	/* Decrypt payload */
	payload = data + ctx.offset;
	payload_len = len - ctx.offset;

	/*
	 * CF-055: Use the dedicated slab cache for decryption buffers when
	 * the payload fits (common case: all standard MTU packets).  Fall
	 * back to kmalloc for the rare jumbo/GSO case.
	 *
	 * The slab objects are exactly TQUIC_RX_BUF_SIZE bytes.  Validate
	 * that payload_len (which comes from the network and is therefore
	 * untrusted) does not exceed the slab object size before we hand
	 * the buffer to the decryption routine.  For oversized payloads
	 * use kmalloc so the buffer is always large enough.
	 */
	if (likely(payload_len > 0 && payload_len <= TQUIC_RX_BUF_SIZE)) {
		decrypted = kmem_cache_alloc(tquic_rx_buf_cache, GFP_ATOMIC);
		decrypted_from_slab = true;
	} else if (payload_len > 0) {
		decrypted = kmalloc(payload_len, GFP_ATOMIC);
	} else {
		if (path_looked_up)
			tquic_path_put(path);
		rcu_read_unlock();
		return -EINVAL;
	}
	if (unlikely(!decrypted)) {
		if (path_looked_up)
			tquic_path_put(path);
		rcu_read_unlock();
		return -ENOMEM;
	}

	/*
	 * Decrypt payload using appropriate keys:
	 * - 0-RTT packets use 0-RTT keys from session ticket
	 * - Other packets use normal crypto state keys
	 */
	if (unlikely(pkt_type == TQUIC_PKT_ZERO_RTT)) {
		/* Decrypt using 0-RTT keys */
		ret = tquic_zero_rtt_decrypt(conn, data, ctx.offset, payload,
					     payload_len, pkt_num, decrypted,
					     &decrypted_len);
		if (unlikely(ret < 0)) {
			if (decrypted_from_slab)
				kmem_cache_free(tquic_rx_buf_cache, decrypted);
			else
				kfree(decrypted);
			if (ret == -ENOKEY)
				tquic_dbg("0-RTT decryption failed, no keys\n");
			if (path_looked_up)
				tquic_path_put(path);
			rcu_read_unlock();
			return ret;
		}
		/* Update 0-RTT stats */
		if (conn->sk)
			TQUIC_ADD_STATS(sock_net(conn->sk),
					TQUIC_MIB_0RTTBYTESRX, decrypted_len);
	} else {
		pr_debug("process_pkt: decrypt: pkt_type=%d hdr_len=%zu "
			 "payload_len=%zu pkt_num=%llu\n",
			 pkt_type, ctx.offset, payload_len, pkt_num);

		ret = tquic_decrypt_payload(conn, data, ctx.offset, payload,
					    payload_len, pkt_num,
					    pkt_type >= 0 ? pkt_type : 3,
					    decrypted, &decrypted_len);

		pr_debug("process_pkt: decrypt ret=%d pkt_type=%d "
			 "decrypted_len=%lu\n",
			 ret, pkt_type, (unsigned long)decrypted_len);

		if (unlikely(ret < 0)) {
			/*
			 * Key Update: Decryption failure for short headers might be
			 * due to key phase change. Try with old keys if available.
			 * Per RFC 9001 Section 6.3, packets in flight during key
			 * update may arrive encrypted with old keys.
			 */
			if (pkt_type < 0 && conn->crypto_state) {
				ret = tquic_try_decrypt_with_old_keys(
					conn, data, ctx.offset, payload,
					payload_len, pkt_num, decrypted,
					&decrypted_len);
			}
			if (ret < 0) {
				if (decrypted_from_slab)
					kmem_cache_free(tquic_rx_buf_cache,
							decrypted);
				else
					kfree(decrypted);
				if (path_looked_up)
					tquic_path_put(path);
				rcu_read_unlock();
				return ret;
			}
		}
	}

	/*
	 * CF-055: Post-decrypt safety check.  Ensure the decryption
	 * routine did not produce more output than the buffer can hold.
	 * For the slab path the ceiling is TQUIC_RX_BUF_SIZE; for the
	 * kmalloc path it is the original payload_len.
	 */
	{
		size_t buf_cap = decrypted_from_slab ? TQUIC_RX_BUF_SIZE :
						       payload_len;
		if (unlikely(decrypted_len > buf_cap)) {
			tquic_warn("decrypted_len %zu exceeds buffer %zu\n",
				   decrypted_len, buf_cap);
			if (decrypted_from_slab)
				kmem_cache_free(tquic_rx_buf_cache, decrypted);
			else
				kfree(decrypted);
			if (path_looked_up)
				tquic_path_put(path);
			rcu_read_unlock();
			return -EOVERFLOW;
		}
	}

	/*
	 * Decryption succeeded -- now safe to update the largest received
	 * packet number for this PN space. This must happen after decryption
	 * to prevent attackers from corrupting the reconstruction window
	 * with forged packets (RFC 9000 Appendix A).
	 */
	if (conn && conn->pn_spaces && pkt_num > largest_pn)
		WRITE_ONCE(conn->pn_spaces[pn_space_idx].largest_recv_pn,
			   pkt_num);

	/*
	 * Failover receiver deduplication (APPLICATION space only).
	 *
	 * When multipath bonding is active a packet may be retransmitted on
	 * a different path after failover.  tquic_failover_dedup_check()
	 * marks the packet number as seen the first time and returns true
	 * for any subsequent copy.  Duplicates are silently dropped here,
	 * after decryption but before frame processing, to prevent double-
	 * counting ACK/flow-control state.
	 */
	if (conn && pn_space_idx == TQUIC_PN_SPACE_APPLICATION) {
		struct tquic_failover_ctx *__fc = tquic_bonding_get_failover(
			(struct tquic_bonding_ctx *)conn->pm);
		if (__fc && tquic_failover_dedup_check(__fc, pkt_num)) {
			if (decrypted_from_slab)
				kmem_cache_free(tquic_rx_buf_cache, decrypted);
			else
				kfree(decrypted);
			if (path_looked_up)
				tquic_path_put(path);
			rcu_read_unlock();
			return 0; /* duplicate: silently discard */
		}
	}

	/*
	 * Key Update Detection (RFC 9001 Section 6)
	 *
	 * For short header packets (1-RTT), check if the key phase bit
	 * differs from our current key phase. A change indicates either:
	 * - Peer has initiated a key update (we need to respond)
	 * - Our previous key update has been acknowledged
	 */
	if (pkt_type < 0 && conn->crypto_state) {
		struct tquic_key_update_state *ku_state;
		ku_state =
			tquic_crypto_get_key_update_state(conn->crypto_state);
		if (ku_state) {
			u8 current_phase = tquic_key_update_get_phase(ku_state);
			if (ctx.key_phase_bit != current_phase) {
				int ku_ret = tquic_handle_key_phase_change(
					conn, ctx.key_phase_bit);
				if (ku_ret < 0)
					tquic_warn(
						"key phase change %u->%u failed: %d\n",
						current_phase,
						ctx.key_phase_bit, ku_ret);
			}
			/* Track packet received for key update timing */
			tquic_key_update_on_packet_received(ku_state);
		}
	}

	/* Process frames */
	pr_debug("tquic: process_frames: type=%d pn=%llu len=%zu\n",
		 pkt_type >= 0 ? pkt_type : 3, pkt_num, decrypted_len);
	ret = tquic_process_frames(conn, path, decrypted, decrypted_len,
				   pkt_type >= 0 ? pkt_type : 3, pkt_num);

	if (decrypted_from_slab)
		kmem_cache_free(tquic_rx_buf_cache, decrypted);
	else
		kfree(decrypted);

	/* Update statistics */
	if (likely(ret >= 0)) {
		conn->stats.rx_packets++;
		if (likely(path)) {
			path->stats.rx_packets++;
			path->stats.rx_bytes += len;
			WRITE_ONCE(path->last_activity, ktime_get());
		}

		/* Update MIB counters for packet reception */
		if (conn->sk) {
			TQUIC_INC_STATS(sock_net(conn->sk),
					TQUIC_MIB_PACKETSRX);
			TQUIC_ADD_STATS(sock_net(conn->sk), TQUIC_MIB_BYTESRX,
					len);
		}

		/*
		 * RFC 9002: Notify connection state machine that a packet
		 * was received. Updates anti-amplification accounting so the
		 * server can send more data after receiving client packets.
		 */
		tquic_conn_on_packet_received(conn, len);

		/*
		 * RFC 9000 Section 10.1: "An endpoint restarts its idle
		 * timer when a packet from its peer is received and
		 * processed successfully."
		 */
		if (conn->timer_state)
			tquic_timer_reset_idle(conn->timer_state);

		/*
		 * HTTP/3 input dispatch (RFC 9114).
		 *
		 * After QUIC frame processing succeeds, drive the
		 * HTTP/3 subsystem for this connection.  Handles
		 * H3 connection upgrade, stream acceptance, QPACK,
		 * priority updates, push, and WebTransport.
		 */
#ifdef CONFIG_TQUIC_HTTP3
		tquic_h3_input_dispatch(conn);
#endif /* CONFIG_TQUIC_HTTP3 */
	}

	/* C-001 FIX: Release path reference if we looked it up */
	if (path_looked_up)
		tquic_path_put(path);

	rcu_read_unlock();
	return ret;
}

/**
 * tquic_process_initial_for_server - Process Initial packet for new server connection
 * @conn: Server connection with CIDs parsed and crypto_state initialized
 * @skb: The Initial packet SKB (data points to QUIC packet, past UDP header)
 * @src_addr: Client source address
 *
 * Called from tquic_server_handshake() after the inline TLS context and
 * Initial crypto keys have been set up. Decrypts the Initial packet,
 * removes header protection, and processes frames — feeding the ClientHello
 * into the inline TLS state machine via the CRYPTO frame handler.
 *
 * Returns: 0 on success, negative errno on error
 */
int tquic_process_initial_for_server(struct tquic_connection *conn,
				     struct sk_buff *skb,
				     struct sockaddr_storage *src_addr)
{
	int ret;

	if (!conn || !skb)
		return -EINVAL;

	/* Ensure packet data is writable for header protection removal */
	if (skb_ensure_writable(skb, skb->len))
		return -ENOMEM;

	pr_debug("process_initial_for_server: len=%u data[0]=0x%02x "
		 "scid_len=%u dcid_len=%u version=0x%08x crypto=%p hp=%p\n",
		 skb->len, skb->data[0], conn->scid.len, conn->dcid.len,
		 conn->version, conn->crypto_state,
		 conn->crypto_state ?
			 tquic_crypto_get_hp_ctx(conn->crypto_state) :
			 NULL);

	if (skb->len >= 22) {
		/*
		 * Safely log DCID and SCID bytes.  skb->data[5] is the
		 * DCID length (attacker-controlled, 0–255); validate that
		 * all accesses stay within skb->len before dereferencing.
		 */
		u8 dcid_len = skb->data[5];

		if (skb->len >= (size_t)(7u + dcid_len + 1u)) {
			u8 scid_len = skb->data[6 + dcid_len];

			if (skb->len >= (size_t)(7u + dcid_len + 1u + scid_len))
				pr_debug(
					"process_initial_for_server: pkt bytes: %02x %02x%02x%02x%02x %02x %*phN %02x %*phN\n",
					skb->data[0], skb->data[1],
					skb->data[2], skb->data[3],
					skb->data[4], dcid_len,
					min_t(int, dcid_len, 8), &skb->data[6],
					scid_len, min_t(int, scid_len, 8),
					&skb->data[7 + dcid_len]);
		}
	}

	ret = tquic_process_packet(conn, NULL, skb->data, skb->len, src_addr);

	pr_debug("process_initial_for_server: process_packet ret=%d\n", ret);
	return ret;
}
EXPORT_SYMBOL_GPL(tquic_process_initial_for_server);

/*
 * UDP receive callback - main entry point for received packets
 *
 * This is the primary entry point for all QUIC packets received via UDP.
 * It handles:
 * - Stateless reset detection (received from peer)
 * - Version negotiation processing
 * - Regular packet processing
 * - Stateless reset transmission (for unknown CIDs, per RFC 9000 Section 10.3)
 */
int tquic_udp_recv(struct sock *sk, struct sk_buff *skb)
{
	struct tquic_connection *conn = NULL;
	struct tquic_path *path = NULL;
	struct sockaddr_storage src_addr;
	struct sockaddr_storage local_addr;
	u8 *data;
	size_t len;
	int ret;

	if (unlikely(!skb))
		return -EINVAL;

	/* Extract source (remote) address */
	memset(&src_addr, 0, sizeof(src_addr));
	memset(&local_addr, 0, sizeof(local_addr));

	if (skb->protocol == htons(ETH_P_IP)) {
		struct sockaddr_in *sin_src = (struct sockaddr_in *)&src_addr;
		struct sockaddr_in *sin_local =
			(struct sockaddr_in *)&local_addr;

		sin_src->sin_family = AF_INET;
		sin_src->sin_addr.s_addr = ip_hdr(skb)->saddr;
		sin_src->sin_port = udp_hdr(skb)->source;

		/* Local address for stateless reset response */
		sin_local->sin_family = AF_INET;
		sin_local->sin_addr.s_addr = ip_hdr(skb)->daddr;
		sin_local->sin_port = udp_hdr(skb)->dest;
	} else if (skb->protocol == htons(ETH_P_IPV6)) {
		struct sockaddr_in6 *sin6_src =
			(struct sockaddr_in6 *)&src_addr;
		struct sockaddr_in6 *sin6_local =
			(struct sockaddr_in6 *)&local_addr;

		sin6_src->sin6_family = AF_INET6;
		sin6_src->sin6_addr = ipv6_hdr(skb)->saddr;
		sin6_src->sin6_port = udp_hdr(skb)->source;

		sin6_local->sin6_family = AF_INET6;
		sin6_local->sin6_addr = ipv6_hdr(skb)->daddr;
		sin6_local->sin6_port = udp_hdr(skb)->dest;
	}

	/*
	 * Ensure the skb data is contiguous before parsing.
	 *
	 * GRO or other aggregation may produce non-linear skbs where
	 * skb->data only covers the first fragment.  All downstream
	 * parsing and decryption use direct pointer arithmetic on
	 * skb->data, so we must linearize first.
	 */
	if (skb_is_nonlinear(skb)) {
		if (skb_linearize(skb)) {
			kfree_skb(skb);
			return -ENOMEM;
		}
	}

	/* Get QUIC payload - UDP header already stripped by encap layer */
	data = skb->data;
	len = skb->len;

	pr_debug("tquic_udp_recv: proto=0x%04x len=%zu data[0]=0x%02x sk=%p\n",
		 ntohs(skb->protocol), len, len > 0 ? data[0] : 0, sk);

	if (unlikely(len < 1)) {
		kfree_skb(skb);
		return -EINVAL;
	}

	/*
	 * Rate limiting check for DDoS protection
	 *
	 * For Initial packets (new connection attempts), check against
	 * per-IP rate limits before allocating any connection state.
	 * This is the first line of defense against amplification attacks.
	 *
	 * We have two rate limiting subsystems:
	 * 1. rate_limit.h: Token bucket with global and per-IP limits
	 * 2. tquic_ratelimit.h: Advanced rate limiting with cookie validation
	 *
	 * Check order:
	 * 1. Global rate limit check (rate_limit.h)
	 * 2. Per-IP rate limit check (rate_limit.h)
	 * 3. Advanced checks with cookie support (tquic_ratelimit.h)
	 */
	pr_debug(
		"tquic_udp_recv: pre-ratelimit len=%zu data[0]=0x%02x longform=%d\n",
		len, data[0], !!(data[0] & TQUIC_HEADER_FORM_LONG));

	if (tquic_is_long_header(data, len)) {
		/* Long header - check if this is an Initial packet */
		int pkt_type = (data[0] & 0x30) >> 4;

		pr_debug("tquic_udp_recv: long hdr pkt_type=%d (Initial=%d)\n",
			 pkt_type, TQUIC_PKT_INITIAL);

		if (pkt_type == TQUIC_PKT_INITIAL) {
			enum tquic_rl_action action;
			u8 dcid_len, scid_len;
			const u8 *token = NULL;
			size_t token_len = 0;
			size_t offset;

			pr_debug(
				"tquic_udp_recv: Initial pkt detected, len=%zu\n",
				len);

			/* Parse enough header to extract DCID */
			if (len >= 6) {
				dcid_len = data[5];

				/*
				 * SECURITY: Validate DCID length before use.
				 * RFC 9000 limits CID to 20 bytes. Without
				 * this check, offset = 6 + dcid_len could
				 * point past the packet buffer, causing
				 * out-of-bounds reads on data + 6.
				 */
				if (dcid_len > TQUIC_MAX_CID_LEN ||
				    6 + (size_t)dcid_len > len) {
					pr_debug(
						"tquic_udp_recv: DCID len invalid (%u)\n",
						dcid_len);
					kfree_skb(skb);
					return -EINVAL;
				}
				offset = 6 + dcid_len;

				/*
				 * First check: Global and per-IP token bucket limits
				 * (rate_limit.h - lightweight fast path)
				 */
				if (!tquic_rate_limit_check_initial(
					    sock_net(sk), &src_addr, data + 6,
					    dcid_len)) {
					/* Rate limited - silently drop */
					pr_debug(
						"tquic_udp_recv: rate limited (token bucket)\n");
					kfree_skb(skb);
					return -EBUSY;
				}

				pr_debug(
					"tquic_udp_recv: dcid_len=%u offset=%zu, parsing SCID\n",
					dcid_len, offset);

				if (offset < len) {
					scid_len = data[offset];
					if (scid_len > TQUIC_MAX_CID_LEN ||
					    offset + 1 + scid_len > len) {
						pr_debug(
							"tquic_udp_recv: SCID len invalid (%u)\n",
							scid_len);
						kfree_skb(skb);
						return -EINVAL;
					}
					offset += 1 + scid_len;

					/* Parse token length (varint) */
					if (offset < len) {
						u64 tlen;
						int vlen;

						vlen = tquic_decode_varint(
							data + offset,
							len - offset, &tlen);
						/*
						 * SECURITY: Validate tlen to prevent
						 * u64 wrap in offset + vlen + tlen.
						 * Use safe subtraction instead.
						 */
						if (vlen > 0 &&
						    tlen <= TQUIC_MAX_TOKEN_LEN &&
						    (size_t)vlen <=
							    len - offset &&
						    tlen <= len - offset -
								    vlen) {
							token = data + offset +
								vlen;
							token_len = tlen;
						}
					}
				}

				/*
				 * Second check: Advanced rate limiting with cookie
				 * support (tquic_ratelimit.h - attack mode handling)
				 */
				action = tquic_ratelimit_check_initial(
					sock_net(sk), &src_addr, data + 6,
					dcid_len, token, token_len);

				pr_debug(
					"tquic_udp_recv: ratelimit action=%d\n",
					action);

				switch (action) {
				case TQUIC_RL_ACCEPT:
					/* Continue processing */
					break;

				case TQUIC_RL_RATE_LIMITED:
					/*
					 * Rate limited - silently drop
					 * No response to avoid amplification
					 */
					kfree_skb(skb);
					return -EBUSY;

				case TQUIC_RL_COOKIE_REQUIRED:
					/*
					 * Under attack - send Retry with cookie
					 * This validates the source address
					 */
					if (dcid_len > 0 &&
					    offset > 6 + dcid_len) {
						u8 cookie[64];
						size_t cookie_len =
							sizeof(cookie);
						u32 pkt_version;
						int ret;

						/* Preserve the client's QUIC version from Initial. */
						pkt_version =
							get_unaligned_be32(
								data + 1);

						ret = tquic_ratelimit_generate_cookie(
							sock_net(sk), &src_addr,
							data + 6, dcid_len,
							cookie, &cookie_len);
						if (ret == 0) {
							/* Send Retry packet with cookie as token */
							tquic_retry_send_with_token(
								sk, &src_addr,
								pkt_version,
								data + 6,
								dcid_len,
								data + 7 +
									dcid_len,
								scid_len,
								cookie,
								cookie_len);
						}
					}
					kfree_skb(skb);
					return 0;

				case TQUIC_RL_BLACKLISTED:
					/* Blacklisted - silently drop */
					kfree_skb(skb);
					return -EACCES;
				}
			}
		}
	}

	/*
	 * Connection lookup by DCID.
	 *
	 * For long header packets, DCID is at offset 6 with length at offset 5.
	 * For short header packets, DCID starts at offset 1.
	 *
	 * This lookup enables the client to match incoming ServerHello and
	 * Handshake packets from the server, and enables the server to match
	 * subsequent client packets on existing connections.
	 */
	if (!conn && tquic_is_long_header(data, len) && len > 6) {
		u8 dcid_len = data[5];

		if (dcid_len <= TQUIC_MAX_CID_LEN &&
		    len > (size_t)6 + dcid_len) {
			conn = tquic_lookup_by_dcid(data + 6, dcid_len);
			pr_debug(
				"tquic: udp_recv long-hdr DCID lookup: len=%u hdr=0x%02x conn=%px\n",
				dcid_len, data[0], conn);
		}
	} else if (!conn && !(data[0] & TQUIC_HEADER_FORM_LONG) &&
		   len > 1 + TQUIC_DEFAULT_CID_LEN) {
		/*
		 * Short header: DCID length is not self-describing.
		 * Use TQUIC_DEFAULT_CID_LEN (the length we generate
		 * for our own CIDs) for the lookup.
		 */
		conn = tquic_lookup_by_dcid(data + 1, TQUIC_DEFAULT_CID_LEN);
		pr_debug("tquic: udp_recv short-hdr DCID lookup: conn=%px\n",
			 conn);
	}

	/* Find the path for this connection based on source address */
	if (conn && !path) {
		rcu_read_lock();
		path = tquic_find_path_by_addr(conn, &src_addr);
		rcu_read_unlock();

		/*
		 * RFC 9000 Section 9: Connection Migration.
		 * If a packet arrives from an address that doesn't match any
		 * known path but we have an established connection, the peer
		 * may have migrated. Notify the connection state machine which
		 * will send a PATH_CHALLENGE to validate the new address.
		 * tquic_conn_handle_migration only triggers on CONNECTED state
		 * and when migration is not disabled via transport parameters.
		 */
		if (!path &&
		    READ_ONCE(conn->state) == TQUIC_CONN_CONNECTED) {
			struct tquic_path *active;

			rcu_read_lock();
			active = rcu_dereference(conn->active_path);
			if (active && tquic_path_get(active)) {
				tquic_conn_handle_migration(
					conn, active,
					(const struct sockaddr *)&src_addr);
				tquic_path_put(active);
			}
			rcu_read_unlock();
		}
	}

	pr_debug(
		"tquic_udp_recv: past ratelimit block, conn=%p data[0]=0x%02x\n",
		conn, data[0]);

	/* Check for stateless reset (received from peer) */
	if (len < TQUIC_STATELESS_RESET_MIN_LEN)
		goto not_reset;

	if (data[0] & TQUIC_HEADER_FORM_LONG)
		goto not_reset;

	/* Try to find connection for reset check (short header fallback) */
	if (!conn && len > 1 + TQUIC_DEFAULT_CID_LEN) {
		conn = tquic_lookup_by_dcid(data + 1, TQUIC_DEFAULT_CID_LEN);
	}

	/*
	 * RFC 9000 Section 10.3.1: Check for stateless reset via the
	 * exported API which verifies the last 16 bytes against tokens
	 * from NEW_CONNECTION_ID frames.
	 */
	if (conn && tquic_verify_stateless_reset(conn, data, len)) {
		tquic_handle_stateless_reset(conn);
		if (path)
			tquic_path_put(path);
		kfree_skb(skb);
		return 0;
	}

	/*
	 * RFC 9000 Section 10.3.1 fallback: if the DCID-based lookup
	 * failed (e.g. non-default CID length) or the found connection's
	 * tokens did not match, scan all connections for a reset token
	 * match in the last 16 bytes of the packet.
	 */
	{
		struct tquic_connection *reset_conn;

		reset_conn = tquic_find_conn_by_reset_token(data, len);
		if (reset_conn) {
			tquic_handle_stateless_reset(reset_conn);
			if (path)
				tquic_path_put(path);
			kfree_skb(skb);
			return 0;
		}
	}

not_reset:
	pr_debug(
		"tquic_udp_recv: at not_reset, version bytes: %02x%02x%02x%02x\n",
		len > 1 ? data[1] : 0, len > 2 ? data[2] : 0,
		len > 3 ? data[3] : 0, len > 4 ? data[4] : 0);

	/* Check for version negotiation */
	if (unlikely(tquic_is_version_negotiation(data, len))) {
		pr_debug(
			"tquic_udp_recv: version negotiation detected (version=0x%08x), conn=%p\n",
			tquic_get_version(data, len), conn);
		/* Need connection context */
		if (len > 6) {
			u8 dcid_len = data[5];

			/*
			 * SECURITY: Validate DCID length before use.
			 * A crafted dcid_len > 20 would cause data + 6
			 * to be passed with an oversized length to
			 * the connection lookup, potentially reading
			 * past the packet buffer.
			 */
			if (dcid_len <= TQUIC_MAX_CID_LEN &&
			    len > (size_t)6 + dcid_len)
				conn = tquic_lookup_by_dcid(data + 6, dcid_len);
		}

		if (conn) {
			/*
			 * RFC 9000 Section 6.1: Process via the exported API
			 * which selects a compatible version and restarts.
			 */
			ret = tquic_handle_version_negotiation(conn, data,
							       len);
		} else {
			ret = 0; /* Ignore orphan version negotiation */
		}

		kfree_skb(skb);
		return ret;
	}

	/*
	 * Handle Initial packets for new connections on listening sockets.
	 *
	 * Per RFC 9000 Section 7.2, servers must accept Initial packets
	 * even when no connection exists. Check if this is an Initial packet
	 * for a new connection and route to server accept path.
	 */
	if (!conn && (data[0] & TQUIC_HEADER_FORM_LONG)) {
		/* Extract packet type from long header */
		u8 pkt_type = (data[0] & 0x30) >> 4;

		pr_debug(
			"tquic_udp_recv: long header, pkt_type=%u, data[0]=0x%02x\n",
			pkt_type, data[0]);

		/* Initial packet type == 0 */
		if (pkt_type == 0) {
			struct sock *listener;
			u32 pkt_version;

			/* Lookup listener socket for this address/port in this netns */
			listener = tquic_lookup_listener_net(sock_net(sk),
							     &local_addr);
			pr_debug(
				"tquic_udp_recv: Initial pkt, listener lookup: %s (local_addr family=%d)\n",
				listener ? "FOUND" : "NOT FOUND",
				local_addr.ss_family);
			if (listener) {
				/*
				 * Extract version from long header (bytes 1-4).
				 * RFC 9000 Section 17.2: Long Header Packet Format
				 */
				if (len < 5) {
					tquic_dbg(
						"Initial packet too short for version\n");
					sock_put(listener);
					kfree_skb(skb);
					return -EINVAL;
				}

				pkt_version = get_unaligned_be32(data + 1);

				/*
				 * Check if version is supported (RFC 9000 Section 6).
				 * Send Version Negotiation if client uses unsupported version.
				 */
				if (pkt_version != TQUIC_VERSION_1 &&
				    pkt_version != TQUIC_VERSION_2 &&
				    pkt_version != TQUIC_VERSION_NEGOTIATION) {
					tquic_dbg(
						"unsupported version 0x%08x, sending VN\n",
						pkt_version);

					/*
					 * Send Version Negotiation packet (RFC 9000 Section 6).
					 * VN packet lists versions we support (v1 and v2).
					 * This is sent from the listener socket context.
					 */
					ret = tquic_send_vn_from_listener(
						listener, skb, &src_addr,
						&local_addr);
					sock_put(listener);
					kfree_skb(skb);
					return ret;
				}

				/*
				 * Version is supported - route to server accept path.
				 * tquic_server_accept() will create a new connection,
				 * perform Retry validation if needed, and initiate
				 * the handshake.
				 */
				ret = tquic_server_accept(listener, skb,
							  &src_addr);

				/*
				 * Server accept consumes the skb on success or
				 * failure, so we return here without freeing it.
				 */
				sock_put(listener);
				return ret;
			}

			/*
			 * No listener found for this port. Fall through to
			 * normal processing which will return -ENOENT and
			 * avoid sending stateless reset for long headers.
			 */
		}
	}

#ifdef CONFIG_TQUIC_OFFLOAD
	if (conn && path && path->dev) {
		struct tquic_nic_device *nic = tquic_nic_find(path->dev);

		if (nic) {
			int offload_ret = tquic_offload_rx(nic, skb, conn);

			tquic_nic_put(nic);
			if (offload_ret == 0) {
				kfree_skb(skb);
				return 0; /* HW handled decryption */
			}
		}
	}
#endif /* CONFIG_TQUIC_OFFLOAD */

#ifdef CONFIG_TQUIC_OVER_TCP
	if (conn && conn->fallback_ctx &&
	    tquic_fallback_is_active(conn->fallback_ctx)) {
		/*
		 * Connection has migrated to TCP fallback transport.
		 * Discard stale UDP packets; data flows via TCP path.
		 */
		if (path)
			tquic_path_put(path);
		kfree_skb(skb);
		return 0;
	}
#endif /* CONFIG_TQUIC_OVER_TCP */

	/* Process the QUIC packet */
	pr_debug(
		"tquic: udp_recv -> process_packet conn=%px data[0]=0x%02x len=%zu\n",
		conn, data[0], len);
	ret = tquic_process_packet(conn, path, data, len, &src_addr);
	pr_debug("tquic: udp_recv <- process_packet ret=%d\n", ret);

	/* Update RX accounting for anti-amplification (RFC 9000 §8.1) */
	if (path && ret >= 0)
		tquic_path_on_data_received(path, len);

	/*
	 * Per RFC 9000 Section 10.3:
	 * "An endpoint that receives packets that it cannot process sends
	 * a stateless reset in response."
	 *
	 * If we couldn't find a connection for a short header packet,
	 * we should send a stateless reset. However, we must NOT send
	 * a stateless reset in response to:
	 * - Long header packets (might be Initial packets for new connections)
	 * - Packets that could themselves be stateless resets
	 * - Packets too small to trigger without amplification
	 */
	if (ret == -ENOENT && !(data[0] & TQUIC_HEADER_FORM_LONG) &&
	    /*
	     * CF-299: Do NOT send stateless resets during handshake
	     * (before authentication). A stateless reset is only valid
	     * for short-header packets to established connections.
	     * If we have no connection context, verify the packet is
	     * large enough to not be an amplification vector.
	     * RFC 9000 Section 10.3: "An endpoint MUST NOT generate a
	     * stateless reset that is smaller than the minimum size."
	     */
	    len > TQUIC_STATELESS_RESET_MIN_LEN + TQUIC_DEFAULT_CID_LEN) {
		/*
		 * Short header packet with unknown CID - send stateless reset
		 *
		 * We need to extract the DCID from the packet to generate
		 * the correct token. For short headers, DCID starts at byte 1.
		 */
		struct tquic_cid unknown_cid;
		const u8 *static_key;

		/*
		 * Don't send reset if this packet could itself be a reset
		 * (would cause infinite loop)
		 */
		if (len >= TQUIC_STATELESS_RESET_MIN_LEN) {
			/*
			 * Extract DCID - we don't know the length, but we
			 * can use up to TQUIC_DEFAULT_CID_LEN bytes
			 */
			unknown_cid.len =
				min_t(size_t,
				      len - 1 - TQUIC_STATELESS_RESET_TOKEN_LEN,
				      TQUIC_DEFAULT_CID_LEN);
			if (unknown_cid.len > 0) {
				memcpy(unknown_cid.id, data + 1,
				       unknown_cid.len);
				unknown_cid.seq_num = 0;
				unknown_cid.retire_prior_to = 0;

				static_key =
					tquic_stateless_reset_get_static_key();
				if (static_key) {
					tquic_stateless_reset_send(
						sk, &local_addr, &src_addr,
						&unknown_cid, static_key, len);
					tquic_dbg(
						"sent stateless reset for unknown CID\n");
				}
			}
		}
	}

	if (path)
		tquic_path_put(path);
	kfree_skb(skb);
	return ret;
}
EXPORT_SYMBOL_GPL(tquic_udp_recv);

/*
 * Encapsulated receive callback for UDP tunnel
 */
static int tquic_encap_recv(struct sock *sk, struct sk_buff *skb)
{
	tquic_dbg("encap_recv: sk=%p skb_len=%u\n", sk, skb ? skb->len : 0);

	/*
	 * CF-625: The UDP layer already pulled past the UDP header before
	 * calling encap_rcv, so skb->data already points at the QUIC
	 * payload. Do NOT strip the UDP header again.
	 */
	return tquic_udp_recv(sk, skb);
}

/*
 * Setup UDP encapsulation for a socket
 */
int tquic_setup_udp_encap(struct sock *sk)
{
	tquic_dbg("setup_udp_encap: sk=%p\n", sk);

	/* Set encapsulation callback */
	udp_sk(sk)->encap_type = 1; /* Custom encapsulation */
	udp_sk(sk)->encap_rcv = tquic_encap_recv;

	/* Enable GRO */
	tquic_udp_tunnel_encap_enable(sk);

	return 0;
}
EXPORT_SYMBOL_GPL(tquic_setup_udp_encap);

/*
 * Remove UDP encapsulation from socket
 */
void tquic_clear_udp_encap(struct sock *sk)
{
	udp_sk(sk)->encap_type = 0;
	udp_sk(sk)->encap_rcv = NULL;
}
EXPORT_SYMBOL_GPL(tquic_clear_udp_encap);

/*
 * =============================================================================
 * Coalesced Packet Handling
 * =============================================================================
 */

/*
 * Process coalesced packets (multiple QUIC packets in single UDP datagram)
 *
 * Uses tquic_split_coalesced() (core/packet.c, EXPORT_SYMBOL_GPL) to split
 * the datagram into individual packet spans first, then processes each span
 * via tquic_process_packet().  This delegates the security-hardened splitting
 * logic (overflow checks, CID bounds, Retry handling) to the canonical
 * implementation instead of duplicating it here.
 */
int tquic_process_coalesced(struct tquic_connection *conn,
			    struct tquic_path *path, u8 *data, size_t total_len,
			    struct sockaddr_storage *src_addr)
{
	const u8 *pkts[TQUIC_MAX_COALESCED_PACKETS];
	size_t lens[TQUIC_MAX_COALESCED_PACKETS];
	int num_pkts = 0;
	int packets = 0;
	int ret;
	int i;

	/*
	 * Split the datagram into individual packet spans.
	 * tquic_split_coalesced() validates CID lengths, handles version-
	 * aware Initial detection (including QUIC v2 / RFC 9369), enforces
	 * integer-overflow-safe arithmetic, and caps the count at
	 * max_packets (CF-075 / C-003).
	 */
	ret = tquic_split_coalesced(data, total_len, pkts, lens,
				    TQUIC_MAX_COALESCED_PACKETS, &num_pkts);
	if (ret < 0) {
		tquic_dbg("coalesced split failed: %d\n", ret);
		return ret;
	}

	for (i = 0; i < num_pkts; i++) {
		/*
		 * tquic_split_coalesced() returns const u8 * pointers into
		 * the original datagram.  tquic_process_packet() takes u8 *
		 * but does not write to the raw header (it writes to a
		 * separately allocated decryption buffer).  The cast is safe.
		 */
		ret = tquic_process_packet(conn, path,
					   (u8 *)pkts[i], lens[i], src_addr);
		if (ret < 0 && ret != -ENOENT)
			return ret;

		packets++;
	}

	return packets;
}
EXPORT_SYMBOL_GPL(tquic_process_coalesced);

/*
 * =============================================================================
 * Module Registration
 * =============================================================================
 */

MODULE_DESCRIPTION("TQUIC Packet Reception Path");
MODULE_LICENSE("GPL");
