/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * TQUIC: Tracepoint Wrapper Function Declarations
 *
 * Copyright (c) 2026 Justin Adams <spotty118@gmail.com>
 */

#ifndef _TQUIC_TRACE_WRAPPERS_H
#define _TQUIC_TRACE_WRAPPERS_H

struct tquic_connection;

/* Connection lifecycle tracepoints */
void tquic_trace_connection_new(struct tquic_connection *conn, bool is_server);
void tquic_trace_connection_established(struct tquic_connection *conn,
					u32 version);
void tquic_trace_connection_closed(struct tquic_connection *conn,
				   u64 error_code, const char *reason);

/* Packet tracepoints */
void tquic_trace_packet_sent(struct tquic_connection *conn,
			     u64 pn, u32 size, u8 pn_space, u32 path_id);
void tquic_trace_packet_received(struct tquic_connection *conn,
				 u64 pn, u32 size, u8 pn_space);
void tquic_trace_packet_dropped(struct tquic_connection *conn,
				u32 size, const char *reason);
void tquic_trace_packet_lost(struct tquic_connection *conn,
			     u64 pn, u32 size, u8 pn_space);

/* Stream tracepoints */
void tquic_trace_stream_opened(struct tquic_connection *conn,
			       u64 stream_id, bool is_local);
void tquic_trace_stream_closed(struct tquic_connection *conn,
			       u64 stream_id, u64 error_code);
void tquic_trace_stream_data(struct tquic_connection *conn,
			     u64 stream_id, u64 offset, u32 len, bool is_fin);

/* Crypto tracepoints */
void tquic_trace_crypto_key_update(struct tquic_connection *conn,
				   u8 generation, bool is_tx);

/* Congestion control tracepoints */
void tquic_trace_cc_state_changed(struct tquic_connection *conn,
				  const char *old_state, const char *new_state);
void tquic_trace_cc_metrics_updated(struct tquic_connection *conn,
				    u64 cwnd, u64 bytes_in_flight,
				    u64 smoothed_rtt);

/* Path tracepoints */
void tquic_trace_path_created(struct tquic_connection *conn,
			      u32 path_id, const char *local_addr);
void tquic_trace_path_validated(struct tquic_connection *conn,
				u32 path_id);
void tquic_trace_path_closed(struct tquic_connection *conn,
			     u32 path_id, const char *reason);

/* Timer tracepoints */
void tquic_trace_timer_set(struct tquic_connection *conn,
			   u32 timer_type, u64 timeout_ns);
void tquic_trace_timer_expired(struct tquic_connection *conn, u32 timer_type);

/* Error tracepoints */
void tquic_trace_error(struct tquic_connection *conn,
		       u64 error_code, const char *reason);

/* Migration tracepoints */
void tquic_trace_migration(struct tquic_connection *conn,
			   const char *old_addr, const char *new_addr);

/* Scheduler tracepoints */
void tquic_trace_scheduler_decision(struct tquic_connection *conn,
				    u32 selected_path, const char *reason);

/* Handshake tracepoints */
void tquic_trace_handshake_start(struct tquic_connection *conn,
				 u32 version, bool is_retry);
void tquic_trace_handshake_complete(struct tquic_connection *conn,
				    u32 version, u64 handshake_duration_ns);

/* Bonding/failover tracepoints */
void tquic_trace_failover(struct tquic_connection *conn,
			  u32 from_path, u32 to_path, const char *reason);
void tquic_trace_bond_state(struct tquic_connection *conn,
			    const char *old_state, const char *new_state);

/* Frame debug tracepoints */
void tquic_trace_frame_debug(struct tquic_connection *conn,
			     u64 frame_type, const u8 *data, u32 len,
			     bool is_tx);

#endif /* _TQUIC_TRACE_WRAPPERS_H */
