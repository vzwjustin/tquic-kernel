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
					u64 handshake_time_us);
void tquic_trace_connection_closed(struct tquic_connection *conn,
				   u64 error_code, const char *reason,
				   bool is_app_error);

/* Packet tracepoints */
void tquic_trace_packet_sent(struct tquic_connection *conn,
			     u64 pkt_num, u32 pkt_type, u32 size,
			     u32 path_id);
void tquic_trace_packet_received(struct tquic_connection *conn,
				 u64 pkt_num, u32 pkt_type, u32 size,
				 u32 path_id, u8 ecn);
void tquic_trace_packet_dropped(struct tquic_connection *conn,
				u32 pkt_type, u32 size, u32 reason);
void tquic_trace_packet_lost(struct tquic_connection *conn,
			     u64 pkt_num, u32 size, u32 trigger,
			     u32 path_id);

/* Stream tracepoints */
void tquic_trace_stream_opened(struct tquic_connection *conn,
			       u64 stream_id, bool is_bidi, bool is_local);
void tquic_trace_stream_closed(struct tquic_connection *conn,
			       u64 stream_id, u64 error_code,
			       u64 bytes_sent, u64 bytes_received);
void tquic_trace_stream_data(struct tquic_connection *conn,
			     u64 stream_id, u64 offset, u32 length,
			     bool is_fin, bool is_send);

/* Crypto tracepoints */
void tquic_trace_crypto_key_update(struct tquic_connection *conn,
				   u32 key_type, u32 key_phase,
				   u32 trigger);

/* Congestion control tracepoints */
void tquic_trace_cc_state_changed(struct tquic_connection *conn,
				  u32 old_state, u32 new_state,
				  u64 cwnd, u64 ssthresh, u32 path_id);
void tquic_trace_cc_metrics_updated(struct tquic_connection *conn,
				    u64 cwnd, u64 bytes_in_flight,
				    u64 smoothed_rtt, u64 min_rtt,
				    u64 pacing_rate, u32 path_id);

/* Path tracepoints */
void tquic_trace_path_created(struct tquic_connection *conn,
			      u32 path_id, u32 local_addr, u32 remote_addr,
			      u16 local_port, u16 remote_port);
void tquic_trace_path_validated(struct tquic_connection *conn,
				u32 path_id, u64 validation_time_us);
void tquic_trace_path_closed(struct tquic_connection *conn,
			     u32 path_id, u32 reason);

/* Timer tracepoints */
void tquic_trace_timer_set(struct tquic_connection *conn,
			   u32 timer_type, u64 timeout_us);
void tquic_trace_timer_expired(struct tquic_connection *conn, u32 timer_type);

/* Error tracepoints */
void tquic_trace_error(struct tquic_connection *conn,
		       u32 error_type, u64 error_code, const char *message);

/* Migration tracepoints */
void tquic_trace_migration(struct tquic_connection *conn,
			   u32 old_path_id, u32 new_path_id,
			   u32 migration_type);

/* Scheduler tracepoints */
void tquic_trace_scheduler_decision(struct tquic_connection *conn,
				    u32 selected_path, u32 reason,
				    u32 candidate_count);

/* Handshake tracepoints */
void tquic_trace_handshake_start(struct tquic_connection *conn,
				 bool is_server, bool has_session_ticket,
				 u32 verify_mode);
void tquic_trace_handshake_complete(struct tquic_connection *conn,
				    int status, u64 duration_us);

/* Bonding/failover tracepoints */
void tquic_trace_failover(struct tquic_connection *conn,
			  u32 failed_path_id, u32 new_path_id,
			  u32 reason, u64 rtt_us);
void tquic_trace_bond_state(struct tquic_connection *conn,
			    u32 bond_mode, u32 active_paths,
			    u64 total_bandwidth);

/* Frame debug tracepoints */
void tquic_trace_frame_debug(struct tquic_connection *conn,
			     u32 frame_type, u32 length,
			     u32 path_id, bool is_send);

#endif /* _TQUIC_TRACE_WRAPPERS_H */
