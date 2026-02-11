/* SPDX-License-Identifier: GPL-2.0 */
/*
 * TQUIC Tracepoint Definitions
 *
 * Copyright (c) 2026 Linux Foundation
 * Kernel implementation by Justin Adams <spotty118@gmail.com>
 *
 * Defines all tracepoints for TQUIC eBPF observability.
 * These tracepoints can be consumed by:
 *   - bpftrace scripts
 *   - Custom BPF programs
 *   - perf tracing
 *   - ftrace
 *
 * Naming convention: tquic:<category>_<event>
 *   - tquic:connection_* - Connection lifecycle
 *   - tquic:packet_* - Packet events
 *   - tquic:stream_* - Stream events
 *   - tquic:crypto_* - Crypto events
 *   - tquic:cc_* - Congestion control
 *   - tquic:path_* - Multipath events
 *   - tquic:timer_* - Timer events
 *   - tquic:error_* - Error events
 */

#undef TRACE_SYSTEM
#define TRACE_SYSTEM tquic

#if !defined(_TQUIC_TRACEPOINTS_H) || defined(TRACE_HEADER_MULTI_READ)
#define _TQUIC_TRACEPOINTS_H

#include <linux/tracepoint.h>

/*
 * =============================================================================
 * Connection Lifecycle Tracepoints
 * =============================================================================
 */

/**
 * tquic:connection_new - New connection attempt
 * @conn_id: Connection ID
 * @is_server: Server or client role
 * @version: QUIC version
 * @scid: Source connection ID
 * @scid_len: SCID length
 * @dcid: Destination connection ID
 * @dcid_len: DCID length
 */
TRACE_EVENT(tquic_connection_new,

	TP_PROTO(u64 conn_id, bool is_server, u32 version,
		 const u8 *scid, u8 scid_len,
		 const u8 *dcid, u8 dcid_len),

	TP_ARGS(conn_id, is_server, version, scid, scid_len, dcid, dcid_len),

	TP_STRUCT__entry(
		__field(u64, conn_id)
		__field(bool, is_server)
		__field(u32, version)
		__array(u8, scid, 20)
		__field(u8, scid_len)
		__array(u8, dcid, 20)
		__field(u8, dcid_len)
	),

	TP_fast_assign(
		__entry->conn_id = conn_id;
		__entry->is_server = is_server;
		__entry->version = version;
		__entry->scid_len = min_t(u8, scid_len, 20);
		__entry->dcid_len = min_t(u8, dcid_len, 20);
		if (scid)
			memcpy(__entry->scid, scid, __entry->scid_len);
		if (dcid)
			memcpy(__entry->dcid, dcid, __entry->dcid_len);
	),

	TP_printk("conn=%llu role=%s version=0x%08x scid=%*phN dcid=%*phN",
		  __entry->conn_id,
		  __entry->is_server ? "server" : "client",
		  __entry->version,
		  __entry->scid_len, __entry->scid,
		  __entry->dcid_len, __entry->dcid)
);

/**
 * tquic:connection_established - Connection established
 */
TRACE_EVENT(tquic_connection_established,

	TP_PROTO(u64 conn_id, u64 handshake_time_us, u32 version,
		 u32 cipher_suite, bool early_data),

	TP_ARGS(conn_id, handshake_time_us, version, cipher_suite, early_data),

	TP_STRUCT__entry(
		__field(u64, conn_id)
		__field(u64, handshake_time_us)
		__field(u32, version)
		__field(u32, cipher_suite)
		__field(bool, early_data)
	),

	TP_fast_assign(
		__entry->conn_id = conn_id;
		__entry->handshake_time_us = handshake_time_us;
		__entry->version = version;
		__entry->cipher_suite = cipher_suite;
		__entry->early_data = early_data;
	),

	TP_printk("conn=%llu handshake=%lluus version=0x%08x cipher=0x%04x early_data=%d",
		  __entry->conn_id, __entry->handshake_time_us,
		  __entry->version, __entry->cipher_suite, __entry->early_data)
);

/**
 * tquic:connection_closed - Connection closed
 */
TRACE_EVENT(tquic_connection_closed,

	TP_PROTO(u64 conn_id, u64 error_code, const char *reason,
		 bool is_app_error, u64 bytes_sent, u64 bytes_received),

	TP_ARGS(conn_id, error_code, reason, is_app_error,
		bytes_sent, bytes_received),

	TP_STRUCT__entry(
		__field(u64, conn_id)
		__field(u64, error_code)
		__string(reason, reason)
		__field(bool, is_app_error)
		__field(u64, bytes_sent)
		__field(u64, bytes_received)
	),

	TP_fast_assign(
		__entry->conn_id = conn_id;
		__entry->error_code = error_code;
		__assign_str(reason);
		__entry->is_app_error = is_app_error;
		__entry->bytes_sent = bytes_sent;
		__entry->bytes_received = bytes_received;
	),

	TP_printk("conn=%llu error=0x%llx reason=%s app=%d tx=%llu rx=%llu",
		  __entry->conn_id, __entry->error_code,
		  __get_str(reason), __entry->is_app_error,
		  __entry->bytes_sent, __entry->bytes_received)
);

/*
 * =============================================================================
 * Packet Tracepoints
 * =============================================================================
 */

/**
 * tquic:packet_sent - Packet transmitted
 */
TRACE_EVENT(tquic_packet_sent,

	TP_PROTO(u64 conn_id, u64 pkt_num, u32 pkt_type, u32 size,
		 u32 path_id, u64 bytes_in_flight, u64 cwnd),

	TP_ARGS(conn_id, pkt_num, pkt_type, size, path_id,
		bytes_in_flight, cwnd),

	TP_STRUCT__entry(
		__field(u64, conn_id)
		__field(u64, pkt_num)
		__field(u32, pkt_type)
		__field(u32, size)
		__field(u32, path_id)
		__field(u64, bytes_in_flight)
		__field(u64, cwnd)
	),

	TP_fast_assign(
		__entry->conn_id = conn_id;
		__entry->pkt_num = pkt_num;
		__entry->pkt_type = pkt_type;
		__entry->size = size;
		__entry->path_id = path_id;
		__entry->bytes_in_flight = bytes_in_flight;
		__entry->cwnd = cwnd;
	),

	TP_printk("conn=%llu pkt=%llu type=%u size=%u path=%u inflight=%llu cwnd=%llu",
		  __entry->conn_id, __entry->pkt_num, __entry->pkt_type,
		  __entry->size, __entry->path_id, __entry->bytes_in_flight,
		  __entry->cwnd)
);

/**
 * tquic:packet_received - Packet received
 */
TRACE_EVENT(tquic_packet_received,

	TP_PROTO(u64 conn_id, u64 pkt_num, u32 pkt_type, u32 size,
		 u32 path_id, u8 ecn),

	TP_ARGS(conn_id, pkt_num, pkt_type, size, path_id, ecn),

	TP_STRUCT__entry(
		__field(u64, conn_id)
		__field(u64, pkt_num)
		__field(u32, pkt_type)
		__field(u32, size)
		__field(u32, path_id)
		__field(u8, ecn)
	),

	TP_fast_assign(
		__entry->conn_id = conn_id;
		__entry->pkt_num = pkt_num;
		__entry->pkt_type = pkt_type;
		__entry->size = size;
		__entry->path_id = path_id;
		__entry->ecn = ecn;
	),

	TP_printk("conn=%llu pkt=%llu type=%u size=%u path=%u ecn=%u",
		  __entry->conn_id, __entry->pkt_num, __entry->pkt_type,
		  __entry->size, __entry->path_id, __entry->ecn)
);

/**
 * tquic:packet_dropped - Packet dropped
 */
TRACE_EVENT(tquic_packet_dropped,

	TP_PROTO(u64 conn_id, u32 pkt_type, u32 size, u32 reason),

	TP_ARGS(conn_id, pkt_type, size, reason),

	TP_STRUCT__entry(
		__field(u64, conn_id)
		__field(u32, pkt_type)
		__field(u32, size)
		__field(u32, reason)
	),

	TP_fast_assign(
		__entry->conn_id = conn_id;
		__entry->pkt_type = pkt_type;
		__entry->size = size;
		__entry->reason = reason;
	),

	TP_printk("conn=%llu type=%u size=%u reason=%u",
		  __entry->conn_id, __entry->pkt_type,
		  __entry->size, __entry->reason)
);

/**
 * tquic:packet_lost - Packet lost
 */
TRACE_EVENT(tquic_packet_lost,

	TP_PROTO(u64 conn_id, u64 pkt_num, u32 size, u32 trigger,
		 u32 path_id, u64 total_lost),

	TP_ARGS(conn_id, pkt_num, size, trigger, path_id, total_lost),

	TP_STRUCT__entry(
		__field(u64, conn_id)
		__field(u64, pkt_num)
		__field(u32, size)
		__field(u32, trigger)
		__field(u32, path_id)
		__field(u64, total_lost)
	),

	TP_fast_assign(
		__entry->conn_id = conn_id;
		__entry->pkt_num = pkt_num;
		__entry->size = size;
		__entry->trigger = trigger;
		__entry->path_id = path_id;
		__entry->total_lost = total_lost;
	),

	TP_printk("conn=%llu pkt=%llu size=%u trigger=%u path=%u total_lost=%llu",
		  __entry->conn_id, __entry->pkt_num, __entry->size,
		  __entry->trigger, __entry->path_id, __entry->total_lost)
);

/*
 * =============================================================================
 * Stream Tracepoints
 * =============================================================================
 */

/**
 * tquic:stream_opened - Stream opened
 */
TRACE_EVENT(tquic_stream_opened,

	TP_PROTO(u64 conn_id, u64 stream_id, bool is_bidi, bool is_local),

	TP_ARGS(conn_id, stream_id, is_bidi, is_local),

	TP_STRUCT__entry(
		__field(u64, conn_id)
		__field(u64, stream_id)
		__field(bool, is_bidi)
		__field(bool, is_local)
	),

	TP_fast_assign(
		__entry->conn_id = conn_id;
		__entry->stream_id = stream_id;
		__entry->is_bidi = is_bidi;
		__entry->is_local = is_local;
	),

	TP_printk("conn=%llu stream=%llu bidi=%d local=%d",
		  __entry->conn_id, __entry->stream_id,
		  __entry->is_bidi, __entry->is_local)
);

/**
 * tquic:stream_closed - Stream closed
 */
TRACE_EVENT(tquic_stream_closed,

	TP_PROTO(u64 conn_id, u64 stream_id, u64 error_code,
		 u64 bytes_sent, u64 bytes_received),

	TP_ARGS(conn_id, stream_id, error_code, bytes_sent, bytes_received),

	TP_STRUCT__entry(
		__field(u64, conn_id)
		__field(u64, stream_id)
		__field(u64, error_code)
		__field(u64, bytes_sent)
		__field(u64, bytes_received)
	),

	TP_fast_assign(
		__entry->conn_id = conn_id;
		__entry->stream_id = stream_id;
		__entry->error_code = error_code;
		__entry->bytes_sent = bytes_sent;
		__entry->bytes_received = bytes_received;
	),

	TP_printk("conn=%llu stream=%llu error=0x%llx tx=%llu rx=%llu",
		  __entry->conn_id, __entry->stream_id, __entry->error_code,
		  __entry->bytes_sent, __entry->bytes_received)
);

/**
 * tquic:stream_data - Stream data transfer
 */
TRACE_EVENT(tquic_stream_data,

	TP_PROTO(u64 conn_id, u64 stream_id, u64 offset, u32 length,
		 bool is_fin, bool is_send),

	TP_ARGS(conn_id, stream_id, offset, length, is_fin, is_send),

	TP_STRUCT__entry(
		__field(u64, conn_id)
		__field(u64, stream_id)
		__field(u64, offset)
		__field(u32, length)
		__field(bool, is_fin)
		__field(bool, is_send)
	),

	TP_fast_assign(
		__entry->conn_id = conn_id;
		__entry->stream_id = stream_id;
		__entry->offset = offset;
		__entry->length = length;
		__entry->is_fin = is_fin;
		__entry->is_send = is_send;
	),

	TP_printk("conn=%llu stream=%llu off=%llu len=%u fin=%d dir=%s",
		  __entry->conn_id, __entry->stream_id, __entry->offset,
		  __entry->length, __entry->is_fin,
		  __entry->is_send ? "tx" : "rx")
);

/*
 * =============================================================================
 * Crypto Tracepoints
 * =============================================================================
 */

/**
 * tquic:crypto_key_update - Key update event
 */
TRACE_EVENT(tquic_crypto_key_update,

	TP_PROTO(u64 conn_id, u32 key_type, u32 key_phase, u32 trigger),

	TP_ARGS(conn_id, key_type, key_phase, trigger),

	TP_STRUCT__entry(
		__field(u64, conn_id)
		__field(u32, key_type)
		__field(u32, key_phase)
		__field(u32, trigger)
	),

	TP_fast_assign(
		__entry->conn_id = conn_id;
		__entry->key_type = key_type;
		__entry->key_phase = key_phase;
		__entry->trigger = trigger;
	),

	TP_printk("conn=%llu key_type=%u phase=%u trigger=%u",
		  __entry->conn_id, __entry->key_type,
		  __entry->key_phase, __entry->trigger)
);

/*
 * =============================================================================
 * Congestion Control Tracepoints
 * =============================================================================
 */

/**
 * tquic:cc_state_changed - CC state transition
 */
TRACE_EVENT(tquic_cc_state_changed,

	TP_PROTO(u64 conn_id, u32 old_state, u32 new_state,
		 u64 cwnd, u64 ssthresh, u32 path_id),

	TP_ARGS(conn_id, old_state, new_state, cwnd, ssthresh, path_id),

	TP_STRUCT__entry(
		__field(u64, conn_id)
		__field(u32, old_state)
		__field(u32, new_state)
		__field(u64, cwnd)
		__field(u64, ssthresh)
		__field(u32, path_id)
	),

	TP_fast_assign(
		__entry->conn_id = conn_id;
		__entry->old_state = old_state;
		__entry->new_state = new_state;
		__entry->cwnd = cwnd;
		__entry->ssthresh = ssthresh;
		__entry->path_id = path_id;
	),

	TP_printk("conn=%llu state=%u->%u cwnd=%llu ssthresh=%llu path=%u",
		  __entry->conn_id, __entry->old_state, __entry->new_state,
		  __entry->cwnd, __entry->ssthresh, __entry->path_id)
);

/**
 * tquic:cc_metrics_updated - CC metrics update
 */
TRACE_EVENT(tquic_cc_metrics_updated,

	TP_PROTO(u64 conn_id, u64 cwnd, u64 bytes_in_flight,
		 u64 smoothed_rtt, u64 min_rtt, u64 pacing_rate, u32 path_id),

	TP_ARGS(conn_id, cwnd, bytes_in_flight, smoothed_rtt, min_rtt,
		pacing_rate, path_id),

	TP_STRUCT__entry(
		__field(u64, conn_id)
		__field(u64, cwnd)
		__field(u64, bytes_in_flight)
		__field(u64, smoothed_rtt)
		__field(u64, min_rtt)
		__field(u64, pacing_rate)
		__field(u32, path_id)
	),

	TP_fast_assign(
		__entry->conn_id = conn_id;
		__entry->cwnd = cwnd;
		__entry->bytes_in_flight = bytes_in_flight;
		__entry->smoothed_rtt = smoothed_rtt;
		__entry->min_rtt = min_rtt;
		__entry->pacing_rate = pacing_rate;
		__entry->path_id = path_id;
	),

	TP_printk("conn=%llu cwnd=%llu inflight=%llu srtt=%lluus min_rtt=%lluus pacing=%llu path=%u",
		  __entry->conn_id, __entry->cwnd, __entry->bytes_in_flight,
		  __entry->smoothed_rtt, __entry->min_rtt,
		  __entry->pacing_rate, __entry->path_id)
);

/*
 * =============================================================================
 * Path/Multipath Tracepoints
 * =============================================================================
 */

/**
 * tquic:path_created - New path created
 */
TRACE_EVENT(tquic_path_created,

	TP_PROTO(u64 conn_id, u32 path_id, u32 local_addr, u32 remote_addr,
		 u16 local_port, u16 remote_port),

	TP_ARGS(conn_id, path_id, local_addr, remote_addr,
		local_port, remote_port),

	TP_STRUCT__entry(
		__field(u64, conn_id)
		__field(u32, path_id)
		__field(u32, local_addr)
		__field(u32, remote_addr)
		__field(u16, local_port)
		__field(u16, remote_port)
	),

	TP_fast_assign(
		__entry->conn_id = conn_id;
		__entry->path_id = path_id;
		__entry->local_addr = local_addr;
		__entry->remote_addr = remote_addr;
		__entry->local_port = local_port;
		__entry->remote_port = remote_port;
	),

	TP_printk("conn=%llu path=%u local=%pI4:%u remote=%pI4:%u",
		  __entry->conn_id, __entry->path_id,
		  &__entry->local_addr, __entry->local_port,
		  &__entry->remote_addr, __entry->remote_port)
);

/**
 * tquic:path_validated - Path validated
 */
TRACE_EVENT(tquic_path_validated,

	TP_PROTO(u64 conn_id, u32 path_id, u64 validation_time_us),

	TP_ARGS(conn_id, path_id, validation_time_us),

	TP_STRUCT__entry(
		__field(u64, conn_id)
		__field(u32, path_id)
		__field(u64, validation_time_us)
	),

	TP_fast_assign(
		__entry->conn_id = conn_id;
		__entry->path_id = path_id;
		__entry->validation_time_us = validation_time_us;
	),

	TP_printk("conn=%llu path=%u validation_time=%lluus",
		  __entry->conn_id, __entry->path_id,
		  __entry->validation_time_us)
);

/**
 * tquic:path_closed - Path closed
 */
TRACE_EVENT(tquic_path_closed,

	TP_PROTO(u64 conn_id, u32 path_id, u32 reason),

	TP_ARGS(conn_id, path_id, reason),

	TP_STRUCT__entry(
		__field(u64, conn_id)
		__field(u32, path_id)
		__field(u32, reason)
	),

	TP_fast_assign(
		__entry->conn_id = conn_id;
		__entry->path_id = path_id;
		__entry->reason = reason;
	),

	TP_printk("conn=%llu path=%u reason=%u",
		  __entry->conn_id, __entry->path_id, __entry->reason)
);

/*
 * =============================================================================
 * Timer Tracepoints
 * =============================================================================
 */

/**
 * tquic:timer_set - Timer armed
 */
TRACE_EVENT(tquic_timer_set,

	TP_PROTO(u64 conn_id, u32 timer_type, u64 timeout_us),

	TP_ARGS(conn_id, timer_type, timeout_us),

	TP_STRUCT__entry(
		__field(u64, conn_id)
		__field(u32, timer_type)
		__field(u64, timeout_us)
	),

	TP_fast_assign(
		__entry->conn_id = conn_id;
		__entry->timer_type = timer_type;
		__entry->timeout_us = timeout_us;
	),

	TP_printk("conn=%llu timer=%u timeout=%lluus",
		  __entry->conn_id, __entry->timer_type, __entry->timeout_us)
);

/**
 * tquic:timer_expired - Timer expired
 */
TRACE_EVENT(tquic_timer_expired,

	TP_PROTO(u64 conn_id, u32 timer_type),

	TP_ARGS(conn_id, timer_type),

	TP_STRUCT__entry(
		__field(u64, conn_id)
		__field(u32, timer_type)
	),

	TP_fast_assign(
		__entry->conn_id = conn_id;
		__entry->timer_type = timer_type;
	),

	TP_printk("conn=%llu timer=%u", __entry->conn_id, __entry->timer_type)
);

/*
 * =============================================================================
 * Error Tracepoints
 * =============================================================================
 */

/**
 * tquic:error - Error event
 */
TRACE_EVENT(tquic_error,

	TP_PROTO(u64 conn_id, u32 error_type, u64 error_code,
		 const char *message),

	TP_ARGS(conn_id, error_type, error_code, message),

	TP_STRUCT__entry(
		__field(u64, conn_id)
		__field(u32, error_type)
		__field(u64, error_code)
		__string(message, message)
	),

	TP_fast_assign(
		__entry->conn_id = conn_id;
		__entry->error_type = error_type;
		__entry->error_code = error_code;
		__assign_str(message);
	),

	TP_printk("conn=%llu type=%u code=0x%llx msg=%s",
		  __entry->conn_id, __entry->error_type,
		  __entry->error_code, __get_str(message))
);

/*
 * =============================================================================
 * Migration/Scheduler Tracepoints
 * =============================================================================
 */

/**
 * tquic:migration - Connection migration
 */
TRACE_EVENT(tquic_migration,

	TP_PROTO(u64 conn_id, u32 old_path_id, u32 new_path_id,
		 u32 migration_type),

	TP_ARGS(conn_id, old_path_id, new_path_id, migration_type),

	TP_STRUCT__entry(
		__field(u64, conn_id)
		__field(u32, old_path_id)
		__field(u32, new_path_id)
		__field(u32, migration_type)
	),

	TP_fast_assign(
		__entry->conn_id = conn_id;
		__entry->old_path_id = old_path_id;
		__entry->new_path_id = new_path_id;
		__entry->migration_type = migration_type;
	),

	TP_printk("conn=%llu path=%u->%u type=%u",
		  __entry->conn_id, __entry->old_path_id,
		  __entry->new_path_id, __entry->migration_type)
);

/**
 * tquic:scheduler_decision - Scheduler path selection
 */
TRACE_EVENT(tquic_scheduler_decision,

	TP_PROTO(u64 conn_id, u32 selected_path, u32 reason,
		 u32 candidate_count),

	TP_ARGS(conn_id, selected_path, reason, candidate_count),

	TP_STRUCT__entry(
		__field(u64, conn_id)
		__field(u32, selected_path)
		__field(u32, reason)
		__field(u32, candidate_count)
	),

	TP_fast_assign(
		__entry->conn_id = conn_id;
		__entry->selected_path = selected_path;
		__entry->reason = reason;
		__entry->candidate_count = candidate_count;
	),

	TP_printk("conn=%llu selected=%u reason=%u candidates=%u",
		  __entry->conn_id, __entry->selected_path,
		  __entry->reason, __entry->candidate_count)
);

/*
 * =============================================================================
 * Handshake Tracepoints
 * =============================================================================
 */

/**
 * tquic:handshake_start - TLS handshake initiated
 * @conn_id: Connection ID
 * @is_server: Server or client role
 * @has_session_ticket: Whether 0-RTT was attempted
 * @verify_mode: Certificate verification mode
 */
TRACE_EVENT(tquic_handshake_start,

	TP_PROTO(u64 conn_id, bool is_server, bool has_session_ticket,
		 u32 verify_mode),

	TP_ARGS(conn_id, is_server, has_session_ticket, verify_mode),

	TP_STRUCT__entry(
		__field(u64, conn_id)
		__field(bool, is_server)
		__field(bool, has_session_ticket)
		__field(u32, verify_mode)
	),

	TP_fast_assign(
		__entry->conn_id = conn_id;
		__entry->is_server = is_server;
		__entry->has_session_ticket = has_session_ticket;
		__entry->verify_mode = verify_mode;
	),

	TP_printk("conn=%llu role=%s ticket=%d verify=%u",
		  __entry->conn_id,
		  __entry->is_server ? "server" : "client",
		  __entry->has_session_ticket, __entry->verify_mode)
);

/**
 * tquic:handshake_complete - TLS handshake completed
 * @conn_id: Connection ID
 * @status: Result (0=success, negative=error)
 * @duration_us: Handshake duration in microseconds
 * @cipher_suite: Negotiated cipher suite
 * @early_data: Whether 0-RTT was used
 */
TRACE_EVENT(tquic_handshake_complete,

	TP_PROTO(u64 conn_id, int status, u64 duration_us,
		 u32 cipher_suite, bool early_data),

	TP_ARGS(conn_id, status, duration_us, cipher_suite, early_data),

	TP_STRUCT__entry(
		__field(u64, conn_id)
		__field(int, status)
		__field(u64, duration_us)
		__field(u32, cipher_suite)
		__field(bool, early_data)
	),

	TP_fast_assign(
		__entry->conn_id = conn_id;
		__entry->status = status;
		__entry->duration_us = duration_us;
		__entry->cipher_suite = cipher_suite;
		__entry->early_data = early_data;
	),

	TP_printk("conn=%llu status=%d duration=%lluus cipher=0x%04x early_data=%d",
		  __entry->conn_id, __entry->status, __entry->duration_us,
		  __entry->cipher_suite, __entry->early_data)
);

/*
 * =============================================================================
 * Bonding/Failover Tracepoints
 * =============================================================================
 */

/**
 * tquic:failover - Path failover event
 * @conn_id: Connection ID
 * @failed_path_id: Path that failed
 * @new_path_id: Path switched to
 * @reason: Failover reason (timeout, loss, manual)
 * @rtt_us: RTT on failed path at time of failover
 */
TRACE_EVENT(tquic_failover,

	TP_PROTO(u64 conn_id, u32 failed_path_id, u32 new_path_id,
		 u32 reason, u64 rtt_us),

	TP_ARGS(conn_id, failed_path_id, new_path_id, reason, rtt_us),

	TP_STRUCT__entry(
		__field(u64, conn_id)
		__field(u32, failed_path_id)
		__field(u32, new_path_id)
		__field(u32, reason)
		__field(u64, rtt_us)
	),

	TP_fast_assign(
		__entry->conn_id = conn_id;
		__entry->failed_path_id = failed_path_id;
		__entry->new_path_id = new_path_id;
		__entry->reason = reason;
		__entry->rtt_us = rtt_us;
	),

	TP_printk("conn=%llu failed=%u new=%u reason=%u rtt=%lluus",
		  __entry->conn_id, __entry->failed_path_id,
		  __entry->new_path_id, __entry->reason, __entry->rtt_us)
);

/**
 * tquic:bond_state - Bonding state change
 * @conn_id: Connection ID
 * @bond_mode: Current bonding mode
 * @active_paths: Number of active paths
 * @total_bandwidth: Estimated aggregate bandwidth (bytes/sec)
 */
TRACE_EVENT(tquic_bond_state,

	TP_PROTO(u64 conn_id, u32 bond_mode, u32 active_paths,
		 u64 total_bandwidth),

	TP_ARGS(conn_id, bond_mode, active_paths, total_bandwidth),

	TP_STRUCT__entry(
		__field(u64, conn_id)
		__field(u32, bond_mode)
		__field(u32, active_paths)
		__field(u64, total_bandwidth)
	),

	TP_fast_assign(
		__entry->conn_id = conn_id;
		__entry->bond_mode = bond_mode;
		__entry->active_paths = active_paths;
		__entry->total_bandwidth = total_bandwidth;
	),

	TP_printk("conn=%llu mode=%u paths=%u bandwidth=%llu",
		  __entry->conn_id, __entry->bond_mode,
		  __entry->active_paths, __entry->total_bandwidth)
);

/**
 * tquic:frame_debug - Frame-level debug trace
 * @conn_id: Connection ID
 * @frame_type: QUIC frame type (RFC 9000 Table 3)
 * @length: Frame length in bytes
 * @path_id: Path ID
 * @is_send: Sending (true) or receiving (false)
 */
TRACE_EVENT(tquic_frame_debug,

	TP_PROTO(u64 conn_id, u32 frame_type, u32 length,
		 u32 path_id, bool is_send),

	TP_ARGS(conn_id, frame_type, length, path_id, is_send),

	TP_STRUCT__entry(
		__field(u64, conn_id)
		__field(u32, frame_type)
		__field(u32, length)
		__field(u32, path_id)
		__field(bool, is_send)
	),

	TP_fast_assign(
		__entry->conn_id = conn_id;
		__entry->frame_type = frame_type;
		__entry->length = length;
		__entry->path_id = path_id;
		__entry->is_send = is_send;
	),

	TP_printk("conn=%llu frame=0x%02x len=%u path=%u dir=%s",
		  __entry->conn_id, __entry->frame_type,
		  __entry->length, __entry->path_id,
		  __entry->is_send ? "tx" : "rx")
);

#endif /* _TQUIC_TRACEPOINTS_H */

/* This must be outside the header guard */
#undef TRACE_INCLUDE_PATH
#define TRACE_INCLUDE_PATH net/tquic/diag
#undef TRACE_INCLUDE_FILE
#define TRACE_INCLUDE_FILE tracepoints

#include <trace/define_trace.h>
