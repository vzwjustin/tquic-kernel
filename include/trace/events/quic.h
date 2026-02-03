/* SPDX-License-Identifier: GPL-2.0 */
/*
 * QUIC Tracepoints
 *
 * Kernel tracepoints for QUIC debugging and observability.
 * Enable with: echo 1 > /sys/kernel/debug/tracing/events/quic/enable
 *
 * Copyright (c) 2024 Linux QUIC Authors
 */
#undef TRACE_SYSTEM
#define TRACE_SYSTEM quic

#if !defined(_TRACE_QUIC_H) || defined(TRACE_HEADER_MULTI_READ)
#define _TRACE_QUIC_H

#include <linux/tracepoint.h>

/*
 * QUIC connection state names for tracing
 */
#define quic_state_names			\
	EM(QUIC_STATE_IDLE)			\
	EM(QUIC_STATE_CONNECTING)		\
	EM(QUIC_STATE_HANDSHAKE)		\
	EM(QUIC_STATE_CONNECTED)		\
	EM(QUIC_STATE_CLOSING)			\
	EM(QUIC_STATE_DRAINING)			\
	EMe(QUIC_STATE_CLOSED)

/*
 * QUIC packet types for tracing
 */
#define quic_packet_type_names			\
	EM(QUIC_PACKET_INITIAL)			\
	EM(QUIC_PACKET_0RTT)			\
	EM(QUIC_PACKET_HANDSHAKE)		\
	EM(QUIC_PACKET_RETRY)			\
	EMe(QUIC_PACKET_1RTT)

/*
 * QUIC frame types for tracing
 */
#define quic_frame_type_names			\
	EM(QUIC_FRAME_PADDING)			\
	EM(QUIC_FRAME_PING)			\
	EM(QUIC_FRAME_ACK)			\
	EM(QUIC_FRAME_ACK_ECN)			\
	EM(QUIC_FRAME_RESET_STREAM)		\
	EM(QUIC_FRAME_STOP_SENDING)		\
	EM(QUIC_FRAME_CRYPTO)			\
	EM(QUIC_FRAME_NEW_TOKEN)		\
	EM(QUIC_FRAME_STREAM)			\
	EM(QUIC_FRAME_MAX_DATA)			\
	EM(QUIC_FRAME_MAX_STREAM_DATA)		\
	EM(QUIC_FRAME_MAX_STREAMS_BIDI)		\
	EM(QUIC_FRAME_MAX_STREAMS_UNI)		\
	EM(QUIC_FRAME_DATA_BLOCKED)		\
	EM(QUIC_FRAME_STREAM_DATA_BLOCKED)	\
	EM(QUIC_FRAME_STREAMS_BLOCKED_BIDI)	\
	EM(QUIC_FRAME_STREAMS_BLOCKED_UNI)	\
	EM(QUIC_FRAME_NEW_CONNECTION_ID)	\
	EM(QUIC_FRAME_RETIRE_CONNECTION_ID)	\
	EM(QUIC_FRAME_PATH_CHALLENGE)		\
	EM(QUIC_FRAME_PATH_RESPONSE)		\
	EM(QUIC_FRAME_CONNECTION_CLOSE)		\
	EM(QUIC_FRAME_CONNECTION_CLOSE_APP)	\
	EMe(QUIC_FRAME_HANDSHAKE_DONE)

/*
 * QUIC congestion control algorithm names
 */
#define quic_cc_algo_names			\
	EM(QUIC_CC_RENO)			\
	EM(QUIC_CC_CUBIC)			\
	EM(QUIC_CC_BBR)				\
	EMe(QUIC_CC_BBR2)

/*
 * QUIC packet number space names
 */
#define quic_pn_space_names			\
	EM(QUIC_PN_SPACE_INITIAL)		\
	EM(QUIC_PN_SPACE_HANDSHAKE)		\
	EMe(QUIC_PN_SPACE_APPLICATION)

/* Export enums to userspace */
#undef EM
#undef EMe
#define EM(a)	TRACE_DEFINE_ENUM(a);
#define EMe(a)	TRACE_DEFINE_ENUM(a);

quic_state_names
quic_packet_type_names
quic_cc_algo_names
quic_pn_space_names

#undef EM
#undef EMe
#define EM(a)	{ a, #a },
#define EMe(a)	{ a, #a }

#define show_quic_state_name(val)		\
	__print_symbolic(val, quic_state_names)

#define show_quic_packet_type(val)		\
	__print_symbolic(val, quic_packet_type_names)

#define show_quic_cc_algo(val)			\
	__print_symbolic(val, quic_cc_algo_names)

#define show_quic_pn_space(val)			\
	__print_symbolic(val, quic_pn_space_names)

/*
 * ============================================================================
 * Connection State Tracepoints
 * ============================================================================
 */

/**
 * quic_conn_state_change - Connection state transition
 * @conn_id: Connection ID (first 8 bytes)
 * @old_state: Previous connection state
 * @new_state: New connection state
 *
 * Traces connection state machine transitions.
 */
TRACE_EVENT(quic_conn_state_change,

	TP_PROTO(u64 conn_id, int old_state, int new_state),

	TP_ARGS(conn_id, old_state, new_state),

	TP_STRUCT__entry(
		__field(u64, conn_id)
		__field(int, old_state)
		__field(int, new_state)
	),

	TP_fast_assign(
		__entry->conn_id = conn_id;
		__entry->old_state = old_state;
		__entry->new_state = new_state;
	),

	TP_printk("conn=%llx old_state=%s new_state=%s",
		__entry->conn_id,
		show_quic_state_name(__entry->old_state),
		show_quic_state_name(__entry->new_state))
);

/**
 * quic_conn_create - New connection created
 * @conn_id: Connection ID (first 8 bytes)
 * @is_server: Server-side connection flag
 */
TRACE_EVENT(quic_conn_create,

	TP_PROTO(u64 conn_id, bool is_server),

	TP_ARGS(conn_id, is_server),

	TP_STRUCT__entry(
		__field(u64, conn_id)
		__field(bool, is_server)
	),

	TP_fast_assign(
		__entry->conn_id = conn_id;
		__entry->is_server = is_server;
	),

	TP_printk("conn=%llx role=%s",
		__entry->conn_id,
		__entry->is_server ? "server" : "client")
);

/**
 * quic_conn_destroy - Connection destroyed
 * @conn_id: Connection ID
 * @error_code: Error code if closed with error, 0 otherwise
 */
TRACE_EVENT(quic_conn_destroy,

	TP_PROTO(u64 conn_id, u64 error_code),

	TP_ARGS(conn_id, error_code),

	TP_STRUCT__entry(
		__field(u64, conn_id)
		__field(u64, error_code)
	),

	TP_fast_assign(
		__entry->conn_id = conn_id;
		__entry->error_code = error_code;
	),

	TP_printk("conn=%llx error=%llu",
		__entry->conn_id, __entry->error_code)
);

/**
 * quic_handshake_complete - Handshake completed successfully
 * @conn_id: Connection ID
 * @time_us: Time taken for handshake in microseconds
 */
TRACE_EVENT(quic_handshake_complete,

	TP_PROTO(u64 conn_id, u64 time_us),

	TP_ARGS(conn_id, time_us),

	TP_STRUCT__entry(
		__field(u64, conn_id)
		__field(u64, time_us)
	),

	TP_fast_assign(
		__entry->conn_id = conn_id;
		__entry->time_us = time_us;
	),

	TP_printk("conn=%llx handshake_time=%llu us",
		__entry->conn_id, __entry->time_us)
);

/*
 * ============================================================================
 * Packet Send/Receive Tracepoints
 * ============================================================================
 */

/**
 * quic_packet_recv - Packet received
 * @conn_id: Connection ID
 * @pkt_num: Packet number
 * @len: Packet length in bytes
 * @pn_space: Packet number space
 */
TRACE_EVENT(quic_packet_recv,

	TP_PROTO(u64 conn_id, u64 pkt_num, u32 len, u8 pn_space),

	TP_ARGS(conn_id, pkt_num, len, pn_space),

	TP_STRUCT__entry(
		__field(u64, conn_id)
		__field(u64, pkt_num)
		__field(u32, len)
		__field(u8, pn_space)
	),

	TP_fast_assign(
		__entry->conn_id = conn_id;
		__entry->pkt_num = pkt_num;
		__entry->len = len;
		__entry->pn_space = pn_space;
	),

	TP_printk("conn=%llx pn=%llu len=%u space=%s",
		__entry->conn_id, __entry->pkt_num, __entry->len,
		show_quic_pn_space(__entry->pn_space))
);

/**
 * quic_packet_send - Packet sent
 * @conn_id: Connection ID
 * @pkt_num: Packet number
 * @len: Packet length in bytes
 * @pn_space: Packet number space
 */
TRACE_EVENT(quic_packet_send,

	TP_PROTO(u64 conn_id, u64 pkt_num, u32 len, u8 pn_space),

	TP_ARGS(conn_id, pkt_num, len, pn_space),

	TP_STRUCT__entry(
		__field(u64, conn_id)
		__field(u64, pkt_num)
		__field(u32, len)
		__field(u8, pn_space)
	),

	TP_fast_assign(
		__entry->conn_id = conn_id;
		__entry->pkt_num = pkt_num;
		__entry->len = len;
		__entry->pn_space = pn_space;
	),

	TP_printk("conn=%llx pn=%llu len=%u space=%s",
		__entry->conn_id, __entry->pkt_num, __entry->len,
		show_quic_pn_space(__entry->pn_space))
);

/**
 * quic_packet_lost - Packet declared lost
 * @conn_id: Connection ID
 * @pkt_num: Lost packet number
 * @pn_space: Packet number space
 */
TRACE_EVENT(quic_packet_lost,

	TP_PROTO(u64 conn_id, u64 pkt_num, u8 pn_space),

	TP_ARGS(conn_id, pkt_num, pn_space),

	TP_STRUCT__entry(
		__field(u64, conn_id)
		__field(u64, pkt_num)
		__field(u8, pn_space)
	),

	TP_fast_assign(
		__entry->conn_id = conn_id;
		__entry->pkt_num = pkt_num;
		__entry->pn_space = pn_space;
	),

	TP_printk("conn=%llx pn=%llu space=%s",
		__entry->conn_id, __entry->pkt_num,
		show_quic_pn_space(__entry->pn_space))
);

/**
 * quic_packet_acked - Packet acknowledged
 * @conn_id: Connection ID
 * @pkt_num: Acknowledged packet number
 * @pn_space: Packet number space
 */
TRACE_EVENT(quic_packet_acked,

	TP_PROTO(u64 conn_id, u64 pkt_num, u8 pn_space),

	TP_ARGS(conn_id, pkt_num, pn_space),

	TP_STRUCT__entry(
		__field(u64, conn_id)
		__field(u64, pkt_num)
		__field(u8, pn_space)
	),

	TP_fast_assign(
		__entry->conn_id = conn_id;
		__entry->pkt_num = pkt_num;
		__entry->pn_space = pn_space;
	),

	TP_printk("conn=%llx pn=%llu space=%s",
		__entry->conn_id, __entry->pkt_num,
		show_quic_pn_space(__entry->pn_space))
);

/*
 * ============================================================================
 * Frame Processing Tracepoints
 * ============================================================================
 */

/**
 * quic_frame_recv - Frame received
 * @conn_id: Connection ID
 * @frame_type: Frame type
 * @len: Frame length in bytes
 */
TRACE_EVENT(quic_frame_recv,

	TP_PROTO(u64 conn_id, u8 frame_type, u32 len),

	TP_ARGS(conn_id, frame_type, len),

	TP_STRUCT__entry(
		__field(u64, conn_id)
		__field(u8, frame_type)
		__field(u32, len)
	),

	TP_fast_assign(
		__entry->conn_id = conn_id;
		__entry->frame_type = frame_type;
		__entry->len = len;
	),

	TP_printk("conn=%llx frame_type=0x%02x len=%u",
		__entry->conn_id, __entry->frame_type, __entry->len)
);

/**
 * quic_stream_data_recv - Stream data received
 * @conn_id: Connection ID
 * @stream_id: Stream ID
 * @offset: Data offset
 * @len: Data length
 * @fin: FIN flag
 */
TRACE_EVENT(quic_stream_data_recv,

	TP_PROTO(u64 conn_id, u64 stream_id, u64 offset, u32 len, bool fin),

	TP_ARGS(conn_id, stream_id, offset, len, fin),

	TP_STRUCT__entry(
		__field(u64, conn_id)
		__field(u64, stream_id)
		__field(u64, offset)
		__field(u32, len)
		__field(bool, fin)
	),

	TP_fast_assign(
		__entry->conn_id = conn_id;
		__entry->stream_id = stream_id;
		__entry->offset = offset;
		__entry->len = len;
		__entry->fin = fin;
	),

	TP_printk("conn=%llx stream=%llu offset=%llu len=%u fin=%d",
		__entry->conn_id, __entry->stream_id,
		__entry->offset, __entry->len, __entry->fin)
);

/**
 * quic_stream_data_send - Stream data sent
 * @conn_id: Connection ID
 * @stream_id: Stream ID
 * @offset: Data offset
 * @len: Data length
 * @fin: FIN flag
 */
TRACE_EVENT(quic_stream_data_send,

	TP_PROTO(u64 conn_id, u64 stream_id, u64 offset, u32 len, bool fin),

	TP_ARGS(conn_id, stream_id, offset, len, fin),

	TP_STRUCT__entry(
		__field(u64, conn_id)
		__field(u64, stream_id)
		__field(u64, offset)
		__field(u32, len)
		__field(bool, fin)
	),

	TP_fast_assign(
		__entry->conn_id = conn_id;
		__entry->stream_id = stream_id;
		__entry->offset = offset;
		__entry->len = len;
		__entry->fin = fin;
	),

	TP_printk("conn=%llx stream=%llu offset=%llu len=%u fin=%d",
		__entry->conn_id, __entry->stream_id,
		__entry->offset, __entry->len, __entry->fin)
);

/*
 * ============================================================================
 * Congestion Control Tracepoints
 * ============================================================================
 */

/**
 * quic_cc_state - Congestion control state update
 * @conn_id: Connection ID
 * @algo: Congestion control algorithm
 * @cwnd: Current congestion window (bytes)
 * @ssthresh: Slow start threshold (bytes)
 * @bytes_in_flight: Bytes currently in flight
 * @in_recovery: Currently in recovery state
 */
TRACE_EVENT(quic_cc_state,

	TP_PROTO(u64 conn_id, int algo, u64 cwnd, u64 ssthresh,
		 u64 bytes_in_flight, bool in_recovery),

	TP_ARGS(conn_id, algo, cwnd, ssthresh, bytes_in_flight, in_recovery),

	TP_STRUCT__entry(
		__field(u64, conn_id)
		__field(int, algo)
		__field(u64, cwnd)
		__field(u64, ssthresh)
		__field(u64, bytes_in_flight)
		__field(bool, in_recovery)
	),

	TP_fast_assign(
		__entry->conn_id = conn_id;
		__entry->algo = algo;
		__entry->cwnd = cwnd;
		__entry->ssthresh = ssthresh;
		__entry->bytes_in_flight = bytes_in_flight;
		__entry->in_recovery = in_recovery;
	),

	TP_printk("conn=%llx algo=%s cwnd=%llu ssthresh=%llu inflight=%llu recovery=%d",
		__entry->conn_id,
		show_quic_cc_algo(__entry->algo),
		__entry->cwnd, __entry->ssthresh,
		__entry->bytes_in_flight, __entry->in_recovery)
);

/**
 * quic_cc_loss - Loss event for congestion control
 * @conn_id: Connection ID
 * @lost_bytes: Bytes lost
 * @cwnd_before: CWND before loss
 * @cwnd_after: CWND after loss
 */
TRACE_EVENT(quic_cc_loss,

	TP_PROTO(u64 conn_id, u64 lost_bytes, u64 cwnd_before, u64 cwnd_after),

	TP_ARGS(conn_id, lost_bytes, cwnd_before, cwnd_after),

	TP_STRUCT__entry(
		__field(u64, conn_id)
		__field(u64, lost_bytes)
		__field(u64, cwnd_before)
		__field(u64, cwnd_after)
	),

	TP_fast_assign(
		__entry->conn_id = conn_id;
		__entry->lost_bytes = lost_bytes;
		__entry->cwnd_before = cwnd_before;
		__entry->cwnd_after = cwnd_after;
	),

	TP_printk("conn=%llx lost=%llu cwnd=%llu->%llu",
		__entry->conn_id, __entry->lost_bytes,
		__entry->cwnd_before, __entry->cwnd_after)
);

/*
 * ============================================================================
 * RTT Measurement Tracepoints
 * ============================================================================
 */

/**
 * quic_rtt_update - RTT measurement updated
 * @conn_id: Connection ID
 * @latest_rtt: Latest RTT sample (microseconds)
 * @min_rtt: Minimum RTT (microseconds)
 * @smoothed_rtt: Smoothed RTT (microseconds)
 * @rttvar: RTT variance (microseconds)
 */
TRACE_EVENT(quic_rtt_update,

	TP_PROTO(u64 conn_id, u32 latest_rtt, u32 min_rtt,
		 u32 smoothed_rtt, u32 rttvar),

	TP_ARGS(conn_id, latest_rtt, min_rtt, smoothed_rtt, rttvar),

	TP_STRUCT__entry(
		__field(u64, conn_id)
		__field(u32, latest_rtt)
		__field(u32, min_rtt)
		__field(u32, smoothed_rtt)
		__field(u32, rttvar)
	),

	TP_fast_assign(
		__entry->conn_id = conn_id;
		__entry->latest_rtt = latest_rtt;
		__entry->min_rtt = min_rtt;
		__entry->smoothed_rtt = smoothed_rtt;
		__entry->rttvar = rttvar;
	),

	TP_printk("conn=%llx latest=%u min=%u srtt=%u rttvar=%u (us)",
		__entry->conn_id, __entry->latest_rtt, __entry->min_rtt,
		__entry->smoothed_rtt, __entry->rttvar)
);

/*
 * ============================================================================
 * Path Management Tracepoints (Multipath)
 * ============================================================================
 */

/**
 * quic_path_create - New path created
 * @conn_id: Connection ID
 * @path_id: Path identifier (index)
 * @mtu: Path MTU
 */
TRACE_EVENT(quic_path_create,

	TP_PROTO(u64 conn_id, u32 path_id, u32 mtu),

	TP_ARGS(conn_id, path_id, mtu),

	TP_STRUCT__entry(
		__field(u64, conn_id)
		__field(u32, path_id)
		__field(u32, mtu)
	),

	TP_fast_assign(
		__entry->conn_id = conn_id;
		__entry->path_id = path_id;
		__entry->mtu = mtu;
	),

	TP_printk("conn=%llx path=%u mtu=%u",
		__entry->conn_id, __entry->path_id, __entry->mtu)
);

/**
 * quic_path_validated - Path validation completed
 * @conn_id: Connection ID
 * @path_id: Path identifier
 */
TRACE_EVENT(quic_path_validated,

	TP_PROTO(u64 conn_id, u32 path_id),

	TP_ARGS(conn_id, path_id),

	TP_STRUCT__entry(
		__field(u64, conn_id)
		__field(u32, path_id)
	),

	TP_fast_assign(
		__entry->conn_id = conn_id;
		__entry->path_id = path_id;
	),

	TP_printk("conn=%llx path=%u validated",
		__entry->conn_id, __entry->path_id)
);

/**
 * quic_path_failed - Path marked as failed
 * @conn_id: Connection ID
 * @path_id: Path identifier
 */
TRACE_EVENT(quic_path_failed,

	TP_PROTO(u64 conn_id, u32 path_id),

	TP_ARGS(conn_id, path_id),

	TP_STRUCT__entry(
		__field(u64, conn_id)
		__field(u32, path_id)
	),

	TP_fast_assign(
		__entry->conn_id = conn_id;
		__entry->path_id = path_id;
	),

	TP_printk("conn=%llx path=%u failed",
		__entry->conn_id, __entry->path_id)
);

/**
 * quic_path_migrate - Connection migrated to new path
 * @conn_id: Connection ID
 * @old_path_id: Previous active path
 * @new_path_id: New active path
 */
TRACE_EVENT(quic_path_migrate,

	TP_PROTO(u64 conn_id, u32 old_path_id, u32 new_path_id),

	TP_ARGS(conn_id, old_path_id, new_path_id),

	TP_STRUCT__entry(
		__field(u64, conn_id)
		__field(u32, old_path_id)
		__field(u32, new_path_id)
	),

	TP_fast_assign(
		__entry->conn_id = conn_id;
		__entry->old_path_id = old_path_id;
		__entry->new_path_id = new_path_id;
	),

	TP_printk("conn=%llx path=%u->%u",
		__entry->conn_id, __entry->old_path_id, __entry->new_path_id)
);

/*
 * ============================================================================
 * Error Condition Tracepoints
 * ============================================================================
 */

/**
 * quic_error - Error condition occurred
 * @conn_id: Connection ID
 * @error_code: QUIC error code
 * @frame_type: Frame type that caused error (0 if N/A)
 * @reason: Error reason (truncated)
 */
TRACE_EVENT(quic_error,

	TP_PROTO(u64 conn_id, u64 error_code, u64 frame_type,
		 const char *reason),

	TP_ARGS(conn_id, error_code, frame_type, reason),

	TP_STRUCT__entry(
		__field(u64, conn_id)
		__field(u64, error_code)
		__field(u64, frame_type)
		__string(reason, reason)
	),

	TP_fast_assign(
		__entry->conn_id = conn_id;
		__entry->error_code = error_code;
		__entry->frame_type = frame_type;
		__assign_str(reason, reason);
	),

	TP_printk("conn=%llx error=%llu frame_type=%llu reason=%s",
		__entry->conn_id, __entry->error_code,
		__entry->frame_type, __get_str(reason))
);

/**
 * quic_crypto_error - Cryptographic operation failed
 * @conn_id: Connection ID
 * @level: Encryption level
 * @operation: Operation name (encrypt/decrypt/protect/unprotect)
 * @err: Error code
 */
TRACE_EVENT(quic_crypto_error,

	TP_PROTO(u64 conn_id, u8 level, const char *operation, int err),

	TP_ARGS(conn_id, level, operation, err),

	TP_STRUCT__entry(
		__field(u64, conn_id)
		__field(u8, level)
		__string(operation, operation)
		__field(int, err)
	),

	TP_fast_assign(
		__entry->conn_id = conn_id;
		__entry->level = level;
		__assign_str(operation, operation);
		__entry->err = err;
	),

	TP_printk("conn=%llx level=%u op=%s err=%d",
		__entry->conn_id, __entry->level,
		__get_str(operation), __entry->err)
);

/*
 * ============================================================================
 * Timer Tracepoints
 * ============================================================================
 */

/**
 * quic_timer_set - Timer armed
 * @conn_id: Connection ID
 * @timer_type: Timer type (loss, ack, idle, etc.)
 * @timeout_us: Timeout value in microseconds
 */
TRACE_EVENT(quic_timer_set,

	TP_PROTO(u64 conn_id, u8 timer_type, u64 timeout_us),

	TP_ARGS(conn_id, timer_type, timeout_us),

	TP_STRUCT__entry(
		__field(u64, conn_id)
		__field(u8, timer_type)
		__field(u64, timeout_us)
	),

	TP_fast_assign(
		__entry->conn_id = conn_id;
		__entry->timer_type = timer_type;
		__entry->timeout_us = timeout_us;
	),

	TP_printk("conn=%llx timer=%u timeout=%llu us",
		__entry->conn_id, __entry->timer_type, __entry->timeout_us)
);

/**
 * quic_timer_expired - Timer expired
 * @conn_id: Connection ID
 * @timer_type: Timer type
 */
TRACE_EVENT(quic_timer_expired,

	TP_PROTO(u64 conn_id, u8 timer_type),

	TP_ARGS(conn_id, timer_type),

	TP_STRUCT__entry(
		__field(u64, conn_id)
		__field(u8, timer_type)
	),

	TP_fast_assign(
		__entry->conn_id = conn_id;
		__entry->timer_type = timer_type;
	),

	TP_printk("conn=%llx timer=%u expired",
		__entry->conn_id, __entry->timer_type)
);

/**
 * quic_pto_timeout - PTO (Probe Timeout) fired
 * @conn_id: Connection ID
 * @pto_count: Current PTO count (backoff level)
 * @pn_space: Packet number space for probe
 */
TRACE_EVENT(quic_pto_timeout,

	TP_PROTO(u64 conn_id, u32 pto_count, u8 pn_space),

	TP_ARGS(conn_id, pto_count, pn_space),

	TP_STRUCT__entry(
		__field(u64, conn_id)
		__field(u32, pto_count)
		__field(u8, pn_space)
	),

	TP_fast_assign(
		__entry->conn_id = conn_id;
		__entry->pto_count = pto_count;
		__entry->pn_space = pn_space;
	),

	TP_printk("conn=%llx pto_count=%u space=%s",
		__entry->conn_id, __entry->pto_count,
		show_quic_pn_space(__entry->pn_space))
);

/*
 * ============================================================================
 * Key Update Tracepoints
 * ============================================================================
 */

/**
 * quic_key_update - Key update initiated or received
 * @conn_id: Connection ID
 * @key_phase: New key phase bit
 * @initiated: true if locally initiated, false if received
 */
TRACE_EVENT(quic_key_update,

	TP_PROTO(u64 conn_id, u8 key_phase, bool initiated),

	TP_ARGS(conn_id, key_phase, initiated),

	TP_STRUCT__entry(
		__field(u64, conn_id)
		__field(u8, key_phase)
		__field(bool, initiated)
	),

	TP_fast_assign(
		__entry->conn_id = conn_id;
		__entry->key_phase = key_phase;
		__entry->initiated = initiated;
	),

	TP_printk("conn=%llx key_phase=%u %s",
		__entry->conn_id, __entry->key_phase,
		__entry->initiated ? "initiated" : "received")
);

#endif /* _TRACE_QUIC_H */

/* This part must be outside protection */
#include <trace/define_trace.h>
