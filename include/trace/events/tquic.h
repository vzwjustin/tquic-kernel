/* SPDX-License-Identifier: GPL-2.0 */
#undef TRACE_SYSTEM
#define TRACE_SYSTEM tquic

#if !defined(_TRACE_TQUIC_H) || defined(TRACE_HEADER_MULTI_READ)
#define _TRACE_TQUIC_H

#include <linux/tracepoint.h>
#include <linux/skbuff.h>
#include <net/tquic.h>

/*
 * TQUIC Tracepoint Definitions
 *
 * These tracepoints enable observability into TQUIC connections,
 * paths, packets, and congestion control for debugging, monitoring,
 * and BPF program attachment.
 */

/*
 * Connection lifecycle events
 */

TRACE_EVENT(tquic_conn_create,

	TP_PROTO(const struct tquic_connection *conn,
		 const struct sockaddr_storage *local,
		 const struct sockaddr_storage *remote),

	TP_ARGS(conn, local, remote),

	TP_STRUCT__entry(
		__field(u64, conn_id)
		__field(u16, local_port)
		__field(u16, remote_port)
		__field(u8, state)
		__field(u8, is_server)
		__array(u8, scid, 20)
		__array(u8, dcid, 20)
	),

	TP_fast_assign(
		__entry->conn_id = (u64)(unsigned long)conn;
		__entry->local_port = conn->local_port;
		__entry->remote_port = conn->remote_port;
		__entry->state = conn->state;
		__entry->is_server = conn->is_server;
		memcpy(__entry->scid, conn->scid.id, min_t(size_t, conn->scid.len, 20));
		memcpy(__entry->dcid, conn->dcid.id, min_t(size_t, conn->dcid.len, 20));
	),

	TP_printk("conn=%llx local_port=%u remote_port=%u state=%u server=%u",
		  __entry->conn_id,
		  __entry->local_port,
		  __entry->remote_port,
		  __entry->state,
		  __entry->is_server)
);

TRACE_EVENT(tquic_conn_destroy,

	TP_PROTO(const struct tquic_connection *conn,
		 u64 bytes_sent, u64 bytes_recv),

	TP_ARGS(conn, bytes_sent, bytes_recv),

	TP_STRUCT__entry(
		__field(u64, conn_id)
		__field(u64, bytes_sent)
		__field(u64, bytes_recv)
		__field(u32, duration_ms)
		__field(u8, close_reason)
	),

	TP_fast_assign(
		__entry->conn_id = (u64)(unsigned long)conn;
		__entry->bytes_sent = bytes_sent;
		__entry->bytes_recv = bytes_recv;
		__entry->duration_ms = jiffies_to_msecs(jiffies - conn->established_time);
		__entry->close_reason = conn->close_reason;
	),

	TP_printk("conn=%llx tx=%llu rx=%llu duration=%ums reason=%u",
		  __entry->conn_id,
		  __entry->bytes_sent,
		  __entry->bytes_recv,
		  __entry->duration_ms,
		  __entry->close_reason)
);

TRACE_EVENT(tquic_conn_state_change,

	TP_PROTO(const struct tquic_connection *conn,
		 u8 old_state, u8 new_state),

	TP_ARGS(conn, old_state, new_state),

	TP_STRUCT__entry(
		__field(u64, conn_id)
		__field(u8, old_state)
		__field(u8, new_state)
	),

	TP_fast_assign(
		__entry->conn_id = (u64)(unsigned long)conn;
		__entry->old_state = old_state;
		__entry->new_state = new_state;
	),

	TP_printk("conn=%llx state=%u->%u",
		  __entry->conn_id,
		  __entry->old_state,
		  __entry->new_state)
);

/*
 * Handshake events
 */

TRACE_EVENT(tquic_handshake_start,

	TP_PROTO(const struct tquic_connection *conn, bool is_retry),

	TP_ARGS(conn, is_retry),

	TP_STRUCT__entry(
		__field(u64, conn_id)
		__field(bool, is_retry)
		__field(bool, is_server)
	),

	TP_fast_assign(
		__entry->conn_id = (u64)(unsigned long)conn;
		__entry->is_retry = is_retry;
		__entry->is_server = conn->is_server;
	),

	TP_printk("conn=%llx retry=%d server=%d",
		  __entry->conn_id,
		  __entry->is_retry,
		  __entry->is_server)
);

TRACE_EVENT(tquic_handshake_complete,

	TP_PROTO(const struct tquic_connection *conn, u32 rtt_us),

	TP_ARGS(conn, rtt_us),

	TP_STRUCT__entry(
		__field(u64, conn_id)
		__field(u32, rtt_us)
		__field(u32, handshake_ms)
	),

	TP_fast_assign(
		__entry->conn_id = (u64)(unsigned long)conn;
		__entry->rtt_us = rtt_us;
		__entry->handshake_ms = jiffies_to_msecs(jiffies - conn->established_time);
	),

	TP_printk("conn=%llx rtt=%uus handshake=%ums",
		  __entry->conn_id,
		  __entry->rtt_us,
		  __entry->handshake_ms)
);

/*
 * Packet events
 */

TRACE_EVENT(tquic_packet_recv,

	TP_PROTO(const struct tquic_connection *conn,
		 const struct tquic_path *path,
		 u64 pkt_num, u32 pkt_len, u8 pkt_type),

	TP_ARGS(conn, path, pkt_num, pkt_len, pkt_type),

	TP_STRUCT__entry(
		__field(u64, conn_id)
		__field(u32, path_id)
		__field(u64, pkt_num)
		__field(u32, pkt_len)
		__field(u8, pkt_type)
	),

	TP_fast_assign(
		__entry->conn_id = (u64)(unsigned long)conn;
		__entry->path_id = path ? path->path_id : 0;
		__entry->pkt_num = pkt_num;
		__entry->pkt_len = pkt_len;
		__entry->pkt_type = pkt_type;
	),

	TP_printk("conn=%llx path=%u pkt=%llu len=%u type=%u",
		  __entry->conn_id,
		  __entry->path_id,
		  __entry->pkt_num,
		  __entry->pkt_len,
		  __entry->pkt_type)
);

TRACE_EVENT(tquic_packet_send,

	TP_PROTO(const struct tquic_connection *conn,
		 const struct tquic_path *path,
		 u64 pkt_num, u32 pkt_len, u8 pkt_type),

	TP_ARGS(conn, path, pkt_num, pkt_len, pkt_type),

	TP_STRUCT__entry(
		__field(u64, conn_id)
		__field(u32, path_id)
		__field(u64, pkt_num)
		__field(u32, pkt_len)
		__field(u8, pkt_type)
	),

	TP_fast_assign(
		__entry->conn_id = (u64)(unsigned long)conn;
		__entry->path_id = path ? path->path_id : 0;
		__entry->pkt_num = pkt_num;
		__entry->pkt_len = pkt_len;
		__entry->pkt_type = pkt_type;
	),

	TP_printk("conn=%llx path=%u pkt=%llu len=%u type=%u",
		  __entry->conn_id,
		  __entry->path_id,
		  __entry->pkt_num,
		  __entry->pkt_len,
		  __entry->pkt_type)
);

TRACE_EVENT(tquic_packet_lost,

	TP_PROTO(const struct tquic_connection *conn,
		 const struct tquic_path *path,
		 u64 pkt_num, u8 reason),

	TP_ARGS(conn, path, pkt_num, reason),

	TP_STRUCT__entry(
		__field(u64, conn_id)
		__field(u32, path_id)
		__field(u64, pkt_num)
		__field(u8, reason)
	),

	TP_fast_assign(
		__entry->conn_id = (u64)(unsigned long)conn;
		__entry->path_id = path ? path->path_id : 0;
		__entry->pkt_num = pkt_num;
		__entry->reason = reason;
	),

	TP_printk("conn=%llx path=%u pkt=%llu reason=%u",
		  __entry->conn_id,
		  __entry->path_id,
		  __entry->pkt_num,
		  __entry->reason)
);

/*
 * Path management events (WAN bonding)
 */

TRACE_EVENT(tquic_path_add,

	TP_PROTO(const struct tquic_connection *conn,
		 const struct tquic_path *path),

	TP_ARGS(conn, path),

	TP_STRUCT__entry(
		__field(u64, conn_id)
		__field(u32, path_id)
		__field(u8, state)
		__field(u32, ifindex)
		__field(u16, local_port)
		__field(u16, remote_port)
	),

	TP_fast_assign(
		__entry->conn_id = (u64)(unsigned long)conn;
		__entry->path_id = path->path_id;
		__entry->state = path->state;
		__entry->ifindex = path->ifindex;
		__entry->local_port = path->local_port;
		__entry->remote_port = path->remote_port;
	),

	TP_printk("conn=%llx path=%u state=%u if=%u ports=%u/%u",
		  __entry->conn_id,
		  __entry->path_id,
		  __entry->state,
		  __entry->ifindex,
		  __entry->local_port,
		  __entry->remote_port)
);

TRACE_EVENT(tquic_path_remove,

	TP_PROTO(const struct tquic_connection *conn,
		 const struct tquic_path *path, u8 reason),

	TP_ARGS(conn, path, reason),

	TP_STRUCT__entry(
		__field(u64, conn_id)
		__field(u32, path_id)
		__field(u8, reason)
		__field(u64, bytes_sent)
		__field(u64, bytes_recv)
	),

	TP_fast_assign(
		__entry->conn_id = (u64)(unsigned long)conn;
		__entry->path_id = path->path_id;
		__entry->reason = reason;
		__entry->bytes_sent = path->stats.tx_bytes;
		__entry->bytes_recv = path->stats.rx_bytes;
	),

	TP_printk("conn=%llx path=%u reason=%u tx=%llu rx=%llu",
		  __entry->conn_id,
		  __entry->path_id,
		  __entry->reason,
		  __entry->bytes_sent,
		  __entry->bytes_recv)
);

TRACE_EVENT(tquic_path_state_change,

	TP_PROTO(const struct tquic_connection *conn,
		 const struct tquic_path *path,
		 u8 old_state, u8 new_state),

	TP_ARGS(conn, path, old_state, new_state),

	TP_STRUCT__entry(
		__field(u64, conn_id)
		__field(u32, path_id)
		__field(u8, old_state)
		__field(u8, new_state)
	),

	TP_fast_assign(
		__entry->conn_id = (u64)(unsigned long)conn;
		__entry->path_id = path->path_id;
		__entry->old_state = old_state;
		__entry->new_state = new_state;
	),

	TP_printk("conn=%llx path=%u state=%u->%u",
		  __entry->conn_id,
		  __entry->path_id,
		  __entry->old_state,
		  __entry->new_state)
);

TRACE_EVENT(tquic_path_rtt_update,

	TP_PROTO(const struct tquic_connection *conn,
		 const struct tquic_path *path,
		 u32 rtt_us, u32 srtt_us, u32 rttvar_us),

	TP_ARGS(conn, path, rtt_us, srtt_us, rttvar_us),

	TP_STRUCT__entry(
		__field(u64, conn_id)
		__field(u32, path_id)
		__field(u32, rtt_us)
		__field(u32, srtt_us)
		__field(u32, rttvar_us)
	),

	TP_fast_assign(
		__entry->conn_id = (u64)(unsigned long)conn;
		__entry->path_id = path->path_id;
		__entry->rtt_us = rtt_us;
		__entry->srtt_us = srtt_us;
		__entry->rttvar_us = rttvar_us;
	),

	TP_printk("conn=%llx path=%u rtt=%uus srtt=%uus var=%uus",
		  __entry->conn_id,
		  __entry->path_id,
		  __entry->rtt_us,
		  __entry->srtt_us,
		  __entry->rttvar_us)
);

/*
 * Congestion control events
 */

TRACE_EVENT(tquic_cong_state_change,

	TP_PROTO(const struct tquic_connection *conn,
		 const struct tquic_path *path,
		 u8 old_state, u8 new_state,
		 u64 cwnd, u64 ssthresh),

	TP_ARGS(conn, path, old_state, new_state, cwnd, ssthresh),

	TP_STRUCT__entry(
		__field(u64, conn_id)
		__field(u32, path_id)
		__field(u8, old_state)
		__field(u8, new_state)
		__field(u64, cwnd)
		__field(u64, ssthresh)
	),

	TP_fast_assign(
		__entry->conn_id = (u64)(unsigned long)conn;
		__entry->path_id = path ? path->path_id : 0;
		__entry->old_state = old_state;
		__entry->new_state = new_state;
		__entry->cwnd = cwnd;
		__entry->ssthresh = ssthresh;
	),

	TP_printk("conn=%llx path=%u state=%u->%u cwnd=%llu ssthresh=%llu",
		  __entry->conn_id,
		  __entry->path_id,
		  __entry->old_state,
		  __entry->new_state,
		  __entry->cwnd,
		  __entry->ssthresh)
);

TRACE_EVENT(tquic_cong_cwnd_update,

	TP_PROTO(const struct tquic_connection *conn,
		 const struct tquic_path *path,
		 u64 old_cwnd, u64 new_cwnd,
		 u64 bytes_in_flight),

	TP_ARGS(conn, path, old_cwnd, new_cwnd, bytes_in_flight),

	TP_STRUCT__entry(
		__field(u64, conn_id)
		__field(u32, path_id)
		__field(u64, old_cwnd)
		__field(u64, new_cwnd)
		__field(u64, bytes_in_flight)
	),

	TP_fast_assign(
		__entry->conn_id = (u64)(unsigned long)conn;
		__entry->path_id = path ? path->path_id : 0;
		__entry->old_cwnd = old_cwnd;
		__entry->new_cwnd = new_cwnd;
		__entry->bytes_in_flight = bytes_in_flight;
	),

	TP_printk("conn=%llx path=%u cwnd=%llu->%llu inflight=%llu",
		  __entry->conn_id,
		  __entry->path_id,
		  __entry->old_cwnd,
		  __entry->new_cwnd,
		  __entry->bytes_in_flight)
);

/*
 * Scheduler events (multipath)
 */

TRACE_EVENT(tquic_sched_select_path,

	TP_PROTO(const struct tquic_connection *conn,
		 const struct tquic_path *path,
		 u8 sched_type, u32 score),

	TP_ARGS(conn, path, sched_type, score),

	TP_STRUCT__entry(
		__field(u64, conn_id)
		__field(u32, path_id)
		__field(u8, sched_type)
		__field(u32, score)
	),

	TP_fast_assign(
		__entry->conn_id = (u64)(unsigned long)conn;
		__entry->path_id = path->path_id;
		__entry->sched_type = sched_type;
		__entry->score = score;
	),

	TP_printk("conn=%llx path=%u sched=%u score=%u",
		  __entry->conn_id,
		  __entry->path_id,
		  __entry->sched_type,
		  __entry->score)
);

/*
 * WAN bonding events
 */

TRACE_EVENT(tquic_bond_failover,

	TP_PROTO(const struct tquic_connection *conn,
		 const struct tquic_path *from_path,
		 const struct tquic_path *to_path,
		 u8 reason),

	TP_ARGS(conn, from_path, to_path, reason),

	TP_STRUCT__entry(
		__field(u64, conn_id)
		__field(u32, from_path_id)
		__field(u32, to_path_id)
		__field(u8, reason)
	),

	TP_fast_assign(
		__entry->conn_id = (u64)(unsigned long)conn;
		__entry->from_path_id = from_path ? from_path->path_id : 0;
		__entry->to_path_id = to_path ? to_path->path_id : 0;
		__entry->reason = reason;
	),

	TP_printk("conn=%llx from=%u to=%u reason=%u",
		  __entry->conn_id,
		  __entry->from_path_id,
		  __entry->to_path_id,
		  __entry->reason)
);

TRACE_EVENT(tquic_bond_mode_change,

	TP_PROTO(const struct tquic_connection *conn,
		 u8 old_mode, u8 new_mode),

	TP_ARGS(conn, old_mode, new_mode),

	TP_STRUCT__entry(
		__field(u64, conn_id)
		__field(u8, old_mode)
		__field(u8, new_mode)
	),

	TP_fast_assign(
		__entry->conn_id = (u64)(unsigned long)conn;
		__entry->old_mode = old_mode;
		__entry->new_mode = new_mode;
	),

	TP_printk("conn=%llx mode=%u->%u",
		  __entry->conn_id,
		  __entry->old_mode,
		  __entry->new_mode)
);

/*
 * Stream events
 */

TRACE_EVENT(tquic_stream_open,

	TP_PROTO(const struct tquic_connection *conn,
		 u64 stream_id, bool local_initiated),

	TP_ARGS(conn, stream_id, local_initiated),

	TP_STRUCT__entry(
		__field(u64, conn_id)
		__field(u64, stream_id)
		__field(bool, local_initiated)
	),

	TP_fast_assign(
		__entry->conn_id = (u64)(unsigned long)conn;
		__entry->stream_id = stream_id;
		__entry->local_initiated = local_initiated;
	),

	TP_printk("conn=%llx stream=%llu local=%d",
		  __entry->conn_id,
		  __entry->stream_id,
		  __entry->local_initiated)
);

TRACE_EVENT(tquic_stream_close,

	TP_PROTO(const struct tquic_connection *conn,
		 u64 stream_id, u64 bytes_sent, u64 bytes_recv),

	TP_ARGS(conn, stream_id, bytes_sent, bytes_recv),

	TP_STRUCT__entry(
		__field(u64, conn_id)
		__field(u64, stream_id)
		__field(u64, bytes_sent)
		__field(u64, bytes_recv)
	),

	TP_fast_assign(
		__entry->conn_id = (u64)(unsigned long)conn;
		__entry->stream_id = stream_id;
		__entry->bytes_sent = bytes_sent;
		__entry->bytes_recv = bytes_recv;
	),

	TP_printk("conn=%llx stream=%llu tx=%llu rx=%llu",
		  __entry->conn_id,
		  __entry->stream_id,
		  __entry->bytes_sent,
		  __entry->bytes_recv)
);

/*
 * Error events
 */

TRACE_EVENT(tquic_error,

	TP_PROTO(const struct tquic_connection *conn,
		 u32 error_code, const char *reason),

	TP_ARGS(conn, error_code, reason),

	TP_STRUCT__entry(
		__field(u64, conn_id)
		__field(u32, error_code)
		__string(reason, reason)
	),

	TP_fast_assign(
		__entry->conn_id = conn ? (u64)(unsigned long)conn : 0;
		__entry->error_code = error_code;
		__assign_str(reason);
	),

	TP_printk("conn=%llx error=%u reason=%s",
		  __entry->conn_id,
		  __entry->error_code,
		  __get_str(reason))
);

/*
 * ICMP/path error events
 */

TRACE_EVENT(tquic_icmp_error,

	TP_PROTO(const struct tquic_connection *conn,
		 const struct tquic_path *path,
		 u8 type, u8 code, u32 info),

	TP_ARGS(conn, path, type, code, info),

	TP_STRUCT__entry(
		__field(u64, conn_id)
		__field(u32, path_id)
		__field(u8, type)
		__field(u8, code)
		__field(u32, info)
	),

	TP_fast_assign(
		__entry->conn_id = conn ? (u64)(unsigned long)conn : 0;
		__entry->path_id = path ? path->path_id : 0;
		__entry->type = type;
		__entry->code = code;
		__entry->info = info;
	),

	TP_printk("conn=%llx path=%u icmp_type=%u code=%u info=%u",
		  __entry->conn_id,
		  __entry->path_id,
		  __entry->type,
		  __entry->code,
		  __entry->info)
);

#endif /* _TRACE_TQUIC_H */

/* This part must be outside protection */
#undef TRACE_INCLUDE_PATH
#define TRACE_INCLUDE_PATH trace/events
#undef TRACE_INCLUDE_FILE
#define TRACE_INCLUDE_FILE tquic
#include <trace/define_trace.h>
