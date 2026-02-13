// SPDX-License-Identifier: GPL-2.0
/*
 * TQUIC Tracepoints for eBPF Observability
 *
 * Copyright (c) 2026 Justin Adams <spotty118@gmail.com>
 * Kernel implementation by Justin Adams <spotty118@gmail.com>
 *
 * Provides comprehensive tracepoints for observing QUIC protocol behavior
 * via eBPF programs. These tracepoints enable:
 *
 *   - Real-time connection monitoring
 *   - Performance analysis and profiling
 *   - Custom metrics collection
 *   - Debugging and troubleshooting
 *   - Security monitoring and auditing
 *
 * Tracepoint Categories:
 *   - tquic:connection_* - Connection lifecycle events
 *   - tquic:packet_* - Packet transmission/reception
 *   - tquic:stream_* - Stream operations
 *   - tquic:crypto_* - Cryptographic operations
 *   - tquic:cc_* - Congestion control events
 *   - tquic:path_* - Multipath events
 *   - tquic:timer_* - Timer events
 *   - tquic:error_* - Error events
 *
 * Usage with bpftrace:
 *   bpftrace -e 'tracepoint:tquic:packet_sent { @bytes = sum(args->size); }'
 *
 * Usage with BPF programs:
 *   SEC("tp/tquic/connection_established")
 *   int trace_conn(struct tquic_conn_established_args *ctx) { ... }
 */

#define CREATE_TRACE_POINTS
#include "tracepoints.h"

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <net/tquic.h>
#include <net/net_namespace.h>

#include "path_metrics.h"
#include "trace.h"
#include "../tquic_debug.h"
#include "../tquic_init.h"
#include "trace_wrappers.h"
/*
 * =============================================================================
 * Tracepoint Implementations
 * =============================================================================
 */

/**
 * tquic_trace_connection_new - Trace new connection attempt
 * @conn: Connection structure
 * @is_server: Server or client role
 */
void tquic_trace_connection_new(struct tquic_connection *conn, bool is_server)
{
	if (!conn)
		return;

	trace_tquic_connection_new(
		quic_trace_conn_id(&conn->scid),
		is_server,
		conn->version,
		conn->scid.id,
		conn->scid.len,
		conn->dcid.id,
		conn->dcid.len
	);
}
EXPORT_SYMBOL_GPL(tquic_trace_connection_new);

/**
 * tquic_trace_connection_established - Trace connection establishment
 * @conn: Connection structure
 * @handshake_time_us: Time to complete handshake
 */
void tquic_trace_connection_established(struct tquic_connection *conn,
					u64 handshake_time_us)
{
	if (!conn)
		return;

	trace_tquic_connection_established(
		quic_trace_conn_id(&conn->scid),
		handshake_time_us,
		conn->version,
		0, /* cipher_suite not on conn */
		conn->early_data_accepted
	);
}
EXPORT_SYMBOL_GPL(tquic_trace_connection_established);

/**
 * tquic_trace_connection_closed - Trace connection closure
 * @conn: Connection structure
 * @error_code: QUIC error code
 * @reason: Closure reason
 * @is_app_error: Application vs transport error
 */
void tquic_trace_connection_closed(struct tquic_connection *conn,
				   u64 error_code, const char *reason,
				   bool is_app_error)
{
	if (!conn)
		return;

	trace_tquic_connection_closed(
		quic_trace_conn_id(&conn->scid),
		error_code,
		reason ? reason : "",
		is_app_error,
		conn->stats.tx_bytes,
		conn->stats.rx_bytes
	);
}
EXPORT_SYMBOL_GPL(tquic_trace_connection_closed);

/**
 * tquic_trace_packet_sent - Trace packet transmission
 * @conn: Connection structure
 * @pkt_num: Packet number
 * @pkt_type: Packet type (initial/handshake/0rtt/1rtt)
 * @size: Packet size in bytes
 * @path_id: Path ID for multipath
 */
void tquic_trace_packet_sent(struct tquic_connection *conn,
			     u64 pkt_num, u32 pkt_type, u32 size,
			     u32 path_id)
{
	struct tquic_path *path;
	u64 bytes_in_flight = 0;
	u64 cwnd = 0;

	if (!conn)
		return;

	rcu_read_lock();
	path = rcu_dereference(conn->active_path);
	if (path) {
		bytes_in_flight = path->cc.bytes_in_flight;
		cwnd = path->cc.cwnd;
	}
	rcu_read_unlock();

	trace_tquic_packet_sent(
		quic_trace_conn_id(&conn->scid),
		pkt_num,
		pkt_type,
		size,
		path_id,
		bytes_in_flight,
		cwnd
	);
}
EXPORT_SYMBOL_GPL(tquic_trace_packet_sent);

/**
 * tquic_trace_packet_received - Trace packet reception
 * @conn: Connection structure
 * @pkt_num: Packet number
 * @pkt_type: Packet type
 * @size: Packet size
 * @path_id: Path ID
 * @ecn: ECN marking
 */
void tquic_trace_packet_received(struct tquic_connection *conn,
				 u64 pkt_num, u32 pkt_type, u32 size,
				 u32 path_id, u8 ecn)
{
	if (!conn)
		return;

	trace_tquic_packet_received(
		quic_trace_conn_id(&conn->scid),
		pkt_num,
		pkt_type,
		size,
		path_id,
		ecn
	);
}
EXPORT_SYMBOL_GPL(tquic_trace_packet_received);

/**
 * tquic_trace_packet_dropped - Trace dropped packet
 * @conn: Connection structure (may be NULL)
 * @pkt_type: Packet type
 * @size: Packet size
 * @reason: Drop reason
 */
void tquic_trace_packet_dropped(struct tquic_connection *conn,
				u32 pkt_type, u32 size, u32 reason)
{
	trace_tquic_packet_dropped(
		conn ? quic_trace_conn_id(&conn->scid) : 0,
		pkt_type,
		size,
		reason
	);
}
EXPORT_SYMBOL_GPL(tquic_trace_packet_dropped);

/**
 * tquic_trace_packet_lost - Trace packet loss detection
 * @conn: Connection structure
 * @pkt_num: Lost packet number
 * @size: Packet size
 * @trigger: Loss detection trigger
 * @path_id: Path ID
 */
void tquic_trace_packet_lost(struct tquic_connection *conn,
			     u64 pkt_num, u32 size, u32 trigger,
			     u32 path_id)
{
	if (!conn)
		return;

	trace_tquic_packet_lost(
		quic_trace_conn_id(&conn->scid),
		pkt_num,
		size,
		trigger,
		path_id,
		conn->stats.lost_packets
	);
}
EXPORT_SYMBOL_GPL(tquic_trace_packet_lost);

/**
 * tquic_trace_stream_opened - Trace stream creation
 * @conn: Connection structure
 * @stream_id: Stream ID
 * @is_bidi: Bidirectional stream
 * @is_local: Locally initiated
 */
void tquic_trace_stream_opened(struct tquic_connection *conn,
			       u64 stream_id, bool is_bidi, bool is_local)
{
	if (!conn)
		return;

	trace_tquic_stream_opened(
		quic_trace_conn_id(&conn->scid),
		stream_id,
		is_bidi,
		is_local
	);
}
EXPORT_SYMBOL_GPL(tquic_trace_stream_opened);

/**
 * tquic_trace_stream_closed - Trace stream closure
 * @conn: Connection structure
 * @stream_id: Stream ID
 * @error_code: Application error code (0 if clean close)
 * @bytes_sent: Bytes sent on stream
 * @bytes_received: Bytes received on stream
 */
void tquic_trace_stream_closed(struct tquic_connection *conn,
			       u64 stream_id, u64 error_code,
			       u64 bytes_sent, u64 bytes_received)
{
	if (!conn)
		return;

	trace_tquic_stream_closed(
		quic_trace_conn_id(&conn->scid),
		stream_id,
		error_code,
		bytes_sent,
		bytes_received
	);
}
EXPORT_SYMBOL_GPL(tquic_trace_stream_closed);

/**
 * tquic_trace_stream_data - Trace stream data transfer
 * @conn: Connection structure
 * @stream_id: Stream ID
 * @offset: Data offset in stream
 * @length: Data length
 * @is_fin: FIN flag set
 * @is_send: Sending (true) or receiving (false)
 */
void tquic_trace_stream_data(struct tquic_connection *conn,
			     u64 stream_id, u64 offset, u32 length,
			     bool is_fin, bool is_send)
{
	if (!conn)
		return;

	trace_tquic_stream_data(
		quic_trace_conn_id(&conn->scid),
		stream_id,
		offset,
		length,
		is_fin,
		is_send
	);
}
EXPORT_SYMBOL_GPL(tquic_trace_stream_data);

/**
 * tquic_trace_crypto_key_update - Trace key update event
 * @conn: Connection structure
 * @key_type: Type of key (initial/handshake/1rtt)
 * @key_phase: Key phase
 * @trigger: Update trigger
 */
void tquic_trace_crypto_key_update(struct tquic_connection *conn,
				   u32 key_type, u32 key_phase,
				   u32 trigger)
{
	if (!conn)
		return;

	trace_tquic_crypto_key_update(
		quic_trace_conn_id(&conn->scid),
		key_type,
		key_phase,
		trigger
	);
}
EXPORT_SYMBOL_GPL(tquic_trace_crypto_key_update);

/**
 * tquic_trace_cc_state_changed - Trace congestion control state change
 * @conn: Connection structure
 * @old_state: Previous state
 * @new_state: New state
 * @cwnd: Current congestion window
 * @ssthresh: Current slow start threshold
 * @path_id: Path ID
 */
void tquic_trace_cc_state_changed(struct tquic_connection *conn,
				  u32 old_state, u32 new_state,
				  u64 cwnd, u64 ssthresh, u32 path_id)
{
	if (!conn)
		return;

	trace_tquic_cc_state_changed(
		quic_trace_conn_id(&conn->scid),
		old_state,
		new_state,
		cwnd,
		ssthresh,
		path_id
	);
}
EXPORT_SYMBOL_GPL(tquic_trace_cc_state_changed);

/**
 * tquic_trace_cc_metrics_updated - Trace congestion metrics update
 * @conn: Connection structure
 * @cwnd: Congestion window
 * @bytes_in_flight: Bytes currently in flight
 * @smoothed_rtt: Smoothed RTT (us)
 * @min_rtt: Minimum RTT (us)
 * @pacing_rate: Pacing rate (bytes/sec)
 * @path_id: Path ID
 */
void tquic_trace_cc_metrics_updated(struct tquic_connection *conn,
				    u64 cwnd, u64 bytes_in_flight,
				    u64 smoothed_rtt, u64 min_rtt,
				    u64 pacing_rate, u32 path_id)
{
	if (!conn)
		return;

	trace_tquic_cc_metrics_updated(
		quic_trace_conn_id(&conn->scid),
		cwnd,
		bytes_in_flight,
		smoothed_rtt,
		min_rtt,
		pacing_rate,
		path_id
	);
}
EXPORT_SYMBOL_GPL(tquic_trace_cc_metrics_updated);

/**
 * tquic_trace_path_created - Trace new path creation
 * @conn: Connection structure
 * @path_id: Path ID
 * @local_addr: Local address (as u32 for IPv4)
 * @remote_addr: Remote address
 * @local_port: Local port
 * @remote_port: Remote port
 */
void tquic_trace_path_created(struct tquic_connection *conn,
			      u32 path_id, u32 local_addr, u32 remote_addr,
			      u16 local_port, u16 remote_port)
{
	if (!conn)
		return;

	trace_tquic_path_created(
		quic_trace_conn_id(&conn->scid),
		path_id,
		local_addr,
		remote_addr,
		local_port,
		remote_port
	);
}
EXPORT_SYMBOL_GPL(tquic_trace_path_created);

/**
 * tquic_trace_path_validated - Trace path validation
 * @conn: Connection structure
 * @path_id: Path ID
 * @validation_time_us: Time to validate path
 */
void tquic_trace_path_validated(struct tquic_connection *conn,
				u32 path_id, u64 validation_time_us)
{
	if (!conn)
		return;

	trace_tquic_path_validated(
		quic_trace_conn_id(&conn->scid),
		path_id,
		validation_time_us
	);
}
EXPORT_SYMBOL_GPL(tquic_trace_path_validated);

/**
 * tquic_trace_path_closed - Trace path closure
 * @conn: Connection structure
 * @path_id: Path ID
 * @reason: Closure reason
 */
void tquic_trace_path_closed(struct tquic_connection *conn,
			     u32 path_id, u32 reason)
{
	if (!conn)
		return;

	trace_tquic_path_closed(
		quic_trace_conn_id(&conn->scid),
		path_id,
		reason
	);
}
EXPORT_SYMBOL_GPL(tquic_trace_path_closed);

/**
 * tquic_trace_timer_set - Trace timer arm/rearm
 * @conn: Connection structure
 * @timer_type: Timer type (ack/pto/idle/etc)
 * @timeout_us: Timeout duration
 */
void tquic_trace_timer_set(struct tquic_connection *conn,
			   u32 timer_type, u64 timeout_us)
{
	if (!conn)
		return;

	trace_tquic_timer_set(
		quic_trace_conn_id(&conn->scid),
		timer_type,
		timeout_us
	);
}
EXPORT_SYMBOL_GPL(tquic_trace_timer_set);

/**
 * tquic_trace_timer_expired - Trace timer expiration
 * @conn: Connection structure
 * @timer_type: Timer type
 */
void tquic_trace_timer_expired(struct tquic_connection *conn, u32 timer_type)
{
	if (!conn)
		return;

	trace_tquic_timer_expired(
		quic_trace_conn_id(&conn->scid),
		timer_type
	);
}
EXPORT_SYMBOL_GPL(tquic_trace_timer_expired);

/**
 * tquic_trace_error - Trace error event
 * @conn: Connection structure (may be NULL)
 * @error_type: Error type
 * @error_code: Error code
 * @message: Error message
 */
void tquic_trace_error(struct tquic_connection *conn,
		       u32 error_type, u64 error_code, const char *message)
{
	trace_tquic_error(
		conn ? quic_trace_conn_id(&conn->scid) : 0,
		error_type,
		error_code,
		message ? message : ""
	);
}
EXPORT_SYMBOL_GPL(tquic_trace_error);

/**
 * tquic_trace_migration - Trace connection migration
 * @conn: Connection structure
 * @old_path_id: Previous path ID
 * @new_path_id: New path ID
 * @migration_type: Type of migration
 */
void tquic_trace_migration(struct tquic_connection *conn,
			   u32 old_path_id, u32 new_path_id,
			   u32 migration_type)
{
	if (!conn)
		return;

	trace_tquic_migration(
		quic_trace_conn_id(&conn->scid),
		old_path_id,
		new_path_id,
		migration_type
	);
}
EXPORT_SYMBOL_GPL(tquic_trace_migration);

/**
 * tquic_trace_scheduler_decision - Trace multipath scheduler decision
 * @conn: Connection structure
 * @selected_path: Path selected for transmission
 * @reason: Selection reason
 * @candidate_count: Number of candidate paths
 */
void tquic_trace_scheduler_decision(struct tquic_connection *conn,
				    u32 selected_path, u32 reason,
				    u32 candidate_count)
{
	if (!conn)
		return;

	trace_tquic_scheduler_decision(
		quic_trace_conn_id(&conn->scid),
		selected_path,
		reason,
		candidate_count
	);
}
EXPORT_SYMBOL_GPL(tquic_trace_scheduler_decision);

/**
 * tquic_trace_handshake_start - Trace handshake initiation
 * @conn: Connection structure
 * @is_server: Server or client role
 * @has_session_ticket: Whether 0-RTT was attempted
 * @verify_mode: Certificate verification mode
 */
void tquic_trace_handshake_start(struct tquic_connection *conn,
				 bool is_server, bool has_session_ticket,
				 u32 verify_mode)
{
	if (!conn)
		return;

	trace_tquic_handshake_start(
		quic_trace_conn_id(&conn->scid),
		is_server,
		has_session_ticket,
		verify_mode
	);
}
EXPORT_SYMBOL_GPL(tquic_trace_handshake_start);

/**
 * tquic_trace_handshake_complete - Trace handshake completion
 * @conn: Connection structure
 * @status: Result (0=success, negative=error)
 * @duration_us: Handshake duration in microseconds
 */
void tquic_trace_handshake_complete(struct tquic_connection *conn,
				    int status, u64 duration_us)
{
	if (!conn)
		return;

	trace_tquic_handshake_complete(
		quic_trace_conn_id(&conn->scid),
		status,
		duration_us,
		0, /* cipher_suite not on conn */
		conn->early_data_accepted
	);
}
EXPORT_SYMBOL_GPL(tquic_trace_handshake_complete);

/**
 * tquic_trace_failover - Trace path failover event
 * @conn: Connection structure
 * @failed_path_id: Path that failed
 * @new_path_id: Path switched to
 * @reason: Failover reason
 * @rtt_us: RTT on failed path at time of failover
 */
void tquic_trace_failover(struct tquic_connection *conn,
			  u32 failed_path_id, u32 new_path_id,
			  u32 reason, u64 rtt_us)
{
	if (!conn)
		return;

	trace_tquic_failover(
		quic_trace_conn_id(&conn->scid),
		failed_path_id,
		new_path_id,
		reason,
		rtt_us
	);
}
EXPORT_SYMBOL_GPL(tquic_trace_failover);

/**
 * tquic_trace_bond_state - Trace bonding state change
 * @conn: Connection structure
 * @bond_mode: Current bonding mode
 * @active_paths: Number of active paths
 * @total_bandwidth: Estimated aggregate bandwidth
 */
void tquic_trace_bond_state(struct tquic_connection *conn,
			    u32 bond_mode, u32 active_paths,
			    u64 total_bandwidth)
{
	if (!conn)
		return;

	trace_tquic_bond_state(
		quic_trace_conn_id(&conn->scid),
		bond_mode,
		active_paths,
		total_bandwidth
	);
}
EXPORT_SYMBOL_GPL(tquic_trace_bond_state);

/**
 * tquic_trace_frame_debug - Trace frame-level event
 * @conn: Connection structure (may be NULL)
 * @frame_type: QUIC frame type
 * @length: Frame length
 * @path_id: Path ID
 * @is_send: Sending or receiving
 */
void tquic_trace_frame_debug(struct tquic_connection *conn,
			     u32 frame_type, u32 length,
			     u32 path_id, bool is_send)
{
	trace_tquic_frame_debug(
		conn ? quic_trace_conn_id(&conn->scid) : 0,
		frame_type,
		length,
		path_id,
		is_send
	);
}
EXPORT_SYMBOL_GPL(tquic_trace_frame_debug);

/*
 * =============================================================================
 * BPF Iterator Support
 * =============================================================================
 */

/**
 * struct tquic_bpf_iter_conn - BPF iterator for connections
 *
 * Allows BPF programs to iterate over all active QUIC connections
 * for monitoring and metrics collection.
 */
struct tquic_bpf_iter_conn {
	struct tquic_connection *conn;
	u64 conn_id;
	u32 state;
	u64 bytes_sent;
	u64 bytes_received;
	u64 packets_sent;
	u64 packets_received;
	u64 packets_lost;
	u64 rtt_smoothed;
	u64 cwnd;
	u32 path_count;
};

/**
 * struct tquic_bpf_iter_path - BPF iterator for paths
 */
struct tquic_bpf_iter_path {
	u32 path_id;
	u32 state;
	u64 rtt_smoothed;
	u64 rtt_min;
	u64 cwnd;
	u64 bytes_in_flight;
	u64 bytes_sent;
	u64 bytes_received;
	u32 loss_rate;
	bool is_primary;
};

/*
 * =============================================================================
 * Module Init
 * =============================================================================
 */

int tquic_tracepoints_init(void)
{
	int ret;

	ret = tquic_path_metrics_init(&init_net);
	if (ret)
		return ret;

	pr_info("tquic: tracepoints module loaded\n");
	return 0;
}

void tquic_tracepoints_exit(void)
{
	pr_info("tquic: tracepoints module unloaded\n");
	tquic_path_metrics_exit(&init_net);
}

/* init called from tquic_main */
/* exit called from tquic_main */

/* MODULE_LICENSE("GPL");
MODULE_AUTHOR("Linux Foundation");
MODULE_DESCRIPTION("TQUIC eBPF Tracepoints for Observability"); */
