/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * TQUIC: QUIC Flow Control
 *
 * Copyright (c) 2026 Linux Foundation
 *
 * Flow control implementation as per RFC 9000 Section 4.
 * Handles connection-level and stream-level flow control,
 * stream count limits, and credit management.
 */

#ifndef _TQUIC_FLOW_CONTROL_H
#define _TQUIC_FLOW_CONTROL_H

#include <linux/types.h>
#include <linux/spinlock.h>
#include <linux/ktime.h>
#include <net/tquic.h>

/* Flow control defaults (RFC 9000 Section 18.2) */
#define TQUIC_FC_DEFAULT_MAX_DATA		(1 << 20)	/* 1 MB */
#define TQUIC_FC_DEFAULT_MAX_STREAM_DATA_BIDI_LOCAL	(256 * 1024)
#define TQUIC_FC_DEFAULT_MAX_STREAM_DATA_BIDI_REMOTE	(256 * 1024)
#define TQUIC_FC_DEFAULT_MAX_STREAM_DATA_UNI		(256 * 1024)
#define TQUIC_FC_DEFAULT_MAX_STREAMS_BIDI	100
#define TQUIC_FC_DEFAULT_MAX_STREAMS_UNI	100

/* Auto-tuning parameters */
#define TQUIC_FC_MIN_WINDOW		(16 * 1024)	/* 16 KB minimum */
#define TQUIC_FC_MAX_WINDOW		(16 * 1024 * 1024)  /* 16 MB maximum */
#define TQUIC_FC_WINDOW_UPDATE_THRESHOLD	2	/* Update when 1/2 consumed */
#define TQUIC_FC_AUTOTUNE_INTERVAL_MS	100		/* Autotune interval */
#define TQUIC_FC_AUTOTUNE_RTT_MULTIPLIER	2	/* BDP multiplier */

/* Stream ID type bits (RFC 9000 Section 2.1) */
#define TQUIC_STREAM_INITIATOR_BIT	0x01	/* 0 = client, 1 = server */
#define TQUIC_STREAM_DIR_BIT		0x02	/* 0 = bidi, 1 = uni */

/* Blocked state flags */
#define TQUIC_FC_BLOCKED_CONN_DATA	BIT(0)	/* Connection data blocked */
#define TQUIC_FC_BLOCKED_STREAM_DATA	BIT(1)	/* Stream data blocked */
#define TQUIC_FC_BLOCKED_STREAMS_BIDI	BIT(2)	/* Bidi streams blocked */
#define TQUIC_FC_BLOCKED_STREAMS_UNI	BIT(3)	/* Uni streams blocked */

/**
 * struct tquic_fc_config - Flow control configuration
 * @initial_max_data: Initial connection MAX_DATA
 * @initial_max_stream_data_bidi_local: Initial MAX_STREAM_DATA for local bidi
 * @initial_max_stream_data_bidi_remote: Initial MAX_STREAM_DATA for remote bidi
 * @initial_max_stream_data_uni: Initial MAX_STREAM_DATA for unidirectional
 * @initial_max_streams_bidi: Initial MAX_STREAMS for bidirectional
 * @initial_max_streams_uni: Initial MAX_STREAMS for unidirectional
 * @autotune_enabled: Enable automatic window tuning
 * @min_window: Minimum window size for autotuning
 * @max_window: Maximum window size for autotuning
 */
struct tquic_fc_config {
	u64 initial_max_data;
	u64 initial_max_stream_data_bidi_local;
	u64 initial_max_stream_data_bidi_remote;
	u64 initial_max_stream_data_uni;
	u64 initial_max_streams_bidi;
	u64 initial_max_streams_uni;

	bool autotune_enabled;
	u64 min_window;
	u64 max_window;
};

/**
 * struct tquic_fc_conn_state - Connection-level flow control state
 * @max_data_local: Local MAX_DATA limit (we advertise to peer)
 * @max_data_remote: Remote MAX_DATA limit (peer advertises to us)
 * @data_sent: Total data sent (against remote limit)
 * @data_received: Total data received (against local limit)
 * @data_consumed: Data consumed by application (for window updates)
 * @max_data_next: Next MAX_DATA value to send
 * @blocked_at: Data offset where we became blocked
 * @data_blocked_sent: We sent DATA_BLOCKED frame
 * @data_blocked_received: Peer sent DATA_BLOCKED
 * @needs_max_data: Need to send MAX_DATA frame
 * @last_max_data_sent: Last MAX_DATA value sent to peer
 */
struct tquic_fc_conn_state {
	/* Local limits (receive direction) */
	u64 max_data_local;
	u64 data_received;
	u64 data_consumed;
	u64 max_data_next;
	u64 last_max_data_sent;
	bool needs_max_data;

	/* Remote limits (send direction) */
	u64 max_data_remote;
	u64 data_sent;
	u64 blocked_at;
	bool data_blocked_sent;
	bool data_blocked_received;

	spinlock_t lock;
};

/**
 * struct tquic_fc_stream_state - Stream-level flow control state
 * @stream_id: Stream identifier
 * @max_data_local: Local MAX_STREAM_DATA (we advertise)
 * @max_data_remote: Remote MAX_STREAM_DATA (peer advertises)
 * @data_sent: Data sent on this stream
 * @data_reserved: Data reserved for pending transmission (CF-428)
 * @data_received: Data received on this stream
 * @data_consumed: Data consumed by application
 * @max_data_next: Next MAX_STREAM_DATA to send
 * @blocked_at: Offset where stream became blocked
 * @data_blocked_sent: We sent STREAM_DATA_BLOCKED
 * @data_blocked_received: Peer sent STREAM_DATA_BLOCKED
 * @needs_max_stream_data: Need to send MAX_STREAM_DATA
 * @last_max_data_sent: Last MAX_STREAM_DATA sent
 * @final_size: Final size if known (FIN received)
 * @final_size_known: Whether final size is known
 */
struct tquic_fc_stream_state {
	u64 stream_id;

	/* Local limits (receive direction) */
	u64 max_data_local;
	u64 data_received;
	u64 data_consumed;
	u64 max_data_next;
	u64 last_max_data_sent;
	bool needs_max_stream_data;

	/* Remote limits (send direction) */
	u64 max_data_remote;
	u64 data_sent;
	u64 data_reserved;	/* CF-428: Bytes reserved but not yet sent */
	u64 blocked_at;
	bool data_blocked_sent;
	bool data_blocked_received;

	/* Final size tracking */
	u64 final_size;
	bool final_size_known;

	spinlock_t lock;
};

/**
 * struct tquic_fc_streams_state - Stream count flow control
 * @max_streams_bidi_local: Local bidi streams limit (we accept)
 * @max_streams_bidi_remote: Remote bidi streams limit (peer accepts)
 * @max_streams_uni_local: Local uni streams limit
 * @max_streams_uni_remote: Remote uni streams limit
 * @streams_bidi_opened: Bidi streams we have opened
 * @streams_uni_opened: Uni streams we have opened
 * @streams_bidi_received: Bidi streams peer has opened
 * @streams_uni_received: Uni streams peer has opened
 * @blocked_bidi_at: Stream count where bidi blocked
 * @blocked_uni_at: Stream count where uni blocked
 * @streams_blocked_bidi_sent: STREAMS_BLOCKED (bidi) sent
 * @streams_blocked_uni_sent: STREAMS_BLOCKED (uni) sent
 * @needs_max_streams_bidi: Need to send MAX_STREAMS (bidi)
 * @needs_max_streams_uni: Need to send MAX_STREAMS (uni)
 */
struct tquic_fc_streams_state {
	/* Local limits (peer can open) */
	u64 max_streams_bidi_local;
	u64 max_streams_uni_local;
	u64 streams_bidi_received;
	u64 streams_uni_received;
	bool needs_max_streams_bidi;
	bool needs_max_streams_uni;

	/* Remote limits (we can open) */
	u64 max_streams_bidi_remote;
	u64 max_streams_uni_remote;
	u64 streams_bidi_opened;
	u64 streams_uni_opened;
	u64 blocked_bidi_at;
	u64 blocked_uni_at;
	bool streams_blocked_bidi_sent;
	bool streams_blocked_uni_sent;

	spinlock_t lock;
};

/**
 * struct tquic_fc_autotune - Auto-tuning state for receive windows
 * @enabled: Whether autotuning is active
 * @last_update: Time of last window update
 * @rtt_us: Current RTT in microseconds
 * @bandwidth: Estimated bandwidth in bytes/sec
 * @target_window: Calculated target window size
 * @bytes_since_update: Bytes received since last update
 * @growth_rate: Current window growth multiplier (fixed point)
 */
struct tquic_fc_autotune {
	bool enabled;
	ktime_t last_update;
	u32 rtt_us;
	u64 bandwidth;
	u64 target_window;
	u64 bytes_since_update;
	u32 growth_rate;
};

/**
 * struct tquic_fc_state - Complete flow control state for a connection
 * @conn: Connection-level flow control
 * @streams: Stream count flow control
 * @autotune: Auto-tuning state
 * @config: Configuration parameters
 * @blocked_flags: Current blocked state flags
 * @stats: Flow control statistics
 */
struct tquic_fc_state {
	struct tquic_fc_conn_state conn;
	struct tquic_fc_streams_state streams;
	struct tquic_fc_autotune autotune;
	struct tquic_fc_config config;
	u32 blocked_flags;

	/* Statistics */
	struct {
		u64 max_data_frames_sent;
		u64 max_data_frames_received;
		u64 data_blocked_frames_sent;
		u64 data_blocked_frames_received;
		u64 max_stream_data_frames_sent;
		u64 max_stream_data_frames_received;
		u64 stream_data_blocked_frames_sent;
		u64 stream_data_blocked_frames_received;
		u64 max_streams_frames_sent;
		u64 max_streams_frames_received;
		u64 streams_blocked_frames_sent;
		u64 streams_blocked_frames_received;
		u64 window_updates;
		u64 autotune_adjustments;
	} stats;
};

/**
 * struct tquic_fc_credit - Credit available for sending
 * @conn_credit: Connection-level credit available
 * @stream_credit: Stream-level credit available
 * @effective_credit: Minimum of conn and stream credit
 * @conn_blocked: Whether connection is blocked
 * @stream_blocked: Whether stream is blocked
 */
struct tquic_fc_credit {
	u64 conn_credit;
	u64 stream_credit;
	u64 effective_credit;
	bool conn_blocked;
	bool stream_blocked;
};

/* Forward declarations */
struct tquic_connection;
struct tquic_stream;

/*
 * Flow Control State Management
 */

/* Initialize flow control state for a connection */
int tquic_fc_init(struct tquic_connection *conn, struct tquic_fc_config *config);

/* Cleanup flow control state */
void tquic_fc_cleanup(struct tquic_connection *conn);

/* Initialize stream flow control state */
int tquic_fc_stream_init(struct tquic_stream *stream,
			 struct tquic_fc_state *fc_state);

/* Cleanup stream flow control state */
void tquic_fc_stream_cleanup(struct tquic_stream *stream);

/*
 * Connection-level Flow Control
 */

/* Check if we can send data at connection level */
bool tquic_fc_conn_can_send(struct tquic_fc_state *fc, u64 bytes);

/* Get available connection-level credit */
u64 tquic_fc_conn_get_credit(struct tquic_fc_state *fc);

/* Record data sent at connection level */
int tquic_fc_conn_data_sent(struct tquic_fc_state *fc, u64 bytes);

/* Record data received at connection level */
int tquic_fc_conn_data_received(struct tquic_fc_state *fc, u64 bytes);

/* Mark data as consumed by application */
void tquic_fc_conn_data_consumed(struct tquic_fc_state *fc, u64 bytes);

/* Handle received MAX_DATA frame */
int tquic_fc_handle_max_data(struct tquic_fc_state *fc, u64 max_data);

/* Handle received DATA_BLOCKED frame */
void tquic_fc_handle_data_blocked(struct tquic_fc_state *fc, u64 max_data);

/* Check if we need to send MAX_DATA */
bool tquic_fc_needs_max_data(struct tquic_fc_state *fc);

/* Get MAX_DATA value to send */
u64 tquic_fc_get_max_data(struct tquic_fc_state *fc);

/* Mark MAX_DATA as sent */
void tquic_fc_max_data_sent(struct tquic_fc_state *fc, u64 max_data);

/* Check if we need to send DATA_BLOCKED */
bool tquic_fc_needs_data_blocked(struct tquic_fc_state *fc);

/* Get DATA_BLOCKED value to send */
u64 tquic_fc_get_data_blocked(struct tquic_fc_state *fc);

/* Mark DATA_BLOCKED as sent */
void tquic_fc_data_blocked_sent(struct tquic_fc_state *fc);

/*
 * Stream-level Flow Control
 */

/* Check if we can send data on a stream */
bool tquic_fc_stream_can_send(struct tquic_fc_stream_state *stream, u64 bytes);

/* Get available stream-level credit */
u64 tquic_fc_stream_get_credit(struct tquic_fc_stream_state *stream);

/* Record data sent on stream */
int tquic_fc_stream_data_sent(struct tquic_fc_stream_state *stream, u64 bytes);

/* Record data received on stream */
int tquic_fc_stream_data_received(struct tquic_fc_stream_state *stream,
				  u64 offset, u64 length, bool fin);

/* Mark stream data as consumed */
void tquic_fc_stream_data_consumed(struct tquic_fc_stream_state *stream,
				   u64 bytes);

/* Handle received MAX_STREAM_DATA frame */
int tquic_fc_handle_max_stream_data(struct tquic_fc_stream_state *stream,
				    u64 max_data);

/* Handle received STREAM_DATA_BLOCKED frame */
void tquic_fc_handle_stream_data_blocked(struct tquic_fc_stream_state *stream,
					 u64 max_data);

/* Check if we need to send MAX_STREAM_DATA */
bool tquic_fc_needs_max_stream_data(struct tquic_fc_stream_state *stream);

/* Get MAX_STREAM_DATA value to send */
u64 tquic_fc_get_max_stream_data(struct tquic_fc_stream_state *stream);

/* Mark MAX_STREAM_DATA as sent */
void tquic_fc_max_stream_data_sent(struct tquic_fc_stream_state *stream,
				   u64 max_data);

/* Check if stream needs STREAM_DATA_BLOCKED */
bool tquic_fc_needs_stream_data_blocked(struct tquic_fc_stream_state *stream);

/* Get STREAM_DATA_BLOCKED value */
u64 tquic_fc_get_stream_data_blocked(struct tquic_fc_stream_state *stream);

/* Mark STREAM_DATA_BLOCKED as sent */
void tquic_fc_stream_data_blocked_sent(struct tquic_fc_stream_state *stream);

/*
 * Stream Count Limits
 */

/* Check if we can open a new bidirectional stream */
bool tquic_fc_can_open_bidi_stream(struct tquic_fc_state *fc);

/* Check if we can open a new unidirectional stream */
bool tquic_fc_can_open_uni_stream(struct tquic_fc_state *fc);

/* Record that we opened a bidirectional stream */
int tquic_fc_bidi_stream_opened(struct tquic_fc_state *fc);

/* Record that we opened a unidirectional stream */
int tquic_fc_uni_stream_opened(struct tquic_fc_state *fc);

/* Record that peer opened a bidirectional stream */
int tquic_fc_bidi_stream_received(struct tquic_fc_state *fc, u64 stream_id);

/* Record that peer opened a unidirectional stream */
int tquic_fc_uni_stream_received(struct tquic_fc_state *fc, u64 stream_id);

/* Handle received MAX_STREAMS frame */
int tquic_fc_handle_max_streams(struct tquic_fc_state *fc, u64 max_streams,
				bool bidi);

/* Handle received STREAMS_BLOCKED frame */
void tquic_fc_handle_streams_blocked(struct tquic_fc_state *fc, u64 max_streams,
				     bool bidi);

/* Check if we need to send MAX_STREAMS */
bool tquic_fc_needs_max_streams(struct tquic_fc_state *fc, bool *bidi);

/* Get MAX_STREAMS value to send */
u64 tquic_fc_get_max_streams(struct tquic_fc_state *fc, bool bidi);

/* Mark MAX_STREAMS as sent */
void tquic_fc_max_streams_sent(struct tquic_fc_state *fc, u64 max_streams,
			       bool bidi);

/* Check if we need to send STREAMS_BLOCKED */
bool tquic_fc_needs_streams_blocked(struct tquic_fc_state *fc, bool *bidi);

/* Get STREAMS_BLOCKED value */
u64 tquic_fc_get_streams_blocked(struct tquic_fc_state *fc, bool bidi);

/* Mark STREAMS_BLOCKED as sent */
void tquic_fc_streams_blocked_sent(struct tquic_fc_state *fc, bool bidi);

/*
 * Credit Management
 */

/* Get combined credit for sending */
void tquic_fc_get_credit(struct tquic_fc_state *fc,
			 struct tquic_fc_stream_state *stream,
			 struct tquic_fc_credit *credit);

/* Reserve credit for pending transmission */
int tquic_fc_reserve_credit(struct tquic_fc_state *fc,
			    struct tquic_fc_stream_state *stream,
			    u64 bytes);

/* Release reserved credit (transmission failed) */
void tquic_fc_release_credit(struct tquic_fc_state *fc,
			     struct tquic_fc_stream_state *stream,
			     u64 bytes);

/* Commit credit usage (transmission succeeded) */
void tquic_fc_commit_credit(struct tquic_fc_state *fc,
			    struct tquic_fc_stream_state *stream,
			    u64 bytes);

/*
 * Window Update Logic
 */

/* Check if connection window should be updated */
bool tquic_fc_should_update_conn_window(struct tquic_fc_state *fc);

/* Check if stream window should be updated */
bool tquic_fc_should_update_stream_window(struct tquic_fc_stream_state *stream,
					  struct tquic_fc_state *fc);

/* Calculate new connection window size */
u64 tquic_fc_calc_conn_window(struct tquic_fc_state *fc);

/* Calculate new stream window size */
u64 tquic_fc_calc_stream_window(struct tquic_fc_stream_state *stream,
				struct tquic_fc_state *fc);

/*
 * Auto-tuning
 */

/* Update RTT for autotuning */
void tquic_fc_update_rtt(struct tquic_fc_state *fc, u32 rtt_us);

/* Update bandwidth estimate for autotuning */
void tquic_fc_update_bandwidth(struct tquic_fc_state *fc, u64 bandwidth);

/* Perform autotune calculation */
void tquic_fc_autotune(struct tquic_fc_state *fc);

/* Set autotune enabled/disabled */
void tquic_fc_set_autotune(struct tquic_fc_state *fc, bool enabled);

/*
 * Utility Functions
 */

/* Check if stream ID is locally initiated */
static inline bool tquic_fc_stream_is_local(u64 stream_id, bool is_server)
{
	bool initiator = stream_id & TQUIC_STREAM_INITIATOR_BIT;
	return initiator == is_server;
}

/* Check if stream is bidirectional */
static inline bool tquic_fc_stream_is_bidi(u64 stream_id)
{
	return !(stream_id & TQUIC_STREAM_DIR_BIT);
}

/* Get stream number from stream ID */
static inline u64 tquic_fc_stream_num(u64 stream_id)
{
	return stream_id >> 2;
}

/* Get initial MAX_STREAM_DATA for a stream type */
u64 tquic_fc_get_initial_max_stream_data(struct tquic_fc_state *fc,
					 u64 stream_id, bool is_server);

/* Reset connection flow control state (for 0-RTT rejection) */
void tquic_fc_reset(struct tquic_fc_state *fc);

/* Get flow control statistics */
void tquic_fc_get_stats(struct tquic_fc_state *fc, void *stats, size_t len);

/*
 * Simplified Flow Control API (quic_flow.c)
 *
 * These functions provide a simpler flow control interface that operates
 * directly on tquic_connection and tquic_stream structures. They are
 * exported for use by other TQUIC modules.
 */

/* Connection-level flow control */
void tquic_flow_control_init(struct tquic_connection *conn);
bool tquic_flow_control_can_send(struct tquic_connection *conn, u64 bytes);
void tquic_flow_control_on_data_sent(struct tquic_connection *conn, u64 bytes);
void tquic_flow_control_on_data_recvd(struct tquic_connection *conn, u64 bytes);
void tquic_flow_control_update_max_data(struct tquic_connection *conn);
void tquic_flow_control_max_data_received(struct tquic_connection *conn, u64 max_data);
u64 tquic_flow_control_get_available(struct tquic_connection *conn);
void tquic_flow_control_send_data_blocked(struct tquic_connection *conn);
void tquic_flow_control_data_blocked_received(struct tquic_connection *conn, u64 limit);

/* Stream-level flow control */
void tquic_stream_flow_control_init(struct tquic_stream *stream,
				    u64 max_stream_data_local,
				    u64 max_stream_data_remote);
bool tquic_stream_flow_control_can_send(struct tquic_stream *stream, u64 bytes);
void tquic_stream_flow_control_on_data_sent(struct tquic_stream *stream, u64 bytes);
int tquic_stream_flow_control_check_recv_limit(struct tquic_stream *stream,
					       u64 offset, u64 len);
void tquic_stream_flow_control_on_data_recvd(struct tquic_stream *stream,
					     u64 offset, u64 len);
void tquic_stream_flow_control_max_stream_data_received(struct tquic_stream *stream,
							u64 max_stream_data);
u64 tquic_stream_flow_control_get_available(struct tquic_stream *stream);

/* Stream count management */
bool tquic_streams_can_open(struct tquic_connection *conn, bool unidirectional);
void tquic_streams_on_stream_opened(struct tquic_connection *conn, bool unidirectional);
void tquic_streams_on_peer_stream_opened(struct tquic_connection *conn, bool unidirectional);
void tquic_streams_max_streams_received(struct tquic_connection *conn,
					u64 max_streams, bool unidirectional);
void tquic_streams_send_blocked(struct tquic_connection *conn, bool unidirectional);

/* Blocked frame handling */
void tquic_stream_data_blocked_received(struct tquic_connection *conn,
					u64 stream_id, u64 limit);
void tquic_streams_blocked_received(struct tquic_connection *conn,
				    u64 limit, bool unidirectional);

/* Combined flow control checks */
bool tquic_flow_can_send_stream_data(struct tquic_stream *stream, u64 bytes);
void tquic_flow_on_stream_data_sent(struct tquic_stream *stream, u64 bytes);
int tquic_flow_check_recv_limits(struct tquic_stream *stream, u64 offset, u64 len);
void tquic_flow_on_stream_data_recvd(struct tquic_stream *stream, u64 offset, u64 len);

/* Statistics */
void tquic_flow_get_stats(struct tquic_connection *conn,
			  u64 *local_max_data, u64 *local_data_recvd,
			  u64 *remote_max_data, u64 *remote_data_sent);
void tquic_stream_flow_get_stats(struct tquic_stream *stream,
				 u64 *send_offset, u64 *send_max,
				 u64 *recv_offset, u64 *recv_max);

/* Module init/exit */
int __init tquic_flow_init(void);
void tquic_flow_exit(void);

#endif /* _TQUIC_FLOW_CONTROL_H */
