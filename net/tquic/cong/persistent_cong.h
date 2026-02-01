/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * TQUIC: Persistent Congestion Detection (RFC 9002 Section 7.6)
 *
 * Copyright (c) 2026 Linux Foundation
 *
 * Persistent congestion detection for QUIC loss recovery.
 * When packets spanning the persistent congestion period are all lost,
 * the sender declares persistent congestion and resets to minimum cwnd.
 *
 * Per RFC 9002 Section 7.6:
 * "A sender that does not have state for all packet number spaces or
 * that does not have RTT samples from them SHOULD NOT declare
 * persistent congestion."
 *
 * The persistent congestion period is:
 *   (smoothed_rtt + max(4*rtt_var, kGranularity)) * kPersistentCongestionThreshold
 *
 * Where:
 *   kGranularity = 1ms (timer granularity)
 *   kPersistentCongestionThreshold = 3 (default)
 */

#ifndef _TQUIC_PERSISTENT_CONG_H
#define _TQUIC_PERSISTENT_CONG_H

#include <linux/types.h>
#include <linux/ktime.h>
#include <net/tquic.h>

/*
 * Default persistent congestion threshold per RFC 9002 Section 7.6.2
 *
 * "kPersistentCongestionThreshold: 3"
 *
 * This can be tuned via sysctl persistent_congestion_threshold.
 */
#define TQUIC_PERSISTENT_CONG_THRESHOLD_DEFAULT	3

/*
 * Minimum threshold value (must be >= 2 for meaningful detection)
 */
#define TQUIC_PERSISTENT_CONG_THRESHOLD_MIN	2

/*
 * Maximum threshold value (higher = less aggressive)
 */
#define TQUIC_PERSISTENT_CONG_THRESHOLD_MAX	10

/*
 * Timer granularity (kGranularity) per RFC 9002
 * 1ms = 1000us
 */
#define TQUIC_TIMER_GRANULARITY_US	1000

/*
 * Minimum cwnd after persistent congestion (in packets)
 * Per RFC 9002: "2 packets worth of data"
 */
#define TQUIC_MIN_CWND_PACKETS		2

/*
 * Default max_datagram_size for cwnd calculation
 */
#define TQUIC_DEFAULT_MAX_DATAGRAM_SIZE	1200

/**
 * struct tquic_lost_packet - Information about a lost packet
 * @send_time: Time when the packet was sent
 * @pkt_num: Packet number
 * @ack_eliciting: Whether this packet was ACK-eliciting
 * @pn_space: Packet number space (Initial, Handshake, Application)
 */
struct tquic_lost_packet {
	ktime_t send_time;
	u64 pkt_num;
	bool ack_eliciting;
	u8 pn_space;
};

/**
 * struct tquic_persistent_cong_state - Per-path persistent congestion state
 * @smoothed_rtt: Smoothed RTT in microseconds
 * @rtt_var: RTT variance in microseconds
 * @has_rtt_sample: Whether we have valid RTT samples
 * @pn_space_active: Bitmask of active packet number spaces
 * @last_persistent_cong: Timestamp of last persistent congestion event
 * @persistent_cong_count: Counter for persistent congestion events
 */
struct tquic_persistent_cong_state {
	u64 smoothed_rtt;
	u64 rtt_var;
	bool has_rtt_sample;
	u8 pn_space_active;
	ktime_t last_persistent_cong;
	u64 persistent_cong_count;
};

/**
 * tquic_persistent_cong_period - Calculate persistent congestion period
 * @state: Persistent congestion state
 * @net: Network namespace for threshold configuration
 *
 * Calculates the persistent congestion period per RFC 9002 Section 7.6.2:
 *   (smoothed_rtt + max(4*rtt_var, kGranularity)) * threshold
 *
 * Return: Persistent congestion period in microseconds
 */
u64 tquic_persistent_cong_period(struct tquic_persistent_cong_state *state,
				 struct net *net);

/**
 * tquic_check_persistent_cong - Check if persistent congestion occurred
 * @state: Persistent congestion state
 * @lost_packets: Array of lost packets
 * @num_lost: Number of lost packets
 * @net: Network namespace for configuration
 *
 * Per RFC 9002 Section 7.6.2:
 * "If there are two packets in flight that are not ack-eliciting,
 * or if there is only one packet in flight, then persistent
 * congestion cannot be declared."
 *
 * This function checks if any two ACK-eliciting lost packets span
 * the persistent congestion period.
 *
 * Return: true if persistent congestion detected, false otherwise
 */
bool tquic_check_persistent_cong(struct tquic_persistent_cong_state *state,
				 struct tquic_lost_packet *lost_packets,
				 int num_lost, struct net *net);

/**
 * tquic_persistent_cong_init - Initialize persistent congestion state
 * @state: State to initialize
 */
void tquic_persistent_cong_init(struct tquic_persistent_cong_state *state);

/**
 * tquic_persistent_cong_update_rtt - Update RTT information
 * @state: Persistent congestion state
 * @smoothed_rtt: New smoothed RTT in microseconds
 * @rtt_var: New RTT variance in microseconds
 *
 * Called when RTT samples are updated to keep state current.
 */
void tquic_persistent_cong_update_rtt(struct tquic_persistent_cong_state *state,
				      u64 smoothed_rtt, u64 rtt_var);

/**
 * tquic_persistent_cong_set_pn_space - Mark a packet number space as active
 * @state: Persistent congestion state
 * @pn_space: Packet number space (0=Initial, 1=Handshake, 2=Application)
 */
void tquic_persistent_cong_set_pn_space(struct tquic_persistent_cong_state *state,
					u8 pn_space);

/**
 * tquic_min_cwnd - Calculate minimum cwnd after persistent congestion
 * @max_datagram_size: Maximum datagram size in bytes
 *
 * Per RFC 9002 Section 7.6:
 * "the congestion window MUST be reduced to the minimum congestion
 * window (kMinimumWindow), which equals 2 * max_datagram_size"
 *
 * Return: Minimum cwnd in bytes
 */
static inline u64 tquic_min_cwnd(u32 max_datagram_size)
{
	return TQUIC_MIN_CWND_PACKETS * max_datagram_size;
}

/**
 * tquic_net_get_persistent_cong_threshold - Get threshold from netns
 * @net: Network namespace
 *
 * Return: Persistent congestion threshold (default 3)
 */
u32 tquic_net_get_persistent_cong_threshold(struct net *net);

/*
 * =============================================================================
 * CC Algorithm Integration
 * =============================================================================
 *
 * Congestion control algorithms should implement on_persistent_congestion
 * callback to handle persistent congestion events. The callback is
 * responsible for:
 *
 * 1. Resetting cwnd to minimum (2 * max_datagram_size)
 * 2. Setting ssthresh (typically to minimum cwnd)
 * 3. Resetting any algorithm-specific state (optional)
 * 4. Clearing bytes_in_flight tracking (optional)
 */

/**
 * struct tquic_persistent_cong_info - Info passed to CC on persistent congestion
 * @min_cwnd: Minimum congestion window to reset to
 * @max_datagram_size: Maximum datagram size for calculations
 * @earliest_send_time: Send time of earliest lost packet
 * @latest_send_time: Send time of latest lost packet
 * @duration_us: Duration of persistent congestion period
 */
struct tquic_persistent_cong_info {
	u64 min_cwnd;
	u32 max_datagram_size;
	ktime_t earliest_send_time;
	ktime_t latest_send_time;
	u64 duration_us;
};

/*
 * Forward declaration for CC callback signature
 *
 * The on_persistent_congestion callback in tquic_cong_ops:
 *   void (*on_persistent_congestion)(void *cong_data,
 *                                    struct tquic_persistent_cong_info *info);
 */

#endif /* _TQUIC_PERSISTENT_CONG_H */
