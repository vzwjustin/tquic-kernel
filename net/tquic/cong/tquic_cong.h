/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * TQUIC: Congestion Control Framework
 *
 * Copyright (c) 2026 Linux Foundation
 *
 * Central CC framework for TQUIC multipath WAN bonding.
 * Provides algorithm registration, per-path lifecycle management,
 * and callback dispatch for ACK/loss/RTT events.
 */

#ifndef _TQUIC_CONG_H
#define _TQUIC_CONG_H

#include <linux/types.h>
#include <net/tquic.h>

/*
 * Default CC algorithm name - used when no CC is specified
 */
#define TQUIC_DEFAULT_CC_NAME	"cubic"

/*
 * Maximum CC algorithm name length
 */
#define TQUIC_CC_NAME_MAX	16

/*
 * tquic_cong_find - Find CC algorithm by name
 * @name: Name of the CC algorithm to find
 *
 * RCU-protected lookup of registered CC algorithms.
 * Returns pointer to tquic_cong_ops if found, NULL otherwise.
 * Caller must hold RCU read lock or ensure ops won't be unregistered.
 *
 * Return: Pointer to CC ops or NULL if not found
 */
struct tquic_cong_ops *tquic_cong_find(const char *name);

/*
 * tquic_cong_init_path - Initialize CC state for a path
 * @path: Path to initialize CC for
 * @name: CC algorithm name (NULL for default)
 *
 * Finds the CC algorithm by name (or uses default "cubic"),
 * calls the algorithm's init function to create per-path state,
 * and stores the ops pointer in the path for callback dispatch.
 *
 * Return: 0 on success, -errno on failure
 */
int tquic_cong_init_path(struct tquic_path *path, const char *name);

/*
 * tquic_cong_init_path_with_rtt - Initialize CC state for a path with RTT auto-selection
 * @path: Path to initialize CC for
 * @net: Network namespace for per-netns defaults and BBR threshold
 * @name: CC algorithm name (NULL for default, "auto" for RTT-based)
 * @rtt_us: Initial RTT estimate in microseconds (for auto-selection)
 *
 * This function supports BBR auto-selection for high-RTT paths:
 * - If name is "auto" and RTT >= bbr_rtt_threshold_ms, BBR is selected
 * - If name is "auto" and RTT < threshold, per-netns default is used
 * - If name is specified (not "auto"), that algorithm is used
 * - If name is NULL, per-netns default is used
 *
 * Per CONTEXT.md: "High-RTT paths (>=100ms) auto-select BBR when configured"
 *
 * Return: 0 on success, -errno on failure
 */
int tquic_cong_init_path_with_rtt(struct tquic_path *path, struct net *net,
				  const char *name, u64 rtt_us);

/*
 * tquic_cong_release_path - Release CC state for a path
 * @path: Path whose CC state should be released
 *
 * Calls the CC algorithm's release function if CC state exists,
 * clears the path's cong and cong_ops pointers.
 * Safe to call with NULL CC state.
 */
void tquic_cong_release_path(struct tquic_path *path);

/*
 * tquic_cong_on_ack - Dispatch ACK event to path's CC algorithm
 * @path: Path that received the ACK
 * @bytes_acked: Number of bytes acknowledged
 * @rtt_us: RTT sample in microseconds
 *
 * Calls the path's CC algorithm on_ack callback if registered.
 * Updates path->stats.cwnd from the CC algorithm after callback.
 */
void tquic_cong_on_ack(struct tquic_path *path, u64 bytes_acked, u64 rtt_us);

/*
 * tquic_cong_on_loss - Dispatch loss event to path's CC algorithm
 * @path: Path that experienced loss
 * @bytes_lost: Number of bytes detected as lost
 *
 * Calls the path's CC algorithm on_loss callback if registered.
 */
void tquic_cong_on_loss(struct tquic_path *path, u64 bytes_lost);

/*
 * =============================================================================
 * Persistent Congestion Detection (RFC 9002 Section 7.6)
 * =============================================================================
 *
 * Persistent congestion is detected when an ack-eliciting packet is lost and
 * its loss is contiguous with a loss spanning more than the persistent
 * congestion duration. When persistent congestion is established, the
 * sender's congestion window MUST be reduced to the minimum congestion
 * window (kMinimumWindow).
 */

/* Forward declaration for persistent congestion info */
struct tquic_persistent_cong_info;
struct tquic_lost_packet;

/*
 * tquic_cong_on_persistent_congestion - Dispatch persistent congestion event
 * @path: Path that experienced persistent congestion
 * @info: Persistent congestion information (period, min_cwnd)
 *
 * Called when persistent congestion is detected per RFC 9002 Section 7.6.
 * Dispatches to the CC algorithm's on_persistent_congestion callback.
 * The CC algorithm should reset its state to minimum congestion window.
 */
void tquic_cong_on_persistent_congestion(struct tquic_path *path,
					 struct tquic_persistent_cong_info *info);

/*
 * tquic_cong_check_persistent_congestion - Check for persistent congestion
 * @path: Path to check for persistent congestion
 * @lost_packets: Array of lost packets sorted by send time
 * @num_lost: Number of packets in the lost_packets array
 * @smoothed_rtt: Smoothed RTT in microseconds
 * @rtt_var: RTT variance in microseconds
 *
 * Checks if the lost packets span a duration exceeding the persistent
 * congestion threshold. If so, invokes persistent congestion handling.
 *
 * Per RFC 9002: Persistent congestion period =
 *   (smoothed_rtt + max(4*rtt_var, kGranularity)) * kPersistentCongestionThreshold
 *
 * Return: true if persistent congestion was detected and handled, false otherwise
 */
bool tquic_cong_check_persistent_congestion(struct tquic_path *path,
					    struct tquic_lost_packet *lost_packets,
					    int num_lost,
					    u64 smoothed_rtt, u64 rtt_var);

/*
 * tquic_cong_on_rtt - Dispatch RTT update to path's CC algorithm
 * @path: Path with RTT update
 * @rtt_us: RTT sample in microseconds
 *
 * Calls the path's CC algorithm on_rtt_update callback if registered.
 */
void tquic_cong_on_rtt(struct tquic_path *path, u64 rtt_us);

/*
 * tquic_cong_get_cwnd - Get current cwnd from path's CC algorithm
 * @path: Path to query
 *
 * Return: Current congestion window in bytes, or default if no CC
 */
u64 tquic_cong_get_cwnd(struct tquic_path *path);

/*
 * tquic_cong_get_pacing_rate - Get pacing rate from path's CC algorithm
 * @path: Path to query
 *
 * Return: Current pacing rate in bytes/sec, or 0 if no pacing
 */
u64 tquic_cong_get_pacing_rate(struct tquic_path *path);

/*
 * =============================================================================
 * Per-Network Namespace CC Configuration
 * =============================================================================
 *
 * These functions manage per-netns CC defaults and auto-selection.
 */

struct net;

/*
 * tquic_cong_set_default - Set default CC algorithm for a network namespace
 * @net: Network namespace
 * @name: CC algorithm name
 *
 * Set the default CC algorithm for new paths in this namespace.
 * The algorithm is looked up and validated before being set.
 *
 * Returns 0 on success, -ENOENT if algorithm not found,
 * -EBUSY if module get fails.
 */
int tquic_cong_set_default(struct net *net, const char *name);

/*
 * tquic_cong_get_default - Get default CC algorithm for a network namespace
 * @net: Network namespace
 *
 * Returns pointer to default CC ops, or NULL if none set.
 * Caller should hold RCU read lock.
 */
struct tquic_cong_ops *tquic_cong_get_default(struct net *net);

/*
 * tquic_cong_get_default_name - Get default CC algorithm name for a netns
 * @net: Network namespace
 *
 * Returns CC algorithm name string, or "cubic" as fallback.
 */
const char *tquic_cong_get_default_name(struct net *net);

/*
 * tquic_cong_select_for_rtt - Select CC algorithm based on RTT
 * @net: Network namespace for configuration
 * @rtt_us: Path RTT in microseconds
 *
 * If RTT >= bbr_rtt_threshold_ms, returns "bbr" for BBR auto-selection.
 * Otherwise returns the per-netns default CC algorithm name.
 *
 * Returns CC algorithm name to use for this path.
 */
const char *tquic_cong_select_for_rtt(struct net *net, u64 rtt_us);

/*
 * tquic_cong_is_bbr_preferred - Check if BBR should be used for RTT
 * @net: Network namespace
 * @rtt_us: Path RTT in microseconds
 *
 * Returns true if RTT exceeds the BBR auto-selection threshold.
 */
bool tquic_cong_is_bbr_preferred(struct net *net, u64 rtt_us);

/*
 * =============================================================================
 * Coupled CC Coordination Layer
 * =============================================================================
 *
 * These functions integrate coupled CC algorithms (OLIA/LIA/BALIA) with
 * the per-path CC framework. Coupled CC ensures TCP-fairness at shared
 * bottlenecks while allowing full bandwidth utilization.
 *
 * Per RESEARCH.md: "OLIA as default" coupled algorithm.
 * Per CONTEXT.md: "Coupled CC is opt-in via sysctl/sockopt".
 */

/*
 * tquic_cong_enable_coupling - Enable coupled CC for a connection
 * @conn: Connection to enable coupling on
 * @algo: Coupled algorithm (TQUIC_COUPLED_OLIA, LIA, or BALIA)
 *
 * Creates coupled CC state and attaches all existing paths.
 * New paths added after this call are automatically attached.
 *
 * Return: 0 on success, -errno on failure
 */
int tquic_cong_enable_coupling(struct tquic_connection *conn,
			       enum tquic_coupled_algo algo);

/*
 * tquic_cong_disable_coupling - Disable coupled CC for a connection
 * @conn: Connection to disable coupling on
 *
 * Detaches all paths and destroys coupled state.
 * Paths continue using their individual CC algorithms.
 */
void tquic_cong_disable_coupling(struct tquic_connection *conn);

/*
 * tquic_cong_is_coupling_enabled - Check if coupled CC is enabled
 * @conn: Connection to check
 *
 * Return: true if coupled CC is active, false otherwise
 */
bool tquic_cong_is_coupling_enabled(struct tquic_connection *conn);

/*
 * tquic_cong_on_ecn - Dispatch ECN CE event to path's CC algorithm
 * @path: Path that received ECN CE marking
 * @ecn_ce_count: Number of ECN CE marks reported in ACK
 *
 * Called when ACK frame reports increased ECN CE count.
 * Per CONTEXT.md: "ECN support: available but off by default".
 *
 * Per RFC 9002 Section 7.1: "Each increase in the ECN-CE counter
 * is a signal of congestion. The sender SHOULD reduce the congestion
 * window using the approach described in..."
 */
void tquic_cong_on_ecn(struct tquic_path *path, u64 ecn_ce_count);

/*
 * =============================================================================
 * ECN (Explicit Congestion Notification) Support
 * =============================================================================
 *
 * Per RFC 9002 Section 7, ECN provides early congestion signals via
 * IP header marking rather than packet loss. This allows congestion
 * control to respond before packets are dropped.
 *
 * ECN Codepoints (IP header):
 * - 00 = Not-ECT (ECN not in use)
 * - 01 = ECT(1)  (ECN Capable Transport)
 * - 10 = ECT(0)  (ECN Capable Transport)
 * - 11 = CE      (Congestion Experienced)
 *
 * Per CONTEXT.md: "ECN support: available but off by default (enable via sysctl)"
 */

/* ECN codepoints for IP header DSCP/ECN field */
#define TQUIC_ECN_NOT_ECT	0x00	/* Not ECN-Capable Transport */
#define TQUIC_ECN_ECT1		0x01	/* ECN Capable Transport (1) */
#define TQUIC_ECN_ECT0		0x02	/* ECN Capable Transport (0) */
#define TQUIC_ECN_CE		0x03	/* Congestion Experienced */

/* Default ECN marking for outgoing packets (ECT(0) per RFC 9000) */
#define TQUIC_ECN_DEFAULT_MARK	TQUIC_ECN_ECT0

/* ECN beta factor for cwnd reduction (scaled by 1000, default 0.8 = 800) */
#define TQUIC_ECN_BETA_DEFAULT	800
#define TQUIC_ECN_BETA_SCALE	1000

/*
 * Per-path ECN state tracking for congestion control
 *
 * Tracks ECN counts from ACK frames to detect CE count increases.
 * Per RFC 9002: Only respond to *increases* in CE count, not absolute values.
 *
 * Note: This is the congestion control layer's view of ECN state.
 * The main tquic_ecn_state is defined in tquic.h for path-level tracking.
 */
struct tquic_cc_ecn_state {
	u64 ect0_count;		/* Previous ECT(0) count from ACK */
	u64 ect1_count;		/* Previous ECT(1) count from ACK */
	u64 ce_count;		/* Previous CE count from ACK */
	ktime_t last_ce_time;	/* Time of last CE response (rate limiting) */
	bool ecn_capable;	/* Path validated as ECN-capable */
	bool ecn_ce_in_round;	/* CE received in current round (RFC 9002) */
	u64 round_start;	/* Packet number at round start */
};

/*
 * tquic_cc_ecn_init - Initialize ECN state for congestion control
 * @ecn: ECN state structure to initialize
 */
static inline void tquic_cc_ecn_init(struct tquic_cc_ecn_state *ecn)
{
	memset(ecn, 0, sizeof(*ecn));
	ecn->ecn_capable = false;
}

/*
 * tquic_cc_ecn_validate_path - Mark path as ECN-capable after validation
 * @ecn: ECN state structure
 *
 * Called when a path successfully receives ECN feedback in ACKs.
 */
static inline void tquic_cc_ecn_validate_path(struct tquic_cc_ecn_state *ecn)
{
	ecn->ecn_capable = true;
}

/*
 * tquic_cc_ecn_is_capable - Check if path is ECN-capable
 * @ecn: ECN state structure
 *
 * Return: true if path has been validated for ECN
 */
static inline bool tquic_cc_ecn_is_capable(const struct tquic_cc_ecn_state *ecn)
{
	return ecn->ecn_capable;
}

/*
 * tquic_cc_ecn_process_ack - Process ECN counts from ACK frame
 * @ecn: ECN state structure
 * @ect0: ECT(0) count from ACK
 * @ect1: ECT(1) count from ACK
 * @ce: CE count from ACK
 *
 * Returns: Number of new CE marks (increase since last ACK), 0 if none
 */
static inline u64 tquic_cc_ecn_process_ack(struct tquic_cc_ecn_state *ecn,
					   u64 ect0, u64 ect1, u64 ce)
{
	u64 ce_increase = 0;

	/* Detect increase in CE count */
	if (ce > ecn->ce_count)
		ce_increase = ce - ecn->ce_count;

	/* Update stored counts */
	ecn->ect0_count = ect0;
	ecn->ect1_count = ect1;
	ecn->ce_count = ce;

	/* Mark path as ECN-capable if we receive any ECN feedback */
	if (ect0 > 0 || ect1 > 0 || ce > 0)
		ecn->ecn_capable = true;

	return ce_increase;
}

/*
 * tquic_cc_ecn_start_round - Start a new congestion round
 * @ecn: ECN state structure
 * @pkt_num: Current packet number
 *
 * Called at the start of a new round to reset CE tracking.
 * Per RFC 9002: Don't reduce more than once per RTT.
 */
static inline void tquic_cc_ecn_start_round(struct tquic_cc_ecn_state *ecn,
					    u64 pkt_num)
{
	ecn->ecn_ce_in_round = false;
	ecn->round_start = pkt_num;
}

/*
 * tquic_cc_ecn_can_respond - Check if we can respond to CE in this round
 * @ecn: ECN state structure
 *
 * Per RFC 9002 Section 7.1: "A sender MUST NOT apply this reduction
 * more than once in a given round trip."
 *
 * Return: true if we can respond to CE, false if already responded this round
 */
static inline bool tquic_cc_ecn_can_respond(struct tquic_cc_ecn_state *ecn)
{
	return !ecn->ecn_ce_in_round;
}

/*
 * tquic_cc_ecn_mark_responded - Mark that we responded to CE in this round
 * @ecn: ECN state structure
 */
static inline void tquic_cc_ecn_mark_responded(struct tquic_cc_ecn_state *ecn)
{
	ecn->ecn_ce_in_round = true;
	ecn->last_ce_time = ktime_get();
}

#endif /* _TQUIC_CONG_H */
