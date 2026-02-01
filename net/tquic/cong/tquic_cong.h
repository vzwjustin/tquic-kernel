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
 */
void tquic_cong_on_ecn(struct tquic_path *path, u64 ecn_ce_count);

#endif /* _TQUIC_CONG_H */
