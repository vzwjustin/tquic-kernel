/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * TQUIC Per-Network Namespace State
 *
 * Copyright (c) 2026 Justin Adams <spotty118@gmail.com>
 * Kernel implementation by Justin Adams <spotty118@gmail.com>
 *
 * This header defines per-network-namespace state for the TQUIC subsystem.
 * Each network namespace has its own MIB counters and error ring buffer.
 */

#ifndef _NET_NETNS_TQUIC_H
#define _NET_NETNS_TQUIC_H

/* Forward declarations */
struct tquic_mib;
struct tquic_error_ring;
struct tquic_sched_ops;
struct tquic_sched_internal;
struct tquic_cong_ops;

/* Scheduler name buffer size (matches TQUIC_SCHED_NAME_MAX) */
#define NETNS_TQUIC_SCHED_NAME_MAX	16

/* Congestion control name buffer size (matches TQUIC_CC_NAME_MAX) */
#define NETNS_TQUIC_CC_NAME_MAX		16

/* Default BBR auto-selection threshold (100ms) */
#define NETNS_TQUIC_BBR_RTT_THRESHOLD_MS	100

/**
 * struct netns_tquic - Per-network-namespace TQUIC state
 * @mib: Pointer to per-CPU MIB statistics counters
 * @error_ring: Pointer to error ring buffer for debugging
 * @default_scheduler: RCU-protected pointer to default scheduler ops
 * @sched_name: Buffer for sysctl scheduler name (net.tquic.scheduler)
 * @default_cong: RCU-protected pointer to default CC algorithm ops
 * @cc_name: Buffer for sysctl CC algorithm name (net.tquic.cc_algorithm)
 * @bbr_rtt_threshold_ms: RTT threshold for BBR auto-selection (default 100ms)
 * @coupled_enabled: Enable coupled CC for multipath fairness (default false)
 * @ecn_enabled: Enable ECN for congestion signals (default false)
 *
 * This structure is embedded in struct net (via net->tquic).
 * It holds namespace-specific state that needs to be isolated
 * between different network namespaces.
 *
 * The mib field points to per-CPU counters allocated lazily
 * when the first TQUIC socket is created in the namespace.
 *
 * The error_ring provides a circular buffer of recent errors
 * for debugging, accessible via /proc/net/tquic_errors.
 *
 * The default_scheduler and sched_name fields support per-netns
 * scheduler configuration. Containers can have different default
 * schedulers via sysctl net.tquic.scheduler.
 *
 * The default_cong and cc_name fields support per-netns congestion
 * control configuration. Different paths can use different CC
 * algorithms, with BBR auto-selected for high-RTT paths.
 */
struct netns_tquic {
	struct tquic_mib __percpu *mib;
	struct tquic_error_ring *error_ring;

	/* Per-netns default scheduler (RCU protected, internal scheduler type) */
	struct tquic_sched_internal __rcu *default_scheduler;

	/* Sysctl buffer for scheduler name */
	char sched_name[NETNS_TQUIC_SCHED_NAME_MAX];

	/* Per-netns default congestion control (RCU protected) */
	struct tquic_cong_ops __rcu *default_cong;

	/* Sysctl buffer for CC algorithm name */
	char cc_name[NETNS_TQUIC_CC_NAME_MAX];

	/* BBR auto-selection: paths with RTT >= threshold use BBR */
	u32 bbr_rtt_threshold_ms;

	/* Coupled CC for multipath fairness (OLIA/LIA/BALIA) */
	bool coupled_enabled;

	/* ECN support for congestion signaling */
	bool ecn_enabled;

	/* ECN beta factor for cwnd reduction (scaled by 1000, default 800 = 0.8) */
	u32 ecn_beta;

	/* Pacing configuration (default: true per CONTEXT.md) */
	bool pacing_enabled;

	/* Path degradation threshold (consecutive losses in same round) */
	int path_degrade_threshold;

	/*
	 * GREASE (RFC 9287) configuration
	 *
	 * GREASE (Generate Random Extensions And Sustain Extensibility)
	 * helps ensure forward compatibility by randomly including
	 * reserved values that receivers must ignore.
	 *
	 * When enabled:
	 *   - May GREASE the fixed bit in long headers (with peer support)
	 *   - Includes grease_quic_bit transport parameter
	 *   - May include reserved transport parameters (31*N + 27)
	 *   - May include reserved versions in Version Negotiation
	 */
	bool grease_enabled;

	/*
	 * Preferred Address (RFC 9000 Section 9.6) configuration
	 *
	 * preferred_address_enabled (server):
	 *   When true, server advertises a preferred address in transport
	 *   parameters. Server must ensure it can receive on this address.
	 *   Default: false (0)
	 *   Value -1 means: use global sysctl default
	 *
	 * prefer_preferred_address (client):
	 *   When true, client automatically migrates to server's preferred
	 *   address after handshake completion. Per RFC 9000, clients
	 *   SHOULD migrate when able.
	 *   Default: true (1)
	 *   Value -1 means: use global sysctl default
	 */
	int preferred_address_enabled;
	int prefer_preferred_address;
};

#endif /* _NET_NETNS_TQUIC_H */
