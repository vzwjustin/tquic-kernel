/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * TQUIC: Path MTU Discovery (DPLPMTUD) Header
 *
 * Copyright (c) 2026 Linux Foundation
 *
 * Definitions and API for DPLPMTUD (RFC 8899) implementation
 * with QUIC-specific adaptations (RFC 9000).
 */

#ifndef _NET_TQUIC_PMTUD_H
#define _NET_TQUIC_PMTUD_H

#include <linux/types.h>
#include <net/tquic.h>

/*
 * =============================================================================
 * PMTUD Constants
 * =============================================================================
 */

/* QUIC minimum MTU - packets MUST be at least this size (RFC 9000) */
#define TQUIC_PMTUD_BASE_MTU		1200

/* IP/UDP overhead for MTU calculation */
#define TQUIC_IPV4_UDP_OVERHEAD		28	/* 20 (IPv4) + 8 (UDP) */
#define TQUIC_IPV6_UDP_OVERHEAD		48	/* 40 (IPv6) + 8 (UDP) */

/* Default maximum MTU to probe for (Ethernet) */
#define TQUIC_PMTUD_MAX_MTU_DEFAULT	1500

/* Maximum MTU supported (jumbo frames) */
#define TQUIC_PMTUD_MAX_MTU_ABSOLUTE	9000

/* Minimum search range to continue probing */
#define TQUIC_PMTUD_SEARCH_THRESHOLD	20

/* Maximum probe attempts at a single size */
#define TQUIC_PMTUD_MAX_PROBES		3

/* Probe timeout in milliseconds */
#define TQUIC_PMTUD_PROBE_TIMEOUT_MS	15000

/* Re-probe timer for potential MTU increases */
#define TQUIC_PMTUD_RAISE_TIMER_MS	600000

/*
 * =============================================================================
 * PMTUD State Machine States
 * =============================================================================
 */

/**
 * enum tquic_pmtud_state - PMTUD state machine states (RFC 8899 Section 5.2)
 * @TQUIC_PMTUD_DISABLED: PMTUD not active for this path
 * @TQUIC_PMTUD_BASE: Using BASE_PLPMTU (1200 bytes for QUIC)
 * @TQUIC_PMTUD_SEARCHING: Actively probing for larger MTU
 * @TQUIC_PMTUD_SEARCH_COMPLETE: Found working MTU, probing complete
 * @TQUIC_PMTUD_ERROR: Probe failed, backing off to base MTU
 */
enum tquic_pmtud_state {
	TQUIC_PMTUD_DISABLED = 0,
	TQUIC_PMTUD_BASE,
	TQUIC_PMTUD_SEARCHING,
	TQUIC_PMTUD_SEARCH_COMPLETE,
	TQUIC_PMTUD_ERROR,
};

/*
 * =============================================================================
 * PMTUD Statistics
 * =============================================================================
 */

/**
 * struct tquic_pmtud_stats - PMTUD statistics for a path
 * @probes_sent: Total number of probes sent
 * @probes_acked: Number of successful probes
 * @probes_lost: Number of lost probes
 * @black_holes_detected: Number of black hole detections
 * @current_mtu: Current effective MTU
 * @max_probed_mtu: Maximum MTU successfully probed
 * @state: Current PMTUD state
 */
struct tquic_pmtud_stats {
	u64 probes_sent;
	u64 probes_acked;
	u64 probes_lost;
	u64 black_holes_detected;
	u32 current_mtu;
	u32 max_probed_mtu;
	enum tquic_pmtud_state state;
};

/*
 * =============================================================================
 * PMTUD API Functions
 * =============================================================================
 */

/* Forward declaration */
struct tquic_path;

/**
 * tquic_pmtud_init_path - Initialize PMTUD state for a path
 * @path: Path to initialize PMTUD for
 *
 * Allocates PMTUD state and initializes it to BASE state with
 * minimum QUIC MTU (1200 bytes). Determines maximum MTU from
 * the network interface.
 *
 * Return: 0 on success, -errno on failure
 */
int tquic_pmtud_init_path(struct tquic_path *path);

/**
 * tquic_pmtud_release_path - Release PMTUD state for a path
 * @path: Path whose PMTUD state should be released
 *
 * Cancels any pending probes and frees PMTUD resources.
 * Safe to call with NULL or already-released paths.
 */
void tquic_pmtud_release_path(struct tquic_path *path);

/**
 * tquic_pmtud_start - Start PMTUD for a path
 * @path: Path to start PMTUD on
 *
 * Begins the MTU discovery process by entering the SEARCHING state.
 * Does nothing if PMTUD is globally disabled.
 *
 * Return: 0 on success, negative error on failure
 */
int tquic_pmtud_start(struct tquic_path *path);

/**
 * tquic_pmtud_stop - Stop PMTUD for a path
 * @path: Path to stop PMTUD on
 *
 * Stops all probing activity and releases PMTUD resources.
 * The path continues using its current MTU.
 */
void tquic_pmtud_stop(struct tquic_path *path);

/**
 * tquic_pmtud_on_probe_ack - Handle ACK of MTU probe packet
 * @path: Path the probe was sent on
 * @pkt_num: Packet number of the acknowledged probe
 * @probed_size: Size of the probed packet
 *
 * Called when an MTU probe packet is acknowledged, indicating
 * the probed size works on this path. Updates the confirmed MTU
 * and continues searching if applicable.
 */
void tquic_pmtud_on_probe_ack(struct tquic_path *path, u64 pkt_num,
			      u32 probed_size);

/**
 * tquic_pmtud_on_probe_lost - Handle loss of MTU probe packet
 * @path: Path the probe was sent on
 * @pkt_num: Packet number of the lost probe
 *
 * Called when an MTU probe packet is declared lost. May retry
 * the probe or adjust search bounds depending on retry count.
 */
void tquic_pmtud_on_probe_lost(struct tquic_path *path, u64 pkt_num);

/**
 * tquic_pmtud_on_packet_loss - Handle packet loss for black hole detection
 * @path: Path that experienced loss
 * @pkt_size: Size of lost packet
 *
 * Tracks consecutive losses of large packets to detect MTU black holes.
 * If threshold exceeded, falls back to base MTU.
 */
void tquic_pmtud_on_packet_loss(struct tquic_path *path, u32 pkt_size);

/**
 * tquic_pmtud_on_ack - Handle ACK for black hole detection reset
 * @path: Path that received ACK
 * @pkt_size: Size of acknowledged packet
 *
 * Resets black hole detection counter when large packets succeed.
 */
void tquic_pmtud_on_ack(struct tquic_path *path, u32 pkt_size);

/**
 * tquic_pmtud_get_mtu - Get current path MTU
 * @path: Path to query
 *
 * Return: Current effective MTU for the path
 */
u32 tquic_pmtud_get_mtu(struct tquic_path *path);

/**
 * tquic_pmtud_set_max_mtu - Set maximum MTU for a path
 * @path: Path to configure
 * @max_mtu: Maximum MTU to probe for
 *
 * Allows external configuration of the maximum MTU to probe.
 * Useful when interface MTU is known to be limited.
 *
 * Return: 0 on success, negative error on failure
 */
int tquic_pmtud_set_max_mtu(struct tquic_path *path, u32 max_mtu);

/**
 * tquic_pmtud_on_icmp_mtu_update - Handle ICMP-reported MTU decrease
 * @path: Path whose MTU is being reported
 * @new_mtu: QUIC payload MTU (IP MTU minus IP/UDP overhead)
 *
 * Called from ICMP error handlers. Validates and clamps the reported
 * MTU before applying it. Per RFC 9000 Section 14.3, the MTU will
 * never be reduced below 1200 bytes. Triggers DPLPMTUD re-probing
 * to confirm the new MTU.
 */
void tquic_pmtud_on_icmp_mtu_update(struct tquic_path *path, u32 new_mtu);

/**
 * tquic_pmtud_get_stats - Get PMTUD statistics for a path
 * @path: Path to query
 * @stats: Output buffer for statistics
 *
 * Return: 0 on success, -errno on failure
 */
int tquic_pmtud_get_stats(struct tquic_path *path,
			  struct tquic_pmtud_stats *stats);

/*
 * =============================================================================
 * Sysctl Interface
 * =============================================================================
 */

/**
 * tquic_pmtud_sysctl_enabled - Get PMTUD enabled status
 *
 * Return: 1 if PMTUD is enabled globally, 0 otherwise
 */
int tquic_pmtud_sysctl_enabled(void);

/**
 * tquic_pmtud_sysctl_probe_interval - Get PMTUD probe interval
 *
 * Return: Probe interval in milliseconds
 */
int tquic_pmtud_sysctl_probe_interval(void);

/*
 * =============================================================================
 * Module Initialization
 * =============================================================================
 */

/**
 * tquic_pmtud_init - Initialize PMTUD subsystem
 *
 * Called during module load to initialize PMTUD workqueue
 * and other global resources.
 *
 * Return: 0 on success, negative error on failure
 */
int __init tquic_pmtud_init(void);

/**
 * tquic_pmtud_exit - Cleanup PMTUD subsystem
 *
 * Called during module unload to cleanup PMTUD resources.
 */
void __exit tquic_pmtud_exit(void);

#endif /* _NET_TQUIC_PMTUD_H */
