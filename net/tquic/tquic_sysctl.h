/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * TQUIC: Sysctl Interface
 *
 * Copyright (c) 2026 Justin Adams <spotty118@gmail.com>
 * Kernel implementation by Justin Adams <spotty118@gmail.com>
 *
 * Public interface for TQUIC sysctl parameters.
 */

#ifndef _TQUIC_SYSCTL_H
#define _TQUIC_SYSCTL_H

#include <linux/types.h>

struct net;

/*
 * Sysctl accessor functions
 */

/* Bonding and multipath */
int tquic_sysctl_get_bond_mode(void);
int tquic_sysctl_get_max_paths(void);
int tquic_sysctl_get_reorder_window(void);
int tquic_sysctl_get_probe_interval(void);
int tquic_sysctl_get_failover_timeout(void);

/* Connection parameters */
int tquic_sysctl_get_idle_timeout(void);
int tquic_sysctl_get_initial_rtt(void);
int tquic_sysctl_get_initial_cwnd(void);

/* Debugging */
int tquic_sysctl_get_debug_level(void);

/* Scheduler and congestion control */
const char *tquic_sysctl_get_scheduler(void);
const char *tquic_sysctl_get_congestion(void);
const char *tquic_net_get_cc_algorithm(struct net *net);
u32 tquic_net_get_bbr_rtt_threshold(struct net *net);
bool tquic_net_get_cc_coupled(struct net *net);
bool tquic_net_get_ecn_enabled(struct net *net);
u32 tquic_net_get_ecn_beta(struct net *net);
bool tquic_net_get_pacing_enabled(struct net *net);
int tquic_net_get_path_degrade_threshold(struct net *net);

/* Key update */
unsigned long tquic_sysctl_get_key_update_interval_packets(void);
int tquic_sysctl_get_key_update_interval_seconds(void);

/* Path MTU discovery */
int tquic_sysctl_get_pmtud_enabled(void);
int tquic_sysctl_get_pmtud_probe_interval(void);

/* Retry and tokens */
int tquic_sysctl_get_retry_required(void);
int tquic_sysctl_get_retry_token_lifetime(void);

/* HTTP/3 */
int tquic_sysctl_get_http3_priorities_enabled(void);
int tquic_sysctl_get_qpack_max_table_capacity(void);

/* Preferred address */
int tquic_sysctl_get_preferred_address_enabled(void);
int tquic_sysctl_get_prefer_preferred_address(void);

/* Additional addresses */
int tquic_sysctl_get_additional_addresses_enabled(void);
int tquic_sysctl_get_additional_addresses_max(void);

/* Spin bit */
u8 tquic_sysctl_get_spin_bit_disable_rate(void);

/* Rate limiting */
int tquic_sysctl_rate_limit_enabled(void);
int tquic_sysctl_max_connections_per_second(void);
int tquic_sysctl_max_connections_burst(void);
int tquic_sysctl_per_ip_rate_limit(void);

/* GRO */
int tquic_sysctl_get_gro_flush_timeout_us(void);

/* Flow control auto-tuning */
bool tquic_sysctl_get_fc_autotune_enabled(void);

/* Memory limits */
extern int sysctl_tquic_wmem[3];
extern int sysctl_tquic_rmem[3];

#endif /* _TQUIC_SYSCTL_H */
