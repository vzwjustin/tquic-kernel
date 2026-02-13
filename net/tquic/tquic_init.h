/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * TQUIC: Module Initialization Function Declarations
 *
 * Copyright (c) 2026 Justin Adams <spotty118@gmail.com>
 * Kernel implementation by Justin Adams <spotty118@gmail.com>
 *
 * This header contains initialization and cleanup function declarations
 * for TQUIC subsystems. These functions are called during module load/unload.
 */

#ifndef _TQUIC_INIT_H
#define _TQUIC_INIT_H

/* ACK frequency module */
int tquic_ack_freq_module_init(void);
void tquic_ack_freq_module_exit(void);

/* Crypto subsystem */
int tquic_cert_verify_init(void);
void tquic_cert_verify_exit(void);
int tquic_zero_rtt_module_init(void);
void tquic_zero_rtt_module_exit(void);
int tquic_hw_offload_init(void);
void tquic_hw_offload_exit(void);

/* Scheduler framework and schedulers */
int tquic_scheduler_init(void);
void tquic_scheduler_exit(void);
int tquic_sched_framework_init(void);
void tquic_sched_framework_exit(void);
int tquic_sched_minrtt_init(void);
void tquic_sched_minrtt_exit(void);
int tquic_sched_aggregate_init(void);
void tquic_sched_aggregate_exit(void);
int tquic_sched_weighted_init(void);
void tquic_sched_weighted_exit(void);
int tquic_sched_blest_init(void);
void tquic_sched_blest_exit(void);
int tquic_sched_ecf_init(void);
void tquic_sched_ecf_exit(void);

/* Multipath extensions */
int tquic_mp_ack_init(void);
void tquic_mp_ack_exit(void);
int tquic_mp_frame_init(void);
void tquic_mp_frame_exit(void);
int tquic_mp_abandon_init(void);
void tquic_mp_abandon_exit(void);
int tquic_mp_deadline_init(void);
void tquic_mp_deadline_exit(void);

/* Bonding subsystem */
int tquic_bonding_init_module(void);
void tquic_bonding_exit_module(void);
int tquic_path_init_module(void);
void tquic_path_exit_module(void);
int coupled_cc_init_module(void);
void coupled_cc_exit_module(void);

/* Path managers */
int tquic_pm_types_init(void);
void tquic_pm_types_exit(void);
int tquic_pm_nl_init(void);
void tquic_pm_nl_exit(void);
int tquic_pm_userspace_init(void);
void tquic_pm_userspace_exit(void);
int tquic_pm_kernel_module_init(void);
void tquic_pm_kernel_module_exit(void);
int tquic_nat_keepalive_module_init(void);
void tquic_nat_keepalive_module_exit(void);
int tquic_nat_lifecycle_module_init(void);
void tquic_nat_lifecycle_module_exit(void);

/* Congestion control algorithms */
int tquic_cong_data_module_init(void);
void tquic_cong_data_module_exit(void);
int tquic_bbrv2_init(void);
void tquic_bbrv2_exit(void);
int tquic_bbrv3_init(void);
void tquic_bbrv3_exit(void);
int tquic_prague_init(void);
void tquic_prague_exit(void);

/* Netlink interface */
int tquic_nl_init(void);
void tquic_nl_exit(void);

/* HTTP/3 subsystem */
int tquic_http3_conn_init(void);
void tquic_http3_conn_exit(void);
int tquic_http3_streams_init(void);
void tquic_http3_streams_exit(void);

/* Output TX subsystem */
int tquic_output_tx_init(void);
void tquic_output_tx_exit(void);

/* CID hash used by core/quic_connection.c */
int tquic_cid_hash_init(void);
void tquic_cid_hash_cleanup(void);

/* Debug infrastructure (debugfs) */
int tquic_debug_init(void);
void tquic_debug_exit(void);

/* Sysctl accessors (defined in tquic_sysctl.c) */
u32 tquic_sysctl_get_preferred_version(void);
bool tquic_sysctl_prefer_v2(void);

/* Tracepoint infrastructure (diag/tracepoints.c) */
int tquic_tracepoints_init(void);
void tquic_tracepoints_exit(void);

/* io_uring integration (io_uring.c) */
int tquic_io_uring_init(void);
void tquic_io_uring_exit(void);
#endif /* _TQUIC_INIT_H */
