/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * QUIC Module Initialization Declarations
 *
 * This header declares all subsystem init/exit functions that need to be
 * called from the main module initialization. Since all these components
 * are compiled into a single quic.o module, only one module_init can be
 * used, and that main init must call all subsystem init functions.
 *
 * Copyright (c) 2024-2026 Linux Foundation
 * Kernel implementation by Justin Adams <spotty118@gmail.com>
 */

#ifndef _QUIC_INIT_H
#define _QUIC_INIT_H

/* Scheduler framework */
int __init tquic_scheduler_init(void);
void __exit tquic_scheduler_exit(void);

/* Individual schedulers */
int __init tquic_sched_minrtt_init(void);
void __exit tquic_sched_minrtt_exit(void);

int __init tquic_sched_aggregate_init(void);
void __exit tquic_sched_aggregate_exit(void);

int __init tquic_sched_weighted_init(void);
void __exit tquic_sched_weighted_exit(void);

int __init tquic_sched_blest_init(void);
void __exit tquic_sched_blest_exit(void);

int __init tquic_sched_ecf_init(void);
void __exit tquic_sched_ecf_exit(void);

/* Bonding and path management */
int __init tquic_bonding_init_module(void);
void __exit tquic_bonding_exit_module(void);

int __init tquic_path_init_module(void);
void __exit tquic_path_exit_module(void);

/* Coupled congestion control */
int __init coupled_cc_init_module(void);
void __exit coupled_cc_exit_module(void);

#endif /* _QUIC_INIT_H */
