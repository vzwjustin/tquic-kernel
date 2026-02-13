/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * TQUIC: Multipath Deadline-Aware Scheduling
 *
 * Copyright (c) 2026 Justin Adams <spotty118@gmail.com>
 * Kernel implementation by Justin Adams <spotty118@gmail.com>
 */

#ifndef _TQUIC_MP_DEADLINE_H
#define _TQUIC_MP_DEADLINE_H

#include <linux/types.h>
#include <net/tquic.h>

/* Forward declarations */
struct tquic_mp_deadline_coordinator;
struct tquic_mp_deadline_stats;

/**
 * tquic_mp_deadline_path_added - Notify coordinator of new path
 * @coord: Coordinator
 * @path: New path
 */
void tquic_mp_deadline_path_added(struct tquic_mp_deadline_coordinator *coord,
				  struct tquic_path *path);

/**
 * tquic_mp_deadline_path_removed - Notify coordinator of removed path
 * @coord: Coordinator
 * @path: Removed path
 */
void tquic_mp_deadline_path_removed(struct tquic_mp_deadline_coordinator *coord,
				    struct tquic_path *path);

/**
 * tquic_mp_deadline_path_state_changed - Notify of path state change
 * @coord: Coordinator
 * @path: Path with changed state
 * @new_state: New path state
 */
void tquic_mp_deadline_path_state_changed(
	struct tquic_mp_deadline_coordinator *coord,
	struct tquic_path *path, enum tquic_path_state new_state);

/**
 * tquic_mp_deadline_assign_load - Assign load with deadline to path
 * @coord: Coordinator
 * @path: Target path
 * @bytes: Load size in bytes
 */
void tquic_mp_deadline_assign_load(struct tquic_mp_deadline_coordinator *coord,
				   struct tquic_path *path, u64 bytes);

/**
 * tquic_mp_deadline_complete_load - Mark load as completed on path
 * @coord: Coordinator
 * @path: Path the load completed on
 * @bytes: Bytes that were sent
 */
void tquic_mp_deadline_complete_load(struct tquic_mp_deadline_coordinator *coord,
				     struct tquic_path *path, u64 bytes);

/**
 * tquic_mp_deadline_get_stats - Get deadline scheduler statistics
 * @coord: Coordinator
 * @stats: Output statistics structure
 */
void tquic_mp_deadline_get_stats(struct tquic_mp_deadline_coordinator *coord,
				 struct tquic_mp_deadline_stats *stats);

#endif /* _TQUIC_MP_DEADLINE_H */
