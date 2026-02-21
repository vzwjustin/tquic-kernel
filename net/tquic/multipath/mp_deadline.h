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

/**
 * struct tquic_mp_deadline_stats - Multipath deadline statistics
 * @num_paths: Number of tracked paths
 * @deadline_capable_paths: Paths capable of meeting deadlines
 * @total_load: Total deadline load in bytes
 * @assignments: Total deadline assignments made
 * @rebalances: Number of rebalancing operations
 * @cross_path_switches: Cross-path deadline switches
 */
struct tquic_mp_deadline_stats {
	u32 num_paths;
	u32 deadline_capable_paths;
	u64 total_load;
	u64 assignments;
	u64 rebalances;
	u64 cross_path_switches;
};

/**
 * mp_deadline_select_best_path - Select best path for a deadline
 * @coord: Coordinator
 * @deadline_us: Deadline in microseconds
 * @data_len: Amount of data to send
 *
 * Returns: Best path for meeting the deadline, or NULL if none can
 */
struct tquic_path *
mp_deadline_select_best_path(struct tquic_mp_deadline_coordinator *coord,
			     u64 deadline_us, size_t data_len);

/**
 * mp_deadline_record_delivery - Record deadline delivery result
 * @coord: Coordinator
 * @path: Path used for delivery
 * @deadline_met: Whether deadline was met
 * @delivery_time_us: Actual delivery time in microseconds
 */
void mp_deadline_record_delivery(struct tquic_mp_deadline_coordinator *coord,
				 struct tquic_path *path, bool deadline_met,
				 u64 delivery_time_us);

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
