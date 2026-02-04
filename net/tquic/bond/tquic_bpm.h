/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * TQUIC Path Manager Internal Header
 *
 * Copyright (c) 2024-2026 Linux Foundation
 *
 * Declarations for path management functions in tquic_path.c
 */

#ifndef _NET_TQUIC_BOND_TQUIC_BPM_PATH_H
#define _NET_TQUIC_BOND_TQUIC_BPM_PATH_H

#include <linux/types.h>
#include <linux/gfp.h>

struct net;
struct tquic_bpm_path;
struct tquic_bpm_path_manager;
struct sockaddr;

/*
 * Path States (mapped to local values for internal management)
 */
enum tquic_bpm_path_state {
	TQUIC_BPM_PATH_CREATED = 0, /* Path allocated, not yet validated */
	TQUIC_BPM_PATH_VALIDATING, /* PATH_CHALLENGE sent, awaiting response */
	TQUIC_BPM_PATH_VALIDATED, /* PATH_RESPONSE received, path valid */
	TQUIC_BPM_PATH_ACTIVE, /* Path in active use for data */
	TQUIC_BPM_PATH_STANDBY, /* Valid but not primary */
	TQUIC_BPM_PATH_FAILED, /* Path failed, awaiting cleanup */
	TQUIC_BPM_PATH_CLOSING, /* Path being torn down */

	__TQUIC_BPM_PATH_STATE_MAX
};

/*
 * Path lifecycle
 */
int tquic_bpm_path_validate(struct tquic_bpm_path *path);
int tquic_bpm_path_challenge_send(struct tquic_bpm_path *path, u8 *data);
int tquic_bpm_path_response_recv(struct tquic_bpm_path *path, const u8 *data);
bool tquic_bpm_path_validation_complete(struct tquic_bpm_path *path);

/*
 * Metrics and scoring
 */
void tquic_bpm_path_update_rtt(struct tquic_bpm_path *path, u32 rtt_sample);
void tquic_bpm_path_update_bandwidth(struct tquic_bpm_path *path, u64 bytes,
				 u64 interval_us);
void tquic_bpm_path_update_loss_rate(struct tquic_bpm_path *path);
u32 tquic_bpm_path_get_score(struct tquic_bpm_path *path);

/*
 * WAN detection
 */
enum tquic_wan_type tquic_wan_detect(struct net_device *dev);
s8 tquic_wan_get_signal_strength(struct net_device *dev);

/*
 * Path allocation and initialization
 */
struct tquic_bpm_path *tquic_bpm_path_alloc(gfp_t gfp);
void tquic_bpm_path_free(struct tquic_bpm_path *path);
int tquic_bpm_path_init(struct tquic_bpm_path *path, const struct sockaddr *local,
		    const struct sockaddr *remote, int ifindex);
int tquic_bpm_path_set_state(struct tquic_bpm_path *path,
			 enum tquic_bpm_path_state new_state);

/*
 * Path Manager lifecycle
 */
struct tquic_bpm_path_manager *tquic_bpm_init(struct net *net, gfp_t gfp);
void tquic_bpm_destroy(struct tquic_bpm_path_manager *pm);

/*
 * Path management operations
 */
struct tquic_bpm_path *tquic_bpm_add_path(struct tquic_bpm_path_manager *pm,
				     const struct sockaddr *local,
				     const struct sockaddr *remote,
				     int ifindex);
void tquic_bpm_remove_path(struct tquic_bpm_path_manager *pm,
			  struct tquic_bpm_path *path);
struct tquic_bpm_path *tquic_bpm_get_path(struct tquic_bpm_path_manager *pm,
				     u32 path_id);
int tquic_bpm_get_active_paths(struct tquic_bpm_path_manager *pm,
			      struct tquic_bpm_path **paths, int max_paths);

/*
 * Path discovery and migration
 */
void tquic_bpm_discover_paths(struct tquic_bpm_path_manager *pm);
int tquic_migrate_to_path(struct tquic_bpm_path_manager *pm,
			  struct tquic_bpm_path *new_path);
int tquic_handle_migration(struct tquic_bpm_path_manager *pm,
			   const struct sockaddr *new_remote);
struct tquic_bpm_path *tquic_bpm_select_path(struct tquic_bpm_path_manager *pm);

/*
 * WAN monitoring
 */
void tquic_wan_monitor_start(struct tquic_bpm_path_manager *pm);

/*
 * Module init/exit
 */
int __init tquic_bpm_path_init_module(void);
void __exit tquic_bpm_path_exit_module(void);

#endif /* _NET_TQUIC_BOND_TQUIC_BPM_PATH_H */
