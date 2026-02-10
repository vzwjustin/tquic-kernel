/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * TQUIC Connection ID Management - Internal Header
 *
 * Copyright (c) 2026 Linux Foundation
 *
 * This header defines structures for CID management that need to be
 * shared between tquic_cid.c and other modules (e.g., stateless reset).
 */

#ifndef _NET_TQUIC_CID_INTERNAL_H
#define _NET_TQUIC_CID_INTERNAL_H

#include <linux/types.h>
#include <linux/spinlock.h>
#include <linux/rhashtable.h>
#include <linux/timer.h>
#include <linux/workqueue.h>
#include <linux/list.h>
#include <net/tquic.h>
#include "security_hardening.h"

#ifndef TQUIC_STATELESS_RESET_TOKEN_LEN
#define TQUIC_STATELESS_RESET_TOKEN_LEN	16
#endif

/**
 * enum tquic_cid_state - Connection ID lifecycle state
 * @CID_STATE_UNUSED: Not in use
 * @CID_STATE_ACTIVE: Active and usable
 * @CID_STATE_RETIRED: Retired, pending cleanup
 */
enum tquic_cid_state {
	CID_STATE_UNUSED = 0,
	CID_STATE_ACTIVE,
	CID_STATE_RETIRED,
};

/**
 * struct tquic_cid_entry - Connection ID entry in pool
 * @cid: The connection ID
 * @seq_num: Sequence number for this CID
 * @retire_prior_to: Retire CIDs before this sequence
 * @reset_token: Stateless reset token (16 bytes per RFC 9000)
 * @conn: Associated connection
 * @state: CID state (active, retired, etc.)
 * @path: Path this CID is assigned to (for multipath)
 * @node: Hash table linkage for global CID lookup
 * @list: Pool list linkage
 */
struct tquic_cid_entry {
	struct tquic_cid cid;
	u64 seq_num;
	u64 retire_prior_to;
	u8 reset_token[TQUIC_STATELESS_RESET_TOKEN_LEN];
	struct tquic_connection *conn;
	enum tquic_cid_state state;
	struct tquic_path *path;
	struct rhash_head node;
	struct list_head list;
	struct rcu_head rcu;
};

/**
 * struct tquic_cid_pool - Connection ID pool
 * @lock: Pool lock (BH-safe spinlock)
 * @local_cids: List of local CIDs (we issue to peer)
 * @remote_cids: List of remote CIDs (peer issues to us)
 * @next_seq: Next sequence number for new local CID
 * @retire_prior_to: Current retire_prior_to value to send
 * @peer_retire_prior_to: retire_prior_to value received from peer
 * @active_count: Number of active local CIDs
 * @remote_active_count: Number of active remote CIDs
 * @cid_len: Length of CIDs in this pool
 * @active_cid_limit: Max active CIDs (from peer transport param)
 * @packets_since_rotation: Packets sent since last CID rotation
 * @last_rotation_time: Timestamp of last CID rotation
 * @rotation_timer: Timer for time-based rotation
 * @rotation_work: Work struct for rotation processing
 * @rotation_enabled: Whether automatic rotation is enabled
 * @conn: Back-pointer to parent connection
 */
struct tquic_cid_pool {
	spinlock_t lock;
	struct list_head local_cids;
	struct list_head remote_cids;
	u64 next_seq;
	u64 retire_prior_to;
	u64 peer_retire_prior_to;
	u32 active_count;
	u32 remote_active_count;
	u8 cid_len;
	u8 active_cid_limit;

	/* CID rotation state */
	u64 packets_since_rotation;
	ktime_t last_rotation_time;
	struct timer_list rotation_timer;
	struct work_struct rotation_work;
	bool rotation_enabled;
	struct tquic_connection *conn;

	/* Security hardening (CVE-2024-22189 defense) */
	struct tquic_cid_security security;
};

#endif /* _NET_TQUIC_CID_INTERNAL_H */
