// SPDX-License-Identifier: GPL-2.0-only
/*
 * TQUIC Debug Infrastructure
 *
 * Copyright (c) 2026 Justin Adams <spotty118@gmail.com>
 * Kernel implementation by Justin Adams <spotty118@gmail.com>
 *
 * Implements debugfs interface for TQUIC runtime inspection and debugging.
 *
 * Debugfs entries (/sys/kernel/debug/tquic/):
 *
 *   connections  - All active connections with state, CIDs, paths, streams
 *   paths        - Per-path state: RTT, cwnd, loss rate, CC state
 *   handshake    - Handshake state for each connection
 *   debug_level  - Read/write debug verbosity control
 *
 * Usage:
 *   # View all connections
 *   cat /sys/kernel/debug/tquic/connections
 *
 *   # View path-level details
 *   cat /sys/kernel/debug/tquic/paths
 *
 *   # Set debug level (0=off, 1=err, 2=warn, 3=info, 4=debug)
 *   echo 4 > /sys/kernel/debug/tquic/debug_level
 *
 *   # View handshake state
 *   cat /sys/kernel/debug/tquic/handshake
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/debugfs.h>
#include <linux/seq_file.h>
#include <linux/rhashtable.h>
#include <net/sock.h>
#include <net/tquic.h>

#include "protocol.h"
#include "tquic_debug.h"

/* Global debug level - controlled via debugfs and sysctl */
int tquic_debug_level = TQUIC_DBG_WARN;
EXPORT_SYMBOL_GPL(tquic_debug_level);

/* Root debugfs directory */
static struct dentry *tquic_debugfs_root;

/* External reference to global connection table */

/*
 * =============================================================================
 * State Name Helpers
 * =============================================================================
 */

static const char *tquic_debug_conn_state(enum tquic_conn_state state)
{
	switch (state) {
	case TQUIC_CONN_IDLE:		return "IDLE";
	case TQUIC_CONN_CONNECTING:	return "CONNECTING";
	case TQUIC_CONN_CONNECTED:	return "CONNECTED";
	case TQUIC_CONN_CLOSING:	return "CLOSING";
	case TQUIC_CONN_DRAINING:	return "DRAINING";
	case TQUIC_CONN_CLOSED:		return "CLOSED";
	default:			return "UNKNOWN";
	}
}

static const char *tquic_debug_path_state(enum tquic_path_state state)
{
	switch (state) {
	case TQUIC_PATH_UNUSED:		return "UNUSED";
	case TQUIC_PATH_PENDING:	return "PENDING";
	case TQUIC_PATH_VALIDATED:	return "VALIDATED";
	case TQUIC_PATH_ACTIVE:		return "ACTIVE";
	case TQUIC_PATH_STANDBY:	return "STANDBY";
	case TQUIC_PATH_UNAVAILABLE:	return "UNAVAIL";
	case TQUIC_PATH_FAILED:		return "FAILED";
	case TQUIC_PATH_CLOSED:		return "CLOSED";
	default:			return "?";
	}
}

static const char *tquic_debug_role(enum tquic_conn_role role)
{
	switch (role) {
	case TQUIC_ROLE_CLIENT:		return "client";
	case TQUIC_ROLE_SERVER:		return "server";
	default:			return "unknown";
	}
}

/*
 * =============================================================================
 * /sys/kernel/debug/tquic/connections
 * =============================================================================
 *
 * Format:
 *   conn  role    state        version   scid             dcid             paths streams  tx_bytes  rx_bytes  rtt_us
 *     0   client  CONNECTED    0x00000001 abcdef01234567... 89abcdef01234567...   2       4   123456    654321   15000
 */

struct tquic_debug_conn_iter {
	struct rhashtable_iter hti;
	bool started;
};

static void *tquic_debug_conn_start(struct seq_file *seq, loff_t *pos)
{
	struct tquic_debug_conn_iter *iter = seq->private;

	if (*pos == 0) {
		iter->started = false;
		return SEQ_START_TOKEN;
	}

	if (!iter->started) {
		rhashtable_walk_enter(&tquic_conn_table, &iter->hti);
		rhashtable_walk_start(&iter->hti);
		iter->started = true;
	}

	return rhashtable_walk_next(&iter->hti);
}

static void *tquic_debug_conn_next(struct seq_file *seq, void *v, loff_t *pos)
{
	struct tquic_debug_conn_iter *iter = seq->private;
	void *ret;

	(*pos)++;

	if (v == SEQ_START_TOKEN) {
		rhashtable_walk_enter(&tquic_conn_table, &iter->hti);
		rhashtable_walk_start(&iter->hti);
		iter->started = true;
	}

	ret = rhashtable_walk_next(&iter->hti);
	if (IS_ERR(ret))
		return NULL;
	return ret;
}

static void tquic_debug_conn_stop(struct seq_file *seq, void *v)
{
	struct tquic_debug_conn_iter *iter = seq->private;

	if (iter->started) {
		rhashtable_walk_stop(&iter->hti);
		rhashtable_walk_exit(&iter->hti);
		iter->started = false;
	}
}

static int tquic_debug_conn_show(struct seq_file *seq, void *v)
{
	struct tquic_connection *conn;
	int num_paths, state;
	u64 tx_bytes, rx_bytes;
	u64 streams_opened, streams_closed;
	u64 smoothed_rtt_us;
	int i;

	if (v == SEQ_START_TOKEN) {
		seq_puts(seq, "# TQUIC Connection Debug Dump\n");
		seq_puts(seq, "#\n");
		seq_printf(seq, "%-8s %-7s %-12s %-10s %-34s %-34s %5s %7s %12s %12s %8s\n",
			   "token", "role", "state", "version", "scid", "dcid",
			   "paths", "streams", "tx_bytes", "rx_bytes", "srtt_us");
		return 0;
	}

	if (IS_ERR(v))
		return 0;

	conn = v;

	spin_lock_bh(&conn->lock);
	state = conn->state;
	num_paths = conn->num_paths;
	tx_bytes = conn->stats.tx_bytes;
	rx_bytes = conn->stats.rx_bytes;
	streams_opened = conn->stats.streams_opened;
	streams_closed = conn->stats.streams_closed;
	smoothed_rtt_us = atomic64_read(&conn->stats.smoothed_rtt_us);
	spin_unlock_bh(&conn->lock);

	/* Connection token (unique identifier) */
	seq_printf(seq, "%-8u ", conn->token);

	/* Role */
	seq_printf(seq, "%-7s ", tquic_debug_role(conn->role));

	/* State */
	seq_printf(seq, "%-12s ", tquic_debug_conn_state(state));

	/* Version */
	seq_printf(seq, "0x%08x ", conn->version);

	/* SCID as hex (up to TQUIC_MAX_CID_LEN = 20 bytes) */
	for (i = 0; i < conn->scid.len && i < TQUIC_MAX_CID_LEN; i++)
		seq_printf(seq, "%02x", conn->scid.id[i]);
	for (i = conn->scid.len * 2; i < TQUIC_MAX_CID_LEN * 2 + 2; i++)
		seq_putc(seq, ' ');
	seq_putc(seq, ' ');

	/* DCID as hex (up to TQUIC_MAX_CID_LEN = 20 bytes) */
	for (i = 0; i < conn->dcid.len && i < TQUIC_MAX_CID_LEN; i++)
		seq_printf(seq, "%02x", conn->dcid.id[i]);
	for (i = conn->dcid.len * 2; i < TQUIC_MAX_CID_LEN * 2 + 2; i++)
		seq_putc(seq, ' ');
	seq_putc(seq, ' ');

	/* Paths, streams, bytes, RTT */
	seq_printf(seq, "%5d %7llu %12llu %12llu %8llu\n",
		   num_paths,
		   streams_opened - streams_closed,
		   tx_bytes, rx_bytes, smoothed_rtt_us);

	return 0;
}

static const struct seq_operations tquic_debug_conn_seq_ops = {
	.start	= tquic_debug_conn_start,
	.next	= tquic_debug_conn_next,
	.stop	= tquic_debug_conn_stop,
	.show	= tquic_debug_conn_show,
};

static int tquic_debug_conn_open(struct inode *inode, struct file *file)
{
	return seq_open_private(file, &tquic_debug_conn_seq_ops,
				sizeof(struct tquic_debug_conn_iter));
}

static const struct file_operations tquic_debug_conn_fops = {
	.open		= tquic_debug_conn_open,
	.read		= seq_read,
	.llseek		= seq_lseek,
	.release	= seq_release_private,
};

/*
 * =============================================================================
 * /sys/kernel/debug/tquic/paths
 * =============================================================================
 *
 * Shows per-path details for every connection. Format:
 *   conn  path  state       local                remote               cwnd     inflight  srtt_us  min_rtt  loss%  primary
 */

struct tquic_debug_path_iter {
	struct rhashtable_iter hti;
	struct tquic_connection *conn;
	struct tquic_path *path;
	bool started;
};

static void *tquic_debug_path_start(struct seq_file *seq, loff_t *pos)
{
	struct tquic_debug_path_iter *iter = seq->private;

	if (*pos == 0) {
		iter->started = false;
		iter->conn = NULL;
		iter->path = NULL;
		return SEQ_START_TOKEN;
	}

	return NULL;  /* Only header for first call */
}

static void *tquic_debug_path_next(struct seq_file *seq, void *v, loff_t *pos)
{
	struct tquic_debug_path_iter *iter = seq->private;
	struct tquic_connection *conn;

	(*pos)++;

	if (v == SEQ_START_TOKEN) {
		rhashtable_walk_enter(&tquic_conn_table, &iter->hti);
		rhashtable_walk_start(&iter->hti);
		iter->started = true;

		/* Find first connection with paths */
		while ((conn = rhashtable_walk_next(&iter->hti)) != NULL) {
			if (IS_ERR(conn))
				continue;
			if (conn->num_paths > 0) {
				iter->conn = conn;
				return conn;
			}
		}
		return NULL;
	}

	/* Try next connection */
	while ((conn = rhashtable_walk_next(&iter->hti)) != NULL) {
		if (IS_ERR(conn))
			continue;
		if (conn->num_paths > 0) {
			iter->conn = conn;
			return conn;
		}
	}

	return NULL;
}

static void tquic_debug_path_stop(struct seq_file *seq, void *v)
{
	struct tquic_debug_path_iter *iter = seq->private;

	if (iter->started) {
		rhashtable_walk_stop(&iter->hti);
		rhashtable_walk_exit(&iter->hti);
		iter->started = false;
	}
}

static int tquic_debug_path_show(struct seq_file *seq, void *v)
{
	struct tquic_connection *conn;
	struct tquic_path *path;

	if (v == SEQ_START_TOKEN) {
		seq_puts(seq, "# TQUIC Path Debug Dump\n");
		seq_puts(seq, "#\n");
		seq_printf(seq, "%-8s %-4s %-10s %-22s %-22s %8s %8s %8s %8s %5s %3s\n",
			   "token", "path", "state", "local", "remote",
			   "cwnd", "inflight", "srtt_us", "min_rtt", "loss%", "pri");
		return 0;
	}

	if (IS_ERR(v))
		return 0;

	conn = v;

	spin_lock_bh(&conn->lock);
	list_for_each_entry(path, &conn->paths, list) {
		bool is_primary = (path == READ_ONCE(conn->active_path));

		seq_printf(seq, "%-8u %-4u %-10s %-22pISpc %-22pISpc %8u %8u %8llu %8llu %4u%% %c\n",
			   conn->token,
			   path->path_id,
			   tquic_debug_path_state(path->state),
			   &path->local_addr,
			   &path->remote_addr,
			   path->cc.cwnd,
			   path->cc.bytes_in_flight,
			   path->cc.smoothed_rtt_us,
			   path->cc.min_rtt_us,
			   path->cc.loss_rate / 10,
			   is_primary ? '*' : ' ');
	}
	spin_unlock_bh(&conn->lock);

	return 0;
}

static const struct seq_operations tquic_debug_path_seq_ops = {
	.start	= tquic_debug_path_start,
	.next	= tquic_debug_path_next,
	.stop	= tquic_debug_path_stop,
	.show	= tquic_debug_path_show,
};

static int tquic_debug_path_open(struct inode *inode, struct file *file)
{
	return seq_open_private(file, &tquic_debug_path_seq_ops,
				sizeof(struct tquic_debug_path_iter));
}

static const struct file_operations tquic_debug_path_fops = {
	.open		= tquic_debug_path_open,
	.read		= seq_read,
	.llseek		= seq_lseek,
	.release	= seq_release_private,
};

/*
 * =============================================================================
 * /sys/kernel/debug/tquic/handshake
 * =============================================================================
 *
 * Shows handshake state for all connections.
 */

struct tquic_debug_hs_iter {
	struct rhashtable_iter hti;
	bool started;
};

static void *tquic_debug_hs_start(struct seq_file *seq, loff_t *pos)
{
	struct tquic_debug_hs_iter *iter = seq->private;

	if (*pos == 0) {
		iter->started = false;
		return SEQ_START_TOKEN;
	}

	if (!iter->started) {
		rhashtable_walk_enter(&tquic_conn_table, &iter->hti);
		rhashtable_walk_start(&iter->hti);
		iter->started = true;
	}

	return rhashtable_walk_next(&iter->hti);
}

static void *tquic_debug_hs_next(struct seq_file *seq, void *v, loff_t *pos)
{
	struct tquic_debug_hs_iter *iter = seq->private;
	void *ret;

	(*pos)++;

	if (v == SEQ_START_TOKEN) {
		rhashtable_walk_enter(&tquic_conn_table, &iter->hti);
		rhashtable_walk_start(&iter->hti);
		iter->started = true;
	}

	ret = rhashtable_walk_next(&iter->hti);
	if (IS_ERR(ret))
		return NULL;
	return ret;
}

static void tquic_debug_hs_stop(struct seq_file *seq, void *v)
{
	struct tquic_debug_hs_iter *iter = seq->private;

	if (iter->started) {
		rhashtable_walk_stop(&iter->hti);
		rhashtable_walk_exit(&iter->hti);
		iter->started = false;
	}
}

static int tquic_debug_hs_show(struct seq_file *seq, void *v)
{
	struct tquic_connection *conn;
	bool hs_complete, hs_confirmed;
	u64 hs_time_us;
	u32 version;
	const char *hs_status;

	if (v == SEQ_START_TOKEN) {
		seq_puts(seq, "# TQUIC Handshake Debug\n");
		seq_puts(seq, "#\n");
		seq_printf(seq, "%-8s %-7s %-12s %-12s %-10s %12s %7s\n",
			   "token", "role", "hs_state", "conn_state",
			   "version", "hs_time_us", "0-RTT");
		return 0;
	}

	if (IS_ERR(v))
		return 0;

	conn = v;

	spin_lock_bh(&conn->lock);
	hs_complete = conn->handshake_complete;
	hs_confirmed = conn->handshake_confirmed;
	hs_time_us = atomic64_read(&conn->stats.handshake_time_us);
	version = conn->version;
	spin_unlock_bh(&conn->lock);

	if (hs_confirmed)
		hs_status = "CONFIRMED";
	else if (hs_complete)
		hs_status = "COMPLETE";
	else
		hs_status = "PENDING";

	seq_printf(seq, "%-8u %-7s %-12s %-12s 0x%08x %12llu %-7s\n",
		   conn->token,
		   tquic_debug_role(conn->role),
		   hs_status,
		   tquic_debug_conn_state(READ_ONCE(conn->state)),
		   version,
		   hs_time_us,
		   conn->early_data_accepted ? "yes" :
		   conn->early_data_rejected ? "rej" : "no");

	return 0;
}

static const struct seq_operations tquic_debug_hs_seq_ops = {
	.start	= tquic_debug_hs_start,
	.next	= tquic_debug_hs_next,
	.stop	= tquic_debug_hs_stop,
	.show	= tquic_debug_hs_show,
};

static int tquic_debug_hs_open(struct inode *inode, struct file *file)
{
	return seq_open_private(file, &tquic_debug_hs_seq_ops,
				sizeof(struct tquic_debug_hs_iter));
}

static const struct file_operations tquic_debug_hs_fops = {
	.open		= tquic_debug_hs_open,
	.read		= seq_read,
	.llseek		= seq_lseek,
	.release	= seq_release_private,
};

/*
 * =============================================================================
 * /sys/kernel/debug/tquic/debug_level
 * =============================================================================
 *
 * Read/write debug verbosity level.
 * 0=off, 1=error, 2=warn, 3=info, 4=debug
 */

static int tquic_debug_level_get(void *data, u64 *val)
{
	*val = tquic_debug_level;
	return 0;
}

static int tquic_debug_level_set(void *data, u64 val)
{
	if (val > TQUIC_DBG_DEBUG)
		return -EINVAL;

	tquic_debug_level = (int)val;
	pr_info("tquic: debug level set to %d\n", tquic_debug_level);
	return 0;
}

DEFINE_DEBUGFS_ATTRIBUTE(tquic_debug_level_fops,
			 tquic_debug_level_get,
			 tquic_debug_level_set,
			 "%llu\n");

/*
 * =============================================================================
 * Module Init / Exit
 * =============================================================================
 */

int tquic_debug_init(void)
{
	tquic_debugfs_root = debugfs_create_dir("tquic", NULL);
	if (IS_ERR(tquic_debugfs_root)) {
		pr_warn("tquic: failed to create debugfs directory\n");
		tquic_debugfs_root = NULL;
		return 0;  /* Non-fatal: debugfs is optional */
	}

	debugfs_create_file("connections", 0444, tquic_debugfs_root,
			    NULL, &tquic_debug_conn_fops);

	debugfs_create_file("paths", 0444, tquic_debugfs_root,
			    NULL, &tquic_debug_path_fops);

	debugfs_create_file("handshake", 0444, tquic_debugfs_root,
			    NULL, &tquic_debug_hs_fops);

	debugfs_create_file("debug_level", 0644, tquic_debugfs_root,
			    NULL, &tquic_debug_level_fops);

	pr_debug("tquic: debugfs interface created at /sys/kernel/debug/tquic/\n");
	return 0;
}

void tquic_debug_exit(void)
{
	debugfs_remove_recursive(tquic_debugfs_root);
	tquic_debugfs_root = NULL;
	pr_debug("tquic: debugfs interface removed\n");
}
