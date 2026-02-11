// SPDX-License-Identifier: GPL-2.0-only
/*
 * TQUIC Proc Interface
 *
 * Copyright (c) 2026 Justin Adams <spotty118@gmail.com>
 * Kernel implementation by Justin Adams <spotty118@gmail.com>
 *
 * Implements /proc/net/tquic, /proc/net/tquic_stat, and /proc/net/tquic_errors
 * for monitoring TQUIC connections and debugging.
 *
 * File contents:
 * - /proc/net/tquic: Connection listing with fixed-column format
 * - /proc/net/tquic_stat: MIB counter display in TquicExt format
 * - /proc/net/tquic_errors: Error ring buffer for debugging
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/spinlock.h>
#include <linux/atomic.h>
#include <linux/rhashtable.h>
#include <linux/rcupdate.h>
#include <net/net_namespace.h>
#include <net/sock.h>
#include <net/tquic.h>
#include <uapi/linux/tquic.h>

#include "protocol.h"
#include "tquic_mib.h"
#include "tquic_debug.h"
#include "tquic_compat.h"
#include "tquic_ratelimit.h"

/* External reference to global connection table from tquic_main.c */

/*
 * =============================================================================
 * Error Name Lookup
 * =============================================================================
 *
 * Per CONTEXT.md: Error codes displayed as "501 (EQUIC_FLOW_CONTROL)"
 */

static const char * const equic_error_names[] = {
	[0x00] = "EQUIC_NO_ERROR",
	[0x01] = "EQUIC_INTERNAL_ERROR",
	[0x02] = "EQUIC_CONNECTION_REFUSED",
	[0x03] = "EQUIC_FLOW_CONTROL",
	[0x04] = "EQUIC_STREAM_LIMIT",
	[0x05] = "EQUIC_STREAM_STATE",
	[0x06] = "EQUIC_FINAL_SIZE",
	[0x07] = "EQUIC_FRAME_ENCODING",
	[0x08] = "EQUIC_TRANSPORT_PARAM",
	[0x09] = "EQUIC_CONNECTION_ID_LIMIT",
	[0x0a] = "EQUIC_PROTOCOL_VIOLATION",
	[0x0b] = "EQUIC_INVALID_TOKEN",
	[0x0c] = "EQUIC_APPLICATION_ERROR",
	[0x0d] = "EQUIC_CRYPTO_BUFFER",
	[0x0e] = "EQUIC_KEY_UPDATE",
	[0x0f] = "EQUIC_AEAD_LIMIT",
	[0x10] = "EQUIC_NO_VIABLE_PATH",
};

/**
 * tquic_error_name - Get human-readable name for EQUIC error code
 * @error_code: EQUIC error code (EQUIC_* from uapi/linux/tquic.h)
 *
 * Returns: Error name string, or "UNKNOWN" for invalid codes
 *
 * Per CONTEXT.md: Format as "501 (EQUIC_FLOW_CONTROL)" in output
 */
const char *tquic_error_name(u32 error_code)
{
	u32 idx;

	if (error_code < EQUIC_BASE)
		return "UNKNOWN";

	idx = error_code - EQUIC_BASE;
	if (idx >= ARRAY_SIZE(equic_error_names))
		return "UNKNOWN";

	return equic_error_names[idx] ?: "UNKNOWN";
}
EXPORT_SYMBOL_GPL(tquic_error_name);

/*
 * =============================================================================
 * Error Ring Buffer
 * =============================================================================
 *
 * Per CONTEXT.md: Dedicated ring buffer captures detailed error context
 * without flooding dmesg.
 */

#define TQUIC_ERROR_RING_SIZE	256

/**
 * struct tquic_error_entry - Single error ring buffer entry
 * @timestamp: When the error occurred
 * @error_code: EQUIC error code
 * @scid: Source connection ID
 * @scid_len: Length of SCID
 * @local_addr: Local address at time of error
 * @remote_addr: Remote address at time of error
 * @path_id: Path ID (for multipath)
 * @message: Short error context message
 */
struct tquic_error_entry {
	ktime_t timestamp;
	u32 error_code;
	u8 scid[TQUIC_MAX_CID_LEN];
	u8 scid_len;
	struct sockaddr_storage local_addr;
	struct sockaddr_storage remote_addr;
	u32 path_id;
	char message[64];
};

/**
 * struct tquic_error_ring - Error ring buffer
 * @entries: Array of error entries
 * @head: Next write position (protected by lock)
 * @count: Number of entries written (saturates at RING_SIZE)
 * @lock: Spinlock protecting all ring state
 */
struct tquic_error_ring {
	struct tquic_error_entry entries[TQUIC_ERROR_RING_SIZE];
	unsigned int head;
	unsigned int count;
	spinlock_t lock;
};

/**
 * tquic_error_ring_alloc - Allocate error ring buffer
 *
 * Returns: Allocated error ring, or NULL on failure
 */
static struct tquic_error_ring *tquic_error_ring_alloc(void)
{
	struct tquic_error_ring *ring;

	ring = kzalloc(sizeof(*ring), GFP_KERNEL);
	if (!ring)
		return NULL;

	spin_lock_init(&ring->lock);
	ring->head = 0;
	ring->count = 0;

	return ring;
}

/**
 * tquic_error_ring_free - Free error ring buffer
 * @ring: Ring to free (can be NULL)
 */
static void tquic_error_ring_free(struct tquic_error_ring *ring)
{
	kfree(ring);
}

/**
 * tquic_log_error - Log an error to the ring buffer
 * @net: Network namespace
 * @conn: Connection where error occurred (can be NULL)
 * @error_code: EQUIC error code
 * @msg: Short context message
 *
 * Adds error to the ring buffer. For important errors, also logs
 * to dmesg via pr_warn_ratelimited.
 *
 * Lock-free write using atomic head increment.
 */
void tquic_log_error(struct net *net, struct tquic_connection *conn,
		     u32 error_code, const char *msg)
{
	struct tquic_error_ring *ring;
	struct tquic_error_entry *entry;
	struct tquic_net *tn;
	int idx;

	/* Get error ring for this namespace */
	tn = tquic_pernet(net);
	if (!tn)
		return;
	ring = tn->error_ring;
	if (!ring)
		return;

	/*
	 * Serialize writers to prevent torn entries visible to readers.
	 * The ring is small and errors are infrequent, so contention
	 * is not a concern.
	 */
	spin_lock_bh(&ring->lock);

	idx = ring->head & (TQUIC_ERROR_RING_SIZE - 1);
	ring->head++;

	/* Track total entries written (for reader wrap detection) */
	if (ring->count < TQUIC_ERROR_RING_SIZE)
		ring->count++;

	entry = &ring->entries[idx];

	/* Fill entry atomically under lock */
	entry->timestamp = ktime_get_real();
	entry->error_code = error_code;

	if (conn) {
		struct tquic_path *apath;
		u8 len = min_t(u8, conn->scid.len, TQUIC_MAX_CID_LEN);

		memcpy(entry->scid, conn->scid.id, len);
		entry->scid_len = len;

		apath = READ_ONCE(conn->active_path);
		if (apath) {
			memcpy(&entry->local_addr,
			       &apath->local_addr,
			       sizeof(entry->local_addr));
			memcpy(&entry->remote_addr,
			       &apath->remote_addr,
			       sizeof(entry->remote_addr));
			entry->path_id = apath->path_id;
		} else {
			memset(&entry->local_addr, 0, sizeof(entry->local_addr));
			memset(&entry->remote_addr, 0, sizeof(entry->remote_addr));
			entry->path_id = 0;
		}
	} else {
		entry->scid_len = 0;
		memset(&entry->local_addr, 0, sizeof(entry->local_addr));
		memset(&entry->remote_addr, 0, sizeof(entry->remote_addr));
		entry->path_id = 0;
	}

	if (msg)
		strscpy(entry->message, msg, sizeof(entry->message));
	else
		entry->message[0] = '\0';

	spin_unlock_bh(&ring->lock);

	/* Log important errors to dmesg (ratelimited) */
	if (error_code != EQUIC_NO_ERROR) {
		pr_warn_ratelimited("tquic: error %u (%s): %s\n",
				    error_code, tquic_error_name(error_code),
				    msg ?: "");
	}
}
EXPORT_SYMBOL_GPL(tquic_log_error);

/*
 * =============================================================================
 * Connection State Name Mapping
 * =============================================================================
 *
 * Per CONTEXT.md: Hybrid state format "QUIC (TCP)" aids operators
 */

static const char *tquic_state_name(enum tquic_conn_state state)
{
	switch (state) {
	case TQUIC_CONN_IDLE:
		return "IDLE (CLOSED)";
	case TQUIC_CONN_CONNECTING:
		return "CONNECTING (SYN_SENT)";
	case TQUIC_CONN_CONNECTED:
		return "CONNECTED (ESTABLISHED)";
	case TQUIC_CONN_CLOSING:
		return "CLOSING (FIN_WAIT)";
	case TQUIC_CONN_DRAINING:
		return "DRAINING (TIME_WAIT)";
	case TQUIC_CONN_CLOSED:
		return "CLOSED (CLOSED)";
	default:
		return "UNKNOWN";
	}
}

/*
 * =============================================================================
 * /proc/net/tquic - Connection Listing
 * =============================================================================
 *
 * Per CONTEXT.md:
 * - Fixed-column format (space-separated, awk-parseable)
 * - Header row with column names
 * - Full hex SCID
 * - Namespace isolation via net_eq()
 */

/* seq_file private data for connection iteration */
struct tquic_conn_iter {
	struct net *net;
	struct rhashtable_iter hti;
	loff_t pos;
};

static void *tquic_conn_seq_start(struct seq_file *seq, loff_t *pos)
{
	struct tquic_conn_iter *iter = seq->private;
	struct tquic_connection *conn;
	loff_t skip = *pos;

	iter->pos = *pos;

	/* Header is position 0 */
	if (*pos == 0)
		return SEQ_START_TOKEN;

	/* Start rhashtable walk for position 1+ */
	rhashtable_walk_enter(&tquic_conn_table, &iter->hti);
	rhashtable_walk_start(&iter->hti);

	/* Skip to requested position, filtering by namespace */
	while ((conn = rhashtable_walk_next(&iter->hti)) != NULL) {
		if (IS_ERR(conn))
			continue;
		/* Filter by namespace */
		if (!net_eq(sock_net(conn->sk), iter->net))
			continue;
		if (--skip == 0)
			return conn;
	}

	rhashtable_walk_stop(&iter->hti);
	rhashtable_walk_exit(&iter->hti);
	return NULL;
}

static void *tquic_conn_seq_next(struct seq_file *seq, void *v, loff_t *pos)
{
	struct tquic_conn_iter *iter = seq->private;
	struct tquic_connection *conn;

	(*pos)++;

	if (v == SEQ_START_TOKEN) {
		/* First connection after header */
		rhashtable_walk_enter(&tquic_conn_table, &iter->hti);
		rhashtable_walk_start(&iter->hti);
	}

	/* Find next connection in our namespace */
	while ((conn = rhashtable_walk_next(&iter->hti)) != NULL) {
		if (IS_ERR(conn))
			continue;
		/* Filter by namespace */
		if (!net_eq(sock_net(conn->sk), iter->net))
			continue;
		return conn;
	}

	rhashtable_walk_stop(&iter->hti);
	rhashtable_walk_exit(&iter->hti);
	return NULL;
}

static void tquic_conn_seq_stop(struct seq_file *seq, void *v)
{
	struct tquic_conn_iter *iter = seq->private;

	if (v && v != SEQ_START_TOKEN) {
		rhashtable_walk_stop(&iter->hti);
		rhashtable_walk_exit(&iter->hti);
	}
}

/**
 * tquic_conn_seq_show - Format one connection line
 *
 * Header format:
 *   sl  local_address:port  remote_address:port  state  paths streams tx_bytes rx_bytes scid
 *
 * Data format:
 *   %4d: %pISpc %pISpc %-19s %5d %7d %10llu %10llu %s
 */
static int tquic_conn_seq_show(struct seq_file *seq, void *v)
{
	struct tquic_connection *conn;
	u64 tx_bytes, rx_bytes;
	u64 streams_opened, streams_closed;
	int num_paths, num_streams;
	int state;
	char scid_hex[TQUIC_MAX_CID_LEN * 2 + 1];
	struct sockaddr_storage local_addr, remote_addr;
	int scid_len;
	int i;

	if (v == SEQ_START_TOKEN) {
		/* Output header row */
		seq_puts(seq, "  sl  local_address:port       remote_address:port      "
			 "state               paths streams   tx_bytes   rx_bytes  scid\n");
		return 0;
	}

	conn = v;

	/* Copy data under lock */
	spin_lock_bh(&conn->lock);
	tx_bytes = conn->stats.tx_bytes;
	rx_bytes = conn->stats.rx_bytes;
	streams_opened = conn->stats.streams_opened;
	streams_closed = conn->stats.streams_closed;
	num_paths = conn->num_paths;
	state = conn->state;
	scid_len = min_t(int, conn->scid.len, TQUIC_MAX_CID_LEN);
	for (i = 0; i < scid_len; i++)
		snprintf(&scid_hex[i * 2], sizeof(scid_hex) - i * 2,
			 "%02x", conn->scid.id[i]);
	scid_hex[scid_len * 2] = '\0';
	if (conn->active_path) {
		memcpy(&local_addr, &conn->active_path->local_addr,
		       sizeof(local_addr));
		memcpy(&remote_addr, &conn->active_path->remote_addr,
		       sizeof(remote_addr));
	} else {
		memset(&local_addr, 0, sizeof(local_addr));
		memset(&remote_addr, 0, sizeof(remote_addr));
	}
	spin_unlock_bh(&conn->lock);

	num_streams = (int)(streams_opened - streams_closed);
	if (num_streams < 0)
		num_streams = 0;

	seq_printf(seq, "%4d: %pISpc %pISpc %-19s %5d %7d %10llu %10llu %s\n",
		   0,  /* slot */
		   &local_addr,
		   &remote_addr,
		   tquic_state_name(state),
		   num_paths,
		   num_streams,
		   tx_bytes,
		   rx_bytes,
		   scid_hex);

	return 0;
}

static const struct seq_operations tquic_conn_seq_ops = {
	.start	= tquic_conn_seq_start,
	.next	= tquic_conn_seq_next,
	.stop	= tquic_conn_seq_stop,
	.show	= tquic_conn_seq_show,
};

/*
 * =============================================================================
 * /proc/net/tquic_stat - MIB Counter Display
 * =============================================================================
 */

static int tquic_stat_seq_show(struct seq_file *seq, void *v)
{
	struct net *net = seq->private;

	tquic_mib_seq_show_net(seq, net);

	/* Include GRO statistics */
	tquic_gro_stats_show(seq);

	return 0;
}

/*
 * =============================================================================
 * /proc/net/tquic_errors - Error Ring Display
 * =============================================================================
 *
 * Format per CONTEXT.md:
 *   timestamp  error  scid  local  remote  path  message
 *   2026-01-31T12:34:56.789  501 (EQUIC_FLOW_CONTROL)  abcd1234...  192.168.1.1:443  10.0.0.5:56789  0  exceeded limit
 */

struct tquic_errors_iter {
	struct net *net;
	int pos;
	int count;
};

static void *tquic_errors_seq_start(struct seq_file *seq, loff_t *pos)
{
	struct tquic_errors_iter *iter = seq->private;
	struct tquic_error_ring *ring;
	struct tquic_net *tn;

	tn = tquic_pernet(iter->net);
	if (!tn)
		return NULL;
	ring = tn->error_ring;
	if (!ring)
		return NULL;

	spin_lock_bh(&ring->lock);
	iter->count = ring->count;
	spin_unlock_bh(&ring->lock);
	if (iter->count == 0)
		return NULL;

	/* Header is position 0 */
	if (*pos == 0)
		return SEQ_START_TOKEN;

	iter->pos = *pos - 1;  /* Adjust for header */
	if (iter->pos >= iter->count)
		return NULL;

	return iter;
}

static void *tquic_errors_seq_next(struct seq_file *seq, void *v, loff_t *pos)
{
	struct tquic_errors_iter *iter = seq->private;

	(*pos)++;

	if (v == SEQ_START_TOKEN) {
		iter->pos = 0;
		if (iter->count == 0)
			return NULL;
		return iter;
	}

	iter->pos++;
	if (iter->pos >= iter->count)
		return NULL;

	return iter;
}

static void tquic_errors_seq_stop(struct seq_file *seq, void *v)
{
	/* Nothing to release */
}

static int tquic_errors_seq_show(struct seq_file *seq, void *v)
{
	struct tquic_errors_iter *iter = seq->private;
	struct tquic_error_ring *ring;
	struct tquic_error_entry *entry;
	char scid_hex[TQUIC_MAX_CID_LEN * 2 + 1];
	struct timespec64 ts;
	int head, idx, i;

	if (v == SEQ_START_TOKEN) {
		seq_puts(seq, "timestamp                  error                          "
			 "scid              local                 remote                path  message\n");
		return 0;
	}

	{
		struct tquic_net *tn = tquic_pernet(iter->net);
		if (!tn)
			return 0;
		ring = tn->error_ring;
	}
	if (!ring)
		return 0;

	/*
	 * Hold lock to get a consistent snapshot of the entry.
	 * Copy entry data under lock, then format outside it.
	 */
	{
		struct tquic_error_entry local_entry;

		spin_lock_bh(&ring->lock);

		/* Calculate actual ring index with safe unsigned masking */
		head = ring->head;
		if (iter->count >= TQUIC_ERROR_RING_SIZE) {
			/* Ring has wrapped, start from oldest */
			idx = (head + iter->pos) & (TQUIC_ERROR_RING_SIZE - 1);
		} else {
			/* Ring hasn't wrapped, start from beginning */
			idx = iter->pos;
			if (idx >= TQUIC_ERROR_RING_SIZE) {
				spin_unlock_bh(&ring->lock);
				return 0;
			}
		}

		memcpy(&local_entry, &ring->entries[idx], sizeof(local_entry));
		spin_unlock_bh(&ring->lock);

		entry = &local_entry;

		/* Format timestamp */
		ts = ktime_to_timespec64(entry->timestamp);

		/* Format SCID as hex - clamp scid_len for safety */
		if (entry->scid_len > TQUIC_MAX_CID_LEN)
			entry->scid_len = TQUIC_MAX_CID_LEN;
		for (i = 0; i < entry->scid_len && i < 8; i++)
			snprintf(scid_hex + i * 2, 3, "%02x", entry->scid[i]);
		if (entry->scid_len > 8)
			strscpy(scid_hex + 16, "...", sizeof(scid_hex) - 16);
		else if (entry->scid_len > 0)
			scid_hex[entry->scid_len * 2] = '\0';
		else
			strscpy(scid_hex, "-", sizeof(scid_hex));

		/* Output: timestamp  error  scid  local  remote  path  message */
		seq_printf(seq, "%lld.%03ld  %3u (%-24s)  %-16s  %-20pISpc  %-20pISpc  %4u  %s\n",
			   (long long)ts.tv_sec,
			   ts.tv_nsec / 1000000,
			   entry->error_code,
			   tquic_error_name(entry->error_code),
			   scid_hex,
			   &entry->local_addr,
			   &entry->remote_addr,
			   entry->path_id,
			   entry->message);
	}

	return 0;
}

static const struct seq_operations tquic_errors_seq_ops = {
	.start	= tquic_errors_seq_start,
	.next	= tquic_errors_seq_next,
	.stop	= tquic_errors_seq_stop,
	.show	= tquic_errors_seq_show,
};

/*
 * =============================================================================
 * Proc File Registration
 * =============================================================================
 */

static int tquic_conn_seq_open(struct inode *inode, struct file *file)
{
	struct seq_file *seq;
	struct tquic_conn_iter *iter;
	int ret;

	ret = seq_open_private(file, &tquic_conn_seq_ops,
			       sizeof(struct tquic_conn_iter));
	if (ret < 0)
		return ret;

	seq = file->private_data;
	iter = seq->private;
	iter->net = pde_data(inode);

	return 0;
}

static const struct proc_ops tquic_conn_proc_ops = {
	.proc_open	= tquic_conn_seq_open,
	.proc_read	= seq_read,
	.proc_lseek	= seq_lseek,
	.proc_release	= seq_release_private,
};

static int tquic_stat_seq_open(struct inode *inode, struct file *file)
{
	return single_open(file, tquic_stat_seq_show, pde_data(inode));
}

static const struct proc_ops tquic_stat_proc_ops = {
	.proc_open	= tquic_stat_seq_open,
	.proc_read	= seq_read,
	.proc_lseek	= seq_lseek,
	.proc_release	= single_release,
};

static int tquic_errors_seq_open(struct inode *inode, struct file *file)
{
	struct seq_file *seq;
	struct tquic_errors_iter *iter;
	int ret;

	ret = seq_open_private(file, &tquic_errors_seq_ops,
			       sizeof(struct tquic_errors_iter));
	if (ret < 0)
		return ret;

	seq = file->private_data;
	iter = seq->private;
	iter->net = pde_data(inode);

	return 0;
}

static const struct proc_ops tquic_errors_proc_ops = {
	.proc_open	= tquic_errors_seq_open,
	.proc_read	= seq_read,
	.proc_lseek	= seq_lseek,
	.proc_release	= seq_release_private,
};

/*
 * =============================================================================
 * /proc/net/tquic_ratelimit - Rate Limiting Statistics
 * =============================================================================
 */

static int tquic_ratelimit_seq_show(struct seq_file *seq, void *v)
{
	return tquic_ratelimit_proc_show(seq, v);
}

static int tquic_ratelimit_seq_open(struct inode *inode, struct file *file)
{
	return single_open(file, tquic_ratelimit_seq_show, pde_data(inode));
}

static const struct proc_ops tquic_ratelimit_proc_ops = {
	.proc_open	= tquic_ratelimit_seq_open,
	.proc_read	= seq_read,
	.proc_lseek	= seq_lseek,
	.proc_release	= single_release,
};

/**
 * tquic_proc_init - Initialize proc files for a network namespace
 * @net: Network namespace
 *
 * Creates:
 * - /proc/net/tquic: Connection listing
 * - /proc/net/tquic_stat: MIB counters
 * - /proc/net/tquic_errors: Error ring buffer
 * - /proc/net/tquic_ratelimit: Rate limiting statistics
 *
 * Also allocates the error ring buffer for this namespace.
 *
 * Returns: 0 on success, negative errno on failure
 */
int tquic_proc_init(struct net *net)
{
	struct proc_dir_entry *p;
	struct tquic_net *tn = tquic_pernet(net);

	if (!tn)
		return -EINVAL;

	/* Allocate error ring for this namespace */
	tn->error_ring = tquic_error_ring_alloc();
	if (!tn->error_ring)
		return -ENOMEM;

	/*
	 * Create /proc/net/tquic using proc_create_data for out-of-tree
	 * compatibility.  Connection listing exposes endpoint addresses
	 * and connection IDs -- restrict to root/group to prevent
	 * information disclosure to unprivileged users.
	 */
	p = proc_create_data("tquic", 0440, net->proc_net,
			     &tquic_conn_proc_ops, net);
	if (!p)
		goto err_ring;

	/* Create /proc/net/tquic_stat - aggregate counters, less sensitive */
	p = proc_create_data("tquic_stat", 0444, net->proc_net,
			     &tquic_stat_proc_ops, net);
	if (!p)
		goto err_tquic;

	/* Create /proc/net/tquic_errors - contains addresses and CIDs */
	p = proc_create_data("tquic_errors", 0440, net->proc_net,
			     &tquic_errors_proc_ops, net);
	if (!p)
		goto err_stat;

	/* Create /proc/net/tquic_ratelimit */
	p = proc_create_data("tquic_ratelimit", 0444, net->proc_net,
			     &tquic_ratelimit_proc_ops, net);
	if (!p)
		goto err_errors;

	return 0;

err_errors:
	remove_proc_entry("tquic_errors", net->proc_net);
err_stat:
	remove_proc_entry("tquic_stat", net->proc_net);
err_tquic:
	remove_proc_entry("tquic", net->proc_net);
err_ring:
	tquic_error_ring_free(tn->error_ring);
	tn->error_ring = NULL;
	return -ENOMEM;
}

/**
 * tquic_proc_exit - Remove proc files for a network namespace
 * @net: Network namespace
 */
void tquic_proc_exit(struct net *net)
{
	struct tquic_net *tn = tquic_pernet(net);

	remove_proc_entry("tquic_ratelimit", net->proc_net);
	remove_proc_entry("tquic_errors", net->proc_net);
	remove_proc_entry("tquic_stat", net->proc_net);
	remove_proc_entry("tquic", net->proc_net);

	if (tn) {
		tquic_error_ring_free(tn->error_ring);
		tn->error_ring = NULL;
	}
}

MODULE_DESCRIPTION("TQUIC Proc Interface");
MODULE_LICENSE("GPL");
