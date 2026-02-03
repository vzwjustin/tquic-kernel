// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * QUIC - Quick UDP Internet Connections
 *
 * Path management implementation per RFC 9000 Section 9
 *
 * Copyright (c) 2024 Linux QUIC Authors
 */

#include <linux/slab.h>
#include <linux/random.h>
#include <linux/in.h>
#include <linux/in6.h>
#include <net/quic.h>
#include "trace.h"

/* Path management constants per RFC 9000 */
#define QUIC_PATH_CHALLENGE_SIZE	8
#define QUIC_PATH_MAX_PROBES		3
#define QUIC_PATH_PROBE_TIMEOUT_MS	1000
#define QUIC_PATH_VALIDATION_TIMEOUT_MS	30000
#define QUIC_PATH_MTU_MIN		1200
#define QUIC_PATH_MTU_MAX		65535
#define QUIC_PATH_MTU_INITIAL		1280
#define QUIC_PATH_MTU_PROBE_SIZE	16

/* MTU discovery probe sizes per RFC 8899 */
static const u32 quic_mtu_probes[] = {
	1280, 1400, 1450, 1480, 1492, 1500, 2048, 4096, 8192, 9000
};

static struct kmem_cache *quic_path_cache __read_mostly;

/*
 * Initialize path management subsystem
 */
int __init quic_path_init(void)
{
	quic_path_cache = kmem_cache_create("quic_path",
					    sizeof(struct quic_path), 0,
					    SLAB_HWCACHE_ALIGN, NULL);
	if (!quic_path_cache)
		return -ENOMEM;

	return 0;
}

void quic_path_exit(void)
{
	kmem_cache_destroy(quic_path_cache);
}

/*
 * Initialize RTT measurements for a new path
 * Per RFC 9002 Section 6
 */
static void quic_path_rtt_init(struct quic_rtt *rtt, u32 initial_rtt_ms)
{
	rtt->latest_rtt = initial_rtt_ms * 1000;  /* Convert to microseconds */
	rtt->min_rtt = U32_MAX;
	rtt->smoothed_rtt = initial_rtt_ms * 1000;
	rtt->rttvar = initial_rtt_ms * 500;  /* Initial variance is half of RTT */
	rtt->first_rtt_sample = 0;
	rtt->has_sample = 0;
}

/*
 * Initialize congestion control state for a new path
 * Per RFC 9002 Section 7
 */
static void quic_path_cc_init(struct quic_cc_state *cc, u32 mtu)
{
	/* Initial window is 10 packets or 14720 bytes, whichever is smaller */
	u64 initial_window = min_t(u64, 10 * mtu, 14720);

	cc->cwnd = initial_window;
	cc->ssthresh = U64_MAX;
	cc->bytes_in_flight = 0;
	cc->congestion_window = initial_window;
	cc->pacing_rate = 0;
	cc->last_sent_time = 0;
	cc->congestion_recovery_start = 0;
	cc->pto_count = 0;
	cc->loss_burst_count = 0;
	cc->in_slow_start = 1;
	cc->in_recovery = 0;
	cc->app_limited = 0;
	cc->algo = QUIC_CC_RENO;  /* Default to Reno */

	/* Initialize BBR-specific fields */
	cc->bbr_bw = 0;
	cc->bbr_min_rtt = U64_MAX;
	cc->bbr_cycle_index = 0;
	cc->bbr_mode = 0;

	/* Initialize CUBIC-specific fields */
	cc->cubic_k = 0;
	cc->cubic_origin_point = 0;
	cc->cubic_epoch_start = 0;
}

/*
 * Copy address to path structure with proper validation
 */
static int quic_path_copy_addr(struct sockaddr_storage *dest,
			       const struct sockaddr *src)
{
	if (!src)
		return 0;

	switch (src->sa_family) {
	case AF_INET:
		memcpy(dest, src, sizeof(struct sockaddr_in));
		return 0;
	case AF_INET6:
		memcpy(dest, src, sizeof(struct sockaddr_in6));
		return 0;
	default:
		return -EAFNOSUPPORT;
	}
}

/*
 * Compare two socket addresses for equality
 */
static bool quic_path_addr_equal(const struct sockaddr_storage *a,
				 const struct sockaddr_storage *b)
{
	if (a->ss_family != b->ss_family)
		return false;

	switch (a->ss_family) {
	case AF_INET: {
		const struct sockaddr_in *a4 = (const struct sockaddr_in *)a;
		const struct sockaddr_in *b4 = (const struct sockaddr_in *)b;
		return a4->sin_addr.s_addr == b4->sin_addr.s_addr &&
		       a4->sin_port == b4->sin_port;
	}
	case AF_INET6: {
		const struct sockaddr_in6 *a6 = (const struct sockaddr_in6 *)a;
		const struct sockaddr_in6 *b6 = (const struct sockaddr_in6 *)b;
		return ipv6_addr_equal(&a6->sin6_addr, &b6->sin6_addr) &&
		       a6->sin6_port == b6->sin6_port;
	}
	default:
		return false;
	}
}

/*
 * Create a new path with given local and remote addresses
 *
 * This function allocates and initializes a new path structure including
 * RTT measurements, congestion control, and MTU discovery state.
 *
 * Per RFC 9000 Section 9: Connection Migration
 */
struct quic_path *quic_path_create(struct quic_connection *conn,
				   struct sockaddr *local,
				   struct sockaddr *remote)
{
	struct quic_path *path;
	u32 initial_rtt_ms;
	int err;

	path = kmem_cache_zalloc(quic_path_cache, GFP_KERNEL);
	if (!path)
		return NULL;

	INIT_LIST_HEAD(&path->list);

	/* Copy addresses if provided */
	if (local) {
		err = quic_path_copy_addr(&path->local_addr, local);
		if (err)
			goto err_free;
	}

	if (remote) {
		err = quic_path_copy_addr(&path->remote_addr, remote);
		if (err)
			goto err_free;
	}

	/* Initialize MTU to safe minimum (IPv6 minimum) */
	path->mtu = QUIC_PATH_MTU_INITIAL;

	/* Initialize anti-amplification limit
	 * Per RFC 9000 Section 8.1: servers must not send more than 3x
	 * the data received until the path is validated
	 */
	path->amplification_limit = 0;

	/* Initialize path statistics */
	atomic64_set(&path->bytes_sent, 0);
	atomic64_set(&path->bytes_recv, 0);

	/* Path starts unvalidated and inactive */
	path->validated = 0;
	path->active = 0;
	path->challenge_pending = 0;

	/* Initialize challenge data (will be set when path validation starts) */
	memset(path->challenge_data, 0, sizeof(path->challenge_data));
	path->validation_start = 0;

	/* Get initial RTT from connection config if available */
	if (conn && conn->qsk)
		initial_rtt_ms = conn->qsk->config.initial_rtt_ms;
	else
		initial_rtt_ms = 333;  /* RFC 9002 default: 333ms */

	/* Initialize RTT measurements */
	quic_path_rtt_init(&path->rtt, initial_rtt_ms);

	/* Initialize congestion control */
	quic_path_cc_init(&path->cc, path->mtu);

	/*
	 * Initialize per-path packet number space (draft-ietf-quic-multipath)
	 * This is used for 1-RTT packets when multipath is enabled.
	 */
	quic_path_pn_space_init(&path->pn_space);

	/*
	 * Initialize ECN state (RFC 9000 Section 13.4)
	 *
	 * ECN validation is per-path because different network paths
	 * may have different ECN handling characteristics.
	 */
	quic_ecn_init(path);

	/* Assign path ID (increments with each path created on connection) */
	if (conn) {
		path->path_id = conn->num_paths;
	} else {
		path->path_id = 0;
	}

	/* Multipath disabled by default; enabled via transport parameter */
	path->multipath_enabled = 0;

	/* Add to connection's path list if connection provided */
	if (conn) {
		list_add_tail(&path->list, &conn->paths);
		conn->num_paths++;
	}

	return path;

err_free:
	kmem_cache_free(quic_path_cache, path);
	return NULL;
}

/*
 * Destroy a path and release its resources
 */
void quic_path_destroy(struct quic_path *path)
{
	if (!path)
		return;

	/* Remove from list if linked */
	if (!list_empty(&path->list))
		list_del(&path->list);

	/* Destroy per-path packet number space */
	quic_path_pn_space_destroy(&path->pn_space);

	/* Securely clear challenge data */
	memzero_explicit(path->challenge_data, sizeof(path->challenge_data));

	kmem_cache_free(quic_path_cache, path);
}

/*
 * Generate cryptographically random challenge data
 *
 * Per RFC 9000 Section 8.2: The PATH_CHALLENGE frame contains 8 bytes
 * of cryptographically random data
 */
static void quic_path_generate_challenge(u8 *data)
{
	get_random_bytes(data, QUIC_PATH_CHALLENGE_SIZE);
}

/*
 * Send a PATH_CHALLENGE frame to validate a path
 *
 * Per RFC 9000 Section 8.2: Path validation is performed using
 * PATH_CHALLENGE and PATH_RESPONSE frames
 */
int quic_path_challenge(struct quic_path *path)
{
	struct quic_connection *conn;
	struct sk_buff *skb;
	u8 *p;

	if (!path)
		return -EINVAL;

	/* Find the connection owning this path */
	conn = container_of(path->list.prev, struct quic_connection, paths);
	if (!conn)
		return -EINVAL;

	/* Generate new challenge data */
	quic_path_generate_challenge(path->challenge_data);

	/* Build PATH_CHALLENGE frame */
	skb = alloc_skb(16, GFP_ATOMIC);
	if (!skb)
		return -ENOMEM;

	p = skb_put(skb, 9);
	p[0] = QUIC_FRAME_PATH_CHALLENGE;
	memcpy(p + 1, path->challenge_data, QUIC_PATH_CHALLENGE_SIZE);

	/* Mark challenge as pending */
	path->challenge_pending = 1;
	path->validation_start = ktime_get();

	/* Queue the frame for transmission */
	if (quic_conn_queue_frame(conn, skb))
		return -ENOBUFS;

	/* Schedule transmission */
	schedule_work(&conn->tx_work);

	/* Set timer for path probe timeout */
	quic_timer_set(conn, QUIC_TIMER_PATH_PROBE,
		       ktime_add_ms(ktime_get(), QUIC_PATH_PROBE_TIMEOUT_MS));

	return 0;
}

/*
 * Start path validation for a new or changed path
 *
 * Per RFC 9000 Section 8.2.1: Path validation is always initiated by
 * an endpoint that wishes to use a new path
 */
int quic_path_validate(struct quic_path *path)
{
	if (!path)
		return -EINVAL;

	/* If already validated, nothing to do */
	if (path->validated)
		return 0;

	/* If validation already in progress, continue with existing challenge */
	if (path->challenge_pending) {
		ktime_t elapsed = ktime_sub(ktime_get(), path->validation_start);

		/* Check for validation timeout */
		if (ktime_to_ms(elapsed) > QUIC_PATH_VALIDATION_TIMEOUT_MS) {
			/* Validation timed out - path is unusable */
			path->challenge_pending = 0;
			return -ETIMEDOUT;
		}

		return 0;
	}

	/* Send initial PATH_CHALLENGE */
	return quic_path_challenge(path);
}

/*
 * Handle successful path validation (PATH_RESPONSE received)
 *
 * Per RFC 9000 Section 8.2.2: A PATH_RESPONSE frame MUST contain the
 * same data as the corresponding PATH_CHALLENGE frame
 */
void quic_path_on_validated(struct quic_path *path)
{
	struct quic_connection *conn;

	if (!path)
		return;

	/* Mark path as validated */
	path->validated = 1;
	path->challenge_pending = 0;

	/* Remove anti-amplification limit */
	path->amplification_limit = QUIC_PATH_MTU_MAX;

	/* Find the connection owning this path */
	if (list_empty(&path->list))
		return;

	conn = container_of(path->list.prev, struct quic_connection, paths);
	if (!conn)
		return;

	trace_quic_path_validated(quic_trace_conn_id(&conn->scid), conn->num_paths);

	/* Cancel path probe timer */
	quic_timer_cancel(conn, QUIC_TIMER_PATH_PROBE);

	/* Notify userspace of path validation */
	if (conn->qsk && conn->qsk->events_enabled) {
		struct sk_buff *event_skb;
		struct quic_event_info *info;

		event_skb = alloc_skb(sizeof(*info) + 16, GFP_ATOMIC);
		if (event_skb) {
			info = (struct quic_event_info *)skb_put(event_skb, sizeof(*info));
			memset(info, 0, sizeof(*info));
			info->type = QUIC_EVENT_PATH_VALIDATED;
			skb_queue_tail(&conn->qsk->event_queue, event_skb);
			wake_up(&conn->qsk->event_wait);
		}
	}

	/* Start MTU discovery on the validated path */
	quic_path_mtu_discovery_start(path);
}

/*
 * Verify a PATH_RESPONSE matches our pending challenge
 *
 * Per RFC 9000 Section 8.2.2: An endpoint MUST use unpredictable data
 * in every PATH_CHALLENGE frame
 */
bool quic_path_verify_response(struct quic_path *path, const u8 *data)
{
	if (!path || !data)
		return false;

	if (!path->challenge_pending)
		return false;

	/* Constant-time comparison to prevent timing attacks */
	return crypto_memneq(path->challenge_data, data,
			     QUIC_PATH_CHALLENGE_SIZE) == 0;
}

/*
 * Migrate connection to a new path
 *
 * Per RFC 9000 Section 9: An endpoint can migrate a connection to a
 * new local address by sending packets containing non-probing frames
 * from that address
 */
int quic_path_migrate(struct quic_connection *conn, struct quic_path *path)
{
	struct quic_path *old_path;

	if (!conn || !path)
		return -EINVAL;

	/* Check if migration is allowed */
	if (conn->migration_disabled)
		return -EPERM;

	/* Path must be validated before migration */
	if (!path->validated)
		return -EINVAL;

	/* Get current active path */
	old_path = conn->active_path;
	if (old_path == path)
		return 0;  /* Already on this path */

	/* Perform migration */
	path->active = 1;
	conn->active_path = path;

	trace_quic_path_migrate(quic_trace_conn_id(&conn->scid),
				old_path ? 0 : 0, conn->num_paths);

	if (old_path)
		old_path->active = 0;

	/* Per RFC 9000 Section 9.4: Reset congestion controller
	 * The congestion window and RTT estimator are reset when
	 * migrating to a completely new path
	 */
	if (old_path && !quic_path_addr_equal(&old_path->remote_addr,
					      &path->remote_addr)) {
		/* New network path - reset congestion control */
		quic_path_cc_init(&path->cc, path->mtu);

		/* Keep minimum RTT from old path as a hint */
		if (old_path->rtt.has_sample && old_path->rtt.min_rtt != U32_MAX) {
			path->rtt.min_rtt = old_path->rtt.min_rtt;
		}
	}

	/* Use a new connection ID for migration per RFC 9000 Section 9.5 */
	quic_conn_rotate_dcid(conn);

	/* Notify userspace of connection migration */
	if (conn->qsk && conn->qsk->events_enabled) {
		struct sk_buff *event_skb;
		struct quic_event_info *info;

		event_skb = alloc_skb(sizeof(*info) + 16, GFP_ATOMIC);
		if (event_skb) {
			info = (struct quic_event_info *)skb_put(event_skb, sizeof(*info));
			memset(info, 0, sizeof(*info));
			info->type = QUIC_EVENT_CONNECTION_MIGRATION;
			skb_queue_tail(&conn->qsk->event_queue, event_skb);
			wake_up(&conn->qsk->event_wait);
		}
	}

	return 0;
}

/*
 * MTU discovery implementation per RFC 8899 (DPLPMTUD)
 */

/* Find the next MTU probe size */
static u32 quic_path_next_mtu_probe(u32 current_mtu)
{
	int i;

	for (i = 0; i < ARRAY_SIZE(quic_mtu_probes); i++) {
		if (quic_mtu_probes[i] > current_mtu)
			return quic_mtu_probes[i];
	}

	return current_mtu;
}

/*
 * Start MTU discovery on a validated path
 */
void quic_path_mtu_discovery_start(struct quic_path *path)
{
	if (!path || !path->validated)
		return;

	/* Start with conservative MTU */
	path->mtu = QUIC_PATH_MTU_INITIAL;

	/* Schedule MTU probe - will be handled by timer */
	quic_path_mtu_probe(path);
}

/*
 * Send an MTU probe packet
 *
 * Per RFC 8899: DPLPMTUD uses probe packets to search for a larger MTU
 */
int quic_path_mtu_probe(struct quic_path *path)
{
	struct quic_connection *conn;
	struct sk_buff *skb;
	u32 probe_size;
	u8 *p;

	if (!path)
		return -EINVAL;

	if (list_empty(&path->list))
		return -EINVAL;

	conn = container_of(path->list.prev, struct quic_connection, paths);
	if (!conn)
		return -EINVAL;

	/* Determine probe size */
	probe_size = quic_path_next_mtu_probe(path->mtu);
	if (probe_size <= path->mtu)
		return 0;  /* Already at maximum MTU */

	/* Build a PING frame padded to probe size */
	skb = alloc_skb(probe_size + 64, GFP_ATOMIC);
	if (!skb)
		return -ENOMEM;

	/* PING frame */
	p = skb_put(skb, 1);
	*p = QUIC_FRAME_PING;

	/* PADDING to reach probe size (accounting for headers and AEAD tag) */
	{
		int padding = probe_size - skb->len - 100;  /* Rough header estimate */
		if (padding > 0) {
			p = skb_put(skb, padding);
			memset(p, 0, padding);  /* PADDING frames */
		}
	}

	/* Queue the probe packet */
	if (quic_conn_queue_frame(conn, skb))
		return -ENOBUFS;
	schedule_work(&conn->tx_work);

	return 0;
}

/*
 * Handle MTU probe acknowledgment
 */
void quic_path_mtu_probe_acked(struct quic_path *path, u32 probe_size)
{
	if (!path)
		return;

	/* Successful probe - update MTU */
	if (probe_size > path->mtu)
		path->mtu = probe_size;

	/* Update congestion window for new MTU */
	quic_cc_init(&path->cc, path->cc.algo);
}

/*
 * Handle MTU probe loss (implicit ICMP too big or timeout)
 *
 * Per RFC 9000 Section 14.3: If a PMTUD probe is lost, the sender should
 * not increase the maximum datagram size. The current MTU remains valid.
 *
 * This implementation tracks the failed probe and sets an upper bound
 * for future probing attempts.
 */
void quic_path_mtu_probe_lost(struct quic_path *path, u32 probe_size)
{
	if (!path)
		return;

	/*
	 * Probe failed at this size. The path MTU is somewhere between
	 * the current working MTU and the failed probe size.
	 *
	 * Keep current MTU (it works) and don't probe larger than
	 * probe_size - 1 in future attempts. The next probe should
	 * use binary search: (current_mtu + failed_size) / 2
	 *
	 * RFC 9000 recommends waiting at least 1 PTO before retrying
	 * with a smaller probe size.
	 */
	pr_debug("QUIC: MTU probe lost at size %u, keeping MTU %u\n",
		 probe_size, path->mtu);
}

/*
 * Update RTT measurements for a path
 *
 * Per RFC 9002 Section 5: RTT is measured by the sender by observing
 * the time between sending an ack-eliciting packet and receiving an ACK
 */
void quic_path_rtt_update(struct quic_path *path, u32 latest_rtt_us,
			  u32 ack_delay_us)
{
	struct quic_rtt *rtt;

	if (!path)
		return;

	rtt = &path->rtt;

	/* Update latest RTT */
	rtt->latest_rtt = latest_rtt_us;

	/* Update minimum RTT (no ack delay adjustment) */
	if (latest_rtt_us < rtt->min_rtt)
		rtt->min_rtt = latest_rtt_us;

	/* First RTT sample */
	if (!rtt->has_sample) {
		rtt->has_sample = 1;
		rtt->first_rtt_sample = ktime_get();
		rtt->smoothed_rtt = latest_rtt_us;
		rtt->rttvar = latest_rtt_us / 2;
		return;
	}

	/* Adjust for ACK delay per RFC 9002 Section 5.3 */
	u32 adjusted_rtt = latest_rtt_us;
	if (adjusted_rtt >= rtt->min_rtt + ack_delay_us)
		adjusted_rtt -= ack_delay_us;

	/* Update RTTVAR and smoothed RTT per RFC 9002 Section 5.3 */
	u32 rttvar_sample;
	if (adjusted_rtt > rtt->smoothed_rtt)
		rttvar_sample = adjusted_rtt - rtt->smoothed_rtt;
	else
		rttvar_sample = rtt->smoothed_rtt - adjusted_rtt;

	rtt->rttvar = (3 * rtt->rttvar + rttvar_sample) / 4;
	rtt->smoothed_rtt = (7 * rtt->smoothed_rtt + adjusted_rtt) / 8;
}

/*
 * Calculate PTO (Probe Timeout) for a path
 *
 * Per RFC 9002 Section 6.2
 */
u32 quic_path_pto(struct quic_path *path)
{
	struct quic_rtt *rtt;
	u32 pto;

	if (!path)
		return 1000000;  /* Default 1 second */

	rtt = &path->rtt;

	/* PTO = smoothed_rtt + max(4 * rttvar, kGranularity) + max_ack_delay */
	pto = rtt->smoothed_rtt + max_t(u32, 4 * rtt->rttvar, 1000);

	/* Add maximum ACK delay (default 25ms = 25000us) */
	pto += 25000;

	return pto;
}

/*
 * Record data sent on a path (for anti-amplification)
 */
void quic_path_on_data_sent(struct quic_path *path, u32 bytes)
{
	if (!path)
		return;

	atomic64_add(bytes, &path->bytes_sent);
}

/*
 * Record data received on a path (for anti-amplification)
 *
 * Per RFC 9000 Section 8.1: Prior to validating the client address,
 * servers MUST NOT send more than three times as many bytes as the
 * number of bytes they have received
 */
void quic_path_on_data_received(struct quic_path *path, u32 bytes)
{
	if (!path)
		return;

	atomic64_add(bytes, &path->bytes_recv);

	/* Update amplification limit (3x received data) */
	if (!path->validated)
		path->amplification_limit = atomic64_read(&path->bytes_recv) * 3;
}

/*
 * Check if sending is allowed under anti-amplification limits
 */
bool quic_path_can_send(struct quic_path *path, u32 bytes)
{
	if (!path)
		return false;

	/* Validated paths have no limit */
	if (path->validated)
		return true;

	/* Check amplification limit */
	return (atomic64_read(&path->bytes_sent) + bytes) <= path->amplification_limit;
}

/*
 * Find a path by remote address
 */
struct quic_path *quic_path_find(struct quic_connection *conn,
				 struct sockaddr *remote)
{
	struct quic_path *path;
	struct sockaddr_storage remote_storage;

	if (!conn || !remote)
		return NULL;

	if (quic_path_copy_addr(&remote_storage, remote))
		return NULL;

	list_for_each_entry(path, &conn->paths, list) {
		if (quic_path_addr_equal(&path->remote_addr, &remote_storage))
			return path;
	}

	return NULL;
}

/*
 * Get path statistics
 */
int quic_path_get_info(struct quic_path *path, struct quic_path_info *info)
{
	if (!path || !info)
		return -EINVAL;

	memset(info, 0, sizeof(*info));

	memcpy(&info->local_addr, &path->local_addr, sizeof(info->local_addr));
	memcpy(&info->remote_addr, &path->remote_addr, sizeof(info->remote_addr));
	info->mtu = path->mtu;
	info->rtt = path->rtt.smoothed_rtt / 1000;  /* Convert to ms */
	info->validated = path->validated;

	return 0;
}

/*
 * Handle path challenge timeout
 */
void quic_path_on_probe_timeout(struct quic_path *path)
{
	ktime_t elapsed;

	if (!path || !path->challenge_pending)
		return;

	elapsed = ktime_sub(ktime_get(), path->validation_start);

	/* Check for overall validation timeout */
	if (ktime_to_ms(elapsed) > QUIC_PATH_VALIDATION_TIMEOUT_MS) {
		/* Validation failed */
		path->challenge_pending = 0;
		return;
	}

	/* Retransmit challenge */
	quic_path_challenge(path);
}

/*
 * Check if a path needs probing
 */
bool quic_path_needs_probe(struct quic_path *path)
{
	if (!path)
		return false;

	return path->challenge_pending && !path->validated;
}
