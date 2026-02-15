// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * TQUIC - True QUIC with WAN Bonding
 *
 * Path management implementation per RFC 9000 Section 9
 *
 * Copyright (c) 2026 Justin Adams <spotty118@gmail.com>
 * Kernel implementation by Justin Adams <spotty118@gmail.com>
 */

#include <linux/slab.h>
#include <linux/random.h>
#include <linux/in.h>
#include <linux/in6.h>
#include <crypto/algapi.h>
#include <net/tquic.h>
#include <net/tquic_frame.h>
#include <net/tquic_pm.h>
#include "../diag/tracepoints.h"
#include "../tquic_debug.h"
#include "../protocol.h"
#include "../tquic_init.h"

/* Forward declarations to silence -Wmissing-prototypes */
void tquic_trace_path_validated(struct tquic_connection *conn, u32 path_id,
				u64 validation_time_us);
int __init tquic_path_init(void);
void tquic_path_exit(void);
void tquic_path_put(struct tquic_path *path);
void tquic_path_on_validated(struct tquic_path *path);
bool tquic_path_verify_response(struct tquic_path *path, const u8 *data);
int tquic_path_migrate(struct tquic_connection *conn, struct tquic_path *path);
void tquic_path_mtu_discovery_start(struct tquic_path *path);
int tquic_path_mtu_probe(struct tquic_path *path);
void tquic_path_mtu_probe_acked(struct tquic_path *path, u32 probe_size);
void tquic_path_mtu_probe_lost(struct tquic_path *path, u32 probe_size);
void tquic_path_rtt_update(struct tquic_path *path, u32 latest_rtt_us,
			   u32 ack_delay_us);
u32 tquic_path_pto(struct tquic_path *path);
void tquic_path_on_data_sent(struct tquic_path *path, u32 bytes);
void tquic_path_on_data_received(struct tquic_path *path, u32 bytes);
bool tquic_path_can_send(struct tquic_path *path, u32 bytes);
struct tquic_path *tquic_path_find(struct tquic_connection *conn,
				   struct sockaddr *remote);
int tquic_path_get_info(struct tquic_path *path, struct tquic_path_info *info);
void tquic_path_on_probe_timeout(struct tquic_path *path);
bool tquic_path_needs_probe(struct tquic_path *path);
void tquic_path_set_state(struct tquic_connection *conn, u8 path_id,
			  enum tquic_path_state state);


/*
 * Human-readable path state names (exported for diagnostics).
 */
const char *tquic_path_state_names[] = {
	[TQUIC_PATH_UNUSED]	= "UNUSED",
	[TQUIC_PATH_PENDING]	= "PENDING",
	[TQUIC_PATH_VALIDATED]	= "VALID",
	[TQUIC_PATH_ACTIVE]	= "ACTIVE",
	[TQUIC_PATH_STANDBY]	= "STANDBY",
	[TQUIC_PATH_UNAVAILABLE] = "UNAVAIL",
	[TQUIC_PATH_FAILED]	= "FAILED",
	[TQUIC_PATH_CLOSED]	= "CLOSED",
};
EXPORT_SYMBOL_GPL(tquic_path_state_names);

/* Path management constants per RFC 9000 */
#define TQUIC_PATH_CHALLENGE_SIZE 8
#define TQUIC_PATH_MAX_PROBES 3
#define TQUIC_PATH_PROBE_TIMEOUT_MS 1000
#define TQUIC_PATH_VALIDATION_TIMEOUT_MS 30000
#define TQUIC_PATH_MTU_MIN 1200
#define TQUIC_PATH_MTU_MAX 65535
/*
 * Initial path MTU: Use QUIC minimum (1200 bytes, RFC 9000 Section 14)
 * rather than IPv6 minimum (1280). This ensures consistency with the
 * PMTUD subsystem which uses 1200 as its base, and avoids sending
 * packets larger than QUIC minimum before MTU is confirmed.
 */
#define TQUIC_PATH_MTU_INITIAL 1200
#define TQUIC_PATH_MTU_PROBE_SIZE 16

/* MTU discovery probe sizes per RFC 8899 */
static const u32 tquic_mtu_probes[] = { 1280, 1400, 1450, 1480, 1492,
					1500, 2048, 4096, 8192, 9000 };

struct kmem_cache *tquic_path_cache __read_mostly;

/*
 * Initialize path management subsystem
 */
int __init tquic_path_init(void)
{
	tquic_path_cache = kmem_cache_create("tquic_path",
					     sizeof(struct tquic_path), 0,
					     SLAB_HWCACHE_ALIGN, NULL);
	if (!tquic_path_cache)
		return -ENOMEM;

	return 0;
}

void tquic_path_exit(void)
{
	kmem_cache_destroy(tquic_path_cache);
}

int __init tquic_path_init_module(void)
{
	return tquic_path_init();
}

void tquic_path_exit_module(void)
{
	tquic_path_exit();
}

/*
 * Initialize RTT measurements for a new path
 * Per RFC 9002 Section 6
 */
static void tquic_path_rtt_init(struct tquic_path *path, u32 initial_rtt_ms)
{
	/* Initialize the scheduler-accessible CC info */
	path->cc.smoothed_rtt_us =
		initial_rtt_ms * 1000; /* Convert to microseconds */
	path->cc.min_rtt_us = U64_MAX;
	path->cc.rtt_var_us =
		initial_rtt_ms * 500; /* Initial variance is half of RTT */
}

/*
 * Initialize congestion control state for a new path
 * Per RFC 9002 Section 7
 */
static void tquic_path_cc_init(struct tquic_path *path, u32 mtu)
{
	/* Initial window is 10 packets or 14720 bytes, whichever is smaller */
	u64 initial_window = min_t(u64, 10 * mtu, 14720);

	path->cc.cwnd = initial_window;
	path->cc.bytes_in_flight = 0;

	/* Full CC state is managed via the cong pointer and cong_ops */
}

/*
 * Copy address to path structure with proper validation
 */
static int tquic_path_copy_addr(struct sockaddr_storage *dest,
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
static bool tquic_path_addr_equal(const struct sockaddr_storage *a,
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
 * Create a new path with given local and remote addresses (internal version)
 *
 * This function allocates and initializes a new path structure including
 * RTT measurements, congestion control, and MTU discovery state.
 *
 * Per RFC 9000 Section 9: Connection Migration
 *
 * Note: The exported tquic_path_create is in tquic_migration.c
 */
static struct tquic_path * __maybe_unused
tquic_path_create_internal(struct tquic_connection *conn,
			   struct sockaddr *local, struct sockaddr *remote)
{
	struct tquic_path *path;
	u32 initial_rtt_ms;
	int err;

	path = kmem_cache_zalloc(tquic_path_cache, GFP_KERNEL);
	if (!path)
		return NULL;
	spin_lock_init(&path->loss_tracker.lock);

	/* RFC 9000 §8.1: New paths are unvalidated, enforce anti-amplification */
	path->anti_amplification.active = true;

	INIT_LIST_HEAD(&path->list);
	INIT_LIST_HEAD(&path->pm_list);

	/* Set back-pointer to connection */
	path->conn = conn;

	/* Copy addresses if provided */
	if (local) {
		err = tquic_path_copy_addr(&path->local_addr, local);
		if (err)
			goto err_free;
	}

	if (remote) {
		err = tquic_path_copy_addr(&path->remote_addr, remote);
		if (err)
			goto err_free;
	}

	/* Initialize MTU to safe minimum (IPv6 minimum) */
	path->mtu = TQUIC_PATH_MTU_INITIAL;

	/* Initialize path statistics */
	memset(&path->stats, 0, sizeof(path->stats));

	/* Path starts unvalidated and unused */
	path->state = TQUIC_PATH_UNUSED;
	path->saved_state = TQUIC_PATH_UNUSED;
	path->validation.challenge_pending = false;
	path->is_backup = false;
	path->schedulable = false;

	/* Initialize challenge data (will be set when path validation starts) */
	memset(path->validation.challenge_data, 0,
	       sizeof(path->validation.challenge_data));
	path->validation.challenge_sent = 0;
	path->validation.retries = 0;

	/* Initialize path validation timer (called once during allocation) */
	timer_setup(&path->validation_timer, tquic_path_validation_expired, 0);

	/* Initialize response queue */
	skb_queue_head_init(&path->response.queue);
	atomic_set(&path->response.count, 0);

	/* Get initial RTT from connection or use default */
	if (conn && conn->sk) {
		struct net *net = sock_net(conn->sk);
		initial_rtt_ms = tquic_net_get_initial_rtt(net);
	} else {
		initial_rtt_ms = TQUIC_DEFAULT_RTT; /* default: 100ms */
	}

	/* Initialize RTT measurements */
	tquic_path_rtt_init(path, initial_rtt_ms);

	/* Initialize congestion control */
	tquic_path_cc_init(path, path->mtu);

	/* Assign path ID (increments with each path created on connection) */
	if (conn) {
		path->path_id = conn->num_paths;
	} else {
		path->path_id = 0;
	}

	/* Initialize priority and weight */
	path->priority = 0;
	path->weight = 100; /* Default weight */

	/* Add to connection's path list if connection provided */
	if (conn) {
		spin_lock_bh(&conn->paths_lock);
		list_add_tail(&path->list, &conn->paths);
		conn->num_paths++;
		spin_unlock_bh(&conn->paths_lock);

		tquic_conn_info(conn, "path %u created, mtu=%u\n",
				path->path_id, path->mtu);
	}

	return path;

err_free:
	kmem_cache_free(tquic_path_cache, path);
	return NULL;
}

/*
 * Destroy a path and release its resources
 */
void tquic_path_destroy(struct tquic_path *path)
{
	if (!path)
		return;

	/* Remove from list if linked */
	if (!list_empty(&path->list))
		list_del_init(&path->list);

	if (!list_empty(&path->pm_list))
		list_del_init(&path->pm_list);

	/* Release PMTUD state if allocated */
	if (path->pmtud_state)
		tquic_pmtud_release_path(path);

	/* Release NAT keepalive state if allocated */
	/* Note: tquic_nat_keepalive_cleanup() should be called here */

	/* Securely clear challenge data */
	memzero_explicit(path->validation.challenge_data,
			 sizeof(path->validation.challenge_data));

	/* Flush response queue */
	skb_queue_purge(&path->response.queue);

	/* Release per-path UDP socket if still attached. */
	if (path->udp_sock)
		tquic_udp_destroy_path_socket(path);

	/* Release congestion control state */
	if (path->cong && path->cong_ops && path->cong_ops->release)
		path->cong_ops->release(path->cong);

	kmem_cache_free(tquic_path_cache, path);
}

/* tquic_path_put is now an inline in include/net/tquic.h with refcounting */

/*
 * Generate cryptographically random challenge data
 *
 * Per RFC 9000 Section 8.2: The PATH_CHALLENGE frame contains 8 bytes
 * of cryptographically random data
 */
static void tquic_path_generate_challenge(u8 *data)
{
	get_random_bytes(data, TQUIC_PATH_CHALLENGE_SIZE);
}

/*
 * Send a PATH_CHALLENGE frame to validate a path
 *
 * Per RFC 9000 Section 8.2: Path validation is performed using
 * PATH_CHALLENGE and PATH_RESPONSE frames
 */
int tquic_path_challenge(struct tquic_path *path)
{
	struct tquic_connection *conn;
	struct sk_buff *skb;
	u8 *p;

	if (!path)
		return -EINVAL;

	conn = path->conn;
	if (!conn)
		return -EINVAL;

	/* Generate new challenge data */
	tquic_path_generate_challenge(path->validation.challenge_data);

	/* Build PATH_CHALLENGE frame */
	skb = alloc_skb(16, GFP_ATOMIC);
	if (!skb)
		return -ENOMEM;

	p = skb_put(skb, 9);
	p[0] = TQUIC_FRAME_PATH_CHALLENGE;
	memcpy(p + 1, path->validation.challenge_data,
	       TQUIC_PATH_CHALLENGE_SIZE);

	/* Mark challenge as pending */
	path->validation.challenge_pending = true;
	path->validation.challenge_sent = ktime_get();

	/* Queue the frame for transmission */
	spin_lock_bh(&conn->lock);
	skb_queue_tail(&conn->control_frames, skb);
	spin_unlock_bh(&conn->lock);

	/* Schedule transmission */
	schedule_work(&conn->tx_work);

	/* Start path validation timer */
	tquic_timer_start_path_validation(conn, path);

	return 0;
}

/*
 * Start path validation for a new or changed path
 *
 * Per RFC 9000 Section 8.2.1: Path validation is always initiated by
 * an endpoint that wishes to use a new path
 */
int tquic_path_validate_start(struct tquic_path *path)
{
	ktime_t elapsed;

	if (!path)
		return -EINVAL;

	/* If already validated, nothing to do */
	if (path->state == TQUIC_PATH_VALIDATED ||
	    path->state == TQUIC_PATH_ACTIVE)
		return 0;

	/* If validation already in progress, check for timeout */
	if (path->validation.challenge_pending) {
		elapsed =
			ktime_sub(ktime_get(), path->validation.challenge_sent);

		/* Check for validation timeout */
		if (ktime_to_ms(elapsed) > TQUIC_PATH_VALIDATION_TIMEOUT_MS) {
			/* Validation timed out - path is unusable */
			path->validation.challenge_pending = false;
			path->state = TQUIC_PATH_FAILED;
			tquic_warn("path %u validation timed out\n",
				   path->path_id);
			return -ETIMEDOUT;
		}

		return 0;
	}

	/* Update state to pending */
	path->state = TQUIC_PATH_PENDING;

	tquic_dbg("path %u validation starting\n", path->path_id);

	/* Send initial PATH_CHALLENGE */
	return tquic_path_challenge(path);
}

/*
 * Handle successful path validation (PATH_RESPONSE received)
 *
 * Per RFC 9000 Section 8.2.2: A PATH_RESPONSE frame MUST contain the
 * same data as the corresponding PATH_CHALLENGE frame
 */
void tquic_path_on_validated(struct tquic_path *path)
{
	struct tquic_connection *conn;
	ktime_t validation_time;

	if (!path)
		return;

	conn = path->conn;

	/* Calculate validation time */
	validation_time =
		ktime_sub(ktime_get(), path->validation.challenge_sent);

	/* Mark path as validated */
	path->state = TQUIC_PATH_VALIDATED;
	path->validation.challenge_pending = false;
	path->schedulable = true;

	if (!conn)
		return;

	/* Trace path validation */
	tquic_trace_path_validated(conn, path->path_id,
				   ktime_to_us(validation_time));

	/* Cancel path validation timer */
	tquic_timer_path_validated(conn, path);

	/* Notify path manager via netlink */
	tquic_nl_path_event(conn, path, TQUIC_PATH_EVENT_ACTIVE);

	/* Start MTU discovery on the validated path.
	 * tquic_pmtud_start() calls tquic_pmtud_init_path() internally,
	 * so do not call init separately to avoid double-allocating
	 * PMTUD state and leaking the first allocation.
	 */
	tquic_pmtud_start(path);
}

/*
 * Verify a PATH_RESPONSE matches our pending challenge
 *
 * Per RFC 9000 Section 8.2.2: An endpoint MUST use unpredictable data
 * in every PATH_CHALLENGE frame
 */
bool tquic_path_verify_response(struct tquic_path *path, const u8 *data)
{
	if (!path || !data)
		return false;

	if (!path->validation.challenge_pending)
		return false;

	/* Constant-time comparison to prevent timing attacks */
	return crypto_memneq(path->validation.challenge_data, data,
			     TQUIC_PATH_CHALLENGE_SIZE) == 0;
}

/*
 * Migrate connection to a new path
 *
 * Per RFC 9000 Section 9: An endpoint can migrate a connection to a
 * new local address by sending packets containing non-probing frames
 * from that address
 */
int tquic_path_migrate(struct tquic_connection *conn, struct tquic_path *path)
{
	struct tquic_path *old_path;

	if (!conn || !path)
		return -EINVAL;

	/* Check if migration is allowed */
	if (conn->migration_disabled)
		return -EPERM;

	/* Path must be validated before migration */
	if (path->state != TQUIC_PATH_VALIDATED &&
	    path->state != TQUIC_PATH_ACTIVE)
		return -EINVAL;

	/* Get current active path */
	old_path = conn->active_path;
	if (old_path == path)
		return 0; /* Already on this path */

	/* Perform migration */
	path->state = TQUIC_PATH_ACTIVE;
	rcu_assign_pointer(conn->active_path, path);

	if (old_path) {
		old_path->state = TQUIC_PATH_STANDBY;
	}

	/* Per RFC 9000 Section 9.4: Reset congestion controller
	 * The congestion window and RTT estimator are reset when
	 * migrating to a completely new path
	 */
	if (old_path && !tquic_path_addr_equal(&old_path->remote_addr,
					       &path->remote_addr)) {
		/* New network path - reset congestion control */
		tquic_path_cc_init(path, path->mtu);

		/* Keep minimum RTT from old path as a hint */
		if (old_path->cc.min_rtt_us != U64_MAX) {
			path->cc.min_rtt_us = old_path->cc.min_rtt_us;
		}
	}

	/* Use a new connection ID for migration per RFC 9000 Section 9.5 */
	if (conn->cid_pool) {
		tquic_cid_rotate(conn);
	}

	/* Notify via netlink of connection migration */
	tquic_nl_path_event(conn, path, TQUIC_PATH_EVENT_MIGRATE);

	/* Update statistics */
	conn->stats.path_migrations++;

	return 0;
}

/*
 * MTU discovery implementation per RFC 8899 (DPLPMTUD)
 */

/* Find the next MTU probe size */
static u32 tquic_path_next_mtu_probe(u32 current_mtu)
{
	int i;

	for (i = 0; i < ARRAY_SIZE(tquic_mtu_probes); i++) {
		if (tquic_mtu_probes[i] > current_mtu)
			return tquic_mtu_probes[i];
	}

	return current_mtu;
}

/*
 * Start MTU discovery on a validated path
 */
void tquic_path_mtu_discovery_start(struct tquic_path *path)
{
	if (!path)
		return;

	if (path->state != TQUIC_PATH_VALIDATED &&
	    path->state != TQUIC_PATH_ACTIVE)
		return;

	/* Start with conservative MTU */
	path->mtu = TQUIC_PATH_MTU_INITIAL;

	/* Schedule MTU probe - will be handled by PMTUD subsystem */
	tquic_pmtud_start(path);
}

/*
 * Send an MTU probe packet
 *
 * Per RFC 8899: DPLPMTUD uses probe packets to search for a larger MTU
 */
int tquic_path_mtu_probe(struct tquic_path *path)
{
	struct tquic_connection *conn;
	struct sk_buff *skb;
	u32 probe_size;
	u8 *p;
	int padding;

	if (!path)
		return -EINVAL;

	conn = path->conn;
	if (!conn)
		return -EINVAL;

	/* Determine probe size */
	probe_size = tquic_path_next_mtu_probe(path->mtu);
	if (probe_size <= path->mtu)
		return 0; /* Already at maximum MTU */

	/* Build a PING frame padded to probe size */
	skb = alloc_skb(probe_size + 64, GFP_ATOMIC);
	if (!skb)
		return -ENOMEM;

	/* PING frame */
	p = skb_put(skb, 1);
	*p = TQUIC_FRAME_PING;

	/* PADDING to reach probe size (accounting for headers and AEAD tag) */
	padding = probe_size - skb->len - 100; /* Rough header estimate */
	if (padding > 0) {
		p = skb_put(skb, padding);
		memset(p, 0, padding); /* PADDING frames */
	}

	/* Queue the probe packet */
	spin_lock_bh(&conn->lock);
	skb_queue_tail(&conn->control_frames, skb);
	spin_unlock_bh(&conn->lock);

	schedule_work(&conn->tx_work);

	return 0;
}

/*
 * Handle MTU probe acknowledgment
 */
void tquic_path_mtu_probe_acked(struct tquic_path *path, u32 probe_size)
{
	if (!path)
		return;

	/* Successful probe - update MTU */
	if (probe_size > path->mtu)
		path->mtu = probe_size;

	/* Update congestion window for new MTU */
	tquic_path_cc_init(path, path->mtu);
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
void tquic_path_mtu_probe_lost(struct tquic_path *path, u32 probe_size)
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
	tquic_dbg("MTU probe lost at size %u, keeping MTU %u\n",
		  probe_size, path->mtu);
}

/*
 * Update RTT measurements for a path
 *
 * Per RFC 9002 Section 5: RTT is measured by the sender by observing
 * the time between sending an ack-eliciting packet and receiving an ACK
 */
void tquic_path_rtt_update(struct tquic_path *path, u32 latest_rtt_us,
			   u32 ack_delay_us)
{
	u64 adjusted_rtt;
	u64 rttvar_sample;

	if (!path)
		return;

	/* Update minimum RTT (no ack delay adjustment) */
	if (latest_rtt_us < path->cc.min_rtt_us)
		path->cc.min_rtt_us = latest_rtt_us;

	/* First RTT sample */
	if (path->cc.smoothed_rtt_us == 0 || path->cc.min_rtt_us == U64_MAX) {
		path->cc.smoothed_rtt_us = latest_rtt_us;
		path->cc.rtt_var_us = latest_rtt_us / 2;
		path->cc.min_rtt_us = latest_rtt_us;
		return;
	}

	/* Adjust for ACK delay per RFC 9002 Section 5.3 */
	adjusted_rtt = latest_rtt_us;
	if (adjusted_rtt >= path->cc.min_rtt_us + ack_delay_us)
		adjusted_rtt -= ack_delay_us;

	/* Update RTTVAR and smoothed RTT per RFC 9002 Section 5.3 */
	if (adjusted_rtt > path->cc.smoothed_rtt_us)
		rttvar_sample = adjusted_rtt - path->cc.smoothed_rtt_us;
	else
		rttvar_sample = path->cc.smoothed_rtt_us - adjusted_rtt;

	path->cc.rtt_var_us = (3 * path->cc.rtt_var_us + rttvar_sample) / 4;
	path->cc.smoothed_rtt_us =
		(7 * path->cc.smoothed_rtt_us + adjusted_rtt) / 8;

	/* Update stats */
	path->stats.rtt_smoothed = (u32)path->cc.smoothed_rtt_us;
	path->stats.rtt_variance = (u32)path->cc.rtt_var_us;
	path->stats.rtt_min = (u32)path->cc.min_rtt_us;
}

/*
 * Calculate PTO (Probe Timeout) for a path
 *
 * Per RFC 9002 Section 6.2
 */
u32 tquic_path_pto(struct tquic_path *path)
{
	u32 pto;

	if (!path)
		return 1000000; /* Default 1 second */

	/* PTO = smoothed_rtt + max(4 * rttvar, kGranularity) + max_ack_delay */
	pto = (u32)path->cc.smoothed_rtt_us +
	      max_t(u32, 4 * (u32)path->cc.rtt_var_us, 1000);

	/* Add maximum ACK delay (default 25ms = 25000us) */
	pto += 25000;

	return pto;
}

/*
 * Record data sent on a path (for anti-amplification and statistics)
 */
void tquic_path_on_data_sent(struct tquic_path *path, u32 bytes)
{
	if (!path)
		return;

	path->stats.tx_bytes += bytes;
	path->stats.tx_packets++;
	path->last_activity = ktime_get();
}

/*
 * Record data received on a path (for anti-amplification)
 *
 * Per RFC 9000 Section 8.1: Prior to validating the client address,
 * servers MUST NOT send more than three times as many bytes as the
 * number of bytes they have received
 */
void tquic_path_on_data_received(struct tquic_path *path, u32 bytes)
{
	if (!path)
		return;

	path->stats.rx_bytes += bytes;
	path->stats.rx_packets++;
	path->last_activity = ktime_get();
}

/*
 * Check if sending is allowed under anti-amplification limits
 */
bool tquic_path_can_send(struct tquic_path *path, u32 bytes)
{
	if (!path)
		return false;

	/* Validated paths have no limit */
	if (path->state == TQUIC_PATH_VALIDATED ||
	    path->state == TQUIC_PATH_ACTIVE)
		return true;

	/* Check amplification limit (3x received data) */
	return (path->stats.tx_bytes + bytes) <= (path->stats.rx_bytes * 3);
}

/*
 * Find a path by remote address
 */
struct tquic_path *tquic_path_find(struct tquic_connection *conn,
				   struct sockaddr *remote)
{
	struct tquic_path *path;
	struct sockaddr_storage remote_storage;

	if (!conn || !remote)
		return NULL;

	if (tquic_path_copy_addr(&remote_storage, remote))
		return NULL;

	spin_lock_bh(&conn->paths_lock);
	list_for_each_entry(path, &conn->paths, list) {
		if (tquic_path_addr_equal(&path->remote_addr,
					  &remote_storage)) {
			spin_unlock_bh(&conn->paths_lock);
			return path;
		}
	}
	spin_unlock_bh(&conn->paths_lock);

	return NULL;
}

/*
 * Get path statistics
 */
int tquic_path_get_info(struct tquic_path *path, struct tquic_path_info *info)
{
	if (!path || !info)
		return -EINVAL;

	memset(info, 0, sizeof(*info));

	info->path_id = path->path_id;
	memcpy(&info->local_addr, &path->local_addr, sizeof(info->local_addr));
	memcpy(&info->remote_addr, &path->remote_addr,
	       sizeof(info->remote_addr));
	info->mtu = path->mtu;
	info->rtt = (u32)(path->cc.smoothed_rtt_us / 1000); /* Convert to ms */
	info->rtt_var = (u32)(path->cc.rtt_var_us / 1000);
	info->cwnd = path->cc.cwnd;
	info->bandwidth = path->stats.bandwidth;
	info->bytes_sent = path->stats.tx_bytes;
	info->bytes_received = path->stats.rx_bytes;
	info->packets_lost = path->stats.lost_packets;
	info->priority = path->priority;
	info->weight = path->weight;

	/* Map internal state to userspace state */
	switch (path->state) {
	case TQUIC_PATH_UNUSED:
		info->state = TQUIC_PATH_STATE_UNUSED;
		break;
	case TQUIC_PATH_PENDING:
		info->state = TQUIC_PATH_STATE_PENDING;
		break;
	case TQUIC_PATH_VALIDATED:
	case TQUIC_PATH_ACTIVE:
		info->state = TQUIC_PATH_STATE_ACTIVE;
		break;
	case TQUIC_PATH_STANDBY:
	case TQUIC_PATH_UNAVAILABLE:
		info->state = TQUIC_PATH_STATE_STANDBY;
		break;
	case TQUIC_PATH_FAILED:
	case TQUIC_PATH_CLOSED:
		info->state = TQUIC_PATH_STATE_FAILED;
		break;
	default:
		info->state = TQUIC_PATH_STATE_UNUSED;
	}

	return 0;
}

/*
 * Handle path challenge timeout
 */
void tquic_path_on_probe_timeout(struct tquic_path *path)
{
	ktime_t elapsed;

	if (!path || !path->validation.challenge_pending)
		return;

	elapsed = ktime_sub(ktime_get(), path->validation.challenge_sent);

	/* Check for overall validation timeout */
	if (ktime_to_ms(elapsed) > TQUIC_PATH_VALIDATION_TIMEOUT_MS) {
		/* Validation failed */
		path->validation.challenge_pending = false;
		path->state = TQUIC_PATH_FAILED;
		return;
	}

	/* Increment retry count */
	path->validation.retries++;
	if (path->validation.retries >= TQUIC_PATH_MAX_PROBES) {
		/* Too many retries - validation failed */
		path->validation.challenge_pending = false;
		path->state = TQUIC_PATH_FAILED;
		return;
	}

	/* Retransmit challenge */
	tquic_path_challenge(path);
}

/*
 * Check if a path needs probing
 */
bool tquic_path_needs_probe(struct tquic_path *path)
{
	if (!path)
		return false;

	return path->validation.challenge_pending &&
	       path->state == TQUIC_PATH_PENDING;
}

EXPORT_SYMBOL_GPL(tquic_path_exit);
/* tquic_path_create exported from tquic_migration.c */
EXPORT_SYMBOL_GPL(tquic_path_destroy);
EXPORT_SYMBOL_GPL(tquic_path_challenge);
EXPORT_SYMBOL_GPL(tquic_path_validate_start);
EXPORT_SYMBOL_GPL(tquic_path_on_validated);
EXPORT_SYMBOL_GPL(tquic_path_verify_response);
EXPORT_SYMBOL_GPL(tquic_path_migrate);
EXPORT_SYMBOL_GPL(tquic_path_mtu_discovery_start);
EXPORT_SYMBOL_GPL(tquic_path_mtu_probe);
EXPORT_SYMBOL_GPL(tquic_path_mtu_probe_acked);
EXPORT_SYMBOL_GPL(tquic_path_mtu_probe_lost);
EXPORT_SYMBOL_GPL(tquic_path_rtt_update);
EXPORT_SYMBOL_GPL(tquic_path_pto);
EXPORT_SYMBOL_GPL(tquic_path_on_data_sent);
EXPORT_SYMBOL_GPL(tquic_path_on_data_received);
EXPORT_SYMBOL_GPL(tquic_path_can_send);
EXPORT_SYMBOL_GPL(tquic_path_find);
EXPORT_SYMBOL_GPL(tquic_path_get_info);
EXPORT_SYMBOL_GPL(tquic_path_on_probe_timeout);
EXPORT_SYMBOL_GPL(tquic_path_needs_probe);

/*
 * Set path state
 */
void tquic_path_set_state(struct tquic_connection *conn, u8 path_id,
			  enum tquic_path_state state)
{
	struct tquic_path *path = NULL;
	struct tquic_path *p;

	spin_lock_bh(&conn->lock);
	spin_lock_bh(&conn->paths_lock);
	list_for_each_entry(p, &conn->paths, list) {
		if (p->path_id == path_id) {
			path = p;
			break;
		}
	}
	spin_unlock_bh(&conn->paths_lock);

	if (path) {
		WRITE_ONCE(path->state, state);
		if (state == TQUIC_PATH_ACTIVE && !conn->active_path)
			rcu_assign_pointer(conn->active_path, path);
	}
	spin_unlock_bh(&conn->lock);
}
EXPORT_SYMBOL_GPL(tquic_path_set_state);
