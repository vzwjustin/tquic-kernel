// SPDX-License-Identifier: GPL-2.0-only
/* TQUIC Multi-Path Management for WAN Bonding
 *
 * Copyright (c) 2026 Justin Adams <spotty118@gmail.com>
 * Kernel implementation by Justin Adams <spotty118@gmail.com>
 *
 * This implements multi-path management for TQUIC connections,
 * enabling WAN bonding with multiple simultaneous network interfaces.
 * Based on RFC 9000 path validation and inspired by MPTCP path management.
 */

#define pr_fmt(fmt) "TQUIC-PM: " fmt

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/rculist.h>
#include <linux/netdevice.h>
#include <linux/inetdevice.h>
#include <linux/notifier.h>
#include <linux/timer.h>
#include <linux/workqueue.h>
#include <linux/random.h>
#include <crypto/utils.h>
#include <linux/atomic.h>
#include <linux/refcount.h>
#include <linux/jhash.h>
#include <linux/if_arp.h>
#include <linux/rtnetlink.h>
#include <net/sock.h>
#include <net/ip.h>
#include <net/ipv6.h>
#include <net/route.h>
#include <net/addrconf.h>

#include "../tquic_compat.h"
#include "../tquic_debug.h"

#include "tquic_bonding.h"
#include "tquic_bpm.h"

/*
 * Path States (RFC 9000 Section 8.2 compliant)
 *
 * Note: enum tquic_bpm_path_state is defined in include/net/tquic.h
 * We define local path state values for the path manager that map
 * to the main enum values.
 */
/* enum tquic_bpm_path_state is defined in tquic_path.h */

static const char *tquic_bpm_path_state_names[] = {
	[TQUIC_BPM_PATH_CREATED] = "CREATED",
	[TQUIC_BPM_PATH_VALIDATING] = "VALIDATING",
	[TQUIC_BPM_PATH_VALIDATED] = "VALIDATED",
	[TQUIC_BPM_PATH_ACTIVE] = "ACTIVE",
	[TQUIC_BPM_PATH_STANDBY] = "STANDBY",
	[TQUIC_BPM_PATH_FAILED] = "FAILED",
	[TQUIC_BPM_PATH_CLOSING] = "CLOSING",
};

/* Backward-compatible aliases for path state constants */
#define TQUIC_BPM_PATH_UNUSED TQUIC_BPM_PATH_CREATED
#define TQUIC_BPM_PATH_CREATED TQUIC_BPM_PATH_CREATED
#define TQUIC_BPM_PATH_VALIDATING TQUIC_BPM_PATH_VALIDATING
#define TQUIC_BPM_PATH_VALIDATED TQUIC_BPM_PATH_VALIDATED
#define TQUIC_BPM_PATH_ACTIVE TQUIC_BPM_PATH_ACTIVE
#define TQUIC_BPM_PATH_STANDBY TQUIC_BPM_PATH_STANDBY
#define TQUIC_BPM_PATH_FAILED TQUIC_BPM_PATH_FAILED
#define TQUIC_BPM_PATH_CLOSED TQUIC_BPM_PATH_CLOSING
#define TQUIC_BPM_PATH_PENDING TQUIC_BPM_PATH_VALIDATING


/* Alias for state name array (backwards compatibility) */
#define tquic_bpm_path_state_names tquic_bpm_path_state_names

/*
 * WAN Interface Types
 */
enum tquic_wan_type {
	TQUIC_WAN_UNKNOWN = 0,
	TQUIC_WAN_ETHERNET, /* Wired ethernet */
	TQUIC_WAN_WIFI, /* 802.11 wireless */
	TQUIC_WAN_CELLULAR_3G, /* 3G/HSPA */
	TQUIC_WAN_CELLULAR_4G, /* LTE */
	TQUIC_WAN_CELLULAR_5G, /* 5G NR */
	TQUIC_WAN_SATELLITE, /* Satellite link */
	TQUIC_WAN_VPN, /* VPN tunnel */

	__TQUIC_WAN_TYPE_MAX
};

static const char *tquic_wan_type_names[] = {
	[TQUIC_WAN_UNKNOWN] = "unknown",     [TQUIC_WAN_ETHERNET] = "ethernet",
	[TQUIC_WAN_WIFI] = "wifi",	     [TQUIC_WAN_CELLULAR_3G] = "3g",
	[TQUIC_WAN_CELLULAR_4G] = "lte",     [TQUIC_WAN_CELLULAR_5G] = "5g",
	[TQUIC_WAN_SATELLITE] = "satellite", [TQUIC_WAN_VPN] = "vpn",
};

/*
 * Path validation constants (RFC 9000)
 */
#define TQUIC_BPM_PATH_CHALLENGE_SIZE 8 /* 8-byte random data */
#define TQUIC_BPM_PATH_VALIDATION_TIMEOUT (3 * HZ) /* 3 seconds initial */
#define TQUIC_BPM_PATH_VALIDATION_MAX_RETRIES 3
#define TQUIC_BPM_PATH_PROBE_TIMEOUT (30 * HZ) /* Probe every 30 seconds */
#define TQUIC_BPM_PATH_FAIL_THRESHOLD 5 /* Consecutive failures */
/* CF-295: Remove local definition; use canonical TQUIC_MAX_PATHS from tquic.h */
#define TQUIC_BPM_PATH_MTU_MIN 1200 /* QUIC minimum MTU */

/*
 * Path quality scoring constants
 * Total score is 0-1000, higher is better
 */
#define TQUIC_BPM_PATH_SCORE_MAX 1000 /* Maximum path score */
#define TQUIC_BPM_PATH_SCORE_RTT_MAX 400 /* Max points for RTT */
#define TQUIC_BPM_PATH_SCORE_LOSS_MAX 400 /* Max points for loss rate */
#define TQUIC_BPM_PATH_SCORE_BW_MAX 200 /* Max points for bandwidth */

/* RTT thresholds for scoring (microseconds) */
#define TQUIC_BPM_PATH_RTT_IDEAL 20000 /* 20ms - full points */
#define TQUIC_BPM_PATH_RTT_POOR 500000 /* 500ms - zero points */

/* Bandwidth thresholds for scoring (bytes/sec) */
#define TQUIC_BPM_PATH_BW_EXCELLENT 100000000 /* 100 MB/s */
#define TQUIC_BPM_PATH_BW_GOOD 10000000 /* 10 MB/s */
#define TQUIC_BPM_PATH_BW_FAIR 1000000 /* 1 MB/s */
#define TQUIC_BPM_PATH_BW_POOR 100000 /* 100 KB/s */

/* Loss rate threshold (permille - parts per thousand) */
#define TQUIC_BPM_PATH_LOSS_THRESHOLD 100 /* 10% loss = zero points */

/*
 * Congestion control state per path
 */
struct tquic_bpm_path_cc {
	u32 cwnd; /* Congestion window (bytes) */
	u32 ssthresh; /* Slow start threshold */
	u32 bytes_in_flight;
	u32 bytes_acked;
	u32 bytes_lost;
	u64 smoothed_rtt_us; /* Smoothed RTT in microseconds */
	u64 pacing_rate; /* bytes per second */
	u8 in_recovery : 1;
	u8 in_slow_start : 1;
	ktime_t congestion_start;
};

/*
 * Path metrics
 */
struct tquic_bpm_path_metrics {
	/* RTT measurements (in microseconds) */
	u32 srtt; /* Smoothed RTT */
	u32 rttvar; /* RTT variance */
	u32 min_rtt; /* Minimum observed RTT */
	u32 latest_rtt; /* Most recent RTT sample */

	/* Bandwidth estimation */
	u64 bandwidth; /* Estimated bandwidth (bytes/sec) */
	u64 bandwidth_hi; /* High watermark */
	u64 bandwidth_lo; /* Low watermark */

	/* Loss statistics */
	u64 packets_sent;
	u64 packets_acked;
	u64 packets_lost;
	u32 loss_rate; /* Loss rate * 1000 (permille) */

	/* Timing */
	ktime_t last_send;
	ktime_t last_recv;
	ktime_t last_rtt_update;
};

/*
 * Address information for a path endpoint
 */
struct tquic_addr_info {
	sa_family_t family;
	__be16 port;
	union {
		__be32 addr4;
		struct in6_addr addr6;
	};
};

/*
 * Path validation context
 */
struct tquic_bpm_path_validation {
	u8 challenge_data[TQUIC_BPM_PATH_CHALLENGE_SIZE];
	u8 response_data[TQUIC_BPM_PATH_CHALLENGE_SIZE];
	u8 retries;
	bool challenge_pending;
	bool response_received;
	ktime_t challenge_sent;
	struct timer_list timer;
};

/*
 * TQUIC Path Structure
 *
 * Represents a network path between local and remote endpoints.
 * Each path maintains its own congestion control state.
 */
struct tquic_bpm_path {
	struct list_head list; /* Link in path manager */
	struct rcu_head rcu;

	/* Path identification */
	u32 path_id;
	u8 local_cid[20]; /* Local connection ID */
	u8 remote_cid[20]; /* Remote connection ID */
	u8 local_cid_len;
	u8 remote_cid_len;

	/* Endpoints */
	struct tquic_addr_info local_addr;
	struct tquic_addr_info remote_addr;
	int ifindex; /* Network interface index */
	struct net_device *dev; /* Network device (RCU) */

	/* State */
	enum tquic_bpm_path_state state;
	spinlock_t state_lock;
	refcount_t refcnt;

	/* WAN information */
	enum tquic_wan_type wan_type;
	s8 signal_strength; /* dBm for cellular, -1 if N/A */
	u8 signal_quality; /* 0-100% quality indicator */

	/* Path validation */
	struct tquic_bpm_path_validation validation;

	/* Congestion control */
	struct tquic_bpm_path_cc cc;
	spinlock_t cc_lock;

	/* Metrics */
	struct tquic_bpm_path_metrics metrics;

	/* Flags */
	u8 is_primary : 1; /* Primary path */
	u8 is_backup : 1; /* Backup only */
	u8 peer_migrated : 1; /* Peer initiated migration */
	u8 nat_rebinding : 1; /* NAT rebinding detected */
	u8 ecn_capable : 1; /* ECN supported */
	u8 mtu_probing : 1; /* MTU discovery active */

	/* Multipath extension state (draft-ietf-quic-multipath) */
	u64 status_seq_num; /* PATH_STATUS sequence number */

	/* MTU */
	u16 mtu;
	u16 mtu_probe_target;

	/* Statistics - compatible with include/net/tquic.h tquic_bpm_path_stats */
	struct {
		u64 tx_packets;
		u64 tx_bytes;
		u64 rx_packets;
		u64 rx_bytes;
		u64 acked_bytes;
		u64 lost_packets;
		u32 rtt_min;
		u32 rtt_smoothed;
		u32 rtt_variance;
		u64 bandwidth;
		u32 cwnd;
	} stats;

	u32 consecutive_failures;

	/* Scheduling parameters */
	u8 priority; /* Lower = preferred */
	u8 weight; /* For weighted schedulers */

	/* Timestamps */
	ktime_t created;
	ktime_t validated;
	ktime_t last_activity;

	/* Back pointer to path manager */
	struct tquic_bpm_path_manager *pm;
};

/*
 * Adapter helpers: bridge tquic_bpm_path lifecycle to the bonding API.
 *
 * The bonding layer uses struct tquic_path *, but BPM has its own
 * struct tquic_bpm_path type.  For callbacks that only read path_id
 * or state, we synthesise a minimal tquic_path stub on the stack.
 * Callbacks that do not dereference the path arg at all pass NULL.
 */
static enum tquic_path_state
bpm_to_core_state(enum tquic_bpm_path_state s)
{
	if (s == TQUIC_BPM_PATH_ACTIVE)
		return TQUIC_PATH_ACTIVE;
	if (s == TQUIC_BPM_PATH_FAILED || s == TQUIC_BPM_PATH_CLOSING)
		return TQUIC_PATH_FAILED;
	return TQUIC_PATH_PENDING;
}

/* on_path_available: bonding callee ignores the path arg entirely */
static void bpm_on_path_available(void *ctx, struct tquic_bpm_path *path)
{
	tquic_bonding_on_path_validated(ctx, NULL);
}

/* on_path_failed: bonding callee reads only path->path_id */
static void bpm_on_path_failed(void *ctx, struct tquic_bpm_path *path)
{
	struct tquic_path tpath = {};

	tpath.path_id = path->path_id;
	tquic_bonding_on_path_failed(ctx, &tpath);
}

/*
 * Path Manager per connection
 */
struct tquic_bpm_path_manager {
	struct list_head path_list; /* List of paths */
	spinlock_t lock;
	refcount_t refcnt;

	/* Path count and limits */
	u8 path_count;
	u8 active_count;
	u8 max_paths;

	/* ID allocation */
	u32 next_path_id;
	DECLARE_BITMAP(path_id_bitmap, TQUIC_MAX_PATHS);

	/* Primary path tracking */
	struct tquic_bpm_path __rcu *primary_path;
	struct tquic_bpm_path __rcu *backup_path;

	/* Work queue for async operations */
	struct work_struct discover_work;
	struct work_struct failover_work;
	struct delayed_work probe_work;

	/* Discovery state */
	bool discovery_enabled;
	bool auto_failover;
	ktime_t last_discovery;

	/* Network namespace */
	struct net *net;

	/* Bonding state machine context (Phase 05) */
	struct tquic_bonding_ctx *bonding;

	/* Callbacks */
	void *cb_ctx;
	void (*on_path_available)(void *ctx, struct tquic_bpm_path *path);
	void (*on_path_failed)(void *ctx, struct tquic_bpm_path *path);
	void (*on_migration_complete)(void *ctx, struct tquic_bpm_path *old,
				      struct tquic_bpm_path *new);

	/* Statistics */
	u32 paths_created;
	u32 paths_validated;
	u32 paths_failed;
	u32 migrations;

	/* RCU */
	struct rcu_head rcu;
};

/*
 * Global path manager registry
 */
static DEFINE_SPINLOCK(tquic_bpm_list_lock);
static LIST_HEAD(tquic_bpm_list);
static struct workqueue_struct *tquic_bpm_wq;
static struct notifier_block tquic_netdev_notifier;
static atomic_t tquic_bpm_count = ATOMIC_INIT(0);

/* Forward declarations */
static void tquic_bpm_path_validation_timeout(struct timer_list *timer);
static void tquic_bpm_probe_work_fn(struct work_struct *work);
static void tquic_bpm_discover_work_fn(struct work_struct *work);
static void tquic_bpm_failover_work_fn(struct work_struct *work);

/*
 * ============================================================================
 * Address Utilities
 * ============================================================================
 */

static inline bool tquic_addr_equal(const struct tquic_addr_info *a,
				    const struct tquic_addr_info *b,
				    bool check_port)
{
	if (a->family != b->family)
		return false;

	if (check_port && a->port != b->port)
		return false;

	if (a->family == AF_INET)
		return a->addr4 == b->addr4;

	if (a->family == AF_INET6)
		return ipv6_addr_equal(&a->addr6, &b->addr6);

	return false;
}

static void tquic_addr_from_sockaddr(struct tquic_addr_info *info,
				     const struct sockaddr *addr)
{
	tquic_dbg("addr_from_sockaddr: family=%u\n", addr->sa_family);
	memset(info, 0, sizeof(*info));

	if (addr->sa_family == AF_INET) {
		const struct sockaddr_in *sin =
			(const struct sockaddr_in *)addr;
		info->family = AF_INET;
		info->port = sin->sin_port;
		info->addr4 = sin->sin_addr.s_addr;
	} else if (addr->sa_family == AF_INET6) {
		const struct sockaddr_in6 *sin6 =
			(const struct sockaddr_in6 *)addr;
		info->family = AF_INET6;
		info->port = sin6->sin6_port;
		info->addr6 = sin6->sin6_addr;
	}
}

void tquic_addr_to_sockaddr(
	const struct tquic_addr_info *info, struct sockaddr_storage *addr)
{
	tquic_dbg("addr_to_sockaddr: family=%u\n", info->family);
	memset(addr, 0, sizeof(*addr));

	if (info->family == AF_INET) {
		struct sockaddr_in *sin = (struct sockaddr_in *)addr;
		sin->sin_family = AF_INET;
		sin->sin_port = info->port;
		sin->sin_addr.s_addr = info->addr4;
	} else if (info->family == AF_INET6) {
		struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)addr;
		sin6->sin6_family = AF_INET6;
		sin6->sin6_port = info->port;
		sin6->sin6_addr = info->addr6;
	}
}

/*
 * ============================================================================
 * Congestion Control Helpers
 * ============================================================================
 */

#define TQUIC_INITIAL_CWND (10 * TQUIC_BPM_PATH_MTU_MIN)
#define TQUIC_MIN_CWND (2 * TQUIC_BPM_PATH_MTU_MIN)
#define TQUIC_INITIAL_SSTHRESH UINT_MAX
#define TQUIC_INITIAL_RTT_US 333000 /* 333ms initial RTT estimate */

static void tquic_cc_init(struct tquic_bpm_path_cc *cc)
{
	tquic_dbg("cc_init: cwnd=%u ssthresh=%u\n",
		  TQUIC_INITIAL_CWND, TQUIC_INITIAL_SSTHRESH);
	cc->cwnd = TQUIC_INITIAL_CWND;
	cc->ssthresh = TQUIC_INITIAL_SSTHRESH;
	cc->bytes_in_flight = 0;
	cc->bytes_acked = 0;
	cc->bytes_lost = 0;
	cc->smoothed_rtt_us = TQUIC_INITIAL_RTT_US;
	cc->pacing_rate = 0;
	cc->in_recovery = false;
	cc->in_slow_start = true;
	cc->congestion_start = 0;
}

static void tquic_cc_on_ack(struct tquic_bpm_path *path,
					   u32 bytes_acked)
{
	struct tquic_bpm_path_cc *cc = &path->cc;

	tquic_dbg("cc_on_ack: path=%u acked=%u cwnd=%u\n",
		  path->path_id, bytes_acked, cc->cwnd);

	spin_lock_bh(&path->cc_lock);

	cc->bytes_acked += bytes_acked;
	if (cc->bytes_in_flight >= bytes_acked)
		cc->bytes_in_flight -= bytes_acked;
	else
		cc->bytes_in_flight = 0;

	/* Congestion window growth */
	if (cc->in_slow_start) {
		/* Slow start: increase cwnd by acked bytes */
		cc->cwnd += bytes_acked;
		if (cc->cwnd >= cc->ssthresh) {
			cc->in_slow_start = false;
		}
	} else {
		/* Congestion avoidance: increase by 1 MSS per RTT */
		u32 increase = (bytes_acked * path->mtu) / cc->cwnd;
		cc->cwnd += max(increase, 1U);
	}

	/* Exit recovery if we've acked enough */
	if (cc->in_recovery && cc->bytes_acked >= cc->cwnd) {
		cc->in_recovery = false;
	}

	spin_unlock_bh(&path->cc_lock);

	/*
	 * BPM manages its own CC state independently.  Do not forward to the
	 * multipath scheduler via the bonding API: that API expects a core
	 * struct tquic_path *, not a struct tquic_bpm_path *.
	 */
}

static void tquic_cc_on_loss(struct tquic_bpm_path *path,
					    u32 bytes_lost)
{
	struct tquic_bpm_path_cc *cc = &path->cc;

	tquic_dbg("cc_on_loss: path=%u lost=%u cwnd=%u\n",
		  path->path_id, bytes_lost, cc->cwnd);

	spin_lock_bh(&path->cc_lock);

	cc->bytes_lost += bytes_lost;

	if (!cc->in_recovery) {
		/* Enter recovery: halve cwnd */
		cc->in_recovery = true;
		cc->in_slow_start = false;
		cc->congestion_start = ktime_get();
		cc->ssthresh = max(cc->cwnd / 2, TQUIC_MIN_CWND);
		cc->cwnd = cc->ssthresh;
	}

	spin_unlock_bh(&path->cc_lock);

	/*
	 * BPM manages its own CC state independently.  Do not forward to the
	 * multipath scheduler via the bonding API: that API expects a core
	 * struct tquic_path *, not a struct tquic_bpm_path *.
	 */
}

static u32 tquic_cc_available_cwnd(struct tquic_bpm_path *path)
{
	struct tquic_bpm_path_cc *cc = &path->cc;
	u32 available;

	spin_lock_bh(&path->cc_lock);
	if (cc->cwnd > cc->bytes_in_flight)
		available = cc->cwnd - cc->bytes_in_flight;
	else
		available = 0;
	spin_unlock_bh(&path->cc_lock);

	tquic_dbg("cc_available_cwnd: path=%u available=%u cwnd=%u inflight=%u\n",
		  path->path_id, available, cc->cwnd, cc->bytes_in_flight);
	return available;
}

/*
 * ============================================================================
 * Path Metrics
 * ============================================================================
 */

#define TQUIC_RTT_ALPHA 8 /* SRTT smoothing factor 1/8 */
#define TQUIC_RTTVAR_BETA 4 /* RTTVAR smoothing factor 1/4 */

static void tquic_metrics_init(struct tquic_bpm_path_metrics *m)
{
	tquic_dbg("metrics_init: initial_rtt=%u us\n", TQUIC_INITIAL_RTT_US);
	m->srtt = TQUIC_INITIAL_RTT_US;
	m->rttvar = TQUIC_INITIAL_RTT_US / 2;
	m->min_rtt = UINT_MAX;
	m->latest_rtt = 0;
	m->bandwidth = 0;
	m->bandwidth_hi = 0;
	m->bandwidth_lo = ULLONG_MAX;
	m->packets_sent = 0;
	m->packets_acked = 0;
	m->packets_lost = 0;
	m->loss_rate = 0;
	m->last_send = 0;
	m->last_recv = 0;
	m->last_rtt_update = 0;
}

/**
 * tquic_bpm_path_update_rtt - Update RTT measurements for a path
 * @path: Path to update
 * @rtt_sample: New RTT sample in microseconds
 *
 * Implements RFC 6298 style RTT estimation with adjustments for QUIC.
 */
void tquic_bpm_path_update_rtt(struct tquic_bpm_path *path, u32 rtt_sample)
{
	struct tquic_bpm_path_metrics *m = &path->metrics;
	s32 delta;

	if (rtt_sample == 0)
		return;

	m->latest_rtt = rtt_sample;
	m->last_rtt_update = ktime_get();

	/* Update minimum RTT */
	if (rtt_sample < m->min_rtt)
		m->min_rtt = rtt_sample;

	/* First sample */
	if (m->srtt == TQUIC_INITIAL_RTT_US) {
		m->srtt = rtt_sample;
		m->rttvar = rtt_sample / 2;
		/* Sync to cc struct for bonding/scheduler access */
		path->cc.smoothed_rtt_us = rtt_sample;
		return;
	}

	/* RFC 6298 SRTT and RTTVAR calculation */
	delta = (s32)rtt_sample - (s32)m->srtt;
	m->srtt = m->srtt + delta / TQUIC_RTT_ALPHA;

	if (delta < 0)
		delta = -delta;
	m->rttvar = m->rttvar + (delta - m->rttvar) / TQUIC_RTTVAR_BETA;

	/* Sync to cc struct for bonding/scheduler access */
	path->cc.smoothed_rtt_us = m->srtt;

	pr_debug("path %u: RTT updated srtt=%u rttvar=%u min=%u\n",
		 path->path_id, m->srtt, m->rttvar, m->min_rtt);
}
EXPORT_SYMBOL_GPL(tquic_bpm_path_update_rtt);

/**
 * tquic_bpm_path_update_bandwidth - Update bandwidth estimate for a path
 * @path: Path to update
 * @bytes: Bytes acknowledged
 * @interval_us: Time interval in microseconds
 */
void tquic_bpm_path_update_bandwidth(struct tquic_bpm_path *path, u64 bytes,
				 u64 interval_us)
{
	struct tquic_bpm_path_metrics *m = &path->metrics;
	u64 bw;

	if (interval_us == 0)
		return;

	/* Calculate bandwidth in bytes/second */
	bw = div64_u64(bytes * USEC_PER_SEC, interval_us);

	/* Exponential moving average with 1/8 weight for new sample */
	if (m->bandwidth == 0)
		m->bandwidth = bw;
	else
		m->bandwidth = (m->bandwidth * 7 + bw) / 8;

	/* Update high/low watermarks */
	if (bw > m->bandwidth_hi)
		m->bandwidth_hi = bw;
	if (bw < m->bandwidth_lo)
		m->bandwidth_lo = bw;

	pr_debug("path %u: bandwidth updated to %llu bytes/sec\n",
		 path->path_id, m->bandwidth);
}
EXPORT_SYMBOL_GPL(tquic_bpm_path_update_bandwidth);

/**
 * tquic_bpm_path_update_loss_rate - Update loss rate for a path
 * @path: Path to update
 */
void tquic_bpm_path_update_loss_rate(struct tquic_bpm_path *path)
{
	struct tquic_bpm_path_metrics *m = &path->metrics;
	u64 total;

	total = m->packets_acked + m->packets_lost;
	if (total == 0) {
		m->loss_rate = 0;
		return;
	}

	/* Calculate loss rate in permille (parts per thousand) */
	m->loss_rate = (u32)div64_u64(m->packets_lost * 1000, total);

	pr_debug("path %u: loss rate %u permille (%llu/%llu)\n", path->path_id,
		 m->loss_rate, m->packets_lost, total);
}
EXPORT_SYMBOL_GPL(tquic_bpm_path_update_loss_rate);

/**
 * tquic_bpm_path_get_score - Calculate quality score for a path
 * @path: Path to evaluate
 *
 * Returns a quality score from 0-1000, higher is better.
 * Score considers RTT, bandwidth, and loss rate.
 */
u32 tquic_bpm_path_get_score(struct tquic_bpm_path *path)
{
	struct tquic_bpm_path_metrics *m = &path->metrics;
	u32 score = TQUIC_BPM_PATH_SCORE_MAX;

	tquic_dbg("path_get_score: path=%u rtt=%u loss=%u bw=%llu\n",
		  path->path_id, m->srtt, m->loss_rate, m->bandwidth);
	u32 rtt_score, loss_score, bw_score;
	u32 rtt_range = TQUIC_BPM_PATH_RTT_POOR - TQUIC_BPM_PATH_RTT_IDEAL;

	/* RTT component (max TQUIC_BPM_PATH_SCORE_RTT_MAX points) */
	if (m->srtt < TQUIC_BPM_PATH_RTT_IDEAL)
		rtt_score = TQUIC_BPM_PATH_SCORE_RTT_MAX;
	else if (m->srtt > TQUIC_BPM_PATH_RTT_POOR)
		rtt_score = 0;
	else
		rtt_score = TQUIC_BPM_PATH_SCORE_RTT_MAX -
			    (m->srtt - TQUIC_BPM_PATH_RTT_IDEAL) *
				    TQUIC_BPM_PATH_SCORE_RTT_MAX / rtt_range;

	/* Loss rate component (max TQUIC_BPM_PATH_SCORE_LOSS_MAX points) */
	if (m->loss_rate == 0)
		loss_score = TQUIC_BPM_PATH_SCORE_LOSS_MAX;
	else if (m->loss_rate >= TQUIC_BPM_PATH_LOSS_THRESHOLD)
		loss_score = 0;
	else
		loss_score = TQUIC_BPM_PATH_SCORE_LOSS_MAX -
			     m->loss_rate * TQUIC_BPM_PATH_SCORE_LOSS_MAX /
				     TQUIC_BPM_PATH_LOSS_THRESHOLD;

	/* Bandwidth component (max TQUIC_BPM_PATH_SCORE_BW_MAX points) */
	if (m->bandwidth >= TQUIC_BPM_PATH_BW_EXCELLENT)
		bw_score = TQUIC_BPM_PATH_SCORE_BW_MAX;
	else if (m->bandwidth >= TQUIC_BPM_PATH_BW_GOOD)
		bw_score = TQUIC_BPM_PATH_SCORE_BW_MAX * 3 / 4;
	else if (m->bandwidth >= TQUIC_BPM_PATH_BW_FAIR)
		bw_score = TQUIC_BPM_PATH_SCORE_BW_MAX / 2;
	else if (m->bandwidth >= TQUIC_BPM_PATH_BW_POOR)
		bw_score = TQUIC_BPM_PATH_SCORE_BW_MAX / 4;
	else
		bw_score = 0;

	score = rtt_score + loss_score + bw_score;

	/* Apply WAN type modifier */
	switch (path->wan_type) {
	case TQUIC_WAN_ETHERNET:
		/* No modifier for wired */
		break;
	case TQUIC_WAN_WIFI:
		score = score * 95 / 100; /* 5% penalty */
		break;
	case TQUIC_WAN_CELLULAR_5G:
		score = score * 90 / 100; /* 10% penalty */
		break;
	case TQUIC_WAN_CELLULAR_4G:
		score = score * 85 / 100; /* 15% penalty */
		break;
	case TQUIC_WAN_CELLULAR_3G:
		score = score * 70 / 100; /* 30% penalty */
		break;
	case TQUIC_WAN_SATELLITE:
		score = score * 60 / 100; /* 40% penalty for latency */
		break;
	default:
		break;
	}

	/* Signal strength modifier for cellular */
	if (path->wan_type >= TQUIC_WAN_CELLULAR_3G &&
	    path->wan_type <= TQUIC_WAN_CELLULAR_5G) {
		if (path->signal_strength != -1) {
			/* Good signal > -70 dBm, poor < -100 dBm */
			if (path->signal_strength > -70)
				; /* No change */
			else if (path->signal_strength > -85)
				score = score * 95 / 100;
			else if (path->signal_strength > -100)
				score = score * 85 / 100;
			else
				score = score * 70 / 100;
		}
	}

	return min(score, 1000U);
}
EXPORT_SYMBOL_GPL(tquic_bpm_path_get_score);

/*
 * ============================================================================
 * WAN Detection
 * ============================================================================
 */

/**
 * tquic_wan_detect - Detect WAN interface type
 * @dev: Network device to classify
 *
 * Returns the WAN type classification for the device.
 */
enum tquic_wan_type tquic_wan_detect(struct net_device *dev)
{
	if (!dev)
		return TQUIC_WAN_UNKNOWN;

	tquic_dbg("wan_detect: dev=%s type=%u\n", dev->name, dev->type);

	/* Check device type and flags */
	switch (dev->type) {
	case ARPHRD_ETHER:
	case ARPHRD_IEEE802:
		/* Could be ethernet or WiFi */
		if (dev->ieee80211_ptr)
			return TQUIC_WAN_WIFI;
		return TQUIC_WAN_ETHERNET;

	case ARPHRD_IEEE80211:
	case ARPHRD_IEEE80211_PRISM:
	case ARPHRD_IEEE80211_RADIOTAP:
		return TQUIC_WAN_WIFI;

	case ARPHRD_RAWIP:
	case ARPHRD_NONE:
		/* Check for cellular/WWAN indicators */
		if (strncmp(dev->name, "wwan", 4) == 0 ||
		    strncmp(dev->name, "rmnet", 5) == 0 ||
		    strncmp(dev->name, "ccmni", 5) == 0)
			return TQUIC_WAN_CELLULAR_4G; /* Assume LTE default */

		/* Check for VPN tunnels */
		if (strncmp(dev->name, "tun", 3) == 0 ||
		    strncmp(dev->name, "tap", 3) == 0 ||
		    strncmp(dev->name, "wg", 2) == 0)
			return TQUIC_WAN_VPN;
		break;

	case ARPHRD_PPP:
		/* PPP could be cellular or DSL */
		if (strncmp(dev->name, "ppp", 3) == 0)
			return TQUIC_WAN_CELLULAR_4G;
		break;

	case ARPHRD_TUNNEL:
	case ARPHRD_TUNNEL6:
	case ARPHRD_IPGRE:
	case ARPHRD_IP6GRE:
		return TQUIC_WAN_VPN;
	}

	return TQUIC_WAN_UNKNOWN;
}
EXPORT_SYMBOL_GPL(tquic_wan_detect);

/**
 * tquic_wan_get_signal_strength - Get network signal strength
 * @dev: Network device
 *
 * Returns signal strength in dBm:
 *   0 dBm: Wired connection (no signal measurement applicable)
 *  -30 to -90 dBm: Typical WiFi/cellular range
 *  -128 dBm: Not available or error
 *
 * For WiFi devices, queries the wireless subsystem.
 * For wired devices, returns 0 (maximum signal equivalent).
 * For WWAN devices, attempts to query signal if available.
 */
s8 tquic_wan_get_signal_strength(struct net_device *dev)
{
	if (!dev)
		return -128;

	tquic_dbg("wan_get_signal_strength: dev=%s type=%u\n",
		  dev->name, dev->type);

	/*
	 * Wired interfaces (Ethernet, loopback) don't have signal strength.
	 * Return 0 to indicate "full signal" equivalent for path selection.
	 */
	switch (dev->type) {
	case ARPHRD_ETHER:
		/*
		 * For Ethernet, check if it's actually WiFi.
		 * WiFi devices also report ARPHRD_ETHER but have
		 * ieee80211_ptr or wireless handlers set.
		 */
#if IS_ENABLED(CONFIG_CFG80211)
		if (dev->ieee80211_ptr) {
			/*
			 * This is a WiFi device. The signal strength
			 * is available via cfg80211/nl80211.
			 * For kernel-internal use, we'd need to query the
			 * station info which requires async operations.
			 * Return -50 dBm as a reasonable default for WiFi.
			 */
			return -50;
		}
#endif
		/* Pure Ethernet - no signal metric */
		return 0;

	case ARPHRD_LOOPBACK:
		/* Loopback - maximum signal equivalent */
		return 0;

	case ARPHRD_PPP:
	case ARPHRD_RAWIP:
		/*
		 * PPP/RAWIP are often used for cellular connections.
		 * Return a moderate signal strength as default.
		 * Real WWAN integration would query the modem.
		 */
		return -70;

	case ARPHRD_TUNNEL:
	case ARPHRD_TUNNEL6:
	case ARPHRD_IPGRE:
	case ARPHRD_IP6GRE:
		/*
		 * VPN tunnels inherit signal from underlying interface.
		 * Return moderate value as we can't easily query the
		 * underlying physical interface.
		 */
		return -60;

	default:
		break;
	}

	/* Unknown device type - signal not available */
	return -128;
}
EXPORT_SYMBOL_GPL(tquic_wan_get_signal_strength);

/*
 * ============================================================================
 * Path Lifecycle
 * ============================================================================
 */

/**
 * tquic_bpm_path_alloc - Allocate a new path structure
 * @gfp: Memory allocation flags
 *
 * Returns allocated path or NULL on failure.
 */
struct tquic_bpm_path *tquic_bpm_path_alloc(gfp_t gfp)
{
	struct tquic_bpm_path *path;

	path = kzalloc(sizeof(*path), gfp);
	if (!path)
		return NULL;

	INIT_LIST_HEAD(&path->list);
	spin_lock_init(&path->state_lock);
	spin_lock_init(&path->cc_lock);
	refcount_set(&path->refcnt, 1);

	path->state = TQUIC_BPM_PATH_UNUSED;
	path->mtu = TQUIC_BPM_PATH_MTU_MIN;
	path->status_seq_num = 0;
	path->signal_strength = -128; /* Unknown */
	path->priority = 128; /* Default priority (middle) */
	path->weight = 100; /* Default weight */
	path->created = ktime_get();

	tquic_cc_init(&path->cc);
	tquic_metrics_init(&path->metrics);

	/* Initialize validation timer */
	timer_setup(&path->validation.timer, tquic_bpm_path_validation_timeout, 0);

	pr_debug("path allocated %p\n", path);

	return path;
}
EXPORT_SYMBOL_GPL(tquic_bpm_path_alloc);

/**
 * tquic_bpm_path_free - Free a path structure
 * @path: Path to free
 *
 * Should be called after all references are released.
 */
void tquic_bpm_path_free(struct tquic_bpm_path *path)
{
	if (!path)
		return;

	WARN_ON(!list_empty(&path->list));
	del_timer_sync(&path->validation.timer);

	if (path->dev)
		dev_put(path->dev);

	pr_debug("path %u freed\n", path->path_id);
	kfree(path);
}
EXPORT_SYMBOL_GPL(tquic_bpm_path_free);

static void tquic_bpm_path_free_rcu(struct rcu_head *head)
{
	struct tquic_bpm_path *path = container_of(head, struct tquic_bpm_path, rcu);
	tquic_bpm_path_free(path);
}

/**
 * tquic_bpm_path_get - Get a reference to a path
 * @path: Path to reference
 */
static inline void tquic_bpm_path_get(struct tquic_bpm_path *path)
{
	refcount_inc(&path->refcnt);
}

/**
 * tquic_bpm_path_put - Release a reference to a path
 * @path: Path to release
 */
static inline void tquic_bpm_path_put(struct tquic_bpm_path *path)
{
	if (refcount_dec_and_test(&path->refcnt))
		call_rcu(&path->rcu, tquic_bpm_path_free_rcu);
}

/**
 * tquic_bpm_path_init - Initialize a path with addresses
 * @path: Path to initialize
 * @local: Local address
 * @remote: Remote address
 * @ifindex: Network interface index
 *
 * Returns 0 on success, negative error code on failure.
 */
int tquic_bpm_path_init(struct tquic_bpm_path *path, const struct sockaddr *local,
		    const struct sockaddr *remote, int ifindex)
{
	struct net_device *dev;

	if (!path || !local || !remote)
		return -EINVAL;

	if (local->sa_family != remote->sa_family)
		return -EINVAL;

	tquic_addr_from_sockaddr(&path->local_addr, local);
	tquic_addr_from_sockaddr(&path->remote_addr, remote);
	path->ifindex = ifindex;

	/* Get network device reference */
	rcu_read_lock();
	if (!path->pm || !path->pm->net) {
		rcu_read_unlock();
		return -EINVAL;
	}
	dev = dev_get_by_index_rcu(path->pm->net, ifindex);
	if (dev) {
		dev_hold(dev);
		path->dev = dev;
		path->wan_type = tquic_wan_detect(dev);
		path->signal_strength = tquic_wan_get_signal_strength(dev);

		/* Get MTU from device */
		path->mtu = min_t(u16, dev->mtu, 65535);
		if (path->mtu < TQUIC_BPM_PATH_MTU_MIN)
			path->mtu = TQUIC_BPM_PATH_MTU_MIN;
	}
	rcu_read_unlock();

	pr_debug("path %u initialized: ifindex=%d wan_type=%s mtu=%u\n",
		 path->path_id, ifindex,
		 path->wan_type < __TQUIC_WAN_TYPE_MAX ?
			 tquic_wan_type_names[path->wan_type] :
			 "unknown",
		 path->mtu);

	return 0;
}
EXPORT_SYMBOL_GPL(tquic_bpm_path_init);

/*
 * ============================================================================
 * Path State Machine
 * ============================================================================
 */

/**
 * tquic_bpm_path_set_state - Change path state
 * @path: Path to modify
 * @new_state: New state
 *
 * Returns 0 on success, negative error code on invalid transition.
 */
int tquic_bpm_path_set_state(struct tquic_bpm_path *path,
			 enum tquic_bpm_path_state new_state)
{
	enum tquic_bpm_path_state old_state;
	int ret = 0;

	if (!path || new_state > TQUIC_BPM_PATH_CLOSED)
		return -EINVAL;

	spin_lock_bh(&path->state_lock);

	old_state = path->state;

	/* Validate state transitions */
	switch (new_state) {
	case TQUIC_BPM_PATH_PENDING:
		if (old_state != TQUIC_BPM_PATH_UNUSED &&
		    old_state != TQUIC_BPM_PATH_STANDBY) {
			ret = -EINVAL;
			goto out;
		}
		break;

	case TQUIC_BPM_PATH_VALIDATED:
		if (old_state != TQUIC_BPM_PATH_PENDING) {
			ret = -EINVAL;
			goto out;
		}
		path->validated = ktime_get();
		break;

	case TQUIC_BPM_PATH_ACTIVE:
		if (old_state != TQUIC_BPM_PATH_VALIDATED &&
		    old_state != TQUIC_BPM_PATH_STANDBY) {
			ret = -EINVAL;
			goto out;
		}
		break;

	case TQUIC_BPM_PATH_STANDBY:
		if (old_state != TQUIC_BPM_PATH_VALIDATED &&
		    old_state != TQUIC_BPM_PATH_ACTIVE) {
			ret = -EINVAL;
			goto out;
		}
		break;

	case TQUIC_BPM_PATH_FAILED:
		/* Can transition to failed from any state */
		break;

	case TQUIC_BPM_PATH_CLOSED:
		/* Can close from any state except CREATED */
		if (old_state == TQUIC_BPM_PATH_UNUSED) {
			ret = -EINVAL;
			goto out;
		}
		break;

	default:
		ret = -EINVAL;
		goto out;
	}

	path->state = new_state;
	path->last_activity = ktime_get();

	pr_debug("path %u: state %s -> %s\n", path->path_id,
		 tquic_bpm_path_state_names[old_state],
		 tquic_bpm_path_state_names[new_state]);

out:
	spin_unlock_bh(&path->state_lock);
	return ret;
}
EXPORT_SYMBOL_GPL(tquic_bpm_path_set_state);

/*
 * ============================================================================
 * Path Validation (RFC 9000 Section 8.2)
 * ============================================================================
 */

static void tquic_bpm_path_validation_timeout(struct timer_list *timer)
{
	struct tquic_bpm_path_validation *val =
		container_of(timer, struct tquic_bpm_path_validation, timer);
	struct tquic_bpm_path *path =
		container_of(val, struct tquic_bpm_path, validation);

	spin_lock_bh(&path->state_lock);

	if (path->state != TQUIC_BPM_PATH_PENDING) {
		spin_unlock_bh(&path->state_lock);
		return;
	}

	if (val->retries >= TQUIC_BPM_PATH_VALIDATION_MAX_RETRIES) {
		/* Validation failed */
		pr_info("path %u: validation timeout after %u retries\n",
			path->path_id, val->retries);

		path->state = TQUIC_BPM_PATH_FAILED;
		path->consecutive_failures++;

		spin_unlock_bh(&path->state_lock);

		/* Notify path manager of failure */
		if (path->pm && path->pm->on_path_failed)
			path->pm->on_path_failed(path->pm->cb_ctx, path);

		return;
	}

	/* Retry: send another PATH_CHALLENGE */
	val->retries++;
	val->challenge_pending = true;
	val->challenge_sent = ktime_get();

	spin_unlock_bh(&path->state_lock);

	pr_debug("path %u: validation retry %u\n", path->path_id, val->retries);

	/* Reschedule with exponential backoff */
	mod_timer(&val->timer,
		  jiffies + (TQUIC_BPM_PATH_VALIDATION_TIMEOUT << val->retries));
}

/**
 * tquic_bpm_path_validate - Start path validation
 * @path: Path to validate
 *
 * Initiates PATH_CHALLENGE/PATH_RESPONSE exchange per RFC 9000.
 * Returns 0 on success, negative error code on failure.
 */
int tquic_bpm_path_validate(struct tquic_bpm_path *path)
{
	struct tquic_bpm_path_validation *val;
	/* int ret; unused */

	if (!path)
		return -EINVAL;

	val = &path->validation;

	spin_lock_bh(&path->state_lock);

	/* Check if already validating or validated */
	if (path->state == TQUIC_BPM_PATH_PENDING) {
		spin_unlock_bh(&path->state_lock);
		return -EINPROGRESS;
	}

	if (path->state == TQUIC_BPM_PATH_VALIDATED ||
	    path->state == TQUIC_BPM_PATH_ACTIVE) {
		spin_unlock_bh(&path->state_lock);
		return 0; /* Already valid */
	}

	/* Generate random challenge data */
	get_random_bytes(val->challenge_data, TQUIC_BPM_PATH_CHALLENGE_SIZE);

	val->retries = 0;
	val->challenge_pending = true;
	val->response_received = false;
	val->challenge_sent = ktime_get();

	path->state = TQUIC_BPM_PATH_PENDING;

	spin_unlock_bh(&path->state_lock);

	/* Start validation timer */
	mod_timer(&val->timer, jiffies + TQUIC_BPM_PATH_VALIDATION_TIMEOUT);

	pr_debug("path %u: validation started\n", path->path_id);

	return 0;
}
EXPORT_SYMBOL_GPL(tquic_bpm_path_validate);

/**
 * tquic_bpm_path_challenge_send - Get PATH_CHALLENGE data to send
 * @path: Path being validated
 * @data: Buffer to receive challenge data (8 bytes)
 *
 * Returns 0 on success with data filled, negative if no challenge pending.
 */
int tquic_bpm_path_challenge_send(struct tquic_bpm_path *path, u8 *data)
{
	struct tquic_bpm_path_validation *val;

	if (!path || !data)
		return -EINVAL;

	val = &path->validation;

	spin_lock_bh(&path->state_lock);

	if (!val->challenge_pending || path->state != TQUIC_BPM_PATH_PENDING) {
		spin_unlock_bh(&path->state_lock);
		return -ENOENT;
	}

	memcpy(data, val->challenge_data, TQUIC_BPM_PATH_CHALLENGE_SIZE);
	val->challenge_pending = false;

	spin_unlock_bh(&path->state_lock);

	pr_debug("path %u: PATH_CHALLENGE sent\n", path->path_id);

	return 0;
}
EXPORT_SYMBOL_GPL(tquic_bpm_path_challenge_send);

/**
 * tquic_bpm_path_response_recv - Process received PATH_RESPONSE
 * @path: Path being validated
 * @data: Response data received (8 bytes)
 *
 * Returns 0 on success (validation complete), negative on mismatch.
 */
int tquic_bpm_path_response_recv(struct tquic_bpm_path *path, const u8 *data)
{
	struct tquic_bpm_path_validation *val;
	ktime_t rtt;

	if (!path || !data)
		return -EINVAL;

	val = &path->validation;

	spin_lock_bh(&path->state_lock);

	if (path->state != TQUIC_BPM_PATH_PENDING) {
		spin_unlock_bh(&path->state_lock);
		return -ENOENT;
	}

	/* Verify response matches challenge (constant-time to prevent timing attacks) */
	if (crypto_memneq(data, val->challenge_data, TQUIC_BPM_PATH_CHALLENGE_SIZE)) {
		spin_unlock_bh(&path->state_lock);
		pr_debug("path %u: PATH_RESPONSE mismatch\n", path->path_id);
		return -EINVAL;
	}

	/* Validation successful */
	memcpy(val->response_data, data, TQUIC_BPM_PATH_CHALLENGE_SIZE);
	val->response_received = true;

	/* Calculate RTT from this exchange */
	rtt = ktime_sub(ktime_get(), val->challenge_sent);
	tquic_bpm_path_update_rtt(path, ktime_to_us(rtt));

	/* Stop validation timer */
	del_timer(&val->timer);

	path->state = TQUIC_BPM_PATH_VALIDATED;
	path->validated = ktime_get();
	path->consecutive_failures = 0;

	spin_unlock_bh(&path->state_lock);

	pr_info("path %u: validation complete, RTT=%lld us\n", path->path_id,
		ktime_to_us(rtt));

	/* Notify path manager */
	if (path->pm) {
		path->pm->paths_validated++;
		if (path->pm->on_path_available)
			path->pm->on_path_available(path->pm->cb_ctx, path);
	}

	return 0;
}
EXPORT_SYMBOL_GPL(tquic_bpm_path_response_recv);

/**
 * tquic_bpm_path_validation_complete - Check if path validation is complete
 * @path: Path to check
 *
 * Returns true if path is validated, false otherwise.
 */
bool tquic_bpm_path_validation_complete(struct tquic_bpm_path *path)
{
	bool complete;

	if (!path)
		return false;

	spin_lock_bh(&path->state_lock);
	complete = (path->state == TQUIC_BPM_PATH_VALIDATED ||
		    path->state == TQUIC_BPM_PATH_ACTIVE ||
		    path->state == TQUIC_BPM_PATH_STANDBY);
	spin_unlock_bh(&path->state_lock);

	tquic_dbg("path_validation_complete: path=%u complete=%d state=%d\n",
		  path->path_id, complete, path->state);
	return complete;
}
EXPORT_SYMBOL_GPL(tquic_bpm_path_validation_complete);

/*
 * ============================================================================
 * Path Manager
 * ============================================================================
 */

/**
 * tquic_bpm_init - Initialize path manager for a connection
 * @net: Network namespace
 * @gfp: Memory allocation flags
 *
 * Returns initialized path manager or NULL on failure.
 */
struct tquic_bpm_path_manager *tquic_bpm_init(struct net *net, gfp_t gfp)
{
	struct tquic_bpm_path_manager *pm;

	pm = kzalloc(sizeof(*pm), gfp);
	if (!pm)
		return NULL;

	INIT_LIST_HEAD(&pm->path_list);
	spin_lock_init(&pm->lock);
	refcount_set(&pm->refcnt, 1);

	pm->max_paths = TQUIC_MAX_PATHS;
	pm->next_path_id = 1;
	bitmap_zero(pm->path_id_bitmap, TQUIC_MAX_PATHS);

	pm->net = net;
	pm->discovery_enabled = true;
	pm->auto_failover = true;

	INIT_WORK(&pm->discover_work, tquic_bpm_discover_work_fn);
	INIT_WORK(&pm->failover_work, tquic_bpm_failover_work_fn);
	INIT_DELAYED_WORK(&pm->probe_work, tquic_bpm_probe_work_fn);

	/* Initialize bonding state machine */
	pm->bonding = tquic_bonding_init((struct tquic_path_manager *)pm, gfp);
	if (!pm->bonding) {
		kfree(pm);
		return NULL;
	}

	/* Wire up bonding callbacks */
	pm->cb_ctx = pm->bonding;
	pm->on_path_available = bpm_on_path_available;
	pm->on_path_failed = bpm_on_path_failed;

	/* Register with global list */
	spin_lock_bh(&tquic_bpm_list_lock);
	list_add_tail_rcu(&pm->path_list, &tquic_bpm_list);
	spin_unlock_bh(&tquic_bpm_list_lock);

	atomic_inc(&tquic_bpm_count);

	pr_debug("path manager initialized %p (bonding=%p)\n", pm, pm->bonding);

	return pm;
}
EXPORT_SYMBOL_GPL(tquic_bpm_init);

/**
 * tquic_bpm_destroy - Destroy path manager
 * @pm: Path manager to destroy
 */
void tquic_bpm_destroy(struct tquic_bpm_path_manager *pm)
{
	struct tquic_bpm_path *path, *tmp;

	if (!pm)
		return;

	/* Cancel all work */
	cancel_work_sync(&pm->discover_work);
	cancel_work_sync(&pm->failover_work);
	cancel_delayed_work_sync(&pm->probe_work);

	/* Remove from global list */
	spin_lock_bh(&tquic_bpm_list_lock);
	list_del_rcu(&pm->path_list);
	spin_unlock_bh(&tquic_bpm_list_lock);

	/* Free all paths */
	spin_lock_bh(&pm->lock);
	list_for_each_entry_safe(path, tmp, &pm->path_list, list) {
		list_del_init(&path->list);
		path->pm = NULL;
		tquic_bpm_path_put(path);
	}
	spin_unlock_bh(&pm->lock);

	synchronize_rcu();

	/* Destroy bonding context */
	if (pm->bonding) {
		tquic_bonding_destroy(pm->bonding);
		pm->bonding = NULL;
	}

	atomic_dec(&tquic_bpm_count);

	pr_debug("path manager destroyed %p\n", pm);

	kfree(pm);
}
EXPORT_SYMBOL_GPL(tquic_bpm_destroy);

/**
 * tquic_bpm_add_path - Add a new path to the manager
 * @pm: Path manager
 * @local: Local address
 * @remote: Remote address
 * @ifindex: Network interface index
 *
 * Returns the new path or ERR_PTR on failure.
 */
struct tquic_bpm_path *tquic_bpm_add_path(struct tquic_bpm_path_manager *pm,
				     const struct sockaddr *local,
				     const struct sockaddr *remote, int ifindex)
{
	struct tquic_bpm_path *path, *existing;
	struct tquic_addr_info local_info, remote_info;
	u32 path_id;
	int ret;

	if (!pm || !local || !remote)
		return ERR_PTR(-EINVAL);

	tquic_addr_from_sockaddr(&local_info, local);
	tquic_addr_from_sockaddr(&remote_info, remote);

	spin_lock_bh(&pm->lock);

	/* Check for existing path with same addresses */
	list_for_each_entry(existing, &pm->path_list, list) {
		if (tquic_addr_equal(&existing->local_addr, &local_info,
				     true) &&
		    tquic_addr_equal(&existing->remote_addr, &remote_info,
				     true)) {
			spin_unlock_bh(&pm->lock);
			return ERR_PTR(-EEXIST);
		}
	}

	/* Check path limit */
	if (pm->path_count >= pm->max_paths) {
		spin_unlock_bh(&pm->lock);
		return ERR_PTR(-ENOSPC);
	}

	/* Allocate path ID */
	path_id = find_first_zero_bit(pm->path_id_bitmap, TQUIC_MAX_PATHS);
	if (path_id >= TQUIC_MAX_PATHS) {
		spin_unlock_bh(&pm->lock);
		return ERR_PTR(-ENOSPC);
	}

	spin_unlock_bh(&pm->lock);

	/* Allocate and initialize path */
	path = tquic_bpm_path_alloc(GFP_KERNEL);
	if (!path)
		return ERR_PTR(-ENOMEM);

	path->path_id = path_id;
	path->pm = pm;

	ret = tquic_bpm_path_init(path, local, remote, ifindex);
	if (ret) {
		tquic_bpm_path_free(path);
		return ERR_PTR(ret);
	}

	spin_lock_bh(&pm->lock);

	/* Double-check after reacquiring lock */
	if (pm->path_count >= pm->max_paths) {
		spin_unlock_bh(&pm->lock);
		tquic_bpm_path_free(path);
		return ERR_PTR(-ENOSPC);
	}

	__set_bit(path_id, pm->path_id_bitmap);
	list_add_tail_rcu(&path->list, &pm->path_list);
	pm->path_count++;
	pm->paths_created++;

	/* First path becomes primary */
	if (!rcu_dereference_protected(pm->primary_path,
				       lockdep_is_held(&pm->lock))) {
		rcu_assign_pointer(pm->primary_path, path);
		path->is_primary = true;
	}

	spin_unlock_bh(&pm->lock);

	pr_info("path %u added: ifindex=%d wan_type=%s\n", path->path_id,
		ifindex,
		path->wan_type < __TQUIC_WAN_TYPE_MAX ?
			tquic_wan_type_names[path->wan_type] :
			"unknown");

	/* Notify bonding state machine of new path (path arg unused by callee) */
	if (pm->bonding)
		tquic_bonding_on_path_added(pm->bonding, NULL);

	return path;
}
EXPORT_SYMBOL_GPL(tquic_bpm_add_path);

/**
 * tquic_bpm_remove_path - Remove a path from the manager
 * @pm: Path manager
 * @path: Path to remove
 */
void tquic_bpm_remove_path(struct tquic_bpm_path_manager *pm,
			  struct tquic_bpm_path *path)
{
	struct tquic_bpm_path *primary, *backup, *iter;
	bool need_failover = false;

	if (!pm || !path)
		return;

	spin_lock_bh(&pm->lock);

	if (list_empty(&path->list)) {
		spin_unlock_bh(&pm->lock);
		return;
	}

	list_del_init(&path->list);
	__clear_bit(path->path_id, pm->path_id_bitmap);
	pm->path_count--;

	/* Check if we need to update primary/backup */
	primary = rcu_dereference_protected(pm->primary_path,
					    lockdep_is_held(&pm->lock));
	backup = rcu_dereference_protected(pm->backup_path,
					   lockdep_is_held(&pm->lock));

	if (primary == path) {
		/* Need to select new primary */
		if (backup) {
			rcu_assign_pointer(pm->primary_path, backup);
			backup->is_primary = true;
			backup->is_backup = false;
			rcu_assign_pointer(pm->backup_path, NULL);
			need_failover = true;
		} else {
			/* Find any validated path */
			list_for_each_entry(iter, &pm->path_list, list) {
				if (iter->state == TQUIC_BPM_PATH_VALIDATED ||
				    iter->state == TQUIC_BPM_PATH_ACTIVE) {
					rcu_assign_pointer(pm->primary_path,
							   iter);
					iter->is_primary = true;
					need_failover = true;
					break;
				}
			}
			if (!need_failover)
				rcu_assign_pointer(pm->primary_path, NULL);
		}
	} else if (backup == path) {
		rcu_assign_pointer(pm->backup_path, NULL);
	}

	spin_unlock_bh(&pm->lock);

	/* Notify bonding state machine before path removal.
	 * Synthesise a minimal tquic_path stub so bonding can account
	 * for the path's current state in its counters.
	 */
	if (pm->bonding) {
		struct tquic_path tpath = {};

		tpath.state = bpm_to_core_state(path->state);
		tquic_bonding_on_path_removed(pm->bonding, &tpath);
	}

	tquic_bpm_path_set_state(path, TQUIC_BPM_PATH_CLOSED);

	pr_info("path %u removed\n", path->path_id);

	path->pm = NULL;
	tquic_bpm_path_put(path);

	if (need_failover && pm->auto_failover)
		queue_work(tquic_bpm_wq, &pm->failover_work);
}
EXPORT_SYMBOL_GPL(tquic_bpm_remove_path);

/**
 * tquic_bpm_get_path - Get path by ID
 * @pm: Path manager
 * @path_id: Path ID to find
 *
 * Returns path with incremented reference count, or NULL if not found.
 */
struct tquic_bpm_path *tquic_bpm_get_path(struct tquic_bpm_path_manager *pm, u32 path_id)
{
	struct tquic_bpm_path *path;

	tquic_dbg("bpm_get_path: looking up path_id=%u\n", path_id);

	if (!pm)
		return NULL;

	rcu_read_lock();
	list_for_each_entry_rcu(path, &pm->path_list, list) {
		if (path->path_id == path_id) {
			tquic_bpm_path_get(path);
			rcu_read_unlock();
			return path;
		}
	}
	rcu_read_unlock();

	return NULL;
}
EXPORT_SYMBOL_GPL(tquic_bpm_get_path);

/**
 * tquic_bpm_get_active_paths - Get list of active paths
 * @pm: Path manager
 * @paths: Array to fill with path pointers
 * @max_paths: Maximum paths to return
 *
 * Returns number of active paths found.
 * Caller must call tquic_bpm_path_put() on each returned path.
 */
int tquic_bpm_get_active_paths(struct tquic_bpm_path_manager *pm,
			      struct tquic_bpm_path **paths, int max_paths)
{
	struct tquic_bpm_path *path;
	int count = 0;

	tquic_dbg("bpm_get_active_paths: max_paths=%d\n", max_paths);

	if (!pm || !paths || max_paths <= 0)
		return 0;

	rcu_read_lock();
	list_for_each_entry_rcu(path, &pm->path_list, list) {
		if (count >= max_paths)
			break;

		if (path->state == TQUIC_BPM_PATH_ACTIVE ||
		    path->state == TQUIC_BPM_PATH_VALIDATED) {
			tquic_bpm_path_get(path);
			paths[count++] = path;
		}
	}
	rcu_read_unlock();

	return count;
}
EXPORT_SYMBOL_GPL(tquic_bpm_get_active_paths);

/*
 * ============================================================================
 * Path Discovery
 * ============================================================================
 */

static bool tquic_is_wan_interface(struct net_device *dev)
{
	tquic_dbg("is_wan_interface: checking dev=%s type=%u\n",
		  dev->name, dev->type);

	/* Exclude loopback */
	if (dev->flags & IFF_LOOPBACK)
		return false;

	/* Must be up */
	if (!(dev->flags & IFF_UP))
		return false;

	/* Must have carrier */
	if (!netif_carrier_ok(dev))
		return false;

	/* Exclude certain device types */
	switch (dev->type) {
	case ARPHRD_LOOPBACK:
	case ARPHRD_SIT: /* IPv6 in IPv4 tunnel */
		return false;
	}

	/* Exclude virtual devices unless they're VPN tunnels */
	if (strncmp(dev->name, "lo", 2) == 0)
		return false;
	if (strncmp(dev->name, "docker", 6) == 0)
		return false;
	if (strncmp(dev->name, "veth", 4) == 0)
		return false;
	if (strncmp(dev->name, "br-", 3) == 0)
		return false;
	if (strncmp(dev->name, "virbr", 5) == 0)
		return false;

	return true;
}

/**
 * tquic_bpm_discover_paths - Discover available network interfaces
 * @pm: Path manager
 *
 * Scans network interfaces and adds paths for WAN-suitable interfaces.
 */
void tquic_bpm_discover_paths(struct tquic_bpm_path_manager *pm)
{
	struct net_device *dev;
	struct in_device *in_dev;
	struct inet6_dev *in6_dev;
	const struct in_ifaddr *ifa;
	struct inet6_ifaddr *ifa6;
	int count = 0;

	if (!pm || !pm->discovery_enabled)
		return;

	pr_debug("starting path discovery\n");

	rcu_read_lock();

	for_each_netdev_rcu(pm->net, dev) {
		if (!tquic_is_wan_interface(dev))
			continue;

		/* Get IPv4 addresses */
		in_dev = __in_dev_get_rcu(dev);
		if (in_dev) {
			in_dev_for_each_ifa_rcu(ifa, in_dev) {
				pr_debug("discovered interface %s addr %pI4\n",
					 dev->name, &ifa->ifa_local);

				count++;
				/* Note: actual path addition would need
				 * remote address from connection context */
			}
		}

		/* Get IPv6 addresses */
		in6_dev = __in6_dev_get(dev);
		if (in6_dev) {
			list_for_each_entry_rcu(ifa6, &in6_dev->addr_list,
						if_list) {
				/* Skip link-local addresses for WAN paths */
				if (ipv6_addr_type(&ifa6->addr) &
				    IPV6_ADDR_LINKLOCAL)
					continue;

				pr_debug("discovered interface %s addr %pI6c\n",
					 dev->name, &ifa6->addr);

				count++;
				/* Note: actual path addition would need
				 * remote address from connection context */
			}
		}
	}

	rcu_read_unlock();

	pm->last_discovery = ktime_get();

	pr_debug("path discovery complete: %d interfaces found\n", count);
}
EXPORT_SYMBOL_GPL(tquic_bpm_discover_paths);

static void tquic_bpm_discover_work_fn(struct work_struct *work)
{
	struct tquic_bpm_path_manager *pm =
		container_of(work, struct tquic_bpm_path_manager, discover_work);

	tquic_bpm_discover_paths(pm);
}

/*
 * ============================================================================
 * Network Device Notifier
 * ============================================================================
 */

/**
 * tquic_bpm_netdev_event - Handle network device events
 * @nb: Notifier block
 * @event: Event type
 * @ptr: Network device
 */
static int tquic_bpm_netdev_event(struct notifier_block *nb, unsigned long event,
				 void *ptr)
{
	struct net_device *dev = netdev_notifier_info_to_dev(ptr);
	struct tquic_bpm_path_manager *pm;
	struct tquic_bpm_path *path;
	bool found;
	int i;

	switch (event) {
	case NETDEV_UP:
		pr_debug("netdev UP: %s\n", dev->name);
		if (tquic_is_wan_interface(dev)) {
			/* Trigger discovery on all path managers */
			rcu_read_lock();
			list_for_each_entry_rcu(pm, &tquic_bpm_list, path_list) {
				if (pm->discovery_enabled)
					queue_work(tquic_bpm_wq,
						   &pm->discover_work);
			}
			rcu_read_unlock();
		}
		break;

	case NETDEV_DOWN:
		pr_debug("netdev DOWN: %s\n", dev->name);
		/*
		 * SECURITY FIX (CF-104): Mark paths on this interface as
		 * failed. Collect matching paths into a temporary list
		 * under pm->lock, then call tquic_bpm_path_set_state()
		 * outside the lock. The original code dropped and
		 * re-acquired pm->lock mid-iteration, which could corrupt
		 * the list or skip entries if the list was modified
		 * concurrently.
		 */
		rcu_read_lock();
		list_for_each_entry_rcu(pm, &tquic_bpm_list, path_list) {
			struct tquic_bpm_path *affected[TQUIC_MAX_PATHS];
			int n_affected = 0;

			spin_lock_bh(&pm->lock);
			list_for_each_entry(path, &pm->path_list, list) {
				if (path->ifindex == dev->ifindex &&
				    path->state != TQUIC_BPM_PATH_FAILED &&
				    n_affected < TQUIC_MAX_PATHS) {
					affected[n_affected++] = path;
				}
			}
			spin_unlock_bh(&pm->lock);

			for (i = 0; i < n_affected; i++) {
				tquic_bpm_path_set_state(affected[i],
							 TQUIC_BPM_PATH_FAILED);
				spin_lock_bh(&pm->lock);
				pm->paths_failed++;
				spin_unlock_bh(&pm->lock);
			}

			if (pm->auto_failover)
				queue_work(tquic_bpm_wq, &pm->failover_work);
		}
		rcu_read_unlock();
		break;

	case NETDEV_CHANGE:
		pr_debug("netdev CHANGE: %s carrier=%d\n", dev->name,
			 netif_carrier_ok(dev));

		/*
		 * SECURITY FIX (CF-104): Same collect-then-act pattern
		 * as NETDEV_DOWN to avoid list iterator invalidation.
		 */
		rcu_read_lock();
		list_for_each_entry_rcu(pm, &tquic_bpm_list, path_list) {
			struct tquic_bpm_path *fail_paths[TQUIC_MAX_PATHS];
			struct tquic_bpm_path *validate_paths[TQUIC_MAX_PATHS];
			int n_fail = 0, n_validate = 0;

			found = false;
			spin_lock_bh(&pm->lock);
			list_for_each_entry(path, &pm->path_list, list) {
				if (path->ifindex == dev->ifindex) {
					found = true;
					if (!netif_carrier_ok(dev) &&
					    path->state != TQUIC_BPM_PATH_FAILED &&
					    n_fail < TQUIC_MAX_PATHS) {
						fail_paths[n_fail++] = path;
					} else if (netif_carrier_ok(dev) &&
						   path->state ==
							TQUIC_BPM_PATH_FAILED &&
						   n_validate < TQUIC_MAX_PATHS) {
						validate_paths[n_validate++] = path;
					}
				}
			}
			spin_unlock_bh(&pm->lock);

			for (i = 0; i < n_fail; i++) {
				tquic_bpm_path_set_state(fail_paths[i],
							 TQUIC_BPM_PATH_FAILED);
				spin_lock_bh(&pm->lock);
				pm->paths_failed++;
				spin_unlock_bh(&pm->lock);
			}
			for (i = 0; i < n_validate; i++)
				tquic_bpm_path_validate(validate_paths[i]);

			if (found && pm->auto_failover)
				queue_work(tquic_bpm_wq, &pm->failover_work);
		}
		rcu_read_unlock();
		break;

	case NETDEV_CHANGEMTU:
		/* Update MTU on affected paths */
		rcu_read_lock();
		list_for_each_entry_rcu(pm, &tquic_bpm_list, path_list) {
			spin_lock_bh(&pm->lock);
			list_for_each_entry(path, &pm->path_list, list) {
				if (path->ifindex == dev->ifindex) {
					u16 new_mtu =
						min_t(u16, dev->mtu, 65535);
					if (new_mtu < TQUIC_BPM_PATH_MTU_MIN)
						new_mtu = TQUIC_BPM_PATH_MTU_MIN;
					path->mtu = new_mtu;
				}
			}
			spin_unlock_bh(&pm->lock);
		}
		rcu_read_unlock();
		break;
	}

	return NOTIFY_DONE;
}

static struct notifier_block tquic_netdev_notifier = {
	.notifier_call = tquic_bpm_netdev_event,
};

/*
 * ============================================================================
 * Connection Migration
 * ============================================================================
 */

/**
 * tquic_migrate_to_path - Migrate connection to a new path
 * @pm: Path manager
 * @new_path: Target path for migration
 *
 * Returns 0 on success, negative error code on failure.
 */
int tquic_migrate_to_path(struct tquic_bpm_path_manager *pm,
			  struct tquic_bpm_path *new_path)
{
	struct tquic_bpm_path *old_path;
	int ret;

	if (!pm || !new_path)
		return -EINVAL;

	/* Validate new path first if needed */
	if (new_path->state == TQUIC_BPM_PATH_UNUSED) {
		ret = tquic_bpm_path_validate(new_path);
		if (ret)
			return ret;
		return -EINPROGRESS; /* Will complete async */
	}

	if (new_path->state != TQUIC_BPM_PATH_VALIDATED &&
	    new_path->state != TQUIC_BPM_PATH_STANDBY) {
		return -EINVAL;
	}

	spin_lock_bh(&pm->lock);

	old_path = rcu_dereference_protected(pm->primary_path,
					     lockdep_is_held(&pm->lock));

	if (old_path == new_path) {
		spin_unlock_bh(&pm->lock);
		return 0; /* Already primary */
	}

	/* Demote old primary */
	if (old_path) {
		old_path->is_primary = false;
		if (old_path->state == TQUIC_BPM_PATH_ACTIVE)
			tquic_bpm_path_set_state(old_path, TQUIC_BPM_PATH_STANDBY);
	}

	/* Promote new path */
	rcu_assign_pointer(pm->primary_path, new_path);
	new_path->is_primary = true;
	new_path->is_backup = false;
	tquic_bpm_path_set_state(new_path, TQUIC_BPM_PATH_ACTIVE);

	/* Old primary becomes backup if still valid */
	if (old_path && old_path->state == TQUIC_BPM_PATH_STANDBY) {
		rcu_assign_pointer(pm->backup_path, old_path);
		old_path->is_backup = true;
	}

	pm->migrations++;

	spin_unlock_bh(&pm->lock);

	pr_info("migrated to path %u (was path %u)\n", new_path->path_id,
		old_path ? old_path->path_id : 0);

	/* Notify callback */
	if (pm->on_migration_complete)
		pm->on_migration_complete(pm->cb_ctx, old_path, new_path);

	return 0;
}
EXPORT_SYMBOL_GPL(tquic_migrate_to_path);

/**
 * tquic_handle_migration - Handle peer-initiated migration
 * @pm: Path manager
 * @new_remote: New remote address from peer
 *
 * Returns 0 on success, negative error code on failure.
 */
int tquic_handle_migration(struct tquic_bpm_path_manager *pm,
			   const struct sockaddr *new_remote)
{
	struct tquic_bpm_path *path;
	struct tquic_addr_info remote_info;
	bool found = false;

	tquic_dbg("handle_migration: peer-initiated migration\n");

	if (!pm || !new_remote)
		return -EINVAL;

	tquic_addr_from_sockaddr(&remote_info, new_remote);

	/* Find path matching new remote address */
	rcu_read_lock();
	list_for_each_entry_rcu(path, &pm->path_list, list) {
		if (tquic_addr_equal(&path->remote_addr, &remote_info, true)) {
			found = true;
			path->peer_migrated = true;

			/* Revalidate this path */
			if (path->state == TQUIC_BPM_PATH_VALIDATED ||
			    path->state == TQUIC_BPM_PATH_STANDBY) {
				tquic_bpm_path_get(path);
				rcu_read_unlock();
				tquic_migrate_to_path(pm, path);
				tquic_bpm_path_put(path);
				return 0;
			}
			break;
		}
	}
	rcu_read_unlock();

	if (!found) {
		/* NAT rebinding - update primary path's remote address */
		rcu_read_lock();
		path = rcu_dereference(pm->primary_path);
		if (path) {
			/*
			 * Take reference before unlocking RCU to ensure
			 * path survives beyond the RCU read section.
			 */
			tquic_bpm_path_get(path);
			rcu_read_unlock();

			spin_lock_bh(&path->state_lock);
			path->remote_addr = remote_info;
			path->nat_rebinding = true;
			spin_unlock_bh(&path->state_lock);

			/* Revalidate path with new address */
			tquic_bpm_path_validate(path);
			tquic_bpm_path_put(path);
			return 0;
		}
		rcu_read_unlock();
	}

	return found ? -EINPROGRESS : -ENOENT;
}
EXPORT_SYMBOL_GPL(tquic_handle_migration);

/*
 * ============================================================================
 * Path Selection
 * ============================================================================
 */

/**
 * tquic_bpm_select_path - Select best path for sending a packet
 * @pm: Path manager
 *
 * Returns selected path with reference, or NULL if no path available.
 * Implements weighted selection based on path quality scores.
 */
struct tquic_bpm_path *tquic_bpm_select_path(struct tquic_bpm_path_manager *pm)
{
	struct tquic_bpm_path *path, *best = NULL;
	u32 best_score = 0;
	u32 available_cwnd;

	tquic_dbg("bpm_select_path: selecting best path for sending\n");

	if (!pm)
		return NULL;

	rcu_read_lock();

	/* First, try the primary path if it has available cwnd */
	path = rcu_dereference(pm->primary_path);
	if (path && (path->state == TQUIC_BPM_PATH_ACTIVE ||
		     path->state == TQUIC_BPM_PATH_VALIDATED)) {
		available_cwnd = tquic_cc_available_cwnd(path);
		if (available_cwnd >= path->mtu) {
			tquic_bpm_path_get(path);
			rcu_read_unlock();
			return path;
		}
		best = path;
		best_score = tquic_bpm_path_get_score(path);
	}

	/* Check other paths */
	list_for_each_entry_rcu(path, &pm->path_list, list) {
		u32 score;

		if (path->state != TQUIC_BPM_PATH_ACTIVE &&
		    path->state != TQUIC_BPM_PATH_VALIDATED &&
		    path->state != TQUIC_BPM_PATH_STANDBY)
			continue;

		if (path->is_backup && best != NULL)
			continue; /* Skip backup if we have non-backup */

		available_cwnd = tquic_cc_available_cwnd(path);
		if (available_cwnd < path->mtu)
			continue; /* Skip if cwnd exhausted */

		score = tquic_bpm_path_get_score(path);
		if (score > best_score) {
			best = path;
			best_score = score;
		}
	}

	if (best)
		tquic_bpm_path_get(best);

	rcu_read_unlock();

	return best;
}
EXPORT_SYMBOL_GPL(tquic_bpm_select_path);

/*
 * ============================================================================
 * Probing and Monitoring
 * ============================================================================
 */

static void tquic_bpm_probe_work_fn(struct work_struct *work)
{
	struct delayed_work *dwork = to_delayed_work(work);
	struct tquic_bpm_path_manager *pm =
		container_of(dwork, struct tquic_bpm_path_manager, probe_work);
	struct tquic_bpm_path *path;
	ktime_t now = ktime_get();
	ktime_t threshold;

	threshold = ktime_sub_ms(now, TQUIC_BPM_PATH_PROBE_TIMEOUT * 1000 / HZ);

	rcu_read_lock();
	list_for_each_entry_rcu(path, &pm->path_list, list) {
		/* Skip paths that are being validated or already failed */
		if (path->state == TQUIC_BPM_PATH_PENDING ||
		    path->state == TQUIC_BPM_PATH_FAILED ||
		    path->state == TQUIC_BPM_PATH_CLOSED)
			continue;

		/* Check if path needs probing */
		if (ktime_before(path->last_activity, threshold)) {
			/* No recent activity, revalidate */
			tquic_bpm_path_validate(path);
		}

		/* Update signal strength for cellular paths */
		if (path->wan_type >= TQUIC_WAN_CELLULAR_3G &&
		    path->wan_type <= TQUIC_WAN_CELLULAR_5G) {
			path->signal_strength =
				tquic_wan_get_signal_strength(path->dev);
		}

		/* Update loss rate */
		tquic_bpm_path_update_loss_rate(path);
	}
	rcu_read_unlock();

	/* Reschedule */
	queue_delayed_work(tquic_bpm_wq, &pm->probe_work,
			   TQUIC_BPM_PATH_PROBE_TIMEOUT);
}

/**
 * tquic_wan_monitor_start - Start monitoring WAN interfaces
 * @pm: Path manager
 */
void tquic_wan_monitor_start(struct tquic_bpm_path_manager *pm)
{
	if (!pm)
		return;

	queue_delayed_work(tquic_bpm_wq, &pm->probe_work,
			   TQUIC_BPM_PATH_PROBE_TIMEOUT);
	pr_debug("WAN monitoring started\n");
}
EXPORT_SYMBOL_GPL(tquic_wan_monitor_start);

/*
 * ============================================================================
 * Automatic Failover
 * ============================================================================
 */

static void tquic_bpm_failover_work_fn(struct work_struct *work)
{
	struct tquic_bpm_path_manager *pm =
		container_of(work, struct tquic_bpm_path_manager, failover_work);
	struct tquic_bpm_path *primary, *backup, *best, *path;
	u32 best_score = 0;

	spin_lock_bh(&pm->lock);

	primary = rcu_dereference_protected(pm->primary_path,
					    lockdep_is_held(&pm->lock));
	backup = rcu_dereference_protected(pm->backup_path,
					   lockdep_is_held(&pm->lock));

	/* Check if primary is still valid */
	if (primary && (primary->state == TQUIC_BPM_PATH_ACTIVE ||
			primary->state == TQUIC_BPM_PATH_VALIDATED)) {
		spin_unlock_bh(&pm->lock);
		return; /* Primary is fine */
	}

	pr_info("primary path failed, initiating failover\n");

	/* Try backup first */
	if (backup && (backup->state == TQUIC_BPM_PATH_VALIDATED ||
		       backup->state == TQUIC_BPM_PATH_STANDBY)) {
		best = backup;
	} else {
		/* Find best available path */
		best = NULL;
		list_for_each_entry(path, &pm->path_list, list) {
			u32 score;

			if (path == primary)
				continue;

			if (path->state != TQUIC_BPM_PATH_VALIDATED &&
			    path->state != TQUIC_BPM_PATH_STANDBY &&
			    path->state != TQUIC_BPM_PATH_ACTIVE)
				continue;

			score = tquic_bpm_path_get_score(path);
			if (score > best_score) {
				best = path;
				best_score = score;
			}
		}
	}

	spin_unlock_bh(&pm->lock);

	if (best) {
		tquic_migrate_to_path(pm, best);
	} else {
		pr_warn("failover failed: no valid paths available\n");
	}
}

/*
 * ============================================================================
 * Module Initialization
 * ============================================================================
 */

int __init tquic_bpm_path_init_module(void)
{
	int ret;

	tquic_bpm_wq =
		alloc_workqueue("tquic_pm", WQ_MEM_RECLAIM | WQ_HIGHPRI, 0);
	if (!tquic_bpm_wq) {
		pr_err("failed to create workqueue\n");
		return -ENOMEM;
	}

	ret = register_netdevice_notifier(&tquic_netdev_notifier);
	if (ret) {
		pr_err("failed to register netdevice notifier: %d\n", ret);
		destroy_workqueue(tquic_bpm_wq);
		return ret;
	}

	pr_info("TQUIC path manager initialized\n");
	return 0;
}

void __exit tquic_bpm_path_exit_module(void)
{
	unregister_netdevice_notifier(&tquic_netdev_notifier);
	destroy_workqueue(tquic_bpm_wq);

	/* Wait for all path managers to be destroyed */
	WARN_ON(atomic_read(&tquic_bpm_count) != 0);

	pr_info("TQUIC path manager unloaded\n");
}

/* Note: module_init/exit handled by main protocol.c */
