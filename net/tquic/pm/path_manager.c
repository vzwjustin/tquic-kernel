// SPDX-License-Identifier: GPL-2.0-only
/*
 * TQUIC: Path Manager for WAN Bonding
 *
 * Copyright (c) 2026 Justin Adams <spotty118@gmail.com>
 * Kernel implementation by Justin Adams <spotty118@gmail.com>
 *
 * Manages discovery, validation, and quality monitoring of network paths
 * for multi-path WAN bonding.
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/timer.h>
#include <linux/workqueue.h>
#include <linux/random.h>
#include <crypto/utils.h>
#include <linux/netdevice.h>
#include <linux/inetdevice.h>
#include <linux/rcupdate.h>
#include <linux/rtnetlink.h>
#include <net/sock.h>
#include <net/route.h>
#include <net/addrconf.h>
#include <net/tquic.h>
#include <net/tquic_pm.h>
#include <net/tquic_pmtud.h>
#include <uapi/linux/tquic_pm.h>
#include "../tquic_compat.h"
#include "../tquic_debug.h"
#include "../cong/tquic_cong.h"
#include "../protocol.h"
#include "../core/additional_addresses.h"
#include "nat_keepalive.h"
#include "nat_lifecycle.h"
#include "path_manager.h"
#include "../tquic_preferred_addr.h"

/* Path probe configuration */
#define TQUIC_PM_PROBE_INTERVAL_MS 1000 /* 1 second */
#define TQUIC_PM_PROBE_TIMEOUT_MS 3000 /* 3 seconds */
#define TQUIC_PM_MAX_PROBES 3 /* Max probes before failure */
#define TQUIC_PM_RTT_ALPHA 8 /* SRTT smoothing factor (1/8) */
#define TQUIC_PM_RTT_BETA 4 /* RTTVAR smoothing factor (1/4) */

/* Bandwidth estimation */
#define TQUIC_PM_BW_WINDOW_MS 1000 /* 1 second window */
#define TQUIC_PM_BW_FILTER_SIZE 10 /* Max-filter size */

/* Per-path probing state */
struct tquic_path_probe {
	ktime_t sent_time;
	u8 challenge[8];
	bool pending;
	u8 attempts;
};

/*
 * tquic_path_state_names is defined in core/quic_path.c
 * and exported from there. Use the definition from the core module.
 */
extern const char *tquic_path_state_names[];

/* Forward declarations */
static int __tquic_pm_discover_addresses_locked(struct tquic_connection *conn,
						struct sockaddr_storage *addrs,
						int max_addrs);
int tquic_pm_discover_addresses(struct tquic_connection *conn,
				struct sockaddr_storage *addrs, int max_addrs);

static struct tquic_path *tquic_pm_active_path_get(struct tquic_connection *conn)
{
	struct tquic_path *path;

	rcu_read_lock();
	path = rcu_dereference(conn->active_path);
	if (path && !tquic_path_get(path))
		path = NULL;
	rcu_read_unlock();

	return path;
}

/*
 * Calculate smoothed RTT using RFC 6298 algorithm
 */
static void tquic_pm_update_rtt(struct tquic_path *path, u32 rtt_sample_us)
{
	struct tquic_path_stats *stats = &path->stats;

	tquic_dbg("tquic_pm_update_rtt: path_id=%u sample=%u us old_srtt=%u\n",
		  path->path_id, rtt_sample_us, stats->rtt_smoothed);

	if (stats->rtt_smoothed == 0) {
		/* First measurement */
		stats->rtt_smoothed = rtt_sample_us;
		stats->rtt_variance = rtt_sample_us / 2;
	} else {
		/* Update SRTT and RTTVAR */
		s32 delta = rtt_sample_us - stats->rtt_smoothed;

		stats->rtt_variance =
			stats->rtt_variance -
			(stats->rtt_variance / TQUIC_PM_RTT_BETA) +
			(abs(delta) / TQUIC_PM_RTT_BETA);

		stats->rtt_smoothed =
			stats->rtt_smoothed -
			(stats->rtt_smoothed / TQUIC_PM_RTT_ALPHA) +
			(rtt_sample_us / TQUIC_PM_RTT_ALPHA);
	}

	/* Update minimum RTT */
	if (stats->rtt_min == 0 || rtt_sample_us < stats->rtt_min)
		stats->rtt_min = rtt_sample_us;

	tquic_dbg("tquic_pm_update_rtt: path_id=%u new_srtt=%u rttvar=%u min=%u\n",
		  path->path_id, stats->rtt_smoothed, stats->rtt_variance,
		  stats->rtt_min);
}

/*
 * Estimate bandwidth using delivery rate
 */

/*
 * Send PATH_CHALLENGE frame on a path
 *
 * RFC 9000 Section 8.2: PATH_CHALLENGE frames are used to verify
 * path reachability. The 8-byte challenge data must be echoed in
 * PATH_RESPONSE.
 *
 * Uses the core tquic_send_path_challenge() from tquic_output.c
 * which handles frame construction and transmission.
 */
static int tquic_pm_send_challenge(struct tquic_connection *conn,
				   struct tquic_path *path)
{
	int ret;

	/* Use the core transmission function from tquic_output.c
	 * which generates random challenge data and sends the frame */
	ret = tquic_send_path_challenge(conn, path);
	if (ret < 0)
		return ret;

	path->probe_count++;
	path->last_activity = ktime_get();

	pr_debug("tquic_pm: sent PATH_CHALLENGE on path %u (attempt %u)\n",
		 path->path_id, path->probe_count);

	return 0;
}

/*
 * Send PATH_RESPONSE frame in reply to PATH_CHALLENGE
 *
 * RFC 9000 Section 8.2.2: Upon receipt of a PATH_CHALLENGE frame,
 * an endpoint MUST respond by echoing the data in a PATH_RESPONSE.
 *
 * Uses the core tquic_send_path_response() from tquic_output.c.
 */
/**
 * tquic_pm_challenge_rate_check - Check per-path PATH_CHALLENGE rate limit
 * @path: Path to check
 *
 * Limits PATH_RESPONSE generation to TQUIC_MAX_CHALLENGE_RESPONSES_PER_RTT
 * per smoothed RTT interval (or 1 second if no RTT estimate is available).
 * This prevents resource exhaustion from a flood of PATH_CHALLENGE frames.
 *
 * Returns: true if a PATH_RESPONSE may be sent, false if rate-limited.
 */
static bool tquic_pm_challenge_rate_check(struct tquic_path *path)
{
	ktime_t now = ktime_get();
	u64 window_us;
	s64 elapsed_us;

	/* Use smoothed RTT as window, minimum 1 second */
	window_us = path->stats.rtt_smoothed;
	if (window_us == 0)
		window_us = 1000000;  /* 1 second default */

	elapsed_us = ktime_us_delta(now, path->challenge_rate.window_start);

	/* Reset window if expired */
	if (elapsed_us >= (s64)window_us) {
		path->challenge_rate.challenge_count = 0;
		path->challenge_rate.window_start = now;
	}

	if (path->challenge_rate.challenge_count >=
	    TQUIC_MAX_CHALLENGE_RESPONSES_PER_RTT) {
		pr_debug("tquic_pm: PATH_CHALLENGE rate limited on path %u "
			 "(%u/%u in window)\n",
			 path->path_id,
			 path->challenge_rate.challenge_count,
			 TQUIC_MAX_CHALLENGE_RESPONSES_PER_RTT);
		return false;
	}

	path->challenge_rate.challenge_count++;
	return true;
}

int tquic_pm_send_response(struct tquic_connection *conn,
			   struct tquic_path *path, const u8 *challenge_data)
{
	if (!conn || !path || !challenge_data)
		return -EINVAL;

	/* Apply per-path rate limit for PATH_RESPONSE generation */
	if (!tquic_pm_challenge_rate_check(path))
		return -EAGAIN;

	/* Use the core transmission function from tquic_output.c */
	return tquic_send_path_response(conn, path, challenge_data);
}
EXPORT_SYMBOL_GPL(tquic_pm_send_response);

/*
 * Handle PATH_RESPONSE - validates the path
 */
int tquic_pm_handle_response(struct tquic_connection *conn,
			     struct tquic_path *path, const u8 *data)
{
	ktime_t now = ktime_get();
	u32 rtt_us;

	/* Verify challenge data matches (constant-time to prevent timing attacks) */
	if (crypto_memneq(data, path->challenge_data, 8)) {
		pr_debug("tquic_pm: PATH_RESPONSE mismatch on path %u\n",
			 path->path_id);
		return -EINVAL;
	}

	/* Calculate RTT */
	rtt_us = ktime_us_delta(now, path->last_activity);
	tquic_pm_update_rtt(path, rtt_us);

	/* Path is validated */
	if (path->state == TQUIC_PATH_PENDING) {
		path->state = TQUIC_PATH_ACTIVE;
		tquic_info("path %u validated (RTT: %u us)\n",
			   path->path_id, rtt_us);
	}

	path->probe_count = 0;
	path->last_activity = now;

	return 0;
}
EXPORT_SYMBOL_GPL(tquic_pm_handle_response);

/*
 * Probe all paths periodically
 *
 * Uses paths_lock when modifying path state to prevent races with
 * concurrent validation timeouts and response handlers. Probing
 * (sending PATH_CHALLENGE) is done outside the lock to avoid
 * holding the lock across potentially blocking I/O.
 */
static void tquic_pm_probe_work(struct work_struct *work)
{
	struct tquic_pm_state *pm =
		container_of(work, struct tquic_pm_state, probe_work.work);
	struct tquic_connection *conn = pm->conn;
	struct tquic_path *path;
	struct tquic_path *probe_paths[TQUIC_MAX_PATHS];
	struct tquic_path *fail_paths[TQUIC_MAX_PATHS];
	int num_probe = 0, num_fail = 0;
	ktime_t now = ktime_get();
	int i;

	/*
	 * SAFETY: Verify connection is still valid before accessing.
	 * The cleanup function calls cancel_delayed_work_sync() which
	 * ensures this work completes before pm is freed, but add
	 * defensive check.
	 */
	if (!conn) {
		pr_warn("tquic_pm: probe work called with NULL connection\n");
		return;
	}

	spin_lock_bh(&conn->paths_lock);
	list_for_each_entry(path, &conn->paths, list) {
		s64 idle_ms;

		/* Skip unused/closed paths */
		if (path->state == TQUIC_PATH_UNUSED ||
		    path->state == TQUIC_PATH_CLOSED)
			continue;

		idle_ms = ktime_ms_delta(now, path->last_activity);

		/* Check if path needs probing */
		if (idle_ms > pm->probe_interval) {
			if (path->probe_count >= TQUIC_PM_MAX_PROBES) {
				/* Path has failed */
				if (path->state != TQUIC_PATH_FAILED) {
					path->state = TQUIC_PATH_FAILED;
					if (num_fail < TQUIC_MAX_PATHS)
						fail_paths[num_fail++] = path;
				}
			} else {
				if (num_probe < TQUIC_MAX_PATHS)
					probe_paths[num_probe++] = path;
			}
		}
	}
	spin_unlock_bh(&conn->paths_lock);

	/*
	 * Send probes and notify failures outside paths_lock.
	 *
	 * Path pointers saved above were collected under paths_lock.
	 * Paths are freed via kfree_rcu() so they remain valid during
	 * an RCU read-side critical section.  Hold rcu_read_lock()
	 * while accessing the saved path pointers to prevent them
	 * from being freed underneath us.
	 */
	rcu_read_lock();
	for (i = 0; i < num_probe; i++)
		tquic_pm_send_challenge(conn, probe_paths[i]);

	/* Notify bonding layer about failures */
	for (i = 0; i < num_fail; i++) {
		tquic_warn("path %u failed after %u probes\n",
			   fail_paths[i]->path_id,
			   fail_paths[i]->probe_count);
		tquic_bond_path_failed(conn, fail_paths[i]);
	}
	rcu_read_unlock();

	/* Reschedule */
	schedule_delayed_work(&pm->probe_work,
			      msecs_to_jiffies(pm->probe_interval));
}

/*
 * Handle network device events for path discovery
 */
static int tquic_pm_netdev_event(struct notifier_block *nb, unsigned long event,
				 void *ptr)
{
	struct tquic_pm_state *pm =
		container_of(nb, struct tquic_pm_state, netdev_notifier);
	struct net_device *dev = netdev_notifier_info_to_dev(ptr);

	if (!pm->auto_discover)
		return NOTIFY_DONE;

	switch (event) {
	case NETDEV_UP:
		pr_debug("tquic_pm: interface %s came up\n", dev->name);
		/* Discover paths through this interface */
		if (pm->conn) {
			struct sockaddr_storage *addrs;
			struct sockaddr_storage remote_addr;
			struct tquic_path *apath;
			bool have_remote = false;
			int num_addrs, i;

			addrs = kmalloc_array(TQUIC_MAX_PATHS,
					      sizeof(*addrs), GFP_ATOMIC);
			if (!addrs)
				break;

			rcu_read_lock();
			apath = rcu_dereference(pm->conn->active_path);
			if (apath) {
				memcpy(&remote_addr, &apath->remote_addr,
				       sizeof(remote_addr));
				have_remote = true;
			}
			rcu_read_unlock();

			num_addrs = __tquic_pm_discover_addresses_locked(
				pm->conn, addrs, TQUIC_MAX_PATHS);
			for (i = 0; i < num_addrs; i++) {
				/* Try to add path if remote addr is known */
				if (have_remote) {
					tquic_conn_add_path(
						pm->conn,
						(struct sockaddr *)&addrs[i],
						(struct sockaddr *)&remote_addr);
				}
			}
			kfree(addrs);
		}
		break;

	case NETDEV_DOWN:
		pr_debug("tquic_pm: interface %s went down\n", dev->name);
		/*
		 * Mark paths through this specific interface as failed.
		 *
		 * Lock ordering: conn->paths_lock is acquired here.
		 * tquic_bond_path_failed() must not reacquire paths_lock;
		 * it only accesses bond/scheduler state which uses its
		 * own lock (bond->lock).  We copy failed paths into a
		 * local array so we can call tquic_bond_path_failed()
		 * outside the lock, avoiding any potential lock inversion.
		 */
		if (pm->conn) {
			struct tquic_connection *conn = pm->conn;
			struct tquic_path *path;
			struct tquic_path *failed[TQUIC_MAX_PATHS];
			int nfail = 0;
			int i;

			spin_lock_bh(&conn->paths_lock);
			list_for_each_entry(path, &conn->paths, list) {
				/*
				 * Only mark paths that actually use the
				 * interface that went down. Without this
				 * check, all active paths would be marked
				 * failed even if they use different interfaces.
				 */
				if (path->dev != dev)
					continue;

				if (path->state == TQUIC_PATH_ACTIVE ||
				    path->state == TQUIC_PATH_STANDBY) {
					path->state = TQUIC_PATH_FAILED;
					if (nfail < TQUIC_MAX_PATHS)
						failed[nfail++] = path;
					pr_debug(
						"tquic_pm: path %u failed (interface %s down)\n",
						path->path_id, dev->name);
				}
			}
			spin_unlock_bh(&conn->paths_lock);

			/* Notify bonding layer outside paths_lock */
			for (i = 0; i < nfail; i++)
				tquic_bond_path_failed(conn, failed[i]);
		}
		break;

	case NETDEV_CHANGE:
		if (netif_carrier_ok(dev)) {
			pr_debug("tquic_pm: interface %s carrier up\n",
				 dev->name);
		} else {
			pr_debug("tquic_pm: interface %s carrier down\n",
				 dev->name);
		}
		break;
	}

	return NOTIFY_OK;
}

/*
 * Discover available local addresses for path creation (locked version)
 * Caller must hold RTNL lock.
 */
static int __tquic_pm_discover_addresses_locked(struct tquic_connection *conn,
						struct sockaddr_storage *addrs,
						int max_addrs)
{
	struct net_device *dev;
	struct in_device *in_dev;
	const struct in_ifaddr *ifa;
	struct net *net;
	int count = 0;

	ASSERT_RTNL();

	/* CF-103: Use connection's namespace instead of init_net */
	net = (conn && conn->sk) ? sock_net(conn->sk) : current->nsproxy->net_ns;

	for_each_netdev(net, dev) {
		/* Skip loopback and down interfaces */
		if (dev->flags & IFF_LOOPBACK)
			continue;
		if (!(dev->flags & IFF_UP))
			continue;

		/* Get IPv4 addresses */
		in_dev = __in_dev_get_rtnl(dev);
		if (in_dev) {
			in_dev_for_each_ifa_rtnl(ifa, in_dev) {
				if (count >= max_addrs)
					break;

				struct sockaddr_in *sin =
					(struct sockaddr_in *)&addrs[count];
				sin->sin_family = AF_INET;
				sin->sin_addr.s_addr = ifa->ifa_local;
				sin->sin_port = 0;
				count++;
			}
		}

		/* Get IPv6 addresses */
#if IS_ENABLED(CONFIG_IPV6)
		{
			struct inet6_dev *idev;

			idev = __in6_dev_get(dev);
			if (idev) {
				struct inet6_ifaddr *ifp;

				read_lock_bh(&idev->lock);
				list_for_each_entry(ifp, &idev->addr_list,
						    if_list) {
					if (count >= max_addrs)
						break;
					/* Skip link-local addresses for WAN bonding */
					if (ipv6_addr_type(&ifp->addr) &
					    IPV6_ADDR_LINKLOCAL)
						continue;

					struct sockaddr_in6 *sin6 =
						(struct sockaddr_in6
							 *)&addrs[count];
					sin6->sin6_family = AF_INET6;
					sin6->sin6_addr = ifp->addr;
					sin6->sin6_port = 0;
					sin6->sin6_scope_id = 0;
					sin6->sin6_flowinfo = 0;
					count++;
				}
				read_unlock_bh(&idev->lock);
			}
		}
#endif
	}

	pr_debug("tquic_pm: discovered %d local addresses\n", count);
	return count;
}

/*
 * Discover available local addresses for path creation
 */
int tquic_pm_discover_addresses(struct tquic_connection *conn,
				struct sockaddr_storage *addrs, int max_addrs)
{
	int ret;

	rtnl_lock();
	ret = __tquic_pm_discover_addresses_locked(conn, addrs, max_addrs);
	rtnl_unlock();

	return ret;
}
EXPORT_SYMBOL_GPL(tquic_pm_discover_addresses);

/*
 * Select best path for a new subflow
 *
 * Returns a referenced path on success; caller must call tquic_path_put().
 */
struct tquic_path *tquic_pm_select_path(struct tquic_connection *conn)
{
	struct tquic_path *path, *best = NULL;
	u64 best_score = 0;

	rcu_read_lock();
	list_for_each_entry_rcu(path, &conn->paths, list) {
		u64 score;

		/* Only select validated or active paths (RFC 9000 Section 9)
		 * TQUIC_PATH_VALIDATED and TQUIC_PATH_ACTIVE are both acceptable */
		if (path->state != TQUIC_PATH_ACTIVE &&
		    path->state != TQUIC_PATH_VALIDATED)
			continue;

		/* Score based on RTT and bandwidth */
		score = path->stats.bandwidth;
		if (path->stats.rtt_smoothed > 0)
			score = score / path->stats.rtt_smoothed;

		/* Apply priority */
		score = score * (256 - path->priority) / 256;

		if (score > best_score) {
			best_score = score;
			best = path;
		}
	}
	if (best && !tquic_path_get(best))
		best = NULL;
	rcu_read_unlock();

	return best ?: tquic_pm_active_path_get(conn);
}
EXPORT_SYMBOL_GPL(tquic_pm_select_path);

/*
 * Update path quality metrics after receiving packet
 */
void tquic_path_update_stats(struct tquic_path *path, struct sk_buff *skb,
			     bool success)
{
	ktime_t now = ktime_get();

	if (success) {
		path->stats.rx_packets++;
		path->stats.rx_bytes += skb->len;
	} else {
		path->stats.lost_packets++;
	}

	path->last_activity = now;

	/* Reset NAT keepalive timer on path activity (RFC 9308) */
	if (success)
		tquic_nat_keepalive_on_activity(path);
}
EXPORT_SYMBOL_GPL(tquic_path_update_stats);

/*
 * Set path weight for scheduling
 */
int tquic_path_set_weight(struct tquic_path *path, u8 weight)
{
	tquic_dbg("tquic_path_set_weight: path_id=%u weight=%u\n",
		  path->path_id, weight);

	if (weight == 0)
		return -EINVAL;

	path->weight = weight;
	return 0;
}
EXPORT_SYMBOL_GPL(tquic_path_set_weight);

/*
 * Initialize path manager for a connection
 */
struct tquic_pm_state *tquic_pm_init(struct tquic_connection *conn)
{
	struct tquic_pm_state *pm;

	pm = kzalloc(sizeof(*pm), GFP_KERNEL);
	if (!pm)
		return NULL;

	pm->conn = conn;
	pm->probe_interval = TQUIC_PM_PROBE_INTERVAL_MS;
	pm->auto_discover = false; /* Manual path management by default */
	pm->prefer_ipv6 = false;

	INIT_DELAYED_WORK(&pm->probe_work, tquic_pm_probe_work);

	/* Start probing */
	schedule_delayed_work(&pm->probe_work,
			      msecs_to_jiffies(pm->probe_interval));

	pr_debug("tquic_pm: initialized path manager\n");

	return pm;
}
EXPORT_SYMBOL_GPL(tquic_pm_init);

/*
 * Enable interface monitoring for auto-discovery
 */
int tquic_pm_enable_monitoring(struct tquic_pm_state *pm)
{
	int ret;

	if (pm->monitoring)
		return 0;

	pm->netdev_notifier.notifier_call = tquic_pm_netdev_event;
	ret = register_netdevice_notifier(&pm->netdev_notifier);
	if (ret)
		return ret;

	pm->monitoring = true;
	pm->auto_discover = true;

	pr_info("tquic_pm: enabled interface monitoring\n");
	return 0;
}
EXPORT_SYMBOL_GPL(tquic_pm_enable_monitoring);

/*
 * Cleanup path manager
 */
void tquic_pm_cleanup(struct tquic_pm_state *pm)
{
	if (!pm)
		return;

	tquic_dbg("tquic_pm_cleanup: monitoring=%d auto_discover=%d\n",
		  pm->monitoring, pm->auto_discover);

	cancel_delayed_work_sync(&pm->probe_work);

	if (pm->monitoring)
		unregister_netdevice_notifier(&pm->netdev_notifier);

	tquic_dbg("tquic_pm_cleanup: path manager released\n");

	kfree(pm);
}
EXPORT_SYMBOL_GPL(tquic_pm_cleanup);

/*
 * Path validation - send challenge and wait for response
 */
int tquic_path_probe(struct tquic_connection *conn, struct tquic_path *path)
{
	tquic_dbg("tquic_path_probe: initiating probe on path_id=%u\n",
		  path->path_id);

	path->state = TQUIC_PATH_PENDING;
	path->probe_count = 0;

	return tquic_pm_send_challenge(conn, path);
}
EXPORT_SYMBOL_GPL(tquic_path_probe);

/*
 * Mark path as validated (e.g., after receiving PATH_RESPONSE)
 */
void tquic_path_validate(struct tquic_connection *conn, struct tquic_path *path)
{
	if (path->state == TQUIC_PATH_PENDING) {
		path->state = TQUIC_PATH_ACTIVE;
		path->probe_count = 0;

			/* Inform bonding layer */
			if (conn->scheduler &&
			    test_bit(TQUIC_F_BONDING_ENABLED, &conn->flags)) {
				struct tquic_bond_state *bond = conn->scheduler;
				bond->stats.active_paths++;
			}

		pr_info("tquic_pm: path %u validated\n", path->path_id);
	}
}
EXPORT_SYMBOL_GPL(tquic_path_validate);

/*
 * Helper: Get path by ID with lock held
 */
struct tquic_path *tquic_conn_get_path_locked(struct tquic_connection *conn,
					      u32 path_id)
{
	struct tquic_path *path;

	list_for_each_entry(path, &conn->paths, list) {
		if (path->path_id == path_id)
			return path;
	}

	return NULL;
}
EXPORT_SYMBOL_GPL(tquic_conn_get_path_locked);

/**
 * tquic_pm_get_path - Get path by ID from path manager state
 * @pm: Path manager state
 * @path_id: Path ID to look up
 *
 * Looks up a path by its ID using the connection's path list.
 * Uses paths_lock for safe access, ensuring the returned pointer
 * remains valid even after the function returns.
 *
 * Caller must be prepared that the path may be freed after this
 * returns if it doesn't hold paths_lock or otherwise prevent removal.
 * For RCU-safe lookup, use tquic_conn_get_path_locked() with paths_lock held.
 *
 * Return: Pointer to path if found, NULL otherwise
 */
struct tquic_path *tquic_pm_get_path(struct tquic_pm_state *pm, u32 path_id)
{
	struct tquic_path *path;
	struct tquic_path *found = NULL;

	if (!pm || !pm->conn)
		return NULL;

	spin_lock_bh(&pm->conn->paths_lock);
	list_for_each_entry(path, &pm->conn->paths, list) {
		if (path->path_id == path_id) {
			if (tquic_path_get(path))
				found = path;
			break;
		}
	}
	spin_unlock_bh(&pm->conn->paths_lock);

	return found;
}
EXPORT_SYMBOL_GPL(tquic_pm_get_path);

/*
 * NOTE: tquic_pm_get_active_paths is defined at end of file to avoid
 * duplicate symbol errors. See the implementation near MODULE_DESCRIPTION.
 */

/*
 * Calculate bytes in-flight on a specific path
 *
 * In-flight bytes = transmitted bytes - acknowledged bytes
 * This tracks data that has been sent but not yet confirmed received.
 */
static u64 tquic_path_inflight_bytes(struct tquic_path *path)
{
	u64 tx = path->stats.tx_bytes;
	u64 acked = path->stats.acked_bytes;
	u64 inflight;

	if (tx > acked)
		inflight = tx - acked;
	else
		inflight = 0;

	tquic_dbg("tquic_path_inflight_bytes: path_id=%u tx=%llu acked=%llu inflight=%llu\n",
		  path->path_id, tx, acked, inflight);

	return inflight;
}

/*
 * Check if path has any unacknowledged data
 */
static bool tquic_path_has_inflight(struct tquic_path *path)
{
	bool has = tquic_path_inflight_bytes(path) > 0 ||
		   path->stats.tx_packets >
			   (path->stats.rx_packets + path->stats.lost_packets);

	tquic_dbg("tquic_path_has_inflight: path_id=%u has_inflight=%d\n",
		  path->path_id, has);

	return has;
}

/*
 * Drain in-flight data from path before removal
 *
 * This function waits for all in-flight data on a path to be acknowledged
 * or timed out before the path can be safely removed. This prevents data
 * loss when migrating away from a path.
 *
 * Per RFC 9000 Section 9.3.3: "An endpoint that has not validated a peer's
 * address is unable to send to that address. Until that address is validated,
 * packets can be sent to the previously validated address."
 *
 * We wait up to 5 seconds (approximately 3x typical PTO) for:
 *   1. All transmitted bytes to be acknowledged, OR
 *   2. Loss detection to declare packets lost, OR
 *   3. Timeout expiry (hard limit to prevent indefinite blocking)
 */
static void tquic_path_drain_data(struct tquic_connection *conn,
				  struct tquic_path *path)
{
	unsigned long timeout = jiffies + msecs_to_jiffies(5000);
	unsigned long check_interval_ms = 50; /* Start with 50ms checks */
	u64 last_inflight = 0;
	u64 current_inflight;
	int stall_count = 0;

	pr_debug("tquic: draining data from path %u (inflight=%llu bytes)\n",
		 path->path_id, tquic_path_inflight_bytes(path));

	while (time_before(jiffies, timeout)) {
		current_inflight = tquic_path_inflight_bytes(path);

		/* Path fully drained - all data acknowledged */
		if (!tquic_path_has_inflight(path)) {
			pr_debug(
				"tquic: path %u drain complete (all data acked)\n",
				path->path_id);
			return;
		}

		/* Check for progress - inflight should be decreasing */
		if (current_inflight == last_inflight) {
			stall_count++;
			/*
			 * If no progress for 500ms (10 checks), assume lost packets
			 * have been retransmitted on another path
			 */
			if (stall_count > 10) {
				pr_debug(
					"tquic: path %u drain stalled, continuing (inflight=%llu)\n",
					path->path_id, current_inflight);
				return;
			}
		} else {
			stall_count = 0;
			last_inflight = current_inflight;
		}

		/*
		 * Use exponential backoff for check interval to reduce
		 * CPU overhead while waiting for slow drains
		 */
		msleep(check_interval_ms);
		if (check_interval_ms < 200)
			check_interval_ms += 25;
	}

	pr_warn("tquic: path %u drain timeout (remaining inflight=%llu bytes)\n",
		path->path_id, tquic_path_inflight_bytes(path));
}

/*
 * Initialize path structure
 */
static struct tquic_path *tquic_path_alloc(struct tquic_connection *conn,
					   struct sockaddr *local,
					   struct sockaddr *remote)
{
	struct tquic_path *path;

	path = kmem_cache_zalloc(tquic_path_cache, GFP_KERNEL);
	if (!path)
		return NULL;

	/* CF-477: Use per-connection counter instead of global static */
	refcount_set(&path->refcnt, 1);
	path->conn = conn;
	path->path_id = 0;
	path->state = TQUIC_PATH_UNUSED;
	path->saved_state = TQUIC_PATH_UNUSED;

	/* Copy addresses */
	if (local)
		memcpy(&path->local_addr, local,
		       local->sa_family == AF_INET ?
			       sizeof(struct sockaddr_in) :
			       sizeof(struct sockaddr_in6));

	if (remote)
		memcpy(&path->remote_addr, remote,
		       remote->sa_family == AF_INET ?
			       sizeof(struct sockaddr_in) :
			       sizeof(struct sockaddr_in6));

	/* Determine network device for this path (for interface tracking) */
	if (local && local->sa_family == AF_INET && conn->sk) {
		struct sockaddr_in *sin = (struct sockaddr_in *)local;
		struct net *net = sock_net(conn->sk);
		struct net_device *dev, *found_dev = NULL;

		rcu_read_lock();
		for_each_netdev_rcu(net, dev) {
			struct in_device *in_dev = __in_dev_get_rcu(dev);
			const struct in_ifaddr *ifa;

			if (!in_dev)
				continue;

			in_dev_for_each_ifa_rcu(ifa, in_dev) {
				if (ifa->ifa_local == sin->sin_addr.s_addr) {
					found_dev = dev;
					break;
				}
			}
			if (found_dev)
				break;
		}
		if (found_dev) {
			path->dev = found_dev;
			dev_hold(path->dev);
		}
		rcu_read_unlock();
	}

	/* Initialize validation timer */
	timer_setup(&path->validation_timer, tquic_path_validation_expired, 0);
	timer_setup(&path->validation.timer, tquic_path_validation_timeout, 0);

	/* Initialize response queue */
	skb_queue_head_init(&path->response.queue);
	atomic_set(&path->response.count, 0);

	/*
	 * Anti-amplification state (RFC 9000 Section 8.1).
	 * New paths start with limits active until validated.
	 */
	atomic64_set(&path->anti_amplification.bytes_received, 0);
	atomic64_set(&path->anti_amplification.bytes_sent, 0);
	path->anti_amplification.active = true;

	/* Initialize challenge rate limiting */
	path->challenge_rate.challenge_count = 0;
	path->challenge_rate.window_start = ktime_get();

	/* Default MTU (will be updated via PMTU discovery) */
	path->mtu = 1200;
	path->priority = 0;
	path->weight = 1;

	INIT_LIST_HEAD(&path->list);

	return path;
}

static int tquic_conn_alloc_path_id_locked(struct tquic_connection *conn)
{
	bool used[TQUIC_MAX_PATHS] = { 0 };
	struct tquic_path *path;
	u32 id;
	int ret;

	tquic_dbg("tquic_conn_alloc_path_id_locked: num_paths=%u\n",
		  conn->num_paths);

	list_for_each_entry(path, &conn->paths, list) {
		if (path->path_id < TQUIC_MAX_PATHS)
			used[path->path_id] = true;
	}

	for (id = 0; id < TQUIC_MAX_PATHS; id++) {
		if (!used[id]) {
			tquic_dbg("tquic_conn_alloc_path_id_locked: allocated id=%u\n",
				  id);
			return id;
		}
	}

	ret = -ENOSPC;
	tquic_dbg("tquic_conn_alloc_path_id_locked: no free id, ret=%d\n",
		  ret);

	return ret;
}

/*
 * Initialize validation state for a path
 */
static void tquic_path_init_validation(struct tquic_path *path)
{
	tquic_dbg("tquic_path_init_validation: path_id=%u\n",
		  path->path_id);

	path->validation.challenge_pending = false;
	path->validation.retries = 0;
	memset(path->validation.challenge_data, 0,
	       sizeof(path->validation.challenge_data));
}

/*
 * RCU-safe path addition
 */
int tquic_conn_add_path_safe(struct tquic_connection *conn,
			     struct sockaddr *local, struct sockaddr *remote)
{
	struct tquic_path *path;
	int path_id;
	int ret;

	if (!conn || !local || !remote)
		return -EINVAL;

	/* Check limits */
	spin_lock_bh(&conn->paths_lock);
	if (conn->num_paths >= conn->max_paths) {
		spin_unlock_bh(&conn->paths_lock);
		return -ENOSPC;
	}
	spin_unlock_bh(&conn->paths_lock);

	/* Allocate path structure */
	path = tquic_path_alloc(conn, local, remote);
	if (!path)
		return -ENOMEM;

	/* Initialize validation state (timer, queue) */
	tquic_path_init_validation(path);

	/* Initialize multipath ACK state (RFC 9369) */
#ifdef CONFIG_TQUIC_MULTIPATH
	{
		extern struct tquic_mp_path_ack_state *tquic_mp_ack_state_create(
			struct tquic_path *);
		path->mp_ack_state = tquic_mp_ack_state_create(path);
		if (!path->mp_ack_state)
			pr_warn("tquic: failed to init MP ACK state for path %u\n",
				path->path_id);
	}
#endif

	/* Initialize congestion control for this path */
	ret = tquic_cong_init_path(path, NULL); /* NULL = use default CC */
	if (ret) {
		pr_warn("tquic: failed to init CC for path %u: %d\n",
			path->path_id, ret);
		/* Continue without CC - not fatal */
	}

	/* Initialize PMTUD for this path (RFC 8899) */
	ret = tquic_pmtud_init_path(path);
	if (ret) {
		pr_warn("tquic: failed to init PMTUD for path %u: %d\n",
			path->path_id, ret);
		/* Continue without PMTUD - not fatal */
	}

	/* Initialize NAT keepalive for this path (RFC 9308 Section 3.5) */
	ret = tquic_nat_keepalive_init(path, conn);
	if (ret) {
		pr_warn("tquic: failed to init NAT keepalive for path %u: %d\n",
			path->path_id, ret);
		/* Continue without NAT keepalive - not fatal */
	}

	/* Initialize NAT lifecycle management for this path */
	ret = tquic_nat_lifecycle_init(path, conn);
	if (ret) {
		pr_debug(
			"tquic: NAT lifecycle init for path %u: %d (optional)\n",
			path->path_id, ret);
		/* Continue without lifecycle - it's optional */
	}

	/* Add to connection's path list with RCU */
	spin_lock_bh(&conn->paths_lock);
	if (conn->num_paths >= conn->max_paths) {
		spin_unlock_bh(&conn->paths_lock);
		del_timer_sync(&path->validation.timer);
		skb_queue_purge(&path->response.queue);
		tquic_nat_lifecycle_cleanup(path);
		tquic_nat_keepalive_cleanup(path);
		tquic_pmtud_release_path(path);
		tquic_cong_release_path(path);
#ifdef CONFIG_TQUIC_MULTIPATH
		{
			extern void tquic_mp_ack_state_destroy(void *);
			extern void tquic_mp_abandon_state_destroy(void *);
			if (path->mp_ack_state)
				tquic_mp_ack_state_destroy(path->mp_ack_state);
			if (path->abandon_state)
				tquic_mp_abandon_state_destroy(path->abandon_state);
		}
#endif
		if (path->dev)
			dev_put(path->dev);
		kmem_cache_free(tquic_path_cache, path);
		return -ENOSPC;
	}

	path_id = tquic_conn_alloc_path_id_locked(conn);
	if (path_id < 0) {
		spin_unlock_bh(&conn->paths_lock);
		del_timer_sync(&path->validation.timer);
		skb_queue_purge(&path->response.queue);
		tquic_nat_lifecycle_cleanup(path);
		tquic_nat_keepalive_cleanup(path);
		tquic_pmtud_release_path(path);
		tquic_cong_release_path(path);
#ifdef CONFIG_TQUIC_MULTIPATH
		{
			extern void tquic_mp_ack_state_destroy(void *);
			extern void tquic_mp_abandon_state_destroy(void *);
			if (path->mp_ack_state)
				tquic_mp_ack_state_destroy(path->mp_ack_state);
			if (path->abandon_state)
				tquic_mp_abandon_state_destroy(path->abandon_state);
		}
#endif
		if (path->dev)
			dev_put(path->dev);
		kmem_cache_free(tquic_path_cache, path);
		return path_id;
	}
	path->path_id = path_id;
	list_add_tail_rcu(&path->list, &conn->paths);
	conn->num_paths++;
	spin_unlock_bh(&conn->paths_lock);

	/* Start validation asynchronously */
	ret = tquic_path_start_validation(conn, path);
	if (ret < 0)
		pr_debug("tquic: path validation start failed: %d\n", ret);

	/* Emit event via PM netlink */
	if (conn && conn->sk)
		tquic_pm_nl_send_event(sock_net(conn->sk), conn, path,
				       TQUIC_PM_EVENT_CREATED);

	tquic_info("added path %u (%pISpc -> %pISpc)\n", path->path_id,
		   &path->local_addr, &path->remote_addr);

	return path->path_id;
}
EXPORT_SYMBOL_GPL(tquic_conn_add_path_safe);

/*
 * RCU-safe path removal
 */
int tquic_conn_remove_path_safe(struct tquic_connection *conn, u32 path_id)
{
	struct tquic_path *path;

	if (!conn)
		return -EINVAL;

	spin_lock_bh(&conn->paths_lock);
	path = tquic_conn_get_path_locked(conn, path_id);
	if (!path) {
		spin_unlock_bh(&conn->paths_lock);
		return -ENOENT;
	}

	/* Don't remove the active path */
	if (path == rcu_access_pointer(conn->active_path)) {
		spin_unlock_bh(&conn->paths_lock);
		return -EBUSY;
	}

	/* Mark as closing and detach from the path list atomically. */
	path->state = TQUIC_PATH_CLOSED;
	list_del_rcu(&path->list);
	if (conn->num_paths > 0)
		conn->num_paths--;
	spin_unlock_bh(&conn->paths_lock);

	/* Stop validation timers before waiting for drain completion. */
	del_timer_sync(&path->validation_timer);
	del_timer_sync(&path->validation.timer);

	/* Drain in-flight data (wait for ACKs or timeout) */
	tquic_path_drain_data(conn, path);

	/*
	 * Wait for pre-existing RCU readers that may still hold @path from
	 * the connection path list before tearing down subordinate state.
	 */
	synchronize_rcu();

	/* Emit removal event via PM netlink */
	if (conn && conn->sk)
		tquic_pm_nl_send_event(sock_net(conn->sk), conn, path,
				       TQUIC_PM_EVENT_REMOVED);

	/* Purge response queue */
	skb_queue_purge(&path->response.queue);

	/* Release congestion control state */
	tquic_cong_release_path(path);

	/* Release PMTUD state */
	tquic_pmtud_release_path(path);

	/* Release NAT lifecycle state */
	tquic_nat_lifecycle_cleanup(path);

	/* Release NAT keepalive state (RFC 9308 Section 3.5) */
	tquic_nat_keepalive_cleanup(path);

	/* Release multipath state (RFC 9369) */
#ifdef CONFIG_TQUIC_MULTIPATH
	{
		extern void tquic_mp_ack_state_destroy(void *);
		extern void tquic_mp_abandon_state_destroy(void *);
		if (path->mp_ack_state)
			tquic_mp_ack_state_destroy(path->mp_ack_state);
		if (path->abandon_state)
			tquic_mp_abandon_state_destroy(path->abandon_state);
	}
#endif

	/* Release device reference */
	if (path->dev)
		dev_put(path->dev);

	/* Free after RCU grace period */
	kfree_rcu(path, rcu_head);

	tquic_info("removed path %u\n", path_id);

	return 0;
}
EXPORT_SYMBOL_GPL(tquic_conn_remove_path_safe);

/**
 * tquic_conn_lookup_by_token - Find a connection by its unique token
 * @net: Network namespace to search in
 * @token: The connection token to search for (assigned during connection setup)
 *
 * This function is used by the netlink interface and diagnostics subsystem
 * to locate a TQUIC connection by its unique 32-bit token. The token is
 * generated using get_random_u32() when the connection's path manager is
 * initialized and serves as a stable identifier for external interfaces.
 *
 * The function iterates through the per-netns connection list under
 * tn->conn_lock. If a matching connection is found, its reference count is
 * incremented before returning to ensure the connection remains valid while
 * the caller uses it.
 *
 * Context: Can be called from process context or soft-IRQ context.
 *          Uses spin_lock_bh() internally.
 *
 * Return: Pointer to the connection with a reference held, or NULL if not found.
 *         Caller must call tquic_conn_put() when done with the connection.
 */
struct tquic_connection *tquic_conn_lookup_by_token(struct net *net, u32 token)
{
	struct tquic_net *tn;
	struct tquic_connection *conn;

	if (!net)
		return NULL;

	tn = tquic_pernet(net);
	if (!tn)
		return NULL;

	/*
	 * Iterate under the per-netns connection lock.
	 * refcount_inc_not_zero() avoids handing out dying connections.
	 */
	spin_lock_bh(&tn->conn_lock);
	list_for_each_entry(conn, &tn->connections, pm_node) {
		if (conn->token != token)
			continue;

		if (refcount_inc_not_zero(&conn->refcnt)) {
			spin_unlock_bh(&tn->conn_lock);
			return conn;
		}

		/* Token collision path: keep searching. */
	}
	spin_unlock_bh(&tn->conn_lock);

	return NULL;
}
EXPORT_SYMBOL_GPL(tquic_conn_lookup_by_token);

/*
 * Flush all paths from connection
 *
 * Removes all non-active paths from the connection's path list.
 * Must acquire paths_lock to prevent races with concurrent path
 * additions, removals, and RCU readers.
 */
void tquic_conn_flush_paths(struct tquic_connection *conn)
{
	struct tquic_path *path, *tmp;
	struct tquic_path *removed[TQUIC_MAX_PATHS];
	int nremoved = 0;
	int i;

	tquic_dbg("tquic_conn_flush_paths: flushing non-active paths, num_paths=%u\n",
		  conn->num_paths);

	spin_lock_bh(&conn->paths_lock);
	list_for_each_entry_safe(path, tmp, &conn->paths, list) {
		/* Don't remove active path */
		if (path == rcu_access_pointer(conn->active_path))
			continue;

		list_del_rcu(&path->list);
		if (conn->num_paths > 0)
			conn->num_paths--;
		if (nremoved < ARRAY_SIZE(removed))
			removed[nremoved++] = path;
	}
	spin_unlock_bh(&conn->paths_lock);

	/* Free paths after RCU grace period */
	synchronize_rcu();
	for (i = 0; i < nremoved; i++) {
		path = removed[i];
		del_timer_sync(&path->validation_timer);
		del_timer_sync(&path->validation.timer);
		skb_queue_purge(&path->response.queue);
		tquic_cong_release_path(path);
		tquic_pmtud_release_path(path);
		tquic_nat_lifecycle_cleanup(path);
		tquic_nat_keepalive_cleanup(path);
#ifdef CONFIG_TQUIC_MULTIPATH
		{
			extern void tquic_mp_ack_state_destroy(void *);
			extern void tquic_mp_abandon_state_destroy(void *);
			if (path->mp_ack_state)
				tquic_mp_ack_state_destroy(path->mp_ack_state);
			if (path->abandon_state)
				tquic_mp_abandon_state_destroy(path->abandon_state);
		}
#endif
		if (path->dev)
			dev_put(path->dev);
		kfree_rcu(path, rcu_head);
	}

	tquic_dbg("tquic_conn_flush_paths: flushed %d paths\n", nremoved);
}
EXPORT_SYMBOL_GPL(tquic_conn_flush_paths);

/*
 * =============================================================================
 * NAT Rebinding Detection with Address Discovery Integration
 * =============================================================================
 *
 * These functions integrate with the Address Discovery extension
 * (draft-ietf-quic-address-discovery) to detect NAT rebinding events
 * and optionally send OBSERVED_ADDRESS frames to the peer.
 */

#include "../core/address_discovery.h"
#include "path_manager.h"

/**
 * tquic_pm_check_address_change - Check for address changes on packet receipt
 * @conn: Connection that received the packet
 * @from_addr: Source address the packet was received from
 * @path: Path the packet was received on
 *
 * Called from the receive path when a packet arrives. Checks if the source
 * address differs from the expected path address, indicating NAT rebinding.
 * If address discovery is enabled and the address changed, sends an
 * OBSERVED_ADDRESS frame to the peer.
 *
 * Return: true if address changed (NAT rebinding detected), false otherwise
 */
bool tquic_pm_check_address_change(struct tquic_connection *conn,
				   const struct sockaddr_storage *from_addr,
				   struct tquic_path *path)
{
	struct tquic_addr_discovery_state *ad_state;
	bool changed = false;
	bool nat_rebind;

	if (!conn || !from_addr || !path)
		return false;

	/* Get address discovery state from connection */
	ad_state = conn->addr_discovery_state;
	if (!ad_state)
		return false;

	/* Check for NAT rebinding using address discovery module */
	nat_rebind = tquic_detect_nat_rebinding(conn, ad_state, from_addr);

	if (nat_rebind) {
		pr_info("tquic_pm: NAT rebinding detected on path %u\n",
			path->path_id);

		/* Update the observed address */
		tquic_update_observed_address(ad_state, from_addr, &changed);

		/* Send OBSERVED_ADDRESS to peer if enabled */
		if (ad_state->config.enabled &&
		    ad_state->config.report_on_change) {
			int ret = tquic_send_observed_address(conn, ad_state,
							      from_addr);
			if (ret == -EAGAIN) {
				pr_debug(
					"tquic_pm: OBSERVED_ADDRESS rate limited\n");
			} else if (ret < 0) {
				pr_debug(
					"tquic_pm: failed to send OBSERVED_ADDRESS: %d\n",
					ret);
			}
		}

		/*
		 * Update path's remote address and trigger re-validation.
		 *
		 * RFC 9000 Section 9.3: An endpoint MUST perform path
		 * validation if it detects any change to a peer's address.
		 * Until the new path is validated, the endpoint MUST limit
		 * data sent to the new address (anti-amplification).
		 */
		spin_lock_bh(&conn->paths_lock);
		memcpy(&path->remote_addr, from_addr, sizeof(*from_addr));

		/* Save current state and set to pending for re-validation */
		if (path->state == TQUIC_PATH_ACTIVE ||
		    path->state == TQUIC_PATH_STANDBY ||
		    path->state == TQUIC_PATH_VALIDATED) {
			path->saved_state = path->state;
			path->state = TQUIC_PATH_PENDING;
		}

		/* Enable anti-amplification limits on the new address */
		atomic64_set(&path->anti_amplification.bytes_received, 0);
		atomic64_set(&path->anti_amplification.bytes_sent, 0);
		path->anti_amplification.active = true;
		spin_unlock_bh(&conn->paths_lock);

		/* Start path validation to the new address */
		tquic_path_start_validation(conn, path);
	}

	return nat_rebind;
}
EXPORT_SYMBOL_GPL(tquic_pm_check_address_change);

/**
 * tquic_pm_notify_observed_address - Notify peer of their observed address
 * @conn: Connection
 * @path: Path to send on
 *
 * Sends an OBSERVED_ADDRESS frame to the peer to inform them of the address
 * we observe for their packets. This is useful for helping peers detect
 * NAT rebinding or discover their public address.
 *
 * Return: 0 on success, negative error code on failure
 */
int tquic_pm_notify_observed_address(struct tquic_connection *conn,
				     struct tquic_path *path)
{
	struct tquic_addr_discovery_state *ad_state;

	if (!conn || !path)
		return -EINVAL;

	ad_state = conn->addr_discovery_state;
	if (!ad_state || !ad_state->config.enabled)
		return -ENOENT;

	return tquic_send_observed_address(conn, ad_state, &path->remote_addr);
}
EXPORT_SYMBOL_GPL(tquic_pm_notify_observed_address);

/**
 * tquic_pm_init_address_discovery - Initialize address discovery for connection
 * @conn: Connection to initialize
 *
 * Allocates and initializes the address discovery state for a connection.
 * Should be called during connection setup after transport parameter negotiation.
 *
 * Return: 0 on success, negative error code on failure
 */
int tquic_pm_init_address_discovery(struct tquic_connection *conn)
{
	struct tquic_addr_discovery_state *state;
	int ret;

	if (!conn)
		return -EINVAL;

	/* Already initialized? */
	if (conn->addr_discovery_state)
		return 0;

	state = kzalloc(sizeof(*state), GFP_KERNEL);
	if (!state)
		return -ENOMEM;

	ret = tquic_addr_discovery_init(state);
	if (ret < 0) {
		kfree(state);
		return ret;
	}

	/* Enable if negotiated */
	if (conn->negotiated_params &&
	    conn->negotiated_params->address_discovery_enabled) {
		state->config.enabled = true;
		state->config.report_on_change = true;
	}

	conn->addr_discovery_state = state;

	pr_debug("tquic_pm: address discovery initialized (enabled=%d)\n",
		 state->config.enabled);

	return 0;
}
EXPORT_SYMBOL_GPL(tquic_pm_init_address_discovery);

/**
 * tquic_pm_cleanup_address_discovery - Clean up address discovery state
 * @conn: Connection to clean up
 */
void tquic_pm_cleanup_address_discovery(struct tquic_connection *conn)
{
	struct tquic_addr_discovery_state *state;

	if (!conn)
		return;

	state = conn->addr_discovery_state;
	if (!state)
		return;

	tquic_dbg("tquic_pm_cleanup_address_discovery: releasing address discovery state\n");

	tquic_addr_discovery_cleanup(state);
	kfree(state);
	conn->addr_discovery_state = NULL;
}
EXPORT_SYMBOL_GPL(tquic_pm_cleanup_address_discovery);

/*
 * =============================================================================
 * Additional Addresses Path Manager Integration
 * (draft-piraux-quic-additional-addresses)
 * =============================================================================
 *
 * These functions integrate the additional_addresses transport parameter
 * extension with the path manager for seamless path creation and validation.
 */

/**
 * tquic_pm_init_additional_addresses - Initialize additional addresses for connection
 * @conn: Connection to initialize
 *
 * Allocates and initializes the additional addresses subsystem for the
 * connection. Should be called during connection setup.
 *
 * Return: 0 on success, negative error code on failure
 */
int tquic_pm_init_additional_addresses(struct tquic_connection *conn)
{
	struct net *net;

	if (!conn || !conn->sk)
		return -EINVAL;

	net = sock_net(conn->sk);

	/* Check if additional addresses is enabled via sysctl */
	if (!tquic_additional_addr_enabled(net)) {
		pr_debug("tquic_pm: additional addresses disabled\n");
		return 0;
	}

	return tquic_additional_addr_conn_init(conn);
}
EXPORT_SYMBOL_GPL(tquic_pm_init_additional_addresses);

/**
 * tquic_pm_cleanup_additional_addresses - Clean up additional addresses state
 * @conn: Connection to clean up
 */
void tquic_pm_cleanup_additional_addresses(struct tquic_connection *conn)
{
	if (!conn)
		return;

	tquic_dbg("tquic_pm_cleanup_additional_addresses: releasing additional addresses state\n");

	tquic_additional_addr_conn_cleanup(conn);
}
EXPORT_SYMBOL_GPL(tquic_pm_cleanup_additional_addresses);

/**
 * tquic_pm_add_local_additional_address - Add a local address to advertise
 * @conn: Connection
 * @addr: Local address to advertise
 * @cid: Connection ID for this address (or NULL to auto-generate)
 *
 * Adds a local address to the list of additional addresses that will be
 * advertised to the peer in the transport parameters.
 *
 * Return: 0 on success, negative error code on failure
 */
int tquic_pm_add_local_additional_address(struct tquic_connection *conn,
					  const struct sockaddr_storage *addr,
					  const struct tquic_cid *cid)
{
	struct tquic_additional_addresses *local_addrs;
	struct tquic_cid auto_cid;
	u8 ip_version;
	int ret;

	if (!conn || !addr)
		return -EINVAL;

	/* Initialize if needed */
	if (!conn->additional_local_addrs) {
		ret = tquic_additional_addr_conn_init(conn);
		if (ret < 0)
			return ret;
	}

	local_addrs = conn->additional_local_addrs;
	if (!local_addrs)
		return -EINVAL;

	/* Determine IP version */
	if (addr->ss_family == AF_INET)
		ip_version = TQUIC_ADDR_IP_VERSION_4;
	else if (addr->ss_family == AF_INET6)
		ip_version = TQUIC_ADDR_IP_VERSION_6;
	else
		return -EAFNOSUPPORT;

	/* Auto-generate CID if not provided */
	if (!cid || cid->len == 0) {
		auto_cid.len = 8; /* Default CID length */
		get_random_bytes(auto_cid.id, auto_cid.len);
		cid = &auto_cid;

		/*
		 * The auto-generated CID is registered via tquic_additional_addr_add()
		 * below, which stores the CID with the address entry. The connection's
		 * cid_pool handles CID-to-path mapping for incoming packet routing.
		 */
	}

	ret = tquic_additional_addr_add(local_addrs, ip_version, addr, cid,
					NULL);
	if (ret < 0)
		return ret;

	pr_info("tquic_pm: added local additional address (IPv%u, total=%u)\n",
		ip_version, local_addrs->count);

	return 0;
}
EXPORT_SYMBOL_GPL(tquic_pm_add_local_additional_address);

/**
 * tquic_pm_remove_local_additional_address - Remove a local additional address
 * @conn: Connection
 * @addr: Address to remove
 *
 * Return: 0 on success, negative error code on failure
 */
int tquic_pm_remove_local_additional_address(
	struct tquic_connection *conn, const struct sockaddr_storage *addr)
{
	struct tquic_additional_addresses *local_addrs;

	if (!conn || !addr)
		return -EINVAL;

	local_addrs = conn->additional_local_addrs;
	if (!local_addrs)
		return -ENOENT;

	return tquic_additional_addr_remove(local_addrs, addr);
}
EXPORT_SYMBOL_GPL(tquic_pm_remove_local_additional_address);

/**
 * tquic_pm_create_path_to_additional - Create path to a remote additional address
 * @conn: Connection
 * @addr_entry: Remote additional address entry
 *
 * Creates a new path to the specified remote additional address and
 * optionally starts path validation.
 *
 * Return: New path on success, ERR_PTR on failure
 */
struct tquic_path *
tquic_pm_create_path_to_additional(struct tquic_connection *conn,
				   struct tquic_additional_address *addr_entry)
{
	struct tquic_path *path;
	struct tquic_path *active_path;
	struct sockaddr_storage local_addr;

	if (!conn || !addr_entry)
		return ERR_PTR(-EINVAL);

	/* Validate address */
	if (!addr_entry->active) {
		pr_debug("tquic_pm: additional address not active\n");
		return ERR_PTR(-EINVAL);
	}

	/* Get local address */
	rcu_read_lock();
	active_path = rcu_dereference(conn->active_path);
	if (active_path) {
		memcpy(&local_addr, &active_path->local_addr,
		       sizeof(local_addr));
	} else {
		/* Use any local address of matching family */
		memset(&local_addr, 0, sizeof(local_addr));
		local_addr.ss_family = addr_entry->addr.ss_family;
	}
	rcu_read_unlock();

	/* Create path */
	path = tquic_path_create(conn, &local_addr, &addr_entry->addr);
	if (!path)
		return ERR_PTR(-ENOMEM);

	/* Set remote CID from the additional address */
	memcpy(&path->remote_cid, &addr_entry->cid, sizeof(addr_entry->cid));

	/*
	 * The stateless reset token from addr_entry is associated with the
	 * remote CID. Stateless reset detection uses the cid_pool to verify
	 * tokens when a potential reset packet is received.
	 */

	pr_debug("tquic_pm: created path %u to additional address\n",
		 path->path_id);

	return path;
}
EXPORT_SYMBOL_GPL(tquic_pm_create_path_to_additional);

/**
 * tquic_pm_validate_additional_address - Validate a remote additional address
 * @conn: Connection
 * @addr_entry: Address entry to validate
 *
 * Creates a path to the additional address and starts PATH_CHALLENGE
 * validation without switching traffic to it.
 *
 * Return: 0 on success, negative error code on failure
 */
int tquic_pm_validate_additional_address(
	struct tquic_connection *conn,
	struct tquic_additional_address *addr_entry)
{
	struct tquic_path *path;
	int ret;

	if (!conn || !addr_entry)
		return -EINVAL;

	/* Already validated? */
	if (addr_entry->validated)
		return 0;

	/* Create path */
	path = tquic_pm_create_path_to_additional(conn, addr_entry);
	if (IS_ERR(path))
		return PTR_ERR(path);

	/* Start validation */
	ret = tquic_path_start_validation(conn, path);
	if (ret < 0) {
		tquic_path_free(path);
		return ret;
	}

	pr_debug("tquic_pm: started validation for additional address\n");

	return 0;
}
EXPORT_SYMBOL_GPL(tquic_pm_validate_additional_address);

/**
 * tquic_pm_get_best_additional_address - Get best additional address for migration
 * @conn: Connection
 * @policy: Selection policy
 *
 * Returns the best additional address according to the specified policy.
 * Does NOT initiate migration - caller should use the returned entry
 * with tquic_migrate_to_additional_address() if migration is desired.
 *
 * Return: Best address entry, or NULL if none available
 */
struct tquic_additional_address *
tquic_pm_get_best_additional_address(struct tquic_connection *conn,
				     enum tquic_addr_select_policy policy)
{
	struct tquic_additional_addresses *remote_addrs;
	struct tquic_path *active_path;
	struct tquic_additional_address *best;
	sa_family_t current_family = AF_UNSPEC;

	if (!conn)
		return NULL;

	remote_addrs = conn->additional_remote_addrs;
	if (!remote_addrs || remote_addrs->count == 0)
		return NULL;

	rcu_read_lock();
	active_path = rcu_dereference(conn->active_path);
	if (active_path) {
		current_family = active_path->remote_addr.ss_family;
	}
	rcu_read_unlock();

	spin_lock_bh(&remote_addrs->lock);
	best = tquic_additional_addr_select(remote_addrs, policy,
					    current_family);
	spin_unlock_bh(&remote_addrs->lock);

	return best;
}
EXPORT_SYMBOL_GPL(tquic_pm_get_best_additional_address);

/**
 * tquic_pm_on_path_validated_additional - Handle path validation for additional addresses
 * @conn: Connection
 * @path: Validated path
 *
 * Called from the path validation completion handler when a path to
 * an additional address is successfully validated.
 */
void tquic_pm_on_path_validated_additional(struct tquic_connection *conn,
					   struct tquic_path *path)
{
	struct tquic_additional_addresses *remote_addrs;
	struct tquic_additional_address *addr_entry;

	if (!conn || !path)
		return;

	remote_addrs = conn->additional_remote_addrs;
	if (!remote_addrs)
		return;

	spin_lock_bh(&remote_addrs->lock);
	addr_entry =
		tquic_additional_addr_find(remote_addrs, &path->remote_addr);
	if (addr_entry) {
		tquic_additional_addr_validate(addr_entry);

		/* Update RTT estimate */
		if (path->stats.rtt_smoothed > 0)
			tquic_additional_addr_update_rtt(
				addr_entry, path->stats.rtt_smoothed);
	}
	spin_unlock_bh(&remote_addrs->lock);
}
EXPORT_SYMBOL_GPL(tquic_pm_on_path_validated_additional);

/**
 * tquic_pm_on_path_failed_additional - Handle path failure for additional addresses
 * @conn: Connection
 * @path: Failed path
 *
 * Called when path validation or connectivity to an additional address fails.
 */
void tquic_pm_on_path_failed_additional(struct tquic_connection *conn,
					struct tquic_path *path)
{
	struct tquic_additional_addresses *remote_addrs;
	struct tquic_additional_address *addr_entry;

	if (!conn || !path)
		return;

	remote_addrs = conn->additional_remote_addrs;
	if (!remote_addrs)
		return;

	spin_lock_bh(&remote_addrs->lock);
	addr_entry =
		tquic_additional_addr_find(remote_addrs, &path->remote_addr);
	if (addr_entry)
		tquic_additional_addr_invalidate(addr_entry);
	spin_unlock_bh(&remote_addrs->lock);
}
EXPORT_SYMBOL_GPL(tquic_pm_on_path_failed_additional);

/**
 * tquic_pm_coordinate_preferred_and_additional - Coordinate preferred and additional addresses
 * @conn: Connection
 *
 * Coordinates migration decisions between the preferred_address transport
 * parameter (RFC 9000) and additional_addresses extension. This ensures
 * that both mechanisms work together properly.
 *
 * Priority:
 * 1. If preferred_address is available and not yet migrated, prefer it
 * 2. If preferred_address migration failed or completed, consider additional addresses
 * 3. Use RTT and policy to select among additional addresses
 *
 * Return: Selected address type (0=none, 1=preferred, 2=additional)
 */
int tquic_pm_coordinate_preferred_and_additional(struct tquic_connection *conn)
{
	struct tquic_pref_addr_migration *pref_migration;
	struct tquic_additional_addresses *remote_addrs;
	enum tquic_pref_addr_state pref_state;
	int ret;

	if (!conn)
		return 0;

	tquic_dbg("tquic_pm_coordinate_preferred_and_additional: evaluating migration options\n");

	/* Check preferred address state */
	pref_migration = conn->preferred_addr;
	if (pref_migration) {
		pref_state = pref_migration->state;

		/* Prefer preferred_address if available and not yet tried */
		if (pref_state == TQUIC_PREF_ADDR_AVAILABLE) {
			tquic_dbg("tquic_pm_coordinate_preferred_and_additional: using preferred address\n");
			return 1; /* Use preferred address */
		}

		/* If preferred address is validating, wait for it */
		if (pref_state == TQUIC_PREF_ADDR_VALIDATING) {
			tquic_dbg("tquic_pm_coordinate_preferred_and_additional: preferred address validating\n");
			return 1;
		}

		/* Preferred address already migrated or failed */
	}

	/* Check additional addresses */
	remote_addrs = conn->additional_remote_addrs;
	if (remote_addrs && remote_addrs->count > 0) {
		struct tquic_additional_address *entry;
		bool has_validated = false;
		bool has_active = false;

		spin_lock_bh(&remote_addrs->lock);
		list_for_each_entry(entry, &remote_addrs->addresses, list) {
			if (entry->active)
				has_active = true;
			if (entry->validated)
				has_validated = true;
		}
		spin_unlock_bh(&remote_addrs->lock);

		if (has_validated || has_active) {
			tquic_dbg("tquic_pm_coordinate_preferred_and_additional: using additional addresses\n");
			return 2; /* Use additional addresses */
		}
	}

	tquic_dbg("tquic_pm_coordinate_preferred_and_additional: no migration option available\n");

	return 0; /* No migration option available */
}
EXPORT_SYMBOL_GPL(tquic_pm_coordinate_preferred_and_additional);

/* tquic_pm_get_path defined earlier in file (line ~588) */

int tquic_pm_get_active_paths(struct tquic_pm_state *pm,
			      struct tquic_path **paths, int max_paths)
{
	struct tquic_pm_state *state = pm;
	struct tquic_connection *conn;
	struct tquic_path *path;
	int count = 0;

	if (!state || !paths || max_paths <= 0)
		return 0;

	conn = state->conn;
	if (!conn)
		return 0;

	/* Caller must hold rcu_read_lock() while consuming returned pointers. */
	spin_lock_bh(&conn->paths_lock);
	list_for_each_entry(path, &conn->paths, list) {
		if (path->state == TQUIC_PATH_ACTIVE ||
		    path->state == TQUIC_PATH_VALIDATED ||
		    path->state == TQUIC_PATH_STANDBY) {
			paths[count++] = path;
			if (count >= max_paths)
				break;
		}
	}
	spin_unlock_bh(&conn->paths_lock);

	return count;
}
EXPORT_SYMBOL_GPL(tquic_pm_get_active_paths);

MODULE_DESCRIPTION("TQUIC Path Manager for WAN Bonding");
MODULE_LICENSE("GPL");
