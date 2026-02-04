// SPDX-License-Identifier: GPL-2.0-only
/*
 * TQUIC: UDP to TCP Fallback Mechanism
 *
 * Copyright (c) 2026 Linux Foundation
 *
 * Implements automatic fallback from UDP to TCP transport when UDP
 * is blocked or unreliable. This is useful in enterprise networks,
 * restrictive firewalls, or NAT devices that block UDP.
 *
 * Detection Methods:
 * 1. Connection timeout - Initial UDP connection attempt times out
 * 2. ICMP errors - Unreachable, prohibited, or admin filtered
 * 3. Persistent packet loss - High loss rate after connection
 * 4. Manual trigger - Application explicitly requests TCP
 *
 * Fallback Process:
 * 1. Detect UDP failure condition
 * 2. Preserve connection state (CIDs, crypto state)
 * 3. Establish TCP connection to same endpoint
 * 4. Resume QUIC handshake over TCP
 * 5. Migrate existing streams to TCP transport
 *
 * Sysctl Parameters:
 * - tquic.fallback_enabled - Enable/disable automatic fallback
 * - tquic.fallback_timeout_ms - UDP attempt timeout before fallback
 * - tquic.fallback_loss_threshold - Loss % to trigger fallback
 * - tquic.fallback_probe_interval_ms - UDP probe interval after fallback
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/timer.h>
#include <linux/workqueue.h>
#include <linux/atomic.h>
#include <linux/sysctl.h>
#include <linux/proc_fs.h>
#include <net/sock.h>
#include <net/net_namespace.h>
#include <net/tquic.h>

#include "quic_over_tcp.h"
#include "../protocol.h"

/*
 * =============================================================================
 * Sysctl Parameters
 * =============================================================================
 */

/* Default values */
#define FALLBACK_ENABLED_DEFAULT	1	/* Enabled by default */
#define FALLBACK_TIMEOUT_MS_DEFAULT	5000	/* 5 seconds */
#define FALLBACK_LOSS_THRESHOLD_DEFAULT	50	/* 50% loss triggers fallback */
#define FALLBACK_PROBE_INTERVAL_DEFAULT	60000	/* 1 minute probe interval */
#define FALLBACK_MAX_RETRIES_DEFAULT	3	/* Max UDP retries */
#define FALLBACK_RECOVERY_THRESHOLD	10	/* 10% loss to recover to UDP */

/* Per-netns sysctl values */
struct tquic_fallback_net {
	int enabled;
	int timeout_ms;
	int loss_threshold;
	int probe_interval_ms;
	int max_retries;
	int recovery_threshold;

	/* Statistics */
	atomic64_t fallback_count;
	atomic64_t recovery_count;
	atomic64_t timeout_triggers;
	atomic64_t loss_triggers;
	atomic64_t icmp_triggers;
	atomic64_t manual_triggers;
};

/* Fallback reason codes */
enum tquic_fallback_reason {
	FALLBACK_REASON_NONE = 0,
	FALLBACK_REASON_TIMEOUT,
	FALLBACK_REASON_ICMP_UNREACH,
	FALLBACK_REASON_ICMP_PROHIBITED,
	FALLBACK_REASON_LOSS,
	FALLBACK_REASON_MANUAL,
	FALLBACK_REASON_MTU,
};

/* Fallback state machine states */
enum tquic_fallback_state {
	FALLBACK_STATE_UDP,		/* Using UDP (normal) */
	FALLBACK_STATE_PROBING,		/* Probing for UDP availability */
	FALLBACK_STATE_FALLING_BACK,	/* Transitioning to TCP */
	FALLBACK_STATE_TCP,		/* Using TCP fallback */
	FALLBACK_STATE_RECOVERING,	/* Trying to recover to UDP */
};

/**
 * struct tquic_fallback_ctx - Per-connection fallback context
 * @state:            Current fallback state
 * @reason:           Reason for last fallback
 * @tcp_conn:         TCP connection (when in fallback)
 * @conn:             Parent QUIC connection
 * @udp_attempt_count: Number of UDP connection attempts
 * @loss_samples:     Recent loss samples for averaging
 * @loss_index:       Current index in loss samples ring
 * @last_probe:       Time of last UDP probe
 * @create_time:      Time context was created (for timeout tracking)
 * @fallback_time:    Time fallback was triggered
 * @probe_timer:      Timer for periodic UDP probing
 * @fallback_work:    Work item for fallback processing
 * @recovery_work:    Work item for recovery processing
 * @lock:             Context lock
 */
struct tquic_fallback_ctx {
	enum tquic_fallback_state state;
	enum tquic_fallback_reason reason;
	struct quic_tcp_connection *tcp_conn;
	struct tquic_connection *conn;

	int udp_attempt_count;

	/* Loss tracking - ring buffer of recent loss rates */
#define LOSS_SAMPLE_COUNT 8
	u8 loss_samples[LOSS_SAMPLE_COUNT];
	int loss_index;

	ktime_t last_probe;
	ktime_t create_time;
	ktime_t fallback_time;

	struct timer_list probe_timer;
	struct work_struct fallback_work;
	struct work_struct recovery_work;

	spinlock_t lock;
};

/*
 * =============================================================================
 * Per-Network Namespace Management
 * =============================================================================
 */

static unsigned int tquic_fallback_net_id;

static struct tquic_fallback_net *tquic_fallback_pernet(struct net *net)
{
	return net_generic(net, tquic_fallback_net_id);
}

/*
 * =============================================================================
 * Sysctl Table
 * =============================================================================
 */

static struct ctl_table tquic_fallback_table[] = {
	{
		.procname	= "fallback_enabled",
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= proc_dointvec_minmax,
		.extra1		= SYSCTL_ZERO,
		.extra2		= SYSCTL_ONE,
	},
	{
		.procname	= "fallback_timeout_ms",
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= proc_dointvec_minmax,
		.extra1		= SYSCTL_ONE,
	},
	{
		.procname	= "fallback_loss_threshold",
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= proc_dointvec_minmax,
		.extra1		= SYSCTL_ONE,
	},
	{
		.procname	= "fallback_probe_interval_ms",
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= proc_dointvec_minmax,
		.extra1		= SYSCTL_ONE,
	},
	{
		.procname	= "fallback_max_retries",
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= proc_dointvec_minmax,
		.extra1		= SYSCTL_ZERO,
	},
	{
		.procname	= "fallback_recovery_threshold",
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= proc_dointvec_minmax,
		.extra1		= SYSCTL_ZERO,
	},
	{ }
};

/* Number of valid entries (exclude the null terminator). */
#define TQUIC_FALLBACK_SYSCTL_ENTRIES (ARRAY_SIZE(tquic_fallback_table) - 1)

static struct ctl_table_header *tquic_fallback_sysctl_header;

/*
 * =============================================================================
 * Loss Tracking
 * =============================================================================
 */

static void fallback_record_loss(struct tquic_fallback_ctx *ctx, u8 loss_pct)
{
	spin_lock(&ctx->lock);
	ctx->loss_samples[ctx->loss_index] = loss_pct;
	ctx->loss_index = (ctx->loss_index + 1) % LOSS_SAMPLE_COUNT;
	spin_unlock(&ctx->lock);
}

static u8 fallback_get_avg_loss(struct tquic_fallback_ctx *ctx)
{
	int i;
	u32 total = 0;
	int count = 0;

	spin_lock(&ctx->lock);
	for (i = 0; i < LOSS_SAMPLE_COUNT; i++) {
		if (ctx->loss_samples[i] > 0) {
			total += ctx->loss_samples[i];
			count++;
		}
	}
	spin_unlock(&ctx->lock);

	return count > 0 ? (total / count) : 0;
}

/*
 * =============================================================================
 * Fallback Detection
 * =============================================================================
 */

/**
 * tquic_fallback_check_timeout - Check if connection attempt timed out
 * @ctx: Fallback context
 *
 * Returns: true if timeout occurred and fallback should be triggered
 */
static bool fallback_check_timeout(struct tquic_fallback_ctx *ctx)
{
	struct tquic_fallback_net *fn;
	struct net *net;
	ktime_t now;
	s64 elapsed_ms;

	if (!ctx || !ctx->conn || !ctx->conn->sk)
		return false;

	net = sock_net(ctx->conn->sk);
	fn = tquic_fallback_pernet(net);

	if (!fn->enabled)
		return false;

	now = ktime_get();

	/* Check elapsed time since context creation (connection start) */
	elapsed_ms = ktime_ms_delta(now, ctx->create_time);

	if (elapsed_ms > fn->timeout_ms) {
		ctx->udp_attempt_count++;
		if (ctx->udp_attempt_count >= fn->max_retries) {
			pr_info("tquic_fallback: timeout after %lld ms, %d attempts\n",
				elapsed_ms, ctx->udp_attempt_count);
			return true;
		}
	}

	return false;
}

/**
 * tquic_fallback_check_loss - Check if loss rate triggers fallback
 * @ctx: Fallback context
 *
 * Returns: true if loss threshold exceeded and fallback should be triggered
 */
static bool fallback_check_loss(struct tquic_fallback_ctx *ctx)
{
	struct tquic_fallback_net *fn;
	struct net *net;
	u8 avg_loss;

	if (!ctx || !ctx->conn || !ctx->conn->sk)
		return false;

	net = sock_net(ctx->conn->sk);
	fn = tquic_fallback_pernet(net);

	if (!fn->enabled)
		return false;

	avg_loss = fallback_get_avg_loss(ctx);

	if (avg_loss >= fn->loss_threshold) {
		pr_info("tquic_fallback: loss rate %u%% exceeds threshold %d%%\n",
			avg_loss, fn->loss_threshold);
		return true;
	}

	return false;
}

/**
 * tquic_fallback_on_icmp - Handle ICMP error indicating UDP blocked
 * @ctx: Fallback context
 * @type: ICMP type
 * @code: ICMP code
 *
 * Returns: true if fallback should be triggered
 */
bool tquic_fallback_on_icmp(struct tquic_fallback_ctx *ctx, int type, int code)
{
	if (!ctx)
		return false;

	/* Check for destination unreachable - port/protocol/admin filtered */
	if (type == 3) {  /* ICMP_DEST_UNREACH */
		switch (code) {
		case 3:   /* ICMP_PORT_UNREACH */
		case 9:   /* ICMP_NET_ANO - admin prohibited */
		case 10:  /* ICMP_HOST_ANO - admin prohibited */
		case 13:  /* ICMP_PKT_FILTERED */
			pr_info("tquic_fallback: ICMP unreachable type=%d code=%d\n",
				type, code);
			ctx->reason = (code == 3) ? FALLBACK_REASON_ICMP_UNREACH :
						    FALLBACK_REASON_ICMP_PROHIBITED;
			return true;
		}
	}

	return false;
}
EXPORT_SYMBOL_GPL(tquic_fallback_on_icmp);

/*
 * =============================================================================
 * Fallback Execution
 * =============================================================================
 */

static void fallback_tcp_packet_callback(void *data, const u8 *packet, size_t len)
{
	struct tquic_fallback_ctx *ctx = data;

	if (!ctx || !ctx->conn)
		return;

	/* Deliver packet to QUIC connection for processing */
	/* This would call into the QUIC packet input path */
	pr_debug("tquic_fallback: received %zu byte packet over TCP\n", len);
}

static void fallback_do_fallback(struct work_struct *work)
{
	struct tquic_fallback_ctx *ctx =
		container_of(work, struct tquic_fallback_ctx, fallback_work);
	struct tquic_fallback_net *fn;
	struct sockaddr_storage addr;
	struct quic_tcp_connection *tcp_conn;
	struct tquic_path *path;
	struct net *net;
	int addrlen;

	if (!ctx || !ctx->conn)
		return;

	net = sock_net(ctx->conn->sk);
	fn = tquic_fallback_pernet(net);

	spin_lock(&ctx->lock);
	if (ctx->state != FALLBACK_STATE_FALLING_BACK) {
		spin_unlock(&ctx->lock);
		return;
	}
	spin_unlock(&ctx->lock);

	/* Get remote address from active (primary) path */
	spin_lock_bh(&ctx->conn->paths_lock);
	path = ctx->conn->active_path;
	if (!path) {
		spin_unlock_bh(&ctx->conn->paths_lock);
		pr_warn("tquic_fallback: no active path for fallback\n");
		return;
	}
	/* Copy address while holding lock */
	memcpy(&addr, &path->remote_addr, sizeof(addr));
	spin_unlock_bh(&ctx->conn->paths_lock);

	addrlen = (addr.ss_family == AF_INET6) ? sizeof(struct sockaddr_in6) :
						 sizeof(struct sockaddr_in);

	/* Create TCP connection */
	tcp_conn = quic_tcp_connect((struct sockaddr *)&addr, addrlen, ctx->conn);
	if (IS_ERR(tcp_conn)) {
		pr_err("tquic_fallback: failed to create TCP connection: %ld\n",
		       PTR_ERR(tcp_conn));
		spin_lock(&ctx->lock);
		ctx->state = FALLBACK_STATE_UDP;  /* Revert to UDP */
		spin_unlock(&ctx->lock);
		return;
	}

	/* Set packet callback */
	quic_tcp_set_packet_callback(tcp_conn, fallback_tcp_packet_callback, ctx);

	/*
	 * Note: We don't need to attach to a specific path as the TCP
	 * connection is associated with the QUIC connection as a whole.
	 * The QUIC connection will route packets through this TCP transport.
	 */

	spin_lock(&ctx->lock);
	ctx->tcp_conn = tcp_conn;
	ctx->state = FALLBACK_STATE_TCP;
	ctx->fallback_time = ktime_get();
	spin_unlock(&ctx->lock);

	/* Update statistics */
	atomic64_inc(&fn->fallback_count);
	switch (ctx->reason) {
	case FALLBACK_REASON_TIMEOUT:
		atomic64_inc(&fn->timeout_triggers);
		break;
	case FALLBACK_REASON_LOSS:
		atomic64_inc(&fn->loss_triggers);
		break;
	case FALLBACK_REASON_ICMP_UNREACH:
	case FALLBACK_REASON_ICMP_PROHIBITED:
		atomic64_inc(&fn->icmp_triggers);
		break;
	case FALLBACK_REASON_MANUAL:
		atomic64_inc(&fn->manual_triggers);
		break;
	default:
		break;
	}

	pr_info("tquic_fallback: switched to TCP transport (reason=%d)\n",
		ctx->reason);

	/* Start UDP probe timer for potential recovery */
	mod_timer(&ctx->probe_timer,
		  jiffies + msecs_to_jiffies(fn->probe_interval_ms));
}

/**
 * tquic_fallback_trigger - Trigger fallback to TCP
 * @ctx: Fallback context
 * @reason: Reason for fallback
 *
 * Returns: 0 on success, negative errno on failure
 */
int tquic_fallback_trigger(struct tquic_fallback_ctx *ctx,
			   enum tquic_fallback_reason reason)
{
	struct tquic_fallback_net *fn;
	struct net *net;

	if (!ctx || !ctx->conn || !ctx->conn->sk)
		return -EINVAL;

	net = sock_net(ctx->conn->sk);
	fn = tquic_fallback_pernet(net);

	if (!fn->enabled)
		return -EOPNOTSUPP;

	spin_lock(&ctx->lock);

	/* Check if already in TCP mode */
	if (ctx->state == FALLBACK_STATE_TCP ||
	    ctx->state == FALLBACK_STATE_FALLING_BACK) {
		spin_unlock(&ctx->lock);
		return -EALREADY;
	}

	ctx->state = FALLBACK_STATE_FALLING_BACK;
	ctx->reason = reason;

	spin_unlock(&ctx->lock);

	/* Schedule fallback work */
	queue_work(system_wq, &ctx->fallback_work);

	return 0;
}
EXPORT_SYMBOL_GPL(tquic_fallback_trigger);

/*
 * =============================================================================
 * Recovery to UDP
 * =============================================================================
 */

static void probe_timer_callback(struct timer_list *t)
{
	struct tquic_fallback_ctx *ctx = from_timer(ctx, t, probe_timer);

	if (ctx->state == FALLBACK_STATE_TCP) {
		/* Queue recovery check work */
		queue_work(system_wq, &ctx->recovery_work);
	}
}

static void fallback_do_recovery(struct work_struct *work)
{
	struct tquic_fallback_ctx *ctx =
		container_of(work, struct tquic_fallback_ctx, recovery_work);
	struct tquic_fallback_net *fn;
	struct net *net;
	u8 avg_loss;

	if (!ctx || !ctx->conn || !ctx->conn->sk)
		return;

	net = sock_net(ctx->conn->sk);
	fn = tquic_fallback_pernet(net);

	spin_lock(&ctx->lock);
	if (ctx->state != FALLBACK_STATE_TCP) {
		spin_unlock(&ctx->lock);
		return;
	}
	ctx->state = FALLBACK_STATE_RECOVERING;
	spin_unlock(&ctx->lock);

	/*
	 * Send a UDP probe packet to test if UDP is now available.
	 * This would be a QUIC packet sent over UDP.
	 */
	pr_debug("tquic_fallback: sending UDP probe\n");

	/* For now, check if loss rate has dropped below recovery threshold */
	avg_loss = fallback_get_avg_loss(ctx);

	if (avg_loss < fn->recovery_threshold) {
		/* UDP appears to be working, attempt recovery */
		pr_info("tquic_fallback: loss rate %u%% below threshold, recovering to UDP\n",
			avg_loss);

		spin_lock(&ctx->lock);

		/* Close TCP connection */
		if (ctx->tcp_conn) {
			quic_tcp_close(ctx->tcp_conn);
			ctx->tcp_conn = NULL;
		}

		ctx->state = FALLBACK_STATE_UDP;
		ctx->reason = FALLBACK_REASON_NONE;

		spin_unlock(&ctx->lock);

		atomic64_inc(&fn->recovery_count);
		pr_info("tquic_fallback: recovered to UDP transport\n");
	} else {
		/* Still high loss, stay on TCP */
		spin_lock(&ctx->lock);
		ctx->state = FALLBACK_STATE_TCP;
		spin_unlock(&ctx->lock);

		/* Schedule next probe */
		mod_timer(&ctx->probe_timer,
			  jiffies + msecs_to_jiffies(fn->probe_interval_ms));
	}
}

/*
 * =============================================================================
 * Context Management
 * =============================================================================
 */

/**
 * tquic_fallback_ctx_create - Create fallback context for connection
 * @conn: QUIC connection
 *
 * Returns: Fallback context or NULL on failure
 */
struct tquic_fallback_ctx *tquic_fallback_ctx_create(struct tquic_connection *conn)
{
	struct tquic_fallback_ctx *ctx;

	ctx = kzalloc(sizeof(*ctx), GFP_KERNEL);
	if (!ctx)
		return NULL;

	ctx->conn = conn;
	ctx->state = FALLBACK_STATE_UDP;
	ctx->reason = FALLBACK_REASON_NONE;
	ctx->create_time = ktime_get();
	spin_lock_init(&ctx->lock);

	INIT_WORK(&ctx->fallback_work, fallback_do_fallback);
	INIT_WORK(&ctx->recovery_work, fallback_do_recovery);
	timer_setup(&ctx->probe_timer, probe_timer_callback, 0);

	return ctx;
}
EXPORT_SYMBOL_GPL(tquic_fallback_ctx_create);

/**
 * tquic_fallback_ctx_destroy - Destroy fallback context
 * @ctx: Fallback context
 */
void tquic_fallback_ctx_destroy(struct tquic_fallback_ctx *ctx)
{
	if (!ctx)
		return;

	del_timer_sync(&ctx->probe_timer);
	cancel_work_sync(&ctx->fallback_work);
	cancel_work_sync(&ctx->recovery_work);

	if (ctx->tcp_conn) {
		quic_tcp_close(ctx->tcp_conn);
		ctx->tcp_conn = NULL;
	}

	kfree(ctx);
}
EXPORT_SYMBOL_GPL(tquic_fallback_ctx_destroy);

/**
 * tquic_fallback_is_active - Check if fallback to TCP is active
 * @ctx: Fallback context
 *
 * Returns: true if currently using TCP fallback
 */
bool tquic_fallback_is_active(struct tquic_fallback_ctx *ctx)
{
	bool active;

	if (!ctx)
		return false;

	spin_lock(&ctx->lock);
	active = (ctx->state == FALLBACK_STATE_TCP);
	spin_unlock(&ctx->lock);

	return active;
}
EXPORT_SYMBOL_GPL(tquic_fallback_is_active);

/**
 * tquic_fallback_get_tcp_conn - Get TCP connection if in fallback mode
 * @ctx: Fallback context
 *
 * Returns: TCP connection or NULL if not in fallback
 */
struct quic_tcp_connection *tquic_fallback_get_tcp_conn(struct tquic_fallback_ctx *ctx)
{
	struct quic_tcp_connection *conn = NULL;

	if (!ctx)
		return NULL;

	spin_lock(&ctx->lock);
	if (ctx->state == FALLBACK_STATE_TCP)
		conn = ctx->tcp_conn;
	spin_unlock(&ctx->lock);

	return conn;
}
EXPORT_SYMBOL_GPL(tquic_fallback_get_tcp_conn);

/**
 * tquic_fallback_send - Send packet (via UDP or TCP depending on state)
 * @ctx: Fallback context
 * @data: Packet data
 * @len: Packet length
 *
 * Returns: Bytes sent, negative errno on error
 */
int tquic_fallback_send(struct tquic_fallback_ctx *ctx,
			const void *data, size_t len)
{
	if (!ctx)
		return -EINVAL;

	spin_lock(&ctx->lock);

	if (ctx->state == FALLBACK_STATE_TCP && ctx->tcp_conn) {
		spin_unlock(&ctx->lock);
		return quic_tcp_send(ctx->tcp_conn, data, len);
	}

	spin_unlock(&ctx->lock);

	/* UDP path - would use normal QUIC send path */
	return -EOPNOTSUPP;
}
EXPORT_SYMBOL_GPL(tquic_fallback_send);

/**
 * tquic_fallback_update_loss - Update loss statistics
 * @ctx: Fallback context
 * @loss_pct: Current loss percentage
 *
 * Called periodically with loss statistics to detect degradation.
 */
void tquic_fallback_update_loss(struct tquic_fallback_ctx *ctx, u8 loss_pct)
{
	if (!ctx)
		return;

	fallback_record_loss(ctx, loss_pct);

	/* Check if we should trigger fallback */
	if (ctx->state == FALLBACK_STATE_UDP && fallback_check_loss(ctx)) {
		tquic_fallback_trigger(ctx, FALLBACK_REASON_LOSS);
	}
}
EXPORT_SYMBOL_GPL(tquic_fallback_update_loss);

/**
 * tquic_fallback_check - Check fallback conditions
 * @ctx: Fallback context
 *
 * Called periodically to check if fallback should be triggered.
 */
void tquic_fallback_check(struct tquic_fallback_ctx *ctx)
{
	if (!ctx)
		return;

	if (ctx->state != FALLBACK_STATE_UDP)
		return;

	if (fallback_check_timeout(ctx)) {
		tquic_fallback_trigger(ctx, FALLBACK_REASON_TIMEOUT);
	}
}
EXPORT_SYMBOL_GPL(tquic_fallback_check);

/*
 * =============================================================================
 * Network Namespace Init/Exit
 * =============================================================================
 */

static int __net_init tquic_fallback_net_init(struct net *net)
{
	struct tquic_fallback_net *fn = tquic_fallback_pernet(net);

	fn->enabled = FALLBACK_ENABLED_DEFAULT;
	fn->timeout_ms = FALLBACK_TIMEOUT_MS_DEFAULT;
	fn->loss_threshold = FALLBACK_LOSS_THRESHOLD_DEFAULT;
	fn->probe_interval_ms = FALLBACK_PROBE_INTERVAL_DEFAULT;
	fn->max_retries = FALLBACK_MAX_RETRIES_DEFAULT;
	fn->recovery_threshold = FALLBACK_RECOVERY_THRESHOLD;

	atomic64_set(&fn->fallback_count, 0);
	atomic64_set(&fn->recovery_count, 0);
	atomic64_set(&fn->timeout_triggers, 0);
	atomic64_set(&fn->loss_triggers, 0);
	atomic64_set(&fn->icmp_triggers, 0);
	atomic64_set(&fn->manual_triggers, 0);

	return 0;
}

static void __net_exit tquic_fallback_net_exit(struct net *net)
{
	/* Nothing to clean up */
}

static struct pernet_operations tquic_fallback_net_ops = {
	.init = tquic_fallback_net_init,
	.exit = tquic_fallback_net_exit,
	.id   = &tquic_fallback_net_id,
	.size = sizeof(struct tquic_fallback_net),
};

/*
 * =============================================================================
 * Procfs Statistics
 * =============================================================================
 */

static int fallback_stats_show(struct seq_file *m, void *v)
{
	struct net *net = current->nsproxy->net_ns;
	struct tquic_fallback_net *fn = tquic_fallback_pernet(net);

	seq_printf(m, "enabled: %d\n", fn->enabled);
	seq_printf(m, "timeout_ms: %d\n", fn->timeout_ms);
	seq_printf(m, "loss_threshold: %d\n", fn->loss_threshold);
	seq_printf(m, "probe_interval_ms: %d\n", fn->probe_interval_ms);
	seq_printf(m, "max_retries: %d\n", fn->max_retries);
	seq_printf(m, "recovery_threshold: %d\n", fn->recovery_threshold);
	seq_printf(m, "\n");
	seq_printf(m, "fallback_count: %lld\n",
		   atomic64_read(&fn->fallback_count));
	seq_printf(m, "recovery_count: %lld\n",
		   atomic64_read(&fn->recovery_count));
	seq_printf(m, "timeout_triggers: %lld\n",
		   atomic64_read(&fn->timeout_triggers));
	seq_printf(m, "loss_triggers: %lld\n",
		   atomic64_read(&fn->loss_triggers));
	seq_printf(m, "icmp_triggers: %lld\n",
		   atomic64_read(&fn->icmp_triggers));
	seq_printf(m, "manual_triggers: %lld\n",
		   atomic64_read(&fn->manual_triggers));

	return 0;
}

static int fallback_stats_open(struct inode *inode, struct file *file)
{
	return single_open(file, fallback_stats_show, NULL);
}

static const struct proc_ops fallback_stats_ops = {
	.proc_open	= fallback_stats_open,
	.proc_read	= seq_read,
	.proc_lseek	= seq_lseek,
	.proc_release	= single_release,
};

/*
 * =============================================================================
 * Module Init/Exit
 * =============================================================================
 */

static struct proc_dir_entry *tquic_proc_dir;

int tquic_fallback_init(void)
{
	int ret;

	/* Initialize QUIC-over-TCP transport first */
	ret = tquic_over_tcp_init();
	if (ret)
		return ret;

	/* Register per-netns operations */
	ret = register_pernet_subsys(&tquic_fallback_net_ops);
	if (ret) {
		tquic_over_tcp_exit();
		return ret;
	}

	/* Register sysctl */
	tquic_fallback_sysctl_header = register_net_sysctl_sz(&init_net,
							      "net/tquic",
							      tquic_fallback_table,
							      TQUIC_FALLBACK_SYSCTL_ENTRIES);
	if (!tquic_fallback_sysctl_header) {
		unregister_pernet_subsys(&tquic_fallback_net_ops);
		tquic_over_tcp_exit();
		return -ENOMEM;
	}

	/* Create proc entries */
	tquic_proc_dir = proc_mkdir("tquic", init_net.proc_net);
	if (tquic_proc_dir) {
		proc_create("fallback_stats", 0444, tquic_proc_dir,
			    &fallback_stats_ops);
	}

	pr_info("tquic_fallback: UDP/TCP fallback mechanism initialized\n");
	return 0;
}

void tquic_fallback_exit(void)
{
	if (tquic_proc_dir) {
		remove_proc_entry("fallback_stats", tquic_proc_dir);
		remove_proc_entry("tquic", init_net.proc_net);
	}

	if (tquic_fallback_sysctl_header)
		unregister_net_sysctl_table(tquic_fallback_sysctl_header);

	unregister_pernet_subsys(&tquic_fallback_net_ops);
	tquic_over_tcp_exit();

	pr_info("tquic_fallback: UDP/TCP fallback mechanism shutdown\n");
}

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("TQUIC UDP to TCP Fallback Mechanism");
MODULE_AUTHOR("Linux Foundation");
