// SPDX-License-Identifier: GPL-2.0-only
/*
 * TQUIC: Sysctl Interface for Tuning
 *
 * Copyright (c) 2026 Linux Foundation
 *
 * Provides sysctl parameters for tuning TQUIC WAN bonding behavior.
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/sysctl.h>
#include <linux/sched.h>
#include <linux/nsproxy.h>
#include <net/net_namespace.h>
#include <net/netns/tquic.h>
#include <net/tquic.h>

/* Global tunables */
static int tquic_enabled = 1;
static int tquic_default_bond_mode = TQUIC_BOND_MODE_AGGREGATE;
static int tquic_max_paths = TQUIC_MAX_PATHS;
static int tquic_reorder_window = 64;
static int tquic_probe_interval = 1000;  /* ms */
static int tquic_failover_timeout = 3000; /* ms */
static int tquic_idle_timeout = 30000;   /* ms */
static int tquic_max_data_mb = 1;        /* MB */
static int tquic_max_stream_data_kb = 256; /* KB */
static int tquic_ack_delay = 25;         /* ms */

/* RTT-related tunables */
static int tquic_initial_rtt = 100;      /* ms */
static int tquic_min_rtt = 1;            /* ms */

/* Congestion control tunables */
static int tquic_initial_cwnd = 10;      /* packets */
static int tquic_min_cwnd = 2;           /* packets */

/* Scheduler tunables */
static char tquic_scheduler[16] = "minrtt";
static char tquic_congestion[16] = "cubic";

/* Debug tunables */
static int tquic_debug_level;

/* GREASE (RFC 9287) tunable - enabled by default */
static int tquic_grease_enabled = 1;

/* Key update tunables (RFC 9001 Section 6) */
static unsigned long tquic_key_update_interval_packets = (1UL << 20);  /* ~1M packets */
static int tquic_key_update_interval_seconds = 3600;  /* 1 hour */

/* PMTUD tunables (RFC 8899) */
static int tquic_pmtud_enabled = 1;
static int tquic_pmtud_probe_interval = 15000;  /* ms - RFC 8899 recommends 15s */

/* ACK Frequency tunables (draft-ietf-quic-ack-frequency) */
static int tquic_ack_frequency_enabled = 1;		/* Enabled by default */
static int tquic_default_ack_delay_us = 25000;		/* 25ms in microseconds */

/* Stateless reset tunable (RFC 9000 Section 10.3) */
static int tquic_stateless_reset_enabled = 1;  /* Enabled by default per RFC */

/* Address validation token tunables (RFC 9000 Section 8.1.3-8.1.4) */
static int tquic_token_lifetime_seconds = 86400;  /* 24 hours default */

/* Retry packet tunables (RFC 9000 Section 8.1) */
static int tquic_retry_required;			/* 0 = disabled (default), 1 = enabled */
static int tquic_retry_token_lifetime = 120;		/* seconds, default 2 minutes */

/* HTTP/3 Extensible Priorities (RFC 9218) */
static int tquic_http3_priorities_enabled = 1;  /* Enabled by default */

/* 0-RTT Early Data (RFC 9001 Section 4.6-4.7) */
static int tquic_zero_rtt_enabled = 1;			/* Enabled by default */
static int tquic_zero_rtt_max_age_seconds = 604800;	/* 7 days default */

/* QPACK HTTP/3 header compression (RFC 9204) */
static int tquic_qpack_max_table_capacity = 4096;	/* Default per RFC 9204 */

/*
 * Preferred Address tunables (RFC 9000 Section 9.6)
 *
 * preferred_address_enabled (server):
 *   When enabled, server advertises a preferred address in transport parameters.
 *   Default: 0 (disabled) - must be explicitly configured with addresses.
 *
 * prefer_preferred_address (client):
 *   When enabled, client automatically migrates to server's preferred address
 *   after handshake completion if one was provided.
 *   Default: 1 (enabled) - per RFC 9000, clients SHOULD migrate if able.
 */
static int tquic_preferred_address_enabled;		/* Server: advertise */
static int tquic_prefer_preferred_address = 1;		/* Client: auto-migrate */

/* Forward declarations for scheduler API */
struct tquic_sched_ops;
struct tquic_sched_ops *tquic_sched_find(const char *name);

/* Forward declarations for CC API */
struct tquic_cong_ops;
struct tquic_cong_ops *tquic_cong_find(const char *name);
int tquic_cong_set_default(struct net *net, const char *name);
const char *tquic_cong_get_default_name(struct net *net);

/*
 * Per-netns scheduler sysctl handler
 *
 * Handles reading/writing net.tquic.scheduler which sets the default
 * scheduler for new connections in this network namespace.
 *
 * On read: Returns current default scheduler name
 * On write: Validates scheduler exists and sets as default
 */
static int proc_tquic_scheduler(struct ctl_table *table, int write,
				void *buffer, size_t *lenp, loff_t *ppos)
{
	struct net *net = current->nsproxy->net_ns;
	char name[NETNS_TQUIC_SCHED_NAME_MAX];
	struct ctl_table tmp_table;
	int ret;

	if (!write) {
		/* Read current default scheduler for this netns */
		const char *current_name;

		rcu_read_lock();
		if (net->tquic.default_scheduler)
			current_name = net->tquic.default_scheduler->name;
		else
			current_name = "aggregate";
		rcu_read_unlock();

		strscpy(name, current_name, sizeof(name));

		/* Use temporary table pointing to our local buffer */
		memset(&tmp_table, 0, sizeof(tmp_table));
		tmp_table.procname = table->procname;
		tmp_table.data = name;
		tmp_table.maxlen = sizeof(name);
		tmp_table.mode = table->mode;

		return proc_dostring(&tmp_table, write, buffer, lenp, ppos);
	}

	/* Write: get new scheduler name from user */
	strscpy(name, net->tquic.sched_name, sizeof(name));

	memset(&tmp_table, 0, sizeof(tmp_table));
	tmp_table.procname = table->procname;
	tmp_table.data = name;
	tmp_table.maxlen = sizeof(name);
	tmp_table.mode = table->mode;

	ret = proc_dostring(&tmp_table, write, buffer, lenp, ppos);
	if (ret)
		return ret;

	/* Validate scheduler exists */
	rcu_read_lock();
	if (!tquic_sched_find(name)) {
		rcu_read_unlock();
		pr_warn("tquic: unknown scheduler '%s'\n", name);
		return -ENOENT;
	}
	rcu_read_unlock();

	/* Set per-netns default scheduler */
	ret = tquic_sched_set_default(net, name);
	if (ret) {
		pr_warn("tquic: failed to set scheduler '%s': %d\n", name, ret);
		return ret;
	}

	pr_debug("tquic: netns scheduler set to '%s'\n", name);
	return 0;
}

/*
 * Per-netns CC algorithm sysctl handler
 *
 * Handles reading/writing net.tquic.cc_algorithm which sets the default
 * CC algorithm for new paths in this network namespace.
 *
 * On read: Returns current default CC algorithm name
 * On write: Validates CC algorithm exists and sets as default
 */
static int proc_tquic_cc_algorithm(struct ctl_table *table, int write,
				   void *buffer, size_t *lenp, loff_t *ppos)
{
	struct net *net = current->nsproxy->net_ns;
	char name[NETNS_TQUIC_CC_NAME_MAX];
	struct ctl_table tmp_table;
	int ret;

	if (!write) {
		/* Read current default CC algorithm for this netns */
		const char *current_name;

		current_name = tquic_cong_get_default_name(net);
		strscpy(name, current_name, sizeof(name));

		/* Use temporary table pointing to our local buffer */
		memset(&tmp_table, 0, sizeof(tmp_table));
		tmp_table.procname = table->procname;
		tmp_table.data = name;
		tmp_table.maxlen = sizeof(name);
		tmp_table.mode = table->mode;

		return proc_dostring(&tmp_table, write, buffer, lenp, ppos);
	}

	/* Write: get new CC algorithm name from user */
	strscpy(name, net->tquic.cc_name, sizeof(name));

	memset(&tmp_table, 0, sizeof(tmp_table));
	tmp_table.procname = table->procname;
	tmp_table.data = name;
	tmp_table.maxlen = sizeof(name);
	tmp_table.mode = table->mode;

	ret = proc_dostring(&tmp_table, write, buffer, lenp, ppos);
	if (ret)
		return ret;

	/* Validate CC algorithm exists */
	if (!tquic_cong_find(name)) {
		pr_warn("tquic: unknown CC algorithm '%s'\n", name);
		return -ENOENT;
	}

	/* Set per-netns default CC algorithm */
	ret = tquic_cong_set_default(net, name);
	if (ret) {
		pr_warn("tquic: failed to set CC algorithm '%s': %d\n", name, ret);
		return ret;
	}

	pr_debug("tquic: netns CC algorithm set to '%s'\n", name);
	return 0;
}

/*
 * Per-netns BBR RTT threshold sysctl handler
 *
 * Handles reading/writing net.tquic.bbr_rtt_threshold_ms which sets the
 * RTT threshold for BBR auto-selection. Paths with RTT >= threshold
 * will automatically use BBR instead of the default CC algorithm.
 *
 * Set to 0 to disable BBR auto-selection.
 */
static int proc_tquic_bbr_rtt_threshold(struct ctl_table *table, int write,
					void *buffer, size_t *lenp, loff_t *ppos)
{
	struct net *net = current->nsproxy->net_ns;
	int val = net->tquic.bbr_rtt_threshold_ms;
	struct ctl_table tmp_table;
	int ret;

	memset(&tmp_table, 0, sizeof(tmp_table));
	tmp_table.procname = table->procname;
	tmp_table.data = &val;
	tmp_table.maxlen = sizeof(val);
	tmp_table.mode = table->mode;
	tmp_table.extra1 = table->extra1;
	tmp_table.extra2 = table->extra2;

	ret = proc_dointvec_minmax(&tmp_table, write, buffer, lenp, ppos);
	if (ret || !write)
		return ret;

	net->tquic.bbr_rtt_threshold_ms = val;
	pr_debug("tquic: netns BBR RTT threshold set to %d ms\n", val);
	return 0;
}

/*
 * Per-netns coupled CC sysctl handler
 *
 * Handles reading/writing net.tquic.cc_coupled which enables/disables
 * coupled congestion control for multipath TCP-fairness.
 */
static int proc_tquic_cc_coupled(struct ctl_table *table, int write,
				 void *buffer, size_t *lenp, loff_t *ppos)
{
	struct net *net = current->nsproxy->net_ns;
	int val = net->tquic.coupled_enabled ? 1 : 0;
	struct ctl_table tmp_table;
	int ret;

	memset(&tmp_table, 0, sizeof(tmp_table));
	tmp_table.procname = table->procname;
	tmp_table.data = &val;
	tmp_table.maxlen = sizeof(val);
	tmp_table.mode = table->mode;
	tmp_table.extra1 = table->extra1;
	tmp_table.extra2 = table->extra2;

	ret = proc_dointvec_minmax(&tmp_table, write, buffer, lenp, ppos);
	if (ret || !write)
		return ret;

	net->tquic.coupled_enabled = !!val;
	pr_debug("tquic: netns coupled CC %s\n",
		 val ? "enabled" : "disabled");
	return 0;
}

/*
 * Per-netns ECN sysctl handler
 *
 * Handles reading/writing net.tquic.ecn_enabled which enables/disables
 * ECN (Explicit Congestion Notification) for congestion signaling.
 * Per CONTEXT.md: "ECN support: available but off by default"
 */
static int proc_tquic_ecn_enabled(struct ctl_table *table, int write,
				  void *buffer, size_t *lenp, loff_t *ppos)
{
	struct net *net = current->nsproxy->net_ns;
	int val = net->tquic.ecn_enabled ? 1 : 0;
	struct ctl_table tmp_table;
	int ret;

	memset(&tmp_table, 0, sizeof(tmp_table));
	tmp_table.procname = table->procname;
	tmp_table.data = &val;
	tmp_table.maxlen = sizeof(val);
	tmp_table.mode = table->mode;
	tmp_table.extra1 = table->extra1;
	tmp_table.extra2 = table->extra2;

	ret = proc_dointvec_minmax(&tmp_table, write, buffer, lenp, ppos);
	if (ret || !write)
		return ret;

	net->tquic.ecn_enabled = !!val;
	pr_debug("tquic: netns ECN %s\n", val ? "enabled" : "disabled");
	return 0;
}

/*
 * Per-netns ECN beta sysctl handler
 *
 * Handles reading/writing net.tquic.ecn_beta which sets the cwnd reduction
 * factor when ECN-CE marks are received. Value is scaled by 1000.
 * Default is 800 (0.8), meaning cwnd is reduced to 80% on ECN signal.
 *
 * Per RFC 9002 Section 7.2: ECN reduction is typically less aggressive
 * than loss-based reduction (0.8 vs 0.7 for CUBIC).
 */
static int proc_tquic_ecn_beta(struct ctl_table *table, int write,
			       void *buffer, size_t *lenp, loff_t *ppos)
{
	struct net *net = current->nsproxy->net_ns;
	int val = net->tquic.ecn_beta ?: 800;  /* Default to 0.8 */
	struct ctl_table tmp_table;
	int ret;

	memset(&tmp_table, 0, sizeof(tmp_table));
	tmp_table.procname = table->procname;
	tmp_table.data = &val;
	tmp_table.maxlen = sizeof(val);
	tmp_table.mode = table->mode;
	tmp_table.extra1 = table->extra1;
	tmp_table.extra2 = table->extra2;

	ret = proc_dointvec_minmax(&tmp_table, write, buffer, lenp, ppos);
	if (ret || !write)
		return ret;

	net->tquic.ecn_beta = val;
	pr_debug("tquic: netns ECN beta set to %d/1000 (%d.%d%%)\n",
		 val, val / 10, val % 10);
	return 0;
}

/* Legacy global sysctl handler (for compatibility) */
static int tquic_sysctl_scheduler(struct ctl_table *table, int write,
				  void *buffer, size_t *lenp, loff_t *ppos)
{
	int ret;

	ret = proc_dostring(table, write, buffer, lenp, ppos);
	if (ret || !write)
		return ret;

	/* Validate and set global scheduler (legacy) */
	rcu_read_lock();
	if (!tquic_sched_find(tquic_scheduler)) {
		rcu_read_unlock();
		pr_warn("tquic: unknown scheduler '%s'\n", tquic_scheduler);
		return -ENOENT;
	}
	rcu_read_unlock();

	/* Also set for init_net as the per-netns default */
	ret = tquic_sched_set_default(&init_net, tquic_scheduler);
	if (ret)
		pr_warn("tquic: failed to set default scheduler '%s'\n",
			tquic_scheduler);

	return 0;
}

static int tquic_sysctl_bond_mode(struct ctl_table *table, int write,
				  void *buffer, size_t *lenp, loff_t *ppos)
{
	int ret;

	ret = proc_dointvec_minmax(table, write, buffer, lenp, ppos);
	if (ret || !write)
		return ret;

	if (tquic_default_bond_mode > TQUIC_BOND_MODE_ECF) {
		tquic_default_bond_mode = TQUIC_BOND_MODE_AGGREGATE;
		return -EINVAL;
	}

	return 0;
}

/*
 * Per-netns pacing sysctl handler
 *
 * Handles reading/writing net.tquic.pacing_enabled which enables/disables
 * pacing for TQUIC connections. Pacing is enabled by default per CONTEXT.md.
 */
static int proc_tquic_pacing_enabled(struct ctl_table *table, int write,
				     void *buffer, size_t *lenp, loff_t *ppos)
{
	struct net *net = current->nsproxy->net_ns;
	int val = net->tquic.pacing_enabled ? 1 : 0;
	struct ctl_table tmp_table;
	int ret;

	memset(&tmp_table, 0, sizeof(tmp_table));
	tmp_table.procname = table->procname;
	tmp_table.data = &val;
	tmp_table.maxlen = sizeof(val);
	tmp_table.mode = table->mode;
	tmp_table.extra1 = table->extra1;
	tmp_table.extra2 = table->extra2;

	ret = proc_dointvec_minmax(&tmp_table, write, buffer, lenp, ppos);
	if (ret || !write)
		return ret;

	net->tquic.pacing_enabled = !!val;
	pr_debug("tquic: netns pacing %s\n", val ? "enabled" : "disabled");
	return 0;
}

/*
 * Per-netns path degradation threshold sysctl handler
 *
 * Handles reading/writing net.tquic.path_degrade_threshold which sets
 * the number of consecutive losses in same round before path degradation.
 * Default is 5 per RESEARCH.md recommendation.
 */
static int proc_tquic_path_degrade_threshold(struct ctl_table *table, int write,
					     void *buffer, size_t *lenp,
					     loff_t *ppos)
{
	struct net *net = current->nsproxy->net_ns;
	int val = net->tquic.path_degrade_threshold;
	struct ctl_table tmp_table;
	int ret;

	memset(&tmp_table, 0, sizeof(tmp_table));
	tmp_table.procname = table->procname;
	tmp_table.data = &val;
	tmp_table.maxlen = sizeof(val);
	tmp_table.mode = table->mode;
	tmp_table.extra1 = table->extra1;
	tmp_table.extra2 = table->extra2;

	ret = proc_dointvec_minmax(&tmp_table, write, buffer, lenp, ppos);
	if (ret || !write)
		return ret;

	net->tquic.path_degrade_threshold = val;
	pr_debug("tquic: netns path_degrade_threshold set to %d\n", val);
	return 0;
}

/*
 * Per-netns GREASE sysctl handler
 *
 * Handles reading/writing net.tquic.grease_enabled which enables/disables
 * GREASE (RFC 9287) for forward compatibility testing.
 *
 * When enabled:
 *   - May GREASE the fixed bit in long headers (with peer support)
 *   - Includes grease_quic_bit transport parameter
 *   - May include reserved transport parameters (31*N + 27)
 *   - May include reserved versions in Version Negotiation
 */
static int proc_tquic_grease_enabled(struct ctl_table *table, int write,
				     void *buffer, size_t *lenp, loff_t *ppos)
{
	struct net *net = current->nsproxy->net_ns;
	int val = net->tquic.grease_enabled ? 1 : 0;
	struct ctl_table tmp_table;
	int ret;

	memset(&tmp_table, 0, sizeof(tmp_table));
	tmp_table.procname = table->procname;
	tmp_table.data = &val;
	tmp_table.maxlen = sizeof(val);
	tmp_table.mode = table->mode;
	tmp_table.extra1 = table->extra1;
	tmp_table.extra2 = table->extra2;

	ret = proc_dointvec_minmax(&tmp_table, write, buffer, lenp, ppos);
	if (ret || !write)
		return ret;

	net->tquic.grease_enabled = !!val;
	pr_debug("tquic: netns GREASE %s\n", val ? "enabled" : "disabled");
	return 0;
}

/* Min/max values for integer tunables */
static int zero;
static int one = 1;
static int ten = 10;
static int max_paths = TQUIC_MAX_PATHS;
static int max_reorder = 1024;
static int max_timeout = 60000;
static int max_rtt = 10000;
static int max_cwnd = 10000;
static int max_bond_mode = TQUIC_BOND_MODE_ECF;
static int max_data = 1024;    /* MB */
static int max_ack_delay = 1000;
static int max_bbr_rtt_threshold = 10000;  /* ms */
static int max_ecn_beta = 1000;  /* Maximum 1.0 (full, no reduction) */
static unsigned long max_key_update_packets = (1UL << 30);  /* ~1B packets max */
static int max_key_update_seconds = 86400;  /* 24 hours max */
static int max_pmtud_probe_interval = 60000;  /* 60 seconds max */
static int max_token_lifetime = 604800;  /* 7 days max */
static int max_ack_delay_us = 16383000;  /* ~16.4 seconds max per spec */
static int max_retry_token_lifetime = 3600;  /* 1 hour max for Retry tokens */
static int max_qpack_table_capacity = 1048576;  /* 1MB max for QPACK table */

/* Sysctl table */
static struct ctl_table tquic_sysctl_table[] = {
	{
		.procname	= "enabled",
		.data		= &tquic_enabled,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= proc_dointvec_minmax,
		.extra1		= &zero,
		.extra2		= &one,
	},
	{
		.procname	= "default_bond_mode",
		.data		= &tquic_default_bond_mode,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= tquic_sysctl_bond_mode,
		.extra1		= &zero,
		.extra2		= &max_bond_mode,
	},
	{
		.procname	= "max_paths",
		.data		= &tquic_max_paths,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= proc_dointvec_minmax,
		.extra1		= &one,
		.extra2		= &max_paths,
	},
	{
		.procname	= "reorder_window",
		.data		= &tquic_reorder_window,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= proc_dointvec_minmax,
		.extra1		= &one,
		.extra2		= &max_reorder,
	},
	{
		.procname	= "probe_interval_ms",
		.data		= &tquic_probe_interval,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= proc_dointvec_minmax,
		.extra1		= &one,
		.extra2		= &max_timeout,
	},
	{
		.procname	= "failover_timeout_ms",
		.data		= &tquic_failover_timeout,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= proc_dointvec_minmax,
		.extra1		= &one,
		.extra2		= &max_timeout,
	},
	{
		.procname	= "idle_timeout_ms",
		.data		= &tquic_idle_timeout,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= proc_dointvec_minmax,
		.extra1		= &one,
		.extra2		= &max_timeout,
	},
	{
		.procname	= "initial_rtt_ms",
		.data		= &tquic_initial_rtt,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= proc_dointvec_minmax,
		.extra1		= &one,
		.extra2		= &max_rtt,
	},
	{
		.procname	= "min_rtt_ms",
		.data		= &tquic_min_rtt,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= proc_dointvec_minmax,
		.extra1		= &one,
		.extra2		= &max_rtt,
	},
	{
		.procname	= "initial_cwnd_packets",
		.data		= &tquic_initial_cwnd,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= proc_dointvec_minmax,
		.extra1		= &one,
		.extra2		= &max_cwnd,
	},
	{
		.procname	= "min_cwnd_packets",
		.data		= &tquic_min_cwnd,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= proc_dointvec_minmax,
		.extra1		= &one,
		.extra2		= &max_cwnd,
	},
	{
		.procname	= "max_data_mb",
		.data		= &tquic_max_data_mb,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= proc_dointvec_minmax,
		.extra1		= &one,
		.extra2		= &max_data,
	},
	{
		.procname	= "max_stream_data_kb",
		.data		= &tquic_max_stream_data_kb,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= proc_dointvec_minmax,
		.extra1		= &one,
		.extra2		= &max_data,
	},
	{
		.procname	= "max_ack_delay_ms",
		.data		= &tquic_ack_delay,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= proc_dointvec_minmax,
		.extra1		= &zero,
		.extra2		= &max_ack_delay,
	},
	{
		.procname	= "scheduler",
		.data		= tquic_scheduler,
		.maxlen		= sizeof(tquic_scheduler),
		.mode		= 0644,
		.proc_handler	= proc_tquic_scheduler,
	},
	{
		.procname	= "congestion",
		.data		= tquic_congestion,
		.maxlen		= sizeof(tquic_congestion),
		.mode		= 0644,
		.proc_handler	= proc_dostring,
	},
	{
		.procname	= "cc_algorithm",
		.data		= NULL,  /* Uses current->nsproxy->net_ns */
		.maxlen		= NETNS_TQUIC_CC_NAME_MAX,
		.mode		= 0644,
		.proc_handler	= proc_tquic_cc_algorithm,
	},
	{
		.procname	= "bbr_rtt_threshold_ms",
		.data		= NULL,  /* Uses current->nsproxy->net_ns */
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= proc_tquic_bbr_rtt_threshold,
		.extra1		= &zero,
		.extra2		= &max_bbr_rtt_threshold,
	},
	{
		.procname	= "cc_coupled",
		.data		= NULL,  /* Uses current->nsproxy->net_ns */
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= proc_tquic_cc_coupled,
		.extra1		= &zero,
		.extra2		= &one,
	},
	{
		.procname	= "ecn_enabled",
		.data		= NULL,  /* Uses current->nsproxy->net_ns */
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= proc_tquic_ecn_enabled,
		.extra1		= &zero,
		.extra2		= &one,
	},
	{
		.procname	= "ecn_beta",
		.data		= NULL,  /* Uses current->nsproxy->net_ns */
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= proc_tquic_ecn_beta,
		.extra1		= &one,  /* Minimum 0.1% */
		.extra2		= &max_ecn_beta,  /* Maximum 100% */
	},
	{
		.procname	= "pacing_enabled",
		.data		= NULL,  /* Uses current->nsproxy->net_ns */
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= proc_tquic_pacing_enabled,
		.extra1		= &zero,
		.extra2		= &one,
	},
	{
		.procname	= "path_degrade_threshold",
		.data		= NULL,  /* Uses current->nsproxy->net_ns */
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= proc_tquic_path_degrade_threshold,
		.extra1		= &one,      /* Minimum 1 */
		.extra2		= &ten,      /* Maximum 10 */
	},
	{
		.procname	= "debug_level",
		.data		= &tquic_debug_level,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= proc_dointvec,
	},
	{
		.procname	= "key_update_interval_packets",
		.data		= &tquic_key_update_interval_packets,
		.maxlen		= sizeof(unsigned long),
		.mode		= 0644,
		.proc_handler	= proc_doulongvec_minmax,
		.extra1		= &zero,
		.extra2		= &max_key_update_packets,
	},
	{
		.procname	= "key_update_interval_seconds",
		.data		= &tquic_key_update_interval_seconds,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= proc_dointvec_minmax,
		.extra1		= &zero,
		.extra2		= &max_key_update_seconds,
	},
	{
		.procname	= "grease_enabled",
		.data		= NULL,  /* Uses current->nsproxy->net_ns */
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= proc_tquic_grease_enabled,
		.extra1		= &zero,
		.extra2		= &one,
	},
	{
		.procname	= "pmtud_enabled",
		.data		= &tquic_pmtud_enabled,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= proc_dointvec_minmax,
		.extra1		= &zero,
		.extra2		= &one,
	},
	{
		.procname	= "pmtud_probe_interval_ms",
		.data		= &tquic_pmtud_probe_interval,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= proc_dointvec_minmax,
		.extra1		= &one,
		.extra2		= &max_pmtud_probe_interval,
	},
	/*
	 * Stateless reset (RFC 9000 Section 10.3)
	 *
	 * When enabled, the server sends stateless reset packets in response
	 * to packets with unknown connection IDs. This allows graceful
	 * termination when the server has lost connection state.
	 *
	 * Default: enabled (required by RFC 9000)
	 */
	{
		.procname	= "stateless_reset_enabled",
		.data		= &tquic_stateless_reset_enabled,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= proc_dointvec_minmax,
		.extra1		= &zero,
		.extra2		= &one,
	},
	/*
	 * Address validation token lifetime (RFC 9000 Section 8.1.4)
	 *
	 * Tokens issued via NEW_TOKEN frames allow clients to skip address
	 * validation on future connections. This setting controls how long
	 * tokens remain valid.
	 *
	 * Default: 86400 seconds (24 hours)
	 * Range: 1 to 604800 seconds (1 second to 7 days)
	 */
	{
		.procname	= "token_lifetime_seconds",
		.data		= &tquic_token_lifetime_seconds,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= proc_dointvec_minmax,
		.extra1		= &one,
		.extra2		= &max_token_lifetime,
	},
	/*
	 * Retry required (RFC 9000 Section 8.1)
	 *
	 * When enabled, the server sends Retry packets in response to new
	 * Initial packets to validate client addresses before allocating
	 * connection state. This mitigates amplification attacks.
	 *
	 * Default: 0 (disabled)
	 * Set to 1 to require Retry for all new connections
	 */
	{
		.procname	= "retry_required",
		.data		= &tquic_retry_required,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= proc_dointvec_minmax,
		.extra1		= &zero,
		.extra2		= &one,
	},
	/*
	 * Retry token lifetime (RFC 9000 Section 8.1)
	 *
	 * Controls how long Retry tokens remain valid. Tokens encode the
	 * client IP address, timestamp, and original DCID. The server
	 * validates the timestamp is within this window.
	 *
	 * Default: 120 seconds (2 minutes)
	 * Range: 1 to 3600 seconds (1 second to 1 hour)
	 */
	{
		.procname	= "retry_token_lifetime",
		.data		= &tquic_retry_token_lifetime,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= proc_dointvec_minmax,
		.extra1		= &one,
		.extra2		= &max_retry_token_lifetime,
	},
	/*
	 * HTTP/3 Extensible Priorities (RFC 9218)
	 *
	 * When enabled, HTTP/3 stream priorities are tracked and used for
	 * scheduling. The priority scheme uses urgency (u=0-7) and incremental
	 * (i) parameters. PRIORITY_UPDATE frames (0xf0700, 0xf0701) allow
	 * dynamic priority changes during request lifetime.
	 *
	 * Default: 1 (enabled)
	 */
	{
		.procname	= "http3_priorities_enabled",
		.data		= &tquic_http3_priorities_enabled,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= proc_dointvec_minmax,
		.extra1		= &zero,
		.extra2		= &one,
	},
	/*
	 * Preferred Address (RFC 9000 Section 9.6)
	 *
	 * preferred_address_enabled: Server advertises a preferred address
	 * in transport parameters. The server must ensure it can receive
	 * packets on this address before enabling.
	 *
	 * Default: 0 (disabled)
	 */
	{
		.procname	= "preferred_address_enabled",
		.data		= &tquic_preferred_address_enabled,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= proc_dointvec_minmax,
		.extra1		= &zero,
		.extra2		= &one,
	},
	/*
	 * prefer_preferred_address: Client automatically migrates to
	 * server's preferred address after handshake if one is provided.
	 * Per RFC 9000, clients SHOULD migrate to preferred address
	 * when able.
	 *
	 * Default: 1 (enabled)
	 */
	{
		.procname	= "prefer_preferred_address",
		.data		= &tquic_prefer_preferred_address,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= proc_dointvec_minmax,
		.extra1		= &zero,
		.extra2		= &one,
	},
	/*
	 * ACK Frequency Extension (draft-ietf-quic-ack-frequency)
	 *
	 * Allows the sender to control how frequently the peer generates
	 * acknowledgments via ACK_FREQUENCY (0xaf) and IMMEDIATE_ACK (0xac)
	 * frames. This can reduce ACK overhead on high-bandwidth paths while
	 * maintaining good feedback for congestion control.
	 *
	 * Default: enabled
	 */
	{
		.procname	= "ack_frequency_enabled",
		.data		= &tquic_ack_frequency_enabled,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= proc_dointvec_minmax,
		.extra1		= &zero,
		.extra2		= &one,
	},
	/*
	 * Default ACK delay in microseconds
	 *
	 * The maximum time an endpoint will wait before sending an ACK frame.
	 * This is used as the default for the min_ack_delay transport parameter
	 * per draft-ietf-quic-ack-frequency.
	 *
	 * Default: 25000 microseconds (25ms)
	 * Range: 1 to 16383000 microseconds (~16.4 seconds per spec)
	 */
	{
		.procname	= "default_ack_delay_us",
		.data		= &tquic_default_ack_delay_us,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= proc_dointvec_minmax,
		.extra1		= &one,
		.extra2		= &max_ack_delay_us,
	},
	/*
	 * 0-RTT Early Data (RFC 9001 Section 4.6-4.7)
	 *
	 * When enabled, clients can send early data before the handshake
	 * completes using cached session tickets. This reduces latency but
	 * early data may be replayed; applications must be idempotent.
	 *
	 * Default: enabled (1)
	 */
	{
		.procname	= "zero_rtt_enabled",
		.data		= &tquic_zero_rtt_enabled,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= proc_dointvec_minmax,
		.extra1		= &zero,
		.extra2		= &one,
	},
	/*
	 * 0-RTT Session Ticket Max Age (RFC 9001 Section 4.6.1)
	 *
	 * Maximum age of session tickets for 0-RTT resumption.
	 * Tickets older than this are rejected for 0-RTT but may
	 * still be used for 1-RTT resumption.
	 *
	 * Default: 604800 seconds (7 days)
	 * Range: 1 to 604800 seconds
	 */
	{
		.procname	= "zero_rtt_max_age_seconds",
		.data		= &tquic_zero_rtt_max_age_seconds,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= proc_dointvec_minmax,
		.extra1		= &one,
		.extra2		= &max_token_lifetime,
	},
	/*
	 * QPACK Dynamic Table Capacity (RFC 9204)
	 *
	 * Maximum size in bytes of the QPACK dynamic table used for
	 * HTTP/3 header compression. Each entry uses name_len + value_len + 32
	 * bytes. Larger tables provide better compression but use more memory.
	 *
	 * This value is advertised via the QPACK_MAX_TABLE_CAPACITY (0x01)
	 * SETTINGS parameter in HTTP/3. The actual table capacity is
	 * negotiated as min(local_max, peer_max).
	 *
	 * Default: 4096 bytes (accommodates ~50-100 typical entries)
	 * Range: 0 to 1048576 bytes (0 disables dynamic table, max 1MB)
	 */
	{
		.procname	= "qpack_max_table_capacity",
		.data		= &tquic_qpack_max_table_capacity,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= proc_dointvec_minmax,
		.extra1		= &zero,
		.extra2		= &max_qpack_table_capacity,
	},
	{ }
};

static struct ctl_table_header *tquic_sysctl_header;

/* Accessor functions for other modules */
int tquic_sysctl_get_bond_mode(void)
{
	return tquic_default_bond_mode;
}
EXPORT_SYMBOL_GPL(tquic_sysctl_get_bond_mode);

int tquic_sysctl_get_max_paths(void)
{
	return tquic_max_paths;
}
EXPORT_SYMBOL_GPL(tquic_sysctl_get_max_paths);

int tquic_sysctl_get_reorder_window(void)
{
	return tquic_reorder_window;
}
EXPORT_SYMBOL_GPL(tquic_sysctl_get_reorder_window);

int tquic_sysctl_get_probe_interval(void)
{
	return tquic_probe_interval;
}
EXPORT_SYMBOL_GPL(tquic_sysctl_get_probe_interval);

int tquic_sysctl_get_failover_timeout(void)
{
	return tquic_failover_timeout;
}
EXPORT_SYMBOL_GPL(tquic_sysctl_get_failover_timeout);

int tquic_sysctl_get_idle_timeout(void)
{
	return tquic_idle_timeout;
}
EXPORT_SYMBOL_GPL(tquic_sysctl_get_idle_timeout);

int tquic_sysctl_get_initial_rtt(void)
{
	return tquic_initial_rtt;
}
EXPORT_SYMBOL_GPL(tquic_sysctl_get_initial_rtt);

int tquic_sysctl_get_initial_cwnd(void)
{
	return tquic_initial_cwnd;
}
EXPORT_SYMBOL_GPL(tquic_sysctl_get_initial_cwnd);

int tquic_sysctl_get_debug_level(void)
{
	return tquic_debug_level;
}
EXPORT_SYMBOL_GPL(tquic_sysctl_get_debug_level);

const char *tquic_sysctl_get_scheduler(void)
{
	return tquic_scheduler;
}
EXPORT_SYMBOL_GPL(tquic_sysctl_get_scheduler);

const char *tquic_sysctl_get_congestion(void)
{
	return tquic_congestion;
}
EXPORT_SYMBOL_GPL(tquic_sysctl_get_congestion);

/* Per-netns accessor functions */
const char *tquic_net_get_cc_algorithm(struct net *net)
{
	if (!net)
		return "cubic";
	return tquic_cong_get_default_name(net);
}
EXPORT_SYMBOL_GPL(tquic_net_get_cc_algorithm);

u32 tquic_net_get_bbr_rtt_threshold(struct net *net)
{
	if (!net)
		return NETNS_TQUIC_BBR_RTT_THRESHOLD_MS;
	return net->tquic.bbr_rtt_threshold_ms;
}
EXPORT_SYMBOL_GPL(tquic_net_get_bbr_rtt_threshold);

bool tquic_net_get_cc_coupled(struct net *net)
{
	if (!net)
		return false;
	return net->tquic.coupled_enabled;
}
EXPORT_SYMBOL_GPL(tquic_net_get_cc_coupled);

bool tquic_net_get_ecn_enabled(struct net *net)
{
	if (!net)
		return false;
	return net->tquic.ecn_enabled;
}
EXPORT_SYMBOL_GPL(tquic_net_get_ecn_enabled);

u32 tquic_net_get_ecn_beta(struct net *net)
{
	if (!net)
		return 800;  /* Default 0.8 scaled by 1000 */
	return net->tquic.ecn_beta ?: 800;
}
EXPORT_SYMBOL_GPL(tquic_net_get_ecn_beta);

bool tquic_net_get_pacing_enabled(struct net *net)
{
	if (!net)
		return true;  /* Pacing enabled by default per CONTEXT.md */
	return net->tquic.pacing_enabled;
}
EXPORT_SYMBOL_GPL(tquic_net_get_pacing_enabled);

int tquic_net_get_path_degrade_threshold(struct net *net)
{
	if (!net)
		return 5;  /* Default per RESEARCH.md recommendation */
	return net->tquic.path_degrade_threshold ?: 5;
}
EXPORT_SYMBOL_GPL(tquic_net_get_path_degrade_threshold);

/* GREASE (RFC 9287) accessor */
int tquic_sysctl_get_grease_enabled(void)
{
	return tquic_grease_enabled;
}
EXPORT_SYMBOL_GPL(tquic_sysctl_get_grease_enabled);

/* Key update (RFC 9001 Section 6) accessors */
unsigned long tquic_sysctl_get_key_update_interval_packets(void)
{
	return tquic_key_update_interval_packets;
}
EXPORT_SYMBOL_GPL(tquic_sysctl_get_key_update_interval_packets);

int tquic_sysctl_get_key_update_interval_seconds(void)
{
	return tquic_key_update_interval_seconds;
}
EXPORT_SYMBOL_GPL(tquic_sysctl_get_key_update_interval_seconds);

/* PMTUD (RFC 8899) accessors */
int tquic_sysctl_get_pmtud_enabled(void)
{
	return tquic_pmtud_enabled;
}
EXPORT_SYMBOL_GPL(tquic_sysctl_get_pmtud_enabled);

int tquic_sysctl_get_pmtud_probe_interval(void)
{
	return tquic_pmtud_probe_interval;
}
EXPORT_SYMBOL_GPL(tquic_sysctl_get_pmtud_probe_interval);

/* Stateless reset (RFC 9000 Section 10.3) - declared in tquic_stateless_reset.c */

/* Address validation token (RFC 9000 Section 8.1.3-8.1.4) accessor */
int tquic_sysctl_get_token_lifetime(void)
{
	return tquic_token_lifetime_seconds;
}
EXPORT_SYMBOL_GPL(tquic_sysctl_get_token_lifetime);

/* Retry packet (RFC 9000 Section 8.1) accessors */
int tquic_sysctl_get_retry_required(void)
{
	return tquic_retry_required;
}
EXPORT_SYMBOL_GPL(tquic_sysctl_get_retry_required);

int tquic_sysctl_get_retry_token_lifetime(void)
{
	return tquic_retry_token_lifetime;
}
EXPORT_SYMBOL_GPL(tquic_sysctl_get_retry_token_lifetime);

/* HTTP/3 Extensible Priorities (RFC 9218) accessor */
int tquic_sysctl_get_http3_priorities_enabled(void)
{
	return tquic_http3_priorities_enabled;
}
EXPORT_SYMBOL_GPL(tquic_sysctl_get_http3_priorities_enabled);

/* ACK Frequency (draft-ietf-quic-ack-frequency) accessors */
bool tquic_sysctl_get_ack_frequency_enabled(void)
{
	return tquic_ack_frequency_enabled;
}
EXPORT_SYMBOL_GPL(tquic_sysctl_get_ack_frequency_enabled);

u32 tquic_sysctl_get_default_ack_delay_us(void)
{
	return tquic_default_ack_delay_us;
}
EXPORT_SYMBOL_GPL(tquic_sysctl_get_default_ack_delay_us);

/* Preferred Address (RFC 9000 Section 9.6) accessors */
int tquic_sysctl_get_preferred_address_enabled(void)
{
	return tquic_preferred_address_enabled;
}
EXPORT_SYMBOL_GPL(tquic_sysctl_get_preferred_address_enabled);

int tquic_sysctl_get_prefer_preferred_address(void)
{
	return tquic_prefer_preferred_address;
}
EXPORT_SYMBOL_GPL(tquic_sysctl_get_prefer_preferred_address);

/* 0-RTT Early Data (RFC 9001 Section 4.6-4.7) accessors */
int tquic_sysctl_get_zero_rtt_enabled(void)
{
	return tquic_zero_rtt_enabled;
}
EXPORT_SYMBOL_GPL(tquic_sysctl_get_zero_rtt_enabled);

int tquic_sysctl_get_zero_rtt_max_age(void)
{
	return tquic_zero_rtt_max_age_seconds;
}
EXPORT_SYMBOL_GPL(tquic_sysctl_get_zero_rtt_max_age);

/* QPACK (RFC 9204) accessor */
int tquic_sysctl_get_qpack_max_table_capacity(void)
{
	return tquic_qpack_max_table_capacity;
}
EXPORT_SYMBOL_GPL(tquic_sysctl_get_qpack_max_table_capacity);

int __init tquic_sysctl_init(void)
{
	tquic_sysctl_header = register_net_sysctl(&init_net, "net/tquic",
						  tquic_sysctl_table);
	if (!tquic_sysctl_header)
		return -ENOMEM;

	pr_info("tquic: sysctl interface registered at /proc/sys/net/tquic/\n");
	return 0;
}

void __exit tquic_sysctl_exit(void)
{
	if (tquic_sysctl_header)
		unregister_net_sysctl_table(tquic_sysctl_header);
}
