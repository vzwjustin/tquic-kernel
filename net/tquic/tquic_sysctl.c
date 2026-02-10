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
#include <net/tquic.h>

#include "protocol.h"
#include "tquic_compat.h"
#include "crypto/cert_verify.h"
#include "crypto/zero_rtt.h"
#include "grease.h"
#include "pm/nat_keepalive.h"
#include "tquic_ack_frequency.h"
#include "tquic_debug.h"
#include "tquic_token.h"
#include "security_hardening.h"

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

/*
 * Connection Rate Limiting for DoS Protection
 *
 * rate_limit_enabled: Enable/disable connection rate limiting (default: enabled)
 * max_connections_per_second: Global rate limit for new connections (default: 10000)
 * max_connections_burst: Maximum burst capacity for global limiter (default: 1000)
 * per_ip_rate_limit: Per-IP connection rate limit (default: 100)
 */
static int tquic_rate_limit_enabled = 1;
static int tquic_max_connections_per_second = 10000;
static int tquic_max_connections_burst = 1000;
static int tquic_per_ip_rate_limit = 100;

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
 * QUIC Version Preference (RFC 9369 - Compatible Version Negotiation)
 *
 * preferred_version: Controls which QUIC version is preferred for new connections.
 *   0 = QUIC v1 (RFC 9000/9001) - default, maximum compatibility
 *   1 = QUIC v2 (RFC 9369) - improved security, ECN-aware congestion control
 *
 * When preferred_version is 1 (v2), clients will attempt to use QUIC v2 and
 * servers will prefer v2 during version negotiation. Falls back to v1 if peer
 * doesn't support v2.
 *
 * RFC 9369 differences from v1:
 *   - Different initial salt (0x0dede3def700a6db819381be6e269dcbf9bd2ed9)
 *   - Different HKDF labels ("quicv2 key/iv/hp/ku" instead of "quic key/iv/hp/ku")
 *   - Different long header packet type encoding
 *   - Different Retry integrity key/nonce
 */
static int tquic_preferred_version;			/* 0 = v1 (default), 1 = v2 */

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

/*
 * Additional Addresses Extension (draft-piraux-quic-additional-addresses)
 *
 * additional_addresses_enabled:
 *   When enabled, endpoints can advertise multiple addresses via transport
 *   parameters and use them for connection migration.
 *   Default: 1 (enabled) - allows flexible migration options.
 *
 * additional_addresses_max:
 *   Maximum number of additional addresses to advertise or accept.
 *   Default: 8 - provides reasonable flexibility without excessive overhead.
 */
static int tquic_additional_addresses_enabled = 1;	/* Enable extension */
static int tquic_additional_addresses_max = 8;		/* Max addresses */

/*
 * TLS Certificate Verification Settings (RFC 5280, RFC 6125)
 *
 * cert_verify_mode:
 *   0 = none (INSECURE - skip all certificate verification)
 *   1 = optional (verify if certificate present, allow missing)
 *   2 = required (full verification required - default, secure)
 *
 * cert_verify_hostname:
 *   0 = disabled (skip hostname verification - INSECURE)
 *   1 = enabled (verify CN/SAN matches - default, per RFC 6125)
 *
 * cert_revocation_mode:
 *   0 = none (skip revocation checking)
 *   1 = soft_fail (check if available, continue on failure - default)
 *   2 = hard_fail (require valid revocation response)
 *
 * cert_time_tolerance:
 *   Tolerance in seconds for notBefore/notAfter checking.
 *   Allows for clock skew between client and server.
 *   Default: 300 seconds (5 minutes), per common practice.
 */
static int tquic_cert_verify_mode = 2;			/* required (secure default) */
static int tquic_cert_verify_hostname = 1;		/* enabled (secure default) */
static int tquic_cert_revocation_mode = 1;		/* soft_fail (pragmatic default) */
static int tquic_cert_time_tolerance = 300;		/* 5 minutes clock skew tolerance */

/*
 * Security Hardening Tunables
 *
 * These settings provide defense against known QUIC vulnerabilities:
 * - CVE-2025-54939 (QUIC-LEAK): Pre-handshake memory exhaustion
 * - CVE-2024-22189: Retire CID stuffing attack
 * - Optimistic ACK attack via packet number skipping
 * - Spin bit privacy concerns
 */

/* Pre-handshake memory limit (CVE-2025-54939 defense) - in bytes */
static u64 tquic_pre_handshake_memory_limit = (64 * 1024 * 1024);  /* 64 MB */
static u64 tquic_pre_handshake_per_ip_budget = (1 * 1024 * 1024);  /* 1 MB */

/* Packet number skip rate for optimistic ACK defense (1 in N packets) */
static int tquic_pn_skip_rate = 128;  /* Default: 1 in 128 packets (~0.78%) */

/* Spin bit policy: 0=always correct, 1=never (random), 2=probabilistic */
static int tquic_spin_bit_policy = 2;  /* Default: probabilistic */
static int tquic_spin_bit_disable_rate = 8;  /* 1 in 8 = 12.5% disable */

/*
 * NAT Keepalive tunables (RFC 9308 Section 3.5)
 *
 * These control NAT binding keepalive behavior. QUIC connections through
 * NAT devices require periodic keepalive to prevent binding timeout.
 * Using PING frames minimizes overhead while keeping bindings alive.
 */
static int tquic_nat_keepalive_enabled = 1;		/* Enabled by default */
static int tquic_nat_keepalive_interval = 25000;	/* 25 seconds default */
static int tquic_nat_keepalive_min_interval = 5000;	/* 5 seconds minimum */
static int tquic_nat_keepalive_max_interval = 120000;	/* 2 minutes maximum */
static int tquic_nat_keepalive_adaptive = 1;		/* Adaptive mode on */

/* Forward declarations for scheduler API */
struct tquic_sched_ops;
struct tquic_sched_ops *tquic_sched_find(const char *name);
int tquic_sched_set_default(const char *name);

/* Forward declarations for CC API */
struct tquic_cong_ops;
struct tquic_cong_ops *tquic_cong_find(const char *name);
int tquic_cong_set_default(struct net *net, const char *name);
const char *tquic_cong_get_default_name(struct net *net);

/* Forward declarations for sysctl accessor functions */
int tquic_sysctl_get_bond_mode(void);
int tquic_sysctl_get_max_paths(void);
int tquic_sysctl_get_reorder_window(void);
int tquic_sysctl_get_probe_interval(void);
int tquic_sysctl_get_failover_timeout(void);
int tquic_sysctl_get_idle_timeout(void);
int tquic_sysctl_get_initial_rtt(void);
int tquic_sysctl_get_initial_cwnd(void);
int tquic_sysctl_get_debug_level(void);
const char *tquic_sysctl_get_scheduler(void);
const char *tquic_sysctl_get_congestion(void);
const char *tquic_net_get_cc_algorithm(struct net *net);
u32 tquic_net_get_bbr_rtt_threshold(struct net *net);
bool tquic_net_get_cc_coupled(struct net *net);
bool tquic_net_get_ecn_enabled(struct net *net);
u32 tquic_net_get_ecn_beta(struct net *net);
bool tquic_net_get_pacing_enabled(struct net *net);
int tquic_net_get_path_degrade_threshold(struct net *net);
unsigned long tquic_sysctl_get_key_update_interval_packets(void);
int tquic_sysctl_get_key_update_interval_seconds(void);
int tquic_sysctl_get_pmtud_enabled(void);
int tquic_sysctl_get_pmtud_probe_interval(void);
int tquic_sysctl_get_retry_required(void);
int tquic_sysctl_get_retry_token_lifetime(void);
int tquic_sysctl_get_http3_priorities_enabled(void);
int tquic_sysctl_get_preferred_address_enabled(void);
int tquic_sysctl_get_prefer_preferred_address(void);
int tquic_sysctl_get_additional_addresses_enabled(void);
int tquic_sysctl_get_additional_addresses_max(void);
int tquic_sysctl_get_qpack_max_table_capacity(void);
u8 tquic_sysctl_get_spin_bit_disable_rate(void);
int tquic_sysctl_rate_limit_enabled(void);
int tquic_sysctl_max_connections_per_second(void);
int tquic_sysctl_max_connections_burst(void);
int tquic_sysctl_per_ip_rate_limit(void);

/*
 * Per-netns scheduler sysctl handler
 *
 * Handles reading/writing net.tquic.scheduler which sets the default
 * scheduler for new connections in this network namespace.
 *
 * On read: Returns current default scheduler name
 * On write: Validates scheduler exists and sets as default
 */
static int proc_tquic_scheduler(TQUIC_CTL_TABLE *table, int write,
				void *buffer, size_t *lenp, loff_t *ppos)
{
	struct net *net = current->nsproxy->net_ns;
	char name[TQUIC_NET_SCHED_NAME_MAX];
	struct ctl_table tmp_table;
	int ret;

	if (!write) {
		/* Read current default scheduler for this netns */
		const char *current_name;

		rcu_read_lock();
		if (tquic_pernet(net)->default_scheduler)
			current_name = tquic_pernet(net)->default_scheduler->name;
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
	strscpy(name, tquic_pernet(net)->sched_name, sizeof(name));

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
		tquic_warn("unknown scheduler '%s'\n", name);
		return -ENOENT;
	}
	rcu_read_unlock();

	/* Set default scheduler (global for out-of-tree build, void return) */
	tquic_sched_set_default(name);

	tquic_dbg("netns scheduler set to '%s'\n", name);
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
static int proc_tquic_cc_algorithm(TQUIC_CTL_TABLE *table, int write,
				   void *buffer, size_t *lenp, loff_t *ppos)
{
	struct net *net = current->nsproxy->net_ns;
	char name[TQUIC_NET_CC_NAME_MAX];
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
	strscpy(name, tquic_pernet(net)->cc_name, sizeof(name));

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
		tquic_warn("unknown CC algorithm '%s'\n", name);
		return -ENOENT;
	}

	/* Set per-netns default CC algorithm */
	ret = tquic_cong_set_default(net, name);
	if (ret) {
		tquic_warn("failed to set CC algorithm '%s': %d\n", name, ret);
		return ret;
	}

	tquic_dbg("netns CC algorithm set to '%s'\n", name);
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
static int proc_tquic_bbr_rtt_threshold(TQUIC_CTL_TABLE *table, int write,
					void *buffer, size_t *lenp, loff_t *ppos)
{
	struct net *net = current->nsproxy->net_ns;
	int val = tquic_pernet(net)->bbr_rtt_threshold_ms;
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

	tquic_pernet(net)->bbr_rtt_threshold_ms = val;
	tquic_dbg("netns BBR RTT threshold set to %d ms\n", val);
	return 0;
}

/*
 * Per-netns coupled CC sysctl handler
 *
 * Handles reading/writing net.tquic.cc_coupled which enables/disables
 * coupled congestion control for multipath TCP-fairness.
 */
static int proc_tquic_cc_coupled(TQUIC_CTL_TABLE *table, int write,
				 void *buffer, size_t *lenp, loff_t *ppos)
{
	struct net *net = current->nsproxy->net_ns;
	int val = tquic_pernet(net)->coupled_enabled ? 1 : 0;
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

	tquic_pernet(net)->coupled_enabled = !!val;
	tquic_dbg("netns coupled CC %s\n",
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
static int proc_tquic_ecn_enabled(TQUIC_CTL_TABLE *table, int write,
				  void *buffer, size_t *lenp, loff_t *ppos)
{
	struct net *net = current->nsproxy->net_ns;
	int val = tquic_pernet(net)->ecn_enabled ? 1 : 0;
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

	tquic_pernet(net)->ecn_enabled = !!val;
	tquic_dbg("netns ECN %s\n", val ? "enabled" : "disabled");
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
static int proc_tquic_ecn_beta(TQUIC_CTL_TABLE *table, int write,
			       void *buffer, size_t *lenp, loff_t *ppos)
{
	struct net *net = current->nsproxy->net_ns;
	int val = tquic_pernet(net)->ecn_beta ?: 800;  /* Default to 0.8 */
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

	tquic_pernet(net)->ecn_beta = val;
	tquic_dbg("netns ECN beta set to %d/1000 (%d.%d%%)\n",
		 val, val / 10, val % 10);
	return 0;
}

/* Legacy global sysctl handler (for compatibility) */
static int __maybe_unused tquic_sysctl_scheduler(TQUIC_CTL_TABLE *table, int write,
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
		tquic_warn("unknown scheduler '%s'\n", tquic_scheduler);
		return -ENOENT;
	}
	rcu_read_unlock();

	/* Set global default scheduler (void return in current API) */
	tquic_sched_set_default(tquic_scheduler);

	return 0;
}

static int tquic_sysctl_bond_mode(TQUIC_CTL_TABLE *table, int write,
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
static int proc_tquic_pacing_enabled(TQUIC_CTL_TABLE *table, int write,
				     void *buffer, size_t *lenp, loff_t *ppos)
{
	struct net *net = current->nsproxy->net_ns;
	int val = tquic_pernet(net)->pacing_enabled ? 1 : 0;
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

	tquic_pernet(net)->pacing_enabled = !!val;
	tquic_dbg("netns pacing %s\n", val ? "enabled" : "disabled");
	return 0;
}

/*
 * Per-netns path degradation threshold sysctl handler
 *
 * Handles reading/writing net.tquic.path_degrade_threshold which sets
 * the number of consecutive losses in same round before path degradation.
 * Default is 5 per RESEARCH.md recommendation.
 */
static int proc_tquic_path_degrade_threshold(TQUIC_CTL_TABLE *table, int write,
					     void *buffer, size_t *lenp,
					     loff_t *ppos)
{
	struct net *net = current->nsproxy->net_ns;
	int val = tquic_pernet(net)->path_degrade_threshold;
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

	tquic_pernet(net)->path_degrade_threshold = val;
	tquic_dbg("netns path_degrade_threshold set to %d\n", val);
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
static int proc_tquic_grease_enabled(TQUIC_CTL_TABLE *table, int write,
				     void *buffer, size_t *lenp, loff_t *ppos)
{
	struct net *net = current->nsproxy->net_ns;
	int val = tquic_pernet(net)->grease_enabled ? 1 : 0;
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

	tquic_pernet(net)->grease_enabled = !!val;
	tquic_dbg("netns GREASE %s\n", val ? "enabled" : "disabled");
	return 0;
}

/* Min/max values for integer tunables */
static int zero;
static int one = 1;
static int sixteen = 16;
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
static int max_cert_verify_mode = 2;      /* required = maximum */
static int max_revocation_mode = 2;       /* hard_fail = maximum */
static int max_cert_time_tolerance = 86400;  /* 24 hours max clock skew */

/* Pre-handshake memory limit bounds (1 MB to 512 MB) */
static unsigned long min_pre_hs_memory = (1UL * 1024 * 1024);	  /* 1 MB */
static unsigned long max_pre_hs_memory = (512UL * 1024 * 1024);  /* 512 MB */
static unsigned long min_pre_hs_per_ip = (64UL * 1024);	  /* 64 KB */
static unsigned long max_pre_hs_per_ip = (64UL * 1024 * 1024);	  /* 64 MB */

/* Debug level bounds */
static int max_debug_level = 7;

/* Rate limiting min/max values */
static int max_connections_rate = 1000000;  /* 1M conn/s max */
static int max_burst_limit = 100000;        /* 100K burst max */
static int max_per_ip_rate = 10000;         /* 10K per-IP max */

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
		.maxlen		= TQUIC_NET_CC_NAME_MAX,
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
		.proc_handler	= proc_dointvec_minmax,
		.extra1		= &zero,
		.extra2		= &max_debug_level,
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
	 * Additional Addresses Extension (draft-piraux-quic-additional-addresses)
	 *
	 * Allows endpoints to advertise multiple addresses for connection
	 * migration and multipath scenarios beyond the single preferred_address.
	 *
	 * Default: enabled
	 */
	{
		.procname	= "additional_addresses_enabled",
		.data		= &tquic_additional_addresses_enabled,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= proc_dointvec_minmax,
		.extra1		= &zero,
		.extra2		= &one,
	},
	/*
	 * Maximum number of additional addresses to advertise/accept.
	 * Higher values provide more migration options but increase
	 * transport parameter size and memory usage.
	 *
	 * Default: 8
	 * Range: 1 to 16
	 */
	{
		.procname	= "additional_addresses_max",
		.data		= &tquic_additional_addresses_max,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= proc_dointvec_minmax,
		.extra1		= &one,
		.extra2		= &sixteen,
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
	/*
	 * QUIC Version Preference (RFC 9369 - QUIC Version 2)
	 *
	 * Controls which QUIC version is preferred for new connections:
	 *   0 = QUIC v1 (RFC 9000/9001) - default, maximum compatibility
	 *   1 = QUIC v2 (RFC 9369) - improved security properties
	 *
	 * QUIC v2 uses different cryptographic parameters:
	 *   - Initial salt: 0x0dede3def700a6db819381be6e269dcbf9bd2ed9
	 *   - HKDF labels: "quicv2 key", "quicv2 iv", "quicv2 hp", "quicv2 ku"
	 *   - Different long header packet type bits encoding
	 *   - Different Retry integrity key/nonce
	 *
	 * Compatible Version Negotiation (RFC 9368) allows graceful fallback
	 * to v1 if the peer doesn't support v2.
	 *
	 * Default: 0 (QUIC v1)
	 */
	{
		.procname	= "preferred_version",
		.data		= &tquic_preferred_version,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= proc_dointvec_minmax,
		.extra1		= &zero,
		.extra2		= &one,
	},
	/*
	 * TLS Certificate Verification Mode (RFC 5280)
	 *
	 * Controls how strictly certificate verification is enforced:
	 *   0 = none (INSECURE - skip all verification, use for testing only)
	 *   1 = optional (verify if present, allow connections without certs)
	 *   2 = required (full chain verification required - secure default)
	 *
	 * In mode 2 (required), all of the following must pass:
	 *   - Certificate signature verified against issuer's public key
	 *   - Certificate chain builds to a trusted root
	 *   - Validity period (notBefore/notAfter) checked
	 *   - Key usage and extended key usage validated
	 *   - Hostname verification (if enabled)
	 *   - Revocation status (per cert_revocation_mode)
	 *
	 * WARNING: Setting to 0 or 1 weakens security significantly.
	 * Only use for testing or in environments with alternative security.
	 *
	 * Default: 2 (required) - maximum security
	 */
	{
		.procname	= "cert_verify_mode",
		.data		= &tquic_cert_verify_mode,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= proc_dointvec_minmax,
		.extra1		= &zero,
		.extra2		= &max_cert_verify_mode,
	},
	/*
	 * TLS Certificate Hostname Verification (RFC 6125)
	 *
	 * When enabled, the hostname provided in SNI must match either:
	 *   - A Subject Alternative Name (SAN) dNSName extension entry
	 *   - The Common Name (CN) in the Subject field (deprecated fallback)
	 *
	 * Wildcard matching is supported per RFC 6125 Section 6.4.3:
	 *   - Wildcard (*) may appear in leftmost label only
	 *   - *.example.com matches foo.example.com but not bar.foo.example.com
	 *   - Wildcard does not match the parent domain (*.com invalid)
	 *
	 * WARNING: Disabling hostname verification allows MITM attacks.
	 * Only disable for testing or when IP addresses are used.
	 *
	 * Default: 1 (enabled) - secure
	 */
	{
		.procname	= "cert_verify_hostname",
		.data		= &tquic_cert_verify_hostname,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= proc_dointvec_minmax,
		.extra1		= &zero,
		.extra2		= &one,
	},
	/*
	 * TLS Certificate Revocation Checking Mode
	 *
	 * Controls how certificate revocation status is verified:
	 *   0 = none (skip revocation checking)
	 *   1 = soft_fail (check OCSP stapling if provided, continue otherwise)
	 *   2 = hard_fail (require valid OCSP response, reject if unavailable)
	 *
	 * In the kernel environment, full OCSP/CRL checking is limited because
	 * the kernel cannot make HTTP/HTTPS requests. Instead, we support:
	 *   - OCSP stapling: Server provides pre-fetched OCSP response
	 *   - Must-staple: Honor the TLS feature extension requiring stapling
	 *
	 * soft_fail (mode 1) is the pragmatic default - it validates OCSP
	 * responses when stapled but doesn't fail connections otherwise.
	 * This matches common browser behavior.
	 *
	 * Default: 1 (soft_fail) - pragmatic balance of security/availability
	 */
	{
		.procname	= "cert_revocation_mode",
		.data		= &tquic_cert_revocation_mode,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= proc_dointvec_minmax,
		.extra1		= &zero,
		.extra2		= &max_revocation_mode,
	},
	/*
	 * TLS Certificate Time Tolerance (seconds)
	 *
	 * Tolerance for certificate validity period checking (notBefore/notAfter).
	 * Allows for clock skew between client, server, and CA systems.
	 *
	 * The certificate is considered valid if:
	 *   current_time >= (notBefore - tolerance)  AND
	 *   current_time <= (notAfter + tolerance)
	 *
	 * A tolerance of 300 seconds (5 minutes) handles typical NTP skew.
	 * In air-gapped or embedded systems, larger values may be needed.
	 *
	 * Range: 0 to 86400 seconds (0 to 24 hours)
	 * Default: 300 seconds (5 minutes)
	 */
	{
		.procname	= "cert_time_tolerance",
		.data		= &tquic_cert_time_tolerance,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= proc_dointvec_minmax,
		.extra1		= &zero,
		.extra2		= &max_cert_time_tolerance,
	},
	/*
	 * Connection Rate Limiting for DoS Protection
	 *
	 * These parameters control connection rate limiting to protect
	 * against denial-of-service attacks. Rate limiting is applied
	 * at the earliest possible point (Initial packet processing)
	 * before allocating any connection state.
	 */
	{
		.procname	= "rate_limit_enabled",
		.data		= &tquic_rate_limit_enabled,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= proc_dointvec_minmax,
		.extra1		= &zero,
		.extra2		= &one,
	},
	/*
	 * max_connections_per_second: Global connection rate limit
	 *
	 * Maximum number of new connections per second across all clients.
	 * This is the first line of defense against connection flood attacks.
	 *
	 * Default: 10000 connections/second
	 * Range: 1 to 1000000
	 */
	{
		.procname	= "max_connections_per_second",
		.data		= &tquic_max_connections_per_second,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= proc_dointvec_minmax,
		.extra1		= &one,
		.extra2		= &max_connections_rate,
	},
	/*
	 * max_connections_burst: Burst capacity for global rate limiter
	 *
	 * Maximum burst of connections that can be accepted before
	 * rate limiting kicks in. This allows handling temporary spikes
	 * while still protecting against sustained attacks.
	 *
	 * Default: 1000 connections
	 * Range: 1 to 100000
	 */
	{
		.procname	= "max_connections_burst",
		.data		= &tquic_max_connections_burst,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= proc_dointvec_minmax,
		.extra1		= &one,
		.extra2		= &max_burst_limit,
	},
	/*
	 * per_ip_rate_limit: Per-IP connection rate limit
	 *
	 * Maximum connections per second from a single IP address.
	 * This prevents a single attacker from exhausting the global
	 * rate limit, ensuring fair access for legitimate clients.
	 *
	 * Default: 100 connections/second per IP
	 * Range: 1 to 10000
	 */
	{
		.procname	= "per_ip_rate_limit",
		.data		= &tquic_per_ip_rate_limit,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= proc_dointvec_minmax,
		.extra1		= &one,
		.extra2		= &max_per_ip_rate,
	},
	/*
	 * =============================================================================
	 * SECURITY HARDENING SETTINGS
	 * =============================================================================
	 */
	/*
	 * pre_handshake_memory_limit: CVE-2025-54939 (QUIC-LEAK) defense
	 *
	 * Maximum total memory allowed for connections before handshake completes.
	 * This limits the damage from amplification attacks using spoofed IPs.
	 *
	 * Default: 67108864 (64 MB)
	 * Range: 1MB to 512MB
	 */
	{
		.procname	= "pre_handshake_memory_limit",
		.data		= &tquic_pre_handshake_memory_limit,
		.maxlen		= sizeof(u64),
		.mode		= 0644,
		.proc_handler	= proc_doulongvec_minmax,
		.extra1		= &min_pre_hs_memory,
		.extra2		= &max_pre_hs_memory,
	},
	/*
	 * pre_handshake_per_ip_budget: Per-IP pre-handshake memory limit
	 *
	 * Maximum memory allowed for pre-handshake state from a single
	 * source IP address. Limits the damage from a single attacker.
	 *
	 * Default: 1048576 (1 MB)
	 * Range: 64KB to 64MB
	 */
	{
		.procname	= "pre_handshake_per_ip_budget",
		.data		= &tquic_pre_handshake_per_ip_budget,
		.maxlen		= sizeof(u64),
		.mode		= 0644,
		.proc_handler	= proc_doulongvec_minmax,
		.extra1		= &min_pre_hs_per_ip,
		.extra2		= &max_pre_hs_per_ip,
	},
	/*
	 * pn_skip_rate: Optimistic ACK attack defense
	 *
	 * Randomly skip packet numbers to detect peers that ACK unsent packets.
	 * Value is "1 in N" - higher means less frequent skipping.
	 *
	 * Default: 128 (skip ~0.78% of packet numbers)
	 * Range: 8 to 65536 (0 disables skipping)
	 */
	{
		.procname	= "pn_skip_rate",
		.data		= &tquic_pn_skip_rate,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= proc_dointvec_minmax,
		.extra1		= SYSCTL_ZERO,
		.extra2		= SYSCTL_INT_MAX,
	},
	/*
	 * spin_bit_policy: Spin bit privacy control
	 *
	 * Controls the spin bit behavior for latency privacy:
	 *   0 = always (always set spin bit correctly)
	 *   1 = never (always use random value - maximum privacy)
	 *   2 = probabilistic (sometimes use random - balance)
	 *
	 * Default: 2 (probabilistic)
	 */
	{
		.procname	= "spin_bit_policy",
		.data		= &tquic_spin_bit_policy,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= proc_dointvec_minmax,
		.extra1		= SYSCTL_ZERO,
		.extra2		= SYSCTL_TWO,
	},
	/*
	 * =============================================================================
	 * NAT KEEPALIVE SETTINGS (RFC 9308 Section 3.5)
	 * =============================================================================
	 *
	 * NAT keepalive sends minimal PING frames to keep NAT bindings alive.
	 * This prevents connection disruption when NAT timeouts occur.
	 */
	/*
	 * nat_keepalive_enabled: Enable/disable NAT keepalive
	 *
	 * When enabled, TQUIC sends minimal PING frames on idle paths to
	 * prevent NAT binding timeout. This is essential for connections
	 * through NAT devices with short UDP binding timeouts.
	 *
	 * Default: 1 (enabled)
	 */
	{
		.procname	= "nat_keepalive_enabled",
		.data		= &tquic_nat_keepalive_enabled,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= proc_dointvec_minmax,
		.extra1		= SYSCTL_ZERO,
		.extra2		= SYSCTL_ONE,
	},
	/*
	 * nat_keepalive_interval: Keepalive interval in milliseconds
	 *
	 * Time between keepalive packets on idle paths. Should be less than
	 * the shortest expected NAT binding timeout (typically 30 seconds).
	 * RFC 9308 recommends sending keepalives well before timeout.
	 *
	 * Default: 25000 (25 seconds, safe for most NATs)
	 * Range: 5000 to 120000 (5 seconds to 2 minutes)
	 */
	{
		.procname	= "nat_keepalive_interval",
		.data		= &tquic_nat_keepalive_interval,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= proc_dointvec_minmax,
		.extra1		= &tquic_nat_keepalive_min_interval,
		.extra2		= &tquic_nat_keepalive_max_interval,
	},
	/*
	 * nat_keepalive_adaptive: Enable adaptive interval estimation
	 *
	 * When enabled, the keepalive interval is automatically adjusted
	 * based on observed NAT timeout behavior:
	 * - Successful keepalives: gradually increase interval (less traffic)
	 * - Failed keepalives: decrease interval (more reliable)
	 *
	 * This optimizes battery life on mobile devices while maintaining
	 * reliable NAT binding.
	 *
	 * Default: 1 (enabled)
	 */
	{
		.procname	= "nat_keepalive_adaptive",
		.data		= &tquic_nat_keepalive_adaptive,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= proc_dointvec_minmax,
		.extra1		= SYSCTL_ZERO,
		.extra2		= SYSCTL_ONE,
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

/* Default BBR RTT threshold in ms (100ms is standard default) */
#define TQUIC_DEFAULT_BBR_RTT_THRESHOLD_MS	100

u32 tquic_net_get_bbr_rtt_threshold(struct net *net)
{
	if (!net)
		return TQUIC_DEFAULT_BBR_RTT_THRESHOLD_MS;
	return tquic_pernet(net)->bbr_rtt_threshold_ms;
}
EXPORT_SYMBOL_GPL(tquic_net_get_bbr_rtt_threshold);

bool tquic_net_get_cc_coupled(struct net *net)
{
	if (!net)
		return false;
	return tquic_pernet(net)->coupled_enabled;
}
EXPORT_SYMBOL_GPL(tquic_net_get_cc_coupled);

bool tquic_net_get_ecn_enabled(struct net *net)
{
	if (!net)
		return false;
	return tquic_pernet(net)->ecn_enabled;
}
EXPORT_SYMBOL_GPL(tquic_net_get_ecn_enabled);

u32 tquic_net_get_ecn_beta(struct net *net)
{
	if (!net)
		return 800;  /* Default 0.8 scaled by 1000 */
	return tquic_pernet(net)->ecn_beta ?: 800;
}
EXPORT_SYMBOL_GPL(tquic_net_get_ecn_beta);

bool tquic_net_get_pacing_enabled(struct net *net)
{
	if (!net)
		return true;  /* Pacing enabled by default per CONTEXT.md */
	return tquic_pernet(net)->pacing_enabled;
}
EXPORT_SYMBOL_GPL(tquic_net_get_pacing_enabled);

int tquic_net_get_path_degrade_threshold(struct net *net)
{
	if (!net)
		return 5;  /* Default per RESEARCH.md recommendation */
	return tquic_pernet(net)->path_degrade_threshold ?: 5;
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

/* Additional Addresses Extension (draft-piraux-quic-additional-addresses) accessors */
int tquic_sysctl_get_additional_addresses_enabled(void)
{
	return tquic_additional_addresses_enabled;
}
EXPORT_SYMBOL_GPL(tquic_sysctl_get_additional_addresses_enabled);

int tquic_sysctl_get_additional_addresses_max(void)
{
	return tquic_additional_addresses_max;
}
EXPORT_SYMBOL_GPL(tquic_sysctl_get_additional_addresses_max);

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

/*
 * QUIC Version Preference (RFC 9369) accessor
 *
 * Returns the preferred QUIC version number based on sysctl setting:
 *   tquic_preferred_version == 0: Returns TQUIC_VERSION_1 (0x00000001)
 *   tquic_preferred_version == 1: Returns TQUIC_VERSION_2 (0x6b3343cf)
 */
u32 tquic_sysctl_get_preferred_version(void)
{
	if (tquic_preferred_version == 1)
		return TQUIC_VERSION_2;
	return TQUIC_VERSION_1;
}
EXPORT_SYMBOL_GPL(tquic_sysctl_get_preferred_version);

/*
 * Check if QUIC v2 is preferred (convenience function)
 */
bool tquic_sysctl_prefer_v2(void)
{
	return tquic_preferred_version == 1;
}
EXPORT_SYMBOL_GPL(tquic_sysctl_prefer_v2);

/*
 * TLS Certificate Verification Settings Accessors (RFC 5280, RFC 6125)
 *
 * These functions provide access to certificate verification configuration
 * from the crypto/cert_verify.c module.
 */

/**
 * tquic_sysctl_get_cert_verify_mode - Get certificate verification mode
 *
 * Returns:
 *   0 = none (skip verification - INSECURE)
 *   1 = optional (verify if present, allow missing)
 *   2 = required (full verification required)
 */
int tquic_sysctl_get_cert_verify_mode(void)
{
	return tquic_cert_verify_mode;
}
EXPORT_SYMBOL_GPL(tquic_sysctl_get_cert_verify_mode);

/**
 * tquic_sysctl_get_cert_verify_hostname - Check if hostname verification enabled
 *
 * Returns: true if hostname verification is enabled, false otherwise
 */
bool tquic_sysctl_get_cert_verify_hostname(void)
{
	return tquic_cert_verify_hostname != 0;
}
EXPORT_SYMBOL_GPL(tquic_sysctl_get_cert_verify_hostname);

/**
 * tquic_sysctl_get_cert_revocation_mode - Get revocation checking mode
 *
 * Returns:
 *   0 = none (skip revocation checking)
 *   1 = soft_fail (check if available, continue on failure)
 *   2 = hard_fail (require valid revocation response)
 */
int tquic_sysctl_get_cert_revocation_mode(void)
{
	return tquic_cert_revocation_mode;
}
EXPORT_SYMBOL_GPL(tquic_sysctl_get_cert_revocation_mode);

/**
 * tquic_sysctl_get_cert_time_tolerance - Get time tolerance for validity check
 *
 * Returns: Tolerance in seconds for notBefore/notAfter checking
 */
u32 tquic_sysctl_get_cert_time_tolerance(void)
{
	return (u32)tquic_cert_time_tolerance;
}
EXPORT_SYMBOL_GPL(tquic_sysctl_get_cert_time_tolerance);

/*
 * Rate Limiting Accessor Functions
 */

/**
 * tquic_sysctl_rate_limit_enabled - Check if rate limiting is enabled
 *
 * Returns: 1 if rate limiting is enabled, 0 if disabled
 */
int tquic_sysctl_rate_limit_enabled(void)
{
	return tquic_rate_limit_enabled;
}
EXPORT_SYMBOL_GPL(tquic_sysctl_rate_limit_enabled);

/**
 * tquic_sysctl_max_connections_per_second - Get global rate limit
 *
 * Returns: Maximum connections per second (global)
 */
int tquic_sysctl_max_connections_per_second(void)
{
	return tquic_max_connections_per_second;
}
EXPORT_SYMBOL_GPL(tquic_sysctl_max_connections_per_second);

/**
 * tquic_sysctl_max_connections_burst - Get burst capacity
 *
 * Returns: Maximum burst size for global rate limiter
 */
int tquic_sysctl_max_connections_burst(void)
{
	return tquic_max_connections_burst;
}
EXPORT_SYMBOL_GPL(tquic_sysctl_max_connections_burst);

/**
 * tquic_sysctl_per_ip_rate_limit - Get per-IP rate limit
 *
 * Returns: Maximum connections per second per IP
 */
int tquic_sysctl_per_ip_rate_limit(void)
{
	return tquic_per_ip_rate_limit;
}
EXPORT_SYMBOL_GPL(tquic_sysctl_per_ip_rate_limit);

/*
 * =============================================================================
 * SECURITY HARDENING ACCESSORS
 * =============================================================================
 */

/**
 * tquic_sysctl_get_pre_handshake_memory_limit - Get pre-handshake memory limit
 *
 * Returns: Maximum bytes allowed for pre-handshake connection state
 *
 * This limit defends against CVE-2025-54939 (QUIC-LEAK attack).
 */
u64 tquic_sysctl_get_pre_handshake_memory_limit(void)
{
	return tquic_pre_handshake_memory_limit;
}
EXPORT_SYMBOL_GPL(tquic_sysctl_get_pre_handshake_memory_limit);

/**
 * tquic_sysctl_get_pre_handshake_per_ip_budget - Get per-IP pre-handshake budget
 *
 * Returns: Maximum bytes per source IP for pre-handshake state
 */
u64 tquic_sysctl_get_pre_handshake_per_ip_budget(void)
{
	return tquic_pre_handshake_per_ip_budget;
}
EXPORT_SYMBOL_GPL(tquic_sysctl_get_pre_handshake_per_ip_budget);

/**
 * tquic_sysctl_get_pn_skip_rate - Get packet number skip rate
 *
 * Returns: Skip rate (1 in N packets), 0 means disabled
 *
 * Packet number skipping helps detect optimistic ACK attacks.
 */
u32 tquic_sysctl_get_pn_skip_rate(void)
{
	return (u32)tquic_pn_skip_rate;
}
EXPORT_SYMBOL_GPL(tquic_sysctl_get_pn_skip_rate);

/**
 * tquic_sysctl_get_spin_bit_policy - Get spin bit privacy policy
 *
 * Returns: Policy value (0=always, 1=never, 2=probabilistic)
 */
u8 tquic_sysctl_get_spin_bit_policy(void)
{
	return (u8)tquic_spin_bit_policy;
}
EXPORT_SYMBOL_GPL(tquic_sysctl_get_spin_bit_policy);

/**
 * tquic_sysctl_get_spin_bit_disable_rate - Get spin bit probabilistic disable rate
 *
 * Returns: Disable rate (1 in N packets)
 */
u8 tquic_sysctl_get_spin_bit_disable_rate(void)
{
	return (u8)tquic_spin_bit_disable_rate;
}
EXPORT_SYMBOL_GPL(tquic_sysctl_get_spin_bit_disable_rate);

/*
 * =============================================================================
 * NAT KEEPALIVE ACCESSORS (RFC 9308 Section 3.5)
 * =============================================================================
 */

/**
 * tquic_sysctl_get_nat_keepalive_enabled - Get NAT keepalive enabled state
 *
 * Returns: 1 if NAT keepalive is enabled, 0 if disabled
 */
int tquic_sysctl_get_nat_keepalive_enabled(void)
{
	return tquic_nat_keepalive_enabled;
}
EXPORT_SYMBOL_GPL(tquic_sysctl_get_nat_keepalive_enabled);

/**
 * tquic_sysctl_get_nat_keepalive_interval - Get NAT keepalive interval
 *
 * Returns: Keepalive interval in milliseconds
 */
u32 tquic_sysctl_get_nat_keepalive_interval(void)
{
	return (u32)tquic_nat_keepalive_interval;
}
EXPORT_SYMBOL_GPL(tquic_sysctl_get_nat_keepalive_interval);

/**
 * tquic_sysctl_get_nat_keepalive_adaptive - Get NAT keepalive adaptive mode
 *
 * Returns: 1 if adaptive mode is enabled, 0 if disabled
 */
int tquic_sysctl_get_nat_keepalive_adaptive(void)
{
	return tquic_nat_keepalive_adaptive;
}
EXPORT_SYMBOL_GPL(tquic_sysctl_get_nat_keepalive_adaptive);

/* Number of actual sysctl entries (excluding null terminator) */
#define TQUIC_SYSCTL_TABLE_ENTRIES (ARRAY_SIZE(tquic_sysctl_table) - 1)

int __init tquic_sysctl_init(void)
{
	/*
	 * Kernel 6.x requires register_net_sysctl_sz() with explicit size
	 * to avoid validation errors on the null terminator entry.
	 */
	tquic_sysctl_header = register_net_sysctl_sz(&init_net, "net/tquic",
						     tquic_sysctl_table,
						     TQUIC_SYSCTL_TABLE_ENTRIES);
	if (!tquic_sysctl_header)
		return -ENOMEM;

	tquic_info("sysctl interface registered at /proc/sys/net/tquic/\n");
	return 0;
}

void __exit tquic_sysctl_exit(void)
{
	if (tquic_sysctl_header)
		unregister_net_sysctl_table(tquic_sysctl_header);
}
