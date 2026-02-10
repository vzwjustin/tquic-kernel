// SPDX-License-Identifier: GPL-2.0-only
/*
 * TQUIC: Persistent Congestion Detection (RFC 9002 Section 7.6)
 *
 * Copyright (c) 2026 Linux Foundation
 *
 * This module implements persistent congestion detection for QUIC loss
 * recovery. When packets spanning the persistent congestion period are
 * all lost, the sender declares persistent congestion and resets to
 * minimum cwnd.
 *
 * Per RFC 9002 Section 7.6:
 * "Persistent congestion is established by marking packets as lost
 * because of a probe timeout (PTO). When an acknowledgment is received
 * that newly acknowledges packets, the sender MUST detect lost packets
 * using the procedure described in Section 6.1. Packets that are
 * declared lost from a single packet number space MUST be analyzed
 * for persistent congestion."
 *
 * Algorithm Overview:
 * 1. When declaring loss, collect all lost packets
 * 2. Find the earliest and latest ACK-eliciting lost packets
 * 3. Check if their send times span the persistent congestion period
 * 4. If so, reset cwnd to minimum and notify CC algorithm
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/sort.h>
#include <net/tquic.h>
#include <net/net_namespace.h>
#include "../protocol.h"
#include "../tquic_compat.h"
#include "../tquic_debug.h"
#include "persistent_cong.h"
#include "../tquic_mib.h"

/*
 * Default persistent congestion threshold
 * This is exposed via sysctl net.tquic.persistent_cong_threshold
 */
static u32 tquic_persistent_cong_threshold = TQUIC_PERSISTENT_CONG_THRESHOLD_DEFAULT;

/**
 * tquic_net_get_persistent_cong_threshold - Get threshold from netns
 * @net: Network namespace
 *
 * Return: Persistent congestion threshold (default 3)
 */
u32 tquic_net_get_persistent_cong_threshold(struct net *net)
{
	/* For now, use global threshold. Per-netns can be added later */
	return tquic_persistent_cong_threshold;
}
EXPORT_SYMBOL_GPL(tquic_net_get_persistent_cong_threshold);

/**
 * tquic_persistent_cong_init - Initialize persistent congestion state
 * @state: State to initialize
 */
void tquic_persistent_cong_init(struct tquic_persistent_cong_state *state)
{
	if (!state)
		return;

	memset(state, 0, sizeof(*state));
	state->smoothed_rtt = 0;
	state->rtt_var = 0;
	state->has_rtt_sample = false;
	state->pn_space_active = 0;
	state->last_persistent_cong = ns_to_ktime(0);
	state->persistent_cong_count = 0;
}
EXPORT_SYMBOL_GPL(tquic_persistent_cong_init);

/**
 * tquic_persistent_cong_update_rtt - Update RTT information
 * @state: Persistent congestion state
 * @smoothed_rtt: New smoothed RTT in microseconds
 * @rtt_var: New RTT variance in microseconds
 */
void tquic_persistent_cong_update_rtt(struct tquic_persistent_cong_state *state,
				      u64 smoothed_rtt, u64 rtt_var)
{
	if (!state)
		return;

	state->smoothed_rtt = smoothed_rtt;
	state->rtt_var = rtt_var;
	state->has_rtt_sample = true;
}
EXPORT_SYMBOL_GPL(tquic_persistent_cong_update_rtt);

/**
 * tquic_persistent_cong_set_pn_space - Mark a packet number space as active
 * @state: Persistent congestion state
 * @pn_space: Packet number space (0=Initial, 1=Handshake, 2=Application)
 */
void tquic_persistent_cong_set_pn_space(struct tquic_persistent_cong_state *state,
					u8 pn_space)
{
	if (!state || pn_space >= TQUIC_PN_SPACE_COUNT)
		return;

	state->pn_space_active |= (1 << pn_space);
}
EXPORT_SYMBOL_GPL(tquic_persistent_cong_set_pn_space);

/**
 * tquic_persistent_cong_period - Calculate persistent congestion period
 * @state: Persistent congestion state
 * @net: Network namespace for threshold configuration
 *
 * Per RFC 9002 Section 7.6.2:
 *   persistent_duration = (smoothed_rtt + max(4*rtt_var, kGranularity)) * threshold
 *
 * Return: Persistent congestion period in microseconds
 */
u64 tquic_persistent_cong_period(struct tquic_persistent_cong_state *state,
				 struct net *net)
{
	u64 pto_period;
	u64 max_rtt_var;
	u32 threshold;

	if (!state || !state->has_rtt_sample)
		return 0;

	/*
	 * Calculate PTO period (RFC 9002 Section 6.2.1):
	 *   PTO = smoothed_rtt + max(4*rtt_var, kGranularity)
	 */
	max_rtt_var = max(4 * state->rtt_var, (u64)TQUIC_TIMER_GRANULARITY_US);
	pto_period = state->smoothed_rtt + max_rtt_var;

	/*
	 * Persistent congestion period = PTO * kPersistentCongestionThreshold
	 */
	threshold = tquic_net_get_persistent_cong_threshold(net);
	return pto_period * threshold;
}
EXPORT_SYMBOL_GPL(tquic_persistent_cong_period);

/*
 * Comparator for sorting lost packets by send time
 */
static int lost_packet_cmp(const void *a, const void *b)
{
	const struct tquic_lost_packet *pa = a;
	const struct tquic_lost_packet *pb = b;
	s64 diff = ktime_to_ns(pa->send_time) - ktime_to_ns(pb->send_time);

	if (diff < 0)
		return -1;
	if (diff > 0)
		return 1;
	return 0;
}

/**
 * tquic_check_persistent_cong - Check if persistent congestion occurred
 * @state: Persistent congestion state
 * @lost_packets: Array of lost packets
 * @num_lost: Number of lost packets
 * @net: Network namespace for configuration
 *
 * Per RFC 9002 Section 7.6.2:
 * "A sender establishes persistent congestion after the receipt of an
 * acknowledgement if two packets that are ack-eliciting are declared
 * lost, and:
 *   - across all packet number spaces, none of the packets sent between
 *     the send times of these two packets are acknowledged;
 *   - the duration between the send times of these two packets exceeds
 *     the persistent congestion duration; and
 *   - a prior RTT sample existed when these two packets were sent."
 *
 * Simplified check: We check if the earliest and latest ACK-eliciting
 * lost packets span the persistent congestion period. A more complete
 * implementation would track all in-flight packets.
 *
 * Return: true if persistent congestion detected, false otherwise
 */
bool tquic_check_persistent_cong(struct tquic_persistent_cong_state *state,
				 struct tquic_lost_packet *lost_packets,
				 int num_lost, struct net *net)
{
	struct tquic_lost_packet *earliest_ack_eliciting = NULL;
	struct tquic_lost_packet *latest_ack_eliciting = NULL;
	u64 pc_period;
	s64 duration_us;
	int i;
	int ack_eliciting_count = 0;

	if (!state || !lost_packets || num_lost < 2)
		return false;

	/*
	 * Per RFC 9002 Section 7.6.2:
	 * "A sender that does not have state for all packet number spaces
	 * or that does not have RTT samples from them SHOULD NOT declare
	 * persistent congestion."
	 */
	if (!state->has_rtt_sample) {
		tquic_dbg("persistent_cong: no RTT sample, skipping check\n");
		return false;
	}

	/*
	 * Calculate persistent congestion period
	 */
	pc_period = tquic_persistent_cong_period(state, net);
	if (pc_period == 0) {
		tquic_dbg("persistent_cong: pc_period is 0, skipping\n");
		return false;
	}

	/*
	 * Sort lost packets by send time to find earliest and latest
	 */
	sort(lost_packets, num_lost, sizeof(struct tquic_lost_packet),
	     lost_packet_cmp, NULL);

	/*
	 * Find earliest and latest ACK-eliciting packets
	 *
	 * Per RFC 9002: "two packets that are ack-eliciting"
	 * Non-ACK-eliciting packets (pure ACKs) don't count.
	 */
	for (i = 0; i < num_lost; i++) {
		if (!lost_packets[i].ack_eliciting)
			continue;

		ack_eliciting_count++;

		if (!earliest_ack_eliciting)
			earliest_ack_eliciting = &lost_packets[i];

		latest_ack_eliciting = &lost_packets[i];
	}

	/*
	 * Need at least 2 ACK-eliciting packets for persistent congestion
	 */
	if (ack_eliciting_count < 2) {
		tquic_dbg("persistent_cong: only %d ack-eliciting packets\n",
			 ack_eliciting_count);
		return false;
	}

	/*
	 * Check if duration spans persistent congestion period
	 *
	 * Per RFC 9002 Section 7.6.2:
	 * "the duration between the send times of these two packets
	 * exceeds the persistent congestion duration"
	 */
	duration_us = ktime_us_delta(latest_ack_eliciting->send_time,
				     earliest_ack_eliciting->send_time);

	if (duration_us < 0) {
		tquic_warn("persistent_cong: negative duration, time corruption?\n");
		return false;
	}

	if ((u64)duration_us >= pc_period) {
		/*
		 * Persistent congestion detected!
		 */
		state->last_persistent_cong = ktime_get();
		state->persistent_cong_count++;

		tquic_warn("persistent_cong: detected! duration=%lldus period=%lluu count=%llu\n",
			duration_us, pc_period, state->persistent_cong_count);

		/* Increment MIB counter */
		if (net)
			TQUIC_INC_STATS(net, TQUIC_MIB_PERSISTENTCONGESTION);

		return true;
	}

	tquic_dbg("persistent_cong: duration=%lldus < period=%lluu, no PC\n",
		 duration_us, pc_period);

	return false;
}
EXPORT_SYMBOL_GPL(tquic_check_persistent_cong);

/*
 * =============================================================================
 * CC Algorithm Integration Helpers
 * =============================================================================
 */

/**
 * tquic_on_persistent_congestion - Handle persistent congestion for a path
 * @path: Path that experienced persistent congestion
 * @info: Persistent congestion information
 *
 * This function is called by the loss detection code when persistent
 * congestion is detected. It invokes the CC algorithm's callback and
 * updates path state.
 */
void tquic_on_persistent_congestion(struct tquic_path *path,
				    struct tquic_persistent_cong_info *info)
{
	struct tquic_cong_ops *ca;

	if (!path || !info)
		return;

	ca = path->cong_ops;

	/*
	 * Call the CC algorithm's persistent congestion handler if available
	 */
	if (ca && ca->on_persistent_congestion && path->cong) {
		ca->on_persistent_congestion(path->cong, info);
	} else {
		/*
		 * Default behavior if CC doesn't implement the callback:
		 * Reset cwnd to minimum
		 */
		path->stats.cwnd = (u32)info->min_cwnd;
		tquic_dbg("persistent_cong: path %u cwnd reset to %u (default)\n",
			 path->path_id, path->stats.cwnd);
	}

	/*
	 * Clear bytes_in_flight since all those packets are considered lost
	 */
	/* Note: bytes_in_flight tracking is handled by the CC algorithm */
}
EXPORT_SYMBOL_GPL(tquic_on_persistent_congestion);

/*
 * =============================================================================
 * Sysctl Integration
 * =============================================================================
 */

/*
 * Per-netns persistent congestion threshold handler
 *
 * Handles reading/writing net.tquic.persistent_cong_threshold
 */
static int proc_tquic_persistent_cong_threshold(TQUIC_CTL_TABLE *table,
						int write, void *buffer,
						size_t *lenp, loff_t *ppos)
{
	int val = tquic_persistent_cong_threshold;
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

	tquic_persistent_cong_threshold = val;
	tquic_dbg("persistent_cong: threshold set to %d\n", val);
	return 0;
}

/* Min/max values for threshold */
static int pc_threshold_min = TQUIC_PERSISTENT_CONG_THRESHOLD_MIN;
static int pc_threshold_max = TQUIC_PERSISTENT_CONG_THRESHOLD_MAX;

/*
 * Sysctl table entry for persistent congestion
 * This should be added to the main tquic_sysctl_table
 */
static struct ctl_table tquic_persistent_cong_sysctl[] = {
	{
		.procname	= "persistent_cong_threshold",
		.data		= &tquic_persistent_cong_threshold,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= proc_tquic_persistent_cong_threshold,
		.extra1		= &pc_threshold_min,
		.extra2		= &pc_threshold_max,
	},
	{ }
};

/* Number of valid entries (exclude the null terminator). */
#define TQUIC_PERSISTENT_CONG_SYSCTL_ENTRIES \
	(ARRAY_SIZE(tquic_persistent_cong_sysctl) - 1)

/*
 * =============================================================================
 * Module Interface
 * =============================================================================
 */

static struct ctl_table_header *persistent_cong_sysctl_header;

int __init tquic_persistent_cong_module_init(void)
{
	tquic_info("persistent_cong: initializing (threshold=%u)\n",
		tquic_persistent_cong_threshold);

	/* Register sysctl - Note: In practice, add to main tquic_sysctl_table */
	persistent_cong_sysctl_header = register_net_sysctl_sz(&init_net,
							       "net/tquic",
							       tquic_persistent_cong_sysctl,
							       TQUIC_PERSISTENT_CONG_SYSCTL_ENTRIES);
	if (!persistent_cong_sysctl_header)
		tquic_warn("persistent_cong: failed to register sysctl\n");

	return 0;
}

void __exit tquic_persistent_cong_module_exit(void)
{
	if (persistent_cong_sysctl_header)
		unregister_net_sysctl_table(persistent_cong_sysctl_header);

	tquic_info("persistent_cong: unloaded\n");
}

MODULE_DESCRIPTION("TQUIC Persistent Congestion Detection (RFC 9002)");
MODULE_LICENSE("GPL");
