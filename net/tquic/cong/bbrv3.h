/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * TQUIC BBRv3 Congestion Control Header
 *
 * Copyright (c) 2026 Linux Foundation
 *
 * BBRv3 brings significant improvements over BBRv2:
 * - More responsive ECN handling with probabilistic marking
 * - Improved startup behavior with pacing gain adjustments
 * - Better coexistence with loss-based algorithms
 * - Enhanced bandwidth probing with longer probe duration
 * - Refined RTT measurement and filtering
 */

#ifndef _TQUIC_BBRV3_H
#define _TQUIC_BBRV3_H

#include <linux/types.h>
#include <linux/ktime.h>

/*
 * =============================================================================
 * BBRv3 Constants
 * =============================================================================
 */

/* Scale factor for gains (fixed-point) */
#define BBR3_SCALE		16
#define BBR3_UNIT		(1 << BBR3_SCALE)

/* Startup phase parameters */
#define BBR3_STARTUP_PACING_GAIN	((BBR3_UNIT * 277) / 100)  /* 2.77x */
#define BBR3_STARTUP_CWND_GAIN		(BBR3_UNIT * 2)            /* 2.0x */

/* Drain phase parameters */
#define BBR3_DRAIN_PACING_GAIN		((BBR3_UNIT * 35) / 100)   /* 0.35x */

/* ProbeBW phase parameters */
#define BBR3_PROBE_BW_PACING_UP		((BBR3_UNIT * 125) / 100)  /* 1.25x */
#define BBR3_PROBE_BW_PACING_DOWN	((BBR3_UNIT * 75) / 100)   /* 0.75x */
#define BBR3_PROBE_BW_CWND_GAIN		(BBR3_UNIT * 2)            /* 2.0x */
#define BBR3_PROBE_BW_REFILL_GAIN	BBR3_UNIT                  /* 1.0x */
#define BBR3_PROBE_BW_CRUISE_GAIN	BBR3_UNIT                  /* 1.0x */

/* ProbeRTT phase parameters */
#define BBR3_PROBE_RTT_CWND		4   /* packets */
#define BBR3_PROBE_RTT_DURATION_MS	200 /* milliseconds */
#define BBR3_PROBE_RTT_INTERVAL_SEC	5   /* seconds */

/* Bandwidth filter window */
#define BBR3_BW_FILTER_ROUNDS		2  /* rounds to keep max bw */

/* Loss/ECN response parameters */
#define BBR3_LOSS_THRESH_PERCENT	2     /* 2% loss threshold */
#define BBR3_ECN_THRESH_PERCENT		50    /* 50% ECN threshold for L4S */
#define BBR3_ECN_ALPHA_INIT		(BBR3_UNIT / 2)
#define BBR3_BETA			((BBR3_UNIT * 70) / 100)  /* 0.7x on loss */
#define BBR3_HEADROOM			((BBR3_UNIT * 15) / 100)  /* 15% headroom */

/* Minimum cwnd */
#define BBR3_MIN_CWND			4  /* packets */

/* Extra acked filter params */
#define BBR3_EXTRA_ACKED_FILTER_LEN	10  /* rounds */
#define BBR3_EXTRA_ACKED_MAX_FILTER	20  /* packets */

/*
 * =============================================================================
 * BBRv3 State Machine
 * =============================================================================
 */

/**
 * enum bbrv3_mode - BBRv3 state machine modes
 */
enum bbrv3_mode {
	BBR3_STARTUP,      /* Exponential growth to fill pipe */
	BBR3_DRAIN,        /* Drain queue after startup */
	BBR3_PROBE_BW,     /* Steady-state bandwidth probing */
	BBR3_PROBE_RTT,    /* Periodic RTT measurement */
};

/**
 * enum bbrv3_probe_bw_phase - ProbeBW sub-states
 */
enum bbrv3_probe_bw_phase {
	BBR3_BW_PROBE_UP,      /* Increase pacing to probe for more bw */
	BBR3_BW_PROBE_DOWN,    /* Decrease pacing after probing */
	BBR3_BW_PROBE_CRUISE,  /* Cruise at estimated bw */
	BBR3_BW_PROBE_REFILL,  /* Refill pipe before next probe */
};

/**
 * enum bbrv3_ack_phase - ACK aggregation handling phases
 */
enum bbrv3_ack_phase {
	BBR3_ACKS_INIT,       /* Initial state */
	BBR3_ACKS_REFILLING,  /* Refilling after idle */
	BBR3_ACKS_FULL,       /* Steady state */
};

/*
 * =============================================================================
 * BBRv3 Windowed Filters
 * =============================================================================
 */

/**
 * struct bbrv3_minmax_sample - Sample for windowed filter
 * @value: Sample value
 * @time:  Timestamp of sample
 */
struct bbrv3_minmax_sample {
	u64 value;
	u64 time;
};

/**
 * struct bbrv3_minmax - Windowed min/max filter
 * @samples:    Three samples for Kathleen Nichols' algorithm
 * @window_len: Window length in time units
 */
struct bbrv3_minmax {
	struct bbrv3_minmax_sample samples[3];
	u64 window_len;
};

/*
 * =============================================================================
 * BBRv3 State Structure
 * =============================================================================
 */

/**
 * struct bbrv3 - BBRv3 congestion control state
 */
struct bbrv3 {
	/* Core state */
	struct tquic_path *path;
	enum bbrv3_mode mode;
	enum bbrv3_probe_bw_phase probe_bw_phase;
	enum bbrv3_ack_phase ack_phase;

	/* Bandwidth and RTT estimates */
	u64 bw;              /* Estimated bandwidth (bytes/sec) */
	u64 max_bw;          /* Max observed bandwidth */
	u64 bw_lo;           /* Lower bound after loss/ECN */
	u64 bw_hi;           /* Upper bound from probing */
	u64 min_rtt_us;      /* Minimum RTT in microseconds */
	u64 rtt_us;          /* Current RTT sample */
	struct bbrv3_minmax bw_filter;   /* Bandwidth filter */
	struct bbrv3_minmax rtt_filter;  /* RTT filter */

	/* Pacing and cwnd */
	u32 pacing_gain;     /* Current pacing gain (fixed-point) */
	u32 cwnd_gain;       /* Current cwnd gain (fixed-point) */
	u32 cwnd;            /* Congestion window (bytes) */

	/* Inflight bounds */
	u32 inflight_lo;     /* Lower inflight bound (loss response) */
	u32 inflight_hi;     /* Upper inflight bound (probe ceiling) */

	/* Round tracking */
	u64 round_count;           /* Round trip counter */
	u64 next_round_delivered;  /* Delivered bytes at round end */
	u64 round_start_delivered; /* Delivered at round start */
	bool round_start;          /* True at start of new round */

	/* Startup state */
	u64 full_bw;         /* Bandwidth sample for full pipe detection */
	u32 full_bw_count;   /* Rounds without bandwidth growth */
	bool full_bw_reached; /* True when pipe is full */
	bool full_bw_now;    /* Full bandwidth reached this round */

	/* ProbeRTT state */
	ktime_t probe_rtt_start;     /* When ProbeRTT started */
	ktime_t probe_rtt_done_time; /* When ProbeRTT completed */
	ktime_t min_rtt_stamp;       /* Timestamp of min RTT */
	bool probe_rtt_round_done;   /* ProbeRTT round complete */
	bool idle_restart;           /* Restarting from idle */

	/* ProbeBW state */
	ktime_t cycle_start;         /* ProbeBW cycle start time */
	u32 cycle_count;             /* Cycles in current phase */
	u32 probe_up_rounds;         /* Rounds probing up */
	bool probe_up_acked;         /* Got ACK while probing up */
	u64 probe_up_cnt;            /* Bytes to send in probe_up */
	u64 bw_probe_samples;        /* Samples since probe started */
	u64 bw_probe_up_acks;        /* ACKs during probe up */

	/* ECN state (L4S support) */
	u64 ecn_alpha;               /* ECN response factor */
	u64 ecn_ce_count;            /* CE marks this round */
	u64 ecn_ect_count;           /* ECT marks this round */
	u64 ecn_in_round;            /* ECN events in round */
	bool ecn_eligible;           /* ECN path validated */

	/* Loss state */
	u64 loss_round_delivered;    /* Delivered at loss round start */
	u64 loss_in_round;           /* Loss events in round */
	bool in_loss_recovery;       /* Currently in loss recovery */
	u32 prior_cwnd;              /* Cwnd before loss */

	/* Extra acked estimation */
	u64 extra_acked[2];          /* Extra acked filter */
	u32 extra_acked_idx;         /* Current filter index */
	u64 extra_acked_win_start;   /* Window start time */
	u64 extra_acked_win_len;     /* Window length */

	/* Delivery rate sampling */
	u64 bytes_delivered;         /* Total bytes delivered */
	u64 bytes_lost;              /* Total bytes lost */
	u64 delivered_ce;            /* Delivered with CE marking */
	ktime_t first_sent_time;     /* Time of first packet in flight */
	ktime_t delivered_time;      /* Time of last delivered packet */

	/* Tunable parameters */
	struct {
		u32 probe_rtt_interval_sec;
		u32 loss_thresh_percent;
		u32 ecn_thresh_percent;
		u32 ecn_alpha_gain;
		u32 beta;
		u32 headroom;
		bool ecn_aware;
		bool use_extra_acked;
	} params;
};

/*
 * =============================================================================
 * Function Declarations
 * =============================================================================
 */

/* Module init/exit */
int __init tquic_bbrv3_init(void);
void __exit tquic_bbrv3_exit(void);

/* Congestion control operations */
extern struct tquic_cong_ops bbrv3_cong_ops;

#endif /* _TQUIC_BBRV3_H */
