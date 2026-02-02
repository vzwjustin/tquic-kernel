/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * TQUIC: QUIC-Exfil Mitigation (draft-iab-quic-exfil)
 *
 * Copyright (c) 2026 Linux Foundation
 *
 * This header provides defense mechanisms against timing side-channel
 * information leakage attacks on QUIC connections as described in
 * draft-iab-quic-exfil. Implements:
 *
 * - Timing normalization to prevent timing-based information leakage
 * - Constant-time operations for critical path processing
 * - Traffic analysis protection via padding and traffic shaping
 * - Spin bit randomization to prevent RTT inference by observers
 * - Packet timing jitter to mask traffic patterns
 *
 * Reference: draft-iab-quic-exfil-01
 * https://datatracker.ietf.org/doc/draft-iab-quic-exfil/
 */

#ifndef _TQUIC_QUIC_EXFIL_H
#define _TQUIC_QUIC_EXFIL_H

#include <linux/types.h>
#include <linux/spinlock.h>
#include <linux/ktime.h>
#include <linux/timer.h>
#include <linux/workqueue.h>
#include <linux/random.h>
#include <linux/atomic.h>

/*
 * =============================================================================
 * QUIC-Exfil Protection Levels
 * =============================================================================
 *
 * Configurable protection levels allow balancing security vs performance:
 *   - NONE: Disabled (maximum performance)
 *   - LOW: Minimal protection (low overhead)
 *   - MEDIUM: Balanced protection (default)
 *   - HIGH: Maximum protection (some performance impact)
 *   - PARANOID: Defense-in-depth (significant overhead)
 */

enum tquic_exfil_protection_level {
	TQUIC_EXFIL_LEVEL_NONE = 0,
	TQUIC_EXFIL_LEVEL_LOW = 1,
	TQUIC_EXFIL_LEVEL_MEDIUM = 2,
	TQUIC_EXFIL_LEVEL_HIGH = 3,
	TQUIC_EXFIL_LEVEL_PARANOID = 4,
};

/*
 * =============================================================================
 * Timing Normalization
 * =============================================================================
 *
 * Adds controlled random delays to packet processing to prevent timing-based
 * information leakage. The delay distribution is configurable per protection
 * level.
 *
 * At LOW level: 0-50us random delay
 * At MEDIUM level: 0-200us random delay
 * At HIGH level: 0-1ms random delay
 * At PARANOID level: Fixed 1ms delay + 0-1ms random
 */

/* Timing normalization delay ranges (microseconds) */
#define TQUIC_EXFIL_DELAY_NONE_US		0
#define TQUIC_EXFIL_DELAY_LOW_MAX_US		50
#define TQUIC_EXFIL_DELAY_MEDIUM_MAX_US		200
#define TQUIC_EXFIL_DELAY_HIGH_MAX_US		1000
#define TQUIC_EXFIL_DELAY_PARANOID_BASE_US	1000
#define TQUIC_EXFIL_DELAY_PARANOID_RAND_US	1000

/* Sysctl bounds for user-configurable delay */
#define TQUIC_EXFIL_DELAY_MIN_US		0
#define TQUIC_EXFIL_DELAY_MAX_US		5000	/* 5ms max */

/**
 * struct tquic_timing_normalizer - Per-connection timing normalization state
 * @enabled: Whether timing normalization is enabled
 * @protection_level: Current protection level
 * @delay_min_us: Minimum delay (microseconds)
 * @delay_max_us: Maximum delay (microseconds)
 * @pending_work: Workqueue item for deferred packet transmission
 * @delay_queue: Queue of packets pending delayed transmission
 * @queue_lock: Protects delay_queue
 * @total_delays: Counter for applied delays (statistics)
 * @total_delay_ns: Total nanoseconds of delay applied (statistics)
 */
struct tquic_timing_normalizer {
	bool enabled;
	enum tquic_exfil_protection_level protection_level;
	u32 delay_min_us;
	u32 delay_max_us;
	struct delayed_work pending_work;
	struct sk_buff_head delay_queue;
	spinlock_t queue_lock;
	atomic64_t total_delays;
	atomic64_t total_delay_ns;
};

/* Timing normalization functions */
int tquic_timing_normalizer_init(struct tquic_timing_normalizer *norm,
				 enum tquic_exfil_protection_level level);
void tquic_timing_normalizer_destroy(struct tquic_timing_normalizer *norm);
void tquic_timing_normalizer_set_level(struct tquic_timing_normalizer *norm,
				       enum tquic_exfil_protection_level level);

/* Apply timing normalization delay to packet processing */
int tquic_timing_normalize_process(struct tquic_timing_normalizer *norm);

/* Queue packet for delayed transmission */
int tquic_timing_normalize_send(struct tquic_timing_normalizer *norm,
				struct sk_buff *skb,
				void (*send_fn)(struct sk_buff *));

/*
 * =============================================================================
 * Constant-Time Operations
 * =============================================================================
 *
 * Provides constant-time implementations of security-critical operations
 * to prevent timing side-channel attacks. Uses techniques like:
 * - Dummy operations to equalize timing
 * - Branchless comparisons
 * - Cache-timing resistant memory access
 */

/* Constant-time comparison flags */
#define TQUIC_CT_FLAG_NONE		0
#define TQUIC_CT_FLAG_EARLY_EXIT	BIT(0)	/* Allow early exit (not const-time) */

/**
 * struct tquic_ct_ops - Constant-time operation context
 * @enabled: Whether constant-time mode is enabled
 * @dummy_ops: Number of dummy operations to perform
 * @timing_noise_ns: Random timing noise to add
 */
struct tquic_ct_ops {
	bool enabled;
	u32 dummy_ops;
	u32 timing_noise_ns;
};

/* Constant-time memory comparison (returns 0 if equal) */
int tquic_ct_memcmp(const void *a, const void *b, size_t len);

/* Constant-time memory copy (to prevent cache timing) */
void tquic_ct_memcpy(void *dst, const void *src, size_t len);

/* Constant-time buffer selection (select a if sel != 0, else b) */
void tquic_ct_select(void *dst, const void *a, const void *b,
		     size_t len, int sel);

/* Constant-time connection ID validation */
bool tquic_ct_validate_cid(const u8 *cid, size_t cid_len,
			   const u8 *expected, size_t expected_len);

/* Constant-time packet number decoding with dummy operations */
u64 tquic_ct_decode_pn(const u8 *buf, size_t len, u64 largest_pn,
		       struct tquic_ct_ops *ops);

/*
 * =============================================================================
 * Traffic Analysis Protection
 * =============================================================================
 *
 * Implements padding and traffic shaping to prevent flow analysis and
 * fingerprinting based on packet sizes and timing patterns.
 *
 * Padding strategies:
 * - NONE: No padding
 * - RANDOM: Random padding up to MTU
 * - BLOCK: Pad to fixed block sizes (128, 256, 512, 1024, MTU)
 * - MAX: Always pad to MTU
 *
 * Traffic shaping:
 * - Constant-rate sending with dummy packets
 * - Packet batching to mask timing
 * - Decoy traffic generation
 */

/* Padding strategy */
enum tquic_padding_strategy {
	TQUIC_PAD_NONE = 0,
	TQUIC_PAD_RANDOM = 1,
	TQUIC_PAD_BLOCK = 2,
	TQUIC_PAD_MAX = 3,
};

/* Padding block sizes */
#define TQUIC_PAD_BLOCK_128		128
#define TQUIC_PAD_BLOCK_256		256
#define TQUIC_PAD_BLOCK_512		512
#define TQUIC_PAD_BLOCK_1024		1024
#define TQUIC_PAD_BLOCK_MTU		0	/* Use MTU as block size */

/* Default padding configuration */
#define TQUIC_PAD_STRATEGY_DEFAULT	TQUIC_PAD_RANDOM
#define TQUIC_PAD_PROBABILITY_DEFAULT	25	/* 25% of packets padded */
#define TQUIC_PAD_MAX_OVERHEAD_DEFAULT	10	/* 10% max overhead */

/**
 * struct tquic_traffic_shaper - Traffic analysis protection state
 * @strategy: Current padding strategy
 * @block_size: Block size for BLOCK strategy (0 = MTU)
 * @pad_probability: Probability of adding padding (0-100%)
 * @max_overhead_pct: Maximum padding overhead percentage
 * @enable_decoy: Enable decoy traffic generation
 * @decoy_interval_ms: Interval between decoy packets
 * @enable_batching: Enable packet batching
 * @batch_size: Target batch size
 * @batch_timeout_us: Maximum batch delay
 * @batch_queue: Queue for packet batching
 * @batch_timer: Timer for batch flushing
 * @batch_lock: Protects batch_queue
 * @decoy_work: Workqueue for decoy traffic
 * @mtu: Current path MTU
 * @stats_padded_packets: Statistics counter
 * @stats_padding_bytes: Statistics counter
 * @stats_decoy_packets: Statistics counter
 */
struct tquic_traffic_shaper {
	enum tquic_padding_strategy strategy;
	u16 block_size;
	u8 pad_probability;
	u8 max_overhead_pct;

	/* Decoy traffic */
	bool enable_decoy;
	u32 decoy_interval_ms;

	/* Packet batching */
	bool enable_batching;
	u16 batch_size;
	u32 batch_timeout_us;
	struct sk_buff_head batch_queue;
	struct hrtimer batch_timer;
	spinlock_t batch_lock;

	/* Decoy traffic generation */
	struct delayed_work decoy_work;

	/* Path MTU for padding calculations */
	u32 mtu;

	/* Statistics */
	atomic64_t stats_padded_packets;
	atomic64_t stats_padding_bytes;
	atomic64_t stats_decoy_packets;
};

/* Traffic shaper functions */
int tquic_traffic_shaper_init(struct tquic_traffic_shaper *shaper,
			      enum tquic_exfil_protection_level level);
void tquic_traffic_shaper_destroy(struct tquic_traffic_shaper *shaper);
void tquic_traffic_shaper_set_mtu(struct tquic_traffic_shaper *shaper, u32 mtu);

/* Calculate padding for a packet */
u16 tquic_traffic_shaper_calc_padding(struct tquic_traffic_shaper *shaper,
				      u16 packet_len);

/* Add padding to packet */
int tquic_traffic_shaper_pad_packet(struct tquic_traffic_shaper *shaper,
				    struct sk_buff *skb);

/* Queue packet for batched transmission */
int tquic_traffic_shaper_batch_send(struct tquic_traffic_shaper *shaper,
				    struct sk_buff *skb,
				    void (*send_fn)(struct sk_buff *));

/* Start/stop decoy traffic generation */
void tquic_traffic_shaper_start_decoy(struct tquic_traffic_shaper *shaper,
				      void (*send_fn)(struct sk_buff *));
void tquic_traffic_shaper_stop_decoy(struct tquic_traffic_shaper *shaper);

/*
 * =============================================================================
 * Spin Bit Randomization (Extended)
 * =============================================================================
 *
 * Extends the basic spin bit privacy controls from security_hardening.h
 * with additional protections against RTT inference by network observers.
 *
 * Features:
 * - Configurable randomization probability
 * - Spin bit freezing (stop transitioning for period)
 * - Coordinated randomization with peer
 * - Per-path spin bit policies
 */

/* Spin bit randomization modes */
enum tquic_spin_random_mode {
	TQUIC_SPIN_RANDOM_OFF = 0,	/* Normal spin bit operation */
	TQUIC_SPIN_RANDOM_PROB = 1,	/* Probabilistic randomization */
	TQUIC_SPIN_RANDOM_FREEZE = 2,	/* Freeze spin bit periodically */
	TQUIC_SPIN_RANDOM_FULL = 3,	/* Always random */
};

/* Default spin bit randomization probability (percentage) */
#define TQUIC_SPIN_RANDOM_PROB_DEFAULT	15	/* 15% random */

/* Spin bit freeze duration range (milliseconds) */
#define TQUIC_SPIN_FREEZE_MIN_MS	100
#define TQUIC_SPIN_FREEZE_MAX_MS	5000

/**
 * struct tquic_spin_randomizer - Extended spin bit randomization state
 * @mode: Current randomization mode
 * @random_probability: Probability of randomization (0-100%)
 * @freeze_duration_ms: Duration to freeze spin bit
 * @frozen: Whether spin bit is currently frozen
 * @frozen_value: Value to use when frozen
 * @freeze_until: ktime when freeze expires
 * @transition_count: Number of spin bit transitions
 * @randomized_count: Number of randomized transitions
 * @lock: Protects state updates
 */
struct tquic_spin_randomizer {
	enum tquic_spin_random_mode mode;
	u8 random_probability;
	u32 freeze_duration_ms;
	bool frozen;
	u8 frozen_value;
	ktime_t freeze_until;
	atomic64_t transition_count;
	atomic64_t randomized_count;
	spinlock_t lock;
};

/* Spin bit randomizer functions */
int tquic_spin_randomizer_init(struct tquic_spin_randomizer *rand,
			       enum tquic_exfil_protection_level level);
void tquic_spin_randomizer_destroy(struct tquic_spin_randomizer *rand);
void tquic_spin_randomizer_set_mode(struct tquic_spin_randomizer *rand,
				    enum tquic_spin_random_mode mode);

/* Get spin bit value (may be randomized) */
u8 tquic_spin_randomizer_get(struct tquic_spin_randomizer *rand,
			     u8 calculated_spin);

/* Trigger spin bit freeze */
void tquic_spin_randomizer_freeze(struct tquic_spin_randomizer *rand,
				  u32 duration_ms);

/* Check if spin bit is frozen */
bool tquic_spin_randomizer_is_frozen(struct tquic_spin_randomizer *rand);

/*
 * =============================================================================
 * Packet Timing Jitter
 * =============================================================================
 *
 * Adds configurable random jitter to outgoing packet timing to prevent
 * timing-based traffic analysis and fingerprinting.
 *
 * Jitter modes:
 * - UNIFORM: Uniform distribution within range
 * - GAUSSIAN: Gaussian distribution centered on mean
 * - EXPONENTIAL: Exponential distribution for bursty patterns
 */

/* Jitter distribution mode */
enum tquic_jitter_mode {
	TQUIC_JITTER_NONE = 0,
	TQUIC_JITTER_UNIFORM = 1,
	TQUIC_JITTER_GAUSSIAN = 2,
	TQUIC_JITTER_EXPONENTIAL = 3,
};

/* Jitter bounds (microseconds) */
#define TQUIC_JITTER_MIN_US		0
#define TQUIC_JITTER_MAX_US		10000	/* 10ms */
#define TQUIC_JITTER_DEFAULT_MIN_US	0
#define TQUIC_JITTER_DEFAULT_MAX_US	500	/* 500us */

/**
 * struct tquic_packet_jitter - Packet timing jitter state
 * @mode: Jitter distribution mode
 * @min_jitter_us: Minimum jitter (microseconds)
 * @max_jitter_us: Maximum jitter (microseconds)
 * @mean_jitter_us: Mean for Gaussian mode
 * @stddev_jitter_us: Std deviation for Gaussian mode
 * @lambda: Rate parameter for exponential mode
 * @adaptive_enabled: Enable adaptive jitter based on traffic
 * @adaptive_scale: Scale factor for adaptive adjustment
 * @pending_queue: Queue of packets pending jittered send
 * @jitter_timer: High-resolution timer for jitter delays
 * @queue_lock: Protects pending_queue
 * @stats_jittered_packets: Statistics counter
 * @stats_total_jitter_ns: Statistics counter
 */
struct tquic_packet_jitter {
	enum tquic_jitter_mode mode;
	u32 min_jitter_us;
	u32 max_jitter_us;
	u32 mean_jitter_us;
	u32 stddev_jitter_us;
	u32 lambda;

	/* Adaptive jitter */
	bool adaptive_enabled;
	u32 adaptive_scale;

	/* Jitter queue */
	struct sk_buff_head pending_queue;
	struct hrtimer jitter_timer;
	spinlock_t queue_lock;

	/* Statistics */
	atomic64_t stats_jittered_packets;
	atomic64_t stats_total_jitter_ns;
};

/* Packet jitter functions */
int tquic_packet_jitter_init(struct tquic_packet_jitter *jitter,
			     enum tquic_exfil_protection_level level);
void tquic_packet_jitter_destroy(struct tquic_packet_jitter *jitter);
void tquic_packet_jitter_set_mode(struct tquic_packet_jitter *jitter,
				  enum tquic_jitter_mode mode);
void tquic_packet_jitter_set_range(struct tquic_packet_jitter *jitter,
				   u32 min_us, u32 max_us);

/* Calculate jitter for next packet */
u32 tquic_packet_jitter_calc(struct tquic_packet_jitter *jitter);

/* Queue packet for jittered transmission */
int tquic_packet_jitter_send(struct tquic_packet_jitter *jitter,
			     struct sk_buff *skb,
			     void (*send_fn)(struct sk_buff *));

/* Cancel pending jittered packets */
void tquic_packet_jitter_cancel(struct tquic_packet_jitter *jitter);

/*
 * =============================================================================
 * Unified QUIC-Exfil Protection Context
 * =============================================================================
 *
 * Aggregates all exfil protection components into a single context
 * that can be attached to a QUIC connection.
 */

/**
 * struct tquic_exfil_ctx - Unified QUIC-Exfil protection context
 * @enabled: Master enable switch
 * @level: Global protection level
 * @timing: Timing normalization component
 * @ct_ops: Constant-time operations context
 * @shaper: Traffic analysis protection
 * @spin_rand: Spin bit randomization
 * @jitter: Packet timing jitter
 * @ref: Reference count
 * @lock: Context-wide lock
 */
struct tquic_exfil_ctx {
	bool enabled;
	enum tquic_exfil_protection_level level;

	struct tquic_timing_normalizer timing;
	struct tquic_ct_ops ct_ops;
	struct tquic_traffic_shaper shaper;
	struct tquic_spin_randomizer spin_rand;
	struct tquic_packet_jitter jitter;

	refcount_t ref;
	spinlock_t lock;
};

/* Context management */
struct tquic_exfil_ctx *tquic_exfil_ctx_alloc(enum tquic_exfil_protection_level level);
void tquic_exfil_ctx_free(struct tquic_exfil_ctx *ctx);
void tquic_exfil_ctx_get(struct tquic_exfil_ctx *ctx);
void tquic_exfil_ctx_put(struct tquic_exfil_ctx *ctx);

/* Context configuration */
void tquic_exfil_ctx_set_level(struct tquic_exfil_ctx *ctx,
			       enum tquic_exfil_protection_level level);
void tquic_exfil_ctx_enable(struct tquic_exfil_ctx *ctx);
void tquic_exfil_ctx_disable(struct tquic_exfil_ctx *ctx);

/* Packet processing hooks */
int tquic_exfil_process_incoming(struct tquic_exfil_ctx *ctx,
				 struct sk_buff *skb);
int tquic_exfil_process_outgoing(struct tquic_exfil_ctx *ctx,
				 struct sk_buff *skb,
				 void (*send_fn)(struct sk_buff *));

/* Statistics */
void tquic_exfil_get_stats(struct tquic_exfil_ctx *ctx,
			   u64 *total_delays, u64 *total_delay_ns,
			   u64 *padded_packets, u64 *padding_bytes,
			   u64 *jittered_packets, u64 *jitter_ns);

/*
 * =============================================================================
 * Sysctl Configuration
 * =============================================================================
 */

/* Sysctl accessors */
enum tquic_exfil_protection_level tquic_sysctl_get_exfil_level(void);
u32 tquic_sysctl_get_exfil_timing_delay_us(void);
enum tquic_padding_strategy tquic_sysctl_get_exfil_padding_strategy(void);
u8 tquic_sysctl_get_exfil_pad_probability(void);
enum tquic_spin_random_mode tquic_sysctl_get_exfil_spin_mode(void);
u32 tquic_sysctl_get_exfil_jitter_min_us(void);
u32 tquic_sysctl_get_exfil_jitter_max_us(void);

/*
 * =============================================================================
 * Module Initialization
 * =============================================================================
 */

int __init tquic_exfil_init(void);
void __exit tquic_exfil_exit(void);

/*
 * =============================================================================
 * Security Event Reporting
 * =============================================================================
 */

/* Security event types (extends security_hardening.h) */
enum tquic_exfil_event {
	TQUIC_EXFIL_EVENT_TIMING_APPLIED = 100,
	TQUIC_EXFIL_EVENT_PADDING_APPLIED,
	TQUIC_EXFIL_EVENT_SPIN_RANDOMIZED,
	TQUIC_EXFIL_EVENT_JITTER_APPLIED,
	TQUIC_EXFIL_EVENT_DECOY_SENT,
};

/* Report exfil protection event */
void tquic_exfil_event(enum tquic_exfil_event event,
		       const char *details);

#endif /* _TQUIC_QUIC_EXFIL_H */
