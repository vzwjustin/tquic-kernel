// SPDX-License-Identifier: GPL-2.0-only
/*
 * TQUIC: Security Hardening Implementation
 *
 * Copyright (c) 2026 Linux Foundation
 *
 * Implements defenses against known QUIC vulnerabilities:
 * - CVE-2025-54939 (QUIC-LEAK): Pre-handshake memory exhaustion
 * - CVE-2024-22189: Retire CID stuffing attack
 * - Optimistic ACK attack defense via packet number skipping
 * - ACK range validation
 * - Spin bit privacy controls
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/random.h>
#include <linux/rhashtable.h>
#include <linux/jhash.h>
#include <linux/inet.h>
#include <linux/in.h>
#include <linux/in6.h>
#include <net/tquic.h>

#include "security_hardening.h"
#include "protocol.h"
#include "tquic_mib.h"
#include "tquic_debug.h"

/*
 * =============================================================================
 * CVE-2025-54939: QUIC-LEAK Defense Implementation
 * =============================================================================
 */

/* Global pre-handshake state */
static struct tquic_pre_hs_state pre_hs_state;
static bool pre_hs_initialized;

/* Hash function for IP addresses */
static u32 tquic_pre_hs_ip_hash(const void *data, u32 len, u32 seed)
{
	const struct tquic_pre_hs_ip_entry *entry = data;

	return jhash(&entry->ip_hash, sizeof(entry->ip_hash), seed);
}

/* Comparison function for IP lookup */
static int tquic_pre_hs_ip_cmp(struct rhashtable_compare_arg *arg,
			       const void *obj)
{
	const u32 *key = arg->key;
	const struct tquic_pre_hs_ip_entry *entry = obj;

	return entry->ip_hash != *key;
}

static const struct rhashtable_params pre_hs_ip_params = {
	.head_offset = offsetof(struct tquic_pre_hs_ip_entry, node),
	.key_offset = offsetof(struct tquic_pre_hs_ip_entry, ip_hash),
	.key_len = sizeof(u32),
	.hashfn = tquic_pre_hs_ip_hash,
	.obj_cmpfn = tquic_pre_hs_ip_cmp,
	.automatic_shrinking = true,
};

/* Compute hash key from address */
static u32 compute_ip_hash(const struct sockaddr_storage *addr)
{
	if (addr->ss_family == AF_INET) {
		const struct sockaddr_in *sin = (const struct sockaddr_in *)addr;
		return jhash(&sin->sin_addr, sizeof(sin->sin_addr), 0);
	} else if (addr->ss_family == AF_INET6) {
		const struct sockaddr_in6 *sin6 = (const struct sockaddr_in6 *)addr;
		/* Use /64 prefix for IPv6 to group hosts in same subnet */
		return jhash(sin6->sin6_addr.s6_addr, 8, 0);
	}
	return 0;
}

/**
 * tquic_pre_hs_init - Initialize pre-handshake memory tracking
 *
 * Returns: 0 on success, negative errno on failure
 */
int tquic_pre_hs_init(void)
{
	int ret;

	if (smp_load_acquire(&pre_hs_initialized))
		return 0;

	spin_lock_init(&pre_hs_state.lock);
	atomic64_set(&pre_hs_state.total_memory, 0);
	pre_hs_state.memory_limit = TQUIC_PRE_HS_MEMORY_LIMIT_DEFAULT;
	pre_hs_state.per_ip_budget = TQUIC_PRE_HS_PER_IP_BUDGET_DEFAULT;

	ret = rhashtable_init(&pre_hs_state.ip_table, &pre_hs_ip_params);
	if (ret) {
		tquic_err("failed to init pre-handshake IP table: %d\n", ret);
		return ret;
	}

	smp_store_release(&pre_hs_initialized, true);
	tquic_info("QUIC-LEAK defense initialized (limit=%llu MB, per-IP=%llu KB)\n",
		   pre_hs_state.memory_limit / (1024 * 1024),
		   pre_hs_state.per_ip_budget / 1024);

	return 0;
}

/**
 * tquic_pre_hs_exit - Cleanup pre-handshake memory tracking
 */
void tquic_pre_hs_exit(void)
{
	if (!smp_load_acquire(&pre_hs_initialized))
		return;

	rhashtable_destroy(&pre_hs_state.ip_table);
	smp_store_release(&pre_hs_initialized, false);
	tquic_info("QUIC-LEAK defense shutdown\n");
}

/*
 * Find or create per-IP entry.
 *
 * Note: The returned entry is safe to use because entries are never removed
 * while pre_hs_initialized is true (only tquic_pre_hs_exit destroys the
 * table). Callers access entry fields via atomics only.
 */
static struct tquic_pre_hs_ip_entry *
find_or_create_ip_entry(const struct sockaddr_storage *addr, bool create)
{
	struct tquic_pre_hs_ip_entry *entry;
	u32 hash = compute_ip_hash(addr);
	int retries = 0;

	/* Try to find existing entry under RCU protection */
retry:
	rcu_read_lock();
	entry = rhashtable_lookup_fast(&pre_hs_state.ip_table, &hash,
				       pre_hs_ip_params);
	rcu_read_unlock();

	if (entry || !create)
		return entry;

	/* Create new entry */
	entry = kzalloc(sizeof(*entry), GFP_ATOMIC);
	if (!entry)
		return NULL;

	entry->ip_hash = hash;
	entry->is_v6 = (addr->ss_family == AF_INET6);
	if (entry->is_v6) {
		const struct sockaddr_in6 *sin6 = (const struct sockaddr_in6 *)addr;
		memcpy(&entry->addr.v6, &sin6->sin6_addr, sizeof(entry->addr.v6));
	} else {
		const struct sockaddr_in *sin = (const struct sockaddr_in *)addr;
		entry->addr.v4 = sin->sin_addr.s_addr;
	}
	atomic64_set(&entry->memory_used, 0);
	atomic_set(&entry->conn_count, 0);
	entry->first_seen = ktime_get();

	spin_lock_bh(&pre_hs_state.lock);
	if (rhashtable_insert_fast(&pre_hs_state.ip_table, &entry->node,
				   pre_hs_ip_params)) {
		spin_unlock_bh(&pre_hs_state.lock);
		kfree(entry);

		/*
		 * Insert failed (-EEXIST) -- another CPU raced us.
		 * Retry the lookup under RCU, but bound retries to
		 * prevent an infinite loop if something is wrong.
		 */
		if (++retries < 3)
			goto retry;

		return NULL;
	}
	spin_unlock_bh(&pre_hs_state.lock);

	return entry;
}

/**
 * tquic_pre_hs_can_allocate - Check if pre-handshake allocation is allowed
 * @addr: Source address
 * @size: Allocation size
 *
 * Returns: true if allocation is allowed, false otherwise
 */
bool tquic_pre_hs_can_allocate(const struct sockaddr_storage *addr, size_t size)
{
	struct tquic_pre_hs_ip_entry *entry;
	u64 total, per_ip;

	if (!smp_load_acquire(&pre_hs_initialized))
		return true;

	/* Check global limit */
	total = atomic64_read(&pre_hs_state.total_memory);
	if (total + size > pre_hs_state.memory_limit) {
		tquic_dbg("pre-handshake global memory limit exceeded "
			 "(total=%llu, limit=%llu)\n",
			 total, pre_hs_state.memory_limit);
		return false;
	}

	/* Check per-IP limit */
	entry = find_or_create_ip_entry(addr, false);
	if (entry) {
		per_ip = atomic64_read(&entry->memory_used);
		if (per_ip + size > pre_hs_state.per_ip_budget) {
			tquic_dbg("pre-handshake per-IP limit exceeded "
				 "(used=%llu, budget=%llu)\n",
				 per_ip, pre_hs_state.per_ip_budget);
			tquic_security_event(TQUIC_SEC_EVENT_PRE_HS_LIMIT,
					     addr, "per-IP memory limit");
			return false;
		}

		/* Check connection count per IP */
		if (atomic_read(&entry->conn_count) >= TQUIC_PRE_HS_MAX_CONNS_PER_IP) {
			tquic_dbg("pre-handshake connection limit per IP\n");
			tquic_security_event(TQUIC_SEC_EVENT_PRE_HS_LIMIT,
					     addr, "per-IP connection limit");
			return false;
		}
	}

	return true;
}

/**
 * tquic_pre_hs_alloc - Account for pre-handshake memory allocation
 * @addr: Source address
 * @size: Allocation size
 *
 * Returns: 0 on success, -ENOMEM if limits exceeded
 */
int tquic_pre_hs_alloc(const struct sockaddr_storage *addr, size_t size)
{
	struct tquic_pre_hs_ip_entry *entry;
	u64 new_total;
	u64 new_per_ip;

	if (!smp_load_acquire(&pre_hs_initialized))
		return 0;

	/* Atomically add to global counter and check limit */
	new_total = atomic64_add_return(size, &pre_hs_state.total_memory);
	if (new_total > pre_hs_state.memory_limit) {
		atomic64_sub(size, &pre_hs_state.total_memory);
		tquic_dbg("pre-handshake global memory limit exceeded "
			 "(total=%llu, limit=%llu)\n",
			 new_total, pre_hs_state.memory_limit);
		return -ENOMEM;
	}

	/* Update per-IP counter with rollback on failure */
	entry = find_or_create_ip_entry(addr, true);
	if (entry) {
		new_per_ip = atomic64_add_return(size, &entry->memory_used);
		if (new_per_ip > pre_hs_state.per_ip_budget) {
			atomic64_sub(size, &entry->memory_used);
			atomic64_sub(size, &pre_hs_state.total_memory);
			tquic_dbg("pre-handshake per-IP limit exceeded "
				 "(used=%llu, budget=%llu)\n",
				 new_per_ip, pre_hs_state.per_ip_budget);
			tquic_security_event(TQUIC_SEC_EVENT_PRE_HS_LIMIT,
					     addr, "per-IP memory limit");
			return -ENOMEM;
		}

		/*
		 * CF-225: Use atomic_inc_return() instead of separate
		 * read + increment to eliminate TOCTOU race where two
		 * CPUs could both pass the check before either increments.
		 */
		if (atomic_inc_return(&entry->conn_count) >
		    TQUIC_PRE_HS_MAX_CONNS_PER_IP) {
			atomic_dec(&entry->conn_count);
			atomic64_sub(size, &entry->memory_used);
			atomic64_sub(size, &pre_hs_state.total_memory);
			tquic_dbg("pre-handshake connection limit per IP\n");
			tquic_security_event(TQUIC_SEC_EVENT_PRE_HS_LIMIT,
					     addr, "per-IP connection limit");
			return -ENOMEM;
		}
	}

	return 0;
}

/**
 * tquic_pre_hs_free - Account for pre-handshake memory deallocation
 * @addr: Source address
 * @size: Deallocation size
 */
void tquic_pre_hs_free(const struct sockaddr_storage *addr, size_t size)
{
	struct tquic_pre_hs_ip_entry *entry;

	if (!smp_load_acquire(&pre_hs_initialized))
		return;

	/* Update global counter */
	atomic64_sub(size, &pre_hs_state.total_memory);

	/* Update per-IP counter */
	entry = find_or_create_ip_entry(addr, false);
	if (entry) {
		atomic64_sub(size, &entry->memory_used);
		atomic_dec(&entry->conn_count);
	}
}

/**
 * tquic_pre_hs_connection_complete - Mark connection handshake complete
 * @addr: Source address
 *
 * Called when handshake completes successfully. Memory is now considered
 * "committed" and no longer counts against pre-handshake limits.
 */
void tquic_pre_hs_connection_complete(const struct sockaddr_storage *addr)
{
	struct tquic_pre_hs_ip_entry *entry;
	u64 memory_used;

	if (!smp_load_acquire(&pre_hs_initialized))
		return;

	entry = find_or_create_ip_entry(addr, false);
	if (entry) {
		memory_used = atomic64_xchg(&entry->memory_used, 0);
		atomic64_sub(memory_used, &pre_hs_state.total_memory);
		atomic_dec(&entry->conn_count);

		tquic_dbg("handshake complete, released %llu bytes from pre-hs accounting\n",
			 memory_used);
	}
}

/*
 * =============================================================================
 * CVE-2024-22189: Retire CID Stuffing Attack Defense
 * =============================================================================
 */

/**
 * tquic_cid_security_init - Initialize CID security state
 * @sec: Security state to initialize
 *
 * Returns: 0 on success
 */
int tquic_cid_security_init(struct tquic_cid_security *sec)
{
	if (!sec)
		return -EINVAL;

	atomic_set(&sec->queued_retire_frames, 0);
	sec->new_cid_count = 0;
	sec->new_cid_window_start = ktime_get();
	sec->last_new_cid_time = ktime_set(0, 0);
	spin_lock_init(&sec->lock);

	return 0;
}

/**
 * tquic_cid_security_destroy - Cleanup CID security state
 * @sec: Security state to destroy
 */
void tquic_cid_security_destroy(struct tquic_cid_security *sec)
{
	/* Nothing to free, just reset */
	if (sec)
		atomic_set(&sec->queued_retire_frames, 0);
}

/**
 * tquic_cid_security_check_new_cid - Check if NEW_CONNECTION_ID can be processed
 * @sec: CID security state
 *
 * Returns: 0 if allowed, -EBUSY if rate limited, -EPROTO if attack detected
 */
int tquic_cid_security_check_new_cid(struct tquic_cid_security *sec)
{
	ktime_t now;
	s64 elapsed_ms;

	if (!sec)
		return 0;

	now = ktime_get();

	spin_lock_bh(&sec->lock);

	/* Check minimum interval */
	elapsed_ms = ktime_ms_delta(now, sec->last_new_cid_time);
	if (elapsed_ms < TQUIC_NEW_CID_MIN_INTERVAL_MS) {
		spin_unlock_bh(&sec->lock);
		tquic_dbg("NEW_CONNECTION_ID rate limited (interval=%lldms)\n",
			 elapsed_ms);
		return -EBUSY;
	}

	/* Check rate limit window */
	elapsed_ms = ktime_ms_delta(now, sec->new_cid_window_start);
	if (elapsed_ms >= 1000) {
		/* Reset window */
		sec->new_cid_count = 0;
		sec->new_cid_window_start = now;
	}

	if (sec->new_cid_count >= TQUIC_NEW_CID_RATE_LIMIT) {
		spin_unlock_bh(&sec->lock);
		tquic_warn("NEW_CONNECTION_ID rate limit exceeded "
			   "(count=%u, limit=%u)\n",
			   sec->new_cid_count, TQUIC_NEW_CID_RATE_LIMIT);
		return -EBUSY;
	}

	sec->new_cid_count++;
	sec->last_new_cid_time = now;

	spin_unlock_bh(&sec->lock);

	return 0;
}

/**
 * tquic_cid_security_queue_retire - Track RETIRE_CONNECTION_ID frame queuing
 * @sec: CID security state
 *
 * Returns: 0 if allowed, -EPROTO if limit exceeded (attack detected)
 */
int tquic_cid_security_queue_retire(struct tquic_cid_security *sec)
{
	int count;

	if (!sec)
		return 0;

	count = atomic_inc_return(&sec->queued_retire_frames);
	if (count > TQUIC_MAX_QUEUED_RETIRE_CID) {
		atomic_dec(&sec->queued_retire_frames);
		tquic_warn("RETIRE_CONNECTION_ID stuffing attack detected "
			   "(queued=%d, limit=%d)\n",
			   count, TQUIC_MAX_QUEUED_RETIRE_CID);
		return -EPROTO;
	}

	return 0;
}

/**
 * tquic_cid_security_dequeue_retire - Track RETIRE_CONNECTION_ID frame sending
 * @sec: CID security state
 */
void tquic_cid_security_dequeue_retire(struct tquic_cid_security *sec)
{
	if (sec)
		atomic_dec_if_positive(&sec->queued_retire_frames);
}

/*
 * =============================================================================
 * Optimistic ACK Attack Defense: Packet Number Skipping
 * =============================================================================
 */

/**
 * tquic_pn_skip_init - Initialize packet number skipping state
 * @state: Skip state to initialize
 * @skip_rate: Skip rate (1 in N packets)
 *
 * Returns: 0 on success
 */
int tquic_pn_skip_init(struct tquic_pn_skip_state *state, u32 skip_rate)
{
	if (!state)
		return -EINVAL;

	memset(state->skipped_pns, 0, sizeof(state->skipped_pns));
	state->head = 0;
	state->count = 0;
	state->skip_rate = skip_rate ? skip_rate : TQUIC_PN_SKIP_RATE_DEFAULT;
	state->packets_since_skip = 0;
	spin_lock_init(&state->lock);

	/* Set initial threshold */
	get_random_bytes(&state->next_skip_threshold, sizeof(u32));
	state->next_skip_threshold %= state->skip_rate;

	return 0;
}

/**
 * tquic_pn_skip_destroy - Cleanup packet number skipping state
 * @state: Skip state to destroy
 */
void tquic_pn_skip_destroy(struct tquic_pn_skip_state *state)
{
	/* Nothing to free */
}

/**
 * tquic_pn_should_skip - Check if packet number should be skipped
 * @state: Skip state
 * @pn_space: Packet number space
 *
 * Returns: Skip amount (0 = don't skip, 1-255 = skip this many PNs)
 */
int tquic_pn_should_skip(struct tquic_pn_skip_state *state, u8 pn_space)
{
	u32 skip_amount = 0;
	u32 rand_val;

	if (!state || state->skip_rate == 0)
		return 0;

	spin_lock_bh(&state->lock);

	state->packets_since_skip++;

	if (state->packets_since_skip >= state->next_skip_threshold) {
		/* Time to skip */
		get_random_bytes(&rand_val, sizeof(rand_val));
		skip_amount = TQUIC_PN_SKIP_MIN +
			      (rand_val % (TQUIC_PN_SKIP_MAX - TQUIC_PN_SKIP_MIN + 1));

		/* Reset counter and set new threshold */
		state->packets_since_skip = 0;
		get_random_bytes(&state->next_skip_threshold, sizeof(u32));
		state->next_skip_threshold %= state->skip_rate;
		if (state->next_skip_threshold == 0)
			state->next_skip_threshold = 1;
	}

	spin_unlock_bh(&state->lock);

	return skip_amount;
}

/**
 * tquic_pn_record_skip - Record a skipped packet number
 * @state: Skip state
 * @pn: The skipped packet number
 * @pn_space: Packet number space
 */
void tquic_pn_record_skip(struct tquic_pn_skip_state *state, u64 pn, u8 pn_space)
{
	u16 idx;

	if (!state)
		return;

	spin_lock_bh(&state->lock);

	/* Add to circular buffer */
	idx = state->head;
	state->skipped_pns[idx].pn = pn;
	state->skipped_pns[idx].pn_space = pn_space;
	state->skipped_pns[idx].skip_time = ktime_get();

	state->head = (state->head + 1) % TQUIC_MAX_SKIPPED_PNS;
	if (state->count < TQUIC_MAX_SKIPPED_PNS)
		state->count++;

	spin_unlock_bh(&state->lock);

	tquic_dbg("recorded skipped PN %llu in space %u\n", pn, pn_space);
}

/**
 * tquic_pn_check_optimistic_ack - Check if ACK references skipped PN
 * @state: Skip state
 * @acked_pn: Acknowledged packet number
 * @pn_space: Packet number space
 *
 * Returns: true if acked_pn was skipped (attack detected), false otherwise
 */
bool tquic_pn_check_optimistic_ack(struct tquic_pn_skip_state *state,
				   u64 acked_pn, u8 pn_space)
{
	int i;
	ktime_t now;
	s64 age_ms;

	if (!state || state->count == 0)
		return false;

	now = ktime_get();

	spin_lock_bh(&state->lock);

	for (i = 0; i < state->count; i++) {
		struct tquic_pn_skip_entry *entry = &state->skipped_pns[i];

		if (entry->pn == acked_pn && entry->pn_space == pn_space) {
			/* Check age - old entries may be false positives */
			age_ms = ktime_ms_delta(now, entry->skip_time);
			if (age_ms < 60000) {  /* 60 second window */
				spin_unlock_bh(&state->lock);
				tquic_warn("OPTIMISTIC ACK ATTACK DETECTED! "
				   "Peer ACKed skipped PN %llu in space %u "
				   "(skipped %lld ms ago)\n",
				   acked_pn, pn_space, age_ms);
				return true;
			}
		}
	}

	spin_unlock_bh(&state->lock);
	return false;
}

/*
 * =============================================================================
 * ACK Range Validation
 * =============================================================================
 */

/**
 * tquic_ack_validation_init - Initialize ACK validation state
 * @state: Validation state to initialize
 *
 * Returns: 0 on success
 */
int tquic_ack_validation_init(struct tquic_ack_validation_state *state)
{
	int i;

	if (!state)
		return -EINVAL;

	for (i = 0; i < TQUIC_PN_SPACE_COUNT; i++)
		state->largest_sent_pn[i] = 0;

	spin_lock_init(&state->lock);

	return 0;
}

/**
 * tquic_ack_validation_destroy - Cleanup ACK validation state
 * @state: Validation state to destroy
 */
void tquic_ack_validation_destroy(struct tquic_ack_validation_state *state)
{
	/* Nothing to free */
}

/**
 * tquic_ack_validation_record_sent - Record sent packet number
 * @state: Validation state
 * @pn: Sent packet number
 * @pn_space: Packet number space
 */
void tquic_ack_validation_record_sent(struct tquic_ack_validation_state *state,
				      u64 pn, u8 pn_space)
{
	if (!state || pn_space >= TQUIC_PN_SPACE_COUNT)
		return;

	spin_lock_bh(&state->lock);
	if (pn > state->largest_sent_pn[pn_space])
		state->largest_sent_pn[pn_space] = pn;
	spin_unlock_bh(&state->lock);
}

/**
 * tquic_ack_validation_check - Validate ACK frame
 * @state: Validation state
 * @largest_acked: Largest acknowledged packet number
 * @pn_space: Packet number space
 *
 * Returns: 0 if valid, -EPROTO if ACK references unsent packet
 */
int tquic_ack_validation_check(struct tquic_ack_validation_state *state,
			       u64 largest_acked, u8 pn_space)
{
	u64 largest_sent;

	if (!state || pn_space >= TQUIC_PN_SPACE_COUNT)
		return 0;

	spin_lock_bh(&state->lock);
	largest_sent = state->largest_sent_pn[pn_space];
	spin_unlock_bh(&state->lock);

	if (largest_acked > largest_sent) {
		tquic_warn("INVALID ACK DETECTED! "
			   "ACK.largest=%llu > largest_sent=%llu in space %u\n",
			   largest_acked, largest_sent, pn_space);
		return -EPROTO;
	}

	return 0;
}

/*
 * =============================================================================
 * Spin Bit Privacy Controls
 * =============================================================================
 */

/**
 * tquic_spin_bit_init - Initialize spin bit privacy state
 * @state: Spin bit state
 * @policy: Spin bit policy
 * @disable_rate: Probabilistic disable rate (1 in N)
 */
void tquic_spin_bit_init(struct tquic_spin_bit_state *state, u8 policy,
			 u8 disable_rate)
{
	if (!state)
		return;

	state->policy = policy;
	state->disable_rate = disable_rate ? disable_rate :
			      TQUIC_SPIN_BIT_DISABLE_RATE_DEFAULT;
	state->current_spin = 0;
	state->packet_count = 0;
	state->last_largest_pn = 0;
}

/**
 * tquic_spin_bit_get - Get spin bit value for outgoing packet
 * @state: Spin bit state
 * @pn: Packet number of outgoing packet
 *
 * Returns: Spin bit value (0 or 1)
 */
u8 tquic_spin_bit_get(struct tquic_spin_bit_state *state, u64 pn)
{
	u8 rand_byte;

	if (!state)
		return 0;

	switch (state->policy) {
	case TQUIC_SPIN_BIT_ALWAYS:
		/* Always return correct spin bit */
		return state->current_spin;

	case TQUIC_SPIN_BIT_NEVER:
		/* Always return random value */
		get_random_bytes(&rand_byte, 1);
		return rand_byte & 1;

	case TQUIC_SPIN_BIT_PROBABILISTIC:
	default:
		/* Probabilistically disable */
		get_random_bytes(&rand_byte, 1);
		if ((rand_byte % state->disable_rate) == 0) {
			/* Disable for this packet - return random */
			return rand_byte & 1;
		}
		/* Return correct spin bit */
		return state->current_spin;
	}
}

/**
 * tquic_spin_bit_update - Update spin bit based on received packet
 * @state: Spin bit state
 * @received_spin: Spin bit from received packet
 * @received_pn: Packet number of received packet
 */
void tquic_spin_bit_update(struct tquic_spin_bit_state *state, u8 received_spin,
			   u64 received_pn)
{
	if (!state)
		return;

	/* Only update on new largest PN */
	if (received_pn > state->last_largest_pn) {
		state->last_largest_pn = received_pn;
		/* Flip the spin bit (server mirrors, client initiates) */
		state->current_spin = received_spin ^ 1;
		state->packet_count++;
	}
}

/*
 * =============================================================================
 * Security Event Reporting
 * =============================================================================
 */

/**
 * tquic_security_event - Report a security event
 * @event: Event type
 * @addr: Source address (may be NULL)
 * @details: Event details
 */
void tquic_security_event(enum tquic_security_event event,
			  const struct sockaddr_storage *addr,
			  const char *details)
{
	char addr_str[64] = "unknown";
	const char *event_name;

	/* Convert address to string */
	if (addr) {
		if (addr->ss_family == AF_INET) {
			const struct sockaddr_in *sin =
				(const struct sockaddr_in *)addr;
			snprintf(addr_str, sizeof(addr_str), "%pI4",
				 &sin->sin_addr);
		} else if (addr->ss_family == AF_INET6) {
			const struct sockaddr_in6 *sin6 =
				(const struct sockaddr_in6 *)addr;
			snprintf(addr_str, sizeof(addr_str), "%pI6c",
				 &sin6->sin6_addr);
		}
	}

	switch (event) {
	case TQUIC_SEC_EVENT_PRE_HS_LIMIT:
		event_name = "PRE_HS_LIMIT";
		break;
	case TQUIC_SEC_EVENT_RETIRE_CID_FLOOD:
		event_name = "RETIRE_CID_FLOOD";
		break;
	case TQUIC_SEC_EVENT_NEW_CID_RATE_LIMIT:
		event_name = "NEW_CID_RATE_LIMIT";
		break;
	case TQUIC_SEC_EVENT_OPTIMISTIC_ACK:
		event_name = "OPTIMISTIC_ACK";
		break;
	case TQUIC_SEC_EVENT_INVALID_ACK:
		event_name = "INVALID_ACK";
		break;
	default:
		event_name = "UNKNOWN";
		break;
	}

	pr_notice("tquic: SECURITY [%s] from %s: %s\n",
		  event_name, addr_str, details ? details : "");

	/* Update MIB counters for each event type */
	switch (event) {
	case TQUIC_SEC_EVENT_PRE_HS_LIMIT:
		TQUIC_INC_STATS(&init_net, TQUIC_MIB_SEC_PRE_HS_LIMIT);
		break;
	case TQUIC_SEC_EVENT_RETIRE_CID_FLOOD:
		TQUIC_INC_STATS(&init_net, TQUIC_MIB_SEC_RETIRE_CID_FLOOD);
		break;
	case TQUIC_SEC_EVENT_NEW_CID_RATE_LIMIT:
		TQUIC_INC_STATS(&init_net, TQUIC_MIB_SEC_NEW_CID_RATE_LIMIT);
		break;
	case TQUIC_SEC_EVENT_OPTIMISTIC_ACK:
		TQUIC_INC_STATS(&init_net, TQUIC_MIB_SEC_OPTIMISTIC_ACK);
		break;
	case TQUIC_SEC_EVENT_INVALID_ACK:
		TQUIC_INC_STATS(&init_net, TQUIC_MIB_SEC_INVALID_ACK);
		break;
	default:
		break;
	}
}

/*
 * =============================================================================
 * Module Initialization
 * =============================================================================
 */

/**
 * tquic_security_hardening_init - Initialize all security hardening features
 *
 * Returns: 0 on success, negative errno on failure
 */
int __init tquic_security_hardening_init(void)
{
	int ret;

	ret = tquic_pre_hs_init();
	if (ret)
		return ret;

	tquic_info("security hardening initialized\n");
	return 0;
}

/**
 * tquic_security_hardening_exit - Cleanup security hardening features
 */
void __exit tquic_security_hardening_exit(void)
{
	tquic_pre_hs_exit();
	tquic_info("security hardening shutdown\n");
}

EXPORT_SYMBOL_GPL(tquic_pre_hs_init);
EXPORT_SYMBOL_GPL(tquic_pre_hs_exit);
EXPORT_SYMBOL_GPL(tquic_pre_hs_alloc);
EXPORT_SYMBOL_GPL(tquic_pre_hs_free);
EXPORT_SYMBOL_GPL(tquic_pre_hs_connection_complete);
EXPORT_SYMBOL_GPL(tquic_pre_hs_can_allocate);

EXPORT_SYMBOL_GPL(tquic_cid_security_init);
EXPORT_SYMBOL_GPL(tquic_cid_security_destroy);
EXPORT_SYMBOL_GPL(tquic_cid_security_check_new_cid);
EXPORT_SYMBOL_GPL(tquic_cid_security_queue_retire);
EXPORT_SYMBOL_GPL(tquic_cid_security_dequeue_retire);

EXPORT_SYMBOL_GPL(tquic_pn_skip_init);
EXPORT_SYMBOL_GPL(tquic_pn_skip_destroy);
EXPORT_SYMBOL_GPL(tquic_pn_should_skip);
EXPORT_SYMBOL_GPL(tquic_pn_record_skip);
EXPORT_SYMBOL_GPL(tquic_pn_check_optimistic_ack);

EXPORT_SYMBOL_GPL(tquic_ack_validation_init);
EXPORT_SYMBOL_GPL(tquic_ack_validation_destroy);
EXPORT_SYMBOL_GPL(tquic_ack_validation_record_sent);
EXPORT_SYMBOL_GPL(tquic_ack_validation_check);

EXPORT_SYMBOL_GPL(tquic_spin_bit_init);
EXPORT_SYMBOL_GPL(tquic_spin_bit_get);
EXPORT_SYMBOL_GPL(tquic_spin_bit_update);

EXPORT_SYMBOL_GPL(tquic_security_event);
EXPORT_SYMBOL_GPL(tquic_security_hardening_init);
EXPORT_SYMBOL_GPL(tquic_security_hardening_exit);

MODULE_DESCRIPTION("TQUIC Security Hardening");
MODULE_LICENSE("GPL");
