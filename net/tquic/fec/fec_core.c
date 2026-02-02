// SPDX-License-Identifier: GPL-2.0-only
/*
 * TQUIC FEC Core - State Management and Module Init
 *
 * Copyright (c) 2026 Linux Foundation
 *
 * Core FEC functionality including state management, negotiation,
 * and module initialization/cleanup.
 */

#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/module.h>

#include "fec.h"

/*
 * =============================================================================
 * FEC State Management
 * =============================================================================
 */

/**
 * tquic_fec_init - Initialize complete FEC state
 * @state: FEC state to initialize
 *
 * Return: 0 on success, negative error on failure
 */
int tquic_fec_init(struct tquic_fec_state *state)
{
	if (!state)
		return -EINVAL;

	memset(state, 0, sizeof(*state));

	state->enabled = false;
	state->scheme = TQUIC_FEC_SCHEME_XOR;
	state->max_source_symbols = TQUIC_FEC_DEFAULT_MAX_SOURCE_SYMBOLS;

	state->peer_enabled = false;
	state->peer_scheme = TQUIC_FEC_SCHEME_XOR;
	state->peer_max_source_symbols = TQUIC_FEC_DEFAULT_MAX_SOURCE_SYMBOLS;

	return 0;
}
EXPORT_SYMBOL_GPL(tquic_fec_init);

/**
 * tquic_fec_destroy - Destroy FEC state
 * @state: FEC state to destroy
 */
void tquic_fec_destroy(struct tquic_fec_state *state)
{
	if (!state)
		return;

	tquic_fec_encoder_destroy(state);
	tquic_fec_decoder_destroy(state);
	tquic_fec_scheduler_destroy(state);

	state->enabled = false;
}
EXPORT_SYMBOL_GPL(tquic_fec_destroy);

/**
 * tquic_fec_negotiate - Negotiate FEC parameters with peer
 * @state: FEC state
 * @local: Local FEC parameters
 * @peer: Peer's FEC parameters
 *
 * FEC is enabled only if both endpoints support it.
 * The negotiated scheme is the scheme both endpoints support,
 * preferring more capable schemes.
 *
 * Return: 0 on success, negative error on failure
 */
int tquic_fec_negotiate(struct tquic_fec_state *state,
			const struct tquic_fec_params *local,
			const struct tquic_fec_params *peer)
{
	enum tquic_fec_scheme negotiated_scheme;
	u8 negotiated_max_source;

	if (!state || !local || !peer)
		return -EINVAL;

	/* Store peer parameters */
	state->peer_enabled = peer->enable_fec;
	state->peer_scheme = peer->fec_scheme;
	state->peer_max_source_symbols = peer->max_source_symbols;

	/* FEC enabled only if both support it */
	if (!local->enable_fec || !peer->enable_fec) {
		state->enabled = false;
		return 0;
	}

	/*
	 * Negotiate scheme - use the more capable scheme both support
	 *
	 * Priority:
	 *   1. Reed-Solomon 16 (most capable)
	 *   2. Reed-Solomon 8
	 *   3. XOR (simplest, always supported)
	 */
	if (local->fec_scheme >= TQUIC_FEC_SCHEME_REED_SOLOMON_16 &&
	    peer->fec_scheme >= TQUIC_FEC_SCHEME_REED_SOLOMON_16) {
		negotiated_scheme = TQUIC_FEC_SCHEME_REED_SOLOMON_16;
	} else if (local->fec_scheme >= TQUIC_FEC_SCHEME_REED_SOLOMON_8 &&
		   peer->fec_scheme >= TQUIC_FEC_SCHEME_REED_SOLOMON_8) {
		negotiated_scheme = TQUIC_FEC_SCHEME_REED_SOLOMON_8;
	} else {
		negotiated_scheme = TQUIC_FEC_SCHEME_XOR;
	}

	/* Negotiate max source symbols - use minimum */
	negotiated_max_source = min(local->max_source_symbols,
				    peer->max_source_symbols);
	if (negotiated_max_source < TQUIC_FEC_MIN_SOURCE_SYMBOLS)
		negotiated_max_source = TQUIC_FEC_MIN_SOURCE_SYMBOLS;

	state->scheme = negotiated_scheme;
	state->max_source_symbols = negotiated_max_source;
	state->enabled = true;

	pr_debug("tquic fec: negotiated scheme=%s max_source=%u\n",
		 tquic_fec_scheme_name(negotiated_scheme), negotiated_max_source);

	return 0;
}
EXPORT_SYMBOL_GPL(tquic_fec_negotiate);

/**
 * tquic_fec_enable - Enable FEC for connection
 * @state: FEC state
 * @scheme: FEC scheme to use
 * @block_size: Source block size
 *
 * Return: 0 on success, negative error on failure
 */
int tquic_fec_enable(struct tquic_fec_state *state,
		     enum tquic_fec_scheme scheme, u8 block_size)
{
	int ret;
	u8 repair_count;

	if (!state)
		return -EINVAL;

	if (scheme >= __TQUIC_FEC_SCHEME_MAX)
		return -EINVAL;

	if (block_size < TQUIC_FEC_MIN_SOURCE_SYMBOLS ||
	    block_size > TQUIC_FEC_MAX_SOURCE_SYMBOLS)
		return -EINVAL;

	/* Initialize scheduler first to compute repair count */
	ret = tquic_fec_scheduler_init(state, 10, true);
	if (ret < 0)
		return ret;

	repair_count = tquic_fec_compute_repair_count(state, block_size);

	/* Initialize encoder */
	ret = tquic_fec_encoder_init(state, scheme, block_size, repair_count);
	if (ret < 0) {
		tquic_fec_scheduler_destroy(state);
		return ret;
	}

	/* Initialize decoder */
	ret = tquic_fec_decoder_init(state, scheme, 16);
	if (ret < 0) {
		tquic_fec_encoder_destroy(state);
		tquic_fec_scheduler_destroy(state);
		return ret;
	}

	state->enabled = true;
	state->scheme = scheme;
	state->max_source_symbols = block_size;

	pr_debug("tquic fec: enabled scheme=%s block_size=%u repair_count=%u\n",
		 tquic_fec_scheme_name(scheme), block_size, repair_count);

	return 0;
}
EXPORT_SYMBOL_GPL(tquic_fec_enable);

/**
 * tquic_fec_disable - Disable FEC for connection
 * @state: FEC state
 */
void tquic_fec_disable(struct tquic_fec_state *state)
{
	if (!state)
		return;

	tquic_fec_encoder_destroy(state);
	tquic_fec_decoder_destroy(state);
	tquic_fec_scheduler_destroy(state);

	state->enabled = false;

	pr_debug("tquic fec: disabled\n");
}
EXPORT_SYMBOL_GPL(tquic_fec_disable);

/*
 * =============================================================================
 * FEC Statistics
 * =============================================================================
 */

/**
 * tquic_fec_get_stats - Get FEC statistics
 * @state: FEC state
 * @stats: Output statistics structure
 */
void tquic_fec_get_stats(struct tquic_fec_state *state,
			 struct tquic_fec_stats *stats)
{
	if (!state || !stats)
		return;

	memset(stats, 0, sizeof(*stats));

	spin_lock_bh(&state->encoder.lock);
	stats->blocks_encoded = state->encoder.stats.blocks_created;
	stats->symbols_encoded = state->encoder.stats.symbols_encoded;
	stats->repair_sent = state->encoder.stats.repair_symbols_sent;
	spin_unlock_bh(&state->encoder.lock);

	spin_lock_bh(&state->decoder.lock);
	stats->blocks_received = state->decoder.stats.blocks_received;
	stats->symbols_received = state->decoder.stats.symbols_received;
	stats->repair_received = state->decoder.stats.repair_symbols_received;
	stats->recovery_attempts = state->decoder.stats.recovery_attempts;
	stats->recovery_success = state->decoder.stats.recovery_success;
	stats->recovery_failed = state->decoder.stats.recovery_failed;
	stats->packets_recovered = state->decoder.stats.packets_recovered;
	spin_unlock_bh(&state->decoder.lock);

	stats->current_fec_rate = tquic_fec_get_current_rate(state);
	stats->current_loss_rate = tquic_fec_get_loss_rate(state);
}
EXPORT_SYMBOL_GPL(tquic_fec_get_stats);

/*
 * =============================================================================
 * Module Init/Exit
 * =============================================================================
 */

/**
 * tquic_fec_module_init - Initialize FEC subsystem
 *
 * Return: 0 on success, negative error on failure
 */
int __init tquic_fec_module_init(void)
{
	int ret;

	/* Initialize Reed-Solomon tables */
	ret = tquic_rs_init();
	if (ret < 0) {
		pr_err("tquic fec: failed to initialize Reed-Solomon: %d\n", ret);
		return ret;
	}

	pr_info("tquic fec: Forward Error Correction subsystem initialized\n");
	pr_info("tquic fec: Supported schemes: XOR, Reed-Solomon GF(2^8), Reed-Solomon GF(2^16)\n");

	return 0;
}
EXPORT_SYMBOL_GPL(tquic_fec_module_init);

/**
 * tquic_fec_module_exit - Clean up FEC subsystem
 */
void __exit tquic_fec_module_exit(void)
{
	tquic_rs_exit();
	pr_info("tquic fec: Forward Error Correction subsystem cleaned up\n");
}
EXPORT_SYMBOL_GPL(tquic_fec_module_exit);
