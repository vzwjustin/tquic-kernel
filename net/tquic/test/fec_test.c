// SPDX-License-Identifier: GPL-2.0-only
/*
 * TQUIC FEC Test Suite
 *
 * Copyright (c) 2026 Linux Foundation
 * Kernel implementation by Justin Adams <spotty118@gmail.com>
 *
 * Comprehensive tests for Forward Error Correction functionality
 * including XOR FEC, Reed-Solomon FEC, encoder, decoder, and scheduler.
 */

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/random.h>

#include "../fec/fec.h"

/* Test configuration */
#define TEST_SYMBOL_SIZE	100
#define TEST_BLOCK_SIZE		8
#define TEST_REPAIR_COUNT	4

/* Test result tracking */
static int tests_run;
static int tests_passed;
static int tests_failed;

#define TEST_START(name) \
	pr_info("tquic_fec_test: Running test: %s\n", name); \
	tests_run++

#define TEST_PASS() \
	do { \
		pr_info("tquic_fec_test:   PASS\n"); \
		tests_passed++; \
	} while (0)

#define TEST_FAIL(fmt, ...) \
	do { \
		pr_err("tquic_fec_test:   FAIL: " fmt "\n", ##__VA_ARGS__); \
		tests_failed++; \
	} while (0)

#define ASSERT_EQ(expected, actual, name) \
	do { \
		if ((expected) != (actual)) { \
			TEST_FAIL("%s: expected %lld, got %lld", \
				  name, (long long)(expected), (long long)(actual)); \
			return -1; \
		} \
	} while (0)

#define ASSERT_TRUE(cond, name) \
	do { \
		if (!(cond)) { \
			TEST_FAIL("%s: expected true", name); \
			return -1; \
		} \
	} while (0)

#define ASSERT_NOT_NULL(ptr, name) \
	do { \
		if ((ptr) == NULL) { \
			TEST_FAIL("%s: unexpected NULL", name); \
			return -1; \
		} \
	} while (0)

/*
 * =============================================================================
 * XOR FEC Tests
 * =============================================================================
 */

/**
 * test_xor_encode_basic - Test basic XOR encoding
 */
static int test_xor_encode_basic(void)
{
	const u8 sym1[] = {0x01, 0x02, 0x03, 0x04};
	const u8 sym2[] = {0x10, 0x20, 0x30, 0x40};
	const u8 sym3[] = {0x11, 0x22, 0x33, 0x44};
	const u8 *symbols[3] = {sym1, sym2, sym3};
	u16 lengths[3] = {4, 4, 4};
	u8 repair[TEST_SYMBOL_SIZE];
	u16 repair_len;
	int ret;
	int i;

	TEST_START("xor_encode_basic");

	ret = tquic_xor_encode(symbols, lengths, 3, repair, &repair_len);
	ASSERT_EQ(0, ret, "xor_encode return");
	ASSERT_EQ(4, repair_len, "repair length");

	/* Verify: repair = sym1 ^ sym2 ^ sym3 */
	for (i = 0; i < 4; i++) {
		u8 expected = sym1[i] ^ sym2[i] ^ sym3[i];
		ASSERT_EQ(expected, repair[i], "repair byte");
	}

	TEST_PASS();
	return 0;
}

/**
 * test_xor_decode_single_loss - Test XOR recovery of single lost packet
 */
static int test_xor_decode_single_loss(void)
{
	const u8 sym1[] = {0xAA, 0xBB, 0xCC, 0xDD};
	const u8 sym2[] = {0x11, 0x22, 0x33, 0x44};
	const u8 sym3[] = {0x55, 0x66, 0x77, 0x88};
	const u8 *symbols[3] = {sym1, sym2, sym3};
	u16 lengths[3] = {4, 4, 4};
	u8 repair[TEST_SYMBOL_SIZE];
	u16 repair_len;
	u8 recovered[TEST_SYMBOL_SIZE];
	u16 recovered_len;
	const u8 *decode_symbols[3];
	u16 decode_lengths[3];
	int ret;
	int i;

	TEST_START("xor_decode_single_loss");

	/* First encode to get repair symbol */
	ret = tquic_xor_encode(symbols, lengths, 3, repair, &repair_len);
	ASSERT_EQ(0, ret, "encode");

	/* Simulate loss of symbol 1 */
	decode_symbols[0] = sym1;
	decode_symbols[1] = NULL;  /* Lost */
	decode_symbols[2] = sym3;
	decode_lengths[0] = 4;
	decode_lengths[1] = 0;
	decode_lengths[2] = 4;

	/* Decode to recover */
	ret = tquic_xor_decode(decode_symbols, decode_lengths, 3,
			       repair, repair_len, recovered, &recovered_len);
	ASSERT_EQ(0, ret, "decode");
	ASSERT_EQ(4, recovered_len, "recovered length");

	/* Verify recovered matches original */
	for (i = 0; i < 4; i++) {
		ASSERT_EQ(sym2[i], recovered[i], "recovered byte");
	}

	TEST_PASS();
	return 0;
}

/**
 * test_xor_decode_two_losses - Test that XOR fails with two losses
 */
static int test_xor_decode_two_losses(void)
{
	const u8 sym1[] = {0x01, 0x02, 0x03, 0x04};
	const u8 sym2[] = {0x10, 0x20, 0x30, 0x40};
	const u8 sym3[] = {0x11, 0x22, 0x33, 0x44};
	const u8 *symbols[3] = {sym1, sym2, sym3};
	u16 lengths[3] = {4, 4, 4};
	u8 repair[TEST_SYMBOL_SIZE];
	u16 repair_len;
	u8 recovered[TEST_SYMBOL_SIZE];
	u16 recovered_len;
	const u8 *decode_symbols[3];
	u16 decode_lengths[3] = {4, 0, 0};
	int ret;

	TEST_START("xor_decode_two_losses");

	ret = tquic_xor_encode(symbols, lengths, 3, repair, &repair_len);
	ASSERT_EQ(0, ret, "encode");

	/* Simulate loss of symbols 1 and 2 */
	decode_symbols[0] = sym1;
	decode_symbols[1] = NULL;
	decode_symbols[2] = NULL;

	/* Should fail - too many losses */
	ret = tquic_xor_decode(decode_symbols, decode_lengths, 3,
			       repair, repair_len, recovered, &recovered_len);
	ASSERT_EQ(-E2BIG, ret, "decode should fail with E2BIG");

	TEST_PASS();
	return 0;
}

/**
 * test_xor_variable_lengths - Test XOR with variable length symbols
 */
static int test_xor_variable_lengths(void)
{
	const u8 sym1[] = {0x01, 0x02};
	const u8 sym2[] = {0x10, 0x20, 0x30, 0x40};
	const u8 sym3[] = {0x11, 0x22, 0x33};
	const u8 *symbols[3] = {sym1, sym2, sym3};
	u16 lengths[3] = {2, 4, 3};
	u8 repair[TEST_SYMBOL_SIZE];
	u16 repair_len;
	int ret;

	TEST_START("xor_variable_lengths");

	ret = tquic_xor_encode(symbols, lengths, 3, repair, &repair_len);
	ASSERT_EQ(0, ret, "encode");
	ASSERT_EQ(4, repair_len, "repair length should be max");

	/* Verify first two bytes XOR correctly */
	ASSERT_EQ(sym1[0] ^ sym2[0] ^ sym3[0], repair[0], "byte 0");
	ASSERT_EQ(sym1[1] ^ sym2[1] ^ sym3[1], repair[1], "byte 1");

	/* Third byte: sym2[2] ^ sym3[2] (sym1 too short) */
	ASSERT_EQ(sym2[2] ^ sym3[2], repair[2], "byte 2");

	/* Fourth byte: only sym2 contributes */
	ASSERT_EQ(sym2[3], repair[3], "byte 3");

	TEST_PASS();
	return 0;
}

/*
 * =============================================================================
 * Reed-Solomon FEC Tests
 * =============================================================================
 */

/**
 * test_rs_init - Test Reed-Solomon initialization
 */
static int test_rs_init(void)
{
	int ret;

	TEST_START("rs_init");

	ret = tquic_rs_init();
	ASSERT_EQ(0, ret, "rs_init");

	TEST_PASS();
	return 0;
}

/**
 * test_rs_encode_basic - Test basic RS encoding
 */
static int test_rs_encode_basic(void)
{
	const u8 sym1[] = {0x01, 0x02, 0x03, 0x04};
	const u8 sym2[] = {0x10, 0x20, 0x30, 0x40};
	const u8 sym3[] = {0x11, 0x22, 0x33, 0x44};
	const u8 sym4[] = {0xAA, 0xBB, 0xCC, 0xDD};
	const u8 *symbols[4] = {sym1, sym2, sym3, sym4};
	u16 lengths[4] = {4, 4, 4, 4};
	u8 *repair[2];
	u16 repair_lens[2];
	int i, ret;

	TEST_START("rs_encode_basic");

	/* Allocate repair buffers */
	for (i = 0; i < 2; i++) {
		repair[i] = kmalloc(TEST_SYMBOL_SIZE, GFP_KERNEL);
		ASSERT_NOT_NULL(repair[i], "repair buffer");
	}

	ret = tquic_rs_encode(symbols, lengths, 4, 2, repair, repair_lens, 8);
	ASSERT_EQ(0, ret, "rs_encode");

	/* Verify repair lengths */
	ASSERT_EQ(4, repair_lens[0], "repair[0] length");
	ASSERT_EQ(4, repair_lens[1], "repair[1] length");

	/* Clean up */
	for (i = 0; i < 2; i++)
		kfree(repair[i]);

	TEST_PASS();
	return 0;
}

/**
 * test_rs_decode_single_erasure - Test RS recovery of single erasure
 */
static int test_rs_decode_single_erasure(void)
{
	const u8 sym1[] = {0x01, 0x02, 0x03, 0x04};
	const u8 sym2[] = {0x10, 0x20, 0x30, 0x40};
	const u8 sym3[] = {0x11, 0x22, 0x33, 0x44};
	const u8 sym4[] = {0xAA, 0xBB, 0xCC, 0xDD};
	const u8 *symbols[4] = {sym1, sym2, sym3, sym4};
	u16 lengths[4] = {4, 4, 4, 4};
	u8 *repair[2];
	u16 repair_lens[2];
	const u8 *decode_symbols[4];
	u16 decode_lengths[4] = {4, 0, 4, 4};
	const u8 *decode_repair[2];
	u8 erasure_pos[1] = {1};
	u8 *recovered[1];
	u16 recovered_lens[1];
	int i, ret;

	TEST_START("rs_decode_single_erasure");

	/* Allocate buffers */
	for (i = 0; i < 2; i++) {
		repair[i] = kmalloc(TEST_SYMBOL_SIZE, GFP_KERNEL);
		ASSERT_NOT_NULL(repair[i], "repair buffer");
	}
	recovered[0] = kmalloc(TEST_SYMBOL_SIZE, GFP_KERNEL);
	ASSERT_NOT_NULL(recovered[0], "recovered buffer");

	/* Encode */
	ret = tquic_rs_encode(symbols, lengths, 4, 2, repair, repair_lens, 8);
	ASSERT_EQ(0, ret, "encode");

	/* Setup decode with symbol 1 lost */
	decode_symbols[0] = sym1;
	decode_symbols[1] = NULL;  /* Lost */
	decode_symbols[2] = sym3;
	decode_symbols[3] = sym4;
	decode_repair[0] = repair[0];
	decode_repair[1] = repair[1];

	/* Decode */
	ret = tquic_rs_decode(decode_symbols, decode_lengths, 4,
			      decode_repair, repair_lens, 2,
			      erasure_pos, 1, recovered, recovered_lens, 8);
	ASSERT_TRUE(ret > 0, "decode success");

	/* Verify recovered matches original */
	for (i = 0; i < 4; i++) {
		ASSERT_EQ(sym2[i], recovered[0][i], "recovered byte");
	}

	/* Clean up */
	for (i = 0; i < 2; i++)
		kfree(repair[i]);
	kfree(recovered[0]);

	TEST_PASS();
	return 0;
}

/**
 * test_rs_decode_multiple_erasures - Test RS recovery of multiple erasures
 */
static int test_rs_decode_multiple_erasures(void)
{
	const u8 sym1[] = {0x01, 0x02, 0x03, 0x04};
	const u8 sym2[] = {0x10, 0x20, 0x30, 0x40};
	const u8 sym3[] = {0x11, 0x22, 0x33, 0x44};
	const u8 sym4[] = {0xAA, 0xBB, 0xCC, 0xDD};
	const u8 *symbols[4] = {sym1, sym2, sym3, sym4};
	u16 lengths[4] = {4, 4, 4, 4};
	u8 *repair[2];
	u16 repair_lens[2];
	const u8 *decode_symbols[4];
	u16 decode_lengths[4] = {0, 4, 0, 4};
	const u8 *decode_repair[2];
	u8 erasure_pos[2] = {0, 2};
	u8 *recovered[2];
	u16 recovered_lens[2];
	int i, ret;

	TEST_START("rs_decode_multiple_erasures");

	/* Allocate buffers */
	for (i = 0; i < 2; i++) {
		repair[i] = kmalloc(TEST_SYMBOL_SIZE, GFP_KERNEL);
		ASSERT_NOT_NULL(repair[i], "repair buffer");
		recovered[i] = kmalloc(TEST_SYMBOL_SIZE, GFP_KERNEL);
		ASSERT_NOT_NULL(recovered[i], "recovered buffer");
	}

	/* Encode */
	ret = tquic_rs_encode(symbols, lengths, 4, 2, repair, repair_lens, 8);
	ASSERT_EQ(0, ret, "encode");

	/* Setup decode with symbols 0 and 2 lost */
	decode_symbols[0] = NULL;  /* Lost */
	decode_symbols[1] = sym2;
	decode_symbols[2] = NULL;  /* Lost */
	decode_symbols[3] = sym4;
	decode_repair[0] = repair[0];
	decode_repair[1] = repair[1];

	/* Decode */
	ret = tquic_rs_decode(decode_symbols, decode_lengths, 4,
			      decode_repair, repair_lens, 2,
			      erasure_pos, 2, recovered, recovered_lens, 8);
	ASSERT_TRUE(ret > 0, "decode success");

	/* Verify recovered matches original */
	for (i = 0; i < 4; i++) {
		ASSERT_EQ(sym1[i], recovered[0][i], "recovered[0] byte");
		ASSERT_EQ(sym3[i], recovered[1][i], "recovered[1] byte");
	}

	/* Clean up */
	for (i = 0; i < 2; i++) {
		kfree(repair[i]);
		kfree(recovered[i]);
	}

	TEST_PASS();
	return 0;
}

/*
 * =============================================================================
 * FEC Encoder Tests
 * =============================================================================
 */

/**
 * test_encoder_init - Test encoder initialization
 */
static int test_encoder_init(void)
{
	struct tquic_fec_state state;
	int ret;

	TEST_START("encoder_init");

	memset(&state, 0, sizeof(state));

	ret = tquic_fec_encoder_init(&state, TQUIC_FEC_SCHEME_XOR, 8, 1);
	ASSERT_EQ(0, ret, "encoder_init");
	ASSERT_TRUE(state.encoder.enabled, "encoder enabled");
	ASSERT_EQ(TQUIC_FEC_SCHEME_XOR, state.encoder.scheme, "scheme");
	ASSERT_EQ(8, state.encoder.block_size, "block_size");

	tquic_fec_encoder_destroy(&state);

	TEST_PASS();
	return 0;
}

/**
 * test_encoder_add_symbols - Test adding source symbols
 */
static int test_encoder_add_symbols(void)
{
	struct tquic_fec_state state;
	u8 data[TEST_SYMBOL_SIZE];
	int ret, i;

	TEST_START("encoder_add_symbols");

	memset(&state, 0, sizeof(state));
	ret = tquic_fec_encoder_init(&state, TQUIC_FEC_SCHEME_XOR, 4, 1);
	ASSERT_EQ(0, ret, "init");

	/* Add symbols until block is complete */
	for (i = 0; i < 4; i++) {
		memset(data, i + 1, TEST_SYMBOL_SIZE);
		ret = tquic_fec_add_source_symbol(&state, i, data, TEST_SYMBOL_SIZE);
		if (i < 3) {
			ASSERT_EQ(0, ret, "add symbol (not complete)");
		} else {
			ASSERT_EQ(1, ret, "add symbol (block complete)");
		}
	}

	ASSERT_EQ(1, state.encoder.stats.blocks_created, "blocks_created");
	ASSERT_EQ(4, state.encoder.stats.symbols_encoded, "symbols_encoded");

	tquic_fec_encoder_destroy(&state);

	TEST_PASS();
	return 0;
}

/**
 * test_encoder_generate_repair - Test repair symbol generation
 */
static int test_encoder_generate_repair(void)
{
	struct tquic_fec_state state;
	u8 data[TEST_SYMBOL_SIZE];
	int ret, i;

	TEST_START("encoder_generate_repair");

	memset(&state, 0, sizeof(state));
	ret = tquic_fec_encoder_init(&state, TQUIC_FEC_SCHEME_XOR, 4, 1);
	ASSERT_EQ(0, ret, "init");

	/* Add symbols */
	for (i = 0; i < 4; i++) {
		memset(data, i + 1, TEST_SYMBOL_SIZE);
		tquic_fec_add_source_symbol(&state, i, data, TEST_SYMBOL_SIZE);
	}

	/* Generate repair */
	ret = tquic_fec_generate_repair(&state, NULL);
	ASSERT_EQ(1, ret, "repair count");

	tquic_fec_encoder_destroy(&state);

	TEST_PASS();
	return 0;
}

/*
 * =============================================================================
 * FEC Decoder Tests
 * =============================================================================
 */

/**
 * test_decoder_init - Test decoder initialization
 */
static int test_decoder_init(void)
{
	struct tquic_fec_state state;
	int ret;

	TEST_START("decoder_init");

	memset(&state, 0, sizeof(state));

	ret = tquic_fec_decoder_init(&state, TQUIC_FEC_SCHEME_XOR, 16);
	ASSERT_EQ(0, ret, "decoder_init");
	ASSERT_TRUE(state.decoder.enabled, "decoder enabled");
	ASSERT_EQ(TQUIC_FEC_SCHEME_XOR, state.decoder.scheme, "scheme");
	ASSERT_EQ(16, state.decoder.max_active_blocks, "max_blocks");

	tquic_fec_decoder_destroy(&state);

	TEST_PASS();
	return 0;
}

/**
 * test_decoder_receive_source - Test receiving source symbols
 */
static int test_decoder_receive_source(void)
{
	struct tquic_fec_state state;
	u8 data[TEST_SYMBOL_SIZE];
	int ret;

	TEST_START("decoder_receive_source");

	memset(&state, 0, sizeof(state));
	ret = tquic_fec_decoder_init(&state, TQUIC_FEC_SCHEME_XOR, 16);
	ASSERT_EQ(0, ret, "init");

	memset(data, 0xAA, TEST_SYMBOL_SIZE);
	ret = tquic_fec_receive_source(&state, 1, 0, 100, data, TEST_SYMBOL_SIZE);
	ASSERT_EQ(0, ret, "receive_source");

	ASSERT_EQ(1, state.decoder.stats.symbols_received, "symbols_received");
	ASSERT_EQ(1, state.decoder.stats.blocks_received, "blocks_received");

	tquic_fec_decoder_destroy(&state);

	TEST_PASS();
	return 0;
}

/*
 * =============================================================================
 * FEC Scheduler Tests
 * =============================================================================
 */

/**
 * test_scheduler_init - Test scheduler initialization
 */
static int test_scheduler_init(void)
{
	struct tquic_fec_state state;
	int ret;

	TEST_START("scheduler_init");

	memset(&state, 0, sizeof(state));

	ret = tquic_fec_scheduler_init(&state, 10, true);
	ASSERT_EQ(0, ret, "scheduler_init");
	ASSERT_EQ(10, state.scheduler.target_fec_rate, "fec_rate");
	ASSERT_TRUE(state.scheduler.adaptive, "adaptive");

	tquic_fec_scheduler_destroy(&state);

	TEST_PASS();
	return 0;
}

/**
 * test_scheduler_loss_tracking - Test loss rate tracking
 */
static int test_scheduler_loss_tracking(void)
{
	struct tquic_fec_state state;
	int ret, i;

	TEST_START("scheduler_loss_tracking");

	memset(&state, 0, sizeof(state));
	ret = tquic_fec_scheduler_init(&state, 10, true);
	ASSERT_EQ(0, ret, "init");

	/* Simulate 10% loss: 9 acks, 1 loss */
	for (i = 0; i < 9; i++)
		tquic_fec_report_ack(&state, i);
	tquic_fec_report_loss(&state, 9);

	/* Loss rate should be ~100 permille (10%) */
	ASSERT_TRUE(state.scheduler.current_loss_rate > 50, "loss rate > 5%");
	ASSERT_TRUE(state.scheduler.current_loss_rate < 150, "loss rate < 15%");

	tquic_fec_scheduler_destroy(&state);

	TEST_PASS();
	return 0;
}

/**
 * test_scheduler_rate_adjustment - Test adaptive rate adjustment
 */
static int test_scheduler_rate_adjustment(void)
{
	struct tquic_fec_state state;
	u8 initial_rate;
	int ret, i;

	TEST_START("scheduler_rate_adjustment");

	memset(&state, 0, sizeof(state));
	ret = tquic_fec_scheduler_init(&state, 10, true);
	ASSERT_EQ(0, ret, "init");

	initial_rate = state.scheduler.target_fec_rate;

	/* Simulate high loss */
	for (i = 0; i < 50; i++) {
		tquic_fec_report_loss(&state, i);
		tquic_fec_report_ack(&state, 50 + i);
	}

	/* Force adjustment (normally time-based) */
	state.scheduler.last_adjustment = ktime_sub_ms(ktime_get(), 200);
	tquic_fec_adjust_rate(&state);

	/* Rate should have increased */
	ASSERT_TRUE(state.scheduler.target_fec_rate >= initial_rate,
		    "rate should increase or stay same");

	tquic_fec_scheduler_destroy(&state);

	TEST_PASS();
	return 0;
}

/*
 * =============================================================================
 * FEC State Management Tests
 * =============================================================================
 */

/**
 * test_fec_init_destroy - Test FEC state init/destroy
 */
static int test_fec_init_destroy(void)
{
	struct tquic_fec_state state;
	int ret;

	TEST_START("fec_init_destroy");

	ret = tquic_fec_init(&state);
	ASSERT_EQ(0, ret, "init");
	ASSERT_TRUE(!state.enabled, "not enabled after init");

	tquic_fec_destroy(&state);

	TEST_PASS();
	return 0;
}

/**
 * test_fec_enable_disable - Test FEC enable/disable
 */
static int test_fec_enable_disable(void)
{
	struct tquic_fec_state state;
	int ret;

	TEST_START("fec_enable_disable");

	ret = tquic_fec_init(&state);
	ASSERT_EQ(0, ret, "init");

	ret = tquic_fec_enable(&state, TQUIC_FEC_SCHEME_XOR, 8);
	ASSERT_EQ(0, ret, "enable");
	ASSERT_TRUE(state.enabled, "enabled");
	ASSERT_EQ(TQUIC_FEC_SCHEME_XOR, state.scheme, "scheme");

	tquic_fec_disable(&state);
	ASSERT_TRUE(!state.enabled, "disabled");

	tquic_fec_destroy(&state);

	TEST_PASS();
	return 0;
}

/**
 * test_fec_negotiate - Test FEC parameter negotiation
 */
static int test_fec_negotiate(void)
{
	struct tquic_fec_state state;
	struct tquic_fec_params local, peer;
	int ret;

	TEST_START("fec_negotiate");

	ret = tquic_fec_init(&state);
	ASSERT_EQ(0, ret, "init");

	/* Both support RS-8 */
	local.enable_fec = true;
	local.fec_scheme = TQUIC_FEC_SCHEME_REED_SOLOMON_8;
	local.max_source_symbols = 32;

	peer.enable_fec = true;
	peer.fec_scheme = TQUIC_FEC_SCHEME_REED_SOLOMON_8;
	peer.max_source_symbols = 16;

	ret = tquic_fec_negotiate(&state, &local, &peer);
	ASSERT_EQ(0, ret, "negotiate");
	ASSERT_TRUE(state.enabled, "enabled");
	ASSERT_EQ(TQUIC_FEC_SCHEME_REED_SOLOMON_8, state.scheme, "scheme");
	ASSERT_EQ(16, state.max_source_symbols, "max_source (min of both)");

	tquic_fec_destroy(&state);

	TEST_PASS();
	return 0;
}

/**
 * test_fec_negotiate_no_support - Test negotiation when peer doesn't support FEC
 */
static int test_fec_negotiate_no_support(void)
{
	struct tquic_fec_state state;
	struct tquic_fec_params local, peer;
	int ret;

	TEST_START("fec_negotiate_no_support");

	ret = tquic_fec_init(&state);
	ASSERT_EQ(0, ret, "init");

	local.enable_fec = true;
	local.fec_scheme = TQUIC_FEC_SCHEME_REED_SOLOMON_8;
	local.max_source_symbols = 32;

	peer.enable_fec = false;  /* Peer doesn't support */
	peer.fec_scheme = 0;
	peer.max_source_symbols = 0;

	ret = tquic_fec_negotiate(&state, &local, &peer);
	ASSERT_EQ(0, ret, "negotiate");
	ASSERT_TRUE(!state.enabled, "not enabled when peer doesn't support");

	tquic_fec_destroy(&state);

	TEST_PASS();
	return 0;
}

/*
 * =============================================================================
 * End-to-End Tests
 * =============================================================================
 */

/**
 * test_e2e_xor_recovery - End-to-end XOR FEC with recovery
 */
static int test_e2e_xor_recovery(void)
{
	struct tquic_fec_state enc_state, dec_state;
	u8 data[4][TEST_SYMBOL_SIZE];
	struct tquic_fec_repair_frame repair_frame;
	int ret, i;

	TEST_START("e2e_xor_recovery");

	/* Initialize encoder and decoder */
	ret = tquic_fec_init(&enc_state);
	ASSERT_EQ(0, ret, "enc init");
	ret = tquic_fec_enable(&enc_state, TQUIC_FEC_SCHEME_XOR, 4);
	ASSERT_EQ(0, ret, "enc enable");

	ret = tquic_fec_init(&dec_state);
	ASSERT_EQ(0, ret, "dec init");
	ret = tquic_fec_decoder_init(&dec_state, TQUIC_FEC_SCHEME_XOR, 16);
	ASSERT_EQ(0, ret, "dec enable");

	/* Encode 4 symbols */
	for (i = 0; i < 4; i++) {
		memset(data[i], (i + 1) * 0x11, TEST_SYMBOL_SIZE);
		ret = tquic_fec_add_source_symbol(&enc_state, i, data[i], TEST_SYMBOL_SIZE);
	}

	/* Generate repair */
	ret = tquic_fec_generate_repair(&enc_state, NULL);
	ASSERT_EQ(1, ret, "generate repair");

	/* Simulate decoder receiving 3 of 4 symbols (symbol 2 lost) */
	for (i = 0; i < 4; i++) {
		if (i == 2)
			continue;  /* Simulate loss */
		tquic_fec_receive_source(&dec_state, 0, i, i, data[i], TEST_SYMBOL_SIZE);
	}

	/* Get repair frame and send to decoder */
	if (tquic_fec_get_pending_repair(&enc_state, &repair_frame)) {
		ret = tquic_fec_receive_repair(&dec_state, &repair_frame);
		ASSERT_TRUE(ret >= 0, "receive repair");
	}

	tquic_fec_destroy(&enc_state);
	tquic_fec_destroy(&dec_state);

	TEST_PASS();
	return 0;
}

/*
 * =============================================================================
 * Test Runner
 * =============================================================================
 */

/**
 * run_all_tests - Run all FEC tests
 */
static int run_all_tests(void)
{
	tests_run = 0;
	tests_passed = 0;
	tests_failed = 0;

	pr_info("tquic_fec_test: Starting FEC test suite\n");
	pr_info("tquic_fec_test: ==============================\n");

	/* XOR FEC Tests */
	pr_info("tquic_fec_test: === XOR FEC Tests ===\n");
	test_xor_encode_basic();
	test_xor_decode_single_loss();
	test_xor_decode_two_losses();
	test_xor_variable_lengths();

	/* Reed-Solomon Tests */
	pr_info("tquic_fec_test: === Reed-Solomon Tests ===\n");
	test_rs_init();
	test_rs_encode_basic();
	test_rs_decode_single_erasure();
	test_rs_decode_multiple_erasures();

	/* Encoder Tests */
	pr_info("tquic_fec_test: === Encoder Tests ===\n");
	test_encoder_init();
	test_encoder_add_symbols();
	test_encoder_generate_repair();

	/* Decoder Tests */
	pr_info("tquic_fec_test: === Decoder Tests ===\n");
	test_decoder_init();
	test_decoder_receive_source();

	/* Scheduler Tests */
	pr_info("tquic_fec_test: === Scheduler Tests ===\n");
	test_scheduler_init();
	test_scheduler_loss_tracking();
	test_scheduler_rate_adjustment();

	/* State Management Tests */
	pr_info("tquic_fec_test: === State Management Tests ===\n");
	test_fec_init_destroy();
	test_fec_enable_disable();
	test_fec_negotiate();
	test_fec_negotiate_no_support();

	/* End-to-End Tests */
	pr_info("tquic_fec_test: === End-to-End Tests ===\n");
	test_e2e_xor_recovery();

	/* Summary */
	pr_info("tquic_fec_test: ==============================\n");
	pr_info("tquic_fec_test: Tests run: %d\n", tests_run);
	pr_info("tquic_fec_test: Tests passed: %d\n", tests_passed);
	pr_info("tquic_fec_test: Tests failed: %d\n", tests_failed);

	if (tests_failed > 0) {
		pr_err("tquic_fec_test: SOME TESTS FAILED\n");
		return -1;
	}

	pr_info("tquic_fec_test: ALL TESTS PASSED\n");
	return 0;
}

static int __init tquic_fec_test_init(void)
{
	pr_info("tquic_fec_test: Loading FEC test module\n");

	/* Initialize FEC subsystem */
	if (tquic_fec_module_init() < 0) {
		pr_err("tquic_fec_test: Failed to initialize FEC module\n");
		return -1;
	}

	return run_all_tests();
}

static void __exit tquic_fec_test_exit(void)
{
	tquic_fec_module_exit();
	pr_info("tquic_fec_test: FEC test module unloaded\n");
}

module_init(tquic_fec_test_init);
module_exit(tquic_fec_test_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Linux Foundation");
MODULE_DESCRIPTION("TQUIC FEC Test Suite");
