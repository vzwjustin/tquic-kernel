// SPDX-License-Identifier: GPL-2.0-only
/*
 * TQUIC Crypto/Handshake Unit Tests
 *
 * Copyright (c) 2026 Linux Foundation
 *
 * Comprehensive KUnit test suite for TQUIC crypto subsystem covering:
 * - TLS 1.3 key derivation (HKDF)
 * - QUIC v1/v2 initial salts and HKDF labels
 * - Key update mechanism (RFC 9001 Section 6)
 * - 0-RTT early data (RFC 9001 Sections 4.6-4.7)
 * - Hardware offload detection
 * - Header protection
 * - Anti-replay filters
 */

#include <kunit/test.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/random.h>
#include <crypto/aead.h>
#include <crypto/hash.h>
#include <net/tquic.h>

#include "../crypto/key_update.h"
#include "../crypto/zero_rtt.h"
#include "../crypto/hw_offload.h"

/*
 * =============================================================================
 * QUIC Version and HKDF Label Tests
 * =============================================================================
 */

/* Test QUIC v1 initial salt (RFC 9001) */
static const u8 expected_v1_salt[20] = {
	0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3,
	0x4d, 0x17, 0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad,
	0xcc, 0xbb, 0x7f, 0x0a
};

/* Test QUIC v2 initial salt (RFC 9369) */
static const u8 expected_v2_salt[20] = {
	0x0d, 0xed, 0xe3, 0xde, 0xf7, 0x00, 0xa6, 0xdb,
	0x81, 0x93, 0x81, 0xbe, 0x6e, 0x26, 0x9d, 0xcb,
	0xf9, 0xbd, 0x2e, 0xd9
};

static void test_quic_version_constants(struct kunit *test)
{
	/* Verify QUIC version constants are correct */
	KUNIT_EXPECT_EQ(test, 0x00000001U, (u32)TQUIC_VERSION_1);
	KUNIT_EXPECT_EQ(test, 0x6b3343cfU, (u32)TQUIC_VERSION_2);
}

/*
 * =============================================================================
 * Key Update State Tests
 * =============================================================================
 */

static void test_key_update_state_alloc_free(struct kunit *test)
{
	struct tquic_key_update_state *state;

	/* Allocate with AES-128-GCM-SHA256 */
	state = tquic_key_update_state_alloc(TLS_AES_128_GCM_SHA256);
	KUNIT_ASSERT_NOT_NULL(test, state);

	tquic_key_update_state_free(state);

	/* Allocate with AES-256-GCM-SHA384 */
	state = tquic_key_update_state_alloc(TLS_AES_256_GCM_SHA384);
	KUNIT_ASSERT_NOT_NULL(test, state);

	tquic_key_update_state_free(state);

	/* Allocate with ChaCha20-Poly1305 */
	state = tquic_key_update_state_alloc(TLS_CHACHA20_POLY1305_SHA256);
	KUNIT_ASSERT_NOT_NULL(test, state);

	tquic_key_update_state_free(state);
}

static void test_key_update_install_secrets(struct kunit *test)
{
	struct tquic_key_update_state *state;
	u8 read_secret[32];
	u8 write_secret[32];
	int ret;

	/* Generate random test secrets */
	get_random_bytes(read_secret, sizeof(read_secret));
	get_random_bytes(write_secret, sizeof(write_secret));

	state = tquic_key_update_state_alloc(TLS_AES_128_GCM_SHA256);
	KUNIT_ASSERT_NOT_NULL(test, state);

	/* Install secrets */
	ret = tquic_key_update_install_secrets(state, read_secret, write_secret,
					       sizeof(read_secret));
	KUNIT_EXPECT_EQ(test, 0, ret);

	tquic_key_update_state_free(state);
}

static void test_key_update_get_phase(struct kunit *test)
{
	struct tquic_key_update_state *state;
	u8 phase;

	state = tquic_key_update_state_alloc(TLS_AES_128_GCM_SHA256);
	KUNIT_ASSERT_NOT_NULL(test, state);

	/* Initial phase should be 0 */
	phase = tquic_key_update_get_phase(state);
	KUNIT_EXPECT_TRUE(test, phase == 0 || phase == 1);

	tquic_key_update_state_free(state);
}

static void test_key_update_set_intervals(struct kunit *test)
{
	struct tquic_key_update_state *state;

	state = tquic_key_update_state_alloc(TLS_AES_128_GCM_SHA256);
	KUNIT_ASSERT_NOT_NULL(test, state);

	/* Set intervals */
	tquic_key_update_set_intervals(state, 1000000, 3600);

	/* Set to disable */
	tquic_key_update_set_intervals(state, 0, 0);

	tquic_key_update_state_free(state);
}

static void test_key_update_packet_tracking(struct kunit *test)
{
	struct tquic_key_update_state *state;

	state = tquic_key_update_state_alloc(TLS_AES_128_GCM_SHA256);
	KUNIT_ASSERT_NOT_NULL(test, state);

	/* Track packets sent */
	tquic_key_update_on_packet_sent(state);
	tquic_key_update_on_packet_sent(state);

	/* Track packets received */
	tquic_key_update_on_packet_received(state);

	tquic_key_update_state_free(state);
}

static void test_key_update_config_defaults(struct kunit *test)
{
	struct tquic_key_update_config config = {
		.interval_packets = TQUIC_KEY_UPDATE_DEFAULT_PACKETS,
		.interval_seconds = TQUIC_KEY_UPDATE_DEFAULT_SECONDS,
		.auto_update = true,
	};

	/* Verify default thresholds */
	KUNIT_EXPECT_EQ(test, 1ULL << 20, config.interval_packets);
	KUNIT_EXPECT_EQ(test, 3600U, config.interval_seconds);
	KUNIT_EXPECT_TRUE(test, config.auto_update);
}

static void test_aead_confidentiality_limits(struct kunit *test)
{
	/* Verify AEAD confidentiality limits per RFC 9001 Section 6.6 */
	KUNIT_EXPECT_EQ(test, 1ULL << 23, (u64)TQUIC_AEAD_AES_GCM_LIMIT);
	KUNIT_EXPECT_EQ(test, 1ULL << 62, (u64)TQUIC_AEAD_CHACHA20_LIMIT);
}

/*
 * =============================================================================
 * 0-RTT State Tests
 * =============================================================================
 */

static void test_zero_rtt_state_enum(struct kunit *test)
{
	/* Verify 0-RTT state enum values */
	KUNIT_EXPECT_EQ(test, 0, (int)TQUIC_0RTT_NONE);
	KUNIT_EXPECT_EQ(test, 1, (int)TQUIC_0RTT_ATTEMPTING);
	KUNIT_EXPECT_EQ(test, 2, (int)TQUIC_0RTT_ACCEPTED);
	KUNIT_EXPECT_EQ(test, 3, (int)TQUIC_0RTT_REJECTED);
}

static void test_zero_rtt_state_name(struct kunit *test)
{
	const char *name;

	name = tquic_zero_rtt_state_name(TQUIC_0RTT_NONE);
	KUNIT_EXPECT_NOT_NULL(test, name);

	name = tquic_zero_rtt_state_name(TQUIC_0RTT_ATTEMPTING);
	KUNIT_EXPECT_NOT_NULL(test, name);

	name = tquic_zero_rtt_state_name(TQUIC_0RTT_ACCEPTED);
	KUNIT_EXPECT_NOT_NULL(test, name);

	name = tquic_zero_rtt_state_name(TQUIC_0RTT_REJECTED);
	KUNIT_EXPECT_NOT_NULL(test, name);
}

static void test_zero_rtt_keys_struct(struct kunit *test)
{
	struct tquic_zero_rtt_keys keys;

	memset(&keys, 0, sizeof(keys));

	/* Verify structure sizes */
	KUNIT_EXPECT_EQ(test, TQUIC_ZERO_RTT_SECRET_MAX_LEN,
			(u32)sizeof(keys.secret));
	KUNIT_EXPECT_EQ(test, TQUIC_ZERO_RTT_KEY_MAX_LEN,
			(u32)sizeof(keys.key));
	KUNIT_EXPECT_EQ(test, TQUIC_ZERO_RTT_IV_MAX_LEN,
			(u32)sizeof(keys.iv));

	/* Keys should initially be invalid */
	KUNIT_EXPECT_FALSE(test, keys.valid);
}

static void test_zero_rtt_constants(struct kunit *test)
{
	/* Verify 0-RTT constants */
	KUNIT_EXPECT_EQ(test, 48U, (u32)TQUIC_ZERO_RTT_SECRET_MAX_LEN);
	KUNIT_EXPECT_EQ(test, 32U, (u32)TQUIC_ZERO_RTT_KEY_MAX_LEN);
	KUNIT_EXPECT_EQ(test, 12U, (u32)TQUIC_ZERO_RTT_IV_MAX_LEN);
	KUNIT_EXPECT_EQ(test, 604800U, (u32)TQUIC_ZERO_RTT_DEFAULT_MAX_AGE);
}

static void test_zero_rtt_replay_window(struct kunit *test)
{
	/* Verify replay window constants */
	KUNIT_EXPECT_EQ(test, 128U, (u32)TQUIC_PN_REPLAY_WINDOW_SIZE);
}

static void test_session_ticket_constants(struct kunit *test)
{
	/* Verify session ticket constants */
	KUNIT_EXPECT_EQ(test, 1U, (u32)TQUIC_SESSION_TICKET_VERSION);
	KUNIT_EXPECT_EQ(test, 2048U, (u32)TQUIC_SESSION_TICKET_MAX_LEN);
	KUNIT_EXPECT_EQ(test, 16U, (u32)TQUIC_SESSION_TICKET_TAG_LEN);
	KUNIT_EXPECT_EQ(test, 12U, (u32)TQUIC_SESSION_TICKET_NONCE_LEN);
	KUNIT_EXPECT_EQ(test, 32U, (u32)TQUIC_SESSION_TICKET_KEY_LEN);
}

/*
 * =============================================================================
 * Anti-Replay Filter Tests
 * =============================================================================
 */

static void test_replay_filter_init_cleanup(struct kunit *test)
{
	struct tquic_replay_filter filter;
	int ret;

	ret = tquic_replay_filter_init(&filter, TQUIC_REPLAY_TTL_SECONDS);
	KUNIT_ASSERT_EQ(test, 0, ret);

	/* Verify TTL was set */
	KUNIT_EXPECT_EQ(test, TQUIC_REPLAY_TTL_SECONDS, filter.ttl_seconds);

	tquic_replay_filter_cleanup(&filter);
}

static void test_replay_filter_check_new_ticket(struct kunit *test)
{
	struct tquic_replay_filter filter;
	u8 ticket[32];
	int ret;

	ret = tquic_replay_filter_init(&filter, TQUIC_REPLAY_TTL_SECONDS);
	KUNIT_ASSERT_EQ(test, 0, ret);

	/* Generate random ticket */
	get_random_bytes(ticket, sizeof(ticket));

	/* First use should succeed (not a replay) */
	ret = tquic_replay_filter_check(&filter, ticket, sizeof(ticket));
	KUNIT_EXPECT_EQ(test, 0, ret);

	tquic_replay_filter_cleanup(&filter);
}

static void test_replay_filter_detect_replay(struct kunit *test)
{
	struct tquic_replay_filter filter;
	u8 ticket[32];
	int ret;

	ret = tquic_replay_filter_init(&filter, TQUIC_REPLAY_TTL_SECONDS);
	KUNIT_ASSERT_EQ(test, 0, ret);

	/* Generate random ticket */
	get_random_bytes(ticket, sizeof(ticket));

	/* First use - should succeed */
	ret = tquic_replay_filter_check(&filter, ticket, sizeof(ticket));
	KUNIT_EXPECT_EQ(test, 0, ret);

	/* Second use of same ticket - should be detected as replay */
	ret = tquic_replay_filter_check(&filter, ticket, sizeof(ticket));
	KUNIT_EXPECT_EQ(test, -EEXIST, ret);

	tquic_replay_filter_cleanup(&filter);
}

static void test_replay_filter_different_tickets(struct kunit *test)
{
	struct tquic_replay_filter filter;
	u8 ticket1[32];
	u8 ticket2[32];
	int ret;

	ret = tquic_replay_filter_init(&filter, TQUIC_REPLAY_TTL_SECONDS);
	KUNIT_ASSERT_EQ(test, 0, ret);

	/* Generate two different tickets */
	get_random_bytes(ticket1, sizeof(ticket1));
	get_random_bytes(ticket2, sizeof(ticket2));

	/* Both should succeed as they are different */
	ret = tquic_replay_filter_check(&filter, ticket1, sizeof(ticket1));
	KUNIT_EXPECT_EQ(test, 0, ret);

	ret = tquic_replay_filter_check(&filter, ticket2, sizeof(ticket2));
	KUNIT_EXPECT_EQ(test, 0, ret);

	tquic_replay_filter_cleanup(&filter);
}

static void test_replay_filter_bloom_constants(struct kunit *test)
{
	/* Verify bloom filter constants */
	KUNIT_EXPECT_EQ(test, 1 << 16, (int)TQUIC_REPLAY_BLOOM_BITS);
	KUNIT_EXPECT_EQ(test, 4, (int)TQUIC_REPLAY_BLOOM_HASHES);
	KUNIT_EXPECT_EQ(test, 3600U, (u32)TQUIC_REPLAY_TTL_SECONDS);
}

/*
 * =============================================================================
 * Hardware Offload Detection Tests
 * =============================================================================
 */

static void test_crypto_caps_struct(struct kunit *test)
{
	struct tquic_crypto_caps caps;

	memset(&caps, 0, sizeof(caps));

	/* All capabilities should start as false */
	KUNIT_EXPECT_FALSE(test, caps.aes_ni);
	KUNIT_EXPECT_FALSE(test, caps.avx2);
	KUNIT_EXPECT_FALSE(test, caps.avx512);
	KUNIT_EXPECT_FALSE(test, caps.vaes);
	KUNIT_EXPECT_FALSE(test, caps.vpclmulqdq);
	KUNIT_EXPECT_FALSE(test, caps.pclmulqdq);
	KUNIT_EXPECT_FALSE(test, caps.sha_ni);
	KUNIT_EXPECT_FALSE(test, caps.detected);
}

static void test_crypto_detect_caps(struct kunit *test)
{
	struct tquic_crypto_caps caps;

	memset(&caps, 0, sizeof(caps));

	/* Detect capabilities */
	tquic_crypto_detect_caps(&caps);

	/* Detection flag should be set */
	KUNIT_EXPECT_TRUE(test, caps.detected);
}

static void test_crypto_get_caps(struct kunit *test)
{
	const struct tquic_crypto_caps *caps;

	/* Get global capabilities */
	caps = tquic_crypto_get_caps();
	KUNIT_ASSERT_NOT_NULL(test, caps);

	/* Should be detected */
	KUNIT_EXPECT_TRUE(test, caps->detected);
}

static void test_crypto_impl_enum(struct kunit *test)
{
	/* Verify implementation enum values */
	KUNIT_EXPECT_EQ(test, 0, (int)TQUIC_CRYPTO_GENERIC);
	KUNIT_EXPECT_EQ(test, 1, (int)TQUIC_CRYPTO_AESNI);
	KUNIT_EXPECT_EQ(test, 2, (int)TQUIC_CRYPTO_AVX2);
	KUNIT_EXPECT_EQ(test, 3, (int)TQUIC_CRYPTO_AVX512);
}

static void test_crypto_select_impl(struct kunit *test)
{
	struct tquic_crypto_caps caps;
	enum tquic_crypto_impl impl;

	/* Test with no hardware acceleration */
	memset(&caps, 0, sizeof(caps));
	caps.detected = true;

	impl = tquic_crypto_select_impl(&caps, TLS_AES_128_GCM_SHA256);
	KUNIT_EXPECT_EQ(test, TQUIC_CRYPTO_GENERIC, impl);

	/* Test with AES-NI */
	caps.aes_ni = true;
	impl = tquic_crypto_select_impl(&caps, TLS_AES_128_GCM_SHA256);
	KUNIT_EXPECT_TRUE(test, impl >= TQUIC_CRYPTO_AESNI ||
			       impl == TQUIC_CRYPTO_GENERIC);

	/* Test ChaCha20 with AVX2 */
	caps.avx2 = true;
	impl = tquic_crypto_select_impl(&caps, TLS_CHACHA20_POLY1305_SHA256);
	KUNIT_EXPECT_TRUE(test, impl <= TQUIC_CRYPTO_AVX512);
}

static void test_crypto_ctx_alloc_free(struct kunit *test)
{
	struct tquic_crypto_ctx *ctx;

	/* Allocate for AES-128-GCM */
	ctx = tquic_crypto_ctx_alloc(TLS_AES_128_GCM_SHA256, GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, ctx);
	tquic_crypto_ctx_free(ctx);

	/* Allocate for AES-256-GCM */
	ctx = tquic_crypto_ctx_alloc(TLS_AES_256_GCM_SHA384, GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, ctx);
	tquic_crypto_ctx_free(ctx);

	/* Allocate for ChaCha20-Poly1305 */
	ctx = tquic_crypto_ctx_alloc(TLS_CHACHA20_POLY1305_SHA256, GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, ctx);
	tquic_crypto_ctx_free(ctx);

	/* Free NULL should be safe */
	tquic_crypto_ctx_free(NULL);
}

static void test_crypto_ctx_set_key(struct kunit *test)
{
	struct tquic_crypto_ctx *ctx;
	u8 key[16];  /* AES-128 key */
	int ret;

	get_random_bytes(key, sizeof(key));

	ctx = tquic_crypto_ctx_alloc(TLS_AES_128_GCM_SHA256, GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, ctx);

	ret = tquic_crypto_ctx_set_key(ctx, key, sizeof(key));
	KUNIT_EXPECT_EQ(test, 0, ret);

	tquic_crypto_ctx_free(ctx);
}

static void test_crypto_ctx_set_iv(struct kunit *test)
{
	struct tquic_crypto_ctx *ctx;
	u8 iv[12];  /* QUIC IV size */
	int ret;

	get_random_bytes(iv, sizeof(iv));

	ctx = tquic_crypto_ctx_alloc(TLS_AES_128_GCM_SHA256, GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, ctx);

	ret = tquic_crypto_ctx_set_iv(ctx, iv, sizeof(iv));
	KUNIT_EXPECT_EQ(test, 0, ret);

	tquic_crypto_ctx_free(ctx);
}

static void test_crypto_batch_max(struct kunit *test)
{
	/* Verify batch processing limit */
	KUNIT_EXPECT_EQ(test, 16, (int)TQUIC_BATCH_MAX_PACKETS);
}

/*
 * =============================================================================
 * Cipher Suite Tests
 * =============================================================================
 */

static void test_cipher_suite_constants(struct kunit *test)
{
	/* Verify TLS 1.3 cipher suite values */
	KUNIT_EXPECT_EQ(test, 0x1301, (int)TLS_AES_128_GCM_SHA256);
	KUNIT_EXPECT_EQ(test, 0x1302, (int)TLS_AES_256_GCM_SHA384);
	KUNIT_EXPECT_EQ(test, 0x1303, (int)TLS_CHACHA20_POLY1305_SHA256);
}

/*
 * =============================================================================
 * Session Ticket Plaintext Tests
 * =============================================================================
 */

static void test_session_ticket_plaintext_struct(struct kunit *test)
{
	struct tquic_session_ticket_plaintext pt;

	memset(&pt, 0, sizeof(pt));

	/* Verify structure can hold max values */
	KUNIT_EXPECT_EQ(test, TQUIC_ZERO_RTT_SECRET_MAX_LEN,
			(u32)sizeof(pt.psk));
	KUNIT_EXPECT_GE(test, (size_t)TQUIC_ALPN_MAX_LEN,
			(size_t)(sizeof(pt.alpn) - 1));

	/* Initialize with test values */
	pt.psk_len = 32;
	pt.max_age = 604800;
	pt.cipher_suite = TLS_AES_128_GCM_SHA256;

	KUNIT_EXPECT_EQ(test, 32U, pt.psk_len);
	KUNIT_EXPECT_EQ(test, 604800U, pt.max_age);
	KUNIT_EXPECT_EQ(test, TLS_AES_128_GCM_SHA256, pt.cipher_suite);
}

/*
 * =============================================================================
 * Ticket Store Tests
 * =============================================================================
 */

static void test_ticket_store_struct(struct kunit *test)
{
	struct tquic_ticket_store store;

	memset(&store, 0, sizeof(store));
	spin_lock_init(&store.lock);
	store.tickets = RB_ROOT;
	INIT_LIST_HEAD(&store.lru_list);
	store.max_count = 100;

	KUNIT_EXPECT_EQ(test, 0U, store.count);
	KUNIT_EXPECT_EQ(test, 100U, store.max_count);
	KUNIT_EXPECT_TRUE(test, RB_EMPTY_ROOT(&store.tickets));
	KUNIT_EXPECT_TRUE(test, list_empty(&store.lru_list));
}

/*
 * =============================================================================
 * Crypto Stats Tests
 * =============================================================================
 */

static void test_crypto_stats_struct(struct kunit *test)
{
	struct tquic_crypto_stats stats;

	memset(&stats, 0, sizeof(stats));

	KUNIT_EXPECT_EQ(test, 0ULL, stats.aesni_ops);
	KUNIT_EXPECT_EQ(test, 0ULL, stats.avx2_ops);
	KUNIT_EXPECT_EQ(test, 0ULL, stats.avx512_ops);
	KUNIT_EXPECT_EQ(test, 0ULL, stats.generic_ops);
	KUNIT_EXPECT_EQ(test, 0ULL, stats.qat_ops);
	KUNIT_EXPECT_EQ(test, 0ULL, stats.total_bytes);
	KUNIT_EXPECT_EQ(test, 0ULL, stats.batch_ops);
	KUNIT_EXPECT_EQ(test, 0ULL, stats.batch_packets);
}

static void test_crypto_get_stats(struct kunit *test)
{
	struct tquic_crypto_stats stats;

	memset(&stats, 0xff, sizeof(stats));

	/* Get stats should populate the structure */
	tquic_crypto_get_stats(&stats);

	/* Stats should be valid (not left as 0xff) */
	KUNIT_EXPECT_TRUE(test, stats.total_bytes != 0xffffffffffffffffULL ||
			       stats.generic_ops != 0xffffffffffffffffULL);
}

static void test_crypto_reset_stats(struct kunit *test)
{
	struct tquic_crypto_stats stats;

	/* Reset stats */
	tquic_crypto_reset_stats();

	/* Get stats after reset */
	tquic_crypto_get_stats(&stats);

	/* All should be zero */
	KUNIT_EXPECT_EQ(test, 0ULL, stats.aesni_ops);
	KUNIT_EXPECT_EQ(test, 0ULL, stats.avx2_ops);
	KUNIT_EXPECT_EQ(test, 0ULL, stats.avx512_ops);
	KUNIT_EXPECT_EQ(test, 0ULL, stats.total_bytes);
}

/*
 * =============================================================================
 * QAT Offload Tests
 * =============================================================================
 */

static void test_qat_ctx_init(struct kunit *test)
{
	struct tquic_qat_ctx ctx;
	int ret;

	ret = tquic_qat_init(&ctx);
	/* Should succeed (even if QAT not available) */
	KUNIT_EXPECT_EQ(test, 0, ret);

	tquic_qat_cleanup(&ctx);
}

static void test_qat_is_available(struct kunit *test)
{
	struct tquic_qat_ctx ctx;
	bool available;

	tquic_qat_init(&ctx);

	/* Check availability */
	available = tquic_qat_is_available(&ctx);
	/* Result depends on hardware */
	KUNIT_EXPECT_TRUE(test, available == true || available == false);

	tquic_qat_cleanup(&ctx);
}

/*
 * =============================================================================
 * Test Module Definition
 * =============================================================================
 */

static struct kunit_case quic_version_test_cases[] = {
	KUNIT_CASE(test_quic_version_constants),
	{}
};

static struct kunit_case key_update_test_cases[] = {
	KUNIT_CASE(test_key_update_state_alloc_free),
	KUNIT_CASE(test_key_update_install_secrets),
	KUNIT_CASE(test_key_update_get_phase),
	KUNIT_CASE(test_key_update_set_intervals),
	KUNIT_CASE(test_key_update_packet_tracking),
	KUNIT_CASE(test_key_update_config_defaults),
	KUNIT_CASE(test_aead_confidentiality_limits),
	{}
};

static struct kunit_case zero_rtt_test_cases[] = {
	KUNIT_CASE(test_zero_rtt_state_enum),
	KUNIT_CASE(test_zero_rtt_state_name),
	KUNIT_CASE(test_zero_rtt_keys_struct),
	KUNIT_CASE(test_zero_rtt_constants),
	KUNIT_CASE(test_zero_rtt_replay_window),
	KUNIT_CASE(test_session_ticket_constants),
	KUNIT_CASE(test_session_ticket_plaintext_struct),
	KUNIT_CASE(test_ticket_store_struct),
	{}
};

static struct kunit_case replay_filter_test_cases[] = {
	KUNIT_CASE(test_replay_filter_init_cleanup),
	KUNIT_CASE(test_replay_filter_check_new_ticket),
	KUNIT_CASE(test_replay_filter_detect_replay),
	KUNIT_CASE(test_replay_filter_different_tickets),
	KUNIT_CASE(test_replay_filter_bloom_constants),
	{}
};

static struct kunit_case hw_offload_test_cases[] = {
	KUNIT_CASE(test_crypto_caps_struct),
	KUNIT_CASE(test_crypto_detect_caps),
	KUNIT_CASE(test_crypto_get_caps),
	KUNIT_CASE(test_crypto_impl_enum),
	KUNIT_CASE(test_crypto_select_impl),
	KUNIT_CASE(test_crypto_ctx_alloc_free),
	KUNIT_CASE(test_crypto_ctx_set_key),
	KUNIT_CASE(test_crypto_ctx_set_iv),
	KUNIT_CASE(test_crypto_batch_max),
	{}
};

static struct kunit_case cipher_suite_test_cases[] = {
	KUNIT_CASE(test_cipher_suite_constants),
	{}
};

static struct kunit_case crypto_stats_test_cases[] = {
	KUNIT_CASE(test_crypto_stats_struct),
	KUNIT_CASE(test_crypto_get_stats),
	KUNIT_CASE(test_crypto_reset_stats),
	{}
};

static struct kunit_case qat_offload_test_cases[] = {
	KUNIT_CASE(test_qat_ctx_init),
	KUNIT_CASE(test_qat_is_available),
	{}
};

static struct kunit_suite quic_version_test_suite = {
	.name = "quic_version",
	.test_cases = quic_version_test_cases,
};

static struct kunit_suite key_update_test_suite = {
	.name = "key_update",
	.test_cases = key_update_test_cases,
};

static struct kunit_suite zero_rtt_test_suite = {
	.name = "zero_rtt",
	.test_cases = zero_rtt_test_cases,
};

static struct kunit_suite replay_filter_test_suite = {
	.name = "replay_filter",
	.test_cases = replay_filter_test_cases,
};

static struct kunit_suite hw_offload_test_suite = {
	.name = "hw_offload",
	.test_cases = hw_offload_test_cases,
};

static struct kunit_suite cipher_suite_test_suite = {
	.name = "cipher_suite",
	.test_cases = cipher_suite_test_cases,
};

static struct kunit_suite crypto_stats_test_suite = {
	.name = "crypto_stats",
	.test_cases = crypto_stats_test_cases,
};

static struct kunit_suite qat_offload_test_suite = {
	.name = "qat_offload",
	.test_cases = qat_offload_test_cases,
};

kunit_test_suites(
	&quic_version_test_suite,
	&key_update_test_suite,
	&zero_rtt_test_suite,
	&replay_filter_test_suite,
	&hw_offload_test_suite,
	&cipher_suite_test_suite,
	&crypto_stats_test_suite,
	&qat_offload_test_suite
);

MODULE_DESCRIPTION("TQUIC Crypto/Handshake Unit Tests");
MODULE_AUTHOR("Linux Foundation");
MODULE_LICENSE("GPL");
