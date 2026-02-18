// SPDX-License-Identifier: GPL-2.0-only
/*
 * TQUIC KUnit Tests for Path Management (quic_path.c)
 *
 * Copyright (c) 2026 Justin Adams <spotty118@gmail.com>
 * Kernel implementation by Justin Adams <spotty118@gmail.com>
 *
 * Tests the path management subsystem defined in net/tquic/core/quic_path.c,
 * covering:
 *
 *   - tquic_path_migrate()     RFC 9000 Section 9 — migration semantics,
 *                               active-path no-op guard, state transitions,
 *                               RCU pointer update, bond notification
 *   - tquic_path_mtu_probe()   Probe packet queued at correct size
 *   - tquic_path_mtu_probe_acked() MTU updated on acknowledgment
 *   - tquic_path_on_validated() PENDING -> VALIDATED state transition
 *   - tquic_path_verify_response() Challenge/response matching
 *   - tquic_path_can_send()    Anti-amplification limits
 *   - tquic_path_rtt_update()  RTT measurement (RFC 9002 Section 5)
 *   - tquic_path_pto()         PTO calculation (RFC 9002 Section 6.2)
 *   - tquic_path_needs_probe() Probe-needed predicate
 *   - tquic_path_get_info()    Stats export
 *
 * Design notes
 * ------------
 * quic_path.c calls into several external subsystems (workqueue, sk_buff
 * allocation, netlink, PMTUD, bonding, CID rotation, timer setup).  Those
 * entry points are exercised via stub structures — the tests build minimal
 * tquic_path and tquic_connection objects on the stack or from kzalloc,
 * directly manipulating the state fields that the functions under test read
 * and write, rather than driving the full kernel networking stack.
 *
 * Functions that unconditionally call into subsystems with heavy side-effects
 * (tquic_path_challenge, tquic_path_migrate, tquic_path_on_validated,
 * tquic_path_mtu_probe) are tested for the state transitions they commit
 * before the first external call; the external calls themselves are allowed
 * to fail gracefully (alloc_skb may return NULL in a KUnit environment, and
 * functions guard against that with -ENOMEM returns which we accept).
 *
 * For tquic_path_migrate the test manipulates path->state and conn->active_path
 * directly so that the no-op guard (old_path == path) or the full migration
 * branch can be exercised.
 */

#include <kunit/test.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/skbuff.h>
#include <linux/workqueue.h>
#include <linux/timer.h>
#include <linux/refcount.h>
#include <linux/atomic.h>
#include <net/tquic.h>

/* =========================================================================
 * Minimal fixture helpers
 *
 * We cannot call tquic_path_create_internal (it uses tquic_path_cache,
 * which requires the full module init sequence) and cannot call
 * tquic_path_destroy (which calls back into the kmem_cache).  Instead we
 * allocate plain kzalloc objects and initialise only the fields that the
 * functions under test actually touch.
 * ========================================================================= */

/*
 * tquic_path_fixture_alloc - allocate and minimally initialise a path struct.
 *
 * The caller must call kfree() when done.  Do NOT call tquic_path_destroy()
 * on the result because it uses the slab cache and frees the response skb
 * queue — neither of which is set up by this helper.
 */
static struct tquic_path *tquic_path_fixture_alloc(struct kunit *test)
{
	struct tquic_path *path;

	path = kunit_kzalloc(test, sizeof(*path), GFP_KERNEL);
	if (!path)
		return NULL;

	refcount_set(&path->refcnt, 1);
	spin_lock_init(&path->loss_tracker.lock);
	INIT_LIST_HEAD(&path->list);
	INIT_LIST_HEAD(&path->pm_list);
	skb_queue_head_init(&path->response.queue);
	atomic_set(&path->response.count, 0);
	atomic64_set(&path->anti_amplification.bytes_received, 0);
	atomic64_set(&path->anti_amplification.bytes_sent, 0);

	/* Safe minimum initial MTU per RFC 9000 Section 14 */
	path->mtu = 1200;
	path->state = TQUIC_PATH_UNUSED;
	path->saved_state = TQUIC_PATH_UNUSED;
	path->cc.min_rtt_us = U64_MAX;
	path->cc.smoothed_rtt_us = 100000; /* 100 ms */
	path->cc.rtt_var_us = 50000;       /* 50 ms */

	return path;
}

/*
 * tquic_conn_fixture_alloc - allocate and minimally initialise a connection.
 *
 * Only the fields exercised by the path management API are initialised.
 */
static struct tquic_connection *tquic_conn_fixture_alloc(struct kunit *test)
{
	struct tquic_connection *conn;

	conn = kunit_kzalloc(test, sizeof(*conn), GFP_KERNEL);
	if (!conn)
		return NULL;

	spin_lock_init(&conn->lock);
	spin_lock_init(&conn->paths_lock);
	INIT_LIST_HEAD(&conn->paths);
	INIT_WORK(&conn->tx_work, NULL); /* NULL handler — never scheduled */
	skb_queue_head_init(&conn->control_frames);
	refcount_set(&conn->refcnt, 1);

	conn->migration_disabled = false;
	conn->sk = NULL;
	conn->active_path = NULL;

	return conn;
}

/* =========================================================================
 * tquic_path_migrate() tests
 * ========================================================================= */

/*
 * Test: migrate_null_args
 * Purpose: NULL conn or path returns -EINVAL immediately.
 * RFC Reference: RFC 9000 Section 9 (defensive coding requirement)
 * Setup: No objects needed.
 * Expected: -EINVAL on NULL inputs.
 */
static void test_path_migrate_null_args(struct kunit *test)
{
	struct tquic_path *path;
	struct tquic_connection *conn;
	int ret;

	path = tquic_path_fixture_alloc(test);
	KUNIT_ASSERT_NOT_NULL(test, path);

	conn = tquic_conn_fixture_alloc(test);
	KUNIT_ASSERT_NOT_NULL(test, conn);

	ret = tquic_path_migrate(NULL, path);
	KUNIT_EXPECT_EQ(test, ret, -EINVAL);

	ret = tquic_path_migrate(conn, NULL);
	KUNIT_EXPECT_EQ(test, ret, -EINVAL);

	ret = tquic_path_migrate(NULL, NULL);
	KUNIT_EXPECT_EQ(test, ret, -EINVAL);
}

/*
 * Test: migrate_already_active_is_noop
 * Purpose: Migrating to the path that is already conn->active_path returns 0
 *          without altering state (RFC 9000 Section 9 — idempotent migration).
 * RFC Reference: RFC 9000 Section 9
 * Setup: path state = ACTIVE; conn->active_path = path.
 * Expected: return 0, path->state unchanged.
 */
static void test_path_migrate_already_active_is_noop(struct kunit *test)
{
	struct tquic_connection *conn;
	struct tquic_path *path;
	int ret;

	conn = tquic_conn_fixture_alloc(test);
	KUNIT_ASSERT_NOT_NULL(test, conn);

	path = tquic_path_fixture_alloc(test);
	KUNIT_ASSERT_NOT_NULL(test, path);

	path->state = TQUIC_PATH_ACTIVE;
	path->conn = conn;

	/*
	 * Set active_path directly.  We hold conn->lock implicitly by being
	 * the only actor here — use rcu_assign_pointer to satisfy the RCU
	 * invariant even in a test context.
	 */
	rcu_assign_pointer(conn->active_path, path);

	ret = tquic_path_migrate(conn, path);

	KUNIT_EXPECT_EQ(test, ret, 0);
	/* State must not have changed */
	KUNIT_EXPECT_EQ(test, (int)path->state, (int)TQUIC_PATH_ACTIVE);
	/* active_path must still point to the same path */
	KUNIT_EXPECT_PTR_EQ(test, rcu_dereference_raw(conn->active_path), path);
}

/*
 * Test: migrate_migration_disabled_returns_eperm
 * Purpose: When migration_disabled is set, tquic_path_migrate returns -EPERM.
 * RFC Reference: RFC 9000 Section 9 disable_active_migration transport param.
 * Setup: conn->migration_disabled = true; path state = VALIDATED.
 * Expected: -EPERM returned, active_path unchanged.
 */
static void test_path_migrate_disabled_returns_eperm(struct kunit *test)
{
	struct tquic_connection *conn;
	struct tquic_path *path;
	int ret;

	conn = tquic_conn_fixture_alloc(test);
	KUNIT_ASSERT_NOT_NULL(test, conn);

	path = tquic_path_fixture_alloc(test);
	KUNIT_ASSERT_NOT_NULL(test, path);

	path->state = TQUIC_PATH_VALIDATED;
	path->conn = conn;
	conn->migration_disabled = true;

	ret = tquic_path_migrate(conn, path);

	KUNIT_EXPECT_EQ(test, ret, -EPERM);
}

/*
 * Test: migrate_unvalidated_path_returns_einval
 * Purpose: A path in PENDING state is not eligible for migration.
 * RFC Reference: RFC 9000 Section 9 — must be validated before migrating.
 * Setup: path->state = PENDING; migration_disabled = false.
 * Expected: -EINVAL.
 */
static void test_path_migrate_unvalidated_returns_einval(struct kunit *test)
{
	struct tquic_connection *conn;
	struct tquic_path *path;
	int ret;

	conn = tquic_conn_fixture_alloc(test);
	KUNIT_ASSERT_NOT_NULL(test, conn);

	path = tquic_path_fixture_alloc(test);
	KUNIT_ASSERT_NOT_NULL(test, path);

	path->state = TQUIC_PATH_PENDING;
	path->conn = conn;

	ret = tquic_path_migrate(conn, path);

	KUNIT_EXPECT_EQ(test, ret, -EINVAL);
}

/*
 * Test: migrate_validated_path_succeeds_and_sets_active
 * Purpose: Migrating to a VALIDATED path sets path->state to ACTIVE and
 *          updates conn->active_path via RCU.
 * RFC Reference: RFC 9000 Section 9
 * Setup: new_path->state = VALIDATED; old_path->state = ACTIVE and is
 *        current active_path.
 * Expected: return 0 (or -ENOMEM from alloc_skb in netlink path, which is
 *           acceptable in test harness), path->state == ACTIVE,
 *           conn->active_path == new_path, old_path->state == STANDBY.
 */
static void test_path_migrate_validated_succeeds(struct kunit *test)
{
	struct tquic_connection *conn;
	struct tquic_path *old_path, *new_path;
	struct sockaddr_in addr4;
	int ret;

	conn = tquic_conn_fixture_alloc(test);
	KUNIT_ASSERT_NOT_NULL(test, conn);

	old_path = tquic_path_fixture_alloc(test);
	KUNIT_ASSERT_NOT_NULL(test, old_path);

	new_path = tquic_path_fixture_alloc(test);
	KUNIT_ASSERT_NOT_NULL(test, new_path);

	old_path->conn = conn;
	new_path->conn = conn;

	old_path->state = TQUIC_PATH_ACTIVE;
	new_path->state = TQUIC_PATH_VALIDATED;
	new_path->mtu = 1200;

	/* Place old_path in the paths list so list operations are safe */
	spin_lock_bh(&conn->paths_lock);
	list_add_tail(&old_path->list, &conn->paths);
	list_add_tail(&new_path->list, &conn->paths);
	conn->num_paths = 2;
	spin_unlock_bh(&conn->paths_lock);

	rcu_assign_pointer(conn->active_path, old_path);

	/*
	 * tquic_path_migrate calls tquic_nl_path_event, tquic_bond_path_recovered,
	 * and possibly tquic_cid_rotate — these may return errors or be no-ops
	 * if their internal state is not initialised.  We accept any non-fatal
	 * return value and check only the state transitions that happen before
	 * those calls.
	 *
	 * The function returns 0 on success.  If a downstream side-effect
	 * allocation fails (e.g. sk_buff in netlink), the function may still
	 * return 0 because those paths are best-effort.
	 */
	ret = tquic_path_migrate(conn, new_path);

	/*
	 * The migration state transitions occur under conn->lock before any
	 * external call, so regardless of what the netlink/bonding layers do,
	 * the post-lock invariants must hold.
	 */
	KUNIT_EXPECT_EQ(test, ret, 0);
	KUNIT_EXPECT_EQ(test, (int)new_path->state, (int)TQUIC_PATH_ACTIVE);
	KUNIT_EXPECT_EQ(test, (int)old_path->state, (int)TQUIC_PATH_STANDBY);
	KUNIT_EXPECT_PTR_EQ(test,
			    rcu_dereference_raw(conn->active_path),
			    new_path);

	/* Migration counter must have been incremented */
	KUNIT_EXPECT_GE(test, (int)conn->stats.path_migrations, 1);
}

/*
 * Test: migrate_from_null_active_path
 * Purpose: When conn->active_path is NULL (no prior active path), migration
 *          to a VALIDATED path still succeeds and sets active_path.
 * RFC Reference: RFC 9000 Section 9
 * Setup: conn->active_path = NULL; new_path->state = VALIDATED.
 * Expected: return 0, new_path->state == ACTIVE.
 */
static void test_path_migrate_from_null_active_path(struct kunit *test)
{
	struct tquic_connection *conn;
	struct tquic_path *new_path;
	int ret;

	conn = tquic_conn_fixture_alloc(test);
	KUNIT_ASSERT_NOT_NULL(test, conn);

	new_path = tquic_path_fixture_alloc(test);
	KUNIT_ASSERT_NOT_NULL(test, new_path);

	new_path->conn = conn;
	new_path->state = TQUIC_PATH_VALIDATED;
	new_path->mtu = 1200;

	spin_lock_bh(&conn->paths_lock);
	list_add_tail(&new_path->list, &conn->paths);
	conn->num_paths = 1;
	spin_unlock_bh(&conn->paths_lock);

	/* Explicitly ensure no active path */
	rcu_assign_pointer(conn->active_path, NULL);

	ret = tquic_path_migrate(conn, new_path);

	KUNIT_EXPECT_EQ(test, ret, 0);
	KUNIT_EXPECT_EQ(test, (int)new_path->state, (int)TQUIC_PATH_ACTIVE);
	KUNIT_EXPECT_PTR_EQ(test,
			    rcu_dereference_raw(conn->active_path),
			    new_path);
}

/* =========================================================================
 * tquic_path_mtu_probe() tests
 * ========================================================================= */

/*
 * Test: mtu_probe_null_path_returns_einval
 * Purpose: NULL path is rejected.
 * RFC Reference: RFC 8899 (DPLPMTUD)
 * Setup: none
 * Expected: -EINVAL
 */
static void test_mtu_probe_null_path_returns_einval(struct kunit *test)
{
	int ret = tquic_path_mtu_probe(NULL);

	KUNIT_EXPECT_EQ(test, ret, -EINVAL);
}

/*
 * Test: mtu_probe_null_conn_returns_einval
 * Purpose: A path without a parent connection is rejected.
 * RFC Reference: RFC 8899 (DPLPMTUD)
 * Setup: path->conn = NULL
 * Expected: -EINVAL
 */
static void test_mtu_probe_null_conn_returns_einval(struct kunit *test)
{
	struct tquic_path *path;
	int ret;

	path = tquic_path_fixture_alloc(test);
	KUNIT_ASSERT_NOT_NULL(test, path);

	path->conn = NULL;

	ret = tquic_path_mtu_probe(path);
	KUNIT_EXPECT_EQ(test, ret, -EINVAL);
}

/*
 * Test: mtu_probe_at_maximum_mtu_is_noop
 * Purpose: When path->mtu is already at or above the last probe size (9000),
 *          tquic_path_next_mtu_probe returns current_mtu and the function
 *          returns 0 without queuing a packet.
 * RFC Reference: RFC 8899 Section 5.2
 * Setup: path->mtu = 9000 (maximum in tquic_mtu_probes[])
 * Expected: return 0, control_frames queue length unchanged.
 */
static void test_mtu_probe_at_maximum_is_noop(struct kunit *test)
{
	struct tquic_connection *conn;
	struct tquic_path *path;
	int ret;
	int queue_len_before;

	conn = tquic_conn_fixture_alloc(test);
	KUNIT_ASSERT_NOT_NULL(test, conn);

	path = tquic_path_fixture_alloc(test);
	KUNIT_ASSERT_NOT_NULL(test, path);

	path->conn = conn;
	/*
	 * 9000 is the last entry in tquic_mtu_probes[].
	 * tquic_path_next_mtu_probe(9000) returns 9000 (no larger size found),
	 * so probe_size <= path->mtu and the function returns 0 immediately.
	 */
	path->mtu = 9000;

	queue_len_before = skb_queue_len(&conn->control_frames);
	ret = tquic_path_mtu_probe(path);

	KUNIT_EXPECT_EQ(test, ret, 0);
	/* No probe packet should have been queued */
	KUNIT_EXPECT_EQ(test, skb_queue_len(&conn->control_frames),
			queue_len_before);
}

/*
 * Test: mtu_probe_queues_packet_for_larger_mtu
 * Purpose: With path->mtu at the QUIC minimum (1200), the next probe size
 *          in tquic_mtu_probes[] is 1280.  The function should queue exactly
 *          one skb into conn->control_frames (if memory is available) and
 *          return 0.
 * RFC Reference: RFC 8899 Section 5.2, RFC 9000 Section 14.3
 * Setup: path->mtu = 1200
 * Expected: return 0 or -ENOMEM; if 0, exactly one frame queued.
 */
static void test_mtu_probe_queues_packet(struct kunit *test)
{
	struct tquic_connection *conn;
	struct tquic_path *path;
	int queue_len_before;
	int ret;

	conn = tquic_conn_fixture_alloc(test);
	KUNIT_ASSERT_NOT_NULL(test, conn);

	path = tquic_path_fixture_alloc(test);
	KUNIT_ASSERT_NOT_NULL(test, path);

	path->conn = conn;
	path->mtu = 1200; /* Below first probe size of 1280 */

	queue_len_before = skb_queue_len(&conn->control_frames);

	ret = tquic_path_mtu_probe(path);

	if (ret == -ENOMEM) {
		/* alloc_skb failed — acceptable in test harness */
		kunit_skip(test, "skb allocation failed in test harness");
		return;
	}

	KUNIT_EXPECT_EQ(test, ret, 0);
	/*
	 * Exactly one probe packet should be appended to control_frames
	 * before schedule_work is called.
	 */
	KUNIT_EXPECT_EQ(test, skb_queue_len(&conn->control_frames),
			queue_len_before + 1);

	/* Clean up the skb we queued */
	skb_queue_purge(&conn->control_frames);
}

/* =========================================================================
 * tquic_path_mtu_probe_acked() tests
 * ========================================================================= */

/*
 * Test: mtu_probe_acked_null_path_is_safe
 * Purpose: NULL path must not crash (void function).
 * RFC Reference: RFC 8899
 * Setup: none
 * Expected: no crash.
 */
static void test_mtu_probe_acked_null_path_is_safe(struct kunit *test)
{
	tquic_path_mtu_probe_acked(NULL, 1400);
	KUNIT_SUCCEED(test);
}

/*
 * Test: mtu_probe_acked_updates_mtu_when_larger
 * Purpose: When a probe of size > current MTU is acknowledged, path->mtu
 *          is updated to the probe size.
 * RFC Reference: RFC 8899 Section 5.3
 * Setup: path->mtu = 1200; probe_size = 1400
 * Expected: path->mtu == 1400 after call.
 */
static void test_mtu_probe_acked_updates_mtu(struct kunit *test)
{
	struct tquic_path *path;

	path = tquic_path_fixture_alloc(test);
	KUNIT_ASSERT_NOT_NULL(test, path);

	path->mtu = 1200;

	tquic_path_mtu_probe_acked(path, 1400);

	KUNIT_EXPECT_EQ(test, path->mtu, 1400u);
}

/*
 * Test: mtu_probe_acked_does_not_decrease_mtu
 * Purpose: Acknowledging a probe smaller than the current MTU must not
 *          decrease path->mtu (probe_size <= path->mtu guard).
 * RFC Reference: RFC 8899 Section 5.3
 * Setup: path->mtu = 1500; probe_size = 1200
 * Expected: path->mtu == 1500 (unchanged).
 */
static void test_mtu_probe_acked_does_not_decrease_mtu(struct kunit *test)
{
	struct tquic_path *path;

	path = tquic_path_fixture_alloc(test);
	KUNIT_ASSERT_NOT_NULL(test, path);

	path->mtu = 1500;

	tquic_path_mtu_probe_acked(path, 1200);

	KUNIT_EXPECT_EQ(test, path->mtu, 1500u);
}

/*
 * Test: mtu_probe_acked_at_same_size_is_noop
 * Purpose: Acknowledging a probe at exactly the current MTU is a no-op.
 * RFC Reference: RFC 8899
 * Setup: path->mtu = 1400; probe_size = 1400
 * Expected: path->mtu == 1400 (unchanged — boundary condition).
 */
static void test_mtu_probe_acked_same_size_noop(struct kunit *test)
{
	struct tquic_path *path;

	path = tquic_path_fixture_alloc(test);
	KUNIT_ASSERT_NOT_NULL(test, path);

	path->mtu = 1400;

	tquic_path_mtu_probe_acked(path, 1400);

	KUNIT_EXPECT_EQ(test, path->mtu, 1400u);
}

/*
 * Test: mtu_probe_acked_updates_congestion_window
 * Purpose: After MTU update, tquic_path_cc_init is called which resets
 *          cwnd to min(10 * new_mtu, 14720).  Verify cwnd is non-zero.
 * RFC Reference: RFC 8899, RFC 9002 Section 7
 * Setup: path->mtu = 1200; probe_size = 1400.
 * Expected: path->cc.cwnd > 0 after call.
 */
static void test_mtu_probe_acked_updates_cwnd(struct kunit *test)
{
	struct tquic_path *path;

	path = tquic_path_fixture_alloc(test);
	KUNIT_ASSERT_NOT_NULL(test, path);

	path->mtu = 1200;
	path->cc.cwnd = 0; /* Ensure we detect the update */

	tquic_path_mtu_probe_acked(path, 1400);

	KUNIT_EXPECT_GT(test, path->cc.cwnd, 0u);
}

/* =========================================================================
 * tquic_path_on_validated() tests
 *
 * tquic_path_on_validated calls external helpers (tquic_timer_path_validated,
 * tquic_nl_path_event, tquic_pmtud_start).  These will be no-ops or benign
 * when conn is minimally initialised.  We verify the state transitions that
 * occur before those calls.
 * ========================================================================= */

/*
 * Test: on_validated_null_path_is_safe
 * Purpose: NULL path must not crash.
 * RFC Reference: RFC 9000 Section 8.2.2
 * Setup: none
 * Expected: no crash.
 */
static void test_path_on_validated_null_path_is_safe(struct kunit *test)
{
	tquic_path_on_validated(NULL);
	KUNIT_SUCCEED(test);
}

/*
 * Test: on_validated_sets_state_to_validated
 * Purpose: After tquic_path_on_validated(), path->state == TQUIC_PATH_VALIDATED.
 * RFC Reference: RFC 9000 Section 8.2.2
 * Setup: path->state = TQUIC_PATH_PENDING; challenge_pending = true.
 *        conn = NULL (to skip external calls that need a real conn).
 * Expected: path->state == TQUIC_PATH_VALIDATED, challenge_pending == false,
 *           schedulable == true.
 */
static void test_path_on_validated_sets_state_validated(struct kunit *test)
{
	struct tquic_path *path;

	path = tquic_path_fixture_alloc(test);
	KUNIT_ASSERT_NOT_NULL(test, path);

	path->state = TQUIC_PATH_PENDING;
	path->validation.challenge_pending = true;
	path->validation.challenge_sent = ktime_get();
	path->schedulable = false;

	/*
	 * conn = NULL — tquic_path_on_validated guards with "if (!conn) return"
	 * after setting state, challenge_pending and schedulable.  This lets
	 * us observe the state transitions without triggering the real netlink /
	 * timer / PMTUD backends.
	 */
	path->conn = NULL;

	tquic_path_on_validated(path);

	KUNIT_EXPECT_EQ(test, (int)path->state, (int)TQUIC_PATH_VALIDATED);
	KUNIT_EXPECT_FALSE(test, path->validation.challenge_pending);
	KUNIT_EXPECT_TRUE(test, path->schedulable);
}

/*
 * Test: on_validated_with_conn_still_sets_state
 * Purpose: With a real (minimal) conn, the function must still set state to
 *          VALIDATED before calling out to helpers.
 * RFC Reference: RFC 9000 Section 8.2.2
 * Setup: path->state = PENDING; conn minimally initialised.
 * Expected: path->state == TQUIC_PATH_VALIDATED.
 */
static void test_path_on_validated_with_conn_sets_state(struct kunit *test)
{
	struct tquic_connection *conn;
	struct tquic_path *path;

	conn = tquic_conn_fixture_alloc(test);
	KUNIT_ASSERT_NOT_NULL(test, conn);

	path = tquic_path_fixture_alloc(test);
	KUNIT_ASSERT_NOT_NULL(test, path);

	path->conn = conn;
	path->state = TQUIC_PATH_PENDING;
	path->validation.challenge_pending = true;
	path->validation.challenge_sent = ktime_get();

	/*
	 * External helpers (tquic_timer_path_validated, tquic_nl_path_event,
	 * tquic_pmtud_start) will run but against a stub connection.  They may
	 * crash if they dereference conn->sk or conn->pm — but those are NULL,
	 * so any well-written function guards against that.  If not, the test
	 * will fault and we will need to further restrict setup.
	 *
	 * The key assertion is that state changes happen before those calls.
	 * We rely on the source order in tquic_path_on_validated().
	 */
	tquic_path_on_validated(path);

	KUNIT_EXPECT_EQ(test, (int)path->state, (int)TQUIC_PATH_VALIDATED);
	KUNIT_EXPECT_FALSE(test, path->validation.challenge_pending);
	KUNIT_EXPECT_TRUE(test, path->schedulable);
}

/* =========================================================================
 * tquic_path_verify_response() tests
 * ========================================================================= */

/*
 * Test: verify_response_null_args_returns_false
 * Purpose: NULL path or data must return false.
 * RFC Reference: RFC 9000 Section 8.2.2
 * Setup: none
 * Expected: false.
 */
static void test_path_verify_response_null_args(struct kunit *test)
{
	struct tquic_path *path;
	u8 data[8] = { 0 };

	path = tquic_path_fixture_alloc(test);
	KUNIT_ASSERT_NOT_NULL(test, path);

	KUNIT_EXPECT_FALSE(test, tquic_path_verify_response(NULL, data));
	KUNIT_EXPECT_FALSE(test, tquic_path_verify_response(path, NULL));
}

/*
 * Test: verify_response_no_pending_challenge_returns_false
 * Purpose: Without an outstanding challenge, any response is invalid.
 * RFC Reference: RFC 9000 Section 8.2.2
 * Setup: challenge_pending = false.
 * Expected: false.
 */
static void test_path_verify_response_no_challenge_pending(struct kunit *test)
{
	struct tquic_path *path;
	u8 data[8] = { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08 };

	path = tquic_path_fixture_alloc(test);
	KUNIT_ASSERT_NOT_NULL(test, path);

	path->validation.challenge_pending = false;

	KUNIT_EXPECT_FALSE(test, tquic_path_verify_response(path, data));
}

/*
 * Test: verify_response_matching_data_returns_true
 * Purpose: A response whose data matches the challenge returns true.
 * RFC Reference: RFC 9000 Section 8.2.2
 * Setup: challenge_pending = true; challenge_data matches data.
 * Expected: true.
 */
static void test_path_verify_response_matching_data(struct kunit *test)
{
	struct tquic_path *path;
	u8 challenge[8] = { 0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe, 0xba, 0xbe };

	path = tquic_path_fixture_alloc(test);
	KUNIT_ASSERT_NOT_NULL(test, path);

	memcpy(path->validation.challenge_data, challenge, 8);
	path->validation.challenge_pending = true;

	KUNIT_EXPECT_TRUE(test, tquic_path_verify_response(path, challenge));
}

/*
 * Test: verify_response_mismatched_data_returns_false
 * Purpose: A response whose data does not match the challenge returns false.
 * RFC Reference: RFC 9000 Section 8.2.2 — timing-safe comparison.
 * Setup: challenge_pending = true; data differs from challenge_data.
 * Expected: false.
 */
static void test_path_verify_response_mismatched_data(struct kunit *test)
{
	struct tquic_path *path;
	u8 challenge[8] = { 0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe, 0xba, 0xbe };
	u8 wrong[8]     = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };

	path = tquic_path_fixture_alloc(test);
	KUNIT_ASSERT_NOT_NULL(test, path);

	memcpy(path->validation.challenge_data, challenge, 8);
	path->validation.challenge_pending = true;

	KUNIT_EXPECT_FALSE(test, tquic_path_verify_response(path, wrong));
}

/*
 * Test: verify_response_off_by_one_byte_returns_false
 * Purpose: A single-byte difference in the response must be rejected.
 * RFC Reference: RFC 9000 Section 8.2.2
 * Setup: challenge_pending = true; data differs by one byte.
 * Expected: false.
 */
static void test_path_verify_response_off_by_one_byte(struct kunit *test)
{
	struct tquic_path *path;
	u8 challenge[8] = { 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88 };
	u8 almost[8]    = { 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x89 };

	path = tquic_path_fixture_alloc(test);
	KUNIT_ASSERT_NOT_NULL(test, path);

	memcpy(path->validation.challenge_data, challenge, 8);
	path->validation.challenge_pending = true;

	KUNIT_EXPECT_FALSE(test, tquic_path_verify_response(path, almost));
}

/* =========================================================================
 * tquic_path_can_send() tests
 * ========================================================================= */

/*
 * Test: can_send_null_path_returns_false
 * Purpose: NULL path returns false.
 * RFC Reference: RFC 9000 Section 8.1
 * Setup: none
 * Expected: false.
 */
static void test_path_can_send_null_path(struct kunit *test)
{
	KUNIT_EXPECT_FALSE(test, tquic_path_can_send(NULL, 100));
}

/*
 * Test: can_send_validated_path_always_true
 * Purpose: A VALIDATED path has no amplification limit.
 * RFC Reference: RFC 9000 Section 8.1
 * Setup: path->state = TQUIC_PATH_VALIDATED; stats.tx_bytes = 1000000.
 * Expected: true regardless of tx_bytes.
 */
static void test_path_can_send_validated_always_true(struct kunit *test)
{
	struct tquic_path *path;

	path = tquic_path_fixture_alloc(test);
	KUNIT_ASSERT_NOT_NULL(test, path);

	path->state = TQUIC_PATH_VALIDATED;
	path->stats.tx_bytes = 1000000;
	path->stats.rx_bytes = 0;

	KUNIT_EXPECT_TRUE(test, tquic_path_can_send(path, 100));
}

/*
 * Test: can_send_active_path_always_true
 * Purpose: A ACTIVE path (same as validated) has no amplification limit.
 * RFC Reference: RFC 9000 Section 8.1
 * Setup: path->state = TQUIC_PATH_ACTIVE.
 * Expected: true.
 */
static void test_path_can_send_active_always_true(struct kunit *test)
{
	struct tquic_path *path;

	path = tquic_path_fixture_alloc(test);
	KUNIT_ASSERT_NOT_NULL(test, path);

	path->state = TQUIC_PATH_ACTIVE;
	path->stats.tx_bytes = 999999;
	path->stats.rx_bytes = 1;

	KUNIT_EXPECT_TRUE(test, tquic_path_can_send(path, 100));
}

/*
 * Test: can_send_pending_within_3x_limit_true
 * Purpose: An unvalidated (PENDING) path can send up to 3x received data.
 * RFC Reference: RFC 9000 Section 8.1
 * Setup: state = PENDING; rx_bytes = 1000; tx_bytes = 0; request 100 bytes.
 * Expected: true (0 + 100 <= 1000 * 3 = 3000).
 */
static void test_path_can_send_pending_within_limit(struct kunit *test)
{
	struct tquic_path *path;

	path = tquic_path_fixture_alloc(test);
	KUNIT_ASSERT_NOT_NULL(test, path);

	path->state = TQUIC_PATH_PENDING;
	path->stats.rx_bytes = 1000;
	path->stats.tx_bytes = 0;

	KUNIT_EXPECT_TRUE(test, tquic_path_can_send(path, 100));
}

/*
 * Test: can_send_pending_exceeds_3x_limit_false
 * Purpose: An unvalidated path must not exceed 3x amplification.
 * RFC Reference: RFC 9000 Section 8.1
 * Setup: state = PENDING; rx_bytes = 100; tx_bytes = 300; request 1 byte.
 * Expected: false (300 + 1 = 301 > 100 * 3 = 300).
 */
static void test_path_can_send_pending_exceeds_limit(struct kunit *test)
{
	struct tquic_path *path;

	path = tquic_path_fixture_alloc(test);
	KUNIT_ASSERT_NOT_NULL(test, path);

	path->state = TQUIC_PATH_PENDING;
	path->stats.rx_bytes = 100;
	path->stats.tx_bytes = 300;

	KUNIT_EXPECT_FALSE(test, tquic_path_can_send(path, 1));
}

/*
 * Test: can_send_pending_exactly_at_3x_limit_true
 * Purpose: Exactly at the 3x limit is allowed (non-strict inequality).
 * RFC Reference: RFC 9000 Section 8.1
 * Setup: state = PENDING; rx_bytes = 100; tx_bytes = 0; request 300 bytes.
 * Expected: true (0 + 300 == 100 * 3 = 300).
 */
static void test_path_can_send_pending_exactly_at_limit(struct kunit *test)
{
	struct tquic_path *path;

	path = tquic_path_fixture_alloc(test);
	KUNIT_ASSERT_NOT_NULL(test, path);

	path->state = TQUIC_PATH_PENDING;
	path->stats.rx_bytes = 100;
	path->stats.tx_bytes = 0;

	KUNIT_EXPECT_TRUE(test, tquic_path_can_send(path, 300));
}

/* =========================================================================
 * tquic_path_rtt_update() tests
 * ========================================================================= */

/*
 * Test: rtt_update_null_path_is_safe
 * Purpose: NULL path must not crash.
 * RFC Reference: RFC 9002 Section 5
 * Setup: none
 * Expected: no crash.
 */
static void test_path_rtt_update_null_path_safe(struct kunit *test)
{
	tquic_path_rtt_update(NULL, 50000, 0);
	KUNIT_SUCCEED(test);
}

/*
 * Test: rtt_update_first_sample_sets_smoothed
 * Purpose: The first RTT sample sets smoothed_rtt, rtt_var, and min_rtt.
 * RFC Reference: RFC 9002 Section 5.3 — first sample: SRTT = RTT,
 *               RTTVAR = RTT/2.
 * Setup: smoothed_rtt_us = 0 (forces first-sample branch).
 * Expected: smoothed_rtt_us = 50000, rtt_var_us = 25000.
 */
static void test_path_rtt_update_first_sample(struct kunit *test)
{
	struct tquic_path *path;

	path = tquic_path_fixture_alloc(test);
	KUNIT_ASSERT_NOT_NULL(test, path);

	/* Force first-sample branch: smoothed_rtt == 0 */
	path->cc.smoothed_rtt_us = 0;
	path->cc.min_rtt_us = U64_MAX;

	tquic_path_rtt_update(path, 50000, 0);

	KUNIT_EXPECT_EQ(test, path->cc.smoothed_rtt_us, 50000ULL);
	KUNIT_EXPECT_EQ(test, path->cc.rtt_var_us, 25000ULL);
	KUNIT_EXPECT_EQ(test, path->cc.min_rtt_us, 50000ULL);
}

/*
 * Test: rtt_update_subsequent_sample_uses_ewma
 * Purpose: A subsequent sample updates smoothed_rtt via EWMA (7/8 old + 1/8
 *          new) and rtt_var via (3/4 old + 1/4 |new - old|).
 * RFC Reference: RFC 9002 Section 5.3
 * Setup: smoothed_rtt_us = 100000; rtt_var_us = 10000; min_rtt_us = 80000.
 *        New sample: 120000 us, ack_delay = 0.
 * Expected: smoothed_rtt_us == (7*100000 + 120000) / 8 == 102500,
 *           rtt_var_us increases.
 */
static void test_path_rtt_update_ewma_smoothing(struct kunit *test)
{
	struct tquic_path *path;
	u64 expected_srtt;
	u64 expected_var;
	u64 rttvar_sample;

	path = tquic_path_fixture_alloc(test);
	KUNIT_ASSERT_NOT_NULL(test, path);

	path->cc.smoothed_rtt_us = 100000;
	path->cc.rtt_var_us      = 10000;
	path->cc.min_rtt_us      = 80000;

	/* latest_rtt = 120000; ack_delay = 0.
	 * adjusted_rtt = 120000 (no ack delay subtraction since
	 *   adjusted_rtt >= min_rtt + ack_delay: 120000 >= 80000 + 0).
	 * rttvar_sample = |120000 - 100000| = 20000
	 * new rtt_var = (3 * 10000 + 20000) / 4 = 12500
	 * new srtt = (7 * 100000 + 120000) / 8 = 102500
	 */
	rttvar_sample = 20000;
	expected_var  = (3 * 10000 + rttvar_sample) / 4;  /* 12500 */
	expected_srtt = (7 * 100000 + 120000) / 8;        /* 102500 */

	tquic_path_rtt_update(path, 120000, 0);

	KUNIT_EXPECT_EQ(test, path->cc.smoothed_rtt_us, expected_srtt);
	KUNIT_EXPECT_EQ(test, path->cc.rtt_var_us, expected_var);
}

/*
 * Test: rtt_update_updates_min_rtt
 * Purpose: Observing a new minimum RTT updates min_rtt_us.
 * RFC Reference: RFC 9002 Section 5.2
 * Setup: min_rtt_us = 100000; new sample = 60000.
 * Expected: min_rtt_us == 60000.
 */
static void test_path_rtt_update_min_rtt(struct kunit *test)
{
	struct tquic_path *path;

	path = tquic_path_fixture_alloc(test);
	KUNIT_ASSERT_NOT_NULL(test, path);

	path->cc.smoothed_rtt_us = 100000;
	path->cc.rtt_var_us      = 10000;
	path->cc.min_rtt_us      = 100000;

	tquic_path_rtt_update(path, 60000, 0);

	KUNIT_EXPECT_EQ(test, path->cc.min_rtt_us, 60000ULL);
}

/* =========================================================================
 * tquic_path_pto() tests
 * ========================================================================= */

/*
 * Test: pto_null_path_returns_default
 * Purpose: NULL path returns a valid 1-second default.
 * RFC Reference: RFC 9002 Section 6.2
 * Setup: none
 * Expected: 1000000 (1 second in microseconds).
 */
static void test_path_pto_null_path_default(struct kunit *test)
{
	u32 pto = tquic_path_pto(NULL);

	KUNIT_EXPECT_EQ(test, pto, 1000000u);
}

/*
 * Test: pto_calculation_matches_rfc9002_formula
 * Purpose: PTO = smoothed_rtt + max(4 * rttvar, kGranularity) + max_ack_delay.
 * RFC Reference: RFC 9002 Section 6.2
 * Setup: smoothed_rtt_us = 100000; rtt_var_us = 10000.
 *        kGranularity = 1000 (1ms); max_ack_delay = 25000 (25ms).
 * Expected: 100000 + max(40000, 1000) + 25000 = 165000.
 */
static void test_path_pto_formula(struct kunit *test)
{
	struct tquic_path *path;
	u32 pto;
	u32 expected;

	path = tquic_path_fixture_alloc(test);
	KUNIT_ASSERT_NOT_NULL(test, path);

	path->cc.smoothed_rtt_us = 100000;
	path->cc.rtt_var_us      = 10000;

	/* expected = srtt + max(4*rttvar, 1000) + 25000
	 *          = 100000 + max(40000, 1000) + 25000
	 *          = 100000 + 40000 + 25000 = 165000
	 */
	expected = 100000 + 40000 + 25000;

	pto = tquic_path_pto(path);

	KUNIT_EXPECT_EQ(test, pto, expected);
}

/*
 * Test: pto_uses_granularity_when_rttvar_small
 * Purpose: When 4 * rttvar < kGranularity (1000 us), kGranularity is used.
 * RFC Reference: RFC 9002 Section 6.2 — max(4*rttvar, kGranularity)
 * Setup: smoothed_rtt_us = 50000; rtt_var_us = 100 (4*100 = 400 < 1000).
 * Expected: 50000 + 1000 + 25000 = 76000.
 */
static void test_path_pto_granularity_floor(struct kunit *test)
{
	struct tquic_path *path;
	u32 pto;
	u32 expected;

	path = tquic_path_fixture_alloc(test);
	KUNIT_ASSERT_NOT_NULL(test, path);

	path->cc.smoothed_rtt_us = 50000;
	path->cc.rtt_var_us      = 100; /* 4 * 100 = 400, below kGranularity */

	expected = 50000 + 1000 + 25000; /* 76000 */

	pto = tquic_path_pto(path);

	KUNIT_EXPECT_EQ(test, pto, expected);
}

/* =========================================================================
 * tquic_path_needs_probe() tests
 * ========================================================================= */

/*
 * Test: needs_probe_null_returns_false
 * Purpose: NULL path returns false.
 * RFC Reference: RFC 9000 Section 8.2
 * Setup: none
 * Expected: false.
 */
static void test_path_needs_probe_null_false(struct kunit *test)
{
	KUNIT_EXPECT_FALSE(test, tquic_path_needs_probe(NULL));
}

/*
 * Test: needs_probe_pending_with_challenge_returns_true
 * Purpose: A PENDING path with an outstanding challenge needs probing.
 * RFC Reference: RFC 9000 Section 8.2
 * Setup: state = PENDING; challenge_pending = true.
 * Expected: true.
 */
static void test_path_needs_probe_pending_with_challenge(struct kunit *test)
{
	struct tquic_path *path;

	path = tquic_path_fixture_alloc(test);
	KUNIT_ASSERT_NOT_NULL(test, path);

	path->state = TQUIC_PATH_PENDING;
	path->validation.challenge_pending = true;

	KUNIT_EXPECT_TRUE(test, tquic_path_needs_probe(path));
}

/*
 * Test: needs_probe_validated_no_challenge_returns_false
 * Purpose: A VALIDATED path does not need probing.
 * RFC Reference: RFC 9000 Section 8.2
 * Setup: state = VALIDATED; challenge_pending = false.
 * Expected: false.
 */
static void test_path_needs_probe_validated_false(struct kunit *test)
{
	struct tquic_path *path;

	path = tquic_path_fixture_alloc(test);
	KUNIT_ASSERT_NOT_NULL(test, path);

	path->state = TQUIC_PATH_VALIDATED;
	path->validation.challenge_pending = false;

	KUNIT_EXPECT_FALSE(test, tquic_path_needs_probe(path));
}

/*
 * Test: needs_probe_pending_no_challenge_returns_false
 * Purpose: PENDING without a pending challenge does not need probing.
 * RFC Reference: RFC 9000 Section 8.2
 * Setup: state = PENDING; challenge_pending = false.
 * Expected: false (both conditions must be true).
 */
static void test_path_needs_probe_pending_no_challenge_false(struct kunit *test)
{
	struct tquic_path *path;

	path = tquic_path_fixture_alloc(test);
	KUNIT_ASSERT_NOT_NULL(test, path);

	path->state = TQUIC_PATH_PENDING;
	path->validation.challenge_pending = false;

	KUNIT_EXPECT_FALSE(test, tquic_path_needs_probe(path));
}

/* =========================================================================
 * tquic_path_get_info() tests
 * ========================================================================= */

/*
 * Test: get_info_null_args_returns_einval
 * Purpose: NULL path or info returns -EINVAL.
 * RFC Reference: diagnostic API contract
 * Setup: none
 * Expected: -EINVAL.
 */
static void test_path_get_info_null_args(struct kunit *test)
{
	struct tquic_path *path;
	struct tquic_path_info info;
	int ret;

	path = tquic_path_fixture_alloc(test);
	KUNIT_ASSERT_NOT_NULL(test, path);

	ret = tquic_path_get_info(NULL, &info);
	KUNIT_EXPECT_EQ(test, ret, -EINVAL);

	ret = tquic_path_get_info(path, NULL);
	KUNIT_EXPECT_EQ(test, ret, -EINVAL);
}

/*
 * Test: get_info_copies_mtu_and_path_id
 * Purpose: tquic_path_get_info populates mtu and path_id correctly.
 * RFC Reference: diagnostic/stats export
 * Setup: path->mtu = 1400; path->path_id = 3.
 * Expected: info.mtu == 1400; info.path_id == 3.
 */
static void test_path_get_info_basic_fields(struct kunit *test)
{
	struct tquic_path *path;
	struct tquic_path_info info;
	int ret;

	path = tquic_path_fixture_alloc(test);
	KUNIT_ASSERT_NOT_NULL(test, path);

	path->mtu = 1400;
	path->path_id = 3;
	path->priority = 1;
	path->weight = 50;
	path->cc.smoothed_rtt_us = 20000; /* 20 ms */
	path->cc.rtt_var_us = 5000;
	path->cc.cwnd = 14720;
	path->state = TQUIC_PATH_ACTIVE;

	ret = tquic_path_get_info(path, &info);

	KUNIT_EXPECT_EQ(test, ret, 0);
	KUNIT_EXPECT_EQ(test, info.mtu, 1400u);
	KUNIT_EXPECT_EQ(test, info.path_id, 3u);
	KUNIT_EXPECT_EQ(test, info.priority, 1u);
	KUNIT_EXPECT_EQ(test, info.weight, 50u);
	/* RTT in ms: 20000 us / 1000 = 20 */
	KUNIT_EXPECT_EQ(test, info.rtt, 20u);
	KUNIT_EXPECT_EQ(test, info.cwnd, 14720u);
}

/*
 * Test: get_info_state_mapping_active
 * Purpose: TQUIC_PATH_ACTIVE maps to TQUIC_PATH_STATE_ACTIVE.
 * RFC Reference: diagnostic API
 * Setup: path->state = TQUIC_PATH_ACTIVE.
 * Expected: info.state == TQUIC_PATH_STATE_ACTIVE.
 */
static void test_path_get_info_state_active(struct kunit *test)
{
	struct tquic_path *path;
	struct tquic_path_info info;

	path = tquic_path_fixture_alloc(test);
	KUNIT_ASSERT_NOT_NULL(test, path);

	path->state = TQUIC_PATH_ACTIVE;

	tquic_path_get_info(path, &info);

	KUNIT_EXPECT_EQ(test, (int)info.state, (int)TQUIC_PATH_STATE_ACTIVE);
}

/*
 * Test: get_info_state_mapping_failed
 * Purpose: TQUIC_PATH_FAILED maps to TQUIC_PATH_STATE_FAILED.
 * RFC Reference: diagnostic API
 * Setup: path->state = TQUIC_PATH_FAILED.
 * Expected: info.state == TQUIC_PATH_STATE_FAILED.
 */
static void test_path_get_info_state_failed(struct kunit *test)
{
	struct tquic_path *path;
	struct tquic_path_info info;

	path = tquic_path_fixture_alloc(test);
	KUNIT_ASSERT_NOT_NULL(test, path);

	path->state = TQUIC_PATH_FAILED;

	tquic_path_get_info(path, &info);

	KUNIT_EXPECT_EQ(test, (int)info.state, (int)TQUIC_PATH_STATE_FAILED);
}

/*
 * Test: get_info_state_mapping_standby
 * Purpose: TQUIC_PATH_STANDBY maps to TQUIC_PATH_STATE_STANDBY.
 * RFC Reference: diagnostic API
 * Setup: path->state = TQUIC_PATH_STANDBY.
 * Expected: info.state == TQUIC_PATH_STATE_STANDBY.
 */
static void test_path_get_info_state_standby(struct kunit *test)
{
	struct tquic_path *path;
	struct tquic_path_info info;

	path = tquic_path_fixture_alloc(test);
	KUNIT_ASSERT_NOT_NULL(test, path);

	path->state = TQUIC_PATH_STANDBY;

	tquic_path_get_info(path, &info);

	KUNIT_EXPECT_EQ(test, (int)info.state, (int)TQUIC_PATH_STATE_STANDBY);
}

/* =========================================================================
 * tquic_path_on_probe_timeout() tests (state machine)
 * ========================================================================= */

/*
 * Test: probe_timeout_max_retries_marks_failed
 * Purpose: Exceeding TQUIC_PATH_MAX_PROBES retries marks the path FAILED.
 * RFC Reference: RFC 9000 Section 8.2.1 — validation timeout.
 * Setup: state = PENDING; challenge_pending = true;
 *        retries = TQUIC_PATH_MAX_PROBES (3); challenge_sent in near past.
 * Expected: path->state == TQUIC_PATH_FAILED; challenge_pending == false.
 *
 * Note: We set challenge_sent to ktime_get() to stay well within the
 *       30-second TQUIC_PATH_VALIDATION_TIMEOUT_MS window so that the
 *       retry-count branch is reached rather than the timeout branch.
 */
static void test_path_probe_timeout_max_retries_failed(struct kunit *test)
{
	struct tquic_path *path;

	path = tquic_path_fixture_alloc(test);
	KUNIT_ASSERT_NOT_NULL(test, path);

	path->state = TQUIC_PATH_PENDING;
	path->validation.challenge_pending = true;
	path->validation.retries = 3; /* == TQUIC_PATH_MAX_PROBES */
	path->validation.challenge_sent = ktime_get(); /* within timeout window */
	path->conn = NULL; /* prevent real tquic_path_challenge call */

	/*
	 * tquic_path_on_probe_timeout increments retries, then checks
	 * if retries >= TQUIC_PATH_MAX_PROBES (3).  Starting at 3 means
	 * after increment it is 4 >= 3, triggering the failure path.
	 *
	 * If path->conn is NULL, tquic_path_challenge returns early with
	 * -EINVAL so no crash occurs on the retransmit branch if we
	 * accidentally reach it.
	 */
	tquic_path_on_probe_timeout(path);

	KUNIT_EXPECT_EQ(test, (int)path->state, (int)TQUIC_PATH_FAILED);
	KUNIT_EXPECT_FALSE(test, path->validation.challenge_pending);
}

/*
 * Test: probe_timeout_no_pending_challenge_is_noop
 * Purpose: Timeout with no pending challenge is a no-op.
 * RFC Reference: RFC 9000 Section 8.2.1
 * Setup: challenge_pending = false.
 * Expected: state unchanged.
 */
static void test_path_probe_timeout_no_challenge_noop(struct kunit *test)
{
	struct tquic_path *path;

	path = tquic_path_fixture_alloc(test);
	KUNIT_ASSERT_NOT_NULL(test, path);

	path->state = TQUIC_PATH_PENDING;
	path->validation.challenge_pending = false;

	tquic_path_on_probe_timeout(path);

	KUNIT_EXPECT_EQ(test, (int)path->state, (int)TQUIC_PATH_PENDING);
}

/* =========================================================================
 * Test suite registration
 * ========================================================================= */

static struct kunit_case quic_path_migrate_cases[] = {
	KUNIT_CASE(test_path_migrate_null_args),
	KUNIT_CASE(test_path_migrate_already_active_is_noop),
	KUNIT_CASE(test_path_migrate_disabled_returns_eperm),
	KUNIT_CASE(test_path_migrate_unvalidated_returns_einval),
	KUNIT_CASE(test_path_migrate_validated_succeeds),
	KUNIT_CASE(test_path_migrate_from_null_active_path),
	{}
};

static struct kunit_suite quic_path_migrate_suite = {
	.name = "tquic_path_migrate",
	.test_cases = quic_path_migrate_cases,
};

static struct kunit_case quic_mtu_probe_cases[] = {
	KUNIT_CASE(test_mtu_probe_null_path_returns_einval),
	KUNIT_CASE(test_mtu_probe_null_conn_returns_einval),
	KUNIT_CASE(test_mtu_probe_at_maximum_is_noop),
	KUNIT_CASE(test_mtu_probe_queues_packet),
	{}
};

static struct kunit_suite quic_mtu_probe_suite = {
	.name = "tquic_path_mtu_probe",
	.test_cases = quic_mtu_probe_cases,
};

static struct kunit_case quic_mtu_probe_acked_cases[] = {
	KUNIT_CASE(test_mtu_probe_acked_null_path_is_safe),
	KUNIT_CASE(test_mtu_probe_acked_updates_mtu),
	KUNIT_CASE(test_mtu_probe_acked_does_not_decrease_mtu),
	KUNIT_CASE(test_mtu_probe_acked_same_size_noop),
	KUNIT_CASE(test_mtu_probe_acked_updates_cwnd),
	{}
};

static struct kunit_suite quic_mtu_probe_acked_suite = {
	.name = "tquic_path_mtu_probe_acked",
	.test_cases = quic_mtu_probe_acked_cases,
};

static struct kunit_case quic_path_on_validated_cases[] = {
	KUNIT_CASE(test_path_on_validated_null_path_is_safe),
	KUNIT_CASE(test_path_on_validated_sets_state_validated),
	KUNIT_CASE(test_path_on_validated_with_conn_sets_state),
	{}
};

static struct kunit_suite quic_path_on_validated_suite = {
	.name = "tquic_path_on_validated",
	.test_cases = quic_path_on_validated_cases,
};

static struct kunit_case quic_path_verify_response_cases[] = {
	KUNIT_CASE(test_path_verify_response_null_args),
	KUNIT_CASE(test_path_verify_response_no_challenge_pending),
	KUNIT_CASE(test_path_verify_response_matching_data),
	KUNIT_CASE(test_path_verify_response_mismatched_data),
	KUNIT_CASE(test_path_verify_response_off_by_one_byte),
	{}
};

static struct kunit_suite quic_path_verify_response_suite = {
	.name = "tquic_path_verify_response",
	.test_cases = quic_path_verify_response_cases,
};

static struct kunit_case quic_path_can_send_cases[] = {
	KUNIT_CASE(test_path_can_send_null_path),
	KUNIT_CASE(test_path_can_send_validated_always_true),
	KUNIT_CASE(test_path_can_send_active_always_true),
	KUNIT_CASE(test_path_can_send_pending_within_limit),
	KUNIT_CASE(test_path_can_send_pending_exceeds_limit),
	KUNIT_CASE(test_path_can_send_pending_exactly_at_limit),
	{}
};

static struct kunit_suite quic_path_can_send_suite = {
	.name = "tquic_path_can_send",
	.test_cases = quic_path_can_send_cases,
};

static struct kunit_case quic_path_rtt_cases[] = {
	KUNIT_CASE(test_path_rtt_update_null_path_safe),
	KUNIT_CASE(test_path_rtt_update_first_sample),
	KUNIT_CASE(test_path_rtt_update_ewma_smoothing),
	KUNIT_CASE(test_path_rtt_update_min_rtt),
	{}
};

static struct kunit_suite quic_path_rtt_suite = {
	.name = "tquic_path_rtt_update",
	.test_cases = quic_path_rtt_cases,
};

static struct kunit_case quic_path_pto_cases[] = {
	KUNIT_CASE(test_path_pto_null_path_default),
	KUNIT_CASE(test_path_pto_formula),
	KUNIT_CASE(test_path_pto_granularity_floor),
	{}
};

static struct kunit_suite quic_path_pto_suite = {
	.name = "tquic_path_pto",
	.test_cases = quic_path_pto_cases,
};

static struct kunit_case quic_path_needs_probe_cases[] = {
	KUNIT_CASE(test_path_needs_probe_null_false),
	KUNIT_CASE(test_path_needs_probe_pending_with_challenge),
	KUNIT_CASE(test_path_needs_probe_validated_false),
	KUNIT_CASE(test_path_needs_probe_pending_no_challenge_false),
	{}
};

static struct kunit_suite quic_path_needs_probe_suite = {
	.name = "tquic_path_needs_probe",
	.test_cases = quic_path_needs_probe_cases,
};

static struct kunit_case quic_path_get_info_cases[] = {
	KUNIT_CASE(test_path_get_info_null_args),
	KUNIT_CASE(test_path_get_info_basic_fields),
	KUNIT_CASE(test_path_get_info_state_active),
	KUNIT_CASE(test_path_get_info_state_failed),
	KUNIT_CASE(test_path_get_info_state_standby),
	{}
};

static struct kunit_suite quic_path_get_info_suite = {
	.name = "tquic_path_get_info",
	.test_cases = quic_path_get_info_cases,
};

static struct kunit_case quic_path_probe_timeout_cases[] = {
	KUNIT_CASE(test_path_probe_timeout_max_retries_failed),
	KUNIT_CASE(test_path_probe_timeout_no_challenge_noop),
	{}
};

static struct kunit_suite quic_path_probe_timeout_suite = {
	.name = "tquic_path_probe_timeout",
	.test_cases = quic_path_probe_timeout_cases,
};

kunit_test_suites(&quic_path_migrate_suite,
		  &quic_mtu_probe_suite,
		  &quic_mtu_probe_acked_suite,
		  &quic_path_on_validated_suite,
		  &quic_path_verify_response_suite,
		  &quic_path_can_send_suite,
		  &quic_path_rtt_suite,
		  &quic_path_pto_suite,
		  &quic_path_needs_probe_suite,
		  &quic_path_get_info_suite,
		  &quic_path_probe_timeout_suite);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("TQUIC Path Management KUnit Tests (quic_path.c)");
MODULE_AUTHOR("Justin Adams <spotty118@gmail.com>");
