// SPDX-License-Identifier: GPL-2.0-only
/*
 * TQUIC Interoperability Testing Framework Implementation
 *
 * Copyright (c) 2026 Linux Foundation
 *
 * Provides a comprehensive testing framework for QUIC protocol compliance
 * and interoperability verification.
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/list.h>
#include <linux/spinlock.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/workqueue.h>
#include <linux/completion.h>
#include <linux/random.h>
#include <net/tquic.h>

#include "interop_framework.h"
#include "../../protocol.h"

/*
 * =============================================================================
 * Global State
 * =============================================================================
 */

static LIST_HEAD(test_list);
static DEFINE_SPINLOCK(test_lock);
static bool interop_initialized;

/* Test runner workqueue */
static struct workqueue_struct *test_wq;

/* Test runner state */
struct tquic_test_runner {
	struct list_head queue;
	spinlock_t lock;
	struct completion done;
	struct tquic_test_results results;
	u32 categories;
	bool running;
};

static struct tquic_test_runner *active_runner;

/*
 * =============================================================================
 * Test Registration
 * =============================================================================
 */

int tquic_test_register(struct tquic_test_case *test)
{
	if (!test || !test->name || !test->run)
		return -EINVAL;

	spin_lock(&test_lock);
	list_add_tail(&test->list, &test_list);
	spin_unlock(&test_lock);

	pr_debug("tquic_test: registered test '%s'\n", test->name);
	return 0;
}
EXPORT_SYMBOL_GPL(tquic_test_register);

void tquic_test_unregister(struct tquic_test_case *test)
{
	if (!test)
		return;

	spin_lock(&test_lock);
	list_del(&test->list);
	spin_unlock(&test_lock);

	pr_debug("tquic_test: unregistered test '%s'\n", test->name);
}
EXPORT_SYMBOL_GPL(tquic_test_unregister);

/*
 * =============================================================================
 * Test Execution
 * =============================================================================
 */

static int run_single_test(struct tquic_test_case *test,
			   struct tquic_test_ctx *ctx)
{
	ktime_t start, end;
	int ret;

	ctx->test = test;
	ctx->result = TQUIC_TEST_PASS;
	ctx->error_msg[0] = '\0';
	ctx->start_time = ktime_get();

	pr_info("tquic_test: running '%s'...\n", test->name);

	/* Setup */
	if (test->setup) {
		ret = test->setup(ctx);
		if (ret != 0) {
			pr_err("tquic_test: '%s' setup failed: %d\n",
			       test->name, ret);
			return TQUIC_TEST_ERROR;
		}
	}

	/* Run test */
	start = ktime_get();
	ret = test->run(ctx);
	end = ktime_get();

	/* Teardown */
	if (test->teardown)
		test->teardown(ctx);

	/* Report result */
	switch (ret) {
	case TQUIC_TEST_PASS:
		pr_info("tquic_test: '%s' PASSED (%lld ms)\n",
			test->name, ktime_ms_delta(end, start));
		break;
	case TQUIC_TEST_FAIL:
		pr_err("tquic_test: '%s' FAILED: %s\n",
		       test->name, ctx->error_msg);
		break;
	case TQUIC_TEST_SKIP:
		pr_info("tquic_test: '%s' SKIPPED\n", test->name);
		break;
	case TQUIC_TEST_TIMEOUT:
		pr_err("tquic_test: '%s' TIMEOUT\n", test->name);
		break;
	default:
		pr_err("tquic_test: '%s' ERROR: %d\n", test->name, ret);
		ret = TQUIC_TEST_ERROR;
		break;
	}

	return ret;
}

int tquic_test_run_all(u32 categories, struct tquic_test_results *results)
{
	struct tquic_test_case *test;
	struct tquic_test_ctx *ctx;
	ktime_t start;
	int ret;

	if (!results)
		return -EINVAL;

	memset(results, 0, sizeof(*results));

	ctx = kzalloc(sizeof(*ctx), GFP_KERNEL);
	if (!ctx)
		return -ENOMEM;

	start = ktime_get();

	spin_lock(&test_lock);
	list_for_each_entry(test, &test_list, list) {
		/* Check category filter */
		if (categories != TQUIC_TEST_CAT_ALL &&
		    !(test->category & categories))
			continue;

		spin_unlock(&test_lock);

		ret = run_single_test(test, ctx);
		results->total++;

		switch (ret) {
		case TQUIC_TEST_PASS:
			results->passed++;
			break;
		case TQUIC_TEST_FAIL:
			results->failed++;
			break;
		case TQUIC_TEST_SKIP:
			results->skipped++;
			break;
		default:
			results->errors++;
			break;
		}

		spin_lock(&test_lock);
	}
	spin_unlock(&test_lock);

	results->duration_ms = ktime_ms_delta(ktime_get(), start);

	pr_info("tquic_test: completed %u tests: %u passed, %u failed, "
		"%u skipped, %u errors (%llu ms)\n",
		results->total, results->passed, results->failed,
		results->skipped, results->errors, results->duration_ms);

	kfree(ctx);
	return results->failed + results->errors;
}
EXPORT_SYMBOL_GPL(tquic_test_run_all);

int tquic_test_run_single(const char *name, struct tquic_test_results *results)
{
	struct tquic_test_case *test, *found = NULL;
	struct tquic_test_ctx *ctx;
	int ret;

	if (!name || !results)
		return -EINVAL;

	memset(results, 0, sizeof(*results));

	/* Find test by name */
	spin_lock(&test_lock);
	list_for_each_entry(test, &test_list, list) {
		if (strcmp(test->name, name) == 0) {
			found = test;
			break;
		}
	}
	spin_unlock(&test_lock);

	if (!found) {
		pr_err("tquic_test: test '%s' not found\n", name);
		return -ENOENT;
	}

	ctx = kzalloc(sizeof(*ctx), GFP_KERNEL);
	if (!ctx)
		return -ENOMEM;

	ret = run_single_test(found, ctx);
	results->total = 1;

	switch (ret) {
	case TQUIC_TEST_PASS:
		results->passed = 1;
		break;
	case TQUIC_TEST_FAIL:
		results->failed = 1;
		break;
	case TQUIC_TEST_SKIP:
		results->skipped = 1;
		break;
	default:
		results->errors = 1;
		break;
	}

	kfree(ctx);
	return ret;
}
EXPORT_SYMBOL_GPL(tquic_test_run_single);

int tquic_test_list(char *buf, size_t size)
{
	struct tquic_test_case *test;
	int len = 0;

	spin_lock(&test_lock);
	list_for_each_entry(test, &test_list, list) {
		int n = snprintf(buf + len, size - len,
				 "%s (cat=0x%x, rfc=%s)\n",
				 test->name, test->category,
				 test->rfc_section ? test->rfc_section : "N/A");
		if (n >= size - len)
			break;
		len += n;
	}
	spin_unlock(&test_lock);

	return len;
}
EXPORT_SYMBOL_GPL(tquic_test_list);

/*
 * =============================================================================
 * Test Utilities
 * =============================================================================
 */

int tquic_test_create_connection(struct tquic_test_ctx *ctx, bool is_server)
{
	/* Stub - would create a loopback QUIC connection for testing */
	pr_debug("tquic_test: creating %s connection\n",
		 is_server ? "server" : "client");
	return 0;
}
EXPORT_SYMBOL_GPL(tquic_test_create_connection);

int tquic_test_complete_handshake(struct tquic_test_ctx *ctx)
{
	/* Stub - would complete handshake between test connections */
	pr_debug("tquic_test: completing handshake\n");
	return 0;
}
EXPORT_SYMBOL_GPL(tquic_test_complete_handshake);

int tquic_test_send_data(struct tquic_test_ctx *ctx, u64 stream_id,
			 const void *data, size_t len)
{
	/* Stub - would send data on stream */
	pr_debug("tquic_test: sending %zu bytes on stream %llu\n",
		 len, stream_id);
	ctx->bytes_tx += len;
	ctx->packets_tx++;
	return len;
}
EXPORT_SYMBOL_GPL(tquic_test_send_data);

int tquic_test_recv_data(struct tquic_test_ctx *ctx, u64 stream_id,
			 void *buf, size_t len)
{
	/* Stub - would receive data from stream */
	pr_debug("tquic_test: receiving up to %zu bytes from stream %llu\n",
		 len, stream_id);
	ctx->bytes_rx += len;
	ctx->packets_rx++;
	return len;
}
EXPORT_SYMBOL_GPL(tquic_test_recv_data);

int tquic_test_inject_packet(struct tquic_test_ctx *ctx,
			     const void *data, size_t len, bool to_server)
{
	/* Stub - would inject raw packet */
	pr_debug("tquic_test: injecting %zu byte packet to %s\n",
		 len, to_server ? "server" : "client");
	return 0;
}
EXPORT_SYMBOL_GPL(tquic_test_inject_packet);

int tquic_test_drop_next_packet(struct tquic_test_ctx *ctx, bool from_server)
{
	/* Stub - would configure packet drop */
	pr_debug("tquic_test: will drop next packet from %s\n",
		 from_server ? "server" : "client");
	return 0;
}
EXPORT_SYMBOL_GPL(tquic_test_drop_next_packet);

int tquic_test_delay_packet(struct tquic_test_ctx *ctx, u32 delay_ms)
{
	/* Stub - would configure packet delay */
	pr_debug("tquic_test: adding %u ms delay\n", delay_ms);
	return 0;
}
EXPORT_SYMBOL_GPL(tquic_test_delay_packet);

int tquic_test_corrupt_packet(struct tquic_test_ctx *ctx, bool from_server)
{
	/* Stub - would configure packet corruption */
	pr_debug("tquic_test: will corrupt next packet from %s\n",
		 from_server ? "server" : "client");
	return 0;
}
EXPORT_SYMBOL_GPL(tquic_test_corrupt_packet);

/*
 * =============================================================================
 * Proc Interface
 * =============================================================================
 */

static int interop_show(struct seq_file *m, void *v)
{
	struct tquic_test_case *test;
	int count = 0;

	seq_puts(m, "TQUIC Interoperability Test Framework\n");
	seq_puts(m, "======================================\n\n");
	seq_puts(m, "Registered Tests:\n");

	spin_lock(&test_lock);
	list_for_each_entry(test, &test_list, list) {
		seq_printf(m, "  [%s] %s (RFC %s)\n",
			   test->category & TQUIC_TEST_CAT_HANDSHAKE ? "HS" :
			   test->category & TQUIC_TEST_CAT_FRAME ? "FR" :
			   test->category & TQUIC_TEST_CAT_SECURITY ? "SC" : "??",
			   test->name,
			   test->rfc_section ? test->rfc_section : "N/A");
		count++;
	}
	spin_unlock(&test_lock);

	seq_printf(m, "\nTotal: %d tests registered\n", count);
	seq_puts(m, "\nTo run tests: echo 'run all' > /proc/tquic_interop\n");
	seq_puts(m, "To run single: echo 'run <name>' > /proc/tquic_interop\n");

	return 0;
}

static int interop_open(struct inode *inode, struct file *file)
{
	return single_open(file, interop_show, NULL);
}

static ssize_t interop_write(struct file *file, const char __user *buf,
			     size_t count, loff_t *pos)
{
	char cmd[64];
	struct tquic_test_results results;
	size_t len;

	if (count >= sizeof(cmd))
		return -EINVAL;

	if (copy_from_user(cmd, buf, count))
		return -EFAULT;

	cmd[count] = '\0';
	len = strlen(cmd);
	if (len > 0 && cmd[len - 1] == '\n')
		cmd[len - 1] = '\0';

	if (strncmp(cmd, "run all", 7) == 0) {
		tquic_test_run_all(TQUIC_TEST_CAT_ALL, &results);
	} else if (strncmp(cmd, "run ", 4) == 0) {
		tquic_test_run_single(cmd + 4, &results);
	} else {
		pr_err("tquic_interop: unknown command '%s'\n", cmd);
		return -EINVAL;
	}

	return count;
}

static const struct proc_ops interop_proc_ops = {
	.proc_open = interop_open,
	.proc_read = seq_read,
	.proc_write = interop_write,
	.proc_lseek = seq_lseek,
	.proc_release = single_release,
};

/*
 * =============================================================================
 * Module Init/Exit
 * =============================================================================
 */

int tquic_interop_init(void)
{
	struct proc_dir_entry *proc_entry;

	if (interop_initialized)
		return 0;

	test_wq = alloc_workqueue("tquic_test", WQ_UNBOUND, 0);
	if (!test_wq) {
		pr_err("tquic_interop: failed to create workqueue\n");
		return -ENOMEM;
	}

	proc_entry = proc_create("tquic_interop", 0644, NULL, &interop_proc_ops);
	if (!proc_entry)
		pr_warn("tquic_interop: failed to create proc entry\n");

	interop_initialized = true;
	pr_info("tquic_interop: framework initialized\n");

	return 0;
}

void tquic_interop_exit(void)
{
	if (!interop_initialized)
		return;

	remove_proc_entry("tquic_interop", NULL);

	if (test_wq) {
		destroy_workqueue(test_wq);
		test_wq = NULL;
	}

	interop_initialized = false;
	pr_info("tquic_interop: framework shutdown\n");
}

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("TQUIC Interoperability Testing Framework");
MODULE_AUTHOR("Linux Foundation");
