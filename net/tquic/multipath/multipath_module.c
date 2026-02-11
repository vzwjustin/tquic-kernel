// SPDX-License-Identifier: GPL-2.0-only
/*
 * TQUIC: Multipath Module Initialization (RFC 9369)
 *
 * Copyright (c) 2024-2026 Linux Foundation
 * Kernel implementation by Justin Adams <spotty118@gmail.com>
 */

#include <linux/module.h>
#include <linux/kernel.h>

#include "mp_frame.h"
#include "mp_ack.h"
#include "path_abandon.h"
#include "../tquic_debug.h"

/* mp_deadline.c does not expose a public header */
extern int __init tquic_mp_deadline_init(void);
extern void __exit tquic_mp_deadline_exit(void);

static int __init __maybe_unused tquic_multipath_module_init(void)
{
	int ret;

	ret = tquic_mp_frame_init();
	if (ret)
		return ret;

	ret = tquic_mp_ack_init();
	if (ret)
		goto err_ack;

	ret = tquic_mp_deadline_init();
	if (ret)
		goto err_deadline;

	ret = tquic_mp_abandon_init();
	if (ret)
		goto err_abandon;

	tquic_info("multipath RFC 9369 extension initialized\n");
	return 0;

err_abandon:
	tquic_mp_deadline_exit();
err_deadline:
	tquic_mp_ack_exit();
err_ack:
	tquic_mp_frame_exit();
	return ret;
}

static void __exit __maybe_unused tquic_multipath_module_exit(void)
{
	tquic_mp_abandon_exit();
	tquic_mp_deadline_exit();
	tquic_mp_ack_exit();
	tquic_mp_frame_exit();

	tquic_info("multipath RFC 9369 extension exited\n");
}

/*
 * Module init/exit only for in-tree builds.
 * For out-of-tree builds, tquic_main.c handles init/exit.
 */
#ifndef TQUIC_OUT_OF_TREE
module_init(tquic_multipath_module_init);
module_exit(tquic_multipath_module_exit);

MODULE_DESCRIPTION("TQUIC Multipath Extension (RFC 9369)");
MODULE_LICENSE("GPL");
MODULE_AUTHOR("Linux Foundation");
#endif /* !TQUIC_OUT_OF_TREE */
