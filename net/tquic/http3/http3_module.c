// SPDX-License-Identifier: GPL-2.0-only
/*
 * TQUIC: HTTP/3 Module Initialization (RFC 9114)
 *
 * Copyright (c) 2026 Justin Adams <spotty118@gmail.com>
 * Kernel implementation by Justin Adams <spotty118@gmail.com>
 */

#include <linux/module.h>
#include <linux/kernel.h>

#include "http3_priority.h"
#include "qpack.h"

extern int __init tquic_http3_conn_init(void);
extern void __exit tquic_http3_conn_exit(void);
extern int __init tquic_http3_streams_init(void);
extern void __exit tquic_http3_streams_exit(void);

int __init tquic_http3_init(void)
{
	int ret;

#if IS_ENABLED(CONFIG_TQUIC_HTTP3_QPACK)
	ret = qpack_init();
	if (ret)
		return ret;
#endif

	ret = http3_priority_init();
	if (ret)
		goto err_priority;

	ret = tquic_http3_conn_init();
	if (ret)
		goto err_conn;

	ret = tquic_http3_streams_init();
	if (ret)
		goto err_streams;

	pr_info("tquic_http3: HTTP/3 subsystem initialized\n");
	return 0;

err_streams:
	tquic_http3_conn_exit();
err_conn:
	http3_priority_exit();
err_priority:
#if IS_ENABLED(CONFIG_TQUIC_HTTP3_QPACK)
	qpack_exit();
#endif
	return ret;
}

void __exit tquic_http3_exit(void)
{
	tquic_http3_streams_exit();
	tquic_http3_conn_exit();
	http3_priority_exit();
#if IS_ENABLED(CONFIG_TQUIC_HTTP3_QPACK)
	qpack_exit();
#endif

	pr_info("tquic_http3: HTTP/3 subsystem exited\n");
}

module_init(tquic_http3_init);
module_exit(tquic_http3_exit);

MODULE_DESCRIPTION("TQUIC HTTP/3 Subsystem");
MODULE_LICENSE("GPL");
MODULE_AUTHOR("Linux Foundation");
