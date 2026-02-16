// SPDX-License-Identifier: GPL-2.0-only
/*
 * TQUIC: Crypto Module Initialization
 *
 * Wires up crypto subcomponents for the TQUIC crypto module.
 *
 * Copyright (c) 2026 Justin Adams <spotty118@gmail.com>
 * Kernel implementation by Justin Adams <spotty118@gmail.com>
 */

#include <linux/module.h>
#include <linux/kernel.h>

#include "cert_verify.h"
#include "hw_offload.h"
#include "zero_rtt.h"
#include "../tquic_debug.h"

static int __init __maybe_unused tquic_crypto_module_init(void)
{
	int ret;

	tquic_dbg("tquic_crypto_module_init: initializing crypto subsystem\n");

#if IS_ENABLED(CONFIG_TQUIC_CRYPTO_HW_OFFLOAD)
	ret = tquic_hw_offload_init();
	if (ret)
		return ret;
#endif

#if IS_ENABLED(CONFIG_TQUIC_CERT_VERIFY)
	ret = tquic_cert_verify_init();
	if (ret)
		goto err_cert_verify;
#endif

	ret = tquic_zero_rtt_module_init();
	if (ret)
		goto err_zero_rtt;

	tquic_info("crypto subsystem initialized\n");
	return 0;

err_zero_rtt:
#if IS_ENABLED(CONFIG_TQUIC_CERT_VERIFY)
	tquic_cert_verify_exit();
err_cert_verify:
#endif
#if IS_ENABLED(CONFIG_TQUIC_CRYPTO_HW_OFFLOAD)
	tquic_hw_offload_exit();
#endif
	return ret;
}

static void __exit __maybe_unused tquic_crypto_module_exit(void)
{
	tquic_dbg("tquic_crypto_module_exit: cleaning up crypto subsystem\n");

	tquic_zero_rtt_module_exit();
#if IS_ENABLED(CONFIG_TQUIC_CERT_VERIFY)
	tquic_cert_verify_exit();
#endif
#if IS_ENABLED(CONFIG_TQUIC_CRYPTO_HW_OFFLOAD)
	tquic_hw_offload_exit();
#endif

	tquic_info("crypto subsystem exited\n");
}

#ifndef TQUIC_OUT_OF_TREE
module_init(tquic_crypto_module_init);
module_exit(tquic_crypto_module_exit);
#endif /* TQUIC_OUT_OF_TREE */

MODULE_DESCRIPTION("TQUIC Crypto Subsystem");
MODULE_LICENSE("GPL");
MODULE_AUTHOR("Linux Foundation");
