// SPDX-License-Identifier: GPL-2.0-only
/*
 * TQUIC: MASQUE Module Initialization (RFC 9297/9298/9484)
 *
 * Copyright (c) 2026 Justin Adams <spotty118@gmail.com>
 * Kernel implementation by Justin Adams <spotty118@gmail.com>
 */

#include <linux/module.h>
#include <linux/kernel.h>

#include "capsule.h"
#include "http_datagram.h"
#include "connect_udp.h"
#include "connect_ip.h"
#include "quic_proxy.h"

static int __init tquic_masque_module_init(void)
{
	int ret;

	ret = tquic_capsule_init();
	if (ret)
		return ret;

	ret = http_datagram_init();
	if (ret)
		goto err_http_datagram;

	ret = tquic_connect_udp_init();
	if (ret)
		goto err_connect_udp;

	ret = tquic_connect_ip_init();
	if (ret)
		goto err_connect_ip;

	ret = tquic_quic_proxy_init_module();
	if (ret)
		goto err_quic_proxy;

	pr_info("tquic_masque: MASQUE subsystem initialized\n");
	return 0;

err_quic_proxy:
	tquic_connect_ip_exit();
err_connect_ip:
	tquic_connect_udp_exit();
err_connect_udp:
	http_datagram_exit();
err_http_datagram:
	tquic_capsule_exit();
	return ret;
}

static void __exit tquic_masque_module_exit(void)
{
	tquic_quic_proxy_exit_module();
	tquic_connect_ip_exit();
	tquic_connect_udp_exit();
	http_datagram_exit();
	tquic_capsule_exit();

	pr_info("tquic_masque: MASQUE subsystem exited\n");
}

module_init(tquic_masque_module_init);
module_exit(tquic_masque_module_exit);

MODULE_DESCRIPTION("TQUIC MASQUE Subsystem");
MODULE_LICENSE("GPL");
MODULE_AUTHOR("Linux Foundation");
