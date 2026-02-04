// SPDX-License-Identifier: GPL-2.0-only
/*
 * TQUIC: Path Manager Module Initialization
 */

#include <linux/module.h>
#include <linux/kernel.h>

#include <net/tquic_pm.h>

#include "nat_keepalive.h"

extern int __init tquic_pm_kernel_module_init(void);
extern void __exit tquic_pm_kernel_module_exit(void);

static int __init tquic_pm_module_init(void)
{
	int ret;

	ret = tquic_pm_types_init();
	if (ret)
		return ret;

	ret = tquic_pm_kernel_module_init();
	if (ret)
		goto err_kernel;

#if IS_ENABLED(CONFIG_TQUIC_PM_NETLINK)
	ret = tquic_pm_nl_init();
	if (ret)
		goto err_netlink;
#endif

#if IS_ENABLED(CONFIG_TQUIC_PM_USERSPACE)
	ret = tquic_pm_userspace_init();
	if (ret)
		goto err_userspace;
#endif

	ret = tquic_nat_keepalive_module_init();
	if (ret)
		goto err_keepalive;

	pr_info("tquic_pm: path manager subsystem initialized\n");
	return 0;

err_keepalive:
#if IS_ENABLED(CONFIG_TQUIC_PM_USERSPACE)
	tquic_pm_userspace_exit();
err_userspace:
#endif
#if IS_ENABLED(CONFIG_TQUIC_PM_NETLINK)
	tquic_pm_nl_exit();
err_netlink:
#endif
	tquic_pm_kernel_module_exit();
err_kernel:
	tquic_pm_types_exit();
	return ret;
}

static void __exit tquic_pm_module_exit(void)
{
	tquic_nat_keepalive_module_exit();
#if IS_ENABLED(CONFIG_TQUIC_PM_USERSPACE)
	tquic_pm_userspace_exit();
#endif
#if IS_ENABLED(CONFIG_TQUIC_PM_NETLINK)
	tquic_pm_nl_exit();
#endif
	tquic_pm_kernel_module_exit();
	tquic_pm_types_exit();

	pr_info("tquic_pm: path manager subsystem exited\n");
}

#ifndef TQUIC_OUT_OF_TREE
module_init(tquic_pm_module_init);
module_exit(tquic_pm_module_exit);
#endif /* TQUIC_OUT_OF_TREE */

MODULE_DESCRIPTION("TQUIC Path Manager");
MODULE_LICENSE("GPL");
MODULE_AUTHOR("Linux Foundation");
