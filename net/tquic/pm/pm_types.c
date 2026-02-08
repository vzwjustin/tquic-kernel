// SPDX-License-Identifier: GPL-2.0-only
/*
 * TQUIC Path Manager Type Registration and Per-Netns Infrastructure
 *
 * Copyright (c) 2026 Linux Foundation
 *
 * This file implements the PM type selection framework following MPTCP's
 * pattern. It provides per-netns sysctl configuration and PM type dispatch.
 */

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/sysctl.h>
#include <linux/inetdevice.h>
#include <net/net_namespace.h>
#include <net/netns/generic.h>
#include <net/tquic.h>
#include <net/tquic_pm.h>
#include "../tquic_compat.h"

/* Per-netns sysctl configuration */
static int pm_type_min = TQUIC_PM_TYPE_KERNEL;
static int pm_type_max = TQUIC_PM_TYPE_MAX;
static int auto_discover_min = 0;
static int auto_discover_max = 1;
static int max_paths_min = 1;
static int max_paths_max = 8;
static int validation_retries_min = 1;
static int validation_retries_max = 5;
static int event_rate_limit_min = 0;
static int event_rate_limit_max = 1000;

/* Global PM ops registry - indexed by enum tquic_pm_type */
static struct tquic_pm_ops *pm_ops[__TQUIC_PM_TYPE_MAX];
static DEFINE_MUTEX(pm_ops_lock);

/* Per-netns key */
static unsigned int tquic_pm_pernet_id __read_mostly;

/**
 * tquic_pm_register - Register a path manager type
 * @ops: PM operations structure
 * @type: PM type (KERNEL or USERSPACE)
 *
 * Returns 0 on success, negative error on failure.
 */
int tquic_pm_register(struct tquic_pm_ops *ops, enum tquic_pm_type type)
{
	if (!ops || !ops->name)
		return -EINVAL;

	if (type >= __TQUIC_PM_TYPE_MAX)
		return -EINVAL;

	mutex_lock(&pm_ops_lock);
	if (pm_ops[type]) {
		mutex_unlock(&pm_ops_lock);
		return -EEXIST;
	}

	pm_ops[type] = ops;
	mutex_unlock(&pm_ops_lock);

	pr_info("TQUIC PM: Registered %s path manager\n", ops->name);
	return 0;
}
EXPORT_SYMBOL_GPL(tquic_pm_register);

/**
 * tquic_pm_unregister - Unregister a path manager type
 * @type: PM type to unregister
 */
void tquic_pm_unregister(enum tquic_pm_type type)
{
	if (type >= __TQUIC_PM_TYPE_MAX)
		return;

	mutex_lock(&pm_ops_lock);
	pm_ops[type] = NULL;
	mutex_unlock(&pm_ops_lock);
}
EXPORT_SYMBOL_GPL(tquic_pm_unregister);

/**
 * tquic_pm_get_type - Get PM ops for a network namespace
 * @net: Network namespace
 *
 * Returns the PM ops based on the netns sysctl configuration.
 */
struct tquic_pm_ops *tquic_pm_get_type(struct net *net)
{
	struct tquic_pm_pernet *pernet;
	struct tquic_pm_ops *ops;

	pernet = net_generic(net, tquic_pm_pernet_id);
	if (!pernet)
		return NULL;

	mutex_lock(&pm_ops_lock);
	ops = pm_ops[pernet->pm_type];
	mutex_unlock(&pm_ops_lock);

	return ops;
}
EXPORT_SYMBOL_GPL(tquic_pm_get_type);

/**
 * tquic_pm_get_pernet - Get per-netns PM state
 * @net: Network namespace
 *
 * Returns the per-netns PM configuration and state.
 */
struct tquic_pm_pernet *tquic_pm_get_pernet(struct net *net)
{
	return net_generic(net, tquic_pm_pernet_id);
}
EXPORT_SYMBOL_GPL(tquic_pm_get_pernet);

/**
 * tquic_pm_alloc_path_id - Allocate a unique path ID
 * @net: Network namespace
 *
 * Returns path ID (0-7) or negative error.
 */
u32 tquic_pm_alloc_path_id(struct net *net)
{
	struct tquic_pm_pernet *pernet = tquic_pm_get_pernet(net);
	unsigned long flags;
	u32 path_id;

	if (!pernet)
		return -EINVAL;

	spin_lock_irqsave(&pernet->lock, flags);

	/* Find first available path ID */
	path_id = find_first_zero_bit(&pernet->next_path_id, 8);
	if (path_id >= 8) {
		spin_unlock_irqrestore(&pernet->lock, flags);
		return -ENOSPC;
	}

	set_bit(path_id, &pernet->next_path_id);
	spin_unlock_irqrestore(&pernet->lock, flags);

	return path_id;
}
EXPORT_SYMBOL_GPL(tquic_pm_alloc_path_id);

/**
 * tquic_pm_free_path_id - Free a path ID
 * @net: Network namespace
 * @path_id: Path ID to free
 */
void tquic_pm_free_path_id(struct net *net, u32 path_id)
{
	struct tquic_pm_pernet *pernet = tquic_pm_get_pernet(net);
	unsigned long flags;

	if (!pernet || path_id >= 8)
		return;

	spin_lock_irqsave(&pernet->lock, flags);
	clear_bit(path_id, &pernet->next_path_id);
	spin_unlock_irqrestore(&pernet->lock, flags);
}
EXPORT_SYMBOL_GPL(tquic_pm_free_path_id);

/*
 * Per-netns sysctl table
 *
 * Following MPTCP pattern: each netns gets its own sysctl table instance
 * pointing to pernet-specific data fields.
 */
static struct ctl_table tquic_pm_sysctl_table[] = {
	{
		.procname	= "type",
		.maxlen		= sizeof(u8),
		.mode		= 0644,
		.proc_handler	= proc_dou8vec_minmax,
		.extra1		= &pm_type_min,
		.extra2		= &pm_type_max,
	},
	{
		.procname	= "auto_discover",
		.maxlen		= sizeof(u8),
		.mode		= 0644,
		.proc_handler	= proc_dou8vec_minmax,
		.extra1		= &auto_discover_min,
		.extra2		= &auto_discover_max,
	},
	{
		.procname	= "max_paths",
		.maxlen		= sizeof(u8),
		.mode		= 0644,
		.proc_handler	= proc_dou8vec_minmax,
		.extra1		= &max_paths_min,
		.extra2		= &max_paths_max,
	},
	{
		.procname	= "validation_retries",
		.maxlen		= sizeof(u8),
		.mode		= 0644,
		.proc_handler	= proc_dou8vec_minmax,
		.extra1		= &validation_retries_min,
		.extra2		= &validation_retries_max,
	},
	{
		.procname	= "event_rate_limit",
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= proc_dointvec_minmax,
		.extra1		= &event_rate_limit_min,
		.extra2		= &event_rate_limit_max,
	},
	{ }
};

/* Number of valid entries (exclude the null terminator). */
#define TQUIC_PM_SYSCTL_TABLE_ENTRIES (ARRAY_SIZE(tquic_pm_sysctl_table) - 1)

/*
 * Per-netns initialization and cleanup
 */
static int __net_init tquic_pm_net_init(struct net *net)
{
	struct tquic_pm_pernet *pernet;
	struct ctl_table *table;
	struct ctl_table_header *hdr;

	pernet = net_generic(net, tquic_pm_pernet_id);

	/* Initialize defaults */
	pernet->pm_type = TQUIC_PM_TYPE_KERNEL;
	pernet->auto_discover = 1;
	pernet->max_paths = 8;
	pernet->validation_retries = 3;
	pernet->event_rate_limit = 100;

	spin_lock_init(&pernet->lock);
	INIT_LIST_HEAD(&pernet->endpoint_list);
	pernet->next_path_id = 0;

	/* Setup sysctl for non-init_net namespaces */
	if (!net_eq(net, &init_net)) {
		table = kmemdup(tquic_pm_sysctl_table,
				sizeof(tquic_pm_sysctl_table), GFP_KERNEL);
		if (!table)
			return -ENOMEM;

		/* Point .data to pernet fields */
		table[0].data = &pernet->pm_type;
		table[1].data = &pernet->auto_discover;
		table[2].data = &pernet->max_paths;
		table[3].data = &pernet->validation_retries;
		table[4].data = &pernet->event_rate_limit;

		hdr = register_net_sysctl_sz(net, "net/tquic/pm", table,
					     TQUIC_PM_SYSCTL_TABLE_ENTRIES);
		if (!hdr) {
			kfree(table);
#ifdef TQUIC_OUT_OF_TREE
			pr_warn("TQUIC PM: sysctl registration failed; continuing without /proc/sys/net/tquic/pm\n");
			return 0;
#else
			return -ENOMEM;
#endif
		}
	} else {
		/* init_net: use static table, point .data to pernet */
		tquic_pm_sysctl_table[0].data = &pernet->pm_type;
		tquic_pm_sysctl_table[1].data = &pernet->auto_discover;
		tquic_pm_sysctl_table[2].data = &pernet->max_paths;
		tquic_pm_sysctl_table[3].data = &pernet->validation_retries;
		tquic_pm_sysctl_table[4].data = &pernet->event_rate_limit;

		hdr = register_net_sysctl_sz(net, "net/tquic/pm",
					     tquic_pm_sysctl_table,
					     TQUIC_PM_SYSCTL_TABLE_ENTRIES);
		if (!hdr) {
#ifdef TQUIC_OUT_OF_TREE
			pr_warn("TQUIC PM: sysctl registration failed; continuing without /proc/sys/net/tquic/pm\n");
			return 0;
#else
			return -ENOMEM;
#endif
		}
	}

	pernet->sysctl_header = hdr;

	/* Call PM-specific init if registered */
	if (pm_ops[pernet->pm_type] && pm_ops[pernet->pm_type]->init)
		pm_ops[pernet->pm_type]->init(net);

	return 0;
}

static void __net_exit tquic_pm_net_exit(struct net *net)
{
	struct tquic_pm_pernet *pernet;
	struct tquic_pm_endpoint *ep, *tmp;

	pernet = net_generic(net, tquic_pm_pernet_id);

	if (pernet->sysctl_header) {
		TQUIC_CTL_TABLE *table = pernet->sysctl_header->ctl_table_arg;

		unregister_net_sysctl_table(pernet->sysctl_header);
		if (!net_eq(net, &init_net))
			kfree((void *)table);
		pernet->sysctl_header = NULL;
	}

	/* Call PM-specific cleanup */
	if (pm_ops[pernet->pm_type] && pm_ops[pernet->pm_type]->release)
		pm_ops[pernet->pm_type]->release(net);

	/* Clean up endpoints */
	spin_lock_bh(&pernet->lock);
	list_for_each_entry_safe(ep, tmp, &pernet->endpoint_list, list) {
		list_del(&ep->list);
		kfree(ep);
	}
	spin_unlock_bh(&pernet->lock);
}

static struct pernet_operations tquic_pm_pernet_ops = {
	.init = tquic_pm_net_init,
	.exit = tquic_pm_net_exit,
	.id = &tquic_pm_pernet_id,
	.size = sizeof(struct tquic_pm_pernet),
};

/**
 * tquic_pm_types_init - Initialize PM type framework
 *
 * Called during TQUIC module initialization.
 */
int __init tquic_pm_types_init(void)
{
	int ret;

	ret = register_pernet_subsys(&tquic_pm_pernet_ops);
	if (ret < 0) {
		pr_err("TQUIC PM: Failed to register pernet subsystem: %d\n",
		       ret);
		return ret;
	}

	pr_info("TQUIC PM: Type framework initialized\n");
	return 0;
}

/**
 * tquic_pm_types_exit - Cleanup PM type framework
 */
void __exit tquic_pm_types_exit(void)
{
	unregister_pernet_subsys(&tquic_pm_pernet_ops);
	pr_info("TQUIC PM: Type framework cleaned up\n");
}
