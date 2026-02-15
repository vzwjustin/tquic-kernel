/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef _NET_GSO_H
#define _NET_GSO_H
/*
 * Compat shim: <net/gso.h> was extracted from skbuff.h/netdevice.h in 6.2.
 * On older kernels, GSO helpers (struct skb_gso_cb, SKB_GSO_CB, etc.) are
 * still available in the original headers.
 *
 * This file is only reached when the kernel does not provide its own
 * <net/gso.h>.
 */
#include <linux/skbuff.h>
#include <linux/netdevice.h>
#endif /* _NET_GSO_H */
