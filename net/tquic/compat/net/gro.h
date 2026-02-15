/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef _NET_GRO_H
#define _NET_GRO_H
/*
 * Compat shim: <net/gro.h> was extracted from netdevice.h in 6.2.
 * On older kernels, GRO structures (struct napi_gro_cb, etc.) are in
 * <linux/netdevice.h>.
 *
 * This file is only reached when the kernel does not provide its own
 * <net/gro.h>.
 */
#include <linux/netdevice.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <net/ip6_checksum.h>
#include <linux/skbuff.h>
#include <net/udp.h>
#endif /* _NET_GRO_H */
