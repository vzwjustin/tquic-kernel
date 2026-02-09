/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef _NET_HOTDATA_H
#define _NET_HOTDATA_H
/*
 * Compat shim: <net/hotdata.h> was introduced in kernel 6.9.
 * On older kernels, these structures do not exist.
 *
 * This file is only reached when the kernel does not provide its own
 * <net/hotdata.h>.  It provides an empty stub so that #include directives
 * from the 6.19 include/ tree don't cause build failures.
 */
#endif /* _NET_HOTDATA_H */
