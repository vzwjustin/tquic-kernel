/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __LINUX_UNALIGNED_H
#define __LINUX_UNALIGNED_H
/*
 * Compat shim: <linux/unaligned.h> was introduced in kernel 6.12.
 * On older kernels, unaligned access helpers live in <asm/unaligned.h>.
 *
 * This file is only reached when the kernel does not provide its own
 * <linux/unaligned.h> (LINUXINCLUDE is searched first).
 */
#include <asm/unaligned.h>
#endif /* __LINUX_UNALIGNED_H */
