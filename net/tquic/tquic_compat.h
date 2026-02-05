/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * TQUIC: Kernel API Compatibility Layer
 *
 * Copyright (c) 2026 Linux Foundation
 *
 * Provides compatibility macros and wrappers for kernel APIs that changed
 * between kernel versions. Include this header in any TQUIC source file
 * that uses timer, socket, or other APIs that vary by kernel version.
 *
 * Kernel 6.12+ compatibility:
 * - Timer API: from_timer() -> timer_container_of()
 * - Timer API: del_timer() -> timer_delete()
 * - Timer API: del_timer_sync() -> timer_delete_sync()
 * - Timer API: hrtimer_init() -> hrtimer_setup()
 * - Socket API: struct sockaddr -> struct sockaddr_unsized in callbacks
 * - Flow routing: flowi4_tos -> flowi4_dscp
 */

#ifndef _TQUIC_COMPAT_H
#define _TQUIC_COMPAT_H

#include <linux/timer.h>
#include <linux/hrtimer.h>

/*
 * Timer API compatibility for kernel 6.12+
 *
 * The timer callback mechanism changed:
 * - Old: void callback(unsigned long data)
 * - New: void callback(struct timer_list *t)
 *
 * The from_timer() macro was replaced with timer_container_of() in 6.12.
 */
#ifndef from_timer
#ifdef timer_container_of
#define from_timer(var, callback_timer, timer_fieldname) \
	timer_container_of(var, callback_timer, timer_fieldname)
#else
#define from_timer(var, callback_timer, timer_fieldname) \
	container_of(callback_timer, typeof(*var), timer_fieldname)
#endif
#endif

/*
 * del_timer() was renamed to timer_delete() in newer kernels
 */
#ifndef del_timer
#define del_timer(t) timer_delete(t)
#endif

/*
 * del_timer_sync() was renamed to timer_delete_sync() in newer kernels
 * (This is also handled via Makefile -D flag, but define here as backup)
 */
#ifndef del_timer_sync
#define del_timer_sync(t) timer_delete_sync(t)
#endif

#endif /* _TQUIC_COMPAT_H */
