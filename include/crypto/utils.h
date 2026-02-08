/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Cryptographic utilities - compat wrapper for out-of-tree builds
 *
 * On kernels >= 6.4, crypto_memneq/crypto_xor were moved from
 * crypto/algapi.h to crypto/utils.h.  This local header ensures
 * #include <crypto/utils.h> works on all kernel versions 5.4+.
 *
 * Since the local include/ directory shadows kernel headers, we
 * cannot use #include_next reliably.  Instead, we provide the
 * declarations directly for the functions TQUIC actually uses.
 */
#ifndef _TQUIC_CRYPTO_UTILS_COMPAT_H
#define _TQUIC_CRYPTO_UTILS_COMPAT_H

#include <linux/types.h>

/*
 * crypto_memneq - Compare two areas of memory without leaking
 *                 timing information.
 *
 * Available in all kernels 5.4+ (originally via crypto/algapi.h,
 * moved to crypto/utils.h in ~6.4).  The symbol is always exported
 * by the crypto subsystem, so we just need the declaration.
 */
noinline unsigned long __crypto_memneq(const void *a, const void *b,
				       size_t size);

static inline int crypto_memneq(const void *a, const void *b, size_t size)
{
	return __crypto_memneq(a, b, size) != 0UL ? 1 : 0;
}

#endif	/* _TQUIC_CRYPTO_UTILS_COMPAT_H */
