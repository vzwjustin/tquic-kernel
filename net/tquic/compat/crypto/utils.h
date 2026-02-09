/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef _CRYPTO_UTILS_H
#define _CRYPTO_UTILS_H
/*
 * Compat shim: <crypto/utils.h> was split from <crypto/algapi.h> in 6.5.
 * On older kernels, crypto_xor(), crypto_memneq(), etc. are available via
 * <crypto/algapi.h>.
 *
 * This file is only reached when the kernel does not provide its own
 * <crypto/utils.h>.
 */
#include <crypto/algapi.h>
#endif /* _CRYPTO_UTILS_H */
