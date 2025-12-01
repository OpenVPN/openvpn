/*
 *  OpenVPN -- An application to securely tunnel IP networks
 *             over a single TCP/UDP port, with support for SSL/TLS-based
 *             session authentication and key exchange,
 *             packet encryption, packet authentication, and
 *             packet compression.
 *
 *  Copyright (C) 2023 Sentyron B.V. <openvpn@sentyron.com>
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License version 2
 *  as published by the Free Software Foundation.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License along
 *  with this program; if not, see <https://www.gnu.org/licenses/>.
 */

/**
 * @file
 * mbedtls compatibility stub.
 * This file provides compatibility stubs to handle API differences between
 * different versions of Mbed TLS.
 */

#ifndef MBEDTLS_COMPAT_H_
#define MBEDTLS_COMPAT_H_

#include "syshead.h"

#include "errlevel.h"

#ifdef HAVE_PSA_CRYPTO_H
#include <psa/crypto.h>
#endif

static inline void
mbedtls_compat_psa_crypto_init(void)
{
#if defined(HAVE_PSA_CRYPTO_H) && defined(MBEDTLS_PSA_CRYPTO_C)
    if (psa_crypto_init() != PSA_SUCCESS)
    {
        msg(M_FATAL, "mbedtls: psa_crypto_init() failed");
    }
#else
    return;
#endif
}

#endif /* MBEDTLS_COMPAT_H_ */
