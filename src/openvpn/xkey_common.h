/*
 *  OpenVPN -- An application to securely tunnel IP networks
 *             over a single TCP/UDP port, with support for SSL/TLS-based
 *             session authentication and key exchange,
 *             packet encryption, packet authentication, and
 *             packet compression.
 *
 *  Copyright (C) 2021 Selva Nair <selva.nair@gmail.com>
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by the
 *  Free Software Foundation, either version 2 of the License,
 *  or (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License along
 *  with this program; if not, write to the Free Software Foundation, Inc.,
 *  51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#ifndef XKEY_COMMON_H_
#define XKEY_COMMON_H_

#include <openssl/opensslv.h>
#if OPENSSL_VERSION_NUMBER >= 0x30000010L && !defined(DISABLE_XKEY_PROVIDER)
#define HAVE_XKEY_PROVIDER 1

#include <openssl/provider.h>
#include <openssl/core_dispatch.h>

/**
 * Initialization function for OpenVPN external key provider for OpenSSL
 * Follows the function signature of OSSL_PROVIDER init()
 */
OSSL_provider_init_fn xkey_provider_init;

#define XKEY_PROV_PROPS "provider=ovpn.xkey"

#endif /* HAVE_XKEY_PROVIDER */

#endif /* XKEY_COMMON_H_ */
