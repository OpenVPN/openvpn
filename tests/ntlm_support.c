/*
 *  OpenVPN -- An application to securely tunnel IP networks
 *             over a single UDP port, with support for SSL/TLS-based
 *             session authentication and key exchange,
 *             packet encryption, packet authentication, and
 *             packet compression.
 *
 * Copyright (C) 2023-2025 OpenVPN Inc <sales@openvpn.net>
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

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "syshead.h"

#include "crypto.h"
#include "error.h"

int
main(void)
{
#ifdef NTLM
#if defined(ENABLE_CRYPTO_OPENSSL)
    provider_t *legacy = crypto_load_provider("legacy");
    provider_t *def = crypto_load_provider("default");
#endif
    if (!md_valid("MD4"))
    {
        msg(M_FATAL, "MD4 not supported");
    }
    if (!md_valid("MD5"))
    {
        msg(M_FATAL, "MD5 not supported");
    }
#if defined(ENABLE_CRYPTO_OPENSSL)
    crypto_unload_provider("legacy", legacy);
    crypto_unload_provider("default", def);
#endif
#else  /* ifdef NTLM */
    msg(M_FATAL, "NTLM support not compiled in");
#endif
}
