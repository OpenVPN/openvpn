/*
 *  OpenVPN -- An application to securely tunnel IP networks
 *             over a single TCP/UDP port, with support for SSL/TLS-based
 *             session authentication and key exchange,
 *             packet encryption, packet authentication, and
 *             packet compression.
 *
 *  Copyright (C) 2002-2026 OpenVPN Inc <sales@openvpn.net>
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
#ifndef SIPHASH_OPENSSL_H
#define SIPHASH_OPENSSL_H

#include <stdint.h>
#include <stdio.h>
#include <stdbool.h>


/* Prototypes for an implementation of SIPHASH in a crypto library */
/**
 *
 * @param hash_size the size of the output hash size
 * @return initialised context for siphash
 */
void *
siphash_openssl_init(size_t hash_size);


/**
 * Calculates SIPHASH using the crypto library function.
 */
int
siphash_openssl(void *sip_context, const void *in, size_t inlen,
                const void *k, uint8_t *out, size_t outlen);

/**
 * Free the siphash context used for the crypto library
 * @param sip_context
 */
void
siphash_openssl_uninit(void *sip_context);

/**
 * Returns if the crypto library is available (and should be used)
 *
 * This returns if there is a crypto library version of Siphash24 is
 * available and should be used (OpenSSL 3/4 version is quite slow, so
 * we prefer the reference implementation)
 *
 */
bool
siphash_openssl_available(void *sip_context);
#endif /* ifndef SIPHASH_OPENSSL_H */