/*
 *  OpenVPN -- An application to securely tunnel IP networks
 *             over a single TCP/UDP port, with support for SSL/TLS-based
 *             session authentication and key exchange,
 *             packet encryption, packet authentication, and
 *             packet compression.
 *
 *  Copyright (C) 2002-2010 OpenVPN Technologies, Inc. <sales@openvpn.net>
 *  Copyright (C) 2010 Fox Crypto B.V. <openvpn@fox-it.com>
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
 *  You should have received a copy of the GNU General Public License
 *  along with this program (see the file COPYING included with this
 *  distribution); if not, write to the Free Software Foundation, Inc.,
 *  59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

/**
 * @file Data Channel Cryptography OpenSSL-specific backend interface
 */

#include "syshead.h"

#include "basic.h"
#include "buffer.h"
#include "integer.h"
#include "crypto_backend.h"
#include <openssl/objects.h>
#include <openssl/evp.h>
#include <openssl/des.h>

/*
 * Check for key size creepage.
 */

#if MAX_CIPHER_KEY_LENGTH < EVP_MAX_KEY_LENGTH
#warning Some OpenSSL EVP ciphers now support key lengths greater than MAX_CIPHER_KEY_LENGTH -- consider increasing MAX_CIPHER_KEY_LENGTH
#endif

#if MAX_HMAC_KEY_LENGTH < EVP_MAX_MD_SIZE
#warning Some OpenSSL HMAC message digests now support key lengths greater than MAX_HMAC_KEY_LENGTH -- consider increasing MAX_HMAC_KEY_LENGTH
#endif

/*
 *
 * Random number functions, used in cases where we want
 * reasonably strong cryptographic random number generation
 * without depleting our entropy pool.  Used for random
 * IV values and a number of other miscellaneous tasks.
 *
 */

int rand_bytes(uint8_t *output, int len)
{
  return RAND_bytes (output, len);
}

