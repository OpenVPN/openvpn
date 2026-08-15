/*
 *  OpenVPN -- An application to securely tunnel IP networks
 *             over a single UDP port, with support for SSL/TLS-based
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

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdlib.h>
#include "syshead.h"
#include "siphash.h"
#include "buffer.h"
#include "crypto.h"
#include "list.h"

static_assert(SIPHASH_KEY_SIZE <= HASH_KEY_LEN, "hash map key size must be at least the same as siphash key size");

uint64_t
siphash_hash_func(const uint8_t *k, uint32_t length, const uint8_t hash_key[SIPHASH_KEY_SIZE])
{
    /* This is not endian-safe but we only care about local hashes here
     * and reversing the byte does not make the hash functions any
     * weaker or less usable */
    union
    {
        uint8_t out[8];
        uint64_t hash;
    } ret;
    siphash(k, length, hash_key, ret.out, sizeof(ret.out));
    return ret.hash;
}