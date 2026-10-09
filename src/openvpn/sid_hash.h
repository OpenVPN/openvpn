/*
 *  OpenVPN -- An application to securely tunnel IP networks
 *             over a single TCP/UDP port, with support for SSL/TLS-based
 *             session authentication and key exchange,
 *             packet encryption, packet authentication, and
 *             packet compression.
 *
 *  Copyright (C) 2026 OpenVPN Inc <sales@openvpn.net>
 *  Copyright (C) 2026 Arne Schwabe <arne@rfc2549.org>
 *
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

#ifndef SID_HASH_H
#define SID_HASH_H

#include "session_id.h"
#include "multi.h"
#include "list.h"
#include "siphash.h"

inline static void
multi_hash_sid_add(struct multi_context *m, const struct session_id *sid,
                   struct multi_instance *mi)
{
    /* This must only be called if the multi instance is not already present
     * in the hash table */
    ASSERT(!session_id_defined(&mi->sid_hashed_value));

    mi->sid_hashed_value = *sid;

    const uint64_t hv = hash_value(m->sid_hash, &mi->sid_hashed_value);
    struct hash_bucket *bucket = hash_bucket(m->sid_hash, hv);
    hash_add_fast(m->sid_hash, bucket, &mi->sid_hashed_value, hv, mi);
    multi_instance_inc_refcount(mi);
}

static inline struct hash_element *
multi_hash_sid_lookup(struct multi_context *m, const struct session_id *sid)
{
    const uint64_t sid_hv = hash_value(m->sid_hash, sid);
    struct hash_bucket *sid_bucket = hash_bucket(m->sid_hash, sid_hv);
    struct hash_element *he_sid = hash_lookup_fast(m->sid_hash, sid_bucket, sid, sid_hv);
    return he_sid;
}

inline static bool
multi_hash_sid_remove(struct multi_context *m, const struct session_id *sid)
{
    const uint64_t sid_hv = hash_value(m->sid_hash, sid);
    struct hash_bucket *sid_bucket = hash_bucket(m->sid_hash, sid_hv);
    struct hash_element *he_sid = hash_lookup_fast(m->sid_hash, sid_bucket, sid, sid_hv);
    if (he_sid)
    {
        struct multi_instance *mi = he_sid->value;
        ASSERT(hash_remove_fast(m->sid_hash, sid_bucket, sid, sid_hv));
        CLEAR(mi->sid_hashed_value);
        multi_instance_dec_refcount(mi);
        return true;
    }
    else
    {
        return false;
    }
}

/* hashing the session. As the struct is just an 8 byte array
 * hashing is straight forward */
static inline uint64_t
session_id_hash_function(const void *key, const uint8_t hash_key[HASH_KEY_LEN])
{
    return siphash_hash_func(key, sizeof(struct session_id), hash_key);
}

/* wrapper for session_id_equal to have the void* arguments that the
 * hash map requires */
static inline bool
session_id_hash_equal(const void *sid1, const void *sid2)
{
    return session_id_equal((struct session_id *)sid1, (struct session_id *)sid2);
}

#endif
