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

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "syshead.h"


#include "integer.h"
#include "list.h"

#include "crypto.h"

struct hash *
hash_init(const uint32_t n_buckets,
          uint64_t (*hash_function)(const void *key, const uint8_t hash_key[HASH_KEY_LEN]),
          bool (*compare_function)(const void *key1, const void *key2))
{
    struct hash *h;

    ASSERT(n_buckets > 0);
    ALLOC_OBJ_CLEAR(h, struct hash);
    h->n_buckets = (uint32_t)adjust_power_of_2(n_buckets);
    h->mask = h->n_buckets - 1;
    h->hash_function = hash_function;
    h->compare_function = compare_function;

    /* create random hash key */
    prng_bytes(h->hash_key, sizeof(h->hash_key));

    ALLOC_ARRAY(h->buckets, struct hash_bucket, h->n_buckets);
    for (uint32_t i = 0; i < h->n_buckets; ++i)
    {
        struct hash_bucket *b = &h->buckets[i];
        b->list = NULL;
    }
    return h;
}

void
hash_free(struct hash *hash)
{
    for (uint32_t i = 0; i < hash->n_buckets; ++i)
    {
        struct hash_bucket *b = &hash->buckets[i];
        struct hash_element *he = b->list;

        while (he)
        {
            struct hash_element *next = he->next;
            free(he);
            he = next;
        }
    }
    free(hash->buckets);
    free(hash);
}

struct hash_element *
hash_lookup_fast(struct hash *hash, struct hash_bucket *bucket, const void *key, uint64_t hv)
{
    struct hash_element *he;
    struct hash_element *prev = NULL;

    he = bucket->list;

    while (he)
    {
        if (hv == he->hash_value && (*hash->compare_function)(key, he->key))
        {
            /* move to head of list */
            if (prev)
            {
                prev->next = he->next;
                he->next = bucket->list;
                bucket->list = he;
            }
            return he;
        }
        prev = he;
        he = he->next;
    }

    return NULL;
}

bool
hash_remove_fast(struct hash *hash, struct hash_bucket *bucket, const void *key, uint64_t hv)
{
    struct hash_element *he;
    struct hash_element *prev = NULL;

    he = bucket->list;

    while (he)
    {
        if (hv == he->hash_value && (*hash->compare_function)(key, he->key))
        {
            if (prev)
            {
                prev->next = he->next;
            }
            else
            {
                bucket->list = he->next;
            }
            free(he);
            --hash->n_elements;
            return true;
        }
        prev = he;
        he = he->next;
    }
    return false;
}

bool
hash_add(struct hash *hash, const void *key, void *value, bool replace)
{
    uint64_t hv;
    struct hash_bucket *bucket;
    struct hash_element *he;
    bool ret = false;

    hv = hash_value(hash, key);
    bucket = &hash->buckets[hv & hash->mask];

    if ((he = hash_lookup_fast(hash, bucket, key, hv))) /* already exists? */
    {
        if (replace)
        {
            he->value = value;
            ret = true;
        }
    }
    else
    {
        hash_add_fast(hash, bucket, key, hv, value);
        ret = true;
    }

    return ret;
}

void
hash_remove_by_value(struct hash *hash, void *value)
{
    struct hash_iterator hi;
    struct hash_element *he;

    hash_iterator_init(hash, &hi);
    while ((he = hash_iterator_next(&hi)))
    {
        if (he->value == value)
        {
            hash_iterator_delete_element(&hi);
        }
    }
    hash_iterator_free(&hi);
}

static void
hash_remove_marked(struct hash *hash, struct hash_bucket *bucket)
{
    struct hash_element *prev = NULL;
    struct hash_element *he = bucket->list;

    while (he)
    {
        if (!he->key) /* marked? */
        {
            struct hash_element *newhe;
            if (prev)
            {
                newhe = prev->next = he->next;
            }
            else
            {
                newhe = bucket->list = he->next;
            }
            free(he);
            --hash->n_elements;
            he = newhe;
        }
        else
        {
            prev = he;
            he = he->next;
        }
    }
}

void
hash_iterator_init_range(struct hash *hash, struct hash_iterator *hi, uint32_t start_bucket,
                         uint32_t end_bucket)
{
    if (end_bucket > hash->n_buckets)
    {
        end_bucket = hash->n_buckets;
    }

    ASSERT(start_bucket <= end_bucket);

    hi->hash = hash;
    hi->elem = NULL;
    hi->bucket = NULL;
    hi->last = NULL;
    hi->bucket_marked = false;
    hi->bucket_index_start = start_bucket;
    hi->bucket_index_end = end_bucket;
    hi->bucket_index = hi->bucket_index_start - 1;
}

void
hash_iterator_init(struct hash *hash, struct hash_iterator *hi)
{
    hash_iterator_init_range(hash, hi, 0, hash->n_buckets);
}

static inline void
hash_iterator_lock(struct hash_iterator *hi, struct hash_bucket *b)
{
    hi->bucket = b;
    hi->last = NULL;
    hi->bucket_marked = false;
}

static inline void
hash_iterator_unlock(struct hash_iterator *hi)
{
    if (hi->bucket)
    {
        if (hi->bucket_marked)
        {
            hash_remove_marked(hi->hash, hi->bucket);
            hi->bucket_marked = false;
        }
        hi->bucket = NULL;
        hi->last = NULL;
    }
}

static inline void
hash_iterator_advance(struct hash_iterator *hi)
{
    hi->last = hi->elem;
    hi->elem = hi->elem->next;
}

void
hash_iterator_free(struct hash_iterator *hi)
{
    hash_iterator_unlock(hi);
}

struct hash_element *
hash_iterator_next(struct hash_iterator *hi)
{
    struct hash_element *ret = NULL;
    if (hi->elem)
    {
        ret = hi->elem;
        hash_iterator_advance(hi);
    }
    else
    {
        while (++hi->bucket_index < hi->bucket_index_end)
        {
            struct hash_bucket *b;
            hash_iterator_unlock(hi);
            b = &hi->hash->buckets[hi->bucket_index];
            if (b->list)
            {
                hash_iterator_lock(hi, b);
                hi->elem = b->list;
                if (hi->elem)
                {
                    ret = hi->elem;
                    hash_iterator_advance(hi);
                    break;
                }
            }
        }
    }
    return ret;
}

void
hash_iterator_delete_element(struct hash_iterator *hi)
{
    ASSERT(hi->last);
    hi->last->key = NULL;
    hi->bucket_marked = true;
}
