/*
 *  OpenVPN -- An application to securely tunnel IP networks
 *             over a single TCP/UDP port, with support for SSL/TLS-based
 *             session authentication and key exchange,
 *             packet encryption, packet authentication, and
 *             packet compression.
 *
 *  Copyright (C) 2002-2022 OpenVPN Inc <sales@openvpn.net>
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
 *  with this program; if not, write to the Free Software Foundation, Inc.,
 *  51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#ifndef LIST_H
#define LIST_H

/*
 * This code is a fairly straightforward hash
 * table implementation using Bob Jenkins'
 * hash function.
 *
 * Hash tables are used in OpenVPN to keep track of
 * client instances over various key spaces.
 */

/* define this to enable special list test mode */
/*#define LIST_TEST*/

#include "basic.h"
#include "buffer.h"

#define hashsize(n) ((uint32_t)1<<(n))
#define hashmask(n) (hashsize(n)-1)

struct hash_element
{
    void *value;
    const void *key;
    unsigned int hash_value;
    struct hash_element *next;
};

struct hash_bucket
{
    struct hash_element *list;
};

struct hash
{
    int n_buckets;
    int n_elements;
    int mask;
    uint32_t iv;
    uint32_t (*hash_function)(const void *key, uint32_t iv);
    bool (*compare_function)(const void *key1, const void *key2); /* return true if equal */
    struct hash_bucket *buckets;
};

struct hash *hash_init(const int n_buckets,
                       const uint32_t iv,
                       uint32_t (*hash_function)(const void *key, uint32_t iv),
                       bool (*compare_function)(const void *key1, const void *key2));

void hash_free(struct hash *hash);

bool hash_add(struct hash *hash, const void *key, void *value, bool replace);

struct hash_element *hash_lookup_fast(struct hash *hash,
                                      struct hash_bucket *bucket,
                                      const void *key,
                                      uint32_t hv);

bool hash_remove_fast(struct hash *hash,
                      struct hash_bucket *bucket,
                      const void *key,
                      uint32_t hv);

void hash_remove_by_value(struct hash *hash, void *value);

struct hash_iterator
{
    struct hash *hash;
    int bucket_index;
    struct hash_bucket *bucket;
    struct hash_element *elem;
    struct hash_element *last;
    bool bucket_marked;
    int bucket_index_start;
    int bucket_index_end;
};

void hash_iterator_init_range(struct hash *hash,
                              struct hash_iterator *hi,
                              int start_bucket,
                              int end_bucket);

void hash_iterator_init(struct hash *hash, struct hash_iterator *iter);

struct hash_element *hash_iterator_next(struct hash_iterator *hi);

void hash_iterator_delete_element(struct hash_iterator *hi);

void hash_iterator_free(struct hash_iterator *hi);

uint32_t hash_func(const uint8_t *k, uint32_t length, uint32_t initval);

#ifdef LIST_TEST
void list_test(void);

#endif

static inline uint32_t
hash_value(const struct hash *hash, const void *key)
{
    return (*hash->hash_function)(key, hash->iv);
}

static inline int
hash_n_elements(const struct hash *hash)
{
    return hash->n_elements;
}

static inline int
hash_n_buckets(const struct hash *hash)
{
    return hash->n_buckets;
}

static inline struct hash_bucket *
hash_bucket(struct hash *hash, uint32_t hv)
{
    return &hash->buckets[hv & hash->mask];
}

static inline void *
hash_lookup(struct hash *hash, const void *key)
{
    void *ret = NULL;
    struct hash_element *he;
    uint32_t hv = hash_value(hash, key);
    struct hash_bucket *bucket = &hash->buckets[hv & hash->mask];

    he = hash_lookup_fast(hash, bucket, key, hv);
    if (he)
    {
        ret = he->value;
    }

    return ret;
}

/* NOTE: assumes that key is not a duplicate */
static inline void
hash_add_fast(struct hash *hash,
              struct hash_bucket *bucket,
              const void *key,
              uint32_t hv,
              void *value)
{
    struct hash_element *he;

    ALLOC_OBJ(he, struct hash_element);
    he->value = value;
    he->key = key;
    he->hash_value = hv;
    he->next = bucket->list;
    bucket->list = he;
    ++hash->n_elements;
}

static inline bool
hash_remove(struct hash *hash, const void *key)
{
    uint32_t hv;
    struct hash_bucket *bucket;
    bool ret;

    hv = hash_value(hash, key);
    bucket = &hash->buckets[hv & hash->mask];
    ret = hash_remove_fast(hash, bucket, key, hv);
    return ret;
}

#endif /* LIST */
