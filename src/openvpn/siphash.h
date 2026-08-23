/*
 * SipHash reference C implementation
 *
 * Copyright (c) 2012-2021 Jean-Philippe Aumasson
 * <jeanphilippe.aumasson@gmail.com>
 * Copyright (c) 2012-2014 Daniel J. Bernstein <djb@cr.yp.to>
 *
 * To the extent possible under law, the author(s) have dedicated all copyright
 * and related and neighboring rights to this software to the public domain
 * worldwide. This software is distributed without any warranty.
 *
 * You should have received a copy of the CC0 Public Domain Dedication along
 * with
 * this software. If not, see
 * <http://creativecommons.org/publicdomain/zero/1.0/>.
 */

#ifndef SIPHASH_H
#define SIPHASH_H

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdint.h>
#include <stdio.h>
#include "crypto.h"

/* We need to include this to check for the OPENSSL_IS_AWSLC macro */
#ifdef ENABLE_CRYPTO_OPENSSL
#include <openssl/opensslv.h>
#endif

/* siphash always uses 128-bit keys */
#define SIPHASH_KEY_SIZE 16

/**
 * Calculates SIPHASH using the reference implementation
 */
void
siphash_reference(const void *in, size_t inlen, const void *k,
                  uint8_t *out, size_t outlen);


#if defined(OPENSSL_IS_AWSLC)
#define USE_CRYPOTOLIB_SIPHASH
#include <openssl/siphash.h>
#include <string.h>
#include "error.h"
/**
 *  Computes a SipHash value
 * @param   in      pointer to input data (read-only)
 * @param   inlen   input data length in bytes (any size_t value)
 * @param   k       pointer to the key data (read-only), must be 16 bytes
 * @param   out     pointer to output data (write-only), outlen bytes must be allocated
 * @param   outlen  length of the output in bytes, must be 8
 */
static inline void
siphash_cryptolib(const void *in, const size_t inlen,
                  const void *k, uint8_t *out, const size_t outlen)
{
    ASSERT(outlen == sizeof(uint64_t));
    uint64_t sipout = SIPHASH_24(k, in, inlen);

    memcpy(out, &sipout, sizeof(uint64_t));
}
#endif

static inline void
siphash(const void *in, size_t inlen, const void *k,
        uint8_t *out, size_t outlen)
{
#if defined(USE_CRYPOTOLIB_SIPHASH)
    siphash_cryptolib(in, inlen, k, out, outlen);
#else
    siphash_reference(in, inlen, k, out, outlen);
#endif
}

/**
 * Initialises a SIPHASH key with a random value
 * @param key the key to be initialised
 */
static inline void
siphash_key_init(uint8_t *key)
{
    prng_bytes(key, SIPHASH_KEY_SIZE);
}

/**
 * Wrapper of the siphash function to be able to use it in the
 * hash map.
 *
 * @param k the data to hash
 * @param length length of the data to hash
 * @param hash_key   the siphash key
 * @return a uint64_t containing the result of the hashing
 */
uint64_t
siphash_hash_func(const uint8_t *k, uint32_t length, const uint8_t hash_key[SIPHASH_KEY_SIZE]);
#endif /* ifndef SIPHASH_H */
