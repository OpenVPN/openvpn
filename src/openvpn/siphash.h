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

#include <stdint.h>
#include <stdio.h>
#include <stdbool.h>

/* siphash always uses 128-bit keys */
#define SIPHASH_KEY_SIZE 16

/**
 * Calculates SIPHASH using the reference implementation
 */
int
siphash_reference(const void *in, size_t inlen, const void *k,
                  uint8_t *out, size_t outlen);


static inline int
siphash(const void *in, size_t inlen, const void *k,
        uint8_t *out, size_t outlen)
{
    return siphash_reference(in, inlen, k, out, outlen);
}

#endif /* ifndef SIPHASH_H */