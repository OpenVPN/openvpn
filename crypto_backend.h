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
 * @file Data Channel Cryptography SSL library-specific backend interface
 */

#ifndef CRYPTO_BACKEND_H_
#define CRYPTO_BACKEND_H_

#include "config.h"

#ifdef USE_OPENSSL
#include "crypto_openssl.h"
#endif

#include "basic.h"


/*
 * This routine should have additional OpenSSL crypto library initialisations
 * used by both crypto and ssl components of OpenVPN.
 */
void crypto_init_lib (void);

void crypto_uninit_lib (void);

void crypto_clear_error (void);

/*
 * Initialise the given named crypto engine.
 */
void crypto_init_lib_engine (const char *engine_name);

#ifdef DMALLOC
/*
 * OpenSSL memory debugging.  If dmalloc debugging is enabled, tell
 * OpenSSL to use our private malloc/realloc/free functions so that
 * we can dispatch them to dmalloc.
 */
void crypto_init_dmalloc (void);
#endif /* DMALLOC */

void show_available_ciphers (void);

void show_available_digests (void);

void show_available_engines (void);

/*
 *
 * Random number functions, used in cases where we want
 * reasonably strong cryptographic random number generation
 * without depleting our entropy pool.  Used for random
 * IV values and a number of other miscellaneous tasks.
 *
 */

/**
 * Wrapper for secure random number generator. Retrieves len bytes of random
 * data, and places it in output.
 *
 * @param output	Output buffer
 * @param len		Length of the output buffer, in bytes
 *
 * @return 		\c 1 on success, \c 0 on failure
 */
int rand_bytes (uint8_t *output, int len);

/*
 *
 * Key functions, allow manipulation of keys.
 *
 */


/**
 * Return number of DES cblocks (1 cblock = length of a single-DES key) for the
 * current key type or 0 if not a DES cipher.
 *
 * @param kt		Type of key
 *
 * @return 		Number of DES cblocks that the key consists of, or 0.
 */
int key_des_num_cblocks (const cipher_kt_t *kt);

/*
 * Check the given DES key. Checks the given key's length, weakness and parity.
 *
 * @param key		Key to check
 * @param key_len	Length of the key, in bytes
 * @param ndc		Number of DES cblocks that the key is made up of.
 *
 * @return 		\c true if the key is valid, \c false otherwise.
 */
bool key_des_check (uint8_t *key, int key_len, int ndc);

/*
 * Fix the given DES key, setting its parity to odd.
 *
 * @param key		Key to check
 * @param key_len	Length of the key, in bytes
 * @param ndc		Number of DES cblocks that the key is made up of.
 */
void key_des_fixup (uint8_t *key, int key_len, int ndc);

/**
 * Encrypt the given block, using DES ECB mode
 *
 * @param key		DES key to use.
 * @param src		Buffer containing the 8-byte source.
 * @param dst		Buffer containing the 8-byte destination
 */
void cipher_des_encrypt_ecb (const unsigned char key[8],
    unsigned char src[8],
    unsigned char dst[8]);

/*
 *
 * Generic cipher key type functions
 *
 */
/*
 * Max size in bytes of any cipher key that might conceivably be used.
 *
 * This value is checked at compile time in crypto.c to make sure
 * it is always at least EVP_MAX_KEY_LENGTH.
 *
 * We define our own value, since this parameter
 * is used to control the size of static key files.
 * If the OpenSSL library increases EVP_MAX_KEY_LENGTH,
 * we don't want our key files to be suddenly rendered
 * unusable.
 */
#define MAX_CIPHER_KEY_LENGTH 64

/*
 *
 * Generic message digest information functions
 *
 */

/*
 * Max size in bytes of any HMAC key that might conceivably be used.
 *
 * This value is checked at compile time in crypto.c to make sure
 * it is always at least EVP_MAX_MD_SIZE.  We define our own value
 * for the same reason as above.
 */
#define MAX_HMAC_KEY_LENGTH 64

#endif /* CRYPTO_BACKEND_H_ */
