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

#ifdef ENABLE_CRYPTO_OPENSSL
#include "crypto_openssl.h"
#endif
#ifdef ENABLE_CRYPTO_POLARSSL
#include "crypto_polarssl.h"
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

/**
 * Translate a data channel cipher name from the OpenVPN config file
 * 'language' to the crypto library specific name.
 */
const char * translate_cipher_name_from_openvpn (const char *cipher_name);

/**
 * Translate a data channel cipher name from the crypto library specific name
 * to the OpenVPN config file 'language'.
 */
const char * translate_cipher_name_from_openvpn (const char *cipher_name);

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
void cipher_des_encrypt_ecb (const unsigned char key[DES_KEY_LENGTH],
    unsigned char src[DES_KEY_LENGTH],
    unsigned char dst[DES_KEY_LENGTH]);

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

/**
 * Return cipher parameters, based on the given cipher name. The
 * contents of these parameters are library-specific, and can be used to
 * initialise encryption/decryption.
 *
 * @param ciphername 	Name of the cipher to retrieve parameters for (e.g.
 * 			\c AES-128-CBC).
 *
 * @return		A statically allocated structure containing parameters
 * 			for the given cipher.
 */
const cipher_kt_t * cipher_kt_get (const char *ciphername);

/**
 * Retrieve a string describing the cipher (e.g. \c AES-128-CBC).
 *
 * @param cipher_kt 	Static cipher parameters
 *
 * @return a statically allocated string describing the cipher.
 */
const char * cipher_kt_name (const cipher_kt_t *cipher_kt);

/**
 * Returns the size of keys used by the cipher, in bytes. If the cipher has a
 * variable key size, return the default key size.
 *
 * @param cipher_kt 	Static cipher parameters
 *
 * @return 		(Default) size of keys used by the cipher, in bytes.
 */
int cipher_kt_key_size (const cipher_kt_t *cipher_kt);

/**
 * Returns the size of the IV used by the cipher, in bytes, or 0 if no IV is
 * used.
 *
 * @param cipher_kt 	Static cipher parameters
 *
 * @return 		Size of the IV, in bytes, or 0 if the cipher does not
 * 			use an IV.
 */
int cipher_kt_iv_size (const cipher_kt_t *cipher_kt);

/**
 * Returns the block size of the cipher, in bytes.
 *
 * @param cipher_kt 	Static cipher parameters
 *
 * @return 		Block size, in bytes.
 */
int cipher_kt_block_size (const cipher_kt_t *cipher_kt);

/**
 * Returns the mode that the cipher runs in.
 *
 * @param cipher_kt	Static cipher parameters. May not be NULL.
 *
 * @return 		Cipher mode, either \c OPENVPN_MODE_CBC, \c
 * 			OPENVPN_MODE_OFB or \c OPENVPN_MODE_CFB
 */
int cipher_kt_mode (const cipher_kt_t *cipher_kt);

/**
 * Check if the supplied cipher is a supported CBC mode cipher.
 *
 * @param cipher	Static cipher parameters.
 *
 * @return		true iff the cipher is a CBC mode cipher.
 */
bool cipher_kt_mode_cbc(const cipher_kt_t *cipher);

/**
 * Check if the supplied cipher is a supported OFB or CFB mode cipher.
 *
 * @param cipher	Static cipher parameters.
 *
 * @return		true iff the cipher is a OFB or CFB mode cipher.
 */
bool cipher_kt_mode_ofb_cfb(const cipher_kt_t *cipher);


/**
 *
 * Generic cipher functions
 *
 */

/**
 * Initialise a cipher context, based on the given key and key type.
 *
 * @param ctx		Cipher context. May not be NULL
 * @param key		Buffer containing the key to use
 * @param key_len 	Length of the key, in bytes
 * @param kt		Static cipher parameters to use
 * @param enc		Whether to encrypt or decrypt (either
 * 			\c POLARSSL_OP_ENCRYPT or \c POLARSSL_OP_DECRYPT).
 */
void cipher_ctx_init (cipher_ctx_t *ctx, uint8_t *key, int key_len,
    const cipher_kt_t *kt, int enc);

/**
 * Cleanup the specified context.
 *
 * @param ctx	Cipher context to cleanup.
 */
void cipher_ctx_cleanup (cipher_ctx_t *ctx);

/**
 * Returns the size of the IV used by the cipher, in bytes, or 0 if no IV is
 * used.
 *
 * @param ctx	 	The cipher's context
 *
 * @return 		Size of the IV, in bytes, or \c 0 if the cipher does not
 * 			use an IV or ctx was NULL.
 */
int cipher_ctx_iv_length (const cipher_ctx_t *ctx);

/**
 * Returns the block size of the cipher, in bytes.
 *
 * @param ctx	 	The cipher's context
 *
 * @return 		Block size, in bytes, or 0 if ctx was NULL.
 */
int cipher_ctx_block_size (const cipher_ctx_t *ctx);

/**
 * Returns the mode that the cipher runs in.
 *
 * @param ctx 		Cipher's context. May not be NULL.
 *
 * @return 		Cipher mode, either \c OPENVPN_MODE_CBC, \c
 * 			OPENVPN_MODE_OFB or \c OPENVPN_MODE_CFB
 */
int cipher_ctx_mode (const cipher_ctx_t *ctx);

/**
 * Returns the static cipher parameters for this context.
 *
 * @param ctx 		Cipher's context. May not be NULL.
 *
 * @return 		Static cipher parameters for the supplied context.
 */
const cipher_kt_t *cipher_ctx_get_cipher_kt (const cipher_ctx_t *ctx)
  __attribute__((nonnull));

/**
 * Resets the given cipher context, setting the IV to the specified value.
 * Preserves the associated key information.
 *
 * @param ctx 		Cipher's context. May not be NULL.
 * @param iv_buf	The IV to use.
 *
 * @return 		\c 0 on failure, \c 1 on success.
 */
int cipher_ctx_reset (cipher_ctx_t *ctx, uint8_t *iv_buf);

/**
 * Updates the given cipher context, encrypting data in the source buffer, and
 * placing any complete blocks in the destination buffer.
 *
 * Note that if a complete block cannot be written, data is cached in the
 * context, and emitted at a later call to \c cipher_ctx_update, or by a call
 * to \c cipher_ctx_final(). This implies that dst should have enough room for
 * src_len + \c cipher_ctx_block_size().
 *
 * @param ctx 		Cipher's context. May not be NULL.
 * @param dst		Destination buffer
 * @param dst_len	Length of the destination buffer, in bytes
 * @param src		Source buffer
 * @param src_len	Length of the source buffer, in bytes
 *
 * @return 		\c 0 on failure, \c 1 on success.
 */
int cipher_ctx_update (cipher_ctx_t *ctx, uint8_t *dst, int *dst_len,
    uint8_t *src, int src_len);

/**
 * Pads the final cipher block using PKCS padding, and output to the destination
 * buffer.
 *
 * @param ctx 		Cipher's context. May not be NULL.
 * @param dst		Destination buffer
 * @param dst_len	Length of the destination buffer, in bytes
 *
 * @return 		\c 0 on failure, \c 1 on success.
 */
int cipher_ctx_final (cipher_ctx_t *ctx, uint8_t *dst, int *dst_len);

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

/**
 * Return message digest parameters, based on the given digest name. The
 * contents of these parameters are library-specific, and can be used to
 * initialise HMAC or message digest operations.
 *
 * @param digest	Name of the digest to retrieve parameters for (e.g.
 * 			\c MD5).
 *
 * @return		A statically allocated structure containing parameters
 * 			for the given message digest.
 */
const md_kt_t * md_kt_get (const char *digest);

/**
 * Retrieve a string describing the digest digest (e.g. \c SHA1).
 *
 * @param kt 		Static message digest parameters
 *
 * @return 		Statically allocated string describing the message
 * 			digest.
 */
const char * md_kt_name (const md_kt_t *kt);

/**
 * Returns the size of the message digest, in bytes.
 *
 * @param kt 		Static message digest parameters
 *
 * @return 		Message digest size, in bytes, or 0 if ctx was NULL.
 */
int md_kt_size (const md_kt_t *kt);


/*
 *
 * Generic message digest functions
 *
 */

/*
 * Calculates the message digest for the given buffer.
 *
 * @param kt 		Static message digest parameters
 * @param src		Buffer to digest. May not be NULL.
 * @param src_len	The length of the incoming buffer.
 * @param dst		Buffer to write the message digest to. May not be NULL.
 *
 * @return		\c 1 on success, \c 0 on failure
 */
int md_full (const md_kt_t *kt, const uint8_t *src, int src_len, uint8_t *dst);

/*
 * Initialises the given message digest context.
 *
 * @param ctx		Message digest context
 * @param kt 		Static message digest parameters
 */
void md_ctx_init (md_ctx_t *ctx, const md_kt_t *kt);

/*
 * Free the given message digest context.
 *
 * @param ctx		Message digest context
 */
void md_ctx_cleanup(md_ctx_t *ctx);

/*
 * Returns the size of the message digest output by the given context
 *
 * @param ctx 		Message digest context.
 *
 * @return 		Size of the message digest, or \0 if ctx is NULL.
 */
int md_ctx_size (const md_ctx_t *ctx);

/*
 * Process the given data for use in the message digest.
 *
 * @param ctx		Message digest context. May not be NULL.
 * @param src		Buffer to digest. May not be NULL.
 * @param src_len	The length of the incoming buffer.
 */
void md_ctx_update (md_ctx_t *ctx, const uint8_t *src, int src_len);

/*
 * Output the message digest to the given buffer.
 *
 * @param ctx		Message digest context. May not be NULL.
 * @param dst		Buffer to write the message digest to. May not be NULL.
 */
void md_ctx_final (md_ctx_t *ctx, uint8_t *dst);


/*
 *
 * Generic HMAC functions
 *
 */

/*
 * Initialises the given HMAC context, using the given digest
 * and key.
 *
 * @param ctx		HMAC context to intialise
 * @param key		The key to use for the HMAC
 * @param key_len	The key length to use
 * @param kt 		Static message digest parameters
 *
 */
void hmac_ctx_init (hmac_ctx_t *ctx, const uint8_t *key, int key_length,
    const md_kt_t *kt);

/*
 * Free the given HMAC context.
 *
 * @param ctx		HMAC context
 */
void hmac_ctx_cleanup(hmac_ctx_t *ctx);

/*
 * Returns the size of the HMAC output by the given HMAC Context
 *
 * @param ctx 		HMAC context.
 *
 * @return 		Size of the HMAC, or \0 if ctx is NULL.
 */
int hmac_ctx_size (const hmac_ctx_t *ctx);

/*
 * Resets the given HMAC context, preserving the associated key information
 *
 * @param ctx 		HMAC context. May not be NULL.
 */
void hmac_ctx_reset (hmac_ctx_t *ctx);

/*
 * Process the given data for use in the HMAC.
 *
 * @param ctx		HMAC context. May not be NULL.
 * @param src		The buffer to HMAC. May not be NULL.
 * @param src_len	The length of the incoming buffer.
 */
void hmac_ctx_update (hmac_ctx_t *ctx, const uint8_t *src, int src_len);

/*
 * Output the HMAC to the given buffer.
 *
 * @param ctx		HMAC context. May not be NULL.
 * @param dst		buffer to write the HMAC to. May not be NULL.
 */
void hmac_ctx_final (hmac_ctx_t *ctx, uint8_t *dst);

#endif /* CRYPTO_BACKEND_H_ */
