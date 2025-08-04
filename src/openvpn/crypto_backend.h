/*
 *  OpenVPN -- An application to securely tunnel IP networks
 *             over a single TCP/UDP port, with support for SSL/TLS-based
 *             session authentication and key exchange,
 *             packet encryption, packet authentication, and
 *             packet compression.
 *
 *  Copyright (C) 2002-2025 OpenVPN Inc <sales@openvpn.net>
 *  Copyright (C) 2010-2021 Fox Crypto B.V. <openvpn@foxcrypto.com>
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

/**
 * @file
 * Data Channel Cryptography SSL library-specific backend interface
 */

#ifndef CRYPTO_BACKEND_H_
#define CRYPTO_BACKEND_H_

#ifdef ENABLE_CRYPTO_OPENSSL
#include "crypto_openssl.h"
#endif
#ifdef ENABLE_CRYPTO_MBEDTLS
#include "crypto_mbedtls.h"
#endif
#include "basic.h"
#include "buffer.h"

/* TLS uses a tag of 128 bits, let's do the same for OpenVPN */
#define OPENVPN_AEAD_TAG_LENGTH 16

/* Maximum cipher block size (bytes) */
#define OPENVPN_MAX_CIPHER_BLOCK_SIZE 32

/* Maximum HMAC digest size (bytes) */
#define OPENVPN_MAX_HMAC_SIZE   64

/** Types referencing specific message digest hashing algorithms */
typedef enum {
    MD_SHA1,
    MD_SHA256
} hash_algo_type;

/** Struct used in cipher name translation table */
typedef struct {
    const char *openvpn_name;   /**< Cipher name used by OpenVPN */
    const char *lib_name;       /**< Cipher name used by crypto library */
} cipher_name_pair;

/** Cipher name translation table */
extern const cipher_name_pair cipher_name_translation_table[];
extern const size_t cipher_name_translation_table_count;

/*
 * This routine should have additional OpenSSL crypto library initialisations
 * used by both crypto and ssl components of OpenVPN.
 */
void crypto_init_lib(void);

void crypto_uninit_lib(void);

void crypto_clear_error(void);

/*
 * Initialise the given named crypto engine.
 */
void crypto_init_lib_engine(const char *engine_name);


/**
 * Load the given (OpenSSL) providers
 * @param provider name of providers to load
 * @return reference to the loaded provider
 */
provider_t *crypto_load_provider(const char *provider);

/**
 * Unloads the given (OpenSSL) provider
 * @param provname  name of the provider to unload
 * @param provider  pointer to the provider to unload
 */
void crypto_unload_provider(const char *provname, provider_t *provider);

#ifdef DMALLOC
/*
 * OpenSSL memory debugging.  If dmalloc debugging is enabled, tell
 * OpenSSL to use our private malloc/realloc/free functions so that
 * we can dispatch them to dmalloc.
 */
void crypto_init_dmalloc(void);

#endif /* DMALLOC */

void show_available_ciphers(void);

void show_available_digests(void);

void show_available_engines(void);

/**
 * Encode binary data as PEM.
 *
 * @param name      The name to use in the PEM header/footer.
 * @param dst       Destination buffer for PEM-encoded data.  Must be a valid
 *                  pointer to an uninitialized buffer structure.  Iff this
 *                  function returns true, the buffer will contain memory
 *                  allocated through the supplied gc.
 * @param src       Source buffer.
 * @param gc        The garbage collector to use when allocating memory for dst.
 *
 * @return true iff PEM encode succeeded.
 */
bool crypto_pem_encode(const char *name, struct buffer *dst,
                       const struct buffer *src, struct gc_arena *gc);

/**
 * Decode a PEM buffer to binary data.
 *
 * @param name      The name expected in the PEM header/footer.
 * @param dst       Destination buffer for decoded data.
 * @param src       Source buffer (PEM data).
 *
 * @return true iff PEM decode succeeded.
 */
bool crypto_pem_decode(const char *name, struct buffer *dst,
                       const struct buffer *src);

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
 * @param output        Output buffer
 * @param len           Length of the output buffer, in bytes
 *
 * @return              \c 1 on success, \c 0 on failure
 */
int rand_bytes(uint8_t *output, int len);

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
 * Returns if the cipher is valid, based on the given cipher name and provides a
 * reason if invalid.
 *
 * @param ciphername    Name of the cipher to check for validity (e.g.
 *                      \c AES-128-CBC). Will be translated to the library name
 *                      from the openvpn config name if needed.
 * @param reason        Pointer where a static string indicating the reason
 *                      for rejecting the cipher should be stored. It is set to
 *                      NULL if the cipher is valid.
 *
 * @return              if the cipher is valid
 */
bool cipher_valid_reason(const char *ciphername, const char **reason);

/**
 * Returns if the cipher is valid, based on the given cipher name.
 *
 * @param ciphername    Name of the cipher to check for validity (e.g.
 *                      \c AES-128-CBC). Will be translated to the library name
 *                      from the openvpn config name if needed.
 *
 * @return              if the cipher is valid
 */
static inline bool
cipher_valid(const char *ciphername)
{
    const char *reason;
    return cipher_valid_reason(ciphername, &reason);
}

/**
 * Checks if the cipher is defined and is not the null (none) cipher
 *
 * @param ciphername    Name of the cipher to check if it is defined, may not
 *                      be NULL
 * @return              The cipher is defined and not the null (none) cipher
 */
static inline bool
cipher_defined(const char *ciphername)
{
    ASSERT(ciphername);
    return strcmp(ciphername, "none") != 0;
}

/**
 * Retrieve a normalised string describing the cipher (e.g. \c AES-128-CBC).
 * The returned name is normalised to the OpenVPN config name in case the
 * name differs from the name used by the crypto library.
 *
 * Returns [null-cipher] in case the ciphername is none. NULL if the cipher
 * is not valid.
 *
 * @param ciphername     Name of the cipher
 *
 * @return a statically allocated string describing the cipher.
 */
const char *cipher_kt_name(const char *ciphername);

/**
 * Returns the size of keys used by the cipher, in bytes. If the cipher has a
 * variable key size, return the default key size.
 *
 * @param ciphername    Cipher name to lookup
 *
 * @return              (Default) size of keys used by the cipher, in bytes.
 */
int cipher_kt_key_size(const char *ciphername);

/**
 * Returns the size of the IV used by the cipher, in bytes, or 0 if no IV is
 * used.
 *
 * @param ciphername    cipher name to lookup
 *
 * @return              Size of the IV, in bytes, or 0 if the cipher does not
 *                      use an IV.
 */
int cipher_kt_iv_size(const char *ciphername);

/**
 * Returns the block size of the cipher, in bytes.
 *
 * @param ciphername    cipher name
 *
 * @return              Block size, in bytes.
 */
int cipher_kt_block_size(const char *ciphername);

/**
 * Returns the MAC tag size of the cipher, in bytes.
 *
 * @param ciphername    Name of the cipher
 *
 * @return              Tag size in bytes, or 0 if the tag size could not be
 *                      determined.
 */
int cipher_kt_tag_size(const char *ciphername);

/**
 * Returns true if we consider this cipher to be insecure.
 */
bool cipher_kt_insecure(const char *ciphername);


/**
 * Check if the supplied cipher is a supported CBC mode cipher.
 *
 * @param ciphername    cipher name
 *
 * @return              true iff the cipher is a CBC mode cipher.
 */
bool cipher_kt_mode_cbc(const char *ciphername);

/**
 * Check if the supplied cipher is a supported OFB or CFB mode cipher.
 *
 * @param ciphername    cipher name
 *
 * @return              true iff the cipher is a OFB or CFB mode cipher.
 */
bool cipher_kt_mode_ofb_cfb(const char *ciphername);

/**
 * Check if the supplied cipher is a supported AEAD mode cipher.
 *
 * @param ciphername    name of the cipher
 *
 * @return              true iff the cipher is a AEAD mode cipher.
 */
bool cipher_kt_mode_aead(const char *ciphername);


/**
 *
 * Generic cipher functions
 *
 */

/**
 * Allocate a new cipher context
 *
 * @return              a new cipher context
 */
cipher_ctx_t *cipher_ctx_new(void);

/**
 * Cleanup and free a cipher context
 *
 * @param ctx           Cipher context.
 */
void cipher_ctx_free(cipher_ctx_t *ctx);

/**
 * Initialise a cipher context, based on the given key and key type.
 *
 * @param ctx           Cipher context. May not be NULL
 * @param key           Buffer containing the key to use
 * @param ciphername    Ciphername of the cipher to use
 * @param enc           Whether to encrypt or decrypt (either
 *                      \c OPENVPN_OP_ENCRYPT or \c OPENVPN_OP_DECRYPT).
 */
void cipher_ctx_init(cipher_ctx_t *ctx, const uint8_t *key,
                     const char *ciphername, crypto_operation_t enc);

/**
 * Returns the size of the IV used by the cipher, in bytes, or 0 if no IV is
 * used.
 *
 * @param ctx           The cipher's context
 *
 * @return              Size of the IV, in bytes, or \c 0 if the cipher does not
 *                      use an IV.
 */
int cipher_ctx_iv_length(const cipher_ctx_t *ctx);

/**
 * Gets the computed message authenticated code (MAC) tag for this cipher.
 *
 * @param ctx           The cipher's context
 * @param tag           The buffer to write computed tag in.
 * @param tag_len       The tag buffer size, in bytes.
 */
int cipher_ctx_get_tag(cipher_ctx_t *ctx, uint8_t *tag, int tag_len);

/**
 * Returns the block size of the cipher, in bytes.
 *
 * @param ctx           The cipher's context
 *
 * @return              Block size, in bytes, or 0 if ctx was NULL.
 */
int cipher_ctx_block_size(const cipher_ctx_t *ctx);

/**
 * Returns the mode that the cipher runs in.
 *
 * @param ctx           Cipher's context. May not be NULL.
 *
 * @return              Cipher mode, either \c OPENVPN_MODE_CBC, \c
 *                      OPENVPN_MODE_OFB or \c OPENVPN_MODE_CFB
 */
int cipher_ctx_mode(const cipher_ctx_t *ctx);

/**
 * Check if the supplied cipher is a supported CBC mode cipher.
 *
 * @param ctx           Cipher's context. May not be NULL.
 *
 * @return              true iff the cipher is a CBC mode cipher.
 */
bool cipher_ctx_mode_cbc(const cipher_ctx_t *ctx);

/**
 * Check if the supplied cipher is a supported OFB or CFB mode cipher.
 *
 * @param ctx           Cipher's context. May not be NULL.
 *
 * @return              true iff the cipher is a OFB or CFB mode cipher.
 */
bool cipher_ctx_mode_ofb_cfb(const cipher_ctx_t *ctx);

/**
 * Check if the supplied cipher is a supported AEAD mode cipher.
 *
 * @param ctx           Cipher's context. May not be NULL.
 *
 * @return              true iff the cipher is a AEAD mode cipher.
 */
bool cipher_ctx_mode_aead(const cipher_ctx_t *ctx);

/**
 * Resets the given cipher context, setting the IV to the specified value.
 * Preserves the associated key information.
 *
 * @param ctx           Cipher's context. May not be NULL.
 * @param iv_buf        The IV to use.
 *
 * @return              \c 0 on failure, \c 1 on success.
 */
int cipher_ctx_reset(cipher_ctx_t *ctx, const uint8_t *iv_buf);

/**
 * Updates the given cipher context, providing additional data (AD) for
 * authenticated encryption with additional data (AEAD) cipher modes.
 *
 * @param ctx           Cipher's context. May not be NULL.
 * @param src           Source buffer
 * @param src_len       Length of the source buffer, in bytes
 *
 * @return              \c 0 on failure, \c 1 on success.
 */
int cipher_ctx_update_ad(cipher_ctx_t *ctx, const uint8_t *src, int src_len);

/**
 * Updates the given cipher context, encrypting data in the source buffer, and
 * placing any complete blocks in the destination buffer.
 *
 * Note that if a complete block cannot be written, data is cached in the
 * context, and emitted at a later call to \c cipher_ctx_update, or by a call
 * to \c cipher_ctx_final(). This implies that dst should have enough room for
 * src_len + \c cipher_ctx_block_size().
 *
 * @param ctx           Cipher's context. May not be NULL.
 * @param dst           Destination buffer
 * @param dst_len       Length of the destination buffer, in bytes
 * @param src           Source buffer
 * @param src_len       Length of the source buffer, in bytes
 *
 * @return              \c 0 on failure, \c 1 on success.
 */
int cipher_ctx_update(cipher_ctx_t *ctx, uint8_t *dst, int *dst_len,
                      uint8_t *src, int src_len);

/**
 * Pads the final cipher block using PKCS padding, and output to the destination
 * buffer.
 *
 * @param ctx           Cipher's context. May not be NULL.
 * @param dst           Destination buffer
 * @param dst_len       Length of the destination buffer, in bytes
 *
 * @return              \c 0 on failure, \c 1 on success.
 */
int cipher_ctx_final(cipher_ctx_t *ctx, uint8_t *dst, int *dst_len);

/**
 * Like \c cipher_ctx_final, but check the computed authentication tag against
 * the supplied (expected) tag. This function reports failure when the tags
 * don't match.
 *
 * @param ctx           Cipher's context. May not be NULL.
 * @param dst           Destination buffer.
 * @param dst_len       Length of the destination buffer, in bytes.
 * @param tag           The expected authentication tag.
 * @param tag_len       The length of tag, in bytes.
 *
 * @return              \c 0 on failure, \c 1 on success.
 */
int cipher_ctx_final_check_tag(cipher_ctx_t *ctx, uint8_t *dst, int *dst_len,
                               uint8_t *tag, size_t tag_len);


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
 * Checks if the cipher is defined and is not the null (none) cipher
 *
 * @param mdname    Name of the digest
 * @return
 */
static inline bool
md_defined(const char *mdname)
{
    return strcmp(mdname, "none") != 0;
}


/**
 * Return if a message digest parameters is valid given the name of the digest.
 *
 * @param digest        Name of the digest to verify, e.g. \c MD5).
 *
 * @return              Whether a digest of the given name is available
 */
bool md_valid(const char *digest);

/**
 * Retrieve a string describing the digest digest (e.g. \c SHA1).
 *
 * @param mdname        Message digest name
 *
 * @return              Statically allocated string describing the message
 *                      digest.
 */
const char *md_kt_name(const char *mdname);

/**
 * Returns the size of the message digest, in bytes.
 *
 * @param mdname        Message digest name
 *
 * @return              Message digest size, in bytes, or 0 if ctx was NULL.
 */
unsigned char md_kt_size(const char *mdname);


/*
 *
 * Generic message digest functions
 *
 */

/**
 * Calculates the message digest for the given buffer.
 *
 * @param mdname        message digest name
 * @param src           Buffer to digest. May not be NULL.
 * @param src_len       The length of the incoming buffer.
 * @param dst           Buffer to write the message digest to. May not be NULL.
 *
 * @return              \c 1 on success, \c 0 on failure
 */
int md_full(const char *mdname, const uint8_t *src, int src_len, uint8_t *dst);

/*
 * Allocate a new message digest context
 *
 * @return              a new zeroed MD context
 */
md_ctx_t *md_ctx_new(void);

/*
 * Free an existing, non-null message digest context
 *
 * @param ctx           Message digest context
 */
void md_ctx_free(md_ctx_t *ctx);

/**
 * Initialises the given message digest context.
 *
 * @param ctx           Message digest context
 * @param mdname        Message digest name
 */
void md_ctx_init(md_ctx_t *ctx, const char *mdname);

/*
 * Free the given message digest context.
 *
 * @param ctx           Message digest context
 */
void md_ctx_cleanup(md_ctx_t *ctx);

/*
 * Returns the size of the message digest output by the given context
 *
 * @param ctx           Message digest context.
 *
 * @return              Size of the message digest, or \0 if ctx is NULL.
 */
int md_ctx_size(const md_ctx_t *ctx);

/*
 * Process the given data for use in the message digest.
 *
 * @param ctx           Message digest context. May not be NULL.
 * @param src           Buffer to digest. May not be NULL.
 * @param src_len       The length of the incoming buffer.
 */
void md_ctx_update(md_ctx_t *ctx, const uint8_t *src, int src_len);

/*
 * Output the message digest to the given buffer.
 *
 * @param ctx           Message digest context. May not be NULL.
 * @param dst           Buffer to write the message digest to. May not be NULL.
 */
void md_ctx_final(md_ctx_t *ctx, uint8_t *dst);


/*
 *
 * Generic HMAC functions
 *
 */

/*
 * Create a new HMAC context
 *
 * @return              A new HMAC context
 */
hmac_ctx_t *hmac_ctx_new(void);

/*
 * Free an existing HMAC context
 *
 * @param  ctx           HMAC context to free
 */
void hmac_ctx_free(hmac_ctx_t *ctx);

/*
 * Initialises the given HMAC context, using the given digest
 * and key.
 *
 * @param ctx           HMAC context to initialise
 * @param key           The key to use for the HMAC
 * @param mdname        message digest name
 *
 */
void hmac_ctx_init(hmac_ctx_t *ctx, const uint8_t *key, const char *mdname);


/*
 * Free the given HMAC context.
 *
 * @param ctx           HMAC context
 */
void hmac_ctx_cleanup(hmac_ctx_t *ctx);

/*
 * Returns the size of the HMAC output by the given HMAC Context
 *
 * @param ctx           HMAC context.
 *
 * @return              Size of the HMAC, or \0 if ctx is NULL.
 */
int hmac_ctx_size(hmac_ctx_t *ctx);

/*
 * Resets the given HMAC context, preserving the associated key information
 *
 * @param ctx           HMAC context. May not be NULL.
 */
void hmac_ctx_reset(hmac_ctx_t *ctx);

/*
 * Process the given data for use in the HMAC.
 *
 * @param ctx           HMAC context. May not be NULL.
 * @param src           The buffer to HMAC. May not be NULL.
 * @param src_len       The length of the incoming buffer.
 */
void hmac_ctx_update(hmac_ctx_t *ctx, const uint8_t *src, int src_len);

/*
 * Output the HMAC to the given buffer.
 *
 * @param ctx           HMAC context. May not be NULL.
 * @param dst           buffer to write the HMAC to. May not be NULL.
 */
void hmac_ctx_final(hmac_ctx_t *ctx, uint8_t *dst);

/**
 * Translate an OpenVPN cipher name to a crypto library cipher name.
 *
 * @param cipher_name   An OpenVPN cipher name
 *
 * @return              The corresponding crypto library cipher name, or NULL
 *                      if no matching cipher name was found.
 */
const char *translate_cipher_name_from_openvpn(const char *cipher_name);

/**
 * Translate a crypto library cipher name to an OpenVPN cipher name.
 *
 * @param cipher_name   A crypto library cipher name
 *
 * @return              The corresponding OpenVPN cipher name, or NULL if no
 *                      matching cipher name was found.
 */
const char *translate_cipher_name_to_openvpn(const char *cipher_name);


/**
 * Calculates the TLS 1.0-1.1 PRF function. For the exact specification of the
 * function definition see the TLS RFCs like RFC 4346.
 *
 * @param seed          seed to use
 * @param seed_len      length of the seed
 * @param secret        secret to use
 * @param secret_len    length of the secret
 * @param output        output destination
 * @param output_len    length of output/number of bytes to generate
 *
 * @return              true if successful, false on any error
 */
bool ssl_tls1_PRF(const uint8_t *seed, int seed_len, const uint8_t *secret,
                  int secret_len, uint8_t *output, int output_len);

#endif /* CRYPTO_BACKEND_H_ */
