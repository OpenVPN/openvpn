
/*
 *  OpenVPN -- An application to securely tunnel IP networks
 *             over a single TCP/UDP port, with support for SSL/TLS-based
 *             session authentication and key exchange,
 *             packet encryption, packet authentication, and
 *             packet compression.
 *
 *  Copyright (C) 2002-2026 OpenVPN Inc <sales@openvpn.net>
 *  Copyright (C) 2010-2026 Sentyron B.V. <openvpn@sentyron.com>
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
 * Data Channel Cryptography backend interface using the TF-PSA-Crypto library
 * part of Mbed TLS 4.
 */

#ifndef CRYPTO_MBEDTLS4_H_
#define CRYPTO_MBEDTLS4_H_

#include <psa/crypto.h>

#include "integer.h"

/** Maximum length of an IV */
#define OPENVPN_MAX_IV_LENGTH 16

/** Cipher is in CBC mode */
#define OPENVPN_MODE_CBC PSA_ALG_CBC_PKCS7

/** Cipher is in OFB mode */
#define OPENVPN_MODE_OFB PSA_ALG_OFB

/** Cipher is in CFB mode */
#define OPENVPN_MODE_CFB PSA_ALG_CFB

/** Cipher is in GCM mode */
#define OPENVPN_MODE_GCM PSA_ALG_GCM

typedef int crypto_operation_t;

/** Cipher should encrypt */
#define OPENVPN_OP_ENCRYPT 0

/** Cipher should decrypt */
#define OPENVPN_OP_DECRYPT 1

#define MD4_DIGEST_LENGTH    16
#define MD5_DIGEST_LENGTH    16
#define SHA_DIGEST_LENGTH    20
#define SHA256_DIGEST_LENGTH 32

typedef void provider_t;

typedef struct cipher_info
{
    const char *name;
    psa_key_type_t psa_key_type;
    psa_algorithm_t psa_alg;
    unsigned int key_bytes;
    unsigned int iv_bytes;
    unsigned int block_size;
} cipher_info_t;

typedef union psa_cipher_or_aead_operation
{
    psa_cipher_operation_t cipher;
    psa_aead_operation_t aead;
} cipher_operation_t;

typedef struct cipher_ctx
{
    mbedtls_svc_key_id_t key;
    psa_key_attributes_t key_attributes;
    const cipher_info_t *cipher_info;
    bool aead_finished;
    cipher_operation_t operation;
    uint8_t tag[16];
} cipher_ctx_t;

typedef struct md_info
{
    const char *name;
    psa_algorithm_t psa_alg;
} md_info_t;

typedef struct md_ctx
{
    const md_info_t *md_info;
    psa_hash_operation_t operation;
} md_ctx_t;

typedef struct hmac_ctx
{
    mbedtls_svc_key_id_t key;
    psa_key_attributes_t key_attributes;
    const md_info_t *md_info;
    psa_mac_operation_t operation;
} hmac_ctx_t;

/**
 * Log the supplied mbed TLS error, prefixed by supplied prefix.
 *
 * @param flags         Flags to indicate error type and priority.
 * @param errval        mbed TLS error code.
 * @param prefix        Prefix to mbed TLS error message.
 *
 * @returns true if no errors are detected, false otherwise.
 */
bool mbed_log_err(unsigned int flags, int errval, const char *prefix);

/**
 * Log the supplied mbed TLS error, prefixed by function name and line number.
 *
 * @param flags         Flags to indicate error type and priority.
 * @param errval        mbed TLS error code.
 * @param func          Function name where error was reported.
 * @param line          Line number where error was reported.
 *
 * @returns true if no errors are detected, false otherwise.
 */
bool mbed_log_func_line(unsigned int flags, int errval, const char *func, int line);

/** Wraps mbed_log_func_line() to prevent function calls for non-errors */
static inline bool
mbed_log_func_line_lite(unsigned int flags, int errval, const char *func, int line)
{
    if (errval)
    {
        return mbed_log_func_line(flags, errval, func, line);
    }
    return true;
}

/**
 * Check errval and log on error.
 *
 * Convenience wrapper to put around mbed TLS library calls, e.g.
 *   if (!mbed_ok (mbedtls_ssl_func())) return 0;
 * or
 *   ASSERT (mbed_ok (mbedtls_ssl_func()));
 *
 * @param errval        mbed TLS error code to convert to error message.
 *
 * @returns true if no errors are detected, false otherwise.
 * TODO: The log function has been removed, do something about it?
 */
#define mbed_ok(errval) mbed_log_func_line_lite(D_CRYPT_ERRORS, errval, __func__, __LINE__)

#endif /* CRYPTO_MBEDTLS4_H_ */
