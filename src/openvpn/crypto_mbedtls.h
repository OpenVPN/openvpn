/*
 *  OpenVPN -- An application to securely tunnel IP networks
 *             over a single TCP/UDP port, with support for SSL/TLS-based
 *             session authentication and key exchange,
 *             packet encryption, packet authentication, and
 *             packet compression.
 *
 *  Copyright (C) 2002-2021 OpenVPN Inc <sales@openvpn.net>
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
 *  with this program; if not, write to the Free Software Foundation, Inc.,
 *  51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

/**
 * @file Data Channel Cryptography mbed TLS-specific backend interface
 */

#ifndef CRYPTO_MBEDTLS_H_
#define CRYPTO_MBEDTLS_H_

#include <mbedtls/cipher.h>
#include <mbedtls/md.h>
#include <mbedtls/ctr_drbg.h>

/** Generic cipher key type %context. */
typedef mbedtls_cipher_info_t cipher_kt_t;

/** Generic message digest key type %context. */
typedef mbedtls_md_info_t md_kt_t;

/** Generic cipher %context. */
typedef mbedtls_cipher_context_t cipher_ctx_t;

/** Generic message digest %context. */
typedef mbedtls_md_context_t md_ctx_t;

/** Generic HMAC %context. */
typedef mbedtls_md_context_t hmac_ctx_t;

/** Maximum length of an IV */
#define OPENVPN_MAX_IV_LENGTH   MBEDTLS_MAX_IV_LENGTH

/** Cipher is in CBC mode */
#define OPENVPN_MODE_CBC        MBEDTLS_MODE_CBC

/** Cipher is in OFB mode */
#define OPENVPN_MODE_OFB        MBEDTLS_MODE_OFB

/** Cipher is in CFB mode */
#define OPENVPN_MODE_CFB        MBEDTLS_MODE_CFB

/** Cipher is in GCM mode */
#define OPENVPN_MODE_GCM        MBEDTLS_MODE_GCM

/** Cipher should encrypt */
#define OPENVPN_OP_ENCRYPT      MBEDTLS_ENCRYPT

/** Cipher should decrypt */
#define OPENVPN_OP_DECRYPT      MBEDTLS_DECRYPT

#define MD4_DIGEST_LENGTH       16
#define MD5_DIGEST_LENGTH       16
#define SHA_DIGEST_LENGTH       20
#define SHA256_DIGEST_LENGTH    32
#define DES_KEY_LENGTH 8

/**
 * Returns a singleton instance of the mbed TLS random number generator.
 *
 * For PolarSSL/mbed TLS 1.1+, this is the CTR_DRBG random number generator. If it
 * hasn't been initialised yet, the RNG will be initialised using the default
 * entropy sources. Aside from the default platform entropy sources, an
 * additional entropy source, the HAVEGE random number generator will also be
 * added. During initialisation, a personalisation string will be added based
 * on the time, the PID, and a pointer to the random context.
 */
mbedtls_ctr_drbg_context *rand_ctx_get(void);

#ifdef ENABLE_PREDICTION_RESISTANCE
/**
 * Enable prediction resistance on the random number generator.
 */
void rand_ctx_enable_prediction_resistance(void);

#endif

/**
 * Log the supplied mbed TLS error, prefixed by supplied prefix.
 *
 * @param flags         Flags to indicate error type and priority.
 * @param errval        mbed TLS error code to convert to error message.
 * @param prefix        Prefix to mbed TLS error message.
 *
 * @returns true if no errors are detected, false otherwise.
 */
bool mbed_log_err(unsigned int flags, int errval, const char *prefix);

/**
 * Log the supplied mbed TLS error, prefixed by function name and line number.
 *
 * @param flags         Flags to indicate error type and priority.
 * @param errval        mbed TLS error code to convert to error message.
 * @param func          Function name where error was reported.
 * @param line          Line number where error was reported.
 *
 * @returns true if no errors are detected, false otherwise.
 */
bool mbed_log_func_line(unsigned int flags, int errval, const char *func,
                        int line);

/** Wraps mbed_log_func_line() to prevent function calls for non-errors */
static inline bool
mbed_log_func_line_lite(unsigned int flags, int errval,
                        const char *func, int line)
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
 */
#define mbed_ok(errval) \
    mbed_log_func_line_lite(D_CRYPT_ERRORS, errval, __func__, __LINE__)

static inline bool
cipher_kt_var_key_size(const cipher_kt_t *cipher)
{
    return cipher->flags & MBEDTLS_CIPHER_VARIABLE_KEY_LEN;
}

#endif /* CRYPTO_MBEDTLS_H_ */
