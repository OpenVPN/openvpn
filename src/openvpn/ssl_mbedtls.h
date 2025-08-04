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
 * Control Channel mbed TLS Backend
 */

#ifndef SSL_MBEDTLS_H_
#define SSL_MBEDTLS_H_

#include "syshead.h"

#include <mbedtls/ssl.h>
#include <mbedtls/x509_crt.h>
#include <mbedtls/version.h>

#if defined(ENABLE_PKCS11)
#include <pkcs11-helper-1.0/pkcs11h-certificate.h>
#endif

#include "mbedtls_compat.h"

typedef struct _buffer_entry buffer_entry;

struct _buffer_entry {
    size_t length;
    uint8_t *data;
    buffer_entry *next_block;
};

typedef struct {
    size_t data_start;
    buffer_entry *first_block;
    buffer_entry *last_block;
} endless_buffer;

typedef struct {
    endless_buffer in;
    endless_buffer out;
} bio_ctx;

/**
 * External signing function prototype.  A function pointer to a function
 * implementing this prototype is provided to
 * tls_ctx_use_external_signing_func().
 *
 * @param sign_ctx  The context for the signing function.
 * @param src       The data to be signed,
 * @param src_size  The length of src, in bytes.
 * @param dst       The destination buffer for the signature.
 * @param dst_size  The length of the destination buffer.
 *
 * @return true if signing succeeded, false otherwise.
 */
typedef bool (*external_sign_func)(
    void *sign_ctx, const void *src, size_t src_size,
    void *dst, size_t dst_size);

/** Context used by external_pkcs1_sign() */
struct external_context {
    size_t signature_length;
    external_sign_func sign;
    void *sign_ctx;
};

#if !defined(MBEDTLS_SSL_KEYING_MATERIAL_EXPORT)
/**
 * struct to cache TLS secrets for keying material exporter (RFC 5705).
 * Not needed if the library itself implements the keying material exporter.
 *
 * The constants 64 and 48 are inherent to TLS 1.2. For TLS 1.3, it is not
 * possible to obtain the exporter master secret from mbed TLS. */
struct tls_key_cache {
    unsigned char client_server_random[64];
    mbedtls_tls_prf_types tls_prf_type;
    unsigned char master_secret[48];
};
#else  /* !defined(MBEDTLS_SSL_KEYING_MATERIAL_EXPORT) */
struct tls_key_cache { };
#endif

/**
 * Structure that wraps the TLS context. Contents differ depending on the
 * SSL library used.
 *
 * Either \c priv_key_pkcs11 or \c priv_key must be filled in.
 */
struct tls_root_ctx {
    bool initialised;           /**< True if the context has been initialised */

    int endpoint;               /**< Whether or not this is a server or a client */

    mbedtls_dhm_context *dhm_ctx;       /**< Diffie-Helmann-Merkle context */
    mbedtls_x509_crt *crt_chain;        /**< Local Certificate chain */
    mbedtls_x509_crt *ca_chain;         /**< CA chain for remote verification */
    mbedtls_pk_context *priv_key;       /**< Local private key */
    mbedtls_x509_crl *crl;              /**< Certificate Revocation List */
    time_t crl_last_mtime;              /**< CRL last modification time */
    off_t crl_last_size;                /**< size of last loaded CRL */
#ifdef ENABLE_PKCS11
    pkcs11h_certificate_t pkcs11_cert;  /**< PKCS11 certificate */
#endif
    struct external_context external_key; /**< External key context */
    int *allowed_ciphers;       /**< List of allowed ciphers for this connection */
    mbedtls_compat_group_id *groups;     /**< List of allowed groups for this connection */
    mbedtls_x509_crt_profile cert_profile; /**< Allowed certificate types */
};

struct key_state_ssl {
    mbedtls_ssl_config *ssl_config;     /**< mbedTLS global ssl config */
    mbedtls_ssl_context *ctx;           /**< mbedTLS connection context */
    bio_ctx *bio_ctx;

    struct tls_key_cache tls_key_cache;
};

/**
 * Call the supplied signing function to create a TLS signature during the
 * TLS handshake.
 *
 * @param ctx                   TLS context to use.
 * @param sign_func             Signing function to call.
 * @param sign_ctx              Context for the sign function.
 *
 * @return                      0 if successful, 1 if an error occurred.
 */
int tls_ctx_use_external_signing_func(struct tls_root_ctx *ctx,
                                      external_sign_func sign_func,
                                      void *sign_ctx);

static inline void
tls_clear_error(void)
{
}
#endif /* SSL_MBEDTLS_H_ */
