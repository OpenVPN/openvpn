/*
 *  OpenVPN -- An application to securely tunnel IP networks
 *             over a single TCP/UDP port, with support for SSL/TLS-based
 *             session authentication and key exchange,
 *             packet encryption, packet authentication, and
 *             packet compression.
 *
 *  Copyright (C) 2002-2024 OpenVPN Inc <sales@openvpn.net>
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
 * @file OpenSSL compatibility stub
 *
 * This file provide compatibility stubs for the OpenSSL libraries
 * prior to version 1.1. This version introduces many changes in the
 * library interface, including the fact that various objects and
 * structures are not fully opaque.
 */

#ifndef OPENSSL_COMPAT_H_
#define OPENSSL_COMPAT_H_

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "buffer.h"

#include <openssl/rsa.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>
#include <openssl/err.h>

/* Functionality missing in 1.1.0 */
#if OPENSSL_VERSION_NUMBER < 0x10101000L && !defined(ENABLE_CRYPTO_WOLFSSL)
#define SSL_CTX_set1_groups SSL_CTX_set1_curves
#endif

/* Functionality missing in LibreSSL before 3.5 */
#if defined(LIBRESSL_VERSION_NUMBER) && LIBRESSL_VERSION_NUMBER < 0x3050000fL
/**
 * Destroy a X509 object
 *
 * @param obj                X509 object
 */
static inline void
X509_OBJECT_free(X509_OBJECT *obj)
{
    if (obj)
    {
        X509_OBJECT_free_contents(obj);
        OPENSSL_free(obj);
    }
}

#define EVP_CTRL_AEAD_SET_TAG                EVP_CTRL_GCM_SET_TAG
#define EVP_CTRL_AEAD_GET_TAG                EVP_CTRL_GCM_GET_TAG
#endif

#if defined(LIBRESSL_VERSION_NUMBER)
#define RSA_F_RSA_OSSL_PRIVATE_ENCRYPT       RSA_F_RSA_EAY_PRIVATE_ENCRYPT
#endif

#if defined(LIBRESSL_VERSION_NUMBER) && LIBRESSL_VERSION_NUMBER < 0x3050400fL
#define SSL_get_peer_tmp_key SSL_get_server_tmp_key
#endif

/* Functionality missing in 1.1.1 */
#if OPENSSL_VERSION_NUMBER < 0x30000000L && !defined(OPENSSL_NO_EC)

/* Note that this is not a perfect emulation of the new function but
 * is good enough for our case of printing certificate details during
 * handshake */
static inline
int
EVP_PKEY_get_group_name(EVP_PKEY *pkey, char *gname, size_t gname_sz,
                        size_t *gname_len)
{
    const EC_KEY *ec = EVP_PKEY_get0_EC_KEY(pkey);
    if (ec == NULL)
    {
        return 0;
    }
    const EC_GROUP *group = EC_KEY_get0_group(ec);
    int nid = EC_GROUP_get_curve_name(group);

    if (nid == 0)
    {
        return 0;
    }
    const char *curve = OBJ_nid2sn(nid);
    if (!curve)
    {
        curve = "(error fetching curve name)";
    }

    strncpynt(gname, curve, gname_sz);

    /* strncpynt ensures null termination so just strlen is fine here */
    *gname_len = strlen(curve);
    return 1;
}
#endif /* if OPENSSL_VERSION_NUMBER < 0x30000000L && !defined(OPENSSL_NO_EC) */

#if OPENSSL_VERSION_NUMBER < 0x30000000L
#define EVP_MD_get0_name EVP_MD_name
#define EVP_CIPHER_get0_name EVP_CIPHER_name
#define EVP_CIPHER_CTX_get_mode EVP_CIPHER_CTX_mode

/** Reduce SSL_CTX_new_ex() to SSL_CTX_new() for OpenSSL < 3 */
#define SSL_CTX_new_ex(libctx, propq, method)                \
    SSL_CTX_new((method))

/* Some safe typedefs to avoid too many ifdefs */
typedef void OSSL_LIB_CTX;
typedef void OSSL_PROVIDER;

/* Mimics the functions but only when the default context without
 * options is chosen */
static inline const EVP_CIPHER *
EVP_CIPHER_fetch(void *ctx, const char *algorithm, const char *properties)
{
    ASSERT(!ctx);
    ASSERT(!properties);
    return EVP_get_cipherbyname(algorithm);
}

static inline const EVP_MD *
EVP_MD_fetch(void *ctx, const char *algorithm, const char *properties)
{
    ASSERT(!ctx);
    ASSERT(!properties);
    return EVP_get_digestbyname(algorithm);
}

static inline void
EVP_CIPHER_free(const EVP_CIPHER *cipher)
{
    /* OpenSSL 1.1.1 and lower use only const EVP_CIPHER, nothing to free */
}

static inline void
EVP_MD_free(const EVP_MD *md)
{
    /* OpenSSL 1.1.1 and lower use only const EVP_MD, nothing to free */
}

static inline unsigned long
ERR_get_error_all(const char **file, int *line,
                  const char **func,
                  const char **data, int *flags)
{
    static const char *empty = "";
    *func = empty;
    unsigned long err = ERR_get_error_line_data(file, line, data, flags);
    return err;
}

#endif /* OPENSSL_VERSION_NUMBER < 0x30000000L */

#endif /* OPENSSL_COMPAT_H_ */
