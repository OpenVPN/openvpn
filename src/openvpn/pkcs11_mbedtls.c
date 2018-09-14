/*
 *  OpenVPN -- An application to securely tunnel IP networks
 *             over a single TCP/UDP port, with support for SSL/TLS-based
 *             session authentication and key exchange,
 *             packet encryption, packet authentication, and
 *             packet compression.
 *
 *  Copyright (C) 2002-2018 OpenVPN Inc <sales@openvpn.net>
 *  Copyright (C) 2010-2018 Fox Crypto B.V. <openvpn@fox-it.com>
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
 * @file PKCS #11 mbed TLS backend
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#elif defined(_MSC_VER)
#include "config-msvc.h"
#endif

#include "syshead.h"

#if defined(ENABLE_PKCS11) && defined(ENABLE_CRYPTO_MBEDTLS)

#include "errlevel.h"
#include "pkcs11_backend.h"
#include "ssl_verify_backend.h"
#include <mbedtls/x509.h>

static bool
pkcs11_get_x509_cert(pkcs11h_certificate_t pkcs11_cert, mbedtls_x509_crt *cert)
{
    unsigned char *cert_blob = NULL;
    size_t cert_blob_size = 0;
    bool ret = false;

    if (pkcs11h_certificate_getCertificateBlob(pkcs11_cert, NULL,
                                               &cert_blob_size) != CKR_OK)
    {
        msg(M_WARN, "PKCS#11: Cannot retrieve certificate object size");
        goto cleanup;
    }

    check_malloc_return((cert_blob = calloc(1, cert_blob_size)));
    if (pkcs11h_certificate_getCertificateBlob(pkcs11_cert, cert_blob,
                                               &cert_blob_size) != CKR_OK)
    {
        msg(M_WARN, "PKCS#11: Cannot retrieve certificate object");
        goto cleanup;
    }

    if (!mbed_ok(mbedtls_x509_crt_parse(cert, cert_blob, cert_blob_size)))
    {
        msg(M_WARN, "PKCS#11: Could not parse certificate");
        goto cleanup;
    }

    ret = true;
cleanup:
    free(cert_blob);
    return ret;
}

static bool
pkcs11_sign(void *pkcs11_cert, const void *src, size_t src_len,
            void *dst, size_t dst_len)
{
    return CKR_OK == pkcs11h_certificate_signAny(pkcs11_cert, CKM_RSA_PKCS,
                                                 src, src_len, dst, &dst_len);
}

int
pkcs11_init_tls_session(pkcs11h_certificate_t certificate,
                        struct tls_root_ctx *const ssl_ctx)
{
    ASSERT(NULL != ssl_ctx);

    ssl_ctx->pkcs11_cert = certificate;

    ALLOC_OBJ_CLEAR(ssl_ctx->crt_chain, mbedtls_x509_crt);
    if (!pkcs11_get_x509_cert(certificate, ssl_ctx->crt_chain))
    {
        msg(M_WARN, "PKCS#11: Cannot initialize certificate");
        return 1;
    }

    if (tls_ctx_use_external_signing_func(ssl_ctx, pkcs11_sign, certificate))
    {
        msg(M_WARN, "PKCS#11: Cannot register signing function");
        return 1;
    }

    return 0;
}

char *
pkcs11_certificate_dn(pkcs11h_certificate_t cert, struct gc_arena *gc)
{
    char *ret = NULL;
    mbedtls_x509_crt mbed_crt = { 0 };

    if (!pkcs11_get_x509_cert(cert, &mbed_crt))
    {
        msg(M_WARN, "PKCS#11: Cannot retrieve mbed TLS certificate object");
        goto cleanup;
    }

    if (!(ret = x509_get_subject(&mbed_crt, gc)))
    {
        msg(M_WARN, "PKCS#11: mbed TLS cannot parse subject");
        goto cleanup;
    }

cleanup:
    mbedtls_x509_crt_free(&mbed_crt);

    return ret;
}

int
pkcs11_certificate_serial(pkcs11h_certificate_t cert, char *serial,
                          size_t serial_len)
{
    int ret = 1;
    mbedtls_x509_crt mbed_crt = { 0 };

    if (!pkcs11_get_x509_cert(cert, &mbed_crt))
    {
        msg(M_WARN, "PKCS#11: Cannot retrieve mbed TLS certificate object");
        goto cleanup;
    }

    if (mbedtls_x509_serial_gets(serial, serial_len, &mbed_crt.serial) < 0)
    {
        msg(M_WARN, "PKCS#11: mbed TLS cannot parse serial");
        goto cleanup;
    }

    ret = 0;
cleanup:
    mbedtls_x509_crt_free(&mbed_crt);

    return ret;
}
#endif /* defined(ENABLE_PKCS11) && defined(ENABLE_CRYPTO_MBEDTLS) */
