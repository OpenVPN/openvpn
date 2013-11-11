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
 * @file PKCS #11 OpenSSL backend
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#elif defined(_MSC_VER)
#include "config-msvc.h"
#endif

#include "syshead.h"

#if defined(ENABLE_PKCS11) && defined(ENABLE_CRYPTO_OPENSSL)

#include "errlevel.h"
#include "pkcs11_backend.h"
#include "ssl_verify.h"
#include <pkcs11-helper-1.0/pkcs11h-openssl.h>

int
pkcs11_init_tls_session(pkcs11h_certificate_t certificate,
    struct tls_root_ctx * const ssl_ctx)
{
  int ret = 1;

  X509 *x509 = NULL;
  EVP_PKEY *evp = NULL;
  pkcs11h_openssl_session_t openssl_session = NULL;

  if ((openssl_session = pkcs11h_openssl_createSession (certificate)) == NULL)
    {
      msg (M_WARN, "PKCS#11: Cannot initialize openssl session");
      goto cleanup;
    }

  /*
   * Will be released by openssl_session
   */
  certificate = NULL;

  if ((evp = pkcs11h_openssl_session_getEVP (openssl_session)) == NULL)
    {
      msg (M_WARN, "PKCS#11: Unable get evp object");
      goto cleanup;
    }

  if ((x509 = pkcs11h_openssl_session_getX509 (openssl_session)) == NULL)
    {
      msg (M_WARN, "PKCS#11: Unable get certificate object");
      goto cleanup;
    }

  if (!SSL_CTX_use_PrivateKey (ssl_ctx->ctx, evp))
    {
      msg (M_WARN, "PKCS#11: Cannot set private key for openssl");
      goto cleanup;
    }

  if (!SSL_CTX_use_certificate (ssl_ctx->ctx, x509))
    {
      msg (M_WARN, "PKCS#11: Cannot set certificate for openssl");
      goto cleanup;
    }
  ret = 0;

cleanup:
  /*
   * Certificate freeing is usually handled by openssl_session.
   * If something went wrong, creating the session we have to do it manually.
   */
  if (certificate != NULL) {
    pkcs11h_certificate_freeCertificate (certificate);
    certificate = NULL;
  }

  /*
   * openssl objects have reference
   * count, so release them
   */
  if (x509 != NULL)
    {
      X509_free (x509);
      x509 = NULL;
    }

  if (evp != NULL)
    {
      EVP_PKEY_free (evp);
      evp = NULL;
    }

  if (openssl_session != NULL)
    {
      pkcs11h_openssl_freeSession (openssl_session);
      openssl_session = NULL;
    }
  return ret;
}

char *
pkcs11_certificate_dn (pkcs11h_certificate_t certificate, struct gc_arena *gc)
{
  X509 *x509 = NULL;

  char *dn = NULL;

  if ((x509 = pkcs11h_openssl_getX509 (certificate)) == NULL)
    {
      msg (M_FATAL, "PKCS#11: Cannot get X509");
      goto cleanup;
    }

  dn = x509_get_subject (x509, gc);

cleanup:
  if (x509 != NULL)
    {
      X509_free (x509);
      x509 = NULL;
    }

  return dn;
}

int
pkcs11_certificate_serial (pkcs11h_certificate_t certificate, char *serial,
    size_t serial_len)
{
  X509 *x509 = NULL;
  BIO *bio = NULL;
  int ret = 1;
  int n;

  if ((x509 = pkcs11h_openssl_getX509 (certificate)) == NULL)
    {
      msg (M_FATAL, "PKCS#11: Cannot get X509");
      goto cleanup;
    }

  if ((bio = BIO_new (BIO_s_mem ())) == NULL)
    {
      msg (M_FATAL, "PKCS#11: Cannot create BIO");
      goto cleanup;
    }

  i2a_ASN1_INTEGER(bio, X509_get_serialNumber (x509));
  n = BIO_read (bio, serial, serial_len-1);

  if (n<0) {
    serial[0] = '\x0';
  }
  else {
    serial[n] = 0;
  }

  ret = 0;

cleanup:

  if (x509 != NULL)
    {
      X509_free (x509);
      x509 = NULL;
    }
  return ret;
}
#endif /* defined(ENABLE_PKCS11) && defined(ENABLE_OPENSSL) */
