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
 * @file PKCS #11 PolarSSL backend
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#elif defined(_MSC_VER)
#include "config-msvc.h"
#endif

#include "syshead.h"

#if defined(ENABLE_PKCS11) && defined(ENABLE_CRYPTO_POLARSSL)

#include "errlevel.h"
#include "pkcs11_backend.h"
#include <polarssl/pkcs11.h>

int
pkcs11_init_tls_session(pkcs11h_certificate_t certificate,
    struct tls_root_ctx * const ssl_ctx)
{
  int ret = 1;

  ASSERT (NULL != ssl_ctx);

  if (pkcs11_x509_cert_init(ssl_ctx->crt_chain, certificate)) {
      msg (M_FATAL, "PKCS#11: Cannot retrieve PolarSSL certificate object");
      goto cleanup;
  }

  ssl_ctx->priv_key_pkcs11 = malloc(sizeof(pkcs11_context));

  if (ssl_ctx->priv_key_pkcs11 == NULL) {
      msg (M_FATAL, "PKCS#11: Cannot allocate PolarSSL private key object");
      goto cleanup;
  }

  if (pkcs11_priv_key_init(ssl_ctx->priv_key_pkcs11, certificate)) {
      msg (M_FATAL, "PKCS#11: Cannot initialize PolarSSL private key object");
      goto cleanup;
  }

  ret = 0;

cleanup:
  return ret;
}

char *
pkcs11_certificate_dn (pkcs11h_certificate_t cert, struct gc_arena *gc)
{
  char *ret = NULL;
  char dn[1024] = {0};

  x509_cert polar_cert = {0};

  if (pkcs11_x509_cert_init(&polar_cert, cert)) {
      msg (M_FATAL, "PKCS#11: Cannot retrieve PolarSSL certificate object");
      goto cleanup;
  }

  if (-1 == x509parse_dn_gets (dn, sizeof(dn), &polar_cert.subject)) {
      msg (M_FATAL, "PKCS#11: PolarSSL cannot parse subject");
      goto cleanup;
  }

  ret = string_alloc(dn, gc);

cleanup:
  x509_free(&polar_cert);

  return ret;
}

int
pkcs11_certificate_serial (pkcs11h_certificate_t cert, char *serial,
    size_t serial_len)
{
  int ret = 1;

  x509_cert polar_cert = {0};

  if (pkcs11_x509_cert_init(&polar_cert, cert)) {
      msg (M_FATAL, "PKCS#11: Cannot retrieve PolarSSL certificate object");
      goto cleanup;
  }

  if (-1 == x509parse_serial_gets (serial, serial_len, &polar_cert.serial)) {
      msg (M_FATAL, "PKCS#11: PolarSSL cannot parse serial");
      goto cleanup;
  }

  ret = 0;

cleanup:
  x509_free(&polar_cert);

  return ret;
}
#endif /* defined(ENABLE_PKCS11) && defined(ENABLE_CRYPTO_POLARSSL) */
