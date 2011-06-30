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
 * @file Control Channel Verification Module OpenSSL implementation
 */

#include "ssl_verify.h"
#include "ssl_verify_backend.h"
#include "ssl_openssl.h"
#include <openssl/x509v3.h>

int
verify_callback (int preverify_ok, X509_STORE_CTX * ctx)
{
  struct tls_session *session;
  SSL *ssl;

  /* get the tls_session pointer */
  ssl = X509_STORE_CTX_get_ex_data (ctx, SSL_get_ex_data_X509_STORE_CTX_idx());
  ASSERT (ssl);
  session = (struct tls_session *) SSL_get_ex_data (ssl, mydata_index);
  ASSERT (session);

  cert_hash_remember (session, ctx->error_depth, ctx->current_cert->sha1_hash);

  /* did peer present cert which was signed by our root cert? */
  if (!preverify_ok)
    {
      /* get the X509 name */
      char *subject = X509_NAME_oneline (
	  X509_get_subject_name (ctx->current_cert), NULL, 0);

      if (subject)
	{
	  /* Remote site specified a certificate, but it's not correct */
	  msg (D_TLS_ERRORS, "VERIFY ERROR: depth=%d, error=%s: %s",
	      ctx->error_depth,
	      X509_verify_cert_error_string (ctx->error),
	      subject);
	  free (subject);
	}

      ERR_clear_error();

      session->verified = false;

      return 1;
    }

  return verify_cert(session, ctx->current_cert, ctx->error_depth);
}
