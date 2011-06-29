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
 * @file Control Channel OpenSSL Backend
 */

#include "syshead.h"
#include "errlevel.h"
#include "buffer.h"
#include "misc.h"
#include "manage.h"
#include "memdbg.h"
#include "ssl_backend.h"
#include "ssl_common.h"

#include "ssl_verify_openssl.h"

#include <openssl/err.h>
#include <openssl/pkcs12.h>
#include <openssl/x509.h>
#include <openssl/crypto.h>

/*
 * Allocate space in SSL objects in which to store a struct tls_session
 * pointer back to parent.
 *
 */

int mydata_index; /* GLOBAL */

void
tls_init_lib()
{
  SSL_library_init();
  SSL_load_error_strings();
  OpenSSL_add_all_algorithms ();

  mydata_index = SSL_get_ex_new_index(0, "struct session *", NULL, NULL, NULL);
  ASSERT (mydata_index >= 0);
}

void
tls_free_lib()
{
  EVP_cleanup();
  ERR_free_strings();
}

void
tls_clear_error()
{
  ERR_clear_error ();
}

/*
 * OpenSSL callback to get a temporary RSA key, mostly
 * used for export ciphers.
 */
static RSA *
tmp_rsa_cb (SSL * s, int is_export, int keylength)
{
  static RSA *rsa_tmp = NULL;
  if (rsa_tmp == NULL)
    {
      msg (D_HANDSHAKE, "Generating temp (%d bit) RSA key", keylength);
      rsa_tmp = RSA_generate_key (keylength, RSA_F4, NULL, NULL);
    }
  return (rsa_tmp);
}

void
tls_ctx_server_new(struct tls_root_ctx *ctx)
{
  ASSERT(NULL != ctx);

  ctx->ctx = SSL_CTX_new (TLSv1_server_method ());

  if (ctx->ctx == NULL)
    msg (M_SSLERR, "SSL_CTX_new TLSv1_server_method");

  SSL_CTX_set_tmp_rsa_callback (ctx->ctx, tmp_rsa_cb);
}

void
tls_ctx_client_new(struct tls_root_ctx *ctx)
{
  ASSERT(NULL != ctx);

  ctx->ctx = SSL_CTX_new (TLSv1_client_method ());

  if (ctx->ctx == NULL)
    msg (M_SSLERR, "SSL_CTX_new TLSv1_client_method");
}

void
tls_ctx_free(struct tls_root_ctx *ctx)
{
  ASSERT(NULL != ctx);
  if (NULL != ctx->ctx)
    SSL_CTX_free (ctx->ctx);
  ctx->ctx = NULL;
}

bool tls_ctx_initialised(struct tls_root_ctx *ctx)
{
  ASSERT(NULL != ctx);
  return NULL != ctx->ctx;
}

void
show_available_tls_ciphers ()
{
  SSL_CTX *ctx;
  SSL *ssl;
  const char *cipher_name;
  int priority = 0;

  ctx = SSL_CTX_new (TLSv1_method ());
  if (!ctx)
    msg (M_SSLERR, "Cannot create SSL_CTX object");

  ssl = SSL_new (ctx);
  if (!ssl)
    msg (M_SSLERR, "Cannot create SSL object");

  printf ("Available TLS Ciphers,\n");
  printf ("listed in order of preference:\n\n");
  while ((cipher_name = SSL_get_cipher_list (ssl, priority++)))
    printf ("%s\n", cipher_name);
  printf ("\n");

  SSL_free (ssl);
  SSL_CTX_free (ctx);
}

void
get_highest_preference_tls_cipher (char *buf, int size)
{
  SSL_CTX *ctx;
  SSL *ssl;
  const char *cipher_name;

  ctx = SSL_CTX_new (TLSv1_method ());
  if (!ctx)
    msg (M_SSLERR, "Cannot create SSL_CTX object");
  ssl = SSL_new (ctx);
  if (!ssl)
    msg (M_SSLERR, "Cannot create SSL object");

  cipher_name = SSL_get_cipher_list (ssl, 0);
  strncpynt (buf, cipher_name, size);

  SSL_free (ssl);
  SSL_CTX_free (ctx);
}
