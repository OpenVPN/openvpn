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

/*
 * Print debugging information on SSL/TLS session negotiation.
 */

#ifndef INFO_CALLBACK_SSL_CONST
#define INFO_CALLBACK_SSL_CONST const
#endif
static void
info_callback (INFO_CALLBACK_SSL_CONST SSL * s, int where, int ret)
{
  if (where & SSL_CB_LOOP)
    {
      dmsg (D_HANDSHAKE_VERBOSE, "SSL state (%s): %s",
	   where & SSL_ST_CONNECT ? "connect" :
	   where & SSL_ST_ACCEPT ? "accept" :
	   "undefined", SSL_state_string_long (s));
    }
  else if (where & SSL_CB_ALERT)
    {
      dmsg (D_HANDSHAKE_VERBOSE, "SSL alert (%s): %s: %s",
	   where & SSL_CB_READ ? "read" : "write",
	   SSL_alert_type_string_long (ret),
	   SSL_alert_desc_string_long (ret));
    }
}

void
tls_ctx_set_options (struct tls_root_ctx *ctx, unsigned int ssl_flags)
{
  ASSERT(NULL != ctx);

  SSL_CTX_set_session_cache_mode (ctx->ctx, SSL_SESS_CACHE_OFF);
  SSL_CTX_set_options (ctx->ctx, SSL_OP_SINGLE_DH_USE);
  SSL_CTX_set_default_passwd_cb (ctx->ctx, pem_password_callback);

  /* Require peer certificate verification */
#if P2MP_SERVER
  if (ssl_flags & SSLF_CLIENT_CERT_NOT_REQUIRED)
    {
      msg (M_WARN, "WARNING: POTENTIALLY DANGEROUS OPTION "
	  "--client-cert-not-required may accept clients which do not present "
	  "a certificate");
    }
  else
#endif
  SSL_CTX_set_verify (ctx->ctx, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT,
		      verify_callback);

  SSL_CTX_set_info_callback (ctx->ctx, info_callback);
}

void
tls_ctx_load_dh_params (struct tls_root_ctx *ctx, const char *dh_file
#if ENABLE_INLINE_FILES
    , const char *dh_file_inline
#endif /* ENABLE_INLINE_FILES */
    )
{
  DH *dh;
  BIO *bio;

  ASSERT(NULL != ctx);

#if ENABLE_INLINE_FILES
  if (!strcmp (dh_file, INLINE_FILE_TAG) && dh_file_inline)
    {
      if (!(bio = BIO_new_mem_buf ((char *)dh_file_inline, -1)))
	msg (M_SSLERR, "Cannot open memory BIO for inline DH parameters");
    }
  else
#endif /* ENABLE_INLINE_FILES */
    {
      /* Get Diffie Hellman Parameters */
      if (!(bio = BIO_new_file (dh_file, "r")))
	msg (M_SSLERR, "Cannot open %s for DH parameters", dh_file);
    }

  dh = PEM_read_bio_DHparams (bio, NULL, NULL, NULL);
  BIO_free (bio);

  if (!dh)
    msg (M_SSLERR, "Cannot load DH parameters from %s", dh_file);
  if (!SSL_CTX_set_tmp_dh (ctx->ctx, dh))
    msg (M_SSLERR, "SSL_CTX_set_tmp_dh");

  msg (D_TLS_DEBUG_LOW, "Diffie-Hellman initialized with %d bit key",
       8 * DH_size (dh));

  DH_free (dh);
}

int
tls_ctx_load_pkcs12(struct tls_root_ctx *ctx, const char *pkcs12_file,
#if ENABLE_INLINE_FILES
    const char *pkcs12_file_inline,
#endif /* ENABLE_INLINE_FILES */
    bool load_ca_file
    )
{
  FILE *fp;
  EVP_PKEY *pkey;
  X509 *cert;
  STACK_OF(X509) *ca = NULL;
  PKCS12 *p12;
  int i;
  char password[256];

  ASSERT(NULL != ctx);

#if ENABLE_INLINE_FILES
  if (!strcmp (pkcs12_file, INLINE_FILE_TAG) && pkcs12_file_inline)
    {
      BIO *b64 = BIO_new(BIO_f_base64());
      BIO *bio = BIO_new_mem_buf((void *) pkcs12_file_inline,
	  (int) strlen(pkcs12_file_inline));
      ASSERT(b64 && bio);
      BIO_push(b64, bio);
      p12 = d2i_PKCS12_bio(b64, NULL);
      if (!p12)
	msg(M_SSLERR, "Error reading inline PKCS#12 file");
      BIO_free(b64);
      BIO_free(bio);
    }
  else
#endif
    {
      /* Load the PKCS #12 file */
      if (!(fp = fopen(pkcs12_file, "rb")))
	msg(M_SSLERR, "Error opening file %s", pkcs12_file);
      p12 = d2i_PKCS12_fp(fp, NULL);
      fclose(fp);
      if (!p12)
	msg(M_SSLERR, "Error reading PKCS#12 file %s", pkcs12_file);
    }

  /* Parse the PKCS #12 file */
  if (!PKCS12_parse(p12, "", &pkey, &cert, &ca))
   {
     pem_password_callback (password, sizeof(password) - 1, 0, NULL);
     /* Reparse the PKCS #12 file with password */
     ca = NULL;
     if (!PKCS12_parse(p12, password, &pkey, &cert, &ca))
      {
#ifdef ENABLE_MANAGEMENT
	      if (management && (ERR_GET_REASON (ERR_peek_error()) == PKCS12_R_MAC_VERIFY_FAILURE))
		management_auth_failure (management, UP_TYPE_PRIVATE_KEY, NULL);
#endif
	PKCS12_free(p12);
	return 1;
      }
   }
  PKCS12_free(p12);

  /* Load Certificate */
  if (!SSL_CTX_use_certificate (ctx->ctx, cert))
   msg (M_SSLERR, "Cannot use certificate");

  /* Load Private Key */
  if (!SSL_CTX_use_PrivateKey (ctx->ctx, pkey))
   msg (M_SSLERR, "Cannot use private key");
  warn_if_group_others_accessible (pkcs12_file);

  /* Check Private Key */
  if (!SSL_CTX_check_private_key (ctx->ctx))
   msg (M_SSLERR, "Private key does not match the certificate");

  /* Set Certificate Verification chain */
  if (load_ca_file)
   {
     if (ca && sk_X509_num(ca))
      {
	for (i = 0; i < sk_X509_num(ca); i++)
	  {
	      if (!X509_STORE_add_cert(ctx->ctx->cert_store,sk_X509_value(ca, i)))
	      msg (M_SSLERR, "Cannot add certificate to certificate chain (X509_STORE_add_cert)");
	    if (!SSL_CTX_add_client_CA(ctx->ctx, sk_X509_value(ca, i)))
	      msg (M_SSLERR, "Cannot add certificate to client CA list (SSL_CTX_add_client_CA)");
	  }
      }
   }
  return 0;
}

#ifdef ENABLE_PKCS11
int
tls_ctx_load_pkcs11(struct tls_root_ctx *ctx, bool pkcs11_id_management,
    const char *pkcs11_id)
{
  ASSERT(NULL != ctx);

  /* Load Certificate and Private Key */
  if (!SSL_CTX_use_pkcs11 (ctx->ctx, pkcs11_id_management, pkcs11_id))
    {
      msg (M_WARN, "Cannot load certificate \"%s\" using PKCS#11 interface", pkcs11_id);
      return 1;
    }
  return 0;
}
#endif /* ENABLE_PKCS11 */

#ifdef WIN32
void
tls_ctx_load_cryptoapi(struct tls_root_ctx *ctx, const char *cryptoapi_cert)
{
  ASSERT(NULL != ctx);

  /* Load Certificate and Private Key */
  if (!SSL_CTX_use_CryptoAPI_certificate (ctx->ctx, cryptoapi_cert))
    msg (M_SSLERR, "Cannot load certificate \"%s\" from Microsoft Certificate Store",
	   options->cryptoapi_cert);
}
#endif /* WIN32 */

/*
 * Based on SSL_CTX_use_certificate_file, return an x509 object for the
 * given file.
 */
static int
tls_ctx_read_certificate_file(SSL_CTX *ctx, const char *file, X509 **x509)
{
  int j;
  BIO *in;
  int ret=0;
  X509 *x=NULL;

  in=BIO_new(BIO_s_file_internal());
  if (in == NULL)
    {
      SSLerr(SSL_F_SSL_CTX_USE_CERTIFICATE_FILE, ERR_R_BUF_LIB);
      goto end;
    }

  if (BIO_read_filename(in,file) <= 0)
    {
      SSLerr(SSL_F_SSL_CTX_USE_CERTIFICATE_FILE, ERR_R_SYS_LIB);
      goto end;
    }

  x = PEM_read_bio_X509(in, NULL, ctx->default_passwd_callback,
    ctx->default_passwd_callback_userdata);
  if (x == NULL)
    {
      SSLerr(SSL_F_SSL_CTX_USE_CERTIFICATE_FILE, ERR_R_PEM_LIB);
      goto end;
    }

 end:
  if (in != NULL)
    BIO_free(in);
  if (x509)
    *x509 = x;
  else if (x)
    X509_free (x);
  return(ret);
}

void
tls_ctx_load_cert_file (struct tls_root_ctx *ctx, const char *cert_file,
#if ENABLE_INLINE_FILES
    const char *cert_file_inline,
#endif
    X509 **x509
    )
{
  ASSERT(NULL != ctx);
  if (NULL != x509)
    ASSERT(NULL == *x509);

#if ENABLE_INLINE_FILES
  if (!strcmp (cert_file, INLINE_FILE_TAG) && cert_file_inline)
    {
      BIO *in = NULL;
      X509 *x = NULL;
      int ret = 0;

      in = BIO_new_mem_buf ((char *)cert_file_inline, -1);
      if (in)
	{
	  x = PEM_read_bio_X509 (in,
			     NULL,
			     ctx->ctx->default_passwd_callback,
			     ctx->ctx->default_passwd_callback_userdata);
	  BIO_free (in);
	  if (x) {
	    ret = SSL_CTX_use_certificate(ctx->ctx, x);
	    if (x509)
	      *x509 = x;
	    else
	      X509_free (x);
	  }
	}

      if (!ret)
        msg (M_SSLERR, "Cannot load inline certificate file");
    }
  else
#endif /* ENABLE_INLINE_FILES */
    {
      if (!SSL_CTX_use_certificate_chain_file (ctx->ctx, cert_file))
	msg (M_SSLERR, "Cannot load certificate file %s", cert_file);
      if (x509)
	{
	  if (!tls_ctx_read_certificate_file(ctx->ctx, cert_file, x509))
	    msg (M_SSLERR, "Cannot load certificate file %s", cert_file);
	}
    }
}

#if ENABLE_INLINE_FILES
static int
use_inline_PrivateKey_file (SSL_CTX *ctx, const char *key_string)
{
  BIO *in = NULL;
  EVP_PKEY *pkey = NULL;
  int ret = 0;

  in = BIO_new_mem_buf ((char *)key_string, -1);
  if (!in)
    goto end;

  pkey = PEM_read_bio_PrivateKey (in,
				  NULL,
				  ctx->default_passwd_callback,
				  ctx->default_passwd_callback_userdata);
  if (!pkey)
    goto end;

  ret = SSL_CTX_use_PrivateKey (ctx, pkey);

 end:
  if (pkey)
    EVP_PKEY_free (pkey);
  if (in)
    BIO_free (in);
  return ret;
}
#endif /* ENABLE_INLINE_FILES */

int
tls_ctx_load_priv_file (struct tls_root_ctx *ctx, const char *priv_key_file
#if ENABLE_INLINE_FILES
    , const char *priv_key_file_inline
#endif
    )
{
  ASSERT(NULL != ctx);

  int status;

#if ENABLE_INLINE_FILES
  if (!strcmp (priv_key_file, INLINE_FILE_TAG) && priv_key_file_inline)
    {
      status = use_inline_PrivateKey_file (ctx->ctx, priv_key_file_inline);
    }
  else
#endif /* ENABLE_INLINE_FILES */
    {
      status = SSL_CTX_use_PrivateKey_file (ctx->ctx, priv_key_file, SSL_FILETYPE_PEM);
    }
  if (!status)
    {
#ifdef ENABLE_MANAGEMENT
      if (management && (ERR_GET_REASON (ERR_peek_error()) == EVP_R_BAD_DECRYPT))
	  management_auth_failure (management, UP_TYPE_PRIVATE_KEY, NULL);
#endif
      msg (M_WARN|M_SSL, "Cannot load private key file %s", priv_key_file);
      return 1;
    }
  warn_if_group_others_accessible (priv_key_file);

  /* Check Private Key */
  if (!SSL_CTX_check_private_key (ctx->ctx))
    msg (M_SSLERR, "Private key does not match the certificate");
  return 0;

}

#ifdef MANAGMENT_EXTERNAL_KEY

/* encrypt */
static int
rsa_pub_enc(int flen, const unsigned char *from, unsigned char *to, RSA *rsa, int padding)
{
  ASSERT(0);
  return -1;
}

/* verify arbitrary data */
static int
rsa_pub_dec(int flen, const unsigned char *from, unsigned char *to, RSA *rsa, int padding)
{
  ASSERT(0);
  return -1;
}

/* decrypt */
static int
rsa_priv_dec(int flen, const unsigned char *from, unsigned char *to, RSA *rsa, int padding)
{
  ASSERT(0);
  return -1;
}

/* called at RSA_free */
static int
rsa_finish(RSA *rsa)
{
  free ((void*)rsa->meth);
  rsa->meth = NULL;
  return 1;
}

/* sign arbitrary data */
static int
rsa_priv_enc(int flen, const unsigned char *from, unsigned char *to, RSA *rsa, int padding)
{
  /* optional app data in rsa->meth->app_data; */
  char *in_b64 = NULL;
  char *out_b64 = NULL;
  int ret = -1;
  int len;

  if (padding != RSA_PKCS1_PADDING)
    {
      RSAerr (RSA_F_RSA_EAY_PRIVATE_ENCRYPT, RSA_R_UNKNOWN_PADDING_TYPE);
      goto done;
    }

  /* convert 'from' to base64 */
  if (base64_encode (from, flen, &in_b64) <= 0)
    goto done;

  /* call MI for signature */
  if (management)
    out_b64 = management_query_rsa_sig (management, in_b64);
  if (!out_b64)
    goto done;

  /* decode base64 signature to binary */
  len = RSA_size(rsa);
  ret = base64_decode (out_b64, to, len);

  /* verify length */
  if (ret != len)
    ret = -1;

 done:
  if (in_b64)
    free (in_b64);
  if (out_b64)
    free (out_b64);
  return ret;
}

int
tls_ctx_use_external_private_key (struct tls_root_ctx *ctx, X509 *cert)
{
  RSA *rsa = NULL;
  RSA *pub_rsa;
  RSA_METHOD *rsa_meth;

  ASSERT (NULL != ctx);
  ASSERT (NULL != cert);

  /* allocate custom RSA method object */
  ALLOC_OBJ_CLEAR (rsa_meth, RSA_METHOD);
  rsa_meth->name = "OpenVPN external private key RSA Method";
  rsa_meth->rsa_pub_enc = rsa_pub_enc;
  rsa_meth->rsa_pub_dec = rsa_pub_dec;
  rsa_meth->rsa_priv_enc = rsa_priv_enc;
  rsa_meth->rsa_priv_dec = rsa_priv_dec;
  rsa_meth->init = NULL;
  rsa_meth->finish = rsa_finish;
  rsa_meth->flags = RSA_METHOD_FLAG_NO_CHECK;
  rsa_meth->app_data = NULL;

  /* allocate RSA object */
  rsa = RSA_new();
  if (rsa == NULL)
    {
      SSLerr(SSL_F_SSL_USE_PRIVATEKEY, ERR_R_MALLOC_FAILURE);
      goto err;
    }

  /* get the public key */
  ASSERT(cert->cert_info->key->pkey); /* NULL before SSL_CTX_use_certificate() is called */
  pub_rsa = cert->cert_info->key->pkey->pkey.rsa;

  /* initialize RSA object */
  rsa->n = BN_dup(pub_rsa->n);
  rsa->flags |= RSA_FLAG_EXT_PKEY;
  if (!RSA_set_method(rsa, rsa_meth))
    goto err;

  /* bind our custom RSA object to ssl_ctx */
  if (!SSL_CTX_use_RSAPrivateKey(ctx->ctx, rsa))
    goto err;

  RSA_free(rsa); /* doesn't necessarily free, just decrements refcount */
  return 1;

 err:
  if (rsa)
    RSA_free(rsa);
  else
    {
      if (rsa_meth)
	free(rsa_meth);
    }
  msg (M_SSLERR, "Cannot enable SSL external private key capability");
  return 0;
}

#endif

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
