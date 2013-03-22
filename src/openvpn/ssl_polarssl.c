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
 * @file Control Channel PolarSSL Backend
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#elif defined(_MSC_VER)
#include "config-msvc.h"
#endif

#include "syshead.h"

#if defined(ENABLE_SSL) && defined(ENABLE_CRYPTO_POLARSSL)

#include "errlevel.h"
#include "ssl_backend.h"
#include "buffer.h"
#include "misc.h"
#include "manage.h"
#include "ssl_common.h"

#include <polarssl/sha2.h>
#include <polarssl/havege.h>

#include "ssl_verify_polarssl.h"
#include <polarssl/pem.h>

void
tls_init_lib()
{
}

void
tls_free_lib()
{
}

void
tls_clear_error()
{
}

void
tls_ctx_server_new(struct tls_root_ctx *ctx)
{
  ASSERT(NULL != ctx);
  CLEAR(*ctx);

  ALLOC_OBJ_CLEAR(ctx->dhm_ctx, dhm_context);
  ALLOC_OBJ_CLEAR(ctx->priv_key, rsa_context);

  ALLOC_OBJ_CLEAR(ctx->ca_chain, x509_cert);
  ALLOC_OBJ_CLEAR(ctx->crt_chain, x509_cert);


  ctx->endpoint = SSL_IS_SERVER;
  ctx->initialised = true;
}

void
tls_ctx_client_new(struct tls_root_ctx *ctx)
{
  ASSERT(NULL != ctx);
  CLEAR(*ctx);

  ALLOC_OBJ_CLEAR(ctx->dhm_ctx, dhm_context);
  ALLOC_OBJ_CLEAR(ctx->priv_key, rsa_context);

  ALLOC_OBJ_CLEAR(ctx->ca_chain, x509_cert);
  ALLOC_OBJ_CLEAR(ctx->crt_chain, x509_cert);

  ctx->endpoint = SSL_IS_CLIENT;
  ctx->initialised = true;
}

void
tls_ctx_free(struct tls_root_ctx *ctx)
{
  if (ctx)
    {
      rsa_free(ctx->priv_key);
      free(ctx->priv_key);

      x509_free(ctx->ca_chain);
      free(ctx->ca_chain);

      x509_free(ctx->crt_chain);
      free(ctx->crt_chain);

      dhm_free(ctx->dhm_ctx);
      free(ctx->dhm_ctx);

#if defined(ENABLE_PKCS11)
      if (ctx->priv_key_pkcs11 != NULL) {
	  pkcs11_priv_key_free(ctx->priv_key_pkcs11);
	  free(ctx->priv_key_pkcs11);
      }
#endif

      if (ctx->allowed_ciphers)
	free(ctx->allowed_ciphers);

      CLEAR(*ctx);

      ctx->initialised = false;

    }
}

bool
tls_ctx_initialised(struct tls_root_ctx *ctx)
{
  ASSERT(NULL != ctx);
  return ctx->initialised;
}

void
tls_ctx_set_options (struct tls_root_ctx *ctx, unsigned int ssl_flags)
{
}

static const char *
tls_translate_cipher_name (const char * cipher_name) {
  const tls_cipher_name_pair * pair = tls_get_cipher_name_pair(cipher_name, strlen(cipher_name));

  if (NULL == pair)
    {
      // No translation found, return original
      return cipher_name;
    }

  if (0 != strcmp(cipher_name, pair->iana_name))
    {
      // Deprecated name found, notify user
      msg(M_WARN, "Deprecated cipher suite name '%s', please use IANA name '%s'", pair->openssl_name, pair->iana_name);
    }

  return pair->iana_name;
}

void
tls_ctx_restrict_ciphers(struct tls_root_ctx *ctx, const char *ciphers)
{
  char *tmp_ciphers, *tmp_ciphers_orig, *token;
  int i, cipher_count;
  int ciphers_len = strlen (ciphers);

  ASSERT (NULL != ctx);
  ASSERT (0 != ciphers_len);

  /* Get number of ciphers */
  for (i = 0, cipher_count = 1; i < ciphers_len; i++)
    if (ciphers[i] == ':')
      cipher_count++;

  /* Allocate an array for them */
  ALLOC_ARRAY_CLEAR(ctx->allowed_ciphers, int, cipher_count+1)

  /* Parse allowed ciphers, getting IDs */
  i = 0;
  tmp_ciphers_orig = tmp_ciphers = strdup(ciphers);

  token = strtok (tmp_ciphers, ":");
  while(token)
    {
      ctx->allowed_ciphers[i] = ssl_get_ciphersuite_id (
	  tls_translate_cipher_name (token));
      if (0 != ctx->allowed_ciphers[i])
	i++;
      token = strtok (NULL, ":");
    }
  free(tmp_ciphers_orig);
}

void
tls_ctx_load_dh_params (struct tls_root_ctx *ctx, const char *dh_file,
    const char *dh_file_inline
    )
{
  if (!strcmp (dh_file, INLINE_FILE_TAG) && dh_file_inline)
    {
      if (0 != x509parse_dhm(ctx->dhm_ctx, dh_file_inline, strlen(dh_file_inline)))
	msg (M_FATAL, "Cannot read inline DH parameters");
  }
else
  {
    if (0 != x509parse_dhmfile(ctx->dhm_ctx, dh_file))
      msg (M_FATAL, "Cannot read DH parameters from file %s", dh_file);
  }

  msg (D_TLS_DEBUG_LOW, "Diffie-Hellman initialized with " counter_format " bit key",
      (counter_type) 8 * mpi_size(&ctx->dhm_ctx->P));
}

int
tls_ctx_load_pkcs12(struct tls_root_ctx *ctx, const char *pkcs12_file,
    const char *pkcs12_file_inline,
    bool load_ca_file
    )
{
  msg(M_FATAL, "PKCS #12 files not yet supported for PolarSSL.");
  return 0;
}

#ifdef ENABLE_CRYPTOAPI
void
tls_ctx_load_cryptoapi(struct tls_root_ctx *ctx, const char *cryptoapi_cert)
{
  msg(M_FATAL, "Windows CryptoAPI not yet supported for PolarSSL.");
}
#endif /* WIN32 */

void
tls_ctx_load_cert_file (struct tls_root_ctx *ctx, const char *cert_file,
    const char *cert_file_inline,
    openvpn_x509_cert_t **x509
    )
{
  ASSERT(NULL != ctx);
  if (NULL != x509)
    ASSERT(NULL == *x509);

  if (!strcmp (cert_file, INLINE_FILE_TAG) && cert_file_inline)
    {
      if (0 != x509parse_crt(ctx->crt_chain, cert_file_inline,
	  strlen(cert_file_inline)))
        msg (M_FATAL, "Cannot load inline certificate file");
    }
  else
    {
      if (0 != x509parse_crtfile(ctx->crt_chain, cert_file))
	msg (M_FATAL, "Cannot load certificate file %s", cert_file);
    }
  if (x509)
    {
      *x509 = ctx->crt_chain;
    }
}

void
tls_ctx_free_cert_file (openvpn_x509_cert_t *x509)
{
  x509_free(x509);
}

int
tls_ctx_load_priv_file (struct tls_root_ctx *ctx, const char *priv_key_file,
    const char *priv_key_file_inline
    )
{
  int status;
  ASSERT(NULL != ctx);

  if (!strcmp (priv_key_file, INLINE_FILE_TAG) && priv_key_file_inline)
    {
      status = x509parse_key(ctx->priv_key,
	  priv_key_file_inline, strlen(priv_key_file_inline),
	  NULL, 0);
      if (POLARSSL_ERR_PEM_PASSWORD_REQUIRED == status)
	{
	  char passbuf[512] = {0};
	  pem_password_callback(passbuf, 512, 0, NULL);
	  status = x509parse_key(ctx->priv_key,
	      priv_key_file_inline, strlen(priv_key_file_inline),
	      passbuf, strlen(passbuf));
	}
    }
  else
    {
      status = x509parse_keyfile(ctx->priv_key, priv_key_file, NULL);
      if (POLARSSL_ERR_PEM_PASSWORD_REQUIRED == status)
	{
	  char passbuf[512] = {0};
	  pem_password_callback(passbuf, 512, 0, NULL);
	  status = x509parse_keyfile(ctx->priv_key, priv_key_file, passbuf);
	}
    }
  if (0 != status)
    {
#ifdef ENABLE_MANAGEMENT
      if (management && (POLARSSL_ERR_PEM_PASSWORD_MISMATCH == status))
	  management_auth_failure (management, UP_TYPE_PRIVATE_KEY, NULL);
#endif
      msg (M_WARN, "Cannot load private key file %s", priv_key_file);
      return 1;
    }

  warn_if_group_others_accessible (priv_key_file);

  /* TODO: Check Private Key */
#if 0
  if (!SSL_CTX_check_private_key (ctx))
    msg (M_SSLERR, "Private key does not match the certificate");
#endif
  return 0;
}

#ifdef MANAGMENT_EXTERNAL_KEY

int
tls_ctx_use_external_private_key (struct tls_root_ctx *ctx, openvpn_x509_cert_t *cert)
{
  msg(M_FATAL, "Use of management external keys not yet supported for PolarSSL.");
  return false;
}

#endif

void tls_ctx_load_ca (struct tls_root_ctx *ctx, const char *ca_file,
    const char *ca_file_inline,
    const char *ca_path, bool tls_server
    )
{
  if (ca_path)
      msg(M_FATAL, "ERROR: PolarSSL cannot handle the capath directive");

  if (ca_file && !strcmp (ca_file, INLINE_FILE_TAG) && ca_file_inline)
    {
      if (0 != x509parse_crt(ctx->ca_chain, ca_file_inline, strlen(ca_file_inline)))
	msg (M_FATAL, "Cannot load inline CA certificates");
    }
  else
    {
      /* Load CA file for verifying peer supplied certificate */
      if (0 != x509parse_crtfile(ctx->ca_chain, ca_file))
	msg (M_FATAL, "Cannot load CA certificate file %s", ca_file);
    }
}

void
tls_ctx_load_extra_certs (struct tls_root_ctx *ctx, const char *extra_certs_file,
    const char *extra_certs_file_inline
    )
{
  ASSERT(NULL != ctx);

  if (!strcmp (extra_certs_file, INLINE_FILE_TAG) && extra_certs_file_inline)
    {
      if (0 != x509parse_crt(ctx->crt_chain, extra_certs_file_inline,
	  strlen(extra_certs_file_inline)))
        msg (M_FATAL, "Cannot load inline extra-certs file");
    }
  else
    {
      if (0 != x509parse_crtfile(ctx->crt_chain, extra_certs_file))
	msg (M_FATAL, "Cannot load extra-certs file: %s", extra_certs_file);
    }
}

/* **************************************
 *
 * Key-state specific functions
 *
 ***************************************/

/*
 * "Endless buffer"
 */

static inline void buf_free_entry(buffer_entry *entry)
{
  if (NULL != entry)
    {
      free(entry->data);
      free(entry);
    }
}

static void buf_free_entries(endless_buffer *buf)
{
  while(buf->first_block)
    {
      buffer_entry *cur_block = buf->first_block;
      buf->first_block = cur_block->next_block;
      buf_free_entry(cur_block);
    }
  buf->last_block = NULL;
}

static int endless_buf_read( void * ctx, unsigned char * out, size_t out_len )
{
  endless_buffer *in = (endless_buffer *) ctx;
  size_t read_len = 0;

  if (in->first_block == NULL)
    return POLARSSL_ERR_NET_WANT_READ;

  while (in->first_block != NULL && read_len < out_len)
    {
      int block_len = in->first_block->length - in->data_start;
      if (block_len <= out_len - read_len)
	{
	  buffer_entry *cur_entry = in->first_block;
	  memcpy(out + read_len, cur_entry->data + in->data_start,
	      block_len);

	  read_len += block_len;

	  in->first_block = cur_entry->next_block;
	  in->data_start = 0;

	  if (in->first_block == NULL)
	    in->last_block = NULL;

	  buf_free_entry(cur_entry);
	}
      else
	{
	  memcpy(out + read_len, in->first_block->data + in->data_start,
	      out_len - read_len);
	  in->data_start += out_len - read_len;
	  read_len = out_len;
	}
    }

  return read_len;
}

static int endless_buf_write( void *ctx, const unsigned char *in, size_t len )
{
  endless_buffer *out = (endless_buffer *) ctx;
  buffer_entry *new_block = malloc(sizeof(buffer_entry));
  if (NULL == new_block)
    return POLARSSL_ERR_NET_SEND_FAILED;

  new_block->data = malloc(len);
  if (NULL == new_block->data)
    {
      free(new_block);
      return POLARSSL_ERR_NET_SEND_FAILED;
    }

  new_block->length = len;
  new_block->next_block = NULL;

  memcpy(new_block->data, in, len);

  if (NULL == out->first_block)
    out->first_block = new_block;

  if (NULL != out->last_block)
    out->last_block->next_block = new_block;

  out->last_block = new_block;

  return len;
}

static void my_debug( void *ctx, int level, const char *str )
{
  if (level == 1)
    {
      dmsg (D_HANDSHAKE_VERBOSE, "PolarSSL alert: %s", str);
    }
}

/*
 * Further personalise the RNG using a hash of the public key
 */
void tls_ctx_personalise_random(struct tls_root_ctx *ctx)
{
  static char old_sha256_hash[32] = {0};
  char sha256_hash[32] = {0};
  ctr_drbg_context *cd_ctx = rand_ctx_get();

  if (NULL != ctx->crt_chain)
    {
      x509_cert *cert = ctx->crt_chain;

      sha2(cert->tbs.p, cert->tbs.len, sha256_hash, false);
      if ( 0 != memcmp(old_sha256_hash, sha256_hash, sizeof(sha256_hash)))
	{
	  ctr_drbg_update(cd_ctx, sha256_hash, 32);
	  memcpy(old_sha256_hash, sha256_hash, sizeof(old_sha256_hash));
	}
    }
}

void key_state_ssl_init(struct key_state_ssl *ks_ssl,
    const struct tls_root_ctx *ssl_ctx, bool is_server, void *session)
{
  ASSERT(NULL != ssl_ctx);
  ASSERT(ks_ssl);
  CLEAR(*ks_ssl);

  ALLOC_OBJ_CLEAR(ks_ssl->ctx, ssl_context);
  if (0 == ssl_init(ks_ssl->ctx))
    {
      /* Initialise SSL context */
      ssl_set_dbg (ks_ssl->ctx, my_debug, NULL);
      ssl_set_endpoint (ks_ssl->ctx, ssl_ctx->endpoint);

      ssl_set_rng (ks_ssl->ctx, ctr_drbg_random, rand_ctx_get());

      if (ssl_ctx->allowed_ciphers)
	ssl_set_ciphersuites (ks_ssl->ctx, ssl_ctx->allowed_ciphers);

      /* Initialise authentication information */
      if (is_server)
	ssl_set_dh_param_ctx (ks_ssl->ctx, ssl_ctx->dhm_ctx );
#if defined(ENABLE_PKCS11)
      if (ssl_ctx->priv_key_pkcs11 != NULL)
	ssl_set_own_cert_alt( ks_ssl->ctx, ssl_ctx->crt_chain,
	    ssl_ctx->priv_key_pkcs11, ssl_pkcs11_decrypt, ssl_pkcs11_sign,
	    ssl_pkcs11_key_len );
      else
#endif
	ssl_set_own_cert( ks_ssl->ctx, ssl_ctx->crt_chain, ssl_ctx->priv_key );

      /* Initialise SSL verification */
      ssl_set_authmode (ks_ssl->ctx, SSL_VERIFY_REQUIRED);
      ssl_set_verify (ks_ssl->ctx, verify_callback, session);
      /* TODO: PolarSSL does not currently support sending the CA chain to the client */
      ssl_set_ca_chain (ks_ssl->ctx, ssl_ctx->ca_chain, NULL, NULL );

      /* Initialise BIOs */
      ALLOC_OBJ_CLEAR (ks_ssl->ct_in, endless_buffer);
      ALLOC_OBJ_CLEAR (ks_ssl->ct_out, endless_buffer);
      ssl_set_bio (ks_ssl->ctx, endless_buf_read, ks_ssl->ct_in,
	  endless_buf_write, ks_ssl->ct_out);
    }
}

void
key_state_ssl_free(struct key_state_ssl *ks_ssl)
{
  if (ks_ssl) {
      if (ks_ssl->ctx)
	{
	  ssl_free(ks_ssl->ctx);
	  free(ks_ssl->ctx);
	}
      if (ks_ssl->ct_in) {
	buf_free_entries(ks_ssl->ct_in);
	free(ks_ssl->ct_in);
      }
      if (ks_ssl->ct_out) {
	buf_free_entries(ks_ssl->ct_out);
	free(ks_ssl->ct_out);
      }
      CLEAR(*ks_ssl);
  }
}

int
key_state_write_plaintext (struct key_state_ssl *ks, struct buffer *buf)
{
  int retval = 0;
  perf_push (PERF_BIO_WRITE_PLAINTEXT);

  ASSERT (NULL != ks);
  ASSERT (buf);
  ASSERT (buf->len >= 0);

  if (0 == buf->len)
    {
      return 0;
      perf_pop ();
    }

  retval = ssl_write(ks->ctx, BPTR(buf), buf->len);

  if (retval < 0)
    {
      perf_pop ();
      if (POLARSSL_ERR_NET_WANT_WRITE == retval || POLARSSL_ERR_NET_WANT_READ == retval)
	return 0;
      msg (D_TLS_ERRORS, "TLS ERROR: write tls_write_plaintext error");
      return -1;
    }

  if (retval != buf->len)
    {
      msg (D_TLS_ERRORS,
	  "TLS ERROR: write tls_write_plaintext incomplete %d/%d",
	  retval, buf->len);
      perf_pop ();
      return -1;
    }

  /* successful write */
  dmsg (D_HANDSHAKE_VERBOSE, "write tls_write_plaintext %d bytes", retval);

  memset (BPTR (buf), 0, BLEN (buf)); /* erase data just written */
  buf->len = 0;

  perf_pop ();
  return 1;
}

int
key_state_write_plaintext_const (struct key_state_ssl *ks, const uint8_t *data, int len)
{
  int retval = 0;
  perf_push (PERF_BIO_WRITE_PLAINTEXT);

  ASSERT (NULL != ks);
  ASSERT (len >= 0);

  if (0 == len)
    {
      perf_pop ();
      return 0;
    }

  ASSERT (data);

  retval = ssl_write(ks->ctx, data, len);

  if (retval < 0)
    {
      perf_pop ();
      if (POLARSSL_ERR_NET_WANT_WRITE == retval || POLARSSL_ERR_NET_WANT_READ == retval)
	return 0;
      msg (D_TLS_ERRORS, "TLS ERROR: write tls_write_plaintext_const error");
      return -1;
    }

  if (retval != len)
    {
      msg (D_TLS_ERRORS,
	  "TLS ERROR: write tls_write_plaintext_const incomplete %d/%d",
	  retval, len);
      perf_pop ();
      return -1;
    }

  /* successful write */
  dmsg (D_HANDSHAKE_VERBOSE, "write tls_write_plaintext_const %d bytes", retval);

  perf_pop ();
  return 1;
}

int
key_state_read_ciphertext (struct key_state_ssl *ks, struct buffer *buf,
    int maxlen)
{
  int retval = 0;
  int len = 0;
  char error_message[1024];

  perf_push (PERF_BIO_READ_CIPHERTEXT);

  ASSERT (NULL != ks);
  ASSERT (buf);
  ASSERT (buf->len >= 0);

  if (buf->len)
    {
      perf_pop ();
      return 0;
    }

  len = buf_forward_capacity (buf);
  if (maxlen < len)
    len = maxlen;

  retval = endless_buf_read(ks->ct_out, BPTR(buf), len);

  /* Error during read, check for retry error */
  if (retval < 0)
    {
      perf_pop ();
      if (POLARSSL_ERR_NET_WANT_WRITE == retval || POLARSSL_ERR_NET_WANT_READ == retval)
	return 0;
      error_strerror(retval, error_message, sizeof(error_message));
      msg (D_TLS_ERRORS, "TLS_ERROR: read tls_read_ciphertext error: %d %s", retval, error_message);
      buf->len = 0;
      return -1;
    }
  /* Nothing read, try again */
  if (0 == retval)
    {
      buf->len = 0;
      perf_pop ();
      return 0;
    }

  /* successful read */
  dmsg (D_HANDSHAKE_VERBOSE, "read tls_read_ciphertext %d bytes", retval);
  buf->len = retval;
  perf_pop ();
  return 1;
}

int
key_state_write_ciphertext (struct key_state_ssl *ks, struct buffer *buf)
{
  int retval = 0;
  perf_push (PERF_BIO_WRITE_CIPHERTEXT);

  ASSERT (NULL != ks);
  ASSERT (buf);
  ASSERT (buf->len >= 0);

  if (0 == buf->len)
    {
      perf_pop ();
      return 0;
    }

  retval = endless_buf_write(ks->ct_in, BPTR(buf), buf->len);

  if (retval < 0)
    {
      perf_pop ();

      if (POLARSSL_ERR_NET_WANT_WRITE == retval || POLARSSL_ERR_NET_WANT_READ == retval)
	return 0;
      msg (D_TLS_ERRORS, "TLS ERROR: write tls_write_ciphertext error");
      return -1;
    }

  if (retval != buf->len)
    {
      msg (D_TLS_ERRORS,
	  "TLS ERROR: write tls_write_ciphertext incomplete %d/%d",
	  retval, buf->len);
      perf_pop ();
      return -1;
    }

  /* successful write */
  dmsg (D_HANDSHAKE_VERBOSE, "write tls_write_ciphertext %d bytes", retval);

  memset (BPTR (buf), 0, BLEN (buf)); /* erase data just written */
  buf->len = 0;

  perf_pop ();
  return 1;
}

int
key_state_read_plaintext (struct key_state_ssl *ks, struct buffer *buf,
    int maxlen)
{
  int retval = 0;
  int len = 0;
  char error_message[1024];

  perf_push (PERF_BIO_READ_PLAINTEXT);

  ASSERT (NULL != ks);
  ASSERT (buf);
  ASSERT (buf->len >= 0);

  if (buf->len)
    {
      perf_pop ();
      return 0;
    }

  len = buf_forward_capacity (buf);
  if (maxlen < len)
    len = maxlen;

  retval = ssl_read(ks->ctx, BPTR(buf), len);

  /* Error during read, check for retry error */
  if (retval < 0)
    {
      if (POLARSSL_ERR_NET_WANT_WRITE == retval || POLARSSL_ERR_NET_WANT_READ == retval)
	return 0;
      error_strerror(retval, error_message, sizeof(error_message));
      msg (D_TLS_ERRORS, "TLS_ERROR: read tls_read_plaintext error: %d %s", retval, error_message);
      buf->len = 0;
      perf_pop ();
      return -1;
    }
  /* Nothing read, try again */
  if (0 == retval)
    {
      buf->len = 0;
      perf_pop ();
      return 0;
    }

  /* successful read */
  dmsg (D_HANDSHAKE_VERBOSE, "read tls_read_plaintext %d bytes", retval);
  buf->len = retval;

  perf_pop ();
  return 1;
}

/* **************************************
 *
 * Information functions
 *
 * Print information for the end user.
 *
 ***************************************/
void
print_details (struct key_state_ssl * ks_ssl, const char *prefix)
{
  const x509_cert *cert;
  char s1[256];
  char s2[256];

  s1[0] = s2[0] = 0;
  openvpn_snprintf (s1, sizeof (s1), "%s %s, cipher %s",
		    prefix,
		    ssl_get_version (ks_ssl->ctx),
		    ssl_get_ciphersuite(ks_ssl->ctx));

  cert = ssl_get_peer_cert(ks_ssl->ctx);
  if (cert != NULL)
    {
      openvpn_snprintf (s2, sizeof (s2), ", " counter_format " bit RSA", (counter_type) cert->rsa.len * 8);
    }

  msg (D_HANDSHAKE, "%s%s", s1, s2);
}

void
show_available_tls_ciphers ()
{
  const int *ciphers = ssl_list_ciphersuites();

#ifndef ENABLE_SMALL
  printf ("Available TLS Ciphers,\n");
  printf ("listed in order of preference:\n\n");
#endif

  while (*ciphers != 0)
    {
      printf ("%s\n", ssl_get_ciphersuite_name(*ciphers));
      ciphers++;
    }
  printf ("\n");
}

void
get_highest_preference_tls_cipher (char *buf, int size)
{
  const char *cipher_name;
  const int *ciphers = ssl_list_ciphersuites();
  if (*ciphers == 0)
    msg (M_FATAL, "Cannot retrieve list of supported SSL ciphers.");

  cipher_name = ssl_get_ciphersuite_name(*ciphers);
  strncpynt (buf, cipher_name, size);
}

#endif /* defined(ENABLE_SSL) && defined(ENABLE_CRYPTO_POLARSSL) */
