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

int
verify_get_subject (char **subject, X509 *cert)
{
  *subject = X509_NAME_oneline (X509_get_subject_name (cert), NULL, 0);
  if (!*subject)
      return 1;

  return 0;
}

#ifdef ENABLE_X509ALTUSERNAME
static
bool extract_x509_extension(X509 *cert, char *fieldname, char *out, int size)
{
  bool retval = false;
  X509_EXTENSION *pExt;
  char *buf = 0;
  int length = 0;
  GENERAL_NAMES *extensions;
  int nid = OBJ_txt2nid(fieldname);

  extensions = (GENERAL_NAMES *)X509_get_ext_d2i(cert, nid, NULL, NULL);
  if ( extensions )
    {
      int numalts;
      int i;
      /* get amount of alternatives,
       * RFC2459 claims there MUST be at least
       * one, but we don't depend on it...
       */

      numalts = sk_GENERAL_NAME_num(extensions);

      /* loop through all alternatives */
      for (i=0; i<numalts; i++)
        {
          /* get a handle to alternative name number i */
          const GENERAL_NAME *name = sk_GENERAL_NAME_value (extensions, i );

          switch (name->type)
            {
              case GEN_EMAIL:
                ASN1_STRING_to_UTF8((unsigned char**)&buf, name->d.ia5);
                if ( strlen (buf) != name->d.ia5->length )
                  {
                    msg (D_TLS_ERRORS, "ASN1 ERROR: string contained terminating zero");
                    OPENSSL_free (buf);
                  } else {
                    strncpynt(out, buf, size);
                    OPENSSL_free(buf);
                    retval = true;
                  }
                break;
              default:
                msg (D_TLS_ERRORS, "ASN1 ERROR: can not handle field type %i",
                     name->type);
                break;
            }
          }
        sk_GENERAL_NAME_free (extensions);
    }
  return retval;
}
#endif /* ENABLE_X509ALTUSERNAME */

/*
 * Extract a field from an X509 subject name.
 *
 * Example:
 *
 * /C=US/ST=CO/L=Denver/O=ORG/CN=First-CN/CN=Test-CA/Email=jim@yonan.net
 *
 * The common name is 'Test-CA'
 *
 * Return true on success, false on error (insufficient buffer size in 'out'
 * to contain result is grounds for error).
 */
static bool
extract_x509_field_ssl (X509_NAME *x509, const char *field_name, char *out,
    int size)
{
  int lastpos = -1;
  int tmp = -1;
  X509_NAME_ENTRY *x509ne = 0;
  ASN1_STRING *asn1 = 0;
  unsigned char *buf = (unsigned char *)1; /* bug in OpenSSL 0.9.6b ASN1_STRING_to_UTF8 requires this workaround */
  int nid = OBJ_txt2nid((char *)field_name);

  ASSERT (size > 0);
  *out = '\0';
  do {
    lastpos = tmp;
    tmp = X509_NAME_get_index_by_NID(x509, nid, lastpos);
  } while (tmp > -1);

  /* Nothing found */
  if (lastpos == -1)
    return false;

  x509ne = X509_NAME_get_entry(x509, lastpos);
  if (!x509ne)
    return false;

  asn1 = X509_NAME_ENTRY_get_data(x509ne);
  if (!asn1)
    return false;
  tmp = ASN1_STRING_to_UTF8(&buf, asn1);
  if (tmp <= 0)
    return false;

  strncpynt(out, (char *)buf, size);

  {
    const bool ret = (strlen ((char *)buf) < size);
    OPENSSL_free (buf);
    return ret;
  }
}

bool
verify_get_username (char *common_name, int cn_len,
    char * x509_username_field, X509 *peer_cert)
{
#ifdef ENABLE_X509ALTUSERNAME
  if (strncmp("ext:",x509_username_field,4) == 0)
    {
      if (!extract_x509_extension (peer_cert, x509_username_field+4, common_name, cn_len))
	return true;
    } else
#endif
  if (!extract_x509_field_ssl (X509_get_subject_name (peer_cert),
      x509_username_field, common_name, cn_len))
      return true;

  return false;
}
