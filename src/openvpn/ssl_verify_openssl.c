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

#ifdef HAVE_CONFIG_H
#include "config.h"
#elif defined(_MSC_VER)
#include "config-msvc.h"
#endif

#include "syshead.h"

#if defined(ENABLE_SSL) && defined(ENABLE_CRYPTO_OPENSSL)

#include "ssl_verify.h"
#include "ssl_verify_backend.h"
#include "ssl_openssl.h"
#include <openssl/x509v3.h>
#include <openssl/err.h>

int
verify_callback (int preverify_ok, X509_STORE_CTX * ctx)
{
  int ret = 0;
  struct tls_session *session;
  SSL *ssl;
  struct gc_arena gc = gc_new();

  /* get the tls_session pointer */
  ssl = X509_STORE_CTX_get_ex_data (ctx, SSL_get_ex_data_X509_STORE_CTX_idx());
  ASSERT (ssl);
  session = (struct tls_session *) SSL_get_ex_data (ssl, mydata_index);
  ASSERT (session);

  cert_hash_remember (session, ctx->error_depth,
      x509_get_sha1_hash(ctx->current_cert, &gc));

  /* did peer present cert which was signed by our root cert? */
  if (!preverify_ok)
    {
      /* get the X509 name */
      char *subject = x509_get_subject(ctx->current_cert, &gc);

      if (subject)
	{
	  /* Remote site specified a certificate, but it's not correct */
	  msg (D_TLS_ERRORS, "VERIFY ERROR: depth=%d, error=%s: %s",
	      ctx->error_depth,
	      X509_verify_cert_error_string (ctx->error),
	      subject);
	}

      ERR_clear_error();

      session->verified = false;
      goto cleanup;
    }

  if (SUCCESS != verify_cert(session, ctx->current_cert, ctx->error_depth))
    goto cleanup;

  ret = 1;

cleanup:
  gc_free(&gc);

  return ret;
}

#ifdef ENABLE_X509ALTUSERNAME
static
bool extract_x509_extension(X509 *cert, char *fieldname, char *out, int size)
{
  bool retval = false;
  char *buf = 0;
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
static result_t
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
    return FAILURE;

  x509ne = X509_NAME_get_entry(x509, lastpos);
  if (!x509ne)
    return FAILURE;

  asn1 = X509_NAME_ENTRY_get_data(x509ne);
  if (!asn1)
    return FAILURE;
  tmp = ASN1_STRING_to_UTF8(&buf, asn1);
  if (tmp <= 0)
    return FAILURE;

  strncpynt(out, (char *)buf, size);

  {
    const result_t ret = (strlen ((char *)buf) < size) ? SUCCESS: FAILURE;
    OPENSSL_free (buf);
    return ret;
  }
}

result_t
x509_get_username (char *common_name, int cn_len,
    char * x509_username_field, X509 *peer_cert)
{
#ifdef ENABLE_X509ALTUSERNAME
  if (strncmp("ext:",x509_username_field,4) == 0)
    {
      if (!extract_x509_extension (peer_cert, x509_username_field+4, common_name, cn_len))
	return FAILURE;
    } else
#endif
  if (FAILURE == extract_x509_field_ssl (X509_get_subject_name (peer_cert),
      x509_username_field, common_name, cn_len))
      return FAILURE;

  return SUCCESS;
}

char *
backend_x509_get_serial (openvpn_x509_cert_t *cert, struct gc_arena *gc)
{
  ASN1_INTEGER *asn1_i;
  BIGNUM *bignum;
  char *openssl_serial, *serial;

  asn1_i = X509_get_serialNumber(cert);
  bignum = ASN1_INTEGER_to_BN(asn1_i, NULL);
  openssl_serial = BN_bn2dec(bignum);

  serial = string_alloc(openssl_serial, gc);

  BN_free(bignum);
  OPENSSL_free(openssl_serial);

  return serial;
}

char *
backend_x509_get_serial_hex (openvpn_x509_cert_t *cert, struct gc_arena *gc)
{
  const ASN1_INTEGER *asn1_i = X509_get_serialNumber(cert);

  return format_hex_ex(asn1_i->data, asn1_i->length, 0, 1, ":", gc);
}

unsigned char *
x509_get_sha1_hash (X509 *cert, struct gc_arena *gc)
{
  unsigned char *hash = gc_malloc(SHA_DIGEST_LENGTH, false, gc);
  memcpy(hash, cert->sha1_hash, SHA_DIGEST_LENGTH);
  return hash;
}

char *
x509_get_subject (X509 *cert, struct gc_arena *gc)
{
  BIO *subject_bio = NULL;
  BUF_MEM *subject_mem;
  char *subject = NULL;
  int maxlen = 0;

  /*
   * Generate the subject string in OpenSSL proprietary format,
   * when in --compat-names mode
   */
  if (compat_flag (COMPAT_FLAG_QUERY | COMPAT_NAMES))
    {
      subject = gc_malloc (256, false, gc);
      X509_NAME_oneline (X509_get_subject_name (cert), subject, 256);
      subject[255] = '\0';
      return subject;
    }

  subject_bio = BIO_new (BIO_s_mem ());
  if (subject_bio == NULL)
    goto err;

  X509_NAME_print_ex (subject_bio, X509_get_subject_name (cert),
                      0, XN_FLAG_SEP_CPLUS_SPC | XN_FLAG_FN_SN |
                      ASN1_STRFLGS_UTF8_CONVERT | ASN1_STRFLGS_ESC_CTRL);

  if (BIO_eof (subject_bio))
    goto err;

  BIO_get_mem_ptr (subject_bio, &subject_mem);

  maxlen = subject_mem->length + 1;
  subject = gc_malloc (maxlen, false, gc);

  memcpy (subject, subject_mem->data, maxlen);
  subject[maxlen - 1] = '\0';

err:
  if (subject_bio)
    BIO_free (subject_bio);

  return subject;
}


#ifdef ENABLE_X509_TRACK

void
x509_track_add (const struct x509_track **ll_head, const char *name, int msglevel, struct gc_arena *gc)
{
  struct x509_track *xt;
  ALLOC_OBJ_CLEAR_GC (xt, struct x509_track, gc);
  if (*name == '+')
    {
      xt->flags |= XT_FULL_CHAIN;
      ++name;
    }
  xt->name = name;
  xt->nid = OBJ_txt2nid(name);
  if (xt->nid != NID_undef)
    {
      xt->next = *ll_head;
      *ll_head = xt;
    }
  else
    msg(msglevel, "x509_track: no such attribute '%s'", name);
}

/* worker method for setenv_x509_track */
static void
do_setenv_x509 (struct env_set *es, const char *name, char *value, int depth)
{
  char *name_expand;
  size_t name_expand_size;

  string_mod (value, CC_ANY, CC_CRLF, '?');
  msg (D_X509_ATTR, "X509 ATTRIBUTE name='%s' value='%s' depth=%d", name, value, depth);
  name_expand_size = 64 + strlen (name);
  name_expand = (char *) malloc (name_expand_size);
  check_malloc_return (name_expand);
  openvpn_snprintf (name_expand, name_expand_size, "X509_%d_%s", depth, name);
  setenv_str (es, name_expand, value);
  free (name_expand);
}

void
x509_setenv_track (const struct x509_track *xt, struct env_set *es, const int depth, X509 *x509)
{
  X509_NAME *x509_name = X509_get_subject_name (x509);
  const char nullc = '\0';
  int i;

  while (xt)
    {
      if (depth == 0 || (xt->flags & XT_FULL_CHAIN))
	{
	  i = X509_NAME_get_index_by_NID(x509_name, xt->nid, -1);
	  if (i >= 0)
	    {
	      X509_NAME_ENTRY *ent = X509_NAME_get_entry(x509_name, i);
	      if (ent)
		{
		  ASN1_STRING *val = X509_NAME_ENTRY_get_data (ent);
		  unsigned char *buf;
		  buf = (unsigned char *)1; /* bug in OpenSSL 0.9.6b ASN1_STRING_to_UTF8 requires this workaround */
		  if (ASN1_STRING_to_UTF8 (&buf, val) > 0)
		    {
		      do_setenv_x509(es, xt->name, (char *)buf, depth);
		      OPENSSL_free (buf);
		    }
		}
	    }
	  else
	    {
	      i = X509_get_ext_by_NID(x509, xt->nid, -1);
	      if (i >= 0)
		{
		  X509_EXTENSION *ext = X509_get_ext(x509, i);
		  if (ext)
		    {
		      BIO *bio = BIO_new(BIO_s_mem());
		      if (bio)
			{
			  if (X509V3_EXT_print(bio, ext, 0, 0))
			    {
			      if (BIO_write(bio, &nullc, 1) == 1)
				{
				  char *str;
				  BIO_get_mem_data(bio, &str);
				  do_setenv_x509(es, xt->name, str, depth);
				}
			    }
			  BIO_free(bio);
			}
		    }
		}
	    }
	}
      xt = xt->next;
    }
}
#endif

/*
 * Save X509 fields to environment, using the naming convention:
 *
 *  X509_{cert_depth}_{name}={value}
 */
void
x509_setenv (struct env_set *es, int cert_depth, openvpn_x509_cert_t *peer_cert)
{
  int i, n;
  int fn_nid;
  ASN1_OBJECT *fn;
  ASN1_STRING *val;
  X509_NAME_ENTRY *ent;
  const char *objbuf;
  unsigned char *buf;
  char *name_expand;
  size_t name_expand_size;
  X509_NAME *x509 = X509_get_subject_name (peer_cert);

  n = X509_NAME_entry_count (x509);
  for (i = 0; i < n; ++i)
    {
      ent = X509_NAME_get_entry (x509, i);
      if (!ent)
	continue;
      fn = X509_NAME_ENTRY_get_object (ent);
      if (!fn)
	continue;
      val = X509_NAME_ENTRY_get_data (ent);
      if (!val)
	continue;
      fn_nid = OBJ_obj2nid (fn);
      if (fn_nid == NID_undef)
	continue;
      objbuf = OBJ_nid2sn (fn_nid);
      if (!objbuf)
	continue;
      buf = (unsigned char *)1; /* bug in OpenSSL 0.9.6b ASN1_STRING_to_UTF8 requires this workaround */
      if (ASN1_STRING_to_UTF8 (&buf, val) <= 0)
	continue;
      name_expand_size = 64 + strlen (objbuf);
      name_expand = (char *) malloc (name_expand_size);
      check_malloc_return (name_expand);
      openvpn_snprintf (name_expand, name_expand_size, "X509_%d_%s", cert_depth,
	  objbuf);
      string_mod (name_expand, CC_PRINT, CC_CRLF, '_');
      string_mod ((char*)buf, CC_PRINT, CC_CRLF, '_');
      setenv_str (es, name_expand, (char*)buf);
      free (name_expand);
      OPENSSL_free (buf);
    }
}

result_t
x509_verify_ns_cert_type(const openvpn_x509_cert_t *peer_cert, const int usage)
{
  if (usage == NS_CERT_CHECK_NONE)
    return SUCCESS;
  if (usage == NS_CERT_CHECK_CLIENT)
    return ((peer_cert->ex_flags & EXFLAG_NSCERT)
	&& (peer_cert->ex_nscert & NS_SSL_CLIENT)) ? SUCCESS: FAILURE;
  if (usage == NS_CERT_CHECK_SERVER)
    return ((peer_cert->ex_flags & EXFLAG_NSCERT)
	&& (peer_cert->ex_nscert & NS_SSL_SERVER))  ? SUCCESS: FAILURE;

  return FAILURE;
}

#if OPENSSL_VERSION_NUMBER >= 0x00907000L

result_t
x509_verify_cert_ku (X509 *x509, const unsigned * const expected_ku,
    int expected_len)
{
  ASN1_BIT_STRING *ku = NULL;
  result_t fFound = FAILURE;

  if ((ku = (ASN1_BIT_STRING *) X509_get_ext_d2i (x509, NID_key_usage, NULL,
      NULL)) == NULL)
    {
      msg (D_HANDSHAKE, "Certificate does not have key usage extension");
    }
  else
    {
      unsigned nku = 0;
      int i;
      for (i = 0; i < 8; i++)
	{
	  if (ASN1_BIT_STRING_get_bit (ku, i))
	    nku |= 1 << (7 - i);
	}

      /*
       * Fixup if no LSB bits
       */
      if ((nku & 0xff) == 0)
	{
	  nku >>= 8;
	}

      msg (D_HANDSHAKE, "Validating certificate key usage");
      for (i = 0; fFound != SUCCESS && i < expected_len; i++)
	{
	  if (expected_ku[i] != 0)
	    {
	      msg (D_HANDSHAKE, "++ Certificate has key usage  %04x, expects "
		  "%04x", nku, expected_ku[i]);

	      if (nku == expected_ku[i])
		fFound = SUCCESS;
	    }
	}
    }

  if (ku != NULL)
    ASN1_BIT_STRING_free (ku);

  return fFound;
}

result_t
x509_verify_cert_eku (X509 *x509, const char * const expected_oid)
{
  EXTENDED_KEY_USAGE *eku = NULL;
  result_t fFound = FAILURE;

  if ((eku = (EXTENDED_KEY_USAGE *) X509_get_ext_d2i (x509, NID_ext_key_usage,
      NULL, NULL)) == NULL)
    {
      msg (D_HANDSHAKE, "Certificate does not have extended key usage extension");
    }
  else
    {
      int i;

      msg (D_HANDSHAKE, "Validating certificate extended key usage");
      for (i = 0; SUCCESS != fFound && i < sk_ASN1_OBJECT_num (eku); i++)
	{
	  ASN1_OBJECT *oid = sk_ASN1_OBJECT_value (eku, i);
	  char szOid[1024];

	  if (SUCCESS != fFound && OBJ_obj2txt (szOid, sizeof(szOid), oid, 0) != -1)
	    {
	      msg (D_HANDSHAKE, "++ Certificate has EKU (str) %s, expects %s",
		  szOid, expected_oid);
	      if (!strcmp (expected_oid, szOid))
		fFound = SUCCESS;
	    }
	  if (SUCCESS != fFound && OBJ_obj2txt (szOid, sizeof(szOid), oid, 1) != -1)
	    {
	      msg (D_HANDSHAKE, "++ Certificate has EKU (oid) %s, expects %s",
		  szOid, expected_oid);
	      if (!strcmp (expected_oid, szOid))
		fFound = SUCCESS;
	    }
	}
    }

  if (eku != NULL)
    sk_ASN1_OBJECT_pop_free (eku, ASN1_OBJECT_free);

  return fFound;
}

result_t
x509_write_pem(FILE *peercert_file, X509 *peercert)
{
  if (PEM_write_X509(peercert_file, peercert) < 0)
    {
      msg (M_ERR, "Failed to write peer certificate in PEM format");
      return FAILURE;
    }
  return SUCCESS;
}

#endif /* OPENSSL_VERSION_NUMBER */

/*
 * check peer cert against CRL
 */
result_t
x509_verify_crl(const char *crl_file, X509 *peer_cert, const char *subject)
{
  X509_CRL *crl=NULL;
  X509_REVOKED *revoked;
  BIO *in=NULL;
  int n,i;
  result_t retval = FAILURE;

  in = BIO_new_file (crl_file, "r");

  if (in == NULL) {
    msg (M_WARN, "CRL: cannot read: %s", crl_file);
    goto end;
  }
  crl=PEM_read_bio_X509_CRL(in,NULL,NULL,NULL);
  if (crl == NULL) {
    msg (M_WARN, "CRL: cannot read CRL from file %s", crl_file);
    goto end;
  }

  if (X509_NAME_cmp(X509_CRL_get_issuer(crl), X509_get_issuer_name(peer_cert)) != 0) {
    msg (M_WARN, "CRL: CRL %s is from a different issuer than the issuer of "
	"certificate %s", crl_file, subject);
    retval = SUCCESS;
    goto end;
  }

  n = sk_X509_REVOKED_num(X509_CRL_get_REVOKED(crl));
  for (i = 0; i < n; i++) {
    revoked = (X509_REVOKED *)sk_X509_REVOKED_value(X509_CRL_get_REVOKED(crl), i);
    if (ASN1_INTEGER_cmp(revoked->serialNumber, X509_get_serialNumber(peer_cert)) == 0) {
      msg (D_HANDSHAKE, "CRL CHECK FAILED: %s is REVOKED",subject);
      goto end;
    }
  }

  retval = SUCCESS;
  msg (D_HANDSHAKE, "CRL CHECK OK: %s",subject);

end:
  BIO_free(in);
  if (crl)
    X509_CRL_free (crl);

  return retval;
}

#endif /* defined(ENABLE_SSL) && defined(ENABLE_CRYPTO_OPENSSL) */
