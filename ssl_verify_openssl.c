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

char *
verify_get_serial (x509_cert_t *cert)
{
  ASN1_INTEGER *asn1_i;
  BIGNUM *bignum;
  char *serial;

  asn1_i = X509_get_serialNumber(cert);
  bignum = ASN1_INTEGER_to_BN(asn1_i, NULL);
  serial = BN_bn2dec(bignum);

  BN_free(bignum);
  return serial;
}

void
verify_free_serial (char *serial)
{
  if (serial)
    OPENSSL_free(serial);
}

#ifdef ENABLE_X509_TRACK
/*
 * setenv_x509_track function -- save X509 fields to environment,
 * using the naming convention:
 *
 *  X509_{cert_depth}_{name}={value}
 *
 * This function differs from setenv_x509 below in the following ways:
 *
 * (1) Only explicitly named attributes in xt are saved, per usage
 *     of --x509-track program options.
 * (2) Only the level 0 cert info is saved unless the XT_FULL_CHAIN
 *     flag is set in xt->flags (corresponds with prepending a '+'
 *     to the name when specified by --x509-track program option).
 * (3) This function supports both X509 subject name fields as
 *     well as X509 V3 extensions.
 */

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
setenv_x509_track (const struct x509_track *xt, struct env_set *es, const int depth, X509 *x509)
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
setenv_x509 (struct env_set *es, int cert_depth, x509_cert_t *peer_cert)
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

bool
verify_nsCertType(const x509_cert_t *peer_cert, const int usage)
{
  if (usage == NS_CERT_CHECK_NONE)
    return true;
  if (usage == NS_CERT_CHECK_CLIENT)
    return ((peer_cert->ex_flags & EXFLAG_NSCERT)
	&& (peer_cert->ex_nscert & NS_SSL_CLIENT));
  if (usage == NS_CERT_CHECK_SERVER)
    return ((peer_cert->ex_flags & EXFLAG_NSCERT)
	&& (peer_cert->ex_nscert & NS_SSL_SERVER));

  return false;
}

#if OPENSSL_VERSION_NUMBER >= 0x00907000L

bool
verify_cert_ku (X509 *x509, const unsigned * const expected_ku,
    int expected_len)
{
  ASN1_BIT_STRING *ku = NULL;
  bool fFound = false;

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
      for (i = 0; !fFound && i < expected_len; i++)
	{
	  if (expected_ku[i] != 0)
	    {
	      msg (D_HANDSHAKE, "++ Certificate has key usage  %04x, expects "
		  "%04x", nku, expected_ku[i]);

	      if (nku == expected_ku[i])
		fFound = true;
	    }
	}
    }

  if (ku != NULL)
    ASN1_BIT_STRING_free (ku);

  return fFound;
}

bool
verify_cert_eku (X509 *x509, const char * const expected_oid)
{
  EXTENDED_KEY_USAGE *eku = NULL;
  bool fFound = false;

  if ((eku = (EXTENDED_KEY_USAGE *) X509_get_ext_d2i (x509, NID_ext_key_usage,
      NULL, NULL)) == NULL)
    {
      msg (D_HANDSHAKE, "Certificate does not have extended key usage extension");
    }
  else
    {
      int i;

      msg (D_HANDSHAKE, "Validating certificate extended key usage");
      for (i = 0; !fFound && i < sk_ASN1_OBJECT_num (eku); i++)
	{
	  ASN1_OBJECT *oid = sk_ASN1_OBJECT_value (eku, i);
	  char szOid[1024];

	  if (!fFound && OBJ_obj2txt (szOid, sizeof(szOid), oid, 0) != -1)
	    {
	      msg (D_HANDSHAKE, "++ Certificate has EKU (str) %s, expects %s",
		  szOid, expected_oid);
	      if (!strcmp (expected_oid, szOid))
		fFound = true;
	    }
	  if (!fFound && OBJ_obj2txt (szOid, sizeof(szOid), oid, 1) != -1)
	    {
	      msg (D_HANDSHAKE, "++ Certificate has EKU (oid) %s, expects %s",
		  szOid, expected_oid);
	      if (!strcmp (expected_oid, szOid))
		fFound = true;
	    }
	}
    }

  if (eku != NULL)
    sk_ASN1_OBJECT_pop_free (eku, ASN1_OBJECT_free);

  return fFound;
}

const char *
write_peer_cert(X509 *peercert, const char *tmp_dir, struct gc_arena *gc)
{
  FILE *peercert_file;
  const char *peercert_filename="";

  if(!tmp_dir)
      return NULL;

  /* create tmp file to store peer cert */
  peercert_filename = create_temp_file (tmp_dir, "pcf", gc);

  /* write peer-cert in tmp-file */
  peercert_file = fopen(peercert_filename, "w+");
  if(!peercert_file)
    {
      msg (M_ERR, "Failed to open temporary file : %s", peercert_filename);
      return NULL;
    }
  if(PEM_write_X509(peercert_file,peercert)<0)
    {
      msg (M_ERR, "Failed to write peer certificate in PEM format");
      fclose(peercert_file);
      return NULL;
    }

  fclose(peercert_file);
  return peercert_filename;
}

#endif /* OPENSSL_VERSION_NUMBER */

