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
 * @file Control Channel Verification Module
 */

#include "syshead.h"
#include "misc.h"
#include "manage.h"
#include "ssl_verify.h"
#include "ssl_verify_backend.h"

#ifdef USE_OPENSSL
#include "ssl_verify_openssl.h"
#endif

static void
tls_deauthenticate (struct tls_multi *multi)
{
  if (multi)
    {
      int i, j;
      for (i = 0; i < TM_SIZE; ++i)
	for (j = 0; j < KS_SIZE; ++j)
	  multi->session[i].key[j].authenticated = false;
    }
}

void
set_common_name (struct tls_session *session, const char *common_name)
{
  if (session->common_name)
    {
      free (session->common_name);
      session->common_name = NULL;
#ifdef ENABLE_PF
      session->common_name_hashval = 0;
#endif
    }
  if (common_name)
    {
      session->common_name = string_alloc (common_name, NULL);
#ifdef ENABLE_PF
      {
	const uint32_t len = (uint32_t) strlen (common_name);
	if (len)
	  session->common_name_hashval = hash_func ((const uint8_t*)common_name, len+1, 0);
	else
	  session->common_name_hashval = 0;
      }
#endif
    }
}

const char *
tls_common_name (const struct tls_multi *multi, const bool null)
{
  const char *ret = NULL;
  if (multi)
    ret = multi->session[TM_ACTIVE].common_name;
  if (ret && strlen (ret))
    return ret;
  else if (null)
    return NULL;
  else
    return "UNDEF";
}

void
tls_lock_common_name (struct tls_multi *multi)
{
  const char *cn = multi->session[TM_ACTIVE].common_name;
  if (cn && !multi->locked_cn)
    multi->locked_cn = string_alloc (cn, NULL);
}


void
cert_hash_remember (struct tls_session *session, const int error_depth, const unsigned char *sha1_hash)
{
  if (error_depth >= 0 && error_depth < MAX_CERT_DEPTH)
    {
      if (!session->cert_hash_set)
	ALLOC_OBJ_CLEAR (session->cert_hash_set, struct cert_hash_set);
      if (!session->cert_hash_set->ch[error_depth])
	ALLOC_OBJ (session->cert_hash_set->ch[error_depth], struct cert_hash);
      {
	struct cert_hash *ch = session->cert_hash_set->ch[error_depth];
	memcpy (ch->sha1_hash, sha1_hash, SHA_DIGEST_LENGTH);
      }
    }
}

#if 0
static void
cert_hash_print (const struct cert_hash_set *chs, int msglevel)
{
  struct gc_arena gc = gc_new ();
  msg (msglevel, "CERT_HASH");
  if (chs)
    {
      int i;
      for (i = 0; i < MAX_CERT_DEPTH; ++i)
	{
	  const struct cert_hash *ch = chs->ch[i];
	  if (ch)
	    msg (msglevel, "%d:%s", i, format_hex(ch->sha1_hash, SHA_DIGEST_LENGTH, 0, &gc));
	}
    }
  gc_free (&gc);
}
#endif

void
cert_hash_free (struct cert_hash_set *chs)
{
  if (chs)
    {
      int i;
      for (i = 0; i < MAX_CERT_DEPTH; ++i)
	free (chs->ch[i]);
      free (chs);
    }
}

static bool
cert_hash_compare (const struct cert_hash_set *chs1, const struct cert_hash_set *chs2)
{
  if (chs1 && chs2)
    {
      int i;
      for (i = 0; i < MAX_CERT_DEPTH; ++i)
	{
	  const struct cert_hash *ch1 = chs1->ch[i];
	  const struct cert_hash *ch2 = chs2->ch[i];

	  if (!ch1 && !ch2)
	    continue;
	  else if (ch1 && ch2 && !memcmp (ch1->sha1_hash, ch2->sha1_hash, SHA_DIGEST_LENGTH))
	    continue;
	  else
	    return false;
	}
      return true;
    }
  else if (!chs1 && !chs2)
    return true;
  else
    return false;
}

static struct cert_hash_set *
cert_hash_copy (const struct cert_hash_set *chs)
{
  struct cert_hash_set *dest = NULL;
  if (chs)
    {
      int i;
      ALLOC_OBJ_CLEAR (dest, struct cert_hash_set);
      for (i = 0; i < MAX_CERT_DEPTH; ++i)
	{
	  const struct cert_hash *ch = chs->ch[i];
	  if (ch)
	    {
	      ALLOC_OBJ (dest->ch[i], struct cert_hash);
	      memcpy (dest->ch[i]->sha1_hash, ch->sha1_hash, SHA_DIGEST_LENGTH);
	    }
	}
    }
  return dest;
}
void
tls_lock_cert_hash_set (struct tls_multi *multi)
{
  const struct cert_hash_set *chs = multi->session[TM_ACTIVE].cert_hash_set;
  if (chs && !multi->locked_cert_hash_set)
    multi->locked_cert_hash_set = cert_hash_copy (chs);
}


void
verify_final_auth_checks(struct tls_multi *multi, struct tls_session *session)
{
  /* While it shouldn't really happen, don't allow the common name to be NULL */
  if (!session->common_name)
    set_common_name (session, "");

  /* Don't allow the CN to change once it's been locked */
  if (multi->locked_cn)
    {
      const char *cn = session->common_name;
      if (cn && strcmp (cn, multi->locked_cn))
	{
	  msg (D_TLS_ERRORS, "TLS Auth Error: TLS object CN attempted to change from '%s' to '%s' -- tunnel disabled",
	       multi->locked_cn,
	       cn);

	  /* change the common name back to its original value and disable the tunnel */
	  set_common_name (session, multi->locked_cn);
	  tls_deauthenticate (multi);
	}
    }

  /* Don't allow the cert hashes to change once they have been locked */
  if (multi->locked_cert_hash_set)
    {
      const struct cert_hash_set *chs = session->cert_hash_set;
      if (chs && !cert_hash_compare (chs, multi->locked_cert_hash_set))
	{
	  msg (D_TLS_ERRORS, "TLS Auth Error: TLS object CN=%s client-provided SSL certs unexpectedly changed during mid-session reauth",
	       session->common_name);

	  /* disable the tunnel */
	  tls_deauthenticate (multi);
	}
    }

  /* verify --client-config-dir based authentication */
  if (session->opt->client_config_dir_exclusive)
    {
      struct key_state *ks = &session->key[KS_PRIMARY]; 	   /* primary key */
      struct gc_arena gc = gc_new ();

      const char *cn = session->common_name;
      const char *path = gen_path (session->opt->client_config_dir_exclusive, cn, &gc);
      if (!cn || !strcmp (cn, CCD_DEFAULT) || !test_file (path))
	{
	  ks->authenticated = false;
	  msg (D_TLS_ERRORS, "TLS Auth Error: --client-config-dir authentication failed for common name '%s' file='%s'",
	       session->common_name,
	       path ? path : "UNDEF");
	}

      gc_free (&gc);
    }
}
