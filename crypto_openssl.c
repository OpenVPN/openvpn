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
 * @file Data Channel Cryptography OpenSSL-specific backend interface
 */

#include "syshead.h"

#include "basic.h"
#include "buffer.h"
#include "integer.h"
#include "crypto_backend.h"
#include <openssl/objects.h>
#include <openssl/evp.h>
#include <openssl/des.h>

/*
 * Check for key size creepage.
 */

#if MAX_CIPHER_KEY_LENGTH < EVP_MAX_KEY_LENGTH
#warning Some OpenSSL EVP ciphers now support key lengths greater than MAX_CIPHER_KEY_LENGTH -- consider increasing MAX_CIPHER_KEY_LENGTH
#endif

#if MAX_HMAC_KEY_LENGTH < EVP_MAX_MD_SIZE
#warning Some OpenSSL HMAC message digests now support key lengths greater than MAX_HMAC_KEY_LENGTH -- consider increasing MAX_HMAC_KEY_LENGTH
#endif

/*
 *
 * Workarounds for incompatibilites between OpenSSL libraries.
 * Right now we accept OpenSSL libraries from 0.9.5 to 0.9.7.
 *
 */

#if SSLEAY_VERSION_NUMBER < 0x00907000L

#endif

#if SSLEAY_VERSION_NUMBER < 0x00906000

static inline bool
cipher_ok (const char* name)
{
  const int i = strlen (name) - 4;
  if (i >= 0)
    return !strcmp (name + i, "-CBC");
  else
    return false;
}

#else

static inline bool
cipher_ok (const char* name)
{
  return true;
}

#endif

#if SSLEAY_VERSION_NUMBER < 0x0090581f

#endif

void
show_available_ciphers ()
{
  int nid;

#ifndef ENABLE_SMALL
  printf ("The following ciphers and cipher modes are available\n"
	  "for use with " PACKAGE_NAME ".  Each cipher shown below may be\n"
	  "used as a parameter to the --cipher option.  The default\n"
	  "key size is shown as well as whether or not it can be\n"
          "changed with the --keysize directive.  Using a CBC mode\n"
	  "is recommended.\n\n");
#endif

  for (nid = 0; nid < 10000; ++nid)	/* is there a better way to get the size of the nid list? */
    {
      const EVP_CIPHER *cipher = EVP_get_cipherbynid (nid);
      if (cipher && cipher_ok (OBJ_nid2sn (nid)))
	{
	  const unsigned int mode = EVP_CIPHER_mode (cipher);
	  if (mode == EVP_CIPH_CBC_MODE
#ifdef ALLOW_NON_CBC_CIPHERS
	      || mode == EVP_CIPH_CFB_MODE || mode == EVP_CIPH_OFB_MODE
#endif
	      )
	    printf ("%s %d bit default key (%s)\n",
		    OBJ_nid2sn (nid),
		    EVP_CIPHER_key_length (cipher) * 8,
		    ((EVP_CIPHER_flags (cipher) & EVP_CIPH_VARIABLE_LENGTH) ?
		     "variable" : "fixed"));
	}
    }
  printf ("\n");
}

void
show_available_digests ()
{
  int nid;

#ifndef ENABLE_SMALL
  printf ("The following message digests are available for use with\n"
	  PACKAGE_NAME ".  A message digest is used in conjunction with\n"
	  "the HMAC function, to authenticate received packets.\n"
	  "You can specify a message digest as parameter to\n"
	  "the --auth option.\n\n");
#endif

  for (nid = 0; nid < 10000; ++nid)
    {
      const EVP_MD *digest = EVP_get_digestbynid (nid);
      if (digest)
	{
	  printf ("%s %d bit digest size\n",
		  OBJ_nid2sn (nid), EVP_MD_size (digest) * 8);
	}
    }
  printf ("\n");
}

void
show_available_engines ()
{
#if CRYPTO_ENGINE /* Only defined for OpenSSL */
  ENGINE *e;

  printf ("OpenSSL Crypto Engines\n\n");

  ENGINE_load_builtin_engines ();

  e = ENGINE_get_first ();
  while (e)
    {
      printf ("%s [%s]\n",
	      ENGINE_get_name (e),
	      ENGINE_get_id (e));
      e = ENGINE_get_next (e);
    }
  ENGINE_cleanup ();
#else
  printf ("Sorry, OpenSSL hardware crypto engine functionality is not available.\n");
#endif
}

/*
 *
 * Random number functions, used in cases where we want
 * reasonably strong cryptographic random number generation
 * without depleting our entropy pool.  Used for random
 * IV values and a number of other miscellaneous tasks.
 *
 */

int rand_bytes(uint8_t *output, int len)
{
  return RAND_bytes (output, len);
}

