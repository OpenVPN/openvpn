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

#ifndef SSL_VERIFY_H_
#define SSL_VERIFY_H_

#include "syshead.h"
#include "misc.h"
#include "manage.h"
#include "ssl_common.h"

/* Include OpenSSL-specific code */
#ifdef USE_OPENSSL
#include "ssl_verify_openssl.h"
#endif

/*
 * Keep track of certificate hashes at various depths
 */

/** Maximum certificate depth we will allow */
#define MAX_CERT_DEPTH 16

/** Structure containing the hash for a single certificate */
struct cert_hash {
  unsigned char sha1_hash[SHA_DIGEST_LENGTH]; /**< The SHA1 hash for a certificate */
};

/** Structure containing the hashes for a full certificate chain */
struct cert_hash_set {
  struct cert_hash *ch[MAX_CERT_DEPTH]; /**< Array of certificate hashes */
};


/**
 * Frees the given set of certificate hashes.
 *
 * @param chs	The certificate hash set to free.
 */
void cert_hash_free (struct cert_hash_set *chs);

/**
 * Locks the certificate hash set used in the given tunnel
 *
 * @param multi	The tunnel to lock
 */
void tls_lock_cert_hash_set (struct tls_multi *multi);

/**
 * Locks the common name field for the given tunnel
 *
 * @param multi	The tunnel to lock
 */
void tls_lock_common_name (struct tls_multi *multi);

/**
 * Returns the common name field for the given tunnel
 *
 * @param multi	The tunnel to return the common name for
 * @param null	Whether null may be returned. If not, "UNDEF" will be returned.
 */
const char *tls_common_name (const struct tls_multi* multi, const bool null);

void tls_set_common_name (struct tls_multi *multi, const char *common_name);

#ifdef ENABLE_PF

/**
 * Retrieve the given tunnel's common name and its hash value.
 *
 * @param multi		The tunnel to use
 * @param cn		Common name's string
 * @param cn_hash	Common name's hash value
 *
 * @return true if the common name was set, false otherwise.
 */
static inline bool
tls_common_name_hash (const struct tls_multi *multi, const char **cn, uint32_t *cn_hash)
{
  if (multi)
    {
      const struct tls_session *s = &multi->session[TM_ACTIVE];
      if (s->common_name && s->common_name[0] != '\0')
	{
	  *cn = s->common_name;
	  *cn_hash = s->common_name_hashval;
	  return true;
	}
    }
  return false;
}

#endif

/**
 * Perform final authentication checks, including locking of the cn, the allowed
 * certificate hashes, and whether a client config entry exists in the
 * client config directory.
 *
 * @param multi		The TLS multi structure to verify locked structures.
 * @param session	The current TLS session
 *
 */
void verify_final_auth_checks(struct tls_multi *multi, struct tls_session *session);


#endif /* SSL_VERIFY_H_ */
