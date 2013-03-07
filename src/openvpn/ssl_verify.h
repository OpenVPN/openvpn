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
#ifdef ENABLE_CRYPTO_OPENSSL
#include "ssl_verify_openssl.h"
#endif
#ifdef ENABLE_CRYPTO_POLARSSL
#include "ssl_verify_polarssl.h"
#endif

#include "ssl_verify_backend.h"

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

#define VERIFY_X509_NONE                0
#define VERIFY_X509_SUBJECT_DN          1
#define VERIFY_X509_SUBJECT_RDN         2
#define VERIFY_X509_SUBJECT_RDN_PREFIX  3
#define TLS_REMOTE_SUBJECT_DN           1 + 0x100
#define TLS_REMOTE_SUBJECT_RDN_PREFIX   3 + 0x100

#define TLS_AUTHENTICATION_SUCCEEDED  0
#define TLS_AUTHENTICATION_FAILED     1
#define TLS_AUTHENTICATION_DEFERRED   2
#define TLS_AUTHENTICATION_UNDEFINED  3

/*
 * Return current session authentication state.  Return
 * value is TLS_AUTHENTICATION_x.
 *
 * TODO: document this function
 */
int tls_authentication_status (struct tls_multi *multi, const int latency);

/** Check whether the \a ks \c key_state is ready to receive data channel
 *   packets.
 *   @ingroup data_crypto
 *
 *   If true, it is safe to assume that this session has been authenticated
 *   by TLS.
 *
 *   @note This macro only works if S_SENT_KEY + 1 == S_GOT_KEY. */
#define DECRYPT_KEY_ENABLED(multi, ks) ((ks)->state >= (S_GOT_KEY - (multi)->opt.server))

/**
 * Remove the given key state's auth control file, if it exists.
 *
 * @param ks	The key state the remove the file for
 */
void key_state_rm_auth_control_file (struct key_state *ks);

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

/**
 * Returns the username field for the given tunnel
 *
 * @param multi	The tunnel to return the username for
 * @param null	Whether null may be returned. If not, "UNDEF" will be returned.
 */
const char *tls_username (const struct tls_multi *multi, const bool null);

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
 * Returns whether or not the server should check for username/password
 *
 * @param session	The current TLS session
 *
 * @return 		true if username and password verification is enabled,
 * 			false if not.
 *
 */
static inline bool verify_user_pass_enabled(struct tls_session *session)
{
  return (session->opt->auth_user_pass_verify_script
        || plugin_defined (session->opt->plugins, OPENVPN_PLUGIN_AUTH_USER_PASS_VERIFY)
#ifdef MANAGEMENT_DEF_AUTH
        || management_enable_def_auth (management)
#endif
        );
}

/**
 * Verify the given username and password, using either an external script, a
 * plugin, or the management interface.
 *
 * If authentication succeeds, the appropriate state is filled into the
 * session's primary key state's authenticated field. Authentication may also
 * be deferred, in which case the key state's auth_deferred field is filled in.
 *
 * @param up		The username and password to verify.
 * @param multi		The TLS multi structure to verify usernames against.
 * @param session	The current TLS session
 *
 */
void verify_user_pass(struct user_pass *up, struct tls_multi *multi,
    struct tls_session *session);

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

#ifdef ENABLE_X509_TRACK

struct x509_track
{
  const struct x509_track *next;
  const char *name;
# define XT_FULL_CHAIN (1<<0)
  unsigned int flags;
  int nid;
};

void x509_track_add (const struct x509_track **ll_head, const char *name, int msglevel, struct gc_arena *gc);

#endif

/*
 * Certificate checking for verify_nsCertType
 */
/** Do not perform Netscape certificate type verification */
#define NS_CERT_CHECK_NONE (0)
/** Do not perform Netscape certificate type verification */
#define NS_CERT_CHECK_SERVER (1<<0)
/** Do not perform Netscape certificate type verification */
#define NS_CERT_CHECK_CLIENT (1<<1)

/*
 * TODO: document
 */
#ifdef MANAGEMENT_DEF_AUTH
bool tls_authenticate_key (struct tls_multi *multi, const unsigned int mda_key_id, const bool auth, const char *client_reason);
void man_def_auth_set_client_reason (struct tls_multi *multi, const char *client_reason);
#endif

static inline const char *
tls_client_reason (struct tls_multi *multi)
{
#ifdef ENABLE_DEF_AUTH
  return multi->client_reason;
#else
  return NULL;
#endif
}

#endif /* SSL_VERIFY_H_ */

