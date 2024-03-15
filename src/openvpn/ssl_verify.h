/*
 *  OpenVPN -- An application to securely tunnel IP networks
 *             over a single TCP/UDP port, with support for SSL/TLS-based
 *             session authentication and key exchange,
 *             packet encryption, packet authentication, and
 *             packet compression.
 *
 *  Copyright (C) 2002-2024 OpenVPN Inc <sales@openvpn.net>
 *  Copyright (C) 2010-2021 Fox Crypto B.V. <openvpn@foxcrypto.com>
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
 *  You should have received a copy of the GNU General Public License along
 *  with this program; if not, write to the Free Software Foundation, Inc.,
 *  51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

/**
 * @file Control Channel Verification Module
 */

#ifndef SSL_VERIFY_H_
#define SSL_VERIFY_H_

#include "syshead.h"
#include "misc.h"
#include "ssl_common.h"

/* Include OpenSSL-specific code */
#ifdef ENABLE_CRYPTO_OPENSSL
#include "ssl_verify_openssl.h"
#endif
#ifdef ENABLE_CRYPTO_MBEDTLS
#include "ssl_verify_mbedtls.h"
#endif

#include "ssl_verify_backend.h"

/*
 * Keep track of certificate hashes at various depths
 */

/** Maximum certificate depth we will allow */
#define MAX_CERT_DEPTH 16

/** Structure containing the hash for a single certificate */
struct cert_hash {
    unsigned char sha256_hash[256/8];
};

/** Structure containing the hashes for a full certificate chain */
struct cert_hash_set {
    struct cert_hash *ch[MAX_CERT_DEPTH]; /**< Array of certificate hashes */
};

#define VERIFY_X509_NONE                0
#define VERIFY_X509_SUBJECT_DN          1
#define VERIFY_X509_SUBJECT_RDN         2
#define VERIFY_X509_SUBJECT_RDN_PREFIX  3

enum tls_auth_status
{
    TLS_AUTHENTICATION_SUCCEEDED=0,
    TLS_AUTHENTICATION_FAILED=1,
    TLS_AUTHENTICATION_DEFERRED=2
};

/**
 * Return current session authentication state of the tls_multi structure
 * This will return TLS_AUTHENTICATION_SUCCEEDED only if the session is
 * fully authenticated, i.e. VPN traffic is allowed over it.
 *
 * Checks the status of all active keys and checks if the deferred
 * authentication has succeeded.
 *
 * As a side effect this function will also transition ks->authenticated
 * from KS_AUTH_DEFERRED to KS_AUTH_FALSE/KS_AUTH_TRUE if the deferred
 * authentication has succeeded after last call.
 *
 * @param   multi       the tls_multi struct to operate on
 *
 * @return              Current authentication status of the tls_multi
 */
enum tls_auth_status
tls_authentication_status(struct tls_multi *multi);

/** Check whether the \a ks \c key_state has finished the key exchange part
 *  of the OpenVPN hand shake. This is that the key_method_2read/write
 *  handshakes have been completed and certificate verification have
 *  been completed.
 *
 * connect/deferred auth might still pending. Also data-channel keys might
 * not have been created since they are delayed until PUSH_REPLY for NCP
 * clients.
 *
 *   @ingroup data_crypto
 *
 *   If true, it is safe to assume that this session has been authenticated
 *   by TLS.
 *
 *   @note This macro only works if S_SENT_KEY + 1 == S_GOT_KEY. */
#define TLS_AUTHENTICATED(multi, ks) ((ks)->state >= (S_GOT_KEY - (multi)->opt.server))

/**
 * Remove the given key state's auth deferred status auth control file,
 * if it exists.
 *
 * @param ads    The key state the remove the file for
 */
void key_state_rm_auth_control_files(struct auth_deferred_status *ads);

/**
 * Frees the given set of certificate hashes.
 *
 * @param chs   The certificate hash set to free.
 */
void cert_hash_free(struct cert_hash_set *chs);

/**
 * Locks the certificate hash set used in the given tunnel
 *
 * @param multi The tunnel to lock
 */
void tls_lock_cert_hash_set(struct tls_multi *multi);

/**
 * Locks the common name field for the given tunnel
 *
 * @param multi The tunnel to lock
 */
void tls_lock_common_name(struct tls_multi *multi);

/**
 * Returns the common name field for the given tunnel
 *
 * @param multi The tunnel to return the common name for
 * @param null  Whether null may be returned. If not, "UNDEF" will be returned.
 */
const char *tls_common_name(const struct tls_multi *multi, const bool null);

/**
 * Returns the username field for the given tunnel
 *
 * @param multi The tunnel to return the username for
 * @param null  Whether null may be returned. If not, "UNDEF" will be returned.
 */
const char *tls_username(const struct tls_multi *multi, const bool null);

/**
 * Compares certificates hashes, returns true if hashes are equal.
 *
 * @param chs1 cert 1 hash set
 * @param chs2 cert 2 hash set
 */
bool cert_hash_compare(const struct cert_hash_set *chs1, const struct cert_hash_set *chs2);

/**
 * Verify the given username and password, using either an external script, a
 * plugin, or the management interface.
 *
 * If authentication succeeds, the appropriate state is filled into the
 * session's primary key state's authenticated field. Authentication may also
 * be deferred, in which case the key state's auth_deferred field is filled in.
 *
 * @param up            The username and password to verify.
 * @param multi         The TLS multi structure to verify usernames against.
 * @param session       The current TLS session
 *
 */
void verify_user_pass(struct user_pass *up, struct tls_multi *multi,
                      struct tls_session *session);



/**
 * Runs the --client-crresponse script if one is defined.
 *
 * As with the management interface the script is stateless in the sense that
 * it does not directly participate in the authentication but rather should set
 * the files for the deferred auth like the management commands.
 *
 */
void
verify_crresponse_script(struct tls_multi *multi, const char *cr_response);

/**
 * Call the plugin OPENVPN_PLUGIN_CLIENT_CRRESPONSE.
 *
 * As with the management interface calling the plugin is stateless in the sense
 * that it does not directly participate in the authentication but rather
 * should set the files for the deferred auth like the management commands.
 */
void
verify_crresponse_plugin(struct tls_multi *multi, const char *cr_response);

/**
 * Perform final authentication checks, including locking of the cn, the allowed
 * certificate hashes, and whether a client config entry exists in the
 * client config directory.
 *
 * @param multi         The TLS multi structure to verify locked structures.
 * @param session       The current TLS session
 *
 */
void verify_final_auth_checks(struct tls_multi *multi, struct tls_session *session);

struct x509_track
{
    const struct x509_track *next;
    const char *name;
#define XT_FULL_CHAIN (1<<0)
    unsigned int flags;
    int nid;
};

/*
 * Certificate checking for verify_nsCertType
 */
/** Do not perform Netscape certificate type verification */
#define NS_CERT_CHECK_NONE (0)
/** Do not perform Netscape certificate type verification */
#define NS_CERT_CHECK_SERVER (1<<0)
/** Do not perform Netscape certificate type verification */
#define NS_CERT_CHECK_CLIENT (1<<1)

/** Require keyUsage to be present in cert (0xFFFF is an invalid KU value) */
#define OPENVPN_KU_REQUIRED (0xFFFF)

/*
 * TODO: document
 */
#ifdef ENABLE_MANAGEMENT
bool tls_authenticate_key(struct tls_multi *multi, const unsigned int mda_key_id, const bool auth, const char *client_reason);

#endif

/**
 * Sets the reason why authentication of a client failed. This be will send to the client
 * when the AUTH_FAILED message is sent
 * An example would be "SESSION: Token expired"
 * @param multi             The multi tls struct
 * @param client_reason     The string to send to the client as part of AUTH_FAILED
 */
void auth_set_client_reason(struct tls_multi *multi, const char *client_reason);

static inline const char *
tls_client_reason(struct tls_multi *multi)
{
    return multi->client_reason;
}

/** Remove any X509_ env variables from env_set es */
void tls_x509_clear_env(struct env_set *es);

#endif /* SSL_VERIFY_H_ */
