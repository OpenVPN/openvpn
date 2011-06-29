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
 * @file Control Channel Verification Module library-specific backend interface
 */

#ifndef SSL_VERIFY_BACKEND_H_
#define SSL_VERIFY_BACKEND_H_

/*
 * Backend support functions.
 *
 * The following functions are needed by the backend, but defined in the main
 * file.
 */

/*
 * Verify certificate for the given session. Performs OpenVPN-specific
 * verification.
 *
 * This function must be called for every certificate in the certificate
 * chain during the certificate verification stage of the handshake.
 *
 * @param session	TLS Session associated with this tunnel
 * @param cert		Certificate to process
 * @param cert_depth	Depth of the current certificate
 *
 * @return 		\c 1 if verification was successful, \c 0 on failure.
 */
int verify_cert(struct tls_session *session, x509_cert_t *cert, int cert_depth);

/*
 * Remember the given certificate hash, allowing the certificate chain to be
 * locked between sessions.
 *
 * Must be called for every certificate in the verification chain, whether it
 * is valid or not.
 *
 * @param session	TLS Session associated with this tunnel
 * @param cert_depth	Depth of the current certificate
 * @param sha1_hash	Hash of the current certificate
 */
void cert_hash_remember (struct tls_session *session, const int cert_depth,
    const unsigned char *sha1_hash);

/*
 * Library-specific functions.
 *
 * The following functions must be implemented on a library-specific basis.
 */

/*
 * Retrieve certificate's subject name, and place it in **subject.
 *
 * Memory for subject is allocated in the process, and must be freed.
 *
 * @param subject	Pointer to memory to be allocated for the subject
 * @param cert		Certificate to retrieve the subject from.
 *
 * @return 		\c 1 on failure, \c 0 on success
 */
bool verify_get_subject (char **subject, x509_cert_t *cert);

/*
 * Retrieve the certificate's username from the specified field.
 *
 * If the field is prepended with ext: and ENABLE_X509ALTUSERNAME is enabled,
 * it will be loaded from an X.509 extension
 *
 * @param cn			Buffer to return the common name in.
 * @param cn_len		Length of the cn buffer.
 * @param x509_username_field	Name of the field to load from
 * @param cert			Certificate to retrieve the common name from.
 *
 * @return 		\c 1 on failure, \c 0 on success
 */
bool verify_get_username (char *common_name, int cn_len,
    char * x509_username_field, x509_cert_t *peer_cert);

/*
 * Return the certificate's serial number.
 *
 * The serial number is returned as a string, since it might be a bignum.
 * The returened string must be freed with \c verify_free_serial()
 *
 * @param cert		Certificate to retrieve the serial number from.
 *
 * @return 		The certificate's serial number.
 */
char *verify_get_serial (x509_cert_t *cert);

/*
 * Free a serial number string as returned by \c verify_get_serial()
 *
 * @param serial	The string to be freed.
 */
void verify_free_serial (char *serial);

/*
 * TODO: document
 *
 * @param xt
 * @param es		Environment set to save variables in
 * @param cert_depth	Depth of the certificate
 * @param cert		Certificate to set the environment for
 */
void setenv_x509_track (const struct x509_track *xt, struct env_set *es,
    const int depth, x509_cert_t *x509);

/*
 * Save X509 fields to environment, using the naming convention:
 *
 * X509_{cert_depth}_{name}={value}
 *
 * @param es		Environment set to save variables in
 * @param cert_depth	Depth of the certificate
 * @param cert		Certificate to set the environment for
 */
void setenv_x509 (struct env_set *es, int cert_depth, x509_cert_t *cert);

/*
 * Check X.509 Netscape certificate type field, if available.
 *
 * @param cert		Certificate to check.
 * @param usage		One of \c NS_CERT_CHECK_CLIENT, \c NS_CERT_CHECK_SERVER,
 * 			or \c NS_CERT_CHECK_NONE.
 *
 * @return		\c true if NS_CERT_CHECK_NONE or if the certificate has
 * 			the expected bit set. \c false if the certificate does
 * 			not have NS cert type verification or the wrong bit set.
 */
bool verify_nsCertType(const x509_cert_t *cert, const int usage);

/*
 * Verify X.509 key usage extension field.
 *
 * @param cert		Certificate to check.
 * @param expected_ku	Array of valid key usage values
 * @param expected_len	Length of the key usage array
 *
 * @return 		\c true if one of the key usage values matches, \c false
 * 			if key usage is not enabled, or the values do not match.
 */
bool verify_cert_ku (x509_cert_t *x509, const unsigned * const expected_ku,
    int expected_len);

/*
 * Verify X.509 extended key usage extension field.
 *
 * @param cert		Certificate to check.
 * @param expected_oid	String representation of the expected Object ID. May be
 * 			either the string representation of the numeric OID
 * 			(e.g. \c "1.2.3.4", or the descriptive string matching
 * 			the OID.
 *
 * @return 		\c true if one of the expected OID matches one of the
 * 			extended key usage fields, \c false if extended key
 * 			usage is not enabled, or the values do not match.
 */
bool verify_cert_eku (x509_cert_t *x509, const char * const expected_oid);

#endif /* SSL_VERIFY_BACKEND_H_ */
