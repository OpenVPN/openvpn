/*
 *  OpenVPN -- An application to securely tunnel IP networks
 *             over a single TCP/UDP port, with support for SSL/TLS-based
 *             session authentication and key exchange,
 *             packet encryption, packet authentication, and
 *             packet compression.
 *
 *  Copyright (C) 2002-2023 OpenVPN Inc <sales@openvpn.net>
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
 * @file Control Channel Verification Module library-specific backend interface
 */

#ifndef SSL_VERIFY_BACKEND_H_
#define SSL_VERIFY_BACKEND_H_

/**
 * Result of verification function
 */
typedef enum { SUCCESS = 0, FAILURE = 1 } result_t;

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
 * @param session       TLS Session associated with this tunnel
 * @param cert          Certificate to process
 * @param cert_depth    Depth of the current certificate
 *
 * @return              \c SUCCESS if verification was successful, \c FAILURE on failure.
 */
result_t verify_cert(struct tls_session *session, openvpn_x509_cert_t *cert, int cert_depth);

/*
 * Remember the given certificate hash, allowing the certificate chain to be
 * locked between sessions.
 *
 * Must be called for every certificate in the verification chain, whether it
 * is valid or not.
 *
 * @param session       TLS Session associated with this tunnel
 * @param cert_depth    Depth of the current certificate
 * @param cert_hash     Hash of the current certificate
 */
void cert_hash_remember(struct tls_session *session, const int cert_depth,
                        const struct buffer *cert_hash);

/*
 * Library-specific functions.
 *
 * The following functions must be implemented on a library-specific basis.
 */

/*
 * Retrieve certificate's subject name.
 *
 * @param cert          Certificate to retrieve the subject from.
 * @param gc            Garbage collection arena to use when allocating string.
 *
 * @return              a string containing the subject
 */
char *x509_get_subject(openvpn_x509_cert_t *cert, struct gc_arena *gc);

/**
 * Retrieve the certificate's SHA1 fingerprint.
 *
 * @param cert          Certificate to retrieve the fingerprint from.
 * @param gc            Garbage collection arena to use when allocating string.
 *
 * @return              a string containing the certificate fingerprint
 */
struct buffer x509_get_sha1_fingerprint(openvpn_x509_cert_t *cert,
                                        struct gc_arena *gc);

/**
 * Retrieve the certificate's SHA256 fingerprint.
 *
 * @param cert          Certificate to retrieve the fingerprint from.
 * @param gc            Garbage collection arena to use when allocating string.
 *
 * @return              a string containing the certificate fingerprint
 */
struct buffer x509_get_sha256_fingerprint(openvpn_x509_cert_t *cert,
                                          struct gc_arena *gc);

/*
 * Retrieve the certificate's username from the specified field.
 *
 * If the field is prepended with ext: and ENABLE_X509ALTUSERNAME is enabled,
 * it will be loaded from an X.509 extension
 *
 * @param cn                    Buffer to return the common name in.
 * @param cn_len                Length of the cn buffer.
 * @param x509_username_field   Name of the field to load from
 * @param cert                  Certificate to retrieve the common name from.
 *
 * @return              \c FAILURE, \c or SUCCESS
 */
result_t backend_x509_get_username(char *common_name, int cn_len,
                                   char *x509_username_field, openvpn_x509_cert_t *peer_cert);

#ifdef ENABLE_X509ALTUSERNAME
/**
 * Return true iff the supplied extension field is supported by the
 * --x509-username-field option.
 */
bool x509_username_field_ext_supported(const char *extname);

#endif

/*
 * Return the certificate's serial number in decimal string representation.
 *
 * The serial number is returned as a string, since it might be a bignum.
 *
 * @param cert          Certificate to retrieve the serial number from.
 * @param gc            Garbage collection arena to use when allocating string.
 *
 * @return              String representation of the certificate's serial number
 *                      in decimal notation, or NULL on error.
 */
char *backend_x509_get_serial(openvpn_x509_cert_t *cert, struct gc_arena *gc);

/*
 * Return the certificate's serial number in hex string representation.
 *
 * The serial number is returned as a string, since it might be a bignum.
 *
 * @param cert          Certificate to retrieve the serial number from.
 * @param gc            Garbage collection arena to use when allocating string.
 *
 * @return              String representation of the certificate's serial number
 *                      in hex notation, or NULL on error.
 */
char *backend_x509_get_serial_hex(openvpn_x509_cert_t *cert,
                                  struct gc_arena *gc);

/*
 * Write the certificate to the file in PEM format.
 *
 *
 * @param cert          Certificate to serialise.
 *
 * @return              \c FAILURE, \c or SUCCESS
 */
result_t backend_x509_write_pem(openvpn_x509_cert_t *cert,
                                const char *filename);

/*
 * Save X509 fields to environment, using the naming convention:
 *
 * X509_{cert_depth}_{name}={value}
 *
 * @param es            Environment set to save variables in
 * @param cert_depth    Depth of the certificate
 * @param cert          Certificate to set the environment for
 */
void x509_setenv(struct env_set *es, int cert_depth, openvpn_x509_cert_t *cert);

/*
 * Start tracking the given attribute.
 *
 * The tracked attributes are stored in ll_head.
 *
 * @param ll_head       The x509_track to store tracked attributes in
 * @param name          Name of the attribute to track
 * @param msglevel      Message level for errors
 * @param gc            Garbage collection arena for temp data
 *
 */
void x509_track_add(const struct x509_track **ll_head, const char *name,
                    int msglevel, struct gc_arena *gc);

/*
 * Save X509 fields to environment, using the naming convention:
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
 *
 * @param xt
 * @param es            Environment set to save variables in
 * @param cert_depth    Depth of the certificate
 * @param cert          Certificate to set the environment for
 */
void x509_setenv_track(const struct x509_track *xt, struct env_set *es,
                       const int depth, openvpn_x509_cert_t *x509);

/*
 * Check X.509 Netscape certificate type field, if available.
 *
 * @param cert          Certificate to check.
 * @param usage         One of \c NS_CERT_CHECK_CLIENT, \c NS_CERT_CHECK_SERVER,
 *                      or \c NS_CERT_CHECK_NONE.
 *
 * @return              \c SUCCESS if NS_CERT_CHECK_NONE or if the certificate has
 *                      the expected bit set. \c FAILURE if the certificate does
 *                      not have NS cert type verification or the wrong bit set.
 */
result_t x509_verify_ns_cert_type(openvpn_x509_cert_t *cert, const int usage);

/*
 * Verify X.509 key usage extension field.
 *
 * @param cert          Certificate to check.
 * @param expected_ku   Array of valid key usage values
 * @param expected_len  Length of the key usage array
 *
 * @return              \c SUCCESS if one of the key usage values matches, \c FAILURE
 *                      if key usage is not enabled, or the values do not match.
 */
result_t x509_verify_cert_ku(openvpn_x509_cert_t *x509, const unsigned *const expected_ku,
                             int expected_len);

/*
 * Verify X.509 extended key usage extension field.
 *
 * @param cert          Certificate to check.
 * @param expected_oid  String representation of the expected Object ID. May be
 *                      either the string representation of the numeric OID
 *                      (e.g. \c "1.2.3.4", or the descriptive string matching
 *                      the OID.
 *
 * @return              \c SUCCESS if one of the expected OID matches one of the
 *                      extended key usage fields, \c FAILURE if extended key
 *                      usage is not enabled, or the values do not match.
 */
result_t x509_verify_cert_eku(openvpn_x509_cert_t *x509, const char *const expected_oid);

/**
 * Return true iff a CRL is configured, but is not loaded.  This can be caused
 * by e.g. a CRL parsing error, a missing CRL file or CRL file permission
 * errors.  (These conditions are checked upon startup, but the CRL might be
 * updated and reloaded during runtime.)
 */
bool tls_verify_crl_missing(const struct tls_options *opt);

#endif /* SSL_VERIFY_BACKEND_H_ */
