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
 * @file Control Channel SSL library backend module
 */


#ifndef SSL_BACKEND_H_
#define SSL_BACKEND_H_

#include "buffer.h"

#ifdef ENABLE_CRYPTO_OPENSSL
#include "ssl_openssl.h"
#include "ssl_verify_openssl.h"
#define SSLAPI SSLAPI_OPENSSL
#endif
#ifdef ENABLE_CRYPTO_POLARSSL
#include "ssl_polarssl.h"
#include "ssl_verify_polarssl.h"
#define SSLAPI SSLAPI_POLARSSL
#endif

/* Ensure that SSLAPI got a sane value if SSL is disabled or unknown */
#ifndef SSLAPI
#define SSLAPI SSLAPI_NONE
#endif

/**
 *  prototype for struct tls_session from ssl_common.h
 */
struct tls_session;

/**
 * Get a tls_cipher_name_pair containing OpenSSL and IANA names for supplied TLS cipher name
 *
 * @param cipher_name	Can be either OpenSSL or IANA cipher name
 * @return		tls_cipher_name_pair* if found, NULL otherwise
 */
typedef struct { const char *openssl_name; const char *iana_name; } tls_cipher_name_pair;
const tls_cipher_name_pair *tls_get_cipher_name_pair (const char *cipher_name, size_t len);

/*
 *
 * Functions implemented in ssl.c for use by the backend SSL library
 *
 */

/**
 * Callback to retrieve the user's password
 *
 * @param buf		Buffer to return the password in
 * @param size		Size of the buffer
 * @param rwflag	Unused, needed for OpenSSL compatibility
 * @param u		Unused, needed for OpenSSL compatibility
 */
int pem_password_callback (char *buf, int size, int rwflag, void *u);

/*
 *
 * Functions used in ssl.c which must be implemented by the backend SSL library
 *
 */

/**
 * Perform any static initialisation necessary by the library.
 * Called on OpenVPN initialisation
 */
void tls_init_lib();

/**
 * Free any global SSL library-specific data structures.
 */
void tls_free_lib();
/**
 * Clear the underlying SSL library's error state.
 */
void tls_clear_error();

/**
 * Parse a TLS version specifier
 *
 * @param vstr		The TLS version string
 * @param extra	        An optional extra parameter, may be NULL
 *
 * @return 		One of the TLS_VER_x constants or TLS_VER_BAD
 *                      if a parse error should be flagged.
 */
#define TLS_VER_BAD    -1
#define TLS_VER_UNSPEC  0 /* default */
#define TLS_VER_1_0     1
#define TLS_VER_1_1     2
#define TLS_VER_1_2     3
int tls_version_parse(const char *vstr, const char *extra);

/**
 * Return the maximum TLS version (as a TLS_VER_x constant)
 * supported by current SSL implementation
 *
 * @return 		One of the TLS_VER_x constants (but not TLS_VER_BAD).
 */
int tls_version_max(void);

/**
 * Initialise a library-specific TLS context for a server.
 *
 * @param ctx		TLS context to initialise
 * @param ssl_flags     SSLF_x flags from ssl_common.h
 */
void tls_ctx_server_new(struct tls_root_ctx *ctx, unsigned int ssl_flags);

/**
 * Initialises a library-specific TLS context for a client.
 *
 * @param ctx		TLS context to initialise
 * @param ssl_flags     SSLF_x flags from ssl_common.h
 */
void tls_ctx_client_new(struct tls_root_ctx *ctx, unsigned int ssl_flags);

/**
 * Frees the library-specific TLSv1 context
 *
 * @param ctx		TLS context to free
 */
void tls_ctx_free(struct tls_root_ctx *ctx);

/**
 * Checks whether the given TLS context is initialised
 *
 * @param ctx		TLS context to check
 *
 * @return	true if the context is initialised, false if not.
 */
bool tls_ctx_initialised(struct tls_root_ctx *ctx);

/**
 * Set any library specific options.
 *
 * Examples include disabling session caching, the password callback to use,
 * and session verification parameters.
 *
 * @param ctx		TLS context to set options on
 * @param ssl_flags	SSL flags to set
 */
void tls_ctx_set_options (struct tls_root_ctx *ctx, unsigned int ssl_flags);

/**
 * Restrict the list of ciphers that can be used within the TLS context.
 *
 * @param ctx		TLS context to restrict
 * @param ciphers	String containing : delimited cipher names.
 */
void tls_ctx_restrict_ciphers(struct tls_root_ctx *ctx, const char *ciphers);

/**
 * Load Diffie Hellman Parameters, and load them into the library-specific
 * TLS context.
 *
 * @param ctx			TLS context to use
 * @param dh_file		The file name to load the parameters from, or
 * 				"[[INLINE]]" in the case of inline files.
 * @param dh_file_inline	A string containing the parameters
 */
void tls_ctx_load_dh_params(struct tls_root_ctx *ctx, const char *dh_file,
    const char *dh_file_inline);

/**
 * Load PKCS #12 file for key, cert and (optionally) CA certs, and add to
 * library-specific TLS context.
 *
 * @param ctx			TLS context to use
 * @param pkcs12_file		The file name to load the information from, or
 * 				"[[INLINE]]" in the case of inline files.
 * @param pkcs12_file_inline	A string containing the information
 *
 * @return 			1 if an error occurred, 0 if parsing was
 * 				successful.
 */
int tls_ctx_load_pkcs12(struct tls_root_ctx *ctx, const char *pkcs12_file,
    const char *pkcs12_file_inline, bool load_ca_file
    );

/**
 * Use Windows cryptoapi for key and cert, and add to library-specific TLS
 * context.
 *
 * @param ctx			TLS context to use
 * @param crypto_api_cert	String representing the certificate to load.
 */
#ifdef ENABLE_CRYPTOAPI
void tls_ctx_load_cryptoapi(struct tls_root_ctx *ctx, const char *cryptoapi_cert);
#endif /* WIN32 */

/**
 * Load certificate file into the given TLS context. If the given certificate
 * file contains a certificate chain, load the whole chain.
 *
 * @param ctx			TLS context to use
 * @param cert_file		The file name to load the certificate from, or
 * 				"[[INLINE]]" in the case of inline files.
 * @param cert_file_inline	A string containing the certificate
 */
void tls_ctx_load_cert_file (struct tls_root_ctx *ctx, const char *cert_file,
    const char *cert_file_inline);

/**
 * Load private key file into the given TLS context.
 *
 * @param ctx			TLS context to use
 * @param priv_key_file		The file name to load the private key from, or
 * 				"[[INLINE]]" in the case of inline files.
 * @param priv_key_file_inline	A string containing the private key
 *
 * @return 			1 if an error occurred, 0 if parsing was
 * 				successful.
 */
int tls_ctx_load_priv_file (struct tls_root_ctx *ctx, const char *priv_key_file,
    const char *priv_key_file_inline
    );

#ifdef MANAGMENT_EXTERNAL_KEY

/**
 * Tell the management interface to load the given certificate and the external
 * private key matching the given certificate.
 *
 * @param ctx			TLS context to use
 * @param cert_file		The file name to load the certificate from, or
 * 				"[[INLINE]]" in the case of inline files.
 * @param cert_file_inline	A string containing the certificate
 *
 * @return 			1 if an error occurred, 0 if parsing was
 * 				successful.
 */
int tls_ctx_use_external_private_key (struct tls_root_ctx *ctx,
    const char *cert_file, const char *cert_file_inline);
#endif


/**
 * Load certificate authority certificates from the given file or path.
 *
 * Note that not all SSL libraries support loading from a path.
 *
 * @param ctx			TLS context to use
 * @param ca_file		The file name to load the CAs from, or
 * 				"[[INLINE]]" in the case of inline files.
 * @param ca_file_inline	A string containing the CAs
 * @param ca_path		The path to load the CAs from
 */
void tls_ctx_load_ca (struct tls_root_ctx *ctx, const char *ca_file,
    const char *ca_file_inline, const char *ca_path, bool tls_server
    );

/**
 * Load extra certificate authority certificates from the given file or path.
 * These Load extra certificates that are part of our own certificate
 * chain but shouldn't be included in the verify chain.
 *
 *
 * @param ctx				TLS context to use
 * @param extra_certs_file		The file name to load the certs from, or
 * 					"[[INLINE]]" in the case of inline files.
 * @param extra_certs_file_inline	A string containing the certs
 */
void tls_ctx_load_extra_certs (struct tls_root_ctx *ctx, const char *extra_certs_file,
    const char *extra_certs_file_inline
    );

#ifdef ENABLE_CRYPTO_POLARSSL
/**
 * Add a personalisation string to the PolarSSL RNG, based on the certificate
 * loaded into the given context.
 *
 * @param ctx			TLS context to use
 */
void tls_ctx_personalise_random(struct tls_root_ctx *ctx);
#endif

/* **************************************
 *
 * Key-state specific functions
 *
 ***************************************/

/**
 * Initialise the SSL channel part of the given key state. Settings will be
 * loaded from a previously initialised TLS context.
 *
 * @param ks_ssl	The SSL channel's state info to initialise
 * @param ssl_ctx	The TLS context to use when initialising the channel.
 * @param is_server	Initialise a server?
 * @param session	The session associated with the given key_state
 */
void key_state_ssl_init(struct key_state_ssl *ks_ssl,
    const struct tls_root_ctx *ssl_ctx, bool is_server, struct tls_session *session);

/**
 * Free the SSL channel part of the given key state.
 *
 * @param ks_ssl	The SSL channel's state info to free
 */
void key_state_ssl_free(struct key_state_ssl *ks_ssl);

/**************************************************************************/
/** @addtogroup control_tls
 *  @{ */

/** @name Functions for packets to be sent to a remote OpenVPN peer
 *  @{ */

/**
 * Insert a plaintext buffer into the TLS module.
 *
 * After successfully processing the data, the data in \a buf is zeroized,
 * its length set to zero, and a value of \c 1 is returned.
 *
 * @param ks_ssl       - The security parameter state for this %key
 *                       session.
 * @param buf          - The plaintext message to process.
 *
 * @return The return value indicates whether the data was successfully
 *     processed:
 * - \c 1: All the data was processed successfully.
 * - \c 0: The data was not processed, this function should be called
 *   again later to retry.
 * - \c -1: An error occurred.
 */
int key_state_write_plaintext (struct key_state_ssl *ks_ssl, struct buffer *buf);

/**
 * Insert plaintext data into the TLS module.
 *
 * @param ks_ssl       - The security parameter state for this %key
 *                       session.
 * @param data         - A pointer to the data to process.
 * @param len          - The length in bytes of the data to process.
 *
 * @return The return value indicates whether the data was successfully
 *     processed:
 * - \c 1: All the data was processed successfully.
 * - \c 0: The data was not processed, this function should be called
 *   again later to retry.
 * - \c -1: An error occurred.
 */
int key_state_write_plaintext_const (struct key_state_ssl *ks_ssl,
    const uint8_t *data, int len);

/**
 * Extract ciphertext data from the TLS module.
 *
 * If the \a buf buffer has a length other than zero, this function does
 * not perform any action and returns 0.
 *
 * @param ks_ssl       - The security parameter state for this %key
 *                       session.
 * @param buf          - A buffer in which to store the ciphertext.
 * @param maxlen       - The maximum number of bytes to extract.
 *
 * @return The return value indicates whether the data was successfully
 *     processed:
 * - \c 1: Data was extracted successfully.
 * - \c 0: No data was extracted, this function should be called again
 *   later to retry.
 * - \c -1: An error occurred.
 */
int key_state_read_ciphertext (struct key_state_ssl *ks_ssl, struct buffer *buf,
    int maxlen);

/** @} name Functions for packets to be sent to a remote OpenVPN peer */


/** @name Functions for packets received from a remote OpenVPN peer
 *  @{ */

/**
 * Insert a ciphertext buffer into the TLS module.
 *
 * After successfully processing the data, the data in \a buf is zeroized,
 * its length set to zero, and a value of \c 1 is returned.
 *
 * @param ks_ssl       - The security parameter state for this %key
 *                       session.
 * @param buf          - The ciphertext message to process.
 *
 * @return The return value indicates whether the data was successfully
 *     processed:
 * - \c 1: All the data was processed successfully.
 * - \c 0: The data was not processed, this function should be called
 *   again later to retry.
 * - \c -1: An error occurred.
 */
int key_state_write_ciphertext (struct key_state_ssl *ks_ssl,
    struct buffer *buf);

/**
 * Extract plaintext data from the TLS module.
 *
 * If the \a buf buffer has a length other than zero, this function does
 * not perform any action and returns 0.
 *
 * @param ks_ssl       - The security parameter state for this %key
 *                       session.
 * @param buf          - A buffer in which to store the plaintext.
 * @param maxlen       - The maximum number of bytes to extract.
 *
 * @return The return value indicates whether the data was successfully
 *     processed:
 * - \c 1: Data was extracted successfully.
 * - \c 0: No data was extracted, this function should be called again
 *   later to retry.
 * - \c -1: An error occurred.
 */
int key_state_read_plaintext (struct key_state_ssl *ks_ssl, struct buffer *buf,
    int maxlen);

/** @} name Functions for packets received from a remote OpenVPN peer */

/** @} addtogroup control_tls */

/* **************************************
 *
 * Information functions
 *
 * Print information for the end user.
 *
 ***************************************/

/*
 * Print a one line summary of SSL/TLS session handshake.
 */
void print_details (struct key_state_ssl * ks_ssl, const char *prefix);

/*
 * Show the TLS ciphers that are available for us to use in the OpenSSL
 * library.
 *
 * @param		- list of allowed TLS cipher, or NULL.
 */
void show_available_tls_ciphers (const char *tls_ciphers);

/*
 * The OpenSSL library has a notion of preference in TLS ciphers.  Higher
 * preference == more secure. Return the highest preference cipher.
 */
void get_highest_preference_tls_cipher (char *buf, int size);

/**
 * return a pointer to a static memory area containing the
 * name and version number of the SSL library in use
 */
const char * get_ssl_library_version(void);

#endif /* SSL_BACKEND_H_ */
