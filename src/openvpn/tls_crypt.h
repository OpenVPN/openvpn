/*
 *  OpenVPN -- An application to securely tunnel IP networks
 *             over a single TCP/UDP port, with support for SSL/TLS-based
 *             session authentication and key exchange,
 *             packet encryption, packet authentication, and
 *             packet compression.
 *
 *  Copyright (C) 2016-2021 Fox Crypto B.V. <openvpn@foxcrypto.com>
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
 * @defgroup tls_crypt Control channel encryption (--tls-crypt, --tls-crypt-v2)
 * @ingroup control_tls
 * @{
 *
 * Control channel encryption uses a pre-shared static key (like the --tls-auth
 * key) to encrypt control channel packets.
 *
 * Encrypting control channel packets has three main advantages:
 *  - It provides more privacy by hiding the certificate used for the TLS
 *    connection.
 *  - It is harder to identify OpenVPN traffic as such.
 *  - It provides "poor-man's" post-quantum security, against attackers who
 *    will never know the pre-shared key (i.e. no forward secrecy).
 *
 * --tls-crypt uses a tls-auth-style group key, where all servers and clients
 * share the same group key. --tls-crypt-v2 adds support for client-specific
 * keys, where all servers share the same client-key encryption key, and each
 * clients receives a unique client key, both in plaintext and in encrypted
 * form.  When connecting to a server, the client sends the encrypted key to
 * the server in the first packet (P_CONTROL_HARD_RESET_CLIENT_V3). The server
 * then decrypts that key, and both parties can use the same client-specific
 * key for tls-crypt packets. See doc/tls-crypt-v2.txt for more details.
 *
 * @par On-the-wire tls-crypt packet specification
 * @parblock
 * Control channel encryption is based on the SIV construction [0], to achieve
 * nonce misuse-resistant authenticated encryption:
 *
 * \code{.unparsed}
 * msg      = control channel plaintext
 * header   = opcode (1 byte) || session_id (8 bytes) || packet_id (8 bytes)
 * Ka       = authentication key (256 bits)
 * Ke       = encryption key (256 bits)
 * (Ka and Ke are pre-shared keys, like with --tls-auth)
 *
 * auth_tag = HMAC-SHA256(Ka, header || msg)
 * IV       = 128 most-significant bits of auth_tag
 * ciph     = AES256-CTR(Ke, IV, msg)
 *
 * output   = Header || Tag || Ciph
 * \endcode
 *
 * This boils down to the following on-the-wire packet format:
 *
 * \code{.unparsed}
 * - opcode - || - session_id - || - packet_id - || auth_tag || * payload *
 * \endcode
 *
 * Where
 * <tt>- XXX -</tt> means authenticated, and
 * <tt>* XXX *</tt> means authenticated and encrypted.
 *
 * @endparblock
 */

#ifndef TLSCRYPT_H
#define TLSCRYPT_H

#include "base64.h"
#include "buffer.h"
#include "crypto.h"
#include "session_id.h"
#include "ssl_common.h"

#define TLS_CRYPT_TAG_SIZE (256/8)
#define TLS_CRYPT_PID_SIZE (sizeof(packet_id_type) + sizeof(net_time_t))
#define TLS_CRYPT_BLOCK_SIZE (128/8)

#define TLS_CRYPT_OFF_PID (1 + SID_SIZE)
#define TLS_CRYPT_OFF_TAG (TLS_CRYPT_OFF_PID + TLS_CRYPT_PID_SIZE)
#define TLS_CRYPT_OFF_CT (TLS_CRYPT_OFF_TAG + TLS_CRYPT_TAG_SIZE)

#define TLS_CRYPT_V2_MAX_WKC_LEN (1024)
#define TLS_CRYPT_V2_CLIENT_KEY_LEN (2048 / 8)
#define TLS_CRYPT_V2_SERVER_KEY_LEN (sizeof(struct key))
#define TLS_CRYPT_V2_TAG_SIZE (TLS_CRYPT_TAG_SIZE)
#define TLS_CRYPT_V2_MAX_METADATA_LEN (unsigned)(TLS_CRYPT_V2_MAX_WKC_LEN \
                                                 - (TLS_CRYPT_V2_CLIENT_KEY_LEN + TLS_CRYPT_V2_TAG_SIZE \
                                                    + sizeof(uint16_t)))
#define TLS_CRYPT_V2_MAX_B64_METADATA_LEN \
    OPENVPN_BASE64_LENGTH(TLS_CRYPT_V2_MAX_METADATA_LEN - 1)

/**
 * Initialize a key_ctx_bi structure for use with --tls-crypt.
 *
 * @param key           The key context to initialize
 * @param key_file      The file to read the key from or the key itself if
 *                      key_inline is true.
 * @param key_inline    True if key_file contains an inline key, False
 *                      otherwise.
 * @param tls_server    Must be set to true is this is a TLS server instance.
 */
void tls_crypt_init_key(struct key_ctx_bi *key, const char *key_file,
                        bool key_inline, bool tls_server);

/**
 * Returns the maximum overhead (in bytes) added to the destination buffer by
 * tls_crypt_wrap().
 */
int tls_crypt_buf_overhead(void);

/**
 * Adjust frame parameters for --tls-crypt overhead.
 */
void tls_crypt_adjust_frame_parameters(struct frame *frame);

/**
 * Wrap a control channel packet (both authenticates and encrypts the data).
 *
 * @param src   Data to authenticate and encrypt.
 * @param dst   Any data present in this buffer is first authenticated, then
 *              the wrapped packet id and data from the src buffer are appended.
 *              Must have at least tls_crypt_buf_overhead()+BLEN(src) headroom.
 * @param opt   The crypto state for this --tls-crypt instance.
 *
 * @returns true iff wrapping succeeded.
 */
bool tls_crypt_wrap(const struct buffer *src, struct buffer *dst,
                    struct crypto_options *opt);

/**
 * Unwrap a control channel packet (decrypts, authenticates and performs
 * replay checks).
 *
 * @param src   Data to decrypt and authenticate.
 * @param dst   Returns the decrypted data, if unwrapping was successful.
 * @param opt   The crypto state for this --tls-crypt instance.
 *
 * @returns true iff unwrapping succeeded (data authenticated correctly and was
 * no replay).
 */
bool tls_crypt_unwrap(const struct buffer *src, struct buffer *dst,
                      struct crypto_options *opt);

/**
 * Initialize a tls-crypt-v2 server key (used to encrypt/decrypt client keys).
 *
 * @param key           Key structure to be initialized.  Must be non-NULL.
 * @parem encrypt       If true, initialize the key structure for encryption,
 *                      otherwise for decryption.
 * @param key_file      File path of the key file to load or the key itself if
 *                      key_inline is true.
 * @param key_inline    True if key_file contains an inline key, False
 *                      otherwise.
 *
 */
void tls_crypt_v2_init_server_key(struct key_ctx *key_ctx, bool encrypt,
                                  const char *key_file, bool key_inline);

/**
 * Initialize a tls-crypt-v2 client key.
 *
 * @param key               Key structure to be initialized with the client
 *                          key.
 * @param wrapped_key_buf   Returns buffer containing the wrapped key that will
 *                          be sent to the server when connecting.  Caller must
 *                          free this buffer when no longer needed.
 * @param key_file          File path of the key file to load or the key itself
 *                          if key_inline is true.
 * @param key_inline        True if key_file contains an inline key, False
 *                          otherwise.
 */
void tls_crypt_v2_init_client_key(struct key_ctx_bi *key,
                                  struct buffer *wrapped_key_buf,
                                  const char *key_file, bool key_inline);

/**
 * Extract a tls-crypt-v2 client key from a P_CONTROL_HARD_RESET_CLIENT_V3
 * message, and load the key into the supplied tls wrap context.
 *
 * @param buf   Buffer containing a received P_CONTROL_HARD_RESET_CLIENT_V3
 *              message.
 * @param ctx   tls-wrap context to be initialized with the client key.
 *
 * @returns true if a key was successfully extracted.
 */
bool tls_crypt_v2_extract_client_key(struct buffer *buf,
                                     struct tls_wrap_ctx *ctx,
                                     const struct tls_options *opt);

/**
 * Generate a tls-crypt-v2 server key, and write to file.
 *
 * @param filename          Filename of the server key file to create.
 */
void tls_crypt_v2_write_server_key_file(const char *filename);

/**
 * Generate a tls-crypt-v2 client key, and write to file.
 *
 * @param filename          Filename of the client key file to create.
 * @param b64_metadata      Base64 metadata to be included in the client key.
 * @param key_file          File path of the server key to use for wrapping the
 *                          client key or the key itself if key_inline is true.
 * @param key_inline        True if key_file contains an inline key, False
 *                          otherwise.
 */
void tls_crypt_v2_write_client_key_file(const char *filename,
                                        const char *b64_metadata,
                                        const char *key_file, bool key_inline);

/** @} */

#endif /* TLSCRYPT_H */
