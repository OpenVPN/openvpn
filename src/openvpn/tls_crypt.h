/*
 *  OpenVPN -- An application to securely tunnel IP networks
 *             over a single TCP/UDP port, with support for SSL/TLS-based
 *             session authentication and key exchange,
 *             packet encryption, packet authentication, and
 *             packet compression.
 *
 *  Copyright (C) 2016-2018 Fox Crypto B.V. <openvpn@fox-it.com>
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
 * @defgroup tls_crypt Control channel encryption (--tls-crypt)
 * @ingroup control_tls
 * @{
 *
 * @par
 * Control channel encryption uses a pre-shared static key (like the --tls-auth
 * key) to encrypt control channel packets.
 *
 * @par
 * Encrypting control channel packets has three main advantages:
 *  - It provides more privacy by hiding the certificate used for the TLS
 *    connection.
 *  - It is harder to identify OpenVPN traffic as such.
 *  - It provides "poor-man's" post-quantum security, against attackers who
 *    will never know the pre-shared key (i.e. no forward secrecy).
 *
 * @par Specification
 * Control channel encryption is based on the SIV construction [0], to achieve
 * nonce misuse-resistant authenticated encryption:
 *
 * @par
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
 * @par
 * This boils down to the following on-the-wire packet format:
 *
 * @par
 * \code{.unparsed}
 * - opcode - || - session_id - || - packet_id - || auth_tag || * payload *
 * \endcode
 *
 * @par
 * Where
 * <tt>- XXX -</tt> means authenticated, and
 * <tt>* XXX *</tt> means authenticated and encrypted.
 */

#ifndef TLSCRYPT_H
#define TLSCRYPT_H

#ifdef ENABLE_CRYPTO

#include "buffer.h"
#include "crypto.h"
#include "session_id.h"

#define TLS_CRYPT_TAG_SIZE (256/8)
#define TLS_CRYPT_PID_SIZE (sizeof(packet_id_type) + sizeof(net_time_t))
#define TLS_CRYPT_BLOCK_SIZE (128/8)

#define TLS_CRYPT_OFF_PID (1 + SID_SIZE)
#define TLS_CRYPT_OFF_TAG (TLS_CRYPT_OFF_PID + TLS_CRYPT_PID_SIZE)
#define TLS_CRYPT_OFF_CT (TLS_CRYPT_OFF_TAG + TLS_CRYPT_TAG_SIZE)

/**
 * Initialize a key_ctx_bi structure for use with --tls-crypt.
 *
 * @param key           The key context to initialize
 * @param key_file      The file to read the key from (or the inline tag to
 *                      indicate and inline key).
 * @param key_inline    Array containing (zero-terminated) inline key, or NULL
 *                      if not used.
 * @param tls_server    Must be set to true is this is a TLS server instance.
 */
void tls_crypt_init_key(struct key_ctx_bi *key, const char *key_file,
                        const char *key_inline, bool tls_server);

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

/** @} */

#endif /* ENABLE_CRYPTO */

#endif /* TLSCRYPT_H */
