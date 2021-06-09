/*
 *  OpenVPN -- An application to securely tunnel IP networks
 *             over a single TCP/UDP port, with support for SSL/TLS-based
 *             session authentication and key exchange,
 *             packet encryption, packet authentication, and
 *             packet compression.
 *
 *  Copyright (C) 2010-2021 Fox Crypto B.V. <openvpn@fox-it.com>
 *
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
 * @file
 * Control Channel TLS module documentation file.
 */

/**
 * @defgroup control_tls Control Channel TLS module
 *
 * This module provides secure encapsulation of control channel messages
 * exchanged between OpenVPN peers.
 *
 * The Control Channel TLS module uses the Transport Layer Security (TLS)
 * protocol to provide an encrypted communication channel between the
 * local OpenVPN process and a remote peer.  This protocol simultaneously
 * offers certificate-based authentication of the communicating parties.
 *
 * @par This module's roles
 * The Control Channel TLS module is essential for the security of any
 * OpenVPN-based system.  On the one hand, it performs the security
 * operations necessary to protect control channel messages exchanged
 * between OpenVPN peers.  On the other hand, before the control and data
 * channels are even setup, it controls the exchange of certificates and
 * verification of the remote's identity during negotiation of VPN
 * tunnels.
 *
 * @par
 * The former role is described below.  The latter is described in the
 * documentation for the \c verify_callback() function.
 *
 * @par
 * In other words, this module takes care of the confidentiality and
 * integrity of data channel communications, and the authentication of
 * both the communicating parties and the control channel messages
 * exchanged.
 *
 * @par Initialization and cleanup
 * Because of the one-to-one relationship between control channel TLS
 * state and \c key_state structures, the initialization and cleanup of an
 * instance of the Control Channel TLS module's state happens within the
 * \c key_state_init() and \c key_state_free() functions.  In other words,
 * each \c key_state object contains exactly one OpenSSL SSL-BIO object,
 * which is initialized and cleaned up together with the rest of the \c
 * key_state object.
 *
 * @par Packet processing functions
 * This object behaves somewhat like a black box with a ciphertext and a
 * plaintext I/O port. Its interaction with OpenVPN's control channel
 * during operation takes place within the \c tls_process() function of
 * the \link control_processor Control Channel Processor\endlink.  The
 * following functions are available for processing packets:
 * - If ciphertext received from the remote peer is available in the \link
 *   reliable Reliability Layer\endlink:
 *   - Insert it into the ciphertext-side of the SSL-BIO.
 *   - Use function: \c key_state_write_ciphertext()
 * - If ciphertext can be extracted from the ciphertext-side of the
 *   SSL-BIO:
 *   - Pass it to the \link reliable Reliability Layer\endlink for sending
 *     to the remote peer.
 *   - Use function: \c key_state_read_ciphertext()
 * - If plaintext can be extracted from the plaintext-side of the SSL-BIO:
 *   - Pass it on to the \link control_processor Control Channel
 *     Processor\endlink for local processing.
 *   - Use function: \c key_state_read_plaintext()
 * - If plaintext from the \link control_processor Control Channel
 *   Processor\endlink is available to be sent to the remote peer:
 *   - Insert it into the plaintext-side of the SSL-BIO.
 *   - Use function: \c key_state_write_plaintext() or \c
 *     key_state_write_plaintext_const()
 *
 * @par Transport Layer Security protocol implementation
 * This module uses the OpenSSL library's implementation of the TLS
 * protocol in the form of an OpenSSL SSL-BIO object.
 *
 * @par
 * For more information on the OpenSSL library's BIO objects, please see:
 *  - OpenSSL's generic BIO objects:
 *    http://www.openssl.org/docs/crypto/bio.html
 *  - OpenSSL's SSL-BIO object:
 *    http://www.openssl.org/docs/crypto/BIO_f_ssl.html
 */
