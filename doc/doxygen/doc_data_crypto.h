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
 * Data Channel Crypto module documentation file.
 */

/**
 * @addtogroup data_crypto Data Channel Crypto module
 *
 * The Data Channel Crypto Module performs cryptographic operations on
 * data channel packets.
 *
 * @par Security parameters
 * This module is merely the user of a VPN tunnel's security parameters.
 * It does not perform the negotiation and setup of the security
 * parameters, nor the %key generation involved.  These actions are done
 * by the \link control_processor Control Channel Processor\endlink.  This
 * module receives the appropriate security parameters from that module in
 * the form of a \c crypto_options structure when they are necessary for
 * processing a packet.
 *
 * @par Packet processing functions
 * This module receives data channel packets from the \link data_control
 * Data Channel Control module\endlink and processes them according to the
 * security parameters of the packet's VPN tunnel.  The \link data_control
 * Data Channel Control module\endlink uses the following interface
 * functions:
 *  - For packets which will be sent to a remote OpenVPN peer:
 *     - \c tls_pre_encrypt()
 *     - \c openvpn_encrypt()
 *     - \c tls_post_encrypt()
 *  - For packets which have been received from a remote OpenVPN peer:
 *     - \c tls_pre_decrypt() (documented as part of the \link
 *       external_multiplexer External Multiplexer\endlink)
 *     - \c openvpn_decrypt()
 *
 * @par Settings that control this module's activity
 * How the data channel processes packets received from the \link data_control
 * Data Channel Control module\endlink at runtime depends on the associated
 * \c crypto_options structure.  To perform cryptographic operations, the
 * \c crypto_options.key_ctx_bi must contain the correct cipher and HMAC
 * security parameters for the direction the packet is traveling in.
 *
 * @par Crypto algorithms
 * This module uses the crypto algorithm implementations of the external
 * crypto library (currently either OpenSSL (default), or mbed TLS).
 */
