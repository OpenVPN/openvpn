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
 * Key generation documentation file.
 */

/**
 * @page key_generation Data channel %key generation
 *
 * This section describes how OpenVPN peers generate and exchange %key
 * material necessary for the security operations performed on data
 * channel packets.
 *
 * The %key generation and exchange process between OpenVPN client and
 * server occurs every time data channel security parameters are
 * negotiated, for example during the initial setup of a VPN tunnel or
 * when the active security parameters expire.  In source code terms, this
 * is when a new key_state structure is initialized.
 *
 * @section key_generation_method Key methods
 *
 * OpenVPN supports two different ways of generating and exchanging %key
 * material between client and server.  These are known as %key method 1
 * and %key method 2.  %Key method 2 is the recommended method. Both are
 * explained below.
 *
 * @subsection key_generation_method_1 Key method 1
 *
 * -# Each host generates its own random material.
 * -# Each host uses its locally generated random material as %key data
 *    for encrypting and signing packets sent to the remote peer.
 * -# Each host then sends its random material to the remote peer, so that
 *    the remote peer can use that %key data for authenticating and
 *    decrypting received packets.
 *
 * @subsection key_generation_method_2 Key method 2
 *
 * -# The client generates random material in the following amounts:
 *    - Pre-master secret: 48 bytes
 *    - Client's PRF seed for master secret: 32 bytes
 *    - Client's PRF seed for %key expansion: 32 bytes
 * -# The client sends its share of random material to the server.
 * -# The server generates random material in the following amounts:
 *    - Server's PRF seed for master secret: 32 bytes
 *    - Server's PRF seed for %key expansion: 32 bytes
 * -# The server computes the %key expansion using its own and the
 *    client's random material.
 * -# The server sends its share of random material to the client.
 * -# The client computes the %key expansion using its own and the
 *    server's random material.
 *
 * %Key method 2 %key expansion is performed by the \c
 * generate_key_expansion() function.  Please refer to its source code for
 * details of the %key expansion process.
 *
 * @subsection key_generation_random Source of random material
 *
 * OpenVPN uses the either the OpenSSL library or the mbed TLS library as its
 * source of random material.
 *
 * In OpenSSL, the \c RAND_bytes() function is called
 * to supply cryptographically strong pseudo-random data.  The following links
 * contain more information on this subject:
 * - For OpenSSL's \c RAND_bytes() function:
 *   http://www.openssl.org/docs/crypto/RAND_bytes.html
 * - For OpenSSL's pseudo-random number generating system:
 *   http://www.openssl.org/docs/crypto/rand.html
 * - For OpenSSL's support for external crypto modules:
 *   http://www.openssl.org/docs/crypto/engine.html
 *
 * In mbed TLS, the Havege random number generator is used. For details, see
 * the mbed TLS documentation.
 *
 * @section key_generation_exchange Key exchange:
 *
 * The %key exchange process is initiated by the OpenVPN process running
 * in client mode.  After the initial three-way handshake has successfully
 * completed, the client sends its share of random material to the server,
 * after which the server responds with its part.  This process is
 * depicted below:
 *
@verbatim
  Client           Client                           Server          Server
  State            Action                           Action          State
----------  --------------------            --------------------  ----------

             ... waiting until three-way handshake complete ...
S_START                                                              S_START
            key_method_?_write()
            send to server  --> --> --> -->  receive from client
S_SENT_KEY                                   key_method_?_read()
                                                                   S_GOT_KEY
                                            key_method_?_write()
            receive from server  <-- <-- <-- <--  send to client
            key_method_?_read()                                   S_SENT_KEY
S_GOT_KEY
          ... waiting until control channel fully synchronized ...
S_ACTIVE                                                            S_ACTIVE
@endverbatim
 *
 * For more information about the client and server state values, see the
 * \link control_processor Control Channel Processor module\endlink.
 *
 * Depending on which %key method is used, the \c ? in the function names
 * of the diagram above is a \c 1 or a \c 2.  For example, if %key method
 * 2 is used, that %key exchange would be started by the client calling \c
 * key_method_2_write().  These functions are called from the \link
 * control_processor Control Channel Processor module's\endlink \c
 * tls_process() function and control the %key generation and exchange
 * process as follows:
 * - %Key method 1 has been removed in OpenVPN 2.5
 * - %Key method 2:
 *   - \c key_method_2_write(): generate random material locally, and if
 *     in server mode generate %key expansion.
 *   - \c key_method_2_read(): read random material received from remote
 *     peer, and if in client mode generate %key expansion.
 *
 * @subsection key_generation_encapsulation Transmission of key material
 *
 * The OpenVPN client and server communicate with each other through their
 * control channel.  This means that all of the data transmitted over the
 * network, such as random material for %key generation, is encapsulated
 * in a TLS layer.  For more details, see the \link control_tls Control
 * Channel TLS module\endlink documentation.
 */
