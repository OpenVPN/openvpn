/*
 *  OpenVPN -- An application to securely tunnel IP networks
 *             over a single TCP/UDP port, with support for SSL/TLS-based
 *             session authentication and key exchange,
 *             packet encryption, packet authentication, and
 *             packet compression.
 *
 *  Copyright (C) 2010-2018 Fox Crypto B.V. <openvpn@fox-it.com>
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
 * @file Network protocol overview documentation file.
 */

/**
 * @page network_protocol OpenVPN's network protocol
 *
 * Description of packet structure in OpenVPN's network protocol.
 *
 * This document describes the structure of packets exchanged between
 * OpenVPN peers.  It is based on the protocol description in the \c ssl.h
 * file.
 *
 * @section network_protocol_external Outer structure of packets exchanged between OpenVPN peers
 *
 * VPN tunnel packets are transported between OpenVPN peers using the UDP
 * or TCP protocols.  Their structure is described below.
 *
 * @subsection network_protocol_external_structure External packet structure
 *
 *  - packet length (16 bits, unsigned) [TCP-mode only]: always sent as
 *    plain text.  Since TCP is a stream protocol, this packet length
 *    defines the packetization of the stream.
 *  - packet opcode and key_id (8 bits) [TLS-mode only]:
 *     - package message type (high 5 bits)
 *     - key_id (low 3 bits): the key_id refers to an already negotiated
 *       TLS session.  OpenVPN seamlessly renegotiates the TLS session by
 *       using a new key_id for the new session.  Overlap (controlled by
 *       user definable parameters) between old and new TLS sessions is
 *       allowed, providing a seamless transition during tunnel operation.
 *  - payload (n bytes)
 *
 * @subsection network_protocol_external_types Message types
 *
 * The type of a VPN tunnel packet is indicated by its opcode.  The
 * following describes the various opcodes available.
 *
 *  - Control channel messages:
 *     - \ref P_CONTROL_HARD_RESET_CLIENT_V1 -- %Key method 1, initial %key
 *       from client, forget previous state.
 *     - \ref P_CONTROL_HARD_RESET_SERVER_V1 -- %Key method 1, initial %key
 *       from server, forget previous state.
 *     - \ref P_CONTROL_HARD_RESET_CLIENT_V2 -- %Key method 2, initial %key
 *       from client, forget previous state.
 *     - \ref P_CONTROL_HARD_RESET_SERVER_V2 -- %Key method 2, initial %key
 *       from server, forget previous state.
 *     - \ref P_CONTROL_SOFT_RESET_V1 -- New %key, with a graceful
 *       transition from old to new %key in the sense that a transition
 *       window exists where both the old or new key_id can be used.
 *     - \ref P_CONTROL_V1 -- Control channel packet (usually TLS
 *       ciphertext).
 *     - \ref P_ACK_V1 -- Acknowledgement for control channel packets
 *       received.
 *  - Data channel messages:
 *     - \ref P_DATA_V1 -- Data channel packet containing data channel
 *       ciphertext.
 *     - \ref P_DATA_V2 -- Data channel packet containing peer-id and data
 *       channel ciphertext.
 *
 * @subsection network_protocol_external_key_id Session IDs and Key IDs
 *
 * OpenVPN uses two different forms of packet identifiers:
 *  - The first form is 64 bits and is used for all control channel
 *    messages.  This form is referred to as a \c session_id.
 *  - Data channel messages on the other hand use a shortened form of 3
 *    bits for efficiency reasons since the vast majority of OpenVPN
 *    packets in an active tunnel will be data channel messages.  This
 *    form is referred to as a \c key_id.
 *
 * The control and data channels use independent packet-id sequences,
 * because the data channel is an unreliable channel while the control
 * channel is a %reliable channel.  Each use their own independent HMAC
 * keys.
 *
 * @subsection network_protocol_external_reliable Control channel reliability layer
 *
 * Control channel messages (\c P_CONTROL_* and \c P_ACK_* message types)
 * are TLS ciphertext packets which have been encapsulated inside of a
 * reliability layer.  The reliability layer is implemented as a
 * straightforward acknowledge and retransmit model.
 *
 * Acknowledgments of received messages can be encoded in either the
 * dedicated \c P_ACK_* record or they can be prepended to a \c
 * P_CONTROL_* message.
 *
 * See the \link reliable Reliability Layer\endlink module for a detailed
 * description.
 *
 * @section network_protocol_control Structure of control channel messages
 *
 * @subsection network_protocol_control_ciphertext Structure of ciphertext control channel messages
 *
 * Control channel packets in ciphertext form consist of the following
 * parts:
 *
 *  - local \c session_id (random 64 bit value to identify TLS session).
 *  - HMAC signature of entire encapsulation header for HMAC firewall
 *    [only if \c --tls-auth is specified] (usually 16 or 20 bytes).
 *  - packet-id for replay protection (4 or 8 bytes, includes sequence
 *    number and optional \c time_t timestamp).
 *  - acknowledgment packet-id array length (1 byte).
 *  - acknowledgment packet-id array (if length > 0).
 *  - acknowledgment remote session-id (if length > 0).
 *  - packet-id of this message (4 bytes).
 *  - TLS payload ciphertext (n bytes) (only for \c P_CONTROL_V1).
 *
 * Note that when \c --tls-auth is used, all message types are protected
 * with an HMAC signature, even the initial packets of the TLS handshake.
 * This makes it easy for OpenVPN to throw away bogus packets quickly,
 * without wasting resources on attempting a TLS handshake which will
 * ultimately fail.
 *
 * @subsection network_protocol_control_key_methods Control channel key methods
 *
 * Once the TLS session has been initialized and authenticated, the TLS
 * channel is used to exchange random %key material for bidirectional
 * cipher and HMAC keys which will be used to secure data channel packets.
 * OpenVPN currently implements two %key methods.  %Key method 1 directly
 * derives keys using random bits obtained from the \c rand_bytes() function.
 * %Key method 2 mixes random %key material from both sides of the connection
 * using the TLS PRF mixing function.  %Key method 2 is the preferred method and
 * is the default for OpenVPN 2.0+.
 *
 * The @ref key_generation "Data channel key generation" related page
 * describes the %key methods in more detail.
 *
 * @subsection network_protocol_control_plaintext Structure of plaintext control channel messages
 *
 *  - %Key method 1 (support removed in OpenVPN 2.5):
 *     - Cipher %key length in bytes (1 byte).
 *     - Cipher %key (n bytes).
 *     - HMAC %key length in bytes (1 byte).
 *     - HMAC %key (n bytes).
 *     - %Options string (n bytes, null terminated, client/server %options
 *       string should match).
 *  - %Key method 2:
 *     - Literal 0 (4 bytes).
 *     - %Key method (1 byte).
 *     - \c key_source structure (\c key_source.pre_master only defined
 *       for client -> server).
 *     - %Options string length, including null (2 bytes).
 *     - %Options string (n bytes, null terminated, client/server %options
 *       string must match).
 *     - [The username/password data below is optional, record can end at
 *       this point.]
 *     - Username string length, including null (2 bytes).
 *     - Username string (n bytes, null terminated).
 *     - Password string length, including null (2 bytes).
 *     - Password string (n bytes, null terminated).
 *
 * @section network_protocol_data Structure of data channel messages
 *
 * The P_DATA_* payload represents encapsulated tunnel packets which tend to be
 * either IP packets or Ethernet frames. This is essentially the "payload" of
 * the VPN. Data channel packets consist of a data channel header, and a
 * payload. There are two possible formats:
 *
 * @par P_DATA_V1
 * P_DATA_V1 packets have a 1-byte header, carrying the \ref P_DATA_V1 \c opcode
 * and \c key_id, followed by the payload:\n
 * <tt> [ 5-bit opcode | 3-bit key_id ] [ payload ] </tt>
 *
 * @par P_DATA_V2
 * P_DATA_V2 packets have the same 1-byte opcode/key_id, but carrying the \ref
 * P_DATA_V2 opcode, followed by a 3-byte peer-id, which uniquely identifies
 * the peer:\n
 * <tt> [ 5-bit opcode | 3-bit key_id ] [ 24-bit peer-id ] [ payload ] </tt>
 *
 * See @ref data_crypto for details on the data channel payload format.
 *
 */
