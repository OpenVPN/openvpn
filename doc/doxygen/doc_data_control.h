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
 * @file
 * Data Channel Control module documentation file.
 */

/**
 * @defgroup data_control Data Channel Control module
 *
 * This module controls the processing of packets as they pass through the
 * data channel.
 *
 * The Data Channel Control module controls the processing of packets as
 * they pass through the data channel.  The processing includes packet
 * compression, fragmentation, and the performing of security operations
 * on the packets.  This module does not do the processing itself, but
 * passes the packet to other data channel modules to perform the
 * appropriate actions.
 *
 * Packets can travel in two directions through the data channel.  They
 * can be going to a remote destination which is reachable through a VPN
 * tunnel, in which case this module prepares them to be sent out through
 * a VPN tunnel.  On the other hand, they can have been received through a
 * VPN tunnel from a remote OpenVPN peer, in which case this module
 * retrieves the packet in its original form as it was before entering the
 * VPN tunnel on the remote OpenVPN peer.  How this module processes
 * packets traveling in the two directions is discussed in more detail
 * below.
 *
 * @par Packets to be sent to a remote OpenVPN peer
 * This module's main function for processing packets traveling in this
 * direction is \c encrypt_sign(), which performs the following processing
 * steps:
 * - Call the \link compression Data Channel Compression module\endlink to
 *   perform packet compression if necessary.
 * - Call the \link fragmentation Data Channel Fragmentation
 *   module\endlink to perform packet fragmentation if necessary.
 * - Call the \link data_crypto Data Channel Crypto module\endlink to
 *   perform the required security operations.
 *
 * @par
 * See the \c encrypt_sign() documentation for details of these
 * interactions.
 *
 * @par
 * After the above processing is complete, the packet is ready to be sent
 * to a remote OpenVPN peer as a VPN tunnel packet.  The actual sending of
 * the packet is handled by the \link external_multiplexer External
 * Multiplexer\endlink.
 *
 * @par Packets received from a remote OpenVPN peer
 * The function that controls how packets traveling in this direction are
 * processed is \c process_incoming_link().  That function, however, also
 * performs some of the tasks required for the \link external_multiplexer
 * External Multiplexer\endlink and is therefore listed as part of that
 * module, instead of here.
 *
 * @par
 * After the \c process_incoming_link() function has determined that a
 * received packet is a data channel packet, it performs the following
 * processing steps:
 * - Call the \link data_crypto Data Channel Crypto module\endlink to
 *   perform the required security operations.
 * - Call the \link fragmentation Data Channel Fragmentation
 *   module\endlink to perform packet reassembly if necessary.
 * - Call the \link compression Data Channel Compression module\endlink to
 *   perform packet decompression if necessary.
 *
 * @par
 * See the \c process_incoming_link() documentation for details of these
 * interactions.
 *
 * @par
 * After the above processing is complete, the packet is in its original
 * form again as it was received by the remote OpenVPN peer.  It can now
 * be routed further to its final destination.  If that destination is a
 * locally reachable host, then the \link internal_multiplexer Internal
 * Multiplexer\endlink will send it there.
 */
