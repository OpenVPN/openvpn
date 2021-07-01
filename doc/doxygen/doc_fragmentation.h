/*
 *  OpenVPN -- An application to securely tunnel IP networks
 *             over a single TCP/UDP port, with support for SSL/TLS-based
 *             session authentication and key exchange,
 *             packet encryption, packet authentication, and
 *             packet compression.
 *
 *  Copyright (C) 2010-2021 Fox Crypto B.V. <openvpn@foxcrypto.com>
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
 * Data Channel Fragmentation module documentation file.
 */

/**
 * @defgroup fragmentation Data Channel Fragmentation module
 *
 * The Data Channel Fragmentation module offers fragmentation of data
 * channel packets.
 *
 * @par State structures
 * The Data Channel Fragmentation module stores its internal state in a \c
 * fragment_master structure.  One such structure is present for each VPN
 * tunnel, and is stored in \c context.c2.fragment of the \c context
 * associated with that VPN tunnel.
 *
 * @par
 * The \c fragment_master structure contains one \c fragment_list
 * structure \c fragment_master.incoming.  This is a list of \c fragment
 * structures, each of which can store the parts of one fragmented packet
 * while it is being reassembled.  The \c fragment_master structure also
 * contains one \c buffer called \c fragment_master.outgoing, in which a
 * data channel large packet to be sent to a remote OpenVPN peer can be
 * broken up into parts to be sent one by one.
 *
 * @par Initialization and cleanup
 * Every time a new \c fragment_master is needed, it must be allocated and
 * initialized by the \c fragment_init() function.  Similarly, every time
 * a \c fragment_master is no longer needed, it must be cleaned up using
 * the \c fragment_free() function.  These functions take care of the
 * allocation and freeing of the \c fragment_master structure itself and
 * all internal memory required for the use of that structure.  Note that
 * this behavior is different from that displayed by the \link compression
 * Data Channel Compression module\endlink.
 *
 * @par
 * Because of the one-to-one relationship between \c fragment_master
 * structures and VPN tunnels, the above-mentioned initialization and
 * cleanup functions are called directly from the \c init_instance() and
 * \c close_instance() functions, which control the initialization and
 * cleanup of VPN tunnel instances and their associated \c context
 * structures.
 *
 * @par Packet processing functions
 * This module receives data channel packets from the \link data_control
 * Data Channel Control module\endlink and processes them according to the
 * settings of the packet's VPN tunnel.  The \link data_control Data
 * Channel Control module\endlink uses the following interface functions:
 * - For packets which will be sent to a remote OpenVPN peer: \c
 *   fragment_outgoing() \n This function inspects data channel packets as
 *   they are being made ready to be sent as VPN tunnel packets to a
 *   remote OpenVPN peer.  If a packet's size is larger than its
 *   destination VPN tunnel's maximum transmission unit (MTU), then this
 *   module breaks that packet up into smaller parts, each of which is
 *   smaller than or equal to the VPN tunnel's MTU.  See \c
 *   fragment_outgoing() for details.
 * - For packets which have been received from a remote OpenVPN peer: \c
 *   fragment_incoming() \n This function inspects data channel packets
 *   that have been received from a remote OpenVPN peer through a VPN
 *   tunnel.  It reads the fragmentation header of the packet, and
 *   depending on its value performs the appropriate action.  See \c
 *   fragment_incoming() for details.
 *
 * @par Settings that control this module's activity
 * Whether the Data Channel Fragmentation module is active or not depends
 * on the compile-time \c ENABLE_FRAGMENT preprocessor macro and the
 * runtime flag \c options.fragment, which gets its value from the
 * process's configuration sources, such as the configuration file and
 * commandline %options.
 */
