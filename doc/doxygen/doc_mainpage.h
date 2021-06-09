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
 * Main page documentation file.
 */

/**
 * @mainpage OpenVPN source code documentation
 *
 * This documentation describes the internal structure of OpenVPN.  It was
 * automatically generated from specially formatted comment blocks in
 * OpenVPN's source code using Doxygen.  (See
 * http://www.stack.nl/~dimitri/doxygen/ for more information on Doxygen)
 *
 * The \ref mainpage_modules "Modules section" below gives an introduction
 * into the high-level module concepts used throughout this documentation.
 * The \ref mainpage_relatedpages "Related Pages section" below describes
 * various special subjects related to OpenVPN's implementation which are
 * discussed in the related pages section.
 *
 * @section mainpage_modules Modules
 *
 * For the purpose of describing the internal structure of OpenVPN, this
 * documentation and the underlying source code has been broken up into a
 * number of conceptually well-defined parts, known as modules. Each
 * module plays a specific role within the OpenVPN process, and in most
 * cases each module has a clear interfacing strategy for interacting with
 * other modules.
 *
 * The following modules have been defined:
 * - Driver module:
 *   - The \link eventloop Main Event Loop\endlink: this module drives the
 *     event handling of OpenVPN.  It implements various types of
 *     select-loop which wait until an event happens, and then delegate
 *     the handling of that event to the appropriate module.
 * - Network interface modules:
 *   - The \link external_multiplexer External Multiplexer\endlink: this
 *     module sends and receives packets to and from remote OpenVPN peers
 *     over the external network interface.  It also takes care of
 *     demultiplexing received packets to their appropriate VPN tunnel and
 *     splitting control channel and data channel packets.
 *   - The \link internal_multiplexer Internal Multiplexer\endlink: this
 *     module sends and receives packets to and from locally reachable
 *     posts over the virtual tun/tap network interface.  It also takes
 *     care of determining through which VPN tunnel a received packet must
 *     be sent to reach its destination.
 * - Control channel modules:
 *   - The \link reliable Reliability Layer\endlink: this module offers a
 *     %reliable and sequential transport layer for control channel
 *     messages.
 *   - The \link control_tls Control Channel TLS module\endlink: this
 *     module offers a secure encapsulation of control channel messages
 *     using the TLS protocol.
 *   - The \link control_processor Control Channel Processor\endlink: his
 *     module manages the setup, maintenance, and shut down of VPN
 *     tunnels.
 * - Data channel modules:
 *   - The \link data_control Data Channel Control module\endlink: this
 *     module controls the processing of data channel packets and,
 *     depending on the settings of the packet's VPN tunnel, passes the
 *     packet to the three modules below for handling.
 *   - The \link data_crypto Data Channel Crypto module\endlink: this
 *     module performs security operations on data channel packets.
 *   - The \link fragmentation Data Channel Fragmentation module\endlink:
 *     this module offers fragmentation of data channel packets larger
 *     than the VPN tunnel's MTU.
 *   - The \link compression Data Channel Compression module\endlink: this
 *     module offers compression of data channel packets.
 *
 * @subsection mainpage_modules_example Example event: receiving a packet
 *
 * OpenVPN handles many types of events during operation.  These include
 * external events, such as network traffic being received, and internal
 * events, such as a %key session timing out causing renegotiation.  An
 * example event, receiving a packet over the network, is described here
 * together with which modules play what roles:
 * -# The \link eventloop Main Event Loop\endlink detects that a packet
 *    can be read from the external or the virtual tun/tap network
 *    interface.
 * -# The \link eventloop Main Event Loop\endlink calls the \link
 *    external_multiplexer External Multiplexer\endlink or \link
 *    internal_multiplexer Internal Multiplexer\endlink to read and
 *    process the packet.
 * -# The multiplexer module determines the type of packet and its
 *    destination, and passes the packet on to the appropriate handling
 *    module:
 *    - A control channel packet received by the \link
 *      external_multiplexer External Multiplexer\endlink is passed on
 *      through the \link reliable Reliability Layer\endlink and the \link
 *      control_tls Control Channel TLS module\endlink to the \link
 *      control_processor Control Channel Processor\endlink.
 *    - A data channel packet received by either multiplexer module is
 *      passed on to the \link data_control Data Channel Control
 *      module\endlink.
 * -# The packet is processed by the appropriate control channel or data
 *    channel modules.
 * -# If, after processing the packet, a resulting packet is generated
 *    that needs to be sent to a local or remote destination, it is given
 *    to the \link external_multiplexer External Multiplexer\endlink or
 *    \link internal_multiplexer Internal Multiplexer\endlink for sending.
 * -# If a packet is waiting to be sent by either multiplexer module and
 *    the \link eventloop Main Event Loop\endlink detects that data can be
 *    written to the associated network interface, it calls the
 *    multiplexer module to send the packet.
 *
 * @section mainpage_relatedpages Related pages
 *
 * This documentation includes a number of descriptions of various aspects
 * of OpenVPN and its implementation.  These are not directly related to
 * one module, function, or data structure, and are therefore listed
 * separately under "Related Pages".
 *
 * @subsection mainpage_relatedpages_key_generation Data channel key generation
 *
 * The @ref key_generation "Data channel key generation" related page
 * describes how, during VPN tunnel setup and renegotiation, OpenVPN peers
 * generate and exchange the %key material required for the symmetric
 * encryption/decryption and HMAC signing/verifying security operations
 * performed on data channel packets.
 *
 * @subsection mainpage_relatedpages_tunnel_state VPN tunnel state
 *
 * The @ref tunnel_state "Structure of VPN tunnel state storage" related
 * page describes how an OpenVPN process manages the state information
 * associated with its active VPN tunnels.
 *
 * @subsection mainpage_relatedpages_network_protocol Network protocol
 *
 * The @ref network_protocol "Network protocol" related page describes the
 * format and content of VPN tunnel packets exchanged between OpenVPN
 * peers.
 *
 * @subsection mainpage_relatedpages_memory_management Memory management
 *
 * The @ref memory_management "Memory management strategies" related page
 * gives a brief introduction into OpenVPN's memory %buffer library and
 * garbage collection facilities.
 */
