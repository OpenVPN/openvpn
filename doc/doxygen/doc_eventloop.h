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
 * Main Event Loop module documentation file.
 */

/**
 * @defgroup eventloop Main Event Loop module
 *
 * This main event loop module drives the packet processing of OpenVPN.
 *
 * OpenVPN is an event driven system.  Its activities are driven by a main
 * event loop, which repeatedly waits for one of several predefined events
 * to occur, and then calls the appropriate module to handle the event.
 * The major types of network events that OpenVPN processes are:
 * - A packet can be read from the external network interface.
 *   - The main event loop activates the \link external_multiplexer
 *     External Multiplexer\endlink to read and process the packet.
 * - A packet can be read from the virtual tun/tap network interface.
 *   - The main event loop activates the \link internal_multiplexer
 *     Internal Multiplexer\endlink to read and process the packet.
 * - If a packet is ready to be sent out as a VPN tunnel packet: the
 *   external network interface can be written to.
 *   - The main event loop activates the \link external_multiplexer
 *     External Multiplexer\endlink to send the packet.
 * - If a packet is ready to be sent to a locally reachable destination:
 *   the virtual tun/tap network interface can be written to.
 *   - The main event loop activates the \link internal_multiplexer
 *     Internal Multiplexer\endlink to send the packet.
 *
 * Beside these external events, OpenVPN also processes other types of
 * internal events.  These include scheduled events, such as resending of
 * non-acknowledged control channel messages.
 *
 * @par Main event loop implementations
 *
 * Depending on the mode in which OpenVPN is running, a different main
 * event loop function is called to drive the event processing.  The
 * following implementations are available:
 * - Client mode using UDP or TCP: \c tunnel_point_to_point()
 * - Server mode using UDP: \c tunnel_server_udp_single_threaded()
 * - Server mode using TCP: \c tunnel_server_tcp()
 */
