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
 * Internal Multiplexer module documentation file.
 */

/**
 * @addtogroup internal_multiplexer Internal Multiplexer module
 *
 * The Internal Multiplexer is the link between the virtual tun/tap
 * network interface and the \link data_control Data Channel Control
 * module\endlink.  It reads packets from the virtual network interface,
 * determines for which remote OpenVPN peer they are destined, and then
 * passes the packets on to the Data Channel Control module together with
 * information about their destination VPN tunnel instance.
 *
 * This module also handles packets traveling in the reverse direction,
 * which have already been processed by the Data Channel Control module
 * and are destined for a locally reachable host.
 */
