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
 *  with this program; if not, see <https://www.gnu.org/licenses/>.
 */

/**
 * @file
 * Reliability Layer module documentation file.
 */

/**
 * @defgroup reliable Reliability Layer module
 *
 * The Reliability Layer is part of OpenVPN's control channel.  It
 * provides a reliable and sequential transport mechanism for control
 * channel messages between OpenVPN peers.  This module forms the
 * interface between the \link external_multiplexer External
 * Multiplexer\endlink and the \link control_tls Control Channel TLS
 * module\endlink.
 *
 * @par UDP or TCP as VPN tunnel transport
 *
 * This is especially important when OpenVPN is configured to communicate
 * over UDP, because UDP does not offer a reliable and sequential
 * transport.  OpenVPN endpoints can also communicate over TCP which does
 * provide a reliable and sequential transport.  In both cases, using UDP
 * or TCP as an external transport, the internal Reliability Layer is
 * active.
 */
