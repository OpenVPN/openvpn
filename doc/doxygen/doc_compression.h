/*
 *  OpenVPN -- An application to securely tunnel IP networks
 *             over a single TCP/UDP port, with support for SSL/TLS-based
 *             session authentication and key exchange,
 *             packet encryption, packet authentication, and
 *             packet compression.
 *
 *  Copyright (C) 2010-2026 Sentyron B.V. <openvpn@sentyron.com>
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
 * Data Channel Compression module documentation file.
 */

/**
 * @defgroup compression Data Channel Compression module
 *
 * This module decompresses incoming data channel packets and adds
 * compression framing to outgoing ones.
 *
 * @par State structures
 * The Data Channel Compression module stores its internal state in a \c
 * compress_context structure.  One such structure is present for each VPN
 * tunnel, and is stored in the \c context.c2.comp_context of the \c
 * context associated with that VPN tunnel.
 *
 * @par Initialization and cleanup
 * \c comp_init() allocates a \c compress_context and calls the \c
 * compress_init method of its \c compress_alg; \c comp_uninit() calls
 * the \c compress_uninit method and frees the structure.  Both are called
 * from \c init_instance() and \c close_instance(), and when pushed
 * options change.
 *
 * @par Packet processing functions
 * This module receives data channel packets from the \link data_control
 * Data Channel Control module\endlink and processes them according to the
 * settings of the packet's VPN tunnel.  The \link data_control Data
 * Channel Control module\endlink uses the following interface functions:
 * - For packets which will be sent to a remote OpenVPN peer: the \c
 *   compress method of \c compress_alg
 * - For packets which have been received from a remote OpenVPN peer: the
 *   \c decompress method of \c compress_alg
 *
 * @par Settings that control this module's activity
 * Whether or not the Data Channel Compression module is active depends on
 * the compile-time \c USE_COMP preprocessor macro and on \c
 * options.comp.alg, which gets its value from the process's configuration
 * sources, such as its configuration file or command line %options.
 * \c comp_init() creates no \c compress_context if no algorithm is set.
 * The flags in \c compress_context.flags, copied from \c
 * options.comp.flags, only adjust framing, option checks and which
 * algorithms are advertised to the peer.
 *
 * @par Outgoing packets
 * Outgoing packets are never compressed, only framed so that the peer
 * can parse them.
 *
 * @par Compression algorithms
 * This module supports the Lempel-Ziv-Oberhumer (LZO) and LZ4
 * algorithms, as implemented by the external \c lzo and \c lz4
 * libraries.
 *
 * @par
 * For more information on these libraries, see:\n
 * https://www.oberhumer.com/opensource/lzo/ \n
 * https://lz4.org/
 */
