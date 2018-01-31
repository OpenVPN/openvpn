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
 * @file Data Channel Compression module documentation file.
 */

/**
 * @defgroup compression Data Channel Compression module
 *
 * This module offers compression of data channel packets.
 *
 * @par State structures
 * The Data Channel Compression module stores its internal state in a \c
 * lzo_compress_workspace structure.  This state includes flags which
 * control the module's behavior and preallocated working memory.  One
 * such structure is present for each VPN tunnel, and is stored in the \c
 * context.c2.lzo_compwork of the \c context associated with that VPN
 * tunnel.
 *
 * @par Initialization and cleanup
 * Every time a new \c lzo_compress_workspace is needed, it must be
 * initialized using the \c lzo_compress_init() function.  Similarly,
 * every time a \c lzo_compress_workspace is no longer needed, it must be
 * cleaned up using the \c lzo_compress_uninit() function.  These
 * functions take care of the allocation and freeing of internal working
 * memory, but not of the \c lzo_compress_workspace structures themselves.
 *
 * @par
 * Because of the one-to-one relationship between \c
 * lzo_compress_workspace structures and VPN tunnels, the above-mentioned
 * initialization and cleanup functions are called directly from the \c
 * init_instance() and \c close_instance() functions, which control the
 * initialization and cleanup of VPN tunnel instances and their associated
 * \c context structures.
 *
 * @par Packet processing functions
 * This module receives data channel packets from the \link data_control
 * Data Channel Control module\endlink and processes them according to the
 * settings of the packet's VPN tunnel.  The \link data_control Data
 * Channel Control module\endlink uses the following interface functions:
 * - For packets which will be sent to a remote OpenVPN peer: \c
 *   lzo_compress()
 * - For packets which have been received from a remote OpenVPN peer: \c
 *   lzo_decompress()
 *
 * @par Settings that control this module's activity
 * Whether or not the Data Channel Compression module is active depends on
 * the compile-time \c ENABLE_LZO preprocessor macro and the runtime flags
 * stored in \c lzo_compress_workspace.flags of the associated VPN tunnel.
 * The latter are initialized from \c options.lzo, which gets its value
 * from the process's configuration sources, such as its configuration
 * file or command line %options.
 *
 * @par Adaptive compression
 * The compression module supports adaptive compression.  If this feature
 * is enabled, the compression routines monitor their own performance and
 * turn compression on or off depending on whether it is leading to
 * significantly reduced payload size.
 *
 * @par Compression algorithms
 * This module uses the Lempel-Ziv-Oberhumer (LZO) compression algorithms.
 * These offer lossless compression and are designed for high-performance
 * decompression.  This module uses the external \c lzo library's
 * implementation of the algorithms.
 *
 * @par
 * For more information on the LZO library, see:\n
 * http://www.oberhumer.com/opensource/lzo/
 */
