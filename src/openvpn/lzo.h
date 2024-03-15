/*
 *  OpenVPN -- An application to securely tunnel IP networks
 *             over a single UDP port, with support for SSL/TLS-based
 *             session authentication and key exchange,
 *             packet encryption, packet authentication, and
 *             packet compression.
 *
 *  Copyright (C) 2002-2024 OpenVPN Inc <sales@openvpn.net>
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

#ifndef OPENVPN_LZO_H
#define OPENVPN_LZO_H


/**
 * @file
 * Data Channel Compression module header file.
 */


#if defined(ENABLE_LZO)

/**
 * @addtogroup compression
 * @{
 */
#if defined(HAVE_LZO_CONF_H)
/* The lzo.h magic gets confused and still wants
 * to include lzo/lzoconf.h even if our include paths
 * are setup to include the paths without lzo/ include lzoconf.h to
 * avoid it being include by lzoutil.h */
#include <lzodefs.h>
#include <lzoconf.h>
#endif
#if defined(HAVE_LZO_LZOUTIL_H)
#include <lzo/lzoutil.h>
#elif defined(HAVE_LZOUTIL_H)
#include <lzoutil.h>
#endif
#if defined(HAVE_LZO_LZO1X_H)
#include <lzo/lzo1x.h>
#elif defined(HAVE_LZO1X_H)
#include <lzo1x.h>
#endif

#include "buffer.h"
#include "mtu.h"
#include "common.h"
#include "status.h"

extern const struct compress_alg lzo_alg;

/**************************************************************************/
/** @name LZO library interface defines *//** @{ *//***********************/
#define LZO_COMPRESS    lzo1x_1_15_compress
/**< LZO library compression function.
 *
 *   Use \c lzo1x_1_15_compress because it
 *   is described as faster than the
 *   standard routine, although it does
 *   need a bit more memory. */
#define LZO_WORKSPACE   LZO1X_1_15_MEM_COMPRESS
/**< The size in bytes of the memory
 *   %buffer required by the LZO library
 *   compression algorithm. */
#define LZO_DECOMPRESS  lzo1x_decompress_safe
/**< LZO library decompression function.
 *
 *   Use safe decompress because it
 *   includes checks for possible %buffer
 *   overflows. If speed is essential and
 *   you will always be using a MAC to
 *   verify the integrity of incoming
 *   packets, you might want to consider
 *   using the non-safe version. */
/** @} name LZO library interface *//**************************************/


/**************************************************************************/
/** @name Adaptive compression defines *//** @{ *//************************/
#define AC_SAMP_SEC    2        /**< Number of seconds in a sample period. */
#define AC_MIN_BYTES   1000     /**< Minimum number of bytes a sample
                                 *   period must contain for it to be
                                 *   evaluated. */
#define AC_SAVE_PCT    5        /**< Minimum size reduction percentage
                                 *   below which compression will be
                                 *   turned off. */
#define AC_OFF_SEC     60       /**< Seconds to wait after compression has
                                 *   been turned off before retesting. */
/** @} name Adaptive compression defines *//*******************************/

/**
 * Adaptive compression state.
 */
struct lzo_adaptive_compress {
    bool compress_state;
    time_t next;
    int n_total;
    int n_comp;
};


/**
 * State for the compression and decompression routines.
 *
 * This structure contains compression module state, such as whether
 * compression is enabled and the status of the adaptive compression
 * routines.  It also contains an allocated working buffer.
 *
 * One of these compression workspace structures is maintained for each
 * VPN tunnel.
 */
struct lzo_compress_workspace
{
    lzo_voidp wmem;
    int wmem_size;
    struct lzo_adaptive_compress ac;
};

/** @} addtogroup compression */


#endif /* ENABLE_LZO && USE_COMP */
#endif /* ifndef OPENVPN_LZO_H */
