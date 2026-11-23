/*
 *  OpenVPN -- An application to securely tunnel IP networks
 *             over a single UDP port, with support for SSL/TLS-based
 *             session authentication and key exchange,
 *             packet encryption, packet authentication, and
 *             packet compression.
 *
 *  Copyright (C) 2002-2026 OpenVPN Inc <sales@openvpn.net>
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
#if defined(HAVE_LZO_LZO1X_H)
#include <lzo/lzo1x.h>
#elif defined(HAVE_LZO1X_H)
/* The lzo.h magic gets confused and still wants
 * to include lzo/lzoconf.h even if our include paths
 * are setup to include the paths without lzo/
 */
#include <lzodefs.h>
#include <lzoconf.h>
#include <lzo1x.h>
#endif

#include "buffer.h"
#include "mtu.h"
#include "common.h"
#include "status.h"

extern const struct compress_alg lzo_alg;

/**************************************************************************/
/** @name LZO library interface defines */ /** @{ */ /***********************/
#define LZO_DECOMPRESS lzo1x_decompress_safe
/**< LZO library decompression function.
 *
 *   Use safe decompress because it
 *   includes checks for possible %buffer
 *   overflows. If speed is essential and
 *   you will always be using a MAC to
 *   verify the integrity of incoming
 *   packets, you might want to consider
 *   using the non-safe version. */
/** @} name LZO library interface */ /**************************************/

/** @} addtogroup compression */


#endif /* ENABLE_LZO && USE_COMP */
#endif /* ifndef OPENVPN_LZO_H */
