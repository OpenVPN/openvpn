/*
 *  OpenVPN -- An application to securely tunnel IP networks
 *             over a single UDP port, with support for SSL/TLS-based
 *             session authentication and key exchange,
 *             packet encryption, packet authentication, and
 *             packet compression.
 *
 *  Copyright (C) 2002-2010 OpenVPN Technologies, Inc. <sales@openvpn.net>
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
 *  You should have received a copy of the GNU General Public License
 *  along with this program (see the file COPYING included with this
 *  distribution); if not, write to the Free Software Foundation, Inc.,
 *  59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

#ifndef OPENVPN_LZO_H
#define OPENVPN_LZO_H


/**
 * @file
 * Data Channel Compression module header file.
 */


#ifdef ENABLE_LZO

/**
 * @addtogroup compression
 * @{
 */

#ifndef ENABLE_LZO_STUB
#if defined(HAVE_LZO_LZOUTIL_H)
#include "lzo/lzoutil.h"
#elif defined(HAVE_LZOUTIL_H)
#include "lzoutil.h"
#endif
#if defined(HAVE_LZO_LZO1X_H)
#include "lzo/lzo1x.h"
#elif defined(HAVE_LZO1X_H)
#include "lzo1x.h"
#endif
#endif

#include "buffer.h"
#include "mtu.h"
#include "common.h"
#include "status.h"

/**************************************************************************/
/** @name Bit-flags which control data channel packet compression *//******/
/** @{ */
#define LZO_SELECTED   (1<<0)   /**< Bit-flag indicating that compression
                                 *   of data channel packets is enabled. */
#define LZO_ON         (1<<1)   /**< Bit-flag indicating that compression
                                 *   of data channel packets is active. */
#define LZO_ADAPTIVE   (1<<2)   /**< Bit-flag indicating that adaptive
                                 *   compression of data channel packets
                                 *   has been selected. */
/** @} name Bit-flags which control data channel packet compression *//****/

/**************************************************************************/
/** @name LZO library interface defines *//** @{ *//***********************/
#ifndef ENABLE_LZO_STUB
#define LZO_COMPRESS    lzo1x_1_15_compress
                                /**< LZO library compression function.
                                 *
                                 *   Use \c lzo1x_1_15_compress because it
                                 *   is described as faster than the
                                 *   standard routine, although it does
                                 *   need a bit more memory. */
#define LZO_WORKSPACE	LZO1X_1_15_MEM_COMPRESS
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
#endif /* ENABLE_LZO_STUB */
/** @} name LZO library interface *//**************************************/


/**************************************************************************/
/** @name Miscellaneous compression defines *//** @{ *//*******************/
#define LZO_EXTRA_BUFFER(len) ((len)/8 + 128 + 3)
                                /**< LZO 2.0 worst-case size expansion. */
#ifndef ENABLE_LZO_STUB
#define COMPRESS_THRESHOLD 100  /**< Minimum packet size to attempt
                                 *   compression. */
#endif /* ENABLE_LZO_STUB */
/** @} name Miscellaneous compression defines *//**************************/


/**************************************************************************/
/** @name Compression header defines *//** @{ *//**************************/
#define LZO_PREFIX_LEN 1        /**< Length in bytes of prepended
                                 *   compression header. */
#define YES_COMPRESS 0x66       /**< Single-byte compression header
                                 *   indicating this packet has been
                                 *   compressed. */
#define NO_COMPRESS  0xFA       /**< Single-byte compression header
                                 *   indicating this packet has not been
                                 *   compressed. */
/** @} name Compression header defines *//*********************************/

/**************************************************************************/
/** @name Adaptive compression defines *//** @{ *//************************/
#ifndef ENABLE_LZO_STUB
#define AC_SAMP_SEC    2        /**< Number of seconds in a sample period. */
#define AC_MIN_BYTES   1000     /**< Minimum number of bytes a sample
                                 *   period must contain for it to be
                                 *   evaluated. */
#define AC_SAVE_PCT    5        /**< Minimum size reduction percentage
                                 *   below which compression will be
                                 *   turned off. */
#define AC_OFF_SEC     60       /**< Seconds to wait after compression has
                                 *   been turned off before retesting. */
#endif /* ENABLE_LZO_STUB */
/** @} name Adaptive compression defines *//*******************************/

#ifndef ENABLE_LZO_STUB

/**
 * Adaptive compression state.
 */
struct lzo_adaptive_compress {
  bool compress_state;
  time_t next;
  int n_total;
  int n_comp;
};

#endif /* ENABLE_LZO_STUB */


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
  bool defined;
  unsigned int flags;
#ifndef ENABLE_LZO_STUB
  lzo_voidp wmem;
  int wmem_size;
  struct lzo_adaptive_compress ac;

  /* statistics */
  counter_type pre_decompress;
  counter_type post_decompress;
  counter_type pre_compress;
  counter_type post_compress;
#endif
};


/**************************************************************************/
/** @name Functions for initialization and cleanup *//** @{ *//************/

/**
 * Adjust %frame parameters for data channel payload compression.
 *
 * Data channel packet compression requires a single-byte header to
 * indicate whether a packet has been compressed or not. The packet
 * handling buffers must also allow for worst-case payload compression
 * where the compressed content size is actually larger than the original
 * content size. This function adjusts the parameters of a given frame
 * structure to include the header and allow for worst-case compression
 * expansion.
 *
 * @param frame        - The frame structure to adjust.
 */
void lzo_adjust_frame_parameters(struct frame *frame);

/**
 * Initialize a compression workspace structure.
 *
 * This function initializes the given workspace structure \a lzowork.
 * This includes allocating a work buffer for internal use and setting its
 * flags to the given value of \a flags.
 *
 * This function also initializes the lzo library.
 *
 * @param lzowork      - A pointer to the workspace structure to
 *                       initialize.
 * @param flags        - The initial flags to set in the workspace
 *                       structure.
 */
void lzo_compress_init (struct lzo_compress_workspace *lzowork, unsigned int flags);

/**
 * Cleanup a compression workspace structure.
 *
 * This function cleans up the given workspace structure \a lzowork.  This
 * includes freeing the structure's internal work buffer.
 *
 * @param lzowork      - A pointer to the workspace structure to clean up.
 */
void lzo_compress_uninit (struct lzo_compress_workspace *lzowork);

/**
 * Set a workspace structure's flags.
 *
 * @param lzowork      - The workspace structure of which to modify the
 *                       flags.
 * @param flags        - The new value to assign to the workspace
 *                       structure's flags.
 */
void lzo_modify_flags (struct lzo_compress_workspace *lzowork, unsigned int flags);

/** @} name Functions for initialization and cleanup *//*******************/


/**************************************************************************/
/** @name Function for packets to be sent to a remote OpenVPN peer *//*****/
/** @{ */

/**
 * Process an outgoing packet according to a VPN tunnel's settings.
 * @ingroup compression
 *
 * This function processes the packet contained in \a buf.  Its behavior
 * depends on the settings contained within \a lzowork.  If compression is
 * enabled and active, this function compresses the packet.  After
 * compression, the size of the uncompressed and compressed packets are
 * compared, and the smallest is used.
 *
 * This function prepends a one-byte header indicating whether the packet
 * was or was not compressed, so as to let the peer know how to handle the
 * packet.
 *
 * If an error occurs during processing, an error message is logged and
 * the length of \a buf is set to zero.
 *
 * @param buf          - A pointer to the buffer containing the outgoing
 *                       packet.  This pointer will be modified to point
 *                       to the processed packet on return.
 * @param work         - A preallocated working buffer.
 * @param lzowork      - The compression workspace structure associated
 *                       with this VPN tunnel.
 * @param frame        - The frame parameters of this tunnel.
 *
 * @return Void.\n  On return, \a buf will point to a buffer containing
 *     the processed, possibly compressed, packet data with a compression
 *     header prepended.
 */
void lzo_compress (struct buffer *buf, struct buffer work,
		   struct lzo_compress_workspace *lzowork,
		   const struct frame* frame);

/** @} name Function for packets to be sent to a remote OpenVPN peer *//***/


/**************************************************************************/
/** @name Function for packets received from a remote OpenVPN peer *//*****/
/** @{ */

/**
 * Inspect an incoming packet and decompress if it is compressed.
 *
 * This function inspects the incoming packet contained in \a buf.  If its
 * one-byte compression header indicates that it was compressed (i.e. \c
 * YES_COMPRESS), then it will be decompressed.  If its header indicates
 * that it was not compressed (i.e. \c NO_COMPRESS), then the buffer is
 * not modified except for removing the compression header.
 *
 * If an error occurs during processing, for example if the compression
 * header has a value other than \c YES_COMPRESS or \c NO_COMPRESS, then
 * the error is logged and the length of \a buf is set to zero.
 *
 * @param buf          - A pointer to the buffer containing the incoming
 *                       packet.  This pointer will be modified to point
 *                       to the processed packet on return.
 * @param work         - A preallocated working buffer.
 * @param lzowork      - The compression workspace structure associated
 *                       with this VPN tunnel.
 * @param frame        - The frame parameters of this tunnel.
 *
 * @return Void.\n  On return, \a buf will point to a buffer containing
 *     the uncompressed packet data and the one-byte compression header
 *     will have been removed.
 */
void lzo_decompress (struct buffer *buf, struct buffer work,
		     struct lzo_compress_workspace *lzowork,
		     const struct frame* frame);

/** @} name Function for packets received from a remote OpenVPN peer *//***/


/**************************************************************************/
/** @name Utility functions *//** @{ *//***********************************/

/**
 * Print statistics on compression and decompression performance.
 *
 * @param lzo_compwork - The workspace structure from which to get the
 *                       statistics.
 * @param so           - The status output structure to which to write the
 *                       statistics.
 */
void lzo_print_stats (const struct lzo_compress_workspace *lzo_compwork, struct status_output *so);

/**
 * Check whether compression is enabled for a workspace structure.
 *
 * @param lzowork      - The workspace structure to check.
 *
 * @return true if compression is enabled; false otherwise.
 */
static inline bool
lzo_defined (const struct lzo_compress_workspace *lzowork)
{
  return lzowork->defined;
}

/** @} name Utility functions *//******************************************/


/** @} addtogroup compression */


#endif /* ENABLE_LZO */
#endif
