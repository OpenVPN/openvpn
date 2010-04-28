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

#ifdef USE_LZO

#ifdef LZO_HEADER_DIR
#include "lzo/lzoutil.h"
#include "lzo/lzo1x.h"
#else
#include "lzoutil.h"
#include "lzo1x.h"
#endif

#include "buffer.h"
#include "mtu.h"
#include "common.h"
#include "status.h"

/* LZO flags */
#define LZO_SELECTED   (1<<0)
#define LZO_ON         (1<<1)
#define LZO_ADAPTIVE   (1<<2)  

/*
 * Use LZO compress routine lzo1x_1_15_compress which is described
 * as faster but needs a bit more memory than the standard routine.
 * Use safe decompress (i.e. check for buffer overflows).
 * You may want to use the non-safe version
 * of decompress if speed is essential and if you know
 * that you will always be using a MAC to verify the
 * integrity of incoming packets.
 */
#define LZO_COMPRESS    lzo1x_1_15_compress
#define LZO_WORKSPACE	LZO1X_1_15_MEM_COMPRESS
#define LZO_DECOMPRESS  lzo1x_decompress_safe

#define LZO_EXTRA_BUFFER(len) ((len)/8 + 128 + 3)	/* LZO 2.0 worst case size expansion. */

/*
 * Don't try to compress any packet smaller than this.
 */
#define COMPRESS_THRESHOLD 100

/*
 * Length of prepended prefix on LZO packets
 */ 
#define LZO_PREFIX_LEN 1

/*
 * Adaptive compress parameters
 */
#define AC_SAMP_SEC    2      /* number of seconds in sample period */
#define AC_MIN_BYTES   1000   /* sample period must have at least n bytes
				 to be valid for testing */
#define AC_SAVE_PCT    5      /* turn off compress if we didn't save at
				 least this % during sample period */
#define AC_OFF_SEC     60     /* if we turn off compression, don't do sample
				 retest for n seconds */

struct lzo_adaptive_compress {
  bool compress_state;
  time_t next;
  int n_total;
  int n_comp;
};

/*
 * Compress and Uncompress routines.
 */

struct lzo_compress_workspace
{
  lzo_voidp wmem;
  int wmem_size;
  struct lzo_adaptive_compress ac;
  unsigned int flags;
  bool defined;

  /* statistics */
  counter_type pre_decompress;
  counter_type post_decompress;
  counter_type pre_compress;
  counter_type post_compress;
};

void lzo_adjust_frame_parameters(struct frame *frame);

void lzo_compress_init (struct lzo_compress_workspace *lzowork, unsigned int flags);

void lzo_compress_uninit (struct lzo_compress_workspace *lzowork);

void lzo_modify_flags (struct lzo_compress_workspace *lzowork, unsigned int flags);

void lzo_compress (struct buffer *buf, struct buffer work,
		   struct lzo_compress_workspace *lzowork,
		   const struct frame* frame);

void lzo_decompress (struct buffer *buf, struct buffer work,
		     struct lzo_compress_workspace *lzowork,
		     const struct frame* frame);

void lzo_print_stats (const struct lzo_compress_workspace *lzo_compwork, struct status_output *so);

static inline bool
lzo_defined (const struct lzo_compress_workspace *lzowork)
{
  return lzowork->defined;
}


#endif /* USE_LZO */
#endif
