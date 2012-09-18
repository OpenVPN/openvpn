/*
 *  OpenVPN -- An application to securely tunnel IP networks
 *             over a single UDP port, with support for SSL/TLS-based
 *             session authentication and key exchange,
 *             packet encryption, packet authentication, and
 *             packet compression.
 *
 *  Copyright (C) 2002-2012 OpenVPN Technologies, Inc. <sales@openvpn.net>
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

#ifdef HAVE_CONFIG_H
#include "config.h"
#elif defined(_MSC_VER)
#include "config-msvc.h"
#endif

#include "syshead.h"

#if defined(ENABLE_SNAPPY)

#include "snappy-c.h"

#include "comp.h"
#include "error.h"
#include "otime.h"

#include "memdbg.h"

/* Initial command byte to tell our peer if we compressed */
#define SNAPPY_COMPRESS_BYTE 0x68

static void
snap_compress_init (struct compress_context *compctx)
{
  msg (D_INIT_MEDIUM, "Snappy compression initializing");
  ASSERT(compctx->flags & COMP_F_SWAP);
}

static void
snap_compress_uninit (struct compress_context *compctx)
{
}

static void
snap_compress (struct buffer *buf, struct buffer work,
	       struct compress_context *compctx,
	       const struct frame* frame)
{
  snappy_status status;
  bool compressed = false;

  if (buf->len <= 0)
    return;

  /*
   * In order to attempt compression, length must be at least COMPRESS_THRESHOLD.
   */
  if (buf->len >= COMPRESS_THRESHOLD)
    {
      const size_t ps = PAYLOAD_SIZE (frame);
      size_t zlen = ps + COMP_EXTRA_BUFFER (ps);

      ASSERT (buf_init (&work, FRAME_HEADROOM (frame)));
      ASSERT (buf_safe (&work, zlen));

      if (buf->len > ps)
	{
	  dmsg (D_COMP_ERRORS, "Snappy compression buffer overflow");
	  buf->len = 0;
	  return;
	}

      status = snappy_compress((const char *)BPTR(buf), (size_t)BLEN(buf), (char *)BPTR(&work), &zlen);
      if (status != SNAPPY_OK)
	{
	  dmsg (D_COMP_ERRORS, "Snappy compression error: %d", status);
	  buf->len = 0;
	  return;
	}

      ASSERT (buf_safe (&work, zlen));
      work.len = zlen;
      compressed = true;

      dmsg (D_COMP, "Snappy compress %d -> %d", buf->len, work.len);
      compctx->pre_compress += buf->len;
      compctx->post_compress += work.len;
    }

  /* did compression save us anything? */
  {
    uint8_t comp_head_byte = NO_COMPRESS_BYTE_SWAP;
    if (compressed && work.len < buf->len)
      {
	*buf = work;
	comp_head_byte = SNAPPY_COMPRESS_BYTE;
      }

    {
      uint8_t *head = BPTR (buf);
      uint8_t *tail  = BEND (buf);
      ASSERT (buf_safe (buf, 1));
      ++buf->len;

      /* move head byte of payload to tail */
      *tail = *head;
      *head = comp_head_byte;
    }
  }
}

static void
snap_decompress (struct buffer *buf, struct buffer work,
		 struct compress_context *compctx,
		 const struct frame* frame)
{
  size_t zlen = EXPANDED_SIZE (frame);
  snappy_status status;
  uint8_t c;		/* flag indicating whether or not our peer compressed */

  if (buf->len <= 0)
    return;

  ASSERT (buf_init (&work, FRAME_HEADROOM (frame)));

  /* do unframing/swap (assumes buf->len > 0) */
  {
    uint8_t *head = BPTR (buf);
    c = *head;
    --buf->len;
    *head = *BEND (buf);
  }

  if (c == SNAPPY_COMPRESS_BYTE)	/* packet was compressed */
    {
      ASSERT (buf_safe (&work, zlen));
      status = snappy_uncompress((const char *)BPTR(buf), (size_t)BLEN(buf), (char *)BPTR(&work), &zlen);
      if (status != SNAPPY_OK)
	{
	  dmsg (D_COMP_ERRORS, "Snappy decompression error: %d", status);
	  buf->len = 0;
	  return;
	}

      ASSERT (buf_safe (&work, zlen));
      work.len = zlen;

      dmsg (D_COMP, "Snappy decompress %d -> %d", buf->len, work.len);
      compctx->pre_decompress += buf->len;
      compctx->post_decompress += work.len;

      *buf = work;
    }
  else if (c == NO_COMPRESS_BYTE_SWAP)	/* packet was not compressed */
    {
      ;
    }
  else
    {
      dmsg (D_COMP_ERRORS, "Bad Snappy decompression header byte: %d", c);
      buf->len = 0;
    }
}

const struct compress_alg snappy_alg = {
  "snappy",
  snap_compress_init,
  snap_compress_uninit,
  snap_compress,
  snap_decompress
};

#else
static void dummy(void) {}
#endif /* ENABLE_SNAPPY */
