/*
 *  OpenVPN -- An application to securely tunnel IP networks
 *             over a single UDP port, with support for SSL/TLS-based
 *             session authentication and key exchange,
 *             packet encryption, packet authentication, and
 *             packet compression.
 *
 *  Copyright (C) 2002-2012 OpenVPN Technologies, Inc. <sales@openvpn.net>
 *  Copyright (C) 2013      Gert Doering <gert@greenie.muc.de>
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

#if defined(ENABLE_ZSTD)

#if defined(NEED_COMPAT_ZSTD)
#include "compat-zstd/zstd.h"
#else
#include "zstd.h"
#endif

#include "comp.h"
#include "error.h"

#include "memdbg.h"

/* Initial command byte to tell our peer if we compressed */
#define ZSTD_COMPRESS_BYTE 0x6A

static void
zstd_compress_init (struct compress_context *compctx)
{
  msg (D_INIT_MEDIUM, "Zstandard compression initializing");
  ASSERT(compctx->flags & COMP_F_SWAP);
}

static void
zstd_compress_uninit (struct compress_context *compctx)
{
}

static void
zstd_compress (struct buffer *buf, struct buffer work,
	       struct compress_context *compctx,
	       const struct frame* frame)
{
  bool compressed = false;

  if (buf->len <= 0)
    return;

  /*
   * In order to attempt compression, length must be at least COMPRESS_THRESHOLD.
   */
  if (buf->len >= COMPRESS_THRESHOLD)
    {
      const size_t ps = PAYLOAD_SIZE (frame);
      int zlen_max = ps + COMP_EXTRA_BUFFER (ps);
      int zlen;

      ASSERT (buf_init (&work, FRAME_HEADROOM (frame)));
      ASSERT (buf_safe (&work, zlen_max));

      if (buf->len > ps)
	{
	  dmsg (D_COMP_ERRORS, "Zstandard compression buffer overflow");
	  buf->len = 0;
	  return;
	}

      zlen = ZSTD_compress((char *)BPTR(&work), zlen_max, (const char *)BPTR(buf), BLEN(buf));

      if (zlen <= 0)
	{
	  dmsg (D_COMP_ERRORS, "Zstandard compression error");
	  buf->len = 0;
	  return;
	}

      ASSERT (buf_safe (&work, zlen));
      work.len = zlen;
      compressed = true;

      dmsg (D_COMP, "Zstandard compress %d -> %d", buf->len, work.len);
      compctx->pre_compress += buf->len;
      compctx->post_compress += work.len;
    }

  /* did compression save us anything? */
  {
    uint8_t comp_head_byte = NO_COMPRESS_BYTE_SWAP;
    if (compressed && work.len < buf->len)
      {
	*buf = work;
	comp_head_byte = ZSTD_COMPRESS_BYTE;
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
zstd_decompress (struct buffer *buf, struct buffer work,
		 struct compress_context *compctx,
		 const struct frame* frame)
{
  size_t zlen_max = EXPANDED_SIZE (frame);
  int uncomp_len;
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

  if (c == ZSTD_COMPRESS_BYTE)	/* packet was compressed */
    {
      ASSERT (buf_safe (&work, zlen_max));
      uncomp_len = ZSTD_decompress((char *)BPTR(&work), zlen_max, (const char *)BPTR(buf), (size_t)BLEN(buf));
      if (uncomp_len <= 0)
	{
	  dmsg (D_COMP_ERRORS, "Zstandard decompression error: %d", uncomp_len);
	  buf->len = 0;
	  return;
	}

      ASSERT (buf_safe (&work, uncomp_len));
      work.len = uncomp_len;

      dmsg (D_COMP, "Zstandard decompress %d -> %d", buf->len, work.len);
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
      dmsg (D_COMP_ERRORS, "Bad Zstandard decompression header byte: %d", c);
      buf->len = 0;
    }
}

const struct compress_alg zstd_alg = {
  "zstd",
  zstd_compress_init,
  zstd_compress_uninit,
  zstd_compress,
  zstd_decompress
};

#else
static void dummy(void) {}
#endif /* ENABLE_ZSTD */
