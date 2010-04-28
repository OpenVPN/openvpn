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

#include "syshead.h"

#ifdef USE_LZO

#include "lzo.h"
#include "error.h"
#include "otime.h"

#include "memdbg.h"

static bool
lzo_adaptive_compress_test (struct lzo_adaptive_compress *ac)
{
  const bool save = ac->compress_state;
  const time_t local_now = now;

  if (!ac->compress_state)
    {
      if (local_now >= ac->next)
	{
	  if (ac->n_total > AC_MIN_BYTES
	      && (ac->n_total - ac->n_comp) < (ac->n_total / (100 / AC_SAVE_PCT)))
	    {
	      ac->compress_state = true;
	      ac->next = local_now + AC_OFF_SEC;
	    }
	  else
	    {
	      ac->next = local_now + AC_SAMP_SEC;
	    }
	  dmsg (D_COMP, "lzo_adaptive_compress_test: comp=%d total=%d", ac->n_comp, ac->n_total);
	  ac->n_total = ac->n_comp = 0;
	}
    }
  else 
    {
      if (local_now >= ac->next)
	{
	  ac->next = local_now + AC_SAMP_SEC;
	  ac->n_total = ac->n_comp = 0;
	  ac->compress_state = false;
	}
    }

  if (ac->compress_state != save)
    dmsg (D_COMP_LOW, "Adaptive compression state %s", (ac->compress_state ? "OFF" : "ON"));

  return !ac->compress_state;
}

static inline void
lzo_adaptive_compress_data (struct lzo_adaptive_compress *ac, int n_total, int n_comp)
{
  ac->n_total += n_total;
  ac->n_comp += n_comp;
}

void lzo_adjust_frame_parameters (struct frame *frame)
{
  /* Leave room for our one-byte compressed/didn't-compress prefix byte. */
  frame_add_to_extra_frame (frame, LZO_PREFIX_LEN);

  /* Leave room for compression buffer to expand in worst case scenario
     where data is totally uncompressible */
  frame_add_to_extra_buffer (frame, LZO_EXTRA_BUFFER (EXPANDED_SIZE(frame)));
}

void
lzo_compress_init (struct lzo_compress_workspace *lzowork, unsigned int flags)
{
  CLEAR (*lzowork);

  lzowork->wmem_size = LZO_WORKSPACE;
  lzowork->flags = flags;

  if (lzo_init () != LZO_E_OK)
    msg (M_FATAL, "Cannot initialize LZO compression library");
  lzowork->wmem = (lzo_voidp) lzo_malloc (lzowork->wmem_size);
  check_malloc_return (lzowork->wmem);
  msg (M_INFO, "LZO compression initialized");
  lzowork->defined = true;
}

void
lzo_compress_uninit (struct lzo_compress_workspace *lzowork)
{
  if (lzowork)
    {
      ASSERT (lzowork->defined);
      lzo_free (lzowork->wmem);
      lzowork->wmem = NULL;
      lzowork->defined = false;
    }
}

static inline bool
lzo_compression_enabled (struct lzo_compress_workspace *lzowork)
{
  if ((lzowork->flags & (LZO_SELECTED|LZO_ON)) == (LZO_SELECTED|LZO_ON))
    {
      if (lzowork->flags & LZO_ADAPTIVE)
	return lzo_adaptive_compress_test (&lzowork->ac);
      else
	return true;
    }
  return false;
}

/* Magic numbers to tell our peer if we compressed or not */
#define YES_COMPRESS 0x66
#define NO_COMPRESS  0xFA

void
lzo_compress (struct buffer *buf, struct buffer work,
	      struct lzo_compress_workspace *lzowork,
	      const struct frame* frame)
{
  lzo_uint zlen = 0;
  int err;
  bool compressed = false;

  ASSERT (lzowork->defined);

  if (buf->len <= 0)
    return;

  /*
   * In order to attempt compression, length must be at least COMPRESS_THRESHOLD,
   * and our adaptive level must give the OK.
   */
  if (buf->len >= COMPRESS_THRESHOLD && lzo_compression_enabled (lzowork))
    {
      ASSERT (buf_init (&work, FRAME_HEADROOM (frame)));
      ASSERT (buf_safe (&work, LZO_EXTRA_BUFFER (PAYLOAD_SIZE (frame))));

      if (!(buf->len <= PAYLOAD_SIZE (frame)))
	{
	  dmsg (D_COMP_ERRORS, "LZO compression buffer overflow");
	  buf->len = 0;
	  return;
	}

      err = LZO_COMPRESS (BPTR (buf), BLEN (buf), BPTR (&work), &zlen, lzowork->wmem);
      if (err != LZO_E_OK)
	{
	  dmsg (D_COMP_ERRORS, "LZO compression error: %d", err);
	  buf->len = 0;
	  return;
	}

      ASSERT (buf_safe (&work, zlen));
      work.len = zlen;
      compressed = true;

      dmsg (D_COMP, "compress %d -> %d", buf->len, work.len);
      lzowork->pre_compress += buf->len;
      lzowork->post_compress += work.len;

      /* tell adaptive level about our success or lack thereof in getting any size reduction */
      if (lzowork->flags & LZO_ADAPTIVE)
	lzo_adaptive_compress_data (&lzowork->ac, buf->len, work.len);
    }

  /* did compression save us anything ? */
  if (compressed && work.len < buf->len)
    {
      uint8_t *header = buf_prepend (&work, 1);
      *header = YES_COMPRESS;
      *buf = work;
    }
  else
    {
      uint8_t *header = buf_prepend (buf, 1);
      *header = NO_COMPRESS;
    }
}

void
lzo_decompress (struct buffer *buf, struct buffer work,
		struct lzo_compress_workspace *lzowork,
		const struct frame* frame)
{
  lzo_uint zlen = EXPANDED_SIZE (frame);
  uint8_t c;		/* flag indicating whether or not our peer compressed */
  int err;

  ASSERT (lzowork->defined);

  if (buf->len <= 0)
    return;

  ASSERT (buf_init (&work, FRAME_HEADROOM (frame)));

  c = *BPTR (buf);
  ASSERT (buf_advance (buf, 1));

  if (c == YES_COMPRESS)	/* packet was compressed */
    {
      ASSERT (buf_safe (&work, zlen));
      err = LZO_DECOMPRESS (BPTR (buf), BLEN (buf), BPTR (&work), &zlen,
			    lzowork->wmem);
      if (err != LZO_E_OK)
	{
	  dmsg (D_COMP_ERRORS, "LZO decompression error: %d", err);
	  buf->len = 0;
	  return;
	}

      ASSERT (buf_safe (&work, zlen));
      work.len = zlen;

      dmsg (D_COMP, "decompress %d -> %d", buf->len, work.len);
      lzowork->pre_decompress += buf->len;
      lzowork->post_decompress += work.len;

      *buf = work;
    }
  else if (c == NO_COMPRESS)	/* packet was not compressed */
    {
      ;
    }
  else
    {
      dmsg (D_COMP_ERRORS, "Bad LZO decompression header byte: %d", c);
      buf->len = 0;
    }
}

void
lzo_modify_flags (struct lzo_compress_workspace *lzowork, unsigned int flags)
{
  ASSERT (lzowork->defined);
  lzowork->flags = flags;
}

/*
 * Print statistics
 */
void lzo_print_stats (const struct lzo_compress_workspace *lzo_compwork, struct status_output *so)
{
  ASSERT (lzo_compwork->defined);

  status_printf (so, "pre-compress bytes," counter_format, lzo_compwork->pre_compress);
  status_printf (so, "post-compress bytes," counter_format, lzo_compwork->post_compress);
  status_printf (so, "pre-decompress bytes," counter_format, lzo_compwork->pre_decompress);
  status_printf (so, "post-decompress bytes," counter_format, lzo_compwork->post_decompress);
}

#else
static void dummy(void) {}
#endif /* USE_LZO */
