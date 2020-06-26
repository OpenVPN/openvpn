/*
 *  OpenVPN -- An application to securely tunnel IP networks
 *             over a single UDP port, with support for SSL/TLS-based
 *             session authentication and key exchange,
 *             packet encryption, packet authentication, and
 *             packet compression.
 *
 *  Copyright (C) 2002-2018 OpenVPN Inc <sales@openvpn.net>
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
 * @file Data Channel Compression module function definitions.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#elif defined(_MSC_VER)
#include "config-msvc.h"
#endif

#include "syshead.h"

#if defined(ENABLE_LZO)

#include "comp.h"
#include "error.h"
#include "otime.h"

#include "memdbg.h"

/**
 * Perform adaptive compression housekeeping.
 *
 * @param ac the adaptive compression state structure.
 *
 * @return
 */
static bool
lzo_adaptive_compress_test(struct lzo_adaptive_compress *ac)
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
            dmsg(D_COMP, "lzo_adaptive_compress_test: comp=%d total=%d", ac->n_comp, ac->n_total);
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
    {
        dmsg(D_COMP_LOW, "Adaptive compression state %s", (ac->compress_state ? "OFF" : "ON"));
    }

    return !ac->compress_state;
}

static inline void
lzo_adaptive_compress_data(struct lzo_adaptive_compress *ac, int n_total, int n_comp)
{
    ac->n_total += n_total;
    ac->n_comp += n_comp;
}

static void
lzo_compress_init(struct compress_context *compctx)
{
    msg(D_INIT_MEDIUM, "LZO compression initializing");
    ASSERT(!(compctx->flags & COMP_F_SWAP));
    compctx->wu.lzo.wmem_size = LZO_WORKSPACE;

    int lzo_status = lzo_init();
    if (lzo_status != LZO_E_OK)
    {
        msg(M_FATAL, "Cannot initialize LZO compression library (lzo_init() returns %d)", lzo_status);
    }
    compctx->wu.lzo.wmem = (lzo_voidp) lzo_malloc(compctx->wu.lzo.wmem_size);
    check_malloc_return(compctx->wu.lzo.wmem);
}

static void
lzo_compress_uninit(struct compress_context *compctx)
{
    lzo_free(compctx->wu.lzo.wmem);
    compctx->wu.lzo.wmem = NULL;
}

static inline bool
lzo_compression_enabled(struct compress_context *compctx)
{
    if (!(compctx->flags & COMP_F_ALLOW_COMPRESS))
    {
        return false;
    }
    else
    {
        if (compctx->flags & COMP_F_ADAPTIVE)
        {
            return lzo_adaptive_compress_test(&compctx->wu.lzo.ac);
        }
        else
        {
            return true;
        }
    }
}

static void
lzo_compress(struct buffer *buf, struct buffer work,
             struct compress_context *compctx,
             const struct frame *frame)
{
    lzo_uint zlen = 0;
    int err;
    bool compressed = false;

    if (buf->len <= 0)
    {
        return;
    }

    /*
     * In order to attempt compression, length must be at least COMPRESS_THRESHOLD,
     * and our adaptive level must give the OK.
     */
    if (buf->len >= COMPRESS_THRESHOLD && lzo_compression_enabled(compctx))
    {
        const size_t ps = PAYLOAD_SIZE(frame);
        ASSERT(buf_init(&work, FRAME_HEADROOM(frame)));
        ASSERT(buf_safe(&work, ps + COMP_EXTRA_BUFFER(ps)));

        if (buf->len > ps)
        {
            dmsg(D_COMP_ERRORS, "LZO compression buffer overflow");
            buf->len = 0;
            return;
        }

        err = LZO_COMPRESS(BPTR(buf), BLEN(buf), BPTR(&work), &zlen, compctx->wu.lzo.wmem);
        if (err != LZO_E_OK)
        {
            dmsg(D_COMP_ERRORS, "LZO compression error: %d", err);
            buf->len = 0;
            return;
        }

        ASSERT(buf_safe(&work, zlen));
        work.len = zlen;
        compressed = true;

        dmsg(D_COMP, "LZO compress %d -> %d", buf->len, work.len);
        compctx->pre_compress += buf->len;
        compctx->post_compress += work.len;

        /* tell adaptive level about our success or lack thereof in getting any size reduction */
        if (compctx->flags & COMP_F_ADAPTIVE)
        {
            lzo_adaptive_compress_data(&compctx->wu.lzo.ac, buf->len, work.len);
        }
    }

    /* did compression save us anything ? */
    if (compressed && work.len < buf->len)
    {
        uint8_t *header = buf_prepend(&work, 1);
        *header = LZO_COMPRESS_BYTE;
        *buf = work;
    }
    else
    {
        uint8_t *header = buf_prepend(buf, 1);
        *header = NO_COMPRESS_BYTE;
    }
}

static void
lzo_decompress(struct buffer *buf, struct buffer work,
               struct compress_context *compctx,
               const struct frame *frame)
{
    lzo_uint zlen = EXPANDED_SIZE(frame);
    int err;
    uint8_t c;          /* flag indicating whether or not our peer compressed */

    if (buf->len <= 0)
    {
        return;
    }

    ASSERT(buf_init(&work, FRAME_HEADROOM(frame)));

    c = *BPTR(buf);
    ASSERT(buf_advance(buf, 1));

    if (c == LZO_COMPRESS_BYTE) /* packet was compressed */
    {
        ASSERT(buf_safe(&work, zlen));
        err = LZO_DECOMPRESS(BPTR(buf), BLEN(buf), BPTR(&work), &zlen,
                             compctx->wu.lzo.wmem);
        if (err != LZO_E_OK)
        {
            dmsg(D_COMP_ERRORS, "LZO decompression error: %d", err);
            buf->len = 0;
            return;
        }

        ASSERT(buf_safe(&work, zlen));
        work.len = zlen;

        dmsg(D_COMP, "LZO decompress %d -> %d", buf->len, work.len);
        compctx->pre_decompress += buf->len;
        compctx->post_decompress += work.len;

        *buf = work;
    }
    else if (c == NO_COMPRESS_BYTE)     /* packet was not compressed */
    {
    }
    else
    {
        dmsg(D_COMP_ERRORS, "Bad LZO decompression header byte: %d", c);
        buf->len = 0;
    }
}

const struct compress_alg lzo_alg = {
    "lzo",
    lzo_compress_init,
    lzo_compress_uninit,
    lzo_compress,
    lzo_decompress
};

#else  /* if defined(ENABLE_LZO) */
static void
dummy(void)
{
}
#endif /* ENABLE_LZO */
