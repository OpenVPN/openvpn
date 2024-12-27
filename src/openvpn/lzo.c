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

/**
 * @file
 * Data Channel Compression module function definitions.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "syshead.h"

#if defined(ENABLE_LZO)

#include "comp.h"
#include "error.h"
#include "otime.h"

#include "memdbg.h"


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
    compctx->wu.lzo.wmem = (lzo_voidp) malloc(compctx->wu.lzo.wmem_size);
    check_malloc_return(compctx->wu.lzo.wmem);
}

static void
lzo_compress_uninit(struct compress_context *compctx)
{
    free(compctx->wu.lzo.wmem);
    compctx->wu.lzo.wmem = NULL;
}

static void
lzo_compress(struct buffer *buf, struct buffer work,
             struct compress_context *compctx,
             const struct frame *frame)
{
    uint8_t *header = buf_prepend(buf, 1);
    *header = NO_COMPRESS_BYTE;
}

static void
lzo_decompress(struct buffer *buf, struct buffer work,
               struct compress_context *compctx,
               const struct frame *frame)
{
    lzo_uint zlen = frame->buf.payload_size;
    int err;
    uint8_t c;          /* flag indicating whether or not our peer compressed */

    if (buf->len <= 0)
    {
        return;
    }

    ASSERT(buf_init(&work, frame->buf.headroom));

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
        /* nothing to do */
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
#endif /* ENABLE_LZO */
