/*
 *  OpenVPN -- An application to securely tunnel IP networks
 *             over a single UDP port, with support for SSL/TLS-based
 *             session authentication and key exchange,
 *             packet encryption, packet authentication, and
 *             packet compression.
 *
 *  Copyright (C) 2002-2018 OpenVPN Inc <sales@openvpn.net>
 *  Copyright (C) 2013-2018 Gert Doering <gert@greenie.muc.de>
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

#ifdef HAVE_CONFIG_H
#include "config.h"
#elif defined(_MSC_VER)
#include "config-msvc.h"
#endif

#include "syshead.h"

#if defined(ENABLE_LZ4)

#if defined(NEED_COMPAT_LZ4)
#include "compat-lz4.h"
#else
#include <lz4.h>
#endif

#include "comp.h"
#include "error.h"

#include "memdbg.h"


static void
lz4_compress_init(struct compress_context *compctx)
{
    msg(D_INIT_MEDIUM, "LZ4 compression initializing");
    ASSERT(compctx->flags & COMP_F_SWAP);
}

static void
lz4v2_compress_init(struct compress_context *compctx)
{
    msg(D_INIT_MEDIUM, "LZ4v2 compression initializing");
}

static void
lz4_compress_uninit(struct compress_context *compctx)
{
}

static bool
do_lz4_compress(struct buffer *buf,
                struct buffer *work,
                struct compress_context *compctx,
                const struct frame *frame)
{
    /*
     * In order to attempt compression, length must be at least COMPRESS_THRESHOLD.
     * and asymmetric compression must be disabled
     */
    if (buf->len >= COMPRESS_THRESHOLD && (compctx->flags & COMP_F_ALLOW_COMPRESS))
    {
        const size_t ps = PAYLOAD_SIZE(frame);
        int zlen_max = ps + COMP_EXTRA_BUFFER(ps);
        int zlen;

        ASSERT(buf_init(work, FRAME_HEADROOM(frame)));
        ASSERT(buf_safe(work, zlen_max));

        if (buf->len > ps)
        {
            dmsg(D_COMP_ERRORS, "LZ4 compression buffer overflow");
            buf->len = 0;
            return false;
        }

        zlen = LZ4_compress_default((const char *)BPTR(buf), (char *)BPTR(work), BLEN(buf), zlen_max);

        if (zlen <= 0)
        {
            dmsg(D_COMP_ERRORS, "LZ4 compression error");
            buf->len = 0;
            return false;
        }

        ASSERT(buf_safe(work, zlen));
        work->len = zlen;


        dmsg(D_COMP, "LZ4 compress %d -> %d", buf->len, work->len);
        compctx->pre_compress += buf->len;
        compctx->post_compress += work->len;
        return true;
    }
    return false;
}


static void
lz4_compress(struct buffer *buf, struct buffer work,
             struct compress_context *compctx,
             const struct frame *frame)
{
    bool compressed;
    if (buf->len <= 0)
    {
        return;
    }

    compressed = do_lz4_compress(buf, &work, compctx, frame);

    /* On error do_lz4_compress sets buf len to zero, just return */
    if (buf->len == 0)
    {
        return;
    }

    /* did compression save us anything? */
    {
        uint8_t comp_head_byte = NO_COMPRESS_BYTE_SWAP;
        if (compressed && work.len < buf->len)
        {
            *buf = work;
            comp_head_byte = LZ4_COMPRESS_BYTE;
        }

        {
            uint8_t *head = BPTR(buf);
            uint8_t *tail  = BEND(buf);
            ASSERT(buf_safe(buf, 1));
            ++buf->len;

            /* move head byte of payload to tail */
            *tail = *head;
            *head = comp_head_byte;
        }
    }
}


static void
lz4v2_compress(struct buffer *buf, struct buffer work,
               struct compress_context *compctx,
               const struct frame *frame)
{
    bool compressed;
    if (buf->len <= 0)
    {
        return;
    }

    compressed = do_lz4_compress(buf, &work, compctx, frame);

    /* On Error just return */
    if (buf->len == 0)
    {
        return;
    }

    /* did compression save us anything?  Include 2 byte compression header
     * in calculation */
    if (compressed && work.len + 2 < buf->len)
    {
        ASSERT(buf_prepend(&work, 2));
        uint8_t *head = BPTR(&work);
        head[0] = COMP_ALGV2_INDICATOR_BYTE;
        head[1] = COMP_ALGV2_LZ4_BYTE;
        *buf = work;
    }
    else
    {
        compv2_escape_data_ifneeded(buf);
    }
}

static void
do_lz4_decompress(size_t zlen_max,
                  struct buffer *work,
                  struct buffer *buf,
                  struct compress_context *compctx)
{
    int uncomp_len;
    ASSERT(buf_safe(work, zlen_max));
    uncomp_len = LZ4_decompress_safe((const char *)BPTR(buf), (char *)BPTR(work), (size_t)BLEN(buf), zlen_max);
    if (uncomp_len <= 0)
    {
        dmsg(D_COMP_ERRORS, "LZ4 decompression error: %d", uncomp_len);
        buf->len = 0;
        return;
    }

    ASSERT(buf_safe(work, uncomp_len));
    work->len = uncomp_len;

    dmsg(D_COMP, "LZ4 decompress %d -> %d", buf->len, work->len);
    compctx->pre_decompress += buf->len;
    compctx->post_decompress += work->len;

    *buf = *work;
}

static void
lz4_decompress(struct buffer *buf, struct buffer work,
               struct compress_context *compctx,
               const struct frame *frame)
{
    size_t zlen_max = EXPANDED_SIZE(frame);
    uint8_t c;          /* flag indicating whether or not our peer compressed */

    if (buf->len <= 0)
    {
        return;
    }

    ASSERT(buf_init(&work, FRAME_HEADROOM(frame)));

    /* do unframing/swap (assumes buf->len > 0) */
    {
        uint8_t *head = BPTR(buf);
        c = *head;
        --buf->len;
        *head = *BEND(buf);
    }

    if (c == LZ4_COMPRESS_BYTE) /* packet was compressed */
    {
        do_lz4_decompress(zlen_max, &work, buf, compctx);
    }
    else if (c == NO_COMPRESS_BYTE_SWAP) /* packet was not compressed */
    {
    }
    else
    {
        dmsg(D_COMP_ERRORS, "Bad LZ4 decompression header byte: %d", c);
        buf->len = 0;
    }
}

static void
lz4v2_decompress(struct buffer *buf, struct buffer work,
                 struct compress_context *compctx,
                 const struct frame *frame)
{
    size_t zlen_max = EXPANDED_SIZE(frame);
    uint8_t c;          /* flag indicating whether or not our peer compressed */

    if (buf->len <= 0)
    {
        return;
    }

    ASSERT(buf_init(&work, FRAME_HEADROOM(frame)));

    /* do unframing/swap (assumes buf->len > 0) */
    uint8_t *head = BPTR(buf);
    c = *head;

    /* Not compressed */
    if (c != COMP_ALGV2_INDICATOR_BYTE)
    {
        return;
    }

    /* Packet to short to make sense */
    if (buf->len <= 1)
    {
        buf->len = 0;
        return;
    }

    c = head[1];
    if (c == COMP_ALGV2_LZ4_BYTE) /* packet was compressed */
    {
        buf_advance(buf,2);
        do_lz4_decompress(zlen_max, &work, buf, compctx);
    }
    else if (c == COMP_ALGV2_UNCOMPRESSED_BYTE)
    {
        buf_advance(buf,2);
    }
    else
    {
        dmsg(D_COMP_ERRORS, "Bad LZ4v2 decompression header byte: %d", c);
        buf->len = 0;
    }
}

const struct compress_alg lz4_alg = {
    "lz4",
    lz4_compress_init,
    lz4_compress_uninit,
    lz4_compress,
    lz4_decompress
};

const struct compress_alg lz4v2_alg = {
    "lz4v2",
    lz4v2_compress_init,
    lz4_compress_uninit,
    lz4v2_compress,
    lz4v2_decompress
};

#else  /* if defined(ENABLE_LZ4) */
static void
dummy(void)
{
}
#endif /* ENABLE_LZ4 */
