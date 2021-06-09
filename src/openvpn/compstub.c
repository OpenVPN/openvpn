/*
 *  OpenVPN -- An application to securely tunnel IP networks
 *             over a single UDP port, with support for SSL/TLS-based
 *             session authentication and key exchange,
 *             packet encryption, packet authentication, and
 *             packet compression.
 *
 *  Copyright (C) 2002-2021 OpenVPN Inc <sales@openvpn.net>
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

#if defined(USE_COMP)

#include "comp.h"
#include "error.h"
#include "otime.h"

#include "memdbg.h"

static void
stub_compress_init(struct compress_context *compctx)
{
}

static void
stub_compress_uninit(struct compress_context *compctx)
{
}

static void
stub_compress(struct buffer *buf, struct buffer work,
              struct compress_context *compctx,
              const struct frame *frame)
{
    if (buf->len <= 0)
    {
        return;
    }
    if (compctx->flags & COMP_F_SWAP)
    {
        uint8_t *head = BPTR(buf);
        uint8_t *tail  = BEND(buf);
        ASSERT(buf_safe(buf, 1));
        ++buf->len;

        /* move head byte of payload to tail */
        *tail = *head;
        *head = NO_COMPRESS_BYTE_SWAP;
    }
    else
    {
        uint8_t *header = buf_prepend(buf, 1);
        *header = NO_COMPRESS_BYTE;
    }
}

static void
stub_decompress(struct buffer *buf, struct buffer work,
                struct compress_context *compctx,
                const struct frame *frame)
{
    uint8_t c;
    if (buf->len <= 0)
    {
        return;
    }
    if (compctx->flags & COMP_F_SWAP)
    {
        uint8_t *head = BPTR(buf);
        c = *head;
        --buf->len;
        *head = *BEND(buf);
        if (c != NO_COMPRESS_BYTE_SWAP)
        {
            dmsg(D_COMP_ERRORS, "Bad compression stub (swap) decompression header byte: %d", c);
            buf->len = 0;
        }
    }
    else
    {
        c = *BPTR(buf);
        ASSERT(buf_advance(buf, 1));
        if (c != NO_COMPRESS_BYTE)
        {
            dmsg(D_COMP_ERRORS, "Bad compression stub decompression header byte: %d", c);
            buf->len = 0;
        }
    }
}


static void
stubv2_compress(struct buffer *buf, struct buffer work,
                struct compress_context *compctx,
                const struct frame *frame)
{
    if (buf->len <= 0)
    {
        return;
    }

    compv2_escape_data_ifneeded(buf);
}

static void
stubv2_decompress(struct buffer *buf, struct buffer work,
                  struct compress_context *compctx,
                  const struct frame *frame)
{
    if (buf->len <= 0)
    {
        return;
    }

    uint8_t *head = BPTR(buf);

    /* no compression or packet to short*/
    if (head[0] != COMP_ALGV2_INDICATOR_BYTE)
    {
        return;
    }

    /* compression header (0x50) is present */
    buf_advance(buf, 1);

    /* Packet buffer too short (only 1 byte) */
    if (buf->len <= 0)
    {
        return;
    }

    head = BPTR(buf);
    buf_advance(buf, 1);

    if (head[0] != COMP_ALGV2_UNCOMPRESSED_BYTE)
    {
        dmsg(D_COMP_ERRORS, "Bad compression stubv2 decompression header byte: %d", *head);
        buf->len = 0;
        return;
    }
}

const struct compress_alg compv2_stub_alg = {
    "stubv2",
    stub_compress_init,
    stub_compress_uninit,
    stubv2_compress,
    stubv2_decompress
};

const struct compress_alg comp_stub_alg = {
    "stub",
    stub_compress_init,
    stub_compress_uninit,
    stub_compress,
    stub_decompress
};
#endif /* USE_STUB */
