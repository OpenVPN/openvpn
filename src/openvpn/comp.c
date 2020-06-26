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

#ifdef HAVE_CONFIG_H
#include "config.h"
#elif defined(_MSC_VER)
#include "config-msvc.h"
#endif

#include "syshead.h"

#ifdef USE_COMP

#include "comp.h"
#include "error.h"
#include "otime.h"

#include "memdbg.h"

struct compress_context *
comp_init(const struct compress_options *opt)
{
    struct compress_context *compctx = NULL;
    switch (opt->alg)
    {
        case COMP_ALG_STUB:
            ALLOC_OBJ_CLEAR(compctx, struct compress_context);
            compctx->flags = opt->flags;
            compctx->alg = comp_stub_alg;
            break;

        case COMP_ALGV2_UNCOMPRESSED:
            ALLOC_OBJ_CLEAR(compctx, struct compress_context);
            compctx->flags = opt->flags;
            compctx->alg = compv2_stub_alg;
            break;

#ifdef ENABLE_LZO
        case COMP_ALG_LZO:
            ALLOC_OBJ_CLEAR(compctx, struct compress_context);
            compctx->flags = opt->flags;
            compctx->alg = lzo_alg;
            break;

#endif
#ifdef ENABLE_LZ4
        case COMP_ALG_LZ4:
            ALLOC_OBJ_CLEAR(compctx, struct compress_context);
            compctx->flags = opt->flags;
            compctx->alg = lz4_alg;
            break;

        case COMP_ALGV2_LZ4:
            ALLOC_OBJ_CLEAR(compctx, struct compress_context);
            compctx->flags = opt->flags;
            compctx->alg = lz4v2_alg;
            break;
#endif
    }
    if (compctx)
    {
        (*compctx->alg.compress_init)(compctx);
    }

    return compctx;
}

/* In the v2 compression schemes, an uncompressed packet has
 * has no opcode in front, unless the first byte is 0x50. In this
 * case the packet needs to be escaped */
void
compv2_escape_data_ifneeded(struct buffer *buf)
{
    uint8_t *head = BPTR(buf);
    if (head[0] != COMP_ALGV2_INDICATOR_BYTE)
    {
        return;
    }

    /* Header is 0x50 */
    ASSERT(buf_prepend(buf, 2));

    head = BPTR(buf);
    head[0] = COMP_ALGV2_INDICATOR_BYTE;
    head[1] = COMP_ALGV2_UNCOMPRESSED;
}


void
comp_uninit(struct compress_context *compctx)
{
    if (compctx)
    {
        (*compctx->alg.compress_uninit)(compctx);
        free(compctx);
    }
}

void
comp_add_to_extra_frame(struct frame *frame)
{
    /* Leave room for our one-byte compressed/didn't-compress prefix byte. */
    frame_add_to_extra_frame(frame, COMP_PREFIX_LEN);
}

void
comp_add_to_extra_buffer(struct frame *frame)
{
    /* Leave room for compression buffer to expand in worst case scenario
     * where data is totally incompressible */
    frame_add_to_extra_buffer(frame, COMP_EXTRA_BUFFER(EXPANDED_SIZE(frame)));
}

void
comp_print_stats(const struct compress_context *compctx, struct status_output *so)
{
    if (compctx)
    {
        status_printf(so, "pre-compress bytes," counter_format, compctx->pre_compress);
        status_printf(so, "post-compress bytes," counter_format, compctx->post_compress);
        status_printf(so, "pre-decompress bytes," counter_format, compctx->pre_decompress);
        status_printf(so, "post-decompress bytes," counter_format, compctx->post_decompress);
    }
}

/*
 * Tell our peer which compression algorithms we support.
 */
void
comp_generate_peer_info_string(const struct compress_options *opt, struct buffer *out)
{
    if (opt)
    {
        bool lzo_avail = false;
        if (!(opt->flags & COMP_F_ADVERTISE_STUBS_ONLY))
        {
#if defined(ENABLE_LZ4)
            buf_printf(out, "IV_LZ4=1\n");
            buf_printf(out, "IV_LZ4v2=1\n");
#endif
#if defined(ENABLE_LZO)
            buf_printf(out, "IV_LZO=1\n");
            lzo_avail = true;
#endif
        }
        if (!lzo_avail)
        {
            buf_printf(out, "IV_LZO_STUB=1\n");
        }
        buf_printf(out, "IV_COMP_STUB=1\n");
        buf_printf(out, "IV_COMP_STUBv2=1\n");
        buf_printf(out, "IV_TCPNL=1\n");
    }
}

#endif /* USE_COMP */
