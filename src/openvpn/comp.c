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

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "syshead.h"

#include "comp.h"
#include "error.h"

#ifdef USE_COMP

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
    if (!opt || opt->flags & COMP_F_ALLOW_NOCOMP_ONLY)
    {
        return;
    }

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
}
#endif /* USE_COMP */

bool
check_compression_settings_valid(struct compress_options *info, int msglevel)
{
    /*
     * We also allow comp-stub-v2 here as it technically allows escaping of
     * weird mac address and IPv5 protocol but practically always is used
     * as an way to disable all framing.
     */
    if (info->alg != COMP_ALGV2_UNCOMPRESSED && info->alg != COMP_ALG_UNDEF
        && (info->flags & COMP_F_ALLOW_NOCOMP_ONLY))
    {
#ifdef USE_COMP
        msg(msglevel, "Compression or compression stub framing is not allowed "
            "since data-channel offloading is enabled.");
#else
        msg(msglevel, "Compression or compression stub framing is not allowed "
            "since OpenVPN was built without compression support.");
#endif
        return false;
    }

    if ((info->flags & COMP_F_ALLOW_STUB_ONLY) && comp_non_stub_enabled(info))
    {
        msg(msglevel, "Compression is not allowed since allow-compression is "
            "set to 'stub-only'");
        return false;
    }
#ifndef ENABLE_LZ4
    if (info->alg == COMP_ALGV2_LZ4 || info->alg == COMP_ALG_LZ4)
    {
        msg(msglevel, "OpenVPN is compiled without LZ4 support. Requested "
            "compression cannot be enabled.");
        return false;
    }
#endif
#ifndef ENABLE_LZO
    if (info->alg == COMP_ALG_LZO)
    {
        msg(msglevel, "OpenVPN is compiled without LZO support. Requested "
            "compression cannot be enabled.");
        return false;
    }
#endif
    return true;
}
