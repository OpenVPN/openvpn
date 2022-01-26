/*
 *  OpenVPN -- An application to securely tunnel IP networks
 *             over a single UDP port, with support for SSL/TLS-based
 *             session authentication and key exchange,
 *             packet encryption, packet authentication, and
 *             packet compression.
 *
 *  Copyright (C) 2002-2022 OpenVPN Inc <sales@openvpn.net>
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

/*
 * Generic compression support.  Currently we support
 * LZO 2 and LZ4.
 */
#ifndef OPENVPN_COMP_H
#define OPENVPN_COMP_H

#ifdef USE_COMP

#include "buffer.h"
#include "mtu.h"
#include "common.h"
#include "status.h"

/* algorithms */
#define COMP_ALG_UNDEF  0
#define COMP_ALG_STUB   1 /* support compression command byte and framing without actual compression */
#define COMP_ALG_LZO    2 /* LZO algorithm */
#define COMP_ALG_SNAPPY 3 /* Snappy algorithm (no longer supported) */
#define COMP_ALG_LZ4    4 /* LZ4 algorithm */


/* algorithm v2 */
#define COMP_ALGV2_UNCOMPRESSED 10
#define COMP_ALGV2_LZ4      11
/*
 #define COMP_ALGV2_LZO     12
 #define COMP_ALGV2_SNAPPY   13
 */

/* Compression flags */
#define COMP_F_ADAPTIVE             (1<<0) /* COMP_ALG_LZO only */
#define COMP_F_ALLOW_COMPRESS       (1<<1) /* not only downlink is compressed but also uplink */
#define COMP_F_SWAP                 (1<<2) /* initial command byte is swapped with last byte in buffer to preserve payload alignment */
#define COMP_F_ADVERTISE_STUBS_ONLY (1<<3) /* tell server that we only support compression stubs */
#define COMP_F_ALLOW_STUB_ONLY      (1<<4) /* Only accept stub compression, even with COMP_F_ADVERTISE_STUBS_ONLY
                                            * we still accept other compressions to be pushed */


/*
 * Length of prepended prefix on compressed packets
 */
#define COMP_PREFIX_LEN 1

/*
 * Prefix bytes
 */

/* V1 on wire codes */
/* Initial command byte to tell our peer if we compressed */
#define LZO_COMPRESS_BYTE 0x66
#define LZ4_COMPRESS_BYTE 0x69
#define NO_COMPRESS_BYTE      0xFA
#define NO_COMPRESS_BYTE_SWAP 0xFB /* to maintain payload alignment, replace this byte with last byte of packet */

/* V2 on wire code */
#define COMP_ALGV2_INDICATOR_BYTE       0x50
#define COMP_ALGV2_UNCOMPRESSED_BYTE    0
#define COMP_ALGV2_LZ4_BYTE             1
#define COMP_ALGV2_LZO_BYTE             2
#define COMP_ALGV2_SNAPPY_BYTE          3

/*
 * Compress worst case size expansion (for any algorithm)
 *
 * LZO:    len + len/8 + 128 + 3
 * Snappy: len + len/6 + 32
 * LZ4:    len + len/255 + 16  (LZ4_COMPRESSBOUND(len))
 */
#define COMP_EXTRA_BUFFER(len) ((len)/6 + 128 + 3 + COMP_PREFIX_LEN)

/*
 * Don't try to compress any packet smaller than this.
 */
#define COMPRESS_THRESHOLD 100

/* Forward declaration of compression context */
struct compress_context;

/*
 * Virtual methods and other static info for each compression algorithm
 */
struct compress_alg
{
    const char *name;
    void (*compress_init)(struct compress_context *compctx);
    void (*compress_uninit)(struct compress_context *compctx);
    void (*compress)(struct buffer *buf, struct buffer work,
                     struct compress_context *compctx,
                     const struct frame *frame);

    void (*decompress)(struct buffer *buf, struct buffer work,
                       struct compress_context *compctx,
                       const struct frame *frame);
};

/*
 * Headers for each compression implementation
 */
#ifdef ENABLE_LZO
#include "lzo.h"
#endif

#ifdef ENABLE_LZ4
#include "comp-lz4.h"
#endif

/*
 * Information that basically identifies a compression
 * algorithm and related flags.
 */
struct compress_options
{
    int alg;
    unsigned int flags;
};

/*
 * Workspace union of all supported compression algorithms
 */
union compress_workspace_union
{
#ifdef ENABLE_LZO
    struct lzo_compress_workspace lzo;
#endif
#ifdef ENABLE_LZ4
    struct lz4_workspace lz4;
#endif
};

/*
 * Context for active compression session
 */
struct compress_context
{
    unsigned int flags;
    struct compress_alg alg;
    union compress_workspace_union wu;

    /* statistics */
    counter_type pre_decompress;
    counter_type post_decompress;
    counter_type pre_compress;
    counter_type post_compress;
};

extern const struct compress_alg comp_stub_alg;
extern const struct compress_alg compv2_stub_alg;

struct compress_context *comp_init(const struct compress_options *opt);

void comp_uninit(struct compress_context *compctx);

void comp_add_to_extra_frame(struct frame *frame);

void comp_add_to_extra_buffer(struct frame *frame);

void comp_print_stats(const struct compress_context *compctx, struct status_output *so);

void comp_generate_peer_info_string(const struct compress_options *opt, struct buffer *out);

void compv2_escape_data_ifneeded(struct buffer *buf);

static inline bool
comp_enabled(const struct compress_options *info)
{
    return info->alg != COMP_ALG_UNDEF;
}

static inline bool
comp_non_stub_enabled(const struct compress_options *info)
{
    return info->alg != COMP_ALGV2_UNCOMPRESSED
           && info->alg != COMP_ALG_STUB
           && info->alg != COMP_ALG_UNDEF;
}

static inline bool
comp_unswapped_prefix(const struct compress_options *info)
{
    return !(info->flags & COMP_F_SWAP);
}

#endif /* USE_COMP */
#endif /* ifndef OPENVPN_COMP_H */
