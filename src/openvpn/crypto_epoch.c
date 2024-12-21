/*
 *  OpenVPN -- An application to securely tunnel IP networks
 *             over a single TCP/UDP port, with support for SSL/TLS-based
 *             session authentication and key exchange,
 *             packet encryption, packet authentication, and
 *             packet compression.
 *
 *  Copyright (C) 2024 OpenVPN Inc <sales@openvpn.net>
 *  Copyright (C) 2024 Arne Schwabe <arne@rfc2549.org>
 *
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

#include <inttypes.h>
#include "crypto_backend.h"
#include "buffer.h"
#include "integer.h"

void
ovpn_hkdf_expand(const uint8_t *secret,
                 const uint8_t *info, int info_len,
                 uint8_t *out, int out_len)
{
    hmac_ctx_t *hmac_ctx = hmac_ctx_new();
    hmac_ctx_init(hmac_ctx, secret, "SHA256");

    const int digest_size = SHA256_DIGEST_LENGTH;

    /* T(0) = empty string */
    uint8_t t_prev[SHA256_DIGEST_LENGTH];
    int t_prev_len = 0;

    for (uint8_t block = 1; (block - 1) * digest_size < out_len; block++)
    {
        hmac_ctx_reset(hmac_ctx);

        /* calculate T(block) */
        hmac_ctx_update(hmac_ctx, t_prev, t_prev_len);
        hmac_ctx_update(hmac_ctx, info, info_len);
        hmac_ctx_update(hmac_ctx, &block, 1);
        hmac_ctx_final(hmac_ctx, t_prev);
        t_prev_len = digest_size;

        /* Copy a full hmac output or remaining bytes */
        int out_offset = (block - 1) * digest_size;
        int copylen = min_int(digest_size, out_len - out_offset);

        memcpy(out + out_offset, t_prev, copylen);
    }
    hmac_ctx_cleanup(hmac_ctx);
    hmac_ctx_free(hmac_ctx);
}

bool
ovpn_expand_label(const uint8_t *secret, size_t secret_len,
                  const uint8_t *label, size_t label_len,
                  const uint8_t *context, size_t context_len,
                  uint8_t *out, uint16_t out_len)
{
    if (secret_len != 32 || label_len > 250 || context_len > 255
        || label_len < 1)
    {
        /* Our current implementation is not a general purpose one
         * and assumes that the secret size matches the size of the
         * hash (SHA256) key. Also label length and context length
         * need need to be in range */
        return false;
    }

    struct gc_arena gc = gc_new();
    /* 2 byte for the outlen encoded as uint16, 5 bytes for "ovpn ",
     * 1 byte for context len byte and 1 byte for label len byte */
    const uint8_t *label_prefix = (const uint8_t *) ("ovpn ");
    int prefix_len = 5;

    int hkdf_label_len = 2 + prefix_len + 1 + label_len + 1 + context_len;
    struct buffer hkdf_label = alloc_buf_gc(hkdf_label_len, &gc);

    buf_write_u16(&hkdf_label, out_len);
    buf_write_u8(&hkdf_label, prefix_len + label_len);
    buf_write(&hkdf_label, label_prefix, prefix_len);
    buf_write(&hkdf_label, label, label_len);

    buf_write_u8(&hkdf_label, context_len);
    if (context_len > 0)
    {
        buf_write(&hkdf_label, context, context_len);
    }

    ASSERT(buf_len(&hkdf_label) == hkdf_label_len);

    ovpn_hkdf_expand(secret, buf_bptr(&hkdf_label),
                     buf_len(&hkdf_label), out, out_len);

    gc_free(&gc);
    return true;
}
