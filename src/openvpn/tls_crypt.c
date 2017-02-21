/*
 *  OpenVPN -- An application to securely tunnel IP networks
 *             over a single TCP/UDP port, with support for SSL/TLS-based
 *             session authentication and key exchange,
 *             packet encryption, packet authentication, and
 *             packet compression.
 *
 *  Copyright (C) 2016-2017 Fox Crypto B.V. <openvpn@fox-it.com>
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

#ifdef ENABLE_CRYPTO
#include "crypto.h"
#include "session_id.h"

#include "tls_crypt.h"

int
tls_crypt_buf_overhead(void)
{
    return packet_id_size(true) + TLS_CRYPT_TAG_SIZE + TLS_CRYPT_BLOCK_SIZE;
}

void
tls_crypt_init_key(struct key_ctx_bi *key, const char *key_file,
                   const char *key_inline, bool tls_server)
{
    const int key_direction = tls_server ?
                              KEY_DIRECTION_NORMAL : KEY_DIRECTION_INVERSE;

    struct key_type kt;
    kt.cipher = cipher_kt_get("AES-256-CTR");
    kt.digest = md_kt_get("SHA256");

    if (!kt.cipher)
    {
        msg(M_FATAL, "ERROR: --tls-crypt requires AES-256-CTR support.");
    }
    if (!kt.digest)
    {
        msg(M_FATAL, "ERROR: --tls-crypt requires HMAC-SHA-256 support.");
    }

    kt.cipher_length = cipher_kt_key_size(kt.cipher);
    kt.hmac_length = md_kt_size(kt.digest);

    crypto_read_openvpn_key(&kt, key, key_file, key_inline, key_direction,
                            "Control Channel Encryption", "tls-crypt");
}

void
tls_crypt_adjust_frame_parameters(struct frame *frame)
{
    frame_add_to_extra_frame(frame, tls_crypt_buf_overhead());

    msg(D_MTU_DEBUG, "%s: Adjusting frame parameters for tls-crypt by %i bytes",
        __func__, tls_crypt_buf_overhead());
}


bool
tls_crypt_wrap(const struct buffer *src, struct buffer *dst,
               struct crypto_options *opt)
{
    const struct key_ctx *ctx = &opt->key_ctx_bi.encrypt;
    struct gc_arena gc;

    /* IV, packet-ID and implicit IV required for this mode. */
    ASSERT(ctx->cipher);
    ASSERT(ctx->hmac);
    ASSERT(packet_id_initialized(&opt->packet_id));
    ASSERT(hmac_ctx_size(ctx->hmac) == 256/8);

    gc_init(&gc);

    dmsg(D_PACKET_CONTENT, "TLS-CRYPT WRAP FROM: %s",
         format_hex(BPTR(src), BLEN(src), 80, &gc));

    /* Get packet ID */
    {
        struct packet_id_net pin;
        packet_id_alloc_outgoing(&opt->packet_id.send, &pin, true);
        packet_id_write(&pin, dst, true, false);
    }

    dmsg(D_PACKET_CONTENT, "TLS-CRYPT WRAP AD: %s",
         format_hex(BPTR(dst), BLEN(dst), 0, &gc));

    /* Buffer overflow check */
    if (!buf_safe(dst, BLEN(src) + TLS_CRYPT_BLOCK_SIZE + TLS_CRYPT_TAG_SIZE))
    {
        msg(D_CRYPT_ERRORS, "TLS-CRYPT WRAP: buffer size error, "
            "sc=%d so=%d sl=%d dc=%d do=%d dl=%d", src->capacity, src->offset,
            src->len, dst->capacity, dst->offset, dst->len);
        goto err;
    }

    /* Calculate auth tag and synthetic IV */
    {
        uint8_t *tag = NULL;
        hmac_ctx_reset(ctx->hmac);
        hmac_ctx_update(ctx->hmac, BPTR(dst), BLEN(dst));
        hmac_ctx_update(ctx->hmac, BPTR(src), BLEN(src));

        ASSERT(tag = buf_write_alloc(dst, TLS_CRYPT_TAG_SIZE));
        hmac_ctx_final(ctx->hmac, tag);

        dmsg(D_PACKET_CONTENT, "TLS-CRYPT WRAP TAG: %s",
             format_hex(tag, TLS_CRYPT_TAG_SIZE, 0, &gc));

        /* Use the 128 most significant bits of the tag as IV */
        ASSERT(cipher_ctx_reset(ctx->cipher, tag));
    }

    /* Encrypt src */
    {
        int outlen = 0;
        ASSERT(cipher_ctx_update(ctx->cipher, BEND(dst), &outlen,
                                 BPTR(src), BLEN(src)));
        ASSERT(buf_inc_len(dst, outlen));
        ASSERT(cipher_ctx_final(ctx->cipher, BPTR(dst), &outlen));
        ASSERT(buf_inc_len(dst, outlen));
    }

    dmsg(D_PACKET_CONTENT, "TLS-CRYPT WRAP TO: %s",
         format_hex(BPTR(dst), BLEN(dst), 80, &gc));

    gc_free(&gc);
    return true;

err:
    crypto_clear_error();
    dst->len = 0;
    gc_free(&gc);
    return false;
}

bool
tls_crypt_unwrap(const struct buffer *src, struct buffer *dst,
                 struct crypto_options *opt)
{
    static const char error_prefix[] = "tls-crypt unwrap error";
    const struct key_ctx *ctx = &opt->key_ctx_bi.decrypt;
    struct gc_arena gc;

    gc_init(&gc);

    ASSERT(opt);
    ASSERT(src->len > 0);
    ASSERT(ctx->cipher);
    ASSERT(packet_id_initialized(&opt->packet_id)
           || (opt->flags & CO_IGNORE_PACKET_ID));

    dmsg(D_PACKET_CONTENT, "TLS-CRYPT UNWRAP FROM: %s",
         format_hex(BPTR(src), BLEN(src), 80, &gc));

    if (buf_len(src) < TLS_CRYPT_OFF_CT)
    {
        CRYPT_ERROR("packet too short");
    }

    /* Decrypt cipher text */
    {
        int outlen = 0;

        /* Buffer overflow check (should never fail) */
        if (!buf_safe(dst, BLEN(src) - TLS_CRYPT_OFF_CT + TLS_CRYPT_BLOCK_SIZE))
        {
            CRYPT_ERROR("potential buffer overflow");
        }

        if (!cipher_ctx_reset(ctx->cipher, BPTR(src) + TLS_CRYPT_OFF_TAG))
        {
            CRYPT_ERROR("cipher reset failed");
        }
        if (!cipher_ctx_update(ctx->cipher, BPTR(dst), &outlen,
                               BPTR(src) + TLS_CRYPT_OFF_CT, BLEN(src) - TLS_CRYPT_OFF_CT))
        {
            CRYPT_ERROR("cipher update failed");
        }
        ASSERT(buf_inc_len(dst, outlen));
        if (!cipher_ctx_final(ctx->cipher, BPTR(dst), &outlen))
        {
            CRYPT_ERROR("cipher final failed");
        }
        ASSERT(buf_inc_len(dst, outlen));
    }

    /* Check authentication */
    {
        const uint8_t *tag = BPTR(src) + TLS_CRYPT_OFF_TAG;
        uint8_t tag_check[TLS_CRYPT_TAG_SIZE] = { 0 };

        dmsg(D_PACKET_CONTENT, "TLS-CRYPT UNWRAP AD: %s",
             format_hex(BPTR(src), TLS_CRYPT_OFF_TAG, 0, &gc));
        dmsg(D_PACKET_CONTENT, "TLS-CRYPT UNWRAP TO: %s",
             format_hex(BPTR(dst), BLEN(dst), 80, &gc));

        hmac_ctx_reset(ctx->hmac);
        hmac_ctx_update(ctx->hmac, BPTR(src), TLS_CRYPT_OFF_TAG);
        hmac_ctx_update(ctx->hmac, BPTR(dst), BLEN(dst));
        hmac_ctx_final(ctx->hmac, tag_check);

        if (memcmp_constant_time(tag, tag_check, sizeof(tag_check)))
        {
            dmsg(D_CRYPTO_DEBUG, "tag      : %s",
                 format_hex(tag, sizeof(tag_check), 0, &gc));
            dmsg(D_CRYPTO_DEBUG, "tag_check: %s",
                 format_hex(tag_check, sizeof(tag_check), 0, &gc));
            CRYPT_ERROR("packet authentication failed");
        }
    }

    /* Check replay */
    if (!(opt->flags & CO_IGNORE_PACKET_ID))
    {
        struct packet_id_net pin;
        struct buffer tmp = *src;
        ASSERT(buf_advance(&tmp, TLS_CRYPT_OFF_PID));
        ASSERT(packet_id_read(&pin, &tmp, true));
        if (!crypto_check_replay(opt, &pin, error_prefix, &gc))
        {
            CRYPT_ERROR("packet replay");
        }
    }

    gc_free(&gc);
    return true;

error_exit:
    crypto_clear_error();
    dst->len = 0;
    gc_free(&gc);
    return false;
}

#endif /* EMABLE_CRYPTO */
