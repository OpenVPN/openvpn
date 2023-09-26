/*
 *  OpenVPN -- An application to securely tunnel IP networks
 *             over a single TCP/UDP port, with support for SSL/TLS-based
 *             session authentication and key exchange,
 *             packet encryption, packet authentication, and
 *             packet compression.
 *
 *  Copyright (C) 2002-2023 OpenVPN Inc <sales@openvpn.net>
 *  Copyright (C) 2010-2021 Fox Crypto B.V. <openvpn@foxcrypto.com>
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

#include "crypto.h"
#include "error.h"
#include "integer.h"
#include "platform.h"

#include "memdbg.h"

/*
 * Encryption and Compression Routines.
 *
 * On entry, buf contains the input data and length.
 * On exit, it should be set to the output data and length.
 *
 * If buf->len is <= 0 we should return
 * If buf->len is set to 0 on exit it tells the caller to ignore the packet.
 *
 * work is a workspace buffer we are given of size BUF_SIZE.
 * work may be used to return output data, or the input buffer
 * may be modified and returned as output.  If output data is
 * returned in work, the data should start after buf.headroom bytes
 * of padding to leave room for downstream routines to prepend.
 *
 * Up to a total of buf.headroom bytes may be prepended to the input buf
 * by all routines (encryption, decryption, compression, and decompression).
 *
 * Note that the buf_prepend return will assert if we try to
 * make a header bigger than buf.headroom.  This should not
 * happen unless the frame parameters are wrong.
 */

static void
openvpn_encrypt_aead(struct buffer *buf, struct buffer work,
                     struct crypto_options *opt)
{
    struct gc_arena gc;
    int outlen = 0;
    const struct key_ctx *ctx = &opt->key_ctx_bi.encrypt;
    uint8_t *mac_out = NULL;
    const int mac_len = OPENVPN_AEAD_TAG_LENGTH;

    /* IV, packet-ID and implicit IV required for this mode. */
    ASSERT(ctx->cipher);
    ASSERT(packet_id_initialized(&opt->packet_id));

    gc_init(&gc);

    /* Prepare IV */
    {
        struct buffer iv_buffer;
        uint8_t iv[OPENVPN_MAX_IV_LENGTH] = {0};
        const int iv_len = cipher_ctx_iv_length(ctx->cipher);

        ASSERT(iv_len >= OPENVPN_AEAD_MIN_IV_LEN && iv_len <= OPENVPN_MAX_IV_LENGTH);

        buf_set_write(&iv_buffer, iv, iv_len);

        /* IV starts with packet id to make the IV unique for packet */
        if (!packet_id_write(&opt->packet_id.send, &iv_buffer, false, false))
        {
            msg(D_CRYPT_ERRORS, "ENCRYPT ERROR: packet ID roll over");
            goto err;
        }

        /* Remainder of IV consists of implicit part (unique per session) */
        ASSERT(buf_write(&iv_buffer, ctx->implicit_iv, ctx->implicit_iv_len));
        ASSERT(iv_buffer.len == iv_len);

        /* Write explicit part of IV to work buffer */
        ASSERT(buf_write(&work, iv, iv_len - ctx->implicit_iv_len));
        dmsg(D_PACKET_CONTENT, "ENCRYPT IV: %s", format_hex(iv, iv_len, 0, &gc));

        /* Init cipher_ctx with IV.  key & keylen are already initialized */
        ASSERT(cipher_ctx_reset(ctx->cipher, iv));
    }

    /* Reserve space for authentication tag */
    mac_out = buf_write_alloc(&work, mac_len);
    ASSERT(mac_out);

    dmsg(D_PACKET_CONTENT, "ENCRYPT FROM: %s", format_hex(BPTR(buf), BLEN(buf), 80, &gc));

    /* Buffer overflow check */
    if (!buf_safe(&work, buf->len + cipher_ctx_block_size(ctx->cipher)))
    {
        msg(D_CRYPT_ERRORS,
            "ENCRYPT: buffer size error, bc=%d bo=%d bl=%d wc=%d wo=%d wl=%d",
            buf->capacity, buf->offset, buf->len, work.capacity, work.offset,
            work.len);
        goto err;
    }

    /* For AEAD ciphers, authenticate Additional Data, including opcode */
    ASSERT(cipher_ctx_update_ad(ctx->cipher, BPTR(&work), BLEN(&work) - mac_len));
    dmsg(D_PACKET_CONTENT, "ENCRYPT AD: %s",
         format_hex(BPTR(&work), BLEN(&work) - mac_len, 0, &gc));

    /* Encrypt packet ID, payload */
    ASSERT(cipher_ctx_update(ctx->cipher, BEND(&work), &outlen, BPTR(buf), BLEN(buf)));
    ASSERT(buf_inc_len(&work, outlen));

    /* Flush the encryption buffer */
    ASSERT(cipher_ctx_final(ctx->cipher, BEND(&work), &outlen));
    ASSERT(buf_inc_len(&work, outlen));

    /* Write authentication tag */
    ASSERT(cipher_ctx_get_tag(ctx->cipher, mac_out, mac_len));

    *buf = work;

    dmsg(D_PACKET_CONTENT, "ENCRYPT TO: %s", format_hex(BPTR(buf), BLEN(buf), 80, &gc));

    gc_free(&gc);
    return;

err:
    crypto_clear_error();
    buf->len = 0;
    gc_free(&gc);
    return;
}

static void
openvpn_encrypt_v1(struct buffer *buf, struct buffer work,
                   struct crypto_options *opt)
{
    struct gc_arena gc;
    gc_init(&gc);

    if (buf->len > 0 && opt)
    {
        const struct key_ctx *ctx = &opt->key_ctx_bi.encrypt;
        uint8_t *mac_out = NULL;
        const uint8_t *hmac_start = NULL;

        /* Do Encrypt from buf -> work */
        if (ctx->cipher)
        {
            uint8_t iv_buf[OPENVPN_MAX_IV_LENGTH] = {0};
            const int iv_size = cipher_ctx_iv_length(ctx->cipher);
            int outlen;

            /* Reserve space for HMAC */
            if (ctx->hmac)
            {
                mac_out = buf_write_alloc(&work, hmac_ctx_size(ctx->hmac));
                ASSERT(mac_out);
                hmac_start = BEND(&work);
            }

            if (cipher_ctx_mode_cbc(ctx->cipher))
            {
                /* generate pseudo-random IV */
                prng_bytes(iv_buf, iv_size);

                /* Put packet ID in plaintext buffer */
                if (packet_id_initialized(&opt->packet_id)
                    && !packet_id_write(&opt->packet_id.send, buf,
                                        opt->flags & CO_PACKET_ID_LONG_FORM,
                                        true))
                {
                    msg(D_CRYPT_ERRORS, "ENCRYPT ERROR: packet ID roll over");
                    goto err;
                }
            }
            else if (cipher_ctx_mode_ofb_cfb(ctx->cipher))
            {
                struct buffer b;

                /* packet-ID required for this mode. */
                ASSERT(packet_id_initialized(&opt->packet_id));

                buf_set_write(&b, iv_buf, iv_size);
                ASSERT(packet_id_write(&opt->packet_id.send, &b, true, false));
            }
            else /* We only support CBC, CFB, or OFB modes right now */
            {
                ASSERT(0);
            }

            /* write the pseudo-randomly IV (CBC)/packet ID (OFB/CFB) */
            ASSERT(buf_write(&work, iv_buf, iv_size));
            dmsg(D_PACKET_CONTENT, "ENCRYPT IV: %s", format_hex(iv_buf, iv_size, 0, &gc));

            dmsg(D_PACKET_CONTENT, "ENCRYPT FROM: %s",
                 format_hex(BPTR(buf), BLEN(buf), 80, &gc));

            /* cipher_ctx was already initialized with key & keylen */
            ASSERT(cipher_ctx_reset(ctx->cipher, iv_buf));

            /* Buffer overflow check */
            if (!buf_safe(&work, buf->len + cipher_ctx_block_size(ctx->cipher)))
            {
                msg(D_CRYPT_ERRORS, "ENCRYPT: buffer size error, bc=%d bo=%d bl=%d wc=%d wo=%d wl=%d cbs=%d",
                    buf->capacity,
                    buf->offset,
                    buf->len,
                    work.capacity,
                    work.offset,
                    work.len,
                    cipher_ctx_block_size(ctx->cipher));
                goto err;
            }

            /* Encrypt packet ID, payload */
            ASSERT(cipher_ctx_update(ctx->cipher, BEND(&work), &outlen, BPTR(buf), BLEN(buf)));
            ASSERT(buf_inc_len(&work, outlen));

            /* Flush the encryption buffer */
            ASSERT(cipher_ctx_final(ctx->cipher, BEND(&work), &outlen));
            ASSERT(buf_inc_len(&work, outlen));

            /* For all CBC mode ciphers, check the last block is complete */
            ASSERT(cipher_ctx_mode(ctx->cipher) != OPENVPN_MODE_CBC
                   || outlen == iv_size);
        }
        else                            /* No Encryption */
        {
            if (packet_id_initialized(&opt->packet_id)
                && !packet_id_write(&opt->packet_id.send, buf,
                                    opt->flags & CO_PACKET_ID_LONG_FORM, true))
            {
                msg(D_CRYPT_ERRORS, "ENCRYPT ERROR: packet ID roll over");
                goto err;
            }
            if (ctx->hmac)
            {
                hmac_start = BPTR(buf);
                ASSERT(mac_out = buf_prepend(buf, hmac_ctx_size(ctx->hmac)));
            }
            if (BLEN(&work))
            {
                buf_write_prepend(buf, BPTR(&work), BLEN(&work));
            }
            work = *buf;
        }

        /* HMAC the ciphertext (or plaintext if !cipher) */
        if (ctx->hmac)
        {
            hmac_ctx_reset(ctx->hmac);
            hmac_ctx_update(ctx->hmac, hmac_start, BEND(&work) - hmac_start);
            hmac_ctx_final(ctx->hmac, mac_out);
            dmsg(D_PACKET_CONTENT, "ENCRYPT HMAC: %s",
                 format_hex(mac_out, hmac_ctx_size(ctx->hmac), 80, &gc));
        }

        *buf = work;

        dmsg(D_PACKET_CONTENT, "ENCRYPT TO: %s",
             format_hex(BPTR(&work), BLEN(&work), 80, &gc));
    }

    gc_free(&gc);
    return;

err:
    crypto_clear_error();
    buf->len = 0;
    gc_free(&gc);
    return;
}

void
openvpn_encrypt(struct buffer *buf, struct buffer work,
                struct crypto_options *opt)
{
    if (buf->len > 0 && opt)
    {
        if (cipher_ctx_mode_aead(opt->key_ctx_bi.encrypt.cipher))
        {
            openvpn_encrypt_aead(buf, work, opt);
        }
        else
        {
            openvpn_encrypt_v1(buf, work, opt);
        }
    }
}

bool
crypto_check_replay(struct crypto_options *opt,
                    const struct packet_id_net *pin, const char *error_prefix,
                    struct gc_arena *gc)
{
    bool ret = false;
    packet_id_reap_test(&opt->packet_id.rec);
    if (packet_id_test(&opt->packet_id.rec, pin))
    {
        packet_id_add(&opt->packet_id.rec, pin);
        if (opt->pid_persist && (opt->flags & CO_PACKET_ID_LONG_FORM))
        {
            packet_id_persist_save_obj(opt->pid_persist, &opt->packet_id);
        }
        ret = true;
    }
    else
    {
        if (!(opt->flags & CO_MUTE_REPLAY_WARNINGS))
        {
            msg(D_REPLAY_ERRORS, "%s: bad packet ID (may be a replay): %s -- "
                "see the man page entry for --no-replay and --replay-window for "
                "more info or silence this warning with --mute-replay-warnings",
                error_prefix, packet_id_net_print(pin, true, gc));
        }
    }
    return ret;
}

/**
 * Unwrap (authenticate, decrypt and check replay protection) AEAD-mode data
 * channel packets.
 *
 * Set buf->len to 0 and return false on decrypt error.
 *
 * On success, buf is set to point to plaintext, true is returned.
 */
static bool
openvpn_decrypt_aead(struct buffer *buf, struct buffer work,
                     struct crypto_options *opt, const struct frame *frame,
                     const uint8_t *ad_start)
{
    static const char error_prefix[] = "AEAD Decrypt error";
    struct packet_id_net pin = { 0 };
    const struct key_ctx *ctx = &opt->key_ctx_bi.decrypt;
    uint8_t *tag_ptr = NULL;
    int outlen;
    struct gc_arena gc;

    gc_init(&gc);

    ASSERT(opt);
    ASSERT(frame);
    ASSERT(buf->len > 0);
    ASSERT(ctx->cipher);

    dmsg(D_PACKET_CONTENT, "DECRYPT FROM: %s",
         format_hex(BPTR(buf), BLEN(buf), 80, &gc));

    ASSERT(ad_start >= buf->data && ad_start <= BPTR(buf));

    ASSERT(buf_init(&work, frame->buf.headroom));

    /* IV and Packet ID required for this mode */
    ASSERT(packet_id_initialized(&opt->packet_id));

    /* Combine IV from explicit part from packet and implicit part from context */
    {
        uint8_t iv[OPENVPN_MAX_IV_LENGTH] = { 0 };
        const int iv_len = cipher_ctx_iv_length(ctx->cipher);
        const size_t packet_iv_len = iv_len - ctx->implicit_iv_len;

        ASSERT(ctx->implicit_iv_len <= iv_len);
        if (buf->len + ctx->implicit_iv_len < iv_len)
        {
            CRYPT_ERROR("missing IV info");
        }

        memcpy(iv, BPTR(buf), packet_iv_len);
        memcpy(iv + packet_iv_len, ctx->implicit_iv, ctx->implicit_iv_len);

        dmsg(D_PACKET_CONTENT, "DECRYPT IV: %s", format_hex(iv, iv_len, 0, &gc));

        /* Load IV, ctx->cipher was already initialized with key & keylen */
        if (!cipher_ctx_reset(ctx->cipher, iv))
        {
            CRYPT_ERROR("cipher init failed");
        }
    }

    /* Read packet ID from packet */
    if (!packet_id_read(&pin, buf, false))
    {
        CRYPT_ERROR("error reading packet-id");
    }

    /* keep the tag value to feed in later */
    const int tag_size = OPENVPN_AEAD_TAG_LENGTH;
    if (buf->len < tag_size)
    {
        CRYPT_ERROR("missing tag");
    }
    tag_ptr = BPTR(buf);
    ASSERT(buf_advance(buf, tag_size));
    dmsg(D_PACKET_CONTENT, "DECRYPT MAC: %s", format_hex(tag_ptr, tag_size, 0, &gc));

    if (buf->len < 1)
    {
        CRYPT_ERROR("missing payload");
    }

    dmsg(D_PACKET_CONTENT, "DECRYPT FROM: %s", format_hex(BPTR(buf), BLEN(buf), 0, &gc));

    /* Buffer overflow check (should never fail) */
    if (!buf_safe(&work, buf->len + cipher_ctx_block_size(ctx->cipher)))
    {
        CRYPT_ERROR("potential buffer overflow");
    }

    {
        /* feed in tag and the authenticated data */
        const int ad_size = BPTR(buf) - ad_start - tag_size;
        ASSERT(cipher_ctx_update_ad(ctx->cipher, ad_start, ad_size));
        dmsg(D_PACKET_CONTENT, "DECRYPT AD: %s",
             format_hex(BPTR(buf) - ad_size - tag_size, ad_size, 0, &gc));
    }

    /* Decrypt and authenticate packet */
    if (!cipher_ctx_update(ctx->cipher, BPTR(&work), &outlen, BPTR(buf),
                           BLEN(buf)))
    {
        CRYPT_ERROR("cipher update failed");
    }
    ASSERT(buf_inc_len(&work, outlen));
    if (!cipher_ctx_final_check_tag(ctx->cipher, BPTR(&work) + outlen,
                                    &outlen, tag_ptr, tag_size))
    {
        CRYPT_ERROR("cipher final failed");
    }
    ASSERT(buf_inc_len(&work, outlen));

    dmsg(D_PACKET_CONTENT, "DECRYPT TO: %s",
         format_hex(BPTR(&work), BLEN(&work), 80, &gc));

    if (!crypto_check_replay(opt, &pin, error_prefix, &gc))
    {
        goto error_exit;
    }

    *buf = work;

    gc_free(&gc);
    return true;

error_exit:
    crypto_clear_error();
    buf->len = 0;
    gc_free(&gc);
    return false;
}

/*
 * Unwrap (authenticate, decrypt and check replay protection) CBC, OFB or CFB
 * mode data channel packets.
 *
 * Set buf->len to 0 and return false on decrypt error.
 *
 * On success, buf is set to point to plaintext, true is returned.
 */
static bool
openvpn_decrypt_v1(struct buffer *buf, struct buffer work,
                   struct crypto_options *opt, const struct frame *frame)
{
    static const char error_prefix[] = "Authenticate/Decrypt packet error";
    struct gc_arena gc;
    gc_init(&gc);

    if (buf->len > 0 && opt)
    {
        const struct key_ctx *ctx = &opt->key_ctx_bi.decrypt;
        struct packet_id_net pin;
        bool have_pin = false;

        dmsg(D_PACKET_CONTENT, "DECRYPT FROM: %s",
             format_hex(BPTR(buf), BLEN(buf), 80, &gc));

        /* Verify the HMAC */
        if (ctx->hmac)
        {
            int hmac_len;
            uint8_t local_hmac[MAX_HMAC_KEY_LENGTH]; /* HMAC of ciphertext computed locally */

            hmac_ctx_reset(ctx->hmac);

            /* Assume the length of the input HMAC */
            hmac_len = hmac_ctx_size(ctx->hmac);

            /* Authentication fails if insufficient data in packet for HMAC */
            if (buf->len < hmac_len)
            {
                CRYPT_ERROR("missing authentication info");
            }

            hmac_ctx_update(ctx->hmac, BPTR(buf) + hmac_len, BLEN(buf) - hmac_len);
            hmac_ctx_final(ctx->hmac, local_hmac);

            /* Compare locally computed HMAC with packet HMAC */
            if (memcmp_constant_time(local_hmac, BPTR(buf), hmac_len))
            {
                CRYPT_ERROR("packet HMAC authentication failed");
            }

            ASSERT(buf_advance(buf, hmac_len));
        }

        /* Decrypt packet ID + payload */

        if (ctx->cipher)
        {
            const int iv_size = cipher_ctx_iv_length(ctx->cipher);
            uint8_t iv_buf[OPENVPN_MAX_IV_LENGTH] = { 0 };
            int outlen;

            /* initialize work buffer with buf.headroom bytes of prepend capacity */
            ASSERT(buf_init(&work, frame->buf.headroom));

            /* read the IV from the packet */
            if (buf->len < iv_size)
            {
                CRYPT_ERROR("missing IV info");
            }
            memcpy(iv_buf, BPTR(buf), iv_size);
            ASSERT(buf_advance(buf, iv_size));
            dmsg(D_PACKET_CONTENT, "DECRYPT IV: %s", format_hex(iv_buf, iv_size, 0, &gc));

            if (buf->len < 1)
            {
                CRYPT_ERROR("missing payload");
            }

            /* ctx->cipher was already initialized with key & keylen */
            if (!cipher_ctx_reset(ctx->cipher, iv_buf))
            {
                CRYPT_ERROR("cipher init failed");
            }

            /* Buffer overflow check (should never happen) */
            if (!buf_safe(&work, buf->len + cipher_ctx_block_size(ctx->cipher)))
            {
                CRYPT_ERROR("potential buffer overflow");
            }

            /* Decrypt packet ID, payload */
            if (!cipher_ctx_update(ctx->cipher, BPTR(&work), &outlen, BPTR(buf), BLEN(buf)))
            {
                CRYPT_ERROR("cipher update failed");
            }
            ASSERT(buf_inc_len(&work, outlen));

            /* Flush the decryption buffer */
            if (!cipher_ctx_final(ctx->cipher, BPTR(&work) + outlen, &outlen))
            {
                CRYPT_ERROR("cipher final failed");
            }
            ASSERT(buf_inc_len(&work, outlen));

            dmsg(D_PACKET_CONTENT, "DECRYPT TO: %s",
                 format_hex(BPTR(&work), BLEN(&work), 80, &gc));

            /* Get packet ID from plaintext buffer or IV, depending on cipher mode */
            {
                if (cipher_ctx_mode_cbc(ctx->cipher))
                {
                    if (packet_id_initialized(&opt->packet_id))
                    {
                        if (!packet_id_read(&pin, &work, BOOL_CAST(opt->flags & CO_PACKET_ID_LONG_FORM)))
                        {
                            CRYPT_ERROR("error reading CBC packet-id");
                        }
                        have_pin = true;
                    }
                }
                else if (cipher_ctx_mode_ofb_cfb(ctx->cipher))
                {
                    struct buffer b;

                    /* packet-ID required for this mode. */
                    ASSERT(packet_id_initialized(&opt->packet_id));

                    buf_set_read(&b, iv_buf, iv_size);
                    if (!packet_id_read(&pin, &b, true))
                    {
                        CRYPT_ERROR("error reading CFB/OFB packet-id");
                    }
                    have_pin = true;
                }
                else /* We only support CBC, CFB, or OFB modes right now */
                {
                    ASSERT(0);
                }
            }
        }
        else
        {
            work = *buf;
            if (packet_id_initialized(&opt->packet_id))
            {
                if (!packet_id_read(&pin, &work, BOOL_CAST(opt->flags & CO_PACKET_ID_LONG_FORM)))
                {
                    CRYPT_ERROR("error reading packet-id");
                }
                have_pin = !BOOL_CAST(opt->flags & CO_IGNORE_PACKET_ID);
            }
        }

        if (have_pin && !crypto_check_replay(opt, &pin, error_prefix, &gc))
        {
            goto error_exit;
        }
        *buf = work;
    }

    gc_free(&gc);
    return true;

error_exit:
    crypto_clear_error();
    buf->len = 0;
    gc_free(&gc);
    return false;
}


bool
openvpn_decrypt(struct buffer *buf, struct buffer work,
                struct crypto_options *opt, const struct frame *frame,
                const uint8_t *ad_start)
{
    bool ret = false;

    if (buf->len > 0 && opt)
    {
        if (cipher_ctx_mode_aead(opt->key_ctx_bi.decrypt.cipher))
        {
            ret = openvpn_decrypt_aead(buf, work, opt, frame, ad_start);
        }
        else
        {
            ret = openvpn_decrypt_v1(buf, work, opt, frame);
        }
    }
    else
    {
        ret = true;
    }
    return ret;
}

unsigned int
calculate_crypto_overhead(const struct key_type *kt,
                          unsigned int pkt_id_size,
                          bool occ)
{
    unsigned int crypto_overhead = 0;

    if (!cipher_kt_mode_cbc(kt->cipher))
    {
        /* In CBC mode, the packet id is part of the payload size/overhead */
        crypto_overhead += pkt_id_size;
    }

    if (cipher_kt_mode_aead(kt->cipher))
    {
        /* For AEAD ciphers, we basically use a stream cipher/CTR for
         * the encryption, so no overhead apart from the extra bytes
         * we add */
        crypto_overhead += cipher_kt_tag_size(kt->cipher);

        if (occ)
        {
            /* the frame calculation of old clients adds these to the link-mtu
             * even though they are not part of the actual packet */
            crypto_overhead += cipher_kt_iv_size(kt->cipher);
            crypto_overhead += cipher_kt_block_size(kt->cipher);
        }
    }
    else
    {
        if (cipher_defined(kt->cipher))
        {
            /* CBC, OFB or CFB mode */
            if (occ)
            {
                crypto_overhead += cipher_kt_block_size(kt->cipher);
            }
            /* IV is always added (no-iv has been removed a while ago) */
            crypto_overhead += cipher_kt_iv_size(kt->cipher);
        }
        if (md_defined(kt->digest))
        {
            crypto_overhead += md_kt_size(kt->digest);
        }
    }

    return crypto_overhead;
}

unsigned int
crypto_max_overhead(void)
{
    return packet_id_size(true) + OPENVPN_MAX_IV_LENGTH
           +OPENVPN_MAX_CIPHER_BLOCK_SIZE
           +max_int(OPENVPN_MAX_HMAC_SIZE, OPENVPN_AEAD_TAG_LENGTH);
}

static void
warn_insecure_key_type(const char *ciphername)
{
    if (cipher_kt_insecure(ciphername))
    {
        msg(M_WARN, "WARNING: INSECURE cipher (%s) with block size less than 128"
            " bit (%d bit).  This allows attacks like SWEET32.  Mitigate by "
            "using a --cipher with a larger block size (e.g. AES-256-CBC). "
            "Support for these insecure ciphers will be removed in "
            "OpenVPN 2.7.",
            ciphername, cipher_kt_block_size(ciphername)*8);
    }
}

/*
 * Build a struct key_type.
 */
void
init_key_type(struct key_type *kt, const char *ciphername,
              const char *authname, bool tls_mode, bool warn)
{
    bool aead_cipher = false;

    ASSERT(ciphername);
    ASSERT(authname);

    CLEAR(*kt);
    kt->cipher = ciphername;
    if (strcmp(ciphername, "none") != 0)
    {
        if (!cipher_valid(ciphername))
        {
            msg(M_FATAL, "Cipher %s not supported", ciphername);
        }

        /* check legal cipher mode */
        aead_cipher = cipher_kt_mode_aead(kt->cipher);
        if (!(cipher_kt_mode_cbc(kt->cipher)
              || (tls_mode && aead_cipher)
#ifdef ENABLE_OFB_CFB_MODE
              || (tls_mode && cipher_kt_mode_ofb_cfb(kt->cipher))
#endif
              ))
        {
            msg(M_FATAL, "Cipher '%s' mode not supported", ciphername);
        }

        if (OPENVPN_MAX_CIPHER_BLOCK_SIZE < cipher_kt_block_size(kt->cipher))
        {
            msg(M_FATAL, "Cipher '%s' not allowed: block size too big.", ciphername);
        }
        if (warn)
        {
            warn_insecure_key_type(ciphername);
        }
    }
    else
    {
        if (warn)
        {
            msg(M_WARN, "******* WARNING *******: '--cipher none' was specified. "
                "This means NO encryption will be performed and tunnelled "
                "data WILL be transmitted in clear text over the network! "
                "PLEASE DO RECONSIDER THIS SETTING!");
        }
    }
    kt->digest = authname;
    if (strcmp(authname, "none") != 0)
    {
        if (aead_cipher) /* Ignore auth for AEAD ciphers */
        {
            kt->digest = "none";
        }
        else
        {
            int hmac_length = md_kt_size(kt->digest);

            if (OPENVPN_MAX_HMAC_SIZE < hmac_length)
            {
                msg(M_FATAL, "HMAC '%s' not allowed: digest size too big.", authname);
            }
        }
    }
    else if (!aead_cipher)
    {
        if (warn)
        {
            msg(M_WARN, "******* WARNING *******: '--auth none' was specified. "
                "This means no authentication will be performed on received "
                "packets, meaning you CANNOT trust that the data received by "
                "the remote side have NOT been manipulated. "
                "PLEASE DO RECONSIDER THIS SETTING!");
        }
    }
}

/* given a key and key_type, build a key_ctx */
void
init_key_ctx(struct key_ctx *ctx, const struct key *key,
             const struct key_type *kt, int enc,
             const char *prefix)
{
    struct gc_arena gc = gc_new();
    CLEAR(*ctx);
    if (cipher_defined(kt->cipher))
    {

        ctx->cipher = cipher_ctx_new();
        cipher_ctx_init(ctx->cipher, key->cipher, kt->cipher, enc);

        const char *ciphername = cipher_kt_name(kt->cipher);
        msg(D_CIPHER_INIT, "%s: Cipher '%s' initialized with %d bit key",
            prefix, ciphername, cipher_kt_key_size(kt->cipher) * 8);

        dmsg(D_SHOW_KEYS, "%s: CIPHER KEY: %s", prefix,
             format_hex(key->cipher, cipher_kt_key_size(kt->cipher), 0, &gc));
        dmsg(D_CRYPTO_DEBUG, "%s: CIPHER block_size=%d iv_size=%d",
             prefix, cipher_kt_block_size(kt->cipher),
             cipher_kt_iv_size(kt->cipher));
        warn_insecure_key_type(ciphername);
    }
    if (md_defined(kt->digest))
    {
        ctx->hmac = hmac_ctx_new();
        hmac_ctx_init(ctx->hmac, key->hmac, kt->digest);

        msg(D_CIPHER_INIT,
            "%s: Using %d bit message hash '%s' for HMAC authentication",
            prefix, md_kt_size(kt->digest) * 8, md_kt_name(kt->digest));

        dmsg(D_SHOW_KEYS, "%s: HMAC KEY: %s", prefix,
             format_hex(key->hmac, md_kt_size(kt->digest), 0, &gc));

        dmsg(D_CRYPTO_DEBUG, "%s: HMAC size=%d block_size=%d",
             prefix,
             md_kt_size(kt->digest),
             hmac_ctx_size(ctx->hmac));

    }
    gc_free(&gc);
}

void
init_key_ctx_bi(struct key_ctx_bi *ctx, const struct key2 *key2,
                int key_direction, const struct key_type *kt, const char *name)
{
    char log_prefix[128] = { 0 };
    struct key_direction_state kds;

    key_direction_state_init(&kds, key_direction);

    openvpn_snprintf(log_prefix, sizeof(log_prefix), "Outgoing %s", name);
    init_key_ctx(&ctx->encrypt, &key2->keys[kds.out_key], kt,
                 OPENVPN_OP_ENCRYPT, log_prefix);

    openvpn_snprintf(log_prefix, sizeof(log_prefix), "Incoming %s", name);
    init_key_ctx(&ctx->decrypt, &key2->keys[kds.in_key], kt,
                 OPENVPN_OP_DECRYPT, log_prefix);

    ctx->initialized = true;
}

void
free_key_ctx(struct key_ctx *ctx)
{
    if (ctx->cipher)
    {
        cipher_ctx_free(ctx->cipher);
        ctx->cipher = NULL;
    }
    if (ctx->hmac)
    {
        hmac_ctx_cleanup(ctx->hmac);
        hmac_ctx_free(ctx->hmac);
        ctx->hmac = NULL;
    }
    ctx->implicit_iv_len = 0;
}

void
free_key_ctx_bi(struct key_ctx_bi *ctx)
{
    free_key_ctx(&ctx->encrypt);
    free_key_ctx(&ctx->decrypt);
}

static bool
key_is_zero(struct key *key, const struct key_type *kt)
{
    int cipher_length = cipher_kt_key_size(kt->cipher);
    for (int i = 0; i < cipher_length; ++i)
    {
        if (key->cipher[i])
        {
            return false;
        }
    }
    msg(D_CRYPT_ERRORS, "CRYPTO INFO: WARNING: zero key detected");
    return true;
}

/*
 * Make sure that cipher key is a valid key for current key_type.
 */
bool
check_key(struct key *key, const struct key_type *kt)
{
    if (cipher_defined(kt->cipher))
    {
        /*
         * Check for zero key
         */
        if (key_is_zero(key, kt))
        {
            return false;
        }
    }
    return true;
}

void
check_replay_consistency(const struct key_type *kt, bool packet_id)
{
    ASSERT(kt);

    if (!packet_id && (cipher_kt_mode_ofb_cfb(kt->cipher)
                       || cipher_kt_mode_aead(kt->cipher)))
    {
        msg(M_FATAL, "--no-replay cannot be used with a CFB, OFB or AEAD mode cipher");
    }
}

/*
 * Generate a random key.  If key_type is provided, make
 * sure generated key is valid for key_type.
 */
void
generate_key_random(struct key *key, const struct key_type *kt)
{
    int cipher_len = MAX_CIPHER_KEY_LENGTH;
    int hmac_len = MAX_HMAC_KEY_LENGTH;

    struct gc_arena gc = gc_new();

    do
    {
        CLEAR(*key);
        if (kt)
        {
            cipher_len = cipher_kt_key_size(kt->cipher);

            int kt_hmac_length = md_kt_size(kt->digest);

            if (kt->digest && kt_hmac_length > 0 && kt_hmac_length <= hmac_len)
            {
                hmac_len = kt_hmac_length;
            }
        }
        if (!rand_bytes(key->cipher, cipher_len)
            || !rand_bytes(key->hmac, hmac_len))
        {
            msg(M_FATAL, "ERROR: Random number generator cannot obtain entropy for key generation");
        }

        dmsg(D_SHOW_KEY_SOURCE, "Cipher source entropy: %s", format_hex(key->cipher, cipher_len, 0, &gc));
        dmsg(D_SHOW_KEY_SOURCE, "HMAC source entropy: %s", format_hex(key->hmac, hmac_len, 0, &gc));

    } while (kt && !check_key(key, kt));

    gc_free(&gc);
}

static void
key_print(const struct key *key,
          const struct key_type *kt,
          const char *prefix)
{
    struct gc_arena gc = gc_new();
    dmsg(D_SHOW_KEY_SOURCE, "%s (cipher, %s, %d bits): %s",
         prefix, cipher_kt_name(kt->cipher), cipher_kt_key_size(kt->cipher) * 8,
         format_hex(key->cipher, cipher_kt_key_size(kt->cipher), 0, &gc));
    dmsg(D_SHOW_KEY_SOURCE, "%s (hmac, %s, %d bits): %s",
         prefix, md_kt_name(kt->digest), md_kt_size(kt->digest) * 8,
         format_hex(key->hmac, md_kt_size(kt->digest), 0, &gc));
    gc_free(&gc);
}
/**
 * Prints the keys in a key2 structure.
 */
void
key2_print(const struct key2 *k,
           const struct key_type *kt,
           const char *prefix0,
           const char *prefix1)
{
    ASSERT(k->n == 2);
    key_print(&k->keys[0], kt, prefix0);
    key_print(&k->keys[1], kt, prefix1);
}

void
test_crypto(struct crypto_options *co, struct frame *frame)
{
    int i, j;
    struct gc_arena gc = gc_new();
    struct buffer src = alloc_buf_gc(frame->buf.payload_size, &gc);
    struct buffer work = alloc_buf_gc(BUF_SIZE(frame), &gc);
    struct buffer encrypt_workspace = alloc_buf_gc(BUF_SIZE(frame), &gc);
    struct buffer decrypt_workspace = alloc_buf_gc(BUF_SIZE(frame), &gc);
    struct buffer buf = clear_buf();
    void *buf_p;

    /* init work */
    ASSERT(buf_init(&work, frame->buf.headroom));

    /* init implicit IV */
    {
        cipher_ctx_t *cipher = co->key_ctx_bi.encrypt.cipher;
        if (cipher_ctx_mode_aead(cipher))
        {
            size_t impl_iv_len = cipher_ctx_iv_length(cipher) - sizeof(packet_id_type);
            ASSERT(cipher_ctx_iv_length(cipher) <= OPENVPN_MAX_IV_LENGTH);
            ASSERT(cipher_ctx_iv_length(cipher) >= OPENVPN_AEAD_MIN_IV_LEN);

            /* Generate dummy implicit IV */
            ASSERT(rand_bytes(co->key_ctx_bi.encrypt.implicit_iv,
                              OPENVPN_MAX_IV_LENGTH));
            co->key_ctx_bi.encrypt.implicit_iv_len = impl_iv_len;

            memcpy(co->key_ctx_bi.decrypt.implicit_iv,
                   co->key_ctx_bi.encrypt.implicit_iv, OPENVPN_MAX_IV_LENGTH);
            co->key_ctx_bi.decrypt.implicit_iv_len = impl_iv_len;
        }
    }

    msg(M_INFO, "Entering " PACKAGE_NAME " crypto self-test mode.");
    for (i = 1; i <= frame->buf.payload_size; ++i)
    {
        update_time();

        msg(M_INFO, "TESTING ENCRYPT/DECRYPT of packet length=%d", i);

        /*
         * Load src with random data.
         */
        ASSERT(buf_init(&src, 0));
        ASSERT(i <= src.capacity);
        src.len = i;
        ASSERT(rand_bytes(BPTR(&src), BLEN(&src)));

        /* copy source to input buf */
        buf = work;
        buf_p = buf_write_alloc(&buf, BLEN(&src));
        ASSERT(buf_p);
        memcpy(buf_p, BPTR(&src), BLEN(&src));

        /* initialize work buffer with buf.headroom bytes of prepend capacity */
        ASSERT(buf_init(&encrypt_workspace, frame->buf.headroom));

        /* encrypt */
        openvpn_encrypt(&buf, encrypt_workspace, co);

        /* decrypt */
        openvpn_decrypt(&buf, decrypt_workspace, co, frame, BPTR(&buf));

        /* compare */
        if (buf.len != src.len)
        {
            msg(M_FATAL, "SELF TEST FAILED, src.len=%d buf.len=%d", src.len, buf.len);
        }
        for (j = 0; j < i; ++j)
        {
            const uint8_t in = *(BPTR(&src) + j);
            const uint8_t out = *(BPTR(&buf) + j);
            if (in != out)
            {
                msg(M_FATAL, "SELF TEST FAILED, pos=%d in=%d out=%d", j, in, out);
            }
        }
    }
    msg(M_INFO, PACKAGE_NAME " crypto self-test mode SUCCEEDED.");
    gc_free(&gc);
}

const char *
print_key_filename(const char *str, bool is_inline)
{
    if (is_inline)
    {
        return "[[INLINE]]";
    }

    return np(str);
}

void
crypto_read_openvpn_key(const struct key_type *key_type,
                        struct key_ctx_bi *ctx, const char *key_file,
                        bool key_inline, const int key_direction,
                        const char *key_name, const char *opt_name,
                        struct key2 *keydata)
{
    struct key2 key2;
    struct key_direction_state kds;
    unsigned int flags = RKF_MUST_SUCCEED;

    if (key_inline)
    {
        flags |= RKF_INLINE;
    }
    read_key_file(&key2, key_file, flags);

    if (key2.n != 2)
    {
        msg(M_ERR, "File '%s' does not have OpenVPN Static Key format.  Using "
            "free-form passphrase file is not supported anymore.",
            print_key_filename(key_file, key_inline));
    }

    /* check for and fix highly unlikely key problems */
    verify_fix_key2(&key2, key_type, key_file);

    /* handle key direction */
    key_direction_state_init(&kds, key_direction);
    must_have_n_keys(key_file, opt_name, &key2, kds.need_keys);

    /* initialize key in both directions */
    init_key_ctx_bi(ctx, &key2, key_direction, key_type, key_name);
    if (keydata)
    {
        *keydata = key2;
    }
    secure_memzero(&key2, sizeof(key2));
}

/* header and footer for static key file */
static const char static_key_head[] = "-----BEGIN OpenVPN Static key V1-----";
static const char static_key_foot[] = "-----END OpenVPN Static key V1-----";

static const char printable_char_fmt[] =
    "Non-Hex character ('%c') found at line %d in key file '%s' (%d/%d/%d bytes found/min/max)";

static const char unprintable_char_fmt[] =
    "Non-Hex, unprintable character (0x%02x) found at line %d in key file '%s' (%d/%d/%d bytes found/min/max)";

/* read key from file */

void
read_key_file(struct key2 *key2, const char *file, const unsigned int flags)
{
    struct gc_arena gc = gc_new();
    struct buffer in;
    int size;
    uint8_t hex_byte[3] = {0, 0, 0};

    /* parse info */
    const unsigned char *cp;
    int hb_index = 0;
    int line_num = 1;
    int line_index = 0;
    int match = 0;

    /* output */
    uint8_t *out = (uint8_t *) &key2->keys;
    const int keylen = sizeof(key2->keys);
    int count = 0;

    /* parse states */
#define PARSE_INITIAL        0
#define PARSE_HEAD           1
#define PARSE_DATA           2
#define PARSE_DATA_COMPLETE  3
#define PARSE_FOOT           4
#define PARSE_FINISHED       5
    int state = PARSE_INITIAL;

    /* constants */
    const int hlen = strlen(static_key_head);
    const int flen = strlen(static_key_foot);
    const int onekeylen = sizeof(key2->keys[0]);

    CLEAR(*key2);

    /*
     * Key can be provided as a filename in 'file' or if RKF_INLINE
     * is set, the actual key data itself in ascii form.
     */
    if (flags & RKF_INLINE) /* 'file' is a string containing ascii representation of key */
    {
        size = strlen(file) + 1;
        buf_set_read(&in, (const uint8_t *)file, size);
    }
    else /* 'file' is a filename which refers to a file containing the ascii key */
    {
        in = buffer_read_from_file(file, &gc);
        if (!buf_valid(&in))
        {
            msg(M_FATAL, "Read error on key file ('%s')", file);
        }

        size = in.len;
    }

    cp = (unsigned char *)in.data;
    while (size > 0)
    {
        const unsigned char c = *cp;

#if 0
        msg(M_INFO, "char='%c'[%d] s=%d ln=%d li=%d m=%d c=%d",
            c, (int)c, state, line_num, line_index, match, count);
#endif

        if (c == '\n')
        {
            line_index = match = 0;
            ++line_num;
        }
        else
        {
            /* first char of new line */
            if (!line_index)
            {
                /* first char of line after header line? */
                if (state == PARSE_HEAD)
                {
                    state = PARSE_DATA;
                }

                /* first char of footer */
                if ((state == PARSE_DATA || state == PARSE_DATA_COMPLETE) && c == '-')
                {
                    state = PARSE_FOOT;
                }
            }

            /* compare read chars with header line */
            if (state == PARSE_INITIAL)
            {
                if (line_index < hlen && c == static_key_head[line_index])
                {
                    if (++match == hlen)
                    {
                        state = PARSE_HEAD;
                    }
                }
            }

            /* compare read chars with footer line */
            if (state == PARSE_FOOT)
            {
                if (line_index < flen && c == static_key_foot[line_index])
                {
                    if (++match == flen)
                    {
                        state = PARSE_FINISHED;
                    }
                }
            }

            /* reading key */
            if (state == PARSE_DATA)
            {
                if (isxdigit(c))
                {
                    ASSERT(hb_index >= 0 && hb_index < 2);
                    hex_byte[hb_index++] = c;
                    if (hb_index == 2)
                    {
                        unsigned int u;
                        ASSERT(sscanf((const char *)hex_byte, "%x", &u) == 1);
                        *out++ = u;
                        hb_index = 0;
                        if (++count == keylen)
                        {
                            state = PARSE_DATA_COMPLETE;
                        }
                    }
                }
                else if (isspace(c))
                {
                    /* ignore white space characters */
                }
                else
                {
                    msg(M_FATAL,
                        (isprint(c) ? printable_char_fmt : unprintable_char_fmt),
                        c, line_num,
                        print_key_filename(file, flags & RKF_INLINE), count,
                        onekeylen, keylen);
                }
            }
            ++line_index;
        }
        ++cp;
        --size;
    }

    /*
     * Normally we will read either 1 or 2 keys from file.
     */
    key2->n = count / onekeylen;

    ASSERT(key2->n >= 0 && key2->n <= (int) SIZE(key2->keys));

    if (flags & RKF_MUST_SUCCEED)
    {
        if (!key2->n)
        {
            msg(M_FATAL, "Insufficient key material or header text not found in file '%s' (%d/%d/%d bytes found/min/max)",
                print_key_filename(file, flags & RKF_INLINE), count, onekeylen,
                keylen);
        }

        if (state != PARSE_FINISHED)
        {
            msg(M_FATAL, "Footer text not found in file '%s' (%d/%d/%d bytes found/min/max)",
                print_key_filename(file, flags & RKF_INLINE), count, onekeylen,
                keylen);
        }
    }

    /* zero file read buffer if not an inline file */
    if (!(flags & RKF_INLINE))
    {
        buf_clear(&in);
    }

#if 0
    /* DEBUGGING */
    {
        int i;
        printf("KEY READ, n=%d\n", key2->n);
        for (i = 0; i < (int) SIZE(key2->keys); ++i)
        {
            /* format key as ascii */
            const char *fmt = format_hex_ex((const uint8_t *)&key2->keys[i],
                                            sizeof(key2->keys[i]),
                                            0,
                                            16,
                                            "\n",
                                            &gc);
            printf("[%d]\n%s\n\n", i, fmt);
        }
    }
#endif

    /* pop our garbage collection level */
    gc_free(&gc);
}

int
write_key_file(const int nkeys, const char *filename)
{
    struct gc_arena gc = gc_new();

    int nbits = nkeys * sizeof(struct key) * 8;

    /* must be large enough to hold full key file */
    struct buffer out = alloc_buf_gc(2048, &gc);

    /* how to format the ascii file representation of key */
    const int bytes_per_line = 16;

    /* write header */
    buf_printf(&out, "#\n# %d bit OpenVPN static key\n#\n", nbits);
    buf_printf(&out, "%s\n", static_key_head);

    for (int i = 0; i < nkeys; ++i)
    {
        struct key key;
        char *fmt;

        /* generate random bits */
        generate_key_random(&key, NULL);

        /* format key as ascii */
        fmt = format_hex_ex((const uint8_t *)&key,
                            sizeof(key),
                            0,
                            bytes_per_line,
                            "\n",
                            &gc);

        /* write to holding buffer */
        buf_printf(&out, "%s\n", fmt);

        /* zero memory which held key component (will be freed by GC) */
        secure_memzero(fmt, strlen(fmt));
        secure_memzero(&key, sizeof(key));
    }

    buf_printf(&out, "%s\n", static_key_foot);

    /* write key file to stdout if no filename given */
    if (!filename || strcmp(filename, "")==0)
    {
        printf("%.*s\n", BLEN(&out), BPTR(&out));
    }
    /* write key file, now formatted in out, to file */
    else if (!buffer_write_file(filename, &out))
    {
        nbits = -1;
    }

    /* zero memory which held file content (memory will be freed by GC) */
    buf_clear(&out);

    /* pop our garbage collection level */
    gc_free(&gc);

    return nbits;
}

void
must_have_n_keys(const char *filename, const char *option, const struct key2 *key2, int n)
{
    if (key2->n < n)
    {
#ifdef ENABLE_SMALL
        msg(M_FATAL, "Key file '%s' used in --%s contains insufficient key material [keys found=%d required=%d]", filename, option, key2->n, n);
#else
        msg(M_FATAL, "Key file '%s' used in --%s contains insufficient key material [keys found=%d required=%d] -- try generating a new key file with '" PACKAGE " --genkey secret [file]', or use the existing key file in bidirectional mode by specifying --%s without a key direction parameter", filename, option, key2->n, n, option);
#endif
    }
}

int
ascii2keydirection(int msglevel, const char *str)
{
    if (!str)
    {
        return KEY_DIRECTION_BIDIRECTIONAL;
    }
    else if (!strcmp(str, "0"))
    {
        return KEY_DIRECTION_NORMAL;
    }
    else if (!strcmp(str, "1"))
    {
        return KEY_DIRECTION_INVERSE;
    }
    else
    {
        msg(msglevel, "Unknown key direction '%s' -- must be '0' or '1'", str);
        return -1;
    }
    return KEY_DIRECTION_BIDIRECTIONAL; /* NOTREACHED */
}

const char *
keydirection2ascii(int kd, bool remote, bool humanreadable)
{
    if (kd == KEY_DIRECTION_BIDIRECTIONAL)
    {
        if (humanreadable)
        {
            return "not set";
        }
        else
        {
            return NULL;
        }
    }
    else if (kd == KEY_DIRECTION_NORMAL)
    {
        return remote ? "1" : "0";
    }
    else if (kd == KEY_DIRECTION_INVERSE)
    {
        return remote ? "0" : "1";
    }
    else
    {
        ASSERT(0);
    }
    return NULL; /* NOTREACHED */
}

void
key_direction_state_init(struct key_direction_state *kds, int key_direction)
{
    CLEAR(*kds);
    switch (key_direction)
    {
        case KEY_DIRECTION_NORMAL:
            kds->out_key = 0;
            kds->in_key = 1;
            kds->need_keys = 2;
            break;

        case KEY_DIRECTION_INVERSE:
            kds->out_key = 1;
            kds->in_key = 0;
            kds->need_keys = 2;
            break;

        case KEY_DIRECTION_BIDIRECTIONAL:
            kds->out_key = 0;
            kds->in_key = 0;
            kds->need_keys = 1;
            break;

        default:
            ASSERT(0);
    }
}

void
verify_fix_key2(struct key2 *key2, const struct key_type *kt, const char *shared_secret_file)
{
    int i;

    for (i = 0; i < key2->n; ++i)
    {
        /* This should be a very improbable failure */
        if (!check_key(&key2->keys[i], kt))
        {
            msg(M_FATAL, "Key #%d in '%s' is bad.  Try making a new key with --genkey.",
                i+1, shared_secret_file);
        }
    }
}

/* given a key and key_type, write key to buffer */
bool
write_key(const struct key *key, const struct key_type *kt,
          struct buffer *buf)
{
    ASSERT(cipher_kt_key_size(kt->cipher) <= MAX_CIPHER_KEY_LENGTH
           && md_kt_size(kt->digest) <= MAX_HMAC_KEY_LENGTH);

    const uint8_t cipher_length = cipher_kt_key_size(kt->cipher);
    if (!buf_write(buf, &cipher_length, 1))
    {
        return false;
    }

    uint8_t hmac_length = md_kt_size(kt->digest);

    if (!buf_write(buf, &hmac_length, 1))
    {
        return false;
    }
    if (!buf_write(buf, key->cipher, cipher_kt_key_size(kt->cipher)))
    {
        return false;
    }
    if (!buf_write(buf, key->hmac, hmac_length))
    {
        return false;
    }

    return true;
}

/*
 * Given a key_type and buffer, read key from buffer.
 * Return: 1 on success
 *        -1 read failure
 *         0 on key length mismatch
 */
int
read_key(struct key *key, const struct key_type *kt, struct buffer *buf)
{
    uint8_t cipher_length;
    uint8_t hmac_length;

    CLEAR(*key);
    if (!buf_read(buf, &cipher_length, 1))
    {
        goto read_err;
    }
    if (!buf_read(buf, &hmac_length, 1))
    {
        goto read_err;
    }

    if (cipher_length != cipher_kt_key_size(kt->cipher) || hmac_length != md_kt_size(kt->digest))
    {
        goto key_len_err;
    }

    if (!buf_read(buf, key->cipher, cipher_length))
    {
        goto read_err;
    }
    if (!buf_read(buf, key->hmac, hmac_length))
    {
        goto read_err;
    }

    return 1;

read_err:
    msg(D_TLS_ERRORS, "TLS Error: error reading key from remote");
    return -1;

key_len_err:
    msg(D_TLS_ERRORS,
        "TLS Error: key length mismatch, local cipher/hmac %d/%d, remote cipher/hmac %d/%d",
        cipher_kt_key_size(kt->cipher), md_kt_size(kt->digest), cipher_length, hmac_length);
    return 0;
}

void
prng_bytes(uint8_t *output, int len)
{
    ASSERT(rand_bytes(output, len));
}

/* an analogue to the random() function, but use prng_bytes */
long int
get_random(void)
{
    long int l;
    prng_bytes((unsigned char *)&l, sizeof(l));
    if (l < 0)
    {
        l = -l;
    }
    return l;
}

void
print_cipher(const char *ciphername)
{
    printf("%s  (%d bit key, ",
           cipher_kt_name(ciphername),
           cipher_kt_key_size(ciphername) * 8);

    if (cipher_kt_block_size(ciphername) == 1)
    {
        printf("stream cipher");
    }
    else
    {
        printf("%d bit block", cipher_kt_block_size(ciphername) * 8);
    }

    if (!cipher_kt_mode_cbc(ciphername))
    {
        printf(", TLS client/server mode only");
    }

    const char *reason;
    if (!cipher_valid_reason(ciphername, &reason))
    {
        printf(", %s", reason);
    }

    printf(")\n");
}

static const cipher_name_pair *
get_cipher_name_pair(const char *cipher_name)
{
    const cipher_name_pair *pair;
    size_t i = 0;

    /* Search for a cipher name translation */
    for (; i < cipher_name_translation_table_count; i++)
    {
        pair = &cipher_name_translation_table[i];
        if (0 == strcmp(cipher_name, pair->openvpn_name)
            || 0 == strcmp(cipher_name, pair->lib_name))
        {
            return pair;
        }
    }

    /* Nothing found, return null */
    return NULL;
}

const char *
translate_cipher_name_from_openvpn(const char *cipher_name)
{
    const cipher_name_pair *pair = get_cipher_name_pair(cipher_name);

    if (NULL == pair)
    {
        return cipher_name;
    }

    return pair->lib_name;
}

const char *
translate_cipher_name_to_openvpn(const char *cipher_name)
{
    const cipher_name_pair *pair = get_cipher_name_pair(cipher_name);

    if (NULL == pair)
    {
        return cipher_name;
    }

    return pair->openvpn_name;
}

void
write_pem_key_file(const char *filename, const char *pem_name)
{
    struct gc_arena gc = gc_new();
    struct key server_key = { 0 };
    struct buffer server_key_buf = clear_buf();
    struct buffer server_key_pem = clear_buf();

    if (!rand_bytes((void *)&server_key, sizeof(server_key)))
    {
        msg(M_NONFATAL, "ERROR: could not generate random key");
        goto cleanup;
    }
    buf_set_read(&server_key_buf, (void *)&server_key, sizeof(server_key));
    if (!crypto_pem_encode(pem_name, &server_key_pem,
                           &server_key_buf, &gc))
    {
        msg(M_WARN, "ERROR: could not PEM-encode key");
        goto cleanup;
    }

    if (!filename || strcmp(filename, "")==0)
    {
        printf("%.*s", BLEN(&server_key_pem), BPTR(&server_key_pem));
    }
    else if (!buffer_write_file(filename, &server_key_pem))
    {
        msg(M_ERR, "ERROR: could not write key file");
        goto cleanup;
    }

cleanup:
    secure_memzero(&server_key, sizeof(server_key));
    buf_clear(&server_key_pem);
    gc_free(&gc);
    return;
}

bool
generate_ephemeral_key(struct buffer *key, const char *key_name)
{
    const int len = BCAP(key);

    msg(M_INFO, "Using random %s.", key_name);

    if (!rand_bytes(BEND(key), len))
    {
        msg(M_WARN, "ERROR: could not generate random key");
        return false;
    }

    buf_inc_len(key, len);

    return true;
}

bool
read_pem_key_file(struct buffer *key, const char *pem_name,
                  const char *key_file, bool key_inline)
{
    bool ret = false;
    struct buffer key_pem = { 0 };
    struct gc_arena gc = gc_new();

    if (!key_inline)
    {
        key_pem = buffer_read_from_file(key_file, &gc);
        if (!buf_valid(&key_pem))
        {
            msg(M_WARN, "ERROR: failed to read %s file (%s)",
                pem_name, key_file);
            goto cleanup;
        }
    }
    else
    {
        buf_set_read(&key_pem, (const void *)key_file, strlen(key_file) + 1);
    }

    if (!crypto_pem_decode(pem_name, key, &key_pem))
    {
        msg(M_WARN, "ERROR: %s pem decode failed", pem_name);
        goto cleanup;
    }

    ret = true;
cleanup:
    if (!key_inline)
    {
        buf_clear(&key_pem);
    }
    gc_free(&gc);
    return ret;
}
