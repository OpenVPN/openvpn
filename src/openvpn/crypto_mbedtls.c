/*
 *  OpenVPN -- An application to securely tunnel IP networks
 *             over a single TCP/UDP port, with support for SSL/TLS-based
 *             session authentication and key exchange,
 *             packet encryption, packet authentication, and
 *             packet compression.
 *
 *  Copyright (C) 2002-2022 OpenVPN Inc <sales@openvpn.net>
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

/**
 * @file Data Channel Cryptography mbed TLS-specific backend interface
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#elif defined(_MSC_VER)
#include "config-msvc.h"
#endif

#include "syshead.h"

#if defined(ENABLE_CRYPTO_MBEDTLS)

#include "errlevel.h"
#include "basic.h"
#include "buffer.h"
#include "crypto.h"
#include "integer.h"
#include "crypto_backend.h"
#include "otime.h"
#include "misc.h"

#include <mbedtls/base64.h>
#include <mbedtls/des.h>
#include <mbedtls/error.h>
#include <mbedtls/md5.h>
#include <mbedtls/cipher.h>
#include <mbedtls/havege.h>
#include <mbedtls/pem.h>

#include <mbedtls/entropy.h>


/*
 *
 * Hardware engine support. Allows loading/unloading of engines.
 *
 */

void
crypto_init_lib_engine(const char *engine_name)
{
    msg(M_WARN, "Note: mbed TLS hardware crypto engine functionality is not "
        "available");
}

provider_t *crypto_load_provider(const char *provider)
{
    if (provider)
    {
        msg(M_WARN, "Note: mbed TLS provider functionality is not available");
    }
    return NULL;
}

void crypto_unload_provider(const char *provname, provider_t *provider)
{
}

/*
 *
 * Functions related to the core crypto library
 *
 */

void
crypto_init_lib(void)
{
}

void
crypto_uninit_lib(void)
{
}

void
crypto_clear_error(void)
{
}

bool
mbed_log_err(unsigned int flags, int errval, const char *prefix)
{
    if (0 != errval)
    {
        char errstr[256];
        mbedtls_strerror(errval, errstr, sizeof(errstr));

        if (NULL == prefix)
        {
            prefix = "mbed TLS error";
        }
        msg(flags, "%s: %s", prefix, errstr);
    }

    return 0 == errval;
}

bool
mbed_log_func_line(unsigned int flags, int errval, const char *func,
                   int line)
{
    char prefix[256];

    if (!openvpn_snprintf(prefix, sizeof(prefix), "%s:%d", func, line))
    {
        return mbed_log_err(flags, errval, func);
    }

    return mbed_log_err(flags, errval, prefix);
}


#ifdef DMALLOC
void
crypto_init_dmalloc(void)
{
    msg(M_ERR, "Error: dmalloc support is not available for mbed TLS.");
}
#endif /* DMALLOC */

const cipher_name_pair cipher_name_translation_table[] = {
    { "BF-CBC", "BLOWFISH-CBC" },
    { "BF-CFB", "BLOWFISH-CFB64" },
    { "CAMELLIA-128-CFB", "CAMELLIA-128-CFB128" },
    { "CAMELLIA-192-CFB", "CAMELLIA-192-CFB128" },
    { "CAMELLIA-256-CFB", "CAMELLIA-256-CFB128" }
};
const size_t cipher_name_translation_table_count =
    sizeof(cipher_name_translation_table) / sizeof(*cipher_name_translation_table);

void
show_available_ciphers(void)
{
    const int *ciphers = mbedtls_cipher_list();

#ifndef ENABLE_SMALL
    printf("The following ciphers and cipher modes are available for use\n"
           "with " PACKAGE_NAME ".  Each cipher shown below may be used as a\n"
           "parameter to the --data-ciphers (or --cipher) option.  Using a\n"
           "GCM or CBC mode is recommended.  In static key mode only CBC\n"
           "mode is allowed.\n\n");
#endif

    while (*ciphers != 0)
    {
        const cipher_kt_t *info = mbedtls_cipher_info_from_type(*ciphers);
        if (info && !cipher_kt_insecure(info)
            && (cipher_kt_mode_aead(info) || cipher_kt_mode_cbc(info)))
        {
            print_cipher(info);
        }
        ciphers++;
    }

    printf("\nThe following ciphers have a block size of less than 128 bits, \n"
           "and are therefore deprecated.  Do not use unless you have to.\n\n");
    ciphers = mbedtls_cipher_list();
    while (*ciphers != 0)
    {
        const cipher_kt_t *info = mbedtls_cipher_info_from_type(*ciphers);
        if (info && cipher_kt_insecure(info)
            && (cipher_kt_mode_aead(info) || cipher_kt_mode_cbc(info)))
        {
            print_cipher(info);
        }
        ciphers++;
    }
    printf("\n");
}

void
show_available_digests(void)
{
    const int *digests = mbedtls_md_list();

#ifndef ENABLE_SMALL
    printf("The following message digests are available for use with\n"
           PACKAGE_NAME ".  A message digest is used in conjunction with\n"
           "the HMAC function, to authenticate received packets.\n"
           "You can specify a message digest as parameter to\n"
           "the --auth option.\n\n");
#endif

    while (*digests != 0)
    {
        const mbedtls_md_info_t *info = mbedtls_md_info_from_type(*digests);

        if (info)
        {
            printf("%s %d bit default key\n", mbedtls_md_get_name(info),
                   mbedtls_md_get_size(info) * 8);
        }
        digests++;
    }
    printf("\n");
}

void
show_available_engines(void)
{
    printf("Sorry, mbed TLS hardware crypto engine functionality is not "
           "available\n");
}

bool
crypto_pem_encode(const char *name, struct buffer *dst,
                  const struct buffer *src, struct gc_arena *gc)
{
    /* 1000 chars is the PEM line length limit (+1 for tailing NUL) */
    char header[1000+1] = { 0 };
    char footer[1000+1] = { 0 };

    if (!openvpn_snprintf(header, sizeof(header), "-----BEGIN %s-----\n", name))
    {
        return false;
    }
    if (!openvpn_snprintf(footer, sizeof(footer), "-----END %s-----\n", name))
    {
        return false;
    }

    size_t out_len = 0;
    if (MBEDTLS_ERR_BASE64_BUFFER_TOO_SMALL !=
        mbedtls_pem_write_buffer(header, footer, BPTR(src), BLEN(src),
                                 NULL, 0, &out_len))
    {
        return false;
    }

    /* We set the size buf to out_len-1 to NOT include the 0 byte that
     * mbedtls_pem_write_buffer in its length calculation */
    *dst = alloc_buf_gc(out_len, gc);
    if (!mbed_ok(mbedtls_pem_write_buffer(header, footer, BPTR(src), BLEN(src),
                                          BPTR(dst), BCAP(dst), &out_len))
        || !buf_inc_len(dst, out_len-1))
    {
        CLEAR(*dst);
        return false;
    }

    return true;
}

bool
crypto_pem_decode(const char *name, struct buffer *dst,
                  const struct buffer *src)
{
    /* 1000 chars is the PEM line length limit (+1 for tailing NUL) */
    char header[1000+1] = { 0 };
    char footer[1000+1] = { 0 };

    if (!openvpn_snprintf(header, sizeof(header), "-----BEGIN %s-----", name))
    {
        return false;
    }
    if (!openvpn_snprintf(footer, sizeof(footer), "-----END %s-----", name))
    {
        return false;
    }

    /* mbed TLS requires the src to be null-terminated */
    /* allocate a new buffer to avoid modifying the src buffer */
    struct gc_arena gc = gc_new();
    struct buffer input = alloc_buf_gc(BLEN(src) + 1, &gc);
    buf_copy(&input, src);
    buf_null_terminate(&input);

    size_t use_len = 0;
    mbedtls_pem_context ctx = { 0 };
    bool ret = mbed_ok(mbedtls_pem_read_buffer(&ctx, header, footer, BPTR(&input),
                                               NULL, 0, &use_len));
    if (ret && !buf_write(dst, ctx.buf, ctx.buflen))
    {
        ret = false;
        msg(M_WARN, "PEM decode error: destination buffer too small");
    }

    mbedtls_pem_free(&ctx);
    gc_free(&gc);
    return ret;
}

/*
 *
 * Random number functions, used in cases where we want
 * reasonably strong cryptographic random number generation
 * without depleting our entropy pool.  Used for random
 * IV values and a number of other miscellaneous tasks.
 *
 */

/*
 * Initialise the given ctr_drbg context, using a personalisation string and an
 * entropy gathering function.
 */
mbedtls_ctr_drbg_context *
rand_ctx_get(void)
{
    static mbedtls_entropy_context ec = {0};
    static mbedtls_ctr_drbg_context cd_ctx = {0};
    static bool rand_initialised = false;

    if (!rand_initialised)
    {
        struct gc_arena gc = gc_new();
        struct buffer pers_string = alloc_buf_gc(100, &gc);

        /*
         * Personalisation string, should be as unique as possible (see NIST
         * 800-90 section 8.7.1). We have very little information at this stage.
         * Include Program Name, memory address of the context and PID.
         */
        buf_printf(&pers_string, "OpenVPN %0u %p %s", platform_getpid(), &cd_ctx, time_string(0, 0, 0, &gc));

        /* Initialise mbed TLS RNG, and built-in entropy sources */
        mbedtls_entropy_init(&ec);

        mbedtls_ctr_drbg_init(&cd_ctx);
        if (!mbed_ok(mbedtls_ctr_drbg_seed(&cd_ctx, mbedtls_entropy_func, &ec,
                                           BPTR(&pers_string), BLEN(&pers_string))))
        {
            msg(M_FATAL, "Failed to initialize random generator");
        }

        gc_free(&gc);
        rand_initialised = true;
    }

    return &cd_ctx;
}

#ifdef ENABLE_PREDICTION_RESISTANCE
void
rand_ctx_enable_prediction_resistance(void)
{
    mbedtls_ctr_drbg_context *cd_ctx = rand_ctx_get();

    mbedtls_ctr_drbg_set_prediction_resistance(cd_ctx, 1);
}
#endif /* ENABLE_PREDICTION_RESISTANCE */

int
rand_bytes(uint8_t *output, int len)
{
    mbedtls_ctr_drbg_context *rng_ctx = rand_ctx_get();

    while (len > 0)
    {
        const size_t blen = min_int(len, MBEDTLS_CTR_DRBG_MAX_REQUEST);
        if (0 != mbedtls_ctr_drbg_random(rng_ctx, output, blen))
        {
            return 0;
        }

        output += blen;
        len -= blen;
    }

    return 1;
}

/*
 *
 * Key functions, allow manipulation of keys.
 *
 */


int
key_des_num_cblocks(const mbedtls_cipher_info_t *kt)
{
    int ret = 0;
    if (kt->type == MBEDTLS_CIPHER_DES_CBC)
    {
        ret = 1;
    }
    if (kt->type == MBEDTLS_CIPHER_DES_EDE_CBC)
    {
        ret = 2;
    }
    if (kt->type == MBEDTLS_CIPHER_DES_EDE3_CBC)
    {
        ret = 3;
    }

    dmsg(D_CRYPTO_DEBUG, "CRYPTO INFO: n_DES_cblocks=%d", ret);
    return ret;
}

bool
key_des_check(uint8_t *key, int key_len, int ndc)
{
    int i;
    struct buffer b;

    buf_set_read(&b, key, key_len);

    for (i = 0; i < ndc; ++i)
    {
        unsigned char *key = buf_read_alloc(&b, MBEDTLS_DES_KEY_SIZE);
        if (!key)
        {
            msg(D_CRYPT_ERRORS, "CRYPTO INFO: check_key_DES: insufficient key material");
            goto err;
        }
        if (0 != mbedtls_des_key_check_weak(key))
        {
            msg(D_CRYPT_ERRORS, "CRYPTO INFO: check_key_DES: weak key detected");
            goto err;
        }
        if (0 != mbedtls_des_key_check_key_parity(key))
        {
            msg(D_CRYPT_ERRORS, "CRYPTO INFO: check_key_DES: bad parity detected");
            goto err;
        }
    }
    return true;

err:
    return false;
}

void
key_des_fixup(uint8_t *key, int key_len, int ndc)
{
    int i;
    struct buffer b;

    buf_set_read(&b, key, key_len);
    for (i = 0; i < ndc; ++i)
    {
        unsigned char *key = buf_read_alloc(&b, MBEDTLS_DES_KEY_SIZE);
        if (!key)
        {
            msg(D_CRYPT_ERRORS, "CRYPTO INFO: fixup_key_DES: insufficient key material");
            return;
        }
        mbedtls_des_key_set_parity(key);
    }
}

/*
 *
 * Generic cipher key type functions
 *
 */


const mbedtls_cipher_info_t *
cipher_kt_get(const char *ciphername)
{
    const mbedtls_cipher_info_t *cipher = NULL;

    ASSERT(ciphername);

    ciphername = translate_cipher_name_from_openvpn(ciphername);
    cipher = mbedtls_cipher_info_from_string(ciphername);

    if (NULL == cipher)
    {
        msg(D_LOW, "Cipher algorithm '%s' not found", ciphername);
        return NULL;
    }

    if (cipher->key_bitlen/8 > MAX_CIPHER_KEY_LENGTH)
    {
        msg(D_LOW, "Cipher algorithm '%s' uses a default key size (%d bytes) "
            "which is larger than " PACKAGE_NAME "'s current maximum key size "
            "(%d bytes)", ciphername, cipher->key_bitlen/8, MAX_CIPHER_KEY_LENGTH);
        return NULL;
    }

    return cipher;
}

const char *
cipher_kt_name(const mbedtls_cipher_info_t *cipher_kt)
{
    if (NULL == cipher_kt)
    {
        return "[null-cipher]";
    }

    return translate_cipher_name_to_openvpn(cipher_kt->name);
}

int
cipher_kt_key_size(const mbedtls_cipher_info_t *cipher_kt)
{
    if (NULL == cipher_kt)
    {
        return 0;
    }

    return cipher_kt->key_bitlen/8;
}

int
cipher_kt_iv_size(const mbedtls_cipher_info_t *cipher_kt)
{
    if (NULL == cipher_kt)
    {
        return 0;
    }
    return cipher_kt->iv_size;
}

int
cipher_kt_block_size(const mbedtls_cipher_info_t *cipher_kt)
{
    if (NULL == cipher_kt)
    {
        return 0;
    }
    return cipher_kt->block_size;
}

int
cipher_kt_tag_size(const mbedtls_cipher_info_t *cipher_kt)
{
    if (cipher_kt && cipher_kt_mode_aead(cipher_kt))
    {
        return OPENVPN_AEAD_TAG_LENGTH;
    }
    return 0;
}

bool
cipher_kt_insecure(const mbedtls_cipher_info_t *cipher_kt)
{
    return !(cipher_kt_block_size(cipher_kt) >= 128 / 8
#ifdef MBEDTLS_CHACHAPOLY_C
             || cipher_kt->type == MBEDTLS_CIPHER_CHACHA20_POLY1305
#endif
             );
}

int
cipher_kt_mode(const mbedtls_cipher_info_t *cipher_kt)
{
    ASSERT(NULL != cipher_kt);
    return cipher_kt->mode;
}

bool
cipher_kt_mode_cbc(const cipher_kt_t *cipher)
{
    return cipher && cipher_kt_mode(cipher) == OPENVPN_MODE_CBC;
}

bool
cipher_kt_mode_ofb_cfb(const cipher_kt_t *cipher)
{
    return cipher && (cipher_kt_mode(cipher) == OPENVPN_MODE_OFB
                      || cipher_kt_mode(cipher) == OPENVPN_MODE_CFB);
}

bool
cipher_kt_mode_aead(const cipher_kt_t *cipher)
{
    return cipher && (cipher_kt_mode(cipher) == OPENVPN_MODE_GCM
#ifdef MBEDTLS_CHACHAPOLY_C
                      || cipher_kt_mode(cipher) == MBEDTLS_MODE_CHACHAPOLY
#endif
                      );
}


/*
 *
 * Generic cipher context functions
 *
 */

mbedtls_cipher_context_t *
cipher_ctx_new(void)
{
    mbedtls_cipher_context_t *ctx;
    ALLOC_OBJ(ctx, mbedtls_cipher_context_t);
    return ctx;
}

void
cipher_ctx_free(mbedtls_cipher_context_t *ctx)
{
    mbedtls_cipher_free(ctx);
    free(ctx);
}

void
cipher_ctx_init(mbedtls_cipher_context_t *ctx, const uint8_t *key, int key_len,
                const mbedtls_cipher_info_t *kt, const mbedtls_operation_t operation)
{
    ASSERT(NULL != kt && NULL != ctx);

    CLEAR(*ctx);

    if (!mbed_ok(mbedtls_cipher_setup(ctx, kt)))
    {
        msg(M_FATAL, "mbed TLS cipher context init #1");
    }

    if (!mbed_ok(mbedtls_cipher_setkey(ctx, key, key_len*8, operation)))
    {
        msg(M_FATAL, "mbed TLS cipher set key");
    }

    /* make sure we used a big enough key */
    ASSERT(ctx->key_bitlen <= key_len*8);
}

int
cipher_ctx_iv_length(const mbedtls_cipher_context_t *ctx)
{
    return mbedtls_cipher_get_iv_size(ctx);
}

int
cipher_ctx_get_tag(cipher_ctx_t *ctx, uint8_t *tag, int tag_len)
{
    if (tag_len > SIZE_MAX)
    {
        return 0;
    }

    if (!mbed_ok(mbedtls_cipher_write_tag(ctx, (unsigned char *) tag, tag_len)))
    {
        return 0;
    }

    return 1;
}

int
cipher_ctx_block_size(const mbedtls_cipher_context_t *ctx)
{
    return mbedtls_cipher_get_block_size(ctx);
}

int
cipher_ctx_mode(const mbedtls_cipher_context_t *ctx)
{
    ASSERT(NULL != ctx);

    return cipher_kt_mode(ctx->cipher_info);
}

const cipher_kt_t *
cipher_ctx_get_cipher_kt(const cipher_ctx_t *ctx)
{
    return ctx ? ctx->cipher_info : NULL;
}

int
cipher_ctx_reset(mbedtls_cipher_context_t *ctx, const uint8_t *iv_buf)
{
    if (!mbed_ok(mbedtls_cipher_reset(ctx)))
    {
        return 0;
    }

    if (!mbed_ok(mbedtls_cipher_set_iv(ctx, iv_buf, ctx->cipher_info->iv_size)))
    {
        return 0;
    }

    return 1;
}

int
cipher_ctx_update_ad(cipher_ctx_t *ctx, const uint8_t *src, int src_len)
{
    if (src_len > SIZE_MAX)
    {
        return 0;
    }

    if (!mbed_ok(mbedtls_cipher_update_ad(ctx, src, src_len)))
    {
        return 0;
    }

    return 1;
}

int
cipher_ctx_update(mbedtls_cipher_context_t *ctx, uint8_t *dst,
                  int *dst_len, uint8_t *src, int src_len)
{
    size_t s_dst_len = *dst_len;

    if (!mbed_ok(mbedtls_cipher_update(ctx, src, (size_t) src_len, dst,
                                       &s_dst_len)))
    {
        return 0;
    }

    *dst_len = s_dst_len;

    return 1;
}

int
cipher_ctx_final(mbedtls_cipher_context_t *ctx, uint8_t *dst, int *dst_len)
{
    size_t s_dst_len = *dst_len;

    if (!mbed_ok(mbedtls_cipher_finish(ctx, dst, &s_dst_len)))
    {
        return 0;
    }

    *dst_len = s_dst_len;

    return 1;
}

int
cipher_ctx_final_check_tag(mbedtls_cipher_context_t *ctx, uint8_t *dst,
                           int *dst_len, uint8_t *tag, size_t tag_len)
{
    size_t olen = 0;

    if (MBEDTLS_DECRYPT != ctx->operation)
    {
        return 0;
    }

    if (tag_len > SIZE_MAX)
    {
        return 0;
    }

    if (!mbed_ok(mbedtls_cipher_finish(ctx, dst, &olen)))
    {
        msg(D_CRYPT_ERRORS, "%s: cipher_ctx_final() failed", __func__);
        return 0;
    }

    if (olen > INT_MAX)
    {
        return 0;
    }
    *dst_len = olen;

    if (!mbed_ok(mbedtls_cipher_check_tag(ctx, (const unsigned char *) tag,
                                          tag_len)))
    {
        return 0;
    }

    return 1;
}

void
cipher_des_encrypt_ecb(const unsigned char key[DES_KEY_LENGTH],
                       unsigned char *src,
                       unsigned char *dst)
{
    mbedtls_des_context ctx;

    ASSERT(mbed_ok(mbedtls_des_setkey_enc(&ctx, key)));
    ASSERT(mbed_ok(mbedtls_des_crypt_ecb(&ctx, src, dst)));
}



/*
 *
 * Generic message digest information functions
 *
 */


const mbedtls_md_info_t *
md_kt_get(const char *digest)
{
    const mbedtls_md_info_t *md = NULL;
    ASSERT(digest);

    md = mbedtls_md_info_from_string(digest);
    if (!md)
    {
        msg(M_FATAL, "Message hash algorithm '%s' not found", digest);
    }
    if (mbedtls_md_get_size(md) > MAX_HMAC_KEY_LENGTH)
    {
        msg(M_FATAL, "Message hash algorithm '%s' uses a default hash size (%d bytes) which is larger than " PACKAGE_NAME "'s current maximum hash size (%d bytes)",
            digest,
            mbedtls_md_get_size(md),
            MAX_HMAC_KEY_LENGTH);
    }
    return md;
}

const char *
md_kt_name(const mbedtls_md_info_t *kt)
{
    if (NULL == kt)
    {
        return "[null-digest]";
    }
    return mbedtls_md_get_name(kt);
}

unsigned char
md_kt_size(const mbedtls_md_info_t *kt)
{
    if (NULL == kt)
    {
        return 0;
    }
    return mbedtls_md_get_size(kt);
}

/*
 *
 * Generic message digest functions
 *
 */

int
md_full(const md_kt_t *kt, const uint8_t *src, int src_len, uint8_t *dst)
{
    return 0 == mbedtls_md(kt, src, src_len, dst);
}

mbedtls_md_context_t *
md_ctx_new(void)
{
    mbedtls_md_context_t *ctx;
    ALLOC_OBJ_CLEAR(ctx, mbedtls_md_context_t);
    return ctx;
}

void
md_ctx_free(mbedtls_md_context_t *ctx)
{
    free(ctx);
}

void
md_ctx_init(mbedtls_md_context_t *ctx, const mbedtls_md_info_t *kt)
{
    ASSERT(NULL != ctx && NULL != kt);

    mbedtls_md_init(ctx);
    ASSERT(0 == mbedtls_md_setup(ctx, kt, 0));
    ASSERT(0 == mbedtls_md_starts(ctx));
}

void
md_ctx_cleanup(mbedtls_md_context_t *ctx)
{
    mbedtls_md_free(ctx);
}

int
md_ctx_size(const mbedtls_md_context_t *ctx)
{
    if (NULL == ctx)
    {
        return 0;
    }
    return mbedtls_md_get_size(ctx->md_info);
}

void
md_ctx_update(mbedtls_md_context_t *ctx, const uint8_t *src, int src_len)
{
    ASSERT(0 == mbedtls_md_update(ctx, src, src_len));
}

void
md_ctx_final(mbedtls_md_context_t *ctx, uint8_t *dst)
{
    ASSERT(0 == mbedtls_md_finish(ctx, dst));
    mbedtls_md_free(ctx);
}


/*
 *
 * Generic HMAC functions
 *
 */


/*
 * TODO: re-enable dmsg for crypto debug
 */

mbedtls_md_context_t *
hmac_ctx_new(void)
{
    mbedtls_md_context_t *ctx;
    ALLOC_OBJ(ctx, mbedtls_md_context_t);
    return ctx;
}

void
hmac_ctx_free(mbedtls_md_context_t *ctx)
{
    free(ctx);
}

void
hmac_ctx_init(mbedtls_md_context_t *ctx, const uint8_t *key, int key_len,
              const mbedtls_md_info_t *kt)
{
    ASSERT(NULL != kt && NULL != ctx);

    mbedtls_md_init(ctx);
    ASSERT(0 == mbedtls_md_setup(ctx, kt, 1));
    ASSERT(0 == mbedtls_md_hmac_starts(ctx, key, key_len));

    /* make sure we used a big enough key */
    ASSERT(mbedtls_md_get_size(kt) <= key_len);
}

void
hmac_ctx_cleanup(mbedtls_md_context_t *ctx)
{
    mbedtls_md_free(ctx);
}

int
hmac_ctx_size(const mbedtls_md_context_t *ctx)
{
    if (NULL == ctx)
    {
        return 0;
    }
    return mbedtls_md_get_size(ctx->md_info);
}

void
hmac_ctx_reset(mbedtls_md_context_t *ctx)
{
    ASSERT(0 == mbedtls_md_hmac_reset(ctx));
}

void
hmac_ctx_update(mbedtls_md_context_t *ctx, const uint8_t *src, int src_len)
{
    ASSERT(0 == mbedtls_md_hmac_update(ctx, src, src_len));
}

void
hmac_ctx_final(mbedtls_md_context_t *ctx, uint8_t *dst)
{
    ASSERT(0 == mbedtls_md_hmac_finish(ctx, dst));
}

int
memcmp_constant_time(const void *a, const void *b, size_t size)
{
    /* mbed TLS has a no const time memcmp function that it exposes
     * via its APIs like OpenSSL does with CRYPTO_memcmp
     * Adapt the function that mbedtls itself uses in
     * mbedtls_safer_memcmp as it considers that to be safe */
    volatile const unsigned char *A = (volatile const unsigned char *) a;
    volatile const unsigned char *B = (volatile const unsigned char *) b;
    volatile unsigned char diff = 0;

    for (size_t i = 0; i < size; i++)
    {
        unsigned char x = A[i], y = B[i];
        diff |= x ^ y;
    }

    return diff;
}
#endif /* ENABLE_CRYPTO_MBEDTLS */
