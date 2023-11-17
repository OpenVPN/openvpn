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

/**
 * @file Data Channel Cryptography mbed TLS-specific backend interface
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
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
#include "mbedtls_compat.h"
#include "misc.h"

#include <mbedtls/base64.h>
#include <mbedtls/des.h>
#include <mbedtls/error.h>
#include <mbedtls/md5.h>
#include <mbedtls/cipher.h>
#include <mbedtls/pem.h>

#include <mbedtls/entropy.h>
#include <mbedtls/ssl.h>


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

provider_t *
crypto_load_provider(const char *provider)
{
    if (provider)
    {
        msg(M_WARN, "Note: mbed TLS provider functionality is not available");
    }
    return NULL;
}

void
crypto_unload_provider(const char *provname, provider_t *provider)
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
        const mbedtls_cipher_info_t *info = mbedtls_cipher_info_from_type(*ciphers);
        const char *name = mbedtls_cipher_info_get_name(info);
        if (info && name && !cipher_kt_insecure(name)
            && (cipher_kt_mode_aead(name) || cipher_kt_mode_cbc(name)))
        {
            print_cipher(name);
        }
        ciphers++;
    }

    printf("\nThe following ciphers have a block size of less than 128 bits, \n"
           "and are therefore deprecated.  Do not use unless you have to.\n\n");
    ciphers = mbedtls_cipher_list();
    while (*ciphers != 0)
    {
        const mbedtls_cipher_info_t *info = mbedtls_cipher_info_from_type(*ciphers);
        const char *name = mbedtls_cipher_info_get_name(info);
        if (info && name && cipher_kt_insecure(name)
            && (cipher_kt_mode_aead(name) || cipher_kt_mode_cbc(name)))
        {
            print_cipher(name);
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
    size_t buf_size = 0;
    const unsigned char *buf = mbedtls_pem_get_buffer(&ctx, &buf_size);
    if (ret && !buf_write(dst, buf, buf_size))
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
 * Generic cipher key type functions
 *
 */
static const mbedtls_cipher_info_t *
cipher_get(const char *ciphername)
{
    ASSERT(ciphername);

    const mbedtls_cipher_info_t *cipher = NULL;

    ciphername = translate_cipher_name_from_openvpn(ciphername);
    cipher = mbedtls_cipher_info_from_string(ciphername);
    return cipher;
}

bool
cipher_valid_reason(const char *ciphername, const char **reason)
{
    ASSERT(reason);

    const mbedtls_cipher_info_t *cipher = cipher_get(ciphername);

    if (NULL == cipher)
    {
        msg(D_LOW, "Cipher algorithm '%s' not found", ciphername);
        *reason = "disabled because unknown";
        return false;
    }

    const size_t key_bytelen = mbedtls_cipher_info_get_key_bitlen(cipher)/8;
    if (key_bytelen > MAX_CIPHER_KEY_LENGTH)
    {
        msg(D_LOW, "Cipher algorithm '%s' uses a default key size (%zu bytes) "
            "which is larger than " PACKAGE_NAME "'s current maximum key size "
            "(%d bytes)", ciphername, key_bytelen, MAX_CIPHER_KEY_LENGTH);
        *reason = "disabled due to key size too large";
        return false;
    }

    *reason = NULL;
    return true;
}

const char *
cipher_kt_name(const char *ciphername)
{
    const mbedtls_cipher_info_t *cipher_kt = cipher_get(ciphername);
    if (NULL == cipher_kt)
    {
        return "[null-cipher]";
    }

    return translate_cipher_name_to_openvpn(mbedtls_cipher_info_get_name(cipher_kt));
}

int
cipher_kt_key_size(const char *ciphername)
{
    const mbedtls_cipher_info_t *cipher_kt = cipher_get(ciphername);

    if (NULL == cipher_kt)
    {
        return 0;
    }

    return (int)mbedtls_cipher_info_get_key_bitlen(cipher_kt)/8;
}

int
cipher_kt_iv_size(const char *ciphername)
{
    const mbedtls_cipher_info_t *cipher_kt = cipher_get(ciphername);

    if (NULL == cipher_kt)
    {
        return 0;
    }
    return (int)mbedtls_cipher_info_get_iv_size(cipher_kt);
}

int
cipher_kt_block_size(const char *ciphername)
{
    const mbedtls_cipher_info_t *cipher_kt = cipher_get(ciphername);
    if (NULL == cipher_kt)
    {
        return 0;
    }
    return (int)mbedtls_cipher_info_get_block_size(cipher_kt);
}

int
cipher_kt_tag_size(const char *ciphername)
{
    if (cipher_kt_mode_aead(ciphername))
    {
        return OPENVPN_AEAD_TAG_LENGTH;
    }
    return 0;
}

bool
cipher_kt_insecure(const char *ciphername)
{
    const mbedtls_cipher_info_t *cipher_kt = cipher_get(ciphername);
    if (!cipher_kt)
    {
        return true;
    }

    return !(cipher_kt_block_size(ciphername) >= 128 / 8
#ifdef MBEDTLS_CHACHAPOLY_C
             || mbedtls_cipher_info_get_type(cipher_kt) == MBEDTLS_CIPHER_CHACHA20_POLY1305
#endif
             );
}

static mbedtls_cipher_mode_t
cipher_kt_mode(const mbedtls_cipher_info_t *cipher_kt)
{
    ASSERT(NULL != cipher_kt);
    return mbedtls_cipher_info_get_mode(cipher_kt);
}

bool
cipher_kt_mode_cbc(const char *ciphername)
{
    const mbedtls_cipher_info_t *cipher = cipher_get(ciphername);
    return cipher && cipher_kt_mode(cipher) == OPENVPN_MODE_CBC;
}

bool
cipher_kt_mode_ofb_cfb(const char *ciphername)
{
    const mbedtls_cipher_info_t *cipher = cipher_get(ciphername);
    return cipher && (cipher_kt_mode(cipher) == OPENVPN_MODE_OFB
                      || cipher_kt_mode(cipher) == OPENVPN_MODE_CFB);
}

bool
cipher_kt_mode_aead(const char *ciphername)
{
    const mbedtls_cipher_info_t *cipher = cipher_get(ciphername);
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
cipher_ctx_init(mbedtls_cipher_context_t *ctx, const uint8_t *key,
                const char *ciphername, const mbedtls_operation_t operation)
{
    ASSERT(NULL != ciphername && NULL != ctx);
    CLEAR(*ctx);

    const mbedtls_cipher_info_t *kt = cipher_get(ciphername);
    ASSERT(kt);
    size_t key_bitlen = mbedtls_cipher_info_get_key_bitlen(kt);

    if (!mbed_ok(mbedtls_cipher_setup(ctx, kt)))
    {
        msg(M_FATAL, "mbed TLS cipher context init #1");
    }

    if (!mbed_ok(mbedtls_cipher_setkey(ctx, key, (int)key_bitlen, operation)))
    {
        msg(M_FATAL, "mbed TLS cipher set key");
    }

    if (mbedtls_cipher_info_get_mode(kt) == MBEDTLS_MODE_CBC)
    {
        if (!mbed_ok(mbedtls_cipher_set_padding_mode(ctx, MBEDTLS_PADDING_PKCS7)))
        {
            msg(M_FATAL, "mbed TLS cipher set padding mode");
        }
    }

    /* make sure we used a big enough key */
    ASSERT(mbedtls_cipher_get_key_bitlen(ctx) <= key_bitlen);
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
    return (int)mbedtls_cipher_get_block_size(ctx);
}

int
cipher_ctx_mode(const mbedtls_cipher_context_t *ctx)
{
    ASSERT(NULL != ctx);

    return mbedtls_cipher_get_cipher_mode(ctx);
}

bool
cipher_ctx_mode_cbc(const cipher_ctx_t *ctx)
{
    return ctx && cipher_ctx_mode(ctx) == OPENVPN_MODE_CBC;
}


bool
cipher_ctx_mode_ofb_cfb(const cipher_ctx_t *ctx)
{
    return ctx && (cipher_ctx_mode(ctx) == OPENVPN_MODE_OFB
                   || cipher_ctx_mode(ctx) == OPENVPN_MODE_CFB);
}

bool
cipher_ctx_mode_aead(const cipher_ctx_t *ctx)
{
    return ctx && (cipher_ctx_mode(ctx) == OPENVPN_MODE_GCM
#ifdef MBEDTLS_CHACHAPOLY_C
                   || cipher_ctx_mode(ctx) == MBEDTLS_MODE_CHACHAPOLY
#endif
                   );
}

int
cipher_ctx_reset(mbedtls_cipher_context_t *ctx, const uint8_t *iv_buf)
{
    if (!mbed_ok(mbedtls_cipher_reset(ctx)))
    {
        return 0;
    }

    if (!mbed_ok(mbedtls_cipher_set_iv(ctx, iv_buf, (size_t)mbedtls_cipher_get_iv_size(ctx))))
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

    if (MBEDTLS_DECRYPT != mbedtls_cipher_get_operation(ctx))
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
                       unsigned char src[DES_KEY_LENGTH],
                       unsigned char dst[DES_KEY_LENGTH])
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


static const mbedtls_md_info_t *
md_get(const char *digest)
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

bool
md_valid(const char *digest)
{
    const mbedtls_md_info_t *md  = mbedtls_md_info_from_string(digest);
    return md != NULL;
}

const char *
md_kt_name(const char *mdname)
{
    if (!strcmp("none", mdname))
    {
        return "[null-digest]";
    }
    const mbedtls_md_info_t *kt = md_get(mdname);
    return mbedtls_md_get_name(kt);
}

unsigned char
md_kt_size(const char *mdname)
{
    if (!strcmp("none", mdname))
    {
        return 0;
    }
    const mbedtls_md_info_t *kt = md_get(mdname);
    return mbedtls_md_get_size(kt);
}

/*
 *
 * Generic message digest functions
 *
 */

int
md_full(const char *mdname, const uint8_t *src, int src_len, uint8_t *dst)
{
    const mbedtls_md_info_t *kt = md_get(mdname);
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
md_ctx_init(mbedtls_md_context_t *ctx, const char *mdname)
{
    const mbedtls_md_info_t *kt = md_get(mdname);
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
    return (int)mbedtls_md_get_size(mbedtls_md_info_from_ctx(ctx));
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
hmac_ctx_init(mbedtls_md_context_t *ctx, const uint8_t *key, const char *mdname)
{
    const mbedtls_md_info_t *kt = md_get(mdname);
    ASSERT(NULL != kt && NULL != ctx);

    mbedtls_md_init(ctx);
    int key_len = mbedtls_md_get_size(kt);
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
hmac_ctx_size(mbedtls_md_context_t *ctx)
{
    if (NULL == ctx)
    {
        return 0;
    }
    return mbedtls_md_get_size(mbedtls_md_info_from_ctx(ctx));
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
/* mbedtls-2.18.0 or newer implements tls_prf, but prf_tls1 is removed
 * from recent versions, so we use our own implementation if necessary. */
#if HAVE_MBEDTLS_SSL_TLS_PRF && defined(MBEDTLS_SSL_TLS_PRF_TLS1)
bool
ssl_tls1_PRF(const uint8_t *seed, int seed_len, const uint8_t *secret,
             int secret_len, uint8_t *output, int output_len)
{
    return mbed_ok(mbedtls_ssl_tls_prf(MBEDTLS_SSL_TLS_PRF_TLS1, secret,
                                       secret_len, "", seed, seed_len, output,
                                       output_len));
}
#else /* HAVE_MBEDTLS_SSL_TLS_PRF && defined(MBEDTLS_SSL_TLS_PRF_TLS1) */
/*
 * Generate the hash required by for the \c tls1_PRF function.
 *
 * @param md_kt         Message digest to use
 * @param sec           Secret to base the hash on
 * @param sec_len       Length of the secret
 * @param seed          Seed to hash
 * @param seed_len      Length of the seed
 * @param out           Output buffer
 * @param olen          Length of the output buffer
 */
static void
tls1_P_hash(const mbedtls_md_info_t *md_kt, const uint8_t *sec, int sec_len,
            const uint8_t *seed, int seed_len, uint8_t *out, int olen)
{
    struct gc_arena gc = gc_new();
    uint8_t A1[MAX_HMAC_KEY_LENGTH];

#ifdef ENABLE_DEBUG
    /* used by the D_SHOW_KEY_SOURCE, guarded with ENABLE_DEBUG to avoid unused
     * variables warnings if compiled with --enable-small */
    const int olen_orig = olen;
    const uint8_t *out_orig = out;
#endif

    hmac_ctx_t *ctx = hmac_ctx_new();
    hmac_ctx_t *ctx_tmp = hmac_ctx_new();

    dmsg(D_SHOW_KEY_SOURCE, "tls1_P_hash sec: %s", format_hex(sec, sec_len, 0, &gc));
    dmsg(D_SHOW_KEY_SOURCE, "tls1_P_hash seed: %s", format_hex(seed, seed_len, 0, &gc));

    int chunk = mbedtls_md_get_size(md_kt);
    unsigned int A1_len = mbedtls_md_get_size(md_kt);

    /* This is the only place where we init an HMAC with a key that is not
     * equal to its size, therefore we init the hmac ctx manually here */
    mbedtls_md_init(ctx);
    ASSERT(0 == mbedtls_md_setup(ctx, md_kt, 1));
    ASSERT(0 == mbedtls_md_hmac_starts(ctx, sec, sec_len));

    mbedtls_md_init(ctx_tmp);
    ASSERT(0 == mbedtls_md_setup(ctx_tmp, md_kt, 1));
    ASSERT(0 == mbedtls_md_hmac_starts(ctx_tmp, sec, sec_len));

    hmac_ctx_update(ctx, seed, seed_len);
    hmac_ctx_final(ctx, A1);

    for (;; )
    {
        hmac_ctx_reset(ctx);
        hmac_ctx_reset(ctx_tmp);
        hmac_ctx_update(ctx, A1, A1_len);
        hmac_ctx_update(ctx_tmp, A1, A1_len);
        hmac_ctx_update(ctx, seed, seed_len);

        if (olen > chunk)
        {
            hmac_ctx_final(ctx, out);
            out += chunk;
            olen -= chunk;
            hmac_ctx_final(ctx_tmp, A1); /* calc the next A1 value */
        }
        else    /* last one */
        {
            hmac_ctx_final(ctx, A1);
            memcpy(out, A1, olen);
            break;
        }
    }
    hmac_ctx_cleanup(ctx);
    hmac_ctx_free(ctx);
    hmac_ctx_cleanup(ctx_tmp);
    hmac_ctx_free(ctx_tmp);
    secure_memzero(A1, sizeof(A1));

    dmsg(D_SHOW_KEY_SOURCE, "tls1_P_hash out: %s", format_hex(out_orig, olen_orig, 0, &gc));
    gc_free(&gc);
}

/*
 * Use the TLS PRF function for generating data channel keys.
 * This code is based on the OpenSSL library.
 *
 * TLS generates keys as such:
 *
 * master_secret[48] = PRF(pre_master_secret[48], "master secret",
 *                         ClientHello.random[32] + ServerHello.random[32])
 *
 * key_block[] = PRF(SecurityParameters.master_secret[48],
 *                 "key expansion",
 *                 SecurityParameters.server_random[32] +
 *                 SecurityParameters.client_random[32]);
 *
 * Notes:
 *
 * (1) key_block contains a full set of 4 keys.
 * (2) The pre-master secret is generated by the client.
 */
bool
ssl_tls1_PRF(const uint8_t *label, int label_len, const uint8_t *sec,
             int slen, uint8_t *out1, int olen)
{
    struct gc_arena gc = gc_new();
    const md_kt_t *md5 = md_get("MD5");
    const md_kt_t *sha1 = md_get("SHA1");

    uint8_t *out2 = (uint8_t *)gc_malloc(olen, false, &gc);

    int len = slen/2;
    const uint8_t *S1 = sec;
    const uint8_t *S2 = &(sec[len]);
    len += (slen&1); /* add for odd, make longer */

    tls1_P_hash(md5, S1, len, label, label_len, out1, olen);
    tls1_P_hash(sha1, S2, len, label, label_len, out2, olen);

    for (int i = 0; i<olen; i++)
    {
        out1[i] ^= out2[i];
    }

    secure_memzero(out2, olen);

    dmsg(D_SHOW_KEY_SOURCE, "tls1_PRF out[%d]: %s", olen, format_hex(out1, olen, 0, &gc));

    gc_free(&gc);
    return true;
}
#endif /* HAVE_MBEDTLS_SSL_TLS_PRF && defined(MBEDTLS_SSL_TLS_PRF_TLS1) */
#endif /* ENABLE_CRYPTO_MBEDTLS */
