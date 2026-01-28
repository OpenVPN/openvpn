/*
 *  OpenVPN -- An application to securely tunnel IP networks
 *             over a single TCP/UDP port, with support for SSL/TLS-based
 *             session authentication and key exchange,
 *             packet encryption, packet authentication, and
 *             packet compression.
 *
 *  Copyright (C) 2002-2025 OpenVPN Inc <sales@openvpn.net>
 *  Copyright (C) 2010-2025 Sentyron B.V. <openvpn@sentyron.com>
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
 *  with this program; if not, see <https://www.gnu.org/licenses/>.
 */

/**
 * @file
 * Data Channel Cryptography backend interface using the TF-PSA-Crypto library
 * part of Mbed TLS 4.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "syshead.h"

#if defined(ENABLE_CRYPTO_MBEDTLS)
#include <mbedtls/version.h>

#if MBEDTLS_VERSION_NUMBER >= 0x04000000

#include "errlevel.h"
#include "basic.h"
#include "buffer.h"
#include "crypto.h"
#include "integer.h"
#include "crypto_backend.h"
#include "crypto_mbedtls.h"
#include "otime.h"
#include "misc.h"

#include <psa/crypto.h>
#include <psa/crypto_config.h>
#include <mbedtls/constant_time.h>
#include <mbedtls/error.h>
#include <mbedtls/pem.h>

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

/* The library doesn't support looking up algorithms by string anymore, so here
 * is a lookup table. */
static const cipher_info_t cipher_info_table[] = {
/* TODO: Complete the table. */

/* AES */
#if PSA_WANT_KEY_TYPE_AES
#if PSA_WANT_ALG_GCM
    { "AES-128-GCM", PSA_KEY_TYPE_AES, PSA_ALG_GCM, 128 / 8, 96 / 8, 128 / 8 },
    { "AES-192-GCM", PSA_KEY_TYPE_AES, PSA_ALG_GCM, 192 / 8, 96 / 8, 128 / 8 },
    { "AES-256-GCM", PSA_KEY_TYPE_AES, PSA_ALG_GCM, 256 / 8, 96 / 8, 128 / 8 },
#endif /* PSA_WANT_ALG_GCM */
#if PSA_WANT_ALG_CBC_PKCS7
    { "AES-128-CBC", PSA_KEY_TYPE_AES, PSA_ALG_CBC_PKCS7, 128 / 8, 128 / 8, 128 / 8 },
    { "AES-192-CBC", PSA_KEY_TYPE_AES, PSA_ALG_CBC_PKCS7, 192 / 8, 128 / 8, 128 / 8 },
    { "AES-256-CBC", PSA_KEY_TYPE_AES, PSA_ALG_CBC_PKCS7, 256 / 8, 128 / 8, 128 / 8 },
#endif /* PSA_WANT_ALG_CBC_PKCS7 */
#if PSA_WANT_ALG_CTR
    { "AES-128-CTR", PSA_KEY_TYPE_AES, PSA_ALG_CTR, 128 / 8, 128 / 8, 128 / 8 },
    { "AES-192-CTR", PSA_KEY_TYPE_AES, PSA_ALG_CTR, 192 / 8, 128 / 8, 128 / 8 },
    { "AES-256-CTR", PSA_KEY_TYPE_AES, PSA_ALG_CTR, 256 / 8, 128 / 8, 128 / 8 },
#endif /* PSA_WANT_ALG_CTR */
#endif /* PSA_WANT_KEY_TYPE_AES */

/* Chacha-Poly */
#if PSA_WANT_KEY_TYPE_CHACHA20 && PSA_WANT_ALG_CHACHA20_POLY1305
    { "CHACHA20-POLY1305", PSA_KEY_TYPE_CHACHA20, PSA_ALG_CHACHA20_POLY1305, 256 / 8, 96 / 8, 1 },
#endif
};
static const size_t cipher_info_table_entries = sizeof(cipher_info_table) / sizeof(cipher_info_t);

static const cipher_info_t *
cipher_get(const char *ciphername)
{
    for (size_t i = 0; i < cipher_info_table_entries; i++)
    {
        if (strcmp(ciphername, cipher_info_table[i].name) == 0)
        {
            return &cipher_info_table[i];
        }
    }
    return NULL;
}

/* Because Mbed TLS 4 doesn't support looking up algorithms by string, there's
 * nothing to translate. */
const cipher_name_pair cipher_name_translation_table[] = {};
const size_t cipher_name_translation_table_count =
    sizeof(cipher_name_translation_table) / sizeof(cipher_name_pair);

int
rand_bytes(uint8_t *output, int len)
{
    if (len < 0)
    {
        return 0;
    }
    psa_status_t result = psa_generate_random(output, (size_t)len);
    return result == PSA_SUCCESS;
}

bool
cipher_valid_reason(const char *ciphername, const char **reason)
{
    ASSERT(reason);

    const cipher_info_t *cipher_info = cipher_get(ciphername);

    if (cipher_info == NULL)
    {
        msg(D_LOW, "Cipher algorithm '%s' not found", ciphername);
        *reason = "disabled because unknown";
        return false;
    }

    if (cipher_info->key_bytes > MAX_CIPHER_KEY_LENGTH)
    {
        msg(D_LOW,
            "Cipher algorithm '%s' uses a default key size (%d bytes) "
            "which is larger than " PACKAGE_NAME "'s current maximum key size "
            "(%d bytes)",
            ciphername, cipher_info->key_bytes, MAX_CIPHER_KEY_LENGTH);
        *reason = "disabled due to key size too large";
        return false;
    }

    *reason = NULL;
    return true;
}

const char *
cipher_kt_name(const char *ciphername)
{
    const cipher_info_t *cipher_info = cipher_get(ciphername);
    if (cipher_info == NULL)
    {
        return "[null-cipher]";
    }
    return cipher_info->name;
}

int
cipher_kt_key_size(const char *ciphername)
{
    const cipher_info_t *cipher_info = cipher_get(ciphername);
    if (cipher_info == NULL)
    {
        return 0;
    }
    return cipher_info->key_bytes;
}

int
cipher_kt_iv_size(const char *ciphername)
{
    const cipher_info_t *cipher_info = cipher_get(ciphername);

    if (cipher_info == NULL)
    {
        return 0;
    }
    return cipher_info->iv_bytes;
}

int
cipher_kt_block_size(const char *ciphername)
{
    const cipher_info_t *cipher_info = cipher_get(ciphername);
    if (cipher_info == NULL)
    {
        return 0;
    }
    return cipher_info->block_size;
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
    const cipher_info_t *cipher_info = cipher_get(ciphername);
    if (cipher_info == NULL)
    {
        return true;
    }

    return !(cipher_info->block_size >= 128 / 8
             || cipher_info->psa_alg == PSA_ALG_CHACHA20_POLY1305);
}

bool
cipher_kt_mode_cbc(const char *ciphername)
{
    const cipher_info_t *cipher_info = cipher_get(ciphername);
    if (cipher_info == NULL)
    {
        return false;
    }
    return cipher_info->psa_alg == PSA_ALG_CBC_PKCS7;
}

bool
cipher_kt_mode_ofb_cfb(const char *ciphername)
{
    const cipher_info_t *cipher_info = cipher_get(ciphername);
    if (cipher_info == NULL)
    {
        return false;
    }
    return cipher_info->psa_alg == PSA_ALG_OFB || cipher_info->psa_alg == PSA_ALG_CFB;
}

bool
cipher_kt_mode_aead(const char *ciphername)
{
    const cipher_info_t *cipher_info = cipher_get(ciphername);
    if (cipher_info == NULL)
    {
        return false;
    }
    return cipher_info->psa_alg == PSA_ALG_GCM || cipher_info->psa_alg == PSA_ALG_CHACHA20_POLY1305;
}

cipher_ctx_t *
cipher_ctx_new(void)
{
    cipher_ctx_t *ctx;
    /* Initializing the object with zeros ensures that it is always safe to call
     * cipher_ctx_free. */
    ALLOC_OBJ_CLEAR(ctx, cipher_ctx_t);
    return ctx;
}

void
cipher_ctx_free(cipher_ctx_t *ctx)
{
    if (cipher_ctx_mode_aead(ctx))
    {
        ASSERT(psa_aead_abort(&ctx->operation.aead) == PSA_SUCCESS);
    }
    else
    {
        ASSERT(psa_cipher_abort(&ctx->operation.cipher) == PSA_SUCCESS);
    }
    ASSERT(psa_destroy_key(ctx->key) == PSA_SUCCESS);
    free(ctx);
}

void
cipher_ctx_init(cipher_ctx_t *ctx, const uint8_t *key, const char *ciphername,
                crypto_operation_t enc)
{
    ASSERT(ciphername != NULL && ctx != NULL);
    CLEAR(*ctx);

    ctx->cipher_info = cipher_get(ciphername);
    ASSERT(ctx->cipher_info != NULL);

    psa_set_key_type(&ctx->key_attributes, ctx->cipher_info->psa_key_type);
    psa_set_key_algorithm(&ctx->key_attributes, ctx->cipher_info->psa_alg);
    psa_set_key_bits(&ctx->key_attributes, (size_t)ctx->cipher_info->key_bytes * 8);
    psa_set_key_usage_flags(&ctx->key_attributes,
                            enc == OPENVPN_OP_ENCRYPT ? PSA_KEY_USAGE_ENCRYPT : PSA_KEY_USAGE_DECRYPT);

    if (psa_import_key(&ctx->key_attributes, key, (size_t)ctx->cipher_info->key_bytes, &ctx->key) != PSA_SUCCESS)
    {
        msg(M_FATAL, "psa_import_key failed");
    }

    /* make sure we used a big enough key */
    ASSERT(psa_get_key_bits(&ctx->key_attributes) == (size_t)(8 * ctx->cipher_info->key_bytes));
}

int
cipher_ctx_iv_length(const cipher_ctx_t *ctx)
{
    return ctx->cipher_info->iv_bytes;
}

int
cipher_ctx_get_tag(cipher_ctx_t *ctx, uint8_t *tag, int tag_len)
{
    if (!ctx->aead_finished || tag_len < OPENVPN_AEAD_TAG_LENGTH)
    {
        return 0;
    }

    memcpy(tag, ctx->tag, OPENVPN_AEAD_TAG_LENGTH);
    return 1;
}

int
cipher_ctx_block_size(const cipher_ctx_t *ctx)
{
    return ctx->cipher_info->block_size;
}

int
cipher_ctx_mode(const cipher_ctx_t *ctx)
{
    ASSERT(ctx != NULL);
    return (int)psa_get_key_algorithm(&ctx->key_attributes);
}

bool
cipher_ctx_mode_cbc(const cipher_ctx_t *ctx)
{
    return ctx != NULL && cipher_ctx_mode(ctx) == OPENVPN_MODE_CBC;
}

bool
cipher_ctx_mode_ofb_cfb(const cipher_ctx_t *ctx)
{
    if (ctx == NULL)
    {
        return false;
    }
    int mode = cipher_ctx_mode(ctx);
    return mode == OPENVPN_MODE_OFB || mode == OPENVPN_MODE_CFB;
}

bool
cipher_ctx_mode_aead(const cipher_ctx_t *ctx)
{
    if (ctx == NULL)
    {
        return false;
    }
    int mode = cipher_ctx_mode(ctx);
    return mode == (int)PSA_ALG_GCM || mode == (int)PSA_ALG_CHACHA20_POLY1305;
}

static int
cipher_ctx_direction(const cipher_ctx_t *ctx)
{
    psa_key_usage_t key_usage = psa_get_key_usage_flags(&ctx->key_attributes);
    if (key_usage & PSA_KEY_USAGE_ENCRYPT)
    {
        return OPENVPN_OP_ENCRYPT;
    }
    else if (key_usage & PSA_KEY_USAGE_DECRYPT)
    {
        return OPENVPN_OP_DECRYPT;
    }
    else
    {
        return -1;
    }
}

int
cipher_ctx_reset(cipher_ctx_t *ctx, const uint8_t *iv_buf)
{
    psa_status_t status = 0;

    if (cipher_ctx_mode_aead(ctx))
    {
        if (psa_aead_abort(&ctx->operation.aead) != PSA_SUCCESS)
        {
            return 0;
        }

        if (cipher_ctx_direction(ctx) == OPENVPN_OP_ENCRYPT)
        {
            status = psa_aead_encrypt_setup(&ctx->operation.aead, ctx->key, ctx->cipher_info->psa_alg);
        }
        else if (cipher_ctx_direction(ctx) == OPENVPN_OP_DECRYPT)
        {
            status = psa_aead_decrypt_setup(&ctx->operation.aead, ctx->key, ctx->cipher_info->psa_alg);
        }
        else
        {
            return 0;
        }

        if (status != PSA_SUCCESS)
        {
            return 0;
        }

        status = psa_aead_set_nonce(&ctx->operation.aead, iv_buf, ctx->cipher_info->iv_bytes);
        if (status != PSA_SUCCESS)
        {
            return 0;
        }
    }
    else
    {
        if (psa_cipher_abort(&ctx->operation.cipher) != PSA_SUCCESS)
        {
            return 0;
        }

        if (cipher_ctx_direction(ctx) == OPENVPN_OP_ENCRYPT)
        {
            status = psa_cipher_encrypt_setup(&ctx->operation.cipher, ctx->key, ctx->cipher_info->psa_alg);
        }
        else if (cipher_ctx_direction(ctx) == OPENVPN_OP_DECRYPT)
        {
            status = psa_cipher_decrypt_setup(&ctx->operation.cipher, ctx->key, ctx->cipher_info->psa_alg);
        }
        else
        {
            return 0;
        }

        if (status != PSA_SUCCESS)
        {
            return 0;
        }

        status = psa_cipher_set_iv(&ctx->operation.cipher, iv_buf, ctx->cipher_info->iv_bytes);
        if (status != PSA_SUCCESS)
        {
            return 0;
        }
    }

    return 1;
}

/* We rely on the caller to ensure that the destination buffer has enough room,
 * but Mbed TLS always wants a size for the destination buffer. This function
 * calculates the minimum necessary size for a given cipher and input length.
 *
 * This funcion assumes that src_len has been checked to be >= 0. */
static size_t
needed_dst_size(const cipher_ctx_t *ctx, int src_len)
{
    int mode = cipher_ctx_mode(ctx);
    if (mode == PSA_ALG_CTR || mode == PSA_ALG_GCM || mode == PSA_ALG_CHACHA20_POLY1305)
    {
        /* These algorithms are based on a keystream, so the input and output
         * length are always equal. */
        return (size_t)src_len;
    }
    else
    {
        /* These algorithms are block-based. The number of output blocks that are
         * produced is at most 1 + src_len / block_size. */
        size_t block_size = (size_t)cipher_ctx_block_size(ctx);
        size_t max_blocks = 1 + (size_t)src_len / block_size;
        return max_blocks * block_size;
    }
}

int
cipher_ctx_update_ad(cipher_ctx_t *ctx, const uint8_t *src, int src_len)
{
    if (src_len < 0 || !cipher_ctx_mode_aead(ctx))
    {
        return 0;
    }

    if (psa_aead_update_ad(&ctx->operation.aead, src, (size_t)src_len) != PSA_SUCCESS)
    {
        return 0;
    }
    return 1;
}

int
cipher_ctx_update(cipher_ctx_t *ctx, uint8_t *dst, int *dst_len, uint8_t *src, int src_len)
{
    if (src_len < 0)
    {
        return 0;
    }

    size_t dst_size = needed_dst_size(ctx, src_len);
    size_t psa_output_len = 0;
    psa_status_t status = 0;

    if (cipher_ctx_mode_aead(ctx))
    {
        status = psa_aead_update(&ctx->operation.aead, src, (size_t)src_len, dst, dst_size, &psa_output_len);
    }
    else
    {
        status = psa_cipher_update(&ctx->operation.cipher, src, (size_t)src_len, dst, dst_size, &psa_output_len);
    }

    if (status != PSA_SUCCESS)
    {
        return 0;
    }

    if (psa_output_len > INT_MAX)
    {
        return 0;
    }
    *dst_len = (int)psa_output_len;

    return 1;
}

int
cipher_ctx_final(cipher_ctx_t *ctx, uint8_t *dst, int *dst_len)
{
    size_t dst_size = needed_dst_size(ctx, 0);
    size_t psa_output_len = 0;
    psa_status_t status = 0;

    if (cipher_ctx_mode_aead(ctx))
    {
        size_t actual_tag_size = 0;
        status = psa_aead_finish(&ctx->operation.aead,
                                 dst,
                                 dst_size,
                                 &psa_output_len,
                                 ctx->tag,
                                 (size_t)OPENVPN_AEAD_TAG_LENGTH,
                                 &actual_tag_size);
        if (status != PSA_SUCCESS || psa_output_len > (size_t)INT_MAX || actual_tag_size != (size_t)OPENVPN_AEAD_TAG_LENGTH)
        {
            return 0;
        }
        ctx->aead_finished = true;
    }
    else
    {
        status = psa_cipher_finish(&ctx->operation.cipher, dst, dst_size, &psa_output_len);
        if (status != PSA_SUCCESS || psa_output_len > (size_t)INT_MAX)
        {
            return 0;
        }
    }

    *dst_len = (int)psa_output_len;

    return 1;
}

int
cipher_ctx_final_check_tag(cipher_ctx_t *ctx, uint8_t *dst, int *dst_len, uint8_t *tag, size_t tag_len)
{
    if (cipher_ctx_direction(ctx) != OPENVPN_OP_DECRYPT || !cipher_ctx_mode_aead(ctx))
    {
        return 0;
    }

    size_t psa_output_len = 0;
    psa_status_t status = 0;

    status = psa_aead_verify(&ctx->operation.aead, dst, 0, &psa_output_len, tag, tag_len);
    if (status != PSA_SUCCESS || psa_output_len > (size_t)INT_MAX)
    {
        return 0;
    }
    *dst_len = (int)psa_output_len;

    return 1;
}

static const md_info_t md_info_table[] = {
    /* TODO: Fill out table. */
    { "MD5", PSA_ALG_MD5 },
    { "SHA1", PSA_ALG_SHA_1 },
    { "SHA256", PSA_ALG_SHA_256 },
};
const size_t md_info_table_entries = sizeof(md_info_table) / sizeof(md_info_t);

static const md_info_t *
md_get(const char *digest_name)
{
    for (size_t i = 0; i < md_info_table_entries; i++)
    {
        if (strcmp(digest_name, md_info_table[i].name) == 0)
        {
            return &md_info_table[i];
        }
    }
    return NULL;
}

bool
md_valid(const char *digest)
{
    const md_info_t *md = md_get(digest);
    return md != NULL;
}

const char *
md_kt_name(const char *mdname)
{
    if (strcmp("none", mdname) == 0)
    {
        return "[null-digest]";
    }
    const md_info_t *md = md_get(mdname);
    if (md == NULL)
    {
        return NULL;
    }
    return md->name;
}

unsigned char
md_kt_size(const char *mdname)
{
    if (strcmp("none", mdname) == 0)
    {
        return 0;
    }
    const md_info_t *md_info = md_get(mdname);
    if (md_info == NULL)
    {
        return 0;
    }
    return (unsigned char)PSA_HASH_LENGTH(md_info->psa_alg);
}

md_ctx_t *
md_ctx_new(void)
{
    md_ctx_t *ctx;
    ALLOC_OBJ_CLEAR(ctx, md_ctx_t);
    return ctx;
}

int
md_full(const char *mdname, const uint8_t *src, int src_len, uint8_t *dst)
{
    const md_info_t *md = md_get(mdname);
    if (md == NULL || src_len < 0)
    {
        return 0;
    }

    /* We depend on the caller to ensure that dst has enough room for the hash,
     * so we just tell PSA that it can hold the appropriate amount of bytes. */
    size_t dst_size = PSA_HASH_LENGTH(md->psa_alg);
    size_t hash_length = 0;

    psa_status_t status = psa_hash_compute(md->psa_alg, src, (size_t)src_len, dst, dst_size, &hash_length);
    if (status != PSA_SUCCESS || hash_length != dst_size)
    {
        return 0;
    }
    return 1;
}

void
md_ctx_free(md_ctx_t *ctx)
{
    free(ctx);
}

void
md_ctx_init(md_ctx_t *ctx, const char *mdname)
{
    const md_info_t *md_info = md_get(mdname);
    ASSERT(ctx != NULL && md_info != NULL);

    ctx->md_info = md_info;
    ASSERT(psa_hash_setup(&ctx->operation, md_info->psa_alg) == PSA_SUCCESS);
}

void
md_ctx_cleanup(md_ctx_t *ctx)
{
    ASSERT(psa_hash_abort(&ctx->operation) == PSA_SUCCESS);
}

int
md_ctx_size(const md_ctx_t *ctx)
{
    if (ctx == NULL)
    {
        return 0;
    }
    return (int)PSA_HASH_LENGTH(ctx->md_info->psa_alg);
}

void
md_ctx_update(md_ctx_t *ctx, const uint8_t *src, size_t src_len)
{
    ASSERT(psa_hash_update(&ctx->operation, src, src_len) == PSA_SUCCESS);
}

void
md_ctx_final(md_ctx_t *ctx, uint8_t *dst)
{
    /* We depend on the caller to ensure that dst has enough room for the hash,
     * so we just tell PSA that it can hold the appropriate amount of bytes. */
    size_t dst_size = PSA_HASH_LENGTH(ctx->md_info->psa_alg);
    size_t hash_length = 0;

    ASSERT(psa_hash_finish(&ctx->operation, dst, dst_size, &hash_length) == PSA_SUCCESS);
    ASSERT(hash_length == dst_size);
}

hmac_ctx_t *
hmac_ctx_new(void)
{
    hmac_ctx_t *ctx;
    ALLOC_OBJ_CLEAR(ctx, hmac_ctx_t);
    return ctx;
}

void
hmac_ctx_free(hmac_ctx_t *ctx)
{
    free(ctx);
}

static void
hmac_ctx_init_with_arbitrary_key_length(hmac_ctx_t *ctx, const uint8_t *key, size_t key_len, const md_info_t *md_info)
{
    ctx->md_info = md_info;
    psa_set_key_type(&ctx->key_attributes, PSA_KEY_TYPE_HMAC);
    psa_set_key_algorithm(&ctx->key_attributes, PSA_ALG_HMAC(md_info->psa_alg));
    psa_set_key_usage_flags(&ctx->key_attributes, PSA_KEY_USAGE_SIGN_MESSAGE);

    if (psa_import_key(&ctx->key_attributes, key, key_len, &ctx->key) != PSA_SUCCESS)
    {
        msg(M_FATAL, "psa_import_key failed");
    }

    ASSERT(psa_mac_sign_setup(&ctx->operation, ctx->key, PSA_ALG_HMAC(md_info->psa_alg)) == PSA_SUCCESS);
}

void
hmac_ctx_init(hmac_ctx_t *ctx, const uint8_t *key, const char *mdname)
{
    const md_info_t *md_info = md_get(mdname);
    ASSERT(ctx != NULL && key != NULL && md_info != NULL);

    hmac_ctx_init_with_arbitrary_key_length(ctx, key, PSA_HASH_LENGTH(md_info->psa_alg), md_info);
}

void
hmac_ctx_cleanup(hmac_ctx_t *ctx)
{
    ASSERT(psa_mac_abort(&ctx->operation) == PSA_SUCCESS);
    ASSERT(psa_destroy_key(ctx->key) == PSA_SUCCESS);
}

int
hmac_ctx_size(hmac_ctx_t *ctx)
{
    return (int)PSA_HASH_LENGTH(ctx->md_info->psa_alg);
}

void
hmac_ctx_reset(hmac_ctx_t *ctx)
{
    ASSERT(psa_mac_abort(&ctx->operation) == PSA_SUCCESS);
    ASSERT(psa_mac_sign_setup(&ctx->operation, ctx->key, PSA_ALG_HMAC(ctx->md_info->psa_alg)) == PSA_SUCCESS);
}

void
hmac_ctx_update(hmac_ctx_t *ctx, const uint8_t *src, int src_len)
{
    ASSERT(src_len >= 0);
    ASSERT(psa_mac_update(&ctx->operation, src, (size_t)src_len) == PSA_SUCCESS);
}

void
hmac_ctx_final(hmac_ctx_t *ctx, uint8_t *dst)
{
    /* We depend on the caller to ensure that dst has enough room for the hash,
     * so we just tell PSA that it can hold the appropriate amount of bytes. */
    size_t dst_size = PSA_HASH_LENGTH(ctx->md_info->psa_alg);
    size_t hmac_length = 0;

    ASSERT(psa_mac_sign_finish(&ctx->operation, dst, dst_size, &hmac_length) == PSA_SUCCESS);
    ASSERT(hmac_length == dst_size);
}

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
tls1_P_hash(const md_info_t *md_info, const uint8_t *sec, size_t sec_len, const uint8_t *seed,
            int seed_len, uint8_t *out, size_t olen)
{
    struct gc_arena gc = gc_new();
    uint8_t A1[MAX_HMAC_KEY_LENGTH];

#ifdef ENABLE_DEBUG
    /* used by the D_SHOW_KEY_SOURCE, guarded with ENABLE_DEBUG to avoid unused
     * variables warnings if compiled with --enable-small */
    const size_t olen_orig = olen;
    const uint8_t *out_orig = out;
#endif

    hmac_ctx_t *ctx = hmac_ctx_new();
    hmac_ctx_t *ctx_tmp = hmac_ctx_new();

    dmsg(D_SHOW_KEY_SOURCE, "tls1_P_hash sec: %s", format_hex(sec, sec_len, 0, &gc));
    dmsg(D_SHOW_KEY_SOURCE, "tls1_P_hash seed: %s", format_hex(seed, seed_len, 0, &gc));

    unsigned int chunk = (unsigned int)PSA_HASH_LENGTH(md_info->psa_alg);
    unsigned int A1_len = (unsigned int)PSA_HASH_LENGTH(md_info->psa_alg);

    /* This is the only place where we init an HMAC with a key that is not
     * equal to its size, therefore we init the hmac ctx manually here */
    hmac_ctx_init_with_arbitrary_key_length(ctx, sec, sec_len, md_info);
    hmac_ctx_init_with_arbitrary_key_length(ctx_tmp, sec, sec_len, md_info);

    hmac_ctx_update(ctx, seed, seed_len);
    hmac_ctx_final(ctx, A1);

    for (;;)
    {
        hmac_ctx_reset(ctx);
        hmac_ctx_reset(ctx_tmp);
        hmac_ctx_update(ctx, A1, A1_len);
        hmac_ctx_update(ctx_tmp, A1, A1_len);
        hmac_ctx_update(ctx, seed, (int)seed_len);

        if (olen > chunk)
        {
            hmac_ctx_final(ctx, out);
            out += chunk;
            olen -= chunk;
            hmac_ctx_final(ctx_tmp, A1); /* calc the next A1 value */
        }
        else                             /* last one */
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
ssl_tls1_PRF(const uint8_t *label, size_t label_len, const uint8_t *sec, size_t slen, uint8_t *out1,
             size_t olen)
{
    const md_info_t *md5 = md_get("MD5");
    const md_info_t *sha1 = md_get("SHA1");

    if (label_len > (size_t)INT_MAX)
    {
        return false;
    }

    struct gc_arena gc = gc_new();

    uint8_t *out2 = (uint8_t *)gc_malloc(olen, false, &gc);

    size_t len = slen / 2;
    const uint8_t *S1 = sec;
    const uint8_t *S2 = &(sec[len]);
    len += (slen & 1); /* add for odd, make longer */

    tls1_P_hash(md5, S1, len, label, (int)label_len, out1, olen);
    tls1_P_hash(sha1, S2, len, label, (int)label_len, out2, olen);

    for (size_t i = 0; i < olen; i++)
    {
        out1[i] ^= out2[i];
    }

    secure_memzero(out2, olen);

    dmsg(D_SHOW_KEY_SOURCE, "tls1_PRF out[%zu]: %s", olen, format_hex(out1, olen, 0, &gc));

    gc_free(&gc);
    return true;
}

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
mbed_log_func_line(unsigned int flags, int errval, const char *func, int line)
{
    char prefix[256];

    if (snprintf(prefix, sizeof(prefix), "%s:%d", func, line) >= sizeof(prefix))
    {
        return mbed_log_err(flags, errval, func);
    }

    return mbed_log_err(flags, errval, prefix);
}

int
memcmp_constant_time(const void *a, const void *b, size_t size)
{
    return mbedtls_ct_memcmp(a, b, size);
}

void
show_available_ciphers(void)
{
    /* Mbed TLS 4 does not currently have a mechanism to discover available
     * ciphers. We instead print out the ciphers from cipher_info_table. */

#ifndef ENABLE_SMALL
    printf("The following ciphers and cipher modes are available for use\n"
           "with " PACKAGE_NAME ".  Each cipher shown below may be used as a\n"
           "parameter to the --data-ciphers (or --cipher) option.  Using a\n"
           "GCM or CBC mode is recommended.  In static key mode only CBC\n"
           "mode is allowed.\n\n");
#endif

    for (size_t i = 0; i < cipher_info_table_entries; i++)
    {
        const cipher_info_t *info = &cipher_info_table[i];
        const char *name = info->name;
        if (!cipher_kt_insecure(name) && (cipher_kt_mode_aead(name) || cipher_kt_mode_cbc(name)))
        {
            print_cipher(name);
        }
    }

    printf("\nThe following ciphers have a block size of less than 128 bits, \n"
           "and are therefore deprecated.  Do not use unless you have to.\n\n");
    for (size_t i = 0; i < cipher_info_table_entries; i++)
    {
        const cipher_info_t *info = &cipher_info_table[i];
        const char *name = info->name;
        if (cipher_kt_insecure(name) && (cipher_kt_mode_aead(name) || cipher_kt_mode_cbc(name)))
        {
            print_cipher(name);
        }
    }
    printf("\n");
}

void
show_available_digests(void)
{
    /* Mbed TLS 4 does not currently have a mechanism to discover available
     * message digests. We instead print out the digests from md_info_table. */

#ifndef ENABLE_SMALL
    printf("The following message digests are available for use with\n" PACKAGE_NAME
           ".  A message digest is used in conjunction with\n"
           "the HMAC function, to authenticate received packets.\n"
           "You can specify a message digest as parameter to\n"
           "the --auth option.\n\n");
#endif

    for (size_t i = 0; i < md_info_table_entries; i++)
    {
        const md_info_t *info = &md_info_table[i];
        printf("%s %d bit default key\n", info->name,
               (unsigned char)PSA_HASH_LENGTH(info->psa_alg) * 8);
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
crypto_pem_encode(const char *name, struct buffer *dst, const struct buffer *src,
                  struct gc_arena *gc)
{
    /* 1000 chars is the PEM line length limit (+1 for tailing NUL) */
    char header[1000 + 1] = { 0 };
    char footer[1000 + 1] = { 0 };

    if (snprintf(header, sizeof(header), "-----BEGIN %s-----\n", name) >= sizeof(header))
    {
        return false;
    }
    if (snprintf(footer, sizeof(footer), "-----END %s-----\n", name) >= sizeof(footer))
    {
        return false;
    }

    size_t out_len = 0;
    if (MBEDTLS_ERR_BASE64_BUFFER_TOO_SMALL
        != mbedtls_pem_write_buffer(header, footer, BPTR(src), BLEN(src), NULL, 0, &out_len))
    {
        return false;
    }

    /* We set the size buf to out_len-1 to NOT include the 0 byte that
     * mbedtls_pem_write_buffer in its length calculation */
    *dst = alloc_buf_gc(out_len, gc);
    if (!mbed_ok(mbedtls_pem_write_buffer(header, footer, BPTR(src), BLEN(src), BPTR(dst),
                                          BCAP(dst), &out_len))
        || !(out_len < INT_MAX && out_len > 1)
        || !buf_inc_len(dst, (int)out_len - 1))
    {
        CLEAR(*dst);
        return false;
    }

    return true;
}

bool
crypto_pem_decode(const char *name, struct buffer *dst, const struct buffer *src)
{
    /* 1000 chars is the PEM line length limit (+1 for tailing NUL) */
    char header[1000 + 1] = { 0 };
    char footer[1000 + 1] = { 0 };

    if (snprintf(header, sizeof(header), "-----BEGIN %s-----", name) >= sizeof(header))
    {
        return false;
    }
    if (snprintf(footer, sizeof(footer), "-----END %s-----", name) >= sizeof(footer))
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
    bool ret =
        mbed_ok(mbedtls_pem_read_buffer(&ctx, header, footer, BPTR(&input), NULL, 0, &use_len));
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

#endif /* MBEDTLS_VERSION_NUMBER >= 0x04000000 */
#endif /* defined(ENABLE_CRYPTO_MBEDTLS) */
