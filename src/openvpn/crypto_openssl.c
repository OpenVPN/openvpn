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
 * @file Data Channel Cryptography OpenSSL-specific backend interface
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#elif defined(_MSC_VER)
#include "config-msvc.h"
#endif

#include "syshead.h"

#if defined(ENABLE_CRYPTO_OPENSSL)

#include "basic.h"
#include "buffer.h"
#include "integer.h"
#include "crypto.h"
#include "crypto_backend.h"
#include "openssl_compat.h"

#include <openssl/conf.h>
#include <openssl/des.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/objects.h>
#include <openssl/rand.h>
#include <openssl/ssl.h>

#if OPENSSL_VERSION_NUMBER >= 0x30000000L
#include <openssl/provider.h>
#endif

#if defined(_WIN32) && defined(OPENSSL_NO_EC)
#error Windows build with OPENSSL_NO_EC: disabling EC key is not supported.
#endif

/*
 * Check for key size creepage.
 */

#if MAX_CIPHER_KEY_LENGTH < EVP_MAX_KEY_LENGTH
#warning Some OpenSSL EVP ciphers now support key lengths greater than MAX_CIPHER_KEY_LENGTH -- consider increasing MAX_CIPHER_KEY_LENGTH
#endif

#if MAX_HMAC_KEY_LENGTH < EVP_MAX_MD_SIZE
#warning Some OpenSSL HMAC message digests now support key lengths greater than MAX_HMAC_KEY_LENGTH -- consider increasing MAX_HMAC_KEY_LENGTH
#endif

#if HAVE_OPENSSL_ENGINE
#include <openssl/ui.h>
#include <openssl/engine.h>

static bool engine_initialized = false; /* GLOBAL */

static ENGINE *engine_persist = NULL;   /* GLOBAL */

/* Try to load an engine in a shareable library */
static ENGINE *
try_load_engine(const char *engine)
{
    ENGINE *e = ENGINE_by_id("dynamic");
    if (e)
    {
        if (!ENGINE_ctrl_cmd_string(e, "SO_PATH", engine, 0)
            || !ENGINE_ctrl_cmd_string(e, "LOAD", NULL, 0))
        {
            ENGINE_free(e);
            e = NULL;
        }
    }
    return e;
}

static ENGINE *
setup_engine(const char *engine)
{
    ENGINE *e = NULL;

    ENGINE_load_builtin_engines();

    if (engine)
    {
        if (strcmp(engine, "auto") == 0)
        {
            msg(M_INFO, "Initializing OpenSSL auto engine support");
            ENGINE_register_all_complete();
            return NULL;
        }
        if ((e = ENGINE_by_id(engine)) == NULL
            && (e = try_load_engine(engine)) == NULL)
        {
            crypto_msg(M_FATAL, "OpenSSL error: cannot load engine '%s'",
                       engine);
        }

        if (!ENGINE_set_default(e, ENGINE_METHOD_ALL))
        {
            crypto_msg(M_FATAL,
                       "OpenSSL error: ENGINE_set_default failed on engine '%s'",
                       engine);
        }

        msg(M_INFO, "Initializing OpenSSL support for engine '%s'",
            ENGINE_get_id(e));
    }
    return e;
}

#endif /* HAVE_OPENSSL_ENGINE */

void
crypto_init_lib_engine(const char *engine_name)
{
#if HAVE_OPENSSL_ENGINE
    if (!engine_initialized)
    {
        ASSERT(engine_name);
        ASSERT(!engine_persist);
        engine_persist = setup_engine(engine_name);
        engine_initialized = true;
    }
#else  /* if HAVE_OPENSSL_ENGINE */
    msg(M_WARN, "Note: OpenSSL hardware crypto engine functionality is not available");
#endif
}

provider_t *
crypto_load_provider(const char *provider)
{
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
    /* Load providers into the default (NULL) library context */
    OSSL_PROVIDER *prov = OSSL_PROVIDER_load(NULL, provider);
    if (!prov)
    {
        crypto_msg(M_FATAL, "failed to load provider '%s'", provider);
    }
    return prov;
#else  /* OPENSSL_VERSION_NUMBER >= 0x30000000L */
    msg(M_WARN, "Note: OpenSSL provider functionality is not available");
    return NULL;
#endif
}

void
crypto_unload_provider(const char *provname, provider_t *provider)
{
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
    if (!OSSL_PROVIDER_unload(provider))
    {
        crypto_msg(M_FATAL, "failed to unload provider '%s'", provname);
    }
#endif
}

/*
 *
 * Functions related to the core crypto library
 *
 */

void
crypto_init_lib(void)
{
#if (OPENSSL_VERSION_NUMBER >= 0x10100000L)
    OPENSSL_init_crypto(OPENSSL_INIT_LOAD_CONFIG, NULL);
#else
    OPENSSL_config(NULL);
#endif
    /*
     * If you build the OpenSSL library and OpenVPN with
     * CRYPTO_MDEBUG, you will get a listing of OpenSSL
     * memory leaks on program termination.
     */

#ifdef CRYPTO_MDEBUG
    CRYPTO_mem_ctrl(CRYPTO_MEM_CHECK_ON);
#endif
}

void
crypto_uninit_lib(void)
{
#ifdef CRYPTO_MDEBUG
    FILE *fp = fopen("sdlog", "w");
    ASSERT(fp);
    CRYPTO_mem_leaks_fp(fp);
    fclose(fp);
#endif

#if HAVE_OPENSSL_ENGINE
    if (engine_initialized)
    {
        ENGINE_cleanup();
        engine_persist = NULL;
        engine_initialized = false;
    }
#endif
}

void
crypto_clear_error(void)
{
    ERR_clear_error();
}

void
crypto_print_openssl_errors(const unsigned int flags)
{
    size_t err = 0;

    while ((err = ERR_get_error()))
    {
        /* Be more clear about frequently occurring "no shared cipher" error */
        if (ERR_GET_REASON(err) == SSL_R_NO_SHARED_CIPHER)
        {
            msg(D_CRYPT_ERRORS, "TLS error: The server has no TLS ciphersuites "
                "in common with the client. Your --tls-cipher setting might be "
                "too restrictive.");
        }
        else if (ERR_GET_REASON(err) == SSL_R_UNSUPPORTED_PROTOCOL)
        {
            msg(D_CRYPT_ERRORS, "TLS error: Unsupported protocol. This typically "
                "indicates that client and server have no common TLS version enabled. "
                "This can be caused by mismatched tls-version-min and tls-version-max "
                "options on client and server. "
                "If your OpenVPN client is between v2.3.6 and v2.3.2 try adding "
                "tls-version-min 1.0 to the client configuration to use TLS 1.0+ "
                "instead of TLS 1.0 only");
        }
        msg(flags, "OpenSSL: %s", ERR_error_string(err, NULL));
    }
}


/*
 *
 * OpenSSL memory debugging.  If dmalloc debugging is enabled, tell
 * OpenSSL to use our private malloc/realloc/free functions so that
 * we can dispatch them to dmalloc.
 *
 */

#ifdef DMALLOC
static void *
crypto_malloc(size_t size, const char *file, int line)
{
    return dmalloc_malloc(file, line, size, DMALLOC_FUNC_MALLOC, 0, 0);
}

static void *
crypto_realloc(void *ptr, size_t size, const char *file, int line)
{
    return dmalloc_realloc(file, line, ptr, size, DMALLOC_FUNC_REALLOC, 0);
}

static void
crypto_free(void *ptr)
{
    dmalloc_free(__FILE__, __LINE__, ptr, DMALLOC_FUNC_FREE);
}

void
crypto_init_dmalloc(void)
{
    CRYPTO_set_mem_ex_functions(crypto_malloc,
                                crypto_realloc,
                                crypto_free);
}
#endif /* DMALLOC */

const cipher_name_pair cipher_name_translation_table[] = {
    { "AES-128-GCM", "id-aes128-GCM" },
    { "AES-192-GCM", "id-aes192-GCM" },
    { "AES-256-GCM", "id-aes256-GCM" },
    { "CHACHA20-POLY1305", "ChaCha20-Poly1305" },
};
const size_t cipher_name_translation_table_count =
    sizeof(cipher_name_translation_table) / sizeof(*cipher_name_translation_table);


static int
cipher_name_cmp(const void *a, const void *b)
{
    const EVP_CIPHER *const *cipher_a = a;
    const EVP_CIPHER *const *cipher_b = b;

    return strcmp(cipher_kt_name(*cipher_a), cipher_kt_name(*cipher_b));
}

void
show_available_ciphers(void)
{
    int nid;
    size_t i;

    /* If we ever exceed this, we must be more selective */
    const EVP_CIPHER *cipher_list[1000];
    size_t num_ciphers = 0;
#ifndef ENABLE_SMALL
    printf("The following ciphers and cipher modes are available for use\n"
           "with " PACKAGE_NAME ".  Each cipher shown below may be used as a\n"
           "parameter to the --data-ciphers (or --cipher) option.  The\n"
           "default key size is shown as well as whether or not it can be\n"
           "changed with the --keysize directive.  Using a GCM or CBC mode\n"
           "is recommended.  In static key mode only CBC mode is allowed.\n\n");
#endif

    for (nid = 0; nid < 10000; ++nid)
    {
        const EVP_CIPHER *cipher = EVP_get_cipherbynid(nid);
        if (cipher && (cipher_kt_mode_cbc(cipher)
#ifdef ENABLE_OFB_CFB_MODE
                       || cipher_kt_mode_ofb_cfb(cipher)
#endif
                       || cipher_kt_mode_aead(cipher)
                       ))
        {
            /* Check explicit availibility (for OpenSSL 3.0) */
            if (cipher_kt_get(cipher_kt_name(cipher)))
            {
                cipher_list[num_ciphers++] = cipher;
            }
        }
        if (num_ciphers == (sizeof(cipher_list)/sizeof(*cipher_list)))
        {
            msg(M_WARN, "WARNING: Too many ciphers, not showing all");
            break;
        }
    }

    /* cast to non-const to prevent warning */
    qsort((EVP_CIPHER *)cipher_list, num_ciphers, sizeof(*cipher_list), cipher_name_cmp);

    for (i = 0; i < num_ciphers; i++)
    {
        if (!cipher_kt_insecure(cipher_list[i]))
        {
            print_cipher(cipher_list[i]);
        }
    }

    printf("\nThe following ciphers have a block size of less than 128 bits, \n"
           "and are therefore deprecated.  Do not use unless you have to.\n\n");
    for (i = 0; i < num_ciphers; i++)
    {
        if (cipher_kt_insecure(cipher_list[i]))
        {
            print_cipher(cipher_list[i]);
        }
    }
    printf("\n");
}

void
print_digest(EVP_MD *digest, void *unused)
{
    printf("%s %d bit digest size\n", md_kt_name(digest),
           EVP_MD_size(digest) * 8);
}

void
show_available_digests(void)
{
    int nid;

#ifndef ENABLE_SMALL
    printf("The following message digests are available for use with\n"
           PACKAGE_NAME ".  A message digest is used in conjunction with\n"
           "the HMAC function, to authenticate received packets.\n"
           "You can specify a message digest as parameter to\n"
           "the --auth option.\n\n");
#endif

#if OPENSSL_VERSION_NUMBER >= 0x30000000L
    EVP_MD_do_all_provided(NULL, print_digest, NULL);
#else
    for (nid = 0; nid < 10000; ++nid)
    {
        const EVP_MD *digest = EVP_get_digestbynid(nid);
        if (digest)
        {
            /* We cast the const away so we can keep the function prototype
             * compatible with EVP_MD_do_all_provided */
            print_digest((EVP_MD *)digest, NULL);
        }
    }
    printf("\n");
#endif
}

void
show_available_engines(void)
{
#if HAVE_OPENSSL_ENGINE /* Only defined for OpenSSL */
    ENGINE *e;

    printf("OpenSSL Crypto Engines\n\n");

    ENGINE_load_builtin_engines();

    e = ENGINE_get_first();
    while (e)
    {
        printf("%s [%s]\n",
               ENGINE_get_name(e),
               ENGINE_get_id(e));
        e = ENGINE_get_next(e);
    }
    ENGINE_cleanup();
#else  /* if HAVE_OPENSSL_ENGINE */
    printf("Sorry, OpenSSL hardware crypto engine functionality is not available.\n");
#endif
}


bool
crypto_pem_encode(const char *name, struct buffer *dst,
                  const struct buffer *src, struct gc_arena *gc)
{
    bool ret = false;
    BIO *bio = BIO_new(BIO_s_mem());
    if (!bio || !PEM_write_bio(bio, name, "", BPTR(src), BLEN(src)))
    {
        ret = false;
        goto cleanup;
    }

    BUF_MEM *bptr;
    BIO_get_mem_ptr(bio, &bptr);

    *dst = alloc_buf_gc(bptr->length, gc);
    ASSERT(buf_write(dst, bptr->data, bptr->length));

    ret = true;
cleanup:
    if (!BIO_free(bio))
    {
        ret = false;
    }

    return ret;
}

bool
crypto_pem_decode(const char *name, struct buffer *dst,
                  const struct buffer *src)
{
    bool ret = false;

    BIO *bio = BIO_new_mem_buf((char *)BPTR(src), BLEN(src));
    if (!bio)
    {
        crypto_msg(M_FATAL, "Cannot open memory BIO for PEM decode");
    }

    char *name_read = NULL;
    char *header_read = NULL;
    uint8_t *data_read = NULL;
    long data_read_len = 0;
    if (!PEM_read_bio(bio, &name_read, &header_read, &data_read,
                      &data_read_len))
    {
        dmsg(D_CRYPT_ERRORS, "%s: PEM decode failed", __func__);
        goto cleanup;
    }

    if (strcmp(name, name_read))
    {
        dmsg(D_CRYPT_ERRORS,
             "%s: unexpected PEM name (got '%s', expected '%s')",
             __func__, name_read, name);
        goto cleanup;
    }

    uint8_t *dst_data = buf_write_alloc(dst, data_read_len);
    if (!dst_data)
    {
        dmsg(D_CRYPT_ERRORS, "%s: dst too small (%i, needs %li)", __func__,
             BCAP(dst), data_read_len);
        goto cleanup;
    }
    memcpy(dst_data, data_read, data_read_len);

    ret = true;
cleanup:
    OPENSSL_free(name_read);
    OPENSSL_free(header_read);
    OPENSSL_free(data_read);
    if (!BIO_free(bio))
    {
        ret = false;
    }

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

int
rand_bytes(uint8_t *output, int len)
{
    if (unlikely(1 != RAND_bytes(output, len)))
    {
        crypto_msg(D_CRYPT_ERRORS, "RAND_bytes() failed");
        return 0;
    }
    return 1;
}

/*
 *
 * Key functions, allow manipulation of keys.
 *
 */


int
key_des_num_cblocks(const EVP_CIPHER *kt)
{
    int ret = 0;
    const char *name = OBJ_nid2sn(EVP_CIPHER_nid(kt));
    if (name)
    {
        if (!strncmp(name, "DES-", 4))
        {
            ret = EVP_CIPHER_key_length(kt) / sizeof(DES_cblock);
        }
        else if (!strncmp(name, "DESX-", 5))
        {
            ret = 1;
        }
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
        DES_cblock *dc = (DES_cblock *) buf_read_alloc(&b, sizeof(DES_cblock));
        if (!dc)
        {
            crypto_msg(D_CRYPT_ERRORS,
                       "CRYPTO INFO: check_key_DES: insufficient key material");
            goto err;
        }
        if (DES_is_weak_key(dc))
        {
            crypto_msg(D_CRYPT_ERRORS,
                       "CRYPTO INFO: check_key_DES: weak key detected");
            goto err;
        }
        if (!DES_check_key_parity(dc))
        {
            crypto_msg(D_CRYPT_ERRORS,
                       "CRYPTO INFO: check_key_DES: bad parity detected");
            goto err;
        }
    }
    return true;

err:
    ERR_clear_error();
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
        DES_cblock *dc = (DES_cblock *) buf_read_alloc(&b, sizeof(DES_cblock));
        if (!dc)
        {
            msg(D_CRYPT_ERRORS, "CRYPTO INFO: fixup_key_DES: insufficient key material");
            ERR_clear_error();
            return;
        }
        DES_set_odd_parity(dc);
    }
}


/*
 *
 * Generic cipher key type functions
 *
 */


const EVP_CIPHER *
cipher_kt_get(const char *ciphername)
{
    const EVP_CIPHER *cipher = NULL;

    ASSERT(ciphername);

    ciphername = translate_cipher_name_from_openvpn(ciphername);
    cipher = EVP_get_cipherbyname(ciphername);

    /* This is a workaround for OpenSSL 3.0 to infer if the cipher is valid
     * without doing all the refactoring that OpenVPN 2.6 has. This will
     * not support custom algorithm from providers but at least ignore
     * algorithms that are not available without providers (legacy) */
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
    EVP_CIPHER *tmpcipher = EVP_CIPHER_fetch(NULL, ciphername, NULL);
    if (!tmpcipher)
    {
        cipher = NULL;
    }
    EVP_CIPHER_free(tmpcipher);
#endif

    if (NULL == cipher)
    {
        crypto_msg(D_LOW, "Cipher algorithm '%s' not found", ciphername);
        return NULL;
    }


    if (EVP_CIPHER_key_length(cipher) > MAX_CIPHER_KEY_LENGTH)
    {
        msg(D_LOW, "Cipher algorithm '%s' uses a default key size (%d bytes) "
            "which is larger than " PACKAGE_NAME "'s current maximum key size "
            "(%d bytes)", ciphername, EVP_CIPHER_key_length(cipher),
            MAX_CIPHER_KEY_LENGTH);
        return NULL;
    }

    return cipher;
}

const char *
cipher_kt_name(const EVP_CIPHER *cipher_kt)
{
    if (NULL == cipher_kt)
    {
        return "[null-cipher]";
    }

    const char *name = EVP_CIPHER_name(cipher_kt);
    return translate_cipher_name_to_openvpn(name);
}

int
cipher_kt_key_size(const EVP_CIPHER *cipher_kt)
{
    return EVP_CIPHER_key_length(cipher_kt);
}

int
cipher_kt_iv_size(const EVP_CIPHER *cipher_kt)
{
    return EVP_CIPHER_iv_length(cipher_kt);
}

int
cipher_kt_block_size(const EVP_CIPHER *cipher)
{
    /*
     * OpenSSL reports OFB/CFB/GCM cipher block sizes as '1 byte'.  To work
     * around that, try to replace the mode with 'CBC' and return the block size
     * reported for that cipher, if possible.  If that doesn't work, just return
     * the value reported by OpenSSL.
     */
    char *name = NULL;
    char *mode_str = NULL;
    const char *orig_name = NULL;
    const EVP_CIPHER *cbc_cipher = NULL;

    int block_size = EVP_CIPHER_block_size(cipher);

    orig_name = EVP_CIPHER_name(cipher);
    if (!orig_name)
    {
        goto cleanup;
    }

    name = string_alloc(translate_cipher_name_to_openvpn(orig_name), NULL);
    mode_str = strrchr(name, '-');
    if (!mode_str || strlen(mode_str) < 4)
    {
        goto cleanup;
    }

    strcpy(mode_str, "-CBC");

    cbc_cipher = EVP_get_cipherbyname(translate_cipher_name_from_openvpn(name));
    if (cbc_cipher)
    {
        block_size = EVP_CIPHER_block_size(cbc_cipher);
    }

cleanup:
    free(name);
    return block_size;
}

int
cipher_kt_tag_size(const EVP_CIPHER *cipher_kt)
{
    if (cipher_kt_mode_aead(cipher_kt))
    {
        return OPENVPN_AEAD_TAG_LENGTH;
    }
    else
    {
        return 0;
    }
}

bool
cipher_kt_insecure(const EVP_CIPHER *cipher)
{
    return !(cipher_kt_block_size(cipher) >= 128 / 8
#ifdef NID_chacha20_poly1305
             || EVP_CIPHER_nid(cipher) == NID_chacha20_poly1305
#endif
             );
}

int
cipher_kt_mode(const EVP_CIPHER *cipher_kt)
{
    ASSERT(NULL != cipher_kt);
    return EVP_CIPHER_mode(cipher_kt);
}

bool
cipher_kt_mode_cbc(const cipher_kt_t *cipher)
{
    return cipher && cipher_kt_mode(cipher) == OPENVPN_MODE_CBC
           /* Exclude AEAD cipher modes, they require a different API */
           && !(EVP_CIPHER_flags(cipher) & EVP_CIPH_FLAG_AEAD_CIPHER);
}

bool
cipher_kt_mode_ofb_cfb(const cipher_kt_t *cipher)
{
    return cipher && (cipher_kt_mode(cipher) == OPENVPN_MODE_OFB
                      || cipher_kt_mode(cipher) == OPENVPN_MODE_CFB)
           /* Exclude AEAD cipher modes, they require a different API */
           && !(EVP_CIPHER_flags(cipher) & EVP_CIPH_FLAG_AEAD_CIPHER);
}

bool
cipher_kt_mode_aead(const cipher_kt_t *cipher)
{
    if (cipher)
    {
        switch (EVP_CIPHER_nid(cipher))
        {
            case NID_aes_128_gcm:
            case NID_aes_192_gcm:
            case NID_aes_256_gcm:
#ifdef NID_chacha20_poly1305
            case NID_chacha20_poly1305:
#endif
                return true;
        }
    }

    return false;
}

/*
 *
 * Generic cipher context functions
 *
 */

cipher_ctx_t *
cipher_ctx_new(void)
{
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    check_malloc_return(ctx);
    return ctx;
}

void
cipher_ctx_free(EVP_CIPHER_CTX *ctx)
{
    EVP_CIPHER_CTX_free(ctx);
}

void
cipher_ctx_init(EVP_CIPHER_CTX *ctx, const uint8_t *key, int key_len,
                const EVP_CIPHER *kt, int enc)
{
    ASSERT(NULL != kt && NULL != ctx);

    EVP_CIPHER_CTX_reset(ctx);
    if (!EVP_CipherInit(ctx, kt, NULL, NULL, enc))
    {
        crypto_msg(M_FATAL, "EVP cipher init #1");
    }
#ifdef HAVE_EVP_CIPHER_CTX_SET_KEY_LENGTH
    if (!EVP_CIPHER_CTX_set_key_length(ctx, key_len))
    {
        crypto_msg(M_FATAL, "EVP set key size");
    }
#endif
    if (!EVP_CipherInit_ex(ctx, NULL, NULL, key, NULL, enc))
    {
        crypto_msg(M_FATAL, "EVP cipher init #2");
    }

    /* make sure we used a big enough key */
    ASSERT(EVP_CIPHER_CTX_key_length(ctx) <= key_len);
}

int
cipher_ctx_iv_length(const EVP_CIPHER_CTX *ctx)
{
    return EVP_CIPHER_CTX_iv_length(ctx);
}

int
cipher_ctx_get_tag(EVP_CIPHER_CTX *ctx, uint8_t *tag_buf, int tag_size)
{
    return EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, tag_size, tag_buf);
}

int
cipher_ctx_block_size(const EVP_CIPHER_CTX *ctx)
{
    return EVP_CIPHER_CTX_block_size(ctx);
}

int
cipher_ctx_mode(const EVP_CIPHER_CTX *ctx)
{
    return EVP_CIPHER_CTX_mode(ctx);
}

const cipher_kt_t *
cipher_ctx_get_cipher_kt(const cipher_ctx_t *ctx)
{
    return ctx ? EVP_CIPHER_CTX_cipher(ctx) : NULL;
}


int
cipher_ctx_reset(EVP_CIPHER_CTX *ctx, const uint8_t *iv_buf)
{
    return EVP_CipherInit_ex(ctx, NULL, NULL, NULL, iv_buf, -1);
}

int
cipher_ctx_update_ad(EVP_CIPHER_CTX *ctx, const uint8_t *src, int src_len)
{
    int len;
    if (!EVP_CipherUpdate(ctx, NULL, &len, src, src_len))
    {
        crypto_msg(M_FATAL, "%s: EVP_CipherUpdate() failed", __func__);
    }
    return 1;
}

int
cipher_ctx_update(EVP_CIPHER_CTX *ctx, uint8_t *dst, int *dst_len,
                  uint8_t *src, int src_len)
{
    if (!EVP_CipherUpdate(ctx, dst, dst_len, src, src_len))
    {
        crypto_msg(M_FATAL, "%s: EVP_CipherUpdate() failed", __func__);
    }
    return 1;
}

int
cipher_ctx_final(EVP_CIPHER_CTX *ctx, uint8_t *dst, int *dst_len)
{
    return EVP_CipherFinal(ctx, dst, dst_len);
}

int
cipher_ctx_final_check_tag(EVP_CIPHER_CTX *ctx, uint8_t *dst, int *dst_len,
                           uint8_t *tag, size_t tag_len)
{
    ASSERT(tag_len < SIZE_MAX);
    if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, tag_len, tag))
    {
        return 0;
    }

    return cipher_ctx_final(ctx, dst, dst_len);
}

void
cipher_des_encrypt_ecb(const unsigned char key[DES_KEY_LENGTH],
                       unsigned char *src,
                       unsigned char *dst)
{
    DES_key_schedule sched;

    DES_set_key_unchecked((DES_cblock *)key, &sched);
    DES_ecb_encrypt((DES_cblock *)src, (DES_cblock *)dst, &sched, DES_ENCRYPT);
}

/*
 *
 * Generic message digest information functions
 *
 */


const EVP_MD *
md_kt_get(const char *digest)
{
    const EVP_MD *md = NULL;
    ASSERT(digest);
    md = EVP_get_digestbyname(digest);

    /* This is a workaround for OpenSSL 3.0 to infer if the digest is valid
     * without doing all the refactoring that OpenVPN 2.6 has. This will
     * not support custom algorithm from providers but at least ignore
     * algorithms that are not available without providers (legacy) */
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
    EVP_MD *tmpmd = EVP_MD_fetch(NULL, digest, NULL);
    if (!tmpmd)
    {
        md = NULL;
    }
    EVP_MD_free(tmpmd);
#endif

    if (!md)
    {
        crypto_msg(M_FATAL, "Message hash algorithm '%s' not found", digest);
    }
    if (EVP_MD_size(md) > MAX_HMAC_KEY_LENGTH)
    {
        crypto_msg(M_FATAL, "Message hash algorithm '%s' uses a default hash "
                   "size (%d bytes) which is larger than " PACKAGE_NAME "'s current "
                   "maximum hash size (%d bytes)",
                   digest, EVP_MD_size(md), MAX_HMAC_KEY_LENGTH);
    }
    return md;
}

/* Since we used the OpenSSL <=1.1 names as part of our OCC message, they
 * are now unfortunately part of our wire protocol.
 *
 * OpenSSL 3.0 will still accept the "old" names so we do not need to use
 * this translation table for forward lookup, only for returning the name
 * with md_kt_name() */
const cipher_name_pair digest_name_translation_table[] = {
    { "BLAKE2s256", "BLAKE2S-256"},
    { "BLAKE2b512", "BLAKE2B-512"},
    { "RIPEMD160", "RIPEMD-160" },
    { "SHA224", "SHA2-224"},
    { "SHA256", "SHA2-256"},
    { "SHA384", "SHA2-384"},
    { "SHA512", "SHA2-512"},
    { "SHA512-224", "SHA2-512/224"},
    { "SHA512-256", "SHA2-512/256"},
    { "SHAKE128", "SHAKE-128"},
    { "SHAKE256", "SHAKE-256"},
};
const size_t digest_name_translation_table_count =
    sizeof(digest_name_translation_table) / sizeof(*digest_name_translation_table);

const char *
md_kt_name(const EVP_MD *kt)
{
    if (NULL == kt)
    {
        return "[null-digest]";
    }

    const char *name = EVP_MD_name(kt);

    /* Search for a digest name translation */
    for (size_t i = 0; i < digest_name_translation_table_count; i++)
    {
        const cipher_name_pair *pair = &digest_name_translation_table[i];
        if (!strcmp(name, pair->lib_name))
        {
            name = pair->openvpn_name;
        }
    }

    return name;
}

unsigned char
md_kt_size(const EVP_MD *kt)
{
    return (unsigned char)EVP_MD_size(kt);
}


/*
 *
 * Generic message digest functions
 *
 */

int
md_full(const EVP_MD *kt, const uint8_t *src, int src_len, uint8_t *dst)
{
    unsigned int in_md_len = 0;

    return EVP_Digest(src, src_len, dst, &in_md_len, kt, NULL);
}

EVP_MD_CTX *
md_ctx_new(void)
{
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    check_malloc_return(ctx);
    return ctx;
}

void
md_ctx_free(EVP_MD_CTX *ctx)
{
    EVP_MD_CTX_free(ctx);
}

void
md_ctx_init(EVP_MD_CTX *ctx, const EVP_MD *kt)
{
    ASSERT(NULL != ctx && NULL != kt);

    EVP_MD_CTX_init(ctx);
    EVP_DigestInit(ctx, kt);
}

void
md_ctx_cleanup(EVP_MD_CTX *ctx)
{
    EVP_MD_CTX_reset(ctx);
}

int
md_ctx_size(const EVP_MD_CTX *ctx)
{
    return EVP_MD_CTX_size(ctx);
}

void
md_ctx_update(EVP_MD_CTX *ctx, const uint8_t *src, int src_len)
{
    EVP_DigestUpdate(ctx, src, src_len);
}

void
md_ctx_final(EVP_MD_CTX *ctx, uint8_t *dst)
{
    unsigned int in_md_len = 0;

    EVP_DigestFinal(ctx, dst, &in_md_len);
}


/*
 *
 * Generic HMAC functions
 *
 */

HMAC_CTX *
hmac_ctx_new(void)
{
    HMAC_CTX *ctx = HMAC_CTX_new();
    check_malloc_return(ctx);
    return ctx;
}

void
hmac_ctx_free(HMAC_CTX *ctx)
{
    HMAC_CTX_free(ctx);
}

void
hmac_ctx_init(HMAC_CTX *ctx, const uint8_t *key, int key_len,
              const EVP_MD *kt)
{
    ASSERT(NULL != kt && NULL != ctx);

    HMAC_CTX_reset(ctx);
    HMAC_Init_ex(ctx, key, key_len, kt, NULL);

    /* make sure we used a big enough key */
    ASSERT(HMAC_size(ctx) <= key_len);
}

void
hmac_ctx_cleanup(HMAC_CTX *ctx)
{
    HMAC_CTX_reset(ctx);
}

int
hmac_ctx_size(const HMAC_CTX *ctx)
{
    return HMAC_size(ctx);
}

void
hmac_ctx_reset(HMAC_CTX *ctx)
{
    HMAC_Init_ex(ctx, NULL, 0, NULL, NULL);
}

void
hmac_ctx_update(HMAC_CTX *ctx, const uint8_t *src, int src_len)
{
    HMAC_Update(ctx, src, src_len);
}

void
hmac_ctx_final(HMAC_CTX *ctx, uint8_t *dst)
{
    unsigned int in_hmac_len = 0;

    HMAC_Final(ctx, dst, &in_hmac_len);
}

int
memcmp_constant_time(const void *a, const void *b, size_t size)
{
    return CRYPTO_memcmp(a, b, size);
}

#if HAVE_OPENSSL_ENGINE
static int
ui_reader(UI *ui, UI_STRING *uis)
{
    SSL_CTX *ctx = UI_get0_user_data(ui);

    if (UI_get_string_type(uis) == UIT_PROMPT)
    {
        pem_password_cb *cb = SSL_CTX_get_default_passwd_cb(ctx);
        void *d = SSL_CTX_get_default_passwd_cb_userdata(ctx);
        char password[64];

        cb(password, sizeof(password), 0, d);
        UI_set_result(ui, uis, password);

        return 1;
    }
    return 0;
}
#endif

EVP_PKEY *
engine_load_key(const char *file, SSL_CTX *ctx)
{
#if HAVE_OPENSSL_ENGINE
    UI_METHOD *ui;
    EVP_PKEY *pkey;

    if (!engine_persist)
    {
        return NULL;
    }

    /* this will print out the error from BIO_read */
    crypto_msg(M_INFO, "PEM_read_bio failed, now trying engine method to load private key");

    ui = UI_create_method("openvpn");
    if (!ui)
    {
        crypto_msg(M_FATAL, "Engine UI creation failed");
        return NULL;
    }

    UI_method_set_reader(ui, ui_reader);

    ENGINE_init(engine_persist);
    pkey = ENGINE_load_private_key(engine_persist, file, ui, ctx);
    ENGINE_finish(engine_persist);
    if (!pkey)
    {
        crypto_msg(M_FATAL, "Engine could not load key file");
    }

    UI_destroy_method(ui);
    return pkey;
#else  /* if HAVE_OPENSSL_ENGINE */
    return NULL;
#endif /* if HAVE_OPENSSL_ENGINE */
}

#endif /* ENABLE_CRYPTO_OPENSSL */
