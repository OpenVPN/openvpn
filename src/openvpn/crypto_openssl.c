/*
 *  OpenVPN -- An application to securely tunnel IP networks
 *             over a single TCP/UDP port, with support for SSL/TLS-based
 *             session authentication and key exchange,
 *             packet encryption, packet authentication, and
 *             packet compression.
 *
 *  Copyright (C) 2002-2024 OpenVPN Inc <sales@openvpn.net>
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

#if (OPENSSL_VERSION_NUMBER >= 0x10100000L) && !defined(LIBRESSL_VERSION_NUMBER)
#include <openssl/kdf.h>
#endif
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
#include <openssl/provider.h>
#endif

#if defined(_WIN32) && defined(OPENSSL_NO_EC)
#error Windows build with OPENSSL_NO_EC: disabling EC key is not supported.
#endif

#ifdef _MSC_VER
/* mute ossl3 deprecation warnings treated as errors in msvc */
#pragma warning(disable: 4996)
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
    unsigned long err = 0;
    int line, errflags;
    const char *file, *data, *func;

    while ((err = ERR_get_error_all(&file, &line, &func, &data, &errflags)) != 0)
    {
        if (!(errflags & ERR_TXT_STRING))
        {
            data = "";
        }

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

        /* print file and line if verb >=8 */
        if (!check_debug_level(D_TLS_DEBUG_MED))
        {
            msg(flags, "OpenSSL: %s:%s", ERR_error_string(err, NULL), data);
        }
        else
        {
            msg(flags, "OpenSSL: %s:%s:%s:%d:%s", ERR_error_string(err, NULL),
                data, file, line, func);
        }
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

    return strcmp(EVP_CIPHER_get0_name(*cipher_a), EVP_CIPHER_get0_name(*cipher_b));
}

struct collect_ciphers {
    /* If we ever exceed this, we must be more selective */
    const EVP_CIPHER *list[1000];
    size_t num;
};

static void
collect_ciphers(EVP_CIPHER *cipher, void *list)
{
    if (!cipher)
    {
        return;
    }
    struct collect_ciphers *cipher_list = list;
    if (cipher_list->num == SIZE(cipher_list->list))
    {
        msg(M_WARN, "WARNING: Too many ciphers, not showing all");
        return;
    }

    const char *ciphername = EVP_CIPHER_get0_name(cipher);

    if (ciphername && (cipher_kt_mode_cbc(ciphername)
#ifdef ENABLE_OFB_CFB_MODE
                       || cipher_kt_mode_ofb_cfb(ciphername)
#endif
                       || cipher_kt_mode_aead(ciphername)
                       ))
    {
        cipher_list->list[cipher_list->num++] = cipher;
    }
}

void
show_available_ciphers(void)
{
    struct collect_ciphers cipher_list = { 0 };

#ifndef ENABLE_SMALL
    printf("The following ciphers and cipher modes are available for use\n"
           "with " PACKAGE_NAME ".  Each cipher shown below may be used as a\n"
           "parameter to the --data-ciphers (or --cipher) option. In static \n"
           "key mode only CBC mode is allowed.\n");
    printf("See also openssl list -cipher-algorithms\n\n");
#endif

#if OPENSSL_VERSION_NUMBER >= 0x30000000L
    EVP_CIPHER_do_all_provided(NULL, collect_ciphers, &cipher_list);
#else
    for (int nid = 0; nid < 10000; ++nid)
    {
#if defined(LIBRESSL_VERSION_NUMBER)
        /* OpenBSD/LibreSSL reimplemented EVP_get_cipherbyname and broke
         * calling EVP_get_cipherbynid with an invalid nid in the process
         * so that it would segfault. */
        const EVP_CIPHER *cipher = NULL;
        const char *name = OBJ_nid2sn(nid);
        if (name)
        {
            cipher = EVP_get_cipherbyname(name);
        }
#else  /* if defined(LIBRESSL_VERSION_NUMBER) */
        const EVP_CIPHER *cipher = EVP_get_cipherbynid(nid);
#endif
        /* We cast the const away so we can keep the function prototype
         * compatible with EVP_CIPHER_do_all_provided */
        collect_ciphers((EVP_CIPHER *) cipher, &cipher_list);
    }
#endif

    /* cast to non-const to prevent warning */
    qsort((EVP_CIPHER *)cipher_list.list, cipher_list.num, sizeof(*cipher_list.list), cipher_name_cmp);

    for (size_t i = 0; i < cipher_list.num; i++)
    {
        if (!cipher_kt_insecure(EVP_CIPHER_get0_name(cipher_list.list[i])))
        {
            print_cipher(EVP_CIPHER_get0_name(cipher_list.list[i]));
        }
    }

    printf("\nThe following ciphers have a block size of less than 128 bits, \n"
           "and are therefore deprecated.  Do not use unless you have to.\n\n");
    for (int i = 0; i < cipher_list.num; i++)
    {
        if (cipher_kt_insecure(EVP_CIPHER_get0_name(cipher_list.list[i])))
        {
            print_cipher(EVP_CIPHER_get0_name(cipher_list.list[i]));
        }
    }
    printf("\n");
}

void
print_digest(EVP_MD *digest, void *unused)
{
    printf("%s %d bit digest size\n", md_kt_name(EVP_MD_get0_name(digest)),
           EVP_MD_size(digest) * 8);
}

void
show_available_digests(void)
{
#ifndef ENABLE_SMALL
    printf("The following message digests are available for use with\n"
           PACKAGE_NAME ".  A message digest is used in conjunction with\n"
           "the HMAC function, to authenticate received packets.\n"
           "You can specify a message digest as parameter to\n"
           "the --auth option.\n");
    printf("See also openssl list -digest-algorithms\n\n");
#endif

#if OPENSSL_VERSION_NUMBER >= 0x30000000L
    EVP_MD_do_all_provided(NULL, print_digest, NULL);
#else
    for (int nid = 0; nid < 10000; ++nid)
    {
        /* OpenBSD/LibreSSL reimplemented EVP_get_digestbyname and broke
         * calling EVP_get_digestbynid with an invalid nid in the process
         * so that it would segfault. */
#ifdef LIBRESSL_VERSION_NUMBER
        const EVP_MD *digest = NULL;
        const char *name = OBJ_nid2sn(nid);
        if (name)
        {
            digest = EVP_get_digestbyname(name);
        }
#else  /* ifdef LIBRESSL_VERSION_NUMBER */
        const EVP_MD *digest = EVP_get_digestbynid(nid);
#endif
        if (digest)
        {
            /* We cast the const away so we can keep the function prototype
             * compatible with EVP_MD_do_all_provided */
            print_digest((EVP_MD *)digest, NULL);
        }
    }
#endif /* if OPENSSL_VERSION_NUMBER >= 0x30000000L */
    printf("\n");
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
 * Generic cipher key type functions
 *
 */

static evp_cipher_type *
cipher_get(const char *ciphername)
{
    ASSERT(ciphername);

    ciphername = translate_cipher_name_from_openvpn(ciphername);
    return EVP_CIPHER_fetch(NULL, ciphername, NULL);
}

bool
cipher_valid_reason(const char *ciphername, const char **reason)
{
    bool ret = false;
    evp_cipher_type *cipher = cipher_get(ciphername);
    if (!cipher)
    {
        crypto_msg(D_LOW, "Cipher algorithm '%s' not found", ciphername);
        *reason = "disabled because unknown";
        goto out;
    }

#ifdef OPENSSL_FIPS
    /* Rhel 8/CentOS 8 have a patched OpenSSL version that return a cipher
     * here that is actually not usable if in FIPS mode */

    if (FIPS_mode() && !(EVP_CIPHER_flags(cipher) & EVP_CIPH_FLAG_FIPS))
    {
        msg(D_LOW, "Cipher algorithm '%s' is known by OpenSSL library but "
            "currently disabled by running in FIPS mode.", ciphername);
        *reason = "disabled by FIPS mode";
        goto out;
    }
#endif
    if (EVP_CIPHER_key_length(cipher) > MAX_CIPHER_KEY_LENGTH)
    {
        msg(D_LOW, "Cipher algorithm '%s' uses a default key size (%d bytes) "
            "which is larger than " PACKAGE_NAME "'s current maximum key size "
            "(%d bytes)", ciphername, EVP_CIPHER_key_length(cipher),
            MAX_CIPHER_KEY_LENGTH);
        *reason = "disabled due to key size too large";
        goto out;
    }

    ret = true;
    *reason = NULL;
out:
    EVP_CIPHER_free(cipher);
    return ret;
}

const char *
cipher_kt_name(const char *ciphername)
{
    ASSERT(ciphername);
    if (strcmp("none", ciphername) == 0)
    {
        return "[null-cipher]";
    }

    evp_cipher_type *cipher_kt = cipher_get(ciphername);
    if (!cipher_kt)
    {
        return NULL;
    }

    const char *name = EVP_CIPHER_name(cipher_kt);
    EVP_CIPHER_free(cipher_kt);
    return translate_cipher_name_to_openvpn(name);
}

int
cipher_kt_key_size(const char *ciphername)
{
    evp_cipher_type *cipher = cipher_get(ciphername);
    int size = EVP_CIPHER_key_length(cipher);
    EVP_CIPHER_free(cipher);
    return size;
}

int
cipher_kt_iv_size(const char *ciphername)
{
    evp_cipher_type *cipher = cipher_get(ciphername);
    int ivsize = EVP_CIPHER_iv_length(cipher);
    EVP_CIPHER_free(cipher);
    return ivsize;
}

int
cipher_kt_block_size(const char *ciphername)
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
    evp_cipher_type *cbc_cipher = NULL;
    evp_cipher_type *cipher = cipher_get(ciphername);
    if (!cipher)
    {
        return 0;
    }

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

    cbc_cipher = EVP_CIPHER_fetch(NULL, translate_cipher_name_from_openvpn(name), NULL);
    if (cbc_cipher)
    {
        block_size = EVP_CIPHER_block_size(cbc_cipher);
    }

cleanup:
    EVP_CIPHER_free(cbc_cipher);
    EVP_CIPHER_free(cipher);
    free(name);
    return block_size;
}

int
cipher_kt_tag_size(const char *ciphername)
{
    if (cipher_kt_mode_aead(ciphername))
    {
        return OPENVPN_AEAD_TAG_LENGTH;
    }
    else
    {
        return 0;
    }
}

bool
cipher_kt_insecure(const char *ciphername)
{

    if (cipher_kt_block_size(ciphername) >= 128 / 8)
    {
        return false;
    }
#ifdef NID_chacha20_poly1305
    evp_cipher_type *cipher = cipher_get(ciphername);
    if (cipher)
    {
        bool ischachapoly = (EVP_CIPHER_nid(cipher) == NID_chacha20_poly1305);
        EVP_CIPHER_free(cipher);
        if (ischachapoly)
        {
            return false;
        }
    }
#endif
    return true;
}

int
cipher_kt_mode(const EVP_CIPHER *cipher_kt)
{
    ASSERT(NULL != cipher_kt);
    return EVP_CIPHER_mode(cipher_kt);
}

bool
cipher_kt_mode_cbc(const char *ciphername)
{
    evp_cipher_type *cipher = cipher_get(ciphername);

    bool ret = cipher && (cipher_kt_mode(cipher) == OPENVPN_MODE_CBC
                          /* Exclude AEAD cipher modes, they require a different API */
#ifdef EVP_CIPH_FLAG_CTS
                          && !(EVP_CIPHER_flags(cipher) & EVP_CIPH_FLAG_CTS)
#endif
                          && !(EVP_CIPHER_flags(cipher) & EVP_CIPH_FLAG_AEAD_CIPHER));
    EVP_CIPHER_free(cipher);
    return ret;
}

bool
cipher_kt_mode_ofb_cfb(const char *ciphername)
{
    evp_cipher_type *cipher = cipher_get(ciphername);
    bool ofb_cfb = cipher && (cipher_kt_mode(cipher) == OPENVPN_MODE_OFB
                              || cipher_kt_mode(cipher) == OPENVPN_MODE_CFB)
                   /* Exclude AEAD cipher modes, they require a different API */
                   && !(EVP_CIPHER_flags(cipher) & EVP_CIPH_FLAG_AEAD_CIPHER);
    EVP_CIPHER_free(cipher);
    return ofb_cfb;
}

bool
cipher_kt_mode_aead(const char *ciphername)
{
    bool isaead = false;

    evp_cipher_type *cipher = cipher_get(ciphername);
    if (cipher)
    {
        if (EVP_CIPHER_mode(cipher) == OPENVPN_MODE_GCM)
        {
            isaead = true;
        }

#ifdef NID_chacha20_poly1305
        if (EVP_CIPHER_nid(cipher) == NID_chacha20_poly1305)
        {
            isaead =  true;
        }
#endif
    }

    EVP_CIPHER_free(cipher);

    return isaead;
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
cipher_ctx_init(EVP_CIPHER_CTX *ctx, const uint8_t *key,
                const char *ciphername, int enc)
{
    ASSERT(NULL != ciphername && NULL != ctx);
    evp_cipher_type *kt = cipher_get(ciphername);

    EVP_CIPHER_CTX_reset(ctx);
    if (!EVP_CipherInit(ctx, kt, NULL, NULL, enc))
    {
        crypto_msg(M_FATAL, "EVP cipher init #1");
    }
    if (!EVP_CipherInit_ex(ctx, NULL, NULL, key, NULL, enc))
    {
        crypto_msg(M_FATAL, "EVP cipher init #2");
    }

    /* make sure we used a big enough key */
    ASSERT(EVP_CIPHER_CTX_key_length(ctx) <= EVP_CIPHER_key_length(kt));
    EVP_CIPHER_free(kt);
}

int
cipher_ctx_iv_length(const EVP_CIPHER_CTX *ctx)
{
    return EVP_CIPHER_CTX_iv_length(ctx);
}

int
cipher_ctx_get_tag(EVP_CIPHER_CTX *ctx, uint8_t *tag_buf, int tag_size)
{
    return EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, tag_size, tag_buf);
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


bool
cipher_ctx_mode_cbc(const cipher_ctx_t *ctx)
{
    if (!ctx)
    {
        return false;
    }

    int flags = EVP_CIPHER_CTX_flags(ctx);
    int mode = EVP_CIPHER_CTX_mode(ctx);

    return mode == EVP_CIPH_CBC_MODE
           /* Exclude AEAD cipher modes, they require a different API */
#ifdef EVP_CIPH_FLAG_CTS
           && !(flags & EVP_CIPH_FLAG_CTS)
#endif
           && !(flags & EVP_CIPH_FLAG_AEAD_CIPHER);
}

bool
cipher_ctx_mode_ofb_cfb(const cipher_ctx_t *ctx)
{
    if (!ctx)
    {
        return false;
    }

    int mode = EVP_CIPHER_CTX_get_mode(ctx);

    return (mode == EVP_CIPH_OFB_MODE || mode == EVP_CIPH_CFB_MODE)
           /* Exclude AEAD cipher modes, they require a different API */
           && !(EVP_CIPHER_CTX_flags(ctx) & EVP_CIPH_FLAG_AEAD_CIPHER);
}

bool
cipher_ctx_mode_aead(const cipher_ctx_t *ctx)
{
    if (ctx)
    {
        int flags = EVP_CIPHER_CTX_flags(ctx);
        if (flags & EVP_CIPH_FLAG_AEAD_CIPHER)
        {
            return true;
        }

#if defined(NID_chacha20_poly1305) && OPENSSL_VERSION_NUMBER < 0x30000000L
        if (EVP_CIPHER_CTX_nid(ctx) == NID_chacha20_poly1305)
        {
            return true;
        }
#endif
    }

    return false;
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
    if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, tag_len, tag))
    {
        return 0;
    }

    return cipher_ctx_final(ctx, dst, dst_len);
}

void
cipher_des_encrypt_ecb(const unsigned char key[DES_KEY_LENGTH],
                       unsigned char src[DES_KEY_LENGTH],
                       unsigned char dst[DES_KEY_LENGTH])
{
    /* We are using 3DES here with three times the same key to cheat
     * and emulate DES as 3DES is better supported than DES */
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx)
    {
        crypto_msg(M_FATAL, "%s: EVP_CIPHER_CTX_new() failed", __func__);
    }

    unsigned char key3[DES_KEY_LENGTH*3];
    for (int i = 0; i < 3; i++)
    {
        memcpy(key3 + (i * DES_KEY_LENGTH), key, DES_KEY_LENGTH);
    }

    if (!EVP_EncryptInit_ex(ctx, EVP_des_ede3_ecb(), NULL, key3, NULL))
    {
        crypto_msg(M_FATAL, "%s: EVP_EncryptInit_ex() failed", __func__);
    }

    int len;

    /* The EVP_EncryptFinal method will write to the dst+len pointer even
     * though there is nothing to encrypt anymore, provide space for that to
     * not overflow the stack */
    unsigned char dst2[DES_KEY_LENGTH * 2];
    if (!EVP_EncryptUpdate(ctx, dst2, &len, src, DES_KEY_LENGTH))
    {
        crypto_msg(M_FATAL, "%s: EVP_EncryptUpdate() failed", __func__);
    }

    if (!EVP_EncryptFinal(ctx, dst2 + len, &len))
    {
        crypto_msg(M_FATAL, "%s: EVP_EncryptFinal() failed", __func__);
    }

    memcpy(dst, dst2, DES_KEY_LENGTH);

    EVP_CIPHER_CTX_free(ctx);
}

/*
 *
 * Generic message digest information functions
 *
 */


static evp_md_type *
md_get(const char *digest)
{
    evp_md_type *md = NULL;
    ASSERT(digest);
    md = EVP_MD_fetch(NULL, digest, NULL);
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


bool
md_valid(const char *digest)
{
    evp_md_type *md = EVP_MD_fetch(NULL, digest, NULL);
    bool valid = (md != NULL);
    EVP_MD_free(md);
    return valid;
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
md_kt_name(const char *mdname)
{
    if (!strcmp("none", mdname))
    {
        return "[null-digest]";
    }
    evp_md_type *kt = md_get(mdname);
    const char *name = EVP_MD_get0_name(kt);

    /* Search for a digest name translation */
    for (size_t i = 0; i < digest_name_translation_table_count; i++)
    {
        const cipher_name_pair *pair = &digest_name_translation_table[i];
        if (!strcmp(name, pair->lib_name))
        {
            name = pair->openvpn_name;
        }
    }

    EVP_MD_free(kt);
    return name;
}

unsigned char
md_kt_size(const char *mdname)
{
    if (!strcmp("none", mdname))
    {
        return 0;
    }
    evp_md_type *kt = md_get(mdname);
    unsigned char size =  (unsigned char)EVP_MD_size(kt);
    EVP_MD_free(kt);
    return size;
}


/*
 *
 * Generic message digest functions
 *
 */

int
md_full(const char *mdname, const uint8_t *src, int src_len, uint8_t *dst)
{
    unsigned int in_md_len = 0;
    evp_md_type *kt = md_get(mdname);

    int ret = EVP_Digest(src, src_len, dst, &in_md_len, kt, NULL);
    EVP_MD_free(kt);
    return ret;
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
md_ctx_init(EVP_MD_CTX *ctx, const char *mdname)
{
    evp_md_type *kt = md_get(mdname);
    ASSERT(NULL != ctx && NULL != kt);

    EVP_MD_CTX_init(ctx);
    if (!EVP_DigestInit(ctx, kt))
    {
        crypto_msg(M_FATAL, "EVP_DigestInit failed");
    }
    EVP_MD_free(kt);
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
#if OPENSSL_VERSION_NUMBER < 0x30000000L
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
hmac_ctx_init(HMAC_CTX *ctx, const uint8_t *key, const char *mdname)
{
    evp_md_type *kt = md_get(mdname);
    ASSERT(NULL != kt && NULL != ctx);

    int key_len = EVP_MD_size(kt);
    HMAC_CTX_reset(ctx);
    if (!HMAC_Init_ex(ctx, key, key_len, kt, NULL))
    {
        crypto_msg(M_FATAL, "HMAC_Init_ex failed");
    }

    /* make sure we used a big enough key */
    ASSERT(HMAC_size(ctx) <= key_len);
}

void
hmac_ctx_cleanup(HMAC_CTX *ctx)
{
    HMAC_CTX_reset(ctx);
}

int
hmac_ctx_size(HMAC_CTX *ctx)
{
    return HMAC_size(ctx);
}

void
hmac_ctx_reset(HMAC_CTX *ctx)
{
    if (!HMAC_Init_ex(ctx, NULL, 0, NULL, NULL))
    {
        crypto_msg(M_FATAL, "HMAC_Init_ex failed");
    }
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
#else  /* if OPENSSL_VERSION_NUMBER < 0x30000000L */
hmac_ctx_t *
hmac_ctx_new(void)
{
    hmac_ctx_t *ctx;
    ALLOC_OBJ_CLEAR(ctx, hmac_ctx_t);
    EVP_MAC *hmac = EVP_MAC_fetch(NULL, "HMAC", NULL);
    ctx->ctx = EVP_MAC_CTX_new(hmac);
    check_malloc_return(ctx->ctx);

    EVP_MAC_free(hmac);

    return ctx;
}

void
hmac_ctx_free(hmac_ctx_t *ctx)
{
    EVP_MAC_CTX_free(ctx->ctx);
    secure_memzero(ctx, sizeof(hmac_ctx_t));
    free(ctx);
}

void
hmac_ctx_init(hmac_ctx_t *ctx, const uint8_t *key, const char *mdname)
{
    evp_md_type *kt = md_get(mdname);
    ASSERT(NULL != kt && NULL != ctx && ctx->ctx != NULL);

    /* We need to make a copy of the key since the OSSL parameters
     * only reference it */
    memcpy(ctx->key, key, EVP_MD_size(kt));

    /* Lookup/setting of parameters in OpenSSL 3.0 are string based
     *
     * The OSSL_PARAM_construct_utf8_string needs a non const str but this
     * only used for lookup so we cast (as OpenSSL also does internally)
     * the constness away here.
     */
    ctx->params[0] = OSSL_PARAM_construct_utf8_string("digest",
                                                      (char *) EVP_MD_get0_name(kt), 0);
    ctx->params[1] = OSSL_PARAM_construct_octet_string("key",
                                                       ctx->key, EVP_MD_size(kt));
    ctx->params[2] = OSSL_PARAM_construct_end();

    if (!EVP_MAC_init(ctx->ctx, NULL, 0, ctx->params))
    {
        crypto_msg(M_FATAL, "EVP_MAC_init failed");
    }

    EVP_MD_free(kt);
}

void
hmac_ctx_cleanup(hmac_ctx_t *ctx)
{
    EVP_MAC_init(ctx->ctx, NULL, 0, NULL);
}

int
hmac_ctx_size(hmac_ctx_t *ctx)
{
    return (int)EVP_MAC_CTX_get_mac_size(ctx->ctx);
}

void
hmac_ctx_reset(hmac_ctx_t *ctx)
{
    /* The OpenSSL MAC API lacks a reset method and passing NULL as params
     * does not reset it either, so use the params array to reinitialise it the
     * same way as before */
    if (!EVP_MAC_init(ctx->ctx, NULL, 0, ctx->params))
    {
        crypto_msg(M_FATAL, "EVP_MAC_init failed");
    }
}

void
hmac_ctx_update(hmac_ctx_t *ctx, const uint8_t *src, int src_len)
{
    EVP_MAC_update(ctx->ctx, src, src_len);
}

void
hmac_ctx_final(hmac_ctx_t *ctx, uint8_t *dst)
{
    /* The calling code always gives us a buffer that has the size of our
     * algorithm */
    size_t in_hmac_len = EVP_MAC_CTX_get_mac_size(ctx->ctx);

    EVP_MAC_final(ctx->ctx, dst, &in_hmac_len, in_hmac_len);
}
#endif /* if OPENSSL_VERSION_NUMBER < 0x30000000L */

int
memcmp_constant_time(const void *a, const void *b, size_t size)
{
    return CRYPTO_memcmp(a, b, size);
}

#if (OPENSSL_VERSION_NUMBER >= 0x10100000L) && !defined(LIBRESSL_VERSION_NUMBER)
bool
ssl_tls1_PRF(const uint8_t *seed, int seed_len, const uint8_t *secret,
             int secret_len, uint8_t *output, int output_len)
{
    EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_TLS1_PRF, NULL);
    if (!pctx)
    {
        return false;
    }

    bool ret = false;
    if (!EVP_PKEY_derive_init(pctx))
    {
        goto out;
    }

    if (!EVP_PKEY_CTX_set_tls1_prf_md(pctx, EVP_md5_sha1()))
    {
        goto out;
    }

    if (!EVP_PKEY_CTX_set1_tls1_prf_secret(pctx, secret, secret_len))
    {
        goto out;
    }

    if (!EVP_PKEY_CTX_add1_tls1_prf_seed(pctx, seed, seed_len))
    {
        goto out;
    }

    size_t out_len = output_len;
    if (!EVP_PKEY_derive(pctx, output, &out_len))
    {
        goto out;
    }
    if (out_len != output_len)
    {
        goto out;
    }
    ret = true;
out:
    EVP_PKEY_CTX_free(pctx);
    return ret;
}
#else  /* if OPENSSL_VERSION_NUMBER >= 0x10100000L */
/*
 * Generate the hash required by for the \c tls1_PRF function.
 *
 * We cannot use our normal hmac_* function as they do not work
 * in a FIPS environment (no MD5 allowed, which we need). Instead
 * we need to directly use the EVP_MD_* API with the special
 * EVP_MD_CTX_FLAG_NON_FIPS_ALLOW flag.
 *
 * The function below is adapted from OpenSSL 1.0.2t
 *
 * @param md_kt         Message digest to use
 * @param sec           Secret to base the hash on
 * @param sec_len       Length of the secret
 * @param seed          Seed to hash
 * @param seed_len      Length of the seed
 * @param out           Output buffer
 * @param olen          Length of the output buffer
 */
static
bool
tls1_P_hash(const EVP_MD *md, const unsigned char *sec,
            int sec_len, const void *seed, int seed_len,
            unsigned char *out, int olen)
{
    int chunk;
    size_t j;
    EVP_MD_CTX *ctx, *ctx_tmp, *ctx_init;
    EVP_PKEY *mac_key;
    unsigned char A1[EVP_MAX_MD_SIZE];
    size_t A1_len = EVP_MAX_MD_SIZE;
    int ret = false;

    chunk = EVP_MD_size(md);
    OPENSSL_assert(chunk >= 0);

    ctx = md_ctx_new();
    ctx_tmp = md_ctx_new();
    ctx_init = md_ctx_new();
    EVP_MD_CTX_set_flags(ctx_init, EVP_MD_CTX_FLAG_NON_FIPS_ALLOW);
    mac_key = EVP_PKEY_new_mac_key(EVP_PKEY_HMAC, NULL, sec, sec_len);
    if (!mac_key)
    {
        goto err;
    }
    if (!EVP_DigestSignInit(ctx_init, NULL, md, NULL, mac_key))
    {
        goto err;
    }
    if (!EVP_MD_CTX_copy_ex(ctx, ctx_init))
    {
        goto err;
    }
    if (!EVP_DigestSignUpdate(ctx, seed, seed_len))
    {
        goto err;
    }
    if (!EVP_DigestSignFinal(ctx, A1, &A1_len))
    {
        goto err;
    }

    for (;; )
    {
        /* Reinit mac contexts */
        if (!EVP_MD_CTX_copy_ex(ctx, ctx_init))
        {
            goto err;
        }
        if (!EVP_DigestSignUpdate(ctx, A1, A1_len))
        {
            goto err;
        }
        if (olen > chunk && !EVP_MD_CTX_copy_ex(ctx_tmp, ctx))
        {
            goto err;
        }
        if (!EVP_DigestSignUpdate(ctx, seed, seed_len))
        {
            goto err;
        }

        if (olen > chunk)
        {
            j = olen;
            if (!EVP_DigestSignFinal(ctx, out, &j))
            {
                goto err;
            }
            out += j;
            olen -= j;
            /* calc the next A1 value */
            if (!EVP_DigestSignFinal(ctx_tmp, A1, &A1_len))
            {
                goto err;
            }
        }
        else
        {
            A1_len = EVP_MAX_MD_SIZE;
            /* last one */
            if (!EVP_DigestSignFinal(ctx, A1, &A1_len))
            {
                goto err;
            }
            memcpy(out, A1, olen);
            break;
        }
    }
    ret = true;
err:
    EVP_PKEY_free(mac_key);
    EVP_MD_CTX_free(ctx);
    EVP_MD_CTX_free(ctx_tmp);
    EVP_MD_CTX_free(ctx_init);
    OPENSSL_cleanse(A1, sizeof(A1));
    return ret;
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
    bool ret = true;
    struct gc_arena gc = gc_new();
    /* For some reason our md_get("MD5") fails otherwise in the unit test */
    const EVP_MD *md5 = EVP_md5();
    const EVP_MD *sha1 = EVP_sha1();

    uint8_t *out2 = (uint8_t *)gc_malloc(olen, false, &gc);

    int len = slen/2;
    const uint8_t *S1 = sec;
    const uint8_t *S2 = &(sec[len]);
    len += (slen&1); /* add for odd, make longer */

    if (!tls1_P_hash(md5, S1, len, label, label_len, out1, olen))
    {
        ret = false;
        goto done;
    }

    if (!tls1_P_hash(sha1, S2, len, label, label_len, out2, olen))
    {
        ret = false;
        goto done;
    }

    for (int i = 0; i < olen; i++)
    {
        out1[i] ^= out2[i];
    }

    secure_memzero(out2, olen);

    dmsg(D_SHOW_KEY_SOURCE, "tls1_PRF out[%d]: %s", olen, format_hex(out1, olen, 0, &gc));
done:
    gc_free(&gc);
    return ret;
}
#endif /* if OPENSSL_VERSION_NUMBER >= 0x10100000L */
#endif /* ENABLE_CRYPTO_OPENSSL */
