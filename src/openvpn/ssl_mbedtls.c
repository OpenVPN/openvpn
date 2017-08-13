/*
 *  OpenVPN -- An application to securely tunnel IP networks
 *             over a single TCP/UDP port, with support for SSL/TLS-based
 *             session authentication and key exchange,
 *             packet encryption, packet authentication, and
 *             packet compression.
 *
 *  Copyright (C) 2002-2017 OpenVPN Technologies, Inc. <sales@openvpn.net>
 *  Copyright (C) 2010-2017 Fox Crypto B.V. <openvpn@fox-it.com>
 *  Copyright (C) 2006-2010, Brainspark B.V.
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
 * @file Control Channel mbed TLS Backend
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#elif defined(_MSC_VER)
#include "config-msvc.h"
#endif

#include "syshead.h"

#if defined(ENABLE_CRYPTO) && defined(ENABLE_CRYPTO_MBEDTLS)

#include "errlevel.h"
#include "ssl_backend.h"
#include "base64.h"
#include "buffer.h"
#include "misc.h"
#include "manage.h"
#include "ssl_common.h"

#include <mbedtls/havege.h>

#include "ssl_verify_mbedtls.h"
#include <mbedtls/debug.h>
#include <mbedtls/error.h>
#include <mbedtls/version.h>

#if MBEDTLS_VERSION_NUMBER >= 0x02040000
    #include <mbedtls/net_sockets.h>
#else
    #include <mbedtls/net.h>
#endif

#include <mbedtls/oid.h>
#include <mbedtls/pem.h>
#include <mbedtls/sha256.h>

void
tls_init_lib(void)
{
}

void
tls_free_lib(void)
{
}

void
tls_clear_error(void)
{
}

void
tls_ctx_server_new(struct tls_root_ctx *ctx)
{
    ASSERT(NULL != ctx);
    CLEAR(*ctx);

    ALLOC_OBJ_CLEAR(ctx->dhm_ctx, mbedtls_dhm_context);

    ALLOC_OBJ_CLEAR(ctx->ca_chain, mbedtls_x509_crt);

    ctx->endpoint = MBEDTLS_SSL_IS_SERVER;
    ctx->initialised = true;
}

void
tls_ctx_client_new(struct tls_root_ctx *ctx)
{
    ASSERT(NULL != ctx);
    CLEAR(*ctx);

    ALLOC_OBJ_CLEAR(ctx->dhm_ctx, mbedtls_dhm_context);
    ALLOC_OBJ_CLEAR(ctx->ca_chain, mbedtls_x509_crt);

    ctx->endpoint = MBEDTLS_SSL_IS_CLIENT;
    ctx->initialised = true;
}

void
tls_ctx_free(struct tls_root_ctx *ctx)
{
    if (ctx)
    {
        mbedtls_pk_free(ctx->priv_key);
        if (ctx->priv_key)
        {
            free(ctx->priv_key);
        }

        mbedtls_x509_crt_free(ctx->ca_chain);
        if (ctx->ca_chain)
        {
            free(ctx->ca_chain);
        }

        mbedtls_x509_crt_free(ctx->crt_chain);
        if (ctx->crt_chain)
        {
            free(ctx->crt_chain);
        }

        mbedtls_dhm_free(ctx->dhm_ctx);
        if (ctx->dhm_ctx)
        {
            free(ctx->dhm_ctx);
        }

        mbedtls_x509_crl_free(ctx->crl);
        if (ctx->crl)
        {
            free(ctx->crl);
        }

#if defined(ENABLE_PKCS11)
        if (ctx->priv_key_pkcs11 != NULL)
        {
            mbedtls_pkcs11_priv_key_free(ctx->priv_key_pkcs11);
            free(ctx->priv_key_pkcs11);
        }
#endif
#if defined(MANAGMENT_EXTERNAL_KEY)
        if (ctx->external_key != NULL)
        {
            free(ctx->external_key);
        }
#endif

        if (ctx->allowed_ciphers)
        {
            free(ctx->allowed_ciphers);
        }

        CLEAR(*ctx);

        ctx->initialised = false;

    }
}

bool
tls_ctx_initialised(struct tls_root_ctx *ctx)
{
    ASSERT(NULL != ctx);
    return ctx->initialised;
}

void
key_state_export_keying_material(struct key_state_ssl *ssl,
                                 struct tls_session *session)
{
}

void
tls_ctx_set_options(struct tls_root_ctx *ctx, unsigned int ssl_flags)
{
}

static const char *
tls_translate_cipher_name(const char *cipher_name)
{
    const tls_cipher_name_pair *pair = tls_get_cipher_name_pair(cipher_name, strlen(cipher_name));

    if (NULL == pair)
    {
        /* No translation found, return original */
        return cipher_name;
    }

    if (0 != strcmp(cipher_name, pair->iana_name))
    {
        /* Deprecated name found, notify user */
        msg(M_WARN, "Deprecated cipher suite name '%s', please use IANA name '%s'", pair->openssl_name, pair->iana_name);
    }

    return pair->iana_name;
}

void
tls_ctx_restrict_ciphers(struct tls_root_ctx *ctx, const char *ciphers)
{
    char *tmp_ciphers, *tmp_ciphers_orig, *token;
    int i, cipher_count;
    int ciphers_len;

    if (NULL == ciphers)
    {
        return; /* Nothing to do */

    }
    ciphers_len = strlen(ciphers);

    ASSERT(NULL != ctx);
    ASSERT(0 != ciphers_len);

    /* Get number of ciphers */
    for (i = 0, cipher_count = 1; i < ciphers_len; i++)
    {
        if (ciphers[i] == ':')
        {
            cipher_count++;
        }
    }

    /* Allocate an array for them */
    ALLOC_ARRAY_CLEAR(ctx->allowed_ciphers, int, cipher_count+1)

    /* Parse allowed ciphers, getting IDs */
    i = 0;
    tmp_ciphers_orig = tmp_ciphers = string_alloc(ciphers, NULL);

    token = strtok(tmp_ciphers, ":");
    while (token)
    {
        ctx->allowed_ciphers[i] = mbedtls_ssl_get_ciphersuite_id(
            tls_translate_cipher_name(token));
        if (0 != ctx->allowed_ciphers[i])
        {
            i++;
        }
        token = strtok(NULL, ":");
    }
    free(tmp_ciphers_orig);
}

void
tls_ctx_check_cert_time(const struct tls_root_ctx *ctx)
{
    ASSERT(ctx);
    if (ctx->crt_chain == NULL)
    {
        return; /* Nothing to check if there is no certificate */
    }

    if (mbedtls_x509_time_is_future(&ctx->crt_chain->valid_from))
    {
        msg(M_WARN, "WARNING: Your certificate is not yet valid!");
    }

    if (mbedtls_x509_time_is_past(&ctx->crt_chain->valid_to))
    {
        msg(M_WARN, "WARNING: Your certificate has expired!");
    }
}

void
tls_ctx_load_dh_params(struct tls_root_ctx *ctx, const char *dh_file,
                       const char *dh_inline
                       )
{
    if (!strcmp(dh_file, INLINE_FILE_TAG) && dh_inline)
    {
        if (!mbed_ok(mbedtls_dhm_parse_dhm(ctx->dhm_ctx,
                                           (const unsigned char *) dh_inline, strlen(dh_inline)+1)))
        {
            msg(M_FATAL, "Cannot read inline DH parameters");
        }
    }
    else
    {
        if (!mbed_ok(mbedtls_dhm_parse_dhmfile(ctx->dhm_ctx, dh_file)))
        {
            msg(M_FATAL, "Cannot read DH parameters from file %s", dh_file);
        }
    }

    msg(D_TLS_DEBUG_LOW, "Diffie-Hellman initialized with " counter_format " bit key",
        (counter_type) 8 * mbedtls_mpi_size(&ctx->dhm_ctx->P));
}

void
tls_ctx_load_ecdh_params(struct tls_root_ctx *ctx, const char *curve_name
                         )
{
    if (NULL != curve_name)
    {
        msg(M_WARN, "WARNING: mbed TLS builds do not support specifying an ECDH "
            "curve, using default curves.");
    }
}

int
tls_ctx_load_pkcs12(struct tls_root_ctx *ctx, const char *pkcs12_file,
                    const char *pkcs12_file_inline,
                    bool load_ca_file
                    )
{
    msg(M_FATAL, "PKCS #12 files not yet supported for mbed TLS.");
    return 0;
}

#ifdef ENABLE_CRYPTOAPI
void
tls_ctx_load_cryptoapi(struct tls_root_ctx *ctx, const char *cryptoapi_cert)
{
    msg(M_FATAL, "Windows CryptoAPI not yet supported for mbed TLS.");
}
#endif /* _WIN32 */

void
tls_ctx_load_cert_file(struct tls_root_ctx *ctx, const char *cert_file,
                       const char *cert_inline
                       )
{
    ASSERT(NULL != ctx);

    if (!ctx->crt_chain)
    {
        ALLOC_OBJ_CLEAR(ctx->crt_chain, mbedtls_x509_crt);
    }

    if (!strcmp(cert_file, INLINE_FILE_TAG) && cert_inline)
    {
        if (!mbed_ok(mbedtls_x509_crt_parse(ctx->crt_chain,
                                            (const unsigned char *) cert_inline, strlen(cert_inline)+1)))
        {
            msg(M_FATAL, "Cannot load inline certificate file");
        }
    }
    else
    {
        if (!mbed_ok(mbedtls_x509_crt_parse_file(ctx->crt_chain, cert_file)))
        {
            msg(M_FATAL, "Cannot load certificate file %s", cert_file);
        }
    }
}

int
tls_ctx_load_priv_file(struct tls_root_ctx *ctx, const char *priv_key_file,
                       const char *priv_key_inline
                       )
{
    int status;
    ASSERT(NULL != ctx);

    if (!ctx->priv_key)
    {
        ALLOC_OBJ_CLEAR(ctx->priv_key, mbedtls_pk_context);
    }

    if (!strcmp(priv_key_file, INLINE_FILE_TAG) && priv_key_inline)
    {
        status = mbedtls_pk_parse_key(ctx->priv_key,
                                      (const unsigned char *) priv_key_inline, strlen(priv_key_inline)+1,
                                      NULL, 0);

        if (MBEDTLS_ERR_PK_PASSWORD_REQUIRED == status)
        {
            char passbuf[512] = {0};
            pem_password_callback(passbuf, 512, 0, NULL);
            status = mbedtls_pk_parse_key(ctx->priv_key,
                                          (const unsigned char *) priv_key_inline,
                                          strlen(priv_key_inline)+1, (unsigned char *) passbuf,
                                          strlen(passbuf));
        }
    }
    else
    {
        status = mbedtls_pk_parse_keyfile(ctx->priv_key, priv_key_file, NULL);
        if (MBEDTLS_ERR_PK_PASSWORD_REQUIRED == status)
        {
            char passbuf[512] = {0};
            pem_password_callback(passbuf, 512, 0, NULL);
            status = mbedtls_pk_parse_keyfile(ctx->priv_key, priv_key_file, passbuf);
        }
    }
    if (!mbed_ok(status))
    {
#ifdef ENABLE_MANAGEMENT
        if (management && (MBEDTLS_ERR_PK_PASSWORD_MISMATCH == status))
        {
            management_auth_failure(management, UP_TYPE_PRIVATE_KEY, NULL);
        }
#endif
        msg(M_WARN, "Cannot load private key file %s", priv_key_file);
        return 1;
    }

    if (!mbed_ok(mbedtls_pk_check_pair(&ctx->crt_chain->pk, ctx->priv_key)))
    {
        msg(M_WARN, "Private key does not match the certificate");
        return 1;
    }

    return 0;
}

#ifdef MANAGMENT_EXTERNAL_KEY


struct external_context {
    size_t signature_length;
};

/**
 * external_pkcs1_sign implements a mbed TLS rsa_sign_func callback, that uses
 * the management interface to request an RSA signature for the supplied hash.
 *
 * @param ctx_voidptr   Management external key context.
 * @param f_rng         (Unused)
 * @param p_rng         (Unused)
 * @param mode          RSA mode (should be RSA_PRIVATE).
 * @param md_alg        Message digest ('hash') algorithm type.
 * @param hashlen       Length of hash (overridden by length specified by md_alg
 *                      if md_alg != MBEDTLS_MD_NONE).
 * @param hash          The digest ('hash') to sign. Should have a size
 *                      matching the length of md_alg (if != MBEDTLS_MD_NONE),
 *                      or hashlen otherwise.
 * @param sig           Buffer that returns the signature. Should be at least of
 *                      size ctx->signature_length.
 *
 * @return 0 on success, non-zero mbed TLS error code on failure.
 */
static inline int
external_pkcs1_sign( void *ctx_voidptr,
                     int (*f_rng)(void *, unsigned char *, size_t), void *p_rng, int mode,
                     mbedtls_md_type_t md_alg, unsigned int hashlen, const unsigned char *hash,
                     unsigned char *sig )
{
    struct external_context *const ctx = ctx_voidptr;
    char *in_b64 = NULL;
    char *out_b64 = NULL;
    int rv;
    unsigned char *p = sig;
    size_t asn_len = 0, oid_size = 0, sig_len = 0;
    const char *oid = NULL;

    if (NULL == ctx)
    {
        return MBEDTLS_ERR_RSA_BAD_INPUT_DATA;
    }

    if (MBEDTLS_RSA_PRIVATE != mode)
    {
        return MBEDTLS_ERR_RSA_BAD_INPUT_DATA;
    }

    /*
     * Support a wide range of hashes. TLSv1.1 and before only need SIG_RSA_RAW,
     * but TLSv1.2 needs the full suite of hashes.
     *
     * This code has been taken from mbed TLS pkcs11_sign(), under the GPLv2.0+.
     */
    if (md_alg != MBEDTLS_MD_NONE)
    {
        const mbedtls_md_info_t *md_info = mbedtls_md_info_from_type( md_alg );
        if (md_info == NULL)
        {
            return( MBEDTLS_ERR_RSA_BAD_INPUT_DATA );
        }

        if (!mbed_ok(mbedtls_oid_get_oid_by_md( md_alg, &oid, &oid_size )))
        {
            return( MBEDTLS_ERR_RSA_BAD_INPUT_DATA );
        }

        hashlen = mbedtls_md_get_size( md_info );
        asn_len = 10 + oid_size;
    }

    sig_len = ctx->signature_length;
    if ( (SIZE_MAX - hashlen) < asn_len || (hashlen + asn_len) > sig_len)
    {
        return MBEDTLS_ERR_RSA_BAD_INPUT_DATA;
    }

    if (md_alg != MBEDTLS_MD_NONE)
    {
        /*
         * DigestInfo ::= SEQUENCE {
         *   digestAlgorithm DigestAlgorithmIdentifier,
         *   digest Digest }
         *
         * DigestAlgorithmIdentifier ::= AlgorithmIdentifier
         *
         * Digest ::= OCTET STRING
         */
        *p++ = MBEDTLS_ASN1_SEQUENCE | MBEDTLS_ASN1_CONSTRUCTED;
        *p++ = (unsigned char) ( 0x08 + oid_size + hashlen );
        *p++ = MBEDTLS_ASN1_SEQUENCE | MBEDTLS_ASN1_CONSTRUCTED;
        *p++ = (unsigned char) ( 0x04 + oid_size );
        *p++ = MBEDTLS_ASN1_OID;
        *p++ = oid_size & 0xFF;
        memcpy( p, oid, oid_size );
        p += oid_size;
        *p++ = MBEDTLS_ASN1_NULL;
        *p++ = 0x00;
        *p++ = MBEDTLS_ASN1_OCTET_STRING;
        *p++ = hashlen;

        /* Determine added ASN length */
        asn_len = p - sig;
    }

    /* Copy the hash to be signed */
    memcpy( p, hash, hashlen );

    /* convert 'from' to base64 */
    if (openvpn_base64_encode(sig, asn_len + hashlen, &in_b64) <= 0)
    {
        rv = MBEDTLS_ERR_RSA_BAD_INPUT_DATA;
        goto done;
    }

    /* call MI for signature */
    if (management)
    {
        out_b64 = management_query_rsa_sig(management, in_b64);
    }
    if (!out_b64)
    {
        rv = MBEDTLS_ERR_RSA_PRIVATE_FAILED;
        goto done;
    }

    /* decode base64 signature to binary and verify length */
    if (openvpn_base64_decode(out_b64, sig, ctx->signature_length) !=
        ctx->signature_length)
    {
        rv = MBEDTLS_ERR_RSA_PRIVATE_FAILED;
        goto done;
    }

    rv = 0;

done:
    if (in_b64)
    {
        free(in_b64);
    }
    if (out_b64)
    {
        free(out_b64);
    }
    return rv;
}

static inline size_t
external_key_len(void *vctx)
{
    struct external_context *const ctx = vctx;

    return ctx->signature_length;
}

int
tls_ctx_use_external_private_key(struct tls_root_ctx *ctx,
                                 const char *cert_file, const char *cert_file_inline)
{
    ASSERT(NULL != ctx);

    tls_ctx_load_cert_file(ctx, cert_file, cert_file_inline);

    if (ctx->crt_chain == NULL)
    {
        return 0;
    }

    ALLOC_OBJ_CLEAR(ctx->external_key, struct external_context);
    ctx->external_key->signature_length = mbedtls_pk_get_len(&ctx->crt_chain->pk);

    ALLOC_OBJ_CLEAR(ctx->priv_key, mbedtls_pk_context);
    if (!mbed_ok(mbedtls_pk_setup_rsa_alt(ctx->priv_key, ctx->external_key,
                                          NULL, external_pkcs1_sign, external_key_len)))
    {
        return 0;
    }

    return 1;
}
#endif /* ifdef MANAGMENT_EXTERNAL_KEY */

void
tls_ctx_load_ca(struct tls_root_ctx *ctx, const char *ca_file,
                const char *ca_inline, const char *ca_path, bool tls_server
                )
{
    if (ca_path)
    {
        msg(M_FATAL, "ERROR: mbed TLS cannot handle the capath directive");
    }

    if (ca_file && !strcmp(ca_file, INLINE_FILE_TAG) && ca_inline)
    {
        if (!mbed_ok(mbedtls_x509_crt_parse(ctx->ca_chain,
                                            (const unsigned char *) ca_inline, strlen(ca_inline)+1)))
        {
            msg(M_FATAL, "Cannot load inline CA certificates");
        }
    }
    else
    {
        /* Load CA file for verifying peer supplied certificate */
        if (!mbed_ok(mbedtls_x509_crt_parse_file(ctx->ca_chain, ca_file)))
        {
            msg(M_FATAL, "Cannot load CA certificate file %s", ca_file);
        }
    }
}

void
tls_ctx_load_extra_certs(struct tls_root_ctx *ctx, const char *extra_certs_file,
                         const char *extra_certs_inline
                         )
{
    ASSERT(NULL != ctx);

    if (!ctx->crt_chain)
    {
        ALLOC_OBJ_CLEAR(ctx->crt_chain, mbedtls_x509_crt);
    }

    if (!strcmp(extra_certs_file, INLINE_FILE_TAG) && extra_certs_inline)
    {
        if (!mbed_ok(mbedtls_x509_crt_parse(ctx->crt_chain,
                                            (const unsigned char *) extra_certs_inline,
                                            strlen(extra_certs_inline)+1)))
        {
            msg(M_FATAL, "Cannot load inline extra-certs file");
        }
    }
    else
    {
        if (!mbed_ok(mbedtls_x509_crt_parse_file(ctx->crt_chain, extra_certs_file)))
        {
            msg(M_FATAL, "Cannot load extra-certs file: %s", extra_certs_file);
        }
    }
}

/* **************************************
 *
 * Key-state specific functions
 *
 ***************************************/

/*
 * "Endless buffer"
 */

static inline void
buf_free_entry(buffer_entry *entry)
{
    if (NULL != entry)
    {
        free(entry->data);
        free(entry);
    }
}

static void
buf_free_entries(endless_buffer *buf)
{
    while (buf->first_block)
    {
        buffer_entry *cur_block = buf->first_block;
        buf->first_block = cur_block->next_block;
        buf_free_entry(cur_block);
    }
    buf->last_block = NULL;
}

static int
endless_buf_read( endless_buffer *in, unsigned char *out, size_t out_len )
{
    size_t read_len = 0;

    if (in->first_block == NULL)
    {
        return MBEDTLS_ERR_SSL_WANT_READ;
    }

    while (in->first_block != NULL && read_len < out_len)
    {
        int block_len = in->first_block->length - in->data_start;
        if (block_len <= out_len - read_len)
        {
            buffer_entry *cur_entry = in->first_block;
            memcpy(out + read_len, cur_entry->data + in->data_start,
                   block_len);

            read_len += block_len;

            in->first_block = cur_entry->next_block;
            in->data_start = 0;

            if (in->first_block == NULL)
            {
                in->last_block = NULL;
            }

            buf_free_entry(cur_entry);
        }
        else
        {
            memcpy(out + read_len, in->first_block->data + in->data_start,
                   out_len - read_len);
            in->data_start += out_len - read_len;
            read_len = out_len;
        }
    }

    return read_len;
}

static int
endless_buf_write( endless_buffer *out, const unsigned char *in, size_t len )
{
    buffer_entry *new_block = malloc(sizeof(buffer_entry));
    if (NULL == new_block)
    {
        return MBEDTLS_ERR_NET_SEND_FAILED;
    }

    new_block->data = malloc(len);
    if (NULL == new_block->data)
    {
        free(new_block);
        return MBEDTLS_ERR_NET_SEND_FAILED;
    }

    new_block->length = len;
    new_block->next_block = NULL;

    memcpy(new_block->data, in, len);

    if (NULL == out->first_block)
    {
        out->first_block = new_block;
    }

    if (NULL != out->last_block)
    {
        out->last_block->next_block = new_block;
    }

    out->last_block = new_block;

    return len;
}

static int
ssl_bio_read( void *ctx, unsigned char *out, size_t out_len)
{
    bio_ctx *my_ctx = (bio_ctx *) ctx;
    return endless_buf_read(&my_ctx->in, out, out_len);
}

static int
ssl_bio_write( void *ctx, const unsigned char *in, size_t in_len)
{
    bio_ctx *my_ctx = (bio_ctx *) ctx;
    return endless_buf_write(&my_ctx->out, in, in_len);
}

static void
my_debug( void *ctx, int level, const char *file, int line,
          const char *str )
{
    int my_loglevel = (level < 3) ? D_TLS_DEBUG_MED : D_TLS_DEBUG;
    msg(my_loglevel, "mbed TLS msg (%s:%d): %s", file, line, str);
}

/*
 * Further personalise the RNG using a hash of the public key
 */
void
tls_ctx_personalise_random(struct tls_root_ctx *ctx)
{
    static char old_sha256_hash[32] = {0};
    unsigned char sha256_hash[32] = {0};
    mbedtls_ctr_drbg_context *cd_ctx = rand_ctx_get();

    if (NULL != ctx->crt_chain)
    {
        mbedtls_x509_crt *cert = ctx->crt_chain;

        mbedtls_sha256(cert->tbs.p, cert->tbs.len, sha256_hash, false);
        if (0 != memcmp(old_sha256_hash, sha256_hash, sizeof(sha256_hash)))
        {
            mbedtls_ctr_drbg_update(cd_ctx, sha256_hash, 32);
            memcpy(old_sha256_hash, sha256_hash, sizeof(old_sha256_hash));
        }
    }
}

int
tls_version_max(void)
{
#if defined(MBEDTLS_SSL_MAJOR_VERSION_3) && defined(MBEDTLS_SSL_MINOR_VERSION_3)
    return TLS_VER_1_2;
#elif defined(MBEDTLS_SSL_MAJOR_VERSION_3) && defined(MBEDTLS_SSL_MINOR_VERSION_2)
    return TLS_VER_1_1;
#else
    return TLS_VER_1_0;
#endif
}

/**
 * Convert an OpenVPN tls-version variable to mbed TLS format (i.e. a major and
 * minor ssl version number).
 *
 * @param tls_ver       The tls-version variable to convert.
 * @param major         Returns the TLS major version in mbed TLS format.
 *                      Must be a valid pointer.
 * @param minor         Returns the TLS minor version in mbed TLS format.
 *                      Must be a valid pointer.
 */
static void
tls_version_to_major_minor(int tls_ver, int *major, int *minor)
{
    ASSERT(major);
    ASSERT(minor);

    switch (tls_ver)
    {
        case TLS_VER_1_0:
            *major = MBEDTLS_SSL_MAJOR_VERSION_3;
            *minor = MBEDTLS_SSL_MINOR_VERSION_1;
            break;

        case TLS_VER_1_1:
            *major = MBEDTLS_SSL_MAJOR_VERSION_3;
            *minor = MBEDTLS_SSL_MINOR_VERSION_2;
            break;

        case TLS_VER_1_2:
            *major = MBEDTLS_SSL_MAJOR_VERSION_3;
            *minor = MBEDTLS_SSL_MINOR_VERSION_3;
            break;

        default:
            msg(M_FATAL, "%s: invalid TLS version %d", __func__, tls_ver);
            break;
    }
}

void
backend_tls_ctx_reload_crl(struct tls_root_ctx *ctx, const char *crl_file,
                           const char *crl_inline)
{
    ASSERT(crl_file);

    if (ctx->crl == NULL)
    {
        ALLOC_OBJ_CLEAR(ctx->crl, mbedtls_x509_crl);
    }
    mbedtls_x509_crl_free(ctx->crl);

    if (!strcmp(crl_file, INLINE_FILE_TAG) && crl_inline)
    {
        if (!mbed_ok(mbedtls_x509_crl_parse(ctx->crl,
                                            (const unsigned char *)crl_inline, strlen(crl_inline)+1)))
        {
            msg(M_WARN, "CRL: cannot parse inline CRL");
            goto err;
        }
    }
    else
    {
        if (!mbed_ok(mbedtls_x509_crl_parse_file(ctx->crl, crl_file)))
        {
            msg(M_WARN, "CRL: cannot read CRL from file %s", crl_file);
            goto err;
        }
    }
    return;

err:
    mbedtls_x509_crl_free(ctx->crl);
}

void
key_state_ssl_init(struct key_state_ssl *ks_ssl,
                   const struct tls_root_ctx *ssl_ctx, bool is_server, struct tls_session *session)
{
    ASSERT(NULL != ssl_ctx);
    ASSERT(ks_ssl);
    CLEAR(*ks_ssl);

    /* Initialise SSL config */
    mbedtls_ssl_config_init(&ks_ssl->ssl_config);
    mbedtls_ssl_config_defaults(&ks_ssl->ssl_config, ssl_ctx->endpoint,
                                MBEDTLS_SSL_TRANSPORT_STREAM, MBEDTLS_SSL_PRESET_DEFAULT);
#ifdef MBEDTLS_DEBUG_C
    mbedtls_debug_set_threshold(3);
#endif
    mbedtls_ssl_conf_dbg(&ks_ssl->ssl_config, my_debug, NULL);
    mbedtls_ssl_conf_rng(&ks_ssl->ssl_config, mbedtls_ctr_drbg_random,
                         rand_ctx_get());

    if (ssl_ctx->allowed_ciphers)
    {
        mbedtls_ssl_conf_ciphersuites(&ks_ssl->ssl_config, ssl_ctx->allowed_ciphers);
    }

    /* Disable record splitting (for now).  OpenVPN assumes records are sent
     * unfragmented, and changing that will require thorough review and
     * testing.  Since OpenVPN is not susceptible to BEAST, we can just
     * disable record splitting as a quick fix. */
#if defined(MBEDTLS_SSL_CBC_RECORD_SPLITTING)
    mbedtls_ssl_conf_cbc_record_splitting(&ks_ssl->ssl_config,
                                          MBEDTLS_SSL_CBC_RECORD_SPLITTING_DISABLED);
#endif /* MBEDTLS_SSL_CBC_RECORD_SPLITTING */

    /* Initialise authentication information */
    if (is_server)
    {
        mbed_ok(mbedtls_ssl_conf_dh_param_ctx(&ks_ssl->ssl_config,
                                              ssl_ctx->dhm_ctx));
    }

    mbed_ok(mbedtls_ssl_conf_own_cert(&ks_ssl->ssl_config, ssl_ctx->crt_chain,
                                      ssl_ctx->priv_key));

    /* Initialise SSL verification */
#if P2MP_SERVER
    if (session->opt->ssl_flags & SSLF_CLIENT_CERT_OPTIONAL)
    {
        mbedtls_ssl_conf_authmode(&ks_ssl->ssl_config, MBEDTLS_SSL_VERIFY_OPTIONAL);
    }
    else if (!(session->opt->ssl_flags & SSLF_CLIENT_CERT_NOT_REQUIRED))
#endif
    {
        mbedtls_ssl_conf_authmode(&ks_ssl->ssl_config, MBEDTLS_SSL_VERIFY_REQUIRED);
    }
    mbedtls_ssl_conf_verify(&ks_ssl->ssl_config, verify_callback, session);

    /* TODO: mbed TLS does not currently support sending the CA chain to the client */
    mbedtls_ssl_conf_ca_chain(&ks_ssl->ssl_config, ssl_ctx->ca_chain, ssl_ctx->crl);

    /* Initialize minimum TLS version */
    {
        const int tls_version_min =
            (session->opt->ssl_flags >> SSLF_TLS_VERSION_MIN_SHIFT)
            &SSLF_TLS_VERSION_MIN_MASK;

        /* default to TLS 1.0 */
        int major = MBEDTLS_SSL_MAJOR_VERSION_3;
        int minor = MBEDTLS_SSL_MINOR_VERSION_1;

        if (tls_version_min > TLS_VER_UNSPEC)
        {
            tls_version_to_major_minor(tls_version_min, &major, &minor);
        }

        mbedtls_ssl_conf_min_version(&ks_ssl->ssl_config, major, minor);
    }

    /* Initialize maximum TLS version */
    {
        const int tls_version_max =
            (session->opt->ssl_flags >> SSLF_TLS_VERSION_MAX_SHIFT)
            &SSLF_TLS_VERSION_MAX_MASK;

        if (tls_version_max > TLS_VER_UNSPEC)
        {
            int major, minor;
            tls_version_to_major_minor(tls_version_max, &major, &minor);
            mbedtls_ssl_conf_max_version(&ks_ssl->ssl_config, major, minor);
        }
    }

    /* Initialise SSL context */
    ALLOC_OBJ_CLEAR(ks_ssl->ctx, mbedtls_ssl_context);
    mbedtls_ssl_init(ks_ssl->ctx);
    mbedtls_ssl_setup(ks_ssl->ctx, &ks_ssl->ssl_config);

    /* Initialise BIOs */
    CLEAR(ks_ssl->bio_ctx);
    mbedtls_ssl_set_bio(ks_ssl->ctx, &ks_ssl->bio_ctx, ssl_bio_write,
                        ssl_bio_read, NULL);
}

void
key_state_ssl_free(struct key_state_ssl *ks_ssl)
{
    if (ks_ssl)
    {
        if (ks_ssl->ctx)
        {
            mbedtls_ssl_free(ks_ssl->ctx);
            free(ks_ssl->ctx);
        }
        mbedtls_ssl_config_free(&ks_ssl->ssl_config);
        buf_free_entries(&ks_ssl->bio_ctx.in);
        buf_free_entries(&ks_ssl->bio_ctx.out);
        CLEAR(*ks_ssl);
    }
}

int
key_state_write_plaintext(struct key_state_ssl *ks, struct buffer *buf)
{
    int retval = 0;

    ASSERT(buf);

    retval = key_state_write_plaintext_const(ks, BPTR(buf), BLEN(buf));

    if (1 == retval)
    {
        memset(BPTR(buf), 0, BLEN(buf));  /* erase data just written */
        buf->len = 0;
    }

    return retval;
}

int
key_state_write_plaintext_const(struct key_state_ssl *ks, const uint8_t *data, int len)
{
    int retval = 0;
    perf_push(PERF_BIO_WRITE_PLAINTEXT);

    ASSERT(NULL != ks);
    ASSERT(len >= 0);

    if (0 == len)
    {
        perf_pop();
        return 0;
    }

    ASSERT(data);

    retval = mbedtls_ssl_write(ks->ctx, data, len);

    if (retval < 0)
    {
        perf_pop();
        if (MBEDTLS_ERR_SSL_WANT_WRITE == retval || MBEDTLS_ERR_SSL_WANT_READ == retval)
        {
            return 0;
        }
        mbed_log_err(D_TLS_ERRORS, retval,
                     "TLS ERROR: write tls_write_plaintext_const error");
        return -1;
    }

    if (retval != len)
    {
        msg(D_TLS_ERRORS,
            "TLS ERROR: write tls_write_plaintext_const incomplete %d/%d",
            retval, len);
        perf_pop();
        return -1;
    }

    /* successful write */
    dmsg(D_HANDSHAKE_VERBOSE, "write tls_write_plaintext_const %d bytes", retval);

    perf_pop();
    return 1;
}

int
key_state_read_ciphertext(struct key_state_ssl *ks, struct buffer *buf,
                          int maxlen)
{
    int retval = 0;
    int len = 0;

    perf_push(PERF_BIO_READ_CIPHERTEXT);

    ASSERT(NULL != ks);
    ASSERT(buf);
    ASSERT(buf->len >= 0);

    if (buf->len)
    {
        perf_pop();
        return 0;
    }

    len = buf_forward_capacity(buf);
    if (maxlen < len)
    {
        len = maxlen;
    }

    retval = endless_buf_read(&ks->bio_ctx.out, BPTR(buf), len);

    /* Error during read, check for retry error */
    if (retval < 0)
    {
        perf_pop();
        if (MBEDTLS_ERR_SSL_WANT_WRITE == retval || MBEDTLS_ERR_SSL_WANT_READ == retval)
        {
            return 0;
        }
        mbed_log_err(D_TLS_ERRORS, retval, "TLS_ERROR: read tls_read_ciphertext error");
        buf->len = 0;
        return -1;
    }
    /* Nothing read, try again */
    if (0 == retval)
    {
        buf->len = 0;
        perf_pop();
        return 0;
    }

    /* successful read */
    dmsg(D_HANDSHAKE_VERBOSE, "read tls_read_ciphertext %d bytes", retval);
    buf->len = retval;
    perf_pop();
    return 1;
}

int
key_state_write_ciphertext(struct key_state_ssl *ks, struct buffer *buf)
{
    int retval = 0;
    perf_push(PERF_BIO_WRITE_CIPHERTEXT);

    ASSERT(NULL != ks);
    ASSERT(buf);
    ASSERT(buf->len >= 0);

    if (0 == buf->len)
    {
        perf_pop();
        return 0;
    }

    retval = endless_buf_write(&ks->bio_ctx.in, BPTR(buf), buf->len);

    if (retval < 0)
    {
        perf_pop();

        if (MBEDTLS_ERR_SSL_WANT_WRITE == retval || MBEDTLS_ERR_SSL_WANT_READ == retval)
        {
            return 0;
        }
        mbed_log_err(D_TLS_ERRORS, retval,
                     "TLS ERROR: write tls_write_ciphertext error");
        return -1;
    }

    if (retval != buf->len)
    {
        msg(D_TLS_ERRORS, "TLS ERROR: write tls_write_ciphertext incomplete %d/%d",
            retval, buf->len);
        perf_pop();
        return -1;
    }

    /* successful write */
    dmsg(D_HANDSHAKE_VERBOSE, "write tls_write_ciphertext %d bytes", retval);

    memset(BPTR(buf), 0, BLEN(buf));  /* erase data just written */
    buf->len = 0;

    perf_pop();
    return 1;
}

int
key_state_read_plaintext(struct key_state_ssl *ks, struct buffer *buf,
                         int maxlen)
{
    int retval = 0;
    int len = 0;

    perf_push(PERF_BIO_READ_PLAINTEXT);

    ASSERT(NULL != ks);
    ASSERT(buf);
    ASSERT(buf->len >= 0);

    if (buf->len)
    {
        perf_pop();
        return 0;
    }

    len = buf_forward_capacity(buf);
    if (maxlen < len)
    {
        len = maxlen;
    }

    retval = mbedtls_ssl_read(ks->ctx, BPTR(buf), len);

    /* Error during read, check for retry error */
    if (retval < 0)
    {
        if (MBEDTLS_ERR_SSL_WANT_WRITE == retval || MBEDTLS_ERR_SSL_WANT_READ == retval)
        {
            return 0;
        }
        mbed_log_err(D_TLS_ERRORS, retval, "TLS_ERROR: read tls_read_plaintext error");
        buf->len = 0;
        perf_pop();
        return -1;
    }
    /* Nothing read, try again */
    if (0 == retval)
    {
        buf->len = 0;
        perf_pop();
        return 0;
    }

    /* successful read */
    dmsg(D_HANDSHAKE_VERBOSE, "read tls_read_plaintext %d bytes", retval);
    buf->len = retval;

    perf_pop();
    return 1;
}

/* **************************************
 *
 * Information functions
 *
 * Print information for the end user.
 *
 ***************************************/
void
print_details(struct key_state_ssl *ks_ssl, const char *prefix)
{
    const mbedtls_x509_crt *cert;
    char s1[256];
    char s2[256];

    s1[0] = s2[0] = 0;
    openvpn_snprintf(s1, sizeof(s1), "%s %s, cipher %s",
                     prefix,
                     mbedtls_ssl_get_version(ks_ssl->ctx),
                     mbedtls_ssl_get_ciphersuite(ks_ssl->ctx));

    cert = mbedtls_ssl_get_peer_cert(ks_ssl->ctx);
    if (cert != NULL)
    {
        openvpn_snprintf(s2, sizeof(s2), ", %u bit key",
                         (unsigned int) mbedtls_pk_get_bitlen(&cert->pk));
    }

    msg(D_HANDSHAKE, "%s%s", s1, s2);
}

void
show_available_tls_ciphers(const char *cipher_list)
{
    struct tls_root_ctx tls_ctx;
    const int *ciphers = mbedtls_ssl_list_ciphersuites();

    tls_ctx_server_new(&tls_ctx);
    tls_ctx_restrict_ciphers(&tls_ctx, cipher_list);

    if (tls_ctx.allowed_ciphers)
    {
        ciphers = tls_ctx.allowed_ciphers;
    }

#ifndef ENABLE_SMALL
    printf("Available TLS Ciphers,\n");
    printf("listed in order of preference:\n\n");
#endif

    while (*ciphers != 0)
    {
        printf("%s\n", mbedtls_ssl_get_ciphersuite_name(*ciphers));
        ciphers++;
    }
    printf("\n" SHOW_TLS_CIPHER_LIST_WARNING);

    tls_ctx_free(&tls_ctx);
}

void
show_available_curves(void)
{
    const mbedtls_ecp_curve_info *pcurve = mbedtls_ecp_curve_list();

    if (NULL == pcurve)
    {
        msg(M_FATAL, "Cannot retrieve curve list from mbed TLS");
    }

    /* Print curve list */
    printf("Available Elliptic curves, listed in order of preference:\n\n");
    while (MBEDTLS_ECP_DP_NONE != pcurve->grp_id)
    {
        printf("%s\n", pcurve->name);
        pcurve++;
    }
}

void
get_highest_preference_tls_cipher(char *buf, int size)
{
    const char *cipher_name;
    const int *ciphers = mbedtls_ssl_list_ciphersuites();
    if (*ciphers == 0)
    {
        msg(M_FATAL, "Cannot retrieve list of supported SSL ciphers.");
    }

    cipher_name = mbedtls_ssl_get_ciphersuite_name(*ciphers);
    strncpynt(buf, cipher_name, size);
}

const char *
get_ssl_library_version(void)
{
    static char mbedtls_version[30];
    unsigned int pv = mbedtls_version_get_number();
    sprintf( mbedtls_version, "mbed TLS %d.%d.%d",
             (pv>>24)&0xff, (pv>>16)&0xff, (pv>>8)&0xff );
    return mbedtls_version;
}

#endif /* defined(ENABLE_CRYPTO) && defined(ENABLE_CRYPTO_MBEDTLS) */
