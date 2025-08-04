/*
 *  OpenVPN -- An application to securely tunnel IP networks
 *             over a single TCP/UDP port, with support for SSL/TLS-based
 *             session authentication and key exchange,
 *             packet encryption, packet authentication, and
 *             packet compression.
 *
 *  Copyright (C) 2002-2025 OpenVPN Inc <sales@openvpn.net>
 *  Copyright (C) 2010-2021 Fox Crypto B.V. <openvpn@foxcrypto.com>
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
 *  with this program; if not, see <https://www.gnu.org/licenses/>.
 */

/**
 * @file
 * Control Channel mbed TLS Backend
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "syshead.h"

#if defined(ENABLE_CRYPTO_MBEDTLS)

#include "errlevel.h"
#include "ssl_backend.h"
#include "base64.h"
#include "buffer.h"
#include "misc.h"
#include "manage.h"
#include "mbedtls_compat.h"
#include "pkcs11_backend.h"
#include "ssl_common.h"
#include "ssl_util.h"

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

static const mbedtls_x509_crt_profile openvpn_x509_crt_profile_legacy =
{
    /* Hashes from SHA-1 and above */
    MBEDTLS_X509_ID_FLAG( MBEDTLS_MD_SHA1 )
    |MBEDTLS_X509_ID_FLAG( MBEDTLS_MD_RIPEMD160 )
    |MBEDTLS_X509_ID_FLAG( MBEDTLS_MD_SHA224 )
    |MBEDTLS_X509_ID_FLAG( MBEDTLS_MD_SHA256 )
    |MBEDTLS_X509_ID_FLAG( MBEDTLS_MD_SHA384 )
    |MBEDTLS_X509_ID_FLAG( MBEDTLS_MD_SHA512 ),
    0xFFFFFFF, /* Any PK alg    */
    0xFFFFFFF, /* Any curve     */
    1024,      /* RSA-1024 and larger */
};

static const mbedtls_x509_crt_profile openvpn_x509_crt_profile_preferred =
{
    /* SHA-2 and above */
    MBEDTLS_X509_ID_FLAG( MBEDTLS_MD_SHA224 )
    |MBEDTLS_X509_ID_FLAG( MBEDTLS_MD_SHA256 )
    |MBEDTLS_X509_ID_FLAG( MBEDTLS_MD_SHA384 )
    |MBEDTLS_X509_ID_FLAG( MBEDTLS_MD_SHA512 ),
    0xFFFFFFF, /* Any PK alg    */
    0xFFFFFFF, /* Any curve     */
    2048,      /* RSA-2048 and larger */
};

#define openvpn_x509_crt_profile_suiteb mbedtls_x509_crt_profile_suiteb;

void
tls_init_lib(void)
{
    mbedtls_compat_psa_crypto_init();
}

void
tls_free_lib(void)
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
        free(ctx->priv_key);

        mbedtls_x509_crt_free(ctx->ca_chain);
        free(ctx->ca_chain);

        mbedtls_x509_crt_free(ctx->crt_chain);
        free(ctx->crt_chain);

        mbedtls_dhm_free(ctx->dhm_ctx);
        free(ctx->dhm_ctx);

        mbedtls_x509_crl_free(ctx->crl);
        free(ctx->crl);

#if defined(ENABLE_PKCS11)
        /* ...freeCertificate() can handle NULL ptrs, but if pkcs11 helper
         * has not been initialized, it will ASSERT() - so, do not pass NULL
         */
        if (ctx->pkcs11_cert)
        {
            pkcs11h_certificate_freeCertificate(ctx->pkcs11_cert);
        }
#endif

        free(ctx->allowed_ciphers);

        free(ctx->groups);

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
#ifdef MBEDTLS_SSL_KEYING_MATERIAL_EXPORT
/* mbedtls_ssl_export_keying_material does not need helper/callback methods */
#elif defined(HAVE_MBEDTLS_SSL_CONF_EXPORT_KEYS_EXT_CB)
/*
 * Key export callback for older versions of mbed TLS, to be used with
 * mbedtls_ssl_conf_export_keys_ext_cb(). It is called with the master
 * secret, client random and server random, and the type of PRF function
 * to use.
 *
 * Mbed TLS stores this callback in the mbedtls_ssl_config struct and it
 * is used in the mbedtls_ssl_contexts set up from that config. */
int
mbedtls_ssl_export_keys_cb(void *p_expkey, const unsigned char *ms,
                           const unsigned char *kb, size_t maclen,
                           size_t keylen, size_t ivlen,
                           const unsigned char client_random[32],
                           const unsigned char server_random[32],
                           mbedtls_tls_prf_types tls_prf_type)
{
    struct tls_session *session = p_expkey;
    struct key_state_ssl *ks_ssl = &session->key[KS_PRIMARY].ks_ssl;
    struct tls_key_cache *cache = &ks_ssl->tls_key_cache;

    static_assert(sizeof(ks_ssl->ctx->session->master)
                  == sizeof(cache->master_secret), "master size mismatch");

    memcpy(cache->client_server_random, client_random, 32);
    memcpy(cache->client_server_random + 32, server_random, 32);
    memcpy(cache->master_secret, ms, sizeof(cache->master_secret));
    cache->tls_prf_type = tls_prf_type;

    return 0;
}
#elif defined(HAVE_MBEDTLS_SSL_SET_EXPORT_KEYS_CB)
/*
 * Key export callback for newer versions of mbed TLS, to be used with
 * mbedtls_ssl_set_export_keys_cb(). When used with TLS 1.2, the callback
 * is called with the TLS 1.2 master secret, client random, server random
 * and the type of PRF to use. With TLS 1.3, it is called with several
 * different keys (indicated by type), but unfortunately not the exporter
 * master secret.
 *
 * Unlike in older versions, the callback is not stored in the
 * mbedtls_ssl_config. It is placed in the mbedtls_ssl_context after it
 * has been set up. */
void
mbedtls_ssl_export_keys_cb(void *p_expkey,
                           mbedtls_ssl_key_export_type type,
                           const unsigned char *secret,
                           size_t secret_len,
                           const unsigned char client_random[32],
                           const unsigned char server_random[32],
                           mbedtls_tls_prf_types tls_prf_type)
{
    /* Since we can't get the TLS 1.3 exporter master secret, we ignore all key
     * types except MBEDTLS_SSL_KEY_EXPORT_TLS12_MASTER_SECRET. */
    if (type != MBEDTLS_SSL_KEY_EXPORT_TLS12_MASTER_SECRET)
    {
        return;
    }

    struct tls_session *session = p_expkey;
    struct key_state_ssl *ks_ssl = &session->key[KS_PRIMARY].ks_ssl;
    struct tls_key_cache *cache = &ks_ssl->tls_key_cache;

    /* The TLS 1.2 master secret has a fixed size, so if secret_len has
     * a different value, something is wrong with mbed TLS. */
    if (secret_len != sizeof(cache->master_secret))
    {
        msg(M_FATAL,
            "ERROR: Incorrect TLS 1.2 master secret length: Got %zu, expected %zu",
            secret_len, sizeof(cache->master_secret));
    }

    memcpy(cache->client_server_random, client_random, 32);
    memcpy(cache->client_server_random + 32, server_random, 32);
    memcpy(cache->master_secret, secret, sizeof(cache->master_secret));
    cache->tls_prf_type = tls_prf_type;
}
#else  /* ifdef MBEDTLS_SSL_KEYING_MATERIAL_EXPORT */
#error mbedtls_ssl_conf_export_keys_ext_cb, mbedtls_ssl_set_export_keys_cb or mbedtls_ssl_export_keying_material must be available in mbed TLS
#endif /* HAVE_MBEDTLS_SSL_CONF_EXPORT_KEYS_EXT_CB */


bool
key_state_export_keying_material(struct tls_session *session,
                                 const char *label, size_t label_size,
                                 void *ekm, size_t ekm_size)
{
    ASSERT(strlen(label) == label_size);

#if defined(MBEDTLS_SSL_KEYING_MATERIAL_EXPORT)
    /* Our version of mbed TLS has a built-in TLS-Exporter. */

    mbedtls_ssl_context *ctx = session->key[KS_PRIMARY].ks_ssl.ctx;
    if (mbed_ok(mbedtls_ssl_export_keying_material(ctx, ekm, ekm_size, label, label_size, NULL, 0, 0)))
    {
        return true;
    }
    else
    {
        return false;
    }

#else  /* defined(MBEDTLS_SSL_KEYING_MATERIAL_EXPORT) */
    struct tls_key_cache *cache = &session->key[KS_PRIMARY].ks_ssl.tls_key_cache;

    /* If the type is NONE, we either have no cached secrets or
     * there is no PRF, in both cases we cannot generate key material */
    if (cache->tls_prf_type == MBEDTLS_SSL_TLS_PRF_NONE)
    {
        return false;
    }

    int ret = mbedtls_ssl_tls_prf(cache->tls_prf_type, cache->master_secret,
                                  sizeof(cache->master_secret),
                                  label, cache->client_server_random,
                                  sizeof(cache->client_server_random),
                                  ekm, ekm_size);

    if (mbed_ok(ret))
    {
        return true;
    }
    else
    {
        secure_memzero(ekm, session->opt->ekm_size);
        return false;
    }
#endif  /* defined(MBEDTLS_SSL_KEYING_MATERIAL_EXPORT) */
}

bool
tls_ctx_set_options(struct tls_root_ctx *ctx, unsigned int ssl_flags)
{
    return true;
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
tls_ctx_restrict_ciphers_tls13(struct tls_root_ctx *ctx, const char *ciphers)
{
    if (ciphers == NULL)
    {
        /* Nothing to do, return without warning message */
        return;
    }

    msg(M_WARN, "mbed TLS does not support setting tls-ciphersuites. "
        "Ignoring TLS 1.3 cipher list: %s", ciphers);
}

void
tls_ctx_restrict_ciphers(struct tls_root_ctx *ctx, const char *ciphers)
{
    char *tmp_ciphers, *tmp_ciphers_orig, *token;

    if (NULL == ciphers)
    {
        return; /* Nothing to do */
    }

    ASSERT(NULL != ctx);

    /* Get number of ciphers */
    int cipher_count = get_num_elements(ciphers, ':');

    /* Allocate an array for them */
    ALLOC_ARRAY_CLEAR(ctx->allowed_ciphers, int, cipher_count+1)

    /* Parse allowed ciphers, getting IDs */
    int i = 0;
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
tls_ctx_set_cert_profile(struct tls_root_ctx *ctx, const char *profile)
{
    if (!profile || 0 == strcmp(profile, "legacy")
        || 0 == strcmp(profile, "insecure"))
    {
        ctx->cert_profile = openvpn_x509_crt_profile_legacy;
    }
    else if (0 == strcmp(profile, "preferred"))
    {
        ctx->cert_profile = openvpn_x509_crt_profile_preferred;
    }
    else if (0 == strcmp(profile, "suiteb"))
    {
        ctx->cert_profile = openvpn_x509_crt_profile_suiteb;
    }
    else
    {
        msg(M_FATAL, "ERROR: Invalid cert profile: %s", profile);
    }
}

void
tls_ctx_set_tls_groups(struct tls_root_ctx *ctx, const char *groups)
{
    ASSERT(ctx);
    struct gc_arena gc = gc_new();

    /* Get number of groups and allocate an array in ctx */
    int groups_count = get_num_elements(groups, ':');
    ALLOC_ARRAY_CLEAR(ctx->groups, mbedtls_compat_group_id, groups_count + 1)

    /* Parse allowed ciphers, getting IDs */
    int i = 0;
    char *tmp_groups = string_alloc(groups, &gc);

    const char *token;
    while ((token = strsep(&tmp_groups, ":")))
    {
        const mbedtls_ecp_curve_info *ci =
            mbedtls_ecp_curve_info_from_name(token);
        if (!ci)
        {
            msg(M_WARN, "Warning unknown curve/group specified: %s", token);
        }
        else
        {
            ctx->groups[i] = mbedtls_compat_get_group_id(ci);
            i++;
        }
    }

    /* Recent mbedtls versions state that the list of groups must be terminated
     * with 0. Older versions state that it must be terminated with MBEDTLS_ECP_DP_NONE
     * which is also 0, so this works either way. */
    ctx->groups[i] = 0;

    gc_free(&gc);
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
                       bool dh_inline)
{
    if (dh_inline)
    {
        if (!mbed_ok(mbedtls_dhm_parse_dhm(ctx->dhm_ctx,
                                           (const unsigned char *) dh_file,
                                           strlen(dh_file) + 1)))
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
        (counter_type) mbedtls_dhm_get_bitlen(ctx->dhm_ctx));
}

void
tls_ctx_load_ecdh_params(struct tls_root_ctx *ctx, const char *curve_name
                         )
{
    if (NULL != curve_name)
    {
        msg(M_WARN, "WARNING: mbed TLS builds do not support specifying an "
            "ECDH curve with --ecdh-curve, using default curves. Use "
            "--tls-groups to specify curves.");
    }
}

int
tls_ctx_load_pkcs12(struct tls_root_ctx *ctx, const char *pkcs12_file,
                    bool pkcs12_file_inline, bool load_ca_file)
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
                       bool cert_inline)
{
    ASSERT(NULL != ctx);

    if (!ctx->crt_chain)
    {
        ALLOC_OBJ_CLEAR(ctx->crt_chain, mbedtls_x509_crt);
    }

    if (cert_inline)
    {
        if (!mbed_ok(mbedtls_x509_crt_parse(ctx->crt_chain,
                                            (const unsigned char *)cert_file,
                                            strlen(cert_file) + 1)))
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
                       bool priv_key_inline)
{
    int status;
    ASSERT(NULL != ctx);

    if (!ctx->priv_key)
    {
        ALLOC_OBJ_CLEAR(ctx->priv_key, mbedtls_pk_context);
    }

    if (priv_key_inline)
    {
        status = mbedtls_compat_pk_parse_key(ctx->priv_key,
                                             (const unsigned char *) priv_key_file,
                                             strlen(priv_key_file) + 1, NULL, 0,
                                             mbedtls_ctr_drbg_random,
                                             rand_ctx_get());

        if (MBEDTLS_ERR_PK_PASSWORD_REQUIRED == status)
        {
            char passbuf[512] = {0};
            pem_password_callback(passbuf, 512, 0, NULL);
            status = mbedtls_compat_pk_parse_key(ctx->priv_key,
                                                 (const unsigned char *) priv_key_file,
                                                 strlen(priv_key_file) + 1,
                                                 (unsigned char *) passbuf,
                                                 strlen(passbuf),
                                                 mbedtls_ctr_drbg_random,
                                                 rand_ctx_get());
        }
    }
    else
    {
        status = mbedtls_compat_pk_parse_keyfile(ctx->priv_key,
                                                 priv_key_file,
                                                 NULL,
                                                 mbedtls_ctr_drbg_random,
                                                 rand_ctx_get());
        if (MBEDTLS_ERR_PK_PASSWORD_REQUIRED == status)
        {
            char passbuf[512] = {0};
            pem_password_callback(passbuf, 512, 0, NULL);
            status = mbedtls_compat_pk_parse_keyfile(ctx->priv_key,
                                                     priv_key_file, passbuf,
                                                     mbedtls_ctr_drbg_random,
                                                     rand_ctx_get());
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
        msg(M_WARN, "Cannot load private key file %s",
            print_key_filename(priv_key_file, priv_key_inline));
        return 1;
    }

    if (!mbed_ok(mbedtls_compat_pk_check_pair(&ctx->crt_chain->pk,
                                              ctx->priv_key,
                                              mbedtls_ctr_drbg_random,
                                              rand_ctx_get())))
    {
        msg(M_WARN, "Private key does not match the certificate");
        return 1;
    }

    return 0;
}

/**
 * external_pkcs1_sign implements a mbed TLS rsa_sign_func callback, that uses
 * the management interface to request an RSA signature for the supplied hash.
 *
 * @param ctx_voidptr   Management external key context.
 * @param f_rng         (Unused)
 * @param p_rng         (Unused)
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
                     int (*f_rng)(void *, unsigned char *, size_t), void *p_rng,
#if MBEDTLS_VERSION_NUMBER < 0x03020100
                     int mode,
#endif
                     mbedtls_md_type_t md_alg, unsigned int hashlen, const unsigned char *hash,
                     unsigned char *sig )
{
    struct external_context *const ctx = ctx_voidptr;
    int rv;
    uint8_t *to_sign = NULL;
    size_t asn_len = 0, oid_size = 0;
    const char *oid = NULL;

    if (NULL == ctx)
    {
        return MBEDTLS_ERR_RSA_BAD_INPUT_DATA;
    }

#if MBEDTLS_VERSION_NUMBER < 0x03020100
    if (MBEDTLS_RSA_PRIVATE != mode)
    {
        return MBEDTLS_ERR_RSA_BAD_INPUT_DATA;
    }
#endif

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

    if ((SIZE_MAX - hashlen) < asn_len
        || ctx->signature_length < (asn_len + hashlen))
    {
        return MBEDTLS_ERR_RSA_BAD_INPUT_DATA;
    }

    ALLOC_ARRAY_CLEAR(to_sign, uint8_t, asn_len + hashlen);
    uint8_t *p = to_sign;
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

        /* Double-check ASN length */
        ASSERT(asn_len == p - to_sign);
    }

    /* Copy the hash to be signed */
    memcpy(p, hash, hashlen);

    /* Call external signature function */
    if (!ctx->sign(ctx->sign_ctx, to_sign, asn_len + hashlen, sig,
                   ctx->signature_length))
    {
        rv = MBEDTLS_ERR_RSA_PRIVATE_FAILED;
        goto done;
    }

    rv = 0;

done:
    free(to_sign);
    return rv;
}

static inline size_t
external_key_len(void *vctx)
{
    struct external_context *const ctx = vctx;

    return ctx->signature_length;
}

int
tls_ctx_use_external_signing_func(struct tls_root_ctx *ctx,
                                  external_sign_func sign_func, void *sign_ctx)
{
    ASSERT(NULL != ctx);

    if (ctx->crt_chain == NULL)
    {
        msg(M_WARN, "ERROR: external key requires a certificate.");
        return 1;
    }

    if (mbedtls_pk_get_type(&ctx->crt_chain->pk) != MBEDTLS_PK_RSA)
    {
        msg(M_WARN, "ERROR: external key with mbed TLS requires a "
            "certificate with an RSA key.");
        return 1;
    }

    ctx->external_key.signature_length = mbedtls_pk_get_len(&ctx->crt_chain->pk);
    ctx->external_key.sign = sign_func;
    ctx->external_key.sign_ctx = sign_ctx;

    ALLOC_OBJ_CLEAR(ctx->priv_key, mbedtls_pk_context);
    if (!mbed_ok(mbedtls_pk_setup_rsa_alt(ctx->priv_key, &ctx->external_key,
                                          NULL, external_pkcs1_sign, external_key_len)))
    {
        return 1;
    }

    return 0;
}

#ifdef ENABLE_MANAGEMENT
/** Query the management interface for a signature, see external_sign_func. */
static bool
management_sign_func(void *sign_ctx, const void *src, size_t src_len,
                     void *dst, size_t dst_len)
{
    bool ret = false;
    char *src_b64 = NULL;
    char *dst_b64 = NULL;

    if (!management || (openvpn_base64_encode(src, src_len, &src_b64) <= 0))
    {
        goto cleanup;
    }

    /*
     * We only support RSA external keys and PKCS1 signatures at the moment
     * in mbed TLS, so the signature parameter is hardcoded to this encoding
     */
    if (!(dst_b64 = management_query_pk_sig(management, src_b64,
                                            "RSA_PKCS1_PADDING")))
    {
        goto cleanup;
    }

    if (openvpn_base64_decode(dst_b64, dst, dst_len) != dst_len)
    {
        goto cleanup;
    }

    ret = true;
cleanup:
    free(src_b64);
    free(dst_b64);

    return ret;
}

int
tls_ctx_use_management_external_key(struct tls_root_ctx *ctx)
{
    return tls_ctx_use_external_signing_func(ctx, management_sign_func, NULL);
}

#endif /* ifdef ENABLE_MANAGEMENT */

void
tls_ctx_load_ca(struct tls_root_ctx *ctx, const char *ca_file,
                bool ca_inline, const char *ca_path, bool tls_server)
{
    if (ca_path)
    {
        msg(M_FATAL, "ERROR: mbed TLS cannot handle the capath directive");
    }

    if (ca_file && ca_inline)
    {
        if (!mbed_ok(mbedtls_x509_crt_parse(ctx->ca_chain,
                                            (const unsigned char *) ca_file,
                                            strlen(ca_file) + 1)))
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
                         bool extra_certs_inline)
{
    ASSERT(NULL != ctx);

    if (!ctx->crt_chain)
    {
        ALLOC_OBJ_CLEAR(ctx->crt_chain, mbedtls_x509_crt);
    }

    if (extra_certs_inline)
    {
        if (!mbed_ok(mbedtls_x509_crt_parse(ctx->crt_chain,
                                            (const unsigned char *) extra_certs_file,
                                            strlen(extra_certs_file) + 1)))
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

        if (!md_full("SHA256", cert->tbs.p, cert->tbs.len, sha256_hash))
        {
            msg(M_WARN, "WARNING: failed to personalise random");
        }

        if (0 != memcmp(old_sha256_hash, sha256_hash, sizeof(sha256_hash)))
        {
            if (!mbed_ok(mbedtls_compat_ctr_drbg_update(cd_ctx, sha256_hash, 32)))
            {
                msg(M_WARN, "WARNING: failed to personalise random, could not update CTR_DRBG");
            }
            memcpy(old_sha256_hash, sha256_hash, sizeof(old_sha256_hash));
        }
    }
}

int
tls_version_max(void)
{
    /* We need mbedtls_ssl_export_keying_material() to support TLS 1.3. */
#if defined(MBEDTLS_SSL_PROTO_TLS1_3) && defined(MBEDTLS_SSL_KEYING_MATERIAL_EXPORT)
    return TLS_VER_1_3;
#elif defined(MBEDTLS_SSL_PROTO_TLS1_2)
    return TLS_VER_1_2;
#else
    #error mbedtls is compiled without support for TLS 1.2 or 1.3
#endif
}

/**
 * Convert an OpenVPN tls-version variable to mbed TLS format
 *
 * @param tls_ver       The tls-version variable to convert.
 *
 * @return Translated mbedTLS SSL version from OpenVPN TLS version.
 */
mbedtls_ssl_protocol_version
tls_version_to_ssl_version(int tls_ver)
{
    switch (tls_ver)
    {
#if defined(MBEDTLS_SSL_PROTO_TLS1_2)
        case TLS_VER_1_2:
            return MBEDTLS_SSL_VERSION_TLS1_2;
#endif

#if defined(MBEDTLS_SSL_PROTO_TLS1_3)
        case TLS_VER_1_3:
            return MBEDTLS_SSL_VERSION_TLS1_3;
#endif

        default:
            msg(M_FATAL, "%s: invalid or unsupported TLS version %d", __func__, tls_ver);
            return MBEDTLS_SSL_VERSION_UNKNOWN;
    }
}

void
backend_tls_ctx_reload_crl(struct tls_root_ctx *ctx, const char *crl_file,
                           bool crl_inline)
{
    ASSERT(crl_file);

    if (ctx->crl == NULL)
    {
        ALLOC_OBJ_CLEAR(ctx->crl, mbedtls_x509_crl);
    }
    mbedtls_x509_crl_free(ctx->crl);

    if (crl_inline)
    {
        if (!mbed_ok(mbedtls_x509_crl_parse(ctx->crl,
                                            (const unsigned char *)crl_file,
                                            strlen(crl_file) + 1)))
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
                   const struct tls_root_ctx *ssl_ctx, bool is_server,
                   struct tls_session *session)
{
    ASSERT(NULL != ssl_ctx);
    ASSERT(ks_ssl);
    CLEAR(*ks_ssl);

    /* Initialise SSL config */
    ALLOC_OBJ_CLEAR(ks_ssl->ssl_config, mbedtls_ssl_config);
    mbedtls_ssl_config_init(ks_ssl->ssl_config);
    mbedtls_ssl_config_defaults(ks_ssl->ssl_config, ssl_ctx->endpoint,
                                MBEDTLS_SSL_TRANSPORT_STREAM, MBEDTLS_SSL_PRESET_DEFAULT);
#ifdef MBEDTLS_DEBUG_C
    /* We only want to have mbed TLS generate debug level logging when we would
     * also display it.
     * In fact mbed TLS 2.25.0 crashes generating debug log if Curve25591 is
     * selected for DH (https://github.com/ARMmbed/mbedtls/issues/4208) */
    if (session->opt->ssl_flags & SSLF_TLS_DEBUG_ENABLED)
    {
        mbedtls_debug_set_threshold(3);
    }
    else
    {
        mbedtls_debug_set_threshold(2);
    }
#endif
    mbedtls_ssl_conf_dbg(ks_ssl->ssl_config, my_debug, NULL);
    mbedtls_ssl_conf_rng(ks_ssl->ssl_config, mbedtls_ctr_drbg_random,
                         rand_ctx_get());

    mbedtls_ssl_conf_cert_profile(ks_ssl->ssl_config, &ssl_ctx->cert_profile);

    if (ssl_ctx->allowed_ciphers)
    {
        mbedtls_ssl_conf_ciphersuites(ks_ssl->ssl_config, ssl_ctx->allowed_ciphers);
    }

    if (ssl_ctx->groups)
    {
        mbedtls_ssl_conf_groups(ks_ssl->ssl_config, ssl_ctx->groups);
    }

    /* Disable TLS renegotiations if the mbedtls library supports that feature.
    * OpenVPN's renegotiation creates new SSL sessions and does not depend on
    * this feature and TLS renegotiations have been problematic in the past. */
#if defined(MBEDTLS_SSL_RENEGOTIATION)
    mbedtls_ssl_conf_renegotiation(ks_ssl->ssl_config, MBEDTLS_SSL_RENEGOTIATION_DISABLED);
#endif /* MBEDTLS_SSL_RENEGOTIATION */

    /* Disable record splitting (for now).  OpenVPN assumes records are sent
     * unfragmented, and changing that will require thorough review and
     * testing.  Since OpenVPN is not susceptible to BEAST, we can just
     * disable record splitting as a quick fix. */
#if defined(MBEDTLS_SSL_CBC_RECORD_SPLITTING)
    mbedtls_ssl_conf_cbc_record_splitting(ks_ssl->ssl_config,
                                          MBEDTLS_SSL_CBC_RECORD_SPLITTING_DISABLED);
#endif /* MBEDTLS_SSL_CBC_RECORD_SPLITTING */

    /* Initialise authentication information */
    if (is_server)
    {
        mbed_ok(mbedtls_ssl_conf_dh_param_ctx(ks_ssl->ssl_config,
                                              ssl_ctx->dhm_ctx));
    }

    mbed_ok(mbedtls_ssl_conf_own_cert(ks_ssl->ssl_config, ssl_ctx->crt_chain,
                                      ssl_ctx->priv_key));

    /* Initialise SSL verification */
    if (session->opt->ssl_flags & SSLF_CLIENT_CERT_OPTIONAL)
    {
        mbedtls_ssl_conf_authmode(ks_ssl->ssl_config, MBEDTLS_SSL_VERIFY_OPTIONAL);
    }
    else if (!(session->opt->ssl_flags & SSLF_CLIENT_CERT_NOT_REQUIRED))
    {
        mbedtls_ssl_conf_authmode(ks_ssl->ssl_config, MBEDTLS_SSL_VERIFY_REQUIRED);
    }
    mbedtls_ssl_conf_verify(ks_ssl->ssl_config, verify_callback, session);

    /* TODO: mbed TLS does not currently support sending the CA chain to the client */
    mbedtls_ssl_conf_ca_chain(ks_ssl->ssl_config, ssl_ctx->ca_chain, ssl_ctx->crl);

    /* Initialize minimum TLS version */
    {
        const int configured_tls_version_min =
            (session->opt->ssl_flags >> SSLF_TLS_VERSION_MIN_SHIFT)
            &SSLF_TLS_VERSION_MIN_MASK;

        /* default to TLS 1.2 */
        mbedtls_ssl_protocol_version version = MBEDTLS_SSL_VERSION_TLS1_2;

        if (configured_tls_version_min > TLS_VER_UNSPEC)
        {
            version = tls_version_to_ssl_version(configured_tls_version_min);
        }

        mbedtls_ssl_conf_min_tls_version(ks_ssl->ssl_config, version);
    }

    /* Initialize maximum TLS version */
    {
        const int configured_tls_version_max =
            (session->opt->ssl_flags >> SSLF_TLS_VERSION_MAX_SHIFT)
            &SSLF_TLS_VERSION_MAX_MASK;

        mbedtls_ssl_protocol_version version = MBEDTLS_SSL_VERSION_UNKNOWN;

        if (configured_tls_version_max > TLS_VER_UNSPEC)
        {
            version = tls_version_to_ssl_version(configured_tls_version_max);
        }
        else
        {
            /* Default to tls_version_max(). */
            version = tls_version_to_ssl_version(tls_version_max());
        }

        mbedtls_ssl_conf_max_tls_version(ks_ssl->ssl_config, version);
    }

#if defined(HAVE_MBEDTLS_SSL_CONF_EXPORT_KEYS_EXT_CB) && !defined(MBEDTLS_SSL_KEYING_MATERIAL_EXPORT)
    /* Initialize keying material exporter, old style. */
    mbedtls_ssl_conf_export_keys_ext_cb(ks_ssl->ssl_config,
                                        mbedtls_ssl_export_keys_cb, session);
#endif

    /* Initialise SSL context */
    ALLOC_OBJ_CLEAR(ks_ssl->ctx, mbedtls_ssl_context);
    mbedtls_ssl_init(ks_ssl->ctx);
    mbed_ok(mbedtls_ssl_setup(ks_ssl->ctx, ks_ssl->ssl_config));
    /* We do verification in our own callback depending on the
     * exact configuration. We do not rely on the default hostname
     * verification. */
    ASSERT(mbed_ok(mbedtls_ssl_set_hostname(ks_ssl->ctx, NULL)));

#if defined(HAVE_MBEDTLS_SSL_SET_EXPORT_KEYS_CB) && !defined(MBEDTLS_SSL_KEYING_MATERIAL_EXPORT)
    /* Initialize keying material exporter, new style. */
    mbedtls_ssl_set_export_keys_cb(ks_ssl->ctx, mbedtls_ssl_export_keys_cb, session);
#endif

    /* Initialise BIOs */
    ALLOC_OBJ_CLEAR(ks_ssl->bio_ctx, bio_ctx);
    mbedtls_ssl_set_bio(ks_ssl->ctx, ks_ssl->bio_ctx, ssl_bio_write,
                        ssl_bio_read, NULL);
}


void
key_state_ssl_shutdown(struct key_state_ssl *ks_ssl)
{
    mbedtls_ssl_send_alert_message(ks_ssl->ctx, MBEDTLS_SSL_ALERT_LEVEL_FATAL,
                                   MBEDTLS_SSL_ALERT_MSG_CLOSE_NOTIFY);
}

void
key_state_ssl_free(struct key_state_ssl *ks_ssl)
{
    if (ks_ssl)
    {
        CLEAR(ks_ssl->tls_key_cache);

        if (ks_ssl->ctx)
        {
            mbedtls_ssl_free(ks_ssl->ctx);
            free(ks_ssl->ctx);
        }
        if (ks_ssl->ssl_config)
        {
            mbedtls_ssl_config_free(ks_ssl->ssl_config);
            free(ks_ssl->ssl_config);
        }
        if (ks_ssl->bio_ctx)
        {
            buf_free_entries(&ks_ssl->bio_ctx->in);
            buf_free_entries(&ks_ssl->bio_ctx->out);
            free(ks_ssl->bio_ctx);
        }
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
key_state_read_ciphertext(struct key_state_ssl *ks, struct buffer *buf)
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

    retval = endless_buf_read(&ks->bio_ctx->out, BPTR(buf), len);

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

    retval = endless_buf_write(&ks->bio_ctx->in, BPTR(buf), buf->len);

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
key_state_read_plaintext(struct key_state_ssl *ks, struct buffer *buf)
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
    snprintf(s1, sizeof(s1), "%s %s, cipher %s",
             prefix,
             mbedtls_ssl_get_version(ks_ssl->ctx),
             mbedtls_ssl_get_ciphersuite(ks_ssl->ctx));

    cert = mbedtls_ssl_get_peer_cert(ks_ssl->ctx);
    if (cert != NULL)
    {
        snprintf(s2, sizeof(s2), ", %u bit key",
                 (unsigned int) mbedtls_pk_get_bitlen(&cert->pk));
    }

    msg(D_HANDSHAKE, "%s%s", s1, s2);
}

void
show_available_tls_ciphers_list(const char *cipher_list,
                                const char *tls_cert_profile,
                                bool tls13)
{
    if (tls13)
    {
        /* mbed TLS has no TLS 1.3 support currently */
        return;
    }
    struct tls_root_ctx tls_ctx;
    const int *ciphers = mbedtls_ssl_list_ciphersuites();

    tls_ctx_server_new(&tls_ctx);
    tls_ctx_set_cert_profile(&tls_ctx, tls_cert_profile);
    tls_ctx_restrict_ciphers(&tls_ctx, cipher_list);

    if (tls_ctx.allowed_ciphers)
    {
        ciphers = tls_ctx.allowed_ciphers;
    }

    while (*ciphers != 0)
    {
        printf("%s\n", mbedtls_ssl_get_ciphersuite_name(*ciphers));
        ciphers++;
    }
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

const char *
get_ssl_library_version(void)
{
    static char mbedtls_version[30];
    unsigned int pv = mbedtls_version_get_number();
    snprintf(mbedtls_version, sizeof(mbedtls_version), "mbed TLS %d.%d.%d",
             (pv>>24)&0xff, (pv>>16)&0xff, (pv>>8)&0xff );
    return mbedtls_version;
}

void
load_xkey_provider(void)
{
    return; /* no external key provider in mbedTLS build */
}

#endif /* defined(ENABLE_CRYPTO_MBEDTLS) */
