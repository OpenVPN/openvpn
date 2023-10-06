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
 * @file Control Channel OpenSSL Backend
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "syshead.h"

#if defined(ENABLE_CRYPTO_OPENSSL)

#include "errlevel.h"
#include "buffer.h"
#include "misc.h"
#include "manage.h"
#include "memdbg.h"
#include "ssl_backend.h"
#include "ssl_common.h"
#include "base64.h"
#include "openssl_compat.h"
#include "xkey_common.h"

#ifdef ENABLE_CRYPTOAPI
#include "cryptoapi.h"
#endif

#include "ssl_verify_openssl.h"

#include <openssl/bn.h>
#include <openssl/crypto.h>
#include <openssl/dh.h>
#include <openssl/dsa.h>
#include <openssl/err.h>
#include <openssl/pkcs12.h>
#include <openssl/rsa.h>
#include <openssl/x509.h>
#include <openssl/ssl.h>
#ifndef OPENSSL_NO_EC
#include <openssl/ec.h>
#endif

#if defined(_MSC_VER) && !defined(_M_ARM64)
#include <openssl/applink.c>
#endif

OSSL_LIB_CTX *tls_libctx; /* Global */

static void unload_xkey_provider(void);

/*
 * Allocate space in SSL objects in which to store a struct tls_session
 * pointer back to parent.
 *
 */

int mydata_index; /* GLOBAL */

void
tls_init_lib(void)
{
#if OPENSSL_VERSION_NUMBER < 0x10100000L
    SSL_library_init();
#ifndef ENABLE_SMALL
    SSL_load_error_strings();
#endif
    OpenSSL_add_all_algorithms();
#endif
    mydata_index = SSL_get_ex_new_index(0, "struct session *", NULL, NULL, NULL);
    ASSERT(mydata_index >= 0);
}

void
tls_free_lib(void)
{
#if OPENSSL_VERSION_NUMBER < 0x10100000L
    EVP_cleanup();
#ifndef ENABLE_SMALL
    ERR_free_strings();
#endif
#endif
}

void
tls_ctx_server_new(struct tls_root_ctx *ctx)
{
    ASSERT(NULL != ctx);

    ctx->ctx = SSL_CTX_new_ex(tls_libctx, NULL, SSLv23_server_method());

    if (ctx->ctx == NULL)
    {
        crypto_msg(M_FATAL, "SSL_CTX_new SSLv23_server_method");
    }
    if (ERR_peek_error() != 0)
    {
        crypto_msg(M_WARN, "Warning: TLS server context initialisation "
                   "has warnings.");
    }
}

void
tls_ctx_client_new(struct tls_root_ctx *ctx)
{
    ASSERT(NULL != ctx);

    ctx->ctx = SSL_CTX_new_ex(tls_libctx, NULL, SSLv23_client_method());

    if (ctx->ctx == NULL)
    {
        crypto_msg(M_FATAL, "SSL_CTX_new SSLv23_client_method");
    }
    if (ERR_peek_error() != 0)
    {
        crypto_msg(M_WARN, "Warning: TLS client context initialisation "
                   "has warnings.");
    }
}

void
tls_ctx_free(struct tls_root_ctx *ctx)
{
    ASSERT(NULL != ctx);
    SSL_CTX_free(ctx->ctx);
    ctx->ctx = NULL;
    unload_xkey_provider(); /* in case it is loaded */
}

bool
tls_ctx_initialised(struct tls_root_ctx *ctx)
{
    ASSERT(NULL != ctx);
    return NULL != ctx->ctx;
}

bool
key_state_export_keying_material(struct tls_session *session,
                                 const char *label, size_t label_size,
                                 void *ekm, size_t ekm_size)

{
    SSL *ssl = session->key[KS_PRIMARY].ks_ssl.ssl;

    if (SSL_export_keying_material(ssl, ekm, ekm_size, label,
                                   label_size, NULL, 0, 0) == 1)
    {
        return true;
    }
    else
    {
        secure_memzero(ekm, ekm_size);
        return false;
    }
}

/*
 * Print debugging information on SSL/TLS session negotiation.
 */

#ifndef INFO_CALLBACK_SSL_CONST
#define INFO_CALLBACK_SSL_CONST const
#endif
static void
info_callback(INFO_CALLBACK_SSL_CONST SSL *s, int where, int ret)
{
    if (where & SSL_CB_LOOP)
    {
        dmsg(D_HANDSHAKE_VERBOSE, "SSL state (%s): %s",
             where & SSL_ST_CONNECT ? "connect" :
             where &SSL_ST_ACCEPT ? "accept" :
             "undefined", SSL_state_string_long(s));
    }
    else if (where & SSL_CB_ALERT)
    {
        dmsg(D_HANDSHAKE_VERBOSE, "SSL alert (%s): %s: %s",
             where & SSL_CB_READ ? "read" : "write",
             SSL_alert_type_string_long(ret),
             SSL_alert_desc_string_long(ret));
    }
}

/*
 * Return maximum TLS version supported by local OpenSSL library.
 * Assume that presence of SSL_OP_NO_TLSvX macro indicates that
 * TLSvX is supported.
 */
int
tls_version_max(void)
{
#if defined(TLS1_3_VERSION)
    /* If this is defined we can safely assume TLS 1.3 support */
    return TLS_VER_1_3;
#elif OPENSSL_VERSION_NUMBER >= 0x10100000L
    /*
     * If TLS_VER_1_3 is not defined, we were compiled against a version that
     * did not support TLS 1.3.
     *
     * However, the library we are *linked* against might be OpenSSL 1.1.1
     * and therefore supports TLS 1.3. This needs to be checked at runtime
     * since we can be compiled against 1.1.0 and then the library can be
     * upgraded to 1.1.1.
     * We only need to check this for OpenSSL versions that can be
     * upgraded to 1.1.1 without recompile (>= 1.1.0)
     */
    if (OpenSSL_version_num() >= 0x1010100fL)
    {
        return TLS_VER_1_3;
    }
    else
    {
        return TLS_VER_1_2;
    }
#elif defined(TLS1_2_VERSION) || defined(SSL_OP_NO_TLSv1_2)
    return TLS_VER_1_2;
#elif defined(TLS1_1_VERSION) || defined(SSL_OP_NO_TLSv1_1)
    return TLS_VER_1_1;
#else  /* if defined(TLS1_3_VERSION) */
    return TLS_VER_1_0;
#endif
}

/** Convert internal version number to openssl version number */
static int
openssl_tls_version(int ver)
{
    if (ver == TLS_VER_1_0)
    {
        return TLS1_VERSION;
    }
    else if (ver == TLS_VER_1_1)
    {
        return TLS1_1_VERSION;
    }
    else if (ver == TLS_VER_1_2)
    {
        return TLS1_2_VERSION;
    }
    else if (ver == TLS_VER_1_3)
    {
        /*
         * Supporting the library upgraded to TLS1.3 without recompile
         * is enough to support here with a simple constant that the same
         * as in the TLS 1.3, so spec it is very unlikely that OpenSSL
         * will change this constant
         */
#ifndef TLS1_3_VERSION
        /*
         * We do not want to define TLS_VER_1_3 if not defined
         * since other parts of the code use the existance of this macro
         * as proxy for TLS 1.3 support
         */
        return 0x0304;
#else
        return TLS1_3_VERSION;
#endif
    }
    return 0;
}

static bool
tls_ctx_set_tls_versions(struct tls_root_ctx *ctx, unsigned int ssl_flags)
{
    int tls_ver_min = openssl_tls_version(
        (ssl_flags >> SSLF_TLS_VERSION_MIN_SHIFT) & SSLF_TLS_VERSION_MIN_MASK);
    int tls_ver_max = openssl_tls_version(
        (ssl_flags >> SSLF_TLS_VERSION_MAX_SHIFT) & SSLF_TLS_VERSION_MAX_MASK);

    if (!tls_ver_min)
    {
        /* Enforce at least TLS 1.0 */
        int cur_min = SSL_CTX_get_min_proto_version(ctx->ctx);
        tls_ver_min = cur_min < TLS1_VERSION ? TLS1_VERSION : cur_min;
    }

    if (!SSL_CTX_set_min_proto_version(ctx->ctx, tls_ver_min))
    {
        msg(D_TLS_ERRORS, "%s: failed to set minimum TLS version", __func__);
        return false;
    }

    if (tls_ver_max && !SSL_CTX_set_max_proto_version(ctx->ctx, tls_ver_max))
    {
        msg(D_TLS_ERRORS, "%s: failed to set maximum TLS version", __func__);
        return false;
    }

    return true;
}

bool
tls_ctx_set_options(struct tls_root_ctx *ctx, unsigned int ssl_flags)
{
    ASSERT(NULL != ctx);

    /* process SSL options */
    long sslopt = SSL_OP_SINGLE_DH_USE | SSL_OP_NO_TICKET;
#ifdef SSL_OP_CIPHER_SERVER_PREFERENCE
    sslopt |= SSL_OP_CIPHER_SERVER_PREFERENCE;
#endif
    sslopt |= SSL_OP_NO_COMPRESSION;
    /* Disable TLS renegotiations. OpenVPN's renegotiation creates new SSL
     * session and does not depend on this feature. And TLS renegotiations have
     * been problematic in the past */
#ifdef SSL_OP_NO_RENEGOTIATION
    sslopt |= SSL_OP_NO_RENEGOTIATION;
#endif

    SSL_CTX_set_options(ctx->ctx, sslopt);

    if (!tls_ctx_set_tls_versions(ctx, ssl_flags))
    {
        return false;
    }

#ifdef SSL_MODE_RELEASE_BUFFERS
    SSL_CTX_set_mode(ctx->ctx, SSL_MODE_RELEASE_BUFFERS);
#endif
    SSL_CTX_set_session_cache_mode(ctx->ctx, SSL_SESS_CACHE_OFF);
    SSL_CTX_set_default_passwd_cb(ctx->ctx, pem_password_callback);

    /* Require peer certificate verification */
    int verify_flags = SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT;
    if (ssl_flags & SSLF_CLIENT_CERT_NOT_REQUIRED)
    {
        verify_flags = 0;
    }
    else if (ssl_flags & SSLF_CLIENT_CERT_OPTIONAL)
    {
        verify_flags = SSL_VERIFY_PEER;
    }
    SSL_CTX_set_verify(ctx->ctx, verify_flags, verify_callback);

    SSL_CTX_set_info_callback(ctx->ctx, info_callback);

    return true;
}

void
convert_tls_list_to_openssl(char *openssl_ciphers, size_t len, const char *ciphers)
{
    /* Parse supplied cipher list and pass on to OpenSSL */
    size_t begin_of_cipher, end_of_cipher;

    const char *current_cipher;
    size_t current_cipher_len;

    const tls_cipher_name_pair *cipher_pair;

    size_t openssl_ciphers_len = 0;
    openssl_ciphers[0] = '\0';

    /* Translate IANA cipher suite names to OpenSSL names */
    begin_of_cipher = end_of_cipher = 0;
    for (; begin_of_cipher < strlen(ciphers); begin_of_cipher = end_of_cipher)
    {
        end_of_cipher += strcspn(&ciphers[begin_of_cipher], ":");
        cipher_pair = tls_get_cipher_name_pair(&ciphers[begin_of_cipher], end_of_cipher - begin_of_cipher);

        if (NULL == cipher_pair)
        {
            /* No translation found, use original */
            current_cipher = &ciphers[begin_of_cipher];
            current_cipher_len = end_of_cipher - begin_of_cipher;

            /* Issue warning on missing translation */
            /* %.*s format specifier expects length of type int, so guarantee */
            /* that length is small enough and cast to int. */
            msg(D_LOW, "No valid translation found for TLS cipher '%.*s'",
                constrain_int(current_cipher_len, 0, 256), current_cipher);
        }
        else
        {
            /* Use OpenSSL name */
            current_cipher = cipher_pair->openssl_name;
            current_cipher_len = strlen(current_cipher);

            if (end_of_cipher - begin_of_cipher == current_cipher_len
                && 0 != memcmp(&ciphers[begin_of_cipher], cipher_pair->iana_name,
                               end_of_cipher - begin_of_cipher))
            {
                /* Non-IANA name used, show warning */
                msg(M_WARN, "Deprecated TLS cipher name '%s', please use IANA name '%s'", cipher_pair->openssl_name, cipher_pair->iana_name);
            }
        }

        /* Make sure new cipher name fits in cipher string */
        if ((SIZE_MAX - openssl_ciphers_len) < current_cipher_len
            || (len - 1) < (openssl_ciphers_len + current_cipher_len))
        {
            msg(M_FATAL,
                "Failed to set restricted TLS cipher list, too long (>%d).",
                (int)(len - 1));
        }

        /* Concatenate cipher name to OpenSSL cipher string */
        memcpy(&openssl_ciphers[openssl_ciphers_len], current_cipher, current_cipher_len);
        openssl_ciphers_len += current_cipher_len;
        openssl_ciphers[openssl_ciphers_len] = ':';
        openssl_ciphers_len++;

        end_of_cipher++;
    }

    if (openssl_ciphers_len > 0)
    {
        openssl_ciphers[openssl_ciphers_len-1] = '\0';
    }
}

void
tls_ctx_restrict_ciphers(struct tls_root_ctx *ctx, const char *ciphers)
{
    if (ciphers == NULL)
    {
        /* Use sane default TLS cipher list */
        if (!SSL_CTX_set_cipher_list(ctx->ctx,
                                     /* Use openssl's default list as a basis */
                                     "DEFAULT"
                                     /* Disable export ciphers and openssl's 'low' and 'medium' ciphers */
                                     ":!EXP:!LOW:!MEDIUM"
                                     /* Disable static (EC)DH keys (no forward secrecy) */
                                     ":!kDH:!kECDH"
                                     /* Disable DSA private keys */
                                     ":!DSS"
                                     /* Disable unsupported TLS modes */
                                     ":!PSK:!SRP:!kRSA"))
        {
            crypto_msg(M_FATAL, "Failed to set default TLS cipher list.");
        }
        return;
    }

    char openssl_ciphers[4096];
    convert_tls_list_to_openssl(openssl_ciphers, sizeof(openssl_ciphers), ciphers);

    ASSERT(NULL != ctx);

    /* Set OpenSSL cipher list */
    if (!SSL_CTX_set_cipher_list(ctx->ctx, openssl_ciphers))
    {
        crypto_msg(M_FATAL, "Failed to set restricted TLS cipher list: %s", openssl_ciphers);
    }
}

void
convert_tls13_list_to_openssl(char *openssl_ciphers, size_t len,
                              const char *ciphers)
{
    /*
     * OpenSSL (and official IANA) cipher names have _ in them. We
     * historically used names with - in them. Silently convert names
     * with - to names with _ to support both
     */
    if (strlen(ciphers) >= (len - 1))
    {
        msg(M_FATAL,
            "Failed to set restricted TLS 1.3 cipher list, too long (>%d).",
            (int) (len - 1));
    }

    strncpy(openssl_ciphers, ciphers, len);

    for (size_t i = 0; i < strlen(openssl_ciphers); i++)
    {
        if (openssl_ciphers[i] == '-')
        {
            openssl_ciphers[i] = '_';
        }
    }
}

void
tls_ctx_restrict_ciphers_tls13(struct tls_root_ctx *ctx, const char *ciphers)
{
    if (ciphers == NULL)
    {
        /* default cipher list of OpenSSL 1.1.1 is sane, do not set own
         * default as we do with tls-cipher */
        return;
    }

#if !defined(TLS1_3_VERSION)
    crypto_msg(M_WARN, "Not compiled with OpenSSL 1.1.1 or higher. "
               "Ignoring TLS 1.3 only tls-ciphersuites '%s' setting.",
               ciphers);
#else
    ASSERT(NULL != ctx);

    char openssl_ciphers[4096];
    convert_tls13_list_to_openssl(openssl_ciphers, sizeof(openssl_ciphers),
                                  ciphers);

    if (!SSL_CTX_set_ciphersuites(ctx->ctx, openssl_ciphers))
    {
        crypto_msg(M_FATAL, "Failed to set restricted TLS 1.3 cipher list: %s",
                   openssl_ciphers);
    }
#endif
}

void
tls_ctx_set_cert_profile(struct tls_root_ctx *ctx, const char *profile)
{
#if OPENSSL_VERSION_NUMBER > 0x10100000L && !defined(LIBRESSL_VERSION_NUMBER)
    /* OpenSSL does not have certificate profiles, but a complex set of
     * callbacks that we could try to implement to achieve something similar.
     * For now, use OpenSSL's security levels to achieve similar (but not equal)
     * behaviour. */
    if (!profile || 0 == strcmp(profile, "legacy"))
    {
        SSL_CTX_set_security_level(ctx->ctx, 1);
    }
    else if (0 == strcmp(profile, "insecure"))
    {
        SSL_CTX_set_security_level(ctx->ctx, 0);
    }
    else if (0 == strcmp(profile, "preferred"))
    {
        SSL_CTX_set_security_level(ctx->ctx, 2);
    }
    else if (0 == strcmp(profile, "suiteb"))
    {
        SSL_CTX_set_security_level(ctx->ctx, 3);
        SSL_CTX_set_cipher_list(ctx->ctx, "SUITEB128");
    }
    else
    {
        msg(M_FATAL, "ERROR: Invalid cert profile: %s", profile);
    }
#else  /* if OPENSSL_VERSION_NUMBER > 0x10100000L */
    if (profile)
    {
        msg(M_WARN, "WARNING: OpenSSL 1.0.2 and LibreSSL do not support "
            "--tls-cert-profile, ignoring user-set profile: '%s'", profile);
    }
#endif /* if OPENSSL_VERSION_NUMBER > 0x10100000L */
}

void
tls_ctx_set_tls_groups(struct tls_root_ctx *ctx, const char *groups)
{
    ASSERT(ctx);
#if OPENSSL_VERSION_NUMBER < 0x30000000L
    struct gc_arena gc = gc_new();
    /* This method could be as easy as
     *  SSL_CTX_set1_groups_list(ctx->ctx, groups)
     * but OpenSSL (< 3.0) does not like the name secp256r1 for prime256v1
     * This is one of the important curves.
     * To support the same name for OpenSSL and mbedTLS, we do
     * this dance.
     * Also note that the code is wrong in the presence of OpenSSL3 providers.
     */

    int groups_count = get_num_elements(groups, ':');

    int *glist;
    /* Allocate an array for them */
    ALLOC_ARRAY_CLEAR_GC(glist, int, groups_count, &gc);

    /* Parse allowed ciphers, getting IDs */
    int glistlen = 0;
    char *tmp_groups = string_alloc(groups, &gc);

    const char *token;
    while ((token = strsep(&tmp_groups, ":")))
    {
        if (streq(token, "secp256r1"))
        {
            token = "prime256v1";
        }
        int nid = OBJ_sn2nid(token);

        if (nid == 0)
        {
            msg(M_WARN, "Warning unknown curve/group specified: %s", token);
        }
        else
        {
            glist[glistlen] = nid;
            glistlen++;
        }
    }

    if (!SSL_CTX_set1_groups(ctx->ctx, glist, glistlen))
    {
        crypto_msg(M_FATAL, "Failed to set allowed TLS group list: %s",
                   groups);
    }
    gc_free(&gc);
#else  /* if OPENSSL_VERSION_NUMBER < 0x30000000L */
    if (!SSL_CTX_set1_groups_list(ctx->ctx, groups))
    {
        crypto_msg(M_FATAL, "Failed to set allowed TLS group list: %s",
                   groups);
    }
#endif /* if OPENSSL_VERSION_NUMBER < 0x30000000L */
}

void
tls_ctx_check_cert_time(const struct tls_root_ctx *ctx)
{
    int ret;
    const X509 *cert;

    ASSERT(ctx);

    cert = SSL_CTX_get0_certificate(ctx->ctx);

    if (cert == NULL)
    {
        return; /* Nothing to check if there is no certificate */
    }

    ret = X509_cmp_time(X509_get0_notBefore(cert), NULL);
    if (ret == 0)
    {
        msg(D_TLS_DEBUG_MED, "Failed to read certificate notBefore field.");
    }
    if (ret > 0)
    {
        msg(M_WARN, "WARNING: Your certificate is not yet valid!");
    }

    ret = X509_cmp_time(X509_get0_notAfter(cert), NULL);
    if (ret == 0)
    {
        msg(D_TLS_DEBUG_MED, "Failed to read certificate notAfter field.");
    }
    if (ret < 0)
    {
        msg(M_WARN, "WARNING: Your certificate has expired!");
    }
}

void
tls_ctx_load_dh_params(struct tls_root_ctx *ctx, const char *dh_file,
                       bool dh_file_inline)
{
    BIO *bio;

    ASSERT(NULL != ctx);

    if (dh_file_inline)
    {
        if (!(bio = BIO_new_mem_buf((char *)dh_file, -1)))
        {
            crypto_msg(M_FATAL, "Cannot open memory BIO for inline DH parameters");
        }
    }
    else
    {
        /* Get Diffie Hellman Parameters */
        if (!(bio = BIO_new_file(dh_file, "r")))
        {
            crypto_msg(M_FATAL, "Cannot open %s for DH parameters", dh_file);
        }
    }

#if OPENSSL_VERSION_NUMBER >= 0x30000000L
    EVP_PKEY *dh = PEM_read_bio_Parameters(bio, NULL);
    BIO_free(bio);

    if (!dh)
    {
        crypto_msg(M_FATAL, "Cannot load DH parameters from %s",
                   print_key_filename(dh_file, dh_file_inline));
    }
    if (!SSL_CTX_set0_tmp_dh_pkey(ctx->ctx, dh))
    {
        crypto_msg(M_FATAL, "SSL_CTX_set0_tmp_dh_pkey");
    }

    msg(D_TLS_DEBUG_LOW, "Diffie-Hellman initialized with %d bit key",
        8 * EVP_PKEY_get_size(dh));
#else  /* if OPENSSL_VERSION_NUMBER >= 0x30000000L */
    DH *dh = PEM_read_bio_DHparams(bio, NULL, NULL, NULL);
    BIO_free(bio);

    if (!dh)
    {
        crypto_msg(M_FATAL, "Cannot load DH parameters from %s",
                   print_key_filename(dh_file, dh_file_inline));
    }
    if (!SSL_CTX_set_tmp_dh(ctx->ctx, dh))
    {
        crypto_msg(M_FATAL, "SSL_CTX_set_tmp_dh");
    }

    msg(D_TLS_DEBUG_LOW, "Diffie-Hellman initialized with %d bit key",
        8 * DH_size(dh));

    DH_free(dh);
#endif /* if OPENSSL_VERSION_NUMBER >= 0x30000000L */
}

void
tls_ctx_load_ecdh_params(struct tls_root_ctx *ctx, const char *curve_name)
{
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
    if (curve_name != NULL)
    {
        msg(M_WARN, "WARNING: OpenSSL 3.0+ builds do not support specifying an "
            "ECDH curve with --ecdh-curve, using default curves. Use "
            "--tls-groups to specify groups.");
    }
#elif !defined(OPENSSL_NO_EC)
    int nid = NID_undef;
    EC_KEY *ecdh = NULL;
    const char *sname = NULL;

    /* Generate a new ECDH key for each SSL session (for non-ephemeral ECDH) */
    SSL_CTX_set_options(ctx->ctx, SSL_OP_SINGLE_ECDH_USE);

    if (curve_name != NULL)
    {
        /* Use user supplied curve if given */
        msg(D_TLS_DEBUG, "Using user specified ECDH curve (%s)", curve_name);
        nid = OBJ_sn2nid(curve_name);
    }
    else
    {
#if OPENSSL_VERSION_NUMBER < 0x10100000L

        /* OpenSSL 1.0.2 and newer can automatically handle ECDH parameter
         * loading */
        SSL_CTX_set_ecdh_auto(ctx->ctx, 1);

        /* OpenSSL 1.1.0 and newer have always ecdh auto loading enabled,
         * so do nothing */
#endif
        return;
    }

    /* Translate NID back to name , just for kicks */
    sname = OBJ_nid2sn(nid);
    if (sname == NULL)
    {
        sname = "(Unknown)";
    }

    /* Create new EC key and set as ECDH key */
    if (NID_undef == nid || NULL == (ecdh = EC_KEY_new_by_curve_name(nid)))
    {
        /* Creating key failed, fall back on sane default */
        ecdh = EC_KEY_new_by_curve_name(NID_secp384r1);
        const char *source = (NULL == curve_name) ?
                             "extract curve from certificate" : "use supplied curve";
        msg(D_TLS_DEBUG_LOW,
            "Failed to %s (%s), using secp384r1 instead.", source, sname);
        sname = OBJ_nid2sn(NID_secp384r1);
    }

    if (!SSL_CTX_set_tmp_ecdh(ctx->ctx, ecdh))
    {
        crypto_msg(M_FATAL, "SSL_CTX_set_tmp_ecdh: cannot add curve");
    }

    msg(D_TLS_DEBUG_LOW, "ECDH curve %s added", sname);

    EC_KEY_free(ecdh);
#else  /* ifndef OPENSSL_NO_EC */
    msg(D_LOW, "Your OpenSSL library was built without elliptic curve support."
        " Skipping ECDH parameter loading.");
#endif /* OPENSSL_NO_EC */
}

int
tls_ctx_load_pkcs12(struct tls_root_ctx *ctx, const char *pkcs12_file,
                    bool pkcs12_file_inline, bool load_ca_file)
{
    FILE *fp;
    EVP_PKEY *pkey;
    X509 *cert;
    STACK_OF(X509) *ca = NULL;
    PKCS12 *p12;
    int i;
    char password[256];

    ASSERT(NULL != ctx);

    if (pkcs12_file_inline)
    {
        BIO *b64 = BIO_new(BIO_f_base64());
        BIO *bio = BIO_new_mem_buf((void *) pkcs12_file,
                                   (int) strlen(pkcs12_file));
        ASSERT(b64 && bio);
        BIO_push(b64, bio);
        p12 = d2i_PKCS12_bio(b64, NULL);
        if (!p12)
        {
            crypto_msg(M_FATAL, "Error reading inline PKCS#12 file");
        }
        BIO_free(b64);
        BIO_free(bio);
    }
    else
    {
        /* Load the PKCS #12 file */
        if (!(fp = platform_fopen(pkcs12_file, "rb")))
        {
            crypto_msg(M_FATAL, "Error opening file %s", pkcs12_file);
        }
        p12 = d2i_PKCS12_fp(fp, NULL);
        fclose(fp);
        if (!p12)
        {
            crypto_msg(M_FATAL, "Error reading PKCS#12 file %s", pkcs12_file);
        }
    }

    /* Parse the PKCS #12 file */
    if (!PKCS12_parse(p12, "", &pkey, &cert, &ca))
    {
        pem_password_callback(password, sizeof(password) - 1, 0, NULL);
        /* Reparse the PKCS #12 file with password */
        ca = NULL;
        if (!PKCS12_parse(p12, password, &pkey, &cert, &ca))
        {
            crypto_msg(M_WARN, "Decoding PKCS12 failed. Probably wrong password "
                       "or unsupported/legacy encryption");
#ifdef ENABLE_MANAGEMENT
            if (management && (ERR_GET_REASON(ERR_peek_error()) == PKCS12_R_MAC_VERIFY_FAILURE))
            {
                management_auth_failure(management, UP_TYPE_PRIVATE_KEY, NULL);
            }
#endif
            PKCS12_free(p12);
            return 1;
        }
    }
    PKCS12_free(p12);

    /* Load Certificate */
    if (!SSL_CTX_use_certificate(ctx->ctx, cert))
    {
        crypto_print_openssl_errors(M_WARN);
        crypto_msg(M_FATAL, "Cannot use certificate");
    }

    /* Load Private Key */
    if (!SSL_CTX_use_PrivateKey(ctx->ctx, pkey))
    {
        crypto_msg(M_FATAL, "Cannot use private key");
    }

    /* Check Private Key */
    if (!SSL_CTX_check_private_key(ctx->ctx))
    {
        crypto_msg(M_FATAL, "Private key does not match the certificate");
    }

    /* Set Certificate Verification chain */
    if (load_ca_file)
    {
        /* Add CAs from PKCS12 to the cert store and mark them as trusted.
         * They're also used to fill in the chain of intermediate certs as
         * necessary.
         */
        if (ca && sk_X509_num(ca))
        {
            for (i = 0; i < sk_X509_num(ca); i++)
            {
                X509_STORE *cert_store = SSL_CTX_get_cert_store(ctx->ctx);
                if (!X509_STORE_add_cert(cert_store, sk_X509_value(ca, i)))
                {
                    crypto_msg(M_FATAL, "Cannot add certificate to certificate chain (X509_STORE_add_cert)");
                }
                if (!SSL_CTX_add_client_CA(ctx->ctx, sk_X509_value(ca, i)))
                {
                    crypto_msg(M_FATAL, "Cannot add certificate to client CA list (SSL_CTX_add_client_CA)");
                }
            }
        }
    }
    else
    {
        /* If trusted CA certs were loaded from a PEM file, and we ignore the
         * ones in PKCS12, do load PKCS12-provided certs to the client extra
         * certs chain just in case they include intermediate CAs needed to
         * prove my identity to the other end. This does not make them trusted.
         */
        if (ca && sk_X509_num(ca))
        {
            for (i = 0; i < sk_X509_num(ca); i++)
            {
                if (!SSL_CTX_add_extra_chain_cert(ctx->ctx, sk_X509_value(ca, i)))
                {
                    crypto_msg(M_FATAL, "Cannot add extra certificate to chain (SSL_CTX_add_extra_chain_cert)");
                }
            }
        }
    }
    return 0;
}

#ifdef ENABLE_CRYPTOAPI
void
tls_ctx_load_cryptoapi(struct tls_root_ctx *ctx, const char *cryptoapi_cert)
{
    ASSERT(NULL != ctx);

    /* Load Certificate and Private Key */
    if (!SSL_CTX_use_CryptoAPI_certificate(ctx->ctx, cryptoapi_cert))
    {
        crypto_msg(M_FATAL, "Cannot load certificate \"%s\" from Microsoft Certificate Store", cryptoapi_cert);
    }
}
#endif /* ENABLE_CRYPTOAPI */

static void
tls_ctx_add_extra_certs(struct tls_root_ctx *ctx, BIO *bio, bool optional)
{
    X509 *cert;
    while (true)
    {
        cert = NULL;
        if (!PEM_read_bio_X509(bio, &cert, NULL, NULL))
        {
            /*  a PEM_R_NO_START_LINE "Error" indicates that no certificate
             *  is found in the buffer.  If loading more certificates is
             *  optional, break without raising an error
             */
            if (optional
                && ERR_GET_REASON(ERR_peek_error()) == PEM_R_NO_START_LINE)
            {
                /* remove that error from error stack */
                (void)ERR_get_error();
                break;
            }

            /* Otherwise, bail out with error */
            crypto_msg(M_FATAL, "Error reading extra certificate");
        }
        /* takes ownership of cert like a set1 method */
        if (SSL_CTX_add_extra_chain_cert(ctx->ctx, cert) != 1)
        {
            crypto_msg(M_FATAL, "Error adding extra certificate");
        }
        /* We loaded at least one certificate, so loading more is optional */
        optional = true;
    }
}

void
tls_ctx_load_cert_file(struct tls_root_ctx *ctx, const char *cert_file,
                       bool cert_file_inline)
{
    BIO *in = NULL;
    X509 *x = NULL;
    int ret = 0;

    ASSERT(NULL != ctx);

    if (cert_file_inline)
    {
        in = BIO_new_mem_buf((char *) cert_file, -1);
    }
    else
    {
        in = BIO_new_file(cert_file, "r");
    }

    if (in == NULL)
    {
        SSLerr(SSL_F_SSL_CTX_USE_CERTIFICATE_FILE, ERR_R_SYS_LIB);
        goto end;
    }

    x = PEM_read_bio_X509(in, NULL,
                          SSL_CTX_get_default_passwd_cb(ctx->ctx),
                          SSL_CTX_get_default_passwd_cb_userdata(ctx->ctx));
    if (x == NULL)
    {
        SSLerr(SSL_F_SSL_CTX_USE_CERTIFICATE_FILE, ERR_R_PEM_LIB);
        goto end;
    }

    ret = SSL_CTX_use_certificate(ctx->ctx, x);
    if (ret)
    {
        tls_ctx_add_extra_certs(ctx, in, true);
    }

end:
    if (!ret)
    {
        crypto_print_openssl_errors(M_WARN);
        if (cert_file_inline)
        {
            crypto_msg(M_FATAL, "Cannot load inline certificate file");
        }
        else
        {
            crypto_msg(M_FATAL, "Cannot load certificate file %s", cert_file);
        }
    }
    else
    {
        crypto_print_openssl_errors(M_DEBUG);
    }

    BIO_free(in);
    X509_free(x);
}

int
tls_ctx_load_priv_file(struct tls_root_ctx *ctx, const char *priv_key_file,
                       bool priv_key_file_inline)
{
    SSL_CTX *ssl_ctx = NULL;
    BIO *in = NULL;
    EVP_PKEY *pkey = NULL;
    int ret = 1;

    ASSERT(NULL != ctx);

    ssl_ctx = ctx->ctx;

    if (priv_key_file_inline)
    {
        in = BIO_new_mem_buf((char *) priv_key_file, -1);
    }
    else
    {
        in = BIO_new_file(priv_key_file, "r");
    }

    if (!in)
    {
        goto end;
    }

    pkey = PEM_read_bio_PrivateKey(in, NULL,
                                   SSL_CTX_get_default_passwd_cb(ctx->ctx),
                                   SSL_CTX_get_default_passwd_cb_userdata(ctx->ctx));

    if (!pkey || !SSL_CTX_use_PrivateKey(ssl_ctx, pkey))
    {
#ifdef ENABLE_MANAGEMENT
        if (management && (ERR_GET_REASON(ERR_peek_error()) == EVP_R_BAD_DECRYPT))
        {
            management_auth_failure(management, UP_TYPE_PRIVATE_KEY, NULL);
        }
#endif
        crypto_msg(M_WARN, "Cannot load private key file %s",
                   print_key_filename(priv_key_file, priv_key_file_inline));
        goto end;
    }

    /* Check Private Key */
    if (!SSL_CTX_check_private_key(ssl_ctx))
    {
        crypto_msg(M_FATAL, "Private key does not match the certificate");
    }
    ret = 0;

end:
    EVP_PKEY_free(pkey);
    BIO_free(in);
    return ret;
}

void
backend_tls_ctx_reload_crl(struct tls_root_ctx *ssl_ctx, const char *crl_file,
                           bool crl_inline)
{
    BIO *in = NULL;

    X509_STORE *store = SSL_CTX_get_cert_store(ssl_ctx->ctx);
    if (!store)
    {
        crypto_msg(M_FATAL, "Cannot get certificate store");
    }

    /* Always start with a cleared CRL list, for that we
     * we need to manually find the CRL object from the stack
     * and remove it */
    STACK_OF(X509_OBJECT) *objs = X509_STORE_get0_objects(store);
    for (int i = 0; i < sk_X509_OBJECT_num(objs); i++)
    {
        X509_OBJECT *obj = sk_X509_OBJECT_value(objs, i);
        ASSERT(obj);
        if (X509_OBJECT_get_type(obj) == X509_LU_CRL)
        {
            sk_X509_OBJECT_delete(objs, i);
            X509_OBJECT_free(obj);
        }
    }

    X509_STORE_set_flags(store, X509_V_FLAG_CRL_CHECK | X509_V_FLAG_CRL_CHECK_ALL);

    if (crl_inline)
    {
        in = BIO_new_mem_buf((char *) crl_file, -1);
    }
    else
    {
        in = BIO_new_file(crl_file, "r");
    }

    if (in == NULL)
    {
        msg(M_WARN, "CRL: cannot read: %s",
            print_key_filename(crl_file, crl_inline));
        goto end;
    }

    int num_crls_loaded = 0;
    while (true)
    {
        X509_CRL *crl = PEM_read_bio_X509_CRL(in, NULL, NULL, NULL);
        if (crl == NULL)
        {
            /*
             * PEM_R_NO_START_LINE can be considered equivalent to EOF.
             */
            bool eof = ERR_GET_REASON(ERR_peek_error()) == PEM_R_NO_START_LINE;
            /* but warn if no CRLs have been loaded */
            if (num_crls_loaded > 0 && eof)
            {
                /* remove that error from error stack */
                (void)ERR_get_error();
                break;
            }

            crypto_msg(M_WARN, "CRL: cannot read CRL from file %s",
                       print_key_filename(crl_file, crl_inline));
            break;
        }

        if (!X509_STORE_add_crl(store, crl))
        {
            X509_CRL_free(crl);
            crypto_msg(M_WARN, "CRL: cannot add %s to store",
                       print_key_filename(crl_file, crl_inline));
            break;
        }
        X509_CRL_free(crl);
        num_crls_loaded++;
    }
    msg(M_INFO, "CRL: loaded %d CRLs from file %s", num_crls_loaded, crl_file);
end:
    BIO_free(in);
}


#if defined(ENABLE_MANAGEMENT) && !defined(HAVE_XKEY_PROVIDER)

/* encrypt */
static int
rsa_pub_enc(int flen, const unsigned char *from, unsigned char *to, RSA *rsa, int padding)
{
    ASSERT(0);
    return -1;
}

/* verify arbitrary data */
static int
rsa_pub_dec(int flen, const unsigned char *from, unsigned char *to, RSA *rsa, int padding)
{
    ASSERT(0);
    return -1;
}

/* decrypt */
static int
rsa_priv_dec(int flen, const unsigned char *from, unsigned char *to, RSA *rsa, int padding)
{
    ASSERT(0);
    return -1;
}

/* called at RSA_free */
static int
openvpn_extkey_rsa_finish(RSA *rsa)
{
    /* meth was allocated in tls_ctx_use_management_external_key() ; since
     * this function is called when the parent RSA object is destroyed,
     * it is no longer used after this point so kill it. */
    const RSA_METHOD *meth = RSA_get_method(rsa);
    RSA_meth_free((RSA_METHOD *)meth);
    return 1;
}

/*
 * Convert OpenSSL's constant to the strings used in the management
 * interface query
 */
const char *
get_rsa_padding_name(const int padding)
{
    switch (padding)
    {
        case RSA_PKCS1_PADDING:
            return "RSA_PKCS1_PADDING";

        case RSA_NO_PADDING:
            return "RSA_NO_PADDING";

        default:
            return "UNKNOWN";
    }
}

/**
 * Pass the input hash in 'dgst' to management and get the signature back.
 *
 * @param dgst          hash to be signed
 * @param dgstlen       len of data in dgst
 * @param sig           On successful return signature is in sig.
 * @param siglen        length of buffer sig
 * @param algorithm     padding/hashing algorithm for the signature
 *
 * @return              signature length or -1 on error.
 */
static int
get_sig_from_man(const unsigned char *dgst, unsigned int dgstlen,
                 unsigned char *sig, unsigned int siglen,
                 const char *algorithm)
{
    char *in_b64 = NULL;
    char *out_b64 = NULL;
    int len = -1;

    int bencret = openvpn_base64_encode(dgst, dgstlen, &in_b64);

    if (management && bencret > 0)
    {
        out_b64 = management_query_pk_sig(management, in_b64, algorithm);

    }
    if (out_b64)
    {
        len = openvpn_base64_decode(out_b64, sig, siglen);
    }

    free(in_b64);
    free(out_b64);
    return len;
}

/* sign arbitrary data */
static int
rsa_priv_enc(int flen, const unsigned char *from, unsigned char *to, RSA *rsa,
             int padding)
{
    unsigned int len = RSA_size(rsa);
    int ret = -1;

    if (padding != RSA_PKCS1_PADDING && padding != RSA_NO_PADDING)
    {
        RSAerr(RSA_F_RSA_OSSL_PRIVATE_ENCRYPT, RSA_R_UNKNOWN_PADDING_TYPE);
        return -1;
    }

    ret = get_sig_from_man(from, flen, to, len, get_rsa_padding_name(padding));

    return (ret == len) ? ret : -1;
}

static int
tls_ctx_use_external_rsa_key(struct tls_root_ctx *ctx, EVP_PKEY *pkey)
{
    RSA *rsa = NULL;
    RSA_METHOD *rsa_meth;

    ASSERT(NULL != ctx);

    const RSA *pub_rsa = EVP_PKEY_get0_RSA(pkey);
    ASSERT(NULL != pub_rsa);

    /* allocate custom RSA method object */
    rsa_meth = RSA_meth_new("OpenVPN external private key RSA Method",
                            RSA_METHOD_FLAG_NO_CHECK);
    check_malloc_return(rsa_meth);
    RSA_meth_set_pub_enc(rsa_meth, rsa_pub_enc);
    RSA_meth_set_pub_dec(rsa_meth, rsa_pub_dec);
    RSA_meth_set_priv_enc(rsa_meth, rsa_priv_enc);
    RSA_meth_set_priv_dec(rsa_meth, rsa_priv_dec);
    RSA_meth_set_init(rsa_meth, NULL);
    RSA_meth_set_finish(rsa_meth, openvpn_extkey_rsa_finish);
    RSA_meth_set0_app_data(rsa_meth, NULL);

    /* allocate RSA object */
    rsa = RSA_new();
    if (rsa == NULL)
    {
        SSLerr(SSL_F_SSL_USE_PRIVATEKEY, ERR_R_MALLOC_FAILURE);
        goto err;
    }

    /* initialize RSA object */
    const BIGNUM *n = NULL;
    const BIGNUM *e = NULL;
    RSA_get0_key(pub_rsa, &n, &e, NULL);
    RSA_set0_key(rsa, BN_dup(n), BN_dup(e), NULL);
    RSA_set_flags(rsa, RSA_flags(rsa) | RSA_FLAG_EXT_PKEY);
    if (!RSA_set_method(rsa, rsa_meth))
    {
        RSA_meth_free(rsa_meth);
        goto err;
    }
    /* from this point rsa_meth will get freed with rsa */

    /* bind our custom RSA object to ssl_ctx */
    if (!SSL_CTX_use_RSAPrivateKey(ctx->ctx, rsa))
    {
        goto err;
    }

    RSA_free(rsa); /* doesn't necessarily free, just decrements refcount */
    return 1;

err:
    if (rsa)
    {
        RSA_free(rsa);
    }
    else if (rsa_meth)
    {
        RSA_meth_free(rsa_meth);
    }
    return 0;
}

#if OPENSSL_VERSION_NUMBER > 0x10100000L && !defined(OPENSSL_NO_EC)

/* called when EC_KEY is destroyed */
static void
openvpn_extkey_ec_finish(EC_KEY *ec)
{
    /* release the method structure */
    const EC_KEY_METHOD *ec_meth = EC_KEY_get_method(ec);
    EC_KEY_METHOD_free((EC_KEY_METHOD *) ec_meth);
}

/* EC_KEY_METHOD callback: sign().
 * Sign the hash using EC key and return DER encoded signature in sig,
 * its length in siglen. Return value is 1 on success, 0 on error.
 */
static int
ecdsa_sign(int type, const unsigned char *dgst, int dgstlen, unsigned char *sig,
           unsigned int *siglen, const BIGNUM *kinv, const BIGNUM *r, EC_KEY *ec)
{
    int capacity = ECDSA_size(ec);
    /*
     * ECDSA does not seem to have proper constants for paddings since
     * there are only signatures without padding at the moment, use
     * a generic ECDSA for the moment
     */
    int len = get_sig_from_man(dgst, dgstlen, sig, capacity, "ECDSA");

    if (len > 0)
    {
        *siglen = len;
        return 1;
    }
    return 0;
}

/* EC_KEY_METHOD callback: sign_setup(). We do no precomputations */
static int
ecdsa_sign_setup(EC_KEY *ec, BN_CTX *ctx_in, BIGNUM **kinvp, BIGNUM **rp)
{
    return 1;
}

/* EC_KEY_METHOD callback: sign_sig().
 * Sign the hash and return the result as a newly allocated ECDS_SIG
 * struct or NULL on error.
 */
static ECDSA_SIG *
ecdsa_sign_sig(const unsigned char *dgst, int dgstlen, const BIGNUM *in_kinv,
               const BIGNUM *in_r, EC_KEY *ec)
{
    ECDSA_SIG *ecsig = NULL;
    unsigned int len = ECDSA_size(ec);
    struct gc_arena gc = gc_new();

    unsigned char *buf = gc_malloc(len, false, &gc);
    if (ecdsa_sign(0, dgst, dgstlen, buf, &len, NULL, NULL, ec) != 1)
    {
        goto out;
    }
    /* const char ** should be avoided: not up to us, so we cast our way through */
    ecsig = d2i_ECDSA_SIG(NULL, (const unsigned char **)&buf, len);

out:
    gc_free(&gc);
    return ecsig;
}

static int
tls_ctx_use_external_ec_key(struct tls_root_ctx *ctx, EVP_PKEY *pkey)
{
    EC_KEY *ec = NULL;
    EVP_PKEY *privkey = NULL;
    EC_KEY_METHOD *ec_method;

    ASSERT(ctx);

    ec_method = EC_KEY_METHOD_new(EC_KEY_OpenSSL());
    if (!ec_method)
    {
        goto err;
    }

    /* Among init methods, we only need the finish method */
    EC_KEY_METHOD_set_init(ec_method, NULL, openvpn_extkey_ec_finish, NULL, NULL, NULL, NULL);
    EC_KEY_METHOD_set_sign(ec_method, ecdsa_sign, ecdsa_sign_setup, ecdsa_sign_sig);

    ec = EC_KEY_dup(EVP_PKEY_get0_EC_KEY(pkey));
    if (!ec)
    {
        EC_KEY_METHOD_free(ec_method);
        goto err;
    }
    if (!EC_KEY_set_method(ec, ec_method))
    {
        EC_KEY_METHOD_free(ec_method);
        goto err;
    }
    /* from this point ec_method will get freed when ec is freed */

    privkey = EVP_PKEY_new();
    if (!EVP_PKEY_assign_EC_KEY(privkey, ec))
    {
        goto err;
    }
    /* from this point ec will get freed when privkey is freed */

    if (!SSL_CTX_use_PrivateKey(ctx->ctx, privkey))
    {
        ec = NULL; /* avoid double freeing it below */
        goto err;
    }

    EVP_PKEY_free(privkey); /* this will down ref privkey and ec */
    return 1;

err:
    /* Reach here only when ec and privkey can be independenly freed */
    EVP_PKEY_free(privkey);
    EC_KEY_free(ec);
    return 0;
}
#endif /* OPENSSL_VERSION_NUMBER > 1.1.0 dev && !defined(OPENSSL_NO_EC) */
#endif /* ENABLE_MANAGEMENT && !HAVE_XKEY_PROVIDER */

#ifdef ENABLE_MANAGEMENT
int
tls_ctx_use_management_external_key(struct tls_root_ctx *ctx)
{
    int ret = 1;

    ASSERT(NULL != ctx);

    X509 *cert = SSL_CTX_get0_certificate(ctx->ctx);

    ASSERT(NULL != cert);

    /* get the public key */
    EVP_PKEY *pkey = X509_get0_pubkey(cert);
    ASSERT(pkey); /* NULL before SSL_CTX_use_certificate() is called */

#ifdef HAVE_XKEY_PROVIDER
    EVP_PKEY *privkey = xkey_load_management_key(tls_libctx, pkey);
    if (!privkey
        || !SSL_CTX_use_PrivateKey(ctx->ctx, privkey))
    {
        EVP_PKEY_free(privkey);
        goto cleanup;
    }
    EVP_PKEY_free(privkey);
#else  /* ifdef HAVE_XKEY_PROVIDER */
#if OPENSSL_VERSION_NUMBER < 0x30000000L
    if (EVP_PKEY_id(pkey) == EVP_PKEY_RSA)
#else /* OPENSSL_VERSION_NUMBER < 0x30000000L */
    if (EVP_PKEY_is_a(pkey, "RSA"))
#endif /* OPENSSL_VERSION_NUMBER < 0x30000000L */
    {
        if (!tls_ctx_use_external_rsa_key(ctx, pkey))
        {
            goto cleanup;
        }
    }
#if (OPENSSL_VERSION_NUMBER > 0x10100000L) && !defined(OPENSSL_NO_EC)
#if OPENSSL_VERSION_NUMBER < 0x30000000L
    else if (EVP_PKEY_id(pkey) == EVP_PKEY_EC)
#else /* OPENSSL_VERSION_NUMBER < 0x30000000L */
    else if (EVP_PKEY_is_a(pkey, "EC"))
#endif /* OPENSSL_VERSION_NUMBER < 0x30000000L */
    {
        if (!tls_ctx_use_external_ec_key(ctx, pkey))
        {
            goto cleanup;
        }
    }
    else
    {
        crypto_msg(M_WARN, "management-external-key requires an RSA or EC certificate");
        goto cleanup;
    }
#else  /* OPENSSL_VERSION_NUMBER > 1.1.0 dev && !defined(OPENSSL_NO_EC) */
    else
    {
        crypto_msg(M_WARN, "management-external-key requires an RSA certificate");
        goto cleanup;
    }
#endif /* OPENSSL_VERSION_NUMBER > 1.1.0 dev && !defined(OPENSSL_NO_EC) */

#endif /* HAVE_XKEY_PROVIDER */

    ret = 0;
cleanup:
    if (ret)
    {
        crypto_msg(M_FATAL, "Cannot enable SSL external private key capability");
    }
    return ret;
}

#endif /* ifdef ENABLE_MANAGEMENT */

static int
sk_x509_name_cmp(const X509_NAME *const *a, const X509_NAME *const *b)
{
    return X509_NAME_cmp(*a, *b);
}

void
tls_ctx_load_ca(struct tls_root_ctx *ctx, const char *ca_file,
                bool ca_file_inline, const char *ca_path, bool tls_server)
{
    STACK_OF(X509_INFO) *info_stack = NULL;
    STACK_OF(X509_NAME) *cert_names = NULL;
    X509_LOOKUP *lookup = NULL;
    X509_STORE *store = NULL;
    X509_NAME *xn = NULL;
    BIO *in = NULL;
    int i, added = 0, prev = 0;

    ASSERT(NULL != ctx);

    store = SSL_CTX_get_cert_store(ctx->ctx);
    if (!store)
    {
        crypto_msg(M_FATAL, "Cannot get certificate store");
    }

    /* Try to add certificates and CRLs from ca_file */
    if (ca_file)
    {
        if (ca_file_inline)
        {
            in = BIO_new_mem_buf((char *)ca_file, -1);
        }
        else
        {
            in = BIO_new_file(ca_file, "r");
        }

        if (in)
        {
            info_stack = PEM_X509_INFO_read_bio(in, NULL, NULL, NULL);
        }

        if (info_stack)
        {
            for (i = 0; i < sk_X509_INFO_num(info_stack); i++)
            {
                X509_INFO *info = sk_X509_INFO_value(info_stack, i);
                if (info->crl)
                {
                    X509_STORE_add_crl(store, info->crl);
                }

                if (tls_server && !info->x509)
                {
                    crypto_msg(M_FATAL, "X509 name was missing in TLS mode");
                }

                if (info->x509)
                {
                    X509_STORE_add_cert(store, info->x509);
                    added++;

                    if (!tls_server)
                    {
                        continue;
                    }

                    /* Use names of CAs as a client CA list */
                    if (cert_names == NULL)
                    {
                        cert_names = sk_X509_NAME_new(sk_x509_name_cmp);
                        if (!cert_names)
                        {
                            continue;
                        }
                    }

                    xn = X509_get_subject_name(info->x509);
                    if (!xn)
                    {
                        continue;
                    }

                    /* Don't add duplicate CA names */
                    if (sk_X509_NAME_find(cert_names, xn) == -1)
                    {
                        xn = X509_NAME_dup(xn);
                        if (!xn)
                        {
                            continue;
                        }
                        sk_X509_NAME_push(cert_names, xn);
                    }
                }

                if (tls_server)
                {
                    int cnum = sk_X509_NAME_num(cert_names);
                    if (cnum != (prev + 1))
                    {
                        crypto_msg(M_WARN,
                                   "Cannot load CA certificate file %s (entry %d did not validate)",
                                   print_key_filename(ca_file, ca_file_inline),
                                   added);
                    }
                    prev = cnum;
                }
            }
            sk_X509_INFO_pop_free(info_stack, X509_INFO_free);
        }

        if (tls_server)
        {
            SSL_CTX_set_client_CA_list(ctx->ctx, cert_names);
        }

        if (!added)
        {
            crypto_msg(M_FATAL,
                       "Cannot load CA certificate file %s (no entries were read)",
                       print_key_filename(ca_file, ca_file_inline));
        }

        if (tls_server)
        {
            int cnum = sk_X509_NAME_num(cert_names);
            if (cnum != added)
            {
                crypto_msg(M_FATAL, "Cannot load CA certificate file %s (only %d "
                           "of %d entries were valid X509 names)",
                           print_key_filename(ca_file, ca_file_inline), cnum,
                           added);
            }
        }

        BIO_free(in);
    }

    /* Set a store for certs (CA & CRL) with a lookup on the "capath" hash directory */
    if (ca_path)
    {
        lookup = X509_STORE_add_lookup(store, X509_LOOKUP_hash_dir());
        if (lookup && X509_LOOKUP_add_dir(lookup, ca_path, X509_FILETYPE_PEM))
        {
            msg(M_WARN, "WARNING: experimental option --capath %s", ca_path);
        }
        else
        {
            crypto_msg(M_FATAL, "Cannot add lookup at --capath %s", ca_path);
        }
        X509_STORE_set_flags(store, X509_V_FLAG_CRL_CHECK | X509_V_FLAG_CRL_CHECK_ALL);
    }
}

void
tls_ctx_load_extra_certs(struct tls_root_ctx *ctx, const char *extra_certs_file,
                         bool extra_certs_file_inline)
{
    BIO *in;
    if (extra_certs_file_inline)
    {
        in = BIO_new_mem_buf((char *)extra_certs_file, -1);
    }
    else
    {
        in = BIO_new_file(extra_certs_file, "r");
    }

    if (in == NULL)
    {
        crypto_msg(M_FATAL, "Cannot load extra-certs file: %s",
                   print_key_filename(extra_certs_file,
                                      extra_certs_file_inline));

    }
    else
    {
        tls_ctx_add_extra_certs(ctx, in, false);
    }

    BIO_free(in);
}

/* **************************************
 *
 * Key-state specific functions
 *
 ***************************************/
/*
 *
 * BIO functions
 *
 */

#ifdef BIO_DEBUG

#warning BIO_DEBUG defined

static FILE *biofp;                            /* GLOBAL */
static bool biofp_toggle;                      /* GLOBAL */
static time_t biofp_last_open;                 /* GLOBAL */
static const int biofp_reopen_interval = 600;  /* GLOBAL */

static void
close_biofp(void)
{
    if (biofp)
    {
        ASSERT(!fclose(biofp));
        biofp = NULL;
    }
}

static void
open_biofp(void)
{
    const time_t current = time(NULL);
    const pid_t pid = getpid();

    if (biofp_last_open + biofp_reopen_interval < current)
    {
        close_biofp();
    }
    if (!biofp)
    {
        char fn[256];
        openvpn_snprintf(fn, sizeof(fn), "bio/%d-%d.log", pid, biofp_toggle);
        biofp = fopen(fn, "w");
        ASSERT(biofp);
        biofp_last_open = time(NULL);
        biofp_toggle ^= 1;
    }
}

static void
bio_debug_data(const char *mode, BIO *bio, const uint8_t *buf, int len, const char *desc)
{
    struct gc_arena gc = gc_new();
    if (len > 0)
    {
        open_biofp();
        fprintf(biofp, "BIO_%s %s time=%" PRIi64 " bio=" ptr_format " len=%d data=%s\n",
                mode, desc, (int64_t)time(NULL), (ptr_type)bio, len, format_hex(buf, len, 0, &gc));
        fflush(biofp);
    }
    gc_free(&gc);
}

static void
bio_debug_oc(const char *mode, BIO *bio)
{
    open_biofp();
    fprintf(biofp, "BIO %s time=%" PRIi64 " bio=" ptr_format "\n",
            mode, (int64_t)time(NULL), (ptr_type)bio);
    fflush(biofp);
}

#endif /* ifdef BIO_DEBUG */

/*
 * Write to an OpenSSL BIO in non-blocking mode.
 */
static int
bio_write(BIO *bio, const uint8_t *data, int size, const char *desc)
{
    int i;
    int ret = 0;
    ASSERT(size >= 0);
    if (size)
    {
        /*
         * Free the L_TLS lock prior to calling BIO routines
         * so that foreground thread can still call
         * tls_pre_decrypt or tls_pre_encrypt,
         * allowing tunnel packet forwarding to continue.
         */
#ifdef BIO_DEBUG
        bio_debug_data("write", bio, data, size, desc);
#endif
        i = BIO_write(bio, data, size);

        if (i < 0)
        {
            if (!BIO_should_retry(bio))
            {
                crypto_msg(D_TLS_ERRORS, "TLS ERROR: BIO write %s error", desc);
                ret = -1;
                ERR_clear_error();
            }
        }
        else if (i != size)
        {
            crypto_msg(D_TLS_ERRORS, "TLS ERROR: BIO write %s incomplete %d/%d",
                       desc, i, size);
            ret = -1;
            ERR_clear_error();
        }
        else
        {                       /* successful write */
            dmsg(D_HANDSHAKE_VERBOSE, "BIO write %s %d bytes", desc, i);
            ret = 1;
        }
    }
    return ret;
}

/*
 * Inline functions for reading from and writing
 * to BIOs.
 */

static void
bio_write_post(const int status, struct buffer *buf)
{
    if (status == 1) /* success status return from bio_write? */
    {
        memset(BPTR(buf), 0, BLEN(buf));  /* erase data just written */
        buf->len = 0;
    }
}

/*
 * Read from an OpenSSL BIO in non-blocking mode.
 */
static int
bio_read(BIO *bio, struct buffer *buf, const char *desc)
{
    ASSERT(buf->len >= 0);
    if (buf->len)
    {
        /* we only want to write empty buffers, ignore read request
         * if the buffer is not empty */
        return 0;
    }
    int len = buf_forward_capacity(buf);

    /*
     * BIO_read brackets most of the serious RSA
     * key negotiation number crunching.
     */
    int i = BIO_read(bio, BPTR(buf), len);

    VALGRIND_MAKE_READABLE((void *) &i, sizeof(i));

#ifdef BIO_DEBUG
    bio_debug_data("read", bio, BPTR(buf), i, desc);
#endif

    int ret = 0;
    if (i < 0)
    {
        if (!BIO_should_retry(bio))
        {
            crypto_msg(D_TLS_ERRORS, "TLS_ERROR: BIO read %s error", desc);
            buf->len = 0;
            ret = -1;
            ERR_clear_error();
        }
    }
    else if (!i)
    {
        buf->len = 0;
    }
    else
    {                       /* successful read */
        dmsg(D_HANDSHAKE_VERBOSE, "BIO read %s %d bytes", desc, i);
        buf->len = i;
        ret = 1;
        VALGRIND_MAKE_READABLE((void *) BPTR(buf), BLEN(buf));
    }
    return ret;
}

void
key_state_ssl_init(struct key_state_ssl *ks_ssl, const struct tls_root_ctx *ssl_ctx, bool is_server, struct tls_session *session)
{
    ASSERT(NULL != ssl_ctx);
    ASSERT(ks_ssl);
    CLEAR(*ks_ssl);

    ks_ssl->ssl = SSL_new(ssl_ctx->ctx);
    if (!ks_ssl->ssl)
    {
        crypto_msg(M_FATAL, "SSL_new failed");
    }

    /* put session * in ssl object so we can access it
     * from verify callback*/
    SSL_set_ex_data(ks_ssl->ssl, mydata_index, session);

    ASSERT((ks_ssl->ssl_bio = BIO_new(BIO_f_ssl())));
    ASSERT((ks_ssl->ct_in = BIO_new(BIO_s_mem())));
    ASSERT((ks_ssl->ct_out = BIO_new(BIO_s_mem())));

#ifdef BIO_DEBUG
    bio_debug_oc("open ssl_bio", ks_ssl->ssl_bio);
    bio_debug_oc("open ct_in", ks_ssl->ct_in);
    bio_debug_oc("open ct_out", ks_ssl->ct_out);
#endif

    if (is_server)
    {
        SSL_set_accept_state(ks_ssl->ssl);
    }
    else
    {
        SSL_set_connect_state(ks_ssl->ssl);
    }

    SSL_set_bio(ks_ssl->ssl, ks_ssl->ct_in, ks_ssl->ct_out);
    BIO_set_ssl(ks_ssl->ssl_bio, ks_ssl->ssl, BIO_NOCLOSE);
}

void
key_state_ssl_free(struct key_state_ssl *ks_ssl)
{
    if (ks_ssl->ssl)
    {
#ifdef BIO_DEBUG
        bio_debug_oc("close ssl_bio", ks_ssl->ssl_bio);
        bio_debug_oc("close ct_in", ks_ssl->ct_in);
        bio_debug_oc("close ct_out", ks_ssl->ct_out);
#endif
        BIO_free_all(ks_ssl->ssl_bio);
        SSL_free(ks_ssl->ssl);
    }
}

int
key_state_write_plaintext(struct key_state_ssl *ks_ssl, struct buffer *buf)
{
    int ret = 0;
    perf_push(PERF_BIO_WRITE_PLAINTEXT);

    ASSERT(NULL != ks_ssl);

    ret = bio_write(ks_ssl->ssl_bio, BPTR(buf), BLEN(buf),
                    "tls_write_plaintext");
    bio_write_post(ret, buf);

    perf_pop();
    return ret;
}

int
key_state_write_plaintext_const(struct key_state_ssl *ks_ssl, const uint8_t *data, int len)
{
    int ret = 0;
    perf_push(PERF_BIO_WRITE_PLAINTEXT);

    ASSERT(NULL != ks_ssl);

    ret = bio_write(ks_ssl->ssl_bio, data, len, "tls_write_plaintext_const");

    perf_pop();
    return ret;
}

int
key_state_read_ciphertext(struct key_state_ssl *ks_ssl, struct buffer *buf)
{
    int ret = 0;
    perf_push(PERF_BIO_READ_CIPHERTEXT);

    ASSERT(NULL != ks_ssl);

    ret = bio_read(ks_ssl->ct_out, buf, "tls_read_ciphertext");

    perf_pop();
    return ret;
}

int
key_state_write_ciphertext(struct key_state_ssl *ks_ssl, struct buffer *buf)
{
    int ret = 0;
    perf_push(PERF_BIO_WRITE_CIPHERTEXT);

    ASSERT(NULL != ks_ssl);

    ret = bio_write(ks_ssl->ct_in, BPTR(buf), BLEN(buf), "tls_write_ciphertext");
    bio_write_post(ret, buf);

    perf_pop();
    return ret;
}

int
key_state_read_plaintext(struct key_state_ssl *ks_ssl, struct buffer *buf)
{
    int ret = 0;
    perf_push(PERF_BIO_READ_PLAINTEXT);

    ASSERT(NULL != ks_ssl);

    ret = bio_read(ks_ssl->ssl_bio, buf, "tls_read_plaintext");

    perf_pop();
    return ret;
}

static void
print_pkey_details(EVP_PKEY *pkey, char *buf, size_t buflen)
{
    const char *curve = "";
    const char *type = "(error getting type)";

    if (pkey == NULL)
    {
        buf[0] = 0;
        return;
    }

    int typeid = EVP_PKEY_id(pkey);
#if OPENSSL_VERSION_NUMBER < 0x30000000L
    bool is_ec = typeid == EVP_PKEY_EC;
#else
    bool is_ec = EVP_PKEY_is_a(pkey, "EC");
#endif

#ifndef OPENSSL_NO_EC
    char groupname[256];
    if (is_ec)
    {
        size_t len;
        if (EVP_PKEY_get_group_name(pkey, groupname, sizeof(groupname), &len))
        {
            curve = groupname;
        }
        else
        {
            curve = "(error getting curve name)";
        }
    }
#endif
    if (typeid != 0)
    {
#if OPENSSL_VERSION_NUMBER < 0x30000000L
        type = OBJ_nid2sn(typeid);

        /* OpenSSL reports rsaEncryption, dsaEncryption and
        * id-ecPublicKey, map these values to nicer ones */
        if (typeid == EVP_PKEY_RSA)
        {
            type = "RSA";
        }
        else if (typeid == EVP_PKEY_DSA)
        {
            type = "DSA";
        }
        else if (typeid == EVP_PKEY_EC)
        {
            /* EC gets the curve appended after the type */
            type = "EC, curve ";
        }
        else if (type == NULL)
        {
            type = "unknown type";
        }
#else /* OpenSSL >= 3 */
        type = EVP_PKEY_get0_type_name(pkey);
        if (type == NULL)
        {
            type = "(error getting public key type)";
        }
#endif /* if OPENSSL_VERSION_NUMBER < 0x30000000L */
    }

    openvpn_snprintf(buf, buflen, "%d bits %s%s",
                     EVP_PKEY_bits(pkey), type, curve);
}

/**
 * Print human readable information about the certificate into buf
 * @param cert      the certificate being used
 * @param buf       output buffer
 * @param buflen    output buffer length
 */
static void
print_cert_details(X509 *cert, char *buf, size_t buflen)
{
    EVP_PKEY *pkey = X509_get_pubkey(cert);
    char pkeybuf[128] = { 0 };
    print_pkey_details(pkey, pkeybuf, sizeof(pkeybuf));

    char sig[128] = { 0 };
    int signature_nid = X509_get_signature_nid(cert);
    if (signature_nid != 0)
    {
        openvpn_snprintf(sig, sizeof(sig), ", signature: %s",
                         OBJ_nid2sn(signature_nid));
    }

    openvpn_snprintf(buf, buflen, ", peer certificate: %s%s",
                     pkeybuf, sig);

    EVP_PKEY_free(pkey);
}

static void
print_server_tempkey(SSL *ssl, char *buf, size_t buflen)
{
    EVP_PKEY *pkey = NULL;
    SSL_get_peer_tmp_key(ssl, &pkey);
    if (!pkey)
    {
        return;
    }

    char pkeybuf[128] = { 0 };
    print_pkey_details(pkey, pkeybuf, sizeof(pkeybuf));

    openvpn_snprintf(buf, buflen, ", peer temporary key: %s",
                     pkeybuf);

    EVP_PKEY_free(pkey);
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
    const SSL_CIPHER *ciph;
    char s1[256];
    char s2[256];
    char s3[256];

    s1[0] = s2[0] = s3[0] = 0;
    ciph = SSL_get_current_cipher(ks_ssl->ssl);
    openvpn_snprintf(s1, sizeof(s1), "%s %s, cipher %s %s",
                     prefix,
                     SSL_get_version(ks_ssl->ssl),
                     SSL_CIPHER_get_version(ciph),
                     SSL_CIPHER_get_name(ciph));
    X509 *cert = SSL_get_peer_certificate(ks_ssl->ssl);

    if (cert)
    {
        print_cert_details(cert, s2, sizeof(s2));
        X509_free(cert);
    }
    print_server_tempkey(ks_ssl->ssl, s3, sizeof(s3));

    msg(D_HANDSHAKE, "%s%s%s", s1, s2, s3);
}

void
show_available_tls_ciphers_list(const char *cipher_list,
                                const char *tls_cert_profile,
                                bool tls13)
{
    struct tls_root_ctx tls_ctx;

    tls_ctx.ctx = SSL_CTX_new(SSLv23_method());
    if (!tls_ctx.ctx)
    {
        crypto_msg(M_FATAL, "Cannot create SSL_CTX object");
    }

#if defined(TLS1_3_VERSION)
    if (tls13)
    {
        SSL_CTX_set_min_proto_version(tls_ctx.ctx,
                                      openssl_tls_version(TLS_VER_1_3));
        tls_ctx_restrict_ciphers_tls13(&tls_ctx, cipher_list);
    }
    else
#endif
    {
        SSL_CTX_set_max_proto_version(tls_ctx.ctx, TLS1_2_VERSION);
        tls_ctx_restrict_ciphers(&tls_ctx, cipher_list);
    }

    tls_ctx_set_cert_profile(&tls_ctx, tls_cert_profile);

    SSL *ssl = SSL_new(tls_ctx.ctx);
    if (!ssl)
    {
        crypto_msg(M_FATAL, "Cannot create SSL object");
    }

#if OPENSSL_VERSION_NUMBER < 0x1010000fL
    STACK_OF(SSL_CIPHER) *sk = SSL_get_ciphers(ssl);
#else
    STACK_OF(SSL_CIPHER) *sk = SSL_get1_supported_ciphers(ssl);
#endif
    for (int i = 0; i < sk_SSL_CIPHER_num(sk); i++)
    {
        const SSL_CIPHER *c = sk_SSL_CIPHER_value(sk, i);

        const char *cipher_name = SSL_CIPHER_get_name(c);

        const tls_cipher_name_pair *pair =
            tls_get_cipher_name_pair(cipher_name, strlen(cipher_name));

        if (tls13)
        {
            printf("%s\n", cipher_name);
        }
        else if (NULL == pair)
        {
            /* No translation found, print warning */
            printf("%s (No IANA name known to OpenVPN, use OpenSSL name.)\n",
                   cipher_name);
        }
        else
        {
            printf("%s\n", pair->iana_name);
        }
    }
#if (OPENSSL_VERSION_NUMBER >= 0x1010000fL)
    sk_SSL_CIPHER_free(sk);
#endif
    SSL_free(ssl);
    SSL_CTX_free(tls_ctx.ctx);
}

/*
 * Show the Elliptic curves that are available for us to use
 * in the OpenSSL library.
 */
void
show_available_curves(void)
{
    printf("Consider using 'openssl ecparam -list_curves' as alternative to running\n"
           "this command.\n"
           "Note this output does only list curves/groups that OpenSSL considers as\n"
           "builtin EC curves. It does not list additional curves nor X448 or X25519\n");
#ifndef OPENSSL_NO_EC
    EC_builtin_curve *curves = NULL;
    size_t crv_len = 0;
    size_t n = 0;

    crv_len = EC_get_builtin_curves(NULL, 0);
    ALLOC_ARRAY(curves, EC_builtin_curve, crv_len);
    if (EC_get_builtin_curves(curves, crv_len))
    {
        printf("\nAvailable Elliptic curves/groups:\n");
        for (n = 0; n < crv_len; n++)
        {
            const char *sname;
            sname   = OBJ_nid2sn(curves[n].nid);
            if (sname == NULL)
            {
                sname = "";
            }

            printf("%s\n", sname);
        }
    }
    else
    {
        crypto_msg(M_FATAL, "Cannot get list of builtin curves");
    }
    free(curves);
#else  /* ifndef OPENSSL_NO_EC */
    msg(M_WARN, "Your OpenSSL library was built without elliptic curve support. "
        "No curves available.");
#endif /* ifndef OPENSSL_NO_EC */
}

void
get_highest_preference_tls_cipher(char *buf, int size)
{
    SSL_CTX *ctx;
    SSL *ssl;
    const char *cipher_name;

    ctx = SSL_CTX_new(SSLv23_method());
    if (!ctx)
    {
        crypto_msg(M_FATAL, "Cannot create SSL_CTX object");
    }
    ssl = SSL_new(ctx);
    if (!ssl)
    {
        crypto_msg(M_FATAL, "Cannot create SSL object");
    }

    cipher_name = SSL_get_cipher_list(ssl, 0);
    strncpynt(buf, cipher_name, size);

    SSL_free(ssl);
    SSL_CTX_free(ctx);
}

const char *
get_ssl_library_version(void)
{
    return OpenSSL_version(OPENSSL_VERSION);
}


/** Some helper routines for provider load/unload */
#ifdef HAVE_XKEY_PROVIDER
static int
provider_load(OSSL_PROVIDER *prov, void *dest_libctx)
{
    const char *name = OSSL_PROVIDER_get0_name(prov);
    OSSL_PROVIDER_load(dest_libctx, name);
    return 1;
}

static int
provider_unload(OSSL_PROVIDER *prov, void *unused)
{
    (void) unused;
    OSSL_PROVIDER_unload(prov);
    return 1;
}
#endif /* HAVE_XKEY_PROVIDER */

/**
 * Setup ovpn.xey provider for signing with external keys.
 * It is loaded into a custom library context so as not to pollute
 * the default context. Alternatively we could override any
 * system-wide property query set on the default context. But we
 * want to avoid that.
 */
void
load_xkey_provider(void)
{
#ifdef HAVE_XKEY_PROVIDER

    /* Make a new library context for use in TLS context */
    if (!tls_libctx)
    {
        tls_libctx = OSSL_LIB_CTX_new();
        check_malloc_return(tls_libctx);

        /* Load all providers in default LIBCTX into this libctx.
         * OpenSSL has a child libctx functionality to automate this,
         * but currently that is usable only from within providers.
         * So we do something close to it manually here.
         */
        OSSL_PROVIDER_do_all(NULL, provider_load, tls_libctx);
    }

    if (!OSSL_PROVIDER_available(tls_libctx, "ovpn.xkey"))
    {
        OSSL_PROVIDER_add_builtin(tls_libctx, "ovpn.xkey", xkey_provider_init);
        if (!OSSL_PROVIDER_load(tls_libctx, "ovpn.xkey"))
        {
            msg(M_NONFATAL, "ERROR: failed loading external key provider: "
                "Signing with external keys will not work.");
        }
    }

    /* We only implement minimal functionality in ovpn.xkey, so we do not want
     * methods in xkey to be picked unless absolutely required (i.e, when the key
     * is external). Ensure this by setting a default propquery for the custom
     * libctx that unprefers, but does not forbid, ovpn.xkey. See also man page
     * of "property" in OpenSSL 3.0.
     */
    EVP_set_default_properties(tls_libctx, "?provider!=ovpn.xkey");

#endif /* HAVE_XKEY_PROVIDER */
}

/**
 * Undo steps in load_xkey_provider
 */
static void
unload_xkey_provider(void)
{
#ifdef HAVE_XKEY_PROVIDER
    if (tls_libctx)
    {
        OSSL_PROVIDER_do_all(tls_libctx, provider_unload, NULL);
        OSSL_LIB_CTX_free(tls_libctx);
    }
#endif /* HAVE_XKEY_PROVIDER */
    tls_libctx = NULL;
}

#endif /* defined(ENABLE_CRYPTO_OPENSSL) */
