/*
 *  OpenVPN -- An application to securely tunnel IP networks
 *             over a single TCP/UDP port, with support for SSL/TLS-based
 *             session authentication and key exchange,
 *             packet encryption, packet authentication, and
 *             packet compression.
 *
 *  Copyright (C) 2002-2017 OpenVPN Technologies, Inc. <sales@openvpn.net>
 *  Copyright (C) 2010-2017 Fox Crypto B.V. <openvpn@fox-it.com>
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
#elif defined(_MSC_VER)
#include "config-msvc.h"
#endif

#include "syshead.h"

#if defined(ENABLE_CRYPTO) && defined(ENABLE_CRYPTO_OPENSSL)

#include "errlevel.h"
#include "buffer.h"
#include "misc.h"
#include "manage.h"
#include "memdbg.h"
#include "ssl_backend.h"
#include "ssl_common.h"
#include "base64.h"
#include "openssl_compat.h"

#ifdef ENABLE_CRYPTOAPI
#include "cryptoapi.h"
#endif

#include "ssl_verify_openssl.h"

#include <openssl/err.h>
#include <openssl/pkcs12.h>
#include <openssl/x509.h>
#include <openssl/crypto.h>
#ifndef OPENSSL_NO_EC
#include <openssl/ec.h>
#endif

/*
 * Allocate space in SSL objects in which to store a struct tls_session
 * pointer back to parent.
 *
 */

int mydata_index; /* GLOBAL */

void
tls_init_lib(void)
{
    SSL_library_init();
#ifndef ENABLE_SMALL
    SSL_load_error_strings();
#endif
    OpenSSL_add_all_algorithms();

    mydata_index = SSL_get_ex_new_index(0, "struct session *", NULL, NULL, NULL);
    ASSERT(mydata_index >= 0);
}

void
tls_free_lib(void)
{
    EVP_cleanup();
#ifndef ENABLE_SMALL
    ERR_free_strings();
#endif
}

void
tls_clear_error(void)
{
    ERR_clear_error();
}

void
tls_ctx_server_new(struct tls_root_ctx *ctx)
{
    ASSERT(NULL != ctx);

    ctx->ctx = SSL_CTX_new(SSLv23_server_method());

    if (ctx->ctx == NULL)
    {
        crypto_msg(M_FATAL, "SSL_CTX_new SSLv23_server_method");
    }
}

void
tls_ctx_client_new(struct tls_root_ctx *ctx)
{
    ASSERT(NULL != ctx);

    ctx->ctx = SSL_CTX_new(SSLv23_client_method());

    if (ctx->ctx == NULL)
    {
        crypto_msg(M_FATAL, "SSL_CTX_new SSLv23_client_method");
    }
}

void
tls_ctx_free(struct tls_root_ctx *ctx)
{
    ASSERT(NULL != ctx);
    if (NULL != ctx->ctx)
    {
        SSL_CTX_free(ctx->ctx);
    }
    ctx->ctx = NULL;
}

bool
tls_ctx_initialised(struct tls_root_ctx *ctx)
{
    ASSERT(NULL != ctx);
    return NULL != ctx->ctx;
}

void
key_state_export_keying_material(struct key_state_ssl *ssl,
                                 struct tls_session *session)
{
    if (session->opt->ekm_size > 0)
    {
#if (OPENSSL_VERSION_NUMBER >= 0x10001000)
        unsigned int size = session->opt->ekm_size;
        struct gc_arena gc = gc_new();
        unsigned char *ekm = (unsigned char *) gc_malloc(size, true, &gc);

        if (SSL_export_keying_material(ssl->ssl, ekm, size,
                                       session->opt->ekm_label, session->opt->ekm_label_size, NULL, 0, 0))
        {
            unsigned int len = (size * 2) + 2;

            const char *key = format_hex_ex(ekm, size, len, 0, NULL, &gc);
            setenv_str(session->opt->es, "exported_keying_material", key);

            dmsg(D_TLS_DEBUG_MED, "%s: exported keying material: %s",
                 __func__, key);
        }
        else
        {
            msg(M_WARN, "WARNING: Export keying material failed!");
            setenv_del(session->opt->es, "exported_keying_material");
        }
        gc_free(&gc);
#endif /* if (OPENSSL_VERSION_NUMBER >= 0x10001000) */
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
#if defined(SSL_OP_NO_TLSv1_2)
    return TLS_VER_1_2;
#elif defined(SSL_OP_NO_TLSv1_1)
    return TLS_VER_1_1;
#else
    return TLS_VER_1_0;
#endif
}

void
tls_ctx_set_options(struct tls_root_ctx *ctx, unsigned int ssl_flags)
{
    ASSERT(NULL != ctx);

    /* default certificate verification flags */
    int flags = SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT;

    /* process SSL options including minimum TLS version we will accept from peer */
    {
        long sslopt = SSL_OP_SINGLE_DH_USE | SSL_OP_NO_TICKET | SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3;
        int tls_ver_max = TLS_VER_UNSPEC;
        const int tls_ver_min =
            (ssl_flags >> SSLF_TLS_VERSION_MIN_SHIFT) & SSLF_TLS_VERSION_MIN_MASK;

        tls_ver_max =
            (ssl_flags >> SSLF_TLS_VERSION_MAX_SHIFT) & SSLF_TLS_VERSION_MAX_MASK;
        if (tls_ver_max <= TLS_VER_UNSPEC)
        {
            tls_ver_max = tls_version_max();
        }

        if (tls_ver_min > TLS_VER_1_0 || tls_ver_max < TLS_VER_1_0)
        {
            sslopt |= SSL_OP_NO_TLSv1;
        }
#ifdef SSL_OP_NO_TLSv1_1
        if (tls_ver_min > TLS_VER_1_1 || tls_ver_max < TLS_VER_1_1)
        {
            sslopt |= SSL_OP_NO_TLSv1_1;
        }
#endif
#ifdef SSL_OP_NO_TLSv1_2
        if (tls_ver_min > TLS_VER_1_2 || tls_ver_max < TLS_VER_1_2)
        {
            sslopt |= SSL_OP_NO_TLSv1_2;
        }
#endif
        sslopt |= SSL_OP_NO_COMPRESSION;
        SSL_CTX_set_options(ctx->ctx, sslopt);
    }

#ifdef SSL_MODE_RELEASE_BUFFERS
    SSL_CTX_set_mode(ctx->ctx, SSL_MODE_RELEASE_BUFFERS);
#endif
    SSL_CTX_set_session_cache_mode(ctx->ctx, SSL_SESS_CACHE_OFF);
    SSL_CTX_set_default_passwd_cb(ctx->ctx, pem_password_callback);

    /* Require peer certificate verification */
#if P2MP_SERVER
    if (ssl_flags & SSLF_CLIENT_CERT_NOT_REQUIRED)
    {
        flags = 0;
    }
    else if (ssl_flags & SSLF_CLIENT_CERT_OPTIONAL)
    {
        flags = SSL_VERIFY_PEER;
    }
#endif
    SSL_CTX_set_verify(ctx->ctx, flags, verify_callback);

    SSL_CTX_set_info_callback(ctx->ctx, info_callback);
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

    /* Parse supplied cipher list and pass on to OpenSSL */
    size_t begin_of_cipher, end_of_cipher;

    const char *current_cipher;
    size_t current_cipher_len;

    const tls_cipher_name_pair *cipher_pair;

    char openssl_ciphers[4096];
    size_t openssl_ciphers_len = 0;
    openssl_ciphers[0] = '\0';

    ASSERT(NULL != ctx);

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
            || ((sizeof(openssl_ciphers)-1) < openssl_ciphers_len + current_cipher_len))
        {
            msg(M_FATAL,
                "Failed to set restricted TLS cipher list, too long (>%d).",
                (int)sizeof(openssl_ciphers)-1);
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

    /* Set OpenSSL cipher list */
    if (!SSL_CTX_set_cipher_list(ctx->ctx, openssl_ciphers))
    {
        crypto_msg(M_FATAL, "Failed to set restricted TLS cipher list: %s", openssl_ciphers);
    }
}

void
tls_ctx_check_cert_time(const struct tls_root_ctx *ctx)
{
    int ret;
    const X509 *cert;

    ASSERT(ctx);

#if OPENSSL_VERSION_NUMBER >= 0x10002000L && !defined(LIBRESSL_VERSION_NUMBER)
    /* OpenSSL 1.0.2 and up */
    cert = SSL_CTX_get0_certificate(ctx->ctx);
#else
    /* OpenSSL 1.0.1 and earlier need an SSL object to get at the certificate */
    SSL *ssl = SSL_new(ctx->ctx);
    cert = SSL_get_certificate(ssl);
#endif

    if (cert == NULL)
    {
        goto cleanup; /* Nothing to check if there is no certificate */
    }

    ret = X509_cmp_time(X509_get_notBefore(cert), NULL);
    if (ret == 0)
    {
        msg(D_TLS_DEBUG_MED, "Failed to read certificate notBefore field.");
    }
    if (ret > 0)
    {
        msg(M_WARN, "WARNING: Your certificate is not yet valid!");
    }

    ret = X509_cmp_time(X509_get_notAfter(cert), NULL);
    if (ret == 0)
    {
        msg(D_TLS_DEBUG_MED, "Failed to read certificate notAfter field.");
    }
    if (ret < 0)
    {
        msg(M_WARN, "WARNING: Your certificate has expired!");
    }

cleanup:
#if OPENSSL_VERSION_NUMBER < 0x10002000L || defined(LIBRESSL_VERSION_NUMBER)
    SSL_free(ssl);
#endif
    return;
}

void
tls_ctx_load_dh_params(struct tls_root_ctx *ctx, const char *dh_file,
                       const char *dh_file_inline
                       )
{
    DH *dh;
    BIO *bio;

    ASSERT(NULL != ctx);

    if (!strcmp(dh_file, INLINE_FILE_TAG) && dh_file_inline)
    {
        if (!(bio = BIO_new_mem_buf((char *)dh_file_inline, -1)))
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

    dh = PEM_read_bio_DHparams(bio, NULL, NULL, NULL);
    BIO_free(bio);

    if (!dh)
    {
        crypto_msg(M_FATAL, "Cannot load DH parameters from %s", dh_file);
    }
    if (!SSL_CTX_set_tmp_dh(ctx->ctx, dh))
    {
        crypto_msg(M_FATAL, "SSL_CTX_set_tmp_dh");
    }

    msg(D_TLS_DEBUG_LOW, "Diffie-Hellman initialized with %d bit key",
        8 * DH_size(dh));

    DH_free(dh);
}

void
tls_ctx_load_ecdh_params(struct tls_root_ctx *ctx, const char *curve_name
                         )
{
#ifndef OPENSSL_NO_EC
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
#if OPENSSL_VERSION_NUMBER >= 0x10002000L
        /* OpenSSL 1.0.2 and newer can automatically handle ECDH parameter
         * loading */
        SSL_CTX_set_ecdh_auto(ctx->ctx, 1);
        return;
#else
        /* For older OpenSSL we have to extract the curve from key on our own */
        EC_KEY *eckey = NULL;
        const EC_GROUP *ecgrp = NULL;
        EVP_PKEY *pkey = NULL;

        /* Little hack to get private key ref from SSL_CTX, yay OpenSSL... */
        SSL *ssl = SSL_new(ctx->ctx);
        if (!ssl)
        {
            crypto_msg(M_FATAL, "SSL_new failed");
        }
        pkey = SSL_get_privatekey(ssl);
        SSL_free(ssl);

        msg(D_TLS_DEBUG, "Extracting ECDH curve from private key");

        if (pkey != NULL && (eckey = EVP_PKEY_get1_EC_KEY(pkey)) != NULL
            && (ecgrp = EC_KEY_get0_group(eckey)) != NULL)
        {
            nid = EC_GROUP_get_curve_name(ecgrp);
        }
#endif
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
    msg(M_DEBUG, "Your OpenSSL library was built without elliptic curve support."
        " Skipping ECDH parameter loading.");
#endif /* OPENSSL_NO_EC */
}

int
tls_ctx_load_pkcs12(struct tls_root_ctx *ctx, const char *pkcs12_file,
                    const char *pkcs12_file_inline,
                    bool load_ca_file
                    )
{
    FILE *fp;
    EVP_PKEY *pkey;
    X509 *cert;
    STACK_OF(X509) *ca = NULL;
    PKCS12 *p12;
    int i;
    char password[256];

    ASSERT(NULL != ctx);

    if (!strcmp(pkcs12_file, INLINE_FILE_TAG) && pkcs12_file_inline)
    {
        BIO *b64 = BIO_new(BIO_f_base64());
        BIO *bio = BIO_new_mem_buf((void *) pkcs12_file_inline,
                                   (int) strlen(pkcs12_file_inline));
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
        platform_fclose(fp);
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
                if (!X509_STORE_add_cert(cert_store,sk_X509_value(ca, i)))
                {
                    crypto_msg(M_FATAL,"Cannot add certificate to certificate chain (X509_STORE_add_cert)");
                }
                if (!SSL_CTX_add_client_CA(ctx->ctx, sk_X509_value(ca, i)))
                {
                    crypto_msg(M_FATAL,"Cannot add certificate to client CA list (SSL_CTX_add_client_CA)");
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
                if (!SSL_CTX_add_extra_chain_cert(ctx->ctx,sk_X509_value(ca, i)))
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
tls_ctx_add_extra_certs(struct tls_root_ctx *ctx, BIO *bio)
{
    X509 *cert;
    for (;; )
    {
        cert = NULL;
        if (!PEM_read_bio_X509(bio, &cert, NULL, NULL)) /* takes ownership of cert */
        {
            break;
        }
        if (!cert)
        {
            crypto_msg(M_FATAL, "Error reading extra certificate");
        }
        if (SSL_CTX_add_extra_chain_cert(ctx->ctx, cert) != 1)
        {
            crypto_msg(M_FATAL, "Error adding extra certificate");
        }
    }
}

/* Like tls_ctx_load_cert, but returns a copy of the certificate in **X509 */
static void
tls_ctx_load_cert_file_and_copy(struct tls_root_ctx *ctx,
                                const char *cert_file, const char *cert_file_inline, X509 **x509
                                )
{
    BIO *in = NULL;
    X509 *x = NULL;
    int ret = 0;
    bool inline_file = false;

    ASSERT(NULL != ctx);
    if (NULL != x509)
    {
        ASSERT(NULL == *x509);
    }

    inline_file = (strcmp(cert_file, INLINE_FILE_TAG) == 0);

    if (inline_file && cert_file_inline)
    {
        in = BIO_new_mem_buf((char *)cert_file_inline, -1);
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
        tls_ctx_add_extra_certs(ctx, in);
    }

end:
    if (!ret)
    {
        if (inline_file)
        {
            crypto_msg(M_FATAL, "Cannot load inline certificate file");
        }
        else
        {
            crypto_msg(M_FATAL, "Cannot load certificate file %s", cert_file);
        }
    }

    if (in != NULL)
    {
        BIO_free(in);
    }
    if (x509)
    {
        *x509 = x;
    }
    else if (x)
    {
        X509_free(x);
    }
}

void
tls_ctx_load_cert_file(struct tls_root_ctx *ctx, const char *cert_file,
                       const char *cert_file_inline)
{
    tls_ctx_load_cert_file_and_copy(ctx, cert_file, cert_file_inline, NULL);
}

int
tls_ctx_load_priv_file(struct tls_root_ctx *ctx, const char *priv_key_file,
                       const char *priv_key_file_inline
                       )
{
    SSL_CTX *ssl_ctx = NULL;
    BIO *in = NULL;
    EVP_PKEY *pkey = NULL;
    int ret = 1;

    ASSERT(NULL != ctx);

    ssl_ctx = ctx->ctx;

    if (!strcmp(priv_key_file, INLINE_FILE_TAG) && priv_key_file_inline)
    {
        in = BIO_new_mem_buf((char *)priv_key_file_inline, -1);
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
    if (!pkey)
    {
        goto end;
    }

    if (!SSL_CTX_use_PrivateKey(ssl_ctx, pkey))
    {
#ifdef ENABLE_MANAGEMENT
        if (management && (ERR_GET_REASON(ERR_peek_error()) == EVP_R_BAD_DECRYPT))
        {
            management_auth_failure(management, UP_TYPE_PRIVATE_KEY, NULL);
        }
#endif
        crypto_msg(M_WARN, "Cannot load private key file %s", priv_key_file);
        goto end;
    }

    /* Check Private Key */
    if (!SSL_CTX_check_private_key(ssl_ctx))
    {
        crypto_msg(M_FATAL, "Private key does not match the certificate");
    }
    ret = 0;

end:
    if (pkey)
    {
        EVP_PKEY_free(pkey);
    }
    if (in)
    {
        BIO_free(in);
    }
    return ret;
}

void
backend_tls_ctx_reload_crl(struct tls_root_ctx *ssl_ctx, const char *crl_file,
                           const char *crl_inline)
{
    X509_CRL *crl = NULL;
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

    if (!strcmp(crl_file, INLINE_FILE_TAG) && crl_inline)
    {
        in = BIO_new_mem_buf((char *)crl_inline, -1);
    }
    else
    {
        in = BIO_new_file(crl_file, "r");
    }

    if (in == NULL)
    {
        msg(M_WARN, "CRL: cannot read: %s", crl_file);
        goto end;
    }

    crl = PEM_read_bio_X509_CRL(in, NULL, NULL, NULL);
    if (crl == NULL)
    {
        msg(M_WARN, "CRL: cannot read CRL from file %s", crl_file);
        goto end;
    }

    if (!X509_STORE_add_crl(store, crl))
    {
        msg(M_WARN, "CRL: cannot add %s to store", crl_file);
        goto end;
    }

end:
    X509_CRL_free(crl);
    BIO_free(in);
}


#ifdef MANAGMENT_EXTERNAL_KEY

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
    /* meth was allocated in tls_ctx_use_external_private_key() ; since
     * this function is called when the parent RSA object is destroyed,
     * it is no longer used after this point so kill it. */
    const RSA_METHOD *meth = RSA_get_method(rsa);
    RSA_meth_free((RSA_METHOD *)meth);
    return 1;
}

/* sign arbitrary data */
static int
rsa_priv_enc(int flen, const unsigned char *from, unsigned char *to, RSA *rsa, int padding)
{
    /* optional app data in rsa->meth->app_data; */
    char *in_b64 = NULL;
    char *out_b64 = NULL;
    int ret = -1;
    int len;

    if (padding != RSA_PKCS1_PADDING)
    {
        RSAerr(RSA_F_RSA_OSSL_PRIVATE_ENCRYPT, RSA_R_UNKNOWN_PADDING_TYPE);
        goto done;
    }

    /* convert 'from' to base64 */
    if (openvpn_base64_encode(from, flen, &in_b64) <= 0)
    {
        goto done;
    }

    /* call MI for signature */
    if (management)
    {
        out_b64 = management_query_rsa_sig(management, in_b64);
    }
    if (!out_b64)
    {
        goto done;
    }

    /* decode base64 signature to binary */
    len = RSA_size(rsa);
    ret = openvpn_base64_decode(out_b64, to, len);

    /* verify length */
    if (ret != len)
    {
        ret = -1;
    }

done:
    if (in_b64)
    {
        free(in_b64);
    }
    if (out_b64)
    {
        free(out_b64);
    }
    return ret;
}

int
tls_ctx_use_external_private_key(struct tls_root_ctx *ctx,
                                 const char *cert_file, const char *cert_file_inline)
{
    RSA *rsa = NULL;
    RSA *pub_rsa;
    RSA_METHOD *rsa_meth;
    X509 *cert = NULL;

    ASSERT(NULL != ctx);

    tls_ctx_load_cert_file_and_copy(ctx, cert_file, cert_file_inline, &cert);

    ASSERT(NULL != cert);

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

    /* get the public key */
    EVP_PKEY *pkey = X509_get0_pubkey(cert);
    ASSERT(pkey); /* NULL before SSL_CTX_use_certificate() is called */
    pub_rsa = EVP_PKEY_get0_RSA(pkey);

    /* Certificate might not be RSA but DSA or EC */
    if (!pub_rsa)
    {
        crypto_msg(M_WARN, "management-external-key requires a RSA certificate");
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
        goto err;
    }

    /* bind our custom RSA object to ssl_ctx */
    if (!SSL_CTX_use_RSAPrivateKey(ctx->ctx, rsa))
    {
        goto err;
    }

    X509_free(cert);
    RSA_free(rsa); /* doesn't necessarily free, just decrements refcount */
    return 1;

err:
    if (cert)
    {
        X509_free(cert);
    }
    if (rsa)
    {
        RSA_free(rsa);
    }
    else
    {
        if (rsa_meth)
        {
            free(rsa_meth);
        }
    }
    crypto_msg(M_FATAL, "Cannot enable SSL external private key capability");
    return 0;
}

#endif /* ifdef MANAGMENT_EXTERNAL_KEY */

static int
sk_x509_name_cmp(const X509_NAME *const *a, const X509_NAME *const *b)
{
    return X509_NAME_cmp(*a, *b);
}

void
tls_ctx_load_ca(struct tls_root_ctx *ctx, const char *ca_file,
                const char *ca_file_inline,
                const char *ca_path, bool tls_server
                )
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
        if (!strcmp(ca_file, INLINE_FILE_TAG) && ca_file_inline)
        {
            in = BIO_new_mem_buf((char *)ca_file_inline, -1);
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
                                   np(ca_file), added);
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
                       np(ca_file));
        }

        if (tls_server)
        {
            int cnum = sk_X509_NAME_num(cert_names);
            if (cnum != added)
            {
                crypto_msg(M_FATAL, "Cannot load CA certificate file %s (only %d "
                           "of %d entries were valid X509 names)",
                           np(ca_file), cnum, added);
            }
        }

        if (in)
        {
            BIO_free(in);
        }
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
                         const char *extra_certs_file_inline
                         )
{
    BIO *in;
    if (!strcmp(extra_certs_file, INLINE_FILE_TAG) && extra_certs_file_inline)
    {
        in = BIO_new_mem_buf((char *)extra_certs_file_inline, -1);
    }
    else
    {
        in = BIO_new_file(extra_certs_file, "r");
    }

    if (in == NULL)
    {
        crypto_msg(M_FATAL, "Cannot load extra-certs file: %s", extra_certs_file);
    }
    else
    {
        tls_ctx_add_extra_certs(ctx, in);
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
        ASSERT(!platform_fclose(biofp));
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
        biofp = platform_fopen(fn, "w");
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
        fprintf(biofp, "BIO_%s %s time=" time_format " bio=" ptr_format " len=%d data=%s\n",
                mode, desc, time(NULL), (ptr_type)bio, len, format_hex(buf, len, 0, &gc));
        fflush(biofp);
    }
    gc_free(&gc);
}

static void
bio_debug_oc(const char *mode, BIO *bio)
{
    open_biofp();
    fprintf(biofp, "BIO %s time=" time_format " bio=" ptr_format "\n",
            mode, time(NULL), (ptr_type)bio);
    fflush(biofp);
}

#endif /* ifdef BIO_DEBUG */

/*
 * OpenVPN's interface to SSL/TLS authentication,
 * encryption, and decryption is exclusively
 * through "memory BIOs".
 */
static BIO *
getbio(BIO_METHOD *type, const char *desc)
{
    BIO *ret;
    ret = BIO_new(type);
    if (!ret)
    {
        crypto_msg(M_FATAL, "Error creating %s BIO", desc);
    }
    return ret;
}

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
            if (BIO_should_retry(bio))
            {
            }
            else
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
bio_read(BIO *bio, struct buffer *buf, int maxlen, const char *desc)
{
    int i;
    int ret = 0;
    ASSERT(buf->len >= 0);
    if (buf->len)
    {
    }
    else
    {
        int len = buf_forward_capacity(buf);
        if (maxlen < len)
        {
            len = maxlen;
        }

        /*
         * BIO_read brackets most of the serious RSA
         * key negotiation number crunching.
         */
        i = BIO_read(bio, BPTR(buf), len);

        VALGRIND_MAKE_READABLE((void *) &i, sizeof(i));

#ifdef BIO_DEBUG
        bio_debug_data("read", bio, BPTR(buf), i, desc);
#endif
        if (i < 0)
        {
            if (BIO_should_retry(bio))
            {
            }
            else
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

    ks_ssl->ssl_bio = getbio(BIO_f_ssl(), "ssl_bio");
    ks_ssl->ct_in = getbio(BIO_s_mem(), "ct_in");
    ks_ssl->ct_out = getbio(BIO_s_mem(), "ct_out");

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

#ifdef ENABLE_CRYPTO_OPENSSL
    ASSERT(NULL != ks_ssl);

    ret = bio_write(ks_ssl->ssl_bio, BPTR(buf), BLEN(buf),
                    "tls_write_plaintext");
    bio_write_post(ret, buf);
#endif /* ENABLE_CRYPTO_OPENSSL */

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
key_state_read_ciphertext(struct key_state_ssl *ks_ssl, struct buffer *buf,
                          int maxlen)
{
    int ret = 0;
    perf_push(PERF_BIO_READ_CIPHERTEXT);

    ASSERT(NULL != ks_ssl);

    ret = bio_read(ks_ssl->ct_out, buf, maxlen, "tls_read_ciphertext");

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
key_state_read_plaintext(struct key_state_ssl *ks_ssl, struct buffer *buf,
                         int maxlen)
{
    int ret = 0;
    perf_push(PERF_BIO_READ_PLAINTEXT);

    ASSERT(NULL != ks_ssl);

    ret = bio_read(ks_ssl->ssl_bio, buf, maxlen, "tls_read_plaintext");

    perf_pop();
    return ret;
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
    X509 *cert;
    char s1[256];
    char s2[256];

    s1[0] = s2[0] = 0;
    ciph = SSL_get_current_cipher(ks_ssl->ssl);
    openvpn_snprintf(s1, sizeof(s1), "%s %s, cipher %s %s",
                     prefix,
                     SSL_get_version(ks_ssl->ssl),
                     SSL_CIPHER_get_version(ciph),
                     SSL_CIPHER_get_name(ciph));
    cert = SSL_get_peer_certificate(ks_ssl->ssl);
    if (cert != NULL)
    {
        EVP_PKEY *pkey = X509_get_pubkey(cert);
        if (pkey != NULL)
        {
            if ((EVP_PKEY_id(pkey) == EVP_PKEY_RSA) && (EVP_PKEY_get0_RSA(pkey) != NULL))
            {
                RSA *rsa = EVP_PKEY_get0_RSA(pkey);
                openvpn_snprintf(s2, sizeof(s2), ", %d bit RSA",
                                 RSA_bits(rsa));
            }
            else if ((EVP_PKEY_id(pkey) == EVP_PKEY_DSA) && (EVP_PKEY_get0_DSA(pkey) != NULL))
            {
                DSA *dsa = EVP_PKEY_get0_DSA(pkey);
                openvpn_snprintf(s2, sizeof(s2), ", %d bit DSA",
                                 DSA_bits(dsa));
            }
#ifndef OPENSSL_NO_EC
            else if ((EVP_PKEY_id(pkey) == EVP_PKEY_EC) && (EVP_PKEY_get0_EC_KEY(pkey) != NULL))
            {
                EC_KEY *ec = EVP_PKEY_get0_EC_KEY(pkey);
                const EC_GROUP *group = EC_KEY_get0_group(ec);
                const char* curve;

                int nid = EC_GROUP_get_curve_name(group);
                if (nid == 0 || (curve = OBJ_nid2sn(nid)) == NULL)
                {
                    curve = "Error getting curve name";
                }

                openvpn_snprintf(s2, sizeof(s2), ", %d bit EC, curve: %s",
                                 EC_GROUP_order_bits(group), curve);

            }
#endif
            EVP_PKEY_free(pkey);
        }
        X509_free(cert);
    }
    /* The SSL API does not allow us to look at temporary RSA/DH keys,
     * otherwise we should print their lengths too */
    msg(D_HANDSHAKE, "%s%s", s1, s2);
}

void
show_available_tls_ciphers(const char *cipher_list)
{
    struct tls_root_ctx tls_ctx;
    SSL *ssl;
    const char *cipher_name;
    const tls_cipher_name_pair *pair;
    int priority = 0;

    tls_ctx.ctx = SSL_CTX_new(SSLv23_method());
    if (!tls_ctx.ctx)
    {
        crypto_msg(M_FATAL, "Cannot create SSL_CTX object");
    }

    ssl = SSL_new(tls_ctx.ctx);
    if (!ssl)
    {
        crypto_msg(M_FATAL, "Cannot create SSL object");
    }

    tls_ctx_restrict_ciphers(&tls_ctx, cipher_list);

    printf("Available TLS Ciphers,\n");
    printf("listed in order of preference:\n\n");
    while ((cipher_name = SSL_get_cipher_list(ssl, priority++)))
    {
        pair = tls_get_cipher_name_pair(cipher_name, strlen(cipher_name));

        if (NULL == pair)
        {
            /* No translation found, print warning */
            printf("%s (No IANA name known to OpenVPN, use OpenSSL name.)\n", cipher_name);
        }
        else
        {
            printf("%s\n", pair->iana_name);
        }

    }
    printf("\n" SHOW_TLS_CIPHER_LIST_WARNING);

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
#ifndef OPENSSL_NO_EC
    EC_builtin_curve *curves = NULL;
    size_t crv_len = 0;
    size_t n = 0;

    crv_len = EC_get_builtin_curves(NULL, 0);
    ALLOC_ARRAY(curves, EC_builtin_curve, crv_len);
    if (EC_get_builtin_curves(curves, crv_len))
    {
        printf("Available Elliptic curves:\n");
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
    return SSLeay_version(SSLEAY_VERSION);
}

#endif /* defined(ENABLE_CRYPTO) && defined(ENABLE_CRYPTO_OPENSSL) */
