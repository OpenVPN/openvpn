/*
 *  OpenVPN -- An application to securely tunnel IP networks
 *             over a single UDP port, with support for SSL/TLS-based
 *             session authentication and key exchange,
 *             packet encryption, packet authentication, and
 *             packet compression.
 *
 *  Copyright (C) 2023 Selva Nair <selva.nair@gmail.com>
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by the
 *  Free Software Foundation, either version 2 of the License,
 *  or (at your option) any later version.
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
#include "manage.h"
#include "integer.h"
#include "xkey_common.h"
#include "cert_data.h"

#if defined(HAVE_XKEY_PROVIDER) && defined (ENABLE_CRYPTOAPI)
#include <setjmp.h>
#include <cmocka.h>
#include <openssl/bio.h>
#include <openssl/pem.h>
#include <openssl/core_names.h>
#include <openssl/evp.h>
#include <openssl/pkcs12.h>

#include <cryptoapi.h>
#include <cryptoapi.c> /* pull-in the whole file to test static functions */

struct management *management; /* global */
static OSSL_PROVIDER *prov[2];

/* mock a management function that xkey_provider needs */
char *
management_query_pk_sig(struct management *man, const char *b64_data,
                        const char *algorithm)
{
    (void) man;
    (void) b64_data;
    (void) algorithm;
    return NULL;
}

/* replacement for crypto_print_openssl_errors() */
void
crypto_print_openssl_errors(const unsigned int flags)
{
    unsigned long e;
    while ((e = ERR_get_error()))
    {
        msg(flags, "OpenSSL error %lu: %s\n", e, ERR_error_string(e, NULL));
    }
}

/* tls_libctx is defined in ssl_openssl.c which we do not want to compile in */
OSSL_LIB_CTX *tls_libctx;

#ifndef _countof
#define _countof(x) sizeof((x))/sizeof(*(x))
#endif

/* A message for signing */
static const char *test_msg = "Lorem ipsum dolor sit amet, consectetur "
                              "adipisici elit, sed eiusmod tempor incidunt "
                              "ut labore et dolore magna aliqua.";

/* test data */
static const uint8_t test_hash[] = {
    0x77, 0x38, 0x65, 0x00, 0x1e, 0x96, 0x48, 0xc6, 0x57, 0x0b, 0xae,
    0xc0, 0xb7, 0x96, 0xf9, 0x66, 0x4d, 0x5f, 0xd0, 0xb7
};

/* valid test strings to test with and without embedded and trailing spaces */
static const char *valid_str[] = {
    "773865001e9648c6570baec0b796f9664d5fd0b7",
    " 77 386500 1e 96 48 c6570b aec0b7   96f9664d5f  d0 b7",
    "   773865001e9648c6570baec0b796f9664d5fd0b7  ",
};

/* some invalid strings to test */
static const char *invalid_str[] = {
    "773 865001e9648c6570baec0b796f9664d5fd0b7",  /* space within byte */
    "77:38:65001e9648c6570baec0b796f9664d5fd0b7", /* invalid separator */
    "7738x5001e9648c6570baec0b796f9664d5fd0b7",   /* non hex character */
};

/* Test certificate database: data for cert1, cert2 .. key1, key2 etc.
 * are stashed away in cert_data.h
 */
static struct test_cert
{
    const char *const cert;             /* certificate as PEM */
    const char *const key;              /* key as unencrypted PEM */
    const char *const cname;            /* common-name */
    const char *const issuer;           /* issuer common-name */
    const char *const friendly_name;    /* identifies certs loaded to the store -- keep unique */
    const char *hash;                   /* SHA1 fingerprint */
    int valid;                          /* nonzero if certificate has not expired */
} certs[5];

static bool certs_loaded;
static HCERTSTORE user_store;

/* Fill-in certs[] array */
void
init_cert_data()
{
    struct test_cert certs_local[] = {
        {cert1,  key1,  cname1,  "OVPN TEST CA1",  "OVPN Test Cert 1",  hash1,  1},
        {cert2,  key2,  cname2,  "OVPN TEST CA2",  "OVPN Test Cert 2",  hash2,  1},
        {cert3,  key3,  cname3,  "OVPN TEST CA1",  "OVPN Test Cert 3",  hash3,  1},
        {cert4,  key4,  cname4,  "OVPN TEST CA2",  "OVPN Test Cert 4",  hash4,  0},
        {0}
    };
    assert(sizeof(certs_local) == sizeof(certs));
    memcpy(certs, certs_local, sizeof(certs_local));
}

/* Lookup a certificate in our certificate/key db */
static struct test_cert *
lookup_cert(const char *friendly_name)
{
    struct test_cert *c = certs;
    while (c->cert && strcmp(c->friendly_name, friendly_name))
    {
        c++;
    }
    return c->cert ? c : NULL;
}

/* import sample certificates into windows cert store */
static void
import_certs(void **state)
{
    (void) state;
    if (certs_loaded)
    {
        return;
    }
    init_cert_data();
    user_store = CertOpenStore(CERT_STORE_PROV_SYSTEM, 0, 0, CERT_SYSTEM_STORE_CURRENT_USER
                               |CERT_STORE_OPEN_EXISTING_FLAG, L"MY");
    assert_non_null(user_store);
    for (struct test_cert *c = certs; c->cert; c++)
    {
        /* Convert PEM cert & key to pkcs12 and import */
        const char *pass = "opensesame";        /* some password */
        const wchar_t *wpass = L"opensesame";   /* same as a wide string */

        X509 *x509 = NULL;
        EVP_PKEY *pkey = NULL;

        BIO *buf = BIO_new_mem_buf(c->cert, -1);
        if (buf)
        {
            x509 = PEM_read_bio_X509(buf, NULL, NULL, NULL);
        }
        BIO_free(buf);

        buf = BIO_new_mem_buf(c->key, -1);
        if (buf)
        {
            pkey = PEM_read_bio_PrivateKey(buf, NULL, NULL, NULL);
        }
        BIO_free(buf);

        if (!x509 || !pkey)
        {
            fail_msg("Failed to parse certificate/key data: <%s>", c->friendly_name);
            return;
        }

        PKCS12 *p12 = PKCS12_create(pass, c->friendly_name, pkey, x509, NULL, 0, 0, 0, 0, 0);
        X509_free(x509);
        EVP_PKEY_free(pkey);
        if (!p12)
        {
            fail_msg("Failed to convert to PKCS12: <%s>", c->friendly_name);
            return;
        }

        CRYPT_DATA_BLOB blob = {.cbData = 0, .pbData = NULL};
        int len = i2d_PKCS12(p12, &blob.pbData); /* pbData will be allocated by OpenSSL */
        if (len <= 0)
        {
            fail_msg("Failed to DER encode PKCS12: <%s>", c->friendly_name);
            return;
        }
        blob.cbData = len;

        DWORD flags = PKCS12_ALLOW_OVERWRITE_KEY|PKCS12_ALWAYS_CNG_KSP;
        HCERTSTORE tmp_store = PFXImportCertStore(&blob, wpass, flags);
        PKCS12_free(p12);
        OPENSSL_free(blob.pbData);

        assert_non_null(tmp_store);

        /* The cert and key get imported into a temp store. We have to move it to
         * user's store to accumulate all certs in one place and use them for tests.
         * It seems there is no API to directly import a p12 blob into an existing store.
         * Nothing in Windows is ever easy.
         */

        const CERT_CONTEXT *ctx = CertEnumCertificatesInStore(tmp_store, NULL);
        assert_non_null(ctx);
        bool added = CertAddCertificateContextToStore(user_store, ctx,
                                                      CERT_STORE_ADD_REPLACE_EXISTING, NULL);
        assert_true(added);

        CertFreeCertificateContext(ctx);
        CertCloseStore(tmp_store, 0);
    }
    certs_loaded = true;
}

static int
cleanup(void **state)
{
    (void) state;
    struct gc_arena gc = gc_new();
    if (user_store) /* delete all certs we imported */
    {
        const CERT_CONTEXT *ctx = NULL;
        while ((ctx = CertEnumCertificatesInStore(user_store, ctx)))
        {
            char *friendly_name = get_cert_name(ctx, &gc);
            if (!lookup_cert(friendly_name)) /* not our cert */
            {
                continue;
            }

            /* create a dup context to not destroy the state of loop iterator */
            const CERT_CONTEXT *ctx_dup = CertDuplicateCertificateContext(ctx);
            if (ctx_dup)
            {
                CertDeleteCertificateFromStore(ctx_dup);
                /* the above also releases ctx_dup */
            }
        }
        CertCloseStore(user_store, 0);
    }
    user_store = NULL;
    certs_loaded = false;
    gc_free(&gc);
    return 0;
}

static void
test_find_cert_bythumb(void **state)
{
    (void) state;
    char select_string[64];
    struct gc_arena gc = gc_new();
    const CERT_CONTEXT *ctx;

    import_certs(state); /* a no-op if already imported */
    assert_non_null(user_store);

    for (struct test_cert *c = certs; c->cert; c++)
    {
        openvpn_snprintf(select_string, sizeof(select_string), "THUMB:%s", c->hash);
        ctx = find_certificate_in_store(select_string, user_store);
        if (ctx)
        {
            /* check we got the right certificate and is valid */
            assert_int_equal(c->valid, 1);
            char *friendly_name = get_cert_name(ctx, &gc);
            assert_string_equal(c->friendly_name, friendly_name);
            CertFreeCertificateContext(ctx);
        }
        else
        {
            /* find should fail only if the certificate has expired */
            assert_int_equal(c->valid, 0);
        }
    }

    gc_free(&gc);
}

static void
test_find_cert_byname(void **state)
{
    (void) state;
    char select_string[64];
    struct gc_arena gc = gc_new();
    const CERT_CONTEXT *ctx;

    import_certs(state); /* a no-op if already imported */
    assert_non_null(user_store);

    for (struct test_cert *c = certs; c->cert; c++)
    {
        openvpn_snprintf(select_string, sizeof(select_string), "SUBJ:%s", c->cname);
        ctx = find_certificate_in_store(select_string, user_store);
        /* In this case we expect a successful return as there is at least one valid
         * cert that matches the common name. But the returned cert may not exactly match
         * c->cert as multiple certs with same common names exist in the db. We check that
         * the return cert is one from our db, has a matching common name and is valid.
         */
        assert_non_null(ctx);

        char *friendly_name = get_cert_name(ctx, &gc);
        struct test_cert *found = lookup_cert(friendly_name);
        assert_non_null(found);
        assert_string_equal(found->cname, c->cname);
        assert_int_equal(found->valid, 1);
        CertFreeCertificateContext(ctx);
    }

    gc_free(&gc);
}

static void
test_find_cert_byissuer(void **state)
{
    (void) state;
    char select_string[64];
    struct gc_arena gc = gc_new();
    const CERT_CONTEXT *ctx;

    import_certs(state); /* a no-op if already imported */
    assert_non_null(user_store);

    for (struct test_cert *c = certs; c->cert; c++)
    {
        openvpn_snprintf(select_string, sizeof(select_string), "ISSUER:%s", c->issuer);
        ctx = find_certificate_in_store(select_string, user_store);
        /* In this case we expect a successful return as there is at least one valid
         * cert that matches the issuer. But the returned cert may not exactly match
         * c->cert as multiple certs with same issuer exist in the db. We check that
         * the returned cert is one from our db, has a matching issuer name and is valid.
         */
        assert_non_null(ctx);

        char *friendly_name = get_cert_name(ctx, &gc);
        struct test_cert *found = lookup_cert(friendly_name);
        assert_non_null(found);
        assert_string_equal(found->issuer, c->issuer);
        assert_int_equal(found->valid, 1);
        CertFreeCertificateContext(ctx);
    }

    gc_free(&gc);
}

static int
setup_xkey_provider(void **state)
{
    (void) state;
    /* Initialize providers in a way matching what OpenVPN core does */
    tls_libctx = OSSL_LIB_CTX_new();
    prov[0] = OSSL_PROVIDER_load(tls_libctx, "default");
    OSSL_PROVIDER_add_builtin(tls_libctx, "ovpn.xkey", xkey_provider_init);
    prov[1] = OSSL_PROVIDER_load(tls_libctx, "ovpn.xkey");

    /* set default propq as we do in ssl_openssl.c */
    EVP_set_default_properties(tls_libctx, "?provider!=ovpn.xkey");
    return 0;
}

static int
teardown_xkey_provider(void **state)
{
    (void) state;
    for (size_t i = 0; i < _countof(prov); i++)
    {
        if (prov[i])
        {
            OSSL_PROVIDER_unload(prov[i]);
            prov[i] = NULL;
        }
    }
    OSSL_LIB_CTX_free(tls_libctx);
    tls_libctx = NULL;
    return 0;
}

/**
 * Sign "test_msg" using a private key. The key may be a "provided" key
 * in which case its signed by the provider's backend -- cryptoapi in our
 * case. Then verify the signature using OpenSSL.
 * Returns 1 on success, 0 on error.
 */
static int
digest_sign_verify(EVP_PKEY *privkey, EVP_PKEY *pubkey)
{
    uint8_t *sig = NULL;
    size_t siglen = 0;
    int ret = 0;

    OSSL_PARAM params[2] = {OSSL_PARAM_END};
    const char *mdname = "SHA256";

    if (EVP_PKEY_get_id(privkey) == EVP_PKEY_RSA)
    {
        const char *padmode = "pss"; /* RSA_PSS: for all other params, use defaults */
        params[0] = OSSL_PARAM_construct_utf8_string(OSSL_SIGNATURE_PARAM_PAD_MODE,
                                                     (char *)padmode, 0);
        params[1] = OSSL_PARAM_construct_end();
    }
    else if (EVP_PKEY_get_id(privkey) == EVP_PKEY_EC)
    {
        params[0] = OSSL_PARAM_construct_end();
    }
    else
    {
        print_error("Unknown key type in digest_sign_verify()");
        return ret;
    }

    EVP_PKEY_CTX *pctx = NULL;
    EVP_MD_CTX *mctx = EVP_MD_CTX_new();

    if (!mctx
        || EVP_DigestSignInit_ex(mctx, &pctx, mdname, tls_libctx, NULL, privkey,  params) <= 0)
    {
        /* cmocka assert output for these kinds of failures is hardly explanatory,
         * print a message and assert in caller. */
        print_error("Failed to initialize EVP_DigestSignInit_ex()\n");
        goto done;
    }

    /* sign with sig = NULL to get required siglen */
    if (EVP_DigestSign(mctx, sig, &siglen, (uint8_t *)test_msg, strlen(test_msg)) != 1)
    {
        print_error("EVP_DigestSign: failed to get required signature size");
        goto done;
    }
    assert_true(siglen > 0);

    if ((sig = test_calloc(1, siglen)) == NULL)
    {
        print_error("Out of memory");
        goto done;
    }
    if (EVP_DigestSign(mctx, sig, &siglen, (uint8_t *)test_msg, strlen(test_msg)) != 1)
    {
        print_error("EVP_DigestSign: signing failed");
        goto done;
    }

    /*
     * Now validate the signature using OpenSSL. Just use the public key
     * which is a native OpenSSL key.
     */
    EVP_MD_CTX_free(mctx); /* this also frees pctx */
    mctx = EVP_MD_CTX_new();
    pctx = NULL;
    if (!mctx
        || EVP_DigestVerifyInit_ex(mctx, &pctx, mdname, tls_libctx, NULL, pubkey,  params) <= 0)
    {
        print_error("Failed to initialize EVP_DigestVerifyInit_ex()");
        goto done;
    }
    if (EVP_DigestVerify(mctx, sig, siglen, (uint8_t *)test_msg, strlen(test_msg)) != 1)
    {
        print_error("EVP_DigestVerify failed");
        goto done;
    }
    ret = 1;

done:
    if (mctx)
    {
        EVP_MD_CTX_free(mctx); /* this also frees pctx */
    }
    test_free(sig);
    return ret;
}

/* Load sample certificates & keys, sign a test message using
 * them and verify the signature.
 */
void
test_cryptoapi_sign(void **state)
{
    (void) state;
    char select_string[64];
    X509 *x509 = NULL;
    EVP_PKEY *privkey = NULL;

    import_certs(state); /* a no-op if already imported */
    assert_true(certs_loaded);

    for (struct test_cert *c = certs; c->cert; c++)
    {
        if (c->valid == 0)
        {
            continue;
        }
        openvpn_snprintf(select_string, sizeof(select_string), "THUMB:%s", c->hash);
        if (Load_CryptoAPI_certificate(select_string, &x509, &privkey) != 1)
        {
            fail_msg("Load_CryptoAPI_certificate failed: <%s>", c->friendly_name);
            return;
        }
        EVP_PKEY *pubkey = X509_get0_pubkey(x509);
        assert_non_null(pubkey);
        assert_int_equal(digest_sign_verify(privkey, pubkey), 1);
        X509_free(x509);
        EVP_PKEY_free(privkey);
    }
}

/* Test that SSL_CTX_use_Cryptoapi_certificate() sets a matching certificate
 * and key in ssl_ctx.
 */
void
test_ssl_ctx_use_cryptoapicert(void **state)
{
    (void) state;
    char select_string[64];

    import_certs(state); /* a no-op if already imported */
    assert_true(certs_loaded);

    for (struct test_cert *c = certs; c->cert; c++)
    {
        if (c->valid == 0)
        {
            continue;
        }
        SSL_CTX *ssl_ctx = SSL_CTX_new_ex(tls_libctx, NULL, SSLv23_client_method());
        assert_non_null(ssl_ctx);

        openvpn_snprintf(select_string, sizeof(select_string), "THUMB:%s", c->hash);
        if (!SSL_CTX_use_CryptoAPI_certificate(ssl_ctx, select_string))
        {
            fail_msg("SSL_CTX_use_CryptoAPI_certificate failed: <%s>", c->friendly_name);
            return;
        }
        /* Use OpenSSL to check that the cert and private key in ssl_ctx "match" */
        if (!SSL_CTX_check_private_key(ssl_ctx))
        {
            fail_msg("Certificate and private key in ssl_ctx do not match for <%s>", c->friendly_name);
            return;
        }

        SSL_CTX_free(ssl_ctx);
    }
}

static void
test_parse_hexstring(void **state)
{
    unsigned char hash[255];
    (void) state;

    for (int i = 0; i < _countof(valid_str); i++)
    {
        int len = parse_hexstring(valid_str[i], hash, _countof(hash));
        assert_int_equal(len, sizeof(test_hash));
        assert_memory_equal(hash, test_hash, sizeof(test_hash));
        memset(hash, 0, _countof(hash));
    }

    for (int i = 0; i < _countof(invalid_str); i++)
    {
        int len = parse_hexstring(invalid_str[i], hash, _countof(hash));
        assert_int_equal(len, 0);
    }
}

int
main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_parse_hexstring),
        cmocka_unit_test(import_certs),
        cmocka_unit_test(test_find_cert_bythumb),
        cmocka_unit_test(test_find_cert_byname),
        cmocka_unit_test(test_find_cert_byissuer),
        cmocka_unit_test_setup_teardown(test_cryptoapi_sign, setup_xkey_provider,
                                        teardown_xkey_provider),
        cmocka_unit_test_setup_teardown(test_ssl_ctx_use_cryptoapicert, setup_xkey_provider,
                                        teardown_xkey_provider),
    };

    int ret = cmocka_run_group_tests_name("cryptoapi tests", tests, NULL, cleanup);

    return ret;
}

#else  /* ifdef HAVE_XKEY_PROVIDER */

int
main(void)
{
    return 0;
}

#endif  /* ifdef HAVE_XKEY_PROVIDER */
