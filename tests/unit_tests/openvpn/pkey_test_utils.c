/*
 *  OpenVPN -- An application to securely tunnel IP networks
 *             over a single UDP port, with support for SSL/TLS-based
 *             session authentication and key exchange,
 *             packet encryption, packet authentication, and
 *             packet compression.
 *
 *  Copyright (C) 2023-2024 Selva Nair <selva.nair@gmail.com>
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
#include "xkey_common.h"
#include <setjmp.h>
#include <cmocka.h>

#ifdef HAVE_XKEY_PROVIDER

#include <openssl/core_names.h>
#include <openssl/evp.h>

extern OSSL_LIB_CTX *tls_libctx;

/* A message for signing */
static const char *test_msg = "Lorem ipsum dolor sit amet, consectetur "
                              "adipisici elit, sed eiusmod tempor incidunt "
                              "ut labore et dolore magna aliqua.";

/**
 * Sign "test_msg" using a private key. The key may be a "provided" key
 * in which case its signed by the provider's backend -- cryptoapi in our
 * case. Then verify the signature using OpenSSL.
 * Returns 1 on success, 0 on error.
 */
int
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
#endif /* HAVE_XKEY_PROVIDER */
