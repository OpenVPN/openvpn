/*
 * Copyright (c) 2004 Peter 'Luna' Runestig <peter@runestig.com>
 * Copyright (c) 2018 Selva Nair <selva.nair@gmail.com>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without modifi-
 * cation, are permitted provided that the following conditions are met:
 *
 *   o  Redistributions of source code must retain the above copyright notice,
 *      this list of conditions and the following disclaimer.
 *
 *   o  Redistributions in binary form must reproduce the above copyright no-
 *      tice, this list of conditions and the following disclaimer in the do-
 *      cumentation and/or other materials provided with the distribution.
 *
 *   o  The names of the contributors may not be used to endorse or promote
 *      products derived from this software without specific prior written
 *      permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
 * TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LI-
 * ABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUEN-
 * TIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEV-
 * ER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABI-
 * LITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF
 * THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#elif defined(_MSC_VER)
#include "config-msvc.h"
#endif

#include "syshead.h"

#ifdef ENABLE_CRYPTOAPI

#include <openssl/ssl.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <windows.h>
#include <wincrypt.h>
#include <ncrypt.h>
#include <stdio.h>
#include <ctype.h>
#include <assert.h>

#include "buffer.h"
#include "openssl_compat.h"
#include "win32.h"

/* index for storing external data in EC_KEY: < 0 means uninitialized */
static int ec_data_idx = -1;

/* Global EVP_PKEY_METHOD used to override the sign operation */
static EVP_PKEY_METHOD *pmethod;
static int (*default_pkey_sign_init) (EVP_PKEY_CTX *ctx);
static int (*default_pkey_sign) (EVP_PKEY_CTX *ctx, unsigned char *sig,
                                 size_t *siglen, const unsigned char *tbs, size_t tbslen);

typedef struct _CAPI_DATA {
    const CERT_CONTEXT *cert_context;
    HCRYPTPROV_OR_NCRYPT_KEY_HANDLE crypt_prov;
    DWORD key_spec;
    BOOL free_crypt_prov;
    int ref_count;
} CAPI_DATA;

/* Translate OpenSSL padding type to CNG padding type
 * Returns 0 for unknown/unsupported padding.
 */
static DWORD
cng_padding_type(int padding)
{
    DWORD pad = 0;

    switch (padding)
    {
        case RSA_NO_PADDING:
            break;

        case RSA_PKCS1_PADDING:
            pad = BCRYPT_PAD_PKCS1;
            break;

        case RSA_PKCS1_PSS_PADDING:
            pad = BCRYPT_PAD_PSS;
            break;

        default:
            msg(M_WARN|M_INFO, "cryptoapicert: unknown OpenSSL padding type %d.",
                padding);
    }

    return pad;
}

/*
 * Translate OpenSSL hash OID to CNG algorithm name. Returns
 * "UNKNOWN" for unsupported algorithms and NULL for MD5+SHA1
 * mixed hash used in TLS 1.1 and earlier.
 */
static const wchar_t *
cng_hash_algo(int md_type)
{
    const wchar_t *alg = L"UNKNOWN";
    switch (md_type)
    {
        case NID_md5:
            alg = BCRYPT_MD5_ALGORITHM;
            break;

        case NID_sha1:
            alg = BCRYPT_SHA1_ALGORITHM;
            break;

        case NID_sha256:
            alg = BCRYPT_SHA256_ALGORITHM;
            break;

        case NID_sha384:
            alg = BCRYPT_SHA384_ALGORITHM;
            break;

        case NID_sha512:
            alg = BCRYPT_SHA512_ALGORITHM;
            break;

        case NID_md5_sha1:
        case 0:
            alg = NULL;
            break;

        default:
            msg(M_WARN|M_INFO, "cryptoapicert: Unknown hash type NID=0x%x", md_type);
            break;
    }
    return alg;
}

static void
CAPI_DATA_free(CAPI_DATA *cd)
{
    if (!cd || cd->ref_count-- > 0)
    {
        return;
    }
    if (cd->free_crypt_prov && cd->crypt_prov)
    {
        if (cd->key_spec == CERT_NCRYPT_KEY_SPEC)
        {
            NCryptFreeObject(cd->crypt_prov);
        }
        else
        {
            CryptReleaseContext(cd->crypt_prov, 0);
        }
    }
    if (cd->cert_context)
    {
        CertFreeCertificateContext(cd->cert_context);
    }
    free(cd);
}

/**
 * Sign the hash in 'from' using NCryptSignHash(). This requires an NCRYPT
 * key handle in cd->crypt_prov. On return the signature is in 'to'. Returns
 * the length of the signature or 0 on error.
 * This is used only for RSA and padding should be BCRYPT_PAD_PKCS1 or
 * BCRYPT_PAD_PSS.
 * If the hash_algo is not NULL, PKCS #1 DigestInfo header gets added
 * to |from|, else it is signed as is. Use NULL for MD5 + SHA1 hash used
 * in TLS 1.1 and earlier.
 * In case of PSS padding, |saltlen| should specify the size of salt to use.
 * If |to| is NULL returns the required buffer size.
 */
static int
priv_enc_CNG(const CAPI_DATA *cd, const wchar_t *hash_algo, const unsigned char *from,
             int flen, unsigned char *to, int tlen, DWORD padding, DWORD saltlen)
{
    NCRYPT_KEY_HANDLE hkey = cd->crypt_prov;
    DWORD len = 0;
    ASSERT(cd->key_spec == CERT_NCRYPT_KEY_SPEC);

    DWORD status;

    msg(D_LOW, "Signing hash using CNG: data size = %d padding = %lu", flen, padding);

    if (padding == BCRYPT_PAD_PKCS1)
    {
        BCRYPT_PKCS1_PADDING_INFO padinfo = {hash_algo};
        status = NCryptSignHash(hkey, &padinfo, (BYTE *)from, flen,
                                to, tlen, &len, padding);
    }
    else if (padding == BCRYPT_PAD_PSS)
    {
        BCRYPT_PSS_PADDING_INFO padinfo = {hash_algo, saltlen};
        status = NCryptSignHash(hkey, &padinfo, (BYTE *)from, flen,
                                to, tlen, &len, padding);
    }
    else
    {
        msg(M_NONFATAL, "Error in cryptoapicert: Unknown padding type");
        return 0;
    }

    if (status != ERROR_SUCCESS)
    {
        SetLastError(status);
        msg(M_NONFATAL|M_ERRNO, "Error in cryptoapicert: NCryptSignHash failed");
        len = 0;
    }

    /* Unlike CAPI, CNG signature is in big endian order. No reversing needed. */
    return len;
}

/* called at RSA_free */
static int
rsa_finish(RSA *rsa)
{
    const RSA_METHOD *rsa_meth = RSA_get_method(rsa);
    CAPI_DATA *cd = (CAPI_DATA *) RSA_meth_get0_app_data(rsa_meth);

    if (cd == NULL)
    {
        return 0;
    }
    CAPI_DATA_free(cd);
    RSA_meth_free((RSA_METHOD *) rsa_meth);
    return 1;
}

static EC_KEY_METHOD *ec_method = NULL;

/** EC_KEY_METHOD callback: called when the key is freed */
static void
ec_finish(EC_KEY *ec)
{
    EC_KEY_METHOD_free(ec_method);
    ec_method = NULL;
    CAPI_DATA *cd = EC_KEY_get_ex_data(ec, ec_data_idx);
    CAPI_DATA_free(cd);
    EC_KEY_set_ex_data(ec, ec_data_idx, NULL);
}

/** EC_KEY_METHOD callback sign_setup(): we do nothing here */
static int
ecdsa_sign_setup(EC_KEY *eckey, BN_CTX *ctx_in, BIGNUM **kinvp, BIGNUM **rp)
{
    return 1;
}

/**
 * Helper to convert ECDSA signature returned by NCryptSignHash
 * to an ECDSA_SIG structure.
 * On entry 'buf[]' of length len contains r and s concatenated.
 * Returns a newly allocated ECDSA_SIG or NULL (on error).
 */
static ECDSA_SIG *
ecdsa_bin2sig(unsigned char *buf, int len)
{
    ECDSA_SIG *ecsig = NULL;
    DWORD rlen = len/2;
    BIGNUM *r = BN_bin2bn(buf, rlen, NULL);
    BIGNUM *s = BN_bin2bn(buf+rlen, rlen, NULL);
    if (!r || !s)
    {
        goto err;
    }
    ecsig = ECDSA_SIG_new(); /* in openssl 1.1 this does not allocate r, s */
    if (!ecsig)
    {
        goto err;
    }
    if (!ECDSA_SIG_set0(ecsig, r, s)) /* ecsig takes ownership of r and s */
    {
        ECDSA_SIG_free(ecsig);
        goto err;
    }
    return ecsig;
err:
    BN_free(r); /* it is ok to free NULL BN */
    BN_free(s);
    return NULL;
}

/** EC_KEY_METHOD callback sign_sig(): sign and return an ECDSA_SIG pointer. */
static ECDSA_SIG *
ecdsa_sign_sig(const unsigned char *dgst, int dgstlen,
               const BIGNUM *in_kinv, const BIGNUM *in_r, EC_KEY *ec)
{
    ECDSA_SIG *ecsig = NULL;
    CAPI_DATA *cd = (CAPI_DATA *)EC_KEY_get_ex_data(ec, ec_data_idx);

    ASSERT(cd->key_spec == CERT_NCRYPT_KEY_SPEC);

    NCRYPT_KEY_HANDLE hkey = cd->crypt_prov;
    BYTE buf[512]; /* large enough buffer for signature to avoid malloc */
    DWORD len = _countof(buf);

    msg(D_LOW, "Cryptoapi: signing hash using EC key: data size = %d", dgstlen);

    DWORD status = NCryptSignHash(hkey, NULL, (BYTE *)dgst, dgstlen, (BYTE *)buf, len, &len, 0);
    if (status != ERROR_SUCCESS)
    {
        SetLastError(status);
        msg(M_NONFATAL|M_ERRNO, "Error in cryptoapticert: NCryptSignHash failed");
    }
    else
    {
        /* NCryptSignHash returns r, s concatenated in buf[] */
        ecsig = ecdsa_bin2sig(buf, len);
    }
    return ecsig;
}

/** EC_KEY_METHOD callback sign(): sign and return a DER encoded signature */
static int
ecdsa_sign(int type, const unsigned char *dgst, int dgstlen, unsigned char *sig,
           unsigned int *siglen, const BIGNUM *kinv, const BIGNUM *r, EC_KEY *ec)
{
    ECDSA_SIG *s;

    *siglen = 0;
    s = ecdsa_sign_sig(dgst, dgstlen, NULL, NULL, ec);
    if (s == NULL)
    {
        return 0;
    }

    /* convert internal signature structure 's' to DER encoded byte array in sig */
    int len = i2d_ECDSA_SIG(s, NULL);
    if (len > ECDSA_size(ec))
    {
        ECDSA_SIG_free(s);
        msg(M_NONFATAL,"Error in cryptoapicert: DER encoded ECDSA signature is too long (%d bytes)", len);
        return 0;
    }
    *siglen = i2d_ECDSA_SIG(s, &sig);
    ECDSA_SIG_free(s);

    return 1;
}

static int
ssl_ctx_set_eckey(SSL_CTX *ssl_ctx, CAPI_DATA *cd, EVP_PKEY *pkey)
{
    EC_KEY *ec = NULL;
    EVP_PKEY *privkey = NULL;

    /* create a method struct with default callbacks filled in */
    ec_method = EC_KEY_METHOD_new(EC_KEY_OpenSSL());
    if (!ec_method)
    {
        goto err;
    }

    /* We only need to set finish among init methods, and sign methods */
    EC_KEY_METHOD_set_init(ec_method, NULL, ec_finish, NULL, NULL, NULL, NULL);
    EC_KEY_METHOD_set_sign(ec_method, ecdsa_sign, ecdsa_sign_setup, ecdsa_sign_sig);

    ec = EC_KEY_dup(EVP_PKEY_get0_EC_KEY(pkey));
    if (!ec)
    {
        goto err;
    }
    if (!EC_KEY_set_method(ec, ec_method))
    {
        goto err;
    }

    /* get an index to store cd as external data */
    if (ec_data_idx < 0)
    {
        ec_data_idx = EC_KEY_get_ex_new_index(0, "cryptapicert ec key", NULL, NULL, NULL);
        if (ec_data_idx < 0)
        {
            goto err;
        }
    }
    EC_KEY_set_ex_data(ec, ec_data_idx, cd);

    /* cd assigned to ec as ex_data, increase its refcount */
    cd->ref_count++;

    privkey = EVP_PKEY_new();
    if (!EVP_PKEY_assign_EC_KEY(privkey, ec))
    {
        EC_KEY_free(ec);
        goto err;
    }
    /* from here on ec will get freed with privkey */

    if (!SSL_CTX_use_PrivateKey(ssl_ctx, privkey))
    {
        goto err;
    }
    EVP_PKEY_free(privkey); /* this will dn_ref or free ec as well */
    return 1;

err:
    if (privkey)
    {
        EVP_PKEY_free(privkey);
    }
    else if (ec)
    {
        EC_KEY_free(ec);
    }
    if (ec_method) /* do always set ec_method = NULL after freeing it */
    {
        EC_KEY_METHOD_free(ec_method);
        ec_method = NULL;
    }
    return 0;
}

static const CERT_CONTEXT *
find_certificate_in_store(const char *cert_prop, HCERTSTORE cert_store)
{
    /* Find, and use, the desired certificate from the store. The
     * 'cert_prop' certificate search string can look like this:
     * SUBJ:<certificate substring to match>
     * THUMB:<certificate thumbprint hex value>, e.g.
     *     THUMB:f6 49 24 41 01 b4 fb 44 0c ce f4 36 ae d0 c4 c9 df 7a b6 28
     * The first matching certificate that has not expired is returned.
     */
    const CERT_CONTEXT *rv = NULL;
    DWORD find_type;
    const void *find_param;
    unsigned char hash[255];
    CRYPT_HASH_BLOB blob = {.cbData = 0, .pbData = hash};
    struct gc_arena gc = gc_new();

    if (!strncmp(cert_prop, "SUBJ:", 5))
    {
        /* skip the tag */
        find_param = wide_string(cert_prop + 5, &gc);
        find_type = CERT_FIND_SUBJECT_STR_W;
    }
    else if (!strncmp(cert_prop, "THUMB:", 6))
    {
        const char *p;
        int i, x = 0;
        find_type = CERT_FIND_HASH;
        find_param = &blob;

        /* skip the tag */
        cert_prop += 6;
        for (p = cert_prop, i = 0; *p && i < sizeof(hash); i++)
        {
            if (*p >= '0' && *p <= '9')
            {
                x = (*p - '0') << 4;
            }
            else if (*p >= 'A' && *p <= 'F')
            {
                x = (*p - 'A' + 10) << 4;
            }
            else if (*p >= 'a' && *p <= 'f')
            {
                x = (*p - 'a' + 10) << 4;
            }
            if (!*++p)  /* unexpected end of string */
            {
                msg(M_WARN|M_INFO, "WARNING: cryptoapicert: error parsing <THUMB:%s>.", cert_prop);
                goto out;
            }
            if (*p >= '0' && *p <= '9')
            {
                x += *p - '0';
            }
            else if (*p >= 'A' && *p <= 'F')
            {
                x += *p - 'A' + 10;
            }
            else if (*p >= 'a' && *p <= 'f')
            {
                x += *p - 'a' + 10;
            }
            hash[i] = x;
            /* skip any space(s) between hex numbers */
            for (p++; *p && *p == ' '; p++)
            {
            }
        }
        blob.cbData = i;
    }
    else
    {
        msg(M_NONFATAL, "Error in cryptoapicert: unsupported certificate specification <%s>", cert_prop);
        goto out;
    }

    while (true)
    {
        int validity = 1;
        /* this frees previous rv, if not NULL */
        rv = CertFindCertificateInStore(cert_store, X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
                                        0, find_type, find_param, rv);
        if (rv)
        {
            validity = CertVerifyTimeValidity(NULL, rv->pCertInfo);
        }
        if (!rv || validity == 0)
        {
            break;
        }
        msg(M_WARN|M_INFO, "WARNING: cryptoapicert: ignoring certificate in store %s.",
            validity < 0 ? "not yet valid" : "that has expired");
    }

out:
    gc_free(&gc);
    return rv;
}

static const CAPI_DATA *
retrieve_capi_data(EVP_PKEY *pkey)
{
    const CAPI_DATA *cd = NULL;

    if (pkey && EVP_PKEY_id(pkey) == EVP_PKEY_RSA)
    {
        RSA *rsa = EVP_PKEY_get0_RSA(pkey);
        if (rsa)
        {
            cd = (CAPI_DATA *)RSA_meth_get0_app_data(RSA_get_method(rsa));
        }
    }
    return cd;
}

static int
pkey_rsa_sign_init(EVP_PKEY_CTX *ctx)
{
    msg(D_LOW, "cryptoapicert: enter pkey_rsa_sign_init");

    EVP_PKEY *pkey = EVP_PKEY_CTX_get0_pkey(ctx);

    if (pkey && retrieve_capi_data(pkey))
    {
        return 1; /* Return success */
    }
    else if (default_pkey_sign_init)  /* Not our key. Call the default method */
    {
        return default_pkey_sign_init(ctx);
    }
    return 1;
}

/**
 * Implementation of EVP_PKEY_sign() using CNG: sign the digest in |tbs|
 * and save the the signature in |sig| and its size in |*siglen|.
 * If |sig| is NULL the required buffer size is returned in |*siglen|.
 * Returns value is 1 on success, 0 or a negative integer on error.
 */
static int
pkey_rsa_sign(EVP_PKEY_CTX *ctx, unsigned char *sig, size_t *siglen,
              const unsigned char *tbs, size_t tbslen)
{
    EVP_PKEY *pkey = NULL;
    const CAPI_DATA *cd = NULL;
    EVP_MD *md = NULL;
    const wchar_t *alg = NULL;

    int padding = 0;
    int hashlen = 0;
    int saltlen = 0;

    pkey = EVP_PKEY_CTX_get0_pkey(ctx);
    if (pkey)
    {
        cd = retrieve_capi_data(pkey);
    }

    /*
     * We intercept all sign requests, not just the one's for our key.
     * Check the key and call the saved OpenSSL method for unknown keys.
     */
    if (!pkey || !cd)
    {
        if (default_pkey_sign)
        {
            return default_pkey_sign(ctx, sig, siglen, tbs, tbslen);
        }
        else  /* This should not happen */
        {
            msg(M_FATAL, "Error in cryptoapicert: Unknown key and no default sign operation to fallback on");
            return -1;
        }
    }

    if (!EVP_PKEY_CTX_get_rsa_padding(ctx, &padding))
    {
        padding = RSA_PKCS1_PADDING; /* Default padding for RSA */
    }

    if (EVP_PKEY_CTX_get_signature_md(ctx, &md))
    {
        hashlen = EVP_MD_size(md);
        alg = cng_hash_algo(EVP_MD_type(md));

        /*
         * alg == NULL indicates legacy MD5+SHA1 hash, else alg should be a valid
         * digest algorithm.
         */
        if (alg && wcscmp(alg, L"UNKNOWN") == 0)
        {
            msg(M_NONFATAL, "Error in cryptoapicert: Unknown hash algorithm <%d>", EVP_MD_type(md));
            return -1;
        }
    }
    else
    {
        msg(M_NONFATAL, "Error in cryptoapicert: could not determine the signature digest algorithm");
        return -1;
    }

    if (tbslen != (size_t)hashlen)
    {
        msg(M_NONFATAL, "Error in cryptoapicert: data size does not match hash");
        return -1;
    }

    /* If padding is PSS, determine parameters to pass to CNG */
    if (padding == RSA_PKCS1_PSS_PADDING)
    {
        /*
         * Ensure the digest type for signature and mask generation match.
         * In CNG there is no option to specify separate hash functions for
         * the two, but OpenSSL supports it. However, I have not seen the
         * two being different in practice. Also the recommended practice is
         * to use the same for both (rfc 8017 sec 8.1).
         */
        EVP_MD *mgf1md;
        if (!EVP_PKEY_CTX_get_rsa_mgf1_md(ctx, &mgf1md)
            || EVP_MD_type(mgf1md) != EVP_MD_type(md))
        {
            msg(M_NONFATAL, "Error in cryptoapicert: Unknown MGF1 digest type or does"
                " not match the signature digest type.");
            return -1;
        }

        if (!EVP_PKEY_CTX_get_rsa_pss_saltlen(ctx, &saltlen))
        {
            msg(M_WARN|M_INFO, "cryptoapicert: unable to get the salt length from context."
                " Using the default value.");
            saltlen = -1;
        }

        /*
         * In OpenSSL saltlen = -1 indicates to use the size of the digest as
         * size of the salt. A value of -2 or -3 indicates maximum salt length
         * that will fit. See RSA_padding_add_PKCS1_PSS_mgf1() of OpenSSL.
         */
        if (saltlen == -1)
        {
            saltlen = hashlen;
        }
        else if (saltlen < 0)
        {
            const RSA *rsa = EVP_PKEY_get0_RSA(pkey);
            saltlen = RSA_size(rsa) - hashlen - 2; /* max salt length for RSASSA-PSS */
            if (RSA_bits(rsa) &0x7) /* number of bits in the key not a multiple of 8 */
            {
                saltlen--;
            }
        }

        if (saltlen < 0)
        {
            msg(M_NONFATAL, "Error in cryptoapicert: invalid salt length (%d). Digest too large for keysize?", saltlen);
            return -1;
        }
        msg(D_LOW, "cryptoapicert: PSS padding using saltlen = %d", saltlen);
    }

    msg(D_LOW, "cryptoapicert: calling priv_enc_CNG with alg = %ls", alg);
    *siglen = priv_enc_CNG(cd, alg, tbs, (int)tbslen, sig, (int)*siglen,
                           cng_padding_type(padding), (DWORD)saltlen);

    return (*siglen == 0) ? 0 : 1;
}

static int
ssl_ctx_set_rsakey(SSL_CTX *ssl_ctx, CAPI_DATA *cd, EVP_PKEY *pkey)
{
    RSA *rsa = NULL;
    RSA_METHOD *my_rsa_method = NULL;
    EVP_PKEY *privkey = NULL;
    int ret = 0;

    my_rsa_method = RSA_meth_new("Microsoft Cryptography API RSA Method",
                                 RSA_METHOD_FLAG_NO_CHECK);
    check_malloc_return(my_rsa_method);
    RSA_meth_set_finish(my_rsa_method, rsa_finish); /* we use this callback to cleanup CAPI_DATA */
    RSA_meth_set0_app_data(my_rsa_method, cd);

    /* pmethod is global -- initialize only if NULL */
    if (!pmethod)
    {
        pmethod = EVP_PKEY_meth_new(EVP_PKEY_RSA, 0);
        if (!pmethod)
        {
            msg(M_NONFATAL, "Error in cryptoapicert: failed to create EVP_PKEY_METHOD");
            return 0;
        }
        const EVP_PKEY_METHOD *default_pmethod = EVP_PKEY_meth_find(EVP_PKEY_RSA);
        EVP_PKEY_meth_copy(pmethod, default_pmethod);

        /* We want to override only sign_init() and sign() */
        EVP_PKEY_meth_set_sign(pmethod, pkey_rsa_sign_init, pkey_rsa_sign);
        EVP_PKEY_meth_add0(pmethod);

        /* Keep a copy of the default sign and sign_init methods */

        EVP_PKEY_meth_get_sign(default_pmethod, &default_pkey_sign_init,
                               &default_pkey_sign);
    }

    rsa = EVP_PKEY_get1_RSA(pkey);

    RSA_set_flags(rsa, RSA_flags(rsa) | RSA_FLAG_EXT_PKEY);
    if (!RSA_set_method(rsa, my_rsa_method))
    {
        goto cleanup;
    }
    my_rsa_method = NULL;  /* we do not want to free it in cleanup */
    cd->ref_count++;       /* with method, cd gets assigned to the key as well */

    privkey = EVP_PKEY_new();
    if (!EVP_PKEY_assign_RSA(privkey, rsa))
    {
        goto cleanup;
    }
    rsa = NULL; /* privkey has taken ownership */

    if (!SSL_CTX_use_PrivateKey(ssl_ctx, privkey))
    {
        goto cleanup;
    }
    ret = 1;

cleanup:
    if (rsa)
    {
        RSA_free(rsa);
    }
    if (my_rsa_method)
    {
        RSA_meth_free(my_rsa_method);
    }
    if (privkey)
    {
        EVP_PKEY_free(privkey);
    }

    return ret;
}

int
SSL_CTX_use_CryptoAPI_certificate(SSL_CTX *ssl_ctx, const char *cert_prop)
{
    HCERTSTORE cs;
    X509 *cert = NULL;
    CAPI_DATA *cd = calloc(1, sizeof(*cd));

    if (cd == NULL)
    {
        msg(M_NONFATAL, "Error in cryptoapicert: out of memory");
        goto err;
    }
    /* search CURRENT_USER first, then LOCAL_MACHINE */
    cs = CertOpenStore((LPCSTR) CERT_STORE_PROV_SYSTEM, 0, 0, CERT_SYSTEM_STORE_CURRENT_USER
                       |CERT_STORE_OPEN_EXISTING_FLAG | CERT_STORE_READONLY_FLAG, L"MY");
    if (cs == NULL)
    {
        msg(M_NONFATAL|M_ERRNO, "Error in cryptoapicert: failed to open user certficate store");
        goto err;
    }
    cd->cert_context = find_certificate_in_store(cert_prop, cs);
    CertCloseStore(cs, 0);
    if (!cd->cert_context)
    {
        cs = CertOpenStore((LPCSTR) CERT_STORE_PROV_SYSTEM, 0, 0, CERT_SYSTEM_STORE_LOCAL_MACHINE
                           |CERT_STORE_OPEN_EXISTING_FLAG | CERT_STORE_READONLY_FLAG, L"MY");
        if (cs == NULL)
        {
            msg(M_NONFATAL|M_ERRNO, "Error in cryptoapicert: failed to open machine certficate store");
            goto err;
        }
        cd->cert_context = find_certificate_in_store(cert_prop, cs);
        CertCloseStore(cs, 0);
        if (cd->cert_context == NULL)
        {
            msg(M_NONFATAL, "Error in cryptoapicert: certificate matching <%s> not found", cert_prop);
            goto err;
        }
    }

    /* cert_context->pbCertEncoded is the cert X509 DER encoded. */
    cert = d2i_X509(NULL, (const unsigned char **) &cd->cert_context->pbCertEncoded,
                    cd->cert_context->cbCertEncoded);
    if (cert == NULL)
    {
        msg(M_NONFATAL, "Error in cryptoapicert: X509 certificate decode failed");
        goto err;
    }

    /* set up stuff to use the private key */
    /* We support NCRYPT key handles only */
    DWORD flags = CRYPT_ACQUIRE_COMPARE_KEY_FLAG
                  | CRYPT_ACQUIRE_ONLY_NCRYPT_KEY_FLAG;
    if (!CryptAcquireCertificatePrivateKey(cd->cert_context, flags, NULL,
                                           &cd->crypt_prov, &cd->key_spec, &cd->free_crypt_prov))
    {
        /* private key may be in a token not available, or incompatible with CNG */
        msg(M_NONFATAL|M_ERRNO, "Error in cryptoapicert: failed to acquire key. Key not present or "
                                "is in a legacy token not supported by Windows CNG API");
        goto err;
    }

    /* Public key in cert is NULL until we call SSL_CTX_use_certificate(),
     * so we do it here then...  */
    if (!SSL_CTX_use_certificate(ssl_ctx, cert))
    {
        goto err;
    }

    /* the public key */
    EVP_PKEY *pkey = X509_get0_pubkey(cert);

    /* SSL_CTX_use_certificate() increased the reference count in 'cert', so
     * we decrease it here with X509_free(), or it will never be cleaned up. */
    X509_free(cert);
    cert = NULL;

    if (EVP_PKEY_id(pkey) == EVP_PKEY_RSA)
    {
        if (!ssl_ctx_set_rsakey(ssl_ctx, cd, pkey))
        {
            goto err;
        }
    }
    else if (EVP_PKEY_id(pkey) == EVP_PKEY_EC)
    {
        if (!ssl_ctx_set_eckey(ssl_ctx, cd, pkey))
        {
            goto err;
        }
    }
    else
    {
        msg(M_WARN|M_INFO, "WARNING: cryptoapicert: key type <%d> not supported",
            EVP_PKEY_id(pkey));
        goto err;
    }
    CAPI_DATA_free(cd); /* this will do a ref_count-- */
    return 1;

err:
    CAPI_DATA_free(cd);
    return 0;
}
#endif                          /* _WIN32 */
