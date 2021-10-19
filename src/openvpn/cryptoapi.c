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

/* MinGW w32api 3.17 is still incomplete when it comes to CryptoAPI while
 * MinGW32-w64 defines all macros used. This is a hack around that problem.
 */
#ifndef CERT_SYSTEM_STORE_LOCATION_SHIFT
#define CERT_SYSTEM_STORE_LOCATION_SHIFT 16
#endif
#ifndef CERT_SYSTEM_STORE_CURRENT_USER_ID
#define CERT_SYSTEM_STORE_CURRENT_USER_ID 1
#endif
#ifndef CERT_SYSTEM_STORE_CURRENT_USER
#define CERT_SYSTEM_STORE_CURRENT_USER (CERT_SYSTEM_STORE_CURRENT_USER_ID << CERT_SYSTEM_STORE_LOCATION_SHIFT)
#endif
#ifndef CERT_STORE_READONLY_FLAG
#define CERT_STORE_READONLY_FLAG 0x00008000
#endif
#ifndef CERT_STORE_OPEN_EXISTING_FLAG
#define CERT_STORE_OPEN_EXISTING_FLAG 0x00004000
#endif

/* Size of an SSL signature: MD5+SHA1 */
#define SSL_SIG_LENGTH  36

/* try to funnel any Windows/CryptoAPI error messages to OpenSSL ERR_... */
#define ERR_LIB_CRYPTOAPI (ERR_LIB_USER + 69)   /* 69 is just a number... */
#define CRYPTOAPIerr(f)   err_put_ms_error(GetLastError(), (f), __FILE__, __LINE__)
#define CRYPTOAPI_F_CERT_OPEN_SYSTEM_STORE                  100
#define CRYPTOAPI_F_CERT_FIND_CERTIFICATE_IN_STORE          101
#define CRYPTOAPI_F_CRYPT_ACQUIRE_CERTIFICATE_PRIVATE_KEY   102
#define CRYPTOAPI_F_CRYPT_CREATE_HASH                       103
#define CRYPTOAPI_F_CRYPT_GET_HASH_PARAM                    104
#define CRYPTOAPI_F_CRYPT_SET_HASH_PARAM                    105
#define CRYPTOAPI_F_CRYPT_SIGN_HASH                         106
#define CRYPTOAPI_F_LOAD_LIBRARY                            107
#define CRYPTOAPI_F_GET_PROC_ADDRESS                        108
#define CRYPTOAPI_F_NCRYPT_SIGN_HASH                        109

static ERR_STRING_DATA CRYPTOAPI_str_functs[] = {
    { ERR_PACK(ERR_LIB_CRYPTOAPI, 0, 0),                                    "microsoft cryptoapi"},
    { ERR_PACK(0, CRYPTOAPI_F_CERT_OPEN_SYSTEM_STORE, 0),                   "CertOpenSystemStore" },
    { ERR_PACK(0, CRYPTOAPI_F_CERT_FIND_CERTIFICATE_IN_STORE, 0),           "CertFindCertificateInStore" },
    { ERR_PACK(0, CRYPTOAPI_F_CRYPT_ACQUIRE_CERTIFICATE_PRIVATE_KEY, 0),    "CryptAcquireCertificatePrivateKey" },
    { ERR_PACK(0, CRYPTOAPI_F_CRYPT_CREATE_HASH, 0),                        "CryptCreateHash" },
    { ERR_PACK(0, CRYPTOAPI_F_CRYPT_GET_HASH_PARAM, 0),                     "CryptGetHashParam" },
    { ERR_PACK(0, CRYPTOAPI_F_CRYPT_SET_HASH_PARAM, 0),                     "CryptSetHashParam" },
    { ERR_PACK(0, CRYPTOAPI_F_CRYPT_SIGN_HASH, 0),                          "CryptSignHash" },
    { ERR_PACK(0, CRYPTOAPI_F_LOAD_LIBRARY, 0),                             "LoadLibrary" },
    { ERR_PACK(0, CRYPTOAPI_F_GET_PROC_ADDRESS, 0),                         "GetProcAddress" },
    { ERR_PACK(0, CRYPTOAPI_F_NCRYPT_SIGN_HASH, 0),                         "NCryptSignHash" },
    { 0, NULL }
};

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

static char *
ms_error_text(DWORD ms_err)
{
    LPVOID lpMsgBuf = NULL;
    char *rv = NULL;

    FormatMessage(
        FORMAT_MESSAGE_ALLOCATE_BUFFER
        |FORMAT_MESSAGE_FROM_SYSTEM
        |FORMAT_MESSAGE_IGNORE_INSERTS,
        NULL, ms_err,
        MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), /* Default language */
        (LPTSTR) &lpMsgBuf, 0, NULL);
    if (lpMsgBuf)
    {
        char *p;
        rv = string_alloc(lpMsgBuf, NULL);
        LocalFree(lpMsgBuf);
        /* trim to the left */
        if (rv)
        {
            for (p = rv + strlen(rv) - 1; p >= rv; p--)
            {
                if (isspace(*p))
                {
                    *p = '\0';
                }
                else
                {
                    break;
                }
            }
        }
    }
    return rv;
}

static void
err_put_ms_error(DWORD ms_err, int func, const char *file, int line)
{
    static int init = 0;
#define ERR_MAP_SZ 16
    static struct {
        int err;
        DWORD ms_err;       /* I don't think we get more than 16 *different* errors */
    } err_map[ERR_MAP_SZ];  /* in here, before we give up the whole thing...        */
    int i;

    if (ms_err == 0)
    {
        /* 0 is not an error */
        return;
    }
    if (!init)
    {
        ERR_load_strings(ERR_LIB_CRYPTOAPI, CRYPTOAPI_str_functs);
        memset(&err_map, 0, sizeof(err_map));
        init++;
    }
    /* since MS error codes are 32 bit, and the ones in the ERR_... system is
     * only 12, we must have a mapping table between them.  */
    for (i = 0; i < ERR_MAP_SZ; i++)
    {
        if (err_map[i].ms_err == ms_err)
        {
            ERR_PUT_error(ERR_LIB_CRYPTOAPI, func, err_map[i].err, file, line);
            break;
        }
        else if (err_map[i].ms_err == 0)
        {
            /* end of table, add new entry */
            ERR_STRING_DATA *esd = calloc(2, sizeof(*esd));
            if (esd == NULL)
            {
                break;
            }
            err_map[i].ms_err = ms_err;
            err_map[i].err = esd->error = i + 100;
            esd->string = ms_error_text(ms_err);
            check_malloc_return(esd->string);
            ERR_load_strings(ERR_LIB_CRYPTOAPI, esd);
            ERR_PUT_error(ERR_LIB_CRYPTOAPI, func, err_map[i].err, file, line);
            break;
        }
    }
}

/* encrypt */
static int
rsa_pub_enc(int flen, const unsigned char *from, unsigned char *to, RSA *rsa, int padding)
{
    /* I haven't been able to trigger this one, but I want to know if it happens... */
    assert(0);

    return 0;
}

/* verify arbitrary data */
static int
rsa_pub_dec(int flen, const unsigned char *from, unsigned char *to, RSA *rsa, int padding)
{
    /* I haven't been able to trigger this one, but I want to know if it happens... */
    assert(0);

    return 0;
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
        RSAerr(RSA_F_RSA_OSSL_PRIVATE_ENCRYPT, RSA_R_UNKNOWN_PADDING_TYPE);
        return 0;
    }

    if (status != ERROR_SUCCESS)
    {
        SetLastError(status);
        CRYPTOAPIerr(CRYPTOAPI_F_NCRYPT_SIGN_HASH);
        len = 0;
    }

    /* Unlike CAPI, CNG signature is in big endian order. No reversing needed. */
    return len;
}

/* sign arbitrary data */
static int
rsa_priv_enc(int flen, const unsigned char *from, unsigned char *to, RSA *rsa, int padding)
{
    CAPI_DATA *cd = (CAPI_DATA *) RSA_meth_get0_app_data(RSA_get_method(rsa));
    HCRYPTHASH hash;
    DWORD hash_size, len, i;
    unsigned char *buf;

    if (cd == NULL)
    {
        RSAerr(RSA_F_RSA_OSSL_PRIVATE_ENCRYPT, ERR_R_PASSED_NULL_PARAMETER);
        return 0;
    }

    if (padding != RSA_PKCS1_PADDING)
    {
        /* AFAICS, CryptSignHash() *always* uses PKCS1 padding. */
        RSAerr(RSA_F_RSA_OSSL_PRIVATE_ENCRYPT, RSA_R_UNKNOWN_PADDING_TYPE);
        return 0;
    }

    if (cd->key_spec == CERT_NCRYPT_KEY_SPEC)
    {
        return priv_enc_CNG(cd, NULL, from, flen, to, RSA_size(rsa),
                            cng_padding_type(padding), 0);
    }

    /* Unfortunately, there is no "CryptSign()" function in CryptoAPI, that would
     * be way to straightforward for M$, I guess... So we have to do it this
     * tricky way instead, by creating a "Hash", and load the already-made hash
     * from 'from' into it.  */
    /* For now, we only support NID_md5_sha1 */
    if (flen != SSL_SIG_LENGTH)
    {
        RSAerr(RSA_F_RSA_OSSL_PRIVATE_ENCRYPT, RSA_R_INVALID_MESSAGE_LENGTH);
        return 0;
    }
    if (!CryptCreateHash(cd->crypt_prov, CALG_SSL3_SHAMD5, 0, 0, &hash))
    {
        CRYPTOAPIerr(CRYPTOAPI_F_CRYPT_CREATE_HASH);
        return 0;
    }
    len = sizeof(hash_size);
    if (!CryptGetHashParam(hash, HP_HASHSIZE, (BYTE *) &hash_size, &len, 0))
    {
        CRYPTOAPIerr(CRYPTOAPI_F_CRYPT_GET_HASH_PARAM);
        CryptDestroyHash(hash);
        return 0;
    }
    if ((int) hash_size != flen)
    {
        RSAerr(RSA_F_RSA_OSSL_PRIVATE_ENCRYPT, RSA_R_INVALID_MESSAGE_LENGTH);
        CryptDestroyHash(hash);
        return 0;
    }
    if (!CryptSetHashParam(hash, HP_HASHVAL, (BYTE * ) from, 0))
    {
        CRYPTOAPIerr(CRYPTOAPI_F_CRYPT_SET_HASH_PARAM);
        CryptDestroyHash(hash);
        return 0;
    }

    len = RSA_size(rsa);
    buf = malloc(len);
    if (buf == NULL)
    {
        RSAerr(RSA_F_RSA_OSSL_PRIVATE_ENCRYPT, ERR_R_MALLOC_FAILURE);
        CryptDestroyHash(hash);
        return 0;
    }
    if (!CryptSignHash(hash, cd->key_spec, NULL, 0, buf, &len))
    {
        CRYPTOAPIerr(CRYPTOAPI_F_CRYPT_SIGN_HASH);
        CryptDestroyHash(hash);
        free(buf);
        return 0;
    }
    /* and now, we have to reverse the byte-order in the result from CryptSignHash()... */
    for (i = 0; i < len; i++)
    {
        to[i] = buf[len - i - 1];
    }
    free(buf);

    CryptDestroyHash(hash);
    return len;
}

/**
 * Sign the hash in |m| and return the signature in |sig|.
 * Returns 1 on success, 0 on error.
 * NCryptSignHash() is used to sign and it is instructed to add the
 * the PKCS #1 DigestInfo header to |m| unless the hash algorithm is
 * the MD5/SHA1 combination used in TLS 1.1 and earlier versions.
 * OpenSSL exercises this callback only when padding is PKCS1 v1.5.
 */
static int
rsa_sign_CNG(int type, const unsigned char *m, unsigned int m_len,
             unsigned char *sig, unsigned int *siglen, const RSA *rsa)
{
    CAPI_DATA *cd = (CAPI_DATA *) RSA_meth_get0_app_data(RSA_get_method(rsa));
    const wchar_t *alg = NULL;
    int padding = RSA_PKCS1_PADDING;

    *siglen = 0;
    if (cd == NULL)
    {
        RSAerr(RSA_F_RSA_OSSL_PRIVATE_ENCRYPT, ERR_R_PASSED_NULL_PARAMETER);
        return 0;
    }

    alg = cng_hash_algo(type);
    if (alg && wcscmp(alg, L"UNKNOWN") == 0)
    {
        RSAerr(RSA_F_RSA_SIGN, RSA_R_UNKNOWN_ALGORITHM_TYPE);
        return 0;
    }

    *siglen = priv_enc_CNG(cd, alg, m, (int)m_len, sig, RSA_size(rsa),
                           cng_padding_type(padding), 0);

    return (*siglen == 0) ? 0 : 1;
}

/* decrypt */
static int
rsa_priv_dec(int flen, const unsigned char *from, unsigned char *to, RSA *rsa, int padding)
{
    /* I haven't been able to trigger this one, but I want to know if it happens... */
    assert(0);

    return 0;
}

/* called at RSA_new */
static int
init(RSA *rsa)
{

    return 0;
}

/* called at RSA_free */
static int
finish(RSA *rsa)
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

#if (OPENSSL_VERSION_NUMBER >= 0x10100000L)

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
        CRYPTOAPIerr(CRYPTOAPI_F_NCRYPT_SIGN_HASH);
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
        msg(M_NONFATAL,"Error: DER encoded ECDSA signature is too long (%d bytes)", len);
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

    if (cd->key_spec != CERT_NCRYPT_KEY_SPEC)
    {
        msg(M_NONFATAL, "ERROR: cryptoapicert with only legacy private key handle available."
            " EC certificate not supported.");
        goto err;
    }
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

#endif /* OPENSSL_VERSION_NUMBER >= 1.1.0 */

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
                msg(M_WARN, "WARNING: cryptoapicert: error parsing <THUMB:%s>.", cert_prop);
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
        msg(M_WARN, "WARNING: cryptoapicert: unsupported certificate specification <%s>", cert_prop);
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
        msg(M_WARN, "WARNING: cryptoapicert: ignoring certificate in store %s.",
            validity < 0 ? "not yet valid" : "that has expired");
    }

out:
    gc_free(&gc);
    return rv;
}

#if (OPENSSL_VERSION_NUMBER >= 0x10100000L)

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
            msg(M_FATAL, "cryptopaicert: Unknown key and no default sign operation to fallback on");
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
            RSAerr(RSA_F_PKEY_RSA_SIGN, RSA_R_UNKNOWN_ALGORITHM_TYPE);
            return -1;
        }
    }
    else
    {
        msg(M_NONFATAL, "cryptoapicert: could not determine the signature digest algorithm");
        RSAerr(RSA_F_PKEY_RSA_SIGN, RSA_R_UNKNOWN_ALGORITHM_TYPE);
        return -1;
    }

    if (tbslen != (size_t)hashlen)
    {
        RSAerr(RSA_F_PKEY_RSA_SIGN, RSA_R_INVALID_DIGEST_LENGTH);
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
            msg(M_NONFATAL, "cryptoapicert: Unknown MGF1 digest type or does"
                " not match the signature digest type.");
            RSAerr(RSA_F_PKEY_RSA_SIGN, RSA_R_UNSUPPORTED_MASK_PARAMETER);
        }

        if (!EVP_PKEY_CTX_get_rsa_pss_saltlen(ctx, &saltlen))
        {
            msg(M_WARN, "cryptoapicert: unable to get the salt length from context."
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
            RSAerr(RSA_F_PKEY_RSA_SIGN, RSA_R_DATA_TOO_LARGE_FOR_KEY_SIZE);
            return -1;
        }
        msg(D_LOW, "cryptoapicert: PSS padding using saltlen = %d", saltlen);
    }

    msg(D_LOW, "cryptoapicert: calling priv_enc_CNG with alg = %ls", alg);
    *siglen = priv_enc_CNG(cd, alg, tbs, (int)tbslen, sig, *siglen,
                           cng_padding_type(padding), (DWORD)saltlen);

    return (*siglen == 0) ? 0 : 1;
}

#endif /* OPENSSL_VERSION >= 1.1.0 */

static int
ssl_ctx_set_rsakey(SSL_CTX *ssl_ctx, CAPI_DATA *cd, EVP_PKEY *pkey)
{
    RSA *rsa = NULL, *pub_rsa;
    RSA_METHOD *my_rsa_method = NULL;
    bool rsa_method_set = false;

    my_rsa_method = RSA_meth_new("Microsoft Cryptography API RSA Method",
                                 RSA_METHOD_FLAG_NO_CHECK);
    check_malloc_return(my_rsa_method);
    RSA_meth_set_pub_enc(my_rsa_method, rsa_pub_enc);
    RSA_meth_set_pub_dec(my_rsa_method, rsa_pub_dec);
    RSA_meth_set_priv_enc(my_rsa_method, rsa_priv_enc);
    RSA_meth_set_priv_dec(my_rsa_method, rsa_priv_dec);
    RSA_meth_set_init(my_rsa_method, NULL);
    RSA_meth_set_finish(my_rsa_method, finish);
    RSA_meth_set0_app_data(my_rsa_method, cd);

    /*
     * For CNG, set the RSA_sign method which gets priority over priv_enc().
     * This method is called with the raw hash without the digestinfo
     * header and works better when using NCryptSignHash() with some tokens.
     * However, if PSS padding is in use, openssl does not call this
     * function but adds the padding and then calls rsa_priv_enc()
     * with padding set to NONE which is not supported by CNG.
     * So, when posisble (OpenSSL 1.1.0 and up), we hook on to the sign
     * operation in EVP_PKEY_METHOD struct.
     */
    if (cd->key_spec == CERT_NCRYPT_KEY_SPEC)
    {
#if (OPENSSL_VERSION_NUMBER < 0x10100000L)
        RSA_meth_set_sign(my_rsa_method, rsa_sign_CNG);
#else
        /* pmethod is global -- initialize only if NULL */
        if (!pmethod)
        {
            pmethod = EVP_PKEY_meth_new(EVP_PKEY_RSA, 0);
            if (!pmethod)
            {
                SSLerr(SSL_F_SSL_CTX_USE_CERTIFICATE_FILE, ERR_R_MALLOC_FAILURE);
                goto err;
            }
            const EVP_PKEY_METHOD *default_pmethod = EVP_PKEY_meth_find(EVP_PKEY_RSA);
            EVP_PKEY_meth_copy(pmethod, default_pmethod);

            /* We want to override only sign_init() and sign() */
            EVP_PKEY_meth_set_sign(pmethod, pkey_rsa_sign_init, pkey_rsa_sign);
            EVP_PKEY_meth_add0(pmethod);

            /* Keep a copy of the default sign and sign_init methods */

#if (OPENSSL_VERSION_NUMBER < 0x1010009fL)   /* > version 1.1.0i */
            /* The function signature is not const-correct in these versions */
            EVP_PKEY_meth_get_sign((EVP_PKEY_METHOD *)default_pmethod, &default_pkey_sign_init,
                                   &default_pkey_sign);
#else
            EVP_PKEY_meth_get_sign(default_pmethod, &default_pkey_sign_init,
                                   &default_pkey_sign);

#endif
        }
#endif /* (OPENSSL_VERSION_NUMBER < 0x10100000L) */
    }

    rsa = RSA_new();
    if (rsa == NULL)
    {
        SSLerr(SSL_F_SSL_CTX_USE_CERTIFICATE_FILE, ERR_R_MALLOC_FAILURE);
        goto err;
    }

    pub_rsa = EVP_PKEY_get0_RSA(pkey);
    if (!pub_rsa)
    {
        goto err;
    }

    /* Our private key is external, so we fill in only n and e from the public key */
    const BIGNUM *n = NULL;
    const BIGNUM *e = NULL;
    RSA_get0_key(pub_rsa, &n, &e, NULL);
    BIGNUM *rsa_n = BN_dup(n);
    BIGNUM *rsa_e = BN_dup(e);
    if (!rsa_n || !rsa_e || !RSA_set0_key(rsa, rsa_n, rsa_e, NULL))
    {
        BN_free(rsa_n); /* ok to free even if NULL */
        BN_free(rsa_e);
        msg(M_NONFATAL, "ERROR: %s: out of memory", __func__);
        goto err;
    }
    RSA_set_flags(rsa, RSA_flags(rsa) | RSA_FLAG_EXT_PKEY);
    if (!RSA_set_method(rsa, my_rsa_method))
    {
        goto err;
    }
    rsa_method_set = true; /* flag that method pointer will get freed with the key */
    cd->ref_count++;       /* with method, cd gets assigned to the key as well */

    if (!SSL_CTX_use_RSAPrivateKey(ssl_ctx, rsa))
    {
        goto err;
    }
    /* SSL_CTX_use_RSAPrivateKey() increased the reference count in 'rsa', so
    * we decrease it here with RSA_free(), or it will never be cleaned up. */
    RSA_free(rsa);
    return 1;

err:
    if (rsa)
    {
        RSA_free(rsa);
    }
    if (my_rsa_method && !rsa_method_set)
    {
        RSA_meth_free(my_rsa_method);
    }
    return 0;
}

int
SSL_CTX_use_CryptoAPI_certificate(SSL_CTX *ssl_ctx, const char *cert_prop)
{
    HCERTSTORE cs;
    X509 *cert = NULL;
    CAPI_DATA *cd = calloc(1, sizeof(*cd));

    if (cd == NULL)
    {
        SSLerr(SSL_F_SSL_CTX_USE_CERTIFICATE_FILE, ERR_R_MALLOC_FAILURE);
        goto err;
    }
    /* search CURRENT_USER first, then LOCAL_MACHINE */
    cs = CertOpenStore((LPCSTR) CERT_STORE_PROV_SYSTEM, 0, 0, CERT_SYSTEM_STORE_CURRENT_USER
                       |CERT_STORE_OPEN_EXISTING_FLAG | CERT_STORE_READONLY_FLAG, L"MY");
    if (cs == NULL)
    {
        CRYPTOAPIerr(CRYPTOAPI_F_CERT_OPEN_SYSTEM_STORE);
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
            CRYPTOAPIerr(CRYPTOAPI_F_CERT_OPEN_SYSTEM_STORE);
            goto err;
        }
        cd->cert_context = find_certificate_in_store(cert_prop, cs);
        CertCloseStore(cs, 0);
        if (cd->cert_context == NULL)
        {
            CRYPTOAPIerr(CRYPTOAPI_F_CERT_FIND_CERTIFICATE_IN_STORE);
            goto err;
        }
    }

    /* cert_context->pbCertEncoded is the cert X509 DER encoded. */
    cert = d2i_X509(NULL, (const unsigned char **) &cd->cert_context->pbCertEncoded,
                    cd->cert_context->cbCertEncoded);
    if (cert == NULL)
    {
        SSLerr(SSL_F_SSL_CTX_USE_CERTIFICATE_FILE, ERR_R_ASN1_LIB);
        goto err;
    }

    /* set up stuff to use the private key */
    /* We prefer to get an NCRYPT key handle so that TLS1.2 can be supported */
    DWORD flags = CRYPT_ACQUIRE_COMPARE_KEY_FLAG
                  | CRYPT_ACQUIRE_PREFER_NCRYPT_KEY_FLAG;
    if (!CryptAcquireCertificatePrivateKey(cd->cert_context, flags, NULL,
                                           &cd->crypt_prov, &cd->key_spec, &cd->free_crypt_prov))
    {
        /* if we don't have a smart card reader here, and we try to access a
         * smart card certificate, we get:
         * "Error 1223: The operation was canceled by the user." */
        CRYPTOAPIerr(CRYPTOAPI_F_CRYPT_ACQUIRE_CERTIFICATE_PRIVATE_KEY);
        goto err;
    }
    /* here we don't need to do CryptGetUserKey() or anything; all necessary key
     * info is in cd->cert_context, and then, in cd->crypt_prov.  */

    /* if we do not have an NCRYPT key handle restrict TLS to v1.1 or lower */
    int max_version = SSL_CTX_get_max_proto_version(ssl_ctx);
    if ((!max_version || max_version > TLS1_1_VERSION)
        && cd->key_spec != CERT_NCRYPT_KEY_SPEC)
    {
        msg(M_WARN, "WARNING: cryptoapicert: private key is in a legacy store."
            " Restricting TLS version to 1.1");
        if (SSL_CTX_get_min_proto_version(ssl_ctx) > TLS1_1_VERSION)
        {
            msg(M_NONFATAL,
                "ERROR: cryptoapicert: min TLS version larger than 1.1."
                " Try config option --tls-version-min 1.1");
            goto err;
        }
        if (!SSL_CTX_set_max_proto_version(ssl_ctx, TLS1_1_VERSION))
        {
            msg(M_NONFATAL, "ERROR: cryptoapicert: set max TLS version failed");
            goto err;
        }
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
#if (OPENSSL_VERSION_NUMBER >= 0x10100000L)
    else if (EVP_PKEY_id(pkey) == EVP_PKEY_EC)
    {
        if (!ssl_ctx_set_eckey(ssl_ctx, cd, pkey))
        {
            goto err;
        }
    }
#endif /* OPENSSL_VERSION_NUMBER >= 1.1.0 */
    else
    {
        msg(M_WARN, "WARNING: cryptoapicert: certificate type not supported");
        goto err;
    }
    CAPI_DATA_free(cd); /* this will do a ref_count-- */
    return 1;

err:
    CAPI_DATA_free(cd);
    return 0;
}

#else  /* ifdef ENABLE_CRYPTOAPI */
#ifdef _MSC_VER  /* Dummy function needed to avoid empty file compiler warning in Microsoft VC */
static void
dummy(void)
{
}
#endif
#endif                          /* _WIN32 */
