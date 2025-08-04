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
#include "xkey_common.h"
#include "crypto_openssl.h"

#ifndef HAVE_XKEY_PROVIDER

int
SSL_CTX_use_CryptoAPI_certificate(SSL_CTX *ssl_ctx, const char *cert_prop)
{
    msg(M_NONFATAL, "ERROR: this binary was built without cryptoapicert support");
    return 0;
}

#else /* HAVE_XKEY_PROVIDER */

static XKEY_EXTERNAL_SIGN_fn xkey_cng_sign;

typedef struct _CAPI_DATA {
    const CERT_CONTEXT *cert_context;
    HCRYPTPROV_OR_NCRYPT_KEY_HANDLE crypt_prov;
    EVP_PKEY *pubkey;
    DWORD key_spec;
    BOOL free_crypt_prov;
    int ref_count;
} CAPI_DATA;

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
    EVP_PKEY_free(cd->pubkey); /* passing NULL is okay */

    free(cd);
}

/**
 * Parse a hex string with optional embedded spaces into
 * a byte array.
 * @param p         pointer to the input string
 * @param arr       on output contains the parsed bytes
 * @param capacity  capacity of the byte array arr
 * @returns the number of bytes parsed or 0 on error
 */
int
parse_hexstring(const char *p, unsigned char *arr, size_t capacity)
{
    int i = 0;
    for ( ; *p && i < capacity; p += 2)
    {
        /* skip spaces */
        while (*p == ' ')
        {
            p++;
        }
        if (!*p) /* ending with spaces is not an error */
        {
            break;
        }

        if (!isxdigit(p[0]) || !isxdigit(p[1])
            || sscanf(p, "%2hhx", &arr[i++]) != 1)
        {
            return 0;
        }
    }
    return i;
}

static void *
decode_object(struct gc_arena *gc, LPCSTR struct_type,
              const CRYPT_OBJID_BLOB *val, DWORD flags, DWORD *cb)
{
    /* get byte count for decoding */
    BYTE *buf;
    if (!CryptDecodeObject(X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, struct_type,
                           val->pbData, val->cbData, flags, NULL, cb))
    {
        return NULL;
    }

    /* do the actual decode */
    buf = gc_malloc(*cb, false, gc);
    if (!CryptDecodeObject(X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, struct_type,
                           val->pbData, val->cbData, flags, buf, cb))
    {
        return NULL;
    }

    return buf;
}

static const CRYPT_OID_INFO *
find_oid(DWORD keytype, const void *key, DWORD groupid)
{
    const CRYPT_OID_INFO *info = NULL;

    /* try proper resolve, also including AD */
    info = CryptFindOIDInfo(keytype, (void *)key, groupid);

    /* fall back to all groups if not found yet */
    if (!info && groupid)
    {
        info = CryptFindOIDInfo(keytype, (void *)key, 0);
    }

    return info;
}

static bool
test_certificate_template(const char *cert_prop, const CERT_CONTEXT *cert_ctx)
{
    const CERT_INFO *info = cert_ctx->pCertInfo;
    const CERT_EXTENSION *ext;
    DWORD cbext;
    void *pvext;
    struct gc_arena gc = gc_new();
    const WCHAR *tmpl_name = wide_string(cert_prop, &gc);

    /* check for V2 extension (Windows 2003+) */
    ext = CertFindExtension(szOID_CERTIFICATE_TEMPLATE, info->cExtension, info->rgExtension);
    if (ext)
    {
        pvext = decode_object(&gc, X509_CERTIFICATE_TEMPLATE, &ext->Value, 0, &cbext);
        if (pvext && cbext >= sizeof(CERT_TEMPLATE_EXT))
        {
            const CERT_TEMPLATE_EXT *cte = (const CERT_TEMPLATE_EXT *)pvext;
            if (!stricmp(cert_prop, cte->pszObjId))
            {
                /* found direct OID match with certificate property specified */
                gc_free(&gc);
                return true;
            }

            const CRYPT_OID_INFO *tmpl_oid = find_oid(CRYPT_OID_INFO_NAME_KEY, tmpl_name,
                                                      CRYPT_TEMPLATE_OID_GROUP_ID);
            if (tmpl_oid && !stricmp(tmpl_oid->pszOID, cte->pszObjId))
            {
                /* found OID match in extension against resolved key */
                gc_free(&gc);
                return true;
            }
        }
    }

    /* no extension found, exit */
    gc_free(&gc);
    return false;
}

static const CERT_CONTEXT *
find_certificate_in_store(const char *cert_prop, HCERTSTORE cert_store)
{
    /* Find, and use, the desired certificate from the store. The
     * 'cert_prop' certificate search string can look like this:
     * SUBJ:<certificate substring to match>
     * THUMB:<certificate thumbprint hex value>, e.g.
     *     THUMB:f6 49 24 41 01 b4 fb 44 0c ce f4 36 ae d0 c4 c9 df 7a b6 28
     * TMPL:<template name or OID>
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
    else if (!strncmp(cert_prop, "ISSUER:", 7))
    {
        find_param = wide_string(cert_prop + 7, &gc);
        find_type = CERT_FIND_ISSUER_STR_W;
    }
    else if (!strncmp(cert_prop, "THUMB:", 6))
    {
        find_type = CERT_FIND_HASH;
        find_param = &blob;

        blob.cbData = parse_hexstring(cert_prop + 6, hash, sizeof(hash));
        if (blob.cbData == 0)
        {
            msg(M_WARN|M_INFO, "WARNING: cryptoapicert: error parsing <%s>.", cert_prop);
            goto out;
        }
    }
    else if (!strncmp(cert_prop, "TMPL:", 5))
    {
        cert_prop += 5;
        find_param = NULL;
        find_type = CERT_FIND_HAS_PRIVATE_KEY;
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
        if (!rv)
        {
            break;
        }
        /* if searching by template name, check now if it matches */
        if (find_type == CERT_FIND_HAS_PRIVATE_KEY
            && !test_certificate_template(cert_prop, rv))
        {
            continue;
        }
        validity = CertVerifyTimeValidity(NULL, rv->pCertInfo);
        if (validity == 0)
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

/** Sign hash in tbs using EC key in cd and NCryptSignHash */
static int
xkey_cng_ec_sign(CAPI_DATA *cd, unsigned char *sig, size_t *siglen, const unsigned char *tbs,
                 size_t tbslen)
{
    DWORD len = *siglen;

    msg(D_LOW, "Signing using NCryptSignHash with EC key");

    DWORD status = NCryptSignHash(cd->crypt_prov, NULL, (BYTE *)tbs, tbslen, sig, len, &len, 0);

    if (status != ERROR_SUCCESS)
    {
        SetLastError(status);
        msg(M_NONFATAL|M_ERRNO, "Error in cryptoapicert: ECDSA signature using CNG failed.");
        return 0;
    }

    /* NCryptSignHash returns r|s -- convert to DER encoded buffer expected by OpenSSL */
    int derlen = ecdsa_bin2der(sig, (int) len, *siglen);
    if (derlen <= 0)
    {
        return 0;
    }
    *siglen = derlen;
    return 1;
}

/** Sign hash in tbs using RSA key in cd and NCryptSignHash */
static int
xkey_cng_rsa_sign(CAPI_DATA *cd, unsigned char *sig, size_t *siglen, const unsigned char *tbs,
                  size_t tbslen, XKEY_SIGALG sigalg)
{
    dmsg(D_LOW, "In xkey_cng_rsa_sign");

    ASSERT(cd);
    ASSERT(sig);
    ASSERT(tbs);

    DWORD status = ERROR_SUCCESS;
    DWORD len = 0;

    const wchar_t *hashalg = cng_hash_algo(OBJ_sn2nid(sigalg.mdname));

    if (hashalg && wcscmp(hashalg, L"UNKNOWN") == 0)
    {
        msg(M_NONFATAL, "Error in cryptoapicert: Unknown hash name <%s>", sigalg.mdname);
        return 0;
    }

    if (!strcmp(sigalg.padmode, "pkcs1"))
    {
        msg(D_LOW, "Signing using NCryptSignHash with PKCS1 padding: hashalg <%s>", sigalg.mdname);

        BCRYPT_PKCS1_PADDING_INFO padinfo = {hashalg};
        status = NCryptSignHash(cd->crypt_prov, &padinfo, (BYTE *)tbs, (DWORD)tbslen,
                                sig, (DWORD)*siglen, &len, BCRYPT_PAD_PKCS1);
    }
    else if (!strcmp(sigalg.padmode, "pss"))
    {
        int saltlen = tbslen; /* digest size by default */
        if (!strcmp(sigalg.saltlen, "max"))
        {
            saltlen = xkey_max_saltlen(EVP_PKEY_bits(cd->pubkey), tbslen);
            if (saltlen < 0)
            {
                msg(M_NONFATAL, "Error in cryptoapicert: invalid salt length (%d)", saltlen);
                return 0;
            }
        }

        msg(D_LOW, "Signing using NCryptSignHash with PSS padding: hashalg <%s>, saltlen <%d>",
            sigalg.mdname, saltlen);

        BCRYPT_PSS_PADDING_INFO padinfo = {hashalg, (DWORD) saltlen}; /* cast is safe as saltlen >= 0 */
        status = NCryptSignHash(cd->crypt_prov, &padinfo, (BYTE *)tbs, (DWORD) tbslen,
                                sig, (DWORD)*siglen, &len, BCRYPT_PAD_PSS);
    }
    else
    {
        msg(M_NONFATAL, "Error in cryptoapicert: Unsupported padding mode <%s>", sigalg.padmode);
        return 0;
    }

    if (status != ERROR_SUCCESS)
    {
        SetLastError(status);
        msg(M_NONFATAL|M_ERRNO, "Error in cryptoapicert: RSA signature using CNG failed.");
        return 0;
    }

    *siglen = len;
    return (*siglen > 0);
}

/** Dispatch sign op to xkey_cng_<rsa/ec>_sign */
static int
xkey_cng_sign(void *handle, unsigned char *sig, size_t *siglen, const unsigned char *tbs,
              size_t tbslen, XKEY_SIGALG sigalg)
{
    dmsg(D_LOW, "In xkey_cng_sign");

    CAPI_DATA *cd = handle;
    ASSERT(cd);
    ASSERT(sig);
    ASSERT(tbs);

    unsigned char mdbuf[EVP_MAX_MD_SIZE];
    size_t buflen = _countof(mdbuf);

    /* compute digest if required */
    if (!strcmp(sigalg.op, "DigestSign"))
    {
        if (!xkey_digest(tbs, tbslen, mdbuf, &buflen, sigalg.mdname))
        {
            return 0;
        }
        tbs = mdbuf;
        tbslen = buflen;
    }

    if (!strcmp(sigalg.keytype, "EC"))
    {
        return xkey_cng_ec_sign(cd, sig, siglen, tbs, tbslen);
    }
    else if (!strcmp(sigalg.keytype, "RSA"))
    {
        return xkey_cng_rsa_sign(cd, sig, siglen, tbs, tbslen, sigalg);
    }
    else
    {
        return 0; /* Unknown keytype -- should not happen */
    }
}

static char *
get_cert_name(const CERT_CONTEXT *cc, struct gc_arena *gc)
{
    DWORD len = CertGetNameStringW(cc, CERT_NAME_FRIENDLY_DISPLAY_TYPE, 0, NULL, NULL, 0);
    char *name = NULL;
    if (len)
    {
        wchar_t *wname = gc_malloc(len*sizeof(wchar_t), false, gc);
        if (!wname
            || CertGetNameStringW(cc, CERT_NAME_FRIENDLY_DISPLAY_TYPE, 0, NULL, wname, len) == 0)
        {
            return NULL;
        }
        name = utf16to8(wname, gc);
    }
    return name;
}

/**
 * Load certificate matching 'cert_prop' from Windows cert store
 * into xkey provider and return pointers to X509 cert and private key.
 * Returns 1 on success, 0 on error.
 * Caller must free 'cert' and 'privkey' after use.
 */
static int
Load_CryptoAPI_certificate(const char *cert_prop, X509 **cert, EVP_PKEY **privkey)
{

    HCERTSTORE cs;
    CAPI_DATA *cd = calloc(1, sizeof(*cd));
    struct gc_arena gc = gc_new();

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

    /* try to log the "name" of the selected certificate */
    char *cert_name = get_cert_name(cd->cert_context, &gc);
    if (cert_name)
    {
        msg(D_LOW, "cryptapicert: using certificate with name <%s>", cert_name);
    }

    /* cert_context->pbCertEncoded is the cert X509 DER encoded. */
    *cert = d2i_X509(NULL, (const unsigned char **) &cd->cert_context->pbCertEncoded,
                     cd->cert_context->cbCertEncoded);
    if (*cert == NULL)
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
        X509_free(*cert);
        goto err;
    }

    /* the public key */
    EVP_PKEY *pkey = X509_get_pubkey(*cert);
    cd->pubkey = pkey; /* will be freed with cd */

    *privkey = xkey_load_generic_key(tls_libctx, cd, pkey,
                                     xkey_cng_sign, (XKEY_PRIVKEY_FREE_fn *) CAPI_DATA_free);
    gc_free(&gc);
    return 1; /* do not free cd -- its kept by xkey provider */

err:
    CAPI_DATA_free(cd);
    gc_free(&gc);
    return 0;
}

int
SSL_CTX_use_CryptoAPI_certificate(SSL_CTX *ssl_ctx, const char *cert_prop)
{
    X509 *cert = NULL;
    EVP_PKEY *privkey = NULL;
    int ret = 0;

    if (!Load_CryptoAPI_certificate(cert_prop, &cert, &privkey))
    {
        return ret;
    }
    if (SSL_CTX_use_certificate(ssl_ctx, cert)
        && SSL_CTX_use_PrivateKey(ssl_ctx, privkey))
    {
        crypto_print_openssl_errors(M_WARN);
        ret = 1;
    }

    /* Always free cert and privkey even if retained by ssl_ctx as
     * they are reference counted */
    X509_free(cert);
    EVP_PKEY_free(privkey);
    return ret;
}

#endif  /* HAVE_XKEY_PROVIDER */
#endif                          /* _WIN32 */
