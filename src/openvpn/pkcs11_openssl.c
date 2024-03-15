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
 * @file PKCS #11 OpenSSL backend
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "syshead.h"

#if defined(ENABLE_PKCS11) && defined(ENABLE_CRYPTO_OPENSSL)

#include "errlevel.h"
#include "pkcs11_backend.h"
#include "ssl_verify.h"
#include "xkey_common.h"
#include <pkcs11-helper-1.0/pkcs11h-openssl.h>

#ifdef HAVE_XKEY_PROVIDER
static XKEY_EXTERNAL_SIGN_fn xkey_pkcs11h_sign;

#if PKCS11H_VERSION > ((1<<16) | (27<<8)) /* version > 1.27 */

/* Table linking OpenSSL digest NID with CKM and CKG constants in PKCS#11 */
#define MD_TYPE(n) {NID_sha ## n, CKM_SHA ## n, CKG_MGF1_SHA ## n}
static const struct
{
    int nid;
    unsigned long ckm_id;
    unsigned long mgf_id;
} mdtypes[] = {MD_TYPE(224), MD_TYPE(256), MD_TYPE(384), MD_TYPE(512),
               {NID_sha1, CKM_SHA_1, CKG_MGF1_SHA1}, /* SHA_1 naming is an oddity */
               {NID_undef, 0, 0}};

/* From sigalg, derive parameters for pss signature and fill in  pss_params.
 * Its of type CK_RSA_PKCS_PSS_PARAMS struct with three fields to be filled in:
 * {enum hashAlg, enum mgf, ulong sLen}
 * where hashAlg is CKM_SHA256 etc., mgf is CKG_MGF1_SHA256 etc.
 */
static int
set_pss_params(CK_RSA_PKCS_PSS_PARAMS *pss_params, XKEY_SIGALG sigalg,
               pkcs11h_certificate_t cert)
{
    int ret = 0;
    X509 *x509 = NULL;
    EVP_PKEY *pubkey = NULL;

    if ((x509 = pkcs11h_openssl_getX509(cert)) == NULL
        || (pubkey = X509_get0_pubkey(x509)) == NULL)
    {
        msg(M_WARN, "PKCS#11: Unable get public key");
        goto cleanup;
    }

    /* map mdname to CKM and CKG constants for hash and mgf algorithms */
    int i = 0;
    int nid = OBJ_sn2nid(sigalg.mdname);
    while (mdtypes[i].nid != NID_undef && mdtypes[i].nid != nid)
    {
        i++;
    }
    pss_params->hashAlg = mdtypes[i].ckm_id;
    pss_params->mgf = mdtypes[i].mgf_id;

    /* determine salt length */
    const EVP_MD *md = EVP_get_digestbyname(sigalg.mdname);
    if (!md)
    {
        msg(M_WARN, "WARN: set_pss_params: EVP_get_digestbyname returned NULL "
            "for mdname = <%s>", sigalg.mdname);
        goto cleanup;
    }
    int mdsize = EVP_MD_get_size(md);

    int saltlen = -1;
    if (!strcmp(sigalg.saltlen, "digest")) /* same as digest size */
    {
        saltlen = mdsize;
    }
    else if (!strcmp(sigalg.saltlen, "max")) /* maximum possible value */
    {
        saltlen = xkey_max_saltlen(EVP_PKEY_get_bits(pubkey), mdsize);
    }

    if (saltlen < 0 || pss_params->hashAlg == 0)
    {
        msg(M_WARN, "WARN: invalid RSA_PKCS1_PSS parameters: saltlen = <%s> "
            "mdname = <%s>.", sigalg.saltlen, sigalg.mdname);
        goto cleanup;
    }
    pss_params->sLen = (unsigned long) saltlen; /* saltlen >= 0 at this point */

    msg(D_XKEY, "set_pss_params: sLen = %lu, hashAlg = %lu, mgf = %lu",
        pss_params->sLen, pss_params->hashAlg, pss_params->mgf);

    ret = 1;

cleanup:
    if (x509)
    {
        X509_free(x509);
    }
    return ret;
}

#else  /* if PKCS11H_VERSION > ((1<<16) | (27<<8)) */

/* Make set_pss_params a no-op that always succeeds */
#define set_pss_params(...) (1)

/* Use a wrapper for pkcs11h_certificate_signAny_ex() for versions < 1.28
 * where its not available.
 * We just call pkcs11h_certificate_signAny() unless the padding
 * is PSS in which case we return an error.
 */
static CK_RV
pkcs11h_certificate_signAny_ex(const pkcs11h_certificate_t cert,
                               const CK_MECHANISM *mech, const unsigned char *tbs,
                               size_t tbslen, unsigned char *sig, size_t *siglen)
{
    if (mech->mechanism == CKM_RSA_PKCS_PSS)
    {
        msg(M_NONFATAL, "PKCS#11: Error: PSS padding is not supported by "
            "this version of pkcs11-helper library.");
        return CKR_MECHANISM_INVALID;
    }
    return pkcs11h_certificate_signAny(cert, mech->mechanism, tbs, tbslen, sig, siglen);
}
#endif /* PKCS11H_VERSION > 1.27 */

/**
 * Sign op called from xkey provider
 *
 * We support ECDSA, RSA_NO_PADDING, RSA_PKCS1_PADDING, RSA_PKCS_PSS_PADDING
 */
static int
xkey_pkcs11h_sign(void *handle, unsigned char *sig,
                  size_t *siglen, const unsigned char *tbs, size_t tbslen, XKEY_SIGALG sigalg)
{
    pkcs11h_certificate_t cert = handle;
    CK_MECHANISM mech = {CKM_RSA_PKCS, NULL, 0}; /* default value */
    CK_RSA_PKCS_PSS_PARAMS pss_params = {0};

    unsigned char buf[EVP_MAX_MD_SIZE];
    size_t buflen;
    size_t siglen_max = *siglen;

    unsigned char enc[EVP_MAX_MD_SIZE + 32]; /* 32 bytes enough for DigestInfo header */
    size_t enc_len = sizeof(enc);

    if (!strcmp(sigalg.op, "DigestSign"))
    {
        msg(D_XKEY, "xkey_pkcs11h_sign: computing digest");
        if (xkey_digest(tbs, tbslen, buf, &buflen, sigalg.mdname))
        {
            tbs = buf;
            tbslen = (size_t) buflen;
            sigalg.op = "Sign";
        }
        else
        {
            return 0;
        }
    }

    if (!strcmp(sigalg.keytype, "EC"))
    {
        msg(D_XKEY, "xkey_pkcs11h_sign: signing with EC key");
        mech.mechanism = CKM_ECDSA;
    }
    else if (!strcmp(sigalg.keytype, "RSA"))
    {
        msg(D_XKEY, "xkey_pkcs11h_sign: signing with RSA key: padmode = %s",
            sigalg.padmode);
        if (!strcmp(sigalg.padmode, "none"))
        {
            mech.mechanism = CKM_RSA_X_509;
        }
        else if (!strcmp(sigalg.padmode, "pss"))
        {
            mech.mechanism = CKM_RSA_PKCS_PSS;

            if (!set_pss_params(&pss_params, sigalg, cert))
            {
                return 0;
            }

            mech.pParameter = &pss_params;
            mech.ulParameterLen = sizeof(pss_params);
        }
        else if (!strcmp(sigalg.padmode, "pkcs1"))
        {
            /* CMA_RSA_PKCS needs pkcs1 encoded digest */

            if (!encode_pkcs1(enc, &enc_len, sigalg.mdname, tbs, tbslen))
            {
                return 0;
            }
            tbs = enc;
            tbslen = enc_len;
        }
        else /* should not happen */
        {
            msg(M_WARN, "PKCS#11: Unknown padmode <%s>", sigalg.padmode);
        }
    }
    else
    {
        ASSERT(0);  /* coding error -- we couldnt have created any such key */
    }

    if (CKR_OK != pkcs11h_certificate_signAny_ex(cert, &mech,
                                                 tbs, tbslen, sig, siglen))
    {
        return 0;
    }
    if (strcmp(sigalg.keytype, "EC"))
    {
        return 1;
    }

    /* For EC keys, pkcs11 returns signature as r|s: convert to der encoded */
    int derlen = ecdsa_bin2der(sig, (int) *siglen, siglen_max);

    if (derlen <= 0)
    {
        return 0;
    }
    *siglen = derlen;

    return 1;
}

/* wrapper for handle free */
static void
xkey_handle_free(void *handle)
{
    pkcs11h_certificate_freeCertificate(handle);
}


/**
 * Load certificate and public key from pkcs11h to SSL_CTX
 * through xkey provider.
 *
 * @param certificate          pkcs11h certificate object
 * @param ctx                  OpenVPN root tls context
 *
 * @returns                    1 on success, 0 on error to match
 *                             other xkey_load_.. routines
 */
static int
xkey_load_from_pkcs11h(pkcs11h_certificate_t certificate,
                       struct tls_root_ctx *const ctx)
{
    int ret = 0;

    X509 *x509 = pkcs11h_openssl_getX509(certificate);
    if (!x509)
    {
        msg(M_WARN, "PKCS#11: Unable get x509 certificate object");
        return 0;
    }

    EVP_PKEY *pubkey = X509_get0_pubkey(x509);

    XKEY_PRIVKEY_FREE_fn *free_op = xkey_handle_free; /* it calls pkcs11h_..._freeCertificate() */
    XKEY_EXTERNAL_SIGN_fn *sign_op = xkey_pkcs11h_sign;

    EVP_PKEY *pkey = xkey_load_generic_key(tls_libctx, certificate, pubkey, sign_op, free_op);
    if (!pkey)
    {
        msg(M_WARN, "PKCS#11: Failed to load private key into xkey provider");
        goto cleanup;
    }
    /* provider took ownership of the pkcs11h certificate object -- do not free below */
    certificate = NULL;

    if (!SSL_CTX_use_cert_and_key(ctx->ctx, x509, pkey, NULL, 0))
    {
        crypto_print_openssl_errors(M_WARN);
        msg(M_FATAL, "PKCS#11: Failed to set cert and private key for OpenSSL");
        goto cleanup;
    }
    ret = 1;

cleanup:
    if (x509)
    {
        X509_free(x509);
    }
    if (pkey)
    {
        EVP_PKEY_free(pkey);
    }
    if (certificate)
    {
        pkcs11h_certificate_freeCertificate(certificate);
    }
    return ret;
}
#endif /* HAVE_XKEY_PROVIDER */

int
pkcs11_init_tls_session(pkcs11h_certificate_t certificate,
                        struct tls_root_ctx *const ssl_ctx)
{

#ifdef HAVE_XKEY_PROVIDER
    return (xkey_load_from_pkcs11h(certificate, ssl_ctx) == 0); /* inverts the return value */
#else
    int ret = 1;

    X509 *x509 = NULL;
    EVP_PKEY *evp = NULL;
    pkcs11h_openssl_session_t openssl_session = NULL;

    if ((openssl_session = pkcs11h_openssl_createSession(certificate)) == NULL)
    {
        msg(M_WARN, "PKCS#11: Cannot initialize openssl session");
        goto cleanup;
    }

    /*
     * Will be released by openssl_session
     */
    certificate = NULL;

    if ((evp = pkcs11h_openssl_session_getEVP(openssl_session)) == NULL)
    {
        msg(M_WARN, "PKCS#11: Unable get evp object");
        goto cleanup;
    }

    if ((x509 = pkcs11h_openssl_session_getX509(openssl_session)) == NULL)
    {
        msg(M_WARN, "PKCS#11: Unable get certificate object");
        goto cleanup;
    }

    if (!SSL_CTX_use_PrivateKey(ssl_ctx->ctx, evp))
    {
        msg(M_WARN, "PKCS#11: Cannot set private key for openssl");
        goto cleanup;
    }

    if (!SSL_CTX_use_certificate(ssl_ctx->ctx, x509))
    {
        crypto_print_openssl_errors(M_WARN);
        msg(M_FATAL, "PKCS#11: Cannot set certificate for openssl");
        goto cleanup;
    }
    ret = 0;

cleanup:
    /*
     * Certificate freeing is usually handled by openssl_session.
     * If something went wrong, creating the session we have to do it manually.
     */
    if (certificate != NULL)
    {
        pkcs11h_certificate_freeCertificate(certificate);
        certificate = NULL;
    }

    /*
     * openssl objects have reference
     * count, so release them
     */
    X509_free(x509);
    x509 = NULL;

    EVP_PKEY_free(evp);
    evp = NULL;

    if (openssl_session != NULL)
    {
        pkcs11h_openssl_freeSession(openssl_session);
        openssl_session = NULL;
    }
    return ret;
#endif /* ifdef HAVE_XKEY_PROVIDER */
}

char *
pkcs11_certificate_dn(pkcs11h_certificate_t certificate, struct gc_arena *gc)
{
    X509 *x509 = NULL;

    char *dn = NULL;

    if ((x509 = pkcs11h_openssl_getX509(certificate)) == NULL)
    {
        msg(M_FATAL, "PKCS#11: Cannot get X509");
        goto cleanup;
    }

    dn = x509_get_subject(x509, gc);

cleanup:
    X509_free(x509);
    x509 = NULL;

    return dn;
}

int
pkcs11_certificate_serial(pkcs11h_certificate_t certificate, char *serial,
                          size_t serial_len)
{
    X509 *x509 = NULL;
    BIO *bio = NULL;
    int ret = 1;
    int n;

    if ((x509 = pkcs11h_openssl_getX509(certificate)) == NULL)
    {
        msg(M_FATAL, "PKCS#11: Cannot get X509");
        goto cleanup;
    }

    if ((bio = BIO_new(BIO_s_mem())) == NULL)
    {
        msg(M_FATAL, "PKCS#11: Cannot create BIO");
        goto cleanup;
    }

    i2a_ASN1_INTEGER(bio, X509_get_serialNumber(x509));
    n = BIO_read(bio, serial, serial_len-1);

    if (n<0)
    {
        serial[0] = '\x0';
    }
    else
    {
        serial[n] = 0;
    }

    ret = 0;

cleanup:
    X509_free(x509);
    x509 = NULL;

    return ret;
}
#endif /* defined(ENABLE_PKCS11) && defined(ENABLE_OPENSSL) */
