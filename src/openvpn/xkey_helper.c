/*
 *  OpenVPN -- An application to securely tunnel IP networks
 *             over a single TCP/UDP port, with support for SSL/TLS-based
 *             session authentication and key exchange,
 *             packet encryption, packet authentication, and
 *             packet compression.
 *
 *  Copyright (C) 2021-2024 Selva Nair <selva.nair@gmail.com>
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
#include <config.h>
#endif

#include "syshead.h"
#include "error.h"
#include "buffer.h"
#include "xkey_common.h"
#include "manage.h"
#include "base64.h"

#ifdef HAVE_XKEY_PROVIDER

#include <openssl/provider.h>
#include <openssl/params.h>
#include <openssl/core_dispatch.h>
#include <openssl/core_object.h>
#include <openssl/core_names.h>
#include <openssl/store.h>
#include <openssl/evp.h>
#include <openssl/err.h>

static const char *const props = XKEY_PROV_PROPS;

XKEY_EXTERNAL_SIGN_fn xkey_management_sign;

static void
print_openssl_errors()
{
    unsigned long e;
    while ((e = ERR_get_error()))
    {
        msg(M_WARN, "OpenSSL error %lu: %s\n", e, ERR_error_string(e, NULL));
    }
}

/** helper to compute digest */
int
xkey_digest(const unsigned char *src, size_t srclen, unsigned char *buf,
            size_t *buflen, const char *mdname)
{
    dmsg(D_XKEY, "In xkey_digest");
    EVP_MD *md = EVP_MD_fetch(NULL, mdname, NULL); /* from default context */
    if (!md)
    {
        msg(M_WARN, "WARN: xkey_digest: MD_fetch failed for <%s>", mdname);
        return 0;
    }

    unsigned int len = (unsigned int) *buflen;
    if (EVP_Digest(src, srclen, buf, &len, md, NULL) != 1)
    {
        msg(M_WARN, "WARN: xkey_digest: EVP_Digest failed");
        return 0;
    }
    EVP_MD_free(md);

    *buflen = len;
    return 1;
}

#ifdef ENABLE_MANAGEMENT
/**
 * Load external key for signing via management interface.
 * The public key must be passed in by the caller as we may not
 * be able to get it from the management.
 * Returns an EVP_PKEY object attached to xkey provider.
 * Caller must free it when no longer needed.
 */
EVP_PKEY *
xkey_load_management_key(OSSL_LIB_CTX *libctx, EVP_PKEY *pubkey)
{
    ASSERT(pubkey);

    /* Management interface doesn't require any handle to be
     * stored in the key. We use a dummy pointer as we do need a
     * non-NULL value to indicate private key is available.
     */
    void *dummy = &"dummy";

    XKEY_EXTERNAL_SIGN_fn *sign_op = xkey_management_sign;

    return xkey_load_generic_key(libctx, dummy, pubkey, sign_op, NULL);
}
#endif

/**
 * Load a generic key into the xkey provider.
 * Returns an EVP_PKEY object attached to xkey provider.
 * Caller must free it when no longer needed.
 */
EVP_PKEY *
xkey_load_generic_key(OSSL_LIB_CTX *libctx, void *handle, EVP_PKEY *pubkey,
                      XKEY_EXTERNAL_SIGN_fn *sign_op, XKEY_PRIVKEY_FREE_fn *free_op)
{
    EVP_PKEY *pkey = NULL;
    const char *origin = "external";

    /* UTF8 string pointers in here are only read from, so cast is safe */
    OSSL_PARAM params[] = {
        {"xkey-origin", OSSL_PARAM_UTF8_STRING, (char *) origin, 0, 0},
        {"pubkey", OSSL_PARAM_OCTET_STRING, &pubkey, sizeof(pubkey), 0},
        {"handle", OSSL_PARAM_OCTET_PTR, &handle, sizeof(handle), 0},
        {"sign_op", OSSL_PARAM_OCTET_PTR, (void **) &sign_op, sizeof(sign_op), 0},
        {"free_op", OSSL_PARAM_OCTET_PTR, (void **) &free_op, sizeof(free_op), 0},
        {NULL, 0, NULL, 0, 0}
    };

    /* Do not use EVP_PKEY_new_from_pkey as that will take keymgmt from pubkey */
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_from_name(libctx, EVP_PKEY_get0_type_name(pubkey), props);
    if (!ctx
        || EVP_PKEY_fromdata_init(ctx) != 1
        || EVP_PKEY_fromdata(ctx, &pkey, EVP_PKEY_KEYPAIR, params) != 1)
    {
        print_openssl_errors();
        msg(M_FATAL, "OpenSSL error: failed to load key into ovpn.xkey provider");
    }
    if (ctx)
    {
        EVP_PKEY_CTX_free(ctx);
    }

    return pkey;
}

#ifdef ENABLE_MANAGEMENT
/**
 * Signature callback for xkey_provider with management-external-key
 *
 * @param handle        Unused -- may be null
 * @param sig           On successful return signature is in sig.
 * @param siglen        On entry *siglen has length of buffer sig,
 *                      on successful return size of signature
 * @param tbs           hash or message to be signed
 * @param tbslen        len of data in dgst
 * @param sigalg        extra signature parameters
 *
 * @return              signature length or -1 on error.
 */
int
xkey_management_sign(void *unused, unsigned char *sig, size_t *siglen,
                     const unsigned char *tbs, size_t tbslen, XKEY_SIGALG alg)
{
    dmsg(D_XKEY, "In xkey_management_sign with keytype = %s, op = %s",
         alg.keytype, alg.op);

    (void) unused;
    char alg_str[128];
    unsigned char buf[EVP_MAX_MD_SIZE]; /* for computing digest if required */
    size_t buflen = sizeof(buf);

    unsigned char enc[EVP_MAX_MD_SIZE + 32]; /* 32 bytes enough for digest info structure */
    size_t enc_len = sizeof(enc);

    unsigned int flags = management->settings.flags;
    bool is_message = !strcmp(alg.op, "DigestSign"); /* tbs is message, not digest */

    /* if management client cannot do digest -- we do it here */
    if (!strcmp(alg.op, "DigestSign") && !(flags & MF_EXTERNAL_KEY_DIGEST)
        && strcmp(alg.mdname, "none"))
    {
        dmsg(D_XKEY, "xkey_management_sign: computing digest");
        if (xkey_digest(tbs, tbslen, buf, &buflen, alg.mdname))
        {
            tbs = buf;
            tbslen = buflen;
            alg.op = "Sign";
            is_message = false;
        }
        else
        {
            return 0;
        }
    }

    if (!strcmp(alg.keytype, "EC"))
    {
        if (!strcmp(alg.op, "Sign"))
        {
            strncpynt(alg_str, "ECDSA", sizeof(alg_str));
        }
        else
        {
            snprintf(alg_str, sizeof(alg_str), "ECDSA,hashalg=%s", alg.mdname);
        }
    }
    else if (!strcmp(alg.keytype, "ED448") || !strcmp(alg.keytype, "ED25519"))
    {
        strncpynt(alg_str, alg.keytype, sizeof(alg_str));
    }
    /* else assume RSA key */
    else if (!strcmp(alg.padmode, "pkcs1") && (flags & MF_EXTERNAL_KEY_PKCS1PAD))
    {
        /* For Sign, management interface expects a pkcs1 encoded digest -- add it */
        if (!strcmp(alg.op, "Sign"))
        {
            if (!encode_pkcs1(enc, &enc_len, alg.mdname, tbs, tbslen))
            {
                return 0;
            }
            tbs = enc;
            tbslen = enc_len;
            strncpynt(alg_str, "RSA_PKCS1_PADDING", sizeof(alg_str));
        }
        /* For undigested message, add hashalg=digest parameter */
        else
        {
            snprintf(alg_str, sizeof(alg_str), "%s,hashalg=%s",
                     "RSA_PKCS1_PADDING", alg.mdname);
        }
    }
    else if (!strcmp(alg.padmode, "none") && (flags & MF_EXTERNAL_KEY_NOPADDING)
             && !strcmp(alg.op, "Sign")) /* NO_PADDING requires digested data */
    {
        strncpynt(alg_str, "RSA_NO_PADDING", sizeof(alg_str));
    }
    else if (!strcmp(alg.padmode, "pss") && (flags & MF_EXTERNAL_KEY_PSSPAD))
    {
        snprintf(alg_str, sizeof(alg_str), "%s,hashalg=%s,saltlen=%s",
                 "RSA_PKCS1_PSS_PADDING", alg.mdname, alg.saltlen);
    }
    else
    {
        msg(M_NONFATAL, "RSA padding mode not supported by management-client <%s>",
            alg.padmode);
        return 0;
    }

    if (is_message)
    {
        strncat(alg_str, ",data=message", sizeof(alg_str) - strlen(alg_str) - 1);
    }

    dmsg(D_LOW, "xkey management_sign: requesting sig with algorithm <%s>", alg_str);

    char *in_b64 = NULL;
    char *out_b64 = NULL;
    int len = -1;

    int bencret = openvpn_base64_encode(tbs, (int) tbslen, &in_b64);

    if (management && bencret > 0)
    {
        out_b64 = management_query_pk_sig(management, in_b64, alg_str);
    }
    if (out_b64)
    {
        len = openvpn_base64_decode(out_b64, sig, (int) *siglen);
    }
    free(in_b64);
    free(out_b64);

    *siglen = (len > 0) ? len : 0;

    return (*siglen > 0);
}
#endif /* ENABLE MANAGEMENT */

/**
 * Add PKCS1 DigestInfo to tbs and return the result in *enc.
 *
 * @param enc           pointer to output buffer
 * @param enc_len       capacity in bytes of output buffer
 * @param mdname        name of the hash algorithm (SHA256, SHA1 etc.)
 * @param tbs           pointer to digest to be encoded
 * @param tbslen        length of data in bytes
 *
 * @return              false on error, true  on success
 *
 * On return enc_len is  set to actual size of the result.
 * enc is NULL or enc_len is not enough to store the result, it is set
 * to the required size and false is returned.
 */
bool
encode_pkcs1(unsigned char *enc, size_t *enc_len, const char *mdname,
             const unsigned char *tbs, size_t tbslen)
{
    ASSERT(enc_len != NULL);
    ASSERT(tbs != NULL);

    /* Tabulate the digest info header for expected hash algorithms
     * These were pre-computed using the DigestInfo definition:
     * DigestInfo ::= SEQUENCE {
     *    digestAlgorithm DigestAlgorithmIdentifier,
     *    digest Digest }
     * Also see the table in RFC 8017 section 9.2, Note 1.
     */

    const unsigned char sha1[] = {0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2b,
                                  0x0e, 0x03, 0x02, 0x1a, 0x05, 0x00, 0x04, 0x14};
    const unsigned char sha256[] = {0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48,
                                    0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20};
    const unsigned char sha384[] = {0x30, 0x41, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48,
                                    0x01, 0x65, 0x03, 0x04, 0x02, 0x02, 0x05, 0x00, 0x04, 0x30};
    const unsigned char sha512[] = {0x30, 0x51, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48,
                                    0x01, 0x65, 0x03, 0x04, 0x02, 0x03, 0x05, 0x00, 0x04, 0x40};
    const unsigned char sha224[] = {0x30, 0x2d, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48,
                                    0x01, 0x65, 0x03, 0x04, 0x02, 0x04, 0x05, 0x00, 0x04, 0x1c};
    const unsigned char sha512_224[] = {0x30, 0x2d, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48,
                                        0x01, 0x65, 0x03, 0x04, 0x02, 0x05, 0x05, 0x00, 0x04, 0x1c};
    const unsigned char sha512_256[] = {0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48,
                                        0x01, 0x65, 0x03, 0x04, 0x02, 0x06, 0x05, 0x00, 0x04, 0x20};

    typedef struct {
        const int nid;
        const unsigned char *header;
        size_t sz;
    } DIG_INFO;

#define MAKE_DI(x) {NID_ ## x, x, sizeof(x)}

    DIG_INFO dinfo[] = {MAKE_DI(sha1), MAKE_DI(sha256), MAKE_DI(sha384),
                        MAKE_DI(sha512), MAKE_DI(sha224), MAKE_DI(sha512_224),
                        MAKE_DI(sha512_256), {0, NULL, 0}};

    int out_len = 0;
    int ret = 0;

    int nid = OBJ_sn2nid(mdname);
    if (nid == NID_undef)
    {
        /* try harder  -- name variants like SHA2-256 doesn't work */
        nid = EVP_MD_type(EVP_get_digestbyname(mdname));
        if (nid == NID_undef)
        {
            msg(M_WARN, "Error: encode_pkcs11: invalid digest name <%s>", mdname);
            goto done;
        }
    }

    if (tbslen != EVP_MD_size(EVP_get_digestbyname(mdname)))
    {
        msg(M_WARN, "Error: encode_pkcs11: invalid input length <%d>", (int)tbslen);
        goto done;
    }

    if (nid == NID_md5_sha1) /* no encoding needed -- just copy */
    {
        if (enc && (*enc_len >= tbslen))
        {
            memcpy(enc, tbs, tbslen);
            ret = true;
        }
        out_len = tbslen;
        goto done;
    }

    /* locate entry for nid in dinfo table */
    DIG_INFO *di = dinfo;
    while ((di->nid != nid) && (di->nid != 0))
    {
        di++;
    }
    if (di->nid != nid) /* not found in our table */
    {
        msg(M_WARN, "Error: encode_pkcs11: unsupported hash algorithm <%s>", mdname);
        goto done;
    }

    out_len = tbslen + di->sz;

    if (enc && (out_len <= (int) *enc_len))
    {
        /* combine header and digest */
        memcpy(enc, di->header, di->sz);
        memcpy(enc + di->sz, tbs, tbslen);
        dmsg(D_XKEY, "encode_pkcs1: digest length = %d encoded length = %d",
             (int) tbslen, (int) out_len);
        ret = true;
    }

done:
    *enc_len = out_len; /* assignment safe as out_len is > 0 at this point */

    return ret;
}

/**
 * Helper to convert ECDSA signature with r and s concatenated
 * to a DER encoded format used by OpenSSL.
 * Returns the size of the converted signature or <= 0 on error.
 * On success, buf is overwritten by the DER encoded signature.
 */
int
ecdsa_bin2der(unsigned char *buf, int len, size_t capacity)
{
    ECDSA_SIG *ecsig = NULL;
    int rlen = len/2;
    BIGNUM *r = BN_bin2bn(buf, rlen, NULL);
    BIGNUM *s = BN_bin2bn(buf+rlen, rlen, NULL);
    if (!r || !s)
    {
        goto err;
    }
    ecsig = ECDSA_SIG_new(); /* this does not allocate r, s */
    if (!ecsig)
    {
        goto err;
    }
    if (!ECDSA_SIG_set0(ecsig, r, s)) /* ecsig takes ownership of r and s */
    {
        ECDSA_SIG_free(ecsig);
        goto err;
    }

    int derlen = i2d_ECDSA_SIG(ecsig, NULL);
    if (derlen > (int) capacity)
    {
        ECDSA_SIG_free(ecsig);
        msg(M_NONFATAL, "Error: DER encoded ECDSA signature is too long (%d)\n", derlen);
        return 0;
    }
    derlen = i2d_ECDSA_SIG(ecsig, &buf);
    ECDSA_SIG_free(ecsig);
    return derlen;

err:
    BN_free(r); /* it is ok to free NULL BN */
    BN_free(s);
    return 0;
}

#endif /* HAVE_XKEY_PROVIDER */
