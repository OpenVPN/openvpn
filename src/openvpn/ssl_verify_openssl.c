/*
 *  OpenVPN -- An application to securely tunnel IP networks
 *             over a single TCP/UDP port, with support for SSL/TLS-based
 *             session authentication and key exchange,
 *             packet encryption, packet authentication, and
 *             packet compression.
 *
 *  Copyright (C) 2002-2021 OpenVPN Inc <sales@openvpn.net>
 *  Copyright (C) 2010-2021 Fox Crypto B.V. <openvpn@fox-it.com>
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
 * @file Control Channel Verification Module OpenSSL implementation
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#elif defined(_MSC_VER)
#include "config-msvc.h"
#endif

#include "syshead.h"

#if defined(ENABLE_CRYPTO_OPENSSL)

#include "ssl_verify_openssl.h"

#include "error.h"
#include "ssl_openssl.h"
#include "ssl_verify.h"
#include "ssl_verify_backend.h"
#include "openssl_compat.h"

#include <openssl/bn.h>
#include <openssl/err.h>
#include <openssl/x509v3.h>

int
verify_callback(int preverify_ok, X509_STORE_CTX *ctx)
{
    int ret = 0;
    struct tls_session *session;
    SSL *ssl;
    struct gc_arena gc = gc_new();

    /* get the tls_session pointer */
    ssl = X509_STORE_CTX_get_ex_data(ctx, SSL_get_ex_data_X509_STORE_CTX_idx());
    ASSERT(ssl);
    session = (struct tls_session *) SSL_get_ex_data(ssl, mydata_index);
    ASSERT(session);

    X509 *current_cert = X509_STORE_CTX_get_current_cert(ctx);
    struct buffer cert_hash = x509_get_sha256_fingerprint(current_cert, &gc);
    cert_hash_remember(session, X509_STORE_CTX_get_error_depth(ctx), &cert_hash);

    /* did peer present cert which was signed by our root cert? */
    if (!preverify_ok)
    {
        /* get the X509 name */
        char *subject = x509_get_subject(current_cert, &gc);
        char *serial = backend_x509_get_serial(current_cert, &gc);

        if (!subject)
        {
            subject = "(Failed to retrieve certificate subject)";
        }

        /* Log and ignore missing CRL errors */
        if (X509_STORE_CTX_get_error(ctx) == X509_V_ERR_UNABLE_TO_GET_CRL)
        {
            msg(D_TLS_DEBUG_LOW, "VERIFY WARNING: depth=%d, %s: %s",
                X509_STORE_CTX_get_error_depth(ctx),
                X509_verify_cert_error_string(X509_STORE_CTX_get_error(ctx)),
                subject);
            ret = 1;
            goto cleanup;
        }

        /* Remote site specified a certificate, but it's not correct */
        msg(D_TLS_ERRORS, "VERIFY ERROR: depth=%d, error=%s: %s, serial=%s",
            X509_STORE_CTX_get_error_depth(ctx),
            X509_verify_cert_error_string(X509_STORE_CTX_get_error(ctx)),
            subject, serial ? serial : "<not available>");

        ERR_clear_error();

        session->verified = false;
        goto cleanup;
    }

    if (SUCCESS != verify_cert(session, current_cert, X509_STORE_CTX_get_error_depth(ctx)))
    {
        goto cleanup;
    }

    ret = 1;

cleanup:
    gc_free(&gc);

    return ret;
}

#ifdef ENABLE_X509ALTUSERNAME
bool
x509_username_field_ext_supported(const char *fieldname)
{
    int nid = OBJ_txt2nid(fieldname);
    return nid == NID_subject_alt_name || nid == NID_issuer_alt_name;
}

static
bool
extract_x509_extension(X509 *cert, char *fieldname, char *out, int size)
{
    bool retval = false;
    char *buf = 0;

    if (!x509_username_field_ext_supported(fieldname))
    {
        msg(D_TLS_ERRORS,
            "ERROR: --x509-username-field 'ext:%s' not supported", fieldname);
        return false;
    }

    int nid = OBJ_txt2nid(fieldname);
    GENERAL_NAMES *extensions = X509_get_ext_d2i(cert, nid, NULL, NULL);
    if (extensions)
    {
        int numalts;
        int i;
        /* get amount of alternatives,
         * RFC2459 claims there MUST be at least
         * one, but we don't depend on it...
         */

        numalts = sk_GENERAL_NAME_num(extensions);

        /* loop through all alternatives */
        for (i = 0; i<numalts; i++)
        {
            /* get a handle to alternative name number i */
            const GENERAL_NAME *name = sk_GENERAL_NAME_value(extensions, i );

            switch (name->type)
            {
                case GEN_EMAIL:
                    if (ASN1_STRING_to_UTF8((unsigned char **)&buf, name->d.ia5) < 0)
                    {
                        continue;
                    }
                    if (strlen(buf) != name->d.ia5->length)
                    {
                        msg(D_TLS_ERRORS, "ASN1 ERROR: string contained terminating zero");
                        OPENSSL_free(buf);
                    }
                    else
                    {
                        strncpynt(out, buf, size);
                        OPENSSL_free(buf);
                        retval = true;
                    }
                    break;

                default:
                    msg(D_TLS_DEBUG, "%s: ignoring general name field type %i",
                        __func__, name->type);
                    break;
            }
        }
        GENERAL_NAMES_free(extensions);
    }
    return retval;
}
#endif /* ENABLE_X509ALTUSERNAME */

/*
 * Extract a field from an X509 subject name.
 *
 * Example:
 *
 * /C=US/ST=CO/L=Denver/O=ORG/CN=First-CN/CN=Test-CA/Email=jim@yonan.net
 *
 * The common name is 'Test-CA'
 *
 * Return true on success, false on error (insufficient buffer size in 'out'
 * to contain result is grounds for error).
 */
static result_t
extract_x509_field_ssl(X509_NAME *x509, const char *field_name, char *out,
                       int size)
{
    int lastpos = -1;
    int tmp = -1;
    X509_NAME_ENTRY *x509ne = NULL;
    ASN1_STRING *asn1 = NULL;
    unsigned char *buf = NULL;
    ASN1_OBJECT *field_name_obj = OBJ_txt2obj(field_name, 0);

    if (field_name_obj == NULL)
    {
        msg(D_TLS_ERRORS, "Invalid X509 attribute name '%s'", field_name);
        return FAILURE;
    }

    ASSERT(size > 0);
    *out = '\0';
    do
    {
        lastpos = tmp;
        tmp = X509_NAME_get_index_by_OBJ(x509, field_name_obj, lastpos);
    } while (tmp > -1);

    ASN1_OBJECT_free(field_name_obj);

    /* Nothing found */
    if (lastpos == -1)
    {
        return FAILURE;
    }

    x509ne = X509_NAME_get_entry(x509, lastpos);
    if (!x509ne)
    {
        return FAILURE;
    }

    asn1 = X509_NAME_ENTRY_get_data(x509ne);
    if (!asn1)
    {
        return FAILURE;
    }
    if (ASN1_STRING_to_UTF8(&buf, asn1) < 0)
    {
        return FAILURE;
    }

    strncpynt(out, (char *)buf, size);

    {
        const result_t ret = (strlen((char *)buf) < size) ? SUCCESS : FAILURE;
        OPENSSL_free(buf);
        return ret;
    }
}

result_t
backend_x509_get_username(char *common_name, int cn_len,
                          char *x509_username_field, X509 *peer_cert)
{
#ifdef ENABLE_X509ALTUSERNAME
    if (strncmp("ext:",x509_username_field,4) == 0)
    {
        if (!extract_x509_extension(peer_cert, x509_username_field+4, common_name, cn_len))
        {
            return FAILURE;
        }
    }
    else
#endif
    if (FAILURE == extract_x509_field_ssl(X509_get_subject_name(peer_cert),
                                          x509_username_field, common_name, cn_len))
    {
        return FAILURE;
    }

    return SUCCESS;
}

char *
backend_x509_get_serial(openvpn_x509_cert_t *cert, struct gc_arena *gc)
{
    ASN1_INTEGER *asn1_i;
    BIGNUM *bignum;
    char *openssl_serial, *serial;

    asn1_i = X509_get_serialNumber(cert);
    bignum = ASN1_INTEGER_to_BN(asn1_i, NULL);
    openssl_serial = BN_bn2dec(bignum);

    serial = string_alloc(openssl_serial, gc);

    BN_free(bignum);
    OPENSSL_free(openssl_serial);

    return serial;
}

char *
backend_x509_get_serial_hex(openvpn_x509_cert_t *cert, struct gc_arena *gc)
{
    const ASN1_INTEGER *asn1_i = X509_get_serialNumber(cert);

    return format_hex_ex(asn1_i->data, asn1_i->length, 0, 1, ":", gc);
}

struct buffer
x509_get_sha1_fingerprint(X509 *cert, struct gc_arena *gc)
{
    const EVP_MD *sha1 = EVP_sha1();
    struct buffer hash = alloc_buf_gc(EVP_MD_size(sha1), gc);
    X509_digest(cert, EVP_sha1(), BPTR(&hash), NULL);
    ASSERT(buf_inc_len(&hash, EVP_MD_size(sha1)));
    return hash;
}

struct buffer
x509_get_sha256_fingerprint(X509 *cert, struct gc_arena *gc)
{
    const EVP_MD *sha256 = EVP_sha256();
    struct buffer hash = alloc_buf_gc(EVP_MD_size(sha256), gc);
    X509_digest(cert, EVP_sha256(), BPTR(&hash), NULL);
    ASSERT(buf_inc_len(&hash, EVP_MD_size(sha256)));
    return hash;
}

char *
x509_get_subject(X509 *cert, struct gc_arena *gc)
{
    BIO *subject_bio = NULL;
    BUF_MEM *subject_mem;
    char *subject = NULL;

    subject_bio = BIO_new(BIO_s_mem());
    if (subject_bio == NULL)
    {
        goto err;
    }

    X509_NAME_print_ex(subject_bio, X509_get_subject_name(cert),
                       0, XN_FLAG_SEP_CPLUS_SPC | XN_FLAG_FN_SN
                       |ASN1_STRFLGS_UTF8_CONVERT | ASN1_STRFLGS_ESC_CTRL);

    if (BIO_eof(subject_bio))
    {
        goto err;
    }

    BIO_get_mem_ptr(subject_bio, &subject_mem);

    subject = gc_malloc(subject_mem->length + 1, false, gc);

    memcpy(subject, subject_mem->data, subject_mem->length);
    subject[subject_mem->length] = '\0';

err:
    if (subject_bio)
    {
        BIO_free(subject_bio);
    }

    return subject;
}


/*
 * x509-track implementation -- save X509 fields to environment,
 * using the naming convention:
 *
 *  X509_{cert_depth}_{name}={value}
 *
 * This function differs from x509_setenv below in the following ways:
 *
 * (1) Only explicitly named attributes in xt are saved, per usage
 *     of "x509-track" program options.
 * (2) Only the level 0 cert info is saved unless the XT_FULL_CHAIN
 *     flag is set in xt->flags (corresponds with prepending a '+'
 *     to the name when specified by "x509-track" program option).
 * (3) This function supports both X509 subject name fields as
 *     well as X509 V3 extensions.
 * (4) This function can return the SHA1 fingerprint of a cert, e.g.
 *       x509-track "+SHA1"
 *     will return the SHA1 fingerprint for each certificate in the
 *     peer chain.
 */

void
x509_track_add(const struct x509_track **ll_head, const char *name, int msglevel, struct gc_arena *gc)
{
    struct x509_track *xt;
    ALLOC_OBJ_CLEAR_GC(xt, struct x509_track, gc);
    if (*name == '+')
    {
        xt->flags |= XT_FULL_CHAIN;
        ++name;
    }
    xt->name = name;
    xt->nid = OBJ_txt2nid(name);
    if (xt->nid != NID_undef)
    {
        xt->next = *ll_head;
        *ll_head = xt;
    }
    else
    {
        msg(msglevel, "x509_track: no such attribute '%s'", name);
    }
}

/* worker method for setenv_x509_track */
static void
do_setenv_x509(struct env_set *es, const char *name, char *value, int depth)
{
    char *name_expand;
    size_t name_expand_size;

    string_mod(value, CC_ANY, CC_CRLF, '?');
    msg(D_X509_ATTR, "X509 ATTRIBUTE name='%s' value='%s' depth=%d", name, value, depth);
    name_expand_size = 64 + strlen(name);
    name_expand = (char *) malloc(name_expand_size);
    check_malloc_return(name_expand);
    openvpn_snprintf(name_expand, name_expand_size, "X509_%d_%s", depth, name);
    setenv_str(es, name_expand, value);
    free(name_expand);
}

void
x509_setenv_track(const struct x509_track *xt, struct env_set *es, const int depth, X509 *x509)
{
    struct gc_arena gc = gc_new();
    X509_NAME *x509_name = X509_get_subject_name(x509);
    const char nullc = '\0';

    while (xt)
    {
        if (depth == 0 || (xt->flags & XT_FULL_CHAIN))
        {
            switch (xt->nid)
            {
                case NID_sha1:
                case NID_sha256:
                {
                    struct buffer fp_buf;
                    char *fp_str = NULL;

                    if (xt->nid == NID_sha1)
                    {
                        fp_buf = x509_get_sha1_fingerprint(x509, &gc);
                    }
                    else
                    {
                        fp_buf = x509_get_sha256_fingerprint(x509, &gc);
                    }

                    fp_str = format_hex_ex(BPTR(&fp_buf), BLEN(&fp_buf), 0,
                                           1 | FHE_CAPS, ":", &gc);
                    do_setenv_x509(es, xt->name, fp_str, depth);
                }
                break;

                default:
                {
                    int i = X509_NAME_get_index_by_NID(x509_name, xt->nid, -1);
                    if (i >= 0)
                    {
                        X509_NAME_ENTRY *ent = X509_NAME_get_entry(x509_name, i);
                        if (ent)
                        {
                            ASN1_STRING *val = X509_NAME_ENTRY_get_data(ent);
                            unsigned char *buf = NULL;
                            if (ASN1_STRING_to_UTF8(&buf, val) >= 0)
                            {
                                do_setenv_x509(es, xt->name, (char *)buf, depth);
                                OPENSSL_free(buf);
                            }
                        }
                    }
                    else
                    {
                        i = X509_get_ext_by_NID(x509, xt->nid, -1);
                        if (i >= 0)
                        {
                            X509_EXTENSION *ext = X509_get_ext(x509, i);
                            if (ext)
                            {
                                BIO *bio = BIO_new(BIO_s_mem());
                                if (bio)
                                {
                                    if (X509V3_EXT_print(bio, ext, 0, 0))
                                    {
                                        if (BIO_write(bio, &nullc, 1) == 1)
                                        {
                                            char *str;
                                            BIO_get_mem_data(bio, &str);
                                            do_setenv_x509(es, xt->name, str, depth);
                                        }
                                    }
                                    BIO_free(bio);
                                }
                            }
                        }
                    }
                }
            }
        }
        xt = xt->next;
    }
    gc_free(&gc);
}

/*
 * Save X509 fields to environment, using the naming convention:
 *
 *  X509_{cert_depth}_{name}={value}
 */
void
x509_setenv(struct env_set *es, int cert_depth, openvpn_x509_cert_t *peer_cert)
{
    int i, n;
    int fn_nid;
    ASN1_OBJECT *fn;
    ASN1_STRING *val;
    X509_NAME_ENTRY *ent;
    const char *objbuf;
    unsigned char *buf = NULL;
    char *name_expand;
    size_t name_expand_size;
    X509_NAME *x509 = X509_get_subject_name(peer_cert);

    n = X509_NAME_entry_count(x509);
    for (i = 0; i < n; ++i)
    {
        ent = X509_NAME_get_entry(x509, i);
        if (!ent)
        {
            continue;
        }
        fn = X509_NAME_ENTRY_get_object(ent);
        if (!fn)
        {
            continue;
        }
        val = X509_NAME_ENTRY_get_data(ent);
        if (!val)
        {
            continue;
        }
        fn_nid = OBJ_obj2nid(fn);
        if (fn_nid == NID_undef)
        {
            continue;
        }
        objbuf = OBJ_nid2sn(fn_nid);
        if (!objbuf)
        {
            continue;
        }
        if (ASN1_STRING_to_UTF8(&buf, val) < 0)
        {
            continue;
        }
        name_expand_size = 64 + strlen(objbuf);
        name_expand = (char *) malloc(name_expand_size);
        check_malloc_return(name_expand);
        openvpn_snprintf(name_expand, name_expand_size, "X509_%d_%s", cert_depth,
                         objbuf);
        string_mod(name_expand, CC_PRINT, CC_CRLF, '_');
        string_mod((char *)buf, CC_PRINT, CC_CRLF, '_');
        setenv_str_incr(es, name_expand, (char *)buf);
        free(name_expand);
        OPENSSL_free(buf);
    }
}

result_t
x509_verify_ns_cert_type(openvpn_x509_cert_t *peer_cert, const int usage)
{
    if (usage == NS_CERT_CHECK_NONE)
    {
        return SUCCESS;
    }
    if (usage == NS_CERT_CHECK_CLIENT)
    {
        /*
         * Unfortunately, X509_check_purpose() does some weird thing that
         * prevent it to take a const argument
         */
        result_t result = X509_check_purpose(peer_cert, X509_PURPOSE_SSL_CLIENT, 0) ?
                          SUCCESS : FAILURE;

        /*
         * old versions of OpenSSL allow us to make the less strict check we used to
         * do. If this less strict check pass, warn user that this might not be the
         * case when its distribution will update to OpenSSL 1.1
         */
        if (result == FAILURE)
        {
            ASN1_BIT_STRING *ns;
            ns = X509_get_ext_d2i(peer_cert, NID_netscape_cert_type, NULL, NULL);
            result = (ns && ns->length > 0 && (ns->data[0] & NS_SSL_CLIENT)) ? SUCCESS : FAILURE;
            if (result == SUCCESS)
            {
                msg(M_WARN, "X509: Certificate is a client certificate yet it's purpose "
                    "cannot be verified (check may fail in the future)");
            }
            ASN1_BIT_STRING_free(ns);
        }
        return result;
    }
    if (usage == NS_CERT_CHECK_SERVER)
    {
        /*
         * Unfortunately, X509_check_purpose() does some weird thing that
         * prevent it to take a const argument
         */
        result_t result = X509_check_purpose(peer_cert, X509_PURPOSE_SSL_SERVER, 0) ?
                          SUCCESS : FAILURE;

        /*
         * old versions of OpenSSL allow us to make the less strict check we used to
         * do. If this less strict check pass, warn user that this might not be the
         * case when its distribution will update to OpenSSL 1.1
         */
        if (result == FAILURE)
        {
            ASN1_BIT_STRING *ns;
            ns = X509_get_ext_d2i(peer_cert, NID_netscape_cert_type, NULL, NULL);
            result = (ns && ns->length > 0 && (ns->data[0] & NS_SSL_SERVER)) ? SUCCESS : FAILURE;
            if (result == SUCCESS)
            {
                msg(M_WARN, "X509: Certificate is a server certificate yet it's purpose "
                    "cannot be verified (check may fail in the future)");
            }
            ASN1_BIT_STRING_free(ns);
        }
        return result;
    }

    return FAILURE;
}

result_t
x509_verify_cert_ku(X509 *x509, const unsigned *const expected_ku,
                    int expected_len)
{
    ASN1_BIT_STRING *ku = X509_get_ext_d2i(x509, NID_key_usage, NULL, NULL);

    if (ku == NULL)
    {
        msg(D_TLS_ERRORS, "Certificate does not have key usage extension");
        return FAILURE;
    }

    if (expected_ku[0] == OPENVPN_KU_REQUIRED)
    {
        /* Extension required, value checked by TLS library */
        ASN1_BIT_STRING_free(ku);
        return SUCCESS;
    }

    unsigned nku = 0;
    for (size_t i = 0; i < 8; i++)
    {
        if (ASN1_BIT_STRING_get_bit(ku, i))
        {
            nku |= 1 << (7 - i);
        }
    }

    /*
     * Fixup if no LSB bits
     */
    if ((nku & 0xff) == 0)
    {
        nku >>= 8;
    }

    msg(D_HANDSHAKE, "Validating certificate key usage");
    result_t fFound = FAILURE;
    for (size_t i = 0; fFound != SUCCESS && i < expected_len; i++)
    {
        if (expected_ku[i] != 0 && (nku & expected_ku[i]) == expected_ku[i])
        {
            fFound = SUCCESS;
        }
    }

    if (fFound != SUCCESS)
    {
        msg(D_TLS_ERRORS,
            "ERROR: Certificate has key usage %04x, expected one of:", nku);
        for (size_t i = 0; i < expected_len && expected_ku[i]; i++)
        {
            msg(D_TLS_ERRORS, " * %04x", expected_ku[i]);
        }
    }

    ASN1_BIT_STRING_free(ku);

    return fFound;
}

result_t
x509_verify_cert_eku(X509 *x509, const char *const expected_oid)
{
    EXTENDED_KEY_USAGE *eku = NULL;
    result_t fFound = FAILURE;

    if ((eku = (EXTENDED_KEY_USAGE *) X509_get_ext_d2i(x509, NID_ext_key_usage,
                                                       NULL, NULL)) == NULL)
    {
        msg(D_HANDSHAKE, "Certificate does not have extended key usage extension");
    }
    else
    {
        int i;

        msg(D_HANDSHAKE, "Validating certificate extended key usage");
        for (i = 0; SUCCESS != fFound && i < sk_ASN1_OBJECT_num(eku); i++)
        {
            ASN1_OBJECT *oid = sk_ASN1_OBJECT_value(eku, i);
            char szOid[1024];

            if (SUCCESS != fFound && OBJ_obj2txt(szOid, sizeof(szOid), oid, 0) != -1)
            {
                msg(D_HANDSHAKE, "++ Certificate has EKU (str) %s, expects %s",
                    szOid, expected_oid);
                if (!strcmp(expected_oid, szOid))
                {
                    fFound = SUCCESS;
                }
            }
            if (SUCCESS != fFound && OBJ_obj2txt(szOid, sizeof(szOid), oid, 1) != -1)
            {
                msg(D_HANDSHAKE, "++ Certificate has EKU (oid) %s, expects %s",
                    szOid, expected_oid);
                if (!strcmp(expected_oid, szOid))
                {
                    fFound = SUCCESS;
                }
            }
        }
    }

    if (eku != NULL)
    {
        sk_ASN1_OBJECT_pop_free(eku, ASN1_OBJECT_free);
    }

    return fFound;
}

result_t
x509_write_pem(FILE *peercert_file, X509 *peercert)
{
    if (PEM_write_X509(peercert_file, peercert) < 0)
    {
        msg(M_NONFATAL, "Failed to write peer certificate in PEM format");
        return FAILURE;
    }
    return SUCCESS;
}

bool
tls_verify_crl_missing(const struct tls_options *opt)
{
    if (!opt->crl_file || (opt->ssl_flags & SSLF_CRL_VERIFY_DIR))
    {
        return false;
    }

    X509_STORE *store = SSL_CTX_get_cert_store(opt->ssl_ctx.ctx);
    if (!store)
    {
        crypto_msg(M_FATAL, "Cannot get certificate store");
    }

    STACK_OF(X509_OBJECT) *objs = X509_STORE_get0_objects(store);
    for (int i = 0; i < sk_X509_OBJECT_num(objs); i++)
    {
        X509_OBJECT *obj = sk_X509_OBJECT_value(objs, i);
        ASSERT(obj);
        if (X509_OBJECT_get_type(obj) == X509_LU_CRL)
        {
            return false;
        }
    }
    return true;
}

#endif /* defined(ENABLE_CRYPTO_OPENSSL) */
