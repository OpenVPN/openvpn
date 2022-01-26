/*
 *  OpenVPN -- An application to securely tunnel IP networks
 *             over a single TCP/UDP port, with support for SSL/TLS-based
 *             session authentication and key exchange,
 *             packet encryption, packet authentication, and
 *             packet compression.
 *
 *  Copyright (C) 2002-2022 OpenVPN Inc <sales@openvpn.net>
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
 * @file Control Channel Verification Module mbed TLS backend
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#elif defined(_MSC_VER)
#include "config-msvc.h"
#endif

#include "syshead.h"

#if defined(ENABLE_CRYPTO_MBEDTLS)

#include "crypto_mbedtls.h"
#include "ssl_verify.h"
#include <mbedtls/asn1.h>
#include <mbedtls/error.h>
#include <mbedtls/bignum.h>
#include <mbedtls/oid.h>
#include <mbedtls/sha1.h>

#define MAX_SUBJECT_LENGTH 256

int
verify_callback(void *session_obj, mbedtls_x509_crt *cert, int cert_depth,
                uint32_t *flags)
{
    struct tls_session *session = (struct tls_session *) session_obj;
    struct gc_arena gc = gc_new();

    ASSERT(cert);
    ASSERT(session);

    session->verified = false;

    /* Remember certificate hash */
    struct buffer cert_fingerprint = x509_get_sha256_fingerprint(cert, &gc);
    cert_hash_remember(session, cert_depth, &cert_fingerprint);

    /* did peer present cert which was signed by our root cert? */
    if (*flags != 0)
    {
        int ret = 0;
        char errstr[512] = { 0 };
        char *subject = x509_get_subject(cert, &gc);
        char *serial = backend_x509_get_serial(cert, &gc);

        ret = mbedtls_x509_crt_verify_info(errstr, sizeof(errstr)-1, "", *flags);
        if (ret <= 0 && !openvpn_snprintf(errstr, sizeof(errstr),
                                          "Could not retrieve error string, flags=%" PRIx32, *flags))
        {
            errstr[0] = '\0';
        }
        else
        {
            chomp(errstr);
        }

        if (subject)
        {
            msg(D_TLS_ERRORS, "VERIFY ERROR: depth=%d, subject=%s, serial=%s: %s",
                cert_depth, subject, serial ? serial : "<not available>", errstr);
        }
        else
        {
            msg(D_TLS_ERRORS, "VERIFY ERROR: depth=%d, (could not extract X509 "
                "subject string from certificate): %s", cert_depth, errstr);
        }

        /* Leave flags set to non-zero to indicate that the cert is not ok */
    }
    else if (SUCCESS != verify_cert(session, cert, cert_depth))
    {
        *flags |= MBEDTLS_X509_BADCERT_OTHER;
    }

    gc_free(&gc);

    /*
     * PolarSSL/mbed TLS-1.2.0+ expects 0 on anything except fatal errors.
     */
    return 0;
}

#ifdef ENABLE_X509ALTUSERNAME
#warning "X509 alt user name not yet supported for mbed TLS"
#endif

result_t
backend_x509_get_username(char *cn, int cn_len,
                          char *x509_username_field, mbedtls_x509_crt *cert)
{
    mbedtls_x509_name *name;

    ASSERT( cn != NULL );

    name = &cert->subject;

    /* Find common name */
    while (name != NULL)
    {
        if (0 == memcmp(name->oid.p, MBEDTLS_OID_AT_CN,
                        MBEDTLS_OID_SIZE(MBEDTLS_OID_AT_CN)))
        {
            break;
        }

        name = name->next;
    }

    /* Not found, return an error if this is the peer's certificate */
    if (name == NULL)
    {
        return FAILURE;
    }

    /* Found, extract CN */
    if (cn_len > name->val.len)
    {
        memcpy( cn, name->val.p, name->val.len );
        cn[name->val.len] = '\0';
    }
    else
    {
        memcpy( cn, name->val.p, cn_len);
        cn[cn_len-1] = '\0';
    }

    return SUCCESS;
}

char *
backend_x509_get_serial(mbedtls_x509_crt *cert, struct gc_arena *gc)
{
    char *buf = NULL;
    size_t buflen = 0;
    mbedtls_mpi serial_mpi = { 0 };

    /* Transform asn1 integer serial into mbed TLS MPI */
    mbedtls_mpi_init(&serial_mpi);
    if (!mbed_ok(mbedtls_mpi_read_binary(&serial_mpi, cert->serial.p,
                                         cert->serial.len)))
    {
        msg(M_WARN, "Failed to retrieve serial from certificate.");
        goto end;
    }

    /* Determine decimal representation length, allocate buffer */
    mbedtls_mpi_write_string(&serial_mpi, 10, NULL, 0, &buflen);
    buf = gc_malloc(buflen, true, gc);

    /* Write MPI serial as decimal string into buffer */
    if (!mbed_ok(mbedtls_mpi_write_string(&serial_mpi, 10, buf, buflen, &buflen)))
    {
        msg(M_WARN, "Failed to write serial to string.");
        buf = NULL;
        goto end;
    }

end:
    mbedtls_mpi_free(&serial_mpi);
    return buf;
}

char *
backend_x509_get_serial_hex(mbedtls_x509_crt *cert, struct gc_arena *gc)
{
    char *buf = NULL;
    size_t len = cert->serial.len * 3 + 1;

    buf = gc_malloc(len, true, gc);

    if (mbedtls_x509_serial_gets(buf, len-1, &cert->serial) < 0)
    {
        buf = NULL;
    }

    return buf;
}

static struct buffer
x509_get_fingerprint(const mbedtls_md_info_t *md_info, mbedtls_x509_crt *cert,
                     struct gc_arena *gc)
{
    const size_t md_size = mbedtls_md_get_size(md_info);
    struct buffer fingerprint = alloc_buf_gc(md_size, gc);
    mbedtls_md(md_info, cert->raw.p, cert->raw.len, BPTR(&fingerprint));
    ASSERT(buf_inc_len(&fingerprint, md_size));
    return fingerprint;
}

struct buffer
x509_get_sha1_fingerprint(mbedtls_x509_crt *cert, struct gc_arena *gc)
{
    return x509_get_fingerprint(mbedtls_md_info_from_type(MBEDTLS_MD_SHA1),
                                cert, gc);
}

struct buffer
x509_get_sha256_fingerprint(mbedtls_x509_crt *cert, struct gc_arena *gc)
{
    return x509_get_fingerprint(mbedtls_md_info_from_type(MBEDTLS_MD_SHA256),
                                cert, gc);
}

char *
x509_get_subject(mbedtls_x509_crt *cert, struct gc_arena *gc)
{
    char tmp_subject[MAX_SUBJECT_LENGTH] = {0};
    char *subject = NULL;

    int ret = 0;

    ret = mbedtls_x509_dn_gets( tmp_subject, MAX_SUBJECT_LENGTH-1, &cert->subject );
    if (ret > 0)
    {
        /* Allocate the required space for the subject */
        subject = string_alloc(tmp_subject, gc);
    }

    return subject;
}

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

static char *
asn1_buf_to_c_string(const mbedtls_asn1_buf *orig, struct gc_arena *gc)
{
    size_t i;
    char *val;

    if (!(orig->tag == MBEDTLS_ASN1_UTF8_STRING
          || orig->tag == MBEDTLS_ASN1_PRINTABLE_STRING
          || orig->tag == MBEDTLS_ASN1_IA5_STRING))
    {
        /* Only support C-string compatible types */
        return string_alloc("ERROR: unsupported ASN.1 string type", gc);
    }

    for (i = 0; i < orig->len; ++i)
    {
        if (orig->p[i] == '\0')
        {
            return string_alloc("ERROR: embedded null value", gc);
        }
    }
    val = gc_malloc(orig->len+1, false, gc);
    memcpy(val, orig->p, orig->len);
    val[orig->len] = '\0';
    return val;
}

static void
do_setenv_name(struct env_set *es, const struct x509_track *xt,
               const mbedtls_x509_crt *cert, int depth, struct gc_arena *gc)
{
    const mbedtls_x509_name *xn;
    for (xn = &cert->subject; xn != NULL; xn = xn->next)
    {
        const char *xn_short_name = NULL;
        if (0 == mbedtls_oid_get_attr_short_name(&xn->oid, &xn_short_name)
            && 0 == strcmp(xt->name, xn_short_name))
        {
            char *val_str = asn1_buf_to_c_string(&xn->val, gc);
            do_setenv_x509(es, xt->name, val_str, depth);
        }
    }
}

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
    xt->next = *ll_head;
    *ll_head = xt;
}

void
x509_setenv_track(const struct x509_track *xt, struct env_set *es,
                  const int depth, mbedtls_x509_crt *cert)
{
    struct gc_arena gc = gc_new();
    while (xt)
    {
        if (depth == 0 || (xt->flags & XT_FULL_CHAIN))
        {
            if (0 == strcmp(xt->name, "SHA1") || 0 == strcmp(xt->name, "SHA256"))
            {
                /* Fingerprint is not part of X509 structure */
                struct buffer cert_hash;
                char *fingerprint;

                if (0 == strcmp(xt->name, "SHA1"))
                {
                    cert_hash = x509_get_sha1_fingerprint(cert, &gc);
                }
                else
                {
                    cert_hash = x509_get_sha256_fingerprint(cert, &gc);
                }

                fingerprint = format_hex_ex(BPTR(&cert_hash),
                                            BLEN(&cert_hash), 0, 1 | FHE_CAPS, ":", &gc);
                do_setenv_x509(es, xt->name, fingerprint, depth);
            }
            else
            {
                do_setenv_name(es, xt, cert, depth, &gc);
            }
        }
        xt = xt->next;
    }
    gc_free(&gc);
}

/*
 * Save X509 fields to environment, using the naming convention:
 *
 * X509_{cert_depth}_{name}={value}
 */
void
x509_setenv(struct env_set *es, int cert_depth, mbedtls_x509_crt *cert)
{
    int i;
    unsigned char c;
    const mbedtls_x509_name *name;
    char s[128] = { 0 };

    name = &cert->subject;

    while (name != NULL)
    {
        char name_expand[64+8];
        const char *shortname;

        if (0 == mbedtls_oid_get_attr_short_name(&name->oid, &shortname) )
        {
            openvpn_snprintf(name_expand, sizeof(name_expand), "X509_%d_%s",
                             cert_depth, shortname);
        }
        else
        {
            openvpn_snprintf(name_expand, sizeof(name_expand), "X509_%d_\?\?",
                             cert_depth);
        }

        for (i = 0; i < name->val.len; i++)
        {
            if (i >= (int) sizeof( s ) - 1)
            {
                break;
            }

            c = name->val.p[i];
            if (c < 32 || c == 127 || ( c > 128 && c < 160 ) )
            {
                s[i] = '?';
            }
            else
            {
                s[i] = c;
            }
        }
        s[i] = '\0';

        /* Check both strings, set environment variable */
        string_mod(name_expand, CC_PRINT, CC_CRLF, '_');
        string_mod((char *)s, CC_PRINT, CC_CRLF, '_');
        setenv_str_incr(es, name_expand, (char *)s);

        name = name->next;
    }
}

result_t
x509_verify_ns_cert_type(mbedtls_x509_crt *cert, const int usage)
{
    if (usage == NS_CERT_CHECK_NONE)
    {
        return SUCCESS;
    }
    if (usage == NS_CERT_CHECK_CLIENT)
    {
        return ((cert->ext_types & MBEDTLS_X509_EXT_NS_CERT_TYPE)
                && (cert->ns_cert_type & MBEDTLS_X509_NS_CERT_TYPE_SSL_CLIENT)) ?
               SUCCESS : FAILURE;
    }
    if (usage == NS_CERT_CHECK_SERVER)
    {
        return ((cert->ext_types & MBEDTLS_X509_EXT_NS_CERT_TYPE)
                && (cert->ns_cert_type & MBEDTLS_X509_NS_CERT_TYPE_SSL_SERVER)) ?
               SUCCESS : FAILURE;
    }

    return FAILURE;
}

result_t
x509_verify_cert_ku(mbedtls_x509_crt *cert, const unsigned *const expected_ku,
                    int expected_len)
{
    msg(D_HANDSHAKE, "Validating certificate key usage");

    if (!(cert->ext_types & MBEDTLS_X509_EXT_KEY_USAGE))
    {
        msg(D_TLS_ERRORS,
            "ERROR: Certificate does not have key usage extension");
        return FAILURE;
    }

    if (expected_ku[0] == OPENVPN_KU_REQUIRED)
    {
        /* Extension required, value checked by TLS library */
        return SUCCESS;
    }

    result_t fFound = FAILURE;
    for (size_t i = 0; SUCCESS != fFound && i<expected_len; i++)
    {
        if (expected_ku[i] != 0
            && 0 == mbedtls_x509_crt_check_key_usage(cert, expected_ku[i]))
        {
            fFound = SUCCESS;
        }
    }

    if (fFound != SUCCESS)
    {
        msg(D_TLS_ERRORS,
            "ERROR: Certificate has key usage %04x, expected one of:",
            cert->key_usage);
        for (size_t i = 0; i < expected_len && expected_ku[i]; i++)
        {
            msg(D_TLS_ERRORS, " * %04x", expected_ku[i]);
        }
    }

    return fFound;
}

result_t
x509_verify_cert_eku(mbedtls_x509_crt *cert, const char *const expected_oid)
{
    result_t fFound = FAILURE;

    if (!(cert->ext_types & MBEDTLS_X509_EXT_EXTENDED_KEY_USAGE))
    {
        msg(D_HANDSHAKE, "Certificate does not have extended key usage extension");
    }
    else
    {
        mbedtls_x509_sequence *oid_seq = &(cert->ext_key_usage);

        msg(D_HANDSHAKE, "Validating certificate extended key usage");
        while (oid_seq != NULL)
        {
            mbedtls_x509_buf *oid = &oid_seq->buf;
            char oid_num_str[1024];
            const char *oid_str;

            if (0 == mbedtls_oid_get_extended_key_usage( oid, &oid_str ))
            {
                msg(D_HANDSHAKE, "++ Certificate has EKU (str) %s, expects %s",
                    oid_str, expected_oid);
                if (!strcmp(expected_oid, oid_str))
                {
                    fFound = SUCCESS;
                    break;
                }
            }

            if (0 < mbedtls_oid_get_numeric_string( oid_num_str,
                                                    sizeof(oid_num_str), oid))
            {
                msg(D_HANDSHAKE, "++ Certificate has EKU (oid) %s, expects %s",
                    oid_num_str, expected_oid);
                if (!strcmp(expected_oid, oid_num_str))
                {
                    fFound = SUCCESS;
                    break;
                }
            }
            oid_seq = oid_seq->next;
        }
    }

    return fFound;
}

result_t
x509_write_pem(FILE *peercert_file, mbedtls_x509_crt *peercert)
{
    msg(M_WARN, "mbed TLS does not support writing peer certificate in PEM format");
    return FAILURE;
}

bool
tls_verify_crl_missing(const struct tls_options *opt)
{
    if (opt->crl_file && !(opt->ssl_flags & SSLF_CRL_VERIFY_DIR)
        && (opt->ssl_ctx.crl == NULL || opt->ssl_ctx.crl->version == 0))
    {
        return true;
    }
    return false;
}

#endif /* #if defined(ENABLE_CRYPTO_MBEDTLS) */
