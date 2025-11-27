/*
 *  OpenVPN -- An application to securely tunnel IP networks
 *             over a single TCP/UDP port, with support for SSL/TLS-based
 *             session authentication and key exchange,
 *             packet encryption, packet authentication, and
 *             packet compression.
 *
 *  Copyright (C) 2023-2026 Sentyron B.V. <openvpn@sentyron.com>
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
 *  with this program; if not, see <https://www.gnu.org/licenses/>.
 */

/**
 * @file
 * mbedtls compatibility stub.
 * This file provides compatibility stubs to handle API differences between
 * different versions of Mbed TLS.
 */

#ifndef MBEDTLS_COMPAT_H_
#define MBEDTLS_COMPAT_H_

#include "syshead.h"

#include "errlevel.h"

#include <mbedtls/asn1.h>
#include <mbedtls/pk.h>

#if MBEDTLS_VERSION_NUMBER < 0x04000000
#include <mbedtls/ctr_drbg.h>
#include "crypto_mbedtls_legacy.h"
#else
#include <mbedtls/oid.h>
#endif /* MBEDTLS_VERSION_NUMBER < 0x04000000 */

#ifdef HAVE_PSA_CRYPTO_H
#include <psa/crypto.h>
#endif

static inline void
mbedtls_compat_psa_crypto_init(void)
{
#if defined(HAVE_PSA_CRYPTO_H) && defined(MBEDTLS_PSA_CRYPTO_C)
    if (psa_crypto_init() != PSA_SUCCESS)
    {
        msg(M_FATAL, "mbedtls: psa_crypto_init() failed");
    }
#else
    return;
#endif
}

#if MBEDTLS_VERSION_NUMBER >= 0x04000000
typedef struct
{
    const char *name;
    uint16_t tls_id;
} mbedtls_ecp_curve_info;

static inline int
mbedtls_oid_get_attr_short_name(const mbedtls_asn1_buf *oid, const char **desc)
{
    /* The relevant OIDs all have equal length. */
    if (oid->tag != MBEDTLS_ASN1_OID || oid->len != strlen(MBEDTLS_OID_AT_CN))
    {
        *desc = NULL;
        return -1;
    }

    if (memcmp(oid->p, MBEDTLS_OID_AT_CN, oid->len) == 0)
    {
        *desc = "CN";
    }
    else if (memcmp(oid->p, MBEDTLS_OID_AT_SUR_NAME, oid->len) == 0)
    {
        *desc = "SN";
    }
    else if (memcmp(oid->p, MBEDTLS_OID_AT_SERIAL_NUMBER, oid->len) == 0)
    {
        *desc = "serialNumber";
    }
    else if (memcmp(oid->p, MBEDTLS_OID_AT_COUNTRY, oid->len) == 0)
    {
        *desc = "C";
    }
    else if (memcmp(oid->p, MBEDTLS_OID_AT_LOCALITY, oid->len) == 0)
    {
        *desc = "L";
    }
    else if (memcmp(oid->p, MBEDTLS_OID_AT_STATE, oid->len) == 0)
    {
        *desc = "ST";
    }
    else if (memcmp(oid->p, MBEDTLS_OID_AT_ORGANIZATION, oid->len) == 0)
    {
        *desc = "O";
    }
    else if (memcmp(oid->p, MBEDTLS_OID_AT_ORG_UNIT, oid->len) == 0)
    {
        *desc = "OU";
    }
    else if (memcmp(oid->p, MBEDTLS_OID_AT_TITLE, oid->len) == 0)
    {
        *desc = "title";
    }
    else if (memcmp(oid->p, MBEDTLS_OID_AT_POSTAL_ADDRESS, oid->len) == 0)
    {
        *desc = "postalAddress";
    }
    else if (memcmp(oid->p, MBEDTLS_OID_AT_POSTAL_CODE, oid->len) == 0)
    {
        *desc = "postalCode";
    }
    else if (memcmp(oid->p, MBEDTLS_OID_AT_GIVEN_NAME, oid->len) == 0)
    {
        *desc = "GN";
    }
    else if (memcmp(oid->p, MBEDTLS_OID_AT_INITIALS, oid->len) == 0)
    {
        *desc = "initials";
    }
    else if (memcmp(oid->p, MBEDTLS_OID_AT_GENERATION_QUALIFIER, oid->len) == 0)
    {
        *desc = "generationQualifier";
    }
    else if (memcmp(oid->p, MBEDTLS_OID_AT_UNIQUE_IDENTIFIER, oid->len) == 0)
    {
        *desc = "uniqueIdentifier";
    }
    else if (memcmp(oid->p, MBEDTLS_OID_AT_DN_QUALIFIER, oid->len) == 0)
    {
        *desc = "dnQualifier";
    }
    else if (memcmp(oid->p, MBEDTLS_OID_AT_PSEUDONYM, oid->len) == 0)
    {
        *desc = "pseudonym";
    }
    else
    {
        *desc = NULL;
        return -1;
    }
    return 0;
}

static inline int
mbedtls_oid_get_extended_key_usage(const mbedtls_asn1_buf *oid, const char **desc)
{
    /* The relevant OIDs all have equal length. */
    if (oid->tag != MBEDTLS_ASN1_OID || oid->len != strlen(MBEDTLS_OID_SERVER_AUTH))
    {
        *desc = NULL;
        return -1;
    }

    if (memcmp(oid->p, MBEDTLS_OID_SERVER_AUTH, oid->len) == 0)
    {
        *desc = "TLS Web Server Authentication";
    }
    else if (memcmp(oid->p, MBEDTLS_OID_CLIENT_AUTH, oid->len) == 0)
    {
        *desc = "TLS Web Client Authentication";
    }
    else if (memcmp(oid->p, MBEDTLS_OID_CODE_SIGNING, oid->len) == 0)
    {
        *desc = "Code Signing";
    }
    else if (memcmp(oid->p, MBEDTLS_OID_EMAIL_PROTECTION, oid->len) == 0)
    {
        *desc = "E-mail Protection";
    }
    else if (memcmp(oid->p, MBEDTLS_OID_TIME_STAMPING, oid->len) == 0)
    {
        *desc = "Time Stamping";
    }
    else if (memcmp(oid->p, MBEDTLS_OID_OCSP_SIGNING, oid->len) == 0)
    {
        *desc = "OCSP Signing";
    }
    else
    {
        *desc = NULL;
        return -1;
    }

    return 0;
}
#endif /* MBEDTLS_VERSION_NUMBER >= 0x04000000 */

/* Some functions that operate on private keys use randomness to protect against
 * side channels. In Mbed TLS 4, they automatically use the RNG in the PSA
 * library, but in Mbed TLS 3, they require them as explicit arguments. */
static inline int
mbedtls_compat_pk_parse_key(mbedtls_pk_context *ctx,
                            const unsigned char *key, size_t keylen,
                            const unsigned char *pwd, size_t pwdlen)
{
#if MBEDTLS_VERSION_NUMBER >= 0x04000000
    return mbedtls_pk_parse_key(ctx, key, keylen, pwd, pwdlen);
#else
    return mbedtls_pk_parse_key(ctx, key, keylen, pwd, pwdlen, mbedtls_ctr_drbg_random, rand_ctx_get());
#endif /* MBEDTLS_VERSION_NUMBER < 0x04000000 */
}

static inline int
mbedtls_compat_pk_parse_keyfile(mbedtls_pk_context *ctx, const char *path, const char *password)
{
#if MBEDTLS_VERSION_NUMBER >= 0x04000000
    return mbedtls_pk_parse_keyfile(ctx, path, password);
#else
    return mbedtls_pk_parse_keyfile(ctx, path, password, mbedtls_ctr_drbg_random, rand_ctx_get());
#endif /* MBEDTLS_VERSION_NUMBER < 0x04000000 */
}

static inline int
mbedtls_compat_pk_check_pair(const mbedtls_pk_context *pub, const mbedtls_pk_context *prv)
{
#if MBEDTLS_VERSION_NUMBER >= 0x04000000
    return mbedtls_pk_check_pair(pub, prv);
#else
    return mbedtls_pk_check_pair(pub, prv, mbedtls_ctr_drbg_random, rand_ctx_get());
#endif /* MBEDTLS_VERSION_NUMBER < 0x04000000 */
}

#endif /* MBEDTLS_COMPAT_H_ */
