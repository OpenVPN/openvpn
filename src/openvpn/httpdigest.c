/*
 *  OpenVPN -- An application to securely tunnel IP networks
 *             over a single TCP/UDP port, with support for SSL/TLS-based
 *             session authentication and key exchange,
 *             packet encryption, packet authentication, and
 *             packet compression.
 *
 *  Copyright (C) 2002-2022 OpenVPN Inc <sales@openvpn.net>
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

#ifdef HAVE_CONFIG_H
#include "config.h"
#elif defined(_MSC_VER)
#include "config-msvc.h"
#endif

#include "syshead.h"

#if PROXY_DIGEST_AUTH

#include "crypto.h"
#include "httpdigest.h"

static void
CvtHex(
    IN HASH Bin,
    OUT HASHHEX Hex
    )
{
    unsigned short i;
    unsigned char j;

    for (i = 0; i < HASHLEN; i++)
    {
        j = (Bin[i] >> 4) & 0xf;
        if (j <= 9)
        {
            Hex[i*2] = (j + '0');
        }
        else
        {
            Hex[i*2] = (j + 'a' - 10);
        }
        j = Bin[i] & 0xf;
        if (j <= 9)
        {
            Hex[i*2+1] = (j + '0');
        }
        else
        {
            Hex[i*2+1] = (j + 'a' - 10);
        }
    }
    Hex[HASHHEXLEN] = '\0';
}

/* calculate H(A1) as per spec */
void
DigestCalcHA1(
    IN char *pszAlg,
    IN char *pszUserName,
    IN char *pszRealm,
    IN char *pszPassword,
    IN char *pszNonce,
    IN char *pszCNonce,
    OUT HASHHEX SessionKey
    )
{
    HASH HA1;
    md_ctx_t *md5_ctx = md_ctx_new();
    const md_kt_t *md5_kt = md_kt_get("MD5");

    md_ctx_init(md5_ctx, md5_kt);
    md_ctx_update(md5_ctx, (const uint8_t *) pszUserName, strlen(pszUserName));
    md_ctx_update(md5_ctx, (const uint8_t *) ":", 1);
    md_ctx_update(md5_ctx, (const uint8_t *) pszRealm, strlen(pszRealm));
    md_ctx_update(md5_ctx, (const uint8_t *) ":", 1);
    md_ctx_update(md5_ctx, (const uint8_t *) pszPassword, strlen(pszPassword));
    md_ctx_final(md5_ctx, HA1);
    if (pszAlg && strcasecmp(pszAlg, "md5-sess") == 0)
    {
        md_ctx_init(md5_ctx, md5_kt);
        md_ctx_update(md5_ctx, HA1, HASHLEN);
        md_ctx_update(md5_ctx, (const uint8_t *) ":", 1);
        md_ctx_update(md5_ctx, (const uint8_t *) pszNonce, strlen(pszNonce));
        md_ctx_update(md5_ctx, (const uint8_t *) ":", 1);
        md_ctx_update(md5_ctx, (const uint8_t *) pszCNonce, strlen(pszCNonce));
        md_ctx_final(md5_ctx, HA1);
    }
    md_ctx_cleanup(md5_ctx);
    md_ctx_free(md5_ctx);
    CvtHex(HA1, SessionKey);
}

/* calculate request-digest/response-digest as per HTTP Digest spec */
void
DigestCalcResponse(
    IN HASHHEX HA1,                          /* H(A1) */
    IN char *pszNonce,                       /* nonce from server */
    IN char *pszNonceCount,                  /* 8 hex digits */
    IN char *pszCNonce,                      /* client nonce */
    IN char *pszQop,                         /* qop-value: "", "auth", "auth-int" */
    IN char *pszMethod,                      /* method from the request */
    IN char *pszDigestUri,                   /* requested URL */
    IN HASHHEX HEntity,                      /* H(entity body) if qop="auth-int" */
    OUT HASHHEX Response                     /* request-digest or response-digest */
    )
{
    HASH HA2;
    HASH RespHash;
    HASHHEX HA2Hex;

    md_ctx_t *md5_ctx = md_ctx_new();
    const md_kt_t *md5_kt = md_kt_get("MD5");

    /* calculate H(A2) */
    md_ctx_init(md5_ctx, md5_kt);
    md_ctx_update(md5_ctx, (const uint8_t *) pszMethod, strlen(pszMethod));
    md_ctx_update(md5_ctx, (const uint8_t *) ":", 1);
    md_ctx_update(md5_ctx, (const uint8_t *) pszDigestUri, strlen(pszDigestUri));
    if (strcasecmp(pszQop, "auth-int") == 0)
    {
        md_ctx_update(md5_ctx, (const uint8_t *) ":", 1);
        md_ctx_update(md5_ctx, HEntity, HASHHEXLEN);
    }
    md_ctx_final(md5_ctx, HA2);
    CvtHex(HA2, HA2Hex);

    /* calculate response */
    md_ctx_init(md5_ctx, md5_kt);
    md_ctx_update(md5_ctx, HA1, HASHHEXLEN);
    md_ctx_update(md5_ctx, (const uint8_t *) ":", 1);
    md_ctx_update(md5_ctx, (const uint8_t *) pszNonce, strlen(pszNonce));
    md_ctx_update(md5_ctx, (const uint8_t *) ":", 1);
    if (*pszQop)
    {
        md_ctx_update(md5_ctx, (const uint8_t *) pszNonceCount, strlen(pszNonceCount));
        md_ctx_update(md5_ctx, (const uint8_t *) ":", 1);
        md_ctx_update(md5_ctx, (const uint8_t *) pszCNonce, strlen(pszCNonce));
        md_ctx_update(md5_ctx, (const uint8_t *) ":", 1);
        md_ctx_update(md5_ctx, (const uint8_t *) pszQop, strlen(pszQop));
        md_ctx_update(md5_ctx, (const uint8_t *) ":", 1);
    }
    md_ctx_update(md5_ctx, HA2Hex, HASHHEXLEN);
    md_ctx_final(md5_ctx, RespHash);
    md_ctx_cleanup(md5_ctx);
    md_ctx_free(md5_ctx);
    CvtHex(RespHash, Response);
}

#endif /* if PROXY_DIGEST_AUTH */
