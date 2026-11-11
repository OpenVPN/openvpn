/*
 *  OpenVPN -- An application to securely tunnel IP networks
 *             over a single TCP/UDP port, with support for SSL/TLS-based
 *             session authentication and key exchange,
 *             packet encryption, packet authentication, and
 *             packet compression.
 *
 *  Copyright (C) 2002-2026 OpenVPN Inc <sales@openvpn.net>
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

#if PROXY_DIGEST_AUTH

#define HASHLEN 16
typedef unsigned char HASH[HASHLEN];
#define HASHHEXLEN 32
typedef unsigned char HASHHEX[HASHHEXLEN + 1];

/* calculate H(A1) as per HTTP Digest spec */
void DigestCalcHA1(const char *pszAlg, const char *pszUserName, const char *pszRealm, const char *pszPassword,
                   const char *pszNonce, const char *pszCNonce, HASHHEX SessionKey);

/* calculate request-digest/response-digest as per HTTP Digest spec */
void DigestCalcResponse(const HASHHEX HA1,         /* H(A1) */
                        const char *pszNonce,      /* nonce from server */
                        const char *pszNonceCount, /* 8 hex digits */
                        const char *pszCNonce,     /* client nonce */
                        const char *pszQop,        /* qop-value: "", "auth", "auth-int" */
                        const char *pszMethod,     /* method from the request */
                        const char *pszDigestUri,  /* requested URL */
                        const HASHHEX HEntity,     /* H(entity body) if qop="auth-int" */
                        HASHHEX Response           /* request-digest or response-digest */
);

#endif /* if PROXY_DIGEST_AUTH */
