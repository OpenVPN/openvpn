/*
 *  OpenVPN -- An application to securely tunnel IP networks
 *             over a single TCP/UDP port, with support for SSL/TLS-based
 *             session authentication and key exchange,
 *             packet encryption, packet authentication, and
 *             packet compression.
 *
 *  Copyright (C) 2002-2010 OpenVPN Technologies, Inc. <sales@openvpn.net>
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
 *  You should have received a copy of the GNU General Public License
 *  along with this program (see the file COPYING included with this
 *  distribution); if not, write to the Free Software Foundation, Inc.,
 *  59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

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

  for (i = 0; i < HASHLEN; i++) {
    j = (Bin[i] >> 4) & 0xf;
    if (j <= 9)
      Hex[i*2] = (j + '0');
    else
      Hex[i*2] = (j + 'a' - 10);
    j = Bin[i] & 0xf;
    if (j <= 9)
      Hex[i*2+1] = (j + '0');
    else
      Hex[i*2+1] = (j + 'a' - 10);
  };
  Hex[HASHHEXLEN] = '\0';
};

/* calculate H(A1) as per spec */
void
DigestCalcHA1(
	      IN char * pszAlg,
	      IN char * pszUserName,
	      IN char * pszRealm,
	      IN char * pszPassword,
	      IN char * pszNonce,
	      IN char * pszCNonce,
	      OUT HASHHEX SessionKey
	      )
{
  MD5_CTX Md5Ctx;
  HASH HA1;

  MD5_Init(&Md5Ctx);
  MD5_Update(&Md5Ctx, pszUserName, strlen(pszUserName));
  MD5_Update(&Md5Ctx, ":", 1);
  MD5_Update(&Md5Ctx, pszRealm, strlen(pszRealm));
  MD5_Update(&Md5Ctx, ":", 1);
  MD5_Update(&Md5Ctx, pszPassword, strlen(pszPassword));
  MD5_Final(HA1, &Md5Ctx);
  if (pszAlg && strcasecmp(pszAlg, "md5-sess") == 0)
    {
      MD5_Init(&Md5Ctx);
      MD5_Update(&Md5Ctx, HA1, HASHLEN);
      MD5_Update(&Md5Ctx, ":", 1);
      MD5_Update(&Md5Ctx, pszNonce, strlen(pszNonce));
      MD5_Update(&Md5Ctx, ":", 1);
      MD5_Update(&Md5Ctx, pszCNonce, strlen(pszCNonce));
      MD5_Final(HA1, &Md5Ctx);
    };
  CvtHex(HA1, SessionKey);
}

/* calculate request-digest/response-digest as per HTTP Digest spec */
void
DigestCalcResponse(
		   IN HASHHEX HA1,           /* H(A1) */
		   IN char * pszNonce,       /* nonce from server */
		   IN char * pszNonceCount,  /* 8 hex digits */
		   IN char * pszCNonce,      /* client nonce */
		   IN char * pszQop,         /* qop-value: "", "auth", "auth-int" */
		   IN char * pszMethod,      /* method from the request */
		   IN char * pszDigestUri,   /* requested URL */
		   IN HASHHEX HEntity,       /* H(entity body) if qop="auth-int" */
		   OUT HASHHEX Response      /* request-digest or response-digest */
		   )
{
  MD5_CTX Md5Ctx;
  HASH HA2;
  HASH RespHash;
  HASHHEX HA2Hex;

  // calculate H(A2)
  MD5_Init(&Md5Ctx);
  MD5_Update(&Md5Ctx, pszMethod, strlen(pszMethod));
  MD5_Update(&Md5Ctx, ":", 1);
  MD5_Update(&Md5Ctx, pszDigestUri, strlen(pszDigestUri));
  if (strcasecmp(pszQop, "auth-int") == 0)
    {
      MD5_Update(&Md5Ctx, ":", 1);
      MD5_Update(&Md5Ctx, HEntity, HASHHEXLEN);
    };
  MD5_Final(HA2, &Md5Ctx);
  CvtHex(HA2, HA2Hex);

  // calculate response
  MD5_Init(&Md5Ctx);
  MD5_Update(&Md5Ctx, HA1, HASHHEXLEN);
  MD5_Update(&Md5Ctx, ":", 1);
  MD5_Update(&Md5Ctx, pszNonce, strlen(pszNonce));
  MD5_Update(&Md5Ctx, ":", 1);
  if (*pszQop)
    {
      MD5_Update(&Md5Ctx, pszNonceCount, strlen(pszNonceCount));
      MD5_Update(&Md5Ctx, ":", 1);
      MD5_Update(&Md5Ctx, pszCNonce, strlen(pszCNonce));
      MD5_Update(&Md5Ctx, ":", 1);
      MD5_Update(&Md5Ctx, pszQop, strlen(pszQop));
      MD5_Update(&Md5Ctx, ":", 1);
    };
  MD5_Update(&Md5Ctx, HA2Hex, HASHHEXLEN);
  MD5_Final(RespHash, &Md5Ctx);
  CvtHex(RespHash, Response);
}

#endif
