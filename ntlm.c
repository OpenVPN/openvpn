/*
 *  ntlm proxy support for OpenVPN
 *
 *  Copyright (C) 2004 William Preston
 *
 *  *NTLMv2 support and domain name parsing by Miroslav Zajic, Nextsoft s.r.o.*
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
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

#if NTLM

#include "common.h"
#include "buffer.h"
#include "misc.h"
#include "socket.h"
#include "fdmisc.h"
#include "proxy.h"
#include "ntlm.h"
#include "base64.h"
#include "crypto.h"

#include "memdbg.h"


/* 64bit datatype macros */
#ifdef _MSC_VER 
	/* MS compilers */
#	define UINTEGER64 __int64
#	define UINT64(c) c ## Ui64
#else 
	/* Non MS compilers */
#	define UINTEGER64 unsigned long long
#	define UINT64(c) c ## LL
#endif




static void
create_des_keys(const unsigned char *hash, unsigned char *key)
{
  key[0] = hash[0];
  key[1] = ((hash[0]&1)<<7)|(hash[1]>>1);
  key[2] = ((hash[1]&3)<<6)|(hash[2]>>2);
  key[3] = ((hash[2]&7)<<5)|(hash[3]>>3);
  key[4] = ((hash[3]&15)<<4)|(hash[4]>>4);
  key[5] = ((hash[4]&31)<<3)|(hash[5]>>5);
  key[6] = ((hash[5]&63)<<2)|(hash[6]>>6);
  key[7] = ((hash[6]&127)<<1);
  des_set_odd_parity((des_cblock *)key);
}

static void
gen_md4_hash (const char* data, int data_len, char *result)
{
  /* result is 16 byte md4 hash */

  MD4_CTX c;
  char md[16];

  MD4_Init (&c);
  MD4_Update (&c, data, data_len);
  MD4_Final ((unsigned char *)md, &c);

  memcpy (result, md, 16);
}

static void
gen_hmac_md5 (const char* data, int data_len, const char* key, int key_len,char *result)
{
	unsigned int len;

	HMAC_CTX c;
	HMAC_Init (&c, key, key_len, EVP_md5());
	HMAC_Update (&c, (const unsigned char *)data, data_len);
	HMAC_Final (&c, (unsigned char *)result, &len);
	HMAC_CTX_cleanup(&c);
}

static void
gen_timestamp (unsigned char *timestamp)
{ 
	/* Copies 8 bytes long timestamp into "timestamp" buffer. 
	 * Timestamp is Little-endian, 64-bit signed value representing the number of tenths of a microsecond since January 1, 1601.
	 */

	UINTEGER64 timestamp_ull;

	timestamp_ull = openvpn_time(NULL);
	timestamp_ull = (timestamp_ull + UINT64(11644473600)) * UINT64(10000000);

	/* store little endian value */
	timestamp[0]= timestamp_ull & UINT64(0xFF);
	timestamp[1]= (timestamp_ull  >> 8)  & UINT64(0xFF);
	timestamp[2]= (timestamp_ull  >> 16) & UINT64(0xFF);
	timestamp[3]= (timestamp_ull  >> 24) & UINT64(0xFF);
	timestamp[4]= (timestamp_ull  >> 32) & UINT64(0xFF);
	timestamp[5]= (timestamp_ull  >> 40) & UINT64(0xFF);
	timestamp[6]= (timestamp_ull  >> 48) & UINT64(0xFF);
	timestamp[7]= (timestamp_ull  >> 56) & UINT64(0xFF);
}

static void
gen_nonce (unsigned char *nonce)
{ 
	/* Generates 8 random bytes to be used as client nonce */
	int i;

	for(i=0;i<8;i++){
		nonce[i] = (unsigned char)get_random();
	}
}

unsigned char *my_strupr(unsigned char *str)
{ 
	/* converts string to uppercase in place */
	unsigned char *tmp = str;;

	do *str = toupper(*str); while (*(++str));
	return tmp;
}

static int
unicodize (char *dst, const char *src)
{
  /* not really unicode... */
  int i = 0;
  do
    {
      dst[i++] = *src;
      dst[i++] = 0;
    }
  while (*src++);

  return i;
}

static void
add_security_buffer(int sb_offset, void *data, int length, unsigned char *msg_buf, int *msg_bufpos)
{
	/* Adds security buffer data to a message and sets security buffer's offset and length */
	msg_buf[sb_offset] = (unsigned char)length;
	msg_buf[sb_offset + 2] = msg_buf[sb_offset];
	msg_buf[sb_offset + 4] = (unsigned char)(*msg_bufpos & 0xff);
	msg_buf[sb_offset + 5] = (unsigned char)((*msg_bufpos >> 8) & 0xff);
	memcpy(&msg_buf[*msg_bufpos], data, msg_buf[sb_offset]);
	*msg_bufpos += length;
}

const char *
ntlm_phase_1 (const struct http_proxy_info *p, struct gc_arena *gc)
{
  struct buffer out = alloc_buf_gc (96, gc);
  /* try a minimal NTLM handshake
   *
   * http://davenport.sourceforge.net/ntlm.html
   *
   * This message contains only the NTLMSSP signature,
   * the NTLM message type,
   * and the minimal set of flags (Negotiate NTLM and Negotiate OEM).
   *
   */
  buf_printf (&out, "%s", "TlRMTVNTUAABAAAAAgIAAA==");
  return (BSTR (&out));
}

const char *
ntlm_phase_3 (const struct http_proxy_info *p, const char *phase_2, struct gc_arena *gc)
{
	/* NTLM handshake
	 *
	 * http://davenport.sourceforge.net/ntlm.html
	 *
	 */
	
  char pwbuf[sizeof (p->up.password) * 2]; /* for unicode password */
  char buf2[128]; /* decoded reply from proxy */
  unsigned char phase3[464];

  char md4_hash[21];
  char challenge[8], ntlm_response[24];
  int i, ret_val;
  des_cblock key1, key2, key3;
  des_key_schedule sched1, sched2, sched3;

	char ntlmv2_response[144];
	char userdomain_u[256]; /* for uppercase unicode username and domain */
	char userdomain[128];   /* the same as previous but ascii */
	char ntlmv2_hash[16];
	char ntlmv2_hmacmd5[16];
	char *ntlmv2_blob = ntlmv2_response + 16; /* inside ntlmv2_response, length: 128 */
	int ntlmv2_blob_size=0;
	int phase3_bufpos = 0x40; /* offset to next security buffer data to be added */
	size_t len;

	char domain[128];
	char username[128];
	char *separator;

	bool ntlmv2_enabled = (p->auth_method == HTTP_AUTH_NTLM2);

  CLEAR (buf2);

  ASSERT (strlen (p->up.username) > 0);
  ASSERT (strlen (p->up.password) > 0);
	
	/* username parsing */
	separator = strchr(p->up.username, '\\');
	if (separator == NULL) {
		strncpy(username, p->up.username, sizeof(username)-1);
		username[sizeof(username)-1]=0;
		domain[0]=0;
	} else {
		strncpy(username, separator+1, sizeof(username)-1);
		username[sizeof(username)-1]=0;
		len = separator - p->up.username;
		if (len > sizeof(domain) - 1) len = sizeof(domain) - 1;
		strncpy(domain, p->up.username,  len);
		domain[len]=0;
	}


  /* fill 1st 16 bytes with md4 hash, disregard terminating null */
  gen_md4_hash (pwbuf, unicodize (pwbuf, p->up.password) - 2, md4_hash);

  /* pad to 21 bytes */
  memset (md4_hash + 16, 0, 5);

  ret_val = base64_decode( phase_2, (void *)buf2);
  if (ret_val < 0)
    return NULL;

  /* we can be sure that phase_2 is less than 128
   * therefore buf2 needs to be (3/4 * 128) */

  /* extract the challenge from bytes 24-31 */
  for (i=0; i<8; i++)
  {
    challenge[i] = buf2[i+24];
  }

	if (ntlmv2_enabled){ /* Generate NTLMv2 response */
	        int tib_len;

		/* NTLMv2 hash */
	        my_strupr((unsigned char *)strcpy(userdomain, username));
		if (strlen(username) + strlen(domain) < sizeof(userdomain))
			strcat(userdomain, domain);
		else
			msg (M_INFO, "Warning: Username or domain too long");
		unicodize (userdomain_u, userdomain);
		gen_hmac_md5(userdomain_u, 2 * strlen(userdomain), md4_hash, 16, ntlmv2_hash);

		/* NTLMv2 Blob */
		memset(ntlmv2_blob, 0, 128);                /* Clear blob buffer */ 
		ntlmv2_blob[0x00]=1;                        /* Signature */
		ntlmv2_blob[0x01]=1;                        /* Signature */
		ntlmv2_blob[0x04]=0;                        /* Reserved */
		gen_timestamp((unsigned char *)&ntlmv2_blob[0x08]);          /* 64-bit Timestamp */
		gen_nonce((unsigned char *)&ntlmv2_blob[0x10]);              /* 64-bit Client Nonce */
		ntlmv2_blob[0x18]=0;                        /* Unknown, zero should work */

		/* Add target information block to the blob */
		if (( *((long *)&buf2[0x14]) & 0x00800000) == 0x00800000){ /* Check for Target Information block */
			tib_len = buf2[0x28];/* Get Target Information block size */
			if (tib_len > 96) tib_len = 96;
			{
			  char *tib_ptr = buf2 + buf2[0x2c]; /* Get Target Information block pointer */
			  memcpy(&ntlmv2_blob[0x1c], tib_ptr, tib_len); /* Copy Target Information block into the blob */
			}
		} else {
			tib_len = 0;
		}

		ntlmv2_blob[0x1c + tib_len] = 0;            /* Unknown, zero works */ 

		/* Get blob length */
		ntlmv2_blob_size = 0x20 + tib_len; 

		/* Add challenge from message 2 */
		memcpy(&ntlmv2_response[8], challenge, 8);

		/* hmac-md5 */
		gen_hmac_md5(&ntlmv2_response[8], ntlmv2_blob_size + 8, ntlmv2_hash, 16, ntlmv2_hmacmd5);
		
		/* Add hmac-md5 result to the blob */
		memcpy(ntlmv2_response, ntlmv2_hmacmd5, 16); /* Note: This overwrites challenge previously written at ntlmv2_response[8..15] */
	
	} else { /* Generate NTLM response */

		create_des_keys ((unsigned char *)md4_hash, key1);
		des_set_key_unchecked ((des_cblock *)key1, sched1);
		des_ecb_encrypt ((des_cblock *)challenge, (des_cblock *)ntlm_response, sched1, DES_ENCRYPT);

		create_des_keys ((unsigned char *)&(md4_hash[7]), key2);
		des_set_key_unchecked ((des_cblock *)key2, sched2);
		des_ecb_encrypt ((des_cblock *)challenge, (des_cblock *)&(ntlm_response[8]), sched2, DES_ENCRYPT);

		create_des_keys ((unsigned char *)&(md4_hash[14]), key3);
		des_set_key_unchecked ((des_cblock *)key3, sched3);
		des_ecb_encrypt ((des_cblock *)challenge, (des_cblock *)&(ntlm_response[16]), sched3, DES_ENCRYPT);
	}
	
	
	memset (phase3, 0, sizeof (phase3)); /* clear reply */

	strcpy ((char *)phase3, "NTLMSSP\0"); /* signature */
	phase3[8] = 3; /* type 3 */

	if (ntlmv2_enabled){ /* NTLMv2 response */
		add_security_buffer(0x14, ntlmv2_response, ntlmv2_blob_size + 16, phase3, &phase3_bufpos);
	}else{ /* NTLM response */
		add_security_buffer(0x14, ntlm_response, 24, phase3, &phase3_bufpos);
	}
	
	/* username in ascii */
	add_security_buffer(0x24, username, strlen (username), phase3, &phase3_bufpos);

	/* Set domain. If <domain> is empty, default domain will be used (i.e. proxy's domain) */ 
	add_security_buffer(0x1c, domain, strlen (domain), phase3, &phase3_bufpos);
	

	/* other security buffers will be empty */
	phase3[0x10] = phase3_bufpos; /* lm not used */
	phase3[0x30] = phase3_bufpos; /* no workstation name supplied */
	phase3[0x38] = phase3_bufpos; /* no session key */
	
	/* flags */
  phase3[0x3c] = 0x02; /* negotiate oem */
  phase3[0x3d] = 0x02; /* negotiate ntlm */

  return ((const char *)make_base64_string2 ((unsigned char *)phase3, phase3_bufpos, gc));
}

#else
static void dummy(void) {}
#endif
