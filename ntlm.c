/*
 *  ntlm proxy support for OpenVPN
 *
 *  Copyright (C) 2004 William Preston
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

#ifdef WIN32
#include "config-win32.h"
#else
#include "config.h"
#endif

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
  char pwbuf[sizeof (p->up.password) * 2]; /* for unicode password */
  char buf2[128]; /* decoded reply from proxy */
  char phase3[146];

  char md4_hash[21];
  char challenge[8], response[24];
  int i, ret_val, buflen;
  des_cblock key1, key2, key3;
  des_key_schedule sched1, sched2, sched3;

  /* try a minimal NTLM handshake
   *
   * http://davenport.sourceforge.net/ntlm.html
   *
   */
  ASSERT (strlen (p->up.username) > 0);
  ASSERT (strlen (p->up.password) > 0);

  /* fill 1st 16 bytes with md4 hash, disregard terminating null */
  gen_md4_hash (pwbuf, unicodize (pwbuf, p->up.password) - 2, md4_hash);

  /* pad to 21 bytes */
  memset (md4_hash + 16, 0, 5);

  ret_val = base64_decode( phase_2, (void *)buf2);
  /* we can be sure that phase_2 is less than 128
   * therefore buf2 needs to be (3/4 * 128) */

  /* extract the challenge from bytes 24-31 */
  for (i=0; i<8; i++)
  {
    challenge[i] = buf2[i+24];
  }

  create_des_keys ((unsigned char *)md4_hash, key1);
  des_set_key_unchecked ((des_cblock *)key1, sched1);
  des_ecb_encrypt ((des_cblock *)challenge, (des_cblock *)response, sched1, DES_ENCRYPT);

  create_des_keys ((unsigned char *)&(md4_hash[7]), key2);
  des_set_key_unchecked ((des_cblock *)key2, sched2);
  des_ecb_encrypt ((des_cblock *)challenge, (des_cblock *)&(response[8]), sched2, DES_ENCRYPT);

  create_des_keys ((unsigned char *)&(md4_hash[14]), key3);
  des_set_key_unchecked ((des_cblock *)key3, sched3);
  des_ecb_encrypt ((des_cblock *)challenge, (des_cblock *)&(response[16]), sched3, DES_ENCRYPT);

  /* clear reply */
  memset (phase3, 0, sizeof (phase3));

  strcpy (phase3, "NTLMSSP\0");
  phase3[8] = 3; /* type 3 */

  buflen = 0x58 + strlen (p->up.username);
  if (buflen > (int) sizeof (phase3))
    buflen = sizeof (phase3);

  phase3[0x10] = buflen; /* lm not used */
  phase3[0x20] = buflen; /* default domain (i.e. proxy's domain) */
  phase3[0x30] = buflen; /* no workstation name supplied */
  phase3[0x38] = buflen; /* no session key */

  phase3[0x14] = 24; /* ntlm response is 24 bytes long */
  phase3[0x16] = phase3[0x14];
  phase3[0x18] = 0x40; /* ntlm offset */
  memcpy (&(phase3[0x40]), response, 24);


  phase3[0x24] = strlen (p->up.username); /* username in ascii */
  phase3[0x26] = phase3[0x24];
  phase3[0x28] = 0x58;
  strncpy (&(phase3[0x58]), p->up.username, sizeof (phase3) - 0x58);

  phase3[0x3c] = 0x02; /* negotiate oem */
  phase3[0x3d] = 0x02; /* negotiate ntlm */

  return ((const char *)make_base64_string2 ((unsigned char *)phase3, buflen, gc));
}

#else
static void dummy(void) {}
#endif
