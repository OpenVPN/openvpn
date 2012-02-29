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
#include "error.h"
#include "mss.h"
#include "memdbg.h"

/*
 * Lower MSS on TCP SYN packets to fix MTU
 * problems which arise from protocol
 * encapsulation.
 */
void
mss_fixup (struct buffer *buf, int maxmss)
{
  const struct openvpn_iphdr *pip;
  int hlen;

  if (BLEN (buf) < (int) sizeof (struct openvpn_iphdr))
    return;
  
  verify_align_4 (buf);
  pip = (struct openvpn_iphdr *) BPTR (buf);

  hlen = OPENVPN_IPH_GET_LEN (pip->version_len);

  if (pip->protocol == OPENVPN_IPPROTO_TCP
      && ntohs (pip->tot_len) == BLEN (buf)
      && (ntohs (pip->frag_off) & OPENVPN_IP_OFFMASK) == 0
      && hlen <= BLEN (buf)
      && BLEN (buf) - hlen
         >= (int) sizeof (struct openvpn_tcphdr))
    {
      struct buffer newbuf = *buf;
      if (buf_advance (&newbuf, hlen))
	{
	  struct openvpn_tcphdr *tc = (struct openvpn_tcphdr *) BPTR (&newbuf);
	  if (tc->flags & OPENVPN_TCPH_SYN_MASK)
	    mss_fixup_dowork (&newbuf, (uint16_t) maxmss);
	}
    }
}

void
mss_fixup_dowork (struct buffer *buf, uint16_t maxmss)
{
  int hlen, olen, optlen;
  uint8_t *opt;
  uint16_t *mss;
  int accumulate;
  struct openvpn_tcphdr *tc;

  ASSERT (BLEN (buf) >= (int) sizeof (struct openvpn_tcphdr));

  verify_align_4 (buf);
  tc = (struct openvpn_tcphdr *) BPTR (buf);
  hlen = OPENVPN_TCPH_GET_DOFF (tc->doff_res);

  /* Invalid header length or header without options. */
  if (hlen <= (int) sizeof (struct openvpn_tcphdr)
      || hlen > BLEN (buf))
    return;

  for (olen = hlen - sizeof (struct openvpn_tcphdr),
	 opt = (uint8_t *)(tc + 1);
       olen > 0;
       olen -= optlen, opt += optlen) {
    if (*opt == OPENVPN_TCPOPT_EOL)
      break;
    else if (*opt == OPENVPN_TCPOPT_NOP)
      optlen = 1;
    else {
      optlen = *(opt + 1);
      if (optlen <= 0 || optlen > olen)
        break;
      if (*opt == OPENVPN_TCPOPT_MAXSEG) {
        if (optlen != OPENVPN_TCPOLEN_MAXSEG)
          continue;
        mss = (uint16_t *)(opt + 2);
        if (ntohs (*mss) > maxmss) {
          dmsg (D_MSS, "MSS: %d -> %d",
               (int) ntohs (*mss),
	       (int) maxmss);
          accumulate = *mss;
          *mss = htons (maxmss);
          accumulate -= *mss;
          ADJUST_CHECKSUM (accumulate, tc->check);
        }
      }
    }
  }
}
