/*
 *  OpenVPN -- An application to securely tunnel IP networks
 *             over a single TCP/UDP port, with support for SSL/TLS-based
 *             session authentication and key exchange,
 *             packet encryption, packet authentication, and
 *             packet compression.
 *
 *  Copyright (C) 2002-2005 OpenVPN Solutions LLC <info@openvpn.net>
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

#ifdef WIN32
#include "config-win32.h"
#else
#include "config.h"
#endif

#include "syshead.h"

#include "proto.h"

#include "memdbg.h"

/*
 * If raw tunnel packet is IPv4, return true and increment
 * buffer offset to start of IP header.
 */
bool
is_ipv4 (int tunnel_type, struct buffer *buf)
{
  int offset;
  const struct openvpn_iphdr *ih;

  verify_align_4 (buf);
  if (tunnel_type == DEV_TYPE_TUN)
    {
      if (BLEN (buf) < (int) sizeof (struct openvpn_iphdr))
	return false;
      offset = 0;
    }
  else if (tunnel_type == DEV_TYPE_TAP)
    {
      const struct openvpn_ethhdr *eh;
      if (BLEN (buf) < (int)(sizeof (struct openvpn_ethhdr)
	  + sizeof (struct openvpn_iphdr)))
	return false;
      eh = (const struct openvpn_ethhdr *) BPTR (buf);
      if (ntohs (eh->proto) != OPENVPN_ETH_P_IPV4)
	return false;
      offset = sizeof (struct openvpn_ethhdr);
    }
  else
    return false;

  ih = (const struct openvpn_iphdr *) (BPTR (buf) + offset);

  if (OPENVPN_IPH_GET_VER (ih->version_len) == 4)
    return buf_advance (buf, offset);
  else
    return false;
}
