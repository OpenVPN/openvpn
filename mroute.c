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

#if P2MP_SERVER

#include "mroute.h"
#include "proto.h"
#include "error.h"
#include "socket.h"

#include "memdbg.h"

void
mroute_addr_init (struct mroute_addr *addr)
{
  CLEAR (*addr);
}

/*
 * Ethernet multicast addresses.
 */

static inline bool
is_mac_mcast_addr (const uint8_t *mac)
{
  return (bool) mac[0] & 1;
}

static inline bool
is_mac_mcast_maddr (const struct mroute_addr *addr)
{
  return (addr->type & MR_ADDR_MASK) == MR_ADDR_ETHER && is_mac_mcast_addr (addr->addr); 
}

/*
 * Don't learn certain addresses.
 */
bool
mroute_learnable_address (const struct mroute_addr *addr)
{
  int i;
  bool not_all_zeros = false;
  bool not_all_ones = false;

  for (i = 0; i < addr->len; ++i)
    {
      int b = addr->addr[i];
      if (b != 0x00)
	not_all_zeros = true;
      if (b != 0xFF)
	not_all_ones = true;
    }
  return not_all_zeros && not_all_ones && !is_mac_mcast_maddr (addr);
}

static inline void
mroute_get_in_addr_t (struct mroute_addr *ma, const in_addr_t src, unsigned int mask)
{
  if (ma)
    {
      ma->type = MR_ADDR_IPV4 | mask;
      ma->netbits = 0;
      ma->len = 4;
      *(in_addr_t*)ma->addr = src;
    }
}

static inline bool
mroute_is_mcast (const in_addr_t addr)
{
  return ((addr & htonl(IP_MCAST_SUBNET_MASK)) == htonl(IP_MCAST_NETWORK));
}

#ifdef ENABLE_PF

static unsigned int
mroute_extract_addr_arp (struct mroute_addr *src,
			 struct mroute_addr *dest,
			 const struct buffer *buf)
{
  unsigned int ret = 0;
  if (BLEN (buf) >= (int) sizeof (struct openvpn_arp))
    {
      const struct openvpn_arp *arp = (const struct openvpn_arp *) BPTR (buf);
      if (arp->mac_addr_type == htons(0x0001)
	  && arp->proto_addr_type == htons(0x0800)
	  && arp->mac_addr_size == 0x06
	  && arp->proto_addr_size == 0x04)
	{
	  mroute_get_in_addr_t (src, arp->ip_src, MR_ARP);
	  mroute_get_in_addr_t (dest, arp->ip_dest, MR_ARP);

	  /* multicast packet? */
	  if (mroute_is_mcast (arp->ip_dest))
	    ret |= MROUTE_EXTRACT_MCAST;

	  ret |= MROUTE_EXTRACT_SUCCEEDED;
	}
    }
  return ret;
}

#endif

unsigned int
mroute_extract_addr_ipv4 (struct mroute_addr *src,
			  struct mroute_addr *dest,
			  const struct buffer *buf)
{
  unsigned int ret = 0;
  static bool ipv6warned = false;

  if (BLEN (buf) >= 1)
    {
      switch (OPENVPN_IPH_GET_VER (*BPTR(buf)))
	{
	case 4:
	  if (BLEN (buf) >= (int) sizeof (struct openvpn_iphdr))
	    {
	      const struct openvpn_iphdr *ip = (const struct openvpn_iphdr *) BPTR (buf);

	      mroute_get_in_addr_t (src, ip->saddr, 0);
	      mroute_get_in_addr_t (dest, ip->daddr, 0);

	      /* multicast packet? */
	      if (mroute_is_mcast (ip->daddr))
		ret |= MROUTE_EXTRACT_MCAST;

	      /* IGMP message? */
	      if (ip->protocol == OPENVPN_IPPROTO_IGMP)
		ret |= MROUTE_EXTRACT_IGMP;

	      ret |= MROUTE_EXTRACT_SUCCEEDED;
	    }
	  break;
	case 6:
	  {
            if( !ipv6warned ) {
              msg (M_WARN, "IPv6 in tun mode is not supported in OpenVPN 2.2");
              ipv6warned = true;
            }
	    break;
	  }
	}
    }
  return ret;
}

unsigned int
mroute_extract_addr_ether (struct mroute_addr *src,
			   struct mroute_addr *dest,
			   struct mroute_addr *esrc,
			   struct mroute_addr *edest,
			   const struct buffer *buf)
{
  unsigned int ret = 0;
  if (BLEN (buf) >= (int) sizeof (struct openvpn_ethhdr))
    {
      const struct openvpn_ethhdr *eth = (const struct openvpn_ethhdr *) BPTR (buf);
      if (src)
	{
	  src->type = MR_ADDR_ETHER;
	  src->netbits = 0;
	  src->len = 6;
	  memcpy (src->addr, eth->source, 6);
	}
      if (dest)
	{
	  dest->type = MR_ADDR_ETHER;
	  dest->netbits = 0;
	  dest->len = 6;
	  memcpy (dest->addr, eth->dest, 6);

	  /* ethernet broadcast/multicast packet? */
	  if (is_mac_mcast_addr (eth->dest))
	    ret |= MROUTE_EXTRACT_BCAST;
	}
	  
      ret |= MROUTE_EXTRACT_SUCCEEDED;

#ifdef ENABLE_PF
      if (esrc || edest)
	{
	  struct buffer b = *buf;
	  if (buf_advance (&b, sizeof (struct openvpn_ethhdr)))
	    {
	      switch (ntohs (eth->proto))
		{
		case OPENVPN_ETH_P_IPV4:
		  ret |= (mroute_extract_addr_ipv4 (esrc, edest, &b) << MROUTE_SEC_SHIFT);
		  break;
		case OPENVPN_ETH_P_ARP:
		  ret |= (mroute_extract_addr_arp (esrc, edest, &b) << MROUTE_SEC_SHIFT);
		  break;
		}
	    }
	}
#endif
    }
  return ret;
}

/*
 * Translate a struct openvpn_sockaddr (osaddr)
 * to a struct mroute_addr (addr).
 */
bool mroute_extract_openvpn_sockaddr (struct mroute_addr *addr,
				      const struct openvpn_sockaddr *osaddr,
				      bool use_port)
{
  if (osaddr->sa.sin_family == AF_INET)
    {
      if (use_port)
	{
	  addr->type = MR_ADDR_IPV4 | MR_WITH_PORT;
	  addr->netbits = 0;
	  addr->len = 6;
	  memcpy (addr->addr, &osaddr->sa.sin_addr.s_addr, 4);
	  memcpy (addr->addr + 4, &osaddr->sa.sin_port, 2);
	}
      else
	{
	  addr->type = MR_ADDR_IPV4;
	  addr->netbits = 0;
	  addr->len = 4;
	  memcpy (addr->addr, &osaddr->sa.sin_addr.s_addr, 4);
	}
      return true;
    }
  return false;
}

/*
 * Zero off the host bits in an address, leaving
 * only the network bits, using the netbits member of
 * struct mroute_addr as the controlling parameter.
 */
void
mroute_addr_mask_host_bits (struct mroute_addr *ma)
{
  in_addr_t addr = ntohl(*(in_addr_t*)ma->addr);
  ASSERT ((ma->type & MR_ADDR_MASK) == MR_ADDR_IPV4);
  addr &= netbits_to_netmask (ma->netbits);
  *(in_addr_t*)ma->addr = htonl (addr);
}

/*
 * The mroute_addr hash function takes into account the
 * address type, number of bits in the network address,
 * and the actual address.
 */
uint32_t
mroute_addr_hash_function (const void *key, uint32_t iv)
{
  return hash_func (mroute_addr_hash_ptr ((const struct mroute_addr *) key),
		    mroute_addr_hash_len ((const struct mroute_addr *) key),
		    iv);
}

bool
mroute_addr_compare_function (const void *key1, const void *key2)
{
  return mroute_addr_equal ((const struct mroute_addr *) key1,
			    (const struct mroute_addr *) key2);
}

const char *
mroute_addr_print (const struct mroute_addr *ma,
		   struct gc_arena *gc)
{
  return mroute_addr_print_ex (ma, MAPF_IA_EMPTY_IF_UNDEF, gc);
}

const char *
mroute_addr_print_ex (const struct mroute_addr *ma,
		      const unsigned int flags,
		      struct gc_arena *gc)
{
  struct buffer out = alloc_buf_gc (64, gc);
  if (ma)
    {
      struct mroute_addr maddr = *ma;

      switch (maddr.type & MR_ADDR_MASK)
	{
	case MR_ADDR_ETHER:
	  buf_printf (&out, "%s", format_hex_ex (ma->addr, 6, 0, 1, ":", gc)); 
	  break;
	case MR_ADDR_IPV4:
	  {
	    struct buffer buf;
	    in_addr_t addr;
	    int port;
	    bool status;
	    buf_set_read (&buf, maddr.addr, maddr.len);
	    addr = buf_read_u32 (&buf, &status);
	    if (status)
	      {
		if ((flags & MAPF_SHOW_ARP) && (maddr.type & MR_ARP))
		  buf_printf (&out, "ARP/");
		buf_printf (&out, "%s", print_in_addr_t (addr, (flags & MAPF_IA_EMPTY_IF_UNDEF) ? IA_EMPTY_IF_UNDEF : 0, gc));
		if (maddr.type & MR_WITH_NETBITS)
		  {
		    if (flags & MAPF_SUBNET)
		      {
			const in_addr_t netmask = netbits_to_netmask (maddr.netbits);
			buf_printf (&out, "/%s", print_in_addr_t (netmask, 0, gc));
		      }
		    else
		      buf_printf (&out, "/%d", maddr.netbits);
		  }
	      }
	    if (maddr.type & MR_WITH_PORT)
	      {
		port = buf_read_u16 (&buf);
		if (port >= 0)
		  buf_printf (&out, ":%d", port);
	      }
	  }
	  break;
	case MR_ADDR_IPV6:
	  buf_printf (&out, "IPV6"); 
	  break;
	default:
	  buf_printf (&out, "UNKNOWN"); 
	  break;
	}
      return BSTR (&out);
    }
  else
    return "[NULL]";
}

/*
 * mroute_helper's main job is keeping track of
 * currently used CIDR netlengths, so we don't
 * have to cycle through all 33.
 */

struct mroute_helper *
mroute_helper_init (int ageable_ttl_secs)
{
  struct mroute_helper *mh;
  ALLOC_OBJ_CLEAR (mh, struct mroute_helper);
  mh->ageable_ttl_secs = ageable_ttl_secs;
  return mh;
}

static void
mroute_helper_regenerate (struct mroute_helper *mh)
{
  int i, j = 0;
  for (i = MR_HELPER_NET_LEN - 1; i >= 0; --i)
    {
      if (mh->net_len_refcount[i] > 0)
	mh->net_len[j++] = (uint8_t) i;
    }
  mh->n_net_len = j;

#ifdef ENABLE_DEBUG
  if (check_debug_level (D_MULTI_DEBUG))
    {
      struct gc_arena gc = gc_new ();
      struct buffer out = alloc_buf_gc (256, &gc);
      buf_printf (&out, "MROUTE CIDR netlen:");
      for (i = 0; i < mh->n_net_len; ++i)
	{
	  buf_printf (&out, " /%d", mh->net_len[i]);
	}
      dmsg (D_MULTI_DEBUG, "%s", BSTR (&out));
      gc_free (&gc);
    }
#endif
}

void
mroute_helper_add_iroute (struct mroute_helper *mh, const struct iroute *ir)
{
  if (ir->netbits >= 0)
    {
      ASSERT (ir->netbits < MR_HELPER_NET_LEN);
      ++mh->cache_generation;
      ++mh->net_len_refcount[ir->netbits];
      if (mh->net_len_refcount[ir->netbits] == 1)
	mroute_helper_regenerate (mh);
    }
}

void
mroute_helper_del_iroute (struct mroute_helper *mh, const struct iroute *ir)
{
  if (ir->netbits >= 0)
    {
      ASSERT (ir->netbits < MR_HELPER_NET_LEN);
      ++mh->cache_generation;
      --mh->net_len_refcount[ir->netbits];
      ASSERT (mh->net_len_refcount[ir->netbits] >= 0);
      if (!mh->net_len_refcount[ir->netbits])
	mroute_helper_regenerate (mh);
    }
}

void
mroute_helper_free (struct mroute_helper *mh)
{
  free (mh);
}

#else
static void dummy(void) {}
#endif /* P2MP_SERVER */
