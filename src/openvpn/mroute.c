/*
 *  OpenVPN -- An application to securely tunnel IP networks
 *             over a single TCP/UDP port, with support for SSL/TLS-based
 *             session authentication and key exchange,
 *             packet encryption, packet authentication, and
 *             packet compression.
 *
 *  Copyright (C) 2002-2021 OpenVPN Inc <sales@openvpn.net>
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


#include "mroute.h"
#include "proto.h"
#include "error.h"
#include "socket.h"

#include "memdbg.h"

void
mroute_addr_init(struct mroute_addr *addr)
{
    CLEAR(*addr);
}

/*
 * Ethernet multicast addresses.
 */

static inline bool
is_mac_mcast_addr(const uint8_t *mac)
{
    return (bool) (mac[0] & 1);
}

static inline bool
is_mac_mcast_maddr(const struct mroute_addr *addr)
{
    return (addr->type & MR_ADDR_MASK) == MR_ADDR_ETHER
           && is_mac_mcast_addr(addr->ether.addr);
}

/*
 * Don't learn certain addresses.
 */
bool
mroute_learnable_address(const struct mroute_addr *addr, struct gc_arena *gc)
{
    int i;
    bool all_zeros = true;
    bool all_ones = true;

    for (i = 0; i < addr->len; ++i)
    {
        int b = addr->raw_addr[i];
        if (b != 0x00)
        {
            all_zeros = false;
        }
        if (b != 0xFF)
        {
            all_ones = false;
        }
    }

    /* only networkss shorter than 8 bits are allowed to be all 0s. */
    if (all_zeros
        && !((addr->type & MR_WITH_NETBITS) && (addr->netbits < 8)))
    {
        msg(D_MULTI_LOW, "Can't learn %s: network is all 0s, but netbits >= 8",
            mroute_addr_print(addr, gc));
        return false;
    }

    if (all_ones)
    {
        msg(D_MULTI_LOW, "Can't learn %s: network is all 1s",
            mroute_addr_print(addr, gc));
        return false;
    }

    if (is_mac_mcast_maddr(addr))
    {
        msg(D_MULTI_LOW, "Can't learn %s: network is a multicast address",
            mroute_addr_print(addr, gc));
        return false;
    }

    return true;
}

static inline void
mroute_get_in_addr_t(struct mroute_addr *ma, const in_addr_t src, unsigned int mask)
{
    if (ma)
    {
        ma->type = MR_ADDR_IPV4 | mask;
        ma->netbits = 0;
        ma->len = 4;
        ma->v4.addr = src;
    }
}

static inline void
mroute_get_in6_addr(struct mroute_addr *ma, const struct in6_addr src, unsigned int mask)
{
    if (ma)
    {
        ma->type = MR_ADDR_IPV6 | mask;
        ma->netbits = 0;
        ma->len = 16;
        ma->v6.addr = src;
    }
}

static inline bool
mroute_is_mcast(const in_addr_t addr)
{
    return ((addr & htonl(IP_MCAST_SUBNET_MASK)) == htonl(IP_MCAST_NETWORK));
}

/* RFC 4291, 2.7, "binary 11111111 at the start of an address identifies
 *                 the address as being a multicast address"
 */
static inline bool
mroute_is_mcast_ipv6(const struct in6_addr addr)
{
    return (addr.s6_addr[0] == 0xff);
}


unsigned int
mroute_extract_addr_ip(struct mroute_addr *src, struct mroute_addr *dest,
                       const struct buffer *buf)
{
    unsigned int ret = 0;
    if (BLEN(buf) >= 1)
    {
        switch (OPENVPN_IPH_GET_VER(*BPTR(buf)))
        {
            case 4:
                if (BLEN(buf) >= (int) sizeof(struct openvpn_iphdr))
                {
                    const struct openvpn_iphdr *ip = (const struct openvpn_iphdr *) BPTR(buf);

                    mroute_get_in_addr_t(src, ip->saddr, 0);
                    mroute_get_in_addr_t(dest, ip->daddr, 0);

                    /* multicast packet? */
                    if (mroute_is_mcast(ip->daddr))
                    {
                        ret |= MROUTE_EXTRACT_MCAST;
                    }

                    /* IGMP message? */
                    if (ip->protocol == OPENVPN_IPPROTO_IGMP)
                    {
                        ret |= MROUTE_EXTRACT_IGMP;
                    }

                    ret |= MROUTE_EXTRACT_SUCCEEDED;
                }
                break;

            case 6:
                if (BLEN(buf) >= (int) sizeof(struct openvpn_ipv6hdr))
                {
                    const struct openvpn_ipv6hdr *ipv6 = (const struct openvpn_ipv6hdr *) BPTR(buf);
#if 0                           /* very basic debug */
                    struct gc_arena gc = gc_new();
                    msg( M_INFO, "IPv6 packet! src=%s, dst=%s",
                         print_in6_addr( ipv6->saddr, 0, &gc ),
                         print_in6_addr( ipv6->daddr, 0, &gc ));
                    gc_free(&gc);
#endif

                    mroute_get_in6_addr(src, ipv6->saddr, 0);
                    mroute_get_in6_addr(dest, ipv6->daddr, 0);

                    if (mroute_is_mcast_ipv6(ipv6->daddr))
                    {
                        ret |= MROUTE_EXTRACT_MCAST;
                    }

                    ret |= MROUTE_EXTRACT_SUCCEEDED;
                }
                break;

            default:
                msg(M_WARN, "IP packet with unknown IP version=%d seen",
                    OPENVPN_IPH_GET_VER(*BPTR(buf)));
        }
    }
    return ret;
}

static void
mroute_copy_ether_to_addr(struct mroute_addr *maddr,
                          const uint8_t *ether_addr,
                          uint16_t vid)
{
    maddr->type = MR_ADDR_ETHER;
    maddr->netbits = 0;
    maddr->len = OPENVPN_ETH_ALEN;
    memcpy(maddr->ether.addr, ether_addr, OPENVPN_ETH_ALEN);
    maddr->len += sizeof(vid);
    maddr->ether.vid = vid;
}

unsigned int
mroute_extract_addr_ether(struct mroute_addr *src,
                          struct mroute_addr *dest,
                          uint16_t vid,
                          const struct buffer *buf)
{
    unsigned int ret = 0;
    if (BLEN(buf) >= (int) sizeof(struct openvpn_ethhdr))
    {
        const struct openvpn_ethhdr *eth = (const struct openvpn_ethhdr *) BPTR(buf);
        if (src)
        {
            mroute_copy_ether_to_addr(src, eth->source, vid);
        }
        if (dest)
        {
            mroute_copy_ether_to_addr(dest, eth->dest, vid);

            /* ethernet broadcast/multicast packet? */
            if (is_mac_mcast_addr(eth->dest))
            {
                ret |= MROUTE_EXTRACT_BCAST;
            }
        }

        ret |= MROUTE_EXTRACT_SUCCEEDED;

    }
    return ret;
}

/*
 * Translate a struct openvpn_sockaddr (osaddr)
 * to a struct mroute_addr (addr).
 */
bool
mroute_extract_openvpn_sockaddr(struct mroute_addr *addr,
                                const struct openvpn_sockaddr *osaddr,
                                bool use_port)
{
    switch (osaddr->addr.sa.sa_family)
    {
        case AF_INET:
        {
            if (use_port)
            {
                addr->type = MR_ADDR_IPV4 | MR_WITH_PORT;
                addr->netbits = 0;
                addr->len = 6;
                addr->v4.addr = osaddr->addr.in4.sin_addr.s_addr;
                addr->v4.port = osaddr->addr.in4.sin_port;
            }
            else
            {
                addr->type = MR_ADDR_IPV4;
                addr->netbits = 0;
                addr->len = 4;
                addr->v4.addr = osaddr->addr.in4.sin_addr.s_addr;
            }
            return true;
        }

        case AF_INET6:
            if (use_port)
            {
                addr->type = MR_ADDR_IPV6 | MR_WITH_PORT;
                addr->netbits = 0;
                addr->len = 18;
                addr->v6.addr = osaddr->addr.in6.sin6_addr;
                addr->v6.port = osaddr->addr.in6.sin6_port;
            }
            else
            {
                addr->type = MR_ADDR_IPV6;
                addr->netbits = 0;
                addr->len = 16;
                addr->v6.addr = osaddr->addr.in6.sin6_addr;
            }
            return true;
    }
    return false;
}

/*
 * Zero off the host bits in an address, leaving
 * only the network bits, using the netbits member of
 * struct mroute_addr as the controlling parameter.
 *
 * TODO: this is called for route-lookup for every yet-unhashed
 * destination address, so for lots of active net-iroutes, this
 * might benefit from some "zeroize 32 bit at a time" improvements
 */
void
mroute_addr_mask_host_bits(struct mroute_addr *ma)
{
    if ((ma->type & MR_ADDR_MASK) == MR_ADDR_IPV4)
    {
        in_addr_t addr = ntohl(ma->v4.addr);
        addr &= netbits_to_netmask(ma->netbits);
        ma->v4.addr = htonl(addr);
    }
    else if ((ma->type & MR_ADDR_MASK) == MR_ADDR_IPV6)
    {
        int byte = sizeof(ma->v6.addr) - 1;     /* rightmost byte in address */
        int bits_to_clear = 128 - ma->netbits;

        while (byte >= 0 && bits_to_clear > 0)
        {
            if (bits_to_clear >= 8)
            {
                ma->v6.addr.s6_addr[byte--] = 0;
                bits_to_clear -= 8;
            }
            else
            {
                ma->v6.addr.s6_addr[byte--] &= (IPV4_NETMASK_HOST << bits_to_clear);
                bits_to_clear = 0;
            }
        }
        ASSERT( bits_to_clear == 0 );
    }
    else
    {
        ASSERT(0);
    }
}

/*
 * The mroute_addr hash function takes into account the
 * address type, number of bits in the network address,
 * and the actual address.
 */
uint32_t
mroute_addr_hash_function(const void *key, uint32_t iv)
{
    return hash_func(mroute_addr_hash_ptr((const struct mroute_addr *) key),
                     mroute_addr_hash_len((const struct mroute_addr *) key),
                     iv);
}

bool
mroute_addr_compare_function(const void *key1, const void *key2)
{
    return mroute_addr_equal((const struct mroute_addr *) key1,
                             (const struct mroute_addr *) key2);
}

const char *
mroute_addr_print(const struct mroute_addr *ma,
                  struct gc_arena *gc)
{
    return mroute_addr_print_ex(ma, MAPF_IA_EMPTY_IF_UNDEF, gc);
}

const char *
mroute_addr_print_ex(const struct mroute_addr *ma,
                     const unsigned int flags,
                     struct gc_arena *gc)
{
    struct buffer out = alloc_buf_gc(64, gc);
    if (ma)
    {
        struct mroute_addr maddr = *ma;

        switch (maddr.type & MR_ADDR_MASK)
        {
            case MR_ADDR_ETHER:
                buf_printf(&out, "%s", format_hex_ex(ma->ether.addr,
                                                     sizeof(ma->ether.addr), 0, 1, ":", gc));
                buf_printf(&out, "@%hu", ma->ether.vid);
                break;

            case MR_ADDR_IPV4:
            {
                if ((flags & MAPF_SHOW_ARP) && (maddr.type & MR_ARP))
                {
                    buf_printf(&out, "ARP/");
                }
                buf_printf(&out, "%s", print_in_addr_t(ntohl(maddr.v4.addr),
                                                       (flags & MAPF_IA_EMPTY_IF_UNDEF) ? IA_EMPTY_IF_UNDEF : 0, gc));
                if (maddr.type & MR_WITH_NETBITS)
                {
                    if (flags & MAPF_SUBNET)
                    {
                        const in_addr_t netmask = netbits_to_netmask(maddr.netbits);
                        buf_printf(&out, "/%s", print_in_addr_t(netmask, 0, gc));
                    }
                    else
                    {
                        buf_printf(&out, "/%d", maddr.netbits);
                    }
                }
                if (maddr.type & MR_WITH_PORT)
                {
                    buf_printf(&out, ":%d", ntohs(maddr.v4.port));
                }
            }
            break;

            case MR_ADDR_IPV6:
            {
                if (IN6_IS_ADDR_V4MAPPED( &maddr.v6.addr ) )
                {
                    buf_printf(&out, "%s", print_in_addr_t(maddr.v4mappedv6.addr,
                                                           IA_NET_ORDER, gc));
                    /* we only print port numbers for v4mapped v6 as of
                     * today, because "v6addr:port" is too ambiguous
                     */
                    if (maddr.type & MR_WITH_PORT)
                    {
                        buf_printf(&out, ":%d", ntohs(maddr.v6.port));
                    }
                }
                else
                {
                    buf_printf(&out, "%s", print_in6_addr(maddr.v6.addr, 0, gc));
                }
                if (maddr.type & MR_WITH_NETBITS)
                {
                    buf_printf(&out, "/%d", maddr.netbits);
                }
            }
            break;

            default:
                buf_printf(&out, "UNKNOWN");
                break;
        }
        return BSTR(&out);
    }
    else
    {
        return "[NULL]";
    }
}

/*
 * mroute_helper's main job is keeping track of
 * currently used CIDR netlengths, so we don't
 * have to cycle through all 33.
 */

struct mroute_helper *
mroute_helper_init(int ageable_ttl_secs)
{
    struct mroute_helper *mh;
    ALLOC_OBJ_CLEAR(mh, struct mroute_helper);
    mh->ageable_ttl_secs = ageable_ttl_secs;
    return mh;
}

static void
mroute_helper_regenerate(struct mroute_helper *mh)
{
    int i, j = 0;
    for (i = MR_HELPER_NET_LEN - 1; i >= 0; --i)
    {
        if (mh->net_len_refcount[i] > 0)
        {
            mh->net_len[j++] = (uint8_t) i;
        }
    }
    mh->n_net_len = j;

#ifdef ENABLE_DEBUG
    if (check_debug_level(D_MULTI_DEBUG))
    {
        struct gc_arena gc = gc_new();
        struct buffer out = alloc_buf_gc(256, &gc);
        buf_printf(&out, "MROUTE CIDR netlen:");
        for (i = 0; i < mh->n_net_len; ++i)
        {
            buf_printf(&out, " /%d", mh->net_len[i]);
        }
        dmsg(D_MULTI_DEBUG, "%s", BSTR(&out));
        gc_free(&gc);
    }
#endif
}

void
mroute_helper_add_iroute46(struct mroute_helper *mh, int netbits)
{
    if (netbits >= 0)
    {
        ASSERT(netbits < MR_HELPER_NET_LEN);
        ++mh->cache_generation;
        ++mh->net_len_refcount[netbits];
        if (mh->net_len_refcount[netbits] == 1)
        {
            mroute_helper_regenerate(mh);
        }
    }
}

void
mroute_helper_del_iroute46(struct mroute_helper *mh, int netbits)
{
    if (netbits >= 0)
    {
        ASSERT(netbits < MR_HELPER_NET_LEN);
        ++mh->cache_generation;
        --mh->net_len_refcount[netbits];
        ASSERT(mh->net_len_refcount[netbits] >= 0);
        if (!mh->net_len_refcount[netbits])
        {
            mroute_helper_regenerate(mh);
        }
    }
}

void
mroute_helper_free(struct mroute_helper *mh)
{
    free(mh);
}
