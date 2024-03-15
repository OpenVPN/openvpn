/*
 *  OpenVPN -- An application to securely tunnel IP networks
 *             over a single TCP/UDP port, with support for SSL/TLS-based
 *             session authentication and key exchange,
 *             packet encryption, packet authentication, and
 *             packet compression.
 *
 *  Copyright (C) 2002-2024 OpenVPN Inc <sales@openvpn.net>
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

#ifndef MROUTE_H
#define MROUTE_H

#include "buffer.h"
#include "list.h"
#include "route.h"

#include <stddef.h>

#define IP_MCAST_SUBNET_MASK  ((in_addr_t)240<<24)
#define IP_MCAST_NETWORK      ((in_addr_t)224<<24)

/* Return status values for mroute_extract_addr_from_packet */

#define MROUTE_EXTRACT_SUCCEEDED (1<<0)
#define MROUTE_EXTRACT_BCAST     (1<<1)
#define MROUTE_EXTRACT_MCAST     (1<<2)
#define MROUTE_EXTRACT_IGMP      (1<<3)

#define MROUTE_SEC_EXTRACT_SUCCEEDED (1<<(0+MROUTE_SEC_SHIFT))
#define MROUTE_SEC_EXTRACT_BCAST     (1<<(1+MROUTE_SEC_SHIFT))
#define MROUTE_SEC_EXTRACT_MCAST     (1<<(2+MROUTE_SEC_SHIFT))
#define MROUTE_SEC_EXTRACT_IGMP      (1<<(3+MROUTE_SEC_SHIFT))

#define MROUTE_SEC_SHIFT         4

/*
 * Choose the largest address possible with
 * any of our supported types, which is IPv6
 * with port number.
 */
#define MR_MAX_ADDR_LEN 20

/*
 * Address Types
 */
#define MR_ADDR_NONE             0
#define MR_ADDR_ETHER            1
#define MR_ADDR_IPV4             2
#define MR_ADDR_IPV6             3
#define MR_ADDR_MASK             3

/* Address type mask indicating that port # is part of address */
#define MR_WITH_PORT             4

/* Address type mask indicating that netbits is part of address */
#define MR_WITH_NETBITS          8

/* Indicates than IPv4 addr was extracted from ARP packet */
#define MR_ARP                   16

struct mroute_addr {
    uint8_t len;    /* length of address */
    uint8_t unused;
    uint8_t type;   /* MR_ADDR/MR_WITH flags */
    uint8_t netbits; /* number of bits in network part of address,
                      * valid if MR_WITH_NETBITS is set */
    union {
        uint8_t raw_addr[MR_MAX_ADDR_LEN]; /* actual address */
        struct {
            uint8_t addr[OPENVPN_ETH_ALEN];
            uint16_t vid;
        } ether;
        struct {
            in_addr_t addr;     /* _network order_ IPv4 address */
            in_port_t port;     /* _network order_ TCP/UDP port */
        } v4;
        struct {
            struct in6_addr addr;
            in_port_t port;     /* _network order_ TCP/UDP port */
        } v6;
        struct {
            uint8_t prefix[12];
            in_addr_t addr;     /* _network order_ IPv4 address */
        } v4mappedv6;
    }
#ifndef HAVE_ANONYMOUS_UNION_SUPPORT
/* Wrappers to support compilers that do not grok anonymous unions */
        mroute_union
#define raw_addr mroute_union.raw_addr
#define ether mroute_union.ether
#define v4 mroute_union.v4
#define v6 mroute_union.v6
#define v4mappedv6 mroute_union.v4mappedv6
#endif
    ;
};

/* Double-check that struct packing works as expected */
static_assert(offsetof(struct mroute_addr, v4.port) ==
              offsetof(struct mroute_addr, v4) + 4,
              "Unexpected struct packing of v4");
static_assert(offsetof(struct mroute_addr, v6.port) ==
              offsetof(struct mroute_addr, v6) + 16,
              "Unexpected struct packing of v6");
static_assert(offsetof(struct mroute_addr, v4mappedv6.addr) ==
              offsetof(struct mroute_addr, v4mappedv6) + 12,
              "Unexpected struct packing of v4mappedv6");

/*
 * Number of bits in an address.  Should be raised for IPv6.
 */
#define MR_HELPER_NET_LEN 129

/*
 * Used to help maintain CIDR routing table.
 */
struct mroute_helper {
    unsigned int cache_generation; /* incremented when route added */
    int ageable_ttl_secs;        /* host route cache entry time-to-live*/
    int n_net_len;               /* length of net_len array */
    uint8_t net_len[MR_HELPER_NET_LEN];    /* CIDR netlengths in descending order */
    int net_len_refcount[MR_HELPER_NET_LEN]; /* refcount of each netlength */
};

struct openvpn_sockaddr;

bool mroute_extract_openvpn_sockaddr(struct mroute_addr *addr,
                                     const struct openvpn_sockaddr *osaddr,
                                     bool use_port);

bool mroute_learnable_address(const struct mroute_addr *addr,
                              struct gc_arena *gc);

uint32_t mroute_addr_hash_function(const void *key, uint32_t iv);

bool mroute_addr_compare_function(const void *key1, const void *key2);

void mroute_addr_init(struct mroute_addr *addr);

const char *mroute_addr_print(const struct mroute_addr *ma,
                              struct gc_arena *gc);

#define MAPF_SUBNET            (1<<0)
#define MAPF_IA_EMPTY_IF_UNDEF (1<<1)
#define MAPF_SHOW_ARP          (1<<2)
const char *mroute_addr_print_ex(const struct mroute_addr *ma,
                                 const unsigned int flags,
                                 struct gc_arena *gc);

void mroute_addr_mask_host_bits(struct mroute_addr *ma);

struct mroute_helper *mroute_helper_init(int ageable_ttl_secs);

void mroute_helper_free(struct mroute_helper *mh);

void mroute_helper_add_iroute46(struct mroute_helper *mh, int netbits);

void mroute_helper_del_iroute46(struct mroute_helper *mh, int netbits);

unsigned int mroute_extract_addr_ip(struct mroute_addr *src,
                                    struct mroute_addr *dest,
                                    const struct buffer *buf);

unsigned int mroute_extract_addr_ether(struct mroute_addr *src,
                                       struct mroute_addr *dest,
                                       uint16_t vid,
                                       const struct buffer *buf);

/*
 * Given a raw packet in buf, return the src and dest
 * addresses of the packet.
 */
static inline unsigned int
mroute_extract_addr_from_packet(struct mroute_addr *src,
                                struct mroute_addr *dest,
                                uint16_t vid,
                                const struct buffer *buf,
                                int tunnel_type)
{
    unsigned int ret = 0;
    verify_align_4(buf);
    if (tunnel_type == DEV_TYPE_TUN)
    {
        ret = mroute_extract_addr_ip(src, dest, buf);
    }
    else if (tunnel_type == DEV_TYPE_TAP)
    {
        ret = mroute_extract_addr_ether(src, dest, vid, buf);
    }
    return ret;
}

static inline bool
mroute_addr_equal(const struct mroute_addr *a1, const struct mroute_addr *a2)
{
    if (a1->type != a2->type)
    {
        return false;
    }
    if (a1->netbits != a2->netbits)
    {
        return false;
    }
    if (a1->len != a2->len)
    {
        return false;
    }
    return memcmp(a1->raw_addr, a2->raw_addr, a1->len) == 0;
}

static inline const uint8_t *
mroute_addr_hash_ptr(const struct mroute_addr *a)
{
    /* NOTE: depends on ordering of struct mroute_addr */
    return (uint8_t *) &a->type;
}

static inline uint32_t
mroute_addr_hash_len(const struct mroute_addr *a)
{
    return (uint32_t) a->len + 2;
}

static inline void
mroute_extract_in_addr_t(struct mroute_addr *dest, const in_addr_t src)
{
    dest->type = MR_ADDR_IPV4;
    dest->netbits = 0;
    dest->len = 4;
    dest->v4.addr = htonl(src);
}

static inline in_addr_t
in_addr_t_from_mroute_addr(const struct mroute_addr *addr)
{
    if ((addr->type & MR_ADDR_MASK) == MR_ADDR_IPV4 && addr->netbits == 0 && addr->len == 4)
    {
        return ntohl(addr->v4.addr);
    }
    else
    {
        return 0;
    }
}

static inline void
mroute_addr_reset(struct mroute_addr *ma)
{
    ma->len = 0;
    ma->type = MR_ADDR_NONE;
}

#endif /* MROUTE_H */
