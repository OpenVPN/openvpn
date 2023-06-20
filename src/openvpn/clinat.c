/*
 *  OpenVPN -- An application to securely tunnel IP networks
 *             over a single TCP/UDP port, with support for SSL/TLS-based
 *             session authentication and key exchange,
 *             packet encryption, packet authentication, and
 *             packet compression.
 *
 *  Copyright (C) 2002-2023 OpenVPN Inc <sales@openvpn.net>
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
#endif

#include "syshead.h"

#include "clinat.h"
#include "proto.h"
#include "socket.h"
#include "memdbg.h"

static bool
add_entry(struct client_nat_option_list *dest,
          const struct client_nat_entry *e)
{
    if (dest->n >= MAX_CLIENT_NAT)
    {
        msg(M_WARN, "WARNING: client-nat table overflow (max %d entries)", MAX_CLIENT_NAT);
        return false;
    }
    else
    {
        dest->entries[dest->n++] = *e;
        return true;
    }
}

void
print_client_nat_list(const struct client_nat_option_list *list, int msglevel)
{
    struct gc_arena gc = gc_new();
    int i;

    msg(msglevel, "*** CNAT list");
    if (list)
    {
        for (i = 0; i < list->n; ++i)
        {
            const struct client_nat_entry *e = &list->entries[i];
            msg(msglevel, "  CNAT[%d] t=%d %s/%s/%s",
                i,
                e->type,
                print_in_addr_t(e->network, IA_NET_ORDER, &gc),
                print_in_addr_t(e->netmask, IA_NET_ORDER, &gc),
                print_in_addr_t(e->foreign_network, IA_NET_ORDER, &gc));
        }
    }
    gc_free(&gc);
}

struct client_nat_option_list *
new_client_nat_list(struct gc_arena *gc)
{
    struct client_nat_option_list *ret;
    ALLOC_OBJ_CLEAR_GC(ret, struct client_nat_option_list, gc);
    return ret;
}

struct client_nat_option_list *
clone_client_nat_option_list(const struct client_nat_option_list *src, struct gc_arena *gc)
{
    struct client_nat_option_list *ret;
    ALLOC_OBJ_GC(ret, struct client_nat_option_list, gc);
    *ret = *src;
    return ret;
}

void
copy_client_nat_option_list(struct client_nat_option_list *dest,
                            const struct client_nat_option_list *src)
{
    int i;
    for (i = 0; i < src->n; ++i)
    {
        if (!add_entry(dest, &src->entries[i]))
        {
            break;
        }
    }
}

void
add_client_nat_to_option_list(struct client_nat_option_list *dest,
                              const char *type,
                              const char *network,
                              const char *netmask,
                              const char *foreign_network,
                              int msglevel)
{
    struct client_nat_entry e;
    bool ok;

    if (!strcmp(type, "snat"))
    {
        e.type = CN_SNAT;
    }
    else if (!strcmp(type, "dnat"))
    {
        e.type = CN_DNAT;
    }
    else
    {
        msg(msglevel, "client-nat: type must be 'snat' or 'dnat'");
        return;
    }

    e.network = getaddr(0, network, 0, &ok, NULL);
    if (!ok)
    {
        msg(msglevel, "client-nat: bad network: %s", network);
        return;
    }
    e.netmask = getaddr(0, netmask, 0, &ok, NULL);
    if (!ok)
    {
        msg(msglevel, "client-nat: bad netmask: %s", netmask);
        return;
    }
    e.foreign_network = getaddr(0, foreign_network, 0, &ok, NULL);
    if (!ok)
    {
        msg(msglevel, "client-nat: bad foreign network: %s", foreign_network);
        return;
    }

    add_entry(dest, &e);
}

#if 0
static void
print_checksum(struct openvpn_iphdr *iph, const char *prefix)
{
    uint16_t *sptr;
    unsigned int sum = 0;
    int i = 0;
    for (sptr = (uint16_t *)iph; (uint8_t *)sptr < (uint8_t *)iph + sizeof(struct openvpn_iphdr); sptr++)
    {
        i += 1;
        sum += *sptr;
    }
    msg(M_INFO, "** CKSUM[%d] %s %08x", i, prefix, sum);
}
#endif

static void
print_pkt(struct openvpn_iphdr *iph, const char *prefix, const int direction, const int msglevel)
{
    struct gc_arena gc = gc_new();

    char *dirstr = "???";
    if (direction == CN_OUTGOING)
    {
        dirstr = "OUT";
    }
    else if (direction == CN_INCOMING)
    {
        dirstr = "IN";
    }

    msg(msglevel, "** CNAT %s %s %s -> %s",
        dirstr,
        prefix,
        print_in_addr_t(iph->saddr, IA_NET_ORDER, &gc),
        print_in_addr_t(iph->daddr, IA_NET_ORDER, &gc));

    gc_free(&gc);
}

void
client_nat_transform(const struct client_nat_option_list *list,
                     struct buffer *ipbuf,
                     const int direction)
{
    struct ip_tcp_udp_hdr *h = (struct ip_tcp_udp_hdr *) BPTR(ipbuf);
    int i;
    uint32_t addr, *addr_ptr;
    const uint32_t *from, *to;
    int accumulate = 0;
    unsigned int amask;
    unsigned int alog = 0;

    if (check_debug_level(D_CLIENT_NAT))
    {
        print_pkt(&h->ip, "BEFORE", direction, D_CLIENT_NAT);
    }

    for (i = 0; i < list->n; ++i)
    {
        const struct client_nat_entry *e = &list->entries[i]; /* current NAT rule */
        if (e->type ^ direction)
        {
            addr = *(addr_ptr = &h->ip.daddr);
            amask = 2;
        }
        else
        {
            addr = *(addr_ptr = &h->ip.saddr);
            amask = 1;
        }
        if (direction)
        {
            from = &e->foreign_network;
            to = &e->network;
        }
        else
        {
            from = &e->network;
            to = &e->foreign_network;
        }

        if (((addr & e->netmask) == *from) && !(amask & alog))
        {
            /* pre-adjust IP checksum */
            ADD_CHECKSUM_32(accumulate, addr);

            /* do NAT transform */
            addr = (addr & ~e->netmask) | *to;

            /* post-adjust IP checksum */
            SUB_CHECKSUM_32(accumulate, addr);

            /* write the modified address to packet */
            *addr_ptr = addr;

            /* mark as modified */
            alog |= amask;
        }
    }
    if (alog)
    {
        if (check_debug_level(D_CLIENT_NAT))
        {
            print_pkt(&h->ip, "AFTER", direction, D_CLIENT_NAT);
        }

        ADJUST_CHECKSUM(accumulate, h->ip.check);

        if (h->ip.protocol == OPENVPN_IPPROTO_TCP)
        {
            if (BLEN(ipbuf) >= sizeof(struct openvpn_iphdr) + sizeof(struct openvpn_tcphdr))
            {
                ADJUST_CHECKSUM(accumulate, h->u.tcp.check);
            }
        }
        else if (h->ip.protocol == OPENVPN_IPPROTO_UDP)
        {
            if (BLEN(ipbuf) >= sizeof(struct openvpn_iphdr) + sizeof(struct openvpn_udphdr))
            {
                ADJUST_CHECKSUM(accumulate, h->u.udp.check);
            }
        }
    }
}
