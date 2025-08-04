/*
 *  OpenVPN -- An application to securely tunnel IP networks
 *             over a single TCP/UDP port, with support for SSL/TLS-based
 *             session authentication and key exchange,
 *             packet encryption, packet authentication, and
 *             packet compression.
 *
 *  Copyright (C) 2002-2025 OpenVPN Inc <sales@openvpn.net>
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

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "syshead.h"

#include "dhcp.h"
#include "socket.h"
#include "error.h"

#include "memdbg.h"

static int
get_dhcp_message_type(const struct dhcp *dhcp, const int optlen)
{
    const uint8_t *p = (uint8_t *) (dhcp + 1);
    int i;

    for (i = 0; i < optlen; ++i)
    {
        const uint8_t type = p[i];
        const int room = optlen - i;
        if (type == DHCP_END)         /* didn't find what we were looking for */
        {
            return -1;
        }
        else if (type == DHCP_PAD)    /* no-operation */
        {
        }
        else if (type == DHCP_MSG_TYPE) /* what we are looking for */
        {
            if (room >= 3)
            {
                if (p[i+1] == 1)      /* option length should be 1 */
                {
                    return p[i+2];    /* return message type */
                }
            }
            return -1;
        }
        else                          /* some other option */
        {
            if (room >= 2)
            {
                const int len = p[i+1]; /* get option length */
                i += (len + 1);       /* advance to next option */
            }
        }
    }
    return -1;
}

static in_addr_t
do_extract(struct dhcp *dhcp, int optlen)
{
    uint8_t *p = (uint8_t *) (dhcp + 1);
    int i;
    in_addr_t ret = 0;

    for (i = 0; i < optlen; )
    {
        const uint8_t type = p[i];
        const int room = optlen - i;
        if (type == DHCP_END)
        {
            break;
        }
        else if (type == DHCP_PAD)
        {
            ++i;
        }
        else if (type == DHCP_ROUTER)
        {
            if (room >= 2)
            {
                const int len = p[i+1]; /* get option length */
                if (len <= (room-2))
                {
                    /* get router IP address */
                    if (!ret && len >= 4 && (len & 3) == 0)
                    {
                        memcpy(&ret, p+i+2, 4);
                        ret = ntohl(ret);
                    }
                    {
                        /* delete the router option */
                        uint8_t *dest = p + i;
                        const int owlen = len + 2;        /* len of data to overwrite */
                        uint8_t *src = dest + owlen;
                        uint8_t *end = p + optlen;
                        const int movlen = end - src;
                        if (movlen > 0)
                        {
                            memmove(dest, src, movlen);   /* overwrite router option */
                        }
                        memset(end - owlen, DHCP_PAD, owlen); /* pad tail */
                    }
                }
                else
                {
                    break;
                }
            }
            else
            {
                break;
            }
        }
        else                            /* some other option */
        {
            if (room >= 2)
            {
                const int len = p[i+1]; /* get option length */
                i += (len + 2);         /* advance to next option */
            }
            else
            {
                break;
            }
        }
    }
    return ret;
}

in_addr_t
dhcp_extract_router_msg(struct buffer *ipbuf)
{
    struct dhcp_full *df = (struct dhcp_full *) BPTR(ipbuf);
    const int optlen = BLEN(ipbuf) - (sizeof(struct openvpn_iphdr) + sizeof(struct openvpn_udphdr) + sizeof(struct dhcp));

    if (optlen >= 0
        && df->ip.protocol == OPENVPN_IPPROTO_UDP
        && df->udp.source == htons(BOOTPS_PORT)
        && df->udp.dest == htons(BOOTPC_PORT)
        && df->dhcp.op == BOOTREPLY)
    {
        const int message_type = get_dhcp_message_type(&df->dhcp, optlen);
        if (message_type == DHCPACK || message_type == DHCPOFFER)
        {
            /* get the router IP address while padding out all DHCP router options */
            const in_addr_t ret = do_extract(&df->dhcp, optlen);

            /* recompute the UDP checksum */
            df->udp.check = 0;
            df->udp.check = htons(ip_checksum(AF_INET, (uint8_t *)&df->udp,
                                              sizeof(struct openvpn_udphdr) + sizeof(struct dhcp) + optlen,
                                              (uint8_t *)&df->ip.saddr, (uint8_t *)&df->ip.daddr,
                                              OPENVPN_IPPROTO_UDP));

            /* only return the extracted Router address if DHCPACK */
            if (message_type == DHCPACK)
            {
                if (ret)
                {
                    struct gc_arena gc = gc_new();
                    msg(D_ROUTE, "Extracted DHCP router address: %s", print_in_addr_t(ret, 0, &gc));
                    gc_free(&gc);
                }

                return ret;
            }
        }
    }
    return 0;
}
