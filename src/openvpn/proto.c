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

#include "proto.h"
#include "error.h"

#include "memdbg.h"

/*
 * If raw tunnel packet is IPv<X>, return true and increment
 * buffer offset to start of IP header.
 */
static bool
is_ipv_X(int tunnel_type, struct buffer *buf, int ip_ver)
{
    int offset;
    uint16_t proto;
    const struct openvpn_iphdr *ih;

    verify_align_4(buf);
    if (tunnel_type == DEV_TYPE_TUN)
    {
        if (BLEN(buf) < sizeof(struct openvpn_iphdr))
        {
            return false;
        }
        offset = 0;
    }
    else if (tunnel_type == DEV_TYPE_TAP)
    {
        const struct openvpn_ethhdr *eh;
        if (BLEN(buf) < (sizeof(struct openvpn_ethhdr)
                         + sizeof(struct openvpn_iphdr)))
        {
            return false;
        }
        eh = (const struct openvpn_ethhdr *)BPTR(buf);

        /* start by assuming this is a standard Eth fram */
        proto = eh->proto;
        offset = sizeof(struct openvpn_ethhdr);

        /* if this is a 802.1q frame, parse the header using the according
         * format
         */
        if (proto == htons(OPENVPN_ETH_P_8021Q))
        {
            const struct openvpn_8021qhdr *evh;
            if (BLEN(buf) < (sizeof(struct openvpn_ethhdr)
                             + sizeof(struct openvpn_iphdr)))
            {
                return false;
            }

            evh = (const struct openvpn_8021qhdr *)BPTR(buf);

            proto = evh->proto;
            offset = sizeof(struct openvpn_8021qhdr);
        }

        if (ntohs(proto) != (ip_ver == 6 ? OPENVPN_ETH_P_IPV6 : OPENVPN_ETH_P_IPV4))
        {
            return false;
        }
    }
    else
    {
        return false;
    }

    ih = (const struct openvpn_iphdr *)(BPTR(buf) + offset);

    /* IP version is stored in the same bits for IPv4 or IPv6 header */
    if (OPENVPN_IPH_GET_VER(ih->version_len) == ip_ver)
    {
        return buf_advance(buf, offset);
    }
    else
    {
        return false;
    }
}

bool
is_ipv4(int tunnel_type, struct buffer *buf)
{
    return is_ipv_X( tunnel_type, buf, 4 );
}
bool
is_ipv6(int tunnel_type, struct buffer *buf)
{
    return is_ipv_X( tunnel_type, buf, 6 );
}


uint16_t
ip_checksum(const sa_family_t af, const uint8_t *payload, const int len_payload,
            const uint8_t *src_addr, const uint8_t *dest_addr, const int proto)
{
    uint32_t sum = 0;
    int addr_len = (af == AF_INET) ? 4 : 16;

    /*
     * make 16 bit words out of every two adjacent 8 bit words and  */
    /* calculate the sum of all 16 bit words
     */
    for (int i = 0; i < len_payload; i += 2)
    {
        sum +=  (uint16_t)(((payload[i] << 8) & 0xFF00)
                           +((i + 1 < len_payload) ? (payload[i + 1] & 0xFF) : 0));

    }

    /*
     * add the pseudo header which contains the IP source and destination
     * addresses
     */
    for (int i = 0; i < addr_len; i += 2)
    {
        sum += (uint16_t)((src_addr[i] << 8) & 0xFF00) + (src_addr[i + 1] & 0xFF);

    }
    for (int i = 0; i < addr_len; i += 2)
    {
        sum += (uint16_t)((dest_addr[i] << 8) & 0xFF00) + (dest_addr[i + 1] & 0xFF);
    }

    /* the length of the payload */
    sum += (uint16_t)len_payload;

    /* The next header or proto field*/
    sum += (uint16_t)proto;

    /*
     * keep only the last 16 bits of the 32 bit calculated sum and add
     * the carries
     */
    while (sum >> 16)
    {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }

    /* Take the one's complement of sum */
    return ((uint16_t) ~sum);
}

#ifdef PACKET_TRUNCATION_CHECK

void
ipv4_packet_size_verify(const uint8_t *data,
                        const int size,
                        const int tunnel_type,
                        const char *prefix,
                        counter_type *errors)
{
    if (size > 0)
    {
        struct buffer buf;

        buf_set_read(&buf, data, size);

        if (is_ipv4(tunnel_type, &buf))
        {
            const struct openvpn_iphdr *pip;
            int hlen;
            int totlen;
            const char *msgstr = "PACKET SIZE INFO";
            unsigned int msglevel = D_PACKET_TRUNC_DEBUG;

            if (BLEN(&buf) < (int) sizeof(struct openvpn_iphdr))
            {
                return;
            }

            verify_align_4(&buf);
            pip = (struct openvpn_iphdr *) BPTR(&buf);

            hlen = OPENVPN_IPH_GET_LEN(pip->version_len);
            totlen = ntohs(pip->tot_len);

            if (BLEN(&buf) != totlen)
            {
                msgstr = "PACKET TRUNCATION ERROR";
                msglevel = D_PACKET_TRUNC_ERR;
                if (errors)
                {
                    ++(*errors);
                }
            }

            msg(msglevel, "%s %s: size=%d totlen=%d hlen=%d errcount=" counter_format,
                msgstr,
                prefix,
                BLEN(&buf),
                totlen,
                hlen,
                errors ? *errors : (counter_type)0);
        }
    }
}

#endif /* ifdef PACKET_TRUNCATION_CHECK */
