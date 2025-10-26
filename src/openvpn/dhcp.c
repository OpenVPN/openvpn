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
#include "socket_util.h"
#include "error.h"

#include "memdbg.h"

static int
get_dhcp_message_type(const struct dhcp *dhcp, const int optlen)
{
    const uint8_t *p = (uint8_t *)(dhcp + 1);
    int i;

    for (i = 0; i < optlen; ++i)
    {
        const uint8_t type = p[i];
        const int room = optlen - i;
        if (type == DHCP_END) /* didn't find what we were looking for */
        {
            return -1;
        }
        else if (type == DHCP_PAD) /* no-operation */
        {
        }
        else if (type == DHCP_MSG_TYPE) /* what we are looking for */
        {
            if (room >= 3)
            {
                if (p[i + 1] == 1)   /* option length should be 1 */
                {
                    return p[i + 2]; /* return message type */
                }
            }
            return -1;
        }
        else /* some other option */
        {
            if (room >= 2)
            {
                const int len = p[i + 1]; /* get option length */
                i += (len + 1);           /* advance to next option */
            }
        }
    }
    return -1;
}

static in_addr_t
do_extract(struct dhcp *dhcp, int optlen)
{
    uint8_t *p = (uint8_t *)(dhcp + 1);
    int i;
    in_addr_t ret = 0;

    for (i = 0; i < optlen;)
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
                const int len = p[i + 1]; /* get option length */
                if (len <= (room - 2))
                {
                    /* get router IP address */
                    if (!ret && len >= 4 && (len & 3) == 0)
                    {
                        memcpy(&ret, p + i + 2, 4);
                        ret = ntohl(ret);
                    }
                    {
                        /* delete the router option */
                        uint8_t *dest = p + i;
                        const int owlen = len + 2; /* len of data to overwrite */
                        uint8_t *src = dest + owlen;
                        uint8_t *end = p + optlen;
                        const intptr_t movlen = end - src;
                        if (movlen > 0)
                        {
                            memmove(dest, src, movlen);       /* overwrite router option */
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
        else /* some other option */
        {
            if (room >= 2)
            {
                const int len = p[i + 1]; /* get option length */
                i += (len + 2);           /* advance to next option */
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
    struct dhcp_full *df = (struct dhcp_full *)BPTR(ipbuf);
    const int optlen =
        BLEN(ipbuf)
        - (int)(sizeof(struct openvpn_iphdr) + sizeof(struct openvpn_udphdr) + sizeof(struct dhcp));

    if (optlen >= 0 && df->ip.protocol == OPENVPN_IPPROTO_UDP
        && df->udp.source == htons(BOOTPS_PORT) && df->udp.dest == htons(BOOTPC_PORT)
        && df->dhcp.op == BOOTREPLY)
    {
        const int message_type = get_dhcp_message_type(&df->dhcp, optlen);
        if (message_type == DHCPACK || message_type == DHCPOFFER)
        {
            /* get the router IP address while padding out all DHCP router options */
            const in_addr_t ret = do_extract(&df->dhcp, optlen);

            /* recompute the UDP checksum */
            df->udp.check = 0;
            df->udp.check = htons(ip_checksum(
                AF_INET, (uint8_t *)&df->udp,
                sizeof(struct openvpn_udphdr) + sizeof(struct dhcp) + optlen,
                (uint8_t *)&df->ip.saddr, (uint8_t *)&df->ip.daddr, OPENVPN_IPPROTO_UDP));

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

#if defined(DHCP_UNIT_TEST)

/*
 * Convert DHCP options from the command line / config file
 * into a raw DHCP-format options string.
 */

static void
write_dhcp_u8(struct buffer *buf, const uint8_t type, const uint8_t data, bool *error)
{
    if (!buf_safe(buf, 3))
    {
        *error = true;
        msg(M_WARN, "write_dhcp_u8: buffer overflow building DHCP options");
        return;
    }
    buf_write_u8(buf, type);
    buf_write_u8(buf, 1);
    buf_write_u8(buf, data);
}

static void
write_dhcp_u32_array(struct buffer *buf, const uint8_t type, const uint32_t *data,
                     const unsigned int len, bool *error)
{
    if (len > 0)
    {
        const size_t size = len * sizeof(uint32_t);

        if (!buf_safe(buf, 2 + size))
        {
            *error = true;
            msg(M_WARN, "write_dhcp_u32_array: buffer overflow building DHCP options");
            return;
        }
        if (size < 1 || size > 255)
        {
            *error = true;
            msg(M_WARN, "write_dhcp_u32_array: size (%zu) must be > 0 and <= 255", size);
            return;
        }
        buf_write_u8(buf, type);
        buf_write_u8(buf, (uint8_t)size);
        for (unsigned int i = 0; i < len; ++i)
        {
            buf_write_u32(buf, data[i]);
        }
    }
}

static void
write_dhcp_str(struct buffer *buf, const uint8_t type, const char *str, bool *error)
{
    const size_t len = strlen(str);
    if (!buf_safe(buf, 2 + len))
    {
        *error = true;
        msg(M_WARN, "write_dhcp_str: buffer overflow building DHCP options");
        return;
    }
    if (len < 1 || len > 255)
    {
        *error = true;
        msg(M_WARN, "write_dhcp_str: string '%s' must be > 0 bytes and <= 255 bytes", str);
        return;
    }
    buf_write_u8(buf, type);
    buf_write_u8(buf, (uint8_t)len);
    buf_write(buf, str, len);
}

/*
 * RFC3397 states that multiple searchdomains are encoded as follows:
 *  - at start the length of the entire option is given
 *  - each subdomain is preceded by its length
 *  - each searchdomain is separated by a NUL character
 * e.g. if you want "openvpn.net" and "duckduckgo.com" then you end up with
 *  0x1D  0x7 openvpn 0x3 net 0x00 0x0A duckduckgo 0x3 com 0x00
 */
static void
write_dhcp_search_str(struct buffer *buf, const uint8_t type, const char *const *str_array,
                      int array_len, bool *error)
{
    char tmp_buf[256];
    size_t len = 0;
    size_t label_length_pos;

    for (int i = 0; i < array_len; i++)
    {
        const char *ptr = str_array[i];

        if (strlen(ptr) + len + 1 > sizeof(tmp_buf))
        {
            *error = true;
            msg(M_WARN, "write_dhcp_search_str: temp buffer overflow building DHCP options");
            return;
        }
        /* Loop over all subdomains separated by a dot and replace the dot
         * with the length of the subdomain */

        /* label_length_pos points to the byte to be replaced by the length
         * of the following domain label */
        label_length_pos = len++;

        while (true)
        {
            if (*ptr == '.' || *ptr == '\0')
            {
                /* cast is protected by sizeof(tmp_buf) */
                tmp_buf[label_length_pos] = (char)(len - label_length_pos - 1);
                label_length_pos = len;
                if (*ptr == '\0')
                {
                    break;
                }
            }
            tmp_buf[len++] = *ptr++;
        }
        /* And close off with an extra NUL char */
        tmp_buf[len++] = 0;
    }

    if (!buf_safe(buf, 2 + len))
    {
        *error = true;
        msg(M_WARN, "write_search_dhcp_str: buffer overflow building DHCP options");
        return;
    }
    if (len > 255)
    {
        *error = true;
        msg(M_WARN, "write_dhcp_search_str: search domain string must be <= 255 bytes");
        return;
    }

    buf_write_u8(buf, type);
    buf_write_u8(buf, (uint8_t)len);
    buf_write(buf, tmp_buf, len);
}

bool
build_dhcp_options_string(struct buffer *buf, const struct tuntap_options *o)
{
    bool error = false;
    if (o->domain)
    {
        write_dhcp_str(buf, DHCP_DOMAIN_NAME, o->domain, &error);
    }

    if (o->netbios_scope)
    {
        write_dhcp_str(buf, DHCP_NETBIOS_SCOPE, o->netbios_scope, &error);
    }

    if (o->netbios_node_type)
    {
        write_dhcp_u8(buf, DHCP_NETBIOS_NODE_TYPE, o->netbios_node_type, &error);
    }

    write_dhcp_u32_array(buf, DHCP_DOMAIN_SERVER, (uint32_t *)o->dns, o->dns_len, &error);
    write_dhcp_u32_array(buf, DHCP_NETBIOS_DOMAIN_SERVER, (uint32_t *)o->wins, o->wins_len, &error);
    write_dhcp_u32_array(buf, DHCP_NTP_SERVER, (uint32_t *)o->ntp, o->ntp_len, &error);
    write_dhcp_u32_array(buf, DHCP_NETBIOS_DIST_SERVER, (uint32_t *)o->nbdd, o->nbdd_len, &error);

    if (o->domain_search_list_len > 0)
    {
        write_dhcp_search_str(buf, DHCP_DOMAIN_SEARCH, o->domain_search_list, o->domain_search_list_len, &error);
    }

    /* the MS DHCP server option 'Disable Netbios-over-TCP/IP
     * is implemented as vendor option 001, value 002.
     * A value of 001 means 'leave NBT alone' which is the default */
    if (o->disable_nbt)
    {
        if (!buf_safe(buf, 8))
        {
            msg(M_WARN, "build_dhcp_options_string: buffer overflow building DHCP options");
            return false;
        }
        buf_write_u8(buf, DHCP_VENDOR);
        buf_write_u8(buf, 6); /* total length field */
        buf_write_u8(buf, 0x001);
        buf_write_u8(buf, 4); /* length of the vendor specified field */
        buf_write_u32(buf, 0x002);
    }
    return !error;
}

#endif
