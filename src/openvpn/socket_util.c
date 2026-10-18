/*
 *  OpenVPN -- An application to securely tunnel IP networks
 *             over a single TCP/UDP port, with support for SSL/TLS-based
 *             session authentication and key exchange,
 *             packet encryption, packet authentication, and
 *             packet compression.
 *
 *  Copyright (C) 2002-2026 OpenVPN Inc <sales@openvpn.net>
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

#include "socket_util.h"
#include "crypto.h"
#include "manage.h"

/*
 * Format IP addresses in ascii
 */

const char *
print_sockaddr_ex(const struct sockaddr *sa, const char *separator, const unsigned int flags,
                  struct gc_arena *gc)
{
    struct buffer out = alloc_buf_gc(128, gc);
    bool addr_is_defined = false;
    char hostaddr[NI_MAXHOST] = "";
    char servname[NI_MAXSERV] = "";
    int status;

    socklen_t salen = 0;
    switch (sa->sa_family)
    {
        case AF_INET:
            if (!(flags & PS_DONT_SHOW_FAMILY))
            {
                buf_puts(&out, "[AF_INET]");
            }
            salen = sizeof(struct sockaddr_in);
            addr_is_defined = ((struct sockaddr_in *)sa)->sin_addr.s_addr != 0;
            break;

        case AF_INET6:
            if (!(flags & PS_DONT_SHOW_FAMILY))
            {
                buf_puts(&out, "[AF_INET6]");
            }
            salen = sizeof(struct sockaddr_in6);
            addr_is_defined = !IN6_IS_ADDR_UNSPECIFIED(&((struct sockaddr_in6 *)sa)->sin6_addr);
            break;

        case AF_UNSPEC:
            if (!(flags & PS_DONT_SHOW_FAMILY))
            {
                return "[AF_UNSPEC]";
            }
            else
            {
                return "";
            }

        default:
            ASSERT(0);
    }

    status = getnameinfo(sa, salen, hostaddr, sizeof(hostaddr), servname, sizeof(servname),
                         NI_NUMERICHOST | NI_NUMERICSERV);

    if (status != 0)
    {
        buf_printf(&out, "[nameinfo() err: %s]", gai_strerror(status));
        return BSTR(&out);
    }

    if (!(flags & PS_DONT_SHOW_ADDR))
    {
        if (addr_is_defined)
        {
            buf_puts(&out, hostaddr);
        }
        else
        {
            buf_puts(&out, "[undef]");
        }
    }

    if ((flags & PS_SHOW_PORT) || (flags & PS_SHOW_PORT_IF_DEFINED))
    {
        if (separator)
        {
            buf_puts(&out, separator);
        }

        buf_puts(&out, servname);
    }

    return BSTR(&out);
}

const char *
print_link_socket_actual(const struct link_socket_actual *act, struct gc_arena *gc)
{
    return print_link_socket_actual_ex(act, ":", PS_SHOW_PORT | PS_SHOW_PKTINFO, gc);
}

#ifndef IF_NAMESIZE
#define IF_NAMESIZE 16
#endif

const char *
print_link_socket_actual_ex(const struct link_socket_actual *act, const char *separator,
                            const unsigned int flags, struct gc_arena *gc)
{
    if (act)
    {
        struct buffer out = alloc_buf_gc(128, gc);
        buf_printf(&out, "%s", print_sockaddr_ex(&act->dest.addr.sa, separator, flags, gc));
#if ENABLE_IP_PKTINFO
        char ifname[IF_NAMESIZE] = "[undef]";

        if ((flags & PS_SHOW_PKTINFO) && addr_defined_ipi(act))
        {
            switch (act->dest.addr.sa.sa_family)
            {
                case AF_INET:
                {
                    struct openvpn_sockaddr sa;
                    CLEAR(sa);
                    sa.addr.in4.sin_family = AF_INET;
#if defined(HAVE_IN_PKTINFO) && defined(HAVE_IPI_SPEC_DST)
                    sa.addr.in4.sin_addr = act->pi.in4.ipi_spec_dst;
                    if_indextoname(act->pi.in4.ipi_ifindex, ifname);
#elif defined(IP_RECVDSTADDR)
                    sa.addr.in4.sin_addr = act->pi.in4;
                    ifname[0] = 0;
#else /* if defined(HAVE_IN_PKTINFO) && defined(HAVE_IPI_SPEC_DST) */
#error ENABLE_IP_PKTINFO is set without IP_PKTINFO xor IP_RECVDSTADDR (fix syshead.h)
#endif
                    buf_printf(&out, " (via %s%%%s)",
                               print_sockaddr_ex(&sa.addr.sa, separator, 0, gc), ifname);
                }
                break;

                case AF_INET6:
                {
                    struct sockaddr_in6 sin6;
                    char buf[INET6_ADDRSTRLEN] = "[undef]";
                    CLEAR(sin6);
                    sin6.sin6_family = AF_INET6;
                    sin6.sin6_addr = act->pi.in6.ipi6_addr;
                    if_indextoname(act->pi.in6.ipi6_ifindex, ifname);
                    if (getnameinfo((struct sockaddr *)&sin6, sizeof(struct sockaddr_in6), buf,
                                    sizeof(buf), NULL, 0, NI_NUMERICHOST)
                        == 0)
                    {
                        buf_printf(&out, " (via %s%%%s)", buf, ifname);
                    }
                    else
                    {
                        buf_printf(&out, " (via [getnameinfo() err]%%%s)", ifname);
                    }
                }
                break;
            }
        }
#endif /* if ENABLE_IP_PKTINFO */
        return BSTR(&out);
    }
    else
    {
        return "[NULL]";
    }
}

/*
 * Convert an in_addr_t in host byte order
 * to an ascii dotted quad.
 */
const char *
print_in_addr_t(in_addr_t addr, unsigned int flags, struct gc_arena *gc)
{
    struct in_addr ia;
    char *out = gc_malloc(INET_ADDRSTRLEN, true, gc);

    if (addr || !(flags & IA_EMPTY_IF_UNDEF))
    {
        CLEAR(ia);
        ia.s_addr = (flags & IA_NET_ORDER) ? addr : htonl(addr);

        inet_ntop(AF_INET, &ia, out, INET_ADDRSTRLEN);
    }
    return out;
}

/*
 * Convert an in6_addr in host byte order
 * to an ascii representation of an IPv6 address
 */
const char *
print_in6_addr(struct in6_addr a6, unsigned int flags, struct gc_arena *gc)
{
    char *out = gc_malloc(INET6_ADDRSTRLEN, true, gc);

    if (memcmp(&a6, &in6addr_any, sizeof(a6)) != 0 || !(flags & IA_EMPTY_IF_UNDEF))
    {
        inet_ntop(AF_INET6, &a6, out, INET6_ADDRSTRLEN);
    }
    return out;
}

/*
 * Convert an in_port_t in host byte order to a string
 */
const char *
print_in_port_t(in_port_t port, struct gc_arena *gc)
{
    struct buffer buffer = alloc_buf_gc(8, gc);
    buf_printf(&buffer, "%hu", port);
    return BSTR(&buffer);
}

/* add some offset to an ipv6 address
 * (add in steps of 8 bits, taking overflow into next round)
 */
struct in6_addr
add_in6_addr(struct in6_addr base, uint32_t add)
{
    for (int i = 15; i >= 0 && add > 0; i--)
    {
        register uint32_t carry;
        register uint32_t h;

        h = base.s6_addr[i];
        base.s6_addr[i] = (h + add) & UINT8_MAX;

        /* using explicit carry for the 8-bit additions will catch
         * 8-bit and(!) 32-bit overruns nicely
         */
        carry = ((h & 0xff) + (add & 0xff)) >> 8;
        add = (add >> 8) + carry;
    }
    return base;
}

/* set environmental variables for ip/port in *addr */
void
setenv_sockaddr(struct env_set *es, const char *name_prefix, const struct openvpn_sockaddr *addr,
                const unsigned int flags)
{
    char name_buf[256];

    char buf[INET6_ADDRSTRLEN];
    switch (addr->addr.sa.sa_family)
    {
        case AF_INET:
            if (flags & SA_IP_PORT)
            {
                snprintf(name_buf, sizeof(name_buf), "%s_ip", name_prefix);
            }
            else
            {
                snprintf(name_buf, sizeof(name_buf), "%s", name_prefix);
            }

            inet_ntop(AF_INET, &addr->addr.in4.sin_addr, buf, sizeof(buf));
            setenv_str(es, name_buf, buf);

            if ((flags & SA_IP_PORT) && addr->addr.in4.sin_port)
            {
                snprintf(name_buf, sizeof(name_buf), "%s_port", name_prefix);
                setenv_int(es, name_buf, ntohs(addr->addr.in4.sin_port));
            }
            break;

        case AF_INET6:
            if (IN6_IS_ADDR_V4MAPPED(&addr->addr.in6.sin6_addr))
            {
                struct in_addr ia;
                memcpy(&ia.s_addr, &addr->addr.in6.sin6_addr.s6_addr[12], sizeof(ia.s_addr));
                snprintf(name_buf, sizeof(name_buf), "%s_ip", name_prefix);
                inet_ntop(AF_INET, &ia, buf, sizeof(buf));
            }
            else
            {
                snprintf(name_buf, sizeof(name_buf), "%s_ip6", name_prefix);
                inet_ntop(AF_INET6, &addr->addr.in6.sin6_addr, buf, sizeof(buf));
            }
            setenv_str(es, name_buf, buf);

            if ((flags & SA_IP_PORT) && addr->addr.in6.sin6_port)
            {
                snprintf(name_buf, sizeof(name_buf), "%s_port", name_prefix);
                setenv_int(es, name_buf, ntohs(addr->addr.in6.sin6_port));
            }
            break;
    }
}

void
setenv_in_addr_t(struct env_set *es, const char *name_prefix, in_addr_t addr,
                 const unsigned int flags)
{
    if (addr || !(flags & SA_SET_IF_NONZERO))
    {
        struct openvpn_sockaddr si;
        CLEAR(si);
        si.addr.in4.sin_family = AF_INET;
        si.addr.in4.sin_addr.s_addr = htonl(addr);
        setenv_sockaddr(es, name_prefix, &si, flags);
    }
}

void
setenv_in6_addr(struct env_set *es, const char *name_prefix, const struct in6_addr *addr,
                const unsigned int flags)
{
    if (!IN6_IS_ADDR_UNSPECIFIED(addr) || !(flags & SA_SET_IF_NONZERO))
    {
        struct openvpn_sockaddr si;
        CLEAR(si);
        si.addr.in6.sin6_family = AF_INET6;
        si.addr.in6.sin6_addr = *addr;
        setenv_sockaddr(es, name_prefix, &si, flags);
    }
}

void
setenv_link_socket_actual(struct env_set *es, const char *name_prefix,
                          const struct link_socket_actual *act, const unsigned int flags)
{
    setenv_sockaddr(es, name_prefix, &act->dest, flags);
}

/*
 * Convert protocol names between index and ascii form.
 */

struct proto_names
{
    const char *short_form;
    const char *display_form;
    sa_family_t proto_af;
    uint8_t proto;
};

/* Indexed by PROTO_x */
static const struct proto_names proto_names[] = {
    { "proto-uninitialized", "proto-NONE", AF_UNSPEC, PROTO_NONE },
    /* try IPv4 and IPv6 (client), bind dual-stack (server) */
    { "udp", "UDP", AF_UNSPEC, PROTO_UDP },
    { "tcp-server", "TCP_SERVER", AF_UNSPEC, PROTO_TCP_SERVER },
    { "tcp-client", "TCP_CLIENT", AF_UNSPEC, PROTO_TCP_CLIENT },
    { "tcp", "TCP", AF_UNSPEC, PROTO_TCP },
    /* force IPv4 */
    { "udp4", "UDPv4", AF_INET, PROTO_UDP },
    { "tcp4-server", "TCPv4_SERVER", AF_INET, PROTO_TCP_SERVER },
    { "tcp4-client", "TCPv4_CLIENT", AF_INET, PROTO_TCP_CLIENT },
    { "tcp4", "TCPv4", AF_INET, PROTO_TCP },
    /* force IPv6 */
    { "udp6", "UDPv6", AF_INET6, PROTO_UDP },
    { "tcp6-server", "TCPv6_SERVER", AF_INET6, PROTO_TCP_SERVER },
    { "tcp6-client", "TCPv6_CLIENT", AF_INET6, PROTO_TCP_CLIENT },
    { "tcp6", "TCPv6", AF_INET6, PROTO_TCP },
};

int
ascii2proto(const char *proto_name)
{
    for (size_t i = 0; i < SIZE(proto_names); ++i)
    {
        if (!strcmp(proto_name, proto_names[i].short_form))
        {
            return proto_names[i].proto;
        }
    }
    return -1;
}

sa_family_t
ascii2af(const char *proto_name)
{
    for (size_t i = 0; i < SIZE(proto_names); ++i)
    {
        if (!strcmp(proto_name, proto_names[i].short_form))
        {
            return proto_names[i].proto_af;
        }
    }
    return 0;
}

const char *
proto2ascii(int proto, sa_family_t af, bool display_form)
{
    for (size_t i = 0; i < SIZE(proto_names); ++i)
    {
        if (proto_names[i].proto_af == af && proto_names[i].proto == proto)
        {
            if (display_form)
            {
                return proto_names[i].display_form;
            }
            else
            {
                return proto_names[i].short_form;
            }
        }
    }

    return "[unknown protocol]";
}

const char *
proto2ascii_all(struct gc_arena *gc)
{
    struct buffer out = alloc_buf_gc(256, gc);

    for (size_t i = 0; i < SIZE(proto_names); ++i)
    {
        if (i)
        {
            buf_printf(&out, " ");
        }
        buf_printf(&out, "[%s]", proto_names[i].short_form);
    }
    return BSTR(&out);
}

const char *
addr_family_name(int af)
{
    switch (af)
    {
        case AF_INET:
            return "AF_INET";

        case AF_INET6:
            return "AF_INET6";
    }
    return "AF_UNSPEC";
}

/*
 * Given a local proto, return local proto
 * if !remote, or compatible remote proto
 * if remote.
 *
 * This is used for options compatibility
 * checking.
 *
 * IPv6 and IPv4 protocols are comptabile but OpenVPN
 * has always sent UDPv4, TCPv4 over the wire. Keep these
 * strings for backward compatibility
 */
const char *
proto_remote(int proto, bool remote)
{
    ASSERT(proto >= 0 && proto < PROTO_N);
    if (proto == PROTO_UDP)
    {
        return "UDPv4";
    }

    if ((remote && proto == PROTO_TCP_CLIENT) || (!remote && proto == PROTO_TCP_SERVER))
    {
        return "TCPv4_SERVER";
    }
    if ((remote && proto == PROTO_TCP_SERVER) || (!remote && proto == PROTO_TCP_CLIENT))
    {
        return "TCPv4_CLIENT";
    }

    ASSERT(0);
    return ""; /* Make the compiler happy */
}

/*
 * We do our own inet_aton because the glibc function
 * isn't very good about error checking.
 */
int
openvpn_inet_aton(const char *dotted_quad, struct in_addr *addr)
{
    unsigned int a, b, c, d;

    CLEAR(*addr);
    if (sscanf(dotted_quad, "%u.%u.%u.%u", &a, &b, &c, &d) == 4)
    {
        if (a < 256 && b < 256 && c < 256 && d < 256)
        {
            addr->s_addr = htonl(a << 24 | b << 16 | c << 8 | d);
            return OIA_IP; /* good dotted quad */
        }
    }
    if (string_class(dotted_quad, CC_DIGIT | CC_DOT, 0))
    {
        return OIA_ERROR; /* probably a badly formatted dotted quad */
    }
    else
    {
        return OIA_HOSTNAME; /* probably a hostname */
    }
}

bool
ip_addr_dotted_quad_safe(const char *dotted_quad)
{
    /* verify non-NULL */
    if (!dotted_quad)
    {
        return false;
    }

    /* verify length is within limits */
    if (strlen(dotted_quad) > 15)
    {
        return false;
    }

    /* verify that all chars are either numeric or '.' and that no numeric
     * substring is greater than 3 chars */
    {
        int nnum = 0;
        const char *p = dotted_quad;
        int c;

        while ((c = *p++))
        {
            if (c >= '0' && c <= '9')
            {
                ++nnum;
                if (nnum > 3)
                {
                    return false;
                }
            }
            else if (c == '.')
            {
                nnum = 0;
            }
            else
            {
                return false;
            }
        }
    }

    /* verify that string will convert to IP address */
    {
        struct in_addr a;
        return openvpn_inet_aton(dotted_quad, &a) == OIA_IP;
    }
}

bool
ipv6_addr_safe(const char *ipv6_text_addr)
{
    /* verify non-NULL */
    if (!ipv6_text_addr)
    {
        return false;
    }

    /* verify length is within limits */
    if (strlen(ipv6_text_addr) > INET6_ADDRSTRLEN)
    {
        return false;
    }

    /* verify that string will convert to IPv6 address */
    {
        struct in6_addr a6;
        return inet_pton(AF_INET6, ipv6_text_addr, &a6) == 1;
    }
}

static bool
dns_addr_safe(const char *addr)
{
    if (addr)
    {
        const size_t len = strlen(addr);
        return len > 0 && len <= 255 && string_class(addr, CC_ALNUM | CC_DASH | CC_DOT, 0);
    }
    else
    {
        return false;
    }
}

bool
ip_or_dns_addr_safe(const char *addr, const bool allow_fqdn)
{
    if (ip_addr_dotted_quad_safe(addr))
    {
        return true;
    }
    else if (allow_fqdn)
    {
        return dns_addr_safe(addr);
    }
    else
    {
        return false;
    }
}

bool
mac_addr_safe(const char *mac_addr)
{
    /* verify non-NULL */
    if (!mac_addr)
    {
        return false;
    }

    /* verify length is within limits */
    if (strlen(mac_addr) > 17)
    {
        return false;
    }

    /* verify that all chars are either alphanumeric or ':' and that no
     * alphanumeric substring is greater than 2 chars */
    {
        int nnum = 0;
        const char *p = mac_addr;
        int c;

        while ((c = *p++))
        {
            if ((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F'))
            {
                ++nnum;
                if (nnum > 2)
                {
                    return false;
                }
            }
            else if (c == ':')
            {
                nnum = 0;
            }
            else
            {
                return false;
            }
        }
    }

    /* error-checking is left to script invoked in lladdr.c */
    return true;
}
