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
    int proto;
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

/**
 * Small helper function for openvpn_getaddrinfo to print the address
 * family when resolving fails
 */
static const char *
getaddrinfo_addr_family_name(int af)
{
    switch (af)
    {
        case AF_INET:
            return "[AF_INET]";

        case AF_INET6:
            return "[AF_INET6]";
    }
    return "";
}

/*
 * Prepend a random string to hostname to prevent DNS caching.
 * For example, foo.bar.gov would be modified to <random-chars>.foo.bar.gov.
 * Of course, this requires explicit support in the DNS server (wildcard).
 */
static const char *
hostname_randomize(const char *hostname, struct gc_arena *gc)
{
#define n_rnd_bytes 6

    uint8_t rnd_bytes[n_rnd_bytes];
    const char *rnd_str;
    struct buffer hname = alloc_buf_gc(strlen(hostname) + sizeof(rnd_bytes) * 2 + 4, gc);

    prng_bytes(rnd_bytes, sizeof(rnd_bytes));
    rnd_str = format_hex_ex(rnd_bytes, sizeof(rnd_bytes), 40, 0, NULL, gc);
    buf_printf(&hname, "%s.%s", rnd_str, hostname);
    return BSTR(&hname);
#undef n_rnd_bytes
}

/*
 * Translate IPv4/IPv6 addr or hostname into struct addrinfo
 * If resolve error, try again for resolve_retry_seconds seconds.
 */
int
openvpn_getaddrinfo(unsigned int flags, const char *hostname, const char *servname,
                    int resolve_retry_seconds, struct signal_info *sig_info, int ai_family,
                    struct addrinfo **res)
{
    struct addrinfo hints;
    int status;
    struct signal_info sigrec = { 0 };
    msglvl_t msglevel = (flags & GETADDR_FATAL) ? M_FATAL : D_RESOLVE_ERRORS;
    struct gc_arena gc = gc_new();
    const char *print_hostname;
    const char *print_servname;

    ASSERT(res);

    ASSERT(hostname || servname);
    ASSERT(!(flags & GETADDR_HOST_ORDER));

    if (servname)
    {
        print_servname = servname;
    }
    else
    {
        print_servname = "";
    }

    if (flags & GETADDR_MSG_VIRT_OUT)
    {
        msglevel |= M_MSG_VIRT_OUT;
    }

    if ((flags & (GETADDR_FATAL_ON_SIGNAL | GETADDR_WARN_ON_SIGNAL)) && !sig_info)
    {
        sig_info = &sigrec;
    }

    /* try numeric ip addr first */
    CLEAR(hints);
    hints.ai_flags = AI_NUMERICHOST;

    if (flags & GETADDR_PASSIVE)
    {
        hints.ai_flags |= AI_PASSIVE;
    }

    if (flags & GETADDR_DATAGRAM)
    {
        hints.ai_socktype = SOCK_DGRAM;
    }
    else
    {
        hints.ai_socktype = SOCK_STREAM;
    }

    /* if hostname is not set, we want to bind to 'ANY', with
     * the correct address family - v4-only or v6/v6-dual-stack */
    if (!hostname)
    {
        hints.ai_family = ai_family;
    }

    status = getaddrinfo(hostname, servname, &hints, res);

    if (status != 0)                      /* parse as numeric address failed? */
    {
        const int fail_wait_interval = 5; /* seconds */
        /* Add +4 to cause integer division rounding up (1 + 4) = 5, (0+4)/5=0 */
        int resolve_retries =
            (flags & GETADDR_TRY_ONCE) ? 1 : ((resolve_retry_seconds + 4) / fail_wait_interval);
        const char *fmt;
        msglvl_t level = 0;

        /* this is not a numeric IP, therefore force resolution using the
         * provided ai_family */
        hints.ai_family = ai_family;

        if (hostname && (flags & GETADDR_RANDOMIZE))
        {
            hostname = hostname_randomize(hostname, &gc);
        }

        if (hostname)
        {
            print_hostname = hostname;
        }
        else
        {
            print_hostname = "undefined";
        }

        fmt = "RESOLVE: Cannot resolve host address: %s:%s%s (%s)";
        if ((flags & GETADDR_MENTION_RESOLVE_RETRY) && !resolve_retry_seconds)
        {
            fmt = "RESOLVE: Cannot resolve host address: %s:%s%s (%s)"
                  "(I would have retried this name query if you had "
                  "specified the --resolv-retry option.)";
        }

        if (!(flags & GETADDR_RESOLVE) || status == EAI_FAIL)
        {
            msg(msglevel, "RESOLVE: Cannot parse IP address: %s:%s (%s)", print_hostname,
                print_servname, gai_strerror(status));
            goto done;
        }

#ifdef ENABLE_MANAGEMENT
        if (flags & GETADDR_UPDATE_MANAGEMENT_STATE)
        {
            if (management)
            {
                management_set_state(management, OPENVPN_STATE_RESOLVE, NULL, NULL, NULL, NULL,
                                     NULL);
            }
        }
#endif

        /*
         * Resolve hostname
         */
        while (true)
        {
#ifndef _WIN32
            /* force resolv.conf reload */
            res_init();
#endif
            /* try hostname lookup */
            hints.ai_flags &= ~AI_NUMERICHOST;
            dmsg(D_SOCKET_DEBUG, "GETADDRINFO flags=0x%04x ai_family=%d ai_socktype=%d", flags,
                 hints.ai_family, hints.ai_socktype);
            status = getaddrinfo(hostname, servname, &hints, res);

            if (sig_info)
            {
                get_signal(&sig_info->signal_received);
                if (sig_info->signal_received) /* were we interrupted by a signal? */
                {
                    /* why are we overwriting SIGUSR1 ? */
                    if (signal_reset(sig_info, SIGUSR1) == SIGUSR1) /* ignore SIGUSR1 */
                    {
                        msg(level, "RESOLVE: Ignored SIGUSR1 signal received during "
                                   "DNS resolution attempt");
                    }
                    else
                    {
                        /* turn success into failure (interrupted syscall) */
                        if (0 == status)
                        {
                            ASSERT(res);
                            freeaddrinfo(*res);
                            *res = NULL;
                            status = EAI_AGAIN; /* = temporary failure */
                            errno = EINTR;
                        }
                        goto done;
                    }
                }
            }

            /* success? */
            if (0 == status)
            {
                break;
            }

            /* resolve lookup failed, should we
             * continue or fail? */
            level = msglevel;
            if (resolve_retries > 0)
            {
                level = D_RESOLVE_ERRORS;
            }

            msg(level, fmt, print_hostname, print_servname, getaddrinfo_addr_family_name(ai_family),
                gai_strerror(status));

            if (--resolve_retries <= 0)
            {
                goto done;
            }

            management_sleep(fail_wait_interval);
        }

        ASSERT(res);

        /* hostname resolve succeeded */

        /*
         * Do not choose an IP Addresse by random or change the order *
         * of IP addresses, doing so will break RFC 3484 address selection *
         */
    }
    else
    {
        /* IP address parse succeeded */
        if (flags & GETADDR_RANDOMIZE)
        {
            msg(M_WARN, "WARNING: ignoring --remote-random-hostname because the "
                        "hostname is an IP address");
        }
    }

done:
    if (sig_info && sig_info->signal_received)
    {
        msglvl_t level = 0;
        if (flags & GETADDR_FATAL_ON_SIGNAL)
        {
            level = M_FATAL;
        }
        else if (flags & GETADDR_WARN_ON_SIGNAL)
        {
            level = M_WARN;
        }
        msg(level, "RESOLVE: signal received during DNS resolution attempt");
    }

    gc_free(&gc);
    return status;
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
