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

#ifndef SOCKET_UTIL_H
#define SOCKET_UTIL_H

#include "buffer.h"
#include "env_set.h"
#include "sig.h"

#define PS_SHOW_PORT_IF_DEFINED (1 << 0)
#define PS_SHOW_PORT            (1 << 1)
#define PS_SHOW_PKTINFO         (1 << 2)
#define PS_DONT_SHOW_ADDR       (1 << 3)
#define PS_DONT_SHOW_FAMILY     (1 << 4)

/* OpenVPN sockaddr struct */
struct openvpn_sockaddr
{
    /*int dummy;*/ /* add offset to force a bug if sa not explicitly dereferenced */
    union
    {
        struct sockaddr sa;
        struct sockaddr_in in4;
        struct sockaddr_in6 in6;
    } addr;
};

/* actual address of remote, based on source address of received packets */
struct link_socket_actual
{
    /*int dummy;*/ /* add offset to force a bug if dest not explicitly dereferenced */

    struct openvpn_sockaddr dest;
#if ENABLE_IP_PKTINFO
    union
    {
#if defined(HAVE_IN_PKTINFO) && defined(HAVE_IPI_SPEC_DST)
        struct in_pktinfo in4;
#elif defined(IP_RECVDSTADDR)
        struct in_addr in4;
#endif
        struct in6_pktinfo in6;
    } pi;
#endif
};

const char *print_sockaddr_ex(const struct sockaddr *addr, const char *separator,
                              const unsigned int flags, struct gc_arena *gc);

static inline const char *
print_openvpn_sockaddr(const struct openvpn_sockaddr *addr, struct gc_arena *gc)
{
    return print_sockaddr_ex(&addr->addr.sa, ":", PS_SHOW_PORT, gc);
}

static inline const char *
print_sockaddr(const struct sockaddr *addr, struct gc_arena *gc)
{
    return print_sockaddr_ex(addr, ":", PS_SHOW_PORT, gc);
}


const char *print_link_socket_actual_ex(const struct link_socket_actual *act, const char *separator,
                                        const unsigned int flags, struct gc_arena *gc);

const char *print_link_socket_actual(const struct link_socket_actual *act, struct gc_arena *gc);


#define IA_EMPTY_IF_UNDEF (1 << 0)
#define IA_NET_ORDER      (1 << 1)
const char *print_in_addr_t(in_addr_t addr, unsigned int flags, struct gc_arena *gc);

const char *print_in6_addr(struct in6_addr addr6, unsigned int flags, struct gc_arena *gc);

const char *print_in_port_t(in_port_t port, struct gc_arena *gc);

struct in6_addr add_in6_addr(struct in6_addr base, uint32_t add);

#define SA_IP_PORT        (1 << 0)
#define SA_SET_IF_NONZERO (1 << 1)
void setenv_sockaddr(struct env_set *es, const char *name_prefix,
                     const struct openvpn_sockaddr *addr, const unsigned int flags);

void setenv_in_addr_t(struct env_set *es, const char *name_prefix, in_addr_t addr,
                      const unsigned int flags);

void setenv_in6_addr(struct env_set *es, const char *name_prefix, const struct in6_addr *addr,
                     const unsigned int flags);

void setenv_link_socket_actual(struct env_set *es, const char *name_prefix,
                               const struct link_socket_actual *act, const unsigned int flags);

/*
 * DNS resolution
 */

#define GETADDR_RESOLVE                 (1u << 0)
#define GETADDR_FATAL                   (1u << 1)
#define GETADDR_HOST_ORDER              (1u << 2)
#define GETADDR_MENTION_RESOLVE_RETRY   (1u << 3)
#define GETADDR_FATAL_ON_SIGNAL         (1u << 4)
#define GETADDR_WARN_ON_SIGNAL          (1u << 5)
#define GETADDR_MSG_VIRT_OUT            (1u << 6)
#define GETADDR_TRY_ONCE                (1u << 7)
#define GETADDR_UPDATE_MANAGEMENT_STATE (1u << 8)
#define GETADDR_RANDOMIZE               (1u << 9)
#define GETADDR_PASSIVE                 (1u << 10)
#define GETADDR_DATAGRAM                (1u << 11)

#define GETADDR_CACHE_MASK (GETADDR_DATAGRAM | GETADDR_PASSIVE)

/**
 * Translate an IPv4 addr or hostname from string form to in_addr_t
 *
 * In case of resolve error, it will try again for
 * resolve_retry_seconds seconds.
 */
in_addr_t getaddr(unsigned int flags, const char *hostname, int resolve_retry_seconds,
                  bool *succeeded, struct signal_info *sig_info);

/**
 * Translate an IPv6 addr or hostname from string form to in6_addr
 */
bool get_ipv6_addr(const char *hostname, struct in6_addr *network, unsigned int *netbits,
                   msglvl_t msglevel);

int openvpn_getaddrinfo(unsigned int flags, const char *hostname, const char *servname,
                        int resolve_retry_seconds, struct signal_info *sig_info, int ai_family,
                        struct addrinfo **res);

/* return values of openvpn_inet_aton */
#define OIA_HOSTNAME 0
#define OIA_IP       1
#define OIA_ERROR    -1
int openvpn_inet_aton(const char *dotted_quad, struct in_addr *addr);

/* integrity validation on pulled options */
bool ip_addr_dotted_quad_safe(const char *dotted_quad);

bool ip_or_dns_addr_safe(const char *addr, const bool allow_fqdn);

bool mac_addr_safe(const char *mac_addr);

bool ipv6_addr_safe(const char *ipv6_text_addr);

/*
 * Transport protocol naming and other details.
 */

/*
 * Use enum's instead of #define to allow for easier
 * optional proto support
 */
enum proto_num
{
    PROTO_NONE, /* catch for uninitialized */
    PROTO_UDP,
    PROTO_TCP,
    PROTO_TCP_SERVER,
    PROTO_TCP_CLIENT,
    PROTO_N
};

static inline bool
proto_is_net(int proto)
{
    ASSERT(proto >= 0 && proto < PROTO_N);
    return proto != PROTO_NONE;
}

/**
 * @brief Returns if the protocol being used is UDP
 */
static inline bool
proto_is_udp(int proto)
{
    ASSERT(proto >= 0 && proto < PROTO_N);
    return proto == PROTO_UDP;
}

/**
 * @brief Return if the protocol is datagram (UDP)
 *
 */
static inline bool
proto_is_dgram(int proto)
{
    return proto_is_udp(proto);
}

/**
 * @brief returns if the proto is a TCP variant (tcp-server, tcp-client or tcp)
 */
static inline bool
proto_is_tcp(int proto)
{
    ASSERT(proto >= 0 && proto < PROTO_N);
    return proto == PROTO_TCP_CLIENT || proto == PROTO_TCP_SERVER;
}

int ascii2proto(const char *proto_name);

sa_family_t ascii2af(const char *proto_name);

const char *proto2ascii(int proto, sa_family_t af, bool display_form);

const char *proto2ascii_all(struct gc_arena *gc);

const char *proto_remote(int proto, bool remote);

const char *addr_family_name(int af);

static inline bool
addr_defined(const struct openvpn_sockaddr *addr)
{
    if (!addr)
    {
        return 0;
    }
    switch (addr->addr.sa.sa_family)
    {
        case AF_INET:
            return addr->addr.in4.sin_addr.s_addr != 0;

        case AF_INET6:
            return !IN6_IS_ADDR_UNSPECIFIED(&addr->addr.in6.sin6_addr);

        default:
            return 0;
    }
}

static inline bool
addr_local(const struct sockaddr *addr)
{
    if (!addr)
    {
        return false;
    }
    switch (addr->sa_family)
    {
        case AF_INET:
            return ((const struct sockaddr_in *)addr)->sin_addr.s_addr == htonl(INADDR_LOOPBACK);

        case AF_INET6:
            return IN6_IS_ADDR_LOOPBACK(&((const struct sockaddr_in6 *)addr)->sin6_addr);

        default:
            return false;
    }
}


static inline bool
addr_defined_ipi(const struct link_socket_actual *lsa)
{
#if ENABLE_IP_PKTINFO
    if (!lsa)
    {
        return 0;
    }
    switch (lsa->dest.addr.sa.sa_family)
    {
#if defined(HAVE_IN_PKTINFO) && defined(HAVE_IPI_SPEC_DST)
        case AF_INET:
            return lsa->pi.in4.ipi_spec_dst.s_addr != 0;

#elif defined(IP_RECVDSTADDR)
        case AF_INET:
            return lsa->pi.in4.s_addr != 0;

#endif
        case AF_INET6:
            return !IN6_IS_ADDR_UNSPECIFIED(&lsa->pi.in6.ipi6_addr);

        default:
            return 0;
    }
#else /* if ENABLE_IP_PKTINFO */
    ASSERT(0);
#endif
    return false;
}

/*
 * Overhead added to packets by various protocols.
 */
static inline int
datagram_overhead(sa_family_t af, int proto)
{
    int overhead = 0;
    overhead += (proto == PROTO_UDP) ? 8 : 20;
    overhead += (af == AF_INET) ? 20 : 40;
    return overhead;
}

/*
 * Misc inline functions
 */

static inline bool
link_socket_proto_connection_oriented(int proto)
{
    return !proto_is_dgram(proto);
}

static inline bool
link_socket_actual_defined(const struct link_socket_actual *act)
{
    return act && addr_defined(&act->dest);
}

static inline bool
addr_match(const struct openvpn_sockaddr *a1, const struct openvpn_sockaddr *a2)
{
    switch (a1->addr.sa.sa_family)
    {
        case AF_INET:
            return a1->addr.in4.sin_addr.s_addr == a2->addr.in4.sin_addr.s_addr;

        case AF_INET6:
            return IN6_ARE_ADDR_EQUAL(&a1->addr.in6.sin6_addr, &a2->addr.in6.sin6_addr);
    }
    ASSERT(0);
    return false;
}

static inline bool
addrlist_match(const struct openvpn_sockaddr *a1, const struct addrinfo *addrlist)
{
    const struct addrinfo *curele;
    for (curele = addrlist; curele; curele = curele->ai_next)
    {
        switch (a1->addr.sa.sa_family)
        {
            case AF_INET:
                if (a1->addr.in4.sin_addr.s_addr
                    == ((struct sockaddr_in *)curele->ai_addr)->sin_addr.s_addr)
                {
                    return true;
                }
                break;

            case AF_INET6:
                if (IN6_ARE_ADDR_EQUAL(&a1->addr.in6.sin6_addr,
                                       &((struct sockaddr_in6 *)curele->ai_addr)->sin6_addr))
                {
                    return true;
                }
                break;

            default:
                ASSERT(0);
        }
    }
    return false;
}

static inline bool
addrlist_port_match(const struct openvpn_sockaddr *a1, const struct addrinfo *a2)
{
    const struct addrinfo *curele;
    for (curele = a2; curele; curele = curele->ai_next)
    {
        switch (a1->addr.sa.sa_family)
        {
            case AF_INET:
                if (curele->ai_family == AF_INET
                    && a1->addr.in4.sin_addr.s_addr
                           == ((struct sockaddr_in *)curele->ai_addr)->sin_addr.s_addr
                    && a1->addr.in4.sin_port == ((struct sockaddr_in *)curele->ai_addr)->sin_port)
                {
                    return true;
                }
                break;

            case AF_INET6:
                if (curele->ai_family == AF_INET6
                    && IN6_ARE_ADDR_EQUAL(&a1->addr.in6.sin6_addr,
                                          &((struct sockaddr_in6 *)curele->ai_addr)->sin6_addr)
                    && a1->addr.in6.sin6_port
                           == ((struct sockaddr_in6 *)curele->ai_addr)->sin6_port)
                {
                    return true;
                }
                break;

            default:
                ASSERT(0);
        }
    }
    return false;
}


static inline bool
addr_port_match(const struct openvpn_sockaddr *a1, const struct openvpn_sockaddr *a2)
{
    switch (a1->addr.sa.sa_family)
    {
        case AF_INET:
            return a1->addr.in4.sin_addr.s_addr == a2->addr.in4.sin_addr.s_addr
                   && a1->addr.in4.sin_port == a2->addr.in4.sin_port;

        case AF_INET6:
            return IN6_ARE_ADDR_EQUAL(&a1->addr.in6.sin6_addr, &a2->addr.in6.sin6_addr)
                   && a1->addr.in6.sin6_port == a2->addr.in6.sin6_port;
    }
    ASSERT(0);
    return false;
}

static inline bool
addr_match_proto(const struct openvpn_sockaddr *a1, const struct openvpn_sockaddr *a2,
                 const int proto)
{
    return link_socket_proto_connection_oriented(proto) ? addr_match(a1, a2)
                                                        : addr_port_match(a1, a2);
}


static inline bool
addrlist_match_proto(const struct openvpn_sockaddr *a1, struct addrinfo *addr_list, const int proto)
{
    return link_socket_proto_connection_oriented(proto) ? addrlist_match(a1, addr_list)
                                                        : addrlist_port_match(a1, addr_list);
}

static inline void
addr_zero_host(struct openvpn_sockaddr *addr)
{
    switch (addr->addr.sa.sa_family)
    {
        case AF_INET:
            addr->addr.in4.sin_addr.s_addr = 0;
            break;

        case AF_INET6:
            memset(&addr->addr.in6.sin6_addr, 0, sizeof(struct in6_addr));
            break;
    }
}

static inline int
af_addr_size(sa_family_t af)
{
    switch (af)
    {
        case AF_INET:
            return sizeof(struct sockaddr_in);

        case AF_INET6:
            return sizeof(struct sockaddr_in6);

        default:
#if 0
            /* could be called from socket_do_accept() with empty addr */
            msg(M_ERR, "Bad address family: %d", af);
            ASSERT(0);
#endif
            return 0;
    }
}

static inline bool
link_socket_actual_match(const struct link_socket_actual *a1, const struct link_socket_actual *a2)
{
    return addr_port_match(&a1->dest, &a2->dest);
}

#endif
