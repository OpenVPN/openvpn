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

#include "socket.h"
#include "fdmisc.h"
#include "misc.h"
#include "gremlin.h"
#include "plugin.h"
#include "ps.h"
#include "run_command.h"
#include "manage.h"
#include "misc.h"
#include "manage.h"
#include "openvpn.h"
#include "forward.h"

#include "memdbg.h"

/*
 * Convert sockflags/getaddr_flags into getaddr_flags
 */
static unsigned int
sf2gaf(const unsigned int getaddr_flags,
       const unsigned int sockflags)
{
    if (sockflags & SF_HOST_RANDOMIZE)
    {
        return getaddr_flags | GETADDR_RANDOMIZE;
    }
    else
    {
        return getaddr_flags;
    }
}

/*
 * Functions related to the translation of DNS names to IP addresses.
 */
static int
get_addr_generic(sa_family_t af, unsigned int flags, const char *hostname,
                 void *network, unsigned int *netbits,
                 int resolve_retry_seconds, struct signal_info *sig_info,
                 int msglevel)
{
    char *endp, *sep, *var_host = NULL;
    struct addrinfo *ai = NULL;
    unsigned long bits;
    uint8_t max_bits;
    int ret = -1;

    if (!hostname)
    {
        msg(M_NONFATAL, "Can't resolve null hostname!");
        goto out;
    }

    /* assign family specific default values */
    switch (af)
    {
        case AF_INET:
            bits = 0;
            max_bits = sizeof(in_addr_t) * 8;
            break;

        case AF_INET6:
            bits = 64;
            max_bits = sizeof(struct in6_addr) * 8;
            break;

        default:
            msg(M_WARN,
                "Unsupported AF family passed to getaddrinfo for %s (%d)",
                hostname, af);
            goto out;
    }

    /* we need to modify the hostname received as input, but we don't want to
     * touch it directly as it might be a constant string.
     *
     * Therefore, we clone the string here and free it at the end of the
     * function */
    var_host = strdup(hostname);
    if (!var_host)
    {
        msg(M_NONFATAL | M_ERRNO,
            "Can't allocate hostname buffer for getaddrinfo");
        goto out;
    }

    /* check if this hostname has a /bits suffix */
    sep = strchr(var_host, '/');
    if (sep)
    {
        bits = strtoul(sep + 1, &endp, 10);
        if ((*endp != '\0') || (bits > max_bits))
        {
            msg(msglevel, "IP prefix '%s': invalid '/bits' spec (%s)", hostname,
                sep + 1);
            goto out;
        }
        *sep = '\0';
    }

    ret = openvpn_getaddrinfo(flags & ~GETADDR_HOST_ORDER, var_host, NULL,
                              resolve_retry_seconds, sig_info, af, &ai);
    if ((ret == 0) && network)
    {
        struct in6_addr *ip6;
        in_addr_t *ip4;

        switch (af)
        {
            case AF_INET:
                ip4 = network;
                *ip4 = ((struct sockaddr_in *)ai->ai_addr)->sin_addr.s_addr;

                if (flags & GETADDR_HOST_ORDER)
                {
                    *ip4 = ntohl(*ip4);
                }
                break;

            case AF_INET6:
                ip6 = network;
                *ip6 = ((struct sockaddr_in6 *)ai->ai_addr)->sin6_addr;
                break;

            default:
                /* can't get here because 'af' was previously checked */
                msg(M_WARN,
                    "Unsupported AF family for %s (%d)", var_host, af);
                goto out;
        }
    }

    if (netbits)
    {
        *netbits = bits;
    }

    /* restore '/' separator, if any */
    if (sep)
    {
        *sep = '/';
    }
out:
    freeaddrinfo(ai);
    free(var_host);

    return ret;
}

in_addr_t
getaddr(unsigned int flags,
        const char *hostname,
        int resolve_retry_seconds,
        bool *succeeded,
        struct signal_info *sig_info)
{
    in_addr_t addr;
    int status;

    status = get_addr_generic(AF_INET, flags, hostname, &addr, NULL,
                              resolve_retry_seconds, sig_info,
                              M_WARN);
    if (status==0)
    {
        if (succeeded)
        {
            *succeeded = true;
        }
        return addr;
    }
    else
    {
        if (succeeded)
        {
            *succeeded = false;
        }
        return 0;
    }
}

bool
get_ipv6_addr(const char *hostname, struct in6_addr *network,
              unsigned int *netbits, int msglevel)
{
    if (get_addr_generic(AF_INET6, GETADDR_RESOLVE, hostname, network, netbits,
                         0, NULL, msglevel) < 0)
    {
        return false;
    }

    return true;                /* parsing OK, values set */
}

static inline bool
streqnull(const char *a, const char *b)
{
    if (a == NULL && b == NULL)
    {
        return true;
    }
    else if (a == NULL || b == NULL)
    {
        return false;
    }
    else
    {
        return streq(a, b);
    }
}

/*
 * get_cached_dns_entry return 0 on success and -1
 * otherwise. (like getaddrinfo)
 */
static int
get_cached_dns_entry(struct cached_dns_entry *dns_cache,
                     const char *hostname,
                     const char *servname,
                     int ai_family,
                     int resolve_flags,
                     struct addrinfo **ai)
{
    struct cached_dns_entry *ph;
    int flags;

    /* Only use flags that are relevant for the structure */
    flags = resolve_flags & GETADDR_CACHE_MASK;

    for (ph = dns_cache; ph; ph = ph->next)
    {
        if (streqnull(ph->hostname, hostname)
            && streqnull(ph->servname, servname)
            && ph->ai_family == ai_family
            && ph->flags == flags)
        {
            *ai = ph->ai;
            return 0;
        }
    }
    return -1;
}


static int
do_preresolve_host(struct context *c,
                   const char *hostname,
                   const char *servname,
                   const int af,
                   const int flags)
{
    struct addrinfo *ai;
    int status;

    if (get_cached_dns_entry(c->c1.dns_cache,
                             hostname,
                             servname,
                             af,
                             flags,
                             &ai) == 0)
    {
        /* entry already cached, return success */
        return 0;
    }

    status = openvpn_getaddrinfo(flags, hostname, servname,
                                 c->options.resolve_retry_seconds, NULL,
                                 af, &ai);
    if (status == 0)
    {
        struct cached_dns_entry *ph;

        ALLOC_OBJ_CLEAR_GC(ph, struct cached_dns_entry, &c->gc);
        ph->ai = ai;
        ph->hostname = hostname;
        ph->servname = servname;
        ph->flags = flags & GETADDR_CACHE_MASK;

        if (!c->c1.dns_cache)
        {
            c->c1.dns_cache = ph;
        }
        else
        {
            struct cached_dns_entry *prev = c->c1.dns_cache;
            while (prev->next)
            {
                prev = prev->next;
            }
            prev->next = ph;
        }

        gc_addspecial(ai, &gc_freeaddrinfo_callback, &c->gc);

    }
    return status;
}

void
do_preresolve(struct context *c)
{
    int i;
    struct connection_list *l = c->options.connection_list;
    const unsigned int preresolve_flags = GETADDR_RESOLVE
                                          |GETADDR_UPDATE_MANAGEMENT_STATE
                                          |GETADDR_MENTION_RESOLVE_RETRY
                                          |GETADDR_FATAL;


    for (i = 0; i < l->len; ++i)
    {
        int status;
        const char *remote;
        int flags = preresolve_flags;

        struct connection_entry *ce = c->options.connection_list->array[i];

        if (proto_is_dgram(ce->proto))
        {
            flags |= GETADDR_DATAGRAM;
        }

        if (c->options.sockflags & SF_HOST_RANDOMIZE)
        {
            flags |= GETADDR_RANDOMIZE;
        }

        if (c->options.ip_remote_hint)
        {
            remote = c->options.ip_remote_hint;
        }
        else
        {
            remote = ce->remote;
        }

        /* HTTP remote hostname does not need to be resolved */
        if (!ce->http_proxy_options)
        {
            status = do_preresolve_host(c, remote, ce->remote_port,
                                        ce->af, flags);
            if (status != 0)
            {
                goto err;
            }
        }

        /* Preresolve proxy */
        if (ce->http_proxy_options)
        {
            status = do_preresolve_host(c,
                                        ce->http_proxy_options->server,
                                        ce->http_proxy_options->port,
                                        ce->af,
                                        preresolve_flags);

            if (status != 0)
            {
                goto err;
            }
        }

        if (ce->socks_proxy_server)
        {
            status = do_preresolve_host(c,
                                        ce->socks_proxy_server,
                                        ce->socks_proxy_port,
                                        ce->af,
                                        flags);
            if (status != 0)
            {
                goto err;
            }
        }

        if (ce->bind_local)
        {
            flags |= GETADDR_PASSIVE;
            flags &= ~GETADDR_RANDOMIZE;
            status = do_preresolve_host(c, ce->local, ce->local_port,
                                        ce->af, flags);
            if (status != 0)
            {
                goto err;
            }

        }

    }
    return;

err:
    throw_signal_soft(SIGHUP, "Preresolving failed");
}

/*
 * Translate IPv4/IPv6 addr or hostname into struct addrinfo
 * If resolve error, try again for resolve_retry_seconds seconds.
 */
int
openvpn_getaddrinfo(unsigned int flags,
                    const char *hostname,
                    const char *servname,
                    int resolve_retry_seconds,
                    struct signal_info *sig_info,
                    int ai_family,
                    struct addrinfo **res)
{
    struct addrinfo hints;
    int status;
    struct signal_info sigrec = {0};
    int msglevel = (flags & GETADDR_FATAL) ? M_FATAL : D_RESOLVE_ERRORS;
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

    if ((flags & (GETADDR_FATAL_ON_SIGNAL|GETADDR_WARN_ON_SIGNAL))
        && !sig_info)
    {
        sig_info = &sigrec;
    }

    /* try numeric ipv6 addr first */
    CLEAR(hints);
    hints.ai_family = ai_family;
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

    status = getaddrinfo(hostname, servname, &hints, res);

    if (status != 0) /* parse as numeric address failed? */
    {
        const int fail_wait_interval = 5; /* seconds */
        /* Add +4 to cause integer division rounding up (1 + 4) = 5, (0+4)/5=0 */
        int resolve_retries = (flags & GETADDR_TRY_ONCE) ? 1 :
                              ((resolve_retry_seconds + 4)/ fail_wait_interval);
        const char *fmt;
        int level = 0;

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

        fmt = "RESOLVE: Cannot resolve host address: %s:%s (%s)";
        if ((flags & GETADDR_MENTION_RESOLVE_RETRY)
            && !resolve_retry_seconds)
        {
            fmt = "RESOLVE: Cannot resolve host address: %s:%s (%s) "
                  "(I would have retried this name query if you had "
                  "specified the --resolv-retry option.)";
        }

        if (!(flags & GETADDR_RESOLVE) || status == EAI_FAIL)
        {
            msg(msglevel, "RESOLVE: Cannot parse IP address: %s:%s (%s)",
                print_hostname, print_servname, gai_strerror(status));
            goto done;
        }

#ifdef ENABLE_MANAGEMENT
        if (flags & GETADDR_UPDATE_MANAGEMENT_STATE)
        {
            if (management)
            {
                management_set_state(management,
                                     OPENVPN_STATE_RESOLVE,
                                     NULL,
                                     NULL,
                                     NULL,
                                     NULL,
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
            dmsg(D_SOCKET_DEBUG,
                 "GETADDRINFO flags=0x%04x ai_family=%d ai_socktype=%d",
                 flags, hints.ai_family, hints.ai_socktype);
            status = getaddrinfo(hostname, servname, &hints, res);

            if (sig_info)
            {
                get_signal(&sig_info->signal_received);
                if (sig_info->signal_received) /* were we interrupted by a signal? */
                {
                    /* why are we overwriting SIGUSR1 ? */
                    if (sig_info->signal_received == SIGUSR1) /* ignore SIGUSR1 */
                    {
                        msg(level,
                            "RESOLVE: Ignored SIGUSR1 signal received during "
                            "DNS resolution attempt");
                        signal_reset(sig_info);
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

            msg(level,
                fmt,
                print_hostname,
                print_servname,
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
            msg(M_WARN,
                "WARNING: ignoring --remote-random-hostname because the "
                "hostname is an IP address");
        }
    }

done:
    if (sig_info && sig_info->signal_received)
    {
        int level = 0;
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
            addr->s_addr = htonl(a<<24 | b<<16 | c<<8 | d);
            return OIA_IP; /* good dotted quad */
        }
    }
    if (string_class(dotted_quad, CC_DIGIT|CC_DOT, 0))
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
        return inet_pton( AF_INET6, ipv6_text_addr, &a6 ) == 1;
    }
}

static bool
dns_addr_safe(const char *addr)
{
    if (addr)
    {
        const size_t len = strlen(addr);
        return len > 0 && len <= 255 && string_class(addr, CC_ALNUM|CC_DASH|CC_DOT, 0);
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
            if ( (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F') )
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

static int
socket_get_sndbuf(socket_descriptor_t sd)
{
#if defined(SOL_SOCKET) && defined(SO_SNDBUF)
    int val;
    socklen_t len;

    len = sizeof(val);
    if (getsockopt(sd, SOL_SOCKET, SO_SNDBUF, (void *) &val, &len) == 0
        && len == sizeof(val))
    {
        return val;
    }
#endif
    return 0;
}

static void
socket_set_sndbuf(socket_descriptor_t sd, int size)
{
#if defined(SOL_SOCKET) && defined(SO_SNDBUF)
    if (setsockopt(sd, SOL_SOCKET, SO_SNDBUF, (void *) &size, sizeof(size)) != 0)
    {
        msg(M_WARN, "NOTE: setsockopt SO_SNDBUF=%d failed", size);
    }
#endif
}

static int
socket_get_rcvbuf(socket_descriptor_t sd)
{
#if defined(SOL_SOCKET) && defined(SO_RCVBUF)
    int val;
    socklen_t len;

    len = sizeof(val);
    if (getsockopt(sd, SOL_SOCKET, SO_RCVBUF, (void *) &val, &len) == 0
        && len == sizeof(val))
    {
        return val;
    }
#endif
    return 0;
}

static bool
socket_set_rcvbuf(socket_descriptor_t sd, int size)
{
#if defined(SOL_SOCKET) && defined(SO_RCVBUF)
    if (setsockopt(sd, SOL_SOCKET, SO_RCVBUF, (void *) &size, sizeof(size)) != 0)
    {
        msg(M_WARN, "NOTE: setsockopt SO_RCVBUF=%d failed", size);
        return false;
    }
    return true;
#endif
}

static void
socket_set_buffers(socket_descriptor_t fd, const struct socket_buffer_size *sbs)
{
    if (sbs)
    {
        const int sndbuf_old = socket_get_sndbuf(fd);
        const int rcvbuf_old = socket_get_rcvbuf(fd);

        if (sbs->sndbuf)
        {
            socket_set_sndbuf(fd, sbs->sndbuf);
        }

        if (sbs->rcvbuf)
        {
            socket_set_rcvbuf(fd, sbs->rcvbuf);
        }

        msg(D_OSBUF, "Socket Buffers: R=[%d->%d] S=[%d->%d]",
            rcvbuf_old,
            socket_get_rcvbuf(fd),
            sndbuf_old,
            socket_get_sndbuf(fd));
    }
}

/*
 * Set other socket options
 */

static bool
socket_set_tcp_nodelay(socket_descriptor_t sd, int state)
{
#if defined(_WIN32) || (defined(IPPROTO_TCP) && defined(TCP_NODELAY))
    if (setsockopt(sd, IPPROTO_TCP, TCP_NODELAY, (void *) &state, sizeof(state)) != 0)
    {
        msg(M_WARN, "NOTE: setsockopt TCP_NODELAY=%d failed", state);
        return false;
    }
    else
    {
        dmsg(D_OSBUF, "Socket flags: TCP_NODELAY=%d succeeded", state);
        return true;
    }
#else  /* if defined(_WIN32) || (defined(IPPROTO_TCP) && defined(TCP_NODELAY)) */
    msg(M_WARN, "NOTE: setsockopt TCP_NODELAY=%d failed (No kernel support)", state);
    return false;
#endif
}

static inline void
socket_set_mark(socket_descriptor_t sd, int mark)
{
#if defined(TARGET_LINUX) && HAVE_DECL_SO_MARK
    if (mark && setsockopt(sd, SOL_SOCKET, SO_MARK, (void *) &mark, sizeof(mark)) != 0)
    {
        msg(M_WARN, "NOTE: setsockopt SO_MARK=%d failed", mark);
    }
#endif
}

static bool
socket_set_flags(socket_descriptor_t sd, unsigned int sockflags)
{
    /* SF_TCP_NODELAY doesn't make sense for dco-win */
    if ((sockflags & SF_TCP_NODELAY) && (!(sockflags & SF_DCO_WIN)))
    {
        return socket_set_tcp_nodelay(sd, 1);
    }
    else
    {
        return true;
    }
}

bool
link_socket_update_flags(struct link_socket *ls, unsigned int sockflags)
{
    if (ls && socket_defined(ls->sd))
    {
        ls->sockflags |= sockflags;
        return socket_set_flags(ls->sd, ls->sockflags);
    }
    else
    {
        return false;
    }
}

void
link_socket_update_buffer_sizes(struct link_socket *ls, int rcvbuf, int sndbuf)
{
    if (ls && socket_defined(ls->sd))
    {
        ls->socket_buffer_sizes.sndbuf = sndbuf;
        ls->socket_buffer_sizes.rcvbuf = rcvbuf;
        socket_set_buffers(ls->sd, &ls->socket_buffer_sizes);
    }
}

/*
 * SOCKET INITIALIZATION CODE.
 * Create a TCP/UDP socket
 */

socket_descriptor_t
create_socket_tcp(struct addrinfo *addrinfo)
{
    socket_descriptor_t sd;

    ASSERT(addrinfo);
    ASSERT(addrinfo->ai_socktype == SOCK_STREAM);

    if ((sd = socket(addrinfo->ai_family, addrinfo->ai_socktype, addrinfo->ai_protocol)) < 0)
    {
        msg(M_ERR, "Cannot create TCP socket");
    }

#ifndef _WIN32 /* using SO_REUSEADDR on Windows will cause bind to succeed on port conflicts! */
    /* set SO_REUSEADDR on socket */
    {
        int on = 1;
        if (setsockopt(sd, SOL_SOCKET, SO_REUSEADDR,
                       (void *) &on, sizeof(on)) < 0)
        {
            msg(M_ERR, "TCP: Cannot setsockopt SO_REUSEADDR on TCP socket");
        }
    }
#endif

    /* set socket file descriptor to not pass across execs, so that
     * scripts don't have access to it */
    set_cloexec(sd);

    return sd;
}

static socket_descriptor_t
create_socket_udp(struct addrinfo *addrinfo, const unsigned int flags)
{
    socket_descriptor_t sd;

    ASSERT(addrinfo);
    ASSERT(addrinfo->ai_socktype == SOCK_DGRAM);

    if ((sd = socket(addrinfo->ai_family, addrinfo->ai_socktype, addrinfo->ai_protocol)) < 0)
    {
        msg(M_ERR, "UDP: Cannot create UDP/UDP6 socket");
    }
#if ENABLE_IP_PKTINFO
    else if (flags & SF_USE_IP_PKTINFO)
    {
        int pad = 1;
        if (addrinfo->ai_family == AF_INET)
        {
#if defined(HAVE_IN_PKTINFO) && defined(HAVE_IPI_SPEC_DST)
            if (setsockopt(sd, SOL_IP, IP_PKTINFO,
                           (void *)&pad, sizeof(pad)) < 0)
            {
                msg(M_ERR, "UDP: failed setsockopt for IP_PKTINFO");
            }
#elif defined(IP_RECVDSTADDR)
            if (setsockopt(sd, IPPROTO_IP, IP_RECVDSTADDR,
                           (void *)&pad, sizeof(pad)) < 0)
            {
                msg(M_ERR, "UDP: failed setsockopt for IP_RECVDSTADDR");
            }
#else  /* if defined(HAVE_IN_PKTINFO) && defined(HAVE_IPI_SPEC_DST) */
#error ENABLE_IP_PKTINFO is set without IP_PKTINFO xor IP_RECVDSTADDR (fix syshead.h)
#endif
        }
        else if (addrinfo->ai_family == AF_INET6)
        {
#ifndef IPV6_RECVPKTINFO /* Some older Darwin platforms require this */
            if (setsockopt(sd, IPPROTO_IPV6, IPV6_PKTINFO,
                           (void *)&pad, sizeof(pad)) < 0)
#else
            if (setsockopt(sd, IPPROTO_IPV6, IPV6_RECVPKTINFO,
                           (void *)&pad, sizeof(pad)) < 0)
#endif
            { msg(M_ERR, "UDP: failed setsockopt for IPV6_RECVPKTINFO");}
        }
    }
#endif /* if ENABLE_IP_PKTINFO */

    /* set socket file descriptor to not pass across execs, so that
     * scripts don't have access to it */
    set_cloexec(sd);

    return sd;
}

static void
bind_local(struct link_socket *sock, const sa_family_t ai_family)
{
    /* bind to local address/port */
    if (sock->bind_local)
    {
        if (sock->socks_proxy && sock->info.proto == PROTO_UDP)
        {
            socket_bind(sock->ctrl_sd, sock->info.lsa->bind_local,
                        ai_family, "SOCKS", false);
        }
        else
        {
            socket_bind(sock->sd, sock->info.lsa->bind_local,
                        ai_family,
                        "TCP/UDP", sock->info.bind_ipv6_only);
        }
    }
}

static void
create_socket(struct link_socket *sock, struct addrinfo *addr)
{
    if (addr->ai_protocol == IPPROTO_UDP || addr->ai_socktype == SOCK_DGRAM)
    {
        sock->sd = create_socket_udp(addr, sock->sockflags);
        sock->sockflags |= SF_GETADDRINFO_DGRAM;

        /* Assume that control socket and data socket to the socks proxy
         * are using the same IP family */
        if (sock->socks_proxy)
        {
            /* Construct a temporary addrinfo to create the socket,
             * currently resolve two remote addresses is not supported,
             * TODO: Rewrite the whole resolve_remote */
            struct addrinfo addrinfo_tmp = *addr;
            addrinfo_tmp.ai_socktype = SOCK_STREAM;
            addrinfo_tmp.ai_protocol = IPPROTO_TCP;
            sock->ctrl_sd = create_socket_tcp(&addrinfo_tmp);
        }
    }
    else if (addr->ai_protocol == IPPROTO_TCP || addr->ai_socktype == SOCK_STREAM)
    {
        sock->sd = create_socket_tcp(addr);
    }
    else
    {
        ASSERT(0);
    }
    /* Set af field of sock->info, so it always reflects the address family
     * of the created socket */
    sock->info.af = addr->ai_family;

    /* set socket buffers based on --sndbuf and --rcvbuf options */
    socket_set_buffers(sock->sd, &sock->socket_buffer_sizes);

    /* set socket to --mark packets with given value */
    socket_set_mark(sock->sd, sock->mark);

#if defined(TARGET_LINUX)
    if (sock->bind_dev)
    {
        msg(M_INFO, "Using bind-dev %s", sock->bind_dev);
        if (setsockopt(sock->sd, SOL_SOCKET, SO_BINDTODEVICE, sock->bind_dev, strlen(sock->bind_dev) + 1) != 0)
        {
            msg(M_WARN|M_ERRNO, "WARN: setsockopt SO_BINDTODEVICE=%s failed", sock->bind_dev);
        }

    }
#endif

    bind_local(sock, addr->ai_family);
}

#ifdef TARGET_ANDROID
static void
protect_fd_nonlocal(int fd, const struct sockaddr *addr)
{
    if (!management)
    {
        msg(M_FATAL, "Required management interface not available.");
    }

    /* pass socket FD to management interface to pass on to VPNService API
     * as "protected socket" (exempt from being routed into tunnel)
     */
    if (addr_local(addr))
    {
        msg(D_SOCKET_DEBUG, "Address is local, not protecting socket fd %d", fd);
        return;
    }

    msg(D_SOCKET_DEBUG, "Protecting socket fd %d", fd);
    management->connection.fdtosend = fd;
    management_android_control(management, "PROTECTFD", __func__);
}
#endif

/*
 * Functions used for establishing a TCP stream connection.
 */
static void
socket_do_listen(socket_descriptor_t sd,
                 const struct addrinfo *local,
                 bool do_listen,
                 bool do_set_nonblock)
{
    struct gc_arena gc = gc_new();
    if (do_listen)
    {
        ASSERT(local);
        msg(M_INFO, "Listening for incoming TCP connection on %s",
            print_sockaddr(local->ai_addr, &gc));
        if (listen(sd, 32))
        {
            msg(M_ERR, "TCP: listen() failed");
        }
    }

    /* set socket to non-blocking mode */
    if (do_set_nonblock)
    {
        set_nonblock(sd);
    }

    gc_free(&gc);
}

socket_descriptor_t
socket_do_accept(socket_descriptor_t sd,
                 struct link_socket_actual *act,
                 const bool nowait)
{
    /* af_addr_size WILL return 0 in this case if AFs other than AF_INET
     * are compiled because act is empty here.
     * could use getsockname() to support later remote_len check
     */
    socklen_t remote_len_af = af_addr_size(act->dest.addr.sa.sa_family);
    socklen_t remote_len = sizeof(act->dest.addr);
    socket_descriptor_t new_sd = SOCKET_UNDEFINED;

    CLEAR(*act);

    if (nowait)
    {
        new_sd = getpeername(sd, &act->dest.addr.sa, &remote_len);

        if (!socket_defined(new_sd))
        {
            msg(D_LINK_ERRORS | M_ERRNO, "TCP: getpeername() failed");
        }
        else
        {
            new_sd = sd;
        }
    }
    else
    {
        new_sd = accept(sd, &act->dest.addr.sa, &remote_len);
    }

#if 0 /* For debugging only, test the effect of accept() failures */
    {
        static int foo = 0;
        ++foo;
        if (foo & 1)
        {
            new_sd = -1;
        }
    }
#endif

    if (!socket_defined(new_sd))
    {
        msg(D_LINK_ERRORS | M_ERRNO, "TCP: accept(%d) failed", (int)sd);
    }
    /* only valid if we have remote_len_af!=0 */
    else if (remote_len_af && remote_len != remote_len_af)
    {
        msg(D_LINK_ERRORS, "TCP: Received strange incoming connection with unknown address length=%d", remote_len);
        openvpn_close_socket(new_sd);
        new_sd = SOCKET_UNDEFINED;
    }
    else
    {
        /* set socket file descriptor to not pass across execs, so that
         * scripts don't have access to it */
        set_cloexec(sd);
    }
    return new_sd;
}

static void
tcp_connection_established(const struct link_socket_actual *act)
{
    struct gc_arena gc = gc_new();
    msg(M_INFO, "TCP connection established with %s",
        print_link_socket_actual(act, &gc));
    gc_free(&gc);
}

static socket_descriptor_t
socket_listen_accept(socket_descriptor_t sd,
                     struct link_socket_actual *act,
                     const char *remote_dynamic,
                     const struct addrinfo *local,
                     bool do_listen,
                     bool nowait,
                     volatile int *signal_received)
{
    struct gc_arena gc = gc_new();
    /* struct openvpn_sockaddr *remote = &act->dest; */
    struct openvpn_sockaddr remote_verify = act->dest;
    socket_descriptor_t new_sd = SOCKET_UNDEFINED;

    CLEAR(*act);
    socket_do_listen(sd, local, do_listen, true);

    while (true)
    {
        int status;
        fd_set reads;
        struct timeval tv;

        FD_ZERO(&reads);
        openvpn_fd_set(sd, &reads);
        tv.tv_sec = 0;
        tv.tv_usec = 0;

        status = select(sd + 1, &reads, NULL, NULL, &tv);

        get_signal(signal_received);
        if (*signal_received)
        {
            gc_free(&gc);
            return sd;
        }

        if (status < 0)
        {
            msg(D_LINK_ERRORS | M_ERRNO, "TCP: select() failed");
        }

        if (status <= 0)
        {
            management_sleep(1);
            continue;
        }

        new_sd = socket_do_accept(sd, act, nowait);

        if (socket_defined(new_sd))
        {
            struct addrinfo *ai = NULL;
            if (remote_dynamic)
            {
                openvpn_getaddrinfo(0, remote_dynamic, NULL, 1, NULL,
                                    remote_verify.addr.sa.sa_family, &ai);
            }

            if (ai && !addrlist_match(&remote_verify, ai))
            {
                msg(M_WARN,
                    "TCP NOTE: Rejected connection attempt from %s due to --remote setting",
                    print_link_socket_actual(act, &gc));
                if (openvpn_close_socket(new_sd))
                {
                    msg(M_ERR, "TCP: close socket failed (new_sd)");
                }
                freeaddrinfo(ai);
            }
            else
            {
                if (ai)
                {
                    freeaddrinfo(ai);
                }
                break;
            }
        }
        management_sleep(1);
    }

    if (!nowait && openvpn_close_socket(sd))
    {
        msg(M_ERR, "TCP: close socket failed (sd)");
    }

    tcp_connection_established(act);

    gc_free(&gc);
    return new_sd;
}

void
socket_bind(socket_descriptor_t sd,
            struct addrinfo *local,
            int ai_family,
            const char *prefix,
            bool ipv6only)
{
    struct gc_arena gc = gc_new();

    /* FIXME (schwabe)
     * getaddrinfo for the bind address might return multiple AF_INET/AF_INET6
     * entries for the requested protocol.
     * For example if an address has multiple A records
     * What is the correct way to deal with it?
     */

    struct addrinfo *cur;

    ASSERT(local);


    /* find the first addrinfo with correct ai_family */
    for (cur = local; cur; cur = cur->ai_next)
    {
        if (cur->ai_family == ai_family)
        {
            break;
        }
    }
    if (!cur)
    {
        msg(M_FATAL, "%s: Socket bind failed: Addr to bind has no %s record",
            prefix, addr_family_name(ai_family));
    }

    if (ai_family == AF_INET6)
    {
        int v6only = ipv6only ? 1 : 0;  /* setsockopt must have an "int" */

        msg(M_INFO, "setsockopt(IPV6_V6ONLY=%d)", v6only);
        if (setsockopt(sd, IPPROTO_IPV6, IPV6_V6ONLY, (void *) &v6only, sizeof(v6only)))
        {
            msg(M_NONFATAL|M_ERRNO, "Setting IPV6_V6ONLY=%d failed", v6only);
        }
    }
    if (bind(sd, cur->ai_addr, cur->ai_addrlen))
    {
        msg(M_FATAL | M_ERRNO, "%s: Socket bind failed on local address %s",
            prefix,
            print_sockaddr_ex(local->ai_addr, ":", PS_SHOW_PORT, &gc));
    }
    gc_free(&gc);
}

int
openvpn_connect(socket_descriptor_t sd,
                const struct sockaddr *remote,
                int connect_timeout,
                volatile int *signal_received)
{
    int status = 0;

#ifdef TARGET_ANDROID
    protect_fd_nonlocal(sd, remote);
#endif

    set_nonblock(sd);
    status = connect(sd, remote, af_addr_size(remote->sa_family));
    if (status)
    {
        status = openvpn_errno();
    }
    if (
#ifdef _WIN32
        status == WSAEWOULDBLOCK
#else
        status == EINPROGRESS
#endif
        )
    {
        while (true)
        {
#if POLL
            struct pollfd fds[1];
            fds[0].fd = sd;
            fds[0].events = POLLOUT;
            status = poll(fds, 1, (connect_timeout > 0) ? 1000 : 0);
#else
            fd_set writes;
            struct timeval tv;

            FD_ZERO(&writes);
            openvpn_fd_set(sd, &writes);
            tv.tv_sec = (connect_timeout > 0) ? 1 : 0;
            tv.tv_usec = 0;

            status = select(sd + 1, NULL, &writes, NULL, &tv);
#endif
            if (signal_received)
            {
                get_signal(signal_received);
                if (*signal_received)
                {
                    status = 0;
                    break;
                }
            }
            if (status < 0)
            {
                status = openvpn_errno();
                break;
            }
            if (status <= 0)
            {
                if (--connect_timeout < 0)
                {
#ifdef _WIN32
                    status = WSAETIMEDOUT;
#else
                    status = ETIMEDOUT;
#endif
                    break;
                }
                management_sleep(0);
                continue;
            }

            /* got it */
            {
                int val = 0;
                socklen_t len;

                len = sizeof(val);
                if (getsockopt(sd, SOL_SOCKET, SO_ERROR, (void *) &val, &len) == 0
                    && len == sizeof(val))
                {
                    status = val;
                }
                else
                {
                    status = openvpn_errno();
                }
                break;
            }
        }
    }

    return status;
}

void
set_actual_address(struct link_socket_actual *actual, struct addrinfo *ai)
{
    CLEAR(*actual);
    ASSERT(ai);

    if (ai->ai_family == AF_INET)
    {
        actual->dest.addr.in4 =
            *((struct sockaddr_in *) ai->ai_addr);
    }
    else if (ai->ai_family == AF_INET6)
    {
        actual->dest.addr.in6 =
            *((struct sockaddr_in6 *) ai->ai_addr);
    }
    else
    {
        ASSERT(0);
    }

}

static void
socket_connect(socket_descriptor_t *sd,
               const struct sockaddr *dest,
               const int connect_timeout,
               struct signal_info *sig_info)
{
    struct gc_arena gc = gc_new();
    int status;

    msg(M_INFO, "Attempting to establish TCP connection with %s",
        print_sockaddr(dest, &gc));

#ifdef ENABLE_MANAGEMENT
    if (management)
    {
        management_set_state(management,
                             OPENVPN_STATE_TCP_CONNECT,
                             NULL,
                             NULL,
                             NULL,
                             NULL,
                             NULL);
    }
#endif

    /* Set the actual address */
    status = openvpn_connect(*sd, dest, connect_timeout, &sig_info->signal_received);

    get_signal(&sig_info->signal_received);
    if (sig_info->signal_received)
    {
        goto done;
    }

    if (status)
    {

        msg(D_LINK_ERRORS, "TCP: connect to %s failed: %s",
            print_sockaddr(dest, &gc), strerror(status));

        openvpn_close_socket(*sd);
        *sd = SOCKET_UNDEFINED;
        register_signal(sig_info, SIGUSR1, "connection-failed");
        sig_info->source = SIG_SOURCE_CONNECTION_FAILED;
    }
    else
    {
        msg(M_INFO, "TCP connection established with %s",
            print_sockaddr(dest, &gc));
    }

done:
    gc_free(&gc);
}

/*
 * Stream buffer handling prototypes -- stream_buf is a helper class
 * to assist in the packetization of stream transport protocols
 * such as TCP.
 */

static void
stream_buf_init(struct stream_buf *sb, struct buffer *buf,
                const unsigned int sockflags, const int proto);

static void
stream_buf_close(struct stream_buf *sb);

static bool
stream_buf_added(struct stream_buf *sb, int length_added);

/* For stream protocols, allocate a buffer to build up packet.
 * Called after frame has been finalized. */

static void
socket_frame_init(const struct frame *frame, struct link_socket *sock)
{
#ifdef _WIN32
    overlapped_io_init(&sock->reads, frame, FALSE);
    overlapped_io_init(&sock->writes, frame, TRUE);
    sock->rw_handle.read = sock->reads.overlapped.hEvent;
    sock->rw_handle.write = sock->writes.overlapped.hEvent;
#endif

    if (link_socket_connection_oriented(sock))
    {
#ifdef _WIN32
        stream_buf_init(&sock->stream_buf,
                        &sock->reads.buf_init,
                        sock->sockflags,
                        sock->info.proto);
#else
        alloc_buf_sock_tun(&sock->stream_buf_data, frame);

        stream_buf_init(&sock->stream_buf,
                        &sock->stream_buf_data,
                        sock->sockflags,
                        sock->info.proto);
#endif
    }
}

static void
resolve_bind_local(struct link_socket *sock, const sa_family_t af)
{
    struct gc_arena gc = gc_new();

    /* resolve local address if undefined */
    if (!sock->info.lsa->bind_local)
    {
        int flags = GETADDR_RESOLVE | GETADDR_WARN_ON_SIGNAL
                    |GETADDR_FATAL | GETADDR_PASSIVE;
        int status;

        if (proto_is_dgram(sock->info.proto))
        {
            flags |= GETADDR_DATAGRAM;
        }

        /* will return AF_{INET|INET6}from local_host */
        status = get_cached_dns_entry(sock->dns_cache,
                                      sock->local_host,
                                      sock->local_port,
                                      af,
                                      flags,
                                      &sock->info.lsa->bind_local);

        if (status)
        {
            status = openvpn_getaddrinfo(flags, sock->local_host, sock->local_port, 0,
                                         NULL, af, &sock->info.lsa->bind_local);
        }

        if (status !=0)
        {
            msg(M_FATAL, "getaddrinfo() failed for local \"%s:%s\": %s",
                sock->local_host, sock->local_port,
                gai_strerror(status));
        }
    }

    gc_free(&gc);
}

static void
resolve_remote(struct link_socket *sock,
               int phase,
               const char **remote_dynamic,
               struct signal_info *sig_info)
{
    volatile int *signal_received = sig_info ? &sig_info->signal_received : NULL;
    struct gc_arena gc = gc_new();

    /* resolve remote address if undefined */
    if (!sock->info.lsa->remote_list)
    {
        if (sock->remote_host)
        {
            unsigned int flags = sf2gaf(GETADDR_RESOLVE|GETADDR_UPDATE_MANAGEMENT_STATE, sock->sockflags);
            int retry = 0;
            int status = -1;
            struct addrinfo *ai;
            if (proto_is_dgram(sock->info.proto))
            {
                flags |= GETADDR_DATAGRAM;
            }

            if (sock->resolve_retry_seconds == RESOLV_RETRY_INFINITE)
            {
                if (phase == 2)
                {
                    flags |= (GETADDR_TRY_ONCE | GETADDR_FATAL);
                }
                retry = 0;
            }
            else if (phase == 1)
            {
                if (sock->resolve_retry_seconds)
                {
                    retry = 0;
                }
                else
                {
                    flags |= (GETADDR_FATAL | GETADDR_MENTION_RESOLVE_RETRY);
                    retry = 0;
                }
            }
            else if (phase == 2)
            {
                if (sock->resolve_retry_seconds)
                {
                    flags |= GETADDR_FATAL;
                    retry = sock->resolve_retry_seconds;
                }
                else
                {
                    ASSERT(0);
                }
            }
            else
            {
                ASSERT(0);
            }


            status = get_cached_dns_entry(sock->dns_cache,
                                          sock->remote_host,
                                          sock->remote_port,
                                          sock->info.af,
                                          flags, &ai);
            if (status)
            {
                status = openvpn_getaddrinfo(flags, sock->remote_host, sock->remote_port,
                                             retry, sig_info, sock->info.af, &ai);
            }

            if (status == 0)
            {
                sock->info.lsa->remote_list = ai;
                sock->info.lsa->current_remote = ai;

                dmsg(D_SOCKET_DEBUG,
                     "RESOLVE_REMOTE flags=0x%04x phase=%d rrs=%d sig=%d status=%d",
                     flags,
                     phase,
                     retry,
                     signal_received ? *signal_received : -1,
                     status);
            }
            if (signal_received && *signal_received)
            {
                goto done;
            }
            if (status!=0)
            {
                if (signal_received)
                {
                    /* potential overwrite of signal */
                    register_signal(sig_info, SIGUSR1, "socks-resolve-failure");
                }
                goto done;
            }
        }
    }

    /* should we re-use previous active remote address? */
    if (link_socket_actual_defined(&sock->info.lsa->actual))
    {
        msg(M_INFO, "TCP/UDP: Preserving recently used remote address: %s",
            print_link_socket_actual(&sock->info.lsa->actual, &gc));
        if (remote_dynamic)
        {
            *remote_dynamic = NULL;
        }
    }
    else
    {
        CLEAR(sock->info.lsa->actual);
        if (sock->info.lsa->current_remote)
        {
            set_actual_address(&sock->info.lsa->actual,
                               sock->info.lsa->current_remote);
        }
    }

done:
    gc_free(&gc);
}



struct link_socket *
link_socket_new(void)
{
    struct link_socket *sock;

    ALLOC_OBJ_CLEAR(sock, struct link_socket);
    sock->sd = SOCKET_UNDEFINED;
    sock->ctrl_sd = SOCKET_UNDEFINED;
    return sock;
}

void
link_socket_init_phase1(struct context *c, int mode)
{
    struct link_socket *sock = c->c2.link_socket;
    struct options *o = &c->options;
    ASSERT(sock);

    const char *remote_host = o->ce.remote;
    const char *remote_port = o->ce.remote_port;

    sock->local_host = o->ce.local;
    sock->local_port = o->ce.local_port;
    sock->remote_host = remote_host;
    sock->remote_port = remote_port;
    sock->dns_cache = c->c1.dns_cache;
    sock->http_proxy = c->c1.http_proxy;
    sock->socks_proxy = c->c1.socks_proxy;
    sock->bind_local = o->ce.bind_local;
    sock->resolve_retry_seconds = o->resolve_retry_seconds;
    sock->mtu_discover_type = o->ce.mtu_discover_type;

#ifdef ENABLE_DEBUG
    sock->gremlin = o->gremlin;
#endif

    sock->socket_buffer_sizes.rcvbuf = o->rcvbuf;
    sock->socket_buffer_sizes.sndbuf = o->sndbuf;

    sock->sockflags = o->sockflags;
#if PORT_SHARE
    if (o->port_share_host && o->port_share_port)
    {
        sock->sockflags |= SF_PORT_SHARE;
    }
#endif
    sock->mark = o->mark;
    sock->bind_dev = o->bind_dev;

    sock->info.proto = o->ce.proto;
    sock->info.af = o->ce.af;
    sock->info.remote_float = o->ce.remote_float;
    sock->info.lsa = &c->c1.link_socket_addr;
    sock->info.bind_ipv6_only = o->ce.bind_ipv6_only;
    sock->info.ipchange_command = o->ipchange;
    sock->info.plugins = c->plugins;
    sock->server_poll_timeout = &c->c2.server_poll_interval;

    sock->mode = mode;
    if (mode == LS_MODE_TCP_ACCEPT_FROM)
    {
        ASSERT(c->c2.accept_from);
        ASSERT(sock->info.proto == PROTO_TCP_SERVER);
        sock->sd = c->c2.accept_from->sd;
        /* inherit (possibly guessed) info AF from parent context */
        sock->info.af = c->c2.accept_from->info.af;
    }

    /* are we running in HTTP proxy mode? */
    if (sock->http_proxy)
    {
        ASSERT(sock->info.proto == PROTO_TCP_CLIENT);

        /* the proxy server */
        sock->remote_host = c->c1.http_proxy->options.server;
        sock->remote_port = c->c1.http_proxy->options.port;

        /* the OpenVPN server we will use the proxy to connect to */
        sock->proxy_dest_host = remote_host;
        sock->proxy_dest_port = remote_port;
    }
    /* or in Socks proxy mode? */
    else if (sock->socks_proxy)
    {
        /* the proxy server */
        sock->remote_host = c->c1.socks_proxy->server;
        sock->remote_port = c->c1.socks_proxy->port;

        /* the OpenVPN server we will use the proxy to connect to */
        sock->proxy_dest_host = remote_host;
        sock->proxy_dest_port = remote_port;
    }
    else
    {
        sock->remote_host = remote_host;
        sock->remote_port = remote_port;
    }

    /* bind behavior for TCP server vs. client */
    if (sock->info.proto == PROTO_TCP_SERVER)
    {
        if (sock->mode == LS_MODE_TCP_ACCEPT_FROM)
        {
            sock->bind_local = false;
        }
        else
        {
            sock->bind_local = true;
        }
    }

    if (mode != LS_MODE_TCP_ACCEPT_FROM)
    {
        if (sock->bind_local)
        {
            resolve_bind_local(sock, sock->info.af);
        }
        resolve_remote(sock, 1, NULL, NULL);
    }
}

static void
phase2_set_socket_flags(struct link_socket *sock)
{
    /* set misc socket parameters */
    socket_set_flags(sock->sd, sock->sockflags);

    /* set socket to non-blocking mode */
    set_nonblock(sock->sd);

    /* set Path MTU discovery options on the socket */
    set_mtu_discover_type(sock->sd, sock->mtu_discover_type, sock->info.af);

#if EXTENDED_SOCKET_ERROR_CAPABILITY
    /* if the OS supports it, enable extended error passing on the socket */
    set_sock_extended_error_passing(sock->sd, sock->info.af);
#endif
}


static void
linksock_print_addr(struct link_socket *sock)
{
    struct gc_arena gc = gc_new();
    const int msglevel = (sock->mode == LS_MODE_TCP_ACCEPT_FROM) ? D_INIT_MEDIUM : M_INFO;

    /* print local address */
    if (sock->bind_local)
    {
        sa_family_t ai_family = sock->info.lsa->actual.dest.addr.sa.sa_family;
        /* Socket is always bound on the first matching address,
         * For bound sockets with no remote addr this is the element of
         * the list */
        struct addrinfo *cur;
        for (cur = sock->info.lsa->bind_local; cur; cur = cur->ai_next)
        {
            if (!ai_family || ai_family == cur->ai_family)
            {
                break;
            }
        }
        ASSERT(cur);
        msg(msglevel, "%s link local (bound): %s",
            proto2ascii(sock->info.proto, sock->info.af, true),
            print_sockaddr(cur->ai_addr, &gc));
    }
    else
    {
        msg(msglevel, "%s link local: (not bound)",
            proto2ascii(sock->info.proto, sock->info.af, true));
    }

    /* print active remote address */
    msg(msglevel, "%s link remote: %s",
        proto2ascii(sock->info.proto, sock->info.af, true),
        print_link_socket_actual_ex(&sock->info.lsa->actual,
                                    ":",
                                    PS_SHOW_PORT_IF_DEFINED,
                                    &gc));
    gc_free(&gc);
}

static void
phase2_tcp_server(struct link_socket *sock, const char *remote_dynamic,
                  struct signal_info *sig_info)
{
    volatile int *signal_received = sig_info ? &sig_info->signal_received : NULL;
    switch (sock->mode)
    {
        case LS_MODE_DEFAULT:
            sock->sd = socket_listen_accept(sock->sd,
                                            &sock->info.lsa->actual,
                                            remote_dynamic,
                                            sock->info.lsa->bind_local,
                                            true,
                                            false,
                                            signal_received);
            break;

        case LS_MODE_TCP_LISTEN:
            socket_do_listen(sock->sd,
                             sock->info.lsa->bind_local,
                             true,
                             false);
            break;

        case LS_MODE_TCP_ACCEPT_FROM:
            sock->sd = socket_do_accept(sock->sd,
                                        &sock->info.lsa->actual,
                                        false);
            if (!socket_defined(sock->sd))
            {
                register_signal(sig_info, SIGTERM, "socket-undefiled");
                return;
            }
            tcp_connection_established(&sock->info.lsa->actual);
            break;

        default:
            ASSERT(0);
    }
}


static void
phase2_tcp_client(struct link_socket *sock, struct signal_info *sig_info)
{
    bool proxy_retry = false;
    do
    {
        socket_connect(&sock->sd,
                       sock->info.lsa->current_remote->ai_addr,
                       get_server_poll_remaining_time(sock->server_poll_timeout),
                       sig_info);

        if (sig_info->signal_received)
        {
            return;
        }

        if (sock->http_proxy)
        {
            proxy_retry = establish_http_proxy_passthru(sock->http_proxy,
                                                        sock->sd,
                                                        sock->proxy_dest_host,
                                                        sock->proxy_dest_port,
                                                        sock->server_poll_timeout,
                                                        &sock->stream_buf.residual,
                                                        sig_info);
        }
        else if (sock->socks_proxy)
        {
            establish_socks_proxy_passthru(sock->socks_proxy,
                                           sock->sd,
                                           sock->proxy_dest_host,
                                           sock->proxy_dest_port,
                                           sig_info);
        }
        if (proxy_retry)
        {
            openvpn_close_socket(sock->sd);
            sock->sd = create_socket_tcp(sock->info.lsa->current_remote);
        }

    } while (proxy_retry);

}

static void
phase2_socks_client(struct link_socket *sock, struct signal_info *sig_info)
{
    socket_connect(&sock->ctrl_sd,
                   sock->info.lsa->current_remote->ai_addr,
                   get_server_poll_remaining_time(sock->server_poll_timeout),
                   sig_info);

    if (sig_info->signal_received)
    {
        return;
    }

    establish_socks_proxy_udpassoc(sock->socks_proxy,
                                   sock->ctrl_sd,
                                   sock->sd,
                                   &sock->socks_relay.dest,
                                   sig_info);

    if (sig_info->signal_received)
    {
        return;
    }

    sock->remote_host = sock->proxy_dest_host;
    sock->remote_port = sock->proxy_dest_port;

    addr_zero_host(&sock->info.lsa->actual.dest);
    if (sock->info.lsa->remote_list)
    {
        freeaddrinfo(sock->info.lsa->remote_list);
        sock->info.lsa->current_remote = NULL;
        sock->info.lsa->remote_list = NULL;
    }

    resolve_remote(sock, 1, NULL, sig_info);
}

#if defined(_WIN32)
static void
create_socket_dco_win(struct context *c, struct link_socket *sock,
                      struct signal_info *sig_info)
{
    if (!c->c1.tuntap)
    {
        struct tuntap *tt;
        ALLOC_OBJ(tt, struct tuntap);

        *tt = create_dco_handle(c->options.dev_node, &c->gc);

        /* Ensure we can "safely" cast the handle to a socket */
        static_assert(sizeof(sock->sd) == sizeof(tt->hand), "HANDLE and SOCKET size differs");

        c->c1.tuntap = tt;
    }

    dco_create_socket(c->c1.tuntap->hand,
                      sock->info.lsa->current_remote,
                      sock->bind_local, sock->info.lsa->bind_local,
                      get_server_poll_remaining_time(sock->server_poll_timeout),
                      sig_info);

    sock->sockflags |= SF_DCO_WIN;

    if (sig_info->signal_received)
    {
        return;
    }

    sock->sd = (SOCKET)c->c1.tuntap->hand;
    linksock_print_addr(sock);
}
#endif /* if defined(_WIN32) */

/* finalize socket initialization */
void
link_socket_init_phase2(struct context *c)
{
    struct link_socket *sock = c->c2.link_socket;
    const struct frame *frame = &c->c2.frame;
    struct signal_info *sig_info = c->sig;

    const char *remote_dynamic = NULL;
    struct signal_info sig_save = {0};

    ASSERT(sock);
    ASSERT(sig_info);

    if (sig_info->signal_received)
    {
        sig_save = *sig_info;
        signal_reset(sig_info);
    }

    /* initialize buffers */
    socket_frame_init(frame, sock);

    /*
     * Pass a remote name to connect/accept so that
     * they can test for dynamic IP address changes
     * and throw a SIGUSR1 if appropriate.
     */
    if (sock->resolve_retry_seconds)
    {
        remote_dynamic = sock->remote_host;
    }

    /* Second chance to resolv/create socket */
    resolve_remote(sock, 2, &remote_dynamic,  sig_info);

    /* If a valid remote has been found, create the socket with its addrinfo */
    if (sock->info.lsa->current_remote)
    {
#if defined(_WIN32)
        if (dco_enabled(&c->options))
        {
            create_socket_dco_win(c, sock, sig_info);
            goto done;
        }
        else
#endif
        {
            create_socket(sock, sock->info.lsa->current_remote);
        }

    }

    /* If socket has not already been created create it now */
    if (sock->sd == SOCKET_UNDEFINED)
    {
        /* If we have no --remote and have still not figured out the
         * protocol family to use we will use the first of the bind */

        if (sock->bind_local  && !sock->remote_host && sock->info.lsa->bind_local)
        {
            /* Warn if this is because neither v4 or v6 was specified
             * and we should not connect a remote */
            if (sock->info.af == AF_UNSPEC)
            {
                msg(M_WARN, "Could not determine IPv4/IPv6 protocol. Using %s",
                    addr_family_name(sock->info.lsa->bind_local->ai_family));
                sock->info.af = sock->info.lsa->bind_local->ai_family;
            }

            create_socket(sock, sock->info.lsa->bind_local);
        }
    }

    /* Socket still undefined, give a warning and abort connection */
    if (sock->sd == SOCKET_UNDEFINED)
    {
        msg(M_WARN, "Could not determine IPv4/IPv6 protocol");
        register_signal(sig_info, SIGUSR1, "Could not determine IPv4/IPv6 protocol");
        goto done;
    }

    if (sig_info->signal_received)
    {
        goto done;
    }

    if (sock->info.proto == PROTO_TCP_SERVER)
    {
        phase2_tcp_server(sock, remote_dynamic, sig_info);
    }
    else if (sock->info.proto == PROTO_TCP_CLIENT)
    {
        phase2_tcp_client(sock, sig_info);

    }
    else if (sock->info.proto == PROTO_UDP && sock->socks_proxy)
    {
        phase2_socks_client(sock, sig_info);
    }
#ifdef TARGET_ANDROID
    if (sock->sd != -1)
    {
        protect_fd_nonlocal(sock->sd, &sock->info.lsa->actual.dest.addr.sa);
    }
#endif
    if (sig_info->signal_received)
    {
        goto done;
    }

    phase2_set_socket_flags(sock);
    linksock_print_addr(sock);

done:
    if (sig_save.signal_received)
    {
        /* Always restore the saved signal -- register/throw_signal will handle priority */
        if (sig_save.source == SIG_SOURCE_HARD && sig_info == &siginfo_static)
        {
            throw_signal(sig_save.signal_received);
        }
        else
        {
            register_signal(sig_info, sig_save.signal_received, sig_save.signal_text);
        }
    }
}

void
link_socket_close(struct link_socket *sock)
{
    if (sock)
    {
#ifdef ENABLE_DEBUG
        const int gremlin = GREMLIN_CONNECTION_FLOOD_LEVEL(sock->gremlin);
#else
        const int gremlin = 0;
#endif

        if (socket_defined(sock->sd))
        {
#ifdef _WIN32
            close_net_event_win32(&sock->listen_handle, sock->sd, 0);
#endif
            if (!gremlin)
            {
                msg(D_LOW, "TCP/UDP: Closing socket");
                if (openvpn_close_socket(sock->sd))
                {
                    msg(M_WARN | M_ERRNO, "TCP/UDP: Close Socket failed");
                }
            }
            sock->sd = SOCKET_UNDEFINED;
#ifdef _WIN32
            if (!gremlin)
            {
                overlapped_io_close(&sock->reads);
                overlapped_io_close(&sock->writes);
            }
#endif
        }

        if (socket_defined(sock->ctrl_sd))
        {
            if (openvpn_close_socket(sock->ctrl_sd))
            {
                msg(M_WARN | M_ERRNO, "TCP/UDP: Close Socket (ctrl_sd) failed");
            }
            sock->ctrl_sd = SOCKET_UNDEFINED;
        }

        stream_buf_close(&sock->stream_buf);
        free_buf(&sock->stream_buf_data);
        if (!gremlin)
        {
            free(sock);
        }
    }
}

void
setenv_trusted(struct env_set *es, const struct link_socket_info *info)
{
    setenv_link_socket_actual(es, "trusted", &info->lsa->actual, SA_IP_PORT);
}

static void
ipchange_fmt(const bool include_cmd, struct argv *argv, const struct link_socket_info *info, struct gc_arena *gc)
{
    const char *host = print_sockaddr_ex(&info->lsa->actual.dest.addr.sa, " ", PS_SHOW_PORT, gc);
    if (include_cmd)
    {
        argv_parse_cmd(argv, info->ipchange_command);
        argv_printf_cat(argv, "%s", host);
    }
    else
    {
        argv_printf(argv, "%s", host);
    }

}

void
link_socket_connection_initiated(struct link_socket_info *info,
                                 const struct link_socket_actual *act,
                                 const char *common_name,
                                 struct env_set *es)
{
    struct gc_arena gc = gc_new();

    info->lsa->actual = *act; /* Note: skip this line for --force-dest */
    setenv_trusted(es, info);
    info->connection_established = true;

    /* Print connection initiated message, with common name if available */
    {
        struct buffer out = alloc_buf_gc(256, &gc);
        if (common_name)
        {
            buf_printf(&out, "[%s] ", common_name);
        }
        buf_printf(&out, "Peer Connection Initiated with %s", print_link_socket_actual(&info->lsa->actual, &gc));
        msg(M_INFO, "%s", BSTR(&out));
    }

    /* set environmental vars */
    setenv_str(es, "common_name", common_name);

    /* Process --ipchange plugin */
    if (plugin_defined(info->plugins, OPENVPN_PLUGIN_IPCHANGE))
    {
        struct argv argv = argv_new();
        ipchange_fmt(false, &argv, info, &gc);
        if (plugin_call(info->plugins, OPENVPN_PLUGIN_IPCHANGE, &argv, NULL, es) != OPENVPN_PLUGIN_FUNC_SUCCESS)
        {
            msg(M_WARN, "WARNING: ipchange plugin call failed");
        }
        argv_free(&argv);
    }

    /* Process --ipchange option */
    if (info->ipchange_command)
    {
        struct argv argv = argv_new();
        setenv_str(es, "script_type", "ipchange");
        ipchange_fmt(true, &argv, info, &gc);
        openvpn_run_script(&argv, es, 0, "--ipchange");
        argv_free(&argv);
    }

    gc_free(&gc);
}

void
link_socket_bad_incoming_addr(struct buffer *buf,
                              const struct link_socket_info *info,
                              const struct link_socket_actual *from_addr)
{
    struct gc_arena gc = gc_new();
    struct addrinfo *ai;

    switch (from_addr->dest.addr.sa.sa_family)
    {
        case AF_INET:
        case AF_INET6:
            msg(D_LINK_ERRORS,
                "TCP/UDP: Incoming packet rejected from %s[%d], expected peer address: %s (allow this incoming source address/port by removing --remote or adding --float)",
                print_link_socket_actual(from_addr, &gc),
                (int)from_addr->dest.addr.sa.sa_family,
                print_sockaddr_ex(info->lsa->remote_list->ai_addr, ":", PS_SHOW_PORT, &gc));
            /* print additional remote addresses */
            for (ai = info->lsa->remote_list->ai_next; ai; ai = ai->ai_next)
            {
                msg(D_LINK_ERRORS, "or from peer address: %s",
                    print_sockaddr_ex(ai->ai_addr, ":", PS_SHOW_PORT, &gc));
            }
            break;
    }
    buf->len = 0;
    gc_free(&gc);
}

void
link_socket_bad_outgoing_addr(void)
{
    dmsg(D_READ_WRITE, "TCP/UDP: No outgoing address to send packet");
}

in_addr_t
link_socket_current_remote(const struct link_socket_info *info)
{
    const struct link_socket_addr *lsa = info->lsa;

/*
 * This logic supports "redirect-gateway" semantic, which
 * makes sense only for PF_INET routes over PF_INET endpoints
 *
 * Maybe in the future consider PF_INET6 endpoints also ...
 * by now just ignore it
 *
 * For --remote entries with multiple addresses this
 * only return the actual endpoint we have successfully connected to
 */
    if (lsa->actual.dest.addr.sa.sa_family != AF_INET)
    {
        return IPV4_INVALID_ADDR;
    }

    if (link_socket_actual_defined(&lsa->actual))
    {
        return ntohl(lsa->actual.dest.addr.in4.sin_addr.s_addr);
    }
    else if (lsa->current_remote)
    {
        return ntohl(((struct sockaddr_in *)lsa->current_remote->ai_addr)
                     ->sin_addr.s_addr);
    }
    else
    {
        return 0;
    }
}

const struct in6_addr *
link_socket_current_remote_ipv6(const struct link_socket_info *info)
{
    const struct link_socket_addr *lsa = info->lsa;

/* This logic supports "redirect-gateway" semantic,
 * for PF_INET6 routes over PF_INET6 endpoints
 *
 * For --remote entries with multiple addresses this
 * only return the actual endpoint we have successfully connected to
 */
    if (lsa->actual.dest.addr.sa.sa_family != AF_INET6)
    {
        return NULL;
    }

    if (link_socket_actual_defined(&lsa->actual))
    {
        return &(lsa->actual.dest.addr.in6.sin6_addr);
    }
    else if (lsa->current_remote)
    {
        return &(((struct sockaddr_in6 *)lsa->current_remote->ai_addr)->sin6_addr);
    }
    else
    {
        return NULL;
    }
}

/*
 * Return a status string describing socket state.
 */
const char *
socket_stat(const struct link_socket *s, unsigned int rwflags, struct gc_arena *gc)
{
    struct buffer out = alloc_buf_gc(64, gc);
    if (s)
    {
        if (rwflags & EVENT_READ)
        {
            buf_printf(&out, "S%s",
                       (s->rwflags_debug & EVENT_READ) ? "R" : "r");
#ifdef _WIN32
            buf_printf(&out, "%s",
                       overlapped_io_state_ascii(&s->reads));
#endif
        }
        if (rwflags & EVENT_WRITE)
        {
            buf_printf(&out, "S%s",
                       (s->rwflags_debug & EVENT_WRITE) ? "W" : "w");
#ifdef _WIN32
            buf_printf(&out, "%s",
                       overlapped_io_state_ascii(&s->writes));
#endif
        }
    }
    else
    {
        buf_printf(&out, "S?");
    }
    return BSTR(&out);
}

/*
 * Stream buffer functions, used to packetize a TCP
 * stream connection.
 */

static inline void
stream_buf_reset(struct stream_buf *sb)
{
    dmsg(D_STREAM_DEBUG, "STREAM: RESET");
    sb->residual_fully_formed = false;
    sb->buf = sb->buf_init;
    buf_reset(&sb->next);
    sb->len = -1;
}

static void
stream_buf_init(struct stream_buf *sb,
                struct buffer *buf,
                const unsigned int sockflags,
                const int proto)
{
    sb->buf_init = *buf;
    sb->maxlen = sb->buf_init.len;
    sb->buf_init.len = 0;
    sb->residual = alloc_buf(sb->maxlen);
    sb->error = false;
#if PORT_SHARE
    sb->port_share_state = ((sockflags & SF_PORT_SHARE) && (proto == PROTO_TCP_SERVER))
                           ? PS_ENABLED
                           : PS_DISABLED;
#endif
    stream_buf_reset(sb);

    dmsg(D_STREAM_DEBUG, "STREAM: INIT maxlen=%d", sb->maxlen);
}

static inline void
stream_buf_set_next(struct stream_buf *sb)
{
    /* set up 'next' for next i/o read */
    sb->next = sb->buf;
    sb->next.offset = sb->buf.offset + sb->buf.len;
    sb->next.len = (sb->len >= 0 ? sb->len : sb->maxlen) - sb->buf.len;
    dmsg(D_STREAM_DEBUG, "STREAM: SET NEXT, buf=[%d,%d] next=[%d,%d] len=%d maxlen=%d",
         sb->buf.offset, sb->buf.len,
         sb->next.offset, sb->next.len,
         sb->len, sb->maxlen);
    ASSERT(sb->next.len > 0);
    ASSERT(buf_safe(&sb->buf, sb->next.len));
}

static inline void
stream_buf_get_final(struct stream_buf *sb, struct buffer *buf)
{
    dmsg(D_STREAM_DEBUG, "STREAM: GET FINAL len=%d",
         buf_defined(&sb->buf) ? sb->buf.len : -1);
    ASSERT(buf_defined(&sb->buf));
    *buf = sb->buf;
}

static inline void
stream_buf_get_next(struct stream_buf *sb, struct buffer *buf)
{
    dmsg(D_STREAM_DEBUG, "STREAM: GET NEXT len=%d",
         buf_defined(&sb->next) ? sb->next.len : -1);
    ASSERT(buf_defined(&sb->next));
    *buf = sb->next;
}

bool
stream_buf_read_setup_dowork(struct link_socket *sock)
{
    if (sock->stream_buf.residual.len && !sock->stream_buf.residual_fully_formed)
    {
        ASSERT(buf_copy(&sock->stream_buf.buf, &sock->stream_buf.residual));
        ASSERT(buf_init(&sock->stream_buf.residual, 0));
        sock->stream_buf.residual_fully_formed = stream_buf_added(&sock->stream_buf, 0);
        dmsg(D_STREAM_DEBUG, "STREAM: RESIDUAL FULLY FORMED [%s], len=%d",
             sock->stream_buf.residual_fully_formed ? "YES" : "NO",
             sock->stream_buf.residual.len);
    }

    if (!sock->stream_buf.residual_fully_formed)
    {
        stream_buf_set_next(&sock->stream_buf);
    }
    return !sock->stream_buf.residual_fully_formed;
}

static bool
stream_buf_added(struct stream_buf *sb,
                 int length_added)
{
    dmsg(D_STREAM_DEBUG, "STREAM: ADD length_added=%d", length_added);
    if (length_added > 0)
    {
        sb->buf.len += length_added;
    }

    /* if length unknown, see if we can get the length prefix from
     * the head of the buffer */
    if (sb->len < 0 && sb->buf.len >= (int) sizeof(packet_size_type))
    {
        packet_size_type net_size;

#if PORT_SHARE
        if (sb->port_share_state == PS_ENABLED)
        {
            if (!is_openvpn_protocol(&sb->buf))
            {
                msg(D_STREAM_ERRORS, "Non-OpenVPN client protocol detected");
                sb->port_share_state = PS_FOREIGN;
                sb->error = true;
                return false;
            }
            else
            {
                sb->port_share_state = PS_DISABLED;
            }
        }
#endif

        ASSERT(buf_read(&sb->buf, &net_size, sizeof(net_size)));
        sb->len = ntohps(net_size);

        if (sb->len < 1 || sb->len > sb->maxlen)
        {
            msg(M_WARN, "WARNING: Bad encapsulated packet length from peer (%d), which must be > 0 and <= %d -- please ensure that --tun-mtu or --link-mtu is equal on both peers -- this condition could also indicate a possible active attack on the TCP link -- [Attempting restart...]", sb->len, sb->maxlen);
            stream_buf_reset(sb);
            sb->error = true;
            return false;
        }
    }

    /* is our incoming packet fully read? */
    if (sb->len > 0 && sb->buf.len >= sb->len)
    {
        /* save any residual data that's part of the next packet */
        ASSERT(buf_init(&sb->residual, 0));
        if (sb->buf.len > sb->len)
        {
            ASSERT(buf_copy_excess(&sb->residual, &sb->buf, sb->len));
        }
        dmsg(D_STREAM_DEBUG, "STREAM: ADD returned TRUE, buf_len=%d, residual_len=%d",
             BLEN(&sb->buf),
             BLEN(&sb->residual));
        return true;
    }
    else
    {
        dmsg(D_STREAM_DEBUG, "STREAM: ADD returned FALSE (have=%d need=%d)", sb->buf.len, sb->len);
        stream_buf_set_next(sb);
        return false;
    }
}

static void
stream_buf_close(struct stream_buf *sb)
{
    free_buf(&sb->residual);
}

/*
 * The listen event is a special event whose sole purpose is
 * to tell us that there's a new incoming connection on a
 * TCP socket, for use in server mode.
 */
event_t
socket_listen_event_handle(struct link_socket *s)
{
#ifdef _WIN32
    if (!defined_net_event_win32(&s->listen_handle))
    {
        init_net_event_win32(&s->listen_handle, FD_ACCEPT, s->sd, 0);
    }
    return &s->listen_handle;
#else  /* ifdef _WIN32 */
    return s->sd;
#endif
}

/*
 * Format IP addresses in ascii
 */

const char *
print_sockaddr_ex(const struct sockaddr *sa,
                  const char *separator,
                  const unsigned int flags,
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
            addr_is_defined = ((struct sockaddr_in *) sa)->sin_addr.s_addr != 0;
            break;

        case AF_INET6:
            if (!(flags & PS_DONT_SHOW_FAMILY))
            {
                buf_puts(&out, "[AF_INET6]");
            }
            salen = sizeof(struct sockaddr_in6);
            addr_is_defined = !IN6_IS_ADDR_UNSPECIFIED(&((struct sockaddr_in6 *) sa)->sin6_addr);
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

    status = getnameinfo(sa, salen, hostaddr, sizeof(hostaddr),
                         servname, sizeof(servname), NI_NUMERICHOST | NI_NUMERICSERV);

    if (status!=0)
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
    return print_link_socket_actual_ex(act, ":", PS_SHOW_PORT|PS_SHOW_PKTINFO, gc);
}

#ifndef IF_NAMESIZE
#define IF_NAMESIZE 16
#endif

const char *
print_link_socket_actual_ex(const struct link_socket_actual *act,
                            const char *separator,
                            const unsigned int flags,
                            struct gc_arena *gc)
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
#else  /* if defined(HAVE_IN_PKTINFO) && defined(HAVE_IPI_SPEC_DST) */
#error ENABLE_IP_PKTINFO is set without IP_PKTINFO xor IP_RECVDSTADDR (fix syshead.h)
#endif
                    buf_printf(&out, " (via %s%%%s)",
                               print_sockaddr_ex(&sa.addr.sa, separator, 0, gc),
                               ifname);
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
                    if (getnameinfo((struct sockaddr *)&sin6, sizeof(struct sockaddr_in6),
                                    buf, sizeof(buf), NULL, 0, NI_NUMERICHOST) == 0)
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
    struct buffer out = alloc_buf_gc(64, gc);

    if (addr || !(flags & IA_EMPTY_IF_UNDEF))
    {
        CLEAR(ia);
        ia.s_addr = (flags & IA_NET_ORDER) ? addr : htonl(addr);

        buf_printf(&out, "%s", inet_ntoa(ia));
    }
    return BSTR(&out);
}

/*
 * Convert an in6_addr in host byte order
 * to an ascii representation of an IPv6 address
 */
const char *
print_in6_addr(struct in6_addr a6, unsigned int flags, struct gc_arena *gc)
{
    struct buffer out = alloc_buf_gc(64, gc);
    char tmp_out_buf[64];       /* inet_ntop wants pointer to buffer */

    if (memcmp(&a6, &in6addr_any, sizeof(a6)) != 0
        || !(flags & IA_EMPTY_IF_UNDEF))
    {
        inet_ntop(AF_INET6, &a6, tmp_out_buf, sizeof(tmp_out_buf)-1);
        buf_printf(&out, "%s", tmp_out_buf );
    }
    return BSTR(&out);
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

#ifndef UINT8_MAX
#define UINT8_MAX 0xff
#endif

/* add some offset to an ipv6 address
 * (add in steps of 8 bits, taking overflow into next round)
 */
struct in6_addr
add_in6_addr( struct in6_addr base, uint32_t add )
{
    int i;

    for (i = 15; i>=0 && add > 0; i--)
    {
        register int carry;
        register uint32_t h;

        h = (unsigned char) base.s6_addr[i];
        base.s6_addr[i] = (h+add) & UINT8_MAX;

        /* using explicit carry for the 8-bit additions will catch
         * 8-bit and(!) 32-bit overruns nicely
         */
        carry = ((h & 0xff)  + (add & 0xff)) >> 8;
        add = (add>>8) + carry;
    }
    return base;
}

/* set environmental variables for ip/port in *addr */
void
setenv_sockaddr(struct env_set *es, const char *name_prefix, const struct openvpn_sockaddr *addr, const unsigned int flags)
{
    char name_buf[256];

    char buf[128];
    switch (addr->addr.sa.sa_family)
    {
        case AF_INET:
            if (flags & SA_IP_PORT)
            {
                openvpn_snprintf(name_buf, sizeof(name_buf), "%s_ip", name_prefix);
            }
            else
            {
                openvpn_snprintf(name_buf, sizeof(name_buf), "%s", name_prefix);
            }

            setenv_str(es, name_buf, inet_ntoa(addr->addr.in4.sin_addr));

            if ((flags & SA_IP_PORT) && addr->addr.in4.sin_port)
            {
                openvpn_snprintf(name_buf, sizeof(name_buf), "%s_port", name_prefix);
                setenv_int(es, name_buf, ntohs(addr->addr.in4.sin_port));
            }
            break;

        case AF_INET6:
            if (IN6_IS_ADDR_V4MAPPED( &addr->addr.in6.sin6_addr ))
            {
                struct in_addr ia;
                memcpy(&ia.s_addr, &addr->addr.in6.sin6_addr.s6_addr[12],
                       sizeof(ia.s_addr));
                openvpn_snprintf(name_buf, sizeof(name_buf), "%s_ip", name_prefix);
                openvpn_snprintf(buf, sizeof(buf), "%s", inet_ntoa(ia) );
            }
            else
            {
                openvpn_snprintf(name_buf, sizeof(name_buf), "%s_ip6", name_prefix);
                getnameinfo(&addr->addr.sa, sizeof(struct sockaddr_in6),
                            buf, sizeof(buf), NULL, 0, NI_NUMERICHOST);
            }
            setenv_str(es, name_buf, buf);

            if ((flags & SA_IP_PORT) && addr->addr.in6.sin6_port)
            {
                openvpn_snprintf(name_buf, sizeof(name_buf), "%s_port", name_prefix);
                setenv_int(es, name_buf, ntohs(addr->addr.in6.sin6_port));
            }
            break;
    }
}

void
setenv_in_addr_t(struct env_set *es, const char *name_prefix, in_addr_t addr, const unsigned int flags)
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
setenv_in6_addr(struct env_set *es,
                const char *name_prefix,
                const struct in6_addr *addr,
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
setenv_link_socket_actual(struct env_set *es,
                          const char *name_prefix,
                          const struct link_socket_actual *act,
                          const unsigned int flags)
{
    setenv_sockaddr(es, name_prefix, &act->dest, flags);
}

/*
 * Convert protocol names between index and ascii form.
 */

struct proto_names {
    const char *short_form;
    const char *display_form;
    sa_family_t proto_af;
    int proto;
};

/* Indexed by PROTO_x */
static const struct proto_names proto_names[] = {
    {"proto-uninitialized", "proto-NONE", AF_UNSPEC, PROTO_NONE},
    /* try IPv4 and IPv6 (client), bind dual-stack (server) */
    {"udp",         "UDP", AF_UNSPEC, PROTO_UDP},
    {"tcp-server",  "TCP_SERVER", AF_UNSPEC, PROTO_TCP_SERVER},
    {"tcp-client",  "TCP_CLIENT", AF_UNSPEC, PROTO_TCP_CLIENT},
    {"tcp",         "TCP", AF_UNSPEC, PROTO_TCP},
    /* force IPv4 */
    {"udp4",        "UDPv4", AF_INET, PROTO_UDP},
    {"tcp4-server", "TCPv4_SERVER", AF_INET, PROTO_TCP_SERVER},
    {"tcp4-client", "TCPv4_CLIENT", AF_INET, PROTO_TCP_CLIENT},
    {"tcp4",        "TCPv4", AF_INET, PROTO_TCP},
    /* force IPv6 */
    {"udp6",        "UDPv6", AF_INET6, PROTO_UDP},
    {"tcp6-server", "TCPv6_SERVER", AF_INET6, PROTO_TCP_SERVER},
    {"tcp6-client", "TCPv6_CLIENT", AF_INET6, PROTO_TCP_CLIENT},
    {"tcp6",        "TCPv6", AF_INET6, PROTO_TCP},
};

int
ascii2proto(const char *proto_name)
{
    int i;
    for (i = 0; i < SIZE(proto_names); ++i)
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
    int i;
    for (i = 0; i < SIZE(proto_names); ++i)
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
    unsigned int i;
    for (i = 0; i < SIZE(proto_names); ++i)
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
    int i;

    for (i = 0; i < SIZE(proto_names); ++i)
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
        case AF_INET:  return "AF_INET";

        case AF_INET6: return "AF_INET6";
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

    if ( (remote && proto == PROTO_TCP_CLIENT)
         || (!remote && proto == PROTO_TCP_SERVER))
    {
        return "TCPv4_SERVER";
    }
    if ( (remote && proto == PROTO_TCP_SERVER)
         || (!remote && proto == PROTO_TCP_CLIENT))
    {
        return "TCPv4_CLIENT";
    }

    ASSERT(0);
    return ""; /* Make the compiler happy */
}

/*
 * Bad incoming address lengths that differ from what
 * we expect are considered to be fatal errors.
 */
void
bad_address_length(int actual, int expected)
{
    msg(M_FATAL, "ERROR: received strange incoming packet with an address length of %d -- we only accept address lengths of %d.",
        actual,
        expected);
}

/*
 * Socket Read Routines
 */

int
link_socket_read_tcp(struct link_socket *sock,
                     struct buffer *buf)
{
    int len = 0;

    if (!sock->stream_buf.residual_fully_formed)
    {
        /* with Linux-DCO, we sometimes try to access a socket that is
         * already installed in the kernel and has no valid file descriptor
         * anymore.  This is a bug.
         * Handle by resetting client instance instead of crashing.
         */
        if (sock->sd == SOCKET_UNDEFINED)
        {
            msg(M_INFO, "BUG: link_socket_read_tcp(): sock->sd==-1, reset client instance" );
            sock->stream_reset = true;              /* reset client instance */
            return buf->len = 0;                    /* nothing to read */
        }

#ifdef _WIN32
        sockethandle_t sh = { .s = sock->sd };
        len = sockethandle_finalize(sh, &sock->reads, buf, NULL);
#else
        struct buffer frag;
        stream_buf_get_next(&sock->stream_buf, &frag);
        len = recv(sock->sd, BPTR(&frag), BLEN(&frag), MSG_NOSIGNAL);
#endif

        if (!len)
        {
            sock->stream_reset = true;
        }
        if (len <= 0)
        {
            return buf->len = len;
        }
    }

    if (sock->stream_buf.residual_fully_formed
        || stream_buf_added(&sock->stream_buf, len)) /* packet complete? */
    {
        stream_buf_get_final(&sock->stream_buf, buf);
        stream_buf_reset(&sock->stream_buf);
        return buf->len;
    }
    else
    {
        return buf->len = 0; /* no error, but packet is still incomplete */
    }
}

#ifndef _WIN32

#if ENABLE_IP_PKTINFO

/* make the buffer large enough to handle ancillary socket data for
 * both IPv4 and IPv6 destination addresses, plus padding (see RFC 2292)
 */
#if defined(HAVE_IN_PKTINFO) && defined(HAVE_IPI_SPEC_DST)
#define PKTINFO_BUF_SIZE max_int( CMSG_SPACE(sizeof(struct in6_pktinfo)), \
                                  CMSG_SPACE(sizeof(struct in_pktinfo)) )
#else
#define PKTINFO_BUF_SIZE max_int( CMSG_SPACE(sizeof(struct in6_pktinfo)), \
                                  CMSG_SPACE(sizeof(struct in_addr)) )
#endif

static socklen_t
link_socket_read_udp_posix_recvmsg(struct link_socket *sock,
                                   struct buffer *buf,
                                   struct link_socket_actual *from)
{
    struct iovec iov;
    uint8_t pktinfo_buf[PKTINFO_BUF_SIZE];
    struct msghdr mesg;
    socklen_t fromlen = sizeof(from->dest.addr);

    ASSERT(sock->sd >= 0);                      /* can't happen */

    iov.iov_base = BPTR(buf);
    iov.iov_len = buf_forward_capacity_total(buf);
    mesg.msg_iov = &iov;
    mesg.msg_iovlen = 1;
    mesg.msg_name = &from->dest.addr;
    mesg.msg_namelen = fromlen;
    mesg.msg_control = pktinfo_buf;
    mesg.msg_controllen = sizeof pktinfo_buf;
    buf->len = recvmsg(sock->sd, &mesg, 0);
    if (buf->len >= 0)
    {
        struct cmsghdr *cmsg;
        fromlen = mesg.msg_namelen;
        cmsg = CMSG_FIRSTHDR(&mesg);
        if (cmsg != NULL
            && CMSG_NXTHDR(&mesg, cmsg) == NULL
#if defined(HAVE_IN_PKTINFO) && defined(HAVE_IPI_SPEC_DST)
            && cmsg->cmsg_level == SOL_IP
            && cmsg->cmsg_type == IP_PKTINFO
            && cmsg->cmsg_len >= CMSG_LEN(sizeof(struct in_pktinfo)) )
#elif defined(IP_RECVDSTADDR)
            && cmsg->cmsg_level == IPPROTO_IP
            && cmsg->cmsg_type == IP_RECVDSTADDR
            && cmsg->cmsg_len >= CMSG_LEN(sizeof(struct in_addr)) )
#else  /* if defined(HAVE_IN_PKTINFO) && defined(HAVE_IPI_SPEC_DST) */
#error ENABLE_IP_PKTINFO is set without IP_PKTINFO xor IP_RECVDSTADDR (fix syshead.h)
#endif
        {
#if defined(HAVE_IN_PKTINFO) && defined(HAVE_IPI_SPEC_DST)
            struct in_pktinfo *pkti = (struct in_pktinfo *) CMSG_DATA(cmsg);
            from->pi.in4.ipi_ifindex = pkti->ipi_ifindex;
            from->pi.in4.ipi_spec_dst = pkti->ipi_spec_dst;
#elif defined(IP_RECVDSTADDR)
            from->pi.in4 = *(struct in_addr *) CMSG_DATA(cmsg);
#else  /* if defined(HAVE_IN_PKTINFO) && defined(HAVE_IPI_SPEC_DST) */
#error ENABLE_IP_PKTINFO is set without IP_PKTINFO xor IP_RECVDSTADDR (fix syshead.h)
#endif
        }
        else if (cmsg != NULL
                 && CMSG_NXTHDR(&mesg, cmsg) == NULL
                 && cmsg->cmsg_level == IPPROTO_IPV6
                 && cmsg->cmsg_type == IPV6_PKTINFO
                 && cmsg->cmsg_len >= CMSG_LEN(sizeof(struct in6_pktinfo)) )
        {
            struct in6_pktinfo *pkti6 = (struct in6_pktinfo *) CMSG_DATA(cmsg);
            from->pi.in6.ipi6_ifindex = pkti6->ipi6_ifindex;
            from->pi.in6.ipi6_addr = pkti6->ipi6_addr;
        }
        else if (cmsg != NULL)
        {
            msg(M_WARN, "CMSG received that cannot be parsed (cmsg_level=%d, cmsg_type=%d, cmsg=len=%d)", (int)cmsg->cmsg_level, (int)cmsg->cmsg_type, (int)cmsg->cmsg_len );
        }
    }

    return fromlen;
}
#endif /* if ENABLE_IP_PKTINFO */

int
link_socket_read_udp_posix(struct link_socket *sock,
                           struct buffer *buf,
                           struct link_socket_actual *from)
{
    socklen_t fromlen = sizeof(from->dest.addr);
    socklen_t expectedlen = af_addr_size(sock->info.af);
    addr_zero_host(&from->dest);

    ASSERT(sock->sd >= 0);                      /* can't happen */

#if ENABLE_IP_PKTINFO
    /* Both PROTO_UDPv4 and PROTO_UDPv6 */
    if (sock->info.proto == PROTO_UDP && sock->sockflags & SF_USE_IP_PKTINFO)
    {
        fromlen = link_socket_read_udp_posix_recvmsg(sock, buf, from);
    }
    else
#endif
    buf->len = recvfrom(sock->sd, BPTR(buf), buf_forward_capacity(buf), 0,
                        &from->dest.addr.sa, &fromlen);
    /* FIXME: won't do anything when sock->info.af == AF_UNSPEC */
    if (buf->len >= 0 && expectedlen && fromlen != expectedlen)
    {
        bad_address_length(fromlen, expectedlen);
    }
    return buf->len;
}

#endif /* ifndef _WIN32 */

/*
 * Socket Write Routines
 */

int
link_socket_write_tcp(struct link_socket *sock,
                      struct buffer *buf,
                      struct link_socket_actual *to)
{
    packet_size_type len = BLEN(buf);
    dmsg(D_STREAM_DEBUG, "STREAM: WRITE %d offset=%d", (int)len, buf->offset);
    ASSERT(len <= sock->stream_buf.maxlen);
    len = htonps(len);
    ASSERT(buf_write_prepend(buf, &len, sizeof(len)));
#ifdef _WIN32
    return link_socket_write_win32(sock, buf, to);
#else
    return link_socket_write_tcp_posix(sock, buf, to);
#endif
}

#if ENABLE_IP_PKTINFO

size_t
link_socket_write_udp_posix_sendmsg(struct link_socket *sock,
                                    struct buffer *buf,
                                    struct link_socket_actual *to)
{
    struct iovec iov;
    struct msghdr mesg;
    struct cmsghdr *cmsg;
    uint8_t pktinfo_buf[PKTINFO_BUF_SIZE];

    iov.iov_base = BPTR(buf);
    iov.iov_len = BLEN(buf);
    mesg.msg_iov = &iov;
    mesg.msg_iovlen = 1;
    switch (to->dest.addr.sa.sa_family)
    {
        case AF_INET:
        {
            mesg.msg_name = &to->dest.addr.sa;
            mesg.msg_namelen = sizeof(struct sockaddr_in);
            mesg.msg_control = pktinfo_buf;
            mesg.msg_flags = 0;
#if defined(HAVE_IN_PKTINFO) && defined(HAVE_IPI_SPEC_DST)
            mesg.msg_controllen = CMSG_SPACE(sizeof(struct in_pktinfo));
            cmsg = CMSG_FIRSTHDR(&mesg);
            cmsg->cmsg_len = CMSG_LEN(sizeof(struct in_pktinfo));
            cmsg->cmsg_level = SOL_IP;
            cmsg->cmsg_type = IP_PKTINFO;
            {
                struct in_pktinfo *pkti;
                pkti = (struct in_pktinfo *) CMSG_DATA(cmsg);
                pkti->ipi_ifindex = to->pi.in4.ipi_ifindex;
                pkti->ipi_spec_dst = to->pi.in4.ipi_spec_dst;
                pkti->ipi_addr.s_addr = 0;
            }
#elif defined(IP_RECVDSTADDR)
            ASSERT( CMSG_SPACE(sizeof(struct in_addr)) <= sizeof(pktinfo_buf) );
            mesg.msg_controllen = CMSG_SPACE(sizeof(struct in_addr));
            cmsg = CMSG_FIRSTHDR(&mesg);
            cmsg->cmsg_len = CMSG_LEN(sizeof(struct in_addr));
            cmsg->cmsg_level = IPPROTO_IP;
            cmsg->cmsg_type = IP_RECVDSTADDR;
            *(struct in_addr *) CMSG_DATA(cmsg) = to->pi.in4;
#else  /* if defined(HAVE_IN_PKTINFO) && defined(HAVE_IPI_SPEC_DST) */
#error ENABLE_IP_PKTINFO is set without IP_PKTINFO xor IP_RECVDSTADDR (fix syshead.h)
#endif /* if defined(HAVE_IN_PKTINFO) && defined(HAVE_IPI_SPEC_DST) */
            break;
        }

        case AF_INET6:
        {
            struct in6_pktinfo *pkti6;
            mesg.msg_name = &to->dest.addr.sa;
            mesg.msg_namelen = sizeof(struct sockaddr_in6);

            ASSERT( CMSG_SPACE(sizeof(struct in6_pktinfo)) <= sizeof(pktinfo_buf) );
            mesg.msg_control = pktinfo_buf;
            mesg.msg_controllen = CMSG_SPACE(sizeof(struct in6_pktinfo));
            mesg.msg_flags = 0;
            cmsg = CMSG_FIRSTHDR(&mesg);
            cmsg->cmsg_len = CMSG_LEN(sizeof(struct in6_pktinfo));
            cmsg->cmsg_level = IPPROTO_IPV6;
            cmsg->cmsg_type = IPV6_PKTINFO;

            pkti6 = (struct in6_pktinfo *) CMSG_DATA(cmsg);
            pkti6->ipi6_ifindex = to->pi.in6.ipi6_ifindex;
            pkti6->ipi6_addr = to->pi.in6.ipi6_addr;
            break;
        }

        default: ASSERT(0);
    }
    return sendmsg(sock->sd, &mesg, 0);
}

#endif /* if ENABLE_IP_PKTINFO */

/*
 * Win32 overlapped socket I/O functions.
 */

#ifdef _WIN32

static int
socket_get_last_error(const struct link_socket *sock)
{
    if (socket_is_dco_win(sock))
    {
        return GetLastError();
    }

    return WSAGetLastError();
}

int
socket_recv_queue(struct link_socket *sock, int maxsize)
{
    if (sock->reads.iostate == IOSTATE_INITIAL)
    {
        WSABUF wsabuf[1];
        int status;

        /* reset buf to its initial state */
        if (proto_is_udp(sock->info.proto))
        {
            sock->reads.buf = sock->reads.buf_init;
        }
        else if (proto_is_tcp(sock->info.proto))
        {
            stream_buf_get_next(&sock->stream_buf, &sock->reads.buf);
        }
        else
        {
            ASSERT(0);
        }

        /* Win32 docs say it's okay to allocate the wsabuf on the stack */
        wsabuf[0].buf = BSTR(&sock->reads.buf);
        wsabuf[0].len = maxsize ? maxsize : BLEN(&sock->reads.buf);

        /* check for buffer overflow */
        ASSERT(wsabuf[0].len <= BLEN(&sock->reads.buf));

        /* the overlapped read will signal this event on I/O completion */
        ASSERT(ResetEvent(sock->reads.overlapped.hEvent));
        sock->reads.flags = 0;

        if (socket_is_dco_win(sock))
        {
            status = ReadFile((HANDLE)sock->sd, wsabuf[0].buf, wsabuf[0].len,
                              &sock->reads.size, &sock->reads.overlapped);
            /* Readfile status is inverted from WSARecv */
            status = !status;
        }
        else if (proto_is_udp(sock->info.proto))
        {
            sock->reads.addr_defined = true;
            sock->reads.addrlen = sizeof(sock->reads.addr6);
            status = WSARecvFrom(
                sock->sd,
                wsabuf,
                1,
                &sock->reads.size,
                &sock->reads.flags,
                (struct sockaddr *) &sock->reads.addr,
                &sock->reads.addrlen,
                &sock->reads.overlapped,
                NULL);
        }
        else if (proto_is_tcp(sock->info.proto))
        {
            sock->reads.addr_defined = false;
            status = WSARecv(
                sock->sd,
                wsabuf,
                1,
                &sock->reads.size,
                &sock->reads.flags,
                &sock->reads.overlapped,
                NULL);
        }
        else
        {
            status = 0;
            ASSERT(0);
        }

        if (!status) /* operation completed immediately? */
        {
            /* FIXME: won't do anything when sock->info.af == AF_UNSPEC */
            int af_len = af_addr_size(sock->info.af);
            if (sock->reads.addr_defined && af_len && sock->reads.addrlen != af_len)
            {
                bad_address_length(sock->reads.addrlen, af_len);
            }
            sock->reads.iostate = IOSTATE_IMMEDIATE_RETURN;

            /* since we got an immediate return, we must signal the event object ourselves */
            ASSERT(SetEvent(sock->reads.overlapped.hEvent));
            sock->reads.status = 0;

            dmsg(D_WIN32_IO, "WIN32 I/O: Socket Receive immediate return [%d,%d]",
                 (int) wsabuf[0].len,
                 (int) sock->reads.size);
        }
        else
        {
            status = socket_get_last_error(sock);
            if (status == WSA_IO_PENDING) /* operation queued? */
            {
                sock->reads.iostate = IOSTATE_QUEUED;
                sock->reads.status = status;
                dmsg(D_WIN32_IO, "WIN32 I/O: Socket Receive queued [%d]",
                     (int) wsabuf[0].len);
            }
            else /* error occurred */
            {
                struct gc_arena gc = gc_new();
                ASSERT(SetEvent(sock->reads.overlapped.hEvent));
                sock->reads.iostate = IOSTATE_IMMEDIATE_RETURN;
                sock->reads.status = status;
                dmsg(D_WIN32_IO, "WIN32 I/O: Socket Receive error [%d]: %s",
                     (int) wsabuf[0].len,
                     strerror_win32(status, &gc));
                gc_free(&gc);
            }
        }
    }
    return sock->reads.iostate;
}

int
socket_send_queue(struct link_socket *sock, struct buffer *buf, const struct link_socket_actual *to)
{
    if (sock->writes.iostate == IOSTATE_INITIAL)
    {
        WSABUF wsabuf[1];
        int status;

        /* make a private copy of buf */
        sock->writes.buf = sock->writes.buf_init;
        sock->writes.buf.len = 0;
        ASSERT(buf_copy(&sock->writes.buf, buf));

        /* Win32 docs say it's okay to allocate the wsabuf on the stack */
        wsabuf[0].buf = BSTR(&sock->writes.buf);
        wsabuf[0].len = BLEN(&sock->writes.buf);

        /* the overlapped write will signal this event on I/O completion */
        ASSERT(ResetEvent(sock->writes.overlapped.hEvent));
        sock->writes.flags = 0;

        if (socket_is_dco_win(sock))
        {
            status = WriteFile((HANDLE)sock->sd, wsabuf[0].buf, wsabuf[0].len,
                               &sock->writes.size, &sock->writes.overlapped);

            /* WriteFile status is inverted from WSASendTo */
            status = !status;

        }
        else if (proto_is_udp(sock->info.proto))
        {
            /* set destination address for UDP writes */
            sock->writes.addr_defined = true;
            if (to->dest.addr.sa.sa_family == AF_INET6)
            {
                sock->writes.addr6 = to->dest.addr.in6;
                sock->writes.addrlen = sizeof(sock->writes.addr6);
            }
            else
            {
                sock->writes.addr = to->dest.addr.in4;
                sock->writes.addrlen = sizeof(sock->writes.addr);
            }

            status = WSASendTo(
                sock->sd,
                wsabuf,
                1,
                &sock->writes.size,
                sock->writes.flags,
                (struct sockaddr *) &sock->writes.addr,
                sock->writes.addrlen,
                &sock->writes.overlapped,
                NULL);
        }
        else if (proto_is_tcp(sock->info.proto))
        {
            /* destination address for TCP writes was established on connection initiation */
            sock->writes.addr_defined = false;

            status = WSASend(
                sock->sd,
                wsabuf,
                1,
                &sock->writes.size,
                sock->writes.flags,
                &sock->writes.overlapped,
                NULL);
        }
        else
        {
            status = 0;
            ASSERT(0);
        }

        if (!status) /* operation completed immediately? */
        {
            sock->writes.iostate = IOSTATE_IMMEDIATE_RETURN;

            /* since we got an immediate return, we must signal the event object ourselves */
            ASSERT(SetEvent(sock->writes.overlapped.hEvent));

            sock->writes.status = 0;

            dmsg(D_WIN32_IO, "WIN32 I/O: Socket Send immediate return [%d,%d]",
                 (int) wsabuf[0].len,
                 (int) sock->writes.size);
        }
        else
        {
            status = socket_get_last_error(sock);
            /* both status code have the identical value */
            if (status == WSA_IO_PENDING || status == ERROR_IO_PENDING) /* operation queued? */
            {
                sock->writes.iostate = IOSTATE_QUEUED;
                sock->writes.status = status;
                dmsg(D_WIN32_IO, "WIN32 I/O: Socket Send queued [%d]",
                     (int) wsabuf[0].len);
            }
            else /* error occurred */
            {
                struct gc_arena gc = gc_new();
                ASSERT(SetEvent(sock->writes.overlapped.hEvent));
                sock->writes.iostate = IOSTATE_IMMEDIATE_RETURN;
                sock->writes.status = status;

                dmsg(D_WIN32_IO, "WIN32 I/O: Socket Send error [%d]: %s",
                     (int) wsabuf[0].len,
                     strerror_win32(status, &gc));

                gc_free(&gc);
            }
        }
    }
    return sock->writes.iostate;
}

/* Returns the number of bytes successfully read */
int
sockethandle_finalize(sockethandle_t sh,
                      struct overlapped_io *io,
                      struct buffer *buf,
                      struct link_socket_actual *from)
{
    int ret = -1;
    BOOL status;

    switch (io->iostate)
    {
        case IOSTATE_QUEUED:
            status = SocketHandleGetOverlappedResult(sh, io);
            if (status)
            {
                /* successful return for a queued operation */
                if (buf)
                {
                    *buf = io->buf;
                }
                ret = io->size;
                io->iostate = IOSTATE_INITIAL;
                ASSERT(ResetEvent(io->overlapped.hEvent));

                dmsg(D_WIN32_IO, "WIN32 I/O: Completion success [%d]", ret);
            }
            else
            {
                /* error during a queued operation */
                ret = -1;
                if (SocketHandleGetLastError(sh) != ERROR_IO_INCOMPLETE)
                {
                    /* if no error (i.e. just not finished yet), then DON'T execute this code */
                    io->iostate = IOSTATE_INITIAL;
                    ASSERT(ResetEvent(io->overlapped.hEvent));
                    msg(D_WIN32_IO | M_ERRNO, "WIN32 I/O: Completion error");
                }
            }
            break;

        case IOSTATE_IMMEDIATE_RETURN:
            io->iostate = IOSTATE_INITIAL;
            ASSERT(ResetEvent(io->overlapped.hEvent));
            if (io->status)
            {
                /* error return for a non-queued operation */
                SocketHandleSetLastError(sh, io->status);
                ret = -1;
                msg(D_WIN32_IO | M_ERRNO, "WIN32 I/O: Completion non-queued error");
            }
            else
            {
                /* successful return for a non-queued operation */
                if (buf)
                {
                    *buf = io->buf;
                }
                ret = io->size;
                dmsg(D_WIN32_IO, "WIN32 I/O: Completion non-queued success [%d]", ret);
            }
            break;

        case IOSTATE_INITIAL: /* were we called without proper queueing? */
            SocketHandleSetInvalError(sh);
            ret = -1;
            dmsg(D_WIN32_IO, "WIN32 I/O: Completion BAD STATE");
            break;

        default:
            ASSERT(0);
    }

    /* return from address if requested */
    if (!sh.is_handle && from)
    {
        if (ret >= 0 && io->addr_defined)
        {
            /* TODO(jjo): streamline this mess */
            /* in this func we don't have relevant info about the PF_ of this
             * endpoint, as link_socket_actual will be zero for the 1st received packet
             *
             * Test for inets PF_ possible sizes
             */
            switch (io->addrlen)
            {
                case sizeof(struct sockaddr_in):
                case sizeof(struct sockaddr_in6):
                /* TODO(jjo): for some reason (?) I'm getting 24,28 for AF_INET6
                 * under _WIN32*/
                case sizeof(struct sockaddr_in6)-4:
                    break;

                default:
                    bad_address_length(io->addrlen, af_addr_size(io->addr.sin_family));
            }

            switch (io->addr.sin_family)
            {
                case AF_INET:
                    from->dest.addr.in4 = io->addr;
                    break;

                case AF_INET6:
                    from->dest.addr.in6 = io->addr6;
                    break;
            }
        }
        else
        {
            CLEAR(from->dest.addr);
        }
    }

    if (buf)
    {
        buf->len = ret;
    }
    return ret;
}

#endif /* _WIN32 */

/*
 * Socket event notification
 */

unsigned int
socket_set(struct link_socket *s,
           struct event_set *es,
           unsigned int rwflags,
           void *arg,
           unsigned int *persistent)
{
    if (s)
    {
        if ((rwflags & EVENT_READ) && !stream_buf_read_setup(s))
        {
            ASSERT(!persistent);
            rwflags &= ~EVENT_READ;
        }

#ifdef _WIN32
        if (rwflags & EVENT_READ)
        {
            socket_recv_queue(s, 0);
        }
#endif

        /* if persistent is defined, call event_ctl only if rwflags has changed since last call */
        if (!persistent || *persistent != rwflags)
        {
            event_ctl(es, socket_event_handle(s), rwflags, arg);
            if (persistent)
            {
                *persistent = rwflags;
            }
        }

        s->rwflags_debug = rwflags;
    }
    return rwflags;
}

void
sd_close(socket_descriptor_t *sd)
{
    if (sd && socket_defined(*sd))
    {
        openvpn_close_socket(*sd);
        *sd = SOCKET_UNDEFINED;
    }
}

#if UNIX_SOCK_SUPPORT

/*
 * code for unix domain sockets
 */

const char *
sockaddr_unix_name(const struct sockaddr_un *local, const char *null)
{
    if (local && local->sun_family == PF_UNIX)
    {
        return local->sun_path;
    }
    else
    {
        return null;
    }
}

socket_descriptor_t
create_socket_unix(void)
{
    socket_descriptor_t sd;

    if ((sd = socket(PF_UNIX, SOCK_STREAM, 0)) < 0)
    {
        msg(M_ERR, "Cannot create unix domain socket");
    }

    /* set socket file descriptor to not pass across execs, so that
     * scripts don't have access to it */
    set_cloexec(sd);

    return sd;
}

void
socket_bind_unix(socket_descriptor_t sd,
                 struct sockaddr_un *local,
                 const char *prefix)
{
    struct gc_arena gc = gc_new();
    const mode_t orig_umask = umask(0);

    if (bind(sd, (struct sockaddr *) local, sizeof(struct sockaddr_un)))
    {
        msg(M_FATAL | M_ERRNO,
            "%s: Socket bind[%d] failed on unix domain socket %s",
            prefix,
            (int)sd,
            sockaddr_unix_name(local, "NULL"));
    }

    umask(orig_umask);
    gc_free(&gc);
}

socket_descriptor_t
socket_accept_unix(socket_descriptor_t sd,
                   struct sockaddr_un *remote)
{
    socklen_t remote_len = sizeof(struct sockaddr_un);
    socket_descriptor_t ret;

    CLEAR(*remote);
    ret = accept(sd, (struct sockaddr *) remote, &remote_len);
    if (ret >= 0)
    {
        /* set socket file descriptor to not pass across execs, so that
         * scripts don't have access to it */
        set_cloexec(ret);
    }
    return ret;
}

int
socket_connect_unix(socket_descriptor_t sd,
                    struct sockaddr_un *remote)
{
    int status = connect(sd, (struct sockaddr *) remote, sizeof(struct sockaddr_un));
    if (status)
    {
        status = openvpn_errno();
    }
    return status;
}

void
sockaddr_unix_init(struct sockaddr_un *local, const char *path)
{
    local->sun_family = PF_UNIX;
    strncpynt(local->sun_path, path, sizeof(local->sun_path));
}

void
socket_delete_unix(const struct sockaddr_un *local)
{
    const char *name = sockaddr_unix_name(local, NULL);
    if (name && strlen(name))
    {
        unlink(name);
    }
}

bool
unix_socket_get_peer_uid_gid(const socket_descriptor_t sd, int *uid, int *gid)
{
#ifdef HAVE_GETPEEREID
    uid_t u;
    gid_t g;
    if (getpeereid(sd, &u, &g) == -1)
    {
        return false;
    }
    if (uid)
    {
        *uid = u;
    }
    if (gid)
    {
        *gid = g;
    }
    return true;
#elif defined(SO_PEERCRED)
    struct ucred peercred;
    socklen_t so_len = sizeof(peercred);
    if (getsockopt(sd, SOL_SOCKET, SO_PEERCRED, &peercred, &so_len) == -1)
    {
        return false;
    }
    if (uid)
    {
        *uid = peercred.uid;
    }
    if (gid)
    {
        *gid = peercred.gid;
    }
    return true;
#else  /* ifdef HAVE_GETPEEREID */
    return false;
#endif /* ifdef HAVE_GETPEEREID */
}

#endif /* if UNIX_SOCK_SUPPORT */
