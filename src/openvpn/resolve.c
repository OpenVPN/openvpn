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

#include "buffer.h"
#include "crypto.h"
#include "manage.h"
#include "openvpn.h"
#include "socket.h"
#include "socket_util.h"

#include "resolve.h"

/*
 * Convert sockflags/getaddr_flags into getaddr_flags
 */
unsigned int
sf2gaf(const unsigned int getaddr_flags, const unsigned int sockflags)
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

static int
get_addr_generic(sa_family_t af, unsigned int flags, const char *hostname, void *network,
                 unsigned int *netbits, int resolve_retry_seconds, struct signal_info *sig_info,
                 msglvl_t msglevel)
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
            msg(M_WARN, "Unsupported AF family passed to getaddrinfo for %s (%d)", hostname, af);
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
        msg(M_NONFATAL | M_ERRNO, "Can't allocate hostname buffer for getaddrinfo");
        goto out;
    }

    /* check if this hostname has a /bits suffix */
    sep = strchr(var_host, '/');
    if (sep)
    {
        bits = strtoul(sep + 1, &endp, 10);
        if ((*endp != '\0') || (bits > max_bits))
        {
            msg(msglevel, "IP prefix '%s': invalid '/bits' spec (%s)", hostname, sep + 1);
            goto out;
        }
        *sep = '\0';
    }

    ret = openvpn_getaddrinfo(flags & ~GETADDR_HOST_ORDER, var_host, NULL, resolve_retry_seconds,
                              sig_info, af, &ai);
    if ((ret == 0) && network)
    {
        struct in6_addr *ip6;
        in_addr_t *ip4;

        if (af != ai->ai_family)
        {
            msg(msglevel, "Can't parse %s as IPv%d address", var_host, (af == AF_INET) ? 4 : 6);
            ret = -1;
            goto out;
        }

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
                msg(M_WARN, "Unsupported AF family for %s (%d)", var_host, af);
                goto out;
        }
    }

    if (netbits)
    {
        *netbits = (unsigned int)bits;
    }

    /* restore '/' separator, if any */
    if (sep)
    {
        *sep = '/';
    }
out:
    if (ai)
    {
        freeaddrinfo(ai);
    }
    free(var_host);

    return ret;
}

in_addr_t
getaddr(unsigned int flags, const char *hostname, int resolve_retry_seconds, bool *succeeded,
        struct signal_info *sig_info)
{
    in_addr_t addr = { 0 };
    int status;

    status = get_addr_generic(AF_INET, flags, hostname, &addr, NULL, resolve_retry_seconds,
                              sig_info, M_WARN);
    if (status == 0)
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

in_addr_t
get_ip_addr(const char *ip_string, msglvl_t msglevel, bool *error)
{
    unsigned int flags = GETADDR_HOST_ORDER;
    bool succeeded = false;
    in_addr_t ret;

    if (msglevel & M_FATAL)
    {
        flags |= GETADDR_FATAL;
    }

    ret = getaddr(flags, ip_string, 0, &succeeded, NULL);
    if (!succeeded && error)
    {
        *error = true;
    }
    return ret;
}

bool
get_ipv6_addr(const char *hostname, struct in6_addr *network, unsigned int *netbits,
              msglvl_t msglevel)
{
    if (get_addr_generic(AF_INET6, GETADDR_RESOLVE, hostname, network, netbits, 0, NULL, msglevel)
        < 0)
    {
        return false;
    }

    return true; /* parsing OK, values set */
}

/*
 * get_cached_dns_entry return 0 on success and -1
 * otherwise. (like getaddrinfo)
 */
int
get_cached_dns_entry(struct cached_dns_entry *dns_cache, const char *hostname, const char *servname,
                     int ai_family, unsigned int resolve_flags, struct addrinfo **ai)
{
    struct cached_dns_entry *ph;
    unsigned int flags;

    /* Only use flags that are relevant for the structure */
    flags = resolve_flags & GETADDR_CACHE_MASK;

    for (ph = dns_cache; ph; ph = ph->next)
    {
        if (streqnull(ph->hostname, hostname) && streqnull(ph->servname, servname)
            && ph->ai_family == ai_family && ph->flags == flags)
        {
            *ai = ph->ai;
            return 0;
        }
    }
    return -1;
}


static int
do_preresolve_host(struct context *c, const char *hostname, const char *servname, const int af,
                   const unsigned int flags)
{
    struct addrinfo *ai;
    int status;

    if (get_cached_dns_entry(c->c1.dns_cache, hostname, servname, af, flags, &ai) == 0)
    {
        /* entry already cached, return success */
        return 0;
    }

    status = openvpn_getaddrinfo(flags, hostname, servname, c->options.resolve_retry_seconds, NULL,
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
    struct connection_list *l = c->options.connection_list;
    const unsigned int preresolve_flags = GETADDR_RESOLVE | GETADDR_UPDATE_MANAGEMENT_STATE
                                          | GETADDR_MENTION_RESOLVE_RETRY | GETADDR_FATAL;


    for (int i = 0; i < l->len; ++i)
    {
        int status;
        const char *remote;
        unsigned int flags = preresolve_flags;

        struct connection_entry *ce = l->array[i];

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
            status = do_preresolve_host(c, remote, ce->remote_port, ce->af, flags);
            if (status != 0)
            {
                goto err;
            }
        }

        /* Preresolve proxy */
        if (ce->http_proxy_options)
        {
            status = do_preresolve_host(c, ce->http_proxy_options->server,
                                        ce->http_proxy_options->port, ce->af, preresolve_flags);

            if (status != 0)
            {
                goto err;
            }
        }

        if (ce->socks_proxy_server)
        {
            status =
                do_preresolve_host(c, ce->socks_proxy_server, ce->socks_proxy_port, ce->af, flags);
            if (status != 0)
            {
                goto err;
            }
        }

        if (ce->bind_local)
        {
            flags |= GETADDR_PASSIVE;
            flags &= ~GETADDR_RANDOMIZE;

            for (int j = 0; j < ce->local_list->len; j++)
            {
                const struct local_entry *le = ce->local_list->array[j];

                if (!le->local)
                {
                    continue;
                }

                status = do_preresolve_host(c, le->local, le->port, ce->af, flags);
                if (status != 0)
                {
                    goto err;
                }
            }
        }
    }
    return;

err:
    throw_signal_soft(SIGHUP, "Preresolving failed");
}
