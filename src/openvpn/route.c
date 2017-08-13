/*
 *  OpenVPN -- An application to securely tunnel IP networks
 *             over a single TCP/UDP port, with support for SSL/TLS-based
 *             session authentication and key exchange,
 *             packet encryption, packet authentication, and
 *             packet compression.
 *
 *  Copyright (C) 2002-2017 OpenVPN Technologies, Inc. <sales@openvpn.net>
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

/*
 * Support routines for adding/deleting network routes.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#elif defined(_MSC_VER)
#include "config-msvc.h"
#endif

#include "syshead.h"

#include "common.h"
#include "error.h"
#include "route.h"
#include "misc.h"
#include "socket.h"
#include "manage.h"
#include "win32.h"
#include "options.h"
#include "platform.h"

#include "memdbg.h"

#if defined(TARGET_LINUX) || defined(TARGET_ANDROID)
#include <linux/rtnetlink.h>            /* RTM_GETROUTE etc. */
#endif

#ifdef _WIN32
#include "openvpn-msg.h"

#define METRIC_NOT_USED ((DWORD)-1)
static bool add_route_service(const struct route_ipv4 *, const struct tuntap *);

static bool del_route_service(const struct route_ipv4 *, const struct tuntap *);

static bool add_route_ipv6_service(const struct route_ipv6 *, const struct tuntap *);

static bool del_route_ipv6_service(const struct route_ipv6 *, const struct tuntap *);

#endif

static void delete_route(struct route_ipv4 *r, const struct tuntap *tt, unsigned int flags, const struct route_gateway_info *rgi, const struct env_set *es);

static void get_bypass_addresses(struct route_bypass *rb, const unsigned int flags);

#ifdef ENABLE_DEBUG

static void
print_bypass_addresses(const struct route_bypass *rb)
{
    struct gc_arena gc = gc_new();
    int i;
    for (i = 0; i < rb->n_bypass; ++i)
    {
        msg(D_ROUTE, "ROUTE: bypass_host_route[%d]=%s",
            i,
            print_in_addr_t(rb->bypass[i], 0, &gc));
    }
    gc_free(&gc);
}

#endif

static bool
add_bypass_address(struct route_bypass *rb, const in_addr_t a)
{
    int i;
    for (i = 0; i < rb->n_bypass; ++i)
    {
        if (a == rb->bypass[i]) /* avoid duplicates */
        {
            return true;
        }
    }
    if (rb->n_bypass < N_ROUTE_BYPASS)
    {
        rb->bypass[rb->n_bypass++] = a;
        return true;
    }
    else
    {
        return false;
    }
}

struct route_option_list *
new_route_option_list(struct gc_arena *a)
{
    struct route_option_list *ret;
    ALLOC_OBJ_CLEAR_GC(ret, struct route_option_list, a);
    ret->gc = a;
    return ret;
}

struct route_ipv6_option_list *
new_route_ipv6_option_list(struct gc_arena *a)
{
    struct route_ipv6_option_list *ret;
    ALLOC_OBJ_CLEAR_GC(ret, struct route_ipv6_option_list, a);
    ret->gc = a;
    return ret;
}

/*
 * NOTE: structs are cloned/copied shallow by design.
 * The routes list from src will stay intact since it is allocated using
 * the options->gc. The cloned/copied lists will share this common tail
 * to avoid copying the data around between pulls. Pulled routes use
 * the c2->gc so they get freed immediately after a reconnect.
 */
struct route_option_list *
clone_route_option_list(const struct route_option_list *src, struct gc_arena *a)
{
    struct route_option_list *ret;
    ALLOC_OBJ_GC(ret, struct route_option_list, a);
    *ret = *src;
    return ret;
}

struct route_ipv6_option_list *
clone_route_ipv6_option_list(const struct route_ipv6_option_list *src, struct gc_arena *a)
{
    struct route_ipv6_option_list *ret;
    ALLOC_OBJ_GC(ret, struct route_ipv6_option_list, a);
    *ret = *src;
    return ret;
}

void
copy_route_option_list(struct route_option_list *dest, const struct route_option_list *src, struct gc_arena *a)
{
    *dest = *src;
    dest->gc = a;
}

void
copy_route_ipv6_option_list(struct route_ipv6_option_list *dest,
                            const struct route_ipv6_option_list *src,
                            struct gc_arena *a)
{
    *dest = *src;
    dest->gc = a;
}

static const char *
route_string(const struct route_ipv4 *r, struct gc_arena *gc)
{
    struct buffer out = alloc_buf_gc(256, gc);
    buf_printf(&out, "ROUTE network %s netmask %s gateway %s",
               print_in_addr_t(r->network, 0, gc),
               print_in_addr_t(r->netmask, 0, gc),
               print_in_addr_t(r->gateway, 0, gc)
               );
    if (r->flags & RT_METRIC_DEFINED)
    {
        buf_printf(&out, " metric %d", r->metric);
    }
    return BSTR(&out);
}

static bool
is_route_parm_defined(const char *parm)
{
    if (!parm)
    {
        return false;
    }
    if (!strcmp(parm, "default"))
    {
        return false;
    }
    return true;
}

static void
setenv_route_addr(struct env_set *es, const char *key, const in_addr_t addr, int i)
{
    struct gc_arena gc = gc_new();
    struct buffer name = alloc_buf_gc(256, &gc);
    if (i >= 0)
    {
        buf_printf(&name, "route_%s_%d", key, i);
    }
    else
    {
        buf_printf(&name, "route_%s", key);
    }
    setenv_str(es, BSTR(&name), print_in_addr_t(addr, 0, &gc));
    gc_free(&gc);
}

static bool
get_special_addr(const struct route_list *rl,
                 const char *string,
                 in_addr_t *out,
                 bool *status)
{
    if (status)
    {
        *status = true;
    }
    if (!strcmp(string, "vpn_gateway"))
    {
        if (rl)
        {
            if (rl->spec.flags & RTSA_REMOTE_ENDPOINT)
            {
                *out = rl->spec.remote_endpoint;
            }
            else
            {
                msg(M_INFO, PACKAGE_NAME " ROUTE: vpn_gateway undefined");
                if (status)
                {
                    *status = false;
                }
            }
        }
        return true;
    }
    else if (!strcmp(string, "net_gateway"))
    {
        if (rl)
        {
            if (rl->rgi.flags & RGI_ADDR_DEFINED)
            {
                *out = rl->rgi.gateway.addr;
            }
            else
            {
                msg(M_INFO, PACKAGE_NAME " ROUTE: net_gateway undefined -- unable to get default gateway from system");
                if (status)
                {
                    *status = false;
                }
            }
        }
        return true;
    }
    else if (!strcmp(string, "remote_host"))
    {
        if (rl)
        {
            if (rl->spec.flags & RTSA_REMOTE_HOST)
            {
                *out = rl->spec.remote_host;
            }
            else
            {
                msg(M_INFO, PACKAGE_NAME " ROUTE: remote_host undefined");
                if (status)
                {
                    *status = false;
                }
            }
        }
        return true;
    }
    return false;
}

bool
is_special_addr(const char *addr_str)
{
    if (addr_str)
    {
        return get_special_addr(NULL, addr_str, NULL, NULL);
    }
    else
    {
        return false;
    }
}

static bool
init_route(struct route_ipv4 *r,
           struct addrinfo **network_list,
           const struct route_option *ro,
           const struct route_list *rl)
{
    const in_addr_t default_netmask = IPV4_NETMASK_HOST;
    bool status;
    int ret;
    struct in_addr special;

    CLEAR(*r);
    r->option = ro;

    /* network */

    if (!is_route_parm_defined(ro->network))
    {
        goto fail;
    }


    /* get_special_addr replaces specialaddr with a special ip addr
     * like gw. getaddrinfo is called to convert a a addrinfo struct */

    if (get_special_addr(rl, ro->network, (in_addr_t *) &special.s_addr, &status))
    {
        special.s_addr = htonl(special.s_addr);
        ret = openvpn_getaddrinfo(0, inet_ntoa(special), NULL, 0, NULL,
                                  AF_INET, network_list);
    }
    else
    {
        ret = openvpn_getaddrinfo(GETADDR_RESOLVE | GETADDR_WARN_ON_SIGNAL,
                                  ro->network, NULL, 0, NULL, AF_INET, network_list);
    }

    status = (ret == 0);

    if (!status)
    {
        goto fail;
    }

    /* netmask */

    if (is_route_parm_defined(ro->netmask))
    {
        r->netmask = getaddr(
            GETADDR_HOST_ORDER
            | GETADDR_WARN_ON_SIGNAL,
            ro->netmask,
            0,
            &status,
            NULL);
        if (!status)
        {
            goto fail;
        }
    }
    else
    {
        r->netmask = default_netmask;
    }

    /* gateway */

    if (is_route_parm_defined(ro->gateway))
    {
        if (!get_special_addr(rl, ro->gateway, &r->gateway, &status))
        {
            r->gateway = getaddr(
                GETADDR_RESOLVE
                | GETADDR_HOST_ORDER
                | GETADDR_WARN_ON_SIGNAL,
                ro->gateway,
                0,
                &status,
                NULL);
        }
        if (!status)
        {
            goto fail;
        }
    }
    else
    {
        if (rl->spec.flags & RTSA_REMOTE_ENDPOINT)
        {
            r->gateway = rl->spec.remote_endpoint;
        }
        else
        {
            msg(M_WARN, PACKAGE_NAME " ROUTE: " PACKAGE_NAME " needs a gateway parameter for a --route option and no default was specified by either --route-gateway or --ifconfig options");
            goto fail;
        }
    }

    /* metric */

    r->metric = 0;
    if (is_route_parm_defined(ro->metric))
    {
        r->metric = atoi(ro->metric);
        if (r->metric < 0)
        {
            msg(M_WARN, PACKAGE_NAME " ROUTE: route metric for network %s (%s) must be >= 0",
                ro->network,
                ro->metric);
            goto fail;
        }
        r->flags |= RT_METRIC_DEFINED;
    }
    else if (rl->spec.flags & RTSA_DEFAULT_METRIC)
    {
        r->metric = rl->spec.default_metric;
        r->flags |= RT_METRIC_DEFINED;
    }

    r->flags |= RT_DEFINED;

    return true;

fail:
    msg(M_WARN, PACKAGE_NAME " ROUTE: failed to parse/resolve route for host/network: %s",
        ro->network);
    return false;
}

static bool
init_route_ipv6(struct route_ipv6 *r6,
                const struct route_ipv6_option *r6o,
                const struct route_ipv6_list *rl6 )
{
    CLEAR(*r6);

    if (!get_ipv6_addr( r6o->prefix, &r6->network, &r6->netbits, M_WARN ))
    {
        goto fail;
    }

    /* gateway */
    if (is_route_parm_defined(r6o->gateway))
    {
        if (inet_pton( AF_INET6, r6o->gateway, &r6->gateway ) != 1)
        {
            msg( M_WARN, PACKAGE_NAME "ROUTE6: cannot parse gateway spec '%s'", r6o->gateway );
        }
    }
    else if (rl6->spec_flags & RTSA_REMOTE_ENDPOINT)
    {
        r6->gateway = rl6->remote_endpoint_ipv6;
    }
    else
    {
        msg(M_WARN, PACKAGE_NAME " ROUTE6: " PACKAGE_NAME " needs a gateway parameter for a --route-ipv6 option and no default was specified by either --route-ipv6-gateway or --ifconfig-ipv6 options");
        goto fail;
    }

    /* metric */

    r6->metric = -1;
    if (is_route_parm_defined(r6o->metric))
    {
        r6->metric = atoi(r6o->metric);
        if (r6->metric < 0)
        {
            msg(M_WARN, PACKAGE_NAME " ROUTE: route metric for network %s (%s) must be >= 0",
                r6o->prefix,
                r6o->metric);
            goto fail;
        }
        r6->flags |= RT_METRIC_DEFINED;
    }
    else if (rl6->spec_flags & RTSA_DEFAULT_METRIC)
    {
        r6->metric = rl6->default_metric;
        r6->flags |= RT_METRIC_DEFINED;
    }

    r6->flags |= RT_DEFINED;

    return true;

fail:
    msg(M_WARN, PACKAGE_NAME " ROUTE: failed to parse/resolve route for host/network: %s",
        r6o->prefix);
    return false;
}

void
add_route_to_option_list(struct route_option_list *l,
                         const char *network,
                         const char *netmask,
                         const char *gateway,
                         const char *metric)
{
    struct route_option *ro;
    ALLOC_OBJ_GC(ro, struct route_option, l->gc);
    ro->network = network;
    ro->netmask = netmask;
    ro->gateway = gateway;
    ro->metric = metric;
    ro->next = l->routes;
    l->routes = ro;

}

void
add_route_ipv6_to_option_list(struct route_ipv6_option_list *l,
                              const char *prefix,
                              const char *gateway,
                              const char *metric)
{
    struct route_ipv6_option *ro;
    ALLOC_OBJ_GC(ro, struct route_ipv6_option, l->gc);
    ro->prefix = prefix;
    ro->gateway = gateway;
    ro->metric = metric;
    ro->next = l->routes_ipv6;
    l->routes_ipv6 = ro;
}

void
clear_route_list(struct route_list *rl)
{
    gc_free(&rl->gc);
    CLEAR(*rl);
}

void
clear_route_ipv6_list(struct route_ipv6_list *rl6)
{
    gc_free(&rl6->gc);
    CLEAR(*rl6);
}

void
route_list_add_vpn_gateway(struct route_list *rl,
                           struct env_set *es,
                           const in_addr_t addr)
{
    ASSERT(rl);
    rl->spec.remote_endpoint = addr;
    rl->spec.flags |= RTSA_REMOTE_ENDPOINT;
    setenv_route_addr(es, "vpn_gateway", rl->spec.remote_endpoint, -1);
}

static void
add_block_local_item(struct route_list *rl,
                     const struct route_gateway_address *gateway,
                     in_addr_t target)
{
    const int rgi_needed = (RGI_ADDR_DEFINED|RGI_NETMASK_DEFINED);
    if ((rl->rgi.flags & rgi_needed) == rgi_needed
        && rl->rgi.gateway.netmask < 0xFFFFFFFF)
    {
        struct route_ipv4 *r1, *r2;
        unsigned int l2;

        ALLOC_OBJ_GC(r1, struct route_ipv4, &rl->gc);
        ALLOC_OBJ_GC(r2, struct route_ipv4, &rl->gc);

        /* split a route into two smaller blocking routes, and direct them to target */
        l2 = ((~gateway->netmask)+1)>>1;
        r1->flags = RT_DEFINED;
        r1->gateway = target;
        r1->network = gateway->addr & gateway->netmask;
        r1->netmask = ~(l2-1);
        r1->next = rl->routes;
        rl->routes = r1;

        *r2 = *r1;
        r2->network += l2;
        r2->next = rl->routes;
        rl->routes = r2;
    }
}

static void
add_block_local(struct route_list *rl)
{
    const int rgi_needed = (RGI_ADDR_DEFINED|RGI_NETMASK_DEFINED);
    if ((rl->flags & RG_BLOCK_LOCAL)
        && (rl->rgi.flags & rgi_needed) == rgi_needed
        && (rl->spec.flags & RTSA_REMOTE_ENDPOINT)
        && rl->spec.remote_host_local != TLA_LOCAL)
    {
        size_t i;

#ifndef TARGET_ANDROID
        /* add bypass for gateway addr */
        add_bypass_address(&rl->spec.bypass, rl->rgi.gateway.addr);
#endif

        /* block access to local subnet */
        add_block_local_item(rl, &rl->rgi.gateway, rl->spec.remote_endpoint);

        /* process additional subnets on gateway interface */
        for (i = 0; i < rl->rgi.n_addrs; ++i)
        {
            const struct route_gateway_address *gwa = &rl->rgi.addrs[i];
            /* omit the add/subnet in &rl->rgi which we processed above */
            if (!((rl->rgi.gateway.addr & rl->rgi.gateway.netmask) == (gwa->addr & gwa->netmask)
                  && rl->rgi.gateway.netmask == gwa->netmask))
            {
                add_block_local_item(rl, gwa, rl->spec.remote_endpoint);
            }
        }
    }
}

bool
init_route_list(struct route_list *rl,
                const struct route_option_list *opt,
                const char *remote_endpoint,
                int default_metric,
                in_addr_t remote_host,
                struct env_set *es)
{
    struct gc_arena gc = gc_new();
    bool ret = true;

    clear_route_list(rl);

    rl->flags = opt->flags;

    if (remote_host)
    {
        rl->spec.remote_host = remote_host;
        rl->spec.flags |= RTSA_REMOTE_HOST;
    }

    if (default_metric)
    {
        rl->spec.default_metric = default_metric;
        rl->spec.flags |= RTSA_DEFAULT_METRIC;
    }

    platform_get_default_gateway(&rl->rgi);
    if (rl->rgi.flags & RGI_ADDR_DEFINED)
    {
        setenv_route_addr(es, "net_gateway", rl->rgi.gateway.addr, -1);
#if defined(ENABLE_DEBUG) && !defined(ENABLE_SMALL)
        print_default_gateway(D_ROUTE, &rl->rgi, NULL);
#endif
    }
    else
    {
        dmsg(D_ROUTE, "ROUTE: default_gateway=UNDEF");
    }

    if (rl->spec.flags & RTSA_REMOTE_HOST)
    {
        rl->spec.remote_host_local = test_local_addr(remote_host, &rl->rgi);
    }

    if (is_route_parm_defined(remote_endpoint))
    {
        bool defined = false;
        rl->spec.remote_endpoint = getaddr(
            GETADDR_RESOLVE
            | GETADDR_HOST_ORDER
            | GETADDR_WARN_ON_SIGNAL,
            remote_endpoint,
            0,
            &defined,
            NULL);

        if (defined)
        {
            setenv_route_addr(es, "vpn_gateway", rl->spec.remote_endpoint, -1);
            rl->spec.flags |= RTSA_REMOTE_ENDPOINT;
        }
        else
        {
            msg(M_WARN, PACKAGE_NAME " ROUTE: failed to parse/resolve default gateway: %s",
                remote_endpoint);
            ret = false;
        }
    }

    if (rl->flags & RG_ENABLE)
    {
        add_block_local(rl);
        /* Disabled for fuzzing
        get_bypass_addresses(&rl->spec.bypass, rl->flags);
#ifdef ENABLE_DEBUG
        print_bypass_addresses(&rl->spec.bypass);
#endif
        */
    }

    /* parse the routes from opt to rl */
    {
        struct route_option *ro;
        for (ro = opt->routes; ro; ro = ro->next)
        {
            struct addrinfo *netlist = NULL;
            struct route_ipv4 r;

            if (!init_route(&r, &netlist, ro, rl))
            {
                ret = false;
            }
            else
            {
                struct addrinfo *curele;
                for (curele = netlist; curele; curele = curele->ai_next)
                {
                    struct route_ipv4 *new;
                    ALLOC_OBJ_GC(new, struct route_ipv4, &rl->gc);
                    *new = r;
                    new->network = ntohl(((struct sockaddr_in *)curele->ai_addr)->sin_addr.s_addr);
                    new->next = rl->routes;
                    rl->routes = new;
                }
            }
            if (netlist)
            {
                gc_addspecial(netlist, &gc_freeaddrinfo_callback, &gc);
            }
        }
    }

    gc_free(&gc);
    return ret;
}

/* check whether an IPv6 host address is covered by a given route_ipv6
 * (not the most beautiful implementation in the world, but portable and
 * "good enough")
 */
static bool
route_ipv6_match_host( const struct route_ipv6 *r6,
                       const struct in6_addr *host )
{
    unsigned int bits = r6->netbits;
    int i;
    unsigned int mask;

    if (bits>128)
    {
        return false;
    }

    for (i = 0; bits >= 8; i++, bits -= 8)
    {
        if (r6->network.s6_addr[i] != host->s6_addr[i])
        {
            return false;
        }
    }

    if (bits == 0)
    {
        return true;
    }

    mask = 0xff << (8-bits);

    if ( (r6->network.s6_addr[i] & mask) == (host->s6_addr[i] & mask ))
    {
        return true;
    }

    return false;
}

bool
init_route_ipv6_list(struct route_ipv6_list *rl6,
                     const struct route_ipv6_option_list *opt6,
                     const char *remote_endpoint,
                     int default_metric,
                     const struct in6_addr *remote_host_ipv6,
                     struct env_set *es)
{
    struct gc_arena gc = gc_new();
    bool ret = true;
    bool need_remote_ipv6_route;

    clear_route_ipv6_list(rl6);

    rl6->flags = opt6->flags;

    if (remote_host_ipv6)
    {
        rl6->remote_host_ipv6 = *remote_host_ipv6;
        rl6->spec_flags |= RTSA_REMOTE_HOST;
    }

    if (default_metric >= 0)
    {
        rl6->default_metric = default_metric;
        rl6->spec_flags |= RTSA_DEFAULT_METRIC;
    }

    msg(D_ROUTE, "GDG6: remote_host_ipv6=%s",
        remote_host_ipv6 ?  print_in6_addr(*remote_host_ipv6, 0, &gc) : "n/a" );

    /* Disabled for fuzzing
    get_default_gateway_ipv6(&rl6->rgi6, remote_host_ipv6);
    */
    if (rl6->rgi6.flags & RGI_ADDR_DEFINED)
    {
        setenv_str(es, "net_gateway_ipv6", print_in6_addr(rl6->rgi6.gateway.addr_ipv6, 0, &gc));
#if defined(ENABLE_DEBUG) && !defined(ENABLE_SMALL)
        print_default_gateway(D_ROUTE, NULL, &rl6->rgi6);
#endif
    }
    else
    {
        dmsg(D_ROUTE, "ROUTE6: default_gateway=UNDEF");
    }

    if (is_route_parm_defined( remote_endpoint ))
    {
        if (inet_pton( AF_INET6, remote_endpoint,
                       &rl6->remote_endpoint_ipv6) == 1)
        {
            rl6->spec_flags |= RTSA_REMOTE_ENDPOINT;
        }
        else
        {
            msg(M_WARN, PACKAGE_NAME " ROUTE: failed to parse/resolve VPN endpoint: %s", remote_endpoint);
            ret = false;
        }
    }

    /* parse the routes from opt6 to rl6
     * discovering potential overlaps with remote_host_ipv6 in the process
     */
    need_remote_ipv6_route = false;

    {
        struct route_ipv6_option *ro6;
        for (ro6 = opt6->routes_ipv6; ro6; ro6 = ro6->next)
        {
            struct route_ipv6 *r6;
            ALLOC_OBJ_GC(r6, struct route_ipv6, &rl6->gc);
            if (!init_route_ipv6(r6, ro6, rl6))
            {
                ret = false;
            }
            else
            {
                r6->next = rl6->routes_ipv6;
                rl6->routes_ipv6 = r6;

#ifndef TARGET_ANDROID
                /* On Android the VPNService protect function call will take of
                 * avoiding routing loops, so ignore this part and let
                 * need_remote_ipv6_route always evaluate to false
                 */
                if (remote_host_ipv6
                    && route_ipv6_match_host( r6, remote_host_ipv6 ) )
                {
                    need_remote_ipv6_route = true;
                    msg(D_ROUTE, "ROUTE6: %s/%d overlaps IPv6 remote %s, adding host route to VPN endpoint",
                        print_in6_addr(r6->network, 0, &gc), r6->netbits,
                        print_in6_addr(*remote_host_ipv6, 0, &gc));
                }
#endif
            }
        }
    }

    /* add VPN server host route if needed */
    if (need_remote_ipv6_route)
    {
        if ( (rl6->rgi6.flags & (RGI_ADDR_DEFINED|RGI_IFACE_DEFINED) ) ==
             (RGI_ADDR_DEFINED|RGI_IFACE_DEFINED) )
        {
            struct route_ipv6 *r6;
            ALLOC_OBJ_CLEAR_GC(r6, struct route_ipv6, &rl6->gc);

            r6->network = *remote_host_ipv6;
            r6->netbits = 128;
            if (!(rl6->rgi6.flags & RGI_ON_LINK) )
            {
                r6->gateway = rl6->rgi6.gateway.addr_ipv6;
            }
            r6->metric = 1;
#ifdef _WIN32
            r6->adapter_index = rl6->rgi6.adapter_index;
#else
            r6->iface = rl6->rgi6.iface;
#endif
            r6->flags = RT_DEFINED | RT_METRIC_DEFINED;

            r6->next = rl6->routes_ipv6;
            rl6->routes_ipv6 = r6;
        }
        else
        {
            msg(M_WARN, "ROUTE6: IPv6 route overlaps with IPv6 remote address, but could not determine IPv6 gateway address + interface, expect failure\n" );
        }
    }

    gc_free(&gc);
    return ret;
}

static void
add_route3(in_addr_t network,
           in_addr_t netmask,
           in_addr_t gateway,
           const struct tuntap *tt,
           unsigned int flags,
           const struct route_gateway_info *rgi,
           const struct env_set *es)
{
    struct route_ipv4 r;
    CLEAR(r);
    r.flags = RT_DEFINED;
    r.network = network;
    r.netmask = netmask;
    r.gateway = gateway;
    add_route(&r, tt, flags, rgi, es);
}

static void
del_route3(in_addr_t network,
           in_addr_t netmask,
           in_addr_t gateway,
           const struct tuntap *tt,
           unsigned int flags,
           const struct route_gateway_info *rgi,
           const struct env_set *es)
{
    struct route_ipv4 r;
    CLEAR(r);
    r.flags = RT_DEFINED|RT_ADDED;
    r.network = network;
    r.netmask = netmask;
    r.gateway = gateway;
    delete_route(&r, tt, flags, rgi, es);
}

static void
add_bypass_routes(struct route_bypass *rb,
                  in_addr_t gateway,
                  const struct tuntap *tt,
                  unsigned int flags,
                  const struct route_gateway_info *rgi,
                  const struct env_set *es)
{
    int i;
    for (i = 0; i < rb->n_bypass; ++i)
    {
        if (rb->bypass[i])
        {
            add_route3(rb->bypass[i],
                       IPV4_NETMASK_HOST,
                       gateway,
                       tt,
                       flags | ROUTE_REF_GW,
                       rgi,
                       es);
        }
    }
}

static void
del_bypass_routes(struct route_bypass *rb,
                  in_addr_t gateway,
                  const struct tuntap *tt,
                  unsigned int flags,
                  const struct route_gateway_info *rgi,
                  const struct env_set *es)
{
    int i;
    for (i = 0; i < rb->n_bypass; ++i)
    {
        if (rb->bypass[i])
        {
            del_route3(rb->bypass[i],
                       IPV4_NETMASK_HOST,
                       gateway,
                       tt,
                       flags | ROUTE_REF_GW,
                       rgi,
                       es);
        }
    }
}

static void
redirect_default_route_to_vpn(struct route_list *rl, const struct tuntap *tt, unsigned int flags, const struct env_set *es)
{
    const char err[] = "NOTE: unable to redirect default gateway --";

    if (rl && rl->flags & RG_ENABLE)
    {
        bool local = rl->flags & RG_LOCAL;

        if (!(rl->spec.flags & RTSA_REMOTE_ENDPOINT) && (rl->flags & RG_REROUTE_GW))
        {
            msg(M_WARN, "%s VPN gateway parameter (--route-gateway or --ifconfig) is missing", err);
        }
        /*
         * check if a default route is defined, unless:
         * - we are connecting to a remote host in our network
         * - we are connecting to a non-IPv4 remote host (i.e. we use IPv6)
         */
        else if (!(rl->rgi.flags & RGI_ADDR_DEFINED) && !local
                 && (rl->spec.remote_host != IPV4_INVALID_ADDR))
        {
            msg(M_WARN, "%s Cannot read current default gateway from system", err);
        }
        else if (!(rl->spec.flags & RTSA_REMOTE_HOST))
        {
            msg(M_WARN, "%s Cannot obtain current remote host address", err);
        }
        else
        {
#ifndef TARGET_ANDROID
            if (rl->flags & RG_AUTO_LOCAL)
            {
                const int tla = rl->spec.remote_host_local;
                if (tla == TLA_NONLOCAL)
                {
                    dmsg(D_ROUTE, "ROUTE remote_host is NOT LOCAL");
                    local = false;
                }
                else if (tla == TLA_LOCAL)
                {
                    dmsg(D_ROUTE, "ROUTE remote_host is LOCAL");
                    local = true;
                }
            }
            if (!local)
            {
                /* route remote host to original default gateway */
                /* if remote_host is not ipv4 (ie: ipv6), just skip
                 * adding this special /32 route */
                if (rl->spec.remote_host != IPV4_INVALID_ADDR)
                {
                    add_route3(rl->spec.remote_host,
                               IPV4_NETMASK_HOST,
                               rl->rgi.gateway.addr,
                               tt,
                               flags | ROUTE_REF_GW,
                               &rl->rgi,
                               es);
                    rl->iflags |= RL_DID_LOCAL;
                }
                else
                {
                    dmsg(D_ROUTE, "ROUTE remote_host protocol differs from tunneled");
                }
            }
#endif /* ifndef TARGET_ANDROID */

            /* route DHCP/DNS server traffic through original default gateway */
            add_bypass_routes(&rl->spec.bypass, rl->rgi.gateway.addr, tt, flags, &rl->rgi, es);

            if (rl->flags & RG_REROUTE_GW)
            {
                if (rl->flags & RG_DEF1)
                {
                    /* add new default route (1st component) */
                    add_route3(0x00000000,
                               0x80000000,
                               rl->spec.remote_endpoint,
                               tt,
                               flags,
                               &rl->rgi,
                               es);

                    /* add new default route (2nd component) */
                    add_route3(0x80000000,
                               0x80000000,
                               rl->spec.remote_endpoint,
                               tt,
                               flags,
                               &rl->rgi,
                               es);
                }
                else
                {
                    /* don't try to remove the def route if it does not exist */
                    if (rl->rgi.flags & RGI_ADDR_DEFINED)
                    {
                        /* delete default route */
                        del_route3(0, 0, rl->rgi.gateway.addr, tt,
                                   flags | ROUTE_REF_GW, &rl->rgi, es);
                    }

                    /* add new default route */
                    add_route3(0,
                               0,
                               rl->spec.remote_endpoint,
                               tt,
                               flags,
                               &rl->rgi,
                               es);
                }
            }

            /* set a flag so we can undo later */
            rl->iflags |= RL_DID_REDIRECT_DEFAULT_GATEWAY;
        }
    }
}

static void
undo_redirect_default_route_to_vpn(struct route_list *rl, const struct tuntap *tt, unsigned int flags, const struct env_set *es)
{
    if (rl && rl->iflags & RL_DID_REDIRECT_DEFAULT_GATEWAY)
    {
        /* delete remote host route */
        if (rl->iflags & RL_DID_LOCAL)
        {
            del_route3(rl->spec.remote_host,
                       IPV4_NETMASK_HOST,
                       rl->rgi.gateway.addr,
                       tt,
                       flags | ROUTE_REF_GW,
                       &rl->rgi,
                       es);
            rl->iflags &= ~RL_DID_LOCAL;
        }

        /* delete special DHCP/DNS bypass route */
        del_bypass_routes(&rl->spec.bypass, rl->rgi.gateway.addr, tt, flags, &rl->rgi, es);

        if (rl->flags & RG_REROUTE_GW)
        {
            if (rl->flags & RG_DEF1)
            {
                /* delete default route (1st component) */
                del_route3(0x00000000,
                           0x80000000,
                           rl->spec.remote_endpoint,
                           tt,
                           flags,
                           &rl->rgi,
                           es);

                /* delete default route (2nd component) */
                del_route3(0x80000000,
                           0x80000000,
                           rl->spec.remote_endpoint,
                           tt,
                           flags,
                           &rl->rgi,
                           es);
            }
            else
            {
                /* delete default route */
                del_route3(0,
                           0,
                           rl->spec.remote_endpoint,
                           tt,
                           flags,
                           &rl->rgi,
                           es);
                /* restore original default route if there was any */
                if (rl->rgi.flags & RGI_ADDR_DEFINED)
                {
                    add_route3(0, 0, rl->rgi.gateway.addr, tt,
                               flags | ROUTE_REF_GW, &rl->rgi, es);
                }
            }
        }

        rl->iflags &= ~RL_DID_REDIRECT_DEFAULT_GATEWAY;
    }
}

void
add_routes(struct route_list *rl, struct route_ipv6_list *rl6, const struct tuntap *tt, unsigned int flags, const struct env_set *es)
{
    redirect_default_route_to_vpn(rl, tt, flags, es);
    if (rl && !(rl->iflags & RL_ROUTES_ADDED) )
    {
        struct route_ipv4 *r;

#ifdef ENABLE_MANAGEMENT
        if (management && rl->routes)
        {
            management_set_state(management,
                                 OPENVPN_STATE_ADD_ROUTES,
                                 NULL,
                                 NULL,
                                 NULL,
                                 NULL,
                                 NULL);
        }
#endif

        for (r = rl->routes; r; r = r->next)
        {
            check_subnet_conflict(r->network, r->netmask, "route");
            if (flags & ROUTE_DELETE_FIRST)
            {
                delete_route(r, tt, flags, &rl->rgi, es);
            }
            add_route(r, tt, flags, &rl->rgi, es);
        }
        rl->iflags |= RL_ROUTES_ADDED;
    }
    if (rl6 && !(rl6->iflags & RL_ROUTES_ADDED) )
    {
        struct route_ipv6 *r;

        if (!tt->did_ifconfig_ipv6_setup)
        {
            msg(M_INFO, "WARNING: OpenVPN was configured to add an IPv6 "
                "route over %s. However, no IPv6 has been configured for "
                "this interface, therefore the route installation may "
                "fail or may not work as expected.", tt->actual_name);
        }

        for (r = rl6->routes_ipv6; r; r = r->next)
        {
            if (flags & ROUTE_DELETE_FIRST)
            {
                delete_route_ipv6(r, tt, flags, es);
            }
            add_route_ipv6(r, tt, flags, es);
        }
        rl6->iflags |= RL_ROUTES_ADDED;
    }
}

void
delete_routes(struct route_list *rl, struct route_ipv6_list *rl6,
              const struct tuntap *tt, unsigned int flags, const struct env_set *es)
{
    if (rl && rl->iflags & RL_ROUTES_ADDED)
    {
        struct route_ipv4 *r;
        for (r = rl->routes; r; r = r->next)
        {
            delete_route(r, tt, flags, &rl->rgi, es);
        }
        rl->iflags &= ~RL_ROUTES_ADDED;
    }

    undo_redirect_default_route_to_vpn(rl, tt, flags, es);

    if (rl)
    {
        clear_route_list(rl);
    }

    if (rl6 && (rl6->iflags & RL_ROUTES_ADDED) )
    {
        struct route_ipv6 *r6;
        for (r6 = rl6->routes_ipv6; r6; r6 = r6->next)
        {
            delete_route_ipv6(r6, tt, flags, es);
        }
        rl6->iflags &= ~RL_ROUTES_ADDED;
    }

    if (rl6)
    {
        clear_route_ipv6_list(rl6);
    }
}

#ifndef ENABLE_SMALL

static const char *
show_opt(const char *option)
{
    if (!option)
    {
        return "default (not set)";
    }
    else
    {
        return option;
    }
}

static void
print_route_option(const struct route_option *ro, int level)
{
    msg(level, "  route %s/%s/%s/%s",
        show_opt(ro->network),
        show_opt(ro->netmask),
        show_opt(ro->gateway),
        show_opt(ro->metric));
}

void
print_route_options(const struct route_option_list *rol,
                    int level)
{
    struct route_option *ro;
    if (rol->flags & RG_ENABLE)
    {
        msg(level, "  [redirect_default_gateway local=%d]",
            (rol->flags & RG_LOCAL) != 0);
    }
    for (ro = rol->routes; ro; ro = ro->next)
    {
        print_route_option(ro, level);
    }
}

void
print_default_gateway(const int msglevel,
                      const struct route_gateway_info *rgi,
                      const struct route_ipv6_gateway_info *rgi6)
{
    struct gc_arena gc = gc_new();
    if (rgi && (rgi->flags & RGI_ADDR_DEFINED))
    {
        struct buffer out = alloc_buf_gc(256, &gc);
        buf_printf(&out, "ROUTE_GATEWAY");
        if (rgi->flags & RGI_ON_LINK)
        {
            buf_printf(&out, " ON_LINK");
        }
        else
        {
            buf_printf(&out, " %s", print_in_addr_t(rgi->gateway.addr, 0, &gc));
        }
        if (rgi->flags & RGI_NETMASK_DEFINED)
        {
            buf_printf(&out, "/%s", print_in_addr_t(rgi->gateway.netmask, 0, &gc));
        }
#ifdef _WIN32
        if (rgi->flags & RGI_IFACE_DEFINED)
        {
            buf_printf(&out, " I=%u", (unsigned int)rgi->adapter_index);
        }
#else
        if (rgi->flags & RGI_IFACE_DEFINED)
        {
            buf_printf(&out, " IFACE=%s", rgi->iface);
        }
#endif
        if (rgi->flags & RGI_HWADDR_DEFINED)
        {
            buf_printf(&out, " HWADDR=%s", format_hex_ex(rgi->hwaddr, 6, 0, 1, ":", &gc));
        }
        msg(msglevel, "%s", BSTR(&out));
    }

    if (rgi6 && (rgi6->flags & RGI_ADDR_DEFINED))
    {
        struct buffer out = alloc_buf_gc(256, &gc);
        buf_printf(&out, "ROUTE6_GATEWAY");
        buf_printf(&out, " %s", print_in6_addr(rgi6->gateway.addr_ipv6, 0, &gc));
        if (rgi6->flags & RGI_ON_LINK)
        {
            buf_printf(&out, " ON_LINK");
        }
        if (rgi6->flags & RGI_NETMASK_DEFINED)
        {
            buf_printf(&out, "/%d", rgi6->gateway.netbits_ipv6);
        }
#ifdef _WIN32
        if (rgi6->flags & RGI_IFACE_DEFINED)
        {
            buf_printf(&out, " I=%u", (unsigned int)rgi6->adapter_index);
        }
#else
        if (rgi6->flags & RGI_IFACE_DEFINED)
        {
            buf_printf(&out, " IFACE=%s", rgi6->iface);
        }
#endif
        if (rgi6->flags & RGI_HWADDR_DEFINED)
        {
            buf_printf(&out, " HWADDR=%s", format_hex_ex(rgi6->hwaddr, 6, 0, 1, ":", &gc));
        }
        msg(msglevel, "%s", BSTR(&out));
    }
    gc_free(&gc);
}

#endif /* ifndef ENABLE_SMALL */

static void
print_route(const struct route_ipv4 *r, int level)
{
    struct gc_arena gc = gc_new();
    if (r->flags & RT_DEFINED)
    {
        msg(level, "%s", route_string(r, &gc));
    }
    gc_free(&gc);
}

void
print_routes(const struct route_list *rl, int level)
{
    struct route_ipv4 *r;
    for (r = rl->routes; r; r = r->next)
    {
        print_route(r, level);
    }
}

static void
setenv_route(struct env_set *es, const struct route_ipv4 *r, int i)
{
    struct gc_arena gc = gc_new();
    if (r->flags & RT_DEFINED)
    {
        setenv_route_addr(es, "network", r->network, i);
        setenv_route_addr(es, "netmask", r->netmask, i);
        setenv_route_addr(es, "gateway", r->gateway, i);

        if (r->flags & RT_METRIC_DEFINED)
        {
            struct buffer name = alloc_buf_gc(256, &gc);
            buf_printf(&name, "route_metric_%d", i);
            setenv_int(es, BSTR(&name), r->metric);
        }
    }
    gc_free(&gc);
}

void
setenv_routes(struct env_set *es, const struct route_list *rl)
{
    int i = 1;
    struct route_ipv4 *r;
    for (r = rl->routes; r; r = r->next)
    {
        setenv_route(es, r, i++);
    }
}

static void
setenv_route_ipv6(struct env_set *es, const struct route_ipv6 *r6, int i)
{
    struct gc_arena gc = gc_new();
    if (r6->flags & RT_DEFINED)
    {
        struct buffer name1 = alloc_buf_gc( 256, &gc );
        struct buffer val = alloc_buf_gc( 256, &gc );
        struct buffer name2 = alloc_buf_gc( 256, &gc );

        buf_printf( &name1, "route_ipv6_network_%d", i );
        buf_printf( &val, "%s/%d", print_in6_addr( r6->network, 0, &gc ),
                    r6->netbits );
        setenv_str( es, BSTR(&name1), BSTR(&val) );

        buf_printf( &name2, "route_ipv6_gateway_%d", i );
        setenv_str( es, BSTR(&name2), print_in6_addr( r6->gateway, 0, &gc ));
    }
    gc_free(&gc);
}
void
setenv_routes_ipv6(struct env_set *es, const struct route_ipv6_list *rl6)
{
    int i = 1;
    struct route_ipv6 *r6;
    for (r6 = rl6->routes_ipv6; r6; r6 = r6->next)
    {
        setenv_route_ipv6(es, r6, i++);
    }
}

/*
 * local_route() determines whether the gateway of a provided host
 * route is on the same interface that owns the default gateway.
 * It uses the data structure
 * returned by get_default_gateway() (struct route_gateway_info)
 * to determine this.  If the route is local, LR_MATCH is returned.
 * When adding routes into the kernel, if LR_MATCH is defined for
 * a given route, the route should explicitly reference the default
 * gateway interface as the route destination.  For example, here
 * is an example on Linux that uses LR_MATCH:
 *
 *   route add -net 10.10.0.1 netmask 255.255.255.255 dev eth0
 *
 * This capability is needed by the "default-gateway block-local"
 * directive, to allow client access to the local subnet to be
 * blocked but still allow access to the local default gateway.
 */

/* local_route() return values */
#define LR_NOMATCH 0 /* route is not local */
#define LR_MATCH   1 /* route is local */
#define LR_ERROR   2 /* caller should abort adding route */

static int
local_route(in_addr_t network,
            in_addr_t netmask,
            in_addr_t gateway,
            const struct route_gateway_info *rgi)
{
    /* set LR_MATCH on local host routes */
    const int rgi_needed = (RGI_ADDR_DEFINED|RGI_NETMASK_DEFINED|RGI_IFACE_DEFINED);
    if (rgi
        && (rgi->flags & rgi_needed) == rgi_needed
        && gateway == rgi->gateway.addr
        && netmask == 0xFFFFFFFF)
    {
        if (((network ^  rgi->gateway.addr) & rgi->gateway.netmask) == 0)
        {
            return LR_MATCH;
        }
        else
        {
            /* examine additional subnets on gateway interface */
            size_t i;
            for (i = 0; i < rgi->n_addrs; ++i)
            {
                const struct route_gateway_address *gwa = &rgi->addrs[i];
                if (((network ^ gwa->addr) & gwa->netmask) == 0)
                {
                    return LR_MATCH;
                }
            }
        }
    }
    return LR_NOMATCH;
}

/* Return true if the "on-link" form of the route should be used.  This is when the gateway for a
 * a route is specified as an interface rather than an address. */
static inline bool
is_on_link(const int is_local_route, const unsigned int flags, const struct route_gateway_info *rgi)
{
    return rgi && (is_local_route == LR_MATCH || ((flags & ROUTE_REF_GW) && (rgi->flags & RGI_ON_LINK)));
}

void
add_route(struct route_ipv4 *r,
          const struct tuntap *tt,
          unsigned int flags,
          const struct route_gateway_info *rgi,  /* may be NULL */
          const struct env_set *es)
{
    struct gc_arena gc;
    struct argv argv = argv_new();
    const char *network;
    const char *netmask;
    const char *gateway;
    bool status = false;
    int is_local_route;

    if (!(r->flags & RT_DEFINED))
    {
        return;
    }

    gc_init(&gc);

    network = print_in_addr_t(r->network, 0, &gc);
    netmask = print_in_addr_t(r->netmask, 0, &gc);
    gateway = print_in_addr_t(r->gateway, 0, &gc);

    is_local_route = local_route(r->network, r->netmask, r->gateway, rgi);
    if (is_local_route == LR_ERROR)
    {
        goto done;
    }

#if defined(TARGET_LINUX)
#ifdef ENABLE_IPROUTE
    argv_printf(&argv, "%s route add %s/%d",
                iproute_path,
                network,
                netmask_to_netbits2(r->netmask));

    if (r->flags & RT_METRIC_DEFINED)
    {
        argv_printf_cat(&argv, "metric %d", r->metric);
    }

    if (is_on_link(is_local_route, flags, rgi))
    {
        argv_printf_cat(&argv, "dev %s", rgi->iface);
    }
    else
    {
        argv_printf_cat(&argv, "via %s", gateway);
    }
#else  /* ifdef ENABLE_IPROUTE */
    argv_printf(&argv, "%s add -net %s netmask %s",
                ROUTE_PATH,
                network,
                netmask);
    if (r->flags & RT_METRIC_DEFINED)
    {
        argv_printf_cat(&argv, "metric %d", r->metric);
    }
    if (is_on_link(is_local_route, flags, rgi))
    {
        argv_printf_cat(&argv, "dev %s", rgi->iface);
    }
    else
    {
        argv_printf_cat(&argv, "gw %s", gateway);
    }

#endif  /*ENABLE_IPROUTE*/
    argv_msg(D_ROUTE, &argv);
    status = openvpn_execve_check(&argv, es, 0, "ERROR: Linux route add command failed");

#elif defined (TARGET_ANDROID)
    struct buffer out = alloc_buf_gc(128, &gc);

    if (rgi)
    {
        buf_printf(&out, "%s %s %s dev %s", network, netmask, gateway, rgi->iface);
    }
    else
    {
        buf_printf(&out, "%s %s %s", network, netmask, gateway);
    }
    management_android_control(management, "ROUTE", buf_bptr(&out));

#elif defined (_WIN32)
    {
        DWORD ai = TUN_ADAPTER_INDEX_INVALID;
        argv_printf(&argv, "%s%sc ADD %s MASK %s %s",
                    get_win_sys_path(),
                    WIN_ROUTE_PATH_SUFFIX,
                    network,
                    netmask,
                    gateway);
        if (r->flags & RT_METRIC_DEFINED)
        {
            argv_printf_cat(&argv, "METRIC %d", r->metric);
        }
        if (is_on_link(is_local_route, flags, rgi))
        {
            ai = rgi->adapter_index;
            argv_printf_cat(&argv, "IF %u", (unsigned int)ai);
        }

        argv_msg(D_ROUTE, &argv);

        if ((flags & ROUTE_METHOD_MASK) == ROUTE_METHOD_SERVICE)
        {
            status = add_route_service(r, tt);
            msg(D_ROUTE, "Route addition via service %s", status ? "succeeded" : "failed");
        }
        else if ((flags & ROUTE_METHOD_MASK) == ROUTE_METHOD_IPAPI)
        {
            status = add_route_ipapi(r, tt, ai);
            msg(D_ROUTE, "Route addition via IPAPI %s", status ? "succeeded" : "failed");
        }
        else if ((flags & ROUTE_METHOD_MASK) == ROUTE_METHOD_EXE)
        {
            netcmd_semaphore_lock();
            status = openvpn_execve_check(&argv, es, 0, "ERROR: Windows route add command failed");
            netcmd_semaphore_release();
        }
        else if ((flags & ROUTE_METHOD_MASK) == ROUTE_METHOD_ADAPTIVE)
        {
            status = add_route_ipapi(r, tt, ai);
            msg(D_ROUTE, "Route addition via IPAPI %s [adaptive]", status ? "succeeded" : "failed");
            if (!status)
            {
                msg(D_ROUTE, "Route addition fallback to route.exe");
                netcmd_semaphore_lock();
                status = openvpn_execve_check(&argv, es, 0, "ERROR: Windows route add command failed [adaptive]");
                netcmd_semaphore_release();
            }
        }
        else
        {
            ASSERT(0);
        }
    }

#elif defined (TARGET_SOLARIS)

    /* example: route add 192.0.2.32 -netmask 255.255.255.224 somegateway */

    argv_printf(&argv, "%s add",
                ROUTE_PATH);

    argv_printf_cat(&argv, "%s -netmask %s %s",
                    network,
                    netmask,
                    gateway);

    /* Solaris can only distinguish between "metric 0" == "on-link on the
     * interface where the IP address given is configured" and "metric > 0"
     * == "use gateway specified" (no finer-grained route metrics available)
     *
     * More recent versions of Solaris can also do "-interface", but that
     * would break backwards compatibility with older versions for no gain.
     */
    if (r->flags & RT_METRIC_DEFINED)
    {
        argv_printf_cat(&argv, "%d", r->metric);
    }

    argv_msg(D_ROUTE, &argv);
    status = openvpn_execve_check(&argv, es, 0, "ERROR: Solaris route add command failed");

#elif defined(TARGET_FREEBSD)

    argv_printf(&argv, "%s add",
                ROUTE_PATH);

#if 0
    if (r->flags & RT_METRIC_DEFINED)
    {
        argv_printf_cat(&argv, "-rtt %d", r->metric);
    }
#endif

    argv_printf_cat(&argv, "-net %s %s %s",
                    network,
                    gateway,
                    netmask);

    /* FIXME -- add on-link support for FreeBSD */

    argv_msg(D_ROUTE, &argv);
    status = openvpn_execve_check(&argv, es, 0, "ERROR: FreeBSD route add command failed");

#elif defined(TARGET_DRAGONFLY)

    argv_printf(&argv, "%s add",
                ROUTE_PATH);

#if 0
    if (r->flags & RT_METRIC_DEFINED)
    {
        argv_printf_cat(&argv, "-rtt %d", r->metric);
    }
#endif

    argv_printf_cat(&argv, "-net %s %s %s",
                    network,
                    gateway,
                    netmask);

    /* FIXME -- add on-link support for Dragonfly */

    argv_msg(D_ROUTE, &argv);
    status = openvpn_execve_check(&argv, es, 0, "ERROR: DragonFly route add command failed");

#elif defined(TARGET_DARWIN)

    argv_printf(&argv, "%s add",
                ROUTE_PATH);

#if 0
    if (r->flags & RT_METRIC_DEFINED)
    {
        argv_printf_cat(&argv, "-rtt %d", r->metric);
    }
#endif

    if (is_on_link(is_local_route, flags, rgi))
    {
        /* Mac OS X route syntax for ON_LINK:
         * route add -cloning -net 10.10.0.1 -netmask 255.255.255.255 -interface en0 */
        argv_printf_cat(&argv, "-cloning -net %s -netmask %s -interface %s",
                        network,
                        netmask,
                        rgi->iface);
    }
    else
    {
        argv_printf_cat(&argv, "-net %s %s %s",
                        network,
                        gateway,
                        netmask);
    }

    argv_msg(D_ROUTE, &argv);
    status = openvpn_execve_check(&argv, es, 0, "ERROR: OS X route add command failed");

#elif defined(TARGET_OPENBSD) || defined(TARGET_NETBSD)

    argv_printf(&argv, "%s add",
                ROUTE_PATH);

#if 0
    if (r->flags & RT_METRIC_DEFINED)
    {
        argv_printf_cat(&argv, "-rtt %d", r->metric);
    }
#endif

    argv_printf_cat(&argv, "-net %s %s -netmask %s",
                    network,
                    gateway,
                    netmask);

    /* FIXME -- add on-link support for OpenBSD/NetBSD */

    argv_msg(D_ROUTE, &argv);
    status = openvpn_execve_check(&argv, es, 0, "ERROR: OpenBSD/NetBSD route add command failed");

#elif defined(TARGET_AIX)

    {
        int netbits = netmask_to_netbits2(r->netmask);
        argv_printf(&argv, "%s add -net %s/%d %s",
                    ROUTE_PATH,
                    network, netbits, gateway);
        argv_msg(D_ROUTE, &argv);
        status = openvpn_execve_check(&argv, es, 0, "ERROR: AIX route add command failed");
    }

#else  /* if defined(TARGET_LINUX) */
    msg(M_FATAL, "Sorry, but I don't know how to do 'route' commands on this operating system.  Try putting your routes in a --route-up script");
#endif /* if defined(TARGET_LINUX) */

done:
    if (status)
    {
        r->flags |= RT_ADDED;
    }
    else
    {
        r->flags &= ~RT_ADDED;
    }
    argv_reset(&argv);
    gc_free(&gc);
}


static void
route_ipv6_clear_host_bits( struct route_ipv6 *r6 )
{
    /* clear host bit parts of route
     * (needed if routes are specified improperly, or if we need to
     * explicitely setup/clear the "connected" network routes on some OSes)
     */
    int byte = 15;
    int bits_to_clear = 128 - r6->netbits;

    while (byte >= 0 && bits_to_clear > 0)
    {
        if (bits_to_clear >= 8)
        {
            r6->network.s6_addr[byte--] = 0; bits_to_clear -= 8;
        }
        else
        {
            r6->network.s6_addr[byte--] &= (0xff << bits_to_clear); bits_to_clear = 0;
        }
    }
}

void
add_route_ipv6(struct route_ipv6 *r6, const struct tuntap *tt, unsigned int flags, const struct env_set *es)
{
    struct gc_arena gc;
    struct argv argv = argv_new();

    const char *network;
    const char *gateway;
    bool status = false;
    const char *device = tt->actual_name;

    bool gateway_needed = false;

    if (!(r6->flags & RT_DEFINED) )
    {
        return;
    }

#ifndef _WIN32
    if (r6->iface != NULL)              /* vpn server special route */
    {
        device = r6->iface;
        if (!IN6_IS_ADDR_UNSPECIFIED(&r6->gateway) )
        {
            gateway_needed = true;
        }
    }
#endif

    gc_init(&gc);

    route_ipv6_clear_host_bits(r6);

    network = print_in6_addr( r6->network, 0, &gc);
    gateway = print_in6_addr( r6->gateway, 0, &gc);

#if defined(TARGET_DARWIN)    \
    || defined(TARGET_FREEBSD) || defined(TARGET_DRAGONFLY)    \
    || defined(TARGET_OPENBSD) || defined(TARGET_NETBSD)

    /* the BSD platforms cannot specify gateway and interface independently,
     * but for link-local destinations, we MUST specify the interface, so
     * we build a combined "$gateway%$interface" gateway string
     */
    if (r6->iface != NULL && gateway_needed
        && IN6_IS_ADDR_LINKLOCAL(&r6->gateway) )        /* fe80::...%intf */
    {
        int len = strlen(gateway) + 1 + strlen(r6->iface)+1;
        char *tmp = gc_malloc( len, true, &gc );
        snprintf( tmp, len, "%s%%%s", gateway, r6->iface );
        gateway = tmp;
    }
#endif

    msg( M_INFO, "add_route_ipv6(%s/%d -> %s metric %d) dev %s",
         network, r6->netbits, gateway, r6->metric, device );

    /*
     * Filter out routes which are essentially no-ops
     * (not currently done for IPv6)
     */

    /* On "tun" interface, we never set a gateway if the operating system
     * can do "route to interface" - it does not add value, as the target
     * dev already fully qualifies the route destination on point-to-point
     * interfaces.   OTOH, on "tap" interface, we must always set the
     * gateway unless the route is to be an on-link network
     */
    if (tt->type == DEV_TYPE_TAP
        && !( (r6->flags & RT_METRIC_DEFINED) && r6->metric == 0 ) )
    {
        gateway_needed = true;
    }

#if defined(TARGET_LINUX)
#ifdef ENABLE_IPROUTE
    argv_printf(&argv, "%s -6 route add %s/%d dev %s",
                iproute_path,
                network,
                r6->netbits,
                device);
    if (gateway_needed)
    {
        argv_printf_cat(&argv, "via %s", gateway);
    }
    if ( (r6->flags & RT_METRIC_DEFINED) && r6->metric > 0)
    {
        argv_printf_cat(&argv, " metric %d", r6->metric);
    }

#else  /* ifdef ENABLE_IPROUTE */
    argv_printf(&argv, "%s -A inet6 add %s/%d dev %s",
                ROUTE_PATH,
                network,
                r6->netbits,
                device);
    if (gateway_needed)
    {
        argv_printf_cat(&argv, "gw %s", gateway);
    }
    if ( (r6->flags & RT_METRIC_DEFINED) && r6->metric > 0)
    {
        argv_printf_cat(&argv, " metric %d", r6->metric);
    }
#endif  /*ENABLE_IPROUTE*/
    argv_msg(D_ROUTE, &argv);
    status = openvpn_execve_check(&argv, es, 0, "ERROR: Linux route -6/-A inet6 add command failed");

#elif defined (TARGET_ANDROID)
    struct buffer out = alloc_buf_gc(64, &gc);

    buf_printf(&out, "%s/%d %s", network, r6->netbits, device);

    management_android_control(management, "ROUTE6", buf_bptr(&out));

#elif defined (_WIN32)

    if (tt->options.msg_channel)
    {
        status = add_route_ipv6_service(r6, tt);
    }
    else
    {
        struct buffer out = alloc_buf_gc(64, &gc);
        if (r6->adapter_index)          /* vpn server special route */
        {
            buf_printf(&out, "interface=%d", r6->adapter_index );
            gateway_needed = true;
        }
        else
        {
            buf_printf(&out, "interface=%d", tt->adapter_index );
        }
        device = buf_bptr(&out);

        /* netsh interface ipv6 add route 2001:db8::/32 MyTunDevice */
        argv_printf(&argv, "%s%sc interface ipv6 add route %s/%d %s",
                    get_win_sys_path(),
                    NETSH_PATH_SUFFIX,
                    network,
                    r6->netbits,
                    device);

        /* next-hop depends on TUN or TAP mode:
         * - in TAP mode, we use the "real" next-hop
         * - in TUN mode we use a special-case link-local address that the tapdrvr
         *   knows about and will answer ND (neighbor discovery) packets for
         */
        if (tt->type == DEV_TYPE_TUN && !gateway_needed)
        {
            argv_printf_cat( &argv, " %s", "fe80::8" );
        }
        else if (!IN6_IS_ADDR_UNSPECIFIED(&r6->gateway) )
        {
            argv_printf_cat( &argv, " %s", gateway );
        }

#if 0
        if (r6->flags & RT_METRIC_DEFINED)
        {
            argv_printf_cat(&argv, " METRIC %d", r->metric);
        }
#endif

        /* in some versions of Windows, routes are persistent across reboots by
         * default, unless "store=active" is set (pointed out by Tony Lim, thanks)
         */
        argv_printf_cat( &argv, " store=active" );

        argv_msg(D_ROUTE, &argv);

        netcmd_semaphore_lock();
        status = openvpn_execve_check(&argv, es, 0, "ERROR: Windows route add ipv6 command failed");
        netcmd_semaphore_release();
    }

#elif defined (TARGET_SOLARIS)

    /* example: route add -inet6 2001:db8::/32 somegateway 0 */

    /* for some reason, routes to tun/tap do not work for me unless I set
     * "metric 0" - otherwise, the routes will be nicely installed, but
     * packets will just disappear somewhere.  So we always use "0" now,
     * unless the route points to "gateway on other interface"...
     *
     * (Note: OpenSolaris can not specify host%interface gateways, so we just
     * use the GW addresses - it seems to still work for fe80:: addresses,
     * however this is done internally.  NUD maybe?)
     */
    argv_printf(&argv, "%s add -inet6 %s/%d %s",
                ROUTE_PATH,
                network,
                r6->netbits,
                gateway );

    /* on tun/tap, not "elsewhere"? -> metric 0 */
    if (!r6->iface)
    {
        argv_printf_cat(&argv, "0");
    }

    argv_msg(D_ROUTE, &argv);
    status = openvpn_execve_check(&argv, es, 0, "ERROR: Solaris route add -inet6 command failed");

#elif defined(TARGET_FREEBSD) || defined(TARGET_DRAGONFLY)

    argv_printf(&argv, "%s add -inet6 %s/%d",
                ROUTE_PATH,
                network,
                r6->netbits);

    if (gateway_needed)
    {
        argv_printf_cat(&argv, "%s", gateway);
    }
    else
    {
        argv_printf_cat(&argv, "-iface %s", device);
    }

    argv_msg(D_ROUTE, &argv);
    status = openvpn_execve_check(&argv, es, 0, "ERROR: *BSD route add -inet6 command failed");

#elif defined(TARGET_DARWIN)

    argv_printf(&argv, "%s add -inet6 %s -prefixlen %d",
                ROUTE_PATH,
                network, r6->netbits );

    if (gateway_needed)
    {
        argv_printf_cat(&argv, "%s", gateway);
    }
    else
    {
        argv_printf_cat(&argv, "-iface %s", device);
    }

    argv_msg(D_ROUTE, &argv);
    status = openvpn_execve_check(&argv, es, 0, "ERROR: MacOS X route add -inet6 command failed");

#elif defined(TARGET_OPENBSD)

    argv_printf(&argv, "%s add -inet6 %s -prefixlen %d %s",
                ROUTE_PATH,
                network, r6->netbits, gateway );

    argv_msg(D_ROUTE, &argv);
    status = openvpn_execve_check(&argv, es, 0, "ERROR: OpenBSD route add -inet6 command failed");

#elif defined(TARGET_NETBSD)

    argv_printf(&argv, "%s add -inet6 %s/%d %s",
                ROUTE_PATH,
                network, r6->netbits, gateway );

    argv_msg(D_ROUTE, &argv);
    status = openvpn_execve_check(&argv, es, 0, "ERROR: NetBSD route add -inet6 command failed");

#elif defined(TARGET_AIX)

    argv_printf(&argv, "%s add -inet6 %s/%d %s",
                ROUTE_PATH,
                network, r6->netbits, gateway);
    argv_msg(D_ROUTE, &argv);
    status = openvpn_execve_check(&argv, es, 0, "ERROR: AIX route add command failed");

#else  /* if defined(TARGET_LINUX) */
    msg(M_FATAL, "Sorry, but I don't know how to do 'route ipv6' commands on this operating system.  Try putting your routes in a --route-up script");
#endif /* if defined(TARGET_LINUX) */

    if (status)
    {
        r6->flags |= RT_ADDED;
    }
    else
    {
        r6->flags &= ~RT_ADDED;
    }
    argv_reset(&argv);
    gc_free(&gc);
}

static void
delete_route(struct route_ipv4 *r,
             const struct tuntap *tt,
             unsigned int flags,
             const struct route_gateway_info *rgi,
             const struct env_set *es)
{
    struct gc_arena gc;
    struct argv argv = argv_new();
    const char *network;
    const char *netmask;
    const char *gateway;
    int is_local_route;

    if ((r->flags & (RT_DEFINED|RT_ADDED)) != (RT_DEFINED|RT_ADDED))
    {
        return;
    }

    gc_init(&gc);

    network = print_in_addr_t(r->network, 0, &gc);
    netmask = print_in_addr_t(r->netmask, 0, &gc);
    gateway = print_in_addr_t(r->gateway, 0, &gc);

    is_local_route = local_route(r->network, r->netmask, r->gateway, rgi);
    if (is_local_route == LR_ERROR)
    {
        goto done;
    }

#if defined(TARGET_LINUX)
#ifdef ENABLE_IPROUTE
    argv_printf(&argv, "%s route del %s/%d",
                iproute_path,
                network,
                netmask_to_netbits2(r->netmask));
#else
    argv_printf(&argv, "%s del -net %s netmask %s",
                ROUTE_PATH,
                network,
                netmask);
#endif /*ENABLE_IPROUTE*/
    if (r->flags & RT_METRIC_DEFINED)
    {
        argv_printf_cat(&argv, "metric %d", r->metric);
    }
    argv_msg(D_ROUTE, &argv);
    openvpn_execve_check(&argv, es, 0, "ERROR: Linux route delete command failed");

#elif defined (_WIN32)

    argv_printf(&argv, "%s%sc DELETE %s MASK %s %s",
                get_win_sys_path(),
                WIN_ROUTE_PATH_SUFFIX,
                network,
                netmask,
                gateway);

    argv_msg(D_ROUTE, &argv);

    if ((flags & ROUTE_METHOD_MASK) == ROUTE_METHOD_SERVICE)
    {
        const bool status = del_route_service(r, tt);
        msg(D_ROUTE, "Route deletion via service %s", status ? "succeeded" : "failed");
    }
    else if ((flags & ROUTE_METHOD_MASK) == ROUTE_METHOD_IPAPI)
    {
        const bool status = del_route_ipapi(r, tt);
        msg(D_ROUTE, "Route deletion via IPAPI %s", status ? "succeeded" : "failed");
    }
    else if ((flags & ROUTE_METHOD_MASK) == ROUTE_METHOD_EXE)
    {
        netcmd_semaphore_lock();
        openvpn_execve_check(&argv, es, 0, "ERROR: Windows route delete command failed");
        netcmd_semaphore_release();
    }
    else if ((flags & ROUTE_METHOD_MASK) == ROUTE_METHOD_ADAPTIVE)
    {
        const bool status = del_route_ipapi(r, tt);
        msg(D_ROUTE, "Route deletion via IPAPI %s [adaptive]", status ? "succeeded" : "failed");
        if (!status)
        {
            msg(D_ROUTE, "Route deletion fallback to route.exe");
            netcmd_semaphore_lock();
            openvpn_execve_check(&argv, es, 0, "ERROR: Windows route delete command failed [adaptive]");
            netcmd_semaphore_release();
        }
    }
    else
    {
        ASSERT(0);
    }

#elif defined (TARGET_SOLARIS)

    argv_printf(&argv, "%s delete %s -netmask %s %s",
                ROUTE_PATH,
                network,
                netmask,
                gateway);

    argv_msg(D_ROUTE, &argv);
    openvpn_execve_check(&argv, es, 0, "ERROR: Solaris route delete command failed");

#elif defined(TARGET_FREEBSD)

    argv_printf(&argv, "%s delete -net %s %s %s",
                ROUTE_PATH,
                network,
                gateway,
                netmask);

    argv_msg(D_ROUTE, &argv);
    openvpn_execve_check(&argv, es, 0, "ERROR: FreeBSD route delete command failed");

#elif defined(TARGET_DRAGONFLY)

    argv_printf(&argv, "%s delete -net %s %s %s",
                ROUTE_PATH,
                network,
                gateway,
                netmask);

    argv_msg(D_ROUTE, &argv);
    openvpn_execve_check(&argv, es, 0, "ERROR: DragonFly route delete command failed");

#elif defined(TARGET_DARWIN)

    if (is_on_link(is_local_route, flags, rgi))
    {
        argv_printf(&argv, "%s delete -cloning -net %s -netmask %s -interface %s",
                    ROUTE_PATH,
                    network,
                    netmask,
                    rgi->iface);
    }
    else
    {
        argv_printf(&argv, "%s delete -net %s %s %s",
                    ROUTE_PATH,
                    network,
                    gateway,
                    netmask);
    }

    argv_msg(D_ROUTE, &argv);
    openvpn_execve_check(&argv, es, 0, "ERROR: OS X route delete command failed");

#elif defined(TARGET_OPENBSD) || defined(TARGET_NETBSD)

    argv_printf(&argv, "%s delete -net %s %s -netmask %s",
                ROUTE_PATH,
                network,
                gateway,
                netmask);

    argv_msg(D_ROUTE, &argv);
    openvpn_execve_check(&argv, es, 0, "ERROR: OpenBSD/NetBSD route delete command failed");

#elif defined(TARGET_ANDROID)
    msg(M_NONFATAL, "Sorry, deleting routes on Android is not possible. The VpnService API allows routes to be set on connect only.");

#elif defined(TARGET_AIX)

    {
        int netbits = netmask_to_netbits2(r->netmask);
        argv_printf(&argv, "%s delete -net %s/%d %s",
                    ROUTE_PATH,
                    network, netbits, gateway);
        argv_msg(D_ROUTE, &argv);
        openvpn_execve_check(&argv, es, 0, "ERROR: AIX route delete command failed");
    }

#else  /* if defined(TARGET_LINUX) */
    msg(M_FATAL, "Sorry, but I don't know how to do 'route' commands on this operating system.  Try putting your routes in a --route-up script");
#endif /* if defined(TARGET_LINUX) */

done:
    r->flags &= ~RT_ADDED;
    argv_reset(&argv);
    gc_free(&gc);
}

void
delete_route_ipv6(const struct route_ipv6 *r6, const struct tuntap *tt, unsigned int flags, const struct env_set *es)
{
    struct gc_arena gc;
    struct argv argv = argv_new();
    const char *network;
    const char *gateway;
    const char *device = tt->actual_name;
    bool gateway_needed = false;

    if ((r6->flags & (RT_DEFINED|RT_ADDED)) != (RT_DEFINED|RT_ADDED))
    {
        return;
    }

#ifndef _WIN32
    if (r6->iface != NULL)              /* vpn server special route */
    {
        device = r6->iface;
        gateway_needed = true;
    }
#endif

    gc_init(&gc);

    network = print_in6_addr( r6->network, 0, &gc);
    gateway = print_in6_addr( r6->gateway, 0, &gc);

#if defined(TARGET_DARWIN)    \
    || defined(TARGET_FREEBSD) || defined(TARGET_DRAGONFLY)    \
    || defined(TARGET_OPENBSD) || defined(TARGET_NETBSD)

    /* the BSD platforms cannot specify gateway and interface independently,
     * but for link-local destinations, we MUST specify the interface, so
     * we build a combined "$gateway%$interface" gateway string
     */
    if (r6->iface != NULL && gateway_needed
        && IN6_IS_ADDR_LINKLOCAL(&r6->gateway) )        /* fe80::...%intf */
    {
        int len = strlen(gateway) + 1 + strlen(r6->iface)+1;
        char *tmp = gc_malloc( len, true, &gc );
        snprintf( tmp, len, "%s%%%s", gateway, r6->iface );
        gateway = tmp;
    }
#endif

    msg( M_INFO, "delete_route_ipv6(%s/%d)", network, r6->netbits );

    /* if we used a gateway on "add route", we also need to specify it on
     * delete, otherwise some OSes will refuse to delete the route
     */
    if (tt->type == DEV_TYPE_TAP
        && !( (r6->flags & RT_METRIC_DEFINED) && r6->metric == 0 ) )
    {
        gateway_needed = true;
    }


#if defined(TARGET_LINUX)
#ifdef ENABLE_IPROUTE
    argv_printf(&argv, "%s -6 route del %s/%d dev %s",
                iproute_path,
                network,
                r6->netbits,
                device);
    if (gateway_needed)
    {
        argv_printf_cat(&argv, "via %s", gateway);
    }
#else  /* ifdef ENABLE_IPROUTE */
    argv_printf(&argv, "%s -A inet6 del %s/%d dev %s",
                ROUTE_PATH,
                network,
                r6->netbits,
                device);
    if (gateway_needed)
    {
        argv_printf_cat(&argv, "gw %s", gateway);
    }
    if ( (r6->flags & RT_METRIC_DEFINED) && r6->metric > 0)
    {
        argv_printf_cat(&argv, " metric %d", r6->metric);
    }
#endif  /*ENABLE_IPROUTE*/
    argv_msg(D_ROUTE, &argv);
    openvpn_execve_check(&argv, es, 0, "ERROR: Linux route -6/-A inet6 del command failed");

#elif defined (_WIN32)

    if (tt->options.msg_channel)
    {
        del_route_ipv6_service(r6, tt);
    }
    else
    {
        struct buffer out = alloc_buf_gc(64, &gc);
        if (r6->adapter_index)          /* vpn server special route */
        {
            buf_printf(&out, "interface=%d", r6->adapter_index );
            gateway_needed = true;
        }
        else
        {
            buf_printf(&out, "interface=%d", tt->adapter_index );
        }
        device = buf_bptr(&out);

        /* netsh interface ipv6 delete route 2001:db8::/32 MyTunDevice */
        argv_printf(&argv, "%s%sc interface ipv6 delete route %s/%d %s",
                    get_win_sys_path(),
                    NETSH_PATH_SUFFIX,
                    network,
                    r6->netbits,
                    device);

        /* next-hop depends on TUN or TAP mode:
         * - in TAP mode, we use the "real" next-hop
         * - in TUN mode we use a special-case link-local address that the tapdrvr
         *   knows about and will answer ND (neighbor discovery) packets for
         * (and "route deletion without specifying next-hop" does not work...)
         */
        if (tt->type == DEV_TYPE_TUN && !gateway_needed)
        {
            argv_printf_cat( &argv, " %s", "fe80::8" );
        }
        else if (!IN6_IS_ADDR_UNSPECIFIED(&r6->gateway) )
        {
            argv_printf_cat( &argv, " %s", gateway );
        }

#if 0
        if (r6->flags & RT_METRIC_DEFINED)
        {
            argv_printf_cat(&argv, "METRIC %d", r->metric);
        }
#endif

        /* Windows XP to 7 "just delete" routes, wherever they came from, but
         * in Windows 8(.1?), if you create them with "store=active", this is
         * how you should delete them as well (pointed out by Cedric Tabary)
         */
        argv_printf_cat( &argv, " store=active" );

        argv_msg(D_ROUTE, &argv);

        netcmd_semaphore_lock();
        openvpn_execve_check(&argv, es, 0, "ERROR: Windows route delete ipv6 command failed");
        netcmd_semaphore_release();
    }

#elif defined (TARGET_SOLARIS)

    /* example: route delete -inet6 2001:db8::/32 somegateway */

    argv_printf(&argv, "%s delete -inet6 %s/%d %s",
                ROUTE_PATH,
                network,
                r6->netbits,
                gateway );

    argv_msg(D_ROUTE, &argv);
    openvpn_execve_check(&argv, es, 0, "ERROR: Solaris route delete -inet6 command failed");

#elif defined(TARGET_FREEBSD) || defined(TARGET_DRAGONFLY)

    argv_printf(&argv, "%s delete -inet6 %s/%d",
                ROUTE_PATH,
                network,
                r6->netbits );

    if (gateway_needed)
    {
        argv_printf_cat(&argv, "%s", gateway);
    }
    else
    {
        argv_printf_cat(&argv, "-iface %s", device);
    }

    argv_msg(D_ROUTE, &argv);
    openvpn_execve_check(&argv, es, 0, "ERROR: *BSD route delete -inet6 command failed");

#elif defined(TARGET_DARWIN)

    argv_printf(&argv, "%s delete -inet6 %s -prefixlen %d",
                ROUTE_PATH,
                network, r6->netbits );

    if (gateway_needed)
    {
        argv_printf_cat(&argv, "%s", gateway);
    }
    else
    {
        argv_printf_cat(&argv, "-iface %s", device);
    }

    argv_msg(D_ROUTE, &argv);
    openvpn_execve_check(&argv, es, 0, "ERROR: MacOS X route delete -inet6 command failed");

#elif defined(TARGET_OPENBSD)

    argv_printf(&argv, "%s delete -inet6 %s -prefixlen %d %s",
                ROUTE_PATH,
                network, r6->netbits, gateway );

    argv_msg(D_ROUTE, &argv);
    openvpn_execve_check(&argv, es, 0, "ERROR: OpenBSD route delete -inet6 command failed");

#elif defined(TARGET_NETBSD)

    argv_printf(&argv, "%s delete -inet6 %s/%d %s",
                ROUTE_PATH,
                network, r6->netbits, gateway );

    argv_msg(D_ROUTE, &argv);
    openvpn_execve_check(&argv, es, 0, "ERROR: NetBSD route delete -inet6 command failed");

#elif defined(TARGET_AIX)

    argv_printf(&argv, "%s delete -inet6 %s/%d %s",
                ROUTE_PATH,
                network, r6->netbits, gateway);
    argv_msg(D_ROUTE, &argv);
    openvpn_execve_check(&argv, es, 0, "ERROR: AIX route add command failed");

#else  /* if defined(TARGET_LINUX) */
    msg(M_FATAL, "Sorry, but I don't know how to do 'route ipv6' commands on this operating system.  Try putting your routes in a --route-down script");
#endif /* if defined(TARGET_LINUX) */

    argv_reset(&argv);
    gc_free(&gc);
}

/*
 * The --redirect-gateway option requires OS-specific code below
 * to get the current default gateway.
 */

#if defined(_WIN32)

static const MIB_IPFORWARDTABLE *
get_windows_routing_table(struct gc_arena *gc)
{
    ULONG size = 0;
    PMIB_IPFORWARDTABLE rt = NULL;
    DWORD status;

    status = GetIpForwardTable(NULL, &size, TRUE);
    if (status == ERROR_INSUFFICIENT_BUFFER)
    {
        rt = (PMIB_IPFORWARDTABLE) gc_malloc(size, false, gc);
        status = GetIpForwardTable(rt, &size, TRUE);
        if (status != NO_ERROR)
        {
            msg(D_ROUTE, "NOTE: GetIpForwardTable returned error: %s (code=%u)",
                strerror_win32(status, gc),
                (unsigned int)status);
            rt = NULL;
        }
    }
    return rt;
}

static int
test_route(const IP_ADAPTER_INFO *adapters,
           const in_addr_t gateway,
           DWORD *index)
{
    int count = 0;
    DWORD i = adapter_index_of_ip(adapters, gateway, &count, NULL);
    if (index)
    {
        *index = i;
    }
    return count;
}

static void
test_route_helper(bool *ret,
                  int *count,
                  int *good,
                  int *ambig,
                  const IP_ADAPTER_INFO *adapters,
                  const in_addr_t gateway)
{
    int c;

    ++*count;
    c = test_route(adapters, gateway, NULL);
    if (c == 0)
    {
        *ret = false;
    }
    else
    {
        ++*good;
    }
    if (c > 1)
    {
        ++*ambig;
    }
}

/*
 * If we tried to add routes now, would we succeed?
 */
bool
test_routes(const struct route_list *rl, const struct tuntap *tt)
{
    struct gc_arena gc = gc_new();
    const IP_ADAPTER_INFO *adapters = get_adapter_info_list(&gc);
    bool ret = false;
    int count = 0;
    int good = 0;
    int ambig = 0;
    int len = -1;
    bool adapter_up = false;

    if (is_adapter_up(tt, adapters))
    {
        ret = true;
        adapter_up = true;

        if (rl)
        {
            struct route_ipv4 *r;
            for (r = rl->routes, len = 0; r; r = r->next, ++len)
            {
                test_route_helper(&ret, &count, &good, &ambig, adapters, r->gateway);
            }

            if ((rl->flags & RG_ENABLE) && (rl->spec.flags & RTSA_REMOTE_ENDPOINT))
            {
                test_route_helper(&ret, &count, &good, &ambig, adapters, rl->spec.remote_endpoint);
            }
        }
    }

    msg(D_ROUTE, "TEST ROUTES: %d/%d succeeded len=%d ret=%d a=%d u/d=%s",
        good,
        count,
        len,
        (int)ret,
        ambig,
        adapter_up ? "up" : "down");

    gc_free(&gc);
    return ret;
}

static const MIB_IPFORWARDROW *
get_default_gateway_row(const MIB_IPFORWARDTABLE *routes)
{
    struct gc_arena gc = gc_new();
    DWORD lowest_metric = MAXDWORD;
    const MIB_IPFORWARDROW *ret = NULL;
    int i;
    int best = -1;

    if (routes)
    {
        for (i = 0; i < routes->dwNumEntries; ++i)
        {
            const MIB_IPFORWARDROW *row = &routes->table[i];
            const in_addr_t net = ntohl(row->dwForwardDest);
            const in_addr_t mask = ntohl(row->dwForwardMask);
            const DWORD index = row->dwForwardIfIndex;
            const DWORD metric = row->dwForwardMetric1;

            dmsg(D_ROUTE_DEBUG, "GDGR: route[%d] %s/%s i=%d m=%d",
                 i,
                 print_in_addr_t((in_addr_t) net, 0, &gc),
                 print_in_addr_t((in_addr_t) mask, 0, &gc),
                 (int)index,
                 (int)metric);

            if (!net && !mask && metric < lowest_metric)
            {
                ret = row;
                lowest_metric = metric;
                best = i;
            }
        }
    }

    dmsg(D_ROUTE_DEBUG, "GDGR: best=%d lm=%u", best, (unsigned int)lowest_metric);

    gc_free(&gc);
    return ret;
}

void
get_default_gateway(struct route_gateway_info *rgi)
{
    struct gc_arena gc = gc_new();

    const IP_ADAPTER_INFO *adapters = get_adapter_info_list(&gc);
    const MIB_IPFORWARDTABLE *routes = get_windows_routing_table(&gc);
    const MIB_IPFORWARDROW *row = get_default_gateway_row(routes);
    DWORD a_index;
    const IP_ADAPTER_INFO *ai;

    CLEAR(*rgi);

    if (row)
    {
        rgi->gateway.addr = ntohl(row->dwForwardNextHop);
        if (rgi->gateway.addr)
        {
            rgi->flags |= RGI_ADDR_DEFINED;
            a_index = adapter_index_of_ip(adapters, rgi->gateway.addr, NULL, &rgi->gateway.netmask);
            if (a_index != TUN_ADAPTER_INDEX_INVALID)
            {
                rgi->adapter_index = a_index;
                rgi->flags |= (RGI_IFACE_DEFINED|RGI_NETMASK_DEFINED);
                ai = get_adapter(adapters, a_index);
                if (ai)
                {
                    memcpy(rgi->hwaddr, ai->Address, 6);
                    rgi->flags |= RGI_HWADDR_DEFINED;
                }
            }
        }
    }

    gc_free(&gc);
}

static DWORD
windows_route_find_if_index(const struct route_ipv4 *r, const struct tuntap *tt)
{
    struct gc_arena gc = gc_new();
    DWORD ret = TUN_ADAPTER_INDEX_INVALID;
    int count = 0;
    const IP_ADAPTER_INFO *adapters = get_adapter_info_list(&gc);
    const IP_ADAPTER_INFO *tun_adapter = get_tun_adapter(tt, adapters);
    bool on_tun = false;

    /* first test on tun interface */
    if (is_ip_in_adapter_subnet(tun_adapter, r->gateway, NULL))
    {
        ret = tun_adapter->Index;
        count = 1;
        on_tun = true;
    }
    else /* test on other interfaces */
    {
        count = test_route(adapters, r->gateway, &ret);
    }

    if (count == 0)
    {
        msg(M_WARN, "Warning: route gateway is not reachable on any active network adapters: %s",
            print_in_addr_t(r->gateway, 0, &gc));
        ret = TUN_ADAPTER_INDEX_INVALID;
    }
    else if (count > 1)
    {
        msg(M_WARN, "Warning: route gateway is ambiguous: %s (%d matches)",
            print_in_addr_t(r->gateway, 0, &gc),
            count);
        ret = TUN_ADAPTER_INDEX_INVALID;
    }

    dmsg(D_ROUTE_DEBUG, "DEBUG: route find if: on_tun=%d count=%d index=%d",
         on_tun,
         count,
         (int)ret);

    gc_free(&gc);
    return ret;
}

/* IPv6 implementation using GetBestRoute2()
 *   (TBD: dynamic linking so the binary can still run on XP?)
 * https://msdn.microsoft.com/en-us/library/windows/desktop/aa365922(v=vs.85).aspx
 * https://msdn.microsoft.com/en-us/library/windows/desktop/aa814411(v=vs.85).aspx
 */
void
get_default_gateway_ipv6(struct route_ipv6_gateway_info *rgi6,
                         const struct in6_addr *dest)
{
    struct gc_arena gc = gc_new();
    MIB_IPFORWARD_ROW2 BestRoute;
    SOCKADDR_INET DestinationAddress, BestSourceAddress;
    DWORD BestIfIndex;
    DWORD status;
    NET_LUID InterfaceLuid;

    CLEAR(*rgi6);
    CLEAR(InterfaceLuid);               /* cleared = not used for lookup */
    CLEAR(DestinationAddress);

    DestinationAddress.si_family = AF_INET6;
    if (dest)
    {
        DestinationAddress.Ipv6.sin6_addr = *dest;
    }

    status = GetBestInterfaceEx( &DestinationAddress, &BestIfIndex );

    if (status != NO_ERROR)
    {
        msg(D_ROUTE, "NOTE: GetBestInterfaceEx returned error: %s (code=%u)",
            strerror_win32(status, &gc),
            (unsigned int)status);
        goto done;
    }

    msg( D_ROUTE, "GetBestInterfaceEx() returned if=%d", (int) BestIfIndex );

    status = GetBestRoute2( &InterfaceLuid, BestIfIndex, NULL,
                            &DestinationAddress, 0,
                            &BestRoute, &BestSourceAddress );

    if (status != NO_ERROR)
    {
        msg(D_ROUTE, "NOTE: GetIpForwardEntry2 returned error: %s (code=%u)",
            strerror_win32(status, &gc),
            (unsigned int)status);
        goto done;
    }

    msg( D_ROUTE, "GDG6: II=%d DP=%s/%d NH=%s",
         BestRoute.InterfaceIndex,
         print_in6_addr( BestRoute.DestinationPrefix.Prefix.Ipv6.sin6_addr, 0, &gc),
         BestRoute.DestinationPrefix.PrefixLength,
         print_in6_addr( BestRoute.NextHop.Ipv6.sin6_addr, 0, &gc) );
    msg( D_ROUTE, "GDG6: Metric=%d, Loopback=%d, AA=%d, I=%d",
         (int) BestRoute.Metric,
         (int) BestRoute.Loopback,
         (int) BestRoute.AutoconfigureAddress,
         (int) BestRoute.Immortal );

    rgi6->gateway.addr_ipv6 = BestRoute.NextHop.Ipv6.sin6_addr;
    rgi6->adapter_index     = BestRoute.InterfaceIndex;
    rgi6->flags |= RGI_ADDR_DEFINED | RGI_IFACE_DEFINED;

    /* on-link is signalled by receiving an empty (::) NextHop */
    if (IN6_IS_ADDR_UNSPECIFIED(&BestRoute.NextHop.Ipv6.sin6_addr) )
    {
        rgi6->flags |= RGI_ON_LINK;
    }

done:
    gc_free(&gc);
}

bool
add_route_ipapi(const struct route_ipv4 *r, const struct tuntap *tt, DWORD adapter_index)
{
    struct gc_arena gc = gc_new();
    bool ret = false;
    DWORD status;
    const DWORD if_index = (adapter_index == TUN_ADAPTER_INDEX_INVALID) ? windows_route_find_if_index(r, tt) : adapter_index;

    if (if_index != TUN_ADAPTER_INDEX_INVALID)
    {
        MIB_IPFORWARDROW fr;
        CLEAR(fr);
        fr.dwForwardDest = htonl(r->network);
        fr.dwForwardMask = htonl(r->netmask);
        fr.dwForwardPolicy = 0;
        fr.dwForwardNextHop = htonl(r->gateway);
        fr.dwForwardIfIndex = if_index;
        fr.dwForwardType = 4; /* the next hop is not the final dest */
        fr.dwForwardProto = 3; /* PROTO_IP_NETMGMT */
        fr.dwForwardAge = 0;
        fr.dwForwardNextHopAS = 0;
        fr.dwForwardMetric1 = (r->flags & RT_METRIC_DEFINED) ? r->metric : 1;
        fr.dwForwardMetric2 = METRIC_NOT_USED;
        fr.dwForwardMetric3 = METRIC_NOT_USED;
        fr.dwForwardMetric4 = METRIC_NOT_USED;
        fr.dwForwardMetric5 = METRIC_NOT_USED;

        if ((r->network & r->netmask) != r->network)
        {
            msg(M_WARN, "Warning: address %s is not a network address in relation to netmask %s",
                print_in_addr_t(r->network, 0, &gc),
                print_in_addr_t(r->netmask, 0, &gc));
        }

        status = CreateIpForwardEntry(&fr);

        if (status == NO_ERROR)
        {
            ret = true;
        }
        else
        {
            /* failed, try increasing the metric to work around Vista issue */
            const unsigned int forward_metric_limit = 2048; /* iteratively retry higher metrics up to this limit */

            for (; fr.dwForwardMetric1 <= forward_metric_limit; ++fr.dwForwardMetric1)
            {
                /* try a different forward type=3 ("the next hop is the final dest") in addition to 4.
                 * --redirect-gateway over RRAS seems to need this. */
                for (fr.dwForwardType = 4; fr.dwForwardType >= 3; --fr.dwForwardType)
                {
                    status = CreateIpForwardEntry(&fr);
                    if (status == NO_ERROR)
                    {
                        msg(D_ROUTE, "ROUTE: CreateIpForwardEntry succeeded with dwForwardMetric1=%u and dwForwardType=%u",
                            (unsigned int)fr.dwForwardMetric1,
                            (unsigned int)fr.dwForwardType);
                        ret = true;
                        goto doublebreak;
                    }
                    else if (status != ERROR_BAD_ARGUMENTS)
                    {
                        goto doublebreak;
                    }
                }
            }

doublebreak:
            if (status != NO_ERROR)
            {
                msg(M_WARN, "ROUTE: route addition failed using CreateIpForwardEntry: %s [status=%u if_index=%u]",
                    strerror_win32(status, &gc),
                    (unsigned int)status,
                    (unsigned int)if_index);
            }
        }
    }

    gc_free(&gc);
    return ret;
}

bool
del_route_ipapi(const struct route_ipv4 *r, const struct tuntap *tt)
{
    struct gc_arena gc = gc_new();
    bool ret = false;
    DWORD status;
    const DWORD if_index = windows_route_find_if_index(r, tt);

    if (if_index != TUN_ADAPTER_INDEX_INVALID)
    {
        MIB_IPFORWARDROW fr;
        CLEAR(fr);

        fr.dwForwardDest = htonl(r->network);
        fr.dwForwardMask = htonl(r->netmask);
        fr.dwForwardPolicy = 0;
        fr.dwForwardNextHop = htonl(r->gateway);
        fr.dwForwardIfIndex = if_index;

        status = DeleteIpForwardEntry(&fr);

        if (status == NO_ERROR)
        {
            ret = true;
        }
        else
        {
            msg(M_WARN, "ROUTE: route deletion failed using DeleteIpForwardEntry: %s",
                strerror_win32(status, &gc));
        }
    }

    gc_free(&gc);
    return ret;
}

static bool
do_route_service(const bool add, const route_message_t *rt, const size_t size, HANDLE pipe)
{
    DWORD len;
    bool ret = false;
    ack_message_t ack;
    struct gc_arena gc = gc_new();

    if (!WriteFile(pipe, rt, size, &len, NULL)
        || !ReadFile(pipe, &ack, sizeof(ack), &len, NULL))
    {
        msg(M_WARN, "ROUTE: could not talk to service: %s [%lu]",
            strerror_win32(GetLastError(), &gc), GetLastError());
        goto out;
    }

    if (ack.error_number != NO_ERROR)
    {
        msg(M_WARN, "ROUTE: route %s failed using service: %s [status=%u if_index=%lu]",
            (add ? "addition" : "deletion"), strerror_win32(ack.error_number, &gc),
            ack.error_number, rt->iface.index);
        goto out;
    }

    ret = true;

out:
    gc_free(&gc);
    return ret;
}

static bool
do_route_ipv4_service(const bool add, const struct route_ipv4 *r, const struct tuntap *tt)
{
    DWORD if_index = windows_route_find_if_index(r, tt);
    if (if_index == ~0)
    {
        return false;
    }

    route_message_t msg = {
        .header = {
            (add ? msg_add_route : msg_del_route),
            sizeof(route_message_t),
            0
        },
        .family = AF_INET,
        .prefix.ipv4.s_addr = htonl(r->network),
        .gateway.ipv4.s_addr = htonl(r->gateway),
        .iface = { .index = if_index, .name = "" },
        .metric = (r->flags & RT_METRIC_DEFINED ? r->metric : -1)
    };

    netmask_to_netbits(r->network, r->netmask, &msg.prefix_len);
    if (msg.prefix_len == -1)
    {
        msg.prefix_len = 32;
    }

    return do_route_service(add, &msg, sizeof(msg), tt->options.msg_channel);
}

static bool
do_route_ipv6_service(const bool add, const struct route_ipv6 *r, const struct tuntap *tt)
{
    bool status;
    route_message_t msg = {
        .header = {
            (add ? msg_add_route : msg_del_route),
            sizeof(route_message_t),
            0
        },
        .family = AF_INET6,
        .prefix.ipv6 = r->network,
        .prefix_len = r->netbits,
        .gateway.ipv6 = r->gateway,
        .iface = { .index = tt->adapter_index, .name = "" },
        .metric = ( (r->flags & RT_METRIC_DEFINED) ? r->metric : -1)
    };

    if (r->adapter_index)               /* vpn server special route */
    {
        msg.iface.index = r->adapter_index;
    }

    /* In TUN mode we use a special link-local address as the next hop.
     * The tapdrvr knows about it and will answer neighbor discovery packets.
     * (only do this for routes actually using the tun/tap device)
     */
    if (tt->type == DEV_TYPE_TUN
	 && msg.iface.index == tt->adapter_index )
    {
        inet_pton(AF_INET6, "fe80::8", &msg.gateway.ipv6);
    }

    if (msg.iface.index == TUN_ADAPTER_INDEX_INVALID)
    {
        strncpy(msg.iface.name, tt->actual_name, sizeof(msg.iface.name));
        msg.iface.name[sizeof(msg.iface.name) - 1] = '\0';
    }

    status = do_route_service(add, &msg, sizeof(msg), tt->options.msg_channel);
    msg(D_ROUTE, "IPv6 route %s via service %s",
        add ? "addition" : "deletion",
        status ? "succeeded" : "failed");
    return status;
}

static bool
add_route_service(const struct route_ipv4 *r, const struct tuntap *tt)
{
    return do_route_ipv4_service(true, r, tt);
}

static bool
del_route_service(const struct route_ipv4 *r, const struct tuntap *tt)
{
    return do_route_ipv4_service(false, r, tt);
}

static bool
add_route_ipv6_service(const struct route_ipv6 *r, const struct tuntap *tt)
{
    return do_route_ipv6_service(true, r, tt);
}

static bool
del_route_ipv6_service(const struct route_ipv6 *r, const struct tuntap *tt)
{
    return do_route_ipv6_service(false, r, tt);
}

static const char *
format_route_entry(const MIB_IPFORWARDROW *r, struct gc_arena *gc)
{
    struct buffer out = alloc_buf_gc(256, gc);
    buf_printf(&out, "%s %s %s p=%d i=%d t=%d pr=%d a=%d h=%d m=%d/%d/%d/%d/%d",
               print_in_addr_t(r->dwForwardDest, IA_NET_ORDER, gc),
               print_in_addr_t(r->dwForwardMask, IA_NET_ORDER, gc),
               print_in_addr_t(r->dwForwardNextHop, IA_NET_ORDER, gc),
               (int)r->dwForwardPolicy,
               (int)r->dwForwardIfIndex,
               (int)r->dwForwardType,
               (int)r->dwForwardProto,
               (int)r->dwForwardAge,
               (int)r->dwForwardNextHopAS,
               (int)r->dwForwardMetric1,
               (int)r->dwForwardMetric2,
               (int)r->dwForwardMetric3,
               (int)r->dwForwardMetric4,
               (int)r->dwForwardMetric5);
    return BSTR(&out);
}

/*
 * Show current routing table
 */
void
show_routes(int msglev)
{
    struct gc_arena gc = gc_new();
    int i;

    const MIB_IPFORWARDTABLE *rt = get_windows_routing_table(&gc);

    msg(msglev, "SYSTEM ROUTING TABLE");
    if (rt)
    {
        for (i = 0; i < rt->dwNumEntries; ++i)
        {
            msg(msglev, "%s", format_route_entry(&rt->table[i], &gc));
        }
    }
    gc_free(&gc);
}

#elif defined(TARGET_LINUX) || defined(TARGET_ANDROID)

void
get_default_gateway(struct route_gateway_info *rgi)
{
    struct gc_arena gc = gc_new();
    int sd = -1;
    char best_name[16];
    best_name[0] = 0;

    CLEAR(*rgi);

#ifndef TARGET_ANDROID
    /* get default gateway IP addr */
    {
        FILE *fp = platform_fopen("/proc/net/route", "r");
        if (fp)
        {
            char line[256];
            int count = 0;
            unsigned int lowest_metric = UINT_MAX;
            in_addr_t best_gw = 0;
            bool found = false;
            while (platform_fgets(line, sizeof(line), fp) != NULL)
            {
                if (count)
                {
                    unsigned int net_x = 0;
                    unsigned int mask_x = 0;
                    unsigned int gw_x = 0;
                    unsigned int metric = 0;
                    unsigned int flags = 0;
                    char name[16];
                    name[0] = 0;
                    const int np = sscanf(line, "%15s\t%x\t%x\t%x\t%*s\t%*s\t%d\t%x",
                                          name,
                                          &net_x,
                                          &gw_x,
                                          &flags,
                                          &metric,
                                          &mask_x);
                    if (np == 6 && (flags & IFF_UP))
                    {
                        const in_addr_t net = ntohl(net_x);
                        const in_addr_t mask = ntohl(mask_x);
                        const in_addr_t gw = ntohl(gw_x);

                        if (!net && !mask && metric < lowest_metric)
                        {
                            found = true;
                            best_gw = gw;
                            strcpy(best_name, name);
                            lowest_metric = metric;
                        }
                    }
                }
                ++count;
            }
            platform_fclose(fp);

            if (found)
            {
                rgi->gateway.addr = best_gw;
                rgi->flags |= RGI_ADDR_DEFINED;
                if (!rgi->gateway.addr && best_name[0])
                {
                    rgi->flags |= RGI_ON_LINK;
                }
            }
        }
    }
#else  /* ifndef TARGET_ANDROID */
    /* Android, set some pseudo GW, addr is in host byte order,
     * Determining the default GW on Android 5.0+ is non trivial
     * and serves almost no purpose since OpenVPN only uses the
     * default GW address to add routes for networks that should
     * NOT be routed over the VPN. Using a well known address
     * (127.'d'.'g'.'w') for the default GW make detecting
     * these routes easier from the controlling app.
     */
    rgi->gateway.addr = 127 << 24 | 'd' << 16 | 'g' << 8 | 'w';
    rgi->flags |= RGI_ADDR_DEFINED;
    strcpy(best_name, "android-gw");
#endif /* ifndef TARGET_ANDROID */

    /* scan adapter list */
    if (rgi->flags & RGI_ADDR_DEFINED)
    {
        struct ifreq *ifr, *ifend;
        in_addr_t addr, netmask;
        struct ifreq ifreq;
        struct ifconf ifc;
        struct ifreq ifs[20]; /* Maximum number of interfaces to scan */

        if ((sd = platform_socket(AF_INET, SOCK_DGRAM, 0)) < 0)
        {
            msg(M_WARN, "GDG: socket() failed");
            goto done;
        }
        ifc.ifc_len = sizeof(ifs);
        ifc.ifc_req = ifs;
        if (ioctl(sd, SIOCGIFCONF, &ifc) < 0)
        {
            msg(M_WARN, "GDG: ioctl(SIOCGIFCONF) failed");
            goto done;
        }

        /* scan through interface list */
        ifend = ifs + (ifc.ifc_len / sizeof(struct ifreq));
        for (ifr = ifc.ifc_req; ifr < ifend; ifr++)
        {
            if (ifr->ifr_addr.sa_family == AF_INET)
            {
                /* get interface addr */
                addr = ntohl(((struct sockaddr_in *) &ifr->ifr_addr)->sin_addr.s_addr);

                /* get interface name */
                strncpynt(ifreq.ifr_name, ifr->ifr_name, sizeof(ifreq.ifr_name));

                /* check that the interface is up */
                if (ioctl(sd, SIOCGIFFLAGS, &ifreq) < 0)
                {
                    continue;
                }
                if (!(ifreq.ifr_flags & IFF_UP))
                {
                    continue;
                }

                if (rgi->flags & RGI_ON_LINK)
                {
                    /* check that interface name of current interface
                     * matches interface name of best default route */
                    if (strcmp(ifreq.ifr_name, best_name))
                    {
                        continue;
                    }
#if 0
                    /* if point-to-point link, use remote addr as route gateway */
                    if ((ifreq.ifr_flags & IFF_POINTOPOINT) && ioctl(sd, SIOCGIFDSTADDR, &ifreq) >= 0)
                    {
                        rgi->gateway.addr = ntohl(((struct sockaddr_in *) &ifreq.ifr_addr)->sin_addr.s_addr);
                        if (rgi->gateway.addr)
                        {
                            rgi->flags &= ~RGI_ON_LINK;
                        }
                    }
#endif
                }
                else
                {
                    /* get interface netmask */
                    if (ioctl(sd, SIOCGIFNETMASK, &ifreq) < 0)
                    {
                        continue;
                    }
                    netmask = ntohl(((struct sockaddr_in *) &ifreq.ifr_addr)->sin_addr.s_addr);

                    /* check that interface matches default route */
                    if (((rgi->gateway.addr ^ addr) & netmask) != 0)
                    {
                        continue;
                    }

                    /* save netmask */
                    rgi->gateway.netmask = netmask;
                    rgi->flags |= RGI_NETMASK_DEFINED;
                }

                /* save iface name */
                strncpynt(rgi->iface, ifreq.ifr_name, sizeof(rgi->iface));
                rgi->flags |= RGI_IFACE_DEFINED;

                /* now get the hardware address. */
                memset(&ifreq.ifr_hwaddr, 0, sizeof(struct sockaddr));
                if (ioctl(sd, SIOCGIFHWADDR, &ifreq) < 0)
                {
                    msg(M_WARN, "GDG: SIOCGIFHWADDR(%s) failed", ifreq.ifr_name);
                    goto done;
                }
                memcpy(rgi->hwaddr, &ifreq.ifr_hwaddr.sa_data, 6);
                rgi->flags |= RGI_HWADDR_DEFINED;

                break;
            }
        }
    }

done:
    if (sd >= 0)
    {
        platform_close(sd);
    }
    gc_free(&gc);
}

/* IPv6 implementation using netlink
 * http://www.linuxjournal.com/article/7356
 * netlink(3), netlink(7), rtnetlink(7)
 * http://www.virtualbox.org/svn/vbox/trunk/src/VBox/NetworkServices/NAT/rtmon_linux.c
 */
struct rtreq {
    struct nlmsghdr nh;
    struct rtmsg rtm;
    char attrbuf[512];
};

void
get_default_gateway_ipv6(struct route_ipv6_gateway_info *rgi6,
                         const struct in6_addr *dest)
{
    int nls = -1;
    struct rtreq rtreq;
    struct rtattr *rta;

    char rtbuf[2000];
    ssize_t ssize;

    CLEAR(*rgi6);

    nls = platform_socket( PF_NETLINK, SOCK_RAW, NETLINK_ROUTE );
    if (nls < 0)
    {
        msg(M_WARN|M_ERRNO, "GDG6: socket() failed" ); goto done;
    }

    /* bind() is not needed, no unsolicited msgs coming in */

    /* request best matching route, see netlink(7) for explanations
     */
    CLEAR(rtreq);
    rtreq.nh.nlmsg_type = RTM_GETROUTE;
    rtreq.nh.nlmsg_flags = NLM_F_REQUEST;       /* best match only */
    rtreq.rtm.rtm_family = AF_INET6;
    rtreq.rtm.rtm_src_len = 0;                  /* not source dependent */
    rtreq.rtm.rtm_dst_len = 128;                /* exact dst */
    rtreq.rtm.rtm_table = RT_TABLE_MAIN;
    rtreq.rtm.rtm_protocol = RTPROT_UNSPEC;
    rtreq.nh.nlmsg_len = NLMSG_SPACE(sizeof(rtreq.rtm));

    /* set RTA_DST for target IPv6 address we want */
    rta = (struct rtattr *)(((char *) &rtreq)+NLMSG_ALIGN(rtreq.nh.nlmsg_len));
    rta->rta_type = RTA_DST;
    rta->rta_len = RTA_LENGTH(16);
    rtreq.nh.nlmsg_len = NLMSG_ALIGN(rtreq.nh.nlmsg_len)
                         +RTA_LENGTH(16);

    if (dest == NULL)                   /* ::, unspecified */
    {
        memset( RTA_DATA(rta), 0, 16 ); /* :: = all-zero */
    }
    else
    {
        memcpy( RTA_DATA(rta), (void *)dest, 16 );
    }

    /* send and receive reply */
    if (platform_send( nls, &rtreq, rtreq.nh.nlmsg_len, 0 ) < 0)
    {
        msg(M_WARN|M_ERRNO, "GDG6: send() failed" ); goto done;
    }

    ssize = platform_recv(nls, rtbuf, sizeof(rtbuf), MSG_TRUNC);

    if (ssize < 0)
    {
        msg(M_WARN|M_ERRNO, "GDG6: recv() failed" ); goto done;
    }

    if (ssize > sizeof(rtbuf))
    {
        msg(M_WARN, "get_default_gateway_ipv6: returned message too big for buffer (%d>%d)", (int)ssize, (int)sizeof(rtbuf) );
        goto done;
    }

    struct nlmsghdr *nh;

    for (nh = (struct nlmsghdr *)rtbuf;
         NLMSG_OK(nh, ssize);
         nh = NLMSG_NEXT(nh, ssize))
    {
        struct rtmsg *rtm;
        int attrlen;

        if (nh->nlmsg_type == NLMSG_DONE)
        {
            break;
        }

        if (nh->nlmsg_type == NLMSG_ERROR)
        {
            struct nlmsgerr *ne = (struct nlmsgerr *)NLMSG_DATA(nh);

            /* since linux-4.11 -ENETUNREACH is returned when no route can be
             * found. Don't print any error message in this case */
            if (ne->error != -ENETUNREACH)
            {
                msg(M_WARN, "GDG6: NLMSG_ERROR: error %s\n",
                    strerror(-ne->error));
            }
            break;
        }

        if (nh->nlmsg_type != RTM_NEWROUTE)
        {
            /* shouldn't happen */
            msg(M_WARN, "GDG6: unexpected msg_type %d", nh->nlmsg_type );
            continue;
        }

        rtm = (struct rtmsg *)NLMSG_DATA(nh);
        attrlen = RTM_PAYLOAD(nh);

        /* we're only looking for routes in the main table, as "we have
         * no IPv6" will lead to a lookup result in "Local" (::/0 reject)
         */
        if (rtm->rtm_family != AF_INET6
            || rtm->rtm_table != RT_TABLE_MAIN)
        {
            continue;
        }                               /* we're not interested */

        for (rta = RTM_RTA(rtm);
             RTA_OK(rta, attrlen);
             rta = RTA_NEXT(rta, attrlen))
        {
            if (rta->rta_type == RTA_GATEWAY)
            {
                if (RTA_PAYLOAD(rta) != sizeof(struct in6_addr) )
                {
                    msg(M_WARN, "GDG6: RTA_GW size mismatch"); continue;
                }
                rgi6->gateway.addr_ipv6 = *(struct in6_addr *) RTA_DATA(rta);
                rgi6->flags |= RGI_ADDR_DEFINED;
            }
            else if (rta->rta_type == RTA_OIF)
            {
                char ifname[IF_NAMESIZE+1];
                int oif;
                if (RTA_PAYLOAD(rta) != sizeof(oif) )
                {
                    msg(M_WARN, "GDG6: oif size mismatch"); continue;
                }

                memcpy(&oif, RTA_DATA(rta), sizeof(oif));
                if_indextoname(oif,ifname);
                strncpy( rgi6->iface, ifname, sizeof(rgi6->iface)-1 );
                rgi6->flags |= RGI_IFACE_DEFINED;
            }
        }
    }

    /* if we have an interface but no gateway, the destination is on-link */
    if ( ( rgi6->flags & (RGI_IFACE_DEFINED|RGI_ADDR_DEFINED) ) ==
         RGI_IFACE_DEFINED)
    {
        rgi6->flags |= (RGI_ADDR_DEFINED | RGI_ON_LINK);
        if (dest)
        {
            rgi6->gateway.addr_ipv6 = *dest;
        }
    }

done:
    if (nls >= 0)
    {
        platform_close(nls);
    }
}

#elif defined(TARGET_DARWIN) || defined(TARGET_SOLARIS)    \
    || defined(TARGET_FREEBSD) || defined(TARGET_DRAGONFLY)    \
    || defined(TARGET_OPENBSD) || defined(TARGET_NETBSD)

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <net/route.h>
#include <net/if_dl.h>

struct rtmsg {
    struct rt_msghdr m_rtm;
    char m_space[512];
};

/* the route socket code is identical for all 4 supported BSDs and for
 * MacOS X (Darwin), with one crucial difference: when going from
 * 32 bit to 64 bit, the BSDs increased the structure size but kept
 * source code compatibility by keeping the use of "long", while
 * MacOS X decided to keep binary compatibility by *changing* the API
 * to use "uint32_t", thus 32 bit on all OS X variants
 *
 * We used to have a large amount of duplicate code here which really
 * differed only in this (long) vs. (uint32_t) - IMHO, worse than
 * having a combined block for all BSDs with this single #ifdef inside
 */

#if defined(TARGET_DARWIN)
#define ROUNDUP(a) \
    ((a) > 0 ? (1 + (((a) - 1) | (sizeof(uint32_t) - 1))) : sizeof(uint32_t))
#else
#define ROUNDUP(a) \
    ((a) > 0 ? (1 + (((a) - 1) | (sizeof(long) - 1))) : sizeof(long))
#endif

#if defined(TARGET_SOLARIS)
#define NEXTADDR(w, u) \
    if (rtm_addrs & (w)) { \
        l = ROUNDUP(sizeof(u)); memmove(cp, &(u), l); cp += l; \
    }

#define ADVANCE(x, n) (x += ROUNDUP(sizeof(struct sockaddr_in)))
#else  /* if defined(TARGET_SOLARIS) */
#define NEXTADDR(w, u) \
    if (rtm_addrs & (w)) { \
        l = ROUNDUP( ((struct sockaddr *)&(u))->sa_len); memmove(cp, &(u), l); cp += l; \
    }

#define ADVANCE(x, n) (x += ROUNDUP((n)->sa_len))
#endif

#define max(a,b) ((a) > (b) ? (a) : (b))

void
get_default_gateway(struct route_gateway_info *rgi)
{
    struct gc_arena gc = gc_new();
    struct rtmsg m_rtmsg;
    int sockfd = -1;
    int seq, l, pid, rtm_addrs;
    unsigned int i;
    struct sockaddr so_dst, so_mask;
    char *cp = m_rtmsg.m_space;
    struct sockaddr *gate = NULL, *ifp = NULL, *sa;
    struct  rt_msghdr *rtm_aux;

#define rtm m_rtmsg.m_rtm

    CLEAR(*rgi);

    /* setup data to send to routing socket */
    pid = getpid();
    seq = 0;
    rtm_addrs = RTA_DST | RTA_NETMASK | RTA_IFP;

    bzero(&m_rtmsg, sizeof(m_rtmsg));
    bzero(&so_dst, sizeof(so_dst));
    bzero(&so_mask, sizeof(so_mask));
    bzero(&rtm, sizeof(struct rt_msghdr));

    rtm.rtm_type = RTM_GET;
    rtm.rtm_flags = RTF_UP | RTF_GATEWAY;
    rtm.rtm_version = RTM_VERSION;
    rtm.rtm_seq = ++seq;
#ifdef TARGET_OPENBSD
    rtm.rtm_tableid = getrtable();
#endif
    rtm.rtm_addrs = rtm_addrs;

    so_dst.sa_family = AF_INET;
    so_mask.sa_family = AF_INET;

#ifndef TARGET_SOLARIS
    so_dst.sa_len = sizeof(struct sockaddr_in);
    so_mask.sa_len = sizeof(struct sockaddr_in);
#endif

    NEXTADDR(RTA_DST, so_dst);
    NEXTADDR(RTA_NETMASK, so_mask);

    rtm.rtm_msglen = l = cp - (char *)&m_rtmsg;

    /* transact with routing socket */
    sockfd = platform_socket(PF_ROUTE, SOCK_RAW, 0);
    if (sockfd < 0)
    {
        msg(M_WARN, "GDG: socket #1 failed");
        goto done;
    }
    if (platform_write(sockfd, (char *)&m_rtmsg, l) < 0)
    {
        msg(M_WARN, "GDG: problem writing to routing socket");
        goto done;
    }
    do
    {
        l = platform_read(sockfd, (char *)&m_rtmsg, sizeof(m_rtmsg));
    } while (l > 0 && (rtm.rtm_seq != seq || rtm.rtm_pid != pid));
    platform_close(sockfd);
    sockfd = -1;

    /* extract return data from routing socket */
    rtm_aux = &rtm;
    cp = ((char *)(rtm_aux + 1));
    if (rtm_aux->rtm_addrs)
    {
        for (i = 1; i; i <<= 1)
        {
            if (i & rtm_aux->rtm_addrs)
            {
                sa = (struct sockaddr *)cp;
                if (i == RTA_GATEWAY)
                {
                    gate = sa;
                }
                else if (i == RTA_IFP)
                {
                    ifp = sa;
                }
                ADVANCE(cp, sa);
            }
        }
    }
    else
    {
        goto done;
    }

    /* get gateway addr and interface name */
    if (gate != NULL)
    {
        /* get default gateway addr */
        rgi->gateway.addr = ntohl(((struct sockaddr_in *)gate)->sin_addr.s_addr);
        if (rgi->gateway.addr)
        {
            rgi->flags |= RGI_ADDR_DEFINED;
        }

        if (ifp)
        {
            /* get interface name */
            const struct sockaddr_dl *adl = (struct sockaddr_dl *) ifp;
            if (adl->sdl_nlen && adl->sdl_nlen < sizeof(rgi->iface))
            {
                memcpy(rgi->iface, adl->sdl_data, adl->sdl_nlen);
                rgi->iface[adl->sdl_nlen] = '\0';
                rgi->flags |= RGI_IFACE_DEFINED;
            }
        }
    }

    /* get netmask of interface that owns default gateway */
    if (rgi->flags & RGI_IFACE_DEFINED)
    {
        struct ifreq ifr;

        sockfd = platform_socket(AF_INET, SOCK_DGRAM, 0);
        if (sockfd < 0)
        {
            msg(M_WARN, "GDG: socket #2 failed");
            goto done;
        }

        CLEAR(ifr);
        ifr.ifr_addr.sa_family = AF_INET;
        strncpynt(ifr.ifr_name, rgi->iface, IFNAMSIZ);

        if (ioctl(sockfd, SIOCGIFNETMASK, (char *)&ifr) < 0)
        {
            msg(M_WARN, "GDG: ioctl #1 failed");
            goto done;
        }
        platform_close(sockfd);
        sockfd = -1;

        rgi->gateway.netmask = ntohl(((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr.s_addr);
        rgi->flags |= RGI_NETMASK_DEFINED;
    }

    /* try to read MAC addr associated with interface that owns default gateway */
    if (rgi->flags & RGI_IFACE_DEFINED)
    {
        struct ifconf ifc;
        struct ifreq *ifr;
        const int bufsize = 4096;
        char *buffer;

        buffer = (char *) gc_malloc(bufsize, true, &gc);
        sockfd = platform_socket(AF_INET, SOCK_DGRAM, 0);
        if (sockfd < 0)
        {
            msg(M_WARN, "GDG: socket #3 failed");
            goto done;
        }

        ifc.ifc_len = bufsize;
        ifc.ifc_buf = buffer;

        if (ioctl(sockfd, SIOCGIFCONF, (char *)&ifc) < 0)
        {
            msg(M_WARN, "GDG: ioctl #2 failed");
            goto done;
        }
        platform_close(sockfd);
        sockfd = -1;

        for (cp = buffer; cp <= buffer + ifc.ifc_len - sizeof(struct ifreq); )
        {
            ifr = (struct ifreq *)cp;
#if defined(TARGET_SOLARIS)
            const size_t len = sizeof(ifr->ifr_name) + sizeof(ifr->ifr_addr);
#else
            const size_t len = sizeof(ifr->ifr_name) + max(sizeof(ifr->ifr_addr), ifr->ifr_addr.sa_len);
#endif

            if (!ifr->ifr_addr.sa_family)
            {
                break;
            }
            if (!strncmp(ifr->ifr_name, rgi->iface, IFNAMSIZ))
            {
                if (ifr->ifr_addr.sa_family == AF_LINK)
                {
                    struct sockaddr_dl *sdl = (struct sockaddr_dl *)&ifr->ifr_addr;
                    memcpy(rgi->hwaddr, LLADDR(sdl), 6);
                    rgi->flags |= RGI_HWADDR_DEFINED;
                }
            }
            cp += len;
        }
    }

done:
    if (sockfd >= 0)
    {
        platform_close(sockfd);
    }
    gc_free(&gc);
}

/* BSD implementation using routing socket (as does IPv4)
 * (the code duplication is somewhat unavoidable if we want this to
 * work on OpenSolaris as well.  *sigh*)
 */

/* Solaris has no length field - this is ugly, but less #ifdef in total
 */
#if defined(TARGET_SOLARIS)
#undef ADVANCE
#define ADVANCE(x, n) (x += ROUNDUP(sizeof(struct sockaddr_in6)))
#endif

void
get_default_gateway_ipv6(struct route_ipv6_gateway_info *rgi6,
                         const struct in6_addr *dest)
{

    struct rtmsg m_rtmsg;
    int sockfd = -1;
    int seq, l, pid, rtm_addrs;
    unsigned int i;
    struct sockaddr_in6 so_dst, so_mask;
    char *cp = m_rtmsg.m_space;
    struct sockaddr *gate = NULL, *ifp = NULL, *sa;
    struct rt_msghdr *rtm_aux;

    CLEAR(*rgi6);

    /* setup data to send to routing socket */
    pid = getpid();
    seq = 0;
    rtm_addrs = RTA_DST | RTA_NETMASK | RTA_IFP;

    bzero(&m_rtmsg, sizeof(m_rtmsg));
    bzero(&so_dst, sizeof(so_dst));
    bzero(&so_mask, sizeof(so_mask));
    bzero(&rtm, sizeof(struct rt_msghdr));

    rtm.rtm_type = RTM_GET;
    rtm.rtm_flags = RTF_UP;
    rtm.rtm_version = RTM_VERSION;
    rtm.rtm_seq = ++seq;
#ifdef TARGET_OPENBSD
    rtm.rtm_tableid = getrtable();
#endif

    so_dst.sin6_family = AF_INET6;
    so_mask.sin6_family = AF_INET6;

    if (dest != NULL                    /* specific host? */
        && !IN6_IS_ADDR_UNSPECIFIED(dest) )
    {
        so_dst.sin6_addr = *dest;
        /* :: needs /0 "netmask", host route wants "no netmask */
        rtm_addrs &= ~RTA_NETMASK;
    }

    rtm.rtm_addrs = rtm_addrs;

#ifndef TARGET_SOLARIS
    so_dst.sin6_len = sizeof(struct sockaddr_in6);
    so_mask.sin6_len = sizeof(struct sockaddr_in6);
#endif

    NEXTADDR(RTA_DST, so_dst);
    NEXTADDR(RTA_NETMASK, so_mask);

    rtm.rtm_msglen = l = cp - (char *)&m_rtmsg;

    /* transact with routing socket */
    sockfd = platform_socket(PF_ROUTE, SOCK_RAW, 0);
    if (sockfd < 0)
    {
        msg(M_WARN, "GDG6: socket #1 failed");
        goto done;
    }
    if (platform_write(sockfd, (char *)&m_rtmsg, l) < 0)
    {
        msg(M_WARN, "GDG6: problem writing to routing socket");
        goto done;
    }

    do
    {
        l = platform_read(sockfd, (char *)&m_rtmsg, sizeof(m_rtmsg));
    }
    while (l > 0 && (rtm.rtm_seq != seq || rtm.rtm_pid != pid));

    platform_close(sockfd);
    sockfd = -1;

    /* extract return data from routing socket */
    rtm_aux = &rtm;
    cp = ((char *)(rtm_aux + 1));
    if (rtm_aux->rtm_addrs)
    {
        for (i = 1; i; i <<= 1)
        {
            if (i & rtm_aux->rtm_addrs)
            {
                sa = (struct sockaddr *)cp;
                if (i == RTA_GATEWAY)
                {
                    gate = sa;
                }
                else if (i == RTA_IFP)
                {
                    ifp = sa;
                }
                ADVANCE(cp, sa);
            }
        }
    }
    else
    {
        goto done;
    }

    /* get gateway addr and interface name */
    if (gate != NULL)
    {
        struct sockaddr_in6 *s6 = (struct sockaddr_in6 *)gate;
        struct in6_addr gw = s6->sin6_addr;

#ifndef TARGET_SOLARIS
        /* You do not really want to know... from FreeBSD's route.c
         * (KAME encodes the 16 bit scope_id in s6_addr[2] + [3],
         * but for a correct link-local address these must be :0000: )
         */
        if (gate->sa_len == sizeof(struct sockaddr_in6)
            && IN6_IS_ADDR_LINKLOCAL(&gw) )
        {
            gw.s6_addr[2] = gw.s6_addr[3] = 0;
        }

        if (gate->sa_len != sizeof(struct sockaddr_in6)
            || IN6_IS_ADDR_UNSPECIFIED(&gw) )
        {
            rgi6->flags |= RGI_ON_LINK;
        }
        else
#endif

        rgi6->gateway.addr_ipv6 = gw;
        rgi6->flags |= RGI_ADDR_DEFINED;

        if (ifp)
        {
            /* get interface name */
            const struct sockaddr_dl *adl = (struct sockaddr_dl *) ifp;
            if (adl->sdl_nlen && adl->sdl_nlen < sizeof(rgi6->iface))
            {
                memcpy(rgi6->iface, adl->sdl_data, adl->sdl_nlen);
                rgi6->flags |= RGI_IFACE_DEFINED;
            }
        }
    }

done:
    if (sockfd >= 0)
    {
        platform_close(sockfd);
    }
}

#undef max

#else  /* if defined(_WIN32) */

/*
 * This is a platform-specific method that returns data about
 * the current default gateway.  Return data is placed into
 * a struct route_gateway_info object provided by caller.  The
 * implementation should CLEAR the structure before adding
 * data to it.
 *
 * Data returned includes:
 * 1. default gateway address (rgi->gateway.addr)
 * 2. netmask of interface that owns default gateway
 *    (rgi->gateway.netmask)
 * 3. hardware address (i.e. MAC address) of interface that owns
 *    default gateway (rgi->hwaddr)
 * 4. interface name (or adapter index on Windows) that owns default
 *    gateway (rgi->iface or rgi->adapter_index)
 * 5. an array of additional address/netmask pairs defined by
 *    interface that owns default gateway (rgi->addrs with length
 *    given in rgi->n_addrs)
 *
 * The flags RGI_x_DEFINED may be used to indicate which of the data
 * members were successfully returned (set in rgi->flags).  All of
 * the data members are optional, however certain OpenVPN functionality
 * may be disabled by missing items.
 */
void
get_default_gateway(struct route_gateway_info *rgi)
{
    CLEAR(*rgi);
}
void
get_default_gateway_ipv6(struct route_ipv6_gateway_info *rgi6,
                         const struct in6_addr *dest)
{
    msg(D_ROUTE, "no support for get_default_gateway_ipv6() on this system");
    CLEAR(*rgi6);
}

#endif /* if defined(_WIN32) */

bool
netmask_to_netbits(const in_addr_t network, const in_addr_t netmask, int *netbits)
{
    int i;
    const int addrlen = sizeof(in_addr_t) * 8;

    if ((network & netmask) == network)
    {
        for (i = 0; i <= addrlen; ++i)
        {
            in_addr_t mask = netbits_to_netmask(i);
            if (mask == netmask)
            {
                if (i == addrlen)
                {
                    *netbits = -1;
                }
                else
                {
                    *netbits = i;
                }
                return true;
            }
        }
    }
    return false;
}

/* similar to netmask_to_netbits(), but don't mess with base address
 * etc., just convert to netbits - non-mappable masks are returned as "-1"
 */
int
netmask_to_netbits2(in_addr_t netmask)
{
    int i;
    const int addrlen = sizeof(in_addr_t) * 8;

    for (i = 0; i <= addrlen; ++i)
    {
        in_addr_t mask = netbits_to_netmask(i);
        if (mask == netmask)
        {
            return i;
        }
    }
    return -1;
}


/*
 * get_bypass_addresses() is used by the redirect-gateway bypass-x
 * functions to build a route bypass to selected DHCP/DNS servers,
 * so that outgoing packets to these servers don't end up in the tunnel.
 */

#if defined(_WIN32)

static void
add_host_route_if_nonlocal(struct route_bypass *rb, const in_addr_t addr)
{
    if (test_local_addr(addr, NULL) == TLA_NONLOCAL && addr != 0 && addr != IPV4_NETMASK_HOST)
    {
        add_bypass_address(rb, addr);
    }
}

static void
add_host_route_array(struct route_bypass *rb, const IP_ADDR_STRING *iplist)
{
    while (iplist)
    {
        bool succeed = false;
        const in_addr_t ip = getaddr(GETADDR_HOST_ORDER, iplist->IpAddress.String, 0, &succeed, NULL);
        if (succeed)
        {
            add_host_route_if_nonlocal(rb, ip);
        }
        iplist = iplist->Next;
    }
}

static void
get_bypass_addresses(struct route_bypass *rb, const unsigned int flags)
{
    struct gc_arena gc = gc_new();
    /*bool ret_bool = false;*/

    /* get full routing table */
    const MIB_IPFORWARDTABLE *routes = get_windows_routing_table(&gc);

    /* get the route which represents the default gateway */
    const MIB_IPFORWARDROW *row = get_default_gateway_row(routes);

    if (row)
    {
        /* get the adapter which the default gateway is associated with */
        const IP_ADAPTER_INFO *dgi = get_adapter_info(row->dwForwardIfIndex, &gc);

        /* get extra adapter info, such as DNS addresses */
        const IP_PER_ADAPTER_INFO *pai = get_per_adapter_info(row->dwForwardIfIndex, &gc);

        /* Bypass DHCP server address */
        if ((flags & RG_BYPASS_DHCP) && dgi && dgi->DhcpEnabled)
        {
            add_host_route_array(rb, &dgi->DhcpServer);
        }

        /* Bypass DNS server addresses */
        if ((flags & RG_BYPASS_DNS) && pai)
        {
            add_host_route_array(rb, &pai->DnsServerList);
        }
    }

    gc_free(&gc);
}

#else  /* if defined(_WIN32) */

static void
get_bypass_addresses(struct route_bypass *rb, const unsigned int flags)   /* PLATFORM-SPECIFIC */
{
}

#endif /* if defined(_WIN32) */

/*
 * Test if addr is reachable via a local interface (return ILA_LOCAL),
 * or if it needs to be routed via the default gateway (return
 * ILA_NONLOCAL).  If the target platform doesn't implement this
 * function, return ILA_NOT_IMPLEMENTED.
 *
 * Used by redirect-gateway autolocal feature
 */

#if defined(_WIN32)

int
test_local_addr(const in_addr_t addr, const struct route_gateway_info *rgi)
{
    struct gc_arena gc = gc_new();
    const in_addr_t nonlocal_netmask = 0x80000000L; /* routes with netmask <= to this are considered non-local */
    int ret = TLA_NONLOCAL;

    /* get full routing table */
    const MIB_IPFORWARDTABLE *rt = get_windows_routing_table(&gc);
    if (rt)
    {
        int i;
        for (i = 0; i < rt->dwNumEntries; ++i)
        {
            const MIB_IPFORWARDROW *row = &rt->table[i];
            const in_addr_t net = ntohl(row->dwForwardDest);
            const in_addr_t mask = ntohl(row->dwForwardMask);
            if (mask > nonlocal_netmask && (addr & mask) == net)
            {
                ret = TLA_LOCAL;
                break;
            }
        }
    }

    gc_free(&gc);
    return ret;
}

#else  /* if defined(_WIN32) */

int
test_local_addr(const in_addr_t addr, const struct route_gateway_info *rgi)  /* PLATFORM-SPECIFIC */
{
    if (rgi)
    {
        if (local_route(addr, 0xFFFFFFFF, rgi->gateway.addr, rgi))
        {
            return TLA_LOCAL;
        }
        else
        {
            return TLA_NONLOCAL;
        }
    }
    return TLA_NOT_IMPLEMENTED;
}

#endif /* if defined(_WIN32) */
