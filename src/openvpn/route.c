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

/*
 * Support routines for adding/deleting network routes.
 */
#include <stddef.h>
#include <stdbool.h>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "syshead.h"

#include "common.h"
#include "error.h"
#include "route.h"
#include "run_command.h"
#include "socket.h"
#include "manage.h"
#include "win32.h"
#include "options.h"
#include "networking.h"
#include "integer.h"

#include "memdbg.h"

#if defined(TARGET_LINUX) || defined(TARGET_ANDROID)
#include <linux/rtnetlink.h> /* RTM_GETROUTE etc. */
#endif

#if defined(TARGET_NETBSD)
#include <net/route.h> /* RT_ROUNDUP(), RT_ADVANCE() */
#endif


static void delete_route(struct route_ipv4 *r, const struct tuntap *tt, unsigned int flags,
                         const struct route_gateway_info *rgi, const struct env_set *es,
                         openvpn_net_ctx_t *ctx);

static void get_bypass_addresses(struct route_bypass *rb, const unsigned int flags);

#ifdef ENABLE_DEBUG

static void
print_bypass_addresses(const struct route_bypass *rb)
{
    struct gc_arena gc = gc_new();
    int i;
    for (i = 0; i < rb->n_bypass; ++i)
    {
        msg(D_ROUTE, "ROUTE: bypass_host_route[%d]=%s", i, print_in_addr_t(rb->bypass[i], 0, &gc));
    }
    gc_free(&gc);
}

#endif

/* Route addition return status codes */
#define RTA_ERROR   0 /* route addition failed */
#define RTA_SUCCESS 1 /* route addition succeeded */
#define RTA_EEXIST  2 /* route not added as it already exists */

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
copy_route_option_list(struct route_option_list *dest, const struct route_option_list *src,
                       struct gc_arena *a)
{
    *dest = *src;
    dest->gc = a;
}

void
copy_route_ipv6_option_list(struct route_ipv6_option_list *dest,
                            const struct route_ipv6_option_list *src, struct gc_arena *a)
{
    *dest = *src;
    dest->gc = a;
}

static const char *
route_string(const struct route_ipv4 *r, struct gc_arena *gc)
{
    struct buffer out = alloc_buf_gc(256, gc);
    buf_printf(&out, "ROUTE network %s netmask %s gateway %s", print_in_addr_t(r->network, 0, gc),
               print_in_addr_t(r->netmask, 0, gc), print_in_addr_t(r->gateway, 0, gc));
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
get_special_addr(const struct route_list *rl, const char *string, in_addr_t *out, bool *status)
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
            if (rl->ngi.flags & RGI_ADDR_DEFINED)
            {
                *out = rl->ngi.gateway.addr;
            }
            else
            {
                msg(M_INFO, PACKAGE_NAME
                    " ROUTE: net_gateway undefined -- unable to get default gateway from system");
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
init_route(struct route_ipv4 *r, struct addrinfo **network_list, const struct route_option *ro,
           const struct route_list *rl)
{
    const in_addr_t default_netmask = IPV4_NETMASK_HOST;
    bool status;
    int ret;
    struct in_addr special = { 0 };

    CLEAR(*r);
    r->option = ro;

    /* network */
    if (!is_route_parm_defined(ro->network))
    {
        goto fail;
    }

    /* get_special_addr replaces specialaddr with a special ip addr
     * like gw. getaddrinfo is called to convert a a addrinfo struct */

    if (get_special_addr(rl, ro->network, (in_addr_t *)&special.s_addr, &status))
    {
        if (!status)
        {
            goto fail;
        }
        special.s_addr = htonl(special.s_addr);
        char buf[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &special, buf, sizeof(buf));
        ret = openvpn_getaddrinfo(0, buf, NULL, 0, NULL, AF_INET, network_list);
    }
    else
    {
        ret = openvpn_getaddrinfo(GETADDR_RESOLVE | GETADDR_WARN_ON_SIGNAL, ro->network, NULL, 0,
                                  NULL, AF_INET, network_list);
    }

    status = (ret == 0);

    if (!status)
    {
        goto fail;
    }

    /* netmask */

    if (is_route_parm_defined(ro->netmask))
    {
        r->netmask =
            getaddr(GETADDR_HOST_ORDER | GETADDR_WARN_ON_SIGNAL, ro->netmask, 0, &status, NULL);
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
            r->gateway = getaddr(GETADDR_RESOLVE | GETADDR_HOST_ORDER | GETADDR_WARN_ON_SIGNAL,
                                 ro->gateway, 0, &status, NULL);
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
            msg(M_WARN, PACKAGE_NAME
                " ROUTE: " PACKAGE_NAME
                " needs a gateway parameter for a --route option and no default was specified by either --route-gateway or --ifconfig options");
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
                ro->network, ro->metric);
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

    /* routing table id */
    r->table_id = ro->table_id;

    return true;

fail:
    msg(M_WARN, PACKAGE_NAME " ROUTE: failed to parse/resolve route for host/network: %s",
        ro->network);
    return false;
}

static bool
init_route_ipv6(struct route_ipv6 *r6, const struct route_ipv6_option *r6o,
                const struct route_ipv6_list *rl6)
{
    CLEAR(*r6);

    if (!get_ipv6_addr(r6o->prefix, &r6->network, &r6->netbits, M_WARN))
    {
        goto fail;
    }

    /* gateway */
    if (is_route_parm_defined(r6o->gateway))
    {
        if (inet_pton(AF_INET6, r6o->gateway, &r6->gateway) != 1)
        {
            msg(M_WARN, PACKAGE_NAME "ROUTE6: cannot parse gateway spec '%s'", r6o->gateway);
        }
    }
    else if (rl6->spec_flags & RTSA_REMOTE_ENDPOINT)
    {
        r6->gateway = rl6->remote_endpoint_ipv6;
    }

    /* metric */

    r6->metric = -1;
    if (is_route_parm_defined(r6o->metric))
    {
        r6->metric = atoi(r6o->metric);
        if (r6->metric < 0)
        {
            msg(M_WARN, PACKAGE_NAME " ROUTE: route metric for network %s (%s) must be >= 0",
                r6o->prefix, r6o->metric);
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

    /* routing table id */
    r6->table_id = r6o->table_id;

    return true;

fail:
    msg(M_WARN, PACKAGE_NAME " ROUTE: failed to parse/resolve route for host/network: %s",
        r6o->prefix);
    return false;
}

void
add_route_to_option_list(struct route_option_list *l, const char *network, const char *netmask,
                         const char *gateway, const char *metric, int table_id)
{
    struct route_option *ro;
    ALLOC_OBJ_GC(ro, struct route_option, l->gc);
    ro->network = network;
    ro->netmask = netmask;
    ro->gateway = gateway;
    ro->metric = metric;
    ro->table_id = table_id;
    ro->next = l->routes;
    l->routes = ro;
}

void
add_route_ipv6_to_option_list(struct route_ipv6_option_list *l, const char *prefix,
                              const char *gateway, const char *metric, int table_id)
{
    struct route_ipv6_option *ro;
    ALLOC_OBJ_GC(ro, struct route_ipv6_option, l->gc);
    ro->prefix = prefix;
    ro->gateway = gateway;
    ro->metric = metric;
    ro->table_id = table_id;
    ro->next = l->routes_ipv6;
    l->routes_ipv6 = ro;
}

static void
clear_route_list(struct route_list *rl)
{
    gc_free(&rl->gc);
    CLEAR(*rl);
}

static void
clear_route_ipv6_list(struct route_ipv6_list *rl6)
{
    gc_free(&rl6->gc);
    CLEAR(*rl6);
}

void
route_list_add_vpn_gateway(struct route_list *rl, struct env_set *es, const in_addr_t addr)
{
    ASSERT(rl);
    rl->spec.remote_endpoint = addr;
    rl->spec.flags |= RTSA_REMOTE_ENDPOINT;
    setenv_route_addr(es, "vpn_gateway", rl->spec.remote_endpoint, -1);
}

static void
add_block_local_item(struct route_list *rl, const struct route_gateway_address *gateway,
                     in_addr_t target)
{
    if (rl->rgi.gateway.netmask < 0xFFFFFFFF)
    {
        struct route_ipv4 *r1, *r2;
        unsigned int l2;

        ALLOC_OBJ_GC(r1, struct route_ipv4, &rl->gc);
        ALLOC_OBJ_GC(r2, struct route_ipv4, &rl->gc);

        /* split a route into two smaller blocking routes, and direct them to target */
        l2 = ((~gateway->netmask) + 1) >> 1;
        r1->flags = RT_DEFINED;
        r1->gateway = target;
        r1->network = gateway->addr & gateway->netmask;
        r1->netmask = ~(l2 - 1);
        r1->next = rl->routes;
        rl->routes = r1;

        *r2 = *r1;
        r2->network += l2;
        r2->next = rl->routes;
        rl->routes = r2;
    }
}

static void
add_block_local_routes(struct route_list *rl)
{
#ifndef TARGET_ANDROID
    /* add bypass for gateway addr */
    add_bypass_address(&rl->spec.bypass, rl->rgi.gateway.addr);
#endif

    /* block access to local subnet */
    add_block_local_item(rl, &rl->rgi.gateway, rl->spec.remote_endpoint);

    /* process additional subnets on gateway interface */
    for (size_t i = 0; i < rl->rgi.n_addrs; ++i)
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

bool
block_local_needed(const struct route_list *rl)
{
    const int rgi_needed = (RGI_ADDR_DEFINED | RGI_NETMASK_DEFINED);
    return (rl->flags & RG_BLOCK_LOCAL) && (rl->rgi.flags & rgi_needed) == rgi_needed
           && (rl->spec.flags & RTSA_REMOTE_ENDPOINT) && rl->spec.remote_host_local != TLA_LOCAL;
}

bool
init_route_list(struct route_list *rl, const struct route_option_list *opt,
                const char *remote_endpoint, int default_metric, in_addr_t remote_host,
                struct env_set *es, openvpn_net_ctx_t *ctx)
{
    struct gc_arena gc = gc_new();
    bool ret = true;

    clear_route_list(rl);

    rl->flags = opt->flags;

    if (remote_host != IPV4_INVALID_ADDR)
    {
        rl->spec.remote_host = remote_host;
        rl->spec.flags |= RTSA_REMOTE_HOST;
    }

    if (default_metric)
    {
        rl->spec.default_metric = default_metric;
        rl->spec.flags |= RTSA_DEFAULT_METRIC;
    }

    get_default_gateway(&rl->ngi, INADDR_ANY, ctx);
    if (rl->ngi.flags & RGI_ADDR_DEFINED)
    {
        setenv_route_addr(es, "net_gateway", rl->ngi.gateway.addr, -1);
#if defined(ENABLE_DEBUG) && !defined(ENABLE_SMALL)
        print_default_gateway(D_ROUTE, &rl->rgi, NULL);
#endif
    }
    else
    {
        dmsg(D_ROUTE, "ROUTE: default_gateway=UNDEF");
    }

    get_default_gateway(&rl->rgi, remote_host != IPV4_INVALID_ADDR ? remote_host : INADDR_ANY, ctx);

    if (rl->spec.flags & RTSA_REMOTE_HOST)
    {
        rl->spec.remote_host_local = test_local_addr(remote_host, &rl->rgi);
    }

    if (is_route_parm_defined(remote_endpoint))
    {
        bool defined = false;
        rl->spec.remote_endpoint =
            getaddr(GETADDR_RESOLVE | GETADDR_HOST_ORDER | GETADDR_WARN_ON_SIGNAL, remote_endpoint,
                    0, &defined, NULL);

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
        if (block_local_needed(rl))
        {
            add_block_local_routes(rl);
        }
        get_bypass_addresses(&rl->spec.bypass, rl->flags);
#ifdef ENABLE_DEBUG
        print_bypass_addresses(&rl->spec.bypass);
#endif
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

bool
ipv6_net_contains_host(const struct in6_addr *network, unsigned int bits, const struct in6_addr *host)
{
    /* not the most beautiful implementation in the world, but portable and
     * "good enough" */
    if (bits > 128)
    {
        return false;
    }

    int i;
    for (i = 0; bits >= 8; i++, bits -= 8)
    {
        if (network->s6_addr[i] != host->s6_addr[i])
        {
            return false;
        }
    }

    if (bits == 0)
    {
        return true;
    }

    unsigned int mask = 0xff << (8 - bits);

    if ((network->s6_addr[i] & mask) == (host->s6_addr[i] & mask))
    {
        return true;
    }

    return false;
}

bool
init_route_ipv6_list(struct route_ipv6_list *rl6, const struct route_ipv6_option_list *opt6,
                     const char *remote_endpoint, int default_metric,
                     const struct in6_addr *remote_host_ipv6, struct env_set *es,
                     openvpn_net_ctx_t *ctx)
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
        remote_host_ipv6 ? print_in6_addr(*remote_host_ipv6, 0, &gc) : "n/a");

    get_default_gateway_ipv6(&rl6->ngi6, NULL, ctx);
    if (rl6->ngi6.flags & RGI_ADDR_DEFINED)
    {
        setenv_str(es, "net_gateway_ipv6", print_in6_addr(rl6->ngi6.gateway.addr_ipv6, 0, &gc));
#if defined(ENABLE_DEBUG) && !defined(ENABLE_SMALL)
        print_default_gateway(D_ROUTE, NULL, &rl6->rgi6);
#endif
    }
    else
    {
        dmsg(D_ROUTE, "ROUTE6: default_gateway=UNDEF");
    }

    get_default_gateway_ipv6(&rl6->rgi6, remote_host_ipv6, ctx);

    if (is_route_parm_defined(remote_endpoint))
    {
        if (inet_pton(AF_INET6, remote_endpoint, &rl6->remote_endpoint_ipv6) == 1)
        {
            rl6->spec_flags |= RTSA_REMOTE_ENDPOINT;
        }
        else
        {
            msg(M_WARN, PACKAGE_NAME " ROUTE: failed to parse/resolve VPN endpoint: %s",
                remote_endpoint);
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
                    && ipv6_net_contains_host(&r6->network, r6->netbits, remote_host_ipv6))
                {
                    need_remote_ipv6_route = true;
                    msg(D_ROUTE,
                        "ROUTE6: %s/%d overlaps IPv6 remote %s, adding host route to VPN endpoint",
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
        if ((rl6->rgi6.flags & (RGI_ADDR_DEFINED | RGI_IFACE_DEFINED))
            == (RGI_ADDR_DEFINED | RGI_IFACE_DEFINED))
        {
            struct route_ipv6 *r6;
            ALLOC_OBJ_CLEAR_GC(r6, struct route_ipv6, &rl6->gc);

            r6->network = *remote_host_ipv6;
            r6->netbits = 128;
            if (!(rl6->rgi6.flags & RGI_ON_LINK))
            {
                r6->gateway = rl6->rgi6.gateway.addr_ipv6;
            }
            r6->metric = 1;
            r6->iface = rl6->rgi6.iface;
            r6->flags = RT_DEFINED | RT_METRIC_DEFINED;

            r6->next = rl6->routes_ipv6;
            rl6->routes_ipv6 = r6;
        }
        else
        {
            msg(M_WARN,
                "ROUTE6: IPv6 route overlaps with IPv6 remote address, but could not determine IPv6 gateway address + interface, expect failure\n");
        }
    }

    gc_free(&gc);
    return ret;
}

static bool
add_route3(in_addr_t network, in_addr_t netmask, in_addr_t gateway, const struct tuntap *tt,
           unsigned int flags, const struct route_gateway_info *rgi, const struct env_set *es,
           openvpn_net_ctx_t *ctx)
{
    struct route_ipv4 r;
    CLEAR(r);
    r.flags = RT_DEFINED;
    r.network = network;
    r.netmask = netmask;
    r.gateway = gateway;
    return add_route(&r, tt, flags, rgi, es, ctx);
}

static void
del_route3(in_addr_t network, in_addr_t netmask, in_addr_t gateway, const struct tuntap *tt,
           unsigned int flags, const struct route_gateway_info *rgi, const struct env_set *es,
           openvpn_net_ctx_t *ctx)
{
    struct route_ipv4 r;
    CLEAR(r);
    r.flags = RT_DEFINED | RT_ADDED;
    r.network = network;
    r.netmask = netmask;
    r.gateway = gateway;
    delete_route(&r, tt, flags, rgi, es, ctx);
}

static bool
add_bypass_routes(struct route_bypass *rb, in_addr_t gateway, const struct tuntap *tt,
                  unsigned int flags, const struct route_gateway_info *rgi,
                  const struct env_set *es, openvpn_net_ctx_t *ctx)
{
    int ret = true;
    for (int i = 0; i < rb->n_bypass; ++i)
    {
        if (rb->bypass[i])
        {
            ret = add_route3(rb->bypass[i], IPV4_NETMASK_HOST, gateway, tt, flags | ROUTE_REF_GW,
                             rgi, es, ctx)
                  && ret;
        }
    }
    return ret;
}

static void
del_bypass_routes(struct route_bypass *rb, in_addr_t gateway, const struct tuntap *tt,
                  unsigned int flags, const struct route_gateway_info *rgi,
                  const struct env_set *es, openvpn_net_ctx_t *ctx)
{
    int i;
    for (i = 0; i < rb->n_bypass; ++i)
    {
        if (rb->bypass[i])
        {
            del_route3(rb->bypass[i], IPV4_NETMASK_HOST, gateway, tt, flags | ROUTE_REF_GW, rgi, es,
                       ctx);
        }
    }
}

static bool
redirect_default_route_to_vpn(struct route_list *rl, const struct tuntap *tt, unsigned int flags,
                              const struct env_set *es, openvpn_net_ctx_t *ctx)
{
    const char err[] = "NOTE: unable to redirect IPv4 default gateway --";
    bool ret = true;

    if (rl && rl->flags & RG_ENABLE)
    {
        bool local = rl->flags & RG_LOCAL;

        if (!(rl->spec.flags & RTSA_REMOTE_ENDPOINT) && (rl->flags & RG_REROUTE_GW))
        {
            msg(M_WARN, "%s VPN gateway parameter (--route-gateway or --ifconfig) is missing", err);
            ret = false;
        }
        /*
         * check if a default route is defined, unless:
         * - we are connecting to a remote host in our network
         * - we are connecting to a non-IPv4 remote host (i.e. we use IPv6)
         */
        else if (!(rl->rgi.flags & RGI_ADDR_DEFINED) && !local
                 && (rl->spec.flags & RTSA_REMOTE_HOST))
        {
            msg(M_WARN, "%s Cannot read current default gateway from system", err);
            ret = false;
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
                if ((rl->spec.flags & RTSA_REMOTE_HOST)
                    && rl->spec.remote_host != IPV4_INVALID_ADDR)
                {
                    ret = add_route3(rl->spec.remote_host, IPV4_NETMASK_HOST, rl->rgi.gateway.addr,
                                     tt, flags | ROUTE_REF_GW, &rl->rgi, es, ctx);
                    if (ret)
                    {
                        rl->iflags |= RL_DID_LOCAL;
                    }
                }
                else
                {
                    dmsg(D_ROUTE, "ROUTE remote_host protocol differs from tunneled");
                }
            }
#endif /* ifndef TARGET_ANDROID */

            /* route DHCP/DNS server traffic through original default gateway */
            ret = add_bypass_routes(&rl->spec.bypass, rl->rgi.gateway.addr, tt, flags, &rl->rgi, es,
                                    ctx)
                  && ret;

            if (rl->flags & RG_REROUTE_GW)
            {
                if (rl->flags & RG_DEF1)
                {
                    /* add new default route (1st component) */
                    ret = add_route3(0x00000000, 0x80000000, rl->spec.remote_endpoint, tt, flags,
                                     &rl->rgi, es, ctx)
                          && ret;

                    /* add new default route (2nd component) */
                    ret = add_route3(0x80000000, 0x80000000, rl->spec.remote_endpoint, tt, flags,
                                     &rl->rgi, es, ctx)
                          && ret;
                }
                else
                {
                    /* don't try to remove the def route if it does not exist */
                    if (rl->rgi.flags & RGI_ADDR_DEFINED)
                    {
                        /* delete default route */
                        del_route3(0, 0, rl->rgi.gateway.addr, tt, flags | ROUTE_REF_GW, &rl->rgi,
                                   es, ctx);
                    }

                    /* add new default route */
                    ret = add_route3(0, 0, rl->spec.remote_endpoint, tt, flags, &rl->rgi, es, ctx)
                          && ret;
                }
            }

            /* set a flag so we can undo later */
            rl->iflags |= RL_DID_REDIRECT_DEFAULT_GATEWAY;
        }
    }
    return ret;
}

static void
undo_redirect_default_route_to_vpn(struct route_list *rl, const struct tuntap *tt,
                                   unsigned int flags, const struct env_set *es,
                                   openvpn_net_ctx_t *ctx)
{
    if (rl && rl->iflags & RL_DID_REDIRECT_DEFAULT_GATEWAY)
    {
        /* delete remote host route */
        if (rl->iflags & RL_DID_LOCAL)
        {
            del_route3(rl->spec.remote_host, IPV4_NETMASK_HOST, rl->rgi.gateway.addr, tt,
                       flags | ROUTE_REF_GW, &rl->rgi, es, ctx);
            rl->iflags &= ~RL_DID_LOCAL;
        }

        /* delete special DHCP/DNS bypass route */
        del_bypass_routes(&rl->spec.bypass, rl->rgi.gateway.addr, tt, flags, &rl->rgi, es, ctx);

        if (rl->flags & RG_REROUTE_GW)
        {
            if (rl->flags & RG_DEF1)
            {
                /* delete default route (1st component) */
                del_route3(0x00000000, 0x80000000, rl->spec.remote_endpoint, tt, flags, &rl->rgi,
                           es, ctx);

                /* delete default route (2nd component) */
                del_route3(0x80000000, 0x80000000, rl->spec.remote_endpoint, tt, flags, &rl->rgi,
                           es, ctx);
            }
            else
            {
                /* delete default route */
                del_route3(0, 0, rl->spec.remote_endpoint, tt, flags, &rl->rgi, es, ctx);
                /* restore original default route if there was any */
                if (rl->rgi.flags & RGI_ADDR_DEFINED)
                {
                    add_route3(0, 0, rl->rgi.gateway.addr, tt, flags | ROUTE_REF_GW, &rl->rgi, es,
                               ctx);
                }
            }
        }

        rl->iflags &= ~RL_DID_REDIRECT_DEFAULT_GATEWAY;
    }
}

bool
add_routes(struct route_list *rl, struct route_ipv6_list *rl6, const struct tuntap *tt,
           unsigned int flags, const struct env_set *es, openvpn_net_ctx_t *ctx)
{
    bool ret = redirect_default_route_to_vpn(rl, tt, flags, es, ctx);
    if (rl && !(rl->iflags & RL_ROUTES_ADDED))
    {
        struct route_ipv4 *r;

        if (rl->routes && !tt->did_ifconfig_setup)
        {
            msg(M_INFO,
                "WARNING: OpenVPN was configured to add an IPv4 "
                "route. However, no IPv4 has been configured for %s, "
                "therefore the route installation may fail or may not work "
                "as expected.",
                tt->actual_name);
        }

#ifdef ENABLE_MANAGEMENT
        if (management && rl->routes)
        {
            management_set_state(management, OPENVPN_STATE_ADD_ROUTES, NULL, NULL, NULL, NULL,
                                 NULL);
        }
#endif

        for (r = rl->routes; r; r = r->next)
        {
            if (flags & ROUTE_DELETE_FIRST)
            {
                delete_route(r, tt, flags, &rl->rgi, es, ctx);
            }
            ret = add_route(r, tt, flags, &rl->rgi, es, ctx) && ret;
        }
        rl->iflags |= RL_ROUTES_ADDED;
    }
    if (rl6 && !(rl6->iflags & RL_ROUTES_ADDED))
    {
        struct route_ipv6 *r;

        if (!tt->did_ifconfig_ipv6_setup)
        {
            msg(M_INFO,
                "WARNING: OpenVPN was configured to add an IPv6 "
                "route. However, no IPv6 has been configured for %s, "
                "therefore the route installation may fail or may not work "
                "as expected.",
                tt->actual_name);
        }

        for (r = rl6->routes_ipv6; r; r = r->next)
        {
            if (flags & ROUTE_DELETE_FIRST)
            {
                delete_route_ipv6(r, tt, es, ctx);
            }
            ret = add_route_ipv6(r, tt, flags, es, ctx) && ret;
        }
        rl6->iflags |= RL_ROUTES_ADDED;
    }

    return ret;
}

void
delete_routes(struct route_list *rl, struct route_ipv6_list *rl6, const struct tuntap *tt,
              unsigned int flags, const struct env_set *es, openvpn_net_ctx_t *ctx)
{
    delete_routes_v4(rl, tt, flags, es, ctx);
    delete_routes_v6(rl6, tt, flags, es, ctx);
}

void
delete_routes_v4(struct route_list *rl, const struct tuntap *tt, unsigned int flags,
                 const struct env_set *es, openvpn_net_ctx_t *ctx)
{
    if (rl && (rl->iflags & RL_ROUTES_ADDED))
    {
        struct route_ipv4 *r;
        for (r = rl->routes; r; r = r->next)
        {
            delete_route(r, tt, flags, &rl->rgi, es, ctx);
        }
        rl->iflags &= ~RL_ROUTES_ADDED;
    }

    undo_redirect_default_route_to_vpn(rl, tt, flags, es, ctx);

    if (rl)
    {
        clear_route_list(rl);
    }
}

void
delete_routes_v6(struct route_ipv6_list *rl6, const struct tuntap *tt, unsigned int flags,
                 const struct env_set *es, openvpn_net_ctx_t *ctx)
{
    if (rl6 && (rl6->iflags & RL_ROUTES_ADDED))
    {
        struct route_ipv6 *r6;
        for (r6 = rl6->routes_ipv6; r6; r6 = r6->next)
        {
            delete_route_ipv6(r6, tt, es, ctx);
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
print_route_option(const struct route_option *ro, msglvl_t msglevel)
{
    msg(msglevel, "  route %s/%s/%s/%s", show_opt(ro->network), show_opt(ro->netmask),
        show_opt(ro->gateway), show_opt(ro->metric));
}

void
print_route_options(const struct route_option_list *rol, msglvl_t msglevel)
{
    struct route_option *ro;
    if (rol->flags & RG_ENABLE)
    {
        msg(msglevel, "  [redirect_default_gateway local=%d]", (rol->flags & RG_LOCAL) != 0);
    }
    for (ro = rol->routes; ro; ro = ro->next)
    {
        print_route_option(ro, msglevel);
    }
}

void
print_default_gateway(const msglvl_t msglevel, const struct route_gateway_info *rgi,
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
        if (rgi->flags & RGI_IFACE_DEFINED)
        {
            buf_printf(&out, " IFACE=%s", rgi->iface);
        }
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
        if (rgi6->flags & RGI_IFACE_DEFINED)
        {
            buf_printf(&out, " IFACE=%s", rgi6->iface);
        }
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
print_route(const struct route_ipv4 *r, msglvl_t msglevel)
{
    struct gc_arena gc = gc_new();
    if (r->flags & RT_DEFINED)
    {
        msg(msglevel, "%s", route_string(r, &gc));
    }
    gc_free(&gc);
}

void
print_routes(const struct route_list *rl, msglvl_t msglevel)
{
    struct route_ipv4 *r;
    for (r = rl->routes; r; r = r->next)
    {
        print_route(r, msglevel);
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
        struct buffer name1 = alloc_buf_gc(256, &gc);
        struct buffer val = alloc_buf_gc(256, &gc);
        struct buffer name2 = alloc_buf_gc(256, &gc);

        buf_printf(&name1, "route_ipv6_network_%d", i);
        buf_printf(&val, "%s/%d", print_in6_addr(r6->network, 0, &gc), r6->netbits);
        setenv_str(es, BSTR(&name1), BSTR(&val));

        buf_printf(&name2, "route_ipv6_gateway_%d", i);
        setenv_str(es, BSTR(&name2), print_in6_addr(r6->gateway, 0, &gc));

        if (r6->flags & RT_METRIC_DEFINED)
        {
            struct buffer name3 = alloc_buf_gc(256, &gc);
            buf_printf(&name3, "route_ipv6_metric_%d", i);
            setenv_int(es, BSTR(&name3), r6->metric);
        }
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
local_route(in_addr_t network, in_addr_t netmask, in_addr_t gateway,
            const struct route_gateway_info *rgi)
{
    /* set LR_MATCH on local host routes */
    const int rgi_needed = (RGI_ADDR_DEFINED | RGI_NETMASK_DEFINED | RGI_IFACE_DEFINED);
    if (rgi && (rgi->flags & rgi_needed) == rgi_needed && gateway == rgi->gateway.addr
        && netmask == 0xFFFFFFFF)
    {
        if (((network ^ rgi->gateway.addr) & rgi->gateway.netmask) == 0)
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

/* Return true if the "on-link" form of the route should be used.  This is when the gateway for
 * a route is specified as an interface rather than an address. */
#if defined(TARGET_LINUX) || defined(TARGET_DARWIN)
static inline bool
is_on_link(const int is_local_route, const unsigned int flags, const struct route_gateway_info *rgi)
{
    return rgi
           && (is_local_route == LR_MATCH
               || ((flags & ROUTE_REF_GW) && (rgi->flags & RGI_ON_LINK)));
}
#endif

bool
add_route(struct route_ipv4 *r, const struct tuntap *tt, unsigned int flags,
          const struct route_gateway_info *rgi, /* may be NULL */
          const struct env_set *es, openvpn_net_ctx_t *ctx)
{
    int status = 0;
    int is_local_route;

    if (!(r->flags & RT_DEFINED))
    {
        return true; /* no error */
    }

    struct argv argv = argv_new();
    struct gc_arena gc = gc_new();

#if !defined(TARGET_LINUX)
    const char *network = print_in_addr_t(r->network, 0, &gc);
#if !defined(TARGET_AIX)
    const char *netmask = print_in_addr_t(r->netmask, 0, &gc);
#endif
    const char *gateway = print_in_addr_t(r->gateway, 0, &gc);
#endif

    is_local_route = local_route(r->network, r->netmask, r->gateway, rgi);
    if (is_local_route == LR_ERROR)
    {
        goto done;
    }

#if defined(TARGET_LINUX)
    const char *iface = NULL;
    int metric = -1;

    if (is_on_link(is_local_route, flags, rgi))
    {
        iface = rgi->iface;
    }

    if (r->flags & RT_METRIC_DEFINED)
    {
        metric = r->metric;
    }


    status = RTA_SUCCESS;
    int ret = net_route_v4_add(ctx, &r->network, netmask_to_netbits2(r->netmask), &r->gateway,
                               iface, r->table_id, metric);
    if (ret == -EEXIST)
    {
        msg(D_ROUTE, "NOTE: Linux route add command failed because route exists");
        status = RTA_EEXIST;
    }
    else if (ret < 0)
    {
        msg(M_WARN, "ERROR: Linux route add command failed");
        status = RTA_ERROR;
    }

#elif defined(TARGET_ANDROID)
    char out[128];

    if (rgi)
    {
        snprintf(out, sizeof(out), "%s %s %s dev %s", network, netmask, gateway, rgi->iface);
    }
    else
    {
        snprintf(out, sizeof(out), "%s %s %s", network, netmask, gateway);
    }
    bool ret = management_android_control(management, "ROUTE", out);
    status = ret ? RTA_SUCCESS : RTA_ERROR;

#elif defined(TARGET_SOLARIS)

    /* example: route add 192.0.2.32 -netmask 255.255.255.224 somegateway */

    argv_printf(&argv, "%s add", ROUTE_PATH);

    argv_printf_cat(&argv, "%s -netmask %s %s", network, netmask, gateway);

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
    bool ret = openvpn_execve_check(&argv, es, 0, "ERROR: Solaris route add command failed");
    status = ret ? RTA_SUCCESS : RTA_ERROR;

#elif defined(TARGET_FREEBSD)

    argv_printf(&argv, "%s add", ROUTE_PATH);

#if 0
    if (r->flags & RT_METRIC_DEFINED)
    {
        argv_printf_cat(&argv, "-rtt %d", r->metric);
    }
#endif

    argv_printf_cat(&argv, "-net %s %s %s", network, gateway, netmask);

    /* FIXME -- add on-link support for FreeBSD */

    argv_msg(D_ROUTE, &argv);
    bool ret = openvpn_execve_check(&argv, es, 0, "ERROR: FreeBSD route add command failed");
    status = ret ? RTA_SUCCESS : RTA_ERROR;

#elif defined(TARGET_DRAGONFLY)

    argv_printf(&argv, "%s add", ROUTE_PATH);

#if 0
    if (r->flags & RT_METRIC_DEFINED)
    {
        argv_printf_cat(&argv, "-rtt %d", r->metric);
    }
#endif

    argv_printf_cat(&argv, "-net %s %s %s", network, gateway, netmask);

    /* FIXME -- add on-link support for Dragonfly */

    argv_msg(D_ROUTE, &argv);
    bool ret = openvpn_execve_check(&argv, es, 0, "ERROR: DragonFly route add command failed");
    status = ret ? RTA_SUCCESS : RTA_ERROR;

#elif defined(TARGET_DARWIN)

    argv_printf(&argv, "%s add", ROUTE_PATH);

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
        argv_printf_cat(&argv, "-cloning -net %s -netmask %s -interface %s", network, netmask,
                        rgi->iface);
    }
    else
    {
        argv_printf_cat(&argv, "-net %s %s %s", network, gateway, netmask);
    }

    argv_msg(D_ROUTE, &argv);
    bool ret = openvpn_execve_check(&argv, es, 0, "ERROR: OS X route add command failed");
    status = ret ? RTA_SUCCESS : RTA_ERROR;

#elif defined(TARGET_OPENBSD) || defined(TARGET_NETBSD)

    argv_printf(&argv, "%s add", ROUTE_PATH);

#if 0
    if (r->flags & RT_METRIC_DEFINED)
    {
        argv_printf_cat(&argv, "-rtt %d", r->metric);
    }
#endif

    argv_printf_cat(&argv, "-net %s %s -netmask %s", network, gateway, netmask);

    /* FIXME -- add on-link support for OpenBSD/NetBSD */

    argv_msg(D_ROUTE, &argv);
    bool ret = openvpn_execve_check(&argv, es, 0, "ERROR: OpenBSD/NetBSD route add command failed");
    status = ret ? RTA_SUCCESS : RTA_ERROR;

#elif defined(TARGET_AIX)

    {
        int netbits = netmask_to_netbits2(r->netmask);
        argv_printf(&argv, "%s add -net %s/%d %s", ROUTE_PATH, network, netbits, gateway);
        argv_msg(D_ROUTE, &argv);
        bool ret = openvpn_execve_check(&argv, es, 0, "ERROR: AIX route add command failed");
        status = ret ? RTA_SUCCESS : RTA_ERROR;
    }

#elif defined(TARGET_HAIKU)

    /* ex: route add /dev/net/ipro1000/0 0.0.0.0 gw 192.168.1.1 netmask 128.0.0.0 */
    argv_printf(&argv, "%s add %s inet %s gw %s netmask %s", ROUTE_PATH, rgi->iface, network,
                gateway, netmask);
    argv_msg(D_ROUTE, &argv);
    bool ret = openvpn_execve_check(&argv, es, 0, "ERROR: Haiku inet route add command failed");
    status = ret ? RTA_SUCCESS : RTA_ERROR;

#else  /* if defined(TARGET_LINUX) */
    msg(M_FATAL,
        "Sorry, but I don't know how to do 'route' commands on this operating system.  Try putting your routes in a --route-up script");
#endif /* if defined(TARGET_LINUX) */

done:
    if (status == RTA_SUCCESS)
    {
        r->flags |= RT_ADDED;
    }
    else
    {
        r->flags &= ~RT_ADDED;
    }
    argv_free(&argv);
    gc_free(&gc);
    /* release resources potentially allocated during route setup */
    net_ctx_reset(ctx);

    return (status != RTA_ERROR);
}

#if defined(__GNUC__) || defined(__clang__)
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wconversion"
#endif

void
route_ipv6_clear_host_bits(struct route_ipv6 *r6)
{
    /* clear host bit parts of route
     * (needed if routes are specified improperly, or if we need to
     * explicitly setup/clear the "connected" network routes on some OSes)
     */
    int byte = 15;
    int bits_to_clear = 128 - r6->netbits;

    while (byte >= 0 && bits_to_clear > 0)
    {
        if (bits_to_clear >= 8)
        {
            r6->network.s6_addr[byte--] = 0;
            bits_to_clear -= 8;
        }
        else
        {
            r6->network.s6_addr[byte--] &= (0xff << bits_to_clear);
            bits_to_clear = 0;
        }
    }
}

bool
add_route_ipv6(struct route_ipv6 *r6, const struct tuntap *tt, unsigned int flags,
               const struct env_set *es, openvpn_net_ctx_t *ctx)
{
    int status = 0;
    bool gateway_needed = false;

    if (!(r6->flags & RT_DEFINED))
    {
        return true; /* no error */
    }

    struct argv argv = argv_new();
    struct gc_arena gc = gc_new();

    const char *device = tt->actual_name;
    if (r6->iface != NULL) /* vpn server special route */
    {
        device = r6->iface;
        if (!IN6_IS_ADDR_UNSPECIFIED(&r6->gateway))
        {
            gateway_needed = true;
        }
    }

    route_ipv6_clear_host_bits(r6);
    const char *network = print_in6_addr(r6->network, 0, &gc);
    const char *gateway = print_in6_addr(r6->gateway, 0, &gc);

#if defined(TARGET_DARWIN) || defined(TARGET_FREEBSD) || defined(TARGET_DRAGONFLY) \
    || defined(TARGET_OPENBSD) || defined(TARGET_NETBSD)

    /* the BSD platforms cannot specify gateway and interface independently,
     * but for link-local destinations, we MUST specify the interface, so
     * we build a combined "$gateway%$interface" gateway string
     */
    if (r6->iface != NULL && gateway_needed
        && IN6_IS_ADDR_LINKLOCAL(&r6->gateway)) /* fe80::...%intf */
    {
        int len = strlen(gateway) + 1 + strlen(r6->iface) + 1;
        char *tmp = gc_malloc(len, true, &gc);
        snprintf(tmp, len, "%s%%%s", gateway, r6->iface);
        gateway = tmp;
    }
#endif

    msg(D_ROUTE, "add_route_ipv6(%s/%d -> %s metric %d) dev %s", network, r6->netbits, gateway,
        r6->metric, device);

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
    if (tt->type == DEV_TYPE_TAP && !((r6->flags & RT_METRIC_DEFINED) && r6->metric == 0))
    {
        gateway_needed = true;
    }

    if (gateway_needed && IN6_IS_ADDR_UNSPECIFIED(&r6->gateway))
    {
        msg(M_WARN,
            "ROUTE6 WARNING: " PACKAGE_NAME " needs a gateway "
            "parameter for a --route-ipv6 option and no default was set via "
            "--ifconfig-ipv6 or --route-ipv6-gateway option.  Not installing "
            "IPv6 route to %s/%d.",
            network, r6->netbits);
        status = 0;
        goto done;
    }

#if defined(TARGET_LINUX)
    int metric = -1;
    if ((r6->flags & RT_METRIC_DEFINED) && (r6->metric > 0))
    {
        metric = r6->metric;
    }

    status = RTA_SUCCESS;
    int ret = net_route_v6_add(ctx, &r6->network, r6->netbits, gateway_needed ? &r6->gateway : NULL,
                               device, r6->table_id, metric);
    if (ret == -EEXIST)
    {
        msg(D_ROUTE, "NOTE: Linux route add command failed because route exists");
        status = RTA_EEXIST;
    }
    else if (ret < 0)
    {
        msg(M_WARN, "ERROR: Linux route add command failed");
        status = RTA_ERROR;
    }

#elif defined(TARGET_ANDROID)
    char out[64];

    snprintf(out, sizeof(out), "%s/%d %s", network, r6->netbits, device);

    status = management_android_control(management, "ROUTE6", out);

#elif defined(TARGET_SOLARIS)

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
    argv_printf(&argv, "%s add -inet6 %s/%d %s", ROUTE_PATH, network, r6->netbits, gateway);

    /* on tun (not tap), not "elsewhere"? -> metric 0 */
    if (tt->type == DEV_TYPE_TUN && !r6->iface)
    {
        argv_printf_cat(&argv, "0");
    }

    argv_msg(D_ROUTE, &argv);
    bool ret = openvpn_execve_check(&argv, es, 0, "ERROR: Solaris route add -inet6 command failed");
    status = ret ? RTA_SUCCESS : RTA_ERROR;

#elif defined(TARGET_FREEBSD) || defined(TARGET_DRAGONFLY)

    argv_printf(&argv, "%s add -inet6 %s/%d", ROUTE_PATH, network, r6->netbits);

    if (gateway_needed)
    {
        argv_printf_cat(&argv, "%s", gateway);
    }
    else
    {
        argv_printf_cat(&argv, "-iface %s", device);
    }

    argv_msg(D_ROUTE, &argv);
    bool ret = openvpn_execve_check(&argv, es, 0, "ERROR: *BSD route add -inet6 command failed");
    status = ret ? RTA_SUCCESS : RTA_ERROR;

#elif defined(TARGET_DARWIN)

    argv_printf(&argv, "%s add -inet6 %s -prefixlen %d", ROUTE_PATH, network, r6->netbits);

    if (gateway_needed)
    {
        argv_printf_cat(&argv, "%s", gateway);
    }
    else
    {
        argv_printf_cat(&argv, "-iface %s", device);
    }

    argv_msg(D_ROUTE, &argv);
    bool ret = openvpn_execve_check(&argv, es, 0, "ERROR: MacOS X route add -inet6 command failed");
    status = ret ? RTA_SUCCESS : RTA_ERROR;

#elif defined(TARGET_OPENBSD)

    argv_printf(&argv, "%s add -inet6 %s -prefixlen %d %s", ROUTE_PATH, network, r6->netbits,
                gateway);

    argv_msg(D_ROUTE, &argv);
    bool ret = openvpn_execve_check(&argv, es, 0, "ERROR: OpenBSD route add -inet6 command failed");
    status = ret ? RTA_SUCCESS : RTA_ERROR;

#elif defined(TARGET_NETBSD)

    argv_printf(&argv, "%s add -inet6 %s/%d %s", ROUTE_PATH, network, r6->netbits, gateway);

    argv_msg(D_ROUTE, &argv);
    bool ret = openvpn_execve_check(&argv, es, 0, "ERROR: NetBSD route add -inet6 command failed");
    status = ret ? RTA_SUCCESS : RTA_ERROR;

#elif defined(TARGET_AIX)

    argv_printf(&argv, "%s add -inet6 %s/%d %s", ROUTE_PATH, network, r6->netbits, gateway);
    argv_msg(D_ROUTE, &argv);
    bool ret = openvpn_execve_check(&argv, es, 0, "ERROR: AIX route add command failed");
    status = ret ? RTA_SUCCESS : RTA_ERROR;

#elif defined(TARGET_HAIKU)

    /* ex: route add /dev/net/ipro1000/0 inet6 :: gw beef::cafe prefixlen 64 */
    argv_printf(&argv, "%s add %s inet6 %s gw %s prefixlen %d", ROUTE_PATH, r6->iface, network,
                gateway, r6->netbits);
    argv_msg(D_ROUTE, &argv);
    bool ret = openvpn_execve_check(&argv, es, 0, "ERROR: Haiku inet6 route add command failed");
    status = ret ? RTA_SUCCESS : RTA_ERROR;

#else  /* if defined(TARGET_LINUX) */
    msg(M_FATAL,
        "Sorry, but I don't know how to do 'route ipv6' commands on this operating system.  Try putting your routes in a --route-up script");
#endif /* if defined(TARGET_LINUX) */

done:
    if (status == RTA_SUCCESS)
    {
        r6->flags |= RT_ADDED;
    }
    else
    {
        r6->flags &= ~RT_ADDED;
    }
    argv_free(&argv);
    gc_free(&gc);
    /* release resources potentially allocated during route setup */
    net_ctx_reset(ctx);

    return (status != RTA_ERROR);
}

static void
delete_route(struct route_ipv4 *r, const struct tuntap *tt, unsigned int flags,
             const struct route_gateway_info *rgi, const struct env_set *es, openvpn_net_ctx_t *ctx)
{
#if !defined(TARGET_LINUX)
    const char *network;
#if !defined(TARGET_AIX)
    const char *netmask;
#endif
#if !defined(TARGET_ANDROID)
    const char *gateway;
#endif
#else /* if !defined(TARGET_LINUX) */
    int metric;
#endif
    int is_local_route;

    if ((r->flags & (RT_DEFINED | RT_ADDED)) != (RT_DEFINED | RT_ADDED))
    {
        return;
    }

    struct gc_arena gc = gc_new();
    struct argv argv = argv_new();

#if !defined(TARGET_LINUX)
    network = print_in_addr_t(r->network, 0, &gc);
#if !defined(TARGET_AIX)
    netmask = print_in_addr_t(r->netmask, 0, &gc);
#endif
#if !defined(TARGET_ANDROID)
    gateway = print_in_addr_t(r->gateway, 0, &gc);
#endif
#endif

    is_local_route = local_route(r->network, r->netmask, r->gateway, rgi);
    if (is_local_route == LR_ERROR)
    {
        goto done;
    }

#if defined(TARGET_LINUX)
    metric = -1;
    if (r->flags & RT_METRIC_DEFINED)
    {
        metric = r->metric;
    }

    if (net_route_v4_del(ctx, &r->network, netmask_to_netbits2(r->netmask), &r->gateway, NULL,
                         r->table_id, metric)
        < 0)
    {
        msg(M_WARN, "ERROR: Linux route delete command failed");
    }

#elif defined(TARGET_SOLARIS)

    argv_printf(&argv, "%s delete %s -netmask %s %s", ROUTE_PATH, network, netmask, gateway);

    argv_msg(D_ROUTE, &argv);
    openvpn_execve_check(&argv, es, 0, "ERROR: Solaris route delete command failed");

#elif defined(TARGET_FREEBSD)

    argv_printf(&argv, "%s delete -net %s %s %s", ROUTE_PATH, network, gateway, netmask);

    argv_msg(D_ROUTE, &argv);
    openvpn_execve_check(&argv, es, 0, "ERROR: FreeBSD route delete command failed");

#elif defined(TARGET_DRAGONFLY)

    argv_printf(&argv, "%s delete -net %s %s %s", ROUTE_PATH, network, gateway, netmask);

    argv_msg(D_ROUTE, &argv);
    openvpn_execve_check(&argv, es, 0, "ERROR: DragonFly route delete command failed");

#elif defined(TARGET_DARWIN)

    if (is_on_link(is_local_route, flags, rgi))
    {
        argv_printf(&argv, "%s delete -cloning -net %s -netmask %s -interface %s", ROUTE_PATH,
                    network, netmask, rgi->iface);
    }
    else
    {
        argv_printf(&argv, "%s delete -net %s %s %s", ROUTE_PATH, network, gateway, netmask);
    }

    argv_msg(D_ROUTE, &argv);
    openvpn_execve_check(&argv, es, 0, "ERROR: OS X route delete command failed");

#elif defined(TARGET_OPENBSD) || defined(TARGET_NETBSD)

    argv_printf(&argv, "%s delete -net %s %s -netmask %s", ROUTE_PATH, network, gateway, netmask);

    argv_msg(D_ROUTE, &argv);
    openvpn_execve_check(&argv, es, 0, "ERROR: OpenBSD/NetBSD route delete command failed");

#elif defined(TARGET_ANDROID)
    msg(D_ROUTE_DEBUG, "Deleting routes on Android is not possible/not "
                       "needed. The VpnService API allows routes to be set "
                       "on connect only and will clean up automatically.");
#elif defined(TARGET_AIX)

    {
        int netbits = netmask_to_netbits2(r->netmask);
        argv_printf(&argv, "%s delete -net %s/%d %s", ROUTE_PATH, network, netbits, gateway);
        argv_msg(D_ROUTE, &argv);
        openvpn_execve_check(&argv, es, 0, "ERROR: AIX route delete command failed");
    }

#elif defined(TARGET_HAIKU)

    /* ex: route delete /dev/net/ipro1000/0 inet 192.168.0.0 gw 192.168.1.1 netmask 255.255.0.0 */
    argv_printf(&argv, "%s delete %s inet %s gw %s netmask %s", ROUTE_PATH, rgi->iface, network,
                gateway, netmask);
    argv_msg(D_ROUTE, &argv);
    openvpn_execve_check(&argv, es, 0, "ERROR: Haiku inet route delete command failed");

#else  /* if defined(TARGET_LINUX) */
    msg(M_FATAL,
        "Sorry, but I don't know how to do 'route' commands on this operating system.  Try putting your routes in a --route-up script");
#endif /* if defined(TARGET_LINUX) */

done:
    r->flags &= ~RT_ADDED;
    argv_free(&argv);
    gc_free(&gc);
    /* release resources potentially allocated during route cleanup */
    net_ctx_reset(ctx);
}

void
delete_route_ipv6(const struct route_ipv6 *r6, const struct tuntap *tt, const struct env_set *es,
                  openvpn_net_ctx_t *ctx)
{
    const char *network;

    if ((r6->flags & (RT_DEFINED | RT_ADDED)) != (RT_DEFINED | RT_ADDED))
    {
        return;
    }

#if !defined(TARGET_LINUX)
    const char *gateway;
#endif
#if !defined(TARGET_SOLARIS)
    bool gateway_needed = false;
    const char *device = tt->actual_name;
    if (r6->iface != NULL) /* vpn server special route */
    {
        device = r6->iface;
        gateway_needed = true;
    }
    (void)device; /* unused on some platforms */

    /* if we used a gateway on "add route", we also need to specify it on
     * delete, otherwise some OSes will refuse to delete the route
     */
    if (tt->type == DEV_TYPE_TAP && !((r6->flags & RT_METRIC_DEFINED) && r6->metric == 0))
    {
        gateway_needed = true;
    }
#endif

    struct gc_arena gc = gc_new();
    struct argv argv = argv_new();

    network = print_in6_addr(r6->network, 0, &gc);
#if !defined(TARGET_LINUX)
    gateway = print_in6_addr(r6->gateway, 0, &gc);
#endif

#if defined(TARGET_DARWIN) || defined(TARGET_FREEBSD) || defined(TARGET_DRAGONFLY) \
    || defined(TARGET_OPENBSD) || defined(TARGET_NETBSD)

    /* the BSD platforms cannot specify gateway and interface independently,
     * but for link-local destinations, we MUST specify the interface, so
     * we build a combined "$gateway%$interface" gateway string
     */
    if (r6->iface != NULL && gateway_needed
        && IN6_IS_ADDR_LINKLOCAL(&r6->gateway)) /* fe80::...%intf */
    {
        int len = strlen(gateway) + 1 + strlen(r6->iface) + 1;
        char *tmp = gc_malloc(len, true, &gc);
        snprintf(tmp, len, "%s%%%s", gateway, r6->iface);
        gateway = tmp;
    }
#endif

    msg(D_ROUTE, "delete_route_ipv6(%s/%d)", network, r6->netbits);

#if defined(TARGET_LINUX)
    int metric = -1;
    if ((r6->flags & RT_METRIC_DEFINED) && (r6->metric > 0))
    {
        metric = r6->metric;
    }

    if (net_route_v6_del(ctx, &r6->network, r6->netbits, gateway_needed ? &r6->gateway : NULL,
                         device, r6->table_id, metric)
        < 0)
    {
        msg(M_WARN, "ERROR: Linux route v6 delete command failed");
    }

#elif defined(TARGET_SOLARIS)

    /* example: route delete -inet6 2001:db8::/32 somegateway */

    argv_printf(&argv, "%s delete -inet6 %s/%d %s", ROUTE_PATH, network, r6->netbits, gateway);

    argv_msg(D_ROUTE, &argv);
    openvpn_execve_check(&argv, es, 0, "ERROR: Solaris route delete -inet6 command failed");

#elif defined(TARGET_FREEBSD) || defined(TARGET_DRAGONFLY)

    argv_printf(&argv, "%s delete -inet6 %s/%d", ROUTE_PATH, network, r6->netbits);

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

    argv_printf(&argv, "%s delete -inet6 %s -prefixlen %d", ROUTE_PATH, network, r6->netbits);

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

    argv_printf(&argv, "%s delete -inet6 %s -prefixlen %d %s", ROUTE_PATH, network, r6->netbits,
                gateway);

    argv_msg(D_ROUTE, &argv);
    openvpn_execve_check(&argv, es, 0, "ERROR: OpenBSD route delete -inet6 command failed");

#elif defined(TARGET_NETBSD)

    argv_printf(&argv, "%s delete -inet6 %s/%d %s", ROUTE_PATH, network, r6->netbits, gateway);

    argv_msg(D_ROUTE, &argv);
    openvpn_execve_check(&argv, es, 0, "ERROR: NetBSD route delete -inet6 command failed");

#elif defined(TARGET_AIX)

    argv_printf(&argv, "%s delete -inet6 %s/%d %s", ROUTE_PATH, network, r6->netbits, gateway);
    argv_msg(D_ROUTE, &argv);
    openvpn_execve_check(&argv, es, 0, "ERROR: AIX route add command failed");

#elif defined(TARGET_ANDROID)
    msg(D_ROUTE_DEBUG, "Deleting routes on Android is not possible/not "
                       "needed. The VpnService API allows routes to be set "
                       "on connect only and will clean up automatically.");
#elif defined(TARGET_HAIKU)

    /* ex: route delete /dev/net/ipro1000/0 inet6 :: gw beef::cafe prefixlen 64 */
    argv_printf(&argv, "%s delete %s inet6 %s gw %s prefixlen %d", ROUTE_PATH, r6->iface, network,
                gateway, r6->netbits);
    argv_msg(D_ROUTE, &argv);
    openvpn_execve_check(&argv, es, 0, "ERROR: Haiku inet6 route delete command failed");

#else  /* if defined(TARGET_LINUX) */
    msg(M_FATAL,
        "Sorry, but I don't know how to do 'route ipv6' commands on this operating system.  Try putting your routes in a --route-down script");
#endif /* if defined(TARGET_LINUX) */

    argv_free(&argv);
    gc_free(&gc);
    /* release resources potentially allocated during route cleanup */
    net_ctx_reset(ctx);
}

#if defined(__GNUC__) || defined(__clang__)
#pragma GCC diagnostic pop
#endif

/*
 * The --redirect-gateway option requires OS-specific code below
 * to get the current default gateway.
 */

#if defined(TARGET_ANDROID)

void
get_default_gateway(struct route_gateway_info *rgi, in_addr_t dest, openvpn_net_ctx_t *ctx)
{
    /* Android, set some pseudo GW, addr is in host byte order,
     * Determining the default GW on Android 5.0+ is non trivial
     * and serves almost no purpose since OpenVPN only uses the
     * default GW address to add routes for networks that should
     * NOT be routed over the VPN. Using a well known address
     * (127.'d'.'g'.'w') for the default GW make detecting
     * these routes easier from the controlling app.
     */
    CLEAR(*rgi);

    rgi->gateway.addr = 127 << 24 | 'd' << 16 | 'g' << 8 | 'w';
    rgi->flags = RGI_ADDR_DEFINED | RGI_IFACE_DEFINED;
    strcpy(rgi->iface, "android-gw");

    /* Skip scanning/fetching interface from loopback interface we do
     * normally on Linux.
     * It always fails and "ioctl(SIOCGIFCONF) failed" confuses users
     */
}

void
get_default_gateway_ipv6(struct route_ipv6_gateway_info *rgi6, const struct in6_addr *dest,
                         openvpn_net_ctx_t *ctx)
{
    /* Same for ipv6 */

    CLEAR(*rgi6);

    /* Use a fake link-local address */
    ASSERT(inet_pton(AF_INET6, "fe80::ad", &rgi6->addrs->addr_ipv6) == 1);
    rgi6->addrs->netbits_ipv6 = 64;
    rgi6->flags = RGI_ADDR_DEFINED | RGI_IFACE_DEFINED;
    strcpy(rgi6->iface, "android-gw");
}

#elif defined(TARGET_LINUX)

void
get_default_gateway(struct route_gateway_info *rgi, in_addr_t dest, openvpn_net_ctx_t *ctx)
{
    struct gc_arena gc = gc_new();
    int sd = -1;
    char best_name[IFNAMSIZ];

    CLEAR(*rgi);
    CLEAR(best_name);

    /* find best route to 'dest', get gateway IP addr + interface */
    if (net_route_v4_best_gw(ctx, &dest, &rgi->gateway.addr, best_name) == 0)
    {
        rgi->flags |= RGI_ADDR_DEFINED;
        if (!rgi->gateway.addr && best_name[0])
        {
            rgi->flags |= RGI_ON_LINK;
        }
    }

    /* scan adapter list */
    if (rgi->flags & RGI_ADDR_DEFINED)
    {
        struct ifreq *ifr, *ifend;
        in_addr_t addr, netmask;
        struct ifreq ifreq;
        struct ifconf ifc;
        struct ifreq ifs[20]; /* Maximum number of interfaces to scan */

        if ((sd = socket(AF_INET, SOCK_DGRAM, 0)) < 0)
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
                addr = ntohl(((struct sockaddr_in *)&ifr->ifr_addr)->sin_addr.s_addr);

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
                    netmask = ntohl(((struct sockaddr_in *)&ifreq.ifr_addr)->sin_addr.s_addr);

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
        close(sd);
    }
    gc_free(&gc);
}

/* IPv6 implementation using netlink
 * https://www.linuxjournal.com/article/7356 - "Kernel Korner - Why and How to Use Netlink Socket"
 * netlink(3), netlink(7), rtnetlink(7)
 * https://www.virtualbox.org/svn/vbox/trunk/src/VBox/NetworkServices/NAT/
 */
struct rtreq
{
    struct nlmsghdr nh;
    struct rtmsg rtm;
    char attrbuf[512];
};

void
get_default_gateway_ipv6(struct route_ipv6_gateway_info *rgi6, const struct in6_addr *dest,
                         openvpn_net_ctx_t *ctx)
{
    int flags;

    CLEAR(*rgi6);

    if (net_route_v6_best_gw(ctx, dest, &rgi6->gateway.addr_ipv6, rgi6->iface) == 0)
    {
        if (!IN6_IS_ADDR_UNSPECIFIED(&rgi6->gateway.addr_ipv6))
        {
            rgi6->flags |= RGI_ADDR_DEFINED;
        }

        if (strlen(rgi6->iface) > 0)
        {
            rgi6->flags |= RGI_IFACE_DEFINED;
        }
    }

    /* if we have an interface but no gateway, the destination is on-link */
    flags = rgi6->flags & (RGI_IFACE_DEFINED | RGI_ADDR_DEFINED);
    if (flags == RGI_IFACE_DEFINED)
    {
        rgi6->flags |= (RGI_ADDR_DEFINED | RGI_ON_LINK);
        if (dest)
        {
            rgi6->gateway.addr_ipv6 = *dest;
        }
    }
}

#elif defined(TARGET_DARWIN) || defined(TARGET_SOLARIS) || defined(TARGET_FREEBSD) \
    || defined(TARGET_DRAGONFLY) || defined(TARGET_OPENBSD) || defined(TARGET_NETBSD)

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <net/route.h>
#include <net/if_dl.h>
#if !defined(TARGET_SOLARIS)
#include <ifaddrs.h>
#endif

struct rtmsg
{
    struct rt_msghdr m_rtm;
    char m_space[512];
};

/* the route socket code is identical for all 4 supported BSDs and for
 * MacOS X (Darwin), with one crucial difference: when going from
 * 32 bit to 64 bit, FreeBSD/OpenBSD increased the structure size but kept
 * source code compatibility by keeping the use of "long", while
 * MacOS X decided to keep binary compatibility by *changing* the API
 * to use "uint32_t", thus 32 bit on all OS X variants
 *
 * NetBSD does the MacOS way of "fixed number of bits, no matter if
 * 32 or 64 bit OS", but chose uint64_t.  For maximum portability, we
 * just use the OS RT_ROUNDUP() macro, which is guaranteed to be correct.
 *
 * We used to have a large amount of duplicate code here which really
 * differed only in this (long) vs. (uint32_t) - IMHO, worse than
 * having a combined block for all BSDs with this single #ifdef inside
 */

#if defined(TARGET_DARWIN)
#define ROUNDUP(a) ((a) > 0 ? (1 + (((a) - 1) | (sizeof(uint32_t) - 1))) : sizeof(uint32_t))
#elif defined(TARGET_NETBSD)
#define ROUNDUP(a) RT_ROUNDUP(a)
#else
#define ROUNDUP(a) ((a) > 0 ? (1 + (((a) - 1) | (sizeof(long) - 1))) : sizeof(long))
#endif

#if defined(TARGET_SOLARIS)
#define NEXTADDR(w, u)        \
    if (rtm_addrs & (w))      \
    {                         \
        l = sizeof(u);        \
        memmove(cp, &(u), l); \
        cp += ROUNDUP(l);     \
    }

#define ADVANCE(x, n) (x += ROUNDUP(sizeof(struct sockaddr_in)))
#else /* if defined(TARGET_SOLARIS) */
#define NEXTADDR(w, u)                         \
    if (rtm_addrs & (w))                       \
    {                                          \
        l = ((struct sockaddr *)&(u))->sa_len; \
        memmove(cp, &(u), l);                  \
        cp += ROUNDUP(l);                      \
    }

#define ADVANCE(x, n) (x += ROUNDUP((n)->sa_len))
#endif

#define max(a, b) ((a) > (b) ? (a) : (b))

#if defined(__GNUC__) || defined(__clang__)
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wconversion"
#endif

void
get_default_gateway(struct route_gateway_info *rgi, in_addr_t dest, openvpn_net_ctx_t *ctx)
{
    struct gc_arena gc = gc_new();
    struct rtmsg m_rtmsg;
    int sockfd = -1;
    int seq, l, pid, rtm_addrs;
    unsigned int i;
    struct sockaddr so_dst, so_mask;
    char *cp = m_rtmsg.m_space;
    struct sockaddr *gate = NULL, *ifp = NULL, *sa;
    struct rt_msghdr *rtm_aux;

#define rtm m_rtmsg.m_rtm

    CLEAR(*rgi);

    /* setup data to send to routing socket */
    pid = getpid();
    seq = 0;
#ifdef TARGET_OPENBSD
    rtm_addrs = RTA_DST | RTA_NETMASK; /* Kernel refuses RTA_IFP */
#else
    rtm_addrs = RTA_DST | RTA_NETMASK | RTA_IFP;
#endif

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
    sockfd = socket(PF_ROUTE, SOCK_RAW, 0);
    if (sockfd < 0)
    {
        msg(M_WARN, "GDG: socket #1 failed");
        goto done;
    }
    if (write(sockfd, (char *)&m_rtmsg, l) < 0)
    {
        msg(M_WARN | M_ERRNO, "GDG: problem writing to routing socket");
        goto done;
    }
    do
    {
        l = read(sockfd, (char *)&m_rtmsg, sizeof(m_rtmsg));
    } while (l > 0 && (rtm.rtm_seq != seq || rtm.rtm_pid != pid));
    close(sockfd);
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
            const struct sockaddr_dl *adl = (struct sockaddr_dl *)ifp;
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

        sockfd = socket(AF_INET, SOCK_DGRAM, 0);
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
        close(sockfd);
        sockfd = -1;

        rgi->gateway.netmask = ntohl(((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr.s_addr);
        rgi->flags |= RGI_NETMASK_DEFINED;
    }

    /* try to read MAC addr associated with interface that owns default gateway */
    if (rgi->flags & RGI_IFACE_DEFINED)
    {
#if defined(TARGET_SOLARIS)
        /* OpenSolaris has getifaddrs(3), but it does not return AF_LINK */
        sockfd = socket(AF_INET, SOCK_DGRAM, 0);
        if (sockfd < 0)
        {
            msg(M_WARN, "GDG: socket #3 failed");
            goto done;
        }

        struct ifreq ifreq = { 0 };

        /* now get the hardware address. */
        strncpynt(ifreq.ifr_name, rgi->iface, sizeof(ifreq.ifr_name));
        if (ioctl(sockfd, SIOCGIFHWADDR, &ifreq) < 0)
        {
            msg(M_WARN, "GDG: SIOCGIFHWADDR(%s) failed", ifreq.ifr_name);
        }
        else
        {
            memcpy(rgi->hwaddr, &ifreq.ifr_addr.sa_data, 6);
            rgi->flags |= RGI_HWADDR_DEFINED;
        }
#else  /* if defined(TARGET_SOLARIS) */
        struct ifaddrs *ifap, *ifa;

        if (getifaddrs(&ifap) != 0)
        {
            msg(M_WARN | M_ERRNO, "GDG: getifaddrs() failed");
            goto done;
        }

        for (ifa = ifap; ifa; ifa = ifa->ifa_next)
        {
            if (ifa->ifa_addr != NULL && ifa->ifa_addr->sa_family == AF_LINK
                && !strncmp(ifa->ifa_name, rgi->iface, IFNAMSIZ))
            {
                struct sockaddr_dl *sdl = (struct sockaddr_dl *)ifa->ifa_addr;
                memcpy(rgi->hwaddr, LLADDR(sdl), 6);
                rgi->flags |= RGI_HWADDR_DEFINED;
            }
        }

        freeifaddrs(ifap);
#endif /* if defined(TARGET_SOLARIS) */
    }

done:
    if (sockfd >= 0)
    {
        close(sockfd);
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
get_default_gateway_ipv6(struct route_ipv6_gateway_info *rgi6, const struct in6_addr *dest,
                         openvpn_net_ctx_t *ctx)
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
#ifdef TARGET_OPENBSD
    rtm_addrs = RTA_DST | RTA_NETMASK; /* Kernel refuses RTA_IFP */
#else
    rtm_addrs = RTA_DST | RTA_NETMASK | RTA_IFP;
#endif

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

    if (dest != NULL /* specific host? */
        && !IN6_IS_ADDR_UNSPECIFIED(dest))
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
    sockfd = socket(PF_ROUTE, SOCK_RAW, 0);
    if (sockfd < 0)
    {
        msg(M_WARN, "GDG6: socket #1 failed");
        goto done;
    }
    if (write(sockfd, (char *)&m_rtmsg, l) < 0)
    {
        msg(M_WARN | M_ERRNO, "GDG6: problem writing to routing socket");
        goto done;
    }

    do
    {
        l = read(sockfd, (char *)&m_rtmsg, sizeof(m_rtmsg));
    } while (l > 0 && (rtm.rtm_seq != seq || rtm.rtm_pid != pid));

    close(sockfd);
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
        if (gate->sa_len == sizeof(struct sockaddr_in6) && IN6_IS_ADDR_LINKLOCAL(&gw))
        {
            gw.s6_addr[2] = gw.s6_addr[3] = 0;
        }

        if (gate->sa_len != sizeof(struct sockaddr_in6) || IN6_IS_ADDR_UNSPECIFIED(&gw))
        {
            rgi6->flags |= RGI_ON_LINK;
        }
        else
#endif
        {
            rgi6->gateway.addr_ipv6 = gw;
        }
        rgi6->flags |= RGI_ADDR_DEFINED;

        if (ifp)
        {
            /* get interface name */
            const struct sockaddr_dl *adl = (struct sockaddr_dl *)ifp;
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
        close(sockfd);
    }
}

#if defined(__GNUC__) || defined(__clang__)
#pragma GCC diagnostic pop
#endif

#undef max

#elif defined(TARGET_HAIKU)

void
get_default_gateway(struct route_gateway_info *rgi, in_addr_t dest, openvpn_net_ctx_t *ctx)
{
    CLEAR(*rgi);

    int sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0)
    {
        msg(M_ERRNO, "%s: Error opening socket for AF_INET", __func__);
        return;
    }

    struct ifconf config;
    config.ifc_len = sizeof(config.ifc_value);
    if (ioctl(sockfd, SIOCGRTSIZE, &config, sizeof(struct ifconf)) < 0)
    {
        msg(M_ERRNO, "%s: Error getting routing table size", __func__);
        return;
    }

    uint32 size = (uint32)config.ifc_value;
    if (size == 0)
    {
        return;
    }

    void *buffer = malloc(size);
    check_malloc_return(buffer);

    config.ifc_len = size;
    config.ifc_buf = buffer;
    if (ioctl(sockfd, SIOCGRTTABLE, &config, sizeof(struct ifconf)) < 0)
    {
        free(buffer);
        return;
    }

    struct ifreq *interface = (struct ifreq *)buffer;
    struct ifreq *end = (struct ifreq *)((uint8 *)buffer + size);

    while (interface < end)
    {
        struct route_entry route = interface->ifr_route;
        if ((route.flags & RTF_GATEWAY) != 0 && (route.flags & RTF_DEFAULT) != 0)
        {
            rgi->gateway.addr = ntohl(((struct sockaddr_in *)route.gateway)->sin_addr.s_addr);
            rgi->flags = RGI_ADDR_DEFINED | RGI_IFACE_DEFINED;
            strncpy(rgi->iface, interface->ifr_name, sizeof(rgi->iface));
        }

        int32 address_size = 0;
        if (route.destination != NULL)
        {
            address_size += route.destination->sa_len;
        }
        if (route.mask != NULL)
        {
            address_size += route.mask->sa_len;
        }
        if (route.gateway != NULL)
        {
            address_size += route.gateway->sa_len;
        }

        interface = (struct ifreq *)((addr_t)interface + IF_NAMESIZE + sizeof(struct route_entry)
                                     + address_size);
    }
    free(buffer);
}

void
get_default_gateway_ipv6(struct route_ipv6_gateway_info *rgi6, const struct in6_addr *dest,
                         openvpn_net_ctx_t *ctx)
{
    /* TODO: Same for ipv6 with AF_INET6 */
    CLEAR(*rgi6);
}

#else

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
get_default_gateway(struct route_gateway_info *rgi, in_addr_t dest, openvpn_net_ctx_t *ctx)
{
    CLEAR(*rgi);
}
void
get_default_gateway_ipv6(struct route_ipv6_gateway_info *rgi6, const struct in6_addr *dest,
                         openvpn_net_ctx_t *ctx)
{
    msg(D_ROUTE, "no support for get_default_gateway_ipv6() on this system");
    CLEAR(*rgi6);
}

#endif

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

static void
get_bypass_addresses(struct route_bypass *rb, const unsigned int flags) /* PLATFORM-SPECIFIC */
{
    /* no-op */
}

/*
 * Test if addr is reachable via a local interface (return ILA_LOCAL),
 * or if it needs to be routed via the default gateway (return
 * ILA_NONLOCAL).  If the target platform doesn't implement this
 * function, return ILA_NOT_IMPLEMENTED.
 *
 * Used by redirect-gateway autolocal feature
 */

int
test_local_addr(const in_addr_t addr, const struct route_gateway_info *rgi) /* PLATFORM-SPECIFIC */
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
