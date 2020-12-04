/*
 *  Networking API implementation for iproute2
 *
 *  Copyright (C) 2018 Antonio Quartulli <a@unstable.cc>
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
 *  You should have received a copy of the GNU General Public License
 *  along with this program (see the file COPYING included with this
 *  distribution); if not, write to the Free Software Foundation, Inc.,
 *  59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#elif defined(_MSC_VER)
#include "config-msvc.h"
#endif

#if defined(TARGET_LINUX) && defined(ENABLE_IPROUTE)

#include "syshead.h"

#include "argv.h"
#include "networking.h"
#include "misc.h"
#include "openvpn.h"
#include "run_command.h"
#include "socket.h"

#include <stdbool.h>
#include <netinet/in.h>

static int
net_iproute2_ctx_init(struct context *c, openvpn_net_ctx_t *ctx_)
{
    openvpn_net_iproute2_ctx_t *ctx = (openvpn_net_iproute2_ctx_t *)ctx_;
    ctx->es = NULL;
    if (c)
    {
        ctx->es = c->es;
    }
    ctx->gc = gc_new();

    return 0;
}

static void
net_iproute2_ctx_reset(openvpn_net_ctx_t *ctx_)
{
    openvpn_net_iproute2_ctx_t *ctx = (openvpn_net_iproute2_ctx_t *)ctx_;
    gc_reset(&ctx->gc);
}

static void
net_iproute2_ctx_free(openvpn_net_ctx_t *ctx_)
{
    openvpn_net_iproute2_ctx_t *ctx = (openvpn_net_iproute2_ctx_t *)ctx_;
    gc_free(&ctx->gc);
}

static int
net_iproute2_iface_up(openvpn_net_ctx_t *ctx_, const char *iface, bool up)
{
    openvpn_net_iproute2_ctx_t *ctx = (openvpn_net_iproute2_ctx_t *)ctx_;
    struct argv argv = argv_new();

    argv_printf(&argv, "%s link set dev %s %s", iproute_path, iface,
                up ? "up" : "down");
    argv_msg(M_INFO, &argv);
    openvpn_execve_check(&argv, ctx->es, S_FATAL, "Linux ip link set failed");

    argv_free(&argv);

    return 0;
}

static int
net_iproute2_iface_mtu_set(openvpn_net_ctx_t *ctx_, const char *iface,
                           uint32_t mtu)
{
    openvpn_net_iproute2_ctx_t *ctx = (openvpn_net_iproute2_ctx_t *)ctx_;
    struct argv argv = argv_new();

    argv_printf(&argv, "%s link set dev %s up mtu %d", iproute_path, iface,
                mtu);
    argv_msg(M_INFO, &argv);
    openvpn_execve_check(&argv, ctx->es, S_FATAL, "Linux ip link set failed");

    argv_free(&argv);

    return 0;
}

static int
net_iproute2_addr_v4_add(openvpn_net_ctx_t *ctx_, const char *iface,
                         const in_addr_t *addr, int prefixlen)
{
    openvpn_net_iproute2_ctx_t *ctx = (openvpn_net_iproute2_ctx_t *)ctx_;
    struct argv argv = argv_new();

    const char *addr_str = print_in_addr_t(*addr, 0, &ctx->gc);

    argv_printf(&argv, "%s addr add dev %s %s/%d", iproute_path, iface,
                addr_str, prefixlen);
    argv_msg(M_INFO, &argv);
    openvpn_execve_check(&argv, ctx->es, S_FATAL, "Linux ip addr add failed");

    argv_free(&argv);

    return 0;
}

static int
net_iproute2_addr_v6_add(openvpn_net_ctx_t *ctx_, const char *iface,
                         const struct in6_addr *addr, int prefixlen)
{
    openvpn_net_iproute2_ctx_t *ctx = (openvpn_net_iproute2_ctx_t *)ctx_;
    struct argv argv = argv_new();
    char *addr_str = (char *)print_in6_addr(*addr, 0, &ctx->gc);

    argv_printf(&argv, "%s -6 addr add %s/%d dev %s", iproute_path, addr_str,
                prefixlen, iface);
    argv_msg(M_INFO, &argv);
    openvpn_execve_check(&argv, ctx->es, S_FATAL,
                         "Linux ip -6 addr add failed");

    argv_free(&argv);

    return 0;
}

static int
net_iproute2_addr_v4_del(openvpn_net_ctx_t *ctx_, const char *iface,
                         const in_addr_t *addr, int prefixlen)
{
    openvpn_net_iproute2_ctx_t *ctx = (openvpn_net_iproute2_ctx_t *)ctx_;
    struct argv argv = argv_new();
    const char *addr_str = print_in_addr_t(*addr, 0, &ctx->gc);

    argv_printf(&argv, "%s addr del dev %s %s/%d", iproute_path, iface,
                addr_str, prefixlen);

    argv_msg(M_INFO, &argv);
    openvpn_execve_check(&argv, ctx->es, 0, "Linux ip addr del failed");

    argv_free(&argv);

    return 0;
}

static int
net_iproute2_addr_v6_del(openvpn_net_ctx_t *ctx_, const char *iface,
                         const struct in6_addr *addr, int prefixlen)
{
    openvpn_net_iproute2_ctx_t *ctx = (openvpn_net_iproute2_ctx_t *)ctx_;
    struct argv argv = argv_new();
    char *addr_str = (char *)print_in6_addr(*addr, 0, &ctx->gc);

    argv_printf(&argv, "%s -6 addr del %s/%d dev %s", iproute_path,
                addr_str, prefixlen, iface);
    argv_msg(M_INFO, &argv);
    openvpn_execve_check(&argv, ctx->es, 0, "Linux ip -6 addr del failed");

    argv_free(&argv);

    return 0;
}

static int
net_iproute2_addr_ptp_v4_add(openvpn_net_ctx_t *ctx_, const char *iface,
                             const in_addr_t *local, const in_addr_t *remote)
{
    openvpn_net_iproute2_ctx_t *ctx = (openvpn_net_iproute2_ctx_t *)ctx_;
    struct argv argv = argv_new();
    const char *local_str = print_in_addr_t(*local, 0, &ctx->gc);
    const char *remote_str = print_in_addr_t(*remote, 0, &ctx->gc);

    argv_printf(&argv, "%s addr add dev %s local %s peer %s", iproute_path,
                iface, local_str, remote_str);
    argv_msg(M_INFO, &argv);
    openvpn_execve_check(&argv, ctx->es, S_FATAL, "Linux ip addr add failed");

    argv_free(&argv);

    return 0;
}

static int
net_iproute2_addr_ptp_v4_del(openvpn_net_ctx_t *ctx_, const char *iface,
                             const in_addr_t *local, const in_addr_t *remote)
{
    openvpn_net_iproute2_ctx_t *ctx = (openvpn_net_iproute2_ctx_t *)ctx_;
    struct argv argv = argv_new();
    const char *local_str = print_in_addr_t(*local, 0, &ctx->gc);
    const char *remote_str = print_in_addr_t(*remote, 0, &ctx->gc);

    argv_printf(&argv, "%s addr del dev %s local %s peer %s", iproute_path,
                iface, local_str, remote_str);
    argv_msg(M_INFO, &argv);
    openvpn_execve_check(&argv, ctx->es, 0, "Linux ip addr del failed");

    argv_free(&argv);

    return 0;
}

static int
net_iproute2_route_v4_add(openvpn_net_ctx_t *ctx_, const in_addr_t *dst,
                          int prefixlen, const in_addr_t *gw, const char *iface,
                          uint32_t table, int metric)
{
    openvpn_net_iproute2_ctx_t *ctx = (openvpn_net_iproute2_ctx_t *)ctx_;
    struct argv argv = argv_new();
    const char *dst_str = print_in_addr_t(*dst, 0, &ctx->gc);

    argv_printf(&argv, "%s route add %s/%d", iproute_path, dst_str, prefixlen);

    if (metric > 0)
    {
        argv_printf_cat(&argv, "metric %d", metric);
    }

    if (iface)
    {
        argv_printf_cat(&argv, "dev %s", iface);
    }

    if (gw)
    {
        const char *gw_str = print_in_addr_t(*gw, 0, &ctx->gc);

        argv_printf_cat(&argv, "via %s", gw_str);
    }

    argv_msg(D_ROUTE, &argv);
    openvpn_execve_check(&argv, ctx->es, 0, "ERROR: Linux route add command failed");

    argv_free(&argv);

    return 0;
}

static int
net_iproute2_route_v6_add(openvpn_net_ctx_t *ctx_, const struct in6_addr *dst,
                          int prefixlen, const struct in6_addr *gw,
                          const char *iface, uint32_t table, int metric)
{
    openvpn_net_iproute2_ctx_t *ctx = (openvpn_net_iproute2_ctx_t *)ctx_;
    struct argv argv = argv_new();
    char *dst_str = (char *)print_in6_addr(*dst, 0, &ctx->gc);

    argv_printf(&argv, "%s -6 route add %s/%d dev %s", iproute_path, dst_str,
                prefixlen, iface);

    if (gw)
    {
        char *gw_str = (char *)print_in6_addr(*gw, 0, &ctx->gc);

        argv_printf_cat(&argv, "via %s", gw_str);
    }

    if (metric > 0)
    {
        argv_printf_cat(&argv, "metric %d", metric);
    }

    argv_msg(D_ROUTE, &argv);
    openvpn_execve_check(&argv, ctx->es, 0, "ERROR: Linux route -6 add command failed");

    argv_free(&argv);

    return 0;
}

static int
net_iproute2_route_v4_del(openvpn_net_ctx_t *ctx_, const in_addr_t *dst,
                          int prefixlen, const in_addr_t *gw, const char *iface,
                          uint32_t table, int metric)
{
    openvpn_net_iproute2_ctx_t *ctx = (openvpn_net_iproute2_ctx_t *)ctx_;
    struct argv argv = argv_new();
    const char *dst_str = print_in_addr_t(*dst, 0, &ctx->gc);

    argv_printf(&argv, "%s route del %s/%d", iproute_path, dst_str, prefixlen);

    if (metric > 0)
    {
        argv_printf_cat(&argv, "metric %d", metric);
    }

    argv_msg(D_ROUTE, &argv);
    openvpn_execve_check(&argv, ctx->es, 0, "ERROR: Linux route delete command failed");

    argv_free(&argv);

    return 0;
}

static int
net_iproute2_route_v6_del(openvpn_net_ctx_t *ctx_, const struct in6_addr *dst,
                          int prefixlen, const struct in6_addr *gw,
                          const char *iface, uint32_t table, int metric)
{
    openvpn_net_iproute2_ctx_t *ctx = (openvpn_net_iproute2_ctx_t *)ctx_;
    struct argv argv = argv_new();
    char *dst_str = (char *)print_in6_addr(*dst, 0, &ctx->gc);

    argv_printf(&argv, "%s -6 route del %s/%d dev %s", iproute_path, dst_str,
                prefixlen, iface);

    if (gw)
    {
        char *gw_str = (char *)print_in6_addr(*gw, 0, &ctx->gc);

        argv_printf_cat(&argv, "via %s", gw_str);
    }

    if (metric > 0)
    {
        argv_printf_cat(&argv, "metric %d", metric);
    }

    argv_msg(D_ROUTE, &argv);
    openvpn_execve_check(&argv, ctx->es, 0, "ERROR: Linux route -6 del command failed");

    argv_free(&argv);

    return 0;
}

static int
net_iproute2_route_v4_best_gw(openvpn_net_ctx_t *ctx_, const in_addr_t *dst,
                              in_addr_t *best_gw, char *best_iface)
{
    best_iface[0] = '\0';

    FILE *fp = fopen("/proc/net/route", "r");
    if (!fp)
    {
        return -1;
    }

    char line[256];
    int count = 0;
    unsigned int lowest_metric = UINT_MAX;
    while (fgets(line, sizeof(line), fp) != NULL)
    {
        if (count)
        {
            unsigned int net_x = 0;
            unsigned int mask_x = 0;
            unsigned int gw_x = 0;
            unsigned int metric = 0;
            unsigned int flags = 0;
            char name[16];
            name[0] = '\0';

            const int np = sscanf(line, "%15s\t%x\t%x\t%x\t%*s\t%*s\t%d\t%x",
                                  name, &net_x, &gw_x, &flags, &metric,
                                  &mask_x);

            if (np == 6 && (flags & IFF_UP))
            {
                const in_addr_t net = ntohl(net_x);
                const in_addr_t mask = ntohl(mask_x);
                const in_addr_t gw = ntohl(gw_x);

                if (!net && !mask && metric < lowest_metric)
                {
                    *best_gw = gw;
                    strcpy(best_iface, name);
                    lowest_metric = metric;
                }
            }
        }
        ++count;
    }
    fclose(fp);

    return 0;
}

/*
 * The following function is not implemented in the iproute backend as it
 * uses the sitnl implementation from networking_sitnl.c.
 */
extern int
net_sitnl_route_v6_best_gw(openvpn_net_ctx_t *ctx, const struct in6_addr *dst,
                           struct in6_addr *best_gw, char *best_iface);
int
net_iproute2_route_v6_best_gw(openvpn_net_ctx_t *ctx,
                              const struct in6_addr *dst,
                              struct in6_addr *best_gw, char *best_iface)
{
    return net_sitnl_route_v6_best_gw(ctx, dst, best_gw, best_iface);
}


const struct net_ops net_iproute2_ops = {
    .ctx_init = net_iproute2_ctx_init,
    .ctx_reset = net_iproute2_ctx_reset,
    .ctx_free = net_iproute2_ctx_free,
    .iface_up = net_iproute2_iface_up,
    .iface_mtu_set = net_iproute2_iface_mtu_set,
    .addr_v4_add = net_iproute2_addr_v4_add,
    .addr_v6_add = net_iproute2_addr_v6_add,
    .addr_v4_del = net_iproute2_addr_v4_del,
    .addr_v6_del = net_iproute2_addr_v6_del,
    .addr_ptp_v4_add = net_iproute2_addr_ptp_v4_add,
    .addr_ptp_v4_del = net_iproute2_addr_ptp_v4_del,
    .route_v4_add = net_iproute2_route_v4_add,
    .route_v6_add = net_iproute2_route_v6_add,
    .route_v4_del = net_iproute2_route_v4_del,
    .route_v6_del = net_iproute2_route_v6_del,
    .route_v4_best_gw = net_iproute2_route_v4_best_gw,
    .route_v6_best_gw = net_iproute2_route_v6_best_gw,
};

#endif /* ENABLE_IPROUTE && TARGET_LINUX */
