/*
 *  Networking API common implementation
 *
 *  Copyright (C) 2020 Gaëtan Harter <hartergaetan@gmail.com>
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

#ifdef TARGET_LINUX
#if defined(ENABLE_IPROUTE) || defined(ENABLE_SITNL)

#include "networking.h"

int
net_ctx_init(struct context *c, openvpn_net_ctx_t *ctx)
{
    return net_ops->ctx_init(c, ctx);
}

void
net_ctx_reset(openvpn_net_ctx_t *ctx)
{
    net_ops->ctx_reset(ctx);
}

void
net_ctx_free(openvpn_net_ctx_t *ctx) {
    net_ops->ctx_free(ctx);
}

int
net_iface_up(openvpn_net_ctx_t *ctx, const openvpn_net_iface_t *iface, bool up)
{
    return net_ops->iface_up(ctx, iface, up);
}

int
net_iface_mtu_set(openvpn_net_ctx_t *ctx, const openvpn_net_iface_t *iface,
                  uint32_t mtu)
{
    return net_ops->iface_mtu_set(ctx, iface, mtu);
}
int
net_addr_v4_add(openvpn_net_ctx_t *ctx, const openvpn_net_iface_t *iface,
                const in_addr_t *addr, int prefixlen)
{
    return net_ops->addr_v4_add(ctx, iface, addr, prefixlen);
}

int
net_addr_v6_add(openvpn_net_ctx_t *ctx, const openvpn_net_iface_t *iface,
                const struct in6_addr *addr, int prefixlen)
{
    return net_ops->addr_v6_add(ctx, iface, addr, prefixlen);
}

int
net_addr_v4_del(openvpn_net_ctx_t *ctx, const openvpn_net_iface_t *iface,
                const in_addr_t *addr, int prefixlen)
{
    return net_ops->addr_v4_del(ctx, iface, addr, prefixlen);
}

int
net_addr_v6_del(openvpn_net_ctx_t *ctx, const openvpn_net_iface_t *iface,
                const struct in6_addr *addr, int prefixlen)
{
    return net_ops->addr_v6_del(ctx, iface, addr, prefixlen);
}

int
net_addr_ptp_v4_add(openvpn_net_ctx_t *ctx, const openvpn_net_iface_t *iface,
                    const in_addr_t *local, const in_addr_t *remote)
{
    return net_ops->addr_ptp_v4_add(ctx, iface, local, remote);
}

int
net_addr_ptp_v4_del(openvpn_net_ctx_t *ctx, const openvpn_net_iface_t *iface,
                    const in_addr_t *local, const in_addr_t *remote)
{
    return net_ops->addr_ptp_v4_del(ctx, iface, local, remote);
}

int
net_route_v4_add(openvpn_net_ctx_t *ctx, const in_addr_t *dst, int prefixlen,
                 const in_addr_t *gw, const openvpn_net_iface_t *iface,
                 uint32_t table, int metric)
{
    return net_ops->route_v4_add(ctx, dst, prefixlen, gw, iface, table, metric);
}

int
net_route_v6_add(openvpn_net_ctx_t *ctx, const struct in6_addr *dst,
                 int prefixlen, const struct in6_addr *gw,
                 const openvpn_net_iface_t *iface, uint32_t table,
                 int metric)
{
    return net_ops->route_v6_add(ctx, dst, prefixlen, gw, iface, table, metric);
}

int
net_route_v4_del(openvpn_net_ctx_t *ctx, const in_addr_t *dst, int prefixlen,
                 const in_addr_t *gw, const openvpn_net_iface_t *iface,
                 uint32_t table, int metric)
{
    return net_ops->route_v4_del(ctx, dst, prefixlen, gw, iface, table, metric);
}

int
net_route_v6_del(openvpn_net_ctx_t *ctx, const struct in6_addr *dst,
                 int prefixlen, const struct in6_addr *gw,
                 const openvpn_net_iface_t *iface, uint32_t table, int metric)
{
    return net_ops->route_v6_del(ctx, dst, prefixlen, gw, iface, table, metric);
}

int
net_route_v4_best_gw(openvpn_net_ctx_t *ctx, const in_addr_t *dst,
                     in_addr_t *best_gw, char *best_iface)
{
    return net_ops->route_v4_best_gw(ctx, dst, best_gw, best_iface);
}

int
net_route_v6_best_gw(openvpn_net_ctx_t *ctx, const struct in6_addr *dst,
                     struct in6_addr *best_gw, char *best_iface)
{
    return net_ops->route_v6_best_gw(ctx, dst, best_gw, best_iface);
}

#endif /* ENABLE_IPROUTE || ENABLE_SITNL */
#endif /* TARGET_LINUX */
