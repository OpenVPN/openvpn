/*
 *  Generic interface to platform specific networking code
 *
 *  Copyright (C) 2016-2022 Antonio Quartulli <a@unstable.cc>
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

#ifndef NETWORKING_H_
#define NETWORKING_H_

#include "syshead.h"

struct context;

#ifdef ENABLE_SITNL
#include "networking_sitnl.h"
#elif ENABLE_IPROUTE
#include "networking_iproute2.h"
#else
/* define mock types to ensure code builds on any platform */
typedef void *openvpn_net_ctx_t;
typedef void *openvpn_net_iface_t;

static inline int
net_ctx_init(struct context *c, openvpn_net_ctx_t *ctx)
{
    return 0;
}

static inline void
net_ctx_reset(openvpn_net_ctx_t *ctx)
{
    (void)ctx;
}

static inline void
net_ctx_free(openvpn_net_ctx_t *ctx)
{
    (void)ctx;
}
#endif /* ifdef ENABLE_SITNL */

#if defined(ENABLE_SITNL) || defined(ENABLE_IPROUTE)

/**
 * Initialize the platform specific context object
 *
 * @param c         openvpn generic context
 * @param ctx       the implementation specific context to initialize
 *
 * @return          0 on success, a negative error code otherwise
 */
int net_ctx_init(struct context *c, openvpn_net_ctx_t *ctx);

/**
 * Release resources allocated by the internal garbage collector
 *
 * @param ctx       the implementation specific context
 */
void net_ctx_reset(openvpn_net_ctx_t *ctx);

/**
 * Release all resources allocated within the platform specific context object
 *
 * @param ctx       the implementation specific context to release
 */
void net_ctx_free(openvpn_net_ctx_t *ctx);

/**
 * Bring interface up or down.
 *
 * @param ctx       the implementation specific context
 * @param iface     the interface to modify
 * @param up        true if the interface has to be brought up, false otherwise
 *
 * @return          0 on success, a negative error code otherwise
 */
int net_iface_up(openvpn_net_ctx_t *ctx, const openvpn_net_iface_t *iface,
                 bool up);

/**
 * Set the MTU for an interface
 *
 * @param ctx       the implementation specific context
 * @param iface     the interface to modify
 * @param mtru      the new MTU
 *
 * @return          0 on success, a negative error code otherwise
 */
int net_iface_mtu_set(openvpn_net_ctx_t *ctx,
                      const openvpn_net_iface_t *iface, uint32_t mtu);

/**
 * Set the Link Layer (Ethernet) address of the TAP interface
 *
 * @param ctx       the implementation specific context
 * @param iface     the interface to modify
 * @param addr      the new address to set (expected ETH_ALEN bytes (6))
 *
 * @return          0 on success, a negative error code otherwise
 */
int net_addr_ll_set(openvpn_net_ctx_t *ctx, const openvpn_net_iface_t *iface,
                    uint8_t *addr);

/**
 * Add an IPv4 address to an interface
 *
 * @param ctx       the implementation specific context
 * @param iface     the interface where the address has to be added
 * @param addr      the address to add
 * @param prefixlen the prefix length of the network associated with the address
 *
 * @return          0 on success, a negative error code otherwise
 */
int net_addr_v4_add(openvpn_net_ctx_t *ctx, const openvpn_net_iface_t *iface,
                    const in_addr_t *addr, int prefixlen);

/**
 * Add an IPv6 address to an interface
 *
 * @param ctx       the implementation specific context
 * @param iface     the interface where the address has to be added
 * @param addr      the address to add
 * @param prefixlen the prefix length of the network associated with the address
 *
 * @return          0 on success, a negative error code otherwise
 */

int net_addr_v6_add(openvpn_net_ctx_t *ctx, const openvpn_net_iface_t *iface,
                    const struct in6_addr *addr, int prefixlen);

/**
 * Remove an IPv4 from an interface
 *
 * @param ctx       the implementation specific context
 * @param iface     the interface to remove the address from
 * @param prefixlen the prefix length of the network associated with the address
 *
 * @return          0 on success, a negative error code otherwise
 */
int net_addr_v4_del(openvpn_net_ctx_t *ctx, const openvpn_net_iface_t *iface,
                    const in_addr_t *addr, int prefixlen);

/**
 * Remove an IPv6 from an interface
 *
 * @param ctx       the implementation specific context
 * @param iface     the interface to remove the address from
 * @param prefixlen the prefix length of the network associated with the address
 *
 * @return          0 on success, a negative error code otherwise
 */
int net_addr_v6_del(openvpn_net_ctx_t *ctx, const openvpn_net_iface_t *iface,
                    const struct in6_addr *addr, int prefixlen);

/**
 * Add a point-to-point IPv4 address to an interface
 *
 * @param ctx       the implementation specific context
 * @param iface     the interface where the address has to be added
 * @param local     the address to add
 * @param remote    the associated p-t-p remote address
 *
 * @return          0 on success, a negative error code otherwise
 */
int net_addr_ptp_v4_add(openvpn_net_ctx_t *ctx,
                        const openvpn_net_iface_t *iface,
                        const in_addr_t *local, const in_addr_t *remote);

/**
 * Remove a point-to-point IPv4 address from an interface
 *
 * @param ctx       the implementation specific context
 * @param iface     the interface to remove the address from
 * @param local     the address to remove
 * @param remote    the associated p-t-p remote address
 *
 * @return          0 on success, a negative error code otherwise
 */
int net_addr_ptp_v4_del(openvpn_net_ctx_t *ctx,
                        const openvpn_net_iface_t *iface,
                        const in_addr_t *local, const in_addr_t *remote);


/**
 * Add a route for an IPv4 address/network
 *
 * @param ctx       the implementation specific context
 * @param dst       the destination of the route
 * @param prefixlen the length of the prefix of the destination
 * @param gw        the gateway for this route
 * @param iface     the interface for this route (can be NULL)
 * @param table     the table to add this route to (if 0, will be added to the
 *                  main table)
 * @param metric    the metric associated with the route
 *
 * @return          0 on success, a negative error code otherwise
 */
int net_route_v4_add(openvpn_net_ctx_t *ctx, const in_addr_t *dst,
                     int prefixlen, const in_addr_t *gw,
                     const openvpn_net_iface_t *iface, uint32_t table,
                     int metric);

/**
 * Add a route for an IPv6 address/network
 *
 * @param ctx       the implementation specific context
 * @param dst       the destination of the route
 * @param prefixlen the length of the prefix of the destination
 * @param gw        the gateway for this route
 * @param iface     the interface for this route (can be NULL)
 * @param table     the table to add this route to (if 0, will be added to the
 *                  main table)
 * @param metric    the metric associated with the route
 *
 * @return          0 on success, a negative error code otherwise
 */
int net_route_v6_add(openvpn_net_ctx_t *ctx, const struct in6_addr *dst,
                     int prefixlen, const struct in6_addr *gw,
                     const openvpn_net_iface_t *iface,
                     uint32_t table, int metric);

/**
 * Delete a route for an IPv4 address/network
 *
 * @param ctx       the implementation specific context
 * @param dst       the destination of the route
 * @param prefixlen the length of the prefix of the destination
 * @param gw        the gateway for this route
 * @param iface     the interface for this route (can be NULL)
 * @param table     the table to add this route to (if 0, will be added to the
 *                  main table)
 * @param metric    the metric associated with the route
 *
 * @return          0 on success, a negative error code otherwise
 */
int net_route_v4_del(openvpn_net_ctx_t *ctx, const in_addr_t *dst,
                     int prefixlen, const in_addr_t *gw,
                     const openvpn_net_iface_t *iface, uint32_t table,
                     int metric);

/**
 * Delete a route for an IPv4 address/network
 *
 * @param ctx       the implementation specific context
 * @param dst       the destination of the route
 * @param prefixlen the length of the prefix of the destination
 * @param gw        the gateway for this route
 * @param iface     the interface for this route (can be NULL)
 * @param table     the table to add this route to (if 0, will be added to the
 *                  main table)
 * @param metric    the metric associated with the route
 *
 * @return          0 on success, a negative error code otherwise
 */
int net_route_v6_del(openvpn_net_ctx_t *ctx, const struct in6_addr *dst,
                     int prefixlen, const struct in6_addr *gw,
                     const openvpn_net_iface_t *iface,
                     uint32_t table, int metric);

/**
 * Retrieve the gateway and outgoing interface for the specified IPv4
 * address/network
 *
 * @param ctx           the implementation specific context
 * @param dst           The destination to lookup
 * @param best_gw       Location where the retrieved GW has to be stored
 * @param best_iface    Location where the retrieved interface has to be stored
 *
 * @return              0 on success, a negative error code otherwise
 */
int net_route_v4_best_gw(openvpn_net_ctx_t *ctx, const in_addr_t *dst,
                         in_addr_t *best_gw, openvpn_net_iface_t *best_iface);

/**
 * Retrieve the gateway and outgoing interface for the specified IPv6
 * address/network
 *
 * @param ctx           the implementation specific context
 * @param dst           The destination to lookup
 * @param best_gw       Location where the retrieved GW has to be stored
 * @param best_iface    Location where the retrieved interface has to be stored
 *
 * @return              0 on success, a negative error code otherwise
 */
int net_route_v6_best_gw(openvpn_net_ctx_t *ctx, const struct in6_addr *dst,
                         struct in6_addr *best_gw,
                         openvpn_net_iface_t *best_iface);

#endif /* ENABLE_SITNL || ENABLE_IPROUTE */

#endif /* NETWORKING_H_ */
