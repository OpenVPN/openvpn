/*
 *  Simplified Interface To NetLink
 *
 *  Copyright (C) 2016-2018 Antonio Quartulli <a@unstable.cc>
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

#ifndef SITNL_H_
#define SITNL_H_

#ifdef TARGET_LINUX

#include <stdbool.h>
#include <netinet/in.h>

/**
 * Bring interface up or down.
 *
 * @param iface     the interface to modify
 * @param up        true if the interface has to be brought up, false otherwise
 *
 * @return          0 on success, a negative error code otherwise
 */
int sitnl_iface_up(const char *iface, bool up);

/**
 * Set the MTU for an interface
 *
 * @param iface     the interface to modify
 * @param mtru      the new MTU
 *
 * @return          0 on success, a negative error code otherwise
 */
int sitnl_iface_mtu_set(const char *iface, uint32_t mtu);

/**
 * Add an IPv4 address to an interface
 *
 * @param iface     the interface where the address has to be added
 * @param addr      the address to add
 * @param prefixlen the prefix length of the network associated with the address
 * @param broadcast the broadcast address to configure on the interface
 *
 * @return          0 on success, a negative error code otherwise
 */
int sitnl_addr_v4_add(const char *iface, const in_addr_t *addr, int prefixlen,
                      const in_addr_t *broadcast);

/**
 * Add an IPv6 address to an interface
 *
 * @param iface     the interface where the address has to be added
 * @param addr      the address to add
 * @param prefixlen the prefix length of the network associated with the address
 *
 * @return          0 on success, a negative error code otherwise
 */

int sitnl_addr_v6_add(const char *iface, const struct in6_addr *addr,
                      int prefixlen);

/**
 * Remove an IPv4 from an interface
 *
 * @param iface     the interface to remove the address from
 * @param prefixlen the prefix length of the network associated with the address
 *
 * @return          0 on success, a negative error code otherwise
 */
int sitnl_addr_v4_del(const char *iface, const in_addr_t *addr, int prefixlen);

/**
 * Remove an IPv6 from an interface
 *
 * @param iface     the interface to remove the address from
 * @param prefixlen the prefix length of the network associated with the address
 *
 * @return          0 on success, a negative error code otherwise
 */
int sitnl_addr_v6_del(const char *iface, const struct in6_addr *addr,
                      int prefixlen);

/**
 * Add a point-to-point IPv4 address to an interface
 *
 * @param iface     the interface where the address has to be added
 * @param local     the address to add
 * @param remote    the associated p-t-p remote address
 *
 * @return          0 on success, a negative error code otherwise
 */
int sitnl_addr_ptp_v4_add(const char *iface, const in_addr_t *local,
                          const in_addr_t *remote);

/**
 * Remove a point-to-point IPv4 address from an interface
 *
 * @param iface     the interface to remove the address from
 * @param local     the address to remove
 *
 * @return          0 on success, a negative error code otherwise
 */
int sitnl_addr_ptp_v4_del(const char *iface, const in_addr_t *local);


/**
 * Add a route for an IPv4 address/network
 *
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
int sitnl_route_v4_add(const in_addr_t *dst, int prefixlen,
                       const in_addr_t *gw, const char *iface, uint32_t table,
                       int metric);

/**
 * Add a route for an IPv6 address/network
 *
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
int sitnl_route_v6_add(const struct in6_addr *dst, int prefixlen,
                       const struct in6_addr *gw, const char *iface,
                       uint32_t table, int metric);

/**
 * Delete a route for an IPv4 address/network
 *
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
int sitnl_route_v4_del(const in_addr_t *dst, int prefixlen,
                       const in_addr_t *gw, const char *iface, uint32_t table,
                       int metric);

/**
 * Delete a route for an IPv4 address/network
 *
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
int sitnl_route_v6_del(const struct in6_addr *dst, int prefixlen,
                       const struct in6_addr *gw, const char *iface,
                       uint32_t table, int metric);

/**
 * Retrieve the gateway and outgoing interface for the specified IPv4
 * address/network
 *
 * @param dst           The destination to lookup
 * @param prefixlen     The length of the prefix of the destination
 * @param best_gw       Location where the retrieved GW has to be stored
 * @param best_iface    Location where the retrieved interface has to be stored
 *
 * @return              0 on success, a negative error code otherwise
 */
int sitnl_route_v4_best_gw(const in_addr_t *dst, int prefixlen,
                           in_addr_t *best_gw, char *best_iface);

/**
 * Retrieve the gateway and outgoing interface for the specified IPv6
 * address/network
 *
 * @param dst           The destination to lookup
 * @param prefixlen     The length of the prefix of the destination
 * @param best_gw       Location where the retrieved GW has to be stored
 * @param best_iface    Location where the retrieved interface has to be stored
 *
 * @return              0 on success, a negative error code otherwise
 */
int sitnl_route_v6_best_gw(const struct in6_addr *dst, int prefixlen,
                           struct in6_addr *best_gw, char *best_iface);

#endif /* TARGET_LINUX */

#endif /* SITNL_H_ */
