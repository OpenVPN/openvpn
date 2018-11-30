/*
 *  OpenVPN -- An application to securely tunnel IP networks
 *             over a single TCP/UDP port, with support for SSL/TLS-based
 *             session authentication and key exchange,
 *             packet encryption, packet authentication, and
 *             packet compression.
 *
 *  Copyright (C) 2016 Selva Nair <selva.nair@gmail.com>
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

#ifdef _WIN32

#ifndef OPENVPN_BLOCK_DNS_H
#define OPENVPN_BLOCK_DNS_H

/* Any value less than 5 should work fine. 3 is chosen without any real reason. */
#define BLOCK_DNS_IFACE_METRIC 3

typedef void (*block_dns_msg_handler_t) (DWORD err, const char *msg);

DWORD
delete_block_dns_filters(HANDLE engine);

DWORD
add_block_dns_filters(HANDLE *engine, int iface_index, const WCHAR *exe_path,
                      block_dns_msg_handler_t msg_handler_callback);

/**
 * Return interface metric value for the specified interface index.
 *
 * @param index         The index of TAP adapter.
 * @param family        Address family (AF_INET for IPv4 and AF_INET6 for IPv6).
 * @param is_auto       On return set to true if automatic metric is in use.
 *                      Unused if NULL.
 *
 * @return positive interface metric on success or -1 on error
 */
int
get_interface_metric(const NET_IFINDEX index, const ADDRESS_FAMILY family, int *is_auto);

/**
 * Sets interface metric value for specified interface index.
 *
 * @param index The index of TAP adapter
 * @param family Address family (AF_INET for IPv4 and AF_INET6 for IPv6)
 * @param metric Metric value. 0 for automatic metric
 *
 * @return 0 on success, a non-zero status code of the last failed action on failure.
 */

DWORD
set_interface_metric(const NET_IFINDEX index, const ADDRESS_FAMILY family,
                     const ULONG metric);

#endif /* ifndef OPENVPN_BLOCK_DNS_H */
#endif /* ifdef _WIN32 */
