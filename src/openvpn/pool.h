/*
 *  OpenVPN -- An application to securely tunnel IP networks
 *             over a single TCP/UDP port, with support for SSL/TLS-based
 *             session authentication and key exchange,
 *             packet encryption, packet authentication, and
 *             packet compression.
 *
 *  Copyright (C) 2002-2021 OpenVPN Inc <sales@openvpn.net>
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

#ifndef POOL_H
#define POOL_H

/*#define IFCONFIG_POOL_TEST*/

#include "basic.h"
#include "status.h"

#define IFCONFIG_POOL_MAX         65536
#define IFCONFIG_POOL_MIN_NETBITS    16

enum pool_type
{
    IFCONFIG_POOL_30NET,
    IFCONFIG_POOL_INDIV
};

struct ifconfig_pool_entry
{
    bool in_use;
    char *common_name;
    time_t last_release;
    bool fixed;
};

struct ifconfig_pool
{
    bool duplicate_cn;
    struct {
        bool enabled;
        enum pool_type type;
        in_addr_t base;
    } ipv4;
    struct {
        bool enabled;
        struct in6_addr base;
    } ipv6;
    int size;
    struct ifconfig_pool_entry *list;
};

struct ifconfig_pool_persist
{
    struct status_output *file;
    bool fixed;
};

typedef int ifconfig_pool_handle;

struct ifconfig_pool *ifconfig_pool_init(const bool ipv4_pool,
                                         enum pool_type type, in_addr_t start,
                                         in_addr_t end, const bool duplicate_cn,
                                         const bool ipv6_pool,
                                         const struct in6_addr ipv6_base,
                                         const int ipv6_netbits);

void ifconfig_pool_free(struct ifconfig_pool *pool);

bool ifconfig_pool_verify_range(const int msglevel, const in_addr_t start, const in_addr_t end);

ifconfig_pool_handle ifconfig_pool_acquire(struct ifconfig_pool *pool, in_addr_t *local, in_addr_t *remote, struct in6_addr *remote_ipv6, const char *common_name);

bool ifconfig_pool_release(struct ifconfig_pool *pool, ifconfig_pool_handle hand, const bool hard);

struct ifconfig_pool_persist *ifconfig_pool_persist_init(const char *filename, int refresh_freq);

void ifconfig_pool_persist_close(struct ifconfig_pool_persist *persist);

bool ifconfig_pool_write_trigger(struct ifconfig_pool_persist *persist);

void ifconfig_pool_read(struct ifconfig_pool_persist *persist, struct ifconfig_pool *pool);

void ifconfig_pool_write(struct ifconfig_pool_persist *persist, const struct ifconfig_pool *pool);

#ifdef IFCONFIG_POOL_TEST
void ifconfig_pool_test(in_addr_t start, in_addr_t end);

#endif

#endif /* ifndef POOL_H */
