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

/**
 * @file
 * DNS resolution
 */
#ifndef RESOLVE_H
#define RESOLVE_H

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "syshead.h"

#include "sig.h"

#define GETADDR_RESOLVE                 (1u << 0)
#define GETADDR_FATAL                   (1u << 1)
#define GETADDR_HOST_ORDER              (1u << 2)
#define GETADDR_MENTION_RESOLVE_RETRY   (1u << 3)
#define GETADDR_FATAL_ON_SIGNAL         (1u << 4)
#define GETADDR_WARN_ON_SIGNAL          (1u << 5)
#define GETADDR_MSG_VIRT_OUT            (1u << 6)
#define GETADDR_TRY_ONCE                (1u << 7)
#define GETADDR_UPDATE_MANAGEMENT_STATE (1u << 8)
#define GETADDR_RANDOMIZE               (1u << 9)
#define GETADDR_PASSIVE                 (1u << 10)
#define GETADDR_DATAGRAM                (1u << 11)

#define GETADDR_CACHE_MASK (GETADDR_DATAGRAM | GETADDR_PASSIVE)

/**
 * Convert sockflags/getaddr_flags into getaddr_flags
 */
unsigned int sf2gaf(const unsigned int getaddr_flags, const unsigned int sockflags);

/**
 * Translate an IPv4 addr or hostname from string form to in_addr_t
 *
 * In case of resolve error, it will try again for
 * resolve_retry_seconds seconds.
 */
in_addr_t getaddr(unsigned int flags, const char *hostname, int resolve_retry_seconds,
                  bool *succeeded, struct signal_info *sig_info);

in_addr_t get_ip_addr(const char *ip_string, msglvl_t msglevel, bool *error);

/**
 * Translate an IPv6 addr or hostname from string form to in6_addr
 */
bool get_ipv6_addr(const char *hostname, struct in6_addr *network, unsigned int *netbits,
                   msglvl_t msglevel);

static inline bool
ipv6_addr_safe_hexplusbits(const char *ipv6_prefix_spec)
{
    return get_ipv6_addr(ipv6_prefix_spec, NULL, NULL, M_WARN);
}

int openvpn_getaddrinfo(unsigned int flags, const char *hostname, const char *servname,
                        int resolve_retry_seconds, struct signal_info *sig_info, int ai_family,
                        struct addrinfo **res);

void do_preresolve(struct context *c);

/* struct to hold preresolved host names */
struct cached_dns_entry
{
    const char *hostname;
    const char *servname;
    int ai_family;
    unsigned int flags;
    struct addrinfo *ai;
    struct cached_dns_entry *next;
};

/**
 * get_cached_dns_entry return 0 on success and -1
 * otherwise. (like getaddrinfo())
 */
int get_cached_dns_entry(struct cached_dns_entry *dns_cache, const char *hostname,
                         const char *servname, int ai_family,
                         unsigned int resolve_flags, struct addrinfo **ai);

#endif /* RESOLVE_H */
