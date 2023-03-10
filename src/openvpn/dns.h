/*
 *  OpenVPN -- An application to securely tunnel IP networks
 *             over a single UDP port, with support for SSL/TLS-based
 *             session authentication and key exchange,
 *             packet encryption, packet authentication, and
 *             packet compression.
 *
 *  Copyright (C) 2022-2023 OpenVPN Inc <sales@openvpn.net>
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

#ifndef DNS_H
#define DNS_H

#include "buffer.h"
#include "env_set.h"

enum dns_domain_type {
    DNS_DOMAINS_UNSET,
    DNS_RESOLVE_DOMAINS,
    DNS_EXCLUDE_DOMAINS
};

enum dns_security {
    DNS_SECURITY_UNSET,
    DNS_SECURITY_NO,
    DNS_SECURITY_YES,
    DNS_SECURITY_OPTIONAL
};

enum dns_server_transport {
    DNS_TRANSPORT_UNSET,
    DNS_TRANSPORT_PLAIN,
    DNS_TRANSPORT_HTTPS,
    DNS_TRANSPORT_TLS
};

struct dns_domain {
    struct dns_domain *next;
    const char *name;
};

struct dns_server_addr
{
    union {
        struct in_addr a4;
        struct in6_addr a6;
    } in;
    sa_family_t family;
    in_port_t port;
};

struct dns_server {
    struct dns_server *next;
    long priority;
    size_t addr_count;
    struct dns_server_addr addr[8];
    struct dns_domain *domains;
    enum dns_domain_type domain_type;
    enum dns_security dnssec;
    enum dns_server_transport transport;
    const char *sni;
};

struct dns_options {
    struct dns_domain *search_domains;
    struct dns_server *servers_prepull;
    struct dns_server *servers;
    struct gc_arena gc;
};

/**
 * Parses a string DNS server priority and validates it.
 *
 * @param   priority    Pointer to where the priority should be stored
 * @param   str         Priority string to parse
 * @param   pulled      Whether this was pulled from a server
 * @return              True if priority in string is valid
 */
bool dns_server_priority_parse(long *priority, const char *str, bool pulled);

/**
 * Find or create DNS server with priority in a linked list.
 * The list is ordered by priority.
 *
 * @param   entry       Address of the first list entry pointer
 * @param   priority    Priority of the DNS server to find / create
 * @param   gc          The gc new list items should be allocated in
 */
struct dns_server *dns_server_get(struct dns_server **entry, long priority, struct gc_arena *gc);

/**
 * Appends DNS domain parameters to a linked list.
 *
 * @param   entry       Address of the first list entry pointer
 * @param   domains     Address of the first domain parameter
 * @param   gc          The gc the new list items should be allocated in
 */
void dns_domain_list_append(struct dns_domain **entry, char **domains, struct gc_arena *gc);

/**
 * Parses a string IPv4 or IPv6 address and optional colon separated port,
 * into a in_addr or in6_addr respectively plus a in_port_t port.
 *
 * @param   server      Pointer to DNS server the address is parsed for
 * @param   addr        Address as string
 * @return              True if parsing was successful
 */
bool dns_server_addr_parse(struct dns_server *server, const char *addr);

/**
 * Checks validity of DNS options
 *
 * @param   msglevel    The message level to log errors with
 * @param   o           Pointer to the DNS options to validate
 * @return              True if no error was found
 */
bool dns_options_verify(int msglevel, const struct dns_options *o);

/**
 * Makes a deep copy of the passed DNS options.
 *
 * @param   o           Pointer to the DNS options to clone
 * @param   gc          Pointer to the gc_arena to use for the clone
 * @return              The dns_options clone
 */
struct dns_options clone_dns_options(const struct dns_options o, struct gc_arena *gc);

/**
 * Saves and resets the server options, so that pulled ones don't mix in.
 *
 * @param   o           Pointer to the DNS options to modify
 */
void dns_options_preprocess_pull(struct dns_options *o);

/**
 * Merges pulled DNS servers with static ones into an ordered list.
 *
 * @param   o           Pointer to the DNS options to modify
 */
void dns_options_postprocess_pull(struct dns_options *o);

/**
 * Puts the DNS options into an environment set.
 *
 * @param   o           Pointer to the DNS options to set
 * @param   es          Pointer to the env_set to set the options into
 */
void setenv_dns_options(const struct dns_options *o, struct env_set *es);

/**
 * Prints configured DNS options.
 *
 * @param   o           Pointer to the DNS options to print
 */
void show_dns_options(const struct dns_options *o);

#endif /* ifndef DNS_H */
