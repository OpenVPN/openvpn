/*
 *  OpenVPN -- An application to securely tunnel IP networks
 *             over a single UDP port, with support for SSL/TLS-based
 *             session authentication and key exchange,
 *             packet encryption, packet authentication, and
 *             packet compression.
 *
 *  Copyright (C) 2022-2024 OpenVPN Inc <sales@openvpn.net>
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

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "syshead.h"

#include "dns.h"
#include "socket.h"

/**
 * Parses a string as port and stores it
 *
 * @param   port        Pointer to in_port_t where the port value is stored
 * @param   addr        Port number as string
 * @return              True if parsing was successful
 */
static bool
dns_server_port_parse(in_port_t *port, char *port_str)
{
    char *endptr;
    errno = 0;
    unsigned long tmp = strtoul(port_str, &endptr, 10);
    if (errno || *endptr != '\0' || tmp == 0 || tmp > UINT16_MAX)
    {
        return false;
    }
    *port = (in_port_t)tmp;
    return true;
}

bool
dns_server_addr_parse(struct dns_server *server, const char *addr)
{
    if (!addr)
    {
        return false;
    }

    char addrcopy[INET6_ADDRSTRLEN] = {0};
    size_t copylen = 0;
    in_port_t port = 0;
    sa_family_t af;

    char *first_colon = strchr(addr, ':');
    char *last_colon = strrchr(addr, ':');

    if (!first_colon || first_colon == last_colon)
    {
        /* IPv4 address with optional port, e.g. 1.2.3.4 or 1.2.3.4:853 */
        if (last_colon)
        {
            if (last_colon == addr || !dns_server_port_parse(&port, last_colon + 1))
            {
                return false;
            }
            copylen = first_colon - addr;
        }
        af = AF_INET;
    }
    else
    {
        /* IPv6 address with optional port, e.g. ab::cd or [ab::cd]:853 */
        if (addr[0] == '[')
        {
            addr += 1;
            char *bracket = last_colon - 1;
            if (*bracket != ']' || bracket == addr || !dns_server_port_parse(&port, last_colon + 1))
            {
                return false;
            }
            copylen = bracket - addr;
        }
        af = AF_INET6;
    }

    /* Copy the address part into a temporary buffer and use that */
    if (copylen)
    {
        if (copylen >= sizeof(addrcopy))
        {
            return false;
        }
        strncpy(addrcopy, addr, copylen);
        addr = addrcopy;
    }

    struct addrinfo *ai = NULL;
    if (openvpn_getaddrinfo(0, addr, NULL, 0, NULL, af, &ai) != 0)
    {
        return false;
    }

    if (server->addr_count >= SIZE(server->addr))
    {
        return false;
    }

    if (ai->ai_family == AF_INET)
    {
        struct sockaddr_in *sin = (struct sockaddr_in *)ai->ai_addr;
        server->addr[server->addr_count].in.a4.s_addr = ntohl(sin->sin_addr.s_addr);
    }
    else
    {
        struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)ai->ai_addr;
        server->addr[server->addr_count].in.a6 = sin6->sin6_addr;
    }

    server->addr[server->addr_count].family = af;
    server->addr[server->addr_count].port = port;
    server->addr_count += 1;

    freeaddrinfo(ai);
    return true;
}

void
dns_domain_list_append(struct dns_domain **entry, char **domains, struct gc_arena *gc)
{
    /* Fast forward to the end of the list */
    while (*entry)
    {
        entry = &((*entry)->next);
    }

    /* Append all domains to the end of the list */
    while (*domains)
    {
        ALLOC_OBJ_CLEAR_GC(*entry, struct dns_domain, gc);
        struct dns_domain *new = *entry;
        new->name = *domains++;
        entry = &new->next;
    }
}

bool
dns_server_priority_parse(long *priority, const char *str, bool pulled)
{
    char *endptr;
    const long min = pulled ? 0 : INT8_MIN;
    const long max = INT8_MAX;
    long prio = strtol(str, &endptr, 10);
    if (*endptr != '\0' || prio < min || prio > max)
    {
        return false;
    }
    *priority = prio;
    return true;
}

struct dns_server *
dns_server_get(struct dns_server **entry, long priority, struct gc_arena *gc)
{
    struct dns_server *obj = *entry;
    while (true)
    {
        if (!obj || obj->priority > priority)
        {
            ALLOC_OBJ_CLEAR_GC(*entry, struct dns_server, gc);
            (*entry)->next = obj;
            (*entry)->priority = priority;
            return *entry;
        }
        else if (obj->priority == priority)
        {
            return obj;
        }
        entry = &obj->next;
        obj = *entry;
    }
}

bool
dns_options_verify(int msglevel, const struct dns_options *o)
{
    const struct dns_server *server =
        o->servers ? o->servers : o->servers_prepull;
    while (server)
    {
        if (server->addr_count == 0)
        {
            msg(msglevel, "ERROR: dns server %ld does not have an address assigned", server->priority);
            return false;
        }
        server = server->next;
    }
    return true;
}

static struct dns_domain *
clone_dns_domains(const struct dns_domain *domain, struct gc_arena *gc)
{
    struct dns_domain *new_list = NULL;
    struct dns_domain **new_entry = &new_list;

    while (domain)
    {
        ALLOC_OBJ_CLEAR_GC(*new_entry, struct dns_domain, gc);
        struct dns_domain *new_domain = *new_entry;
        *new_domain = *domain;
        new_entry = &new_domain->next;
        domain = domain->next;
    }

    return new_list;
}

static struct dns_server *
clone_dns_servers(const struct dns_server *server, struct gc_arena *gc)
{
    struct dns_server *new_list = NULL;
    struct dns_server **new_entry = &new_list;

    while (server)
    {
        ALLOC_OBJ_CLEAR_GC(*new_entry, struct dns_server, gc);
        struct dns_server *new_server = *new_entry;
        *new_server = *server;
        new_server->domains = clone_dns_domains(server->domains, gc);
        new_entry = &new_server->next;
        server = server->next;
    }

    return new_list;
}

struct dns_options
clone_dns_options(const struct dns_options o, struct gc_arena *gc)
{
    struct dns_options clone;
    memset(&clone, 0, sizeof(clone));
    clone.search_domains = clone_dns_domains(o.search_domains, gc);
    clone.servers = clone_dns_servers(o.servers, gc);
    clone.servers_prepull = clone_dns_servers(o.servers_prepull, gc);
    return clone;
}

void
dns_options_preprocess_pull(struct dns_options *o)
{
    o->servers_prepull = o->servers;
    o->servers = NULL;
}

void
dns_options_postprocess_pull(struct dns_options *o)
{
    struct dns_server **entry = &o->servers;
    struct dns_server *server = *entry;
    struct dns_server *server_pp = o->servers_prepull;

    while (server && server_pp)
    {
        if (server->priority > server_pp->priority)
        {
            /* Merge static server in front of pulled one */
            struct dns_server *next_pp = server_pp->next;
            server_pp->next = server;
            *entry = server_pp;
            server = *entry;
            server_pp = next_pp;
        }
        else if (server->priority == server_pp->priority)
        {
            /* Pulled server overrides static one */
            server_pp = server_pp->next;
        }
        entry = &server->next;
        server = *entry;
    }

    /* Append remaining local servers */
    if (server_pp)
    {
        *entry = server_pp;
    }

    o->servers_prepull = NULL;
}

static const char *
dnssec_value(const enum dns_security dnssec)
{
    switch (dnssec)
    {
        case DNS_SECURITY_YES:
            return "yes";

        case DNS_SECURITY_OPTIONAL:
            return "optional";

        case DNS_SECURITY_NO:
            return "no";

        default:
            return "unset";
    }
}

static const char *
transport_value(const enum dns_server_transport transport)
{
    switch (transport)
    {
        case DNS_TRANSPORT_HTTPS:
            return "DoH";

        case DNS_TRANSPORT_TLS:
            return "DoT";

        case DNS_TRANSPORT_PLAIN:
            return "plain";

        default:
            return "unset";
    }
}

static void
setenv_dns_option(struct env_set *es,
                  const char *format, int i, int j,
                  const char *value)
{
    char name[64];
    bool name_ok = false;

    if (j < 0)
    {
        name_ok = openvpn_snprintf(name, sizeof(name), format, i);
    }
    else
    {
        name_ok = openvpn_snprintf(name, sizeof(name), format, i, j);
    }

    if (!name_ok)
    {
        msg(M_WARN, "WARNING: dns option setenv name buffer overflow");
    }

    setenv_str(es, name, value);
}

void
setenv_dns_options(const struct dns_options *o, struct env_set *es)
{
    struct gc_arena gc = gc_new();
    const struct dns_server *s;
    const struct dns_domain *d;
    int i, j;

    for (i = 1, d = o->search_domains; d != NULL; i++, d = d->next)
    {
        setenv_dns_option(es, "dns_search_domain_%d", i, -1, d->name);
    }

    for (i = 1, s = o->servers; s != NULL; i++, s = s->next)
    {
        for (j = 0; j < s->addr_count; ++j)
        {
            if (s->addr[j].family == AF_INET)
            {
                setenv_dns_option(es, "dns_server_%d_address_%d", i, j + 1,
                                  print_in_addr_t(s->addr[j].in.a4.s_addr, 0, &gc));
            }
            else
            {
                setenv_dns_option(es, "dns_server_%d_address_%d", i, j + 1,
                                  print_in6_addr(s->addr[j].in.a6, 0, &gc));
            }
            if (s->addr[j].port)
            {
                setenv_dns_option(es, "dns_server_%d_port_%d", i, j + 1,
                                  print_in_port_t(s->addr[j].port, &gc));
            }
        }

        if (s->domains)
        {
            for (j = 1, d = s->domains; d != NULL; j++, d = d->next)
            {
                setenv_dns_option(es, "dns_server_%d_resolve_domain_%d", i, j, d->name);
            }
        }

        if (s->dnssec)
        {
            setenv_dns_option(es, "dns_server_%d_dnssec", i, -1,
                              dnssec_value(s->dnssec));
        }

        if (s->transport)
        {
            setenv_dns_option(es, "dns_server_%d_transport", i, -1,
                              transport_value(s->transport));
        }
        if (s->sni)
        {
            setenv_dns_option(es, "dns_server_%d_sni", i, -1, s->sni);
        }
    }

    gc_free(&gc);
}

void
show_dns_options(const struct dns_options *o)
{
    struct gc_arena gc = gc_new();

    int i = 1;
    struct dns_server *server = o->servers_prepull ? o->servers_prepull : o->servers;
    while (server)
    {
        msg(D_SHOW_PARMS, "  DNS server #%d:", i++);

        for (int j = 0; j < server->addr_count; ++j)
        {
            const char *addr;
            const char *fmt_port;
            if (server->addr[j].family == AF_INET)
            {
                addr = print_in_addr_t(server->addr[j].in.a4.s_addr, 0, &gc);
                fmt_port = "    address = %s:%s";
            }
            else
            {
                addr = print_in6_addr(server->addr[j].in.a6, 0, &gc);
                fmt_port = "    address = [%s]:%s";
            }

            if (server->addr[j].port)
            {
                const char *port = print_in_port_t(server->addr[j].port, &gc);
                msg(D_SHOW_PARMS, fmt_port, addr, port);
            }
            else
            {
                msg(D_SHOW_PARMS, "    address = %s", addr);
            }
        }

        if (server->dnssec)
        {
            msg(D_SHOW_PARMS, "    dnssec = %s", dnssec_value(server->dnssec));
        }

        if (server->transport)
        {
            msg(D_SHOW_PARMS, "    transport = %s", transport_value(server->transport));
        }
        if (server->sni)
        {
            msg(D_SHOW_PARMS, "    sni = %s", server->sni);
        }

        struct dns_domain *domain = server->domains;
        if (domain)
        {
            msg(D_SHOW_PARMS, "    resolve domains:");
            while (domain)
            {
                msg(D_SHOW_PARMS, "      %s", domain->name);
                domain = domain->next;
            }
        }

        server = server->next;
    }

    struct dns_domain *search_domain = o->search_domains;
    if (search_domain)
    {
        msg(D_SHOW_PARMS, "  DNS search domains:");
        while (search_domain)
        {
            msg(D_SHOW_PARMS, "    %s", search_domain->name);
            search_domain = search_domain->next;
        }
    }

    gc_free(&gc);
}
