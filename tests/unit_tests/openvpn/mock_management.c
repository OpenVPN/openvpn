/*
 *  OpenVPN -- An application to securely tunnel IP networks
 *             over a single UDP port, with support for SSL/TLS-based
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

/* Minimal set of mocked management function/globals to get unit tests to
 * compile */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "syshead.h"

#include "manage.h"

#ifdef ENABLE_MANAGEMENT

struct management *management; /* GLOBAL */

void
management_auth_failure(struct management *man, const char *type, const char *reason)
{
    ASSERT(false);
}

char *
management_query_pk_sig(struct management *man, const char *b64_data, const char *algorithm)
{
    return NULL;
}

void
management_set_state(struct management *man, const int state, const char *detail,
                     const in_addr_t *tun_local_ip, const struct in6_addr *tun_local_ip6,
                     const struct openvpn_sockaddr *local_addr,
                     const struct openvpn_sockaddr *remote_addr)
{
}

#endif

void
management_sleep(const int n)
{
}
