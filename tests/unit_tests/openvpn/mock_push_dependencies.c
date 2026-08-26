/*
 *  OpenVPN -- An application to securely tunnel IP networks
 *             over a single UDP port, with support for SSL/TLS-based
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

/* Set of mocked function/globals to get unit tests to
 * compile that use the push_util.c file */


#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "error.h"
#include "options.h"

void
throw_signal_soft(const int signum, const char *signal_text)
{
    msg(M_WARN, "Offending option received from server");
}

uint64_t
pull_permission_mask(const struct context *c)
{
    uint64_t flags = OPT_P_UP | OPT_P_ROUTE_EXTRAS | OPT_P_SOCKBUF | OPT_P_SOCKFLAGS
                     | OPT_P_SETENV | OPT_P_SHAPER | OPT_P_TIMER | OPT_P_COMP | OPT_P_PERSIST
                     | OPT_P_MESSAGES | OPT_P_EXPLICIT_NOTIFY | OPT_P_ECHO | OPT_P_PULL_MODE
                     | OPT_P_PEER_ID | OPT_P_NCP | OPT_P_PUSH_MTU | OPT_P_ROUTE | OPT_P_DHCPDNS;
    return flags;
}

void
unlearn_ifconfig(struct multi_context *m, struct multi_instance *mi)
{
}

void
unlearn_ifconfig_ipv6(struct multi_context *m, struct multi_instance *mi)
{
}

void
update_vhash(struct multi_context *m, struct multi_instance *mi, const char *new_ip, const char *new_ipv6)
{
}

bool
options_postprocess_pull(struct options *options, struct env_set *es)
{
    return true;
}
