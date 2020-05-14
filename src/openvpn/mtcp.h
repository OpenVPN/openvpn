/*
 *  OpenVPN -- An application to securely tunnel IP networks
 *             over a single TCP/UDP port, with support for SSL/TLS-based
 *             session authentication and key exchange,
 *             packet encryption, packet authentication, and
 *             packet compression.
 *
 *  Copyright (C) 2002-2018 OpenVPN Inc <sales@openvpn.net>
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

/*
 * TCP specific code for --mode server
 */

#ifndef MTCP_H
#define MTCP_H

#include "event.h"

/*
 * Extra state info needed for TCP mode
 */
struct multi_tcp
{
    struct event_set *es;
    struct event_set_return *esr;
    int n_esr;
    int maxevents;
    unsigned int tun_rwflags;
#ifdef ENABLE_MANAGEMENT
    unsigned int management_persist_flags;
#endif
};

struct multi_instance;
struct context;

struct multi_tcp *multi_tcp_init(int maxevents, int *maxclients);

void multi_tcp_free(struct multi_tcp *mtcp);

void multi_tcp_dereference_instance(struct multi_tcp *mtcp, struct multi_instance *mi);

bool multi_tcp_instance_specific_init(struct multi_context *m, struct multi_instance *mi);

void multi_tcp_instance_specific_free(struct multi_instance *mi);

void multi_tcp_link_out_deferred(struct multi_context *m, struct multi_instance *mi);


/**************************************************************************/
/**
 * Main event loop for OpenVPN in TCP server mode.
 * @ingroup eventloop
 *
 * @param top - Top-level context structure.
 */
void tunnel_server_tcp(struct context *top);


void multi_tcp_delete_event(struct multi_tcp *mtcp, event_t event);

#endif /* ifndef MTCP_H */
