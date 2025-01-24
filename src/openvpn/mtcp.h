/*
 *  OpenVPN -- An application to securely tunnel IP networks
 *             over a single TCP/UDP port, with support for SSL/TLS-based
 *             session authentication and key exchange,
 *             packet encryption, packet authentication, and
 *             packet compression.
 *
 *  Copyright (C) 2002-2024 OpenVPN Inc <sales@openvpn.net>
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

struct multi_context;
struct multi_instance;
struct context;

void multi_tcp_dereference_instance(struct multi_io *multi_io, struct multi_instance *mi);

bool multi_tcp_instance_specific_init(struct multi_context *m, struct multi_instance *mi);

void multi_tcp_instance_specific_free(struct multi_instance *mi);

void multi_tcp_set_global_rw_flags(struct multi_context *m, struct multi_instance *mi);

bool multi_tcp_process_outgoing_link(struct multi_context *m, bool defer, const unsigned int mpp_flags);

bool multi_tcp_process_outgoing_link_ready(struct multi_context *m, struct multi_instance *mi, const unsigned int mpp_flags);

struct multi_instance *multi_create_instance_tcp(struct multi_context *m, struct link_socket *ls);

void multi_tcp_link_out_deferred(struct multi_context *m, struct multi_instance *mi);


/**************************************************************************/
/**
 * Main event loop for OpenVPN in TCP server mode.
 * @ingroup eventloop
 *
 * @param top - Top-level context structure.
 */
void tunnel_server_tcp(struct context *top);


void multi_tcp_delete_event(struct multi_io *multi_io, event_t event);

#endif /* ifndef MTCP_H */
