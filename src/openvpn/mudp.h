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

/*
 * UDP specific code for --mode server
 */

#ifndef MUDP_H
#define MUDP_H

struct context;
struct multi_context;


/**
 * Main event loop for OpenVPN in UDP server mode.
 * @ingroup eventloop
 *
 * This function implements OpenVPN's main event loop for UDP server mode.
 *
 * @param top - Top-level context structure.
 */
void tunnel_server_udp(struct context *top);


/**************************************************************************/
/**
 * Get, and if necessary create, the multi_instance associated with a
 * packet's source address.
 * @ingroup external_multiplexer
 *
 * This function extracts the source address of a recently read packet
 * from \c m->top.c2.from and uses that source address as a hash key for
 * the hash table \c m->hash.  If an entry exists, this function returns
 * it.  If no entry exists, this function handles its creation, and if
 * successful, returns the newly created instance.
 *
 * @param m            - The single multi_context structure.
 *
 * @return A pointer to a multi_instance if one already existed for the
 *     packet's source address or if one was a newly created successfully.
 *      NULL if one did not yet exist and a new one was not created.
 */
struct multi_instance *multi_get_create_instance_udp(struct multi_context *m, bool *floated);

#endif /* ifndef MUDP_H */
