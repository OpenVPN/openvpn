/*
 *  OpenVPN -- An application to securely tunnel IP networks
 *             over a single TCP/UDP port, with support for SSL/TLS-based
 *             session authentication and key exchange,
 *             packet encryption, packet authentication, and
 *             packet compression.
 *
 *  Copyright (C) 2002-2010 OpenVPN Technologies, Inc. <sales@openvpn.net>
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
 *  You should have received a copy of the GNU General Public License
 *  along with this program (see the file COPYING included with this
 *  distribution); if not, write to the Free Software Foundation, Inc.,
 *  59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

/*
 * UDP specific code for --mode server
 */

#ifndef MUDP_H
#define MUDP_H

#if P2MP_SERVER

struct context;
struct multi_context;


/**************************************************************************/
/**
 * Main event loop wrapper function for OpenVPN in UDP server mode.
 * @ingroup eventloop
 *
 * This function simply calls \c tunnel_server_udp_single_threaded().
 *
 * @param top          - Top-level context structure.
 */
void tunnel_server_udp (struct context *top);


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
struct multi_instance *multi_get_create_instance_udp (struct multi_context *m);


/**************************************************************************/
/**
 * Find a client instance based on the HMAC, if auth is used.
 * @ingroup external_multiplexer
 *
 * Find a client instance based on the HMAC, if auth is used. The function 
 * iterates over all peers to find a fitting instance. The found instance is
 * updated with the current peer address.
 *  
 * @param m            - The single multi_context structure.
 * @param mi           - The multi_instance structure.
 * @param real         - The mroute_addr structure.
 *
 * @return Boolen, true if peer found, false if not.
 */
bool multi_find_instance_udp (struct multi_context *m,  struct multi_instance *mi, struct mroute_addr real);

#endif
#endif
