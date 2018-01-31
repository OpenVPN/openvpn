/*
 *  OpenVPN -- An application to securely tunnel IP networks
 *             over a single TCP/UDP port, with support for SSL/TLS-based
 *             session authentication and key exchange,
 *             packet encryption, packet authentication, and
 *             packet compression.
 *
 *  Copyright (C) 2010-2018 Fox Crypto B.V. <openvpn@fox-it.com>
 *
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

/**
 * @file
 * VPN tunnel state documentation file.
 */

/**
 * @page tunnel_state Structure of the VPN tunnel state storage
 *
 * This section describes how OpenVPN stores its VPN tunnel state during
 * operation.
 *
 * OpenVPN uses several data structures as storage containers for state
 * information of active VPN tunnels.  These are described in this
 * section, together with a little bit of history to help understand the
 * origin of the current architecture.
 *
 * Whether an OpenVPN process is running in client-mode or server-mode
 * determines whether it can support only one or multiple simultaneously
 * active VPN tunnels.  This consequently also determines how the
 * associated state information is wrapped up internally.  This section
 * gives an overview of the differences.
 *
 * @section tunnel_state_history Historic developments
 *
 * In the old v1.x series, an OpenVPN process managed only one single VPN
 * tunnel.  This allowed the VPN tunnel state to be stored together with
 * process-global information in one single \c context structure.
 *
 * This changed, however, in the v2.x series, as new OpenVPN versions
 * running in server-mode can support multiple simultaneously active VPN
 * tunnels.  This necessitated a redesign of the VPN tunnel state
 * container structures, and modification of the \link
 * external_multiplexer External Multiplexer\endlink and \link
 * internal_multiplexer Internal Multiplexer\endlink systems.  The
 * majority of these changes are only relevant for OpenVPN processes
 * running in server-mode, and the client-mode structure has remained very
 * similar to the v1.x single-tunnel form.
 *
 * @section tunnel_state_client Client-mode state
 *
 * An OpenVPN process running in client-mode can manage at most one single
 * VPN tunnel at any one time.  The state information for a client's VPN
 * tunnel is stored in a \c context structure.
 *
 * The \c context structure is created in the \c main() function.  That is
 * also where process-wide initialization takes place, such as parsing
 * command line %options and reading configuration files.  The \c context
 * is then passed to \c tunnel_point_to_point() which drives OpenVPN's
 * main event processing loop.  These functions are both part of the \link
 * eventloop Main Event Loop\endlink module.
 *
 * @subsection tunnel_state_client_init Initialization and cleanup
 *
 * Because there is only one \c context structure present, it can be
 * initialized and cleaned up from the client's main event processing
 * function.  Before the \c tunnel_point_to_point() function enters its
 * event loop, it calls \c init_instance_handle_signals() which calls \c
 * init_instance() to initialize the single \c context structure.  After
 * the event loop stops, it calls \c close_instance() to clean up the \c
 * context.
 *
 * @subsection tunnel_state_client_event Event processing
 *
 * When the main event processing loop activates the external or internal
 * multiplexer to handle a network event, it is not necessary to determine
 * which VPN tunnel the event is associated with, because there is only
 * one VPN tunnel active.
 *
 * @section tunnel_state_server Server-mode state
 *
 * An OpenVPN process running in server-mode can manage multiple
 * simultaneously active VPN tunnels.  For every VPN tunnel active, in
 * other words for every OpenVPN client which is connected to a server,
 * the OpenVPN server has one \c context structure in which it stores that
 * particular VPN tunnel's state information.
 *
 * @subsection tunnel_state_server_multi Multi_context and multi_instance structures
 *
 * To support multiple \c context structures, each is wrapped in a \c
 * multi_instance structure, and all the \c multi_instance structures are
 * registered in one single \c multi_context structure.  The \link
 * external_multiplexer External Multiplexer\endlink and \link
 * internal_multiplexer Internal Multiplexer\endlink then use the \c
 * multi_context to retrieve the correct \c multi_instance and \c context
 * associated with a given network address.
 *
 * @subsection tunnel_state_server_init Startup and initialization
 *
 * An OpenVPN process running in server-mode starts in the same \c main()
 * function as it would in client-mode.  The same process-wide
 * initialization is performed, and the resulting state and configuration
 * is stored in a \c context structure. The server-mode and client-mode
 * processes diverge when the \c main() function calls one of \c
 * tunnel_point_to_point() or \c tunnel_server().
 *
 * In server-mode, \c main() calls the \c tunnel_server() function, which
 * transfers control to \c tunnel_server_udp_single_threaded() or \c
 * tunnel_server_tcp() depending on the external transport protocol.
 *
 * These functions receive the \c context created in \c main().  This
 * object has a special status in server-mode, as it does not represent an
 * active VPN tunnel, but does contain process-wide configuration
 * parameters.  In the source code, it is often stored in "top" variables.
 * To distinguish this object from other instances of the same type, its
 * \c context.mode value is set to \c CM_TOP.  Other \c context objects,
 * which do represent active VPN tunnels, have a \c context.mode set to \c
 * CM_CHILD_UDP or \c CM_CHILD_TCP, depending on the external transport
 * protocol.
 *
 * Both \c tunnel_server_udp_single_threaded() and \c tunnel_server_tcp()
 * perform similar initialization.  In either case, a \c multi_context
 * structure is created, and it is initialized according to the
 * configuration stored in the top \c context by the \c multi_init() and
 * \c multi_top_init() functions.
 *
 * @subsection tunnel_state_server_tunnels Creating and destroying VPN tunnels
 *
 * When an OpenVPN client makes a new connection to a server, the server
 * creates a new \c context and \c multi_instance.  The latter is
 * registered in the \c multi_context, which makes it possible for the
 * external and internal multiplexers to retrieve the correct \c
 * multi_instance and \c context when a network event occurs.
 *
 * @subsection tunnel_state_server_cleanup Final cleanup
 *
 * After the main event loop exits, both \c
 * tunnel_server_udp_single_threaded() and \c tunnel_server_tcp() perform
 * similar cleanup.  They call \c multi_uninit() followed by \c
 * multi_top_free() to clean up the \c multi_context structure.
 */
