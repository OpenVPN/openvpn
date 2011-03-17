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

#ifndef PING_INLINE_H
#define PING_INLINE_H

/*
 * Should we exit or restart due to ping (or other authenticated packet)
 * not received in n seconds?
 */
static inline void
check_ping_restart (struct context *c)
{
  void check_ping_restart_dowork (struct context *c);
  if (c->options.ping_rec_timeout
      && event_timeout_trigger (&c->c2.ping_rec_interval,
				&c->c2.timeval,
				(!c->options.ping_timer_remote
				 || link_socket_actual_defined (&c->c1.link_socket_addr.actual))
				? ETT_DEFAULT : 15))
    check_ping_restart_dowork (c);
}

/*
 * Should we ping the remote?
 */
static inline void
check_ping_send (struct context *c)
{
  void check_ping_send_dowork (struct context *c);
  if (c->options.ping_send_timeout
      && event_timeout_trigger (&c->c2.ping_send_interval,
				&c->c2.timeval,
				!TO_LINK_DEF(c) ? ETT_DEFAULT : 1))
    check_ping_send_dowork (c);
}

#endif
