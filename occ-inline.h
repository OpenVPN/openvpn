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

#ifndef OCC_INLINE_H
#define OCC_INLINE_H

#ifdef ENABLE_OCC

/*
 * Inline functions
 */

static inline int
occ_reset_op ()
{
  return -1;
}

/*
 * Should we send an OCC_REQUEST message?
 */
static inline void
check_send_occ_req (struct context *c)
{
  void check_send_occ_req_dowork (struct context *c);
  if (event_timeout_defined (&c->c2.occ_interval)
      && event_timeout_trigger (&c->c2.occ_interval,
				&c->c2.timeval,
				(!TO_LINK_DEF(c) && c->c2.occ_op < 0) ? ETT_DEFAULT : 0))
    check_send_occ_req_dowork (c);
}

/*
 * Should we send an MTU load test?
 */
static inline void
check_send_occ_load_test (struct context *c)
{
  void check_send_occ_load_test_dowork (struct context *c);
  if (event_timeout_defined (&c->c2.occ_mtu_load_test_interval)
      && event_timeout_trigger (&c->c2.occ_mtu_load_test_interval,
				&c->c2.timeval,
				(!TO_LINK_DEF(c) && c->c2.occ_op < 0) ? ETT_DEFAULT : 0))
    check_send_occ_load_test_dowork (c);
}

/*
 * Should we send an OCC message?
 */
static inline void
check_send_occ_msg (struct context *c)
{
  void check_send_occ_msg_dowork (struct context *c);
  if (c->c2.occ_op >= 0)
    {
      if (!TO_LINK_DEF(c))
	check_send_occ_msg_dowork (c);
      else
	tv_clear (&c->c2.timeval);  /* ZERO-TIMEOUT */
    }
}

#endif
#endif
