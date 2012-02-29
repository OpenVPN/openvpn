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

#ifndef PING_H
#define PING_H

#include "init.h"
#include "forward.h"

/*
 * Initial default --ping-restart before --pull
 */
#define PRE_PULL_INITIAL_PING_RESTART 120  /* in seconds */

extern const uint8_t ping_string[];

/* PING_STRING_SIZE must be sizeof (ping_string) */
#define PING_STRING_SIZE 16

static inline bool
is_ping_msg (const struct buffer* buf)
{
  return buf_string_match (buf, ping_string, PING_STRING_SIZE);
}

#endif
