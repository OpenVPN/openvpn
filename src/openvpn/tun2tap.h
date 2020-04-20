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
Author: pengtianabc@hotmail.com
*/

#ifndef TUN2TAP_H
#define TUN2TAP_H

#include "init.h"
#define TUN2TAP_FLAG_ENCAP 1
#define TUN2TAP_FLAG_DECAP (1<<1)

/*
 * Should we convert tun2tap for the remote?
 */
static inline bool
check_tun2tap_send(struct context *c, int flag)
{
    bool check_tun2tap_arp_dowork(struct context *c, int flag);
    return check_tun2tap_arp_dowork(c, flag);
}

#endif /* ifndef TUN2TAP_H */
