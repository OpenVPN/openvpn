/*
 *  OpenVPN -- An application to securely tunnel IP networks
 *             over a single TCP/UDP port, with support for SSL/TLS-based
 *             session authentication and key exchange,
 *             packet encryption, packet authentication, and
 *             packet compression.
 *
 *  Copyright (C) 2002-2024 OpenVPN Technologies, Inc. <sales@openvpn.net>
 *  Copyright (C) 2010      Fabian Knittel <fabian.knittel@lettink.de>
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

#ifndef VLAN_H
#define VLAN_H

#include "buffer.h"
#include "mroute.h"
#include "openvpn.h"

struct multi_context;
struct multi_instance;

int16_t
vlan_decapsulate(const struct context *c, struct buffer *buf);

bool
vlan_is_tagged(const struct buffer *buf);

void
vlan_process_outgoing_tun(struct multi_context *m, struct multi_instance *mi);

#endif /* VLAN_H */
