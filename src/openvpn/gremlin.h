/*
 *  OpenVPN -- An application to securely tunnel IP networks
 *             over a single UDP port, with support for SSL/TLS-based
 *             session authentication and key exchange,
 *             packet encryption, packet authentication, and
 *             packet compression.
 *
 *  Copyright (C) 2002-2023 OpenVPN Inc <sales@openvpn.net>
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

#ifndef GREMLIN_H
#define GREMLIN_H

#ifdef ENABLE_DEBUG

/*
 * Gremlin options, presented as bitmask argument to --gremlin directive
 */

#define GREMLIN_CONNECTION_FLOOD_SHIFT   (0)
#define GREMLIN_CONNECTION_FLOOD_MASK    (0x07)

#define GREMLIN_PACKET_FLOOD_SHIFT       (3)
#define GREMLIN_PACKET_FLOOD_MASK        (0x03)

#define GREMLIN_CORRUPT_SHIFT            (5)
#define GREMLIN_CORRUPT_MASK             (0x03)

#define GREMLIN_UP_DOWN_SHIFT            (7)
#define GREMLIN_UP_DOWN_MASK             (0x03)

/* 512:1/500 1024:1/100 1536:1/50 */

#define GREMLIN_DROP_SHIFT               (9)
#define GREMLIN_DROP_MASK                (0x03)

/* extract gremlin parms */

#define GREMLIN_CONNECTION_FLOOD_LEVEL(x) (((x)>>GREMLIN_CONNECTION_FLOOD_SHIFT) & GREMLIN_CONNECTION_FLOOD_MASK)
#define GREMLIN_PACKET_FLOOD_LEVEL(x)     (((x)>>GREMLIN_PACKET_FLOOD_SHIFT)     & GREMLIN_PACKET_FLOOD_MASK)
#define GREMLIN_CORRUPT_LEVEL(x)          (((x)>>GREMLIN_CORRUPT_SHIFT)          & GREMLIN_CORRUPT_MASK)
#define GREMLIN_UP_DOWN_LEVEL(x)          (((x)>>GREMLIN_UP_DOWN_SHIFT)          & GREMLIN_UP_DOWN_MASK)
#define GREMLIN_DROP_LEVEL(x)             (((x)>>GREMLIN_DROP_SHIFT)             & GREMLIN_DROP_MASK)

#include "buffer.h"

struct packet_flood_parms
{
    int n_packets;
    int packet_size;
};

bool ask_gremlin(int flags);

void corrupt_gremlin(struct buffer *buf, int flags);

struct packet_flood_parms get_packet_flood_parms(int level);

#endif /* ifdef ENABLE_DEBUG */
#endif /* ifndef GREMLIN_H */
