/*
 *  OpenVPN -- An application to securely tunnel IP networks
 *             over a single TCP/UDP port, with support for SSL/TLS-based
 *             session authentication and key exchange,
 *             packet encryption, packet authentication, and
 *             packet compression.
 *
 *  Copyright (C) 2002-2025 OpenVPN Inc <sales@openvpn.net>
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
 *  with this program; if not, see <https://www.gnu.org/licenses/>.
 */

#ifndef MSS_H
#define MSS_H

#include "proto.h"
#include "error.h"
#include "mtu.h"
#include "ssl_common.h"

void mss_fixup_ipv4(struct buffer *buf, uint16_t maxmss);

void mss_fixup_ipv6(struct buffer *buf, uint16_t maxmss);

void mss_fixup_dowork(struct buffer *buf, uint16_t maxmss);

/** Set the --mssfix option. */
void frame_calculate_dynamic(struct frame *frame, struct key_type *kt,
                             const struct options *options,
                             struct link_socket_info *lsi);

/**
 * Checks and adjusts the fragment and mssfix value according to the
 * discovered path mtu value
 * @param c     context to adjust
 */
void frame_adjust_path_mtu(struct context *c);

#endif /* ifndef MSS_H */
