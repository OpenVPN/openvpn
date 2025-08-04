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

#ifndef PS_H
#define PS_H

#if PORT_SHARE

#include "basic.h"
#include "buffer.h"
#include "ssl.h"

struct port_share {
    /* Foreground's socket to background process */
    socket_descriptor_t foreground_fd;

    /* Process ID of background process */
    pid_t background_pid;
};

extern struct port_share *port_share;

struct port_share *port_share_open(const char *host,
                                   const char *port,
                                   const int max_initial_buf,
                                   const char *journal_dir);

void port_share_close(struct port_share *ps);

void port_share_abort(struct port_share *ps);

bool is_openvpn_protocol(const struct buffer *buf);

void port_share_redirect(struct port_share *ps, const struct buffer *head, socket_descriptor_t sd);

#endif /* if PORT_SHARE */
#endif /* ifndef PS_H */
