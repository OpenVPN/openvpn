/*
 *  OpenVPN -- An application to securely tunnel IP networks
 *             over a single TCP/UDP port, with support for SSL/TLS-based
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

/*
 * Multi-protocol specific code for --mode server
 */

#ifndef MULTI_IO_H
#define MULTI_IO_H

#include "event.h"

/*
 * I/O processing States
 */

#define TA_UNDEF                 0
#define TA_SOCKET_READ           1
#define TA_SOCKET_READ_RESIDUAL  2
#define TA_SOCKET_WRITE          3
#define TA_SOCKET_WRITE_READY    4
#define TA_SOCKET_WRITE_DEFERRED 5
#define TA_TUN_READ              6
#define TA_TUN_WRITE             7
#define TA_INITIAL               8
#define TA_TIMEOUT               9
#define TA_TUN_WRITE_TIMEOUT     10

/*
 * I/O state and events tracker
 */
struct multi_io
{
    struct event_set *es;
    struct event_set_return *esr;
    int n_esr;
    int maxevents;
    unsigned int tun_rwflags;
    unsigned int udp_flags;
#ifdef ENABLE_MANAGEMENT
    unsigned int management_persist_flags;
#endif
};

struct multi_io *multi_io_init(int maxevents, int *maxclients);

void multi_io_free(struct multi_io *multi_io);

int multi_io_wait(struct multi_context *m);

void multi_io_process_io(struct multi_context *m);

void multi_io_action(struct multi_context *m, struct multi_instance *mi, int action, bool poll);

void multi_io_delete_event(struct multi_io *multi_io, event_t event);

#endif /* ifndef MULTI_IO_H */
