/*
 *  OpenVPN -- An application to securely tunnel IP networks
 *             over a single TCP/UDP port, with support for SSL/TLS-based
 *             session authentication and key exchange,
 *             packet encryption, packet authentication, and
 *             packet compression.
 *
 *  Copyright (C) 2002-2024 OpenVPN Inc <sales@openvpn.net>
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

#ifndef AFUNIX_TUN_H
#define AFUNIX_TUN_H
#include <sys/types.h>

#include "tun.h"

/**
 * Opens an AF_UNIX based tun device. This also executes the command that
 * the user provided taking care of implementing the actual tun
 * device.
 */
void
open_tun_afunix(struct options *o,
                int mtu,
                struct tuntap *tt,
                struct env_set *env);


/**
 * Closes the socket used for the AF_UNIX based device. Also sends a
 * SIGINT to the child process that was spawned to handle the tun device
 */
void
close_tun_afunix(struct tuntap *tt);

/**
 * Writes a packet to a AF_UNIX based tun device.
 */
ssize_t
write_tun_afunix(struct tuntap *tt, uint8_t *buf, int len);

/**
 * Reads a packet from a AF_UNIX based tun device.
 */
ssize_t
read_tun_afunix(struct tuntap *tt, uint8_t *buf, int len);

#endif /* AFUNIX_TUN_H */

/**
 * Checks whether a --dev-node parameter specifies a AF_UNIX device
 * @param devnode   the string to check
 * @return          true if the string starts with unix:
 */
static inline bool
is_tun_afunix(const char *devnode)
{
    return devnode && strprefix(devnode, "unix:");
}
