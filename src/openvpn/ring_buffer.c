/*
 *  OpenVPN -- An application to securely tunnel IP networks
 *             over a single UDP port, with support for SSL/TLS-based
 *             session authentication and key exchange,
 *             packet encryption, packet authentication, and
 *             packet compression.
 *
 *  Copyright (C) 2002-2019 OpenVPN Inc <sales@openvpn.net>
 *                2019 Lev Stipakov <lev@openvpn.net>
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

#include "ring_buffer.h"

#ifdef _WIN32

bool
register_ring_buffers(HANDLE device,
                      struct tun_ring *send_ring,
                      struct tun_ring *receive_ring,
                      HANDLE send_tail_moved,
                      HANDLE receive_tail_moved)
{
    struct tun_register_rings rr;
    BOOL res;
    DWORD bytes_returned;

    ZeroMemory(&rr, sizeof(rr));

    rr.send.ring = send_ring;
    rr.send.ring_size = sizeof(struct tun_ring);
    rr.send.tail_moved = send_tail_moved;

    rr.receive.ring = receive_ring;
    rr.receive.ring_size = sizeof(struct tun_ring);
    rr.receive.tail_moved = receive_tail_moved;

    res = DeviceIoControl(device, TUN_IOCTL_REGISTER_RINGS, &rr, sizeof(rr),
                          NULL, 0, &bytes_returned, NULL);

    return res != FALSE;
}

#endif /* ifdef _WIN32 */