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

#ifdef _WIN32
#ifndef OPENVPN_RING_BUFFER_H
#define OPENVPN_RING_BUFFER_H

#include <windows.h>
#include <winioctl.h>

#include <stdint.h>
#include <stdbool.h>

/*
 * Values below are taken from Wireguard Windows client
 * https://github.com/WireGuard/wireguard-go/blob/master/tun/wintun/ring_windows.go#L14
 */
#define WINTUN_RING_CAPACITY        0x800000
#define WINTUN_RING_TRAILING_BYTES  0x10000
#define WINTUN_MAX_PACKET_SIZE      0xffff
#define WINTUN_PACKET_ALIGN         4

#define TUN_IOCTL_REGISTER_RINGS CTL_CODE(51820U, 0x970U, METHOD_BUFFERED, FILE_READ_DATA | FILE_WRITE_DATA)

/**
 * Wintun ring buffer
 * See https://github.com/WireGuard/wintun#ring-layout
 */
struct tun_ring
{
    volatile ULONG head;
    volatile ULONG tail;
    volatile LONG alertable;
    UCHAR data[WINTUN_RING_CAPACITY + WINTUN_RING_TRAILING_BYTES];
};

/**
 * Struct for ring buffers registration
 * See https://github.com/WireGuard/wintun#registering-rings
 */
struct tun_register_rings
{
    struct
    {
        ULONG ring_size;
        struct tun_ring *ring;
        HANDLE tail_moved;
    } send, receive;
};

struct TUN_PACKET_HEADER
{
    uint32_t size;
};

struct TUN_PACKET
{
    uint32_t size;
    UCHAR data[WINTUN_MAX_PACKET_SIZE];
};

/**
 * Registers ring buffers used to exchange data between
 * userspace openvpn process and wintun kernel driver,
 * see https://github.com/WireGuard/wintun#registering-rings
 *
 * @param device              handle to opened wintun device
 * @param send_ring           pointer to send ring
 * @param receive_ring        pointer to receive ring
 * @param send_tail_moved     event set by wintun to signal openvpn
 *                            that data is available for reading in send ring
 * @param receive_tail_moved  event set by openvpn to signal wintun
 *                            that data has been written to receive ring
 * @return                    true if registration is successful, false otherwise - use GetLastError()
 */
static bool
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

#endif /* ifndef OPENVPN_RING_BUFFER_H */
#endif /* ifdef _WIN32 */
