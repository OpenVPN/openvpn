/*
 *  OpenVPN -- An application to securely tunnel IP networks
 *             over a single TCP/UDP port, with support for SSL/TLS-based
 *             session authentication and key exchange,
 *             packet encryption, packet authentication, and
 *             packet compression.
 *
 *  Copyright (C) 2002-2021 OpenVPN Inc <sales@openvpn.net>
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

#ifndef DHCP_H
#define DHCP_H

#include "common.h"
#include "buffer.h"
#include "proto.h"

#pragma pack(1)

/* DHCP Option types */
#define DHCP_PAD          0
#define DHCP_ROUTER       3
#define DHCP_MSG_TYPE    53  /* message type (u8) */
#define DHCP_END        255

/* DHCP Messages types */
#define DHCPDISCOVER 1
#define DHCPOFFER    2
#define DHCPREQUEST  3
#define DHCPDECLINE  4
#define DHCPACK      5
#define DHCPNAK      6
#define DHCPRELEASE  7
#define DHCPINFORM   8

/* DHCP UDP port numbers */
#define BOOTPS_PORT 67
#define BOOTPC_PORT 68

struct dhcp {
#define BOOTREQUEST 1
#define BOOTREPLY   2
    uint8_t op;        /* message op */

    uint8_t htype;     /* hardware address type (e.g. '1' = 10Mb Ethernet) */
    uint8_t hlen;      /* hardware address length (e.g. '6' for 10Mb Ethernet) */
    uint8_t hops;      /* client sets to 0, may be used by relay agents */
    uint32_t xid;      /* transaction ID, chosen by client */
    uint16_t secs;     /* seconds since request process began, set by client */
    uint16_t flags;
    uint32_t ciaddr;   /* client IP address, client sets if known */
    uint32_t yiaddr;   /* 'your' IP address -- server's response to client */
    uint32_t siaddr;   /* server IP address */
    uint32_t giaddr;   /* relay agent IP address */
    uint8_t chaddr[16]; /* client hardware address */
    uint8_t sname[64]; /* optional server host name */
    uint8_t file[128]; /* boot file name */
    uint32_t magic;    /* must be 0x63825363 (network order) */
};

struct dhcp_full {
    struct openvpn_iphdr ip;
    struct openvpn_udphdr udp;
    struct dhcp dhcp;
#define DHCP_OPTIONS_BUFFER_SIZE 256
    uint8_t options[DHCP_OPTIONS_BUFFER_SIZE];
};

#pragma pack()

in_addr_t dhcp_extract_router_msg(struct buffer *ipbuf);

#endif /* ifndef DHCP_H */
