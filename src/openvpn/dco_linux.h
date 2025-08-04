/*
 *  Interface to linux dco networking code
 *
 *  Copyright (C) 2020-2025 Antonio Quartulli <a@unstable.cc>
 *  Copyright (C) 2020-2025 Arne Schwabe <arne@rfc2549.org>
 *  Copyright (C) 2020-2025 OpenVPN Inc <sales@openvpn.net>
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
 *  You should have received a copy of the GNU General Public License
 *  along with this program (see the file COPYING included with this
 *  distribution); if not, see <https://www.gnu.org/licenses/>.
 */
#ifndef DCO_LINUX_H
#define DCO_LINUX_H

#if defined(ENABLE_DCO) && defined(TARGET_LINUX)

#include "event.h"

#include "ovpn_dco_linux.h"

#include <netlink/socket.h>
#include <netlink/netlink.h>

/* Defines to avoid mismatching with other platforms */
#define OVPN_CMD_DEL_PEER   OVPN_CMD_PEER_DEL_NTF
#define OVPN_CMD_SWAP_KEYS  OVPN_CMD_KEY_SWAP_NTF
#define OVPN_CMD_FLOAT_PEER OVPN_CMD_PEER_FLOAT_NTF

typedef enum ovpn_key_slot dco_key_slot_t;
typedef enum ovpn_cipher_alg dco_cipher_t;

/* OVPN section */

#ifndef IFLA_OVPN_MAX

enum ovpn_mode
{
    OVPN_MODE_P2P,
    OVPN_MODE_MP,
};

enum ovpn_ifla_attrs
{
    IFLA_OVPN_UNSPEC = 0,
    IFLA_OVPN_MODE,

    __IFLA_OVPN_MAX,
};

#define IFLA_OVPN_MAX (__IFLA_OVPN_MAX - 1)

#endif /* ifndef IFLA_OVPN_MAX */

typedef struct
{
    struct nl_sock *nl_sock;
    struct nl_cb *nl_cb;
    int status;

    struct context *c;
    int ctrlid;

    enum ovpn_mode ifmode;

    int ovpn_dco_id;
    int ovpn_dco_mcast_id;

    unsigned int ifindex;

    int dco_message_type;
    int dco_message_peer_id;
    int dco_message_key_id;
    int dco_del_peer_reason;
    struct sockaddr_storage dco_float_peer_ss;
    uint64_t dco_read_bytes;
    uint64_t dco_write_bytes;
} dco_context_t;

#endif /* defined(ENABLE_DCO) && defined(TARGET_LINUX) */
#endif /* ifndef DCO_LINUX_H */
