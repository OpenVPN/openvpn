/*
 *  Interface to linux dco networking code
 *
 *  Copyright (C) 2020-2021 Antonio Quartulli <a@unstable.cc>
 *  Copyright (C) 2020-2021 Arne Schwabe <arne@rfc2549.org>
 *  Copyright (C) 2020-2021 OpenVPN Inc <sales@openvpn.net>
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
 *  distribution); if not, write to the Free Software Foundation, Inc.,
 *  59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */
#ifndef DCO_LINUX_H
#define DCO_LINUX_H

#if defined(ENABLE_DCO) && defined(TARGET_LINUX)

#include "event.h"

#include "ovpn_dco_linux.h"

#include <netlink/socket.h>
#include <netlink/netlink.h>

typedef enum ovpn_key_slot dco_key_slot_t;
typedef enum ovpn_cipher_alg dco_cipher_t;

#define DCO_IROUTE_METRIC   100
#define DCO_DEFAULT_METRIC  200

typedef struct
{
    struct nl_sock *nl_sock;
    struct nl_cb *nl_cb;
    int status;

    enum ovpn_mode ifmode;

    int ovpn_dco_id;
    int ovpn_dco_mcast_id;

    unsigned int ifindex;

    struct buffer dco_packet_in;

    int dco_message_type;
    int dco_message_peer_id;
    int dco_del_peer_reason;
} dco_context_t;

#endif /* defined(ENABLE_DCO) && defined(TARGET_LINUX) */
#endif /* ifndef DCO_LINUX_H */
