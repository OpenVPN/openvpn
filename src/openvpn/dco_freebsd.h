/*
 *  Interface to FreeBSD dco networking code
 *
 *  Copyright (C) 2022 Rubicon Communications, LLC (Netgate). All Rights Reserved.
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
#ifndef DCO_FREEBSD_H
#define DCO_FREEBSD_H

#if defined(ENABLE_DCO) && defined(TARGET_FREEBSD)

#include <buffer.h>
#include "event.h"

#include "ovpn_dco_freebsd.h"

typedef enum ovpn_key_slot dco_key_slot_t;
typedef enum ovpn_key_cipher dco_cipher_t;

enum ovpn_message_type_t {
    OVPN_CMD_DEL_PEER,
    OVPN_CMD_PACKET,
};

enum ovpn_del_reason_t {
    OVPN_DEL_PEER_REASON_EXPIRED,
    OVPN_DEL_PEER_REASON_TRANSPORT_ERROR,
    OVPN_DEL_PEER_REASON_USERSPACE,
};

typedef struct dco_context {
    bool open;
    int fd;
    int pipefd[2];

    char ifname[IFNAMSIZ];

    struct buffer dco_packet_in;

    int dco_message_type;
    int dco_message_peer_id;
    int dco_del_peer_reason;
} dco_context_t;

#endif /* defined(ENABLE_DCO) && defined(TARGET_FREEBSD) */
#endif /* ifndef DCO_FREEBSD_H */
