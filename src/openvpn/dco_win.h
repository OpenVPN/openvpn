/*
 *  Interface to ovpn-win-dco networking code
 *
 *  Copyright (C) 2020-2024 Arne Schwabe <arne@rfc2549.org>
 *  Copyright (C) 2020-2024 OpenVPN Inc <sales@openvpn.net>
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

#ifndef DCO_WIN_H
#define DCO_WIN_H

#if defined(ENABLE_DCO) && defined(_WIN32)

#include "buffer.h"
#include "ovpn_dco_win.h"
#include "sig.h"

typedef OVPN_KEY_SLOT dco_key_slot_t;
typedef OVPN_CIPHER_ALG dco_cipher_t;

typedef enum {
    DCO_MODE_UNINIT,
    DCO_MODE_P2P,
    DCO_MODE_MP
} dco_mode_type;

struct dco_context {
    struct tuntap *tt;
    dco_mode_type ifmode;

    OVPN_NOTIFY_EVENT notif_buf; /**< Buffer for incoming notifications. */
    OVERLAPPED ov; /**< Used by overlapped I/O for async IOCTL. */
    int iostate; /**< State of overlapped I/O; see definitions in win32.h. */
    struct rw_handle rwhandle; /**< Used to hook async I/O to the OpenVPN event loop. */
    int ov_ret; /**< Win32 error code for overlapped operation, 0 for success */

    int dco_message_peer_id;
    int dco_message_type;
    int dco_del_peer_reason;

    uint64_t dco_read_bytes;
    uint64_t dco_write_bytes;
};

typedef struct dco_context dco_context_t;

void
dco_mp_start_vpn(HANDLE handle, struct link_socket *sock);

void
dco_p2p_new_peer(HANDLE handle, struct link_socket *sock, struct signal_info *sig_info);

void
dco_start_tun(struct tuntap *tt);

bool
dco_win_supports_multipeer(void);

#else /* if defined(ENABLE_DCO) && defined(_WIN32) */

static inline void
dco_start_tun(struct tuntap *tt)
{
    ASSERT(false);
}

#endif /* defined(_WIN32) */
#endif /* ifndef DCO_H */
