/*
 *  Interface to ovpn-win-dco networking code
 *
 *  Copyright (C) 2020-2022 Arne Schwabe <arne@rfc2549.org>
 *  Copyright (C) 2020-2022 OpenVPN Inc <sales@openvpn.net>
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
#include "ovpn-dco-win.h"

typedef OVPN_KEY_SLOT dco_key_slot_t;
typedef OVPN_CIPHER_ALG dco_cipher_t;

struct dco_context {
    bool real_tun_init;
    struct tuntap *tt;
};

typedef struct dco_context dco_context_t;

struct tuntap
dco_create_socket(struct addrinfo *remoteaddr, bool bind_local,
                  struct addrinfo *bind, const char *devname,
                  struct gc_arena *gc, int timeout,
                  volatile int *signal_received);

void
dco_start_tun(struct tuntap *tt);

#else

static inline void dco_start_tun(struct tuntap *tt)
{
    ASSERT(false);
}

#endif /* defined(_WIN32) */
#endif /* ifndef DCO_H */
