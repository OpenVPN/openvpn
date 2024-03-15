/*
 *  OpenVPN -- An application to securely tunnel IP networks
 *             over a single TCP/UDP port, with support for SSL/TLS-based
 *             session authentication and key exchange,
 *             packet encryption, packet authentication, and
 *             packet compression.
 *
 *  Copyright (C) 2022-2024 Antonio Quartulli <a@unstable.cc>
 *  Copyright (C) 2022-2024 OpenVPN Inc <sales@openvpn.net>
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
#ifndef DCO_INTERNAL_H
#define DCO_INTERNAL_H

#if defined(ENABLE_DCO)

#include "dco_freebsd.h"
#include "dco_linux.h"
#include "dco_win.h"

/**
 * This file contains the internal DCO API definition.
 * It is expected that this file is included only in dco.h.
 * The OpenVPN code should never directly include this file
 */

static inline dco_cipher_t
dco_get_cipher(const char *cipher)
{
    if (strcmp(cipher, "AES-256-GCM") == 0 || strcmp(cipher, "AES-128-GCM") == 0
        || strcmp(cipher, "AES-192-GCM") == 0)
    {
        return OVPN_CIPHER_ALG_AES_GCM;
    }
    else if (strcmp(cipher, "CHACHA20-POLY1305") == 0)
    {
        return OVPN_CIPHER_ALG_CHACHA20_POLY1305;
    }
    else
    {
        msg(M_FATAL, "DCO: provided unsupported cipher: %s", cipher);
    }
}

/**
 * The following are the DCO APIs used to control the driver.
 * They are implemented by dco_linux.c
 */

int dco_new_peer(dco_context_t *dco, unsigned int peerid, int sd,
                 struct sockaddr *localaddr, struct sockaddr *remoteaddr,
                 struct in_addr *remote_in4, struct in6_addr *remote_in6);

int dco_del_peer(dco_context_t *dco, unsigned int peerid);

int dco_new_key(dco_context_t *dco, unsigned int peerid, int keyid,
                dco_key_slot_t slot,
                const uint8_t *encrypt_key, const uint8_t *encrypt_iv,
                const uint8_t *decrypt_key, const uint8_t *decrypt_iv,
                const char *ciphername);

int dco_del_key(dco_context_t *dco, unsigned int peerid, dco_key_slot_t slot);

int dco_swap_keys(dco_context_t *dco, unsigned int peerid);

#endif /* defined(ENABLE_DCO) */
#endif /* ifndef DCO_INTERNAL_H */
