/*
 *  OpenVPN -- An application to securely tunnel IP networks
 *             over a single TCP/UDP port, with support for SSL/TLS-based
 *             session authentication and key exchange,
 *             packet encryption, packet authentication, and
 *             packet compression.
 *
 *  Copyright (C) 2002-2022 OpenVPN Inc <sales@openvpn.net>
 *  Copyright (C) 2010-2021 Fox Crypto B.V. <openvpn@foxcrypto.com>
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

/**
 * @file Control Channel SSL/Data dynamic negotion Module
 * This file is split from ssl.h to be able to unit test it.
 */

#ifndef OPENVPN_SSL_NCP_H
#define OPENVPN_SSL_NCP_H

#include "buffer.h"
#include "options.h"

/**
 * Returns whether the client supports NCP either by
 * announcing IV_NCP>=2 or the IV_CIPHERS list
 */
bool
tls_peer_supports_ncp(const char *peer_info);

/* forward declaration to break include dependency loop */
struct context;

/**
 * Checks whether the cipher negotiation is in an acceptable state
 * and we continue to connect or should abort.
 *
 * @return  Wether the client NCP process suceeded or failed
 */
bool
check_pull_client_ncp(struct context *c, int found);

/**
 * Iterates through the ciphers in server_list and return the first
 * cipher that is also supported by the peer according to the IV_NCP
 * and IV_CIPHER values in peer_info.
 *
 * We also accept a cipher that is the remote cipher of the client for
 * "Poor man's NCP": Use peer cipher if it is an allowed (NCP) cipher.
 * Allows non-NCP peers to upgrade their cipher individually.
 *
 * Make sure to call tls_session_update_crypto_params() after calling this
 * function.
 *
 * @param gc   gc arena that is ONLY used to allocate the returned string
 *
 * @returns NULL if no common cipher is available, otherwise the best common
 * cipher
 */
char *
ncp_get_best_cipher(const char *server_list, const char *peer_info,
                    const char *remote_cipher, struct gc_arena *gc);


/**
 * Returns the support cipher list from the peer according to the IV_NCP
 * and IV_CIPHER values in peer_info.
 *
 * @returns Either a string containing the ncp list that is either static
 * or allocated via gc. If no information is available an empty string
 * ("") is returned.
 */
const char *
tls_peer_ncp_list(const char *peer_info, struct gc_arena *gc);

/**
 * Check whether the ciphers in the supplied list are supported.
 *
 * @param list          Colon-separated list of ciphers
 * @parms gc            gc_arena to allocate the returned string
 *
 * @returns             colon separated string of normalised (via
 *                      translate_cipher_name_from_openvpn) and
 *                      zero terminated string iff all ciphers
 *                      in list are supported and the total length
 *                      is short than MAX_NCP_CIPHERS_LENGTH. NULL
 *                      otherwise.
 */
char *
mutate_ncp_cipher_list(const char *list, struct gc_arena *gc);

/**
 * Return true iff item is present in the colon-separated zero-terminated
 * cipher list.
 */
bool tls_item_in_cipher_list(const char *item, const char *list);

/**
 * The maximum length of a ncp-cipher string that is accepted.
 *
 * Since this list needs to be pushed as IV_CIPHERS, we are conservative
 * about its length.
 */
#define MAX_NCP_CIPHERS_LENGTH 127

#endif /* ifndef OPENVPN_SSL_NCP_H */
