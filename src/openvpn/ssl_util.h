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

/**
 * @file SSL utility function. This file (and its .c file) is designed to
 *       to be included in units/etc without pulling in a lot of dependencies
 */

#ifndef SSL_UTIL_H_
#define SSL_UTIL_H_

#include "buffer.h"

/**
 * Extracts a variable from peer info, the returned string will be allocated
 * using the supplied gc_arena
 *
 * @param peer_info     The peer's peer_info
 * @param var           The variable *including* =, e.g. IV_CIPHERS=
 *
 * @return  The content of the variable as NULL terminated string or NULL if the
 *          variable cannot be found.
 */
char *
extract_var_peer_info(const char *peer_info,
                      const char *var,
                      struct gc_arena *gc);

/**
 * Extracts the IV_PROTO variable and returns its value or 0
 * if it cannot be extracted.
 *
 * @param peer_info     peer info string to search for IV_PROTO
 */
unsigned int
extract_iv_proto(const char *peer_info);

/**
 * Takes a locally produced OCC string for TLS server mode and modifies as
 * if the option comp-lzo was enabled. This is to send a client in
 * comp-lzo migrate mode the expected OCC string.
 *
 * Note: This function expects the string to be in the locally generated
 * format and does not accept arbitrary strings.
 *
 * @param options   the locally generated OCC string
 * @param gc        gc_arena to allocate the returned string in
 * @return          the modified string or options on error
 */
const char *
options_string_compat_lzo(const char *options, struct gc_arena *gc);
#endif
