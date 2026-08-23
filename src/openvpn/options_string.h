/*
 *  OpenVPN -- An application to securely tunnel IP networks
 *             over a single UDP port, with support for SSL/TLS-based
 *             session authentication and key exchange,
 *             packet encryption, packet authentication, and
 *             packet compression.
 *
 *  Copyright (C) 2002-2026 OpenVPN Inc <sales@openvpn.net>
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
 *  with this program; if not, see <https://www.gnu.org/licenses/>.
 */

#ifndef OPTIONS_STRING_H
#define OPTIONS_STRING_H

#include "buffer.h"
#include "options.h"

const char *options_string_version(const char *s, struct gc_arena *gc);

/**
 * Build an options string to represent data channel encryption options.
 * This string must match exactly between peers.  The keysize is checked
 * separately by read_key().
 *
 * The following options must match on both peers:
 *
 * Tunnel options:
 *
 * --dev tun|tap [unit number need not match]
 * --dev-type tun|tap
 * --link-mtu
 * --udp-mtu
 * --tun-mtu
 * --proto udp
 * --proto tcp-client [matched with --proto tcp-server
 *                     on the other end of the connection]
 * --proto tcp-server [matched with --proto tcp-client on
 *                     the other end of the connection]
 * --tun-ipv6
 * --ifconfig x y [matched with --ifconfig y x on
 *                 the other end of the connection]
 *
 * --comp-lzo
 * --compress alg
 * --fragment
 *
 * Crypto Options:
 *
 * --cipher
 * --auth
 * --secret
 *
 * SSL Options:
 *
 * --tls-auth
 * --tls-client [matched with --tls-server on
 *               the other end of the connection]
 * --tls-server [matched with --tls-client on
 *               the other end of the connection]
 */
char *options_string(const struct options *o, const struct frame *frame, struct tuntap *tt,
                     openvpn_net_ctx_t *ctx, bool remote, struct gc_arena *gc);

bool options_cmp_equal_safe(char *actual, const char *expected, size_t actual_n);

void options_warning_safe(char *actual, const char *expected, size_t actual_n);

bool options_cmp_equal(char *actual, const char *expected);

void options_warning(char *actual, const char *expected);

/**
 * Given an OpenVPN options string, extract the value of an option.
 *
 * @param options_string        Zero-terminated, comma-separated options string
 * @param opt_name              The name of the option to extract
 * @param gc                    The gc to allocate the return value
 *
 * @return gc-allocated value of option with name opt_name if option was found,
 *         or NULL otherwise.
 */
char *options_string_extract_option(const char *options_string, const char *opt_name,
                                    struct gc_arena *gc);


#endif
