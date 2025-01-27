/*
 *  OpenVPN -- An application to securely tunnel IP networks
 *             over a single TCP/UDP port, with support for SSL/TLS-based
 *             session authentication and key exchange,
 *             packet encryption, packet authentication, and
 *             packet compression.
 *
 *  Copyright (C) 2002-2024 OpenVPN Inc <sales@openvpn.net>
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

#ifndef OPTIONS_UTIL_H_
#define OPTIONS_UTIL_H_

#include "options.h"

const char *
parse_auth_failed_temp(struct options *o, const char *reason);


/** Checks if the string is a valid integer by checking if it can be
 *  converted to an integer */
bool
valid_integer(const char *str, bool positive);

/**
 * Converts a str to a positive number if the string represents a postive
 * integer number. Otherwise print a warning with msglevel and return 0
 */
int
positive_atoi(const char *str, int msglevel);

/**
 * Converts a str to an integer if the string can be represented as an
 * integer number. Otherwise print a warning with msglevel and return 0
 */
int
atoi_warn(const char *str, int msglevel);

#endif /* ifndef OPTIONS_UTIL_H_ */
