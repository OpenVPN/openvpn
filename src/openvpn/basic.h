/*
 *  OpenVPN -- An application to securely tunnel IP networks
 *             over a single UDP port, with support for SSL/TLS-based
 *             session authentication and key exchange,
 *             packet encryption, packet authentication, and
 *             packet compression.
 *
 *  Copyright (C) 2002-2025 OpenVPN Inc <sales@openvpn.net>
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

#ifndef BASIC_H
#define BASIC_H

#define BOOL_CAST(x) ((x) ? (true) : (false))

/* size of an array */
#define SIZE(x) (sizeof(x)/sizeof(x[0]))

/* clear an object (may be optimized away, use secure_memzero() to erase secrets) */
#define CLEAR(x) memset(&(x), 0, sizeof(x))

#define IPV4_NETMASK_HOST 0xffffffffU

#endif
