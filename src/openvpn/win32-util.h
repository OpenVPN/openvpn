/*
 *  OpenVPN -- An application to securely tunnel IP networks
 *             over a single UDP port, with support for SSL/TLS-based
 *             session authentication and key exchange,
 *             packet encryption, packet authentication, and
 *             packet compression.
 *
 *  Copyright (C) 2002-2024 OpenVPN Inc <sales@openvpn.net>
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

#ifdef _WIN32
#ifndef OPENVPN_WIN32_UTIL_H
#define OPENVPN_WIN32_UTIL_H

#include <winioctl.h>

#include "mtu.h"
#include "openvpn-msg.h"
#include "argv.h"

/* Convert a string from UTF-8 to UCS-2 */
WCHAR *wide_string(const char *utf8, struct gc_arena *gc);

/* Convert a string from UTF-16 to UTF-8 */
char *utf16to8(const wchar_t *utf16, struct gc_arena *gc);

/* return true if filename is safe to be used on Windows */
bool win_safe_filename(const char *fn);

/* Find temporary directory */
const char *win_get_tempdir(void);

#endif /* OPENVPN_WIN32_UTIL_H */
#endif /* ifdef _WIN32 */
