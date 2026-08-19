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

#ifndef CHECK_FILE_ACCESS_H
#define CHECK_FILE_ACCESS_H

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#ifndef ENABLE_SMALL

#include "options.h"

/**
 * Verifies that the path in the "command" that comes after certain script options (e.g., --up) is a
 * valid file with appropriate permissions.
 *
 * "command" consists of a path, optionally followed by a space, which may be
 * followed by arbitrary arguments. It is NOT a full shell command line -- shell expansion is not
 * performed.
 *
 * The path and arguments in "command" may be single- or double-quoted or escaped.
 *
 * The path is extracted from "command", then check_file_access() is called to check it. The
 * arguments, if any, are ignored.
 *
 * Note that the type, mode, and opt arguments to this routine are the same as the corresponding
 * check_file_access() arguments.
 */
bool check_cmd_access(const char *command, const char *opt, const char *chroot);

/**
 * Sanity check of all file/dir options.  Checks that file/dir
 * is accessible by OpenVPN
 */
void options_postprocess_filechecks(struct options *options);

#endif /* !ENABLE_SMALL */

#endif /* CHECK_FILE_ACCESS_H */
