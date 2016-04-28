/*
 *  OpenVPN -- An application to securely tunnel IP networks
 *             over a single TCP/UDP port, with support for SSL/TLS-based
 *             session authentication and key exchange,
 *             packet encryption, packet authentication, and
 *             packet compression.
 *
 *  Copyright (C) 2002-2010 OpenVPN Technologies, Inc. <sales@openvpn.net>
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

#ifndef _PLUGIN_AUTH_PAM_UTILS__H
#define _PLUGIN_AUTH_PAM_UTILS__H

/*  Read 'tosearch', replace all occurences of 'searchfor' with 'replacewith' and return
 *  a pointer to the NEW string.  Does not modify the input strings.  Will not enter an
 *  infinite loop with clever 'searchfor' and 'replacewith' strings.
 *  Daniel Johnson - Progman2000@usa.net / djohnson@progman.us
 *
 *  Retuns NULL when
 *   - any parameter is NULL
 *   - the worst-case result is to large ( >= SIZE_MAX)
 */
char *
searchandreplace(const char *tosearch, const char *searchfor, const char *replacewith);

/*
 * Given an environmental variable name, search
 * the envp array for its value, returning it
 * if found or NULL otherwise.
 */
const char *
get_env (const char *name, const char *envp[]);

/*
 * Return the length of a string array
 */
int
string_array_len (const char *array[]);

#endif
