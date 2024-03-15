/*
 *  OpenVPN -- An application to securely tunnel IP networks
 *             over a single TCP/UDP port, with support for SSL/TLS-based
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

#ifndef _PLUGIN_AUTH_PAM_UTILS__H
#define _PLUGIN_AUTH_PAM_UTILS__H

/**
 *  Read 'tosearch', replace all occurrences of 'searchfor' with 'replacewith' and return
 *  a pointer to the NEW string.  Does not modify the input strings.  Will not enter an
 *  infinite loop with clever 'searchfor' and 'replacewith' strings.
 *
 *  @author Daniel Johnson - Progman2000@usa.net / djohnson@progman.us
 *
 *  @param tosearch      haystack to search in
 *  @param searchfor     needle to search for in the haystack
 *  @param replacewith   when a match is found, replace needle with this string
 *
 *  @return Returns NULL when any parameter is NULL or the worst-case result is to large ( >= SIZE_MAX).
 *          Otherwise it returns a pointer to a new buffer containing the modified input
 */
char *
searchandreplace(const char *tosearch, const char *searchfor, const char *replacewith);

/**
 * Given an environmental variable name, search
 * the envp array for its value
 *
 * @param name  Environment variable to look up
 * @param envp  Environment variable table with all key/value pairs
 *
 * @return Returns a pointer to the value of the environment variable if found, otherwise NULL is returned.
 */
const char *
get_env(const char *name, const char *envp[]);

/**
 * Return the length of a string array
 *
 * @param array   Pointer to the array to calculate size of
 *
 */
int
string_array_len(const char *array[]);

#endif
