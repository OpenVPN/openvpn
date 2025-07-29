/*
 *  OpenVPN -- An application to securely tunnel IP networks
 *             over a single TCP/UDP port, with support for SSL/TLS-based
 *             session authentication and key exchange,
 *             packet encryption, packet authentication, and
 *             packet compression.
 *
 *  Copyright (C) 2002-2025 OpenVPN Inc <sales@openvpn.net>
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

/**
 * Filter an option line by all pull filters.
 *
 * If a match is found, the line is modified depending on
 * the filter type, and returns true. If the filter type is
 * reject, SIGUSR1 is triggered and the return value is false.
 * In that case the caller must end the push processing.
 */
bool
apply_pull_filter(const struct options *o,
                  char *line);

/**
 * @brief Checks the formatting and validity of options inside push-update messages.
 *
 * This function is used to validate and process options
 * in push-update messages. It performs the following checks:
 * - Determines if the options are updatable.
 * - Checks for the presence of the `-` flag, which indicates that the option
 *   should be removed.
 * - Checks for the `?` flag, which marks the option as optional and suppresses
 *   errors if the client cannot update it.
 * - Increase the value pointed by 'i' when we encounter the `'-'` and `'?'` flags
 *   after validating them and updating the appropriate flags in the `flags` variable.
 * - `-?option`, `-option`, `?option` are valid formats, `?-option` is not a valid format.
 * - If the flags and the option are not consecutive, the option is invalid:
 *   `- ?option`, `-? option`, `- option` are invalid formats.
 *
 * @param line A pointer to an option string. This string is the option being validated.
 * @param i A pointer to an integer that represents the current index in the `line` string.
 * @param flags A pointer where flags will be stored:
 *              - `PUSH_OPT_TO_REMOVE`: Set if the `-` flag is present.
 *              - `PUSH_OPT_OPTIONAL`: Set if the `?` flag is present.
 *
 * @return true if the flags and option combination are valid.
 * @return false if:
 *         - The `-` and `?` flags are not formatted correctly.
 *         - The `line` parameter is empty or `NULL`.
 *         - The `?` flag is absent and the option is not updatable.
 */
bool
check_push_update_option_flags(char *line, int *i, unsigned int *flags);

#endif /* ifndef OPTIONS_UTIL_H_ */
