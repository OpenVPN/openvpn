/*
 *  OpenVPN -- An application to securely tunnel IP networks
 *             over a single UDP port, with support for SSL/TLS-based
 *             session authentication and key exchange,
 *             packet encryption, packet authentication, and
 *             packet compression.
 *
 *  Copyright (C) 2002-2024 OpenVPN Inc <sales@openvpn.net>
 *  Copyright (C) 2014-2015 David Sommerseth <davids@redhat.com>
 *  Copyright (C) 2016-2024 David Sommerseth <davids@openvpn.net>
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

#ifndef CONSOLE_H
#define CONSOLE_H

#include "basic.h"

/**
 *  Configuration setup for declaring what kind of information to ask a user for
 */
struct _query_user {
    char *prompt;             /**< Prompt to present to the user */
    size_t prompt_len;        /**< Length of the prompt string */
    char *response;           /**< The user's response */
    size_t response_len;      /**< Length the of the user response */
    bool echo;                /**< True: The user should see what is being typed, otherwise mask it */
};

#define QUERY_USER_NUMSLOTS 10
extern struct _query_user query_user[];  /**< Global variable, declared in console.c */

/**
 * Wipes all data put into all of the query_user structs
 *
 */
void query_user_clear(void);


/**
 * Adds an item to ask the user for
 *
 * @param prompt     Prompt to display to the user
 * @param prompt_len Length of the prompt string
 * @param resp       String containing the user response
 * @param resp_len   Length of the response string
 * @param echo       Should the user input be echoed to the user?  If False, input will be masked
 *
 */
void query_user_add(char *prompt, size_t prompt_len,
                    char *resp, size_t resp_len,
                    bool echo);


/**
 * Executes a configured setup, using the built-in method for querying the user.
 * This method uses the console/TTY directly.
 *
 * @param setup    Pointer to the setup defining what to ask the user
 *
 * @return True if executing all the defined steps completed successfully
 */
bool query_user_exec_builtin(void);


#if defined(ENABLE_SYSTEMD)
/**
 * Executes a configured setup, using the compiled method for querying the user
 *
 * @param setup    Pointer to the setup defining what to ask the user
 *
 * @return True if executing all the defined steps completed successfully
 */
bool query_user_exec(void);

#else  /* ENABLE_SYSTEMD not defined*/
/**
 * Wrapper function enabling query_user_exec() if no alternative methods have
 * been enabled
 *
 */
static bool
query_user_exec(void)
{
    return query_user_exec_builtin();
}
#endif  /* defined(ENABLE_SYSTEMD) */


/**
 * A plain "make Gert happy" wrapper.  Same arguments as @query_user_add
 *
 * FIXME/TODO: Remove this when refactoring the complete user query process
 *             to be called at start-up initialization of OpenVPN.
 *
 */
static inline bool
query_user_SINGLE(char *prompt, size_t prompt_len,
                  char *resp, size_t resp_len,
                  bool echo)
{
    query_user_clear();
    query_user_add(prompt, prompt_len, resp, resp_len, echo);
    return query_user_exec();
}

#endif /* ifndef CONSOLE_H */
