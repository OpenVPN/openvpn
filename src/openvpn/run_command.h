/*
 *  OpenVPN -- An application to securely tunnel IP networks
 *             over a single TCP/UDP port, with support for SSL/TLS-based
 *             session authentication and key exchange,
 *             packet encryption, packet authentication, and
 *             packet compression.
 *
 *  Copyright (C) 2002-2025 OpenVPN Technologies, Inc. <sales@openvpn.net>
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

#ifndef RUN_COMMAND_H
#define RUN_COMMAND_H

#include "basic.h"
#include "env_set.h"

/* Script security */
#define SSEC_NONE      0 /* strictly no calling of external programs */
#define SSEC_BUILT_IN  1 /* only call built-in programs such as ifconfig, route, netsh, etc.*/
#define SSEC_SCRIPTS   2 /* allow calling of built-in programs and user-defined scripts */
#define SSEC_PW_ENV    3 /* allow calling of built-in programs and user-defined scripts that may receive a password as an environmental variable */

#define OPENVPN_EXECVE_ERROR       -1 /* generic error while forking to run an external program */
#define OPENVPN_EXECVE_NOT_ALLOWED -2 /* external program not run due to script security */
#define OPENVPN_EXECVE_FAILURE    127 /* exit code passed back from child when execve fails */

int script_security(void);

void script_security_set(int level);

/* openvpn_execve flags */
#define S_SCRIPT    (1<<0)
#define S_FATAL     (1<<1)
/** Instead of returning 1/0 for success/fail,
 * return exit code when between 0 and 255 and -1 otherwise */
#define S_EXITCODE  (1<<2)
/** instead of waiting for child process to exit and report the status,
 * return the pid of the child process */
#define S_NOWAITPID (1<<3)

/* wrapper around the execve() call */
int openvpn_popen(const struct argv *a,  const struct env_set *es);

bool openvpn_execve_allowed(const unsigned int flags);

int openvpn_execve_check(const struct argv *a, const struct env_set *es,
                         const unsigned int flags, const char *error_message);


#ifndef WIN32
/** Checks if a running process is still running. This is mainly useful
 * for processes started with \c S_NOWAITPID
 *
 * This function is currently not implemented for Windows as the helper
 * macros used by this function are not available.
 *
 * @param pid               pid of the process to be checked
 * @param msg_prefix     prefixed of the message that be printed
 * @param msglevel          msglevel of the messages to be printed
 * @return                  true if the process is still running, false if
 *                          an error condition occurred
 */
bool
openvpn_waitpid_check(pid_t pid, const char *msg_prefix,
                      int msglevel);

#endif

/**
 * Will run a script and return the exit code of the script if between
 * 0 and 255, -1 otherwise
 */
static inline int
openvpn_run_script(const struct argv *a, const struct env_set *es,
                   const unsigned int flags, const char *hook)
{
    char msg[256];

    snprintf(msg, sizeof(msg),
             "WARNING: Failed running command (%s)", hook);
    return openvpn_execve_check(a, es, flags | S_SCRIPT, msg);
}

#endif /* ifndef RUN_COMMAND_H */
