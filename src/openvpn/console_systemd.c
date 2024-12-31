/*
 *  OpenVPN -- An application to securely tunnel IP networks
 *             over a single UDP port, with support for SSL/TLS-based
 *             session authentication and key exchange,
 *             packet encryption, packet authentication, and
 *             packet compression.
 *
 *  Copyright (C) 2014-2015 David Sommerseth <davids@redhat.com>
 *  Copyright (C) 2016      David Sommerseth <dazo@privateinternetaccess.com>
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

/**
 * @file Alternative method to query for user input, using systemd
 *
 */

#include "config.h"

#ifdef ENABLE_SYSTEMD
#include "syshead.h"
#include "console.h"
#include "misc.h"
#include "run_command.h"

#include <systemd/sd-daemon.h>

/*
 * is systemd running
 */

static bool
check_systemd_running(void)
{
    struct stat c;

    /* We simply test whether the systemd cgroup hierarchy is
     * mounted, as well as the systemd-ask-password executable
     * being available */

    return (sd_booted() > 0)
           && (stat(SYSTEMD_ASK_PASSWORD_PATH, &c) == 0);

}

static bool
get_console_input_systemd(const char *prompt, const bool echo, char *input, const int capacity)
{
    int std_out;
    bool ret = false;
    struct argv argv = argv_new();

    argv_printf(&argv, SYSTEMD_ASK_PASSWORD_PATH);
#ifdef SYSTEMD_NEWER_THAN_216
    /* the --echo support arrived in upstream systemd 217 */
    if (echo)
    {
        argv_printf_cat(&argv, "--echo");
    }
#endif
    argv_printf_cat(&argv, "--icon network-vpn");
    argv_printf_cat(&argv, "--timeout=0");
    argv_printf_cat(&argv, "%s", prompt);

    if ((std_out = openvpn_popen(&argv, NULL)) < 0)
    {
        return false;
    }
    memset(input, 0, capacity);
    if (read(std_out, input, capacity-1) != 0)
    {
        chomp(input);
        ret = true;
    }
    close(std_out);

    argv_free(&argv);

    return ret;
}

/**
 *  Systemd aware implementation of query_user_exec().  If systemd is not running
 *  it will fall back to use query_user_exec_builtin() instead.
 *
 */
bool
query_user_exec(void)
{
    bool ret = true;  /* Presume everything goes okay */
    int i;

    /* If systemd is not available, use the default built-in mechanism */
    if (!check_systemd_running())
    {
        return query_user_exec_builtin();
    }

    /* Loop through the complete query setup and when needed, collect the information */
    for (i = 0; i < QUERY_USER_NUMSLOTS && query_user[i].response != NULL; i++)
    {
        if (!get_console_input_systemd(query_user[i].prompt, query_user[i].echo,
                                       query_user[i].response, query_user[i].response_len) )
        {
            /* Force the final result state to failed on failure */
            ret = false;
        }
    }

    return ret;
}

#endif /* ENABLE_SYSTEMD */
