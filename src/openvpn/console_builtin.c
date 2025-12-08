/*
 *  OpenVPN -- An application to securely tunnel IP networks
 *             over a single UDP port, with support for SSL/TLS-based
 *             session authentication and key exchange,
 *             packet encryption, packet authentication, and
 *             packet compression.
 *
 *  Copyright (C) 2002-2025 OpenVPN Inc <sales@openvpn.net>
 *  Copyright (C) 2014-2015  David Sommerseth <davids@redhat.com>
 *  Copyright (C) 2016-2025 David Sommerseth <davids@openvpn.net>
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

/*
 *  These functions covers handing user input/output using the default consoles
 *
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "syshead.h"
#include "console.h"
#include "error.h"
#include "buffer.h"
#include "misc.h"

#ifdef HAVE_TERMIOS_H
#include <termios.h>
#endif


#ifdef HAVE_TERMIOS_H

/**
 * Open the current console TTY for read/write operations
 *
 * @params write   If true, the user wants to write to the console
 *                 otherwise read from the console
 *
 * @returns Returns a FILE pointer to either the TTY in read or write mode
 *          or stdin/stderr, depending on the write flag
 *
 */
static FILE *
open_tty(const bool write)
{
    FILE *ret;
    ret = fopen("/dev/tty", write ? "w" : "r");
    if (!ret)
    {
        ret = write ? stderr : stdin;
    }
    return ret;
}

/**
 * Closes the TTY FILE pointer, but only if it is not a stdin/stderr FILE object.
 *
 * @param fp     FILE pointer to close
 *
 */
static void
close_tty(FILE *fp)
{
    if (fp != stderr && fp != stdin)
    {
        fclose(fp);
    }
}

#endif /* HAVE_TERMIOS_H */


/**
 *  Core function for getting input from console
 *
 *  @param prompt    The prompt to present to the user
 *  @param echo      Should the user see what is being typed
 *  @param input     Pointer to the buffer used to save the user input
 *  @param capacity  Size of the input buffer
 *
 *  @returns Returns True if user input was gathered
 */
static bool
get_console_input(const char *prompt, const bool echo, char *input, const int capacity)
{
    bool ret = false;
    ASSERT(prompt);
    ASSERT(input);
    ASSERT(capacity > 0);
    input[0] = '\0';

#if defined(HAVE_TERMIOS_H)
    bool restore_tty = false;
    struct termios tty_tmp, tty_save;

    /* did we --daemon'ize before asking for passwords?
     * (in which case neither stdin or stderr are connected to a tty and
     * /dev/tty can not be open()ed anymore)
     */
    if (!isatty(0) && !isatty(2))
    {
        int fd = open("/dev/tty", O_RDWR);
        if (fd < 0)
        {
            msg(M_FATAL,
                "neither stdin nor stderr are a tty device and you have neither a "
                "controlling tty nor systemd - can't ask for '%s'.  If you used --daemon, "
                "you need to use --askpass to make passphrase-protected keys work, and you "
                "can not use --auth-nocache.",
                prompt);
        }
        close(fd);
    }

    FILE *fp = open_tty(true);
    fprintf(fp, "%s", prompt);
    fflush(fp);
    close_tty(fp);

    fp = open_tty(false);

    if (!echo && (tcgetattr(fileno(fp), &tty_tmp) == 0))
    {
        tty_save = tty_tmp;
        tty_tmp.c_lflag &= ~(ECHO | ECHOE | ECHOK | ECHONL | ISIG);
        restore_tty = (tcsetattr(fileno(fp), TCSAFLUSH, &tty_tmp) == 0);
    }

    if (fgets(input, capacity, fp) != NULL)
    {
        chomp(input);
        ret = true;
    }

    if (restore_tty)
    {
        if (tcsetattr(fileno(fp), TCSAFLUSH, &tty_save) == -1)
        {
            msg(M_WARN | M_ERRNO, "tcsetattr() failed to restore tty settings");
        }

        /* Echo the non-echoed newline */
        close_tty(fp);
        fp = open_tty(true);
        fprintf(fp, "\n");
        fflush(fp);
    }

    close_tty(fp);
#else
    msg(M_FATAL, "Sorry, but I can't get console input on this OS (%s)", prompt);
#endif
    return ret;
}

/**
 * @copydoc query_user_exec()
 *
 * Default method for querying user using default stdin/stdout on a console.
 * This needs to be available as a backup interface for the alternative
 * implementations in case they cannot query through their implementation
 * specific methods.
 *
 * If no alternative implementation is declared, a wrapper in console.h will ensure
 * query_user_exec() will call this function instead.
 *
 */
bool
query_user_exec_builtin(void)
{
    bool ret = true; /* Presume everything goes okay */
    int i;

    /* Loop through configured query_user slots */
    for (i = 0; i < QUERY_USER_NUMSLOTS && query_user[i].response != NULL; i++)
    {
        if (!get_console_input(query_user[i].prompt, query_user[i].echo, query_user[i].response,
                               query_user[i].response_len))
        {
            /* Force the final result state to failed on failure */
            ret = false;
        }
    }

    return ret;
}
