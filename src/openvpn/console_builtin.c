/*
 *  OpenVPN -- An application to securely tunnel IP networks
 *             over a single UDP port, with support for SSL/TLS-based
 *             session authentication and key exchange,
 *             packet encryption, packet authentication, and
 *             packet compression.
 *
 *  Copyright (C) 2002-2021 OpenVPN Inc <sales@openvpn.net>
 *  Copyright (C) 2014-2015  David Sommerseth <davids@redhat.com>
 *  Copyright (C) 2016-2021 David Sommerseth <davids@openvpn.net>
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

/*
 *  These functions covers handing user input/output using the default consoles
 *
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#elif defined(_MSC_VER)
#include "config-msvc.h"
#endif

#include "syshead.h"
#include "console.h"
#include "error.h"
#include "buffer.h"
#include "misc.h"

#ifdef HAVE_TERMIOS_H
#include <termios.h>
#endif

#ifdef _WIN32

#include "win32.h"

/**
 * Get input from a Windows console.
 *
 * @param prompt    Prompt to display to the user
 * @param echo      Should the user input be displayed in the console
 * @param input     Pointer to the buffer the user input will be saved
 * @param capacity  Size of the buffer for the user input
 *
 * @return Return false on input error, or if service
 *         exit event is signaled.
 */
static bool
get_console_input_win32(const char *prompt, const bool echo, char *input, const int capacity)
{
    ASSERT(prompt);
    ASSERT(input);
    ASSERT(capacity > 0);

    input[0] = '\0';

    HANDLE in = GetStdHandle(STD_INPUT_HANDLE);
    int orig_stderr = get_orig_stderr(); // guaranteed to be always valid
    if ((in == INVALID_HANDLE_VALUE)
        || win32_service_interrupt(&win32_signal)
        || (_write(orig_stderr, prompt, strlen(prompt)) == -1))
    {
        msg(M_WARN|M_ERRNO, "get_console_input_win32(): unexpected error");
        return false;
    }

    bool is_console = (GetFileType(in) == FILE_TYPE_CHAR);
    DWORD flags_save = 0;
    int status = 0;
    WCHAR *winput;

    if (is_console)
    {
        if (GetConsoleMode(in, &flags_save))
        {
            DWORD flags = ENABLE_LINE_INPUT | ENABLE_PROCESSED_INPUT;
            if (echo)
            {
                flags |= ENABLE_ECHO_INPUT;
            }
            SetConsoleMode(in, flags);
        }
        else
        {
            is_console = 0;
        }
    }

    DWORD len = 0;

    if (is_console)
    {
        winput = malloc(capacity * sizeof(WCHAR));
        if (winput == NULL)
        {
            return false;
        }

        status = ReadConsoleW(in, winput, capacity, &len, NULL);
        WideCharToMultiByte(CP_UTF8, 0, winput, len, input, capacity, NULL, NULL);
        free(winput);
    }
    else
    {
        status = ReadFile(in, input, capacity, &len, NULL);
    }

    string_null_terminate(input, (int)len, capacity);
    chomp(input);

    if (!echo)
    {
        _write(orig_stderr, "\r\n", 2);
    }
    if (is_console)
    {
        SetConsoleMode(in, flags_save);
    }
    if (status && !win32_service_interrupt(&win32_signal))
    {
        return true;
    }

    return false;
}

#endif   /* _WIN32 */


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
 * @params fp     FILE pointer to close
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

#endif   /* HAVE_TERMIOS_H */


/**
 *  Core function for getting input from console
 *
 *  @params prompt    The prompt to present to the user
 *  @params echo      Should the user see what is being typed
 *  @params input     Pointer to the buffer used to save the user input
 *  @params capacity  Size of the input buffer
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

#if defined(_WIN32)
    return get_console_input_win32(prompt, echo, input, capacity);
#elif defined(HAVE_TERMIOS_H)
    bool restore_tty = false;
    struct termios tty_tmp, tty_save;

    /* did we --daemon'ize before asking for passwords?
     * (in which case neither stdin or stderr are connected to a tty and
     * /dev/tty can not be open()ed anymore)
     */
    if (!isatty(0) && !isatty(2) )
    {
        int fd = open( "/dev/tty", O_RDWR );
        if (fd < 0)
        {
            msg(M_FATAL, "neither stdin nor stderr are a tty device and you have neither a "
                "controlling tty nor systemd - can't ask for '%s'.  If you used --daemon, "
                "you need to use --askpass to make passphrase-protected keys work, and you "
                "can not use --auth-nocache.", prompt );
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
#else  /* if defined(_WIN32) */
    msg(M_FATAL, "Sorry, but I can't get console input on this OS (%s)", prompt);
#endif /* if defined(_WIN32) */
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
        if (!get_console_input(query_user[i].prompt, query_user[i].echo,
                               query_user[i].response, query_user[i].response_len) )
        {
            /* Force the final result state to failed on failure */
            ret = false;
        }
    }

    return ret;
}
