/*
 *  OpenVPN -- An application to securely tunnel IP networks
 *             over a single TCP/UDP port, with support for SSL/TLS-based
 *             session authentication and key exchange,
 *             packet encryption, packet authentication, and
 *             packet compression.
 *
 *  Copyright (C) 2002-2021 OpenVPN Inc <sales@openvpn.net>
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

#ifdef HAVE_CONFIG_H
#include "config.h"
#elif defined(_MSC_VER)
#include "config-msvc.h"
#endif

#include "syshead.h"

#include "error.h"
#include "buffer.h"
#include "init.h"
#include "misc.h"
#include "win32.h"
#include "socket.h"
#include "tun.h"
#include "otime.h"
#include "perf.h"
#include "status.h"
#include "integer.h"
#include "ps.h"
#include "mstats.h"


#if SYSLOG_CAPABILITY
#ifndef LOG_OPENVPN
#define LOG_OPENVPN LOG_DAEMON
#endif
#endif

/* Globals */
unsigned int x_debug_level; /* GLOBAL */

/* Mute state */
static int mute_cutoff;     /* GLOBAL */
static int mute_count;      /* GLOBAL */
static int mute_category;   /* GLOBAL */

/*
 * Output mode priorities are as follows:
 *
 *  (1) --log-x overrides everything
 *  (2) syslog is used if --daemon or --inetd is defined and not --log-x
 *  (3) if OPENVPN_DEBUG_COMMAND_LINE is defined, output
 *      to constant logfile name.
 *  (4) Output to stdout.
 */

/* If true, indicates that stdin/stdout/stderr
 * have been redirected due to --log */
static bool std_redir;      /* GLOBAL */

/* Should messages be written to the syslog? */
static bool use_syslog;     /* GLOBAL */

/* Should stdout/stderr be be parsable and always be prefixed with time
 * and message flags */
static bool machine_readable_output;   /* GLOBAL */

/* Should timestamps be included on messages to stdout/stderr? */
static bool suppress_timestamps; /* GLOBAL */

/* The program name passed to syslog */
#if SYSLOG_CAPABILITY
static char *pgmname_syslog;  /* GLOBAL */
#endif

/* If non-null, messages should be written here (used for debugging only) */
static FILE *msgfp;         /* GLOBAL */

/* If true, we forked from main OpenVPN process */
static bool forked;         /* GLOBAL */

/* our default output targets */
static FILE *default_out; /* GLOBAL */
static FILE *default_err; /* GLOBAL */

void
msg_forked(void)
{
    forked = true;
}

bool
set_debug_level(const int level, const unsigned int flags)
{
    const int ceiling = 15;

    if (level >= 0 && level <= ceiling)
    {
        x_debug_level = level;
        return true;
    }
    else if (flags & SDL_CONSTRAIN)
    {
        x_debug_level = constrain_int(level, 0, ceiling);
        return true;
    }
    return false;
}

bool
set_mute_cutoff(const int cutoff)
{
    if (cutoff >= 0)
    {
        mute_cutoff = cutoff;
        return true;
    }
    else
    {
        return false;
    }
}

int
get_debug_level(void)
{
    return x_debug_level;
}

int
get_mute_cutoff(void)
{
    return mute_cutoff;
}

void
set_suppress_timestamps(bool suppressed)
{
    suppress_timestamps = suppressed;
}

void
set_machine_readable_output(bool parsable)
{
    machine_readable_output = parsable;
}

void
error_reset(void)
{
    use_syslog = std_redir = false;
    suppress_timestamps = false;
    machine_readable_output = false;
    x_debug_level = 1;
    mute_cutoff = 0;
    mute_count = 0;
    mute_category = 0;
    default_out = OPENVPN_MSG_FP;
    default_err = OPENVPN_MSG_FP;

#ifdef OPENVPN_DEBUG_COMMAND_LINE
    msgfp = fopen(OPENVPN_DEBUG_FILE, "w");
    if (!msgfp)
    {
        openvpn_exit(OPENVPN_EXIT_STATUS_CANNOT_OPEN_DEBUG_FILE); /* exit point */
    }
#else  /* ifdef OPENVPN_DEBUG_COMMAND_LINE */
    msgfp = NULL;
#endif
}

void
errors_to_stderr(void)
{
    default_err = OPENVPN_ERROR_FP;
}

/*
 * Return a file to print messages to before syslog is opened.
 */
FILE *
msg_fp(const unsigned int flags)
{
    FILE *fp = msgfp;
    if (!fp)
    {
        fp = (flags & (M_FATAL|M_USAGE_SMALL)) ? default_err : default_out;
    }
    if (!fp)
    {
        openvpn_exit(OPENVPN_EXIT_STATUS_CANNOT_OPEN_DEBUG_FILE); /* exit point */
    }
    return fp;
}

#define SWAP { tmp = m1; m1 = m2; m2 = tmp; }

int x_msg_line_num; /* GLOBAL */

void
x_msg(const unsigned int flags, const char *format, ...)
{
    va_list arglist;
    va_start(arglist, format);
    x_msg_va(flags, format, arglist);
    va_end(arglist);
}

void
x_msg_va(const unsigned int flags, const char *format, va_list arglist)
{
    struct gc_arena gc;
#if SYSLOG_CAPABILITY
    int level;
#endif
    char *m1;
    char *m2;
    char *tmp;
    int e;
    const char *prefix;
    const char *prefix_sep;

    void usage_small(void);

#ifndef HAVE_VARARG_MACROS
    /* the macro has checked this otherwise */
    if (!msg_test(flags))
    {
        return;
    }
#endif

    e = openvpn_errno();

    /*
     * Apply muting filter.
     */
#ifndef HAVE_VARARG_MACROS
    /* the macro has checked this otherwise */
    if (!dont_mute(flags))
    {
        return;
    }
#endif

    gc_init(&gc);

    m1 = (char *) gc_malloc(ERR_BUF_SIZE, false, &gc);
    m2 = (char *) gc_malloc(ERR_BUF_SIZE, false, &gc);

    vsnprintf(m1, ERR_BUF_SIZE, format, arglist);
    m1[ERR_BUF_SIZE - 1] = 0; /* windows vsnprintf needs this */

    if ((flags & M_ERRNO) && e)
    {
        openvpn_snprintf(m2, ERR_BUF_SIZE, "%s: %s (errno=%d)",
                         m1, strerror(e), e);
        SWAP;
    }

    if (flags & M_OPTERR)
    {
        openvpn_snprintf(m2, ERR_BUF_SIZE, "Options error: %s", m1);
        SWAP;
    }

#if SYSLOG_CAPABILITY
    if (flags & (M_FATAL|M_NONFATAL|M_USAGE_SMALL))
    {
        level = LOG_ERR;
    }
    else if (flags & M_WARN)
    {
        level = LOG_WARNING;
    }
    else
    {
        level = LOG_NOTICE;
    }
#endif

    /* set up client prefix */
    if (flags & M_NOIPREFIX)
    {
        prefix = NULL;
    }
    else
    {
        prefix = msg_get_prefix();
    }
    prefix_sep = " ";
    if (!prefix)
    {
        prefix_sep = prefix = "";
    }

    /* virtual output capability used to copy output to management subsystem */
    if (!forked)
    {
        const struct virtual_output *vo = msg_get_virtual_output();
        if (vo)
        {
            openvpn_snprintf(m2, ERR_BUF_SIZE, "%s%s%s",
                             prefix,
                             prefix_sep,
                             m1);
            virtual_output_print(vo, flags, m2);
        }
    }

    if (!(flags & M_MSG_VIRT_OUT))
    {
        if (use_syslog && !std_redir && !forked)
        {
#if SYSLOG_CAPABILITY
            syslog(level, "%s%s%s",
                   prefix,
                   prefix_sep,
                   m1);
#endif
        }
        else
        {
            FILE *fp = msg_fp(flags);
            const bool show_usec = check_debug_level(DEBUG_LEVEL_USEC_TIME);

            if (machine_readable_output)
            {
                struct timeval tv;
                gettimeofday(&tv, NULL);

                fprintf(fp, "%" PRIi64 ".%06ld %x %s%s%s%s",
                        (int64_t)tv.tv_sec,
                        (long)tv.tv_usec,
                        flags,
                        prefix,
                        prefix_sep,
                        m1,
                        "\n");

            }
            else if ((flags & M_NOPREFIX) || suppress_timestamps)
            {
                fprintf(fp, "%s%s%s%s",
                        prefix,
                        prefix_sep,
                        m1,
                        (flags&M_NOLF) ? "" : "\n");
            }
            else
            {
                fprintf(fp, "%s %s%s%s%s",
                        time_string(0, 0, show_usec, &gc),
                        prefix,
                        prefix_sep,
                        m1,
                        (flags&M_NOLF) ? "" : "\n");
            }
            fflush(fp);
            ++x_msg_line_num;
        }
    }

    if (flags & M_FATAL)
    {
        msg(M_INFO, "Exiting due to fatal error");
    }

    if (flags & M_FATAL)
    {
        openvpn_exit(OPENVPN_EXIT_STATUS_ERROR); /* exit point */

    }
    if (flags & M_USAGE_SMALL)
    {
        usage_small();
    }

    gc_free(&gc);
}

/*
 * Apply muting filter.
 */
bool
dont_mute(unsigned int flags)
{
    bool ret = true;
    if (mute_cutoff > 0 && !(flags & M_NOMUTE))
    {
        const int mute_level = DECODE_MUTE_LEVEL(flags);
        if (mute_level > 0 && mute_level == mute_category)
        {
            if (mute_count == mute_cutoff)
            {
                msg(M_INFO | M_NOMUTE, "NOTE: --mute triggered...");
            }
            if (++mute_count > mute_cutoff)
            {
                ret = false;
            }
        }
        else
        {
            const int suppressed = mute_count - mute_cutoff;
            if (suppressed > 0)
            {
                msg(M_INFO | M_NOMUTE,
                    "%d variation(s) on previous %d message(s) suppressed by --mute",
                    suppressed,
                    mute_cutoff);
            }
            mute_count = 1;
            mute_category = mute_level;
        }
    }
    return ret;
}

void
assert_failed(const char *filename, int line, const char *condition)
{
    if (condition)
    {
        msg(M_FATAL, "Assertion failed at %s:%d (%s)", filename, line, condition);
    }
    else
    {
        msg(M_FATAL, "Assertion failed at %s:%d", filename, line);
    }
    _exit(1);
}

/*
 * Fail memory allocation.  Don't use msg() because it tries
 * to allocate memory as part of its operation.
 */
void
out_of_memory(void)
{
    fprintf(stderr, PACKAGE_NAME ": Out of Memory\n");
    exit(1);
}

void
open_syslog(const char *pgmname, bool stdio_to_null)
{
#if SYSLOG_CAPABILITY
    if (!msgfp && !std_redir)
    {
        if (!use_syslog)
        {
            pgmname_syslog = string_alloc(pgmname ? pgmname : PACKAGE, NULL);
            openlog(pgmname_syslog, LOG_PID, LOG_OPENVPN);
            use_syslog = true;

            /* Better idea: somehow pipe stdout/stderr output to msg() */
            if (stdio_to_null)
            {
                set_std_files_to_null(false);
            }
        }
    }
#else  /* if SYSLOG_CAPABILITY */
    msg(M_WARN, "Warning on use of --daemon/--inetd: this operating system lacks daemon logging features, therefore when I become a daemon, I won't be able to log status or error messages");
#endif
}

void
close_syslog(void)
{
#if SYSLOG_CAPABILITY
    if (use_syslog)
    {
        closelog();
        use_syslog = false;
        if (pgmname_syslog)
        {
            free(pgmname_syslog);
            pgmname_syslog = NULL;
        }
    }
#endif
}

#ifdef _WIN32
static int orig_stderr;

int get_orig_stderr()
{
    return orig_stderr ? orig_stderr : _fileno(stderr);
}
#endif

void
redirect_stdout_stderr(const char *file, bool append)
{
#if defined(_WIN32)
    if (!std_redir)
    {
        struct gc_arena gc = gc_new();
        HANDLE log_handle;
        int log_fd;

        SECURITY_ATTRIBUTES saAttr;
        saAttr.nLength = sizeof(SECURITY_ATTRIBUTES);
        saAttr.bInheritHandle = TRUE;
        saAttr.lpSecurityDescriptor = NULL;

        log_handle = CreateFileW(wide_string(file, &gc),
                                 GENERIC_WRITE,
                                 FILE_SHARE_READ,
                                 &saAttr,
                                 append ? OPEN_ALWAYS : CREATE_ALWAYS,
                                 FILE_ATTRIBUTE_NORMAL,
                                 NULL);

        gc_free(&gc);

        if (log_handle == INVALID_HANDLE_VALUE)
        {
            msg(M_WARN|M_ERRNO, "Warning: cannot open --log file: %s", file);
            return;
        }

        /* append to logfile? */
        if (append)
        {
            if (SetFilePointer(log_handle, 0, NULL, FILE_END) == INVALID_SET_FILE_POINTER)
            {
                msg(M_ERR, "Error: cannot seek to end of --log file: %s", file);
            }
        }

        /* save original stderr for password prompts */
        orig_stderr = _dup(_fileno(stderr));
        if (orig_stderr == -1)
        {
            msg(M_WARN | M_ERRNO, "Warning: cannot duplicate stderr, password prompts will appear in log file instead of console.");
            orig_stderr = _fileno(stderr);
        }

        /* direct stdout/stderr to point to log_handle */
        log_fd = _open_osfhandle((intptr_t)log_handle, _O_TEXT);
        if (log_fd == -1)
        {
            msg(M_ERR, "Error: --log redirect failed due to _open_osfhandle failure");
        }

        /* open log_handle as FILE stream */
        ASSERT(msgfp == NULL);
        msgfp = _fdopen(log_fd, "wt");
        if (msgfp == NULL)
        {
            msg(M_ERR, "Error: --log redirect failed due to _fdopen");
        }

        /* redirect C-library stdout/stderr to log file */
        if (_dup2(log_fd, 1) == -1 || _dup2(log_fd, 2) == -1)
        {
            msg(M_WARN, "Error: --log redirect of stdout/stderr failed");
        }

        std_redir = true;
    }
#elif defined(HAVE_DUP2)
    if (!std_redir)
    {
        int out = open(file,
                       O_CREAT | O_WRONLY | (append ? O_APPEND : O_TRUNC),
                       S_IRUSR | S_IWUSR);

        if (out < 0)
        {
            msg(M_WARN|M_ERRNO, "Warning: Error redirecting stdout/stderr to --log file: %s", file);
            return;
        }

        if (dup2(out, 1) == -1)
        {
            msg(M_ERR, "--log file redirection error on stdout");
        }
        if (dup2(out, 2) == -1)
        {
            msg(M_ERR, "--log file redirection error on stderr");
        }

        if (out > 2)
        {
            close(out);
        }

        std_redir = true;
    }

#else  /* if defined(_WIN32) */
    msg(M_WARN, "WARNING: The --log option is not supported on this OS because it lacks the dup2 function");
#endif /* if defined(_WIN32) */
}

/*
 * Functions used to check return status
 * of I/O operations.
 */

unsigned int x_cs_info_level;    /* GLOBAL */
unsigned int x_cs_verbose_level; /* GLOBAL */
unsigned int x_cs_err_delay_ms;  /* GLOBAL */

void
reset_check_status(void)
{
    x_cs_info_level = 0;
    x_cs_verbose_level = 0;
}

void
set_check_status(unsigned int info_level, unsigned int verbose_level)
{
    x_cs_info_level = info_level;
    x_cs_verbose_level = verbose_level;
}

/*
 * Called after most socket or tun/tap operations, via the inline
 * function check_status().
 *
 * Decide if we should print an error message, and see if we can
 * extract any useful info from the error, such as a Path MTU hint
 * from the OS.
 */
void
x_check_status(int status,
               const char *description,
               struct link_socket *sock,
               struct tuntap *tt)
{
    const int my_errno = openvpn_errno();
    const char *extended_msg = NULL;

    msg(x_cs_verbose_level, "%s %s returned %d",
        sock ? proto2ascii(sock->info.proto, sock->info.af, true) : "",
        description,
        status);

    if (status < 0)
    {
        struct gc_arena gc = gc_new();
#if EXTENDED_SOCKET_ERROR_CAPABILITY
        /* get extended socket error message and possible PMTU hint from OS */
        if (sock)
        {
            int mtu;
            extended_msg = format_extended_socket_error(sock->sd, &mtu, &gc);
            if (mtu > 0 && sock->mtu != mtu)
            {
                sock->mtu = mtu;
                sock->info.mtu_changed = true;
            }
        }
#elif defined(_WIN32)
        /* get possible driver error from TAP-Windows driver */
        if (tuntap_defined(tt))
        {
            extended_msg = tap_win_getinfo(tt, &gc);
        }
#endif
        if (!ignore_sys_error(my_errno))
        {
            if (extended_msg)
            {
                msg(x_cs_info_level, "%s %s [%s]: %s (code=%d)", description,
                    sock ? proto2ascii(sock->info.proto, sock->info.af, true) : "",
                    extended_msg, strerror(my_errno), my_errno);
            }
            else
            {
                msg(x_cs_info_level, "%s %s: %s (code=%d)", description,
                    sock ? proto2ascii(sock->info.proto, sock->info.af, true) : "",
                    strerror(my_errno), my_errno);
            }

            if (x_cs_err_delay_ms)
            {
                platform_sleep_milliseconds(x_cs_err_delay_ms);
            }
        }
        gc_free(&gc);
    }
}

/*
 * In multiclient mode, put a client-specific prefix
 * before each message.
 */
const char *x_msg_prefix; /* GLOBAL */

/*
 * Allow MSG to be redirected through a virtual_output object
 */

const struct virtual_output *x_msg_virtual_output; /* GLOBAL */

/*
 * Exiting.
 */

void
openvpn_exit(const int status)
{
    if (!forked)
    {
        tun_abort();

#ifdef _WIN32
        uninit_win32();
#endif
        remove_pid_file();

        close_syslog();

#ifdef ENABLE_PLUGIN
        plugin_abort();
#endif

#if PORT_SHARE
        if (port_share)
        {
            port_share_abort(port_share);
        }
#endif

#ifdef ENABLE_MEMSTATS
        mstats_close();
#endif

#ifdef ABORT_ON_ERROR
        if (status == OPENVPN_EXIT_STATUS_ERROR)
        {
            abort();
        }
#endif

        if (status == OPENVPN_EXIT_STATUS_GOOD)
        {
            perf_output_results();
        }
    }

    exit(status);
}

/*
 * Translate msg flags into a string
 */
const char *
msg_flags_string(const unsigned int flags, struct gc_arena *gc)
{
    struct buffer out = alloc_buf_gc(16, gc);
    if (flags == M_INFO)
    {
        buf_printf(&out, "I");
    }
    if (flags & M_FATAL)
    {
        buf_printf(&out, "F");
    }
    if (flags & M_NONFATAL)
    {
        buf_printf(&out, "N");
    }
    if (flags & M_WARN)
    {
        buf_printf(&out, "W");
    }
    if (flags & M_DEBUG)
    {
        buf_printf(&out, "D");
    }
    return BSTR(&out);
}

#ifdef ENABLE_DEBUG
void
crash(void)
{
    char *null = NULL;
    *null = 0;
}
#endif

#ifdef _WIN32

const char *
strerror_win32(DWORD errnum, struct gc_arena *gc)
{
    /*
     * This code can be omitted, though often the Windows
     * WSA error messages are less informative than the
     * Posix equivalents.
     */
#if 1
    switch (errnum)
    {
        /*
         * When the TAP-Windows driver returns STATUS_UNSUCCESSFUL, this code
         * gets returned to user space.
         */
        case ERROR_GEN_FAILURE:
            return "General failure (ERROR_GEN_FAILURE)";

        case ERROR_IO_PENDING:
            return "I/O Operation in progress (ERROR_IO_PENDING)";

        case WSA_IO_INCOMPLETE:
            return "I/O Operation in progress (WSA_IO_INCOMPLETE)";

        case WSAEINTR:
            return "Interrupted system call (WSAEINTR)";

        case WSAEBADF:
            return "Bad file number (WSAEBADF)";

        case WSAEACCES:
            return "Permission denied (WSAEACCES)";

        case WSAEFAULT:
            return "Bad address (WSAEFAULT)";

        case WSAEINVAL:
            return "Invalid argument (WSAEINVAL)";

        case WSAEMFILE:
            return "Too many open files (WSAEMFILE)";

        case WSAEWOULDBLOCK:
            return "Operation would block (WSAEWOULDBLOCK)";

        case WSAEINPROGRESS:
            return "Operation now in progress (WSAEINPROGRESS)";

        case WSAEALREADY:
            return "Operation already in progress (WSAEALREADY)";

        case WSAEDESTADDRREQ:
            return "Destination address required (WSAEDESTADDRREQ)";

        case WSAEMSGSIZE:
            return "Message too long (WSAEMSGSIZE)";

        case WSAEPROTOTYPE:
            return "Protocol wrong type for socket (WSAEPROTOTYPE)";

        case WSAENOPROTOOPT:
            return "Bad protocol option (WSAENOPROTOOPT)";

        case WSAEPROTONOSUPPORT:
            return "Protocol not supported (WSAEPROTONOSUPPORT)";

        case WSAESOCKTNOSUPPORT:
            return "Socket type not supported (WSAESOCKTNOSUPPORT)";

        case WSAEOPNOTSUPP:
            return "Operation not supported on socket (WSAEOPNOTSUPP)";

        case WSAEPFNOSUPPORT:
            return "Protocol family not supported (WSAEPFNOSUPPORT)";

        case WSAEAFNOSUPPORT:
            return "Address family not supported by protocol family (WSAEAFNOSUPPORT)";

        case WSAEADDRINUSE:
            return "Address already in use (WSAEADDRINUSE)";

        case WSAENETDOWN:
            return "Network is down (WSAENETDOWN)";

        case WSAENETUNREACH:
            return "Network is unreachable (WSAENETUNREACH)";

        case WSAENETRESET:
            return "Net dropped connection or reset (WSAENETRESET)";

        case WSAECONNABORTED:
            return "Software caused connection abort (WSAECONNABORTED)";

        case WSAECONNRESET:
            return "Connection reset by peer (WSAECONNRESET)";

        case WSAENOBUFS:
            return "No buffer space available (WSAENOBUFS)";

        case WSAEISCONN:
            return "Socket is already connected (WSAEISCONN)";

        case WSAENOTCONN:
            return "Socket is not connected (WSAENOTCONN)";

        case WSAETIMEDOUT:
            return "Connection timed out (WSAETIMEDOUT)";

        case WSAECONNREFUSED:
            return "Connection refused (WSAECONNREFUSED)";

        case WSAELOOP:
            return "Too many levels of symbolic links (WSAELOOP)";

        case WSAENAMETOOLONG:
            return "File name too long (WSAENAMETOOLONG)";

        case WSAEHOSTDOWN:
            return "Host is down (WSAEHOSTDOWN)";

        case WSAEHOSTUNREACH:
            return "No Route to Host (WSAEHOSTUNREACH)";

        case WSAENOTEMPTY:
            return "Directory not empty (WSAENOTEMPTY)";

        case WSAEPROCLIM:
            return "Too many processes (WSAEPROCLIM)";

        case WSAEUSERS:
            return "Too many users (WSAEUSERS)";

        case WSAEDQUOT:
            return "Disc Quota Exceeded (WSAEDQUOT)";

        case WSAESTALE:
            return "Stale NFS file handle (WSAESTALE)";

        case WSASYSNOTREADY:
            return "Network SubSystem is unavailable (WSASYSNOTREADY)";

        case WSAVERNOTSUPPORTED:
            return "WINSOCK DLL Version out of range (WSAVERNOTSUPPORTED)";

        case WSANOTINITIALISED:
            return "Successful WSASTARTUP not yet performed (WSANOTINITIALISED)";

        case WSAEREMOTE:
            return "Too many levels of remote in path (WSAEREMOTE)";

        case WSAHOST_NOT_FOUND:
            return "Host not found (WSAHOST_NOT_FOUND)";

        default:
            break;
    }
#endif /* if 1 */

    /* format a windows error message */
    {
        char message[256];
        struct buffer out = alloc_buf_gc(256, gc);
        const int status =  FormatMessage(
            FORMAT_MESSAGE_IGNORE_INSERTS
            | FORMAT_MESSAGE_FROM_SYSTEM
            | FORMAT_MESSAGE_ARGUMENT_ARRAY,
            NULL,
            errnum,
            0,
            message,
            sizeof(message),
            NULL);
        if (!status)
        {
            buf_printf(&out, "[Unknown Win32 Error]");
        }
        else
        {
            char *cp;
            for (cp = message; *cp != '\0'; ++cp)
            {
                if (*cp == '\n' || *cp == '\r')
                {
                    *cp = ' ';
                }
            }

            buf_printf(&out, "%s", message);
        }

        return BSTR(&out);
    }
}

#endif /* ifdef _WIN32 */
