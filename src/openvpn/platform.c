/*
 *  OpenVPN -- An application to securely tunnel IP networks
 *             over a single TCP/UDP port, with support for SSL/TLS-based
 *             session authentication and key exchange,
 *             packet encryption, packet authentication, and
 *             packet compression.
 *
 *  Copyright (C) 2002-2022 OpenVPN Inc <sales@openvpn.net>
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

#include "buffer.h"
#include "crypto.h"
#include "error.h"
#include "misc.h"
#include "win32.h"

#include "memdbg.h"

#include "platform.h"

/* Redefine the top level directory of the filesystem
 * to restrict access to files for security */
void
platform_chroot(const char *path)
{
    if (path)
    {
#ifdef HAVE_CHROOT
        const char *top = "/";
        if (chroot(path))
        {
            msg(M_ERR, "chroot to '%s' failed", path);
        }
        if (platform_chdir(top))
        {
            msg(M_ERR, "cd to '%s' failed", top);
        }
        msg(M_INFO, "chroot to '%s' and cd to '%s' succeeded", path, top);
#else  /* ifdef HAVE_CHROOT */
        msg(M_FATAL, "Sorry but I can't chroot to '%s' because this operating system doesn't appear to support the chroot() system call", path);
#endif
    }
}

/* Get/Set UID of process */

bool
platform_user_get(const char *username, struct platform_state_user *state)
{
    bool ret = false;
    CLEAR(*state);
    if (username)
    {
#if defined(HAVE_GETPWNAM) && defined(HAVE_SETUID)
        state->pw = getpwnam(username);
        if (!state->pw)
        {
            msg(M_ERR, "failed to find UID for user %s", username);
        }
        state->username = username;
        ret = true;
#else  /* if defined(HAVE_GETPWNAM) && defined(HAVE_SETUID) */
        msg(M_FATAL, "cannot get UID for user %s -- platform lacks getpwname() or setuid() system calls", username);
#endif
    }
    return ret;
}

void
platform_user_set(const struct platform_state_user *state)
{
#if defined(HAVE_GETPWNAM) && defined(HAVE_SETUID)
    if (state->username && state->pw)
    {
        if (setuid(state->pw->pw_uid))
        {
            msg(M_ERR, "setuid('%s') failed", state->username);
        }
        msg(M_INFO, "UID set to %s", state->username);
    }
#endif
}

/* Get/Set GID of process */

bool
platform_group_get(const char *groupname, struct platform_state_group *state)
{
    bool ret = false;
    CLEAR(*state);
    if (groupname)
    {
#if defined(HAVE_GETGRNAM) && defined(HAVE_SETGID)
        state->gr = getgrnam(groupname);
        if (!state->gr)
        {
            msg(M_ERR, "failed to find GID for group %s", groupname);
        }
        state->groupname = groupname;
        ret = true;
#else  /* if defined(HAVE_GETGRNAM) && defined(HAVE_SETGID) */
        msg(M_FATAL, "cannot get GID for group %s -- platform lacks getgrnam() or setgid() system calls", groupname);
#endif
    }
    return ret;
}

void
platform_group_set(const struct platform_state_group *state)
{
#if defined(HAVE_GETGRNAM) && defined(HAVE_SETGID)
    if (state->groupname && state->gr)
    {
        if (setgid(state->gr->gr_gid))
        {
            msg(M_ERR, "setgid('%s') failed", state->groupname);
        }
        msg(M_INFO, "GID set to %s", state->groupname);
#ifdef HAVE_SETGROUPS
        {
            gid_t gr_list[1];
            gr_list[0] = state->gr->gr_gid;
            if (setgroups(1, gr_list))
            {
                msg(M_ERR, "setgroups('%s') failed", state->groupname);
            }
        }
#endif
    }
#endif
}

/* Change process priority */
void
platform_nice(int niceval)
{
    if (niceval)
    {
#ifdef HAVE_NICE
        errno = 0;
        if (nice(niceval) < 0 && errno != 0)
        {
            msg(M_WARN | M_ERRNO, "WARNING: nice %d failed", niceval);
        }
        else
        {
            msg(M_INFO, "nice %d succeeded", niceval);
        }
#else  /* ifdef HAVE_NICE */
        msg(M_WARN, "WARNING: nice %d failed (function not implemented)", niceval);
#endif
    }
}

/* Get current PID */
unsigned int
platform_getpid(void)
{
#ifdef _WIN32
    return (unsigned int) GetCurrentProcessId();
#else
#ifdef HAVE_GETPID
    return (unsigned int) getpid();
#else
    return 0;
#endif
#endif
}

/* Disable paging */
void
platform_mlockall(bool print_msg)
{
#ifdef HAVE_MLOCKALL
    if (mlockall(MCL_CURRENT | MCL_FUTURE))
    {
        msg(M_WARN | M_ERRNO, "WARNING: mlockall call failed");
    }
    else if (print_msg)
    {
        msg(M_INFO, "mlockall call succeeded");
    }
#else  /* ifdef HAVE_MLOCKALL */
    msg(M_WARN, "WARNING: mlockall call failed (function not implemented)");
#endif
}

/*
 * Wrapper for chdir library function
 */
int
platform_chdir(const char *dir)
{
#ifdef HAVE_CHDIR
#ifdef _WIN32
    int res;
    struct gc_arena gc = gc_new();
    res = _wchdir(wide_string(dir, &gc));
    gc_free(&gc);
    return res;
#else  /* ifdef _WIN32 */
    return chdir(dir);
#endif
#else  /* ifdef HAVE_CHDIR */
    return -1;
#endif
}

/*
 * convert execve() return into a success/failure value
 */
bool
platform_system_ok(int stat)
{
#ifdef _WIN32
    return stat == 0;
#else
    return stat != -1 && WIFEXITED(stat) && WEXITSTATUS(stat) == 0;
#endif
}

int
platform_access(const char *path, int mode)
{
#ifdef _WIN32
    struct gc_arena gc = gc_new();
    int ret = _waccess(wide_string(path, &gc), mode & ~X_OK);
    gc_free(&gc);
    return ret;
#else
    return access(path, mode);
#endif
}

/*
 * Go to sleep for n milliseconds.
 */
void
platform_sleep_milliseconds(unsigned int n)
{
#ifdef _WIN32
    Sleep(n);
#else
    struct timeval tv;
    tv.tv_sec = n / 1000;
    tv.tv_usec = (n % 1000) * 1000;
    select(0, NULL, NULL, NULL, &tv);
#endif
}

/*
 * Go to sleep indefinitely.
 */
void
platform_sleep_until_signal(void)
{
#ifdef _WIN32
    ASSERT(0);
#else
    select(0, NULL, NULL, NULL, NULL);
#endif
}

/* delete a file, return true if succeeded */
bool
platform_unlink(const char *filename)
{
#if defined(_WIN32)
    struct gc_arena gc = gc_new();
    BOOL ret = DeleteFileW(wide_string(filename, &gc));
    gc_free(&gc);
    return (ret != 0);
#elif defined(HAVE_UNLINK)
    return (unlink(filename) == 0);
#else  /* if defined(_WIN32) */
    return false;
#endif
}

FILE *
platform_fopen(const char *path, const char *mode)
{
#ifdef _WIN32
    struct gc_arena gc = gc_new();
    FILE *f = _wfopen(wide_string(path, &gc), wide_string(mode, &gc));
    gc_free(&gc);
    return f;
#else
    return fopen(path, mode);
#endif
}

int
platform_open(const char *path, int flags, int mode)
{
#ifdef _WIN32
    struct gc_arena gc = gc_new();
    int fd = _wopen(wide_string(path, &gc), flags, mode);
    gc_free(&gc);
    return fd;
#else
    return open(path, flags, mode);
#endif
}

int
platform_stat(const char *path, platform_stat_t *buf)
{
#ifdef _WIN32
    struct gc_arena gc = gc_new();
    int res = _wstat(wide_string(path, &gc), buf);
    gc_free(&gc);
    return res;
#else
    return stat(path, buf);
#endif
}

/* create a temporary filename in directory */
const char *
platform_create_temp_file(const char *directory, const char *prefix, struct gc_arena *gc)
{
    int fd;
    const char *retfname = NULL;
    unsigned int attempts = 0;
    char fname[256] = { 0 };
    const char *fname_fmt = PACKAGE "_%.*s_%08lx%08lx.tmp";
    const int max_prefix_len = sizeof(fname) - (sizeof(PACKAGE) + 7 + (2 * 8));

    while (attempts < 6)
    {
        ++attempts;

        if (!openvpn_snprintf(fname, sizeof(fname), fname_fmt, max_prefix_len,
                              prefix, (unsigned long) get_random(),
                              (unsigned long) get_random()))
        {
            msg(M_WARN, "ERROR: temporary filename too long");
            return NULL;
        }

        retfname = platform_gen_path(directory, fname, gc);
        if (!retfname)
        {
            msg(M_WARN, "Failed to create temporary filename and path");
            return NULL;
        }

        /* Atomically create the file.  Errors out if the file already
         * exists.  */
        fd = platform_open(retfname, O_CREAT | O_EXCL | O_WRONLY, S_IRUSR | S_IWUSR);
        if (fd != -1)
        {
            close(fd);
            return retfname;
        }
        else if (fd == -1 && errno != EEXIST)
        {
            /* Something else went wrong, no need to retry.  */
            msg(M_WARN | M_ERRNO, "Could not create temporary file '%s'",
                retfname);
            return NULL;
        }
    }

    msg(M_WARN, "Failed to create temporary file after %i attempts", attempts);
    return NULL;
}

/*
 * Put a directory and filename together.
 */
const char *
platform_gen_path(const char *directory, const char *filename,
                  struct gc_arena *gc)
{
#ifdef _WIN32
    const int CC_PATH_RESERVED = CC_LESS_THAN|CC_GREATER_THAN|CC_COLON
                                 |CC_DOUBLE_QUOTE|CC_SLASH|CC_BACKSLASH|CC_PIPE|CC_QUESTION_MARK|CC_ASTERISK;
#else
    const int CC_PATH_RESERVED = CC_SLASH;
#endif

    if (!gc)
    {
        return NULL; /* Would leak memory otherwise */
    }

    const char *safe_filename = string_mod_const(filename, CC_PRINT, CC_PATH_RESERVED, '_', gc);

    if (safe_filename
        && strcmp(safe_filename, ".")
        && strcmp(safe_filename, "..")
#ifdef _WIN32
        && win_safe_filename(safe_filename)
#endif
        )
    {
        const size_t outsize = strlen(safe_filename) + (directory ? strlen(directory) : 0) + 16;
        struct buffer out = alloc_buf_gc(outsize, gc);
        char dirsep[2];

        dirsep[0] = OS_SPECIFIC_DIRSEP;
        dirsep[1] = '\0';

        if (directory)
        {
            buf_printf(&out, "%s%s", directory, dirsep);
        }
        buf_printf(&out, "%s", safe_filename);

        return BSTR(&out);
    }
    else
    {
        return NULL;
    }
}

bool
platform_absolute_pathname(const char *pathname)
{
    if (pathname)
    {
        const int c = pathname[0];
#ifdef _WIN32
        return c == '\\' || (isalpha(c) && pathname[1] == ':' && pathname[2] == '\\');
#else
        return c == '/';
#endif
    }
    else
    {
        return false;
    }
}

/* return true if filename can be opened for read */
bool
platform_test_file(const char *filename)
{
    bool ret = false;
    if (filename)
    {
        FILE *fp = platform_fopen(filename, "r");
        if (fp)
        {
            fclose(fp);
            ret = true;
        }
        else
        {
            if (errno == EACCES)
            {
                msg( M_WARN | M_ERRNO, "Could not access file '%s'", filename);
            }
        }
    }

    dmsg(D_TEST_FILE, "TEST FILE '%s' [%d]",
         filename ? filename : "UNDEF",
         ret);

    return ret;
}
