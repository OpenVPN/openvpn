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

#ifndef PLATFORM_H
#define PLATFORM_H

#ifdef HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif

#ifdef HAVE_SYS_STAT_H
#include <sys/stat.h>
#endif

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

#ifdef HAVE_PWD_H
#include <pwd.h>
#endif

#ifdef HAVE_GRP_H
#include <grp.h>
#endif

#ifdef HAVE_STDIO_H
#include <stdio.h>
#endif

#include "basic.h"
#include "buffer.h"

/* Get/Set UID of process */

struct platform_state_user {
#if defined(HAVE_GETPWNAM) && defined(HAVE_SETUID)
    const char *username;
    struct passwd *pw;
#else
    int dummy;
#endif
};

/* Get/Set GID of process */

struct platform_state_group {
#if defined(HAVE_GETGRNAM) && defined(HAVE_SETGID)
    const char *groupname;
    struct group *gr;
#else
    int dummy;
#endif
};

bool platform_user_get(const char *username, struct platform_state_user *state);

void platform_user_set(const struct platform_state_user *state);

bool platform_group_get(const char *groupname, struct platform_state_group *state);

void platform_group_set(const struct platform_state_group *state);

/*
 * Extract UID or GID
 */

static inline int
platform_state_user_uid(const struct platform_state_user *s)
{
#if defined(HAVE_GETPWNAM) && defined(HAVE_SETUID)
    if (s->pw)
    {
        return s->pw->pw_uid;
    }
#endif
    return -1;
}

static inline int
platform_state_group_gid(const struct platform_state_group *s)
{
#if defined(HAVE_GETGRNAM) && defined(HAVE_SETGID)
    if (s->gr)
    {
        return s->gr->gr_gid;
    }
#endif
    return -1;
}

void platform_chroot(const char *path);

void platform_nice(int niceval);

unsigned int platform_getpid(void);

void platform_mlockall(bool print_msg);  /* Disable paging */

int platform_chdir(const char *dir);

/* interpret the status code returned by execve() */
bool platform_system_ok(int stat);

int platform_access(const char *path, int mode);

void platform_sleep_milliseconds(unsigned int n);

void platform_sleep_until_signal(void);

/* delete a file, return true if succeeded */
bool platform_unlink(const char *filename);

int platform_putenv(char *string);

FILE *platform_fopen(const char *path, const char *mode);

int platform_open(const char *path, int flags, int mode);

#ifdef _WIN32
typedef struct _stat platform_stat_t;
#else
typedef struct stat platform_stat_t;
#endif
int platform_stat(const char *path, platform_stat_t *buf);

/**
 * Create a temporary file in directory, returns the filename of the created
 * file.
 */
const char *platform_create_temp_file(const char *directory, const char *prefix,
                                      struct gc_arena *gc);

/** Put a directory and filename together. */
const char *platform_gen_path(const char *directory, const char *filename,
                              struct gc_arena *gc);

/** Return true if pathname is absolute. */
bool platform_absolute_pathname(const char *pathname);

/** Return true if filename can be opened for read. */
bool platform_test_file(const char *filename);

#endif /* ifndef PLATFORM_H */
