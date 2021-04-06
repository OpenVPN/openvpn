/*
 *  OpenVPN -- An application to securely tunnel IP networks
 *             over a single UDP port, with support for SSL/TLS-based
 *             session authentication and key exchange,
 *             packet encryption, packet authentication, and
 *             packet compression.
 *
 *  Copyright (C) 2011 - David Sommerseth <davids@redhat.com>
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

#ifndef HAVE_DAEMON

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

#include <stdlib.h>

#ifdef HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif

#ifdef HAVE_SYS_STAT_H
#include <sys/stat.h>
#endif

#ifdef HAVE_FCNTL_H
#include <fcntl.h>
#endif

#include <errno.h>

int
daemon(int nochdir, int noclose)
{
#if defined(HAVE_FORK) && defined(HAVE_SETSID)
    switch (fork())
    {
        case -1:
            return (-1);

        case 0:
            break;

        default:
            exit(0);
    }

    if (setsid() == -1)
    {
        return (-1);
    }

    if (!nochdir)
    {
        chdir("/");
    }

    if (!noclose)
    {
#if defined(HAVE_DUP) && defined(HAVE_DUP2)
        int fd;
        if ((fd = open("/dev/null", O_RDWR, 0)) != -1)
        {
            dup2(fd, 0);
            dup2(fd, 1);
            dup2(fd, 2);
            if (fd > 2)
            {
                close(fd);
            }
        }
#endif
    }

    return 0;
#else  /* if defined(HAVE_FORK) && defined(HAVE_SETSID) */
    (void)nochdir;
    (void)noclose;
    errno = EFAULT;
    return -1;
#endif /* if defined(HAVE_FORK) && defined(HAVE_SETSID) */
}

#endif /* ifndef HAVE_DAEMON */

