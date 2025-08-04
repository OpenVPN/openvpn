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
 *  with this program; if not, see <https://www.gnu.org/licenses/>.
 */

#ifndef COMPAT_H
#define COMPAT_H

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#endif

#ifdef HAVE_SYS_TIME_H
#include <sys/time.h>
#endif

#ifdef HAVE_SYS_SOCKET_H
#include <sys/socket.h>
#endif

#ifndef HAVE_DIRNAME
char *dirname(char *str);

#endif /* HAVE_DIRNAME */

#ifndef HAVE_BASENAME
char *basename(char *str);

#endif /* HAVE_BASENAME */

#ifndef HAVE_GETTIMEOFDAY
int gettimeofday(struct timeval *tv, void *tz);

#endif

#ifndef HAVE_DAEMON
int daemon(int nochdir, int noclose);

#endif

#ifndef HAVE_STRSEP
char *strsep(char **stringp, const char *delim);

#endif

#endif /* COMPAT_H */
