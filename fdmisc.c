/*
 *  OpenVPN -- An application to securely tunnel IP networks
 *             over a single UDP port, with support for SSL/TLS-based
 *             session authentication and key exchange,
 *             packet encryption, packet authentication, and
 *             packet compression.
 *
 *  Copyright (C) 2002-2005 OpenVPN Solutions LLC <info@openvpn.net>
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
 *  You should have received a copy of the GNU General Public License
 *  along with this program (see the file COPYING included with this
 *  distribution); if not, write to the Free Software Foundation, Inc.,
 *  59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

#ifdef WIN32
#include "config-win32.h"
#else
#include "config.h"
#endif

#include "syshead.h"

#include "fdmisc.h"
#include "error.h"

#include "memdbg.h"

/* Set a file descriptor to non-blocking */
void
set_nonblock (int fd)
{
#ifdef WIN32
  u_long arg = 1;
  if (ioctlsocket (fd, FIONBIO, &arg))
    msg (M_SOCKERR, "Set socket to non-blocking mode failed");
#else
  if (fcntl (fd, F_SETFL, O_NONBLOCK) < 0)
    msg (M_ERR, "Set file descriptor to non-blocking mode failed");
#endif
}

/* Set a file descriptor to not be passed across execs */
void
set_cloexec (int fd)
{
#ifndef WIN32
  if (fcntl (fd, F_SETFD, FD_CLOEXEC) < 0)
    msg (M_ERR, "Set FD_CLOEXEC flag on file descriptor failed");
#endif
}
