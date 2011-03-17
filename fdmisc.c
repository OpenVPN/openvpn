/*
 *  OpenVPN -- An application to securely tunnel IP networks
 *             over a single UDP port, with support for SSL/TLS-based
 *             session authentication and key exchange,
 *             packet encryption, packet authentication, and
 *             packet compression.
 *
 *  Copyright (C) 2002-2010 OpenVPN Technologies, Inc. <sales@openvpn.net>
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

#include "syshead.h"

#include "fdmisc.h"
#include "error.h"

#include "memdbg.h"

/* Set a file descriptor to non-blocking */
bool
set_nonblock_action (int fd)
{
#ifdef WIN32
  u_long arg = 1;
  if (ioctlsocket (fd, FIONBIO, &arg))
    return false;
#else
  if (fcntl (fd, F_SETFL, O_NONBLOCK) < 0)
    return false;
#endif
  return true;
}

/* Set a file descriptor to not be passed across execs */
bool
set_cloexec_action (int fd)
{
#ifndef WIN32
  if (fcntl (fd, F_SETFD, FD_CLOEXEC) < 0)
    return false;
#endif
  return true;
}

/* Set a file descriptor to non-blocking */
void
set_nonblock (int fd)
{
  if (!set_nonblock_action (fd))
    msg (M_SOCKERR, "Set socket to non-blocking mode failed");
}

/* Set a file descriptor to not be passed across execs */
void
set_cloexec (int fd)
{
  if (!set_cloexec_action (fd))
    msg (M_ERR, "Set FD_CLOEXEC flag on file descriptor failed");
}
