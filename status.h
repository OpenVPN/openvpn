/*
 *  OpenVPN -- An application to securely tunnel IP networks
 *             over a single TCP/UDP port, with support for SSL/TLS-based
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

#ifndef STATUS_H
#define STATUS_H

#include "interval.h"

/*
 * virtual function interface for status output
 */
struct virtual_output {
  void *arg;
  unsigned int flags_default;
  void (*func) (void *arg, const unsigned int flags, const char *str);
};

static inline void
virtual_output_print (const struct virtual_output *vo, const unsigned int flags, const char *str)
{
  (*vo->func) (vo->arg, flags, str);
}

/*
 * printf-style interface for inputting/outputting status info
 */

struct status_output
{
# define STATUS_OUTPUT_READ  (1<<0)
# define STATUS_OUTPUT_WRITE (1<<1)
  unsigned int flags;

  char *filename;
  int fd;
  int msglevel;
  const struct virtual_output *vout;

  struct buffer read_buf;

  struct event_timeout et;

  bool errors;
};

struct status_output *status_open (const char *filename,
				   const int refresh_freq,
				   const int msglevel,
				   const struct virtual_output *vout,
				   const unsigned int flags);

bool status_trigger_tv (struct status_output *so, struct timeval *tv);
bool status_trigger (struct status_output *so);
void status_reset (struct status_output *so);
void status_flush (struct status_output *so);
bool status_close (struct status_output *so);
void status_printf (struct status_output *so, const char *format, ...)
#ifdef __GNUC__
    __attribute__ ((format (printf, 2, 3)))
#endif
    ;

bool status_read (struct status_output *so, struct buffer *buf);

static inline unsigned int
status_rw_flags (const struct status_output *so)
{
  if (so)
    return so->flags;
  else
    return 0;
}

#endif
