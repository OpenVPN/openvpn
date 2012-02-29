/*
 *  OpenVPN -- An application to securely tunnel IP networks
 *             over a single TCP/UDP port, with support for SSL/TLS-based
 *             session authentication and key exchange,
 *             packet encryption, packet authentication, and
 *             packet compression.
 *
 *  Copyright (C) 2002-2011 OpenVPN Technologies, Inc. <sales@openvpn.net>
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

/*
 * Maintain usage stats in a memory-mapped file
 */

#if !defined(OPENVPN_MEMSTATS_H) && defined(ENABLE_MEMSTATS)
#define OPENVPN_MEMSTATS_H

#include "basic.h"

/* this struct is mapped to the file */
struct mmap_stats {
  counter_type link_read_bytes;   /* counter_type can be assumed to be a uint64_t */
  counter_type link_write_bytes;
  int n_clients;

# define MSTATS_UNDEF   0
# define MSTATS_ACTIVE  1
# define MSTATS_EXPIRED 2
  int state;
};

extern volatile struct mmap_stats *mmap_stats; /* GLOBAL */

void mstats_open(const char *fn);
void mstats_close(void);

#endif
