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

#if !defined(CLINAT_H) && defined(ENABLE_CLIENT_NAT)
#define CLINAT_H

#include "buffer.h"

#define MAX_CLIENT_NAT 64

#define CN_OUTGOING 0
#define CN_INCOMING 1

struct client_nat_entry {
# define CN_SNAT 0
# define CN_DNAT 1
  int type;
  in_addr_t network;
  in_addr_t netmask;
  in_addr_t foreign_network;
};

struct client_nat_option_list {
  int n;
  struct client_nat_entry entries[MAX_CLIENT_NAT];
};

struct client_nat_option_list *new_client_nat_list (struct gc_arena *gc);
struct client_nat_option_list *clone_client_nat_option_list (const struct client_nat_option_list *src, struct gc_arena *gc);
void copy_client_nat_option_list (struct client_nat_option_list *dest, const struct client_nat_option_list *src);
void print_client_nat_list(const struct client_nat_option_list *list, int msglevel);

void add_client_nat_to_option_list (struct client_nat_option_list *dest,
				    const char *type,
				    const char *network,
				    const char *netmask,
				    const char *foreign_network,
				    int msglevel);

void client_nat_transform (const struct client_nat_option_list *list,
			   struct buffer *ipbuf,
			   const int direction);

#endif
