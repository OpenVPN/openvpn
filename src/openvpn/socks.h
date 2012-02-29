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

/*
 * 2004-01-30: Added Socks5 proxy support
 *   (Christof Meerwald, http://cmeerw.org)
 */

#ifndef SOCKS_H
#define SOCKS_H

#ifdef ENABLE_SOCKS

#include "buffer.h"

struct openvpn_sockaddr;
struct link_socket_actual;

struct socks_proxy_info {
  bool defined;
  bool retry;

  char server[128];
  int port;
  char authfile[256];
};

void socks_adjust_frame_parameters (struct frame *frame, int proto);

struct socks_proxy_info *socks_proxy_new (const char *server,
					  int port,
					  const char *authfile,
					  bool retry,
					  struct auto_proxy_info *auto_proxy_info);

void socks_proxy_close (struct socks_proxy_info *sp);

void establish_socks_proxy_passthru (struct socks_proxy_info *p,
				     socket_descriptor_t sd, /* already open to proxy */
				     const char *host,       /* openvpn server remote */
				     const int port,         /* openvpn server port */
				     volatile int *signal_received);

void establish_socks_proxy_udpassoc (struct socks_proxy_info *p,
				     socket_descriptor_t ctrl_sd, /* already open to proxy */
				     socket_descriptor_t udp_sd,
				     struct openvpn_sockaddr *relay_addr,
				     volatile int *signal_received);

void socks_process_incoming_udp (struct buffer *buf,
				struct link_socket_actual *from);

int socks_process_outgoing_udp (struct buffer *buf,
				const struct link_socket_actual *to);

#endif
#endif
