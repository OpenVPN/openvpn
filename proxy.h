/*
 *  OpenVPN -- An application to securely tunnel IP networks
 *             over a single TCP/UDP port, with support for SSL/TLS-based
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

#ifndef PROXY_H
#define PROXY_H

#ifdef ENABLE_HTTP_PROXY

#include "buffer.h"
#include "misc.h"

/* HTTP CONNECT authentication methods */
#define HTTP_AUTH_NONE  0
#define HTTP_AUTH_BASIC 1
#define HTTP_AUTH_NTLM  2
#define HTTP_AUTH_N     3

struct http_proxy_options {
  const char *server;
  int port;
  bool retry;
  int timeout;
  const char *auth_method_string;
  const char *auth_file;
  const char *http_version;
  const char *user_agent;
};

struct http_proxy_info {
  bool defined;
  int auth_method;
  struct http_proxy_options options;
  struct user_pass up;
};

struct http_proxy_info *new_http_proxy (const struct http_proxy_options *o,
					struct gc_arena *gc);

void establish_http_proxy_passthru (struct http_proxy_info *p,
				    socket_descriptor_t sd, /* already open to proxy */
				    const char *host,       /* openvpn server remote */
				    const int port,         /* openvpn server port */
				    struct buffer *lookahead,
				    volatile int *signal_received);

uint8_t *make_base64_string2 (const uint8_t *str, int str_len, struct gc_arena *gc);
uint8_t *make_base64_string (const uint8_t *str, struct gc_arena *gc);

#endif
#endif
