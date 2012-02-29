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

#ifndef PROXY_H
#define PROXY_H

#include "buffer.h"
#include "misc.h"

#ifdef GENERAL_PROXY_SUPPORT

/*
 * Return value for get_proxy_settings to automatically
 * determine proxy information.
 */
struct auto_proxy_info_entry {
  char *server;
  int port;
};

struct auto_proxy_info {
  struct auto_proxy_info_entry http;
  struct auto_proxy_info_entry socks;
};

struct auto_proxy_info *get_proxy_settings (char **err, struct gc_arena *gc);

#ifdef WIN32
void show_win_proxy_settings (const int msglevel);
#endif /* WIN32 */

#endif /* GENERAL_PROXY_SUPPORT */

#ifdef ENABLE_HTTP_PROXY

/* HTTP CONNECT authentication methods */
#define HTTP_AUTH_NONE   0
#define HTTP_AUTH_BASIC  1
#define HTTP_AUTH_DIGEST 2
#define HTTP_AUTH_NTLM   3
#define HTTP_AUTH_NTLM2  4
#define HTTP_AUTH_N      5 /* number of HTTP_AUTH methods */

struct http_proxy_options {
  const char *server;
  int port;
  bool retry;
  int timeout;

# define PAR_NO  0  /* don't support any auth retries */
# define PAR_ALL 1  /* allow all proxy auth protocols */
# define PAR_NCT 2  /* disable cleartext proxy auth protocols */
  int auth_retry;

  const char *auth_method_string;
  const char *auth_file;
  const char *http_version;
  const char *user_agent;
};

struct http_proxy_options_simple {
  const char *server;
  int port;
  int auth_retry;
};

struct http_proxy_info {
  bool defined;
  int auth_method;
  struct http_proxy_options options;
  struct user_pass up;
  char *proxy_authenticate;
  bool queried_creds;
};

struct http_proxy_info *http_proxy_new (const struct http_proxy_options *o,
					struct auto_proxy_info *auto_proxy_info);

void http_proxy_close (struct http_proxy_info *hp);

bool establish_http_proxy_passthru (struct http_proxy_info *p,
				    socket_descriptor_t sd, /* already open to proxy */
				    const char *host,       /* openvpn server remote */
				    const int port,         /* openvpn server port */
				    struct buffer *lookahead,
				    volatile int *signal_received);

uint8_t *make_base64_string2 (const uint8_t *str, int str_len, struct gc_arena *gc);
uint8_t *make_base64_string (const uint8_t *str, struct gc_arena *gc);

#endif /* ENABLE_HTTP_PROXY */

#endif /* PROXY_H */
