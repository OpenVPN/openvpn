/*
 *  OpenVPN -- An application to securely tunnel IP networks
 *             over a single TCP/UDP port, with support for SSL/TLS-based
 *             session authentication and key exchange,
 *             packet encryption, packet authentication, and
 *             packet compression.
 *
 *  Copyright (C) 2002-2024 OpenVPN Inc <sales@openvpn.net>
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

#ifndef PROXY_H
#define PROXY_H

#include "buffer.h"
#include "misc.h"

/* HTTP CONNECT authentication methods */
#define HTTP_AUTH_NONE   0
#define HTTP_AUTH_BASIC  1
#define HTTP_AUTH_DIGEST 2
/* #define HTTP_AUTH_NTLM   3 removed in OpenVPN 2.7 */
#define HTTP_AUTH_NTLM2  4
#define HTTP_AUTH_N      5 /* number of HTTP_AUTH methods */

struct http_custom_header {
    const char *name;
    const char *content;
};

#define MAX_CUSTOM_HTTP_HEADER 10
struct http_proxy_options {
    const char *server;
    const char *port;

#define PAR_NO  0   /* don't support any auth retries */
#define PAR_ALL 1   /* allow all proxy auth protocols */
#define PAR_NCT 2   /* disable cleartext proxy auth protocols */
    int auth_retry;

    const char *auth_method_string;
    const char *auth_file;
    const char *auth_file_up; /* specified with --http-proxy-user-pass */
    const char *http_version;
    const char *user_agent;
    struct http_custom_header custom_headers[MAX_CUSTOM_HTTP_HEADER];
    bool inline_creds; /* auth_file_up is inline credentials */
};

struct http_proxy_options_simple {
    const char *server;
    const char *port;
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

struct http_proxy_options *init_http_proxy_options_once(struct http_proxy_options **hpo,
                                                        struct gc_arena *gc);

struct http_proxy_info *http_proxy_new(const struct http_proxy_options *o);

void http_proxy_close(struct http_proxy_info *hp);

bool establish_http_proxy_passthru(struct http_proxy_info *p,
                                   socket_descriptor_t sd,  /* already open to proxy */
                                   const char *host,        /* openvpn server remote */
                                   const char *port,          /* openvpn server port */
                                   struct event_timeout *server_poll_timeout,
                                   struct buffer *lookahead,
                                   struct signal_info *sig_info);

uint8_t *make_base64_string2(const uint8_t *str, int str_len, struct gc_arena *gc);

uint8_t *make_base64_string(const uint8_t *str, struct gc_arena *gc);

#endif /* PROXY_H */
