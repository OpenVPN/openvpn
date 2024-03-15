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

#ifndef PUSH_H
#define PUSH_H

#include "forward.h"

#define PUSH_MSG_ERROR            0
#define PUSH_MSG_REQUEST          1
#define PUSH_MSG_REPLY            2
#define PUSH_MSG_REQUEST_DEFERRED 3
#define PUSH_MSG_AUTH_FAILURE     4
#define PUSH_MSG_CONTINUATION     5
#define PUSH_MSG_ALREADY_REPLIED  6

int process_incoming_push_request(struct context *c);

int process_incoming_push_msg(struct context *c,
                              const struct buffer *buffer,
                              bool honor_received_options,
                              unsigned int permission_mask,
                              unsigned int *option_types_found);

bool send_push_request(struct context *c);

void receive_auth_failed(struct context *c, const struct buffer *buffer);

void server_pushed_signal(struct context *c, const struct buffer *buffer, const bool restart, const int adv);

void receive_exit_message(struct context *c);

void server_pushed_info(struct context *c, const struct buffer *buffer,
                        const int adv);

void receive_cr_response(struct context *c, const struct buffer *buffer);

void incoming_push_message(struct context *c, const struct buffer *buffer);

void clone_push_list(struct options *o);

void push_option(struct options *o, const char *opt, int msglevel);

void push_options(struct options *o, char **p, int msglevel,
                  struct gc_arena *gc);

void push_reset(struct options *o);

void push_remove_option(struct options *o, const char *p);

void remove_iroutes_from_push_route_list(struct options *o);

void send_auth_failed(struct context *c, const char *client_reason);

/**
 * Sends the auth pending control messages to a client. See
 * doc/management-notes.txt under client-pending-auth for
 * more details on message format
 */
bool
send_auth_pending_messages(struct tls_multi *tls_multi,
                           struct tls_session *session, const char *extra,
                           unsigned int timeout);

void send_restart(struct context *c, const char *kill_msg);

/**
 * Sends a push reply message only containin the auth-token to update
 * the auth-token on the client. Always pushes to the active session
 *
 * @param multi    - The \c tls_multi structure belonging to the instance
 *                   to push to
 */
void send_push_reply_auth_token(struct tls_multi *multi);

/**
 * Parses an AUTH_PENDING message and if in pull mode extends the timeout
 *
 * @param c             The context struct
 * @param buffer        Buffer containing the control message with AUTH_PENDING
 */
void
receive_auth_pending(struct context *c, const struct buffer *buffer);

#endif /* ifndef PUSH_H */
