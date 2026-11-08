/*
 *  OpenVPN -- An application to securely tunnel IP networks
 *             over a single TCP/UDP port, with support for SSL/TLS-based
 *             session authentication and key exchange,
 *             packet encryption, packet authentication, and
 *             packet compression.
 *
 *  Copyright (C) 2025 OpenVPN Inc <sales@openvpn.net>
 *  Copyright (C) 2025 Arne Schwabe <arne@rfc2549.org>
 *
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

#ifndef ACC_H
#define ACC_H

#include "openvpn.h"

#define ACC_MIN_MSG_LEN 64
/* This is a conservative limit. The theoretical maximum
 * is much closer to the TLS_CHANNEL_BUF_SIZE */
#define ACC_MAX_MSG_LEN (TLS_CHANNEL_BUF_SIZE - 128)

/**
 * This method parses an app custom control message and delivers it to the
 * management interface. We leave reassembly of fragmented messages to the
 * management interface.
 *
 * @param c            The context struct
 * @param buffer       Buffer containing the control message with ACC
 */
void
receive_acc_message(struct context *c, const struct buffer *buffer);

bool
send_acc_message(struct context *c,
                 struct tls_multi *tls_multi,
                 struct tls_session *session,
                 const char *protocol, bool fragment,
                 const char *msg, bool base64);


/**
 * Parses an info message from the server that contains app custom control info
 * information prior to the PUSH_REPLY to be able to use app custom control
 * protocols before sending
 *
 * In client mode only allow what we support ourselves. In server mode
 * allow also capabilities that we not support ourselves.
 *
 * @param capabilities      The string to parse
 * @param delim             The delimiter to use when parsing the string.
 *                          IV_ACC uses "," as delimiter while the
 *                          custom-control PUSH message uses " " as "," is
 *                          already used to separate different push directives
 * @param max_acc_len       Set to the maximum ACC message length
 * @param server            Whether we are server or client
 * @param gc                The gc arena to use for allocating the resulting string
 * @return                  The resulting protocol string or NULL on error
 */
char *
parse_acc_parameters(const char *capabilities,
                     const char *delim,
                     int *max_acc_len,
                     bool server,
                     struct gc_arena *gc);

/**
 * Parses the IV_ACC of the peer and sets multi.acc_negotiated_protocols
 * to the common protocols of server and client and
 * multi.acc_max_message_length  to the maximum length of the ACC message
 * support by both server and client.
 *
 * If there is no common protocol or the client does not support any app custom
 * protocol multi.acc_negotiated_protocols will be set to NULL.
 *
 * @param multi      the multi instance to use the set the app custom protocols.
 * @param session    the session to read the client env from
 */
void
determine_common_acc_protocols(struct tls_multi *multi, struct tls_session *session);

/**
 * Flags returned by the parse_acc_message_flags method
 */
enum acc_message_flag
{
    ACC_MESSAGE_FLAGS_ASCII = 1,
    ACC_MESSAGE_FLAGS_BASE64 = 2,
    ACC_MESSAGE_FLAGS_FRAGMENT = 4,
};

/**
 *  Parses the flags field of an app control message If there is an
 *  error parsing the flags field the method returns -1 and
 *  puts the error reason in err_reason
 */
int
parse_acc_message_flags(const char *flags, const char **err_reason, struct gc_arena *gc);

/**
 * Calculates the intersection of two list that are both separated by :
 * Items in the result will have the same ordering as in the list1
 * parameters
 * @param gc            Returned buffer will be allocated in this gc
 * @param list1         First list to intersect
 * @param list2         Second list to intersect.
 * @return A (potentially empty) buffer containing an intersection list
 */
struct buffer
get_list_intersection(struct gc_arena *gc, const char *list1, const char *list2);

/**
 * Notifies a client via management interface of the negotiated app
 * custom protocols
 * @param multi the tls_multi instance of the connection
 */
void
notify_client_acc_protocols(struct tls_multi *multi);
#endif
