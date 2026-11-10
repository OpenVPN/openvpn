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

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "syshead.h"

#include <string.h>
#include "buffer.h"
#include "error.h"
#include "acc.h"
#include "forward.h"
#include "options_util.h"
#include "ssl_util.h"
#include "ssl_ncp.h"
#include "multi.h"

static void
log_acc_message(struct context *c, const struct buffer *buf, int payload_len,
                const char *protocol, int flags)
{
    bool fragment = flags & ACC_MESSAGE_FLAGS_FRAGMENT;
#ifdef ENABLE_MANAGEMENT
    struct gc_arena gc = gc_new();
    const char *payload_msg = NULL;

    /* For simplicity, we always encode payload to be base64 encoded
     * if not already in base64 format */
    if (flags & ACC_MESSAGE_FLAGS_ASCII)
    {
        char *b64out = NULL;
        ASSERT(openvpn_base64_encode(CBPTR(buf), payload_len, &b64out) >= 0);
        gc_addspecial(b64out, free, &gc);
        payload_msg = b64out;
    }
    else
    {
        payload_msg = CBSTR(buf);
    }

    if (management)
    {
        struct tls_session *session = &c->c2.tls_multi->session[TM_ACTIVE];

        if (c->options.mode == MODE_SERVER)
        {
            /* server mode. Report client context */
            struct man_def_auth_context *mda = session->opt->mda_context;
            unsigned int mda_key_id = get_primary_key(c->c2.tls_multi)->mda_key_id;
            msg(M_CLIENT, ">CLIENT:ACC,%lu,%u,%s,%d,%s",
                mda->cid, mda_key_id, protocol, fragment, payload_msg);
        }
        else
        {
            /* Client mode. Do not a report a CLIENT id */
            msg(M_CLIENT, ">ACC:%s,%d,%s", protocol, fragment, payload_msg);
        }
    }
    gc_free(&gc);
#endif /* ifdef ENABLE_MANAGEMENT */
    msg(D_PUSH, "Received custom app control message (protocol '%s'%s)",
        protocol, fragment ? ", fragment" : "");
}


int
parse_acc_message_flags(const char *flags, const char **err_reason, struct gc_arena *gc)
{
    int acc_flags = 0;

    for (const char *flag = flags; *flag != '\0'; flag++)
    {
        if (*flag == 'A')
        {
            acc_flags |= ACC_MESSAGE_FLAGS_ASCII;
        }
        else if (*flag == '6')
        {
            acc_flags |= ACC_MESSAGE_FLAGS_BASE64;
        }
        else if (*flag == 'F')
        {
            acc_flags |= ACC_MESSAGE_FLAGS_FRAGMENT;
        }
        else
        {
            *err_reason = "Unknown flag in flags";
            return -1;
        }
    }
    /* The message should be encoded with exactly one encoding. Ensure that
     * only one of the flags is present */
    bool asciienc = (bool)(acc_flags & ACC_MESSAGE_FLAGS_ASCII);
    bool base64enc = (bool)(acc_flags & ACC_MESSAGE_FLAGS_BASE64);

    if (base64enc + asciienc != 1)
    {
        char *tmp = gc_malloc(512, 1, gc);
        snprintf(tmp, 512, "number of encodings must be exactly one "
                           "(B64=%d, ASCII=%d)",
                 base64enc, asciienc);
        *err_reason = tmp;
        return -1;
    }

    return acc_flags;
}

/**
 * Wrapper around parse_acc_message_flags to also include the step of
 * extracting the flags from the buffer and forwarding the buffer
 * beyond the flags field.
 */
static int
parse_acc_message_flags_buf(struct buffer *buf, const char **err_reason, struct gc_arena *gc)
{
    const char *flags = buf_extract_field(buf, ',', gc);

    if (!flags)
    {
        *err_reason = "could not extract flags field";
        return -1;
    }
    return parse_acc_message_flags(flags, err_reason, gc);
}

void
receive_acc_message(struct context *c, const struct buffer *buffer)
{
    struct gc_arena gc = gc_new();
    const char *err_reason = "";

    /* Example message: ACC,muppets,15,A,I am Miss Piggy */
    struct buffer buf = *buffer;

    const struct tls_multi *multi = c->c2.tls_multi;
    if (!multi->acc_negotiated_protocols)
    {
        err_reason = "ACC not enabled or no negotiated protocols";
        goto err;
    }

    if (!buf_advance(&buf, strlen("ACC")) || buf_read_u8(&buf) != ',')
    {
        err_reason = "missing , after ACC";
        goto err;
    }

    /* extract protocol, payload length, flags substrings */
    const char *protocol = buf_extract_field(&buf, ',', &gc);
    if (!protocol)
    {
        err_reason = "could not extract protocol field";
        goto err;
    }

    if (!tls_item_in_cipher_list(protocol, multi->acc_negotiated_protocols))
    {
        struct buffer msg_buf = alloc_buf_gc(1024, &gc);
        buf_printf(&msg_buf, "protocol '%s' not in list of negotiated protocols '%s'",
                   protocol, multi->acc_negotiated_protocols);
        err_reason = buf_cstr(&msg_buf);


        goto err;
    }

    /* We do not check the length here. We make no promises to support
     * anything larger than our announced message length but we accept also
     * longer messages if they manage to get through all the other layers
     * that restrict the message size like TLS_CHANNEL_BUF_SIZE.
     */

    int payload_len;
    const char *payload_len_str = buf_extract_field(&buf, ',', &gc);
    if (!payload_len_str
        || !atoi_constrained(payload_len_str, &payload_len, "acc_payload_len", 0, TLS_CHANNEL_BUF_SIZE - 1, D_PUSH_ERRORS))
    {
        err_reason = "could not extract payload length field";
        goto err;
    }

    int flags = parse_acc_message_flags_buf(&buf, &err_reason, &gc);

    if (flags < 0)
    {
        goto err;
    }

    /* We should have a final NUL byte in the control message buffer
     * and thus the length of the buffer should be payload_len + 1 */
    if (buf_len(&buf) != payload_len + 1)
    {
        char *tmp = gc_malloc(512, 1, &gc);
        snprintf(tmp, 512, "field length %d, payload length %d mismatch",
                 payload_len, buf_len(&buf) - 1);
        err_reason = tmp;
        goto err;
    }


    log_acc_message(c, &buf, payload_len, protocol, flags);
    gc_free(&gc);
    return;

err:
    msg(D_PUSH_ERRORS, "WARNING: Received malformed custom app control channel "
                       "message (%s): %s",
        err_reason,
        format_hex(CBPTR(buffer), BLENZ(buffer), 80, &gc));
    gc_free(&gc);
}

bool
send_acc_message(struct context *c,
                 struct tls_multi *multi,
                 struct tls_session *session,
                 const char *protocol, bool fragment,
                 const char *acc_msg_payload, bool base64)
{
    /*
     * length of the protocol string + one ','
     * 2 for the encoding (A or 6), potential F (fragment), and 1 for the ',',
     * 4 for the message size itself and one comma
     * 1 for the comma before the message itself */
    const size_t max_header_size = strlen("ACC,") + strlen(protocol) + 1 + 4 + 1 + 2 + 1;
    size_t len = max_header_size + strlen(acc_msg_payload);

    if (len > TLS_CHANNEL_BUF_SIZE)
    {
        msg(M_CLIENT, "message length (%zu) exceeds maximum possible message length (%d)", len, TLS_CHANNEL_BUF_SIZE);
        return false;
    }

    if ((int)len > multi->acc_max_message_length)
    {
        msg(M_CLIENT, "header (%zu) + message size (%zu) length (%zu) exceeds "
                      "maximum allowed length negotiated with peer (%d)",
            max_header_size, strlen(acc_msg_payload), len,
            multi->acc_max_message_length);
        return false;
    }

    struct gc_arena gc = gc_new();
    /* add 1 for the final \0 */
    struct buffer buf = alloc_buf_gc(len + 1, &gc);

    /* Example message: ACC,muppets,15,A,I am Miss Piggy */
    buf_printf(&buf, "ACC,%s,%zu,%s%s,%s", protocol,
               strlen(acc_msg_payload),
               base64 ? "6" : "A",
               fragment ? "F" : "",
               acc_msg_payload);

    bool ret = send_control_channel_string_dowork(session, BSTR(&buf), D_PUSH);
    reschedule_multi_process(c);
    gc_free(&gc);
    return ret;
}

char *
parse_acc_parameters(const char *capabilities,
                     const char *delim,
                     int *max_acc_len,
                     bool server,
                     struct gc_arena *gc)
{
    char *tmp_message = string_alloc(capabilities, NULL);
    char *tmp_message_orig = tmp_message;
    char *lasts = NULL;

    const char *token = strtok_r(tmp_message, delim, &lasts);

    int p = 0;
    int acclen = 0;
    const char *protocols = NULL;
    char *ret = NULL;

    /* In server mode we allow more capabilities than our own, in client
     * mode we reject if we should use capabilities that we do not support */
    int allowed_acc_len = server ? INT_MAX : ACC_MAX_MSG_LEN;

    while (token)
    {
        if (p == 0 && !atoi_constrained(token, &acclen, "ACC message length", ACC_MIN_MSG_LEN, allowed_acc_len, D_PUSH_ERRORS))
        {
            goto done;
        }

        if (p == 1 && (!tls_item_in_cipher_list("A", token) || !tls_item_in_cipher_list("6", token)))
        {
            msg(D_PUSH_ERRORS, "App custom control encoding must include base64 and ascii");
            goto done;
        }

        if (p == 1 && !server && strcmp(token, "A:6") && strcmp(token, "6:A"))
        {
            msg(D_PUSH_ERRORS, "App custom control encoding must be exactly base64 and ascii");
            goto done;
        }

        if (p == 2)
        {
            protocols = token;
        }

        if (p == 3)
        {
            msg(D_PUSH_ERRORS, "Too many parameters for INFO ACC message/IV_ACC.");
            goto done;
        }

        token = strtok_r(NULL, delim, &lasts);
        p++;
    }

    *max_acc_len = min_int(acclen, ACC_MAX_MSG_LEN);
    ret = string_alloc(protocols, gc);

done:
    free(tmp_message_orig);
    return ret;
}

struct buffer
get_list_intersection(struct gc_arena *gc, const char *list1, const char *list2)
{
    char *tmp = string_alloc(list1, NULL);
    char *lasts = NULL;
    const char *token = strtok_r(tmp, ":", &lasts);

    /* The maximum possible length is the shorter of the two input lists */
    size_t max_len = min_size(strlen(list1), strlen(list2));

    struct buffer common_protocols = alloc_buf_gc(max_len + 1, gc);

    while (token)
    {
        /* check for every items is in both lists and not already in the
         * common list */
        if (tls_item_in_cipher_list(token, list2)
            && !tls_item_in_cipher_list(token, buf_cstr(&common_protocols)))
        {
            if (buf_len(&common_protocols) > 0)
            {
                buf_write_u8(&common_protocols, ':');
            }
            buf_printf(&common_protocols, "%s", token);
        }
        token = strtok_r(NULL, ":", &lasts);
    }
    free(tmp);
    return common_protocols;
}

void
determine_common_acc_protocols(struct tls_multi *multi, struct tls_session *session)
{
    if (!multi->opt.acc_protocols)
    {
        /* No app custom protocols have been configured server-side. */
        return;
    }

    if (multi->acc_negotiated_protocols)
    {
        /* We already have determined the common protocols. */
        return;
    }

    struct gc_arena gc = gc_new();

    /* example IV_ACC: IV_ACC=2048,6:A,flower:power */
    const char *peer_info = multi->peer_info;
    const char *iv_acc = extract_var_peer_info(peer_info, "IV_ACC=", &gc);
    if (!iv_acc)
    {
        gc_free(&gc);
        return;
    }

    int max_acc_len = 0;
    const char *protocols = parse_acc_parameters(iv_acc, ",", &max_acc_len, true, &gc);

    if (!protocols)
    {
        gc_free(&gc);
        msg(D_PUSH_ERRORS, "WARNING: IV_ACC peer info variable of peer is malformed");
        return;
    }

    struct buffer common_protocols = get_list_intersection(&gc, multi->opt.acc_protocols, protocols);

    if (buf_len(&common_protocols) == 0)
    {
        msg(D_PUSH_DEBUG, "WARNING: No common app custom control protocol.");
        gc_free(&gc);
        return;
    }

    multi->acc_negotiated_protocols = string_alloc(buf_str(&common_protocols), NULL);
    multi->acc_max_message_length = max_acc_len;

    /* The normal case is that this is a server where we notify the client
     * capabilities via environment variables */
    if (multi->opt.mode == MODE_SERVER)
    {
        setenv_str(session->opt->es, "acc_protocols", multi->acc_negotiated_protocols);
        setenv_int(session->opt->es, "acc_message_len", multi->acc_max_message_length);
    }
    else
    {
        /* We can also end up here in p2p or if the server has --push-peer-info
         * We do not set variables in that case to keep behavior consistent with
         * the other paths on the client that also do not set variables */
        notify_client_acc_protocols(multi);
    }

    gc_free(&gc);
}

void
notify_client_acc_protocols(struct tls_multi *multi)
{
#ifdef ENABLE_MANAGEMENT
    if (management)
    {
        msg(M_CLIENT, ">ACC_PROTOCOLS:protocols=%s,message_len=%d",
            multi->acc_negotiated_protocols, multi->acc_max_message_length);
    }
#endif
}
