/*
 *  OpenVPN -- An application to securely tunnel IP networks
 *             over a single TCP/UDP port, with support for SSL/TLS-based
 *             session authentication and key exchange,
 *             packet encryption, packet authentication, and
 *             packet compression.
 *
 *  Copyright (C) 2002-2023 OpenVPN Inc <sales@openvpn.net>
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

#include "push.h"
#include "options.h"
#include "ssl.h"
#include "ssl_verify.h"
#include "ssl_ncp.h"
#include "manage.h"

#include "memdbg.h"
#include "ssl_util.h"
#include "options_util.h"

static char push_reply_cmd[] = "PUSH_REPLY";

/*
 * Auth username/password
 *
 * Client received an authentication failed message from server.
 * Runs on client.
 */
void
receive_auth_failed(struct context *c, const struct buffer *buffer)
{
    msg(M_VERB0, "AUTH: Received control message: %s", BSTR(buffer));
    c->options.no_advance = true;

    if (!c->options.pull)
    {
        return;
    }

    struct buffer buf = *buffer;

    /* If the AUTH_FAIL message ends with a , it is an extended message that
     * contains further flags */
    bool authfail_extended = buf_string_compare_advance(&buf, "AUTH_FAILED,");

    const char *reason = NULL;
    if (authfail_extended && BLEN(&buf))
    {
        reason = BSTR(&buf);
    }

    if (authfail_extended && buf_string_match_head_str(&buf, "TEMP"))
    {
        parse_auth_failed_temp(&c->options, reason + strlen("TEMP"));
        register_signal(c->sig, SIGUSR1, "auth-temp-failure (server temporary reject)");
    }

    /* Before checking how to react on AUTH_FAILED, first check if the
     * failed auth might be the result of an expired auth-token.
     * Note that a server restart will trigger a generic AUTH_FAILED
     * instead an AUTH_FAILED,SESSION so handle all AUTH_FAILED message
     * identical for this scenario */
    else if (ssl_clean_auth_token())
    {
        /* SOFT-SIGUSR1 -- Auth failure error */
        register_signal(c->sig, SIGUSR1, "auth-failure (auth-token)");
        c->options.no_advance = true;
    }
    else
    {
        switch (auth_retry_get())
        {
            case AR_NONE:
                /* SOFT-SIGTERM -- Auth failure error */
                register_signal(c->sig, SIGTERM, "auth-failure");
                break;

            case AR_INTERACT:
                ssl_purge_auth(false);

            case AR_NOINTERACT:
                /* SOFT-SIGTUSR1 -- Auth failure error */
                register_signal(c->sig, SIGUSR1, "auth-failure");
                break;

            default:
                ASSERT(0);
        }
    }
#ifdef ENABLE_MANAGEMENT
    if (management)
    {
        management_auth_failure(management, UP_TYPE_AUTH, reason);
    }
    /*
     * Save the dynamic-challenge text even when management is defined
     */
    if (authfail_extended
        && buf_string_match_head_str(&buf, "CRV1:") && BLEN(&buf))
    {
        ssl_put_auth_challenge(BSTR(&buf));
    }
#endif /* ifdef ENABLE_MANAGEMENT */

}

/*
 * Act on received restart message from server
 */
void
server_pushed_signal(struct context *c, const struct buffer *buffer, const bool restart, const int adv)
{
    if (c->options.pull)
    {
        struct buffer buf = *buffer;
        const char *m = "";
        if (buf_advance(&buf, adv) && buf_read_u8(&buf) == ',' && BLEN(&buf))
        {
            m = BSTR(&buf);
        }

        /* preserve cached passwords? */
        /* advance to next server? */
        {
            bool purge = true;

            if (m[0] == '[')
            {
                int i;
                for (i = 1; m[i] != '\0' && m[i] != ']'; ++i)
                {
                    if (m[i] == 'P')
                    {
                        purge = false;
                    }
                    else if (m[i] == 'N')
                    {
                        /* next server? */
                        c->options.no_advance = false;
                    }
                }
            }
            if (purge)
            {
                ssl_purge_auth(true);
            }
        }

        if (restart)
        {
            msg(D_STREAM_ERRORS, "Connection reset command was pushed by server ('%s')", m);
            /* SOFT-SIGUSR1 -- server-pushed connection reset */
            register_signal(c->sig, SIGUSR1, "server-pushed-connection-reset");
        }
        else
        {
            msg(D_STREAM_ERRORS, "Halt command was pushed by server ('%s')", m);
            /* SOFT-SIGTERM -- server-pushed halt */
            register_signal(c->sig, SIGTERM, "server-pushed-halt");
        }
#ifdef ENABLE_MANAGEMENT
        if (management)
        {
            management_notify(management, "info", c->sig->signal_text, m);
        }
#endif
    }
}

void
receive_exit_message(struct context *c)
{
    dmsg(D_STREAM_ERRORS, "CC-EEN exit message received by peer");
    /* With control channel exit notification, we want to give the session
     * enough time to handle retransmits and acknowledgment, so that eventual
     * retries from the client to resend the exit or ACKs will not trigger
     * a new session (we already forgot the session but the packet's HMAC
     * is still valid).  This could happen for the entire period that the
     * HMAC timeslot is still valid, but waiting five seconds here does not
     * hurt much, takes care of the retransmits, and is easier code-wise.
     *
     * This does not affect OCC exit since the HMAC session code will
     * ignore DATA packets
     * */
    if (c->options.mode == MODE_SERVER)
    {
        schedule_exit(c, c->options.scheduled_exit_interval, SIGTERM);
    }
    else
    {
        register_signal(c->sig, SIGUSR1, "remote-exit");
    }
#ifdef ENABLE_MANAGEMENT
    if (management)
    {
        management_notify(management, "info", "remote-exit", "EXIT");
    }
#endif
}


void
server_pushed_info(struct context *c, const struct buffer *buffer,
                   const int adv)
{
    const char *m = "";
    struct buffer buf = *buffer;

    if (buf_advance(&buf, adv) && buf_read_u8(&buf) == ',' && BLEN(&buf))
    {
        m = BSTR(&buf);
    }

#ifdef ENABLE_MANAGEMENT
    struct gc_arena gc;
    if (management)
    {
        gc = gc_new();

        /*
         * We use >INFOMSG here instead of plain >INFO since INFO is used to
         * for management greeting and we don't want to confuse the client
         */
        struct buffer out = alloc_buf_gc(256, &gc);
        if (buf_printf(&out, ">%s:%s", "INFOMSG", m))
        {
            management_notify_generic(management, BSTR(&out));
        }
        else
        {
            msg(D_PUSH_ERRORS, "WARNING: Received INFO command is too long, won't notify management client.");
        }

        gc_free(&gc);
    }
    #endif
    msg(D_PUSH, "Info command was pushed by server ('%s')", m);
}

void
receive_cr_response(struct context *c, const struct buffer *buffer)
{
    struct buffer buf = *buffer;
    const char *m = "";

    if (buf_advance(&buf, 11) && buf_read_u8(&buf) == ',' && BLEN(&buf))
    {
        m = BSTR(&buf);
    }
#ifdef ENABLE_MANAGEMENT
    struct tls_session *session = &c->c2.tls_multi->session[TM_ACTIVE];
    struct man_def_auth_context *mda = session->opt->mda_context;
    struct env_set *es = session->opt->es;
    unsigned int mda_key_id = get_primary_key(c->c2.tls_multi)->mda_key_id;

    management_notify_client_cr_response(mda_key_id, mda, es, m);
#endif
#if ENABLE_PLUGIN
    verify_crresponse_plugin(c->c2.tls_multi, m);
#endif
    verify_crresponse_script(c->c2.tls_multi, m);
    msg(D_PUSH, "CR response was sent by client ('%s')", m);
}

/**
 * Parse the keyword for the AUTH_PENDING request
 * @param buffer                buffer containing the keywords, the buffer's
 *                              content will be modified by this function
 * @param server_timeout        timeout pushed by the server or unchanged
 *                              if the server does not push a timeout
 */
static void
parse_auth_pending_keywords(const struct buffer *buffer,
                            unsigned int *server_timeout)
{
    struct buffer buf = *buffer;

    /* does the buffer start with "AUTH_PENDING," ? */
    if (!buf_advance(&buf, strlen("AUTH_PENDING"))
        || !(buf_read_u8(&buf) == ',') || !BLEN(&buf))
    {
#ifdef ENABLE_MANAGEMENT
        if (management)
        {
            management_set_state(management, OPENVPN_STATE_AUTH_PENDING,
                                 "", NULL, NULL, NULL, NULL);
        }
#endif

        return;
    }

    /* parse the keywords in the same way that push options are parsed */
    char line[OPTION_LINE_SIZE];

#ifdef ENABLE_MANAGEMENT
    /* Need to do the management notification with the keywords before
     * buf_parse is called, as it will insert \0 bytes into the buffer */
    if (management)
    {
        management_set_state(management, OPENVPN_STATE_AUTH_PENDING,
                             BSTR(&buf), NULL, NULL, NULL, NULL);
    }
#endif

    while (buf_parse(&buf, ',', line, sizeof(line)))
    {
        if (sscanf(line, "timeout %u", server_timeout) != 1)
        {
            msg(D_PUSH, "ignoring AUTH_PENDING parameter: %s", line);
        }
    }
}

void
receive_auth_pending(struct context *c, const struct buffer *buffer)
{
    if (!c->options.pull)
    {
        return;
    }

    /* Cap the increase at the maximum time we are willing stay in the
     * pending authentication state */
    unsigned int max_timeout = max_uint(c->options.renegotiate_seconds/2,
                                        c->options.handshake_window);

    /* try to parse parameter keywords, default to hand-winow timeout if the
     * server does not supply a timeout */
    unsigned int server_timeout = c->options.handshake_window;
    parse_auth_pending_keywords(buffer, &server_timeout);

    msg(D_PUSH, "AUTH_PENDING received, extending handshake timeout from %us "
        "to %us", c->options.handshake_window,
        min_uint(max_timeout, server_timeout));

    const struct key_state *ks = get_primary_key(c->c2.tls_multi);
    c->c2.push_request_timeout = ks->established + min_uint(max_timeout, server_timeout);
}

/**
 * Add an option to the given push list by providing a format string.
 *
 * The string added to the push options is allocated in o->gc, so the caller
 * does not have to preserve anything.
 *
 * @param gc        GC arena where options are allocated
 * @param push_list Push list containing options
 * @param msglevel  The message level to use when printing errors
 * @param fmt       Format string for the option
 * @param ...       Format string arguments
 *
 * @return true on success, false on failure.
 */
static bool push_option_fmt(struct gc_arena *gc, struct push_list *push_list,
                            int msglevel, const char *fmt, ...)
#ifdef __GNUC__
#if __USE_MINGW_ANSI_STDIO
__attribute__ ((format(gnu_printf, 4, 5)))
#else
__attribute__ ((format(__printf__, 4, 5)))
#endif
#endif
;

/*
 * Send auth failed message from server to client.
 *
 * Does nothing if an exit is already scheduled
 */
void
send_auth_failed(struct context *c, const char *client_reason)
{
    if (event_timeout_defined(&c->c2.scheduled_exit))
    {
        msg(D_TLS_DEBUG, "exit already scheduled for context");
        return;
    }

    struct gc_arena gc = gc_new();
    static const char auth_failed[] = "AUTH_FAILED";
    size_t len;

    schedule_exit(c, c->options.scheduled_exit_interval, SIGTERM);

    len = (client_reason ? strlen(client_reason)+1 : 0) + sizeof(auth_failed);
    if (len > PUSH_BUNDLE_SIZE)
    {
        len = PUSH_BUNDLE_SIZE;
    }

    {
        struct buffer buf = alloc_buf_gc(len, &gc);
        buf_printf(&buf, auth_failed);
        if (client_reason)
        {
            buf_printf(&buf, ",%s", client_reason);
        }

        /* We kill the whole session, send the AUTH_FAILED to any TLS session
         * that might be active */
        send_control_channel_string_dowork(&c->c2.tls_multi->session[TM_INITIAL],
                                           BSTR(&buf), D_PUSH);
        send_control_channel_string_dowork(&c->c2.tls_multi->session[TM_ACTIVE],
                                           BSTR(&buf), D_PUSH);

        reschedule_multi_process(c);

    }

    gc_free(&gc);
}


bool
send_auth_pending_messages(struct tls_multi *tls_multi,
                           struct tls_session *session,
                           const char *extra, unsigned int timeout)
{
    struct key_state *ks = &session->key[KS_PRIMARY];

    static const char info_pre[] = "INFO_PRE,";

    const char *const peer_info = tls_multi->peer_info;
    unsigned int proto = extract_iv_proto(peer_info);


    /* Calculate the maximum timeout and subtract the time we already waited */
    unsigned int max_timeout = max_uint(tls_multi->opt.renegotiate_seconds/2,
                                        tls_multi->opt.handshake_window);
    max_timeout = max_timeout - (now - ks->initial);
    timeout = min_uint(max_timeout, timeout);

    struct gc_arena gc = gc_new();
    if ((proto & IV_PROTO_AUTH_PENDING_KW) == 0)
    {
        send_control_channel_string_dowork(session, "AUTH_PENDING", D_PUSH);
    }
    else
    {
        static const char auth_pre[] = "AUTH_PENDING,timeout ";
        /* Assume a worst case of 8 byte uint64 in decimal which */
        /* needs 20 bytes */
        size_t len = 20 + 1 + sizeof(auth_pre);
        struct buffer buf = alloc_buf_gc(len, &gc);
        buf_printf(&buf, auth_pre);
        buf_printf(&buf, "%u", timeout);
        send_control_channel_string_dowork(session, BSTR(&buf), D_PUSH);
    }

    size_t len = strlen(extra) + 1 + sizeof(info_pre);
    if (len > PUSH_BUNDLE_SIZE)
    {
        gc_free(&gc);
        return false;
    }

    struct buffer buf = alloc_buf_gc(len, &gc);
    buf_printf(&buf, info_pre);
    buf_printf(&buf, "%s", extra);
    send_control_channel_string_dowork(session, BSTR(&buf), D_PUSH);

    ks->auth_deferred_expire = now + timeout;

    gc_free(&gc);
    return true;
}

/*
 * Send restart message from server to client.
 */
void
send_restart(struct context *c, const char *kill_msg)
{
    schedule_exit(c, c->options.scheduled_exit_interval, SIGTERM);
    send_control_channel_string(c, kill_msg ? kill_msg : "RESTART", D_PUSH);
}

/*
 * Push/Pull
 */

void
incoming_push_message(struct context *c, const struct buffer *buffer)
{
    struct gc_arena gc = gc_new();
    unsigned int option_types_found = 0;

    msg(D_PUSH, "PUSH: Received control message: '%s'", sanitize_control_message(BSTR(buffer), &gc));

    int status = process_incoming_push_msg(c, buffer, c->options.pull,
                                           pull_permission_mask(c),
                                           &option_types_found);

    if (status == PUSH_MSG_ERROR)
    {
        msg(D_PUSH_ERRORS, "WARNING: Received bad push/pull message: %s", sanitize_control_message(BSTR(buffer), &gc));
    }
    else if (status == PUSH_MSG_REPLY || status == PUSH_MSG_CONTINUATION)
    {
        c->options.push_option_types_found |= option_types_found;

        /* delay bringing tun/tap up until --push parms received from remote */
        if (status == PUSH_MSG_REPLY)
        {
            if (!options_postprocess_pull(&c->options, c->c2.es))
            {
                goto error;
            }
            if (!do_up(c, true, c->options.push_option_types_found))
            {
                msg(D_PUSH_ERRORS, "Failed to open tun/tap interface");
                goto error;
            }
        }
        event_timeout_clear(&c->c2.push_request_interval);
        event_timeout_clear(&c->c2.wait_for_connect);
    }

    goto cleanup;

error:
    register_signal(c->sig, SIGUSR1, "process-push-msg-failed");
cleanup:
    gc_free(&gc);
}

bool
send_push_request(struct context *c)
{
    const struct key_state *ks = get_primary_key(c->c2.tls_multi);

    /* We timeout here under two conditions:
     * a) we reached the hard limit of push_request_timeout
     * b) we have not seen anything from the server in hand_window time
     *
     * for non auth-pending scenario, push_request_timeout is the same as
     * hand_window timeout. For b) every PUSH_REQUEST is a acknowledged by
     * the server by a P_ACK_V1 packet that reset the keepalive timer
     */

    if (c->c2.push_request_timeout > now
        && (now - ks->peer_last_packet) < c->options.handshake_window)
    {
        return send_control_channel_string(c, "PUSH_REQUEST", D_PUSH);
    }
    else
    {
        msg(D_STREAM_ERRORS, "No reply from server to push requests in %ds",
            (int)(now - ks->established));
        /* SOFT-SIGUSR1 -- server-pushed connection reset */
        register_signal(c->sig, SIGUSR1, "no-push-reply");
        return false;
    }
}

/**
 * Prepare push option for auth-token
 * @param tls_multi     tls multi context of VPN tunnel
 * @param gc            gc arena for allocating push options
 * @param push_list     push list to where options are added
 *
 * @return true on success, false on failure.
 */
void
prepare_auth_token_push_reply(struct tls_multi *tls_multi, struct gc_arena *gc,
                              struct push_list *push_list)
{
    /*
     * If server uses --auth-gen-token and we have an auth token
     * to send to the client
     */
    if (tls_multi->auth_token)
    {
        push_option_fmt(gc, push_list, M_USAGE,
                        "auth-token %s",
                        tls_multi->auth_token);
    }
}

/**
 * Prepare push options, based on local options
 *
 * @param context       context structure storing data for VPN tunnel
 * @param gc            gc arena for allocating push options
 * @param push_list     push list to where options are added
 *
 * @return true on success, false on failure.
 */
bool
prepare_push_reply(struct context *c, struct gc_arena *gc,
                   struct push_list *push_list)
{
    struct tls_multi *tls_multi = c->c2.tls_multi;
    struct options *o = &c->options;

    /* ipv6 */
    if (c->c2.push_ifconfig_ipv6_defined && !o->push_ifconfig_ipv6_blocked)
    {
        push_option_fmt(gc, push_list, M_USAGE, "ifconfig-ipv6 %s/%d %s",
                        print_in6_addr(c->c2.push_ifconfig_ipv6_local, 0, gc),
                        c->c2.push_ifconfig_ipv6_netbits,
                        print_in6_addr(c->c2.push_ifconfig_ipv6_remote,
                                       0, gc));
    }

    /* ipv4 */
    if (c->c2.push_ifconfig_defined && c->c2.push_ifconfig_local
        && c->c2.push_ifconfig_remote_netmask
        && !o->push_ifconfig_ipv4_blocked)
    {
        in_addr_t ifconfig_local = c->c2.push_ifconfig_local;
        if (c->c2.push_ifconfig_local_alias)
        {
            ifconfig_local = c->c2.push_ifconfig_local_alias;
        }
        push_option_fmt(gc, push_list, M_USAGE, "ifconfig %s %s",
                        print_in_addr_t(ifconfig_local, 0, gc),
                        print_in_addr_t(c->c2.push_ifconfig_remote_netmask,
                                        0, gc));
    }

    if (tls_multi->use_peer_id)
    {
        push_option_fmt(gc, push_list, M_USAGE, "peer-id %d",
                        tls_multi->peer_id);
    }
    /*
     * If server uses --auth-gen-token and we have an auth token
     * to send to the client
     */
    prepare_auth_token_push_reply(tls_multi, gc, push_list);

    /*
     * Push the selected cipher, at this point the cipher has been
     * already negotiated and been fixed.
     *
     * We avoid pushing the cipher to clients not supporting NCP
     * to avoid error messages in their logs
     */
    if (tls_peer_supports_ncp(c->c2.tls_multi->peer_info))
    {
        push_option_fmt(gc, push_list, M_USAGE, "cipher %s", o->ciphername);
    }

    struct buffer proto_flags = alloc_buf_gc(128, gc);

    if (o->imported_protocol_flags & CO_USE_CC_EXIT_NOTIFY)
    {
        buf_printf(&proto_flags, " cc-exit");

        /* if the cc exit flag is supported, pushing tls-ekm via protocol-flags
         * is also supported */
        if (o->imported_protocol_flags & CO_USE_TLS_KEY_MATERIAL_EXPORT)
        {
            buf_printf(&proto_flags, " tls-ekm");
        }
    }
    else if (o->imported_protocol_flags & CO_USE_TLS_KEY_MATERIAL_EXPORT)
    {
        push_option_fmt(gc, push_list, M_USAGE, "key-derivation tls-ekm");
    }

    if (o->imported_protocol_flags & CO_USE_DYNAMIC_TLS_CRYPT)
    {
        buf_printf(&proto_flags, " dyn-tls-crypt");
    }

    if (buf_len(&proto_flags) > 0)
    {
        push_option_fmt(gc, push_list, M_USAGE, "protocol-flags%s", buf_str(&proto_flags));
    }

    /* Push our mtu to the peer if it supports pushable MTUs */
    int client_max_mtu = 0;
    const char *iv_mtu = extract_var_peer_info(tls_multi->peer_info, "IV_MTU=", gc);

    if (iv_mtu && sscanf(iv_mtu, "%d", &client_max_mtu) == 1)
    {
        push_option_fmt(gc, push_list, M_USAGE, "tun-mtu %d", o->ce.tun_mtu);
        if (client_max_mtu < o->ce.tun_mtu)
        {
            msg(M_WARN, "Warning: reported maximum MTU from client (%d) is lower "
                "than MTU used on the server (%d). Add tun-max-mtu %d "
                "to client configuration.", client_max_mtu,
                o->ce.tun_mtu, o->ce.tun_mtu);
        }
    }

    return true;
}

static bool
send_push_options(struct context *c, struct buffer *buf,
                  struct push_list *push_list, int safe_cap,
                  bool *push_sent, bool *multi_push)
{
    struct push_entry *e = push_list->head;

    while (e)
    {
        if (e->enable)
        {
            const int l = strlen(e->option);
            if (BLEN(buf) + l >= safe_cap)
            {
                buf_printf(buf, ",push-continuation 2");
                {
                    const bool status = send_control_channel_string(c, BSTR(buf), D_PUSH);
                    if (!status)
                    {
                        return false;
                    }
                    *push_sent = true;
                    *multi_push = true;
                    buf_reset_len(buf);
                    buf_printf(buf, "%s", push_reply_cmd);
                }
            }
            if (BLEN(buf) + l >= safe_cap)
            {
                msg(M_WARN, "--push option is too long");
                return false;
            }
            buf_printf(buf, ",%s", e->option);
        }
        e = e->next;
    }
    return true;
}

void
send_push_reply_auth_token(struct tls_multi *multi)
{
    struct gc_arena gc = gc_new();
    struct push_list push_list = { 0 };
    struct tls_session *session = &multi->session[TM_ACTIVE];

    prepare_auth_token_push_reply(multi, &gc, &push_list);

    /* prepare auth token should always add the auth-token option */
    struct push_entry *e = push_list.head;
    ASSERT(e && e->enable);

    /* Construct a mimimal control channel push reply message */
    struct buffer buf = alloc_buf_gc(PUSH_BUNDLE_SIZE, &gc);
    buf_printf(&buf, "%s,%s", push_reply_cmd, e->option);
    send_control_channel_string_dowork(session, BSTR(&buf), D_PUSH);
    gc_free(&gc);
}

bool
send_push_reply(struct context *c, struct push_list *per_client_push_list)
{
    struct gc_arena gc = gc_new();
    struct buffer buf = alloc_buf_gc(PUSH_BUNDLE_SIZE, &gc);
    bool multi_push = false;
    const int extra = 84; /* extra space for possible trailing ifconfig and push-continuation */
    const int safe_cap = BCAP(&buf) - extra;
    bool push_sent = false;

    buf_printf(&buf, "%s", push_reply_cmd);

    /* send options which are common to all clients */
    if (!send_push_options(c, &buf, &c->options.push_list, safe_cap,
                           &push_sent, &multi_push))
    {
        goto fail;
    }

    /* send client-specific options */
    if (!send_push_options(c, &buf, per_client_push_list, safe_cap,
                           &push_sent, &multi_push))
    {
        goto fail;
    }

    if (multi_push)
    {
        buf_printf(&buf, ",push-continuation 1");
    }

    if (BLEN(&buf) > sizeof(push_reply_cmd)-1)
    {
        const bool status = send_control_channel_string(c, BSTR(&buf), D_PUSH);
        if (!status)
        {
            goto fail;
        }
        push_sent = true;
    }

    /* If nothing have been pushed, send an empty push,
     * as the client is expecting a response
     */
    if (!push_sent)
    {
        bool status = false;

        buf_reset_len(&buf);
        buf_printf(&buf, "%s", push_reply_cmd);
        status = send_control_channel_string(c, BSTR(&buf), D_PUSH);
        if (!status)
        {
            goto fail;
        }
    }

    gc_free(&gc);
    return true;

fail:
    gc_free(&gc);
    return false;
}

static void
push_option_ex(struct gc_arena *gc, struct push_list *push_list,
               const char *opt, bool enable, int msglevel)
{
    if (!string_class(opt, CC_ANY, CC_COMMA))
    {
        msg(msglevel, "PUSH OPTION FAILED (illegal comma (',') in string): '%s'", opt);
    }
    else
    {
        struct push_entry *e;
        ALLOC_OBJ_CLEAR_GC(e, struct push_entry, gc);
        e->enable = true;
        e->option = opt;
        if (push_list->head)
        {
            ASSERT(push_list->tail);
            push_list->tail->next = e;
            push_list->tail = e;
        }
        else
        {
            ASSERT(!push_list->tail);
            push_list->head = e;
            push_list->tail = e;
        }
    }
}

void
push_option(struct options *o, const char *opt, int msglevel)
{
    push_option_ex(&o->gc, &o->push_list, opt, true, msglevel);
}

void
clone_push_list(struct options *o)
{
    if (o->push_list.head)
    {
        const struct push_entry *e = o->push_list.head;
        push_reset(o);
        while (e)
        {
            push_option_ex(&o->gc, &o->push_list,
                           string_alloc(e->option, &o->gc), true, M_FATAL);
            e = e->next;
        }
    }
}

void
push_options(struct options *o, char **p, int msglevel, struct gc_arena *gc)
{
    const char **argv = make_extended_arg_array(p, false, gc);
    char *opt = print_argv(argv, gc, 0);
    push_option(o, opt, msglevel);
}

static bool
push_option_fmt(struct gc_arena *gc, struct push_list *push_list,
                int msglevel, const char *format, ...)
{
    va_list arglist;
    char tmp[256] = {0};
    int len;
    va_start(arglist, format);
    len = vsnprintf(tmp, sizeof(tmp), format, arglist);
    va_end(arglist);
    if (len > sizeof(tmp)-1)
    {
        return false;
    }
    push_option_ex(gc, push_list, string_alloc(tmp, gc), true, msglevel);
    return true;
}

void
push_reset(struct options *o)
{
    CLEAR(o->push_list);
}

void
push_remove_option(struct options *o, const char *p)
{
    msg(D_PUSH_DEBUG, "PUSH_REMOVE searching for: '%s'", p);

    /* ifconfig is special, as not part of the push list */
    if (streq(p, "ifconfig"))
    {
        o->push_ifconfig_ipv4_blocked = true;
        return;
    }

    /* ifconfig-ipv6 is special, as not part of the push list */
    if (streq( p, "ifconfig-ipv6" ))
    {
        o->push_ifconfig_ipv6_blocked = true;
        return;
    }

    if (o && o->push_list.head)
    {
        struct push_entry *e = o->push_list.head;

        /* cycle through the push list */
        while (e)
        {
            if (e->enable
                && strncmp( e->option, p, strlen(p) ) == 0)
            {
                msg(D_PUSH_DEBUG, "PUSH_REMOVE removing: '%s'", e->option);
                e->enable = false;
            }

            e = e->next;
        }
    }
}

int
process_incoming_push_request(struct context *c)
{
    int ret = PUSH_MSG_ERROR;


    if (tls_authentication_status(c->c2.tls_multi) == TLS_AUTHENTICATION_FAILED
        || c->c2.tls_multi->multi_state == CAS_FAILED)
    {
        const char *client_reason = tls_client_reason(c->c2.tls_multi);
        send_auth_failed(c, client_reason);
        ret = PUSH_MSG_AUTH_FAILURE;
    }
    else if (tls_authentication_status(c->c2.tls_multi) == TLS_AUTHENTICATION_SUCCEEDED
             && c->c2.tls_multi->multi_state >= CAS_CONNECT_DONE)
    {
        time_t now;

        openvpn_time(&now);
        if (c->c2.sent_push_reply_expiry > now)
        {
            ret = PUSH_MSG_ALREADY_REPLIED;
        }
        else
        {
            /* per-client push options - peer-id, cipher, ifconfig, ipv6-ifconfig */
            struct push_list push_list = { 0 };
            struct gc_arena gc = gc_new();

            if (prepare_push_reply(c, &gc, &push_list)
                && send_push_reply(c, &push_list))
            {
                ret = PUSH_MSG_REQUEST;
                c->c2.sent_push_reply_expiry = now + 30;
            }
            gc_free(&gc);
        }
    }
    else
    {
        ret = PUSH_MSG_REQUEST_DEFERRED;
    }

    return ret;
}

static void
push_update_digest(md_ctx_t *ctx, struct buffer *buf, const struct options *opt)
{
    char line[OPTION_PARM_SIZE];
    while (buf_parse(buf, ',', line, sizeof(line)))
    {
        /* peer-id and auth-token might change on restart and this should not trigger reopening tun */
        if (strprefix(line, "peer-id ")
            || strprefix(line, "auth-token ")
            || strprefix(line, "auth-token-user "))
        {
            continue;
        }
        /* tun reopen only needed if cipher change can change tun MTU */
        if (strprefix(line, "cipher ") && !opt->ce.tun_mtu_defined)
        {
            continue;
        }
        md_ctx_update(ctx, (const uint8_t *) line, strlen(line)+1);
    }
}

static int
process_incoming_push_reply(struct context *c,
                            unsigned int permission_mask,
                            unsigned int *option_types_found,
                            struct buffer *buf)
{
    int ret = PUSH_MSG_ERROR;
    const uint8_t ch = buf_read_u8(buf);
    if (ch == ',')
    {
        struct buffer buf_orig = (*buf);
        if (!c->c2.pulled_options_digest_init_done)
        {
            c->c2.pulled_options_state = md_ctx_new();
            md_ctx_init(c->c2.pulled_options_state, "SHA256");
            c->c2.pulled_options_digest_init_done = true;
        }
        if (apply_push_options(&c->options,
                               buf,
                               permission_mask,
                               option_types_found,
                               c->c2.es))
        {
            push_update_digest(c->c2.pulled_options_state, &buf_orig,
                               &c->options);
            switch (c->options.push_continuation)
            {
                case 0:
                case 1:
                    md_ctx_final(c->c2.pulled_options_state,
                                 c->c2.pulled_options_digest.digest);
                    md_ctx_cleanup(c->c2.pulled_options_state);
                    md_ctx_free(c->c2.pulled_options_state);
                    c->c2.pulled_options_state = NULL;
                    c->c2.pulled_options_digest_init_done = false;
                    ret = PUSH_MSG_REPLY;
                    break;

                case 2:
                    ret = PUSH_MSG_CONTINUATION;
                    break;
            }
        }
    }
    else if (ch == '\0')
    {
        ret = PUSH_MSG_REPLY;
    }
    /* show_settings (&c->options); */
    return ret;
}

int
process_incoming_push_msg(struct context *c,
                          const struct buffer *buffer,
                          bool honor_received_options,
                          unsigned int permission_mask,
                          unsigned int *option_types_found)
{
    struct buffer buf = *buffer;

    if (buf_string_compare_advance(&buf, "PUSH_REQUEST"))
    {
        c->c2.push_request_received = true;
        return process_incoming_push_request(c);
    }
    else if (honor_received_options
             && buf_string_compare_advance(&buf, push_reply_cmd))
    {
        return process_incoming_push_reply(c, permission_mask,
                                           option_types_found, &buf);
    }
    else
    {
        return PUSH_MSG_ERROR;
    }
}


/*
 * Remove iroutes from the push_list.
 */
void
remove_iroutes_from_push_route_list(struct options *o)
{
    if (o && o->push_list.head && (o->iroutes || o->iroutes_ipv6))
    {
        struct gc_arena gc = gc_new();
        struct push_entry *e = o->push_list.head;

        /* cycle through the push list */
        while (e)
        {
            char *p[MAX_PARMS+1];
            bool enable = true;

            /* parse the push item */
            CLEAR(p);
            if (e->enable
                && parse_line(e->option, p, SIZE(p)-1, "[PUSH_ROUTE_REMOVE]", 1, D_ROUTE_DEBUG, &gc))
            {
                /* is the push item a route directive? */
                if (p[0] && !strcmp(p[0], "route") && !p[3] && o->iroutes)
                {
                    /* get route parameters */
                    bool status1, status2;
                    const in_addr_t network = getaddr(GETADDR_HOST_ORDER, p[1], 0, &status1, NULL);
                    const in_addr_t netmask = getaddr(GETADDR_HOST_ORDER, p[2] ? p[2] : "255.255.255.255", 0, &status2, NULL);

                    /* did route parameters parse correctly? */
                    if (status1 && status2)
                    {
                        const struct iroute *ir;

                        /* does route match an iroute? */
                        for (ir = o->iroutes; ir != NULL; ir = ir->next)
                        {
                            if (network == ir->network && netmask == netbits_to_netmask(ir->netbits >= 0 ? ir->netbits : 32))
                            {
                                enable = false;
                                break;
                            }
                        }
                    }
                }
                else if (p[0] && !strcmp(p[0], "route-ipv6") && !p[2]
                         && o->iroutes_ipv6)
                {
                    /* get route parameters */
                    struct in6_addr network;
                    unsigned int netbits;

                    /* parse route-ipv6 arguments */
                    if (get_ipv6_addr(p[1], &network, &netbits, D_ROUTE_DEBUG))
                    {
                        struct iroute_ipv6 *ir;

                        /* does this route-ipv6 match an iroute-ipv6? */
                        for (ir = o->iroutes_ipv6; ir != NULL; ir = ir->next)
                        {
                            if (!memcmp(&network, &ir->network, sizeof(network))
                                && netbits == ir->netbits)
                            {
                                enable = false;
                                break;
                            }
                        }
                    }
                }

                /* should we copy the push item? */
                e->enable = enable;
                if (!enable)
                {
                    msg(D_PUSH, "REMOVE PUSH ROUTE: '%s'", e->option);
                }
            }

            e = e->next;
        }

        gc_free(&gc);
    }
}
