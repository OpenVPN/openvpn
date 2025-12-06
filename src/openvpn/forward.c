/*
 *  OpenVPN -- An application to securely tunnel IP networks
 *             over a single TCP/UDP port, with support for SSL/TLS-based
 *             session authentication and key exchange,
 *             packet encryption, packet authentication, and
 *             packet compression.
 *
 *  Copyright (C) 2002-2025 OpenVPN Inc <sales@openvpn.net>
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
 *  with this program; if not, see <https://www.gnu.org/licenses/>.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "syshead.h"

#include "forward.h"
#include "init.h"
#include "push.h"
#include "gremlin.h"
#include "mss.h"
#include "event.h"
#include "occ.h"
#include "otime.h"
#include "ping.h"
#include "ps.h"
#include "dhcp.h"
#include "common.h"
#include "ssl_verify.h"
#include "dco.h"
#include "auth_token.h"
#include "tun_afunix.h"

#include "memdbg.h"

#include <sys/select.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <pthread.h>

counter_type link_read_bytes_global;  /* GLOBAL */
counter_type link_write_bytes_global; /* GLOBAL */

static void
check_tls_errors_co(struct context *c)
{
    msg(D_STREAM_ERRORS, "Fatal TLS error (check_tls_errors_co), restarting");
    register_signal(c->sig, c->c2.tls_exit_signal, "tls-error"); /* SOFT-SIGUSR1 -- TLS error */
}

static void
check_tls_errors_nco(struct context *c)
{
    register_signal(c->sig, c->c2.tls_exit_signal, "tls-error"); /* SOFT-SIGUSR1 -- TLS error */
}

/*
 * TLS errors are fatal in TCP mode.
 * Also check for --tls-exit trigger.
 */
static inline void
check_tls_errors(struct context *c)
{
    if (c->c2.tls_multi && c->c2.tls_exit_signal)
    {
        if (link_socket_connection_oriented(c->c2.link_sockets[0]))
        {
            if (c->c2.tls_multi->n_soft_errors)
            {
                check_tls_errors_co(c);
            }
        }
        else
        {
            if (c->c2.tls_multi->n_hard_errors)
            {
                check_tls_errors_nco(c);
            }
        }
    }
}

/*
 * Set our wakeup to 0 seconds, so we will be rescheduled
 * immediately.
 */
static inline void
context_immediate_reschedule(struct context *c)
{
    c->c2.timeval.tv_sec = 0; /* ZERO-TIMEOUT */
    c->c2.timeval.tv_usec = 0;
}

static inline void
context_reschedule_sec(struct context *c, time_t sec)
{
    if (sec < 0)
    {
        sec = 0;
    }
    if (sec < c->c2.timeval.tv_sec)
    {
        c->c2.timeval.tv_sec = (tv_sec_t)sec;
        c->c2.timeval.tv_usec = 0;
    }
}

void
check_dco_key_status(struct context *c)
{
    /* DCO context is not yet initialised or enabled */
    if (!dco_enabled(&c->options))
    {
        return;
    }

    /* no active peer (p2p tls-server mode) */
    if (c->c2.tls_multi->dco_peer_id == -1)
    {
        return;
    }

    if (!dco_update_keys(&c->c1.tuntap->dco, c->c2.tls_multi))
    {
        /* Something bad happened. Kill the connection to
         * be able to recover. */
        register_signal(c->sig, SIGUSR1, "dco update keys error");
    }
}

/*
 * In TLS mode, let TLS level respond to any control-channel
 * packets which were received, or prepare any packets for
 * transmission.
 *
 * tmp_int is purely an optimization that allows us to call
 * tls_multi_process less frequently when there's not much
 * traffic on the control-channel.
 *
 */
static void
check_tls(struct context *c)
{
    if (!c->c2.tls_multi) { return; }

    interval_t wakeup = LOOP_WAIT;

    if (interval_test(&c->c2.tmp_int))
    {
        const int tmp_status = tls_multi_process(c->c2.tls_multi, &c->c2.to_link, &c->c2.to_link_addr, get_link_socket_info(c), &wakeup);

        if (tmp_status == TLSMP_RECONNECT)
        {
            event_timeout_init(&c->c2.wait_for_connect, 1, now);
            reset_coarse_timers(c);
        }

        if (tmp_status == TLSMP_ACTIVE || tmp_status == TLSMP_RECONNECT)
        {
            update_time();
            interval_action(&c->c2.tmp_int);
        }

        else if (tmp_status == TLSMP_KILL)
        {
            if (c->options.mode == MODE_SERVER)
            {
                send_auth_failed(c, c->c2.tls_multi->client_reason);
            }
            else
            {
                register_signal(c->sig, SIGTERM, "auth-control-exit");
            }
        }

        interval_future_trigger(&c->c2.tmp_int, wakeup);
    }

    interval_schedule_wakeup(&c->c2.tmp_int, &wakeup);

    /*
     * Our current code has no good hooks in the TLS machinery to update
     * DCO keys. So we check the key status after the whole TLS machinery
     * has been completed and potentially update them
     *
     * We have a hidden state transition from secondary to primary key based
     * on ks->auth_deferred_expire that DCO needs to check that the normal
     * TLS state engine does not check. So we call the \c check_dco_key_status
     * function even if tmp_status does not indicate that something has changed.
     */
    check_dco_key_status(c);

    if (wakeup)
    {
        context_reschedule_sec(c, wakeup);
    }
}

static void
parse_incoming_control_channel_command(struct context *c, struct buffer *buf)
{
    if (buf_string_match_head_str(buf, "AUTH_FAILED"))
    {
        receive_auth_failed(c, buf);
    }
    else if (buf_string_match_head_str(buf, "PUSH_"))
    {
        incoming_push_message(c, buf);
    }
    else if (buf_string_match_head_str(buf, "RESTART"))
    {
        server_pushed_signal(c, buf, true, 7);
    }
    else if (buf_string_match_head_str(buf, "HALT"))
    {
        server_pushed_signal(c, buf, false, 4);
    }
    else if (buf_string_match_head_str(buf, "INFO_PRE"))
    {
        server_pushed_info(buf, 8);
    }
    else if (buf_string_match_head_str(buf, "INFO"))
    {
        server_pushed_info(buf, 4);
    }
    else if (buf_string_match_head_str(buf, "CR_RESPONSE"))
    {
        receive_cr_response(c, buf);
    }
    else if (buf_string_match_head_str(buf, "AUTH_PENDING"))
    {
        receive_auth_pending(c, buf);
    }
    else if (buf_string_match_head_str(buf, "EXIT"))
    {
        receive_exit_message(c);
    }
    else
    {
        msg(D_PUSH_ERRORS, "WARNING: Received unknown control message: %s", BSTR(buf));
    }
}

/*
 * Handle incoming configuration
 * messages on the control channel.
 */
static void
check_tls_control_channel(struct context *c)
{
    if (!c->c2.tls_multi) { return; }

    int len = tls_test_payload_len(c->c2.tls_multi);
    if (len < 1) { return; }

    struct gc_arena gc = gc_new();
    struct buffer buf = alloc_buf_gc(len, &gc);
    while (tls_rec_payload(c->c2.tls_multi, &buf))
    {
        while (BLEN(&buf) > 1)
        {
            struct buffer cmdbuf = extract_command_buffer(&buf, &gc);

            if (cmdbuf.len > 0)
            {
                parse_incoming_control_channel_command(c, &cmdbuf);
            }
        }
    }

    gc_free(&gc);
}

/*
 * Periodically resend PUSH_REQUEST until PUSH message received
 */
static void
check_push_request(struct context *c)
{
    send_push_request(c);

    /* if no response to first push_request, retry at PUSH_REQUEST_INTERVAL second intervals */
    event_timeout_modify_wakeup(&c->c2.push_request_interval, PUSH_REQUEST_INTERVAL);
}

/*
 * Things that need to happen immediately after connection initiation should go here.
 *
 * Options like --up-delay need to be triggered by this function which
 * checks for connection establishment.
 *
 * Note: The process_incoming_push_reply currently assumes that this function
 * only sets up the pull request timer when pull is enabled.
 */
static void
check_connection_established(struct context *c)
{
    if (connection_established(c))
    {
        /* if --pull was specified, send a push request to server */
        if (c->c2.tls_multi && c->options.pull)
        {
#ifdef ENABLE_MANAGEMENT
            if (management)
            {
                management_set_state(management, OPENVPN_STATE_GET_CONFIG, NULL, NULL, NULL, NULL,
                                     NULL);
            }
#endif
            /* fire up push request right away (already 1s delayed) */
            /* We might receive a AUTH_PENDING request before we armed this
             * timer. In that case we don't change the value */
            if (c->c2.push_request_timeout < now)
            {
                c->c2.push_request_timeout = now + c->options.handshake_window;
            }
            event_timeout_init(&c->c2.push_request_interval, 0, now);
            reset_coarse_timers(c);
        }
        else
        {
            if (!do_up(c, false, 0))
            {
                register_signal(c->sig, SIGUSR1, "connection initialisation failed");
            }
        }

        event_timeout_clear(&c->c2.wait_for_connect);
    }
}

bool
send_control_channel_string_dowork(struct tls_multi *multi, struct key_state *ks, const char *str, msglvl_t msglevel)
{
    struct gc_arena gc = gc_new();
    bool stat;

    ASSERT(multi);

    /* buffered cleartext write onto TLS control channel */
    stat = tls_send_payload(ks, (uint8_t *)str, strlen(str) + 1);

    msg(msglevel, "SENT CONTROL [%s]: '%s' (status=%d)",
        multi->common_name ? multi->common_name : "UNDEF", sanitize_control_message(str, &gc),
        (int)stat);

    gc_free(&gc);
    return stat;
}

void
reschedule_multi_process(struct context *c)
{
    interval_action(&c->c2.tmp_int);
    context_immediate_reschedule(c); /* ZERO-TIMEOUT */
}

bool
send_control_channel_string(struct context *c, const char *str, msglvl_t msglevel)
{
    struct tls_multi *multi = c->c2.tls_multi;
    if (multi)
    {
        struct key_state *ks = tls_select_encryption_key_init(multi);
        bool ret = send_control_channel_string_dowork(multi, ks, str, msglevel);
        reschedule_multi_process(c);
        return ret;
    }
    return true;
}
/*
 * Add routes.
 */

static void
check_add_routes_action(struct context *c, const bool errors)
{
    bool route_status = do_route(&c->options, c->c1.route_list, c->c1.route_ipv6_list, c->c1.tuntap,
                                 c->plugins, c->c2.es, &c->net_ctx);

    int flags = (errors ? ISC_ERRORS : 0);
    flags |= (!route_status ? ISC_ROUTE_ERRORS : 0);

    update_time();
    event_timeout_clear(&c->c2.route_wakeup);
    event_timeout_clear(&c->c2.route_wakeup_expire);
    initialization_sequence_completed(c, flags); /* client/p2p --route-delay was defined */
}

static void
check_add_routes(struct context *c)
{
    if (test_routes(c->c1.route_list, c->c1.tuntap))
    {
        check_add_routes_action(c, false);
    }
    else if (event_timeout_trigger(&c->c2.route_wakeup_expire, &c->c2.timeval, ETT_DEFAULT))
    {
        check_add_routes_action(c, true);
    }
    else
    {
        msg(D_ROUTE, "Route: Waiting for TUN/TAP interface to come up...");
        if (c->c1.tuntap)
        {
            if (!tun_standby(c->c1.tuntap))
            {
                register_signal(c->sig, SIGHUP, "ip-fail");
                c->persist.restart_sleep_seconds = 10;
            }
        }
        update_time();
        if (c->c2.route_wakeup.n != 1)
        {
            event_timeout_init(&c->c2.route_wakeup, 1, now);
        }
    }
}

int
get_server_poll_remaining_time(struct event_timeout *server_poll_timeout)
{
    update_time();
    int remaining = event_timeout_remaining(server_poll_timeout);
    return max_int(0, remaining);
}

static void
check_server_poll_timeout(struct context *c)
{
    event_timeout_reset(&c->c2.server_poll_interval);
    ASSERT(c->c2.tls_multi);
    if (!tls_initial_packet_received(c->c2.tls_multi))
    {
        msg(M_INFO, "Server poll timeout, restarting");
        register_signal(c->sig, SIGUSR1, "server_poll");
        c->persist.restart_sleep_seconds = -1;
    }
}

/*
 * Schedule a SIGTERM signal c->options.scheduled_exit_interval seconds from now.
 */
bool
schedule_exit(struct context *c)
{
    const int n_seconds = c->options.scheduled_exit_interval;
    /* don't reschedule if already scheduled. */
    if (event_timeout_defined(&c->c2.scheduled_exit))
    {
        return false;
    }
    tls_set_single_session(c->c2.tls_multi);
    update_time();
    reset_coarse_timers(c);
    event_timeout_init(&c->c2.scheduled_exit, n_seconds, now);
    c->c2.scheduled_exit_signal = SIGTERM;
    msg(D_SCHED_EXIT, "Delayed exit in %d seconds", n_seconds);
    return true;
}

/*
 * Scheduled exit?
 */
static void
check_scheduled_exit(struct context *c)
{
    register_signal(c->sig, c->c2.scheduled_exit_signal, "delayed-exit");
}

/*
 * Should we write timer-triggered status file.
 */
static void
check_status_file(struct context *c)
{
    if (c->c1.status_output)
    {
        print_status(c, c->c1.status_output);
    }
}

/*
 * Buffer reallocation, for use with null encryption.
 */
static inline void
buffer_turnover(const uint8_t *orig_buf, struct buffer *dest_stub, struct buffer *src_stub,
                struct buffer *storage)
{
    if (orig_buf == src_stub->data && src_stub->data != storage->data)
    {
        buf_assign(storage, src_stub);
        *dest_stub = *storage;
    }
    else
    {
        *dest_stub = *src_stub;
    }
}

uint8_t *buff_prepsize(uint8_t *buff, int *size)
{
    buff[0] = (uint8_t)((*size >> 8) & 0xff);
    buff[1] = (uint8_t)((*size >> 0) & 0xff);
    buff += 2;
    return buff;
}

uint8_t *buff_postsize(uint8_t *buff, int *size)
{
    *size = ((buff[0] << 8) + (buff[1] << 0));
    buff += 2;
    return buff;
}

/*
 * Compress, fragment, encrypt and HMAC-sign an outgoing packet.
 * Input: c->c2.buf
 * Output: c->c2.to_link
 */
void
encrypt_sign(struct context *c, bool comp_frag)
{
    struct context_buffers *b = c->c2.buffers;
    const uint8_t *orig_buf = c->c2.buf.data;
    struct crypto_options *co = NULL;
    int op_v = (!c->c2.tls_multi->use_peer_id) ? 0 : 1;
    op_v = (!c->c2.tls_multi->send_buf_key) ? op_v : 2;

    if (dco_enabled(&c->options))
    {
        msg(M_WARN, "Attempting to send data packet while data channel offload is in use. "
                    "Dropping packet");
        c->c2.buf.len = 0;
    }

    /*
     * Drop non-TLS outgoing packet if client-connect script/plugin
     * has not yet succeeded. In non-TLS tls_multi mode is not defined
     * and we always pass packets.
     */
    if (c->c2.tls_multi && c->c2.tls_multi->multi_state < CAS_CONNECT_DONE)
    {
        c->c2.buf.len = 0;
    }

    if (comp_frag)
    {
#ifdef USE_COMP
        /* Compress the packet. */
        if (c->c2.comp_context)
        {
            (*c->c2.comp_context->alg.compress)(&c->c2.buf, b->compress_buf, c->c2.comp_context,
                                                &c->c2.frame);
        }
#endif
    }

    /* initialize work buffer with buf.headroom bytes of prepend capacity */
    ASSERT(buf_init(&b->encrypt_buf, c->c2.frame.buf.headroom));

    if (c->c2.tls_multi)
    {
        /* Get the key we will use to encrypt the packet. */
        tls_pre_encrypt(c->c2.tls_multi, &c->c2.buf, &co);
        /* If using P_DATA_V2, prepend the 1-byte opcode and 3-byte peer-id to the
         * packet before openvpn_encrypt(), so we can authenticate the opcode too.
         */
        if (c->c2.buf.len > 0 && op_v == 1)
        {
            tls_prepend_opcode_v2(c->c2.tls_multi, &b->encrypt_buf);
        }
        if (c->c2.buf.len > 0 && op_v == 2)
        {
            tls_prepend_opcode_k1(c->c2.tls_multi, &b->encrypt_buf);
        }
    }
    else
    {
        co = &c->c2.crypto_options;
    }

    /* Encrypt and authenticate the packet */
    openvpn_encrypt(&c->c2.buf, b->encrypt_buf, co);

    /* Do packet administration */
    if (c->c2.tls_multi)
    {
        if (c->c2.buf.len > 0 && op_v == 0)
        {
            tls_prepend_opcode_v1(c->c2.tls_multi, &c->c2.buf);
        }
        tls_post_encrypt(c->c2.tls_multi, &c->c2.buf);
    }

    /*
     * Get the address we will be sending the packet to.
     */
    link_socket_get_outgoing_addr(&c->c2.buf, get_link_socket_info(c), &c->c2.to_link_addr);

    /* if null encryption, copy result to read_tun_buf */
    buffer_turnover(orig_buf, &c->c2.to_link, &c->c2.buf, &b->read_tun_buf);
}

/*
 * Coarse timers work to 1 second resolution.
 */
static void
process_coarse_timers(struct context *c)
{
    /* flush current packet-id to file once per 60
     * seconds if --replay-persist was specified */
    if (packet_id_persist_enabled(&c->c1.pid_persist)
        && event_timeout_trigger(&c->c2.packet_id_persist_interval, &c->c2.timeval, ETT_DEFAULT))
    {
        packet_id_persist_save(&c->c1.pid_persist);
    }

    /* Should we write timer-triggered status file */
    if (c->c1.status_output
        && event_timeout_trigger(&c->c1.status_output->et, &c->c2.timeval, ETT_DEFAULT))
    {
        check_status_file(c);
    }

    /* process connection establishment items */
    if (event_timeout_trigger(&c->c2.wait_for_connect, &c->c2.timeval, ETT_DEFAULT))
    {
        check_connection_established(c);
    }

    /* see if we should send a push_request (option --pull) */
    if (event_timeout_trigger(&c->c2.push_request_interval, &c->c2.timeval, ETT_DEFAULT))
    {
        check_push_request(c);
    }

    /* process --route options */
    if (event_timeout_trigger(&c->c2.route_wakeup, &c->c2.timeval, ETT_DEFAULT))
    {
        check_add_routes(c);
    }

    /* check if we want to refresh the auth-token */
    if (event_timeout_trigger(&c->c2.auth_token_renewal_interval, &c->c2.timeval, ETT_DEFAULT))
    {
        check_send_auth_token(c);
    }

    if (c->sig->signal_received)
    {
        return;
    }

    if (c->c2.tls_multi)
    {
        if (c->options.ce.connect_timeout
            && event_timeout_trigger(&c->c2.server_poll_interval, &c->c2.timeval, ETT_DEFAULT))
        {
            check_server_poll_timeout(c);
        }
        if (c->sig->signal_received)
        {
            return;
        }
        if (event_timeout_trigger(&c->c2.scheduled_exit, &c->c2.timeval, ETT_DEFAULT))
        {
            check_scheduled_exit(c);
        }
        if (c->sig->signal_received)
        {
            return;
        }
    }

    /* Should we send an OCC_EXIT message to remote? */
    if (c->c2.explicit_exit_notification_time_wait)
    {
        process_explicit_exit_notification_timer_wakeup(c);
    }

#ifdef ENABLE_MANAGEMENT
    if (management)
    {
        management_check_bytecount_client(c, management, &c->c2.timeval);
    }
#endif /* ENABLE_MANAGEMENT */
}

static void
check_coarse_timers(struct context *c)
{
    if (now < c->c2.coarse_timer_wakeup)
    {
        context_reschedule_sec(c, c->c2.coarse_timer_wakeup - now);
        return;
    }

    const struct timeval save = c->c2.timeval;
    c->c2.timeval.tv_sec = LOOP_WAIT;
    c->c2.timeval.tv_usec = 0;
    process_coarse_timers(c);
    c->c2.coarse_timer_wakeup = now + c->c2.timeval.tv_sec;

    dmsg(D_INTERVAL, "TIMER: coarse timer wakeup %" PRIi64 " seconds",
         (int64_t)c->c2.timeval.tv_sec);

    /* Is the coarse timeout NOT the earliest one? */
    if (c->c2.timeval.tv_sec > save.tv_sec)
    {
        c->c2.timeval = save;
    }
}

static void
check_timeout_random_component_dowork(struct context *c)
{
    const int update_interval = 10; /* seconds */
    c->c2.update_timeout_random_component = now + update_interval;
    c->c2.timeout_random_component.tv_usec = (time_t)get_random() & 0x0003FFFF;
    c->c2.timeout_random_component.tv_sec = 0;

    dmsg(D_INTERVAL, "RANDOM USEC=%ld", (long)c->c2.timeout_random_component.tv_usec);
}

static inline void
check_timeout_random_component(struct context *c)
{
    if (now >= c->c2.update_timeout_random_component)
    {
        check_timeout_random_component_dowork(c);
    }
    if (c->c2.timeval.tv_sec >= 1)
    {
        tv_add(&c->c2.timeval, &c->c2.timeout_random_component);
    }
}

/*
 * Output: c->c2.buf2
 */

void
read_incoming_link(struct context *c, struct link_socket *sock)
{
    /*
     * Set up for recvfrom call to read datagram
     * sent to our TCP/UDP port.
     */
    int status;

    /*ASSERT (!c->c2.to_tun.len);*/

    c->c2.buf2 = c->c2.buffers->read_link_buf;
    ASSERT(buf_init(&c->c2.buf2, c->c2.frame.buf.headroom));

    status = link_socket_read(sock, &c->c2.buf2, &c->c2.from);

    if (socket_connection_reset(sock, status))
    {
#if PORT_SHARE
        if (port_share && socket_foreign_protocol_detected(sock))
        {
            const struct buffer *fbuf = socket_foreign_protocol_head(sock);
            const int sd = socket_foreign_protocol_sd(sock);
            port_share_redirect(port_share, fbuf, sd);
            register_signal(c->sig, SIGTERM, "port-share-redirect");
        }
        else
#endif
        {
            /* received a disconnect from a connection-oriented protocol */
            if (event_timeout_defined(&c->c2.explicit_exit_notification_interval))
            {
                msg(D_STREAM_ERRORS,
                    "Connection reset during exit notification period, ignoring [%d]", status);
                management_sleep(1);
            }
            else
            {
                register_signal(c->sig, SIGUSR1,
                                "connection-reset"); /* SOFT-SIGUSR1 -- TCP connection reset */
                msg(D_STREAM_ERRORS, "Connection reset, restarting [%d]", status);
            }
        }
        return;
    }

    /* check recvfrom status */
    check_status(status, "read", sock, NULL);
}

bool
process_incoming_link_part1(struct context *c, struct link_socket_info *lsi, bool floated)
{
    struct gc_arena gc = gc_new();
    bool decrypt_status = false;
    uint8_t opcode = 0;

    if (c->c2.buf2.len > 0)
    {
        c->c2.link_read_bytes += c->c2.buf2.len;
        link_read_bytes_global += c->c2.buf2.len;
        c->c2.original_recv_size = c->c2.buf2.len;
    }

    else
    {
        c->c2.original_recv_size = 0;
    }

    msg(D_LINK_RW, "%s READ [%d] from %s: %s", proto2ascii(lsi->proto, lsi->af, true),
        BLEN(&c->c2.buf2), print_link_socket_actual(&c->c2.from, &gc), PROTO_DUMP(&c->c2.buf2, &gc));

    /*
     * Good, non-zero length packet received.
     * Commence multi-stage processing of packet,
     * such as authenticate, decrypt, decompress.
     * If any stage fails, it sets buf.len to 0 or -1,
     * telling downstream stages to ignore the packet.
     */
    if (c->c2.buf2.len > 0)
    {
        struct crypto_options *co = NULL;
        const uint8_t *ad_start = NULL;

        if (!link_socket_verify_incoming_addr(&c->c2.buf2, lsi, &c->c2.from))
        {
            link_socket_bad_incoming_addr(&c->c2.buf2, lsi, &c->c2.from);
        }

        if (c->c2.tls_multi)
        {
            opcode = *BPTR(&c->c2.buf2) >> P_OPCODE_SHIFT;

            /*
             * If DCO is enabled, the kernel drivers require that the
             * other end only sends P_DATA_V2 packets. V1 are unknown
             * to kernel and passed to userland, but we cannot handle them
             * either because crypto context is missing - so drop the packet.
             *
             * This can only happen with particular old (2.4.0-2.4.4) servers.
             */
            if ((opcode == P_DATA_V1) && dco_enabled(&c->options))
            {
                msg(D_LINK_ERRORS, "Data Channel Offload doesn't support DATA_V1 packets. "
                                   "Upgrade your server to 2.4.5 or newer.");
                c->c2.buf2.len = 0;
            }

            /*
             * If tls_pre_decrypt returns true, it means the incoming
             * packet was a good TLS control channel packet.  If so, TLS code
             * will deal with the packet and set buf.len to 0 so downstream
             * stages ignore it.
             *
             * If the packet is a data channel packet, tls_pre_decrypt
             * will load crypto_options with the correct encryption key
             * and return false.
             */
            if (tls_pre_decrypt(c->c2.tls_multi, &c->c2.from, &c->c2.buf2, &co, floated, &ad_start))
            {
                interval_action(&c->c2.tmp_int);
            }
        }

        else
        {
            co = &c->c2.crypto_options;
        }

        /*
         * Drop non-TLS packet if client-connect script/plugin and cipher selection
         * has not yet succeeded. In non-TLS mode tls_multi is not defined
         * and we always pass packets.
         */
        if (c->c2.tls_multi && c->c2.tls_multi->multi_state < CAS_CONNECT_DONE)
        {
            c->c2.buf2.len = 0;
        }

        /* authenticate and decrypt the incoming packet */
        decrypt_status = openvpn_decrypt(&c->c2.buf2, c->c2.buffers->decrypt_buf, co, &c->c2.frame, ad_start);

        if (!decrypt_status
            /* on the instance context we have only one socket, so just check the first one */
            && link_socket_connection_oriented(c->c2.link_sockets[0]))
        {
            /* decryption errors are fatal in TCP mode */
            register_signal(c->sig, SIGUSR1,
                            "decryption-error"); /* SOFT-SIGUSR1 -- decryption error in TCP mode */
            msg(D_STREAM_ERRORS, "Fatal decryption error (process_incoming_link), restarting");
        }

        if (opcode == P_KEYS_V1)
        {
            c->c2.tls_multi->plaintext_read_buf.len = 0;
            buf_copy(&c->c2.tls_multi->plaintext_read_buf, &c->c2.buf2);
            c->c2.buf2.len = 0;
        }
    }

    gc_free(&gc);

    return decrypt_status;
}

void
process_incoming_link_part2(struct context *c, struct link_socket_info *lsi, const uint8_t *orig_buf)
{
    if (c->c2.buf2.len > 0)
    {

#ifdef USE_COMP
        /* decompress the incoming packet */
        if (c->c2.comp_context)
        {
            (*c->c2.comp_context->alg.decompress)(&c->c2.buf2, c->c2.buffers->decompress_buf,
                                                  c->c2.comp_context, &c->c2.frame);
        }
#endif

#ifdef PACKET_TRUNCATION_CHECK
        /* if (c->c2.buf2.len > 1) --c->c2.buf2.len; */
        ipv4_packet_size_verify(BPTR(&c->c2.buf2), BLEN(&c->c2.buf2), TUNNEL_TYPE(c->c1.tuntap),
                                "POST_DECRYPT", &c->c2.n_trunc_post_decrypt);
#endif

        /*
         * Set our "official" outgoing address, since
         * if buf.len is non-zero, we know the packet
         * authenticated.  In TLS mode we do nothing
         * because TLS mode takes care of source address
         * authentication.
         *
         * Also, update the persisted version of our packet-id.
         */
        if (!TLS_MODE(c) && c->c2.buf2.len > 0)
        {
            link_socket_set_outgoing_addr(lsi, &c->c2.from, NULL, c->c2.es);
        }

        /* increment authenticated receive byte count */
        if (c->c2.buf2.len > 0)
        {
            c->c2.link_read_bytes_auth += c->c2.buf2.len;
            c->c2.max_recv_size_local =
                max_int(c->c2.original_recv_size, c->c2.max_recv_size_local);
        }

        buffer_turnover(orig_buf, &c->c2.to_tun, &c->c2.buf2, &c->c2.buffers->read_link_buf);

        /* to_tun defined + unopened tuntap can cause deadlock */
        if (!tuntap_defined(c->c1.tuntap))
        {
            c->c2.to_tun.len = 0;
        }
    }
}

void
process_incoming_link(struct context *c, struct link_socket *sock)
{
    struct link_socket_info *lsi = &sock->info;
    const uint8_t *orig_buf = c->c2.buf2.data;

    process_incoming_link_part1(c, lsi, false);
    process_incoming_link_part2(c, lsi, orig_buf);

    c->c2.buf2.len = 0;
}

void
extract_dco_float_peer_addr(const sa_family_t socket_family, struct openvpn_sockaddr *out_osaddr,
                            const struct sockaddr *float_sa)
{
    if (float_sa->sa_family == AF_INET)
    {
        struct sockaddr_in *float4 = (struct sockaddr_in *)float_sa;
        /* DCO treats IPv4-mapped IPv6 addresses as pure IPv4. However, on a
         * dual-stack socket, we need to preserve the mapping otherwise openvpn
         * will not be able to find the peer by its transport address.
         */
        if (socket_family == AF_INET6)
        {
            out_osaddr->addr.in6.sin6_family = AF_INET6;
            out_osaddr->addr.in6.sin6_port = float4->sin_port;

            memset(&out_osaddr->addr.in6.sin6_addr.s6_addr, 0, 10);
            out_osaddr->addr.in6.sin6_addr.s6_addr[10] = 0xff;
            out_osaddr->addr.in6.sin6_addr.s6_addr[11] = 0xff;
            memcpy(&out_osaddr->addr.in6.sin6_addr.s6_addr[12], &float4->sin_addr.s_addr,
                   sizeof(in_addr_t));
        }
        else
        {
            memcpy(&out_osaddr->addr.in4, float4, sizeof(struct sockaddr_in));
        }
    }
    else
    {
        struct sockaddr_in6 *float6 = (struct sockaddr_in6 *)float_sa;
        memcpy(&out_osaddr->addr.in6, float6, sizeof(struct sockaddr_in6));
    }
}

void
process_incoming_dco(dco_context_t *dco)
{
#if defined(ENABLE_DCO) && (defined(TARGET_LINUX) || defined(TARGET_FREEBSD))
    struct context *c = dco->c;

    /* FreeBSD currently sends us removal notifcation with the old peer-id in
     * p2p mode with the ping timeout reason, so ignore that one to not shoot
     * ourselves in the foot and removing the just established session */
    if (dco->dco_message_peer_id != c->c2.tls_multi->dco_peer_id)
    {
        msg(D_DCO_DEBUG,
            "%s: received message for mismatching peer-id %d, "
            "expected %d",
            __func__, dco->dco_message_peer_id, c->c2.tls_multi->dco_peer_id);
        return;
    }

    switch (dco->dco_message_type)
    {
        case OVPN_CMD_DEL_PEER:
            /* peer is gone, unset ID to prevent more kernel calls */
            c->c2.tls_multi->dco_peer_id = -1;
            if (dco->dco_del_peer_reason == OVPN_DEL_PEER_REASON_EXPIRED)
            {
                msg(D_DCO_DEBUG,
                    "%s: received peer expired notification of for peer-id "
                    "%d",
                    __func__, dco->dco_message_peer_id);
                return;
            }
            break;

        case OVPN_CMD_SWAP_KEYS:
            msg(D_DCO_DEBUG, "%s: received key rotation notification for peer-id %d", __func__,
                dco->dco_message_peer_id);
            tls_session_soft_reset(c->c2.tls_multi);
            break;

        default:
            msg(D_DCO_DEBUG, "%s: received message of type %u - ignoring", __func__,
                dco->dco_message_type);
            return;
    }

#endif /* if defined(ENABLE_DCO) && (defined(TARGET_LINUX) || defined(TARGET_FREEBSD)) */
}

#if defined(__GNUC__) || defined(__clang__)
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wconversion"
#endif

/*
 * Output: c->c2.buf
 */

void
read_incoming_tun_part2(struct context *c)
{
    /*
     * Setup for read() call on TUN/TAP device.
     */
    /*ASSERT (!c->c2.to_link.len);*/

    c->c2.buf = c->c2.buffers->read_tun_buf;

    ASSERT(buf_init(&c->c2.buf, c->c2.frame.buf.headroom));
    ASSERT(buf_safe(&c->c2.buf, c->c2.frame.buf.payload_size));
    if (c->c1.tuntap->backend_driver == DRIVER_AFUNIX)
    {
        c->c2.buf.len = read_tun_afunix(c->c1.tuntap, BPTR(&c->c2.buf), c->c2.frame.buf.payload_size);
    }
    else
    {
        c->c2.buf.len = read_tun(c->c1.tuntap, BPTR(&c->c2.buf), c->c2.frame.buf.payload_size);
    }

#ifdef PACKET_TRUNCATION_CHECK
    ipv4_packet_size_verify(BPTR(&c->c2.buf), BLEN(&c->c2.buf), TUNNEL_TYPE(c->c1.tuntap),
                            "READ_TUN", &c->c2.n_trunc_tun_read);
#endif

    /* Was TUN/TAP interface stopped? */
    if (tuntap_stop(c->c2.buf.len))
    {
        register_signal(c->sig, SIGTERM, "tun-stop");
        msg(M_INFO, "TUN/TAP interface has been stopped, exiting");
        return;
    }

    /* Was TUN/TAP I/O operation aborted? */
    if (tuntap_abort(c->c2.buf.len))
    {
        register_signal(c->sig, SIGHUP, "tun-abort");
        c->persist.restart_sleep_seconds = 10;
        msg(M_INFO, "TUN/TAP I/O operation aborted, restarting");
        return;
    }

    /* Check the status return from read() */
    check_status(c->c2.buf.len, "read from TUN/TAP", NULL, c->c1.tuntap);
}

void read_incoming_tun_part3(struct context *c)
{
    fd_set rfds;
    struct timeval timo;
    int plen = 0, pidx = -1;
    int fdno = c->c1.tuntap->fd;
    for (int x = 0; x < TUN_BAT_MIN; ++x)
    {
        int leng = plen, indx = (pidx + 1);
        if (leng < 1)
        {
            FD_ZERO(&rfds);
            FD_SET(fdno, &rfds);
            timo.tv_sec = 0;
            timo.tv_usec = 0;
            select(fdno+1, &rfds, NULL, NULL, &timo);
            if (FD_ISSET(fdno, &rfds))
            {
                read_incoming_tun_part2(c);
                plen = BLEN(&c->c2.buf);
            }
            else
            {
                break;
            }
        }
        leng = plen;
        if (leng > 0)
        {
            c->c2.buffers->read_tun_bufs[indx].offset = TUN_BAT_OFF;
            c->c2.buffers->read_tun_bufs[indx].len = leng;
            bcopy(BPTR(&c->c2.buf), BPTR(&c->c2.buffers->read_tun_bufs[indx]), leng);
            c->c2.bufs[indx] = c->c2.buffers->read_tun_bufs[indx];
            pidx = indx;
        }
        else
        {
            break;
        }
        plen = 0;
    }
    c->c2.buffers->bulk_indx = 0;
    c->c2.buffers->bulk_leng = (pidx + 1);
}

void read_incoming_tun(struct context *c)
{
    if (!BULK_MODE(c))
    {
        read_incoming_tun_part2(c);
    }
    else
    {
        read_incoming_tun_part3(c);
    }
}

/**
 * Drops UDP packets which OS decided to route via tun.
 *
 * On Windows and OS X when netwotk adapter is disabled or
 * disconnected, platform starts to use tun as external interface.
 * When packet is sent to tun, it comes to openvpn, encapsulated
 * and sent to routing table, which sends it again to tun.
 */
static void
drop_if_recursive_routing(struct context *c, struct buffer *buf)
{
    if (c->c2.to_link_addr == NULL) /* no remote addr known */
    {
        return;
    }

    struct openvpn_sockaddr *link_addr = &c->c2.to_link_addr->dest;
    struct link_socket_info *lsi = get_link_socket_info(c);

    int ip_hdr_offset = 0;
    int tun_ip_ver = get_tun_ip_ver(TUNNEL_TYPE(c->c1.tuntap), buf, &ip_hdr_offset);

    if (tun_ip_ver == 4)
    {
        /* Ensure we can safely read the IPv4 header */
        const int min_ip_header = ip_hdr_offset + sizeof(struct openvpn_iphdr);
        if (BLEN(buf) < min_ip_header)
        {
            return;
        }

        struct openvpn_iphdr *pip = (struct openvpn_iphdr *)(BPTR(buf) + ip_hdr_offset);
        const int ip_hlen = OPENVPN_IPH_GET_LEN(pip->version_len);
        /* Reject malformed or truncated headers */
        if (ip_hlen < sizeof(struct openvpn_iphdr)
            || BLEN(buf) < (int)(ip_hdr_offset + ip_hlen + sizeof(uint16_t) * 2))
        {
            return;
        }

        /* skip ipv4 packets for ipv6 tun */
        if (link_addr->addr.sa.sa_family != AF_INET)
        {
            return;
        }

        /* skip if tun protocol doesn't match link protocol */
        if ((lsi->proto == PROTO_TCP && pip->protocol != OPENVPN_IPPROTO_TCP)
            || (lsi->proto == PROTO_UDP && pip->protocol != OPENVPN_IPPROTO_UDP))
        {
            return;
        }

        /* drop packets with same dest addr and port as remote */
        uint8_t *l4_hdr = (uint8_t *)pip + ip_hlen;

        uint16_t link_port = ntohs(link_addr->addr.in4.sin_port);

        /* TCP and UDP ports are at the same place in the header, and other protocols
         * can not happen here due to the lsi->proto check above */
        uint16_t src_port = ntohs(*(uint16_t *)l4_hdr);
        uint16_t dst_port = ntohs(*(uint16_t *)(l4_hdr + sizeof(uint16_t)));
        if ((memcmp(&link_addr->addr.in4.sin_addr.s_addr, &pip->daddr, sizeof(pip->daddr)) == 0) && (link_port == dst_port))
        {
            buf->len = 0;

            struct gc_arena gc = gc_new();
            msg(D_LOW, "Recursive routing detected, packet dropped %s:%" PRIu16 " -> %s",
                print_in_addr_t(pip->saddr, IA_NET_ORDER, &gc),
                src_port,
                print_link_socket_actual(c->c2.to_link_addr, &gc));
            gc_free(&gc);
        }
    }
    else if (tun_ip_ver == 6)
    {
        /* make sure we got whole IPv6 header and TCP/UDP src/dst ports */
        const int min_ipv6 = ip_hdr_offset + sizeof(struct openvpn_ipv6hdr) + sizeof(uint16_t) * 2;
        if (BLEN(buf) < min_ipv6)
        {
            return;
        }

        /* skip ipv6 packets for ipv4 tun */
        if (link_addr->addr.sa.sa_family != AF_INET6)
        {
            return;
        }

        struct openvpn_ipv6hdr *pip6 = (struct openvpn_ipv6hdr *)(BPTR(buf) + ip_hdr_offset);

        /* skip if tun protocol doesn't match link protocol */
        if ((lsi->proto == PROTO_TCP && pip6->nexthdr != OPENVPN_IPPROTO_TCP)
            || (lsi->proto == PROTO_UDP && pip6->nexthdr != OPENVPN_IPPROTO_UDP))
        {
            return;
        }

        uint16_t link_port = ntohs(link_addr->addr.in6.sin6_port);

        /* drop packets with same dest addr and port as remote */
        uint8_t *l4_hdr = (uint8_t *)pip6 + sizeof(struct openvpn_ipv6hdr);
        uint16_t src_port = ntohs(*(uint16_t *)l4_hdr);
        uint16_t dst_port = ntohs(*(uint16_t *)(l4_hdr + sizeof(uint16_t)));
        if ((OPENVPN_IN6_ARE_ADDR_EQUAL(&link_addr->addr.in6.sin6_addr, &pip6->daddr)) && (link_port == dst_port))
        {
            buf->len = 0;

            struct gc_arena gc = gc_new();
            msg(D_LOW, "Recursive routing detected, packet dropped %s:%" PRIu16 " -> %s",
                print_in6_addr(pip6->saddr, IA_NET_ORDER, &gc),
                src_port,
                print_link_socket_actual(c->c2.to_link_addr, &gc));
            gc_free(&gc);
        }
    }
}

/*
 * Input:  c->c2.buf
 * Output: c->c2.to_link
 */

void
process_incoming_tun_part2(struct context *c, struct link_socket *out_sock)
{
    struct gc_arena gc = gc_new();

    if (c->c2.buf.len > 0)
    {
        c->c2.tun_read_bytes += c->c2.buf.len;
    }

    dmsg(D_TUN_RW, "TUN READ [%d] [%d]", BLEN(&c->c2.buf), c->c2.frame.buf.payload_size);

    if (c->c2.buf.len > 0)
    {
        if ((c->options.mode == MODE_POINT_TO_POINT) && (!c->options.allow_recursive_routing))
        {
            drop_if_recursive_routing(c, &c->c2.buf);
        }
        /*
         * The --passtos and --mssfix options require
         * us to examine the IP header (IPv4 or IPv6).
         */
        unsigned int flags =
            PIPV4_PASSTOS | PIP_MSSFIX | PIPV4_CLIENT_NAT | PIPV6_ICMP_NOHOST_CLIENT;
        process_ip_header(c, flags, &c->c2.buf, out_sock);

#ifdef PACKET_TRUNCATION_CHECK
        /* if (c->c2.buf.len > 1) --c->c2.buf.len; */
        ipv4_packet_size_verify(BPTR(&c->c2.buf), BLEN(&c->c2.buf), TUNNEL_TYPE(c->c1.tuntap),
                                "PRE_ENCRYPT", &c->c2.n_trunc_pre_encrypt);
#endif
    }

    if (c->c2.buf.len > 0)
    {
        if (!BULK_MODE(c))
        {
            encrypt_sign(c, true);
        }
    }

    gc_free(&gc);
}

void process_incoming_tun_part3(struct context *c, struct link_socket *out_sock)
{
    if (BULK_DATA(c->c2.buffers))
    {
        c->c2.buffers->read_tun_max.offset = TUN_BAT_OFF;
        c->c2.buffers->read_tun_max.len = 0;
        uint8_t *temp = BPTR(&c->c2.buffers->read_tun_max);
        int leng = c->c2.buffers->bulk_leng;
        int plen = 0, maxl = 0;
        for (int x = 0; x < leng; ++x)
        {
            c->c2.buf = c->c2.bufs[x];
            process_incoming_tun_part2(c, out_sock);
            plen = BLEN(&c->c2.buf);
            if (plen > 0)
            {
                temp = buff_prepsize(temp, &plen);
                bcopy(BPTR(&c->c2.buf), temp, plen);
                temp += plen; maxl += (plen + 2);
            }
            c->c2.bufs[x].len = 0;
        }
        if (maxl > 0)
        {
            c->c2.buffers->read_tun_max.offset = TUN_BAT_OFF;
            c->c2.buffers->read_tun_max.len = maxl;
            c->c2.buf = c->c2.buffers->read_tun_max;
            encrypt_sign(c, true);
        }
    }
    c->c2.buffers->bulk_indx = -1;
    c->c2.buffers->bulk_leng = -1;
}

void process_incoming_tun(struct context *c, struct link_socket *out_sock)
{
    if (!BULK_MODE(c))
    {
        process_incoming_tun_part2(c, out_sock);
    }
    else
    {
        process_incoming_tun_part3(c, out_sock);
    }

    c->c2.buf.len = 0;
}

/**
 * Forges a IPv6 ICMP packet with a no route to host error code from the
 * IPv6 packet in buf and sends it directly back to the client via the tun
 * device when used on a client and via the link if used on the server.
 *
 * @param c         Tunnel context
 * @param buf       The buf containing the packet for which the icmp6
 *                  unreachable should be constructed.
 * @param client    Determines whether to the send packet back via tun or link
 */
void
ipv6_send_icmp_unreachable(struct context *c, struct buffer *buf, bool client)
{
#define MAX_ICMPV6LEN 1280
    struct openvpn_icmp6hdr icmp6out;
    CLEAR(icmp6out);

    /*
     * Get a buffer to the ip packet, is_ipv6 automatically forwards
     * the buffer to the ip packet
     */
    struct buffer inputipbuf = *buf;

    is_ipv6(TUNNEL_TYPE(c->c1.tuntap), &inputipbuf);

    if (BLEN(&inputipbuf) < (int)sizeof(struct openvpn_ipv6hdr))
    {
        return;
    }

    const struct openvpn_ipv6hdr *pip6 = (struct openvpn_ipv6hdr *)BPTR(&inputipbuf);

    /* Copy version, traffic class, flow label from input packet */
    struct openvpn_ipv6hdr pip6out = *pip6;

    pip6out.version_prio = pip6->version_prio;
    pip6out.daddr = pip6->saddr;

    /*
     * Use the IPv6 remote address if we have one, otherwise use a fake one
     * using the remote address is preferred since it makes debugging and
     * understanding where the ICMPv6 error originates easier
     */
    if (c->options.ifconfig_ipv6_remote)
    {
        inet_pton(AF_INET6, c->options.ifconfig_ipv6_remote, &pip6out.saddr);
    }
    else
    {
        inet_pton(AF_INET6, "fe80::7", &pip6out.saddr);
    }

    pip6out.nexthdr = OPENVPN_IPPROTO_ICMPV6;

    /*
     * The ICMPv6 unreachable code worked best in my (arne) tests with Windows,
     * Linux and Android. Windows did not like the administratively prohibited
     * return code (no fast fail)
     */
    icmp6out.icmp6_type = OPENVPN_ICMP6_DESTINATION_UNREACHABLE;
    icmp6out.icmp6_code = OPENVPN_ICMP6_DU_NOROUTE;

    int icmpheader_len = sizeof(struct openvpn_ipv6hdr) + sizeof(struct openvpn_icmp6hdr);
    int totalheader_len = icmpheader_len;

    if (TUNNEL_TYPE(c->c1.tuntap) == DEV_TYPE_TAP)
    {
        totalheader_len += sizeof(struct openvpn_ethhdr);
    }

    /*
     * Calculate size for payload, defined in the standard that the resulting
     * frame should be <= 1280 and have as much as possible of the original
     * packet
     */
    int max_payload_size = min_int(MAX_ICMPV6LEN, c->c2.frame.tun_mtu - icmpheader_len);
    int payload_len = min_int(max_payload_size, BLEN(&inputipbuf));

    pip6out.payload_len = htons(sizeof(struct openvpn_icmp6hdr) + payload_len);

    /* Construct the packet as outgoing packet back to the client */
    struct buffer *outbuf;
    if (client)
    {
        c->c2.to_tun = c->c2.buffers->aux_buf;
        outbuf = &(c->c2.to_tun);
    }
    else
    {
        c->c2.to_link = c->c2.buffers->aux_buf;
        outbuf = &(c->c2.to_link);
    }
    ASSERT(buf_init(outbuf, totalheader_len));

    /* Fill the end of the buffer with original packet */
    ASSERT(buf_safe(outbuf, payload_len));
    ASSERT(buf_copy_n(outbuf, &inputipbuf, payload_len));

    /* ICMP Header, copy into buffer to allow checksum calculation */
    ASSERT(buf_write_prepend(outbuf, &icmp6out, sizeof(struct openvpn_icmp6hdr)));

    /* Calculate checksum over the packet and write to header */

    uint16_t new_csum =
        ip_checksum(AF_INET6, BPTR(outbuf), BLEN(outbuf), (const uint8_t *)&pip6out.saddr,
                    (uint8_t *)&pip6out.daddr, OPENVPN_IPPROTO_ICMPV6);
    ((struct openvpn_icmp6hdr *)BPTR(outbuf))->icmp6_cksum = htons(new_csum);


    /* IPv6 Header */
    ASSERT(buf_write_prepend(outbuf, &pip6out, sizeof(struct openvpn_ipv6hdr)));

    /*
     * Tap mode, we also need to create an Ethernet header.
     */
    if (TUNNEL_TYPE(c->c1.tuntap) == DEV_TYPE_TAP)
    {
        if (BLEN(buf) < (int)sizeof(struct openvpn_ethhdr))
        {
            return;
        }

        const struct openvpn_ethhdr *orig_ethhdr = (struct openvpn_ethhdr *)BPTR(buf);

        /* Copy frametype and reverse source/destination for the response */
        struct openvpn_ethhdr ethhdr;
        memcpy(ethhdr.source, orig_ethhdr->dest, OPENVPN_ETH_ALEN);
        memcpy(ethhdr.dest, orig_ethhdr->source, OPENVPN_ETH_ALEN);
        ethhdr.proto = htons(OPENVPN_ETH_P_IPV6);
        ASSERT(buf_write_prepend(outbuf, &ethhdr, sizeof(struct openvpn_ethhdr)));
    }
#undef MAX_ICMPV6LEN
}

#if defined(__GNUC__) || defined(__clang__)
#pragma GCC diagnostic pop
#endif

void
process_ip_header(struct context *c, unsigned int flags, struct buffer *buf,
                  struct link_socket *sock)
{
    if (!c->options.ce.mssfix)
    {
        flags &= ~PIP_MSSFIX;
    }
#if PASSTOS_CAPABILITY
    if (!c->options.passtos)
    {
        flags &= ~PIPV4_PASSTOS;
    }
#endif
    if (!c->options.client_nat)
    {
        flags &= ~PIPV4_CLIENT_NAT;
    }
    if (!c->options.route_gateway_via_dhcp)
    {
        flags &= ~PIPV4_EXTRACT_DHCP_ROUTER;
    }
    if (!c->options.block_ipv6)
    {
        flags &= ~(PIPV6_ICMP_NOHOST_CLIENT | PIPV6_ICMP_NOHOST_SERVER);
    }

    if (buf->len > 0)
    {
        struct buffer ipbuf = *buf;
        if (is_ipv4(TUNNEL_TYPE(c->c1.tuntap), &ipbuf))
        {
#if PASSTOS_CAPABILITY
            /* extract TOS from IP header */
            if (flags & PIPV4_PASSTOS)
            {
                link_socket_extract_tos(sock, &ipbuf);
            }
#endif

            /* possibly alter the TCP MSS */
            if (flags & PIP_MSSFIX)
            {
                mss_fixup_ipv4(&ipbuf, c->c2.frame.mss_fix);
            }

            /* possibly do NAT on packet */
            if ((flags & PIPV4_CLIENT_NAT) && c->options.client_nat)
            {
                const int direction = (flags & PIP_OUTGOING) ? CN_INCOMING : CN_OUTGOING;
                client_nat_transform(c->options.client_nat, &ipbuf, direction);
            }
            /* possibly extract a DHCP router message */
            if (flags & PIPV4_EXTRACT_DHCP_ROUTER)
            {
                const in_addr_t dhcp_router = dhcp_extract_router_msg(&ipbuf);
                if (dhcp_router)
                {
                    route_list_add_vpn_gateway(c->c1.route_list, c->c2.es, dhcp_router);
                }
            }
        }
        else if (is_ipv6(TUNNEL_TYPE(c->c1.tuntap), &ipbuf))
        {
            /* possibly alter the TCP MSS */
            if (flags & PIP_MSSFIX)
            {
                mss_fixup_ipv6(&ipbuf, c->c2.frame.mss_fix);
            }
            if (!(flags & PIP_OUTGOING)
                && (flags & (PIPV6_ICMP_NOHOST_CLIENT | PIPV6_ICMP_NOHOST_SERVER)))
            {
                ipv6_send_icmp_unreachable(c, buf, (bool)(flags & PIPV6_ICMP_NOHOST_CLIENT));
                /* Drop the IPv6 packet */
                buf->len = 0;
            }
        }
    }
}

/*
 * Input: c->c2.to_link
 */

void
process_outgoing_link(struct context *c, struct link_socket *sock)
{
    struct gc_arena gc = gc_new();
    int error_code = 0;
    struct buffer og = c->c2.buf;

    if ((!LINK_OUT(c)) && REKEY_OUT(c))
    {
        c->c2.tls_multi->send_buf_key = true;
        c->c2.buf = c->c2.tls_multi->plaintext_send_buf;
        encrypt_sign(c, false);
        c->c2.buf = og;
        c->c2.tls_multi->plaintext_send_buf.len = 0;
        c->c2.tls_multi->send_buf_key = false;
    }

    if (c->c2.to_link.len > 0 && (c->c2.to_link.len <= c->c2.frame.buf.payload_size || c->c2.frame.bulk_size > 0))
    {
        /*
         * Setup for call to send/sendto which will send
         * packet to remote over the TCP/UDP port.
         */
        int size = 0;
        ASSERT(link_socket_actual_defined(c->c2.to_link_addr));

        {
            /*
             * Let the traffic shaper know how many bytes
             * we wrote.
             */
            if (c->options.shaper)
            {
                int overhead =
                    datagram_overhead(c->c2.to_link_addr->dest.addr.sa.sa_family, sock->info.proto);
                shaper_wrote_bytes(&c->c2.shaper, BLEN(&c->c2.to_link) + overhead);
            }

#if PASSTOS_CAPABILITY
            /* Set TOS */
            link_socket_set_tos(sock);
#endif

            msg(D_LINK_RW, "%s WRITE [%d] to %s: %s",
                proto2ascii(sock->info.proto, sock->info.af, true), BLEN(&c->c2.to_link),
                print_link_socket_actual(c->c2.to_link_addr, &gc), PROTO_DUMP(&c->c2.to_link, &gc));

            /* Send packet */
            struct link_socket_actual *to_addr = c->c2.to_link_addr;
            size = (int)link_socket_write(sock, &c->c2.to_link, to_addr);

            if (size > 0)
            {
                c->c2.max_send_size_local = max_int(size, c->c2.max_send_size_local);
                c->c2.link_write_bytes += size;
                link_write_bytes_global += size;
            }
        }

        /* Check return status */
        error_code = openvpn_errno();
        check_status(size, "write", sock, NULL);

        if (size > 0)
        {
            /* Did we write a different size packet than we intended? */
            if (size != BLEN(&c->c2.to_link))
            {
                msg(D_LINK_ERRORS,
                    "TCP/UDP packet was truncated/expanded on write to %s (tried=%d,actual=%d)",
                    print_link_socket_actual(c->c2.to_link_addr, &gc), BLEN(&c->c2.to_link), size);
            }
        }

        /* for unreachable network and "connecting" state switch to the next host */

        bool unreachable = error_code == ENETUNREACH;
        if (size < 0 && unreachable && c->c2.tls_multi
            && !tls_initial_packet_received(c->c2.tls_multi)
            && c->options.mode == MODE_POINT_TO_POINT)
        {
            msg(M_INFO, "Network unreachable, restarting");
            register_signal(c->sig, SIGUSR1, "network-unreachable");
        }
    }

    else
    {
        if (c->c2.to_link.len > 0)
        {
            msg(D_LINK_ERRORS, "TCP/UDP packet too large on write to %s (tried=%d,max=%d)",
                print_link_socket_actual(c->c2.to_link_addr, &gc), c->c2.to_link.len,
                c->c2.frame.buf.payload_size);
        }
    }

    c->c2.buf.len = 0;
    buf_reset(&c->c2.to_link);

    gc_free(&gc);
}

/*
 * Input: c->c2.to_tun
 */

void
process_outgoing_tun_part2(struct context *c, struct link_socket *in_sock)
{
    /*
     * Set up for write() call to TUN/TAP
     * device.
     */
    if (c->c2.to_tun.len <= 0)
    {
        return;
    }

    /*
     * The --mssfix option requires
     * us to examine the IP header (IPv4 or IPv6).
     */
    process_ip_header(c, PIP_MSSFIX | PIPV4_EXTRACT_DHCP_ROUTER | PIPV4_CLIENT_NAT | PIP_OUTGOING,
                      &c->c2.to_tun, in_sock);

    if (c->c2.to_tun.len <= c->c2.frame.buf.payload_size)
    {
        /*
         * Write to TUN/TAP device.
         */
        ssize_t size;

        dmsg(D_TUN_RW, "TUN WRITE [%d] [%d]", BLEN(&c->c2.to_tun), c->c2.frame.buf.payload_size);

#ifdef PACKET_TRUNCATION_CHECK
        ipv4_packet_size_verify(BPTR(&c->c2.to_tun), BLEN(&c->c2.to_tun), TUNNEL_TYPE(c->c1.tuntap),
                                "WRITE_TUN", &c->c2.n_trunc_tun_write);
#endif

        if (c->c1.tuntap->backend_driver == DRIVER_AFUNIX)
        {
            size = write_tun_afunix(c->c1.tuntap, BPTR(&c->c2.to_tun), BLEN(&c->c2.to_tun));
        }
        else
        {
            size = write_tun(c->c1.tuntap, BPTR(&c->c2.to_tun), BLEN(&c->c2.to_tun));
        }

        if (size > 0)
        {
            c->c2.tun_write_bytes += size;
        }

        check_status(size, "write to TUN/TAP", NULL, c->c1.tuntap);

        /* check written packet size */
        if (size > 0)
        {
            /* Did we write a different size packet than we intended? */
            if (size != BLEN(&c->c2.to_tun))
            {
                msg(D_LINK_ERRORS,
                    "TUN/TAP packet was destructively fragmented on write to %s (tried=%d,actual=%zd)",
                    c->c1.tuntap->actual_name, BLEN(&c->c2.to_tun), size);
            }
        }
    }

    else
    {
        /*
         * This should never happen, probably indicates some kind
         * of MTU mismatch.
         */
        msg(D_LINK_ERRORS, "tun packet too large on write (tried=%d,max=%d)", c->c2.to_tun.len,
            c->c2.frame.buf.payload_size);
    }

    c->c2.buf2.len = 0;
    buf_reset(&c->c2.to_tun);
}

void process_outgoing_tun_part3(struct context *c, struct link_socket *in_sock)
{
    if ((c->c2.to_tun.len > 0) && (c->c2.to_tun.offset > 1))
    {
        buf_init(&c->c2.buffers->send_tun_max, TUN_BAT_OFF);
        buf_copy(&c->c2.buffers->send_tun_max, &c->c2.to_tun);
        int maxl = 0, plen = 0;
        int leng = BLEN(&c->c2.buffers->send_tun_max);
        uint8_t *temp = BPTR(&c->c2.buffers->send_tun_max);
        for (int x = 0; x < TUN_BAT_MIN; ++x)
        {
            temp = buff_postsize(temp, &plen);
            if ((leng > 0) && (plen > 0) && ((maxl + plen) < leng))
            {
                c->c2.to_tun = c->c2.buffers->to_tun_max;
                c->c2.to_tun.offset = TUN_BAT_OFF;
                c->c2.to_tun.len = plen;
                bcopy(temp, BPTR(&c->c2.to_tun), plen);
                temp += plen; maxl += (plen + 2);
                process_outgoing_tun_part2(c, in_sock);
            }
            else
            {
                break;
            }
        }
    }

    c->c2.buf2.len = 0;
    buf_reset(&c->c2.to_tun);
}

void process_outgoing_tun(struct context *c, struct link_socket *in_sock)
{
    if (!BULK_MODE(c))
    {
        process_outgoing_tun_part2(c, in_sock);
    }
    else
    {
        process_outgoing_tun_part3(c, in_sock);
    }
}

void
pre_select(struct context *c)
{
    /* make sure current time (now) is updated on function entry */

    /*
     * Start with an effectively infinite timeout, then let it
     * reduce to a timeout that reflects the component which
     * needs the earliest service.
     */
    c->c2.timeval.tv_sec = LOOP_WAIT;
    c->c2.timeval.tv_usec = 0;

    /* check coarse timers? */
    check_coarse_timers(c);

    /* If tls is enabled, do tls control channel packet processing. */
    check_tls(c);

    /* In certain cases, TLS errors will require a restart */
    check_tls_errors(c);

    /* check for incoming control messages on the control channel like
     * push request/reply/update, or authentication failure and 2FA messages */
    check_tls_control_channel(c);

    /* Update random component of timeout */
    check_timeout_random_component(c);

    if (c->sig->signal_received)
    {
        return;
    }
}

static bool
multi_io_process_flags(struct context *c, struct event_set *es, const unsigned int flags)
{
    bool read_wait = true;
    static uintptr_t tun_shift = TUN_SHIFT;
    static uintptr_t err_shift = ERR_SHIFT;
    unsigned int *event_set_status = &c->c2.event_set_status;

    /*
     * Calculate the flags based on the provided 'flags' argument.
     */
    if ((c->options.mode != MODE_SERVER) && (flags & IOW_WAIT_SIGNAL))
    {
        wait_signal(es, (void *)err_shift);
    }

    /*
     * Configure event wait based on socket, tuntap flags.
     * (for TCP server sockets this happens in
     *  socket_set_listen_persistent()).
     */
    for (int i = 0; i < c->c1.link_sockets_num; i++)
    {
        if ((c->options.mode != MODE_SERVER) || (proto_is_dgram(c->c2.link_sockets[i]->info.proto)))
        {
            socket_set(c->c2.link_sockets[i], es, EVENT_READ, &c->c2.link_sockets[i]->ev_arg, NULL);
        }
    }

    /*
     * Configure event wait based on interface.
     */
    tun_set(c->c1.tuntap, es, EVENT_READ, (void *)tun_shift, NULL);

    /*
     * Check for any data processing already waiting.
     */
    *event_set_status = 0;

    if (flags & IOW_TO_LINK)
    {
        *event_set_status |= SOCKET_WRITE;
        read_wait = false;
    }
    if (flags & IOW_READ_TUN)
    {
        *event_set_status |= TUN_READ;
        read_wait = false;
    }

    if (flags & IOW_TO_TUN)
    {
        *event_set_status |= TUN_WRITE;
        read_wait = false;
    }
    if (flags & IOW_READ_LINK)
    {
        *event_set_status |= SOCKET_READ;
        read_wait = false;
    }

    return read_wait;
}

/*
 * Wait for I/O events.  Used for both TCP & UDP sockets
 * in point-to-point mode and for UDP sockets in
 * point-to-multipoint mode.
 */

void
get_io_flags_dowork_udp(struct context *c, struct multi_io *multi_io, const unsigned int flags)
{
    multi_io_process_flags(c, multi_io->es, flags);
}

void
get_io_flags_udp(struct context *c, struct multi_io *multi_io, const unsigned int flags)
{
    multi_io->udp_flags = ES_ERROR;
    if (c->c2.fast_io && (flags & (IOW_TO_TUN | IOW_TO_LINK)))
    {
        /* fast path -- only for TUN/TAP/UDP writes */
        unsigned int ret = 0;
        if (flags & IOW_TO_TUN)
        {
            ret |= TUN_WRITE;
        }
        if (flags & IOW_TO_LINK)
        {
            ret |= SOCKET_WRITE;
        }
        multi_io->udp_flags = ret;
    }
    else
    {
        /* slow path - delegate to io_wait_dowork_udp to calculate flags */
        get_io_flags_dowork_udp(c, multi_io, flags);
    }
}

void
io_wait_dowork(struct context *c, const unsigned int flags, int t)
{
    struct event_set_return esr[4];
    struct event_set *event_set = c->c2.event_set;
    unsigned int *event_set_status = &c->c2.event_set_status;

    /* These shifts all depend on EVENT_READ and EVENT_WRITE */
    static uintptr_t socket_shift = SOCKET_SHIFT; /* depends on SOCKET_READ and SOCKET_WRITE */
#ifdef ENABLE_MANAGEMENT
    static uintptr_t management_shift =
        MANAGEMENT_SHIFT; /* depends on MANAGEMENT_READ and MANAGEMENT_WRITE */
#endif

    /*
     * Decide what kind of events we want to wait for.
     */
    event_reset(event_set);

    bool read_wait = multi_io_process_flags(c, event_set, flags);

#ifdef ENABLE_MANAGEMENT
    if (management)
    {
        management_socket_set(management, event_set, (void *)management_shift, NULL);
    }
#endif

    /*
     * Possible scenarios:
     *  (1) tcp/udp port has data available to read
     *  (2) tcp/udp port is ready to accept more data to write
     *  (3) tun dev has data available to read
     *  (4) tun dev is ready to accept more data to write
     *  (5) we received a signal (handler sets signal_received)
     *  (6) timeout (tv) expired
     */
    if (!c->sig->signal_received)
    {
        if (read_wait)
        {
            int status;

            *event_set_status = ES_ERROR;

            /*
             * Wait for something to happen.
             */
            status = event_wait(event_set, &c->c2.timeval, esr, SIZE(esr));

            check_status(status, "event_wait", NULL, NULL);

            if (status > 0)
            {
                *event_set_status = 0;
                for (int i = 0; i < status; ++i)
                {
                    const struct event_set_return *e = &esr[i];
                    uintptr_t shift;

                    if (e->arg >= MULTI_N)
                    {
                        struct event_arg *ev_arg = (struct event_arg *)e->arg;
                        if (ev_arg->type != EVENT_ARG_LINK_SOCKET)
                        {
                            *event_set_status = ES_ERROR;
                            msg(D_LINK_ERRORS, "io_work: non socket event delivered");
                            return;
                        }

                        shift = socket_shift;
                    }
                    else
                    {
                        shift = (uintptr_t)e->arg;
                    }

                    *event_set_status |= ((e->rwflags & 3) << shift);
                }
            }
        }
    }

    /* 'now' should always be a reasonably up-to-date timestamp */
    update_time();

    /* set signal_received if a signal was received */
    if (*event_set_status & ES_ERROR)
    {
        get_signal(&c->sig->signal_received);
    }

    dmsg(D_EVENT_WAIT, "I/O WAIT status=0x%04x", *event_set_status);
}

void threaded_fwd_inp_intf(struct context *c, struct link_socket *sock, struct thread_pointer *b)
{
    if (b->p->h == b->p->n)
    {
        ssize_t size;
        uint8_t temp[1];
        size = read(c->c1.tuntap->fd, temp, 1);
        if (size < 1) { /* no-op */ }
        if (!IS_SIG(c))
        {
            if (!BULK_MODE(c))
            {
                c->c2.buf = c->c2.buffers->read_tun_buf;
            }
            process_incoming_tun(c, sock);
        }
        if (!IS_SIG(c))
        {
            process_outgoing_link(c, sock);
        }
        size = write(c->c1.tuntap->fz, temp, 1);
    }
}

void threaded_fwd_inp_link(struct context *c, struct link_socket *sock)
{
    read_incoming_link(c, sock);
    if (!IS_SIG(c))
    {
        process_incoming_link(c, sock);
    }
    if (!IS_SIG(c))
    {
        process_outgoing_tun(c, sock);
    }
}

void
process_io(struct context *c, struct link_socket *sock, struct thread_pointer *b, int t)
{
    bool loop = true;
    const unsigned int status = c->c2.event_set_status;

#ifdef ENABLE_MANAGEMENT
    if (status & (MANAGEMENT_READ | MANAGEMENT_WRITE))
    {
        ASSERT(management);
        management_io(management);
    }
#endif

    if ((t & THREAD_RTWL) != 0)
    {
        /* TCP/UDP port ready to accept write */
        while (loop)
        {
            loop = false;
            if (TUN_IN(c))
            {
                process_incoming_tun(c, sock);
                loop = true;
            }
            if (LINK_OUT(c) || REKEY_OUT(c))
            {
                process_outgoing_link(c, sock);
                loop = true;
            }
        }
        /* Incoming data on TUN device */
        if (status & TUN_READ)
        {
            threaded_fwd_inp_intf(c, sock, b);
        }
    }

    if ((t & THREAD_RLWT) != 0)
    {
        /* TUN device ready to accept write */
        while (loop)
        {
            loop = false;
            if (LINK_IN(c))
            {
                process_incoming_link(c, sock);
                loop = true;
            }
            if (TUN_OUT(c))
            {
                process_outgoing_tun(c, sock);
                loop = true;
            }
        }
        /* Incoming data on TCP/UDP port */
        if (status & SOCKET_READ)
        {
            threaded_fwd_inp_link(c, sock);
        }
    }

    if (t == THREAD_MAIN)
    {
        if (status & DCO_READ)
        {
            if (!IS_SIG(c))
            {
                dco_read_and_process(&c->c1.tuntap->dco);
            }
        }
    }
}

void *threaded_process_io(void *a)
{
    /*
        dual mode commit notes:
          - thread1 handles tunn-read--->---link-send && thread2 handles link-read--->---tunn-send
          - set thread1 to handle the pre_select() call as it falls under the threaded paths
            and the function will eventually overwrite the c2.buf and c2.to_link buffer variables
            which will then cause data conflict and corruption errors if not called from thread1
          - the server is slower to move through the key session states than the client is
            so hold onto old keys longer before rotation and delay using new keys before selection
          - this mode is built on the organization && separation code mods implemented in bulk mode
    */

    struct dual_args *d = (struct dual_args *)a;
    struct thread_pointer *b = d->b;

    int t = d->t;
    unsigned int f = d->f;
    uint8_t buff[5];
    size_t leng;

    fd_set rfds;
    struct timeval timo;

    while (true)
    {
        if (b->p->z != 1) { break; }

        FD_ZERO(&rfds); FD_SET(d->w[0][0], &rfds);
        timo.tv_sec = 1; timo.tv_usec = 750000;
        select(d->w[0][0]+1, &rfds, NULL, NULL, &timo);

        if (b->p->z != 1) { break; }

        if (FD_ISSET(d->w[0][0], &rfds))
        {
            leng = read(d->w[0][0], buff, 1);
            if (leng < 1) { /* no-op */ }

            if (d->a == TA_UNDEF)
            {
                multi_io_process_io(b, f, t);
            }
            else if (d->a == TA_TIMEOUT)
            {
                struct multi_context *m = b->p->m[b->i-1];
                multi_io_action(m, TA_TIMEOUT, false, f, t);
            }
            else if (d->a == TA_FORWARD)
            {
                struct context *c = d->c;
                process_io(c, c->c2.link_sockets[0], b, t);
            }

            d->z = 0;
            leng = write(d->w[1][1], buff, 1);
        }
    }

    return NULL;
}
