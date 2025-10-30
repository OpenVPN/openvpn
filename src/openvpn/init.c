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

#ifdef ENABLE_SYSTEMD
#include <systemd/sd-daemon.h>
#endif

#include "win32.h"
#include "init.h"
#include "run_command.h"
#include "sig.h"
#include "occ.h"
#include "list.h"
#include "otime.h"
#include "pool.h"
#include "gremlin.h"
#include "occ.h"
#include "pkcs11.h"
#include "ps.h"
#include "lladdr.h"
#include "ping.h"
#include "ssl_verify.h"
#include "ssl_ncp.h"
#include "tls_crypt.h"
#include "forward.h"
#include "auth_token.h"
#include "mss.h"
#include "mudp.h"
#include "dco.h"
#include "tun_afunix.h"

#include "memdbg.h"


static struct context *static_context;  /* GLOBAL */
static const char *saved_pid_file_name; /* GLOBAL */

/*
 * Crypto initialization flags
 */
#define CF_LOAD_PERSISTED_PACKET_ID (1 << 0)
#define CF_INIT_TLS_MULTI           (1 << 1)
#define CF_INIT_TLS_AUTH_STANDALONE (1 << 2)

static void do_init_first_time(struct context *c);

static bool do_deferred_p2p_ncp(struct context *c);

void
context_clear(struct context *c)
{
    CLEAR(*c);
}

void
context_clear_1(struct context *c)
{
    CLEAR(c->c1);
}

void
context_clear_2(struct context *c)
{
    CLEAR(c->c2);
}

void
context_clear_all_except_first_time(struct context *c)
{
    const bool first_time_save = c->first_time;
    const struct context_persist cpsave = c->persist;
    context_clear(c);
    c->first_time = first_time_save;
    c->persist = cpsave;
}

/*
 * Pass tunnel endpoint and MTU parms to a user-supplied script.
 * Used to execute the up/down script/plugins.
 */
static void
run_up_down(const char *command, const struct plugin_list *plugins, int plugin_type,
            const char *arg,
#ifdef _WIN32
            DWORD adapter_index,
#endif
            const char *dev_type, int tun_mtu, const char *ifconfig_local,
            const char *ifconfig_remote, const char *context, const char *signal_text,
            const char *script_type, struct env_set *es)
{
    struct gc_arena gc = gc_new();

    if (signal_text)
    {
        setenv_str(es, "signal", signal_text);
    }
    setenv_str(es, "script_context", context);
    setenv_int(es, "tun_mtu", tun_mtu);
    setenv_str(es, "dev", arg);
    if (dev_type)
    {
        setenv_str(es, "dev_type", dev_type);
    }
#ifdef _WIN32
    setenv_int(es, "dev_idx", adapter_index);
#endif

    if (!ifconfig_local)
    {
        ifconfig_local = "";
    }
    if (!ifconfig_remote)
    {
        ifconfig_remote = "";
    }
    if (!context)
    {
        context = "";
    }

    if (plugin_defined(plugins, plugin_type))
    {
        struct argv argv = argv_new();
        ASSERT(arg);
        argv_printf(&argv, "%s %d 0 %s %s %s", arg, tun_mtu, ifconfig_local, ifconfig_remote,
                    context);

        if (plugin_call(plugins, plugin_type, &argv, NULL, es) != OPENVPN_PLUGIN_FUNC_SUCCESS)
        {
            msg(M_FATAL, "ERROR: up/down plugin call failed");
        }

        argv_free(&argv);
    }

    if (command)
    {
        struct argv argv = argv_new();
        ASSERT(arg);
        setenv_str(es, "script_type", script_type);
        argv_parse_cmd(&argv, command);
        argv_printf_cat(&argv, "%s %d 0 %s %s %s", arg, tun_mtu, ifconfig_local, ifconfig_remote,
                        context);
        argv_msg(M_INFO, &argv);
        openvpn_run_script(&argv, es, S_FATAL, "--up/--down");
        argv_free(&argv);
    }

    gc_free(&gc);
}

/*
 * Should be called after options->ce is modified at the top
 * of a SIGUSR1 restart.
 */
static void
update_options_ce_post(struct options *options)
{
    /*
     * In pull mode, we usually import --ping/--ping-restart parameters from
     * the server.  However we should also set an initial default --ping-restart
     * for the period of time before we pull the --ping-restart parameter
     * from the server.
     */
    if (options->pull && options->ping_rec_timeout_action == PING_UNDEF
        && proto_is_dgram(options->ce.proto))
    {
        options->ping_rec_timeout = PRE_PULL_INITIAL_PING_RESTART;
        options->ping_rec_timeout_action = PING_RESTART;
    }
}

#ifdef ENABLE_MANAGEMENT
static bool
management_callback_proxy_cmd(void *arg, const char **p)
{
    struct context *c = arg;
    struct connection_entry *ce = &c->options.ce;
    struct gc_arena *gc = &c->c2.gc;
    bool ret = false;

    update_time();
    if (streq(p[1], "NONE"))
    {
        ret = true;
    }
    else if (p[2] && p[3])
    {
        if (streq(p[1], "HTTP"))
        {
            struct http_proxy_options *ho;
            if (ce->proto != PROTO_TCP && ce->proto != PROTO_TCP_CLIENT)
            {
                msg(M_WARN, "HTTP proxy support only works for TCP based connections");
                return false;
            }
            ho = init_http_proxy_options_once(&ce->http_proxy_options, gc);
            ho->server = string_alloc(p[2], gc);
            ho->port = string_alloc(p[3], gc);
            ho->auth_retry = (p[4] && streq(p[4], "nct") ? PAR_NCT : PAR_ALL);
            ret = true;
        }
        else if (streq(p[1], "SOCKS"))
        {
            ce->socks_proxy_server = string_alloc(p[2], gc);
            ce->socks_proxy_port = string_alloc(p[3], gc);
            ret = true;
        }
    }
    else
    {
        msg(M_WARN, "Bad proxy command");
    }

    ce->flags &= ~CE_MAN_QUERY_PROXY;

    return ret;
}

static bool
ce_management_query_proxy(struct context *c)
{
    const struct connection_list *l = c->options.connection_list;
    struct connection_entry *ce = &c->options.ce;
    struct gc_arena gc;
    bool ret = true;

    update_time();
    if (management)
    {
        gc = gc_new();
        {
            struct buffer out = alloc_buf_gc(256, &gc);
            buf_printf(&out, ">PROXY:%u,%s,%s", (l ? l->current : 0) + 1,
                       (proto_is_udp(ce->proto) ? "UDP" : "TCP"), np(ce->remote));
            management_notify_generic(management, BSTR(&out));
            management->persist.special_state_msg = BSTR(&out);
        }
        ce->flags |= CE_MAN_QUERY_PROXY;
        while (ce->flags & CE_MAN_QUERY_PROXY)
        {
            management_event_loop_n_seconds(management, 1);
            if (IS_SIG(c))
            {
                ret = false;
                break;
            }
        }
        management->persist.special_state_msg = NULL;
        gc_free(&gc);
    }

    return ret;
}

/**
 * This method sends a custom control channel message
 *
 * This will write the control message
 *
 *  command parm1,parm2,...
 *
 * to the control channel.
 *
 * @param arg           The context struct
 * @param command       The command being sent
 * @param parameters    the parameters to the command
 * @return              if sending was successful
 */
static bool
management_callback_send_cc_message(void *arg, const char *command, const char *parameters)
{
    struct context *c = (struct context *)arg;
    size_t len = strlen(command) + 1 + strlen(parameters) + 1;
    if (len > PUSH_BUNDLE_SIZE)
    {
        return false;
    }

    struct gc_arena gc = gc_new();
    struct buffer buf = alloc_buf_gc(len, &gc);
    ASSERT(buf_printf(&buf, "%s", command));
    if (parameters)
    {
        ASSERT(buf_printf(&buf, ",%s", parameters));
    }
    bool status = send_control_channel_string(c, BSTR(&buf), D_PUSH);

    gc_free(&gc);
    return status;
}

static unsigned int
management_callback_remote_entry_count(void *arg)
{
    ASSERT(arg);
    struct context *c = (struct context *)arg;
    struct connection_list *l = c->options.connection_list;

    return l->len;
}

static bool
management_callback_remote_entry_get(void *arg, unsigned int index, char **remote)
{
    ASSERT(arg);
    ASSERT(remote);

    struct context *c = (struct context *)arg;
    struct connection_list *l = c->options.connection_list;
    bool ret = true;

    if (index < l->len)
    {
        struct connection_entry *ce = l->array[index];
        const char *proto = proto2ascii(ce->proto, ce->af, false);
        const char *status = (ce->flags & CE_DISABLED) ? "disabled" : "enabled";

        /* space for output including 3 commas and a nul */
        size_t len =
            strlen(ce->remote) + strlen(ce->remote_port) + strlen(proto) + strlen(status) + 3 + 1;
        char *out = malloc(len);
        check_malloc_return(out);

        snprintf(out, len, "%s,%s,%s,%s", ce->remote, ce->remote_port, proto, status);
        *remote = out;
    }
    else
    {
        ret = false;
        msg(M_WARN, "Out of bounds index in management query for remote entry: index = %u", index);
    }

    return ret;
}

static bool
management_callback_remote_cmd(void *arg, const char **p)
{
    struct context *c = (struct context *)arg;
    struct connection_entry *ce = &c->options.ce;
    int ret = false;
    if (p[1]
        && ((ce->flags >> CE_MAN_QUERY_REMOTE_SHIFT) & CE_MAN_QUERY_REMOTE_MASK)
               == CE_MAN_QUERY_REMOTE_QUERY)
    {
        unsigned int flags = 0;
        if (!strcmp(p[1], "ACCEPT"))
        {
            flags = CE_MAN_QUERY_REMOTE_ACCEPT;
            ret = true;
        }
        else if (!strcmp(p[1], "SKIP"))
        {
            flags = CE_MAN_QUERY_REMOTE_SKIP;
            ret = true;
            c->options.ce_advance_count = (p[2]) ? atoi(p[2]) : 1;
        }
        else if (!strcmp(p[1], "MOD") && p[2] && p[3])
        {
            if (strlen(p[2]) < RH_HOST_LEN && strlen(p[3]) < RH_PORT_LEN)
            {
                struct remote_host_store *rhs = c->options.rh_store;
                if (!rhs)
                {
                    ALLOC_OBJ_CLEAR_GC(rhs, struct remote_host_store, &c->options.gc);
                    c->options.rh_store = rhs;
                }
                strncpynt(rhs->host, p[2], RH_HOST_LEN);
                strncpynt(rhs->port, p[3], RH_PORT_LEN);

                ce->remote = rhs->host;
                ce->remote_port = rhs->port;
                flags = CE_MAN_QUERY_REMOTE_MOD;
                ret = true;
            }
        }
        if (ret)
        {
            ce->flags &= ~(CE_MAN_QUERY_REMOTE_MASK << CE_MAN_QUERY_REMOTE_SHIFT);
            ce->flags |= ((flags & CE_MAN_QUERY_REMOTE_MASK) << CE_MAN_QUERY_REMOTE_SHIFT);
        }
    }
    return ret;
}

static bool
ce_management_query_remote(struct context *c)
{
    struct gc_arena gc = gc_new();
    volatile struct connection_entry *ce = &c->options.ce;
    int ce_changed = true; /* presume the connection entry will be changed */

    update_time();
    if (management)
    {
        struct buffer out = alloc_buf_gc(256, &gc);

        buf_printf(&out, ">REMOTE:%s,%s,%s", np(ce->remote), ce->remote_port,
                   proto2ascii(ce->proto, ce->af, false));
        management_notify_generic(management, BSTR(&out));
        management->persist.special_state_msg = BSTR(&out);

        ce->flags &= ~(CE_MAN_QUERY_REMOTE_MASK << CE_MAN_QUERY_REMOTE_SHIFT);
        ce->flags |= (CE_MAN_QUERY_REMOTE_QUERY << CE_MAN_QUERY_REMOTE_SHIFT);
        while (((ce->flags >> CE_MAN_QUERY_REMOTE_SHIFT) & CE_MAN_QUERY_REMOTE_MASK)
               == CE_MAN_QUERY_REMOTE_QUERY)
        {
            management_event_loop_n_seconds(management, 1);
            if (IS_SIG(c))
            {
                ce_changed = false; /* connection entry have not been set */
                break;
            }
        }
        management->persist.special_state_msg = NULL;
    }
    gc_free(&gc);

    if (ce_changed)
    {
        /* If it is likely a connection entry was modified,
         * check what changed in the flags and that it was not skipped
         */
        const int flags = ((ce->flags >> CE_MAN_QUERY_REMOTE_SHIFT) & CE_MAN_QUERY_REMOTE_MASK);
        ce_changed = (flags != CE_MAN_QUERY_REMOTE_SKIP);
    }
    return ce_changed;
}
#endif /* ENABLE_MANAGEMENT */

#if defined(__GNUC__) || defined(__clang__)
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wconversion"
#endif

/*
 * Initialize and possibly randomize the connection list.
 *
 * Applies the Fisher-Yates shuffle algorithm to ensure all permutations
 * are equally probable, thereby eliminating shuffling bias.
 *
 * The algorithm randomly selects an element from the unshuffled portion
 * and places it at position i. There's only one way to obtain each
 * permutation through these swaps. This guarantees that each permutation
 * occurs with equal probability in theory.
 */
static void
init_connection_list(struct context *c)
{
    struct connection_list *l = c->options.connection_list;

    l->current = -1;
    if (c->options.remote_random)
    {
        int i;
        for (i = l->len - 1; i > 0; --i)
        {
            const int j = get_random() % (i + 1);
            if (i != j)
            {
                struct connection_entry *tmp;
                tmp = l->array[i];
                l->array[i] = l->array[j];
                l->array[j] = tmp;
            }
        }
    }
}

/*
 * Clear the remote address list
 */
static void
clear_remote_addrlist(struct link_socket_addr *lsa, bool free)
{
    if (lsa->remote_list && free)
    {
        freeaddrinfo(lsa->remote_list);
    }
    lsa->remote_list = NULL;
    lsa->current_remote = NULL;
}

/*
 * Increment to next connection entry
 */
static void
next_connection_entry(struct context *c)
{
    struct connection_list *l = c->options.connection_list;
    bool ce_defined;
    struct connection_entry *ce;
    int n_cycles = 0;

    do
    {
        ce_defined = true;
        if (c->options.no_advance && l->current >= 0)
        {
            c->options.no_advance = false;
        }
        else
        {
            /* Check if there is another resolved address to try for
             * the current connection */
            if (c->c1.link_socket_addrs[0].current_remote
                && c->c1.link_socket_addrs[0].current_remote->ai_next
                && !c->options.advance_next_remote)
            {
                c->c1.link_socket_addrs[0].current_remote =
                    c->c1.link_socket_addrs[0].current_remote->ai_next;
            }
            else
            {
                c->options.advance_next_remote = false;
                /* FIXME (schwabe) fix the persist-remote-ip option for real,
                 * this is broken probably ever since connection lists and multiple
                 * remote existed
                 */
                if (!c->options.persist_remote_ip)
                {
                    /* Connection entry addrinfo objects might have been
                     * resolved earlier but the entry itself might have been
                     * skipped by management on the previous loop.
                     * If so, clear the addrinfo objects as close_instance does
                     */
                    if (c->c1.link_socket_addrs[0].remote_list)
                    {
                        clear_remote_addrlist(&c->c1.link_socket_addrs[0],
                                              !c->options.resolve_in_advance);
                    }

                    /* close_instance should have cleared the addrinfo objects */
                    ASSERT(c->c1.link_socket_addrs[0].current_remote == NULL);
                    ASSERT(c->c1.link_socket_addrs[0].remote_list == NULL);
                }
                else
                {
                    c->c1.link_socket_addrs[0].current_remote =
                        c->c1.link_socket_addrs[0].remote_list;
                }

                int advance_count = 1;

                /* If previous connection entry was skipped by management client
                 * with a count to advance by, apply it.
                 */
                if (c->options.ce_advance_count > 0)
                {
                    advance_count = c->options.ce_advance_count;
                }

                /*
                 * Increase the number of connection attempts
                 * If this is connect-retry-max * size(l)
                 * OpenVPN will quit
                 */

                c->options.unsuccessful_attempts += advance_count;
                l->current += advance_count;

                if (l->current >= l->len)
                {
                    l->current %= l->len;
                    if (++n_cycles >= 2)
                    {
                        msg(M_FATAL, "No usable connection profiles are present");
                    }
                }
            }
        }

        c->options.ce_advance_count = 1;
        ce = l->array[l->current];

        if (ce->flags & CE_DISABLED)
        {
            ce_defined = false;
        }

        c->options.ce = *ce;

#ifdef ENABLE_MANAGEMENT
        if (ce_defined && management && management_query_remote_enabled(management))
        {
            /* allow management interface to override connection entry details */
            ce_defined = ce_management_query_remote(c);
            if (IS_SIG(c))
            {
                break;
            }
        }
        else if (ce_defined && management && management_query_proxy_enabled(management))
        {
            ce_defined = ce_management_query_proxy(c);
            if (IS_SIG(c))
            {
                break;
            }
        }
#endif
    } while (!ce_defined);

    /* Check if this connection attempt would bring us over the limit */
    if (c->options.connect_retry_max > 0
        && c->options.unsuccessful_attempts > (l->len * c->options.connect_retry_max))
    {
        msg(M_FATAL, "All connections have been connect-retry-max (%d) times unsuccessful, exiting",
            c->options.connect_retry_max);
    }
    update_options_ce_post(&c->options);
}

/*
 * Query for private key and auth-user-pass username/passwords
 */
void
init_query_passwords(const struct context *c)
{
    /* Certificate password input */
    if (c->options.key_pass_file)
    {
        pem_password_setup(c->options.key_pass_file);
    }

    /* Auth user/pass input */
    if (c->options.auth_user_pass_file)
    {
        enable_auth_user_pass();
#ifdef ENABLE_MANAGEMENT
        auth_user_pass_setup(c->options.auth_user_pass_file, c->options.auth_user_pass_file_inline,
                             &c->options.sc_info);
#else
        auth_user_pass_setup(c->options.auth_user_pass_file, c->options.auth_user_pass_file_inline,
                             NULL);
#endif
    }
}

/*
 * Initialize/Uninitialize HTTP or SOCKS proxy
 */

static void
uninit_proxy_dowork(struct context *c)
{
    if (c->c1.http_proxy_owned && c->c1.http_proxy)
    {
        http_proxy_close(c->c1.http_proxy);
        c->c1.http_proxy = NULL;
        c->c1.http_proxy_owned = false;
    }
    if (c->c1.socks_proxy_owned && c->c1.socks_proxy)
    {
        socks_proxy_close(c->c1.socks_proxy);
        c->c1.socks_proxy = NULL;
        c->c1.socks_proxy_owned = false;
    }
}

static void
init_proxy_dowork(struct context *c)
{
    bool did_http = false;

    uninit_proxy_dowork(c);

    if (c->options.ce.http_proxy_options)
    {
        c->options.ce.http_proxy_options->first_time = c->first_time;

        /* Possible HTTP proxy user/pass input */
        c->c1.http_proxy = http_proxy_new(c->options.ce.http_proxy_options);
        if (c->c1.http_proxy)
        {
            did_http = true;
            c->c1.http_proxy_owned = true;
        }
    }

    if (!did_http && c->options.ce.socks_proxy_server)
    {
        c->c1.socks_proxy =
            socks_proxy_new(c->options.ce.socks_proxy_server, c->options.ce.socks_proxy_port,
                            c->options.ce.socks_proxy_authfile);
        if (c->c1.socks_proxy)
        {
            c->c1.socks_proxy_owned = true;
        }
    }
}

static void
init_proxy(struct context *c)
{
    init_proxy_dowork(c);
}

static void
uninit_proxy(struct context *c)
{
    uninit_proxy_dowork(c);
}

static void
do_link_socket_addr_new(struct context *c)
{
    ALLOC_ARRAY_CLEAR_GC(c->c1.link_socket_addrs, struct link_socket_addr, c->c1.link_sockets_num,
                         &c->gc);
}

void
context_init_1(struct context *c)
{
    context_clear_1(c);

    packet_id_persist_init(&c->c1.pid_persist);

    init_connection_list(c);

    c->c1.link_sockets_num = c->options.ce.local_list->len;

    do_link_socket_addr_new(c);

#if defined(ENABLE_PKCS11)
    if (c->first_time)
    {
        int i;
        pkcs11_initialize(true, c->options.pkcs11_pin_cache_period);
        for (i = 0; i < MAX_PARMS && c->options.pkcs11_providers[i] != NULL; i++)
        {
            pkcs11_addProvider(
                c->options.pkcs11_providers[i], c->options.pkcs11_protected_authentication[i],
                c->options.pkcs11_private_mode[i], c->options.pkcs11_cert_private[i]);
        }
    }
#endif

#if 0 /* test get_user_pass with GET_USER_PASS_NEED_OK flag */
    {
        /*
         * In the management interface, you can okay the request by entering "needok token-insertion-request ok"
         */
        struct user_pass up;
        CLEAR(up);
        strcpy(up.username, "Please insert your cryptographic token"); /* put the high-level message in up.username */
        get_user_pass(&up, NULL, "token-insertion-request", GET_USER_PASS_MANAGEMENT|GET_USER_PASS_NEED_OK);
        msg(M_INFO, "RET:%s", up.password); /* will return the third argument to management interface
                                             * 'needok' command, usually 'ok' or 'cancel'. */
    }
#endif

#ifdef ENABLE_SYSTEMD
    /* We can report the PID via getpid() to systemd here as OpenVPN will not
     * do any fork due to daemon() a future call.
     * See possibly_become_daemon() [init.c] for more details.
     */
    sd_notifyf(0, "READY=1\nSTATUS=Pre-connection initialization successful\nMAINPID=%lu",
               (unsigned long)getpid());
#endif
}

void
context_gc_free(struct context *c)
{
    gc_free(&c->c2.gc);
    gc_free(&c->options.gc);
    gc_free(&c->gc);
}

#if PORT_SHARE

static void
close_port_share(void)
{
    if (port_share)
    {
        port_share_close(port_share);
        port_share = NULL;
    }
}

static void
init_port_share(struct context *c)
{
    if (!port_share && (c->options.port_share_host && c->options.port_share_port))
    {
        port_share =
            port_share_open(c->options.port_share_host, c->options.port_share_port,
                            c->c2.frame.buf.payload_size, c->options.port_share_journal_dir);
        if (port_share == NULL)
        {
            msg(M_FATAL, "Fatal error: Port sharing failed");
        }
    }
}

#endif /* if PORT_SHARE */


bool
init_static(void)
{
#if defined(DMALLOC)
    crypto_init_dmalloc();
#endif


    /*
     * Initialize random number seed.  random() is only used
     * when "weak" random numbers are acceptable.
     * SSL library routines are always used when cryptographically
     * strong random numbers are required.
     */
    struct timeval tv;
    if (!gettimeofday(&tv, NULL))
    {
        const unsigned int seed = (unsigned int)tv.tv_sec ^ tv.tv_usec;
        srandom(seed);
    }

    error_reset();        /* initialize error.c */
    reset_check_status(); /* initialize status check code in socket.c */

#ifdef _WIN32
    init_win32();
#endif

#ifdef OPENVPN_DEBUG_COMMAND_LINE
    {
        int i;
        for (i = 0; i < argc; ++i)
        {
            msg(M_INFO, "argv[%d] = '%s'", i, argv[i]);
        }
    }
#endif

    update_time();

    init_ssl_lib();

#ifdef SCHEDULE_TEST
    schedule_test();
    return false;
#endif

#ifdef IFCONFIG_POOL_TEST
    ifconfig_pool_test(0x0A010004, 0x0A0100FF);
    return false;
#endif

#ifdef TIME_TEST
    time_test();
    return false;
#endif

#ifdef GEN_PATH_TEST
    {
        struct gc_arena gc = gc_new();
        const char *fn = gen_path("foo", "bar", &gc);
        printf("%s\n", fn);
        gc_free(&gc);
    }
    return false;
#endif

#ifdef STATUS_PRINTF_TEST
    {
        struct gc_arena gc = gc_new();
        const char *tmp_file = platform_create_temp_file("/tmp", "foo", &gc);
        struct status_output *so = status_open(tmp_file, 0, -1, NULL, STATUS_OUTPUT_WRITE);
        status_printf(so, "%s", "foo");
        status_printf(so, "%s", "bar");
        if (!status_close(so))
        {
            msg(M_WARN, "STATUS_PRINTF_TEST: %s: write error", tmp_file);
        }
        gc_free(&gc);
    }
    return false;
#endif

    return true;
}

void
uninit_static(void)
{
    free_ssl_lib();

#ifdef ENABLE_PKCS11
    pkcs11_terminate();
#endif

#if PORT_SHARE
    close_port_share();
#endif

#if defined(MEASURE_TLS_HANDSHAKE_STATS)
    show_tls_performance_stats();
#endif
}

void
init_verb_mute(struct context *c, unsigned int flags)
{
    if (flags & IVM_LEVEL_1)
    {
        /* set verbosity and mute levels */
        set_check_status(D_LINK_ERRORS, D_READ_WRITE);
        set_debug_level(c->options.verbosity, SDL_CONSTRAIN);
        set_mute_cutoff(c->options.mute);
    }

    /* special D_LOG_RW mode */
    if (flags & IVM_LEVEL_2)
    {
        c->c2.log_rw = (check_debug_level(D_LOG_RW) && !check_debug_level(D_LOG_RW + 1));
    }
}

/*
 * Possibly set --dev based on --dev-node.
 * For example, if --dev-node /tmp/foo/tun, and --dev undefined,
 * set --dev to tun.
 */
void
init_options_dev(struct options *options)
{
    if (!options->dev && options->dev_node)
    {
        /* POSIX basename() implementations may modify its arguments */
        char *dev_node = string_alloc(options->dev_node, NULL);
        options->dev = basename(dev_node);
    }
}

bool
print_openssl_info(const struct options *options)
{
    /*
     * OpenSSL info print mode?
     */
    if (options->show_ciphers || options->show_digests || options->show_engines
        || options->show_tls_ciphers || options->show_curves)
    {
        if (options->show_ciphers)
        {
            show_available_ciphers();
        }
        if (options->show_digests)
        {
            show_available_digests();
        }
        if (options->show_engines)
        {
            show_available_engines();
        }
        if (options->show_tls_ciphers)
        {
            show_available_tls_ciphers(options->cipher_list, options->cipher_list_tls13,
                                       options->tls_cert_profile);
        }
        if (options->show_curves)
        {
            show_available_curves();
        }
        return true;
    }
    return false;
}

/*
 * Static pre-shared key generation mode?
 */
bool
do_genkey(const struct options *options)
{
    /* should we disable paging? */
    if (options->mlock && (options->genkey))
    {
        platform_mlockall(true);
    }

    /*
     * We do not want user to use --genkey with --secret. In the transistion
     * phase we for secret.
     */
    if (options->genkey && options->genkey_type != GENKEY_SECRET && options->shared_secret_file)
    {
        msg(M_USAGE, "Using --genkey type with --secret filename is "
                     "not supported.  Use --genkey type filename instead.");
    }
    if (options->genkey && options->genkey_type == GENKEY_SECRET)
    {
        int nbits_written;
        const char *genkey_filename = options->genkey_filename;
        if (options->shared_secret_file && options->genkey_filename)
        {
            msg(M_USAGE, "You must provide a filename to either --genkey "
                         "or --secret, not both");
        }

        /*
         * Copy filename from shared_secret_file to genkey_filename to support
         * the old --genkey --secret foo.file syntax.
         */
        if (options->shared_secret_file)
        {
            msg(M_WARN, "WARNING: Using --genkey --secret filename is "
                        "DEPRECATED.  Use --genkey secret filename instead.");
            genkey_filename = options->shared_secret_file;
        }

        nbits_written = write_key_file(2, genkey_filename);
        if (nbits_written < 0)
        {
            msg(M_FATAL, "Failed to write key file");
        }

        msg(D_GENKEY | M_NOPREFIX, "Randomly generated %d bit key written to %s", nbits_written,
            options->shared_secret_file);
        return true;
    }
    else if (options->genkey && options->genkey_type == GENKEY_TLS_CRYPTV2_SERVER)
    {
        tls_crypt_v2_write_server_key_file(options->genkey_filename);
        return true;
    }
    else if (options->genkey && options->genkey_type == GENKEY_TLS_CRYPTV2_CLIENT)
    {
        if (!options->tls_crypt_v2_file)
        {
            msg(M_USAGE,
                "--genkey tls-crypt-v2-client requires a server key to be set via --tls-crypt-v2 to create a client key");
        }

        tls_crypt_v2_write_client_key_file(options->genkey_filename, options->genkey_extra_data,
                                           options->tls_crypt_v2_file,
                                           options->tls_crypt_v2_file_inline);
        return true;
    }
    else if (options->genkey && options->genkey_type == GENKEY_AUTH_TOKEN)
    {
        auth_token_write_server_key_file(options->genkey_filename);
        return true;
    }
    else
    {
        return false;
    }
}

/*
 * Persistent TUN/TAP device management mode?
 */
bool
do_persist_tuntap(struct options *options, openvpn_net_ctx_t *ctx)
{
    if (!options->persist_config)
    {
        return false;
    }

    /* sanity check on options for --mktun or --rmtun */
    notnull(options->dev, "TUN/TAP device (--dev)");
    if (options->ce.remote || options->ifconfig_local || options->ifconfig_remote_netmask
        || options->shared_secret_file || options->tls_server || options->tls_client)
    {
        msg(M_FATAL | M_OPTERR,
            "options --mktun or --rmtun should only be used together with --dev");
    }

#if defined(ENABLE_DCO)
    if (dco_enabled(options))
    {
        /* creating a DCO interface via --mktun is not supported as it does not
         * make much sense. Since DCO is enabled by default, people may run into
         * this without knowing, therefore this case should be properly handled.
         *
         * Disable DCO if --mktun was provided and print a message to let
         * user know.
         */
        if (dev_type_enum(options->dev, options->dev_type) == DEV_TYPE_TUN)
        {
            msg(M_WARN, "Note: --mktun does not support DCO. Creating TUN interface.");
        }

        options->disable_dco = true;
    }
#endif

#ifdef ENABLE_FEATURE_TUN_PERSIST
    tuncfg(options->dev, options->dev_type, options->dev_node, options->persist_mode,
           options->username, options->groupname, &options->tuntap_options, ctx);
    if (options->persist_mode && options->lladdr)
    {
        set_lladdr(ctx, options->dev, options->lladdr, NULL);
    }
    return true;
#else /* ifdef ENABLE_FEATURE_TUN_PERSIST */
    msg(M_FATAL | M_OPTERR,
        "options --mktun and --rmtun are not available on your operating "
        "system.  Please check 'man tun' (or 'tap'), whether your system "
        "supports using 'ifconfig %s create' / 'destroy' to create/remove "
        "persistent tunnel interfaces.",
        options->dev);
#endif
    return false;
}

/*
 * Should we become a daemon?
 * Return true if we did it.
 */
bool
possibly_become_daemon(const struct options *options)
{
    bool ret = false;

#ifdef ENABLE_SYSTEMD
    /* return without forking if we are running from systemd */
    if (sd_notify(0, "READY=0") > 0)
    {
        return ret;
    }
#endif

    if (options->daemon)
    {
        /* Don't chdir immediately, but the end of the init sequence, if needed */

#if defined(__APPLE__) && defined(__clang__)
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
#endif
        if (daemon(1, options->log) < 0)
        {
            msg(M_ERR, "daemon() failed or unsupported");
        }
#if defined(__APPLE__) && defined(__clang__)
#pragma clang diagnostic pop
#endif
        restore_signal_state();
        if (options->log)
        {
            set_std_files_to_null(true);
        }

        ret = true;
    }
    return ret;
}

/*
 * Actually do UID/GID downgrade, chroot and SELinux context switching, if requested.
 */
static void
do_uid_gid_chroot(struct context *c, bool no_delay)
{
    static const char why_not[] = "will be delayed because of --client, --pull, or --up-delay";
    struct context_0 *c0 = c->c0;

    if (c0 && !c0->uid_gid_chroot_set)
    {
        /* chroot if requested */
        if (c->options.chroot_dir)
        {
            if (no_delay)
            {
                platform_chroot(c->options.chroot_dir);
            }
            else if (c->first_time)
            {
                msg(M_INFO, "NOTE: chroot %s", why_not);
            }
        }

        /* set user and/or group if we want to setuid/setgid */
        if (c0->uid_gid_specified)
        {
            if (no_delay)
            {
                platform_user_group_set(&c0->platform_state_user, &c0->platform_state_group, c);
            }
            else if (c->first_time)
            {
                msg(M_INFO, "NOTE: UID/GID downgrade %s", why_not);
            }
        }

#ifdef ENABLE_SELINUX
        /* Apply a SELinux context in order to restrict what OpenVPN can do
         * to _only_ what it is supposed to do after initialization is complete
         * (basically just network I/O operations). Doing it after chroot
         * requires /proc to be mounted in the chroot (which is annoying indeed
         * but doing it before requires more complex SELinux policies.
         */
        if (c->options.selinux_context)
        {
            if (no_delay)
            {
                if (-1 == setcon(c->options.selinux_context))
                {
                    msg(M_ERR, "setcon to '%s' failed; is /proc accessible?",
                        c->options.selinux_context);
                }
                else
                {
                    msg(M_INFO, "setcon to '%s' succeeded", c->options.selinux_context);
                }
            }
            else if (c->first_time)
            {
                msg(M_INFO, "NOTE: setcon %s", why_not);
            }
        }
#endif

        /* Privileges are going to be dropped by now (if requested), be sure
         * to prevent any future privilege dropping attempts from now on.
         */
        if (no_delay)
        {
            c0->uid_gid_chroot_set = true;
        }
    }
}

/*
 * Return common name in a way that is formatted for
 * prepending to msg() output.
 */
const char *
format_common_name(struct context *c, struct gc_arena *gc)
{
    struct buffer out = alloc_buf_gc(256, gc);
    if (c->c2.tls_multi)
    {
        buf_printf(&out, "[%s] ", tls_common_name(c->c2.tls_multi, false));
    }
    return BSTR(&out);
}

void
pre_setup(const struct options *options)
{
#ifdef _WIN32
    if (options->exit_event_name)
    {
        win32_signal_open(&win32_signal, WSO_FORCE_SERVICE, options->exit_event_name,
                          options->exit_event_initial_state);
    }
    else
    {
        win32_signal_open(&win32_signal, WSO_FORCE_CONSOLE, NULL, false);

        /* put a title on the top window bar */
        if (win32_signal.mode == WSO_MODE_CONSOLE)
        {
            window_title_save(&window_title);
            window_title_generate(options->config);
        }
    }
#endif /* ifdef _WIN32 */
}

void
reset_coarse_timers(struct context *c)
{
    c->c2.coarse_timer_wakeup = 0;
}

/*
 * Initialise the server poll timeout timer
 * This timer is used in the http/socks proxy setup so it needs to be setup
 * before
 */
static void
do_init_server_poll_timeout(struct context *c)
{
    update_time();
    if (c->options.ce.connect_timeout)
    {
        event_timeout_init(&c->c2.server_poll_interval, c->options.ce.connect_timeout, now);
    }
}

/*
 * Initialize timers
 */
static void
do_init_timers(struct context *c, bool deferred)
{
    update_time();
    reset_coarse_timers(c);

    /* initialize inactivity timeout */
    if (c->options.inactivity_timeout)
    {
        event_timeout_init(&c->c2.inactivity_interval, c->options.inactivity_timeout, now);
    }

    /* initialize inactivity timeout */
    if (c->options.session_timeout)
    {
        event_timeout_init(&c->c2.session_interval, c->options.session_timeout, now);
    }

    /* initialize pings */
    if (dco_enabled(&c->options))
    {
        /* The DCO kernel module will send the pings instead of user space */
        event_timeout_clear(&c->c2.ping_rec_interval);
        event_timeout_clear(&c->c2.ping_send_interval);
    }
    else
    {
        if (c->options.ping_send_timeout)
        {
            event_timeout_init(&c->c2.ping_send_interval, c->options.ping_send_timeout, 0);
        }

        if (c->options.ping_rec_timeout)
        {
            event_timeout_init(&c->c2.ping_rec_interval, c->options.ping_rec_timeout, now);
        }
    }

    /* If the auth-token renewal interval is shorter than reneg-sec, arm
     * "auth-token renewal" timer to send additional auth-token to update the
     * token on the client more often.  If not, this happens automatically
     * at renegotiation time, without needing an extra event.
     */
    if (c->options.auth_token_generate
        && c->options.auth_token_renewal < c->options.renegotiate_seconds)
    {
        event_timeout_init(&c->c2.auth_token_renewal_interval, c->options.auth_token_renewal, now);
    }

    if (!deferred)
    {
        /* initialize connection establishment timer */
        event_timeout_init(&c->c2.wait_for_connect, 1, now);

        /* initialize occ timers */

        if (c->options.occ && !TLS_MODE(c) && c->c2.options_string_local
            && c->c2.options_string_remote)
        {
            event_timeout_init(&c->c2.occ_interval, OCC_INTERVAL_SECONDS, now);
        }

        if (c->options.mtu_test)
        {
            event_timeout_init(&c->c2.occ_mtu_load_test_interval, OCC_MTU_LOAD_INTERVAL_SECONDS,
                               now);
        }

        /* initialize packet_id persistence timer */
        if (c->options.packet_id_file)
        {
            event_timeout_init(&c->c2.packet_id_persist_interval, 60, now);
        }

        /* initialize tmp_int optimization that limits the number of times we call
         * tls_multi_process in the main event loop */
        interval_init(&c->c2.tmp_int, TLS_MULTI_HORIZON, TLS_MULTI_REFRESH);
    }
}

/*
 * Initialize traffic shaper.
 */
static void
do_init_traffic_shaper(struct context *c)
{
    /* initialize traffic shaper (i.e. transmit bandwidth limiter) */
    if (c->options.shaper)
    {
        shaper_init(&c->c2.shaper, c->options.shaper);
        shaper_msg(&c->c2.shaper);
    }
}

/*
 * Allocate route list structures for IPv4 and IPv6
 * (we do this for IPv4 even if no --route option has been seen, as other
 * parts of OpenVPN might want to fill the route-list with info, e.g. DHCP)
 */
static void
do_alloc_route_list(struct context *c)
{
    if (!c->c1.route_list)
    {
        ALLOC_OBJ_CLEAR_GC(c->c1.route_list, struct route_list, &c->gc);
    }
    if (c->options.routes_ipv6 && !c->c1.route_ipv6_list)
    {
        ALLOC_OBJ_CLEAR_GC(c->c1.route_ipv6_list, struct route_ipv6_list, &c->gc);
    }
}


/*
 * Initialize the route list, resolving any DNS names in route
 * options and saving routes in the environment.
 */
static void
do_init_route_list(const struct options *options, struct route_list *route_list,
                   const struct link_socket_info *link_socket_info, struct env_set *es,
                   openvpn_net_ctx_t *ctx)
{
    const char *gw = NULL;
    int dev = dev_type_enum(options->dev, options->dev_type);
    int metric = 0;

    /* if DCO is enabled we have both regular routes and iroutes in the system
     * routing table, and normal routes must have a higher metric for that to
     * work so that iroutes are always matched first
     */
    if (dco_enabled(options))
    {
        metric = DCO_DEFAULT_METRIC;
    }

    if (dev == DEV_TYPE_TUN && (options->topology == TOP_NET30 || options->topology == TOP_P2P))
    {
        gw = options->ifconfig_remote_netmask;
    }
    if (options->route_default_gateway)
    {
        gw = options->route_default_gateway;
    }
    if (options->route_default_metric)
    {
        metric = options->route_default_metric;
    }

    if (init_route_list(route_list, options->routes, gw, metric,
                        link_socket_current_remote(link_socket_info), es, ctx))
    {
        /* copy routes to environment */
        setenv_routes(es, route_list);
    }
}

static void
do_init_route_ipv6_list(const struct options *options, struct route_ipv6_list *route_ipv6_list,
                        const struct link_socket_info *link_socket_info, struct env_set *es,
                        openvpn_net_ctx_t *ctx)
{
    const char *gw = NULL;
    int metric = -1; /* no metric set */

    /* see explanation in do_init_route_list() */
    if (dco_enabled(options))
    {
        metric = DCO_DEFAULT_METRIC;
    }

    gw = options->ifconfig_ipv6_remote; /* default GW = remote end */
    if (options->route_ipv6_default_gateway)
    {
        gw = options->route_ipv6_default_gateway;
    }

    if (options->route_default_metric)
    {
        metric = options->route_default_metric;
    }

    /* redirect (IPv6) gateway to VPN?  if yes, add a few more specifics
     */
    if (options->routes_ipv6->flags & RG_REROUTE_GW && options->ifconfig_ipv6_local)
    {
        char *opt_list[] = { "::/3", "2000::/4", "3000::/4", "fc00::/7", NULL };
        int i;

        for (i = 0; opt_list[i]; i++)
        {
            add_route_ipv6_to_option_list(options->routes_ipv6,
                                          string_alloc(opt_list[i], options->routes_ipv6->gc), NULL,
                                          NULL, options->route_default_table_id);
        }
    }

    if (init_route_ipv6_list(route_ipv6_list, options->routes_ipv6, gw, metric,
                             link_socket_current_remote_ipv6(link_socket_info), es, ctx))
    {
        /* copy routes to environment */
        setenv_routes_ipv6(es, route_ipv6_list);
    }
}


/*
 * Called after all initialization has been completed.
 */
void
initialization_sequence_completed(struct context *c, const unsigned int flags)
{
    static const char message[] = "Initialization Sequence Completed";

    /* Reset the unsuccessful connection counter on complete initialisation */
    c->options.unsuccessful_attempts = 0;

    /* If we delayed UID/GID downgrade or chroot, do it now */
    do_uid_gid_chroot(c, true);

    /* Test if errors */
    if (flags & ISC_ERRORS)
    {
#ifdef _WIN32
        show_routes(M_INFO | M_NOPREFIX);
        show_adapters(M_INFO | M_NOPREFIX);
        msg(M_INFO, "%s With Errors ( see http://openvpn.net/faq.html#dhcpclientserv )", message);
#else
#ifdef ENABLE_SYSTEMD
        sd_notifyf(0, "STATUS=Failed to start up: %s With Errors\nERRNO=1", message);
#endif /* HAVE_SYSTEMD_SD_DAEMON_H */
        msg(M_INFO, "%s With Errors", message);
#endif
    }
    else
    {
#ifdef ENABLE_SYSTEMD
        sd_notifyf(0, "STATUS=%s", message);
#endif
        msg(M_INFO, "%s", message);
    }

    /* Flag that we initialized */
    if ((flags & (ISC_ERRORS | ISC_SERVER)) == 0)
    {
        c->options.no_advance = true;
    }

#ifdef _WIN32
    fork_register_dns_action(c->c1.tuntap);
#endif

#ifdef ENABLE_MANAGEMENT
    /* Tell management interface that we initialized */
    if (management)
    {
        in_addr_t *tun_local = NULL;
        struct in6_addr *tun_local6 = NULL;
        struct openvpn_sockaddr local, remote;
        struct link_socket_actual *actual;
        socklen_t sa_len = sizeof(local);
        const char *detail = "SUCCESS";
        if (flags & ISC_ERRORS)
        {
            detail = "ERROR";
        }
        /* Flag route error only on platforms where trivial "already exists" errors
         * are filtered out. Currently this is the case on Windows or if usng netlink.
         */
#if defined(_WIN32) || defined(ENABLE_SITNL)
        else if (flags & ISC_ROUTE_ERRORS)
        {
            detail = "ROUTE_ERROR";
        }
#endif

        CLEAR(local);
        actual = &get_link_socket_info(c)->lsa->actual;
        remote = actual->dest;
        getsockname(c->c2.link_sockets[0]->sd, &local.addr.sa, &sa_len);
#if ENABLE_IP_PKTINFO
        if (!addr_defined(&local))
        {
            switch (local.addr.sa.sa_family)
            {
                case AF_INET:
#if defined(HAVE_IN_PKTINFO) && defined(HAVE_IPI_SPEC_DST)
                    local.addr.in4.sin_addr = actual->pi.in4.ipi_spec_dst;
#else
                    local.addr.in4.sin_addr = actual->pi.in4;
#endif
                    break;

                case AF_INET6:
                    local.addr.in6.sin6_addr = actual->pi.in6.ipi6_addr;
                    break;
            }
        }
#endif

        if (c->c1.tuntap)
        {
            tun_local = &c->c1.tuntap->local;
            tun_local6 = &c->c1.tuntap->local_ipv6;
        }
        management_set_state(management, OPENVPN_STATE_CONNECTED, detail, tun_local, tun_local6,
                             &local, &remote);
        if (tun_local)
        {
            management_post_tunnel_open(management, *tun_local);
        }
    }
#endif /* ifdef ENABLE_MANAGEMENT */
}

/**
 * Determine if external route commands should be executed based on
 * configured options and backend driver
 */
static bool
route_noexec_enabled(const struct options *o, const struct tuntap *tt)
{
    return o->route_noexec || (tt && tt->backend_driver == DRIVER_AFUNIX)
           || (tt && tt->backend_driver == DRIVER_NULL);
}

/*
 * Possibly add routes and/or call route-up script
 * based on options.
 */
bool
do_route(const struct options *options, struct route_list *route_list,
         struct route_ipv6_list *route_ipv6_list, const struct tuntap *tt,
         const struct plugin_list *plugins, struct env_set *es, openvpn_net_ctx_t *ctx)
{
    bool ret = true;
    if (!route_noexec_enabled(options, tt) && (route_list || route_ipv6_list))
    {
        ret = add_routes(route_list, route_ipv6_list, tt, ROUTE_OPTION_FLAGS(options), es, ctx);
        setenv_int(es, "redirect_gateway", route_did_redirect_default_gateway(route_list));
    }
#ifdef ENABLE_MANAGEMENT
    if (management)
    {
        management_up_down(management, "UP", es);
    }
#endif

    if (plugin_defined(plugins, OPENVPN_PLUGIN_ROUTE_UP))
    {
        if (plugin_call(plugins, OPENVPN_PLUGIN_ROUTE_UP, NULL, NULL, es)
            != OPENVPN_PLUGIN_FUNC_SUCCESS)
        {
            msg(M_WARN, "WARNING: route-up plugin call failed");
        }
    }

    if (options->route_script)
    {
        struct argv argv = argv_new();
        setenv_str(es, "script_type", "route-up");
        argv_parse_cmd(&argv, options->route_script);
        openvpn_run_script(&argv, es, 0, "--route-up");
        argv_free(&argv);
    }

#ifdef _WIN32
    if (options->show_net_up)
    {
        show_routes(M_INFO | M_NOPREFIX);
        show_adapters(M_INFO | M_NOPREFIX);
    }
    else if (check_debug_level(D_SHOW_NET))
    {
        show_routes(D_SHOW_NET | M_NOPREFIX);
        show_adapters(D_SHOW_NET | M_NOPREFIX);
    }
#endif
    return ret;
}

/*
 * initialize tun/tap device object
 */
static void
do_init_tun(struct context *c)
{
    c->c1.tuntap = init_tun(c->options.dev, c->options.dev_type, c->options.topology,
                            c->options.ifconfig_local, c->options.ifconfig_remote_netmask,
                            c->options.ifconfig_ipv6_local, c->options.ifconfig_ipv6_netbits,
                            c->options.ifconfig_ipv6_remote, c->c1.link_socket_addrs[0].bind_local,
                            c->c1.link_socket_addrs[0].remote_list, !c->options.ifconfig_nowarn,
                            c->c2.es, &c->net_ctx, c->c1.tuntap);

    if (is_tun_afunix(c->options.dev_node))
    {
        /* Using AF_UNIX trumps using DCO */
        c->c1.tuntap->backend_driver = DRIVER_AFUNIX;
    }
    else if (is_dev_type(c->options.dev, c->options.dev_type, "null"))
    {
        c->c1.tuntap->backend_driver = DRIVER_NULL;
    }
#ifdef _WIN32
    else
    {
        c->c1.tuntap->backend_driver = c->options.windows_driver;
    }
#else
    else if (dco_enabled(&c->options))
    {
        c->c1.tuntap->backend_driver = DRIVER_DCO;
    }
    else
    {
        c->c1.tuntap->backend_driver = DRIVER_GENERIC_TUNTAP;
    }
#endif

    init_tun_post(c->c1.tuntap, &c->c2.frame, &c->options.tuntap_options);

    c->c1.tuntap_owned = true;
}

/*
 * Open tun/tap device, ifconfig, call up script, etc.
 */


static bool
can_preserve_tun(struct tuntap *tt)
{
    if (tt && tt->backend_driver == DRIVER_AFUNIX)
    {
        return false;
    }
#ifdef TARGET_ANDROID
    return false;
#else
    return is_tun_type_set(tt);
#endif
}

/**
 * Add WFP filters to block traffic to local networks.
 * Depending on the configuration all or just DNS is filtered.
 * This functionality is only available on Windows on all other
 * systems this function is a noop.
 *
 * @param c pointer to the connection context
 */
static void
add_wfp_block(struct context *c)
{
#if defined(_WIN32)
    /* Fortify 'redirect-gateway block-local' with firewall rules? */
    bool block_local = block_local_needed(c->c1.route_list);

    if (c->options.block_outside_dns || block_local)
    {
        BOOL dns_only = !block_local;
        if (!win_wfp_block(c->c1.tuntap->adapter_index, c->options.msg_channel, dns_only))
        {
            msg(M_FATAL, "WFP: initialization failed");
        }
    }
#endif
}

/**
 * Remove any WFP block filters previously added.
 * This functionality is only available on Windows on all other
 * systems the function is a noop.
 *
 * @param c             pointer to the connection context
 * @param adapter_index the VPN adapter index
 */
static void
del_wfp_block(struct context *c, unsigned long adapter_index)
{
#if defined(_WIN32)
    if (c->options.block_outside_dns || block_local_needed(c->c1.route_list))
    {
        if (!win_wfp_uninit(adapter_index, c->options.msg_channel))
        {
            msg(M_FATAL, "WFP: deinitialization failed");
        }
    }
#endif
}

/**
 * Determines if ifconfig execution should be disabled because of a
 * @param c
 * @return
 */
static bool
ifconfig_noexec_enabled(const struct context *c)
{
    return c->options.ifconfig_noexec
           || (c->c1.tuntap && c->c1.tuntap->backend_driver == DRIVER_AFUNIX)
           || (c->c1.tuntap && c->c1.tuntap->backend_driver == DRIVER_NULL);
}

static void
open_tun_backend(struct context *c)
{
    struct tuntap *tt = c->c1.tuntap;

    if (tt->backend_driver == DRIVER_NULL)
    {
        open_tun_null(c->c1.tuntap);
    }
    else if (tt->backend_driver == DRIVER_AFUNIX)
    {
        open_tun_afunix(&c->options, c->c2.frame.tun_mtu, tt, c->c2.es);
    }
    else
    {
        open_tun(c->options.dev, c->options.dev_type, c->options.dev_node, tt, &c->net_ctx);
    }
    msg(M_INFO, "%s device [%s] opened", print_tun_backend_driver(tt->backend_driver),
        tt->actual_name);
}


static bool
do_open_tun(struct context *c, int *error_flags)
{
    struct gc_arena gc = gc_new();
    bool ret = false;
    *error_flags = 0;

    if (!can_preserve_tun(c->c1.tuntap))
    {
#ifdef TARGET_ANDROID
        /* If we emulate persist-tun on android we still have to open a new tun and
         * then close the old */
        int oldtunfd = -1;
        if (c->c1.tuntap)
        {
            oldtunfd = c->c1.tuntap->fd;
            free(c->c1.tuntap);
            c->c1.tuntap = NULL;
            c->c1.tuntap_owned = false;
        }
#endif

        /* initialize (but do not open) tun/tap object, this also sets
         * the backend driver type */
        do_init_tun(c);

        /* inherit the dco context from the tuntap object */
        if (c->c2.tls_multi)
        {
            c->c2.tls_multi->dco = &c->c1.tuntap->dco;
        }

#ifdef _WIN32
        /* store (hide) interactive service handle in tuntap_options */
        c->c1.tuntap->options.msg_channel = c->options.msg_channel;
        msg(D_ROUTE, "interactive service msg_channel=%" PRIuPTR, (intptr_t)c->options.msg_channel);
#endif

        /* allocate route list structure */
        do_alloc_route_list(c);

        /* parse and resolve the route option list */
        ASSERT(c->c2.link_sockets[0]);
        if (c->options.routes && c->c1.route_list)
        {
            do_init_route_list(&c->options, c->c1.route_list, &c->c2.link_sockets[0]->info,
                               c->c2.es, &c->net_ctx);
        }
        if (c->options.routes_ipv6 && c->c1.route_ipv6_list)
        {
            do_init_route_ipv6_list(&c->options, c->c1.route_ipv6_list,
                                    &c->c2.link_sockets[0]->info, c->c2.es, &c->net_ctx);
        }

        /* do ifconfig */
        if (!ifconfig_noexec_enabled(c) && ifconfig_order(c->c1.tuntap) == IFCONFIG_BEFORE_TUN_OPEN)
        {
            /* guess actual tun/tap unit number that will be returned
             * by open_tun */
            const char *guess =
                guess_tuntap_dev(c->options.dev, c->options.dev_type, c->options.dev_node, &gc);
            do_ifconfig(c->c1.tuntap, guess, c->c2.frame.tun_mtu, c->c2.es, &c->net_ctx);
        }

        /* possibly add routes */
        if (route_order(c->c1.tuntap) == ROUTE_BEFORE_TUN)
        {
            /* Ignore route_delay, would cause ROUTE_BEFORE_TUN to be ignored */
            bool status = do_route(&c->options, c->c1.route_list, c->c1.route_ipv6_list,
                                   c->c1.tuntap, c->plugins, c->c2.es, &c->net_ctx);
            *error_flags |= (status ? 0 : ISC_ROUTE_ERRORS);
        }
#ifdef TARGET_ANDROID
        /* Store the old fd inside the fd so open_tun can use it */
        c->c1.tuntap->fd = oldtunfd;
#endif

        if (dco_enabled(&c->options))
        {
            ovpn_dco_init(c);
        }

        /* open the tun device */
        open_tun_backend(c);

        /* set the hardware address */
        if (c->options.lladdr)
        {
            set_lladdr(&c->net_ctx, c->c1.tuntap->actual_name, c->options.lladdr, c->c2.es);
        }

        /* do ifconfig */
        if (!ifconfig_noexec_enabled(c) && ifconfig_order(c->c1.tuntap) == IFCONFIG_AFTER_TUN_OPEN)
        {
            do_ifconfig(c->c1.tuntap, c->c1.tuntap->actual_name, c->c2.frame.tun_mtu, c->c2.es,
                        &c->net_ctx);
        }

        run_dns_up_down(true, &c->options, c->c1.tuntap, &c->persist.duri);

        /* run the up script */
        run_up_down(c->options.up_script, c->plugins, OPENVPN_PLUGIN_UP, c->c1.tuntap->actual_name,
#ifdef _WIN32
                    c->c1.tuntap->adapter_index,
#endif
                    dev_type_string(c->options.dev, c->options.dev_type), c->c2.frame.tun_mtu,
                    print_in_addr_t(c->c1.tuntap->local, IA_EMPTY_IF_UNDEF, &gc),
                    print_in_addr_t(c->c1.tuntap->remote_netmask, IA_EMPTY_IF_UNDEF, &gc), "init",
                    NULL, "up", c->c2.es);

        add_wfp_block(c);

        /* possibly add routes */
        if ((route_order(c->c1.tuntap) == ROUTE_AFTER_TUN) && (!c->options.route_delay_defined))
        {
            bool status = do_route(&c->options, c->c1.route_list, c->c1.route_ipv6_list,
                                   c->c1.tuntap, c->plugins, c->c2.es, &c->net_ctx);
            *error_flags |= (status ? 0 : ISC_ROUTE_ERRORS);
        }

        ret = true;
        static_context = c;
    }
    else
    {
        msg(M_INFO, "Preserving previous TUN/TAP instance: %s", c->c1.tuntap->actual_name);

        /* explicitly set the ifconfig_* env vars */
        do_ifconfig_setenv(c->c1.tuntap, c->c2.es);

        run_dns_up_down(true, &c->options, c->c1.tuntap, &c->persist.duri);

        /* run the up script if user specified --up-restart */
        if (c->options.up_restart)
        {
            run_up_down(c->options.up_script, c->plugins, OPENVPN_PLUGIN_UP,
                        c->c1.tuntap->actual_name,
#ifdef _WIN32
                        c->c1.tuntap->adapter_index,
#endif
                        dev_type_string(c->options.dev, c->options.dev_type), c->c2.frame.tun_mtu,
                        print_in_addr_t(c->c1.tuntap->local, IA_EMPTY_IF_UNDEF, &gc),
                        print_in_addr_t(c->c1.tuntap->remote_netmask, IA_EMPTY_IF_UNDEF, &gc),
                        "restart", NULL, "up", c->c2.es);
        }

        add_wfp_block(c);
    }
    gc_free(&gc);
    return ret;
}

/*
 * Close TUN/TAP device
 */

static void
do_close_tun_simple(struct context *c)
{
    msg(D_CLOSE, "Closing %s interface", print_tun_backend_driver(c->c1.tuntap->backend_driver));

    if (c->c1.tuntap)
    {
        if (!ifconfig_noexec_enabled(c))
        {
            undo_ifconfig(c->c1.tuntap, &c->net_ctx);
        }
        if (c->c1.tuntap->backend_driver == DRIVER_AFUNIX)
        {
            close_tun_afunix(c->c1.tuntap);
        }
        else if (c->c1.tuntap->backend_driver == DRIVER_NULL)
        {
            free(c->c1.tuntap->actual_name);
            free(c->c1.tuntap);
        }
        else
        {
            close_tun(c->c1.tuntap, &c->net_ctx);
        }
        c->c1.tuntap = NULL;
    }
    c->c1.tuntap_owned = false;
    CLEAR(c->c1.pulled_options_digest_save);
}

static void
do_close_tun(struct context *c, bool force)
{
    /* With dco-win we open tun handle in the very beginning.
     * In case when tun wasn't opened - like we haven't connected,
     * we still need to close tun handle
     */
    if (tuntap_is_dco_win(c->c1.tuntap) && !is_tun_type_set(c->c1.tuntap))
    {
        do_close_tun_simple(c);
        return;
    }

    if (!c->c1.tuntap || !c->c1.tuntap_owned)
    {
        return;
    }

    struct gc_arena gc = gc_new();
    const char *tuntap_actual = string_alloc(c->c1.tuntap->actual_name, &gc);
    const in_addr_t local = c->c1.tuntap->local;
    const in_addr_t remote_netmask = c->c1.tuntap->remote_netmask;
    unsigned long adapter_index = 0;
#ifdef _WIN32
    adapter_index = c->c1.tuntap->adapter_index;
#endif

    run_dns_up_down(false, &c->options, c->c1.tuntap, &c->persist.duri);

    if (force || !(c->sig->signal_received == SIGUSR1 && c->options.persist_tun))
    {
        static_context = NULL;

#ifdef ENABLE_MANAGEMENT
        /* tell management layer we are about to close the TUN/TAP device */
        if (management)
        {
            management_pre_tunnel_close(management);
            management_up_down(management, "DOWN", c->c2.es);
        }
#endif

        /* delete any routes we added */
        if (c->c1.route_list || c->c1.route_ipv6_list)
        {
            run_up_down(c->options.route_predown_script, c->plugins, OPENVPN_PLUGIN_ROUTE_PREDOWN,
                        tuntap_actual,
#ifdef _WIN32
                        adapter_index,
#endif
                        NULL, c->c2.frame.tun_mtu, print_in_addr_t(local, IA_EMPTY_IF_UNDEF, &gc),
                        print_in_addr_t(remote_netmask, IA_EMPTY_IF_UNDEF, &gc), "init",
                        signal_description(c->sig->signal_received, c->sig->signal_text),
                        "route-pre-down", c->c2.es);

            delete_routes(c->c1.route_list, c->c1.route_ipv6_list, c->c1.tuntap,
                          ROUTE_OPTION_FLAGS(&c->options), c->c2.es, &c->net_ctx);
        }

        /* actually close tun/tap device based on --down-pre flag */
        if (!c->options.down_pre)
        {
            do_close_tun_simple(c);
        }

        /* Run the down script -- note that it will run at reduced
         * privilege if, for example, "--user" was used. */
        run_up_down(c->options.down_script, c->plugins, OPENVPN_PLUGIN_DOWN, tuntap_actual,
#ifdef _WIN32
                    adapter_index,
#endif
                    NULL, c->c2.frame.tun_mtu, print_in_addr_t(local, IA_EMPTY_IF_UNDEF, &gc),
                    print_in_addr_t(remote_netmask, IA_EMPTY_IF_UNDEF, &gc), "init",
                    signal_description(c->sig->signal_received, c->sig->signal_text), "down",
                    c->c2.es);

        del_wfp_block(c, adapter_index);

        /* actually close tun/tap device based on --down-pre flag */
        if (c->options.down_pre)
        {
            do_close_tun_simple(c);
        }
    }
    else
    {
        /* run the down script on this restart if --up-restart was specified */
        if (c->options.up_restart)
        {
            run_up_down(c->options.down_script, c->plugins, OPENVPN_PLUGIN_DOWN, tuntap_actual,
#ifdef _WIN32
                        adapter_index,
#endif
                        NULL, c->c2.frame.tun_mtu, print_in_addr_t(local, IA_EMPTY_IF_UNDEF, &gc),
                        print_in_addr_t(remote_netmask, IA_EMPTY_IF_UNDEF, &gc), "restart",
                        signal_description(c->sig->signal_received, c->sig->signal_text), "down",
                        c->c2.es);
        }

        del_wfp_block(c, adapter_index);
    }
    gc_free(&gc);
}

void
tun_abort(void)
{
    struct context *c = static_context;
    if (c)
    {
        static_context = NULL;
        do_close_tun(c, true);
    }
}

/*
 * Handle delayed tun/tap interface bringup due to --up-delay or --pull
 */

/**
 * Helper for do_up().  Take two option hashes and return true if they are not
 * equal, or either one is all-zeroes.
 */
static bool
options_hash_changed_or_zero(const struct sha256_digest *a, const struct sha256_digest *b)
{
    const struct sha256_digest zero = { { 0 } };
    return memcmp(a, b, sizeof(struct sha256_digest))
           || !memcmp(a, &zero, sizeof(struct sha256_digest));
}

/**
 * Helper function for tls_print_deferred_options_results
 * Adds the ", " delimitor if there already some data in the
 * buffer.
 */
static void
add_delim_if_non_empty(struct buffer *buf, const char *header)
{
    if (buf_len(buf) > strlen(header))
    {
        buf_printf(buf, ", ");
    }
}


/**
 * Prints the results of options imported for the data channel
 * @param c
 */
static void
tls_print_deferred_options_results(struct context *c)
{
    struct options *o = &c->options;

    struct buffer out;
    uint8_t line[1024] = { 0 };
    buf_set_write(&out, line, sizeof(line));


    if (cipher_kt_mode_aead(o->ciphername))
    {
        buf_printf(&out, "Data Channel: cipher '%s'", cipher_kt_name(o->ciphername));
    }
    else
    {
        buf_printf(&out, "Data Channel: cipher '%s', auth '%s'", cipher_kt_name(o->ciphername),
                   md_kt_name(o->authname));
    }

    if (o->use_peer_id)
    {
        buf_printf(&out, ", peer-id: %d", o->peer_id);
    }

#ifdef USE_COMP
    if (c->c2.comp_context)
    {
        buf_printf(&out, ", compression: '%s'", c->c2.comp_context->alg.name);
    }
#endif

    msg(D_HANDSHAKE, "%s", BSTR(&out));

    buf_clear(&out);

    const char *header = "Timers: ";

    buf_printf(&out, "%s", header);

    if (o->ping_send_timeout)
    {
        buf_printf(&out, "ping %d", o->ping_send_timeout);
    }

    if (o->ping_rec_timeout_action != PING_UNDEF)
    {
        /* yes unidirectional ping is possible .... */
        add_delim_if_non_empty(&out, header);

        if (o->ping_rec_timeout_action == PING_EXIT)
        {
            buf_printf(&out, "ping-exit %d", o->ping_rec_timeout);
        }
        else
        {
            buf_printf(&out, "ping-restart %d", o->ping_rec_timeout);
        }
    }

    if (o->inactivity_timeout)
    {
        add_delim_if_non_empty(&out, header);

        buf_printf(&out, "inactive %d", o->inactivity_timeout);
        if (o->inactivity_minimum_bytes)
        {
            buf_printf(&out, " %" PRIu64, o->inactivity_minimum_bytes);
        }
    }

    if (o->session_timeout)
    {
        add_delim_if_non_empty(&out, header);
        buf_printf(&out, "session-timeout %d", o->session_timeout);
    }

    if (buf_len(&out) > strlen(header))
    {
        msg(D_HANDSHAKE, "%s", BSTR(&out));
    }

    buf_clear(&out);
    header = "Protocol options: ";
    buf_printf(&out, "%s", header);

    if (c->options.ce.explicit_exit_notification)
    {
        buf_printf(&out, "explicit-exit-notify %d", c->options.ce.explicit_exit_notification);
    }
    if (c->options.imported_protocol_flags)
    {
        add_delim_if_non_empty(&out, header);

        buf_printf(&out, "protocol-flags");

        if (o->imported_protocol_flags & CO_USE_CC_EXIT_NOTIFY)
        {
            buf_printf(&out, " cc-exit");
        }
        if (o->imported_protocol_flags & CO_USE_TLS_KEY_MATERIAL_EXPORT)
        {
            buf_printf(&out, " tls-ekm");
        }
        if (o->imported_protocol_flags & CO_USE_DYNAMIC_TLS_CRYPT)
        {
            buf_printf(&out, " dyn-tls-crypt");
        }
        if (o->imported_protocol_flags & CO_EPOCH_DATA_KEY_FORMAT)
        {
            buf_printf(&out, " aead-epoch");
        }
    }

    if (buf_len(&out) > strlen(header))
    {
        msg(D_HANDSHAKE, "%s", BSTR(&out));
    }
}


/**
 * This function is expected to be invoked after open_tun() was performed.
 *
 * This kind of behaviour is required by DCO, because the following operations
 * can be done only after the DCO device was created and the new peer was
 * properly added.
 */
static bool
do_deferred_options_part2(struct context *c)
{
    struct frame *frame_fragment = NULL;
#ifdef ENABLE_FRAGMENT
    if (c->options.ce.fragment)
    {
        frame_fragment = &c->c2.frame_fragment;
    }
#endif

    struct tls_session *session = &c->c2.tls_multi->session[TM_ACTIVE];
    if (!tls_session_update_crypto_params(c->c2.tls_multi, session, &c->options, &c->c2.frame,
                                          frame_fragment, get_link_socket_info(c),
                                          &c->c1.tuntap->dco))
    {
        msg(D_TLS_ERRORS, "OPTIONS ERROR: failed to import crypto options");
        return false;
    }

    return true;
}

bool
do_up(struct context *c, bool pulled_options, unsigned int option_types_found)
{
    int error_flags = 0;
    if (!c->c2.do_up_ran)
    {
        reset_coarse_timers(c);

        if (pulled_options)
        {
            if (!do_deferred_options(c, option_types_found, false))
            {
                msg(D_PUSH_ERRORS, "ERROR: Failed to apply push options");
                return false;
            }
        }

        /* if --up-delay specified, open tun, do ifconfig, and run up script now */
        if (c->options.up_delay || PULL_DEFINED(&c->options))
        {
            c->c2.did_open_tun = do_open_tun(c, &error_flags);
            update_time();

            /*
             * Was tun interface object persisted from previous restart iteration,
             * and if so did pulled options string change from previous iteration?
             */
            if (!c->c2.did_open_tun && PULL_DEFINED(&c->options) && c->c1.tuntap
                && options_hash_changed_or_zero(&c->c1.pulled_options_digest_save,
                                                &c->c2.pulled_options_digest))
            {
                /* if so, close tun, delete routes, then reinitialize tun and add routes */
                msg(M_INFO,
                    "NOTE: Pulled options changed on restart, will need to close and reopen TUN/TAP device.");

                bool tt_dco_win = tuntap_is_dco_win(c->c1.tuntap);
                do_close_tun(c, true);

                if (tt_dco_win)
                {
                    msg(M_NONFATAL, "dco-win doesn't yet support reopening TUN device");
                    /* prevent link_socket_close() from closing handle with WinSock API */
                    c->c2.link_sockets[0]->sd = SOCKET_UNDEFINED;
                    return false;
                }
                else
                {
                    management_sleep(1);
                    c->c2.did_open_tun = do_open_tun(c, &error_flags);
                    update_time();
                }
            }
        }
    }

    /* This part needs to be run in p2p mode (without pull) when the client
     * reconnects to setup various things (like DCO and NCP cipher) that
     * might have changed from the previous connection.
     */
    if (!c->c2.do_up_ran
        || (c->c2.tls_multi && c->c2.tls_multi->multi_state == CAS_RECONNECT_PENDING))
    {
        if (c->mode == MODE_POINT_TO_POINT)
        {
            /* ovpn-dco requires adding the peer now, before any option can be set,
             * but *after* having parsed the pushed peer-id in do_deferred_options()
             */
            int ret = dco_p2p_add_new_peer(c);
            if (ret < 0)
            {
                msg(D_DCO, "Cannot add peer to DCO: %s (%d)", strerror(-ret), ret);
                return false;
            }
        }

        /* do_deferred_options_part2() and do_deferred_p2p_ncp() *must* be
         * invoked after open_tun().
         * This is required by DCO because we must have created the interface
         * and added the peer before we can fiddle with the keys or any other
         * data channel per-peer setting.
         */
        if (pulled_options)
        {
            if (!do_deferred_options_part2(c))
            {
                return false;
            }
        }
        else
        {
            if (c->mode == MODE_POINT_TO_POINT)
            {
                if (!do_deferred_p2p_ncp(c))
                {
                    msg(D_TLS_ERRORS, "ERROR: Failed to apply P2P negotiated protocol options");
                    return false;
                }
            }
        }

        if (c->c2.did_open_tun)
        {
            c->c1.pulled_options_digest_save = c->c2.pulled_options_digest;

            /* if --route-delay was specified, start timer */
            if ((route_order(c->c1.tuntap) == ROUTE_AFTER_TUN) && c->options.route_delay_defined)
            {
                event_timeout_init(&c->c2.route_wakeup, c->options.route_delay, now);
                event_timeout_init(&c->c2.route_wakeup_expire,
                                   c->options.route_delay + c->options.route_delay_window, now);
                tun_standby_init(c->c1.tuntap);
            }
            else
            {
                /* client/p2p --route-delay undefined */
                initialization_sequence_completed(c, error_flags);
            }
        }
        else if (c->options.mode == MODE_POINT_TO_POINT)
        {
            /* client/p2p restart with --persist-tun */
            initialization_sequence_completed(c, error_flags);
        }

        tls_print_deferred_options_results(c);

        c->c2.do_up_ran = true;
        if (c->c2.tls_multi)
        {
            c->c2.tls_multi->multi_state = CAS_CONNECT_DONE;
        }
    }
    return true;
}

bool
do_update(struct context *c, unsigned int option_types_found)
{
    /* Not necessary since to receive the update the openvpn
     * instance must be up and running but just in case
     */
    if (!c->c2.do_up_ran)
    {
        return false;
    }

    bool tt_dco_win = tuntap_is_dco_win(c->c1.tuntap);
    if (tt_dco_win)
    {
        msg(M_NONFATAL, "dco-win doesn't yet support reopening TUN device");
        return false;
    }

    if (!do_deferred_options(c, option_types_found, true))
    {
        msg(D_PUSH_ERRORS, "ERROR: Failed to apply push options");
        return false;
    }

    do_close_tun(c, true);

    management_sleep(1);
    int error_flags = 0;
    c->c2.did_open_tun = do_open_tun(c, &error_flags);
    update_time();

    if (c->c2.did_open_tun)
    {
        /* if --route-delay was specified, start timer */
        if ((route_order(c->c1.tuntap) == ROUTE_AFTER_TUN) && c->options.route_delay_defined)
        {
            event_timeout_init(&c->c2.route_wakeup, c->options.route_delay, now);
            event_timeout_init(&c->c2.route_wakeup_expire,
                               c->options.route_delay + c->options.route_delay_window, now);
            tun_standby_init(c->c1.tuntap);
        }

        initialization_sequence_completed(c, error_flags);
    }

    CLEAR(c->c1.pulled_options_digest_save);

    return true;
}

/*
 * These are the option categories which will be accepted by pull.
 */
unsigned int
pull_permission_mask(const struct context *c)
{
    unsigned int flags = OPT_P_UP | OPT_P_ROUTE_EXTRAS | OPT_P_SOCKBUF | OPT_P_SOCKFLAGS
                         | OPT_P_SETENV | OPT_P_SHAPER | OPT_P_TIMER | OPT_P_COMP | OPT_P_PERSIST
                         | OPT_P_MESSAGES | OPT_P_EXPLICIT_NOTIFY | OPT_P_ECHO | OPT_P_PULL_MODE
                         | OPT_P_PEER_ID | OPT_P_NCP | OPT_P_PUSH_MTU;

    if (!c->options.route_nopull)
    {
        flags |= (OPT_P_ROUTE | OPT_P_DHCPDNS);
    }

    return flags;
}

static bool
do_deferred_p2p_ncp(struct context *c)
{
    if (!c->c2.tls_multi)
    {
        return true;
    }

    c->options.use_peer_id = c->c2.tls_multi->use_peer_id;

    struct tls_session *session = &c->c2.tls_multi->session[TM_ACTIVE];

    const char *ncp_cipher =
        get_p2p_ncp_cipher(session, c->c2.tls_multi->peer_info, &c->options.gc);

    if (ncp_cipher)
    {
        c->options.ciphername = ncp_cipher;
    }
    else if (!c->options.enable_ncp_fallback)
    {
        msg(D_TLS_ERRORS, "ERROR: failed to negotiate cipher with peer and "
                          "--data-ciphers-fallback not enabled. No usable "
                          "data channel cipher");
        return false;
    }

    struct frame *frame_fragment = NULL;
#ifdef ENABLE_FRAGMENT
    if (c->options.ce.fragment)
    {
        frame_fragment = &c->c2.frame_fragment;
    }
#endif

    if (!tls_session_update_crypto_params(c->c2.tls_multi, session, &c->options, &c->c2.frame,
                                          frame_fragment, get_link_socket_info(c),
                                          &c->c1.tuntap->dco))
    {
        msg(D_TLS_ERRORS, "ERROR: failed to set crypto cipher");
        return false;
    }
    return true;
}

bool
do_deferred_options(struct context *c, const unsigned int found, const bool is_update)
{
    if (found & OPT_P_MESSAGES)
    {
        init_verb_mute(c, IVM_LEVEL_1 | IVM_LEVEL_2);
        msg(D_PUSH, "OPTIONS IMPORT: --verb and/or --mute level changed");
    }
    if (found & OPT_P_TIMER)
    {
        do_init_timers(c, true);
        msg(D_PUSH_DEBUG, "OPTIONS IMPORT: timers and/or timeouts modified");
    }

    if (found & OPT_P_EXPLICIT_NOTIFY)
    {
        /* Client side, so just check the first link_socket */
        if (!proto_is_udp(c->c2.link_sockets[0]->info.proto)
            && c->options.ce.explicit_exit_notification)
        {
            msg(D_PUSH, "OPTIONS IMPORT: --explicit-exit-notify can only be used with --proto udp");
            c->options.ce.explicit_exit_notification = 0;
        }
        else
        {
            msg(D_PUSH_DEBUG, "OPTIONS IMPORT: explicit notify parm(s) modified");
        }
    }

    if (found & OPT_P_COMP)
    {
        if (!check_compression_settings_valid(&c->options.comp, D_PUSH_ERRORS))
        {
            msg(D_PUSH_ERRORS, "OPTIONS ERROR: server pushed compression "
                               "settings that are not allowed and will result "
                               "in a non-working connection. "
                               "See also allow-compression in the manual.");
            return false;
        }
#ifdef USE_COMP
        msg(D_PUSH_DEBUG, "OPTIONS IMPORT: compression parms modified");
        comp_uninit(c->c2.comp_context);
        c->c2.comp_context = comp_init(&c->options.comp);
#endif
    }

    if (found & OPT_P_SHAPER)
    {
        msg(D_PUSH, "OPTIONS IMPORT: traffic shaper enabled");
        do_init_traffic_shaper(c);
    }

    if (found & OPT_P_SOCKBUF)
    {
        msg(D_PUSH, "OPTIONS IMPORT: --sndbuf/--rcvbuf options modified");

        for (int i = 0; i < c->c1.link_sockets_num; i++)
        {
            link_socket_update_buffer_sizes(c->c2.link_sockets[i], c->options.rcvbuf,
                                            c->options.sndbuf);
        }
    }

    if (found & OPT_P_SOCKFLAGS)
    {
        msg(D_PUSH, "OPTIONS IMPORT: --socket-flags option modified");
        for (int i = 0; i < c->c1.link_sockets_num; i++)
        {
            link_socket_update_flags(c->c2.link_sockets[i], c->options.sockflags);
        }
    }

    if (found & OPT_P_PERSIST)
    {
        msg(D_PUSH, "OPTIONS IMPORT: --persist options modified");
    }
    if (found & OPT_P_UP)
    {
        msg(D_PUSH, "OPTIONS IMPORT: --ifconfig/up options modified");
    }
    if (found & OPT_P_ROUTE)
    {
        msg(D_PUSH, "OPTIONS IMPORT: route options modified");
    }
    if (found & OPT_P_ROUTE_EXTRAS)
    {
        msg(D_PUSH, "OPTIONS IMPORT: route-related options modified");
    }
    if (found & OPT_P_DHCPDNS)
    {
        msg(D_PUSH, "OPTIONS IMPORT: --ip-win32 and/or --dhcp-option options modified");
    }
    if (found & OPT_P_SETENV)
    {
        msg(D_PUSH, "OPTIONS IMPORT: environment modified");
    }

    if (found & OPT_P_PEER_ID)
    {
        msg(D_PUSH_DEBUG, "OPTIONS IMPORT: peer-id set");
        c->c2.tls_multi->use_peer_id = true;
        c->c2.tls_multi->peer_id = c->options.peer_id;
    }

    /* process (potentially) pushed options */
    if (c->options.pull)
    {
        /* On PUSH_UPDATE, NCP related flags are never updated, and so the code
         * would assume "no cipher pushed = NCP failed" - so, don't call it on
         * updates */
        if (!is_update && !check_pull_client_ncp(c, found))
        {
            return false;
        }

        /* Check if pushed options are compatible with DCO, if enabled */
        if (dco_enabled(&c->options) && !dco_check_pull_options(D_PUSH_ERRORS, &c->options))
        {
            msg(D_PUSH_ERRORS, "OPTIONS ERROR: pushed options are incompatible "
                               "with data channel offload. Use --disable-dco to connect to "
                               "this server");
            return false;
        }
    }

    /* Ensure that for epoch data format is only enabled if also data v2
     * is enabled */
    bool epoch_data = c->options.imported_protocol_flags & CO_EPOCH_DATA_KEY_FORMAT;
    bool datav2_enabled = c->options.use_peer_id && c->options.peer_id < MAX_PEER_ID;

    if (epoch_data && !datav2_enabled)
    {
        msg(D_PUSH_ERRORS, "OPTIONS ERROR: Epoch key data format tag requires "
                           "data v2 (peer-id) to be enabled.");
        return false;
    }


    if (found & OPT_P_PUSH_MTU)
    {
        /* MTU has changed, check that the pushed MTU is small enough to
         * be able to change it */
        msg(D_PUSH, "OPTIONS IMPORT: tun-mtu set to %d", c->options.ce.tun_mtu);

        struct frame *frame = &c->c2.frame;

        if (c->options.ce.tun_mtu > frame->tun_max_mtu)
        {
            msg(D_PUSH_ERRORS,
                "Server-pushed tun-mtu is too large, please add "
                "tun-mtu-max %d in the client configuration",
                c->options.ce.tun_mtu);
        }
        frame->tun_mtu = min_int(frame->tun_max_mtu, c->options.ce.tun_mtu);
    }

    return true;
}

/*
 * Possible hold on initialization, holdtime is the
 * time OpenVPN would wait without management
 */
static bool
do_hold(int holdtime)
{
#ifdef ENABLE_MANAGEMENT
    if (management)
    {
        /* block until management hold is released */
        if (management_hold(management, holdtime))
        {
            return true;
        }
    }
#endif
    return false;
}

/*
 * Sleep before restart.
 */
static void
socket_restart_pause(struct context *c)
{
    int sec = 2;
    int backoff = 0;

    switch (c->mode)
    {
        case CM_TOP:
            sec = 1;
            break;

        case CM_CHILD_UDP:
        case CM_CHILD_TCP:
            sec = c->options.ce.connect_retry_seconds;
            break;
    }

#ifdef ENABLE_DEBUG
    if (GREMLIN_CONNECTION_FLOOD_LEVEL(c->options.gremlin))
    {
        sec = 0;
    }
#endif

    if (auth_retry_get() == AR_NOINTERACT)
    {
        sec = 10;
    }

    /* Slow down reconnection after 5 retries per remote -- for TCP client or UDP tls-client only */
    if (c->mode == CM_CHILD_TCP || (c->options.ce.proto == PROTO_UDP && c->options.tls_client))
    {
        backoff = (c->options.unsuccessful_attempts / c->options.connection_list->len) - 4;
        if (backoff > 0)
        {
            /* sec is less than 2^16; we can left shift it by up to 15 bits without overflow */
            sec = max_int(sec, 1) << min_int(backoff, 15);
        }
        if (c->options.server_backoff_time)
        {
            sec = max_int(sec, c->options.server_backoff_time);
            c->options.server_backoff_time = 0;
        }

        if (sec > c->options.ce.connect_retry_seconds_max)
        {
            sec = c->options.ce.connect_retry_seconds_max;
        }
    }

    if (c->persist.restart_sleep_seconds > 0 && c->persist.restart_sleep_seconds > sec)
    {
        sec = c->persist.restart_sleep_seconds;
    }
    else if (c->persist.restart_sleep_seconds == -1)
    {
        sec = 0;
    }
    c->persist.restart_sleep_seconds = 0;

    /* do management hold on context restart, i.e. second, third, fourth, etc. initialization */
    if (do_hold(sec))
    {
        sec = 0;
    }

    if (sec)
    {
        msg(D_RESTART, "Restart pause, %d second(s)", sec);
        management_sleep(sec);
    }
}

/*
 * Do a possible pause on context_2 initialization.
 */
static void
do_startup_pause(struct context *c)
{
    if (!c->first_time)
    {
        socket_restart_pause(c);
    }
    else
    {
        do_hold(0); /* do management hold on first context initialization */
    }
}

static size_t
get_frame_mtu(struct context *c, const struct options *o)
{
    size_t mtu;

    if (o->ce.link_mtu_defined)
    {
        ASSERT(o->ce.link_mtu_defined);
        /* if we have a link mtu defined we calculate what the old code
         * would have come up with as tun-mtu */
        size_t overhead = frame_calculate_protocol_header_size(&c->c1.ks.key_type, o, true);
        mtu = o->ce.link_mtu - overhead;
    }
    else
    {
        ASSERT(o->ce.tun_mtu_defined);
        mtu = o->ce.tun_mtu;
    }

    if (mtu < TUN_MTU_MIN)
    {
        msg(M_WARN, "TUN MTU value (%zu) must be at least %d", mtu, TUN_MTU_MIN);
        frame_print(&c->c2.frame, M_FATAL, "MTU is too small");
    }
    return mtu;
}

/*
 * Finalize MTU parameters based on command line or config file options.
 */
static void
frame_finalize_options(struct context *c, const struct options *o)
{
    if (!o)
    {
        o = &c->options;
    }

    struct frame *frame = &c->c2.frame;

    frame->tun_mtu = get_frame_mtu(c, o);
    frame->tun_max_mtu = o->ce.tun_mtu_max;

    /* max mtu needs to be at least as large as the tun mtu */
    frame->tun_max_mtu = max_int(frame->tun_mtu, frame->tun_max_mtu);

    /* We always allow at least 1600 MTU packets to be received in our buffer
     * space to allow server to push "baby giant" MTU sizes */
    frame->tun_max_mtu = max_int(TUN_MTU_MAX_MIN, frame->tun_max_mtu);

    size_t payload_size = frame->tun_max_mtu;

    /* we need to be also large enough to hold larger control channel packets
     * if configured */
    payload_size = max_int(payload_size, o->ce.tls_mtu);

    /* The extra tun needs to be added to the payload size */
    if (o->ce.tun_mtu_defined)
    {
        payload_size += o->ce.tun_mtu_extra;
    }

    /* Add 32 byte of extra space in the buffer to account for small errors
     * in the calculation */
    payload_size += 32;


    /* the space that is reserved before the payload to add extra headers to it
     * we always reserve the space for the worst case */
    size_t headroom = 0;

    /* includes IV and packet ID */
    headroom += crypto_max_overhead();

    /* peer id + opcode */
    headroom += 4;

    /* socks proxy header */
    headroom += 10;

    /* compression header and fragment header (part of the encrypted payload) */
    headroom += 1 + 1;

    /* Round up headroom to the next multiple of 4 to ensure alignment */
    headroom = (headroom + 3) & ~3;

    /* Add the headroom to the payloadsize as a received (IP) packet can have
     * all the extra headers in it */
    payload_size += headroom;

    /* the space after the payload, this needs some extra buffer space for
     * encryption so headroom is probably too much but we do not really care
     * the few extra bytes */
    size_t tailroom = headroom;

#ifdef USE_COMP
    msg(D_MTU_DEBUG,
        "MTU: adding %zu buffer tailroom for compression for %zu "
        "bytes of payload",
        COMP_EXTRA_BUFFER(payload_size), payload_size);
    tailroom += COMP_EXTRA_BUFFER(payload_size);
#endif

    if (frame->bulk_size > 0)
    {
        payload_size = BAT_SIZE(TUN_BAT_ONE, frame->tun_mtu, TUN_BAT_OFF);
    }

    frame->buf.payload_size = payload_size;
    frame->buf.headroom = headroom;
    frame->buf.tailroom = tailroom;
}

/*
 * Free a key schedule, including OpenSSL components.
 */
static void
key_schedule_free(struct key_schedule *ks, bool free_ssl_ctx)
{
    free_key_ctx_bi(&ks->static_key);
    if (tls_ctx_initialised(&ks->ssl_ctx) && free_ssl_ctx)
    {
        tls_ctx_free(&ks->ssl_ctx);
        free_key_ctx(&ks->auth_token_key);
    }
    CLEAR(*ks);
}

static void
init_crypto_pre(struct context *c, const unsigned int flags)
{
    if (c->options.engine)
    {
        crypto_init_lib_engine(c->options.engine);
    }

    if (flags & CF_LOAD_PERSISTED_PACKET_ID)
    {
        /* load a persisted packet-id for cross-session replay-protection */
        if (c->options.packet_id_file)
        {
            packet_id_persist_load(&c->c1.pid_persist, c->options.packet_id_file);
        }
    }

#ifdef ENABLE_PREDICTION_RESISTANCE
    if (c->options.use_prediction_resistance)
    {
        rand_ctx_enable_prediction_resistance();
    }
#endif
}

/*
 * Static Key Mode (using a pre-shared key)
 */
static void
do_init_crypto_static(struct context *c, const unsigned int flags)
{
    const struct options *options = &c->options;
    ASSERT(options->shared_secret_file);

    init_crypto_pre(c, flags);

    /* Initialize flags */
    if (c->options.mute_replay_warnings)
    {
        c->c2.crypto_options.flags |= CO_MUTE_REPLAY_WARNINGS;
    }

    /* Initialize packet ID tracking */
    packet_id_init(&c->c2.crypto_options.packet_id, options->replay_window, options->replay_time,
                   "STATIC", 0);
    c->c2.crypto_options.pid_persist = &c->c1.pid_persist;
    c->c2.crypto_options.flags |= CO_PACKET_ID_LONG_FORM;
    packet_id_persist_load_obj(&c->c1.pid_persist, &c->c2.crypto_options.packet_id);

    if (!key_ctx_bi_defined(&c->c1.ks.static_key))
    {
        /* Get cipher & hash algorithms */
        init_key_type(&c->c1.ks.key_type, options->ciphername, options->authname,
                      options->test_crypto, true);

        /* Read cipher and hmac keys from shared secret file */
        crypto_read_openvpn_key(&c->c1.ks.key_type, &c->c1.ks.static_key,
                                options->shared_secret_file, options->shared_secret_file_inline,
                                options->key_direction, "Static Key Encryption", "secret", NULL);
    }
    else
    {
        msg(M_INFO, "Re-using pre-shared static key");
    }

    /* Get key schedule */
    c->c2.crypto_options.key_ctx_bi = c->c1.ks.static_key;
}

/*
 * Initialize the tls-auth/crypt key context
 */
static void
do_init_tls_wrap_key(struct context *c)
{
    const struct options *options = &c->options;

    /* TLS handshake authentication (--tls-auth) */
    if (options->ce.tls_auth_file)
    {
        /* Initialize key_type for tls-auth with auth only */
        CLEAR(c->c1.ks.tls_auth_key_type);
        c->c1.ks.tls_auth_key_type.cipher = "none";
        c->c1.ks.tls_auth_key_type.digest = options->authname;
        if (!md_valid(options->authname))
        {
            msg(M_FATAL,
                "ERROR: tls-auth enabled, but no valid --auth "
                "algorithm specified ('%s')",
                options->authname);
        }

        crypto_read_openvpn_key(&c->c1.ks.tls_auth_key_type, &c->c1.ks.tls_wrap_key,
                                options->ce.tls_auth_file, options->ce.tls_auth_file_inline,
                                options->ce.key_direction, "Control Channel Authentication",
                                "tls-auth", &c->c1.ks.original_wrap_keydata);
    }

    /* TLS handshake encryption+authentication (--tls-crypt) */
    if (options->ce.tls_crypt_file)
    {
        tls_crypt_init_key(&c->c1.ks.tls_wrap_key, &c->c1.ks.original_wrap_keydata,
                           options->ce.tls_crypt_file, options->ce.tls_crypt_file_inline,
                           options->tls_server);
    }

    /* tls-crypt with client-specific keys (--tls-crypt-v2) */
    if (options->ce.tls_crypt_v2_file)
    {
        if (options->tls_server)
        {
            tls_crypt_v2_init_server_key(&c->c1.ks.tls_crypt_v2_server_key, true,
                                         options->ce.tls_crypt_v2_file,
                                         options->ce.tls_crypt_v2_file_inline);
        }
        else
        {
            tls_crypt_v2_init_client_key(&c->c1.ks.tls_wrap_key, &c->c1.ks.original_wrap_keydata,
                                         &c->c1.ks.tls_crypt_v2_wkc, options->ce.tls_crypt_v2_file,
                                         options->ce.tls_crypt_v2_file_inline);
        }
        /* We have to ensure that the loaded tls-crypt key is small enough
         * to fit into the initial hard reset v3 packet */
        int wkc_len = buf_len(&c->c1.ks.tls_crypt_v2_wkc);

        /* empty ACK/message id, tls-crypt, Opcode, UDP, ipv6 */
        int required_size = 5 + wkc_len + tls_crypt_buf_overhead() + 1 + 8 + 40;

        if (required_size > c->options.ce.tls_mtu)
        {
            msg(M_WARN,
                "ERROR: tls-crypt-v2 client key too large to work with "
                "requested --max-packet-size %d, requires at least "
                "--max-packet-size %d. Packets will ignore requested "
                "maximum packet size",
                c->options.ce.tls_mtu, required_size);
        }
    }
}

/*
 * Initialize the persistent component of OpenVPN's TLS mode,
 * which is preserved across SIGUSR1 resets.
 */
static void
do_init_crypto_tls_c1(struct context *c)
{
    const struct options *options = &c->options;

    if (!tls_ctx_initialised(&c->c1.ks.ssl_ctx))
    {
        /*
         * Initialize the OpenSSL library's global
         * SSL context.
         */
        init_ssl(options, &(c->c1.ks.ssl_ctx), c->c0 && c->c0->uid_gid_chroot_set);
        if (!tls_ctx_initialised(&c->c1.ks.ssl_ctx))
        {
            switch (auth_retry_get())
            {
                case AR_NONE:
                    msg(M_FATAL, "Error: private key password verification failed");
                    break;

                case AR_INTERACT:
                    ssl_purge_auth(false);
                    /* Intentional [[fallthrough]]; */

                case AR_NOINTERACT:
                    /* SOFT-SIGUSR1 -- Password failure error */
                    register_signal(c->sig, SIGUSR1, "private-key-password-failure");
                    break;

                default:
                    ASSERT(0);
            }
            return;
        }

        /*
         * BF-CBC is allowed to be used only when explicitly configured
         * as NCP-fallback or when NCP has been disabled or explicitly
         * allowed in the in ncp_ciphers list.
         * In all other cases do not attempt to initialize BF-CBC as it
         * may not even be supported by the underlying SSL library.
         *
         * Therefore, the key structure has to be initialized when:
         * - any non-BF-CBC cipher was selected; or
         * - BF-CBC is selected, NCP is enabled and fallback is enabled
         *   (BF-CBC will be the fallback).
         * - BF-CBC is in data-ciphers and we negotiate to use BF-CBC:
         *   If the negotiated cipher and options->ciphername are the
         *   same we do not reinit the cipher
         *
         * Note that BF-CBC will still be part of the OCC string to retain
         * backwards compatibility with older clients.
         */
        const char *ciphername = options->ciphername;
        if (streq(options->ciphername, "BF-CBC")
            && !tls_item_in_cipher_list("BF-CBC", options->ncp_ciphers)
            && !options->enable_ncp_fallback)
        {
            ciphername = "none";
        }

        /* Do not warn if the cipher is used only in OCC */
        bool warn = options->enable_ncp_fallback;
        init_key_type(&c->c1.ks.key_type, ciphername, options->authname, true, warn);

        /* initialize tls-auth/crypt/crypt-v2 key */
        do_init_tls_wrap_key(c);

        /* initialise auth-token crypto support */
        if (c->options.auth_token_generate)
        {
            auth_token_init_secret(&c->c1.ks.auth_token_key, c->options.auth_token_secret_file,
                                   c->options.auth_token_secret_file_inline);
        }

#if 0 /* was: #if ENABLE_INLINE_FILES --  Note that enabling this code will break restarts */
        if (options->priv_key_file_inline)
        {
            string_clear(c->options.priv_key_file_inline);
            c->options.priv_key_file_inline = NULL;
        }
#endif
    }
    else
    {
        msg(D_INIT_MEDIUM, "Re-using SSL/TLS context");

        /*
         * tls-auth/crypt key can be configured per connection block, therefore
         * we must reload it as it may have changed
         */
        do_init_tls_wrap_key(c);
    }
}

static void
do_init_crypto_tls(struct context *c, const unsigned int flags)
{
    const struct options *options = &c->options;
    struct tls_options to;
    bool packet_id_long_form;

    ASSERT(options->tls_server || options->tls_client);
    ASSERT(!options->test_crypto);

    init_crypto_pre(c, flags);

    /* Make sure we are either a TLS client or server but not both */
    ASSERT(options->tls_server == !options->tls_client);

    /* initialize persistent component */
    do_init_crypto_tls_c1(c);
    if (IS_SIG(c))
    {
        return;
    }

    /* In short form, unique datagram identifier is 32 bits, in long form 64 bits */
    packet_id_long_form = cipher_kt_mode_ofb_cfb(c->c1.ks.key_type.cipher);

    /* Set all command-line TLS-related options */
    CLEAR(to);

    if (options->mute_replay_warnings)
    {
        to.crypto_flags |= CO_MUTE_REPLAY_WARNINGS;
    }

    to.crypto_flags &= ~(CO_PACKET_ID_LONG_FORM);
    if (packet_id_long_form)
    {
        to.crypto_flags |= CO_PACKET_ID_LONG_FORM;
    }

    to.ssl_ctx = c->c1.ks.ssl_ctx;
    to.key_type = c->c1.ks.key_type;
    to.server = options->tls_server;
    to.replay_window = options->replay_window;
    to.replay_time = options->replay_time;
    to.config_ciphername = c->options.ciphername;
    to.config_ncp_ciphers = c->options.ncp_ciphers;
    to.transition_window = options->transition_window;
    to.handshake_window = options->handshake_window;
    to.packet_timeout = options->tls_timeout;
    to.renegotiate_bytes = options->renegotiate_bytes;
    to.renegotiate_packets = options->renegotiate_packets;
    if (options->renegotiate_seconds_min < 0)
    {
        /* Add 10% jitter to reneg-sec by default (server side only) */
        int auto_jitter = options->mode != MODE_SERVER
                              ? 0
                              : get_random() % max_int(options->renegotiate_seconds / 10, 1);
        to.renegotiate_seconds = options->renegotiate_seconds - auto_jitter;
    }
    else
    {
        /* Add user-specified jitter to reneg-sec */
        to.renegotiate_seconds =
            options->renegotiate_seconds
            - (get_random()
               % max_int(options->renegotiate_seconds - options->renegotiate_seconds_min, 1));
    }
    to.single_session = options->single_session;
    to.mode = options->mode;
    to.pull = options->pull;
    if (options->push_peer_info) /* all there is */
    {
        to.push_peer_info_detail = 3;
    }
    else if (options->pull) /* pull clients send some details */
    {
        to.push_peer_info_detail = 2;
    }
    else if (options->mode == MODE_SERVER) /* server: no peer info at all */
    {
        to.push_peer_info_detail = 0;
    }
    else /* default: minimal info to allow NCP in P2P mode */
    {
        to.push_peer_info_detail = 1;
    }

    /* Check if the DCO drivers support the epoch data format */
    if (dco_enabled(options))
    {
        to.data_epoch_supported = dco_supports_epoch_data(c);
    }
    else
    {
        to.data_epoch_supported = true;
    }

    /* should we not xmit any packets until we get an initial
     * response from client? */
    if (to.server && c->mode == CM_CHILD_TCP)
    {
        to.xmit_hold = true;
    }

    to.verify_command = options->tls_verify;
    to.verify_x509_type = (options->verify_x509_type & 0xff);
    to.verify_x509_name = options->verify_x509_name;
    to.crl_file = options->crl_file;
    to.crl_file_inline = options->crl_file_inline;
    to.ssl_flags = options->ssl_flags;
    to.ns_cert_type = options->ns_cert_type;
    memcpy(to.remote_cert_ku, options->remote_cert_ku, sizeof(to.remote_cert_ku));
    to.remote_cert_eku = options->remote_cert_eku;
    to.verify_hash = options->verify_hash;
    to.verify_hash_algo = options->verify_hash_algo;
    to.verify_hash_depth = options->verify_hash_depth;
    to.verify_hash_no_ca = options->verify_hash_no_ca;
#ifdef ENABLE_X509ALTUSERNAME
    memcpy(to.x509_username_field, options->x509_username_field, sizeof(to.x509_username_field));
#else
    to.x509_username_field[0] = X509_USERNAME_FIELD_DEFAULT;
#endif
    to.es = c->c2.es;
    to.net_ctx = &c->net_ctx;

#ifdef ENABLE_DEBUG
    to.gremlin = c->options.gremlin;
#endif

    to.plugins = c->plugins;

#ifdef ENABLE_MANAGEMENT
    to.mda_context = &c->c2.mda_context;
#endif

    to.auth_user_pass_verify_script = options->auth_user_pass_verify_script;
    to.auth_user_pass_verify_script_via_file = options->auth_user_pass_verify_script_via_file;
    to.client_crresponse_script = options->client_crresponse_script;
    to.tmp_dir = options->tmp_dir;
    to.export_peer_cert_dir = options->tls_export_peer_cert_dir;
    if (options->ccd_exclusive)
    {
        to.client_config_dir_exclusive = options->client_config_dir;
    }
    to.auth_user_pass_file = options->auth_user_pass_file;
    to.auth_user_pass_file_inline = options->auth_user_pass_file_inline;
    to.auth_token_generate = options->auth_token_generate;
    to.auth_token_lifetime = options->auth_token_lifetime;
    to.auth_token_renewal = options->auth_token_renewal;
    to.auth_token_call_auth = options->auth_token_call_auth;
    to.auth_token_key = c->c1.ks.auth_token_key;

    to.x509_track = options->x509_track;

#ifdef ENABLE_MANAGEMENT
    to.sci = &options->sc_info;
#endif

#ifdef USE_COMP
    to.comp_options = options->comp;
#endif

    if (options->keying_material_exporter_label)
    {
        to.ekm_size = options->keying_material_exporter_length;
        if (to.ekm_size < 16 || to.ekm_size > 4095)
        {
            to.ekm_size = 0;
        }

        to.ekm_label = options->keying_material_exporter_label;
        to.ekm_label_size = strlen(to.ekm_label);
    }
    else
    {
        to.ekm_size = 0;
    }

    /* TLS handshake authentication (--tls-auth) */
    if (options->ce.tls_auth_file)
    {
        to.tls_wrap.mode = TLS_WRAP_AUTH;
    }

    /* TLS handshake encryption (--tls-crypt) */
    if (options->ce.tls_crypt_file || (options->ce.tls_crypt_v2_file && options->tls_client))
    {
        to.tls_wrap.mode = TLS_WRAP_CRYPT;
    }

    if (to.tls_wrap.mode == TLS_WRAP_AUTH || to.tls_wrap.mode == TLS_WRAP_CRYPT)
    {
        to.tls_wrap.opt.key_ctx_bi = c->c1.ks.tls_wrap_key;
        to.tls_wrap.opt.pid_persist = &c->c1.pid_persist;
        to.tls_wrap.opt.flags |= CO_PACKET_ID_LONG_FORM;
        to.tls_wrap.original_wrap_keydata = c->c1.ks.original_wrap_keydata;
    }

    if (options->ce.tls_crypt_v2_file)
    {
        to.tls_crypt_v2 = true;
        to.tls_wrap.tls_crypt_v2_wkc = &c->c1.ks.tls_crypt_v2_wkc;

        if (options->tls_server)
        {
            to.tls_wrap.tls_crypt_v2_server_key = c->c1.ks.tls_crypt_v2_server_key;
            to.tls_crypt_v2_verify_script = c->options.tls_crypt_v2_verify_script;
            if (options->ce.tls_crypt_v2_force_cookie)
            {
                to.tls_wrap.opt.flags |= CO_FORCE_TLSCRYPTV2_COOKIE;
            }
        }
    }

    /* let the TLS engine know if keys have to be installed in DCO or not */
    to.dco_enabled = dco_enabled(options);

    /*
     * Initialize OpenVPN's master TLS-mode object.
     */
    if (flags & CF_INIT_TLS_MULTI)
    {
        c->c2.tls_multi = tls_multi_init(&to);
        /* inherit the dco context from the tuntap object */
        if (c->c1.tuntap)
        {
            c->c2.tls_multi->dco = &c->c1.tuntap->dco;
        }
    }

    if (flags & CF_INIT_TLS_AUTH_STANDALONE)
    {
        c->c2.tls_auth_standalone = tls_auth_standalone_init(&to, &c->c2.gc);
        c->c2.session_id_hmac = session_id_hmac_init();
    }
}

static void
do_init_frame_tls(struct context *c)
{
    if (c->c2.tls_multi)
    {
        tls_multi_init_finalize(c->c2.tls_multi, c->options.ce.tls_mtu);
        if (c->c2.frame.bulk_size > 0)
        {
            c->c2.tls_multi->opt.frame.buf.payload_size = c->c2.frame.tun_mtu;
        }
        ASSERT(c->c2.tls_multi->opt.frame.buf.payload_size <= c->c2.frame.buf.payload_size);
        frame_print(&c->c2.tls_multi->opt.frame, D_MTU_INFO, "Control Channel MTU parms");

        /* Keep the max mtu also in the frame of tls multi so it can access
         * it in push_peer_info */
        c->c2.tls_multi->opt.frame.tun_max_mtu = c->c2.frame.tun_max_mtu;
    }
    if (c->c2.tls_auth_standalone)
    {
        tls_init_control_channel_frame_parameters(&c->c2.tls_auth_standalone->frame,
                                                  c->options.ce.tls_mtu);
        frame_print(&c->c2.tls_auth_standalone->frame, D_MTU_INFO, "TLS-Auth MTU parms");
        c->c2.tls_auth_standalone->tls_wrap.work = alloc_buf_gc(BUF_SIZE(&c->c2.frame), &c->c2.gc);
        c->c2.tls_auth_standalone->workbuf = alloc_buf_gc(BUF_SIZE(&c->c2.frame), &c->c2.gc);
    }
}

#if defined(__GNUC__) || defined(__clang__)
#pragma GCC diagnostic pop
#endif

/*
 * No encryption or authentication.
 */
static void
do_init_crypto_none(struct context *c)
{
    ASSERT(!c->options.test_crypto);

    /* Initialise key_type with auth/cipher "none", so the key_type struct is
     * valid */
    init_key_type(&c->c1.ks.key_type, "none", "none", c->options.test_crypto, true);

    msg(M_WARN, "******* WARNING *******: All encryption and authentication features "
                "disabled -- All data will be tunnelled as clear text and will not be "
                "protected against man-in-the-middle changes. "
                "PLEASE DO RECONSIDER THIS CONFIGURATION!");
}

static void
do_init_crypto(struct context *c, const unsigned int flags)
{
    if (c->options.shared_secret_file)
    {
        do_init_crypto_static(c, flags);
    }
    else if (c->options.tls_server || c->options.tls_client)
    {
        do_init_crypto_tls(c, flags);
    }
    else /* no encryption or authentication. */
    {
        do_init_crypto_none(c);
    }
}

static void
do_init_frame(struct context *c)
{
    /*
     * Adjust frame size based on the --tun-mtu-extra parameter.
     */
    if (c->options.ce.tun_mtu_extra_defined)
    {
        c->c2.frame.extra_tun += c->options.ce.tun_mtu_extra;
    }

    /*
     * Adjust bulk size based on the --bulk-mode parameter.
     */
    if (c->options.ce.bulk_mode)
    {
        c->c2.frame.bulk_size = c->options.ce.tun_mtu;
    }

    /*
     * Fill in the blanks in the frame parameters structure,
     * make sure values are rational, etc.
     */
    frame_finalize_options(c, NULL);


#if defined(ENABLE_FRAGMENT)
    /*
     * MTU advisories
     */
    if (c->options.ce.fragment && c->options.mtu_test)
    {
        msg(M_WARN,
            "WARNING: using --fragment and --mtu-test together may produce an inaccurate MTU test result");
    }
#endif

#ifdef ENABLE_FRAGMENT
    if (c->options.ce.fragment > 0 && c->options.ce.mssfix > c->options.ce.fragment)
    {
        msg(M_WARN,
            "WARNING: if you use --mssfix and --fragment, you should "
            "set --fragment (%d) larger or equal than --mssfix (%d)",
            c->options.ce.fragment, c->options.ce.mssfix);
    }
    if (c->options.ce.fragment > 0 && c->options.ce.mssfix > 0
        && c->options.ce.fragment_encap != c->options.ce.mssfix_encap)
    {
        msg(M_WARN, "WARNING: if you use --mssfix and --fragment, you should "
                    "use the \"mtu\" flag for both or none of of them.");
    }
#endif
}

static void
do_option_warnings(struct context *c)
{
    const struct options *o = &c->options;

    if (o->ping_send_timeout && !o->ping_rec_timeout)
    {
        msg(M_WARN, "WARNING: --ping should normally be used with --ping-restart or --ping-exit");
    }

    if (o->username || o->groupname || o->chroot_dir
#ifdef ENABLE_SELINUX
        || o->selinux_context
#endif
    )
    {
        if (!o->persist_tun)
        {
            msg(M_WARN,
                "WARNING: you are using user/group/chroot/setcon without persist-tun -- this may cause restarts to fail");
        }
    }

    if (o->chroot_dir && !(o->username && o->groupname))
    {
        msg(M_WARN,
            "WARNING: you are using chroot without specifying user and group -- this may cause the chroot jail to be insecure");
    }

    if (o->pull && o->ifconfig_local && c->first_time)
    {
        msg(M_WARN,
            "WARNING: using --pull/--client and --ifconfig together is probably not what you want");
    }

    if (o->server_bridge_defined || o->server_bridge_proxy_dhcp)
    {
        msg(M_WARN,
            "NOTE: when bridging your LAN adapter with the TAP adapter, note that the new bridge adapter will often take on its own IP address that is different from what the LAN adapter was previously set to");
    }

    if (o->mode == MODE_SERVER)
    {
        if (o->duplicate_cn && o->client_config_dir)
        {
            msg(M_WARN,
                "WARNING: using --duplicate-cn and --client-config-dir together is probably not what you want");
        }
        if (o->duplicate_cn && o->ifconfig_pool_persist_filename)
        {
            msg(M_WARN, "WARNING: --ifconfig-pool-persist will not work with --duplicate-cn");
        }
        if (!o->keepalive_ping || !o->keepalive_timeout)
        {
            msg(M_WARN, "WARNING: --keepalive option is missing from server config");
        }
    }

    if (o->tls_server)
    {
        warn_on_use_of_common_subnets(&c->net_ctx);
    }
    if (o->tls_client && !o->tls_verify && o->verify_x509_type == VERIFY_X509_NONE
        && !(o->ns_cert_type & NS_CERT_CHECK_SERVER) && !o->remote_cert_eku
        && !(o->verify_hash_depth == 0 && o->verify_hash))
    {
        msg(M_WARN,
            "WARNING: No server certificate verification method has been enabled.  See http://openvpn.net/howto.html#mitm for more info.");
    }
    if (o->ns_cert_type)
    {
        msg(M_WARN, "WARNING: --ns-cert-type is DEPRECATED.  Use --remote-cert-tls instead.");
    }

    /* If a script is used, print appropriate warnings */
    if (o->user_script_used)
    {
        if (script_security() >= SSEC_SCRIPTS)
        {
            msg(M_WARN,
                "NOTE: the current --script-security setting may allow this configuration to call user-defined scripts");
        }
        else if (script_security() >= SSEC_PW_ENV)
        {
            msg(M_WARN,
                "WARNING: the current --script-security setting may allow passwords to be passed to scripts via environmental variables");
        }
        else
        {
            msg(M_WARN,
                "NOTE: starting with " PACKAGE_NAME
                " 2.1, '--script-security 2' or higher is required to call user-defined scripts or executables");
        }
    }
}

struct context_buffers *
init_context_buffers(const struct frame *frame)
{
    struct context_buffers *b;

    ALLOC_OBJ_CLEAR(b, struct context_buffers);

    size_t buf_size = BUF_SIZE(frame);

    if (frame->bulk_size > 0)
    {
        size_t off_size = (frame->buf.headroom + TUN_BAT_OFF + frame->buf.tailroom);
        buf_size = BAT_SIZE(TUN_BAT_MAX, frame->tun_mtu, off_size);
    }

    dmsg(M_INFO, "MEM NEW [%ld] [%d+%d+%d]", buf_size, frame->buf.headroom, frame->buf.payload_size, frame->buf.tailroom);

    b->read_link_buf = alloc_buf(buf_size);
    b->read_tun_buf = alloc_buf(buf_size);

    if (frame->bulk_size > 0)
    {
        size_t off_size = (frame->buf.headroom + TUN_BAT_OFF + frame->buf.tailroom);
        size_t one_size = BAT_SIZE(TUN_BAT_ONE, frame->tun_mtu, off_size);

        for (int x = 0; x < TUN_BAT_MAX; ++x)
        {
            b->read_tun_bufs[x] = alloc_buf(one_size);
            b->read_tun_bufs[x].offset = TUN_BAT_OFF;
            b->read_tun_bufs[x].len = 0;
        }

        b->read_tun_max = alloc_buf(buf_size);
        b->read_tun_max.offset = TUN_BAT_OFF;
        b->read_tun_max.len = 0;

        b->send_tun_max = alloc_buf(buf_size);
        b->send_tun_max.offset = TUN_BAT_OFF;
        b->send_tun_max.len = 0;

        b->to_tun_max = alloc_buf(buf_size);
        b->to_tun_max.offset = TUN_BAT_OFF;
        b->to_tun_max.len = 0;
    }

    b->bulk_indx = -1;
    b->bulk_leng = -1;

    b->aux_buf = alloc_buf(buf_size);

    b->encrypt_buf = alloc_buf(buf_size);
    b->decrypt_buf = alloc_buf(buf_size);

#ifdef USE_COMP
    b->compress_buf = alloc_buf(buf_size);
    b->decompress_buf = alloc_buf(buf_size);
#endif

    return b;
}

void
free_context_buffers(struct context_buffers *b)
{
    if (b)
    {
        free_buf(&b->read_link_buf);
        free_buf(&b->read_tun_buf);
        free_buf(&b->aux_buf);

        if (b->to_tun_max.data)
        {
            free_buf(&b->to_tun_max);
            free_buf(&b->send_tun_max);
            free_buf(&b->read_tun_max);
            for (int x = 0; x < TUN_BAT_MAX; ++x)
            {
                free_buf(&b->read_tun_bufs[x]);
            }
        }

#ifdef USE_COMP
        free_buf(&b->compress_buf);
        free_buf(&b->decompress_buf);
#endif

        free_buf(&b->encrypt_buf);
        free_buf(&b->decrypt_buf);

        free(b);
    }
}

/*
 * Now that we know all frame parameters, initialize
 * our buffers.
 */
static void
do_init_buffers(struct context *c)
{
    c->c2.buffers = init_context_buffers(&c->c2.frame);
    c->c2.buffers_owned = true;
}

#ifdef ENABLE_FRAGMENT
/*
 * Fragmenting code has buffers to initialize
 * once frame parameters are known.
 */
static void
do_init_fragment(struct context *c)
{
    ASSERT(c->options.ce.fragment);

    /*
     * Set frame parameter for fragment code.  This is necessary because
     * the fragmentation code deals with payloads which have already been
     * passed through the compression code.
     */
    c->c2.frame_fragment = c->c2.frame;

    frame_calculate_dynamic(&c->c2.frame_fragment, &c->c1.ks.key_type, &c->options,
                            get_link_socket_info(c));
    fragment_frame_init(c->c2.fragment, &c->c2.frame_fragment);
}
#endif

/*
 * Allocate our socket object.
 */
static void
do_link_socket_new(struct context *c)
{
    ASSERT(!c->c2.link_sockets);

    ALLOC_ARRAY_GC(c->c2.link_sockets, struct link_socket *, c->c1.link_sockets_num, &c->c2.gc);

    for (int i = 0; i < c->c1.link_sockets_num; i++)
    {
        c->c2.link_sockets[i] = link_socket_new();
    }
    c->c2.link_socket_owned = true;
}

/*
 * bind TCP/UDP sockets
 */
static void
do_init_socket_phase1(struct context *c)
{
    for (int i = 0; i < c->c1.link_sockets_num; i++)
    {
        int mode = LS_MODE_DEFAULT;

        /* mode allows CM_CHILD_TCP
         * instances to inherit acceptable fds
         * from a top-level parent */
        if (c->options.mode == MODE_SERVER)
        {
            /* initializing listening socket */
            if (c->mode == CM_TOP)
            {
                mode = LS_MODE_TCP_LISTEN;
            }
            /* initializing socket to client */
            else if (c->mode == CM_CHILD_TCP)
            {
                mode = LS_MODE_TCP_ACCEPT_FROM;
            }
        }

        /* init each socket with its specific args */
        link_socket_init_phase1(c, i, mode);
    }
}

/*
 * finalize TCP/UDP sockets
 */
static void
do_init_socket_phase2(struct context *c)
{
    for (int i = 0; i < c->c1.link_sockets_num; i++)
    {
        link_socket_init_phase2(c, c->c2.link_sockets[i]);
    }
}

/*
 * Print MTU INFO
 */
static void
do_print_data_channel_mtu_parms(struct context *c)
{
    frame_print(&c->c2.frame, D_MTU_INFO, "Data Channel MTU parms");
#ifdef ENABLE_FRAGMENT
    if (c->c2.fragment)
    {
        frame_print(&c->c2.frame_fragment, D_MTU_INFO, "Fragmentation MTU parms");
    }
#endif
}

/*
 * Get local and remote options compatibility strings.
 */
static void
do_compute_occ_strings(struct context *c)
{
    struct gc_arena gc = gc_new();

    c->c2.options_string_local =
        options_string(&c->options, &c->c2.frame, c->c1.tuntap, &c->net_ctx, false, &gc);
    c->c2.options_string_remote =
        options_string(&c->options, &c->c2.frame, c->c1.tuntap, &c->net_ctx, true, &gc);

    msg(D_SHOW_OCC, "Local Options String (VER=%s): '%s'",
        options_string_version(c->c2.options_string_local, &gc), c->c2.options_string_local);
    msg(D_SHOW_OCC, "Expected Remote Options String (VER=%s): '%s'",
        options_string_version(c->c2.options_string_remote, &gc), c->c2.options_string_remote);

    if (c->c2.tls_multi)
    {
        tls_multi_init_set_options(c->c2.tls_multi, c->c2.options_string_local,
                                   c->c2.options_string_remote);
    }

    gc_free(&gc);
}

/*
 * These things can only be executed once per program instantiation.
 * Set up for possible UID/GID downgrade, but don't do it yet.
 * Daemonize if requested.
 */
static void
do_init_first_time(struct context *c)
{
    if (c->first_time && !c->c0)
    {
        struct context_0 *c0;

        ALLOC_OBJ_CLEAR_GC(c->c0, struct context_0, &c->gc);
        c0 = c->c0;

        /* get user and/or group that we want to setuid/setgid to,
         * sets also platform_x_state */
        bool group_defined = platform_group_get(c->options.groupname, &c0->platform_state_group);
        bool user_defined = platform_user_get(c->options.username, &c0->platform_state_user);

        c0->uid_gid_specified = user_defined || group_defined;

        /* fork the dns script runner to preserve root? */
        c->persist.duri.required = user_defined;

        /* perform postponed chdir if --daemon */
        if (c->did_we_daemonize && c->options.cd_dir == NULL)
        {
            platform_chdir("/");
        }

        /* should we change scheduling priority? */
        platform_nice(c->options.nice);
    }
}

/*
 * free buffers
 */
static void
do_close_free_buf(struct context *c)
{
    if (c->c2.buffers_owned)
    {
        free_context_buffers(c->c2.buffers);
        c->c2.buffers = NULL;
        c->c2.buffers_owned = false;
    }
}

/*
 * close TLS
 */
static void
do_close_tls(struct context *c)
{
    if (c->c2.tls_multi)
    {
        tls_multi_free(c->c2.tls_multi, true);
        c->c2.tls_multi = NULL;
    }

    /* free options compatibility strings */
    free(c->c2.options_string_local);
    free(c->c2.options_string_remote);

    c->c2.options_string_local = c->c2.options_string_remote = NULL;

    if (c->c2.pulled_options_state)
    {
        md_ctx_cleanup(c->c2.pulled_options_state);
        md_ctx_free(c->c2.pulled_options_state);
    }

    tls_auth_standalone_free(c->c2.tls_auth_standalone);
}

/*
 * Free key schedules
 */
static void
do_close_free_key_schedule(struct context *c, bool free_ssl_ctx)
{
    /*
     * always free the tls_auth/crypt key. The key will
     * be reloaded from memory (pre-cached)
     */
    free_key_ctx(&c->c1.ks.tls_crypt_v2_server_key);
    free_key_ctx_bi(&c->c1.ks.tls_wrap_key);
    CLEAR(c->c1.ks.tls_wrap_key);
    buf_clear(&c->c1.ks.tls_crypt_v2_wkc);
    free_buf(&c->c1.ks.tls_crypt_v2_wkc);

    if (!(c->sig->signal_received == SIGUSR1))
    {
        key_schedule_free(&c->c1.ks, free_ssl_ctx);
    }
}

/*
 * Close TCP/UDP connection
 */
static void
do_close_link_socket(struct context *c)
{
    if (c->c2.link_sockets && c->c2.link_socket_owned)
    {
        for (int i = 0; i < c->c1.link_sockets_num; i++)
        {
            /* in dco-win case, link socket is a tun handle which is
             * closed in do_close_tun(). Set it to UNDEFINED so
             * we won't use WinSock API to close it. */
            if (tuntap_is_dco_win(c->c1.tuntap))
            {
                c->c2.link_sockets[i]->sd = SOCKET_UNDEFINED;
            }

            link_socket_close(c->c2.link_sockets[i]);
        }
        c->c2.link_sockets = NULL;
    }


    /* Preserve the resolved list of remote if the user request to or if we want
     * reconnect to the same host again or there are still addresses that need
     * to be tried */
    if (!(c->sig->signal_received == SIGUSR1
          && ((c->options.persist_remote_ip)
              || (c->sig->source != SIG_SOURCE_HARD
                  && ((c->c1.link_socket_addrs[0].current_remote
                       && c->c1.link_socket_addrs[0].current_remote->ai_next)
                      || c->options.no_advance)))))
    {
        clear_remote_addrlist(&c->c1.link_socket_addrs[0], !c->options.resolve_in_advance);
    }

    /* Clear the remote actual address when persist_remote_ip is not in use */
    if (!(c->sig->signal_received == SIGUSR1 && c->options.persist_remote_ip))
    {
        for (int i = 0; i < c->c1.link_sockets_num; i++)
        {
            CLEAR(c->c1.link_socket_addrs[i].actual);
        }
    }

    if (!(c->sig->signal_received == SIGUSR1 && c->options.persist_local_ip))
    {
        for (int i = 0; i < c->c1.link_sockets_num; i++)
        {
            if (c->c1.link_socket_addrs[i].bind_local && !c->options.resolve_in_advance)
            {
                freeaddrinfo(c->c1.link_socket_addrs[i].bind_local);
            }

            c->c1.link_socket_addrs[i].bind_local = NULL;
        }
    }
}

/*
 * Close packet-id persistence file
 */
static void
do_close_packet_id(struct context *c)
{
    packet_id_free(&c->c2.crypto_options.packet_id);
    packet_id_persist_save(&c->c1.pid_persist);
    if (!(c->sig->signal_received == SIGUSR1))
    {
        packet_id_persist_close(&c->c1.pid_persist);
    }
}

#ifdef ENABLE_FRAGMENT
/*
 * Close fragmentation handler.
 */
static void
do_close_fragment(struct context *c)
{
    if (c->c2.fragment)
    {
        fragment_free(c->c2.fragment);
        c->c2.fragment = NULL;
    }
}
#endif

/*
 * Open and close our event objects.
 */

static void
do_event_set_init(struct context *c, bool need_us_timeout)
{
    unsigned int flags = 0;

    c->c2.event_set_max = BASE_N_EVENTS;

    flags |= EVENT_METHOD_FAST;

    if (need_us_timeout)
    {
        flags |= EVENT_METHOD_US_TIMEOUT;
    }

    c->c2.event_set = event_set_init(&c->c2.event_set_max, flags);
    c->c2.event_set_owned = true;
}

static void
do_close_event_set(struct context *c)
{
    if (c->c2.event_set && c->c2.event_set_owned)
    {
        event_free(c->c2.event_set);
        c->c2.event_set = NULL;
        c->c2.event_set_owned = false;
    }
}

/*
 * Open and close --status file
 */

static void
do_open_status_output(struct context *c)
{
    if (!c->c1.status_output)
    {
        c->c1.status_output =
            status_open(c->options.status_file, c->options.status_file_update_freq, -1, NULL,
                        STATUS_OUTPUT_WRITE);
        c->c1.status_output_owned = true;
    }
}

static void
do_close_status_output(struct context *c)
{
    if (!(c->sig->signal_received == SIGUSR1))
    {
        if (c->c1.status_output_owned && c->c1.status_output)
        {
            status_close(c->c1.status_output);
            c->c1.status_output = NULL;
            c->c1.status_output_owned = false;
        }
    }
}

/*
 * Handle ifconfig-pool persistence object.
 */
static void
do_open_ifconfig_pool_persist(struct context *c)
{
    if (!c->c1.ifconfig_pool_persist && c->options.ifconfig_pool_persist_filename)
    {
        c->c1.ifconfig_pool_persist =
            ifconfig_pool_persist_init(c->options.ifconfig_pool_persist_filename,
                                       c->options.ifconfig_pool_persist_refresh_freq);
        c->c1.ifconfig_pool_persist_owned = true;
    }
}

static void
do_close_ifconfig_pool_persist(struct context *c)
{
    if (!(c->sig->signal_received == SIGUSR1))
    {
        if (c->c1.ifconfig_pool_persist && c->c1.ifconfig_pool_persist_owned)
        {
            ifconfig_pool_persist_close(c->c1.ifconfig_pool_persist);
            c->c1.ifconfig_pool_persist = NULL;
            c->c1.ifconfig_pool_persist_owned = false;
        }
    }
}

/*
 * Inherit environmental variables
 */

static void
do_inherit_env(struct context *c, const struct env_set *src)
{
    c->c2.es = env_set_create(NULL);
    c->c2.es_owned = true;
    env_set_inherit(c->c2.es, src);
}

static void
do_env_set_destroy(struct context *c)
{
    if (c->c2.es && c->c2.es_owned)
    {
        env_set_destroy(c->c2.es);
        c->c2.es = NULL;
        c->c2.es_owned = false;
    }
}

/*
 * Fast I/O setup.  Fast I/O is an optimization which only works
 * if all of the following are true:
 *
 * (1) The platform is not Windows
 * (2) --proto udp is enabled
 * (3) --shaper is disabled
 */
static void
do_setup_fast_io(struct context *c)
{
    if (c->options.fast_io)
    {
#ifdef _WIN32
        msg(M_INFO, "NOTE: --fast-io is disabled since we are running on Windows");
#else
        if (c->options.shaper)
        {
            msg(M_INFO, "NOTE: --fast-io is disabled since we are using --shaper");
        }
        else
        {
            c->c2.fast_io = true;
        }
#endif
    }
}

static void
do_signal_on_tls_errors(struct context *c)
{
    if (c->options.tls_exit)
    {
        c->c2.tls_exit_signal = SIGTERM;
    }
    else
    {
        c->c2.tls_exit_signal = SIGUSR1;
    }
}

#ifdef ENABLE_PLUGIN

void
init_plugins(struct context *c)
{
    if (c->options.plugin_list && !c->plugins)
    {
        c->plugins = plugin_list_init(c->options.plugin_list);
        c->plugins_owned = true;
    }
}

void
open_plugins(struct context *c, const bool import_options, int init_point)
{
    if (c->plugins && c->plugins_owned)
    {
        if (import_options)
        {
            struct plugin_return pr, config;
            plugin_return_init(&pr);
            plugin_list_open(c->plugins, c->options.plugin_list, &pr, c->c2.es, init_point);
            plugin_return_get_column(&pr, &config, "config");
            if (plugin_return_defined(&config))
            {
                int i;
                for (i = 0; i < config.n; ++i)
                {
                    unsigned int option_types_found = 0;
                    if (config.list[i] && config.list[i]->value)
                    {
                        options_string_import(
                            &c->options, config.list[i]->value, D_IMPORT_ERRORS | M_OPTERR,
                            OPT_P_DEFAULT & ~OPT_P_PLUGIN, &option_types_found, c->es);
                    }
                }
            }
            plugin_return_free(&pr);
        }
        else
        {
            plugin_list_open(c->plugins, c->options.plugin_list, NULL, c->c2.es, init_point);
        }
    }
}

static void
do_close_plugins(struct context *c)
{
    if (c->plugins && c->plugins_owned && !(c->sig->signal_received == SIGUSR1))
    {
        plugin_list_close(c->plugins);
        c->plugins = NULL;
        c->plugins_owned = false;
    }
}

static void
do_inherit_plugins(struct context *c, const struct context *src)
{
    if (!c->plugins && src->plugins)
    {
        c->plugins = plugin_list_inherit(src->plugins);
        c->plugins_owned = true;
    }
}

#endif /* ifdef ENABLE_PLUGIN */

#ifdef ENABLE_MANAGEMENT

static void
management_callback_status_p2p(void *arg, const int version, struct status_output *so)
{
    struct context *c = (struct context *)arg;
    print_status(c, so);
}

void
management_show_net_callback(void *arg, const msglvl_t msglevel)
{
#ifdef _WIN32
    show_routes(msglevel);
    show_adapters(msglevel);
    msg(msglevel, "END");
#else
    msg(msglevel, "ERROR: Sorry, this command is currently only implemented on Windows");
#endif
}

#ifdef TARGET_ANDROID
int
management_callback_network_change(void *arg, bool samenetwork)
{
    /* Check if the client should translate the network change to a SIGUSR1 to
     * reestablish the connection or just reprotect the socket
     *
     * At the moment just assume that, for all settings that use pull (not
     * --static) and are not using peer-id reestablishing the connection is
     * required (unless the network is the same)
     *
     * The function returns -1 on invalid fd and -2 if the socket cannot be
     * reused. On the -2 return value the man_network_change function triggers
     * a SIGUSR1 to force a reconnect.
     */

    int socketfd = -1;
    struct context *c = (struct context *)arg;
    if (!c->c2.link_sockets || !c->c2.link_sockets[0])
    {
        return -1;
    }
    if (c->c2.link_sockets[0]->sd == SOCKET_UNDEFINED)
    {
        return -1;
    }

    /* On some newer Android handsets, changing to a different network
     * often does not trigger a TCP reset but continue using the old
     * connection (e.g. using mobile connection when WiFi becomes available */
    struct link_socket_info *lsi = get_link_socket_info(c);
    if (lsi && proto_is_tcp(lsi->proto) && !samenetwork)
    {
        return -2;
    }

    socketfd = c->c2.link_sockets[0]->sd;
    if (!c->options.pull || c->c2.tls_multi->use_peer_id || samenetwork)
    {
        return socketfd;
    }
    else
    {
        return -2;
    }
}
#endif /* ifdef TARGET_ANDROID */

#endif /* ifdef ENABLE_MANAGEMENT */

void
init_management_callback_p2p(struct context *c)
{
#ifdef ENABLE_MANAGEMENT
    if (management)
    {
        struct management_callback cb;
        CLEAR(cb);
        cb.arg = c;
        cb.status = management_callback_status_p2p;
        cb.show_net = management_show_net_callback;
        cb.proxy_cmd = management_callback_proxy_cmd;
        cb.remote_cmd = management_callback_remote_cmd;
        cb.send_cc_message = management_callback_send_cc_message;
#ifdef TARGET_ANDROID
        cb.network_change = management_callback_network_change;
#endif
        cb.remote_entry_count = management_callback_remote_entry_count;
        cb.remote_entry_get = management_callback_remote_entry_get;
        management_set_callback(management, &cb);
    }
#endif
}

#ifdef ENABLE_MANAGEMENT

void
init_management(void)
{
    if (!management)
    {
        management = management_init();
    }
}

bool
open_management(struct context *c)
{
    /* initialize management layer */
    if (management)
    {
        if (c->options.management_addr)
        {
            unsigned int flags = c->options.management_flags;
            if (c->options.mode == MODE_SERVER)
            {
                flags |= MF_SERVER;
            }
            if (management_open(
                    management, c->options.management_addr, c->options.management_port,
                    c->options.management_user_pass, c->options.management_client_user,
                    c->options.management_client_group, c->options.management_log_history_cache,
                    c->options.management_echo_buffer_size, c->options.management_state_buffer_size,
                    c->options.remap_sigusr1, flags))
            {
                management_set_state(management, OPENVPN_STATE_CONNECTING, NULL, NULL, NULL, NULL,
                                     NULL);
            }

            /* initial management hold, called early, before first context initialization */
            do_hold(0);
            if (IS_SIG(c))
            {
                msg(M_WARN, "Signal received from management interface, exiting");
                return false;
            }
        }
        else
        {
            close_management();
        }
    }
    return true;
}

void
close_management(void)
{
    if (management)
    {
        management_close(management);
        management = NULL;
    }
}

#endif /* ifdef ENABLE_MANAGEMENT */


void
uninit_management_callback(void)
{
#ifdef ENABLE_MANAGEMENT
    if (management)
    {
        management_clear_callback(management);
    }
#endif
}

void
persist_client_stats(struct context *c)
{
#ifdef ENABLE_MANAGEMENT
    if (management)
    {
        man_persist_client_stats(management, c);
    }
#endif
}

/*
 * Initialize a tunnel instance, handle pre and post-init
 * signal settings.
 */
void
init_instance_handle_signals(struct context *c, const struct env_set *env, const unsigned int flags)
{
    pre_init_signal_catch();
    init_instance(c, env, flags);
    post_init_signal_catch();

    /*
     * This is done so that signals thrown during
     * initialization can bring us back to
     * a management hold.
     */
    if (IS_SIG(c))
    {
        remap_signal(c);
        uninit_management_callback();
    }
}

/*
 * Initialize a tunnel instance.
 */
void
init_instance(struct context *c, const struct env_set *env, const unsigned int flags)
{
    const struct options *options = &c->options;
    const bool child = (c->mode == CM_CHILD_TCP || c->mode == CM_CHILD_UDP);

    /* init garbage collection level */
    gc_init(&c->c2.gc);

    /* inherit environmental variables */
    if (env)
    {
        do_inherit_env(c, env);
    }

    if (c->mode == CM_P2P)
    {
        init_management_callback_p2p(c);
    }

    /* possible sleep or management hold if restart */
    if (c->mode == CM_P2P || c->mode == CM_TOP)
    {
        do_startup_pause(c);
        if (IS_SIG(c))
        {
            goto sig;
        }
    }

    if (c->options.resolve_in_advance)
    {
        do_preresolve(c);
        if (IS_SIG(c))
        {
            goto sig;
        }
    }

    /* Resets all values to the initial values from the config where needed */
    pre_connect_restore(&c->options, &c->c2.gc);

    /* map in current connection entry */
    next_connection_entry(c);

    /* should we disable paging? */
    if (c->first_time && options->mlock)
    {
        platform_mlockall(true);
    }

    /* get passwords if undefined */
    if (auth_retry_get() == AR_INTERACT)
    {
        init_query_passwords(c);
    }

    /* initialize context level 2 --verb/--mute parms */
    init_verb_mute(c, IVM_LEVEL_2);

    /* set error message delay for non-server modes */
    if (c->mode == CM_P2P)
    {
        set_check_status_error_delay(P2P_ERROR_DELAY_MS);
    }

    /* warn about inconsistent options */
    if (c->mode == CM_P2P || c->mode == CM_TOP)
    {
        do_option_warnings(c);
    }

#ifdef ENABLE_PLUGIN
    /* initialize plugins */
    if (c->mode == CM_P2P || c->mode == CM_TOP)
    {
        open_plugins(c, false, OPENVPN_PLUGIN_INIT_PRE_DAEMON);
    }
#endif

    /* should we enable fast I/O? */
    if (c->mode == CM_P2P || c->mode == CM_TOP)
    {
        do_setup_fast_io(c);
    }

    /* should we throw a signal on TLS errors? */
    do_signal_on_tls_errors(c);

    /* open --status file */
    if (c->mode == CM_P2P || c->mode == CM_TOP)
    {
        do_open_status_output(c);
    }

    /* open --ifconfig-pool-persist file */
    if (c->mode == CM_TOP)
    {
        do_open_ifconfig_pool_persist(c);
    }

    /* reset OCC state */
    if (c->mode == CM_P2P || child)
    {
        c->c2.occ_op = occ_reset_op();
    }

    /* our wait-for-i/o objects, different for posix vs. win32 */
    if (c->mode == CM_P2P || c->mode == CM_TOP)
    {
        do_event_set_init(c, SHAPER_DEFINED(&c->options));
    }
    else if (c->mode == CM_CHILD_TCP)
    {
        do_event_set_init(c, false);
    }

    /* initialize HTTP or SOCKS proxy object at scope level 2 */
    init_proxy(c);

    /* allocate our socket object */
    if (c->mode == CM_P2P || c->mode == CM_TOP || c->mode == CM_CHILD_TCP)
    {
        do_link_socket_new(c);
    }

#ifdef ENABLE_FRAGMENT
    /* initialize internal fragmentation object */
    if (options->ce.fragment && (c->mode == CM_P2P || child))
    {
        c->c2.fragment = fragment_init(&c->c2.frame);
    }
#endif

    /* init crypto layer */
    {
        unsigned int crypto_flags = 0;
        if (c->mode == CM_TOP)
        {
            crypto_flags = CF_INIT_TLS_AUTH_STANDALONE;
        }
        else if (c->mode == CM_P2P)
        {
            crypto_flags = CF_LOAD_PERSISTED_PACKET_ID | CF_INIT_TLS_MULTI;
        }
        else if (child)
        {
            crypto_flags = CF_INIT_TLS_MULTI;
        }
        do_init_crypto(c, crypto_flags);
        if (IS_SIG(c) && !child)
        {
            goto sig;
        }
    }

#ifdef USE_COMP
    /* initialize compression library. */
    if (comp_enabled(&options->comp) && (c->mode == CM_P2P || child))
    {
        c->c2.comp_context = comp_init(&options->comp);
    }
#endif

    /* initialize MTU variables */
    do_init_frame(c);

    /* initialize TLS MTU variables */
    do_init_frame_tls(c);

    /* init workspace buffers whose size is derived from frame size */
    if (c->mode == CM_P2P || c->mode == CM_CHILD_TCP)
    {
        do_init_buffers(c);
    }

#ifdef ENABLE_FRAGMENT
    /* initialize internal fragmentation capability with known frame size */
    if (options->ce.fragment && (c->mode == CM_P2P || child))
    {
        do_init_fragment(c);
    }
#endif

    /* bind the TCP/UDP socket */
    if (c->mode == CM_P2P || c->mode == CM_TOP || c->mode == CM_CHILD_TCP)
    {
        do_init_socket_phase1(c);
    }

    /* initialize tun/tap device object,
     * open tun/tap device, ifconfig, run up script, etc. */
    if (!(options->up_delay || PULL_DEFINED(options)) && (c->mode == CM_P2P || c->mode == CM_TOP))
    {
        int error_flags = 0;
        c->c2.did_open_tun = do_open_tun(c, &error_flags);
    }

    /* print MTU info */
    do_print_data_channel_mtu_parms(c);

    /* get local and remote options compatibility strings */
    if (c->mode == CM_P2P || child)
    {
        do_compute_occ_strings(c);
    }

    /* initialize output speed limiter */
    if (c->mode == CM_P2P)
    {
        do_init_traffic_shaper(c);
    }

    /* do one-time inits, and possibly become a daemon here */
    do_init_first_time(c);

#ifdef ENABLE_PLUGIN
    /* initialize plugins */
    if (c->mode == CM_P2P || c->mode == CM_TOP)
    {
        open_plugins(c, false, OPENVPN_PLUGIN_INIT_POST_DAEMON);
    }
#endif

    /* initialise connect timeout timer */
    do_init_server_poll_timeout(c);

    /* finalize the TCP/UDP socket */
    if (c->mode == CM_P2P || c->mode == CM_TOP || c->mode == CM_CHILD_TCP)
    {
        do_init_socket_phase2(c);


        /* Update dynamic frame calculation as exact transport socket information
         * (IP vs IPv6) may be only available after socket phase2 has finished.
         * This is only needed for --static or no crypto, NCP will recalculate this
         * in tls_session_update_crypto_params (P2MP) */
        for (int i = 0; i < c->c1.link_sockets_num; i++)
        {
            frame_calculate_dynamic(&c->c2.frame, &c->c1.ks.key_type, &c->options,
                                    &c->c2.link_sockets[i]->info);
        }
    }

    /*
     * Actually do UID/GID downgrade, and chroot, if requested.
     * May be delayed by --client, --pull, or --up-delay.
     */
    do_uid_gid_chroot(c, c->c2.did_open_tun);

    /* initialize timers */
    if (c->mode == CM_P2P || child)
    {
        do_init_timers(c, false);
    }

#ifdef ENABLE_PLUGIN
    /* initialize plugins */
    if (c->mode == CM_P2P || c->mode == CM_TOP)
    {
        open_plugins(c, false, OPENVPN_PLUGIN_INIT_POST_UID_CHANGE);
    }
#endif

#if PORT_SHARE
    /* share OpenVPN port with foreign (such as HTTPS) server */
    if (c->first_time && (c->mode == CM_P2P || c->mode == CM_TOP))
    {
        init_port_share(c);
    }
#endif

    /* Check for signals */
    if (IS_SIG(c))
    {
        goto sig;
    }

    return;

sig:
    if (!c->sig->signal_text)
    {
        c->sig->signal_text = "init_instance";
    }
    close_context(c, -1, flags);
    return;
}

/*
 * Close a tunnel instance.
 */
void
close_instance(struct context *c)
{
    /* close event objects */
    do_close_event_set(c);

    if (c->mode == CM_P2P || c->mode == CM_CHILD_TCP || c->mode == CM_CHILD_UDP
        || c->mode == CM_TOP)
    {
#ifdef USE_COMP
        if (c->c2.comp_context)
        {
            comp_uninit(c->c2.comp_context);
            c->c2.comp_context = NULL;
        }
#endif

        /* free buffers */
        do_close_free_buf(c);

        /* close peer for DCO if enabled, needs peer-id so must be done before
         * closing TLS contexts */
        dco_remove_peer(c);

        /* close TLS */
        do_close_tls(c);

        /* free key schedules */
        do_close_free_key_schedule(c, (c->mode == CM_P2P || c->mode == CM_TOP));

        /* close TCP/UDP connection */
        do_close_link_socket(c);

        /* close TUN/TAP device */
        do_close_tun(c, false);

#ifdef ENABLE_MANAGEMENT
        if (management)
        {
            management_notify_client_close(management, &c->c2.mda_context, NULL);
        }
#endif

#ifdef ENABLE_PLUGIN
        /* call plugin close functions and unload */
        do_close_plugins(c);
#endif

        /* close packet-id persistence file */
        do_close_packet_id(c);

        /* close --status file */
        do_close_status_output(c);

#ifdef ENABLE_FRAGMENT
        /* close fragmentation handler */
        do_close_fragment(c);
#endif

        /* close --ifconfig-pool-persist obj */
        do_close_ifconfig_pool_persist(c);

        /* free up environmental variable store */
        do_env_set_destroy(c);

        /* close HTTP or SOCKS proxy */
        uninit_proxy(c);

        /* garbage collect */
        gc_free(&c->c2.gc);
    }
}

void
inherit_context_child(struct context *dest, const struct context *src, struct link_socket *sock)
{
    CLEAR(*dest);

    /* proto_is_dgram will ASSERT(0) if proto is invalid */
    dest->mode = proto_is_dgram(sock->info.proto) ? CM_CHILD_UDP : CM_CHILD_TCP;

    dest->gc = gc_new();

    ALLOC_OBJ_CLEAR_GC(dest->sig, struct signal_info, &dest->gc);

    /* c1 init */
    packet_id_persist_init(&dest->c1.pid_persist);
    dest->c1.link_sockets_num = 1;
    do_link_socket_addr_new(dest);

    dest->c1.ks.key_type = src->c1.ks.key_type;
    /* inherit SSL context */
    dest->c1.ks.ssl_ctx = src->c1.ks.ssl_ctx;
    dest->c1.ks.tls_wrap_key = src->c1.ks.tls_wrap_key;
    dest->c1.ks.tls_auth_key_type = src->c1.ks.tls_auth_key_type;
    dest->c1.ks.tls_crypt_v2_server_key = src->c1.ks.tls_crypt_v2_server_key;
    /* inherit pre-NCP ciphers */
    dest->options.ciphername = src->options.ciphername;
    dest->options.authname = src->options.authname;

    /* inherit auth-token */
    dest->c1.ks.auth_token_key = src->c1.ks.auth_token_key;

    /* options */
    dest->options = src->options;
    dest->options.ce.proto = sock->info.proto;
    options_detach(&dest->options);

    dest->c2.event_set = src->c2.event_set;

    if (dest->mode == CM_CHILD_TCP)
    {
        /*
         * The CM_TOP context does the socket listen(),
         * and the CM_CHILD_TCP context does the accept().
         */
        dest->c2.accept_from = sock;
    }

#ifdef ENABLE_PLUGIN
    /* inherit plugins */
    do_inherit_plugins(dest, src);
#endif

    /* context init */

    /* inherit tun/tap interface object now as it may be required
     * to initialize the DCO context in init_instance()
     */
    dest->c1.tuntap = src->c1.tuntap;

    /* UDP inherits some extra things which TCP does not */
    if (dest->mode == CM_CHILD_UDP)
    {
        ASSERT(!dest->c2.link_sockets);
        ASSERT(dest->options.ce.local_list);

        /* inherit buffers */
        dest->c2.buffers = src->c2.buffers;

        ALLOC_ARRAY_GC(dest->c2.link_sockets, struct link_socket *, 1, &dest->gc);

        /* inherit parent link_socket and tuntap */
        dest->c2.link_sockets[0] = sock;

        ALLOC_ARRAY_GC(dest->c2.link_socket_infos, struct link_socket_info *, 1, &dest->gc);
        ALLOC_OBJ_GC(dest->c2.link_socket_infos[0], struct link_socket_info, &dest->gc);
        *dest->c2.link_socket_infos[0] = sock->info;

        /* locally override some link_socket_info fields */
        dest->c2.link_socket_infos[0]->lsa = &dest->c1.link_socket_addrs[0];
        dest->c2.link_socket_infos[0]->connection_established = false;
    }

    init_instance(dest, src->c2.es, CC_NO_CLOSE | CC_USR1_TO_HUP);
    if (IS_SIG(dest))
    {
        return;
    }
}

void
inherit_context_top(struct context *dest, const struct context *src)
{
    /* copy parent */
    *dest = *src;

    /*
     * CM_TOP_CLONE will prevent close_instance from freeing or closing
     * resources owned by the parent.
     *
     * Also note that CM_TOP_CLONE context objects are
     * closed by multi_top_free in multi.c.
     */
    dest->mode = CM_TOP_CLONE;

    dest->first_time = false;
    dest->c0 = NULL;

    options_detach(&dest->options);
    gc_detach(&dest->gc);
    gc_detach(&dest->c2.gc);

    /* detach plugins */
    dest->plugins_owned = false;

    dest->c2.tls_multi = NULL;

    /* detach c1 ownership */
    dest->c1.tuntap_owned = false;
    dest->c1.status_output_owned = false;
    dest->c1.ifconfig_pool_persist_owned = false;

    /* detach c2 ownership */
    dest->c2.event_set_owned = false;
    dest->c2.link_socket_owned = false;
    dest->c2.buffers_owned = false;
    dest->c2.es_owned = false;

    dest->c2.event_set = NULL;
    do_event_set_init(dest, false);

#ifdef USE_COMP
    dest->c2.comp_context = NULL;
#endif
}

void
close_context(struct context *c, int sig, unsigned int flags)
{
    ASSERT(c);
    ASSERT(c->sig);

    if (sig >= 0)
    {
        register_signal(c->sig, sig, "close_context");
    }

    if (c->sig->signal_received == SIGUSR1)
    {
        if ((flags & CC_USR1_TO_HUP)
            || (c->sig->source == SIG_SOURCE_HARD && (flags & CC_HARD_USR1_TO_HUP)))
        {
            register_signal(c->sig, SIGHUP, "close_context usr1 to hup");
        }
    }

    if (!(flags & CC_NO_CLOSE))
    {
        close_instance(c);
    }

    if (flags & CC_GC_FREE)
    {
        context_gc_free(c);
    }
}

/* Write our PID to a file */
void
write_pid_file(const char *filename, const char *chroot_dir)
{
    if (filename)
    {
        unsigned int pid = 0;
        FILE *fp = platform_fopen(filename, "w");
        if (!fp)
        {
            msg(M_ERR, "Open error on pid file %s", filename);
            return;
        }

        pid = platform_getpid();
        fprintf(fp, "%u\n", pid);
        if (fclose(fp))
        {
            msg(M_ERR, "Close error on pid file %s", filename);
        }

        /* remember file name so it can be deleted "out of context" later */
        /* (the chroot case is more complex and not handled today) */
        if (!chroot_dir)
        {
            saved_pid_file_name = strdup(filename);
            if (!saved_pid_file_name)
            {
                msg(M_FATAL, "Failed allocate memory saved_pid_file_name");
            }
        }
    }
}

/* remove PID file on exit, called from openvpn_exit() */
void
remove_pid_file(void)
{
    if (saved_pid_file_name)
    {
        platform_unlink(saved_pid_file_name);
    }
}


/*
 * Do a loopback test
 * on the crypto subsystem.
 */
static void *
test_crypto_thread(void *arg)
{
    struct context *c = (struct context *)arg;
    const struct options *options = &c->options;

    ASSERT(options->test_crypto);
    init_verb_mute(c, IVM_LEVEL_1);
    context_init_1(c);
    next_connection_entry(c);
    do_init_crypto_static(c, 0);

    frame_finalize_options(c, options);

    test_crypto(&c->c2.crypto_options, &c->c2.frame);

    key_schedule_free(&c->c1.ks, true);
    packet_id_free(&c->c2.crypto_options.packet_id);

    context_gc_free(c);
    return NULL;
}

bool
do_test_crypto(const struct options *o)
{
    if (o->test_crypto)
    {
        struct context c;

        /* print version number */
        msg(M_INFO, "%s", title_string);

        context_clear(&c);
        c.options = *o;
        options_detach(&c.options);
        c.first_time = true;
        test_crypto_thread((void *)&c);
        return true;
    }
    return false;
}
