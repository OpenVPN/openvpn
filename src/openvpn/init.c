/*
 *  OpenVPN -- An application to securely tunnel IP networks
 *             over a single TCP/UDP port, with support for SSL/TLS-based
 *             session authentication and key exchange,
 *             packet encryption, packet authentication, and
 *             packet compression.
 *
 *  Copyright (C) 2002-2017 OpenVPN Technologies, Inc. <sales@openvpn.net>
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
#elif defined(_MSC_VER)
#include "config-msvc.h"
#endif

#include "syshead.h"

#ifdef ENABLE_SYSTEMD
#include <systemd/sd-daemon.h>
#endif

#include "win32.h"
#include "init.h"
#include "sig.h"
#include "occ.h"
#include "list.h"
#include "otime.h"
#include "pool.h"
#include "gremlin.h"
#include "pkcs11.h"
#include "ps.h"
#include "lladdr.h"
#include "ping.h"
#include "mstats.h"
#include "ssl_verify.h"
#include "tls_crypt.h"
#include "forward-inline.h"

#include "memdbg.h"

#include "occ-inline.h"

static struct context *static_context; /* GLOBAL */

/*
 * Crypto initialization flags
 */
#define CF_LOAD_PERSISTED_PACKET_ID (1<<0)
#define CF_INIT_TLS_MULTI           (1<<1)
#define CF_INIT_TLS_AUTH_STANDALONE (1<<2)

static void do_init_first_time(struct context *c);

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
 * Should be called after options->ce is modified at the top
 * of a SIGUSR1 restart.
 */
static void
update_options_ce_post(struct options *options)
{
#if P2MP
    /*
     * In pull mode, we usually import --ping/--ping-restart parameters from
     * the server.  However we should also set an initial default --ping-restart
     * for the period of time before we pull the --ping-restart parameter
     * from the server.
     */
    if (options->pull
        && options->ping_rec_timeout_action == PING_UNDEF
        && proto_is_dgram(options->ce.proto))
    {
        options->ping_rec_timeout = PRE_PULL_INITIAL_PING_RESTART;
        options->ping_rec_timeout_action = PING_RESTART;
    }
#endif
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
            ce->socks_proxy_port = p[3];
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
        gc_free(&gc);
    }

    return ret;
}


static bool
management_callback_remote_cmd(void *arg, const char **p)
{
    struct context *c = (struct context *) arg;
    struct connection_entry *ce = &c->options.ce;
    int ret = false;
    if (p[1] && ((ce->flags>>CE_MAN_QUERY_REMOTE_SHIFT)&CE_MAN_QUERY_REMOTE_MASK) == CE_MAN_QUERY_REMOTE_QUERY)
    {
        int flags = 0;
        if (!strcmp(p[1], "ACCEPT"))
        {
            flags = CE_MAN_QUERY_REMOTE_ACCEPT;
            ret = true;
        }
        else if (!strcmp(p[1], "SKIP"))
        {
            flags = CE_MAN_QUERY_REMOTE_SKIP;
            ret = true;
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
            ce->flags &= ~(CE_MAN_QUERY_REMOTE_MASK<<CE_MAN_QUERY_REMOTE_SHIFT);
            ce->flags |= ((flags&CE_MAN_QUERY_REMOTE_MASK)<<CE_MAN_QUERY_REMOTE_SHIFT);
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

        ce->flags &= ~(CE_MAN_QUERY_REMOTE_MASK << CE_MAN_QUERY_REMOTE_SHIFT);
        ce->flags |= (CE_MAN_QUERY_REMOTE_QUERY << CE_MAN_QUERY_REMOTE_SHIFT);
        while (((ce->flags >> CE_MAN_QUERY_REMOTE_SHIFT)
                & CE_MAN_QUERY_REMOTE_MASK) == CE_MAN_QUERY_REMOTE_QUERY)
        {
            management_event_loop_n_seconds(management, 1);
            if (IS_SIG(c))
            {
                ce_changed = false; /* connection entry have not been set */
                break;
            }
        }
    }
    gc_free(&gc);

    if (ce_changed)
    {
        /* If it is likely a connection entry was modified,
         * check what changed in the flags and that it was not skipped
         */
        const int flags = ((ce->flags >> CE_MAN_QUERY_REMOTE_SHIFT)
                           & CE_MAN_QUERY_REMOTE_MASK);
        ce_changed = (flags != CE_MAN_QUERY_REMOTE_SKIP);
    }
    return ce_changed;
}
#endif /* ENABLE_MANAGEMENT */

/*
 * Initialize and possibly randomize connection list.
 */
static void
init_connection_list(struct context *c)
{
    struct connection_list *l = c->options.connection_list;

    l->current = -1;
    if (c->options.remote_random)
    {
        int i;
        for (i = 0; i < l->len; ++i)
        {
            const int j = get_random() % l->len;
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
        platform_freeaddrinfo(lsa->remote_list);
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
            if (c->c1.link_socket_addr.current_remote
                && c->c1.link_socket_addr.current_remote->ai_next)
            {
                c->c1.link_socket_addr.current_remote =
                    c->c1.link_socket_addr.current_remote->ai_next;
            }
            else
            {
                /* FIXME (schwabe) fix the persist-remote-ip option for real,
                 * this is broken probably ever since connection lists and multiple
                 * remote existed
                 */
                if (!c->options.persist_remote_ip)
                {
                    /* close_instance should have cleared the addrinfo objects */
                    ASSERT(c->c1.link_socket_addr.current_remote == NULL);
                    ASSERT(c->c1.link_socket_addr.remote_list == NULL);
                }
                else
                {
                    c->c1.link_socket_addr.current_remote =
                        c->c1.link_socket_addr.remote_list;
                }

                /*
                 * Increase the number of connection attempts
                 * If this is connect-retry-max * size(l)
                 * OpenVPN will quit
                 */

                c->options.unsuccessful_attempts++;

                if (++l->current >= l->len)
                {

                    l->current = 0;
                    if (++n_cycles >= 2)
                    {
                        msg(M_FATAL, "No usable connection profiles are present");
                    }
                }
            }
        }

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
        && c->options.unsuccessful_attempts > (l->len  * c->options.connect_retry_max))
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
#ifdef ENABLE_CRYPTO
    /* Certificate password input */
    if (c->options.key_pass_file)
    {
        pem_password_setup(c->options.key_pass_file);
    }
#endif

#if P2MP
    /* Auth user/pass input */
    if (c->options.auth_user_pass_file)
    {
#ifdef ENABLE_CLIENT_CR
        auth_user_pass_setup(c->options.auth_user_pass_file, &c->options.sc_info);
#else
        auth_user_pass_setup(c->options.auth_user_pass_file, NULL);
#endif
    }
#endif
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
        c->c1.socks_proxy = socks_proxy_new(c->options.ce.socks_proxy_server,
                                            c->options.ce.socks_proxy_port,
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

void
context_init_1(struct context *c)
{
    context_clear_1(c);

    packet_id_persist_init(&c->c1.pid_persist);

    init_connection_list(c);

#if defined(ENABLE_PKCS11)
    if (c->first_time)
    {
        int i;
        pkcs11_initialize(true, c->options.pkcs11_pin_cache_period);
        for (i = 0; i<MAX_PARMS && c->options.pkcs11_providers[i] != NULL; i++)
        {
            pkcs11_addProvider(c->options.pkcs11_providers[i], c->options.pkcs11_protected_authentication[i],
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
               (unsigned long) getpid());
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
        port_share = port_share_open(c->options.port_share_host,
                                     c->options.port_share_port,
                                     MAX_RW_SIZE_LINK(&c->c2.frame),
                                     c->options.port_share_journal_dir);
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
    /* configure_path (); */

#if defined(ENABLE_CRYPTO) && defined(DMALLOC)
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
        const unsigned int seed = (unsigned int) tv.tv_sec ^ tv.tv_usec;
        srandom(seed);
    }

    error_reset();              /* initialize error.c */
    reset_check_status();       /* initialize status check code in socket.c */

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

#ifdef ENABLE_CRYPTO
    init_ssl_lib();

    /* init PRNG used for IV generation */
    /* When forking, copy this to more places in the code to avoid fork
     * random-state predictability */
    prng_init(NULL, 0);
#endif

#ifdef PID_TEST
    packet_id_interactive_test();       /* test the sequence number code */
    return false;
#endif

#ifdef SCHEDULE_TEST
    schedule_test();
    return false;
#endif

#ifdef LIST_TEST
    list_test();
    return false;
#endif

#ifdef IFCONFIG_POOL_TEST
    ifconfig_pool_test(0x0A010004, 0x0A0100FF);
    return false;
#endif

#ifdef CHARACTER_CLASS_DEBUG
    character_class_debug();
    return false;
#endif

#ifdef EXTRACT_X509_FIELD_TEST
    extract_x509_field_test();
    return false;
#endif

#ifdef TIME_TEST
    time_test();
    return false;
#endif

#ifdef TEST_GET_DEFAULT_GATEWAY
    {
        struct route_gateway_info rgi;
        struct route_ipv6_gateway_info rgi6;
        get_default_gateway(&rgi);
        get_default_gateway_ipv6(&rgi6, NULL);
        print_default_gateway(M_INFO, &rgi, &rgi6);
        return false;
    }
#endif

#ifdef GEN_PATH_TEST
    {
        struct gc_arena gc = gc_new();
        const char *fn = gen_path("foo",
                                  "bar",
                                  &gc);
        printf("%s\n", fn);
        gc_free(&gc);
    }
    return false;
#endif

#ifdef STATUS_PRINTF_TEST
    {
        struct gc_arena gc = gc_new();
        const char *tmp_file = create_temp_file("/tmp", "foo", &gc);
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

#ifdef ARGV_TEST
    {
        void argv_test(void);

        argv_test();
        return false;
    }
#endif

#ifdef PRNG_TEST
    {
        struct gc_arena gc = gc_new();
        uint8_t rndbuf[8];
        int i;
        prng_init("sha1", 16);
        /*prng_init (NULL, 0);*/
        const int factor = 1;
        for (i = 0; i < factor * 8; ++i)
        {
#if 1
            prng_bytes(rndbuf, sizeof(rndbuf));
#else
            ASSERT(rand_bytes(rndbuf, sizeof(rndbuf)));
#endif
            printf("[%d] %s\n", i, format_hex(rndbuf, sizeof(rndbuf), 0, &gc));
        }
        gc_free(&gc);
        prng_uninit();
        return false;
    }
#endif /* ifdef PRNG_TEST */

#ifdef BUFFER_LIST_AGGREGATE_TEST
    /* test buffer_list_aggregate function */
    {
        static const char *text[] = {
            "It was a bright cold day in April, ",
            "and the clocks were striking ",
            "thirteen. ",
            "Winston Smith, ",
            "his chin nuzzled into his breast in an ",
            "effort to escape the vile wind, ",
            "slipped quickly through the glass doors ",
            "of Victory Mansions, though not quickly ",
            "enough to prevent a swirl of gritty dust from ",
            "entering along with him."
        };

        int iter, listcap;
        for (listcap = 0; listcap < 12; ++listcap)
        {
            for (iter = 0; iter < 512; ++iter)
            {
                struct buffer_list *bl = buffer_list_new(listcap);
                {
                    int i;
                    for (i = 0; i < SIZE(text); ++i)
                    {
                        buffer_list_push(bl, (unsigned char *)text[i]);
                    }
                }
                printf("[cap=%d i=%d] *************************\n", listcap, iter);
                if (!(iter & 8))
                {
                    buffer_list_aggregate(bl, iter/2);
                }
                if (!(iter & 16))
                {
                    buffer_list_push(bl, (unsigned char *)"Even more text...");
                }
                buffer_list_aggregate(bl, iter);
                if (!(iter & 1))
                {
                    buffer_list_push(bl, (unsigned char *)"More text...");
                }
                {
                    struct buffer *buf;
                    while ((buf = buffer_list_peek(bl)))
                    {
                        int c;
                        printf("'");
                        while ((c = buf_read_u8(buf)) >= 0)
                        {
                            putchar(c);
                        }
                        printf("'\n");
                        buffer_list_advance(bl, 0);
                    }
                }
                buffer_list_free(bl);
            }
        }
        return false;
    }
#endif /* ifdef BUFFER_LIST_AGGREGATE_TEST */

#ifdef MSTATS_TEST
    {
        int i;
        mstats_open("/dev/shm/mstats.dat");
        for (i = 0; i < 30; ++i)
        {
            mmap_stats->n_clients += 1;
            mmap_stats->link_write_bytes += 8;
            mmap_stats->link_read_bytes += 16;
            sleep(1);
        }
        mstats_close();
        return false;
    }
#endif

    return true;
}

void
uninit_static(void)
{
#ifdef ENABLE_CRYPTO
    free_ssl_lib();
#endif

#ifdef ENABLE_PKCS11
    pkcs11_terminate();
#endif

#if PORT_SHARE
    close_port_share();
#endif

#if defined(MEASURE_TLS_HANDSHAKE_STATS) && defined(ENABLE_CRYPTO)
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
        char *dev_node = string_alloc(options->dev_node, NULL); /* POSIX basename() implementaions may modify its arguments */
        options->dev = basename(dev_node);
    }
}

bool
print_openssl_info(const struct options *options)
{
    /*
     * OpenSSL info print mode?
     */
#ifdef ENABLE_CRYPTO
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
            show_available_tls_ciphers(options->cipher_list);
        }
        if (options->show_curves)
        {
            show_available_curves();
        }
        return true;
    }
#endif /* ifdef ENABLE_CRYPTO */
    return false;
}

/*
 * Static pre-shared key generation mode?
 */
bool
do_genkey(const struct options *options)
{
#ifdef ENABLE_CRYPTO
    if (options->genkey)
    {
        int nbits_written;

        notnull(options->shared_secret_file,
                "shared secret output file (--secret)");

        if (options->mlock)     /* should we disable paging? */
        {
            platform_mlockall(true);
        }

        nbits_written = write_key_file(2, options->shared_secret_file);

        msg(D_GENKEY | M_NOPREFIX,
            "Randomly generated %d bit key written to %s", nbits_written,
            options->shared_secret_file);
        return true;
    }
#endif
    return false;
}

/*
 * Persistent TUN/TAP device management mode?
 */
bool
do_persist_tuntap(const struct options *options)
{
    if (options->persist_config)
    {
        /* sanity check on options for --mktun or --rmtun */
        notnull(options->dev, "TUN/TAP device (--dev)");
        if (options->ce.remote || options->ifconfig_local
            || options->ifconfig_remote_netmask
#ifdef ENABLE_CRYPTO
            || options->shared_secret_file
            || options->tls_server || options->tls_client
#endif
            )
        {
            msg(M_FATAL|M_OPTERR,
                "options --mktun or --rmtun should only be used together with --dev");
        }
#ifdef ENABLE_FEATURE_TUN_PERSIST
        tuncfg(options->dev, options->dev_type, options->dev_node,
               options->persist_mode,
               options->username, options->groupname, &options->tuntap_options);
        if (options->persist_mode && options->lladdr)
        {
            set_lladdr(options->dev, options->lladdr, NULL);
        }
        return true;
#else  /* ifdef ENABLE_FEATURE_TUN_PERSIST */
        msg( M_FATAL|M_OPTERR,
             "options --mktun and --rmtun are not available on your operating "
             "system.  Please check 'man tun' (or 'tap'), whether your system "
             "supports using 'ifconfig %s create' / 'destroy' to create/remove "
             "persistant tunnel interfaces.", options->dev );
#endif
    }
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
        ASSERT(!options->inetd);
        /* Don't chdir immediately, but the end of the init sequence, if needed */
        if (daemon(1, options->log) < 0)
        {
            msg(M_ERR, "daemon() failed or unsupported");
        }
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
                platform_group_set(&c0->platform_state_group);
                platform_user_set(&c0->platform_state_user);
            }
            else if (c->first_time)
            {
                msg(M_INFO, "NOTE: UID/GID downgrade %s", why_not);
            }
        }

#ifdef ENABLE_MEMSTATS
        if (c->first_time && c->options.memstats_fn)
        {
            mstats_open(c->options.memstats_fn);
        }
#endif

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
                    msg(M_ERR, "setcon to '%s' failed; is /proc accessible?", c->options.selinux_context);
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
#ifdef ENABLE_CRYPTO
    if (c->c2.tls_multi)
    {
        buf_printf(&out, "[%s] ", tls_common_name(c->c2.tls_multi, false));
    }
#endif
    return BSTR(&out);
}

void
pre_setup(const struct options *options)
{
#ifdef _WIN32
    if (options->exit_event_name)
    {
        win32_signal_open(&win32_signal,
                          WSO_FORCE_SERVICE,
                          options->exit_event_name,
                          options->exit_event_initial_state);
    }
    else
    {
        win32_signal_open(&win32_signal,
                          WSO_FORCE_CONSOLE,
                          NULL,
                          false);

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

    /* initialize pings */

    if (c->options.ping_send_timeout)
    {
        event_timeout_init(&c->c2.ping_send_interval, c->options.ping_send_timeout, 0);
    }

    if (c->options.ping_rec_timeout)
    {
        event_timeout_init(&c->c2.ping_rec_interval, c->options.ping_rec_timeout, now);
    }

    if (!deferred)
    {
        /* initialize connection establishment timer */
        event_timeout_init(&c->c2.wait_for_connect, 1, now);

#ifdef ENABLE_OCC
        /* initialize occ timers */

        if (c->options.occ
            && !TLS_MODE(c)
            && c->c2.options_string_local && c->c2.options_string_remote)
        {
            event_timeout_init(&c->c2.occ_interval, OCC_INTERVAL_SECONDS, now);
        }

        if (c->options.mtu_test)
        {
            event_timeout_init(&c->c2.occ_mtu_load_test_interval, OCC_MTU_LOAD_INTERVAL_SECONDS, now);
        }
#endif

        /* initialize packet_id persistence timer */
#ifdef ENABLE_CRYPTO
        if (c->options.packet_id_file)
        {
            event_timeout_init(&c->c2.packet_id_persist_interval, 60, now);
        }

        /* initialize tmp_int optimization that limits the number of times we call
         * tls_multi_process in the main event loop */
        interval_init(&c->c2.tmp_int, TLS_MULTI_HORIZON, TLS_MULTI_REFRESH);
#endif
    }
}

/*
 * Initialize traffic shaper.
 */
static void
do_init_traffic_shaper(struct context *c)
{
#ifdef ENABLE_FEATURE_SHAPER
    /* initialize traffic shaper (i.e. transmit bandwidth limiter) */
    if (c->options.shaper)
    {
        shaper_init(&c->c2.shaper, c->options.shaper);
        shaper_msg(&c->c2.shaper);
    }
#endif
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
do_init_route_list(const struct options *options,
                   struct route_list *route_list,
                   const struct link_socket_info *link_socket_info,
                   struct env_set *es)
{
    const char *gw = NULL;
    int dev = dev_type_enum(options->dev, options->dev_type);
    int metric = 0;

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

    if (init_route_list(route_list,
                        options->routes,
                        gw,
                        metric,
                        link_socket_current_remote(link_socket_info),
                        es))
    {
        /* copy routes to environment */
        setenv_routes(es, route_list);
    }
}

static void
do_init_route_ipv6_list(const struct options *options,
                        struct route_ipv6_list *route_ipv6_list,
                        const struct link_socket_info *link_socket_info,
                        struct env_set *es)
{
    const char *gw = NULL;
    int metric = -1;            /* no metric set */

    gw = options->ifconfig_ipv6_remote;         /* default GW = remote end */
#if 0                                   /* not yet done for IPv6 - TODO!*/
    if (options->route_ipv6_default_gateway)            /* override? */
    {
        gw = options->route_ipv6_default_gateway;
    }
#endif

    if (options->route_default_metric)
    {
        metric = options->route_default_metric;
    }

    /* redirect (IPv6) gateway to VPN?  if yes, add a few more specifics
     */
    if (options->routes_ipv6->flags & RG_REROUTE_GW)
    {
        char *opt_list[] = { "::/3", "2000::/4", "3000::/4", "fc00::/7", NULL };
        int i;

        for (i = 0; opt_list[i]; i++)
        {
            add_route_ipv6_to_option_list( options->routes_ipv6,
                                           string_alloc(opt_list[i], options->routes_ipv6->gc),
                                           NULL, NULL );
        }
    }

    if (init_route_ipv6_list(route_ipv6_list,
                             options->routes_ipv6,
                             gw,
                             metric,
                             link_socket_current_remote_ipv6(link_socket_info),
                             es))
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


#ifdef ENABLE_CRYPTO
    /*
     * In some cases (i.e. when receiving auth-token via
     * push-reply) the auth-nocache option configured on the
     * client is overridden; for this reason we have to wait
     * for the push-reply message before attempting to wipe
     * the user/pass entered by the user
     */
    if (c->options.mode == MODE_POINT_TO_POINT)
    {
        delayed_auth_pass_purge();
    }
#endif /* ENABLE_CRYPTO */

    /* Test if errors */
    if (flags & ISC_ERRORS)
    {
#ifdef _WIN32
        show_routes(M_INFO|M_NOPREFIX);
        show_adapters(M_INFO|M_NOPREFIX);
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
    if ((flags & (ISC_ERRORS|ISC_SERVER)) == 0)
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

        CLEAR(local);
        actual = &get_link_socket_info(c)->lsa->actual;
        remote = actual->dest;
        platform_getsockname(c->c2.link_socket->sd, &local.addr.sa, &sa_len);
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
        management_set_state(management,
                             OPENVPN_STATE_CONNECTED,
                             detail,
                             tun_local,
                             tun_local6,
                             &local,
                             &remote);
        if (tun_local)
        {
            management_post_tunnel_open(management, *tun_local);
        }
    }
#endif /* ifdef ENABLE_MANAGEMENT */
}

/*
 * Possibly add routes and/or call route-up script
 * based on options.
 */
void
do_route(const struct options *options,
         struct route_list *route_list,
         struct route_ipv6_list *route_ipv6_list,
         const struct tuntap *tt,
         const struct plugin_list *plugins,
         struct env_set *es)
{
    if (!options->route_noexec && ( route_list || route_ipv6_list ) )
    {
        add_routes(route_list, route_ipv6_list, tt, ROUTE_OPTION_FLAGS(options), es);
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
        if (plugin_call(plugins, OPENVPN_PLUGIN_ROUTE_UP, NULL, NULL, es) != OPENVPN_PLUGIN_FUNC_SUCCESS)
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
        argv_reset(&argv);
    }

#ifdef _WIN32
    if (options->show_net_up)
    {
        show_routes(M_INFO|M_NOPREFIX);
        show_adapters(M_INFO|M_NOPREFIX);
    }
    else if (check_debug_level(D_SHOW_NET))
    {
        show_routes(D_SHOW_NET|M_NOPREFIX);
        show_adapters(D_SHOW_NET|M_NOPREFIX);
    }
#endif
}

/*
 * initialize tun/tap device object
 */
static void
do_init_tun(struct context *c)
{
    c->c1.tuntap = init_tun(c->options.dev,
                            c->options.dev_type,
                            c->options.topology,
                            c->options.ifconfig_local,
                            c->options.ifconfig_remote_netmask,
                            c->options.ifconfig_ipv6_local,
                            c->options.ifconfig_ipv6_netbits,
                            c->options.ifconfig_ipv6_remote,
                            c->c1.link_socket_addr.bind_local,
                            c->c1.link_socket_addr.remote_list,
                            !c->options.ifconfig_nowarn,
                            c->c2.es);

    init_tun_post(c->c1.tuntap,
                  &c->c2.frame,
                  &c->options.tuntap_options);

    c->c1.tuntap_owned = true;
}

/*
 * Open tun/tap device, ifconfig, call up script, etc.
 */

static bool
do_open_tun(struct context *c)
{
    struct gc_arena gc = gc_new();
    bool ret = false;

#ifndef TARGET_ANDROID
    if (!c->c1.tuntap)
    {
#endif

#ifdef TARGET_ANDROID
    /* If we emulate persist-tun on android we still have to open a new tun and
     * then close the old */
    int oldtunfd = -1;
    if (c->c1.tuntap)
    {
        oldtunfd = c->c1.tuntap->fd;
    }
#endif

    /* initialize (but do not open) tun/tap object */
    do_init_tun(c);

#ifdef _WIN32
    /* store (hide) interactive service handle in tuntap_options */
    c->c1.tuntap->options.msg_channel = c->options.msg_channel;
    msg(D_ROUTE, "interactive service msg_channel=%u", (unsigned int) c->options.msg_channel);
#endif

    /* allocate route list structure */
    do_alloc_route_list(c);

    /* parse and resolve the route option list */
    ASSERT(c->c2.link_socket);
    if (c->options.routes && c->c1.route_list)
    {
        do_init_route_list(&c->options, c->c1.route_list,
                           &c->c2.link_socket->info, c->c2.es);
    }
    if (c->options.routes_ipv6 && c->c1.route_ipv6_list)
    {
        do_init_route_ipv6_list(&c->options, c->c1.route_ipv6_list,
                                &c->c2.link_socket->info, c->c2.es);
    }

    /* do ifconfig */
    if (!c->options.ifconfig_noexec
        && ifconfig_order() == IFCONFIG_BEFORE_TUN_OPEN)
    {
        /* guess actual tun/tap unit number that will be returned
         * by open_tun */
        const char *guess = guess_tuntap_dev(c->options.dev,
                                             c->options.dev_type,
                                             c->options.dev_node,
                                             &gc);
        do_ifconfig(c->c1.tuntap, guess, TUN_MTU_SIZE(&c->c2.frame), c->c2.es);
    }

    /* possibly add routes */
    if (route_order() == ROUTE_BEFORE_TUN)
    {
        /* Ignore route_delay, would cause ROUTE_BEFORE_TUN to be ignored */
        do_route(&c->options, c->c1.route_list, c->c1.route_ipv6_list,
                 c->c1.tuntap, c->plugins, c->c2.es);
    }
#ifdef TARGET_ANDROID
    /* Store the old fd inside the fd so open_tun can use it */
    c->c1.tuntap->fd = oldtunfd;
#endif
    /* open the tun device */
    open_tun(c->options.dev, c->options.dev_type, c->options.dev_node,
             c->c1.tuntap);

    /* set the hardware address */
    if (c->options.lladdr)
    {
        set_lladdr(c->c1.tuntap->actual_name, c->options.lladdr, c->c2.es);
    }

    /* do ifconfig */
    if (!c->options.ifconfig_noexec
        && ifconfig_order() == IFCONFIG_AFTER_TUN_OPEN)
    {
        do_ifconfig(c->c1.tuntap, c->c1.tuntap->actual_name, TUN_MTU_SIZE(&c->c2.frame), c->c2.es);
    }

    /* run the up script */
    run_up_down(c->options.up_script,
                c->plugins,
                OPENVPN_PLUGIN_UP,
                c->c1.tuntap->actual_name,
#ifdef _WIN32
                c->c1.tuntap->adapter_index,
#endif
                dev_type_string(c->options.dev, c->options.dev_type),
                TUN_MTU_SIZE(&c->c2.frame),
                EXPANDED_SIZE(&c->c2.frame),
                print_in_addr_t(c->c1.tuntap->local, IA_EMPTY_IF_UNDEF, &gc),
                print_in_addr_t(c->c1.tuntap->remote_netmask, IA_EMPTY_IF_UNDEF, &gc),
                "init",
                NULL,
                "up",
                c->c2.es);

#if defined(_WIN32)
    if (c->options.block_outside_dns)
    {
        dmsg(D_LOW, "Blocking outside DNS");
        if (!win_wfp_block_dns(c->c1.tuntap->adapter_index, c->options.msg_channel))
        {
            msg(M_FATAL, "Blocking DNS failed!");
        }
    }
#endif

    /* possibly add routes */
    if ((route_order() == ROUTE_AFTER_TUN) && (!c->options.route_delay_defined))
    {
        do_route(&c->options, c->c1.route_list, c->c1.route_ipv6_list,
                 c->c1.tuntap, c->plugins, c->c2.es);
    }

    /*
     * Did tun/tap driver give us an MTU?
     */
    if (c->c1.tuntap->post_open_mtu)
    {
        frame_set_mtu_dynamic(&c->c2.frame,
                              c->c1.tuntap->post_open_mtu,
                              SET_MTU_TUN | SET_MTU_UPPER_BOUND);
    }

    ret = true;
    static_context = c;
#ifndef TARGET_ANDROID
}
else
{
    msg(M_INFO, "Preserving previous TUN/TAP instance: %s",
        c->c1.tuntap->actual_name);

    /* explicitly set the ifconfig_* env vars */
    do_ifconfig_setenv(c->c1.tuntap, c->c2.es);

    /* run the up script if user specified --up-restart */
    if (c->options.up_restart)
    {
        run_up_down(c->options.up_script,
                    c->plugins,
                    OPENVPN_PLUGIN_UP,
                    c->c1.tuntap->actual_name,
#ifdef _WIN32
                    c->c1.tuntap->adapter_index,
#endif
                    dev_type_string(c->options.dev, c->options.dev_type),
                    TUN_MTU_SIZE(&c->c2.frame),
                    EXPANDED_SIZE(&c->c2.frame),
                    print_in_addr_t(c->c1.tuntap->local, IA_EMPTY_IF_UNDEF, &gc),
                    print_in_addr_t(c->c1.tuntap->remote_netmask, IA_EMPTY_IF_UNDEF, &gc),
                    "restart",
                    NULL,
                    "up",
                    c->c2.es);
    }
#if defined(_WIN32)
    if (c->options.block_outside_dns)
    {
        dmsg(D_LOW, "Blocking outside DNS");
        if (!win_wfp_block_dns(c->c1.tuntap->adapter_index, c->options.msg_channel))
        {
            msg(M_FATAL, "Blocking DNS failed!");
        }
    }
#endif

}
#endif /* ifndef TARGET_ANDROID */
    gc_free(&gc);
    return ret;
}

/*
 * Close TUN/TAP device
 */

static void
do_close_tun_simple(struct context *c)
{
    msg(D_CLOSE, "Closing TUN/TAP interface");
    close_tun(c->c1.tuntap);
    c->c1.tuntap = NULL;
    c->c1.tuntap_owned = false;
#if P2MP
    CLEAR(c->c1.pulled_options_digest_save);
#endif
}

static void
do_close_tun(struct context *c, bool force)
{
    struct gc_arena gc = gc_new();
    if (c->c1.tuntap && c->c1.tuntap_owned)
    {
        const char *tuntap_actual = string_alloc(c->c1.tuntap->actual_name, &gc);
#ifdef _WIN32
        DWORD adapter_index = c->c1.tuntap->adapter_index;
#endif
        const in_addr_t local = c->c1.tuntap->local;
        const in_addr_t remote_netmask = c->c1.tuntap->remote_netmask;

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
                run_up_down(c->options.route_predown_script,
                            c->plugins,
                            OPENVPN_PLUGIN_ROUTE_PREDOWN,
                            tuntap_actual,
#ifdef _WIN32
                            adapter_index,
#endif
                            NULL,
                            TUN_MTU_SIZE(&c->c2.frame),
                            EXPANDED_SIZE(&c->c2.frame),
                            print_in_addr_t(local, IA_EMPTY_IF_UNDEF, &gc),
                            print_in_addr_t(remote_netmask, IA_EMPTY_IF_UNDEF, &gc),
                            "init",
                            signal_description(c->sig->signal_received,
                                               c->sig->signal_text),
                            "route-pre-down",
                            c->c2.es);

                delete_routes(c->c1.route_list, c->c1.route_ipv6_list,
                              c->c1.tuntap, ROUTE_OPTION_FLAGS(&c->options), c->c2.es);
            }

            /* actually close tun/tap device based on --down-pre flag */
            if (!c->options.down_pre)
            {
                do_close_tun_simple(c);
            }

            /* Run the down script -- note that it will run at reduced
             * privilege if, for example, "--user nobody" was used. */
            run_up_down(c->options.down_script,
                        c->plugins,
                        OPENVPN_PLUGIN_DOWN,
                        tuntap_actual,
#ifdef _WIN32
                        adapter_index,
#endif
                        NULL,
                        TUN_MTU_SIZE(&c->c2.frame),
                        EXPANDED_SIZE(&c->c2.frame),
                        print_in_addr_t(local, IA_EMPTY_IF_UNDEF, &gc),
                        print_in_addr_t(remote_netmask, IA_EMPTY_IF_UNDEF, &gc),
                        "init",
                        signal_description(c->sig->signal_received,
                                           c->sig->signal_text),
                        "down",
                        c->c2.es);

#if defined(_WIN32)
            if (c->options.block_outside_dns)
            {
                if (!win_wfp_uninit(adapter_index, c->options.msg_channel))
                {
                    msg(M_FATAL, "Uninitialising WFP failed!");
                }
            }
#endif

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
                run_up_down(c->options.down_script,
                            c->plugins,
                            OPENVPN_PLUGIN_DOWN,
                            tuntap_actual,
#ifdef _WIN32
                            adapter_index,
#endif
                            NULL,
                            TUN_MTU_SIZE(&c->c2.frame),
                            EXPANDED_SIZE(&c->c2.frame),
                            print_in_addr_t(local, IA_EMPTY_IF_UNDEF, &gc),
                            print_in_addr_t(remote_netmask, IA_EMPTY_IF_UNDEF, &gc),
                            "restart",
                            signal_description(c->sig->signal_received,
                                               c->sig->signal_text),
                            "down",
                            c->c2.es);
            }

#if defined(_WIN32)
            if (c->options.block_outside_dns)
            {
                if (!win_wfp_uninit(adapter_index, c->options.msg_channel))
                {
                    msg(M_FATAL, "Uninitialising WFP failed!");
                }
            }
#endif

        }
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

#if P2MP
/**
 * Helper for do_up().  Take two option hashes and return true if they are not
 * equal, or either one is all-zeroes.
 */
static bool
options_hash_changed_or_zero(const struct sha256_digest *a,
                             const struct sha256_digest *b)
{
    const struct sha256_digest zero = {{0}};
    return memcmp(a, b, sizeof(struct sha256_digest))
           || !memcmp(a, &zero, sizeof(struct sha256_digest));
}
#endif /* P2MP */

bool
do_up(struct context *c, bool pulled_options, unsigned int option_types_found)
{
    if (!c->c2.do_up_ran)
    {
        reset_coarse_timers(c);

        if (pulled_options)
        {
            if (!do_deferred_options(c, option_types_found))
            {
                msg(D_PUSH_ERRORS, "ERROR: Failed to apply push options");
                return false;
            }
        }

        /* if --up-delay specified, open tun, do ifconfig, and run up script now */
        if (c->options.up_delay || PULL_DEFINED(&c->options))
        {
            c->c2.did_open_tun = do_open_tun(c);
            update_time();

#if P2MP
            /*
             * Was tun interface object persisted from previous restart iteration,
             * and if so did pulled options string change from previous iteration?
             */
            if (!c->c2.did_open_tun
                && PULL_DEFINED(&c->options)
                && c->c1.tuntap
                && options_hash_changed_or_zero(&c->c1.pulled_options_digest_save,
                                                &c->c2.pulled_options_digest))
            {
                /* if so, close tun, delete routes, then reinitialize tun and add routes */
                msg(M_INFO, "NOTE: Pulled options changed on restart, will need to close and reopen TUN/TAP device.");
                do_close_tun(c, true);
                management_sleep(1);
                c->c2.did_open_tun = do_open_tun(c);
                update_time();
            }
#endif
        }

        if (c->c2.did_open_tun)
        {
#if P2MP
            c->c1.pulled_options_digest_save = c->c2.pulled_options_digest;
#endif

            /* if --route-delay was specified, start timer */
            if ((route_order() == ROUTE_AFTER_TUN) && c->options.route_delay_defined)
            {
                event_timeout_init(&c->c2.route_wakeup, c->options.route_delay, now);
                event_timeout_init(&c->c2.route_wakeup_expire, c->options.route_delay + c->options.route_delay_window, now);
                if (c->c1.tuntap)
                {
                    tun_standby_init(c->c1.tuntap);
                }
            }
            else
            {
                initialization_sequence_completed(c, 0); /* client/p2p --route-delay undefined */
            }
        }
        else if (c->options.mode == MODE_POINT_TO_POINT)
        {
            initialization_sequence_completed(c, 0); /* client/p2p restart with --persist-tun */
        }

        c->c2.do_up_ran = true;
    }
    return true;
}

/*
 * These are the option categories which will be accepted by pull.
 */
unsigned int
pull_permission_mask(const struct context *c)
{
    unsigned int flags =
        OPT_P_UP
        | OPT_P_ROUTE_EXTRAS
        | OPT_P_SOCKBUF
        | OPT_P_SOCKFLAGS
        | OPT_P_SETENV
        | OPT_P_SHAPER
        | OPT_P_TIMER
        | OPT_P_COMP
        | OPT_P_PERSIST
        | OPT_P_MESSAGES
        | OPT_P_EXPLICIT_NOTIFY
        | OPT_P_ECHO
        | OPT_P_PULL_MODE
        | OPT_P_PEER_ID;

    if (!c->options.route_nopull)
    {
        flags |= (OPT_P_ROUTE | OPT_P_IPWIN32);
    }

#ifdef ENABLE_CRYPTO
    if (c->options.ncp_enabled)
    {
        flags |= OPT_P_NCP;
    }
#endif

    return flags;
}

/*
 * Handle non-tun-related pulled options.
 */
bool
do_deferred_options(struct context *c, const unsigned int found)
{
    if (found & OPT_P_MESSAGES)
    {
        init_verb_mute(c, IVM_LEVEL_1|IVM_LEVEL_2);
        msg(D_PUSH, "OPTIONS IMPORT: --verb and/or --mute level changed");
    }
    if (found & OPT_P_TIMER)
    {
        do_init_timers(c, true);
        msg(D_PUSH, "OPTIONS IMPORT: timers and/or timeouts modified");
    }

#ifdef ENABLE_OCC
    if (found & OPT_P_EXPLICIT_NOTIFY)
    {
        if (!proto_is_udp(c->options.ce.proto) && c->options.ce.explicit_exit_notification)
        {
            msg(D_PUSH, "OPTIONS IMPORT: --explicit-exit-notify can only be used with --proto udp");
            c->options.ce.explicit_exit_notification = 0;
        }
        else
        {
            msg(D_PUSH, "OPTIONS IMPORT: explicit notify parm(s) modified");
        }
    }
#endif

#ifdef USE_COMP
    if (found & OPT_P_COMP)
    {
        msg(D_PUSH, "OPTIONS IMPORT: compression parms modified");
        comp_uninit(c->c2.comp_context);
        c->c2.comp_context = comp_init(&c->options.comp);
    }
#endif

    if (found & OPT_P_SHAPER)
    {
        msg(D_PUSH, "OPTIONS IMPORT: traffic shaper enabled");
        do_init_traffic_shaper(c);
    }

    if (found & OPT_P_SOCKBUF)
    {
        msg(D_PUSH, "OPTIONS IMPORT: --sndbuf/--rcvbuf options modified");
        link_socket_update_buffer_sizes(c->c2.link_socket, c->options.rcvbuf, c->options.sndbuf);
    }

    if (found & OPT_P_SOCKFLAGS)
    {
        msg(D_PUSH, "OPTIONS IMPORT: --socket-flags option modified");
        link_socket_update_flags(c->c2.link_socket, c->options.sockflags);
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
    if (found & OPT_P_IPWIN32)
    {
        msg(D_PUSH, "OPTIONS IMPORT: --ip-win32 and/or --dhcp-option options modified");
    }
    if (found & OPT_P_SETENV)
    {
        msg(D_PUSH, "OPTIONS IMPORT: environment modified");
    }

#ifdef ENABLE_CRYPTO
    if (found & OPT_P_PEER_ID)
    {
        msg(D_PUSH, "OPTIONS IMPORT: peer-id set");
        c->c2.tls_multi->use_peer_id = true;
        c->c2.tls_multi->peer_id = c->options.peer_id;
        frame_add_to_extra_frame(&c->c2.frame, +3);     /* peer-id overhead */
        if (!c->options.ce.link_mtu_defined)
        {
            frame_add_to_link_mtu(&c->c2.frame, +3);
            msg(D_PUSH, "OPTIONS IMPORT: adjusting link_mtu to %d",
                EXPANDED_SIZE(&c->c2.frame));
        }
        else
        {
            msg(M_WARN, "OPTIONS IMPORT: WARNING: peer-id set, but link-mtu"
                " fixed by config - reducing tun-mtu to %d, expect"
                " MTU problems", TUN_MTU_SIZE(&c->c2.frame) );
        }
    }

    /* process (potentially pushed) crypto options */
    if (c->options.pull)
    {
        struct tls_session *session = &c->c2.tls_multi->session[TM_ACTIVE];
        if (found & OPT_P_NCP)
        {
            msg(D_PUSH, "OPTIONS IMPORT: data channel crypto options modified");
        }
        else if (c->options.ncp_enabled)
        {
            tls_poor_mans_ncp(&c->options, c->c2.tls_multi->remote_ciphername);
        }
        /* Do not regenerate keys if server sends an extra push reply */
        if (!session->key[KS_PRIMARY].crypto_options.key_ctx_bi.initialized
            && !tls_session_update_crypto_params(session, &c->options, &c->c2.frame))
        {
            msg(D_TLS_ERRORS, "OPTIONS ERROR: failed to import crypto options");
            return false;
        }
    }
#endif /* ifdef ENABLE_CRYPTO */
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

    switch (c->options.ce.proto)
    {
        case PROTO_TCP_SERVER:
            sec = 1;
            break;

        case PROTO_UDP:
        case PROTO_TCP_CLIENT:
            sec = c->options.ce.connect_retry_seconds;
            break;
    }

#ifdef ENABLE_DEBUG
    if (GREMLIN_CONNECTION_FLOOD_LEVEL(c->options.gremlin))
    {
        sec = 0;
    }
#endif

#if P2MP
    if (auth_retry_get() == AR_NOINTERACT)
    {
        sec = 10;
    }
#endif

    /* Slow down reconnection after 5 retries per remote -- for tcp only in client mode */
    if (c->options.ce.proto != PROTO_TCP_SERVER)
    {
        backoff = (c->options.unsuccessful_attempts / c->options.connection_list->len) - 4;
        if (backoff > 0)
        {
            /* sec is less than 2^16; we can left shift it by up to 15 bits without overflow */
            sec = max_int(sec, 1) << min_int(backoff, 15);
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

    /* do managment hold on context restart, i.e. second, third, fourth, etc. initialization */
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

    /*
     * Set adjustment factor for buffer alignment when no
     * cipher is used.
     */
    if (!CIPHER_ENABLED(c))
    {
        frame_align_to_extra_frame(&c->c2.frame);
        frame_or_align_flags(&c->c2.frame,
                             FRAME_HEADROOM_MARKER_FRAGMENT
                             |FRAME_HEADROOM_MARKER_READ_LINK
                             |FRAME_HEADROOM_MARKER_READ_STREAM);
    }

    frame_add_to_extra_buffer(&c->c2.frame, PAYLOAD_ALIGN);
    frame_finalize(&c->c2.frame,
                   o->ce.link_mtu_defined,
                   o->ce.link_mtu,
                   o->ce.tun_mtu_defined,
                   o->ce.tun_mtu);
}

/*
 * Free a key schedule, including OpenSSL components.
 */
static void
key_schedule_free(struct key_schedule *ks, bool free_ssl_ctx)
{
#ifdef ENABLE_CRYPTO
    free_key_ctx_bi(&ks->static_key);
    if (tls_ctx_initialised(&ks->ssl_ctx) && free_ssl_ctx)
    {
        tls_ctx_free(&ks->ssl_ctx);
        free_key_ctx_bi(&ks->tls_wrap_key);
    }
#endif /* ENABLE_CRYPTO */
    CLEAR(*ks);
}

#ifdef ENABLE_CRYPTO

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
    if (options->replay)
    {
        packet_id_init(&c->c2.crypto_options.packet_id,
                       options->replay_window,
                       options->replay_time,
                       "STATIC", 0);
        c->c2.crypto_options.pid_persist = &c->c1.pid_persist;
        c->c2.crypto_options.flags |= CO_PACKET_ID_LONG_FORM;
        packet_id_persist_load_obj(&c->c1.pid_persist,
                                   &c->c2.crypto_options.packet_id);
    }

    if (!key_ctx_bi_defined(&c->c1.ks.static_key))
    {
        /* Get cipher & hash algorithms */
        init_key_type(&c->c1.ks.key_type, options->ciphername, options->authname,
                      options->keysize, options->test_crypto, true);

        /* Read cipher and hmac keys from shared secret file */
        crypto_read_openvpn_key(&c->c1.ks.key_type, &c->c1.ks.static_key,
                                options->shared_secret_file,
                                options->shared_secret_file_inline,
                                options->key_direction, "Static Key Encryption",
                                "secret");
    }
    else
    {
        msg(M_INFO, "Re-using pre-shared static key");
    }

    /* Get key schedule */
    c->c2.crypto_options.key_ctx_bi = c->c1.ks.static_key;

    /* Compute MTU parameters */
    crypto_adjust_frame_parameters(&c->c2.frame, &c->c1.ks.key_type,
                                   options->replay, true);

    /* Sanity check on sequence number, and cipher mode options */
    check_replay_consistency(&c->c1.ks.key_type, options->replay);
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
        init_ssl(options, &(c->c1.ks.ssl_ctx));
        if (!tls_ctx_initialised(&c->c1.ks.ssl_ctx))
        {
#if P2MP
            switch (auth_retry_get())
            {
                case AR_NONE:
                    msg(M_FATAL, "Error: private key password verification failed");
                    break;

                case AR_INTERACT:
                    ssl_purge_auth(false);

                case AR_NOINTERACT:
                    c->sig->signal_received = SIGUSR1; /* SOFT-SIGUSR1 -- Password failure error */
                    break;

                default:
                    ASSERT(0);
            }
            c->sig->signal_text = "private-key-password-failure";
            return;
#else  /* if P2MP */
            msg(M_FATAL, "Error: private key password verification failed");
#endif
        }

        /* Get cipher & hash algorithms */
        init_key_type(&c->c1.ks.key_type, options->ciphername, options->authname,
                      options->keysize, true, true);

        /* Initialize PRNG with config-specified digest */
        prng_init(options->prng_hash, options->prng_nonce_secret_len);

        /* TLS handshake authentication (--tls-auth) */
        if (options->tls_auth_file)
        {
            /* Initialize key_type for tls-auth with auth only */
            CLEAR(c->c1.ks.tls_auth_key_type);
            if (!streq(options->authname, "none"))
            {
                c->c1.ks.tls_auth_key_type.digest = md_kt_get(options->authname);
                c->c1.ks.tls_auth_key_type.hmac_length =
                    md_kt_size(c->c1.ks.tls_auth_key_type.digest);
            }
            else
            {
                msg(M_FATAL, "ERROR: tls-auth enabled, but no valid --auth "
                    "algorithm specified ('%s')", options->authname);
            }

            crypto_read_openvpn_key(&c->c1.ks.tls_auth_key_type,
                                    &c->c1.ks.tls_wrap_key, options->tls_auth_file,
                                    options->tls_auth_file_inline, options->key_direction,
                                    "Control Channel Authentication", "tls-auth");
        }

        /* TLS handshake encryption+authentication (--tls-crypt) */
        if (options->tls_crypt_file)
        {
            tls_crypt_init_key(&c->c1.ks.tls_wrap_key, options->tls_crypt_file,
                               options->tls_crypt_inline, options->tls_server);
        }

        c->c1.ciphername = options->ciphername;
        c->c1.authname = options->authname;
        c->c1.keysize = options->keysize;

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

        /* Restore pre-NCP cipher options */
        c->options.ciphername = c->c1.ciphername;
        c->options.authname = c->c1.authname;
        c->options.keysize = c->c1.keysize;
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

    /* Sanity check on sequence number, and cipher mode options */
    check_replay_consistency(&c->c1.ks.key_type, options->replay);

    /* In short form, unique datagram identifier is 32 bits, in long form 64 bits */
    packet_id_long_form = cipher_kt_mode_ofb_cfb(c->c1.ks.key_type.cipher);

    /* Compute MTU parameters (postpone if we push/pull options) */
    if (c->options.pull || c->options.mode == MODE_SERVER)
    {
        /* Account for worst-case crypto overhead before allocating buffers */
        frame_add_to_extra_frame(&c->c2.frame, crypto_max_overhead());
    }
    else
    {
        crypto_adjust_frame_parameters(&c->c2.frame, &c->c1.ks.key_type,
                                       options->replay, packet_id_long_form);
    }
    tls_adjust_frame_parameters(&c->c2.frame);

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
    to.key_method = options->key_method;
    to.replay = options->replay;
    to.replay_window = options->replay_window;
    to.replay_time = options->replay_time;
    to.tcp_mode = link_socket_proto_connection_oriented(options->ce.proto);
    to.config_ciphername = c->c1.ciphername;
    to.config_authname = c->c1.authname;
    to.ncp_enabled = options->ncp_enabled;
    to.transition_window = options->transition_window;
    to.handshake_window = options->handshake_window;
    to.packet_timeout = options->tls_timeout;
    to.renegotiate_bytes = options->renegotiate_bytes;
    to.renegotiate_packets = options->renegotiate_packets;
    to.renegotiate_seconds = options->renegotiate_seconds;
    to.single_session = options->single_session;
    to.mode = options->mode;
    to.pull = options->pull;
#ifdef ENABLE_PUSH_PEER_INFO
    if (options->push_peer_info)        /* all there is */
    {
        to.push_peer_info_detail = 2;
    }
    else if (options->pull)             /* pull clients send some details */
    {
        to.push_peer_info_detail = 1;
    }
    else                                /* default: no peer-info at all */
    {
        to.push_peer_info_detail = 0;
    }
#endif

    /* should we not xmit any packets until we get an initial
     * response from client? */
    if (to.server && options->ce.proto == PROTO_TCP_SERVER)
    {
        to.xmit_hold = true;
    }

#ifdef ENABLE_OCC
    to.disable_occ = !options->occ;
#endif

    to.verify_command = options->tls_verify;
    to.verify_export_cert = options->tls_export_cert;
    to.verify_x509_type = (options->verify_x509_type & 0xff);
    to.verify_x509_name = options->verify_x509_name;
    to.crl_file = options->crl_file;
    to.crl_file_inline = options->crl_file_inline;
    to.ssl_flags = options->ssl_flags;
    to.ns_cert_type = options->ns_cert_type;
    memmove(to.remote_cert_ku, options->remote_cert_ku, sizeof(to.remote_cert_ku));
    to.remote_cert_eku = options->remote_cert_eku;
    to.verify_hash = options->verify_hash;
    to.verify_hash_algo = options->verify_hash_algo;
#ifdef ENABLE_X509ALTUSERNAME
    to.x509_username_field = (char *) options->x509_username_field;
#else
    to.x509_username_field = X509_USERNAME_FIELD_DEFAULT;
#endif
    to.es = c->c2.es;

#ifdef ENABLE_DEBUG
    to.gremlin = c->options.gremlin;
#endif

    to.plugins = c->plugins;

#ifdef MANAGEMENT_DEF_AUTH
    to.mda_context = &c->c2.mda_context;
#endif

#if P2MP_SERVER
    to.auth_user_pass_verify_script = options->auth_user_pass_verify_script;
    to.auth_user_pass_verify_script_via_file = options->auth_user_pass_verify_script_via_file;
    to.tmp_dir = options->tmp_dir;
    if (options->ccd_exclusive)
    {
        to.client_config_dir_exclusive = options->client_config_dir;
    }
    to.auth_user_pass_file = options->auth_user_pass_file;
    to.auth_token_generate = options->auth_token_generate;
    to.auth_token_lifetime = options->auth_token_lifetime;
#endif

    to.x509_track = options->x509_track;

#if P2MP
#ifdef ENABLE_CLIENT_CR
    to.sci = &options->sc_info;
#endif
#endif

#ifdef USE_COMP
    to.comp_options = options->comp;
#endif

#if defined(ENABLE_CRYPTO_OPENSSL) && OPENSSL_VERSION_NUMBER >= 0x10001000
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
#endif

    /* TLS handshake authentication (--tls-auth) */
    if (options->tls_auth_file)
    {
        to.tls_wrap.mode = TLS_WRAP_AUTH;
        to.tls_wrap.opt.key_ctx_bi = c->c1.ks.tls_wrap_key;
        to.tls_wrap.opt.pid_persist = &c->c1.pid_persist;
        to.tls_wrap.opt.flags |= CO_PACKET_ID_LONG_FORM;
        crypto_adjust_frame_parameters(&to.frame, &c->c1.ks.tls_auth_key_type,
                                       true, true);
    }

    /* TLS handshake encryption (--tls-crypt) */
    if (options->tls_crypt_file)
    {
        to.tls_wrap.mode = TLS_WRAP_CRYPT;
        to.tls_wrap.opt.key_ctx_bi = c->c1.ks.tls_wrap_key;
        to.tls_wrap.opt.pid_persist = &c->c1.pid_persist;
        to.tls_wrap.opt.flags |= CO_PACKET_ID_LONG_FORM;
        tls_crypt_adjust_frame_parameters(&to.frame);
    }

    /* If we are running over TCP, allow for
     * length prefix */
    socket_adjust_frame_parameters(&to.frame, options->ce.proto);

    /*
     * Initialize OpenVPN's master TLS-mode object.
     */
    if (flags & CF_INIT_TLS_MULTI)
    {
        c->c2.tls_multi = tls_multi_init(&to);
    }

    if (flags & CF_INIT_TLS_AUTH_STANDALONE)
    {
        c->c2.tls_auth_standalone = tls_auth_standalone_init(&to, &c->c2.gc);
    }
}

static void
do_init_finalize_tls_frame(struct context *c)
{
    if (c->c2.tls_multi)
    {
        tls_multi_init_finalize(c->c2.tls_multi, &c->c2.frame);
        ASSERT(EXPANDED_SIZE(&c->c2.tls_multi->opt.frame) <=
               EXPANDED_SIZE(&c->c2.frame));
        frame_print(&c->c2.tls_multi->opt.frame, D_MTU_INFO,
                    "Control Channel MTU parms");
    }
    if (c->c2.tls_auth_standalone)
    {
        tls_auth_standalone_finalize(c->c2.tls_auth_standalone, &c->c2.frame);
        frame_print(&c->c2.tls_auth_standalone->frame, D_MTU_INFO,
                    "TLS-Auth MTU parms");
    }
}

/*
 * No encryption or authentication.
 */
static void
do_init_crypto_none(const struct context *c)
{
    ASSERT(!c->options.test_crypto);
    msg(M_WARN,
        "******* WARNING *******: All encryption and authentication features "
        "disabled -- All data will be tunnelled as clear text and will not be "
        "protected against man-in-the-middle changes. "
        "PLEASE DO RECONSIDER THIS CONFIGURATION!");
}
#endif /* ifdef ENABLE_CRYPTO */

static void
do_init_crypto(struct context *c, const unsigned int flags)
{
#ifdef ENABLE_CRYPTO
    if (c->options.shared_secret_file)
    {
        do_init_crypto_static(c, flags);
    }
    else if (c->options.tls_server || c->options.tls_client)
    {
        do_init_crypto_tls(c, flags);
    }
    else                        /* no encryption or authentication. */
    {
        do_init_crypto_none(c);
    }
#else /* ENABLE_CRYPTO */
    msg(M_WARN,
        "******* WARNING *******: " PACKAGE_NAME
        " built without crypto library -- encryption and authentication features disabled -- all data will be tunnelled as cleartext");
#endif /* ENABLE_CRYPTO */
}

static void
do_init_frame(struct context *c)
{
#ifdef USE_COMP
    /*
     * modify frame parameters if compression is enabled
     */
    if (comp_enabled(&c->options.comp))
    {
        comp_add_to_extra_frame(&c->c2.frame);

#if !defined(ENABLE_LZ4)
        /*
         * Compression usage affects buffer alignment when non-swapped algs
         * such as LZO is used.
         * Newer algs like LZ4 and comp-stub with COMP_F_SWAP don't need
         * any special alignment because of the control-byte swap approach.
         * LZO alignment (on the other hand) is problematic because
         * the presence of the control byte means that either the output of
         * decryption must be written to an unaligned buffer, or the input
         * to compression (or packet dispatch if packet is uncompressed)
         * must be read from an unaligned buffer.
         * This code tries to align the input to compression (or packet
         * dispatch if packet is uncompressed) at the cost of requiring
         * decryption output to be written to an unaligned buffer, so
         * it's more of a tradeoff than an optimal solution and we don't
         * include it when we are doing a modern build with LZ4.
         * Strictly speaking, on the server it would be better to execute
         * this code for every connection after we decide the compression
         * method, but currently the frame code doesn't appear to be
         * flexible enough for this, since the frame is already established
         * before it is known which compression options will be pushed.
         */
        if (comp_unswapped_prefix(&c->options.comp) && CIPHER_ENABLED(c))
        {
            frame_add_to_align_adjust(&c->c2.frame, COMP_PREFIX_LEN);
            frame_or_align_flags(&c->c2.frame,
                                 FRAME_HEADROOM_MARKER_FRAGMENT
                                 |FRAME_HEADROOM_MARKER_DECRYPT);
        }
#endif

#ifdef ENABLE_FRAGMENT
        comp_add_to_extra_frame(&c->c2.frame_fragment_omit); /* omit compression frame delta from final frame_fragment */
#endif
    }
#endif /* USE_COMP */

    /*
     * Adjust frame size for UDP Socks support.
     */
    if (c->options.ce.socks_proxy_server)
    {
        socks_adjust_frame_parameters(&c->c2.frame, c->options.ce.proto);
    }

    /*
     * Adjust frame size based on the --tun-mtu-extra parameter.
     */
    if (c->options.ce.tun_mtu_extra_defined)
    {
        tun_adjust_frame_parameters(&c->c2.frame, c->options.ce.tun_mtu_extra);
    }

    /*
     * Adjust frame size based on link socket parameters.
     * (Since TCP is a stream protocol, we need to insert
     * a packet length uint16_t in the buffer.)
     */
    socket_adjust_frame_parameters(&c->c2.frame, c->options.ce.proto);

    /*
     * Fill in the blanks in the frame parameters structure,
     * make sure values are rational, etc.
     */
    frame_finalize_options(c, NULL);

#ifdef USE_COMP
    /*
     * Modify frame parameters if compression is compiled in.
     * Should be called after frame_finalize_options.
     */
    comp_add_to_extra_buffer(&c->c2.frame);
#ifdef ENABLE_FRAGMENT
    comp_add_to_extra_buffer(&c->c2.frame_fragment_omit); /* omit compression frame delta from final frame_fragment */
#endif
#endif /* USE_COMP */

    /* packets with peer-id (P_DATA_V2) need 3 extra bytes in frame (on client)
     * and need link_mtu+3 bytes on socket reception (on server).
     *
     * accomodate receive path in f->extra_link, which has the side effect of
     * also increasing send buffers (BUF_SIZE() macro), which need to be
     * allocated big enough before receiving peer-id option from server.
     *
     * f->extra_frame is adjusted when peer-id option is push-received
     */
    frame_add_to_extra_link(&c->c2.frame, 3);

#ifdef ENABLE_FRAGMENT
    /*
     * Set frame parameter for fragment code.  This is necessary because
     * the fragmentation code deals with payloads which have already been
     * passed through the compression code.
     */
    c->c2.frame_fragment = c->c2.frame;
    frame_subtract_extra(&c->c2.frame_fragment, &c->c2.frame_fragment_omit);
#endif

#if defined(ENABLE_FRAGMENT) && defined(ENABLE_OCC)
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
    if ((c->options.ce.mssfix || c->options.ce.fragment)
        && TUN_MTU_SIZE(&c->c2.frame_fragment) != ETHERNET_MTU)
    {
        msg(M_WARN,
            "WARNING: normally if you use --mssfix and/or --fragment, you should also set --tun-mtu %d (currently it is %d)",
            ETHERNET_MTU, TUN_MTU_SIZE(&c->c2.frame_fragment));
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
            msg(M_WARN, "WARNING: you are using user/group/chroot/setcon without persist-tun -- this may cause restarts to fail");
        }
        if (!o->persist_key
#ifdef ENABLE_PKCS11
            && !o->pkcs11_id
#endif
            )
        {
            msg(M_WARN, "WARNING: you are using user/group/chroot/setcon without persist-key -- this may cause restarts to fail");
        }
    }

    if (o->chroot_dir && !(o->username && o->groupname))
    {
        msg(M_WARN, "WARNING: you are using chroot without specifying user and group -- this may cause the chroot jail to be insecure");
    }

#if P2MP
    if (o->pull && o->ifconfig_local && c->first_time)
    {
        msg(M_WARN, "WARNING: using --pull/--client and --ifconfig together is probably not what you want");
    }

#if P2MP_SERVER
    if (o->server_bridge_defined | o->server_bridge_proxy_dhcp)
    {
        msg(M_WARN, "NOTE: when bridging your LAN adapter with the TAP adapter, note that the new bridge adapter will often take on its own IP address that is different from what the LAN adapter was previously set to");
    }

    if (o->mode == MODE_SERVER)
    {
        if (o->duplicate_cn && o->client_config_dir)
        {
            msg(M_WARN, "WARNING: using --duplicate-cn and --client-config-dir together is probably not what you want");
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
#endif /* if P2MP_SERVER */
#endif /* if P2MP */

#ifdef ENABLE_CRYPTO
    if (!o->replay)
    {
        msg(M_WARN, "WARNING: You have disabled Replay Protection (--no-replay) which may make " PACKAGE_NAME " less secure");
    }

    if (o->tls_server)
    {
        warn_on_use_of_common_subnets();
    }
    if (o->tls_client
        && !o->tls_verify
        && o->verify_x509_type == VERIFY_X509_NONE
        && !(o->ns_cert_type & NS_CERT_CHECK_SERVER)
        && !o->remote_cert_eku)
    {
        msg(M_WARN, "WARNING: No server certificate verification method has been enabled.  See http://openvpn.net/howto.html#mitm for more info.");
    }
    if (o->ns_cert_type)
    {
        msg(M_WARN, "WARNING: --ns-cert-type is DEPRECATED.  Use --remote-cert-tls instead.");
    }
#endif /* ifdef ENABLE_CRYPTO */

    /* If a script is used, print appropiate warnings */
    if (o->user_script_used)
    {
        if (script_security >= SSEC_SCRIPTS)
        {
            msg(M_WARN, "NOTE: the current --script-security setting may allow this configuration to call user-defined scripts");
        }
        else if (script_security >= SSEC_PW_ENV)
        {
            msg(M_WARN, "WARNING: the current --script-security setting may allow passwords to be passed to scripts via environmental variables");
        }
        else
        {
            msg(M_WARN, "NOTE: starting with " PACKAGE_NAME " 2.1, '--script-security 2' or higher is required to call user-defined scripts or executables");
        }
    }
}

static void
do_init_frame_tls(struct context *c)
{
#ifdef ENABLE_CRYPTO
    do_init_finalize_tls_frame(c);
#endif
}

struct context_buffers *
init_context_buffers(const struct frame *frame)
{
    struct context_buffers *b;

    ALLOC_OBJ_CLEAR(b, struct context_buffers);

    b->read_link_buf = alloc_buf(BUF_SIZE(frame));
    b->read_tun_buf = alloc_buf(BUF_SIZE(frame));

    b->aux_buf = alloc_buf(BUF_SIZE(frame));

#ifdef ENABLE_CRYPTO
    b->encrypt_buf = alloc_buf(BUF_SIZE(frame));
    b->decrypt_buf = alloc_buf(BUF_SIZE(frame));
#endif

#ifdef USE_COMP
    b->compress_buf = alloc_buf(BUF_SIZE(frame));
    b->decompress_buf = alloc_buf(BUF_SIZE(frame));
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

#ifdef USE_COMP
        free_buf(&b->compress_buf);
        free_buf(&b->decompress_buf);
#endif

#ifdef ENABLE_CRYPTO
        free_buf(&b->encrypt_buf);
        free_buf(&b->decrypt_buf);
#endif

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
    frame_set_mtu_dynamic(&c->c2.frame_fragment,
                          c->options.ce.fragment, SET_MTU_UPPER_BOUND);
    fragment_frame_init(c->c2.fragment, &c->c2.frame_fragment);
}
#endif

/*
 * Allocate our socket object.
 */
static void
do_link_socket_new(struct context *c)
{
    ASSERT(!c->c2.link_socket);
    c->c2.link_socket = link_socket_new();
    c->c2.link_socket_owned = true;
}

/*
 * bind the TCP/UDP socket
 */
static void
do_init_socket_1(struct context *c, const int mode)
{
    unsigned int sockflags = c->options.sockflags;

#if PORT_SHARE
    if (c->options.port_share_host && c->options.port_share_port)
    {
        sockflags |= SF_PORT_SHARE;
    }
#endif

    link_socket_init_phase1(c->c2.link_socket,
                            c->options.ce.local,
                            c->options.ce.local_port,
                            c->options.ce.remote,
                            c->options.ce.remote_port,
                            c->c1.dns_cache,
                            c->options.ce.proto,
                            c->options.ce.af,
                            c->options.ce.bind_ipv6_only,
                            mode,
                            c->c2.accept_from,
                            c->c1.http_proxy,
                            c->c1.socks_proxy,
#ifdef ENABLE_DEBUG
                            c->options.gremlin,
#endif
                            c->options.ce.bind_local,
                            c->options.ce.remote_float,
                            c->options.inetd,
                            &c->c1.link_socket_addr,
                            c->options.ipchange,
                            c->plugins,
                            c->options.resolve_retry_seconds,
                            c->options.ce.mtu_discover_type,
                            c->options.rcvbuf,
                            c->options.sndbuf,
                            c->options.mark,
                            &c->c2.server_poll_interval,
                            sockflags);
}

/*
 * finalize the TCP/UDP socket
 */
static void
do_init_socket_2(struct context *c)
{
    link_socket_init_phase2(c->c2.link_socket, &c->c2.frame,
                            c->sig);
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
        frame_print(&c->c2.frame_fragment, D_MTU_INFO,
                    "Fragmentation MTU parms");
    }
#endif
}

#ifdef ENABLE_OCC
/*
 * Get local and remote options compatibility strings.
 */
static void
do_compute_occ_strings(struct context *c)
{
    struct gc_arena gc = gc_new();

    c->c2.options_string_local =
        options_string(&c->options, &c->c2.frame, c->c1.tuntap, false, &gc);
    c->c2.options_string_remote =
        options_string(&c->options, &c->c2.frame, c->c1.tuntap, true, &gc);

    msg(D_SHOW_OCC, "Local Options String (VER=%s): '%s'",
        options_string_version(c->c2.options_string_local, &gc),
        c->c2.options_string_local);
    msg(D_SHOW_OCC, "Expected Remote Options String (VER=%s): '%s'",
        options_string_version(c->c2.options_string_remote, &gc),
        c->c2.options_string_remote);

#ifdef ENABLE_CRYPTO
    if (c->c2.tls_multi)
    {
        tls_multi_init_set_options(c->c2.tls_multi,
                                   c->c2.options_string_local,
                                   c->c2.options_string_remote);
    }
#endif

    gc_free(&gc);
}
#endif /* ifdef ENABLE_OCC */

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

        /* get user and/or group that we want to setuid/setgid to */
        c0->uid_gid_specified =
            platform_group_get(c->options.groupname, &c0->platform_state_group)
            |platform_user_get(c->options.username, &c0->platform_state_user);

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
 * If xinetd/inetd mode, don't allow restart.
 */
static void
do_close_check_if_restart_permitted(struct context *c)
{
    if (c->options.inetd
        && (c->sig->signal_received == SIGHUP
            || c->sig->signal_received == SIGUSR1))
    {
        c->sig->signal_received = SIGTERM;
        msg(M_INFO,
            PACKAGE_NAME
            " started by inetd/xinetd cannot restart... Exiting.");
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
#ifdef ENABLE_CRYPTO
    if (c->c2.tls_multi)
    {
        tls_multi_free(c->c2.tls_multi, true);
        c->c2.tls_multi = NULL;
    }

#ifdef ENABLE_OCC
    /* free options compatibility strings */
    if (c->c2.options_string_local)
    {
        free(c->c2.options_string_local);
    }
    if (c->c2.options_string_remote)
    {
        free(c->c2.options_string_remote);
    }
    c->c2.options_string_local = c->c2.options_string_remote = NULL;
#endif
#endif
}

/*
 * Free key schedules
 */
static void
do_close_free_key_schedule(struct context *c, bool free_ssl_ctx)
{
    if (!(c->sig->signal_received == SIGUSR1 && c->options.persist_key))
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
    if (c->c2.link_socket && c->c2.link_socket_owned)
    {
        link_socket_close(c->c2.link_socket);
        c->c2.link_socket = NULL;
    }


    /* Preserve the resolved list of remote if the user request to or if we want
     * reconnect to the same host again or there are still addresses that need
     * to be tried */
    if (!(c->sig->signal_received == SIGUSR1
          && ( (c->options.persist_remote_ip)
               ||
               ( c->sig->source != SIG_SOURCE_HARD
                 && ((c->c1.link_socket_addr.current_remote && c->c1.link_socket_addr.current_remote->ai_next)
                     || c->options.no_advance))
               )))
    {
        clear_remote_addrlist(&c->c1.link_socket_addr, !c->options.resolve_in_advance);
    }

    /* Clear the remote actual address when persist_remote_ip is not in use */
    if (!(c->sig->signal_received == SIGUSR1 && c->options.persist_remote_ip))
    {
        CLEAR(c->c1.link_socket_addr.actual);
    }

    if (!(c->sig->signal_received == SIGUSR1 && c->options.persist_local_ip))
    {
        if (c->c1.link_socket_addr.bind_local && !c->options.resolve_in_advance)
        {
            platform_freeaddrinfo(c->c1.link_socket_addr.bind_local);
        }

        c->c1.link_socket_addr.bind_local = NULL;
    }
}

/*
 * Close packet-id persistance file
 */
static void
do_close_packet_id(struct context *c)
{
#ifdef ENABLE_CRYPTO
    packet_id_free(&c->c2.crypto_options.packet_id);
    packet_id_persist_save(&c->c1.pid_persist);
    if (!(c->sig->signal_received == SIGUSR1))
    {
        packet_id_persist_close(&c->c1.pid_persist);
    }
#endif
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
do_event_set_init(struct context *c,
                  bool need_us_timeout)
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
        c->c1.status_output = status_open(c->options.status_file,
                                          c->options.status_file_update_freq,
                                          -1,
                                          NULL,
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
 * Handle ifconfig-pool persistance object.
 */
static void
do_open_ifconfig_pool_persist(struct context *c)
{
#if P2MP_SERVER
    if (!c->c1.ifconfig_pool_persist && c->options.ifconfig_pool_persist_filename)
    {
        c->c1.ifconfig_pool_persist = ifconfig_pool_persist_init(c->options.ifconfig_pool_persist_filename,
                                                                 c->options.ifconfig_pool_persist_refresh_freq);
        c->c1.ifconfig_pool_persist_owned = true;
    }
#endif
}

static void
do_close_ifconfig_pool_persist(struct context *c)
{
#if P2MP_SERVER
    if (!(c->sig->signal_received == SIGUSR1))
    {
        if (c->c1.ifconfig_pool_persist && c->c1.ifconfig_pool_persist_owned)
        {
            ifconfig_pool_persist_close(c->c1.ifconfig_pool_persist);
            c->c1.ifconfig_pool_persist = NULL;
            c->c1.ifconfig_pool_persist_owned = false;
        }
    }
#endif
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
        if (!proto_is_udp(c->options.ce.proto))
        {
            msg(M_INFO, "NOTE: --fast-io is disabled since we are not using UDP");
        }
        else
        {
#ifdef ENABLE_FEATURE_SHAPER
            if (c->options.shaper)
            {
                msg(M_INFO, "NOTE: --fast-io is disabled since we are using --shaper");
            }
            else
#endif
            {
                c->c2.fast_io = true;
            }
        }
#endif
    }
}

static void
do_signal_on_tls_errors(struct context *c)
{
#ifdef ENABLE_CRYPTO
    if (c->options.tls_exit)
    {
        c->c2.tls_exit_signal = SIGTERM;
    }
    else
    {
        c->c2.tls_exit_signal = SIGUSR1;
    }
#endif
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
                        options_string_import(&c->options,
                                              config.list[i]->value,
                                              D_IMPORT_ERRORS|M_OPTERR,
                                              OPT_P_DEFAULT & ~OPT_P_PLUGIN,
                                              &option_types_found,
                                              c->es);
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
    struct context *c = (struct context *) arg;
    print_status(c, so);
}

void
management_show_net_callback(void *arg, const int msglevel)
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
    struct context *c = (struct context *) arg;
    if (!c->c2.link_socket)
    {
        return -1;
    }
    if (c->c2.link_socket->sd == SOCKET_UNDEFINED)
    {
        return -1;
    }

    socketfd = c->c2.link_socket->sd;
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
#ifdef TARGET_ANDROID
        cb.network_change = management_callback_network_change;
#endif
        management_set_callback(management, &cb);
    }
#endif
}

#ifdef ENABLE_MANAGEMENT

void
init_management(struct context *c)
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
            if (management_open(management,
                                c->options.management_addr,
                                c->options.management_port,
                                c->options.management_user_pass,
                                c->options.management_client_user,
                                c->options.management_client_group,
                                c->options.management_log_history_cache,
                                c->options.management_echo_buffer_size,
                                c->options.management_state_buffer_size,
                                c->options.management_write_peer_info_file,
                                c->options.remap_sigusr1,
                                flags))
            {
                management_set_state(management,
                                     OPENVPN_STATE_CONNECTING,
                                     NULL,
                                     NULL,
                                     NULL,
                                     NULL,
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
    int link_socket_mode = LS_MODE_DEFAULT;

    /* init garbage collection level */
    gc_init(&c->c2.gc);

    /* inherit environmental variables */
    if (env)
    {
        do_inherit_env(c, env);
    }

    /* signals caught here will abort */
    c->sig->signal_received = 0;
    c->sig->signal_text = NULL;
    c->sig->source = SIG_SOURCE_SOFT;

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

    /* map in current connection entry */
    next_connection_entry(c);

    /* link_socket_mode allows CM_CHILD_TCP
     * instances to inherit acceptable fds
     * from a top-level parent */
    if (c->options.ce.proto == PROTO_TCP_SERVER)
    {
        if (c->mode == CM_TOP)
        {
            link_socket_mode = LS_MODE_TCP_LISTEN;
        }
        else if (c->mode == CM_CHILD_TCP)
        {
            link_socket_mode = LS_MODE_TCP_ACCEPT_FROM;
        }
    }

    /* should we disable paging? */
    if (c->first_time && options->mlock)
    {
        platform_mlockall(true);
    }

#if P2MP
    /* get passwords if undefined */
    if (auth_retry_get() == AR_INTERACT)
    {
        init_query_passwords(c);
    }
#endif

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

#ifdef ENABLE_OCC
    /* reset OCC state */
    if (c->mode == CM_P2P || child)
    {
        c->c2.occ_op = occ_reset_op();
    }
#endif

    /* our wait-for-i/o objects, different for posix vs. win32 */
    if (c->mode == CM_P2P)
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

    /* initialize dynamic MTU variable */
    frame_init_mssfix(&c->c2.frame, &c->options);

    /* bind the TCP/UDP socket */
    if (c->mode == CM_P2P || c->mode == CM_TOP || c->mode == CM_CHILD_TCP)
    {
        do_init_socket_1(c, link_socket_mode);
    }

    /* initialize tun/tap device object,
     * open tun/tap device, ifconfig, run up script, etc. */
    if (!(options->up_delay || PULL_DEFINED(options)) && (c->mode == CM_P2P || c->mode == CM_TOP))
    {
        c->c2.did_open_tun = do_open_tun(c);
    }

    c->c2.frame_initial = c->c2.frame;

    /* print MTU info */
    do_print_data_channel_mtu_parms(c);

#ifdef ENABLE_OCC
    /* get local and remote options compatibility strings */
    if (c->mode == CM_P2P || child)
    {
        do_compute_occ_strings(c);
    }
#endif

    /* initialize output speed limiter */
    if (c->mode == CM_P2P)
    {
        do_init_traffic_shaper(c);
    }

    /* do one-time inits, and possibily become a daemon here */
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
        do_init_socket_2(c);
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

#ifdef ENABLE_PF
    if (child)
    {
        pf_init_context(c);
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

    if (c->mode == CM_P2P
        || c->mode == CM_CHILD_TCP
        || c->mode == CM_CHILD_UDP
        || c->mode == CM_TOP)
    {
        /* if xinetd/inetd mode, don't allow restart */
        do_close_check_if_restart_permitted(c);

#ifdef USE_COMP
        if (c->c2.comp_context)
        {
            comp_uninit(c->c2.comp_context);
            c->c2.comp_context = NULL;
        }
#endif

        /* free buffers */
        do_close_free_buf(c);

        /* close TLS */
        do_close_tls(c);

        /* free key schedules */
        do_close_free_key_schedule(c, (c->mode == CM_P2P || c->mode == CM_TOP));

        /* close TCP/UDP connection */
        do_close_link_socket(c);

        /* close TUN/TAP device */
        do_close_tun(c, false);

#ifdef MANAGEMENT_DEF_AUTH
        if (management)
        {
            management_notify_client_close(management, &c->c2.mda_context, NULL);
        }
#endif

#ifdef ENABLE_PF
        pf_destroy_context(&c->c2.pf);
#endif

#ifdef ENABLE_PLUGIN
        /* call plugin close functions and unload */
        do_close_plugins(c);
#endif

        /* close packet-id persistance file */
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
inherit_context_child(struct context *dest,
                      const struct context *src)
{
    CLEAR(*dest);

    /* proto_is_dgram will ASSERT(0) if proto is invalid */
    dest->mode = proto_is_dgram(src->options.ce.proto) ? CM_CHILD_UDP : CM_CHILD_TCP;

    dest->gc = gc_new();

    ALLOC_OBJ_CLEAR_GC(dest->sig, struct signal_info, &dest->gc);

    /* c1 init */
    packet_id_persist_init(&dest->c1.pid_persist);

#ifdef ENABLE_CRYPTO
    dest->c1.ks.key_type = src->c1.ks.key_type;
    /* inherit SSL context */
    dest->c1.ks.ssl_ctx = src->c1.ks.ssl_ctx;
    dest->c1.ks.tls_wrap_key = src->c1.ks.tls_wrap_key;
    dest->c1.ks.tls_auth_key_type = src->c1.ks.tls_auth_key_type;
    /* inherit pre-NCP ciphers */
    dest->c1.ciphername = src->c1.ciphername;
    dest->c1.authname = src->c1.authname;
    dest->c1.keysize = src->c1.keysize;
#endif

    /* options */
    dest->options = src->options;
    options_detach(&dest->options);

    if (dest->mode == CM_CHILD_TCP)
    {
        /*
         * The CM_TOP context does the socket listen(),
         * and the CM_CHILD_TCP context does the accept().
         */
        dest->c2.accept_from = src->c2.link_socket;
    }

#ifdef ENABLE_PLUGIN
    /* inherit plugins */
    do_inherit_plugins(dest, src);
#endif

    /* context init */
    init_instance(dest, src->c2.es, CC_NO_CLOSE | CC_USR1_TO_HUP);
    if (IS_SIG(dest))
    {
        return;
    }

    /* inherit tun/tap interface object */
    dest->c1.tuntap = src->c1.tuntap;

    /* UDP inherits some extra things which TCP does not */
    if (dest->mode == CM_CHILD_UDP)
    {
        /* inherit buffers */
        dest->c2.buffers = src->c2.buffers;

        /* inherit parent link_socket and tuntap */
        dest->c2.link_socket = src->c2.link_socket;

        ALLOC_OBJ_GC(dest->c2.link_socket_info, struct link_socket_info, &dest->gc);
        *dest->c2.link_socket_info = src->c2.link_socket->info;

        /* locally override some link_socket_info fields */
        dest->c2.link_socket_info->lsa = &dest->c1.link_socket_addr;
        dest->c2.link_socket_info->connection_established = false;
    }
}

void
inherit_context_top(struct context *dest,
                    const struct context *src)
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

#ifdef ENABLE_CRYPTO
    dest->c2.tls_multi = NULL;
#endif

    /* detach c1 ownership */
    dest->c1.tuntap_owned = false;
    dest->c1.status_output_owned = false;
#if P2MP_SERVER
    dest->c1.ifconfig_pool_persist_owned = false;
#endif

    /* detach c2 ownership */
    dest->c2.event_set_owned = false;
    dest->c2.link_socket_owned = false;
    dest->c2.buffers_owned = false;
    dest->c2.es_owned = false;

    dest->c2.event_set = NULL;
    if (proto_is_dgram(src->options.ce.proto))
    {
        do_event_set_init(dest, false);
    }

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
        c->sig->signal_received = sig;
    }

    if (c->sig->signal_received == SIGUSR1)
    {
        if ((flags & CC_USR1_TO_HUP)
            || (c->sig->source == SIG_SOURCE_HARD && (flags & CC_HARD_USR1_TO_HUP)))
        {
            c->sig->signal_received = SIGHUP;
            c->sig->signal_text = "close_context usr1 to hup";
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

#ifdef ENABLE_CRYPTO

/*
 * Do a loopback test
 * on the crypto subsystem.
 */
static void *
test_crypto_thread(void *arg)
{
    struct context *c = (struct context *) arg;
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

#endif /* ENABLE_CRYPTO */

bool
do_test_crypto(const struct options *o)
{
#ifdef ENABLE_CRYPTO
    if (o->test_crypto)
    {
        struct context c;

        /* print version number */
        msg(M_INFO, "%s", title_string);

        context_clear(&c);
        c.options = *o;
        options_detach(&c.options);
        c.first_time = true;
        test_crypto_thread((void *) &c);
        return true;
    }
#endif
    return false;
}
