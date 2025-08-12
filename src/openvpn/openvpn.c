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

#include "init.h"
#include "forward.h"
#include "multi.h"
#include "win32.h"
#include "platform.h"
#include "string.h"

#include "memdbg.h"

#define P2P_CHECK_SIG() EVENT_LOOP_CHECK_SIGNAL(c, process_signal_p2p, c);

static bool
process_signal_p2p(struct context *c)
{
    remap_signal(c);
    return process_signal(c);
}


/**************************************************************************/
/**
 * Main event loop for OpenVPN in client mode, where only one VPN tunnel
 * is active.
 * @ingroup eventloop
 *
 * @param c - The context structure of the single active VPN tunnel.
 */
void *tunnel_point_to_point(void *a)
{
    struct thread_pointer *b = (struct thread_pointer *)a;
    struct context_pointer *p = b->p;
    struct context *c = (b->n == 1) ? p->c : b->c;
    struct context *d = (b->n == 1) ? b->c : p->c;

    context_clear_2(c);

    /* set point-to-point mode */
    c->mode = CM_P2P;
    /* initialize tunnel instance, avoid SIGHUP when config is stdin since
     * re-reading the config from stdin will not work */
    bool stdin_config = c->options.config && (strcmp(c->options.config, "stdin") == 0);
    init_instance_handle_signals(c, c->es, stdin_config ? 0 : CC_HARD_USR1_TO_HUP);
    if (IS_SIG(c))
    {
        return NULL;
    }

    if (b->i == 1) { p->z += 1; }
    else
    {
        while ((p->z != 1) || (!(d->c1.tuntap)) || (d->c1.tuntap->ff <= 1))
        {
            if (p->z == -1) { break; }
            sleep(1);
        }
        b->h += 1; p->h += 1;
    }

    msg(M_INFO, "TCPv4_CLIENT MTIO init [%d][%d] [%d][%d] [%d][%d]", b->h, p->n, b->i, b->n, p->h, p->z);

    /* main event loop */
    while (true)
    {
        if (p->z != 1) { break; }
        if (c->c1.tuntap && (c->c1.tuntap->ff <= 1))
        {
            socketpair(AF_UNIX, SOCK_DGRAM, 0, p->s[b->i-1]);
            socketpair(AF_UNIX, SOCK_DGRAM, 0, p->r[b->i-1]);
            c->c1.tuntap->ff = c->c1.tuntap->fd;
            c->c1.tuntap->fe = (b->i == 1) ? c->c1.tuntap->ff : d->c1.tuntap->ff;
            //c->c1.tuntap->fd = (b->i == 1) ? c->c1.tuntap->ff : d->c1.tuntap->ff;
            c->c1.tuntap->fd = p->s[b->i-1][0];
            c->c1.tuntap->fz = p->r[b->i-1][1];
            msg(M_INFO, "TCPv4_CLIENT MTIO fdno [%d][%d][%d][%d] {%d}", c->c1.tuntap->fd, c->c1.tuntap->fe, c->c1.tuntap->ff, c->c1.tuntap->fz, b->i);
        }

        perf_push(PERF_EVENT_LOOP);

        /* process timers, TLS, etc. */
        pre_select(c);
        P2P_CHECK_SIG();

        /* set up and do the I/O wait */
        io_wait(c, p2p_iow_flags(c));
        P2P_CHECK_SIG();

        /* timeout? */
        if (c->c2.event_set_status == ES_TIMEOUT)
        {
            perf_pop();
            continue;
        }

        /* process the I/O which triggered select */
        process_io(c, c->c2.link_sockets[0], b);
        P2P_CHECK_SIG();

        perf_pop();
    }

    msg(M_INFO, "TCPv4_CLIENT MTIO fins [%d][%d] [%d][%d] [%d][%d]", b->h, p->n, b->i, b->n, p->h, p->z);

    p->z = -1;

    if (c->c1.tuntap && (c->c1.tuntap->ff > 1))
    {
        close(p->s[b->i-1][0]);
        close(p->s[b->i-1][1]);
        close(p->r[b->i-1][0]);
        close(p->r[b->i-1][1]);
        c->c1.tuntap->fd = c->c1.tuntap->ff;
        c->c1.tuntap->ff = -1;
    }

    persist_client_stats(c);

    uninit_management_callback();

    /* tear down tunnel instance (unless --persist-tun) */
    close_instance(c);

    return NULL;
}

void *threaded_io_management(void *args)
{
    struct thread_pointer *a = (struct thread_pointer *)args;
    struct context_pointer *p = a->p;
    struct context *c, *d;
    int size = p->c->options.ce.tun_mtu;
    int maxt = p->n, maxf = 0;
    int indx = 0, leng = 0;
    int fdno, flag;
    uint8_t buff[MAX_THREADS*2];
    fd_set rfds;
    struct timeval timo;

    msg(M_INFO, "%s MTIO mgmt [%d]", (p->m) ? "TCPv4_SERVER" : "TCPv4_CLIENT", size);

    bzero(buff, maxt * sizeof(uint8_t));
    while (true)
    {
        if (p->z == -1) { break; }
        if ((p->z == 1) && (p->h == p->n))
        {
            indx = -1; maxf = 0;
            FD_ZERO(&rfds);
            for (int x = 0; x < maxt; ++x)
            {
                if (buff[x] != 1) { indx = x; break; }
                FD_SET(p->r[x][0], &rfds);
                if (p->r[x][0] > maxf) { maxf = p->r[x][0]; }
            }
            if (indx < 0)
            {
                select(maxf+1, &rfds, NULL, NULL, NULL);
                for (int x = 0; x < maxt; ++x)
                {
                    if (FD_ISSET(p->r[x][0], &rfds))
                    {
                        leng = read(p->r[x][0], &(buff[maxt+1]), 1);
                        buff[x] = 0;
                        indx = x;
                    }
                }
            }
            if (p->m) {
                c = &(p->m[indx]->top);
                d = &(p->m[0]->top);
            } else {
                c = a[indx].c;
                d = a[0].c;
            }
            if (d->c1.tuntap && (d->c1.tuntap->ff > 1) && c->c2.buffers)
            {
                flag = 0;
                fdno = d->c1.tuntap->ff;
                FD_ZERO(&rfds); FD_SET(fdno, &rfds);
                timo.tv_sec = 5; timo.tv_usec = 0;
                if (check_bulk_mode(c))
                {
                    for (int x = 0; x < TUN_BAT_MIN; ++x)
                    {
                        select(fdno+1, &rfds, NULL, NULL, &timo);
                        if ((p->z == 1) && FD_ISSET(fdno, &rfds))
                        {
                            c->c2.buffers->read_tun_bufs[x].offset = TUN_BAT_OFF;
                            leng = read(fdno, BPTR(&c->c2.buffers->read_tun_bufs[x]), size);
                            c->c2.buffers->read_tun_bufs[x].len = leng;
                            c->c2.bufs[x] = c->c2.buffers->read_tun_bufs[x];
                            c->c2.buf = c->c2.bufs[0];
                            c->c2.buffers->bulk_indx = x;
                            flag = 1;
                        }
                        else
                        {
                            break;
                        }
                        FD_ZERO(&rfds); FD_SET(fdno, &rfds);
                        timo.tv_sec = 0; timo.tv_usec = 0;
                    }
                }
                else
                {
                    select(fdno+1, &rfds, NULL, NULL, &timo);
                    if ((p->z == 1) && FD_ISSET(fdno, &rfds))
                    {
                        leng = read(fdno, BPTR(&c->c2.buffers->read_tun_buf), size);
                        c->c2.buffers->read_tun_buf.len = leng;
                        c->c2.buf = c->c2.buffers->read_tun_buf;
                        flag = 1;
                    }
                }
                if (flag > 0)
                {
                    leng = write(p->s[indx][1], buff, 1);
                    buff[indx] = 1;
                }
            }
            else
            {
                sleep(1);
            }
        }
        else
        {
            sleep(1);
        }
    }

    p->z = -1;

    return NULL;
}

void threaded_tunnel_point_to_point(struct context *c, struct context *d)
{
    int maxt = (c->options.ce.mtio_mode) ? MAX_THREADS : 1;
    struct context_pointer p;
    struct thread_pointer a[MAX_THREADS];
    pthread_t thrm, thrd[MAX_THREADS];
    pthread_mutex_t lock;

    bzero(&p, sizeof(struct context_pointer));
    p.c = c; p.i = 1; p.n = maxt; p.h = 1; p.z = 0;
    p.l = &(lock);
    bzero(p.l, sizeof(pthread_mutex_t));
    pthread_mutex_init(p.l, NULL);

    c->skip_bind = 0;
    a[0].p = &(p); a[0].c = c; a[0].i = 1; a[0].n = p.n; a[0].h = 0;
    bzero(&(thrd[0]), sizeof(pthread_t));
    pthread_create(&(thrd[0]), NULL, tunnel_point_to_point, &(a[0]));

    bzero(&(thrm), sizeof(pthread_t));
    pthread_create(&(thrm), NULL, threaded_io_management, &(a[0]));

    for (int x = 1; x < p.n; ++x)
    {
        d[x].skip_bind = -1;
        a[x].p = &(p); a[x].c = &(d[x]); a[x].i = (x + 1); a[x].n = p.n; a[x].h = 1;
        bzero(&(thrd[x]), sizeof(pthread_t));
        pthread_create(&(thrd[x]), NULL, tunnel_point_to_point, &(a[x]));
    }

    pthread_join(thrd[0], NULL);

    for (int x = 1; x < p.n; ++x)
    {
        pthread_join(thrd[x], NULL);
    }

    pthread_join(thrm, NULL);
}

#undef PROCESS_SIGNAL_P2P

void
init_early(struct context *c)
{
    net_ctx_init(c, &c->net_ctx);

    /* init verbosity and mute levels */
    init_verb_mute(c, IVM_LEVEL_1);

    /* Initialise OpenSSL provider, this needs to be initialised this
     * early since option post-processing and also openssl info
     * printing depends on it */
    for (int j = 1; j < MAX_PARMS && c->options.providers.names[j]; j++)
    {
        c->options.providers.providers[j] = crypto_load_provider(c->options.providers.names[j]);
    }
}

static void
uninit_early(struct context *c)
{
    for (int j = 1; j < MAX_PARMS && c->options.providers.providers[j]; j++)
    {
        crypto_unload_provider(c->options.providers.names[j], c->options.providers.providers[j]);
    }
    net_ctx_free(&c->net_ctx);
}


/**************************************************************************/
/**
 * OpenVPN's main init-run-cleanup loop.
 * @ingroup eventloop
 *
 * This function contains the two outer OpenVPN loops.  Its structure is
 * as follows:
 *  - Once-per-process initialization.
 *  - Outer loop, run at startup and then once per \c SIGHUP:
 *    - Level 1 initialization
 *    - Inner loop, run at startup and then once per \c SIGUSR1:
 *      - Call event loop function depending on client or server mode:
 *        - \c tunnel_point_to_point()
 *        - \c tunnel_server()
 *    - Level 1 cleanup
 *  - Once-per-process cleanup.
 *
 * @param argc - Commandline argument count.
 * @param argv - Commandline argument values.
 */
static int
openvpn_main(int argc, char *argv[])
{
    struct context c;
    struct context d[MAX_THREADS];
    char devs[MAX_THREADS][MAX_STRLENG];
    char fils[MAX_THREADS][MAX_STRLENG];

#if PEDANTIC
    fprintf(stderr, "Sorry, I was built with --enable-pedantic and I am incapable of doing any real work!\n");
    return 1;
#endif

#ifdef _WIN32
    SetConsoleOutputCP(CP_UTF8);
#endif

    CLEAR(c);

    /* signify first time for components which can
     * only be initialized once per program instantiation. */
    c.first_time = true;

    /* initialize program-wide statics */
    if (init_static())
    {
        /*
         * This loop is initially executed on startup and then
         * once per SIGHUP.
         */
        do
        {
            /* enter pre-initialization mode with regard to signal handling */
            pre_init_signal_catch();

            /* zero context struct but leave first_time member alone */
            context_clear_all_except_first_time(&c);

            /* static signal info object */
            c.sig = &siginfo_static;

            /* initialize garbage collector scoped to context object */
            gc_init(&c.gc);

            /* initialize environmental variable store */
            c.es = env_set_create(NULL);
#ifdef _WIN32
            set_win_sys_path_via_env(c.es);
#endif

#ifdef ENABLE_MANAGEMENT
            /* initialize management subsystem */
            init_management();
#endif

            /* initialize options to default state */
            init_options(&c.options, true);

            /* parse command line options, and read configuration file */
            parse_argv(&c.options, argc, argv, M_USAGE, OPT_P_DEFAULT, NULL, c.es);

#ifdef ENABLE_PLUGIN
            /* plugins may contribute options configuration */
            init_verb_mute(&c, IVM_LEVEL_1);
            init_plugins(&c);
            open_plugins(&c, true, OPENVPN_PLUGIN_INIT_PRE_CONFIG_PARSE);
#endif

            /* Early initialisation that need to happen before option
             * post processing and other early startup but after parsing */
            init_early(&c);

            /* set dev options */
            init_options_dev(&c.options);

            /* openssl print info? */
            if (print_openssl_info(&c.options))
            {
                break;
            }

            /* --genkey mode? */
            if (do_genkey(&c.options))
            {
                break;
            }

            /* tun/tap persist command? */
            if (do_persist_tuntap(&c.options, &c.net_ctx))
            {
                break;
            }

            /* sanity check on options */
            options_postprocess(&c.options, c.es);

            /* show all option settings */
            show_settings(&c.options);

            /* print version number */
            msg(M_INFO, "%s", title_string);
#ifdef _WIN32
            show_windows_version(M_INFO);
#endif
            show_library_versions(M_INFO);

            show_dco_version(M_INFO);

            /* misc stuff */
            pre_setup(&c.options);

            /* test crypto? */
            if (do_test_crypto(&c.options))
            {
                break;
            }

            /* Query passwords before becoming a daemon if we don't use the
             * management interface to get them. */
            if (!(c.options.management_flags & MF_QUERY_PASSWORDS))
            {
                init_query_passwords(&c);
            }

            /* become a daemon if --daemon */
            if (c.first_time)
            {
                c.did_we_daemonize = possibly_become_daemon(&c.options);
                write_pid_file(c.options.writepid, c.options.chroot_dir);
            }

#ifdef ENABLE_MANAGEMENT
            /* open management subsystem */
            if (!open_management(&c))
            {
                break;
            }
            /* query for passwords through management interface, if needed */
            if (c.options.management_flags & MF_QUERY_PASSWORDS)
            {
                init_query_passwords(&c);
            }
#endif

            /* set certain options as environmental variables */
            setenv_settings(c.es, &c.options);

            /* finish context init */
            context_init_1(&c);

            if (c.options.ce.mtio_mode)
            {
                for (int x = 0; x < MAX_THREADS; ++x)
                {
                    struct context *b = &(d[x]);

                    bcopy(&c, b, sizeof(struct context));
                    context_init_1(b);

                    if (c.options.dev)
                    {
                        bzero(devs[x], MAX_STRLENG * sizeof(char));
                        snprintf(devs[x], MAX_STRLENG-8, "%st%02d", c.options.dev, x);
                        b->options.dev = devs[x];
                    }

                    if (c.options.status_file)
                    {
                        bzero(fils[x], MAX_STRLENG * sizeof(char));
                        snprintf(fils[x], MAX_STRLENG-8, "%st%02d", c.options.status_file, x);
                        b->options.status_file = fils[x];
                    }

                    msg(M_INFO, "INFO MTIO init [%d] [%s][%s]", x, b->options.dev, b->options.status_file);
                }
            }

            do
            {
                /* run tunnel depending on mode */
                switch (c.options.mode)
                {
                    case MODE_POINT_TO_POINT:
                        threaded_tunnel_point_to_point(&c, d);
                        break;

                    case MODE_SERVER:
                        threaded_tunnel_server(&c, d);
                        break;

                    default:
                        ASSERT(0);
                }

                /* indicates first iteration -- has program-wide scope */
                c.first_time = false;

                /* any signals received? */
                if (IS_SIG(&c))
                {
                    print_signal(c.sig, NULL, M_INFO);
                }

                /* pass restart status to management subsystem */
                signal_restart_status(c.sig);

                if (c.options.ce.mtio_mode)
                {
                    for (int x = 0; x < MAX_THREADS; ++x)
                    {
                        d[x].first_time = false;
                        signal_restart_status(d[x].sig);
                    }
                }
            } while (signal_reset(c.sig, SIGUSR1) == SIGUSR1);

            env_set_destroy(c.es);
            uninit_options(&c.options);
            gc_reset(&c.gc);
            uninit_early(&c);
        } while (signal_reset(c.sig, SIGHUP) == SIGHUP);
    }

    context_gc_free(&c);

#ifdef ENABLE_MANAGEMENT
    /* close management interface */
    close_management();
#endif

    /* uninitialize program-wide statics */
    uninit_static();

    openvpn_exit(OPENVPN_EXIT_STATUS_GOOD); /* exit point */
    return 0;                               /* NOTREACHED */
}

#ifdef _WIN32
int
wmain(int argc, wchar_t *wargv[])
{
    char **argv;
    int ret;
    int i;

    if ((argv = calloc(argc + 1, sizeof(char *))) == NULL)
    {
        return 1;
    }

    for (i = 0; i < argc; i++)
    {
        int n = WideCharToMultiByte(CP_UTF8, 0, wargv[i], -1, NULL, 0, NULL, NULL);
        argv[i] = malloc(n);
        WideCharToMultiByte(CP_UTF8, 0, wargv[i], -1, argv[i], n, NULL, NULL);
    }

    ret = openvpn_main(argc, argv);

    for (i = 0; i < argc; i++)
    {
        free(argv[i]);
    }
    free(argv);

    return ret;
}
#else  /* ifdef _WIN32 */
int
main(int argc, char *argv[])
{
    return openvpn_main(argc, argv);
}
#endif /* ifdef _WIN32 */
