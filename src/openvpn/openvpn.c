/*
 *  OpenVPN -- An application to securely tunnel IP networks
 *             over a single TCP/UDP port, with support for SSL/TLS-based
 *             session authentication and key exchange,
 *             packet encryption, packet authentication, and
 *             packet compression.
 *
 *  Copyright (C) 2002-2021 OpenVPN Inc <sales@openvpn.net>
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

#include "init.h"
#include "forward.h"
#include "multi.h"
#include "win32.h"
#include "platform.h"

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
static void
tunnel_point_to_point(struct context *c)
{
    context_clear_2(c);

    /* set point-to-point mode */
    c->mode = CM_P2P;

    /* initialize tunnel instance */
    init_instance_handle_signals(c, c->es, CC_HARD_USR1_TO_HUP);
    if (IS_SIG(c))
    {
        return;
    }

    /* main event loop */
    while (true)
    {
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
        process_io(c);
        P2P_CHECK_SIG();

        perf_pop();
    }

    uninit_management_callback();

    /* tear down tunnel instance (unless --persist-tun) */
    close_instance(c);
}

#undef PROCESS_SIGNAL_P2P


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
static
int
openvpn_main(int argc, char *argv[])
{
    struct context c;

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
            CLEAR(siginfo_static);
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

            net_ctx_init(&c, &c.net_ctx);

            /* init verbosity and mute levels */
            init_verb_mute(&c, IVM_LEVEL_1);

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
            options_postprocess(&c.options);

            /* show all option settings */
            show_settings(&c.options);

            /* print version number */
            msg(M_INFO, "%s", title_string);
#ifdef _WIN32
            show_windows_version(M_INFO);
#endif
            show_library_versions(M_INFO);

            /* misc stuff */
            pre_setup(&c.options);

            /* test crypto? */
            if (do_test_crypto(&c.options))
            {
                break;
            }

            /* Query passwords before becoming a daemon if we don't use the
             * management interface to get them. */
#ifdef ENABLE_MANAGEMENT
            if (!(c.options.management_flags & MF_QUERY_PASSWORDS))
#endif
            init_query_passwords(&c);

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

            do
            {
                /* run tunnel depending on mode */
                switch (c.options.mode)
                {
                    case MODE_POINT_TO_POINT:
                        tunnel_point_to_point(&c);
                        break;

                    case MODE_SERVER:
                        tunnel_server(&c);
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
            }
            while (c.sig->signal_received == SIGUSR1);

            env_set_destroy(c.es);
            uninit_options(&c.options);
            gc_reset(&c.gc);
            net_ctx_free(&c.net_ctx);
        }
        while (c.sig->signal_received == SIGHUP);
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

    if ((argv = calloc(argc+1, sizeof(char *))) == NULL)
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
