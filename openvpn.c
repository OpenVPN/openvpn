/*
 *  OpenVPN -- An application to securely tunnel IP networks
 *             over a single TCP/UDP port, with support for SSL/TLS-based
 *             session authentication and key exchange,
 *             packet encryption, packet authentication, and
 *             packet compression.
 *
 *  Copyright (C) 2002-2010 OpenVPN Technologies, Inc. <sales@openvpn.net>
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
 *  You should have received a copy of the GNU General Public License
 *  along with this program (see the file COPYING included with this
 *  distribution); if not, write to the Free Software Foundation, Inc.,
 *  59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

#include "syshead.h"

#include "init.h"
#include "forward.h"
#include "multi.h"
#include "win32.h"

#include "memdbg.h"

#include "forward-inline.h"

#define P2P_CHECK_SIG() EVENT_LOOP_CHECK_SIGNAL (c, process_signal_p2p, c);

static bool
process_signal_p2p (struct context *c)
{
  remap_signal (c);
  return process_signal (c);
}

static void
tunnel_point_to_point (struct context *c)
{
  context_clear_2 (c);

  /* set point-to-point mode */
  c->mode = CM_P2P;

  /* initialize tunnel instance */
  init_instance_handle_signals (c, c->es, CC_HARD_USR1_TO_HUP);
  if (IS_SIG (c))
    return;

  /* main event loop */
  while (true)
    {
      perf_push (PERF_EVENT_LOOP);

      /* process timers, TLS, etc. */
      pre_select (c);
      P2P_CHECK_SIG();

      /* set up and do the I/O wait */
      io_wait (c, p2p_iow_flags (c));
      P2P_CHECK_SIG();

      /* timeout? */
      if (c->c2.event_set_status == ES_TIMEOUT)
	{
	  perf_pop ();
	  continue;
	}

      /* process the I/O which triggered select */
      process_io (c);
      P2P_CHECK_SIG();

      perf_pop ();
    }

  uninit_management_callback ();

  /* tear down tunnel instance (unless --persist-tun) */
  close_instance (c);
}

#undef PROCESS_SIGNAL_P2P

int
main (int argc, char *argv[])
{
  struct context c;

#if PEDANTIC
  fprintf (stderr, "Sorry, I was built with --enable-pedantic and I am incapable of doing any real work!\n");
  return 1;
#endif

  CLEAR (c);

  /* signify first time for components which can
     only be initialized once per program instantiation. */
  c.first_time = true;

  /* initialize program-wide statics */
  if (init_static ())
    {
      /*
       * This loop is initially executed on startup and then
       * once per SIGHUP.
       */
      do
	{
	  /* enter pre-initialization mode with regard to signal handling */
	  pre_init_signal_catch ();

	  /* zero context struct but leave first_time member alone */
	  context_clear_all_except_first_time (&c);

	  /* static signal info object */
	  CLEAR (siginfo_static);
	  c.sig = &siginfo_static;

	  /* initialize garbage collector scoped to context object */
	  gc_init (&c.gc);

	  /* initialize environmental variable store */
	  c.es = env_set_create (NULL);
#ifdef WIN32
	  env_set_add_win32 (c.es);
#endif

#ifdef ENABLE_MANAGEMENT
	  /* initialize management subsystem */
	  init_management (&c);
#endif

	  /* initialize options to default state */
	  init_options (&c.options, true);

	  /* parse command line options, and read configuration file */
	  parse_argv (&c.options, argc, argv, M_USAGE, OPT_P_DEFAULT, NULL, c.es);

#ifdef ENABLE_PLUGIN
	  /* plugins may contribute options configuration */
	  init_verb_mute (&c, IVM_LEVEL_1);
	  init_plugins (&c);
	  open_plugins (&c, true, OPENVPN_PLUGIN_INIT_PRE_CONFIG_PARSE);
#endif

	  /* init verbosity and mute levels */
	  init_verb_mute (&c, IVM_LEVEL_1);

	  /* set dev options */
	  init_options_dev (&c.options);

	  /* openssl print info? */
	  if (print_openssl_info (&c.options))
	    break;

	  /* --genkey mode? */
	  if (do_genkey (&c.options))
	    break;

	  /* tun/tap persist command? */
	  if (do_persist_tuntap (&c.options))
	    break;

	  /* sanity check on options */
	  options_postprocess (&c.options);

	  /* show all option settings */
	  show_settings (&c.options);

	  /* print version number */
	  msg (M_INFO, "%s", title_string);

	  /* misc stuff */
	  pre_setup (&c.options);

	  /* test crypto? */
	  if (do_test_crypto (&c.options))
	    break;
	  
#ifdef ENABLE_MANAGEMENT
	  /* open management subsystem */
	  if (!open_management (&c))
	    break;
#endif

	  /* set certain options as environmental variables */
	  setenv_settings (c.es, &c.options);

	  /* finish context init */
	  context_init_1 (&c);

	  do
	    {
	      /* run tunnel depending on mode */
	      switch (c.options.mode)
		{
		case MODE_POINT_TO_POINT:
		  tunnel_point_to_point (&c);
		  break;
#if P2MP_SERVER
		case MODE_SERVER:
		  tunnel_server (&c);
		  break;
#endif
		default:
		  ASSERT (0);
		}

	      /* indicates first iteration -- has program-wide scope */
	      c.first_time = false;

	      /* any signals received? */
	      if (IS_SIG (&c))
		print_signal (c.sig, NULL, M_INFO);

	      /* pass restart status to management subsystem */
	      signal_restart_status (c.sig);
	    }
	  while (c.sig->signal_received == SIGUSR1);

	  uninit_options (&c.options);
	  gc_reset (&c.gc);
	}
      while (c.sig->signal_received == SIGHUP);
    }

  context_gc_free (&c);

  env_set_destroy (c.es);

#ifdef ENABLE_MANAGEMENT
  /* close management interface */
  close_management ();
#endif

  /* uninitialize program-wide statics */
  uninit_static ();

  openvpn_exit (OPENVPN_EXIT_STATUS_GOOD);  /* exit point */
  return 0;			            /* NOTREACHED */
}
