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

#include "memdbg.h"

#include "occ-inline.h"

static struct context *static_context; /* GLOBAL */

/*
 * Crypto initialization flags
 */
#define CF_LOAD_PERSISTED_PACKET_ID (1<<0)
#define CF_INIT_TLS_MULTI           (1<<1)
#define CF_INIT_TLS_AUTH_STANDALONE (1<<2)

static void do_init_first_time (struct context *c);

void
context_clear (struct context *c)
{
  CLEAR (*c);
}

void
context_clear_1 (struct context *c)
{
  CLEAR (c->c1);
}

void
context_clear_2 (struct context *c)
{
  CLEAR (c->c2);
}

void
context_clear_all_except_first_time (struct context *c)
{
  const bool first_time_save = c->first_time;
  const struct context_persist cpsave = c->persist;
  context_clear (c);
  c->first_time = first_time_save;
  c->persist = cpsave;
}

/*
 * Should be called after options->ce is modified at the top
 * of a SIGUSR1 restart.
 */
static void
update_options_ce_post (struct options *options)
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
      && options->ce.proto == PROTO_UDPv4)
    {
      options->ping_rec_timeout = PRE_PULL_INITIAL_PING_RESTART;
      options->ping_rec_timeout_action = PING_RESTART;
    }
#endif
#ifdef USE_CRYPTO
  /* 
   * Don't use replay window for TCP mode (i.e. require that packets be strictly in sequence).
   */
  if (link_socket_proto_connection_oriented (options->ce.proto))
    options->replay_window = options->replay_time = 0;
#endif
}

#if HTTP_PROXY_FALLBACK

static bool
ce_http_proxy_fallback_defined(const struct context *c)
{
  const struct connection_list *l = c->options.connection_list;
  if (l && l->current == 0)
    {
      int i;
      for (i = 0; i < l->len; ++i)
	{
	  const struct connection_entry *ce = l->array[i];
	  if (ce->flags & CE_HTTP_PROXY_FALLBACK)
	    return true;
	}
    }
  return false;
}

static void
ce_http_proxy_fallback_start(struct context *c, const char *remote_ip_hint)
{
  const struct connection_list *l = c->options.connection_list;
  if (l)
    {
      int i;
      for (i = 0; i < l->len; ++i)
	{
	  struct connection_entry *ce = l->array[i];
	  if (ce->flags & CE_HTTP_PROXY_FALLBACK)
	    {
	      ce->http_proxy_options = NULL;
	      ce->ce_http_proxy_fallback_timestamp = 0;
	      if (!remote_ip_hint)
		remote_ip_hint = ce->remote;
	    }
	}
    }

  if (management)
    management_http_proxy_fallback_notify(management, "NEED_LATER", remote_ip_hint);
}

static bool
ce_http_proxy_fallback (struct context *c, volatile const struct connection_entry *ce)
{
  const int proxy_info_expire = 120; /* seconds before proxy info expires */

  update_time();
  if (management)
    {
      if (!ce->ce_http_proxy_fallback_timestamp)
	{
	  management_http_proxy_fallback_notify(management, "NEED_NOW", NULL);
	  while (!ce->ce_http_proxy_fallback_timestamp)
	    {
	      management_event_loop_n_seconds (management, 1);
	      if (IS_SIG (c))
		return false;
	    }
	}
      return (now < ce->ce_http_proxy_fallback_timestamp + proxy_info_expire && ce->http_proxy_options);
    }
  return false;
}

static bool
management_callback_http_proxy_fallback_cmd (void *arg, const char *server, const char *port, const char *flags)
{
  struct context *c = (struct context *) arg;
  const struct connection_list *l = c->options.connection_list;
  int ret = false;
  struct http_proxy_options *ho = parse_http_proxy_fallback (c, server, port, flags, M_WARN);

  update_time();
  if (l)
    {
      int i;
      for (i = 0; i < l->len; ++i)
	{
	  struct connection_entry *ce = l->array[i];
	  if (ce->flags & CE_HTTP_PROXY_FALLBACK)
	    {
	      ce->http_proxy_options = ho;
	      ce->ce_http_proxy_fallback_timestamp = now;
	      ret = true;
	    }
	}
    }
  
  return ret;
}

#endif

/*
 * Initialize and possibly randomize connection list.
 */
static void
init_connection_list (struct context *c)
{
#ifdef ENABLE_CONNECTION
  struct connection_list *l = c->options.connection_list;
  if (l)
    {
      l->current = -1;
      if (c->options.remote_random)
	{
	  int i;
	  for (i = 0; i < l->len; ++i)
	    {
	      const int j = get_random () % l->len;
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
#endif
}

#if 0 /* fixme -- disable for production */
static void
show_connection_list (const struct connection_list *l)
{
  int i;
  dmsg (M_INFO, "CONNECTION_LIST len=%d current=%d",
	l->len, l->current);
  for (i = 0; i < l->len; ++i)
    {
      dmsg (M_INFO, "[%d] %s:%d proto=%s http_proxy=%d",
	    i,
	    l->array[i]->remote,
	    l->array[i]->remote_port,
	    proto2ascii(l->array[i]->proto, true),
	    BOOL_CAST(l->array[i]->http_proxy_options));
    }
}
#else
static inline void
show_connection_list (const struct connection_list *l)
{
}
#endif

/*
 * Increment to next connection entry
 */
static void
next_connection_entry (struct context *c)
{
#ifdef ENABLE_CONNECTION
  struct connection_list *l = c->options.connection_list;
  if (l)
    {
      bool ce_defined;
      struct connection_entry *ce;
      int n_cycles = 0;

      do {
	const char *remote_ip_hint = NULL;
	bool newcycle = false;

	ce_defined = true;
	if (l->no_advance && l->current >= 0)
	  {
	    l->no_advance = false;
	  }
	else
	  {
	    if (++l->current >= l->len)
	      {
		l->current = 0;
		++l->n_cycles;
		if (++n_cycles >= 2)
		  msg (M_FATAL, "No usable connection profiles are present");
	      }

	    if (l->current == 0)
	      newcycle = true;
	    show_connection_list(l);
	  }

	ce = l->array[l->current];

	if (c->options.remote_ip_hint && !l->n_cycles)
	  remote_ip_hint = c->options.remote_ip_hint;

#if HTTP_PROXY_FALLBACK
	if (newcycle && ce_http_proxy_fallback_defined(c))
	  ce_http_proxy_fallback_start(c, remote_ip_hint);

	if (ce->flags & CE_HTTP_PROXY_FALLBACK)
	  {
	    ce_defined = ce_http_proxy_fallback(c, ce);
	    if (IS_SIG (c))
	      break;
	  }
#endif

	if (ce->flags & CE_DISABLED)
	  ce_defined = false;

	c->options.ce = *ce;

	if (remote_ip_hint)
	  c->options.ce.remote = remote_ip_hint;

#if 0 /* fixme -- disable for production, this code simulates a network where proxy fallback is the only method to reach the OpenVPN server */
	if (!(c->options.ce.flags & CE_HTTP_PROXY_FALLBACK))
	  {
	    c->options.ce.remote = "10.10.0.1"; /* use an unreachable address here */
	  }
#endif
      } while (!ce_defined);
    }
#endif
  update_options_ce_post (&c->options);
}

/*
 * Query for private key and auth-user-pass username/passwords
 */
static void
init_query_passwords (struct context *c)
{
#if defined(USE_CRYPTO) && defined(USE_SSL)
  /* Certificate password input */
  if (c->options.key_pass_file)
    pem_password_setup (c->options.key_pass_file);
#endif
  
#if P2MP
  /* Auth user/pass input */
  if (c->options.auth_user_pass_file)
    auth_user_pass_setup (c->options.auth_user_pass_file);
#endif
}

/*
 * Initialize/Uninitialize HTTP or SOCKS proxy
 */

#ifdef GENERAL_PROXY_SUPPORT

static int
proxy_scope (struct context *c)
{
  return connection_list_defined (&c->options) ? 2 : 1;
}

static void
uninit_proxy_dowork (struct context *c)
{
#ifdef ENABLE_HTTP_PROXY
  if (c->c1.http_proxy_owned && c->c1.http_proxy)
    {
      http_proxy_close (c->c1.http_proxy);
      c->c1.http_proxy = NULL;
      c->c1.http_proxy_owned = false;
    }
#endif
#ifdef ENABLE_SOCKS
  if (c->c1.socks_proxy_owned && c->c1.socks_proxy)
    {
      socks_proxy_close (c->c1.socks_proxy);
      c->c1.socks_proxy = NULL;
      c->c1.socks_proxy_owned = false;
    }
#endif
}

static void
init_proxy_dowork (struct context *c)
{
#ifdef ENABLE_HTTP_PROXY
  bool did_http = false;
#else
  const bool did_http = false;
#endif

  uninit_proxy_dowork (c);

#ifdef ENABLE_HTTP_PROXY
  if (c->options.ce.http_proxy_options || c->options.auto_proxy_info)
    {
      /* Possible HTTP proxy user/pass input */
      c->c1.http_proxy = http_proxy_new (c->options.ce.http_proxy_options,
					 c->options.auto_proxy_info);
      if (c->c1.http_proxy)
	{
	  did_http = true;
	  c->c1.http_proxy_owned = true;
	}
    }
#endif

#ifdef ENABLE_SOCKS
  if (!did_http && (c->options.ce.socks_proxy_server || c->options.auto_proxy_info))
    {
      c->c1.socks_proxy = socks_proxy_new (c->options.ce.socks_proxy_server,
					   c->options.ce.socks_proxy_port,
					   c->options.ce.socks_proxy_authfile,
					   c->options.ce.socks_proxy_retry,
					   c->options.auto_proxy_info);
      if (c->c1.socks_proxy)
	{
	  c->c1.socks_proxy_owned = true;
	}
    }
#endif
}

static void
init_proxy (struct context *c, const int scope)
{
  if (scope == proxy_scope (c))
    init_proxy_dowork (c);
}

static void
uninit_proxy (struct context *c)
{
  if (c->sig->signal_received != SIGUSR1 || proxy_scope (c) == 2)
    uninit_proxy_dowork (c);
}

#else

static inline void
init_proxy (struct context *c, const int scope)
{
}

static inline void
uninit_proxy (struct context *c)
{
}

#endif

void
context_init_1 (struct context *c)
{
  context_clear_1 (c);

  packet_id_persist_init (&c->c1.pid_persist);

  init_connection_list (c);

  init_query_passwords (c);

#if defined(ENABLE_PKCS11)
  if (c->first_time) {
    int i;
    pkcs11_initialize (true, c->options.pkcs11_pin_cache_period);
    for (i=0;i<MAX_PARMS && c->options.pkcs11_providers[i] != NULL;i++)
     pkcs11_addProvider (c->options.pkcs11_providers[i], c->options.pkcs11_protected_authentication[i],
       c->options.pkcs11_private_mode[i], c->options.pkcs11_cert_private[i]);
  }
#endif

#if 0 /* test get_user_pass with GET_USER_PASS_NEED_OK flag */
 {
   /*
    * In the management interface, you can okay the request by entering "needok token-insertion-request ok"
    */
   struct user_pass up;
   CLEAR (up);
   strcpy (up.username, "Please insert your cryptographic token"); /* put the high-level message in up.username */
   get_user_pass (&up, NULL, "token-insertion-request", GET_USER_PASS_MANAGEMENT|GET_USER_PASS_NEED_OK);
   msg (M_INFO, "RET:%s", up.password); /* will return the third argument to management interface
                                           'needok' command, usually 'ok' or 'cancel'. */
 }
#endif

  /* initialize HTTP or SOCKS proxy object at scope level 1 */
  init_proxy (c, 1);
}

void
context_gc_free (struct context *c)
{
  gc_free (&c->c2.gc);
  gc_free (&c->options.gc);
  gc_free (&c->gc);
}

#if PORT_SHARE

static void
close_port_share (void)
{
  if (port_share)
    {
      port_share_close (port_share);
      port_share = NULL;
    }
}

static void
init_port_share (struct context *c)
{
  if (!port_share && (c->options.port_share_host && c->options.port_share_port))
    {
      port_share = port_share_open (c->options.port_share_host,
				    c->options.port_share_port);
      if (port_share == NULL)
	msg (M_FATAL, "Fatal error: Port sharing failed");
    }
}

#endif

bool
init_static (void)
{
  /* configure_path (); */

#if defined(USE_CRYPTO) && defined(DMALLOC)
  openssl_dmalloc_init ();
#endif

  init_random_seed ();		/* init random() function, only used as
				   source for weak random numbers */
  error_reset ();		/* initialize error.c */
  reset_check_status ();	/* initialize status check code in socket.c */

#ifdef WIN32
  init_win32 ();
#endif

#ifdef OPENVPN_DEBUG_COMMAND_LINE
  {
    int i;
    for (i = 0; i < argc; ++i)
      msg (M_INFO, "argv[%d] = '%s'", i, argv[i]);
  }
#endif

  update_time ();

#ifdef USE_CRYPTO
  init_ssl_lib ();

  /* init PRNG used for IV generation */
  /* When forking, copy this to more places in the code to avoid fork
     random-state predictability */
  prng_init (NULL, 0);
#endif

#ifdef PID_TEST
  packet_id_interactive_test ();	/* test the sequence number code */
  return false;
#endif

#ifdef SCHEDULE_TEST
  schedule_test ();
  return false;
#endif

#ifdef LIST_TEST
  list_test ();
  return false;
#endif

#ifdef IFCONFIG_POOL_TEST
  ifconfig_pool_test (0x0A010004, 0x0A0100FF);
  return false;
#endif

#ifdef CHARACTER_CLASS_DEBUG
  character_class_debug ();
  return false;
#endif

#ifdef EXTRACT_X509_FIELD_TEST
  extract_x509_field_test ();
  return false;
#endif

#ifdef TIME_TEST
  time_test ();
  return false;
#endif

#ifdef GEN_PATH_TEST
  {
    struct gc_arena gc = gc_new ();
    const char *fn = gen_path ("foo",
			       "bar",
			       &gc);
    printf ("%s\n", fn);
    gc_free (&gc);
  }
  return false;
#endif

#ifdef STATUS_PRINTF_TEST
  {
    struct gc_arena gc = gc_new ();
    const char *tmp_file = create_temp_file ("/tmp", "foo", &gc);
    struct status_output *so = status_open (tmp_file, 0, -1, NULL, STATUS_OUTPUT_WRITE);
    status_printf (so, "%s", "foo");
    status_printf (so, "%s", "bar");
    if (!status_close (so))
      msg (M_WARN, "STATUS_PRINTF_TEST: %s: write error", tmp_file);
    gc_free (&gc);
  }
  return false;
#endif

#ifdef ARGV_TEST
  {
    void argv_test (void);
    argv_test ();
    return false;
  }
#endif

#ifdef PRNG_TEST
  {
    struct gc_arena gc = gc_new ();
    uint8_t rndbuf[8];
    int i;
    prng_init ("sha1", 16);
    //prng_init (NULL, 0);
    const int factor = 1;
    for (i = 0; i < factor * 8; ++i)
      {
#if 1
	prng_bytes (rndbuf, sizeof (rndbuf));
#else
	ASSERT(RAND_bytes (rndbuf, sizeof (rndbuf)));
#endif
	printf ("[%d] %s\n", i, format_hex (rndbuf, sizeof (rndbuf), 0, &gc));
      }
    gc_free (&gc);
    prng_uninit ();
    return false;
  }
#endif

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
		buffer_list_push(bl, (unsigned char *)text[i]);
	    }
	    printf("[cap=%d i=%d] *************************\n", listcap, iter);
	    if (!(iter & 8))
	      buffer_list_aggregate(bl, iter/2);
	    if (!(iter & 16))
	      buffer_list_push(bl, (unsigned char *)"Even more text...");
	    buffer_list_aggregate(bl, iter);
	    if (!(iter & 1))
	      buffer_list_push(bl, (unsigned char *)"More text...");
	    {
	      struct buffer *buf;
	      while ((buf = buffer_list_peek(bl)))
		{
		  int c;
		  printf ("'");
		  while ((c = buf_read_u8(buf)) >= 0)
		    putchar(c);
		  printf ("'\n");
		  buffer_list_advance(bl, 0);
		}
	    }
	    buffer_list_free(bl);
	  }
      }
    return false;
  }
#endif

  return true;
}

void
uninit_static (void)
{
#ifdef USE_CRYPTO
  free_ssl_lib ();
#endif

#ifdef ENABLE_PKCS11
  pkcs11_terminate ();
#endif

#if PORT_SHARE
  close_port_share ();
#endif

#if defined(MEASURE_TLS_HANDSHAKE_STATS) && defined(USE_CRYPTO) && defined(USE_SSL)
  show_tls_performance_stats ();
#endif
}

void
init_verb_mute (struct context *c, unsigned int flags)
{
  if (flags & IVM_LEVEL_1)
    {
      /* set verbosity and mute levels */
      set_check_status (D_LINK_ERRORS, D_READ_WRITE);
      set_debug_level (c->options.verbosity, SDL_CONSTRAIN);
      set_mute_cutoff (c->options.mute);
    }

  /* special D_LOG_RW mode */
  if (flags & IVM_LEVEL_2)
    c->c2.log_rw = (check_debug_level (D_LOG_RW) && !check_debug_level (D_LOG_RW + 1));
}

/*
 * Possibly set --dev based on --dev-node.
 * For example, if --dev-node /tmp/foo/tun, and --dev undefined,
 * set --dev to tun.
 */
void
init_options_dev (struct options *options)
{
  if (!options->dev)
    options->dev = openvpn_basename (options->dev_node);
}

bool
print_openssl_info (const struct options *options)
{
  /*
   * OpenSSL info print mode?
   */
#ifdef USE_CRYPTO
  if (options->show_ciphers || options->show_digests || options->show_engines
#ifdef USE_SSL
      || options->show_tls_ciphers
#endif
    )
    {
      if (options->show_ciphers)
	show_available_ciphers ();
      if (options->show_digests)
	show_available_digests ();
      if (options->show_engines)
	show_available_engines ();
#ifdef USE_SSL
      if (options->show_tls_ciphers)
	show_available_tls_ciphers ();
#endif
      return true;
    }
#endif
  return false;
}

/*
 * Static pre-shared key generation mode?
 */
bool
do_genkey (const struct options * options)
{
#ifdef USE_CRYPTO
  if (options->genkey)
    {
      int nbits_written;

      notnull (options->shared_secret_file,
	       "shared secret output file (--secret)");

      if (options->mlock)	/* should we disable paging? */
	do_mlockall (true);

      nbits_written = write_key_file (2, options->shared_secret_file);

      msg (D_GENKEY | M_NOPREFIX,
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
do_persist_tuntap (const struct options *options)
{
#ifdef TUNSETPERSIST
  if (options->persist_config)
    {
      /* sanity check on options for --mktun or --rmtun */
      notnull (options->dev, "TUN/TAP device (--dev)");
      if (options->ce.remote || options->ifconfig_local
	  || options->ifconfig_remote_netmask
#ifdef USE_CRYPTO
	  || options->shared_secret_file
#ifdef USE_SSL
	  || options->tls_server || options->tls_client
#endif
#endif
	)
	msg (M_FATAL|M_OPTERR,
	     "options --mktun or --rmtun should only be used together with --dev");
      tuncfg (options->dev, options->dev_type, options->dev_node,
	      options->tun_ipv6, options->persist_mode,
	      options->username, options->groupname, &options->tuntap_options);
      if (options->persist_mode && options->lladdr)
        set_lladdr(options->dev, options->lladdr, NULL);
      return true;
    }
#endif
  return false;
}

/*
 * Should we become a daemon?
 * Return true if we did it.
 */
static bool
possibly_become_daemon (const struct options *options, const bool first_time)
{
  bool ret = false;
  if (first_time && options->daemon)
    {
      ASSERT (!options->inetd);
      if (daemon (options->cd_dir != NULL, options->log) < 0)
	msg (M_ERR, "daemon() failed");
      restore_signal_state ();
      if (options->log)
	set_std_files_to_null (true);

#if defined(ENABLE_PKCS11)
      pkcs11_forkFixup ();
#endif

      ret = true;
    }
  return ret;
}

/*
 * Actually do UID/GID downgrade, chroot and SELinux context switching, if requested.
 */
static void
do_uid_gid_chroot (struct context *c, bool no_delay)
{
  static const char why_not[] = "will be delayed because of --client, --pull, or --up-delay";
  struct context_0 *c0 = c->c0;

  if (c->first_time && c0 && !c0->uid_gid_set)
    {
      /* chroot if requested */
      if (c->options.chroot_dir)
	{
	  if (no_delay)
	    do_chroot (c->options.chroot_dir);
	  else
	    msg (M_INFO, "NOTE: chroot %s", why_not);
	}

      /* set user and/or group that we want to setuid/setgid to */
      if (no_delay)
	{
	  set_group (&c0->group_state);
	  set_user (&c0->user_state);
	  c0->uid_gid_set = true;
	}
      else if (c0->uid_gid_specified)
	{
	  msg (M_INFO, "NOTE: UID/GID downgrade %s", why_not);
	}

#ifdef HAVE_SETCON
      /* Apply a SELinux context in order to restrict what OpenVPN can do
       * to _only_ what it is supposed to do after initialization is complete
       * (basically just network I/O operations). Doing it after chroot
       * requires /proc to be mounted in the chroot (which is annoying indeed
       * but doing it before requires more complex SELinux policies.
       */
      if (c->options.selinux_context)
	{
	  if (no_delay) {
	    if (-1 == setcon (c->options.selinux_context))
	      msg (M_ERR, "setcon to '%s' failed; is /proc accessible?", c->options.selinux_context);
	    else
	      msg (M_INFO, "setcon to '%s' succeeded", c->options.selinux_context);
	  }
	  else
	    msg (M_INFO, "NOTE: setcon %s", why_not);
	}
#endif
    }
}

/*
 * Return common name in a way that is formatted for
 * prepending to msg() output.
 */
const char *
format_common_name (struct context *c, struct gc_arena *gc)
{
  struct buffer out = alloc_buf_gc (256, gc);
#if defined(USE_CRYPTO) && defined(USE_SSL)
  if (c->c2.tls_multi)
    {
      buf_printf (&out, "[%s] ", tls_common_name (c->c2.tls_multi, false));
    }
#endif
  return BSTR (&out);
}

void
pre_setup (const struct options *options)
{
#ifdef WIN32
  if (options->exit_event_name)
    {
      win32_signal_open (&win32_signal,
			 WSO_FORCE_SERVICE,
			 options->exit_event_name,
			 options->exit_event_initial_state);
    }
  else
    {
      win32_signal_open (&win32_signal,
			 WSO_FORCE_CONSOLE,
			 NULL,
			 false);

      /* put a title on the top window bar */
      if (win32_signal.mode == WSO_MODE_CONSOLE)
	{
	  window_title_save (&window_title); 
	  window_title_generate (options->config);
	}
    }
#endif
}

void
reset_coarse_timers (struct context *c)
{
  c->c2.coarse_timer_wakeup = 0;
}

/*
 * Initialize timers
 */
static void
do_init_timers (struct context *c, bool deferred)
{
  update_time ();
  reset_coarse_timers (c);

  /* initialize inactivity timeout */
  if (c->options.inactivity_timeout)
    event_timeout_init (&c->c2.inactivity_interval, c->options.inactivity_timeout, now);

  /* initialize pings */

  if (c->options.ping_send_timeout)
    event_timeout_init (&c->c2.ping_send_interval, c->options.ping_send_timeout, 0);

  if (c->options.ping_rec_timeout)
    event_timeout_init (&c->c2.ping_rec_interval, c->options.ping_rec_timeout, now);

#if P2MP
  if (c->options.server_poll_timeout)
    event_timeout_init (&c->c2.server_poll_interval, c->options.server_poll_timeout, now);
#endif

  if (!deferred)
    {
      /* initialize connection establishment timer */
      event_timeout_init (&c->c2.wait_for_connect, 1, now);

#ifdef ENABLE_OCC
      /* initialize occ timers */

      if (c->options.occ
	  && !TLS_MODE (c)
	  && c->c2.options_string_local && c->c2.options_string_remote)
	event_timeout_init (&c->c2.occ_interval, OCC_INTERVAL_SECONDS, now);

      if (c->options.mtu_test)
	event_timeout_init (&c->c2.occ_mtu_load_test_interval, OCC_MTU_LOAD_INTERVAL_SECONDS, now);
#endif

      /* initialize packet_id persistence timer */
#ifdef USE_CRYPTO
      if (c->options.packet_id_file)
	event_timeout_init (&c->c2.packet_id_persist_interval, 60, now);
#endif

#if defined(USE_CRYPTO) && defined(USE_SSL)
      /* initialize tmp_int optimization that limits the number of times we call
	 tls_multi_process in the main event loop */
      interval_init (&c->c2.tmp_int, TLS_MULTI_HORIZON, TLS_MULTI_REFRESH);
#endif
    }
}

/*
 * Initialize traffic shaper.
 */
static void
do_init_traffic_shaper (struct context *c)
{
#ifdef HAVE_GETTIMEOFDAY
  /* initialize traffic shaper (i.e. transmit bandwidth limiter) */
  if (c->options.shaper)
    {
      shaper_init (&c->c2.shaper, c->options.shaper);
      shaper_msg (&c->c2.shaper);
    }
#endif
}

/*
 * Allocate a route list structure if at least one
 * --route option was specified.
 */
static void
do_alloc_route_list (struct context *c)
{
  if (c->options.routes && !c->c1.route_list)
    c->c1.route_list = new_route_list (c->options.max_routes, &c->gc);
}


/*
 * Initialize the route list, resolving any DNS names in route
 * options and saving routes in the environment.
 */
static void
do_init_route_list (const struct options *options,
		    struct route_list *route_list,
		    const struct link_socket_info *link_socket_info,
		    bool fatal,
		    struct env_set *es)
{
  const char *gw = NULL;
  int dev = dev_type_enum (options->dev, options->dev_type);
  int metric = 0;

  if (dev == DEV_TYPE_TUN && (options->topology == TOP_NET30 || options->topology == TOP_P2P))
    gw = options->ifconfig_remote_netmask;
  if (options->route_default_gateway)
    gw = options->route_default_gateway;
  if (options->route_default_metric)
    metric = options->route_default_metric;

  if (!init_route_list (route_list,
			options->routes,
			gw,
			metric,
			link_socket_current_remote (link_socket_info),
			es))
    {
      if (fatal)
	openvpn_exit (OPENVPN_EXIT_STATUS_ERROR);	/* exit point */
    }
  else
    {
      /* copy routes to environment */
      setenv_routes (es, route_list);
    }
}

/*
 * Called after all initialization has been completed.
 */
void
initialization_sequence_completed (struct context *c, const unsigned int flags)
{
  static const char message[] = "Initialization Sequence Completed";

  /* If we delayed UID/GID downgrade or chroot, do it now */
  do_uid_gid_chroot (c, true);

  /* Test if errors */
  if (flags & ISC_ERRORS)
    {
#ifdef WIN32
      show_routes (M_INFO|M_NOPREFIX);
      show_adapters (M_INFO|M_NOPREFIX);
      msg (M_INFO, "%s With Errors ( see http://openvpn.net/faq.html#dhcpclientserv )", message);
#else
      msg (M_INFO, "%s With Errors", message);
#endif
    }
  else
    msg (M_INFO, "%s", message);

  /* Flag connection_list that we initialized */
  if ((flags & (ISC_ERRORS|ISC_SERVER)) == 0 && connection_list_defined (&c->options))
    connection_list_set_no_advance (&c->options);

#ifdef WIN32
  fork_register_dns_action (c->c1.tuntap);
#endif

#ifdef ENABLE_MANAGEMENT
  /* Tell management interface that we initialized */
  if (management)
    {
      in_addr_t tun_local = 0;
      in_addr_t tun_remote = 0; /* FKS */
      const char *detail = "SUCCESS";
      if (c->c1.tuntap)
	tun_local = c->c1.tuntap->local;
      tun_remote = htonl (c->c1.link_socket_addr.actual.dest.sa.sin_addr.s_addr);
      if (flags & ISC_ERRORS)
	detail = "ERROR";
      management_set_state (management,
			    OPENVPN_STATE_CONNECTED,
			    detail,
			    tun_local,
			    tun_remote);
      if (tun_local)
	management_post_tunnel_open (management, tun_local);
    }
#endif

}

/*
 * Possibly add routes and/or call route-up script
 * based on options.
 */
void
do_route (const struct options *options,
	  struct route_list *route_list,
	  const struct tuntap *tt,
	  const struct plugin_list *plugins,
	  struct env_set *es)
{
  if (!options->route_noexec && route_list)
    add_routes (route_list, tt, ROUTE_OPTION_FLAGS (options), es);

  if (plugin_defined (plugins, OPENVPN_PLUGIN_ROUTE_UP))
    {
      if (plugin_call (plugins, OPENVPN_PLUGIN_ROUTE_UP, NULL, NULL, es) != OPENVPN_PLUGIN_FUNC_SUCCESS)
	msg (M_WARN, "WARNING: route-up plugin call failed");
    }

  if (options->route_script)
    {
      struct argv argv = argv_new ();
      setenv_str (es, "script_type", "route-up");
      argv_printf (&argv, "%sc", options->route_script);
      openvpn_run_script (&argv, es, 0, "--route-up");
      argv_reset (&argv);
    }

#ifdef WIN32
  if (options->show_net_up)
    {
      show_routes (M_INFO|M_NOPREFIX);
      show_adapters (M_INFO|M_NOPREFIX);
    }
  else if (check_debug_level (D_SHOW_NET))
    {
      show_routes (D_SHOW_NET|M_NOPREFIX);
      show_adapters (D_SHOW_NET|M_NOPREFIX);
    }
#endif
}

/*
 * Save current pulled options string in the c1 context store, so we can
 * compare against it after possible future restarts.
 */
#if P2MP
static void
save_pulled_options_digest (struct context *c, const struct md5_digest *newdigest)
{
  if (newdigest)
    c->c1.pulled_options_digest_save = *newdigest;
  else
    md5_digest_clear (&c->c1.pulled_options_digest_save);
}
#endif

/*
 * initialize tun/tap device object
 */
static void
do_init_tun (struct context *c)
{
  c->c1.tuntap = init_tun (c->options.dev,
			   c->options.dev_type,
			   c->options.topology,
			   c->options.ifconfig_local,
			   c->options.ifconfig_remote_netmask,
			   addr_host (&c->c1.link_socket_addr.local),
			   addr_host (&c->c1.link_socket_addr.remote),
			   !c->options.ifconfig_nowarn,
			   c->c2.es);

  init_tun_post (c->c1.tuntap,
		 &c->c2.frame,
		 &c->options.tuntap_options);

  c->c1.tuntap_owned = true;
}

/*
 * Open tun/tap device, ifconfig, call up script, etc.
 */

static bool
do_open_tun (struct context *c)
{
  struct gc_arena gc = gc_new ();
  bool ret = false;

  c->c2.ipv4_tun = (!c->options.tun_ipv6
		    && is_dev_type (c->options.dev, c->options.dev_type, "tun"));

  if (!c->c1.tuntap)
    {
      /* initialize (but do not open) tun/tap object */
      do_init_tun (c);

      /* allocate route list structure */
      do_alloc_route_list (c);

      /* parse and resolve the route option list */
      if (c->options.routes && c->c1.route_list && c->c2.link_socket)
	do_init_route_list (&c->options, c->c1.route_list, &c->c2.link_socket->info, false, c->c2.es);

      /* do ifconfig */
      if (!c->options.ifconfig_noexec
	  && ifconfig_order () == IFCONFIG_BEFORE_TUN_OPEN)
	{
	  /* guess actual tun/tap unit number that will be returned
	     by open_tun */
	  const char *guess = guess_tuntap_dev (c->options.dev,
						c->options.dev_type,
						c->options.dev_node,
						&gc);
	  do_ifconfig (c->c1.tuntap, guess, TUN_MTU_SIZE (&c->c2.frame), c->c2.es);
	}

      /* open the tun device */
      open_tun (c->options.dev, c->options.dev_type, c->options.dev_node,
		c->options.tun_ipv6, c->c1.tuntap);

      /* set the hardware address */
      if (c->options.lladdr)
	  set_lladdr(c->c1.tuntap->actual_name, c->options.lladdr, c->c2.es);

      /* do ifconfig */
      if (!c->options.ifconfig_noexec
	  && ifconfig_order () == IFCONFIG_AFTER_TUN_OPEN)
	{
	  do_ifconfig (c->c1.tuntap, c->c1.tuntap->actual_name, TUN_MTU_SIZE (&c->c2.frame), c->c2.es);
	}

      /* run the up script */
      run_up_down (c->options.up_script,
		   c->plugins,
		   OPENVPN_PLUGIN_UP,
		   c->c1.tuntap->actual_name,
		   TUN_MTU_SIZE (&c->c2.frame),
		   EXPANDED_SIZE (&c->c2.frame),
		   print_in_addr_t (c->c1.tuntap->local, IA_EMPTY_IF_UNDEF, &gc),
		   print_in_addr_t (c->c1.tuntap->remote_netmask, IA_EMPTY_IF_UNDEF, &gc),
		   "init",
		   NULL,
		   "up",
		   c->c2.es);

      /* possibly add routes */
      if (!c->options.route_delay_defined)
	do_route (&c->options, c->c1.route_list, c->c1.tuntap, c->plugins, c->c2.es);

      /*
       * Did tun/tap driver give us an MTU?
       */
      if (c->c1.tuntap->post_open_mtu)
	frame_set_mtu_dynamic (&c->c2.frame,
			       c->c1.tuntap->post_open_mtu,
			       SET_MTU_TUN | SET_MTU_UPPER_BOUND);

      ret = true;
      static_context = c;
    }
  else
    {
      msg (M_INFO, "Preserving previous TUN/TAP instance: %s",
	   c->c1.tuntap->actual_name);

      /* run the up script if user specified --up-restart */
      if (c->options.up_restart)
	run_up_down (c->options.up_script,
		     c->plugins,
		     OPENVPN_PLUGIN_UP,
		     c->c1.tuntap->actual_name,
		     TUN_MTU_SIZE (&c->c2.frame),
		     EXPANDED_SIZE (&c->c2.frame),
		     print_in_addr_t (c->c1.tuntap->local, IA_EMPTY_IF_UNDEF, &gc),
		     print_in_addr_t (c->c1.tuntap->remote_netmask, IA_EMPTY_IF_UNDEF, &gc),
		     "restart",
		     NULL,
		     "up",
		     c->c2.es);
    }
  gc_free (&gc);
  return ret;
}

/*
 * Close TUN/TAP device
 */

static void
do_close_tun_simple (struct context *c)
{
  msg (D_CLOSE, "Closing TUN/TAP interface");
  close_tun (c->c1.tuntap);
  c->c1.tuntap = NULL;
  c->c1.tuntap_owned = false;
#if P2MP
  save_pulled_options_digest (c, NULL); /* delete C1-saved pulled_options_digest */
#endif
}

static void
do_close_tun (struct context *c, bool force)
{
  struct gc_arena gc = gc_new ();
  if (c->c1.tuntap && c->c1.tuntap_owned)
    {
      const char *tuntap_actual = string_alloc (c->c1.tuntap->actual_name, &gc);
      const in_addr_t local = c->c1.tuntap->local;
      const in_addr_t remote_netmask = c->c1.tuntap->remote_netmask;

      if (force || !(c->sig->signal_received == SIGUSR1 && c->options.persist_tun))
	{
	  static_context = NULL;

#ifdef ENABLE_MANAGEMENT
	  /* tell management layer we are about to close the TUN/TAP device */
	  if (management)
	    management_pre_tunnel_close (management);
#endif

	  /* delete any routes we added */
	  if (c->c1.route_list)
	    delete_routes (c->c1.route_list, c->c1.tuntap, ROUTE_OPTION_FLAGS (&c->options), c->c2.es);

	  /* actually close tun/tap device based on --down-pre flag */
	  if (!c->options.down_pre)
	    do_close_tun_simple (c);

	  /* Run the down script -- note that it will run at reduced
	     privilege if, for example, "--user nobody" was used. */
	  run_up_down (c->options.down_script,
		       c->plugins,
		       OPENVPN_PLUGIN_DOWN,
		       tuntap_actual,
		       TUN_MTU_SIZE (&c->c2.frame),
		       EXPANDED_SIZE (&c->c2.frame),
		       print_in_addr_t (local, IA_EMPTY_IF_UNDEF, &gc),
		       print_in_addr_t (remote_netmask, IA_EMPTY_IF_UNDEF, &gc),
		       "init",
		       signal_description (c->sig->signal_received,
					   c->sig->signal_text),
		       "down",
		       c->c2.es);

	  /* actually close tun/tap device based on --down-pre flag */
	  if (c->options.down_pre)
	    do_close_tun_simple (c);
	}
      else
	{
	  /* run the down script on this restart if --up-restart was specified */
	  if (c->options.up_restart)
	    run_up_down (c->options.down_script,
			 c->plugins,
			 OPENVPN_PLUGIN_DOWN,
			 tuntap_actual,
			 TUN_MTU_SIZE (&c->c2.frame),
			 EXPANDED_SIZE (&c->c2.frame),
			 print_in_addr_t (local, IA_EMPTY_IF_UNDEF, &gc),
			 print_in_addr_t (remote_netmask, IA_EMPTY_IF_UNDEF, &gc),
			 "restart",
			 signal_description (c->sig->signal_received,
					     c->sig->signal_text),
			 "down",
			 c->c2.es);
	}
    }
  gc_free (&gc);
}

void
tun_abort()
{
  struct context *c = static_context;
  if (c)
    {
      static_context = NULL;
      do_close_tun (c, true);
    }
}

/*
 * Handle delayed tun/tap interface bringup due to --up-delay or --pull
 */

void
do_up (struct context *c, bool pulled_options, unsigned int option_types_found)
{
  if (!c->c2.do_up_ran)
    {
      reset_coarse_timers (c);

      if (pulled_options && option_types_found)
	do_deferred_options (c, option_types_found);

      /* if --up-delay specified, open tun, do ifconfig, and run up script now */
      if (c->options.up_delay || PULL_DEFINED (&c->options))
	{
	  c->c2.did_open_tun = do_open_tun (c);
	  update_time ();

#if P2MP
	  /*
	   * Was tun interface object persisted from previous restart iteration,
	   * and if so did pulled options string change from previous iteration?
	   */
	  if (!c->c2.did_open_tun
	      && PULL_DEFINED (&c->options)
	      && c->c1.tuntap
	      && (!md5_digest_defined (&c->c1.pulled_options_digest_save) || !md5_digest_defined (&c->c2.pulled_options_digest)
		  || !md5_digest_equal (&c->c1.pulled_options_digest_save, &c->c2.pulled_options_digest)))
	    {
	      /* if so, close tun, delete routes, then reinitialize tun and add routes */
	      msg (M_INFO, "NOTE: Pulled options changed on restart, will need to close and reopen TUN/TAP device.");
	      do_close_tun (c, true);
	      openvpn_sleep (1);
	      c->c2.did_open_tun = do_open_tun (c);
	      update_time ();
	    }
#endif
	}

      if (c->c2.did_open_tun)
	{
#if P2MP
	  save_pulled_options_digest (c, &c->c2.pulled_options_digest);
#endif

	  /* if --route-delay was specified, start timer */
	  if (c->options.route_delay_defined)
	    {
	      event_timeout_init (&c->c2.route_wakeup, c->options.route_delay, now);
	      event_timeout_init (&c->c2.route_wakeup_expire, c->options.route_delay + c->options.route_delay_window, now);
	      if (c->c1.tuntap)
		tun_standby_init (c->c1.tuntap);
	    }
	  else
	    {
	      initialization_sequence_completed (c, 0); /* client/p2p --route-delay undefined */
	    }
	}
      else if (c->options.mode == MODE_POINT_TO_POINT)
	{
	  initialization_sequence_completed (c, 0); /* client/p2p restart with --persist-tun */
	}
	
      c->c2.do_up_ran = true;
    }
}

/*
 * These are the option categories which will be accepted by pull.
 */
unsigned int
pull_permission_mask (const struct context *c)
{
  unsigned int flags =
      OPT_P_UP
    | OPT_P_ROUTE_EXTRAS
    | OPT_P_IPWIN32
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
    | OPT_P_PULL_MODE;

  if (!c->options.route_nopull)
    flags |= OPT_P_ROUTE;

  return flags;
}

/*
 * Handle non-tun-related pulled options.
 */
void
do_deferred_options (struct context *c, const unsigned int found)
{
  if (found & OPT_P_MESSAGES)
    {
      init_verb_mute (c, IVM_LEVEL_1|IVM_LEVEL_2);
      msg (D_PUSH, "OPTIONS IMPORT: --verb and/or --mute level changed");
    }
  if (found & OPT_P_TIMER)
    {
      do_init_timers (c, true);
      msg (D_PUSH, "OPTIONS IMPORT: timers and/or timeouts modified");
    }

#ifdef ENABLE_OCC
  if (found & OPT_P_EXPLICIT_NOTIFY)
    {
      if (c->options.ce.proto != PROTO_UDPv4 && c->options.explicit_exit_notification)
	{
	  msg (D_PUSH, "OPTIONS IMPORT: --explicit-exit-notify can only be used with --proto udp");
	  c->options.explicit_exit_notification = 0;
	}
      else
	msg (D_PUSH, "OPTIONS IMPORT: explicit notify parm(s) modified");
    }
#endif

#ifdef USE_LZO
  if (found & OPT_P_COMP)
    {
      if (lzo_defined (&c->c2.lzo_compwork))
	{
	  msg (D_PUSH, "OPTIONS IMPORT: LZO parms modified");
	  lzo_modify_flags (&c->c2.lzo_compwork, c->options.lzo);
	}
    }
#endif

  if (found & OPT_P_SHAPER)
    {
      msg (D_PUSH, "OPTIONS IMPORT: traffic shaper enabled");
      do_init_traffic_shaper (c);
    }

  if (found & OPT_P_SOCKBUF)
    {
      msg (D_PUSH, "OPTIONS IMPORT: --sndbuf/--rcvbuf options modified");
      link_socket_update_buffer_sizes (c->c2.link_socket, c->options.rcvbuf, c->options.sndbuf);
    }

  if (found & OPT_P_SOCKFLAGS)
    {
      msg (D_PUSH, "OPTIONS IMPORT: --socket-flags option modified");
      link_socket_update_flags (c->c2.link_socket, c->options.sockflags);
    }

  if (found & OPT_P_PERSIST)
    msg (D_PUSH, "OPTIONS IMPORT: --persist options modified");
  if (found & OPT_P_UP)
    msg (D_PUSH, "OPTIONS IMPORT: --ifconfig/up options modified");
  if (found & OPT_P_ROUTE)
    msg (D_PUSH, "OPTIONS IMPORT: route options modified");
  if (found & OPT_P_ROUTE_EXTRAS)
    msg (D_PUSH, "OPTIONS IMPORT: route-related options modified");
  if (found & OPT_P_IPWIN32)
    msg (D_PUSH, "OPTIONS IMPORT: --ip-win32 and/or --dhcp-option options modified");
  if (found & OPT_P_SETENV)
    msg (D_PUSH, "OPTIONS IMPORT: environment modified");
}

/*
 * Possible hold on initialization
 */
static bool
do_hold (struct context *c)
{
#ifdef ENABLE_MANAGEMENT
  if (management)
    {
      /* if c is defined, daemonize before hold */
      if (c && c->options.daemon && management_should_daemonize (management))
	do_init_first_time (c);

      /* block until management hold is released */
      if (management_hold (management))
	return true;
    }
#endif
  return false;
}

/*
 * Sleep before restart.
 */
static void
socket_restart_pause (struct context *c)
{
  bool proxy = false;
  int sec = 2;

#ifdef ENABLE_HTTP_PROXY
  if (c->options.ce.http_proxy_options)
    proxy = true;
#endif
#ifdef ENABLE_SOCKS
  if (c->options.ce.socks_proxy_server)
    proxy = true;
#endif

  switch (c->options.ce.proto)
    {
    case PROTO_UDPv4:
      if (proxy)
	sec = c->options.ce.connect_retry_seconds;
      break;
    case PROTO_TCPv4_SERVER:
      sec = 1;
      break;
    case PROTO_TCPv4_CLIENT:
      sec = c->options.ce.connect_retry_seconds;
      break;
    }

#ifdef ENABLE_DEBUG
  if (GREMLIN_CONNECTION_FLOOD_LEVEL (c->options.gremlin))
    sec = 0;
#endif

#if P2MP
  if (auth_retry_get () == AR_NOINTERACT)
    sec = 10;

  if (c->options.server_poll_timeout && sec > 1)
    sec = 1;
#endif

  if (c->persist.restart_sleep_seconds > 0 && c->persist.restart_sleep_seconds > sec)
    sec = c->persist.restart_sleep_seconds;
  else if (c->persist.restart_sleep_seconds == -1)
    sec = 0;
  c->persist.restart_sleep_seconds = 0;

  /* do managment hold on context restart, i.e. second, third, fourth, etc. initialization */
  if (do_hold (NULL))
    sec = 0;

  if (sec)
    {
      msg (D_RESTART, "Restart pause, %d second(s)", sec);
      openvpn_sleep (sec);
    }
}

/*
 * Do a possible pause on context_2 initialization.
 */
static void
do_startup_pause (struct context *c)
{
  if (!c->first_time)
    socket_restart_pause (c);
  else
    do_hold (NULL); /* do management hold on first context initialization */
}

/*
 * Finalize MTU parameters based on command line or config file options.
 */
static void
frame_finalize_options (struct context *c, const struct options *o)
{
  if (!o)
    o = &c->options;

  /*
   * Set adjustment factor for buffer alignment when no
   * cipher is used.
   */
  if (!CIPHER_ENABLED (c))
    {
      frame_align_to_extra_frame (&c->c2.frame);
      frame_or_align_flags (&c->c2.frame,
			    FRAME_HEADROOM_MARKER_FRAGMENT
			    |FRAME_HEADROOM_MARKER_READ_LINK
			    |FRAME_HEADROOM_MARKER_READ_STREAM);
    }
  
  frame_finalize (&c->c2.frame,
		  o->link_mtu_defined,
		  o->link_mtu,
		  o->tun_mtu_defined,
		  o->tun_mtu);
}

/*
 * Free a key schedule, including OpenSSL components.
 */
static void
key_schedule_free (struct key_schedule *ks, bool free_ssl_ctx)
{
#ifdef USE_CRYPTO
  free_key_ctx_bi (&ks->static_key);
#ifdef USE_SSL
  if (ks->ssl_ctx && free_ssl_ctx)
    {
      SSL_CTX_free (ks->ssl_ctx);
      free_key_ctx_bi (&ks->tls_auth_key);
    }
#endif /* USE_SSL */
#endif /* USE_CRYPTO */
  CLEAR (*ks);
}

#ifdef USE_CRYPTO

static void
init_crypto_pre (struct context *c, const unsigned int flags)
{
  if (c->options.engine)
    init_crypto_lib_engine (c->options.engine);

  if (flags & CF_LOAD_PERSISTED_PACKET_ID)
    {
      /* load a persisted packet-id for cross-session replay-protection */
      if (c->options.packet_id_file)
	packet_id_persist_load (&c->c1.pid_persist, c->options.packet_id_file);
    }

  /* Initialize crypto options */

  if (c->options.use_iv)
    c->c2.crypto_options.flags |= CO_USE_IV;

  if (c->options.mute_replay_warnings)
    c->c2.crypto_options.flags |= CO_MUTE_REPLAY_WARNINGS;
}

/*
 * Static Key Mode (using a pre-shared key)
 */
static void
do_init_crypto_static (struct context *c, const unsigned int flags)
{
  const struct options *options = &c->options;
  ASSERT (options->shared_secret_file);

  init_crypto_pre (c, flags);

  /* Initialize packet ID tracking */
  if (options->replay)
    {
      packet_id_init (&c->c2.packet_id, options->replay_window,
		      options->replay_time);
      c->c2.crypto_options.packet_id = &c->c2.packet_id;
      c->c2.crypto_options.pid_persist = &c->c1.pid_persist;
      c->c2.crypto_options.flags |= CO_PACKET_ID_LONG_FORM;
      packet_id_persist_load_obj (&c->c1.pid_persist,
				  c->c2.crypto_options.packet_id);
    }

  if (!key_ctx_bi_defined (&c->c1.ks.static_key))
    {
      struct key2 key2;
      struct key_direction_state kds;

      /* Get cipher & hash algorithms */
      init_key_type (&c->c1.ks.key_type, options->ciphername,
		     options->ciphername_defined, options->authname,
		     options->authname_defined, options->keysize,
		     options->test_crypto, true);

      /* Read cipher and hmac keys from shared secret file */
      {
	unsigned int rkf_flags = RKF_MUST_SUCCEED;
	const char *rkf_file = options->shared_secret_file;

#if ENABLE_INLINE_FILES
	if (options->shared_secret_file_inline)
	  {
	    rkf_file = options->shared_secret_file_inline;
	    rkf_flags |= RKF_INLINE;
	  }
#endif
	read_key_file (&key2, rkf_file, rkf_flags);
      }

      /* Check for and fix highly unlikely key problems */
      verify_fix_key2 (&key2, &c->c1.ks.key_type,
		       options->shared_secret_file);

      /* Initialize OpenSSL key objects */
      key_direction_state_init (&kds, options->key_direction);
      must_have_n_keys (options->shared_secret_file, "secret", &key2,
			kds.need_keys);
      init_key_ctx (&c->c1.ks.static_key.encrypt, &key2.keys[kds.out_key],
		    &c->c1.ks.key_type, DO_ENCRYPT, "Static Encrypt");
      init_key_ctx (&c->c1.ks.static_key.decrypt, &key2.keys[kds.in_key],
		    &c->c1.ks.key_type, DO_DECRYPT, "Static Decrypt");

      /* Erase the temporary copy of key */
      CLEAR (key2);
    }
  else
    {
      msg (M_INFO, "Re-using pre-shared static key");
    }

  /* Get key schedule */
  c->c2.crypto_options.key_ctx_bi = &c->c1.ks.static_key;

  /* Compute MTU parameters */
  crypto_adjust_frame_parameters (&c->c2.frame,
				  &c->c1.ks.key_type,
				  options->ciphername_defined,
				  options->use_iv, options->replay, true);

  /* Sanity check on IV, sequence number, and cipher mode options */
  check_replay_iv_consistency (&c->c1.ks.key_type, options->replay,
			       options->use_iv);
}

#ifdef USE_SSL

/*
 * Initialize the persistent component of OpenVPN's TLS mode,
 * which is preserved across SIGUSR1 resets.
 */
static void
do_init_crypto_tls_c1 (struct context *c)
{
  const struct options *options = &c->options;

  if (!c->c1.ks.ssl_ctx)
    {
      /*
       * Initialize the OpenSSL library's global
       * SSL context.
       */
      c->c1.ks.ssl_ctx = init_ssl (options);
      if (!c->c1.ks.ssl_ctx)
	{
#if P2MP
	  switch (auth_retry_get ())
	    {
	    case AR_NONE:
	      msg (M_FATAL, "Error: private key password verification failed");
	      break;
	    case AR_INTERACT:
	      ssl_purge_auth ();
	    case AR_NOINTERACT:
	      c->sig->signal_received = SIGUSR1; /* SOFT-SIGUSR1 -- Password failure error */
	      break;
	    default:
	      ASSERT (0);
	    }
	  c->sig->signal_text = "private-key-password-failure";
	  return;
#else
	  msg (M_FATAL, "Error: private key password verification failed");
#endif
	}

      /* Get cipher & hash algorithms */
      init_key_type (&c->c1.ks.key_type, options->ciphername,
		     options->ciphername_defined, options->authname,
		     options->authname_defined, options->keysize, true, true);

      /* Initialize PRNG with config-specified digest */
      prng_init (options->prng_hash, options->prng_nonce_secret_len);

      /* TLS handshake authentication (--tls-auth) */
      if (options->tls_auth_file)
	{
	  unsigned int flags = 0;
	  const char *file = options->tls_auth_file;

#if ENABLE_INLINE_FILES
	  if (options->tls_auth_file_inline)
	    {
	      flags |= GHK_INLINE;
	      file = options->tls_auth_file_inline;
	    }
#endif
	  get_tls_handshake_key (&c->c1.ks.key_type,
				 &c->c1.ks.tls_auth_key,
				 file,
				 options->key_direction,
				 flags);
	}

#if 0 /* was: #if ENABLE_INLINE_FILES --  Note that enabling this code will break restarts */
      if (options->priv_key_file_inline)
	{
	  string_clear (c->options.priv_key_file_inline);
	  c->options.priv_key_file_inline = NULL;
	}
#endif
    }
  else
    {
      msg (M_INFO, "Re-using SSL/TLS context");
    }
}

static void
do_init_crypto_tls (struct context *c, const unsigned int flags)
{
  const struct options *options = &c->options;
  struct tls_options to;
  bool packet_id_long_form;

  ASSERT (options->tls_server || options->tls_client);
  ASSERT (!options->test_crypto);

  init_crypto_pre (c, flags);

  /* Make sure we are either a TLS client or server but not both */
  ASSERT (options->tls_server == !options->tls_client);

  /* initialize persistent component */
  do_init_crypto_tls_c1 (c);
  if (IS_SIG (c))
    return;

  /* Sanity check on IV, sequence number, and cipher mode options */
  check_replay_iv_consistency (&c->c1.ks.key_type, options->replay,
			       options->use_iv);

  /* In short form, unique datagram identifier is 32 bits, in long form 64 bits */
  packet_id_long_form = cfb_ofb_mode (&c->c1.ks.key_type);

  /* Compute MTU parameters */
  crypto_adjust_frame_parameters (&c->c2.frame,
				  &c->c1.ks.key_type,
				  options->ciphername_defined,
				  options->use_iv,
				  options->replay, packet_id_long_form);
  tls_adjust_frame_parameters (&c->c2.frame);

  /* Set all command-line TLS-related options */
  CLEAR (to);

  to.crypto_flags_and = ~(CO_PACKET_ID_LONG_FORM);
  if (packet_id_long_form)
    to.crypto_flags_or = CO_PACKET_ID_LONG_FORM;

  to.ssl_ctx = c->c1.ks.ssl_ctx;
  to.key_type = c->c1.ks.key_type;
  to.server = options->tls_server;
  to.key_method = options->key_method;
  to.replay = options->replay;
  to.replay_window = options->replay_window;
  to.replay_time = options->replay_time;
  to.transition_window = options->transition_window;
  to.handshake_window = options->handshake_window;
  to.packet_timeout = options->tls_timeout;
  to.renegotiate_bytes = options->renegotiate_bytes;
  to.renegotiate_packets = options->renegotiate_packets;
  to.renegotiate_seconds = options->renegotiate_seconds;
  to.single_session = options->single_session;
#ifdef ENABLE_PUSH_PEER_INFO
  to.push_peer_info = options->push_peer_info;
#endif

  /* should we not xmit any packets until we get an initial
     response from client? */
  if (to.server && options->ce.proto == PROTO_TCPv4_SERVER)
    to.xmit_hold = true;

#ifdef ENABLE_OCC
  to.disable_occ = !options->occ;
#endif

  to.verify_command = options->tls_verify;
  to.verify_export_cert = options->tls_export_cert;
  to.verify_x509name = options->tls_remote;
  to.crl_file = options->crl_file;
  to.ns_cert_type = options->ns_cert_type;
  memmove (to.remote_cert_ku, options->remote_cert_ku, sizeof (to.remote_cert_ku));
  to.remote_cert_eku = options->remote_cert_eku;
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
  to.ssl_flags = options->ssl_flags;
  if (options->ccd_exclusive)
    to.client_config_dir_exclusive = options->client_config_dir;
#endif

  /* TLS handshake authentication (--tls-auth) */
  if (options->tls_auth_file)
    {
      to.tls_auth_key = c->c1.ks.tls_auth_key;
      to.tls_auth.pid_persist = &c->c1.pid_persist;
      to.tls_auth.flags |= CO_PACKET_ID_LONG_FORM;
      crypto_adjust_frame_parameters (&to.frame,
				      &c->c1.ks.key_type,
				      false, false, true, true);
    }

  /* If we are running over TCP, allow for
     length prefix */
  socket_adjust_frame_parameters (&to.frame, options->ce.proto);

  /*
   * Initialize OpenVPN's master TLS-mode object.
   */
  if (flags & CF_INIT_TLS_MULTI)
    c->c2.tls_multi = tls_multi_init (&to);

  if (flags & CF_INIT_TLS_AUTH_STANDALONE)
    c->c2.tls_auth_standalone = tls_auth_standalone_init (&to, &c->c2.gc);
}

static void
do_init_finalize_tls_frame (struct context *c)
{
  if (c->c2.tls_multi)
    {
      tls_multi_init_finalize (c->c2.tls_multi, &c->c2.frame);
      ASSERT (EXPANDED_SIZE (&c->c2.tls_multi->opt.frame) <=
	      EXPANDED_SIZE (&c->c2.frame));
      frame_print (&c->c2.tls_multi->opt.frame, D_MTU_INFO,
		   "Control Channel MTU parms");
    }
  if (c->c2.tls_auth_standalone)
    {
      tls_auth_standalone_finalize (c->c2.tls_auth_standalone, &c->c2.frame);
      frame_print (&c->c2.tls_auth_standalone->frame, D_MTU_INFO,
		   "TLS-Auth MTU parms");
    }
}

#endif /* USE_SSL */
#endif /* USE_CRYPTO */

#ifdef USE_CRYPTO
/*
 * No encryption or authentication.
 */
static void
do_init_crypto_none (const struct context *c)
{
  ASSERT (!c->options.test_crypto);
  msg (M_WARN,
       "******* WARNING *******: all encryption and authentication features disabled -- all data will be tunnelled as cleartext");
}
#endif

static void
do_init_crypto (struct context *c, const unsigned int flags)
{
#ifdef USE_CRYPTO
  if (c->options.shared_secret_file)
    do_init_crypto_static (c, flags);
#ifdef USE_SSL
  else if (c->options.tls_server || c->options.tls_client)
    do_init_crypto_tls (c, flags);
#endif
  else				/* no encryption or authentication. */
    do_init_crypto_none (c);
#else /* USE_CRYPTO */
  msg (M_WARN,
       "******* WARNING *******: " PACKAGE_NAME
       " built without OpenSSL -- encryption and authentication features disabled -- all data will be tunnelled as cleartext");
#endif /* USE_CRYPTO */
}

static void
do_init_frame (struct context *c)
{
#ifdef USE_LZO
  /*
   * Initialize LZO compression library.
   */
  if (c->options.lzo & LZO_SELECTED)
    {
      lzo_adjust_frame_parameters (&c->c2.frame);

      /*
       * LZO usage affects buffer alignment.
       */
      if (CIPHER_ENABLED (c))
	{
	  frame_add_to_align_adjust (&c->c2.frame, LZO_PREFIX_LEN);
	  frame_or_align_flags (&c->c2.frame,
				FRAME_HEADROOM_MARKER_FRAGMENT
				|FRAME_HEADROOM_MARKER_DECRYPT);
	}

#ifdef ENABLE_FRAGMENT
      lzo_adjust_frame_parameters (&c->c2.frame_fragment_omit);	/* omit LZO frame delta from final frame_fragment */
#endif
    }
#endif /* USE_LZO */

#ifdef ENABLE_SOCKS
  /*
   * Adjust frame size for UDP Socks support.
   */
  if (c->options.ce.socks_proxy_server)
    socks_adjust_frame_parameters (&c->c2.frame, c->options.ce.proto);
#endif

  /*
   * Adjust frame size based on the --tun-mtu-extra parameter.
   */
  if (c->options.tun_mtu_extra_defined)
    tun_adjust_frame_parameters (&c->c2.frame, c->options.tun_mtu_extra);

  /*
   * Adjust frame size based on link socket parameters.
   * (Since TCP is a stream protocol, we need to insert
   * a packet length uint16_t in the buffer.)
   */
  socket_adjust_frame_parameters (&c->c2.frame, c->options.ce.proto);

  /*
   * Fill in the blanks in the frame parameters structure,
   * make sure values are rational, etc.
   */
  frame_finalize_options (c, NULL);

#ifdef ENABLE_FRAGMENT
  /*
   * Set frame parameter for fragment code.  This is necessary because
   * the fragmentation code deals with payloads which have already been
   * passed through the compression code.
   */
  c->c2.frame_fragment = c->c2.frame;
  frame_subtract_extra (&c->c2.frame_fragment, &c->c2.frame_fragment_omit);
#endif

#if defined(ENABLE_FRAGMENT) && defined(ENABLE_OCC)
  /*
   * MTU advisories
   */
  if (c->options.fragment && c->options.mtu_test)
    msg (M_WARN,
	 "WARNING: using --fragment and --mtu-test together may produce an inaccurate MTU test result");
#endif

#ifdef ENABLE_FRAGMENT
  if ((c->options.mssfix || c->options.fragment)
      && TUN_MTU_SIZE (&c->c2.frame_fragment) != ETHERNET_MTU)
    msg (M_WARN,
	 "WARNING: normally if you use --mssfix and/or --fragment, you should also set --tun-mtu %d (currently it is %d)",
	 ETHERNET_MTU, TUN_MTU_SIZE (&c->c2.frame_fragment));
#endif
}

static void
do_option_warnings (struct context *c)
{
  const struct options *o = &c->options;

#if 1 /* JYFIXME -- port warning */
  if (!o->ce.port_option_used && (o->ce.local_port == OPENVPN_PORT && o->ce.remote_port == OPENVPN_PORT))
    msg (M_WARN, "IMPORTANT: OpenVPN's default port number is now %d, based on an official port number assignment by IANA.  OpenVPN 2.0-beta16 and earlier used 5000 as the default port.",
	 OPENVPN_PORT);
#endif

  if (o->ping_send_timeout && !o->ping_rec_timeout)
    msg (M_WARN, "WARNING: --ping should normally be used with --ping-restart or --ping-exit");

  if (o->username || o->groupname || o->chroot_dir
#ifdef HAVE_SETCON
      || o->selinux_context
#endif
      )
   {
    if (!o->persist_tun)
     msg (M_WARN, "WARNING: you are using user/group/chroot/setcon without persist-tun -- this may cause restarts to fail");
    if (!o->persist_key
#ifdef ENABLE_PKCS11
	&& !o->pkcs11_id
#endif
	)
     msg (M_WARN, "WARNING: you are using user/group/chroot/setcon without persist-key -- this may cause restarts to fail");
   }

  if (o->chroot_dir && !(o->username && o->groupname))
    msg (M_WARN, "WARNING: you are using chroot without specifying user and group -- this may cause the chroot jail to be insecure");

#if P2MP
  if (o->pull && o->ifconfig_local && c->first_time)
    msg (M_WARN, "WARNING: using --pull/--client and --ifconfig together is probably not what you want");

#if P2MP_SERVER
  if (o->server_bridge_defined | o->server_bridge_proxy_dhcp)
    msg (M_WARN, "NOTE: when bridging your LAN adapter with the TAP adapter, note that the new bridge adapter will often take on its own IP address that is different from what the LAN adapter was previously set to");

  if (o->mode == MODE_SERVER)
    {
      if (o->duplicate_cn && o->client_config_dir)
	msg (M_WARN, "WARNING: using --duplicate-cn and --client-config-dir together is probably not what you want");
      if (o->duplicate_cn && o->ifconfig_pool_persist_filename)
	msg (M_WARN, "WARNING: --ifconfig-pool-persist will not work with --duplicate-cn");
      if (!o->keepalive_ping || !o->keepalive_timeout)
	msg (M_WARN, "WARNING: --keepalive option is missing from server config");
    }
#endif
#endif

#ifdef USE_CRYPTO
  if (!o->replay)
    msg (M_WARN, "WARNING: You have disabled Replay Protection (--no-replay) which may make " PACKAGE_NAME " less secure");
  if (!o->use_iv)
    msg (M_WARN, "WARNING: You have disabled Crypto IVs (--no-iv) which may make " PACKAGE_NAME " less secure");

#ifdef USE_SSL
  if (o->tls_server)
    warn_on_use_of_common_subnets ();
  if (o->tls_client
      && !o->tls_verify
      && !o->tls_remote
      && !(o->ns_cert_type & NS_SSL_SERVER)
      && !o->remote_cert_eku)
    msg (M_WARN, "WARNING: No server certificate verification method has been enabled.  See http://openvpn.net/howto.html#mitm for more info.");
  if (o->tls_remote)
    msg (M_WARN, "WARNING: Make sure you understand the semantics of --tls-remote before using it (see the man page).");
#endif
#endif

#ifndef CONNECT_NONBLOCK
  if (o->ce.connect_timeout_defined)
    msg (M_WARN, "NOTE: --connect-timeout option is not supported on this OS");
#endif

  if (script_security >= SSEC_SCRIPTS)
    msg (M_WARN, "NOTE: the current --script-security setting may allow this configuration to call user-defined scripts");
  else if (script_security >= SSEC_PW_ENV)
    msg (M_WARN, "WARNING: the current --script-security setting may allow passwords to be passed to scripts via environmental variables");
  else
    msg (M_WARN, "NOTE: " PACKAGE_NAME " 2.1 requires '--script-security 2' or higher to call user-defined scripts or executables");

  if (script_method == SM_SYSTEM)
    msg (M_WARN, "NOTE: --script-security method='system' is deprecated due to the fact that passed parameters will be subject to shell expansion");
}

static void
do_init_frame_tls (struct context *c)
{
#if defined(USE_CRYPTO) && defined(USE_SSL)
  do_init_finalize_tls_frame (c);
#endif
}

struct context_buffers *
init_context_buffers (const struct frame *frame)
{
  struct context_buffers *b;

  ALLOC_OBJ_CLEAR (b, struct context_buffers);

  b->read_link_buf = alloc_buf (BUF_SIZE (frame));
  b->read_tun_buf = alloc_buf (BUF_SIZE (frame));

  b->aux_buf = alloc_buf (BUF_SIZE (frame));

#ifdef USE_CRYPTO
  b->encrypt_buf = alloc_buf (BUF_SIZE (frame));
  b->decrypt_buf = alloc_buf (BUF_SIZE (frame));
#endif

#ifdef USE_LZO
  b->lzo_compress_buf = alloc_buf (BUF_SIZE (frame));
  b->lzo_decompress_buf = alloc_buf (BUF_SIZE (frame));
#endif

  return b;
}

void
free_context_buffers (struct context_buffers *b)
{
  if (b)
    {
      free_buf (&b->read_link_buf);
      free_buf (&b->read_tun_buf);
      free_buf (&b->aux_buf);

#ifdef USE_LZO
      free_buf (&b->lzo_compress_buf);
      free_buf (&b->lzo_decompress_buf);
#endif

#ifdef USE_CRYPTO
      free_buf (&b->encrypt_buf);
      free_buf (&b->decrypt_buf);
#endif

      free (b);
    }
}

/*
 * Now that we know all frame parameters, initialize
 * our buffers.
 */
static void
do_init_buffers (struct context *c)
{
  c->c2.buffers = init_context_buffers (&c->c2.frame);
  c->c2.buffers_owned = true;
}

#ifdef ENABLE_FRAGMENT
/*
 * Fragmenting code has buffers to initialize
 * once frame parameters are known.
 */
static void
do_init_fragment (struct context *c)
{
  ASSERT (c->options.fragment);
  frame_set_mtu_dynamic (&c->c2.frame_fragment,
			 c->options.fragment, SET_MTU_UPPER_BOUND);
  fragment_frame_init (c->c2.fragment, &c->c2.frame_fragment);
}
#endif

/*
 * Set the --mssfix option.
 */
static void
do_init_mssfix (struct context *c)
{
  if (c->options.mssfix)
    {
      frame_set_mtu_dynamic (&c->c2.frame,
			     c->options.mssfix, SET_MTU_UPPER_BOUND);
    }
}

/*
 * Allocate our socket object.
 */
static void
do_link_socket_new (struct context *c)
{
  ASSERT (!c->c2.link_socket);
  c->c2.link_socket = link_socket_new ();
  c->c2.link_socket_owned = true;
}

/*
 * bind the TCP/UDP socket
 */
static void
do_init_socket_1 (struct context *c, const int mode)
{
  unsigned int sockflags = c->options.sockflags;

#if PORT_SHARE
  if (c->options.port_share_host && c->options.port_share_port)
    sockflags |= SF_PORT_SHARE;
#endif

  link_socket_init_phase1 (c->c2.link_socket,
			   connection_list_defined (&c->options),
			   c->options.ce.local,
			   c->options.ce.local_port,
			   c->options.ce.remote,
			   c->options.ce.remote_port,
			   c->options.ce.proto,
			   mode,
			   c->c2.accept_from,
#ifdef ENABLE_HTTP_PROXY
			   c->c1.http_proxy,
#endif
#ifdef ENABLE_SOCKS
			   c->c1.socks_proxy,
#endif
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
			   c->options.ce.connect_retry_seconds,
			   c->options.ce.connect_timeout,
			   c->options.ce.connect_retry_max,
			   c->options.mtu_discover_type,
			   c->options.rcvbuf,
			   c->options.sndbuf,
			   sockflags);
}

/*
 * finalize the TCP/UDP socket
 */
static void
do_init_socket_2 (struct context *c)
{
  link_socket_init_phase2 (c->c2.link_socket, &c->c2.frame,
			   &c->sig->signal_received);
}

/*
 * Print MTU INFO
 */
static void
do_print_data_channel_mtu_parms (struct context *c)
{
  frame_print (&c->c2.frame, D_MTU_INFO, "Data Channel MTU parms");
#ifdef ENABLE_FRAGMENT
  if (c->c2.fragment)
    frame_print (&c->c2.frame_fragment, D_MTU_INFO,
		 "Fragmentation MTU parms");
#endif
}

#ifdef ENABLE_OCC
/*
 * Get local and remote options compatibility strings.
 */
static void
do_compute_occ_strings (struct context *c)
{
  struct gc_arena gc = gc_new ();

  c->c2.options_string_local =
    options_string (&c->options, &c->c2.frame, c->c1.tuntap, false, &gc);
  c->c2.options_string_remote =
    options_string (&c->options, &c->c2.frame, c->c1.tuntap, true, &gc);

  msg (D_SHOW_OCC, "Local Options String: '%s'", c->c2.options_string_local);
  msg (D_SHOW_OCC, "Expected Remote Options String: '%s'",
       c->c2.options_string_remote);

#ifdef USE_CRYPTO
  msg (D_SHOW_OCC_HASH, "Local Options hash (VER=%s): '%s'",
       options_string_version (c->c2.options_string_local, &gc),
       md5sum ((uint8_t*)c->c2.options_string_local,
	       strlen (c->c2.options_string_local), 9, &gc));
  msg (D_SHOW_OCC_HASH, "Expected Remote Options hash (VER=%s): '%s'",
       options_string_version (c->c2.options_string_remote, &gc),
       md5sum ((uint8_t*)c->c2.options_string_remote,
	       strlen (c->c2.options_string_remote), 9, &gc));
#endif

#if defined(USE_CRYPTO) && defined(USE_SSL)
  if (c->c2.tls_multi)
    tls_multi_init_set_options (c->c2.tls_multi,
				c->c2.options_string_local,
				c->c2.options_string_remote);
#endif

  gc_free (&gc);
}
#endif

/*
 * These things can only be executed once per program instantiation.
 * Set up for possible UID/GID downgrade, but don't do it yet.
 * Daemonize if requested.
 */
static void
do_init_first_time (struct context *c)
{
  if (c->first_time && !c->did_we_daemonize && !c->c0)
    {
      struct context_0 *c0;

      ALLOC_OBJ_CLEAR_GC (c->c0, struct context_0, &c->gc);
      c0 = c->c0;
      
      /* get user and/or group that we want to setuid/setgid to */
      c0->uid_gid_specified =
	get_group (c->options.groupname, &c0->group_state) |
	get_user (c->options.username, &c0->user_state);

      /* get --writepid file descriptor */
      get_pid_file (c->options.writepid, &c0->pid_state);

      /* become a daemon if --daemon */
      c->did_we_daemonize = possibly_become_daemon (&c->options, c->first_time);

      /* should we disable paging? */
      if (c->options.mlock && c->did_we_daemonize)
	do_mlockall (true);	/* call again in case we daemonized */

      /* save process ID in a file */
      write_pid (&c0->pid_state);

      /* should we change scheduling priority? */
      set_nice (c->options.nice);
    }
}

/*
 * If xinetd/inetd mode, don't allow restart.
 */
static void
do_close_check_if_restart_permitted (struct context *c)
{
  if (c->options.inetd
      && (c->sig->signal_received == SIGHUP
	  || c->sig->signal_received == SIGUSR1))
    {
      c->sig->signal_received = SIGTERM;
      msg (M_INFO,
	   PACKAGE_NAME
	   " started by inetd/xinetd cannot restart... Exiting.");
    }
}

/*
 * free buffers
 */
static void
do_close_free_buf (struct context *c)
{
  if (c->c2.buffers_owned)
    {
      free_context_buffers (c->c2.buffers);
      c->c2.buffers = NULL;
      c->c2.buffers_owned = false;
    }
}

/*
 * close TLS
 */
static void
do_close_tls (struct context *c)
{
#if defined(USE_CRYPTO) && defined(USE_SSL)
  if (c->c2.tls_multi)
    {
      tls_multi_free (c->c2.tls_multi, true);
      c->c2.tls_multi = NULL;
    }

#ifdef ENABLE_OCC
  /* free options compatibility strings */
  if (c->c2.options_string_local)
    free (c->c2.options_string_local);
  if (c->c2.options_string_remote)
    free (c->c2.options_string_remote);
  c->c2.options_string_local = c->c2.options_string_remote = NULL;
#endif
#endif
}

/*
 * Free key schedules
 */
static void
do_close_free_key_schedule (struct context *c, bool free_ssl_ctx)
{
  if (!(c->sig->signal_received == SIGUSR1 && c->options.persist_key))
    key_schedule_free (&c->c1.ks, free_ssl_ctx);
}

/*
 * Close TCP/UDP connection
 */
static void
do_close_link_socket (struct context *c)
{
  if (c->c2.link_socket && c->c2.link_socket_owned)
    {
      link_socket_close (c->c2.link_socket);
      c->c2.link_socket = NULL;
    }

  if (!(c->sig->signal_received == SIGUSR1 && c->options.persist_remote_ip))
    {
      CLEAR (c->c1.link_socket_addr.remote);
      CLEAR (c->c1.link_socket_addr.actual);
    }

  if (!(c->sig->signal_received == SIGUSR1 && c->options.persist_local_ip))
    CLEAR (c->c1.link_socket_addr.local);
}

/*
 * Close packet-id persistance file
 */
static void
do_close_packet_id (struct context *c)
{
#ifdef USE_CRYPTO
  packet_id_free (&c->c2.packet_id);
  packet_id_persist_save (&c->c1.pid_persist);
  if (!(c->sig->signal_received == SIGUSR1))
    packet_id_persist_close (&c->c1.pid_persist);
#endif
}

#ifdef ENABLE_FRAGMENT
/*
 * Close fragmentation handler.
 */
static void
do_close_fragment (struct context *c)
{
  if (c->c2.fragment)
    {
      fragment_free (c->c2.fragment);
      c->c2.fragment = NULL;
    }
}
#endif

/*
 * Open and close our event objects.
 */

static void
do_event_set_init (struct context *c,
		   bool need_us_timeout)
{
  unsigned int flags = 0;

  c->c2.event_set_max = BASE_N_EVENTS;

  flags |= EVENT_METHOD_FAST;

  if (need_us_timeout)
    flags |= EVENT_METHOD_US_TIMEOUT;

  c->c2.event_set = event_set_init (&c->c2.event_set_max, flags);
  c->c2.event_set_owned = true;
}

static void
do_close_event_set (struct context *c)
{
  if (c->c2.event_set && c->c2.event_set_owned)
    {
      event_free (c->c2.event_set);
      c->c2.event_set = NULL;
      c->c2.event_set_owned = false;
    }
}

/*
 * Open and close --status file
 */

static void
do_open_status_output (struct context *c)
{
  if (!c->c1.status_output)
    {
      c->c1.status_output = status_open (c->options.status_file,
					 c->options.status_file_update_freq,
					 -1,
					 NULL,
					 STATUS_OUTPUT_WRITE);
      c->c1.status_output_owned = true;
    }
}

static void
do_close_status_output (struct context *c)
{
  if (!(c->sig->signal_received == SIGUSR1))
    {
      if (c->c1.status_output_owned && c->c1.status_output)
	{
	  status_close (c->c1.status_output);
	  c->c1.status_output = NULL;
	  c->c1.status_output_owned = false;
	}
    }
}

/*
 * Handle ifconfig-pool persistance object.
 */
static void
do_open_ifconfig_pool_persist (struct context *c)
{
#if P2MP_SERVER
  if (!c->c1.ifconfig_pool_persist && c->options.ifconfig_pool_persist_filename)
    {
      c->c1.ifconfig_pool_persist = ifconfig_pool_persist_init (c->options.ifconfig_pool_persist_filename,
								c->options.ifconfig_pool_persist_refresh_freq);
      c->c1.ifconfig_pool_persist_owned = true;
    }
#endif
}

static void
do_close_ifconfig_pool_persist (struct context *c)
{
#if P2MP_SERVER
  if (!(c->sig->signal_received == SIGUSR1))
    {
      if (c->c1.ifconfig_pool_persist && c->c1.ifconfig_pool_persist_owned)
	{
	  ifconfig_pool_persist_close (c->c1.ifconfig_pool_persist);
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
do_inherit_env (struct context *c, const struct env_set *src)
{
  c->c2.es = env_set_create (NULL);
  c->c2.es_owned = true;
  env_set_inherit (c->c2.es, src);
}

static void
do_env_set_destroy (struct context *c)
{
  if (c->c2.es && c->c2.es_owned)
    {
      env_set_destroy (c->c2.es);
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
do_setup_fast_io (struct context *c)
{
  if (c->options.fast_io)
    {
#ifdef WIN32
      msg (M_INFO, "NOTE: --fast-io is disabled since we are running on Windows");
#else
      if (c->options.ce.proto != PROTO_UDPv4)
	msg (M_INFO, "NOTE: --fast-io is disabled since we are not using UDP");
      else
	{
#ifdef HAVE_GETTIMEOFDAY
	  if (c->options.shaper)
	    msg (M_INFO, "NOTE: --fast-io is disabled since we are using --shaper");
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
do_signal_on_tls_errors (struct context *c)
{
#if defined(USE_CRYPTO) && defined(USE_SSL)
  if (c->options.tls_exit)
    c->c2.tls_exit_signal = SIGTERM;
  else
    c->c2.tls_exit_signal = SIGUSR1;    
#endif
}

#ifdef ENABLE_PLUGIN

void
init_plugins (struct context *c)
{
  if (c->options.plugin_list && !c->plugins)
    {
      c->plugins = plugin_list_init (c->options.plugin_list);
      c->plugins_owned = true;
    }
}

void
open_plugins (struct context *c, const bool import_options, int init_point)
{
  if (c->plugins && c->plugins_owned)
    {
      if (import_options)
	{
	  struct plugin_return pr, config;
	  plugin_return_init (&pr);
	  plugin_list_open (c->plugins, c->options.plugin_list, &pr, c->c2.es, init_point);
	  plugin_return_get_column (&pr, &config, "config");
	  if (plugin_return_defined (&config))
	    {
	      int i;
	      for (i = 0; i < config.n; ++i)
		{
		  unsigned int option_types_found = 0;
		  if (config.list[i] && config.list[i]->value)
		    options_string_import (&c->options,
					   config.list[i]->value,
					   D_IMPORT_ERRORS|M_OPTERR,
					   OPT_P_DEFAULT & ~OPT_P_PLUGIN,
					   &option_types_found,
					   c->es);
		}
	    }
	  plugin_return_free (&pr);
	}
      else
	{
	  plugin_list_open (c->plugins, c->options.plugin_list, NULL, c->c2.es, init_point);
	}
    }
}

static void
do_close_plugins (struct context *c)
{
  if (c->plugins && c->plugins_owned && !(c->sig->signal_received == SIGUSR1))
    {
      plugin_list_close (c->plugins);
      c->plugins = NULL;
      c->plugins_owned = false;
    }
}

static void
do_inherit_plugins (struct context *c, const struct context *src)
{
  if (!c->plugins && src->plugins)
    {
      c->plugins = plugin_list_inherit (src->plugins);
      c->plugins_owned = true;
    }
}

#endif

#ifdef ENABLE_MANAGEMENT

static void
management_callback_status_p2p (void *arg, const int version, struct status_output *so)
{
  struct context *c = (struct context *) arg;
  print_status (c, so);
}

void
management_show_net_callback (void *arg, const int msglevel)
{
#ifdef WIN32
  show_routes (msglevel);
  show_adapters (msglevel);
  msg (msglevel, "END");
#else
  msg (msglevel, "ERROR: Sorry, this command is currently only implemented on Windows");
#endif
}

#endif

void
init_management_callback_p2p (struct context *c)
{
#ifdef ENABLE_MANAGEMENT
  if (management)
    {
      struct management_callback cb;
      CLEAR (cb);
      cb.arg = c;
      cb.status = management_callback_status_p2p;
      cb.show_net = management_show_net_callback;
#if HTTP_PROXY_FALLBACK
      cb.http_proxy_fallback_cmd = management_callback_http_proxy_fallback_cmd;
#endif
      management_set_callback (management, &cb);
    }
#endif
}

#ifdef ENABLE_MANAGEMENT

void
init_management (struct context *c)
{
  if (!management)
    management = management_init ();
}

bool
open_management (struct context *c)
{
  /* initialize management layer */
  if (management)
    {
      if (c->options.management_addr)
	{
	  unsigned int flags = c->options.management_flags;
	  if (c->options.mode == MODE_SERVER)
	    flags |= MF_SERVER;
	  if (management_open (management,
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
	      management_set_state (management,
				    OPENVPN_STATE_CONNECTING,
				    NULL,
				    (in_addr_t)0,
				    (in_addr_t)0);
	    }

	  /* initial management hold, called early, before first context initialization */
	  do_hold (c);
	  if (IS_SIG (c))
	    {
	      msg (M_WARN, "Signal received from management interface, exiting");
	      return false;
	    }
	}
      else
	close_management ();
    }
  return true;
}

void
close_management (void)
{
  if (management)
    {
      management_close (management);
      management = NULL;
    }
}

#endif


void
uninit_management_callback (void)
{
#ifdef ENABLE_MANAGEMENT
  if (management)
    {
      management_clear_callback (management);
    }
#endif
}

/*
 * Initialize a tunnel instance, handle pre and post-init
 * signal settings.
 */
void
init_instance_handle_signals (struct context *c, const struct env_set *env, const unsigned int flags)
{
  pre_init_signal_catch ();
  init_instance (c, env, flags);
  post_init_signal_catch ();

  /*
   * This is done so that signals thrown during
   * initialization can bring us back to
   * a management hold.
   */
  if (IS_SIG (c))
    {
      remap_signal (c);
      uninit_management_callback ();  
    }
}

/*
 * Initialize a tunnel instance.
 */
void
init_instance (struct context *c, const struct env_set *env, const unsigned int flags)
{
  const struct options *options = &c->options;
  const bool child = (c->mode == CM_CHILD_TCP || c->mode == CM_CHILD_UDP);
  int link_socket_mode = LS_MODE_DEFAULT;

  /* init garbage collection level */
  gc_init (&c->c2.gc);

  /* signals caught here will abort */
  c->sig->signal_received = 0;
  c->sig->signal_text = NULL;
  c->sig->hard = false;

  if (c->mode == CM_P2P)
    init_management_callback_p2p (c);

  /* possible sleep or management hold if restart */
  if (c->mode == CM_P2P || c->mode == CM_TOP)
    {
      do_startup_pause (c);
      if (IS_SIG (c))
	goto sig;
    }

  /* map in current connection entry */
  next_connection_entry (c);

  /* link_socket_mode allows CM_CHILD_TCP
     instances to inherit acceptable fds
     from a top-level parent */
  if (c->options.ce.proto == PROTO_TCPv4_SERVER)
    {
      if (c->mode == CM_TOP)
	link_socket_mode = LS_MODE_TCP_LISTEN;
      else if (c->mode == CM_CHILD_TCP)
	link_socket_mode = LS_MODE_TCP_ACCEPT_FROM;
    }

  /* should we disable paging? */
  if (c->first_time && options->mlock)
    do_mlockall (true);

#if P2MP
  /* get passwords if undefined */
  if (auth_retry_get () == AR_INTERACT)
    init_query_passwords (c);
#endif

  /* initialize context level 2 --verb/--mute parms */
  init_verb_mute (c, IVM_LEVEL_2);

  /* set error message delay for non-server modes */
  if (c->mode == CM_P2P)
    set_check_status_error_delay (P2P_ERROR_DELAY_MS);
    
  /* warn about inconsistent options */
  if (c->mode == CM_P2P || c->mode == CM_TOP)
    do_option_warnings (c);

  /* inherit environmental variables */
  if (env)
    do_inherit_env (c, env);

#ifdef ENABLE_PLUGIN
  /* initialize plugins */
  if (c->mode == CM_P2P || c->mode == CM_TOP)
    open_plugins (c, false, OPENVPN_PLUGIN_INIT_PRE_DAEMON);
#endif

  /* should we enable fast I/O? */
  if (c->mode == CM_P2P || c->mode == CM_TOP)
    do_setup_fast_io (c);

  /* should we throw a signal on TLS errors? */
  do_signal_on_tls_errors (c);

  /* open --status file */
  if (c->mode == CM_P2P || c->mode == CM_TOP)
    do_open_status_output (c);

  /* open --ifconfig-pool-persist file */
  if (c->mode == CM_TOP)
    do_open_ifconfig_pool_persist (c);

#ifdef ENABLE_OCC
  /* reset OCC state */
  if (c->mode == CM_P2P || child)
    c->c2.occ_op = occ_reset_op ();
#endif

  /* our wait-for-i/o objects, different for posix vs. win32 */
  if (c->mode == CM_P2P)
    do_event_set_init (c, SHAPER_DEFINED (&c->options));
  else if (c->mode == CM_CHILD_TCP)
    do_event_set_init (c, false);

  /* initialize HTTP or SOCKS proxy object at scope level 2 */
  init_proxy (c, 2);

  /* allocate our socket object */
  if (c->mode == CM_P2P || c->mode == CM_TOP || c->mode == CM_CHILD_TCP)
    do_link_socket_new (c);

#ifdef ENABLE_FRAGMENT
  /* initialize internal fragmentation object */
  if (options->fragment && (c->mode == CM_P2P || child))
    c->c2.fragment = fragment_init (&c->c2.frame);
#endif

  /* init crypto layer */
  {
    unsigned int crypto_flags = 0;
    if (c->mode == CM_TOP)
      crypto_flags = CF_INIT_TLS_AUTH_STANDALONE;
    else if (c->mode == CM_P2P)
      crypto_flags = CF_LOAD_PERSISTED_PACKET_ID | CF_INIT_TLS_MULTI;
    else if (child)
      crypto_flags = CF_INIT_TLS_MULTI;
    do_init_crypto (c, crypto_flags);
    if (IS_SIG (c) && !child)
      goto sig;
  }

#ifdef USE_LZO
  /* initialize LZO compression library. */
  if ((options->lzo & LZO_SELECTED) && (c->mode == CM_P2P || child))
    lzo_compress_init (&c->c2.lzo_compwork, options->lzo);
#endif

  /* initialize MTU variables */
  do_init_frame (c);

  /* initialize TLS MTU variables */
  do_init_frame_tls (c);

  /* init workspace buffers whose size is derived from frame size */
  if (c->mode == CM_P2P || c->mode == CM_CHILD_TCP)
    do_init_buffers (c);

#ifdef ENABLE_FRAGMENT
  /* initialize internal fragmentation capability with known frame size */
  if (options->fragment && (c->mode == CM_P2P || child))
    do_init_fragment (c);
#endif

  /* initialize dynamic MTU variable */
  do_init_mssfix (c);

  /* bind the TCP/UDP socket */
  if (c->mode == CM_P2P || c->mode == CM_TOP || c->mode == CM_CHILD_TCP)
    do_init_socket_1 (c, link_socket_mode);

  /* initialize tun/tap device object,
     open tun/tap device, ifconfig, run up script, etc. */
  if (!(options->up_delay || PULL_DEFINED (options)) && (c->mode == CM_P2P || c->mode == CM_TOP))
    c->c2.did_open_tun = do_open_tun (c);

  /* print MTU info */
  do_print_data_channel_mtu_parms (c);

#ifdef ENABLE_OCC
  /* get local and remote options compatibility strings */
  if (c->mode == CM_P2P || child)
    do_compute_occ_strings (c);
#endif

  /* initialize output speed limiter */
  if (c->mode == CM_P2P)
    do_init_traffic_shaper (c);

  /* do one-time inits, and possibily become a daemon here */
  do_init_first_time (c);

#ifdef ENABLE_PLUGIN
  /* initialize plugins */
  if (c->mode == CM_P2P || c->mode == CM_TOP)
    open_plugins (c, false, OPENVPN_PLUGIN_INIT_POST_DAEMON);
#endif

  /*
   * Actually do UID/GID downgrade, and chroot, if requested.
   * May be delayed by --client, --pull, or --up-delay.
   */
  do_uid_gid_chroot (c, c->c2.did_open_tun);

  /* finalize the TCP/UDP socket */
  if (c->mode == CM_P2P || c->mode == CM_TOP || c->mode == CM_CHILD_TCP)
    do_init_socket_2 (c);

  /* initialize timers */
  if (c->mode == CM_P2P || child)
    do_init_timers (c, false);

#ifdef ENABLE_PLUGIN
  /* initialize plugins */
  if (c->mode == CM_P2P || c->mode == CM_TOP)
    open_plugins (c, false, OPENVPN_PLUGIN_INIT_POST_UID_CHANGE);
#endif

#if PORT_SHARE
  /* share OpenVPN port with foreign (such as HTTPS) server */
  if (c->first_time && (c->mode == CM_P2P || c->mode == CM_TOP))
    init_port_share (c);
#endif
	  
#ifdef ENABLE_PF
  if (child)
    pf_init_context (c);
#endif

  /* Check for signals */
  if (IS_SIG (c))
    goto sig;

  return;

 sig:
  if (!c->sig->signal_text)
    c->sig->signal_text = "init_instance";
  close_context (c, -1, flags);
  return;
}

/*
 * Close a tunnel instance.
 */
void
close_instance (struct context *c)
{
  /* close event objects */
  do_close_event_set (c);

    if (c->mode == CM_P2P
	|| c->mode == CM_CHILD_TCP
	|| c->mode == CM_CHILD_UDP
	|| c->mode == CM_TOP)
      {
	/* if xinetd/inetd mode, don't allow restart */
	do_close_check_if_restart_permitted (c);

#ifdef USE_LZO
	if (lzo_defined (&c->c2.lzo_compwork))
	  lzo_compress_uninit (&c->c2.lzo_compwork);
#endif

	/* free buffers */
	do_close_free_buf (c);

	/* close TLS */
	do_close_tls (c);

	/* free key schedules */
	do_close_free_key_schedule (c, (c->mode == CM_P2P || c->mode == CM_TOP));

	/* close TCP/UDP connection */
	do_close_link_socket (c);

	/* close TUN/TAP device */
	do_close_tun (c, false);

#ifdef MANAGEMENT_DEF_AUTH
	if (management)
	  management_notify_client_close (management, &c->c2.mda_context, NULL);
#endif

#ifdef ENABLE_PF
	pf_destroy_context (&c->c2.pf);
#endif

#ifdef ENABLE_PLUGIN
	/* call plugin close functions and unload */
	do_close_plugins (c);
#endif

	/* close packet-id persistance file */
	do_close_packet_id (c);

	/* close --status file */
	do_close_status_output (c);

#ifdef ENABLE_FRAGMENT
	/* close fragmentation handler */
	do_close_fragment (c);
#endif

	/* close --ifconfig-pool-persist obj */
	do_close_ifconfig_pool_persist (c);

	/* free up environmental variable store */
	do_env_set_destroy (c);

	/* close HTTP or SOCKS proxy */
	uninit_proxy (c);

	/* garbage collect */
	gc_free (&c->c2.gc);
      }
}

void
inherit_context_child (struct context *dest,
		       const struct context *src)
{
  CLEAR (*dest);

  switch (src->options.ce.proto)
    {
    case PROTO_UDPv4:
      dest->mode = CM_CHILD_UDP;
      break;
    case PROTO_TCPv4_SERVER:
      dest->mode = CM_CHILD_TCP;
      break;
    default:
      ASSERT (0);
    }

  dest->gc = gc_new ();

  ALLOC_OBJ_CLEAR_GC (dest->sig, struct signal_info, &dest->gc);

  /* c1 init */
  packet_id_persist_init (&dest->c1.pid_persist);

#ifdef USE_CRYPTO
  dest->c1.ks.key_type = src->c1.ks.key_type;
#ifdef USE_SSL
  /* inherit SSL context */
  dest->c1.ks.ssl_ctx = src->c1.ks.ssl_ctx;
  dest->c1.ks.tls_auth_key = src->c1.ks.tls_auth_key;
#endif
#endif

  /* options */
  dest->options = src->options;
  options_detach (&dest->options);

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
  do_inherit_plugins (dest, src);
#endif

  /* context init */
  init_instance (dest, src->c2.es, CC_NO_CLOSE | CC_USR1_TO_HUP);
  if (IS_SIG (dest))
    return;

  /* inherit tun/tap interface object */
  dest->c1.tuntap = src->c1.tuntap;

  /* UDP inherits some extra things which TCP does not */
  if (dest->mode == CM_CHILD_UDP)
    {
      /* inherit buffers */
      dest->c2.buffers = src->c2.buffers;

      /* inherit parent link_socket and tuntap */
      dest->c2.link_socket = src->c2.link_socket;

      ALLOC_OBJ_GC (dest->c2.link_socket_info, struct link_socket_info, &dest->gc);
      *dest->c2.link_socket_info = src->c2.link_socket->info;

      /* locally override some link_socket_info fields */
      dest->c2.link_socket_info->lsa = &dest->c1.link_socket_addr;
      dest->c2.link_socket_info->connection_established = false;
    }
}

void
inherit_context_top (struct context *dest,
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

  options_detach (&dest->options);
  gc_detach (&dest->gc);
  gc_detach (&dest->c2.gc);

  /* detach plugins */
  dest->plugins_owned = false;

#if defined(USE_CRYPTO) && defined(USE_SSL)
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
  if (src->options.ce.proto == PROTO_UDPv4)
    do_event_set_init (dest, false);
}

void
close_context (struct context *c, int sig, unsigned int flags)
{
  ASSERT (c);
  ASSERT (c->sig);

  if (sig >= 0)
    c->sig->signal_received = sig;

  if (c->sig->signal_received == SIGUSR1)
    {
      if ((flags & CC_USR1_TO_HUP)
	  || (c->sig->hard && (flags & CC_HARD_USR1_TO_HUP)))
	c->sig->signal_received = SIGHUP;
    }

  if (!(flags & CC_NO_CLOSE))
    close_instance (c);

  if (flags & CC_GC_FREE)
    context_gc_free (c);
}

#ifdef USE_CRYPTO

/*
 * Do a loopback test
 * on the crypto subsystem.
 */
static void *
test_crypto_thread (void *arg)
{
  struct context *c = (struct context *) arg;
  const struct options *options = &c->options;

  ASSERT (options->test_crypto);
  init_verb_mute (c, IVM_LEVEL_1);
  context_init_1 (c);
  do_init_crypto_static (c, 0);

  frame_finalize_options (c, options);

  test_crypto (&c->c2.crypto_options, &c->c2.frame);

  key_schedule_free (&c->c1.ks, true);
  packet_id_free (&c->c2.packet_id);

  context_gc_free (c);
  return NULL;
}

#endif

bool
do_test_crypto (const struct options *o)
{
#ifdef USE_CRYPTO
  if (o->test_crypto)
    {
      struct context c;

      /* print version number */
      msg (M_INFO, "%s", title_string);

      context_clear (&c);
      c.options = *o;
      options_detach (&c.options);
      c.first_time = true;
      test_crypto_thread ((void *) &c);
      return true;
    }
#endif
  return false;
}
