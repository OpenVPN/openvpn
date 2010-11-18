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

#ifndef OPENVPN_H
#define OPENVPN_H

#include "buffer.h"
#include "options.h"
#include "socket.h"
#include "crypto.h"
#include "ssl.h"
#include "packet_id.h"
#include "lzo.h"
#include "tun.h"
#include "interval.h"
#include "status.h"
#include "fragment.h"
#include "shaper.h"
#include "route.h"
#include "proxy.h"
#include "socks.h"
#include "sig.h"
#include "misc.h"
#include "mbuf.h"
#include "pool.h"
#include "plugin.h"
#include "manage.h"
#include "pf.h"

/*
 * Our global key schedules, packaged thusly
 * to facilitate --persist-key.
 */

struct key_schedule
{
#ifdef USE_CRYPTO
  /* which cipher, HMAC digest, and key sizes are we using? */
  struct key_type key_type;

  /* pre-shared static key, read from a file */
  struct key_ctx_bi static_key;

#ifdef USE_SSL
  /* our global SSL context */
  SSL_CTX *ssl_ctx;

  /* optional authentication HMAC key for TLS control channel */
  struct key_ctx_bi tls_auth_key;

#endif				/* USE_SSL */
#else				/* USE_CRYPTO */
  int dummy;
#endif				/* USE_CRYPTO */
};

/*
 * struct packet_id_persist should be empty if we are not
 * building with crypto.
 */
#ifndef PACKET_ID_H
struct packet_id_persist
{
  int dummy;
};
static inline void
packet_id_persist_init (struct packet_id_persist *p)
{
}
#endif

/*
 * Packet processing buffers.
 */
struct context_buffers
{
  /* miscellaneous buffer, used by ping, occ, etc. */
  struct buffer aux_buf;

  /* workspace buffers used by crypto routines */
#ifdef USE_CRYPTO
  struct buffer encrypt_buf;
  struct buffer decrypt_buf;
#endif

  /* workspace buffers for LZO compression */
#ifdef USE_LZO
  struct buffer lzo_compress_buf;
  struct buffer lzo_decompress_buf;
#endif

  /*
   * Buffers used to read from TUN device
   * and TCP/UDP port.
   */
  struct buffer read_link_buf;
  struct buffer read_tun_buf;
};

/*
 * always-persistent context variables
 */
struct context_persist
{
  int restart_sleep_seconds;
};

/* 
 * level 0 context contains data related to
 * once-per OpenVPN instantiation events
 * such as daemonization.
 */
struct context_0
{
  /* workspace for get_pid_file/write_pid */
  struct pid_state pid_state;

  /* workspace for --user/--group */
  bool uid_gid_specified;
  bool uid_gid_set;
  struct user_state user_state;
  struct group_state group_state;
};

/*
 * Contains the persist-across-restart OpenVPN tunnel instance state.
 * Reset only for SIGHUP restarts.
 */
struct context_1
{
  /* local and remote addresses */
  struct link_socket_addr link_socket_addr;

  /* tunnel session keys */
  struct key_schedule ks;

  /* persist crypto sequence number to/from file */
  struct packet_id_persist pid_persist;

  /* TUN/TAP interface */
  struct tuntap *tuntap;
  bool tuntap_owned;

  /* list of --route directives */
  struct route_list *route_list;

  /* --status file */
  struct status_output *status_output;
  bool status_output_owned;

#ifdef ENABLE_HTTP_PROXY
  /* HTTP proxy object */
  struct http_proxy_info *http_proxy;
  bool http_proxy_owned;
#endif

#ifdef ENABLE_SOCKS
  /* SOCKS proxy object */
  struct socks_proxy_info *socks_proxy;
  bool socks_proxy_owned;
#endif

#if P2MP

#if P2MP_SERVER
  /* persist --ifconfig-pool db to file */
  struct ifconfig_pool_persist *ifconfig_pool_persist;
  bool ifconfig_pool_persist_owned;
#endif

  /* if client mode, hash of option strings we pulled from server */
  struct md5_digest pulled_options_digest_save;

  /* save user/pass for authentication */
  struct user_pass *auth_user_pass;
#endif
};

/*
 * Contains the OpenVPN tunnel instance state, wiped across
 * SIGUSR1 and SIGHUP restarts.
 */
struct context_2
{
  /* garbage collection arena for context_2 scope */
  struct gc_arena gc;

  /* our global wait events */
  struct event_set *event_set;
  int event_set_max;
  bool event_set_owned;

  /* event flags returned by io_wait */
# define SOCKET_READ       (1<<0)
# define SOCKET_WRITE      (1<<1)
# define TUN_READ          (1<<2)
# define TUN_WRITE         (1<<3)
# define ES_ERROR          (1<<4)
# define ES_TIMEOUT        (1<<5)
# ifdef ENABLE_MANAGEMENT
#  define MANAGEMENT_READ  (1<<6)
#  define MANAGEMENT_WRITE (1<<7)
# endif

  unsigned int event_set_status;

  struct link_socket *link_socket;	 /* socket used for TCP/UDP connection to remote */
  bool link_socket_owned;
  struct link_socket_info *link_socket_info;
  const struct link_socket *accept_from; /* possibly do accept() on a parent link_socket */

  struct link_socket_actual *to_link_addr;	/* IP address of remote */
  struct link_socket_actual from;               /* address of incoming datagram */

  /* MTU frame parameters */
  struct frame frame;

#ifdef ENABLE_FRAGMENT
  /* Object to handle advanced MTU negotiation and datagram fragmentation */
  struct fragment_master *fragment;
  struct frame frame_fragment;
  struct frame frame_fragment_omit;
#endif

#ifdef HAVE_GETTIMEOFDAY
  /*
   * Traffic shaper object.
   */
  struct shaper shaper;
#endif

  /*
   * Statistics
   */
  counter_type tun_read_bytes;
  counter_type tun_write_bytes;
  counter_type link_read_bytes;
  counter_type link_read_bytes_auth;
  counter_type link_write_bytes;
#ifdef PACKET_TRUNCATION_CHECK
  counter_type n_trunc_tun_read;
  counter_type n_trunc_tun_write;
  counter_type n_trunc_pre_encrypt;
  counter_type n_trunc_post_decrypt;
#endif

  /*
   * Timer objects for ping and inactivity
   * timeout features.
   */
  struct event_timeout wait_for_connect;
  struct event_timeout ping_send_interval;
  struct event_timeout ping_rec_interval;

  /* --inactive */
  struct event_timeout inactivity_interval;
  int inactivity_bytes;

#ifdef ENABLE_OCC
  /* the option strings must match across peers */
  char *options_string_local;
  char *options_string_remote;

  int occ_op;			/* INIT to -1 */
  int occ_n_tries;
  struct event_timeout occ_interval;
#endif

  /*
   * Keep track of maximum packet size received so far
   * (of authenticated packets).
   */
  int original_recv_size;	/* temporary */
  int max_recv_size_local;	/* max packet size received */
  int max_recv_size_remote;	/* max packet size received by remote */
  int max_send_size_local;	/* max packet size sent */
  int max_send_size_remote;	/* max packet size sent by remote */

#ifdef ENABLE_OCC
  /* remote wants us to send back a load test packet of this size */
  int occ_mtu_load_size;

  struct event_timeout occ_mtu_load_test_interval;
  int occ_mtu_load_n_tries;
#endif

#ifdef USE_CRYPTO

  /*
   * TLS-mode crypto objects.
   */
#ifdef USE_SSL

  /* master OpenVPN SSL/TLS object */
  struct tls_multi *tls_multi;

  /* check --tls-auth signature without needing
     a full-size tls_multi object */
  struct tls_auth_standalone *tls_auth_standalone;

  /* used to optimize calls to tls_multi_process */
  struct interval tmp_int;

  /* throw this signal on TLS errors */
  int tls_exit_signal;

#endif /* USE_SSL */

  /* passed to encrypt or decrypt, contains all
     crypto-related command line options related
     to data channel encryption/decryption */
  struct crypto_options crypto_options;

  /* used to keep track of data channel packet sequence numbers */
  struct packet_id packet_id;
  struct event_timeout packet_id_persist_interval;

#endif /* USE_CRYPTO */

  /*
   * LZO compression library workspace.
   */
#ifdef USE_LZO
  struct lzo_compress_workspace lzo_compwork;
#endif

  /*
   * Buffers used for packet processing.
   */
  struct context_buffers *buffers;
  bool buffers_owned; /* if true, we should free all buffers on close */

  /*
   * These buffers don't actually allocate storage, they are used
   * as pointers to the allocated buffers in
   * struct context_buffers.
   */
  struct buffer buf;
  struct buffer to_tun;
  struct buffer to_link;

  /*
   * IPv4 TUN device?
   */
  bool ipv4_tun;

  /* should we print R|W|r|w to console on packet transfers? */
  bool log_rw;

  /* route stuff */
  struct event_timeout route_wakeup;
  struct event_timeout route_wakeup_expire;

  /* did we open tun/tap dev during this cycle? */
  bool did_open_tun;

  /*
   * Event loop info
   */

  /* how long to wait on link/tun read before we will need to be serviced */
  struct timeval timeval;

  /* next wakeup for processing coarse timers (>1 sec resolution) */
  time_t coarse_timer_wakeup;

  /* maintain a random delta to add to timeouts to avoid contexts
     waking up simultaneously */
  time_t update_timeout_random_component;
  struct timeval timeout_random_component;

  /* indicates that the do_up_delay function has run */
  bool do_up_ran;

#ifdef ENABLE_OCC
  /* indicates that we have received a SIGTERM when
     options->explicit_exit_notification is enabled,
     but we have not exited yet */
  time_t explicit_exit_notification_time_wait;
  struct event_timeout explicit_exit_notification_interval;
#endif

  /* environmental variables to pass to scripts */
  struct env_set *es;
  bool es_owned;

  /* don't wait for TUN/TAP/UDP to be ready to accept write */
  bool fast_io;

#if P2MP

#if P2MP_SERVER
  /* --ifconfig endpoints to be pushed to client */
  bool push_reply_deferred;
  bool push_ifconfig_defined;
  in_addr_t push_ifconfig_local;
  in_addr_t push_ifconfig_remote_netmask;

  /* client authentication state, CAS_SUCCEEDED must be 0 */
# define CAS_SUCCEEDED 0
# define CAS_PENDING   1
# define CAS_FAILED    2
# define CAS_PARTIAL   3 /* at least one client-connect script/plugin
			    succeeded while a later one in the chain failed */
  int context_auth;
#endif

  struct event_timeout push_request_interval;
  bool did_pre_pull_restore;

  /* hash of pulled options, so we can compare when options change */
  struct md5_state pulled_options_state;
  struct md5_digest pulled_options_digest;

  struct event_timeout server_poll_interval;

  struct event_timeout scheduled_exit;
  int scheduled_exit_signal;
#endif

  /* packet filter */
#ifdef ENABLE_PF
  struct pf_context pf;
#endif

#ifdef MANAGEMENT_DEF_AUTH
  struct man_def_auth_context mda_context;
#endif
};

/*
 * Contains all state information for one tunnel.
 */
struct context
{
  /* command line or config file options */
  struct options options;

  /* true on initial VPN iteration */
  bool first_time;

  /* context modes */
# define CM_P2P            0 /* standalone point-to-point session or client */
# define CM_TOP            1 /* top level of a multi-client or point-to-multipoint server */
# define CM_TOP_CLONE      2 /* clone of a CM_TOP context for one thread */
# define CM_CHILD_UDP      3 /* child context of a CM_TOP or CM_THREAD */
# define CM_CHILD_TCP      4 /* child context of a CM_TOP or CM_THREAD */
  int mode;

  /* garbage collection for context scope
     allocations */
  struct gc_arena gc;

  /* environmental variable settings */
  struct env_set *es;

  /* signal info */
  struct signal_info *sig;

  /* shared object plugins */
  struct plugin_list *plugins;
  bool plugins_owned;
  
  /* set to true after we daemonize */
  bool did_we_daemonize;

  /* persistent across SIGHUP */
  struct context_persist persist;

  /* level 0 context contains data related to
     once-per OpenVPN instantiation events
     such as daemonization */
  struct context_0 *c0;

  /* level 1 context is preserved for
     SIGUSR1 restarts, but initialized
     for SIGHUP restarts */
  struct context_1 c1;

  /* level 2 context is initialized for all
     restarts (SIGUSR1 and SIGHUP) */
  struct context_2 c2;
};

/*
 * Check for a signal when inside an event loop
 */
#define EVENT_LOOP_CHECK_SIGNAL(c, func, arg)   \
      if (IS_SIG (c))                           \
	{                                       \
	  const int brk = func (arg);           \
	  perf_pop ();                          \
	  if (brk)                              \
	    break;                              \
	  else                                  \
	    continue;                           \
	}

/*
 * Macros for referencing objects which may not
 * have been compiled in.
 */

#if defined(USE_CRYPTO) && defined(USE_SSL)
#define TLS_MODE(c) ((c)->c2.tls_multi != NULL)
#define PROTO_DUMP_FLAGS (check_debug_level (D_LINK_RW_VERBOSE) ? (PD_SHOW_DATA|PD_VERBOSE) : 0)
#define PROTO_DUMP(buf, gc) protocol_dump((buf), \
				      PROTO_DUMP_FLAGS | \
				      (c->c2.tls_multi ? PD_TLS : 0) | \
				      (c->options.tls_auth_file ? c->c1.ks.key_type.hmac_length : 0), \
				      gc)
#else
#define TLS_MODE(c) (false)
#define PROTO_DUMP(buf, gc) format_hex (BPTR (buf), BLEN (buf), 80, gc)
#endif

#ifdef USE_CRYPTO
#define MD5SUM(buf, len, gc) md5sum((buf), (len), 0, (gc))
#else
#define MD5SUM(buf, len, gc) "[unavailable]"
#endif

#ifdef USE_CRYPTO
#define CIPHER_ENABLED(c) (c->c1.ks.key_type.cipher != NULL)
#else
#define CIPHER_ENABLED(c) (false)
#endif

#endif
