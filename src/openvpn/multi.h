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

/**
 * @file Header file for server-mode related structures and functions.
 */

#ifndef MULTI_H
#define MULTI_H

#if P2MP_SERVER

#include "init.h"
#include "forward.h"
#include "mroute.h"
#include "mbuf.h"
#include "list.h"
#include "schedule.h"
#include "pool.h"
#include "mudp.h"
#include "mtcp.h"
#include "perf.h"

/*
 * Walk (don't run) through the routing table,
 * deleting old entries, and possibly multi_instance
 * structs as well which have been marked for deletion.
 */
struct multi_reap
{
  int bucket_base;
  int buckets_per_pass;
  time_t last_call;
};


/**
 * Server-mode state structure for one single VPN tunnel.
 *
 * This structure is used by OpenVPN processes running in server-mode to
 * store state information related to one single VPN tunnel.
 *
 * The @ref tunnel_state "Structure of VPN tunnel state storage" related
 * page describes the role the structure plays when OpenVPN is running in
 * server-mode.
 */
struct multi_instance {
  struct schedule_entry se;    /* this must be the first element of the structure */
  struct gc_arena gc;
  bool defined;
  bool halt;
  int refcount;
  int route_count;             /* number of routes (including cached routes) owned by this instance */
  time_t created;               /**< Time at which a VPN tunnel instance
                                 *   was created.  This parameter is set
                                 *   by the \c multi_create_instance()
                                 *   function. */
  struct timeval wakeup;       /* absolute time */
  struct mroute_addr real;      /**< External network address of the
                                 *   remote peer. */
  ifconfig_pool_handle vaddr_handle;
  const char *msg_prefix;

  /* queued outgoing data in Server/TCP mode */
  unsigned int tcp_rwflags;
  struct mbuf_set *tcp_link_out_deferred;
  bool socket_set_called;

  in_addr_t reporting_addr;       /* IP address shown in status listing */

  bool did_open_context;
  bool did_real_hash;
  bool did_iter;
#ifdef MANAGEMENT_DEF_AUTH
  bool did_cid_hash;
  struct buffer_list *cc_config;
#endif
  bool connection_established_flag;
  bool did_iroutes;
  int n_clients_delta; /* added to multi_context.n_clients when instance is closed */

  struct context context;       /**< The context structure storing state
                                 *   for this VPN tunnel. */
};


/**
 * Main OpenVPN server state structure.
 *
 * This structure is used by OpenVPN processes running in server-mode to
 * store all the VPN tunnel and process-wide state.
 *
 * The @ref tunnel_state "Structure of VPN tunnel state storage" related
 * page describes the role the structure plays when OpenVPN is running in
 * server-mode.
 */
struct multi_context {
# define MC_UNDEF                      0
# define MC_SINGLE_THREADED            (1<<0)
# define MC_MULTI_THREADED_MASTER      (1<<1)
# define MC_MULTI_THREADED_WORKER      (1<<2)
# define MC_MULTI_THREADED_SCHEDULER   (1<<3)
# define MC_WORK_THREAD                (MC_MULTI_THREADED_WORKER|MC_MULTI_THREADED_SCHEDULER)
  int thread_mode;

  struct hash *hash;            /**< VPN tunnel instances indexed by real
                                 *   address of the remote peer. */
  struct hash *vhash;           /**< VPN tunnel instances indexed by
                                 *   virtual address of remote hosts. */
  struct hash *iter;            /**< VPN tunnel instances indexed by real
                                 *   address of the remote peer, optimized
                                 *   for iteration. */
  struct schedule *schedule;
  struct mbuf_set *mbuf;        /**< Set of buffers for passing data
                                 *   channel packets between VPN tunnel
                                 *   instances. */
  struct multi_tcp *mtcp;       /**< State specific to OpenVPN using TCP
                                 *   as external transport. */
  struct ifconfig_pool *ifconfig_pool;
  struct frequency_limit *new_connection_limiter;
  struct mroute_helper *route_helper;
  struct multi_reap *reaper;
  struct mroute_addr local;
  bool enable_c2c;
  int max_clients;
  int tcp_queue_limit;
  int status_file_version;
  int n_clients; /* current number of authenticated clients */

#ifdef MANAGEMENT_DEF_AUTH
  struct hash *cid_hash;
  unsigned long cid_counter;
#endif

  struct multi_instance *pending;
  struct multi_instance *earliest_wakeup;
  struct multi_instance **mpp_touched;
  struct context_buffers *context_buffers;
  time_t per_second_trigger;

  struct context top;           /**< Storage structure for process-wide
                                 *   configuration. */

  /*
   * Timer object for stale route check
   */
  struct event_timeout stale_routes_check_et;
};

/*
 * Host route
 */
struct multi_route
{
  struct mroute_addr addr;
  struct multi_instance *instance;

# define MULTI_ROUTE_CACHE   (1<<0)
# define MULTI_ROUTE_AGEABLE (1<<1)
  unsigned int flags;

  unsigned int cache_generation;
  time_t last_reference;
};


/**************************************************************************/
/**
 * Main event loop for OpenVPN in server mode.
 * @ingroup eventloop
 *
 * This function calls the appropriate main event loop function depending
 * on the transport protocol used:
 *  - \c tunnel_server_udp()
 *  - \c tunnel_server_tcp()
 *
 * @param top          - Top-level context structure.
 */
void tunnel_server (struct context *top);


const char *multi_instance_string (const struct multi_instance *mi, bool null, struct gc_arena *gc);

/*
 * Called by mtcp.c, mudp.c, or other (to be written) protocol drivers
 */

void multi_init (struct multi_context *m, struct context *t, bool tcp_mode, int thread_mode);
void multi_uninit (struct multi_context *m);

void multi_top_init (struct multi_context *m, const struct context *top, const bool alloc_buffers);
void multi_top_free (struct multi_context *m);

struct multi_instance *multi_create_instance (struct multi_context *m, const struct mroute_addr *real);
void multi_close_instance (struct multi_context *m, struct multi_instance *mi, bool shutdown);

bool multi_process_timeout (struct multi_context *m, const unsigned int mpp_flags);

#define MPP_PRE_SELECT             (1<<0)
#define MPP_CONDITIONAL_PRE_SELECT (1<<1)
#define MPP_CLOSE_ON_SIGNAL        (1<<2)
#define MPP_RECORD_TOUCH           (1<<3)


/**************************************************************************/
/**
 * Perform postprocessing of a VPN tunnel instance.
 *
 * After some VPN tunnel activity has taken place, the VPN tunnel's state
 * may need updating and some follow-up action may be required.  This
 * function controls the necessary postprocessing.  It is called by many
 * other functions that handle VPN tunnel related activity, such as \c
 * multi_process_incoming_link(), \c multi_process_outgoing_link(), \c
 * multi_process_incoming_tun(), \c multi_process_outgoing_tun(), and \c
 * multi_process_timeout(), among others.
 *
 * @param m            - The single \c multi_context structure.
 * @param mi           - The \c multi_instance of the VPN tunnel to be
 *                       postprocessed.
 * @param flags        - Fast I/O optimization flags.
 *
 * @return
 *  - True, if the VPN tunnel instance \a mi was not closed due to a
 *    signal during processing.
 *  - False, if the VPN tunnel instance \a mi was closed.
 */
bool multi_process_post (struct multi_context *m, struct multi_instance *mi, const unsigned int flags);


/**************************************************************************/
/**
 * Demultiplex and process a packet received over the external network
 * interface.
 * @ingroup external_multiplexer
 *
 * This function determines which VPN tunnel instance the incoming packet
 * is associated with, and then calls \c process_incoming_link() to handle
 * it.  Afterwards, if the packet is destined for a broadcast/multicast
 * address or a remote host reachable through a different VPN tunnel, this
 * function takes care of sending it they are.
 *
 * @note This function is only used by OpenVPN processes which are running
 *     in server mode, and can therefore sustain multiple active VPN
 *     tunnels.
 *
 * @param m            - The single \c multi_context structure.
 * @param instance     - The VPN tunnel state structure associated with
 *                       the incoming packet, if known, as is the case
 *                       when using TCP transport. Otherwise NULL, as is
 *                       the case when using UDP transport.
 * @param mpp_flags    - Fast I/O optimization flags.
 */
bool multi_process_incoming_link (struct multi_context *m, struct multi_instance *instance, const unsigned int mpp_flags);


/**
 * Determine the destination VPN tunnel of a packet received over the
 * virtual tun/tap network interface and then process it accordingly.
 * @ingroup internal_multiplexer
 *
 * This function determines which VPN tunnel instance the packet is
 * destined for, and then calls \c process_outgoing_tun() to handle it.
 *
 * @note This function is only used by OpenVPN processes which are running
 *     in server mode, and can therefore sustain multiple active VPN
 *     tunnels.
 *
 * @param m            - The single \c multi_context structure.
 * @param mpp_flags    - Fast I/O optimization flags.
 */
bool multi_process_incoming_tun (struct multi_context *m, const unsigned int mpp_flags);


void multi_process_drop_outgoing_tun (struct multi_context *m, const unsigned int mpp_flags);

void multi_print_status (struct multi_context *m, struct status_output *so, const int version);

struct multi_instance *multi_get_queue (struct mbuf_set *ms);

void multi_add_mbuf (struct multi_context *m,
		     struct multi_instance *mi,
		     struct mbuf_buffer *mb);

void multi_ifconfig_pool_persist (struct multi_context *m, bool force);

bool multi_process_signal (struct multi_context *m);

void multi_close_instance_on_signal (struct multi_context *m, struct multi_instance *mi);

void init_management_callback_multi (struct multi_context *m);
void uninit_management_callback_multi (struct multi_context *m);

/*
 * Return true if our output queue is not full
 */
static inline bool
multi_output_queue_ready (const struct multi_context *m,
			  const struct multi_instance *mi)
{
  if (mi->tcp_link_out_deferred)
    return mbuf_len (mi->tcp_link_out_deferred) <= m->tcp_queue_limit;
  else
    return true;
}

/*
 * Determine which instance has pending output
 * and prepare the output for sending in
 * the to_link buffer.
 */
static inline struct multi_instance *
multi_process_outgoing_link_pre (struct multi_context *m)
{
  struct multi_instance *mi = NULL;

  if (m->pending)
    mi = m->pending;
  else if (mbuf_defined (m->mbuf))
    mi = multi_get_queue (m->mbuf);
  return mi;
}

/*
 * Per-client route quota management
 */

void route_quota_exceeded (const struct multi_context *m, const struct multi_instance *mi);

static inline void
route_quota_inc (struct multi_instance *mi)
{
  ++mi->route_count;
}

static inline void
route_quota_dec (struct multi_instance *mi)
{
  --mi->route_count;
}

/* can we add a new route? */
static inline bool
route_quota_test (const struct multi_context *m, const struct multi_instance *mi)
{
  if (mi->route_count >= mi->context.options.max_routes_per_client)
    {
      route_quota_exceeded (m, mi);
      return false;
    }
  else
    return true;
}

/*
 * Instance reference counting
 */

static inline void
multi_instance_inc_refcount (struct multi_instance *mi)
{
  ++mi->refcount;
}

static inline void
multi_instance_dec_refcount (struct multi_instance *mi)
{
  if (--mi->refcount <= 0)
    {
      gc_free (&mi->gc);
      free (mi);
    }
}

static inline void
multi_route_del (struct multi_route *route)
{
  struct multi_instance *mi = route->instance;
  route_quota_dec (mi);
  multi_instance_dec_refcount (mi);
  free (route);
}

static inline bool
multi_route_defined (const struct multi_context *m,
		     const struct multi_route *r)
{
  if (r->instance->halt)
    return false;
  else if ((r->flags & MULTI_ROUTE_CACHE)
	   && r->cache_generation != m->route_helper->cache_generation)
    return false;
  else if ((r->flags & MULTI_ROUTE_AGEABLE)
	   && r->last_reference + m->route_helper->ageable_ttl_secs < now)
    return false;
  else
    return true;
}

/*
 * Set a msg() function prefix with our current client instance ID.
 */

static inline void
set_prefix (struct multi_instance *mi)
{
#ifdef MULTI_DEBUG_EVENT_LOOP
  if (mi->msg_prefix)
    printf ("[%s]\n", mi->msg_prefix);
#endif
  msg_set_prefix (mi->msg_prefix);
}

static inline void
clear_prefix (void)
{
#ifdef MULTI_DEBUG_EVENT_LOOP
  printf ("[NULL]\n");
#endif
  msg_set_prefix (NULL);
}

/*
 * Instance Reaper
 *
 * Reaper constants.  The reaper is the process where the virtual address
 * and virtual route hash table is scanned for dead entries which are
 * then removed.  The hash table could potentially be quite large, so we
 * don't want to reap in a single pass.
 */

#define REAP_MAX_WAKEUP   10  /* Do reap pass at least once per n seconds */
#define REAP_DIVISOR     256  /* How many passes to cover whole hash table */
#define REAP_MIN          16  /* Minimum number of buckets per pass */
#define REAP_MAX        1024  /* Maximum number of buckets per pass */

/*
 * Mark a cached host route for deletion after this
 * many seconds without any references.
 */
#define MULTI_CACHE_ROUTE_TTL 60

static inline void
multi_reap_process (const struct multi_context *m)
{
  void multi_reap_process_dowork (const struct multi_context *m);
  if (m->reaper->last_call != now)
    multi_reap_process_dowork (m);
}

static inline void
multi_process_per_second_timers (struct multi_context *m)
{
  if (m->per_second_trigger != now)
    {
      void multi_process_per_second_timers_dowork (struct multi_context *m);
      multi_process_per_second_timers_dowork (m);
      m->per_second_trigger = now;
    }
}

/*
 * Compute earliest timeout expiry from the set of
 * all instances.  Output:
 *
 * m->earliest_wakeup : instance needing the earliest service.
 * dest               : earliest timeout as a delta in relation
 *                      to current time.
 */
static inline void
multi_get_timeout (struct multi_context *m, struct timeval *dest)
{
  struct timeval tv, current;

  CLEAR (tv);
  m->earliest_wakeup = (struct multi_instance *) schedule_get_earliest_wakeup (m->schedule, &tv);
  if (m->earliest_wakeup)
    {
      ASSERT (!openvpn_gettimeofday (&current, NULL));
      tv_delta (dest, &current, &tv);
      if (dest->tv_sec >= REAP_MAX_WAKEUP)
	{
	  m->earliest_wakeup = NULL;
	  dest->tv_sec = REAP_MAX_WAKEUP;
	  dest->tv_usec = 0;
	}
    }
  else
    {
      dest->tv_sec = REAP_MAX_WAKEUP;
      dest->tv_usec = 0;
    }
}


/**
 * Send a packet over the virtual tun/tap network interface to its locally
 * reachable destination.
 * @ingroup internal_multiplexer
 *
 * This function calls \c process_outgoing_tun() to perform the actual
 * sending of the packet.  Afterwards, it calls \c multi_process_post() to
 * perform server-mode postprocessing.
 *
 * @param m            - The single \c multi_context structure.
 * @param mpp_flags    - Fast I/O optimization flags.
 *
 * @return
 *  - True, if the \c multi_instance associated with the packet sent was
 *    not closed due to a signal during processing.
 *  - Falls, if the \c multi_instance was closed.
 */
static inline bool
multi_process_outgoing_tun (struct multi_context *m, const unsigned int mpp_flags)
{
  struct multi_instance *mi = m->pending;
  bool ret = true;

  ASSERT (mi);
#ifdef MULTI_DEBUG_EVENT_LOOP
  printf ("%s -> TUN len=%d\n",
	  id(mi),
	  mi->context.c2.to_tun.len);
#endif
  set_prefix (mi);
  process_outgoing_tun (&mi->context);
  ret = multi_process_post (m, mi, mpp_flags);
  clear_prefix ();
  return ret;
}



static inline bool
multi_process_outgoing_link_dowork (struct multi_context *m, struct multi_instance *mi, const unsigned int mpp_flags)
{
  bool ret = true;
  set_prefix (mi);
  process_outgoing_link (&mi->context);
  ret = multi_process_post (m, mi, mpp_flags);
  clear_prefix ();
  return ret;
}

/*
 * Check for signals.
 */
#define MULTI_CHECK_SIG(m) EVENT_LOOP_CHECK_SIGNAL (&(m)->top, multi_process_signal, (m))

static inline void
multi_set_pending (struct multi_context *m, struct multi_instance *mi)
{
  m->pending = mi;
}

static inline void
multi_release_io_lock (struct multi_context *m)
{
}

#endif /* P2MP_SERVER */
#endif /* MULTI_H */
