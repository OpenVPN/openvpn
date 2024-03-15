/*
 *  OpenVPN -- An application to securely tunnel IP networks
 *             over a single TCP/UDP port, with support for SSL/TLS-based
 *             session authentication and key exchange,
 *             packet encryption, packet authentication, and
 *             packet compression.
 *
 *  Copyright (C) 2002-2024 OpenVPN Inc <sales@openvpn.net>
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

/**
 * @file Header file for server-mode related structures and functions.
 */

#ifndef MULTI_H
#define MULTI_H

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
#include "vlan.h"
#include "reflect_filter.h"

#define MULTI_PREFIX_MAX_LENGTH 256

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


struct deferred_signal_schedule_entry
{
    struct schedule_entry se;
    int signal_received;
    struct timeval wakeup;
};

/**
 * Detached client connection state.  This is the state that is tracked while
 * the client connect hooks are executed.
 */
struct client_connect_defer_state
{
    /* Index of currently executed handler.  */
    int cur_handler_index;
    /* Remember which option classes where processed for delayed option
     * handling. */
    unsigned int option_types_found;

    /**
     * The temporary file name that contains the return status of the
     * client-connect script if it exits with defer as status
     */
    char *deferred_ret_file;

    /**
     * The temporary file name that contains the config directives
     * returned by the client-connect script
     */
    char *config_file;
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
    struct schedule_entry se;  /* this must be the first element of the structure,
                                * We cast between this and schedule_entry so the
                                * beginning of the struct must be identical */
    struct gc_arena gc;
    bool halt;
    int refcount;
    int route_count;           /* number of routes (including cached routes) owned by this instance */
    time_t created;             /**< Time at which a VPN tunnel instance
                                 *   was created.  This parameter is set
                                 *   by the \c multi_create_instance()
                                 *   function. */
    struct timeval wakeup;     /* absolute time */
    struct mroute_addr real;    /**< External network address of the
                                 *   remote peer. */
    ifconfig_pool_handle vaddr_handle;
    char msg_prefix[MULTI_PREFIX_MAX_LENGTH];

    /* queued outgoing data in Server/TCP mode */
    unsigned int tcp_rwflags;
    struct mbuf_set *tcp_link_out_deferred;
    bool socket_set_called;

    in_addr_t reporting_addr;     /* IP address shown in status listing */
    struct in6_addr reporting_addr_ipv6; /* IPv6 address in status listing */

    bool did_real_hash;
    bool did_iter;
#ifdef ENABLE_MANAGEMENT
    bool did_cid_hash;
    struct buffer_list *cc_config;
#endif
    bool did_iroutes;
    int n_clients_delta; /* added to multi_context.n_clients when instance is closed */

    struct context context;     /**< The context structure storing state
                                 *   for this VPN tunnel. */
    struct client_connect_defer_state client_connect_defer_state;
#ifdef ENABLE_ASYNC_PUSH
    int inotify_watch; /* watch descriptor for acf */
#endif
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
    struct multi_instance **instances;  /**< Array of multi_instances. An instance can be
                                         * accessed using peer-id as an index. */

    struct hash *hash;          /**< VPN tunnel instances indexed by real
                                 *   address of the remote peer. */
    struct hash *vhash;         /**< VPN tunnel instances indexed by
                                 *   virtual address of remote hosts. */
    struct hash *iter;          /**< VPN tunnel instances indexed by real
                                 *   address of the remote peer, optimized
                                 *   for iteration. */
    struct schedule *schedule;
    struct mbuf_set *mbuf;      /**< Set of buffers for passing data
                                 *   channel packets between VPN tunnel
                                 *   instances. */
    struct multi_tcp *mtcp;     /**< State specific to OpenVPN using TCP
                                 *   as external transport. */
    struct ifconfig_pool *ifconfig_pool;
    struct frequency_limit *new_connection_limiter;
    struct initial_packet_rate_limit *initial_rate_limiter;
    struct mroute_helper *route_helper;
    struct multi_reap *reaper;
    struct mroute_addr local;
    bool enable_c2c;
    int max_clients;
    int tcp_queue_limit;
    int status_file_version;
    int n_clients; /* current number of authenticated clients */

#ifdef ENABLE_MANAGEMENT
    struct hash *cid_hash;
    unsigned long cid_counter;
#endif

    struct multi_instance *pending;
    struct multi_instance *earliest_wakeup;
    struct multi_instance **mpp_touched;
    struct context_buffers *context_buffers;
    time_t per_second_trigger;

    struct context top;         /**< Storage structure for process-wide
                                 *   configuration. */

    struct buffer hmac_reply;
    struct link_socket_actual *hmac_reply_dest;

    /*
     * Timer object for stale route check
     */
    struct event_timeout stale_routes_check_et;

#ifdef ENABLE_ASYNC_PUSH
    /* mapping between inotify watch descriptors and multi_instances */
    struct hash *inotify_watchers;
#endif

    struct deferred_signal_schedule_entry deferred_shutdown_signal;
};

/**
 * Return values used by the client connect call-back functions.
 */
enum client_connect_return
{
    CC_RET_FAILED,
    CC_RET_SUCCEEDED,
    CC_RET_DEFERRED,
    CC_RET_SKIPPED
};

/*
 * Host route
 */
struct multi_route
{
    struct mroute_addr addr;
    struct multi_instance *instance;

#define MULTI_ROUTE_CACHE   (1<<0)
#define MULTI_ROUTE_AGEABLE (1<<1)
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
void tunnel_server(struct context *top);


const char *multi_instance_string(const struct multi_instance *mi, bool null, struct gc_arena *gc);

/*
 * Called by mtcp.c, mudp.c, or other (to be written) protocol drivers
 */

void multi_init(struct multi_context *m, struct context *t, bool tcp_mode);

void multi_uninit(struct multi_context *m);

void multi_top_init(struct multi_context *m, struct context *top);

void multi_top_free(struct multi_context *m);

struct multi_instance *multi_create_instance(struct multi_context *m, const struct mroute_addr *real);

void multi_close_instance(struct multi_context *m, struct multi_instance *mi, bool shutdown);

bool multi_process_timeout(struct multi_context *m, const unsigned int mpp_flags);

/**
 * Handles peer floating.
 *
 * If peer is floated to a taken address, either drops packet
 * (if peer that owns address has different CN) or disconnects
 * existing peer. Updates multi_instance with new address,
 * updates hashtables in multi_context.
 */
void multi_process_float(struct multi_context *m, struct multi_instance *mi);

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
bool multi_process_post(struct multi_context *m, struct multi_instance *mi, const unsigned int flags);

/**
 * Process an incoming DCO message (from kernel space).
 *
 * @param m            - The single \c multi_context structur.e
 *
 * @return
 *  - True, if the message was received correctly.
 *  - False, if there was an error while reading the message.
 */
bool multi_process_incoming_dco(struct multi_context *m);

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
bool multi_process_incoming_link(struct multi_context *m, struct multi_instance *instance, const unsigned int mpp_flags);


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
bool multi_process_incoming_tun(struct multi_context *m, const unsigned int mpp_flags);


void multi_process_drop_outgoing_tun(struct multi_context *m, const unsigned int mpp_flags);

void multi_print_status(struct multi_context *m, struct status_output *so, const int version);

struct multi_instance *multi_get_queue(struct mbuf_set *ms);

void multi_add_mbuf(struct multi_context *m,
                    struct multi_instance *mi,
                    struct mbuf_buffer *mb);

void multi_ifconfig_pool_persist(struct multi_context *m, bool force);

bool multi_process_signal(struct multi_context *m);

void multi_close_instance_on_signal(struct multi_context *m, struct multi_instance *mi);

void init_management_callback_multi(struct multi_context *m);

#ifdef ENABLE_ASYNC_PUSH
/**
 * Called when inotify event is fired, which happens when acf file is closed or deleted.
 * Continues authentication and sends push_repl
 *
 * @param m multi_context
 * @param mpp_flags
 */
void multi_process_file_closed(struct multi_context *m, const unsigned int mpp_flags);

#endif

/*
 * Return true if our output queue is not full
 */
static inline bool
multi_output_queue_ready(const struct multi_context *m,
                         const struct multi_instance *mi)
{
    if (mi->tcp_link_out_deferred)
    {
        return mbuf_len(mi->tcp_link_out_deferred) <= m->tcp_queue_limit;
    }
    else
    {
        return true;
    }
}

/*
 * Determine which instance has pending output
 * and prepare the output for sending in
 * the to_link buffer.
 */
static inline struct multi_instance *
multi_process_outgoing_link_pre(struct multi_context *m)
{
    struct multi_instance *mi = NULL;

    if (m->pending)
    {
        mi = m->pending;
    }
    else if (mbuf_defined(m->mbuf))
    {
        mi = multi_get_queue(m->mbuf);
    }
    return mi;
}

/*
 * Per-client route quota management
 */

void route_quota_exceeded(const struct multi_instance *mi);

static inline void
route_quota_inc(struct multi_instance *mi)
{
    ++mi->route_count;
}

static inline void
route_quota_dec(struct multi_instance *mi)
{
    --mi->route_count;
}

/* can we add a new route? */
static inline bool
route_quota_test(const struct multi_instance *mi)
{
    if (mi->route_count >= mi->context.options.max_routes_per_client)
    {
        route_quota_exceeded(mi);
        return false;
    }
    else
    {
        return true;
    }
}

/*
 * Instance reference counting
 */

static inline void
multi_instance_inc_refcount(struct multi_instance *mi)
{
    ++mi->refcount;
}

static inline void
multi_instance_dec_refcount(struct multi_instance *mi)
{
    if (--mi->refcount <= 0)
    {
        gc_free(&mi->gc);
        free(mi);
    }
}

static inline void
multi_route_del(struct multi_route *route)
{
    struct multi_instance *mi = route->instance;
    route_quota_dec(mi);
    multi_instance_dec_refcount(mi);
    free(route);
}

static inline bool
multi_route_defined(const struct multi_context *m,
                    const struct multi_route *r)
{
    if (r->instance->halt)
    {
        return false;
    }
    else if ((r->flags & MULTI_ROUTE_CACHE)
             && r->cache_generation != m->route_helper->cache_generation)
    {
        return false;
    }
    else if ((r->flags & MULTI_ROUTE_AGEABLE)
             && r->last_reference + m->route_helper->ageable_ttl_secs < now)
    {
        return false;
    }
    else
    {
        return true;
    }
}

/*
 * Takes prefix away from multi_instance.
 */
void
ungenerate_prefix(struct multi_instance *mi);

/*
 * Set a msg() function prefix with our current client instance ID.
 */

static inline void
set_prefix(struct multi_instance *mi)
{
#ifdef MULTI_DEBUG_EVENT_LOOP
    if (mi->msg_prefix[0])
    {
        printf("[%s]\n", mi->msg_prefix);
    }
#endif
    msg_set_prefix(mi->msg_prefix[0] ? mi->msg_prefix : NULL);
}

static inline void
clear_prefix(void)
{
#ifdef MULTI_DEBUG_EVENT_LOOP
    printf("[NULL]\n");
#endif
    msg_set_prefix(NULL);
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

void multi_reap_process_dowork(const struct multi_context *m);

void multi_process_per_second_timers_dowork(struct multi_context *m);

static inline void
multi_reap_process(const struct multi_context *m)
{
    if (m->reaper->last_call != now)
    {
        multi_reap_process_dowork(m);
    }
}

static inline void
multi_process_per_second_timers(struct multi_context *m)
{
    if (m->per_second_trigger != now)
    {
        multi_process_per_second_timers_dowork(m);
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
multi_get_timeout(struct multi_context *m, struct timeval *dest)
{
    struct timeval tv, current;

    CLEAR(tv);
    m->earliest_wakeup = (struct multi_instance *) schedule_get_earliest_wakeup(m->schedule, &tv);
    if (m->earliest_wakeup)
    {
        ASSERT(!openvpn_gettimeofday(&current, NULL));
        tv_delta(dest, &current, &tv);
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
multi_process_outgoing_tun(struct multi_context *m, const unsigned int mpp_flags)
{
    struct multi_instance *mi = m->pending;
    bool ret = true;

    ASSERT(mi);
#ifdef MULTI_DEBUG_EVENT_LOOP
    printf("%s -> TUN len=%d\n",
           id(mi),
           mi->context.c2.to_tun.len);
#endif
    set_prefix(mi);
    vlan_process_outgoing_tun(m, mi);
    process_outgoing_tun(&mi->context);
    ret = multi_process_post(m, mi, mpp_flags);
    clear_prefix();
    return ret;
}

#define CLIENT_CONNECT_OPT_MASK (OPT_P_INSTANCE | OPT_P_INHERIT   \
                                 |OPT_P_PUSH | OPT_P_TIMER | OPT_P_CONFIG   \
                                 |OPT_P_ECHO | OPT_P_COMP | OPT_P_SOCKFLAGS)

static inline bool
multi_process_outgoing_link_dowork(struct multi_context *m, struct multi_instance *mi, const unsigned int mpp_flags)
{
    bool ret = true;
    set_prefix(mi);
    process_outgoing_link(&mi->context);
    ret = multi_process_post(m, mi, mpp_flags);
    clear_prefix();
    return ret;
}

/*
 * Check for signals.
 */
#define MULTI_CHECK_SIG(m) EVENT_LOOP_CHECK_SIGNAL(&(m)->top, multi_process_signal, (m))

static inline void
multi_set_pending(struct multi_context *m, struct multi_instance *mi)
{
    m->pending = mi;
}
/**
 * Assigns a peer-id to a a client and adds the instance to the
 * the instances array of the \c multi_context structure.
 *
 * @param m            - The single \c multi_context structure.
 * @param mi           - The \c multi_instance of the VPN tunnel to be
 *                       postprocessed.
 */
void multi_assign_peer_id(struct multi_context *m, struct multi_instance *mi);


#endif /* MULTI_H */
