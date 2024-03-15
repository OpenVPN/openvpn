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

#ifndef OPENVPN_H
#define OPENVPN_H

#include "buffer.h"
#include "options.h"
#include "socket.h"
#include "crypto.h"
#include "ssl.h"
#include "packet_id.h"
#include "comp.h"
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

/*
 * Our global key schedules, packaged thusly
 * to facilitate --persist-key.
 */

struct key_schedule
{
    /* which cipher, HMAC digest, and key sizes are we using? */
    struct key_type key_type;

    /* pre-shared static key, read from a file */
    struct key_ctx_bi static_key;

    /* our global SSL context */
    struct tls_root_ctx ssl_ctx;

    /* optional TLS control channel wrapping */
    struct key_type tls_auth_key_type;
    struct key_ctx_bi tls_wrap_key;
    /** original tls-crypt key preserved to xored into the tls_crypt
     * renegotiation key */
    struct key2 original_wrap_keydata;
    struct key_ctx tls_crypt_v2_server_key;
    struct buffer tls_crypt_v2_wkc;             /**< Wrapped client key */
    struct key_ctx auth_token_key;
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
packet_id_persist_init(struct packet_id_persist *p)
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
    struct buffer encrypt_buf;
    struct buffer decrypt_buf;

    /* workspace buffers for compression */
#ifdef USE_COMP
    struct buffer compress_buf;
    struct buffer decompress_buf;
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


/**************************************************************************/
/**
 * Level 0 %context containing information related to the OpenVPN process.
 *
 * Level 0 state is initialized once at program startup, and then remains
 * throughout the lifetime of the OpenVPN process.  This structure
 * contains information related to the process's PID, user, group, and
 * privileges.
 */
struct context_0
{
    /* workspace for --user/--group */
    bool uid_gid_specified;
    /* helper which tells us whether we should keep trying to drop privileges */
    bool uid_gid_chroot_set;
    struct platform_state_user platform_state_user;
    struct platform_state_group platform_state_group;
};


/**
 * Level 1 %context containing state that persists across \c SIGUSR1
 * restarts.
 *
 * Level 1 state is reset on \c SIGHUP restarts.  This structure is
 * initialized for every iteration of the \c main() function's outer \c
 * SIGHUP loop, but persists over iteration of that function's inner \c
 * SIGUSR1 loop.
 */
struct context_1
{
    struct link_socket_addr link_socket_addr;
    /**< Local and remote addresses on the
     *   external network. */

    /* tunnel session keys */
    struct key_schedule ks;

    /* preresolved and cached host names */
    struct cached_dns_entry *dns_cache;

    /* persist crypto sequence number to/from file */
    struct packet_id_persist pid_persist;

    struct tuntap *tuntap;      /**< Tun/tap virtual network interface. */
    bool tuntap_owned;          /**< Whether the tun/tap interface should
                                 *   be cleaned up when this %context is
                                 *   cleaned up. */

    struct route_list *route_list;
    /**< List of routing information. See the
     *   \c --route command line option. */

    /* list of --route-ipv6 directives */
    struct route_ipv6_list *route_ipv6_list;

    /* --status file */
    struct status_output *status_output;
    bool status_output_owned;

    /* HTTP proxy object */
    struct http_proxy_info *http_proxy;
    bool http_proxy_owned;

    /* SOCKS proxy object */
    struct socks_proxy_info *socks_proxy;
    bool socks_proxy_owned;

    /* persist --ifconfig-pool db to file */
    struct ifconfig_pool_persist *ifconfig_pool_persist;
    bool ifconfig_pool_persist_owned;

    /* if client mode, hash of option strings we pulled from server */
    struct sha256_digest pulled_options_digest_save;
    /**< Hash of option strings received from the
     *   remote OpenVPN server.  Only used in
     *   client-mode. */

    struct user_pass *auth_user_pass;
    /**< Username and password for
     *   authentication. */
};


static inline bool
is_cas_pending(enum multi_status cas)
{
    return cas == CAS_PENDING || cas == CAS_PENDING_DEFERRED
           || cas == CAS_PENDING_DEFERRED_PARTIAL;
}

/**
 * Level 2 %context containing state that is reset on both \c SIGHUP and
 * \c SIGUSR1 restarts.
 *
 * This structure is initialized at the top of the \c
 * tunnel_point_to_point(), \c tunnel_server_udp(), and \c
 * tunnel_server_tcp() functions.  In other words, it is reset for every
 * iteration of the \c main() function's inner \c SIGUSR1 loop.
 */
struct context_2
{
    struct gc_arena gc;         /**< Garbage collection arena for
                                 *   allocations done in the level 2 scope
                                 *   of this context_2 structure. */

    /* our global wait events */
    struct event_set *event_set;
    int event_set_max;
    bool event_set_owned;

    /* bitmask for event status. Check event.h for possible values */
    unsigned int event_set_status;

    struct link_socket *link_socket;     /* socket used for TCP/UDP connection to remote */
    bool link_socket_owned;

    /** This variable is used instead link_socket->info for P2MP UDP childs */
    struct link_socket_info *link_socket_info;
    const struct link_socket *accept_from; /* possibly do accept() on a parent link_socket */

    struct link_socket_actual *to_link_addr;    /* IP address of remote */
    struct link_socket_actual from;             /* address of incoming datagram */

    /* MTU frame parameters */
    struct frame frame;                         /* Active frame parameters */

#ifdef ENABLE_FRAGMENT
    /* Object to handle advanced MTU negotiation and datagram fragmentation */
    struct fragment_master *fragment;
    struct frame frame_fragment;
#endif

    /*
     * Traffic shaper object.
     */
    struct shaper shaper;

    /*
     * Statistics
     */
    counter_type tun_read_bytes;
    counter_type tun_write_bytes;
    counter_type link_read_bytes;
    counter_type dco_read_bytes;
    counter_type link_read_bytes_auth;
    counter_type link_write_bytes;
    counter_type dco_write_bytes;
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
    int64_t inactivity_bytes;

    struct event_timeout session_interval;

    /* auth token renewal timer */
    struct event_timeout auth_token_renewal_interval;

    /* the option strings must match across peers */
    char *options_string_local;
    char *options_string_remote;

    int occ_op;                 /* INIT to -1 */
    int occ_n_tries;
    struct event_timeout occ_interval;

    /*
     * Keep track of maximum packet size received so far
     * (of authenticated packets).
     */
    int original_recv_size;     /* temporary */
    int max_recv_size_local;    /* max packet size received */
    int max_recv_size_remote;   /* max packet size received by remote */
    int max_send_size_local;    /* max packet size sent */
    int max_send_size_remote;   /* max packet size sent by remote */


    /* remote wants us to send back a load test packet of this size */
    int occ_mtu_load_size;

    struct event_timeout occ_mtu_load_test_interval;
    int occ_mtu_load_n_tries;

    /*
     * TLS-mode crypto objects.
     */
    struct tls_multi *tls_multi; /**< TLS state structure for this VPN
                                  *   tunnel. */

    struct tls_auth_standalone *tls_auth_standalone;
    /**< TLS state structure required for the
     *   initial authentication of a client's
     *   connection attempt.  This structure
     *   is used by the \c
     *   tls_pre_decrypt_lite() function when
     *   it performs the HMAC firewall check
     *   on the first connection packet
     *   received from a new client.  See the
     *   \c --tls-auth commandline option. */


    hmac_ctx_t *session_id_hmac;
    /**< the HMAC we use to generate and verify our syn cookie like
     * session ids from the server.
     */

    /* used to optimize calls to tls_multi_process */
    struct interval tmp_int;

    /* throw this signal on TLS errors */
    int tls_exit_signal;

    struct crypto_options crypto_options;
    /**< Security parameters and crypto state
     *   used by the \link data_crypto Data
     *   Channel Crypto module\endlink to
     *   process data channel packet. */

    struct event_timeout packet_id_persist_interval;

#ifdef USE_COMP
    struct compress_context *comp_context;
    /**< Compression context used by the
     *   \link compression Data Channel
     *   Compression module\endlink. */
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

    /** Time to next event of timers and similar. This is used to determine
     *  how long to wait on event wait (select/poll on link/tun read)
     *  before this context wants to be serviced. */
    struct timeval timeval;

    /* next wakeup for processing coarse timers (>1 sec resolution) */
    time_t coarse_timer_wakeup;

    /* maintain a random delta to add to timeouts to avoid contexts
     * waking up simultaneously */
    time_t update_timeout_random_component;
    struct timeval timeout_random_component;

    /* Timer for everything up to the first packet from the *OpenVPN* server
     * socks, http proxy, and tcp packets do not count */
    struct event_timeout server_poll_interval;

    /* indicates that the do_up_delay function has run */
    bool do_up_ran;

    /* indicates that we have received a SIGTERM when
     * options->explicit_exit_notification is enabled,
     * but we have not exited yet */
    time_t explicit_exit_notification_time_wait;
    struct event_timeout explicit_exit_notification_interval;

    /* environmental variables to pass to scripts */
    struct env_set *es;
    bool es_owned;

    /* don't wait for TUN/TAP/UDP to be ready to accept write */
    bool fast_io;

    /* --ifconfig endpoints to be pushed to client */
    bool push_request_received;
    bool push_ifconfig_defined;
    time_t sent_push_reply_expiry;
    in_addr_t push_ifconfig_local;
    in_addr_t push_ifconfig_remote_netmask;
    in_addr_t push_ifconfig_local_alias;

    bool push_ifconfig_ipv6_defined;
    struct in6_addr push_ifconfig_ipv6_local;
    int push_ifconfig_ipv6_netbits;
    struct in6_addr push_ifconfig_ipv6_remote;

    struct event_timeout push_request_interval;
    time_t push_request_timeout;

    /* hash of pulled options, so we can compare when options change */
    bool pulled_options_digest_init_done;
    md_ctx_t *pulled_options_state;
    struct sha256_digest pulled_options_digest;

    struct event_timeout scheduled_exit;
    int scheduled_exit_signal;

    /* packet filter */

#ifdef ENABLE_MANAGEMENT
    struct man_def_auth_context mda_context;
#endif

#ifdef ENABLE_ASYNC_PUSH
    int inotify_fd; /* descriptor for monitoring file changes */
#endif
};


/**
 * Contains all state information for one tunnel.
 *
 * This structure represents one VPN tunnel.  It is used to store state
 * information related to a VPN tunnel, but also includes process-wide
 * data, such as configuration options.
 *
 * The @ref tunnel_state "Structure of VPN tunnel state storage" related
 * page describes how this structure is used in client-mode and
 * server-mode.
 */
struct context
{
    struct options options;     /**< Options loaded from command line or
                                 *   configuration file. */

    bool first_time;            /**< True on the first iteration of
                                 *   OpenVPN's main loop. */

    /* context modes */
#define CM_P2P            0  /* standalone point-to-point session or client */
#define CM_TOP            1  /* top level of a multi-client or point-to-multipoint server */
#define CM_TOP_CLONE      2  /* clone of a CM_TOP context for one thread */
#define CM_CHILD_UDP      3  /* child context of a CM_TOP or CM_THREAD */
#define CM_CHILD_TCP      4  /* child context of a CM_TOP or CM_THREAD */
    int mode;                   /**< Role of this context within the
                                 *   OpenVPN process.  Valid values are \c
                                 *   CM_P2P, \c CM_TOP, \c CM_TOP_CLONE,
                                 *   \c CM_CHILD_UDP, and \c CM_CHILD_TCP. */

    struct gc_arena gc;         /**< Garbage collection arena for
                                 *   allocations done in the scope of this
                                 *   context structure. */

    struct env_set *es;         /**< Set of environment variables. */

    openvpn_net_ctx_t net_ctx;  /**< Networking API opaque context */

    struct signal_info *sig;    /**< Internal error signaling object. */

    struct plugin_list *plugins; /**< List of plug-ins. */
    bool plugins_owned;         /**< Whether the plug-ins should be
                                 *   cleaned up when this %context is
                                 *   cleaned up. */

    bool did_we_daemonize;      /**< Whether demonization has already
                                 *   taken place. */

    struct context_persist persist;
    /**< Persistent %context. */
    struct context_0 *c0;       /**< Level 0 %context. */
    struct context_1 c1;        /**< Level 1 %context. */
    struct context_2 c2;        /**< Level 2 %context. */
};

/*
 * Check for a signal when inside an event loop
 */
#define EVENT_LOOP_CHECK_SIGNAL(c, func, arg)   \
    if (IS_SIG(c))                           \
    {                                       \
        const int brk = func(arg);           \
        perf_pop();                          \
        if (brk) {                              \
            break;}                              \
        else {                                  \
            continue;}                           \
    }

/*
 * Macros for referencing objects which may not
 * have been compiled in.
 */

#define TLS_MODE(c) ((c)->c2.tls_multi != NULL)
#define PROTO_DUMP_FLAGS (check_debug_level(D_LINK_RW_VERBOSE) ? (PD_SHOW_DATA|PD_VERBOSE) : 0)
#define PROTO_DUMP(buf, gc) protocol_dump((buf), \
                                          PROTO_DUMP_FLAGS   \
                                          |(c->c2.tls_multi ? PD_TLS : 0)   \
                                          |(c->options.tls_auth_file ? md_kt_size(c->c1.ks.key_type.digest) : 0) \
                                          |(c->options.tls_crypt_file || c->options.tls_crypt_v2_file ? PD_TLS_CRYPT : 0), \
                                          gc)

/* this represents "disabled peer-id" */
#define MAX_PEER_ID 0xFFFFFF

#endif /* ifndef OPENVPN_H */
