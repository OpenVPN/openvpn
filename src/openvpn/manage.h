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

#ifndef MANAGE_H
#define MANAGE_H

/* management_open flags */
#define MF_SERVER            (1<<0)
#define MF_QUERY_PASSWORDS   (1<<1)
#define MF_HOLD              (1<<2)
#define MF_SIGNAL            (1<<3)
#define MF_FORGET_DISCONNECT (1<<4)
#define MF_CONNECT_AS_CLIENT (1<<5)
#define MF_CLIENT_AUTH       (1<<6)
/* #define MF_CLIENT_PF         (1<<7) *REMOVED FEATURE* */
#define MF_UNIX_SOCK                (1<<8)
#define MF_EXTERNAL_KEY             (1<<9)
#define MF_EXTERNAL_KEY_NOPADDING   (1<<10)
#define MF_EXTERNAL_KEY_PKCS1PAD    (1<<11)
#define MF_UP_DOWN                  (1<<12)
#define MF_QUERY_REMOTE             (1<<13)
#define MF_QUERY_PROXY              (1<<14)
#define MF_EXTERNAL_CERT            (1<<15)
#define MF_EXTERNAL_KEY_PSSPAD      (1<<16)
#define MF_EXTERNAL_KEY_DIGEST      (1<<17)


#ifdef ENABLE_MANAGEMENT

#include "misc.h"
#include "event.h"
#include "socket.h"
#include "mroute.h"

#define MANAGEMENT_VERSION                      5
#define MANAGEMENT_N_PASSWORD_RETRIES           3
#define MANAGEMENT_LOG_HISTORY_INITIAL_SIZE   100
#define MANAGEMENT_ECHO_BUFFER_SIZE           100
#define MANAGEMENT_STATE_BUFFER_SIZE          100

/*
 * Management-interface-based deferred authentication
 */
struct man_def_auth_context {
    unsigned long cid;

#define DAF_CONNECTION_ESTABLISHED (1<<0)
#define DAF_CONNECTION_CLOSED      (1<<1)
#define DAF_INITIAL_AUTH           (1<<2)
    unsigned int flags;

    unsigned int mda_key_id_counter;

    time_t bytecount_last_update;
};

/*
 * Manage build-up of command line
 */
struct command_line
{
    struct buffer buf;
    struct buffer residual;
};

struct command_line *command_line_new(const int buf_len);

void command_line_free(struct command_line *cl);

void command_line_add(struct command_line *cl, const unsigned char *buf, const int len);

const char *command_line_get(struct command_line *cl);

void command_line_reset(struct command_line *cl);

void command_line_next(struct command_line *cl);

/*
 * Manage log file history
 */

union log_entry_union {
    unsigned int msg_flags;
    int state;
    int intval;
};

struct log_entry
{
    time_t timestamp;
    const char *string;
    in_addr_t local_ip;
    struct in6_addr local_ip6;
    struct openvpn_sockaddr local_sock;
    struct openvpn_sockaddr remote_sock;
    union log_entry_union u;
};

#define LOG_PRINT_LOG_PREFIX   (1<<0)
#define LOG_PRINT_ECHO_PREFIX  (1<<1)
#define LOG_PRINT_STATE_PREFIX (1<<2)

#define LOG_PRINT_INT_DATE     (1<<3)
#define LOG_PRINT_MSG_FLAGS    (1<<4)
#define LOG_PRINT_STATE        (1<<5)
#define LOG_PRINT_LOCAL_IP     (1<<6)

#define LOG_PRINT_CRLF         (1<<7)
#define LOG_FATAL_NOTIFY       (1<<8)

#define LOG_PRINT_INTVAL       (1<<9)

#define LOG_PRINT_REMOTE_IP    (1<<10)

#define LOG_ECHO_TO_LOG        (1<<11)

const char *log_entry_print(const struct log_entry *e, unsigned int flags, struct gc_arena *gc);

struct log_history
{
    int base;
    int size;
    int capacity;
    struct log_entry *array;
};

struct log_history *log_history_init(const int capacity);

void log_history_close(struct log_history *h);

void log_history_add(struct log_history *h, const struct log_entry *le);

void log_history_resize(struct log_history *h, const int capacity);

const struct log_entry *log_history_ref(const struct log_history *h, const int index);

static inline int
log_history_size(const struct log_history *h)
{
    return h->size;
}

static inline int
log_history_capacity(const struct log_history *h)
{
    return h->capacity;
}

/*
 * Callbacks for 'status' and 'kill' commands.
 * Also for management-based deferred authentication and packet filter.
 */
struct management_callback
{
    void *arg;

#define MCF_SERVER (1<<0)  /* is OpenVPN being run as a server? */
    unsigned int flags;

    void (*status) (void *arg, const int version, struct status_output *so);
    void (*show_net) (void *arg, const int msglevel);
    int (*kill_by_cn) (void *arg, const char *common_name);
    int (*kill_by_addr) (void *arg, const in_addr_t addr, const int port);
    void (*delete_event) (void *arg, event_t event);
    int (*n_clients) (void *arg);
    bool (*send_cc_message) (void *arg, const char *message, const char *parameter);
    bool (*kill_by_cid)(void *arg, const unsigned long cid, const char *kill_msg);
    bool (*client_auth) (void *arg,
                         const unsigned long cid,
                         const unsigned int mda_key_id,
                         const bool auth,
                         const char *reason,
                         const char *client_reason,
                         struct buffer_list *cc_config); /* ownership transferred */
    bool (*client_pending_auth) (void *arg,
                                 const unsigned long cid,
                                 const unsigned int kid,
                                 const char *extra,
                                 unsigned int timeout);
    char *(*get_peer_info) (void *arg, const unsigned long cid);
    bool (*proxy_cmd)(void *arg, const char **p);
    bool (*remote_cmd) (void *arg, const char **p);
#ifdef TARGET_ANDROID
    int (*network_change)(void *arg, bool samenetwork);
#endif
    unsigned int (*remote_entry_count)(void *arg);
    bool (*remote_entry_get)(void *arg, unsigned int index, char **remote);
};

/*
 * Management object, split into three components:
 *
 * struct man_persist : Data elements which are persistent across
 *                      man_connection open and close.
 *
 * struct man_settings : management parameters.
 *
 * struct man_connection : created on socket binding and listen,
 *                         deleted on socket unbind, may
 *                         handle multiple sequential client
 *                         connections.
 */

struct man_persist {
    bool defined;

    struct log_history *log;
    struct virtual_output vout;

    bool standalone_disabled;
    struct management_callback callback;

    struct log_history *echo; /* saved --echo strings */
    struct log_history *state;

    bool hold_release;

    const char *special_state_msg;

    counter_type bytes_in;
    counter_type bytes_out;
};

struct man_settings {
    bool defined;
    unsigned int flags; /* MF_x flags */
    struct addrinfo *local;
#if UNIX_SOCK_SUPPORT
    struct sockaddr_un local_unix;
#endif
    bool management_over_tunnel;
    struct user_pass up;
    int log_history_cache;
    int echo_buffer_size;
    int state_buffer_size;
    int client_uid;
    int client_gid;

/* flags for handling the management interface "signal" command */
#define MANSIG_IGNORE_USR1_HUP  (1<<0)
#define MANSIG_MAP_USR1_TO_HUP  (1<<1)
#define MANSIG_MAP_USR1_TO_TERM (1<<2)
    unsigned int mansig;
};

/* up_query modes */
#define UP_QUERY_DISABLED  0
#define UP_QUERY_USER_PASS 1
#define UP_QUERY_PASS      2
#define UP_QUERY_NEED_OK   3
#define UP_QUERY_NEED_STR  4

/* states */
#define MS_INITIAL          0  /* all sockets are closed */
#define MS_LISTEN           1  /* no client is connected */
#define MS_CC_WAIT_READ     2  /* client is connected, waiting for read on socket */
#define MS_CC_WAIT_WRITE    3  /* client is connected, waiting for ability to write to socket */

struct man_connection {
    int state;

    socket_descriptor_t sd_top;
    socket_descriptor_t sd_cli;
    struct openvpn_sockaddr remote;

#ifdef _WIN32
    struct net_event_win32 ne32;
#endif

    bool halt;
    bool password_verified;
    int password_tries;

    struct command_line *in;
    struct buffer_list *out;

#define IEC_UNDEF       0
#define IEC_CLIENT_AUTH 1
/* #define IEC_CLIENT_PF   2 *REMOVED FEATURE* */
#define IEC_RSA_SIGN    3
#define IEC_CERTIFICATE 4
#define IEC_PK_SIGN     5
    int in_extra_cmd;
    struct buffer_list *in_extra;
    unsigned long in_extra_cid;
    unsigned int in_extra_kid;
#define EKS_UNDEF   0
#define EKS_SOLICIT 1
#define EKS_INPUT   2
#define EKS_READY   3
    int ext_key_state;
    struct buffer_list *ext_key_input;
    int ext_cert_state;
    struct buffer_list *ext_cert_input;
    struct event_set *es;
    int env_filter_level;

    bool state_realtime;
    bool log_realtime;
    bool echo_realtime;
    int bytecount_update_seconds;
    struct event_timeout bytecount_update_interval;

    const char *up_query_type;
    int up_query_mode;
    struct user_pass up_query;

#ifdef TARGET_ANDROID
    int fdtosend;
    int lastfdreceived;
#endif
    int client_version;
};

struct management
{
    struct man_persist persist;
    struct man_settings settings;
    struct man_connection connection;
};

extern struct management *management;

struct user_pass;

struct management *management_init(void);

bool management_open(struct management *man,
                     const char *addr,
                     const char *port,
                     const char *pass_file,
                     const char *client_user,
                     const char *client_group,
                     const int log_history_cache,
                     const int echo_buffer_size,
                     const int state_buffer_size,
                     const int remap_sigusr1,
                     const unsigned int flags);

void management_close(struct management *man);

void management_post_tunnel_open(struct management *man, const in_addr_t tun_local_ip);

void management_pre_tunnel_close(struct management *man);

void management_socket_set(struct management *man,
                           struct event_set *es,
                           void *arg,
                           unsigned int *persistent);

void management_io(struct management *man);

void management_set_callback(struct management *man,
                             const struct management_callback *cb);

void management_clear_callback(struct management *man);

bool management_query_user_pass(struct management *man,
                                struct user_pass *up,
                                const char *type,
                                const unsigned int flags,
                                const char *static_challenge);

#ifdef TARGET_ANDROID
bool management_android_control(struct management *man, const char *command, const char *msg);

#define ANDROID_KEEP_OLD_TUN 1
#define ANDROID_OPEN_BEFORE_CLOSE 2
int managment_android_persisttun_action(struct management *man);

#endif

bool management_should_daemonize(struct management *man);

bool management_would_hold(struct management *man);

bool management_hold(struct management *man, int holdtime);

void management_event_loop_n_seconds(struct management *man, int sec);

void management_up_down(struct management *man, const char *updown, const struct env_set *es);

void management_notify(struct management *man, const char *severity, const char *type, const char *text);

void management_notify_generic(struct management *man, const char *str);

void management_notify_client_needing_auth(struct management *management,
                                           const unsigned int auth_id,
                                           struct man_def_auth_context *mdac,
                                           const struct env_set *es);

void management_connection_established(struct management *management,
                                       struct man_def_auth_context *mdac,
                                       const struct env_set *es);

void management_notify_client_close(struct management *management,
                                    struct man_def_auth_context *mdac,
                                    const struct env_set *es);

void management_learn_addr(struct management *management,
                           struct man_def_auth_context *mdac,
                           const struct mroute_addr *addr,
                           const bool primary);

void management_notify_client_cr_response(unsigned mda_key_id,
                                          const struct man_def_auth_context *mdac,
                                          const struct env_set *es,
                                          const char *response);

char *management_query_pk_sig(struct management *man, const char *b64_data,
                              const char *algorithm);

char *management_query_cert(struct management *man, const char *cert_name);

static inline bool
management_connected(const struct management *man)
{
    return man->connection.state == MS_CC_WAIT_READ || man->connection.state == MS_CC_WAIT_WRITE;
}

static inline bool
management_query_user_pass_enabled(const struct management *man)
{
    return BOOL_CAST(man->settings.flags & MF_QUERY_PASSWORDS);
}

static inline bool
management_query_remote_enabled(const struct management *man)
{
    return BOOL_CAST(man->settings.flags & MF_QUERY_REMOTE);
}

static inline bool
management_query_proxy_enabled(const struct management *man)
{
    return BOOL_CAST(man->settings.flags & MF_QUERY_PROXY);
}


static inline bool
management_enable_def_auth(const struct management *man)
{
    return man && BOOL_CAST(man->settings.flags & MF_CLIENT_AUTH);
}

/*
 * OpenVPN tells the management layer what state it's in
 */

/* client/server states */
#define OPENVPN_STATE_INITIAL       0  /* Initial, undefined state */
#define OPENVPN_STATE_CONNECTING    1  /* Management interface has been initialized */
#define OPENVPN_STATE_ASSIGN_IP     2  /* Assigning IP address to virtual network interface */
#define OPENVPN_STATE_ADD_ROUTES    3  /* Adding routes to system */
#define OPENVPN_STATE_CONNECTED     4  /* Initialization sequence completed */
#define OPENVPN_STATE_RECONNECTING  5  /* Restart */
#define OPENVPN_STATE_EXITING       6  /* Exit */

/* client-only states */
#define OPENVPN_STATE_WAIT          7  /* Waiting for initial response from server */
#define OPENVPN_STATE_AUTH          8  /* Authenticating with server */
#define OPENVPN_STATE_GET_CONFIG    9  /* Downloading configuration from server */
#define OPENVPN_STATE_RESOLVE       10 /* DNS lookup */
#define OPENVPN_STATE_TCP_CONNECT   11 /* Connecting to TCP server */
#define OPENVPN_STATE_AUTH_PENDING  12 /* Waiting in auth-pending mode
                                        * technically variant of GET_CONFIG */

#define OPENVPN_STATE_CLIENT_BASE   7  /* Base index of client-only states */

void management_set_state(struct management *man,
                          const int state,
                          const char *detail,
                          const in_addr_t *tun_local_ip,
                          const struct in6_addr *tun_local_ip6,
                          const struct openvpn_sockaddr *local_addr,
                          const struct openvpn_sockaddr *remote_addr);

/*
 * The management object keeps track of OpenVPN --echo
 * parameters.
 */
void management_echo(struct management *man, const char *string, const bool pull);

/*
 * OpenVPN calls here to indicate a password failure
 */

void management_auth_failure(struct management *man, const char *type, const char *reason);

/*
 * Echo an authentication token to management interface
 */
void management_auth_token(struct management *man, const char *token);

/*
 * These functions drive the bytecount in/out counters.
 */

void
management_check_bytecount(struct context *c,
                           struct management *man,
                           struct timeval *timeval);

static inline void
management_bytes_client(struct management *man,
                        const int size_in,
                        const int size_out)
{
    if (!(man->persist.callback.flags & MCF_SERVER))
    {
        man->persist.bytes_in += size_in;
        man->persist.bytes_out += size_out;
    }
}

void
man_bytecount_output_server(const counter_type *bytes_in_total,
                            const counter_type *bytes_out_total,
                            struct man_def_auth_context *mdac);

static inline void
management_bytes_server(struct management *man,
                        const counter_type *bytes_in_total,
                        const counter_type *bytes_out_total,
                        struct man_def_auth_context *mdac)
{
    if (man->connection.bytecount_update_seconds > 0
        && now >= mdac->bytecount_last_update + man->connection.bytecount_update_seconds
        && (mdac->flags & (DAF_CONNECTION_ESTABLISHED | DAF_CONNECTION_CLOSED)) == DAF_CONNECTION_ESTABLISHED)
    {
        man_bytecount_output_server(bytes_in_total, bytes_out_total, mdac);
    }
}

void
man_persist_client_stats(struct management *man, struct context *c);

#endif /* ifdef ENABLE_MANAGEMENT */

/**
 * A sleep function that services the management layer for n seconds rather
 * than doing nothing.
 */
void management_sleep(const int n);

#endif /* ifndef MANAGE_H */
