/*
 *  OpenVPN -- An application to securely tunnel IP networks
 *             over a single TCP/UDP port, with support for SSL/TLS-based
 *             session authentication and key exchange,
 *             packet encryption, packet authentication, and
 *             packet compression.
 *
 *  Copyright (C) 2002-2005 OpenVPN Solutions LLC <info@openvpn.net>
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

#ifndef MANAGE_H
#define MANAGE_H

#ifdef ENABLE_MANAGEMENT

#include "misc.h"
#include "event.h"
#include "socket.h"

#define MANAGEMENT_VERSION                      1
#define MANAGEMENT_N_PASSWORD_RETRIES           3
#define MANAGEMENT_LOG_HISTORY_INITIAL_SIZE   100
#define MANAGEMENT_ECHO_BUFFER_SIZE           100
#define MANAGEMENT_STATE_BUFFER_SIZE          100

/*
 * Manage build-up of command line
 */
struct command_line
{
  struct buffer buf;
  struct buffer residual;
};

struct command_line *command_line_new (const int buf_len);
void command_line_free (struct command_line *cl);

void command_line_add (struct command_line *cl, const unsigned char *buf, const int len);
const unsigned char *command_line_get (struct command_line *cl);
void command_line_reset (struct command_line *cl);
void command_line_next (struct command_line *cl);

/*
 * Manage lists of output strings
 */

struct output_entry
{
  struct buffer buf;
  struct output_entry *next;
};

struct output_list
{
  struct output_entry *head; /* next item to pop/peek */
  struct output_entry *tail; /* last item pushed */
  int size;                  /* current number of entries */
  int max_size;              /* maximum size list should grow to */
};

struct output_list *output_list_new (const int max_size);
void output_list_free (struct output_list *ol);

bool output_list_defined (const struct output_list *ol);
void output_list_reset (struct output_list *ol);

void output_list_push (struct output_list *ol, const unsigned char *str);
const struct buffer *output_list_peek (struct output_list *ol);
void output_list_advance (struct output_list *ol, int n);

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
  in_addr_t remote_ip;
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

const char *log_entry_print (const struct log_entry *e, unsigned int flags, struct gc_arena *gc);

struct log_history
{
  int base;
  int size;
  int capacity;
  struct log_entry *array;
};

struct log_history *log_history_init (const int capacity);
void log_history_close (struct log_history *h);
void log_history_add (struct log_history *h, const struct log_entry *le);
void log_history_resize (struct log_history *h, const int capacity);
const struct log_entry *log_history_ref (const struct log_history *h, const int index);

static inline int
log_history_size (const struct log_history *h)
{
  return h->size;
}

static inline int
log_history_capacity (const struct log_history *h)
{
  return h->capacity;
}

/*
 * Callbacks for 'status' and 'kill' commands
 */
struct management_callback
{
  void *arg;
  void (*status) (void *arg, const int version, struct status_output *so);
  void (*show_net) (void *arg, const int msglevel);
  int (*kill_by_cn) (void *arg, const char *common_name);
  int (*kill_by_addr) (void *arg, const in_addr_t addr, const int port);
  void (*delete_event) (void *arg, event_t event);
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
  struct openvpn_sockaddr local;
  bool up_query_passwords;
  bool management_over_tunnel;
  struct user_pass up;
  int log_history_cache;
  int echo_buffer_size;
  int state_buffer_size;
  bool server;
  bool hold;
  bool signal_on_disconnect;
  bool management_forget_disconnect;
  bool connect_as_client;
  char *write_peer_info_file;

/* flags for handling the management interface "signal" command */
# define MANSIG_IGNORE_USR1_HUP  (1<<0)
# define MANSIG_MAP_USR1_TO_HUP  (1<<1)
# define MANSIG_MAP_USR1_TO_TERM (1<<2)
  unsigned int mansig;
};

/* up_query modes */
#define UP_QUERY_DISABLED  0
#define UP_QUERY_USER_PASS 1
#define UP_QUERY_PASS      2
#define UP_QUERY_NEED_OK   3

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

#ifdef WIN32
  struct net_event_win32 ne32;
#endif

  bool halt;
  bool password_verified;
  int password_tries;

  struct command_line *in;
  struct output_list *out;

  struct event_set *es;

  bool state_realtime;
  bool log_realtime;
  bool echo_realtime;
  int bytecount_update_seconds;
  time_t bytecount_last_update;

  const char *up_query_type;
  int up_query_mode;
  struct user_pass up_query;
};

struct management
{
  struct man_persist persist;
  struct man_settings settings;
  struct man_connection connection;
};

extern struct management *management;

struct user_pass;

struct management *management_init (void);

bool management_open (struct management *man,
		      const char *addr,
		      const int port,
		      const char *pass_file,
		      const bool server,
		      const bool query_passwords,
		      const int log_history_cache,
		      const int echo_buffer_size,
		      const int state_buffer_size,
		      const bool hold,
		      const bool signal_on_disconnect,
		      const bool management_forget_disconnect,
		      const bool connect_as_client,
		      const char *write_peer_info_file,
		      const int remap_sigusr1);

void management_close (struct management *man);

void management_post_tunnel_open (struct management *man, const in_addr_t tun_local_ip);

void management_pre_tunnel_close (struct management *man);

void management_socket_set (struct management *man,
			    struct event_set *es,
			    void *arg,
			    unsigned int *persistent);

void management_io (struct management *man);

void management_set_callback (struct management *man,
			      const struct management_callback *cb);

void management_clear_callback (struct management *man);

bool management_query_user_pass (struct management *man, struct user_pass *up, const char *type, const unsigned int flags);

bool management_should_daemonize (struct management *man);
bool management_would_hold (struct management *man);
bool management_hold (struct management *man);

void management_event_loop_n_seconds (struct management *man, int sec);

static inline bool
management_connected (const struct management *man)
{
  return man->connection.state == MS_CC_WAIT_READ || man->connection.state == MS_CC_WAIT_WRITE;
}

static inline bool
management_query_user_pass_enabled (const struct management *man)
{
  return man->settings.up_query_passwords;
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

#define OPENVPN_STATE_CLIENT_BASE   7  /* Base index of client-only states */

void management_set_state (struct management *man,
			   const int state,
			   const char *detail,
			   const in_addr_t tun_local_ip,
			   const in_addr_t tun_remote_ip);

/*
 * The management object keeps track of OpenVPN --echo
 * parameters.
 */
void management_echo (struct management *man, const char *string, const bool pull);

/*
 * OpenVPN calls here to indicate a password failure
 */

void management_auth_failure (struct management *man, const char *type);

/*
 * These functions drive the bytecount in/out counters.
 */

void man_bytecount_output (struct management *man);

static inline void
man_bytecount_possible_output (struct management *man)
{
  if (man->connection.bytecount_update_seconds > 0
      && now >= man->connection.bytecount_last_update
      + man->connection.bytecount_update_seconds)
    man_bytecount_output (man);
}

static inline void
management_bytes_out (struct management *man, const int size)
{
  man->persist.bytes_out += size;
  man_bytecount_possible_output (man);
}

static inline void
management_bytes_in (struct management *man, const int size)
{
  man->persist.bytes_in += size;
  man_bytecount_possible_output (man);
}

#endif

#endif
