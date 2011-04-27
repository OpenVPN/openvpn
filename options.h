/*
 *  OpenVPN -- An application to securely tunnel IP networks
 *             over a single UDP port, with support for SSL/TLS-based
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

/*
 * 2004-01-28: Added Socks5 proxy support
 *   (Christof Meerwald, http://cmeerw.org)
 */

#ifndef OPTIONS_H
#define OPTIONS_H

#include "basic.h"
#include "common.h"
#include "mtu.h"
#include "route.h"
#include "tun.h"
#include "socket.h"
#include "plugin.h"
#include "manage.h"
#include "proxy.h"
#include "lzo.h"
#include "pushlist.h"

/*
 * Maximum number of parameters associated with an option,
 * including the option name itself.
 */
#define MAX_PARMS 16

/*
 * Max size of options line and parameter.
 */
#define OPTION_PARM_SIZE 256
#define OPTION_LINE_SIZE 256

extern const char title_string[];

#if P2MP

/* certain options are saved before --pull modifications are applied */
struct options_pre_pull
{
  bool tuntap_options_defined;
  struct tuntap_options tuntap_options;

  bool routes_defined;
  struct route_option_list *routes;

  int foreign_option_index;
};

#endif

struct connection_entry
{
  int proto;
  int local_port;
  bool local_port_defined;
  int remote_port;
  bool port_option_used;
  const char *local;
  const char *remote;
  bool remote_float;
  bool bind_defined;
  bool bind_local;
  int connect_retry_seconds;
  bool connect_retry_defined;
  int connect_retry_max;
  int connect_timeout;
  bool connect_timeout_defined;
#ifdef ENABLE_HTTP_PROXY
  struct http_proxy_options *http_proxy_options;
#endif  
#ifdef ENABLE_SOCKS
  const char *socks_proxy_server;
  int socks_proxy_port;
  const char *socks_proxy_authfile;
  bool socks_proxy_retry;
#endif

# define CE_DISABLED (1<<0)
#if HTTP_PROXY_FALLBACK
# define CE_HTTP_PROXY_FALLBACK (1<<1)
  time_t ce_http_proxy_fallback_timestamp; /* time when fallback http_proxy_options was last updated */
#endif

  unsigned int flags;
};

struct remote_entry
{
  const char *remote;
  int remote_port;
  int proto;
};

#ifdef ENABLE_CONNECTION

#define CONNECTION_LIST_SIZE 64

struct connection_list
{
  int len;
  int current;
  int n_cycles;
  bool no_advance;
  struct connection_entry *array[CONNECTION_LIST_SIZE];
};

struct remote_list
{
  int len;
  struct remote_entry *array[CONNECTION_LIST_SIZE];
};

#endif

#if HTTP_PROXY_FALLBACK
struct hpo_store
{
  struct http_proxy_options hpo;
  char server[80];
};
#endif

/* Command line options */
struct options
{
  struct gc_arena gc;
  bool gc_owned;

  /* first config file */
  const char *config;

  /* major mode */
# define MODE_POINT_TO_POINT 0
# define MODE_SERVER         1
  int mode;

  /* enable forward compatibility for post-2.1 features */
  bool forward_compatible;

  /* persist parms */
  bool persist_config;
  int persist_mode;

#ifdef USE_CRYPTO
  const char *key_pass_file;
  bool show_ciphers;
  bool show_digests;
  bool show_engines;
#ifdef USE_SSL
  bool show_tls_ciphers;
#endif
  bool genkey;
#endif

  /* Networking parms */
  struct connection_entry ce;

#ifdef ENABLE_CONNECTION
  char *remote_ip_hint;
  struct connection_list *connection_list;
  struct remote_list *remote_list;
  bool force_connection_list;
#endif

#ifdef GENERAL_PROXY_SUPPORT
  struct auto_proxy_info *auto_proxy_info;
#endif

#if HTTP_PROXY_FALLBACK
  bool http_proxy_fallback;
  struct http_proxy_options *http_proxy_override;
  struct hpo_store *hpo_store; /* used to store dynamic proxy info given by management interface */
#endif

  bool remote_random;
  const char *ipchange;
  const char *dev;
  const char *dev_type;
  const char *dev_node;
  const char *lladdr;
  int topology; /* one of the TOP_x values from proto.h */
  const char *ifconfig_local;
  const char *ifconfig_remote_netmask;
  bool ifconfig_noexec;
  bool ifconfig_nowarn;
#ifdef HAVE_GETTIMEOFDAY
  int shaper;
#endif
  int tun_mtu;           /* MTU of tun device */
  int tun_mtu_extra;
  bool tun_mtu_extra_defined;
  int link_mtu;          /* MTU of device over which tunnel packets pass via TCP/UDP */
  bool tun_mtu_defined;  /* true if user overriding parm with command line option */
  bool link_mtu_defined; /* true if user overriding parm with command line option */

  int proto_force;

  /* Advanced MTU negotiation and datagram fragmentation options */
  int mtu_discover_type; /* used if OS supports setting Path MTU discovery options on socket */

#ifdef ENABLE_OCC
  bool mtu_test;
#endif

  int fragment;                 /* internal fragmentation size */

  bool mlock;

  int keepalive_ping;           /* a proxy for ping/ping-restart */
  int keepalive_timeout;

  int inactivity_timeout;       /* --inactive */
  int inactivity_minimum_bytes;

  int ping_send_timeout;        /* Send a TCP/UDP ping to remote every n seconds */
  int ping_rec_timeout;         /* Expect a TCP/UDP ping from remote at least once every n seconds */
  bool ping_timer_remote;       /* Run ping timer only if we have a remote address */
  bool tun_ipv6;                /* Build tun dev that supports IPv6 */

# define PING_UNDEF   0
# define PING_EXIT    1
# define PING_RESTART 2
  int ping_rec_timeout_action;  /* What action to take on ping_rec_timeout (exit or restart)? */

#ifdef ENABLE_OCC
  int explicit_exit_notification;  /* Explicitly tell peer when we are exiting via OCC_EXIT message */
#endif

  bool persist_tun;             /* Don't close/reopen TUN/TAP dev on SIGUSR1 or PING_RESTART */
  bool persist_local_ip;        /* Don't re-resolve local address on SIGUSR1 or PING_RESTART */
  bool persist_remote_ip;       /* Don't re-resolve remote address on SIGUSR1 or PING_RESTART */
  bool persist_key;             /* Don't re-read key files on SIGUSR1 or PING_RESTART */

  int mssfix;                   /* Upper bound on TCP MSS */
  bool mssfix_default;          /* true if --mssfix was supplied without a parameter */

#if PASSTOS_CAPABILITY
  bool passtos;                  
#endif

  int resolve_retry_seconds;    /* If hostname resolve fails, retry for n seconds */

  struct tuntap_options tuntap_options;

  /* Misc parms */
  const char *username;
  const char *groupname;
  const char *chroot_dir;
  const char *cd_dir;
#ifdef HAVE_SETCON
  char *selinux_context;
#endif
  const char *writepid;
  const char *up_script;
  const char *down_script;
  bool down_pre;
  bool up_delay;
  bool up_restart;
  bool daemon;

  int remap_sigusr1;

  /* inetd modes defined in socket.h */
  int inetd;

  bool log;
  bool suppress_timestamps;
  int nice;
  int verbosity;
  int mute;

#ifdef ENABLE_DEBUG
  int gremlin;
#endif

  const char *status_file;
  int status_file_version;
  int status_file_update_freq;

  /* optimize TUN/TAP/UDP writes */
  bool fast_io;

#ifdef USE_LZO
  /* LZO_x flags from lzo.h */
  unsigned int lzo;
#endif

  /* buffer sizes */
  int rcvbuf;
  int sndbuf;

  /* socket flags */
  unsigned int sockflags;

  /* route management */
  const char *route_script;
  const char *route_default_gateway;
  int route_default_metric;
  bool route_noexec;
  int route_delay;
  int route_delay_window;
  bool route_delay_defined;
  int max_routes;
  struct route_option_list *routes;
  bool route_nopull;
  bool route_gateway_via_dhcp;
  bool allow_pull_fqdn; /* as a client, allow server to push a FQDN for certain parameters */

#ifdef ENABLE_OCC
  /* Enable options consistency check between peers */
  bool occ;
#endif

#ifdef ENABLE_MANAGEMENT
  const char *management_addr;
  int management_port;
  const char *management_user_pass;
  int management_log_history_cache;
  int management_echo_buffer_size;
  int management_state_buffer_size;
  const char *management_write_peer_info_file;

  const char *management_client_user;
  const char *management_client_group;

  /* Mask of MF_ values of manage.h */
  unsigned int management_flags;
#endif

#ifdef ENABLE_PLUGIN
  struct plugin_option_list *plugin_list;
#endif

  const char *tmp_dir;

#if P2MP

#if P2MP_SERVER
  bool server_defined;
  in_addr_t server_network;
  in_addr_t server_netmask;

# define SF_NOPOOL (1<<0)
# define SF_TCP_NODELAY_HELPER (1<<1)
# define SF_NO_PUSH_ROUTE_GATEWAY (1<<2)
  unsigned int server_flags;

  bool server_bridge_proxy_dhcp;

  bool server_bridge_defined;
  in_addr_t server_bridge_ip;
  in_addr_t server_bridge_netmask;
  in_addr_t server_bridge_pool_start;
  in_addr_t server_bridge_pool_end;

  struct push_list push_list;
  bool ifconfig_pool_defined;
  in_addr_t ifconfig_pool_start;
  in_addr_t ifconfig_pool_end;
  in_addr_t ifconfig_pool_netmask;
  const char *ifconfig_pool_persist_filename;
  int ifconfig_pool_persist_refresh_freq;
  int real_hash_size;
  int virtual_hash_size;
  const char *client_connect_script;
  const char *client_disconnect_script;
  const char *learn_address_script;
  const char *client_config_dir;
  bool ccd_exclusive;
  bool disable;
  int n_bcast_buf;
  int tcp_queue_limit;
  struct iroute *iroutes;
  bool push_ifconfig_defined;
  in_addr_t push_ifconfig_local;
  in_addr_t push_ifconfig_remote_netmask;
  bool push_ifconfig_constraint_defined;
  in_addr_t push_ifconfig_constraint_network;
  in_addr_t push_ifconfig_constraint_netmask;
  bool enable_c2c;
  bool duplicate_cn;
  int cf_max;
  int cf_per;
  int max_clients;
  int max_routes_per_client;

  const char *auth_user_pass_verify_script;
  bool auth_user_pass_verify_script_via_file;
  unsigned int ssl_flags; /* set to SSLF_x flags from ssl.h */
#if PORT_SHARE
  char *port_share_host;
  int port_share_port;
#endif
#endif

  bool client;
  bool pull; /* client pull of config options from server */
  int push_continuation;
  const char *auth_user_pass_file;
  struct options_pre_pull *pre_pull;

  int server_poll_timeout;

  int scheduled_exit_interval;

#endif

#ifdef USE_CRYPTO
  /* Cipher parms */
  const char *shared_secret_file;
#if ENABLE_INLINE_FILES
  const char *shared_secret_file_inline;
#endif
  int key_direction;
  bool ciphername_defined;
  const char *ciphername;
  bool authname_defined;
  const char *authname;
  int keysize;
  const char *prng_hash;
  int prng_nonce_secret_len;
  const char *engine;
  bool replay;
  bool mute_replay_warnings;
  int replay_window;
  int replay_time;
  const char *packet_id_file;
  bool use_iv;
  bool test_crypto;

#ifdef USE_SSL
  /* TLS (control channel) parms */
  bool tls_server;
  bool tls_client;
  const char *ca_file;
  const char *ca_path;
  const char *dh_file;
  const char *cert_file;
  const char *priv_key_file;
  const char *pkcs12_file;
  const char *cipher_list;
  const char *tls_verify;
  const char *tls_export_cert;
  const char *tls_remote;
  const char *crl_file;

#if ENABLE_INLINE_FILES
  const char *ca_file_inline;
  const char *cert_file_inline;
  char *priv_key_file_inline;
  const char *dh_file_inline;
  const char *pkcs12_file_inline; /* contains the base64 encoding of pkcs12 file */
#endif

  int ns_cert_type; /* set to 0, NS_SSL_SERVER, or NS_SSL_CLIENT */
  unsigned remote_cert_ku[MAX_PARMS];
  const char *remote_cert_eku;

#ifdef ENABLE_PKCS11
  const char *pkcs11_providers[MAX_PARMS];
  unsigned pkcs11_private_mode[MAX_PARMS];
  bool pkcs11_protected_authentication[MAX_PARMS];
  bool pkcs11_cert_private[MAX_PARMS];
  int pkcs11_pin_cache_period;
  const char *pkcs11_id;
  bool pkcs11_id_management;
#endif

#ifdef WIN32
  const char *cryptoapi_cert;
#endif

  /* data channel key exchange method */
  int key_method;

  /* Per-packet timeout on control channel */
  int tls_timeout;

  /* Data channel key renegotiation parameters */
  int renegotiate_bytes;
  int renegotiate_packets;
  int renegotiate_seconds;

  /* Data channel key handshake must finalize
     within n seconds of handshake initiation. */
  int handshake_window;

#ifdef ENABLE_X509ALTUSERNAME
  /* Field used to be the username in X509 cert. */
  char *x509_username_field;
#endif

  /* Old key allowed to live n seconds after new key goes active */
  int transition_window;

  /* Special authentication MAC for TLS control channel */
  const char *tls_auth_file;		/* shared secret */
#if ENABLE_INLINE_FILES
  const char *tls_auth_file_inline;
#endif

  /* Allow only one session */
  bool single_session;

#ifdef ENABLE_PUSH_PEER_INFO
  bool push_peer_info;
#endif

  bool tls_exit;

#endif /* USE_SSL */
#endif /* USE_CRYPTO */

  /* special state parms */
  int foreign_option_index;

#ifdef WIN32
  const char *exit_event_name;
  bool exit_event_initial_state;
  bool show_net_up;
  int route_method;
#endif
};

#define streq(x, y) (!strcmp((x), (y)))

/*
 * Option classes.
 */
#define OPT_P_GENERAL         (1<<0)
#define OPT_P_UP              (1<<1)
#define OPT_P_ROUTE           (1<<2)
#define OPT_P_IPWIN32         (1<<3)
#define OPT_P_SCRIPT          (1<<4)
#define OPT_P_SETENV          (1<<5)
#define OPT_P_SHAPER          (1<<6)
#define OPT_P_TIMER           (1<<7)
#define OPT_P_PERSIST         (1<<8)
#define OPT_P_PERSIST_IP      (1<<9)
#define OPT_P_COMP            (1<<10) /* TODO */
#define OPT_P_MESSAGES        (1<<11)
#define OPT_P_CRYPTO          (1<<12) /* TODO */
#define OPT_P_TLS_PARMS       (1<<13) /* TODO */
#define OPT_P_MTU             (1<<14) /* TODO */
#define OPT_P_NICE            (1<<15)
#define OPT_P_PUSH            (1<<16)
#define OPT_P_INSTANCE        (1<<17)
#define OPT_P_CONFIG          (1<<18)
#define OPT_P_EXPLICIT_NOTIFY (1<<19)
#define OPT_P_ECHO            (1<<20)
#define OPT_P_INHERIT         (1<<21)
#define OPT_P_ROUTE_EXTRAS    (1<<22)
#define OPT_P_PULL_MODE       (1<<23)
#define OPT_P_PLUGIN          (1<<24)
#define OPT_P_SOCKBUF         (1<<25)
#define OPT_P_SOCKFLAGS       (1<<26)
#define OPT_P_CONNECTION      (1<<27)

#define OPT_P_DEFAULT   (~(OPT_P_INSTANCE|OPT_P_PULL_MODE))

#if P2MP
#define PULL_DEFINED(opt) ((opt)->pull)
#if P2MP_SERVER
#define PUSH_DEFINED(opt) ((opt)->push_list)
#endif
#endif

#ifndef PULL_DEFINED
#define PULL_DEFINED(opt) (false)
#endif

#ifndef PUSH_DEFINED
#define PUSH_DEFINED(opt) (false)
#endif

#ifdef WIN32
#define ROUTE_OPTION_FLAGS(o) ((o)->route_method & ROUTE_METHOD_MASK)
#else
#define ROUTE_OPTION_FLAGS(o) (0)
#endif

#ifdef HAVE_GETTIMEOFDAY
#define SHAPER_DEFINED(opt) ((opt)->shaper)
#else
#define SHAPER_DEFINED(opt) (false)
#endif

#ifdef ENABLE_PLUGIN
#define PLUGIN_OPTION_LIST(opt) ((opt)->plugin_list)
#else
#define PLUGIN_OPTION_LIST(opt) (NULL)
#endif

#ifdef MANAGEMENT_DEF_AUTH
#define MAN_CLIENT_AUTH_ENABLED(opt) ((opt)->management_flags & MF_CLIENT_AUTH)
#else
#define MAN_CLIENT_AUTH_ENABLED(opt) (false)
#endif

void parse_argv (struct options *options,
		 const int argc,
		 char *argv[],
		 const int msglevel,
		 const unsigned int permission_mask,
		 unsigned int *option_types_found,
		 struct env_set *es);

void notnull (const char *arg, const char *description);

void usage_small (void);

void init_options (struct options *o, const bool init_gc);
void uninit_options (struct options *o);

void setenv_settings (struct env_set *es, const struct options *o);
void show_settings (const struct options *o);

bool string_defined_equal (const char *s1, const char *s2);

#ifdef ENABLE_OCC

const char *options_string_version (const char* s, struct gc_arena *gc);

char *options_string (const struct options *o,
		      const struct frame *frame,
		      struct tuntap *tt,
		      bool remote,
		      struct gc_arena *gc);

bool options_cmp_equal_safe (char *actual, const char *expected, size_t actual_n);
void options_warning_safe (char *actual, const char *expected, size_t actual_n);
bool options_cmp_equal (char *actual, const char *expected);
void options_warning (char *actual, const char *expected);

#endif

void options_postprocess (struct options *options);

void pre_pull_save (struct options *o);
void pre_pull_restore (struct options *o);

bool apply_push_options (struct options *options,
			 struct buffer *buf,
			 unsigned int permission_mask,
			 unsigned int *option_types_found,
			 struct env_set *es);

bool is_persist_option (const struct options *o);
bool is_stateful_restart (const struct options *o);

void options_detach (struct options *o);

void options_server_import (struct options *o,
			    const char *filename,
			    int msglevel,
			    unsigned int permission_mask,
			    unsigned int *option_types_found,
			    struct env_set *es);

void pre_pull_default (struct options *o);

void rol_check_alloc (struct options *options);

int parse_line (const char *line,
		char *p[],
		const int n,
		const char *file,
		const int line_num,
		int msglevel,
		struct gc_arena *gc);

/*
 * parse/print topology coding
 */

int parse_topology (const char *str, const int msglevel);
const char *print_topology (const int topology);

/*
 * Manage auth-retry variable
 */

#if P2MP

#define AR_NONE       0
#define AR_INTERACT   1
#define AR_NOINTERACT 2

int auth_retry_get (void);
bool auth_retry_set (const int msglevel, const char *option);
const char *auth_retry_print (void);

#endif

void options_string_import (struct options *options,
			    const char *config,
			    const int msglevel,
			    const unsigned int permission_mask,
			    unsigned int *option_types_found,
			    struct env_set *es);

/*
 * inline functions
 */
static inline bool
connection_list_defined (const struct options *o)
{
#ifdef ENABLE_CONNECTION
  return o->connection_list != NULL;
#else
  return false;
#endif
}

static inline void
connection_list_set_no_advance (struct options *o)
{
#ifdef ENABLE_CONNECTION
  if (o->connection_list)
    o->connection_list->no_advance = true;
#endif
}

#if HTTP_PROXY_FALLBACK

struct http_proxy_options *
parse_http_proxy_fallback (struct context *c,
			   const char *server,
			   const char *port,
			   const char *flags,
			   const int msglevel);

#endif /* HTTP_PROXY_FALLBACK */

#endif
