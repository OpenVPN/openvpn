/*
 *  OpenVPN -- An application to securely tunnel IP networks
 *             over a single UDP port, with support for SSL/TLS-based
 *             session authentication and key exchange,
 *             packet encryption, packet authentication, and
 *             packet compression.
 *
 *  Copyright (C) 2002-2025 OpenVPN Inc <sales@openvpn.net>
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
 *  with this program; if not, see <https://www.gnu.org/licenses/>.
 */

/*
 * 2004-01-28: Added Socks5 proxy support
 *   (Christof Meerwald, https://cmeerw.org)
 */

#ifndef OPTIONS_H
#define OPTIONS_H

#include "basic.h"
#include "common.h"
#include "mtu.h"
#include "route.h"
#include "tun.h"
#include "socket_util.h"
#include "plugin.h"
#include "manage.h"
#include "proxy.h"
#include "comp.h"
#include "pushlist.h"
#include "clinat.h"
#include "crypto_backend.h"
#include "dns.h"


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

/* certain options are saved before --pull modifications are applied */
struct options_pre_connect
{
    bool tuntap_options_defined;
    struct tuntap_options tuntap_options;

    const char *ifconfig_local;
    const char *ifconfig_ipv6_local;

    bool routes_defined;
    struct route_option_list *routes;

    bool routes_ipv6_defined;
    struct route_ipv6_option_list *routes_ipv6;

    const char *route_default_gateway;
    const char *route_ipv6_default_gateway;

    bool client_nat_defined;
    struct client_nat_option_list *client_nat;

    struct dns_options dns_options;

    const char *ciphername;
    const char *authname;

    int ping_send_timeout;
    int ping_rec_timeout;
    int ping_rec_timeout_action;

    int foreign_option_index;
    struct compress_options comp;
};

#if !defined(ENABLE_CRYPTO_OPENSSL) && !defined(ENABLE_CRYPTO_MBEDTLS)
#error "At least one of OpenSSL or mbed TLS needs to be defined."
#endif

struct local_entry
{
    const char *local;
    const char *port;
    int proto;
};

struct connection_entry
{
    struct local_list *local_list;
    int proto;
    sa_family_t af;
    const char *local_port;
    bool local_port_defined;
    const char *remote_port;
    const char *remote;
    bool remote_float;
    bool bind_defined;
    bool bind_ipv6_only;
    bool bind_local;
    int connect_retry_seconds;
    int connect_retry_seconds_max;
    int connect_timeout;
    struct http_proxy_options *http_proxy_options;
    const char *socks_proxy_server;
    const char *socks_proxy_port;
    const char *socks_proxy_authfile;

    int tun_mtu;          /* MTU of tun device */
    int occ_mtu;          /* if non-null, this is the MTU we announce to peers in OCC */
    int tun_mtu_max;      /* maximum MTU that can be pushed */

    bool tun_mtu_defined; /* true if user overriding parm with command line option */
    int tun_mtu_extra;
    bool tun_mtu_extra_defined;
    int link_mtu;          /* MTU of device over which tunnel packets pass via TCP/UDP */
    bool link_mtu_defined; /* true if user overriding parm with command line option */
    int tls_mtu;           /* Maximum MTU for the control channel messages */

    /* Advanced MTU negotiation and datagram fragmentation options */
    int mtu_discover_type;          /* used if OS supports setting Path MTU discovery options on socket */

    int fragment;                   /* internal fragmentation size */
    bool fragment_encap;            /* true if --fragment had the "mtu" parameter to
                                     * include overhead from IP and TCP/UDP encapsulation */
    int mssfix;                     /* Upper bound on TCP MSS */
    bool mssfix_default;            /* true if --mssfix should use the default parameters */
    bool mssfix_encap;              /* true if --mssfix had the "mtu" parameter to include
                                     * overhead from IP and TCP/UDP encapsulation */
    bool mssfix_fixed;              /* use the mssfix value without any encapsulation adjustments */

    int explicit_exit_notification; /* Explicitly tell peer when we are exiting via OCC_EXIT or
                                       [RESTART] message */

#define CE_DISABLED                (1u << 0)
#define CE_MAN_QUERY_PROXY         (1u << 1)
#define CE_MAN_QUERY_REMOTE_UNDEF  0
#define CE_MAN_QUERY_REMOTE_QUERY  1
#define CE_MAN_QUERY_REMOTE_ACCEPT 2
#define CE_MAN_QUERY_REMOTE_MOD    3
#define CE_MAN_QUERY_REMOTE_SKIP   4
#define CE_MAN_QUERY_REMOTE_MASK   (0x07u)
#define CE_MAN_QUERY_REMOTE_SHIFT  (2)
    unsigned int flags;

    /* Shared secret used for TLS control channel authentication */
    const char *tls_auth_file;
    bool tls_auth_file_inline;
    int key_direction;

    /* Shared secret used for TLS control channel authenticated encryption */
    const char *tls_crypt_file;
    bool tls_crypt_file_inline;

    /* Client-specific secret or server key used for TLS control channel
     * authenticated encryption v2 */
    const char *tls_crypt_v2_file;
    bool tls_crypt_v2_file_inline;

    /* Allow only client that support resending the wrapped client key */
    bool tls_crypt_v2_force_cookie;
};

struct remote_entry
{
    const char *remote;
    const char *remote_port;
    int proto;
    sa_family_t af;
};

#define CONNECTION_LIST_SIZE 64

struct local_list
{
    int capacity;
    int len;
    struct local_entry **array;
};

struct connection_list
{
    int capacity;
    int len;
    int current;
    struct connection_entry **array;
};

struct remote_list
{
    int capacity;
    int len;
    struct remote_entry **array;
};

struct provider_list
{
    /* Names of the providers */
    const char *names[MAX_PARMS];
    /* Pointers to the loaded providers to unload them */
    provider_t *providers[MAX_PARMS];
};

enum vlan_acceptable_frames
{
    VLAN_ONLY_TAGGED,
    VLAN_ONLY_UNTAGGED_OR_PRIORITY,
    VLAN_ALL,
};

struct remote_host_store
{
#define RH_HOST_LEN 80
    char host[RH_HOST_LEN];
#define RH_PORT_LEN 20
    char port[RH_PORT_LEN];
};

enum genkey_type
{
    GENKEY_SECRET,
    GENKEY_TLS_CRYPTV2_CLIENT,
    GENKEY_TLS_CRYPTV2_SERVER,
    GENKEY_AUTH_TOKEN
};

struct verify_hash_list
{
    /* We support SHA256 and SHA1 fingerpint. In the case of using the
     * deprecated SHA1, only the first 20 bytes of each list item are used */
    uint8_t hash[SHA256_DIGEST_LENGTH];
    struct verify_hash_list *next;
};

/* Command line options */
struct options
{
    struct gc_arena gc;
    bool gc_owned;

    /* first config file */
    const char *config;

    /* major mode */
#define MODE_POINT_TO_POINT 0
#define MODE_SERVER         1
    int mode;

    /* enable forward compatibility for post-2.1 features */
    bool forward_compatible;
    /** What version we should try to be compatible with as major * 10000 +
     * minor * 100 + patch, e.g. 2.4.7 => 20407 */
    unsigned int backwards_compatible;

    /* list of options that should be ignored even if unknown */
    const char **ignore_unknown_option;

    /* persist parms */
    bool persist_config;
    int persist_mode;

    const char *key_pass_file;
    bool show_ciphers;
    bool show_digests;
    bool show_engines;
    bool show_tls_ciphers;
    bool show_curves;
    bool genkey;
    enum genkey_type genkey_type;
    const char *genkey_filename;
    const char *genkey_extra_data;

    /* Networking parms */
    int connect_retry_max;
    struct connection_entry ce;
    struct connection_list *connection_list;

    struct remote_list *remote_list;
    /* Do not advance the connection or remote addr list */
    bool no_advance;
    /* Advance directly to the next remote, skipping remaining addresses of the
     * current remote */
    bool advance_next_remote;
    /* Counts the number of unsuccessful connection attempts */
    unsigned int unsuccessful_attempts;
    /* count of connection entries to advance by when no_advance is not set */
    int ce_advance_count;
    /* the server can suggest a backoff time to the client, it
     * will still be capped by the max timeout between connections
     * (300s by default) */
    int server_backoff_time;

#if ENABLE_MANAGEMENT
    struct http_proxy_options *http_proxy_override;
#endif

    struct remote_host_store *rh_store;

    struct dns_options dns_options;

    bool remote_random;
    const char *ipchange;
    const char *dev;
    const char *dev_type;
    const char *dev_node;
    const char *lladdr;
    int topology; /* one of the TOP_x values from proto.h */
    const char *ifconfig_local;
    const char *ifconfig_remote_netmask;
    const char *ifconfig_ipv6_local;
    int ifconfig_ipv6_netbits;
    const char *ifconfig_ipv6_remote;
    bool ifconfig_noexec;
    bool ifconfig_nowarn;
    int shaper;

    int proto_force;

    bool mtu_test;

#ifdef ENABLE_MEMSTATS
    char *memstats_fn;
#endif

    bool mlock;

    int keepalive_ping; /* a proxy for ping/ping-restart */
    int keepalive_timeout;

    int inactivity_timeout; /* --inactive */
    int64_t inactivity_minimum_bytes;

    int session_timeout;    /* Force-kill session after n seconds */

    int ping_send_timeout;  /* Send a TCP/UDP ping to remote every n seconds */
    int ping_rec_timeout;   /* Expect a TCP/UDP ping from remote at least once every n seconds */
    bool ping_timer_remote; /* Run ping timer only if we have a remote address */

#define PING_UNDEF   0
#define PING_EXIT    1
#define PING_RESTART 2
    int ping_rec_timeout_action; /* What action to take on ping_rec_timeout (exit or restart)? */

    bool persist_tun;            /* Don't close/reopen TUN/TAP dev on SIGUSR1 or PING_RESTART */
    bool persist_local_ip;       /* Don't re-resolve local address on SIGUSR1 or PING_RESTART */
    bool persist_remote_ip;      /* Don't re-resolve remote address on SIGUSR1 or PING_RESTART */

#if PASSTOS_CAPABILITY
    bool passtos;
#endif

    int resolve_retry_seconds; /* If hostname resolve fails, retry for n seconds */
    bool resolve_in_advance;
    const char *ip_remote_hint;

    struct tuntap_options tuntap_options;
    /* DCO is disabled and should not be used as backend driver for the
     * tun/tap device */
    bool disable_dco;

    /* Misc parms */
    const char *username;
    const char *groupname;
    const char *chroot_dir;
    const char *cd_dir;
#ifdef ENABLE_SELINUX
    char *selinux_context;
#endif
    const char *writepid;
    const char *up_script;
    const char *down_script;
    bool user_script_used;
    bool down_pre;
    bool up_delay;
    bool up_restart;
    bool daemon;

    int remap_sigusr1;

    bool log;
    bool suppress_timestamps;
    bool machine_readable_output;
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

    struct compress_options comp;

    /* buffer sizes */
    int rcvbuf;
    int sndbuf;

    /* mark value */
    int mark;
    char *bind_dev;

    /* socket flags */
    unsigned int sockflags;

    /* route management */
    const char *route_script;
    const char *route_predown_script;
    const char *route_default_gateway;
    const char *route_ipv6_default_gateway;
    int route_default_table_id;
    int route_default_metric;
    bool route_noexec;
    int route_delay;
    int route_delay_window;
    bool route_delay_defined;
    struct route_option_list *routes;
    struct route_ipv6_option_list *routes_ipv6; /* IPv6 */
    bool block_ipv6;
    bool route_nopull;
    bool route_gateway_via_dhcp;
    bool allow_pull_fqdn; /* as a client, allow server to push a FQDN for certain parameters */
    struct client_nat_option_list *client_nat;

    /* Enable options consistency check between peers */
    bool occ;

#ifdef ENABLE_MANAGEMENT
    const char *management_addr;
    const char *management_port;
    const char *management_user_pass;
    int management_log_history_cache;
    int management_echo_buffer_size;
    int management_state_buffer_size;

    const char *management_client_user;
    const char *management_client_group;

    const char *management_certificate;
#endif
    /* Mask of MF_ values of manage.h */
    unsigned int management_flags;

#ifdef ENABLE_PLUGIN
    struct plugin_option_list *plugin_list;
#endif

    /* the tmp dir is for now only used in the P2P server context */
    const char *tmp_dir;
    bool server_defined;
    in_addr_t server_network;
    in_addr_t server_netmask;
    bool server_ipv6_defined;            /* IPv6 */
    struct in6_addr server_network_ipv6; /* IPv6 */
    unsigned int server_netbits_ipv6;    /* IPv6 */

#define SF_NOPOOL                (1 << 0)
#define SF_TCP_NODELAY_HELPER    (1 << 1)
#define SF_NO_PUSH_ROUTE_GATEWAY (1 << 2)
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

    bool ifconfig_ipv6_pool_defined;         /* IPv6 */
    struct in6_addr ifconfig_ipv6_pool_base; /* IPv6 */
    int ifconfig_ipv6_pool_netbits;          /* IPv6 */

    uint32_t real_hash_size;
    uint32_t virtual_hash_size;
    const char *client_connect_script;
    const char *client_disconnect_script;
    const char *learn_address_script;
    const char *client_crresponse_script;
    const char *client_config_dir;
    bool ccd_exclusive;
    bool disable;
    const char *override_username;
    int n_bcast_buf;
    int tcp_queue_limit;
    struct iroute *iroutes;
    struct iroute_ipv6 *iroutes_ipv6; /* IPv6 */
    bool push_ifconfig_defined;
    in_addr_t push_ifconfig_local;
    in_addr_t push_ifconfig_remote_netmask;
    in_addr_t push_ifconfig_local_alias;
    bool push_ifconfig_constraint_defined;
    in_addr_t push_ifconfig_constraint_network;
    in_addr_t push_ifconfig_constraint_netmask;
    bool push_ifconfig_ipv4_blocked;           /* IPv4 */
    bool push_ifconfig_ipv6_defined;           /* IPv6 */
    struct in6_addr push_ifconfig_ipv6_local;  /* IPv6 */
    int push_ifconfig_ipv6_netbits;            /* IPv6 */
    struct in6_addr push_ifconfig_ipv6_remote; /* IPv6 */
    bool push_ifconfig_ipv6_blocked;           /* IPv6 */
    bool enable_c2c;
    bool duplicate_cn;

    int cf_max;
    int cf_per;

    int cf_initial_max;
    int cf_initial_per;

    int max_clients;
    int max_routes_per_client;
    int stale_routes_check_interval;
    int stale_routes_ageing_time;

    const char *auth_user_pass_verify_script;
    bool auth_user_pass_verify_script_via_file;
    bool auth_token_generate;
    bool auth_token_call_auth;
    int auth_token_lifetime;
    int auth_token_renewal;
    const char *auth_token_secret_file;
    bool auth_token_secret_file_inline;

#if PORT_SHARE
    char *port_share_host;
    char *port_share_port;
    const char *port_share_journal_dir;
#endif

    bool client;
    bool pull; /* client pull of config options from server */
    int push_continuation;
    unsigned int push_option_types_found;
    const char *auth_user_pass_file;
    bool auth_user_pass_file_inline;
    struct options_pre_connect *pre_connect;

    int scheduled_exit_interval;

#ifdef ENABLE_MANAGEMENT
    struct static_challenge_info sc_info;
#endif
    /* Cipher parms */
    const char *shared_secret_file;
    bool shared_secret_file_inline;
    bool allow_deprecated_insecure_static_crypto;
    int key_direction;
    const char *ciphername;
    bool enable_ncp_fallback; /**< If defined fall back to
                               * ciphername if NCP fails */
    /** The original ncp_ciphers specified by the user in the configuration*/
    const char *ncp_ciphers_conf;
    const char *ncp_ciphers;
    const char *authname;
    const char *engine;
    struct provider_list providers;
    bool mute_replay_warnings;
    int replay_window;
    int replay_time;
    const char *packet_id_file;
    bool test_crypto;
#ifdef ENABLE_PREDICTION_RESISTANCE
    bool use_prediction_resistance;
#endif

    /* TLS (control channel) parms */
    bool tls_server;
    bool tls_client;
    const char *ca_file;
    bool ca_file_inline;
    const char *ca_path;
    const char *dh_file;
    bool dh_file_inline;
    const char *cert_file;
    bool cert_file_inline;
    const char *extra_certs_file;
    bool extra_certs_file_inline;
    const char *priv_key_file;
    bool priv_key_file_inline;
    const char *pkcs12_file;
    bool pkcs12_file_inline;
    const char *cipher_list;
    const char *cipher_list_tls13;
    const char *tls_groups;
    const char *tls_cert_profile;
    const char *ecdh_curve;
    const char *tls_verify;
    const char *tls_export_peer_cert_dir;
    int verify_x509_type;
    const char *verify_x509_name;
    const char *crl_file;
    bool crl_file_inline;

    int ns_cert_type; /* set to 0, NS_CERT_CHECK_SERVER, or NS_CERT_CHECK_CLIENT */
    unsigned remote_cert_ku[MAX_PARMS];
    const char *remote_cert_eku;
    struct verify_hash_list *verify_hash;
    hash_algo_type verify_hash_algo;
    int verify_hash_depth;
    bool verify_hash_no_ca;
    unsigned int ssl_flags; /* set to SSLF_x flags from ssl.h */

#ifdef ENABLE_PKCS11
    const char *pkcs11_providers[MAX_PARMS];
    unsigned pkcs11_private_mode[MAX_PARMS];
    bool pkcs11_protected_authentication[MAX_PARMS];
    bool pkcs11_cert_private[MAX_PARMS];
    int pkcs11_pin_cache_period;
    const char *pkcs11_id;
    bool pkcs11_id_management;
#endif

#ifdef ENABLE_CRYPTOAPI
    const char *cryptoapi_cert;
#endif
    /* Per-packet timeout on control channel */
    int tls_timeout;

    /* Data channel key renegotiation parameters */
    int64_t renegotiate_bytes;
    int64_t renegotiate_packets;
    int renegotiate_seconds;
    int renegotiate_seconds_min;

    /* Data channel key handshake must finalize
     * within n seconds of handshake initiation. */
    int handshake_window;

#ifdef ENABLE_X509ALTUSERNAME
    /* Field list used to be the username in X509 cert. */
    char *x509_username_field[MAX_PARMS];
#endif

    /* Old key allowed to live n seconds after new key goes active */
    int transition_window;

    /* Shared secret used for TLS control channel authentication */
    const char *tls_auth_file;
    bool tls_auth_file_inline;

    /* Shared secret used for TLS control channel authenticated encryption */
    const char *tls_crypt_file;
    bool tls_crypt_file_inline;

    /* Client-specific secret or server key used for TLS control channel
     * authenticated encryption v2 */
    const char *tls_crypt_v2_file;
    bool tls_crypt_v2_file_inline;

    const char *tls_crypt_v2_metadata;

    const char *tls_crypt_v2_verify_script;

    /* Allow only one session */
    bool single_session;

    bool push_peer_info;

    bool tls_exit;

    const struct x509_track *x509_track;

    /* special state parms */
    int foreign_option_index;

#ifdef _WIN32
    HANDLE msg_channel;
    const char *exit_event_name;
    bool exit_event_initial_state;
    bool show_net_up;
    int route_method;
    bool block_outside_dns;
    enum tun_driver_type windows_driver;
#endif

    bool use_peer_id;
    uint32_t peer_id;

    /* Keying Material Exporters [RFC 5705] */
    const char *keying_material_exporter_label;
    int keying_material_exporter_length;
    /* force using TLS key material export for data channel key generation */
    bool force_key_material_export;

    bool vlan_tagging;
    enum vlan_acceptable_frames vlan_accept;
    uint16_t vlan_pvid;

    struct pull_filter_list *pull_filter_list;

    /* Useful when packets sent by openvpn itself are not subject
     * to the routing tables that would move packets into the tunnel. */
    bool allow_recursive_routing;

    /* data channel crypto flags set by push/pull. Reuses the CO_* crypto_flags */
    unsigned int imported_protocol_flags;
};

#define streq(x, y) (!strcmp((x), (y)))

/*
 * Option classes.
 */
#define OPT_P_GENERAL         (1u << 0)
#define OPT_P_UP              (1u << 1)
#define OPT_P_ROUTE           (1u << 2)
#define OPT_P_DHCPDNS         (1u << 3) /* includes ip windows options like */
#define OPT_P_SCRIPT          (1u << 4)
#define OPT_P_SETENV          (1u << 5)
#define OPT_P_SHAPER          (1u << 6)
#define OPT_P_TIMER           (1u << 7)
#define OPT_P_PERSIST         (1u << 8)
#define OPT_P_PERSIST_IP      (1u << 9)
#define OPT_P_COMP            (1u << 10) /* TODO */
#define OPT_P_MESSAGES        (1u << 11)
#define OPT_P_NCP             (1u << 12) /**< Negotiable crypto parameters */
#define OPT_P_TLS_PARMS       (1u << 13) /* TODO */
#define OPT_P_MTU             (1u << 14) /* TODO */
#define OPT_P_NICE            (1u << 15)
#define OPT_P_PUSH            (1u << 16)
#define OPT_P_INSTANCE        (1u << 17) /**< allowed in ccd, client-connect etc*/
#define OPT_P_CONFIG          (1u << 18)
#define OPT_P_EXPLICIT_NOTIFY (1u << 19)
#define OPT_P_ECHO            (1u << 20)
#define OPT_P_INHERIT         (1u << 21)
#define OPT_P_ROUTE_EXTRAS    (1u << 22)
#define OPT_P_PULL_MODE       (1u << 23)
#define OPT_P_PLUGIN          (1u << 24)
#define OPT_P_SOCKBUF         (1u << 25)
#define OPT_P_SOCKFLAGS       (1u << 26)
#define OPT_P_CONNECTION      (1u << 27)
#define OPT_P_PEER_ID         (1u << 28)
#define OPT_P_INLINE          (1u << 29)
#define OPT_P_PUSH_MTU        (1u << 30)
#define OPT_P_ROUTE_TABLE     (1u << 31)

#define OPT_P_DEFAULT (~(OPT_P_INSTANCE | OPT_P_PULL_MODE))

#define PULL_DEFINED(opt) ((opt)->pull)
#define PUSH_DEFINED(opt) ((opt)->push_list)

#ifndef PULL_DEFINED
#define PULL_DEFINED(opt) (false)
#endif

#ifndef PUSH_DEFINED
#define PUSH_DEFINED(opt) (false)
#endif

#ifdef _WIN32
#define ROUTE_OPTION_FLAGS(o) ((o)->route_method & ROUTE_METHOD_MASK)
#else
#define ROUTE_OPTION_FLAGS(o) (0)
#endif

#define SHAPER_DEFINED(opt) ((opt)->shaper)

#ifdef ENABLE_PLUGIN
#define PLUGIN_OPTION_LIST(opt) ((opt)->plugin_list)
#else
#define PLUGIN_OPTION_LIST(opt) (NULL)
#endif

#ifdef ENABLE_MANAGEMENT
#define MAN_CLIENT_AUTH_ENABLED(opt) ((opt)->management_flags & MF_CLIENT_AUTH)
#else
#define MAN_CLIENT_AUTH_ENABLED(opt) (false)
#endif

/*
 * some PUSH_UPDATE options
 */
#define OPT_P_U_ROUTE         (1 << 0)
#define OPT_P_U_ROUTE6        (1 << 1)
#define OPT_P_U_DNS           (1 << 2)
#define OPT_P_U_DHCP          (1 << 3)
#define OPT_P_U_REDIR_GATEWAY (1 << 4)

struct pull_filter
{
#define PUF_TYPE_UNDEF  0 /**< undefined filter type */
#define PUF_TYPE_ACCEPT 1 /**< filter type to accept a matching option */
#define PUF_TYPE_IGNORE 2 /**< filter type to ignore a matching option */
#define PUF_TYPE_REJECT 3 /**< filter type to reject and trigger SIGUSR1 */
    int type;
    int size;
    char *pattern;
    struct pull_filter *next;
};

struct pull_filter_list
{
    struct pull_filter *head;
    struct pull_filter *tail;
};

void add_option(struct options *options, char *p[], bool is_inline, const char *file,
                int line, const int level, const msglvl_t msglevel,
                const unsigned int permission_mask, unsigned int *option_types_found,
                struct env_set *es);

/**
 * @brief Resets options found in the PUSH_UPDATE message that are preceded by the `-` flag.
 *        This function is used in push-updates to reset specified options.
 *        The number of parameters `p` must always be 1. If the permission is verified,
 *        all related options are erased or reset to their default values.
 *        Upon successful permission verification (by VERIFY_PERMISSION()),
 *        `option_types_found` is filled with the flag corresponding to the option.
 *
 * @param c The context structure.
 * @param options A pointer to the options structure.
 * @param p An array of strings containing the options and their parameters.
 * @param is_inline A boolean indicating if the option is inline.
 * @param file The file where the function is called.
 * @param line The line number where the function is called.
 * @param msglevel The message level.
 * @param permission_mask The permission mask used by VERIFY_PERMISSION().
 * @param option_types_found A pointer to the variable where the flags corresponding to the options
 * found are stored.
 * @param es The environment set structure.
 */
void remove_option(struct context *c, struct options *options, char *p[], bool is_inline,
                   const char *file, int line, const msglvl_t msglevel,
                   const unsigned int permission_mask, unsigned int *option_types_found,
                   struct env_set *es);

/**
 * @brief Processes an option to update. It first checks whether it has already
 *        received an option of the same type within the same update message.
 *        If the option has already been received, it calls add_option().
 *        Otherwise, it deletes all existing values related to that option before calling
 * add_option().
 *
 * @param c The context structure.
 * @param options A pointer to the options structure.
 * @param p An array of strings containing the options and their parameters.
 * @param is_inline A boolean indicating if the option is inline.
 * @param file The file where the function is called.
 * @param line The line number where the function is called.
 * @param level The level of the option.
 * @param msglevel The message level for logging.
 * @param permission_mask The permission mask used by VERIFY_PERMISSION().
 * @param option_types_found A pointer to the variable where the flags corresponding to the options
 * found are stored.
 * @param es The environment set structure.
 * @param update_options_found A pointer to the variable where the flags corresponding to the update
 * options found are stored, used to check if an option of the same type has already been processed
 * by update_option() within the same push-update message.
 */
void update_option(struct context *c, struct options *options, char *p[], bool is_inline,
                   const char *file, int line, const int level, const msglvl_t msglevel,
                   const unsigned int permission_mask, unsigned int *option_types_found,
                   struct env_set *es, unsigned int *update_options_found);

void parse_argv(struct options *options, const int argc, char *argv[], const msglvl_t msglevel,
                const unsigned int permission_mask, unsigned int *option_types_found,
                struct env_set *es);

void read_config_file(struct options *options, const char *file, int level, const char *top_file,
                      const int top_line, const msglvl_t msglevel,
                      const unsigned int permission_mask, unsigned int *option_types_found,
                      struct env_set *es);

void read_config_string(const char *prefix, struct options *options, const char *config,
                        const msglvl_t msglevel, const unsigned int permission_mask,
                        unsigned int *option_types_found, struct env_set *es);

void notnull(const char *arg, const char *description);

void usage_small(void);

void usage(void);

void show_library_versions(const unsigned int flags);

#ifdef _WIN32
void show_windows_version(const unsigned int flags);

#endif

void show_dco_version(const unsigned int flags);

void init_options(struct options *o, const bool init_gc);

void uninit_options(struct options *o);

void setenv_settings(struct env_set *es, const struct options *o);

void show_settings(const struct options *o);

bool string_defined_equal(const char *s1, const char *s2);

const char *options_string_version(const char *s, struct gc_arena *gc);

char *options_string(const struct options *o, const struct frame *frame, struct tuntap *tt,
                     openvpn_net_ctx_t *ctx, bool remote, struct gc_arena *gc);

bool options_cmp_equal_safe(char *actual, const char *expected, size_t actual_n);

void options_warning_safe(char *actual, const char *expected, size_t actual_n);

bool options_cmp_equal(char *actual, const char *expected);

void options_warning(char *actual, const char *expected);

/**
 * Given an OpenVPN options string, extract the value of an option.
 *
 * @param options_string        Zero-terminated, comma-separated options string
 * @param opt_name              The name of the option to extract
 * @param gc                    The gc to allocate the return value
 *
 * @return gc-allocated value of option with name opt_name if option was found,
 *         or NULL otherwise.
 */
char *options_string_extract_option(const char *options_string, const char *opt_name,
                                    struct gc_arena *gc);


void options_postprocess(struct options *options, struct env_set *es);

bool options_postprocess_pull(struct options *o, struct env_set *es);

void pre_connect_restore(struct options *o, struct gc_arena *gc);

bool apply_push_options(struct context *c, struct options *options, struct buffer *buf,
                        unsigned int permission_mask, unsigned int *option_types_found,
                        struct env_set *es, bool is_update);

void options_detach(struct options *o);

void options_server_import(struct options *o, const char *filename, msglvl_t msglevel,
                           unsigned int permission_mask, unsigned int *option_types_found,
                           struct env_set *es);

void pre_pull_default(struct options *o);

void rol_check_alloc(struct options *options);

int parse_line(const char *line, char *p[], const int n, const char *file, const int line_num,
               msglvl_t msglevel, struct gc_arena *gc);

/*
 * parse/print topology coding
 */

int parse_topology(const char *str, const msglvl_t msglevel);

const char *print_topology(const int topology);

/*
 * Manage auth-retry variable
 */

#define AR_NONE       0
#define AR_INTERACT   1
#define AR_NOINTERACT 2

int auth_retry_get(void);

bool auth_retry_set(const msglvl_t msglevel, const char *option);

const char *auth_retry_print(void);

void options_string_import(struct options *options, const char *config, const msglvl_t msglevel,
                           const unsigned int permission_mask, unsigned int *option_types_found,
                           struct env_set *es);

bool key_is_external(const struct options *options);

bool has_udp_in_local_list(const struct options *options);

/**
 * Returns whether the current configuration has dco enabled.
 */
static inline bool
dco_enabled(const struct options *o)
{
#ifdef ENABLE_DCO
    return !o->disable_dco;
#else
    return false;
#endif /* ENABLE_DCO */
}

#endif /* ifndef OPTIONS_H */
