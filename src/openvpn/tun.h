/*
 *  OpenVPN -- An application to securely tunnel IP networks
 *             over a single TCP/UDP port, with support for SSL/TLS-based
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

#ifndef TUN_H
#define TUN_H

#ifdef _WIN32
#include <winioctl.h>
#include <tap-windows.h>
#include <setupapi.h>
#include <cfgmgr32.h>
#endif

#include "buffer.h"
#include "error.h"
#include "mtu.h"
#include "win32.h"
#include "event.h"
#include "proto.h"
#include "misc.h"
#include "networking.h"
#include "dco.h"

enum tun_driver_type {
    WINDOWS_DRIVER_UNSPECIFIED,
    WINDOWS_DRIVER_TAP_WINDOWS6,
    DRIVER_GENERIC_TUNTAP,
    /** using an AF_UNIX socket to pass packets from/to an external program.
     *  This is always defined. We error out if a user tries to open this type
     *  of backend on unsupported platforms. */
    DRIVER_AFUNIX,
    DRIVER_NULL,
    DRIVER_DCO,
    /** macOS internal tun driver */
    DRIVER_UTUN
};

#ifdef _WIN32
#define DCO_WIN_REFERENCE_STRING "ovpn-dco"
#endif

#if defined(_WIN32) || defined(TARGET_ANDROID)

#define TUN_ADAPTER_INDEX_INVALID ((DWORD)-1)

/* time constants for --ip-win32 adaptive */
#define IPW32_SET_ADAPTIVE_DELAY_WINDOW 300
#define IPW32_SET_ADAPTIVE_TRY_NETSH    20

/* bit flags for DHCP options */
#define DHCP_OPTIONS_DHCP_OPTIONAL (1<<0)
#define DHCP_OPTIONS_DHCP_REQUIRED (1<<1)

struct tuntap_options {
    /* --ip-win32 options */
    bool ip_win32_defined;

#define IPW32_SET_MANUAL       0   /* "--ip-win32 manual" */
#define IPW32_SET_NETSH        1   /* "--ip-win32 netsh" */
#define IPW32_SET_IPAPI        2   /* "--ip-win32 ipapi" */
#define IPW32_SET_DHCP_MASQ    3   /* "--ip-win32 dynamic" */
#define IPW32_SET_ADAPTIVE     4   /* "--ip-win32 adaptive" */
#define IPW32_SET_N            5
    int ip_win32_type;

#ifdef _WIN32
    HANDLE msg_channel;
#endif

    /* --ip-win32 dynamic options */
    bool dhcp_masq_custom_offset;
    int dhcp_masq_offset;
    int dhcp_lease_time;

    /* --tap-sleep option */
    int tap_sleep;

    /* --dhcp-option options */

    int dhcp_options;

    const char *domain;      /* DOMAIN (15) */

    const char *netbios_scope; /* NBS (47) */

    int netbios_node_type;   /* NBT 1,2,4,8 (46) */

#define N_DHCP_ADDR 4        /* Max # of addresses allowed for
                              * DNS, WINS, etc. */

    /* DNS (6) */
    in_addr_t dns[N_DHCP_ADDR];
    int dns_len;

    /* WINS (44) */
    in_addr_t wins[N_DHCP_ADDR];
    int wins_len;

    /* NTP (42) */
    in_addr_t ntp[N_DHCP_ADDR];
    int ntp_len;

    /* NBDD (45) */
    in_addr_t nbdd[N_DHCP_ADDR];
    int nbdd_len;

#define N_SEARCH_LIST_LEN 10 /* Max # of entries in domin-search list */

    /* SEARCH (119), MacOS, Linux, Win10 1809+ */
    const char *domain_search_list[N_SEARCH_LIST_LEN];
    int domain_search_list_len;

    /* DISABLE_NBT (43, Vendor option 001) */
    bool disable_nbt;

    bool dhcp_renew;
    bool dhcp_pre_release;

    bool register_dns;

    struct in6_addr dns6[N_DHCP_ADDR];
    int dns6_len;
#if defined(TARGET_ANDROID)
    const char *http_proxy;
    int http_proxy_port;
#endif
};

#elif defined(TARGET_LINUX)

struct tuntap_options {
    int txqueuelen;
};

#else  /* if defined(_WIN32) || defined(TARGET_ANDROID) */

struct tuntap_options {
    int dummy; /* not used */
};

#endif /* if defined(_WIN32) || defined(TARGET_ANDROID) */

/*
 * Define a TUN/TAP dev.
 */
#ifndef WIN32
typedef struct afunix_context
{
    pid_t childprocess;
} afunix_context_t;

#else /* ifndef WIN32 */
typedef struct {
    int dummy;
} afunix_context_t;
#endif

struct tuntap
{
#define TUNNEL_TYPE(tt) ((tt) ? ((tt)->type) : DEV_TYPE_UNDEF)
    int type; /* DEV_TYPE_x as defined in proto.h */

#define TUNNEL_TOPOLOGY(tt) ((tt) ? ((tt)->topology) : TOP_UNDEF)
    int topology; /* one of the TOP_x values */

    /** The backend driver that used for this tun/tap device. This can be
     * one of the various windows drivers, "normal" tun/tap, utun, dco, ...
     */
    enum tun_driver_type backend_driver;

    /** if the internal variables related to ifconfig of this struct have
     * been set up. This does NOT mean ifconfig has been called */
    bool did_ifconfig_setup;

    /** if the internal variables related to ifconfig-ipv6 of this struct have
     * been set up. This does NOT mean ifconfig has been called */
    bool did_ifconfig_ipv6_setup;

    bool persistent_if;         /* if existed before, keep on program end */

    struct tuntap_options options; /* options set on command line */

    char *actual_name; /* actual name of TUN/TAP dev, usually including unit number */

    /* ifconfig parameters */
    in_addr_t local;
    in_addr_t remote_netmask;

    struct in6_addr local_ipv6;
    struct in6_addr remote_ipv6;
    int netbits_ipv6;

#ifdef _WIN32
    HANDLE hand;
    /* used for async NEW_PEER dco call, which might wait for TCP connect */
    OVERLAPPED dco_new_peer_ov;
    struct overlapped_io reads;
    struct overlapped_io writes;
    struct rw_handle rw_handle;

    /* used for setting interface address via IP Helper API
     * or DHCP masquerade */
    bool ipapi_context_defined;
    ULONG ipapi_context;
    ULONG ipapi_instance;
    in_addr_t adapter_netmask;

    /* Windows adapter index for TAP-Windows adapter,
     * ~0 if undefined */
    DWORD adapter_index;

    int standby_iter;

    #else  /* ifdef _WIN32 */
    int fd; /* file descriptor for TUN/TAP dev */
#endif /* ifdef _WIN32 */

#ifdef TARGET_SOLARIS
    int ip_fd;
#endif

    /* used for printing status info only */
    unsigned int rwflags_debug;

    dco_context_t dco;
    afunix_context_t afunix;
};

static inline bool
tuntap_defined(const struct tuntap *tt)
{
#ifdef _WIN32
    return tt && tt->hand != NULL;
#else
    return tt && tt->fd >= 0;
#endif
}

/*
 * Function prototypes
 */

void open_tun(const char *dev, const char *dev_type, const char *dev_node,
              struct tuntap *tt, openvpn_net_ctx_t *ctx);

void close_tun(struct tuntap *tt, openvpn_net_ctx_t *ctx);

void tun_open_device(struct tuntap *tt, const char *dev_node,
                     const char **device_guid, struct gc_arena *gc);

void close_tun_handle(struct tuntap *tt);

int write_tun(struct tuntap *tt, uint8_t *buf, int len);

int read_tun(struct tuntap *tt, uint8_t *buf, int len);

void tuncfg(const char *dev, const char *dev_type, const char *dev_node,
            int persist_mode, const char *username,
            const char *groupname, const struct tuntap_options *options,
            openvpn_net_ctx_t *ctx);

const char *guess_tuntap_dev(const char *dev,
                             const char *dev_type,
                             const char *dev_node,
                             struct gc_arena *gc);

struct tuntap *init_tun(const char *dev,        /* --dev option */
                        const char *dev_type,   /* --dev-type option */
                        int topology,           /* one of the TOP_x values */
                        const char *ifconfig_local_parm,           /* --ifconfig parm 1 */
                        const char *ifconfig_remote_netmask_parm,  /* --ifconfig parm 2 */
                        const char *ifconfig_ipv6_local_parm,      /* --ifconfig parm 1 / IPv6 */
                        int ifconfig_ipv6_netbits_parm,            /* --ifconfig parm 1 / bits */
                        const char *ifconfig_ipv6_remote_parm,     /* --ifconfig parm 2 / IPv6 */
                        struct addrinfo *local_public,
                        struct addrinfo *remote_public,
                        const bool strict_warn,
                        struct env_set *es,
                        openvpn_net_ctx_t *ctx,
                        struct tuntap *tt);

void init_tun_post(struct tuntap *tt,
                   const struct frame *frame,
                   const struct tuntap_options *options);

void do_ifconfig_setenv(const struct tuntap *tt,
                        struct env_set *es);

/**
 * do_ifconfig - configure the tunnel interface
 *
 * @param tt        the tuntap interface context
 * @param ifname    the human readable interface name
 * @param tun_mtu   the MTU value to set the interface to
 * @param es        the environment to be used when executing the commands
 * @param ctx       the networking API opaque context
 */
void do_ifconfig(struct tuntap *tt, const char *ifname, int tun_mtu,
                 const struct env_set *es, openvpn_net_ctx_t *ctx);

/**
 * undo_ifconfig - undo configuration of the tunnel interface
 *
 * @param tt    the tuntap interface context
 * @param ctx   the networking API opaque context
 */
void undo_ifconfig(struct tuntap *tt, openvpn_net_ctx_t *ctx);

bool is_dev_type(const char *dev, const char *dev_type, const char *match_type);

int dev_type_enum(const char *dev, const char *dev_type);

const char *dev_type_string(const char *dev, const char *dev_type);

const char *ifconfig_options_string(const struct tuntap *tt, bool remote, bool disable, struct gc_arena *gc);

bool is_tun_p2p(const struct tuntap *tt);

void warn_on_use_of_common_subnets(openvpn_net_ctx_t *ctx);

/**
 * Return a string representation of the tun backed driver type
 */
const char *
print_tun_backend_driver(enum tun_driver_type driver);

/*
 * Should ifconfig be called before or after
 * tun dev open?
 */

#define IFCONFIG_BEFORE_TUN_OPEN 0
#define IFCONFIG_AFTER_TUN_OPEN  1

#define IFCONFIG_DEFAULT         IFCONFIG_AFTER_TUN_OPEN

static inline int
ifconfig_order(struct tuntap *tt)
{
    if (tt->backend_driver == DRIVER_AFUNIX)
    {
        return IFCONFIG_BEFORE_TUN_OPEN;
    }
#if defined(TARGET_LINUX)
    return IFCONFIG_AFTER_TUN_OPEN;
#elif defined(TARGET_SOLARIS)
    return IFCONFIG_AFTER_TUN_OPEN;
#elif defined(TARGET_OPENBSD)
    return IFCONFIG_AFTER_TUN_OPEN;
#elif defined(TARGET_DARWIN)
    return IFCONFIG_AFTER_TUN_OPEN;
#elif defined(TARGET_NETBSD)
    return IFCONFIG_AFTER_TUN_OPEN;
#elif defined(_WIN32)
    return IFCONFIG_AFTER_TUN_OPEN;
#elif defined(TARGET_ANDROID)
    return IFCONFIG_BEFORE_TUN_OPEN;
#else  /* if defined(TARGET_LINUX) */
    return IFCONFIG_DEFAULT;
#endif
}

#define ROUTE_BEFORE_TUN 0
#define ROUTE_AFTER_TUN 1
#define ROUTE_ORDER_DEFAULT ROUTE_AFTER_TUN

static inline int
route_order(struct tuntap *tt)
{
    if (tt->backend_driver == DRIVER_AFUNIX)
    {
        return ROUTE_BEFORE_TUN;
    }
#if defined(TARGET_ANDROID)
    return ROUTE_BEFORE_TUN;
#else
    return ROUTE_ORDER_DEFAULT;
#endif
}


#ifdef _WIN32

struct tap_reg
{
    const char *guid;
    enum tun_driver_type windows_driver;
    struct tap_reg *next;
};

struct panel_reg
{
    const char *name;
    const char *guid;
    struct panel_reg *next;
};

struct device_instance_id_interface
{
    LPBYTE net_cfg_instance_id;
    const char *device_interface;
    struct device_instance_id_interface *next;
};

int ascii2ipset(const char *name);

const char *ipset2ascii(int index);

const char *ipset2ascii_all(struct gc_arena *gc);

void verify_255_255_255_252(in_addr_t local, in_addr_t remote);

const IP_ADAPTER_INFO *get_adapter_info_list(struct gc_arena *gc);

const IP_ADAPTER_INFO *get_tun_adapter(const struct tuntap *tt, const IP_ADAPTER_INFO *list);

const IP_ADAPTER_INFO *get_adapter_info(DWORD index, struct gc_arena *gc);

const IP_PER_ADAPTER_INFO *get_per_adapter_info(const DWORD index, struct gc_arena *gc);

const IP_ADAPTER_INFO *get_adapter(const IP_ADAPTER_INFO *ai, DWORD index);

bool is_adapter_up(const struct tuntap *tt, const IP_ADAPTER_INFO *list);

bool is_ip_in_adapter_subnet(const IP_ADAPTER_INFO *ai, const in_addr_t ip, in_addr_t *highest_netmask);

DWORD adapter_index_of_ip(const IP_ADAPTER_INFO *list,
                          const in_addr_t ip,
                          int *count,
                          in_addr_t *netmask);

void show_tap_win_adapters(int msglev, int warnlev);

void show_adapters(int msglev);

void tap_allow_nonadmin_access(const char *dev_node);

void show_valid_win32_tun_subnets(void);

const char *tap_win_getinfo(const struct tuntap *tt, struct gc_arena *gc);

void tun_show_debug(struct tuntap *tt);

bool dhcp_release_by_adapter_index(const DWORD adapter_index);

bool dhcp_renew_by_adapter_index(const DWORD adapter_index);

void fork_register_dns_action(struct tuntap *tt);

void ipconfig_register_dns(const struct env_set *es);

void tun_standby_init(struct tuntap *tt);

bool tun_standby(struct tuntap *tt);

int tun_read_queue(struct tuntap *tt, int maxsize);

int tun_write_queue(struct tuntap *tt, struct buffer *buf);

static inline bool
tuntap_stop(int status)
{
    /*
     * This corresponds to the STATUS_NO_SUCH_DEVICE
     * error in tapdrvr.c.
     */
    if (status < 0)
    {
        return GetLastError() == ERROR_FILE_NOT_FOUND;
    }
    return false;
}

static inline bool
tuntap_abort(int status)
{
    /*
     * Typically generated when driver is halted.
     */
    if (status < 0)
    {
        return GetLastError() == ERROR_OPERATION_ABORTED;
    }
    return false;
}

int tun_write_win32(struct tuntap *tt, struct buffer *buf);

static inline bool
is_ip_packet_valid(const struct buffer *buf)
{
    const struct openvpn_iphdr *ih = (const struct openvpn_iphdr *)BPTR(buf);

    if (OPENVPN_IPH_GET_VER(ih->version_len) == 4)
    {
        if (BLEN(buf) < sizeof(struct openvpn_iphdr))
        {
            return false;
        }
    }
    else if (OPENVPN_IPH_GET_VER(ih->version_len) == 6)
    {
        if (BLEN(buf) < sizeof(struct openvpn_ipv6hdr))
        {
            return false;
        }
    }
    else
    {
        return false;
    }

    return true;
}

static inline bool
tuntap_is_dco_win(struct tuntap *tt)
{
    return tt && tt->backend_driver == DRIVER_DCO;
}

static inline bool
tuntap_is_dco_win_timeout(struct tuntap *tt, int status)
{
    return tuntap_is_dco_win(tt) && (status < 0) && (openvpn_errno() == ERROR_NETNAME_DELETED);
}

#else  /* ifdef _WIN32 */

static inline bool
tuntap_stop(int status)
{
    return false;
}

static inline bool
tuntap_abort(int status)
{
    return false;
}

static inline void
tun_standby_init(struct tuntap *tt)
{
}

static inline bool
tun_standby(struct tuntap *tt)
{
    return true;
}


static inline bool
tuntap_is_dco_win(struct tuntap *tt)
{
    return false;
}

static inline bool
tuntap_is_dco_win_timeout(struct tuntap *tt, int status)
{
    return false;
}

#endif /* ifdef _WIN32 */

/*
 * TUN/TAP I/O wait functions
 */

static inline event_t
tun_event_handle(const struct tuntap *tt)
{
#ifdef _WIN32
    return &tt->rw_handle;
#else
    return tt->fd;
#endif
}

static inline void
tun_set(struct tuntap *tt,
        struct event_set *es,
        unsigned int rwflags,
        void *arg,
        unsigned int *persistent)
{
    if (!tuntap_defined(tt) || tuntap_is_dco_win(tt))
    {
        return;
    }

    /* if persistent is defined, call event_ctl only if rwflags has changed since last call */
    if (!persistent || *persistent != rwflags)
    {
        event_ctl(es, tun_event_handle(tt), rwflags, arg);
        if (persistent)
        {
            *persistent = rwflags;
        }
    }
#ifdef _WIN32
    if (tt->backend_driver == WINDOWS_DRIVER_TAP_WINDOWS6 && (rwflags & EVENT_READ))
    {
        tun_read_queue(tt, 0);
    }
#endif
    tt->rwflags_debug = rwflags;

}

const char *tun_stat(const struct tuntap *tt, unsigned int rwflags, struct gc_arena *gc);
bool tun_name_is_fixed(const char *dev);

static inline bool
is_tun_type_set(const struct tuntap *tt)
{
    return tt && tt->type != DEV_TYPE_UNDEF;
}

static inline void
open_tun_null(struct tuntap *tt)
{
    tt->actual_name = string_alloc("null", NULL);
}
#endif /* TUN_H */
