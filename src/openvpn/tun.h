/*
 *  OpenVPN -- An application to securely tunnel IP networks
 *             over a single TCP/UDP port, with support for SSL/TLS-based
 *             session authentication and key exchange,
 *             packet encryption, packet authentication, and
 *             packet compression.
 *
 *  Copyright (C) 2002-2022 OpenVPN Inc <sales@openvpn.net>
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
#include "ring_buffer.h"
#include "dco.h"

#ifdef _WIN32
#define WINTUN_COMPONENT_ID "wintun"

enum windows_driver_type {
    WINDOWS_DRIVER_UNSPECIFIED,
    WINDOWS_DRIVER_TAP_WINDOWS6,
    WINDOWS_DRIVER_WINTUN,
    WINDOWS_DRIVER_WINDCO
};
#endif

#if defined(_WIN32) || defined(TARGET_ANDROID)

#define TUN_ADAPTER_INDEX_INVALID ((DWORD)-1)

/* time constants for --ip-win32 adaptive */
#define IPW32_SET_ADAPTIVE_DELAY_WINDOW 300
#define IPW32_SET_ADAPTIVE_TRY_NETSH    20

struct tuntap_options {
    /* --ip-win32 options */
    bool ip_win32_defined;

    bool disable_dco;

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

    bool dhcp_options;

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
    bool disable_dco;
};

#else  /* if defined(_WIN32) || defined(TARGET_ANDROID) */

struct tuntap_options {
    int dummy; /* not used */
};

#endif /* if defined(_WIN32) || defined(TARGET_ANDROID) */

/*
 * Define a TUN/TAP dev.
 */

struct tuntap
{
#define TUNNEL_TYPE(tt) ((tt) ? ((tt)->type) : DEV_TYPE_UNDEF)
    int type; /* DEV_TYPE_x as defined in proto.h */

#define TUNNEL_TOPOLOGY(tt) ((tt) ? ((tt)->topology) : TOP_UNDEF)
    int topology; /* one of the TOP_x values */

    bool did_ifconfig_setup;
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

    enum windows_driver_type windows_driver;
    int standby_iter;

    HANDLE wintun_send_ring_handle;
    HANDLE wintun_receive_ring_handle;
    struct tun_ring *wintun_send_ring;
    struct tun_ring *wintun_receive_ring;
#else  /* ifdef _WIN32 */
    int fd; /* file descriptor for TUN/TAP dev */
#endif /* ifdef _WIN32 */

#ifdef TARGET_SOLARIS
    int ip_fd;
#endif

#ifdef HAVE_NET_IF_UTUN_H
    bool is_utun;
#endif
    /* used for printing status info only */
    unsigned int rwflags_debug;

    dco_context_t dco;
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

#ifdef _WIN32
static inline bool
tuntap_is_wintun(struct tuntap *tt)
{
    return tt && tt->windows_driver == WINDOWS_DRIVER_WINTUN;
}

static inline bool
tuntap_ring_empty(struct tuntap *tt)
{
    return tuntap_is_wintun(tt) && (tt->wintun_send_ring->head == tt->wintun_send_ring->tail);
}

/* Low level function to open tun handle, used by DCO to create a handle for DCO*/
void
tun_open_device(struct tuntap* tt, const char* dev_node, const char** device_guid, struct gc_arena* gc);
#endif

/*
 * Function prototypes
 */

void open_tun(const char *dev, const char *dev_type, const char *dev_node,
              struct tuntap *tt, openvpn_net_ctx_t *ctx);

void close_tun(struct tuntap *tt, openvpn_net_ctx_t *ctx);

void close_tun_handle(struct tuntap* tt);

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
 * @param mtu       the MTU value to set the interface to
 * @param es        the environment to be used when executing the commands
 * @param ctx       the networking API opaque context
 */
void do_ifconfig(struct tuntap *tt, const char *ifname, int tun_mtu,
                 const struct env_set *es, openvpn_net_ctx_t *ctx);

bool is_dev_type(const char *dev, const char *dev_type, const char *match_type);

int dev_type_enum(const char *dev, const char *dev_type);

const char *dev_type_string(const char *dev, const char *dev_type);

const char *ifconfig_options_string(const struct tuntap *tt, bool remote, bool disable, struct gc_arena *gc);

bool is_tun_p2p(const struct tuntap *tt);

void check_subnet_conflict(const in_addr_t ip,
                           const in_addr_t netmask,
                           const char *prefix);

void warn_on_use_of_common_subnets(openvpn_net_ctx_t *ctx);

/*
 * Should ifconfig be called before or after
 * tun dev open?
 */

#define IFCONFIG_BEFORE_TUN_OPEN 0
#define IFCONFIG_AFTER_TUN_OPEN  1

#define IFCONFIG_DEFAULT         IFCONFIG_AFTER_TUN_OPEN

static inline int
ifconfig_order(void)
{
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
route_order(void)
{
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
    enum windows_driver_type windows_driver;
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
    const char *device_interface_list;
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
        return openvpn_errno() == ERROR_FILE_NOT_FOUND;
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
        return openvpn_errno() == ERROR_OPERATION_ABORTED;
    }
    return false;
}

int tun_write_win32(struct tuntap *tt, struct buffer *buf);

static inline ULONG
wintun_ring_packet_align(ULONG size)
{
    return (size + (WINTUN_PACKET_ALIGN - 1)) & ~(WINTUN_PACKET_ALIGN - 1);
}

static inline ULONG
wintun_ring_wrap(ULONG value)
{
    return value & (WINTUN_RING_CAPACITY - 1);
}

static inline void
read_wintun(struct tuntap *tt, struct buffer *buf)
{
    struct tun_ring *ring = tt->wintun_send_ring;
    ULONG head = ring->head;
    ULONG tail = ring->tail;
    ULONG content_len;
    struct TUN_PACKET *packet;
    ULONG aligned_packet_size;

    *buf = tt->reads.buf_init;
    buf->len = 0;

    if ((head >= WINTUN_RING_CAPACITY) || (tail >= WINTUN_RING_CAPACITY))
    {
        msg(M_INFO, "Wintun: ring capacity exceeded");
        buf->len = -1;
        return;
    }

    if (head == tail)
    {
        /* nothing to read */
        return;
    }

    content_len = wintun_ring_wrap(tail - head);
    if (content_len < sizeof(struct TUN_PACKET_HEADER))
    {
        msg(M_INFO, "Wintun: incomplete packet header in send ring");
        buf->len = -1;
        return;
    }

    packet = (struct TUN_PACKET *) &ring->data[head];
    if (packet->size > WINTUN_MAX_PACKET_SIZE)
    {
        msg(M_INFO, "Wintun: packet too big in send ring");
        buf->len = -1;
        return;
    }

    aligned_packet_size = wintun_ring_packet_align(sizeof(struct TUN_PACKET_HEADER) + packet->size);
    if (aligned_packet_size > content_len)
    {
        msg(M_INFO, "Wintun: incomplete packet in send ring");
        buf->len = -1;
        return;
    }

    buf_write(buf, packet->data, packet->size);

    head = wintun_ring_wrap(head + aligned_packet_size);
    ring->head = head;
}

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

static inline int
write_wintun(struct tuntap *tt, struct buffer *buf)
{
    struct tun_ring *ring = tt->wintun_receive_ring;
    ULONG head = ring->head;
    ULONG tail = ring->tail;
    ULONG aligned_packet_size;
    ULONG buf_space;
    struct TUN_PACKET *packet;

    /* wintun marks ring as corrupted (overcapacity) if it receives invalid IP packet */
    if (!is_ip_packet_valid(buf))
    {
        msg(D_LOW, "write_wintun(): drop invalid IP packet");
        return 0;
    }

    if ((head >= WINTUN_RING_CAPACITY) || (tail >= WINTUN_RING_CAPACITY))
    {
        msg(M_INFO, "write_wintun(): head/tail value is over capacity");
        return -1;
    }

    aligned_packet_size = wintun_ring_packet_align(sizeof(struct TUN_PACKET_HEADER) + BLEN(buf));
    buf_space = wintun_ring_wrap(head - tail - WINTUN_PACKET_ALIGN);
    if (aligned_packet_size > buf_space)
    {
        msg(M_INFO, "write_wintun(): ring is full");
        return 0;
    }

    /* copy packet size and data into ring */
    packet = (struct TUN_PACKET * )&ring->data[tail];
    packet->size = BLEN(buf);
    memcpy(packet->data, BPTR(buf), BLEN(buf));

    /* move ring tail */
    ring->tail = wintun_ring_wrap(tail + aligned_packet_size);
    if (ring->alertable != 0)
    {
        SetEvent(tt->rw_handle.write);
    }

    return BLEN(buf);
}

static inline int
write_tun_buffered(struct tuntap *tt, struct buffer *buf)
{
    if (tt->windows_driver == WINDOWS_DRIVER_WINTUN)
    {
        return write_wintun(tt, buf);
    }
    else
    {
        return tun_write_win32(tt, buf);
    }
}

static inline bool is_windco(struct tuntap *tt)
{
    return tt->windows_driver == WINDOWS_DRIVER_WINDCO;
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


static inline bool is_windco(struct tuntap *tt)
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
    if (!tuntap_defined(tt) || is_windco(tt))
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
    if (tt->windows_driver == WINDOWS_DRIVER_TAP_WINDOWS6 && (rwflags & EVENT_READ))
    {
        tun_read_queue(tt, 0);
    }
#endif
    tt->rwflags_debug = rwflags;

}

const char *tun_stat(const struct tuntap *tt, unsigned int rwflags, struct gc_arena *gc);

#endif /* TUN_H */
