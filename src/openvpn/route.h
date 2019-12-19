/*
 *  OpenVPN -- An application to securely tunnel IP networks
 *             over a single TCP/UDP port, with support for SSL/TLS-based
 *             session authentication and key exchange,
 *             packet encryption, packet authentication, and
 *             packet compression.
 *
 *  Copyright (C) 2002-2018 OpenVPN Inc <sales@openvpn.net>
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

/*
 * Support routines for adding/deleting network routes.
 */

#ifndef ROUTE_H
#define ROUTE_H

#include "basic.h"
#include "tun.h"
#include "misc.h"
#include "networking.h"

#ifdef _WIN32
/*
 * Windows route methods
 */
#define ROUTE_METHOD_ADAPTIVE  0  /* try IP helper first then route.exe */
#define ROUTE_METHOD_IPAPI     1  /* use IP helper API */
#define ROUTE_METHOD_EXE       2  /* use route.exe */
#define ROUTE_METHOD_SERVICE   3  /* use the privileged Windows service */
#define ROUTE_METHOD_MASK      3
#endif

/*
 * Route add/delete flags (must stay clear of ROUTE_METHOD bits)
 */
#define ROUTE_DELETE_FIRST  (1<<2)
#define ROUTE_REF_GW        (1<<3)

struct route_bypass
{
#define N_ROUTE_BYPASS 8
    int n_bypass;
    in_addr_t bypass[N_ROUTE_BYPASS];
};

struct route_special_addr
{
    /* bits indicating which members below are defined */
#define RTSA_REMOTE_ENDPOINT  (1<<0)
#define RTSA_REMOTE_HOST      (1<<1)
#define RTSA_DEFAULT_METRIC   (1<<2)
    unsigned int flags;

    in_addr_t remote_endpoint;
    in_addr_t remote_host;
    int remote_host_local; /* TLA_x value */
    struct route_bypass bypass;
    int default_metric;
};

struct route_option {
    struct route_option *next;
    const char *network;
    const char *netmask;
    const char *gateway;
    const char *metric;
};

/* redirect-gateway flags */
#define RG_ENABLE         (1<<0)
#define RG_LOCAL          (1<<1)
#define RG_DEF1           (1<<2)
#define RG_BYPASS_DHCP    (1<<3)
#define RG_BYPASS_DNS     (1<<4)
#define RG_REROUTE_GW     (1<<5)
#define RG_AUTO_LOCAL     (1<<6)
#define RG_BLOCK_LOCAL    (1<<7)

struct route_option_list {
    unsigned int flags; /* RG_x flags */
    struct route_option *routes;
    struct gc_arena *gc;
};

struct route_ipv6_option {
    struct route_ipv6_option *next;
    const char *prefix;         /* e.g. "2001:db8:1::/64" */
    const char *gateway;        /* e.g. "2001:db8:0::2" */
    const char *metric;         /* e.g. "5" */
};

struct route_ipv6_option_list {
    unsigned int flags;         /* RG_x flags, see route_option-list */
    struct route_ipv6_option *routes_ipv6;
    struct gc_arena *gc;
};

struct route_ipv4 {
#define RT_DEFINED        (1<<0)
#define RT_ADDED          (1<<1)
#define RT_METRIC_DEFINED (1<<2)
    struct route_ipv4 *next;
    unsigned int flags;
    const struct route_option *option;
    in_addr_t network;
    in_addr_t netmask;
    in_addr_t gateway;
    int metric;
};

struct route_ipv6 {
    struct route_ipv6 *next;
    unsigned int flags;                         /* RT_ flags, see route_ipv4 */
    struct in6_addr network;
    unsigned int netbits;
    struct in6_addr gateway;
    int metric;
    /* gateway interface */
#ifdef _WIN32
    DWORD adapter_index;        /* interface or ~0 if undefined */
#else
    char *iface;                /* interface name (null terminated) */
#endif
};


struct route_gateway_address {
    in_addr_t addr;
    in_addr_t netmask;
};

struct route_gateway_info {
#define RGI_ADDR_DEFINED     (1<<0)  /* set if gateway.addr defined */
#define RGI_NETMASK_DEFINED  (1<<1)  /* set if gateway.netmask defined */
#define RGI_HWADDR_DEFINED   (1<<2)  /* set if hwaddr is defined */
#define RGI_IFACE_DEFINED    (1<<3)  /* set if iface is defined */
#define RGI_OVERFLOW         (1<<4)  /* set if more interface addresses than will fit in addrs */
#define RGI_ON_LINK          (1<<5)
    unsigned int flags;

    /* gateway interface */
#ifdef _WIN32
    DWORD adapter_index; /* interface or ~0 if undefined */
#else
    char iface[16]; /* interface name (null terminated), may be empty */
#endif

    /* gateway interface hardware address */
    uint8_t hwaddr[6];

    /* gateway/router address */
    struct route_gateway_address gateway;

    /* address/netmask pairs bound to interface */
#define RGI_N_ADDRESSES 8
    int n_addrs; /* len of addrs, may be 0 */
    struct route_gateway_address addrs[RGI_N_ADDRESSES]; /* local addresses attached to iface */
};

struct route_ipv6_gateway_address {
    struct in6_addr addr_ipv6;
    int netbits_ipv6;
};

struct route_ipv6_gateway_info {
/* RGI_ flags used as in route_gateway_info */
    unsigned int flags;

    /* gateway interface */
#ifdef _WIN32
    DWORD adapter_index; /* interface or ~0 if undefined */
#else
    /* non linux platform don't have this constant defined */
#ifndef IFNAMSIZ
#define IFNAMSIZ 16
#endif
    char iface[IFNAMSIZ]; /* interface name (null terminated), may be empty */
#endif

    /* gateway interface hardware address */
    uint8_t hwaddr[6];

    /* gateway/router address */
    struct route_ipv6_gateway_address gateway;

    /* address/netmask pairs bound to interface */
#define RGI_N_ADDRESSES 8
    int n_addrs; /* len of addrs, may be 0 */
    struct route_ipv6_gateway_address addrs[RGI_N_ADDRESSES]; /* local addresses attached to iface */
};

struct route_list {
#define RL_DID_REDIRECT_DEFAULT_GATEWAY (1<<0)
#define RL_DID_LOCAL                    (1<<1)
#define RL_ROUTES_ADDED                 (1<<2)
    unsigned int iflags;

    struct route_special_addr spec;
    struct route_gateway_info rgi;
    unsigned int flags;   /* RG_x flags */
    struct route_ipv4 *routes;
    struct gc_arena gc;
};

struct route_ipv6_list {
    unsigned int iflags;                /* RL_ flags, see route_list */

    unsigned int spec_flags;            /* RTSA_ flags, route_special_addr */
    struct in6_addr remote_endpoint_ipv6; /* inside tun */
    struct in6_addr remote_host_ipv6;   /* --remote address */
    int default_metric;

    struct route_ipv6_gateway_info rgi6;
    unsigned int flags;                 /* RG_x flags, see route_option_list */
    struct route_ipv6 *routes_ipv6;
    struct gc_arena gc;
};

#if P2MP
/* internal OpenVPN route */
struct iroute {
    in_addr_t network;
    int netbits;
    struct iroute *next;
};

struct iroute_ipv6 {
    struct in6_addr network;
    unsigned int netbits;
    struct iroute_ipv6 *next;
};
#endif

struct route_option_list *new_route_option_list(struct gc_arena *a);

struct route_ipv6_option_list *new_route_ipv6_option_list(struct gc_arena *a);

struct route_option_list *clone_route_option_list(const struct route_option_list *src, struct gc_arena *a);

struct route_ipv6_option_list *clone_route_ipv6_option_list(const struct route_ipv6_option_list *src, struct gc_arena *a);

void copy_route_option_list(struct route_option_list *dest, const struct route_option_list *src, struct gc_arena *a);

void copy_route_ipv6_option_list(struct route_ipv6_option_list *dest,
                                 const struct route_ipv6_option_list *src,
                                 struct gc_arena *a);

void route_ipv6_clear_host_bits( struct route_ipv6 *r6 );

void add_route_ipv6(struct route_ipv6 *r, const struct tuntap *tt, unsigned int flags, const struct env_set *es, openvpn_net_ctx_t *ctx);

void delete_route_ipv6(const struct route_ipv6 *r, const struct tuntap *tt, unsigned int flags, const struct env_set *es, openvpn_net_ctx_t *ctx);

void add_route(struct route_ipv4 *r,
               const struct tuntap *tt,
               unsigned int flags,
               const struct route_gateway_info *rgi,
               const struct env_set *es,
               openvpn_net_ctx_t *ctx);

void add_route_to_option_list(struct route_option_list *l,
                              const char *network,
                              const char *netmask,
                              const char *gateway,
                              const char *metric);

void add_route_ipv6_to_option_list(struct route_ipv6_option_list *l,
                                   const char *prefix,
                                   const char *gateway,
                                   const char *metric);

bool init_route_list(struct route_list *rl,
                     const struct route_option_list *opt,
                     const char *remote_endpoint,
                     int default_metric,
                     in_addr_t remote_host,
                     struct env_set *es,
                     openvpn_net_ctx_t *ctx);

bool init_route_ipv6_list(struct route_ipv6_list *rl6,
                          const struct route_ipv6_option_list *opt6,
                          const char *remote_endpoint,
                          int default_metric,
                          const struct in6_addr *remote_host,
                          struct env_set *es,
                          openvpn_net_ctx_t *ctx);

void route_list_add_vpn_gateway(struct route_list *rl,
                                struct env_set *es,
                                const in_addr_t addr);

void add_routes(struct route_list *rl,
                struct route_ipv6_list *rl6,
                const struct tuntap *tt,
                unsigned int flags,
                const struct env_set *es,
                openvpn_net_ctx_t *ctx);

void delete_routes(struct route_list *rl,
                   struct route_ipv6_list *rl6,
                   const struct tuntap *tt,
                   unsigned int flags,
                   const struct env_set *es,
                   openvpn_net_ctx_t *ctx);

void setenv_routes(struct env_set *es, const struct route_list *rl);

void setenv_routes_ipv6(struct env_set *es, const struct route_ipv6_list *rl6);

bool is_special_addr(const char *addr_str);

void get_default_gateway(struct route_gateway_info *rgi,
                         openvpn_net_ctx_t *ctx);

void get_default_gateway_ipv6(struct route_ipv6_gateway_info *rgi,
                              const struct in6_addr *dest,
                              openvpn_net_ctx_t *ctx);

void print_default_gateway(const int msglevel,
                           const struct route_gateway_info *rgi,
                           const struct route_ipv6_gateway_info *rgi6);

/*
 * Test if addr is reachable via a local interface (return ILA_LOCAL),
 * or if it needs to be routed via the default gateway (return
 * ILA_NONLOCAL).  If the current platform doesn't implement this
 * function, return ILA_NOT_IMPLEMENTED.
 */
#define TLA_NOT_IMPLEMENTED 0
#define TLA_NONLOCAL        1
#define TLA_LOCAL           2
int test_local_addr(const in_addr_t addr, const struct route_gateway_info *rgi);

#ifndef ENABLE_SMALL
void print_route_options(const struct route_option_list *rol,
                         int level);

#endif

void print_routes(const struct route_list *rl, int level);

#ifdef _WIN32

void show_routes(int msglev);

bool test_routes(const struct route_list *rl, const struct tuntap *tt);

bool add_route_ipapi(const struct route_ipv4 *r, const struct tuntap *tt, DWORD adapter_index);

bool del_route_ipapi(const struct route_ipv4 *r, const struct tuntap *tt);

#else  /* ifdef _WIN32 */
static inline bool
test_routes(const struct route_list *rl, const struct tuntap *tt)
{
    return true;
}
#endif

bool netmask_to_netbits(const in_addr_t network, const in_addr_t netmask, int *netbits);

int netmask_to_netbits2(in_addr_t netmask);

static inline in_addr_t
netbits_to_netmask(const int netbits)
{
    const int addrlen = sizeof(in_addr_t) * 8;
    in_addr_t mask = 0;
    if (netbits > 0 && netbits <= addrlen)
    {
        mask = IPV4_NETMASK_HOST << (addrlen-netbits);
    }
    return mask;
}

static inline bool
route_list_vpn_gateway_needed(const struct route_list *rl)
{
    if (!rl)
    {
        return false;
    }
    else
    {
        return !(rl->spec.flags & RTSA_REMOTE_ENDPOINT);
    }
}

static inline int
route_did_redirect_default_gateway(const struct route_list *rl)
{
    return rl && BOOL_CAST(rl->iflags & RL_DID_REDIRECT_DEFAULT_GATEWAY);
}

#endif /* ifndef ROUTE_H */
