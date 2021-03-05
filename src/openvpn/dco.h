/*
 *  OpenVPN -- An application to securely tunnel IP networks
 *             over a single TCP/UDP port, with support for SSL/TLS-based
 *             session authentication and key exchange,
 *             packet encryption, packet authentication, and
 *             packet compression.
 *
 *  Copyright (C) 2021-2022 Arne Schwabe <arne@rfc2549.org>
 *  Copyright (C) 2021-2022 Antonio Quartulli <a@unstable.cc>
 *  Copyright (C) 2021-2022 OpenVPN Inc <sales@openvpn.net>
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
#ifndef DCO_H
#define DCO_H

#include "crypto.h"
#include "networking.h"
#include "dco_internal.h"

/* forward declarations, including multi.h leads to nasty include
 * order problems */
struct context;
struct key_state;
struct multi_context;
struct multi_instance;
struct mroute_addr;
struct tls_multi;
struct tuntap;
struct event_set;

#if defined(TARGET_LINUX)
#define DCO_DEFAULT_METRIC  200
#else
#define DCO_DEFAULT_METRIC  0
#endif

#if defined(ENABLE_DCO)

/**
 * Check whether the options struct has any option that is not supported by
 * our current dco implementation. If so it print a warning at warning level
 * for the first conflicting option found and return true.
 *
 * @param msglevel  the msg level to use to print the warnings
 * @param o         the optiions struct that hold the options
 * @return          true if a conflict was detected, false otherwise
 */
bool dco_check_option_conflict(int msglevel, const struct options *o);

/**
 * Initialize the DCO context
 *
 * @param mode      the instance operating mode (P2P or multi-peer)
 * @param dco       the context to initialize
 * @return          true on success, false otherwise
 */
bool ovpn_dco_init(int mode, dco_context_t *dco);

/**
 * Open/create a DCO interface
 *
 * @param tt        the tuntap context
 * @param ctx       the networking API context
 * @param dev       the name of the interface to create
 * @return          0 on success or a negative error code otherwise
 */
int open_tun_dco(struct tuntap *tt, openvpn_net_ctx_t *ctx, const char *dev);

/**
 * Close/destroy a DCO interface
 *
 * @param tt        the tuntap context
 * @param ctx       the networking API context
 */
void close_tun_dco(struct tuntap *tt, openvpn_net_ctx_t *ctx);

/**
 * Install a new peer in DCO - to be called by a SERVER instance
 *
 * @param m         the server context
 * @param mi        the client instance
 * @return          0 on success or a negative error code otherwise
 */
int dco_multi_add_new_peer(struct multi_context *m, struct multi_instance *mi);

/**
 * Install a new peer in DCO - to be called by a CLIENT (or P2P) instance
 *
 * @param c         the main instance context
 * @return          0 on success or a negative error code otherwise
 */
int dco_p2p_add_new_peer(struct context *c);

/**
 * Remove a peer from DCO
 *
 * @param c         the main instance context of the peer to remove
 */
void dco_remove_peer(struct context *c);

/**
 * Read data from the DCO communication channel (i.e. a control packet)
 *
 * @param dco       the DCO context
 * @return          0 on success or a negative error code otherwise
 */
int dco_do_read(dco_context_t *dco);

/**
 * Write data to the DCO communication channel (control packet expected)
 *
 * @param dco       the DCO context
 * @param peer_id   the ID of the peer to send the data to
 * @param buf       the buffer containing the data to send
 */
int dco_do_write(dco_context_t *dco, int peer_id, struct buffer *buf);

/**
 * Install an iroute in DCO, which means adding a route to the system routing
 * table. To be called by a SERVER instance only.
 *
 * @param m         the server context
 * @param mi        the client instance acting as nexthop for the route
 * @param addr      the route to add
 */
void dco_install_iroute(struct multi_context *m, struct multi_instance *mi,
                        struct mroute_addr *addr);

/**
 * Remove all routes added through the specified client
 *
 * @param m         the server context
 * @param mi        the client instance for which routes have to be removed
 */
void dco_delete_iroutes(struct multi_context *m, struct multi_instance *mi);

/**
 * Install the key material in DCO for the specified peer, at the specified slot
 *
 * @param multi     the TLS context of the current instance
 * @param ks        the state of the key being installed
 * @param key2      the container for the raw key material
 * @param key_direction the key direction to be used to extract the material
 * @param ciphername    the name of the cipher to use the key with
 * @param server    whether we are running on a server instance or not
 *
 * @return          0 on success or a negative error code otherwise
 */
int init_key_dco_bi(struct tls_multi *multi, struct key_state *ks,
                    const struct key2 *key2, int key_direction,
                    const char *ciphername, bool server);

/**
 * Possibly swaps or wipes keys from DCO
 *
 * @param dco           DCO device context
 * @param multi         TLS multi instance
 */
void dco_update_keys(dco_context_t *dco, struct tls_multi *multi);

/**
 * Check whether ovpn-dco is available on this platform (i.e. kernel support is
 * there)
 *
 * @param msglevel      level to print messages to
 * @return              true if ovpn-dco is available, false otherwise
 */
bool dco_available(int msglevel);

/**
 * Returns list of colon-separated ciphers supported by platform
 */
const char *dco_get_supported_ciphers();

/**
 * Installs a DCO in the main event loop
 */
void dco_event_set(dco_context_t *dco, struct event_set *es, void *arg);

/**
 * Modify DCO peer options. Special values are 0 (disable)
 * and -1 (do not touch).
 *
 * @param dco                DCO device context
 * @param peer_id            the ID of the peer to be modified
 * @param keepalive_interval keepalive interval in seconds
 * @param keepalive_timeout  keepalive timeout in seconds
 * @param mss                TCP MSS value
 *
 * @return                   0 on success or a negative error code otherwise
 */
int dco_set_peer(dco_context_t *dco, unsigned int peerid,
                 int keepalive_interval, int keepalive_timeout, int mss);

#else

typedef void *dco_context_t;

static inline bool
dco_check_option_conflict(int msglevel, const struct options *o)
{
    return true;
}

static inline bool
ovpn_dco_init(int mode, dco_context_t *dco)
{
    return true;
}

static inline void
dco_install_iroute(struct multi_context *m, struct multi_instance *mi,
                   struct mroute_addr *addr)
{
}

static inline void
dco_delete_iroutes(struct multi_context *m, struct multi_instance *mi)
{
}

static inline int
open_tun_dco(struct tuntap *tt, openvpn_net_ctx_t *ctx, const char* dev)
{
    return 0;
}

static inline void
close_tun_dco(struct tuntap *tt, openvpn_net_ctx_t *ctx)
{
}

static inline int
init_key_dco_bi(struct tls_multi *multi, struct key_state *ks,
                    const struct key2 *key2, int key_direction,
                    const char *ciphername, bool server)
{
    ASSERT(false);
}

static inline void
dco_update_keys(dco_context_t *dco, struct tls_multi *multi)
{
    ASSERT(false);
}

static inline bool
dco_multi_add_new_peer(struct multi_context *m, struct multi_instance *mi)
{
    return true;
}

static inline bool
dco_p2p_add_new_peer(struct context *c)
{
    return true;
}

static inline int
dco_set_peer(dco_context_t *dco, unsigned int peerid,
             int keepalive_interval, int keepalive_timeout, int mss)
{
    return 0;
}

static inline void
dco_remove_peer(struct context *c)
{
}

static inline int
dco_do_read(dco_context_t *dco)
{
    ASSERT(false);
    return 0;
}

static inline int
dco_do_write(dco_context_t *dco, int peer_id, struct buffer *buf)
{
    ASSERT(false);
    return 0;
}

static inline bool
dco_available(int msglevel)
{
    return false;
}

static inline void
dco_event_set(dco_context_t *dco, struct event_set *es, void *arg)
{
}

#endif /* defined(ENABLE_DCO) */
#endif /* ifndef DCO_H */
