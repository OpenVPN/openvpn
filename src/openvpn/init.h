/*
 *  OpenVPN -- An application to securely tunnel IP networks
 *             over a single TCP/UDP port, with support for SSL/TLS-based
 *             session authentication and key exchange,
 *             packet encryption, packet authentication, and
 *             packet compression.
 *
 *  Copyright (C) 2002-2026 OpenVPN Inc <sales@openvpn.net>
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

#ifndef INIT_H
#define INIT_H

#include "openvpn.h"

/*
 * Baseline maximum number of events
 * to wait for.
 */
#define BASE_N_EVENTS 5

void context_clear_2(struct context *c);

void context_init_1(struct context *c);

void context_clear_all_except_first_time(struct context *c);

bool init_static(void);

void uninit_static(void);

#define IVM_LEVEL_1 (1 << 0)
#define IVM_LEVEL_2 (1 << 1)
void init_verb_mute(struct context *c, unsigned int flags);

void init_options_dev(struct options *options);

bool print_openssl_info(const struct options *options);

bool do_genkey(const struct options *options);

bool do_persist_tuntap(struct options *options, openvpn_net_ctx_t *ctx);

bool possibly_become_daemon(const struct options *options);

void pre_setup(const struct options *options);

void init_instance_handle_signals(struct context *c, const struct env_set *env,
                                  const unsigned int flags);

/**
 * Query for private key and auth-user-pass username/passwords.
 */
void init_query_passwords(const struct context *c);

bool do_route(const struct options *options, struct route_list *route_list,
              struct route_ipv6_list *route_ipv6_list, const struct tuntap *tt,
              const struct plugin_list *plugins, struct env_set *es, openvpn_net_ctx_t *ctx);

void close_instance(struct context *c);

void do_test_crypto(struct context *o);

/**
 * @brief Load the tls-auth/tls-crypt(-v2) key material into c->c1.ks.
 *
 * Reads the key from the file configured on connection entry ce (--tls-auth,
 * --tls-crypt or --tls-crypt-v2); a no-op when none of them is set. May be
 * called more than once (the key can be configured per connection block, so it
 * is reloaded for each connection).
 *
 * @param c  The context whose c1.ks key schedule is populated.
 * @param ce The connection entry whose tls-wrap key file is loaded.
 */
void do_init_tls_wrap_key(struct context *c, const struct connection_entry *ce);

/**
 * @brief Configure a control-channel wrapping context from a connection entry
 *        and previously loaded tls-wrap key material.
 *
 * Sets tls_wrap to TLS_WRAP_AUTH (--tls-auth) or TLS_WRAP_CRYPT
 * (--tls-crypt / client --tls-crypt-v2) and installs the key context, or
 * leaves it in TLS_WRAP_NONE when neither is configured. The key material must
 * already have been loaded with do_init_tls_wrap_key(). tls-crypt-v2 specifics
 * (the wrapped client key and the server key) are left to the caller.
 *
 * @param tls_wrap   The wrapping context to configure.
 * @param ce         The connection entry selecting the wrapping mode.
 * @param tls_client Whether this is a TLS client (selects tls-crypt-v2 mode).
 * @param ks         Key schedule holding the loaded tls-wrap key material.
 */
void init_tls_wrap_ctx(struct tls_wrap_ctx *tls_wrap, const struct connection_entry *ce,
                       bool tls_client, const struct key_schedule *ks);

void context_gc_free(struct context *c);

bool do_up(struct context *c, bool pulled_options, uint64_t option_types_found);

/**
 * @brief A simplified version of the do_up() function. This function is called
 *        after receiving a successful PUSH_UPDATE message. It closes and reopens
 *        the TUN device to apply the updated options.
 *
 * @param c The context structure.
 * @param option_types_found The options found in the PUSH_UPDATE message.
 * @return true on success.
 * @return false on error.
 */
bool do_update(struct context *c, uint64_t option_types_found);

uint64_t pull_permission_mask(const struct context *c);

const char *format_common_name(const struct context *c, struct gc_arena *gc);

void reset_coarse_timers(struct context *c);

/*
 * Handle non-tun-related pulled options.
 * Set `is_update` param to true to skip NCP check.
 */
bool do_deferred_options(struct context *c, const uint64_t found, const bool is_update);

void inherit_context_child(struct context *dest, const struct context *src,
                           struct link_socket *sock);

void inherit_context_top(struct context *dest, const struct context *src);

#define CC_GC_FREE          (1 << 0)
#define CC_USR1_TO_HUP      (1 << 1)
#define CC_HARD_USR1_TO_HUP (1 << 2)
#define CC_NO_CLOSE         (1 << 3)

void close_context(struct context *c, int sig, unsigned int flags);

struct context_buffers *init_context_buffers(const struct frame *frame);

void free_context_buffers(struct context_buffers *b);

#define ISC_ERRORS       (1 << 0)
#define ISC_SERVER       (1 << 1)
#define ISC_ROUTE_ERRORS (1 << 2)
void initialization_sequence_completed(struct context *c, const unsigned int flags);

#ifdef ENABLE_MANAGEMENT

void init_management(void);

bool open_management(struct context *c);

void close_management(void);

void management_show_net_callback(void *arg, const msglvl_t msglevel);

#endif

void init_management_callback_p2p(struct context *c);

void uninit_management_callback(void);

#ifdef ENABLE_PLUGIN
void init_plugins(struct context *c);

void open_plugins(struct context *c, const bool import_options, int init_point);

#endif

void tun_abort(void);

void write_pid_file(const char *filename, const char *chroot_dir);

void remove_pid_file(void);

void persist_client_stats(struct context *c);

#endif /* ifndef INIT_H */
