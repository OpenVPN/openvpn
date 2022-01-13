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

#ifndef INIT_H
#define INIT_H

#include "openvpn.h"

/*
 * Baseline maximum number of events
 * to wait for.
 */
#define BASE_N_EVENTS 5

void context_clear(struct context *c);

void context_clear_1(struct context *c);

void context_clear_2(struct context *c);

void context_init_1(struct context *c);

void context_clear_all_except_first_time(struct context *c);

bool init_static(void);

void uninit_static(void);

#define IVM_LEVEL_1 (1<<0)
#define IVM_LEVEL_2 (1<<1)
void init_verb_mute(struct context *c, unsigned int flags);

void init_options_dev(struct options *options);

bool print_openssl_info(const struct options *options);

bool do_genkey(const struct options *options);

bool do_persist_tuntap(const struct options *options, openvpn_net_ctx_t *ctx);

bool possibly_become_daemon(const struct options *options);

void pre_setup(const struct options *options);

void init_instance_handle_signals(struct context *c, const struct env_set *env, const unsigned int flags);

void init_instance(struct context *c, const struct env_set *env, const unsigned int flags);

/**
 * Query for private key and auth-user-pass username/passwords.
 */
void init_query_passwords(const struct context *c);

void do_route(const struct options *options,
              struct route_list *route_list,
              struct route_ipv6_list *route_ipv6_list,
              const struct tuntap *tt,
              const struct plugin_list *plugins,
              struct env_set *es,
              openvpn_net_ctx_t *ctx);

void close_instance(struct context *c);

bool do_test_crypto(const struct options *o);

void context_gc_free(struct context *c);

bool do_up(struct context *c,
           bool pulled_options,
           unsigned int option_types_found);

unsigned int pull_permission_mask(const struct context *c);

const char *format_common_name(struct context *c, struct gc_arena *gc);

void reset_coarse_timers(struct context *c);

bool do_deferred_options(struct context *c, const unsigned int found);

void inherit_context_child(struct context *dest,
                           const struct context *src);

void inherit_context_top(struct context *dest,
                         const struct context *src);

#define CC_GC_FREE          (1<<0)
#define CC_USR1_TO_HUP      (1<<1)
#define CC_HARD_USR1_TO_HUP (1<<2)
#define CC_NO_CLOSE         (1<<3)

void close_context(struct context *c, int sig, unsigned int flags);

struct context_buffers *init_context_buffers(const struct frame *frame);

void free_context_buffers(struct context_buffers *b);

#define ISC_ERRORS (1<<0)
#define ISC_SERVER (1<<1)
void initialization_sequence_completed(struct context *c, const unsigned int flags);

#ifdef ENABLE_MANAGEMENT

void init_management(void);

bool open_management(struct context *c);

void close_management(void);

void management_show_net_callback(void *arg, const int msglevel);

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

#endif /* ifndef INIT_H */
