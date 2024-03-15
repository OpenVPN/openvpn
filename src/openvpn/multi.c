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

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#ifdef HAVE_SYS_INOTIFY_H
#include <sys/inotify.h>
#define INOTIFY_EVENT_BUFFER_SIZE 16384
#endif

#include "syshead.h"

#include "forward.h"
#include "multi.h"
#include "push.h"
#include "run_command.h"
#include "otime.h"
#include "gremlin.h"
#include "mstats.h"
#include "ssl_verify.h"
#include "ssl_ncp.h"
#include "vlan.h"
#include <inttypes.h>

#include "memdbg.h"


#include "crypto_backend.h"
#include "ssl_util.h"
#include "dco.h"
#include "reflect_filter.h"

/*#define MULTI_DEBUG_EVENT_LOOP*/

#ifdef MULTI_DEBUG_EVENT_LOOP
static const char *
id(struct multi_instance *mi)
{
    if (mi)
    {
        return tls_common_name(mi->context.c2.tls_multi, false);
    }
    else
    {
        return "NULL";
    }
}
#endif

#ifdef ENABLE_MANAGEMENT
static void
set_cc_config(struct multi_instance *mi, struct buffer_list *cc_config)
{
    buffer_list_free(mi->cc_config);
    mi->cc_config = cc_config;
}
#endif

static inline void
update_mstat_n_clients(const int n_clients)
{
#ifdef ENABLE_MEMSTATS
    if (mmap_stats)
    {
        mmap_stats->n_clients = n_clients;
    }
#endif
}

static bool
learn_address_script(const struct multi_context *m,
                     const struct multi_instance *mi,
                     const char *op,
                     const struct mroute_addr *addr)
{
    struct gc_arena gc = gc_new();
    struct env_set *es;
    bool ret = true;
    struct plugin_list *plugins;

    /* get environmental variable source */
    if (mi && mi->context.c2.es)
    {
        es = mi->context.c2.es;
    }
    else
    {
        es = env_set_create(&gc);
    }

    /* get plugin source */
    if (mi)
    {
        plugins = mi->context.plugins;
    }
    else
    {
        plugins = m->top.plugins;
    }

    if (plugin_defined(plugins, OPENVPN_PLUGIN_LEARN_ADDRESS))
    {
        struct argv argv = argv_new();
        argv_printf(&argv, "%s %s",
                    op,
                    mroute_addr_print(addr, &gc));
        if (mi)
        {
            argv_printf_cat(&argv, "%s", tls_common_name(mi->context.c2.tls_multi, false));
        }
        if (plugin_call(plugins, OPENVPN_PLUGIN_LEARN_ADDRESS, &argv, NULL, es) != OPENVPN_PLUGIN_FUNC_SUCCESS)
        {
            msg(M_WARN, "WARNING: learn-address plugin call failed");
            ret = false;
        }
        argv_free(&argv);
    }

    if (m->top.options.learn_address_script)
    {
        struct argv argv = argv_new();
        setenv_str(es, "script_type", "learn-address");
        argv_parse_cmd(&argv, m->top.options.learn_address_script);
        argv_printf_cat(&argv, "%s %s", op, mroute_addr_print(addr, &gc));
        if (mi)
        {
            argv_printf_cat(&argv, "%s", tls_common_name(mi->context.c2.tls_multi, false));
        }
        if (!openvpn_run_script(&argv, es, 0, "--learn-address"))
        {
            ret = false;
        }
        argv_free(&argv);
    }

    gc_free(&gc);
    return ret;
}

void
multi_ifconfig_pool_persist(struct multi_context *m, bool force)
{
    /* write pool data to file */
    if (m->ifconfig_pool
        && m->top.c1.ifconfig_pool_persist
        && (force || ifconfig_pool_write_trigger(m->top.c1.ifconfig_pool_persist)))
    {
        ifconfig_pool_write(m->top.c1.ifconfig_pool_persist, m->ifconfig_pool);
    }
}

static void
multi_reap_range(const struct multi_context *m,
                 int start_bucket,
                 int end_bucket)
{
    struct gc_arena gc = gc_new();
    struct hash_iterator hi;
    struct hash_element *he;

    if (start_bucket < 0)
    {
        start_bucket = 0;
        end_bucket = hash_n_buckets(m->vhash);
    }

    dmsg(D_MULTI_DEBUG, "MULTI: REAP range %d -> %d", start_bucket, end_bucket);
    hash_iterator_init_range(m->vhash, &hi, start_bucket, end_bucket);
    while ((he = hash_iterator_next(&hi)) != NULL)
    {
        struct multi_route *r = (struct multi_route *) he->value;
        if (!multi_route_defined(m, r))
        {
            dmsg(D_MULTI_DEBUG, "MULTI: REAP DEL %s",
                 mroute_addr_print(&r->addr, &gc));
            learn_address_script(m, NULL, "delete", &r->addr);
            multi_route_del(r);
            hash_iterator_delete_element(&hi);
        }
    }
    hash_iterator_free(&hi);
    gc_free(&gc);
}

static void
multi_reap_all(const struct multi_context *m)
{
    multi_reap_range(m, -1, 0);
}

static struct multi_reap *
multi_reap_new(int buckets_per_pass)
{
    struct multi_reap *mr;
    ALLOC_OBJ(mr, struct multi_reap);
    mr->bucket_base = 0;
    mr->buckets_per_pass = buckets_per_pass;
    mr->last_call = now;
    return mr;
}

void
multi_reap_process_dowork(const struct multi_context *m)
{
    struct multi_reap *mr = m->reaper;
    if (mr->bucket_base >= hash_n_buckets(m->vhash))
    {
        mr->bucket_base = 0;
    }
    multi_reap_range(m, mr->bucket_base, mr->bucket_base + mr->buckets_per_pass);
    mr->bucket_base += mr->buckets_per_pass;
    mr->last_call = now;
}

static void
multi_reap_free(struct multi_reap *mr)
{
    free(mr);
}

/*
 * How many buckets in vhash to reap per pass.
 */
static int
reap_buckets_per_pass(int n_buckets)
{
    return constrain_int(n_buckets / REAP_DIVISOR, REAP_MIN, REAP_MAX);
}

#ifdef ENABLE_MANAGEMENT

static uint32_t
cid_hash_function(const void *key, uint32_t iv)
{
    const unsigned long *k = (const unsigned long *)key;
    return (uint32_t) *k;
}

static bool
cid_compare_function(const void *key1, const void *key2)
{
    const unsigned long *k1 = (const unsigned long *)key1;
    const unsigned long *k2 = (const unsigned long *)key2;
    return *k1 == *k2;
}

#endif

#ifdef ENABLE_ASYNC_PUSH
static uint32_t
/*
 * inotify watcher descriptors are used as hash value
 */
int_hash_function(const void *key, uint32_t iv)
{
    return (unsigned long)key;
}

static bool
int_compare_function(const void *key1, const void *key2)
{
    return (unsigned long)key1 == (unsigned long)key2;
}
#endif

/*
 * Main initialization function, init multi_context object.
 */
void
multi_init(struct multi_context *m, struct context *t, bool tcp_mode)
{
    int dev = DEV_TYPE_UNDEF;

    msg(D_MULTI_LOW, "MULTI: multi_init called, r=%d v=%d",
        t->options.real_hash_size,
        t->options.virtual_hash_size);

    /*
     * Get tun/tap/null device type
     */
    dev = dev_type_enum(t->options.dev, t->options.dev_type);

    /*
     * Init our multi_context object.
     */
    CLEAR(*m);

    /*
     * Real address hash table (source port number is
     * considered to be part of the address).  Used
     * to determine which client sent an incoming packet
     * which is seen on the TCP/UDP socket.
     */
    m->hash = hash_init(t->options.real_hash_size,
                        get_random(),
                        mroute_addr_hash_function,
                        mroute_addr_compare_function);

    /*
     * Virtual address hash table.  Used to determine
     * which client to route a packet to.
     */
    m->vhash = hash_init(t->options.virtual_hash_size,
                         get_random(),
                         mroute_addr_hash_function,
                         mroute_addr_compare_function);

    /*
     * This hash table is a clone of m->hash but with a
     * bucket size of one so that it can be used
     * for fast iteration through the list.
     */
    m->iter = hash_init(1,
                        get_random(),
                        mroute_addr_hash_function,
                        mroute_addr_compare_function);

#ifdef ENABLE_MANAGEMENT
    m->cid_hash = hash_init(t->options.real_hash_size,
                            0,
                            cid_hash_function,
                            cid_compare_function);
#endif

#ifdef ENABLE_ASYNC_PUSH
    /*
     * Mapping between inotify watch descriptors and
     * multi_instances.
     */
    m->inotify_watchers = hash_init(t->options.real_hash_size,
                                    get_random(),
                                    int_hash_function,
                                    int_compare_function);
#endif

    /*
     * This is our scheduler, for time-based wakeup
     * events.
     */
    m->schedule = schedule_init();

    /*
     * Limit frequency of incoming connections to control
     * DoS.
     */
    m->new_connection_limiter = frequency_limit_init(t->options.cf_max,
                                                     t->options.cf_per);
    m->initial_rate_limiter = initial_rate_limit_init(t->options.cf_initial_max,
                                                      t->options.cf_initial_per);

    /*
     * Allocate broadcast/multicast buffer list
     */
    m->mbuf = mbuf_init(t->options.n_bcast_buf);

    /*
     * Different status file format options are available
     */
    m->status_file_version = t->options.status_file_version;

    /*
     * Possibly allocate an ifconfig pool, do it
     * differently based on whether a tun or tap style
     * tunnel.
     */
    if (t->options.ifconfig_pool_defined
        || t->options.ifconfig_ipv6_pool_defined)
    {
        int pool_type = IFCONFIG_POOL_INDIV;

        if (dev == DEV_TYPE_TUN && t->options.topology == TOP_NET30)
        {
            pool_type = IFCONFIG_POOL_30NET;
        }

        m->ifconfig_pool = ifconfig_pool_init(t->options.ifconfig_pool_defined,
                                              pool_type,
                                              t->options.ifconfig_pool_start,
                                              t->options.ifconfig_pool_end,
                                              t->options.duplicate_cn,
                                              t->options.ifconfig_ipv6_pool_defined,
                                              t->options.ifconfig_ipv6_pool_base,
                                              t->options.ifconfig_ipv6_pool_netbits );

        /* reload pool data from file */
        if (t->c1.ifconfig_pool_persist)
        {
            ifconfig_pool_read(t->c1.ifconfig_pool_persist, m->ifconfig_pool);
        }
    }

    /*
     * Help us keep track of routing table.
     */
    m->route_helper = mroute_helper_init(MULTI_CACHE_ROUTE_TTL);

    /*
     * Initialize route and instance reaper.
     */
    m->reaper = multi_reap_new(reap_buckets_per_pass(t->options.virtual_hash_size));

    /*
     * Get local ifconfig address
     */
    CLEAR(m->local);
    ASSERT(t->c1.tuntap);
    mroute_extract_in_addr_t(&m->local, t->c1.tuntap->local);

    /*
     * Per-client limits
     */
    m->max_clients = t->options.max_clients;

    m->instances = calloc(m->max_clients, sizeof(struct multi_instance *));

    /*
     * Initialize multi-socket TCP I/O wait object
     */
    if (tcp_mode)
    {
        m->mtcp = multi_tcp_init(t->options.max_clients, &m->max_clients);
    }
    m->tcp_queue_limit = t->options.tcp_queue_limit;

    /*
     * Allow client <-> client communication, without going through
     * tun/tap interface and network stack?
     */
    m->enable_c2c = t->options.enable_c2c;

    /* initialize stale routes check timer */
    if (t->options.stale_routes_check_interval > 0)
    {
        msg(M_INFO, "Initializing stale route check timer to run every %i seconds and to removing routes with activity timeout older than %i seconds",
            t->options.stale_routes_check_interval, t->options.stale_routes_ageing_time);
        event_timeout_init(&m->stale_routes_check_et, t->options.stale_routes_check_interval, 0);
    }

    m->deferred_shutdown_signal.signal_received = 0;
}

const char *
multi_instance_string(const struct multi_instance *mi, bool null, struct gc_arena *gc)
{
    if (mi)
    {
        struct buffer out = alloc_buf_gc(MULTI_PREFIX_MAX_LENGTH, gc);
        const char *cn = tls_common_name(mi->context.c2.tls_multi, true);

        if (cn)
        {
            buf_printf(&out, "%s/", cn);
        }
        buf_printf(&out, "%s", mroute_addr_print(&mi->real, gc));
        if (mi->context.c2.tls_multi
            && check_debug_level(D_DCO_DEBUG)
            && dco_enabled(&mi->context.options))
        {
            buf_printf(&out, " peer-id=%d", mi->context.c2.tls_multi->peer_id);
        }
        return BSTR(&out);
    }
    else if (null)
    {
        return NULL;
    }
    else
    {
        return "UNDEF";
    }
}

static void
generate_prefix(struct multi_instance *mi)
{
    struct gc_arena gc = gc_new();
    const char *prefix = multi_instance_string(mi, true, &gc);
    if (prefix)
    {
        strncpynt(mi->msg_prefix, prefix, sizeof(mi->msg_prefix));
    }
    else
    {
        mi->msg_prefix[0] = '\0';
    }
    set_prefix(mi);
    gc_free(&gc);
}

void
ungenerate_prefix(struct multi_instance *mi)
{
    mi->msg_prefix[0] = '\0';
    set_prefix(mi);
}

/*
 * Tell the route helper about deleted iroutes so
 * that it can update its mask of currently used
 * CIDR netlengths.
 */
static void
multi_del_iroutes(struct multi_context *m,
                  struct multi_instance *mi)
{
    const struct iroute *ir;
    const struct iroute_ipv6 *ir6;

    dco_delete_iroutes(m, mi);

    if (TUNNEL_TYPE(mi->context.c1.tuntap) == DEV_TYPE_TUN)
    {
        for (ir = mi->context.options.iroutes; ir != NULL; ir = ir->next)
        {
            mroute_helper_del_iroute46(m->route_helper, ir->netbits);
        }

        for (ir6 = mi->context.options.iroutes_ipv6; ir6 != NULL; ir6 = ir6->next)
        {
            mroute_helper_del_iroute46(m->route_helper, ir6->netbits);
        }
    }
}

static void
setenv_stats(struct multi_context *m, struct context *c)
{
    if (dco_enabled(&m->top.options))
    {
        dco_get_peer_stats_multi(&m->top.c1.tuntap->dco, m);
    }

    setenv_counter(c->c2.es, "bytes_received", c->c2.link_read_bytes + c->c2.dco_read_bytes);
    setenv_counter(c->c2.es, "bytes_sent", c->c2.link_write_bytes + c->c2.dco_write_bytes);
}

static void
multi_client_disconnect_setenv(struct multi_context *m, struct multi_instance *mi)
{
    /* setenv client real IP address */
    setenv_trusted(mi->context.c2.es, get_link_socket_info(&mi->context));

    /* setenv stats */
    setenv_stats(m, &mi->context);

    /* setenv connection duration */
    setenv_long_long(mi->context.c2.es, "time_duration", now - mi->created);
}

static void
multi_client_disconnect_script(struct multi_context *m, struct multi_instance *mi)
{
    multi_client_disconnect_setenv(m, mi);

    if (plugin_defined(mi->context.plugins, OPENVPN_PLUGIN_CLIENT_DISCONNECT))
    {
        if (plugin_call(mi->context.plugins, OPENVPN_PLUGIN_CLIENT_DISCONNECT, NULL, NULL, mi->context.c2.es) != OPENVPN_PLUGIN_FUNC_SUCCESS)
        {
            msg(M_WARN, "WARNING: client-disconnect plugin call failed");
        }
    }

    if (mi->context.options.client_disconnect_script)
    {
        struct argv argv = argv_new();
        setenv_str(mi->context.c2.es, "script_type", "client-disconnect");
        argv_parse_cmd(&argv, mi->context.options.client_disconnect_script);
        openvpn_run_script(&argv, mi->context.c2.es, 0, "--client-disconnect");
        argv_free(&argv);
    }
#ifdef ENABLE_MANAGEMENT
    if (management)
    {
        management_notify_client_close(management, &mi->context.c2.mda_context, mi->context.c2.es);
    }
#endif
}

void
multi_close_instance(struct multi_context *m,
                     struct multi_instance *mi,
                     bool shutdown)
{
    perf_push(PERF_MULTI_CLOSE_INSTANCE);

    ASSERT(!mi->halt);
    mi->halt = true;

    dmsg(D_MULTI_DEBUG, "MULTI: multi_close_instance called");

    /* adjust current client connection count */
    m->n_clients += mi->n_clients_delta;
    update_mstat_n_clients(m->n_clients);
    mi->n_clients_delta = 0;

    /* prevent dangling pointers */
    if (m->pending == mi)
    {
        multi_set_pending(m, NULL);
    }
    if (m->earliest_wakeup == mi)
    {
        m->earliest_wakeup = NULL;
    }

    if (!shutdown)
    {
        if (mi->did_real_hash)
        {
            ASSERT(hash_remove(m->hash, &mi->real));
        }
        if (mi->did_iter)
        {
            ASSERT(hash_remove(m->iter, &mi->real));
        }
#ifdef ENABLE_MANAGEMENT
        if (mi->did_cid_hash)
        {
            ASSERT(hash_remove(m->cid_hash, &mi->context.c2.mda_context.cid));
        }
#endif

#ifdef ENABLE_ASYNC_PUSH
        if (mi->inotify_watch != -1)
        {
            hash_remove(m->inotify_watchers, (void *) (unsigned long)mi->inotify_watch);
            mi->inotify_watch = -1;
        }
#endif

        if (mi->context.c2.tls_multi->peer_id != MAX_PEER_ID)
        {
            m->instances[mi->context.c2.tls_multi->peer_id] = NULL;
        }

        schedule_remove_entry(m->schedule, (struct schedule_entry *) mi);

        ifconfig_pool_release(m->ifconfig_pool, mi->vaddr_handle, false);

        if (mi->did_iroutes)
        {
            multi_del_iroutes(m, mi);
            mi->did_iroutes = false;
        }

        if (m->mtcp)
        {
            multi_tcp_dereference_instance(m->mtcp, mi);
        }

        mbuf_dereference_instance(m->mbuf, mi);
    }

#ifdef ENABLE_MANAGEMENT
    set_cc_config(mi, NULL);
#endif

    if (mi->context.c2.tls_multi->multi_state >= CAS_CONNECT_DONE)
    {
        multi_client_disconnect_script(m, mi);
    }

    close_context(&mi->context, SIGTERM, CC_GC_FREE);

    multi_tcp_instance_specific_free(mi);

    ungenerate_prefix(mi);

    /*
     * Don't actually delete the instance memory allocation yet,
     * because virtual routes may still point to it.  Let the
     * vhash reaper deal with it.
     */
    multi_instance_dec_refcount(mi);

    perf_pop();
}

/*
 * Called on shutdown or restart.
 */
void
multi_uninit(struct multi_context *m)
{
    if (m->hash)
    {
        struct hash_iterator hi;
        struct hash_element *he;

        hash_iterator_init(m->iter, &hi);
        while ((he = hash_iterator_next(&hi)))
        {
            struct multi_instance *mi = (struct multi_instance *) he->value;
            mi->did_iter = false;
            multi_close_instance(m, mi, true);
        }
        hash_iterator_free(&hi);

        multi_reap_all(m);

        hash_free(m->hash);
        hash_free(m->vhash);
        hash_free(m->iter);
#ifdef ENABLE_MANAGEMENT
        hash_free(m->cid_hash);
#endif
        m->hash = NULL;

        free(m->instances);

#ifdef ENABLE_ASYNC_PUSH
        hash_free(m->inotify_watchers);
        m->inotify_watchers = NULL;
#endif

        schedule_free(m->schedule);
        mbuf_free(m->mbuf);
        ifconfig_pool_free(m->ifconfig_pool);
        frequency_limit_free(m->new_connection_limiter);
        initial_rate_limit_free(m->initial_rate_limiter);
        multi_reap_free(m->reaper);
        mroute_helper_free(m->route_helper);
        multi_tcp_free(m->mtcp);
    }
}

/*
 * Create a client instance object for a newly connected client.
 */
struct multi_instance *
multi_create_instance(struct multi_context *m, const struct mroute_addr *real)
{
    struct gc_arena gc = gc_new();
    struct multi_instance *mi;

    perf_push(PERF_MULTI_CREATE_INSTANCE);

    msg(D_MULTI_MEDIUM, "MULTI: multi_create_instance called");

    ALLOC_OBJ_CLEAR(mi, struct multi_instance);

    mi->gc = gc_new();
    multi_instance_inc_refcount(mi);
    mi->vaddr_handle = -1;
    mi->created = now;
    mroute_addr_init(&mi->real);

    if (real)
    {
        mi->real = *real;
        generate_prefix(mi);
    }

    inherit_context_child(&mi->context, &m->top);
    if (IS_SIG(&mi->context))
    {
        goto err;
    }

    mi->context.c2.tls_multi->multi_state = CAS_NOT_CONNECTED;

    if (hash_n_elements(m->hash) >= m->max_clients)
    {
        msg(D_MULTI_ERRORS, "MULTI: new incoming connection would exceed maximum number of clients (%d)", m->max_clients);
        goto err;
    }

    if (!real) /* TCP mode? */
    {
        if (!multi_tcp_instance_specific_init(m, mi))
        {
            goto err;
        }
        generate_prefix(mi);
    }

    if (!hash_add(m->iter, &mi->real, mi, false))
    {
        msg(D_MULTI_LOW, "MULTI: unable to add real address [%s] to iterator hash table",
            mroute_addr_print(&mi->real, &gc));
        goto err;
    }
    mi->did_iter = true;

#ifdef ENABLE_MANAGEMENT
    do
    {
        mi->context.c2.mda_context.cid = m->cid_counter++;
    } while (!hash_add(m->cid_hash, &mi->context.c2.mda_context.cid, mi, false));
    mi->did_cid_hash = true;
#endif

    mi->context.c2.push_request_received = false;
#ifdef ENABLE_ASYNC_PUSH
    mi->inotify_watch = -1;
#endif

    if (!multi_process_post(m, mi, MPP_PRE_SELECT))
    {
        msg(D_MULTI_ERRORS, "MULTI: signal occurred during client instance initialization");
        goto err;
    }

    perf_pop();
    gc_free(&gc);
    return mi;

err:
    multi_close_instance(m, mi, false);
    perf_pop();
    gc_free(&gc);
    return NULL;
}

/*
 * Dump tables -- triggered by SIGUSR2.
 * If status file is defined, write to file.
 * If status file is NULL, write to syslog.
 */
void
multi_print_status(struct multi_context *m, struct status_output *so, const int version)
{
    if (m->hash)
    {
        struct gc_arena gc_top = gc_new();
        struct hash_iterator hi;
        const struct hash_element *he;

        status_reset(so);

        if (dco_enabled(&m->top.options))
        {
            dco_get_peer_stats_multi(&m->top.c1.tuntap->dco, m);
        }

        if (version == 1)
        {
            /*
             * Status file version 1
             */
            status_printf(so, "OpenVPN CLIENT LIST");
            status_printf(so, "Updated,%s", time_string(0, 0, false, &gc_top));
            status_printf(so, "Common Name,Real Address,Bytes Received,Bytes Sent,Connected Since");
            hash_iterator_init(m->hash, &hi);
            while ((he = hash_iterator_next(&hi)))
            {
                struct gc_arena gc = gc_new();
                const struct multi_instance *mi = (struct multi_instance *) he->value;

                if (!mi->halt)
                {
                    status_printf(so, "%s,%s," counter_format "," counter_format ",%s",
                                  tls_common_name(mi->context.c2.tls_multi, false),
                                  mroute_addr_print(&mi->real, &gc),
                                  mi->context.c2.link_read_bytes + mi->context.c2.dco_read_bytes,
                                  mi->context.c2.link_write_bytes + mi->context.c2.dco_write_bytes,
                                  time_string(mi->created, 0, false, &gc));
                }
                gc_free(&gc);
            }
            hash_iterator_free(&hi);

            status_printf(so, "ROUTING TABLE");
            status_printf(so, "Virtual Address,Common Name,Real Address,Last Ref");
            hash_iterator_init(m->vhash, &hi);
            while ((he = hash_iterator_next(&hi)))
            {
                struct gc_arena gc = gc_new();
                const struct multi_route *route = (struct multi_route *) he->value;

                if (multi_route_defined(m, route))
                {
                    const struct multi_instance *mi = route->instance;
                    const struct mroute_addr *ma = &route->addr;
                    char flags[2] = {0, 0};

                    if (route->flags & MULTI_ROUTE_CACHE)
                    {
                        flags[0] = 'C';
                    }
                    status_printf(so, "%s%s,%s,%s,%s",
                                  mroute_addr_print(ma, &gc),
                                  flags,
                                  tls_common_name(mi->context.c2.tls_multi, false),
                                  mroute_addr_print(&mi->real, &gc),
                                  time_string(route->last_reference, 0, false, &gc));
                }
                gc_free(&gc);
            }
            hash_iterator_free(&hi);

            status_printf(so, "GLOBAL STATS");
            if (m->mbuf)
            {
                status_printf(so, "Max bcast/mcast queue length,%d",
                              mbuf_maximum_queued(m->mbuf));
            }

            status_printf(so, "END");
        }
        else if (version == 2 || version == 3)
        {
            const char sep = (version == 3) ? '\t' : ',';

            /*
             * Status file version 2 and 3
             */
            status_printf(so, "TITLE%c%s", sep, title_string);
            status_printf(so, "TIME%c%s%c%u", sep, time_string(now, 0, false, &gc_top), sep, (unsigned int)now);
            status_printf(so, "HEADER%cCLIENT_LIST%cCommon Name%cReal Address%cVirtual Address%cVirtual IPv6 Address%cBytes Received%cBytes Sent%cConnected Since%cConnected Since (time_t)%cUsername%cClient ID%cPeer ID%cData Channel Cipher",
                          sep, sep, sep, sep, sep, sep, sep, sep, sep, sep, sep, sep, sep);
            hash_iterator_init(m->hash, &hi);
            while ((he = hash_iterator_next(&hi)))
            {
                struct gc_arena gc = gc_new();
                const struct multi_instance *mi = (struct multi_instance *) he->value;

                if (!mi->halt)
                {
                    status_printf(so, "CLIENT_LIST%c%s%c%s%c%s%c%s%c" counter_format "%c" counter_format "%c%s%c%u%c%s%c"
#ifdef ENABLE_MANAGEMENT
                                  "%lu"
#else
                                  ""
#endif
                                  "%c%" PRIu32 "%c%s",
                                  sep, tls_common_name(mi->context.c2.tls_multi, false),
                                  sep, mroute_addr_print(&mi->real, &gc),
                                  sep, print_in_addr_t(mi->reporting_addr, IA_EMPTY_IF_UNDEF, &gc),
                                  sep, print_in6_addr(mi->reporting_addr_ipv6, IA_EMPTY_IF_UNDEF, &gc),
                                  sep, mi->context.c2.link_read_bytes + mi->context.c2.dco_read_bytes,
                                  sep, mi->context.c2.link_write_bytes + mi->context.c2.dco_write_bytes,
                                  sep, time_string(mi->created, 0, false, &gc),
                                  sep, (unsigned int)mi->created,
                                  sep, tls_username(mi->context.c2.tls_multi, false),
#ifdef ENABLE_MANAGEMENT
                                  sep, mi->context.c2.mda_context.cid,
#else
                                  sep,
#endif
                                  sep, mi->context.c2.tls_multi ? mi->context.c2.tls_multi->peer_id : UINT32_MAX,
                                  sep, translate_cipher_name_to_openvpn(mi->context.options.ciphername));
                }
                gc_free(&gc);
            }
            hash_iterator_free(&hi);

            status_printf(so, "HEADER%cROUTING_TABLE%cVirtual Address%cCommon Name%cReal Address%cLast Ref%cLast Ref (time_t)",
                          sep, sep, sep, sep, sep, sep);
            hash_iterator_init(m->vhash, &hi);
            while ((he = hash_iterator_next(&hi)))
            {
                struct gc_arena gc = gc_new();
                const struct multi_route *route = (struct multi_route *) he->value;

                if (multi_route_defined(m, route))
                {
                    const struct multi_instance *mi = route->instance;
                    const struct mroute_addr *ma = &route->addr;
                    char flags[2] = {0, 0};

                    if (route->flags & MULTI_ROUTE_CACHE)
                    {
                        flags[0] = 'C';
                    }
                    status_printf(so, "ROUTING_TABLE%c%s%s%c%s%c%s%c%s%c%u",
                                  sep, mroute_addr_print(ma, &gc), flags,
                                  sep, tls_common_name(mi->context.c2.tls_multi, false),
                                  sep, mroute_addr_print(&mi->real, &gc),
                                  sep, time_string(route->last_reference, 0, false, &gc),
                                  sep, (unsigned int)route->last_reference);
                }
                gc_free(&gc);
            }
            hash_iterator_free(&hi);

            if (m->mbuf)
            {
                status_printf(so, "GLOBAL_STATS%cMax bcast/mcast queue length%c%d",
                              sep, sep, mbuf_maximum_queued(m->mbuf));
            }

            status_printf(so, "GLOBAL_STATS%cdco_enabled%c%d", sep, sep, dco_enabled(&m->top.options));
            status_printf(so, "END");
        }
        else
        {
            status_printf(so, "ERROR: bad status format version number");
        }

#ifdef PACKET_TRUNCATION_CHECK
        {
            status_printf(so, "HEADER,ERRORS,Common Name,TUN Read Trunc,TUN Write Trunc,Pre-encrypt Trunc,Post-decrypt Trunc");
            hash_iterator_init(m->hash, &hi);
            while ((he = hash_iterator_next(&hi)))
            {
                struct gc_arena gc = gc_new();
                const struct multi_instance *mi = (struct multi_instance *) he->value;

                if (!mi->halt)
                {
                    status_printf(so, "ERRORS,%s," counter_format "," counter_format "," counter_format "," counter_format,
                                  tls_common_name(mi->context.c2.tls_multi, false),
                                  m->top.c2.n_trunc_tun_read,
                                  mi->context.c2.n_trunc_tun_write,
                                  mi->context.c2.n_trunc_pre_encrypt,
                                  mi->context.c2.n_trunc_post_decrypt);
                }
                gc_free(&gc);
            }
            hash_iterator_free(&hi);
        }
#endif /* ifdef PACKET_TRUNCATION_CHECK */

        status_flush(so);
        gc_free(&gc_top);
    }

#ifdef ENABLE_ASYNC_PUSH
    if (m->inotify_watchers)
    {
        msg(D_MULTI_DEBUG, "inotify watchers count: %d\n", hash_n_elements(m->inotify_watchers));
    }
#endif
}

/*
 * Learn a virtual address or route.
 * The learn will fail if the learn address
 * script/plugin fails.  In this case the
 * return value may be != mi.
 * Return the instance which owns this route,
 * or NULL if none.
 */
static struct multi_instance *
multi_learn_addr(struct multi_context *m,
                 struct multi_instance *mi,
                 const struct mroute_addr *addr,
                 const unsigned int flags)
{
    struct hash_element *he;
    const uint32_t hv = hash_value(m->vhash, addr);
    struct hash_bucket *bucket = hash_bucket(m->vhash, hv);
    struct multi_route *oldroute = NULL;
    struct multi_instance *owner = NULL;
    struct gc_arena gc = gc_new();

    /* if route currently exists, get the instance which owns it */
    he = hash_lookup_fast(m->vhash, bucket, addr, hv);
    if (he)
    {
        oldroute = (struct multi_route *) he->value;
    }
    if (oldroute && multi_route_defined(m, oldroute))
    {
        owner = oldroute->instance;
    }

    /* do we need to add address to hash table? */
    if ((!owner || owner != mi) && mroute_learnable_address(addr, &gc)
        && !mroute_addr_equal(addr, &m->local))
    {
        struct multi_route *newroute;
        bool learn_succeeded = false;

        ALLOC_OBJ(newroute, struct multi_route);
        newroute->addr = *addr;
        newroute->instance = mi;
        newroute->flags = flags;
        newroute->last_reference = now;
        newroute->cache_generation = 0;

        /* The cache is invalidated when cache_generation is incremented */
        if (flags & MULTI_ROUTE_CACHE)
        {
            newroute->cache_generation = m->route_helper->cache_generation;
        }

        if (oldroute) /* route already exists? */
        {
            if (route_quota_test(mi) && learn_address_script(m, mi, "update", &newroute->addr))
            {
                learn_succeeded = true;
                owner = mi;
                multi_instance_inc_refcount(mi);
                route_quota_inc(mi);

                /* delete old route */
                multi_route_del(oldroute);

                /* modify hash table entry, replacing old route */
                he->key = &newroute->addr;
                he->value = newroute;
            }
        }
        else
        {
            if (route_quota_test(mi) && learn_address_script(m, mi, "add", &newroute->addr))
            {
                learn_succeeded = true;
                owner = mi;
                multi_instance_inc_refcount(mi);
                route_quota_inc(mi);

                /* add new route */
                hash_add_fast(m->vhash, bucket, &newroute->addr, hv, newroute);
            }
        }

        msg(D_MULTI_LOW, "MULTI: Learn%s: %s -> %s",
            learn_succeeded ? "" : " FAILED",
            mroute_addr_print(&newroute->addr, &gc),
            multi_instance_string(mi, false, &gc));

        if (!learn_succeeded)
        {
            free(newroute);
        }
    }
    gc_free(&gc);

    return owner;
}

/*
 * Get client instance based on virtual address.
 */
static struct multi_instance *
multi_get_instance_by_virtual_addr(struct multi_context *m,
                                   const struct mroute_addr *addr,
                                   bool cidr_routing)
{
    struct multi_route *route;
    struct multi_instance *ret = NULL;

    /* check for local address */
    if (mroute_addr_equal(addr, &m->local))
    {
        return NULL;
    }

    route = (struct multi_route *) hash_lookup(m->vhash, addr);

    /* does host route (possible cached) exist? */
    if (route && multi_route_defined(m, route))
    {
        struct multi_instance *mi = route->instance;
        route->last_reference = now;
        ret = mi;
    }
    else if (cidr_routing) /* do we need to regenerate a host route cache entry? */
    {
        struct mroute_helper *rh = m->route_helper;
        struct mroute_addr tryaddr;
        int i;

        /* cycle through each CIDR length */
        for (i = 0; i < rh->n_net_len; ++i)
        {
            tryaddr = *addr;
            tryaddr.type |= MR_WITH_NETBITS;
            tryaddr.netbits = rh->net_len[i];
            mroute_addr_mask_host_bits(&tryaddr);

            /* look up a possible route with netbits netmask */
            route = (struct multi_route *) hash_lookup(m->vhash, &tryaddr);

            if (route && multi_route_defined(m, route))
            {
                /* found an applicable route, cache host route */
                struct multi_instance *mi = route->instance;
                multi_learn_addr(m, mi, addr, MULTI_ROUTE_CACHE|MULTI_ROUTE_AGEABLE);
                ret = mi;
                break;
            }
        }
    }

#ifdef ENABLE_DEBUG
    if (check_debug_level(D_MULTI_DEBUG))
    {
        struct gc_arena gc = gc_new();
        const char *addr_text = mroute_addr_print(addr, &gc);
        if (ret)
        {
            dmsg(D_MULTI_DEBUG, "GET INST BY VIRT: %s -> %s via %s",
                 addr_text,
                 multi_instance_string(ret, false, &gc),
                 mroute_addr_print(&route->addr, &gc));
        }
        else
        {
            dmsg(D_MULTI_DEBUG, "GET INST BY VIRT: %s [failed]",
                 addr_text);
        }
        gc_free(&gc);
    }
#endif

    ASSERT(!(ret && ret->halt));
    return ret;
}

/*
 * Helper function to multi_learn_addr().
 */
static struct multi_instance *
multi_learn_in_addr_t(struct multi_context *m,
                      struct multi_instance *mi,
                      in_addr_t a,
                      int netbits,  /* -1 if host route, otherwise # of network bits in address */
                      bool primary)
{
    struct openvpn_sockaddr remote_si;
    struct mroute_addr addr;

    CLEAR(remote_si);
    remote_si.addr.in4.sin_family = AF_INET;
    remote_si.addr.in4.sin_addr.s_addr = htonl(a);
    ASSERT(mroute_extract_openvpn_sockaddr(&addr, &remote_si, false));

    if (netbits >= 0)
    {
        addr.type |= MR_WITH_NETBITS;
        addr.netbits = (uint8_t) netbits;
    }

    struct multi_instance *owner = multi_learn_addr(m, mi, &addr, 0);
#ifdef ENABLE_MANAGEMENT
    if (management && owner)
    {
        management_learn_addr(management, &mi->context.c2.mda_context, &addr, primary);
    }
#endif
    if (!primary)
    {
        /* "primary" is the VPN ifconfig address of the peer and already
         * known to DCO, so only install "extra" iroutes (primary = false)
         */
        ASSERT(netbits >= 0);           /* DCO requires populated netbits */
        dco_install_iroute(m, mi, &addr);
    }

    return owner;
}

static struct multi_instance *
multi_learn_in6_addr(struct multi_context *m,
                     struct multi_instance *mi,
                     struct in6_addr a6,
                     int netbits,   /* -1 if host route, otherwise # of network bits in address */
                     bool primary)
{
    struct mroute_addr addr;

    addr.len = 16;
    addr.type = MR_ADDR_IPV6;
    addr.netbits = 0;
    addr.v6.addr = a6;

    if (netbits >= 0)
    {
        addr.type |= MR_WITH_NETBITS;
        addr.netbits = (uint8_t) netbits;
        mroute_addr_mask_host_bits( &addr );
    }

    struct multi_instance *owner = multi_learn_addr(m, mi, &addr, 0);
#ifdef ENABLE_MANAGEMENT
    if (management && owner)
    {
        management_learn_addr(management, &mi->context.c2.mda_context, &addr, primary);
    }
#endif
    if (!primary)
    {
        /* "primary" is the VPN ifconfig address of the peer and already
         * known to DCO, so only install "extra" iroutes (primary = false)
         */
        ASSERT(netbits >= 0);           /* DCO requires populated netbits */
        dco_install_iroute(m, mi, &addr);
    }

    return owner;
}

/*
 * A new client has connected, add routes (server -> client)
 * to internal routing table.
 */
static void
multi_add_iroutes(struct multi_context *m,
                  struct multi_instance *mi)
{
    struct gc_arena gc = gc_new();
    const struct iroute *ir;
    const struct iroute_ipv6 *ir6;
    if (TUNNEL_TYPE(mi->context.c1.tuntap) == DEV_TYPE_TUN)
    {
        mi->did_iroutes = true;
        for (ir = mi->context.options.iroutes; ir != NULL; ir = ir->next)
        {
            if (ir->netbits >= 0)
            {
                msg(D_MULTI_LOW, "MULTI: internal route %s/%d -> %s",
                    print_in_addr_t(ir->network, 0, &gc),
                    ir->netbits,
                    multi_instance_string(mi, false, &gc));
            }
            else
            {
                msg(D_MULTI_LOW, "MULTI: internal route %s -> %s",
                    print_in_addr_t(ir->network, 0, &gc),
                    multi_instance_string(mi, false, &gc));
            }

            mroute_helper_add_iroute46(m->route_helper, ir->netbits);

            multi_learn_in_addr_t(m, mi, ir->network, ir->netbits, false);
        }
        for (ir6 = mi->context.options.iroutes_ipv6; ir6 != NULL; ir6 = ir6->next)
        {
            msg(D_MULTI_LOW, "MULTI: internal route %s/%d -> %s",
                print_in6_addr(ir6->network, 0, &gc),
                ir6->netbits,
                multi_instance_string(mi, false, &gc));

            mroute_helper_add_iroute46(m->route_helper, ir6->netbits);

            multi_learn_in6_addr(m, mi, ir6->network, ir6->netbits, false);
        }
    }
    gc_free(&gc);
}

/*
 * Given an instance (new_mi), delete all other instances which use the
 * same common name.
 */
static void
multi_delete_dup(struct multi_context *m, struct multi_instance *new_mi)
{
    if (new_mi)
    {
        const char *new_cn = tls_common_name(new_mi->context.c2.tls_multi, true);
        if (new_cn)
        {
            struct hash_iterator hi;
            struct hash_element *he;
            int count = 0;

            hash_iterator_init(m->iter, &hi);
            while ((he = hash_iterator_next(&hi)))
            {
                struct multi_instance *mi = (struct multi_instance *) he->value;
                if (mi != new_mi && !mi->halt)
                {
                    const char *cn = tls_common_name(mi->context.c2.tls_multi, true);
                    if (cn && !strcmp(cn, new_cn))
                    {
                        mi->did_iter = false;
                        multi_close_instance(m, mi, false);
                        hash_iterator_delete_element(&hi);
                        ++count;
                    }
                }
            }
            hash_iterator_free(&hi);

            if (count)
            {
                msg(D_MULTI_LOW, "MULTI: new connection by client '%s' will cause previous active sessions by this client to be dropped.  Remember to use the --duplicate-cn option if you want multiple clients using the same certificate or username to concurrently connect.", new_cn);
            }
        }
    }
}

static void
check_stale_routes(struct multi_context *m)
{

    struct gc_arena gc = gc_new();
    struct hash_iterator hi;
    struct hash_element *he;

    dmsg(D_MULTI_DEBUG, "MULTI: Checking stale routes");
    hash_iterator_init_range(m->vhash, &hi, 0, hash_n_buckets(m->vhash));
    while ((he = hash_iterator_next(&hi)) != NULL)
    {
        struct multi_route *r = (struct multi_route *) he->value;
        if (multi_route_defined(m, r) && difftime(now, r->last_reference) >= m->top.options.stale_routes_ageing_time)
        {
            dmsg(D_MULTI_DEBUG, "MULTI: Deleting stale route for address '%s'",
                 mroute_addr_print(&r->addr, &gc));
            learn_address_script(m, NULL, "delete", &r->addr);
            multi_route_del(r);
            hash_iterator_delete_element(&hi);
        }
    }
    hash_iterator_free(&hi);
    gc_free(&gc);
}

/*
 * Ensure that endpoint to be pushed to client
 * complies with --ifconfig-push-constraint directive.
 */
static bool
ifconfig_push_constraint_satisfied(const struct context *c)
{
    const struct options *o = &c->options;
    if (o->push_ifconfig_constraint_defined && c->c2.push_ifconfig_defined)
    {
        return (o->push_ifconfig_constraint_netmask & c->c2.push_ifconfig_local) == o->push_ifconfig_constraint_network;
    }
    else
    {
        return true;
    }
}

/*
 * Select a virtual address for a new client instance.
 * Use an --ifconfig-push directive, if given (static IP).
 * Otherwise use an --ifconfig-pool address (dynamic IP).
 */
static void
multi_select_virtual_addr(struct multi_context *m, struct multi_instance *mi)
{
    struct gc_arena gc = gc_new();

    /*
     * If ifconfig addresses were set by dynamic config file,
     * release pool addresses, otherwise keep them.
     */
    if (mi->context.options.push_ifconfig_defined)
    {
        /* ifconfig addresses were set statically,
         * release dynamic allocation */
        if (mi->vaddr_handle >= 0)
        {
            ifconfig_pool_release(m->ifconfig_pool, mi->vaddr_handle, true);
            mi->vaddr_handle = -1;
        }

        mi->context.c2.push_ifconfig_defined = true;
        mi->context.c2.push_ifconfig_local = mi->context.options.push_ifconfig_local;
        mi->context.c2.push_ifconfig_remote_netmask = mi->context.options.push_ifconfig_remote_netmask;
        mi->context.c2.push_ifconfig_local_alias = mi->context.options.push_ifconfig_local_alias;

        /* the current implementation does not allow "static IPv4, pool IPv6",
         * (see below) so issue a warning if that happens - don't break the
         * session, though, as we don't even know if this client WANTS IPv6
         */
        if (mi->context.options.ifconfig_ipv6_pool_defined
            && !mi->context.options.push_ifconfig_ipv6_defined)
        {
            msg( M_INFO, "MULTI_sva: WARNING: if --ifconfig-push is used for IPv4, automatic IPv6 assignment from --ifconfig-ipv6-pool does not work.  Use --ifconfig-ipv6-push for IPv6 then." );
        }
    }
    else if (m->ifconfig_pool && mi->vaddr_handle < 0) /* otherwise, choose a pool address */
    {
        in_addr_t local = 0, remote = 0;
        struct in6_addr remote_ipv6;
        const char *cn = NULL;

        if (!mi->context.options.duplicate_cn)
        {
            cn = tls_common_name(mi->context.c2.tls_multi, true);
        }

        CLEAR(remote_ipv6);
        mi->vaddr_handle = ifconfig_pool_acquire(m->ifconfig_pool, &local, &remote, &remote_ipv6, cn);
        if (mi->vaddr_handle >= 0)
        {
            const int tunnel_type = TUNNEL_TYPE(mi->context.c1.tuntap);
            const int tunnel_topology = TUNNEL_TOPOLOGY(mi->context.c1.tuntap);

            msg( M_INFO, "MULTI_sva: pool returned IPv4=%s, IPv6=%s",
                 (mi->context.options.ifconfig_pool_defined
                  ? print_in_addr_t(remote, 0, &gc)
                  : "(Not enabled)"),
                 (mi->context.options.ifconfig_ipv6_pool_defined
                  ? print_in6_addr( remote_ipv6, 0, &gc )
                  : "(Not enabled)") );

            if (mi->context.options.ifconfig_pool_defined)
            {
                /* set push_ifconfig_remote_netmask from pool ifconfig address(es) */
                mi->context.c2.push_ifconfig_local = remote;
                if (tunnel_type == DEV_TYPE_TAP || (tunnel_type == DEV_TYPE_TUN && tunnel_topology == TOP_SUBNET))
                {
                    mi->context.c2.push_ifconfig_remote_netmask = mi->context.options.ifconfig_pool_netmask;
                    if (!mi->context.c2.push_ifconfig_remote_netmask)
                    {
                        mi->context.c2.push_ifconfig_remote_netmask = mi->context.c1.tuntap->remote_netmask;
                    }
                }
                else if (tunnel_type == DEV_TYPE_TUN)
                {
                    if (tunnel_topology == TOP_P2P)
                    {
                        mi->context.c2.push_ifconfig_remote_netmask = mi->context.c1.tuntap->local;
                    }
                    else if (tunnel_topology == TOP_NET30)
                    {
                        mi->context.c2.push_ifconfig_remote_netmask = local;
                    }
                }

                if (mi->context.c2.push_ifconfig_remote_netmask)
                {
                    mi->context.c2.push_ifconfig_defined = true;
                }
                else
                {
                    msg(D_MULTI_ERRORS,
                        "MULTI: no --ifconfig-pool netmask parameter is available to push to %s",
                        multi_instance_string(mi, false, &gc));
                }
            }

            if (mi->context.options.ifconfig_ipv6_pool_defined)
            {
                mi->context.c2.push_ifconfig_ipv6_local = remote_ipv6;
                mi->context.c2.push_ifconfig_ipv6_remote =
                    mi->context.c1.tuntap->local_ipv6;
                mi->context.c2.push_ifconfig_ipv6_netbits =
                    mi->context.options.ifconfig_ipv6_netbits;
                mi->context.c2.push_ifconfig_ipv6_defined = true;
            }
        }
        else
        {
            msg(D_MULTI_ERRORS, "MULTI: no free --ifconfig-pool addresses are available");
        }
    }

    /* IPv6 push_ifconfig is a bit problematic - since IPv6 shares the
     * pool handling with IPv4, the combination "static IPv4, dynamic IPv6"
     * will fail (because no pool will be allocated in this case).
     * OTOH, this doesn't make too much sense in reality - and the other
     * way round ("dynamic IPv4, static IPv6") or "both static" makes sense
     * -> and so it's implemented right now
     */
    if (mi->context.options.push_ifconfig_ipv6_defined)
    {
        mi->context.c2.push_ifconfig_ipv6_local =
            mi->context.options.push_ifconfig_ipv6_local;
        mi->context.c2.push_ifconfig_ipv6_remote =
            mi->context.options.push_ifconfig_ipv6_remote;
        mi->context.c2.push_ifconfig_ipv6_netbits =
            mi->context.options.push_ifconfig_ipv6_netbits;
        mi->context.c2.push_ifconfig_ipv6_defined = true;

        msg( M_INFO, "MULTI_sva: push_ifconfig_ipv6 %s/%d",
             print_in6_addr( mi->context.c2.push_ifconfig_ipv6_local, 0, &gc ),
             mi->context.c2.push_ifconfig_ipv6_netbits );
    }

    gc_free(&gc);
}

/*
 * Set virtual address environmental variables.
 */
static void
multi_set_virtual_addr_env(struct multi_instance *mi)
{
    setenv_del(mi->context.c2.es, "ifconfig_pool_local_ip");
    setenv_del(mi->context.c2.es, "ifconfig_pool_remote_ip");
    setenv_del(mi->context.c2.es, "ifconfig_pool_netmask");

    if (mi->context.c2.push_ifconfig_defined)
    {
        const int tunnel_type = TUNNEL_TYPE(mi->context.c1.tuntap);
        const int tunnel_topology = TUNNEL_TOPOLOGY(mi->context.c1.tuntap);

        setenv_in_addr_t(mi->context.c2.es,
                         "ifconfig_pool_remote_ip",
                         mi->context.c2.push_ifconfig_local,
                         SA_SET_IF_NONZERO);

        if (tunnel_type == DEV_TYPE_TAP || (tunnel_type == DEV_TYPE_TUN && tunnel_topology == TOP_SUBNET))
        {
            setenv_in_addr_t(mi->context.c2.es,
                             "ifconfig_pool_netmask",
                             mi->context.c2.push_ifconfig_remote_netmask,
                             SA_SET_IF_NONZERO);
        }
        else if (tunnel_type == DEV_TYPE_TUN)
        {
            setenv_in_addr_t(mi->context.c2.es,
                             "ifconfig_pool_local_ip",
                             mi->context.c2.push_ifconfig_remote_netmask,
                             SA_SET_IF_NONZERO);
        }
    }

    setenv_del(mi->context.c2.es, "ifconfig_pool_local_ip6");
    setenv_del(mi->context.c2.es, "ifconfig_pool_remote_ip6");
    setenv_del(mi->context.c2.es, "ifconfig_pool_ip6_netbits");

    if (mi->context.c2.push_ifconfig_ipv6_defined)
    {
        setenv_in6_addr(mi->context.c2.es,
                        "ifconfig_pool_remote",
                        &mi->context.c2.push_ifconfig_ipv6_local,
                        SA_SET_IF_NONZERO);
        setenv_in6_addr(mi->context.c2.es,
                        "ifconfig_pool_local",
                        &mi->context.c2.push_ifconfig_ipv6_remote,
                        SA_SET_IF_NONZERO);
        setenv_int(mi->context.c2.es,
                   "ifconfig_pool_ip6_netbits",
                   mi->context.c2.push_ifconfig_ipv6_netbits);
    }
}

/*
 * Called after client-connect script is called
 */
static void
multi_client_connect_post(struct multi_context *m,
                          struct multi_instance *mi,
                          const char *dc_file,
                          unsigned int *option_types_found)
{
    /* Did script generate a dynamic config file? */
    if (platform_test_file(dc_file))
    {
        options_server_import(&mi->context.options,
                              dc_file,
                              D_IMPORT_ERRORS|M_OPTERR,
                              CLIENT_CONNECT_OPT_MASK,
                              option_types_found,
                              mi->context.c2.es);

        /*
         * If the --client-connect script generates a config file
         * with an --ifconfig-push directive, it will override any
         * --ifconfig-push directive from the --client-config-dir
         * directory or any --ifconfig-pool dynamic address.
         */
        multi_select_virtual_addr(m, mi);
        multi_set_virtual_addr_env(mi);
    }
}

#ifdef ENABLE_PLUGIN

/*
 * Called after client-connect plug-in is called
 */
static void
multi_client_connect_post_plugin(struct multi_context *m,
                                 struct multi_instance *mi,
                                 const struct plugin_return *pr,
                                 unsigned int *option_types_found)
{
    struct plugin_return config;

    plugin_return_get_column(pr, &config, "config");

    /* Did script generate a dynamic config file? */
    if (plugin_return_defined(&config))
    {
        int i;
        for (i = 0; i < config.n; ++i)
        {
            if (config.list[i] && config.list[i]->value)
            {
                options_string_import(&mi->context.options,
                                      config.list[i]->value,
                                      D_IMPORT_ERRORS|M_OPTERR,
                                      CLIENT_CONNECT_OPT_MASK,
                                      option_types_found,
                                      mi->context.c2.es);
            }
        }

        /*
         * If the --client-connect script generates a config file
         * with an --ifconfig-push directive, it will override any
         * --ifconfig-push directive from the --client-config-dir
         * directory or any --ifconfig-pool dynamic address.
         */
        multi_select_virtual_addr(m, mi);
        multi_set_virtual_addr_env(mi);
    }
}

#endif /* ifdef ENABLE_PLUGIN */


/*
 * Called to load management-derived client-connect config
 */
enum client_connect_return
multi_client_connect_mda(struct multi_context *m,
                         struct multi_instance *mi,
                         bool deferred,
                         unsigned int *option_types_found)
{
    /* We never return CC_RET_DEFERRED */
    ASSERT(!deferred);
    enum client_connect_return ret = CC_RET_SKIPPED;
#ifdef ENABLE_MANAGEMENT
    if (mi->cc_config)
    {
        struct buffer_entry *be;
        for (be = mi->cc_config->head; be != NULL; be = be->next)
        {
            const char *opt = BSTR(&be->buf);
            options_string_import(&mi->context.options,
                                  opt,
                                  D_IMPORT_ERRORS|M_OPTERR,
                                  CLIENT_CONNECT_OPT_MASK,
                                  option_types_found,
                                  mi->context.c2.es);
        }

        /*
         * If the --client-connect script generates a config file
         * with an --ifconfig-push directive, it will override any
         * --ifconfig-push directive from the --client-config-dir
         * directory or any --ifconfig-pool dynamic address.
         */
        multi_select_virtual_addr(m, mi);
        multi_set_virtual_addr_env(mi);

        ret = CC_RET_SUCCEEDED;
    }
#endif /* ifdef ENABLE_MANAGEMENT */
    return ret;
}

static void
multi_client_connect_setenv(struct multi_context *m,
                            struct multi_instance *mi)
{
    struct gc_arena gc = gc_new();

    /* setenv incoming cert common name for script */
    setenv_str(mi->context.c2.es, "common_name", tls_common_name(mi->context.c2.tls_multi, true));

    /* setenv client real IP address */
    setenv_trusted(mi->context.c2.es, get_link_socket_info(&mi->context));

    /* setenv client virtual IP address */
    multi_set_virtual_addr_env(mi);

    /* setenv connection time */
    {
        const char *created_ascii = time_string(mi->created, 0, false, &gc);
        setenv_str(mi->context.c2.es, "time_ascii", created_ascii);
        setenv_long_long(mi->context.c2.es, "time_unix", mi->created);
    }

    gc_free(&gc);
}

/**
 * Calculates the options that depend on the client capabilities
 * based on local options and available peer info
 * - choosen cipher
 * - peer id
 */
static bool
multi_client_set_protocol_options(struct context *c)
{
    struct tls_multi *tls_multi = c->c2.tls_multi;
    const char *const peer_info = tls_multi->peer_info;
    struct options *o = &c->options;


    unsigned int proto = extract_iv_proto(peer_info);
    if (proto & IV_PROTO_DATA_V2)
    {
        tls_multi->use_peer_id = true;
        o->use_peer_id = true;
    }
    else if (dco_enabled(o))
    {
        msg(M_INFO, "Client does not support DATA_V2. Data channel offloaing "
            "requires DATA_V2. Dropping client.");
        auth_set_client_reason(tls_multi, "Data channel negotiation "
                               "failed (missing DATA_V2)");
        return false;
    }

    /* Print a warning if we detect the client being in P2P mode and will
     * not accept our pushed ciphers */
    if (proto & IV_PROTO_NCP_P2P)
    {
        msg(M_WARN, "Note: peer reports running in P2P mode (no --pull/--client"
            "option). It will not negotiate ciphers with this server. "
            "Expect this connection to fail.");
    }

    if (proto & IV_PROTO_REQUEST_PUSH)
    {
        c->c2.push_request_received = true;
    }

#ifdef HAVE_EXPORT_KEYING_MATERIAL
    if (proto & IV_PROTO_TLS_KEY_EXPORT)
    {
        o->imported_protocol_flags |= CO_USE_TLS_KEY_MATERIAL_EXPORT;
    }
    else if (o->force_key_material_export)
    {
        msg(M_INFO, "PUSH: client does not support TLS Keying Material "
            "Exporters but --force-tls-key-material-export is enabled.");
        auth_set_client_reason(tls_multi, "Client incompatible with this "
                               "server. Keying Material Exporters (RFC 5705) "
                               "support missing. Upgrade to a client that "
                               "supports this feature (OpenVPN 2.6.0+).");
        return false;
    }
    if (proto & IV_PROTO_DYN_TLS_CRYPT)
    {
        o->imported_protocol_flags |= CO_USE_DYNAMIC_TLS_CRYPT;
    }
#endif

    if (proto & IV_PROTO_CC_EXIT_NOTIFY)
    {
        o->imported_protocol_flags |= CO_USE_CC_EXIT_NOTIFY;
    }

    /* Select cipher if client supports Negotiable Crypto Parameters */

    /* if we have already created our key, we cannot *change* our own
     * cipher -> so log the fact and push the "what we have now" cipher
     * (so the client is always told what we expect it to use)
     */
    if (get_primary_key(tls_multi)->crypto_options.key_ctx_bi.initialized)
    {
        msg(M_INFO, "PUSH: client wants to negotiate cipher (NCP), but "
            "server has already generated data channel keys, "
            "re-sending previously negotiated cipher '%s'",
            o->ciphername );
        return true;
    }

    /*
     * Push the first cipher from --data-ciphers to the client that
     * the client announces to be supporting.
     */
    char *push_cipher = ncp_get_best_cipher(o->ncp_ciphers, peer_info,
                                            tls_multi->remote_ciphername,
                                            &o->gc);

    if (push_cipher)
    {
        o->ciphername = push_cipher;
        return true;
    }

    /* NCP cipher negotiation failed. Try to figure out why exactly it
     * failed and give good error messages and potentially do a fallback
     * for non NCP clients */
    struct gc_arena gc = gc_new();
    bool ret = false;

    const char *peer_ciphers = tls_peer_ncp_list(peer_info, &gc);
    /* If we are in a situation where we know the client ciphers, there is no
     * reason to fall back to a cipher that will not be accepted by the other
     * side, in this situation we fail the auth*/
    if (strlen(peer_ciphers) > 0)
    {
        msg(M_INFO, "PUSH: No common cipher between server and client. "
            "Server data-ciphers: '%s', client supported ciphers '%s'",
            o->ncp_ciphers, peer_ciphers);
    }
    else if (tls_multi->remote_ciphername)
    {
        msg(M_INFO, "PUSH: No common cipher between server and client. "
            "Server data-ciphers: '%s', client supports cipher '%s'",
            o->ncp_ciphers, tls_multi->remote_ciphername);
    }
    else
    {
        msg(M_INFO, "PUSH: No NCP or OCC cipher data received from peer.");

        if (o->enable_ncp_fallback && !tls_multi->remote_ciphername)
        {
            msg(M_INFO, "Using data channel cipher '%s' since "
                "--data-ciphers-fallback is set.", o->ciphername);
            ret = true;
        }
        else
        {
            msg(M_INFO, "Use --data-ciphers-fallback with the cipher the "
                "client is using if you want to allow the client to connect");
        }
    }
    if (!ret)
    {
        auth_set_client_reason(tls_multi, "Data channel cipher negotiation "
                               "failed (no shared cipher)");
    }

    gc_free(&gc);
    return ret;
}

/**
 * Delete the temporary file for the return value of client connect
 * It also removes it from client_connect_defer_state and environment
 */
static void
ccs_delete_deferred_ret_file(struct multi_instance *mi)
{
    struct client_connect_defer_state *ccs = &(mi->client_connect_defer_state);
    if (!ccs->deferred_ret_file)
    {
        return;
    }

    setenv_del(mi->context.c2.es, "client_connect_deferred_file");
    if (!platform_unlink(ccs->deferred_ret_file))
    {
        msg(D_MULTI_ERRORS, "MULTI: problem deleting temporary file: %s",
            ccs->deferred_ret_file);
    }
    free(ccs->deferred_ret_file);
    ccs->deferred_ret_file = NULL;
}

/**
 * Create a temporary file for the return value of client connect
 * and puts it into the client_connect_defer_state and environment
 * as "client_connect_deferred_file"
 *
 * @return boolean value if creation was successful
 */
static bool
ccs_gen_deferred_ret_file(struct multi_instance *mi)
{
    struct client_connect_defer_state *ccs = &(mi->client_connect_defer_state);
    struct gc_arena gc = gc_new();
    const char *fn;

    /* Delete file if it already exists */
    ccs_delete_deferred_ret_file(mi);

    fn = platform_create_temp_file(mi->context.options.tmp_dir, "ccr", &gc);
    if (!fn)
    {
        gc_free(&gc);
        return false;
    }
    ccs->deferred_ret_file = string_alloc(fn, NULL);

    setenv_str(mi->context.c2.es, "client_connect_deferred_file",
               ccs->deferred_ret_file);

    gc_free(&gc);
    return true;
}

/**
 * Tests whether the deferred return value file exists and returns the
 * contained return value.
 *
 * @return CC_RET_SKIPPED if the file does not exist or is empty.
 *         CC_RET_DEFERRED, CC_RET_SUCCEEDED or CC_RET_FAILED depending on
 *         the value stored in the file.
 */
static enum client_connect_return
ccs_test_deferred_ret_file(struct multi_instance *mi)
{
    struct client_connect_defer_state *ccs = &(mi->client_connect_defer_state);
    FILE *fp = fopen(ccs->deferred_ret_file, "r");
    if (!fp)
    {
        return CC_RET_SKIPPED;
    }

    enum client_connect_return ret = CC_RET_SKIPPED;
    const int c = fgetc(fp);
    switch (c)
    {
        case '0':
            ret = CC_RET_FAILED;
            break;

        case '1':
            ret = CC_RET_SUCCEEDED;
            break;

        case '2':
            ret = CC_RET_DEFERRED;
            break;

        case EOF:
            if (feof(fp))
            {
                ret = CC_RET_SKIPPED;
                break;
            }

        /* Not EOF but other error -> fall through to error state */
        default:
            /* We received an unknown/unexpected value.  Assume failure. */
            msg(M_WARN, "WARNING: Unknown/unexpected value in deferred"
                "client-connect resultfile");
            ret = CC_RET_FAILED;
    }
    fclose(fp);

    return ret;
}

/**
 * Deletes the temporary file for the config directives of the  client connect
 * script and removes it into the client_connect_defer_state and environment
 *
 */
static void
ccs_delete_config_file(struct multi_instance *mi)
{
    struct client_connect_defer_state *ccs = &(mi->client_connect_defer_state);
    if (ccs->config_file)
    {
        setenv_del(mi->context.c2.es, "client_connect_config_file");
        if (!platform_unlink(ccs->config_file))
        {
            msg(D_MULTI_ERRORS, "MULTI: problem deleting temporary file: %s",
                ccs->config_file);
        }
        free(ccs->config_file);
        ccs->config_file = NULL;
    }
}

/**
 * Create a temporary file for the config directives of the  client connect
 * script and puts it into the client_connect_defer_state and environment
 * as "client_connect_config_file"
 *
 * @return boolean value if creation was successful
 */
static bool
ccs_gen_config_file(struct multi_instance *mi)
{
    struct client_connect_defer_state *ccs = &(mi->client_connect_defer_state);
    struct gc_arena gc = gc_new();
    const char *fn;

    if (ccs->config_file)
    {
        ccs_delete_config_file(mi);
    }

    fn = platform_create_temp_file(mi->context.options.tmp_dir, "cc", &gc);
    if (!fn)
    {
        gc_free(&gc);
        return false;
    }
    ccs->config_file = string_alloc(fn, NULL);

    setenv_str(mi->context.c2.es, "client_connect_config_file",
               ccs->config_file);

    gc_free(&gc);
    return true;
}

static enum client_connect_return
multi_client_connect_call_plugin_v1(struct multi_context *m,
                                    struct multi_instance *mi,
                                    bool deferred,
                                    unsigned int *option_types_found)
{
    enum client_connect_return ret = CC_RET_SKIPPED;
#ifdef ENABLE_PLUGIN
    ASSERT(m);
    ASSERT(mi);
    ASSERT(option_types_found);
    struct client_connect_defer_state *ccs = &(mi->client_connect_defer_state);

    /* deprecated callback, use a file for passing back return info */
    if (plugin_defined(mi->context.plugins, OPENVPN_PLUGIN_CLIENT_CONNECT))
    {
        struct argv argv = argv_new();
        int call;

        if (!deferred)
        {
            call = OPENVPN_PLUGIN_CLIENT_CONNECT;
            if (!ccs_gen_config_file(mi)
                || !ccs_gen_deferred_ret_file(mi))
            {
                ret = CC_RET_FAILED;
                goto cleanup;
            }
        }
        else
        {
            call = OPENVPN_PLUGIN_CLIENT_CONNECT_DEFER;
            /* the initial call should have created these files */
            ASSERT(ccs->config_file);
            ASSERT(ccs->deferred_ret_file);
        }

        argv_printf(&argv, "%s", ccs->config_file);
        int plug_ret = plugin_call(mi->context.plugins, call,
                                   &argv, NULL, mi->context.c2.es);
        if (plug_ret == OPENVPN_PLUGIN_FUNC_SUCCESS)
        {
            ret = CC_RET_SUCCEEDED;
        }
        else if (plug_ret == OPENVPN_PLUGIN_FUNC_DEFERRED)
        {
            ret = CC_RET_DEFERRED;
            /**
             * Contrary to the plugin v2 API, we do not demand a working
             * deferred plugin as all return can be handled by the files
             * and plugin_call return success if a plugin is not defined
             */
        }
        else
        {
            msg(M_WARN, "WARNING: client-connect plugin call failed");
            ret = CC_RET_FAILED;
        }


        /**
         * plugin api v1 client connect async feature has both plugin and
         * file return status, so in cases where the file has a code that
         * demands override, we override our return code
         */
        int file_ret = ccs_test_deferred_ret_file(mi);

        if (file_ret == CC_RET_FAILED)
        {
            ret = CC_RET_FAILED;
        }
        else if (ret == CC_RET_SUCCEEDED && file_ret == CC_RET_DEFERRED)
        {
            ret = CC_RET_DEFERRED;
        }

        /* if we still think we have succeeded, do postprocessing */
        if (ret == CC_RET_SUCCEEDED)
        {
            multi_client_connect_post(m, mi, ccs->config_file,
                                      option_types_found);
        }
cleanup:
        argv_free(&argv);

        if (ret != CC_RET_DEFERRED)
        {
            ccs_delete_config_file(mi);
            ccs_delete_deferred_ret_file(mi);
        }
    }
#endif /* ifdef ENABLE_PLUGIN */
    return ret;
}

static enum client_connect_return
multi_client_connect_call_plugin_v2(struct multi_context *m,
                                    struct multi_instance *mi,
                                    bool deferred,
                                    unsigned int *option_types_found)
{
    enum client_connect_return ret = CC_RET_SKIPPED;
#ifdef ENABLE_PLUGIN
    ASSERT(m);
    ASSERT(mi);
    ASSERT(option_types_found);

    int call = deferred ? OPENVPN_PLUGIN_CLIENT_CONNECT_DEFER_V2 :
               OPENVPN_PLUGIN_CLIENT_CONNECT_V2;
    /* V2 callback, use a plugin_return struct for passing back return info */
    if (plugin_defined(mi->context.plugins, call))
    {
        struct plugin_return pr;

        plugin_return_init(&pr);

        int plug_ret = plugin_call(mi->context.plugins, call,
                                   NULL, &pr, mi->context.c2.es);
        if (plug_ret == OPENVPN_PLUGIN_FUNC_SUCCESS)
        {
            multi_client_connect_post_plugin(m, mi, &pr, option_types_found);
            ret = CC_RET_SUCCEEDED;
        }
        else if (plug_ret == OPENVPN_PLUGIN_FUNC_DEFERRED)
        {
            ret = CC_RET_DEFERRED;
            if (!(plugin_defined(mi->context.plugins,
                                 OPENVPN_PLUGIN_CLIENT_CONNECT_DEFER_V2)))
            {
                msg(M_WARN, "A plugin that defers from the "
                    "OPENVPN_PLUGIN_CLIENT_CONNECT_V2 call must also "
                    "declare support for "
                    "OPENVPN_PLUGIN_CLIENT_CONNECT_DEFER_V2");
                ret = CC_RET_FAILED;
            }
        }
        else
        {
            msg(M_WARN, "WARNING: client-connect-v2 plugin call failed");
            ret = CC_RET_FAILED;
        }


        plugin_return_free(&pr);
    }
#endif /* ifdef ENABLE_PLUGIN */
    return ret;
}

static enum client_connect_return
multi_client_connect_script_deferred(struct multi_context *m,
                                     struct multi_instance *mi,
                                     unsigned int *option_types_found)
{
    ASSERT(mi);
    ASSERT(option_types_found);
    struct client_connect_defer_state *ccs = &(mi->client_connect_defer_state);
    enum client_connect_return ret = CC_RET_SKIPPED;

    ret = ccs_test_deferred_ret_file(mi);

    if (ret == CC_RET_SKIPPED)
    {
        /*
         * Skipped and deferred are equivalent in this context.
         * skipped means that the called program has not yet
         * written a return status implicitly needing more time
         * while deferred is the explicit notification that it
         * needs more time
         */
        ret = CC_RET_DEFERRED;
    }

    if (ret == CC_RET_SUCCEEDED)
    {
        ccs_delete_deferred_ret_file(mi);
        multi_client_connect_post(m, mi, ccs->config_file,
                                  option_types_found);
        ccs_delete_config_file(mi);
    }
    if (ret == CC_RET_FAILED)
    {
        msg(M_INFO, "MULTI: deferred --client-connect script returned CC_RET_FAILED");
        ccs_delete_deferred_ret_file(mi);
        ccs_delete_config_file(mi);
    }
    return ret;
}

/**
 * Runs the --client-connect script if one is defined.
 */
static enum client_connect_return
multi_client_connect_call_script(struct multi_context *m,
                                 struct multi_instance *mi,
                                 bool deferred,
                                 unsigned int *option_types_found)
{
    if (deferred)
    {
        return multi_client_connect_script_deferred(m, mi, option_types_found);
    }
    ASSERT(m);
    ASSERT(mi);

    enum client_connect_return ret = CC_RET_SKIPPED;
    struct client_connect_defer_state *ccs = &(mi->client_connect_defer_state);

    if (mi->context.options.client_connect_script)
    {
        struct argv argv = argv_new();
        struct gc_arena gc = gc_new();

        setenv_str(mi->context.c2.es, "script_type", "client-connect");

        if (!ccs_gen_config_file(mi)
            || !ccs_gen_deferred_ret_file(mi))
        {
            ret = CC_RET_FAILED;
            goto cleanup;
        }

        argv_parse_cmd(&argv, mi->context.options.client_connect_script);
        argv_printf_cat(&argv, "%s", ccs->config_file);

        if (openvpn_run_script(&argv, mi->context.c2.es, 0, "--client-connect"))
        {
            if (ccs_test_deferred_ret_file(mi) == CC_RET_DEFERRED)
            {
                ret = CC_RET_DEFERRED;
            }
            else
            {
                multi_client_connect_post(m, mi, ccs->config_file,
                                          option_types_found);
                ret = CC_RET_SUCCEEDED;
            }
        }
        else
        {
            ret = CC_RET_FAILED;
        }
cleanup:
        if (ret != CC_RET_DEFERRED)
        {
            ccs_delete_config_file(mi);
            ccs_delete_deferred_ret_file(mi);
        }
        argv_free(&argv);
        gc_free(&gc);
    }
    return ret;
}

static bool
multi_client_setup_dco_initial(struct multi_context *m,
                               struct multi_instance *mi,
                               struct gc_arena *gc)
{
    if (!dco_enabled(&mi->context.options))
    {
        /* DCO not enabled, nothing to do, return sucess */
        return true;
    }
    int ret = dco_multi_add_new_peer(m, mi);
    if (ret < 0)
    {
        msg(D_DCO, "Cannot add peer to DCO for %s: %s (%d)",
            multi_instance_string(mi, false, gc), strerror(-ret), ret);
        return false;
    }

    if (mi->context.options.ping_send_timeout || mi->context.c2.frame.mss_fix)
    {
        ret = dco_set_peer(&mi->context.c1.tuntap->dco,
                           mi->context.c2.tls_multi->dco_peer_id,
                           mi->context.options.ping_send_timeout,
                           mi->context.options.ping_rec_timeout,
                           mi->context.c2.frame.mss_fix);
        if (ret < 0)
        {
            msg(D_DCO, "Cannot set DCO peer parameters for %s (id=%u): %s",
                multi_instance_string(mi, false, gc),
                mi->context.c2.tls_multi->dco_peer_id, strerror(-ret));
            return false;
        }
    }
    return true;
}

/**
 * Generates the data channel keys
 */
static bool
multi_client_generate_tls_keys(struct context *c)
{
    struct frame *frame_fragment = NULL;
#ifdef ENABLE_FRAGMENT
    if (c->options.ce.fragment)
    {
        frame_fragment = &c->c2.frame_fragment;
    }
#endif
    struct tls_session *session = &c->c2.tls_multi->session[TM_ACTIVE];
    if (!tls_session_update_crypto_params(c->c2.tls_multi, session, &c->options,
                                          &c->c2.frame, frame_fragment,
                                          get_link_socket_info(c)))
    {
        msg(D_TLS_ERRORS, "TLS Error: initializing data channel failed");
        register_signal(c->sig, SIGUSR1, "process-push-msg-failed");
        return false;
    }

    return true;
}

static void
multi_client_connect_late_setup(struct multi_context *m,
                                struct multi_instance *mi,
                                const unsigned int option_types_found)
{
    ASSERT(m);
    ASSERT(mi);

    struct gc_arena gc = gc_new();
    /*
     * Process sourced options.
     */
    do_deferred_options(&mi->context, option_types_found);

    /*
     * make sure we got ifconfig settings from somewhere
     */
    if (!mi->context.c2.push_ifconfig_defined)
    {
        msg(D_MULTI_ERRORS, "MULTI: no dynamic or static remote"
            "--ifconfig address is available for %s",
            multi_instance_string(mi, false, &gc));
    }

    /*
     * make sure that ifconfig settings comply with constraints
     */
    if (!ifconfig_push_constraint_satisfied(&mi->context))
    {
        const char *ifconfig_constraint_network =
            print_in_addr_t(mi->context.options.push_ifconfig_constraint_network, 0, &gc);
        const char *ifconfig_constraint_netmask =
            print_in_addr_t(mi->context.options.push_ifconfig_constraint_netmask, 0, &gc);

        /* JYFIXME -- this should cause the connection to fail */
        msg(D_MULTI_ERRORS, "MULTI ERROR: primary virtual IP for %s (%s)"
            "violates tunnel network/netmask constraint (%s/%s)",
            multi_instance_string(mi, false, &gc),
            print_in_addr_t(mi->context.c2.push_ifconfig_local, 0, &gc),
            ifconfig_constraint_network, ifconfig_constraint_netmask);
    }

    /*
     * For routed tunnels, set up internal route to endpoint
     * plus add all iroute routes.
     */
    if (TUNNEL_TYPE(mi->context.c1.tuntap) == DEV_TYPE_TUN)
    {
        if (mi->context.c2.push_ifconfig_defined)
        {
            multi_learn_in_addr_t(m, mi,
                                  mi->context.c2.push_ifconfig_local,
                                  -1, true);
            msg(D_MULTI_LOW, "MULTI: primary virtual IP for %s: %s",
                multi_instance_string(mi, false, &gc),
                print_in_addr_t(mi->context.c2.push_ifconfig_local, 0, &gc));
        }

        if (mi->context.c2.push_ifconfig_ipv6_defined)
        {
            multi_learn_in6_addr(m, mi,
                                 mi->context.c2.push_ifconfig_ipv6_local,
                                 -1, true);
            /* TODO: find out where addresses are "unlearned"!! */
            const char *ifconfig_local_ipv6 =
                print_in6_addr(mi->context.c2.push_ifconfig_ipv6_local, 0, &gc);
            msg(D_MULTI_LOW, "MULTI: primary virtual IPv6 for %s: %s",
                multi_instance_string(mi, false, &gc),
                ifconfig_local_ipv6);
        }

        /* add routes locally, pointing to new client, if
         * --iroute options have been specified */
        multi_add_iroutes(m, mi);

        /*
         * iroutes represent subnets which are "owned" by a particular
         * client.  Therefore, do not actually push a route to a client
         * if it matches one of the client's iroutes.
         */
        remove_iroutes_from_push_route_list(&mi->context.options);
    }
    else if (mi->context.options.iroutes)
    {
        msg(D_MULTI_ERRORS, "MULTI: --iroute options rejected for %s -- iroute"
            "only works with tun-style tunnels",
            multi_instance_string(mi, false, &gc));
    }

    /* set our client's VPN endpoint for status reporting purposes */
    mi->reporting_addr = mi->context.c2.push_ifconfig_local;
    mi->reporting_addr_ipv6 = mi->context.c2.push_ifconfig_ipv6_local;

    /* set context-level authentication flag */
    mi->context.c2.tls_multi->multi_state = CAS_CONNECT_DONE;

    /* authentication complete, calculate dynamic client specific options */
    if (!multi_client_set_protocol_options(&mi->context))
    {
        mi->context.c2.tls_multi->multi_state = CAS_FAILED;
    }
    /* only continue if setting protocol options worked */
    else if (!multi_client_setup_dco_initial(m, mi, &gc))
    {
        mi->context.c2.tls_multi->multi_state = CAS_FAILED;
    }
    /* Generate data channel keys only if setting protocol options
     * and DCO initial setup has not failed */
    else if (!multi_client_generate_tls_keys(&mi->context))
    {
        mi->context.c2.tls_multi->multi_state = CAS_FAILED;
    }

    /* send push reply if ready */
    if (mi->context.c2.push_request_received)
    {
        process_incoming_push_request(&mi->context);
    }
    gc_free(&gc);
}

static void
multi_client_connect_early_setup(struct multi_context *m,
                                 struct multi_instance *mi)
{
    ASSERT(mi->context.c1.tuntap);
    /*
     * lock down the common name and cert hashes so they can't change
     * during future TLS renegotiations
     */
    tls_lock_common_name(mi->context.c2.tls_multi);
    tls_lock_cert_hash_set(mi->context.c2.tls_multi);

    /* generate a msg() prefix for this client instance */
    generate_prefix(mi);

    /* delete instances of previous clients with same common-name */
    if (!mi->context.options.duplicate_cn)
    {
        multi_delete_dup(m, mi);
    }

    /* reset pool handle to null */
    mi->vaddr_handle = -1;

    /* do --client-connect setenvs */
    multi_select_virtual_addr(m, mi);

    multi_client_connect_setenv(m, mi);
}

/**
 *  Do the necessary modification for doing the compress migrate. This is
 *  implemented as a connect handler as it fits the modify config for a client
 *  paradigm and also is early enough in the chain to be overwritten by another
 *  ccd/script to do compression on a special client.
 */
static enum client_connect_return
multi_client_connect_compress_migrate(struct multi_context *m,
                                      struct multi_instance *mi,
                                      bool deferred,
                                      unsigned int *option_types_found)
{
#ifdef USE_COMP
    struct options *o = &mi->context.options;
    const char *const peer_info = mi->context.c2.tls_multi->peer_info;

    if (o->comp.flags & COMP_F_MIGRATE && mi->context.c2.tls_multi->remote_usescomp)
    {
        if (peer_info && strstr(peer_info, "IV_COMP_STUBv2=1"))
        {
            push_option(o, "compress stub-v2", M_USAGE);
        }
        else
        {
            /* Client is old and does not support STUBv2 but since it
             * announced comp-lzo via OCC we assume it uses comp-lzo, so
             * switch to that and push the uncompressed variant. */
            push_option(o, "comp-lzo no", M_USAGE);
            o->comp.alg = COMP_ALG_STUB;
            *option_types_found |= OPT_P_COMP;
        }
    }
#endif
    return CC_RET_SUCCEEDED;
}

/**
 * Try to source a dynamic config file from the
 * --client-config-dir directory.
 */
static enum client_connect_return
multi_client_connect_source_ccd(struct multi_context *m,
                                struct multi_instance *mi,
                                bool deferred,
                                unsigned int *option_types_found)
{
    /* Since we never return a CC_RET_DEFERRED, this indicates a serious
     * problem */
    ASSERT(!deferred);
    enum client_connect_return ret = CC_RET_SKIPPED;
    if (mi->context.options.client_config_dir)
    {
        struct gc_arena gc = gc_new();
        const char *ccd_file = NULL;

        const char *ccd_client =
            platform_gen_path(mi->context.options.client_config_dir,
                              tls_common_name(mi->context.c2.tls_multi, false),
                              &gc);

        const char *ccd_default =
            platform_gen_path(mi->context.options.client_config_dir,
                              CCD_DEFAULT, &gc);


        /* try common-name file */
        if (platform_test_file(ccd_client))
        {
            ccd_file = ccd_client;
        }
        /* try default file */
        else if (platform_test_file(ccd_default))
        {
            ccd_file = ccd_default;
        }

        if (ccd_file)
        {
            options_server_import(&mi->context.options,
                                  ccd_file,
                                  D_IMPORT_ERRORS|M_OPTERR,
                                  CLIENT_CONNECT_OPT_MASK,
                                  option_types_found,
                                  mi->context.c2.es);
            /*
             * Select a virtual address from either --ifconfig-push in
             * --client-config-dir file or --ifconfig-pool.
             */
            multi_select_virtual_addr(m, mi);

            multi_client_connect_setenv(m, mi);

            ret = CC_RET_SUCCEEDED;
        }
        gc_free(&gc);
    }
    return ret;
}

typedef enum client_connect_return (*multi_client_connect_handler)
    (struct multi_context *m, struct multi_instance *mi,
    bool from_deferred, unsigned int *option_types_found);

static const multi_client_connect_handler client_connect_handlers[] = {
    multi_client_connect_compress_migrate,
    multi_client_connect_source_ccd,
    multi_client_connect_call_plugin_v1,
    multi_client_connect_call_plugin_v2,
    multi_client_connect_call_script,
    multi_client_connect_mda,
    NULL,
};

/*
 * Called as soon as the SSL/TLS connection is authenticated.
 *
 * Will collect the client specific configuration from the different
 * sources like ccd files, connect plugins and management interface.
 *
 * This method starts with cas_context CAS_PENDING and will move the
 * state machine to either CAS_SUCCEEDED on success or
 * CAS_FAILED/CAS_PARTIAL on failure.
 *
 * Instance-specific directives to be processed (CLIENT_CONNECT_OPT_MASK)
 * include:
 *
 *   iroute start-ip end-ip
 *   ifconfig-push local remote-netmask
 *   push
 *
 *
 */
static void
multi_connection_established(struct multi_context *m, struct multi_instance *mi)
{
    /* We are only called for the CAS_PENDING_x states, so we
     * can ignore other states here */
    bool from_deferred = (mi->context.c2.tls_multi->multi_state != CAS_PENDING);

    int *cur_handler_index = &mi->client_connect_defer_state.cur_handler_index;
    unsigned int *option_types_found =
        &mi->client_connect_defer_state.option_types_found;

    /* We are called for the first time */
    if (!from_deferred)
    {
        *cur_handler_index = 0;
        *option_types_found = 0;
        /* Initially we have no handler that has returned a result */
        mi->context.c2.tls_multi->multi_state = CAS_PENDING_DEFERRED;

        multi_client_connect_early_setup(m, mi);
    }

    bool cc_succeeded = true;

    while (cc_succeeded
           && client_connect_handlers[*cur_handler_index] != NULL)
    {
        enum client_connect_return ret;
        ret = client_connect_handlers[*cur_handler_index](m, mi, from_deferred,
                                                          option_types_found);

        from_deferred = false;

        switch (ret)
        {
            case CC_RET_SUCCEEDED:
                /*
                 * Remember that we already had at least one handler
                 * returning a result should we go to into deferred state
                 */
                mi->context.c2.tls_multi->multi_state = CAS_PENDING_DEFERRED_PARTIAL;
                break;

            case CC_RET_SKIPPED:
                /*
                 * Move on with the next handler without modifying any
                 * other state
                 */
                break;

            case CC_RET_DEFERRED:
                /*
                 * we already set multi_status to DEFERRED_RESULT or
                 * DEFERRED_NO_RESULT. We just return
                 * from the function as having multi_status
                 */
                return;

            case CC_RET_FAILED:
                /*
                 * One handler failed. We abort the chain and set the final
                 * result to failed
                 */
                cc_succeeded = false;
                break;

            default:
                ASSERT(0);
        }

        /*
         * Check for "disable" directive in client-config-dir file
         * or config file generated by --client-connect script.
         */
        if (mi->context.options.disable)
        {
            msg(D_MULTI_ERRORS, "MULTI: client has been rejected due to "
                "'disable' directive");
            cc_succeeded = false;
        }

        (*cur_handler_index)++;
    }

    /* Check if we have forbidding options in the current mode */
    if (dco_enabled(&mi->context.options)
        && !dco_check_option(D_MULTI_ERRORS, &mi->context.options))
    {
        msg(D_MULTI_ERRORS, "MULTI: client has been rejected due to incompatible DCO options");
        cc_succeeded = false;
    }

    if (!check_compression_settings_valid(&mi->context.options.comp, D_MULTI_ERRORS))
    {
        msg(D_MULTI_ERRORS, "MULTI: client has been rejected due to invalid compression options");
        cc_succeeded = false;
    }

    if (cc_succeeded)
    {
        multi_client_connect_late_setup(m, mi, *option_types_found);
    }
    else
    {
        /* run the disconnect script if we had a connect script that
         * did not fail */
        if (mi->context.c2.tls_multi->multi_state == CAS_PENDING_DEFERRED_PARTIAL)
        {
            multi_client_disconnect_script(m, mi);
        }

        mi->context.c2.tls_multi->multi_state = CAS_FAILED;
    }

    /* increment number of current authenticated clients */
    ++m->n_clients;
    update_mstat_n_clients(m->n_clients);
    --mi->n_clients_delta;

#ifdef ENABLE_MANAGEMENT
    if (management)
    {
        management_connection_established(management,
                                          &mi->context.c2.mda_context, mi->context.c2.es);
    }
#endif
}

#ifdef ENABLE_ASYNC_PUSH
/*
 * Called when inotify event is fired, which happens when acf
 * or connect-status file is closed or deleted.
 * Continues authentication and sends push_reply
 * (or be deferred again by client-connect)
 */
void
multi_process_file_closed(struct multi_context *m, const unsigned int mpp_flags)
{
    char buffer[INOTIFY_EVENT_BUFFER_SIZE];
    size_t buffer_i = 0;
    int r = read(m->top.c2.inotify_fd, buffer, INOTIFY_EVENT_BUFFER_SIZE);

    while (buffer_i < r)
    {
        /* parse inotify events */
        struct inotify_event *pevent = (struct inotify_event *) &buffer[buffer_i];
        size_t event_size = sizeof(struct inotify_event) + pevent->len;
        buffer_i += event_size;

        msg(D_MULTI_DEBUG, "MULTI: modified fd %d, mask %d", pevent->wd, pevent->mask);

        struct multi_instance *mi = hash_lookup(m->inotify_watchers, (void *) (unsigned long) pevent->wd);

        if (pevent->mask & IN_CLOSE_WRITE)
        {
            if (mi)
            {
                /* continue authentication, perform NCP negotiation and send push_reply */
                multi_process_post(m, mi, mpp_flags);
            }
            else
            {
                msg(D_MULTI_ERRORS, "MULTI: multi_instance not found!");
            }
        }
        else if (pevent->mask & IN_IGNORED)
        {
            /* this event is _always_ fired when watch is removed or file is deleted */
            if (mi)
            {
                hash_remove(m->inotify_watchers, (void *) (unsigned long) pevent->wd);
                mi->inotify_watch = -1;
            }
        }
        else
        {
            msg(D_MULTI_ERRORS, "MULTI: unknown mask %d", pevent->mask);
        }
    }
}
#endif /* ifdef ENABLE_ASYNC_PUSH */

/*
 * Add a mbuf buffer to a particular
 * instance.
 */
void
multi_add_mbuf(struct multi_context *m,
               struct multi_instance *mi,
               struct mbuf_buffer *mb)
{
    if (multi_output_queue_ready(m, mi))
    {
        struct mbuf_item item;
        item.buffer = mb;
        item.instance = mi;
        mbuf_add_item(m->mbuf, &item);
    }
    else
    {
        msg(D_MULTI_DROPPED, "MULTI: packet dropped due to output saturation (multi_add_mbuf)");
    }
}

/*
 * Add a packet to a client instance output queue.
 */
static inline void
multi_unicast(struct multi_context *m,
              const struct buffer *buf,
              struct multi_instance *mi)
{
    struct mbuf_buffer *mb;

    if (BLEN(buf) > 0)
    {
        mb = mbuf_alloc_buf(buf);
        mb->flags = MF_UNICAST;
        multi_add_mbuf(m, mi, mb);
        mbuf_free_buf(mb);
    }
}

/*
 * Broadcast a packet to all clients.
 */
static void
multi_bcast(struct multi_context *m,
            const struct buffer *buf,
            const struct multi_instance *sender_instance,
            const struct mroute_addr *sender_addr,
            uint16_t vid)
{
    struct hash_iterator hi;
    struct hash_element *he;
    struct multi_instance *mi;
    struct mbuf_buffer *mb;

    if (BLEN(buf) > 0)
    {
        perf_push(PERF_MULTI_BCAST);
#ifdef MULTI_DEBUG_EVENT_LOOP
        printf("BCAST len=%d\n", BLEN(buf));
#endif
        mb = mbuf_alloc_buf(buf);
        hash_iterator_init(m->iter, &hi);

        while ((he = hash_iterator_next(&hi)))
        {
            mi = (struct multi_instance *) he->value;
            if (mi != sender_instance && !mi->halt)
            {
                if (vid != 0 && vid != mi->context.options.vlan_pvid)
                {
                    continue;
                }
                multi_add_mbuf(m, mi, mb);
            }
        }

        hash_iterator_free(&hi);
        mbuf_free_buf(mb);
        perf_pop();
    }
}

/*
 * Given a time delta, indicating that we wish to be
 * awoken by the scheduler at time now + delta, figure
 * a sigma parameter (in microseconds) that represents
 * a sort of fuzz factor around delta, so that we're
 * really telling the scheduler to wake us up any time
 * between now + delta - sigma and now + delta + sigma.
 *
 * The sigma parameter helps the scheduler to run more efficiently.
 * Sigma should be no larger than TV_WITHIN_SIGMA_MAX_USEC
 */
static inline unsigned int
compute_wakeup_sigma(const struct timeval *delta)
{
    if (delta->tv_sec < 1)
    {
        /* if < 1 sec, fuzz = # of microseconds / 8 */
        return delta->tv_usec >> 3;
    }
    else
    {
        /* if < 10 minutes, fuzz = 13.1% of timeout */
        if (delta->tv_sec < 600)
        {
            return delta->tv_sec << 17;
        }
        else
        {
            return 120000000; /* if >= 10 minutes, fuzz = 2 minutes */
        }
    }
}

static void
multi_schedule_context_wakeup(struct multi_context *m, struct multi_instance *mi)
{
    /* calculate an absolute wakeup time */
    ASSERT(!openvpn_gettimeofday(&mi->wakeup, NULL));
    tv_add(&mi->wakeup, &mi->context.c2.timeval);

    /* tell scheduler to wake us up at some point in the future */
    schedule_add_entry(m->schedule,
                       (struct schedule_entry *) mi,
                       &mi->wakeup,
                       compute_wakeup_sigma(&mi->context.c2.timeval));
}

#if defined(ENABLE_ASYNC_PUSH)
static void
add_inotify_file_watch(struct multi_context *m, struct multi_instance *mi,
                       int inotify_fd, const char *file)
{
    /* watch acf file */
    long watch_descriptor = inotify_add_watch(inotify_fd, file,
                                              IN_CLOSE_WRITE | IN_ONESHOT);
    if (watch_descriptor >= 0)
    {
        if (mi->inotify_watch != -1)
        {
            hash_remove(m->inotify_watchers,
                        (void *) (unsigned long)mi->inotify_watch);
        }
        hash_add(m->inotify_watchers, (const uintptr_t *)watch_descriptor,
                 mi, true);
        mi->inotify_watch = watch_descriptor;
    }
    else
    {
        msg(M_NONFATAL | M_ERRNO, "MULTI: inotify_add_watch error");
    }
}
#endif /* if defined(ENABLE_ASYNC_PUSH) */

/*
 * Figure instance-specific timers, convert
 * earliest to absolute time in mi->wakeup,
 * call scheduler with our future wakeup time.
 *
 * Also close context on signal.
 */
bool
multi_process_post(struct multi_context *m, struct multi_instance *mi, const unsigned int flags)
{
    bool ret = true;

    if (!IS_SIG(&mi->context) && ((flags & MPP_PRE_SELECT) || ((flags & MPP_CONDITIONAL_PRE_SELECT) && !ANY_OUT(&mi->context))))
    {
#if defined(ENABLE_ASYNC_PUSH)
        bool was_unauthenticated = true;
        struct key_state *ks = NULL;
        if (mi->context.c2.tls_multi)
        {
            ks = &mi->context.c2.tls_multi->session[TM_ACTIVE].key[KS_PRIMARY];
            was_unauthenticated = (ks->authenticated == KS_AUTH_FALSE);
        }
#endif

        /* figure timeouts and fetch possible outgoing
         * to_link packets (such as ping or TLS control) */
        pre_select(&mi->context);

#if defined(ENABLE_ASYNC_PUSH)
        /*
         * if we see the state transition from unauthenticated to deferred
         * and an auth_control_file, we assume it got just added and add
         * inotify watch to that file
         */
        if (ks && ks->plugin_auth.auth_control_file && was_unauthenticated
            && (ks->authenticated == KS_AUTH_DEFERRED))
        {
            add_inotify_file_watch(m, mi, m->top.c2.inotify_fd,
                                   ks->plugin_auth.auth_control_file);
        }
        if (ks && ks->script_auth.auth_control_file && was_unauthenticated
            && (ks->authenticated == KS_AUTH_DEFERRED))
        {
            add_inotify_file_watch(m, mi, m->top.c2.inotify_fd,
                                   ks->script_auth.auth_control_file);
        }
#endif

        if (!IS_SIG(&mi->context))
        {
            /* connection is "established" when SSL/TLS key negotiation succeeds
             * and (if specified) auth user/pass succeeds */

            if (is_cas_pending(mi->context.c2.tls_multi->multi_state))
            {
                multi_connection_established(m, mi);
            }
#if defined(ENABLE_ASYNC_PUSH)
            if (is_cas_pending(mi->context.c2.tls_multi->multi_state)
                && mi->client_connect_defer_state.deferred_ret_file)
            {
                add_inotify_file_watch(m, mi, m->top.c2.inotify_fd,
                                       mi->client_connect_defer_state.
                                       deferred_ret_file);
            }
#endif
            /* tell scheduler to wake us up at some point in the future */
            multi_schedule_context_wakeup(m, mi);
        }
    }

    if (IS_SIG(&mi->context))
    {
        if (flags & MPP_CLOSE_ON_SIGNAL)
        {
            multi_close_instance_on_signal(m, mi);
            ret = false;
        }
    }
    else
    {
        /* continue to pend on output? */
        multi_set_pending(m, ANY_OUT(&mi->context) ? mi : NULL);

#ifdef MULTI_DEBUG_EVENT_LOOP
        printf("POST %s[%d] to=%d lo=%d/%d w=%" PRIi64 "/%ld\n",
               id(mi),
               (int) (mi == m->pending),
               mi ? mi->context.c2.to_tun.len : -1,
               mi ? mi->context.c2.to_link.len : -1,
               (mi && mi->context.c2.fragment) ? mi->context.c2.fragment->outgoing.len : -1,
               (int64_t)mi->context.c2.timeval.tv_sec,
               (long)mi->context.c2.timeval.tv_usec);
#endif
    }

    if ((flags & MPP_RECORD_TOUCH) && m->mpp_touched)
    {
        *m->mpp_touched = mi;
    }

    return ret;
}

void
multi_process_float(struct multi_context *m, struct multi_instance *mi)
{
    struct mroute_addr real;
    struct hash *hash = m->hash;
    struct gc_arena gc = gc_new();

    if (!mroute_extract_openvpn_sockaddr(&real, &m->top.c2.from.dest, true))
    {
        goto done;
    }

    const uint32_t hv = hash_value(hash, &real);
    struct hash_bucket *bucket = hash_bucket(hash, hv);

    /* make sure that we don't float to an address taken by another client */
    struct hash_element *he = hash_lookup_fast(hash, bucket, &real, hv);
    if (he)
    {
        struct multi_instance *ex_mi = (struct multi_instance *) he->value;

        struct tls_multi *m1 = mi->context.c2.tls_multi;
        struct tls_multi *m2 = ex_mi->context.c2.tls_multi;

        /* do not float if target address is taken by client with another cert */
        if (!cert_hash_compare(m1->locked_cert_hash_set, m2->locked_cert_hash_set))
        {
            msg(D_MULTI_LOW, "Disallow float to an address taken by another client %s",
                multi_instance_string(ex_mi, false, &gc));

            mi->context.c2.buf.len = 0;

            goto done;
        }

        msg(D_MULTI_MEDIUM, "closing instance %s", multi_instance_string(ex_mi, false, &gc));
        multi_close_instance(m, ex_mi, false);
    }

    msg(D_MULTI_MEDIUM, "peer %" PRIu32 " (%s) floated from %s to %s",
        mi->context.c2.tls_multi->peer_id,
        tls_common_name(mi->context.c2.tls_multi, false),
        mroute_addr_print(&mi->real, &gc),
        print_link_socket_actual(&m->top.c2.from, &gc));

    /* remove old address from hash table before changing address */
    ASSERT(hash_remove(m->hash, &mi->real));
    ASSERT(hash_remove(m->iter, &mi->real));

    /* change external network address of the remote peer */
    mi->real = real;
    generate_prefix(mi);

    mi->context.c2.from = m->top.c2.from;
    mi->context.c2.to_link_addr = &mi->context.c2.from;

    /* inherit parent link_socket and link_socket_info */
    mi->context.c2.link_socket = m->top.c2.link_socket;
    mi->context.c2.link_socket_info->lsa->actual = m->top.c2.from;

    tls_update_remote_addr(mi->context.c2.tls_multi, &mi->context.c2.from);

    ASSERT(hash_add(m->hash, &mi->real, mi, false));
    ASSERT(hash_add(m->iter, &mi->real, mi, false));

#ifdef ENABLE_MANAGEMENT
    ASSERT(hash_add(m->cid_hash, &mi->context.c2.mda_context.cid, mi, true));
#endif

done:
    gc_free(&gc);
}

/*
 * Called when an instance should be closed due to the
 * reception of a soft signal.
 */
void
multi_close_instance_on_signal(struct multi_context *m, struct multi_instance *mi)
{
    remap_signal(&mi->context);
    set_prefix(mi);
    print_signal(mi->context.sig, "client-instance", D_MULTI_LOW);
    clear_prefix();
    multi_close_instance(m, mi, false);
}

#if (defined(ENABLE_DCO) && (defined(TARGET_LINUX) || defined(TARGET_FREEBSD))) || defined(ENABLE_MANAGEMENT)
static void
multi_signal_instance(struct multi_context *m, struct multi_instance *mi, const int sig)
{
    mi->context.sig->signal_received = sig;
    multi_close_instance_on_signal(m, mi);
}
#endif

#if defined(ENABLE_DCO) && (defined(TARGET_LINUX) || defined(TARGET_FREEBSD))
static void
process_incoming_del_peer(struct multi_context *m, struct multi_instance *mi,
                          dco_context_t *dco)
{
    const char *reason = "ovpn-dco: unknown reason";
    switch (dco->dco_del_peer_reason)
    {
        case OVPN_DEL_PEER_REASON_EXPIRED:
            reason = "ovpn-dco: ping expired";
            break;

        case OVPN_DEL_PEER_REASON_TRANSPORT_ERROR:
            reason = "ovpn-dco: transport error";
            break;

        case OVPN_DEL_PEER_REASON_TRANSPORT_DISCONNECT:
            reason = "ovpn-dco: transport disconnected";
            break;

        case OVPN_DEL_PEER_REASON_USERSPACE:
            /* We assume that is ourselves. Unfortunately, sometimes these
             * events happen with enough delay that they can have an order of
             *
             * dco_del_peer x
             * [new client connecting]
             * dco_new_peer x
             * event from dco_del_peer arrives.
             *
             * if we do not ignore this we get desynced with the kernel
             * since we assume the peer-id is free again. The other way would
             * be to send a dco_del_peer again
             */
            return;
    }

    /* When kernel already deleted the peer, the socket is no longer
     * installed, and we do not need to clean up the state in the kernel */
    mi->context.c2.tls_multi->dco_peer_id = -1;
    mi->context.sig->signal_text = reason;
    mi->context.c2.dco_read_bytes = dco->dco_read_bytes;
    mi->context.c2.dco_write_bytes = dco->dco_write_bytes;
    multi_signal_instance(m, mi, SIGTERM);
}

bool
multi_process_incoming_dco(struct multi_context *m)
{
    dco_context_t *dco = &m->top.c1.tuntap->dco;

    struct multi_instance *mi = NULL;

    int ret = dco_do_read(&m->top.c1.tuntap->dco);

    int peer_id = dco->dco_message_peer_id;

    /* no peer-specific message delivered -> nothing to process.
     * bail out right away
     */
    if (peer_id < 0)
    {
        return ret > 0;
    }

    if ((peer_id < m->max_clients) && (m->instances[peer_id]))
    {
        mi = m->instances[peer_id];
        if (dco->dco_message_type == OVPN_CMD_DEL_PEER)
        {
            process_incoming_del_peer(m, mi, dco);
        }
        else if (dco->dco_message_type == OVPN_CMD_SWAP_KEYS)
        {
            tls_session_soft_reset(mi->context.c2.tls_multi);
        }
    }
    else
    {
        int msglevel = D_DCO;
        if (dco->dco_message_type == OVPN_CMD_DEL_PEER
            && dco->dco_del_peer_reason == OVPN_DEL_PEER_REASON_USERSPACE)
        {
            /* we receive OVPN_CMD_DEL_PEER message with reason USERSPACE
             * after we kill the peer ourselves. This peer may have already
             * been deleted, so we end up here.
             * In this case, print the following debug message with DCO_DEBUG
             * level only to avoid polluting the standard DCO level with this
             * harmless event.
             */
            msglevel = D_DCO_DEBUG;
        }
        msg(msglevel, "Received DCO message for unknown peer-id: %d, "
            "type %d, del_peer_reason %d", peer_id, dco->dco_message_type,
            dco->dco_del_peer_reason);
    }

    dco->dco_message_type = 0;
    dco->dco_message_peer_id = -1;
    dco->dco_del_peer_reason = -1;
    dco->dco_read_bytes = 0;
    dco->dco_write_bytes = 0;
    return ret > 0;
}
#endif /* if defined(ENABLE_DCO) && defined(TARGET_LINUX) */

/*
 * Process packets in the TCP/UDP socket -> TUN/TAP interface direction,
 * i.e. client -> server direction.
 */
bool
multi_process_incoming_link(struct multi_context *m, struct multi_instance *instance, const unsigned int mpp_flags)
{
    struct gc_arena gc = gc_new();

    struct context *c;
    struct mroute_addr src, dest;
    unsigned int mroute_flags;
    struct multi_instance *mi;
    bool ret = true;
    bool floated = false;

    if (m->pending)
    {
        return true;
    }

    if (!instance)
    {
#ifdef MULTI_DEBUG_EVENT_LOOP
        printf("TCP/UDP -> TUN [%d]\n", BLEN(&m->top.c2.buf));
#endif
        multi_set_pending(m, multi_get_create_instance_udp(m, &floated));
    }
    else
    {
        multi_set_pending(m, instance);
    }

    if (m->pending)
    {
        set_prefix(m->pending);

        /* get instance context */
        c = &m->pending->context;

        if (!instance)
        {
            /* transfer packet pointer from top-level context buffer to instance */
            c->c2.buf = m->top.c2.buf;

            /* transfer from-addr from top-level context buffer to instance */
            if (!floated)
            {
                c->c2.from = m->top.c2.from;
            }
        }

        if (BLEN(&c->c2.buf) > 0)
        {
            struct link_socket_info *lsi;
            const uint8_t *orig_buf;

            /* decrypt in instance context */

            perf_push(PERF_PROC_IN_LINK);
            lsi = get_link_socket_info(c);
            orig_buf = c->c2.buf.data;
            if (process_incoming_link_part1(c, lsi, floated))
            {
                /* nonzero length means that we have a valid, decrypted packed */
                if (floated && c->c2.buf.len > 0)
                {
                    multi_process_float(m, m->pending);
                }

                process_incoming_link_part2(c, lsi, orig_buf);
            }
            perf_pop();

            if (TUNNEL_TYPE(m->top.c1.tuntap) == DEV_TYPE_TUN)
            {
                /* extract packet source and dest addresses */
                mroute_flags = mroute_extract_addr_from_packet(&src,
                                                               &dest,
                                                               0,
                                                               &c->c2.to_tun,
                                                               DEV_TYPE_TUN);

                /* drop packet if extract failed */
                if (!(mroute_flags & MROUTE_EXTRACT_SUCCEEDED))
                {
                    c->c2.to_tun.len = 0;
                }
                /* make sure that source address is associated with this client */
                else if (multi_get_instance_by_virtual_addr(m, &src, true) != m->pending)
                {
                    /* IPv6 link-local address (fe80::xxx)? */
                    if ( (src.type & MR_ADDR_MASK) == MR_ADDR_IPV6
                         && IN6_IS_ADDR_LINKLOCAL(&src.v6.addr) )
                    {
                        /* do nothing, for now.  TODO: add address learning */
                    }
                    else
                    {
                        msg(D_MULTI_DROPPED, "MULTI: bad source address from client [%s], packet dropped",
                            mroute_addr_print(&src, &gc));
                    }
                    c->c2.to_tun.len = 0;
                }
                /* client-to-client communication enabled? */
                else if (m->enable_c2c)
                {
                    /* multicast? */
                    if (mroute_flags & MROUTE_EXTRACT_MCAST)
                    {
                        /* for now, treat multicast as broadcast */
                        multi_bcast(m, &c->c2.to_tun, m->pending, NULL, 0);
                    }
                    else /* possible client to client routing */
                    {
                        ASSERT(!(mroute_flags & MROUTE_EXTRACT_BCAST));
                        mi = multi_get_instance_by_virtual_addr(m, &dest, true);

                        /* if dest addr is a known client, route to it */
                        if (mi)
                        {
                            {
                                multi_unicast(m, &c->c2.to_tun, mi);
                                register_activity(c, BLEN(&c->c2.to_tun));
                            }
                            c->c2.to_tun.len = 0;
                        }
                    }
                }
            }
            else if (TUNNEL_TYPE(m->top.c1.tuntap) == DEV_TYPE_TAP)
            {
                uint16_t vid = 0;

                if (m->top.options.vlan_tagging)
                {
                    if (vlan_is_tagged(&c->c2.to_tun))
                    {
                        /* Drop VLAN-tagged frame. */
                        msg(D_VLAN_DEBUG, "dropping incoming VLAN-tagged frame");
                        c->c2.to_tun.len = 0;
                    }
                    else
                    {
                        vid = c->options.vlan_pvid;
                    }
                }
                /* extract packet source and dest addresses */
                mroute_flags = mroute_extract_addr_from_packet(&src,
                                                               &dest,
                                                               vid,
                                                               &c->c2.to_tun,
                                                               DEV_TYPE_TAP);

                if (mroute_flags & MROUTE_EXTRACT_SUCCEEDED)
                {
                    if (multi_learn_addr(m, m->pending, &src, 0) == m->pending)
                    {
                        /* check for broadcast */
                        if (m->enable_c2c)
                        {
                            if (mroute_flags & (MROUTE_EXTRACT_BCAST|MROUTE_EXTRACT_MCAST))
                            {
                                multi_bcast(m, &c->c2.to_tun, m->pending, NULL,
                                            vid);
                            }
                            else /* try client-to-client routing */
                            {
                                mi = multi_get_instance_by_virtual_addr(m, &dest, false);

                                /* if dest addr is a known client, route to it */
                                if (mi)
                                {
                                    multi_unicast(m, &c->c2.to_tun, mi);
                                    register_activity(c, BLEN(&c->c2.to_tun));
                                    c->c2.to_tun.len = 0;
                                }
                            }
                        }
                    }
                    else
                    {
                        msg(D_MULTI_DROPPED, "MULTI: bad source address from client [%s], packet dropped",
                            mroute_addr_print(&src, &gc));
                        c->c2.to_tun.len = 0;
                    }
                }
                else
                {
                    c->c2.to_tun.len = 0;
                }
            }
        }

        /* postprocess and set wakeup */
        ret = multi_process_post(m, m->pending, mpp_flags);

        clear_prefix();
    }

    gc_free(&gc);
    return ret;
}

/*
 * Process packets in the TUN/TAP interface -> TCP/UDP socket direction,
 * i.e. server -> client direction.
 */
bool
multi_process_incoming_tun(struct multi_context *m, const unsigned int mpp_flags)
{
    bool ret = true;

    if (BLEN(&m->top.c2.buf) > 0)
    {
        unsigned int mroute_flags;
        struct mroute_addr src, dest;
        const int dev_type = TUNNEL_TYPE(m->top.c1.tuntap);
        int16_t vid = 0;


#ifdef MULTI_DEBUG_EVENT_LOOP
        printf("TUN -> TCP/UDP [%d]\n", BLEN(&m->top.c2.buf));
#endif

        if (m->pending)
        {
            return true;
        }

        if (dev_type == DEV_TYPE_TAP && m->top.options.vlan_tagging)
        {
            vid = vlan_decapsulate(&m->top, &m->top.c2.buf);
            if (vid < 0)
            {
                return false;
            }
        }

        /*
         * Route an incoming tun/tap packet to
         * the appropriate multi_instance object.
         */

        mroute_flags = mroute_extract_addr_from_packet(&src,
                                                       &dest,
                                                       vid,
                                                       &m->top.c2.buf,
                                                       dev_type);

        if (mroute_flags & MROUTE_EXTRACT_SUCCEEDED)
        {
            struct context *c;

            /* broadcast or multicast dest addr? */
            if (mroute_flags & (MROUTE_EXTRACT_BCAST|MROUTE_EXTRACT_MCAST))
            {
                /* for now, treat multicast as broadcast */
                multi_bcast(m, &m->top.c2.buf, NULL, NULL, vid);
            }
            else
            {
                multi_set_pending(m, multi_get_instance_by_virtual_addr(m, &dest, dev_type == DEV_TYPE_TUN));

                if (m->pending)
                {
                    /* get instance context */
                    c = &m->pending->context;

                    set_prefix(m->pending);

                    {
                        if (multi_output_queue_ready(m, m->pending))
                        {
                            /* transfer packet pointer from top-level context buffer to instance */
                            c->c2.buf = m->top.c2.buf;
                        }
                        else
                        {
                            /* drop packet */
                            msg(D_MULTI_DROPPED, "MULTI: packet dropped due to output saturation (multi_process_incoming_tun)");
                            buf_reset_len(&c->c2.buf);
                        }
                    }

                    /* encrypt in instance context */
                    process_incoming_tun(c);

                    /* postprocess and set wakeup */
                    ret = multi_process_post(m, m->pending, mpp_flags);

                    clear_prefix();
                }
            }
        }
    }
    return ret;
}

/*
 * Process a possible client-to-client/bcast/mcast message in the
 * queue.
 */
struct multi_instance *
multi_get_queue(struct mbuf_set *ms)
{
    struct mbuf_item item;

    if (mbuf_extract_item(ms, &item)) /* cleartext IP packet */
    {
        unsigned int pip_flags = PIPV4_PASSTOS | PIPV6_IMCP_NOHOST_SERVER;

        set_prefix(item.instance);
        item.instance->context.c2.buf = item.buffer->buf;
        if (item.buffer->flags & MF_UNICAST) /* --mssfix doesn't make sense for broadcast or multicast */
        {
            pip_flags |= PIP_MSSFIX;
        }
        process_ip_header(&item.instance->context, pip_flags, &item.instance->context.c2.buf);
        encrypt_sign(&item.instance->context, true);
        mbuf_free_buf(item.buffer);

        dmsg(D_MULTI_DEBUG, "MULTI: C2C/MCAST/BCAST");

        clear_prefix();
        return item.instance;
    }
    else
    {
        return NULL;
    }
}

/*
 * Called when an I/O wait times out.  Usually means that a particular
 * client instance object needs timer-based service.
 */
bool
multi_process_timeout(struct multi_context *m, const unsigned int mpp_flags)
{
    bool ret = true;

#ifdef MULTI_DEBUG_EVENT_LOOP
    printf("%s -> TIMEOUT\n", id(m->earliest_wakeup));
#endif

    /* instance marked for wakeup? */
    if (m->earliest_wakeup)
    {
        if (m->earliest_wakeup == (struct multi_instance *)&m->deferred_shutdown_signal)
        {
            schedule_remove_entry(m->schedule, (struct schedule_entry *) &m->deferred_shutdown_signal);
            throw_signal(m->deferred_shutdown_signal.signal_received);
        }
        else
        {
            set_prefix(m->earliest_wakeup);
            ret = multi_process_post(m, m->earliest_wakeup, mpp_flags);
            clear_prefix();
        }
        m->earliest_wakeup = NULL;
    }
    return ret;
}

/*
 * Drop a TUN/TAP outgoing packet..
 */
void
multi_process_drop_outgoing_tun(struct multi_context *m, const unsigned int mpp_flags)
{
    struct multi_instance *mi = m->pending;

    ASSERT(mi);

    set_prefix(mi);

    msg(D_MULTI_ERRORS, "MULTI: Outgoing TUN queue full, dropped packet len=%d",
        mi->context.c2.to_tun.len);

    buf_reset(&mi->context.c2.to_tun);

    multi_process_post(m, mi, mpp_flags);
    clear_prefix();
}

/*
 * Per-client route quota management
 */

void
route_quota_exceeded(const struct multi_instance *mi)
{
    struct gc_arena gc = gc_new();
    msg(D_ROUTE_QUOTA, "MULTI ROUTE: route quota (%d) exceeded for %s (see --max-routes-per-client option)",
        mi->context.options.max_routes_per_client,
        multi_instance_string(mi, false, &gc));
    gc_free(&gc);
}

#ifdef ENABLE_DEBUG
/*
 * Flood clients with random packets
 */
static void
gremlin_flood_clients(struct multi_context *m)
{
    const int level = GREMLIN_PACKET_FLOOD_LEVEL(m->top.options.gremlin);
    if (level)
    {
        struct gc_arena gc = gc_new();
        struct buffer buf = alloc_buf_gc(BUF_SIZE(&m->top.c2.frame), &gc);
        struct packet_flood_parms parm = get_packet_flood_parms(level);
        int i;

        ASSERT(buf_init(&buf, m->top.c2.frame.buf.headroom));
        parm.packet_size = min_int(parm.packet_size, m->top.c2.frame.buf.payload_size);

        msg(D_GREMLIN, "GREMLIN_FLOOD_CLIENTS: flooding clients with %d packets of size %d",
            parm.n_packets,
            parm.packet_size);

        for (i = 0; i < parm.packet_size; ++i)
        {
            ASSERT(buf_write_u8(&buf, get_random() & 0xFF));
        }

        for (i = 0; i < parm.n_packets; ++i)
        {
            multi_bcast(m, &buf, NULL, NULL, 0);
        }

        gc_free(&gc);
    }
}
#endif /* ifdef ENABLE_DEBUG */

static bool
stale_route_check_trigger(struct multi_context *m)
{
    struct timeval null;
    CLEAR(null);
    return event_timeout_trigger(&m->stale_routes_check_et, &null, ETT_DEFAULT);
}

/*
 * Process timers in the top-level context
 */
void
multi_process_per_second_timers_dowork(struct multi_context *m)
{
    /* possibly reap instances/routes in vhash */
    multi_reap_process(m);

    /* possibly print to status log */
    if (m->top.c1.status_output)
    {
        if (status_trigger(m->top.c1.status_output))
        {
            multi_print_status(m, m->top.c1.status_output, m->status_file_version);
        }
    }

    /* possibly flush ifconfig-pool file */
    multi_ifconfig_pool_persist(m, false);

#ifdef ENABLE_DEBUG
    gremlin_flood_clients(m);
#endif

    /* Should we check for stale routes? */
    if (m->top.options.stale_routes_check_interval && stale_route_check_trigger(m))
    {
        check_stale_routes(m);
    }
}

void
multi_top_init(struct multi_context *m, struct context *top)
{
    inherit_context_top(&m->top, top);
    m->top.c2.buffers = init_context_buffers(&top->c2.frame);
}

void
multi_top_free(struct multi_context *m)
{
    close_context(&m->top, -1, CC_GC_FREE);
    free_context_buffers(m->top.c2.buffers);
}

static bool
is_exit_restart(int sig)
{
    return (sig == SIGUSR1 || sig == SIGTERM || sig == SIGHUP || sig == SIGINT);
}

static void
multi_push_restart_schedule_exit(struct multi_context *m, bool next_server)
{
    struct hash_iterator hi;
    struct hash_element *he;
    struct timeval tv;

    /* tell all clients to restart */
    hash_iterator_init(m->iter, &hi);
    while ((he = hash_iterator_next(&hi)))
    {
        struct multi_instance *mi = (struct multi_instance *) he->value;
        if (!mi->halt)
        {
            send_control_channel_string(&mi->context, next_server ? "RESTART,[N]" : "RESTART", D_PUSH);
            multi_schedule_context_wakeup(m, mi);
        }
    }
    hash_iterator_free(&hi);

    /* reschedule signal */
    ASSERT(!openvpn_gettimeofday(&m->deferred_shutdown_signal.wakeup, NULL));
    tv.tv_sec = 2;
    tv.tv_usec = 0;
    tv_add(&m->deferred_shutdown_signal.wakeup, &tv);

    m->deferred_shutdown_signal.signal_received = m->top.sig->signal_received;

    schedule_add_entry(m->schedule,
                       (struct schedule_entry *) &m->deferred_shutdown_signal,
                       &m->deferred_shutdown_signal.wakeup,
                       compute_wakeup_sigma(&m->deferred_shutdown_signal.wakeup));

    signal_reset(m->top.sig);
}

/*
 * Return true if event loop should break,
 * false if it should continue.
 */
bool
multi_process_signal(struct multi_context *m)
{
    if (m->top.sig->signal_received == SIGUSR2)
    {
        struct status_output *so = status_open(NULL, 0, M_INFO, NULL, 0);
        multi_print_status(m, so, m->status_file_version);
        status_close(so);
        signal_reset(m->top.sig);
        return false;
    }
    else if (proto_is_dgram(m->top.options.ce.proto)
             && is_exit_restart(m->top.sig->signal_received)
             && (m->deferred_shutdown_signal.signal_received == 0)
             && m->top.options.ce.explicit_exit_notification != 0)
    {
        multi_push_restart_schedule_exit(m, m->top.options.ce.explicit_exit_notification == 2);
        return false;
    }
    return true;
}

/*
 * Management subsystem callbacks
 */
#ifdef ENABLE_MANAGEMENT

static void
management_callback_status(void *arg, const int version, struct status_output *so)
{
    struct multi_context *m = (struct multi_context *) arg;

    if (!version)
    {
        multi_print_status(m, so, m->status_file_version);
    }
    else
    {
        multi_print_status(m, so, version);
    }
}

static int
management_callback_n_clients(void *arg)
{
    struct multi_context *m = (struct multi_context *) arg;
    return m->n_clients;
}

static int
management_callback_kill_by_cn(void *arg, const char *del_cn)
{
    struct multi_context *m = (struct multi_context *) arg;
    struct hash_iterator hi;
    struct hash_element *he;
    int count = 0;

    hash_iterator_init(m->iter, &hi);
    while ((he = hash_iterator_next(&hi)))
    {
        struct multi_instance *mi = (struct multi_instance *) he->value;
        if (!mi->halt)
        {
            const char *cn = tls_common_name(mi->context.c2.tls_multi, false);
            if (cn && !strcmp(cn, del_cn))
            {
                multi_signal_instance(m, mi, SIGTERM);
                ++count;
            }
        }
    }
    hash_iterator_free(&hi);
    return count;
}

static int
management_callback_kill_by_addr(void *arg, const in_addr_t addr, const int port)
{
    struct multi_context *m = (struct multi_context *) arg;
    struct hash_iterator hi;
    struct hash_element *he;
    struct openvpn_sockaddr saddr;
    struct mroute_addr maddr;
    int count = 0;

    CLEAR(saddr);
    saddr.addr.in4.sin_family = AF_INET;
    saddr.addr.in4.sin_addr.s_addr = htonl(addr);
    saddr.addr.in4.sin_port = htons(port);
    if (mroute_extract_openvpn_sockaddr(&maddr, &saddr, true))
    {
        hash_iterator_init(m->iter, &hi);
        while ((he = hash_iterator_next(&hi)))
        {
            struct multi_instance *mi = (struct multi_instance *) he->value;
            if (!mi->halt && mroute_addr_equal(&maddr, &mi->real))
            {
                multi_signal_instance(m, mi, SIGTERM);
                ++count;
            }
        }
        hash_iterator_free(&hi);
    }
    return count;
}

static void
management_delete_event(void *arg, event_t event)
{
    struct multi_context *m = (struct multi_context *) arg;
    if (m->mtcp)
    {
        multi_tcp_delete_event(m->mtcp, event);
    }
}

static struct multi_instance *
lookup_by_cid(struct multi_context *m, const unsigned long cid)
{
    if (m)
    {
        struct multi_instance *mi = (struct multi_instance *) hash_lookup(m->cid_hash, &cid);
        if (mi && !mi->halt)
        {
            return mi;
        }
    }
    return NULL;
}

static bool
management_kill_by_cid(void *arg, const unsigned long cid, const char *kill_msg)
{
    struct multi_context *m = (struct multi_context *) arg;
    struct multi_instance *mi = lookup_by_cid(m, cid);
    if (mi)
    {
        send_restart(&mi->context, kill_msg); /* was: multi_signal_instance (m, mi, SIGTERM); */
        multi_schedule_context_wakeup(m, mi);
        return true;
    }
    else
    {
        return false;
    }
}

static bool
management_client_pending_auth(void *arg,
                               const unsigned long cid,
                               const unsigned int mda_key_id,
                               const char *extra,
                               unsigned int timeout)
{
    struct multi_context *m = (struct multi_context *) arg;
    struct multi_instance *mi = lookup_by_cid(m, cid);

    if (mi)
    {
        struct tls_multi *multi = mi->context.c2.tls_multi;
        struct tls_session *session;

        if (multi->session[TM_INITIAL].key[KS_PRIMARY].mda_key_id == mda_key_id)
        {
            session = &multi->session[TM_INITIAL];
        }
        else if (multi->session[TM_ACTIVE].key[KS_PRIMARY].mda_key_id == mda_key_id)
        {
            session = &multi->session[TM_ACTIVE];
        }
        else
        {
            return false;
        }

        /* sends INFO_PRE and AUTH_PENDING messages to client */
        bool ret = send_auth_pending_messages(multi, session, extra,
                                              timeout);
        reschedule_multi_process(&mi->context);
        multi_schedule_context_wakeup(m, mi);
        return ret;
    }
    return false;
}


static bool
management_client_auth(void *arg,
                       const unsigned long cid,
                       const unsigned int mda_key_id,
                       const bool auth,
                       const char *reason,
                       const char *client_reason,
                       struct buffer_list *cc_config)  /* ownership transferred */
{
    struct multi_context *m = (struct multi_context *) arg;
    struct multi_instance *mi = lookup_by_cid(m, cid);
    bool cc_config_owned = true;
    bool ret = false;

    if (mi)
    {
        ret = tls_authenticate_key(mi->context.c2.tls_multi, mda_key_id, auth, client_reason);
        if (ret)
        {
            if (auth)
            {
                if (mi->context.c2.tls_multi->multi_state <= CAS_WAITING_AUTH)
                {
                    set_cc_config(mi, cc_config);
                    cc_config_owned = false;
                }
            }
            else if (reason)
            {
                msg(D_MULTI_LOW, "MULTI: connection rejected: %s, CLI:%s", reason, np(client_reason));
            }
        }
    }
    if (cc_config_owned && cc_config)
    {
        buffer_list_free(cc_config);
    }
    return ret;
}

static char *
management_get_peer_info(void *arg, const unsigned long cid)
{
    struct multi_context *m = (struct multi_context *) arg;
    struct multi_instance *mi = lookup_by_cid(m, cid);
    char *ret = NULL;

    if (mi)
    {
        ret = mi->context.c2.tls_multi->peer_info;
    }

    return ret;
}

#endif /* ifdef ENABLE_MANAGEMENT */


void
init_management_callback_multi(struct multi_context *m)
{
#ifdef ENABLE_MANAGEMENT
    if (management)
    {
        struct management_callback cb;
        CLEAR(cb);
        cb.arg = m;
        cb.flags = MCF_SERVER;
        cb.status = management_callback_status;
        cb.show_net = management_show_net_callback;
        cb.kill_by_cn = management_callback_kill_by_cn;
        cb.kill_by_addr = management_callback_kill_by_addr;
        cb.delete_event = management_delete_event;
        cb.n_clients = management_callback_n_clients;
        cb.kill_by_cid = management_kill_by_cid;
        cb.client_auth = management_client_auth;
        cb.client_pending_auth = management_client_pending_auth;
        cb.get_peer_info = management_get_peer_info;
        management_set_callback(management, &cb);
    }
#endif /* ifdef ENABLE_MANAGEMENT */
}

void
multi_assign_peer_id(struct multi_context *m, struct multi_instance *mi)
{
    /* max_clients must be less then max peer-id value */
    ASSERT(m->max_clients < MAX_PEER_ID);

    for (int i = 0; i < m->max_clients; ++i)
    {
        if (!m->instances[i])
        {
            mi->context.c2.tls_multi->peer_id = i;
            m->instances[i] = mi;
            break;
        }
    }

    /* should not really end up here, since multi_create_instance returns null
     * if amount of clients exceeds max_clients */
    ASSERT(mi->context.c2.tls_multi->peer_id < m->max_clients);
}


/*
 * Top level event loop.
 */
void
tunnel_server(struct context *top)
{
    ASSERT(top->options.mode == MODE_SERVER);

    if (proto_is_dgram(top->options.ce.proto))
    {
        tunnel_server_udp(top);
    }
    else
    {
        tunnel_server_tcp(top);
    }
}
