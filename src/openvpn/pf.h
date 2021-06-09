/*
 *  OpenVPN -- An application to securely tunnel IP networks
 *             over a single TCP/UDP port, with support for SSL/TLS-based
 *             session authentication and key exchange,
 *             packet encryption, packet authentication, and
 *             packet compression.
 *
 *  Copyright (C) 2002-2021 OpenVPN Inc <sales@openvpn.net>
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

/* packet filter functions */

#if defined(ENABLE_PF) && !defined(OPENVPN_PF_H)
#define OPENVPN_PF_H

#include "list.h"
#include "mroute.h"

#define PF_MAX_LINE_LEN 256

#define PCT_SRC  1
#define PCT_DEST 2

struct context;

struct ipv4_subnet {
    bool exclude;
    in_addr_t network;
    in_addr_t netmask;
};

struct pf_subnet {
    struct pf_subnet *next;
    struct ipv4_subnet rule;
};

struct pf_subnet_set {
    bool default_allow;
    struct pf_subnet *list;
};

struct pf_cn {
    bool exclude;
    char *cn;
};

struct pf_cn_elem {
    struct pf_cn_elem *next;
    struct pf_cn rule;
};

struct pf_cn_set {
    bool default_allow;
    struct pf_cn_elem *list;
    struct hash *hash_table;
};

struct pf_set {
    bool kill;
    struct pf_subnet_set sns;
    struct pf_cn_set cns;
};

struct pf_context {
    bool enabled;
    struct pf_set *pfs;
#ifdef PLUGIN_PF
    const char *filename;
    time_t file_last_mod;
    unsigned int n_check_reload;
    struct event_timeout reload;
#endif
};

void pf_init_context(struct context *c);

void pf_destroy_context(struct pf_context *pfc);

#ifdef PLUGIN_PF
void pf_check_reload(struct context *c);

#endif

#ifdef MANAGEMENT_PF
bool pf_load_from_buffer_list(struct context *c, const struct buffer_list *config);

#endif

#ifdef ENABLE_DEBUG
void pf_context_print(const struct pf_context *pfc, const char *prefix, const int lev);

#endif

bool pf_addr_test_dowork(const struct context *src,
                         const struct mroute_addr *dest, const char *prefix);

static inline bool
pf_addr_test(const struct pf_context *src_pf, const struct context *src,
             const struct mroute_addr *dest, const char *prefix)
{
    if (src_pf->enabled)
    {
        return pf_addr_test_dowork(src, dest, prefix);
    }
    else
    {
        return true;
    }
}

/*
 * Inline functions
 */

bool pf_cn_test(struct pf_set *pfs, const struct tls_multi *tm, const int type,
                const char *prefix);

static inline bool
pf_c2c_test(const struct pf_context *src_pf, const struct tls_multi *src,
            const struct pf_context *dest_pf, const struct tls_multi *dest,
            const char *prefix)
{
    return (!src_pf->enabled || pf_cn_test(src_pf->pfs, dest, PCT_DEST, prefix))
           && (!dest_pf->enabled || pf_cn_test(dest_pf->pfs, src, PCT_SRC,
                                               prefix));
}

static inline bool
pf_kill_test(const struct pf_set *pfs)
{
    return pfs->kill;
}

#endif /* if defined(ENABLE_PF) && !defined(OPENVPN_PF_H) */
