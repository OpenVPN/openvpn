/*
 *  OpenVPN -- An application to securely tunnel IP networks
 *             over a single UDP port, with support for SSL/TLS-based
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

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "syshead.h"

#include "buffer.h"
#include "crypto.h"
#include "error.h"
#include "mtu.h"
#include "options.h"
#include "socket_util.h"
#include "ssl.h"
#include "ssl_ncp.h"
#include "tun.h"

#include <string.h>

char *
options_string(const struct options *o, const struct frame *frame, struct tuntap *tt,
               openvpn_net_ctx_t *ctx, bool remote, struct gc_arena *gc)
{
    struct buffer out = alloc_buf(OPTION_LINE_SIZE);
    bool tt_local = false;

    buf_printf(&out, "V4");

    /*
     * Tunnel Options
     */

    buf_printf(&out, ",dev-type %s", dev_type_string(o->dev, o->dev_type));
    /* the link-mtu that we send has only a meaning if have a fixed
     * cipher (p2p) or have a fallback cipher configured for older non
     * ncp clients. But not sending it will make even 2.4 complain
     * about it being missing. So still send it. */
    buf_printf(&out, ",link-mtu %u", (unsigned int)calc_options_string_link_mtu(o, frame));

    if (o->ce.occ_mtu != 0)
    {
        buf_printf(&out, ",tun-mtu %d", o->ce.occ_mtu);
    }
    else
    {
        buf_printf(&out, ",tun-mtu %d", frame->tun_mtu);
    }

    buf_printf(&out, ",proto %s", proto_remote(o->ce.proto, remote));

    bool p2p_nopull = o->mode == MODE_POINT_TO_POINT && !PULL_DEFINED(o);
    /* send tun_ipv6 only in peer2peer mode - in client/server mode, it
     * is usually pushed by the server, triggering a non-helpful warning
     */
    if (o->ifconfig_ipv6_local && p2p_nopull)
    {
        buf_printf(&out, ",tun-ipv6");
    }

    /*
     * Try to get ifconfig parameters into the options string.
     * If tt is undefined, make a temporary instantiation.
     */
    if (!tt)
    {
        tt = init_tun(o->dev, o->dev_type, o->topology, o->ifconfig_local,
                      o->ifconfig_remote_netmask, o->ifconfig_ipv6_local, o->ifconfig_ipv6_netbits,
                      o->ifconfig_ipv6_remote, NULL, NULL, false, NULL, ctx, NULL);
        if (tt)
        {
            tt_local = true;
        }
    }

    if (tt && p2p_nopull)
    {
        const char *ios = ifconfig_options_string(tt, remote, o->ifconfig_nowarn, gc);
        if (ios && strlen(ios))
        {
            buf_printf(&out, ",ifconfig %s", ios);
        }
    }
    if (tt_local)
    {
        free(tt);
        tt = NULL;
    }

#ifdef USE_COMP
    if (o->comp.alg != COMP_ALG_UNDEF)
    {
        /* for compatibility, this simply indicates that compression
         * context is active, not necessarily LZO per-se */
        buf_printf(&out, ",comp-lzo");
    }
#endif

#ifdef ENABLE_FRAGMENT
    if (o->ce.fragment)
    {
        buf_printf(&out, ",mtu-dynamic");
    }
#endif

#define TLS_CLIENT (o->tls_client)
#define TLS_SERVER (o->tls_server)

    /*
     * Key direction
     */
    {
        const char *kd = keydirection2ascii(o->key_direction, remote, false);
        if (kd)
        {
            buf_printf(&out, ",keydir %s", kd);
        }
    }

    /*
     * Crypto Options
     */
    if (o->shared_secret_file || TLS_CLIENT || TLS_SERVER)
    {
        struct key_type kt;

        ASSERT((o->shared_secret_file != NULL) + (TLS_CLIENT == true) + (TLS_SERVER == true) <= 1);

        /* Skip resolving BF-CBC to allow SSL libraries without BF-CBC
         * to work here in the default configuration */
        const char *ciphername = o->ciphername;
        size_t keysize = 0;

        if (strcmp(o->ciphername, "BF-CBC") == 0)
        {
            init_key_type(&kt, "none", o->authname, true, false);
            keysize = 128;
        }
        else
        {
            init_key_type(&kt, o->ciphername, o->authname, true, false);
            ciphername = cipher_kt_name(kt.cipher);
            if (cipher_defined(o->ciphername))
            {
                keysize = cipher_kt_key_size(kt.cipher) * 8;
            }
        }
        /* Only announce the cipher to our peer if we are willing to
         * support it */
        if (p2p_nopull || tls_item_in_cipher_list(ciphername, o->ncp_ciphers))
        {
            buf_printf(&out, ",cipher %s", ciphername);
        }
        buf_printf(&out, ",auth %s", md_kt_name(kt.digest));
        buf_printf(&out, ",keysize %zu", keysize);
        if (o->shared_secret_file)
        {
            buf_printf(&out, ",secret");
        }
    }

    /*
     * SSL Options
     */
    {
        if (TLS_CLIENT || TLS_SERVER)
        {
            if (o->ce.tls_auth_file)
            {
                buf_printf(&out, ",tls-auth");
            }
            /* Not adding tls-crypt here, because we won't reach this code if
             * tls-auth/tls-crypt does not match.  Removing tls-auth here would
             * break stuff, so leaving that in place. */

            buf_printf(&out, ",key-method %d", KEY_METHOD_2);
        }

        if (remote)
        {
            if (TLS_CLIENT)
            {
                buf_printf(&out, ",tls-server");
            }
            else if (TLS_SERVER)
            {
                buf_printf(&out, ",tls-client");
            }
        }
        else
        {
            if (TLS_CLIENT)
            {
                buf_printf(&out, ",tls-client");
            }
            else if (TLS_SERVER)
            {
                buf_printf(&out, ",tls-server");
            }
        }
    }

#undef TLS_CLIENT
#undef TLS_SERVER

    return BSTR(&out);
}

/**
 * Compare option strings for equality.
 *
 * If the first two chars of the strings differ, it means that
 * we are looking at different versions of the options string,
 * therefore don't compare them and return true.
 */
static const char *
options_warning_extract_parm1(const char *option_string, struct gc_arena *gc_ret)
{
    struct gc_arena gc = gc_new();
    struct buffer b = string_alloc_buf(option_string, &gc);
    char *p = gc_malloc(OPTION_PARM_SIZE, false, &gc);
    const char *ret;

    buf_parse(&b, ' ', p, OPTION_PARM_SIZE);
    ret = string_alloc(p, gc_ret);
    gc_free(&gc);
    return ret;
}

static void
options_warning_safe_scan2(const msglvl_t msglevel, const int delim,
                           const bool report_inconsistent, const char *p1,
                           const struct buffer *b2_src, const char *b1_name,
                           const char *b2_name)
{
    /* We will stop sending 'key-method', 'keydir', 'proto' and 'tls-auth' in
     * OCC in a future version (because it's not useful). To reduce questions
     * when interoperating, we no longer printing a warning about it.
     */
    if (strprefix(p1, "key-method ") || strprefix(p1, "keydir ") || strprefix(p1, "proto ")
        || streq(p1, "tls-auth") || strprefix(p1, "tun-ipv6") || strprefix(p1, "cipher "))
    {
        return;
    }

    if (strlen(p1) > 0)
    {
        struct gc_arena gc = gc_new();
        struct buffer b2 = *b2_src;
        const char *p1_prefix = options_warning_extract_parm1(p1, &gc);
        char *p2 = gc_malloc(OPTION_PARM_SIZE, false, &gc);

        while (buf_parse(&b2, delim, p2, OPTION_PARM_SIZE))
        {
            if (strlen(p2))
            {
                const char *p2_prefix = options_warning_extract_parm1(p2, &gc);

                if (!strcmp(p1, p2))
                {
                    goto done;
                }
                if (!strcmp(p1_prefix, p2_prefix))
                {
                    if (report_inconsistent)
                    {
                        msg(msglevel, "WARNING: '%s' is used inconsistently, %s='%s', %s='%s'",
                            safe_print(p1_prefix, &gc), b1_name, safe_print(p1, &gc), b2_name,
                            safe_print(p2, &gc));
                    }
                    goto done;
                }
            }
        }

        msg(msglevel, "WARNING: '%s' is present in %s config but missing in %s config, %s='%s'",
            safe_print(p1_prefix, &gc), b1_name, b2_name, b1_name, safe_print(p1, &gc));

done:
        gc_free(&gc);
    }
}

static void
options_warning_safe_scan1(const msglvl_t msglevel, const int delim,
                           const bool report_inconsistent, const struct buffer *b1_src,
                           const struct buffer *b2_src, const char *b1_name, const char *b2_name)
{
    struct gc_arena gc = gc_new();
    struct buffer b = *b1_src;
    char *p = gc_malloc(OPTION_PARM_SIZE, true, &gc);

    while (buf_parse(&b, delim, p, OPTION_PARM_SIZE))
    {
        options_warning_safe_scan2(msglevel, delim, report_inconsistent, p, b2_src, b1_name,
                                   b2_name);
    }

    gc_free(&gc);
}

static void
options_warning_safe_ml(const msglvl_t msglevel, char *actual, const char *expected, size_t actual_n)
{
    struct gc_arena gc = gc_new();

    if (actual_n > 0)
    {
        struct buffer local = alloc_buf_gc(OPTION_PARM_SIZE + 16, &gc);
        struct buffer remote = alloc_buf_gc(OPTION_PARM_SIZE + 16, &gc);
        actual[actual_n - 1] = 0;

        buf_printf(&local, "version %s", expected);
        buf_printf(&remote, "version %s", actual);

        options_warning_safe_scan1(msglevel, ',', true, &local, &remote, "local", "remote");

        options_warning_safe_scan1(msglevel, ',', false, &remote, &local, "remote", "local");
    }

    gc_free(&gc);
}

bool
options_cmp_equal_safe(char *actual, const char *expected, size_t actual_n)
{
    struct gc_arena gc = gc_new();
    bool ret = true;

    if (actual_n > 0)
    {
        actual[actual_n - 1] = 0;
        if (strncmp(actual, expected, 2))
        {
            msg(D_SHOW_OCC, "NOTE: Options consistency check may be skewed by version differences");
            options_warning_safe_ml(D_SHOW_OCC, actual, expected, actual_n);
        }
        else
        {
            ret = !strcmp(actual, expected);
        }
    }
    gc_free(&gc);
    return ret;
}

bool
options_cmp_equal(char *actual, const char *expected)
{
    return options_cmp_equal_safe(actual, expected, strlen(actual) + 1);
}

void
options_warning_safe(char *actual, const char *expected, size_t actual_n)
{
    options_warning_safe_ml(D_SHOW_OCC, actual, expected, actual_n);
}

void
options_warning(char *actual, const char *expected)
{
    options_warning_safe(actual, expected, strlen(actual) + 1);
}

const char *
options_string_version(const char *s, struct gc_arena *gc)
{
    struct buffer out = alloc_buf_gc(4, gc);
    strncpynt((char *)BPTR(&out), s, 3);
    return BSTR(&out);
}

#if defined(__GNUC__) || defined(__clang__)
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wsign-compare"
#endif

char *
options_string_extract_option(const char *options_string, const char *opt_name, struct gc_arena *gc)
{
    char *ret = NULL;
    const size_t opt_name_len = strlen(opt_name);

    const char *p = options_string;
    while (p)
    {
        if (0 == strncmp(p, opt_name, opt_name_len) && strlen(p) > (opt_name_len + 1)
            && p[opt_name_len] == ' ')
        {
            /* option found, extract value */
            const char *start = &p[opt_name_len + 1];
            const char *end = strchr(p, ',');
            size_t val_len = end ? end - start : strlen(start);
            ret = gc_malloc(val_len + 1, true, gc);
            memcpy(ret, start, val_len);
            break;
        }
        p = strchr(p, ',');
        if (p)
        {
            p++; /* skip delimiter */
        }
    }
    return ret;
}

#if defined(__GNUC__) || defined(__clang__)
#pragma GCC diagnostic pop
#endif
