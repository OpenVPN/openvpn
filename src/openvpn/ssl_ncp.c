/*
 *  OpenVPN -- An application to securely tunnel IP networks
 *             over a single TCP/UDP port, with support for SSL/TLS-based
 *             session authentication and key exchange,
 *             packet encryption, packet authentication, and
 *             packet compression.
 *
 *  Copyright (C) 2002-2018 OpenVPN Inc <sales@openvpn.net>
 *  Copyright (C) 2010-2018 Fox Crypto B.V. <openvpn@fox-it.com>
 *  Copyright (C) 2008-2013 David Sommerseth <dazo@users.sourceforge.net>
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

/**
 * @file Control Channel SSL/Data dynamic negotion Module
 * This file is split from ssl.c to be able to unit test it.
 */

/*
 * The routines in this file deal with dynamically negotiating
 * the data channel HMAC and cipher keys through a TLS session.
 *
 * Both the TLS session and the data channel are multiplexed
 * over the same TCP/UDP port.
 */
#ifdef HAVE_CONFIG_H
#include "config.h"
#elif defined(_MSC_VER)
#include "config-msvc.h"
#endif

#include "syshead.h"
#include "win32.h"

#include "error.h"
#include "common.h"

#include "ssl_ncp.h"
#include "openvpn.h"

/**
 * Return the Negotiable Crypto Parameters version advertised in the peer info
 * string, or 0 if none specified.
 */
static int
tls_peer_info_ncp_ver(const char *peer_info)
{
    const char *ncpstr = peer_info ? strstr(peer_info, "IV_NCP=") : NULL;
    if (ncpstr)
    {
        int ncp = 0;
        int r = sscanf(ncpstr, "IV_NCP=%d", &ncp);
        if (r == 1)
        {
            return ncp;
        }
    }
    return 0;
}

/**
 * Returns whether the client supports NCP either by
 * announcing IV_NCP>=2 or the IV_CIPHERS list
 */
bool
tls_peer_supports_ncp(const char *peer_info)
{
    if (!peer_info)
    {
        return false;
    }
    else if (tls_peer_info_ncp_ver(peer_info) >= 2
             || strstr(peer_info, "IV_CIPHERS="))
    {
        return true;
    }
    else
    {
        return false;
    }
}

char *
mutate_ncp_cipher_list(const char *list, struct gc_arena *gc)
{
    bool error_found = false;

    struct buffer new_list  = alloc_buf(MAX_NCP_CIPHERS_LENGTH);

    char *const tmp_ciphers = string_alloc(list, NULL);
    const char *token = strtok(tmp_ciphers, ":");
    while (token)
    {
        /*
         * Going through a roundtrip by using cipher_kt_get/cipher_kt_name
         * (and translate_cipher_name_from_openvpn/
         * translate_cipher_name_to_openvpn) also normalises the cipher name,
         * e.g. replacing AeS-128-gCm with AES-128-GCM
         */
        const cipher_kt_t *ktc = cipher_kt_get(token);
        if (strcmp(token, "none") == 0)
        {
            msg(M_WARN, "WARNING: cipher 'none' specified for --data-ciphers. "
                        "This allows negotiation of NO encryption and "
                        "tunnelled data WILL then be transmitted in clear text "
                        "over the network! "
                        "PLEASE DO RECONSIDER THIS SETTING!");
        }
        if (!ktc && strcmp(token, "none") != 0)
        {
            msg(M_WARN, "Unsupported cipher in --data-ciphers: %s", token);
            error_found = true;
        }
        else
        {
            const char *ovpn_cipher_name = cipher_kt_name(ktc);
            if (ktc == NULL)
            {
                /* NULL resolves to [null-cipher] but we need none for
                 * data-ciphers */
                ovpn_cipher_name = "none";
            }

            if (buf_len(&new_list)> 0)
            {
                /* The next if condition ensure there is always space for
                 * a :
                 */
                buf_puts(&new_list, ":");
            }

            /* Ensure buffer has capacity for cipher name + : + \0 */
            if (!(buf_forward_capacity(&new_list) >
                  strlen(ovpn_cipher_name) + 2))
            {
                msg(M_WARN, "Length of --data-ciphers is over the "
                    "limit of 127 chars");
                error_found = true;
            }
            else
            {
                buf_puts(&new_list, ovpn_cipher_name);
            }
        }
        token = strtok(NULL, ":");
    }



    char *ret = NULL;
    if (!error_found && buf_len(&new_list) > 0)
    {
        buf_null_terminate(&new_list);
        ret = string_alloc(buf_str(&new_list), gc);
    }
    free(tmp_ciphers);
    free_buf(&new_list);

    return ret;
}

bool
tls_item_in_cipher_list(const char *item, const char *list)
{
    char *tmp_ciphers = string_alloc(list, NULL);
    char *tmp_ciphers_orig = tmp_ciphers;

    const char *token = strtok(tmp_ciphers, ":");
    while (token)
    {
        if (0 == strcmp(token, item))
        {
            break;
        }
        token = strtok(NULL, ":");
    }
    free(tmp_ciphers_orig);

    return token != NULL;
}

const char *
tls_peer_ncp_list(const char *peer_info, struct gc_arena *gc)
{
    /* Check if the peer sends the IV_CIPHERS list */
    const char *ncp_ciphers_start;
    if (peer_info && (ncp_ciphers_start = strstr(peer_info, "IV_CIPHERS=")))
    {
        ncp_ciphers_start += strlen("IV_CIPHERS=");
        const char *ncp_ciphers_end = strstr(ncp_ciphers_start, "\n");
        if (!ncp_ciphers_end)
        {
            /* IV_CIPHERS is at end of the peer_info list and no '\n'
             * follows */
            ncp_ciphers_end = ncp_ciphers_start + strlen(ncp_ciphers_start);
        }

        char *ncp_ciphers_peer = string_alloc(ncp_ciphers_start, gc);
        /* NULL terminate the copy at the right position */
        ncp_ciphers_peer[ncp_ciphers_end - ncp_ciphers_start] = '\0';
        return ncp_ciphers_peer;

    }
    else if (tls_peer_info_ncp_ver(peer_info)>=2)
    {
        /* If the peer announces IV_NCP=2 then it supports the AES GCM
         * ciphers */
        return "AES-256-GCM:AES-128-GCM";
    }
    else
    {
        return "";
    }
}

char *
ncp_get_best_cipher(const char *server_list, const char *peer_info,
                    const char *remote_cipher, struct gc_arena *gc)
{
    /*
     * The gc of the parameter is tied to the VPN session, create a
     * short lived gc arena that is only valid for the duration of
     * this function
     */

    struct gc_arena gc_tmp = gc_new();

    const char *peer_ncp_list = tls_peer_ncp_list(peer_info, &gc_tmp);

    /* non-NCP client without OCC?  "assume nothing" */
    /* For client doing the newer version of NCP (that send IV_CIPHER)
     * we cannot assume that they will accept remote_cipher */
    if (remote_cipher == NULL ||
        (peer_info && strstr(peer_info, "IV_CIPHERS=")))
    {
        remote_cipher = "";
    }

    char *tmp_ciphers = string_alloc(server_list, &gc_tmp);

    const char *token;
    while ((token = strsep(&tmp_ciphers, ":")))
    {
        if (tls_item_in_cipher_list(token, peer_ncp_list)
            || streq(token, remote_cipher))
        {
            break;
        }
    }

    char *ret = NULL;
    if (token != NULL)
    {
        ret = string_alloc(token, gc);
    }

    gc_free(&gc_tmp);
    return ret;
}

/**
 * "Poor man's NCP": Use peer cipher if it is an allowed (NCP) cipher.
 * Allows non-NCP peers to upgrade their cipher individually.
 *
 * Returns true if we switched to the peer's cipher
 *
 * Make sure to call tls_session_update_crypto_params() after calling this
 * function.
 */
static bool
tls_poor_mans_ncp(struct options *o, const char *remote_ciphername)
{
    if (remote_ciphername
        && tls_item_in_cipher_list(remote_ciphername, o->ncp_ciphers))
    {
        o->ciphername = string_alloc(remote_ciphername, &o->gc);
        msg(D_TLS_DEBUG_LOW, "Using peer cipher '%s'", o->ciphername);
        return true;
    }
    return false;
}

bool
check_pull_client_ncp(struct context *c, const int found)
{
    if (found & OPT_P_NCP)
    {
        msg(D_PUSH, "OPTIONS IMPORT: data channel crypto options modified");
        return true;
    }

    if (!c->options.ncp_enabled)
    {
        return true;
    }
    /* If the server did not push a --cipher, we will switch to the
     * remote cipher if it is in our ncp-ciphers list */
    if(tls_poor_mans_ncp(&c->options, c->c2.tls_multi->remote_ciphername))
    {
        return true;
    }

    /* We could not figure out the peer's cipher but we have fallback
     * enabled */
    if (!c->c2.tls_multi->remote_ciphername && c->options.enable_ncp_fallback)
    {
        return true;
    }

    /* We failed negotiation, give appropiate error message */
    if (c->c2.tls_multi->remote_ciphername)
    {
        msg(D_TLS_ERRORS, "OPTIONS ERROR: failed to negotiate "
            "cipher with server.  Add the server's "
            "cipher ('%s') to --data-ciphers (currently '%s') if "
            "you want to connect to this server.",
            c->c2.tls_multi->remote_ciphername,
            c->options.ncp_ciphers);
        return false;

    }
    else
    {
        msg(D_TLS_ERRORS, "OPTIONS ERROR: failed to negotiate "
            "cipher with server. Configure "
            "--data-ciphers-fallback if you want to connect "
            "to this server.");
        return false;
    }
}
