/*
 *  OpenVPN -- An application to securely tunnel IP networks
 *             over a single TCP/UDP port, with support for SSL/TLS-based
 *             session authentication and key exchange,
 *             packet encryption, packet authentication, and
 *             packet compression.
 *
 *  Copyright (C) 2002-2023 OpenVPN Inc <sales@openvpn.net>
 *  Copyright (C) 2010-2021 Fox Crypto B.V. <openvpn@foxcrypto.com>
 *  Copyright (C) 2008-2023 David Sommerseth <dazo@eurephia.org>
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
#include "ssl_util.h"
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
         * Going cipher_kt_name (and translate_cipher_name_from_openvpn/
         * translate_cipher_name_to_openvpn) also normalises the cipher name,
         * e.g. replacing AeS-128-gCm with AES-128-GCM
         *
         * ciphers that have ? in front of them are considered optional and
         * OpenVPN will only warn if they are not found (and remove them from
         * the list)
         */
        bool optional = false;
        if (token[0] == '?')
        {
            token++;
            optional = true;
        }

        const bool nonecipher = (strcmp(token, "none") == 0);
        const char *optstr = optional ? "optional " : "";

        if (nonecipher)
        {
            msg(M_WARN, "WARNING: cipher 'none' specified for --data-ciphers. "
                "This allows negotiation of NO encryption and "
                "tunnelled data WILL then be transmitted in clear text "
                "over the network! "
                "PLEASE DO RECONSIDER THIS SETTING!");
        }
        if (!nonecipher && !cipher_valid(token))
        {
            msg(M_WARN, "Unsupported %scipher in --data-ciphers: %s", optstr, token);
            error_found = error_found || !optional;
        }
        else if (!nonecipher && !cipher_kt_mode_aead(token)
                 && !cipher_kt_mode_cbc(token)
                 && !cipher_kt_mode_ofb_cfb(token))
        {
            msg(M_WARN, "Unsupported %scipher algorithm '%s'. It does not use "
                "CFB, OFB, CBC, or a supported AEAD mode", optstr, token);
            error_found = error_found || !optional;
        }
        else
        {
            const char *ovpn_cipher_name = cipher_kt_name(token);
            if (nonecipher)
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


void
append_cipher_to_ncp_list(struct options *o, const char *ciphername)
{
    /* Append the --cipher to ncp_ciphers to allow it in NCP */
    size_t newlen = strlen(o->ncp_ciphers) + 1 + strlen(ciphername) + 1;
    char *ncp_ciphers = gc_malloc(newlen, false, &o->gc);

    ASSERT(openvpn_snprintf(ncp_ciphers, newlen, "%s:%s", o->ncp_ciphers,
                            ciphername));
    o->ncp_ciphers = ncp_ciphers;
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
    const char *iv_ciphers = extract_var_peer_info(peer_info, "IV_CIPHERS=", gc);
    if (iv_ciphers)
    {
        return iv_ciphers;
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
    if (remote_cipher == NULL
        || (peer_info && strstr(peer_info, "IV_CIPHERS=")))
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
        msg(D_PUSH_DEBUG, "OPTIONS IMPORT: data channel crypto options modified");
        return true;
    }

    /* If the server did not push a --cipher, we will switch to the
     * remote cipher if it is in our ncp-ciphers list */
    if (tls_poor_mans_ncp(&c->options, c->c2.tls_multi->remote_ciphername))
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

const char *
get_p2p_ncp_cipher(struct tls_session *session, const char *peer_info,
                   struct gc_arena *gc)
{
    /* we use a local gc arena to keep the temporary strings needed by strsep */
    struct gc_arena gc_local = gc_new();
    const char *peer_ciphers = extract_var_peer_info(peer_info, "IV_CIPHERS=", &gc_local);

    if (!peer_ciphers)
    {
        gc_free(&gc_local);
        return NULL;
    }

    const char *server_ciphers;
    const char *client_ciphers;

    if (session->opt->server)
    {
        server_ciphers = session->opt->config_ncp_ciphers;
        client_ciphers = peer_ciphers;
    }
    else
    {
        client_ciphers = session->opt->config_ncp_ciphers;
        server_ciphers = peer_ciphers;
    }

    /* Find the first common cipher from TLS server and TLS client. We
     * use the preference of the server here to make it deterministic */
    char *tmp_ciphers = string_alloc(server_ciphers, &gc_local);

    const char *token;
    while ((token = strsep(&tmp_ciphers, ":")))
    {
        if (tls_item_in_cipher_list(token, client_ciphers))
        {
            break;
        }
    }

    const char *ret = NULL;
    if (token != NULL)
    {
        ret = string_alloc(token, gc);
    }
    gc_free(&gc_local);

    return ret;
}

static void
p2p_ncp_set_options(struct tls_multi *multi, struct tls_session *session)
{
    /* will return 0 if peer_info is null */
    const unsigned int iv_proto_peer = extract_iv_proto(multi->peer_info);

    /* The other peer does not support P2P NCP */
    if (!(iv_proto_peer & IV_PROTO_NCP_P2P))
    {
        return;
    }

    if (iv_proto_peer & IV_PROTO_DATA_V2)
    {
        multi->use_peer_id = true;
        multi->peer_id = 0x76706e; /* 'v' 'p' 'n' */
    }

    if (iv_proto_peer & IV_PROTO_CC_EXIT_NOTIFY)
    {
        session->opt->crypto_flags |= CO_USE_CC_EXIT_NOTIFY;
    }

#if defined(HAVE_EXPORT_KEYING_MATERIAL)
    if (iv_proto_peer & IV_PROTO_TLS_KEY_EXPORT)
    {
        session->opt->crypto_flags |= CO_USE_TLS_KEY_MATERIAL_EXPORT;

        if (multi->use_peer_id)
        {
            /* Using a non hardcoded peer-id makes a tiny bit harder to
             * fingerprint packets and also gives each connection a unique
             * peer-id that can be useful for NAT tracking etc. */

            uint8_t peerid[3];
            if (!key_state_export_keying_material(session, EXPORT_P2P_PEERID_LABEL,
                                                  strlen(EXPORT_P2P_PEERID_LABEL),
                                                  &peerid, 3))
            {
                /* Non DCO setup might still work but also this should never
                 * happen or very likely the TLS encryption key exporter will
                 * also fail */
                msg(M_NONFATAL, "TLS key export for P2P peer id failed. "
                    "Continuing anyway, expect problems");
            }
            else
            {
                multi->peer_id = (peerid[0] << 16) + (peerid[1] << 8) + peerid[2];
            }

        }
    }
    if (iv_proto_peer & IV_PROTO_DYN_TLS_CRYPT)
    {
        session->opt->crypto_flags |= CO_USE_DYNAMIC_TLS_CRYPT;
    }
#endif /* if defined(HAVE_EXPORT_KEYING_MATERIAL) */
}

void
p2p_mode_ncp(struct tls_multi *multi, struct tls_session *session)
{
    /* Set the common options */
    p2p_ncp_set_options(multi, session);

    struct gc_arena gc = gc_new();

    /* Query the common cipher here to log it as part of our message.
     * We postpone switching the cipher to do_up */
    const char *common_cipher = get_p2p_ncp_cipher(session, multi->peer_info, &gc);

    if (!common_cipher)
    {
        struct buffer out = alloc_buf_gc(128, &gc);
        /* at this point we do not really know if our fallback is
         * not enabled or if we use 'none' cipher as fallback, so
         * keep this ambiguity here and print fallback-cipher: none
         */

        const char *fallback_name = "none";
        const char *ciphername = session->opt->key_type.cipher;

        if (cipher_defined(ciphername))
        {
            fallback_name = cipher_kt_name(ciphername);
        }

        buf_printf(&out, "(not negotiated, fallback-cipher: %s)", fallback_name);
        common_cipher = BSTR(&out);
    }

    msg(D_TLS_DEBUG_LOW, "P2P mode NCP negotiation result: "
        "TLS_export=%d, DATA_v2=%d, peer-id %d, cipher=%s",
        (bool)(session->opt->crypto_flags & CO_USE_TLS_KEY_MATERIAL_EXPORT),
        multi->use_peer_id, multi->peer_id, common_cipher);

    gc_free(&gc);
}


bool
check_session_cipher(struct tls_session *session, struct options *options)
{
    bool cipher_allowed_as_fallback = options->enable_ncp_fallback
                                      && streq(options->ciphername, session->opt->config_ciphername);

    if (!session->opt->server && !cipher_allowed_as_fallback
        && !tls_item_in_cipher_list(options->ciphername, options->ncp_ciphers))
    {
        msg(D_TLS_ERRORS, "Error: negotiated cipher not allowed - %s not in %s",
            options->ciphername, options->ncp_ciphers);
        /* undo cipher push, abort connection setup */
        options->ciphername = session->opt->config_ciphername;
        return false;
    }
    else
    {
        return true;
    }
}
