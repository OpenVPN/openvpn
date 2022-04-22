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
#ifdef HAVE_CONFIG_H
#include "config.h"
#elif defined(_MSC_VER)
#include "config-msvc.h"
#endif

#include "syshead.h"

#include "ssl_util.h"
#include "ssl_pkt.h"
#include "ssl_common.h"
#include "crypto.h"
#include "session_id.h"
#include "reliable.h"
#include "tls_crypt.h"

/*
 * Dependent on hmac size, opcode size, and session_id size.
 * Will assert if too small.
 */
#define SWAP_BUF_SIZE 256

/**
 * Move a packet authentication HMAC + related fields to or from the front
 * of the buffer so it can be processed by encrypt/decrypt.
 *
 * Turning the on wire format that starts with the opcode to a format
 * that starts with the hmac
 * e.g. "onwire" [opcode, peer session id] [hmac, packet id] [remainder of packed]
 *
 *
 *    "internal" [hmac, packet id] [opcode, peer session id] [remainder of packet]
 *
 *  @param buf      the buffer the swap operation is executed on
 *  @param incoming determines the direction of the swap
 *  @param co       crypto options, determines the hmac to use in the swap
 *
 *  @return         if the swap was successful (buf was large enough)
 */
static bool
swap_hmac(struct buffer *buf, const struct crypto_options *co, bool incoming)
{
    ASSERT(co);

    const struct key_ctx *ctx = (incoming ? &co->key_ctx_bi.decrypt :
                                 &co->key_ctx_bi.encrypt);
    ASSERT(ctx->hmac);

    {
        /* hmac + packet_id (8 bytes) */
        const int hmac_size = hmac_ctx_size(ctx->hmac) + packet_id_size(true);

        /* opcode (1 byte) + session_id (8 bytes) */
        const int osid_size = 1 + SID_SIZE;

        int e1, e2;
        uint8_t *b = BPTR(buf);
        uint8_t buf1[SWAP_BUF_SIZE];
        uint8_t buf2[SWAP_BUF_SIZE];

        if (incoming)
        {
            e1 = osid_size;
            e2 = hmac_size;
        }
        else
        {
            e1 = hmac_size;
            e2 = osid_size;
        }

        ASSERT(e1 <= SWAP_BUF_SIZE && e2 <= SWAP_BUF_SIZE);

        if (buf->len >= e1 + e2)
        {
            memcpy(buf1, b, e1);
            memcpy(buf2, b + e1, e2);
            memcpy(b, buf2, e2);
            memcpy(b + e2, buf1, e1);
            return true;
        }
        else
        {
            return false;
        }
    }
}

#undef SWAP_BUF_SIZE

void
write_control_auth(struct tls_session *session,
                   struct key_state *ks,
                   struct buffer *buf,
                   struct link_socket_actual **to_link_addr,
                   int opcode,
                   int max_ack,
                   bool prepend_ack)
{
    uint8_t header = ks->key_id | (opcode << P_OPCODE_SHIFT);
    struct buffer null = clear_buf();

    ASSERT(link_socket_actual_defined(&ks->remote_addr));
    ASSERT(reliable_ack_write
               (ks->rec_ack, buf, &ks->session_id_remote, max_ack, prepend_ack));

    msg(D_TLS_DEBUG, "%s(): %s", __func__, packet_opcode_name(opcode));

    if (session->tls_wrap.mode == TLS_WRAP_AUTH
        || session->tls_wrap.mode == TLS_WRAP_NONE)
    {
        ASSERT(session_id_write_prepend(&session->session_id, buf));
        ASSERT(buf_write_prepend(buf, &header, sizeof(header)));
    }
    if (session->tls_wrap.mode == TLS_WRAP_AUTH)
    {
        /* no encryption, only write hmac */
        openvpn_encrypt(buf, null, &session->tls_wrap.opt);
        ASSERT(swap_hmac(buf, &session->tls_wrap.opt, false));
    }
    else if (session->tls_wrap.mode == TLS_WRAP_CRYPT)
    {
        ASSERT(buf_init(&session->tls_wrap.work, buf->offset));
        ASSERT(buf_write(&session->tls_wrap.work, &header, sizeof(header)));
        ASSERT(session_id_write(&session->session_id, &session->tls_wrap.work));
        if (!tls_crypt_wrap(buf, &session->tls_wrap.work, &session->tls_wrap.opt))
        {
            buf->len = 0;
            return;
        }

        if (opcode == P_CONTROL_HARD_RESET_CLIENT_V3)
        {
            if (!buf_copy(&session->tls_wrap.work,
                          session->tls_wrap.tls_crypt_v2_wkc))
            {
                msg(D_TLS_ERRORS, "Could not append tls-crypt-v2 client key");
                buf->len = 0;
                return;
            }
        }

        /* Don't change the original data in buf, it's used by the reliability
         * layer to resend on failure. */
        *buf = session->tls_wrap.work;
    }
    *to_link_addr = &ks->remote_addr;
}

bool
read_control_auth(struct buffer *buf,
                  struct tls_wrap_ctx *ctx,
                  const struct link_socket_actual *from,
                  const struct tls_options *opt)
{
    struct gc_arena gc = gc_new();
    bool ret = false;

    const uint8_t opcode = *(BPTR(buf)) >> P_OPCODE_SHIFT;
    if (opcode == P_CONTROL_HARD_RESET_CLIENT_V3
        && !tls_crypt_v2_extract_client_key(buf, ctx, opt))
    {
        msg(D_TLS_ERRORS,
            "TLS Error: can not extract tls-crypt-v2 client key from %s",
            print_link_socket_actual(from, &gc));
        goto cleanup;
    }

    if (ctx->mode == TLS_WRAP_AUTH)
    {
        struct buffer null = clear_buf();

        /* move the hmac record to the front of the packet */
        if (!swap_hmac(buf, &ctx->opt, true))
        {
            msg(D_TLS_ERRORS,
                "TLS Error: cannot locate HMAC in incoming packet from %s",
                print_link_socket_actual(from, &gc));
            gc_free(&gc);
            return false;
        }

        /* authenticate only (no decrypt) and remove the hmac record
         * from the head of the buffer */
        openvpn_decrypt(buf, null, &ctx->opt, NULL, BPTR(buf));
        if (!buf->len)
        {
            msg(D_TLS_ERRORS,
                "TLS Error: incoming packet authentication failed from %s",
                print_link_socket_actual(from, &gc));
            goto cleanup;
        }

    }
    else if (ctx->mode == TLS_WRAP_CRYPT)
    {
        struct buffer tmp = alloc_buf_gc(buf_forward_capacity_total(buf), &gc);
        if (!tls_crypt_unwrap(buf, &tmp, &ctx->opt))
        {
            msg(D_TLS_ERRORS, "TLS Error: tls-crypt unwrapping failed from %s",
                print_link_socket_actual(from, &gc));
            goto cleanup;
        }
        ASSERT(buf_init(buf, buf->offset));
        ASSERT(buf_copy(buf, &tmp));
        buf_clear(&tmp);
    }
    else if (ctx->tls_crypt_v2_server_key.cipher)
    {
        /* If tls-crypt-v2 is enabled, require *some* wrapping */
        msg(D_TLS_ERRORS, "TLS Error: could not determine wrapping from %s",
            print_link_socket_actual(from, &gc));
        /* TODO Do we want to support using tls-crypt-v2 and no control channel
         * wrapping at all simultaneously?  That would allow server admins to
         * upgrade clients one-by-one without running a second instance, but we
         * should not enable it by default because it breaks DoS-protection.
         * So, add something like --tls-crypt-v2-allow-insecure-fallback ? */
        goto cleanup;
    }

    if (ctx->mode == TLS_WRAP_NONE || ctx->mode == TLS_WRAP_AUTH)
    {
        /* advance buffer pointer past opcode & session_id since our caller
         * already read it */
        buf_advance(buf, SID_SIZE + 1);
    }

    ret = true;
cleanup:
    gc_free(&gc);
    return ret;
}

void
free_tls_pre_decrypt_state(struct tls_pre_decrypt_state *state)
{
    free_buf(&state->newbuf);
    free_buf(&state->tls_wrap_tmp.tls_crypt_v2_metadata);
    if (state->tls_wrap_tmp.cleanup_key_ctx)
    {
        free_key_ctx_bi(&state->tls_wrap_tmp.opt.key_ctx_bi);
    }
}

/*
 * This function is similar to tls_pre_decrypt, except it is called
 * when we are in server mode and receive an initial incoming
 * packet.  Note that we don't modify
 * any state in our parameter objects.  The purpose is solely to
 * determine whether we should generate a client instance
 * object, in which case true is returned.
 *
 * This function is essentially the first-line HMAC firewall
 * on the UDP port listener in --mode server mode.
 */
enum first_packet_verdict
tls_pre_decrypt_lite(const struct tls_auth_standalone *tas,
                     struct tls_pre_decrypt_state *state,
                     const struct link_socket_actual *from,
                     const struct buffer *buf)
{
    struct gc_arena gc = gc_new();
    /* A packet needs to have at least an opcode and session id */
    if (buf->len < (1 + SID_SIZE))
    {
        dmsg(D_TLS_STATE_ERRORS,
             "TLS State Error: Too short packet (length  %d) received from %s",
             buf->len, print_link_socket_actual(from, &gc));
        goto error;
    }

    /* get opcode and key ID */
    uint8_t pkt_firstbyte = *BPTR(buf);
    int op = pkt_firstbyte >> P_OPCODE_SHIFT;
    int key_id = pkt_firstbyte & P_KEY_ID_MASK;

    /* this packet is from an as-yet untrusted source, so
     * scrutinize carefully */

    /* Allow only the reset packet or the first packet of the actual handshake. */
    if (op != P_CONTROL_HARD_RESET_CLIENT_V2
        && op != P_CONTROL_HARD_RESET_CLIENT_V3
        && op != P_CONTROL_V1)
    {
        /*
         * This can occur due to bogus data or DoS packets.
         */
        dmsg(D_TLS_STATE_ERRORS,
             "TLS State Error: No TLS state for client %s, opcode=%d",
             print_link_socket_actual(from, &gc),
             op);
        goto error;
    }

    if (key_id != 0)
    {
        dmsg(D_TLS_STATE_ERRORS,
             "TLS State Error: Unknown key ID (%d) received from %s -- 0 was expected",
             key_id,
             print_link_socket_actual(from, &gc));
        goto error;
    }

    /* read peer session id, we do this at this point since
     * read_control_auth will skip over it */
    struct buffer tmp = *buf;
    buf_advance(&tmp, 1);
    if (!session_id_read(&state->peer_session_id, &tmp)
        || !session_id_defined(&state->peer_session_id))
    {
        msg(D_TLS_ERRORS,
            "TLS Error: session-id not found in packet from %s",
            print_link_socket_actual(from, &gc));
        goto error;
    }

    state->newbuf = clone_buf(buf);
    state->tls_wrap_tmp = tas->tls_wrap;

    /* HMAC test and unwrapping the encrypted part of the control message
     * into newbuf or just setting newbuf to point to the start of control
     * message */
    bool status = read_control_auth(&state->newbuf, &state->tls_wrap_tmp,
                                    from, NULL);

    if (!status)
    {
        goto error;
    }

    /*
     * At this point, if --tls-auth is being used, we know that
     * the packet has passed the HMAC test, but we don't know if
     * it is a replay yet.  We will attempt to defeat replays
     * by not advancing to the S_START state until we
     * receive an ACK from our first reply to the client
     * that includes an HMAC of our randomly generated 64 bit
     * session ID.
     *
     * On the other hand if --tls-auth is not being used, we
     * will proceed to begin the TLS authentication
     * handshake with only cursory integrity checks having
     * been performed, since we will be leaving the task
     * of authentication solely up to TLS.
     */
    gc_free(&gc);
    if (op == P_CONTROL_V1)
    {
        return VERDICT_VALID_CONTROL_V1;
    }
    else
    {
        return VERDICT_VALID_RESET;
    }

error:
    tls_clear_error();
    gc_free(&gc);
    return VERDICT_INVALID;
}
