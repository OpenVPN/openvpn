/*
 *  OpenVPN -- An application to securely tunnel IP networks
 *             over a single TCP/UDP port, with support for SSL/TLS-based
 *             session authentication and key exchange,
 *             packet encryption, packet authentication, and
 *             packet compression.
 *
 *  Copyright (C) 2024 OpenVPN Inc <sales@openvpn.net>
 *  Copyright (C) 2024 Arne Schwabe <arne@rfc2549.org>
 *
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

#include <inttypes.h>
#include <string.h>
#include <stdlib.h>

#include "crypto_backend.h"
#include "packet_id.h"
#include "crypto.h"
#include "crypto_epoch.h"
#include "buffer.h"
#include "integer.h"

void
ovpn_hkdf_expand(const uint8_t *secret,
                 const uint8_t *info, int info_len,
                 uint8_t *out, int out_len)
{
    hmac_ctx_t *hmac_ctx = hmac_ctx_new();
    hmac_ctx_init(hmac_ctx, secret, "SHA256");

    const int digest_size = SHA256_DIGEST_LENGTH;

    /* T(0) = empty string */
    uint8_t t_prev[SHA256_DIGEST_LENGTH];
    int t_prev_len = 0;

    for (uint8_t block = 1; (block - 1) * digest_size < out_len; block++)
    {
        hmac_ctx_reset(hmac_ctx);

        /* calculate T(block) */
        hmac_ctx_update(hmac_ctx, t_prev, t_prev_len);
        hmac_ctx_update(hmac_ctx, info, info_len);
        hmac_ctx_update(hmac_ctx, &block, 1);
        hmac_ctx_final(hmac_ctx, t_prev);
        t_prev_len = digest_size;

        /* Copy a full hmac output or remaining bytes */
        int out_offset = (block - 1) * digest_size;
        int copylen = min_int(digest_size, out_len - out_offset);

        memcpy(out + out_offset, t_prev, copylen);
    }
    hmac_ctx_cleanup(hmac_ctx);
    hmac_ctx_free(hmac_ctx);
}

bool
ovpn_expand_label(const uint8_t *secret, size_t secret_len,
                  const uint8_t *label, size_t label_len,
                  const uint8_t *context, size_t context_len,
                  uint8_t *out, uint16_t out_len)
{
    if (secret_len != 32 || label_len > 250 || context_len > 255
        || label_len < 1)
    {
        /* Our current implementation is not a general purpose one
         * and assumes that the secret size matches the size of the
         * hash (SHA256) key. Also label length and context length
         * need need to be in range */
        return false;
    }

    struct gc_arena gc = gc_new();
    /* 2 byte for the outlen encoded as uint16, 5 bytes for "ovpn ",
     * 1 byte for context len byte and 1 byte for label len byte */
    const uint8_t *label_prefix = (const uint8_t *) ("ovpn ");
    int prefix_len = 5;

    int hkdf_label_len = 2 + prefix_len + 1 + label_len + 1 + context_len;
    struct buffer hkdf_label = alloc_buf_gc(hkdf_label_len, &gc);

    buf_write_u16(&hkdf_label, out_len);
    buf_write_u8(&hkdf_label, prefix_len + label_len);
    buf_write(&hkdf_label, label_prefix, prefix_len);
    buf_write(&hkdf_label, label, label_len);

    buf_write_u8(&hkdf_label, context_len);
    if (context_len > 0)
    {
        buf_write(&hkdf_label, context, context_len);
    }

    ASSERT(buf_len(&hkdf_label) == hkdf_label_len);

    ovpn_hkdf_expand(secret, buf_bptr(&hkdf_label),
                     buf_len(&hkdf_label), out, out_len);

    gc_free(&gc);
    return true;
}

/**
 * Iterates the epoch key to make it E_n+1, ie increase the epoch by one
 * and derive the new key material accordingly
 * @param epoch_key epoch key to iterate
 */
static void
epoch_key_iterate(struct epoch_key *epoch_key)
{
    struct epoch_key new_epoch_key = { 0 };
    new_epoch_key.epoch = epoch_key->epoch + 1;
    const uint8_t epoch_update_label[] = "datakey upd";
    /* length of the array without extra \0 byte from the string */
    const size_t epoch_update_label_len = sizeof(epoch_update_label) - 1;

    /* E_N+1 = OVPN-Expand-Label(E_N, "datakey upd", "", 32) */
    ovpn_expand_label(epoch_key->epoch_key, sizeof(epoch_key->epoch_key),
                      epoch_update_label, epoch_update_label_len,
                      NULL, 0,
                      new_epoch_key.epoch_key, sizeof(new_epoch_key.epoch_key));
    *epoch_key = new_epoch_key;
}

void
epoch_data_key_derive(struct key_parameters *key,
                      const struct epoch_key *epoch_key,
                      const struct key_type *kt)
{
    key->hmac_size = cipher_kt_iv_size(kt->cipher);
    key->cipher_size = cipher_kt_key_size(kt->cipher);

    /* Generate data key from epoch key:
     * K_i = OVPN-Expand-Label(E_i, "data_key", "", key_size)
     * implicit_iv = OVPN-Expand-Label(E_i, "data_iv", "", implicit_iv_len)
     */

    const uint8_t epoch_data_key_label[] = "data_key";
    /* length of the array without extra \0 byte from the string */
    const size_t epoch_data_key_label_len = sizeof(epoch_data_key_label) - 1;

    ovpn_expand_label(epoch_key->epoch_key, sizeof(epoch_key->epoch_key),
                      epoch_data_key_label, epoch_data_key_label_len,
                      NULL, 0,
                      (uint8_t *)(&key->cipher), key->cipher_size);

    const uint8_t epoch_data_iv_label[] = "data_iv";
    /* length of the array without extra \0 byte from the string */
    const size_t epoch_data_iv_label_len = sizeof(epoch_data_iv_label) - 1;

    ovpn_expand_label(epoch_key->epoch_key, sizeof(epoch_key->epoch_key),
                      epoch_data_iv_label, epoch_data_iv_label_len,
                      NULL, 0,
                      (uint8_t *)(&key->hmac), key->hmac_size);
    key->epoch = epoch_key->epoch;
}

static void
epoch_init_send_key_ctx(struct crypto_options *co)
{
    /* Ensure that we are NEVER regenerating the same key that has already
     * been generated. Since we also reset the packet ID counter this would be
     * catastrophic as we would do IV reuse which breaks ciphers like AES-GCM */
    ASSERT(co->key_ctx_bi.encrypt.epoch != co->epoch_key_send.epoch);
    char name[32] = { 0 };
    snprintf(name, sizeof(name), "Epoch Data key %" PRIu16, co->epoch_key_send.epoch);

    struct key_parameters send_key = { 0 };

    epoch_data_key_derive(&send_key, &co->epoch_key_send, &co->epoch_key_type);

    init_key_bi_ctx_send(&co->key_ctx_bi.encrypt, &send_key,
                         &co->epoch_key_type, name);
    reset_packet_id_send(&co->packet_id.send);
    CLEAR(send_key);
}


static void
epoch_init_recv_key(struct key_ctx *ctx, struct crypto_options *co)
{
    struct key_parameters recv_key = { 0 };
    epoch_data_key_derive(&recv_key, &co->epoch_key_recv, &co->epoch_key_type);

    char name[32];

    snprintf(name, sizeof(name), "Epoch Data key %" PRIu16, co->epoch_key_recv.epoch);

    init_key_bi_ctx_recv(ctx, &recv_key, &co->epoch_key_type, name);
    CLEAR(recv_key);
}

void
epoch_generate_future_receive_keys(struct crypto_options *co)
{
    /* We want the future receive keys to start just after the epoch of
     * the currently used decryption key. */
    ASSERT(co->key_ctx_bi.initialized);
    uint16_t current_decrypt_epoch = co->key_ctx_bi.decrypt.epoch;

    /* Either we have not generated any future keys yet (first initialisation)
     * or the last index is the same as our current epoch key
     * (last generated receive epoch key should match the epoch key) */
    struct key_ctx *highest_future_key = &co->epoch_data_keys_future[co->epoch_data_keys_future_count - 1];

    ASSERT(co->epoch_key_recv.epoch == 1
           || highest_future_key->epoch == co->epoch_key_recv.epoch);

    /* free the keys that are not used anymore */
    for (uint16_t i = 0; i < co->epoch_data_keys_future_count; i++)
    {
        /* Keys in future keys are always epoch > 1 if initialised */
        if (co->epoch_data_keys_future[i].epoch > 0
            && co->epoch_data_keys_future[i].epoch < current_decrypt_epoch)
        {
            /* Key is old, free it */
            free_key_ctx(&co->epoch_data_keys_future[i]);
        }
    }

    /* Calculate the number of keys that need to be generated,
     * if no keys have been generated assume only the first key is defined */
    uint16_t current_highest_key = highest_future_key->epoch ? highest_future_key->epoch : 1;
    uint16_t desired_highest_key = current_decrypt_epoch + co->epoch_data_keys_future_count;
    uint16_t num_keys_generate = desired_highest_key - current_highest_key;


    /* Move the old keys out of the way so the order of keys stays strictly
     * monotonic and consecutive. */
    /* first check that the destination we are going to overwrite is freed */
    for (uint16_t i = 0; i < num_keys_generate; i++)
    {
        ASSERT(co->epoch_data_keys_future[i].epoch == 0);
    }
    memmove(co->epoch_data_keys_future,
            co->epoch_data_keys_future + num_keys_generate,
            (co->epoch_data_keys_future_count - num_keys_generate) * sizeof(struct key_ctx));

    /* Clear and regenerate the array elements at the end */
    for (uint16_t i = co->epoch_data_keys_future_count - num_keys_generate; i < co->epoch_data_keys_future_count; i++)
    {
        CLEAR(co->epoch_data_keys_future[i]);
        epoch_key_iterate(&co->epoch_key_recv);

        epoch_init_recv_key(&co->epoch_data_keys_future[i], co);
    }

    /* Assert that all keys are initialised */
    for (uint16_t i = 0; i < co->epoch_data_keys_future_count; i++)
    {
        ASSERT(co->epoch_data_keys_future[i].epoch > 0);
    }
}

void
epoch_iterate_send_key(struct crypto_options *co)
{
    ASSERT(co->epoch_key_send.epoch < UINT16_MAX);
    epoch_key_iterate(&co->epoch_key_send);
    free_key_ctx(&co->key_ctx_bi.encrypt);
    epoch_init_send_key_ctx(co);
}

void
epoch_replace_update_recv_key(struct crypto_options *co,
                              uint16_t new_epoch)
{
    /* Find the key of the new epoch in future keys */
    uint16_t fki;
    for (fki = 0; fki < co->epoch_data_keys_future_count; fki++)
    {
        if (co->epoch_data_keys_future[fki].epoch == new_epoch)
        {
            break;
        }
    }
    /* we should only ever be called when we successfully decrypted/authenticated
     * a packet from a peer, ie the epoch recv key *MUST* be in that
     * array */
    ASSERT(fki < co->epoch_data_keys_future_count);
    ASSERT(co->epoch_data_keys_future[fki].epoch == new_epoch);

    struct key_ctx *new_ctx = &co->epoch_data_keys_future[fki];

    /* Check if the new recv key epoch is higher than the send key epoch. If
     * yes we will replace the send key as well */
    if (co->key_ctx_bi.encrypt.epoch < new_epoch)
    {
        free_key_ctx(&co->key_ctx_bi.encrypt);

        /* Update the epoch_key for send to match the current key being used.
         * This is a bit of extra work but since we are a maximum of 16
         * keys behind, a maximum 16 HMAC invocations are a small price to
         * pay for not keeping all the old epoch keys around in future_keys
         * array */
        while (co->epoch_key_send.epoch < new_epoch)
        {
            epoch_key_iterate(&co->epoch_key_send);
        }
        epoch_init_send_key_ctx(co);
    }

    /* Replace receive key */
    free_key_ctx(&co->epoch_retiring_data_receive_key);
    co->epoch_retiring_data_receive_key = co->key_ctx_bi.decrypt;
    packet_id_move_recv(&co->epoch_retiring_key_pid_recv, &co->packet_id.rec);

    co->key_ctx_bi.decrypt = *new_ctx;

    /* Zero the old location instead to of free_key_ctx since we moved the keys
     * and do not want to free the pointers in the old place */
    memset(new_ctx, 0, sizeof(struct key_ctx));

    /* Generate new future keys */
    epoch_generate_future_receive_keys(co);
}

void
free_epoch_key_ctx(struct crypto_options *co)
{
    for (uint16_t i = 0; i < co->epoch_data_keys_future_count; i++)
    {
        free_key_ctx(&co->epoch_data_keys_future[i]);
    }

    free(co->epoch_data_keys_future);
    free_key_ctx(&co->epoch_retiring_data_receive_key);
    free(co->epoch_retiring_key_pid_recv.seq_list);
    CLEAR(co->epoch_key_recv);
    CLEAR(co->epoch_key_send);
}

void
epoch_init_key_ctx(struct crypto_options *co, const struct key_type *key_type,
                   const struct epoch_key *e1_send,
                   const struct epoch_key *e1_recv,
                   uint16_t future_key_count)
{
    ASSERT(e1_send->epoch == 1 && e1_recv->epoch == 1);
    co->epoch_key_recv = *e1_recv;
    co->epoch_key_send = *e1_send;

    co->epoch_key_type = *key_type;
    co->aead_usage_limit = cipher_get_aead_limits(key_type->cipher);

    epoch_init_send_key_ctx(co);
    epoch_init_recv_key(&co->key_ctx_bi.decrypt, co);
    co->key_ctx_bi.initialized = true;

    co->epoch_data_keys_future_count = future_key_count;
    ALLOC_ARRAY_CLEAR(co->epoch_data_keys_future, struct key_ctx, co->epoch_data_keys_future_count);
    epoch_generate_future_receive_keys(co);
}

struct key_ctx *
epoch_lookup_decrypt_key(struct crypto_options *opt, uint16_t epoch)
{
    /* Current decrypt key is the most likely one */
    if (opt->key_ctx_bi.decrypt.epoch == epoch)
    {
        return &opt->key_ctx_bi.decrypt;
    }
    else if (opt->epoch_retiring_data_receive_key.epoch
             && opt->epoch_retiring_data_receive_key.epoch == epoch)
    {
        return &opt->epoch_retiring_data_receive_key;
    }
    else if (epoch > opt->key_ctx_bi.decrypt.epoch
             && epoch <= opt->key_ctx_bi.decrypt.epoch + opt->epoch_data_keys_future_count)
    {
        /* Key in the range of future keys */
        int index = epoch - (opt->key_ctx_bi.decrypt.epoch + 1);

        /* If we have reached the edge of the valid keys we do not return
         * the key anymore since regenerating the new keys would move us
         * over the window of valid keys and would need all kind of
         * special casing, so we stop returning the key in this case */
        if (epoch > (UINT16_MAX - opt->epoch_data_keys_future_count - 1))
        {
            return NULL;
        }
        else
        {
            return &opt->epoch_data_keys_future[index];
        }
    }
    else
    {
        return NULL;
    }
}


void
epoch_check_send_iterate(struct crypto_options *opt)
{
    if (opt->epoch_key_send.epoch == UINT16_MAX)
    {
        /* limit of epoch keys reached, cannot move to a newer key anymore */
        return;
    }
    if (opt->aead_usage_limit)
    {
        if (aead_usage_limit_reached(opt->aead_usage_limit, &opt->key_ctx_bi.encrypt,
                                     opt->packet_id.send.id))
        {
            /* Send key limit reached */
            epoch_iterate_send_key(opt);
        }
        /* draft 8 of the aead usage limit still had but draft 9 complete
         * dropped this statement:
         *
         *    In particular, in two-party communication, one participant cannot
         *    regard apparent overuse of a key by other participants as
         *    being in error, when it could be that the other participant has
         *    better information about bounds.
         *
         * OpenVPN 2.x implements a compromise of not regarding this as an
         * error but still accepting packets of the usage limit but tries to
         * push the peer to a new epoch key by increasing our own key epoch
         *
         * Also try to push the sender to use a new key if we are the
         * decryption fail warn limit.
         * */
        else if (opt->key_ctx_bi.encrypt.epoch == opt->key_ctx_bi.decrypt.epoch
                 && (aead_usage_limit_reached(opt->aead_usage_limit,
                                              &opt->key_ctx_bi.decrypt,
                                              opt->packet_id.rec.id)
                     || cipher_decrypt_verify_fail_warn(&opt->key_ctx_bi.decrypt)
                     ))
        {
            /* Receive key limit reached. Increase our own send key to signal
             * that we want to use a new epoch. Peer should then also move its
             * key but is not required to do this */
            epoch_iterate_send_key(opt);
        }
    }

    if (opt->packet_id.send.id == PACKET_ID_EPOCH_MAX)
    {
        epoch_iterate_send_key(opt);
    }

}
