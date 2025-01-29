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

#ifndef CRYPTO_EPOCH_H
#define CRYPTO_EPOCH_H

/**
 * Implementation of the RFC5869 HKDF-Expand function with the following
 * restrictions
 *
 *  - secret is assumed to be always 32 bytes
 *  - HASH is always SHA256
 *
 *  @param secret   the input keying material (HMAC key)
 *  @param info     context and application specific information
 *  @param info_len length of the info string
 *  @param out      output keying material
 *  @param out_len  length of output keying material
 */
void
ovpn_hkdf_expand(const uint8_t *secret,
                 const uint8_t *info, int info_len,
                 uint8_t *out, int out_len);

/**
 * Variant of the RFC 8446 TLS 1.3  HKDF-Expand-Label function with the
 * following differences/restrictions:
 *  - secret must 32 bytes in length
 *  - label prefix is "ovpn " instead of "tls13 "
 *  - HASH is always SHA256
 *
 * @param secret        Input secret
 * @param secret_len    length of the input secret
 * @param label         Label for the exported key material
 * @param label_len     length of the label
 * @param context       optional context
 * @param context_len   length of the context
 * @param out      output keying material
 * @param out_len  length of output keying material
 * @return
 */
bool
ovpn_expand_label(const uint8_t *secret, size_t secret_len,
                  const uint8_t *label, size_t label_len,
                  const uint8_t *context, size_t context_len,
                  uint8_t *out, uint16_t out_len);

/**
 * Generate a data channel key pair from the epoch key
 * @param key           Destination for the generated data key
 * @param epoch_key     Epoch key to be used
 * @param kt            Cipher information to generate the data channel key for
 */
void
epoch_data_key_derive(struct key_parameters *key,
                      const struct epoch_key *epoch_key,
                      const struct key_type *kt);

/**
 * Generates and fills the epoch_data_keys_future with next valid
 * future keys in crypto_options using the epoch of the key in
 * crypto_options.key_ctx_bi.decrypt as starting point
 *
 * This assume that the normal key_ctx_bi and epoch keys have been already
 * setup.
 *
 * This method is also called if crypto_options.key_ctx_bi.decrypt is changed.
 * The method will then change the future keys in epoch_data_keys_future to
 * free the ones that are older than the crypto_options.key_ctx_bi.decrypt and
 * generate the keys from the newer epoch.
 */
void
epoch_generate_future_receive_keys(struct crypto_options *co);


/** This is called when the peer uses a new send key that is not the default
 * key. This function ensures the following:
 * - recv key matches the epoch index provided
 * - send key epoch is equal or higher than recv_key epoch
 *
 * @param co        crypto_options to update
 * @param new_epoch the new epoch to use for the receive key
 */
void
epoch_replace_update_recv_key(struct crypto_options *co,
                              uint16_t new_epoch);

/**
 * Updates the send key and send_epoch_key in cryptio_options->key_ctx_bi to
 * use the next epoch */
void
epoch_iterate_send_key(struct crypto_options *co);

/**
 * Frees the extra data structures used by epoch keys in \c crypto_options
 */
void
free_epoch_key_ctx(struct crypto_options *co);

/**
 * Initialises data channel keys and internal structures for epoch data keys
 * using the provided E0 epoch key
 *
 * @param co                The crypto option struct to initialise the epoch
 *                          related fields
 * @param key_type          The parameter of what encryption cipher to use when
 *                          initialising the epoch related fields
 * @param e1_send           The E1 send epoch key derived by TLS-EKM
 * @param e1_recv           The E1 receive epoch key derived by TLS-EKM
 * @param future_key_count  the number of future epoch keys that should be
 *                          considered valid when receiving data from the peer
 */
void
epoch_init_key_ctx(struct crypto_options *co, const struct key_type *key_type,
                   const struct epoch_key *e1_send, const struct epoch_key *e1_recv,
                   uint16_t future_key_count);

/**
 * Using an epoch, this function will try to retrieve a decryption
 * key context that matches that epoch from the \c opt argument
 * @param opt       crypto_options to use to find the decrypt key
 * @param epoch     epoch of the key to lookup
 * @return          the key context with
 */
struct key_ctx *
epoch_lookup_decrypt_key(struct crypto_options *opt, uint16_t epoch);

/**
 * Checks if we need to iterate the send epoch key. This needs to be in one
 * of the following condition
 *  - max epoch counter reached
 *  - send key aead usage limit reached (for AES-GCM and similar ciphers)
 *  - recv key usage limit reached
 */
void
epoch_check_send_iterate(struct crypto_options *opt);


#endif /* ifndef CRYPTO_EPOCH_H */
