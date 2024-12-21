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

#endif
