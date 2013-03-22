/*
 *  OpenVPN -- An application to securely tunnel IP networks
 *             over a single TCP/UDP port, with support for SSL/TLS-based
 *             session authentication and key exchange,
 *             packet encryption, packet authentication, and
 *             packet compression.
 *
 *  Copyright (C) 2002-2010 OpenVPN Technologies, Inc. <sales@openvpn.net>
 *  Copyright (C) 2010 Fox Crypto B.V. <openvpn@fox-it.com>
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
 *  You should have received a copy of the GNU General Public License
 *  along with this program (see the file COPYING included with this
 *  distribution); if not, write to the Free Software Foundation, Inc.,
 *  59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

/**
 * @file Data Channel Cryptography PolarSSL-specific backend interface
 */

#ifndef CRYPTO_POLARSSL_H_
#define CRYPTO_POLARSSL_H_

#include <polarssl/cipher.h>
#include <polarssl/md.h>
#include <polarssl/ctr_drbg.h>

/** Generic cipher key type %context. */
typedef cipher_info_t cipher_kt_t;

/** Generic message digest key type %context. */
typedef md_info_t md_kt_t;

/** Generic cipher %context. */
typedef cipher_context_t cipher_ctx_t;

/** Generic message digest %context. */
typedef md_context_t md_ctx_t;

/** Generic HMAC %context. */
typedef md_context_t hmac_ctx_t;

/** Maximum length of an IV */
#define OPENVPN_MAX_IV_LENGTH 	POLARSSL_MAX_IV_LENGTH

/** Cipher is in CBC mode */
#define OPENVPN_MODE_CBC 	POLARSSL_MODE_CBC

/** Cipher is in OFB mode */
#define OPENVPN_MODE_OFB 	POLARSSL_MODE_OFB

/** Cipher is in CFB mode */
#define OPENVPN_MODE_CFB 	POLARSSL_MODE_CFB

/** Cipher should encrypt */
#define OPENVPN_OP_ENCRYPT 	POLARSSL_ENCRYPT

/** Cipher should decrypt */
#define OPENVPN_OP_DECRYPT 	POLARSSL_DECRYPT

#define MD4_DIGEST_LENGTH 	16
#define MD5_DIGEST_LENGTH 	16
#define SHA_DIGEST_LENGTH 	20
#define DES_KEY_LENGTH 8

/**
 * Returns a singleton instance of the PolarSSL random number generator.
 *
 * For PolarSSL 1.1+, this is the CTR_DRBG random number generator. If it
 * hasn't been initialised yet, the RNG will be initialised using the default
 * entropy sources. Aside from the default platform entropy sources, an
 * additional entropy source, the HAVEGE random number generator will also be
 * added. During initialisation, a personalisation string will be added based
 * on the time, the PID, and a pointer to the random context.
 */
ctr_drbg_context * rand_ctx_get();

#ifdef ENABLE_PREDICTION_RESISTANCE
/**
 * Enable prediction resistance on the random number generator.
 */
void rand_ctx_enable_prediction_resistance();
#endif

#endif /* CRYPTO_POLARSSL_H_ */
