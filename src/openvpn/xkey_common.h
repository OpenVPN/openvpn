/*
 *  OpenVPN -- An application to securely tunnel IP networks
 *             over a single TCP/UDP port, with support for SSL/TLS-based
 *             session authentication and key exchange,
 *             packet encryption, packet authentication, and
 *             packet compression.
 *
 *  Copyright (C) 2021 Selva Nair <selva.nair@gmail.com>
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by the
 *  Free Software Foundation, either version 2 of the License,
 *  or (at your option) any later version.
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

#ifndef XKEY_COMMON_H_
#define XKEY_COMMON_H_

#include <openssl/opensslv.h>
#if OPENSSL_VERSION_NUMBER >= 0x30000010L && !defined(DISABLE_XKEY_PROVIDER)
#define HAVE_XKEY_PROVIDER 1
#include <openssl/provider.h>
#include <openssl/core_dispatch.h>

/**
 * Initialization function for OpenVPN external key provider for OpenSSL
 * Follows the function signature of OSSL_PROVIDER init()
 */
OSSL_provider_init_fn xkey_provider_init;

#define XKEY_PROV_PROPS "provider=ovpn.xkey"

/**
 * Stuct to encapsulate signature algorithm parameters to pass
 * to sign operation.
 */
typedef struct {
   const char *padmode; /**< "pkcs1", "pss" or "none" */
   const char *mdname;  /**< "SHA256" or "SHA2-256" etc. */
   const char *saltlen; /**< "digest", "auto" or "max" */
   const char *keytype; /**< "EC" or "RSA" */
   const char *op;      /**< "Sign" or "DigestSign" */
} XKEY_SIGALG;

/**
 * Callback for sign operation -- must be implemented for each backend and
 * is used in xkey_signature_sign(), or set when loading the key.
 * (custom key loading not yet implemented).
 *
 * @param handle opaque key handle provided by the backend -- could be null
 *               or unused for management interface.
 * @param sig    On return caller should fill this with the signature
 * @param siglen On entry *siglen has max size of sig and on return must be
 *               set to the actual size of the signature
 * @param tbs    buffer to sign
 * @param tbslen size of data in tbs buffer
 * @sigalg       contains the signature algorithm parameters
 *
 * @returns 1 on success, 0 on error.
 *
 * If sigalg.op = "Sign", the data in tbs is the digest. If sigalg.op = "DigestSign"
 * it is the message that the backend should hash wih appropriate hash algorithm before
 * signing. In the former case no DigestInfo header is added to tbs. This is
 * unlike the deprecated RSA_sign callback which provides encoded digest.
 * For RSA_PKCS1 signatures, the external signing function must encode the digest
 * before signing. The digest algorithm used (or to be used) is passed in the sigalg
 * structure.
 */
typedef int (XKEY_EXTERNAL_SIGN_fn)(void *handle, unsigned char *sig, size_t *siglen,
                                 const unsigned char *tbs, size_t tbslen,
                                 XKEY_SIGALG sigalg);
/**
 * Signature of private key free function callback used
 * to free the opaque private key handle obtained from the
 * backend. Not required for management-external-key.
 */
typedef void (XKEY_PRIVKEY_FREE_fn)(void *handle);

/**
 * Generate an encapsulated EVP_PKEY for management-external-key
 *
 * @param libctx library context in which xkey provider has been loaded
 * @param pubkey corresponding pubkey in the default provider's context
 *
 * @returns a new EVP_PKEY in the provider's keymgmt context.
 * The pubkey is up-refd if retained -- the caller can free it after return
 */
EVP_PKEY *xkey_load_management_key(OSSL_LIB_CTX *libctx, EVP_PKEY *pubkey);

#endif /* HAVE_XKEY_PROVIDER */

#endif /* XKEY_COMMON_H_ */
