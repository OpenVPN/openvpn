/*
 *  OpenVPN -- An application to securely tunnel IP networks
 *             over a single TCP/UDP port, with support for SSL/TLS-based
 *             session authentication and key exchange,
 *             packet encryption, packet authentication, and
 *             packet compression.
 *
 *  Copyright (C) 2002-2010 OpenVPN Technologies, Inc. <sales@openvpn.net>
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

#ifndef CRYPTO_H
#define CRYPTO_H
#ifdef USE_CRYPTO

#define ALLOW_NON_CBC_CIPHERS

/*
 * Does our OpenSSL library support crypto hardware acceleration?
 */
#if defined(HAVE_OPENSSL_ENGINE_H) && defined(HAVE_ENGINE_LOAD_BUILTIN_ENGINES) && defined(HAVE_ENGINE_REGISTER_ALL_COMPLETE) && defined(HAVE_ENGINE_CLEANUP)
#define CRYPTO_ENGINE 1
#else
#define CRYPTO_ENGINE 0
#endif

#include <openssl/objects.h>
#include <openssl/rand.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/des.h>
#include <openssl/md5.h>
#if NTLM
#include <openssl/md4.h>
#endif
#include <openssl/sha.h>
#include <openssl/err.h>

#if CRYPTO_ENGINE
#include <openssl/engine.h>
#endif

#if SSLEAY_VERSION_NUMBER >= 0x00907000L
#include <openssl/des_old.h>
#endif

#include "basic.h"
#include "buffer.h"
#include "packet_id.h"
#include "mtu.h"

/*
 * Workarounds for incompatibilites between OpenSSL libraries.
 * Right now we accept OpenSSL libraries from 0.9.5 to 0.9.7.
 */

#if SSLEAY_VERSION_NUMBER < 0x00907000L

/* Workaround: EVP_CIPHER_mode is defined wrong in OpenSSL 0.9.6 but is fixed in 0.9.7 */
#undef EVP_CIPHER_mode
#define EVP_CIPHER_mode(e)                (((e)->flags) & EVP_CIPH_MODE)

#define DES_cblock                        des_cblock
#define DES_is_weak_key                   des_is_weak_key
#define DES_check_key_parity              des_check_key_parity
#define DES_set_odd_parity                des_set_odd_parity

#define HMAC_CTX_init(ctx)                CLEAR (*ctx)
#define HMAC_Init_ex(ctx,sec,len,md,impl) HMAC_Init(ctx, sec, len, md) 
#define HMAC_CTX_cleanup(ctx)             HMAC_cleanup(ctx)
#define EVP_MD_CTX_cleanup(md)            CLEAR (*md)

#define INFO_CALLBACK_SSL_CONST

#endif

#ifndef INFO_CALLBACK_SSL_CONST
#define INFO_CALLBACK_SSL_CONST const
#endif

#if SSLEAY_VERSION_NUMBER < 0x00906000

#undef EVP_CIPHER_mode
#define EVP_CIPHER_mode(x) 1
#define EVP_CIPHER_CTX_mode(x) 1
#define EVP_CIPHER_flags(x) 0

#define EVP_CIPH_CBC_MODE 1
#define EVP_CIPH_CFB_MODE 0
#define EVP_CIPH_OFB_MODE 0
#define EVP_CIPH_VARIABLE_LENGTH 0

#define OPENSSL_malloc(x) malloc(x)
#define OPENSSL_free(x) free(x)

static inline int
EVP_CipherInit_ov (EVP_CIPHER_CTX *ctx, const EVP_CIPHER *type, uint8_t *key, uint8_t *iv, int enc)
{
  EVP_CipherInit (ctx, type, key, iv, enc);
  return 1;
}

static inline int
EVP_CipherUpdate_ov (EVP_CIPHER_CTX *ctx, uint8_t *out, int *outl, uint8_t *in, int inl)
{
  EVP_CipherUpdate (ctx, out, outl, in, inl);
  return 1;
}

static inline bool
cipher_ok (const char* name)
{
  const int i = strlen (name) - 4;
  if (i >= 0)
    return !strcmp (name + i, "-CBC");
  else
    return false;
}

#else

static inline int
EVP_CipherInit_ov (EVP_CIPHER_CTX *ctx, const EVP_CIPHER *type, uint8_t *key, uint8_t *iv, int enc)
{
  return EVP_CipherInit (ctx, type, key, iv, enc);
}

static inline int
EVP_CipherUpdate_ov (EVP_CIPHER_CTX *ctx, uint8_t *out, int *outl, uint8_t *in, int inl)
{
  return EVP_CipherUpdate (ctx, out, outl, in, inl);
}

static inline bool
cipher_ok (const char* name)
{
  return true;
}

#endif

#if SSLEAY_VERSION_NUMBER < 0x0090581f
#undef DES_check_key_parity
#define DES_check_key_parity(x) 1
#endif

#ifndef EVP_CIPHER_name
#define EVP_CIPHER_name(e)		OBJ_nid2sn(EVP_CIPHER_nid(e))
#endif

#ifndef EVP_MD_name
#define EVP_MD_name(e)			OBJ_nid2sn(EVP_MD_type(e))
#endif

/*
 * Max size in bytes of any cipher key that might conceivably be used.
 *
 * This value is checked at compile time in crypto.c to make sure
 * it is always at least EVP_MAX_KEY_LENGTH.
 *
 * We define our own value, since this parameter
 * is used to control the size of static key files.
 * If the OpenSSL library increases EVP_MAX_KEY_LENGTH,
 * we don't want our key files to be suddenly rendered
 * unusable.
 */
#define MAX_CIPHER_KEY_LENGTH 64

/*
 * Max size in bytes of any HMAC key that might conceivably be used.
 *
 * This value is checked at compile time in crypto.c to make sure
 * it is always at least EVP_MAX_MD_SIZE.  We define our own value
 * for the same reason as above.
 */
#define MAX_HMAC_KEY_LENGTH 64

/*
 * Defines a key type and key length for both cipher and HMAC.
 */
struct key_type
{
  uint8_t cipher_length;
  uint8_t hmac_length;
  const EVP_CIPHER *cipher;
  const EVP_MD *digest;
};

/*
 * A random key.
 */
struct key
{
  uint8_t cipher[MAX_CIPHER_KEY_LENGTH];
  uint8_t hmac[MAX_HMAC_KEY_LENGTH];
};

#define KEY_DIRECTION_BIDIRECTIONAL 0 /* same keys for both directions */
#define KEY_DIRECTION_NORMAL        1 /* encrypt with keys[0], decrypt with keys[1] */
#define KEY_DIRECTION_INVERSE       2 /* encrypt with keys[1], decrypt with keys[0] */

/*
 * Dual random keys (for encrypt/decrypt)
 */
struct key2
{
  int n;
  struct key keys[2];
};

/*
 * Used for controlling bidirectional keys
 * vs. a separate key for each direction.
 */
struct key_direction_state
{
  int out_key;
  int in_key;
  int need_keys;
};

/*
 * A key context for cipher and/or HMAC.
 */
struct key_ctx
{
  EVP_CIPHER_CTX *cipher;
  HMAC_CTX *hmac;
};

/*
 * Cipher/HMAC key context for both sending and receiving
 * directions.
 */
struct key_ctx_bi
{
  struct key_ctx encrypt;
  struct key_ctx decrypt;
};

/*
 * Options for encrypt/decrypt.
 */
struct crypto_options
{
  struct key_ctx_bi *key_ctx_bi;
  struct packet_id *packet_id;
  struct packet_id_persist *pid_persist;

# define CO_PACKET_ID_LONG_FORM  (1<<0)
# define CO_USE_IV               (1<<1)
# define CO_IGNORE_PACKET_ID     (1<<2)
# define CO_MUTE_REPLAY_WARNINGS (1<<3)
  unsigned int flags;
};

void init_key_type (struct key_type *kt, const char *ciphername,
		    bool ciphername_defined, const char *authname,
		    bool authname_defined, int keysize,
		    bool cfb_ofb_allowed, bool warn);

#define RKF_MUST_SUCCEED (1<<0)
#define RKF_INLINE       (1<<1)
void read_key_file (struct key2 *key2, const char *file, const unsigned int flags);

int write_key_file (const int nkeys, const char *filename);

int read_passphrase_hash (const char *passphrase_file,
			  const EVP_MD *digest,
			  uint8_t *output,
			  int len);

void generate_key_random (struct key *key, const struct key_type *kt);

void check_replay_iv_consistency(const struct key_type *kt, bool packet_id, bool use_iv);

bool check_key (struct key *key, const struct key_type *kt);

void fixup_key (struct key *key, const struct key_type *kt);

bool write_key (const struct key *key, const struct key_type *kt,
		struct buffer *buf);

int read_key (struct key *key, const struct key_type *kt, struct buffer *buf);

bool cfb_ofb_mode (const struct key_type* kt);

const char *kt_cipher_name (const struct key_type *kt);
const char *kt_digest_name (const struct key_type *kt);
int kt_key_size (const struct key_type *kt);

/* enc parameter in init_key_ctx */
#define DO_ENCRYPT 1
#define DO_DECRYPT 0

void init_key_ctx (struct key_ctx *ctx, struct key *key,
		   const struct key_type *kt, int enc,
		   const char *prefix);

void free_key_ctx (struct key_ctx *ctx);
void free_key_ctx_bi (struct key_ctx_bi *ctx);

void openvpn_encrypt (struct buffer *buf, struct buffer work,
		      const struct crypto_options *opt,
		      const struct frame* frame);

bool openvpn_decrypt (struct buffer *buf, struct buffer work,
		      const struct crypto_options *opt,
		      const struct frame* frame);


void crypto_adjust_frame_parameters(struct frame *frame,
				    const struct key_type* kt,
				    bool cipher_defined,
				    bool use_iv,
				    bool packet_id,
				    bool packet_id_long_form);

#define NONCE_SECRET_LEN_MIN 16
#define NONCE_SECRET_LEN_MAX 64
void prng_init (const char *md_name, const int nonce_secret_len_parm);
void prng_bytes (uint8_t *output, int len);
void prng_uninit ();

void test_crypto (const struct crypto_options *co, struct frame* f);

const char *md5sum(uint8_t *buf, int len, int n_print_chars, struct gc_arena *gc);

void show_available_ciphers (void);

void show_available_digests (void);

void show_available_engines (void);

void init_crypto_lib_engine (const char *engine_name);

void init_crypto_lib (void);

void uninit_crypto_lib (void);

/* key direction functions */

void key_direction_state_init (struct key_direction_state *kds, int key_direction);

void verify_fix_key2 (struct key2 *key2, const struct key_type *kt, const char *shared_secret_file);

void must_have_n_keys (const char *filename, const char *option, const struct key2 *key2, int n);

int ascii2keydirection (int msglevel, const char *str);

const char *keydirection2ascii (int kd, bool remote);

/* print keys */
void key2_print (const struct key2* k,
		 const struct key_type *kt,
		 const char* prefix0,
		 const char* prefix1);

/* memory debugging */
void openssl_dmalloc_init (void);

#ifdef USE_SSL

#define GHK_INLINE  (1<<0)
void get_tls_handshake_key (const struct key_type *key_type,
			    struct key_ctx_bi *ctx,
			    const char *passphrase_file,
			    const int key_direction,
			    const unsigned int flags);

#else

void init_ssl_lib (void);
void free_ssl_lib (void);

#endif /* USE_SSL */

/*
 * Inline functions
 */

static inline bool
key_ctx_bi_defined(const struct key_ctx_bi* key)
{
  return key->encrypt.cipher || key->encrypt.hmac || key->decrypt.cipher || key->decrypt.hmac;
}

/*
 * md5 functions
 */

struct md5_state {
  MD5_CTX ctx;
};

struct md5_digest {
  uint8_t digest [MD5_DIGEST_LENGTH];
};

void md5_state_init (struct md5_state *s);
void md5_state_update (struct md5_state *s, void *data, size_t len);
void md5_state_final (struct md5_state *s, struct md5_digest *out);
void md5_digest_clear (struct md5_digest *digest);
bool md5_digest_defined (const struct md5_digest *digest);
bool md5_digest_equal (const struct md5_digest *d1, const struct md5_digest *d2);

#endif /* USE_CRYPTO */
#endif /* CRYPTO_H */
