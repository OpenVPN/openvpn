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

#ifdef HAVE_CONFIG_H
#include "config.h"
#elif defined(_MSC_VER)
#include "config-msvc.h"
#endif

#include "syshead.h"

#if defined(ENABLE_CRYPTO) && defined(ENABLE_CRYPTO_POLARSSL)

#include "errlevel.h"
#include "basic.h"
#include "buffer.h"
#include "integer.h"
#include "crypto_backend.h"
#include "otime.h"
#include "misc.h"

#include <polarssl/des.h>
#include <polarssl/md5.h>
#include <polarssl/cipher.h>
#include <polarssl/havege.h>

#include <polarssl/entropy.h>

/*
 *
 * Hardware engine support. Allows loading/unloading of engines.
 *
 */

void
crypto_init_lib_engine (const char *engine_name)
{
  msg (M_WARN, "Note: PolarSSL hardware crypto engine functionality is not "
      "available");
}

/*
 *
 * Functions related to the core crypto library
 *
 */

void
crypto_init_lib (void)
{
}

void
crypto_uninit_lib (void)
{
}

void
crypto_clear_error (void)
{
}

#ifdef DMALLOC
void
crypto_init_dmalloc (void)
{
  msg (M_ERR, "Error: dmalloc support is not available for PolarSSL.");
}
#endif /* DMALLOC */

typedef struct { const char * openvpn_name; const char * polarssl_name; } cipher_name_pair;
cipher_name_pair cipher_name_translation_table[] = {
    { "BF-CBC", "BLOWFISH-CBC" },
    { "BF-CFB", "BLOWFISH-CFB64" },
    { "CAMELLIA-128-CFB", "CAMELLIA-128-CFB128" },
    { "CAMELLIA-192-CFB", "CAMELLIA-192-CFB128" },
    { "CAMELLIA-256-CFB", "CAMELLIA-256-CFB128" }
};

const cipher_name_pair *
get_cipher_name_pair(const char *cipher_name) {
  cipher_name_pair *pair;
  size_t i = 0;

  /* Search for a cipher name translation */
  for (; i < sizeof (cipher_name_translation_table) / sizeof (*cipher_name_translation_table); i++)
    {
      pair = &cipher_name_translation_table[i];
      if (0 == strcmp (cipher_name, pair->openvpn_name) ||
	  0 == strcmp (cipher_name, pair->polarssl_name))
	  return pair;
    }

  /* Nothing found, return null */
  return NULL;
}

const char *
translate_cipher_name_from_openvpn (const char *cipher_name) {
  const cipher_name_pair *pair = get_cipher_name_pair(cipher_name);

  if (NULL == pair)
    return cipher_name;

  return pair->polarssl_name;
}

const char *
translate_cipher_name_to_openvpn (const char *cipher_name) {
  const cipher_name_pair *pair = get_cipher_name_pair(cipher_name);

  if (NULL == pair)
    return cipher_name;

  return pair->openvpn_name;
}

void
show_available_ciphers ()
{
  const int *ciphers = cipher_list();

#ifndef ENABLE_SMALL
  printf ("The following ciphers and cipher modes are available\n"
	  "for use with " PACKAGE_NAME ".  Each cipher shown below may be\n"
	  "used as a parameter to the --cipher option.  The default\n"
	  "key size is shown as well as whether or not it can be\n"
          "changed with the --keysize directive.  Using a CBC mode\n"
	  "is recommended.\n\n");
#endif

  while (*ciphers != 0)
    {
      const cipher_info_t *info = cipher_info_from_type(*ciphers);

      if (info && info->mode == POLARSSL_MODE_CBC)
	printf ("%s %d bit default key\n",
		cipher_kt_name(info), cipher_kt_key_size(info) * 8);

      ciphers++;
    }
  printf ("\n");
}

void
show_available_digests ()
{
  const int *digests = md_list();

#ifndef ENABLE_SMALL
  printf ("The following message digests are available for use with\n"
	  PACKAGE_NAME ".  A message digest is used in conjunction with\n"
	  "the HMAC function, to authenticate received packets.\n"
	  "You can specify a message digest as parameter to\n"
	  "the --auth option.\n\n");
#endif

  while (*digests != 0)
    {
      const md_info_t *info = md_info_from_type(*digests);

      if (info)
	printf ("%s %d bit default key\n",
		info->name, info->size * 8);
      digests++;
    }
  printf ("\n");
}

void
show_available_engines ()
{
  printf ("Sorry, PolarSSL hardware crypto engine functionality is not "
      "available\n");
}

/*
 *
 * Random number functions, used in cases where we want
 * reasonably strong cryptographic random number generation
 * without depleting our entropy pool.  Used for random
 * IV values and a number of other miscellaneous tasks.
 *
 */

/*
 * Initialise the given ctr_drbg context, using a personalisation string and an
 * entropy gathering function.
 */
ctr_drbg_context * rand_ctx_get()
{
  static entropy_context ec = {0};
  static ctr_drbg_context cd_ctx = {0};
  static bool rand_initialised = false;

  if (!rand_initialised)
    {
      struct gc_arena gc = gc_new();
      struct buffer pers_string = alloc_buf_gc(100, &gc);

      /*
       * Personalisation string, should be as unique as possible (see NIST
       * 800-90 section 8.7.1). We have very little information at this stage.
       * Include Program Name, memory address of the context and PID.
       */
      buf_printf(&pers_string, "OpenVPN %0u %p %s", platform_getpid(), &cd_ctx, time_string(0, 0, 0, &gc));

      /* Initialise PolarSSL RNG, and built-in entropy sources */
      entropy_init(&ec);

      if (0 != ctr_drbg_init(&cd_ctx, entropy_func, &ec, BPTR(&pers_string), BLEN(&pers_string)))
        msg (M_FATAL, "Failed to initialize random generator");

      gc_free(&gc);
      rand_initialised = true;
  }

  return &cd_ctx;
}

#ifdef ENABLE_PREDICTION_RESISTANCE
void rand_ctx_enable_prediction_resistance()
{
  ctr_drbg_context *cd_ctx = rand_ctx_get();

  ctr_drbg_set_prediction_resistance(cd_ctx, 1);
}
#endif /* ENABLE_PREDICTION_RESISTANCE */

int
rand_bytes (uint8_t *output, int len)
{
  ctr_drbg_context *rng_ctx = rand_ctx_get();

  while (len > 0)
    {
      const size_t blen = min_int (len, CTR_DRBG_MAX_REQUEST);
      if (0 != ctr_drbg_random(rng_ctx, output, blen))
	return 0;

      output += blen;
      len -= blen;
    }

  return 1;
}

/*
 *
 * Key functions, allow manipulation of keys.
 *
 */


int
key_des_num_cblocks (const cipher_info_t *kt)
{
  int ret = 0;
  if (kt->type == POLARSSL_CIPHER_DES_CBC)
    ret = 1;
  if (kt->type == POLARSSL_CIPHER_DES_EDE_CBC)
    ret = 2;
  if (kt->type == POLARSSL_CIPHER_DES_EDE3_CBC)
    ret = 3;

  dmsg (D_CRYPTO_DEBUG, "CRYPTO INFO: n_DES_cblocks=%d", ret);
  return ret;
}

bool
key_des_check (uint8_t *key, int key_len, int ndc)
{
  int i;
  struct buffer b;

  buf_set_read (&b, key, key_len);

  for (i = 0; i < ndc; ++i)
    {
      unsigned char *key = buf_read_alloc(&b, DES_KEY_SIZE);
      if (!key)
	{
	  msg (D_CRYPT_ERRORS, "CRYPTO INFO: check_key_DES: insufficient key material");
	  goto err;
	}
      if (0 != des_key_check_weak(key))
	{
	  msg (D_CRYPT_ERRORS, "CRYPTO INFO: check_key_DES: weak key detected");
	  goto err;
	}
      if (0 != des_key_check_key_parity(key))
	{
	  msg (D_CRYPT_ERRORS, "CRYPTO INFO: check_key_DES: bad parity detected");
	  goto err;
	}
    }
  return true;

 err:
  return false;
}

void
key_des_fixup (uint8_t *key, int key_len, int ndc)
{
  int i;
  struct buffer b;

  buf_set_read (&b, key, key_len);
  for (i = 0; i < ndc; ++i)
    {
      unsigned char *key = buf_read_alloc(&b, DES_KEY_SIZE);
      if (!key)
	{
	  msg (D_CRYPT_ERRORS, "CRYPTO INFO: fixup_key_DES: insufficient key material");
	  return;
	}
      des_key_set_parity(key);
    }
}

/*
 *
 * Generic cipher key type functions
 *
 */


const cipher_info_t *
cipher_kt_get (const char *ciphername)
{
  const cipher_info_t *cipher = NULL;

  ASSERT (ciphername);

  cipher = cipher_info_from_string(ciphername);

  if (NULL == cipher)
    msg (M_FATAL, "Cipher algorithm '%s' not found", ciphername);

  if (cipher->key_length/8 > MAX_CIPHER_KEY_LENGTH)
    msg (M_FATAL, "Cipher algorithm '%s' uses a default key size (%d bytes) which is larger than " PACKAGE_NAME "'s current maximum key size (%d bytes)",
	 ciphername,
	 cipher->key_length/8,
	 MAX_CIPHER_KEY_LENGTH);

  return cipher;
}

const char *
cipher_kt_name (const cipher_info_t *cipher_kt)
{
  if (NULL == cipher_kt)
    return "[null-cipher]";

  return translate_cipher_name_to_openvpn(cipher_kt->name);
}

int
cipher_kt_key_size (const cipher_info_t *cipher_kt)
{
  if (NULL == cipher_kt)
    return 0;
  if (POLARSSL_CIPHER_ID_BLOWFISH == cipher_kt->base->cipher)
    return 128/8; /* Override PolarSSL 32 bit default key size with sane 128 bit default */

  return cipher_kt->key_length/8;
}

int
cipher_kt_iv_size (const cipher_info_t *cipher_kt)
{
  if (NULL == cipher_kt)
    return 0;
  return cipher_kt->iv_size;
}

int
cipher_kt_block_size (const cipher_info_t *cipher_kt)
{
  if (NULL == cipher_kt)
    return 0;
  return cipher_kt->block_size;
}

int
cipher_kt_mode (const cipher_info_t *cipher_kt)
{
  ASSERT(NULL != cipher_kt);
  return cipher_kt->mode;
}

bool
cipher_kt_mode_cbc(const cipher_kt_t *cipher)
{
  return cipher && cipher_kt_mode(cipher) == OPENVPN_MODE_CBC;
}

bool
cipher_kt_mode_ofb_cfb(const cipher_kt_t *cipher)
{
  return cipher && (cipher_kt_mode(cipher) == OPENVPN_MODE_OFB ||
	  cipher_kt_mode(cipher) == OPENVPN_MODE_CFB);
}


/*
 *
 * Generic cipher context functions
 *
 */


void
cipher_ctx_init (cipher_context_t *ctx, uint8_t *key, int key_len,
    const cipher_info_t *kt, int enc)
{
  ASSERT(NULL != kt && NULL != ctx);

  CLEAR (*ctx);

  if (0 != cipher_init_ctx(ctx, kt))
    msg (M_FATAL, "PolarSSL cipher context init #1");

  if (0 != cipher_setkey(ctx, key, key_len*8, enc))
    msg (M_FATAL, "PolarSSL cipher set key");

  /* make sure we used a big enough key */
  ASSERT (ctx->key_length <= key_len*8);
}

void cipher_ctx_cleanup (cipher_context_t *ctx)
{
  cipher_free_ctx(ctx);
}

int cipher_ctx_iv_length (const cipher_context_t *ctx)
{
  return cipher_get_iv_size(ctx);
}

int cipher_ctx_block_size(const cipher_context_t *ctx)
{
  return cipher_get_block_size(ctx);
}

int cipher_ctx_mode (const cipher_context_t *ctx)
{
  ASSERT(NULL != ctx);

  return cipher_kt_mode(ctx->cipher_info);
}

const cipher_kt_t *
cipher_ctx_get_cipher_kt (const cipher_ctx_t *ctx)
{
  ASSERT(NULL != ctx);

  return ctx->cipher_info;
}

int cipher_ctx_reset (cipher_context_t *ctx, uint8_t *iv_buf)
{
  return 0 == cipher_reset(ctx, iv_buf);
}

int cipher_ctx_update (cipher_context_t *ctx, uint8_t *dst, int *dst_len,
    uint8_t *src, int src_len)
{
  int retval = 0;
  size_t s_dst_len = *dst_len;

  retval = cipher_update(ctx, src, (size_t)src_len, dst, &s_dst_len);

  *dst_len = s_dst_len;

  return 0 == retval;
}

int cipher_ctx_final (cipher_context_t *ctx, uint8_t *dst, int *dst_len)
{
  int retval = 0;
  size_t s_dst_len = *dst_len;

  retval = cipher_finish(ctx, dst, &s_dst_len);
  *dst_len = s_dst_len;

  return 0 == retval;
}

void
cipher_des_encrypt_ecb (const unsigned char key[DES_KEY_LENGTH],
    unsigned char *src,
    unsigned char *dst)
{
    des_context ctx;

    des_setkey_enc(&ctx, key);
    des_crypt_ecb(&ctx, src, dst);
}



/*
 *
 * Generic message digest information functions
 *
 */


const md_info_t *
md_kt_get (const char *digest)
{
  const md_info_t *md = NULL;
  ASSERT (digest);

  md = md_info_from_string(digest);
  if (!md)
    msg (M_FATAL, "Message hash algorithm '%s' not found", digest);
  if (md->size > MAX_HMAC_KEY_LENGTH)
    msg (M_FATAL, "Message hash algorithm '%s' uses a default hash size (%d bytes) which is larger than " PACKAGE_NAME "'s current maximum hash size (%d bytes)",
	 digest,
	 md->size,
	 MAX_HMAC_KEY_LENGTH);
  return md;
}

const char *
md_kt_name (const md_info_t *kt)
{
  if (NULL == kt)
    return "[null-digest]";
  return md_get_name (kt);
}

int
md_kt_size (const md_info_t *kt)
{
  if (NULL == kt)
    return 0;
  return md_get_size(kt);
}

/*
 *
 * Generic message digest functions
 *
 */

int
md_full (const md_kt_t *kt, const uint8_t *src, int src_len, uint8_t *dst)
{
  return 0 == md(kt, src, src_len, dst);
}


void
md_ctx_init (md_context_t *ctx, const md_info_t *kt)
{
  ASSERT(NULL != ctx && NULL != kt);

  CLEAR(*ctx);

  ASSERT(0 == md_init_ctx(ctx, kt));
  ASSERT(0 == md_starts(ctx));
}

void
md_ctx_cleanup(md_context_t *ctx)
{
}

int
md_ctx_size (const md_context_t *ctx)
{
  if (NULL == ctx)
    return 0;
  return md_get_size(ctx->md_info);
}

void
md_ctx_update (md_context_t *ctx, const uint8_t *src, int src_len)
{
  ASSERT(0 == md_update(ctx, src, src_len));
}

void
md_ctx_final (md_context_t *ctx, uint8_t *dst)
{
  ASSERT(0 == md_finish(ctx, dst));
  ASSERT(0 == md_free_ctx(ctx));
}


/*
 *
 * Generic HMAC functions
 *
 */


/*
 * TODO: re-enable dmsg for crypto debug
 */
void
hmac_ctx_init (md_context_t *ctx, const uint8_t *key, int key_len, const md_info_t *kt)
{
  ASSERT(NULL != kt && NULL != ctx);

  CLEAR(*ctx);

  ASSERT(0 == md_init_ctx(ctx, kt));
  ASSERT(0 == md_hmac_starts(ctx, key, key_len));

  /* make sure we used a big enough key */
  ASSERT (md_get_size(kt) <= key_len);
}

void
hmac_ctx_cleanup(md_context_t *ctx)
{
  ASSERT(0 == md_free_ctx(ctx));
}

int
hmac_ctx_size (const md_context_t *ctx)
{
  if (NULL == ctx)
    return 0;
  return md_get_size(ctx->md_info);
}

void
hmac_ctx_reset (md_context_t *ctx)
{
  ASSERT(0 == md_hmac_reset(ctx));
}

void
hmac_ctx_update (md_context_t *ctx, const uint8_t *src, int src_len)
{
  ASSERT(0 == md_hmac_update(ctx, src, src_len));
}

void
hmac_ctx_final (md_context_t *ctx, uint8_t *dst)
{
  ASSERT(0 == md_hmac_finish(ctx, dst));
}

#endif /* ENABLE_CRYPTO && ENABLE_CRYPTO_POLARSSL */
