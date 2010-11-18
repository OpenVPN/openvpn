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

#include "syshead.h"

#ifdef USE_CRYPTO

#include "crypto.h"
#include "error.h"
#include "misc.h"

#include "memdbg.h"

/*
 * Check for key size creepage.
 */

#if MAX_CIPHER_KEY_LENGTH < EVP_MAX_KEY_LENGTH
#warning Some OpenSSL EVP ciphers now support key lengths greater than MAX_CIPHER_KEY_LENGTH -- consider increasing MAX_CIPHER_KEY_LENGTH
#endif

#if MAX_HMAC_KEY_LENGTH < EVP_MAX_MD_SIZE
#warning Some OpenSSL HMAC message digests now support key lengths greater than MAX_HMAC_KEY_LENGTH -- consider increasing MAX_HMAC_KEY_LENGTH
#endif

/*
 * Encryption and Compression Routines.
 *
 * On entry, buf contains the input data and length.
 * On exit, it should be set to the output data and length.
 *
 * If buf->len is <= 0 we should return
 * If buf->len is set to 0 on exit it tells the caller to ignore the packet.
 *
 * work is a workspace buffer we are given of size BUF_SIZE.
 * work may be used to return output data, or the input buffer
 * may be modified and returned as output.  If output data is
 * returned in work, the data should start after FRAME_HEADROOM bytes
 * of padding to leave room for downstream routines to prepend.
 *
 * Up to a total of FRAME_HEADROOM bytes may be prepended to the input buf
 * by all routines (encryption, decryption, compression, and decompression).
 *
 * Note that the buf_prepend return will assert if we try to
 * make a header bigger than FRAME_HEADROOM.  This should not
 * happen unless the frame parameters are wrong.
 */

#define CRYPT_ERROR(format) \
  do { msg (D_CRYPT_ERRORS, "%s: " format, error_prefix); goto error_exit; } while (false)

void
openvpn_encrypt (struct buffer *buf, struct buffer work,
		 const struct crypto_options *opt,
		 const struct frame* frame)
{
  struct gc_arena gc;
  gc_init (&gc);

  if (buf->len > 0 && opt->key_ctx_bi)
    {
      struct key_ctx *ctx = &opt->key_ctx_bi->encrypt;

      /* Do Encrypt from buf -> work */
      if (ctx->cipher)
	{
	  uint8_t iv_buf[EVP_MAX_IV_LENGTH];
	  const int iv_size = EVP_CIPHER_CTX_iv_length (ctx->cipher);
	  const unsigned int mode = EVP_CIPHER_CTX_mode (ctx->cipher);  
	  int outlen;

	  if (mode == EVP_CIPH_CBC_MODE)
	    {
	      CLEAR (iv_buf);

	      /* generate pseudo-random IV */
	      if (opt->flags & CO_USE_IV)
		prng_bytes (iv_buf, iv_size);

	      /* Put packet ID in plaintext buffer or IV, depending on cipher mode */
	      if (opt->packet_id)
		{
		  struct packet_id_net pin;
		  packet_id_alloc_outgoing (&opt->packet_id->send, &pin, BOOL_CAST (opt->flags & CO_PACKET_ID_LONG_FORM));
		  ASSERT (packet_id_write (&pin, buf, BOOL_CAST (opt->flags & CO_PACKET_ID_LONG_FORM), true));
		}
	    }
	  else if (mode == EVP_CIPH_CFB_MODE || mode == EVP_CIPH_OFB_MODE)
	    {
	      struct packet_id_net pin;
	      struct buffer b;

	      ASSERT (opt->flags & CO_USE_IV);    /* IV and packet-ID required */
	      ASSERT (opt->packet_id); /*  for this mode. */

	      packet_id_alloc_outgoing (&opt->packet_id->send, &pin, true);
	      memset (iv_buf, 0, iv_size);
	      buf_set_write (&b, iv_buf, iv_size);
	      ASSERT (packet_id_write (&pin, &b, true, false));
	    }
	  else /* We only support CBC, CFB, or OFB modes right now */
	    {
	      ASSERT (0);
	    }

	  /* initialize work buffer with FRAME_HEADROOM bytes of prepend capacity */
	  ASSERT (buf_init (&work, FRAME_HEADROOM (frame)));

	  /* set the IV pseudo-randomly */
	  if (opt->flags & CO_USE_IV)
	    dmsg (D_PACKET_CONTENT, "ENCRYPT IV: %s", format_hex (iv_buf, iv_size, 0, &gc));

	  dmsg (D_PACKET_CONTENT, "ENCRYPT FROM: %s",
	       format_hex (BPTR (buf), BLEN (buf), 80, &gc));

	  /* cipher_ctx was already initialized with key & keylen */
	  ASSERT (EVP_CipherInit_ov (ctx->cipher, NULL, NULL, iv_buf, DO_ENCRYPT));

	  /* Buffer overflow check */
	  if (!buf_safe (&work, buf->len + EVP_CIPHER_CTX_block_size (ctx->cipher)))
	    {
	      msg (D_CRYPT_ERRORS, "ENCRYPT: buffer size error, bc=%d bo=%d bl=%d wc=%d wo=%d wl=%d cbs=%d",
		   buf->capacity,
		   buf->offset,
		   buf->len,
		   work.capacity,
		   work.offset,
		   work.len,
		   EVP_CIPHER_CTX_block_size (ctx->cipher));
	      goto err;
	    }

	  /* Encrypt packet ID, payload */
	  ASSERT (EVP_CipherUpdate_ov (ctx->cipher, BPTR (&work), &outlen, BPTR (buf), BLEN (buf)));
	  work.len += outlen;

	  /* Flush the encryption buffer */
	  ASSERT (EVP_CipherFinal (ctx->cipher, BPTR (&work) + outlen, &outlen));
	  work.len += outlen;
	  ASSERT (outlen == iv_size);

	  /* prepend the IV to the ciphertext */
	  if (opt->flags & CO_USE_IV)
	    {
	      uint8_t *output = buf_prepend (&work, iv_size);
	      ASSERT (output);
	      memcpy (output, iv_buf, iv_size);
	    }

	  dmsg (D_PACKET_CONTENT, "ENCRYPT TO: %s",
	       format_hex (BPTR (&work), BLEN (&work), 80, &gc));
	}
      else				/* No Encryption */
	{
	  if (opt->packet_id)
	    {
	      struct packet_id_net pin;
	      packet_id_alloc_outgoing (&opt->packet_id->send, &pin, BOOL_CAST (opt->flags & CO_PACKET_ID_LONG_FORM));
	      ASSERT (packet_id_write (&pin, buf, BOOL_CAST (opt->flags & CO_PACKET_ID_LONG_FORM), true));
	    }
	  work = *buf;
	}

      /* HMAC the ciphertext (or plaintext if !cipher) */
      if (ctx->hmac)
	{
	  int hmac_len;
	  uint8_t *output;

	  HMAC_Init_ex (ctx->hmac, NULL, 0, NULL, NULL);
	  HMAC_Update (ctx->hmac, BPTR (&work), BLEN (&work));
	  output = buf_prepend (&work, HMAC_size (ctx->hmac));
	  ASSERT (output);
	  HMAC_Final (ctx->hmac, output, (unsigned int *)&hmac_len);
	  ASSERT (hmac_len == HMAC_size (ctx->hmac));
	}

      *buf = work;
    }

  gc_free (&gc);
  return;

 err:
  ERR_clear_error ();
  buf->len = 0;
  gc_free (&gc);
  return;
}

/*
 * If (opt->flags & CO_USE_IV) is not NULL, we will read an IV from the packet.
 *
 * Set buf->len to 0 and return false on decrypt error.
 *
 * On success, buf is set to point to plaintext, true
 * is returned.
 */
bool
openvpn_decrypt (struct buffer *buf, struct buffer work,
		 const struct crypto_options *opt,
		 const struct frame* frame)
{
  static const char error_prefix[] = "Authenticate/Decrypt packet error";
  struct gc_arena gc;
  gc_init (&gc);

  if (buf->len > 0 && opt->key_ctx_bi)
    {
      struct key_ctx *ctx = &opt->key_ctx_bi->decrypt;
      struct packet_id_net pin;
      bool have_pin = false;

      /* Verify the HMAC */
      if (ctx->hmac)
	{
	  int hmac_len;
	  uint8_t local_hmac[MAX_HMAC_KEY_LENGTH]; /* HMAC of ciphertext computed locally */
	  int in_hmac_len;

	  HMAC_Init_ex (ctx->hmac, NULL, 0, NULL, NULL);

	  /* Assume the length of the input HMAC */
	  hmac_len = HMAC_size (ctx->hmac);

	  /* Authentication fails if insufficient data in packet for HMAC */
	  if (buf->len < hmac_len)
	    CRYPT_ERROR ("missing authentication info");

	  HMAC_Update (ctx->hmac, BPTR (buf) + hmac_len,
		       BLEN (buf) - hmac_len);
	  HMAC_Final (ctx->hmac, local_hmac, (unsigned int *)&in_hmac_len);
	  ASSERT (hmac_len == in_hmac_len);

	  /* Compare locally computed HMAC with packet HMAC */
	  if (memcmp (local_hmac, BPTR (buf), hmac_len))
	    CRYPT_ERROR ("packet HMAC authentication failed");

	  ASSERT (buf_advance (buf, hmac_len));
	}

      /* Decrypt packet ID + payload */

      if (ctx->cipher)
	{
	  const unsigned int mode = EVP_CIPHER_CTX_mode (ctx->cipher);
	  const int iv_size = EVP_CIPHER_CTX_iv_length (ctx->cipher);
	  uint8_t iv_buf[EVP_MAX_IV_LENGTH];
	  int outlen;

	  /* initialize work buffer with FRAME_HEADROOM bytes of prepend capacity */
	  ASSERT (buf_init (&work, FRAME_HEADROOM_ADJ (frame, FRAME_HEADROOM_MARKER_DECRYPT)));

	  /* use IV if user requested it */
	  CLEAR (iv_buf);
	  if (opt->flags & CO_USE_IV)
	    {
	      if (buf->len < iv_size)
		CRYPT_ERROR ("missing IV info");
	      memcpy (iv_buf, BPTR (buf), iv_size);
	      ASSERT (buf_advance (buf, iv_size));
	    }

	  /* show the IV's initial state */
	  if (opt->flags & CO_USE_IV)
	    dmsg (D_PACKET_CONTENT, "DECRYPT IV: %s", format_hex (iv_buf, iv_size, 0, &gc));

	  if (buf->len < 1)
	    CRYPT_ERROR ("missing payload");

	  /* ctx->cipher was already initialized with key & keylen */
	  if (!EVP_CipherInit_ov (ctx->cipher, NULL, NULL, iv_buf, DO_DECRYPT))
	    CRYPT_ERROR ("cipher init failed");

	  /* Buffer overflow check (should never happen) */
	  if (!buf_safe (&work, buf->len))
	    CRYPT_ERROR ("buffer overflow");

	  /* Decrypt packet ID, payload */
	  if (!EVP_CipherUpdate_ov (ctx->cipher, BPTR (&work), &outlen, BPTR (buf), BLEN (buf)))
	    CRYPT_ERROR ("cipher update failed");
	  work.len += outlen;

	  /* Flush the decryption buffer */
	  if (!EVP_CipherFinal (ctx->cipher, BPTR (&work) + outlen, &outlen))
	    CRYPT_ERROR ("cipher final failed");
	  work.len += outlen;

	  dmsg (D_PACKET_CONTENT, "DECRYPT TO: %s",
	       format_hex (BPTR (&work), BLEN (&work), 80, &gc));

	  /* Get packet ID from plaintext buffer or IV, depending on cipher mode */
	  {
	    if (mode == EVP_CIPH_CBC_MODE)
	      {
		if (opt->packet_id)
		  {
		    if (!packet_id_read (&pin, &work, BOOL_CAST (opt->flags & CO_PACKET_ID_LONG_FORM)))
		      CRYPT_ERROR ("error reading CBC packet-id");
		    have_pin = true;
		  }
	      }
	    else if (mode == EVP_CIPH_CFB_MODE || mode == EVP_CIPH_OFB_MODE)
	      {
		struct buffer b;

		ASSERT (opt->flags & CO_USE_IV);    /* IV and packet-ID required */
		ASSERT (opt->packet_id); /*  for this mode. */

		buf_set_read (&b, iv_buf, iv_size);
		if (!packet_id_read (&pin, &b, true))
		  CRYPT_ERROR ("error reading CFB/OFB packet-id");
		have_pin = true;
	      }
	    else /* We only support CBC, CFB, or OFB modes right now */
	      {
		ASSERT (0);
	      }
	  }
	}
      else
	{
	  work = *buf;
	  if (opt->packet_id)
	    {
	      if (!packet_id_read (&pin, &work, BOOL_CAST (opt->flags & CO_PACKET_ID_LONG_FORM)))
		CRYPT_ERROR ("error reading packet-id");
	      have_pin = !BOOL_CAST (opt->flags & CO_IGNORE_PACKET_ID);
	    }
	}
      
      if (have_pin)
	{
	  packet_id_reap_test (&opt->packet_id->rec);
	  if (packet_id_test (&opt->packet_id->rec, &pin))
	    {
	      packet_id_add (&opt->packet_id->rec, &pin);
	      if (opt->pid_persist && (opt->flags & CO_PACKET_ID_LONG_FORM))
		packet_id_persist_save_obj (opt->pid_persist, opt->packet_id);
	    }
	  else
	    {
	      if (!(opt->flags & CO_MUTE_REPLAY_WARNINGS))
	      msg (D_REPLAY_ERRORS, "%s: bad packet ID (may be a replay): %s -- see the man page entry for --no-replay and --replay-window for more info or silence this warning with --mute-replay-warnings",
		   error_prefix, packet_id_net_print (&pin, true, &gc));
	      goto error_exit;
	    }
	}
      *buf = work;
    }

  gc_free (&gc);
  return true;

 error_exit:
  ERR_clear_error ();
  buf->len = 0;
  gc_free (&gc);
  return false;
}

/*
 * How many bytes will we add to frame buffer for a given
 * set of crypto options?
 */
void
crypto_adjust_frame_parameters(struct frame *frame,
			       const struct key_type* kt,
			       bool cipher_defined,
			       bool use_iv,
			       bool packet_id,
			       bool packet_id_long_form)
{
  frame_add_to_extra_frame (frame,
			    (packet_id ? packet_id_size (packet_id_long_form) : 0) +
			    ((cipher_defined && use_iv) ? EVP_CIPHER_iv_length (kt->cipher) : 0) +
			    (cipher_defined ? EVP_CIPHER_block_size (kt->cipher) : 0) + /* worst case padding expansion */
			    kt->hmac_length);
}

static const EVP_CIPHER *
get_cipher (const char *ciphername)
{
  const EVP_CIPHER *cipher = NULL;
  ASSERT (ciphername);
  cipher = EVP_get_cipherbyname (ciphername);
  if ( !(cipher && cipher_ok (OBJ_nid2sn (EVP_CIPHER_nid (cipher)))))
    msg (M_SSLERR, "Cipher algorithm '%s' not found", ciphername);
  if (EVP_CIPHER_key_length (cipher) > MAX_CIPHER_KEY_LENGTH)
    msg (M_FATAL, "Cipher algorithm '%s' uses a default key size (%d bytes) which is larger than " PACKAGE_NAME "'s current maximum key size (%d bytes)",
	 ciphername,
	 EVP_CIPHER_key_length (cipher),
	 MAX_CIPHER_KEY_LENGTH);
  return cipher;
}

static const EVP_MD *
get_md (const char *digest)
{
  const EVP_MD *md = NULL;
  ASSERT (digest);
  md = EVP_get_digestbyname (digest);
  if (!md)
    msg (M_SSLERR, "Message hash algorithm '%s' not found", digest);
  if (EVP_MD_size (md) > MAX_HMAC_KEY_LENGTH)
    msg (M_FATAL, "Message hash algorithm '%s' uses a default hash size (%d bytes) which is larger than " PACKAGE_NAME "'s current maximum hash size (%d bytes)",
	 digest,
	 EVP_MD_size (md),
	 MAX_HMAC_KEY_LENGTH);
  return md;
}

static void
init_cipher (EVP_CIPHER_CTX *ctx, const EVP_CIPHER *cipher,
	     struct key *key, const struct key_type *kt, int enc,
	     const char *prefix)
{
  struct gc_arena gc = gc_new ();

  EVP_CIPHER_CTX_init (ctx);
  if (!EVP_CipherInit_ov (ctx, cipher, NULL, NULL, enc))
    msg (M_SSLERR, "EVP cipher init #1");
#ifdef HAVE_EVP_CIPHER_CTX_SET_KEY_LENGTH
  if (!EVP_CIPHER_CTX_set_key_length (ctx, kt->cipher_length))
    msg (M_SSLERR, "EVP set key size");
#endif
  if (!EVP_CipherInit_ov (ctx, NULL, key->cipher, NULL, enc))
    msg (M_SSLERR, "EVP cipher init #2");

  msg (D_HANDSHAKE, "%s: Cipher '%s' initialized with %d bit key",
       prefix,
       OBJ_nid2sn (EVP_CIPHER_CTX_nid (ctx)),
       EVP_CIPHER_CTX_key_length (ctx) * 8);

  /* make sure we used a big enough key */
  ASSERT (EVP_CIPHER_CTX_key_length (ctx) <= kt->cipher_length);

  dmsg (D_SHOW_KEYS, "%s: CIPHER KEY: %s", prefix,
       format_hex (key->cipher, kt->cipher_length, 0, &gc));
  dmsg (D_CRYPTO_DEBUG, "%s: CIPHER block_size=%d iv_size=%d",
       prefix,
       EVP_CIPHER_CTX_block_size (ctx),
       EVP_CIPHER_CTX_iv_length (ctx));

  gc_free (&gc);
}

static void
init_hmac (HMAC_CTX *ctx, const EVP_MD *digest,
	   struct key *key, const struct key_type *kt, const char *prefix)
{
  struct gc_arena gc = gc_new ();

  HMAC_CTX_init (ctx);
  HMAC_Init_ex (ctx, key->hmac, kt->hmac_length, digest, NULL);
  msg (D_HANDSHAKE,
       "%s: Using %d bit message hash '%s' for HMAC authentication",
       prefix, HMAC_size (ctx) * 8, OBJ_nid2sn (EVP_MD_type (digest)));

  /* make sure we used a big enough key */
  ASSERT (HMAC_size (ctx) <= kt->hmac_length);

  dmsg (D_SHOW_KEYS, "%s: HMAC KEY: %s", prefix,
       format_hex (key->hmac, kt->hmac_length, 0, &gc));
  dmsg (D_CRYPTO_DEBUG, "%s: HMAC size=%d block_size=%d",
       prefix,
       EVP_MD_size (digest),
       EVP_MD_block_size (digest));

  gc_free (&gc);
}

/*
 * Build a struct key_type.
 */
void
init_key_type (struct key_type *kt, const char *ciphername,
	       bool ciphername_defined, const char *authname,
	       bool authname_defined, int keysize,
	       bool cfb_ofb_allowed, bool warn)
{
  CLEAR (*kt);
  if (ciphername && ciphername_defined)
    {
      kt->cipher = get_cipher (ciphername);
      kt->cipher_length = EVP_CIPHER_key_length (kt->cipher);
      if (keysize > 0 && keysize <= MAX_CIPHER_KEY_LENGTH)
	kt->cipher_length = keysize;

      /* check legal cipher mode */
      {
	const unsigned int mode = EVP_CIPHER_mode (kt->cipher);
	if (!(mode == EVP_CIPH_CBC_MODE
#ifdef ALLOW_NON_CBC_CIPHERS
	      || (cfb_ofb_allowed && (mode == EVP_CIPH_CFB_MODE || mode == EVP_CIPH_OFB_MODE))
#endif
	      ))
#ifdef ENABLE_SMALL
	  msg (M_FATAL, "Cipher '%s' mode not supported", ciphername);
#else
	  msg (M_FATAL, "Cipher '%s' uses a mode not supported by " PACKAGE_NAME " in your current configuration.  CBC mode is always supported, while CFB and OFB modes are supported only when using SSL/TLS authentication and key exchange mode, and when " PACKAGE_NAME " has been built with ALLOW_NON_CBC_CIPHERS.", ciphername);
#endif
      }
    }
  else
    {
      if (warn)
	msg (M_WARN, "******* WARNING *******: null cipher specified, no encryption will be used");
    }
  if (authname && authname_defined)
    {
      kt->digest = get_md (authname);
      kt->hmac_length = EVP_MD_size (kt->digest);
    }
  else
    {
      if (warn)
	msg (M_WARN, "******* WARNING *******: null MAC specified, no authentication will be used");
    }
}

const char *
kt_cipher_name (const struct key_type *kt)
{
  if (kt->cipher)
    return EVP_CIPHER_name (kt->cipher);
  else
    return "[null-cipher]";
}

const char *
kt_digest_name (const struct key_type *kt)
{
  if (kt->digest)
    return EVP_MD_name (kt->digest);
  else
    return "[null-digest]";
}

int
kt_key_size (const struct key_type *kt)
{
  if (kt->cipher_length)
    return kt->cipher_length * 8;
  else if (kt->cipher)
    return EVP_CIPHER_key_length (kt->cipher) * 8;
  else
    return 0;
}

/* given a key and key_type, build a key_ctx */
void
init_key_ctx (struct key_ctx *ctx, struct key *key,
	      const struct key_type *kt, int enc,
	      const char *prefix)
{
  CLEAR (*ctx);
  if (kt->cipher && kt->cipher_length > 0)
    {
      ALLOC_OBJ (ctx->cipher, EVP_CIPHER_CTX);
      init_cipher (ctx->cipher, kt->cipher, key, kt, enc, prefix);
    }
  if (kt->digest && kt->hmac_length > 0)
    {
      ALLOC_OBJ (ctx->hmac, HMAC_CTX);
      init_hmac (ctx->hmac, kt->digest, key, kt, prefix);
    }
}

void
free_key_ctx (struct key_ctx *ctx)
{
  if (ctx->cipher)
    {
      EVP_CIPHER_CTX_cleanup (ctx->cipher);
      free (ctx->cipher);
      ctx->cipher = NULL;
    }
  if (ctx->hmac)
    {
      HMAC_CTX_cleanup (ctx->hmac);
      free (ctx->hmac);
      ctx->hmac = NULL;
    }
}

void
free_key_ctx_bi (struct key_ctx_bi *ctx)
{
  free_key_ctx(&ctx->encrypt);
  free_key_ctx(&ctx->decrypt);
}

/*
 * Return number of DES cblocks for the current
 * key type or 0 if not a DES cipher.
 */
static int
n_DES_cblocks (const struct key_type *kt)
{
  int ret = 0;
  const char *name = OBJ_nid2sn (EVP_CIPHER_nid (kt->cipher));
  if (name)
    {
      if (!strncmp (name, "DES-", 4))
	{
	  ret = EVP_CIPHER_key_length (kt->cipher) / sizeof (DES_cblock);
	}
      else if (!strncmp (name, "DESX-", 5))
	{
	  ret = 1;
	}
    }
  dmsg (D_CRYPTO_DEBUG, "CRYPTO INFO: n_DES_cblocks=%d", ret);
  return ret;
}

static bool
check_key_DES (struct key *key, const struct key_type *kt, int ndc)
{
  int i;
  struct buffer b;

  buf_set_read (&b, key->cipher, kt->cipher_length);

  for (i = 0; i < ndc; ++i)
    {
      DES_cblock *dc = (DES_cblock*) buf_read_alloc (&b, sizeof (DES_cblock));
      if (!dc)
	{
	  msg (D_CRYPT_ERRORS, "CRYPTO INFO: check_key_DES: insufficient key material");
	  goto err;
	}
      if (DES_is_weak_key(dc))
	{
	  msg (D_CRYPT_ERRORS, "CRYPTO INFO: check_key_DES: weak key detected");
	  goto err;
	}
      if (!DES_check_key_parity (dc))
	{
	  msg (D_CRYPT_ERRORS, "CRYPTO INFO: check_key_DES: bad parity detected");
	  goto err;
	}
    }
  return true;

 err:
  ERR_clear_error ();
  return false;
}

static void
fixup_key_DES (struct key *key, const struct key_type *kt, int ndc)
{
  int i;
  struct buffer b;

  buf_set_read (&b, key->cipher, kt->cipher_length);
  for (i = 0; i < ndc; ++i)
    {
      DES_cblock *dc = (DES_cblock*) buf_read_alloc(&b, sizeof(DES_cblock));
      if (!dc)
	{
	  msg (D_CRYPT_ERRORS, "CRYPTO INFO: fixup_key_DES: insufficient key material");
	  ERR_clear_error ();
	  return;
	}
      DES_set_odd_parity (dc);
    }
}

static bool
key_is_zero (struct key *key, const struct key_type *kt)
{
  int i;
  for (i = 0; i < kt->cipher_length; ++i)
    if (key->cipher[i])
      return false;
  msg (D_CRYPT_ERRORS, "CRYPTO INFO: WARNING: zero key detected");
  return true;
}

/*
 * Make sure that cipher key is a valid key for current key_type.
 */
bool
check_key (struct key *key, const struct key_type *kt)
{
  if (kt->cipher)
    {
      /*
       * Check for zero key
       */
      if (key_is_zero(key, kt))
	return false;

      /*
       * Check for weak or semi-weak DES keys.
       */
      {
	const int ndc = n_DES_cblocks (kt);
	if (ndc)
	  return check_key_DES (key, kt, ndc);
	else
	  return true;
      }
    }
  return true;
}

/*
 * Make safe mutations to key to ensure it is valid,
 * such as ensuring correct parity on DES keys.
 *
 * This routine cannot guarantee it will generate a good
 * key.  You must always call check_key after this routine
 * to make sure.
 */ 
void
fixup_key (struct key *key, const struct key_type *kt)
{
  struct gc_arena gc = gc_new ();
  if (kt->cipher)
    {
#ifdef ENABLE_DEBUG
      const struct key orig = *key;
#endif
      const int ndc = n_DES_cblocks (kt);

      if (ndc)
	fixup_key_DES (key, kt, ndc);

#ifdef ENABLE_DEBUG
      if (check_debug_level (D_CRYPTO_DEBUG))
	{
	  if (memcmp (orig.cipher, key->cipher, kt->cipher_length))
	    dmsg (D_CRYPTO_DEBUG, "CRYPTO INFO: fixup_key: before=%s after=%s",
		 format_hex (orig.cipher, kt->cipher_length, 0, &gc),
		 format_hex (key->cipher, kt->cipher_length, 0, &gc));
	}
#endif
    }
  gc_free (&gc);
}

void
check_replay_iv_consistency (const struct key_type *kt, bool packet_id, bool use_iv)
{
  if (cfb_ofb_mode (kt) && !(packet_id && use_iv))
    msg (M_FATAL, "--no-replay or --no-iv cannot be used with a CFB or OFB mode cipher");
}

bool
cfb_ofb_mode (const struct key_type* kt)
{
  if (kt->cipher) {
    const unsigned int mode = EVP_CIPHER_mode (kt->cipher);
    return mode == EVP_CIPH_CFB_MODE || mode == EVP_CIPH_OFB_MODE;
  } else
    return false;
}

/*
 * Generate a random key.  If key_type is provided, make
 * sure generated key is valid for key_type.
 */
void
generate_key_random (struct key *key, const struct key_type *kt)
{
  int cipher_len = MAX_CIPHER_KEY_LENGTH;
  int hmac_len = MAX_HMAC_KEY_LENGTH;

  struct gc_arena gc = gc_new ();

  do {
    CLEAR (*key);
    if (kt)
      {
	if (kt->cipher && kt->cipher_length > 0 && kt->cipher_length <= cipher_len)
	  cipher_len = kt->cipher_length;

	if (kt->digest && kt->hmac_length > 0 && kt->hmac_length <= hmac_len)
	  hmac_len = kt->hmac_length;
      }
    if (!RAND_bytes (key->cipher, cipher_len)
	|| !RAND_bytes (key->hmac, hmac_len))
      msg (M_FATAL, "ERROR: Random number generator cannot obtain entropy for key generation");

    dmsg (D_SHOW_KEY_SOURCE, "Cipher source entropy: %s", format_hex (key->cipher, cipher_len, 0, &gc));
    dmsg (D_SHOW_KEY_SOURCE, "HMAC source entropy: %s", format_hex (key->hmac, hmac_len, 0, &gc));

    if (kt)
      fixup_key (key, kt);
  } while (kt && !check_key (key, kt));

  gc_free (&gc);
}

/*
 * Print key material
 */
void
key2_print (const struct key2* k,
	    const struct key_type *kt,
	    const char* prefix0,
	    const char* prefix1)
{
  struct gc_arena gc = gc_new ();
  ASSERT (k->n == 2);
  dmsg (D_SHOW_KEY_SOURCE, "%s (cipher): %s",
       prefix0,
       format_hex (k->keys[0].cipher, kt->cipher_length, 0, &gc));
  dmsg (D_SHOW_KEY_SOURCE, "%s (hmac): %s",
       prefix0,
       format_hex (k->keys[0].hmac, kt->hmac_length, 0, &gc));
  dmsg (D_SHOW_KEY_SOURCE, "%s (cipher): %s",
       prefix1,
       format_hex (k->keys[1].cipher, kt->cipher_length, 0, &gc));
  dmsg (D_SHOW_KEY_SOURCE, "%s (hmac): %s",
       prefix1,
       format_hex (k->keys[1].hmac, kt->hmac_length, 0, &gc));
  gc_free (&gc);
}

void
test_crypto (const struct crypto_options *co, struct frame* frame)
{
  int i, j;
  struct gc_arena gc = gc_new ();
  struct buffer src = alloc_buf_gc (TUN_MTU_SIZE (frame), &gc);
  struct buffer work = alloc_buf_gc (BUF_SIZE (frame), &gc);
  struct buffer encrypt_workspace = alloc_buf_gc (BUF_SIZE (frame), &gc);
  struct buffer decrypt_workspace = alloc_buf_gc (BUF_SIZE (frame), &gc);
  struct buffer buf = clear_buf();

  /* init work */
  ASSERT (buf_init (&work, FRAME_HEADROOM (frame)));

  msg (M_INFO, "Entering " PACKAGE_NAME " crypto self-test mode.");
  for (i = 1; i <= TUN_MTU_SIZE (frame); ++i)
    {
      update_time ();

      msg (M_INFO, "TESTING ENCRYPT/DECRYPT of packet length=%d", i);

      /*
       * Load src with random data.
       */
      ASSERT (buf_init (&src, 0));
      ASSERT (i <= src.capacity);
      src.len = i;
      ASSERT (RAND_pseudo_bytes (BPTR (&src), BLEN (&src)));

      /* copy source to input buf */
      buf = work;
      memcpy (buf_write_alloc (&buf, BLEN (&src)), BPTR (&src), BLEN (&src));

      /* encrypt */
      openvpn_encrypt (&buf, encrypt_workspace, co, frame);

      /* decrypt */
      openvpn_decrypt (&buf, decrypt_workspace, co, frame);

      /* compare */
      if (buf.len != src.len)
	msg (M_FATAL, "SELF TEST FAILED, src.len=%d buf.len=%d", src.len, buf.len);
      for (j = 0; j < i; ++j)
	{
	  const uint8_t in = *(BPTR (&src) + j);
	  const uint8_t out = *(BPTR (&buf) + j);
	  if (in != out)
	    msg (M_FATAL, "SELF TEST FAILED, pos=%d in=%d out=%d", j, in, out);
	}
    }
  msg (M_INFO, PACKAGE_NAME " crypto self-test mode SUCCEEDED.");
  gc_free (&gc);
}

#ifdef USE_SSL

void
get_tls_handshake_key (const struct key_type *key_type,
		       struct key_ctx_bi *ctx,
		       const char *passphrase_file,
		       const int key_direction,
		       const unsigned int flags)
{
  if (passphrase_file && key_type->hmac_length)
    {
      struct key2 key2;
      struct key_type kt = *key_type;
      struct key_direction_state kds;

      /* for control channel we are only authenticating, not encrypting */
      kt.cipher_length = 0;
      kt.cipher = NULL;

#if ENABLE_INLINE_FILES
      if (flags & GHK_INLINE)
	{
	  /* key was specified inline, key text is in passphrase_file */
	  read_key_file (&key2, passphrase_file, RKF_INLINE|RKF_MUST_SUCCEED);

	  /* succeeded? */
	  if (key2.n == 2)
	    msg (M_INFO, "Control Channel Authentication: tls-auth using INLINE static key file");
	  else
	    msg (M_FATAL, "INLINE tls-auth file lacks the requisite 2 keys");
	}
      else
#endif
      {
	/* first try to parse as an OpenVPN static key file */
	read_key_file (&key2, passphrase_file, 0);

	/* succeeded? */
	if (key2.n == 2)
	  {
	    msg (M_INFO,
		 "Control Channel Authentication: using '%s' as a " PACKAGE_NAME " static key file",
		 passphrase_file);
	  }
	else
	  {
	    int hash_size;

	    CLEAR (key2);

	    /* failed, now try to get hash from a freeform file */
	    hash_size = read_passphrase_hash (passphrase_file,
					      kt.digest,
					      key2.keys[0].hmac,
					      MAX_HMAC_KEY_LENGTH);
	    ASSERT (hash_size == kt.hmac_length);

	    /* suceeded */
	    key2.n = 1;

	    msg (M_INFO,
		 "Control Channel Authentication: using '%s' as a free-form passphrase file",
		 passphrase_file);
	  }
      }
      /* handle key direction */

      key_direction_state_init (&kds, key_direction);
      must_have_n_keys (passphrase_file, "tls-auth", &key2, kds.need_keys);

      /* initialize hmac key in both directions */

      init_key_ctx (&ctx->encrypt, &key2.keys[kds.out_key], &kt, DO_ENCRYPT,
		    "Outgoing Control Channel Authentication");
      init_key_ctx (&ctx->decrypt, &key2.keys[kds.in_key], &kt, DO_DECRYPT,
		    "Incoming Control Channel Authentication");

      CLEAR (key2);
    }
  else
    {
      CLEAR (*ctx);
    }
}
#endif

/* header and footer for static key file */
static const char static_key_head[] = "-----BEGIN OpenVPN Static key V1-----";
static const char static_key_foot[] = "-----END OpenVPN Static key V1-----";

static const char printable_char_fmt[] =
  "Non-Hex character ('%c') found at line %d in key file '%s' (%d/%d/%d bytes found/min/max)";

static const char unprintable_char_fmt[] =
  "Non-Hex, unprintable character (0x%02x) found at line %d in key file '%s' (%d/%d/%d bytes found/min/max)";

/* read key from file */

void
read_key_file (struct key2 *key2, const char *file, const unsigned int flags)
{
  struct gc_arena gc = gc_new ();
  struct buffer in;
  int fd, size;
  uint8_t hex_byte[3] = {0, 0, 0};
  const char *error_filename = file;

  /* parse info */
  const unsigned char *cp;
  int hb_index = 0;
  int line_num = 1;
  int line_index = 0;
  int match = 0;

  /* output */
  uint8_t* out = (uint8_t*) &key2->keys;
  const int keylen = sizeof (key2->keys);
  int count = 0;

  /* parse states */
# define PARSE_INITIAL        0
# define PARSE_HEAD           1
# define PARSE_DATA           2
# define PARSE_DATA_COMPLETE  3
# define PARSE_FOOT           4
# define PARSE_FINISHED       5
  int state = PARSE_INITIAL;

  /* constants */
  const int hlen = strlen (static_key_head);
  const int flen = strlen (static_key_foot);
  const int onekeylen = sizeof (key2->keys[0]);

  CLEAR (*key2);

  /*
   * Key can be provided as a filename in 'file' or if RKF_INLINE
   * is set, the actual key data itself in ascii form.
   */
#if ENABLE_INLINE_FILES
  if (flags & RKF_INLINE) /* 'file' is a string containing ascii representation of key */
    {
      size = strlen (file) + 1;
      buf_set_read (&in, (const uint8_t *)file, size);
      error_filename = INLINE_FILE_TAG;
    }
  else /* 'file' is a filename which refers to a file containing the ascii key */
#endif
    {
      in = alloc_buf_gc (2048, &gc);
      fd = open (file, O_RDONLY);
      if (fd == -1)
	msg (M_ERR, "Cannot open file key file '%s'", file);
      size = read (fd, in.data, in.capacity);
      if (size < 0)
	msg (M_FATAL, "Read error on key file ('%s')", file);
      if (size == in.capacity)
	msg (M_FATAL, "Key file ('%s') can be a maximum of %d bytes", file, (int)in.capacity);
      close (fd);
    }

  cp = (unsigned char *)in.data;
  while (size > 0)
    {
      const unsigned char c = *cp;

#if 0
      msg (M_INFO, "char='%c'[%d] s=%d ln=%d li=%d m=%d c=%d",
	   c, (int)c, state, line_num, line_index, match, count);
#endif

      if (c == '\n')
	{
	  line_index = match = 0;
	  ++line_num;	      
	}
      else
	{
	  /* first char of new line */
	  if (!line_index)
	    {
	      /* first char of line after header line? */
	      if (state == PARSE_HEAD)
		state = PARSE_DATA;

	      /* first char of footer */
	      if ((state == PARSE_DATA || state == PARSE_DATA_COMPLETE) && c == '-')
		state = PARSE_FOOT;
	    }

	  /* compare read chars with header line */
	  if (state == PARSE_INITIAL)
	    {
	      if (line_index < hlen && c == static_key_head[line_index])
		{
		  if (++match == hlen)
		    state = PARSE_HEAD;
		}
	    }

	  /* compare read chars with footer line */
	  if (state == PARSE_FOOT)
	    {
	      if (line_index < flen && c == static_key_foot[line_index])
		{
		  if (++match == flen)
		    state = PARSE_FINISHED;
		}
	    }

	  /* reading key */
	  if (state == PARSE_DATA)
	    {
	      if (isxdigit(c))
		{
		  ASSERT (hb_index >= 0 && hb_index < 2);
		  hex_byte[hb_index++] = c;
		  if (hb_index == 2)
		    {
		      unsigned int u;
		      ASSERT(sscanf((const char *)hex_byte, "%x", &u) == 1);
		      *out++ = u;
		      hb_index = 0;
		      if (++count == keylen)
			state = PARSE_DATA_COMPLETE;
		    }
		}
	      else if (isspace(c))
		;
	      else
		{
		  msg (M_FATAL,
		       (isprint (c) ? printable_char_fmt : unprintable_char_fmt),
		       c, line_num, error_filename, count, onekeylen, keylen);
		}
	    }
	  ++line_index;
	}
      ++cp;
      --size;
    }

  /*
   * Normally we will read either 1 or 2 keys from file.
   */
  key2->n = count / onekeylen;

  ASSERT (key2->n >= 0 && key2->n <= (int) SIZE (key2->keys));

  if (flags & RKF_MUST_SUCCEED)
    {
      if (!key2->n)
	msg (M_FATAL, "Insufficient key material or header text not found in file '%s' (%d/%d/%d bytes found/min/max)",
	     error_filename, count, onekeylen, keylen);

      if (state != PARSE_FINISHED)
	msg (M_FATAL, "Footer text not found in file '%s' (%d/%d/%d bytes found/min/max)",
	     error_filename, count, onekeylen, keylen);
    }

  /* zero file read buffer if not an inline file */
#if ENABLE_INLINE_FILES
  if (!(flags & RKF_INLINE))
#endif
    buf_clear (&in);

  if (key2->n)
    warn_if_group_others_accessible (error_filename);

#if 0
  /* DEBUGGING */
  {
    int i;
    printf ("KEY READ, n=%d\n", key2->n);
    for (i = 0; i < (int) SIZE (key2->keys); ++i)
      {
	/* format key as ascii */
	const char *fmt = format_hex_ex ((const uint8_t*)&key2->keys[i],
					 sizeof (key2->keys[i]),
					 0,
					 16,
					 "\n",
					 &gc);
	printf ("[%d]\n%s\n\n", i, fmt);
      }
  }
#endif

  /* pop our garbage collection level */
  gc_free (&gc);
}

int
read_passphrase_hash (const char *passphrase_file,
		      const EVP_MD *digest,
		      uint8_t *output,
		      int len)
{
  unsigned int outlen = 0;
  EVP_MD_CTX md;

  ASSERT (len >= EVP_MD_size (digest));
  memset (output, 0, len);

  EVP_DigestInit (&md, digest);

  /* read passphrase file */
  {
    const int min_passphrase_size = 8;
    uint8_t buf[64];
    int total_size = 0;
    int fd = open (passphrase_file, O_RDONLY);

    if (fd == -1)
      msg (M_ERR, "Cannot open passphrase file: '%s'", passphrase_file);

    for (;;)
      {
	int size = read (fd, buf, sizeof (buf));
	if (size == 0)
	  break;
	if (size == -1)
	  msg (M_ERR, "Read error on passphrase file: '%s'",
	       passphrase_file);
	EVP_DigestUpdate (&md, buf, size);
	total_size += size;
      }
    close (fd);

    warn_if_group_others_accessible (passphrase_file);

    if (total_size < min_passphrase_size)
      msg (M_FATAL,
	   "Passphrase file '%s' is too small (must have at least %d characters)",
	   passphrase_file, min_passphrase_size);
  }

  EVP_DigestFinal (&md, output, &outlen);
  EVP_MD_CTX_cleanup (&md);
  return outlen;
}

/*
 * Write key to file, return number of random bits
 * written.
 */
int
write_key_file (const int nkeys, const char *filename)
{
  struct gc_arena gc = gc_new ();

  int fd, i;
  int nbits = 0;

  /* must be large enough to hold full key file */
  struct buffer out = alloc_buf_gc (2048, &gc);
  struct buffer nbits_head_text = alloc_buf_gc (128, &gc);

  /* how to format the ascii file representation of key */
  const int bytes_per_line = 16;

  /* open key file */
  fd = open (filename, O_CREAT | O_TRUNC | O_WRONLY, S_IRUSR | S_IWUSR);

  if (fd == -1)
    msg (M_ERR, "Cannot open shared secret file '%s' for write", filename);

  buf_printf (&out, "%s\n", static_key_head);

  for (i = 0; i < nkeys; ++i)
    {
      struct key key;
      char* fmt;

      /* generate random bits */
      generate_key_random (&key, NULL);

      /* format key as ascii */
      fmt = format_hex_ex ((const uint8_t*)&key,
			   sizeof (key),
			   0,
			   bytes_per_line,
			   "\n",
			   &gc);

      /* increment random bits counter */
      nbits += sizeof (key) * 8;

      /* write to holding buffer */
      buf_printf (&out, "%s\n", fmt);

      /* zero memory which held key component (will be freed by GC) */
      memset (fmt, 0, strlen(fmt));
      CLEAR (key);
    }

  buf_printf (&out, "%s\n", static_key_foot);

  /* write number of bits */
  buf_printf (&nbits_head_text, "#\n# %d bit OpenVPN static key\n#\n", nbits);
  buf_write_string_file (&nbits_head_text, filename, fd);

  /* write key file, now formatted in out, to file */
  buf_write_string_file (&out, filename, fd);

  if (close (fd))
    msg (M_ERR, "Close error on shared secret file %s", filename);

  /* zero memory which held file content (memory will be freed by GC) */
  buf_clear (&out);

  /* pop our garbage collection level */
  gc_free (&gc);

  return nbits;
}

void
must_have_n_keys (const char *filename, const char *option, const struct key2 *key2, int n)
{
  if (key2->n < n)
    {
#ifdef ENABLE_SMALL
      msg (M_FATAL, "Key file '%s' used in --%s contains insufficient key material [keys found=%d required=%d]", filename, option, key2->n, n);
#else
      msg (M_FATAL, "Key file '%s' used in --%s contains insufficient key material [keys found=%d required=%d] -- try generating a new key file with '" PACKAGE " --genkey --secret [file]', or use the existing key file in bidirectional mode by specifying --%s without a key direction parameter", filename, option, key2->n, n, option);
#endif
    }
}

int
ascii2keydirection (int msglevel, const char *str)
{
  if (!str)
    return KEY_DIRECTION_BIDIRECTIONAL;
  else if (!strcmp (str, "0"))
    return KEY_DIRECTION_NORMAL;
  else if (!strcmp (str, "1"))
    return KEY_DIRECTION_INVERSE;
  else
    {
      msg (msglevel, "Unknown key direction '%s' -- must be '0' or '1'", str);
      return -1;
    }
  return KEY_DIRECTION_BIDIRECTIONAL; /* NOTREACHED */
}

const char *
keydirection2ascii (int kd, bool remote)
{
  if (kd == KEY_DIRECTION_BIDIRECTIONAL)
    return NULL;
  else if (kd == KEY_DIRECTION_NORMAL)
    return remote ? "1" : "0";
  else if (kd == KEY_DIRECTION_INVERSE)
    return remote ? "0" : "1";
  else
    {
      ASSERT (0);
    }
  return NULL; /* NOTREACHED */
}

void
key_direction_state_init (struct key_direction_state *kds, int key_direction)
{
  CLEAR (*kds);
  switch (key_direction)
    {
    case KEY_DIRECTION_NORMAL:
      kds->out_key = 0;
      kds->in_key = 1;
      kds->need_keys = 2;
      break;
    case KEY_DIRECTION_INVERSE:
      kds->out_key = 1;
      kds->in_key = 0;
      kds->need_keys = 2;
      break;
    case KEY_DIRECTION_BIDIRECTIONAL:
      kds->out_key = 0;
      kds->in_key = 0;
      kds->need_keys = 1;
      break;
    default:
      ASSERT (0);
    }
}

void
verify_fix_key2 (struct key2 *key2, const struct key_type *kt, const char *shared_secret_file)
{
  int i;

  for (i = 0; i < key2->n; ++i)
    {
      /* Fix parity for DES keys and make sure not a weak key */
      fixup_key (&key2->keys[i], kt);

      /* This should be a very improbable failure */
      if (!check_key (&key2->keys[i], kt))
	msg (M_FATAL, "Key #%d in '%s' is bad.  Try making a new key with --genkey.",
	     i+1, shared_secret_file);
    }
}

/* given a key and key_type, write key to buffer */
bool
write_key (const struct key *key, const struct key_type *kt,
	   struct buffer *buf)
{
  ASSERT (kt->cipher_length <= MAX_CIPHER_KEY_LENGTH
	  && kt->hmac_length <= MAX_HMAC_KEY_LENGTH);

  if (!buf_write (buf, &kt->cipher_length, 1))
    return false;
  if (!buf_write (buf, &kt->hmac_length, 1))
    return false;
  if (!buf_write (buf, key->cipher, kt->cipher_length))
    return false;
  if (!buf_write (buf, key->hmac, kt->hmac_length))
    return false;

  return true;
}

/*
 * Given a key_type and buffer, read key from buffer.
 * Return: 1 on success
 *        -1 read failure
 *         0 on key length mismatch 
 */
int
read_key (struct key *key, const struct key_type *kt, struct buffer *buf)
{
  uint8_t cipher_length;
  uint8_t hmac_length;

  CLEAR (*key);
  if (!buf_read (buf, &cipher_length, 1))
    goto read_err;
  if (!buf_read (buf, &hmac_length, 1))
    goto read_err;

  if (!buf_read (buf, key->cipher, cipher_length))
    goto read_err;
  if (!buf_read (buf, key->hmac, hmac_length))
    goto read_err;

  if (cipher_length != kt->cipher_length || hmac_length != kt->hmac_length)
    goto key_len_err;

  return 1;

read_err:
  msg (D_TLS_ERRORS, "TLS Error: error reading key from remote");
  return -1;

key_len_err:
  msg (D_TLS_ERRORS,
       "TLS Error: key length mismatch, local cipher/hmac %d/%d, remote cipher/hmac %d/%d",
       kt->cipher_length, kt->hmac_length, cipher_length, hmac_length);
  return 0;
}

void
show_available_ciphers ()
{
  int nid;


#ifndef ENABLE_SMALL
  printf ("The following ciphers and cipher modes are available\n"
	  "for use with " PACKAGE_NAME ".  Each cipher shown below may be\n"
	  "used as a parameter to the --cipher option.  The default\n"
	  "key size is shown as well as whether or not it can be\n"
          "changed with the --keysize directive.  Using a CBC mode\n"
	  "is recommended.\n\n");
#endif

  for (nid = 0; nid < 10000; ++nid)	/* is there a better way to get the size of the nid list? */
    {
      const EVP_CIPHER *cipher = EVP_get_cipherbynid (nid);
      if (cipher && cipher_ok (OBJ_nid2sn (nid)))
	{
	  const unsigned int mode = EVP_CIPHER_mode (cipher);
	  if (mode == EVP_CIPH_CBC_MODE
#ifdef ALLOW_NON_CBC_CIPHERS
	      || mode == EVP_CIPH_CFB_MODE || mode == EVP_CIPH_OFB_MODE
#endif
	      )
	    printf ("%s %d bit default key (%s)\n",
		    OBJ_nid2sn (nid),
		    EVP_CIPHER_key_length (cipher) * 8,
		    ((EVP_CIPHER_flags (cipher) & EVP_CIPH_VARIABLE_LENGTH) ?
		     "variable" : "fixed"));
	}
    }
  printf ("\n");
}

void
show_available_digests ()
{
  int nid;

#ifndef ENABLE_SMALL
  printf ("The following message digests are available for use with\n"
	  PACKAGE_NAME ".  A message digest is used in conjunction with\n"
	  "the HMAC function, to authenticate received packets.\n"
	  "You can specify a message digest as parameter to\n"
	  "the --auth option.\n\n");
#endif

  for (nid = 0; nid < 10000; ++nid)
    {
      const EVP_MD *digest = EVP_get_digestbynid (nid);
      if (digest)
	{
	  printf ("%s %d bit digest size\n",
		  OBJ_nid2sn (nid), EVP_MD_size (digest) * 8);
	}
    }
  printf ("\n");
}

void
show_available_engines ()
{
#if CRYPTO_ENGINE
  ENGINE *e;

  printf ("OpenSSL Crypto Engines\n\n");

  ENGINE_load_builtin_engines ();

  e = ENGINE_get_first ();
  while (e)
    {
      printf ("%s [%s]\n",
	      ENGINE_get_name (e),
	      ENGINE_get_id (e));
      e = ENGINE_get_next (e);
    }
  ENGINE_cleanup ();
#else
  printf ("Sorry, OpenSSL hardware crypto engine functionality is not available.\n");
#endif
}

/*
 * Enable crypto acceleration, if available
 */

static bool engine_initialized = false; /* GLOBAL */

#if CRYPTO_ENGINE

static ENGINE *engine_persist = NULL;   /* GLOBAL */

/* Try to load an engine in a shareable library */
static ENGINE *
try_load_engine (const char *engine)
{
  ENGINE *e = ENGINE_by_id ("dynamic");
  if (e)
    {
      if (!ENGINE_ctrl_cmd_string (e, "SO_PATH", engine, 0)
	  || !ENGINE_ctrl_cmd_string (e, "LOAD", NULL, 0))
	{
	  ENGINE_free (e);
	  e = NULL;
	}
    }
  return e;
}

static ENGINE *
setup_engine (const char *engine)
{
  ENGINE *e = NULL;

  ENGINE_load_builtin_engines ();

  if (engine)
    {
      if (strcmp (engine, "auto") == 0)
	{
	  msg (M_INFO, "Initializing OpenSSL auto engine support");
	  ENGINE_register_all_complete ();
	  return NULL;
	}
      if ((e = ENGINE_by_id (engine)) == NULL
	 && (e = try_load_engine (engine)) == NULL)
	{
	  msg (M_FATAL, "OpenSSL error: cannot load engine '%s'", engine);
	}

      if (!ENGINE_set_default (e, ENGINE_METHOD_ALL))
	{
	  msg (M_FATAL, "OpenSSL error: ENGINE_set_default failed on engine '%s'",
	       engine);
	}

      msg (M_INFO, "Initializing OpenSSL support for engine '%s'",
	   ENGINE_get_id (e));
    }
  return e;
}
#endif

void
init_crypto_lib_engine (const char *engine_name)
{
  if (!engine_initialized)
    {
#if CRYPTO_ENGINE
      ASSERT (engine_name);
      ASSERT (!engine_persist);
      engine_persist = setup_engine (engine_name);
#else
      msg (M_WARN, "Note: OpenSSL hardware crypto engine functionality is not available");
#endif
      engine_initialized = true;
    }
}

/*
 * This routine should have additional OpenSSL crypto library initialisations
 * used by both crypto and ssl components of OpenVPN.
 */
void init_crypto_lib ()
{
}

void uninit_crypto_lib ()
{
#if CRYPTO_ENGINE
  if (engine_initialized)
    {
      ENGINE_cleanup ();
      engine_persist = NULL;
      engine_initialized = false;
    }
#endif
  prng_uninit ();
}

/*
 * Random number functions, used in cases where we want
 * reasonably strong cryptographic random number generation
 * without depleting our entropy pool.  Used for random
 * IV values and a number of other miscellaneous tasks.
 */

static uint8_t *nonce_data; /* GLOBAL */
static const EVP_MD *nonce_md = NULL; /* GLOBAL */
static int nonce_secret_len; /* GLOBAL */

void
prng_init (const char *md_name, const int nonce_secret_len_parm)
{
  prng_uninit ();
  nonce_md = md_name ? get_md (md_name) : NULL;
  if (nonce_md)
    {
      ASSERT (nonce_secret_len_parm >= NONCE_SECRET_LEN_MIN && nonce_secret_len_parm <= NONCE_SECRET_LEN_MAX);
      nonce_secret_len = nonce_secret_len_parm;
      {
	const int size = EVP_MD_size (nonce_md) + nonce_secret_len;
	dmsg (D_CRYPTO_DEBUG, "PRNG init md=%s size=%d", EVP_MD_name (nonce_md), size);
	nonce_data = (uint8_t*) malloc (size);
	check_malloc_return (nonce_data);
#if 1 /* Must be 1 for real usage */
	if (!RAND_bytes (nonce_data, size))
	  msg (M_FATAL, "ERROR: Random number generator cannot obtain entropy for PRNG");
#else
	/* Only for testing -- will cause a predictable PRNG sequence */
	{
	  int i;
	  for (i = 0; i < size; ++i)
	    nonce_data[i] = (uint8_t) i;
	}
#endif
      }
    }
}

void
prng_uninit (void)
{
  free (nonce_data);
  nonce_data = NULL;
  nonce_md = NULL;
  nonce_secret_len = 0;
}

void
prng_bytes (uint8_t *output, int len)
{
  if (nonce_md)
    {
      EVP_MD_CTX ctx;
      const int md_size = EVP_MD_size (nonce_md);
      while (len > 0)
	{
	  unsigned int outlen = 0;
	  const int blen = min_int (len, md_size);
	  EVP_DigestInit (&ctx, nonce_md);
	  EVP_DigestUpdate (&ctx, nonce_data, md_size + nonce_secret_len);
	  EVP_DigestFinal (&ctx, nonce_data, &outlen);
	  ASSERT (outlen == md_size);
	  EVP_MD_CTX_cleanup (&ctx);
	  memcpy (output, nonce_data, blen);
	  output += blen;
	  len -= blen;
	}
    }
  else
    RAND_bytes (output, len);
}

/* an analogue to the random() function, but use prng_bytes */
long int
get_random()
{
  long int l;
  prng_bytes ((unsigned char *)&l, sizeof(l));
  if (l < 0)
    l = -l;
  return l;
}

const char *
md5sum (uint8_t *buf, int len, int n_print_chars, struct gc_arena *gc)
{
  uint8_t digest[MD5_DIGEST_LENGTH];
  MD5 (buf, len, digest);
  return format_hex (digest, MD5_DIGEST_LENGTH, n_print_chars, gc);
}

/*
 * OpenSSL memory debugging.  If dmalloc debugging is enabled, tell
 * OpenSSL to use our private malloc/realloc/free functions so that
 * we can dispatch them to dmalloc.
 */

#ifdef DMALLOC

static void *
crypto_malloc (size_t size, const char *file, int line)
{
  return dmalloc_malloc(file, line, size, DMALLOC_FUNC_MALLOC, 0, 0);
}

static void *
crypto_realloc (void *ptr, size_t size, const char *file, int line)
{
  return dmalloc_realloc(file, line, ptr, size, DMALLOC_FUNC_REALLOC, 0);
}

static void
crypto_free (void *ptr)
{
  dmalloc_free (__FILE__, __LINE__, ptr, DMALLOC_FUNC_FREE);
}

void
openssl_dmalloc_init (void)
{
   CRYPTO_set_mem_ex_functions (crypto_malloc,
				crypto_realloc,
				crypto_free);
}

#endif /* DMALLOC */

#ifndef USE_SSL

void
init_ssl_lib (void)
{
  ERR_load_crypto_strings ();
  OpenSSL_add_all_algorithms ();
  init_crypto_lib ();
}

void
free_ssl_lib (void)
{
  uninit_crypto_lib ();
  EVP_cleanup ();
  ERR_free_strings ();
}

#endif /* USE_SSL */

/*
 * md5 functions
 */

void
md5_state_init (struct md5_state *s)
{
  MD5_Init (&s->ctx);
}

void
md5_state_update (struct md5_state *s, void *data, size_t len)
{
  MD5_Update (&s->ctx, data, len);
}

void
md5_state_final (struct md5_state *s, struct md5_digest *out)
{
  MD5_Final (out->digest, &s->ctx);
}

void
md5_digest_clear (struct md5_digest *digest)
{
  CLEAR (*digest);
}

bool
md5_digest_defined (const struct md5_digest *digest)
{
  int i;
  for (i = 0; i < MD5_DIGEST_LENGTH; ++i)
    if (digest->digest[i])
      return true;
  return false;
}

bool
md5_digest_equal (const struct md5_digest *d1, const struct md5_digest *d2)
{
  return memcmp(d1->digest, d2->digest, MD5_DIGEST_LENGTH) == 0;
}

#endif /* USE_CRYPTO */
