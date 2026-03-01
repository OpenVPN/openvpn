/* Copyright 2021 Google LLC
Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at
      http://www.apache.org/licenses/LICENSE-2.0
Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/


#include "config.h"
#include "syshead.h"

#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#include "fuzz_verify_cert.h"
#include "misc.h"
#include "manage.h"
#include "otime.h"
#include "base64.h"
#include "ssl_verify.h"
#include "ssl_verify_backend.h"

#include "fuzz_randomizer.h"

static void key_ctx_update_implicit_iv(struct key_ctx *ctx, uint8_t *key,
                                       size_t key_len) {
  //const cipher_kt_t *cipher_kt = cipher_ctx_get_cipher_kt(ctx->cipher);

  cipher_ctx_t *cipher_kt = ctx->cipher;
  /* Only use implicit IV in AEAD cipher mode, where HMAC key is not used */
  if (cipher_ctx_mode_aead(cipher_kt)) {
    size_t impl_iv_len = 0;
    ASSERT(cipher_kt_iv_size(cipher_kt) >= OPENVPN_AEAD_MIN_IV_LEN);
    impl_iv_len = cipher_kt_iv_size(cipher_kt) - sizeof(packet_id_type);
    ASSERT(impl_iv_len <= OPENVPN_MAX_IV_LENGTH);
    ASSERT(impl_iv_len <= key_len);
    memcpy(ctx->implicit_iv, key, impl_iv_len);
    ctx->implicit_iv_len = impl_iv_len;
  }
}

static int init_frame(struct frame *frame) {
  frame->link_mtu = fuzz_randomizer_get_int(100, 1000);
  frame->extra_buffer = fuzz_randomizer_get_int(100, 1000);
  frame->link_mtu_dynamic = fuzz_randomizer_get_int(100, 1000);
  frame->extra_frame = fuzz_randomizer_get_int(100, 1000);
  frame->extra_tun = fuzz_randomizer_get_int(100, 1000);
  frame->extra_link = fuzz_randomizer_get_int(100, 1000);
  frame->align_flags = 0;
  frame->align_adjust = 0;
  if (TUN_MTU_SIZE(frame) <= 0) {
    return -1;
  }
  return 0;
}

int LLVMFuzzerInitialize(int *argc, char ***argv) {
  OPENSSL_malloc_init();
  SSL_library_init();
  ERR_load_crypto_strings();

  OpenSSL_add_all_algorithms();
  OpenSSL_add_ssl_algorithms();

  SSL_load_error_strings();
  return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  fuzz_random_init(data, size);
  fuzz_success = 1;
  bool key_ctx_dec_initialized = false;
  bool key_ctx_enc_initialized = false;
  struct key_ctx key_ctx_dec;
  memset(&key_ctx_dec, 0, sizeof(struct key_ctx));
  struct key_ctx key_ctx_enc;
  memset(&key_ctx_enc, 0, sizeof(struct key_ctx));

  struct gc_arena gc;
  struct tls_session *session = NULL;
  X509 *x509 = NULL;
  gc = gc_new();

  gb_init();

  // Read key file
  struct key2 key2;
  char *keydata = gb_get_random_string();
  read_key_file(&key2, keydata, RKF_INLINE);

  // init key type
  struct key_type kt;
  memset(&kt, 0, sizeof(struct key_type));

  char *ciphername = gb_get_random_string();
  char *authname = gb_get_random_string();
  bool key_type_initialized = false;

  if (strcmp(ciphername, "AES-256-GCM") == 0 ||
      strcmp(ciphername, "AES-128-GCM") == 0 ||
      strcmp(ciphername, "AES-192-GCM") == 0 ||
      strcmp(ciphername, "CAMELLIA-128-CFB128") == 0) {

    int v = fuzz_randomizer_get_int(0, 1);
    if (v == 0) {
      init_key_type(&kt, ciphername, authname, true, 0);
    } else {
      init_key_type(&kt, ciphername, authname, false, 0);
    }
    key_type_initialized = true;
  }

  if (fuzz_success == 0) {
    goto cleanup;
  }

  // Generate key.
  // Identify which one we should do, read or generate a random key.
  int c = fuzz_randomizer_get_int(0, 1);
  const uint8_t d[1024];
  int key_read = 0;
  struct key key;
  if (c == 0) {
    if (fuzz_get_random_data(d, 1024) != 1024) {
      struct buffer buf = alloc_buf(1024);
      buf_write(&buf, d, 1024);
      if (read_key(&key, &kt, &buf) == 1) {
        key_read = 1;
      }
      free_buf(&buf);
    }
  }
  else {
    if (key_type_initialized == true) {
      generate_key_random(&key, &kt);
    }
  }

  if (fuzz_success == 0) {
    goto cleanup;
  }
  key_read = 1;

  // init decryption context
  if (key_type_initialized && key_read) {
    init_key_ctx(&key_ctx_dec, &key, &kt, OPENVPN_OP_DECRYPT, "x");
    key_ctx_update_implicit_iv(&key_ctx_dec, &(key.hmac), MAX_HMAC_KEY_LENGTH);
    key_ctx_dec_initialized = true;
  }

  // init encryption context
  if (key_type_initialized && key_read) {
    init_key_ctx(&key_ctx_enc, &key, &kt, OPENVPN_OP_DECRYPT, "x");
    key_ctx_update_implicit_iv(&key_ctx_enc, &(key.hmac), MAX_HMAC_KEY_LENGTH);
    key_ctx_enc_initialized = true;
  }

  // perform encryption
  struct frame frame;
  memset(&frame, 0, sizeof(struct frame));
  if (key_ctx_enc_initialized == true && key_ctx_dec_initialized == true &&
      init_frame(&frame) == 0) {
    struct crypto_options opt;
    memset(&opt, 0, sizeof(opt));
    opt.pid_persist = NULL;
    opt.key_ctx_bi.encrypt = key_ctx_enc;
    opt.key_ctx_bi.decrypt = key_ctx_dec;
    opt.key_ctx_bi.initialized = true;
    opt.packet_id.rec.initialized = true;
    opt.packet_id.rec.seq_list = NULL;
    opt.packet_id.rec.name = NULL;

    void *buf_p;

    struct buffer encrypt_workspace = alloc_buf_gc(BUF_SIZE(&(frame)), &gc);
    struct buffer work = alloc_buf_gc(BUF_SIZE(&(frame)), &gc);
    struct buffer src = alloc_buf_gc(TUN_MTU_SIZE(&(frame)), &gc);
    struct buffer buf = clear_buf();

    int x = fuzz_randomizer_get_int(1, TUN_MTU_SIZE(&frame));

    ASSERT(buf_init(&work, FRAME_HEADROOM(&(frame))));
    ASSERT(buf_init(&src, 0));
    src.len = x;
    ASSERT(rand_bytes(BPTR(&src), BLEN(&src)));

    buf = work;
    buf_p = buf_write_alloc(&buf, BLEN(&src));
    ASSERT(buf_p);
    memcpy(buf_p, BPTR(&src), BLEN(&src));

    ASSERT(buf_init(&encrypt_workspace, FRAME_HEADROOM(&(frame))));

    openvpn_encrypt(&buf, encrypt_workspace, &opt);
  }

  // perform decryption
  memset(&frame, 0, sizeof(struct frame));
  if (key_ctx_dec_initialized == true && key_ctx_enc_initialized == true &&
      init_frame(&frame) == 0) {
    struct crypto_options opt;
    memset(&opt, 0, sizeof(opt));
    opt.pid_persist = NULL;
    opt.key_ctx_bi.encrypt = key_ctx_enc;
    opt.key_ctx_bi.decrypt = key_ctx_dec;
    opt.key_ctx_bi.initialized = true;
    opt.packet_id.rec.initialized = true;
    opt.packet_id.rec.seq_list = NULL;
    opt.packet_id.rec.name = NULL;

    void *buf_p;

    struct buffer decrypt_workspace = alloc_buf_gc(BUF_SIZE(&(frame)), &gc);
    struct buffer work = alloc_buf_gc(BUF_SIZE(&(frame)), &gc);
    struct buffer src = alloc_buf_gc(TUN_MTU_SIZE(&(frame)), &gc);
    struct buffer buf = clear_buf();

    int x = fuzz_randomizer_get_int(1, TUN_MTU_SIZE(&frame));

    ASSERT(buf_init(&work, FRAME_HEADROOM(&(frame))));
    ASSERT(buf_init(&src, 0));
    src.len = x;
    ASSERT(rand_bytes(BPTR(&src), BLEN(&src)));

    buf = work;
    buf_p = buf_write_alloc(&buf, BLEN(&src));
    ASSERT(buf_p);
    memcpy(buf_p, BPTR(&src), BLEN(&src));

    ASSERT(buf_init(&decrypt_workspace, FRAME_HEADROOM(&(frame))));
    
    openvpn_decrypt(&buf, decrypt_workspace, &opt, &frame, BPTR(&buf));
  }

cleanup:
  // cleanup
  gc_free(&gc);

  if (key_ctx_dec_initialized == true) {
    free_key_ctx(&key_ctx_dec);
  }

  if (key_ctx_enc_initialized == true) {
    free_key_ctx(&key_ctx_enc);
  }
  fuzz_random_destroy();

  gb_cleanup();

  return 0;
}
