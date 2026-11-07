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


static int parse_x509(const uint8_t *data, size_t size, X509 **out) {
  *out = d2i_X509(NULL, (const unsigned char **)&data, size);
  if (*out == NULL) {
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
  return 1;
}


static int init_session_opt(struct tls_options **_opt, struct gc_arena *gc) {
  ssize_t nid;
  ssize_t generic_ssizet;
  struct tls_options *opt;
  int r;

  ALLOC_OBJ_GC(*_opt, struct tls_options, gc);
  if (opt == NULL) {
		return -1;
  }

  opt = *_opt;

  memset(opt, 0xFE, sizeof(struct tls_options));

  opt->es = env_set_create(gc);
  opt->x509_username_field[0] = NULL;
  opt->remote_cert_eku = NULL;

  /* Prevents failure if x509 sha1 hashes do not match */
  opt->verify_hash = NULL;

  /* Prevent attempt to run --tls-verify script */
  opt->verify_command = NULL;

  /* Do not verify against CRL file */
  opt->crl_file = NULL;

  /* Do not run --tls-verify plugins */
  opt->plugins = NULL;

  r = fuzz_randomizer_get_int(0, 1);
  if (r == 0) {
    opt->x509_username_field[0] = nidstrs[fuzz_randomizer_get_int(0, (sizeof(nidstrs)/sizeof(nidstrs[0])) - 1)];
  } 
  else {
    opt->x509_username_field[0] = "ext:subjectAltName";
  }
  opt->x509_username_field[1] = NULL;

  r = fuzz_randomizer_get_int(0, 2);
  if (r == 0)
    opt->ns_cert_type = NS_CERT_CHECK_CLIENT;
  else if (r == 1)
    opt->ns_cert_type = NS_CERT_CHECK_SERVER;
  else
    opt->ns_cert_type = NS_CERT_CHECK_NONE;

  opt->x509_track = NULL;

  r = fuzz_randomizer_get_int(0, 1);
  if (r == 0)
    opt->remote_cert_eku = NULL;
  else
    opt->remote_cert_eku = get_random_string();

  return 0;
}


static int init_session(struct tls_session **_session, struct gc_arena *gc) {
  struct tls_session *session;

  ALLOC_OBJ_GC(*_session, struct tls_session, gc);
  if (*_session == NULL) {
		return -1;
  }

  session = *_session;
  memset(session, 0xFE, sizeof(struct tls_session));

  /* Accessed in set_common_name() */
  session->common_name = get_random_string();;

  /* Initialize the session->opt structure */
  if (init_session_opt(&(session->opt), gc) == -1) {
    free(session->common_name);
		return -1;
  }

  /* Accessed in server_untrusted() */
  session->untrusted_addr.dest.addr.sa.sa_family = AF_UNSPEC;

  return 0;
}


int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  fuzz_random_init(data, size);

  struct gc_arena gc;
  struct tls_session *session = NULL;
  X509 *x509 = NULL;
  gc = gc_new();

  if (parse_x509(data, size, &x509) == 0) {
    if (init_session(&session, &gc) == 0) {
      verify_cert(session, x509, 100);
      if (session->opt->remote_cert_eku != NULL) {
        free(session->opt->remote_cert_eku);
      }
      free(session->common_name);
    }
    
  }

  X509_free(x509);
  gc_free(&gc);

  fuzz_random_destroy();

  return 0;
}
