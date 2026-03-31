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
#include "list.h"

#include "fuzz_randomizer.h"

#define KEY_SIZE 23

/* Required for hash_init() */
static uint32_t word_hash_function(const void *key, uint32_t iv) {
  return hash_func(key, KEY_SIZE, iv);
}

/* Required for hash_init() */
static bool word_compare_function(const void *key1, const void *key2) {
  return ((size_t)key1 & 0xFFF) == ((size_t)key1 & 0xFFF);
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  struct gc_arena gc;
  struct hash *hash = NULL;
  ssize_t generic_ssizet, generic_ssizet2, num_loops;

  fuzz_random_init(data, size);

  gc = gc_new();

  int total_to_fuzz = fuzz_randomizer_get_int(1, 20);
  for (int i = 0; i < total_to_fuzz; i++) {
    generic_ssizet = fuzz_randomizer_get_int(0, 8);

    switch (generic_ssizet) {
    case 0:
      if (hash == NULL) {
        int n_buckets = fuzz_randomizer_get_int(1, 1000);
        uint32_t iv;

        hash =
            hash_init(n_buckets, iv, word_hash_function, word_compare_function);
      }
      break;
    case 1:
      if (hash) {
        hash_free(hash);
        hash = NULL;
      }
      break;
    case 2:
      if (hash) {
        struct hash_iterator hi;
        struct hash_element *he;
        hash_iterator_init(hash, &hi);
        while ((he = hash_iterator_next(&hi))) {
          void *w = he->value;
        }
        hash_iterator_free(&hi);
      }
      break;
    case 3:
      if (hash) {
        void *key;
        void *value;
        char arr[KEY_SIZE];
        memset(arr, 0, KEY_SIZE);
        fuzz_get_random_data(arr, KEY_SIZE);
        key = (void *)arr;
        if (!hash_lookup(hash, key)) {
          generic_ssizet = fuzz_randomizer_get_int(0, 0xfffffff);
          value = (void *)generic_ssizet;
          hash_add(hash, key, value, false);
        }
      }
      break;
    case 4:
      if (hash) {
        hash_n_elements(hash);
      }
      break;
    case 5:
      if (hash) {
        hash_n_buckets(hash);
      }
      break;
    case 6:
      if (hash) {
        uint32_t hv;
        generic_ssizet = fuzz_randomizer_get_int(0, 0xfffffff);
        hv = generic_ssizet;
        hash_bucket(hash, hv);
      }
      break;
    case 7:
      if (hash) {
        void *key;
        char arr[KEY_SIZE];
        memset(arr, 0, KEY_SIZE);
        fuzz_get_random_data(arr, KEY_SIZE);
        key = (void *)arr;
        hash_remove(hash, key);
      }
      break;
    case 8:
      if (hash) {
        void *value;
        generic_ssizet = fuzz_randomizer_get_int(0, 0xfffffff);
        value = (void *)generic_ssizet;
        hash_remove_by_value(hash, value);
      }
    default:
      break;
    }
  }

  if (hash) {
    hash_free(hash);
  }

  gc_free(&gc);

  fuzz_random_destroy();

  return 0;
}
