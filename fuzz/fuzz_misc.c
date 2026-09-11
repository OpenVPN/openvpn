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
#include "misc.h"
#include "buffer.h"

#include "fuzz_randomizer.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  fuzz_random_init(data, size);

  struct gc_arena gc;
  struct env_set *es;
  gc = gc_new();
  es = env_set_create(&gc);

  int total_to_fuzz = fuzz_randomizer_get_int(1, 9);
  for (int i = 0; i <total_to_fuzz; i++) {
    int type = fuzz_randomizer_get_int(0, 3);
    char *tmp1 = get_random_string();
    char *tmp2 = get_random_string();

    switch (type) {
    case 0:
      env_set_del(es, tmp1);
      break;
    case 1:
      env_set_add(es, tmp1);
      break;
    case 2:
      env_set_get(es, tmp1);
      break;
    case 3:
      if (strlen(tmp1) > 1 && strlen(tmp2) > 1) {
        setenv_str(es, tmp2, tmp1);
      }
      break;
    default:
      sanitize_control_message(tmp1, &gc);
    }
    free(tmp1);
    free(tmp2);
  }

  env_set_destroy(es);
  gc_free(&gc);

  fuzz_random_destroy();
  return 0;
}
