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
#include "dhcp.h"
#include "buffer.h"

#include "fuzz_randomizer.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  struct buffer ipbuf;
  in_addr_t ret;

  fuzz_random_init(data, size);
  char *ran_val = get_random_string();

  ipbuf = alloc_buf(strlen(ran_val));
  if (buf_write(&ipbuf, ran_val, strlen(ran_val)) != false) {
    ret = dhcp_extract_router_msg(&ipbuf);
  }
  free_buf(&ipbuf);

  fuzz_random_destroy();
  free(ran_val);

  return 0;
}
