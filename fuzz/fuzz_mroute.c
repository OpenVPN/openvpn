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
#include "init.h"
#include "mroute.h"

#include "fuzz_randomizer.h"


int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {

  fuzz_random_init(data, size);
  struct buffer buf;
  struct gc_arena gc;

  gc = gc_new();

  char *tmp = get_random_string();
  buf = string_alloc_buf(tmp, &gc);
  free(tmp);

  struct mroute_addr src_addr;
  struct mroute_addr dst_addr;
  mroute_addr_init(&src_addr);
  mroute_addr_init(&dst_addr);
  unsigned int ret = mroute_extract_addr_ip(&src_addr, &dst_addr, &buf);

  if (ret & MROUTE_EXTRACT_SUCCEEDED) {
    mroute_addr_mask_host_bits(&src_addr);
    mroute_addr_print(&src_addr, &gc);
    mroute_learnable_address(&src_addr, &gc);
  }

  uint16_t vid;
  struct mroute_addr a1, a2;
  mroute_addr_init(&a1);
  mroute_addr_init(&a2);
  mroute_extract_addr_ether(&a1, &a2, vid, &buf);

  if (size > sizeof(struct openvpn_sockaddr)) {
    struct openvpn_sockaddr local_sock;
    memcpy(&local_sock, data, sizeof(struct openvpn_sockaddr));
    mroute_extract_openvpn_sockaddr(&a1, &local_sock, true);
    mroute_extract_openvpn_sockaddr(&a1, &local_sock, false);
  }

  struct mroute_helper *mhelper = NULL;
  mhelper = mroute_helper_init(fuzz_randomizer_get_int(0, 0xfffffff));
  if (mhelper != NULL) {
    mroute_helper_add_iroute46(mhelper, fuzz_randomizer_get_int(0, MR_HELPER_NET_LEN-1));
    mroute_helper_free(mhelper);
  }

  gc_free(&gc);

  fuzz_random_destroy();
  return 0;
}

