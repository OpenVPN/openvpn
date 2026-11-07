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
#include "proxy.h"
#include "interval.h"
#include "route.h"
#include "buffer.h"

#include "fuzz_randomizer.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {

  fuzz_random_init(data, size);

  gb_init();

  struct route_option_list *opt;
  struct route_list rl;

  int route_list_inited = 0;
  int route_list_ipv6_inited = 0;

  struct context c;
  memset(&c, 0, sizeof(struct context));
  gc_init(&c.gc);
  c.es = env_set_create(&c.gc);
  init_options(&c.options, true);
  net_ctx_init(&c, &c.net_ctx);
  init_verb_mute(&c, IVM_LEVEL_1);

  init_options_dev(&c.options);

  // options_postprocess(&c.options);
  pre_setup(&c.options);

  setenv_settings(c.es, &c.options);

  ALLOC_OBJ_CLEAR_GC(c.options.ce.local_list, struct local_list, &c.options.gc);
  ALLOC_OBJ_CLEAR_GC(c.options.connection_list, struct connection_list,
                     &c.options.gc);
  context_init_1(&c);

  in_addr_t remote_host;
  ssize_t default_metric;

  struct route_ipv6_list rl6;
  struct route_ipv6_option_list *opt6;

  memset(&rl, 0, sizeof(rl));
  memset(&rl6, 0, sizeof(rl6));
  memset(&opt, 0, sizeof(opt));
  memset(&opt6, 0, sizeof(opt6));

  opt6 = new_route_ipv6_option_list(&c.gc);
  opt = new_route_option_list(&c.gc);

  int total_to_fuzz = fuzz_randomizer_get_int(1, 20);
  for (int i = 0; i < total_to_fuzz; i++) {
    int selector = fuzz_randomizer_get_int(0, 13);
    switch (selector) {
    case 0:
      if (route_list_inited == 0) {
        const char *remote_endpoint = gb_get_random_string();
        memset(&rl, 0, sizeof(struct route_list));
        rl.flags = fuzz_randomizer_get_int(0, 0xffffff);

        init_route_list(&rl, opt, remote_endpoint, default_metric, remote_host,
                        c.es, &c);
        route_list_inited = 1;
      }
      break;
    case 1:
      if (route_list_inited) {
        in_addr_t addr;
        route_list_add_vpn_gateway(&rl, c.es, addr);
      }
      break;
    case 2:
      if (route_list_inited && route_list_ipv6_inited) {
        struct tuntap tt;
        memset(&tt, 0, sizeof(tt));
        add_routes(&rl, &rl6, &tt, 0, c.es, &c);
      }
      break;
    case 3:
      if (route_list_inited) {
        setenv_routes(c.es, &rl);
      }
      break;
    case 4:
      if (route_list_inited) {
        struct route_ipv4 r;
        struct route_option ro;
        ro.network = gb_get_random_string();
        ro.netmask = gb_get_random_string();
        ro.gateway = gb_get_random_string();
        ro.metric = gb_get_random_string();
        ro.next = NULL;

        memset(&r, 0, sizeof(struct route_ipv4));
        r.option = &ro;
        r.flags = RT_DEFINED;
        add_route(&r, NULL, 0, NULL, c.es, &c);
      }
      break;
    case 5:
      if (route_list_inited) {
        char *s1 = get_random_string();
        is_special_addr(s1);
        free(s1);
      }
      break;
    case 6:
      if (route_list_ipv6_inited == 0) {
        const char *remote_endpoint = gb_get_random_string();
        memset(&rl, 0, sizeof(struct route_list));
        struct in6_addr remote_host;

        rl6.rgi6.flags = fuzz_randomizer_get_int(0, 0xffffff);
        fuzz_get_random_data(&rl6.rgi6.hwaddr, 6);

        char *t1 = gb_get_random_string();
        if (strlen(t1) > 16) {
          memcpy(rl6.rgi6.iface, t1, 16);
        } else {
          memcpy(rl6.rgi6.iface, t1, strlen(t1));
        }

        init_route_ipv6_list(&rl6, opt6, remote_endpoint, 0, &remote_host, c.es,
                             &c);
        route_list_ipv6_inited = 1;
      }
      break;
    case 7: {
      unsigned int flags;
      struct route_ipv6 r6;
      struct tuntap tt;
      memset(&tt, 0, sizeof(tt));
      tt.actual_name = gb_get_random_string();
      r6.iface = gb_get_random_string();
      r6.flags = fuzz_randomizer_get_int(0, 0xfffff);
      r6.netbits = fuzz_randomizer_get_int(0, 0xfffff);
      r6.metric = fuzz_randomizer_get_int(0, 0xfffff);

      r6.next = NULL;

      add_route_ipv6(&r6, &tt, 0, c.es, &c);
    } break;
    case 8:
      if (route_list_ipv6_inited && route_list_inited) {
        delete_routes(&rl, &rl6, NULL, 0, c.es, &c);
        route_list_ipv6_inited = 0;
        route_list_inited = 0;
      }
      break;
    case 9:
      if (route_list_ipv6_inited) {
        setenv_routes_ipv6(c.es, &rl6);
      }
      break;
    case 10: {
      add_route_ipv6_to_option_list(opt6,
		                    gb_get_random_string(),
                                    gb_get_random_string(),
                                    gb_get_random_string(),
				    fuzz_randomizer_get_int(0, 100));
    } break;
    case 11: {
      print_route_options(opt, M_NONFATAL);
    } break;
    case 12: {
      add_route_to_option_list(opt,
		               gb_get_random_string(),
                               gb_get_random_string(),
			       gb_get_random_string(),
                               gb_get_random_string(),
			       fuzz_randomizer_get_int(0, 100));
    } break;
    default:
      break;
    }
  }

  if (route_list_inited) {
    gc_free(&rl.gc);
  }
  env_set_destroy(c.es);
  context_gc_free(&c);

  fuzz_random_destroy();

  gb_cleanup();

  return 0;
}
