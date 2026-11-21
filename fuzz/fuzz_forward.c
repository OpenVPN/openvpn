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
#include <sys/time.h>
#include "syshead.h"
#include "interval.h"
#include "init.h"
#include "buffer.h"
#include "forward.h"

#include "fuzz_randomizer.h"


static int init_c2_outgoing_link(struct context_2 *c2, struct gc_arena *gc) {
  struct link_socket_actual *to_link_addr = NULL;
  struct link_socket *link_socket = NULL;
  struct socks_proxy_info *socks_proxy = NULL;
  struct buffer buf;

  c2->tun_write_bytes = 0;
  ALLOC_ARRAY_GC(link_socket, struct link_socket, 1, gc);
  memset(link_socket, 0, sizeof(*link_socket));

  c2->link_socket = link_socket;

  if (fuzz_randomizer_get_int(0, 2) != 0) {
    c2->link_socket->info.proto = PROTO_UDP;
  } else {
    c2->link_socket->info.proto = PROTO_TCP_SERVER;
  }

  ALLOC_ARRAY_GC(socks_proxy, struct socks_proxy_info, 1, gc);
  memset(socks_proxy, 0, sizeof(*socks_proxy));
  c2->link_socket->socks_proxy = socks_proxy;

  c2->frame.link_mtu_dynamic = fuzz_randomizer_get_int(0, 0xfffffff);
  c2->frame.extra_frame = fuzz_randomizer_get_int(0, 0xfffffff);
  c2->frame.extra_tun = fuzz_randomizer_get_int(0, 0xfffffff);
  c2->frame.link_mtu = fuzz_randomizer_get_int(0, 0xfffffff);

  ALLOC_ARRAY_GC(to_link_addr, struct link_socket_actual, 1, gc);
  memset(to_link_addr, 0, sizeof(*to_link_addr));
  c2->to_link_addr = to_link_addr;

  c2->to_link_addr->dest.addr.sa.sa_family = AF_INET;
  c2->to_link_addr->dest.addr.in4.sin_addr.s_addr = 1;

  char *tmp = get_random_string();
  buf = alloc_buf_gc(strlen(tmp), gc);
  buf_write(&buf, tmp, strlen(tmp));
  int val = fuzz_randomizer_get_int(0, strlen(tmp));
  buf.offset = val;
  free(tmp);

  c2->link_socket->stream_buf.maxlen = BLEN(&buf);
  c2->to_link = buf;

  if (buf.offset < 10) {
    return -1;
  }
  return 0;
}

void fuzz_process_outgoing_link(const uint8_t *data, size_t size) {
  struct context ctx;
  struct gc_arena gc = gc_new();
  memset(&ctx, 0, sizeof(ctx));

  if (init_c2_outgoing_link(&ctx.c2, &gc) == 0) {
    process_outgoing_link(&ctx);
  }

  gc_free(&gc);
}

static int _init_options(struct options *options, struct client_nat_entry **cne,
                         struct gc_arena *gc) {
  options->passtos = false;
  options->mode = MODE_POINT_TO_POINT;
  options->allow_recursive_routing = true;
  options->client_nat = new_client_nat_list(gc);

  struct client_nat_entry *_cne;
  ALLOC_ARRAY_GC(cne[0], struct client_nat_entry, 1, gc);
  _cne = cne[0];
  memset(_cne, 0, sizeof(struct client_nat_entry));

  struct client_nat_option_list clist;
  clist.n = 1;
  clist.entries[0] = *_cne;
  copy_client_nat_option_list(options->client_nat, &clist);
  options->route_gateway_via_dhcp = false;

  return 0;
}

static int init_c2_incoming_tun(struct context_2 *c2, struct gc_arena *gc) {
  struct buffer buf;
  memset(&buf, 0, sizeof(buf));

  struct link_socket *link_socket = NULL;
  ALLOC_ARRAY_GC(link_socket, struct link_socket, 1, gc);
  c2->link_socket = link_socket;

  ALLOC_OBJ_GC(c2->link_socket_info, struct link_socket_info, gc);
  ALLOC_OBJ_GC(c2->link_socket_info->lsa, struct link_socket_addr, gc);
  c2->link_socket_info->lsa->bind_local = NULL;
  c2->link_socket_info->lsa->remote_list = NULL;
  c2->link_socket_info->lsa->current_remote = NULL;
  c2->link_socket_info->lsa->remote_list = NULL;
  c2->es = env_set_create(gc);

  c2->frame.link_mtu_dynamic = 0;
  c2->frame.extra_frame = 0;
  c2->frame.extra_tun = 0;
  c2->to_link_addr = NULL;

  char *tmp = get_random_string();
  buf = alloc_buf(strlen(tmp));
  buf_write(&buf, tmp, strlen(tmp));

  int retval;
  if (strlen(tmp) > 5) {
    retval = 0;
  } else {
    retval = 1;
  }

  free(tmp);

  c2->buf = buf;
  c2->buffers = init_context_buffers(&c2->frame);
  c2->log_rw = false;

  return retval;
}

int run_process_incoming_tun(const uint8_t *data, size_t size) {
  struct gc_arena gc;
  struct context ctx;
  struct client_nat_entry *cne[MAX_CLIENT_NAT];
  struct route_list route_list;

  memset(&ctx, 0, sizeof(ctx));
  memset(cne, 0, sizeof(cne));

  gc = gc_new();

  _init_options(&ctx.options, cne, &gc);

  // Init tuntap
  struct tuntap tuntap;
  tuntap.type = DEV_TYPE_TAP;

  ctx.c1.tuntap = &tuntap;

  int retval = init_c2_incoming_tun(&ctx.c2, &gc);
  ctx.c1.route_list = &route_list;
  if (retval == 0) {
    process_incoming_tun(&ctx);
  }

  free(ctx.c2.buf.data);
  free_context_buffers(ctx.c2.buffers);
  gc_free(&gc);
}

static int init_c2_outgoing_tun(struct context_2 *c2, struct gc_arena *gc) {
  struct buffer buf;

  c2->tun_write_bytes = 0;
  c2->frame.link_mtu_dynamic = fuzz_randomizer_get_int(0, 0xfffffff);
  c2->frame.extra_frame = fuzz_randomizer_get_int(0, 0xfffffff);
  c2->frame.extra_tun = fuzz_randomizer_get_int(0, 0xfffffff);

  char *tmp = get_random_string();
  buf = alloc_buf_gc(strlen(tmp), gc);
  buf_write(&buf, tmp, strlen(tmp));
  free(tmp);

  c2->to_tun = buf;
  return 0;
}

void run_process_outgoing_tun(uint8_t *data, size_t size) {
  struct gc_arena gc;
  struct context ctx;
  struct tuntap tuntap;

  memset(&ctx, 0, sizeof(ctx));
  gc = gc_new();

  tuntap.type = DEV_TYPE_TAP;
  ctx.c1.tuntap = &tuntap;

  init_c2_outgoing_tun(&ctx.c2, &gc);
  process_outgoing_tun(&ctx);

  gc_free(&gc);
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  fuzz_random_init(data, size);

  int dec = fuzz_randomizer_get_int(0, 2);
  if (dec == 0) {
    run_process_incoming_tun(data, size);
  }
	else if (dec == 1) {
		run_process_outgoing_tun(data, size);
	}
  else {
    fuzz_process_outgoing_link(data, size);
  }

  fuzz_random_destroy();
  return 0;
}
