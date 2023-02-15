#include "config.h"
#include "syshead.h"

#include "buffer.h"
#include "mss.h"
#include "fuzz_randomizer.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  fuzz_random_init(data, size);

  struct buffer buf;

  int src_len = fuzz_randomizer_get_int(0, 4096);
  int maxmss = fuzz_randomizer_get_int(0, 4096);

  buf = alloc_buf(size);
  char* src = malloc(src_len);
  fuzz_get_random_data(src, src_len);
  if (buf_write(&buf, src, src_len) != false) {
    mss_fixup_ipv4(&buf, maxmss);
    mss_fixup_ipv6(&buf, maxmss);
  }
  free_buf(&buf);
  free(src);

  fuzz_random_destroy();
  return 0;
}
