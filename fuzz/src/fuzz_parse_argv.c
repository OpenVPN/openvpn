#include "config.h"
#include "syshead.h"

#include "buffer.h"
#include "options.h"

#define N 100

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  if (size < 10) { return 0; }
  if (data[size-1] != 0) { return 0; }

  struct gc_arena gc;
  struct options options;
  struct env_set *es;

  gc = gc_new();
  init_options(&options, false);
  es = env_set_create(&gc);

  char* argv[N+1];
  memset(argv, 0, sizeof(argv));

  int argv_pos = 0;

  int last_start = 0;
  for (int i = 0; i < size; i++) {
    if (argv_pos >= N) goto cleanup;

    if (data[i] == 0) {
      if (last_start == i) goto cleanup; // don't want empty args
      argv[argv_pos] = data+last_start;
      last_start = i+1;
      argv_pos++;
    }
  }

  if (argv_pos > 1)
    //parse_argv(&options, argv_pos, argv, M_USAGE, OPT_P_DEFAULT, NULL, es);
    parse_argv(&options, argv_pos, argv, M_NOPREFIX | M_OPTERR, OPT_P_DEFAULT, NULL, es);

cleanup:
  env_set_destroy(es);
  gc_free(&gc);

  return 0;
}
