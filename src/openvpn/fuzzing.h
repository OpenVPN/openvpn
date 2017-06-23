#ifdef FUZZING
#ifdef HAVE_CONFIG_H
#include "config.h"
#elif defined(_MSC_VER)
#include "config-msvc.h"
#endif
#include "syshead.h"
#include "buffer.h"
void fuzzer_set_input(unsigned char* data, size_t size);
unsigned char* fuzzer_get_current_data(void);
size_t fuzzer_get_current_size(void);
void fuzzer_set_recv_no_rnd(int yesno);
ssize_t fuzzer_get_data(void* dest, size_t size);
ssize_t fuzzer_get_data_rnd(void* dest, size_t size);
ssize_t fuzzer_get_integer(size_t max);
char* fuzzer_get_string(size_t maxsize);
char* fuzzer_get_string_gc(size_t maxsize, struct gc_arena* gc);
ssize_t fuzzer_read(void* dest, size_t size);
ssize_t fuzzer_recv(void* dest, size_t size);
ssize_t fuzzer_send(size_t size);
void fuzzer_alter_buffer(struct buffer* buffer);
void test_undefined_memory(void* vp, size_t s);
#define FUZZER_GET_DATA(dest, size) { \
    if ( fuzzer_get_data((dest), (size)) < 0 ) { \
        goto cleanup; \
    } \
}
#define FUZZER_GET_INTEGER(dest, max) { \
    (dest) = fuzzer_get_integer(max); \
    if ( (dest) < 0 ) { \
        goto cleanup; \
    } \
}
#define FUZZER_GET_STRING(dest, max) { \
    (dest) = NULL; \
    if ( ((dest) = fuzzer_get_string(max)) == NULL ) { \
        goto cleanup; \
    } \
}

#define FUZZER_GET_STRING_GC(dest, max, gc) { \
    (dest) = NULL; \
    if ( ((dest) = fuzzer_get_string_gc((max), (gc))) == NULL ) { \
        goto cleanup; \
    } \
}
#endif
