#ifdef FUZZING
#ifdef HAVE_CONFIG_H
#include "config.h"
#elif defined(_MSC_VER)
#include "config-msvc.h"
#endif
#include "syshead.h"
#include "buffer.h"
#include "fuzzing.h"

static unsigned char* fuzzer_data = NULL;
static size_t fuzzer_data_size = 0;

void fuzzer_set_input(unsigned char* data, size_t size)
{
    fuzzer_data = data;
    fuzzer_data_size = size;
}

unsigned char* fuzzer_get_current_data(void)
{
    return fuzzer_data;
}

size_t fuzzer_get_current_size(void)
{
    return fuzzer_data_size;
}

static int recv_no_rnd = 0;
void fuzzer_set_recv_no_rnd(int yesno)
{
    recv_no_rnd = yesno;
}

ssize_t fuzzer_get_data(void* dest, size_t size)
{
    if ( size > fuzzer_data_size )
    {
        return -1;
    }

    memcpy(dest, fuzzer_data, size);

    fuzzer_data += size;
    fuzzer_data_size -= size;

    return size;
}

ssize_t fuzzer_get_data_rnd(void* dest, size_t size)
{
    size_t realsize;
    unsigned int realsize_ui;
    unsigned short realsize_us;
    unsigned char realsize_uc;

    if ( size == 0 )
    {
        return 0;
    }

    if ( size > 0x7FFFFFFF )
    {
        return 0;
    }

    if ( size > 65535 )
    {
        if ( fuzzer_get_data(&realsize_ui, sizeof(realsize_ui)) < 0 )
        {
            return -1;
        }
        realsize = realsize_ui;
    }
    else if ( size > 255 )
    {
        if ( fuzzer_get_data(&realsize_us, sizeof(realsize_us)) < 0 )
        {
            return -1;
        }
        realsize = realsize_us;
    }
    else
    {
        if ( fuzzer_get_data(&realsize_uc, sizeof(realsize_uc)) < 0 )
        {
            return -1;
        }
        realsize = realsize_uc;
    }

    realsize %= (size+1);

    return fuzzer_get_data(dest, realsize);
}

ssize_t fuzzer_get_integer(size_t max)
{
    size_t s;

    if ( max == 0 )
    {
        return 0;
    }

    /*    
    if ( max > 0x7FFFFFFF )
    {
        return -1;
    }
    */

    if ( fuzzer_get_data(&s, sizeof(s)) < 0 )
    {
        return -1;
    }

    return s % (max+1);
}

static char* fuzzer_get_string_inner(size_t maxsize, struct gc_arena* gc)
{
    ssize_t strsize;
    char* ret;

    if ( (strsize = fuzzer_get_integer(maxsize)) < 0 )
    {
        return NULL;
    }

    if ( gc == NULL )
    {
        ret = malloc(strsize+1);
    }
    else
    {
        ALLOC_ARRAY_GC(ret, char, strsize+1, gc);
    }

    if ( ret == NULL )
    {
        return NULL;
    }

    if ( fuzzer_get_data(ret, strsize) < 0 )
    {
        if ( gc == NULL )
        {
            free(ret);
        }
        return NULL;
    }

    ret[strsize] = 0;

    return ret;
}

char* fuzzer_get_string(size_t maxsize)
{
    return fuzzer_get_string_inner(maxsize, NULL);
}

char* fuzzer_get_string_gc(size_t maxsize, struct gc_arena* gc)
{
    return fuzzer_get_string_inner(maxsize, gc);
}

ssize_t fuzzer_read(void* dest, size_t size)
{
    if ( recv_no_rnd )
    {
        return fuzzer_get_data(dest, size);
    }
    else
    {
        return fuzzer_get_data_rnd(dest, size);
    }
}

ssize_t fuzzer_recv(void* dest, size_t size)
{
    if ( recv_no_rnd )
    {
        return fuzzer_get_data(dest, size);
    }
    else
    {
        return fuzzer_get_data_rnd(dest, size);
    }
}

ssize_t fuzzer_send(size_t size)
{
    /*
    ssize_t r = fuzzer_get_integer(size);

    if ( r < 0 )
    {
        return -1;
    }
    */
    return size;
    //return r;
}

void fuzzer_alter_buffer(struct buffer* buffer)
{
    ssize_t newoffset, newlen;
    if ( buffer->capacity == 0 )
    {
        return;
    }
    FUZZER_GET_INTEGER(newoffset, buffer->capacity);
    newlen = buffer->capacity - newoffset;
    if ( newlen != 0 )
    {
        FUZZER_GET_INTEGER(newlen, newlen);
    }
    buffer->offset = newoffset;
    buffer->len = newlen;

    return;
cleanup:
    return;
}

void test_undefined_memory(void* vp, size_t s)
{
    FILE* fp = fopen("/dev/null", "wb");
    unsigned char* p = (unsigned char*)vp;
    fwrite(p, s, 1, fp);
    fclose(fp);
}
#endif
