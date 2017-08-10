#ifdef FUZZING
#ifdef HAVE_CONFIG_H
#include "config.h"
#elif defined(_MSC_VER)
#include "config-msvc.h"
#endif
#include "syshead.h"
#include "buffer.h"
#include "fuzzing.h"

/* Pointer to current position in the input buffer.
 * Incremented by 1 for every byte read. */
static unsigned char* fuzzer_data = NULL;

/* Remaining buffer size.
 * Decremented by 1 for every byte read */
static size_t fuzzer_data_size = 0;

/* Sets internal buffer state. Must be called before any other functions
 * in this file */
void fuzzer_set_input(unsigned char* data, size_t size)
{
    fuzzer_data = data;
    fuzzer_data_size = size;
}

/* Getter for pointer to current buffer position */
unsigned char* fuzzer_get_current_data(void)
{
    return fuzzer_data;
}

/* Getter for pointer to current remaining buffer size */
size_t fuzzer_get_current_size(void)
{
    return fuzzer_data_size;
}

static int recv_no_rnd = 0;
void fuzzer_set_recv_no_rnd(int yesno)
{
    recv_no_rnd = yesno;
}

/* Extract data of size 'size' and store it in 'dest' */
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
/* Does two things:
 *    - Extract an integer of max size 'size' from the input stream
 *    - If that much data is left in the input stream, copy it to 'dest'
 */
ssize_t fuzzer_get_data_rnd(void* dest, size_t size)
{
    size_t realsize;
    unsigned int realsize_ui;
    unsigned short realsize_us;
    unsigned char realsize_uc;

    /* No operation */
    if ( size == 0 )
    {
        return 0;
    }

    /* Refuse to serve requests for more than 2 gigabytes */
    if ( size > 0x7FFFFFFF )
    {
        return 0;
    }

    /* Get an integer from the input stream.
     * Use different data types for different size requests, so as not
     * to waste input buffer space */
    if ( size > 65535 )
    {
        /* An unsigned int is needed */
        if ( fuzzer_get_data(&realsize_ui, sizeof(realsize_ui)) < 0 )
        {
            return -1;
        }
        realsize = realsize_ui;
    }
    else if ( size > 255 )
    {
        /* An unsigned short is needed */
        if ( fuzzer_get_data(&realsize_us, sizeof(realsize_us)) < 0 )
        {
            return -1;
        }
        realsize = realsize_us;
    }
    else
    {
        /* An unsigned char will suffice */
        if ( fuzzer_get_data(&realsize_uc, sizeof(realsize_uc)) < 0 )
        {
            return -1;
        }
        realsize = realsize_uc;
    }

    /* Map the retrieved integer to the space [0..size+1] using modulo */
    realsize %= (size+1);

    /* Attempt to get this much data */
    return fuzzer_get_data(dest, realsize);
}

ssize_t fuzzer_get_integer(size_t max)
{
    size_t s;

    /* No operation */
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

    /* Get a size_t from the input buffer */
    if ( fuzzer_get_data(&s, sizeof(s)) < 0 )
    {
        return -1;
    }

    /* Map the retrieved integer to the space [0..max+1] using modulo */
    return s % (max+1);
}

static char* fuzzer_get_string_inner(size_t maxsize, struct gc_arena* gc)
{
    ssize_t strsize;
    char* ret;

    /* Get integer in range [0..maxsize] */
    if ( (strsize = fuzzer_get_integer(maxsize)) < 0 )
    {
        return NULL;
    }

    if ( gc == NULL )
    {
        /* Use default allocator */
        ret = malloc(strsize+1);
    }
    else
    {
        /* Use the garbage collector allocator */
        ALLOC_ARRAY_GC(ret, char, strsize+1, gc);
    }

    /* Allocation failure */
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

    /* Null-terminate */
    ret[strsize] = 0;

    return ret;
}

/* Create null-terminated string of length 'maxsize' from
 * fuzzer input data */
char* fuzzer_get_string(size_t maxsize)
{
    return fuzzer_get_string_inner(maxsize, NULL);
}

/* Create null-terminated string of length 'maxsize' from
 * fuzzer input data, allocate memory using 'gc' */
char* fuzzer_get_string_gc(size_t maxsize, struct gc_arena* gc)
{
    return fuzzer_get_string_inner(maxsize, gc);
}

/* Abstraction function for POSIX read/recv/..
 * Rather than giving socket or file data to the caller,
 * return data from the fuzzer input stream
 */
ssize_t fuzzer_recv(void* dest, size_t size)
{
    if ( recv_no_rnd )
    {
        /* Store 'size' bytes in 'dest', or fail if insufficient data
         * is available */
        return fuzzer_get_data(dest, size);
    }
    else
    {
        /* Store up to 'size' bytes in 'dest', or fail if insufficient data
         * is available */
        return fuzzer_get_data_rnd(dest, size);
    }
}

/* Abstraction function for POSIX send/write/..
 * Currently always succeeds
 */
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

/* Pseudo-randomly alter the struct buffer members
 * 'offset' and 'len' such that:
 *
 * offset >= 0 and offset <= capacity
 * len >= 0 and len <= (capacity - offset)
 */
void fuzzer_alter_buffer(struct buffer* buffer)
{
    ssize_t newoffset, newlen;

    if ( buffer->capacity == 0 )
    {
        return;
    }

    /* newoffset = integer in range [0..buffer->capacity] */
    FUZZER_GET_INTEGER(newoffset, buffer->capacity);

    newlen = buffer->capacity - newoffset;
    if ( newlen != 0 )
    {
        /* newlen = integer in range [0..newlen] */
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
    /* MemorySanitizer (MSAN) will not trigger an exception for
     * uninitialized data unless:
     *    - The data is used for branching
     *    - The data is serialized
     *
     * So here we "serialize" data 'vp' of size 's' to /dev/null.
     * This is a trick to force MSAN to evaluate whether any bit in this
     * buffer constitutes uninitialized data.
     */

    FILE* fp = fopen("/dev/null", "wb");
    unsigned char* p = (unsigned char*)vp;
    fwrite(p, s, 1, fp);
    fclose(fp);
}
#endif
