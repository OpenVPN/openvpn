#include "config.h"
#include "syshead.h"
#include "fuzzing.h"
#include "buffer.h"

#define MAX_STR_LEN 128

int LLVMFuzzerInitialize(int *argc, char ***argv)
{
    return 1;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    struct gc_arena gc;
    struct buffer* bufp;
    struct buffer buf, buf2;
    char* str = NULL, *str2 = NULL;
    int generic_int;
    char generic_char, generic_char2;
    ssize_t i, generic_ssizet, generic_ssizet2, _size, num_loops;
    uint16_t generic_uint16;
    uint32_t generic_uint32;
    struct buffer_list* buflistp  = NULL;

    gc = gc_new();

    bufp = NULL;

    fuzzer_set_input((unsigned char*)data, size);
    FUZZER_GET_INTEGER(num_loops, 10);
    for (i = 0; i < num_loops; i++)
    {
        /* If the buffer is not defined yet, do that first */
        if ( bufp == NULL )
        {
            /* Get integer range [0..1]*/
            FUZZER_GET_INTEGER(generic_ssizet, 1);
            switch ( generic_ssizet )
            {
                case    0:
                    FUZZER_GET_INTEGER(_size, MAX_STR_LEN);
                    buf = alloc_buf_gc(_size, &gc);
                    bufp = &buf;
                    break;
                case    1:
                    FUZZER_GET_STRING(str, MAX_STR_LEN);
                    buf = string_alloc_buf(str, &gc);
                    bufp = &buf;
                    free(str); str = NULL;
                    break;
            }
        }
        else
        {
            /* pseudo-randomize 'offset' and 'len' members of the
             * buffer struct */
            fuzzer_alter_buffer(bufp);

            /* pseudo-randomly pick one of the 38 functions */
            FUZZER_GET_INTEGER(generic_ssizet, 38);
            switch ( generic_ssizet )
            {
                case    0:
                    buf_clear(bufp);
                    break;
                case    1:
                    buf2 = clone_buf(bufp);
                    free_buf(&buf2);
                    break;
                case    2:
                    buf_defined(bufp);
                    break;
                case    3:
                    buf_valid(bufp);
                    break;
                case    4:
                    buf_bptr(bufp);
                    break;
                case    5:
                    buf_len(bufp);
                    break;
                case    6:
                    buf_bend(bufp);
                    break;
                case    7:
                    buf_blast(bufp);
                    break;
                case    8:
                    buf_str(bufp);
                    break;
                case    9:
                    /*
                    buf_reset(bufp);
                    */
                    break;
                case    10:
                    FUZZER_GET_INTEGER(generic_ssizet, 255);
                    generic_char = generic_ssizet;
                    buf_rmtail(bufp, (uint8_t)generic_char);
                    break;
                case    11:
                    buf_null_terminate(bufp);
                    if ( BLEN(bufp) )
                    {
                        /* Never true but this prevents optimizing away the strlen */
                        if ( strlen((char*)BPTR(bufp)) == (MAX_STR_LEN*2) )
                        {
                            abort();
                        }
                    }
                    break;
                case    12:
                    buf_chomp(bufp);
                    if ( BLEN(bufp) )
                    {
                        /* Never true but this prevents optimizing away the strlen */
                        if ( strlen((char*)BPTR(bufp)) == (MAX_STR_LEN*2) )
                        {
                            abort();
                        }
                    }
                    break;
                case    13:
                    FUZZER_GET_STRING(str, MAX_STR_LEN);
                    skip_leading_whitespace(str);
                    free(str); str = NULL;
                    break;
                case    14:
                    FUZZER_GET_STRING(str, MAX_STR_LEN);
                    chomp(str);
                    free(str); str = NULL;
                    break;
                case    15:
                    FUZZER_GET_STRING(str, MAX_STR_LEN);
                    FUZZER_GET_STRING(str2, MAX_STR_LEN);
                    rm_trailing_chars(str, str2);
                    free(str); str = NULL;
                    free(str2); str2 = NULL;
                    break;
                case    16:
                    FUZZER_GET_STRING(str, MAX_STR_LEN);
                    string_clear(str);
                    free(str); str = NULL;
                    break;
                case    17:
                    FUZZER_GET_STRING(str, MAX_STR_LEN);
                    buf_string_match_head_str(bufp, str);
                    free(str); str = NULL;
                    break;
                case    18:
                    FUZZER_GET_STRING(str, MAX_STR_LEN);
                    buf_string_compare_advance(bufp, str);
                    free(str); str = NULL;
                    break;
                case    19:
                    FUZZER_GET_STRING(str, MAX_STR_LEN);
                    FUZZER_GET_INTEGER(generic_ssizet, 255);
                    generic_char = generic_ssizet;
                    if ( strlen(str) )
                    {
#ifdef MSAN
                        test_undefined_memory(str, strlen(str)+1);
#endif
                        buf_parse(bufp, (int)generic_char, str, strlen(str));
                    }
                    free(str); str = NULL;
                    break;
                case    20:
                    FUZZER_GET_STRING(str, MAX_STR_LEN);
                    FUZZER_GET_INTEGER(generic_ssizet, 255);
                    generic_char = generic_ssizet;
                    FUZZER_GET_INTEGER(generic_ssizet, 4294967295);
                    FUZZER_GET_INTEGER(generic_ssizet2, 4294967295);
                    string_mod(str, (int)generic_ssizet, (int)generic_ssizet, generic_char);
                    free(str); str = NULL;
                    break;
                case    21:
                    FUZZER_GET_STRING(str, MAX_STR_LEN);
                    FUZZER_GET_INTEGER(generic_ssizet, 255);
                    generic_char = generic_ssizet;
                    FUZZER_GET_INTEGER(generic_ssizet, 255);
                    generic_char2 = generic_ssizet;
                    if ( generic_char )
                    {
                        string_replace_leading(str, generic_char, generic_char2);
                    }
                    free(str); str = NULL;
                    break;
                case    22:
                    FUZZER_GET_STRING(str, MAX_STR_LEN);
                    buf_write(bufp, str, strlen(str));
                    free(str); str = NULL;
                    break;
                case    23:
                    FUZZER_GET_STRING(str, MAX_STR_LEN);
                    buf_write_prepend(bufp, str, strlen(str));
                    free(str); str = NULL;
                    break;
                case    24:
                    FUZZER_GET_INTEGER(generic_ssizet, 255);
                    generic_char = generic_ssizet;
                    buf_write_u8(bufp, (int)generic_char);
                    break;
                case    25:
                    FUZZER_GET_INTEGER(generic_ssizet, 65535);
                    generic_uint16 = generic_ssizet;
                    buf_write_u16(bufp, (int)generic_uint16);
                    break;
                case    26:
                    FUZZER_GET_INTEGER(generic_ssizet, 4294967295);
                    generic_uint32 = generic_ssizet;
                    buf_write_u32(bufp, (int)generic_uint32);
                    break;
                case    27:
                    FUZZER_GET_STRING(str, MAX_STR_LEN);
                    buf_catrunc(bufp, str);
                    free(str); str = NULL;
                    break;
                case    28:
                    convert_to_one_line(bufp);
                    break;
                case    29:
                    FUZZER_GET_INTEGER(generic_ssizet, MAX_STR_LEN);
                    str = (char*)buf_read_alloc(bufp, (int)generic_ssizet);
                    if ( str )
                    {
                        memset(str, 0, generic_ssizet);
                        str = NULL;
                    }
                    break;
                case    30:
                    FUZZER_GET_INTEGER(generic_ssizet, MAX_STR_LEN);
                    buf_advance(bufp, (int)generic_ssizet);
                    break;
                case    31:
                    FUZZER_GET_INTEGER(generic_ssizet, MAX_STR_LEN);
                    buf_prepend(bufp, (int)generic_ssizet);
                    break;
                case    32:
                    /*
                    FUZZER_GET_INTEGER(generic_ssizet, MAX_STR_LEN);
                    buf_inc_len(bufp, (int)generic_ssizet);
                    */
                    break;
                case    33:
                    buf_reverse_capacity(bufp);
                    break;
                case    34:
                    buf_forward_capacity_total(bufp);
                    break;
                case    35:
                    buf_forward_capacity(bufp);
                    break;
                case    36:
                    FUZZER_GET_STRING(str, MAX_STR_LEN);
                    buf_puts(bufp, str);
                    free(str); str = NULL;
                    break;
                case    37:
                    FUZZER_GET_STRING(str, MAX_STR_LEN);
                    buf_printf(bufp, "%s", str);
                    free(str); str = NULL;
                    break;
                case    38:
                    {
                        unsigned char* ret;
                        FUZZER_GET_INTEGER(generic_ssizet, 4294967295);
                        ret = buf_write_alloc(bufp, generic_ssizet);
                        if ( ret )
                        {
                            memset(ret, 0, generic_ssizet);
                        }
                    }
                    break;
            }
        }

        /* Same procedure as above, but now test struct buffer_list */
        if ( buflistp == NULL )
        {
            FUZZER_GET_INTEGER(_size, MAX_STR_LEN);
            buflistp = buffer_list_new(_size);
        }
        else
        {
            FUZZER_GET_INTEGER(generic_ssizet, 6);
            switch ( generic_ssizet )
            {
                case    0:
                    buffer_list_free(buflistp);
                    buflistp = NULL;
                    break;
                case    1:
                    buffer_list_defined(buflistp);
                    break;
                case    2:
                    FUZZER_GET_STRING(str, MAX_STR_LEN);
                    buffer_list_push(buflistp, (const unsigned char*)str);
                    free(str); str = NULL;
                    break;
                case    3:
                    buffer_list_peek(buflistp);
                    break;
                case    4:
                    FUZZER_GET_INTEGER(generic_ssizet, 1024);
                    FUZZER_GET_STRING(str, MAX_STR_LEN);
                    buffer_list_aggregate_separator(buflistp, generic_ssizet, str);
                    free(str); str = NULL;
                    break;
                case    5:
                    FUZZER_GET_INTEGER(generic_ssizet, 1024);
                    buffer_list_aggregate(buflistp, generic_ssizet);
                    break;
                case    6:
                    buffer_list_pop(buflistp);
                    break;
            }
        }
    }

cleanup:
    buffer_list_free(buflistp);
    free(str);
    free(str2);
    gc_free(&gc);
    return 0;
}
