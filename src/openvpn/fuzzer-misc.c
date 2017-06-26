#include "config.h"
#include "syshead.h"
#include "fuzzing.h"
#include "misc.h"
#include "buffer.h"

#define SUBBUFFER_SIZE 256

int LLVMFuzzerInitialize(int *argc, char ***argv)
{
    return 1;
}
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    struct gc_arena gc;
    struct env_set* es;
    ssize_t i, generic_ssizet, num_loops;
    size_t value1, value2;
    char *string1 = NULL, *string2 = NULL, *string_out;
    fuzzer_set_input((unsigned char*)data, size);
    gc = gc_new();
    es = env_set_create(&gc);

    FUZZER_GET_STRING_GC(string1, 256, &gc);
    FUZZER_GET_STRING_GC(string2, 256, &gc);

    if ( strlen(string1) < 2 || strlen(string2) < 2 )
    {
        goto cleanup;
    }

    /* Randomize in case the function depends on it value (it shouldn't)*/
    FUZZER_GET_DATA(&string_out, sizeof(char*));

    FUZZER_GET_INTEGER(num_loops, 16);
    for (i = 0; i < num_loops; i++)
    {
        FUZZER_GET_INTEGER(generic_ssizet, 24);
        switch ( generic_ssizet )
        {
            case 0:
                break;
            case 1:
                //deconstruct_name_value(string1, &string_out, string2, &gc);
                break;
            case 2:
                env_set_del(es, string1);
                break;
            case 3:
                env_set_add(es, string1);
                break;
            case 4:
                env_set_get(es, string1);
                break;
            case 5:
                env_set_print(0, es);
                break;
            case 6:
                setenv_counter(es, string1, (counter_type)value1);
                break;
            case 7:
                setenv_int(es, string1, (int)value1);
                break;
            case 8:
                FUZZER_GET_DATA(&value1, sizeof(value1));
                setenv_unsigned(es, string1, (unsigned int)value1);
                break;
            case 9:
                setenv_str(es, string1, string2);
                break;
            case 10:
                setenv_str_safe(es, string1, string2);
                break;
            case 11:
                setenv_str_incr(es, string1, string2);
                break;
            case 12:
                env_set_del(es, string1);
                break;
            case 13:
                FUZZER_GET_DATA(&value1, sizeof(value1));
                FUZZER_GET_DATA(&value2, sizeof(value2));
                setenv_int_i(es, string1, value1, (int)value2);
                break;
            case 14:
                FUZZER_GET_DATA(&value1, sizeof(value1));
                setenv_str_i(es, string1, string2, (int)value1);
                break;
            case 15:
                hostname_randomize(string1, &gc);
                break;
            case 16:
                gen_path(string1, string2, &gc);
                break;
            case 17:
                absolute_pathname(string1);
                break;
            case 18:
                get_auth_challenge(string1, &gc);
                break;
            case 19:
                safe_print(string1, &gc);
                break;
            case 20:
                FUZZER_GET_INTEGER(generic_ssizet, 1);
                string_array_len( make_env_array(es, generic_ssizet ? true : false, &gc) );
                break;
            case 21:
                string_array_len( make_arg_array(string1, string2, &gc) );
                break;
            case 22:
                sanitize_control_message(string1, &gc);
                break;
            case 23:
                validate_peer_info_line(string1);
                break;
            case 24:
                output_peer_info_env(es, string1);
                break;
        }
    }
cleanup:
    env_set_destroy(es);
    gc_free(&gc);
    return 0;
}
