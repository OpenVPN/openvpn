#include "config.h"
#include "syshead.h"

#include "fuzzing.h"
#include "misc.h"
#include "list.h"

/* Required for hash_init() */
static uint32_t
word_hash_function(const void *key, uint32_t iv)
{
    return hash_func(key, sizeof(key), iv);
}

/* Required for hash_init() */
static bool
word_compare_function(const void *key1, const void *key2)
{
    return ((size_t)key1 & 0xFFF) == ((size_t)key1 & 0xFFF);
}

/* Start of serialization of struct hash.
 * This is necessary to test whether the data structure contains
 * any uninitialized data. If it does, MemorySanitizer will detect
 * it upon serialization */

static void serialize_hash_element(struct hash_element* he)
{
    test_undefined_memory(&he->hash_value, sizeof(he->hash_value));
}
static void serialize_hash_element_list(struct hash_element* list)
{
    while ( list )
    {
        serialize_hash_element(list);
        list = list->next;
    }
}
static void serialize_hash_bucket(struct hash_bucket* buckets)
{
    if ( buckets->list )
    {
        serialize_hash_element_list(buckets->list);
    }
}
static void serialize_hash(struct hash* hash)
{
    test_undefined_memory(&hash->n_buckets, sizeof(hash->n_buckets));
    test_undefined_memory(&hash->n_elements, sizeof(hash->n_elements));
    test_undefined_memory(&hash->mask, sizeof(hash->mask));
    test_undefined_memory(&hash->iv, sizeof(hash->iv));
    if ( hash->buckets )
    {
        serialize_hash_bucket(hash->buckets);
    }
}

/* End of serialization of struct hash */

int LLVMFuzzerInitialize(int *argc, char ***argv)
{
    return 1;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    struct gc_arena gc;
    struct hash* hash = NULL;
    ssize_t i, generic_ssizet, generic_ssizet2, num_loops;
    fuzzer_set_input((unsigned char*)data, size);
    gc = gc_new();

    /* Pseudo-randomize the number of loops */
    FUZZER_GET_INTEGER(num_loops, 16);
    for (i = 0; i < num_loops; i++)
    {
        /* Pick one of the functions */
        FUZZER_GET_INTEGER(generic_ssizet, 7);
        switch ( generic_ssizet )
        {
            case    0:
                if ( hash == NULL )
                {
                    int n_buckets;
                    uint32_t iv;
                    FUZZER_GET_INTEGER(generic_ssizet, 102400);
                    n_buckets = generic_ssizet;
                    FUZZER_GET_INTEGER(generic_ssizet, 4294967296);
                    iv = generic_ssizet;
                    hash = hash_init(generic_ssizet, iv, word_hash_function, word_compare_function);
                }
                break;
            case    1:
                if ( hash )
                {
                    hash_free(hash);
                    hash = NULL;
                }
                break;
            case    2:
                if ( hash )
                {
                    struct hash_iterator hi;
                    struct hash_element *he;
                    hash_iterator_init(hash, &hi);
                    while ((he = hash_iterator_next(&hi)))
                    {
                        void *w =  he->value;
                    }
                    hash_iterator_free(&hi);
                }
            case    3:
                if ( hash )
                {
                    void* key;
                    void* value;
                    FUZZER_GET_INTEGER(generic_ssizet, 4294967296);
                    key = (void*)generic_ssizet;
                    if ( !hash_lookup(hash, key) )
                    {
                        FUZZER_GET_INTEGER(generic_ssizet, 4294967296);
                        value = (void*)generic_ssizet;
                        hash_add(hash, key, value, false);
                    }
                }
                break;
            case    4:
                if ( hash )
                {
                    hash_n_elements(hash);
                }
                break;
            case    5:
                if ( hash )
                {
                    hash_n_buckets(hash);
                }
                break;
            case    6:
                if ( hash )
                {
                    uint32_t hv;
                    FUZZER_GET_INTEGER(generic_ssizet, 4294967296);
                    hv = generic_ssizet;
                    hash_bucket(hash, hv);
                }
                break;
            case    7:
                if ( hash )
                {
                    void* key;
                    FUZZER_GET_INTEGER(generic_ssizet, 4294967296);
                    key = (void*)generic_ssizet;
                    hash_remove(hash, key);
                }
                break;
        }
    }

cleanup:
    if ( hash )
    {
        hash_free(hash);
    }
    return 0;
}
