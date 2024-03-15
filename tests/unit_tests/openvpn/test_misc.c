/*
 *  OpenVPN -- An application to securely tunnel IP networks
 *             over a single UDP port, with support for SSL/TLS-based
 *             session authentication and key exchange,
 *             packet encryption, packet authentication, and
 *             packet compression.
 *
 *  Copyright (C) 2021-2024 Arne Schwabe <arne@rfc2549.org>
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License version 2
 *  as published by the Free Software Foundation.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License along
 *  with this program; if not, write to the Free Software Foundation, Inc.,
 *  51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "syshead.h"

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <setjmp.h>
#include <cmocka.h>

#include "ssl_util.h"
#include "options_util.h"
#include "test_common.h"
#include "list.h"

static void
test_compat_lzo_string(void **state)
{
    struct gc_arena gc = gc_new();

    const char *input = "V4,dev-type tun,link-mtu 1457,tun-mtu 1400,proto UDPv4,auth SHA1,keysize 128,key-method 2,tls-server";

    const char *output = options_string_compat_lzo(input, &gc);

    assert_string_equal(output, "V4,dev-type tun,link-mtu 1458,tun-mtu 1400,proto UDPv4,auth SHA1,keysize 128,key-method 2,tls-server,comp-lzo");

    /* This string is has a much too small link-mtu so we should fail on it" */
    input = "V4,dev-type tun,link-mtu 2,tun-mtu 1400,proto UDPv4,auth SHA1,keysize 128,key-method 2,tls-server";

    output = options_string_compat_lzo(input, &gc);

    assert_string_equal(input, output);

    /* not matching at all */
    input = "V4,dev-type tun";
    output = options_string_compat_lzo(input, &gc);

    assert_string_equal(input, output);


    input = "V4,dev-type tun,link-mtu 999,tun-mtu 1400,proto UDPv4,auth SHA1,keysize 128,key-method 2,tls-server";
    output = options_string_compat_lzo(input, &gc);

    /* 999 -> 1000, 3 to 4 chars */
    assert_string_equal(output, "V4,dev-type tun,link-mtu 1000,tun-mtu 1400,proto UDPv4,auth SHA1,keysize 128,key-method 2,tls-server,comp-lzo");

    gc_free(&gc);
}

static void
test_auth_fail_temp_no_flags(void **state)
{
    struct options o;

    const char *teststr = "TEMP:There are no flags here [really not]";

    const char *msg = parse_auth_failed_temp(&o, teststr + strlen("TEMP"));
    assert_string_equal(msg, "There are no flags here [really not]");
}

static void
test_auth_fail_temp_flags(void **state)
{
    struct options o;

    const char *teststr = "[backoff 42,advance no]";

    const char *msg = parse_auth_failed_temp(&o, teststr);
    assert_string_equal(msg, "");
    assert_int_equal(o.server_backoff_time, 42);
    assert_int_equal(o.no_advance, true);
}

static void
test_auth_fail_temp_flags_msg(void **state)
{
    struct options o;

    const char *teststr = "[advance remote,backoff 77]:go round and round";

    const char *msg = parse_auth_failed_temp(&o, teststr);
    assert_string_equal(msg, "go round and round");
    assert_int_equal(o.server_backoff_time, 77);
}



struct word
{
    const char *word;
    int n;
};


static uint32_t
word_hash_function(const void *key, uint32_t iv)
{
    const char *str = (const char *) key;
    const int len = strlen(str);
    return hash_func((const uint8_t *)str, len, iv);
}

static bool
word_compare_function(const void *key1, const void *key2)
{
    return strcmp((const char *)key1, (const char *)key2) == 0;
}

static unsigned long
get_random(void)
{
    /* rand() is not very random, but it's C99 and this is just for testing */
    return rand();
}

static struct hash_element *
hash_lookup_by_value(struct hash *hash, void *value)
{
    struct hash_iterator hi;
    struct hash_element *he;
    struct hash_element *ret = NULL;
    hash_iterator_init(hash, &hi);

    while ((he = hash_iterator_next(&hi)))
    {
        if (he->value == value)
        {
            ret = he;
        }
    }
    hash_iterator_free(&hi);
    return ret;
}

static void
test_list(void **state)
{

/*
 * Test the hash code by implementing a simple
 * word frequency algorithm.
 */

    struct gc_arena gc = gc_new();
    struct hash *hash = hash_init(10000, get_random(), word_hash_function, word_compare_function);
    struct hash *nhash = hash_init(256, get_random(), word_hash_function, word_compare_function);

    printf("hash_init n_buckets=%d mask=0x%08x\n", hash->n_buckets, hash->mask);

    char wordfile[PATH_MAX] = { 0 };
    openvpn_test_get_srcdir_dir(wordfile, PATH_MAX, "/../../../COPYRIGHT.GPL" );

    FILE *words = fopen(wordfile, "r");
    assert_non_null(words);

    int wordcount = 0;

    /* parse words from file */
    while (true)
    {
        char buf[256];
        char wordbuf[256];

        if (!fgets(buf, sizeof(buf), words))
        {
            break;
        }

        char c = 0;
        int bi = 0, wbi = 0;

        do
        {
            c = buf[bi++];
            if (isalnum(c) || c == '_')
            {
                assert_true(wbi < (int) sizeof(wordbuf));
                wordbuf[wbi++] = c;
            }
            else
            {
                if (wbi)
                {
                    wordcount++;

                    ASSERT(wbi < (int) sizeof(wordbuf));
                    wordbuf[wbi++] = '\0';

                    /* word is parsed from stdin */

                    /* does it already exist in table? */
                    struct word *w = (struct word *) hash_lookup(hash, wordbuf);

                    if (w)
                    {
                        assert_string_equal(w->word, wordbuf);
                        /* yes, increment count */
                        ++w->n;
                    }
                    else
                    {
                        /* no, make a new object */
                        ALLOC_OBJ_GC(w, struct word, &gc);
                        w->word = string_alloc(wordbuf, &gc);
                        w->n = 1;
                        assert_true(hash_add(hash, w->word, w, false));
                        assert_true(hash_add(nhash, w->word, (void *) ((ptr_type )(random() & 0x0F) + 1), false));
                    }
                }
                wbi = 0;
            }
        }
        while (c);
    }

    assert_int_equal(wordcount, 2978);

    /* remove some words from the table */
    {
        assert_true(hash_remove(hash, "DEFECTIVE"));
        assert_false(hash_remove(hash, "false"));
    }

    /* output contents of hash table */
    {
        ptr_type inc = 0;
        int count = 0;

        for (ptr_type base = 0; base < hash_n_buckets(hash); base += inc)
        {
            struct hash_iterator hi;
            struct hash_element *he;
            inc = (get_random() % 3) + 1;
            hash_iterator_init_range(hash, &hi, base, base + inc);

            while ((he = hash_iterator_next(&hi)))
            {
                struct word *w = (struct word *) he->value;
                /*printf("%6d '%s'\n", w->n, w->word); */
                ++count;
                /* check a few words to match prior results */
                if (!strcmp(w->word, "is"))
                {
                    assert_int_equal(w->n, 49);
                }
                else if  (!strcmp(w->word, "redistribute"))
                {
                    assert_int_equal(w->n, 5);
                }
                else if  (!strcmp(w->word, "circumstances"))
                {
                    assert_int_equal(w->n, 1);
                }
                else if  (!strcmp(w->word, "so"))
                {
                    assert_int_equal(w->n, 8);
                }
                else if  (!strcmp(w->word, "BECAUSE"))
                {
                    assert_int_equal(w->n, 1);
                }
            }

            hash_iterator_free(&hi);
        }
        assert_int_equal(count, hash_n_elements(hash));
    }

    /* test hash_remove_by_value function */
    {
        for (ptr_type i = 1; i <= 16; ++i)
        {
            struct hash_element *item = hash_lookup_by_value(nhash, (void *) i);
            hash_remove_by_value(nhash, (void *) i);
            /* check item got removed if it was present before */
            if (item)
            {
                assert_null(hash_lookup_by_value(nhash, (void *) i));
            }
        }
    }

    hash_free(hash);
    hash_free(nhash);
    gc_free(&gc);
}


const struct CMUnitTest misc_tests[] = {
    cmocka_unit_test(test_compat_lzo_string),
    cmocka_unit_test(test_auth_fail_temp_no_flags),
    cmocka_unit_test(test_auth_fail_temp_flags),
    cmocka_unit_test(test_auth_fail_temp_flags_msg),
    cmocka_unit_test(test_list)
};

int
main(void)
{
    openvpn_unit_test_setup();
    return cmocka_run_group_tests(misc_tests, NULL, NULL);
}
