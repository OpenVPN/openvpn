/*
 *  OpenVPN -- An application to securely tunnel IP networks
 *             over a single UDP port, with support for SSL/TLS-based
 *             session authentication and key exchange,
 *             packet encryption, packet authentication, and
 *             packet compression.
 *
 *  Copyright (C) 2016-2021 Fox Crypto B.V. <openvpn@foxcrypto.com>
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

#include <setjmp.h>
#include <cmocka.h>

#include "buffer.h"
#include "buffer.c"
#include "test_common.h"

static void
test_buffer_strprefix(void **state)
{
    assert_true(strprefix("123456", "123456"));
    assert_true(strprefix("123456", "123"));
    assert_true(strprefix("123456", ""));
    assert_false(strprefix("123456", "456"));
    assert_false(strprefix("12", "123"));
}

#define testsep ","
#define testnosep ""
#define teststr1 "one"
#define teststr2 "two"
#define teststr3 "three"
#define teststr4 "four"

#define assert_buf_equals_str(buf, str) \
    assert_int_equal(BLEN(buf), strlen(str)); \
    assert_memory_equal(BPTR(buf), str, BLEN(buf));

static void
test_buffer_printf_catrunc(void **state)
{
    struct gc_arena gc = gc_new();
    struct buffer buf = alloc_buf_gc(16, &gc);

    buf_printf(&buf, "%d", 123);
    buf_printf(&buf, "%s", "some text, too long to fit");
    assert_buf_equals_str(&buf, "123some text, t");

    buf_catrunc(&buf, "...");
    assert_buf_equals_str(&buf, "123some text...");

    buf_catrunc(&buf, "some other text, much too long to fit");
    assert_buf_equals_str(&buf, "123some text...");

    buf_catrunc(&buf, "something else"); /* exactly right */
    assert_buf_equals_str(&buf, "1something else");

    buf_catrunc(&buf, "something other"); /* 1 byte too long */
    assert_buf_equals_str(&buf, "1something else");

    gc_free(&gc);
}

static void
test_buffer_format_hex_ex(void **state)
{
    const int input_size = 10;
    const uint8_t input[] = {
        0x01, 0x00, 0xff, 0x10, 0xff, 0x00, 0xf0, 0x0f, 0x09, 0x0a
    };
    char *output;
    struct gc_arena gc = gc_new();

    int maxoutput = 0;
    unsigned int blocksize = 5;
    char *separator = " ";
    output = format_hex_ex(input, input_size, maxoutput, blocksize, separator, &gc);
    assert_string_equal(output, "0100ff10ff 00f00f090a");

    maxoutput = 14;
    output = format_hex_ex(input, input_size, maxoutput, blocksize, separator, &gc);
    assert_string_equal(output, "0100[more...]");

    maxoutput = 11;
    output = format_hex_ex(input, input_size, maxoutput, blocksize, separator, &gc);
    assert_string_equal(output, "0[more...]");

    maxoutput = 10;
    output = format_hex_ex(input, input_size, maxoutput, blocksize, separator, &gc);
    assert_string_equal(output, "0100ff10f");

    maxoutput = 9;
    output = format_hex_ex(input, input_size, maxoutput, blocksize, separator, &gc);
    assert_string_equal(output, "0100ff10");

    gc_free(&gc);
}

struct test_buffer_list_aggregate_ctx {
    struct buffer_list *empty;
    struct buffer_list *one_two_three;
    struct buffer_list *zero_length_strings;
    struct buffer_list *empty_buffers;
};

static int
test_buffer_list_setup(void **state)
{
    struct test_buffer_list_aggregate_ctx *ctx  = calloc(1, sizeof(*ctx));
    ctx->empty = buffer_list_new();

    ctx->one_two_three = buffer_list_new();
    buffer_list_push(ctx->one_two_three, teststr1);
    buffer_list_push(ctx->one_two_three, teststr2);
    buffer_list_push(ctx->one_two_three, teststr3);

    ctx->zero_length_strings = buffer_list_new();
    buffer_list_push(ctx->zero_length_strings, "");
    buffer_list_push(ctx->zero_length_strings, "");

    ctx->empty_buffers = buffer_list_new();
    uint8_t data = 0;
    buffer_list_push_data(ctx->empty_buffers, &data, 0);
    buffer_list_push_data(ctx->empty_buffers, &data, 0);

    *state = ctx;
    return 0;
}

static int
test_buffer_list_teardown(void **state)
{
    struct test_buffer_list_aggregate_ctx *ctx = *state;

    buffer_list_free(ctx->empty);
    buffer_list_free(ctx->one_two_three);
    buffer_list_free(ctx->zero_length_strings);
    buffer_list_free(ctx->empty_buffers);
    free(ctx);
    return 0;
}

static void
test_buffer_list_aggregate_separator_empty(void **state)
{
    struct test_buffer_list_aggregate_ctx *ctx = *state;

    /* aggregating an empty buffer list results in an empty buffer list */
    buffer_list_aggregate_separator(ctx->empty, 3, testsep);
    assert_null(ctx->empty->head);
}

static void
test_buffer_list_aggregate_separator_noop(void **state)
{
    struct test_buffer_list_aggregate_ctx *ctx = *state;

    /* With a max length of 2, no aggregation should take place */
    buffer_list_aggregate_separator(ctx->one_two_three, 2, testsep);
    assert_int_equal(ctx->one_two_three->size, 3);
    struct buffer *buf = buffer_list_peek(ctx->one_two_three);
    assert_buf_equals_str(buf, teststr1);
}

static void
test_buffer_list_aggregate_separator_two(void **state)
{
    struct test_buffer_list_aggregate_ctx *ctx = *state;
    const char *expected = teststr1 testsep teststr2 testsep;

    /* Aggregate the first two elements
     * (add 1 to max_len to test if "three" is not sneaked in too)
     */
    buffer_list_aggregate_separator(ctx->one_two_three, strlen(expected) + 1,
                                    testsep);
    assert_int_equal(ctx->one_two_three->size, 2);
    struct buffer *buf = buffer_list_peek(ctx->one_two_three);
    assert_buf_equals_str(buf, expected);
}

static void
test_buffer_list_aggregate_separator_all(void **state)
{
    struct test_buffer_list_aggregate_ctx *ctx = *state;

    /* Aggregate all */
    buffer_list_aggregate_separator(ctx->one_two_three, 1<<16, testsep);
    assert_int_equal(ctx->one_two_three->size, 1);
    struct buffer *buf = buffer_list_peek(ctx->one_two_three);
    assert_buf_equals_str(buf,
                          teststr1 testsep teststr2 testsep teststr3 testsep);
}

static void
test_buffer_list_aggregate_separator_nosep(void **state)
{
    struct test_buffer_list_aggregate_ctx *ctx = *state;

    /* Aggregate all */
    buffer_list_aggregate_separator(ctx->one_two_three, 1<<16, testnosep);
    assert_int_equal(ctx->one_two_three->size, 1);
    struct buffer *buf = buffer_list_peek(ctx->one_two_three);
    assert_buf_equals_str(buf, teststr1 teststr2 teststr3);
}

static void
test_buffer_list_aggregate_separator_zerolen(void **state)
{
    struct test_buffer_list_aggregate_ctx *ctx = *state;
    struct buffer_list *bl_zerolen = ctx->zero_length_strings;

    /* Aggregate all */
    buffer_list_aggregate_separator(bl_zerolen, 1<<16, testnosep);
    assert_int_equal(bl_zerolen->size, 1);
    struct buffer *buf = buffer_list_peek(bl_zerolen);
    assert_buf_equals_str(buf, "");
}

static void
test_buffer_list_aggregate_separator_emptybuffers(void **state)
{
    struct test_buffer_list_aggregate_ctx *ctx = *state;
    struct buffer_list *bl_emptybuffers = ctx->empty_buffers;

    /* Aggregate all */
    buffer_list_aggregate_separator(bl_emptybuffers, 1<<16, testnosep);
    assert_int_equal(bl_emptybuffers->size, 1);
    struct buffer *buf = buffer_list_peek(bl_emptybuffers);
    assert_int_equal(BLEN(buf), 0);
}

static void
test_buffer_free_gc_one(void **state)
{
    struct gc_arena gc = gc_new();
    struct buffer buf = alloc_buf_gc(1024, &gc);

    assert_ptr_equal(gc.list + 1, buf.data);
    free_buf_gc(&buf, &gc);
    assert_null(gc.list);

    gc_free(&gc);
}

static void
test_buffer_free_gc_two(void **state)
{
    struct gc_arena gc = gc_new();
    struct buffer buf1 = alloc_buf_gc(1024, &gc);
    struct buffer buf2 = alloc_buf_gc(1024, &gc);
    struct buffer buf3 = alloc_buf_gc(1024, &gc);

    struct gc_entry *e;

    e = gc.list;

    assert_ptr_equal(e + 1, buf3.data);
    assert_ptr_equal(e->next + 1, buf2.data);
    assert_ptr_equal(e->next->next + 1, buf1.data);

    free_buf_gc(&buf2, &gc);

    assert_non_null(gc.list);

    while (e)
    {
        assert_ptr_not_equal(e + 1, buf2.data);
        e = e->next;
    }

    gc_free(&gc);
}


static void
test_buffer_gc_realloc(void **state)
{
    struct gc_arena gc = gc_new();

    void *p1 = gc_realloc(NULL, 512, &gc);
    void *p2 = gc_realloc(NULL, 512, &gc);

    assert_ptr_not_equal(p1, p2);

    memset(p1, '1', 512);
    memset(p2, '2', 512);

    p1 = gc_realloc(p1, 512, &gc);

    /* allocate 512kB to ensure the pointer needs to change */
    void *p1new = gc_realloc(p1, 512ul * 1024, &gc);
    assert_ptr_not_equal(p1, p1new);

    void *p2new = gc_realloc(p2, 512ul * 1024, &gc);
    assert_ptr_not_equal(p2, p2new);

    void *p3 = gc_realloc(NULL, 512, &gc);
    memset(p3, '3', 512);


    gc_free(&gc);
}

static void
test_character_class(void **state)
{
    char buf[256];
    strcpy(buf, "There is \x01 a nice 1234 year old tr\x7f ee!");
    assert_false(string_mod(buf, CC_PRINT, 0, '@'));
    assert_string_equal(buf, "There is @ a nice 1234 year old tr@ ee!");

    strcpy(buf, "There is \x01 a nice 1234 year old tr\x7f ee!");
    assert_true(string_mod(buf, CC_ANY, 0, '@'));
    assert_string_equal(buf, "There is \x01 a nice 1234 year old tr\x7f ee!");

    /* 0 as replace removes characters */
    strcpy(buf, "There is \x01 a nice 1234 year old tr\x7f ee!");
    assert_false(string_mod(buf, CC_PRINT, 0, '\0'));
    assert_string_equal(buf, "There is  a nice 1234 year old tr ee!");

    strcpy(buf, "There is \x01 a nice 1234 year old tr\x7f ee!");
    assert_false(string_mod(buf, CC_PRINT, CC_DIGIT, '@'));
    assert_string_equal(buf, "There is @ a nice @@@@ year old tr@ ee!");

    strcpy(buf, "There is \x01 a nice 1234 year old tr\x7f ee!");
    assert_false(string_mod(buf, CC_ALPHA, CC_DIGIT, '.'));
    assert_string_equal(buf, "There.is...a.nice......year.old.tr..ee.");

    strcpy(buf, "There is \x01 a 'nice' \"1234\"\n year old \ntr\x7f ee!");
    assert_false(string_mod(buf, CC_ALPHA|CC_DIGIT|CC_NEWLINE|CC_SINGLE_QUOTE, CC_DOUBLE_QUOTE|CC_BLANK, '.'));
    assert_string_equal(buf, "There.is...a.'nice'..1234.\n.year.old.\ntr..ee.");

    strcpy(buf, "There is a \\'nice\\' \"1234\" [*] year old \ntree!");
    assert_false(string_mod(buf, CC_PRINT, CC_BACKSLASH|CC_ASTERISK, '.'));
    assert_string_equal(buf, "There is a .'nice.' \"1234\" [.] year old .tree!");
}

static void
test_snprintf(void **state)
{
    /* we used to have a custom openvpn_snprintf function because some
     * OS (the comment did not specify which) did not always put the
     * null byte there. So we unit test this to be sure.
     *
     * This probably refers to the MSVC behaviour, see also
     * https://stackoverflow.com/questions/7706936/is-snprintf-always-null-terminating
     */

    /* Instead of trying to trick the compiler here, disable the warnings
     * for this unit test. We know that the results will be truncated
     * and we want to test that */
#if defined(__GNUC__)
/* some clang version do not understand -Wformat-truncation, so ignore the
 * warning to avoid warnings/errors (-Werror) about unknown pragma/option */
#if defined(__clang__)
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wunknown-warning-option"
#endif
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wformat-truncation"
#endif

    char buf[10] = { 'a' };
    int ret = 0;

    ret = snprintf(buf, sizeof(buf), "0123456789abcde");
    assert_int_equal(ret, 15);
    assert_int_equal(buf[9], '\0');

    memset(buf, 'b', sizeof(buf));
    ret = snprintf(buf, sizeof(buf), "- %d - %d -", 77, 88);
    assert_int_equal(ret, 11);
    assert_int_equal(buf[9], '\0');

    memset(buf, 'c', sizeof(buf));
    ret = snprintf(buf, sizeof(buf), "- %8.2f", 77.8899);
    assert_int_equal(ret, 10);
    assert_int_equal(buf[9], '\0');

#if defined(__GNUC__)
#pragma GCC diagnostic pop
#if defined(__clang__)
#pragma clang diagnostic pop
#endif
#endif
}

int
main(void)
{
    openvpn_unit_test_setup();
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_buffer_strprefix),
        cmocka_unit_test(test_buffer_printf_catrunc),
        cmocka_unit_test(test_buffer_format_hex_ex),
        cmocka_unit_test_setup_teardown(test_buffer_list_aggregate_separator_empty,
                                        test_buffer_list_setup,
                                        test_buffer_list_teardown),
        cmocka_unit_test_setup_teardown(test_buffer_list_aggregate_separator_noop,
                                        test_buffer_list_setup,
                                        test_buffer_list_teardown),
        cmocka_unit_test_setup_teardown(test_buffer_list_aggregate_separator_two,
                                        test_buffer_list_setup,
                                        test_buffer_list_teardown),
        cmocka_unit_test_setup_teardown(test_buffer_list_aggregate_separator_all,
                                        test_buffer_list_setup,
                                        test_buffer_list_teardown),
        cmocka_unit_test_setup_teardown(test_buffer_list_aggregate_separator_nosep,
                                        test_buffer_list_setup,
                                        test_buffer_list_teardown),
        cmocka_unit_test_setup_teardown(test_buffer_list_aggregate_separator_zerolen,
                                        test_buffer_list_setup,
                                        test_buffer_list_teardown),
        cmocka_unit_test_setup_teardown(test_buffer_list_aggregate_separator_emptybuffers,
                                        test_buffer_list_setup,
                                        test_buffer_list_teardown),
        cmocka_unit_test(test_buffer_free_gc_one),
        cmocka_unit_test(test_buffer_free_gc_two),
        cmocka_unit_test(test_buffer_gc_realloc),
        cmocka_unit_test(test_character_class),
        cmocka_unit_test(test_snprintf)
    };

    return cmocka_run_group_tests_name("buffer", tests, NULL, NULL);
}
