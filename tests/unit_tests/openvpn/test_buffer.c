/*
 *  OpenVPN -- An application to securely tunnel IP networks
 *             over a single UDP port, with support for SSL/TLS-based
 *             session authentication and key exchange,
 *             packet encryption, packet authentication, and
 *             packet compression.
 *
 *  Copyright (C) 2016-2018 Fox Crypto B.V. <openvpn@fox-it.com>
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
#elif defined(_MSC_VER)
#include "config-msvc.h"
#endif

#include "syshead.h"

#include <setjmp.h>
#include <cmocka.h>

#include "buffer.h"
#include "buffer.c"

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
    ctx->empty = buffer_list_new(0);

    ctx->one_two_three = buffer_list_new(3);
    buffer_list_push(ctx->one_two_three, teststr1);
    buffer_list_push(ctx->one_two_three, teststr2);
    buffer_list_push(ctx->one_two_three, teststr3);

    ctx->zero_length_strings = buffer_list_new(2);
    buffer_list_push(ctx->zero_length_strings, "");
    buffer_list_push(ctx->zero_length_strings, "");

    ctx->empty_buffers = buffer_list_new(2);
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
test_buffer_list_full(void **state)
{
    struct test_buffer_list_aggregate_ctx *ctx = *state;

    /* list full */
    assert_int_equal(ctx->one_two_three->size, 3);
    buffer_list_push(ctx->one_two_three, teststr4);
    assert_int_equal(ctx->one_two_three->size, 3);
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

int
main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_buffer_strprefix),
        cmocka_unit_test_setup_teardown(test_buffer_list_full,
                                        test_buffer_list_setup,
                                        test_buffer_list_teardown),
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
    };

    return cmocka_run_group_tests_name("buffer", tests, NULL, NULL);
}
