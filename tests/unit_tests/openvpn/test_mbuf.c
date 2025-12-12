/*
 *  OpenVPN -- An application to securely tunnel IP networks
 *             over a single UDP port, with support for SSL/TLS-based
 *             session authentication and key exchange,
 *             packet encryption, packet authentication, and
 *             packet compression.
 *
 *  Copyright (C) 2025 OpenVPN Inc. <sales@openvpn.com>
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
 *  with this program; if not, see <https://www.gnu.org/licenses/>.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "syshead.h"

#include <setjmp.h>
#include <cmocka.h>

#include "buffer.h"
#include "multi.h"
#include "mbuf.h"
#include "test_common.h"

static void
test_mbuf_init(void **state)
{
    struct mbuf_set *ms = mbuf_init(256);
    assert_int_equal(ms->capacity, 256);
    assert_false(mbuf_defined(ms));
    assert_non_null(ms->array);
    mbuf_free(ms);

    ms = mbuf_init(257);
    assert_int_equal(ms->capacity, 512);
    mbuf_free(ms);

#ifdef UNIT_TEST_ALLOW_BIG_ALLOC /* allocates up to 2GB of memory */
    ms = mbuf_init(MBUF_SIZE_MAX);
    assert_int_equal(ms->capacity, MBUF_SIZE_MAX);
    mbuf_free(ms);

/* NOTE: expect_assert_failure does not seem to work with MSVC */
#ifndef _MSC_VER
    expect_assert_failure(mbuf_init(MBUF_SIZE_MAX + 1));
#endif
#endif
}

static void
test_mbuf_add_remove(void **state)
{
    struct mbuf_set *ms = mbuf_init(4);
    assert_int_equal(ms->capacity, 4);
    assert_false(mbuf_defined(ms));
    assert_non_null(ms->array);

    /* instances */
    struct multi_instance mi = { 0 };
    struct multi_instance mi2 = { 0 };
    /* buffers */
    struct buffer buf = alloc_buf(16);
    struct mbuf_buffer *mbuf_buf = mbuf_alloc_buf(&buf);
    assert_int_equal(mbuf_buf->refcount, 1);
    struct mbuf_buffer *mbuf_buf2 = mbuf_alloc_buf(&buf);
    assert_int_equal(mbuf_buf2->refcount, 1);
    free_buf(&buf);
    /* items */
    struct mbuf_item mb_item = { .buffer = mbuf_buf, .instance = &mi };
    struct mbuf_item mb_item2 = { .buffer = mbuf_buf2, .instance = &mi2 };

    mbuf_add_item(ms, &mb_item);
    assert_int_equal(mbuf_buf->refcount, 2);
    assert_int_equal(mbuf_buf2->refcount, 1);
    assert_int_equal(mbuf_len(ms), 1);
    assert_int_equal(mbuf_maximum_queued(ms), 1);
    assert_int_equal(ms->head, 0);
    assert_ptr_equal(mbuf_peek(ms), &mi);

    mbuf_add_item(ms, &mb_item2);
    assert_int_equal(mbuf_buf->refcount, 2);
    assert_int_equal(mbuf_buf2->refcount, 2);
    assert_int_equal(mbuf_len(ms), 2);
    assert_int_equal(mbuf_maximum_queued(ms), 2);
    assert_int_equal(ms->head, 0);
    assert_ptr_equal(mbuf_peek(ms), &mi);

    mbuf_add_item(ms, &mb_item2);
    assert_int_equal(mbuf_buf->refcount, 2);
    assert_int_equal(mbuf_buf2->refcount, 3);
    assert_int_equal(mbuf_len(ms), 3);
    assert_int_equal(mbuf_maximum_queued(ms), 3);
    assert_int_equal(ms->head, 0);
    assert_ptr_equal(mbuf_peek(ms), &mi);

    mbuf_add_item(ms, &mb_item2);
    mbuf_add_item(ms, &mb_item2); /* overflow, first item gets removed */
    assert_int_equal(mbuf_buf->refcount, 1);
    assert_int_equal(mbuf_buf2->refcount, 5);
    assert_int_equal(mbuf_len(ms), 4);
    assert_int_equal(mbuf_maximum_queued(ms), 4);
    assert_int_equal(ms->head, 1);
    assert_ptr_equal(mbuf_peek(ms), &mi2);

    mbuf_add_item(ms, &mb_item);
    assert_int_equal(mbuf_buf->refcount, 2);
    assert_int_equal(mbuf_buf2->refcount, 4);
    assert_int_equal(mbuf_len(ms), 4);
    assert_int_equal(mbuf_maximum_queued(ms), 4);
    assert_int_equal(ms->head, 2);
    assert_ptr_equal(mbuf_peek(ms), &mi2);

    struct mbuf_item out_item;
    assert_true(mbuf_extract_item(ms, &out_item));
    assert_ptr_equal(out_item.instance, mb_item2.instance);
    assert_int_equal(mbuf_buf->refcount, 2);
    assert_int_equal(mbuf_buf2->refcount, 4);
    assert_int_equal(mbuf_len(ms), 3);
    assert_int_equal(mbuf_maximum_queued(ms), 4);
    assert_int_equal(ms->head, 3);
    assert_ptr_equal(mbuf_peek(ms), &mi2);
    mbuf_free_buf(out_item.buffer);

    mbuf_dereference_instance(ms, &mi2);
    assert_int_equal(mbuf_buf->refcount, 2);
    assert_int_equal(mbuf_buf2->refcount, 1);
    assert_int_equal(mbuf_len(ms), 3);
    assert_int_equal(mbuf_maximum_queued(ms), 4);
    assert_int_equal(ms->head, 3);
    assert_ptr_equal(mbuf_peek(ms), &mi);

    mbuf_free(ms);
    assert_int_equal(mbuf_buf->refcount, 1);
    mbuf_free_buf(mbuf_buf);
    assert_int_equal(mbuf_buf2->refcount, 1);
    mbuf_free_buf(mbuf_buf2);
}

int
main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_mbuf_init),
        cmocka_unit_test(test_mbuf_add_remove),
    };

    return cmocka_run_group_tests_name("mbuf", tests, NULL, NULL);
}
