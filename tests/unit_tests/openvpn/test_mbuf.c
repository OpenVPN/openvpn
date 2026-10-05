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
    assert_int_equal(mbuf_len(ms), 1);
    assert_int_equal(mbuf_maximum_queued(ms), 4);
    assert_int_equal(ms->head, 1);
    assert_ptr_equal(mbuf_peek(ms), &mi);

    mbuf_free(ms);
    assert_int_equal(mbuf_buf->refcount, 1);
    mbuf_free_buf(mbuf_buf);
    assert_int_equal(mbuf_buf2->refcount, 1);
    mbuf_free_buf(mbuf_buf2);
}

/* a queue holding nothing but dereferenced items is an empty queue */
static void
test_mbuf_dereference_reclaims_queue(void **state)
{
    struct mbuf_set *ms = mbuf_init(4);
    struct multi_instance mi = { 0 };
    struct buffer buf = alloc_buf(16);
    struct mbuf_buffer *mbuf_buf = mbuf_alloc_buf(&buf);
    struct mbuf_item item = { .buffer = mbuf_buf, .instance = &mi };
    free_buf(&buf);

    for (int i = 0; i < 4; ++i)
    {
        mbuf_add_item(ms, &item);
    }
    assert_int_equal(mbuf_len(ms), 4);
    assert_int_equal(mbuf_buf->refcount, 5);

    mbuf_dereference_instance(ms, &mi);

    assert_int_equal(mbuf_len(ms), 0);
    assert_false(mbuf_defined(ms));
    assert_null(mbuf_peek(ms));
    assert_int_equal(mbuf_buf->refcount, 1);

    /* the queue is empty, so this must be queued and not dropped */
    mbuf_add_item(ms, &item);
    assert_int_equal(mbuf_len(ms), 1);
    assert_ptr_equal(mbuf_peek(ms), &mi);

    mbuf_free(ms);
    mbuf_free_buf(mbuf_buf);
}

/* extracting the last live item must not leave a trailing hole behind */
static void
test_mbuf_extract_reclaims_tail(void **state)
{
    struct mbuf_set *ms = mbuf_init(4);
    struct multi_instance mi = { 0 };
    struct multi_instance mi2 = { 0 };
    struct buffer buf = alloc_buf(16);
    struct mbuf_buffer *mbuf_buf = mbuf_alloc_buf(&buf);
    struct mbuf_item item = { .buffer = mbuf_buf, .instance = &mi };
    struct mbuf_item item2 = { .buffer = mbuf_buf, .instance = &mi2 };
    free_buf(&buf);

    mbuf_add_item(ms, &item);
    mbuf_add_item(ms, &item2);
    mbuf_dereference_instance(ms, &mi2);
    assert_int_equal(mbuf_len(ms), 2); /* head is still live, nothing to reclaim */

    struct mbuf_item out;
    assert_true(mbuf_extract_item(ms, &out));
    assert_ptr_equal(out.instance, &mi);
    mbuf_free_buf(out.buffer);

    assert_int_equal(mbuf_len(ms), 0);
    assert_false(mbuf_defined(ms));
    assert_null(mbuf_peek(ms));

    mbuf_free(ms);
    mbuf_free_buf(mbuf_buf);
}

/* reclaiming stops at the first live item, it does not walk the whole ring */
static void
test_mbuf_extract_reclaims_up_to_live(void **state)
{
    struct mbuf_set *ms = mbuf_init(4);
    struct multi_instance mi = { 0 };
    struct multi_instance mi2 = { 0 };
    struct buffer buf = alloc_buf(16);
    struct mbuf_buffer *mbuf_buf = mbuf_alloc_buf(&buf);
    struct mbuf_item item = { .buffer = mbuf_buf, .instance = &mi };
    struct mbuf_item item2 = { .buffer = mbuf_buf, .instance = &mi2 };
    free_buf(&buf);

    /* [mi][mi2][mi] -> dereferencing mi2 leaves [mi][hole][mi] */
    mbuf_add_item(ms, &item);
    mbuf_add_item(ms, &item2);
    mbuf_add_item(ms, &item);
    mbuf_dereference_instance(ms, &mi2);
    assert_int_equal(mbuf_len(ms), 3); /* head is live, nothing to reclaim yet */

    /* extracting the head leaves the hole in front: it must be reclaimed, and
     * the walk must stop at the live item behind it */
    struct mbuf_item out;
    assert_true(mbuf_extract_item(ms, &out));
    assert_ptr_equal(out.instance, &mi);
    mbuf_free_buf(out.buffer);

    assert_int_equal(mbuf_len(ms), 1);
    assert_true(mbuf_defined(ms));
    assert_ptr_equal(mbuf_peek(ms), &mi);

    mbuf_free(ms);
    mbuf_free_buf(mbuf_buf);
}

/* Holes behind a live item are not reclaimed, so a full ring can still hold
 * them. mbuf_add_item() must cope: it evicts the live head, which drags the
 * holes with it, rather than finding nothing to drop. */
static void
test_mbuf_add_on_full_queue_with_holes(void **state)
{
    struct mbuf_set *ms = mbuf_init(4);
    struct multi_instance mi = { 0 };
    struct multi_instance mi2 = { 0 };
    struct multi_instance mi3 = { 0 };
    struct buffer buf = alloc_buf(16);
    struct mbuf_buffer *mbuf_buf = mbuf_alloc_buf(&buf);
    struct mbuf_item item = { .buffer = mbuf_buf, .instance = &mi };
    struct mbuf_item item2 = { .buffer = mbuf_buf, .instance = &mi2 };
    struct mbuf_item item3 = { .buffer = mbuf_buf, .instance = &mi3 };
    free_buf(&buf);

    /* [mi][mi2][mi2][mi2] -> dereferencing mi2 leaves [mi][hole][hole][hole],
     * which mbuf_reclaim_head() cannot touch: the head is still live */
    mbuf_add_item(ms, &item);
    mbuf_add_item(ms, &item2);
    mbuf_add_item(ms, &item2);
    mbuf_add_item(ms, &item2);
    mbuf_dereference_instance(ms, &mi2);
    assert_int_equal(mbuf_len(ms), 4);
    assert_int_equal(mbuf_len(ms), ms->capacity); /* still counts as full */

    mbuf_add_item(ms, &item3);
    assert_int_equal(mbuf_len(ms), 1);
    assert_ptr_equal(mbuf_peek(ms), &mi3);

    mbuf_free(ms);
    mbuf_free_buf(mbuf_buf);
}

int
main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_mbuf_init),
        cmocka_unit_test(test_mbuf_add_remove),
        cmocka_unit_test(test_mbuf_dereference_reclaims_queue),
        cmocka_unit_test(test_mbuf_extract_reclaims_tail),
        cmocka_unit_test(test_mbuf_extract_reclaims_up_to_live),
        cmocka_unit_test(test_mbuf_add_on_full_queue_with_holes),
    };

    return cmocka_run_group_tests_name("mbuf", tests, NULL, NULL);
}
