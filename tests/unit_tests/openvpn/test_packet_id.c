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
 *  You should have received a copy of the GNU General Public License
 *  along with this program (see the file COPYING included with this
 *  distribution); if not, write to the Free Software Foundation, Inc.,
 *  59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "syshead.h"

#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>

#include "packet_id.h"
#include "reliable.h"
#include "test_common.h"

struct test_packet_id_write_data {
    struct {
        uint32_t buf_id;
        uint32_t buf_time;
    } test_buf_data;
    struct buffer test_buf;
    struct packet_id_send pis;
    struct gc_arena gc;
};

static int
test_packet_id_write_setup(void **state)
{
    struct test_packet_id_write_data *data =
        calloc(1, sizeof(struct test_packet_id_write_data));

    if (!data)
    {
        return -1;
    }

    data->test_buf.data = (void *) &data->test_buf_data;
    data->test_buf.capacity = sizeof(data->test_buf_data);
    data->gc = gc_new();

    *state = data;
    return 0;
}

static int
test_packet_id_write_teardown(void **state)
{
    struct test_packet_id_write_data *data = *state;
    gc_free(&data->gc);
    free(*state);
    return 0;
}

static void
test_packet_id_write_short(void **state)
{
    struct test_packet_id_write_data *data = *state;

    now = 5010;
    assert_true(packet_id_write(&data->pis, &data->test_buf, false, false));
    assert_true(data->pis.id == 1);
    assert_true(data->test_buf_data.buf_id == htonl(1));
    assert_true(data->test_buf_data.buf_time == 0);
}

static void
test_packet_id_write_long(void **state)
{
    struct test_packet_id_write_data *data = *state;

    now = 5010;
    assert_true(packet_id_write(&data->pis, &data->test_buf, true, false));
    assert_int_equal(data->pis.id, 1);
    assert_int_equal(data->pis.time, now);
    assert_true(data->test_buf_data.buf_id == htonl(1));
    assert_true(data->test_buf_data.buf_time == htonl((uint32_t)now));
}

static void
test_packet_id_write_short_prepend(void **state)
{
    struct test_packet_id_write_data *data = *state;

    data->test_buf.offset = sizeof(packet_id_type);
    now = 5010;
    assert_true(packet_id_write(&data->pis, &data->test_buf, false, true));
    assert_true(data->pis.id == 1);
    assert_true(data->test_buf_data.buf_id == htonl(1));
    assert_true(data->test_buf_data.buf_time == 0);
}

static void
test_packet_id_write_long_prepend(void **state)
{
    struct test_packet_id_write_data *data = *state;

    data->test_buf.offset = sizeof(data->test_buf_data);
    now = 5010;
    assert_true(packet_id_write(&data->pis, &data->test_buf, true, true));
    assert_int_equal(data->pis.id, 1);
    assert_int_equal(data->pis.time, now);
    assert_true(data->test_buf_data.buf_id == htonl(1));
    assert_true(data->test_buf_data.buf_time == htonl((uint32_t)now));
}

static void
test_packet_id_write_short_wrap(void **state)
{
    struct test_packet_id_write_data *data = *state;

    /* maximum 32-bit packet id */
    data->pis.id = (packet_id_type)(~0);
    assert_false(packet_id_write(&data->pis, &data->test_buf, false, false));
}

static void
test_packet_id_write_long_wrap(void **state)
{
    struct test_packet_id_write_data *data = *state;

    /* maximum 32-bit packet id */
    data->pis.id = (packet_id_type)(~0);
    data->pis.time = 5006;

    /* Write fails if time did not change */
    now = 5006;
    assert_false(packet_id_write(&data->pis, &data->test_buf, true, false));

    /* Write succeeds if time moved forward */
    now = 5010;
    assert_true(packet_id_write(&data->pis, &data->test_buf, true, false));

    assert_int_equal(data->pis.id, 1);
    assert_int_equal(data->pis.time, now);
    assert_true(data->test_buf_data.buf_id == htonl(1));
    assert_true(data->test_buf_data.buf_time == htonl((uint32_t)now));
}

static void
test_get_num_output_sequenced_available(void **state)
{

    struct reliable *rel = malloc(sizeof(struct reliable));
    reliable_init(rel, 100, 50, 8, false);

    rel->array[5].active = true;
    rel->array[5].packet_id = 100;

    rel->packet_id = 103;

    assert_int_equal(5, reliable_get_num_output_sequenced_available(rel));

    rel->array[6].active = true;
    rel->array[6].packet_id = 97;
    assert_int_equal(2, reliable_get_num_output_sequenced_available(rel));

    /* test ids close to int/unsigned int barrier */

    rel->array[5].active = true;
    rel->array[5].packet_id = (0x80000000u -3);
    rel->array[6].active = false;
    rel->packet_id = (0x80000000u -1);

    assert_int_equal(6, reliable_get_num_output_sequenced_available(rel));

    rel->array[5].active = true;
    rel->array[5].packet_id = (0x80000000u -3);
    rel->packet_id = 0x80000001u;

    assert_int_equal(4, reliable_get_num_output_sequenced_available(rel));


    /* test wrapping */
    rel->array[5].active = true;
    rel->array[5].packet_id = (0xffffffffu -3);
    rel->array[6].active = false;
    rel->packet_id = (0xffffffffu - 1);

    assert_int_equal(6, reliable_get_num_output_sequenced_available(rel));

    rel->array[2].packet_id = 0;
    rel->array[2].active = true;

    assert_int_equal(6, reliable_get_num_output_sequenced_available(rel));

    rel->packet_id = 3;
    assert_int_equal(1, reliable_get_num_output_sequenced_available(rel));

    reliable_free(rel);
}

static void
test_packet_id_write_epoch(void **state)
{
    struct test_packet_id_write_data *data = *state;

    struct buffer buf = alloc_buf_gc(128, &data->gc);

    /* test normal writing of packet id to the buffer */
    assert_true(packet_id_write_epoch(&data->pis, 0x23, &buf));

    assert_int_equal(buf.len, 8);
    uint8_t expected_header[8] = { 0x00, 0x23, 0, 0, 0, 0, 0, 1};
    assert_memory_equal(BPTR(&buf), expected_header, 8);

    /* too small buffer should error out */
    struct buffer buf_short = alloc_buf_gc(5, &data->gc);
    assert_false(packet_id_write_epoch(&data->pis, 0xabde, &buf_short));

    /* test a true 48 bit packet id */
    data->pis.id = 0xfa079ab9d2e8;
    struct buffer buf_48 = alloc_buf_gc(128, &data->gc);
    assert_true(packet_id_write_epoch(&data->pis, 0xfffe, &buf_48));
    uint8_t expected_header_48[8] = { 0xff, 0xfe, 0xfa, 0x07, 0x9a, 0xb9, 0xd2, 0xe9};
    assert_memory_equal(BPTR(&buf_48), expected_header_48, 8);

    /* test writing/checking the 48 bit per epoch packet counter
     * overflow */
    data->pis.id = 0xfffffffffffe;
    struct buffer buf_of = alloc_buf_gc(128, &data->gc);
    assert_true(packet_id_write_epoch(&data->pis, 0xf00f, &buf_of));
    uint8_t expected_header_of[8] = { 0xf0, 0x0f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
    assert_memory_equal(BPTR(&buf_of), expected_header_of, 8);

    /* This is go over 2^48 - 1 and should error out. */
    assert_false(packet_id_write_epoch(&data->pis, 0xf00f, &buf_of));

    /* Now read back the packet ids and check if they are the same as what we
     * have written */
    struct packet_id_net pin;
    assert_int_equal(packet_id_read_epoch(&pin, &buf), 0x23);
    assert_int_equal(pin.id, 1);

    assert_int_equal(packet_id_read_epoch(&pin, &buf_48), 0xfffe);
    assert_int_equal(pin.id, 0xfa079ab9d2e9);

    assert_int_equal(packet_id_read_epoch(&pin, &buf_of), 0xf00f);
    assert_int_equal(pin.id, 0xffffffffffff);
}

static void
test_copy_acks_to_lru(void **state)
{
    struct reliable_ack ack = { .len = 4, .packet_id = {2, 1, 3, 2} };

    struct reliable_ack mru_ack = {0 };

    /* Test copying to empty ack structure */
    copy_acks_to_mru(&ack, &mru_ack, 4);
    assert_int_equal(mru_ack.len, 3);
    assert_int_equal(mru_ack.packet_id[0], 2);
    assert_int_equal(mru_ack.packet_id[1], 1);
    assert_int_equal(mru_ack.packet_id[2], 3);

    /* Copying again should not change the result */
    copy_acks_to_mru(&ack, &mru_ack, 4);
    assert_int_equal(mru_ack.len, 3);
    assert_int_equal(mru_ack.packet_id[0], 2);
    assert_int_equal(mru_ack.packet_id[1], 1);
    assert_int_equal(mru_ack.packet_id[2], 3);

    /* Copying just the first two element should not change the order
     * as they are still the most recent*/
    struct reliable_ack mru_ack2 = mru_ack;
    copy_acks_to_mru(&ack, &mru_ack2, 2);
    assert_int_equal(mru_ack2.packet_id[0], 2);
    assert_int_equal(mru_ack2.packet_id[1], 1);
    assert_int_equal(mru_ack2.packet_id[2], 3);

    /* Adding just two packets shoudl ignore the 42 in array and
     * reorder the order in the MRU */
    struct reliable_ack ack2 = { .len = 3, .packet_id = {3, 2, 42} };
    copy_acks_to_mru(&ack2, &mru_ack2, 2);
    assert_int_equal(mru_ack2.packet_id[0], 3);
    assert_int_equal(mru_ack2.packet_id[1], 2);
    assert_int_equal(mru_ack2.packet_id[2], 1);

    /* Copying a zero array into it should also change nothing */
    struct reliable_ack empty_ack = { .len = 0 };
    copy_acks_to_mru(&empty_ack, &mru_ack, 0);
    assert_int_equal(mru_ack.len, 3);
    assert_int_equal(mru_ack.packet_id[0], 2);
    assert_int_equal(mru_ack.packet_id[1], 1);
    assert_int_equal(mru_ack.packet_id[2], 3);

    /* Or should just 0 elements of the ack */
    copy_acks_to_mru(&ack, &mru_ack, 0);
    assert_int_equal(mru_ack.len, 3);
    assert_int_equal(mru_ack.packet_id[0], 2);
    assert_int_equal(mru_ack.packet_id[1], 1);
    assert_int_equal(mru_ack.packet_id[2], 3);

    struct reliable_ack ack3 = { .len = 7, .packet_id = {5, 6, 7, 8, 9, 10, 11}};

    /* Adding multiple acks tests if the a full array is handled correctly */
    copy_acks_to_mru(&ack3, &mru_ack, 7);

    struct reliable_ack expected_ack = { .len = 8, .packet_id = {5, 6, 7, 8, 9, 10, 11, 2}};
    assert_int_equal(mru_ack.len, expected_ack.len);

    assert_memory_equal(mru_ack.packet_id, expected_ack.packet_id, sizeof(expected_ack.packet_id));
}

int
main(void)
{
    openvpn_unit_test_setup();
    const struct CMUnitTest tests[] = {
        cmocka_unit_test_setup_teardown(test_packet_id_write_short,
                                        test_packet_id_write_setup,
                                        test_packet_id_write_teardown),
        cmocka_unit_test_setup_teardown(test_packet_id_write_long,
                                        test_packet_id_write_setup,
                                        test_packet_id_write_teardown),
        cmocka_unit_test_setup_teardown(test_packet_id_write_short_prepend,
                                        test_packet_id_write_setup,
                                        test_packet_id_write_teardown),
        cmocka_unit_test_setup_teardown(test_packet_id_write_long_prepend,
                                        test_packet_id_write_setup,
                                        test_packet_id_write_teardown),
        cmocka_unit_test_setup_teardown(test_packet_id_write_short_wrap,
                                        test_packet_id_write_setup,
                                        test_packet_id_write_teardown),
        cmocka_unit_test_setup_teardown(test_packet_id_write_long_wrap,
                                        test_packet_id_write_setup,
                                        test_packet_id_write_teardown),
        cmocka_unit_test_setup_teardown(test_packet_id_write_epoch,
                                        test_packet_id_write_setup,
                                        test_packet_id_write_teardown),

        cmocka_unit_test(test_get_num_output_sequenced_available),
        cmocka_unit_test(test_copy_acks_to_lru)

    };

    return cmocka_run_group_tests_name("packet_id tests", tests, NULL, NULL);
}
