/*
 *  OpenVPN -- An application to securely tunnel IP networks
 *             over a single UDP port, with support for SSL/TLS-based
 *             session authentication and key exchange,
 *             packet encryption, packet authentication, and
 *             packet compression.
 *
 *  Copyright (C) 2016-2026 Sentyron B.V. <openvpn@sentyron.com>
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
 *  distribution); if not, see <https://www.gnu.org/licenses/>.
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

struct test_packet_id_write_data
{
    struct
    {
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
    struct test_packet_id_write_data *data = calloc(1, sizeof(struct test_packet_id_write_data));

    if (!data)
    {
        return -1;
    }

    data->test_buf.data = (void *)&data->test_buf_data;
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
    assert_int_equal(data->pis.id, 1);
    assert_int_equal(data->test_buf_data.buf_id, htonl(1));
    assert_int_equal(data->test_buf_data.buf_time, 0);
}

static void
test_packet_id_write_long(void **state)
{
    struct test_packet_id_write_data *data = *state;

    now = 5010;
    assert_true(packet_id_write(&data->pis, &data->test_buf, true, false));
    assert_int_equal(data->pis.id, 1);
    assert_int_equal(data->pis.time, now);
    assert_int_equal(data->test_buf_data.buf_id, htonl(1));
    assert_int_equal(data->test_buf_data.buf_time, htonl((uint32_t)now));
}

static void
test_packet_id_write_short_prepend(void **state)
{
    struct test_packet_id_write_data *data = *state;

    data->test_buf.offset = sizeof(packet_id_type);
    now = 5010;
    assert_true(packet_id_write(&data->pis, &data->test_buf, false, true));
    assert_int_equal(data->pis.id, 1);
    assert_int_equal(data->test_buf_data.buf_id, htonl(1));
    assert_int_equal(data->test_buf_data.buf_time, 0);
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
    assert_int_equal(data->test_buf_data.buf_id, htonl(1));
    assert_int_equal(data->test_buf_data.buf_time, htonl((uint32_t)now));
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
    assert_int_equal(data->test_buf_data.buf_id, htonl(1));
    assert_int_equal(data->test_buf_data.buf_time, htonl((uint32_t)now));
}

static void
test_get_num_output_sequenced_available(void **state)
{
    struct reliable *rel = malloc(sizeof(struct reliable));
    assert_non_null(rel);
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
    rel->array[5].packet_id = (0x80000000u - 3);
    rel->array[6].active = false;
    rel->packet_id = (0x80000000u - 1);

    assert_int_equal(6, reliable_get_num_output_sequenced_available(rel));

    rel->array[5].active = true;
    rel->array[5].packet_id = (0x80000000u - 3);
    rel->packet_id = 0x80000001u;

    assert_int_equal(4, reliable_get_num_output_sequenced_available(rel));


    /* test wrapping */
    rel->array[5].active = true;
    rel->array[5].packet_id = (0xffffffffu - 3);
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
    uint8_t expected_header[8] = { 0x00, 0x23, 0, 0, 0, 0, 0, 1 };
    assert_memory_equal(BPTR(&buf), expected_header, 8);

    /* too small buffer should error out */
    struct buffer buf_short = alloc_buf_gc(5, &data->gc);
    assert_false(packet_id_write_epoch(&data->pis, 0xabde, &buf_short));

    /* test a true 48 bit packet id */
    data->pis.id = 0xfa079ab9d2e8;
    struct buffer buf_48 = alloc_buf_gc(128, &data->gc);
    assert_true(packet_id_write_epoch(&data->pis, 0xfffe, &buf_48));
    uint8_t expected_header_48[8] = { 0xff, 0xfe, 0xfa, 0x07, 0x9a, 0xb9, 0xd2, 0xe9 };
    assert_memory_equal(BPTR(&buf_48), expected_header_48, 8);

    /* test writing/checking the 48 bit per epoch packet counter
     * overflow */
    data->pis.id = 0xfffffffffffe;
    struct buffer buf_of = alloc_buf_gc(128, &data->gc);
    assert_true(packet_id_write_epoch(&data->pis, 0xf00f, &buf_of));
    uint8_t expected_header_of[8] = { 0xf0, 0x0f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };
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
    struct reliable_ack ack = { .len = 4, .packet_id = { 2, 1, 3, 2 } };

    struct reliable_ack mru_ack = { 0 };

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
    struct reliable_ack ack2 = { .len = 3, .packet_id = { 3, 2, 42 } };
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

    struct reliable_ack ack3 = { .len = 7, .packet_id = { 5, 6, 7, 8, 9, 10, 11 } };

    /* Adding multiple acks tests if the a full array is handled correctly */
    copy_acks_to_mru(&ack3, &mru_ack, 7);

    struct reliable_ack expected_ack = { .len = 8, .packet_id = { 5, 6, 7, 8, 9, 10, 11, 2 } };
    assert_int_equal(mru_ack.len, expected_ack.len);

    assert_memory_equal(mru_ack.packet_id, expected_ack.packet_id, sizeof(expected_ack.packet_id));
}

static void
test_packet_id_window(void **state)
{
    struct reliable rel = { 0 };
    rel.packet_id = 1;

    assert_true(validate_packet_id_window(&rel, 0));

    /* packet id 1 is outside the window as it is the *next* packet id */
    assert_false(validate_packet_id_window(&rel, 1));

    /* wrapped around packet id, "-2" */
    assert_true(validate_packet_id_window(&rel, 0xFFFFFFFD));

    /* wrapped around packet id, "-10" */
    assert_true(validate_packet_id_window(&rel, 0xFFFFFFF6));

    /* wrapped around packet id, "-11" */
    assert_false(validate_packet_id_window(&rel, 0xFFFFFFF5));
    assert_false(validate_packet_id_window(&rel, 0x80000000));

    rel.packet_id = 0x80000000;

    /* near the signed/usigned integer area */
    assert_false(validate_packet_id_window(&rel, 0x80000001));
    assert_true(validate_packet_id_window(&rel, 0x7fffffff));
    assert_true(validate_packet_id_window(&rel, 0x7ffffff5));
    assert_false(validate_packet_id_window(&rel, 0x7ffffff4));

    rel.packet_id = 0xFFFFFFFD;
    assert_false(validate_packet_id_window(&rel, 0xFFFFFFFD));
    assert_false(validate_packet_id_window(&rel, 0));
    assert_false(validate_packet_id_window(&rel, 1));
    assert_false(validate_packet_id_window(&rel, 0xFFFFFFFE));
    assert_false(validate_packet_id_window(&rel, 0xFFFFFFFF));
    assert_true(validate_packet_id_window(&rel, 0xFFFFFFF3));
    assert_true(validate_packet_id_window(&rel, 0xFFFFFFF2));
    assert_false(validate_packet_id_window(&rel, 0xFFFFFFF1));

    rel.packet_id = 500;
    assert_false(validate_packet_id_window(&rel, 501));
    assert_true(validate_packet_id_window(&rel, 497));
    assert_true(validate_packet_id_window(&rel, 500 - (RELIABLE_CAPACITY - 1)));
    assert_false(validate_packet_id_window(&rel, 500 - RELIABLE_CAPACITY));
}


/* The fix keeps the timeout well below this; the broken code grows past it.
 * A plain number, so the test builds with or without the fix. */
#define SANE_TIMEOUT_BOUND (10 * 1000 * 1000)

static struct reliable *
test_reliable_new(void)
{
    struct reliable *rel = malloc(sizeof(struct reliable));
    assert_non_null(rel);
    /* reliable_init() zeroes everything, so each test only sets the
     * fields it actually needs. */
    reliable_init(rel, 100, 50, 8, false);
    rel->initial_timeout = 2;
    return rel;
}

/*
 * Each retransmit doubles the timeout. If a peer keeps forcing retransmits,
 * the broken code doubles it forever: after about 30 rounds it overflows and
 * turns zero or negative, and then the packet is resent nonstop (the flood).
 * The fix caps the doubling. This test forces many retransmits and checks the
 * timeout never overflows or grows without limit.
 */
static void
test_reliable_backoff_is_bounded(void **state)
{
    (void)state;
    now = 1000;

    struct reliable *rel = test_reliable_new();

    struct reliable_entry *e = &rel->array[0];
    e->active = true;
    e->packet_id = 1;
    e->timeout = rel->initial_timeout;
    rel->packet_id = 2;

    for (int i = 0; i < 40; ++i)
    {
        /* make the packet due for a fast retransmit */
        e->n_acks = N_ACK_RETRANSMIT;

        int opcode;
        struct buffer *buf = reliable_send(rel, &opcode);
        /* our one active packet is the one picked to send */
        assert_ptr_equal(buf, &e->buf);

        /* a zero or negative timeout would resend with no delay (the flood) */
        assert_true(e->timeout > 0);
        /* the timeout must stop growing, not double forever */
        assert_true(e->timeout <= SANE_TIMEOUT_BOUND);
    }

    reliable_free(rel);
}

/*
 * An ACK should only count if it is for a packet we actually sent. If the
 * broken code accepts ACKs for packets that were never sent, a peer can force
 * early retransmits at will (which then feeds the timeout overflow above).
 * These two cases send such bogus ACKs and check they are ignored.
 */
static void
test_reliable_purge_ignores_forged_acks(void **state)
{
    (void)state;

    /* Case (a): an ACK for pid 0x40000000, which we never sent (we only sent
     * 0 and 1). The old "e->packet_id < pid" check treats it as newer and
     * counts it. It should be ignored. */
    {
        struct reliable *rel = test_reliable_new();
        struct reliable_entry *e = &rel->array[0];
        e->active = true;
        e->packet_id = 1;
        rel->packet_id = 2; /* only pids 0 and 1 were ever sent */

        struct reliable_ack ack = { .len = 1, .packet_id = { 0x40000000 } };
        reliable_send_purge(rel, &ack);

        /* the bogus ACK must not be counted */
        assert_int_equal(e->n_acks, 0);
        /* and must not drop our real packet */
        assert_true(e->active);
        reliable_free(rel);
    }

    /* Case (b): an ACK for pid 0xFFFFFFFF. It is inside the send window, so
     * it passes the window check, but ids wrap around and 0xFFFFFFFF is really
     * older than our pid 1. A plain "<" thinks it is newer and counts it; the
     * wraparound-aware comparison must not. */
    {
        struct reliable *rel = test_reliable_new();
        struct reliable_entry *e = &rel->array[0];
        e->active = true;
        e->packet_id = 1;
        rel->packet_id = 2;

        struct reliable_ack ack = { .len = 1, .packet_id = { 0xFFFFFFFF } };
        reliable_send_purge(rel, &ack);

        /* the bogus ACK must not be counted */
        assert_int_equal(e->n_acks, 0);
        /* and must not drop our real packet */
        assert_true(e->active);
        reliable_free(rel);
    }
}

/*
 * Sanity check: a real ACK must still work. Acknowledging a higher packet
 * should drop that packet and count once towards resending the older one.
 * The fix must not break this.
 */
static void
test_reliable_purge_legitimate_ack(void **state)
{
    (void)state;

    struct reliable *rel = test_reliable_new();

    struct reliable_entry *e0 = &rel->array[0];
    e0->active = true;
    e0->packet_id = 1;

    struct reliable_entry *e1 = &rel->array[1];
    e1->active = true;
    e1->packet_id = 2;

    rel->packet_id = 3; /* pids 0,1,2 sent; 1 and 2 still waiting */

    struct reliable_ack ack = { .len = 1, .packet_id = { 2 } };
    reliable_send_purge(rel, &ack);

    /* packet 2 was acked, so it is dropped */
    assert_false(e1->active);
    /* packet 1 is older, so it gets one ACK towards an early resend */
    assert_int_equal(e0->n_acks, 1);
    /* packet 1 was not acked, so it stays */
    assert_true(e0->active);

    reliable_free(rel);
}

/*
 * Reference implementations of the packet id comparisons as they behave today.
 * The sweeps below assert reliable.c agrees with them at the anchors swept, so
 * a change to an accepted id set there fails a test. Keep them standalone:
 * expressing them in terms of reliable.c would make the sweeps tautologies.
 */

/* "p1 < p2" with the 2^31 horizon, i.e. ((int32_t)(p1 - p2) < 0) */
static bool
ref_pid_min(packet_id_type p1, packet_id_type p2)
{
    return (packet_id_type)(p1 - p2) >= 0x80000000u;
}

/* one short of RELIABLE_CAPACITY, which is what the code accepts today */
#define CHARACTERIZED_SEND_WINDOW 11

/* TLS_RELIABLE_N_SEND_BUFFERS and P_CONTROL_V1, from ssl_pkt.h, which this
 * test binary does not pull in */
#define CHAR_N_SEND_BUFFERS    6
#define CHAR_OPCODE_CONTROL_V1 4

static bool
ref_pid_in_send_window(const struct reliable *rel, packet_id_type pid)
{
    const packet_id_type dist = (packet_id_type)(rel->packet_id - pid);

    return dist >= 1 && dist <= CHARACTERIZED_SEND_WINDOW;
}

static bool
ref_wont_break_sequentiality(const struct reliable *rel, packet_id_type id)
{
    const packet_id_type base = rel->packet_id;
    const packet_id_type extent = (packet_id_type)rel->size;

    /* char_anchors and char_anchors_high stay clear of the overflow, where
     * reliable_pid_in_range2() used a 0x80000000 bias instead */
    assert_true(base + extent >= base);

    return id < base + extent;
}

static bool
ref_not_replay(const struct reliable *rel, packet_id_type id)
{
    if (ref_pid_min(id, rel->packet_id))
    {
        return false;
    }

    for (int i = 0; i < rel->size; ++i)
    {
        if (rel->array[i].active && rel->array[i].packet_id == id)
        {
            return false;
        }
    }

    return true;
}

/* The receive path verdict as ssl.c produces it: stored only if both checks
 * pass, a replay still ACKed, a sequentiality break dropped without an ACK. */
enum recv_verdict
{
    RECV_DROP,
    RECV_ACK_ONLY,
    RECV_STORE
};

static enum recv_verdict
recv_filter(const struct reliable *rel, packet_id_type id)
{
    if (!reliable_wont_break_sequentiality(rel, id))
    {
        return RECV_DROP;
    }

    return reliable_not_replay(rel, id) ? RECV_STORE : RECV_ACK_ONLY;
}

static enum recv_verdict
ref_recv_filter(const struct reliable *rel, packet_id_type id)
{
    if (!ref_wont_break_sequentiality(rel, id))
    {
        return RECV_DROP;
    }

    return ref_not_replay(rel, id) ? RECV_STORE : RECV_ACK_ONLY;
}

/* Anchors for rel->packet_id. reliable_wont_break_sequentiality() compares id
 * against rel->packet_id + rel->size in absolute terms, so its accepted set
 * depends on where rel->packet_id sits: up to 2^31 that leaves the composite
 * verdict unchanged, above it it does not, hence the split. Bases past
 * 0xFFFFFFF3 are excluded, rel->packet_id + rel->size overflowing there. */
static const packet_id_type char_anchors[] = {
    0x00000000,
    0x00000001,
    0x00000005,
    0x0000000B,
    0x0000000C,
    0x0000000D,
    0x000001F4,
    0x7FFFFFF4,
    0x7FFFFFFF,
    0x80000000,
};

static const packet_id_type char_anchors_high[] = {
    0x80000001,
    0x8000000C,
    0xFFFFFFF0,
    0xFFFFFFF3,
};

/* offsets applied below and above each anchor */
static const packet_id_type char_offsets[] = {
    0,
    1,
    2,
    10,
    11,
    12,
    13,
    14,
    100,
    0x3FFFFFFF,
    0x40000000,
    0x7FFFFFFE,
    0x7FFFFFFF,
    0x80000000,
    0x80000001,
    0x80000002,
    0xFFFFFFF4,
    0xFFFFFFFE,
    0xFFFFFFFF,
};

static void
sweep_recv_filter(const packet_id_type *anchors, size_t n_anchors,
                  enum recv_verdict (*oracle)(const struct reliable *, packet_id_type))
{
    for (size_t a = 0; a < n_anchors; a++)
    {
        for (size_t o = 0; o < SIZE(char_offsets); o++)
        {
            /* probe both below and above the anchor */
            const packet_id_type ids[] = {
                (packet_id_type)(anchors[a] - char_offsets[o]),
                (packet_id_type)(anchors[a] + char_offsets[o]),
            };

            for (size_t i = 0; i < SIZE(ids); i++)
            {
                struct reliable rel = { 0 };
                rel.size = RELIABLE_CAPACITY;
                rel.packet_id = anchors[a];

                assert_int_equal(oracle(&rel, ids[i]), recv_filter(&rel, ids[i]));

                /* with the id already in a receive slot it can only be
                 * acknowledged or dropped, never stored again */
                rel.array[3].active = true;
                rel.array[3].packet_id = ids[i];

                assert_int_equal(oracle(&rel, ids[i]), recv_filter(&rel, ids[i]));
                assert_int_not_equal(RECV_STORE, recv_filter(&rel, ids[i]));
            }
        }
    }
}

/* bases at or below 2^31, where old and new agree; never to change */
static void
test_recv_filter_characterization(void **state)
{
    sweep_recv_filter(char_anchors, SIZE(char_anchors), ref_recv_filter);
}

/* bases above 2^31, where they diverge, kept apart so a change confined
 * there touches one test */
static void
test_recv_filter_high_base(void **state)
{
    sweep_recv_filter(char_anchors_high, SIZE(char_anchors_high), ref_recv_filter);
}

static void
sweep_send_window(const packet_id_type *anchors, size_t n_anchors)
{
    for (size_t a = 0; a < n_anchors; a++)
    {
        for (size_t o = 0; o < SIZE(char_offsets); o++)
        {
            const packet_id_type ids[] = {
                (packet_id_type)(anchors[a] - char_offsets[o]),
                (packet_id_type)(anchors[a] + char_offsets[o]),
            };

            for (size_t i = 0; i < SIZE(ids); i++)
            {
                struct reliable rel = { 0 };
                rel.size = CHAR_N_SEND_BUFFERS;
                rel.packet_id = anchors[a];

                assert_int_equal(ref_pid_in_send_window(&rel, ids[i]),
                                 validate_packet_id_window(&rel, ids[i]) != 0);
            }
        }
    }
}

/* a pure distance test, so identical at every base */
static void
test_send_window_characterization(void **state)
{
    sweep_send_window(char_anchors, SIZE(char_anchors));
    sweep_send_window(char_anchors_high, SIZE(char_anchors_high));
}

/* reliable_send() picks the oldest eligible entry, across the wrap and the
 * signed midpoint */
static void
test_reliable_send_picks_oldest(void **state)
{
    now = 1000;

    struct reliable rel = { 0 };
    rel.size = CHAR_N_SEND_BUFFERS;
    rel.initial_timeout = 2;
    rel.packet_id = 3;

    /* 6, 2 and 1 below rel->packet_id; the first sits exactly on the window
     * edge, where rel->size still admits it */
    const packet_id_type wrapped[] = { 0xFFFFFFFD, 1, 2 };

    for (size_t i = 0; i < SIZE(wrapped); i++)
    {
        rel.array[i].active = true;
        rel.array[i].packet_id = wrapped[i];
        rel.array[i].timeout = 2;
        rel.array[i].next_try = 0;
    }

    int opcode = 0;
    assert_ptr_equal(&rel.array[0].buf, reliable_send(&rel, &opcode));

    /* same across the signed midpoint */
    struct reliable rel2 = { 0 };
    rel2.size = CHAR_N_SEND_BUFFERS;
    rel2.initial_timeout = 2;
    rel2.packet_id = 0x80000002;

    const packet_id_type midpoint[] = { 0x7FFFFFFF, 0x80000000, 0x80000001 };

    for (size_t i = 0; i < SIZE(midpoint); i++)
    {
        rel2.array[i].active = true;
        rel2.array[i].packet_id = midpoint[i];
        rel2.array[i].timeout = 2;
        rel2.array[i].next_try = 0;
    }

    assert_ptr_equal(&rel2.array[0].buf, reliable_send(&rel2, &opcode));
}

/* reliable_get_buf_output_sequenced() stops issuing ids once rel->packet_id is
 * a full window ahead of the oldest unacknowledged one */
static void
test_get_buf_output_sequenced_boundary(void **state)
{
    struct reliable *rel = test_reliable_new();

    rel->array[0].active = true;
    rel->array[0].packet_id = 100;

    /* distance 7 < size 8: still allowed */
    rel->packet_id = 107;
    assert_non_null(reliable_get_buf_output_sequenced(rel));

    /* distance 8 == size 8: refused */
    rel->packet_id = 108;
    assert_null(reliable_get_buf_output_sequenced(rel));

    /* same boundary across the wrap */
    rel->array[0].packet_id = 0xFFFFFFFC;
    rel->packet_id = 3;
    assert_non_null(reliable_get_buf_output_sequenced(rel));

    rel->packet_id = 4;
    assert_null(reliable_get_buf_output_sequenced(rel));

    reliable_free(rel);
}

/* Ids at or just ahead of rel->packet_id are accepted */
static void
test_mark_active_incoming_accepts_window(void **state)
{
    struct reliable rel = { 0 };
    rel.size = RELIABLE_CAPACITY;
    rel.packet_id = 10;

    reliable_mark_active_incoming(&rel, &rel.array[0].buf, 10, CHAR_OPCODE_CONTROL_V1);
    assert_true(rel.array[0].active);
    assert_int_equal(10, rel.array[0].packet_id);

    reliable_mark_active_incoming(&rel, &rel.array[1].buf, 10 + RELIABLE_CAPACITY - 1,
                                  CHAR_OPCODE_CONTROL_V1);
    assert_true(rel.array[1].active);
}

/* Ids below rel->packet_id abort. The far-ahead case is left unpinned: callers
 * cannot produce it, and the bound may legitimately tighten.
 *
 * NOTE: expect_assert_failure() does not work with MSVC. It catches the ASSERT
 * by longjmp()ing out of assert_failed(), and MSVC's longjmp() unwinds the
 * intervening frames through RtlUnwindEx() instead of just restoring the
 * registers, which faults. */
#ifndef _MSC_VER
static void
test_mark_active_incoming_rejects_past_ids(void **state)
{
    struct reliable rel = { 0 };
    rel.size = RELIABLE_CAPACITY;
    rel.packet_id = 10;

    expect_assert_failure(
        reliable_mark_active_incoming(&rel, &rel.array[0].buf, 5, CHAR_OPCODE_CONTROL_V1));
    expect_assert_failure(
        reliable_mark_active_incoming(&rel, &rel.array[1].buf, 0xFFFFFFFF, CHAR_OPCODE_CONTROL_V1));
}
#endif /* ifndef _MSC_VER */


int
main(void)
{
    openvpn_unit_test_setup();
    const struct CMUnitTest tests[] = {
        cmocka_unit_test_setup_teardown(test_packet_id_write_short, test_packet_id_write_setup,
                                        test_packet_id_write_teardown),
        cmocka_unit_test_setup_teardown(test_packet_id_write_long, test_packet_id_write_setup,
                                        test_packet_id_write_teardown),
        cmocka_unit_test_setup_teardown(test_packet_id_write_short_prepend,
                                        test_packet_id_write_setup, test_packet_id_write_teardown),
        cmocka_unit_test_setup_teardown(test_packet_id_write_long_prepend,
                                        test_packet_id_write_setup, test_packet_id_write_teardown),
        cmocka_unit_test_setup_teardown(test_packet_id_write_short_wrap, test_packet_id_write_setup,
                                        test_packet_id_write_teardown),
        cmocka_unit_test_setup_teardown(test_packet_id_write_long_wrap, test_packet_id_write_setup,
                                        test_packet_id_write_teardown),
        cmocka_unit_test_setup_teardown(test_packet_id_write_epoch, test_packet_id_write_setup,
                                        test_packet_id_write_teardown),

        cmocka_unit_test(test_get_num_output_sequenced_available),
        cmocka_unit_test(test_copy_acks_to_lru),
        cmocka_unit_test(test_packet_id_window),
        cmocka_unit_test(test_reliable_backoff_is_bounded),
        cmocka_unit_test(test_reliable_purge_ignores_forged_acks),
        cmocka_unit_test(test_reliable_purge_legitimate_ack),
        cmocka_unit_test(test_recv_filter_characterization),
        cmocka_unit_test(test_recv_filter_high_base),
        cmocka_unit_test(test_send_window_characterization),
        cmocka_unit_test(test_reliable_send_picks_oldest),
        cmocka_unit_test(test_get_buf_output_sequenced_boundary),
        cmocka_unit_test(test_mark_active_incoming_accepts_window),
#ifndef _MSC_VER
        cmocka_unit_test(test_mark_active_incoming_rejects_past_ids),
#endif
    };

    return cmocka_run_group_tests_name("packet_id tests", tests, NULL, NULL);
}
