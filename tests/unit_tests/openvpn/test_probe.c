/*
 *  OpenVPN -- An application to securely tunnel IP networks
 *             over a single TCP/UDP port, with support for SSL/TLS-based
 *             session authentication and key exchange,
 *             packet encryption, packet authentication, and
 *             packet compression.
 *
 *  Copyright (C) 2002-2026 OpenVPN Inc <sales@openvpn.net>
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

#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>

#include "control_msg.h"
#include "probe.h"
#include "test_common.h"
#include "test_probe.h"

/* Write a probe request TLV and read it back; the fields must survive the
 * round trip and the whole buffer must be consumed. */
void
test_probe_request_roundtrip(void **state)
{
    struct gc_arena gc = gc_new();
    struct buffer buf = alloc_buf_gc(128, &gc);

    const struct probe_request in = {
        .request_id = 0xdeadbeefcafef00dULL,
        .timestamp = 0x0123456789abcdefULL,
        .flags = PROBE_REQUEST_FLAG_PROBE_ONLY,
    };
    assert_true(probe_request_write(&buf, &in));
    assert_int_equal(BLEN(&buf), CTRL_MSG_TLV_HEADER_LEN + PROBE_REQUEST_LEN);

    struct ctrl_msg_tlv_header hdr;
    assert_true(ctrl_msg_tlv_peek_header(&buf, &hdr));
    assert_int_equal(hdr.type, TLV_TYPE_PROBE_REQUEST);
    assert_false(hdr.optional);
    assert_int_equal(hdr.value_len, PROBE_REQUEST_LEN);

    struct buffer value;
    assert_true(ctrl_msg_find_tlv(&buf, TLV_TYPE_PROBE_REQUEST, &value));
    assert_int_equal(BLEN(&value), PROBE_REQUEST_LEN);

    struct probe_request out = { 0 };
    assert_true(probe_request_read(&value, &out));
    assert_true(in.request_id == out.request_id);
    assert_true(in.timestamp == out.timestamp);
    assert_int_equal(in.flags, out.flags);
    /* the scan consumed header and value alike */
    assert_int_equal(BLEN(&buf), 0);

    gc_free(&gc);
}

/* The probe request wire format is locked to the field order of the spec
 * (request_id, timestamp, flags), big-endian. */
void
test_probe_request_wire_format(void **state)
{
    struct gc_arena gc = gc_new();
    struct buffer buf = alloc_buf_gc(128, &gc);

    const struct probe_request in = {
        .request_id = 0x1122334455667788ULL,
        .timestamp = 0x0102030405060708ULL,
        .flags = 0,
    };
    assert_true(probe_request_write(&buf, &in));

    /* clang-format off */
    const uint8_t expected[] = {
        0x00, 0x02,                                     /* TLV type 2, not optional */
        0x00, 0x14,                                     /* TLV value length = 20 */
        0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, /* request_id */
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, /* timestamp */
        0x00, 0x00, 0x00, 0x00,                         /* flags */
    };
    /* clang-format on */
    assert_int_equal(BLEN(&buf), sizeof(expected));
    assert_memory_equal(BPTR(&buf), expected, sizeof(expected));

    gc_free(&gc);
}

/* Write a probe reply TLV and read it back. */
void
test_probe_reply_roundtrip(void **state)
{
    struct gc_arena gc = gc_new();
    struct buffer buf = alloc_buf_gc(128, &gc);

    const struct probe_reply in = {
        .request_id = 0x1122334455667788ULL,
        .priority = 10,
        .weight = 100,
        .max_latency_diff = 25,
        .connect_lifetime = 30,
        .flags = PROBE_REPLY_FLAG_RESEND_WKC,
    };

    assert_true(probe_reply_write(&buf, &in));
    assert_int_equal(BLEN(&buf), CTRL_MSG_TLV_HEADER_LEN + PROBE_REPLY_LEN);

    struct ctrl_msg_tlv_header hdr;
    assert_true(ctrl_msg_tlv_peek_header(&buf, &hdr));
    assert_int_equal(hdr.type, TLV_TYPE_PROBE_REPLY);
    assert_false(hdr.optional);
    assert_int_equal(hdr.value_len, PROBE_REPLY_LEN);

    struct buffer value;
    assert_true(ctrl_msg_find_tlv(&buf, TLV_TYPE_PROBE_REPLY, &value));

    struct probe_reply out = { 0 };
    assert_true(probe_reply_read(&value, &out));
    assert_true(in.request_id == out.request_id);
    assert_int_equal(in.priority, out.priority);
    assert_int_equal(in.weight, out.weight);
    assert_int_equal(in.max_latency_diff, out.max_latency_diff);
    assert_int_equal(in.connect_lifetime, out.connect_lifetime);
    assert_int_equal(in.flags, out.flags);
    assert_int_equal(BLEN(&buf), 0);

    gc_free(&gc);
}

/* The probe reply wire format is locked to the field order of the spec
 * (request_id, priority, weight, max_latency_diff, connect_lifetime, flags),
 * big-endian. */
void
test_probe_reply_wire_format(void **state)
{
    struct gc_arena gc = gc_new();
    struct buffer buf = alloc_buf_gc(128, &gc);

    const struct probe_reply in = {
        .request_id = 0x1122334455667788ULL,
        .priority = 10,
        .weight = 100,
        .max_latency_diff = 25,
        .connect_lifetime = 30,
        .flags = PROBE_REPLY_FLAG_RESEND_WKC,
    };

    assert_true(probe_reply_write(&buf, &in));

    /* clang-format off */
    const uint8_t expected[] = {
        0x00, 0x03,                                     /* TLV type 3, not optional */
        0x00, 0x12,                                     /* TLV value length = 18 */
        0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, /* request_id */
        0x00, 0x0a,                                     /* priority = 10 */
        0x00, 0x64,                                     /* weight = 100 */
        0x00, 0x19,                                     /* max_latency_diff = 25 */
        0x00, 0x1e,                                     /* connect_lifetime = 30 */
        0x00, 0x01,                                     /* flags = RESEND_WKC */
    };
    /* clang-format on */
    assert_int_equal(BLEN(&buf), sizeof(expected));
    assert_memory_equal(BPTR(&buf), expected, sizeof(expected));

    gc_free(&gc);
}

/* A TLV with a longer-than-known value must still parse: the known fields are
 * read and the trailing bytes are skipped. Flag bits we do not know are kept
 * rather than rejected, for the same forward compatibility. */
void
test_probe_request_forward_compat(void **state)
{
    struct gc_arena gc = gc_new();
    struct buffer buf = alloc_buf_gc(128, &gc);

    const uint16_t extended_len = PROBE_REQUEST_LEN + 4;
    assert_true(ctrl_msg_tlv_write_header(&buf, TLV_TYPE_PROBE_REQUEST, false, extended_len));
    assert_true(buf_write_u64(&buf, 7));             /* request_id */
    assert_true(buf_write_u64(&buf, 0xdeadbeefULL)); /* timestamp */
    assert_true(buf_write_u32(&buf, 0x80000000));    /* flags, unknown bit set */
    assert_true(buf_write_u32(&buf, 0x11223344));    /* unknown trailing field */

    struct buffer value;
    assert_true(ctrl_msg_find_tlv(&buf, TLV_TYPE_PROBE_REQUEST, &value));
    assert_int_equal(BLEN(&value), extended_len);

    struct probe_request out = { 0 };
    assert_true(probe_request_read(&value, &out));
    assert_true(out.request_id == 7);
    assert_true(out.timestamp == 0xdeadbeefULL);
    assert_true(out.flags == 0x80000000);
    /* the unknown trailing field must have been consumed from the payload */
    assert_int_equal(BLEN(&buf), 0);

    gc_free(&gc);
}

/* A value shorter than the mandatory fields must be rejected, even when it
 * holds enough bytes for some of the individual fields to read successfully. */
void
test_probe_request_too_short(void **state)
{
    struct gc_arena gc = gc_new();
    struct buffer buf = alloc_buf_gc(128, &gc);

    /* 8 of the 20 mandatory value bytes: enough for the request_id alone */
    assert_true(buf_write_u64(&buf, 0xdeadbeefULL));

    struct probe_request out = { 0 };
    assert_false(probe_request_read(&buf, &out));

    gc_free(&gc);
}

/* The same for the reply, one u16 short of its 18 mandatory bytes. */
void
test_probe_reply_too_short(void **state)
{
    struct gc_arena gc = gc_new();
    struct buffer buf = alloc_buf_gc(128, &gc);

    assert_true(buf_write_u64(&buf, 1));
    for (int i = 0; i < 4; i++)
    {
        assert_true(buf_write_u16(&buf, 0));
    }

    struct probe_reply out = { 0 };
    assert_false(probe_reply_read(&buf, &out));

    gc_free(&gc);
}

/* The flag combinations the protocol rules out must be rejected: the other
 * addresses of a remote cannot be both the same server and distinct ones, and
 * a shared connect_lifetime needs them to have been called equal. */
void
test_probe_reply_flags_contradict(void **state)
{
    struct gc_arena gc = gc_new();
    const uint16_t bad[] = {
        PROBE_REPLY_FLAG_ADDRS_EQUAL | PROBE_REPLY_FLAG_PROBE_MORE,
        PROBE_REPLY_FLAG_LIFETIME_SHARED,
        PROBE_REPLY_FLAG_LIFETIME_SHARED | PROBE_REPLY_FLAG_PROBE_MORE,
    };
    const uint16_t good[] = {
        0,
        PROBE_REPLY_FLAG_ADDRS_EQUAL,
        PROBE_REPLY_FLAG_PROBE_MORE,
        PROBE_REPLY_FLAG_ADDRS_EQUAL | PROBE_REPLY_FLAG_LIFETIME_SHARED,
    };

    for (size_t i = 0; i < SIZE(bad) + SIZE(good); i++)
    {
        const bool expect_ok = i >= SIZE(bad);
        const uint16_t flags = expect_ok ? good[i - SIZE(bad)] : bad[i];

        struct buffer buf = alloc_buf_gc(128, &gc);
        const struct probe_reply in = { .request_id = 1, .flags = flags };
        assert_true(probe_reply_write(&buf, &in));

        struct buffer value;
        assert_true(ctrl_msg_find_tlv(&buf, TLV_TYPE_PROBE_REPLY, &value));

        struct probe_reply out = { 0 };
        assert_int_equal(probe_reply_read(&value, &out), expect_ok);
    }

    gc_free(&gc);
}

/* A TLV header claiming more value bytes than the payload holds must be
 * rejected by the scan rather than reported as found -- for the TLV being
 * looked for as much as for one that would merely be skipped. */
void
test_find_tlv_value_truncated(void **state)
{
    struct gc_arena gc = gc_new();
    struct buffer value;

    /* the wanted TLV declares 20 value bytes, only 8 are present */
    struct buffer buf = alloc_buf_gc(128, &gc);
    assert_true(ctrl_msg_tlv_write_header(&buf, TLV_TYPE_PROBE_REQUEST, false, PROBE_REQUEST_LEN));
    assert_true(buf_write_u64(&buf, 0xdeadbeefULL));
    assert_false(ctrl_msg_find_tlv(&buf, TLV_TYPE_PROBE_REQUEST, &value));

    /* same defect on a TLV that would be skipped: the scan must not walk past
     * the end of the payload looking for the next header */
    struct buffer buf2 = alloc_buf_gc(128, &gc);
    assert_true(ctrl_msg_tlv_write_header(&buf2, 0x7ff, false, 64));
    assert_true(buf_write_u32(&buf2, 0));
    assert_false(ctrl_msg_find_tlv(&buf2, TLV_TYPE_PROBE_REQUEST, &value));

    gc_free(&gc);
}

/* Bytes left over after the last TLV that are too few for a header make the
 * message malformed, even when the wanted TLV was already found. */
void
test_find_tlv_trailing_bytes(void **state)
{
    struct gc_arena gc = gc_new();
    struct buffer value;

    /* 1 to 3 bytes: less than a 4-byte TLV header */
    for (int trailing = 1; trailing < CTRL_MSG_TLV_HEADER_LEN; trailing++)
    {
        struct buffer buf = alloc_buf_gc(128, &gc);
        const struct probe_request in = { .request_id = 1, .timestamp = 1 };
        assert_true(probe_request_write(&buf, &in));
        for (int i = 0; i < trailing; i++)
        {
            assert_true(buf_write_u8(&buf, 0));
        }
        assert_false(ctrl_msg_find_tlv(&buf, TLV_TYPE_PROBE_REQUEST, &value));
    }

    gc_free(&gc);
}

/* An unknown TLV marked optional after the wanted one is skipped, and the
 * wanted value is still the one returned. */
void
test_find_tlv_skips_optional_after_wanted(void **state)
{
    struct gc_arena gc = gc_new();
    struct buffer buf = alloc_buf_gc(128, &gc);
    struct buffer value;

    const struct probe_request in = { .request_id = 1, .timestamp = 7 };
    assert_true(probe_request_write(&buf, &in));
    assert_true(ctrl_msg_tlv_write_header(&buf, 0x7ff, true, 4));
    assert_true(buf_write_u32(&buf, 0));

    assert_true(ctrl_msg_find_tlv(&buf, TLV_TYPE_PROBE_REQUEST, &value));
    assert_int_equal(BLEN(&value), PROBE_REQUEST_LEN);
    struct probe_request out = { 0 };
    assert_true(probe_request_read(&value, &out));
    assert_true(out.timestamp == 7);

    gc_free(&gc);
}

/* A TLV we do not know that is not marked optional carries something its
 * sender requires us to act on, so the scan rejects the message whether that
 * TLV comes before or after the wanted one. */
void
test_find_tlv_rejects_unknown_mandatory(void **state)
{
    struct gc_arena gc = gc_new();
    struct buffer value;
    const struct probe_request in = { .request_id = 1, .timestamp = 7 };

    struct buffer before = alloc_buf_gc(128, &gc);
    assert_true(ctrl_msg_tlv_write_header(&before, 0x7ff, false, 4));
    assert_true(buf_write_u32(&before, 0xcafef00d));
    assert_true(probe_request_write(&before, &in));

    struct buffer after = alloc_buf_gc(128, &gc);
    assert_true(probe_request_write(&after, &in));
    assert_true(ctrl_msg_tlv_write_header(&after, 0x7ff, false, 4));
    assert_true(buf_write_u32(&after, 0xcafef00d));

    assert_false(ctrl_msg_find_tlv(&before, TLV_TYPE_PROBE_REQUEST, &value));
    assert_false(ctrl_msg_find_tlv(&after, TLV_TYPE_PROBE_REQUEST, &value));

    gc_free(&gc);
}

/* The wanted TLV may occur only once: a second one rejects the message. Repeats
 * of an unknown TLV marked optional are skipped like any other. */
void
test_find_tlv_rejects_duplicate(void **state)
{
    struct gc_arena gc = gc_new();
    struct buffer value;
    const struct probe_request in = { .request_id = 1 };

    struct buffer buf = alloc_buf_gc(128, &gc);
    assert_true(probe_request_write(&buf, &in));
    assert_true(probe_request_write(&buf, &in));
    assert_false(ctrl_msg_find_tlv(&buf, TLV_TYPE_PROBE_REQUEST, &value));

    buf = alloc_buf_gc(128, &gc);
    for (int i = 0; i < 2; i++)
    {
        assert_true(ctrl_msg_tlv_write_header(&buf, 0x7ff, true, 4));
        assert_true(buf_write_u32(&buf, 0));
    }
    assert_true(probe_request_write(&buf, &in));
    assert_true(ctrl_msg_find_tlv(&buf, TLV_TYPE_PROBE_REQUEST, &value));

    gc_free(&gc);
}

/* An empty payload holds no TLV. */
void
test_find_tlv_empty_payload(void **state)
{
    struct gc_arena gc = gc_new();
    struct buffer buf = alloc_buf_gc(16, &gc);
    struct buffer value;

    assert_false(ctrl_msg_find_tlv(&buf, TLV_TYPE_PROBE_REQUEST, &value));

    gc_free(&gc);
}
