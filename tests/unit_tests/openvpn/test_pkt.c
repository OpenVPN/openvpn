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

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <setjmp.h>
#include <cmocka.h>

#include "crypto.h"
#include "options.h"
#include "ssl_backend.h"
#include "ssl_pkt.h"
#include "tls_crypt.h"

#include "mss.h"
#include "reliable.h"

int
parse_line(const char *line, char **p, const int n, const char *file,
           const int line_num, int msglevel, struct gc_arena *gc)
{
    /* Dummy function to get the linker happy, should never be called */
    assert_true(false);
    return 0;
}

/* Define this function here as dummy since including the ssl_*.c files
 * leads to having to include even more unrelated code */
bool
key_state_export_keying_material(struct tls_session *session,
                                 const char *label, size_t label_size,
                                 void *ekm, size_t ekm_size)
{
    ASSERT(0);
}

const char *
print_link_socket_actual(const struct link_socket_actual *act, struct gc_arena *gc)
{
    return "dummy print_link_socket_actual from unit test";
}

struct test_pkt_context {
    struct tls_auth_standalone tas_tls_auth;
    struct tls_auth_standalone tas_crypt;
};

const char static_key[] = "<tls-auth>\n"
                          "-----BEGIN OpenVPN Static key V1-----\n"
                          "37268ea8f95d7f71f9fb8fc03770c460\n"
                          "daf714a483d815c013ce0a537efc18f2\n"
                          "8f4f172669d9e6a413bac6741d8ea054\n"
                          "00f49b7fd6326470f23798c606bf53d4\n"
                          "de63ebc64ec59d57ce5d04d5b62e68b5\n"
                          "3ca6e5354351097fa370446c4d269f18\n"
                          "7bb6ae54af2dc70ff7317fe2f8754b82\n"
                          "82aad4202f9fa42c8640245d883e2c54\n"
                          "a0c1c489a036cf3a8964d8d289c1583b\n"
                          "9447c262b1da5fd167a5d27bd5ac5143\n"
                          "17bc2343a31a2efc38dd920d910375f5\n"
                          "1c2e27f3afd36c49269da079f7ce466e\n"
                          "bb0f9ad13e9bbb4665974e6bc24b513c\n"
                          "5700393bf4a3e7f967e2f384069ac8a8\n"
                          "e78b18b15604993fd16515cce9c0f3e4\n"
                          "2b4126b999005ade802797b0eeb8b9e6\n"
                          "-----END OpenVPN Static key V1-----\n"
                          "</tls-auth>\n";

const uint8_t client_reset_v2_none[] =
{ 0x38, 0x68, 0x91, 0x92,  0x3f, 0xa3, 0x10, 0x34,
  0x37, 0x00, 0x00, 0x00, 0x00, 0x00 };

const uint8_t client_reset_v2_tls_auth[] =
{ 0x38, 0xde, 0x69, 0x4c, 0x5c, 0x7b, 0xfb, 0xa2,
  0x74, 0x93, 0x53, 0x7c, 0x1d, 0xed, 0x4e, 0x78,
  0x15, 0x29, 0xae, 0x7c, 0xfe, 0x4b, 0x8c, 0x6d,
  0x6b, 0x2b, 0x51, 0xf0, 0x5a, 0x00, 0x00, 0x00,
  0x01, 0x61, 0xd3, 0xbf, 0x6c, 0x00, 0x00, 0x00,
  0x00, 0x00};

const uint8_t client_reset_v2_tls_crypt[] =
{0x38, 0xf4, 0x19, 0xcb, 0x12, 0xd1, 0xf9, 0xe4,
 0x8f, 0x00, 0x00, 0x00, 0x01, 0x61, 0xd3, 0xf8,
 0xe1, 0x33, 0x02, 0x06, 0xf5, 0x68, 0x02, 0xbe,
 0x44, 0xfb, 0xed, 0x90, 0x50, 0x64, 0xe3, 0xdb,
 0x43, 0x41, 0x6b, 0xec, 0x5e, 0x52, 0x67, 0x19,
 0x46, 0x2b, 0x7e, 0xb9, 0x0c, 0x96, 0xde, 0xfc,
 0x9b, 0x05, 0xc4, 0x48, 0x79, 0xf7};

/* Valid tls-auth client CONTROL_V1 packet with random server id */
const uint8_t client_ack_tls_auth_randomid[] = {
    0x20, 0x14, 0x01, 0x4e, 0xbc, 0x80, 0xc6, 0x14,
    0x2b, 0x7b, 0xc8, 0x76, 0xfb, 0xc5, 0x2e, 0x27,
    0xb1, 0xc5, 0x07, 0x35, 0x5b, 0xb6, 0x00, 0x6b,
    0xae, 0x71, 0xba, 0x4e, 0x38, 0x00, 0x00, 0x00,
    0x03, 0x61, 0xd3, 0xff, 0x53, 0x00, 0x00, 0x00,
    0x00, 0x01, 0x16, 0x03, 0x01, 0x01, 0x0c, 0x01,
    0x00, 0x01, 0x08, 0x03, 0x03, 0x8c, 0xaa, 0xac,
    0x3a, 0x1a, 0x07, 0xbd, 0xe7, 0xb7, 0x50, 0x06,
    0x9b, 0x94, 0x0c, 0x34, 0x4b, 0x5a, 0x35, 0xca,
    0xc4, 0x79, 0xbd, 0xc9, 0x09, 0xb0, 0x7b, 0xd9,
    0xee, 0xbb, 0x7d, 0xe7, 0x25, 0x20, 0x39, 0x38,
    0xe2, 0x18, 0x33, 0x36, 0x14, 0x9f, 0x34, 0xf0,
    0x44, 0x59, 0x96, 0x8d, 0x0e, 0xd2, 0x47, 0x76,
    0x64, 0x88, 0x59, 0xe9, 0x38, 0x03, 0x97, 0x96,
    0x98, 0x45, 0xfb, 0xf5, 0xff, 0x23, 0x00, 0x32,
    0x13, 0x02, 0x13, 0x03, 0x13, 0x01, 0xc0, 0x2c,
    0xc0, 0x30, 0x00, 0x9f, 0xcc, 0xa9, 0xcc, 0xa8,
    0xcc, 0xaa, 0xc0, 0x2b, 0xc0, 0x2f, 0x00, 0x9e,
    0xc0, 0x24, 0xc0, 0x28, 0x00, 0x6b, 0xc0, 0x23,
    0xc0, 0x27, 0x00, 0x67, 0xc0, 0x0a, 0xc0, 0x14,
    0x00, 0x39, 0xc0, 0x09, 0xc0, 0x13, 0x00, 0x33,
    0x00, 0xff, 0x01, 0x00, 0x00, 0x8d, 0x00, 0x0b,
    0x00, 0x04, 0x03, 0x00, 0x01, 0x02, 0x00, 0x0a,
    0x00, 0x0c, 0x00, 0x0a, 0x00, 0x1d, 0x00, 0x17,
    0x00, 0x1e, 0x00, 0x19, 0x00, 0x18, 0x00, 0x16,
    0x00, 0x00, 0x00, 0x17, 0x00, 0x00, 0x00, 0x0d,
    0x00, 0x30, 0x00, 0x2e, 0x04, 0x03, 0x05, 0x03,
    0x06, 0x03, 0x08, 0x07, 0x08, 0x08, 0x08, 0x09,
    0x08, 0x0a, 0x08, 0x0b, 0x08, 0x04, 0x08, 0x05,
    0x08, 0x06, 0x04, 0x01, 0x05, 0x01, 0x06, 0x01,
    0x03, 0x03, 0x02, 0x03, 0x03, 0x01, 0x02, 0x01,
    0x03, 0x02, 0x02, 0x02, 0x04, 0x02, 0x05, 0x02,
    0x06, 0x02, 0x00, 0x2b, 0x00, 0x05, 0x04, 0x03,
    0x04, 0x03, 0x03, 0x00, 0x2d, 0x00, 0x02, 0x01,
    0x01, 0x00, 0x33, 0x00, 0x26, 0x00, 0x24, 0x00,
    0x1d, 0x00, 0x20, 0x0e, 0xc9, 0x7a, 0xff, 0x58,
    0xdb, 0x56, 0xf6, 0x40, 0xd1, 0xed, 0xdb, 0x91,
    0x81, 0xd6, 0xef, 0x83, 0x86, 0x8a, 0xb2, 0x3d,
    0x88, 0x92, 0x3f, 0xd8, 0x51, 0x9c, 0xd6, 0x26,
    0x56, 0x33, 0x6b
};

/* This is a truncated packet as we do not care for the TLS payload in the
 * unit test */
const uint8_t client_control_with_ack[] = {
    0x20, 0x78, 0x19, 0xbf, 0x2e, 0xbc, 0xd1, 0x9a,
    0x45, 0x01, 0x00, 0x00, 0x00, 0x00, 0xea,
    0xfe, 0xbf, 0xa4, 0x41, 0x8a, 0xe3, 0x1b,
    0x00, 0x00, 0x00, 0x01, 0x16, 0x03, 0x01
};

const uint8_t client_ack_none_random_id[] = {
    0x28, 0xae, 0xb9, 0xaf, 0xe1, 0xf0, 0x1d, 0x79,
    0xc8, 0x01, 0x00, 0x00, 0x00, 0x00, 0xdd,
    0x85, 0xdb, 0x53, 0x56, 0x23, 0xb0, 0x2e
};

struct tls_auth_standalone
init_tas_auth(int key_direction)
{
    struct tls_auth_standalone tas = { 0 };
    struct frame frame = { {.headroom = 200, .payload_size = 1400}, 0};
    tas.frame = frame;

    tas.tls_wrap.mode = TLS_WRAP_AUTH;
    /* we ignore packet ids on for the first packet check */
    tas.tls_wrap.opt.flags |= (CO_IGNORE_PACKET_ID|CO_PACKET_ID_LONG_FORM);

    struct key_type tls_crypt_kt;
    init_key_type(&tls_crypt_kt, "none", "SHA1", true, false);

    crypto_read_openvpn_key(&tls_crypt_kt, &tas.tls_wrap.opt.key_ctx_bi,
                            static_key, true, key_direction,
                            "Control Channel Authentication", "tls-auth",
                            NULL);
    tas.workbuf = alloc_buf(1600);

    return tas;
}

struct tls_auth_standalone
init_tas_crypt(bool server)
{
    struct tls_auth_standalone tas = { 0 };
    tas.tls_wrap.mode = TLS_WRAP_CRYPT;
    tas.tls_wrap.opt.flags |= (CO_IGNORE_PACKET_ID|CO_PACKET_ID_LONG_FORM);

    tls_crypt_init_key(&tas.tls_wrap.opt.key_ctx_bi,
                       &tas.tls_wrap.original_wrap_keydata, static_key,
                       true, server);
    tas.workbuf = alloc_buf(1600);
    tas.tls_wrap.work = alloc_buf(1600);

    return tas;
}

void
free_tas(struct tls_auth_standalone *tas)
{
    /* Not some of these might be null pointers but calling free on null
     * pointers is a noop */
    free_key_ctx_bi(&tas->tls_wrap.opt.key_ctx_bi);
    free_buf(&tas->workbuf);
    free_buf(&tas->tls_wrap.work);
}

void
test_tls_decrypt_lite_crypt(void **ut_state)
{
    struct link_socket_actual from = { 0 };
    struct tls_pre_decrypt_state state = { 0 };

    struct tls_auth_standalone tas = init_tas_crypt(true);
    struct buffer buf = alloc_buf(1024);

    /* tls-auth should be invalid */
    buf_write(&buf, client_reset_v2_tls_auth, sizeof(client_reset_v2_tls_auth));
    enum first_packet_verdict verdict = tls_pre_decrypt_lite(&tas, &state, &from, &buf);
    assert_int_equal(verdict, VERDICT_INVALID);
    free_tls_pre_decrypt_state(&state);

    /* as well as the too short normal reset */
    buf_reset_len(&buf);
    buf_write(&buf, client_reset_v2_none, sizeof(client_reset_v2_none));
    verdict = tls_pre_decrypt_lite(&tas, &state, &from, &buf);
    assert_int_equal(verdict, VERDICT_INVALID);
    free_tls_pre_decrypt_state(&state);

    /* the tls-crypt should validate */
    buf_reset_len(&buf);
    buf_write(&buf, client_reset_v2_tls_crypt, sizeof(client_reset_v2_tls_crypt));
    verdict = tls_pre_decrypt_lite(&tas, &state, &from, &buf);
    assert_int_equal(verdict, VERDICT_VALID_RESET_V2);
    free_tls_pre_decrypt_state(&state);

    /* flip a byte in various places */
    for (int i = 0; i<sizeof(client_reset_v2_tls_crypt); i++)
    {
        buf_reset_len(&buf);
        buf_write(&buf, client_reset_v2_tls_crypt, sizeof(client_reset_v2_tls_crypt));
        BPTR(&buf)[i] = 0x23;
        verdict = tls_pre_decrypt_lite(&tas, &state, &from, &buf);
        assert_int_equal(verdict, VERDICT_INVALID);
        free_tls_pre_decrypt_state(&state);
    }

    free_key_ctx_bi(&tas.tls_wrap.opt.key_ctx_bi);
    free_tas(&tas);
    free_buf(&buf);
}


void
test_tls_decrypt_lite_auth(void **ut_state)
{
    struct link_socket_actual from = { 0 };
    struct tls_auth_standalone tas = { 0 };
    struct tls_pre_decrypt_state state = { 0 };
    enum first_packet_verdict verdict;

    struct buffer buf = alloc_buf(1024);
    tas = init_tas_auth(KEY_DIRECTION_NORMAL);

    /* Packet to short to contain the hmac */
    buf_write(&buf, client_reset_v2_none, sizeof(client_reset_v2_none));

    verdict = tls_pre_decrypt_lite(&tas, &state, &from, &buf);
    assert_int_equal(verdict, VERDICT_INVALID);
    free_tls_pre_decrypt_state(&state);

    /* Valid tls-auth packet, should validate */
    buf_reset_len(&buf);
    buf_write(&buf, client_reset_v2_tls_auth, sizeof(client_reset_v2_tls_auth));
    verdict = tls_pre_decrypt_lite(&tas, &state, &from, &buf);
    assert_int_equal(verdict, VERDICT_VALID_RESET_V2);
    free_tls_pre_decrypt_state(&state);

    free_tls_pre_decrypt_state(&state);
    /* The pre decrypt function should not modify the buffer, so calling it
     * again should have the same result */
    verdict = tls_pre_decrypt_lite(&tas, &state, &from, &buf);
    assert_int_equal(verdict, VERDICT_VALID_RESET_V2);
    free_tls_pre_decrypt_state(&state);

    /* and buf memory should be equal */
    assert_memory_equal(BPTR(&buf), client_reset_v2_tls_auth, sizeof(client_reset_v2_tls_auth));
    free_tls_pre_decrypt_state(&state);

    buf_reset_len(&buf);
    buf_write(&buf, client_ack_tls_auth_randomid, sizeof(client_ack_tls_auth_randomid));
    verdict = tls_pre_decrypt_lite(&tas, &state, &from, &buf);
    assert_int_equal(verdict, VERDICT_VALID_CONTROL_V1);
    free_tls_pre_decrypt_state(&state);

    /* flip a byte in the hmac */
    BPTR(&buf)[20] = 0x23;
    verdict = tls_pre_decrypt_lite(&tas, &state, &from, &buf);
    assert_int_equal(verdict, VERDICT_INVALID);
    free_tls_pre_decrypt_state(&state);

    free_tls_pre_decrypt_state(&state);
    /* Wrong key direction gives a wrong hmac key and should not validate */
    free_key_ctx_bi(&tas.tls_wrap.opt.key_ctx_bi);
    free_tas(&tas);
    tas = init_tas_auth(KEY_DIRECTION_INVERSE);

    buf_reset_len(&buf);
    buf_write(&buf, client_reset_v2_tls_auth, sizeof(client_reset_v2_tls_auth));
    verdict = tls_pre_decrypt_lite(&tas, &state, &from, &buf);
    assert_int_equal(verdict, VERDICT_INVALID);

    free_tls_pre_decrypt_state(&state);
    free_tas(&tas);
    free_buf(&buf);
}

void
test_tls_decrypt_lite_none(void **ut_state)
{
    struct link_socket_actual from = { 0 };
    struct tls_auth_standalone tas = { 0 };
    struct tls_pre_decrypt_state state = { 0 };

    struct buffer buf = alloc_buf(1024);
    buf_write(&buf, client_reset_v2_tls_auth, sizeof(client_reset_v2_tls_auth));

    tas.tls_wrap.mode = TLS_WRAP_NONE;

    /* the method will not do additional test, so the tls-auth and tls-crypt
     * reset will be accepted */
    enum first_packet_verdict verdict = tls_pre_decrypt_lite(&tas, &state, &from, &buf);
    assert_int_equal(verdict, VERDICT_VALID_RESET_V2);
    free_tls_pre_decrypt_state(&state);

    buf_reset_len(&buf);
    buf_write(&buf, client_reset_v2_none, sizeof(client_reset_v2_none));
    verdict = tls_pre_decrypt_lite(&tas, &state, &from, &buf);
    assert_int_equal(verdict, VERDICT_VALID_RESET_V2);
    free_tls_pre_decrypt_state(&state);

    free_tls_pre_decrypt_state(&state);
    buf_reset_len(&buf);
    buf_write(&buf, client_reset_v2_tls_crypt, sizeof(client_reset_v2_none));
    verdict = tls_pre_decrypt_lite(&tas, &state, &from, &buf);
    assert_int_equal(verdict, VERDICT_VALID_RESET_V2);
    free_tls_pre_decrypt_state(&state);

    free_tls_pre_decrypt_state(&state);

    /* This is not a reset packet and should trigger the other response */
    buf_reset_len(&buf);
    buf_write(&buf, client_ack_tls_auth_randomid, sizeof(client_ack_tls_auth_randomid));
    verdict = tls_pre_decrypt_lite(&tas, &state, &from, &buf);
    assert_int_equal(verdict, VERDICT_VALID_CONTROL_V1);

    free_tls_pre_decrypt_state(&state);
    free_buf(&buf);
    free_tas(&tas);
}

static void
test_parse_ack(void **ut_state)
{
    struct buffer buf = alloc_buf(1024);
    buf_write(&buf, client_control_with_ack, sizeof(client_control_with_ack));

    /* skip over op code and peer session id */
    buf_advance(&buf, 9);

    struct reliable_ack ack;
    struct session_id sid;
    bool ret;

    ret = reliable_ack_parse(&buf, &ack, &sid);
    assert_true(ret);

    assert_int_equal(ack.len, 1);
    assert_int_equal(ack.packet_id[0], 0);

    struct session_id expected_id = { .id = {0xea, 0xfe, 0xbf, 0xa4, 0x41, 0x8a, 0xe3, 0x1b }};
    assert_memory_equal(&sid, &expected_id, SID_SIZE);

    buf_reset_len(&buf);
    buf_write(&buf, client_ack_none_random_id, sizeof(client_ack_none_random_id));

    /* skip over op code and peer session id */
    buf_advance(&buf, 9);
    ret = reliable_ack_parse(&buf, &ack, &sid);
    assert_true(ret);

    assert_int_equal(ack.len, 1);
    assert_int_equal(ack.packet_id[0], 0);

    struct session_id expected_id2 = { .id = {0xdd, 0x85, 0xdb, 0x53, 0x56, 0x23, 0xb0, 0x2e }};
    assert_memory_equal(&sid, &expected_id2, SID_SIZE);

    buf_reset_len(&buf);
    buf_write(&buf, client_reset_v2_none, sizeof(client_reset_v2_none));

    /* skip over op code and peer session id */
    buf_advance(&buf, 9);
    ret = reliable_ack_parse(&buf, &ack, &sid);

    free_buf(&buf);
}

static void
test_verify_hmac_tls_auth(void **ut_state)
{
    hmac_ctx_t *hmac = session_id_hmac_init();

    struct link_socket_actual from = { 0 };
    struct tls_auth_standalone tas = { 0 };
    struct tls_pre_decrypt_state state = { 0 };

    struct buffer buf = alloc_buf(1024);
    enum first_packet_verdict verdict;

    tas = init_tas_auth(KEY_DIRECTION_NORMAL);

    buf_reset_len(&buf);
    buf_write(&buf, client_ack_tls_auth_randomid, sizeof(client_ack_tls_auth_randomid));
    verdict = tls_pre_decrypt_lite(&tas, &state, &from, &buf);
    assert_int_equal(verdict, VERDICT_VALID_CONTROL_V1);

    /* This is a valid packet but containing a random id instead of an HMAC id*/
    bool valid = check_session_id_hmac(&state, &from.dest, hmac, 30);
    assert_false(valid);

    free_tls_pre_decrypt_state(&state);
    free_buf(&buf);
    free_tas(&tas);
    hmac_ctx_cleanup(hmac);
    hmac_ctx_free(hmac);
}

static void
test_verify_hmac_none(void **ut_state)
{
    hmac_ctx_t *hmac = session_id_hmac_init();

    struct link_socket_actual from = { 0 };
    from.dest.addr.sa.sa_family = AF_INET;

    struct tls_auth_standalone tas = { 0 };
    struct tls_pre_decrypt_state state = { 0 };

    struct buffer buf = alloc_buf(1024);
    enum first_packet_verdict verdict;

    tas.tls_wrap.mode = TLS_WRAP_NONE;

    buf_reset_len(&buf);
    buf_write(&buf, client_ack_none_random_id, sizeof(client_ack_none_random_id));
    verdict = tls_pre_decrypt_lite(&tas, &state, &from, &buf);
    assert_int_equal(verdict, VERDICT_VALID_ACK_V1);

    bool valid = check_session_id_hmac(&state, &from.dest, hmac, 30);
    assert_true(valid);

    free_tls_pre_decrypt_state(&state);
    free_buf(&buf);
    hmac_ctx_cleanup(hmac);
    hmac_ctx_free(hmac);
}

static hmac_ctx_t *
init_static_hmac(void)
{
    ASSERT(md_valid("SHA256"));
    hmac_ctx_t *hmac_ctx = hmac_ctx_new();

    uint8_t key[SHA256_DIGEST_LENGTH] = {1, 2, 3, 0};

    hmac_ctx_init(hmac_ctx, key, "SHA256");
    return hmac_ctx;
}

static void
test_calc_session_id_hmac_static(void **ut_state)
{
    hmac_ctx_t *hmac = init_static_hmac();
    static const int handwindow = 100;

    struct openvpn_sockaddr addr = { 0 };

    addr.addr.in4.sin_family = AF_INET;
    addr.addr.in4.sin_addr.s_addr = ntohl(0xff000ff);
    addr.addr.in4.sin_port = ntohs(1195);

    struct session_id client_id = { {0, 1, 2, 3, 4, 5, 6, 7}};

    now = 1005;
    struct session_id server_id = calculate_session_id_hmac(client_id, &addr, hmac, handwindow, 0);


    struct session_id expected_server_id = {{0x84, 0x73, 0x52, 0x2b, 0x5b, 0xa9, 0x2a, 0x70}};
    /* We have to deal with different structs here annoyingly */
    /* Linux has an unsigned short int as family_t and this is field is always
     * stored in host endianness even though the rest of the struct isn't...,
     * so Linux little endian differs from all BSD and Linux big endian */
    if (sizeof(addr.addr.in4.sin_family) == sizeof(unsigned short int)
        && ntohs(AF_INET) != AF_INET)
    {
        struct session_id linuxle = {{0x8b, 0xeb, 0x3d, 0x20, 0x14, 0x53, 0xbe, 0x0a }};
        expected_server_id = linuxle;
    }
    assert_memory_equal(expected_server_id.id, server_id.id, SID_SIZE);

    struct session_id server_id_m1 = calculate_session_id_hmac(client_id, &addr, hmac, handwindow, -1);
    struct session_id server_id_p1 = calculate_session_id_hmac(client_id, &addr, hmac, handwindow, 1);
    struct session_id server_id_p2 = calculate_session_id_hmac(client_id, &addr, hmac, handwindow, 2);

    assert_memory_not_equal(expected_server_id.id, server_id_m1.id, SID_SIZE);
    assert_memory_not_equal(expected_server_id.id, server_id_p1.id, SID_SIZE);

    /* changing the time puts us into the next hmac time window (handwindow/2=50)
     * and shifts the ids by one */
    now = 1062;

    struct session_id server_id2_m2 = calculate_session_id_hmac(client_id, &addr, hmac, handwindow, -2);
    struct session_id server_id2_m1 = calculate_session_id_hmac(client_id, &addr, hmac, handwindow, -1);
    struct session_id server_id2 = calculate_session_id_hmac(client_id, &addr, hmac, handwindow, 0);
    struct session_id server_id2_p1 = calculate_session_id_hmac(client_id, &addr, hmac, handwindow, 1);

    assert_memory_equal(server_id2_m2.id, server_id_m1.id, SID_SIZE);
    assert_memory_equal(server_id2_m1.id, expected_server_id.id, SID_SIZE);
    assert_memory_equal(server_id2.id, server_id_p1.id, SID_SIZE);
    assert_memory_equal(server_id2_p1.id, server_id_p2.id, SID_SIZE);

    hmac_ctx_cleanup(hmac);
    hmac_ctx_free(hmac);
}

static void
test_generate_reset_packet_plain(void **ut_state)
{
    struct link_socket_actual from = { 0 };
    struct tls_auth_standalone tas = { 0 };
    struct tls_pre_decrypt_state state = { 0 };

    struct session_id client_id = {{0, 1, 2, 3, 4, 5, 6, 7}};
    struct session_id server_id = {{8, 9, 0, 9, 8, 7, 6, 2}};

    enum first_packet_verdict verdict;

    tas.tls_wrap.mode = TLS_WRAP_NONE;
    struct frame frame = { {.headroom = 200, .payload_size = 1400}, 0};
    tas.frame = frame;
    tas.workbuf = alloc_buf(1600);

    uint8_t header = 0 | (P_CONTROL_HARD_RESET_CLIENT_V2 << P_OPCODE_SHIFT);

    struct buffer buf = tls_reset_standalone(&tas.tls_wrap, &tas, &client_id, &server_id, header, false);


    verdict = tls_pre_decrypt_lite(&tas, &state, &from, &buf);
    assert_int_equal(verdict, VERDICT_VALID_RESET_V2);

    /* Assure repeated generation of reset is deterministic/stateless*/
    assert_memory_equal(state.peer_session_id.id, client_id.id, SID_SIZE);
    struct buffer buf2 = tls_reset_standalone(&tas.tls_wrap, &tas, &client_id, &server_id, header, false);
    assert_int_equal(BLEN(&buf), BLEN(&buf2));
    assert_memory_equal(BPTR(&buf), BPTR(&buf2), BLEN(&buf));

    free_tls_pre_decrypt_state(&state);
    free_buf(&tas.workbuf);
}

static void
test_generate_reset_packet_tls_auth(void **ut_state)
{
    struct link_socket_actual from = { 0 };
    struct tls_pre_decrypt_state state = { 0 };

    struct tls_auth_standalone tas_server = init_tas_auth(KEY_DIRECTION_NORMAL);
    struct tls_auth_standalone tas_client = init_tas_auth(KEY_DIRECTION_INVERSE);

    packet_id_init(&tas_client.tls_wrap.opt.packet_id, 5, 5, "UNITTEST", 0);

    struct session_id client_id = {{0xab, 1, 2, 3, 4, 5, 6, 0xcd}};
    struct session_id server_id = {{8, 9, 0xa, 0xc, 8, 7, 6, 2}};

    uint8_t header = 0 | (P_CONTROL_HARD_RESET_CLIENT_V2 << P_OPCODE_SHIFT);

    now = 0x22446688;
    reset_packet_id_send(&tas_client.tls_wrap.opt.packet_id.send);
    struct buffer buf = tls_reset_standalone(&tas_client.tls_wrap, &tas_client, &client_id, &server_id, header, false);

    enum first_packet_verdict verdict = tls_pre_decrypt_lite(&tas_server, &state, &from, &buf);
    assert_int_equal(verdict, VERDICT_VALID_RESET_V2);

    assert_memory_equal(state.peer_session_id.id, client_id.id, SID_SIZE);

    /* Assure repeated generation of reset is deterministic/stateless*/
    reset_packet_id_send(&tas_client.tls_wrap.opt.packet_id.send);
    struct buffer buf2 = tls_reset_standalone(&tas_client.tls_wrap, &tas_client, &client_id, &server_id, header, false);
    assert_int_equal(BLEN(&buf), BLEN(&buf2));
    assert_memory_equal(BPTR(&buf), BPTR(&buf2), BLEN(&buf));

    free_tls_pre_decrypt_state(&state);

    packet_id_free(&tas_client.tls_wrap.opt.packet_id);

    free_tas(&tas_client);
    free_tas(&tas_server);
}

static void
test_extract_control_message(void **ut_state)
{
    struct gc_arena gc = gc_new();
    struct buffer input_buf = alloc_buf_gc(1024, &gc);

    /* This message will have a \0x00 at the end since it is a C string */
    const char input[] = "valid control message\r\n\0\0Invalid\r\none\0valid one again";

    buf_write(&input_buf, input, sizeof(input));
    struct buffer cmd1 = extract_command_buffer(&input_buf, &gc);
    struct buffer cmd2 = extract_command_buffer(&input_buf, &gc);
    struct buffer cmd3 = extract_command_buffer(&input_buf, &gc);
    struct buffer cmd4 = extract_command_buffer(&input_buf, &gc);
    struct buffer cmd5 = extract_command_buffer(&input_buf, &gc);

    assert_string_equal(BSTR(&cmd1), "valid control message");
    /* empty message with just a \0x00 */
    assert_int_equal(cmd2.len, 1);
    assert_string_equal(BSTR(&cmd2), "");
    assert_int_equal(cmd3.len, 0);
    assert_string_equal(BSTR(&cmd4), "valid one again");
    assert_int_equal(cmd5.len, 0);

    const uint8_t nonull[6] = { 'n', 'o', ' ', 'N', 'U', 'L'};
    struct buffer nonull_buf = alloc_buf_gc(1024, &gc);

    buf_write(&nonull_buf, nonull, sizeof(nonull));
    struct buffer nonullcmd = extract_command_buffer(&nonull_buf, &gc);
    assert_int_equal(nonullcmd.len, 0);

    gc_free(&gc);
}

int
main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_tls_decrypt_lite_none),
        cmocka_unit_test(test_tls_decrypt_lite_auth),
        cmocka_unit_test(test_tls_decrypt_lite_crypt),
        cmocka_unit_test(test_parse_ack),
        cmocka_unit_test(test_calc_session_id_hmac_static),
        cmocka_unit_test(test_verify_hmac_none),
        cmocka_unit_test(test_verify_hmac_tls_auth),
        cmocka_unit_test(test_generate_reset_packet_plain),
        cmocka_unit_test(test_generate_reset_packet_tls_auth),
        cmocka_unit_test(test_extract_control_message)
    };

#if defined(ENABLE_CRYPTO_OPENSSL)
    OpenSSL_add_all_algorithms();
#endif

    int ret = cmocka_run_group_tests_name("pkt tests", tests, NULL, NULL);

#if defined(ENABLE_CRYPTO_OPENSSL)
    EVP_cleanup();
#endif

    return ret;
}
