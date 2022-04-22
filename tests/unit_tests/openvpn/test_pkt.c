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
#elif defined(_MSC_VER)
#include "config-msvc.h"
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

#include "mock_msg.h"
#include "mss.h"

int
parse_line(const char *line, char **p, const int n, const char *file,
           const int line_num, int msglevel, struct gc_arena *gc)
{
    /* Dummy function to get the linker happy, should never be called */
    assert_true(false);
    return 0;
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
    0x56, 0x33, 0x6b};

struct tls_auth_standalone init_tas_auth(int key_direction)
{
    struct tls_auth_standalone tas = { 0 };

    tas.tls_wrap.mode = TLS_WRAP_AUTH;
    /* we ignore packet ids on for the first packet check */
    tas.tls_wrap.opt.flags |= CO_IGNORE_PACKET_ID;

    struct key_type tls_crypt_kt;
    init_key_type(&tls_crypt_kt, "none", "SHA1", true, false);

    crypto_read_openvpn_key(&tls_crypt_kt, &tas.tls_wrap.opt.key_ctx_bi,
                            static_key, true, key_direction,
                            "Control Channel Authentication", "tls-auth");
    return tas;
}

struct tls_auth_standalone init_tas_crypt(bool server)
{
    struct tls_auth_standalone tas = { 0 };
    tas.tls_wrap.mode = TLS_WRAP_CRYPT;
    tas.tls_wrap.opt.flags |= CO_IGNORE_PACKET_ID;

    tls_crypt_init_key(&tas.tls_wrap.opt.key_ctx_bi, static_key, true, server);

    return tas;
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
    assert_int_equal(verdict, VERDICT_VALID_RESET);
    free_tls_pre_decrypt_state(&state);

    /* flip a byte in various places */
    for (int i=0;i<sizeof(client_reset_v2_tls_crypt);i++)
    {
        buf_reset_len(&buf);
        buf_write(&buf, client_reset_v2_tls_crypt, sizeof(client_reset_v2_tls_crypt));
        BPTR(&buf)[i] = 0x23;
        verdict = tls_pre_decrypt_lite(&tas, &state, &from, &buf);
        assert_int_equal(verdict, VERDICT_INVALID);
        free_tls_pre_decrypt_state(&state);
    }

    free_key_ctx_bi(&tas.tls_wrap.opt.key_ctx_bi);
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
    assert_int_equal(verdict, VERDICT_VALID_RESET);

    free_tls_pre_decrypt_state(&state);
    /* The pre decrypt function should not modify the buffer, so calling it
     * again should have the same result */
    verdict = tls_pre_decrypt_lite(&tas, &state, &from, &buf);
    assert_int_equal(verdict, VERDICT_VALID_RESET);
    free_tls_pre_decrypt_state(&state);

    /* and buf memory should be equal */
    assert_memory_equal(BPTR(&buf), client_reset_v2_tls_auth, sizeof(client_reset_v2_tls_auth));

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
    /* Wrong key direction gives a wrong hmac key and should not validate */
    free_key_ctx_bi(&tas.tls_wrap.opt.key_ctx_bi);
    tas = init_tas_auth(KEY_DIRECTION_INVERSE);

    buf_reset_len(&buf);
    buf_write(&buf, client_reset_v2_tls_auth, sizeof(client_reset_v2_tls_auth));
    verdict = tls_pre_decrypt_lite(&tas, &state, &from, &buf);
    assert_int_equal(verdict, VERDICT_INVALID);

    free_tls_pre_decrypt_state(&state);
    free_key_ctx_bi(&tas.tls_wrap.opt.key_ctx_bi);
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
    assert_int_equal(verdict, VERDICT_VALID_RESET);
    free_tls_pre_decrypt_state(&state);

    buf_reset_len(&buf);
    buf_write(&buf, client_reset_v2_none, sizeof(client_reset_v2_none));
    verdict = tls_pre_decrypt_lite(&tas, &state, &from, &buf);
    assert_int_equal(verdict, VERDICT_VALID_RESET);

    free_tls_pre_decrypt_state(&state);
    buf_reset_len(&buf);
    buf_write(&buf, client_reset_v2_tls_crypt, sizeof(client_reset_v2_none));
    verdict = tls_pre_decrypt_lite(&tas, &state, &from, &buf);
    assert_int_equal(verdict, VERDICT_VALID_RESET);

    free_tls_pre_decrypt_state(&state);

    /* This is not a reset packet and should trigger the other response */
    buf_reset_len(&buf);
    buf_write(&buf, client_ack_tls_auth_randomid, sizeof(client_ack_tls_auth_randomid));
    verdict = tls_pre_decrypt_lite(&tas, &state, &from, &buf);
    assert_int_equal(verdict, VERDICT_VALID_CONTROL_V1);
    free_tls_pre_decrypt_state(&state);
    free_buf(&buf);
}

int
main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_tls_decrypt_lite_none),
        cmocka_unit_test(test_tls_decrypt_lite_auth),
        cmocka_unit_test(test_tls_decrypt_lite_crypt),
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
