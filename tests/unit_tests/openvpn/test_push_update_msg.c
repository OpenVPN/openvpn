#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdlib.h>
#include <stdarg.h>
#include <setjmp.h>
#include <cmocka.h>
#include "push.h"
#include "options_util.h"
#include "multi.h"

#include "push_util.c"

/* mocks */

void
throw_signal_soft(const int signum, const char *signal_text)
{
    msg(M_WARN, "Offending option received from server");
}

unsigned int
pull_permission_mask(const struct context *c)
{
    unsigned int flags = OPT_P_UP | OPT_P_ROUTE_EXTRAS | OPT_P_SOCKBUF | OPT_P_SOCKFLAGS
                         | OPT_P_SETENV | OPT_P_SHAPER | OPT_P_TIMER | OPT_P_COMP | OPT_P_PERSIST
                         | OPT_P_MESSAGES | OPT_P_EXPLICIT_NOTIFY | OPT_P_ECHO | OPT_P_PULL_MODE
                         | OPT_P_PEER_ID | OPT_P_NCP | OPT_P_PUSH_MTU | OPT_P_ROUTE | OPT_P_DHCPDNS;
    return flags;
}

void
unlearn_ifconfig(struct multi_context *m, struct multi_instance *mi)
{
    return;
}

void
unlearn_ifconfig_ipv6(struct multi_context *m, struct multi_instance *mi)
{
    return;
}

void
update_vhash(struct multi_context *m, struct multi_instance *mi, const char *new_ip, const char *new_ipv6)
{
    return;
}

bool
options_postprocess_pull(struct options *options, struct env_set *es)
{
    return true;
}

bool
apply_push_options(struct context *c, struct options *options, struct buffer *buf,
                   unsigned int permission_mask, unsigned int *option_types_found,
                   struct env_set *es, bool is_update)
{
    char line[OPTION_PARM_SIZE];

    while (buf_parse(buf, ',', line, sizeof(line)))
    {
        unsigned int push_update_option_flags = 0;
        int i = 0;

        if (is_update || options->pull_filter_list)
        {
            /* skip leading spaces matching the behaviour of parse_line */
            while (isspace(line[i]))
            {
                i++;
            }

            if ((is_update && !check_push_update_option_flags(line, &i, &push_update_option_flags))
                || (options->pull_filter_list && !apply_pull_filter(options, &line[i])))
            {
                if (push_update_option_flags & PUSH_OPT_OPTIONAL)
                {
                    continue; /* Ignoring this option */
                }
                return false; /* Cause push/pull error and stop push processing */
            }
        }
        /*
         * No need to test also the application part here
         * (add_option/remove_option/update_option)
         */
    }
    return true;
}

int
process_incoming_push_msg(struct context *c, const struct buffer *buffer,
                          bool honor_received_options, unsigned int permission_mask,
                          unsigned int *option_types_found)
{
    struct buffer buf = *buffer;

    if (buf_string_compare_advance(&buf, "PUSH_REQUEST"))
    {
        return PUSH_MSG_REQUEST;
    }
    else if (honor_received_options && buf_string_compare_advance(&buf, push_reply_cmd))
    {
        return PUSH_MSG_REPLY;
    }
    else if (honor_received_options && buf_string_compare_advance(&buf, push_update_cmd))
    {
        return process_push_update(c, &c->options, permission_mask, option_types_found, &buf, false);
    }
    else
    {
        return PUSH_MSG_ERROR;
    }
}

const char *
tls_common_name(const struct tls_multi *multi, const bool null)
{
    return NULL;
}

#ifndef ENABLE_MANAGEMENT
bool
send_control_channel_string(struct context *c, const char *str, msglvl_t msglevel)
{
    return true;
}
#else  /* ifndef ENABLE_MANAGEMENT */

bool
send_control_channel_string(struct context *c, const char *str, msglvl_t msglevel)
{
    check_expected(str);
    return true;
}

struct multi_instance *
lookup_by_cid(struct multi_context *m, const unsigned long cid)
{
    return *(m->instances);
}

bool
mroute_extract_openvpn_sockaddr(struct mroute_addr *addr,
                                const struct openvpn_sockaddr *osaddr,
                                bool use_port)
{
    return true;
}

unsigned int
extract_iv_proto(const char *peer_info)
{
    return IV_PROTO_PUSH_UPDATE;
}
#endif /* ifdef ENABLE_MANAGEMENT */

/* tests */

static void
test_incoming_push_message_basic(void **state)
{
    struct context *c = *state;
    struct buffer buf = alloc_buf(256);
    const char *update_msg =
        "PUSH_UPDATE,dhcp-option DNS 8.8.8.8, route 0.0.0.0 0.0.0.0 10.10.10.1";
    buf_write(&buf, update_msg, strlen(update_msg));
    unsigned int option_types_found = 0;

    assert_int_equal(process_incoming_push_msg(c, &buf, c->options.pull, pull_permission_mask(c),
                                               &option_types_found),
                     PUSH_MSG_UPDATE);

    free_buf(&buf);
}

static void
test_incoming_push_message_error1(void **state)
{
    struct context *c = *state;
    struct buffer buf = alloc_buf(256);
    const char *update_msg = "PUSH_UPDATEerr,dhcp-option DNS 8.8.8.8";
    buf_write(&buf, update_msg, strlen(update_msg));
    unsigned int option_types_found = 0;

    assert_int_equal(process_incoming_push_msg(c, &buf, c->options.pull, pull_permission_mask(c),
                                               &option_types_found),
                     PUSH_MSG_ERROR);

    free_buf(&buf);
}

static void
test_incoming_push_message_error2(void **state)
{
    struct context *c = *state;
    struct buffer buf = alloc_buf(256);
    const char *update_msg = "PUSH_UPDATE ,dhcp-option DNS 8.8.8.8";
    buf_write(&buf, update_msg, strlen(update_msg));
    unsigned int option_types_found = 0;

    assert_int_equal(process_incoming_push_msg(c, &buf, c->options.pull, pull_permission_mask(c),
                                               &option_types_found),
                     PUSH_MSG_ERROR);

    free_buf(&buf);
}

static void
test_incoming_push_message_1(void **state)
{
    struct context *c = *state;
    struct buffer buf = alloc_buf(256);
    const char *update_msg = "PUSH_UPDATE, -?dns, route something, ?dhcp-option DNS 8.8.8.8";
    buf_write(&buf, update_msg, strlen(update_msg));
    unsigned int option_types_found = 0;

    assert_int_equal(process_incoming_push_msg(c, &buf, c->options.pull, pull_permission_mask(c),
                                               &option_types_found),
                     PUSH_MSG_UPDATE);

    free_buf(&buf);
}

static void
test_incoming_push_message_bad_format(void **state)
{
    struct context *c = *state;
    struct buffer buf = alloc_buf(256);
    const char *update_msg = "PUSH_UPDATE, -dhcp-option, ?-dns";
    buf_write(&buf, update_msg, strlen(update_msg));
    unsigned int option_types_found = 0;

    assert_int_equal(process_incoming_push_msg(c, &buf, c->options.pull, pull_permission_mask(c),
                                               &option_types_found),
                     PUSH_MSG_ERROR);

    free_buf(&buf);
}

static void
test_incoming_push_message_not_updatable_option(void **state)
{
    struct context *c = *state;
    struct buffer buf = alloc_buf(256);
    const char *update_msg = "PUSH_UPDATE, dev tun";
    buf_write(&buf, update_msg, strlen(update_msg));
    unsigned int option_types_found = 0;

    assert_int_equal(process_incoming_push_msg(c, &buf, c->options.pull, pull_permission_mask(c),
                                               &option_types_found),
                     PUSH_MSG_ERROR);

    free_buf(&buf);
}

static void
test_incoming_push_message_mix(void **state)
{
    struct context *c = *state;
    struct buffer buf = alloc_buf(256);
    const char *update_msg =
        "PUSH_UPDATE,-dhcp-option, route 10.10.10.0, dhcp-option DNS 1.1.1.1, route 10.11.12.0, dhcp-option DOMAIN corp.local, keepalive 10 60";
    buf_write(&buf, update_msg, strlen(update_msg));
    unsigned int option_types_found = 0;

    assert_int_equal(process_incoming_push_msg(c, &buf, c->options.pull, pull_permission_mask(c),
                                               &option_types_found),
                     PUSH_MSG_UPDATE);

    free_buf(&buf);
}

static void
test_incoming_push_message_mix2(void **state)
{
    struct context *c = *state;
    struct buffer buf = alloc_buf(256);
    const char *update_msg =
        "PUSH_UPDATE,-dhcp-option,dhcp-option DNS 8.8.8.8,redirect-gateway local,route 192.168.1.0 255.255.255.0";
    buf_write(&buf, update_msg, strlen(update_msg));
    unsigned int option_types_found = 0;

    assert_int_equal(process_incoming_push_msg(c, &buf, c->options.pull, pull_permission_mask(c),
                                               &option_types_found),
                     PUSH_MSG_UPDATE);

    free_buf(&buf);
}

#ifdef ENABLE_MANAGEMENT
char *r0[] = {
    "PUSH_UPDATE,redirect-gateway local,route 192.168.1.0 255.255.255.0",
    NULL
};
char *r1[] = {
    "PUSH_UPDATE,-dhcp-option,blablalalalalalalalalalalalalf, lalalalalalalalalalalalalalaf,push-continuation 2",
    "PUSH_UPDATE, akakakakakakakakakakakaf, dhcp-option DNS 8.8.8.8,redirect-gateway local,push-continuation 2",
    "PUSH_UPDATE,route 192.168.1.0 255.255.255.0,push-continuation 1",
    NULL
};
char *r3[] = {
    "PUSH_UPDATE,,,",
    NULL
};
char *r4[] = {
    "PUSH_UPDATE,-dhcp-option, blablalalalalalalalalalalalalf, lalalalalalalalalalalalalalaf,push-continuation 2",
    "PUSH_UPDATE, akakakakakakakakakakakaf,dhcp-option DNS 8.8.8.8, redirect-gateway local,push-continuation 2",
    "PUSH_UPDATE, route 192.168.1.0 255.255.255.0,,push-continuation 1",
    NULL
};
char *r5[] = {
    "PUSH_UPDATE,,-dhcp-option, blablalalalalalalalalalalalalf, lalalalalalalalalalalalalalaf,push-continuation 2",
    "PUSH_UPDATE, akakakakakakakakakakakaf,dhcp-option DNS 8.8.8.8, redirect-gateway local,push-continuation 2",
    "PUSH_UPDATE, route 192.168.1.0 255.255.255.0,push-continuation 1",
    NULL
};
char *r6[] = {
    "PUSH_UPDATE,-dhcp-option,blablalalalalalalalalalalalalf, lalalalalalalalalalalalalalaf,push-continuation 2",
    "PUSH_UPDATE, akakakakakakakakakakakaf, dhcp-option DNS 8.8.8.8, redirect-gateway 10.10.10.10,,push-continuation 2",
    "PUSH_UPDATE, route 192.168.1.0 255.255.255.0,,push-continuation 1",
    NULL
};
char *r7[] = {
    "PUSH_UPDATE,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,push-continuation 2",
    "PUSH_UPDATE,,,,,,,,,,,,,,,,,,,push-continuation 1",
    NULL
};
char *r8[] = {
    "PUSH_UPDATE,-dhcp-option,blablalalalalalalalalalalalalf, lalalalalalalalalalalalalalaf,push-continuation 2",
    "PUSH_UPDATE, akakakakakakakakakakakaf, dhcp-option DNS 8.8.8.8,redirect-gateway\n local,push-continuation 2",
    "PUSH_UPDATE,route 192.168.1.0 255.255.255.0\n\n\n,push-continuation 1",
    NULL
};
char *r9[] = {
    "PUSH_UPDATE,,",
    NULL
};
char *r11[] = {
    "PUSH_UPDATE,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,push-continuation 2",
    "PUSH_UPDATE,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,push-continuation 2",
    "PUSH_UPDATE,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,push-continuation 2",
    "PUSH_UPDATE,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,push-continuation 2",
    "PUSH_UPDATE,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,push-continuation 1",
    NULL
};
char *r12[] = {
    "PUSH_UPDATE,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,,,,,,a,push-continuation 2",
    "PUSH_UPDATE,abc,push-continuation 1",
    NULL
};
char *r13[] = {
    "PUSH_UPDATE,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,,,,,,a,",
    NULL
};
char *r14[] = {
    "PUSH_UPDATE,a,push-continuation 2",
    "PUSH_UPDATE,aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa,push-continuation 2",
    "PUSH_UPDATE,a,push-continuation 1",
    NULL
};

const char *msg0 = "redirect-gateway local,route 192.168.1.0 255.255.255.0";
const char *msg1 = "-dhcp-option,blablalalalalalalalalalalalalf, lalalalalalalalalalalalalalaf,"
                   " akakakakakakakakakakakaf, dhcp-option DNS 8.8.8.8,redirect-gateway local,route 192.168.1.0 255.255.255.0";
const char *msg2 = "";
const char *msg3 = ",,";
const char *msg4 = "-dhcp-option, blablalalalalalalalalalalalalf, lalalalalalalalalalalalalalaf,"
                   " akakakakakakakakakakakaf,dhcp-option DNS 8.8.8.8, redirect-gateway local, route 192.168.1.0 255.255.255.0,";
const char *msg5 = ",-dhcp-option, blablalalalalalalalalalalalalf, lalalalalalalalalalalalalalaf,"
                   " akakakakakakakakakakakaf,dhcp-option DNS 8.8.8.8, redirect-gateway local, route 192.168.1.0 255.255.255.0";
const char *msg6 = "-dhcp-option,blablalalalalalalalalalalalalf, lalalalalalalalalalalalalalaf, akakakakakakakakakakakaf,"
                   " dhcp-option DNS 8.8.8.8, redirect-gateway 10.10.10.10,, route 192.168.1.0 255.255.255.0,";
const char *msg7 = ",,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,";
const char *msg8 = "-dhcp-option,blablalalalalalalalalalalalalf, lalalalalalalalalalalalalalaf, akakakakakakakakakakakaf,"
                   " dhcp-option DNS 8.8.8.8,redirect-gateway\n local,route 192.168.1.0 255.255.255.0\n\n\n";
const char *msg9 = ",";

const char *msg10 = "abandon ability able about above absent absorb abstract absurd abuse access accident account accuse achieve"
                    "acid acoustic acquire across act action actor actress actual adapt add addict address adjust"
                    "baby bachelor bacon badge bag balance balcony ball bamboo banana banner bar barely bargain barrel base basic"
                    "basket battle beach bean beauty because become beef before begin behave behind"
                    "cabbage cabin cable cactus cage cake call calm camera camp can canal cancel candy cannon canoe canvas canyon"
                    "capable capital captain car carbon card cargo carpet carry cart case"
                    "daisy damage damp dance danger daring dash daughter dawn day deal debate debris decade december decide decline"
                    "decorate decrease deer defense define defy degree delay deliver demand demise denial";

const char *msg11 = "a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,"
                    "a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,"
                    "a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,"
                    "a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,"
                    "a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a";

const char *msg12 = "a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,,,,,,a,abc";

const char *msg13 = "a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,,,,,,a,";

const char *msg14 = "a,aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa,a";

#define PUSH_BUNDLE_SIZE_TEST 184

#define expect_control_channel_strings(res)                          \
    do                                                               \
    {                                                                \
        for (int j = 0; res[j] != NULL; j++)                         \
        {                                                            \
            expect_string(send_control_channel_string, str, res[j]); \
        }                                                            \
    } while (0)

static void
test_send_push_msg0(void **state)
{
    struct multi_context *m = *state;
    const unsigned long cid = 0;
    expect_control_channel_strings(r0);
    assert_int_equal(send_push_update(m, &cid, msg0, UPT_BY_CID, PUSH_BUNDLE_SIZE_TEST), 1);
}

static void
test_send_push_msg1(void **state)
{
    struct multi_context *m = *state;
    const unsigned long cid = 0;
    expect_control_channel_strings(r1);
    assert_int_equal(send_push_update(m, &cid, msg1, UPT_BY_CID, PUSH_BUNDLE_SIZE_TEST), 1);
}

static void
test_send_push_msg2(void **state)
{
    struct multi_context *m = *state;
    const unsigned long cid = 0;
    assert_int_equal(send_push_update(m, &cid, msg2, UPT_BY_CID, PUSH_BUNDLE_SIZE_TEST), -EINVAL);
}

static void
test_send_push_msg3(void **state)
{
    struct multi_context *m = *state;
    const unsigned long cid = 0;
    expect_control_channel_strings(r3);
    assert_int_equal(send_push_update(m, &cid, msg3, UPT_BY_CID, PUSH_BUNDLE_SIZE_TEST), 1);
}

static void
test_send_push_msg4(void **state)
{
    struct multi_context *m = *state;
    const unsigned long cid = 0;
    expect_control_channel_strings(r4);
    assert_int_equal(send_push_update(m, &cid, msg4, UPT_BY_CID, PUSH_BUNDLE_SIZE_TEST), 1);
}

static void
test_send_push_msg5(void **state)
{
    struct multi_context *m = *state;
    const unsigned long cid = 0;
    expect_control_channel_strings(r5);
    assert_int_equal(send_push_update(m, &cid, msg5, UPT_BY_CID, PUSH_BUNDLE_SIZE_TEST), 1);
}

static void
test_send_push_msg6(void **state)
{
    struct multi_context *m = *state;
    const unsigned long cid = 0;
    expect_control_channel_strings(r6);
    assert_int_equal(send_push_update(m, &cid, msg6, UPT_BY_CID, PUSH_BUNDLE_SIZE_TEST), 1);
}

static void
test_send_push_msg7(void **state)
{
    struct multi_context *m = *state;
    const unsigned long cid = 0;
    expect_control_channel_strings(r7);
    assert_int_equal(send_push_update(m, &cid, msg7, UPT_BY_CID, PUSH_BUNDLE_SIZE_TEST), 1);
}

static void
test_send_push_msg8(void **state)
{
    struct multi_context *m = *state;
    const unsigned long cid = 0;
    expect_control_channel_strings(r8);
    assert_int_equal(send_push_update(m, &cid, msg8, UPT_BY_CID, PUSH_BUNDLE_SIZE_TEST), 1);
}

static void
test_send_push_msg9(void **state)
{
    struct multi_context *m = *state;
    const unsigned long cid = 0;
    expect_control_channel_strings(r9);
    assert_int_equal(send_push_update(m, &cid, msg9, UPT_BY_CID, PUSH_BUNDLE_SIZE_TEST), 1);
}

static void
test_send_push_msg10(void **state)
{
    struct multi_context *m = *state;
    const unsigned long cid = 0;
    assert_int_equal(send_push_update(m, &cid, msg10, UPT_BY_CID, PUSH_BUNDLE_SIZE_TEST), -EINVAL);
}

static void
test_send_push_msg11(void **state)
{
    struct multi_context *m = *state;
    const unsigned long cid = 0;
    expect_control_channel_strings(r11);
    assert_int_equal(send_push_update(m, &cid, msg11, UPT_BY_CID, PUSH_BUNDLE_SIZE_TEST), 1);
}

static void
test_send_push_msg12(void **state)
{
    struct multi_context *m = *state;
    const unsigned long cid = 0;
    expect_control_channel_strings(r12);
    assert_int_equal(send_push_update(m, &cid, msg12, UPT_BY_CID, PUSH_BUNDLE_SIZE_TEST), 1);
}

static void
test_send_push_msg13(void **state)
{
    struct multi_context *m = *state;
    const unsigned long cid = 0;
    expect_control_channel_strings(r13);
    assert_int_equal(send_push_update(m, &cid, msg13, UPT_BY_CID, PUSH_BUNDLE_SIZE_TEST), 1);
}

static void
test_send_push_msg14(void **state)
{
    struct multi_context *m = *state;
    const unsigned long cid = 0;
    expect_control_channel_strings(r14);
    assert_int_equal(send_push_update(m, &cid, msg14, UPT_BY_CID, PUSH_BUNDLE_SIZE_TEST), 1);
}

#undef PUSH_BUNDLE_SIZE_TEST

static int
setup2(void **state)
{
    struct multi_context *m = calloc(1, sizeof(struct multi_context));
    m->instances = calloc(1, sizeof(struct multi_instance *));
    struct multi_instance *mi = calloc(1, sizeof(struct multi_instance));
    mi->context.c2.tls_multi = calloc(1, sizeof(struct tls_multi));
    *(m->instances) = mi;
    m->top.options.disable_dco = true;
    *state = m;
    return 0;
}

static int
teardown2(void **state)
{
    struct multi_context *m = *state;
    free((*(m->instances))->context.c2.tls_multi);
    free(*(m->instances));
    free(m->instances);
    free(m);
    return 0;
}
#endif /* ifdef ENABLE_MANAGEMENT */

static int
setup(void **state)
{
    struct context *c = calloc(1, sizeof(struct context));
    c->options.pull = true;
    c->options.route_nopull = false;
    *state = c;
    return 0;
}

static int
teardown(void **state)
{
    struct context *c = *state;
    free(c);
    return 0;
}

int
main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test_setup_teardown(test_incoming_push_message_basic, setup, teardown),
        cmocka_unit_test_setup_teardown(test_incoming_push_message_error1, setup, teardown),
        cmocka_unit_test_setup_teardown(test_incoming_push_message_error2, setup, teardown),
        cmocka_unit_test_setup_teardown(test_incoming_push_message_not_updatable_option, setup,
                                        teardown),
        cmocka_unit_test_setup_teardown(test_incoming_push_message_1, setup, teardown),
        cmocka_unit_test_setup_teardown(test_incoming_push_message_bad_format, setup, teardown),
        cmocka_unit_test_setup_teardown(test_incoming_push_message_mix, setup, teardown),
        cmocka_unit_test_setup_teardown(test_incoming_push_message_mix2, setup, teardown),
#ifdef ENABLE_MANAGEMENT

        cmocka_unit_test_setup_teardown(test_send_push_msg0, setup2, teardown2),
        cmocka_unit_test_setup_teardown(test_send_push_msg1, setup2, teardown2),
        cmocka_unit_test_setup_teardown(test_send_push_msg2, setup2, teardown2),
        cmocka_unit_test_setup_teardown(test_send_push_msg3, setup2, teardown2),
        cmocka_unit_test_setup_teardown(test_send_push_msg4, setup2, teardown2),
        cmocka_unit_test_setup_teardown(test_send_push_msg5, setup2, teardown2),
        cmocka_unit_test_setup_teardown(test_send_push_msg6, setup2, teardown2),
        cmocka_unit_test_setup_teardown(test_send_push_msg7, setup2, teardown2),
        cmocka_unit_test_setup_teardown(test_send_push_msg8, setup2, teardown2),
        cmocka_unit_test_setup_teardown(test_send_push_msg9, setup2, teardown2),
        cmocka_unit_test_setup_teardown(test_send_push_msg10, setup2, teardown2),
        cmocka_unit_test_setup_teardown(test_send_push_msg11, setup2, teardown2),
        cmocka_unit_test_setup_teardown(test_send_push_msg12, setup2, teardown2),
        cmocka_unit_test_setup_teardown(test_send_push_msg13, setup2, teardown2),
        cmocka_unit_test_setup_teardown(test_send_push_msg14, setup2, teardown2)
#endif
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
