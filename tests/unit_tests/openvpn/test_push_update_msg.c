#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdlib.h>
#include <stdarg.h>
#include <setjmp.h>
#include <cmocka.h>
#include "push.h"
#include "options_util.h"

/* mocks */

unsigned int
pull_permission_mask(const struct context *c)
{
    unsigned int flags =
        OPT_P_UP
        | OPT_P_ROUTE_EXTRAS
        | OPT_P_SOCKBUF
        | OPT_P_SOCKFLAGS
        | OPT_P_SETENV
        | OPT_P_SHAPER
        | OPT_P_TIMER
        | OPT_P_COMP
        | OPT_P_PERSIST
        | OPT_P_MESSAGES
        | OPT_P_EXPLICIT_NOTIFY
        | OPT_P_ECHO
        | OPT_P_PULL_MODE
        | OPT_P_PEER_ID
        | OPT_P_NCP
        | OPT_P_PUSH_MTU
        | OPT_P_ROUTE
        | OPT_P_DHCPDNS;
    return flags;
}

bool
apply_push_options(struct context *c,
                   struct options *options,
                   struct buffer *buf,
                   unsigned int permission_mask,
                   unsigned int *option_types_found,
                   struct env_set *es,
                   bool is_update)
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
                msg(M_WARN, "Offending option received from server");
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
process_incoming_push_msg(struct context *c,
                          const struct buffer *buffer,
                          bool honor_received_options,
                          unsigned int permission_mask,
                          unsigned int *option_types_found)
{
    struct buffer buf = *buffer;

    if (buf_string_compare_advance(&buf, "PUSH_REQUEST"))
    {
        return PUSH_MSG_REQUEST;
    }
    else if (honor_received_options
             && buf_string_compare_advance(&buf, push_reply_cmd))
    {
        return PUSH_MSG_REPLY;
    }
    else if (honor_received_options
             && buf_string_compare_advance(&buf, push_update_cmd))
    {
        return process_incoming_push_update(c, permission_mask,
                                            option_types_found, &buf);
    }
    else
    {
        return PUSH_MSG_ERROR;
    }
}

/* tests */

static void
test_incoming_push_message_basic(void **state)
{
    struct context *c = *state;
    struct buffer buf = alloc_buf(256);
    const char *update_msg = "PUSH_UPDATE,dhcp-option DNS 8.8.8.8, route 0.0.0.0 0.0.0.0 10.10.10.1";
    buf_write(&buf, update_msg, strlen(update_msg));
    unsigned int option_types_found = 0;

    assert_int_equal(process_incoming_push_msg(c, &buf, c->options.pull, pull_permission_mask(c), &option_types_found), PUSH_MSG_UPDATE);

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

    assert_int_equal(process_incoming_push_msg(c, &buf, c->options.pull, pull_permission_mask(c), &option_types_found), PUSH_MSG_ERROR);

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

    assert_int_equal(process_incoming_push_msg(c, &buf, c->options.pull, pull_permission_mask(c), &option_types_found), PUSH_MSG_ERROR);

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

    assert_int_equal(process_incoming_push_msg(c, &buf, c->options.pull, pull_permission_mask(c), &option_types_found), PUSH_MSG_UPDATE);

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

    assert_int_equal(process_incoming_push_msg(c, &buf, c->options.pull, pull_permission_mask(c), &option_types_found), PUSH_MSG_ERROR);

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

    assert_int_equal(process_incoming_push_msg(c, &buf, c->options.pull, pull_permission_mask(c), &option_types_found), PUSH_MSG_ERROR);

    free_buf(&buf);
}

static void
test_incoming_push_message_mix(void **state)
{
    struct context *c = *state;
    struct buffer buf = alloc_buf(256);
    const char *update_msg = "PUSH_UPDATE,-dhcp-option, route 10.10.10.0, dhcp-option DNS 1.1.1.1, route 10.11.12.0, dhcp-option DOMAIN corp.local, keepalive 10 60";
    buf_write(&buf, update_msg, strlen(update_msg));
    unsigned int option_types_found = 0;

    assert_int_equal(process_incoming_push_msg(c, &buf, c->options.pull, pull_permission_mask(c), &option_types_found), PUSH_MSG_UPDATE);

    free_buf(&buf);
}

static void
test_incoming_push_message_mix2(void **state)
{
    struct context *c = *state;
    struct buffer buf = alloc_buf(256);
    const char *update_msg = "PUSH_UPDATE,-dhcp-option,dhcp-option DNS 8.8.8.8,redirect-gateway local,route 192.168.1.0 255.255.255.0";
    buf_write(&buf, update_msg, strlen(update_msg));
    unsigned int option_types_found = 0;

    assert_int_equal(process_incoming_push_msg(c, &buf, c->options.pull, pull_permission_mask(c), &option_types_found), PUSH_MSG_UPDATE);

    free_buf(&buf);
}

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
        cmocka_unit_test_setup_teardown(test_incoming_push_message_not_updatable_option, setup, teardown),
        cmocka_unit_test_setup_teardown(test_incoming_push_message_1, setup, teardown),
        cmocka_unit_test_setup_teardown(test_incoming_push_message_bad_format, setup, teardown),
        cmocka_unit_test_setup_teardown(test_incoming_push_message_mix, setup, teardown),
        cmocka_unit_test_setup_teardown(test_incoming_push_message_mix2, setup, teardown)
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
