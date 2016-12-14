#include "config.h"
#include "syshead.h"

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <setjmp.h>
#include <cmocka.h>
#include <assert.h>

#include "argv.h"
#include "buffer.h"

/*
 * This is defined here to prevent #include'ing misc.h
 * which makes things difficult beyond any recognition
 */
size_t
adjust_power_of_2(size_t u)
{
    size_t ret = 1;

    while (ret < u)
    {
        ret <<= 1;
        assert(ret > 0);
    }

    return ret;
}

/* Defines for use in the tests and the mock parse_line() */
#define PATH1       "/s p a c e"
#define PATH2       "/foo bar/baz"
#define PARAM1      "param1"
#define PARAM2      "param two"
#define SCRIPT_CMD  "\"" PATH1 PATH2 "\"" PARAM1 "\"" PARAM2 "\""

int
__wrap_parse_line(const char *line, char **p, const int n, const char *file,
                  const int line_num, int msglevel, struct gc_arena *gc)
{
    p[0] = PATH1 PATH2;
    p[1] = PARAM1;
    p[2] = PARAM2;
    return 3;
}

static void
argv_printf__multiple_spaces_in_format__parsed_as_one(void **state)
{
    struct argv a = argv_new();

    argv_printf(&a, "    %s     %s  %d   ", PATH1, PATH2, 42);
    assert_int_equal(a.argc, 3);

    argv_reset(&a);
}

static void
argv_printf_cat__multiple_spaces_in_format__parsed_as_one(void **state)
{
    struct argv a = argv_new();

    argv_printf(&a, "%s ", PATH1);
    argv_printf_cat(&a, " %s  %s", PATH2, PARAM1);
    assert_int_equal(a.argc, 3);

    argv_reset(&a);
}

static void
argv_printf__combined_path_with_spaces__argc_correct(void **state)
{
    struct argv a = argv_new();

    argv_printf(&a, "%s%sc", PATH1, PATH2);
    assert_int_equal(a.argc, 1);

    argv_printf(&a, "%s%sc %d", PATH1, PATH2, 42);
    assert_int_equal(a.argc, 2);

    argv_printf(&a, "foo %s%sc %s x y", PATH2, PATH1, "foo");
    assert_int_equal(a.argc, 5);

    argv_reset(&a);
}

static void
argv_parse_cmd__command_string__argc_correct(void **state)
{
    struct argv a = argv_new();

    argv_parse_cmd(&a, SCRIPT_CMD);
    assert_int_equal(a.argc, 3);

    argv_reset(&a);
}

static void
argv_parse_cmd__command_and_extra_options__argc_correct(void **state)
{
    struct argv a = argv_new();

    argv_parse_cmd(&a, SCRIPT_CMD);
    argv_printf_cat(&a, "bar baz %d %s", 42, PATH1);
    assert_int_equal(a.argc, 7);

    argv_reset(&a);
}

static void
argv_printf_cat__used_twice__argc_correct(void **state)
{
    struct argv a = argv_new();

    argv_printf(&a, "%s %s %s", PATH1, PATH2, PARAM1);
    argv_printf_cat(&a, "%s", PARAM2);
    argv_printf_cat(&a, "foo");
    assert_int_equal(a.argc, 5);

    argv_reset(&a);
}

static void
argv_str__multiple_argv__correct_output(void **state)
{
    struct argv a = argv_new();
    struct gc_arena gc = gc_new();
    const char *output;

    argv_printf(&a, "%s%sc", PATH1, PATH2);
    argv_printf_cat(&a, "%s", PARAM1);
    argv_printf_cat(&a, "%s", PARAM2);
    output = argv_str(&a, &gc, PA_BRACKET);
    assert_string_equal(output, "[" PATH1 PATH2 "] [" PARAM1 "] [" PARAM2 "]");

    argv_reset(&a);
    gc_free(&gc);
}

static void
argv_insert_head__empty_argv__head_only(void **state)
{
    struct argv a = argv_new();
    struct argv b;

    b = argv_insert_head(&a, PATH1);
    assert_int_equal(b.argc, 1);
    assert_string_equal(b.argv[0], PATH1);
    argv_reset(&b);

    argv_reset(&a);
}

static void
argv_insert_head__non_empty_argv__head_added(void **state)
{
    struct argv a = argv_new();
    struct argv b;
    int i;

    argv_printf(&a, "%s", PATH2);
    b = argv_insert_head(&a, PATH1);
    assert_int_equal(b.argc, a.argc + 1);
    for (i = 0; i < b.argc; i++) {
        if (i == 0)
        {
            assert_string_equal(b.argv[i], PATH1);
        }
        else
        {
            assert_string_equal(b.argv[i], a.argv[i - 1]);
        }
    }
    argv_reset(&b);

    argv_reset(&a);
}

int
main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(argv_printf__multiple_spaces_in_format__parsed_as_one),
        cmocka_unit_test(argv_printf_cat__multiple_spaces_in_format__parsed_as_one),
        cmocka_unit_test(argv_printf__combined_path_with_spaces__argc_correct),
        cmocka_unit_test(argv_parse_cmd__command_string__argc_correct),
        cmocka_unit_test(argv_parse_cmd__command_and_extra_options__argc_correct),
        cmocka_unit_test(argv_printf_cat__used_twice__argc_correct),
        cmocka_unit_test(argv_str__multiple_argv__correct_output),
        cmocka_unit_test(argv_insert_head__non_empty_argv__head_added),
    };

    return cmocka_run_group_tests_name("argv", tests, NULL, NULL);
}
