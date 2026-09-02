#include "config.h"
#include "syshead.h"

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <setjmp.h>
#include <cmocka.h>
#include <assert.h>
#include <stdbool.h>

#include "argv.h"
#include "buffer.h"
#include "test_common.h"

#ifdef _WIN32
#include "win32-util.h"
#endif

/* Defines for use in the tests and the mock parse_line() */
#define PATH1      "/s p a c e"
#define PATH2      "/foo bar/baz"
#define PARAM1     "param1"
#define PARAM2     "param two"
#define SCRIPT_CMD "\"" PATH1 PATH2 "\"" PARAM1 "\"" PARAM2 "\""

int
parse_line(const char *line, char **p, const int n, const char *file, const int line_num,
           msglvl_t msglevel, struct gc_arena *gc)
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

    argv_free(&a);
}

static void
argv_printf_cat__multiple_spaces_in_format__parsed_as_one(void **state)
{
    struct argv a = argv_new();

    argv_printf(&a, "%s ", PATH1);
    argv_printf_cat(&a, " %s  %s", PATH2, PARAM1);
    assert_int_equal(a.argc, 3);

    argv_free(&a);
}

static void
argv_printf__embedded_format_directive__replaced_in_output(void **state)
{
    struct argv a = argv_new();

    argv_printf(&a, "<p1:%s>", PATH1);
    assert_int_equal(a.argc, 1);
    assert_string_equal(a.argv[0], "<p1:" PATH1 ">");

    argv_free(&a);
}

static void
argv_printf__group_sep_in_arg__fail_no_ouput(void **state)
{
    struct argv a = argv_new();

    assert_false(argv_printf(&a, "tool --do %s", "this\035--harmful"));
    assert_int_equal(a.argc, 0);

    argv_free(&a);
}

static void
argv_printf__combined_path_with_spaces__argc_correct(void **state)
{
    struct argv a = argv_new();

    argv_printf(&a, "%s%s", PATH1, PATH2);
    assert_int_equal(a.argc, 1);

    argv_printf(&a, "%s%s %d", PATH1, PATH2, 42);
    assert_int_equal(a.argc, 2);

    argv_printf(&a, "foo %s%s %s x y", PATH2, PATH1, "foo");
    assert_int_equal(a.argc, 5);

    argv_free(&a);
}

static void
argv_printf__empty_parameter__argc_correct(void **state)
{
    struct argv a = argv_new();

    argv_printf(&a, "%s", "");
    assert_int_equal(a.argc, 1);

    argv_printf(&a, "%s %s", PATH1, "");
    assert_int_equal(a.argc, 2);

    argv_printf(&a, "%s %s %s", PATH1, "", PARAM1);
    assert_int_equal(a.argc, 3);

    argv_printf(&a, "%s %s %s %s", PATH1, "", "", PARAM1);
    assert_int_equal(a.argc, 4);

    argv_printf(&a, "%s %s", "", PARAM1);
    assert_int_equal(a.argc, 2);

    argv_free(&a);
}

static void
argv_printf__long_args__data_correct(void **state)
{
    int i;
    struct argv a = argv_new();
    const char *args[] = {
        "good_tools_have_good_names_even_though_it_might_impair_typing",
        "--long-opt=looooooooooooooooooooooooooooooooooooooooooooooooong",
        "--long-cat=loooooooooooooooooooooooooooooooooooooooooooooooooooonger",
        "file_with_very_descriptive_filename_that_leaves_no_questions_open.jpg.exe"
    };

    argv_printf(&a, "%s %s %s %s", args[0], args[1], args[2], args[3]);
    assert_int_equal(a.argc, 4);
    for (i = 0; i < a.argc; i++)
    {
        assert_string_equal(a.argv[i], args[i]);
    }

    argv_free(&a);
}

static void
argv_parse_cmd__command_string__argc_correct(void **state)
{
    struct argv a = argv_new();

    argv_parse_cmd(&a, SCRIPT_CMD);
    assert_int_equal(a.argc, 3);

    argv_free(&a);
}

static void
argv_parse_cmd__command_and_extra_options__argc_correct(void **state)
{
    struct argv a = argv_new();

    argv_parse_cmd(&a, SCRIPT_CMD);
    argv_printf_cat(&a, "bar baz %d %s", 42, PATH1);
    assert_int_equal(a.argc, 7);

    argv_free(&a);
}

static void
argv_printf_cat__used_twice__argc_correct(void **state)
{
    struct argv a = argv_new();

    argv_printf(&a, "%s %s %s", PATH1, PATH2, PARAM1);
    argv_printf_cat(&a, "%s", PARAM2);
    argv_printf_cat(&a, "foo");
    assert_int_equal(a.argc, 5);

    argv_free(&a);
}

static void
argv_str__empty_argv__empty_output(void **state)
{
    struct argv a = argv_new();
    struct gc_arena gc = gc_new();
    const char *output;

    output = argv_str(&a, &gc, PA_BRACKET);
    assert_string_equal(output, "");

    argv_free(&a);
    gc_free(&gc);
}

static void
argv_str__multiple_argv__correct_output(void **state)
{
    struct argv a = argv_new();
    struct gc_arena gc = gc_new();
    const char *output;

    argv_printf(&a, "%s%s", PATH1, PATH2);
    argv_printf_cat(&a, "%s", PARAM1);
    argv_printf_cat(&a, "%s", PARAM2);
    argv_printf_cat(&a, "%d", -1);
    argv_printf_cat(&a, "%u", -1);
    argv_printf_cat(&a, "%lu", 1L);
    output = argv_str(&a, &gc, PA_BRACKET);
    assert_string_equal(output, "[" PATH1 PATH2 "] [" PARAM1 "] [" PARAM2 "]"
                                " [-1] [4294967295] [1]");

    argv_free(&a);
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
    argv_free(&b);

    argv_free(&a);
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
    for (i = 0; i < b.argc; i++)
    {
        if (i == 0)
        {
            assert_string_equal(b.argv[i], PATH1);
        }
        else
        {
            assert_string_equal(b.argv[i], a.argv[i - 1]);
        }
    }
    argv_free(&b);

    argv_free(&a);
}

#ifdef _WIN32
/*
 * An argument is quoted if and only if it holds a space or a character that
 * cmd.exe would act on when CreateProcess() runs a .bat/.cmd target.
 */
static void
wide_cmd_line__quotes_only_what_cmd_would_reinterpret(void **state)
{
    static const struct
    {
        const char *arg;
        const WCHAR *expected;
    } cases[] = {
        /* nothing special - must stay unquoted, or existing scripts break */
        { "CN=user1", L"script.bat 0 CN=user1" },
        /* the batch delimiters are deliberately not triggers */
        { "CN=a,b;c=d", L"script.bat 0 CN=a,b;c=d" },
        /* a space has always forced quoting */
        { "O=Ctrl, CN=y", L"script.bat 0 \"O=Ctrl, CN=y\"" },
        /* cmd.exe operators */
        { "CN=x&ver", L"script.bat 0 \"CN=x&ver\"" },
        { "CN=x|ver", L"script.bat 0 \"CN=x|ver\"" },
        { "CN=x>f", L"script.bat 0 \"CN=x>f\"" },
        { "CN=x<f", L"script.bat 0 \"CN=x<f\"" },
        { "CN=x^f", L"script.bat 0 \"CN=x^f\"" },
        { "CN=x%f", L"script.bat 0 \"CN=x%f\"" },
        { "CN=x(f)", L"script.bat 0 \"CN=x(f)\"" },
        { "CN=x!f", L"script.bat 0 \"CN=x!f\"" },
        /* a double quote is replaced, so quoting cannot be broken out of */
        { "CN=a\"b", L"script.bat 0 CN=a_b" },
    };

    for (size_t i = 0; i < SIZE(cases); i++)
    {
        struct gc_arena gc = gc_new();
        struct argv a = argv_new();

        argv_printf(&a, "%s %d %s", "script.bat", 0, cases[i].arg);
        assert_int_equal(a.argc, 3);

        WCHAR *cmd_line = wide_cmd_line(&a, &gc);
        assert_non_null(cmd_line);
        assert_int_equal(wcscmp(cmd_line, cases[i].expected), 0);

        argv_free(&a);
        gc_free(&gc);
    }
}
#endif /* _WIN32 */

int
main(void)
{
    openvpn_unit_test_setup();
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(argv_printf__multiple_spaces_in_format__parsed_as_one),
        cmocka_unit_test(argv_printf_cat__multiple_spaces_in_format__parsed_as_one),
        cmocka_unit_test(argv_printf__embedded_format_directive__replaced_in_output),
        cmocka_unit_test(argv_printf__group_sep_in_arg__fail_no_ouput),
        cmocka_unit_test(argv_printf__combined_path_with_spaces__argc_correct),
        cmocka_unit_test(argv_printf__empty_parameter__argc_correct),
        cmocka_unit_test(argv_printf__long_args__data_correct),
        cmocka_unit_test(argv_parse_cmd__command_string__argc_correct),
        cmocka_unit_test(argv_parse_cmd__command_and_extra_options__argc_correct),
        cmocka_unit_test(argv_printf_cat__used_twice__argc_correct),
        cmocka_unit_test(argv_str__empty_argv__empty_output),
        cmocka_unit_test(argv_str__multiple_argv__correct_output),
        cmocka_unit_test(argv_insert_head__non_empty_argv__head_added),
        cmocka_unit_test(argv_insert_head__empty_argv__head_only),
#ifdef _WIN32
        cmocka_unit_test(wide_cmd_line__quotes_only_what_cmd_would_reinterpret),
#endif
    };

    return cmocka_run_group_tests_name("argv", tests, NULL, NULL);
}
