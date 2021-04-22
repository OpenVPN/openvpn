#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <setjmp.h>
#include <cmocka.h>

static int
setup(void **state)
{
    int *answer  = malloc(sizeof(int));

    *answer = 42;
    *state = answer;

    return 0;
}

static int
teardown(void **state)
{
    free(*state);

    return 0;
}

static void
null_test_success(void **state)
{
    (void) state;
}

static void
int_test_success(void **state)
{
    int *answer = *state;
    assert_int_equal(*answer, 42);
}

__attribute__((unused))
static void
failing_test(void **state)
{
    /* This tests fails to test that make check fails */
    assert_int_equal(0, 42);
}

int
main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(null_test_success),
        cmocka_unit_test_setup_teardown(int_test_success, setup, teardown),
/*        cmocka_unit_test(failing_test), */
    };

    return cmocka_run_group_tests_name("success_test", tests, NULL, NULL);
}
