#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <setjmp.h>
#include <stdint.h>
#include <cmocka.h>


static void
test_true(void **state)
{
    (void) state;
}


int
main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_true),
    };

    return cmocka_run_group_tests_name("success_test2", tests, NULL, NULL);
}
