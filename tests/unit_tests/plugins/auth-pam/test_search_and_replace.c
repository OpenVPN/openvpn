#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <setjmp.h>
#include <cmocka.h>

#include "utils.h"

static void
pass_any_null_param__returns_null() {

    char DUMMY[] = "DUMMY";

    assert_null(searchandreplace(NULL,DUMMY,DUMMY));
    assert_null(searchandreplace(DUMMY,NULL,DUMMY));
    assert_null(searchandreplace(DUMMY,DUMMY,NULL));
}

static void
pass_any_empty_string__returns_null() {

    char DUMMY[] = "DUMMY";
    char EMPTY[] = "";

    assert_null(searchandreplace(EMPTY,DUMMY,DUMMY));
    assert_null(searchandreplace(DUMMY,EMPTY,DUMMY));
    assert_null(searchandreplace(DUMMY,DUMMY,EMPTY));
}

static void
replace_single_char__one_time__match_is_replaced() {
    char *replaced = searchandreplace("X","X","Y");

    assert_non_null(replaced);
    assert_string_equal("Y", replaced);

    free(replaced);
}

static void
replace_single_char__multiple_times__match_all_matches_are_replaced() {
    char *replaced = searchandreplace("XaX","X","Y");

    assert_non_null(replaced);
    assert_string_equal("YaY", replaced);

    free(replaced);
}

static void
replace_longer_text__multiple_times__match_all_matches_are_replaced() {
    char *replaced = searchandreplace("XXaXX","XX","YY");

    assert_non_null(replaced);
    assert_string_equal("YYaYY", replaced);

    free(replaced);
}

static void
pattern_not_found__returns_original() {
    char *replaced = searchandreplace("abc","X","Y");

    assert_non_null(replaced);
    assert_string_equal("abc", replaced);

    free(replaced);
}


int
main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(pass_any_null_param__returns_null),
        cmocka_unit_test(pass_any_empty_string__returns_null),
        cmocka_unit_test(replace_single_char__one_time__match_is_replaced),
        cmocka_unit_test(replace_single_char__multiple_times__match_all_matches_are_replaced),
        cmocka_unit_test(replace_longer_text__multiple_times__match_all_matches_are_replaced),
        cmocka_unit_test(pattern_not_found__returns_original),
    };

    return cmocka_run_group_tests_name("searchandreplace", tests, NULL, NULL);
}
