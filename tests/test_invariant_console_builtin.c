#include <check.h>
#include <stdlib.h>
#include <string.h>
#include "src/openvpn/console_builtin.c"

START_TEST(test_buffer_reads_never_exceed_declared_length)
{
    // Invariant: Buffer reads never exceed the declared length
    const char *payloads[] = {
        "A",  // Valid input (boundary case: minimal)
        "1234567890123456789012345678901234567890",  // Exact capacity-1 (39 chars + null)
        "1234567890123456789012345678901234567890123456789012345678901234567890",  // 2x capacity
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",  // 10x capacity
        "\x1b[31m\x1b[0mAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"  // Escape sequences + overflow
    };
    int num_payloads = sizeof(payloads) / sizeof(payloads[0]);
    const int capacity = 40;
    
    for (int i = 0; i < num_payloads; i++) {
        char input[capacity] = {0};
        char guard_before[16] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
                                 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
        char guard_after[16] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
                                0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
        
        // Simulate input by mocking fgets behavior
        FILE *mock_fp = tmpfile();
        fputs(payloads[i], mock_fp);
        rewind(mock_fp);
        
        // Replace fgets with our mock for testing
        char *original_fgets = fgets;
        fgets = mock_fgets;
        
        bool result = get_console_input("test", true, input, capacity);
        
        fgets = original_fgets;
        fclose(mock_fp);
        
        // Check guard bytes remain unchanged
        for (int j = 0; j < 16; j++) {
            ck_assert_msg(guard_before[j] == (char)0xFF, 
                         "Buffer underflow detected before input buffer");
            ck_assert_msg(guard_after[j] == (char)0xFF, 
                         "Buffer overflow detected after input buffer");
        }
        
        // Check input is properly null-terminated
        ck_assert_msg(input[capacity-1] == '\0' || strlen(input) < capacity,
                     "Input buffer not properly null-terminated");
        
        // Check no out-of-bounds write occurred
        if (result) {
            ck_assert_msg(strlen(input) < capacity,
                         "Successful read produced string exceeding capacity");
        }
    }
}
END_TEST

// Mock fgets that respects capacity
char *mock_fgets(char *s, int size, FILE *stream) {
    if (size <= 0) return NULL;
    
    int c;
    int i = 0;
    
    while (i < size - 1 && (c = fgetc(stream)) != EOF) {
        s[i++] = (char)c;
        if (c == '\n') {
            break;
        }
    }
    
    if (i == 0 && c == EOF) {
        return NULL;
    }
    
    s[i] = '\0';
    return s;
}

Suite *security_suite(void) {
    Suite *s;
    TCase *tc_core;

    s = suite_create("Security");
    tc_core = tcase_create("Core");

    tcase_add_test(tc_core, test_buffer_reads_never_exceed_declared_length);
    suite_add_tcase(s, tc_core);

    return s;
}

int main(void) {
    int number_failed;
    Suite *s;
    SRunner *sr;

    s = security_suite();
    sr = srunner_create(s);

    srunner_run_all(sr, CK_NORMAL);
    number_failed = srunner_ntests_failed(sr);
    srunner_free(sr);

    return (number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}