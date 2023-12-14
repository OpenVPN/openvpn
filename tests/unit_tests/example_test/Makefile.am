AUTOMAKE_OPTIONS = foreign

AM_TESTSUITE_SUMMARY_HEADER = ' for $(PACKAGE_STRING) example Unit-Tests'

check_PROGRAMS = example_testdriver example2_testdriver

if !CROSS_COMPILING
TESTS = $(check_PROGRAMS)
endif

example_testdriver_CFLAGS  = @TEST_CFLAGS@
example_testdriver_LDFLAGS = @TEST_LDFLAGS@
example_testdriver_SOURCES = test.c

example2_testdriver_CFLAGS  = @TEST_CFLAGS@
example2_testdriver_LDFLAGS = @TEST_LDFLAGS@
example2_testdriver_SOURCES = test2.c
