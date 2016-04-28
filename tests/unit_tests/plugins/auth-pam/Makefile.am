AUTOMAKE_OPTIONS = foreign

check_PROGRAMS = testdriver

TESTS = testdriver

sut_sourcedir = $(top_srcdir)/src/plugins/auth-pam

testdriver_SOURCES = test_search_and_replace.c  $(sut_sourcedir)/utils.h $(sut_sourcedir)/utils.c
testdriver_CFLAGS  = @TEST_CFLAGS@ -I$(sut_sourcedir)
testdriver_LDFLAGS = @TEST_LDFLAGS@
