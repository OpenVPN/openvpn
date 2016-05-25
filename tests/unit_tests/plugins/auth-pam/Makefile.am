AUTOMAKE_OPTIONS = foreign

if ENABLE_PLUGIN_AUTH_PAM
check_PROGRAMS = auth_pam_testdriver
TESTS = $(check_PROGRAMS)
endif

sut_sourcedir = $(top_srcdir)/src/plugins/auth-pam

auth_pam_testdriver_SOURCES = test_search_and_replace.c  $(sut_sourcedir)/utils.h $(sut_sourcedir)/utils.c
auth_pam_testdriver_CFLAGS  = @TEST_CFLAGS@ -I$(sut_sourcedir)
auth_pam_testdriver_LDFLAGS = @TEST_LDFLAGS@
