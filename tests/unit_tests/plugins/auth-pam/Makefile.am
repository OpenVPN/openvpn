AUTOMAKE_OPTIONS = foreign

if ENABLE_PLUGIN_AUTH_PAM
check_PROGRAMS = auth_pam_testdriver
TESTS = $(check_PROGRAMS)
endif

auth_pam_testdriver_SOURCES = test_search_and_replace.c  $(top_srcdir)/src/plugins/auth-pam/utils.h $(top_srcdir)/src/plugins/auth-pam/utils.c
auth_pam_testdriver_CFLAGS  = @TEST_CFLAGS@ -I$(top_srcdir)/src/plugins/auth-pam
auth_pam_testdriver_LDFLAGS = @TEST_LDFLAGS@
