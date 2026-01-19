AUTOMAKE_OPTIONS = foreign

AM_TESTSUITE_SUMMARY_HEADER = ' for $(PACKAGE_STRING) service Unit-Tests'

if WIN32
test_binaries = openvpnserv_testdriver
endif

openvpnserv_testdriver_CFLAGS  = -I$(top_srcdir)/include -I$(top_srcdir)/src/openvpn -I$(top_srcdir)/src/compat -I$(top_srcdir)/src/openvpnserv @TEST_CFLAGS@
openvpnserv_testdriver_LDFLAGS = @TEST_LDFLAGS@ -L$(top_srcdir)/src/openvpn
openvpnserv_testdriver_SOURCES = test_openvpnserv.c \
	$(top_srcdir)/src/openvpnserv/common.c \
	$(top_srcdir)/src/openvpnserv/validate.c \
	$(top_srcdir)/src//openvpn/wfp_block.c \
	$(top_srcdir)/src//openvpn/wfp_block.h
