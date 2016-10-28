AUTOMAKE_OPTIONS = foreign

check_PROGRAMS = argv_testdriver

TESTS = $(check_PROGRAMS)

openvpn_srcdir = $(top_srcdir)/src/openvpn
compat_srcdir = $(top_srcdir)/src/compat

argv_testdriver_CFLAGS  = @TEST_CFLAGS@ -I$(openvpn_srcdir) -I$(compat_srcdir)
argv_testdriver_LDFLAGS = @TEST_LDFLAGS@ -L$(openvpn_srcdir) -Wl,--wrap=parse_line
argv_testdriver_SOURCES = test_argv.c \
	$(openvpn_srcdir)/platform.c \
	$(openvpn_srcdir)/buffer.c \
	$(openvpn_srcdir)/argv.c
