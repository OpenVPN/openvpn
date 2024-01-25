#
#  OpenVPN -- An application to securely tunnel IP networks
#             over a single UDP port, with support for SSL/TLS-based
#             session authentication and key exchange,
#             packet encryption, packet authentication, and
#             packet compression.
#
#  Copyright (C) 2002-2024 OpenVPN Inc <sales@openvpn.net>
#  Copyright (C) 2006-2012 Alon Bar-Lev <alon.barlev@gmail.com>
#

MAINTAINERCLEANFILES = \
	$(srcdir)/Makefile.in

SUBDIRS = unit_tests

AM_TESTSUITE_SUMMARY_HEADER = ' for $(PACKAGE_STRING) System Tests'
LOG_DRIVER = $(SHELL) $(top_srcdir)/forked-test-driver

if !WIN32
test_scripts = t_client.sh t_lpback.sh t_cltsrv.sh

check_PROGRAMS = ntlm_support
if HAVE_SITNL
test_scripts += t_net.sh
endif
endif

TESTS_ENVIRONMENT = top_srcdir="$(top_srcdir)"
TESTS = $(test_scripts)

dist_noinst_SCRIPTS = \
	t_cltsrv.sh \
	t_cltsrv-down.sh \
	t_lpback.sh \
	t_net.sh \
	update_t_client_ips.sh

dist_noinst_DATA = \
	t_client.rc-sample

ntlm_support_CFLAGS  = -I$(top_srcdir)/src/openvpn -I$(top_srcdir)/src/compat -I$(top_srcdir)/tests/unit_tests/openvpn -DNO_CMOCKA @TEST_CFLAGS@
ntlm_support_LDFLAGS = @TEST_LDFLAGS@ -L$(top_srcdir)/src/openvpn $(OPTIONAL_CRYPTO_LIBS)
ntlm_support_SOURCES = ntlm_support.c \
	unit_tests/openvpn/mock_msg.c unit_tests/openvpn/mock_msg.h \
	$(top_srcdir)/src/openvpn/buffer.c \
	$(top_srcdir)/src/openvpn/crypto.c \
	$(top_srcdir)/src/openvpn/crypto_openssl.c \
	$(top_srcdir)/src/openvpn/crypto_mbedtls.c \
	$(top_srcdir)/src/openvpn/otime.c \
	$(top_srcdir)/src/openvpn/packet_id.c \
	$(top_srcdir)/src/openvpn/platform.c
