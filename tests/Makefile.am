#
#  OpenVPN -- An application to securely tunnel IP networks
#             over a single UDP port, with support for SSL/TLS-based
#             session authentication and key exchange,
#             packet encryption, packet authentication, and
#             packet compression.
#
#  Copyright (C) 2002-2021 OpenVPN Inc <sales@openvpn.net>
#  Copyright (C) 2006-2012 Alon Bar-Lev <alon.barlev@gmail.com>
#

MAINTAINERCLEANFILES = \
	$(srcdir)/Makefile.in

SUBDIRS = unit_tests

test_scripts = t_client.sh t_lpback.sh t_cltsrv.sh
if HAVE_SITNL
test_scripts += t_net.sh
endif

TESTS_ENVIRONMENT = top_srcdir="$(top_srcdir)"
TESTS = $(test_scripts)

dist_noinst_SCRIPTS = \
	$(test_scripts) \
	t_cltsrv-down.sh \
	update_t_client_ips.sh

dist_noinst_DATA = \
	t_client.rc-sample
