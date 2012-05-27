#
#  OpenVPN -- An application to securely tunnel IP networks
#             over a single UDP port, with support for SSL/TLS-based
#             session authentication and key exchange,
#             packet encryption, packet authentication, and
#             packet compression.
#
#  Copyright (C) 2002-2010 OpenVPN Technologies, Inc. <sales@openvpn.net>
#  Copyright (C) 2006-2012 Alon Bar-Lev <alon.barlev@gmail.com>
#

MAINTAINERCLEANFILES = \
	$(srcdir)/Makefile.in

test_scripts = t_client.sh t_lpback.sh t_cltsrv.sh

TESTS_ENVIRONMENT = top_srcdir="$(top_srcdir)"
TESTS = $(test_scripts)

dist_noinst_SCRIPTS = \
	$(test_scripts) \
	t_cltsrv-down.sh

