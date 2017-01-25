#
#  OpenVPN -- An application to securely tunnel IP networks
#             over a single UDP port, with support for SSL/TLS-based
#             session authentication and key exchange,
#             packet encryption, packet authentication, and
#             packet compression.
#
#  Copyright (C) 2002-2017 OpenVPN Technologies, Inc. <sales@openvpn.net>
#  Copyright (C) 2006-2012 Alon Bar-Lev <alon.barlev@gmail.com>
#

MAINTAINERCLEANFILES = \
	$(srcdir)/Makefile.in \
	$(srcdir)/openvpn-plugin.h.in

include_HEADERS = \
	openvpn-plugin.h \
	openvpn-msg.h

openvpn-plugin.h: openvpn-plugin.h.in Makefile
	$(AM_V_GEN)sed -e 's|\@PLUGINDIR\@|$(plugindir)|' \
		-e 's|\@OPENVPN_VERSION_MAJOR\@|$(OPENVPN_VERSION_MAJOR)|' \
		-e 's|\@OPENVPN_VERSION_MINOR\@|$(OPENVPN_VERSION_MINOR)|' \
		-e 's|\@OPENVPN_VERSION_PATCH\@|$(OPENVPN_VERSION_PATCH)|' \
               $< > $@.tmp && mv $@.tmp $@
