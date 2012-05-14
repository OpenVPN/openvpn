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

CLEANFILES = openvpn.8.html

dist_doc_DATA = \
	management-notes.txt

dist_noinst_DATA = \
	README.plugins

if WIN32
dist_noinst_DATA += openvpn.8
nodist_html_DATA = openvpn.8.html
openvpn.8.html: $(srcdir)/openvpn.8
	$(MAN2HTML) < $(srcdir)/openvpn.8 > openvpn.8.html
else
dist_man_MANS = openvpn.8
endif

