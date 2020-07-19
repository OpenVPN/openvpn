#
#  OpenVPN -- An application to securely tunnel IP networks
#             over a single UDP port, with support for SSL/TLS-based
#             session authentication and key exchange,
#             packet encryption, packet authentication, and
#             packet compression.
#
#  Copyright (C) 2002-2020 OpenVPN Inc <sales@openvpn.net>
#  Copyright (C) 2006-2012 Alon Bar-Lev <alon.barlev@gmail.com>
#

MAINTAINERCLEANFILES = \
	$(srcdir)/Makefile.in

SUBDIRS = doxygen

dist_doc_DATA = \
	management-notes.txt

dist_noinst_DATA = \
	README.plugins interactive-service-notes.rst \
	openvpn.8.rst \
	man-sections/advanced-options.rst \
	man-sections/client-options.rst \
	man-sections/connection-profiles.rst \
	man-sections/encryption-options.rst \
	man-sections/examples.rst \
	man-sections/generic-options.rst \
	man-sections/inline-files.rst \
	man-sections/link-options.rst \
	man-sections/log-options.rst \
	man-sections/management-options.rst \
	man-sections/network-config.rst \
	man-sections/pkcs11-options.rst \
	man-sections/plugin-options.rst \
	man-sections/protocol-options.rst \
	man-sections/proxy-options.rst \
	man-sections/renegotiation.rst \
	man-sections/signals.rst \
	man-sections/script-options.rst \
	man-sections/server-options.rst \
	man-sections/tls-options.rst \
	man-sections/unsupported-options.rst \
	man-sections/virtual-routing-and-forwarding.rst \
	man-sections/vpn-network-options.rst \
	man-sections/windows-options.rst

openvpn.8 :
if HAVE_PYDOCUTILS
	$(RST2MAN) $(srcdir)/$@.rst > $@
else
	@echo "Missing python-docutils - skipping man page generation"
endif

openvpn.8.html:
if HAVE_PYDOCUTILS
	$(RST2HTML) $(srcdir)/openvpn.8.rst > $@
else
	@echo "Missing python-docutils - skipping man/html page generation"
endif

if HAVE_PYDOCUTILS
dist_noinst_DATA += openvpn.8
dist_html_DATA = openvpn.8.html

# Failsafe - do not delete these files unless we can recreate them
CLEANFILES = \
	 openvpn.8 openvpn.8.html

if WIN32
else
dist_man_MANS = openvpn.8
endif
endif

dist-hook : openvpn.8 openvpn.8.html
