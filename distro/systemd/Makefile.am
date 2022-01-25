#
#  OpenVPN -- An application to securely tunnel IP networks
#             over a single UDP port, with support for SSL/TLS-based
#             session authentication and key exchange,
#             packet encryption, packet authentication, and
#             packet compression.
#
#  Copyright (C) 2017-2022 OpenVPN Inc <sales@openvpn.net>
#

%.service: %.service.in Makefile
	$(AM_V_GEN)sed -e 's|\@sbindir\@|$(sbindir)|' \
		$< > $@.tmp && mv $@.tmp $@

EXTRA_DIST = \
	tmpfiles-openvpn.conf \
	openvpn-client@.service.in \
	openvpn-server@.service.in

if ENABLE_SYSTEMD
systemdunit_DATA = \
	openvpn-client@.service \
	openvpn-server@.service
tmpfiles_DATA = \
	tmpfiles-openvpn.conf
dist_doc_DATA = \
	README.systemd

install-data-hook:
	mv $(DESTDIR)$(tmpfilesdir)/tmpfiles-openvpn.conf $(DESTDIR)$(tmpfilesdir)/openvpn.conf
endif

MAINTAINERCLEANFILES = \
	$(srcdir)/Makefile.in
