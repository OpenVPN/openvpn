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

DISTCLEANFILES = \
       $(builddir)/sample-plugins/Makefile

EXTRA_DIST = \
	sample-plugins \
	sample-config-files \
	sample-windows \
	sample-keys \
	sample-scripts

if WIN32
sample_DATA = \
	client.ovpn \
	server.ovpn \
	sample-windows/sample.ovpn

client.ovpn: sample-config-files/client.conf
	-rm -f client.ovpn
	cp "$(srcdir)/sample-config-files/client.conf" client.ovpn
server.ovpn: sample-config-files/server.conf
	-rm -f server.ovpn
	cp "$(srcdir)/sample-config-files/server.conf" server.ovpn
endif
