#
#  OpenVPN -- An application to securely tunnel IP networks
#             over a single UDP port, with support for SSL/TLS-based
#             session authentication and key exchange,
#             packet encryption, packet authentication, and
#             packet compression.
#
#  Copyright (C) 2002-2025 OpenVPN Inc <sales@openvpn.net>
#

MAINTAINERCLEANFILES = \
	$(srcdir)/Makefile.in

EXTRA_DIST = \
	macos-dns-updown.sh \
	systemd-dns-updown.sh \
	openresolv-dns-updown.sh \
	haikuos_file-dns-updown.sh \
	resolvconf_file-dns-updown.sh

script_SCRIPTS = \
	dns-updown

CLEANFILES = $(script_SCRIPTS)

dns-updown: @DNS_UPDOWN_TYPE@-dns-updown.sh
	cp ${srcdir}/@DNS_UPDOWN_TYPE@-dns-updown.sh $@
	chmod +x $@

all: $(script_SCRIPTS)
