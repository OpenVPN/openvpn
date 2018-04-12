#
#  OpenVPN -- An application to securely tunnel IP networks
#             over a single UDP port, with support for SSL/TLS-based
#             session authentication and key exchange,
#             packet encryption, packet authentication, and
#             packet compression.
#
#  Copyright (C) 2017-2018 Fox-IT B.V. <openvpn@fox-it.com>
#

MAINTAINERCLEANFILES = \
	$(srcdir)/Makefile.in

DISTCLEANFILES = openvpn.doxyfile

.PHONY: doxygen
doxygen: openvpn.doxyfile
	doxygen openvpn.doxyfile

clean-local:
	-rm -rf html latex
