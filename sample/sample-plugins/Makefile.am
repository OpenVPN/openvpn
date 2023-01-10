#
#  OpenVPN -- An application to securely tunnel IP networks
#             over a single UDP port, with support for SSL/TLS-based
#             session authentication and key exchange,
#             packet encryption, packet authentication, and
#             packet compression.
#
#  Copyright (C) 2002-2023 OpenVPN Inc <sales@openvpn.net>
#

MAINTAINERCLEANFILES = \
	$(srcdir)/Makefile.in

AM_CPPFLAGS = -I$(top_srcdir) -I$(top_builddir) \
	-I$(top_srcdir)/include -I$(top_builddir)/include

# We don't want automake to pull in libtool for building these
# sample-plugins.  Even though this breaks the conceptual ideas
# around autoconf/automake/libtools ... these sample plug-ins
# are just sample code, not to be installed or distributed outside
# of the source tarball.  Not even built by default, by design.
#
# We only add this as a simple and convenient way to build all
# these plug-ins with the same build parameters as the rest
# of the OpenVPN code.
#
# All the plugins which will be built are processed in this
# separate Makefile, which disconnects everything just enough
# to achieve our goal.
include Makefile.plugins


dist-hook :
	make -f Makefile.plugins clean
