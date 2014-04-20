#
#  OpenVPN -- An application to securely tunnel IP networks
#             over a single UDP port, with support for SSL/TLS-based
#             session authentication and key exchange,
#             packet encryption, packet authentication, and
#             packet compression.
#
#  Copyright (C) 2002-2010 OpenVPN Technologies, Inc. <sales@openvpn.net>
#  Copyright (C) 2010      David Sommerseth <dazo@users.sourceforge.net>
#  Copyright (C) 2006-2012 Alon Bar-Lev <alon.barlev@gmail.com>
#
#  This program is free software; you can redistribute it and/or modify
#  it under the terms of the GNU General Public License version 2
#  as published by the Free Software Foundation.
#
#  This program is distributed in the hope that it will be useful,
#  but WITHOUT ANY WARRANTY; without even the implied warranty of
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#  GNU General Public License for more details.
#
#  You should have received a copy of the GNU General Public License
#  along with this program (see the file COPYING included with this
#  distribution); if not, write to the Free Software Foundation, Inc.,
#  59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
#

# This option prevents autoreconf from overriding our COPYING and
# INSTALL targets:
AUTOMAKE_OPTIONS = foreign 1.9
ACLOCAL_AMFLAGS = -I m4

MAINTAINERCLEANFILES = \
	config.log config.status \
	$(srcdir)/Makefile.in \
	$(srcdir)/config.h.in $(srcdir)/config.h.in~ $(srcdir)/configure \
	$(srcdir)/install-sh $(srcdir)/ltmain.sh $(srcdir)/missing \
	$(srcdir)/m4/libtool.m4 $(srcdir)/m4/lt~obsolete.m4 \
	$(srcdir)/m4/ltoptions.m4 $(srcdir)/m4/ltsugar.m4 \
	$(srcdir)/m4/ltversion.m4 \
	$(srcdir)/depcomp $(srcdir)/aclocal.m4 \
	$(srcdir)/config.guess $(srcdir)/config.sub

CLEANFILES = \
	config-version.h tests/t_client.sh

EXTRA_DIST = \
	contrib \
	debug

.PHONY: config-version.h

if GIT_CHECKOUT
BUILT_SOURCES = \
	config-version.h
endif

SUBDIRS = build distro include src sample doc tests

dist_doc_DATA = \
	README \
	README.IPv6 \
	README.polarssl \
	COPYRIGHT.GPL \
	COPYING

dist_noinst_DATA = \
	.gitignore \
	.gitattributes \
	config-version.h.in \
	PORTS \
	README.IPv6 TODO.IPv6 \
	README.polarssl \
	openvpn.sln \
	msvc-env.bat \
	msvc-dev.bat \
	msvc-build.bat

if WIN32
dist_doc_DATA += INSTALL-win32.txt
else
dist_noinst_DATA += INSTALL-win32.txt
endif

dist_noinst_HEADERS = \
	config-msvc.h \
	config-msvc-version.h.in

if WIN32
rootdir=$(prefix)
root_DATA = version.sh
endif

config-version.h:
	@CONFIGURE_GIT_REVISION="`GIT_DIR=\"$(top_srcdir)/.git\" $(GIT) rev-parse --symbolic-full-name HEAD`/`GIT_DIR=\"$(top_srcdir)/.git\" $(GIT) rev-parse --short=16 HEAD`"; \
		$(SED) "s#@CONFIGURE_GIT_REVISION[@]#$${CONFIGURE_GIT_REVISION}#g" "$(srcdir)/config-version.h.in" > config-version.h.tmp
	@if ! [ -f config-version.h ] || ! cmp -s config-version.h.tmp config-version.h; then \
		echo "replacing config-version.h"; \
		mv config-version.h.tmp config-version.h; \
	else \
		rm -f config-version.h.tmp; \
	fi
