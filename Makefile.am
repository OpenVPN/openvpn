#
#  OpenVPN -- An application to securely tunnel IP networks
#             over a single UDP port, with support for SSL/TLS-based
#             session authentication and key exchange,
#             packet encryption, packet authentication, and
#             packet compression.
#
#  Copyright (C) 2002-2024 OpenVPN Inc <sales@openvpn.net>
#  Copyright (C) 2010-2024 David Sommerseth <dazo@eurephia.org>
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
#  You should have received a copy of the GNU General Public License along
#  with this program; if not, write to the Free Software Foundation, Inc.,
#  51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
#

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
	debug \
	ltrc.inc \
	CMakeLists.txt \
	CMakePresets.json \
	config.h.cmake.in \
	forked-test-driver

.PHONY: config-version.h doxygen

if GIT_CHECKOUT
BUILT_SOURCES = \
	config-version.h
endif

SUBDIRS = distro include src sample doc tests

dist_doc_DATA = \
	README \
	README.mbedtls \
	Changes.rst \
	COPYRIGHT.GPL \
	COPYING

dist_noinst_DATA = \
	.gitignore \
	.gitattributes \
	CONTRIBUTING.rst \
	PORTS \
	README.cmake.md \
	README.dco.md \
	README.ec \
	README.wolfssl

config-version.h:
	@CONFIGURE_GIT_CHFILES="`GIT_DIR=\"$(top_srcdir)/.git\" $(GIT) diff-files --name-status -r --ignore-submodules --quiet -- || echo \"+\"`"; \
	CONFIGURE_GIT_UNCOMMITTED="`GIT_DIR=\"$(top_srcdir)/.git\" $(GIT) diff-index --cached  --quiet --ignore-submodules HEAD || echo \"*\"`"; \
	CONFIGURE_GIT_REVISION="`GIT_DIR=\"$(top_srcdir)/.git\" $(GIT) rev-parse --symbolic-full-name HEAD | cut -d/ -f3-`/`GIT_DIR=\"$(top_srcdir)/.git\" $(GIT) rev-parse --short=16 HEAD`"; \
	echo "#define CONFIGURE_GIT_REVISION \"$${CONFIGURE_GIT_REVISION}\"" > config-version.h.tmp; \
	echo "#define CONFIGURE_GIT_FLAGS \"$${CONFIGURE_GIT_CHFILES}$${CONFIGURE_GIT_UNCOMMITTED}\"" >> config-version.h.tmp

	@if ! [ -f config-version.h ] || ! cmp -s config-version.h.tmp config-version.h; then \
		echo "replacing config-version.h"; \
		mv config-version.h.tmp config-version.h; \
	else \
		rm -f config-version.h.tmp; \
	fi

doxygen:
	$(MAKE) -C doc/doxygen doxygen
