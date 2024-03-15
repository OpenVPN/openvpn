#
#  tapctl -- Utility to manipulate TUN/TAP interfaces on Windows
#
#  Copyright (C) 2002-2024 OpenVPN Inc <sales@openvpn.net>
#  Copyright (C) 2018-2024 Simon Rozman <simon@rozman.si>
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

include $(top_srcdir)/ltrc.inc

MAINTAINERCLEANFILES = $(srcdir)/Makefile.in

AM_CPPFLAGS = \
	-I$(top_srcdir)/include -I$(top_srcdir)/src/compat

AM_CFLAGS = \
	$(TAP_CFLAGS)

EXTRA_DIST = \
	CMakeLists.txt \
	tapctl.exe.manifest

if WIN32
sbin_PROGRAMS = tapctl
tapctl_CFLAGS = \
	-municode -D_UNICODE \
	-UNTDDI_VERSION -U_WIN32_WINNT \
	-D_WIN32_WINNT=_WIN32_WINNT_VISTA
tapctl_LDADD = -ladvapi32 -lole32 -lsetupapi
endif

tapctl_SOURCES = \
	basic.h \
	error.c error.h \
	main.c \
	tap.c tap.h \
	tapctl_resources.rc
